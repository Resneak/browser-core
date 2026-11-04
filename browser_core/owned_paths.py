from __future__ import annotations

import os
import re
import stat
import time
import uuid
from itertools import islice
from pathlib import Path
from typing import Any

from .errors import ContractError


DirectoryIdentity = tuple[int, int, int, int]
OwnedEntryIdentity = tuple[int, int, int, int, int, int, int]
MAX_OWNED_DIRECTORY_ENTRIES = 100_000
MAX_OWNED_DIRECTORY_DEPTH = 128
MAX_OWNED_TREE_ENTRIES = 1_000_000


def _validated_directory_identity(identity: object) -> DirectoryIdentity:
    if (
        type(identity) is not tuple
        or len(identity) != 4
        or any(
            isinstance(value, bool) or not isinstance(value, int) or value < 0
            for value in identity
        )
        or identity[2] != stat.S_IFDIR
        or identity[3] & 0x400
    ):
        raise ContractError("directory identity is invalid")
    return identity


def _validate_owned_path_request(path: object, *, label: object) -> tuple[Path, str]:
    if not isinstance(path, Path):
        raise ContractError("owned directory path must be a Path")
    if (
        not isinstance(label, str)
        or not label
        or len(label.encode("utf-8", errors="surrogatepass")) > 256
        or any(ord(character) < 0x20 or ord(character) == 0x7F for character in label)
    ):
        raise ContractError("owned directory label is invalid")
    try:
        label.encode("utf-8", errors="strict")
    except UnicodeEncodeError:
        raise ContractError("owned directory label is invalid") from None
    try:
        rendered_path = str(path)
        rendered_path.encode("utf-8", errors="strict")
    except (UnicodeError, ValueError):
        raise ContractError(f"{label} path is invalid") from None
    if "\x00" in rendered_path:
        raise ContractError(f"{label} path is invalid")
    return path, label


def directory_identity(path: Path, *, label: str) -> DirectoryIdentity | None:
    path, label = _validate_owned_path_request(path, label=label)
    try:
        metadata = os.lstat(path)
    except FileNotFoundError:
        return None
    except OSError as exc:
        code = getattr(exc, "winerror", None) or exc.errno
        suffix = f" (os_error={code})" if isinstance(code, int) else ""
        raise ContractError(f"{label} inspection failed{suffix}") from None
    attributes = int(getattr(metadata, "st_file_attributes", 0))
    if not stat.S_ISDIR(metadata.st_mode) or attributes & 0x400:
        raise ContractError(f"{label} is not an owned regular directory")
    return (
        metadata.st_dev,
        metadata.st_ino,
        stat.S_IFMT(metadata.st_mode),
        attributes,
    )


def require_owned_directory_ancestors(parent: Path, *, label: str) -> None:
    """Require every directory component to exist without following a link."""
    parent, label = _validate_owned_path_request(parent, label=label)
    for ancestor in reversed((parent, *parent.parents)):
        if directory_identity(ancestor, label=label) is None:
            raise ContractError(f"{label} ancestor is unavailable")


def directory_ancestry_binding(parent: Path, *, label: str) -> tuple[DirectoryIdentity, ...]:
    """Retain every directory identity from the filesystem root to ``parent``."""
    parent, label = _validate_owned_path_request(parent, label=label)
    identities = tuple(
        directory_identity(ancestor, label=label)
        for ancestor in reversed((parent, *parent.parents))
    )
    if any(identity is None for identity in identities):
        raise ContractError(f"{label} ancestor is unavailable")
    return identities


def prepare_owned_directory_parent(parent: Path, *, label: str) -> None:
    """Create missing parents only after checking each preexisting ancestor."""
    parent, label = _validate_owned_path_request(parent, label=label)
    for ancestor in reversed((parent, *parent.parents)):
        if directory_identity(ancestor, label=label) is not None:
            continue
        try:
            ancestor.mkdir()
        except FileExistsError:
            pass
        except OSError:
            raise ContractError(f"{label} cannot be created") from None
        if directory_identity(ancestor, label=label) is None:
            raise ContractError(f"{label} disappeared during creation")


def directory_identity_document(identity: DirectoryIdentity) -> dict[str, Any]:
    device, inode, file_type, attributes = _validated_directory_identity(identity)
    return {
        "device": str(device),
        "inode": str(inode),
        "file_type": file_type,
        "attributes": attributes,
    }


def parse_directory_identity(document: Any) -> DirectoryIdentity:
    if not isinstance(document, dict) or set(document) != {
        "device",
        "inode",
        "file_type",
        "attributes",
    }:
        raise ContractError("directory identity fields are invalid")
    values: list[int] = []
    for field in ("device", "inode"):
        value = document.get(field)
        if not isinstance(value, str) or not re.fullmatch(r"0|[1-9][0-9]{0,31}", value):
            raise ContractError(f"directory identity {field} is invalid")
        values.append(int(value))
    for field in ("file_type", "attributes"):
        value = document.get(field)
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise ContractError(f"directory identity {field} is invalid")
        values.append(value)
    identity = tuple(values)
    if identity[2] != stat.S_IFDIR or identity[3] & 0x400:
        raise ContractError("directory identity does not describe a regular directory")
    return identity  # type: ignore[return-value]


def _owned_entry_identity(metadata: os.stat_result) -> OwnedEntryIdentity:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_size,
        metadata.st_mtime_ns,
        int(getattr(metadata, "st_file_attributes", 0)),
        metadata.st_nlink,
    )


def _remove_owned_entry(
    path: Path,
    *,
    expected_identity: OwnedEntryIdentity,
    label: str,
    retry_deadline: float,
) -> None:
    require_owned_directory_ancestors(path.parent, label=label)
    parent_identity = directory_identity(path.parent, label=label)
    if parent_identity is None:
        raise ContractError(f"{label} entry parent is unavailable")
    try:
        observed = os.lstat(path)
    except FileNotFoundError:
        return
    except OSError:
        raise ContractError(f"{label} entry inspection failed") from None
    if _owned_entry_identity(observed) != expected_identity:
        raise ContractError(f"{label} entry changed before removal")
    if _try_remove_windows_file(path, expected_identity, parent_identity, label):
        return
    quarantine = path.with_name(f".{path.name}.removed-{uuid.uuid4().hex}")
    try:
        while True:
            try:
                require_owned_directory_ancestors(path.parent, label=label)
                os.rename(path, quarantine)
                break
            except OSError as error:
                # A sharing conflict leaves the public entry unchanged. Retry
                # only this operation, before any mutation, within the whole
                # tree's shared budget. Access errors and changed identities
                # remain failures; no arbitrary exception is retried.
                remaining = retry_deadline - time.monotonic()
                if getattr(error, 'winerror', None) not in (32, 33) or remaining <= 0:
                    raise
                time.sleep(min(0.05, remaining))
                if directory_identity(path.parent, label=label) != parent_identity:
                    raise ContractError(f"{label} entry parent changed before removal")
                if _owned_entry_identity(os.lstat(path)) != expected_identity:
                    raise ContractError(f"{label} entry changed before removal")
        if directory_identity(path.parent, label=label) != parent_identity:
            raise ContractError(f"{label} entry parent changed during removal")
        moved = os.lstat(quarantine)
    except FileNotFoundError:
        return
    except ContractError:
        raise
    except OSError:
        raise ContractError(f"{label} entry quarantine failed") from None
    if _owned_entry_identity(moved) != expected_identity:
        # A replacement won between the entry snapshot and quarantine rename.
        # For an ordinary file, restore its public name without replacing any
        # later winner and retain the quarantine alias for operator inspection.
        if stat.S_ISREG(moved.st_mode) and not bool(
            getattr(moved, "st_file_attributes", 0) & 0x400
        ):
            try:
                os.link(quarantine, path, follow_symlinks=False)
            except OSError:
                pass
        raise ContractError(f"{label} entry changed during removal")
    try:
        if stat.S_ISDIR(moved.st_mode):
            os.rmdir(quarantine)
        else:
            os.unlink(quarantine)
    except OSError:
        raise ContractError(f"{label} entry removal failed") from None
    if directory_identity(path.parent, label=label) != parent_identity:
        raise ContractError(f"{label} entry parent changed during removal")


def _try_remove_windows_file(
    path: Path, expected_identity: OwnedEntryIdentity,
    parent_identity: DirectoryIdentity, label: str,
) -> bool:
    if (os.name != "nt" or not stat.S_ISREG(expected_identity[2])
            or expected_identity[5] & 0x400):
        return False
    from .windows_file_delete import exclusive_file, mark_for_delete

    opened = False
    try:
        with exclusive_file(path) as descriptor:
            opened = True
            held = list(_owned_entry_identity(os.fstat(descriptor)))
            # Windows path stat synthesizes executable permission bits from the
            # extension; fstat has no filename. All actual handle metadata must
            # match, and the fresh path check below also checks the full mode.
            held[2] |= expected_identity[2] & 0o111
            if tuple(held) != expected_identity:
                raise ContractError(f"{label} entry changed before handle removal")
            if (directory_identity(path.parent, label=label) != parent_identity
                    or _owned_entry_identity(os.lstat(path)) != expected_identity):
                raise ContractError(f"{label} entry path changed before handle removal")
            require_owned_directory_ancestors(path.parent, label=label)
            mark_for_delete(descriptor)
        if directory_identity(path.parent, label=label) != parent_identity:
            raise ContractError(f"{label} entry parent changed during removal")
        return True
    except FileNotFoundError:
        if not opened:
            return True
        raise ContractError(f"{label} entry path changed during handle removal") from None
    except OSError as error:
        code = getattr(error, "winerror", None) or error.errno
        # No handle was acquired and nothing changed. Preserve the existing
        # verified quarantine path for files held by a sharing-compatible reader.
        if not opened and code in (32, 33):
            return False
        suffix = f" (os_error={code})" if isinstance(code, int) else ""
        raise ContractError(f"{label} entry handle removal failed{suffix}") from None


def remove_owned_directory_tree(
    path: Path,
    *,
    expected_identity: DirectoryIdentity,
    missing_ok: bool = False,
    label: str,
) -> None:
    path, label = _validate_owned_path_request(path, label=label)
    expected_identity = _validated_directory_identity(expected_identity)
    if type(missing_ok) is not bool:
        raise ContractError("owned directory missing policy must be boolean")
    _remove_owned_directory_tree(
        path, expected_identity=expected_identity, missing_ok=missing_ok,
        label=label, retry_deadline=time.monotonic() + 1.0, depth=0,
        remaining_entries=[MAX_OWNED_TREE_ENTRIES])


def _remove_owned_directory_tree(
    path: Path, *, expected_identity: DirectoryIdentity, missing_ok: bool,
    label: str, retry_deadline: float, depth: int, remaining_entries: list[int],
) -> None:
    if depth > MAX_OWNED_DIRECTORY_DEPTH:
        raise ContractError(f"{label} exceeds its depth bound")
    observed = directory_identity(path, label=label)
    if observed is None and missing_ok:
        return
    if observed != expected_identity:
        raise ContractError(f"{label} changed before removal")
    require_owned_directory_ancestors(path.parent, label=label)
    parent_identity = directory_identity(path.parent, label=label)
    if parent_identity is None:
        raise ContractError(f"{label} parent is unavailable")
    scan_limit = min(MAX_OWNED_DIRECTORY_ENTRIES, remaining_entries[0])
    try:
        with os.scandir(path) as scan:
            entries = list(islice(scan, scan_limit + 1))
    except OSError:
        raise ContractError(f"{label} scan failed") from None
    if len(entries) > scan_limit:
        raise ContractError(f"{label} exceeds its entry bound")
    remaining_entries[0] -= len(entries)
    for entry in entries:
        child = path / entry.name
        try:
            metadata = os.lstat(child)
        except FileNotFoundError:
            continue
        except OSError:
            raise ContractError(f"{label} entry inspection failed") from None
        attributes = int(getattr(metadata, "st_file_attributes", 0))
        if stat.S_ISDIR(metadata.st_mode) and not attributes & 0x400:
            _remove_owned_directory_tree(
                child,
                expected_identity=(
                    metadata.st_dev,
                    metadata.st_ino,
                    stat.S_IFMT(metadata.st_mode),
                    attributes,
                ),
                label=label,
                missing_ok=False,
                retry_deadline=retry_deadline,
                depth=depth + 1,
                remaining_entries=remaining_entries,
            )
            continue
        if stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
            _remove_owned_entry(
                child,
                expected_identity=_owned_entry_identity(metadata),
                label=label,
                retry_deadline=retry_deadline,
            )
            continue
        if attributes & 0x400 and stat.S_ISDIR(metadata.st_mode):
            _remove_owned_entry(
                child,
                expected_identity=_owned_entry_identity(metadata),
                label=label,
                retry_deadline=retry_deadline,
            )
            continue
        raise ContractError(f"{label} contains an unsupported entry")
    if directory_identity(path, label=label) != expected_identity:
        raise ContractError(f"{label} changed during removal")
    quarantine = path.with_name(f".{path.name}.removed-{uuid.uuid4().hex}")
    try:
        require_owned_directory_ancestors(path.parent, label=label)
        os.rename(path, quarantine)
    except FileNotFoundError:
        if missing_ok:
            return
        raise ContractError(f"{label} changed during removal") from None
    except OSError:
        raise ContractError(f"{label} removal quarantine failed") from None
    if (
        directory_identity(path.parent, label=label) != parent_identity
        or directory_identity(quarantine, label=label) != expected_identity
    ):
        raise ContractError(f"{label} changed during removal")
    try:
        os.rmdir(quarantine)
    except OSError:
        raise ContractError(f"{label} removal failed") from None
    if directory_identity(path.parent, label=label) != parent_identity:
        raise ContractError(f"{label} parent changed during removal")
