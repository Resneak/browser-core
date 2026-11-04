from __future__ import annotations

import json
import math
import os
import re
import stat
import uuid
from dataclasses import dataclass
from itertools import islice
from pathlib import Path
from typing import Any, Literal

from .errors import ContractError
from .owned_paths import (DirectoryIdentity, directory_ancestry_binding, directory_identity,
                          require_owned_directory_ancestors)


MAX_GATEWAY_CONTROL_BYTES = 4096
MAX_SESSION_DOCUMENT_BYTES = 1024 * 1024
MAX_STRICT_JSON_DEPTH = 128
MAX_STRICT_JSON_INTEGER_DIGITS = 1024
# Scan strings in the regex engine instead of calling Python ord() for every
# character on every canonicalization pass. The rejected range is unchanged.
_UNPAIRED_SURROGATE = re.compile(r"[\ud800-\udfff]")


@dataclass(frozen=True)
class BoundedControlSnapshot:
    state: Literal["complete", "missing", "locked", "changed"]
    body: bytes | None = None
    identity: tuple[int, int, int, int, int, int] | None = None


@dataclass(frozen=True)
class PublishedControlSnapshot:
    body: bytes
    identity: tuple[int, int, int, int, int, int]


@dataclass(frozen=True)
class BoundedJsonDirectoryInventory:
    state: Literal["complete", "missing"]
    directory_identity: tuple[int, int, int, int, int, int] | None
    files: tuple[tuple[str, tuple[int, int, int, int, int, int]], ...]


class JsonPublicationCursor:
    """Exclusively publish JSON, then replace only the population we own."""

    def __init__(self, path: Path, *, maximum: int, label: str) -> None:
        if not isinstance(path, Path):
            raise ContractError("JSON publication path must be a Path")
        if (
            isinstance(maximum, bool)
            or not isinstance(maximum, int)
            or not 1 <= maximum <= 1024 * 1024 * 1024
        ):
            raise ContractError("JSON publication byte limit is invalid")
        if (
            not isinstance(label, str)
            or not 1 <= len(label) <= 128
            or any(ord(character) < 0x20 for character in label)
        ):
            raise ContractError("JSON publication label is invalid")
        self._path = path
        self._maximum = maximum
        self._label = label
        self._published: PublishedControlSnapshot | None = None

    def publish(self, document: dict[str, Any]) -> bytes:
        if self._published is None:
            publication = publish_json_exclusive_result(
                self._path,
                document,
                maximum=self._maximum,
                label=self._label,
            )
        else:
            publication = replace_json_conditionally_result(
                self._path,
                document,
                expected_body=self._published.body,
                expected_identity=self._published.identity,
                maximum=self._maximum,
                label=self._label,
            )
        self._published = publication
        return publication.body


def canonical_json_bytes(document: dict[str, Any]) -> bytes:
    if not isinstance(document, dict):
        raise ContractError("control document must be a JSON object")
    try:
        rendered = json.dumps(
            document,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
    except (OverflowError, RecursionError, TypeError, ValueError) as exc:
        raise ContractError(
            f"control document is not strict JSON ({type(exc).__name__})"
        ) from None
    body = (rendered + "\n").encode("ascii")
    # A writer and its loader must describe the same language. `json.dumps`
    # accepts escaped lone surrogates, arbitrarily deep values, and enormous
    # integers that the strict decoder deliberately refuses; never publish bytes
    # that this module cannot read back under its own contract.
    decode_strict_json_bytes(body, label="control document")
    return body


def decode_strict_json_bytes(body: bytes, *, label: str) -> Any:
    """Decode UTF-8 JSON without JavaScript-only constants or duplicate keys.

    This helper deliberately does not impose a byte limit. Callers must first
    obtain ``body`` through a bounded snapshot (or apply an equivalent bound),
    so decoding can never become the first resource-control boundary.
    """
    if not isinstance(body, bytes):
        raise ContractError("strict JSON body must be bytes")
    if (
        not isinstance(label, str)
        or not 1 <= len(label) <= 128
        or any(ord(character) < 0x20 for character in label)
    ):
        raise ContractError("strict JSON label is invalid")

    def reject_constant(_value: str) -> None:
        raise ContractError(f"{label} is not strict JSON: contains a non-finite number")

    def finite_float(value: str) -> float:
        parsed = float(value)
        if not math.isfinite(parsed):
            raise ContractError(
                f"{label} is not strict JSON: contains a non-finite number"
            )
        return parsed

    def bounded_int(value: str) -> int:
        digits = value[1:] if value.startswith("-") else value
        if len(digits) > MAX_STRICT_JSON_INTEGER_DIGITS:
            raise ContractError(f"{label} is not strict JSON: integer is too large")
        return int(value)

    def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ContractError(f"{label} contains a duplicate key")
            result[key] = value
        return result

    try:
        document = json.loads(
            body.decode("utf-8", errors="strict"),
            parse_constant=reject_constant,
            parse_float=finite_float,
            parse_int=bounded_int,
            object_pairs_hook=unique_object,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
        raise ContractError(f"{label} must contain valid UTF-8 JSON") from None

    stack: list[tuple[Any, int]] = [(document, 0)]
    while stack:
        value, depth = stack.pop()
        if depth > MAX_STRICT_JSON_DEPTH:
            raise ContractError(f"{label} exceeds the strict JSON nesting limit")
        if isinstance(value, str):
            if _UNPAIRED_SURROGATE.search(value) is not None:
                raise ContractError(f"{label} contains an unpaired Unicode surrogate")
        elif isinstance(value, list):
            stack.extend((item, depth + 1) for item in value)
        elif isinstance(value, dict):
            for key, item in value.items():
                if _UNPAIRED_SURROGATE.search(key) is not None:
                    raise ContractError(
                        f"{label} contains an unpaired Unicode surrogate"
                    )
                stack.append((item, depth + 1))
    return document


def _os_error_code(exc: OSError) -> int | None:
    code = getattr(exc, "winerror", None)
    return code if isinstance(code, int) else exc.errno


def _require_valid_control_path_text(path: Path, *, label: str) -> None:
    try:
        rendered_path = str(path)
        rendered_path.encode("utf-8", errors="strict")
    except (UnicodeError, ValueError):
        raise ContractError(f"{label} path is invalid") from None
    if "\x00" in rendered_path:
        raise ContractError(f"{label} path is invalid")
    if os.name == "nt" and any(
        component != path.anchor
        and component not in {".", ".."}
        and (component.endswith((".", " ")) or ":" in component)
        for component in path.parts
    ):
        raise ContractError(f"{label} path is invalid")


def _identity(metadata: os.stat_result) -> tuple[int, int, int, int, int, int]:
    # Windows path stat synthesizes executable bits for .bat/.cmd/.exe names,
    # while fstat on that same file has no basename and omits those bits.
    # Keep the file type and real read/write bits in the custody comparison.
    mode = metadata.st_mode & ~0o111 if os.name == "nt" else metadata.st_mode
    return (
        metadata.st_dev,
        metadata.st_ino,
        mode,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _validate_control_mutation_request(
    path: object,
    *,
    maximum: object,
    label: object,
    operation: str,
) -> tuple[Path, int, str]:
    if not isinstance(path, Path):
        raise ContractError(f"control {operation} path must be a Path")
    if (
        not isinstance(label, str)
        or not label
        or len(label.encode("utf-8", errors="surrogatepass")) > 256
        or any(ord(character) < 0x20 or ord(character) == 0x7F for character in label)
    ):
        raise ContractError(f"control {operation} label is invalid")
    try:
        label.encode("utf-8", errors="strict")
    except UnicodeEncodeError:
        raise ContractError(f"control {operation} label is invalid") from None
    if (
        isinstance(maximum, bool)
        or not isinstance(maximum, int)
        or not 1 <= maximum <= 1024 * 1024 * 1024
    ):
        raise ContractError(f"control {operation} byte limit is invalid")
    _require_valid_control_path_text(path, label=label)
    return path, maximum, label


def _validate_control_mutation_body(
    body: object,
    *,
    maximum: int,
    label: str,
    role: str,
) -> bytes:
    if not isinstance(body, bytes):
        raise ContractError(f"{label} {role} body must be bytes")
    if len(body) > maximum:
        raise ContractError(f"{label} exceeds {maximum} bytes")
    return body


def _validate_control_mutation_identity(
    identity: object,
    *,
    operation: str,
) -> tuple[int, int, int, int, int, int]:
    if (
        type(identity) is not tuple
        or len(identity) != 6
        or any(
            isinstance(value, bool) or not isinstance(value, int) or value < 0
            for value in identity
        )
        or not stat.S_ISREG(identity[2])
    ):
        raise ContractError(f"control {operation} expected identity is invalid")
    return identity


def inventory_bounded_json_directory(
    directory: Path,
    *,
    maximum_entries: int,
    maximum_files: int,
    maximum_file_bytes: int,
    maximum_total_bytes: int,
    label: str,
    require_json_only: bool = False,
) -> BoundedJsonDirectoryInventory:
    if (
        not isinstance(label, str)
        or not label
        or len(label.encode("utf-8", errors="surrogatepass")) > 256
        or any(ord(character) < 0x20 or ord(character) == 0x7F for character in label)
    ):
        raise ContractError("JSON directory inventory label is invalid")
    try:
        label.encode("utf-8", errors="strict")
    except UnicodeEncodeError:
        raise ContractError("JSON directory inventory label is invalid") from None
    if not isinstance(directory, Path):
        raise ContractError(f"{label} path must be a Path")
    for value, maximum, field in (
        (maximum_entries, 1_000_000, "entry limit"),
        (maximum_files, 1_000_000, "file limit"),
        (maximum_file_bytes, 1024 * 1024 * 1024, "per-file byte limit"),
        (maximum_total_bytes, 1024 * 1024 * 1024, "aggregate byte limit"),
    ):
        if (
            isinstance(value, bool)
            or not isinstance(value, int)
            or not 1 <= value <= maximum
        ):
            raise ContractError(f"{label} {field} is invalid")
    if maximum_files > maximum_entries or maximum_file_bytes > maximum_total_bytes:
        raise ContractError(f"{label} inventory limits are inconsistent")
    if type(require_json_only) is not bool:
        raise ContractError(f"{label} JSON-only policy is invalid")
    _require_valid_control_path_text(directory, label=label)

    def inspect_parent_ancestry() -> tuple[DirectoryIdentity | None, ...]:
        # Missing catalog roots are a valid inventory state. Inspect existing
        # ancestors for links without requiring the full path to exist.
        return tuple(
            directory_identity(ancestor, label="JSON directory inventory parent")
            for ancestor in reversed((directory.parent, *directory.parent.parents))
        )

    parent_before = inspect_parent_ancestry()
    try:
        root_before = os.lstat(directory)
    except FileNotFoundError:
        if inspect_parent_ancestry() != parent_before:
            raise ContractError(f"{label} changed during inventory") from None
        return BoundedJsonDirectoryInventory("missing", None, ())
    except OSError:
        raise ContractError(f"{label} inventory failed") from None
    if not stat.S_ISDIR(root_before.st_mode) or bool(
        getattr(root_before, "st_file_attributes", 0) & 0x400
    ):
        raise ContractError(f"{label} is not a stable directory")
    if any(identity is None for identity in parent_before):
        raise ContractError(f"{label} changed during inventory")
    try:
        with os.scandir(directory) as iterator:
            entries = sorted(
                islice(iterator, maximum_entries + 1),
                key=lambda entry: (entry.name.casefold(), entry.name),
            )
    except OSError:
        raise ContractError(f"{label} inventory failed") from None
    if len(entries) > maximum_entries:
        raise ContractError(f"{label} has too many entries")
    files: list[tuple[str, tuple[int, int, int, int, int, int]]] = []
    total = 0
    for entry in entries:
        try:
            metadata = os.lstat(entry.path)
        except OSError:
            raise ContractError(f"{label} changed during inventory") from None
        if entry.is_symlink() or bool(
            getattr(metadata, "st_file_attributes", 0) & 0x400
        ):
            raise ContractError(f"{label} contains a link")
        if entry.name.casefold().endswith(".json") and not entry.name.endswith(".json"):
            raise ContractError(f"{label} contains a noncanonical JSON entry")
        if not entry.name.endswith(".json"):
            if require_json_only:
                raise ContractError(f"{label} contains a non-JSON entry")
            continue
        if not stat.S_ISREG(metadata.st_mode):
            raise ContractError(f"{label} JSON candidate is not a regular file")
        if metadata.st_nlink != 1:
            raise ContractError(
                f"{label} JSON candidate must not have additional hard links"
            )
        if metadata.st_size > maximum_file_bytes:
            raise ContractError(
                f"{label} JSON candidate exceeds the per-file byte limit"
            )
        total += metadata.st_size
        if total > maximum_total_bytes:
            raise ContractError(f"{label} exceeds the aggregate byte limit")
        files.append((entry.name, _identity(metadata)))
        if len(files) > maximum_files:
            raise ContractError(f"{label} has too many JSON files")
    try:
        root_after = os.lstat(directory)
    except OSError:
        raise ContractError(f"{label} changed during inventory") from None
    if _identity(root_before) != _identity(root_after):
        raise ContractError(f"{label} changed during inventory")
    if inspect_parent_ancestry() != parent_before:
        raise ContractError(f"{label} changed during inventory")
    return BoundedJsonDirectoryInventory(
        "complete",
        _identity(root_after),
        tuple(files),
    )


def read_bounded_control_snapshot_result(
    path: Path,
    *,
    maximum: int,
    label: str,
    require_private: bool = False,
    require_single_link: bool = False,
) -> BoundedControlSnapshot:
    if not isinstance(path, Path):
        raise ContractError("control read path must be a Path")
    if (
        not isinstance(label, str)
        or not label
        or len(label.encode("utf-8", errors="surrogatepass")) > 256
        or any(ord(character) < 0x20 or ord(character) == 0x7F for character in label)
    ):
        raise ContractError("control read label is invalid")
    try:
        label.encode("utf-8", errors="strict")
    except UnicodeEncodeError:
        raise ContractError("control read label is invalid") from None
    if (
        isinstance(maximum, bool)
        or not isinstance(maximum, int)
        or not 0 <= maximum <= 1024 * 1024 * 1024
    ):
        raise ContractError("control read byte limit is invalid")
    if type(require_private) is not bool:
        raise ContractError(f"{label} private-file policy is invalid")
    if type(require_single_link) is not bool:
        raise ContractError(f"{label} link policy is invalid")
    _require_valid_control_path_text(path, label=label)
    parent_ancestors = tuple(reversed((path.parent, *path.parent.parents)))
    parent_before = tuple(
        directory_identity(ancestor, label=f"{label} parent")
        for ancestor in parent_ancestors
    )

    def _enforce_private(metadata: os.stat_result) -> None:
        if (require_private or require_single_link) and metadata.st_nlink != 1:
            raise ContractError(f"{label} must not have additional hard links")
        if not require_private:
            return
        if os.name != "nt" and stat.S_IMODE(metadata.st_mode) & 0o077:
            raise ContractError(f"{label} permissions are too broad")

    bytes_changed = False
    path_observed = False
    try:
        path_before = os.lstat(path)
        path_observed = True
        if not stat.S_ISREG(path_before.st_mode) or bool(
            getattr(path_before, "st_file_attributes", 0) & 0x400
        ):
            raise ContractError(f"{label} is not a regular file")
        _enforce_private(path_before)
        # A regular leaf can still be reached through a selected junction or
        # symlinked parent. The earlier scan also admits a genuinely missing
        # nested path while refusing a linked parent of a missing leaf.
        if any(identity is None for identity in parent_before):
            return BoundedControlSnapshot("changed")
        with path.open("rb", buffering=0) as handle:
            before = os.fstat(handle.fileno())
            if not stat.S_ISREG(before.st_mode) or bool(
                getattr(before, "st_file_attributes", 0) & 0x400
            ):
                raise ContractError(f"{label} is not a regular file")
            _enforce_private(before)
            if before.st_size > maximum:
                raise ContractError(f"{label} exceeds {maximum} bytes")
            body = bytearray()
            # Unbuffered FileIO.read(n) allocates n bytes before reading, so
            # asking for the whole limit costs ~13 ms per call at 64 MiB.
            # Request the observed size plus one byte (bounded below by one
            # page) per call; the loop still reads to EOF or past the limit,
            # so a file that grows after fstat is still detected.
            request = max(before.st_size + 1, 64 * 1024)
            while len(body) <= maximum:
                chunk = handle.read(min(maximum + 1 - len(body), request))
                if not chunk:
                    break
                body.extend(chunk)
            after = os.fstat(handle.fileno())
            _enforce_private(after)
            if os.name == "nt" and after.st_size == len(body):
                # Python 3.10 exposes creation time as st_ctime on Windows.
                # A same-size edit with restored mtime can leave stat fields
                # unchanged, so compare a bounded second pass on this handle.
                handle.seek(0)
                original = memoryview(body)
                offset = 0
                while offset < len(body):
                    observed = handle.read(min(1024 * 1024, len(body) - offset))
                    if not observed or observed != original[offset:offset + len(observed)]:
                        bytes_changed = True
                        break
                    offset += len(observed)
                if not bytes_changed and handle.read(1):
                    bytes_changed = True
        path_after = os.lstat(path)
        _enforce_private(path_after)
        parent_after = tuple(
            directory_identity(ancestor, label=f"{label} parent")
            for ancestor in parent_ancestors
        )
    except FileNotFoundError:
        # Only the first lookup can establish absence. If an accepted entry
        # vanishes while it is opened or read, callers must not treat that
        # transition as a clean missing-path result.
        if path_observed:
            return BoundedControlSnapshot("changed")
        parent_after = tuple(
            directory_identity(ancestor, label=f"{label} parent")
            for ancestor in parent_ancestors
        )
        return BoundedControlSnapshot(
            "missing" if parent_before == parent_after else "changed"
        )
    except PermissionError:
        return BoundedControlSnapshot("locked")
    except ContractError:
        raise
    except OSError as exc:
        code = _os_error_code(exc) if isinstance(exc, OSError) else None
        suffix = f" (os_error={code})" if isinstance(code, int) else ""
        raise ContractError(f"{label} read failed{suffix}") from None
    if len(body) > maximum:
        raise ContractError(f"{label} exceeds {maximum} bytes")
    if (
        bytes_changed
        or _identity(path_before) != _identity(before)
        or _identity(before) != _identity(after)
        or _identity(after) != _identity(path_after)
        or after.st_size != len(body)
        or parent_before != parent_after
    ):
        return BoundedControlSnapshot("changed")
    return BoundedControlSnapshot("complete", bytes(body), _identity(after))


def read_bounded_control_snapshot(
    path: Path,
    *,
    maximum: int,
    label: str,
) -> bytes | None:
    snapshot = read_bounded_control_snapshot_result(
        path,
        maximum=maximum,
        label=label,
    )
    return snapshot.body if snapshot.state == "complete" else None


def require_bounded_control_snapshot_unchanged(
    path: Path,
    expected: BoundedControlSnapshot,
    *,
    maximum: int,
    label: str,
    require_private: bool = False,
    require_single_link: bool = False,
) -> None:
    """Rebind one selected control file after its decoded contents are validated."""
    changed = f"{label} changed during validation"
    try:
        current = read_bounded_control_snapshot_result(
            path,
            maximum=maximum,
            label=label,
            require_private=require_private,
            require_single_link=require_single_link,
        )
    except ContractError:
        raise ContractError(changed) from None
    if (
        expected.state != "complete"
        or current.state != "complete"
        or current.identity != expected.identity
        or current.body != expected.body
    ):
        raise ContractError(changed)


def load_canonical_json_document(body: bytes, *, label: str) -> dict[str, Any]:
    try:
        document = decode_strict_json_bytes(body, label=label)
    except ContractError:
        raise ContractError(f"{label} is not canonical JSON") from None
    if not isinstance(document, dict) or canonical_json_bytes(document) != body:
        raise ContractError(f"{label} is not canonical JSON")
    return document


def _same_file_object(
    left: tuple[int, int, int, int, int, int],
    right: tuple[int, int, int, int, int, int],
) -> bool:
    # Creating or removing a hard link can advance ctime without changing the
    # file object. All other identity fields, plus an exact bounded body check
    # at the caller, remain stable across the publication transition.
    return left[:5] == right[:5]


def _control_parent_ancestry(parent: Path, *, label: str) -> tuple[DirectoryIdentity, ...]:
    # Bind the lexical authority, including ancestors above a stable leaf.
    return directory_ancestry_binding(Path(os.path.abspath(parent)), label=label)


def _control_parent_matches(
    parent: Path,
    *,
    expected_identity: DirectoryIdentity,
    expected_ancestry: tuple[DirectoryIdentity, ...] | None,
    label: str,
) -> bool:
    try:
        return (
            directory_identity(parent, label=label) == expected_identity
            and (
                expected_ancestry is None
                or _control_parent_ancestry(parent, label=label) == expected_ancestry
            )
        )
    except ContractError:
        return False


def _cleanup_publication_name(
    path: Path,
    *,
    expected_body: bytes,
    owned_identity: tuple[int, int, int, int, int, int] | None,
    expected_parent_identity: DirectoryIdentity | None = None,
    expected_parent_ancestry: tuple[DirectoryIdentity, ...] | None = None,
    maximum: int,
    label: str,
) -> bool:
    if expected_parent_identity is not None:
        if not _control_parent_matches(
            path.parent,
            expected_identity=expected_parent_identity,
            expected_ancestry=expected_parent_ancestry,
            label="control cleanup parent",
        ):
            return False
    if owned_identity is None:
        try:
            os.lstat(path)
        except FileNotFoundError:
            return True
        except OSError:
            return False
        return False
    try:
        snapshot = read_bounded_control_snapshot_result(
            path,
            maximum=maximum,
            label=label,
        )
    except ContractError:
        return False
    if snapshot.state == "missing":
        return True
    if snapshot.state != "complete" or snapshot.identity is None:
        return False
    if snapshot.body != expected_body or not _same_file_object(
        snapshot.identity,
        owned_identity,
    ):
        # The name now belongs to another publisher. Preserving it is a clean
        # outcome, not a cleanup failure.
        return True
    try:
        remove_control_conditionally(
            path,
            expected_body=expected_body,
            expected_identity=snapshot.identity,
            maximum=maximum,
            label=label,
        )
        return True
    except ContractError:
        # A replacement may have won after our snapshot. Recheck once so that
        # this race is distinguished from an owned artifact left behind.
        try:
            current = read_bounded_control_snapshot_result(
                path,
                maximum=maximum,
                label=label,
            )
        except ContractError:
            return False
        if current.state == "missing":
            return True
        if current.state != "complete" or current.identity is None:
            return False
        return current.body != expected_body or not _same_file_object(
            current.identity,
            owned_identity,
        )


def publish_bytes_exclusive_result(
    path: Path,
    body: bytes,
    *,
    maximum: int,
    label: str,
    require_single_link: bool = False,
) -> PublishedControlSnapshot:
    path, maximum, label = _validate_control_mutation_request(
        path,
        maximum=maximum,
        label=label,
        operation="publication",
    )
    body = _validate_control_mutation_body(
        body,
        maximum=maximum,
        label=label,
        role="publication",
    )
    if type(require_single_link) is not bool:
        raise ContractError("control publication link policy is invalid")
    parent_identity = directory_identity(
        path.parent,
        label="control publication parent",
    )
    if parent_identity is None:
        raise ContractError(f"{label} publication parent is unavailable")
    require_owned_directory_ancestors(path.parent, label="control publication parent")
    parent_ancestry = _control_parent_ancestry(
        path.parent, label="control publication parent"
    )
    if parent_ancestry[-1] != parent_identity:
        raise ContractError(f"{label} publication parent changed")

    def require_parent_authority() -> None:
        if not _control_parent_matches(
            path.parent,
            expected_identity=parent_identity,
            expected_ancestry=parent_ancestry,
            label="control publication parent",
        ):
            raise ContractError(f"{label} publication parent changed")

    temporary = path.with_name(f".{path.name}.tmp-{uuid.uuid4().hex}")
    descriptor: int | None = None
    descriptor_identity: tuple[int, int, int, int, int, int] | None = None
    temporary_identity: tuple[int, int, int, int, int, int] | None = None
    written_count = 0
    published = False
    temporary_removed = False
    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
        descriptor = os.open(temporary, flags, 0o600)
        view = memoryview(body)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("control-file write made no progress")
            written_count += written
            view = view[written:]
        os.fsync(descriptor)
        descriptor_identity = _identity(os.fstat(descriptor))
        os.close(descriptor)
        descriptor = None
        require_parent_authority()

        before_link = read_bounded_control_snapshot_result(
            temporary,
            maximum=maximum,
            label=f"{label} temporary publication",
        )
        if (
            before_link.state != "complete"
            or before_link.body != body
            or before_link.identity is None
            or not _same_file_object(before_link.identity, descriptor_identity)
        ):
            raise ContractError(f"{label} temporary publication changed")
        temporary_identity = before_link.identity
        require_parent_authority()
        os.link(temporary, path, follow_symlinks=False)
        published = True
        require_parent_authority()

        linked_temporary = read_bounded_control_snapshot_result(
            temporary,
            maximum=maximum,
            label=f"{label} temporary publication",
        )
        linked_final = read_bounded_control_snapshot_result(
            path,
            maximum=maximum,
            label=label,
        )
        if (
            linked_temporary.state != "complete"
            or linked_temporary.body != body
            or linked_temporary.identity is None
            or linked_final.state != "complete"
            or linked_final.body != body
            or linked_final.identity is None
            or linked_temporary.identity != linked_final.identity
            or not _same_file_object(linked_temporary.identity, temporary_identity)
        ):
            raise ContractError(f"{label} changed during publication")
        temporary_identity = linked_temporary.identity
        remove_control_conditionally(
            temporary,
            expected_body=body,
            expected_identity=linked_temporary.identity,
            maximum=maximum,
            label=f"{label} temporary publication",
        )
        temporary_removed = True
        require_parent_authority()

        final = read_bounded_control_snapshot_result(
            path,
            maximum=maximum,
            label=label,
            require_single_link=require_single_link,
        )
        if (
            final.state != "complete"
            or final.body != body
            or final.identity is None
            or not _same_file_object(final.identity, linked_final.identity)
        ):
            raise ContractError(f"{label} changed after publication")
        require_parent_authority()
        return PublishedControlSnapshot(body=body, identity=final.identity)
    except (OSError, ContractError, KeyboardInterrupt) as exc:
        if descriptor is not None:
            if descriptor_identity is None:
                try:
                    descriptor_identity = _identity(os.fstat(descriptor))
                except OSError:
                    pass
            try:
                os.close(descriptor)
            except OSError:
                pass
        cleanup_failed = False
        if published:
            if not _cleanup_publication_name(
                path,
                expected_body=body,
                owned_identity=temporary_identity or descriptor_identity,
                expected_parent_identity=parent_identity,
                expected_parent_ancestry=parent_ancestry,
                maximum=maximum,
                label=label,
            ):
                cleanup_failed = True
        if not temporary_removed and not _cleanup_publication_name(
            temporary,
            expected_body=body[:written_count],
            owned_identity=temporary_identity or descriptor_identity,
            expected_parent_identity=parent_identity,
            expected_parent_ancestry=parent_ancestry,
            maximum=maximum,
            label=f"{label} temporary publication",
        ):
            cleanup_failed = True
        code = _os_error_code(exc) if isinstance(exc, OSError) else None
        suffix = f" (os_error={code})" if isinstance(code, int) else ""
        cleanup = "; cleanup incomplete" if cleanup_failed else ""
        if isinstance(exc, KeyboardInterrupt):
            if cleanup_failed:
                raise ContractError(f"{label} publication interrupted; cleanup incomplete") from exc
            raise
        raise ContractError(f"{label} publication failed{suffix}{cleanup}") from None


def publish_bytes_exclusive(
    path: Path,
    body: bytes,
    *,
    maximum: int,
    label: str,
) -> bytes:
    return publish_bytes_exclusive_result(
        path,
        body,
        maximum=maximum,
        label=label,
    ).body


def publish_json_exclusive_result(
    path: Path,
    document: dict[str, Any],
    *,
    maximum: int,
    label: str,
) -> PublishedControlSnapshot:
    return publish_bytes_exclusive_result(
        path,
        canonical_json_bytes(document),
        maximum=maximum,
        label=label,
    )


def publish_json_exclusive(
    path: Path,
    document: dict[str, Any],
    *,
    maximum: int,
    label: str,
) -> bytes:
    return publish_json_exclusive_result(
        path,
        document,
        maximum=maximum,
        label=label,
    ).body


def _restore_quarantined_control(
    quarantine: Path,
    path: Path,
    *,
    expected_body: bytes,
    expected_identity: tuple[int, int, int, int, int, int],
    expected_parent_identity: DirectoryIdentity,
    maximum: int,
    label: str,
    expected_parent_ancestry: tuple[DirectoryIdentity, ...] | None = None,
) -> None:
    linked = False
    linked_identity: tuple[int, int, int, int, int, int] | None = None
    try:
        if not _control_parent_matches(
            path.parent,
            expected_identity=expected_parent_identity,
            expected_ancestry=expected_parent_ancestry,
            label="control rollback parent",
        ):
            raise ContractError(f"{label} rollback parent changed")
        source = read_bounded_control_snapshot_result(
            quarantine,
            maximum=maximum,
            label=f"{label} rollback source",
        )
        if (
            source.state != "complete"
            or source.body != expected_body
            or source.identity != expected_identity
        ):
            raise ContractError(f"{label} rollback source changed")
        os.link(quarantine, path, follow_symlinks=False)
        linked = True
        if not _control_parent_matches(
            path.parent,
            expected_identity=expected_parent_identity,
            expected_ancestry=expected_parent_ancestry,
            label="control rollback parent",
        ):
            raise ContractError(f"{label} rollback parent changed")
        linked_source = read_bounded_control_snapshot_result(
            quarantine,
            maximum=maximum,
            label=f"{label} rollback source",
        )
        linked_target = read_bounded_control_snapshot_result(
            path,
            maximum=maximum,
            label=f"{label} rollback target",
        )
        if (
            linked_source.state != "complete"
            or linked_source.body != expected_body
            or linked_source.identity is None
            or linked_target.state != "complete"
            or linked_target.body != expected_body
            or linked_target.identity is None
            or linked_source.identity != linked_target.identity
            or not _same_file_object(linked_source.identity, expected_identity)
        ):
            raise ContractError(f"{label} rollback link changed")
        linked_identity = linked_target.identity
        cleanup_source = read_bounded_control_snapshot_result(
            quarantine,
            maximum=maximum,
            label=f"{label} rollback source",
        )
        if (
            cleanup_source.state != "complete"
            or cleanup_source.body != expected_body
            or cleanup_source.identity != linked_source.identity
        ):
            raise ContractError(f"{label} rollback source changed before cleanup")
        os.unlink(quarantine)
        final = read_bounded_control_snapshot_result(
            path,
            maximum=maximum,
            label=f"{label} rollback target",
        )
        if (
            final.state != "complete"
            or final.body != expected_body
            or final.identity is None
            or not _same_file_object(final.identity, linked_target.identity)
            or not _control_parent_matches(
                path.parent,
                expected_identity=expected_parent_identity,
                expected_ancestry=expected_parent_ancestry,
                label="control rollback parent",
            )
        ):
            raise ContractError(f"{label} rollback result changed")
    except (OSError, ContractError) as exc:
        cleanup_failed = linked and not _cleanup_publication_name(
            path,
            expected_body=expected_body,
            owned_identity=linked_identity or expected_identity,
            expected_parent_identity=expected_parent_identity,
            expected_parent_ancestry=expected_parent_ancestry,
            maximum=maximum,
            label=f"{label} rollback target",
        )
        code = _os_error_code(exc) if isinstance(exc, OSError) else None
        suffix = f" (os_error={code})" if isinstance(code, int) else ""
        cleanup = "; cleanup incomplete" if cleanup_failed else ""
        raise ContractError(f"{label} rollback failed{suffix}{cleanup}") from None


def _rollback_transition(
    quarantine: Path,
    path: Path,
    *,
    expected_body: bytes,
    expected_identity: tuple[int, int, int, int, int, int],
    expected_parent_identity: DirectoryIdentity,
    maximum: int,
    label: str,
    primary: ContractError,
    expected_parent_ancestry: tuple[DirectoryIdentity, ...] | None = None,
) -> None:
    try:
        _restore_quarantined_control(
            quarantine,
            path,
            expected_body=expected_body,
            expected_identity=expected_identity,
            expected_parent_identity=expected_parent_identity,
            expected_parent_ancestry=expected_parent_ancestry,
            maximum=maximum,
            label=label,
        )
    except ContractError:
        raise ContractError(
            f"{label} transition failed; rollback incomplete"
        ) from primary
    raise primary


def replace_bytes_conditionally_result(
    path: Path,
    replacement_body: bytes,
    *,
    expected_body: bytes,
    expected_identity: tuple[int, int, int, int, int, int],
    maximum: int,
    label: str,
) -> PublishedControlSnapshot:
    path, maximum, label = _validate_control_mutation_request(
        path,
        maximum=maximum,
        label=label,
        operation="replacement",
    )
    replacement_body = _validate_control_mutation_body(
        replacement_body,
        maximum=maximum,
        label=label,
        role="replacement",
    )
    expected_body = _validate_control_mutation_body(
        expected_body,
        maximum=maximum,
        label=label,
        role="replacement expected",
    )
    expected_identity = _validate_control_mutation_identity(
        expected_identity,
        operation="replacement",
    )
    parent_identity = directory_identity(
        path.parent,
        label="control replacement parent",
    )
    if parent_identity is None:
        raise ContractError(f"{label} changed before transition")
    parent_ancestry = _control_parent_ancestry(
        path.parent, label="control replacement parent"
    )
    if parent_ancestry[-1] != parent_identity:
        raise ContractError(f"{label} replacement parent changed")

    def require_parent_authority() -> None:
        if not _control_parent_matches(
            path.parent,
            expected_identity=parent_identity,
            expected_ancestry=parent_ancestry,
            label="control replacement parent",
        ):
            raise ContractError(f"{label} replacement parent changed")

    quarantine = path.with_name(f".{path.name}.previous-{uuid.uuid4().hex}")
    try:
        current = os.lstat(path)
    except FileNotFoundError:
        raise ContractError(f"{label} changed before transition") from None
    except OSError as exc:
        code = _os_error_code(exc)
        suffix = f" (os_error={code})" if isinstance(code, int) else ""
        raise ContractError(f"{label} transition inspection failed{suffix}") from None
    if not stat.S_ISREG(current.st_mode) or bool(
        getattr(current, "st_file_attributes", 0) & 0x400
    ):
        raise ContractError(f"{label} changed before transition")
    if _identity(current) != expected_identity:
        raise ContractError(f"{label} changed before transition")
    require_parent_authority()
    try:
        os.rename(path, quarantine)
    except OSError as exc:
        code = _os_error_code(exc)
        suffix = f" (os_error={code})" if isinstance(code, int) else ""
        raise ContractError(f"{label} transition quarantine failed{suffix}") from None

    try:
        require_parent_authority()
    except ContractError as exc:
        _rollback_transition(
            quarantine,
            path,
            expected_body=expected_body,
            expected_identity=expected_identity,
            expected_parent_identity=parent_identity,
            expected_parent_ancestry=parent_ancestry,
            maximum=maximum,
            label=label,
            primary=exc,
        )

    try:
        moved = read_bounded_control_snapshot_result(
            quarantine,
            maximum=maximum,
            label=f"{label} quarantined source",
        )
    except ContractError as exc:
        _rollback_transition(
            quarantine,
            path,
            expected_body=expected_body,
            expected_identity=expected_identity,
            expected_parent_identity=parent_identity,
            expected_parent_ancestry=parent_ancestry,
            maximum=maximum,
            label=label,
            primary=exc,
        )
    if moved.state != "complete" or moved.identity is None or moved.body is None:
        _rollback_transition(
            quarantine,
            path,
            expected_body=expected_body,
            expected_identity=expected_identity,
            expected_parent_identity=parent_identity,
            expected_parent_ancestry=parent_ancestry,
            maximum=maximum,
            label=label,
            primary=ContractError(f"{label} changed during transition"),
        )
    if moved.identity != expected_identity or moved.body != expected_body:
        _rollback_transition(
            quarantine,
            path,
            expected_body=moved.body,
            expected_identity=moved.identity,
            expected_parent_identity=parent_identity,
            expected_parent_ancestry=parent_ancestry,
            maximum=maximum,
            label=label,
            primary=ContractError(f"{label} changed during transition"),
        )
    try:
        require_parent_authority()
    except ContractError as exc:
        _rollback_transition(
            quarantine,
            path,
            expected_body=expected_body,
            expected_identity=expected_identity,
            expected_parent_identity=parent_identity,
            expected_parent_ancestry=parent_ancestry,
            maximum=maximum,
            label=label,
            primary=exc,
        )

    try:
        publication = publish_bytes_exclusive_result(
            path,
            replacement_body,
            maximum=maximum,
            label=label,
        )
    except ContractError as exc:
        _rollback_transition(
            quarantine,
            path,
            expected_body=expected_body,
            expected_identity=expected_identity,
            expected_parent_identity=parent_identity,
            expected_parent_ancestry=parent_ancestry,
            maximum=maximum,
            label=label,
            primary=exc,
        )
    try:
        require_parent_authority()
    except ContractError:
        raise ContractError(
            f"{label} transition committed; output parent changed"
        ) from None
    try:
        remove_control_conditionally(
            quarantine,
            expected_body=expected_body,
            expected_identity=expected_identity,
            maximum=maximum,
            label=f"{label} previous publication",
        )
    except (OSError, ContractError) as exc:
        code = _os_error_code(exc) if isinstance(exc, OSError) else None
        suffix = f" (os_error={code})" if isinstance(code, int) else ""
        raise ContractError(
            f"{label} transition committed; cleanup failed{suffix}"
        ) from None
    try:
        require_parent_authority()
    except ContractError:
        raise ContractError(
            f"{label} transition committed; output parent changed"
        ) from None
    try:
        final = read_bounded_control_snapshot_result(
            path, maximum=maximum, label=label
        )
    except ContractError:
        raise ContractError(f"{label} transition committed; output changed") from None
    if (
        final.state != "complete"
        or final.body != publication.body
        or final.identity != publication.identity
    ):
        raise ContractError(f"{label} transition committed; output changed")
    try:
        require_parent_authority()
    except ContractError:
        raise ContractError(
            f"{label} transition committed; output parent changed"
        ) from None
    return publication


def replace_json_conditionally_result(
    path: Path,
    document: dict[str, Any],
    *,
    expected_body: bytes,
    expected_identity: tuple[int, int, int, int, int, int],
    maximum: int,
    label: str,
) -> PublishedControlSnapshot:
    return replace_bytes_conditionally_result(
        path,
        canonical_json_bytes(document),
        expected_body=expected_body,
        expected_identity=expected_identity,
        maximum=maximum,
        label=label,
    )


def replace_bytes_conditionally(
    path: Path,
    replacement_body: bytes,
    *,
    expected_body: bytes,
    expected_identity: tuple[int, int, int, int, int, int],
    maximum: int,
    label: str,
) -> bytes:
    return replace_bytes_conditionally_result(
        path,
        replacement_body,
        expected_body=expected_body,
        expected_identity=expected_identity,
        maximum=maximum,
        label=label,
    ).body


def replace_json_conditionally(
    path: Path,
    document: dict[str, Any],
    *,
    expected_body: bytes,
    expected_identity: tuple[int, int, int, int, int, int],
    maximum: int,
    label: str,
) -> bytes:
    return replace_json_conditionally_result(
        path,
        document,
        expected_body=expected_body,
        expected_identity=expected_identity,
        maximum=maximum,
        label=label,
    ).body


def _same_windows_control_identity(left, right) -> bool:
    # Windows path stat synthesizes executable bits from the basename extension;
    # quarantine renaming changes those bits and fstat has no filename at all.
    # File type, real write bits and every other identity field still must match.
    return (left[:2] == right[:2] and left[2] & ~0o111 == right[2] & ~0o111
            and left[3:] == right[3:])


def _remove_control_by_held_handle(
    path: Path, *, expected_body: bytes,
    expected_identity: tuple[int, int, int, int, int, int],
    expected_parent_identity: DirectoryIdentity, label: str,
    expected_parent_ancestry: tuple[DirectoryIdentity, ...] | None = None,
) -> None:
    """No pathname unlink or rollback after the final exclusive verification."""
    from .windows_file_delete import exclusive_file, mark_for_delete

    with exclusive_file(path, read_contents=True) as descriptor:
        def require_held_identity() -> None:
            metadata = os.fstat(descriptor)
            if (not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1
                    or getattr(metadata, 'st_file_attributes', 0) & 0x400
                    or not _same_windows_control_identity(_identity(metadata), expected_identity)):
                raise ContractError(f'{label} changed before handle removal')

        require_held_identity()
        body = bytearray()
        while len(body) <= len(expected_body):
            chunk = os.read(descriptor, min(64*1024, len(expected_body)+1-len(body)))
            if not chunk:
                break
            body.extend(chunk)
        if body != expected_body:
            raise ContractError(f'{label} contents changed before handle removal')
        require_held_identity()
        if (not _control_parent_matches(path.parent,
                expected_identity=expected_parent_identity,
                expected_ancestry=expected_parent_ancestry,
                label='control removal parent')
                or not _same_windows_control_identity(_identity(os.lstat(path)), expected_identity)):
            raise ContractError(f'{label} path changed before handle removal')
        # Share mode zero prevents a new writer/renamer through this boundary.
        # Mark only this verified handle, never the possibly replaced pathname.
        mark_for_delete(descriptor)
    if os.path.lexists(path):
        raise ContractError(f'{label} handle removal is not confirmed')


def _remove_control_strict(
    path: Path, *, expected_body: bytes,
    expected_identity: tuple[int, int, int, int, int, int],
    expected_parent_identity: DirectoryIdentity, maximum: int, label: str,
    expected_parent_ancestry: tuple[DirectoryIdentity, ...] | None = None,
) -> None:
    """Preserve uncertain quarantine contents; do not run legacy path rollback."""
    if os.name != 'nt':
        # No verified identity-bound unlink primitive is implemented elsewhere.
        raise ContractError(f'{label} handle-bound removal is unavailable')
    quarantine = path.with_name(f'.{path.name}.removed-{uuid.uuid4().hex}')
    try:
        os.rename(path, quarantine)
        if not _control_parent_matches(path.parent,
                expected_identity=expected_parent_identity,
                expected_ancestry=expected_parent_ancestry,
                label='control removal parent'):
            raise ContractError(f'{label} removal parent changed')
        moved = read_bounded_control_snapshot_result(quarantine, maximum=maximum,
            label=f'{label} quarantined source', require_single_link=True)
        if (moved.state != 'complete' or moved.identity is None
                or not _same_windows_control_identity(moved.identity, expected_identity)
                or moved.body != expected_body):
            raise ContractError(f'{label} changed during removal; quarantine retained')
        if not _control_parent_matches(path.parent,
                expected_identity=expected_parent_identity,
                expected_ancestry=expected_parent_ancestry,
                label='control removal parent'):
            raise ContractError(f'{label} removal parent changed')
        _remove_control_by_held_handle(quarantine, expected_body=expected_body,
            expected_identity=expected_identity, expected_parent_identity=expected_parent_identity,
            expected_parent_ancestry=expected_parent_ancestry, label=label)
        if (not _control_parent_matches(path.parent,
                expected_identity=expected_parent_identity,
                expected_ancestry=expected_parent_ancestry,
                label='control removal parent')
                or os.path.lexists(path)):
            raise ContractError(f'{label} removal custody changed')
    except OSError as error:
        code = _os_error_code(error)
        suffix = f' (os_error={code})' if isinstance(code, int) else ''
        # In particular, sharing conflicts do not fall back to pathname unlink.
        raise ContractError(f'{label} handle-bound removal failed{suffix}; quarantine retained') from None


def remove_control_conditionally(
    path: Path,
    *,
    expected_body: bytes,
    expected_identity: tuple[int, int, int, int, int, int],
    maximum: int,
    label: str,
    missing_ok: bool = False,
    require_handle_delete: bool = False,
) -> None:
    """Conditional removal; strict callers retain final handle-bound custody.

    ``require_handle_delete`` has no pathname-delete/rollback fallback. Unsupported
    platforms, sharing conflicts or changed files retain residue and fail closed.
    Other callers keep the preexisting transition/rollback contract.
    """
    path, maximum, label = _validate_control_mutation_request(
        path,
        maximum=maximum,
        label=label,
        operation="removal",
    )
    expected_body = _validate_control_mutation_body(
        expected_body,
        maximum=maximum,
        label=label,
        role="removal expected",
    )
    expected_identity = _validate_control_mutation_identity(
        expected_identity,
        operation="removal",
    )
    if type(missing_ok) is not bool:
        raise ContractError("control removal missing policy must be boolean")
    if type(require_handle_delete) is not bool:
        raise ContractError('control removal handle policy must be boolean')
    if require_handle_delete and missing_ok:
        raise ContractError('handle-bound control removal requires an existing source')
    parent_identity = directory_identity(
        path.parent,
        label="control removal parent",
    )
    if parent_identity is None:
        if missing_ok:
            return
        raise ContractError(f"{label} changed before removal")
    parent_ancestry = _control_parent_ancestry(
        path.parent, label="control removal parent"
    )
    if parent_ancestry[-1] != parent_identity:
        raise ContractError(f"{label} removal parent changed")

    def require_parent_authority() -> None:
        if not _control_parent_matches(
            path.parent,
            expected_identity=parent_identity,
            expected_ancestry=parent_ancestry,
            label="control removal parent",
        ):
            raise ContractError(f"{label} removal parent changed")

    quarantine = path.with_name(f".{path.name}.removed-{uuid.uuid4().hex}")
    try:
        current = os.lstat(path)
    except FileNotFoundError:
        if missing_ok:
            return
        raise ContractError(f"{label} changed before removal") from None
    except OSError as exc:
        code = _os_error_code(exc)
        suffix = f" (os_error={code})" if isinstance(code, int) else ""
        raise ContractError(f"{label} removal inspection failed{suffix}") from None
    if not stat.S_ISREG(current.st_mode) or bool(
        getattr(current, "st_file_attributes", 0) & 0x400
    ):
        raise ContractError(f"{label} changed before removal")
    if _identity(current) != expected_identity:
        raise ContractError(f"{label} changed before removal")
    require_parent_authority()
    if require_handle_delete:
        return _remove_control_strict(path, expected_body=expected_body,
            expected_identity=expected_identity, expected_parent_identity=parent_identity,
            expected_parent_ancestry=parent_ancestry, maximum=maximum, label=label)
    try:
        os.rename(path, quarantine)
    except FileNotFoundError as exc:
        if missing_ok:
            return
        code = _os_error_code(exc)
        suffix = f" (os_error={code})" if isinstance(code, int) else ""
        raise ContractError(f"{label} removal quarantine failed{suffix}") from None
    except OSError as exc:
        code = _os_error_code(exc)
        suffix = f" (os_error={code})" if isinstance(code, int) else ""
        raise ContractError(f"{label} removal quarantine failed{suffix}") from None

    try:
        require_parent_authority()
    except ContractError as exc:
        _rollback_transition(
            quarantine,
            path,
            expected_body=expected_body,
            expected_identity=expected_identity,
            expected_parent_identity=parent_identity,
            expected_parent_ancestry=parent_ancestry,
            maximum=maximum,
            label=label,
            primary=exc,
        )

    try:
        moved = read_bounded_control_snapshot_result(
            quarantine,
            maximum=maximum,
            label=f"{label} quarantined source",
        )
    except ContractError as exc:
        _rollback_transition(
            quarantine,
            path,
            expected_body=expected_body,
            expected_identity=expected_identity,
            expected_parent_identity=parent_identity,
            expected_parent_ancestry=parent_ancestry,
            maximum=maximum,
            label=label,
            primary=exc,
        )
    if moved.state == "missing" and missing_ok:
        return
    if moved.state != "complete" or moved.identity is None or moved.body is None:
        _rollback_transition(
            quarantine,
            path,
            expected_body=expected_body,
            expected_identity=expected_identity,
            expected_parent_identity=parent_identity,
            expected_parent_ancestry=parent_ancestry,
            maximum=maximum,
            label=label,
            primary=ContractError(f"{label} changed during removal"),
        )
    if moved.identity != expected_identity or moved.body != expected_body:
        _rollback_transition(
            quarantine,
            path,
            expected_body=moved.body,
            expected_identity=moved.identity,
            expected_parent_identity=parent_identity,
            expected_parent_ancestry=parent_ancestry,
            maximum=maximum,
            label=label,
            primary=ContractError(f"{label} changed during removal"),
        )
    try:
        require_parent_authority()
    except ContractError as exc:
        _rollback_transition(
            quarantine,
            path,
            expected_body=expected_body,
            expected_identity=expected_identity,
            expected_parent_identity=parent_identity,
            expected_parent_ancestry=parent_ancestry,
            maximum=maximum,
            label=label,
            primary=exc,
        )
    try:
        os.unlink(quarantine)
    except FileNotFoundError as exc:
        if missing_ok:
            return
        code = _os_error_code(exc)
        suffix = f" (os_error={code})" if isinstance(code, int) else ""
        _rollback_transition(
            quarantine,
            path,
            expected_body=expected_body,
            expected_identity=expected_identity,
            expected_parent_identity=parent_identity,
            expected_parent_ancestry=parent_ancestry,
            maximum=maximum,
            label=label,
            primary=ContractError(f"{label} removal failed{suffix}"),
        )
    except OSError as exc:
        code = _os_error_code(exc)
        suffix = f" (os_error={code})" if isinstance(code, int) else ""
        _rollback_transition(
            quarantine,
            path,
            expected_body=expected_body,
            expected_identity=expected_identity,
            expected_parent_identity=parent_identity,
            expected_parent_ancestry=parent_ancestry,
            maximum=maximum,
            label=label,
            primary=ContractError(f"{label} removal failed{suffix}"),
        )
    try:
        require_parent_authority()
    except ContractError:
        raise ContractError(f"{label} removal committed; parent changed") from None
