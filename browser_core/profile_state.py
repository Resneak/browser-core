from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from datetime import datetime, timezone
from itertools import islice
from pathlib import Path
from typing import Any

from .contracts import ContractError, reject_sensitive_keys
from .control_files import (
    BoundedJsonDirectoryInventory,
    canonical_json_bytes,
    inventory_bounded_json_directory,
    load_canonical_json_document,
    publish_json_exclusive,
    read_bounded_control_snapshot_result,
)
from .owned_paths import directory_identity, require_owned_directory_ancestors
from .profiles import (
    _profile_workspace_path,
    acquire_profile_lock,
    is_disposable_profile_id,
    load_profile,
    profile_data_path,
    release_profile_lock,
    validate_profile_id,
)
from .windows_change_time import windows_change_time


PROFILE_STATE_SCHEMA = "browser-core.profile-state-receipt/1"
PROFILE_STATE_TREE_DOMAIN = b"browser-core.profile-state-tree/1\n"
MAX_PROFILE_STATE_RECEIPT_BYTES = 64 * 1024
MAX_PROFILE_STATE_RECEIPTS = 4096
MAX_PROFILE_STATE_RECEIPT_ENTRIES = 8192
MAX_PROFILE_STATE_RECEIPT_TOTAL_BYTES = 256 * 1024 * 1024
MAX_PROFILE_STATE_TREE_ENTRIES = 100_000
MAX_PROFILE_STATE_TREE_FILES = 50_000
MAX_PROFILE_STATE_TREE_DIRECTORIES = 50_000
MAX_PROFILE_STATE_FILE_BYTES = 256 * 1024 * 1024
MAX_PROFILE_STATE_TOTAL_BYTES = 2 * 1024 * 1024 * 1024
MAX_PROFILE_STATE_ENTRY_NAME_BYTES = 1024
MAX_PROFILE_STATE_RELATIVE_PATH_BYTES = 64 * 1024
MAX_PROFILE_STATE_TOTAL_PATH_BYTES = 64 * 1024 * 1024
MAX_PROFILE_STATE_DEPTH = 64
PROFILE_STATE_EXCLUSIONS = (".browser-core.lock",)
PROFILE_STATE_NON_CLAIMS = (
    "the aggregate digest is not a cookie, storage, or browsing-history export",
    "the unsalted aggregate digest reveals equality and is not a confidentiality boundary against guessed state",
    "equal digests show equal captured bytes and names under this bounded walk, not equal server-side identity",
    "the advisory-lock walk is not an atomic filesystem snapshot against non-cooperating writers",
    "the receipt does not attest that a remote target accepted or observed the profile",
)


FileIdentity = tuple[int, int, int, int, int, int, int, int]
ProfileTreePopulation = tuple[
    tuple[tuple[Path, FileIdentity, tuple[str, ...]], ...],
    tuple[tuple[Path, FileIdentity, int | None], ...],
]


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _identity(metadata: os.stat_result) -> FileIdentity:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
        metadata.st_nlink,
        int(getattr(metadata, "st_file_attributes", 0)),
    )


def _is_reparse(metadata: os.stat_result) -> bool:
    return bool(int(getattr(metadata, "st_file_attributes", 0)) & 0x400)


def _safe_record_path(relative: Path) -> str:
    value = "/".join(relative.parts)
    try:
        value.encode("utf-8", errors="strict")
    except UnicodeEncodeError:
        raise ContractError("profile state contains an invalid entry name") from None
    if any(0xD800 <= ord(character) <= 0xDFFF for character in value):
        raise ContractError("profile state contains an invalid entry name")
    return value


def _bounded_entry_path(relative: Path, name: str, counters: dict[str, Any]) -> Path:
    if not isinstance(name, str):
        raise ContractError("profile state entry name is invalid")
    try:
        name_bytes = name.encode("utf-8", errors="strict")
    except UnicodeEncodeError:
        raise ContractError("profile state contains an invalid entry name") from None
    if len(name_bytes) > MAX_PROFILE_STATE_ENTRY_NAME_BYTES:
        raise ContractError("profile state entry name exceeds the byte limit")
    child_relative = relative / name
    record_path = _safe_record_path(child_relative)
    encoded_path = record_path.encode("utf-8")
    if len(encoded_path) > MAX_PROFILE_STATE_RELATIVE_PATH_BYTES:
        raise ContractError("profile state relative path exceeds the byte limit")
    if counters["path_bytes"] + len(encoded_path) > MAX_PROFILE_STATE_TOTAL_PATH_BYTES:
        raise ContractError("profile state exceeds the aggregate path byte limit")
    counters["path_bytes"] += len(encoded_path)
    return child_relative


def _update_tree_digest(digest: Any, record: dict[str, Any]) -> None:
    try:
        encoded = json.dumps(
            record,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (OverflowError, RecursionError, TypeError, ValueError):
        raise ContractError("profile state tree record is invalid") from None
    digest.update(encoded)
    digest.update(b"\n")


def _hash_profile_file(
    path: Path,
    *,
    expected_identity: FileIdentity,
    counters: dict[str, Any],
) -> tuple[str, int]:
    try:
        path_before = os.lstat(path)
        if (
            not stat.S_ISREG(path_before.st_mode)
            or _is_reparse(path_before)
            or path_before.st_nlink != 1
        ):
            raise ContractError("profile state contains a linked or non-regular file")
        if _identity(path_before) != expected_identity:
            raise ContractError("profile state file changed during capture")
        if path_before.st_size > MAX_PROFILE_STATE_FILE_BYTES:
            raise ContractError("profile state file exceeds the byte limit")
        if counters["total_bytes"] + path_before.st_size > MAX_PROFILE_STATE_TOTAL_BYTES:
            raise ContractError("profile state exceeds the aggregate byte limit")
        consumed = 0
        digest = hashlib.sha256()
        with path.open("rb", buffering=0) as handle:
            before = os.fstat(handle.fileno())
            if (
                not stat.S_ISREG(before.st_mode)
                or _is_reparse(before)
                or before.st_nlink != 1
            ):
                raise ContractError(
                    "profile state contains a linked or non-regular file"
                )
            change_before = windows_change_time(handle) if os.name == "nt" else None
            while consumed <= MAX_PROFILE_STATE_FILE_BYTES:
                chunk = handle.read(
                    min(1024 * 1024, MAX_PROFILE_STATE_FILE_BYTES + 1 - consumed)
                )
                if not chunk:
                    break
                consumed += len(chunk)
                digest.update(chunk)
            change_after = windows_change_time(handle) if os.name == "nt" else None
            after = os.fstat(handle.fileno())
        path_after = os.lstat(path)
    except ContractError:
        raise
    except OSError:
        raise ContractError("profile state file could not be read") from None
    if consumed > MAX_PROFILE_STATE_FILE_BYTES:
        raise ContractError("profile state file exceeds the byte limit")
    identities = tuple(
        _identity(value) for value in (path_before, before, after, path_after)
    )
    if (len(set(identities)) != 1
            or consumed != after.st_size
            or change_before != change_after):
        raise ContractError("profile state file changed during capture")
    counters["files"] += 1
    counters["total_bytes"] += consumed
    if counters["files"] > MAX_PROFILE_STATE_TREE_FILES:
        raise ContractError("profile state contains too many files")
    counters["file_identities"].append((path, identities[-1], change_after))
    return digest.hexdigest(), consumed


def _walk_profile_directory(
    root: Path,
    path: Path,
    *,
    relative: Path,
    depth: int,
    digest: Any,
    counters: dict[str, Any],
    expected_identity: FileIdentity | None = None,
) -> None:
    if depth > MAX_PROFILE_STATE_DEPTH:
        raise ContractError("profile state exceeds the directory depth limit")
    try:
        before = os.lstat(path)
    except OSError:
        raise ContractError("profile state directory could not be inspected") from None
    if not stat.S_ISDIR(before.st_mode) or _is_reparse(before):
        raise ContractError("profile state contains a linked or non-directory entry")
    if expected_identity is not None and _identity(before) != expected_identity:
        raise ContractError("profile state directory changed during capture")
    counters["directories"] += 1
    if counters["directories"] > MAX_PROFILE_STATE_TREE_DIRECTORIES:
        raise ContractError("profile state contains too many directories")
    _update_tree_digest(
        digest,
        {"kind": "directory", "path": _safe_record_path(relative)},
    )
    try:
        with os.scandir(path) as iterator:
            entries: list[tuple[str, Path]] = []
            for entry in iterator:
                if counters["entries"] >= MAX_PROFILE_STATE_TREE_ENTRIES:
                    raise ContractError("profile state contains too many entries")
                child_relative = _bounded_entry_path(
                    relative,
                    entry.name,
                    counters,
                )
                counters["entries"] += 1
                entries.append((entry.name, child_relative))
            entries.sort(key=lambda item: (item[0].casefold(), item[0]))
    except ContractError:
        raise
    except OSError:
        raise ContractError("profile state directory could not be scanned") from None
    counters["directory_identities"].append(
        (path, _identity(before), tuple(name for name, _ in entries))
    )
    for entry_name, child_relative in entries:
        if path == root and entry_name == PROFILE_STATE_EXCLUSIONS[0]:
            continue
        child = path / entry_name
        try:
            metadata = os.lstat(child)
        except OSError:
            raise ContractError("profile state changed during directory scan") from None
        if stat.S_ISDIR(metadata.st_mode) and not _is_reparse(metadata):
            _walk_profile_directory(
                root,
                child,
                relative=child_relative,
                depth=depth + 1,
                digest=digest,
                counters=counters,
                expected_identity=_identity(metadata),
            )
        elif stat.S_ISREG(metadata.st_mode) and not _is_reparse(metadata):
            file_digest, file_bytes = _hash_profile_file(
                child,
                expected_identity=_identity(metadata),
                counters=counters,
            )
            _update_tree_digest(
                digest,
                {
                    "bytes": file_bytes,
                    "kind": "file",
                    "path": _safe_record_path(child_relative),
                    "sha256": file_digest,
                },
            )
        else:
            raise ContractError("profile state contains a linked or unsupported entry")
    try:
        after = os.lstat(path)
    except OSError:
        raise ContractError("profile state directory changed during capture") from None
    if _identity(after) != _identity(before):
        raise ContractError("profile state directory changed during capture")


def _verify_profile_tree_population(
    population: ProfileTreePopulation,
) -> None:
    directories, files = population
    for path, expected, expected_names in directories:
        try:
            observed = os.lstat(path)
            with os.scandir(path) as iterator:
                names = tuple(
                    sorted(
                        (entry.name for entry in islice(iterator, len(expected_names) + 1)),
                        key=lambda name: (name.casefold(), name),
                    )
                )
            after = os.lstat(path)
        except OSError:
            raise ContractError("profile state population changed after capture") from None
        if (names != expected_names
                or _identity(observed) != expected
                or _identity(after) != expected):
            raise ContractError("profile state population changed after capture")
    for path, expected, expected_change in files:
        try:
            observed = os.lstat(path)
            if _identity(observed) != expected:
                raise ContractError("profile state population changed after capture")
            if expected_change is not None:
                with path.open("rb", buffering=0) as handle:
                    opened = os.fstat(handle.fileno())
                    change = windows_change_time(handle)
                    closed = os.fstat(handle.fileno())
                after = os.lstat(path)
                if (change != expected_change
                        or any(
                            _identity(metadata) != expected
                            for metadata in (opened, closed, after)
                        )):
                    raise ContractError("profile state population changed after capture")
        except OSError:
            raise ContractError("profile state population changed after capture") from None


def _capture_profile_tree(
    path: Path,
) -> tuple[dict[str, Any], ProfileTreePopulation]:
    counters: dict[str, Any] = {
        "entries": 0,
        "directories": 0,
        "files": 0,
        "total_bytes": 0,
        "path_bytes": 0,
        "directory_identities": [],
        "file_identities": [],
    }
    digest = hashlib.sha256()
    digest.update(PROFILE_STATE_TREE_DOMAIN)
    digest.update(
        canonical_json_bytes({"exclusions": list(PROFILE_STATE_EXCLUSIONS)})
    )
    _walk_profile_directory(
        path,
        path,
        relative=Path(),
        depth=0,
        digest=digest,
        counters=counters,
    )
    population = (
        tuple(counters["directory_identities"]),
        tuple(counters["file_identities"]),
    )
    _verify_profile_tree_population(population)
    return {
        "digest_sha256": digest.hexdigest(),
        "directories": counters["directories"],
        "files": counters["files"],
        "total_bytes": counters["total_bytes"],
        "complete": True,
    }, population


def _binding_from_profile(profile: dict[str, Any]) -> dict[str, Any]:
    identity = profile.get("identity_contract")
    persona = profile.get("persona")
    route = profile.get("network_route")
    return {
        "document_sha256": hashlib.sha256(canonical_json_bytes(profile)).hexdigest(),
        "identity_mode": profile["identity_mode"],
        "identity_contract_sha256_16": (
            identity.get("sha256_16") if isinstance(identity, dict) else None
        ),
        "persona_sha256_16": (
            persona.get("sha256_16") if isinstance(persona, dict) else None
        ),
        "network_route_sha256_16": (
            route.get("sha256_16") if isinstance(route, dict) else None
        ),
    }


def _receipt_digest(receipt: dict[str, Any]) -> str:
    body = {key: value for key, value in receipt.items() if key != "receipt_sha256"}
    return hashlib.sha256(canonical_json_bytes(body)).hexdigest()


def validate_profile_state_receipt(document: Any) -> dict[str, Any]:
    fields = {
        "schema",
        "snapshot_id",
        "profile_id",
        "revision",
        "captured_at",
        "previous_receipt_sha256",
        "profile_binding",
        "state",
        "exclusions",
        "non_claims",
        "receipt_sha256",
    }
    if (
        not isinstance(document, dict)
        or set(document) != fields
        or document.get("schema") != PROFILE_STATE_SCHEMA
    ):
        raise ContractError("profile state receipt fields are invalid")
    validate_profile_id(document.get("snapshot_id"))
    validate_profile_id(document.get("profile_id"))
    revision = document.get("revision")
    if (
        isinstance(revision, bool)
        or not isinstance(revision, int)
        or not 1 <= revision <= MAX_PROFILE_STATE_RECEIPTS
    ):
        raise ContractError("profile state receipt revision is invalid")
    captured_at = document.get("captured_at")
    try:
        timestamp = datetime.fromisoformat(
            captured_at.replace("Z", "+00:00")
            if isinstance(captured_at, str)
            else ""
        )
    except ValueError:
        timestamp = None
    if (
        not isinstance(captured_at, str)
        or len(captured_at) > 64
        or timestamp is None
        or timestamp.utcoffset() is None
    ):
        raise ContractError("profile state receipt timestamp is invalid")
    for field in ("previous_receipt_sha256", "receipt_sha256"):
        value = document.get(field)
        if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
            raise ContractError(f"profile state receipt {field} is invalid")
    binding = document.get("profile_binding")
    if not isinstance(binding, dict) or set(binding) != {
        "document_sha256",
        "identity_mode",
        "identity_contract_sha256_16",
        "persona_sha256_16",
        "network_route_sha256_16",
    }:
        raise ContractError("profile state receipt binding is invalid")
    if (
        not isinstance(binding.get("document_sha256"), str)
        or not re.fullmatch(r"[0-9a-f]{64}", binding["document_sha256"])
        or not isinstance(binding.get("identity_mode"), str)
        or binding["identity_mode"] not in {"host-native", "host-native-pinned"}
    ):
        raise ContractError("profile state receipt binding is invalid")
    for field in (
        "identity_contract_sha256_16",
        "persona_sha256_16",
        "network_route_sha256_16",
    ):
        value = binding.get(field)
        if value is not None and (
            not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{16}", value)
        ):
            raise ContractError("profile state receipt binding is invalid")
    if (
        binding["identity_mode"] == "host-native"
        and binding["identity_contract_sha256_16"] is not None
    ) or (
        binding["identity_mode"] == "host-native-pinned"
        and binding["identity_contract_sha256_16"] is None
    ):
        raise ContractError("profile state receipt binding is inconsistent")
    state = document.get("state")
    if not isinstance(state, dict) or set(state) != {
        "digest_sha256",
        "directories",
        "files",
        "total_bytes",
        "complete",
    }:
        raise ContractError("profile state receipt summary is invalid")
    if (
        not isinstance(state.get("digest_sha256"), str)
        or not re.fullmatch(r"[0-9a-f]{64}", state["digest_sha256"])
        or state.get("complete") is not True
    ):
        raise ContractError("profile state receipt summary is invalid")
    for field, maximum in (
        ("directories", MAX_PROFILE_STATE_TREE_DIRECTORIES),
        ("files", MAX_PROFILE_STATE_TREE_FILES),
        ("total_bytes", MAX_PROFILE_STATE_TOTAL_BYTES),
    ):
        value = state.get(field)
        if (
            isinstance(value, bool)
            or not isinstance(value, int)
            or not 0 <= value <= maximum
        ):
            raise ContractError("profile state receipt summary is invalid")
    if state["directories"] < 1:
        raise ContractError("profile state receipt summary is invalid")
    if state["files"] == 0 and state["total_bytes"] != 0:
        raise ContractError("profile state receipt summary is inconsistent")
    if document.get("exclusions") != list(PROFILE_STATE_EXCLUSIONS):
        raise ContractError("profile state receipt exclusions are invalid")
    if document.get("non_claims") != list(PROFILE_STATE_NON_CLAIMS):
        raise ContractError("profile state receipt claim boundary is invalid")
    if document["receipt_sha256"] != _receipt_digest(document):
        raise ContractError("profile state receipt digest is inconsistent")
    reject_sensitive_keys(document)
    return document


def _profile_data_authorities(
    workspace: Path,
    profile_id: str,
) -> tuple[tuple[Path, tuple[int, int, int, int]], ...]:
    workspace_root = _profile_workspace_path(workspace)
    paths = (
        (workspace_root / "profiles", "profile state profiles root"),
        (workspace_root / "profiles" / "data", "profile state data root"),
        (
            profile_data_path(workspace, profile_id),
            "profile state profile data",
        ),
    )
    identities: list[tuple[Path, tuple[int, int, int, int]]] = []
    for path, label in paths:
        identity = directory_identity(path, label=label)
        if identity is None:
            raise ContractError(f"{label} is unavailable")
        identities.append((path, identity))
    return tuple(identities)


def _require_directory_authorities(
    identities: tuple[tuple[Path, tuple[int, int, int, int]], ...],
    *,
    label: str,
) -> None:
    if any(
        directory_identity(path, label=label) != identity
        for path, identity in identities
    ):
        raise ContractError(f"{label} changed")


def _existing_state_registry(
    workspace: Path,
    profile_id: str,
) -> tuple[Path, tuple[tuple[Path, tuple[int, int, int, int]], ...]] | None:
    if not isinstance(workspace, Path):
        raise ContractError("profile state workspace must be a Path")
    validate_profile_id(profile_id)
    profiles_root = _profile_workspace_path(workspace) / "profiles"
    profiles_identity = directory_identity(
        profiles_root,
        label="profile state profiles root",
    )
    if profiles_identity is None:
        raise ContractError("profile state profiles root is unavailable")
    state_root = profiles_root / "state"
    state_identity = directory_identity(state_root, label="profile state root")
    if state_identity is None:
        return None
    registry = state_root / profile_id
    registry_identity = directory_identity(
        registry,
        label="profile state receipt registry",
    )
    if registry_identity is None:
        return None
    authorities = (
        (profiles_root, profiles_identity),
        (state_root, state_identity),
        (registry, registry_identity),
    )
    _require_directory_authorities(
        authorities,
        label="profile state registry authority",
    )
    return registry, authorities


def _ensure_state_registry(
    workspace: Path,
    profile_id: str,
) -> tuple[Path, tuple[tuple[Path, tuple[int, int, int, int]], ...]]:
    workspace_root = _profile_workspace_path(workspace)
    profiles_root = workspace_root / "profiles"
    profiles_identity = directory_identity(
        profiles_root,
        label="profile state profiles root",
    )
    if profiles_identity is None:
        raise ContractError("profile state profiles root is unavailable")
    state_root = profiles_root / "state"
    require_owned_directory_ancestors(
        profiles_root, label="profile state profiles root"
    )
    if directory_identity(
        profiles_root, label="profile state profiles root"
    ) != profiles_identity:
        raise ContractError("profile state profiles root changed before creation")
    try:
        state_root.mkdir(exist_ok=True)
    except OSError:
        raise ContractError("profile state root could not be created") from None
    state_identity = directory_identity(state_root, label="profile state root")
    if state_identity is None:
        raise ContractError("profile state root is unavailable")
    registry = state_root / profile_id
    require_owned_directory_ancestors(state_root, label="profile state root")
    if (
        directory_identity(profiles_root, label="profile state profiles root")
        != profiles_identity
        or directory_identity(state_root, label="profile state root")
        != state_identity
    ):
        raise ContractError("profile state root changed before registry creation")
    try:
        registry.mkdir(exist_ok=True)
    except OSError:
        raise ContractError("profile state receipt registry could not be created") from None
    registry_identity = directory_identity(
        registry,
        label="profile state receipt registry",
    )
    if registry_identity is None:
        raise ContractError("profile state receipt registry is unavailable")
    identities = (
        (profiles_root, profiles_identity),
        (state_root, state_identity),
        (registry, registry_identity),
    )
    _require_directory_authorities(
        identities,
        label="profile state registry authority",
    )
    return registry, identities


def _receipt_inventory(registry: Path) -> BoundedJsonDirectoryInventory:
    return inventory_bounded_json_directory(
        registry,
        maximum_entries=MAX_PROFILE_STATE_RECEIPT_ENTRIES,
        maximum_files=MAX_PROFILE_STATE_RECEIPTS,
        maximum_file_bytes=MAX_PROFILE_STATE_RECEIPT_BYTES,
        maximum_total_bytes=MAX_PROFILE_STATE_RECEIPT_TOTAL_BYTES,
        label="profile state receipt registry",
        require_json_only=True,
    )


def _load_profile_state_receipt_snapshot(
    path: Path,
) -> tuple[dict[str, Any], tuple[int, int, int, int, int, int]]:
    snapshot = read_bounded_control_snapshot_result(
        path,
        maximum=MAX_PROFILE_STATE_RECEIPT_BYTES,
        label="profile state receipt",
        require_single_link=True,
    )
    if snapshot.state != "complete" or snapshot.body is None or snapshot.identity is None:
        raise ContractError(f"profile state receipt is {snapshot.state}")
    try:
        document = validate_profile_state_receipt(
            load_canonical_json_document(snapshot.body, label="profile state receipt")
        )
    except ContractError:
        raise ContractError("profile state receipt is invalid") from None
    return document, snapshot.identity


def _load_receipt_chain(
    registry: Path,
    profile_id: str,
    inventory: BoundedJsonDirectoryInventory,
) -> list[dict[str, Any]]:
    receipts: list[dict[str, Any]] = []
    for filename, expected_identity in inventory.files:
        snapshot_id = filename[:-5]
        validate_profile_id(snapshot_id)
        receipt, identity = _load_profile_state_receipt_snapshot(registry / filename)
        if (
            identity != expected_identity
            or receipt["snapshot_id"] != snapshot_id
            or receipt["profile_id"] != profile_id
        ):
            raise ContractError("profile state receipt registry binding is invalid")
        receipts.append(receipt)
    if len({receipt["snapshot_id"].casefold() for receipt in receipts}) != len(receipts):
        raise ContractError("profile state receipt registry contains duplicate snapshot IDs")
    receipts.sort(key=lambda item: item["revision"])
    previous = "0" * 64
    for revision, receipt in enumerate(receipts, start=1):
        if (
            receipt["revision"] != revision
            or receipt["previous_receipt_sha256"] != previous
        ):
            raise ContractError("profile state receipt chain is invalid")
        previous = receipt["receipt_sha256"]
    return receipts


def list_profile_state_receipts(
    workspace: Path,
    profile_id: str,
) -> list[dict[str, Any]]:
    if not isinstance(workspace, Path):
        raise ContractError("profile state workspace must be a Path")
    workspace = _profile_workspace_path(workspace)
    profile_body = canonical_json_bytes(load_profile(workspace, profile_id))
    existing = _existing_state_registry(workspace, profile_id)
    if existing is None:
        receipts = []
    else:
        registry, authorities = existing
        before = _receipt_inventory(registry)
        receipts = _load_receipt_chain(registry, profile_id, before)
        if _receipt_inventory(registry) != before:
            raise ContractError("profile state receipt registry changed during load")
    if canonical_json_bytes(load_profile(workspace, profile_id)) != profile_body:
        raise ContractError("profile document changed during state receipt listing")
    # A missing registry can appear during the final profile read, and a
    # present one can disappear or be replaced there. Bind that authority
    # before returning either an empty or a populated result.
    if _existing_state_registry(workspace, profile_id) != existing:
        raise ContractError("profile state receipt registry changed during load")
    if existing is not None:
        # Windows file identity can survive an in-place, same-size edit with
        # restored mtime. Verify bounded receipt contents after the profile
        # read, then recheck the inventory and its directory authorities.
        if (_load_receipt_chain(registry, profile_id, before) != receipts
                or _receipt_inventory(registry) != before):
            raise ContractError("profile state receipt registry changed during load")
        _require_directory_authorities(
            authorities,
            label="profile state registry authority",
        )
        # Keep the original profile binding after the final receipt scan as
        # well. This catches a profile edit made while that scan was running.
        if canonical_json_bytes(load_profile(workspace, profile_id)) != profile_body:
            raise ContractError("profile document changed during state receipt listing")
        # The last profile read can outlast the preceding receipt scan.
        # Recheck bounded receipt bytes once more before returning; the
        # registry permits at most 4,096 files / 256 MiB per pass.
        if (
            _existing_state_registry(workspace, profile_id) != existing
            or _load_receipt_chain(registry, profile_id, before) != receipts
            or _receipt_inventory(registry) != before
        ):
            raise ContractError("profile state receipt registry changed during load")
    return receipts


def capture_profile_state(
    workspace: Path,
    profile_id: str,
    snapshot_id: str,
) -> dict[str, Any]:
    if not isinstance(workspace, Path):
        raise ContractError("profile state workspace must be a Path")
    workspace = _profile_workspace_path(workspace)
    profile_id = validate_profile_id(profile_id)
    snapshot_id = validate_profile_id(snapshot_id)
    if is_disposable_profile_id(profile_id):
        raise ContractError("profile state receipts require a persistent named profile")
    data_authorities = _profile_data_authorities(workspace, profile_id)
    owner = f"state-{snapshot_id}"
    lock = acquire_profile_lock(workspace, profile_id, owner)
    try:
        _require_directory_authorities(
            data_authorities,
            label="profile state data authority",
        )
        profile_before = load_profile(workspace, profile_id)
        profile_before_body = canonical_json_bytes(profile_before)
        registry, registry_identities = _ensure_state_registry(
            workspace,
            profile_id,
        )
        before = _receipt_inventory(registry)
        prior = _load_receipt_chain(registry, profile_id, before)
        if _receipt_inventory(registry) != before:
            raise ContractError("profile state receipt registry changed during load")
        if len(prior) >= MAX_PROFILE_STATE_RECEIPTS:
            raise ContractError("profile state receipt registry is full")
        destination = registry / f"{snapshot_id}.json"
        if any(
            receipt["snapshot_id"].casefold() == snapshot_id.casefold()
            for receipt in prior
        ):
            raise ContractError("profile state snapshot ID already exists")

        state, state_population = _capture_profile_tree(
            profile_data_path(workspace, profile_id)
        )
        profile_after = load_profile(workspace, profile_id)
        if canonical_json_bytes(profile_after) != profile_before_body:
            raise ContractError("profile document changed during state capture")
        if _receipt_inventory(registry) != before:
            raise ContractError("profile state receipt registry changed before publication")
        receipt: dict[str, Any] = {
            "schema": PROFILE_STATE_SCHEMA,
            "snapshot_id": snapshot_id,
            "profile_id": profile_id,
            "revision": len(prior) + 1,
            "captured_at": _utc_now(),
            "previous_receipt_sha256": (
                prior[-1]["receipt_sha256"] if prior else "0" * 64
            ),
            "profile_binding": _binding_from_profile(profile_before),
            "state": state,
            "exclusions": list(PROFILE_STATE_EXCLUSIONS),
            "non_claims": list(PROFILE_STATE_NON_CLAIMS),
        }
        receipt["receipt_sha256"] = _receipt_digest(receipt)
        validate_profile_state_receipt(receipt)
        publish_json_exclusive(
            destination,
            receipt,
            maximum=MAX_PROFILE_STATE_RECEIPT_BYTES,
            label="profile state receipt",
        )
        published, published_identity = _load_profile_state_receipt_snapshot(
            destination
        )
        if published != receipt:
            raise ContractError("profile state receipt changed after publication")
        after = _receipt_inventory(registry)
        before_files = dict(before.files)
        after_files = dict(after.files)
        if (
            len(after_files) != len(before_files) + 1
            or any(after_files.get(name) != identity for name, identity in before.files)
            or after_files.get(destination.name) != published_identity
        ):
            raise ContractError("profile state receipt registry changed during publication")
        _require_directory_authorities(
            registry_identities,
            label="profile state registry authority",
        )
        _require_directory_authorities(
            data_authorities,
            label="profile state data authority",
        )
        if canonical_json_bytes(load_profile(workspace, profile_id)) != profile_before_body:
            raise ContractError("profile document changed during state capture")
        _verify_profile_tree_population(state_population)
        _require_directory_authorities(
            registry_identities,
            label="profile state registry authority",
        )
        _require_directory_authorities(
            data_authorities,
            label="profile state data authority",
        )
        if canonical_json_bytes(load_profile(workspace, profile_id)) != profile_before_body:
            raise ContractError("profile document changed during state capture")
        final_receipt, final_identity = _load_profile_state_receipt_snapshot(
            destination
        )
        if final_receipt != receipt or final_identity != published_identity:
            raise ContractError("profile state receipt changed before completion")
        final_chain = _load_receipt_chain(registry, profile_id, after)
        if final_chain != [*prior, receipt] or _receipt_inventory(registry) != after:
            raise ContractError("profile state receipt chain changed after publication")
        if canonical_json_bytes(load_profile(workspace, profile_id)) != profile_before_body:
            raise ContractError("profile document changed during state capture")
        # The final receipt scan can outlast the earlier data-tree check.
        _verify_profile_tree_population(state_population)
        return receipt
    finally:
        release_profile_lock(lock, owner, missing_ok=False)
