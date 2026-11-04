from __future__ import annotations

import copy
import json
import re
import hashlib
import os
import uuid
from functools import wraps
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .control_files import (
    BoundedControlSnapshot,
    PublishedControlSnapshot,
    canonical_json_bytes,
    decode_strict_json_bytes,
    inventory_bounded_json_directory,
    load_canonical_json_document,
    publish_json_exclusive,
    publish_json_exclusive_result,
    read_bounded_control_snapshot_result,
    replace_json_conditionally,
    remove_control_conditionally,
)

from .contracts import ContractError
from .owned_paths import (
    DirectoryIdentity,
    directory_identity,
    prepare_owned_directory_parent,
    require_owned_directory_ancestors,
    remove_owned_directory_tree,
)


PROFILE_SCHEMA = "browser-core.profile/1"
MAX_PROFILE_DOCUMENT_BYTES = 64 * 1024
MAX_IDENTITY_CONTRACT_BYTES = 64 * 1024
MAX_IDENTITY_CONTRACT_CLAIMS = 128
MAX_PROFILE_REGISTRY_FILES = 4096
MAX_PROFILE_REGISTRY_ENTRIES = 8192
MAX_PROFILE_REGISTRY_BYTES = 256 * 1024 * 1024
PROFILE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
WINDOWS_DEVICE_BASENAMES = frozenset({"CON", "PRN", "AUX", "NUL"}) | frozenset(
    f"{prefix}{number}" for prefix in ("COM", "LPT") for number in range(1, 10)
)
IDENTITY_PATH_RE = re.compile(r"^[A-Za-z][A-Za-z0-9]*(?:\.[A-Za-z][A-Za-z0-9]*)+$")
IDENTITY_ALLOWED_ROOTS = {
    "automation",
    "iframe",
    "permissions",
    "rendering",
    "surfaces",
    "userAgentData",
    "window",
    "worker",
}
IDENTITY_DENIED_FRAGMENTS = {
    "authorization",
    "cookie",
    "credential",
    "password",
    "secret",
    "session",
    "token",
}


def is_valid_identity_claim_path(value: Any) -> bool:
    return (
        type(value) is str
        and IDENTITY_PATH_RE.fullmatch(value) is not None
        and value.split(".", 1)[0] in IDENTITY_ALLOWED_ROOTS
        and not any(
            fragment in value.lower() for fragment in IDENTITY_DENIED_FRAGMENTS
        )
    )


def validate_identity_claim_path(value: Any) -> str:
    if type(value) is not str or IDENTITY_PATH_RE.fullmatch(value) is None:
        raise ContractError("invalid identity claim path")
    if value.split(".", 1)[0] not in IDENTITY_ALLOWED_ROOTS:
        raise ContractError("identity claim root is not allowed")
    if any(fragment in value.lower() for fragment in IDENTITY_DENIED_FRAGMENTS):
        raise ContractError("identity claim path is sensitive or ambiguous")
    return value


def _created_at() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _write_json_atomic(
    path: Path,
    document: dict[str, Any],
    *,
    expected: BoundedControlSnapshot | None = None,
) -> PublishedControlSnapshot | None:
    prepare_owned_directory_parent(path.parent, label="profile registry parent")
    if expected is None:
        return publish_json_exclusive_result(
            path,
            document,
            maximum=MAX_PROFILE_DOCUMENT_BYTES,
            label="profile document",
        )
    if (
        expected.state != "complete"
        or expected.body is None
        or expected.identity is None
    ):
        raise ContractError("profile document changed before update")
    replace_json_conditionally(
        path,
        document,
        expected_body=expected.body,
        expected_identity=expected.identity,
        maximum=MAX_PROFILE_DOCUMENT_BYTES,
        label="profile document",
    )


def is_valid_profile_id(profile_id: Any) -> bool:
    return (
        isinstance(profile_id, str)
        and PROFILE_ID_RE.fullmatch(profile_id) is not None
        and not profile_id.endswith(".")
        and not has_windows_device_basename(profile_id)
    )


def has_windows_device_basename(value: str) -> bool:
    """Whether Win32 interprets this identifier as a device, even with a suffix."""
    return value.split(".", 1)[0].upper() in WINDOWS_DEVICE_BASENAMES


def validate_profile_id(profile_id: str) -> str:
    if not is_valid_profile_id(profile_id):
        raise ContractError("profile ID must be 1-64 safe ASCII characters")
    return profile_id


def _profile_workspace_path(workspace: Path) -> Path:
    if not isinstance(workspace, Path):
        raise ContractError("profile workspace must be a Path")
    path = Path(os.path.abspath(workspace))
    for ancestor in reversed((path, *path.parents)):
        directory_identity(ancestor, label="profile workspace")
    return path


def _registry_path(workspace: Path, profile_id: str) -> Path:
    validate_profile_id(profile_id)
    return _profile_workspace_path(workspace) / "profiles" / "registry" / f"{profile_id}.json"


def profile_data_path(workspace: Path, profile_id: str) -> Path:
    validate_profile_id(profile_id)
    return _profile_workspace_path(workspace) / "profiles" / "data" / profile_id


def validate_profile(document: Any) -> dict[str, Any]:
    if not isinstance(document, dict) or document.get("schema") != PROFILE_SCHEMA:
        raise ContractError("unsupported profile document")
    allowed = {
        "schema",
        "id",
        "name",
        "created_at",
        "identity_mode",
        "identity_contract",
        "persona",
        "network_route",
    }
    required = {"schema", "id", "name", "created_at", "identity_mode"}
    if not required.issubset(document) or set(document) - allowed:
        raise ContractError("profile document fields are invalid")
    validate_profile_id(document.get("id"))
    name = document.get("name")
    if not isinstance(name, str) or not name.strip() or len(name) > 128:
        raise ContractError("profile name must be 1-128 characters")
    if any(
        ord(character) < 32
        or ord(character) == 127
        or 0xD800 <= ord(character) <= 0xDFFF
        for character in name
    ):
        raise ContractError("profile name must be 1-128 characters")
    created_at = document.get("created_at")
    if not isinstance(created_at, str) or len(created_at) > 64:
        raise ContractError("profile created_at is invalid")
    try:
        created_at_value = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
    except ValueError:
        raise ContractError("profile created_at is invalid") from None
    if created_at_value.utcoffset() is None:
        raise ContractError("profile created_at is invalid")
    if (
        not isinstance(document.get("identity_mode"), str)
        or document["identity_mode"] not in {"host-native", "host-native-pinned"}
    ):
        raise ContractError("unsupported profile identity mode")
    identity = document.get("identity_contract")
    if identity is not None:
        if not isinstance(identity, dict):
            raise ContractError("profile identity contract metadata must be an object")
        if set(identity) != {"file", "sha256_16", "fields"}:
            raise ContractError("profile identity contract metadata fields are invalid")
        if identity.get("file") != "identity-contract.json":
            raise ContractError("profile identity contract filename is invalid")
        digest = identity.get("sha256_16")
        if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{16}", digest):
            raise ContractError("profile identity contract digest is invalid")
        fields = identity.get("fields")
        if (
            not isinstance(fields, list)
            or not 1 <= len(fields) <= MAX_IDENTITY_CONTRACT_CLAIMS
            or not all(is_valid_identity_claim_path(item) for item in fields)
            or len(set(fields)) != len(fields)
        ):
            raise ContractError("profile identity contract fields are invalid")
    if (document["identity_mode"] == "host-native-pinned") != (identity is not None):
        raise ContractError("profile identity mode and contract metadata are inconsistent")
    for field, label in (("persona", "persona"), ("network_route", "network route")):
        binding = document.get(field)
        if binding is not None:
            if not isinstance(binding, dict) or set(binding) != {"id", "sha256_16"}:
                raise ContractError(f"profile {label} binding is invalid")
            if (
                not isinstance(binding["id"], str)
                or not PROFILE_ID_RE.fullmatch(binding["id"])
                or has_windows_device_basename(binding["id"])
            ):
                raise ContractError(f"profile {label} ID is invalid")
            if not isinstance(binding["sha256_16"], str) or not re.fullmatch(
                r"[0-9a-f]{16}", binding["sha256_16"]
            ):
                raise ContractError(f"profile {label} digest is invalid")
    return document


def create_profile(
    workspace: Path, profile_id: str, name: str | None = None
) -> dict[str, Any]:
    profile_id = validate_profile_id(profile_id)
    if name is not None and not isinstance(name, str):
        raise ContractError("profile name must be 1-128 characters")
    document = validate_profile(
        {
            "schema": PROFILE_SCHEMA,
            "id": profile_id,
            "name": name or profile_id,
            "created_at": _created_at(),
            "identity_mode": "host-native",
        }
    )
    path = _registry_path(workspace, profile_id)
    if path.exists():
        raise ContractError(f"profile already exists: {profile_id}")
    data_path = profile_data_path(workspace, profile_id)
    prepare_owned_directory_parent(data_path.parent, label="profile creation data parent")
    require_owned_directory_ancestors(data_path.parent, label="profile creation data parent")
    data_parent_identity = directory_identity(data_path.parent, label="profile creation data parent")
    if data_parent_identity is None:
        raise ContractError("profile creation data parent is unavailable")
    try:
        data_path.mkdir(exist_ok=False)
    except FileExistsError:
        # A data directory without its registry entry is still somebody's
        # existing state. Do not enter the rollback path for a tree we did not
        # create, or expose a filesystem exception to the caller.
        raise ContractError("profile data already exists") from None
    except OSError:
        raise ContractError("profile data could not be created") from None
    data_identity = directory_identity(data_path, label="profile creation data")
    if data_identity is None:
        raise ContractError("profile creation data is unavailable")
    published: PublishedControlSnapshot | None = None
    registry_parent_identity: DirectoryIdentity | None = None
    try:
        require_owned_directory_ancestors(data_path.parent, label="profile creation data parent")
        if directory_identity(data_path.parent, label="profile creation data parent") != data_parent_identity:
            raise ContractError("profile creation data parent changed")
        prepare_owned_directory_parent(path.parent, label="profile registry parent")
        require_owned_directory_ancestors(path.parent, label="profile registry parent")
        registry_parent_identity = directory_identity(path.parent, label="profile registry parent")
        if registry_parent_identity is None:
            raise ContractError("profile registry parent is unavailable")
        published = _write_json_atomic(path, document)
        if published is None:
            raise ContractError("profile document publication changed")
        require_owned_directory_ancestors(data_path.parent, label="profile creation data parent")
        if (directory_identity(data_path.parent, label="profile creation data parent") != data_parent_identity
                or directory_identity(data_path, label="profile creation data") != data_identity):
            raise ContractError("profile creation data changed")
        require_owned_directory_ancestors(path.parent, label="profile registry parent")
        saved = read_bounded_control_snapshot_result(
            path,
            maximum=MAX_PROFILE_DOCUMENT_BYTES,
            label="profile document",
            require_single_link=True,
        )
        require_owned_directory_ancestors(path.parent, label="profile registry parent")
        if directory_identity(path.parent, label="profile registry parent") != registry_parent_identity:
            raise ContractError("profile registry parent changed after publication")
        if (saved.state != "complete" or saved.body != published.body
                or saved.identity != published.identity):
            raise ContractError("profile document changed after publication")
        require_owned_directory_ancestors(data_path.parent, label="profile creation data parent")
        if (directory_identity(data_path.parent, label="profile creation data parent") != data_parent_identity
                or directory_identity(data_path, label="profile creation data") != data_identity):
            raise ContractError("profile creation data changed after publication")
    except (Exception, KeyboardInterrupt) as active_error:
        rollback_incomplete = False
        try:
            # Creation never places children in this directory. Another actor's
            # new file must prevent rollback, rather than be recursively erased.
            require_owned_directory_ancestors(
                data_path.parent, label="profile creation data parent"
            )
            if (directory_identity(data_path.parent, label="profile creation data parent")
                    != data_parent_identity
                    or directory_identity(data_path, label="profile creation data")
                    != data_identity):
                raise ContractError("profile creation data changed before rollback")
            try:
                os.rmdir(data_path)
            except OSError:
                raise ContractError("profile creation data is not empty for rollback") from None
            require_owned_directory_ancestors(
                data_path.parent, label="profile creation data parent"
            )
            if (directory_identity(data_path.parent, label="profile creation data parent")
                    != data_parent_identity
                    or directory_identity(data_path, label="profile creation data")
                    is not None):
                raise ContractError("profile creation data changed during rollback")
        except ContractError:
            rollback_incomplete = True
        if published is not None:
            try:
                require_owned_directory_ancestors(path.parent, label="profile registry parent")
                if directory_identity(path.parent, label="profile registry parent") != registry_parent_identity:
                    raise ContractError("profile registry parent changed before rollback")
                remove_control_conditionally(
                    path,
                    expected_body=published.body,
                    expected_identity=published.identity,
                    maximum=MAX_PROFILE_DOCUMENT_BYTES,
                    label="profile document",
                )
                require_owned_directory_ancestors(path.parent, label="profile registry parent")
                if (directory_identity(path.parent, label="profile registry parent") != registry_parent_identity
                        or os.path.lexists(path)):
                    raise ContractError("profile document changed during rollback")
            except ContractError:
                rollback_incomplete = True
        if rollback_incomplete:
            from .errors import ProfileCreationRollbackError
            raise ProfileCreationRollbackError(
                "profile creation rollback incomplete"
            ) from active_error
        raise
    return document


def load_profile(workspace: Path, profile_id: str) -> dict[str, Any]:
    document, _snapshot = _load_profile_snapshot(workspace, profile_id)
    return document


def _load_profile_snapshot(
    workspace: Path, profile_id: str, *, read_bytes: list[int] | None = None
) -> tuple[dict[str, Any], BoundedControlSnapshot]:
    path = _registry_path(workspace, validate_profile_id(profile_id))
    parent_identity = directory_identity(path.parent, label="profile registry parent")
    if parent_identity is None:
        raise ContractError("profile document is missing")
    ancestors = tuple(reversed((path.parent, *path.parent.parents)))

    def registry_ancestry() -> tuple[DirectoryIdentity | None, ...]:
        return tuple(
            directory_identity(ancestor, label="profile registry ancestry")
            for ancestor in ancestors
        )

    ancestry_before = registry_ancestry()
    if ancestry_before[-1] != parent_identity:
        raise ContractError("profile registry ancestry changed during read")
    require_owned_directory_ancestors(path.parent, label="profile registry parent")
    snapshot = read_bounded_control_snapshot_result(
        path,
        maximum=MAX_PROFILE_DOCUMENT_BYTES,
        label="profile document",
        require_single_link=True,
    )
    if snapshot.state != "complete" or snapshot.body is None:
        raise ContractError(f"profile document is {snapshot.state}")
    if read_bytes is not None:
        read_bytes[0] += len(snapshot.body)
    try:
        document = copy.deepcopy(
            validate_profile(
                load_canonical_json_document(snapshot.body, label="profile document")
            )
        )
    except ContractError:
        raise ContractError(
            "cannot read profile document: invalid managed document"
        ) from None
    if document["id"] != profile_id:
        raise ContractError(
            "cannot read profile document: filename does not match profile ID"
        )
    require_owned_directory_ancestors(path.parent, label="profile registry parent")
    if directory_identity(path.parent, label="profile registry parent") != parent_identity:
        raise ContractError("profile registry parent changed during read")
    if registry_ancestry() != ancestry_before:
        raise ContractError("profile registry ancestry changed during read")
    repeated = read_bounded_control_snapshot_result(
        path,
        maximum=MAX_PROFILE_DOCUMENT_BYTES,
        label="profile document",
        require_single_link=True,
    )
    if read_bytes is not None and repeated.body is not None:
        read_bytes[0] += len(repeated.body)
    require_owned_directory_ancestors(path.parent, label="profile registry parent")
    if (directory_identity(path.parent, label="profile registry parent") != parent_identity
            or repeated.state != "complete"
            or repeated.body != snapshot.body
            or repeated.identity != snapshot.identity):
        raise ContractError("profile document changed during read")
    if registry_ancestry() != ancestry_before:
        raise ContractError("profile registry ancestry changed during read")
    return document, snapshot


def list_profiles(workspace: Path) -> list[dict[str, Any]]:
    registry = _profile_workspace_path(workspace) / "profiles" / "registry"
    ancestors = tuple(reversed((registry, *registry.parents)))

    def registry_ancestry() -> tuple[DirectoryIdentity | None, ...]:
        return tuple(
            directory_identity(path, label="profile registry ancestry")
            for path in ancestors
        )

    parent_snapshot = registry_ancestry()

    def require_inventory_root(observed: tuple[int, int, int, int, int, int] | None) -> None:
        expected = parent_snapshot[-1]
        if (expected is None) != (observed is None) or (
            expected is not None and observed is not None
            and observed[:2] != expected[:2]
        ):
            raise ContractError("profile registry changed during inventory")

    before = inventory_bounded_json_directory(
        registry,
        maximum_entries=MAX_PROFILE_REGISTRY_ENTRIES,
        maximum_files=MAX_PROFILE_REGISTRY_FILES,
        maximum_file_bytes=MAX_PROFILE_DOCUMENT_BYTES,
        maximum_total_bytes=MAX_PROFILE_REGISTRY_BYTES,
        label="profile registry",
    )
    require_inventory_root(before.directory_identity)
    profiles: list[dict[str, Any]] = []
    loaded_snapshots: list[tuple[str, BoundedControlSnapshot]] = []
    for name, expected_identity in before.files:
        stem = name[:-5]
        validate_profile_id(stem)
        profile, snapshot = _load_profile_snapshot(workspace, stem)
        if snapshot.identity != expected_identity:
            raise ContractError("profile changed during registry load")
        profiles.append(profile)
        loaded_snapshots.append((stem, snapshot))
    after = inventory_bounded_json_directory(
        registry,
        maximum_entries=MAX_PROFILE_REGISTRY_ENTRIES,
        maximum_files=MAX_PROFILE_REGISTRY_FILES,
        maximum_file_bytes=MAX_PROFILE_DOCUMENT_BYTES,
        maximum_total_bytes=MAX_PROFILE_REGISTRY_BYTES,
        label="profile registry",
    )
    require_inventory_root(after.directory_identity)
    if after != before:
        raise ContractError("profile registry changed during load")
    if len({profile["id"].casefold() for profile in profiles}) != len(profiles):
        raise ContractError("profile registry contains duplicate IDs")
    # File metadata can remain identical after an in-place edit with restored
    # mtime on Windows. Bind returned documents to their final contents too.
    for stem, original_snapshot in loaded_snapshots:
        _, current_snapshot = _load_profile_snapshot(workspace, stem)
        if (current_snapshot.body != original_snapshot.body
                or current_snapshot.identity != original_snapshot.identity):
            raise ContractError("profile changed during registry load")
    final = inventory_bounded_json_directory(
        registry,
        maximum_entries=MAX_PROFILE_REGISTRY_ENTRIES,
        maximum_files=MAX_PROFILE_REGISTRY_FILES,
        maximum_file_bytes=MAX_PROFILE_DOCUMENT_BYTES,
        maximum_total_bytes=MAX_PROFILE_REGISTRY_BYTES,
        label="profile registry",
    )
    require_inventory_root(final.directory_identity)
    if final != before:
        raise ContractError("profile registry changed during load")
    if registry_ancestry() != parent_snapshot:
        raise ContractError("profile registry ancestry changed during load")
    return profiles


def canonicalize_identity_contract(raw: bytes) -> tuple[bytes, dict[str, Any]]:
    if not isinstance(raw, bytes):
        raise ContractError("identity contract must be bytes")
    if len(raw) > MAX_IDENTITY_CONTRACT_BYTES:
        raise ContractError("identity contract is larger than 64 KiB")
    payload = decode_strict_json_bytes(raw, label="identity contract")
    if (
        not isinstance(payload, dict)
        or type(payload.get("schema_version")) is not int
        or payload["schema_version"] != 1
    ):
        raise ContractError("identity contract must use schema_version 1")
    if set(payload) != {"schema_version", "expected"}:
        raise ContractError("identity contract fields are invalid")
    expected = payload.get("expected")
    if (
        not isinstance(expected, dict)
        or not expected
        or len(expected) > MAX_IDENTITY_CONTRACT_CLAIMS
    ):
        raise ContractError("identity contract must contain 1-128 expected claims")
    normalized: dict[str, Any] = {}
    for claim, value in expected.items():
        path = validate_identity_claim_path(claim)
        if isinstance(value, dict) or (
            isinstance(value, list)
            and any(isinstance(item, (dict, list)) for item in value)
        ):
            raise ContractError("identity claim must target a leaf")
        try:
            encoded_value = json.dumps(
                value,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
                allow_nan=False,
            )
        except (TypeError, ValueError) as exc:
            raise ContractError(
                f"identity claim is not strict JSON ({type(exc).__name__})"
            ) from None
        if len(encoded_value.encode("utf-8")) > 4096:
            raise ContractError("identity claim is too large")
        normalized[path] = value
    canonical = canonical_json_bytes({"schema_version": 1, "expected": normalized})
    metadata = {
        "file": "identity-contract.json",
        "sha256_16": hashlib.sha256(canonical[:-1]).hexdigest()[:16],
        "fields": sorted(normalized),
    }
    return canonical, metadata


def _read_identity_contract_bytes(
    path: Path, *, read_bytes: list[int] | None = None
) -> bytes:
    snapshot = read_bounded_control_snapshot_result(
        path,
        maximum=MAX_IDENTITY_CONTRACT_BYTES,
        label="identity contract",
        require_single_link=True,
    )
    if snapshot.state != "complete" or snapshot.body is None:
        raise ContractError(f"identity contract is {snapshot.state}")
    if read_bytes is not None:
        read_bytes[0] += len(snapshot.body)
    return snapshot.body


def _ensure_identity_contract(
    destination: Path,
    canonical: bytes,
    metadata: dict[str, Any],
) -> None:
    snapshot = read_bounded_control_snapshot_result(
        destination,
        maximum=MAX_IDENTITY_CONTRACT_BYTES,
        label="profile identity contract",
        require_single_link=True,
    )
    if snapshot.state == "missing":
        try:
            payload = json.loads(canonical.decode("ascii", errors="strict"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise ContractError("canonical identity contract is invalid") from None
        published = publish_json_exclusive(
            destination,
            payload,
            maximum=MAX_IDENTITY_CONTRACT_BYTES,
            label="profile identity contract",
        )
        if published != canonical:
            raise ContractError("profile identity contract publication changed")
        return
    if snapshot.state != "complete" or snapshot.body is None:
        raise ContractError(f"profile identity contract is {snapshot.state}")
    existing_canonical, existing_metadata = canonicalize_identity_contract(
        snapshot.body
    )
    if existing_canonical != canonical or existing_metadata != metadata:
        raise ContractError(
            "profile identity contract is already pinned to different claims"
        )


def _exclusive_profile_mutation(function: Any) -> Any:
    @wraps(function)
    def guarded(workspace: Path, profile_id: str, *args: Any, **kwargs: Any) -> Any:
        owner = f"mutation-{uuid.uuid4().hex}"
        lock_path = acquire_profile_lock(workspace, profile_id, owner)
        try:
            return function(workspace, profile_id, *args, **kwargs)
        finally:
            release_profile_lock(lock_path, owner, missing_ok=False)

    return guarded


@_exclusive_profile_mutation
def attach_identity_contract(
    workspace: Path,
    profile_id: str,
    contract_path: Path,
) -> dict[str, Any]:
    if not isinstance(contract_path, Path):
        raise ContractError("identity contract path must be a Path")
    document, profile_snapshot = _load_profile_snapshot(workspace, profile_id)
    raw = _read_identity_contract_bytes(contract_path.absolute())
    canonical, metadata = canonicalize_identity_contract(raw)
    destination = profile_data_path(workspace, profile_id) / metadata["file"]
    _ensure_identity_contract(destination, canonical, metadata)
    document["identity_mode"] = "host-native-pinned"
    document["identity_contract"] = metadata
    validate_profile(document)
    _write_json_atomic(
        _registry_path(workspace, profile_id), document, expected=profile_snapshot
    )
    _require_attached_identity(workspace, profile_id, document, canonical)
    return document


def _attach_identity_bytes(
    workspace: Path,
    profile_id: str,
    document: dict[str, Any],
    raw: bytes,
) -> tuple[dict[str, Any], bytes]:
    canonical, metadata = canonicalize_identity_contract(raw)
    destination = profile_data_path(workspace, profile_id) / metadata["file"]
    _ensure_identity_contract(destination, canonical, metadata)
    document["identity_mode"] = "host-native-pinned"
    document["identity_contract"] = metadata
    return document, canonical


@_exclusive_profile_mutation
def attach_persona(workspace: Path, profile_id: str, persona_id: str) -> dict[str, Any]:
    from .personas import load_persona

    document, profile_snapshot = _load_profile_snapshot(workspace, profile_id)
    persona = load_persona(workspace, persona_id)
    if persona["kernel"] != {
        "engine": "chromium",
        "product": "browser-core",
        "minimum_major": persona["kernel"]["minimum_major"],
        "maximum_major": persona["kernel"]["maximum_major"],
    }:
        raise ContractError(
            "named Browser Core profiles require a browser-core Chromium persona"
        )
    document, canonical = _attach_identity_bytes(
        workspace,
        profile_id,
        document,
        json.dumps(
            persona["identity_contract"], sort_keys=True, separators=(",", ":")
        ).encode("utf-8"),
    )
    document["persona"] = {
        "id": persona_id,
        "sha256_16": persona["integrity_sha256"][:16],
    }
    validate_profile(document)
    _write_json_atomic(
        _registry_path(workspace, profile_id), document, expected=profile_snapshot
    )
    _require_attached_identity(workspace, profile_id, document, canonical)
    _require_attached_persona(workspace, profile_id, document, persona)
    # The catalog read can outlast the earlier pinned-identity check.
    _require_attached_identity(workspace, profile_id, document, canonical)
    # The final identity read can outlast the catalog check.
    _require_attached_persona(workspace, profile_id, document, persona)
    return document


@_exclusive_profile_mutation
def attach_network_route(
    workspace: Path, profile_id: str, route_id: str
) -> dict[str, Any]:
    from .network import load_network_route

    document, profile_snapshot = _load_profile_snapshot(workspace, profile_id)
    route = load_network_route(workspace, route_id)
    document["network_route"] = {
        "id": route_id,
        "sha256_16": route["integrity_sha256"][:16],
    }
    validate_profile(document)
    _write_json_atomic(
        _registry_path(workspace, profile_id), document, expected=profile_snapshot
    )
    saved, saved_snapshot = _load_profile_snapshot(workspace, profile_id)
    if saved != document or load_network_route(workspace, route_id) != route:
        raise ContractError("profile network route attachment changed")
    # The route read can outlast the saved-profile check.
    _, final_snapshot = _load_profile_snapshot(workspace, profile_id)
    if (final_snapshot.body != saved_snapshot.body
            or final_snapshot.identity != saved_snapshot.identity):
        raise ContractError("profile network route attachment changed")
    # The second route load can return just before the saved route changes.
    # Profile writes are serialized by the held profile lock; finish with a
    # fresh route read so success is bound to the current unguarded source.
    if load_network_route(workspace, route_id) != route:
        raise ContractError("profile network route attachment changed")
    return document


def profile_bindings(workspace: Path, profile_id: str) -> dict[str, Any]:
    from .network import load_network_route
    from .personas import load_persona

    registry_parent = _registry_path(workspace, profile_id).parent
    ancestors = tuple(reversed((registry_parent, *registry_parent.parents)))

    def registry_ancestry() -> tuple[DirectoryIdentity | None, ...]:
        return tuple(
            directory_identity(ancestor, label="profile registry ancestry")
            for ancestor in ancestors
        )

    ancestry_before = registry_ancestry()
    document, profile_snapshot = _load_profile_snapshot(workspace, profile_id)
    if registry_ancestry() != ancestry_before:
        raise ContractError("profile registry ancestry changed during binding load")
    result: dict[str, Any] = {}
    persona_binding = document.get("persona")
    if persona_binding is not None:
        persona = load_persona(workspace, persona_binding["id"])
        if persona["integrity_sha256"][:16] != persona_binding["sha256_16"]:
            raise ContractError("profile persona binding has changed")
        result["persona"] = persona
    route_binding = document.get("network_route")
    if route_binding is not None:
        route = load_network_route(workspace, route_binding["id"])
        if route["integrity_sha256"][:16] != route_binding["sha256_16"]:
            raise ContractError("profile network route binding has changed")
        result["network_route"] = route
    if "persona" in result and "network_route" in result:
        persona_geo = result["persona"]["geography"]
        route_geo = result["network_route"]["geography"]
        for field in ("country", "locale", "timezone"):
            if persona_geo[field].casefold() != route_geo[field].casefold():
                raise ContractError(
                    f"profile persona and network route disagree on {field}"
                )
    _, current_snapshot = _load_profile_snapshot(workspace, profile_id)
    if (current_snapshot.body != profile_snapshot.body
            or current_snapshot.identity != profile_snapshot.identity):
        raise ContractError("profile changed during binding load")
    if persona_binding is not None and load_persona(workspace, persona_binding["id"]) != result["persona"]:
        raise ContractError("profile persona binding changed during load")
    if route_binding is not None and load_network_route(workspace, route_binding["id"]) != result["network_route"]:
        raise ContractError("profile network route binding changed during load")
    # Either final source read can outlast the earlier profile snapshot.
    _, final_snapshot = _load_profile_snapshot(workspace, profile_id)
    if (final_snapshot.body != profile_snapshot.body
            or final_snapshot.identity != profile_snapshot.identity):
        raise ContractError("profile changed during binding load")
    if registry_ancestry() != ancestry_before:
        raise ContractError("profile registry ancestry changed during binding load")
    return result


def _profile_identity_snapshot(
    workspace: Path,
    profile_id: str,
    *,
    read_bytes: list[int] | None = None,
) -> tuple[dict[str, Any], Path, bytes, DirectoryIdentity] | None:
    document, profile_snapshot = _load_profile_snapshot(
        workspace, profile_id, read_bytes=read_bytes
    )
    metadata = document.get("identity_contract")
    if not isinstance(metadata, dict):
        _, rebound = _load_profile_snapshot(
            workspace, profile_id, read_bytes=read_bytes
        )
        if (rebound.body != profile_snapshot.body
                or rebound.identity != profile_snapshot.identity):
            raise ContractError("profile identity changed during read")
        return None
    path = profile_data_path(workspace, profile_id) / metadata["file"]
    require_owned_directory_ancestors(path.parent, label="profile identity parent")
    parent_identity = directory_identity(path.parent, label="profile identity parent")
    if parent_identity is None:
        raise ContractError("profile identity parent is unavailable")
    ancestors = tuple(reversed((path.parent, *path.parent.parents)))

    def identity_ancestry() -> tuple[DirectoryIdentity | None, ...]:
        return tuple(
            directory_identity(ancestor, label="profile identity ancestry")
            for ancestor in ancestors
        )

    ancestry_before = identity_ancestry()
    if ancestry_before[-1] != parent_identity:
        raise ContractError("profile identity ancestry changed during read")
    canonical, observed = canonicalize_identity_contract(
        _read_identity_contract_bytes(path, read_bytes=read_bytes)
    )
    require_owned_directory_ancestors(path.parent, label="profile identity parent")
    if directory_identity(path.parent, label="profile identity parent") != parent_identity:
        raise ContractError("profile identity parent changed during read")
    if identity_ancestry() != ancestry_before:
        raise ContractError("profile identity ancestry changed during read")
    if observed != metadata:
        raise ContractError(
            "profile identity contract does not match its pinned metadata"
        )
    # The contract read can outlast the profile read that selected it. Check
    # the saved binding again before returning either the path or its bytes.
    _, rebound = _load_profile_snapshot(
        workspace, profile_id, read_bytes=read_bytes
    )
    if rebound.body != profile_snapshot.body or rebound.identity != profile_snapshot.identity:
        raise ContractError("profile identity changed during read")
    if identity_ancestry() != ancestry_before:
        raise ContractError("profile identity ancestry changed during read")
    return metadata, path, canonical, parent_identity


def _require_attached_identity(
    workspace: Path, profile_id: str, document: dict[str, Any], canonical: bytes
) -> None:
    # Registry publication is a separate operation from the identity file.
    # Rebind both before reporting a successful attachment.
    rebound = _profile_identity_snapshot(workspace, profile_id)
    if (rebound is None or rebound[0] != document["identity_contract"]
            or rebound[2] != canonical):
        raise ContractError("profile identity changed during attachment")
    saved, _snapshot = _load_profile_snapshot(workspace, profile_id)
    if saved != document:
        raise ContractError("profile changed during identity attachment")


def _require_attached_persona(
    workspace: Path, profile_id: str, document: dict[str, Any], persona: dict[str, Any]
) -> None:
    from .personas import load_persona

    saved, _snapshot = _load_profile_snapshot(workspace, profile_id)
    if saved != document or load_persona(workspace, persona["id"]) != persona:
        raise ContractError("profile persona attachment changed")


def load_profile_identity_document(
    workspace: Path,
    profile_id: str,
) -> tuple[dict[str, Any], bytes] | None:
    return _load_profile_identity_document_counted(workspace, profile_id)[0]


def _load_profile_identity_document_counted(
    workspace: Path,
    profile_id: str,
) -> tuple[tuple[dict[str, Any], bytes] | None, int]:
    read_bytes = [0]
    snapshot = _profile_identity_snapshot(workspace, profile_id, read_bytes=read_bytes)
    if snapshot is None:
        return None, read_bytes[0]
    _metadata, path, canonical, parent_identity = snapshot
    try:
        document = json.loads(canonical.decode("ascii", errors="strict"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ContractError("canonical profile identity contract is invalid") from None
    if not isinstance(document, dict):
        raise ContractError("canonical profile identity contract is invalid")
    require_owned_directory_ancestors(path.parent, label="profile identity parent")
    if directory_identity(path.parent, label="profile identity parent") != parent_identity:
        raise ContractError("profile identity parent changed during read")
    # Decoding can outlast the first checked read. Keep a returned document
    # bound to the profile's currently pinned contract as well as its parent.
    if _profile_identity_snapshot(workspace, profile_id, read_bytes=read_bytes) != snapshot:
        raise ContractError("profile identity contract changed during read")
    return (document, canonical), read_bytes[0]


def profile_identity_contract(
    workspace: Path, profile_id: str
) -> dict[str, Any] | None:
    snapshot = _profile_identity_snapshot(workspace, profile_id)
    if snapshot is None:
        return None
    metadata, path, canonical, parent_identity = snapshot
    resolved = path.resolve()
    require_owned_directory_ancestors(path.parent, label="profile identity parent")
    if (resolved != path
            or directory_identity(path.parent, label="profile identity parent") != parent_identity):
        raise ContractError("profile identity path changed during read")
    rebound = _profile_identity_snapshot(workspace, profile_id)
    if rebound is None or rebound != (metadata, path, canonical, parent_identity):
        raise ContractError("profile identity contract changed during read")
    return {**metadata, "path": str(resolved)}


def acquire_profile_lock(workspace: Path, profile_id: str, run_id: str) -> Path:
    if (
        not isinstance(run_id, str)
        or not 1 <= len(run_id) <= 256
        or any(ord(character) < 0x20 for character in run_id)
    ):
        raise ContractError("profile lock run ID is invalid")
    _, profile_snapshot = _load_profile_snapshot(workspace, profile_id)
    lock_path = profile_data_path(workspace, profile_id) / ".browser-core.lock"
    require_owned_directory_ancestors(lock_path.parent, label="profile lock parent")
    lock_parent_identity = directory_identity(lock_path.parent, label="profile lock parent")
    if lock_parent_identity is None:
        raise ContractError("profile lock parent is unavailable")

    def require_lock_parent() -> None:
        require_owned_directory_ancestors(lock_path.parent, label="profile lock parent")
        if directory_identity(lock_path.parent, label="profile lock parent") != lock_parent_identity:
            raise ContractError("profile lock parent changed")

    try:
        published = publish_json_exclusive_result(
            lock_path,
            {"schema": "browser-core.profile-lock/1", "run_id": run_id},
            maximum=4096,
            label="profile lock",
        )
    except ContractError:
        if lock_path.exists():
            raise ContractError(
                f"profile {profile_id} is locked; inspect the owning session before recovery"
            ) from None
        raise
    try:
        require_lock_parent()
        _, current_profile = _load_profile_snapshot(workspace, profile_id)
        if (current_profile.body != profile_snapshot.body
                or current_profile.identity != profile_snapshot.identity):
            raise ContractError("profile changed during lock acquisition")
        current_lock = read_bounded_control_snapshot_result(
            lock_path,
            maximum=4096,
            label="profile lock",
            require_single_link=True,
        )
        if (current_lock.state != "complete"
                or current_lock.body != published.body
                or current_lock.identity != published.identity):
            raise ContractError("profile lock changed during acquisition")
        require_lock_parent()
    except ContractError:
        try:
            require_lock_parent()
            remove_control_conditionally(
                lock_path,
                expected_body=published.body,
                expected_identity=published.identity,
                maximum=4096,
                label="profile lock",
                missing_ok=True,
            )
        except ContractError:
            raise ContractError("profile lock acquisition rollback incomplete") from None
        raise
    return lock_path


def release_profile_lock(
    lock_path: Path,
    run_id: str,
    *,
    missing_ok: bool = False,
) -> None:
    if not isinstance(lock_path, Path):
        raise ContractError("profile lock path must be a Path")
    if (
        not isinstance(run_id, str)
        or not 1 <= len(run_id) <= 256
        or any(ord(character) < 0x20 for character in run_id)
    ):
        raise ContractError("profile lock run ID is invalid")
    if not isinstance(missing_ok, bool):
        raise ContractError("profile lock missing policy is invalid")

    def lock_ancestry() -> tuple[DirectoryIdentity | None, ...]:
        return tuple(
            directory_identity(ancestor, label="profile lock parent")
            for ancestor in reversed((lock_path.parent, *lock_path.parent.parents))
        )

    parent_before = lock_ancestry()
    snapshot = read_bounded_control_snapshot_result(
        lock_path,
        maximum=4096,
        label="profile lock",
        require_single_link=True,
    )
    if lock_ancestry() != parent_before:
        raise ContractError("profile lock parent changed during release")
    if snapshot.state == "missing" and missing_ok:
        return
    if snapshot.state != "complete":
        raise ContractError(f"profile lock is {snapshot.state}")
    assert snapshot.body is not None and snapshot.identity is not None
    document = decode_strict_json_bytes(snapshot.body, label="profile lock")
    if document != {"schema": "browser-core.profile-lock/1", "run_id": run_id}:
        raise ContractError(
            "refusing to release a profile lock owned by another session"
        )
    remove_control_conditionally(
        lock_path,
        expected_body=snapshot.body,
        expected_identity=snapshot.identity,
        maximum=4096,
        label="profile lock",
        missing_ok=missing_ok,
    )
    if lock_ancestry() != parent_before:
        raise ContractError("profile lock parent changed during release")


DISPOSABLE_PROFILE_PREFIX = "ops-disp-"


def is_disposable_profile_id(profile_id: str) -> bool:
    return isinstance(profile_id, str) and profile_id.startswith(
        DISPOSABLE_PROFILE_PREFIX
    )


@_exclusive_profile_mutation
def attach_persona_identity_for_ops(
    workspace: Path,
    profile_id: str,
    persona_id: str,
    *,
    identity_contract: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Bind any catalog persona identity contract onto a disposable ops profile.

    Unlike attach_persona, this does not require a browser-core Chromium product
    kernel — multi-account research ops may pin Firefox/WebKit/mobile personas.

    identity_contract, when provided, replaces the persona's catalog contract
    bytes (used by coherence cohort to align lab-fixture host leaves).
    """
    from .personas import load_persona

    if not is_disposable_profile_id(profile_id):
        raise ContractError(
            "ops persona binding is restricted to disposable profile IDs"
        )
    document, profile_snapshot = _load_profile_snapshot(workspace, profile_id)
    persona = load_persona(workspace, persona_id)
    if persona.get("state") != "active":
        raise ContractError("ops persona binding requires an active persona")
    contract = (
        identity_contract
        if identity_contract is not None
        else persona["identity_contract"]
    )
    if not isinstance(contract, dict):
        raise ContractError("identity_contract override must be an object")
    try:
        contract_bytes = canonical_json_bytes(contract)
    except (ContractError, OverflowError, RecursionError):
        raise ContractError("identity contract override is not strict JSON") from None
    document, canonical = _attach_identity_bytes(
        workspace,
        profile_id,
        document,
        contract_bytes,
    )
    document["persona"] = {
        "id": persona_id,
        "sha256_16": persona["integrity_sha256"][:16],
    }
    validate_profile(document)
    _write_json_atomic(
        _registry_path(workspace, profile_id), document, expected=profile_snapshot
    )
    _require_attached_identity(workspace, profile_id, document, canonical)
    _require_attached_persona(workspace, profile_id, document, persona)
    _require_attached_identity(workspace, profile_id, document, canonical)
    _require_attached_persona(workspace, profile_id, document, persona)
    return document


def _profile_directory_identity(
    path: Path,
    *,
    label: str,
) -> DirectoryIdentity | None:
    return directory_identity(path, label=label)


def _remove_empty_profile_quarantine(
    path: Path, *, expected_identity: DirectoryIdentity
) -> None:
    label = "profile deletion quarantine"
    require_owned_directory_ancestors(path.parent, label=label)
    parent_identity = directory_identity(path.parent, label=label)
    if (parent_identity is None
            or directory_identity(path, label=label) != expected_identity):
        raise ContractError("profile deletion quarantine changed before cleanup")
    try:
        os.rmdir(path)
    except OSError:
        raise ContractError("profile deletion quarantine is not empty or changed") from None
    require_owned_directory_ancestors(path.parent, label=label)
    if (directory_identity(path.parent, label=label) != parent_identity
            or directory_identity(path, label=label) is not None):
        raise ContractError("profile deletion quarantine changed during cleanup")


def _rollback_profile_data(
    quarantined: Path,
    data: Path,
    *,
    expected_identity: DirectoryIdentity,
    quarantine_root: Path,
    quarantine_identity: DirectoryIdentity,
) -> None:
    if (
        _profile_directory_identity(
            quarantined,
            label="quarantined profile data",
        )
        != expected_identity
    ):
        raise ContractError("profile data rollback incomplete")
    try:
        os.lstat(data)
    except FileNotFoundError:
        pass
    except OSError:
        raise ContractError("profile data rollback incomplete") from None
    else:
        raise ContractError("profile data rollback incomplete")
    try:
        os.rename(quarantined, data)
    except OSError:
        raise ContractError("profile data rollback incomplete") from None
    if _profile_directory_identity(data, label="profile data") != expected_identity:
        raise ContractError("profile data rollback incomplete")
    if (
        _profile_directory_identity(
            quarantine_root,
            label="profile deletion quarantine",
        )
        != quarantine_identity
    ):
        raise ContractError("profile data rollback incomplete")
    try:
        _remove_empty_profile_quarantine(
            quarantine_root,
            expected_identity=quarantine_identity,
        )
    except ContractError:
        raise ContractError("profile data rollback incomplete") from None


def _remove_profile_tree(
    path: Path,
    *,
    expected_identity: DirectoryIdentity,
) -> None:
    remove_owned_directory_tree(
        path,
        expected_identity=expected_identity,
        label="profile deletion tree",
    )


def delete_disposable_profile(workspace: Path, profile_id: str) -> dict[str, Any]:
    """Remove a disposable ops profile registry entry and data directory."""
    profile_id = validate_profile_id(profile_id)
    if not is_disposable_profile_id(profile_id):
        raise ContractError("refusing to delete a non-disposable profile")
    registry = _registry_path(workspace, profile_id)
    data = profile_data_path(workspace, profile_id)

    def deletion_ancestry() -> tuple[DirectoryIdentity | None, ...]:
        return tuple(
            directory_identity(ancestor, label="profile deletion ancestry")
            for parent in (registry.parent, data.parent)
            for ancestor in reversed((parent, *parent.parents))
        )

    ancestry_before = deletion_ancestry()
    lock_path = data / ".browser-core.lock"
    if lock_path.exists():
        raise ContractError(
            f"profile {profile_id} is still locked; stop the session first"
        )
    registry_exists = os.path.lexists(registry)
    data_identity = _profile_directory_identity(data, label="profile data")
    if not registry_exists and data_identity is None:
        if os.path.lexists(registry) or _profile_directory_identity(
            data, label="profile data"
        ) is not None or deletion_ancestry() != ancestry_before:
            raise ContractError("profile appeared during deletion")
        return {"id": profile_id, "state": "absent", "deleted": False}
    registry_parent_identity = directory_identity(
        registry.parent, label="profile deletion registry parent"
    )
    if registry_parent_identity is not None:
        require_owned_directory_ancestors(
            registry.parent, label="profile deletion registry parent"
        )
    data_parent_identity: DirectoryIdentity | None = None
    if data_identity is not None:
        require_owned_directory_ancestors(data.parent, label="profile deletion data parent")
        data_parent_identity = directory_identity(
            data.parent, label="profile deletion data parent"
        )
        if data_parent_identity is None:
            raise ContractError("profile deletion data parent is unavailable")

    def require_data_parent() -> None:
        require_owned_directory_ancestors(data.parent, label="profile deletion data parent")
        if directory_identity(
            data.parent, label="profile deletion data parent"
        ) != data_parent_identity:
            raise ContractError("profile deletion data parent changed")

    registry_snapshot: BoundedControlSnapshot | None = None
    if registry_exists:
        _document, registry_snapshot = _load_profile_snapshot(workspace, profile_id)
    quarantine_root: Path | None = None
    quarantined: Path | None = None
    quarantine_identity: DirectoryIdentity | None = None
    if data_identity is not None:
        quarantine_root = data.parent / f".profile-delete-{uuid.uuid4().hex}"
        require_data_parent()
        try:
            os.mkdir(quarantine_root, 0o700)
        except OSError as exc:
            code = getattr(exc, "winerror", None) or exc.errno
            suffix = f" (os_error={code})" if isinstance(code, int) else ""
            raise ContractError(f"profile deletion quarantine failed{suffix}") from None
        quarantine_identity = _profile_directory_identity(
            quarantine_root,
            label="profile deletion quarantine",
        )
        assert quarantine_identity is not None
        quarantined = quarantine_root / "data"
        require_data_parent()
        try:
            os.rename(data, quarantined)
        except OSError:
            try:
                _remove_empty_profile_quarantine(
                    quarantine_root,
                    expected_identity=quarantine_identity,
                )
            except ContractError:
                pass
            raise ContractError("profile data changed before deletion") from None
        moved_identity = _profile_directory_identity(
            quarantined,
            label="quarantined profile data",
        )
        if moved_identity != data_identity:
            assert moved_identity is not None
            _rollback_profile_data(
                quarantined,
                data,
                expected_identity=moved_identity,
                quarantine_root=quarantine_root,
                quarantine_identity=quarantine_identity,
            )
            raise ContractError("profile data changed before deletion")
        try:
            os.lstat(quarantined / ".browser-core.lock")
        except FileNotFoundError:
            pass
        except OSError:
            _rollback_profile_data(
                quarantined,
                data,
                expected_identity=data_identity,
                quarantine_root=quarantine_root,
                quarantine_identity=quarantine_identity,
            )
            raise ContractError("profile lock inspection failed") from None
        else:
            _rollback_profile_data(
                quarantined,
                data,
                expected_identity=data_identity,
                quarantine_root=quarantine_root,
                quarantine_identity=quarantine_identity,
            )
            raise ContractError(
                f"profile {profile_id} is still locked; stop the session first"
            )
    if registry_snapshot is None and quarantined is not None:
        try:
            appeared = read_bounded_control_snapshot_result(
                registry,
                maximum=MAX_PROFILE_DOCUMENT_BYTES,
                label="profile document",
            )
        except ContractError:
            assert quarantine_root is not None
            assert quarantine_identity is not None
            assert data_identity is not None
            _rollback_profile_data(
                quarantined,
                data,
                expected_identity=data_identity,
                quarantine_root=quarantine_root,
                quarantine_identity=quarantine_identity,
            )
            raise ContractError("profile registry changed before deletion") from None
        if appeared.state != "missing":
            assert quarantine_root is not None
            assert quarantine_identity is not None
            assert data_identity is not None
            _rollback_profile_data(
                quarantined,
                data,
                expected_identity=data_identity,
                quarantine_root=quarantine_root,
                quarantine_identity=quarantine_identity,
            )
            raise ContractError("profile registry changed before deletion")
    try:
        if registry_snapshot is not None:
            if data_identity is not None:
                require_data_parent()
            assert (
                registry_snapshot.body is not None
                and registry_snapshot.identity is not None
            )
            remove_control_conditionally(
                registry,
                expected_body=registry_snapshot.body,
                expected_identity=registry_snapshot.identity,
                maximum=MAX_PROFILE_DOCUMENT_BYTES,
                label="profile document",
            )
    except Exception:
        if (
            quarantined is not None
            and quarantine_root is not None
            and quarantine_identity is not None
            and data_identity is not None
        ):
            _rollback_profile_data(
                quarantined,
                data,
                expected_identity=data_identity,
                quarantine_root=quarantine_root,
                quarantine_identity=quarantine_identity,
            )
        raise
    if (
        quarantined is not None
        and quarantine_root is not None
        and quarantine_identity is not None
        and data_identity is not None
    ):
        if (
            _profile_directory_identity(
                quarantine_root,
                label="profile deletion quarantine",
            )
            != quarantine_identity
        ):
            raise ContractError("profile deletion quarantine changed before cleanup")
        _remove_profile_tree(quarantined, expected_identity=data_identity)
        if (
            _profile_directory_identity(
                quarantine_root,
                label="profile deletion quarantine",
            )
            != quarantine_identity
        ):
            raise ContractError("profile deletion quarantine changed during cleanup")
        try:
            _remove_empty_profile_quarantine(
                quarantine_root,
                expected_identity=quarantine_identity,
            )
        except ContractError:
            raise ContractError("profile deletion quarantine cleanup failed") from None
    if registry_parent_identity is not None:
        require_owned_directory_ancestors(
            registry.parent, label="profile deletion registry parent"
        )
    if directory_identity(
        registry.parent, label="profile deletion registry parent"
    ) != registry_parent_identity:
        raise ContractError("profile deletion registry parent changed after cleanup")
    if data_identity is not None:
        require_data_parent()
    if os.path.lexists(registry) or os.path.lexists(data):
        raise ContractError("profile deletion changed after cleanup")
    if deletion_ancestry() != ancestry_before:
        raise ContractError("profile deletion ancestry changed after cleanup")
    return {"id": profile_id, "state": "deleted", "deleted": True}
