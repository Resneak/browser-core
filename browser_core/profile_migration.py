"""Normalize validated legacy profile metadata without touching browser data."""
from __future__ import annotations

import hashlib
from pathlib import Path
import uuid

from . import profiles
from .contracts import ContractError
from .control_files import (
    canonical_json_bytes, decode_strict_json_bytes,
    inventory_bounded_json_directory, publish_bytes_exclusive,
    publish_json_exclusive, read_bounded_control_snapshot_result,
    replace_json_conditionally,
)
from .owned_paths import directory_identity, prepare_owned_directory_parent


def normalize_profile_registry(workspace: Path, *, apply: bool = False) -> dict:
    if not isinstance(workspace, Path) or type(apply) is not bool:
        raise ContractError("profile format migration arguments are invalid")
    workspace_path = profiles._profile_workspace_path(workspace)
    workspace_ancestors = tuple(reversed((workspace_path, *workspace_path.parents)))
    workspace_binding = tuple(
        directory_identity(path, label="profile migration workspace")
        for path in workspace_ancestors
    )

    def require_workspace_unchanged() -> None:
        if tuple(
            directory_identity(path, label="profile migration workspace")
            for path in workspace_ancestors
        ) != workspace_binding:
            raise ContractError("profile migration workspace changed")

    directory = workspace_path / "profiles" / "registry"
    source_parent_identity = directory_identity(
        directory.parent, label="profile migration source parent"
    )

    def inventory():
        return inventory_bounded_json_directory(
            directory,
            maximum_entries=profiles.MAX_PROFILE_REGISTRY_ENTRIES,
            maximum_files=profiles.MAX_PROFILE_REGISTRY_FILES,
            maximum_file_bytes=profiles.MAX_PROFILE_DOCUMENT_BYTES,
            maximum_total_bytes=profiles.MAX_PROFILE_REGISTRY_BYTES,
            label="profile registry",
        )

    before = inventory()
    pending = []
    validated_bytes = []
    for name, identity in before.files:
        profile_id = profiles.validate_profile_id(name[:-5])
        snapshot = read_bounded_control_snapshot_result(
            directory / name, maximum=profiles.MAX_PROFILE_DOCUMENT_BYTES,
            label="legacy profile document", require_single_link=True,
        )
        if snapshot.state != "complete" or snapshot.body is None or snapshot.identity != identity:
            raise ContractError("profile changed during format migration")
        document = profiles.validate_profile(
            decode_strict_json_bytes(snapshot.body, label="legacy profile document")
        )
        if document["id"] != profile_id:
            raise ContractError("profile filename does not match profile ID")
        validated_bytes.append((name, identity, hashlib.sha256(snapshot.body).digest()))
        if snapshot.body != canonical_json_bytes(document):
            pending.append((name, document, snapshot))
    if inventory() != before:
        raise ContractError("profile registry changed during format migration")
    # A same-size in-place edit with restored mtime can retain the inventory
    # identity. Bind every validated document before reporting a dry run too.
    for name, identity, digest in validated_bytes:
        current = read_bounded_control_snapshot_result(
            directory / name,
            maximum=profiles.MAX_PROFILE_DOCUMENT_BYTES,
            label="legacy profile document",
            require_single_link=True,
        )
        if (current.state != "complete" or current.identity != identity
                or current.body is None
                or hashlib.sha256(current.body).digest() != digest):
            raise ContractError("profile registry changed during format migration")
    if (inventory() != before or directory_identity(
        directory.parent, label="profile migration source parent"
    ) != source_parent_identity):
        raise ContractError("profile registry changed during format migration")
    require_workspace_unchanged()
    report = {"schema":"browser-core.profile-format-migration/1", "applied":apply,
              "validated":len(before.files), "requires_migration":len(pending),
              "migrated":0, "content_changes":0, "backups":"profiles/format-backups"}
    if not apply or not pending:
        return report
    owner = "format-migration-" + uuid.uuid4().hex
    locks = []
    try:
        # The ordinary lock-acquisition helper intentionally rejects legacy
        # metadata. Migration uses its same exclusive lock document, after the
        # complete legacy registry has passed schema and identity validation.
        for _name, document, _snapshot in pending:
            require_workspace_unchanged()
            data = profiles.profile_data_path(workspace, document["id"])
            if profiles._profile_directory_identity(data, label="profile data") is None:
                raise ContractError("profile data is missing during format migration")
            lock = data / ".browser-core.lock"
            publish_json_exclusive(
                lock, {"schema":"browser-core.profile-lock/1", "run_id":owner},
                maximum=4096, label="profile migration lock",
            )
            locks.append(lock)
            require_workspace_unchanged()
        backup_directory = directory.parent / "format-backups"
        require_workspace_unchanged()
        if (source_parent_identity is None or directory_identity(
            directory.parent, label="profile migration source parent"
        ) != source_parent_identity):
            raise ContractError("profile migration source parent changed before backup")
        prepare_owned_directory_parent(
            backup_directory, label="profile format backup directory"
        )
        if directory_identity(
            directory.parent, label="profile migration source parent"
        ) != source_parent_identity:
            raise ContractError("profile migration source parent changed during backup setup")
        backup_identity = directory_identity(
            backup_directory, label="profile format backup directory")
        if backup_identity is None:
            raise ContractError("profile format backup directory is unavailable")
        for _name, _document, snapshot in pending:
            require_workspace_unchanged()
            if directory_identity(backup_directory, label="profile format backup directory") != backup_identity:
                raise ContractError("profile format backup directory changed")
            digest = hashlib.sha256(snapshot.body).hexdigest()
            backup = backup_directory / f"{digest}.bin"
            old = read_bounded_control_snapshot_result(
                backup, maximum=profiles.MAX_PROFILE_DOCUMENT_BYTES,
                label="profile format backup", require_single_link=True,
            )
            if directory_identity(backup_directory, label="profile format backup directory") != backup_identity:
                raise ContractError("profile format backup directory changed")
            if old.state == "missing":
                publish_bytes_exclusive(backup, snapshot.body,
                    maximum=profiles.MAX_PROFILE_DOCUMENT_BYTES, label="profile format backup")
            elif old.state != "complete" or old.body != snapshot.body:
                raise ContractError("profile format backup is unavailable or changed")
        if directory_identity(backup_directory, label="profile format backup directory") != backup_identity:
            raise ContractError("profile format backup directory changed")
        if inventory() != before:
            raise ContractError("profile registry changed before format migration")
        for name, document, snapshot in pending:
            require_workspace_unchanged()
            replace_json_conditionally(directory / name, document,
                expected_body=snapshot.body, expected_identity=snapshot.identity,
                maximum=profiles.MAX_PROFILE_DOCUMENT_BYTES, label="profile format migration")
            report["migrated"] += 1
        checked_backups = set()
        for _name, _document, snapshot in pending:
            digest = hashlib.sha256(snapshot.body).hexdigest()
            if digest in checked_backups:
                continue
            backup = read_bounded_control_snapshot_result(
                backup_directory / f"{digest}.bin",
                maximum=profiles.MAX_PROFILE_DOCUMENT_BYTES,
                label="profile format backup",
                require_single_link=True,
            )
            if backup.state != "complete" or backup.body != snapshot.body:
                raise ContractError("profile format backup changed before completion")
            checked_backups.add(digest)
        if (directory_identity(
            directory.parent, label="profile migration source parent"
        ) != source_parent_identity or directory_identity(
            backup_directory, label="profile format backup directory"
        ) != backup_identity):
            raise ContractError("profile format migration parent changed")
        require_workspace_unchanged()
    finally:
        cleanup_failed = False
        for lock in reversed(locks):
            try:
                profiles.release_profile_lock(lock, owner, missing_ok=False)
            except Exception:
                cleanup_failed = True
        if cleanup_failed:
            raise ContractError("profile migration lock cleanup failed") from None
    return report
