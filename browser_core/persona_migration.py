"""Explicit, lossless migration of legacy persona JSON formatting.

Normal loading remains strict. This operation validates the entire bounded
catalog before writing, backs up original bytes, and conditionally replaces
each file. It changes neither persona content nor its integrity digest. A
concurrent writer aborts the operation; already migrated files remain valid and
the command can be rerun. The catalog is not a multi-file transaction.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from . import personas
from .contracts import ContractError
from .control_files import (
    canonical_json_bytes,
    decode_strict_json_bytes,
    inventory_bounded_json_directory,
    publish_bytes_exclusive,
    read_bounded_control_snapshot_result,
    replace_json_conditionally,
)
from .owned_paths import directory_identity, prepare_owned_directory_parent


def normalize_persona_catalog(
    workspace: Path, *, apply: bool = False
) -> dict[str, Any]:
    if not isinstance(workspace, Path) or type(apply) is not bool:
        raise ContractError("persona format migration arguments are invalid")
    workspace_path = personas._persona_workspace_path(workspace)
    workspace_ancestors = tuple(reversed((workspace_path, *workspace_path.parents)))
    workspace_binding = tuple(
        directory_identity(path, label="persona migration workspace")
        for path in workspace_ancestors
    )

    def require_workspace_unchanged() -> None:
        if tuple(
            directory_identity(path, label="persona migration workspace")
            for path in workspace_ancestors
        ) != workspace_binding:
            raise ContractError("persona migration workspace changed")

    directory = workspace_path / "personas" / "catalog"
    source_parent_identity = directory_identity(
        directory.parent, label="persona format source parent"
    )

    def inventory():
        return inventory_bounded_json_directory(
            directory,
            maximum_entries=personas.MAX_PERSONA_CATALOG_ENTRIES,
            maximum_files=personas.MAX_PERSONA_CATALOG_FILES,
            maximum_file_bytes=personas.MAX_PERSONA_DOCUMENT_BYTES,
            maximum_total_bytes=personas.MAX_PERSONA_CATALOG_BYTES,
            label="persona catalog",
        )

    before = inventory()
    pending = []
    validated_bytes = []
    ids = set()
    for name, identity in before.files:
        if not personas.PROFILE_ID_RE.fullmatch(name[:-5]):
            raise ContractError("persona catalog candidate name is invalid")
        snapshot = read_bounded_control_snapshot_result(
            directory / name,
            maximum=personas.MAX_PERSONA_DOCUMENT_BYTES,
            label="legacy persona document",
            require_single_link=True,
        )
        if snapshot.state != "complete" or snapshot.body is None:
            raise ContractError("legacy persona document is unavailable")
        if snapshot.identity != identity:
            raise ContractError("persona changed during format migration")
        document = personas.validate_persona(
            decode_strict_json_bytes(snapshot.body, label="legacy persona document")
        )
        if document["id"] != name[:-5]:
            raise ContractError("persona document filename does not match persona ID")
        if document["id"].casefold() in ids:
            raise ContractError("persona catalog contains duplicate IDs")
        ids.add(document["id"].casefold())
        validated_bytes.append((name, identity, hashlib.sha256(snapshot.body).digest()))
        if snapshot.body != canonical_json_bytes(document):
            pending.append((name, document, snapshot))
    if inventory() != before:
        raise ContractError("persona catalog changed during format migration")
    # Directory metadata does not bind same-size content after validation.
    # Recheck the exact bytes for every validated record, including canonical
    # ones omitted from the pending replacement list.
    for name, identity, digest in validated_bytes:
        current = read_bounded_control_snapshot_result(
            directory / name,
            maximum=personas.MAX_PERSONA_DOCUMENT_BYTES,
            label="legacy persona document",
            require_single_link=True,
        )
        if (current.state != "complete" or current.identity != identity
                or current.body is None
                or hashlib.sha256(current.body).digest() != digest):
            raise ContractError("persona catalog changed during format migration")
    if (inventory() != before or directory_identity(
        directory.parent, label="persona format source parent"
    ) != source_parent_identity):
        raise ContractError("persona catalog changed during format migration")
    require_workspace_unchanged()
    report = {
        "schema": "browser-core.persona-format-migration/1",
        "applied": apply,
        "validated": len(before.files),
        "already_canonical": len(before.files) - len(pending),
        "requires_migration": len(pending),
        "migrated": 0,
        "content_changes": 0,
        "backups": "personas/format-backups",
    }
    if not apply or not pending:
        return report
    backup_directory = directory.parent / "format-backups"
    require_workspace_unchanged()
    if (source_parent_identity is None or directory_identity(
        directory.parent, label="persona format source parent"
    ) != source_parent_identity):
        raise ContractError("persona format source parent changed before backup")
    prepare_owned_directory_parent(
        backup_directory, label="persona format backup directory"
    )
    if directory_identity(
        directory.parent, label="persona format source parent"
    ) != source_parent_identity:
        raise ContractError("persona format source parent changed during backup setup")
    backup_identity = directory_identity(
        backup_directory, label="persona format backup directory")
    if backup_identity is None:
        raise ContractError("persona format backup directory is unavailable")
    # Back up the entire proposed migration before changing the first record.
    for _name, _document, snapshot in pending:
        require_workspace_unchanged()
        if directory_identity(backup_directory, label="persona format backup directory") != backup_identity:
            raise ContractError("persona format backup directory changed")
        digest = hashlib.sha256(snapshot.body).hexdigest()
        backup = backup_directory / f"{digest}.bin"
        previous = read_bounded_control_snapshot_result(
            backup,
            maximum=personas.MAX_PERSONA_DOCUMENT_BYTES,
            label="persona format backup",
            require_single_link=True,
        )
        if directory_identity(backup_directory, label="persona format backup directory") != backup_identity:
            raise ContractError("persona format backup directory changed")
        if previous.state == "missing":
            publish_bytes_exclusive(
                backup,
                snapshot.body,
                maximum=personas.MAX_PERSONA_DOCUMENT_BYTES,
                label="persona format backup",
            )
        elif previous.state != "complete" or previous.body != snapshot.body:
            raise ContractError("persona format backup is unavailable or changed")
    if directory_identity(backup_directory, label="persona format backup directory") != backup_identity:
        raise ContractError("persona format backup directory changed")
    if inventory() != before:
        raise ContractError("persona catalog changed before format migration")
    for name, document, snapshot in pending:
        require_workspace_unchanged()
        replace_json_conditionally(
            directory / name,
            document,
            expected_body=snapshot.body,
            expected_identity=snapshot.identity,
            maximum=personas.MAX_PERSONA_DOCUMENT_BYTES,
            label="persona format migration",
        )
        report["migrated"] += 1
    checked_backups = set()
    for _name, _document, snapshot in pending:
        digest = hashlib.sha256(snapshot.body).hexdigest()
        if digest in checked_backups:
            continue
        backup = read_bounded_control_snapshot_result(
            backup_directory / f"{digest}.bin",
            maximum=personas.MAX_PERSONA_DOCUMENT_BYTES,
            label="persona format backup",
            require_single_link=True,
        )
        if backup.state != "complete" or backup.body != snapshot.body:
            raise ContractError("persona format backup changed before completion")
        checked_backups.add(digest)
    if (directory_identity(
        directory.parent, label="persona format source parent"
    ) != source_parent_identity or directory_identity(
        backup_directory, label="persona format backup directory"
    ) != backup_identity):
        raise ContractError("persona format migration parent changed")
    require_workspace_unchanged()
    return report
