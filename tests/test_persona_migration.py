from pathlib import Path
import hashlib
import json
import os
import subprocess

import pytest

from browser_core.contracts import ContractError
from browser_core.control_files import canonical_json_bytes
from browser_core.persona_migration import normalize_persona_catalog
from browser_core.personas import list_personas
from test_personas import fixture_persona


def legacy_record(workspace, name="legacy-persona"):
    document = fixture_persona(name)
    path = workspace / "personas" / "catalog" / f"{name}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    body = (json.dumps(document, indent=2) + "\n").replace("\n", "\r\n").encode()
    path.write_bytes(body)
    return path, document, body


def test_migration_preserves_content_backup_and_digest(tmp_path: Path):
    path, document, original = legacy_record(tmp_path)
    with pytest.raises(ContractError, match="valid managed document"):
        list_personas(tmp_path)
    dry = normalize_persona_catalog(tmp_path)
    assert dry["requires_migration"] == 1 and dry["migrated"] == 0
    assert path.read_bytes() == original
    assert not (tmp_path / "personas" / "format-backups").exists()
    applied = normalize_persona_catalog(tmp_path, apply=True)
    assert applied["migrated"] == 1 and applied["content_changes"] == 0
    assert path.read_bytes() == canonical_json_bytes(document)
    assert list_personas(tmp_path) == [document]
    backups = list((tmp_path / "personas" / "format-backups").glob("*.bin"))
    assert len(backups) == 1 and backups[0].read_bytes() == original
    assert normalize_persona_catalog(tmp_path, apply=True)["migrated"] == 0


def test_migration_validates_entire_catalog_before_writing(tmp_path: Path):
    path, document, original = legacy_record(tmp_path, "a-valid")
    bad = path.with_name("z-invalid.json")
    bad.write_text('{"id":"one","id":"two"}', encoding="utf-8")
    with pytest.raises(ContractError):
        normalize_persona_catalog(tmp_path, apply=True)
    assert path.read_bytes() == original
    assert not (tmp_path / "personas" / "format-backups").exists()


@pytest.mark.skipif(os.name != 'nt', reason='Windows directory junction regression')
def test_persona_migration_rejects_linked_workspace_before_access(tmp_path: Path):
    foreign = tmp_path / 'foreign'
    foreign.mkdir()
    record, _, original = legacy_record(foreign)
    workspace = tmp_path / 'workspace'
    result = subprocess.run(
        ['cmd', '/c', 'mklink', '/J', str(workspace), str(foreign)],
        capture_output=True, check=False,
    )
    if result.returncode:
        pytest.skip('directory junction creation is unavailable')
    try:
        with pytest.raises(ContractError, match='persona workspace'):
            normalize_persona_catalog(workspace, apply=True)
        assert record.read_bytes() == original
        assert not (foreign / 'personas' / 'format-backups').exists()
    finally:
        workspace.rmdir()


def test_persona_migration_dry_run_rejects_replaced_workspace_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import browser_core.persona_migration as migration

    workspace = tmp_path / 'workspace'
    workspace.mkdir()
    record, _, original = legacy_record(workspace)
    retained = tmp_path / 'retained-workspace'
    inventory = migration.inventory_bounded_json_directory
    calls = 0

    def replace_root_after_inventory(*args, **kwargs):
        nonlocal calls
        result = inventory(*args, **kwargs)
        calls += 1
        if calls == 1:
            workspace.rename(retained)
            workspace.mkdir()
            (retained / 'personas').rename(workspace / 'personas')
        return result

    monkeypatch.setattr(
        migration, 'inventory_bounded_json_directory', replace_root_after_inventory
    )
    with pytest.raises(ContractError, match='workspace changed'):
        normalize_persona_catalog(workspace)
    assert calls >= 1
    assert record.read_bytes() == original
    assert not (workspace / 'personas' / 'format-backups').exists()


@pytest.mark.skipif(os.name != 'nt', reason='Windows directory junction regression')
def test_persona_migration_rejects_preexisting_backup_through_junction(tmp_path: Path):
    record, _, original = legacy_record(tmp_path)
    target = tmp_path / 'outside-backups'
    target.mkdir()
    (target / f'{hashlib.sha256(original).hexdigest()}.bin').write_bytes(original)
    junction = tmp_path / 'personas' / 'format-backups'
    result = subprocess.run(
        ['cmd', '/c', 'mklink', '/J', str(junction), str(target)],
        capture_output=True, check=False,
    )
    if result.returncode != 0:
        pytest.skip('directory junction creation is unavailable')
    try:
        assert not junction.is_symlink()
        with pytest.raises(ContractError):
            normalize_persona_catalog(tmp_path, apply=True)
        assert record.read_bytes() == original
        assert [path.read_bytes() for path in target.iterdir()] == [original]
    finally:
        junction.rmdir()


def test_migration_does_not_overwrite_a_concurrent_edit(tmp_path, monkeypatch):
    import browser_core.persona_migration as migration

    path, document, original = legacy_record(tmp_path)
    publish = migration.publish_bytes_exclusive

    def racing_backup(*args, **kwargs):
        result = publish(*args, **kwargs)
        path.write_bytes(b"concurrent edit")
        return result

    monkeypatch.setattr(migration, "publish_bytes_exclusive", racing_backup)
    with pytest.raises(ContractError, match="catalog changed"):
        normalize_persona_catalog(tmp_path, apply=True)
    assert path.read_bytes() == b"concurrent edit"


def test_persona_migration_does_not_create_backup_under_replaced_parent(
    tmp_path, monkeypatch
):
    import browser_core.persona_migration as migration

    path, _, original = legacy_record(tmp_path)
    personas_root = tmp_path / "personas"
    retained = tmp_path / "retained-personas"
    replacement = tmp_path / "replacement-personas"
    replacement.mkdir()
    (replacement / "sentinel").write_bytes(b"foreign directory")
    inventory = migration.inventory_bounded_json_directory
    calls = 0

    def swap_after_validation(*args, **kwargs):
        nonlocal calls
        result = inventory(*args, **kwargs)
        calls += 1
        if calls == 2:
            personas_root.rename(retained)
            replacement.rename(personas_root)
        return result

    monkeypatch.setattr(migration, "inventory_bounded_json_directory", swap_after_validation)
    with pytest.raises(ContractError):
        normalize_persona_catalog(tmp_path, apply=True)
    assert not (personas_root / "format-backups").exists()
    assert (personas_root / "sentinel").read_bytes() == b"foreign directory"
    assert (retained / "catalog" / path.name).read_bytes() == original


def test_persona_migration_dry_run_rechecks_validated_bytes(tmp_path, monkeypatch):
    import browser_core.persona_migration as migration

    path, _, original = legacy_record(tmp_path)
    inventory = migration.inventory_bounded_json_directory
    calls = 0

    def edit_after_inventory(*args, **kwargs):
        nonlocal calls
        result = inventory(*args, **kwargs)
        calls += 1
        if calls == 2:
            metadata = path.stat()
            path.write_bytes(b"!" + original[1:])
            os.utime(path, ns=(metadata.st_atime_ns, metadata.st_mtime_ns))
        return result

    monkeypatch.setattr(migration, "inventory_bounded_json_directory", edit_after_inventory)
    with pytest.raises(ContractError, match="changed"):
        normalize_persona_catalog(tmp_path)
    assert path.read_bytes() == b"!" + original[1:]


def test_persona_migration_requires_backup_at_completion(tmp_path, monkeypatch):
    import browser_core.persona_migration as migration

    path, document, original = legacy_record(tmp_path)
    backup = tmp_path / "personas" / "format-backups" / f"{hashlib.sha256(original).hexdigest()}.bin"
    replace = migration.replace_json_conditionally

    def remove_backup_after_replace(*args, **kwargs):
        result = replace(*args, **kwargs)
        backup.unlink()
        return result

    monkeypatch.setattr(migration, "replace_json_conditionally", remove_backup_after_replace)
    with pytest.raises(ContractError, match="backup"):
        normalize_persona_catalog(tmp_path, apply=True)
    assert path.read_bytes() == canonical_json_bytes(document)
    assert not backup.exists()


@pytest.mark.parametrize("value", [None, 1, "yes"])
def test_migration_apply_requires_boolean(tmp_path, value):
    with pytest.raises(ContractError, match="arguments"):
        normalize_persona_catalog(tmp_path, apply=value)
