import json
import hashlib
import os
import subprocess
import pytest

from browser_core.contracts import ContractError
from browser_core.profiles import create_profile, list_profiles, profile_data_path
from browser_core.profile_migration import normalize_profile_registry
import browser_core.profile_migration as migration_module


def legacy_profile(workspace, name):
    document = create_profile(workspace, name)
    path = workspace / "profiles" / "registry" / f"{name}.json"
    body = (json.dumps(document, indent=2) + "\n").encode()
    path.write_bytes(body)
    return path, document, body


def test_profile_migration_preserves_browser_data_and_original_metadata(tmp_path):
    path, document, original = legacy_profile(tmp_path, "example")
    data = profile_data_path(tmp_path, "example")
    sentinel = data / "owned-fixture.txt"
    sentinel.write_bytes(b"preserve browser data")
    assert normalize_profile_registry(tmp_path)["requires_migration"] == 1
    assert path.read_bytes() == original
    assert normalize_profile_registry(tmp_path, apply=True)["migrated"] == 1
    assert list_profiles(tmp_path) == [document]
    assert sentinel.read_bytes() == b"preserve browser data"
    assert not (data / ".browser-core.lock").exists()
    assert next((tmp_path / "profiles/format-backups").glob("*.bin")).read_bytes() == original
    assert normalize_profile_registry(tmp_path, apply=True)["migrated"] == 0


def test_busy_profile_prevents_migration_and_releases_only_owned_locks(tmp_path):
    first, _, original_first = legacy_profile(tmp_path, "a-first")
    second, _, original_second = legacy_profile(tmp_path, "z-second")
    busy = profile_data_path(tmp_path, "z-second") / ".browser-core.lock"
    busy.write_bytes(b"existing owner")
    with pytest.raises(ContractError):
        normalize_profile_registry(tmp_path, apply=True)
    assert first.read_bytes() == original_first and second.read_bytes() == original_second
    assert busy.read_bytes() == b"existing owner"
    assert not (profile_data_path(tmp_path, "a-first") / ".browser-core.lock").exists()


def test_invalid_profile_prevents_all_migration(tmp_path):
    first, _, original = legacy_profile(tmp_path, "a-first")
    (first.parent / "z-invalid.json").write_text('{"id":"z-invalid"}', encoding="utf-8")
    with pytest.raises(ContractError):
        normalize_profile_registry(tmp_path, apply=True)
    assert first.read_bytes() == original


@pytest.mark.skipif(os.name != 'nt', reason='Windows directory junction regression')
def test_profile_migration_dry_run_rejects_linked_workspace(tmp_path):
    foreign = tmp_path / 'foreign'
    foreign.mkdir()
    record, _, original = legacy_profile(foreign, 'example')
    workspace = tmp_path / 'workspace'
    result = subprocess.run(
        ['cmd', '/c', 'mklink', '/J', str(workspace), str(foreign)],
        capture_output=True, check=False,
    )
    if result.returncode != 0:
        pytest.skip('directory junction creation is unavailable')
    try:
        with pytest.raises(ContractError, match='profile workspace'):
            normalize_profile_registry(workspace)
        assert record.read_bytes() == original
        assert not (foreign / 'profiles' / 'format-backups').exists()
    finally:
        workspace.rmdir()


def test_profile_migration_dry_run_rejects_replaced_workspace_root(
    tmp_path, monkeypatch
):
    workspace = tmp_path / 'workspace'
    workspace.mkdir()
    record, _, original = legacy_profile(workspace, 'example')
    retained = tmp_path / 'retained-workspace'
    inventory = migration_module.inventory_bounded_json_directory
    calls = 0

    def replace_root_after_inventory(*args, **kwargs):
        nonlocal calls
        result = inventory(*args, **kwargs)
        calls += 1
        if calls == 1:
            workspace.rename(retained)
            workspace.mkdir()
            (retained / 'profiles').rename(workspace / 'profiles')
        return result

    monkeypatch.setattr(
        migration_module, 'inventory_bounded_json_directory',
        replace_root_after_inventory,
    )
    with pytest.raises(ContractError, match='workspace changed'):
        normalize_profile_registry(workspace)
    assert calls >= 1
    assert record.read_bytes() == original
    assert not (workspace / 'profiles' / 'format-backups').exists()


@pytest.mark.skipif(os.name != 'nt', reason='Windows directory junction regression')
@pytest.mark.parametrize('component', ['profiles', 'registry'])
def test_profile_migration_rejects_junction_source_ancestor(tmp_path, component):
    profile, _, original = legacy_profile(tmp_path, 'example')
    junction = tmp_path / 'profiles'
    if component == 'registry':
        junction /= 'registry'
    target = tmp_path / f'outside-{component}'
    junction.rename(target)
    result = subprocess.run(
        ['cmd', '/c', 'mklink', '/J', str(junction), str(target)],
        capture_output=True, check=False,
    )
    if result.returncode != 0:
        pytest.skip('directory junction creation is unavailable')
    try:
        assert not junction.is_symlink()
        with pytest.raises(ContractError):
            normalize_profile_registry(tmp_path)
        external_profile = target / ('registry' if component == 'profiles' else '') / 'example.json'
        assert external_profile.read_bytes() == original
    finally:
        junction.rmdir()


@pytest.mark.skipif(os.name != 'nt', reason='Windows directory junction regression')
@pytest.mark.parametrize('preexisting', [False, True])
def test_profile_migration_rejects_junction_backup_directory(tmp_path, preexisting):
    profile, _, original = legacy_profile(tmp_path, 'example')
    target = tmp_path / 'outside-backups'
    target.mkdir()
    if preexisting:
        (target / f'{hashlib.sha256(original).hexdigest()}.bin').write_bytes(original)
    junction = tmp_path / 'profiles' / 'format-backups'
    result = subprocess.run(
        ['cmd', '/c', 'mklink', '/J', str(junction), str(target)],
        capture_output=True, check=False,
    )
    if result.returncode != 0:
        pytest.skip('directory junction creation is unavailable')
    try:
        assert not junction.is_symlink()
        with pytest.raises(ContractError):
            normalize_profile_registry(tmp_path, apply=True)
        assert [path.read_bytes() for path in target.iterdir()] == ([original] if preexisting else [])
        assert profile.read_bytes() == original
    finally:
        junction.rmdir()


def test_lock_release_failure_still_releases_other_owned_profile_locks(
    tmp_path, monkeypatch
):
    legacy_profile(tmp_path, "a-first")
    legacy_profile(tmp_path, "z-second")
    original_release = migration_module.profiles.release_profile_lock
    attempts = []

    def release(path, owner, *, missing_ok):
        attempts.append(path.parent.name)
        if path.parent.name == "z-second":
            raise ContractError("injected release failure")
        return original_release(path, owner, missing_ok=missing_ok)

    monkeypatch.setattr(migration_module.profiles, "release_profile_lock", release)
    with pytest.raises(ContractError, match="lock cleanup failed"):
        normalize_profile_registry(tmp_path, apply=True)
    assert attempts == ["z-second", "a-first"]
    assert not (profile_data_path(tmp_path, "a-first") / ".browser-core.lock").exists()
    assert (profile_data_path(tmp_path, "z-second") / ".browser-core.lock").exists()


def test_profile_migration_does_not_create_backup_under_replaced_parent(
    tmp_path, monkeypatch
):
    path, _, original = legacy_profile(tmp_path, "example")
    profiles_root = tmp_path / "profiles"
    retained = tmp_path / "retained-profiles"
    replacement = tmp_path / "replacement-profiles"
    replacement.mkdir()
    (replacement / "sentinel").write_bytes(b"foreign directory")
    publish = migration_module.publish_json_exclusive

    def swap_after_lock(lock_path, *args, **kwargs):
        result = publish(lock_path, *args, **kwargs)
        if lock_path.name == ".browser-core.lock":
            profiles_root.rename(retained)
            replacement.rename(profiles_root)
        return result

    monkeypatch.setattr(migration_module, "publish_json_exclusive", swap_after_lock)
    with pytest.raises(ContractError):
        normalize_profile_registry(tmp_path, apply=True)
    assert not (profiles_root / "format-backups").exists()
    assert (profiles_root / "sentinel").read_bytes() == b"foreign directory"
    assert (retained / "registry" / path.name).read_bytes() == original


def test_profile_migration_dry_run_rechecks_validated_bytes(tmp_path, monkeypatch):
    path, _, original = legacy_profile(tmp_path, "example")
    inventory = migration_module.inventory_bounded_json_directory
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

    monkeypatch.setattr(migration_module, "inventory_bounded_json_directory", edit_after_inventory)
    with pytest.raises(ContractError, match="changed"):
        normalize_profile_registry(tmp_path)
    assert path.read_bytes() == b"!" + original[1:]


def test_profile_migration_requires_backup_at_completion(tmp_path, monkeypatch):
    path, document, original = legacy_profile(tmp_path, "example")
    backup = tmp_path / "profiles" / "format-backups" / f"{hashlib.sha256(original).hexdigest()}.bin"
    replace = migration_module.replace_json_conditionally

    def remove_backup_after_replace(*args, **kwargs):
        result = replace(*args, **kwargs)
        backup.unlink()
        return result

    monkeypatch.setattr(
        migration_module, "replace_json_conditionally", remove_backup_after_replace
    )
    with pytest.raises(ContractError, match="backup"):
        normalize_profile_registry(tmp_path, apply=True)
    assert json.loads(path.read_text(encoding="utf-8")) == document
    assert not backup.exists()
