from __future__ import annotations

from pathlib import Path
import hashlib
import json
import os
import subprocess

import pytest

import browser_core.control_files as control_files
import browser_core.network as network_module
import browser_core.personas as personas_module
import browser_core.profiles as profiles_module
from browser_core.contracts import ContractError
from browser_core.control_files import canonical_json_bytes
from browser_core.profiles import (
    acquire_profile_lock,
    attach_identity_contract,
    attach_network_route,
    attach_persona,
    create_profile,
    canonicalize_identity_contract,
    delete_disposable_profile,
    list_profiles,
    load_profile,
    profile_data_path,
    profile_identity_contract,
    profile_bindings,
    release_profile_lock,
    validate_profile,
)
from browser_core.personas import add_persona, build_persona, persona_digest
from browser_core.network import add_network_route, build_network_route


@pytest.mark.parametrize("workspace", [None, "workspace"])
def test_profile_data_path_rejects_non_path_workspace(workspace: object) -> None:
    with pytest.raises(ContractError, match="profile workspace must be a Path"):
        profile_data_path(workspace, "fixture")  # type: ignore[arg-type]


def test_profile_creation_rejects_orphaned_data_directory(tmp_path: Path) -> None:
    data = tmp_path / "profiles" / "data" / "fixture"
    data.mkdir(parents=True)
    marker = data / "owned.txt"
    marker.write_text("keep", encoding="utf-8")

    with pytest.raises(ContractError, match="profile data already exists"):
        create_profile(tmp_path, "fixture")

    assert marker.read_text(encoding="utf-8") == "keep"
    assert not (tmp_path / "profiles" / "registry" / "fixture.json").exists()


def test_profile_creation_maps_data_parent_disappearance_during_mkdir(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    data_parent = tmp_path / "profiles" / "data"
    data_parent.mkdir(parents=True)
    marker = data_parent / "keep.txt"
    marker.write_text("keep", encoding="utf-8")
    moved = tmp_path / "moved-data"
    original_mkdir = Path.mkdir

    def disappear_before_mkdir(path: Path, *args: object, **kwargs: object) -> None:
        if path == data_parent / "fixture":
            data_parent.rename(moved)
        original_mkdir(path, *args, **kwargs)

    monkeypatch.setattr(Path, "mkdir", disappear_before_mkdir)
    with pytest.raises(ContractError, match="profile data could not be created"):
        create_profile(tmp_path, "fixture")
    assert (moved / "keep.txt").read_text(encoding="utf-8") == "keep"
    assert not (tmp_path / "profiles" / "registry" / "fixture.json").exists()


def test_profile_creation_rechecks_registry_parent_after_final_document_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    registry = tmp_path / "profiles" / "registry"
    moved = tmp_path / "moved-registry"
    original_read = profiles_module.read_bounded_control_snapshot_result
    swapped = False

    def swap_after_read(path: Path, **kwargs: object) -> object:
        nonlocal swapped
        snapshot = original_read(path, **kwargs)
        if path == registry / "fixture.json" and snapshot.state == "complete":
            assert not swapped
            registry.rename(moved)
            registry.mkdir()
            swapped = True
        return snapshot

    monkeypatch.setattr(
        profiles_module, "read_bounded_control_snapshot_result", swap_after_read
    )
    with pytest.raises(ContractError):
        create_profile(tmp_path, "fixture")
    assert swapped
    assert not (registry / "fixture.json").exists()
    assert (moved / "fixture.json").exists()


@pytest.mark.skipif(os.name != "nt", reason="Windows directory junction boundary")
@pytest.mark.parametrize("branch", ["data", "registry"])
def test_profile_creation_rejects_preexisting_parent_junction(
    tmp_path: Path, branch: str
) -> None:
    target = tmp_path / "unrelated"
    target.mkdir()
    profiles = tmp_path / "profiles"
    profiles.mkdir()
    junction = profiles / branch
    created = subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(junction), str(target)],
        capture_output=True, check=False,
    )
    if created.returncode:
        pytest.skip("host could not create an unprivileged directory junction")
    try:
        with pytest.raises(ContractError):
            create_profile(tmp_path, "fixture")
        assert list(target.iterdir()) == []
        if branch == "registry":
            assert not (profiles / "data" / "fixture").exists()
    finally:
        if junction.exists():
            junction.rmdir()


@pytest.mark.skipif(os.name != "nt", reason="Windows directory junction boundary")
def test_profile_operations_reject_workspace_junction_before_access(
    tmp_path: Path,
) -> None:
    target = tmp_path / "unrelated"
    target.mkdir()
    junction = tmp_path / "workspace"
    created = subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(junction), str(target)],
        capture_output=True,
        check=False,
    )
    if created.returncode:
        pytest.skip("host could not create an unprivileged directory junction")
    try:
        with pytest.raises(ContractError, match="profile workspace"):
            create_profile(junction, "fixture")
        assert list(target.iterdir()) == []
        create_profile(target, "fixture")
        with pytest.raises(ContractError, match="profile workspace"):
            load_profile(junction, "fixture")
        with pytest.raises(ContractError, match="profile workspace"):
            list_profiles(junction)
    finally:
        junction.rmdir()


@pytest.mark.skipif(os.name != "nt", reason="Windows directory junction boundary")
def test_profile_creation_rechecks_data_parent_before_mkdir(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    profiles = tmp_path / "profiles"
    data = profiles / "data"
    data.mkdir(parents=True)
    moved = tmp_path / "moved-data"
    foreign = tmp_path / "foreign"
    foreign.mkdir()
    probe = tmp_path / "junction-probe"
    created = subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(probe), str(foreign)],
        capture_output=True, check=False,
    )
    if created.returncode:
        pytest.skip("host could not create an unprivileged directory junction")
    probe.rmdir()

    original_prepare = profiles_module.prepare_owned_directory_parent

    def redirect_after_prepare(parent: Path, *, label: str) -> None:
        original_prepare(parent, label=label)
        if label == "profile creation data parent":
            data.rename(moved)
            redirect = subprocess.run(
                ["cmd", "/c", "mklink", "/J", str(data), str(foreign)],
                capture_output=True, check=False,
            )
            assert redirect.returncode == 0, redirect.stderr

    monkeypatch.setattr(profiles_module, "prepare_owned_directory_parent", redirect_after_prepare)
    try:
        with pytest.raises(ContractError):
            create_profile(tmp_path, "fixture")
        assert list(foreign.iterdir()) == []
    finally:
        if data.exists():
            data.rmdir()


@pytest.mark.skipif(os.name != "nt", reason="Windows directory junction boundary")
def test_profile_registry_writer_rejects_preexisting_ancestor_junction(
    tmp_path: Path,
) -> None:
    target = tmp_path / "unrelated"
    target.mkdir()
    junction = tmp_path / "profiles"
    created = subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(junction), str(target)],
        capture_output=True, check=False,
    )
    if created.returncode:
        pytest.skip("host could not create an unprivileged directory junction")
    try:
        with pytest.raises(ContractError):
            profiles_module._write_json_atomic(
                junction / "registry" / "fixture.json", {"fixture": True}
            )
        assert list(target.iterdir()) == []
    finally:
        if junction.exists():
            junction.rmdir()


def test_profile_lock_disappearance_after_acceptance_is_clean_when_allowed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    create_profile(tmp_path, "profile")
    lock = acquire_profile_lock(tmp_path, "profile", "owner")
    real_remove = profiles_module.remove_control_conditionally

    def disappear_then_remove(path: Path, **kwargs: object) -> None:
        assert kwargs["missing_ok"] is True
        control_files.os.unlink(path)
        real_remove(path, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(
        profiles_module,
        "remove_control_conditionally",
        disappear_then_remove,
    )

    release_profile_lock(lock, "owner", missing_ok=True)
    assert not lock.exists()


def fixture_persona() -> dict:
    return build_persona(
        persona_id="win-core-153",
        name="Owned Windows Chromium 153",
        tags=("owned",),
        device={
            "class": "desktop",
            "os_family": "windows",
            "os_version": "11",
            "architecture": "x86_64",
            "is_mobile": False,
            "has_touch": False,
            "viewport": {
                "width": 2560,
                "height": 1440,
                "device_scale_factor": 1,
                "orientation": "landscape",
            },
            "screen": {"width": 2560, "height": 1440},
        },
        kernel={
            "engine": "chromium",
            "product": "browser-core",
            "minimum_major": 153,
            "maximum_major": 153,
        },
        geography={
            "country": "US",
            "locale": "en-US",
            "languages": ["en-US"],
            "timezone": "America/Chicago",
        },
        identity_contract={
            "schema_version": 1,
            "expected": {"userAgentData.mobile": False, "window.platform": "Win32"},
        },
        provenance={
            "kind": "owned-capture",
            "source": "fixture",
            "source_sha256": hashlib.sha256(b"fixture").hexdigest(),
            "captured_at": "2026-08-03T00:00:00Z",
        },
    )


def test_named_profile_roundtrip_and_exclusive_lock(tmp_path: Path) -> None:
    document = create_profile(tmp_path, "research-main", "Research Main")
    assert document["identity_mode"] == "host-native"
    assert list_profiles(tmp_path) == [document]
    assert profile_data_path(tmp_path, "research-main").is_dir()
    lock = acquire_profile_lock(tmp_path, "research-main", "run-one")
    assert lock.read_bytes() == canonical_json_bytes(
        {
            "schema": "browser-core.profile-lock/1",
            "run_id": "run-one",
        }
    )
    with pytest.raises(ContractError, match="locked"):
        acquire_profile_lock(tmp_path, "research-main", "run-two")
    release_profile_lock(lock, "run-one")
    assert not lock.exists()


def test_profile_list_rejects_uppercase_json_extension_alias(
    tmp_path: Path,
) -> None:
    document = create_profile(tmp_path, "fixture")
    registry = tmp_path / "profiles" / "registry"
    saved = registry / "fixture.json"
    temporary = registry / "renaming.tmp"
    saved.rename(temporary)
    uppercase = registry / "fixture.JSON"
    temporary.rename(uppercase)
    if os.name == "nt":
        assert load_profile(tmp_path, "fixture") == document
    with pytest.raises(ContractError, match="noncanonical JSON entry"):
        list_profiles(tmp_path)
    assert uppercase.is_file()


def test_profile_list_rejects_appearance_during_final_document_rebind(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    first = create_profile(tmp_path, "first-profile")
    other = tmp_path / "other-workspace"
    create_profile(other, "second-profile")
    second_body = (
        other / "profiles" / "registry" / "second-profile.json"
    ).read_bytes()
    second_path = tmp_path / "profiles" / "registry" / "second-profile.json"
    original = profiles_module._load_profile_snapshot
    reads = 0

    def add_after_final_read(workspace: Path, profile_id: str, **kwargs):
        nonlocal reads
        result = original(workspace, profile_id, **kwargs)
        if workspace == tmp_path and profile_id == "first-profile":
            reads += 1
            if reads == 2:
                second_path.write_bytes(second_body)
        return result

    monkeypatch.setattr(profiles_module, "_load_profile_snapshot", add_after_final_read)
    with pytest.raises(ContractError, match="registry changed during load"):
        list_profiles(tmp_path)
    assert second_path.read_bytes() == second_body
    assert first["id"] == "first-profile"


def test_profile_lock_rejects_profile_removed_before_publication(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    create_profile(tmp_path, "fixture")
    registry = tmp_path / "profiles" / "registry" / "fixture.json"
    held = tmp_path / "held-profile.json"
    lock = profile_data_path(tmp_path, "fixture") / ".browser-core.lock"
    original = profiles_module._load_profile_snapshot
    removed = False

    def remove_after_first_read(workspace: Path, profile_id: str):
        nonlocal removed
        result = original(workspace, profile_id)
        if not removed:
            removed = True
            registry.rename(held)
        return result

    monkeypatch.setattr(profiles_module, "_load_profile_snapshot", remove_after_first_read)
    with pytest.raises(ContractError):
        acquire_profile_lock(tmp_path, "fixture", "owner")
    assert removed
    assert held.is_file()
    assert not lock.exists()


def test_profile_lock_rejects_replaced_data_parent_after_publication(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    create_profile(tmp_path, "fixture")
    data = profile_data_path(tmp_path, "fixture")
    held = tmp_path / "held-profile-data"
    lock = data / ".browser-core.lock"
    original_publish = profiles_module.publish_json_exclusive_result
    changed = False

    def move_lock_to_replaced_parent(path: Path, *args, **kwargs):
        nonlocal changed
        published = original_publish(path, *args, **kwargs)
        if path == lock:
            data.rename(held)
            data.mkdir()
            (held / lock.name).rename(lock)
            changed = True
        return published

    monkeypatch.setattr(
        profiles_module, "publish_json_exclusive_result", move_lock_to_replaced_parent
    )
    with pytest.raises(ContractError, match="lock.*(?:parent changed|rollback incomplete)"):
        acquire_profile_lock(tmp_path, "fixture", "owner")
    assert changed
    assert lock.is_file()
    assert held.is_dir()


def test_profile_creation_rollback_preserves_a_replaced_data_directory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    data = tmp_path / "profiles" / "data" / "fixture"
    held = tmp_path / "held-profile-data"

    def replace_data_then_fail(*_args: object, **_kwargs: object) -> None:
        data.rename(held)
        data.mkdir()
        (data / "competitor.bin").write_bytes(b"competitor")
        raise RuntimeError("private registry failure")

    monkeypatch.setattr(profiles_module, "_write_json_atomic", replace_data_then_fail)
    with pytest.raises(ContractError, match="profile creation rollback incomplete") as failure:
        create_profile(tmp_path, "fixture")

    assert isinstance(failure.value.__cause__, RuntimeError)
    assert held.is_dir()
    assert (data / "competitor.bin").read_bytes() == b"competitor"
    assert not (tmp_path / "profiles" / "registry" / "fixture.json").exists()


def test_profile_creation_rollback_preserves_new_unowned_data_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    data = tmp_path / "profiles" / "data" / "fixture"
    sentinel = data / "competitor.bin"

    def fail_after_competitor_write(*_args: object, **_kwargs: object) -> None:
        sentinel.write_bytes(b"not created by profile publication")
        raise RuntimeError("synthetic registry failure")

    monkeypatch.setattr(profiles_module, "_write_json_atomic", fail_after_competitor_write)
    with pytest.raises(ContractError, match="profile creation rollback incomplete") as failure:
        create_profile(tmp_path, "fixture")
    assert isinstance(failure.value.__cause__, RuntimeError)
    assert sentinel.read_bytes() == b"not created by profile publication"


def test_profile_creation_rejects_replaced_publication_before_success(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    registry = tmp_path / "profiles" / "registry"
    held = tmp_path / "held-registry"
    original = profiles_module._write_json_atomic

    def replace_after_write(path: Path, document: dict, **kwargs: object):
        published = original(path, document, **kwargs)
        registry.rename(held)
        registry.mkdir()
        path.write_bytes((held / path.name).read_bytes())
        return published

    monkeypatch.setattr(profiles_module, "_write_json_atomic", replace_after_write)
    with pytest.raises(ContractError, match="profile creation rollback incomplete"):
        create_profile(tmp_path, "fixture")
    assert not profile_data_path(tmp_path, "fixture").exists()
    assert (registry / "fixture.json").read_bytes() == (
        held / "fixture.json"
    ).read_bytes()


def test_profile_creation_rechecks_data_after_final_registry_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    data = tmp_path / "profiles" / "data" / "fixture"
    held = tmp_path / "held-profile-data"
    registry = tmp_path / "profiles" / "registry" / "fixture.json"
    original_read = profiles_module.read_bounded_control_snapshot_result
    changed = False

    def replace_data_after_registry_read(path: Path, *args, **kwargs):
        nonlocal changed
        snapshot = original_read(path, *args, **kwargs)
        if path == registry and not changed:
            changed = True
            data.rename(held)
            data.mkdir()
            (data / "competitor.bin").write_bytes(b"competitor")
        return snapshot

    monkeypatch.setattr(
        profiles_module,
        "read_bounded_control_snapshot_result",
        replace_data_after_registry_read,
    )
    with pytest.raises(ContractError, match="profile creation rollback incomplete"):
        create_profile(tmp_path, "fixture")
    assert changed
    assert held.is_dir()
    assert (data / "competitor.bin").read_bytes() == b"competitor"
    assert not registry.exists()


def test_profile_creation_removes_its_published_registry_on_late_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    registry = tmp_path / "profiles" / "registry" / "fixture.json"
    original_read = profiles_module.read_bounded_control_snapshot_result
    failed = False

    def fail_final_registry_read(path: Path, *args, **kwargs):
        nonlocal failed
        if path == registry and path.is_file() and not failed:
            failed = True
            raise ContractError("synthetic final registry read failure")
        return original_read(path, *args, **kwargs)

    monkeypatch.setattr(
        profiles_module, "read_bounded_control_snapshot_result", fail_final_registry_read
    )
    with pytest.raises(ContractError, match="synthetic final registry read failure"):
        create_profile(tmp_path, "fixture")
    assert failed
    assert not registry.exists()
    assert not profile_data_path(tmp_path, "fixture").exists()


def test_profile_registry_requires_canonical_name_bound_single_link_documents(
    tmp_path: Path,
) -> None:
    create_profile(tmp_path, "first-profile")
    registry = tmp_path / "profiles" / "registry"
    path = registry / "first-profile.json"
    canonical = path.read_bytes()
    path.write_bytes(
        canonical.replace(
            b'"id":"first-profile"',
            b'"id":"first-profile","id":"first-profile"',
            1,
        )
    )
    with pytest.raises(ContractError, match="invalid managed document"):
        load_profile(tmp_path, "first-profile")

    path.write_bytes(canonical)
    (registry / "other-profile.json").write_bytes(canonical)
    with pytest.raises(ContractError, match="filename"):
        load_profile(tmp_path, "other-profile")

    (registry / "other-profile.json").unlink()
    os.link(path, tmp_path / "profile-hard-link")
    with pytest.raises(ContractError, match="hard links"):
        load_profile(tmp_path, "first-profile")


def test_profile_registry_bounds_and_rechecks_population(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    create_profile(tmp_path, "first-profile")
    create_profile(tmp_path, "second-profile")
    monkeypatch.setattr(profiles_module, "MAX_PROFILE_REGISTRY_FILES", 1)
    with pytest.raises(ContractError, match="too many JSON files"):
        list_profiles(tmp_path)
    monkeypatch.setattr(profiles_module, "MAX_PROFILE_REGISTRY_FILES", 4096)
    original = profiles_module.inventory_bounded_json_directory
    calls = 0

    def appearing(directory: Path, **kwargs):
        nonlocal calls
        calls += 1
        result = original(directory, **kwargs)
        if calls == 1:
            (directory / "appeared-profile.json").write_text("{}\n", encoding="utf-8")
        return result

    monkeypatch.setattr(profiles_module, "inventory_bounded_json_directory", appearing)
    with pytest.raises(ContractError, match="registry changed"):
        list_profiles(tmp_path)


def test_profile_registry_rejects_casefold_duplicate_ids(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    template = create_profile(tmp_path, "fixture")
    profiles = {
        profile_id: validate_profile({**template, "id": profile_id, "name": profile_id})
        for profile_id in ("Alpha", "alpha")
    }
    identities = {
        "Alpha": (1, 2, 3, 4, 5, 6),
        "alpha": (1, 3, 3, 4, 5, 6),
    }
    inventory = profiles_module.inventory_bounded_json_directory

    def case_colliding_inventory(directory: Path, **kwargs: object):
        actual = inventory(directory, **kwargs)
        return control_files.BoundedJsonDirectoryInventory(
            state=actual.state,
            directory_identity=actual.directory_identity,
            files=tuple(
                (f"{profile_id}.json", identities[profile_id])
                for profile_id in profiles
            ),
        )

    def load_case_colliding_profile(_workspace: Path, profile_id: str):
        document = profiles[profile_id]
        return document, control_files.BoundedControlSnapshot(
            state="complete",
            body=canonical_json_bytes(document),
            identity=identities[profile_id],
        )

    monkeypatch.setattr(
        profiles_module, "inventory_bounded_json_directory", case_colliding_inventory
    )
    monkeypatch.setattr(
        profiles_module, "_load_profile_snapshot", load_case_colliding_profile
    )
    with pytest.raises(ContractError, match="duplicate IDs"):
        list_profiles(tmp_path)


@pytest.mark.skipif(os.name != "nt", reason="Windows restored-mtime profile custody")
def test_profile_list_rechecks_same_identity_content_after_inventory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    create_profile(tmp_path, "fixture", "Original")
    path = tmp_path / "profiles" / "registry" / "fixture.json"
    original_inventory = profiles_module.inventory_bounded_json_directory
    inventories = 0

    def mutate_before_second_inventory(directory: Path, **kwargs: object):
        nonlocal inventories
        inventories += 1
        if inventories == 2:
            before = path.stat()
            document = json.loads(path.read_text(encoding="ascii"))
            document["name"] = "Modified"
            replacement = canonical_json_bytes(document)
            assert len(replacement) == before.st_size
            path.write_bytes(replacement)
            os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns))
            after = path.stat()
            assert (after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns) == (
                before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns
            )
        return original_inventory(directory, **kwargs)

    monkeypatch.setattr(
        profiles_module,
        "inventory_bounded_json_directory",
        mutate_before_second_inventory,
    )
    with pytest.raises(ContractError, match="changed during registry load"):
        list_profiles(tmp_path)
    assert inventories == 2


def test_profile_lock_cannot_be_released_by_another_run(tmp_path: Path) -> None:
    create_profile(tmp_path, "fixture")
    lock = acquire_profile_lock(tmp_path, "fixture", "owner")
    with pytest.raises(ContractError, match="another session"):
        release_profile_lock(lock, "intruder")
    assert lock.exists()


@pytest.mark.skipif(os.name != "nt", reason="Windows directory junction boundary")
def test_profile_lock_missing_release_rejects_replaced_parent_junction(
    tmp_path: Path,
) -> None:
    create_profile(tmp_path, "fixture")
    lock = acquire_profile_lock(tmp_path, "fixture", "owner")
    data = lock.parent
    detached = tmp_path / "detached-profile-data"
    data.rename(detached)
    foreign = tmp_path / "foreign"
    foreign.mkdir()
    created = subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(data), str(foreign)],
        capture_output=True,
        check=False,
    )
    if created.returncode:
        detached.rename(data)
        pytest.skip("host could not create an unprivileged directory junction")
    try:
        with pytest.raises(ContractError, match="profile lock parent"):
            release_profile_lock(lock, "owner", missing_ok=True)
        assert (detached / lock.name).exists()
        assert list(foreign.iterdir()) == []
    finally:
        data.rmdir()
        detached.rename(data)
        release_profile_lock(lock, "owner")


def test_profile_lock_release_accepts_legacy_formatting(tmp_path: Path) -> None:
    create_profile(tmp_path, "fixture")
    lock = acquire_profile_lock(tmp_path, "fixture", "owner")
    lock.write_text(
        '{\n  "schema": "browser-core.profile-lock/1",\n  "run_id": "owner"\n}',
        encoding="utf-8",
    )
    release_profile_lock(lock, "owner")
    assert not lock.exists()


def test_profile_lock_release_rejects_ambiguous_or_hard_linked_ownership(
    tmp_path: Path,
) -> None:
    create_profile(tmp_path, "fixture")
    lock = acquire_profile_lock(tmp_path, "fixture", "owner")
    lock.write_text(
        '{"schema":"browser-core.profile-lock/1","run_id":"owner","run_id":"owner"}',
        encoding="utf-8",
    )
    with pytest.raises(ContractError, match="duplicate key"):
        release_profile_lock(lock, "owner")
    assert lock.exists()

    lock.write_bytes(
        canonical_json_bytes(
            {
                "schema": "browser-core.profile-lock/1",
                "run_id": "owner",
            }
        )
    )
    alias = tmp_path / "lock-alias"
    os.link(lock, alias)
    with pytest.raises(ContractError, match="hard links"):
        release_profile_lock(lock, "owner")
    assert lock.exists()


def test_profile_lock_release_preserves_a_racing_replacement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    create_profile(tmp_path, "fixture")
    lock = acquire_profile_lock(tmp_path, "fixture", "owner")
    competitor = canonical_json_bytes(
        {
            "schema": "browser-core.profile-lock/1",
            "run_id": "competitor",
        }
    )
    real_rename = control_files.os.rename

    def replace_before_rename(source_path: Path, quarantine: Path) -> None:
        injected = tmp_path / "injected-lock"
        injected.write_bytes(competitor)
        control_files.os.replace(injected, source_path)
        real_rename(source_path, quarantine)

    monkeypatch.setattr(control_files.os, "rename", replace_before_rename)
    with pytest.raises(ContractError, match="changed during removal") as raised:
        release_profile_lock(lock, "owner")
    assert str(lock) not in str(raised.value)
    assert lock.read_bytes() == competitor
    assert not list(lock.parent.glob("..browser-core.lock.removed-*"))


def test_identity_contract_is_canonicalized_and_pinned(tmp_path: Path) -> None:
    create_profile(tmp_path, "fixture")
    source = tmp_path / "source.json"
    source.write_text(
        '{"expected":{"window.platform":"Win32","userAgentData.mobile":false},"schema_version":1}',
        encoding="utf-8",
    )
    profile = attach_identity_contract(tmp_path, "fixture", source)
    assert profile["identity_mode"] == "host-native-pinned"
    assert profile["identity_contract"]["fields"] == [
        "userAgentData.mobile",
        "window.platform",
    ]
    resolved = profile_identity_contract(tmp_path, "fixture")
    assert resolved is not None
    assert Path(resolved["path"]).parent == profile_data_path(tmp_path, "fixture")


def test_identity_contract_tampering_is_detected(tmp_path: Path) -> None:
    create_profile(tmp_path, "fixture")
    source = tmp_path / "source.json"
    source.write_text(
        '{"schema_version":1,"expected":{"window.platform":"Win32"}}',
        encoding="utf-8",
    )
    attach_identity_contract(tmp_path, "fixture", source)
    pinned = profile_data_path(tmp_path, "fixture") / "identity-contract.json"
    pinned.write_text(
        '{"schema_version":1,"expected":{"window.platform":"Linux x86_64"}}',
        encoding="utf-8",
    )
    with pytest.raises(ContractError, match="pinned metadata"):
        profile_identity_contract(tmp_path, "fixture")


def test_profile_identity_path_rechecks_contract_after_resolution(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    create_profile(tmp_path, "fixture")
    source = tmp_path / "source.json"
    source.write_text(
        '{"schema_version":1,"expected":{"window.platform":"Win32"}}',
        encoding="utf-8",
    )
    attach_identity_contract(tmp_path, "fixture", source)
    pinned = profile_data_path(tmp_path, "fixture") / "identity-contract.json"
    original_resolve = Path.resolve
    replaced = False

    def replace_during_resolve(path: Path, *args: object, **kwargs: object) -> Path:
        nonlocal replaced
        if path == pinned and not replaced:
            replaced = True
            pinned.write_text(
                '{"schema_version":1,"expected":{"window.platform":"Linux x86_64"}}',
                encoding="utf-8",
            )
        return original_resolve(path, *args, **kwargs)

    monkeypatch.setattr(Path, "resolve", replace_during_resolve)
    with pytest.raises(ContractError):
        profile_identity_contract(tmp_path, "fixture")
    assert replaced


def test_load_profile_identity_document_rechecks_contract_after_decode(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    create_profile(tmp_path, "fixture")
    source = tmp_path / "source.json"
    source.write_text(
        '{"schema_version":1,"expected":{"window.platform":"Win32"}}',
        encoding="utf-8",
    )
    attach_identity_contract(tmp_path, "fixture", source)
    pinned = profile_data_path(tmp_path, "fixture") / "identity-contract.json"
    original_snapshot = profiles_module._profile_identity_snapshot
    changed = False

    def change_after_snapshot(workspace: Path, profile_id: str, **kwargs: object):
        nonlocal changed
        snapshot = original_snapshot(workspace, profile_id, **kwargs)
        if not changed:
            changed = True
            original = pinned.read_bytes()
            assert b"Win32" in original
            pinned.write_bytes(original.replace(b"Win32", b"Linux"))
        return snapshot

    monkeypatch.setattr(profiles_module, "_profile_identity_snapshot", change_after_snapshot)
    with pytest.raises(ContractError):
        profiles_module.load_profile_identity_document(tmp_path, "fixture")
    assert changed


@pytest.mark.parametrize("reader", ["path", "document"])
def test_profile_identity_reader_rechecks_profile_after_final_contract_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, reader: str
) -> None:
    create_profile(tmp_path, "fixture")
    source = tmp_path / "source.json"
    source.write_text(
        '{"schema_version":1,"expected":{"window.platform":"Win32"}}',
        encoding="utf-8",
    )
    attach_identity_contract(tmp_path, "fixture", source)
    registry = tmp_path / "profiles" / "registry" / "fixture.json"
    original_read = profiles_module._read_identity_contract_bytes
    reads = 0

    def change_profile_after_contract_read(path: Path, **kwargs: object) -> bytes:
        nonlocal reads
        body = original_read(path, **kwargs)
        reads += 1
        if reads == 2:
            profile = load_profile(tmp_path, "fixture")
            profile["identity_mode"] = "host-native"
            profile.pop("identity_contract")
            registry.write_bytes(canonical_json_bytes(profile))
        return body

    monkeypatch.setattr(
        profiles_module,
        "_read_identity_contract_bytes",
        change_profile_after_contract_read,
    )
    with pytest.raises(ContractError, match="profile identity changed during read"):
        if reader == "path":
            profile_identity_contract(tmp_path, "fixture")
        else:
            profiles_module.load_profile_identity_document(tmp_path, "fixture")
    assert reads == 2


@pytest.mark.parametrize("reader", ["path", "document"])
def test_profile_identity_reader_rejects_replaced_profiles_parent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, reader: str
) -> None:
    create_profile(tmp_path, "fixture")
    source = tmp_path / "source.json"
    source.write_text(
        '{"schema_version":1,"expected":{"window.platform":"Win32"}}',
        encoding="utf-8",
    )
    attach_identity_contract(tmp_path, "fixture", source)
    profiles = tmp_path / "profiles"
    detached = tmp_path / "detached-profiles"
    original_read = profiles_module._read_identity_contract_bytes
    swapped = False

    def swap_after_contract_read(path: Path, **kwargs: object) -> bytes:
        nonlocal swapped
        body = original_read(path, **kwargs)
        if not swapped:
            swapped = True
            profiles.rename(detached)
            profiles.mkdir()
            (detached / "registry").rename(profiles / "registry")
            (detached / "data").rename(profiles / "data")
        return body

    monkeypatch.setattr(
        profiles_module, "_read_identity_contract_bytes", swap_after_contract_read
    )
    with pytest.raises(ContractError, match="profile identity ancestry changed during read"):
        if reader == "path":
            profile_identity_contract(tmp_path, "fixture")
        else:
            profiles_module.load_profile_identity_document(tmp_path, "fixture")
    assert swapped
    assert (profiles / "registry" / "fixture.json").is_file()
    assert (profiles / "data" / "fixture" / "identity-contract.json").is_file()


def test_load_profile_identity_document_rechecks_missing_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    create_profile(tmp_path, "fixture")
    source = tmp_path / "source.json"
    source.write_text(
        '{"schema_version":1,"expected":{"window.platform":"Win32"}}',
        encoding="utf-8",
    )
    original_snapshot = profiles_module._load_profile_snapshot
    attached = False

    def attach_after_missing_read(workspace: Path, profile_id: str, **kwargs: object):
        nonlocal attached
        result = original_snapshot(workspace, profile_id, **kwargs)
        if not attached:
            attached = True
            monkeypatch.setattr(profiles_module, "_load_profile_snapshot", original_snapshot)
            attach_identity_contract(tmp_path, "fixture", source)
        return result

    monkeypatch.setattr(profiles_module, "_load_profile_snapshot", attach_after_missing_read)
    with pytest.raises(ContractError, match="profile identity changed during read"):
        profiles_module.load_profile_identity_document(tmp_path, "fixture")
    assert attached


@pytest.mark.skipif(os.name != "nt", reason="Windows directory junction boundary")
def test_profile_identity_read_rejects_replaced_data_directory_junction(
    tmp_path: Path,
) -> None:
    create_profile(tmp_path, "fixture")
    source = tmp_path / "source.json"
    source.write_text(
        '{"schema_version":1,"expected":{"window.platform":"Win32"}}',
        encoding="utf-8",
    )
    attach_identity_contract(tmp_path, "fixture", source)
    data = profile_data_path(tmp_path, "fixture")
    foreign = tmp_path / "foreign"
    foreign.mkdir()
    (foreign / "identity-contract.json").write_bytes(
        (data / "identity-contract.json").read_bytes()
    )
    held = tmp_path / "held-profile-data"
    data.rename(held)
    created = subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(data), str(foreign)],
        capture_output=True, check=False,
    )
    if created.returncode:
        pytest.skip("host could not create an unprivileged directory junction")
    try:
        with pytest.raises(ContractError):
            profile_identity_contract(tmp_path, "fixture")
        with pytest.raises(ContractError):
            profiles_module.load_profile_identity_document(tmp_path, "fixture")
    finally:
        if data.exists():
            data.rmdir()


@pytest.mark.skipif(os.name != "nt", reason="Windows directory junction boundary")
def test_profile_reader_rejects_replaced_registry_directory_junction(
    tmp_path: Path,
) -> None:
    create_profile(tmp_path, "fixture")
    registry = tmp_path / "profiles" / "registry"
    held = tmp_path / "held-registry"
    registry.rename(held)
    foreign = tmp_path / "foreign"
    foreign.mkdir()
    (foreign / "fixture.json").write_bytes((held / "fixture.json").read_bytes())
    created = subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(registry), str(foreign)],
        capture_output=True, check=False,
    )
    if created.returncode:
        pytest.skip("host could not create an unprivileged directory junction")
    try:
        with pytest.raises(ContractError):
            load_profile(tmp_path, "fixture")
    finally:
        if registry.exists():
            registry.rmdir()


def test_profile_reader_rejects_registry_replaced_only_during_snapshot(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    create_profile(tmp_path, "fixture", "Local")
    registry = tmp_path / "profiles" / "registry"
    path = registry / "fixture.json"
    foreign = tmp_path / "foreign-registry"
    foreign.mkdir()
    forged = {**load_profile(tmp_path, "fixture"), "name": "Foreign"}
    (foreign / "fixture.json").write_bytes(canonical_json_bytes(forged))
    held = tmp_path / "held-registry"
    original = profiles_module.read_bounded_control_snapshot_result
    redirected = False

    def swapped_snapshot(candidate: Path, **kwargs: object):
        nonlocal redirected
        if candidate == path and not redirected:
            redirected = True
            registry.rename(held)
            foreign.rename(registry)
            try:
                return original(candidate, **kwargs)
            finally:
                registry.rename(foreign)
                held.rename(registry)
        return original(candidate, **kwargs)

    monkeypatch.setattr(
        profiles_module, "read_bounded_control_snapshot_result", swapped_snapshot
    )
    with pytest.raises(ContractError, match="changed"):
        load_profile(tmp_path, "fixture")
    assert redirected
    assert path.read_bytes() != (foreign / "fixture.json").read_bytes()


def test_profile_reader_rejects_replaced_profiles_parent_with_same_registry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    create_profile(tmp_path, "fixture")
    profiles = tmp_path / "profiles"
    detached = tmp_path / "detached-profiles"
    registry = profiles / "registry"
    path = registry / "fixture.json"
    original = profiles_module.read_bounded_control_snapshot_result
    swapped = False

    def swap_after_first_read(candidate: Path, **kwargs: object):
        nonlocal swapped
        result = original(candidate, **kwargs)
        if candidate == path and not swapped:
            swapped = True
            profiles.rename(detached)
            profiles.mkdir()
            (detached / "registry").rename(registry)
        return result

    monkeypatch.setattr(
        profiles_module, "read_bounded_control_snapshot_result", swap_after_first_read
    )
    with pytest.raises(ContractError, match="profile registry ancestry changed during read"):
        load_profile(tmp_path, "fixture")
    assert swapped
    assert path.is_file()
    assert (detached / "data" / "fixture").is_dir()


@pytest.mark.skipif(os.name != "nt", reason="Windows directory junction boundary")
def test_profile_inventory_rejects_empty_foreign_registry(
    tmp_path: Path,
) -> None:
    create_profile(tmp_path, "fixture")
    profiles = tmp_path / "profiles"
    held = tmp_path / "held-profiles"
    profiles.rename(held)
    foreign = tmp_path / "foreign"
    (foreign / "registry").mkdir(parents=True)
    created = subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(profiles), str(foreign)],
        capture_output=True, check=False,
    )
    if created.returncode:
        pytest.skip("host could not create an unprivileged directory junction")
    try:
        with pytest.raises(ContractError):
            list_profiles(tmp_path)
    finally:
        if profiles.exists():
            profiles.rmdir()


def test_profile_inventory_rejects_same_transient_foreign_directory_twice(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    create_profile(tmp_path, "fixture")
    registry = tmp_path / "profiles" / "registry"
    foreign = tmp_path / "foreign-registry"
    foreign.mkdir()
    held = tmp_path / "held-registry"
    original = profiles_module.inventory_bounded_json_directory
    swaps = 0

    def swapped_inventory(directory: Path, **kwargs: object):
        nonlocal swaps
        swaps += 1
        registry.rename(held)
        foreign.rename(registry)
        try:
            return original(directory, **kwargs)
        finally:
            registry.rename(foreign)
            held.rename(registry)

    monkeypatch.setattr(
        profiles_module, "inventory_bounded_json_directory", swapped_inventory
    )
    with pytest.raises(ContractError, match="changed"):
        list_profiles(tmp_path)
    assert swaps >= 1
    assert (registry / "fixture.json").exists()


def test_identity_contract_rejects_sensitive_claim_path(tmp_path: Path) -> None:
    create_profile(tmp_path, "fixture")
    source = tmp_path / "source.json"
    source.write_text(
        '{"schema_version":1,"expected":{"window.sessionToken":"no"}}',
        encoding="utf-8",
    )
    with pytest.raises(ContractError, match="sensitive"):
        attach_identity_contract(tmp_path, "fixture", source)


def test_profile_binds_exact_persona_and_aligned_network_route(tmp_path: Path) -> None:
    create_profile(tmp_path, "fixture")
    persona = fixture_persona()
    add_persona(tmp_path, persona)
    route = build_network_route(
        route_id="direct-us",
        name="Direct US",
        geography={"country": "US", "locale": "en-US", "timezone": "America/Chicago"},
    )
    add_network_route(tmp_path, route)
    attached = attach_persona(tmp_path, "fixture", persona["id"])
    assert attached["persona"]["sha256_16"] == persona["integrity_sha256"][:16]
    attach_network_route(tmp_path, "fixture", route["id"])
    bindings = profile_bindings(tmp_path, "fixture")
    assert bindings["persona"] == persona and bindings["network_route"] == route
    identity = profile_identity_contract(tmp_path, "fixture")
    assert identity is not None and set(identity["fields"]) == {
        "userAgentData.mobile",
        "window.platform",
    }


def test_profile_bindings_reject_profile_removed_during_binding_load(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    create_profile(tmp_path, "fixture")
    persona = fixture_persona()
    add_persona(tmp_path, persona)
    attach_persona(tmp_path, "fixture", persona["id"])
    registry = tmp_path / "profiles" / "registry" / "fixture.json"
    held = tmp_path / "held-profile.json"
    original = profiles_module._load_profile_snapshot
    removed = False

    def remove_after_first_snapshot(workspace: Path, profile_id: str):
        nonlocal removed
        result = original(workspace, profile_id)
        if not removed:
            removed = True
            registry.rename(held)
        return result

    monkeypatch.setattr(profiles_module, "_load_profile_snapshot", remove_after_first_snapshot)
    with pytest.raises(ContractError):
        profile_bindings(tmp_path, "fixture")
    assert removed
    assert held.is_file()


@pytest.mark.parametrize("removed_kind", ["persona", "route"])
def test_profile_bindings_recheck_bound_documents_after_profile_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, removed_kind: str
) -> None:
    create_profile(tmp_path, "fixture")
    persona = fixture_persona()
    add_persona(tmp_path, persona)
    route = build_network_route(
        route_id="direct-us",
        name="Direct US",
        geography={"country": "US", "locale": "en-US", "timezone": "America/Chicago"},
    )
    add_network_route(tmp_path, route)
    attach_persona(tmp_path, "fixture", persona["id"])
    attach_network_route(tmp_path, "fixture", route["id"])
    target = (
        tmp_path / "personas" / "catalog" / f"{persona['id']}.json"
        if removed_kind == "persona"
        else tmp_path / "network" / "routes" / f"{route['id']}.json"
    )
    held = tmp_path / f"held-{removed_kind}.json"
    original = profiles_module._load_profile_snapshot
    reads = 0

    def remove_after_final_profile_read(workspace: Path, profile_id: str):
        nonlocal reads
        result = original(workspace, profile_id)
        reads += 1
        if reads == 2:
            target.rename(held)
        return result

    monkeypatch.setattr(
        profiles_module, "_load_profile_snapshot", remove_after_final_profile_read,
    )
    with pytest.raises(ContractError):
        profile_bindings(tmp_path, "fixture")
    assert reads >= 2 and held.is_file()


@pytest.mark.parametrize("source_kind", ["persona", "route"])
def test_profile_bindings_recheck_profile_after_final_source_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, source_kind: str
) -> None:
    create_profile(tmp_path, "fixture")
    persona = fixture_persona()
    add_persona(tmp_path, persona)
    route = build_network_route(
        route_id="direct-us",
        name="Direct US",
        geography={"country": "US", "locale": "en-US", "timezone": "America/Chicago"},
    )
    add_network_route(tmp_path, route)
    attach_persona(tmp_path, "fixture", persona["id"])
    attach_network_route(tmp_path, "fixture", route["id"])
    registry = tmp_path / "profiles" / "registry" / "fixture.json"
    source_module = personas_module if source_kind == "persona" else network_module
    loader_name = "load_persona" if source_kind == "persona" else "load_network_route"
    original_load = getattr(source_module, loader_name)
    reads = 0

    def change_profile_after_source_read(workspace: Path, source_id: str):
        nonlocal reads
        document = original_load(workspace, source_id)
        reads += 1
        if reads == 2:
            competitor = json.loads(registry.read_bytes())
            competitor["name"] = "Changed during final binding read"
            registry.write_bytes(canonical_json_bytes(competitor))
        return document

    monkeypatch.setattr(source_module, loader_name, change_profile_after_source_read)
    with pytest.raises(ContractError, match="profile changed during binding load"):
        profile_bindings(tmp_path, "fixture")
    assert reads == 2
    assert load_profile(tmp_path, "fixture")["name"] == "Changed during final binding read"


def test_profile_bindings_rejects_profiles_parent_replaced_between_reads(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    create_profile(tmp_path, "fixture")
    persona = fixture_persona()
    add_persona(tmp_path, persona)
    attach_persona(tmp_path, "fixture", persona["id"])
    profiles = tmp_path / "profiles"
    detached = tmp_path / "detached-profiles"
    registry = profiles / "registry"
    original = profiles_module._load_profile_snapshot
    swapped = False

    def swap_after_first_profile_read(workspace: Path, profile_id: str):
        nonlocal swapped
        result = original(workspace, profile_id)
        if not swapped:
            swapped = True
            profiles.rename(detached)
            profiles.mkdir()
            (detached / "registry").rename(registry)
        return result

    monkeypatch.setattr(
        profiles_module, "_load_profile_snapshot", swap_after_first_profile_read
    )
    with pytest.raises(ContractError, match="profile registry ancestry changed during binding load"):
        profile_bindings(tmp_path, "fixture")
    assert swapped
    assert (registry / "fixture.json").is_file()
    assert (detached / "data" / "fixture" / "identity-contract.json").is_file()


def test_profile_rejects_persona_network_geography_mismatch(tmp_path: Path) -> None:
    create_profile(tmp_path, "fixture")
    persona = fixture_persona()
    add_persona(tmp_path, persona)
    add_network_route(
        tmp_path,
        build_network_route(
            route_id="direct-ca",
            name="Direct CA",
            geography={
                "country": "CA",
                "locale": "en-CA",
                "timezone": "America/Toronto",
            },
        ),
    )
    attach_persona(tmp_path, "fixture", persona["id"])
    attach_network_route(tmp_path, "fixture", "direct-ca")
    with pytest.raises(ContractError, match="disagree"):
        profile_bindings(tmp_path, "fixture")


@pytest.mark.parametrize(
    "profile_id", ["", ".hidden", "../escape", "space name", "x" * 65, "alias."]
)
def test_profile_id_is_path_safe(tmp_path: Path, profile_id: str) -> None:
    with pytest.raises(ContractError):
        create_profile(tmp_path, profile_id)


@pytest.mark.parametrize(
    "profile_id", ["CON", "con.log", "PRN", "AUX", "NUL", "nul.x", "COM1", "LPT9.backup"]
)
def test_profile_id_rejects_windows_device_names_before_creation(
    tmp_path: Path, profile_id: str
) -> None:
    with pytest.raises(ContractError, match="profile ID"):
        create_profile(tmp_path, profile_id)
    assert not (tmp_path / "profiles").exists()


def test_saved_profile_rejects_trailing_dot_id(tmp_path: Path) -> None:
    original = create_profile(tmp_path, "alias")
    saved = {**original, "id": "alias."}
    (tmp_path / "profiles" / "registry" / "alias..json").write_bytes(
        canonical_json_bytes(saved)
    )
    with pytest.raises(ContractError, match="profile ID"):
        load_profile(tmp_path, "alias.")


@pytest.mark.parametrize("name", [False, 0, [], {}])
def test_profile_creation_rejects_falsey_nonstring_names(
    tmp_path: Path, name: object
) -> None:
    with pytest.raises(ContractError, match="profile name"):
        create_profile(tmp_path, "fixture", name=name)  # type: ignore[arg-type]
    assert not (tmp_path / "profiles").exists()


@pytest.mark.parametrize("surrogate", ["\ud800", "\udc00"])
def test_profile_rejects_unpaired_surrogate_name_before_creation(
    tmp_path: Path, surrogate: str
) -> None:
    seed = tmp_path / "seed"
    document = create_profile(seed, "fixture")
    malformed = {**document, "name": f"invalid{surrogate}"}
    with pytest.raises(ContractError, match="profile name"):
        validate_profile(malformed)

    destination = tmp_path / "destination"
    with pytest.raises(ContractError, match="profile name"):
        create_profile(destination, "fixture", name=malformed["name"])
    assert not (destination / "profiles").exists()


def test_profile_validation_rejects_unknown_and_unhashable_identity_fields(
    tmp_path: Path,
) -> None:
    document = create_profile(tmp_path, "fixture")
    with pytest.raises(ContractError, match="fields are invalid"):
        validate_profile({**document, "uninterpreted": True})
    with pytest.raises(ContractError, match="identity mode"):
        validate_profile({**document, "identity_mode": []})

    malformed = {
        **document,
        "identity_mode": "host-native-pinned",
        "identity_contract": {
            "file": "identity-contract.json",
            "sha256_16": "0" * 16,
            "fields": [["window.platform"]],
        },
    }
    with pytest.raises(ContractError, match="fields are invalid"):
        validate_profile(malformed)


@pytest.mark.parametrize("field", ["persona", "network_route"])
def test_saved_profile_rejects_windows_device_binding_id(
    tmp_path: Path, field: str
) -> None:
    document = create_profile(tmp_path, "fixture")
    malformed = {
        **document,
        field: {"id": "NUL", "sha256_16": "0" * 16},
    }
    path = tmp_path / "profiles" / "registry" / "fixture.json"
    path.write_bytes(canonical_json_bytes(malformed))

    with pytest.raises(ContractError, match="invalid managed document"):
        load_profile(tmp_path, "fixture")


@pytest.mark.parametrize("mode", ["pinned-without-contract", "native-with-contract"])
def test_profile_identity_mode_and_contract_metadata_must_agree(
    tmp_path: Path, mode: str
) -> None:
    profile = create_profile(tmp_path, "fixture")
    if mode == "pinned-without-contract":
        malformed = {**profile, "identity_mode": "host-native-pinned"}
    else:
        malformed = {
            **profile,
            "identity_contract": {
                "file": "identity-contract.json",
                "sha256_16": "0" * 16,
                "fields": ["window.platform"],
            },
        }
    with pytest.raises(ContractError, match="identity mode and contract"):
        validate_profile(malformed)
    path = tmp_path / "profiles" / "registry" / "fixture.json"
    path.write_bytes(canonical_json_bytes(malformed))
    with pytest.raises(ContractError, match="cannot read profile document"):
        load_profile(tmp_path, "fixture")


def test_profile_rejects_nonstring_created_at_without_coercion(tmp_path: Path) -> None:
    document = create_profile(tmp_path, "fixture")

    class UnexpectedStringConversion:
        def __str__(self) -> str:
            pytest.fail("invalid created_at was converted before type validation")

    with pytest.raises(ContractError, match="created_at is invalid"):
        validate_profile({**document, "created_at": UnexpectedStringConversion()})


def test_profile_load_enforces_byte_bound_before_json_decode(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    create_profile(tmp_path, "fixture")
    monkeypatch.setattr(profiles_module, "MAX_PROFILE_DOCUMENT_BYTES", 1)
    with pytest.raises(ContractError, match="exceeds 1 bytes"):
        load_profile(tmp_path, "fixture")


@pytest.mark.parametrize("value", ["NaN", "Infinity", "-Infinity"])
def test_identity_contract_rejects_non_finite_values(value: str) -> None:
    raw = (
        '{"schema_version":1,"expected":{"window.devicePixelRatio":%s}}' % value
    ).encode()
    with pytest.raises(ContractError, match="strict JSON"):
        canonicalize_identity_contract(raw)


@pytest.mark.parametrize(
    "raw",
    [
        b'{"schema_version":1,"schema_version":1,"expected":{"window.platform":"Win32"}}',
        b'{"schema_version":1,"expected":{"window.platform":"Win32","window.platform":"Linux"}}',
    ],
)
def test_identity_contract_rejects_duplicate_members(raw: bytes) -> None:
    with pytest.raises(ContractError, match="duplicate key"):
        canonicalize_identity_contract(raw)


def test_identity_contract_rejects_unknown_top_level_fields() -> None:
    raw = b'{"schema_version":1,"expected":{"window.platform":"Win32"},"ignored":true}'
    with pytest.raises(ContractError, match="fields are invalid"):
        canonicalize_identity_contract(raw)


@pytest.mark.parametrize("version", [True, 1.0])
def test_identity_contract_requires_exact_integer_schema_version(version: object) -> None:
    raw = canonical_json_bytes(
        {"schema_version": version, "expected": {"window.platform": "Win32"}}
    )
    with pytest.raises(ContractError, match="schema_version 1"):
        canonicalize_identity_contract(raw)


@pytest.mark.parametrize(
    "claim,value",
    [
        ("private-location-marker", "value"),
        ("privateLocationMarker.value", "value"),
        ("window.privateTokenMarker", "value"),
        ("window.privateLocationMarker", {"nested": "value"}),
        ("window.privateLocationMarker", "x" * 4097),
    ],
)
def test_identity_contract_rejection_does_not_echo_claim_path(
    claim: str, value: object
) -> None:
    raw = json.dumps({"schema_version": 1, "expected": {claim: value}}).encode()
    with pytest.raises(ContractError) as failure:
        canonicalize_identity_contract(raw)
    assert "private" not in str(failure.value).lower()


def test_identity_contract_source_and_pin_require_single_link_files(
    tmp_path: Path,
) -> None:
    create_profile(tmp_path, "fixture")
    source = tmp_path / "source.json"
    source.write_text(
        '{"schema_version":1,"expected":{"window.platform":"Win32"}}',
        encoding="utf-8",
    )
    alias = tmp_path / "source-alias.json"
    os.link(source, alias)
    with pytest.raises(ContractError, match="hard links"):
        attach_identity_contract(tmp_path, "fixture", source)

    alias.unlink()
    attach_identity_contract(tmp_path, "fixture", source)
    pinned = profile_data_path(tmp_path, "fixture") / "identity-contract.json"
    os.link(pinned, tmp_path / "pinned-alias.json")
    with pytest.raises(ContractError, match="hard links"):
        profile_identity_contract(tmp_path, "fixture")


def test_identity_contract_path_requires_exact_path_type(tmp_path: Path) -> None:
    create_profile(tmp_path, "fixture")
    with pytest.raises(ContractError, match="path must be a Path"):
        attach_identity_contract(tmp_path, "fixture", str(tmp_path / "source.json"))  # type: ignore[arg-type]


def test_identity_contract_source_is_bounded_before_json_decode(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    create_profile(tmp_path, "fixture")
    source = tmp_path / "source.json"
    source.write_bytes(b"{" + b"x" * 128)
    monkeypatch.setattr(profiles_module, "MAX_IDENTITY_CONTRACT_BYTES", 32)
    with pytest.raises(ContractError, match="exceeds 32 bytes"):
        attach_identity_contract(tmp_path, "fixture", source)


def test_identity_contract_is_immutable_after_first_pin(tmp_path: Path) -> None:
    create_profile(tmp_path, "fixture")
    first = tmp_path / "first.json"
    first.write_text(
        '{"schema_version":1,"expected":{"window.platform":"Win32"}}',
        encoding="utf-8",
    )
    second = tmp_path / "second.json"
    second.write_text(
        '{"schema_version":1,"expected":{"window.platform":"Linux x86_64"}}',
        encoding="utf-8",
    )
    attach_identity_contract(tmp_path, "fixture", first)
    pinned = profile_data_path(tmp_path, "fixture") / "identity-contract.json"
    original = pinned.read_bytes()

    with pytest.raises(ContractError, match="already pinned"):
        attach_identity_contract(tmp_path, "fixture", second)
    assert pinned.read_bytes() == original


@pytest.mark.parametrize("attachment", ["identity", "persona", "ops-persona"])
def test_identity_attachment_rechecks_pin_after_profile_write(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, attachment: str
) -> None:
    profile_id = "ops-disp-fixture" if attachment == "ops-persona" else "fixture"
    create_profile(tmp_path, profile_id)
    source = tmp_path / "source.json"
    source.write_text(
        '{"schema_version":1,"expected":{"window.platform":"Win32"}}',
        encoding="utf-8",
    )
    if attachment != "identity":
        persona = fixture_persona()
        add_persona(tmp_path, persona)
    pinned = profile_data_path(tmp_path, profile_id) / "identity-contract.json"
    registry = tmp_path / "profiles" / "registry" / f"{profile_id}.json"
    original_write = profiles_module._write_json_atomic
    changed = False

    def change_after_registry_write(path: Path, document: dict, *, expected=None):
        nonlocal changed
        result = original_write(path, document, expected=expected)
        if path == registry and not changed:
            changed = True
            original = pinned.read_bytes()
            assert b"Win32" in original
            pinned.write_bytes(original.replace(b"Win32", b"Linux"))
        return result

    monkeypatch.setattr(profiles_module, "_write_json_atomic", change_after_registry_write)
    with pytest.raises(ContractError):
        if attachment == "identity":
            attach_identity_contract(tmp_path, profile_id, source)
        elif attachment == "persona":
            attach_persona(tmp_path, profile_id, persona["id"])
        else:
            profiles_module.attach_persona_identity_for_ops(tmp_path, profile_id, persona["id"])
    assert changed


def test_identity_attachment_rechecks_full_profile_after_write(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    create_profile(tmp_path, "fixture")
    source = tmp_path / "source.json"
    source.write_text(
        '{"schema_version":1,"expected":{"window.platform":"Win32"}}',
        encoding="utf-8",
    )
    registry = tmp_path / "profiles" / "registry" / "fixture.json"
    original_write = profiles_module._write_json_atomic
    changed = False

    def change_after_registry_write(path: Path, document: dict, *, expected=None):
        nonlocal changed
        result = original_write(path, document, expected=expected)
        if path == registry and not changed:
            changed = True
            replacement = json.loads(registry.read_bytes())
            replacement["name"] = "Changed after attachment"
            registry.write_bytes(canonical_json_bytes(replacement))
        return result

    monkeypatch.setattr(profiles_module, "_write_json_atomic", change_after_registry_write)
    with pytest.raises(ContractError, match="profile changed during identity attachment"):
        attach_identity_contract(tmp_path, "fixture", source)
    assert changed


@pytest.mark.parametrize("attachment", ["persona", "ops-persona"])
@pytest.mark.parametrize("changed_document", ["catalog", "registry"])
def test_persona_attachment_rechecks_catalog_and_profile_after_write(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    attachment: str,
    changed_document: str,
) -> None:
    profile_id = "ops-disp-fixture" if attachment == "ops-persona" else "fixture"
    create_profile(tmp_path, profile_id)
    persona = fixture_persona()
    add_persona(tmp_path, persona)
    registry = tmp_path / "profiles" / "registry" / f"{profile_id}.json"
    catalog = tmp_path / "personas" / "catalog" / f"{persona['id']}.json"
    original_write = profiles_module._write_json_atomic
    changed = False

    def change_after_registry_write(path: Path, document: dict, *, expected=None):
        nonlocal changed
        result = original_write(path, document, expected=expected)
        if path == registry and not changed:
            changed = True
            if changed_document == "catalog":
                replacement = json.loads(catalog.read_bytes())
                replacement["name"] = "Changed persona"
                replacement["integrity_sha256"] = persona_digest(replacement)
                catalog.write_bytes(canonical_json_bytes(replacement))
            else:
                replacement = json.loads(registry.read_bytes())
                replacement["persona"]["id"] = "other-persona"
                registry.write_bytes(canonical_json_bytes(replacement))
        return result

    monkeypatch.setattr(profiles_module, "_write_json_atomic", change_after_registry_write)
    with pytest.raises(ContractError, match="changed"):
        if attachment == "persona":
            attach_persona(tmp_path, profile_id, persona["id"])
        else:
            profiles_module.attach_persona_identity_for_ops(
                tmp_path, profile_id, persona["id"]
            )
    assert changed


@pytest.mark.parametrize("attachment", ["persona", "ops-persona"])
def test_persona_attachment_rechecks_identity_after_final_persona_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, attachment: str
) -> None:
    profile_id = "ops-disp-fixture" if attachment == "ops-persona" else "fixture"
    create_profile(tmp_path, profile_id)
    persona = fixture_persona()
    add_persona(tmp_path, persona)
    pinned = profile_data_path(tmp_path, profile_id) / "identity-contract.json"
    original_require = profiles_module._require_attached_persona
    changed = False

    def change_identity_after_persona_read(
        workspace: Path, profile_id: str, document: dict, selected: dict
    ) -> None:
        nonlocal changed
        original_require(workspace, profile_id, document, selected)
        original = pinned.read_bytes()
        assert b"Win32" in original
        pinned.write_bytes(original.replace(b"Win32", b"Linux"))
        changed = True

    monkeypatch.setattr(
        profiles_module, "_require_attached_persona", change_identity_after_persona_read
    )
    with pytest.raises(ContractError, match="identity"):
        if attachment == "persona":
            attach_persona(tmp_path, profile_id, persona["id"])
        else:
            profiles_module.attach_persona_identity_for_ops(
                tmp_path, profile_id, persona["id"]
            )
    assert changed
    assert b"Linux" in pinned.read_bytes()


@pytest.mark.parametrize("attachment", ["persona", "ops-persona"])
def test_persona_attachment_rechecks_catalog_after_final_identity_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, attachment: str
) -> None:
    profile_id = "ops-disp-fixture" if attachment == "ops-persona" else "fixture"
    create_profile(tmp_path, profile_id)
    persona = fixture_persona()
    add_persona(tmp_path, persona)
    catalog = tmp_path / "personas" / "catalog" / f"{persona['id']}.json"
    replacement = {**persona, "name": "Changed after persona read"}
    replacement["integrity_sha256"] = persona_digest(replacement)
    original_load = personas_module.load_persona
    reads = 0

    def change_after_persona_read(workspace: Path, persona_id: str):
        nonlocal reads
        document = original_load(workspace, persona_id)
        reads += 1
        if reads == 2:
            catalog.write_bytes(canonical_json_bytes(replacement))
        return document

    monkeypatch.setattr(personas_module, "load_persona", change_after_persona_read)
    with pytest.raises(ContractError, match="persona attachment changed"):
        if attachment == "persona":
            attach_persona(tmp_path, profile_id, persona["id"])
        else:
            profiles_module.attach_persona_identity_for_ops(
                tmp_path, profile_id, persona["id"]
            )
    assert reads >= 2
    assert catalog.read_bytes() == canonical_json_bytes(replacement)


def test_ops_identity_override_rejects_a_cycle_without_profile_mutation(
    tmp_path: Path,
) -> None:
    profile_id = "ops-disp-cycle"
    persona = fixture_persona()
    create_profile(tmp_path, profile_id)
    add_persona(tmp_path, persona)
    before = load_profile(tmp_path, profile_id)
    cyclic: dict[str, object] = {"schema_version": 1}
    cyclic["expected"] = cyclic

    with pytest.raises(ContractError, match="identity contract override"):
        profiles_module.attach_persona_identity_for_ops(
            tmp_path,
            profile_id,
            persona["id"],
            identity_contract=cyclic,
        )

    assert load_profile(tmp_path, profile_id) == before
    assert not (profile_data_path(tmp_path, profile_id) / "identity-contract.json").exists()


def test_profile_update_preserves_a_racing_registry_replacement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    create_profile(tmp_path, "fixture")
    add_network_route(
        tmp_path,
        build_network_route(
            route_id="direct-us",
            name="Direct US",
            geography={
                "country": "US",
                "locale": "en-US",
                "timezone": "America/Chicago",
            },
        ),
    )
    competitor = {**load_profile(tmp_path, "fixture"), "name": "Competitor"}
    real_replace = profiles_module.replace_json_conditionally

    def inject_then_replace(path: Path, document: dict, **kwargs: object) -> None:
        injected = tmp_path / "competitor-profile.json"
        injected.write_bytes(canonical_json_bytes(competitor))
        injected.replace(path)
        real_replace(path, document, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(
        profiles_module, "replace_json_conditionally", inject_then_replace
    )
    with pytest.raises(ContractError, match="changed before transition"):
        attach_network_route(tmp_path, "fixture", "direct-us")
    assert load_profile(tmp_path, "fixture")["name"] == "Competitor"


def test_disposable_profile_delete_quarantines_then_removes_owned_tree(
    tmp_path: Path,
) -> None:
    profile_id = "ops-disp-fixture"
    create_profile(tmp_path, profile_id)
    nested = profile_data_path(tmp_path, profile_id) / "nested"
    nested.mkdir()
    (nested / "state.bin").write_bytes(b"owned")

    assert delete_disposable_profile(tmp_path, profile_id) == {
        "id": profile_id,
        "state": "deleted",
        "deleted": True,
    }
    assert not profile_data_path(tmp_path, profile_id).exists()
    assert not (tmp_path / "profiles" / "registry" / f"{profile_id}.json").exists()
    assert not list((tmp_path / "profiles" / "data").glob(".profile-delete-*"))


def test_disposable_profile_delete_rechecks_absent_result(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    profile_id = "ops-disp-appeared"
    data = profile_data_path(tmp_path, profile_id)
    original_identity = profiles_module._profile_directory_identity
    appeared = False

    def create_after_missing_data(path: Path, *, label: str):
        nonlocal appeared
        identity = original_identity(path, label=label)
        if path == data and label == "profile data" and identity is None and not appeared:
            appeared = True
            monkeypatch.setattr(
                profiles_module, "_profile_directory_identity", original_identity
            )
            create_profile(tmp_path, profile_id)
        return identity

    monkeypatch.setattr(
        profiles_module, "_profile_directory_identity", create_after_missing_data
    )
    with pytest.raises(ContractError, match="appeared during deletion"):
        delete_disposable_profile(tmp_path, profile_id)
    assert appeared
    assert load_profile(tmp_path, profile_id)["id"] == profile_id
    assert data.is_dir()


@pytest.mark.skipif(os.name != "nt", reason="Windows directory junction boundary")
def test_disposable_profile_delete_rejects_false_absent_linked_profiles_parent(
    tmp_path: Path,
) -> None:
    profile_id = "ops-disp-fixture"
    create_profile(tmp_path, profile_id)
    profiles = tmp_path / "profiles"
    detached = tmp_path / "detached-profiles"
    profiles.rename(detached)
    foreign = tmp_path / "foreign"
    foreign.mkdir()
    created = subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(profiles), str(foreign)],
        capture_output=True,
        check=False,
    )
    if created.returncode:
        detached.rename(profiles)
        pytest.skip("host could not create an unprivileged directory junction")
    try:
        with pytest.raises(ContractError, match="profile deletion ancestry"):
            delete_disposable_profile(tmp_path, profile_id)
        assert (detached / "registry" / f"{profile_id}.json").is_file()
        assert (detached / "data" / profile_id).is_dir()
        assert list(foreign.iterdir()) == []
    finally:
        profiles.rmdir()
        detached.rename(profiles)


@pytest.mark.skipif(os.name != "nt", reason="Windows directory junction boundary")
def test_disposable_profile_delete_rejects_foreign_data_parent_before_quarantine(
    tmp_path: Path,
) -> None:
    profile_id = "ops-disp-fixture"
    profiles = tmp_path / "profiles"
    profiles.mkdir()
    foreign = tmp_path / "foreign"
    data = foreign / profile_id
    data.mkdir(parents=True)
    sentinel = data / "keep.bin"
    sentinel.write_bytes(b"foreign profile data")
    junction = profiles / "data"
    created = subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(junction), str(foreign)],
        capture_output=True, check=False,
    )
    if created.returncode:
        pytest.skip("host could not create an unprivileged directory junction")
    try:
        with pytest.raises(ContractError):
            delete_disposable_profile(tmp_path, profile_id)
        assert sentinel.read_bytes() == b"foreign profile data"
        assert [entry.name for entry in foreign.iterdir()] == [profile_id]
        assert not (profiles / "registry" / f"{profile_id}.json").exists()
    finally:
        if junction.exists():
            junction.rmdir()


def test_disposable_profile_delete_rolls_back_when_locked(tmp_path: Path) -> None:
    profile_id = "ops-disp-fixture"
    create_profile(tmp_path, profile_id)
    lock = acquire_profile_lock(tmp_path, profile_id, "owner")

    with pytest.raises(ContractError, match="still locked"):
        delete_disposable_profile(tmp_path, profile_id)
    assert load_profile(tmp_path, profile_id)["id"] == profile_id
    assert profile_data_path(tmp_path, profile_id).is_dir()
    release_profile_lock(lock, "owner")


def test_disposable_profile_delete_preserves_racing_registry_and_rolls_back_data(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    profile_id = "ops-disp-fixture"
    original = create_profile(tmp_path, profile_id)
    data = profile_data_path(tmp_path, profile_id)
    (data / "state.bin").write_bytes(b"owned")
    competitor = {**original, "name": "Competitor"}
    real_remove = profiles_module.remove_control_conditionally

    def inject_then_remove(path: Path, **kwargs: object) -> None:
        injected = tmp_path / "competitor-profile.json"
        injected.write_bytes(canonical_json_bytes(competitor))
        injected.replace(path)
        real_remove(path, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(
        profiles_module, "remove_control_conditionally", inject_then_remove
    )
    with pytest.raises(ContractError, match="changed .* removal"):
        delete_disposable_profile(tmp_path, profile_id)
    assert load_profile(tmp_path, profile_id)["name"] == "Competitor"
    assert (data / "state.bin").read_bytes() == b"owned"
    assert not list(data.parent.glob(".profile-delete-*"))


def test_disposable_profile_delete_preserves_unowned_quarantine_sibling(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    profile_id = "ops-disp-fixture"
    create_profile(tmp_path, profile_id)
    data = profile_data_path(tmp_path, profile_id)
    (data / "owned.bin").write_bytes(b"owned")
    original = profiles_module._remove_profile_tree
    sentinel: Path | None = None

    def inject_after_data_removal(path: Path, **kwargs: object) -> None:
        nonlocal sentinel
        original(path, **kwargs)
        sentinel = path.parent / "competitor.bin"
        sentinel.write_bytes(b"not part of the profile")

    monkeypatch.setattr(profiles_module, "_remove_profile_tree", inject_after_data_removal)
    with pytest.raises(ContractError, match="quarantine cleanup failed"):
        delete_disposable_profile(tmp_path, profile_id)
    assert sentinel is not None
    assert sentinel.read_bytes() == b"not part of the profile"


@pytest.mark.parametrize("replacement", ["registry", "data"])
def test_disposable_profile_delete_rejects_recreated_final_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, replacement: str
) -> None:
    profile_id = "ops-disp-fixture"
    create_profile(tmp_path, profile_id)
    data = profile_data_path(tmp_path, profile_id)
    registry = tmp_path / "profiles" / "registry" / f"{profile_id}.json"
    original_registry = registry.read_bytes()
    original_cleanup = profiles_module._remove_empty_profile_quarantine

    def recreate_after_cleanup(path: Path, **kwargs: object) -> None:
        original_cleanup(path, **kwargs)
        if replacement == "registry":
            registry.write_bytes(original_registry)
        else:
            data.mkdir()
            (data / "competitor.bin").write_bytes(b"replacement data")

    monkeypatch.setattr(
        profiles_module, "_remove_empty_profile_quarantine", recreate_after_cleanup
    )
    with pytest.raises(ContractError, match="changed after cleanup"):
        delete_disposable_profile(tmp_path, profile_id)
    if replacement == "registry":
        assert registry.read_bytes() == original_registry
    else:
        assert (data / "competitor.bin").read_bytes() == b"replacement data"


def test_disposable_profile_rollback_preserves_unowned_quarantine_sibling(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    profile_id = "ops-disp-fixture"
    create_profile(tmp_path, profile_id)
    data = profile_data_path(tmp_path, profile_id)
    (data / "owned.bin").write_bytes(b"owned")
    sentinel: Path | None = None

    def fail_registry_removal(*_args: object, **_kwargs: object) -> None:
        nonlocal sentinel
        quarantine = next(data.parent.glob(".profile-delete-*"))
        sentinel = quarantine / "competitor.bin"
        sentinel.write_bytes(b"not part of the profile")
        raise ContractError("synthetic registry rejection")

    monkeypatch.setattr(profiles_module, "remove_control_conditionally", fail_registry_removal)
    with pytest.raises(ContractError):
        delete_disposable_profile(tmp_path, profile_id)
    assert (data / "owned.bin").read_bytes() == b"owned"
    assert sentinel is not None
    assert sentinel.read_bytes() == b"not part of the profile"


def test_disposable_profile_delete_does_not_remove_a_racing_data_replacement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    profile_id = "ops-disp-fixture"
    create_profile(tmp_path, profile_id)
    data = profile_data_path(tmp_path, profile_id)
    (data / "original.bin").write_bytes(b"original")
    holding = tmp_path / "racing-original-data"
    real_rename = profiles_module.os.rename
    injected = False

    def replace_before_quarantine(source: Path, destination: Path) -> None:
        nonlocal injected
        if not injected and Path(source) == data and Path(destination).name == "data":
            injected = True
            real_rename(source, holding)
            data.mkdir()
            (data / "competitor.bin").write_bytes(b"competitor")
        real_rename(source, destination)

    monkeypatch.setattr(profiles_module.os, "rename", replace_before_quarantine)
    with pytest.raises(ContractError, match="changed before deletion"):
        delete_disposable_profile(tmp_path, profile_id)
    assert (data / "competitor.bin").read_bytes() == b"competitor"
    assert (holding / "original.bin").read_bytes() == b"original"
    assert load_profile(tmp_path, profile_id)["id"] == profile_id


def test_profile_binding_mutation_cannot_run_under_a_live_session_lock(
    tmp_path: Path,
) -> None:
    create_profile(tmp_path, "fixture")
    add_network_route(
        tmp_path,
        build_network_route(
            route_id="direct-us",
            name="Direct US",
            geography={
                "country": "US",
                "locale": "en-US",
                "timezone": "America/Chicago",
            },
        ),
    )
    lock = acquire_profile_lock(tmp_path, "fixture", "active-session")
    with pytest.raises(ContractError, match="locked"):
        attach_network_route(tmp_path, "fixture", "direct-us")
    assert "network_route" not in load_profile(tmp_path, "fixture")
    release_profile_lock(lock, "active-session")
    assert (
        attach_network_route(tmp_path, "fixture", "direct-us")["network_route"]["id"]
        == "direct-us"
    )


@pytest.mark.parametrize("changed", ["registry", "route"])
def test_network_route_attachment_rechecks_saved_binding_after_write(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, changed: str
) -> None:
    create_profile(tmp_path, "fixture")
    route = build_network_route(
        route_id="direct-us",
        name="Direct US",
        geography={"country": "US", "locale": "en-US", "timezone": "America/Chicago"},
    )
    add_network_route(tmp_path, route)
    registry = tmp_path / "profiles" / "registry" / "fixture.json"
    route_path = tmp_path / "network" / "routes" / "direct-us.json"
    original_write = profiles_module._write_json_atomic

    def change_after_registry_write(path: Path, document: dict, *, expected=None):
        published = original_write(path, document, expected=expected)
        if path == registry:
            if changed == "registry":
                competitor = json.loads(registry.read_text(encoding="utf-8"))
                competitor["name"] = "Competitor"
                registry.write_bytes(canonical_json_bytes(competitor))
            else:
                replacement = build_network_route(
                    route_id="direct-us",
                    name="Changed route",
                    geography={
                        "country": "US", "locale": "en-US",
                        "timezone": "America/Chicago",
                    },
                )
                route_path.write_bytes(canonical_json_bytes(replacement))
        return published

    monkeypatch.setattr(profiles_module, "_write_json_atomic", change_after_registry_write)
    with pytest.raises(ContractError, match="network route attachment"):
        attach_network_route(tmp_path, "fixture", "direct-us")


def test_network_route_attachment_rechecks_profile_after_final_route_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    create_profile(tmp_path, "fixture")
    route = build_network_route(
        route_id="direct-us",
        name="Direct US",
        geography={"country": "US", "locale": "en-US", "timezone": "America/Chicago"},
    )
    add_network_route(tmp_path, route)
    registry = tmp_path / "profiles" / "registry" / "fixture.json"
    original_load = network_module.load_network_route
    reads = 0

    def change_profile_after_route_read(workspace: Path, route_id: str):
        nonlocal reads
        document = original_load(workspace, route_id)
        reads += 1
        if reads == 2:
            competitor = json.loads(registry.read_bytes())
            competitor["name"] = "Changed during final route read"
            registry.write_bytes(canonical_json_bytes(competitor))
        return document

    monkeypatch.setattr(network_module, "load_network_route", change_profile_after_route_read)
    with pytest.raises(ContractError, match="network route attachment changed"):
        attach_network_route(tmp_path, "fixture", "direct-us")
    assert reads == 2
    assert load_profile(tmp_path, "fixture")["name"] == "Changed during final route read"


def test_network_route_attachment_rechecks_route_after_final_profile_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    create_profile(tmp_path, "fixture")
    route = build_network_route(
        route_id="direct-us",
        name="Direct US",
        geography={"country": "US", "locale": "en-US", "timezone": "America/Chicago"},
    )
    add_network_route(tmp_path, route)
    route_path = tmp_path / "network" / "routes" / "direct-us.json"
    replacement = {**route, "name": "Changed after route read"}
    replacement["integrity_sha256"] = network_module.route_digest(replacement)
    original_load = network_module.load_network_route
    reads = 0

    def change_after_route_read(workspace: Path, route_id: str):
        nonlocal reads
        document = original_load(workspace, route_id)
        reads += 1
        if reads == 2:
            route_path.write_bytes(canonical_json_bytes(replacement))
        return document

    monkeypatch.setattr(network_module, "load_network_route", change_after_route_read)
    with pytest.raises(ContractError, match="network route attachment changed"):
        attach_network_route(tmp_path, "fixture", "direct-us")
    assert reads >= 2
    assert route_path.read_bytes() == canonical_json_bytes(replacement)
