from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

import browser_core.profile_state as profile_state_module
from browser_core.contracts import ContractError
from browser_core.control_files import BoundedJsonDirectoryInventory, canonical_json_bytes
from browser_core.profile_state import (
    capture_profile_state,
    list_profile_state_receipts,
    validate_profile_state_receipt,
)
from browser_core.profiles import acquire_profile_lock, create_profile, release_profile_lock


def _profile_with_state(tmp_path: Path) -> tuple[Path, Path]:
    create_profile(tmp_path, "research-main", "Research Main")
    data = tmp_path / "profiles" / "data" / "research-main"
    (data / "Default" / "Local Storage").mkdir(parents=True)
    (data / "Default" / "Cookies").write_bytes(b"private-cookie-state")
    (data / "Default" / "Local Storage" / "leveldb.log").write_bytes(
        b"private-origin-state"
    )
    return tmp_path, data


@pytest.mark.skipif(os.name != "nt", reason="Windows directory junction boundary")
@pytest.mark.parametrize("operation", ["capture", "list"])
def test_profile_state_rejects_linked_workspace(
    tmp_path: Path, operation: str
) -> None:
    target = tmp_path / "unrelated"
    target.mkdir()
    _profile_with_state(target)
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
            if operation == "capture":
                capture_profile_state(junction, "research-main", "snapshot-1")
            else:
                list_profile_state_receipts(junction, "research-main")
        assert not (target / "profiles" / "state").exists()
    finally:
        junction.rmdir()


def test_profile_state_receipts_are_redacted_stable_and_revision_chained(
    tmp_path: Path,
) -> None:
    workspace, _data = _profile_with_state(tmp_path)

    first = capture_profile_state(workspace, "research-main", "snapshot-1")
    second = capture_profile_state(workspace, "research-main", "snapshot-2")

    assert first["schema"] == "browser-core.profile-state-receipt/1"
    assert first["state"]["digest_sha256"] == second["state"]["digest_sha256"]
    assert first["revision"] == 1
    assert first["previous_receipt_sha256"] == "0" * 64
    assert second["revision"] == 2
    assert second["previous_receipt_sha256"] == first["receipt_sha256"]
    assert first["state"] == {
        "digest_sha256": first["state"]["digest_sha256"],
        "directories": 3,
        "files": 2,
        "total_bytes": 40,
        "complete": True,
    }
    serialized = str(first) + str(second)
    for private in (
        "Cookies",
        "Local Storage",
        "leveldb.log",
        "private-cookie-state",
        "private-origin-state",
        str(tmp_path),
    ):
        assert private not in serialized
    assert list_profile_state_receipts(workspace, "research-main") == [
        first,
        second,
    ]


def test_profile_state_list_rejects_casefold_duplicate_snapshot_ids(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace, _data = _profile_with_state(tmp_path)
    first = capture_profile_state(workspace, "research-main", "Alpha")
    second = capture_profile_state(workspace, "research-main", "beta")
    colliding = {**second, "snapshot_id": "alpha"}
    colliding["receipt_sha256"] = profile_state_module._receipt_digest(colliding)
    validate_profile_state_receipt(colliding)
    registry = workspace / "profiles" / "state" / "research-main"
    actual = profile_state_module._receipt_inventory(registry)
    identities = dict(actual.files)
    inventory = BoundedJsonDirectoryInventory(
        state=actual.state,
        directory_identity=actual.directory_identity,
        files=(
            ("Alpha.json", identities["Alpha.json"]),
            ("alpha.json", identities["beta.json"]),
        ),
    )
    monkeypatch.setattr(profile_state_module, "_receipt_inventory", lambda _path: inventory)

    def load_colliding_receipt(path: Path):
        if path.name == "Alpha.json":
            return first, identities["Alpha.json"]
        assert path.name == "alpha.json"
        return colliding, identities["beta.json"]

    monkeypatch.setattr(
        profile_state_module, "_load_profile_state_receipt_snapshot", load_colliding_receipt
    )
    with pytest.raises(ContractError, match="duplicate snapshot IDs"):
        list_profile_state_receipts(workspace, "research-main")


def test_profile_state_capture_rejects_casefold_duplicate_before_publication(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace, _data = _profile_with_state(tmp_path)
    capture_profile_state(workspace, "research-main", "Alpha")
    registry = workspace / "profiles" / "state" / "research-main"
    original = (registry / "Alpha.json").read_bytes()

    def unexpected_publication(*_args, **_kwargs):
        raise AssertionError("casefold-colliding receipt reached publication")

    monkeypatch.setattr(
        profile_state_module, "publish_json_exclusive", unexpected_publication
    )
    with pytest.raises(ContractError, match="snapshot ID already exists"):
        capture_profile_state(workspace, "research-main", "alpha")
    assert (registry / "Alpha.json").read_bytes() == original
    assert [path.name for path in registry.iterdir()] == ["Alpha.json"]


@pytest.mark.skipif(os.name != "nt", reason="Windows directory junction boundary")
def test_profile_state_registry_creation_rechecks_profiles_root_before_mkdir(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace, _data = _profile_with_state(tmp_path)
    profiles_root = workspace / "profiles"
    held = workspace / "held-profiles"
    foreign = workspace / "foreign-profiles"
    foreign.mkdir()
    original_identity = profile_state_module.directory_identity
    swapped = False

    def swap_after_profiles_root_check(path: Path, *, label: str):
        nonlocal swapped
        observed = original_identity(path, label=label)
        if path == profiles_root and label == "profile state profiles root" and not swapped:
            profiles_root.rename(held)
            created = subprocess.run(
                ["cmd", "/c", "mklink", "/J", str(profiles_root), str(foreign)],
                capture_output=True,
                check=False,
            )
            if created.returncode:
                held.rename(profiles_root)
                pytest.skip("host could not create an unprivileged directory junction")
            swapped = True
        return observed

    monkeypatch.setattr(
        profile_state_module, "directory_identity", swap_after_profiles_root_check
    )
    try:
        with pytest.raises(ContractError):
            profile_state_module._ensure_state_registry(workspace, "research-main")
        assert swapped
        assert not (foreign / "state").exists()
    finally:
        if swapped:
            profiles_root.rmdir()
            held.rename(profiles_root)


@pytest.mark.skipif(os.name != "nt", reason="Windows directory junction boundary")
def test_profile_state_list_rejects_replaced_state_root_during_inventory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace, _data = _profile_with_state(tmp_path)
    capture_profile_state(workspace, "research-main", "snapshot-1")
    state_root = workspace / "profiles" / "state"
    held = workspace / "held-state"
    foreign = workspace / "foreign-state"
    (foreign / "research-main").mkdir(parents=True)
    original = profile_state_module._receipt_inventory
    swapped = False

    def swap_before_inventory(registry: Path):
        nonlocal swapped
        if not swapped:
            state_root.rename(held)
            created = subprocess.run(
                ["cmd", "/c", "mklink", "/J", str(state_root), str(foreign)],
                capture_output=True,
                check=False,
            )
            if created.returncode:
                held.rename(state_root)
                pytest.skip("host could not create an unprivileged directory junction")
            swapped = True
        return original(registry)

    monkeypatch.setattr(profile_state_module, "_receipt_inventory", swap_before_inventory)
    try:
        with pytest.raises(ContractError):
            list_profile_state_receipts(workspace, "research-main")
        assert swapped
        assert (held / "research-main" / "snapshot-1.json").is_file()
    finally:
        if swapped:
            state_root.rmdir()


@pytest.mark.skipif(os.name != "nt", reason="Windows directory junction boundary")
def test_profile_state_capture_rechecks_state_root_before_success(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace, _data = _profile_with_state(tmp_path)
    state_root = workspace / "profiles" / "state"
    held = workspace / "held-state"
    foreign = workspace / "foreign-state"
    (foreign / "research-main").mkdir(parents=True)
    original = profile_state_module._verify_profile_tree_population
    swapped = False
    checks = 0

    def swap_after_tree_check(population: object) -> None:
        nonlocal swapped, checks
        original(population)
        checks += 1
        if checks != 2:
            return
        state_root.rename(held)
        created = subprocess.run(
            ["cmd", "/c", "mklink", "/J", str(state_root), str(foreign)],
            capture_output=True,
            check=False,
        )
        if created.returncode:
            held.rename(state_root)
            pytest.skip("host could not create an unprivileged directory junction")
        swapped = True

    monkeypatch.setattr(
        profile_state_module, "_verify_profile_tree_population", swap_after_tree_check
    )
    try:
        with pytest.raises(ContractError):
            capture_profile_state(workspace, "research-main", "snapshot-1")
        assert swapped
        assert (held / "research-main" / "snapshot-1.json").is_file()
    finally:
        if swapped:
            state_root.rmdir()


def test_profile_state_digest_changes_when_stopped_profile_state_changes(
    tmp_path: Path,
) -> None:
    workspace, data = _profile_with_state(tmp_path)
    first = capture_profile_state(workspace, "research-main", "snapshot-1")
    (data / "Default" / "Cookies").write_bytes(b"different-private-state")

    second = capture_profile_state(workspace, "research-main", "snapshot-2")

    assert first["state"]["digest_sha256"] != second["state"]["digest_sha256"]
    assert second["revision"] == 2


def test_profile_state_capture_refuses_a_live_profile_lock(tmp_path: Path) -> None:
    workspace, _data = _profile_with_state(tmp_path)
    lock = acquire_profile_lock(workspace, "research-main", "active-session")
    try:
        with pytest.raises(ContractError, match="locked"):
            capture_profile_state(workspace, "research-main", "snapshot-1")
    finally:
        release_profile_lock(lock, "active-session")


def test_profile_state_capture_rejects_hardlinked_state(tmp_path: Path) -> None:
    workspace, data = _profile_with_state(tmp_path)
    source = data / "Default" / "Cookies"
    alias = data / "Default" / "Cookies-alias"
    try:
        os.link(source, alias)
    except OSError as exc:
        pytest.skip(f"hard links are unavailable: {exc}")

    with pytest.raises(ContractError, match="linked"):
        capture_profile_state(workspace, "research-main", "snapshot-1")

    assert not (data / ".browser-core.lock").exists()
    assert list(
        (workspace / "profiles" / "state" / "research-main").iterdir()
    ) == []


def test_profile_state_capture_rejects_symlinked_state(tmp_path: Path) -> None:
    workspace, data = _profile_with_state(tmp_path)
    link = data / "Default" / "Cookies-link"
    try:
        link.symlink_to(data / "Default" / "Cookies")
    except OSError as exc:
        pytest.skip(f"symbolic links are unavailable: {exc}")

    with pytest.raises(ContractError, match="linked|unsupported"):
        capture_profile_state(workspace, "research-main", "snapshot-1")

    assert not (data / ".browser-core.lock").exists()


def test_profile_state_capture_detects_post_read_state_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace, data = _profile_with_state(tmp_path)
    real_hash = profile_state_module._hash_profile_file
    mutated = False

    def hash_then_mutate(*args: object, **kwargs: object) -> tuple[str, int]:
        nonlocal mutated
        result = real_hash(*args, **kwargs)  # type: ignore[arg-type]
        if not mutated:
            mutated = True
            (data / "Default" / "Cookies").write_bytes(b"mutated-after-read")
        return result

    monkeypatch.setattr(profile_state_module, "_hash_profile_file", hash_then_mutate)

    with pytest.raises(ContractError, match="population changed"):
        capture_profile_state(workspace, "research-main", "snapshot-1")

    assert not (data / ".browser-core.lock").exists()


@pytest.mark.skipif(os.name != "nt", reason="Windows file change-time boundary")
def test_profile_state_capture_detects_same_size_restored_mtime_mutation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace, data = _profile_with_state(tmp_path)
    cookie = data / "Default" / "Cookies"
    original = profile_state_module._hash_profile_file
    mutated = False

    def hash_then_mutate(*args: object, **kwargs: object) -> tuple[str, int]:
        nonlocal mutated
        result = original(*args, **kwargs)  # type: ignore[arg-type]
        if args[0] == cookie and not mutated:
            before = os.lstat(cookie)
            cookie.write_bytes(b"changed-cookie-state")
            os.utime(cookie, ns=(before.st_atime_ns, before.st_mtime_ns))
            assert profile_state_module._identity(os.lstat(cookie)) == (
                profile_state_module._identity(before)
            )
            mutated = True
        return result

    monkeypatch.setattr(profile_state_module, "_hash_profile_file", hash_then_mutate)
    with pytest.raises(ContractError, match="population changed"):
        capture_profile_state(workspace, "research-main", "snapshot-1")
    assert mutated
    assert not (data / ".browser-core.lock").exists()
    assert not (
        workspace / "profiles" / "state" / "research-main" / "snapshot-1.json"
    ).exists()


@pytest.mark.skipif(os.name != "nt", reason="Windows directory change-time boundary")
def test_profile_state_capture_detects_added_file_with_restored_directory_mtime(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace, data = _profile_with_state(tmp_path)
    original = profile_state_module._capture_profile_tree
    added = False

    def capture_then_add(path: Path):
        nonlocal added
        result = original(path)
        before = os.lstat(data)
        (data / "unexpected.bin").write_bytes(b"unrecorded-state")
        os.utime(data, ns=(before.st_atime_ns, before.st_mtime_ns))
        assert profile_state_module._identity(os.lstat(data)) == (
            profile_state_module._identity(before)
        )
        added = True
        return result

    monkeypatch.setattr(profile_state_module, "_capture_profile_tree", capture_then_add)
    with pytest.raises(ContractError, match="population changed"):
        capture_profile_state(workspace, "research-main", "snapshot-1")
    assert added
    assert not (data / ".browser-core.lock").exists()


def test_profile_state_capture_detects_profile_document_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace, data = _profile_with_state(tmp_path)
    registry_document = workspace / "profiles" / "registry" / "research-main.json"
    real_capture = profile_state_module._capture_profile_tree

    def capture_then_mutate(path: Path) -> object:
        result = real_capture(path)
        profile = json.loads(registry_document.read_text(encoding="ascii"))
        profile["name"] = "Changed During Capture"
        registry_document.write_bytes(canonical_json_bytes(profile))
        return result

    monkeypatch.setattr(
        profile_state_module,
        "_capture_profile_tree",
        capture_then_mutate,
    )

    with pytest.raises(ContractError, match="profile document changed"):
        capture_profile_state(workspace, "research-main", "snapshot-1")

    assert not (data / ".browser-core.lock").exists()


def test_profile_state_capture_rechecks_profile_after_final_tree_verification(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace, data = _profile_with_state(tmp_path)
    registry_document = workspace / "profiles" / "registry" / "research-main.json"
    original = profile_state_module._verify_profile_tree_population
    checks = 0

    def mutate_after_final_check(population: object) -> None:
        nonlocal checks
        original(population)
        checks += 1
        if checks == 2:
            profile = json.loads(registry_document.read_text(encoding="ascii"))
            profile["name"] = "Changed During Final Verification"
            registry_document.write_bytes(canonical_json_bytes(profile))

    monkeypatch.setattr(
        profile_state_module, "_verify_profile_tree_population", mutate_after_final_check
    )
    with pytest.raises(ContractError, match="profile document changed"):
        capture_profile_state(workspace, "research-main", "snapshot-1")
    assert checks == 2
    assert not (data / ".browser-core.lock").exists()


def test_profile_state_capture_rechecks_receipt_after_final_tree_verification(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace, data = _profile_with_state(tmp_path)
    destination = (
        workspace / "profiles" / "state" / "research-main" / "snapshot-1.json"
    )
    competitor = b'{"different":true}\n'
    original = profile_state_module._verify_profile_tree_population
    checks = 0

    def replace_after_final_check(population: object) -> None:
        nonlocal checks
        original(population)
        checks += 1
        if checks == 2:
            replacement = destination.with_name("replacement.tmp")
            replacement.write_bytes(competitor)
            os.replace(replacement, destination)

    monkeypatch.setattr(
        profile_state_module, "_verify_profile_tree_population", replace_after_final_check
    )
    with pytest.raises(ContractError):
        capture_profile_state(workspace, "research-main", "snapshot-1")
    assert checks == 2
    assert destination.read_bytes() == competitor
    assert not (data / ".browser-core.lock").exists()


def test_profile_state_capture_rechecks_prior_receipt_after_final_tree_verification(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace, data = _profile_with_state(tmp_path)
    capture_profile_state(workspace, "research-main", "snapshot-1")
    prior = workspace / "profiles" / "state" / "research-main" / "snapshot-1.json"
    competitor = b'{"different":true}\n'
    original = profile_state_module._verify_profile_tree_population
    checks = 0

    def replace_prior_after_final_check(population: object) -> None:
        nonlocal checks
        original(population)
        checks += 1
        if checks == 2:
            replacement = prior.with_name("replacement.tmp")
            replacement.write_bytes(competitor)
            os.replace(replacement, prior)

    monkeypatch.setattr(
        profile_state_module,
        "_verify_profile_tree_population",
        replace_prior_after_final_check,
    )
    with pytest.raises(ContractError):
        capture_profile_state(workspace, "research-main", "snapshot-2")
    assert checks == 2
    assert prior.read_bytes() == competitor
    assert not (data / ".browser-core.lock").exists()


def test_profile_state_capture_rechecks_profile_after_final_chain_scan(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace, data = _profile_with_state(tmp_path)
    profile_path = workspace / "profiles" / "registry" / "research-main.json"
    original = profile_state_module._load_receipt_chain
    scans = 0

    def change_profile_during_final_scan(*args: object, **kwargs: object):
        nonlocal scans
        receipts = original(*args, **kwargs)  # type: ignore[arg-type]
        scans += 1
        if scans == 2:
            profile = json.loads(profile_path.read_text(encoding="ascii"))
            profile["name"] = "Changed During Final Chain Scan"
            profile_path.write_bytes(canonical_json_bytes(profile))
        return receipts

    monkeypatch.setattr(
        profile_state_module, "_load_receipt_chain", change_profile_during_final_scan
    )
    with pytest.raises(ContractError, match="profile document changed"):
        capture_profile_state(workspace, "research-main", "snapshot-1")
    assert scans == 2
    assert not (data / ".browser-core.lock").exists()


def test_profile_state_capture_rechecks_tree_after_final_chain_scan(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace, data = _profile_with_state(tmp_path)
    original = profile_state_module._load_receipt_chain
    scans = 0

    def change_tree_during_final_scan(*args: object, **kwargs: object):
        nonlocal scans
        receipts = original(*args, **kwargs)  # type: ignore[arg-type]
        scans += 1
        if scans == 2:
            (data / "Default" / "Cookies").write_bytes(b"changed-cookie-state")
        return receipts

    monkeypatch.setattr(
        profile_state_module, "_load_receipt_chain", change_tree_during_final_scan
    )
    with pytest.raises(ContractError, match="population changed"):
        capture_profile_state(workspace, "research-main", "snapshot-1")
    assert scans == 2
    # A published receipt remains as historical evidence of the failed final check.
    assert (workspace / "profiles" / "state" / "research-main" / "snapshot-1.json").exists()
    assert not (data / ".browser-core.lock").exists()


def test_profile_state_capture_enforces_file_and_aggregate_limits(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace, data = _profile_with_state(tmp_path)
    monkeypatch.setattr(profile_state_module, "MAX_PROFILE_STATE_FILE_BYTES", 8)
    with pytest.raises(ContractError, match="file exceeds"):
        capture_profile_state(workspace, "research-main", "snapshot-file-limit")
    assert not (data / ".browser-core.lock").exists()

    monkeypatch.setattr(profile_state_module, "MAX_PROFILE_STATE_FILE_BYTES", 1024)
    monkeypatch.setattr(profile_state_module, "MAX_PROFILE_STATE_TOTAL_BYTES", 30)
    with pytest.raises(ContractError, match="aggregate byte limit"):
        capture_profile_state(workspace, "research-main", "snapshot-total-limit")
    assert not (data / ".browser-core.lock").exists()


def test_profile_state_directory_scan_stops_at_entry_limit_before_exhaustion(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    data = tmp_path / "profile"
    data.mkdir()
    consumed = 0

    class Entries:
        def __enter__(self) -> "Entries":
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def __iter__(self):  # type: ignore[no-untyped-def]
            nonlocal consumed
            for name in ("a", "b", "must-not-be-consumed"):
                consumed += 1
                if consumed > 2:
                    raise AssertionError("directory iterator was exhausted")
                yield SimpleNamespace(name=name)

    monkeypatch.setattr(profile_state_module, "MAX_PROFILE_STATE_TREE_ENTRIES", 1)
    monkeypatch.setattr(profile_state_module.os, "scandir", lambda _path: Entries())

    with pytest.raises(ContractError, match="too many entries"):
        profile_state_module._capture_profile_tree(data)

    assert consumed == 2


def test_profile_state_capture_budgets_entry_and_aggregate_path_bytes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace, data = _profile_with_state(tmp_path)
    monkeypatch.setattr(
        profile_state_module,
        "MAX_PROFILE_STATE_ENTRY_NAME_BYTES",
        3,
        raising=False,
    )
    with pytest.raises(ContractError, match="entry name exceeds"):
        capture_profile_state(workspace, "research-main", "entry-name-limit")
    assert not (data / ".browser-core.lock").exists()

    monkeypatch.setattr(
        profile_state_module,
        "MAX_PROFILE_STATE_ENTRY_NAME_BYTES",
        1024,
        raising=False,
    )
    monkeypatch.setattr(
        profile_state_module,
        "MAX_PROFILE_STATE_TOTAL_PATH_BYTES",
        8,
        raising=False,
    )
    with pytest.raises(ContractError, match="aggregate path byte limit"):
        capture_profile_state(workspace, "research-main", "path-total-limit")
    assert not (data / ".browser-core.lock").exists()


def test_profile_state_receipt_chain_rejects_digest_repaired_tampering(
    tmp_path: Path,
) -> None:
    workspace, _data = _profile_with_state(tmp_path)
    capture_profile_state(workspace, "research-main", "snapshot-1")
    capture_profile_state(workspace, "research-main", "snapshot-2")
    receipt_path = (
        workspace / "profiles" / "state" / "research-main" / "snapshot-2.json"
    )
    receipt = json.loads(receipt_path.read_text(encoding="ascii"))
    receipt["previous_receipt_sha256"] = "f" * 64
    receipt["receipt_sha256"] = profile_state_module._receipt_digest(receipt)
    receipt_path.write_bytes(canonical_json_bytes(receipt))

    with pytest.raises(ContractError, match="chain is invalid"):
        list_profile_state_receipts(workspace, "research-main")


def test_profile_state_listing_rechecks_profile_after_chain_load(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace, _data = _profile_with_state(tmp_path)
    capture_profile_state(workspace, "research-main", "snapshot-1")
    profile_path = workspace / "profiles" / "registry" / "research-main.json"
    original_load = profile_state_module._load_receipt_chain

    def load_then_change_profile(*args: object, **kwargs: object):
        receipts = original_load(*args, **kwargs)  # type: ignore[arg-type]
        profile = json.loads(profile_path.read_text(encoding="ascii"))
        profile["name"] = "Changed During Receipt Listing"
        profile_path.write_bytes(canonical_json_bytes(profile))
        return receipts

    monkeypatch.setattr(profile_state_module, "_load_receipt_chain", load_then_change_profile)
    with pytest.raises(ContractError, match="profile document changed"):
        list_profile_state_receipts(workspace, "research-main")


def test_profile_state_listing_rechecks_profile_after_final_chain_scan(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace, _data = _profile_with_state(tmp_path)
    capture_profile_state(workspace, "research-main", "snapshot-1")
    profile_path = workspace / "profiles" / "registry" / "research-main.json"
    original_load = profile_state_module._load_receipt_chain
    scans = 0

    def change_profile_on_final_scan(*args, **kwargs):
        nonlocal scans
        receipts = original_load(*args, **kwargs)
        scans += 1
        if scans == 2:
            profile = json.loads(profile_path.read_text(encoding="ascii"))
            profile["name"] = "Changed During Final Receipt Scan"
            profile_path.write_bytes(canonical_json_bytes(profile))
        return receipts

    monkeypatch.setattr(profile_state_module, "_load_receipt_chain", change_profile_on_final_scan)
    with pytest.raises(ContractError, match="profile document changed"):
        list_profile_state_receipts(workspace, "research-main")


@pytest.mark.parametrize("initially_present", [False, True])
def test_profile_state_listing_rechecks_registry_after_final_profile_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    initially_present: bool,
) -> None:
    workspace, _data = _profile_with_state(tmp_path)
    capture_profile_state(workspace, "research-main", "snapshot-1")
    registry = workspace / "profiles" / "state" / "research-main"
    held = workspace / "held-receipts"
    if not initially_present:
        registry.rename(held)
    original_load = profile_state_module.load_profile
    loads = 0

    def transition_on_final_profile_read(*args, **kwargs):
        nonlocal loads
        profile = original_load(*args, **kwargs)
        loads += 1
        if loads == 2:
            if initially_present:
                registry.rename(held)
            else:
                held.rename(registry)
        return profile

    monkeypatch.setattr(profile_state_module, "load_profile", transition_on_final_profile_read)
    with pytest.raises(ContractError, match="receipt registry changed during load"):
        list_profile_state_receipts(workspace, "research-main")
    assert loads == 2
    assert ((held if initially_present else registry) / "snapshot-1.json").is_file()


@pytest.mark.skipif(os.name != "nt", reason="Windows restored-mtime receipt custody")
def test_profile_state_listing_rechecks_same_identity_receipt_content(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace, _data = _profile_with_state(tmp_path)
    capture_profile_state(workspace, "research-main", "snapshot-1")
    path = workspace / "profiles" / "state" / "research-main" / "snapshot-1.json"
    original_inventory = profile_state_module._receipt_inventory
    inventories = 0

    def mutate_before_second_inventory(registry: Path):
        nonlocal inventories
        inventories += 1
        if inventories == 2:
            before = path.stat()
            receipt = json.loads(path.read_text(encoding="ascii"))
            current_digest = receipt["state"]["digest_sha256"]
            receipt["state"]["digest_sha256"] = (
                "0" if current_digest[0] != "0" else "1"
            ) + current_digest[1:]
            replacement = canonical_json_bytes(receipt)
            assert len(replacement) == before.st_size
            path.write_bytes(replacement)
            os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns))
            after = path.stat()
            assert (after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns) == (
                before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns
            )
        return original_inventory(registry)

    monkeypatch.setattr(
        profile_state_module, "_receipt_inventory", mutate_before_second_inventory
    )
    with pytest.raises(ContractError):
        list_profile_state_receipts(workspace, "research-main")
    assert inventories >= 2


@pytest.mark.skipif(os.name != "nt", reason="Windows restored-mtime receipt custody")
@pytest.mark.parametrize("mutate_at_load", [2, 3])
def test_profile_state_listing_rechecks_receipt_after_final_profile_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mutate_at_load: int
) -> None:
    workspace, _data = _profile_with_state(tmp_path)
    capture_profile_state(workspace, "research-main", "snapshot-1")
    path = workspace / "profiles" / "state" / "research-main" / "snapshot-1.json"
    original_load = profile_state_module.load_profile
    loads = 0

    def mutate_on_final_profile_read(*args, **kwargs):
        nonlocal loads
        profile = original_load(*args, **kwargs)
        loads += 1
        if loads == mutate_at_load:
            before = path.stat()
            receipt = json.loads(path.read_text(encoding="ascii"))
            digest = receipt["state"]["digest_sha256"]
            receipt["state"]["digest_sha256"] = (
                "0" if digest[0] != "0" else "1"
            ) + digest[1:]
            replacement = canonical_json_bytes(receipt)
            assert len(replacement) == before.st_size
            path.write_bytes(replacement)
            os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns))
            after = path.stat()
            assert (after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns) == (
                before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns
            )
        return profile

    monkeypatch.setattr(profile_state_module, "load_profile", mutate_on_final_profile_read)
    with pytest.raises(ContractError):
        list_profile_state_receipts(workspace, "research-main")


def test_profile_state_receipt_loader_rejects_hardlinked_receipt(
    tmp_path: Path,
) -> None:
    workspace, _data = _profile_with_state(tmp_path)
    capture_profile_state(workspace, "research-main", "snapshot-1")
    receipt_path = (
        workspace / "profiles" / "state" / "research-main" / "snapshot-1.json"
    )
    alias = tmp_path / "receipt-alias.json"
    try:
        os.link(receipt_path, alias)
    except OSError as exc:
        pytest.skip(f"hard links are unavailable: {exc}")

    with pytest.raises(ContractError, match="hard links|invalid"):
        list_profile_state_receipts(workspace, "research-main")


def test_profile_state_publication_preserves_a_competing_destination(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace, data = _profile_with_state(tmp_path)
    destination = (
        workspace / "profiles" / "state" / "research-main" / "snapshot-1.json"
    )
    real_publish = profile_state_module.publish_json_exclusive
    competitor = {"competitor": True}

    def publish_after_competitor(
        path: Path,
        document: dict[str, object],
        **kwargs: object,
    ) -> bytes:
        real_publish(path, competitor, **kwargs)  # type: ignore[arg-type]
        return real_publish(path, document, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(
        profile_state_module,
        "publish_json_exclusive",
        publish_after_competitor,
    )

    with pytest.raises(ContractError, match="publication failed"):
        capture_profile_state(workspace, "research-main", "snapshot-1")

    assert json.loads(destination.read_text(encoding="ascii")) == competitor
    assert not (data / ".browser-core.lock").exists()


def test_profile_state_capture_detects_profile_drift_during_publication(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace, data = _profile_with_state(tmp_path)
    registry_document = workspace / "profiles" / "registry" / "research-main.json"
    real_publish = profile_state_module.publish_json_exclusive

    def mutate_profile_then_publish(
        path: Path,
        document: dict[str, object],
        **kwargs: object,
    ) -> bytes:
        profile = json.loads(registry_document.read_text(encoding="ascii"))
        profile["name"] = "Changed During Publication"
        registry_document.write_bytes(canonical_json_bytes(profile))
        return real_publish(path, document, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(
        profile_state_module,
        "publish_json_exclusive",
        mutate_profile_then_publish,
    )

    with pytest.raises(ContractError, match="profile document changed"):
        capture_profile_state(workspace, "research-main", "snapshot-1")

    retained = (
        workspace / "profiles" / "state" / "research-main" / "snapshot-1.json"
    )
    assert retained.is_file()
    assert not (data / ".browser-core.lock").exists()


def test_profile_state_receipts_refuse_disposable_profiles(tmp_path: Path) -> None:
    create_profile(tmp_path, "ops-disp-1", "Disposable")

    with pytest.raises(ContractError, match="persistent named profile"):
        capture_profile_state(tmp_path, "ops-disp-1", "snapshot-1")


def test_profile_state_normalizes_workspace_once_before_authority_contact(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace, _data = _profile_with_state(tmp_path)
    unresolved = workspace / "absent-segment" / ".."
    observed: list[Path] = []
    real_authorities = profile_state_module._profile_data_authorities

    def record_workspace(path: Path, profile_id: str):  # type: ignore[no-untyped-def]
        observed.append(path)
        return real_authorities(path, profile_id)

    monkeypatch.setattr(
        profile_state_module,
        "_profile_data_authorities",
        record_workspace,
    )

    capture_profile_state(unresolved, "research-main", "snapshot-1")

    assert observed == [workspace.resolve()]


def test_profile_state_return_value_cannot_mutate_receipt_contract(
    tmp_path: Path,
) -> None:
    workspace, _data = _profile_with_state(tmp_path)
    first = capture_profile_state(workspace, "research-main", "snapshot-1")
    first["exclusions"].append("secret-local-file")
    first["non_claims"].clear()

    second = capture_profile_state(workspace, "research-main", "snapshot-2")

    assert second["exclusions"] == [".browser-core.lock"]
    assert len(second["non_claims"]) == 5


def test_profile_state_receipt_rejects_digest_repaired_internal_contradictions(
    tmp_path: Path,
) -> None:
    workspace, _data = _profile_with_state(tmp_path)
    receipt = capture_profile_state(workspace, "research-main", "snapshot-1")

    bad_binding = json.loads(json.dumps(receipt))
    bad_binding["profile_binding"]["identity_mode"] = "host-native-pinned"
    bad_binding["receipt_sha256"] = profile_state_module._receipt_digest(bad_binding)
    with pytest.raises(ContractError, match="binding is inconsistent"):
        validate_profile_state_receipt(bad_binding)

    bad_summary = json.loads(json.dumps(receipt))
    bad_summary["state"]["files"] = 0
    bad_summary["receipt_sha256"] = profile_state_module._receipt_digest(bad_summary)
    with pytest.raises(ContractError, match="summary is inconsistent"):
        validate_profile_state_receipt(bad_summary)


@pytest.mark.parametrize("identity_mode", [[], {"mode": "host-native"}])
def test_profile_state_receipt_rejects_unhashable_identity_mode(
    tmp_path: Path, identity_mode: object
) -> None:
    workspace, _data = _profile_with_state(tmp_path)
    receipt = capture_profile_state(workspace, "research-main", "snapshot-1")
    receipt["profile_binding"]["identity_mode"] = identity_mode
    with pytest.raises(ContractError, match="binding is invalid"):
        validate_profile_state_receipt(receipt)


def test_profile_state_capture_rejects_symlinked_receipt_root(
    tmp_path: Path,
) -> None:
    workspace, data = _profile_with_state(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    state_root = workspace / "profiles" / "state"
    try:
        state_root.symlink_to(outside, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"directory symbolic links are unavailable: {exc}")

    with pytest.raises(ContractError, match="owned regular directory"):
        capture_profile_state(workspace, "research-main", "snapshot-1")

    assert list(outside.iterdir()) == []
    assert not (data / ".browser-core.lock").exists()
