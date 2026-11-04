from __future__ import annotations

import os
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

import browser_core.owned_paths as owned_paths_module
import time
from browser_core.contracts import ContractError
from browser_core.owned_paths import (
    directory_identity,
    directory_identity_document,
    parse_directory_identity,
    remove_owned_directory_tree,
)


def test_owned_directory_identity_roundtrip_and_nested_removal(tmp_path: Path) -> None:
    root = tmp_path / "owned"
    nested = root / "nested"
    nested.mkdir(parents=True)
    (nested / "state.bin").write_bytes(b"owned")
    identity = directory_identity(root, label="owned directory")
    assert identity is not None
    assert parse_directory_identity(directory_identity_document(identity)) == identity

    remove_owned_directory_tree(
        root,
        expected_identity=identity,
        label="owned directory",
    )
    assert not root.exists()


@pytest.mark.parametrize("invalid", ["bad\x00dir", "bad\ud800dir"])
def test_owned_directory_identity_rejects_invalid_path_text(invalid: str) -> None:
    with pytest.raises(ContractError, match="owned directory path is invalid") as raised:
        directory_identity(Path(invalid), label="owned directory")
    assert invalid not in str(raised.value)


@pytest.mark.skipif(os.name != "nt", reason="Windows directory junction boundary")
@pytest.mark.parametrize("with_file", [False, True])
def test_owned_directory_removal_rejects_preexisting_ancestor_junction(
    tmp_path: Path, with_file: bool,
) -> None:
    outside = tmp_path / "outside"
    owned = outside / "inner" / "owned"
    owned.mkdir(parents=True)
    sentinel = owned / "sentinel.bin"
    if with_file:
        sentinel.write_bytes(b"unrelated")
    junction = tmp_path / "junction"
    created = subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(junction), str(outside)],
        capture_output=True, check=False,
    )
    if created.returncode:
        pytest.skip("host could not create an unprivileged directory junction")
    try:
        path = junction / "inner" / "owned"
        identity = directory_identity(path, label="owned directory")
        assert identity is not None
        with pytest.raises(ContractError):
            remove_owned_directory_tree(
                path, expected_identity=identity,
                label="owned directory",
            )
        assert owned.is_dir()
        if with_file:
            assert sentinel.read_bytes() == b"unrelated"
    finally:
        if junction.exists():
            junction.rmdir()


@pytest.mark.skipif(os.name != "nt", reason="Windows directory junction boundary")
@pytest.mark.parametrize("with_file", [False, True])
def test_owned_directory_removal_rechecks_ancestor_before_child_mutation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, with_file: bool,
) -> None:
    parent = tmp_path / "parent"
    root = parent / "owned"
    root.mkdir(parents=True)
    sentinel = root / "sentinel.bin"
    if with_file:
        sentinel.write_bytes(b"unrelated")
    identity = directory_identity(root, label="owned directory")
    assert identity is not None
    outside = tmp_path / "outside"
    real_scandir = owned_paths_module.os.scandir
    swapped = False

    def swap_before_scan(path: Path):
        nonlocal swapped
        if not swapped and Path(path) == root:
            swapped = True
            parent.rename(outside)
            created = subprocess.run(
                ["cmd", "/c", "mklink", "/J", str(parent), str(outside)],
                capture_output=True, check=False,
            )
            assert created.returncode == 0
        return real_scandir(path)

    monkeypatch.setattr(owned_paths_module.os, "scandir", swap_before_scan)
    try:
        with pytest.raises(ContractError):
            remove_owned_directory_tree(
                root, expected_identity=identity, label="owned directory",
            )
        assert (outside / "owned").is_dir()
        if with_file:
            assert (outside / "owned" / "sentinel.bin").read_bytes() == b"unrelated"
    finally:
        if parent.exists():
            parent.rmdir()


def test_owned_directory_scan_stops_at_entry_bound_before_removal(tmp_path, monkeypatch):
    root = tmp_path / 'owned'
    root.mkdir()
    identity = directory_identity(root, label='owned directory')
    assert identity is not None
    monkeypatch.setattr(owned_paths_module, 'MAX_OWNED_DIRECTORY_ENTRIES', 2, raising=False)
    scanned = []

    class Entries:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def __iter__(self):
            return self

        def __next__(self):
            if len(scanned) == 7:
                raise StopIteration
            scanned.append(len(scanned))
            return SimpleNamespace(name=f'phantom-{len(scanned)}')

    monkeypatch.setattr(owned_paths_module.os, 'scandir', lambda _path: Entries())
    monkeypatch.setattr(owned_paths_module.os, 'rename',
                        lambda *_args: pytest.fail('oversized scan reached removal'))
    with pytest.raises(ContractError, match='entry bound'):
        remove_owned_directory_tree(root, expected_identity=identity, label='owned directory')
    assert len(scanned) == 3
    assert root.exists()


def test_owned_directory_removal_stops_at_depth_bound(tmp_path, monkeypatch):
    root = tmp_path / 'owned'
    nested = root / 'one' / 'two'
    nested.mkdir(parents=True)
    retained = nested / 'state.bin'
    retained.write_bytes(b'owned')
    identity = directory_identity(root, label='owned directory')
    assert identity is not None
    monkeypatch.setattr(owned_paths_module, 'MAX_OWNED_DIRECTORY_DEPTH', 1, raising=False)

    with pytest.raises(ContractError, match='depth bound'):
        remove_owned_directory_tree(root, expected_identity=identity, label='owned directory')
    assert root.exists() and retained.read_bytes() == b'owned'


def test_owned_directory_removal_stops_at_aggregate_entry_bound(tmp_path, monkeypatch):
    root = tmp_path / 'owned'
    nested = root / 'nested'
    nested.mkdir(parents=True)
    retained = nested / 'state.bin'
    retained.write_bytes(b'owned')
    (nested / 'other.bin').write_bytes(b'owned')
    identity = directory_identity(root, label='owned directory')
    assert identity is not None
    monkeypatch.setattr(owned_paths_module, 'MAX_OWNED_TREE_ENTRIES', 2, raising=False)

    with pytest.raises(ContractError, match='entry bound'):
        remove_owned_directory_tree(root, expected_identity=identity, label='owned directory')
    assert root.exists() and retained.read_bytes() == b'owned'


def _sharing_error(code=32):
    error = OSError('synthetic Windows file sharing conflict')
    error.winerror = code
    return error


@pytest.mark.parametrize('code', [32, 33])
def test_owned_removal_retries_a_transient_sharing_conflict(tmp_path, monkeypatch, code):
    root = tmp_path / 'owned'; root.mkdir()
    child = root / 'state.bin'; child.write_bytes(b'owned')
    identity = directory_identity(root, label='owned directory')
    original = owned_paths_module.os.rename
    attempts = []
    monkeypatch.setattr(owned_paths_module, '_try_remove_windows_file', lambda *_a: False)
    def rename(source, destination):
        if source == child:
            attempts.append(source)
            if len(attempts) == 1:
                raise _sharing_error(code)
        return original(source, destination)
    monkeypatch.setattr(owned_paths_module.os, 'rename', rename)
    remove_owned_directory_tree(root, expected_identity=identity, label='owned directory')
    assert len(attempts) == 2 and not root.exists()


def test_sharing_retry_rechecks_the_exact_entry_before_removal(tmp_path, monkeypatch):
    root = tmp_path / 'owned'; root.mkdir()
    child = root / 'state.bin'; child.write_bytes(b'owned')
    identity = directory_identity(root, label='owned directory')
    monkeypatch.setattr(owned_paths_module, '_try_remove_windows_file', lambda *_a: False)
    attempts = []
    def rename(source, destination):
        attempts.append(source)
        raise _sharing_error()
    monkeypatch.setattr(owned_paths_module.os, 'rename', rename)
    monkeypatch.setattr(time, 'sleep', lambda _seconds: child.write_bytes(b'changed content'))
    with pytest.raises(ContractError, match='changed before removal'):
        remove_owned_directory_tree(root, expected_identity=identity, label='owned directory')
    assert attempts == [child]
    assert child.read_bytes() == b'changed content'


def test_persistent_sharing_conflict_is_bounded_and_keeps_the_entry(tmp_path, monkeypatch):
    root = tmp_path / 'owned'; root.mkdir()
    child = root / 'state.bin'; child.write_bytes(b'owned')
    identity = directory_identity(root, label='owned directory')
    clock = [0.0]; attempts = []
    monkeypatch.setattr(owned_paths_module, '_try_remove_windows_file', lambda *_a: False)
    monkeypatch.setattr(time, 'monotonic', lambda: clock[0])
    monkeypatch.setattr(time, 'sleep', lambda seconds: clock.__setitem__(0, clock[0] + seconds))
    def rename(source, destination):
        attempts.append(source)
        raise _sharing_error()
    monkeypatch.setattr(owned_paths_module.os, 'rename', rename)
    with pytest.raises(ContractError, match='quarantine failed'):
        remove_owned_directory_tree(root, expected_identity=identity, label='owned directory')
    assert 2 <= len(attempts) <= 25
    assert 0 < clock[0] <= 1.0 and child.read_bytes() == b'owned'


def test_access_denial_is_not_retried_as_a_sharing_conflict(tmp_path, monkeypatch):
    root = tmp_path / 'owned'; root.mkdir()
    child = root / 'state.bin'; child.write_bytes(b'owned')
    identity = directory_identity(root, label='owned directory')
    monkeypatch.setattr(owned_paths_module, '_try_remove_windows_file', lambda *_a: False)
    monkeypatch.setattr(time, 'sleep', lambda _s: pytest.fail('access denial was retried'))
    def rename(source, destination):
        raise _sharing_error(5)
    monkeypatch.setattr(owned_paths_module.os, 'rename', rename)
    with pytest.raises(ContractError, match='quarantine failed'):
        remove_owned_directory_tree(root, expected_identity=identity, label='owned directory')
    assert child.read_bytes() == b'owned'


def test_sharing_retry_budget_is_shared_across_nested_entries(tmp_path, monkeypatch):
    root = tmp_path / 'owned'; nested = root / 'nested'; nested.mkdir(parents=True)
    for name in ('a.bin', 'b.bin'):
        (nested / name).write_bytes(b'owned')
    identity = directory_identity(root, label='owned directory')
    clock = [0.0]; first = []
    original = owned_paths_module.os.rename
    monkeypatch.setattr(owned_paths_module, '_try_remove_windows_file', lambda *_a: False)
    monkeypatch.setattr(time, 'monotonic', lambda: clock[0])
    monkeypatch.setattr(time, 'sleep', lambda seconds: clock.__setitem__(0, clock[0] + seconds))
    def rename(source, destination):
        if source.suffix == '.bin':
            if not first:
                first.append(source)
            if source != first[0] or clock[0] < 0.6:
                raise _sharing_error()
        return original(source, destination)
    monkeypatch.setattr(owned_paths_module.os, 'rename', rename)
    with pytest.raises(ContractError, match='quarantine failed'):
        remove_owned_directory_tree(root, expected_identity=identity, label='owned directory')
    assert clock[0] == pytest.approx(1.0)
    assert not first[0].exists() and len(list(nested.glob('*.bin'))) == 1


def test_owned_directory_removal_preserves_a_racing_root_replacement(
    tmp_path: Path,
) -> None:
    root = tmp_path / "owned"
    root.mkdir()
    (root / "original.bin").write_bytes(b"original")
    identity = directory_identity(root, label="owned directory")
    assert identity is not None
    holding = tmp_path / "holding"
    root.rename(holding)
    root.mkdir()
    (root / "competitor.bin").write_bytes(b"competitor")

    with pytest.raises(ContractError, match="changed before removal"):
        remove_owned_directory_tree(
            root,
            expected_identity=identity,
            label="owned directory",
        )
    assert (root / "competitor.bin").read_bytes() == b"competitor"
    assert (holding / "original.bin").read_bytes() == b"original"


def test_owned_directory_removal_unlinks_symlink_without_following_target(
    tmp_path: Path,
) -> None:
    root = tmp_path / "owned"
    outside = tmp_path / "outside"
    root.mkdir()
    outside.mkdir()
    (outside / "sentinel.bin").write_bytes(b"outside")
    link = root / "linked-outside"
    try:
        link.symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("directory symlinks are unavailable on this host")
    identity = directory_identity(root, label="owned directory")
    assert identity is not None

    remove_owned_directory_tree(
        root,
        expected_identity=identity,
        label="owned directory",
    )
    assert (outside / "sentinel.bin").read_bytes() == b"outside"


def test_owned_directory_removal_preserves_a_replaced_file_entry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Exercise the portable quarantine fallback even on Windows. The exclusive
    # handle branch has real replacement/write races in test_windows_file_delete.
    monkeypatch.setattr(owned_paths_module, "_try_remove_windows_file", lambda *_a: False)
    root = tmp_path / "owned"
    root.mkdir()
    child = root / "state.bin"
    child.write_bytes(b"original")
    identity = directory_identity(root, label="owned directory")
    assert identity is not None
    held = tmp_path / "held-original.bin"
    real_rename = owned_paths_module.os.rename
    injected = False

    def replace_before_quarantine(source: Path, destination: Path) -> None:
        nonlocal injected
        if not injected and Path(source) == child:
            injected = True
            real_rename(child, held)
            child.write_bytes(b"competitor")
        real_rename(source, destination)

    monkeypatch.setattr(
        owned_paths_module.os,
        "rename",
        replace_before_quarantine,
    )
    with pytest.raises(ContractError, match="entry changed during removal"):
        remove_owned_directory_tree(
            root,
            expected_identity=identity,
            label="owned directory",
        )

    assert root.is_dir()
    assert held.read_bytes() == b"original"
    assert child.read_bytes() == b"competitor"
    quarantines = list(root.glob(".state.bin.removed-*"))
    assert len(quarantines) == 1
    assert quarantines[0].read_bytes() == b"competitor"


def test_owned_directory_removal_preserves_a_replaced_empty_root(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "owned"
    root.mkdir()
    identity = directory_identity(root, label="owned directory")
    assert identity is not None
    held = tmp_path / "held-original"
    real_rename = owned_paths_module.os.rename
    injected = False

    def replace_before_root_quarantine(source: Path, destination: Path) -> None:
        nonlocal injected
        if not injected and Path(source) == root:
            injected = True
            real_rename(root, held)
            root.mkdir()
        real_rename(source, destination)

    monkeypatch.setattr(
        owned_paths_module.os,
        "rename",
        replace_before_root_quarantine,
    )
    with pytest.raises(ContractError, match="changed during removal"):
        remove_owned_directory_tree(
            root,
            expected_identity=identity,
            label="owned directory",
        )

    assert held.is_dir()
    assert not root.exists()
    competitors = list(tmp_path.glob(".owned.removed-*"))
    assert len(competitors) == 1
    assert competitors[0].is_dir()


@pytest.mark.parametrize(
    "override",
    [
        {"path": "owned"},
        {"expected_identity": [0, 0, 0, 0]},
        {"expected_identity": (0, 0, 0, 0)},
        {"expected_identity": (0, 0, True, 0)},
        {"missing_ok": 1},
        {"label": "private\nlabel"},
    ],
)
def test_owned_directory_removal_validates_before_identity_lookup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    override: dict,
) -> None:
    touched = False

    def fail_if_touched(*_args, **_kwargs):
        nonlocal touched
        touched = True
        raise AssertionError("directory identity must not be read")

    monkeypatch.setattr(owned_paths_module, "directory_identity", fail_if_touched)
    arguments = {
        "path": tmp_path / "owned",
        "expected_identity": (0, 0, 0o040000, 0),
        "missing_ok": False,
        "label": "owned directory",
    }
    arguments.update(override)
    with pytest.raises(ContractError):
        remove_owned_directory_tree(**arguments)
    assert touched is False


@pytest.mark.parametrize(
    "identity",
    [None, [0, 0, 0o040000, 0], (0, 0, 0, 0), (0, 0, 0o040000, True)],
)
def test_directory_identity_document_rejects_malformed_runtime_shapes(identity) -> None:
    with pytest.raises(ContractError, match="directory identity is invalid"):
        directory_identity_document(identity)
