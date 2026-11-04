"""Real Windows handle checks, including replacement and sharing races."""
from contextlib import contextmanager
import os
from pathlib import Path

import pytest

from browser_core import owned_paths, windows_file_delete
from browser_core.contracts import ContractError

pytestmark = pytest.mark.skipif(os.name != "nt", reason="Windows handle API")


def remove(root):
    identity = owned_paths.directory_identity(root, label="owned test tree")
    owned_paths.remove_owned_directory_tree(root, expected_identity=identity, label="owned test tree")


@pytest.mark.parametrize("filename", ["state.bin", "tool.exe", "tool.cmd", "unicode-\u00e9.txt"])
def test_exclusive_handle_blocks_replacement_and_write(tmp_path, monkeypatch, filename):
    root = tmp_path / "owned"
    root.mkdir()
    path = root / filename
    path.write_bytes(b"owned")
    original = windows_file_delete.mark_for_delete
    checks = []
    def checked(descriptor):
        with pytest.raises(OSError):
            os.read(descriptor, 1)  # The handle can inspect attributes, not content.
        with pytest.raises(OSError):
            path.rename(tmp_path / "moved")
        with pytest.raises(OSError):
            path.write_bytes(b"changed")
        checks.append(True)
        original(descriptor)
    monkeypatch.setattr(windows_file_delete, "mark_for_delete", checked)
    remove(root)
    assert checks == [True] and not root.exists()


def test_replacement_before_open_is_preserved(tmp_path, monkeypatch):
    root = tmp_path / "owned"
    root.mkdir()
    child = root / "state.bin"
    child.write_bytes(b"original")
    before = child.stat()
    held = tmp_path / "held-original"
    original = windows_file_delete.exclusive_file
    @contextmanager
    def replace_then_open(path):
        child.rename(held)
        child.write_bytes(b"intruder")
        os.utime(child, ns=(before.st_atime_ns, before.st_mtime_ns))
        with original(path) as descriptor:
            yield descriptor
    monkeypatch.setattr(windows_file_delete, "exclusive_file", replace_then_open)
    with pytest.raises(ContractError, match="entry changed before handle removal"):
        remove(root)
    assert child.read_bytes() == b"intruder"
    assert held.read_bytes() == b"original"


def test_deleting_one_hardlink_keeps_the_other_name_and_bytes(tmp_path):
    root = tmp_path / "owned"
    root.mkdir()
    child = root / "state.bin"
    child.write_bytes(b"shared fixture")
    outside = tmp_path / "outside-link"
    os.link(child, outside)
    remove(root)
    assert not root.exists()
    assert outside.read_bytes() == b"shared fixture"
    assert outside.stat().st_nlink == 1


def test_parent_replacement_cannot_delete_a_foreign_child(tmp_path, monkeypatch):
    root = tmp_path / "owned"
    root.mkdir()
    (root / "state.bin").write_bytes(b"owned")
    held = tmp_path / "held-owned"
    original = windows_file_delete.mark_for_delete
    replaced = []
    def race(descriptor):
        try:
            root.rename(held)
        except OSError:
            replaced.append(False)  # The OS also protected the parent rename.
        else:
            replaced.append(True)
            root.mkdir()
            (root / "state.bin").write_bytes(b"foreign")
        original(descriptor)
    monkeypatch.setattr(windows_file_delete, "mark_for_delete", race)
    try:
        remove(root)
    except ContractError:
        assert replaced == [True]
        assert (root / "state.bin").read_bytes() == b"foreign"
    else:
        assert replaced == [False] and not root.exists()


def test_failed_mark_releases_handle_and_preserves_file(tmp_path, monkeypatch):
    root = tmp_path / "owned"
    root.mkdir()
    child = root / "state.bin"
    child.write_bytes(b"owned")
    def fail(_descriptor):
        raise OSError(5, "synthetic-private-message")
    monkeypatch.setattr(windows_file_delete, "mark_for_delete", fail)
    with pytest.raises(ContractError, match="handle removal failed") as error:
        remove(root)
    assert "synthetic-private-message" not in str(error.value)
    assert child.read_bytes() == b"owned"
    child.rename(tmp_path / "unlocked")


def test_interruption_before_mark_releases_handle_without_deleting(tmp_path, monkeypatch):
    root = tmp_path / "owned"
    root.mkdir()
    child = root / "state.bin"
    child.write_bytes(b"owned")
    def interrupt(_descriptor):
        raise KeyboardInterrupt()
    monkeypatch.setattr(windows_file_delete, "mark_for_delete", interrupt)
    with pytest.raises(KeyboardInterrupt):
        remove(root)
    assert child.read_bytes() == b"owned"
    child.rename(tmp_path / "unlocked")


def test_existing_reader_failure_preserves_file_then_allows_retry(tmp_path):
    root = tmp_path / "owned"
    root.mkdir()
    child = root / "state.bin"
    child.write_bytes(b"owned")
    with child.open("rb"):
        with pytest.raises(ContractError):
            remove(root)
    assert child.read_bytes() == b"owned"
    remove(root)
    assert not root.exists()


def test_long_local_path_is_deleted_by_verified_handle(tmp_path):
    root = tmp_path / "owned"
    nested = root / ("a" * 120) / ("b" * 120)
    nested.mkdir(parents=True)
    child = nested / "state.bin"
    child.write_bytes(b"owned")
    assert len(str(child)) > 260
    remove(root)
    assert not root.exists()
