"""Cancellation during owned publication must release files and directories."""
import pytest

from browser_core import control_files, multi_identity_ops as ops, profiles
from test_multi_identity_ops import _seed


@pytest.mark.parametrize("stage", ["flush", "published-read"])
def test_cancelled_profile_publication_removes_owned_partial_state(tmp_path, monkeypatch, stage):
    fired = False
    if stage == "flush":
        original = control_files.os.fsync
        def cancel_once(descriptor):
            nonlocal fired
            if not fired:
                fired = True
                raise KeyboardInterrupt("synthetic publication cancellation")
            return original(descriptor)
        monkeypatch.setattr(control_files.os, "fsync", cancel_once)
    else:
        original = control_files.read_bounded_control_snapshot_result
        def cancel_once(path, **kwargs):
            nonlocal fired
            if path.name == "ops-disp-cancelled.json" and not fired:
                fired = True
                raise KeyboardInterrupt("synthetic publication cancellation")
            return original(path, **kwargs)
        monkeypatch.setattr(control_files, "read_bounded_control_snapshot_result", cancel_once)
    with pytest.raises(KeyboardInterrupt):
        profiles.create_profile(tmp_path, "ops-disp-cancelled")
    assert fired
    assert not profiles.profile_data_path(tmp_path, "ops-disp-cancelled").exists()
    assert not list((tmp_path / "profiles" / "registry").glob("*"))


def test_interrupted_creation_with_failed_rollback_retains_uncertainty(tmp_path, monkeypatch):
    ids = _seed(tmp_path, count=2)
    def cancel(*_a, **_kw):
        raise KeyboardInterrupt("synthetic creation cancellation")
    original_rmdir = profiles.os.rmdir
    target = profiles.profile_data_path(tmp_path, "ops-disp-retained-000")
    def cannot_remove(path, *args, **kwargs):
        if path == target:
            raise PermissionError("synthetic cleanup denied")
        return original_rmdir(path, *args, **kwargs)
    with monkeypatch.context() as patcher:
        patcher.setattr(profiles, "_write_json_atomic", cancel)
        patcher.setattr(profiles.os, "rmdir", cannot_remove)
        result = ops.run_multi_identity_batch(tmp_path, ids, batch_id="retained")
    assert result["interrupted"] and not result["passed"]
    assert result["not_started"] == 1
    assert result["uncertain_profile_cleanup"] == ["ops-disp-retained-000"]
    assert result["cleanup_inventory_verified"] is False
    assert result["cleanup_failures"][0]["stage"] == "create-profile-rollback"


def test_batch_cancelled_during_profile_publication_leaves_no_unreported_profile(tmp_path, monkeypatch):
    ids = _seed(tmp_path, count=2)
    original = control_files.os.fsync
    fired = False
    def cancel_once(descriptor):
        nonlocal fired
        if not fired:
            fired = True
            raise KeyboardInterrupt("synthetic batch cancellation")
        return original(descriptor)
    monkeypatch.setattr(control_files.os, "fsync", cancel_once)
    result = ops.run_multi_identity_batch(tmp_path, ids, batch_id="cancelled")
    assert result["interrupted"] and not result["passed"]
    assert result["not_started"] == 1
    assert result["orphans"] == result["unreleased_claims"] == []
    assert not profiles.profile_data_path(tmp_path, "ops-disp-cancelled-000").exists()
    assert not list((tmp_path / "profiles" / "registry").glob("*"))
