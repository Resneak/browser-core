"""A failed/cancelled batch cleans only resources it actually acquired."""
from pathlib import Path

import pytest

from browser_core import multi_identity_ops as ops
from browser_core.contracts import ContractError
from browser_core.profiles import create_profile, list_profiles, profile_data_path
from test_multi_identity_ops import _seed, _stopped_receipt


def test_reused_batch_name_does_not_delete_preexisting_profile(tmp_path):
    ids = _seed(tmp_path, count=1)
    profile_id = "ops-disp-existing-000"
    create_profile(tmp_path, profile_id)
    sentinel = profile_data_path(tmp_path, profile_id) / "owned-by-earlier-run"
    sentinel.write_bytes(b"retained")
    report = ops.run_multi_identity_batch(tmp_path, ids, batch_id="existing")
    assert not report["passed"]
    assert sentinel.read_bytes() == b"retained"
    assert profile_id in {p["id"] for p in list_profiles(tmp_path)}
    assert report["orphans"] == []  # The failed invocation never owned it.


def test_failed_attempt_keeps_cleanup_failure_and_claim(tmp_path, monkeypatch):
    ids = _seed(tmp_path, count=1)
    def fail_binding(*_a, **_kw): raise ContractError("synthetic bind failure")
    def fail_release(*_a, **_kw): raise ContractError("synthetic release failure")
    monkeypatch.setattr(ops, "attach_persona_identity_for_ops", fail_binding)
    monkeypatch.setattr(ops, "release_persona_claim", fail_release)
    report = ops.run_multi_identity_batch(tmp_path, ids, batch_id="failed-binding")
    assert not report["passed"]
    assert report["cleanup_failures"]
    assert report["unreleased_claims"] == [{"persona_id": ids[0], "claim_id": f"failed-binding-{ids[0]}"}]
    assert report["timing"]["failed_identity_cleanup_ms"] > 0


def test_failed_profile_cleanup_keeps_exclusive_claim(tmp_path, monkeypatch):
    ids = _seed(tmp_path, count=1)
    def fail_binding(*_a, **_kw): raise ContractError("synthetic bind failure")
    def fail_delete(*_a, **_kw): raise ContractError("synthetic locked profile")
    monkeypatch.setattr(ops, "attach_persona_identity_for_ops", fail_binding)
    monkeypatch.setattr(ops, "delete_disposable_profile", fail_delete)
    report = ops.run_multi_identity_batch(tmp_path, ids, batch_id="retained-profile")
    assert not report["passed"]
    assert report["cleanup_failures"]
    assert (tmp_path / "personas" / "claims" / f"{ids[0]}.json").exists()
    assert report["orphans"] == ["ops-disp-retained-profile-000"]


@pytest.mark.parametrize("interrupt_at", [1, 2])
def test_interruption_stops_prior_sessions_and_does_not_start_later_slots(tmp_path, monkeypatch, interrupt_at):
    ids = _seed(tmp_path, count=3, product="browser-core", major=153)
    launched, stopped = [], []
    def launch(config, root):
        launched.append(config.profile_id)
        if len(launched) == interrupt_at:
            raise KeyboardInterrupt()
        path = tmp_path / "sessions" / f"{config.profile_id}.json"
        return path, {"run_id": f"run-{config.profile_id}", "state": "active"}
    def stop(path, **_kw):
        stopped.append(path.stem)
        return _stopped_receipt(path)
    monkeypatch.setattr(ops, "discover_browser_core_launch_major", lambda _root: 153)
    monkeypatch.setattr("browser_core.launcher.launch_evaluation", launch)
    monkeypatch.setattr("browser_core.lifecycle.stop_session", stop)
    report = ops.run_multi_identity_batch(tmp_path, ids, batch_id="interrupted",
        ready_mode="launch", executable=tmp_path/"fake.exe", repository_root=tmp_path)
    assert report["interrupted"] is True
    assert not report["passed"]
    assert len(launched) == interrupt_at
    assert stopped == launched[:-1]
    assert len(report["attempts"]) == interrupt_at
    assert len(report["stop_receipts"]) == interrupt_at - 1
    assert list_profiles(tmp_path) == []
    assert list((tmp_path / "personas" / "claims").glob("*.json")) == []
    assert report["unreleased_claims"] == []


def test_interrupt_during_stop_still_cleans_other_owned_sessions(tmp_path, monkeypatch):
    ids = _seed(tmp_path, count=2, product="browser-core", major=153)
    stopped = []
    def launch(config, root):
        return tmp_path / f"{config.profile_id}.json", {"run_id": f"run-{config.profile_id}"}
    def stop(path, **_kw):
        stopped.append(path.stem)
        if len(stopped) == 1: raise KeyboardInterrupt()
        return _stopped_receipt(path)
    monkeypatch.setattr(ops, "discover_browser_core_launch_major", lambda _root: 153)
    monkeypatch.setattr("browser_core.launcher.launch_evaluation", launch)
    monkeypatch.setattr("browser_core.lifecycle.stop_session", stop)
    report = ops.run_multi_identity_batch(tmp_path, ids, batch_id="stop-interrupt",
        ready_mode="launch", executable=tmp_path/"fake.exe", repository_root=tmp_path)
    assert report["interrupted"] and not report["passed"]
    assert len(stopped) == 2
    assert report["orphans"] == ["ops-disp-stop-interrupt-000"]
    assert len(report["unreleased_claims"]) == 1
    assert len(report["stop_receipts"]) == 1
