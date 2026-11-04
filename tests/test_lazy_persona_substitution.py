"""Replacement selection is unnecessary until a measured mismatch occurs."""
import pytest

from browser_core import multi_identity_ops as ops
from browser_core.contracts import ContractError
from test_adversarial_review_regressions import fake_launches
from test_multi_identity_ops import _seed


def test_successful_automatic_batch_does_not_reload_catalog_for_replacements(tmp_path, monkeypatch):
    _seed(tmp_path, count=3, product="browser-core", major=153)
    fake_launches(tmp_path, monkeypatch, failures=0)
    def unnecessary(*_a, **_kw):
        raise AssertionError("replacement catalog must not be read on success")
    monkeypatch.setattr(ops, "list_launch_compatible_persona_ids", unnecessary)
    result = ops.run_profile_velocity_batch(tmp_path, count=2, ready_mode="launch",
        executable=tmp_path / "fake.exe", repository_root=tmp_path)["ops_batch"]
    assert result["passed"]
    assert result["persona_substitution"]["pool_loaded"] is False
    assert result["timing"]["substitution_selection_ms"] == 0


@pytest.mark.parametrize("exception", [ContractError, KeyboardInterrupt])
def test_replacement_selection_failure_is_recorded_after_owned_cleanup(tmp_path, monkeypatch, exception):
    _seed(tmp_path, count=3, product="browser-core", major=153)
    attempts = fake_launches(tmp_path, monkeypatch)
    def unavailable(*_a, **_kw):
        # No failed browser profile or exclusive claim remains during lookup.
        assert not list((tmp_path / "personas" / "claims").glob("*.json"))
        raise exception("synthetic catalog lookup failure")
    monkeypatch.setattr(ops, "list_launch_compatible_persona_ids", unavailable)
    result = ops.run_profile_velocity_batch(tmp_path, count=1, ready_mode="launch",
        executable=tmp_path / "fake.exe", repository_root=tmp_path)["ops_batch"]
    assert not result["passed"]
    assert len(attempts) == 1
    assert result["persona_substitution"]["pool_load_error"]
    assert result["persona_substitution"]["skipped"][0]["cleanup_completed"]
    assert result["orphans"] == result["unreleased_claims"] == []
    assert result["interrupted"] is (exception is KeyboardInterrupt)
