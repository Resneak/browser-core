"""B02 — bounded parallel launch pool for disposable coherence arms.

The properties that matter are: concurrency is actually bounded, results are
reported in arm order regardless of completion order, aggregation cannot race, and
a failing arm still cleans up and is still reported.
"""

from __future__ import annotations

import json
import threading
import time
from pathlib import Path

import pytest

from browser_core.contracts import ContractError
from browser_core.multi_identity_ops import (
    MAX_COHORT_PARALLEL,
    run_ops_coherence_cohort,
)
from browser_core.profiles import is_disposable_profile_id, list_profiles

from test_multi_identity_ops import _seed, _seed_host_anchor  # noqa: E402


def _primary(verdict: str = "pass") -> dict:
    return {
        "evaluator_id": "controlled_coherence",
        "status": "ok" if verdict != "error" else "error",
        "verdict": verdict,
        "passed_checks": 62,
        "failed_checks": 0,
        "unavailable_checks": 0,
        "identity_passed_claims": 2,
        "identity_failed_claims": 0,
        "identity_unavailable_claims": 0,
        "failed_check_ids": [],
        "unavailable_check_ids": [],
    }


class _Harness:
    """Fakes that record concurrency without touching a real browser."""

    def __init__(self, tmp_path: Path, hold_seconds: float = 0.05) -> None:
        self.tmp_path = tmp_path
        self.hold = hold_seconds
        self.lock = threading.Lock()
        self.live = 0
        self.peak = 0
        self.completion_order: list[str] = []
        self.fail_profiles: set[str] = set()

    def launch(self, config, repository_root):  # noqa: ANN001
        with self.lock:
            self.live += 1
            self.peak = max(self.peak, self.live)
        path = self.tmp_path / "sessions" / f"{config.profile_id}.json"
        path.parent.mkdir(exist_ok=True)
        path.write_text(
            json.dumps(
                {
                    "schema": "browser-core.session/1",
                    "run_id": f"run-{config.profile_id}",
                    "state": "active",
                    "profile": {"id": config.profile_id},
                }
            ),
            encoding="utf-8",
        )
        return path, {"run_id": f"run-{config.profile_id}", "state": "active"}

    def stop(self, path, timeout_seconds=15.0):  # noqa: ANN001
        with self.lock:
            self.live -= 1
        return {
            "run_id": f"run-{path.stem}",
            "state": "stopped",
            "running": False,
            "identity_protected": True,
        }

    def evaluate(
        self,
        session_file,
        *,
        out_dir,
        evaluators="controlled_coherence",
        workspace=None,
        **_kw,
    ):  # noqa: ANN001
        stem = Path(session_file).stem
        # Stagger so completion order cannot match submission order. Derived from the
        # stem's bytes rather than hash(), which Python randomises per process and
        # would make interleaving -- and therefore any failure -- unreproducible.
        time.sleep(self.hold * (1 + (sum(stem.encode()) % 3)))
        with self.lock:
            self.completion_order.append(stem)
        if stem in self.fail_profiles:
            raise RuntimeError(f"eval blew up for {stem}")
        return {
            "schema": "browser-core.session-coherence-eval/1",
            "session_file": str(session_file),
            "eval_exit": 0,
            "evaluators_requested": evaluators,
            "arms": [_primary()],
            "primary": _primary(),
            "error": None,
            "stderr_tail": "",
        }


def _install(monkeypatch: pytest.MonkeyPatch, harness: _Harness) -> None:
    monkeypatch.setattr(
        "browser_core.multi_identity_ops.discover_browser_core_launch_major",
        lambda _root: 153,
    )
    monkeypatch.setattr("browser_core.launcher.launch_evaluation", harness.launch)
    monkeypatch.setattr("browser_core.lifecycle.stop_session", harness.stop)


def _run(
    tmp_path: Path,
    harness: _Harness,
    *,
    count: int,
    parallel: int,
    ids: list[str],
    batch: str,
) -> dict:
    return run_ops_coherence_cohort(
        tmp_path,
        count=count,
        persona_ids=ids,
        executable=tmp_path / "chrome.exe",
        repository_root=tmp_path,
        out_dir=tmp_path / f"out-{batch}",
        evaluate_session=harness.evaluate,
        headless=False,
        batch_id=batch,
        parallel=parallel,
    )


# ------------------------------------------------------------------ validation


@pytest.mark.parametrize("bad", [0, -1, True, 1.5, "2"])
def test_parallel_must_be_a_positive_integer(tmp_path: Path, bad) -> None:
    with pytest.raises(ContractError, match="parallel must be a positive integer"):
        run_ops_coherence_cohort(
            tmp_path,
            count=1,
            executable=tmp_path / "c.exe",
            repository_root=tmp_path,
            parallel=bad,
        )


def test_parallel_is_hard_capped(tmp_path: Path) -> None:
    """A typo must not be able to start dozens of headed browsers."""
    with pytest.raises(ContractError, match="exceeds the hard cap"):
        run_ops_coherence_cohort(
            tmp_path,
            count=1,
            executable=tmp_path / "c.exe",
            repository_root=tmp_path,
            parallel=MAX_COHORT_PARALLEL + 1,
        )


# ------------------------------------------------------------------ behaviour


def test_parallel_one_stays_strictly_sequential(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The default must keep the historical behaviour exactly."""
    _seed_host_anchor(tmp_path, hw=32)
    ids = _seed(
        tmp_path,
        count=4,
        product="browser-core",
        major=153,
        id_prefix="ops-seq",
        hardware_concurrency=8,
        provenance_source="ops-launch-fixture:{id}",
    )
    harness = _Harness(tmp_path)
    _install(monkeypatch, harness)

    report = _run(tmp_path, harness, count=3, parallel=1, ids=ids, batch="coh-seq01")

    assert report["parallel"] == 1
    assert harness.peak == 1
    assert report["coherence_summary"]["pass"] == 3
    assert report["passed"] is True


def test_parallel_actually_overlaps_arms(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _seed_host_anchor(tmp_path, hw=32)
    ids = _seed(
        tmp_path,
        count=6,
        product="browser-core",
        major=153,
        id_prefix="ops-par",
        hardware_concurrency=8,
        provenance_source="ops-launch-fixture:{id}",
    )
    harness = _Harness(tmp_path)
    _install(monkeypatch, harness)

    report = _run(tmp_path, harness, count=4, parallel=3, ids=ids, batch="coh-par01")

    assert report["parallel"] == 3
    assert harness.peak > 1, "arms never overlapped"
    assert harness.peak <= 3, f"pool exceeded its bound: {harness.peak}"
    assert report["coherence_summary"]["pass"] == 4
    assert report["passed"] is True


def test_pool_never_exceeds_the_requested_bound(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _seed_host_anchor(tmp_path, hw=32)
    ids = _seed(
        tmp_path,
        count=8,
        product="browser-core",
        major=153,
        id_prefix="ops-bound",
        hardware_concurrency=8,
        provenance_source="ops-launch-fixture:{id}",
    )
    harness = _Harness(tmp_path)
    _install(monkeypatch, harness)

    _run(tmp_path, harness, count=6, parallel=2, ids=ids, batch="coh-bound1")

    assert harness.peak <= 2


def test_results_are_in_arm_order_not_completion_order(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Completion order is nondeterministic; the report must not be."""
    _seed_host_anchor(tmp_path, hw=32)
    ids = _seed(
        tmp_path,
        count=6,
        product="browser-core",
        major=153,
        id_prefix="ops-order",
        hardware_concurrency=8,
        provenance_source="ops-launch-fixture:{id}",
    )
    harness = _Harness(tmp_path)
    _install(monkeypatch, harness)

    report = _run(tmp_path, harness, count=5, parallel=4, ids=ids, batch="coh-order1")

    profile_ids = [item["profile_id"] for item in report["identities"]]
    assert profile_ids == [f"ops-disp-coh-order1-{i:03d}" for i in range(5)]
    assert len(report["identities"]) == 5
    # And the fakes really did finish out of order at least once across the run.
    assert len(harness.completion_order) == 5


def test_counters_do_not_race(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _seed_host_anchor(tmp_path, hw=32)
    ids = _seed(
        tmp_path,
        count=8,
        product="browser-core",
        major=153,
        id_prefix="ops-count",
        hardware_concurrency=8,
        provenance_source="ops-launch-fixture:{id}",
    )
    harness = _Harness(tmp_path)
    _install(monkeypatch, harness)

    report = _run(tmp_path, harness, count=6, parallel=4, ids=ids, batch="coh-count1")

    summary = report["coherence_summary"]
    assert summary["pass"] + summary["fail"] + summary["error"] == 6
    assert summary["pass"] == 6
    assert len(report["identity_alignments"]) == 6


def test_failing_arm_is_reported_and_cleaned_up_in_parallel(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """One bad arm must not take the cohort down or leak a disposable profile."""
    _seed_host_anchor(tmp_path, hw=32)
    ids = _seed(
        tmp_path,
        count=6,
        product="browser-core",
        major=153,
        id_prefix="ops-fail",
        hardware_concurrency=8,
        provenance_source="ops-launch-fixture:{id}",
    )
    harness = _Harness(tmp_path)
    harness.fail_profiles = {"ops-disp-coh-fail01-001"}
    _install(monkeypatch, harness)

    report = _run(tmp_path, harness, count=4, parallel=3, ids=ids, batch="coh-fail01")

    assert report["coherence_summary"]["pass"] == 3
    assert report["coherence_summary"]["error"] == 1
    assert report["passed"] is False
    assert any("coh-fail01-001" in e for e in report["errors"])
    assert report["orphans"] == []
    leftovers = [
        p for p in list_profiles(tmp_path) if is_disposable_profile_id(p["id"])
    ]
    assert leftovers == []
    # The healthy arms still disposed cleanly.
    states = [i["state"] for i in report["identities"]]
    assert states.count("disposed") == 3


def test_wall_ms_is_reported(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _seed_host_anchor(tmp_path, hw=32)
    ids = _seed(
        tmp_path,
        count=4,
        product="browser-core",
        major=153,
        id_prefix="ops-wall",
        hardware_concurrency=8,
        provenance_source="ops-launch-fixture:{id}",
    )
    harness = _Harness(tmp_path)
    _install(monkeypatch, harness)

    report = _run(tmp_path, harness, count=3, parallel=2, ids=ids, batch="coh-wall01")

    assert isinstance(report["wall_ms"], float)
    assert report["wall_ms"] > 0
