from __future__ import annotations

import copy

import pytest

from browser_core.cohort import (
    summarize_trace_mode_runs,
    validate_trace_mode_cohort_report,
)
from browser_core.contracts import ContractError


def run(mode: str, launch: float, evaluation: float, *, verdict: str = "pass") -> dict:
    trace_on = mode == "on"
    return {
        "trace_mode": mode,
        "trace_scope": "broad" if trace_on else None,
        "run_id": f"run-{mode}-{launch}-{evaluation}",
        "session_file": f"C:/sessions/{mode}-{launch}.json",
        "run_dir": f"C:/runs/{mode}-{launch}",
        "launch_ms": launch,
        "evaluation_ms": evaluation,
        "stop_ms": 25.0,
        "trace_bytes": 4096 if trace_on else None,
        "trace_summary": {"events": 8, "dropped_events": 0} if trace_on else None,
        "vector": {
            "verdict": verdict,
            "collector_checkset_sha256_16": "a" * 16,
            "passed_checks": 60,
            "failed_checks": 0,
            "unavailable_checks": 2,
            "identity_contract_sha256_16": "b" * 16,
            "identity_passed_claims": 26,
            "identity_failed_claims": 0,
            "identity_unavailable_claims": 0,
            "render_fingerprint": "c" * 16,
            "surface_fingerprint": "d" * 16,
            "automation_fingerprint": "e" * 16,
        },
    }


def test_trace_mode_cohort_passes_balanced_stable_runs() -> None:
    runs = [
        run("off", 100, 500),
        run("on", 110, 520),
        run("on", 108, 510),
        run("off", 102, 505),
    ]
    result = summarize_trace_mode_runs(
        runs,
        trials_per_arm=2,
        max_launch_overhead_percent=20,
        max_evaluation_overhead_percent=10,
        max_trace_bytes=8192,
    )

    assert result["passed"] is True
    assert result["arms"]["on"]["trace_bytes_max"] == 4096
    assert result["delta"]["launch_median_overhead_percent"] > 0


def test_trace_mode_cohort_does_not_round_over_limit_launch_median_into_pass() -> None:
    runs = [
        run("off", 100.0, 500),
        run("on", 110.0002, 520),
        run("on", 110.0003, 510),
        run("off", 100.0002, 505),
    ]
    result = summarize_trace_mode_runs(
        runs,
        trials_per_arm=2,
        max_launch_overhead_percent=10,
        max_evaluation_overhead_percent=10,
        max_trace_bytes=8192,
    )

    assert result["delta"]["launch_median_overhead_percent"] > 10
    assert result["gates"]["launch_overhead_within_limit"] is False
    assert result["passed"] is False


def test_trace_mode_cohort_fails_detector_and_drop_gates() -> None:
    runs = [
        run("off", 100, 500),
        run("on", 110, 520, verdict="fail"),
        run("on", 108, 510),
        run("off", 102, 505),
    ]
    runs[1]["vector"]["failed_checks"] = 1
    runs[1]["trace_summary"]["dropped_events"] = 1
    result = summarize_trace_mode_runs(
        runs,
        trials_per_arm=2,
        max_launch_overhead_percent=20,
        max_evaluation_overhead_percent=10,
        max_trace_bytes=8192,
    )

    assert result["passed"] is False
    assert result["gates"]["all_controlled_verdicts_pass"] is False
    assert result["gates"]["zero_failed_checks"] is False
    assert result["gates"]["trace_on_nonempty_zero_drop"] is False


def test_trace_mode_cohort_fails_inconsistent_complete_identity_claim_counts() -> None:
    runs = [
        run("off", 100, 500),
        run("on", 110, 520),
        run("on", 108, 510),
        run("off", 102, 505),
    ]
    runs[1]["vector"]["identity_passed_claims"] = 25

    result = summarize_trace_mode_runs(
        runs,
        trials_per_arm=2,
        max_launch_overhead_percent=20,
        max_evaluation_overhead_percent=10,
        max_trace_bytes=8192,
    )

    assert result["gates"]["stable_identity_contract"] is True
    assert result["gates"]["all_identity_claims_pass"] is False
    assert result["passed"] is False


def test_trace_mode_cohort_fails_inconsistent_checkset_size() -> None:
    runs = [
        run("off", 100, 500),
        run("on", 110, 520),
        run("on", 108, 510),
        run("off", 102, 505),
    ]
    runs[1]["vector"]["passed_checks"] = 61

    result = summarize_trace_mode_runs(
        runs,
        trials_per_arm=2,
        max_launch_overhead_percent=20,
        max_evaluation_overhead_percent=10,
        max_trace_bytes=8192,
    )

    assert result["gates"]["stable_checkset"] is False
    assert result["passed"] is False


def test_trace_mode_cohort_rejects_mixed_trace_scopes() -> None:
    runs = [
        run("off", 100, 500),
        run("on", 110, 520),
        run("on", 108, 510),
        run("off", 102, 505),
    ]
    runs[2]["trace_scope"] = "causal"
    result = summarize_trace_mode_runs(
        runs,
        trials_per_arm=2,
        max_launch_overhead_percent=20,
        max_evaluation_overhead_percent=10,
        max_trace_bytes=8192,
    )

    assert result["passed"] is False
    assert result["gates"]["stable_trace_scope"] is False


def test_trace_mode_cohort_rejects_unbalanced_runs() -> None:
    with pytest.raises(ContractError, match="run count"):
        summarize_trace_mode_runs(
            [run("off", 100, 500)],
            trials_per_arm=2,
            max_launch_overhead_percent=20,
            max_evaluation_overhead_percent=10,
            max_trace_bytes=8192,
        )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("launch_ms", float("nan")),
        ("evaluation_ms", float("inf")),
        ("stop_ms", True),
        ("stop_ms", 10**400),
    ],
)
def test_trace_mode_cohort_rejects_nonfinite_or_boolean_durations(
    field: str,
    value: object,
) -> None:
    runs = [
        run("off", 100, 500),
        run("on", 110, 520),
        run("on", 108, 510),
        run("off", 102, 505),
    ]
    runs[0][field] = value
    with pytest.raises(ContractError, match="finite|duration"):
        summarize_trace_mode_runs(
            runs,
            trials_per_arm=2,
            max_launch_overhead_percent=20,
            max_evaluation_overhead_percent=10,
            max_trace_bytes=8192,
        )


def test_trace_mode_cohort_rejects_boolean_vector_counts() -> None:
    runs = [
        run("off", 100, 500),
        run("on", 110, 520),
        run("on", 108, 510),
        run("off", 102, 505),
    ]
    runs[0]["vector"]["identity_failed_claims"] = False
    with pytest.raises(ContractError, match="identity_failed_claims"):
        summarize_trace_mode_runs(
            runs,
            trials_per_arm=2,
            max_launch_overhead_percent=20,
            max_evaluation_overhead_percent=10,
            max_trace_bytes=8192,
        )


@pytest.mark.parametrize(
    ("passed_checks", "unavailable_checks"),
    [(0, 62), (1, 61)],
)
def test_trace_mode_cohort_rejects_pass_without_available_check_majority(
    passed_checks: int, unavailable_checks: int
) -> None:
    runs = [
        run("off", 100, 500),
        run("on", 110, 520),
        run("on", 108, 510),
        run("off", 102, 505),
    ]
    runs[0]["vector"]["passed_checks"] = passed_checks
    runs[0]["vector"]["unavailable_checks"] = unavailable_checks

    with pytest.raises(ContractError, match="pass check counts"):
        summarize_trace_mode_runs(
            runs,
            trials_per_arm=2,
            max_launch_overhead_percent=20,
            max_evaluation_overhead_percent=10,
            max_trace_bytes=8192,
        )


@pytest.mark.parametrize("field", ["trace_mode", "trace_scope", "verdict"])
def test_trace_mode_cohort_rejects_unhashable_run_choices(field: str) -> None:
    runs = [
        run("off", 100, 500),
        run("on", 110, 520),
        run("on", 108, 510),
        run("off", 102, 505),
    ]
    target = runs[1]["vector"] if field == "verdict" else runs[1]
    target[field] = ["on"]
    with pytest.raises(ContractError, match="trace mode|trace scope|verdict"):
        summarize_trace_mode_runs(
            runs,
            trials_per_arm=2,
            max_launch_overhead_percent=20,
            max_evaluation_overhead_percent=10,
            max_trace_bytes=8192,
        )


def test_trace_mode_cohort_rejects_extra_trace_summary_fields_without_echo() -> None:
    runs = [
        run("off", 100, 500),
        run("on", 110, 520),
        run("on", 108, 510),
        run("off", 102, 505),
    ]
    runs[1]["trace_summary"]["private"] = "private-trace-marker"
    with pytest.raises(ContractError) as failure:
        summarize_trace_mode_runs(
            runs,
            trials_per_arm=2,
            max_launch_overhead_percent=20,
            max_evaluation_overhead_percent=10,
            max_trace_bytes=8192,
        )
    assert "private-trace-marker" not in str(failure.value)


def test_portable_trace_mode_report_recomputes_aggregate_gates() -> None:
    report = summarize_trace_mode_runs(
        [
            run("off", 100, 500),
            run("on", 110, 520),
            run("on", 108, 510),
            run("off", 102, 505),
        ],
        trials_per_arm=2,
        max_launch_overhead_percent=20,
        max_evaluation_overhead_percent=10,
        max_trace_bytes=8192,
    )
    assert validate_trace_mode_cohort_report(report) == report

    mutations = []
    extra = copy.deepcopy(report)
    extra["private"] = "private-report-marker"
    mutations.append(extra)
    unbalanced = copy.deepcopy(report)
    unbalanced["arms"]["off"]["runs"] = 3
    mutations.append(unbalanced)
    pass_count = copy.deepcopy(report)
    pass_count["arms"]["on"]["pass_runs"] = 1
    mutations.append(pass_count)
    trace_median = copy.deepcopy(report)
    trace_median["arms"]["on"]["trace_bytes_median"] = 10**400
    mutations.append(trace_median)
    delta = copy.deepcopy(report)
    delta["delta"]["launch_median_overhead_percent"] += 1
    mutations.append(delta)
    huge_delta = copy.deepcopy(report)
    huge_delta["delta"]["launch_median_overhead_percent"] = 10**400
    mutations.append(huge_delta)
    limit = copy.deepcopy(report)
    limit["limits"]["max_trace_bytes"] = 1
    mutations.append(limit)
    gate = copy.deepcopy(report)
    gate["gates"]["balanced_arms"] = False
    mutations.append(gate)
    verdict = copy.deepcopy(report)
    verdict["passed"] = False
    mutations.append(verdict)

    for mutation in mutations:
        with pytest.raises(ContractError) as failure:
            validate_trace_mode_cohort_report(mutation)
        assert "private-report-marker" not in str(failure.value)


def test_trace_mode_cohort_rejects_non_alternating_pair_order() -> None:
    runs = [
        run("on", 110, 520),
        run("off", 100, 500),
        run("on", 108, 510),
        run("off", 102, 505),
    ]
    with pytest.raises(ContractError, match="pair order"):
        summarize_trace_mode_runs(
            runs,
            trials_per_arm=2,
            max_launch_overhead_percent=20,
            max_evaluation_overhead_percent=10,
            max_trace_bytes=8192,
        )


@pytest.mark.parametrize("field", ["session_file", "run_dir"])
def test_trace_mode_cohort_rejects_reused_trial_evidence(field: str) -> None:
    runs = [
        run("off", 100, 500),
        run("on", 110, 520),
        run("on", 108, 510),
        run("off", 102, 505),
    ]
    runs[2][field] = runs[1][field]

    with pytest.raises(ContractError, match="not unique"):
        summarize_trace_mode_runs(
            runs,
            trials_per_arm=2,
            max_launch_overhead_percent=20,
            max_evaluation_overhead_percent=10,
            max_trace_bytes=8192,
        )


@pytest.mark.parametrize("field", ["session_file", "run_dir"])
@pytest.mark.parametrize("alias", ["case-and-separator", "dot-segment"])
def test_trace_mode_cohort_rejects_windows_path_aliases(field: str, alias: str) -> None:
    runs = [
        run("off", 100, 500),
        run("on", 110, 520),
        run("on", 108, 510),
        run("off", 102, 505),
    ]
    original = runs[1][field]
    runs[2][field] = (
        original.replace("/", "\\").swapcase()
        if alias == "case-and-separator" else original.replace("C:/", "C:/./")
    )

    with pytest.raises(ContractError, match="not unique"):
        summarize_trace_mode_runs(
            runs,
            trials_per_arm=2,
            max_launch_overhead_percent=20,
            max_evaluation_overhead_percent=10,
            max_trace_bytes=8192,
        )


@pytest.mark.parametrize(
    "kwargs",
    [
        {"trials_per_arm": True},
        {"trials_per_arm": 65},
        {"max_launch_overhead_percent": float("nan")},
        {"max_launch_overhead_percent": 10**400},
        {"max_evaluation_overhead_percent": -1},
        {"max_trace_bytes": True},
    ],
)
def test_trace_mode_cohort_rejects_invalid_controls(kwargs: dict) -> None:
    controls = {
        "trials_per_arm": 2,
        "max_launch_overhead_percent": 20,
        "max_evaluation_overhead_percent": 10,
        "max_trace_bytes": 8192,
    }
    controls.update(kwargs)
    with pytest.raises(ContractError):
        summarize_trace_mode_runs([], **controls)
