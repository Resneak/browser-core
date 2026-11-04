from __future__ import annotations

import ntpath
import os
import re
import statistics
from typing import Any

from .contracts import ContractError
from .contracts import RUN_ID_RE
from .numeric import is_finite_number
from .trace_scopes import TRACE_SCOPES


TRACE_MODE_COHORT_SCHEMA = "browser-core.trace-mode-cohort/1"
MAX_TRACE_MODE_TRIALS_PER_ARM = 64
MAX_TRACE_MODE_DURATION_MS = 1_000_000.0
MAX_TRACE_MODE_TRACE_BYTES = 1024 * 1024 * 1024
_DIGEST_16_RE = re.compile(r"^[0-9a-f]{16}$")
_COHORT_GATES = {
    "balanced_arms",
    "stable_trace_scope",
    "all_controlled_verdicts_pass",
    "zero_failed_checks",
    "stable_identity_contract",
    "all_identity_claims_pass",
    "stable_checkset",
    "stable_render_fingerprint",
    "stable_surface_fingerprint",
    "stable_automation_fingerprint",
    "trace_on_nonempty_zero_drop",
    "trace_off_has_no_artifact",
    "trace_size_within_limit",
    "launch_overhead_within_limit",
    "evaluation_overhead_within_limit",
}


def validate_trace_mode_cohort_controls(
    *,
    trials_per_arm: int,
    max_launch_overhead_percent: float,
    max_evaluation_overhead_percent: float,
    max_trace_bytes: int,
) -> None:
    if (
        isinstance(trials_per_arm, bool)
        or not isinstance(trials_per_arm, int)
        or not 2 <= trials_per_arm <= MAX_TRACE_MODE_TRIALS_PER_ARM
    ):
        raise ContractError("trace-mode trials per arm must be in [2, 64]")
    for value, label in (
        (max_launch_overhead_percent, "launch overhead limit"),
        (max_evaluation_overhead_percent, "evaluation overhead limit"),
    ):
        if not is_finite_number(value) or not 0 <= value <= 1000:
            raise ContractError(f"trace-mode {label} must be finite and in [0, 1000]")
    if (
        isinstance(max_trace_bytes, bool)
        or not isinstance(max_trace_bytes, int)
        or not 1 <= max_trace_bytes <= MAX_TRACE_MODE_TRACE_BYTES
    ):
        raise ContractError("trace-mode maximum trace bytes is invalid")


def _number(value: Any, label: str) -> float:
    if not is_finite_number(value) or not 0 <= value <= MAX_TRACE_MODE_DURATION_MS:
        raise ContractError(f"{label} must be finite and in the duration budget")
    return float(value)


def _count(value: Any, label: str, *, positive: bool = False) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not (1 <= value <= 10_000_000 if positive else 0 <= value <= 10_000_000)
    ):
        raise ContractError(f"{label} is invalid")
    return value


def _fingerprint(value: Any, label: str) -> str:
    if not isinstance(value, str) or _DIGEST_16_RE.fullmatch(value) is None:
        raise ContractError(f"{label} is invalid")
    return value


def _evidence_path_key(value: str) -> tuple[str, str]:
    if ntpath.splitdrive(value)[0]:
        return ("windows", ntpath.normcase(ntpath.normpath(value)))
    return ("native", os.path.normcase(os.path.normpath(value)))


def _validated_run(run: Any, index: int) -> dict[str, Any]:
    fields = {
        "trace_mode",
        "trace_scope",
        "run_id",
        "session_file",
        "run_dir",
        "launch_ms",
        "evaluation_ms",
        "stop_ms",
        "trace_bytes",
        "trace_summary",
        "vector",
    }
    if not isinstance(run, dict) or set(run) != fields:
        raise ContractError(f"cohort run {index} structure is invalid")
    mode = run.get("trace_mode")
    if not isinstance(mode, str) or mode not in {"off", "on"}:
        raise ContractError(f"cohort run {index} has an invalid trace mode")
    scope = run.get("trace_scope")
    if (mode == "off" and scope is not None) or (
        mode == "on" and (not isinstance(scope, str) or scope not in TRACE_SCOPES)
    ):
        raise ContractError(f"cohort run {index} has an invalid trace scope")
    run_id = run.get("run_id")
    if not isinstance(run_id, str) or RUN_ID_RE.fullmatch(run_id) is None:
        raise ContractError(f"cohort run {index} run ID is invalid")
    for field in ("session_file", "run_dir"):
        value = run.get(field)
        if (
            not isinstance(value, str)
            or not 1 <= len(value) <= 32_768
            or any(
                ord(character) < 0x20 or ord(character) == 0x7F for character in value
            )
        ):
            raise ContractError(f"cohort run {index} {field} is invalid")
    for field in ("launch_ms", "evaluation_ms", "stop_ms"):
        _number(run.get(field), f"cohort run {index} {field}")
    vector = run.get("vector")
    vector_fields = {
        "verdict",
        "collector_checkset_sha256_16",
        "passed_checks",
        "failed_checks",
        "unavailable_checks",
        "identity_contract_sha256_16",
        "identity_passed_claims",
        "identity_failed_claims",
        "identity_unavailable_claims",
        "render_fingerprint",
        "surface_fingerprint",
        "automation_fingerprint",
    }
    if not isinstance(vector, dict) or set(vector) != vector_fields:
        raise ContractError(f"cohort run {index} vector is invalid")
    if not isinstance(vector.get("verdict"), str) or vector["verdict"] not in {"pass", "fail"}:
        raise ContractError(f"cohort run {index} verdict is invalid")
    for field in ("passed_checks", "failed_checks", "unavailable_checks"):
        _count(vector.get(field), f"cohort run {index} {field}")
    if (
        vector["verdict"] == "pass"
        and vector["passed_checks"] <= vector["unavailable_checks"]
    ):
        raise ContractError(f"cohort run {index} pass check counts are inconsistent")
    _count(
        vector.get("identity_passed_claims"),
        f"cohort run {index} identity_passed_claims",
        positive=True,
    )
    for field in ("identity_failed_claims", "identity_unavailable_claims"):
        _count(vector.get(field), f"cohort run {index} {field}")
    for field in (
        "collector_checkset_sha256_16",
        "identity_contract_sha256_16",
        "render_fingerprint",
        "surface_fingerprint",
        "automation_fingerprint",
    ):
        _fingerprint(vector.get(field), f"cohort run {index} {field}")
    if mode == "off":
        if run.get("trace_bytes") is not None or run.get("trace_summary") is not None:
            raise ContractError("trace-off cohort run retained trace evidence")
    else:
        trace_bytes = run.get("trace_bytes")
        if (
            isinstance(trace_bytes, bool)
            or not isinstance(trace_bytes, int)
            or not 1 <= trace_bytes <= MAX_TRACE_MODE_TRACE_BYTES
        ):
            raise ContractError(
                "trace-on cohort requires a bounded positive trace size"
            )
        trace_summary = run.get("trace_summary")
        if not isinstance(trace_summary, dict) or set(trace_summary) != {
            "events",
            "dropped_events",
        }:
            raise ContractError("trace-on cohort summary is invalid")
        _count(
            trace_summary.get("events"), "trace-on cohort event count", positive=True
        )
        _count(
            trace_summary.get("dropped_events"), "trace-on cohort dropped-event count"
        )
    return run


def _median(values: list[float]) -> float:
    return float(statistics.median(values))


def _overhead_percent(enabled: float, disabled: float) -> float:
    if disabled <= 0:
        raise ContractError("trace-off median must be positive")
    return ((enabled - disabled) / disabled) * 100.0


def validate_trace_mode_cohort_report(report: Any) -> dict[str, Any]:
    if not isinstance(report, dict) or set(report) != {
        "schema",
        "arms",
        "delta",
        "limits",
        "gates",
        "passed",
    }:
        raise ContractError("trace-mode cohort report fields are invalid")
    if report.get("schema") != TRACE_MODE_COHORT_SCHEMA:
        raise ContractError("trace-mode cohort report schema is invalid")

    arms = report.get("arms")
    if not isinstance(arms, dict) or set(arms) != {"off", "on"}:
        raise ContractError("trace-mode cohort report arms are invalid")
    common = {
        "runs",
        "pass_runs",
        "launch_ms_median",
        "evaluation_ms_median",
        "stop_ms_median",
    }
    if not isinstance(arms["off"], dict) or set(arms["off"]) != common:
        raise ContractError("trace-mode cohort trace-off arm is invalid")
    if not isinstance(arms["on"], dict) or set(arms["on"]) != common | {
        "trace_bytes_median",
        "trace_bytes_max",
    }:
        raise ContractError("trace-mode cohort trace-on arm is invalid")
    for mode in ("off", "on"):
        arm = arms[mode]
        runs = _count(arm.get("runs"), f"trace-{mode} report runs", positive=True)
        if not 2 <= runs <= MAX_TRACE_MODE_TRIALS_PER_ARM:
            raise ContractError(f"trace-{mode} report runs are invalid")
        pass_runs = _count(arm.get("pass_runs"), f"trace-{mode} report passes")
        if pass_runs > runs:
            raise ContractError(f"trace-{mode} report passes are invalid")
        for field in ("launch_ms_median", "evaluation_ms_median", "stop_ms_median"):
            _number(arm.get(field), f"trace-{mode} report {field}")
    trace_bytes_median = arms["on"].get("trace_bytes_median")
    trace_bytes_max = arms["on"].get("trace_bytes_max")
    if (
        not is_finite_number(trace_bytes_median)
        or isinstance(trace_bytes_max, bool)
        or not isinstance(trace_bytes_max, int)
    ):
        raise ContractError("trace-on report trace-byte aggregate is invalid")
    if not 0 < trace_bytes_median <= trace_bytes_max <= MAX_TRACE_MODE_TRACE_BYTES:
        raise ContractError("trace-on report trace-byte aggregate is invalid")

    delta = report.get("delta")
    if not isinstance(delta, dict) or set(delta) != {
        "launch_median_overhead_percent",
        "evaluation_median_overhead_percent",
    }:
        raise ContractError("trace-mode cohort report delta is invalid")
    expected_launch = _overhead_percent(
        float(arms["on"]["launch_ms_median"]),
        float(arms["off"]["launch_ms_median"]),
    )
    expected_evaluation = _overhead_percent(
        float(arms["on"]["evaluation_ms_median"]),
        float(arms["off"]["evaluation_ms_median"]),
    )
    if (
        not is_finite_number(delta.get("launch_median_overhead_percent"))
        or delta["launch_median_overhead_percent"] != expected_launch
        or not is_finite_number(delta.get("evaluation_median_overhead_percent"))
        or delta["evaluation_median_overhead_percent"] != expected_evaluation
    ):
        raise ContractError("trace-mode cohort report overhead is inconsistent")

    limits = report.get("limits")
    if not isinstance(limits, dict) or set(limits) != {
        "max_launch_overhead_percent",
        "max_evaluation_overhead_percent",
        "max_trace_bytes",
    }:
        raise ContractError("trace-mode cohort report limits are invalid")
    validate_trace_mode_cohort_controls(trials_per_arm=arms["off"]["runs"], **limits)

    gates = report.get("gates")
    if (
        not isinstance(gates, dict)
        or set(gates) != _COHORT_GATES
        or any(type(value) is not bool for value in gates.values())
    ):
        raise ContractError("trace-mode cohort report gates are invalid")
    derived_gates = {
        "balanced_arms": arms["off"]["runs"] == arms["on"]["runs"],
        "all_controlled_verdicts_pass": all(
            arm["pass_runs"] == arm["runs"] for arm in arms.values()
        ),
        "trace_size_within_limit": trace_bytes_max <= limits["max_trace_bytes"],
        "launch_overhead_within_limit": expected_launch
        <= limits["max_launch_overhead_percent"],
        "evaluation_overhead_within_limit": expected_evaluation
        <= limits["max_evaluation_overhead_percent"],
    }
    if any(gates[field] is not value for field, value in derived_gates.items()):
        raise ContractError("trace-mode cohort report gates are inconsistent")
    if type(report.get("passed")) is not bool or report["passed"] is not all(
        gates.values()
    ):
        raise ContractError("trace-mode cohort report verdict is inconsistent")
    return report


def summarize_trace_mode_runs(
    runs: list[dict[str, Any]],
    *,
    trials_per_arm: int,
    max_launch_overhead_percent: float,
    max_evaluation_overhead_percent: float,
    max_trace_bytes: int,
) -> dict[str, Any]:
    validate_trace_mode_cohort_controls(
        trials_per_arm=trials_per_arm,
        max_launch_overhead_percent=max_launch_overhead_percent,
        max_evaluation_overhead_percent=max_evaluation_overhead_percent,
        max_trace_bytes=max_trace_bytes,
    )
    if not isinstance(runs, list):
        raise ContractError("trace-mode cohort runs must be a list")
    if len(runs) != trials_per_arm * 2:
        raise ContractError("trace-mode cohort has an unexpected run count")

    validated_runs = [_validated_run(run, index) for index, run in enumerate(runs)]
    if len({run["run_id"] for run in validated_runs}) != len(validated_runs):
        raise ContractError("trace-mode cohort run IDs are not unique")
    for field in ("session_file", "run_dir"):
        if len({_evidence_path_key(run[field]) for run in validated_runs}) != len(validated_runs):
            raise ContractError(f"trace-mode cohort {field} paths are not unique")
    for pair_index in range(trials_per_arm):
        expected = ("off", "on") if pair_index % 2 == 0 else ("on", "off")
        observed = tuple(
            validated_runs[pair_index * 2 + offset]["trace_mode"] for offset in (0, 1)
        )
        if observed != expected:
            raise ContractError("trace-mode cohort pair order is invalid")

    by_mode: dict[str, list[dict[str, Any]]] = {"off": [], "on": []}
    for index, run in enumerate(validated_runs):
        mode = run.get("trace_mode")
        by_mode[mode].append(run)
    if any(len(items) != trials_per_arm for items in by_mode.values()):
        raise ContractError("trace-mode cohort arms are unbalanced")

    aggregates: dict[str, Any] = {}
    all_vectors: list[dict[str, Any]] = []
    for mode, items in by_mode.items():
        vectors = [item.get("vector") for item in items]
        if not all(isinstance(vector, dict) for vector in vectors):
            raise ContractError(f"trace-{mode} cohort vector is invalid")
        typed_vectors = [vector for vector in vectors if isinstance(vector, dict)]
        all_vectors.extend(typed_vectors)
        launch_values = [
            _number(item.get("launch_ms"), f"trace-{mode} launch_ms") for item in items
        ]
        evaluation_values = [
            _number(item.get("evaluation_ms"), f"trace-{mode} evaluation_ms")
            for item in items
        ]
        stop_values = [
            _number(item.get("stop_ms"), f"trace-{mode} stop_ms") for item in items
        ]
        aggregates[mode] = {
            "runs": len(items),
            "pass_runs": sum(
                vector.get("verdict") == "pass" for vector in typed_vectors
            ),
            "launch_ms_median": _median(launch_values),
            "evaluation_ms_median": _median(evaluation_values),
            "stop_ms_median": _median(stop_values),
        }
        if mode == "on":
            trace_bytes = [item.get("trace_bytes") for item in items]
            if not all(
                isinstance(value, int) and not isinstance(value, bool) and value > 0
                for value in trace_bytes
            ):
                raise ContractError("trace-on cohort requires positive trace sizes")
            aggregates[mode]["trace_bytes_median"] = _median(
                [float(value) for value in trace_bytes]
            )
            aggregates[mode]["trace_bytes_max"] = max(trace_bytes)

    checksets = {vector.get("collector_checkset_sha256_16") for vector in all_vectors}
    check_totals = {
        sum(vector[field] for field in (
            "passed_checks", "failed_checks", "unavailable_checks"
        )) for vector in all_vectors
    }
    identity_contracts = {
        vector.get("identity_contract_sha256_16") for vector in all_vectors
    }
    render_vectors = {vector.get("render_fingerprint") for vector in all_vectors}
    surface_vectors = {vector.get("surface_fingerprint") for vector in all_vectors}
    automation_vectors = {
        vector.get("automation_fingerprint") for vector in all_vectors
    }
    launch_overhead = _overhead_percent(
        aggregates["on"]["launch_ms_median"], aggregates["off"]["launch_ms_median"]
    )
    evaluation_overhead = _overhead_percent(
        aggregates["on"]["evaluation_ms_median"],
        aggregates["off"]["evaluation_ms_median"],
    )
    on_trace_scopes = {item.get("trace_scope") for item in by_mode["on"]}

    gates = {
        "balanced_arms": all(
            len(items) == trials_per_arm for items in by_mode.values()
        ),
        "stable_trace_scope": (
            len(on_trace_scopes) == 1
            and next(iter(on_trace_scopes)) in TRACE_SCOPES
            and all(item.get("trace_scope") is None for item in by_mode["off"])
        ),
        "all_controlled_verdicts_pass": all(
            vector.get("verdict") == "pass" for vector in all_vectors
        ),
        "zero_failed_checks": all(
            vector.get("failed_checks") == 0 for vector in all_vectors
        ),
        "stable_identity_contract": len(identity_contracts) == 1
        and None not in identity_contracts,
        "all_identity_claims_pass": len({
            vector.get("identity_passed_claims") for vector in all_vectors
        }) == 1 and all(
            isinstance(vector.get("identity_passed_claims"), int)
            and vector["identity_passed_claims"] > 0
            and vector.get("identity_failed_claims") == 0
            and vector.get("identity_unavailable_claims") == 0
            for vector in all_vectors
        ),
        "stable_checkset": len(checksets) == 1 and None not in checksets
        and len(check_totals) == 1,
        "stable_render_fingerprint": len(render_vectors) == 1
        and None not in render_vectors,
        "stable_surface_fingerprint": len(surface_vectors) == 1
        and None not in surface_vectors,
        "stable_automation_fingerprint": len(automation_vectors) == 1
        and None not in automation_vectors,
        "trace_on_nonempty_zero_drop": all(
            isinstance(item.get("trace_summary"), dict)
            and item["trace_summary"].get("events", 0) > 0
            and item["trace_summary"].get("dropped_events") == 0
            for item in by_mode["on"]
        ),
        "trace_off_has_no_artifact": all(
            item.get("trace_bytes") is None and item.get("trace_summary") is None
            for item in by_mode["off"]
        ),
        "trace_size_within_limit": aggregates["on"]["trace_bytes_max"]
        <= max_trace_bytes,
        "launch_overhead_within_limit": launch_overhead <= max_launch_overhead_percent,
        "evaluation_overhead_within_limit": evaluation_overhead
        <= max_evaluation_overhead_percent,
    }
    report = {
        "schema": TRACE_MODE_COHORT_SCHEMA,
        "arms": aggregates,
        "delta": {
            "launch_median_overhead_percent": launch_overhead,
            "evaluation_median_overhead_percent": evaluation_overhead,
        },
        "limits": {
            "max_launch_overhead_percent": max_launch_overhead_percent,
            "max_evaluation_overhead_percent": max_evaluation_overhead_percent,
            "max_trace_bytes": max_trace_bytes,
        },
        "gates": gates,
        "passed": all(gates.values()),
    }
    return validate_trace_mode_cohort_report(report)
