from __future__ import annotations

import argparse
import json
import os
import re
import stat
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable


REPOSITORY = Path(__file__).resolve().parents[3]
CORE_ROOT = REPOSITORY / "general" / "browser-core"
EVAL_ROOT = REPOSITORY / "general" / "browser-eval"
sys.path[:0] = [str(CORE_ROOT), str(EVAL_ROOT)]

from browser_core.build import executable_evidence  # noqa: E402
from browser_core.cohort import summarize_trace_mode_runs  # noqa: E402
from browser_core.cohort import validate_trace_mode_cohort_controls  # noqa: E402
from browser_core.contracts import ContractError  # noqa: E402
from browser_core.control_files import (  # noqa: E402
    JsonPublicationCursor,
    decode_strict_json_bytes,
    read_bounded_control_snapshot_result,
)
from browser_core.launcher import EvaluationLaunch, launch_evaluation  # noqa: E402
from browser_core.lifecycle import (  # noqa: E402
    stop_session,
    validate_stopped_session_receipt,
)
from browser_core.owned_paths import directory_identity  # noqa: E402
from browser_core.perfetto import export_perfetto  # noqa: E402
from browser_core.profiles import PROFILE_ID_RE, load_profile, profile_identity_contract  # noqa: E402
from browser_core.trace import summarize  # noqa: E402
from browser_core.trace_scopes import TRACE_SCOPES  # noqa: E402
from browser_eval.registry import load_registry, select_specs  # noqa: E402
from browser_eval.redact import redact_obj  # noqa: E402
from browser_eval.runner import RunConfig, execute_run  # noqa: E402


MAX_TRACE_COHORT_REPORT_BYTES = 64 * 1024 * 1024
MAX_EVALUATOR_SELECTION_CHARACTERS = 512
_DIGEST_16_RE = re.compile(r"^[0-9a-f]{16}$")


def utc_stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _strict_json_file(path: Path, *, label: str) -> dict[str, Any]:
    snapshot = read_bounded_control_snapshot_result(
        path,
        maximum=MAX_TRACE_COHORT_REPORT_BYTES,
        label=label,
        require_single_link=True,
    )
    if snapshot.state != "complete" or snapshot.body is None:
        raise ContractError(f"{label} is {snapshot.state}")

    try:
        document = decode_strict_json_bytes(snapshot.body, label=label)
    except ContractError:
        raise ContractError(f"{label} is not strict JSON") from None
    if not isinstance(document, dict):
        raise ContractError(f"{label} must be a JSON object")
    return document


def _validate_evaluator_selection(value: object) -> str:
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= MAX_EVALUATOR_SELECTION_CHARACTERS
        or any(ord(character) < 0x20 or ord(character) == 0x7F for character in value)
    ):
        raise ContractError("trace-mode evaluator selection is invalid")
    return value


def _validate_trace_processor(path: Path) -> None:
    try:
        metadata = os.lstat(path)
    except OSError:
        raise ContractError("trace-mode trace processor is unavailable") from None
    if (
        not stat.S_ISREG(metadata.st_mode)
        or bool(getattr(metadata, "st_file_attributes", 0) & 0x400)
        or metadata.st_nlink != 1
        or metadata.st_size <= 0
    ):
        raise ContractError(
            "trace-mode trace processor is not a stable single-link file"
        )


def result_vector(summary: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(summary, dict) or not isinstance(summary.get("evaluators"), list):
        raise ContractError("trace-mode evaluator summary is invalid")
    matches = [
        item
        for item in summary["evaluators"]
        if isinstance(item, dict) and item.get("id") == "controlled_coherence"
    ]
    if len(matches) != 1 or not isinstance(matches[0].get("signals"), dict):
        raise ContractError("trace-mode controlled evaluator result is invalid")
    evaluator = matches[0]
    if evaluator.get("status") != "ok":
        raise ContractError("trace-mode controlled evaluator result is invalid")
    signals = evaluator["signals"]
    keys = (
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
    )
    if evaluator.get("verdict") not in {"pass", "fail"} or any(
        signals.get(key) is None for key in keys
    ):
        raise ContractError("trace-mode controlled evaluator signals are incomplete")
    for key in (
        "passed_checks",
        "failed_checks",
        "unavailable_checks",
        "identity_passed_claims",
        "identity_failed_claims",
        "identity_unavailable_claims",
    ):
        value = signals[key]
        if (
            isinstance(value, bool)
            or not isinstance(value, int)
            or not 0 <= value <= 1_000_000
            or (key == "identity_passed_claims" and value == 0)
        ):
            raise ContractError("trace-mode controlled evaluator signals are invalid")
    for key in (
        "collector_checkset_sha256_16",
        "identity_contract_sha256_16",
        "render_fingerprint",
        "surface_fingerprint",
        "automation_fingerprint",
    ):
        value = signals[key]
        if not isinstance(value, str) or _DIGEST_16_RE.fullmatch(value) is None:
            raise ContractError("trace-mode controlled evaluator signals are invalid")
    if evaluator["verdict"] == "pass" and any(
        signals[key] != 0
        for key in ("failed_checks", "identity_failed_claims", "identity_unavailable_claims")
    ):
        raise ContractError("trace-mode controlled evaluator signals are inconsistent")
    return {"verdict": evaluator["verdict"], **{key: signals[key] for key in keys}}


def evaluator_run(output: Path, selection: str) -> tuple[Path, dict[str, Any]]:
    selection = _validate_evaluator_selection(selection)
    specs = select_specs(
        load_registry(EVAL_ROOT / "browser_eval" / "data" / "evaluators.json"),
        selection,
    )
    if not any(spec.id == "controlled_coherence" for spec in specs):
        raise ValueError(
            "trace-mode cohort requires the controlled_coherence evaluator"
        )
    return execute_run(
        specs,
        RunConfig(
            backend="external-cdp",
            channel="chromium",
            headless=False,
            profile=None,
            screenshots=False,
            out=output,
            timeout_ms=90_000,
        ),
    )


def elapsed_ms(start_ns: int) -> float:
    return round((time.perf_counter_ns() - start_ns) / 1_000_000.0, 3)


def run_trial(
    *,
    executable: Path,
    trace_processor: Path,
    workspace: Path,
    profile_id: str,
    trace_mode: str,
    trace_scope: str,
    output: Path,
    evaluator_selection: str,
) -> dict[str, Any]:
    if not all(
        isinstance(path, Path)
        for path in (executable, trace_processor, workspace, output)
    ):
        raise ContractError("trace-mode trial paths must be Paths")
    if not isinstance(profile_id, str) or PROFILE_ID_RE.fullmatch(profile_id) is None:
        raise ContractError("trace-mode trial profile ID is invalid")
    if (
        not isinstance(trace_mode, str)
        or trace_mode not in {"off", "on"}
        or not isinstance(trace_scope, str)
        or trace_scope not in TRACE_SCOPES
    ):
        raise ContractError("trace-mode trial mode or scope is invalid")
    evaluator_selection = _validate_evaluator_selection(evaluator_selection)
    launch_started = time.perf_counter_ns()
    session_path, session = launch_evaluation(
        EvaluationLaunch(
            executable=executable,
            workspace=workspace,
            profile_id=profile_id,
            timeout_seconds=60,
            trace_mode=trace_mode,
            trace_scope=trace_scope,
        ),
        CORE_ROOT,
    )
    launch_ms = elapsed_ms(launch_started)
    old_endpoint = os.environ.pop("BROWSER_EVAL_CDP_ENDPOINT", None)
    old_session = os.environ.get("BROWSER_CORE_SESSION_FILE")
    os.environ["BROWSER_CORE_SESSION_FILE"] = str(session_path)
    summary: dict[str, Any] | None = None
    run_dir: Path | None = None
    evaluation_ms: float | None = None
    stop_ms: float | None = None
    try:
        evaluation_started = time.perf_counter_ns()
        returned_run_dir, returned_summary = evaluator_run(output, evaluator_selection)
        if not isinstance(returned_run_dir, Path):
            raise ContractError("trace-mode evaluator run directory is invalid")
        run_dir = returned_run_dir.resolve()
        try:
            run_dir.relative_to(output.resolve())
        except ValueError:
            raise ContractError(
                "trace-mode evaluator run directory escaped its output"
            ) from None
        summary = _strict_json_file(
            run_dir / "summary.json",
            label="trace-mode evaluator summary",
        )
        if not isinstance(returned_summary, dict):
            raise ContractError("trace-mode evaluator summary changed after evaluation")
        try:
            returned_json = json.dumps(
                redact_obj(returned_summary), sort_keys=True, separators=(",", ":"), allow_nan=False
            )
            saved_json = json.dumps(summary, sort_keys=True, separators=(",", ":"), allow_nan=False)
        except (TypeError, ValueError):
            raise ContractError("trace-mode evaluator summary changed after evaluation") from None
        if returned_json != saved_json:
            raise ContractError("trace-mode evaluator summary changed after evaluation")
        evaluation_ms = elapsed_ms(evaluation_started)
    finally:
        try:
            stop_started = time.perf_counter_ns()
            validate_stopped_session_receipt(
                stop_session(session_path, timeout_seconds=30),
                expected_run_id=session.get("run_id"),
            )
            stop_ms = elapsed_ms(stop_started)
        finally:
            if old_session is None:
                os.environ.pop("BROWSER_CORE_SESSION_FILE", None)
            else:
                os.environ["BROWSER_CORE_SESSION_FILE"] = old_session
            if old_endpoint is None:
                os.environ.pop("BROWSER_EVAL_CDP_ENDPOINT", None)
            else:
                os.environ["BROWSER_EVAL_CDP_ENDPOINT"] = old_endpoint
    if summary is None or run_dir is None or evaluation_ms is None or stop_ms is None:
        raise RuntimeError("trace-mode trial did not produce a complete evaluation")

    trace_bytes: int | None = None
    trace_summary: dict[str, Any] | None = None
    if trace_mode == "on":
        trace_path = Path(session["trace_path"])
        normalized = trace_path.with_suffix(".jsonl")
        export = export_perfetto(
            trace_processor,
            trace_path,
            normalized,
            session["run_id"],
            session["chromium_revision"],
        )
        trace_bytes = export["report"]["source_trace"]["bytes"]
        trace_summary = summarize(normalized)
    elif session.get("trace_path") is not None:
        raise RuntimeError("trace-off trial unexpectedly retained a trace path")

    return {
        "trace_mode": trace_mode,
        "trace_scope": session.get("trace_scope"),
        "run_id": session["run_id"],
        "session_file": str(session_path),
        "run_dir": str(run_dir),
        "launch_ms": launch_ms,
        "evaluation_ms": evaluation_ms,
        "stop_ms": stop_ms,
        "trace_bytes": trace_bytes,
        "trace_summary": trace_summary,
        "vector": result_vector(summary),
    }


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(
        description="Alternate tracing-off and tracing-on trials for one attested Browser Core build"
    )
    result.add_argument("--executable", type=Path, required=True)
    result.add_argument("--trace-processor", type=Path, required=True)
    result.add_argument("--workspace", type=Path, required=True)
    result.add_argument("--profile-id", required=True)
    result.add_argument("--out", type=Path, required=True)
    result.add_argument("--trials", type=int, default=5, help="trials per arm")
    result.add_argument("--evaluators", default="controlled_coherence")
    result.add_argument("--trace-scope", choices=tuple(TRACE_SCOPES), default="broad")
    result.add_argument("--max-launch-overhead-percent", type=float, default=30.0)
    result.add_argument("--max-evaluation-overhead-percent", type=float, default=20.0)
    result.add_argument("--max-trace-bytes", type=int, default=5 * 1024 * 1024)
    return result


def main() -> int:
    args = parser().parse_args()
    if not all(
        isinstance(path, Path)
        for path in (args.executable, args.trace_processor, args.workspace, args.out)
    ):
        raise ContractError("trace-mode cohort paths must be Paths")
    if (
        not isinstance(args.profile_id, str)
        or PROFILE_ID_RE.fullmatch(args.profile_id) is None
    ):
        raise ContractError("trace-mode cohort profile ID is invalid")
    if not isinstance(args.trace_scope, str) or args.trace_scope not in TRACE_SCOPES:
        raise ContractError("trace-mode cohort scope is invalid")
    evaluator_selection = _validate_evaluator_selection(args.evaluators)
    validate_trace_mode_cohort_controls(
        trials_per_arm=args.trials,
        max_launch_overhead_percent=args.max_launch_overhead_percent,
        max_evaluation_overhead_percent=args.max_evaluation_overhead_percent,
        max_trace_bytes=args.max_trace_bytes,
    )
    executable = args.executable.absolute()
    trace_processor = args.trace_processor.absolute()
    workspace = args.workspace.absolute()
    output = args.out.absolute()
    if directory_identity(output, label="trace-mode cohort output") is not None:
        raise ContractError("trace-mode cohort output directory already exists")
    _validate_trace_processor(trace_processor)
    build = executable_evidence(CORE_ROOT, executable, allow_unverified=False)
    load_profile(workspace, args.profile_id)
    if profile_identity_contract(workspace, args.profile_id) is None:
        raise ValueError(
            "trace-mode cohort requires a pinned profile identity contract"
        )
    output.mkdir(parents=True, exist_ok=False)
    output_identity = directory_identity(output, label="trace-mode cohort output")
    if output_identity is None:
        raise ContractError("trace-mode cohort output directory was not created")

    cohort_id = utc_stamp()
    publication = JsonPublicationCursor(
        output / "cohort.json",
        maximum=MAX_TRACE_COHORT_REPORT_BYTES,
        label="trace-mode cohort report",
    )
    runs: list[dict[str, Any]] = []
    completed = {"off": 0, "on": 0}

    def arm(mode: str) -> Callable[[], None]:
        def execute() -> None:
            completed[mode] += 1
            run = run_trial(
                executable=executable,
                trace_processor=trace_processor,
                workspace=workspace,
                profile_id=args.profile_id,
                trace_mode=mode,
                trace_scope=args.trace_scope,
                output=output
                / f"{len(runs) + 1:02d}-trace-{mode}-{completed[mode]:02d}",
                evaluator_selection=evaluator_selection,
            )
            runs.append(run)
            publication.publish(
                {
                    "schema": "browser-core.trace-mode-cohort-progress/1",
                    "cohort_id": cohort_id,
                    "build": build,
                    "runs": runs,
                },
            )

        return execute

    for trial in range(args.trials):
        schedule = (
            (arm("off"), arm("on")) if trial % 2 == 0 else (arm("on"), arm("off"))
        )
        for execute in schedule:
            execute()

    analysis = summarize_trace_mode_runs(
        runs,
        trials_per_arm=args.trials,
        max_launch_overhead_percent=args.max_launch_overhead_percent,
        max_evaluation_overhead_percent=args.max_evaluation_overhead_percent,
        max_trace_bytes=args.max_trace_bytes,
    )
    final = {
        **analysis,
        "cohort_id": cohort_id,
        "build": build,
        "profile_id": args.profile_id,
        "trace_scope": args.trace_scope,
        "evaluators": args.evaluators,
        "runs": runs,
    }
    final_body = publication.publish(final)
    if directory_identity(output, label="trace-mode cohort output") != output_identity:
        raise ContractError("trace-mode cohort output directory changed")
    sys.stdout.buffer.write(final_body)
    return 0 if final["passed"] else 1


if __name__ == "__main__":
    try:
        exit_code = main()
    except (ContractError, OSError, RuntimeError, ValueError) as exc:
        print(
            f"browser-core trace-mode cohort failed ({type(exc).__name__})",
            file=sys.stderr,
        )
        exit_code = 2
    raise SystemExit(exit_code)
