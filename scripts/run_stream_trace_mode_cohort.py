from __future__ import annotations

import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


CORE_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(CORE_ROOT))

from browser_core.build import executable_evidence  # noqa: E402
from browser_core.control_files import JsonPublicationCursor  # noqa: E402
from browser_core.contracts import ContractError  # noqa: E402
from browser_core.owned_paths import directory_identity  # noqa: E402
from browser_core.perfetto import validate_trace_processor  # noqa: E402
from browser_core.stream_calibration import (  # noqa: E402
    COHORT_SCHEMA,
    MAX_STREAM_REPORT_BYTES,
    StreamCalibrationTrial,
    run_stream_calibration_trial,
    summarize_stream_trace_mode_runs,
    validate_stream_calibration_trial_config,
    validate_stream_cohort_controls,
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Run paired tracing-off/on default and BYOB reader calibration "
            "against an owned loopback fixture"
        )
    )
    parser.add_argument("--executable", type=Path, required=True)
    parser.add_argument("--trace-processor", type=Path, required=True)
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--trials", type=int, default=5, help="trials per arm")
    parser.add_argument("--reads", type=int, default=1024)
    parser.add_argument("--warmup-reads", type=int, default=32)
    parser.add_argument("--timeout-seconds", type=float, default=45.0)
    parser.add_argument("--max-read-overhead-percent", type=float, default=200.0)
    parser.add_argument("--max-trace-bytes", type=int, default=5 * 1024 * 1024)
    return parser


def main() -> int:
    args = _parser().parse_args()
    if not all(
        isinstance(path, Path)
        for path in (args.executable, args.trace_processor, args.workspace, args.out)
    ):
        raise ContractError("stream trace-mode cohort paths must be Paths")
    executable = args.executable.absolute()
    trace_processor = args.trace_processor.absolute()
    workspace = args.workspace.absolute()
    output = args.out.absolute()
    validate_stream_cohort_controls(
        trials_per_arm=args.trials,
        maximum_overhead_percent=args.max_read_overhead_percent,
        max_trace_bytes=args.max_trace_bytes,
    )
    configs = {
        mode: StreamCalibrationTrial(
            executable=executable,
            trace_processor=trace_processor,
            workspace=workspace,
            trace_mode=mode,
            reads=args.reads,
            warmup_reads=args.warmup_reads,
            timeout_seconds=args.timeout_seconds,
        )
        for mode in ("off", "on")
    }
    for config in configs.values():
        validate_stream_calibration_trial_config(config, CORE_ROOT)
    validate_trace_processor(trace_processor)
    if directory_identity(output, label="stream trace-mode cohort output") is not None:
        raise ContractError("stream trace-mode cohort output directory already exists")
    build = executable_evidence(CORE_ROOT, executable, allow_unverified=False)
    output.mkdir(parents=True, exist_ok=False)
    output_identity = directory_identity(output, label="stream trace-mode cohort output")
    if output_identity is None:
        raise ContractError("stream trace-mode cohort output directory was not created")
    publisher = JsonPublicationCursor(
        output / "cohort.json",
        maximum=MAX_STREAM_REPORT_BYTES,
        label="stream trace-mode cohort report",
    )
    cohort_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    runs: list[dict[str, Any]] = []

    for pair_index in range(args.trials):
        schedule = ("off", "on") if pair_index % 2 == 0 else ("on", "off")
        for position, mode in enumerate(schedule):
            run = run_stream_calibration_trial(configs[mode], CORE_ROOT)
            run.update({"pair_index": pair_index, "position": position})
            runs.append(run)
            publisher.publish(
                {
                    "schema": "browser-core.stream-trace-mode-cohort-progress/1",
                    "cohort_id": cohort_id,
                    "build": build,
                    "runs": runs,
                },
            )

    analysis = summarize_stream_trace_mode_runs(
        runs,
        trials_per_arm=args.trials,
        max_read_overhead_percent=args.max_read_overhead_percent,
        max_trace_bytes=args.max_trace_bytes,
    )
    final = {
        **analysis,
        "schema": COHORT_SCHEMA,
        "cohort_id": cohort_id,
        "build": build,
        "reads": args.reads,
        "warmup_reads": args.warmup_reads,
        "runs": runs,
    }
    final_body = publisher.publish(final)
    if directory_identity(output, label="stream trace-mode cohort output") != output_identity:
        raise ContractError("stream trace-mode cohort output directory changed")
    sys.stdout.buffer.write(final_body)
    return 0 if final["passed"] else 1


if __name__ == "__main__":
    try:
        status = main()
    except (OSError, ValueError) as exc:
        print(f"browser-core stream trace-mode cohort: {exc}", file=sys.stderr)
        status = 2
    raise SystemExit(status)
