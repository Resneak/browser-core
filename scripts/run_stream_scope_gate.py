from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path


CORE_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(CORE_ROOT))

from browser_core.build import executable_evidence  # noqa: E402
from browser_core.control_files import JsonPublicationCursor  # noqa: E402
from browser_core.contracts import ContractError  # noqa: E402
from browser_core.perfetto import validate_trace_processor  # noqa: E402
from browser_core.stream_calibration import (  # noqa: E402
    MAX_STREAM_REPORT_BYTES,
    StreamCalibrationTrial,
    run_stream_calibration_trial,
    summarize_stream_scope_runs,
    validate_stream_calibration_trial_config,
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Prove that causal tracing leaves Browser Core stream hooks disabled "
            "while causal-stream retains exact reader evidence"
        )
    )
    parser.add_argument("--executable", type=Path, required=True)
    parser.add_argument("--trace-processor", type=Path, required=True)
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--reads", type=int, default=128)
    parser.add_argument("--warmup-reads", type=int, default=8)
    parser.add_argument("--timeout-seconds", type=float, default=45.0)
    return parser


def main() -> int:
    args = _parser().parse_args()
    if not all(
        isinstance(path, Path)
        for path in (args.executable, args.trace_processor, args.workspace, args.out)
    ):
        raise ContractError("stream scope gate paths must be Paths")
    executable = args.executable.absolute()
    trace_processor = args.trace_processor.absolute()
    workspace = args.workspace.absolute()
    output = args.out.absolute()
    configs = {
        scope: StreamCalibrationTrial(
            executable=executable,
            trace_processor=trace_processor,
            workspace=workspace,
            trace_mode="on",
            trace_scope=scope,
            reads=args.reads,
            warmup_reads=args.warmup_reads,
            timeout_seconds=args.timeout_seconds,
        )
        for scope in ("causal", "causal-stream")
    }
    for config in configs.values():
        validate_stream_calibration_trial_config(config, CORE_ROOT)
    if os.path.lexists(output):
        raise ContractError("stream scope gate output already exists")
    validate_trace_processor(trace_processor)
    build = executable_evidence(CORE_ROOT, executable, allow_unverified=False)
    runs = {}
    for scope, config in configs.items():
        runs[scope] = run_stream_calibration_trial(config, CORE_ROOT)
    report = {**summarize_stream_scope_runs(runs), "build": build}
    output.parent.mkdir(parents=True, exist_ok=True)
    final_body = JsonPublicationCursor(
        output,
        maximum=MAX_STREAM_REPORT_BYTES,
        label="stream scope gate report",
    ).publish(
        report
    )
    sys.stdout.buffer.write(final_body)
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    try:
        status = main()
    except (OSError, ValueError) as exc:
        print(f"browser-core stream scope gate: {exc}", file=sys.stderr)
        status = 2
    raise SystemExit(status)
