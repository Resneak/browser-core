from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from browser_core.contracts import ContractError
import scripts.run_stream_scope_cohort as scope_cohort
import scripts.run_stream_scope_gate as scope_gate
import scripts.run_stream_trace_mode_cohort as trace_mode_cohort


class _Parser:
    def __init__(self, args: SimpleNamespace) -> None:
        self._args = args

    def parse_args(self) -> SimpleNamespace:
        return self._args


def _base_args(tmp_path: Path) -> dict[str, object]:
    return {
        "executable": tmp_path / "missing-browser",
        "trace_processor": tmp_path / "missing-trace-processor",
        "workspace": tmp_path / "workspace",
        "out": tmp_path / "report",
        "reads": 8,
        "warmup_reads": 2,
        "timeout_seconds": 5.0,
    }


def _must_not_verify_build(*_args: object, **_kwargs: object) -> None:
    raise AssertionError("build verification must not run after failed preflight")


def test_scope_gate_rejects_trial_controls_before_build_or_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    args = SimpleNamespace(**{**_base_args(tmp_path), "reads": 0})
    monkeypatch.setattr(scope_gate, "_parser", lambda: _Parser(args))
    monkeypatch.setattr(scope_gate, "executable_evidence", _must_not_verify_build)

    with pytest.raises(ContractError, match="read bounds"):
        scope_gate.main()

    assert list(tmp_path.iterdir()) == []


def test_scope_cohort_rejects_trial_population_before_build_or_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    args = SimpleNamespace(
        **{
            **_base_args(tmp_path),
            "trials": 129,
            "max_added_overhead_percent": 10.0,
            "max_trace_bytes": 4096,
        }
    )
    monkeypatch.setattr(scope_cohort, "_parser", lambda: _Parser(args))
    monkeypatch.setattr(scope_cohort, "executable_evidence", _must_not_verify_build)

    with pytest.raises(ContractError, match="trial count"):
        scope_cohort.main()

    assert list(tmp_path.iterdir()) == []


def test_trace_mode_cohort_rejects_nonfinite_limit_before_build_or_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    args = SimpleNamespace(
        **{
            **_base_args(tmp_path),
            "trials": 2,
            "max_read_overhead_percent": float("nan"),
            "max_trace_bytes": 4096,
        }
    )
    monkeypatch.setattr(trace_mode_cohort, "_parser", lambda: _Parser(args))
    monkeypatch.setattr(
        trace_mode_cohort,
        "executable_evidence",
        _must_not_verify_build,
    )

    with pytest.raises(ContractError, match="cohort limits"):
        trace_mode_cohort.main()

    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize(
    ("module", "extra"),
    [
        (scope_gate, {}),
        (
            scope_cohort,
            {"trials": 2, "max_added_overhead_percent": 10.0, "max_trace_bytes": 4096},
        ),
        (
            trace_mode_cohort,
            {"trials": 2, "max_read_overhead_percent": 10.0, "max_trace_bytes": 4096},
        ),
    ],
)
def test_stream_scripts_require_exact_path_arguments_before_resolution(
    module: object,
    extra: dict[str, object],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    args = SimpleNamespace(**{**_base_args(tmp_path), **extra, "executable": "browser.exe"})
    monkeypatch.setattr(module, "_parser", lambda: _Parser(args))
    monkeypatch.setattr(module, "executable_evidence", _must_not_verify_build)
    with pytest.raises(ContractError, match="paths must be Paths"):
        module.main()
    assert list(tmp_path.iterdir()) == []


def test_scope_gate_rejects_empty_trace_processor_before_build(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    args = SimpleNamespace(**_base_args(tmp_path))
    args.trace_processor.write_bytes(b"")
    monkeypatch.setattr(scope_gate, "_parser", lambda: _Parser(args))
    monkeypatch.setattr(scope_gate, "executable_evidence", _must_not_verify_build)
    with pytest.raises(ContractError, match="trace processor is empty"):
        scope_gate.main()
    assert not args.out.exists()


def test_scope_gate_stdout_is_the_exact_retained_report(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsysbinary: pytest.CaptureFixture[bytes],
) -> None:
    args = SimpleNamespace(**_base_args(tmp_path))
    args.trace_processor.write_bytes(b"owned trace processor")
    monkeypatch.setattr(scope_gate, "_parser", lambda: _Parser(args))
    monkeypatch.setattr(
        scope_gate,
        "executable_evidence",
        lambda *_args, **_kwargs: {"revision": "1" * 40},
    )
    monkeypatch.setattr(
        scope_gate,
        "run_stream_calibration_trial",
        lambda config, root: {"trace_scope": config.trace_scope},
    )
    monkeypatch.setattr(
        scope_gate,
        "summarize_stream_scope_runs",
        lambda runs: {"schema": "owned", "passed": True, "arms": runs},
    )
    assert scope_gate.main() == 0
    captured = capsysbinary.readouterr()
    assert captured.out == args.out.read_bytes()
