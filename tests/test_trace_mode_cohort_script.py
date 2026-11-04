from __future__ import annotations

import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

import scripts.run_trace_mode_cohort as cohort_script
from browser_core.contracts import ContractError


class _Parser:
    def __init__(self, args: SimpleNamespace) -> None:
        self.args = args

    def parse_args(self) -> SimpleNamespace:
        return self.args


def _args(tmp_path: Path, **changes: object) -> SimpleNamespace:
    trace_processor = tmp_path / "trace_processor.exe"
    trace_processor.write_bytes(b"processor")
    values: dict[str, object] = {
        "executable": tmp_path / "browser.exe",
        "trace_processor": trace_processor,
        "workspace": tmp_path / "workspace",
        "profile_id": "owned-profile",
        "out": tmp_path / "cohort",
        "trials": 2,
        "evaluators": "controlled_coherence",
        "trace_scope": "broad",
        "max_launch_overhead_percent": 30.0,
        "max_evaluation_overhead_percent": 20.0,
        "max_trace_bytes": 5 * 1024 * 1024,
    }
    values.update(changes)
    return SimpleNamespace(**values)


def _summary() -> dict[str, object]:
    return {
        "evaluators": [
            {
                "id": "controlled_coherence",
                "status": "ok",
                "verdict": "pass",
                "signals": {
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
        ]
    }


def _write_summary(output: Path) -> Path:
    run_dir = output / "run-1"
    run_dir.mkdir(parents=True)
    (run_dir / "summary.json").write_text(json.dumps(_summary()), encoding="utf-8")
    return run_dir


def _session(tmp_path: Path, *, mode: str) -> tuple[Path, dict[str, object]]:
    session_path = tmp_path / f"session-{mode}.json"
    return session_path, {
        "run_id": f"owned-{mode}",
        "chromium_revision": "1" * 40,
        "trace_scope": "broad" if mode == "on" else None,
        "trace_path": str(tmp_path / "owned.perfetto-trace") if mode == "on" else None,
    }


def _stopped_receipt(run_id: object) -> dict[str, object]:
    return {
        "run_id": run_id,
        "state": "stopped",
        "running": False,
        "identity_protected": True,
    }


def test_trace_cohort_strict_file_rejects_exponent_overflow(tmp_path: Path) -> None:
    path = tmp_path / "summary.json"
    path.write_bytes(b'{"value":1e400}')
    with pytest.raises(ContractError, match="strict JSON"):
        cohort_script._strict_json_file(path, label="trace cohort summary")


def test_trace_mode_result_vector_accepts_typed_controlled_summary() -> None:
    vector = cohort_script.result_vector(_summary())
    assert vector["verdict"] == "pass"
    assert vector["passed_checks"] == 60
    assert vector["identity_contract_sha256_16"] == "b" * 16


@pytest.mark.parametrize("status", ["error", "skipped", None, True])
def test_trace_mode_result_vector_rejects_noncompleted_controlled_result(status: object) -> None:
    summary = _summary()
    summary["evaluators"][0]["status"] = status
    with pytest.raises(ContractError, match="controlled evaluator result"):
        cohort_script.result_vector(summary)


@pytest.mark.parametrize("field", ["failed_checks", "identity_failed_claims", "identity_unavailable_claims"])
def test_trace_mode_result_vector_rejects_pass_with_failed_or_missing_claims(field: str) -> None:
    summary = _summary()
    summary["evaluators"][0]["signals"][field] = 1
    with pytest.raises(ContractError, match="controlled evaluator signals"):
        cohort_script.result_vector(summary)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("passed_checks", True),
        ("failed_checks", -1),
        ("unavailable_checks", 1_000_001),
        ("identity_passed_claims", 0),
        ("identity_failed_claims", 0.0),
        ("collector_checkset_sha256_16", "A" * 16),
        ("identity_contract_sha256_16", "not-a-digest"),
        ("render_fingerprint", 123),
    ],
)
def test_trace_mode_result_vector_rejects_malformed_claim_signal(
    field: str,
    value: object,
) -> None:
    summary = _summary()
    summary["evaluators"][0]["signals"][field] = value
    with pytest.raises(ContractError, match="signals are invalid"):
        cohort_script.result_vector(summary)


def test_trace_mode_main_rejects_invalid_controls_before_build_or_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    args = _args(tmp_path, max_launch_overhead_percent=float("nan"))
    monkeypatch.setattr(cohort_script, "parser", lambda: _Parser(args))
    monkeypatch.setattr(
        cohort_script,
        "executable_evidence",
        lambda *_args, **_kwargs: pytest.fail(
            "invalid controls reached build inspection"
        ),
    )
    with pytest.raises(ContractError, match="finite"):
        cohort_script.main()
    assert not args.out.exists()


def test_trace_mode_main_refuses_existing_output_before_build(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    args = _args(tmp_path)
    args.out.mkdir()
    monkeypatch.setattr(cohort_script, "parser", lambda: _Parser(args))
    monkeypatch.setattr(
        cohort_script,
        "executable_evidence",
        lambda *_args, **_kwargs: pytest.fail(
            "existing output reached build inspection"
        ),
    )
    with pytest.raises(ContractError, match="already exists"):
        cohort_script.main()


def test_trace_mode_trial_stops_and_restores_environment_on_eval_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session_path, session = _session(tmp_path, mode="off")
    stopped: list[Path] = []
    monkeypatch.setattr(
        cohort_script,
        "launch_evaluation",
        lambda *_args, **_kwargs: (session_path, session),
    )
    monkeypatch.setattr(
        cohort_script,
        "evaluator_run",
        lambda *_args: (_ for _ in ()).throw(RuntimeError("owned eval failure")),
    )
    monkeypatch.setattr(
        cohort_script,
        "stop_session",
        lambda path, timeout_seconds: stopped.append(path)
        or _stopped_receipt(session["run_id"]),
    )
    monkeypatch.setenv("BROWSER_CORE_SESSION_FILE", "prior-session")
    monkeypatch.setenv("BROWSER_EVAL_CDP_ENDPOINT", "prior-endpoint")
    with pytest.raises(RuntimeError, match="owned eval failure"):
        cohort_script.run_trial(
            executable=tmp_path / "browser.exe",
            trace_processor=tmp_path / "processor.exe",
            workspace=tmp_path,
            profile_id="owned-profile",
            trace_mode="off",
            trace_scope="broad",
            output=tmp_path / "eval",
            evaluator_selection="controlled_coherence",
        )
    assert stopped == [session_path]
    assert os.environ["BROWSER_CORE_SESSION_FILE"] == "prior-session"
    assert os.environ["BROWSER_EVAL_CDP_ENDPOINT"] == "prior-endpoint"


def test_trace_mode_trial_rejects_saved_summary_changed_after_evaluation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    session_path, session = _session(tmp_path, mode="off")
    returned = _summary()
    returned["evaluators"][0]["verdict"] = "fail"
    stopped: list[Path] = []
    monkeypatch.setattr(
        cohort_script,
        "launch_evaluation",
        lambda *_args, **_kwargs: (session_path, session),
    )
    monkeypatch.setattr(
        cohort_script,
        "evaluator_run",
        lambda output, selection: (_write_summary(output), returned),
    )
    monkeypatch.setattr(
        cohort_script,
        "stop_session",
        lambda path, timeout_seconds: stopped.append(path)
        or _stopped_receipt(session["run_id"]),
    )
    with pytest.raises(ContractError, match="summary changed"):
        cohort_script.run_trial(
            executable=tmp_path / "browser.exe",
            trace_processor=tmp_path / "processor.exe",
            workspace=tmp_path,
            profile_id="owned-profile",
            trace_mode="off",
            trace_scope="broad",
            output=tmp_path / "eval",
            evaluator_selection="controlled_coherence",
        )
    assert stopped == [session_path]


def test_trace_mode_trial_restores_environment_when_stop_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session_path, session = _session(tmp_path, mode="off")
    monkeypatch.setattr(
        cohort_script,
        "launch_evaluation",
        lambda *_args, **_kwargs: (session_path, session),
    )
    monkeypatch.setattr(
        cohort_script,
        "evaluator_run",
        lambda output, selection: (_write_summary(output), _summary()),
    )
    monkeypatch.setattr(
        cohort_script,
        "stop_session",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            ContractError("owned stop failure")
        ),
    )
    monkeypatch.delenv("BROWSER_CORE_SESSION_FILE", raising=False)
    monkeypatch.delenv("BROWSER_EVAL_CDP_ENDPOINT", raising=False)
    with pytest.raises(ContractError, match="owned stop failure"):
        cohort_script.run_trial(
            executable=tmp_path / "browser.exe",
            trace_processor=tmp_path / "processor.exe",
            workspace=tmp_path,
            profile_id="owned-profile",
            trace_mode="off",
            trace_scope="broad",
            output=tmp_path / "eval",
            evaluator_selection="controlled_coherence",
        )
    assert "BROWSER_CORE_SESSION_FILE" not in os.environ
    assert "BROWSER_EVAL_CDP_ENDPOINT" not in os.environ


def test_trace_mode_trial_uses_export_binding_for_trace_size(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session_path, session = _session(tmp_path, mode="on")
    monkeypatch.setattr(
        cohort_script,
        "launch_evaluation",
        lambda *_args, **_kwargs: (session_path, session),
    )
    monkeypatch.setattr(
        cohort_script,
        "evaluator_run",
        lambda output, selection: (_write_summary(output), _summary()),
    )
    monkeypatch.setattr(
        cohort_script,
        "stop_session",
        lambda *_args, **_kwargs: _stopped_receipt(session["run_id"]),
    )
    monkeypatch.setattr(
        cohort_script,
        "export_perfetto",
        lambda *_args, **_kwargs: {
            "report": {"source_trace": {"bytes": 4321}},
        },
    )
    monkeypatch.setattr(
        cohort_script,
        "summarize",
        lambda _path: {"events": 8, "dropped_events": 0},
    )
    result = cohort_script.run_trial(
        executable=tmp_path / "browser.exe",
        trace_processor=tmp_path / "processor.exe",
        workspace=tmp_path,
        profile_id="owned-profile",
        trace_mode="on",
        trace_scope="broad",
        output=tmp_path / "eval",
        evaluator_selection="controlled_coherence",
    )
    assert result["trace_bytes"] == 4321


def test_trace_mode_active_stop_blocks_trace_export(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session_path, session = _session(tmp_path, mode="on")
    monkeypatch.setattr(
        cohort_script,
        "launch_evaluation",
        lambda *_args, **_kwargs: (session_path, session),
    )
    monkeypatch.setattr(
        cohort_script,
        "evaluator_run",
        lambda output, selection: (_write_summary(output), _summary()),
    )
    monkeypatch.setattr(
        cohort_script,
        "stop_session",
        lambda *_args, **_kwargs: {
            **_stopped_receipt(session["run_id"]),
            "state": "active",
            "running": True,
        },
    )
    monkeypatch.setattr(
        cohort_script,
        "export_perfetto",
        lambda *_args, **_kwargs: pytest.fail("active producer reached trace export"),
    )
    with pytest.raises(ContractError, match="stop was not verified"):
        cohort_script.run_trial(
            executable=tmp_path / "browser.exe",
            trace_processor=tmp_path / "processor.exe",
            workspace=tmp_path,
            profile_id="owned-profile",
            trace_mode="on",
            trace_scope="broad",
            output=tmp_path / "eval",
            evaluator_selection="controlled_coherence",
        )


def test_trace_mode_progress_cursor_preserves_competing_replacement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    args = _args(tmp_path)
    monkeypatch.setattr(cohort_script, "parser", lambda: _Parser(args))
    monkeypatch.setattr(
        cohort_script,
        "executable_evidence",
        lambda *_args, **_kwargs: {"revision": "1" * 40},
    )
    monkeypatch.setattr(cohort_script, "load_profile", lambda *_args: {})
    monkeypatch.setattr(
        cohort_script, "profile_identity_contract", lambda *_args: {"fields": []}
    )
    calls = 0
    foreign = b"foreign cohort progress"

    def trial(**kwargs):
        nonlocal calls
        calls += 1
        if calls == 2:
            (args.out / "cohort.json").write_bytes(foreign)
        return {"run": calls}

    monkeypatch.setattr(cohort_script, "run_trial", trial)
    with pytest.raises(ContractError, match="changed"):
        cohort_script.main()
    assert (args.out / "cohort.json").read_bytes() == foreign


def test_trace_mode_finalization_detects_output_directory_replacement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    args = _args(tmp_path)
    monkeypatch.setattr(cohort_script, "parser", lambda: _Parser(args))
    identities = iter([None, (1, 2, 3, 0), (1, 9, 3, 0)])
    monkeypatch.setattr(
        cohort_script,
        "directory_identity",
        lambda *_args, **_kwargs: next(identities),
    )
    monkeypatch.setattr(
        cohort_script,
        "executable_evidence",
        lambda *_args, **_kwargs: {"revision": "1" * 40},
    )
    monkeypatch.setattr(cohort_script, "load_profile", lambda *_args: {})
    monkeypatch.setattr(
        cohort_script, "profile_identity_contract", lambda *_args: {"fields": []}
    )
    monkeypatch.setattr(
        cohort_script, "run_trial", lambda **kwargs: {"mode": kwargs["trace_mode"]}
    )
    monkeypatch.setattr(
        cohort_script,
        "summarize_trace_mode_runs",
        lambda *_args, **_kwargs: {"schema": "owned", "passed": True},
    )
    with pytest.raises(ContractError, match="output directory changed"):
        cohort_script.main()
