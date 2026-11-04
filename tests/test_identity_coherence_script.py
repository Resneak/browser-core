from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

import scripts.run_identity_coherence_cohort as cohort
from browser_core.contracts import ContractError


_SESSION_RUN_ID = "owned-browser-run"


def _stopped_receipt() -> dict[str, object]:
    return {
        "run_id": _SESSION_RUN_ID,
        "state": "stopped",
        "running": False,
        "identity_protected": True,
    }


class _Parser:
    def __init__(self, args: SimpleNamespace) -> None:
        self.args = args

    def parse_args(self) -> SimpleNamespace:
        return self.args


def _args(tmp_path: Path, **changes: object) -> SimpleNamespace:
    values: dict[str, object] = {
        "workspace": tmp_path / "workspace",
        "repository_root": tmp_path / "repo",
        "out": tmp_path / "cohort",
        "executable": None,
        "profile_id": "eval-windows-native",
        "skip_primary": True,
        "max_personas": 0,
    }
    values.update(changes)
    return SimpleNamespace(**values)


def _metrics(**changes: object) -> dict[str, object]:
    checks = {
        **{f"owned-pass-{index:02d}": True for index in range(60)},
        "owned-missing": None,
        "owned-missing-2": None,
    }
    checkset = hashlib.sha256(
        json.dumps(sorted(checks), separators=(",", ":")).encode("utf-8")
    ).hexdigest()[:16]
    result: dict[str, object] = {
        "passed_checks": 60,
        "failed_checks": 0,
        "unavailable_checks": 2,
        "collector_checkset_sha256_16": checkset,
        "identity_passed_claims": 26,
        "identity_failed_claims": 0,
        "identity_unavailable_claims": 0,
        "identity_contract_sha256_16": "2" * 16,
        "render_fingerprint": "3" * 16,
        "surface_fingerprint": "4" * 16,
        "automation_fingerprint": "5" * 16,
        "checks": checks,
    }
    result.update(changes)
    return result


def _write_evaluator_run(
    root: Path, *, metrics: dict[str, object] | None = None
) -> Path:
    owned_metrics = metrics or _metrics()
    run_dir = root / "run-1"
    evaluator_dir = run_dir / "evaluators"
    evaluator_dir.mkdir(parents=True)
    (run_dir / "summary.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "kind": "browser_eval_summary",
                "run_id": "owned-run-1",
                "completed": 1,
                "failed": 0,
                "total": 1,
                "private": "not retained",
                "evaluators": [
                    {
                        "id": "controlled_coherence",
                        "status": "ok",
                        "verdict": "pass",
                        "signals": {
                            key: owned_metrics[key]
                            for key in (
                                "passed_checks",
                                "failed_checks",
                                "unavailable_checks",
                                "collector_checkset_sha256_16",
                                "identity_passed_claims",
                                "identity_failed_claims",
                                "identity_unavailable_claims",
                                "identity_contract_sha256_16",
                                "render_fingerprint",
                                "surface_fingerprint",
                                "automation_fingerprint",
                            )
                        },
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    (evaluator_dir / "controlled_coherence.json").write_text(
        json.dumps({"metrics": owned_metrics}),
        encoding="utf-8",
    )
    return run_dir


def _write_evaluator_run_with_return(
    root: Path, *, metrics: dict[str, object] | None = None
) -> tuple[Path, dict[str, object]]:
    run_dir = _write_evaluator_run(root, metrics=metrics)
    return run_dir, json.loads((run_dir / "summary.json").read_text(encoding="utf-8"))


def test_controlled_evaluation_dispatches_the_selected_specs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    specs = [SimpleNamespace(id="controlled_coherence")]
    expected = (tmp_path / "run", {"summary": True})
    monkeypatch.setattr(cohort, "load_registry", lambda _path: {"owned": True})
    monkeypatch.setattr(cohort, "select_specs", lambda registry, selection: specs)

    def execute(received_specs, config):
        assert received_specs is specs
        assert config.out == tmp_path / "out"
        return expected

    monkeypatch.setattr(cohort, "execute_run", execute)
    assert cohort._run_controlled_evaluation(tmp_path / "out") == expected


def test_identity_cohort_strict_file_rejects_exponent_overflow(tmp_path: Path) -> None:
    path = tmp_path / "summary.json"
    path.write_bytes(b'{"value":1e400}')
    with pytest.raises(ContractError, match="strict JSON"):
        cohort._strict_json_file(path, label="identity cohort summary")


def test_primary_cohort_stops_session_and_restores_environment_on_eval_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session_path = tmp_path / "session.json"
    stopped: list[Path] = []
    monkeypatch.setattr(
        cohort,
        "launch_evaluation",
        lambda *_args: (session_path, {"run_id": _SESSION_RUN_ID}),
    )
    monkeypatch.setattr(
        cohort,
        "_run_controlled_evaluation",
        lambda _output: (_ for _ in ()).throw(RuntimeError("owned evaluator failure")),
    )
    monkeypatch.setattr(
        cohort,
        "stop_session",
        lambda path, timeout_seconds: stopped.append(path) or _stopped_receipt(),
    )
    monkeypatch.setenv("BROWSER_CORE_SESSION_FILE", "prior-session")
    monkeypatch.setenv("BROWSER_EVAL_CDP_ENDPOINT", "prior-endpoint")

    with pytest.raises(RuntimeError, match="owned evaluator failure"):
        cohort.run_primary_browser_core(
            workspace=tmp_path,
            executable=tmp_path / "browser.exe",
            profile_id="owned-profile",
            out_dir=tmp_path / "out",
        )

    assert stopped == [session_path]
    assert os.environ["BROWSER_CORE_SESSION_FILE"] == "prior-session"
    assert os.environ["BROWSER_EVAL_CDP_ENDPOINT"] == "prior-endpoint"


def test_primary_cohort_reads_strict_bounded_results_from_owned_run(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session_path = tmp_path / "session.json"
    out = tmp_path / "out"
    stopped: list[Path] = []
    monkeypatch.setattr(
        cohort,
        "launch_evaluation",
        lambda *_args: (session_path, {"run_id": _SESSION_RUN_ID}),
    )

    def evaluate(output: Path):
        return _write_evaluator_run_with_return(output)

    monkeypatch.setattr(cohort, "_run_controlled_evaluation", evaluate)
    monkeypatch.setattr(
        cohort,
        "stop_session",
        lambda path, timeout_seconds: stopped.append(path) or _stopped_receipt(),
    )
    result = cohort.run_primary_browser_core(
        workspace=tmp_path,
        executable=tmp_path / "browser.exe",
        profile_id="owned-profile",
        out_dir=out,
    )
    assert result["coherence"]["passed_checks"] == 60
    assert result["identity"]["identity_failed_claims"] == 0
    assert result["failed_check_ids"] == []
    assert result["unavailable_check_ids"] == ["owned-missing", "owned-missing-2"]
    assert result["summary_receipt"] == {
        "schema_version": 1,
        "kind": "browser_eval_summary",
        "run_id": "owned-run-1",
        "status": "ok",
        "verdict": "pass",
        "completed": 1,
        "failed": 0,
        "total": 1,
    }
    assert stopped == [session_path]


def test_primary_cohort_rejects_saved_summary_changed_after_evaluation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    session_path = tmp_path / "session.json"
    stopped: list[Path] = []
    monkeypatch.setattr(
        cohort,
        "launch_evaluation",
        lambda *_args: (session_path, {"run_id": _SESSION_RUN_ID}),
    )

    def evaluate(output: Path):
        run_dir, returned = _write_evaluator_run_with_return(output)
        summary_path = run_dir / "summary.json"
        saved = json.loads(summary_path.read_text(encoding="utf-8"))
        saved["private"] = "changed after evaluation"
        summary_path.write_text(json.dumps(saved), encoding="utf-8")
        return run_dir, returned

    monkeypatch.setattr(cohort, "_run_controlled_evaluation", evaluate)
    monkeypatch.setattr(
        cohort,
        "stop_session",
        lambda path, timeout_seconds: stopped.append(path) or _stopped_receipt(),
    )
    with pytest.raises(ContractError, match="summary changed"):
        cohort.run_primary_browser_core(
            workspace=tmp_path,
            executable=tmp_path / "browser.exe",
            profile_id="owned-profile",
            out_dir=tmp_path / "out",
        )
    assert stopped == [session_path]


@pytest.mark.parametrize(
    "checks",
    [
        {"owned-pass": False, "owned-missing": None},
        None,
    ],
)
def test_primary_cohort_rejects_check_counts_disconnected_from_saved_rows(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, checks: object,
) -> None:
    session_path = tmp_path / "session.json"
    monkeypatch.setattr(
        cohort,
        "launch_evaluation",
        lambda *_args: (session_path, {"run_id": _SESSION_RUN_ID}),
    )
    monkeypatch.setattr(
        cohort,
        "_run_controlled_evaluation",
        lambda output: _write_evaluator_run_with_return(output, metrics=_metrics(checks=checks)),
    )
    monkeypatch.setattr(cohort, "stop_session", lambda *_args, **_kwargs: _stopped_receipt())
    with pytest.raises(ContractError, match="checks are"):
        cohort.run_primary_browser_core(
            workspace=tmp_path,
            executable=tmp_path / "browser.exe",
            profile_id="owned-profile",
            out_dir=tmp_path / "out",
        )


def test_primary_cohort_rejects_checkset_digest_disconnected_from_saved_names(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    session_path = tmp_path / "session.json"
    monkeypatch.setattr(
        cohort,
        "launch_evaluation",
        lambda *_args: (session_path, {"run_id": _SESSION_RUN_ID}),
    )
    monkeypatch.setattr(
        cohort,
        "_run_controlled_evaluation",
        lambda output: _write_evaluator_run_with_return(
            output, metrics=_metrics(collector_checkset_sha256_16="f" * 16)
        ),
    )
    monkeypatch.setattr(cohort, "stop_session", lambda *_args, **_kwargs: _stopped_receipt())
    with pytest.raises(ContractError, match="checks are inconsistent"):
        cohort.run_primary_browser_core(
            workspace=tmp_path,
            executable=tmp_path / "browser.exe",
            profile_id="owned-profile",
            out_dir=tmp_path / "out",
        )


@pytest.mark.parametrize("field", ["identity_failed_claims", "identity_unavailable_claims"])
def test_primary_cohort_rejects_pass_verdict_with_identity_failures(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, field: str,
) -> None:
    session_path = tmp_path / "session.json"
    monkeypatch.setattr(
        cohort,
        "launch_evaluation",
        lambda *_args: (session_path, {"run_id": _SESSION_RUN_ID}),
    )
    monkeypatch.setattr(
        cohort,
        "_run_controlled_evaluation",
        lambda output: _write_evaluator_run_with_return(output, metrics=_metrics(**{field: 1})),
    )
    monkeypatch.setattr(cohort, "stop_session", lambda *_args, **_kwargs: _stopped_receipt())
    with pytest.raises(ContractError, match="pass verdict"):
        cohort.run_primary_browser_core(
            workspace=tmp_path,
            executable=tmp_path / "browser.exe",
            profile_id="owned-profile",
            out_dir=tmp_path / "out",
        )


def test_primary_cohort_rejects_active_stop_before_returning_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session_path = tmp_path / "session.json"
    monkeypatch.setattr(
        cohort,
        "launch_evaluation",
        lambda *_args: (session_path, {"run_id": _SESSION_RUN_ID}),
    )
    monkeypatch.setattr(
        cohort,
        "_run_controlled_evaluation",
        lambda output: (_write_evaluator_run(output), {}),
    )
    monkeypatch.setattr(
        cohort,
        "stop_session",
        lambda *_args, **_kwargs: {
            **_stopped_receipt(),
            "state": "active",
            "running": True,
        },
    )
    monkeypatch.setenv("BROWSER_CORE_SESSION_FILE", "prior-session")
    with pytest.raises(ContractError, match="stop was not verified"):
        cohort.run_primary_browser_core(
            workspace=tmp_path,
            executable=tmp_path / "browser.exe",
            profile_id="owned-profile",
            out_dir=tmp_path / "out",
        )
    assert os.environ["BROWSER_CORE_SESSION_FILE"] == "prior-session"


def test_primary_cohort_rejects_escaped_run_directory_and_still_stops(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session_path = tmp_path / "session.json"
    stopped: list[Path] = []
    monkeypatch.setattr(
        cohort,
        "launch_evaluation",
        lambda *_args: (session_path, {"run_id": _SESSION_RUN_ID}),
    )
    monkeypatch.setattr(
        cohort,
        "_run_controlled_evaluation",
        lambda _output: (tmp_path / "escaped", {}),
    )
    monkeypatch.setattr(
        cohort,
        "stop_session",
        lambda path, timeout_seconds: stopped.append(path) or _stopped_receipt(),
    )
    with pytest.raises(ContractError, match="escaped"):
        cohort.run_primary_browser_core(
            workspace=tmp_path,
            executable=tmp_path / "browser.exe",
            profile_id="owned-profile",
            out_dir=tmp_path / "out",
        )
    assert stopped == [session_path]


def test_primary_cohort_rejects_boolean_counts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session_path = tmp_path / "session.json"
    monkeypatch.setattr(
        cohort,
        "launch_evaluation",
        lambda *_args: (session_path, {"run_id": _SESSION_RUN_ID}),
    )
    monkeypatch.setattr(
        cohort,
        "_run_controlled_evaluation",
        lambda output: _write_evaluator_run_with_return(
            output, metrics=_metrics(identity_failed_claims=False)
        ),
    )
    monkeypatch.setattr(
        cohort,
        "stop_session",
        lambda *_args, **_kwargs: _stopped_receipt(),
    )
    with pytest.raises(ContractError, match="metrics"):
        cohort.run_primary_browser_core(
            workspace=tmp_path,
            executable=tmp_path / "browser.exe",
            profile_id="owned-profile",
            out_dir=tmp_path / "out",
        )


def test_primary_cohort_rejects_summary_evaluator_disagreement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session_path = tmp_path / "session.json"
    monkeypatch.setattr(
        cohort,
        "launch_evaluation",
        lambda *_args: (session_path, {"run_id": _SESSION_RUN_ID}),
    )

    def evaluate(output: Path):
        run_dir = _write_evaluator_run(output)
        summary_path = run_dir / "summary.json"
        summary = json.loads(summary_path.read_text(encoding="utf-8"))
        summary["evaluators"][0]["signals"]["passed_checks"] = 59
        summary_path.write_text(json.dumps(summary), encoding="utf-8")
        return run_dir, summary

    monkeypatch.setattr(cohort, "_run_controlled_evaluation", evaluate)
    monkeypatch.setattr(
        cohort,
        "stop_session",
        lambda *_args, **_kwargs: _stopped_receipt(),
    )
    with pytest.raises(ContractError, match="disagree"):
        cohort.run_primary_browser_core(
            workspace=tmp_path,
            executable=tmp_path / "browser.exe",
            profile_id="owned-profile",
            out_dir=tmp_path / "out",
        )


def test_identity_cohort_invalid_controls_fail_before_output_or_persona_contact(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    args = _args(tmp_path, max_personas=257)
    monkeypatch.setattr(cohort, "_parser", lambda: _Parser(args))
    monkeypatch.setattr(
        cohort,
        "list_personas",
        lambda _workspace: pytest.fail("invalid controls reached persona contact"),
    )
    with pytest.raises(ContractError, match="controls"):
        cohort.main()
    assert not args.out.exists()


def test_identity_cohort_refuses_existing_output_before_persona_contact(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    args = _args(tmp_path)
    args.out.mkdir(parents=True)
    monkeypatch.setattr(cohort, "_parser", lambda: _Parser(args))
    monkeypatch.setattr(
        cohort,
        "list_personas",
        lambda _workspace: pytest.fail("existing output reached persona contact"),
    )
    with pytest.raises(ContractError, match="already exists"):
        cohort.main()


def test_identity_cohort_report_publication_preserves_a_racer(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    args = _args(tmp_path)
    monkeypatch.setattr(cohort, "_parser", lambda: _Parser(args))
    personas = [{"id": f"persona-{index}"} for index in range(4)]
    monkeypatch.setattr(cohort, "list_personas", lambda _workspace: personas)
    monkeypatch.setattr(
        cohort,
        "evaluate_from_evidence",
        lambda workspace, repo, persona: {
            "id": persona["id"],
            "arm": "fixture",
            "identity_failed_claims": 0,
            "identity_unavailable_claims": 0,
        },
    )
    real_publish = cohort.publish_json_exclusive_result
    foreign = b"foreign cohort report"

    def racing_publish(path: Path, document: dict, **kwargs):
        path.write_bytes(foreign)
        return real_publish(path, document, **kwargs)

    monkeypatch.setattr(cohort, "publish_json_exclusive_result", racing_publish)
    with pytest.raises(ContractError):
        cohort.main()
    assert (args.out / "identity-coherence-cohort.json").read_bytes() == foreign
