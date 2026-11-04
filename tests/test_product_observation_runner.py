"""Runner-level honesty gates that unit tests of one observation cannot cover."""

from __future__ import annotations

import json

import pytest

from browser_core import product_observation
from scripts import run_product_script_observation as runner


def _sealed_observation(**fields):
    label = fields.get("label", "fixture")
    payload = b"runner observation fixture"
    identity = product_observation.classify_product_script(payload)
    return product_observation._seal_observation_document(
        {
            "schema": "browser-core.product-script-observation/1",
            "generated_at": "2026-08-12T01:02:03Z",
            "script_sha256_16": identity["signals"]["sha256_16"],
            "script_bytes": len(payload),
            "script_identity": identity,
            "source_provenance": {
                "status": "not_supplied",
                "note": "no public source URL pin was supplied",
            },
            "provenance": {
                "status": "not_checked",
                "note": "no capture tree was supplied",
                "asserted_label": label,
            },
            **fields,
        }
    )


def test_trace_scope_help_states_the_measured_surface_volume_tradeoff(capsys) -> None:
    with pytest.raises(SystemExit) as exc:
        runner.main(["--help"])

    assert exc.value.code == 0
    help_text = " ".join(capsys.readouterr().out.split())
    assert "Anubis pure-JS" in help_text
    assert "117.7 MB" in help_text
    assert "5.7 KB" in help_text


@pytest.mark.parametrize("label", ["../escape", "with space", "control"])
def test_runner_rejects_unsafe_or_reserved_labels_before_launch(
    tmp_path, monkeypatch, label
) -> None:
    sample = tmp_path / "collector.js"
    sample.write_text("collector", encoding="utf-8")
    out = tmp_path / "out"
    monkeypatch.setattr(
        runner,
        "run_product_script_observation",
        lambda *_args, **_kwargs: pytest.fail("browser launch must not occur"),
    )

    with pytest.raises(SystemExit) as exc:
        runner.main(
            [
                "--script",
                str(sample),
                "--label",
                label,
                "--executable",
                str(tmp_path / "chrome.exe"),
                "--trace-processor",
                str(tmp_path / "trace_processor.exe"),
                "--workspace",
                str(tmp_path),
                "--out",
                str(out),
            ]
        )

    assert exc.value.code == 2
    assert not out.exists()


def test_runner_rejects_colliding_retry_namespace_before_launch(
    tmp_path, monkeypatch
) -> None:
    sample = tmp_path / "collector.js"
    sample.write_text("collector", encoding="utf-8")
    out = tmp_path / "out"
    monkeypatch.setattr(
        runner,
        "run_product_script_observation",
        lambda *_args, **_kwargs: pytest.fail("browser launch must not occur"),
    )

    with pytest.raises(SystemExit) as exc:
        runner.main(
            [
                "--script",
                str(sample),
                "--label",
                "pin",
                "--script",
                str(sample),
                "--label",
                "pin-retry1",
                "--retry-failed",
                "1",
                "--executable",
                str(tmp_path / "chrome.exe"),
                "--trace-processor",
                str(tmp_path / "trace_processor.exe"),
                "--workspace",
                str(tmp_path),
                "--out",
                str(out),
            ]
        )

    assert exc.value.code == 2
    assert not out.exists()


def test_runner_refuses_existing_output_without_overwriting_control_source(
    tmp_path, monkeypatch
) -> None:
    sample = tmp_path / "collector.js"
    sample.write_text("collector", encoding="utf-8")
    out = tmp_path / "out"
    out.mkdir()
    control = out / "control-source.js"
    control.write_bytes(b"foreign-control-bytes")
    monkeypatch.setattr(
        runner,
        "classify_product_script",
        lambda _payload: {"looks_like_built_antibot_script": True, "reasons": []},
    )
    monkeypatch.setattr(
        runner,
        "run_product_script_observation",
        lambda *_args, **_kwargs: pytest.fail("existing output reached browser launch"),
    )

    with pytest.raises(runner.ContractError, match="already exists"):
        runner.main(
            [
                "--script",
                str(sample),
                "--label",
                "pin",
                "--executable",
                str(tmp_path / "chrome.exe"),
                "--trace-processor",
                str(tmp_path / "trace_processor.exe"),
                "--workspace",
                str(tmp_path),
                "--out",
                str(out),
            ]
        )

    assert control.read_bytes() == b"foreign-control-bytes"


def test_runner_rejects_invalid_repeat_before_launch(tmp_path, monkeypatch) -> None:
    sample = tmp_path / "collector.js"
    sample.write_text("collector", encoding="utf-8")
    out = tmp_path / "out"
    monkeypatch.setattr(
        runner,
        "run_product_script_observation",
        lambda *_args, **_kwargs: pytest.fail("browser launch must not occur"),
    )

    with pytest.raises(SystemExit) as exc:
        runner.main(
            [
                "--script",
                str(sample),
                "--label",
                "pin",
                "--repeat",
                "0",
                "--executable",
                str(tmp_path / "chrome.exe"),
                "--trace-processor",
                str(tmp_path / "trace_processor.exe"),
                "--workspace",
                str(tmp_path),
                "--out",
                str(out),
            ]
        )

    assert exc.value.code == 2
    assert not out.exists()


@pytest.mark.parametrize(
    ("flag", "value"),
    [
        ("--dwell-seconds", "nan"),
        ("--timeout-seconds", "0"),
        ("--await-ready-seconds", "inf"),
        ("--reloads", "-1"),
    ],
)
def test_runner_rejects_invalid_run_bounds_before_output_or_launch(
    tmp_path, monkeypatch, flag, value
) -> None:
    sample = tmp_path / "collector.js"
    sample.write_text("collector", encoding="utf-8")
    out = tmp_path / "out"
    monkeypatch.setattr(
        runner,
        "classify_product_script",
        lambda _payload: {"looks_like_built_antibot_script": True, "reasons": []},
    )
    monkeypatch.setattr(
        runner,
        "run_product_script_observation",
        lambda *_args, **_kwargs: pytest.fail("browser launch must not occur"),
    )

    with pytest.raises(runner.ContractError, match="finite number|reloads"):
        runner.main(
            [
                "--script",
                str(sample),
                "--label",
                "pin",
                flag,
                value,
                "--executable",
                str(tmp_path / "chrome.exe"),
                "--trace-processor",
                str(tmp_path / "trace_processor.exe"),
                "--workspace",
                str(tmp_path),
                "--out",
                str(out),
            ]
        )

    assert not out.exists()


def test_runner_rejects_duplicate_stage_prefixes_before_output_or_launch(
    tmp_path, monkeypatch
) -> None:
    sample = tmp_path / "collector.js"
    sample.write_text("collector", encoding="utf-8")
    stage_a = tmp_path / "stage-a.js"
    stage_b = tmp_path / "stage-b.js"
    stage_a.write_text("a", encoding="utf-8")
    stage_b.write_text("b", encoding="utf-8")
    out = tmp_path / "out"
    monkeypatch.setattr(
        runner,
        "classify_product_script",
        lambda _payload: {"looks_like_built_antibot_script": True, "reasons": []},
    )
    monkeypatch.setattr(
        runner,
        "run_product_script_observation",
        lambda *_args, **_kwargs: pytest.fail("browser launch must not occur"),
    )

    with pytest.raises(runner.ContractError, match="duplicate stage route prefix"):
        runner.main(
            [
                "--script",
                str(sample),
                "--label",
                "pin",
                "--stage",
                f"/worker={stage_a}",
                "--stage",
                f"/worker={stage_b}",
                "--executable",
                str(tmp_path / "chrome.exe"),
                "--trace-processor",
                str(tmp_path / "trace_processor.exe"),
                "--workspace",
                str(tmp_path),
                "--out",
                str(out),
            ]
        )

    assert not out.exists()


def test_public_source_pin_is_preflighted_before_control_launch(
    tmp_path, monkeypatch
) -> None:
    sample = tmp_path / "collector.js"
    sample.write_text("collector", encoding="utf-8")
    out = tmp_path / "out"
    monkeypatch.setattr(
        runner,
        "classify_product_script",
        lambda _payload: {"looks_like_built_antibot_script": True, "reasons": []},
    )
    monkeypatch.setattr(
        runner,
        "run_product_script_observation",
        lambda *_args, **_kwargs: pytest.fail("browser launch must not occur"),
    )

    with pytest.raises(runner.ContractError, match="SHA-256 mismatch"):
        runner.main(
            [
                "--script",
                str(sample),
                "--label",
                "pin",
                "--executable",
                str(tmp_path / "chrome.exe"),
                "--trace-processor",
                str(tmp_path / "trace_processor.exe"),
                "--workspace",
                str(tmp_path),
                "--out",
                str(out),
                "--source-url",
                "https://vendor.example/collector.js",
                "--source-retrieved-at",
                "2026-08-09T14:38:39.7189073-05:00",
                "--source-sha256",
                "0" * 64,
            ]
        )

    assert not out.exists()


def test_git_input_pin_is_preflighted_before_control_launch(
    tmp_path, monkeypatch
) -> None:
    sample = tmp_path / "collector.js"
    sample.write_text("collector", encoding="utf-8")
    out = tmp_path / "out"
    monkeypatch.setattr(
        runner,
        "classify_product_script",
        lambda _payload: {"looks_like_built_antibot_script": True, "reasons": []},
    )
    monkeypatch.setattr(
        runner,
        "grade_script_source_provenance",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            runner.ContractError("Git provenance revision mismatch")
        ),
    )
    monkeypatch.setattr(
        runner,
        "run_product_script_observation",
        lambda *_args, **_kwargs: pytest.fail("browser launch must not occur"),
    )

    with pytest.raises(runner.ContractError, match="revision mismatch"):
        runner.main(
            [
                "--script",
                str(sample),
                "--label",
                "pin",
                "--executable",
                str(tmp_path / "chrome.exe"),
                "--trace-processor",
                str(tmp_path / "trace_processor.exe"),
                "--workspace",
                str(tmp_path),
                "--out",
                str(out),
                "--source-git-checkout",
                str(tmp_path),
                "--source-git-repository-url",
                "https://vendor.example/public.git",
                "--source-git-revision",
                "a" * 40,
                "--source-build-recipe",
                str(tmp_path / "build.sh"),
                "--source-sha256",
                "b" * 64,
            ]
        )

    assert not out.exists()


def test_trace_health_summary_is_path_free_and_counts_every_attempt() -> None:
    summary = runner._trace_health_summary(
        [
            {
                "browser_shutdown": {
                    "mode": "graceful",
                    "diagnostic": "C:/private/browser",
                },
                "trace_flush": {
                    "status": "settled",
                    "bytes": 1234,
                    "path": "C:/private/trace",
                },
                "trace_export_budget": {
                    "within_budget": True,
                    "bytes_within_budget": True,
                    "events_within_budget": True,
                    "source_trace": "C:/private/trace",
                },
            },
            {
                "browser_shutdown": {"mode": "forced"},
                "trace_flush": {"status": "missing"},
                "trace_export_budget": {
                    "within_budget": False,
                    "bytes_within_budget": True,
                    "events_within_budget": False,
                },
            },
            {
                "browser_shutdown": {"mode": "private-secret"},
                "trace_flush": {"status": "private-secret"},
            },
        ]
    )
    assert summary == {
        "attempted_arms_including_control": 3,
        "shutdown_modes": {"forced": 1, "graceful": 1},
        "trace_flush_statuses": {"missing": 1, "settled": 1},
        "trace_export_budget_statuses": {"over": 1, "within": 1},
        "trace_export_budget_overruns": {"exportable_events": 1},
        "missing_shutdown_receipts": 1,
        "missing_trace_flush_receipts": 1,
        "missing_trace_export_budget_receipts": 1,
    }
    assert "private" not in json.dumps(summary)


def test_source_provenance_summary_is_path_free_and_omits_unpinned_arms() -> None:
    digest = "a" * 64
    summary = runner._source_provenance_summary(
        [
            {
                "arm_label": "control",
                "source_provenance": {"status": "not_supplied"},
            },
            {
                "arm_label": "pin-r1",
                "source_provenance": {
                    "status": "verified_git_inputs_artifact_digest",
                    "repository_url": "https://vendor.example/public.git",
                    "revision": "b" * 40,
                    "sha256": digest,
                    "artifact_relative_path": "web/static/js/main.mjs",
                    "artifact_git_state": "ignored-generated",
                    "build_recipe_relative_path": "web/build.sh",
                    "build_recipe_sha256": "c" * 64,
                    "tracked_worktree_clean": True,
                    "distinct_checkout_artifact_verified": True,
                    "rebuild_artifact_sha256": digest,
                    "private_checkout": "C:/private/source-pin",
                },
            },
        ]
    )

    assert list(summary) == ["pin-r1"]
    assert summary["pin-r1"]["status"] == (
        "verified_git_inputs_artifact_digest"
    )
    assert summary["pin-r1"]["distinct_checkout_artifact_verified"] is True
    assert "private" not in json.dumps(summary)


def test_partial_repeat_is_structured_and_returns_nonzero(
    tmp_path, monkeypatch, capsys
) -> None:
    sample = tmp_path / "collector.js"
    sample.write_text("collector", encoding="utf-8")
    out = tmp_path / "out"

    monkeypatch.setattr(
        runner,
        "classify_product_script",
        lambda _payload: {"looks_like_built_antibot_script": True, "reasons": []},
    )

    def fake_observe(config, _root):
        if config.label.endswith("-r2"):
            return _sealed_observation(
                label=config.label,
                error="trace export failed: C:\\private\\trace-file",
                diagnostic_trace_analysis={
                    "script_execution": {
                        "total": 1,
                        "complete": 0,
                        "open": 1,
                        "max_complete_duration_ns": None,
                    },
                    "private_path": "C:\\private\\trace-file",
                },
            )
        return _sealed_observation(label=config.label)

    monkeypatch.setattr(runner, "run_product_script_observation", fake_observe)
    monkeypatch.setattr(
        runner,
        "subtract_control",
        lambda arm, _control: {
            "arm_label": arm["label"],
            "attributed_api_names": 7,
            "clean_subtraction": True,
        },
    )

    result = runner.main(
        [
            "--script",
            str(sample),
            "--label",
            "pin",
            "--executable",
            str(tmp_path / "chrome.exe"),
            "--trace-processor",
            str(tmp_path / "trace_processor.exe"),
            "--workspace",
            str(tmp_path),
            "--out",
            str(out),
            "--repeat",
            "2",
        ]
    )

    summary = json.loads((out / "summary.json").read_text(encoding="utf-8"))
    assert result == 2
    assert summary["complete"] is False
    assert summary["execution_complete"] is False
    assert summary["all_surface_claim_ready"] is False
    assert summary["claim_ready_arms"] == ["pin-r1"]
    assert summary["not_claim_ready_arms"] == []
    assert summary["planned_arms"] == ["pin-r1", "pin-r2"]
    assert summary["successful_arms"] == 1
    assert summary["failed_arms"] == [
        {
            "label": "pin-r2",
            "group": "pin",
            "error_kind": "trace export failed",
            "diagnostic_script_execution": {
                "total": 1,
                "complete": 0,
                "open": 1,
                "max_complete_duration_ns": None,
            },
        }
    ]
    assert summary["failed_attempts"][-1]["diagnostic_script_execution"]["open"] == 1
    assert summary["groups"]["pin"] == {
        "requested": 2,
        "successful": 1,
        "claim_ready": 1,
        "failed": ["pin-r2"],
        "complete": False,
        "all_surface_claim_ready": False,
    }
    assert "private" not in json.dumps(summary)
    assert "[SCRIPT EXECUTION OPEN: 1]" in capsys.readouterr().err


def test_complete_repeat_carries_request_activity_noise_floor(
    tmp_path, monkeypatch, capsys
) -> None:
    sample = tmp_path / "collector.js"
    sample.write_text("collector", encoding="utf-8")
    out = tmp_path / "out"
    monkeypatch.setattr(
        runner,
        "classify_product_script",
        lambda _payload: {"looks_like_built_antibot_script": True, "reasons": []},
    )
    monkeypatch.setattr(
        runner,
        "run_product_script_observation",
        lambda config, _root: _sealed_observation(
            label=config.label,
            browser_shutdown={"mode": "graceful"},
            trace_flush={"status": "settled", "bytes": 1234},
        ),
    )
    monkeypatch.setattr(
        runner,
        "subtract_control",
        lambda arm, _control: {
            "arm_label": arm["label"],
            "attributed_api_names": 7,
            "elevated_in_arm": {
                "api.TextEncoder.encode": {"arm": 100, "control": 2},
                "api.HTMLElement.style.get": {"arm": 10, "control": 3},
            },
            "clean_subtraction": True,
        },
    )
    request_floor = {
        "status": "ok",
        "arms": 2,
        "stable_shapes": 1,
        "union_shapes": 1,
        "variable_shapes": 1,
        "rows": [],
    }
    monkeypatch.setattr(
        runner,
        "build_repeated_surface_baseline",
        lambda _arms, label: {
            "arms": 2,
            "api_name_count": 7,
            "volatile_api_names": [],
            "measured_noise_floor": 0,
            "pairwise_differences": [0],
            "request_activity_baseline": request_floor,
        },
    )
    monkeypatch.setattr(
        runner,
        "compare_surfaces",
        lambda _arms: product_observation.compare_surfaces(
            [
                {
                    "schema": product_observation.SUBTRACTION_SCHEMA,
                    "arm_label": label,
                    "arm_script_sha256_16": "0" * 16,
                    "only_in_arm": {"api.A": 1},
                    "clean_subtraction": True,
                }
                for label in ("pin-r1", "pin-r2")
            ]
        ),
    )

    result = runner.main(
        [
            "--script",
            str(sample),
            "--label",
            "pin",
            "--executable",
            str(tmp_path / "chrome.exe"),
            "--trace-processor",
            str(tmp_path / "trace_processor.exe"),
            "--workspace",
            str(tmp_path),
            "--out",
            str(out),
            "--repeat",
            "2",
        ]
    )

    summary = json.loads((out / "summary.json").read_text(encoding="utf-8"))
    assert result == 0
    assert summary["complete"] is True
    assert summary["execution_complete"] is True
    assert summary["all_surface_claim_ready"] is True
    assert summary["claim_ready_arms"] == ["pin-r1", "pin-r2"]
    assert summary["not_claim_ready_arms"] == []
    assert summary["groups"]["pin"]["claim_ready"] == 2
    assert summary["groups"]["pin"]["all_surface_claim_ready"] is True
    assert summary["baselines"]["pin"]["request_activity_baseline"] == request_floor
    assert summary["trace_health"] == {
        "attempted_arms_including_control": 3,
        "shutdown_modes": {"graceful": 3},
        "trace_flush_statuses": {"settled": 3},
        "trace_export_budget_statuses": {},
        "trace_export_budget_overruns": {},
        "missing_shutdown_receipts": 0,
        "missing_trace_flush_receipts": 0,
        "missing_trace_export_budget_receipts": 3,
    }
    assert summary["attributed_api_names"] == {"pin-r1": 7, "pin-r2": 7}
    assert summary["arm_only_api_names"] == {"pin-r1": 7, "pin-r2": 7}
    assert summary["elevated_api_names"] == {"pin-r1": 2, "pin-r2": 2}
    assert summary["total_distinguishing_api_names"] == {
        "pin-r1": 9,
        "pin-r2": 9,
    }
    stderr = capsys.readouterr().err
    assert "7 arm-only API names, 2 elevated control-shared names" in stderr
    assert "request metrics vary on 1 of 1" in stderr


def test_opt_in_trace_export_retry_recovers_without_erasing_failed_attempt(
    tmp_path, monkeypatch
) -> None:
    sample = tmp_path / "collector.js"
    sample.write_text("collector", encoding="utf-8")
    out = tmp_path / "out"
    monkeypatch.setattr(
        runner,
        "classify_product_script",
        lambda _payload: {"looks_like_built_antibot_script": True, "reasons": []},
    )

    def fake_observe(config, _root):
        if config.label == "pin":
            return _sealed_observation(
                label=config.label,
                error="trace export failed: C:\\private\\trace-file",
            )
        return _sealed_observation(label=config.label)

    monkeypatch.setattr(runner, "run_product_script_observation", fake_observe)
    monkeypatch.setattr(
        runner,
        "subtract_control",
        lambda arm, _control: {
            "arm_label": arm["label"],
            "attributed_api_names": 7,
            "clean_subtraction": True,
            "surface_claim_ready": False,
        },
    )

    result = runner.main(
        [
            "--script",
            str(sample),
            "--label",
            "pin",
            "--executable",
            str(tmp_path / "chrome.exe"),
            "--trace-processor",
            str(tmp_path / "trace_processor.exe"),
            "--workspace",
            str(tmp_path),
            "--out",
            str(out),
            "--retry-failed",
            "1",
        ]
    )

    summary = json.loads((out / "summary.json").read_text(encoding="utf-8"))
    assert result == 0
    assert summary["complete"] is True
    assert summary["execution_complete"] is True
    assert summary["all_surface_claim_ready"] is False
    assert summary["claim_ready_arms"] == []
    assert summary["not_claim_ready_arms"] == ["pin-retry1"]
    assert summary["groups"]["pin"] == {
        "requested": 1,
        "successful": 1,
        "claim_ready": 0,
        "failed": [],
        "complete": True,
        "all_surface_claim_ready": False,
    }
    assert summary["failed_arms"] == []
    assert summary["recovered_arms"] == {"pin": "pin-retry1"}
    assert summary["failed_attempts"] == [
        {
            "planned_label": "pin",
            "attempt_label": "pin",
            "group": "pin",
            "attempt": 1,
            "error_kind": "trace export failed",
        }
    ]
    assert (out / "arm-pin.json").is_file()
    assert (out / "arm-pin-retry1.json").is_file()
    assert "private" not in json.dumps(summary)


def test_method_source_files_avoid_command_line_source_and_paths(
    tmp_path, monkeypatch
) -> None:
    sample = tmp_path / "collector.js"
    sample.write_text("collector", encoding="utf-8")
    prelude = tmp_path / "private-prelude-name.js"
    driver = tmp_path / "private-driver-name.js"
    ready = tmp_path / "private-ready-name.js"
    prelude_source = "window.ddoptions={endpoint:'/configured-js/'};"
    driver_source = "(() => { window.publicDriver(); return 'ok'; })()"
    ready_source = 'window.__collector_state === "offline"'
    prelude.write_text(prelude_source, encoding="utf-8")
    driver.write_text(driver_source, encoding="utf-8")
    ready.write_text(ready_source, encoding="utf-8")
    observed = []

    monkeypatch.setattr(
        runner,
        "classify_product_script",
        lambda _payload: {"looks_like_built_antibot_script": True, "reasons": []},
    )

    def fake_observe(config, _root):
        observed.append(config)
        return _sealed_observation(label=config.label)

    monkeypatch.setattr(runner, "run_product_script_observation", fake_observe)
    monkeypatch.setattr(
        runner,
        "subtract_control",
        lambda arm, _control: {
            "arm_label": arm["label"],
            "attributed_api_names": 7,
            "clean_subtraction": True,
        },
    )

    result = runner.main(
        [
            "--script",
            str(sample),
            "--label",
            "pin",
            "--executable",
            str(tmp_path / "chrome.exe"),
            "--trace-processor",
            str(tmp_path / "trace_processor.exe"),
            "--workspace",
            str(tmp_path),
            "--out",
            str(tmp_path / "out"),
            "--prelude-file",
            str(prelude),
            "--driver-file",
            str(driver),
            "--await-ready-seconds",
            "1",
            "--ready-expression-file",
            str(ready),
        ]
    )

    assert result == 0
    assert len(observed) == 2
    assert all(config.prelude_js == prelude_source for config in observed)
    assert all(config.driver_js == driver_source for config in observed)
    assert [config.ready_expression for config in observed] == [None, ready_source]
    summary = (tmp_path / "out" / "summary.json").read_text(encoding="utf-8")
    assert prelude_source not in summary
    assert driver_source not in summary
    assert ready_source not in summary
    assert prelude.name not in summary
    assert driver.name not in summary
    assert ready.name not in summary


def test_inline_and_file_method_source_are_mutually_exclusive(tmp_path) -> None:
    sample = tmp_path / "collector.js"
    sample.write_text("collector", encoding="utf-8")
    source = tmp_path / "prelude.js"
    source.write_text("window.x=1", encoding="utf-8")

    with pytest.raises(SystemExit) as caught:
        runner.main(
            [
                "--script",
                str(sample),
                "--label",
                "pin",
                "--executable",
                str(tmp_path / "chrome.exe"),
                "--trace-processor",
                str(tmp_path / "trace_processor.exe"),
                "--workspace",
                str(tmp_path),
                "--out",
                str(tmp_path / "out"),
                "--prelude",
                "window.x=1",
                "--prelude-file",
                str(source),
            ]
        )

    assert caught.value.code == 2


def test_inline_and_file_ready_expressions_are_mutually_exclusive(tmp_path) -> None:
    sample = tmp_path / "collector.js"
    sample.write_text("collector", encoding="utf-8")
    source = tmp_path / "ready.js"
    source.write_text("window.ready === true", encoding="utf-8")

    with pytest.raises(SystemExit) as caught:
        runner.main(
            [
                "--script",
                str(sample),
                "--label",
                "pin",
                "--executable",
                str(tmp_path / "chrome.exe"),
                "--trace-processor",
                str(tmp_path / "trace_processor.exe"),
                "--workspace",
                str(tmp_path),
                "--out",
                str(tmp_path / "out"),
                "--await-ready-seconds",
                "1",
                "--ready-expression",
                "window.ready === true",
                "--ready-expression-file",
                str(source),
            ]
        )

    assert caught.value.code == 2
