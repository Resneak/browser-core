"""Bounded next-action plans over verified saved evidence inventory."""
import copy
import json
from pathlib import Path

import pytest

from browser_core import agent_plan
from browser_core.contracts import ContractError
from browser_core.inspection_contract import APIS_V1, APIS_V2, APIS_V3
from browser_core.observation_digest import technique_of


ROOT = Path(__file__).resolve().parents[1]


def clean_counts(total):
    return {
        "binding_value_records": total,
        "thread_process_linked_records": total,
        "thread_process_unlinked_records": 0,
        "capture_envelope_matching_records": total,
        "capture_envelope_mismatched_records": 0,
        "recognized_api_records": total,
        "unrecognized_api_records": 0,
        "completion_compatible_records": total,
        "completion_incompatible_records": 0,
        "queryable_records": total,
    }


def summary(*, observed=True):
    selected_counts = {
        "Navigator.userAgent.get": 7 if observed else 0,
        "Navigator.language.get": 2 if observed else 0,
        "OffscreenCanvasRenderingContext2D.getImageData": 150 if observed else 0,
    }
    counts = [(name, selected_counts.get(name, 0)) for name in sorted(APIS_V2)]
    return {
        "schema": "browser-core.evidence-summary/1",
        "status": "ok",
        "bundle": {
            "sha256": "a" * 64,
            "expected_digest_matched": True,
            "authenticity": "unsigned-exporter-metadata",
        },
        "capture": {
            "schema": "browser-core.inspection/2",
            "allowlist": "fingerprint-v2",
        },
        "recording": {
            "sha256": "b" * 64,
            "source_phase": "finalized-recording",
        },
        "counts": clean_counts(sum(value for _, value in counts)),
        "recording_health": {
            "status": "no-issues-reported",
            "capture_stats_seen": True,
            "counters_truncated": False,
            "sorter_dropped_events": "0",
            "proves_complete": False,
        },
        "semantics": {
            "population": "native-binding-value-records",
            "unique_calls": False,
            "api_counts": "matching-envelope-and-compatible-completion",
            "capability_basis": "reader-known-capture-contract",
            "zero_count": "not-observed-in-this-recording",
            "private_payloads_validated": False,
            "thread_process_link_is_context_attribution": False,
            "private_values_included": False,
            "proves_capture_complete": False,
            "browser_launched": False,
            "active_probes": False,
            "source_snapshot": "fixed-verified-copy",
            "recording_metadata": "unsigned-exporter-claims-except-verified-bytes-and-sha256",
            "attribution_analysis": "not-performed",
            "decoder_read": "end-of-file",
            "live_freshness": "not-applicable",
            "proves_server_behavior": False,
        },
        "apis": [
            {"api": name, "records": value, "first_ns": None, "last_ns": None}
            for name, value in counts
        ],
    }


def set_api_counts(document, rows):
    selected = dict(rows)
    assert set(selected) <= APIS_V2
    document['apis'] = [
        {'api': name, 'records': selected.get(name, 0),
         'first_ns': None, 'last_ns': None}
        for name in sorted(APIS_V2)
    ]
    document['counts'] = clean_counts(sum(selected.values()))


def validator():
    import jsonschema

    schema = json.loads(
        (ROOT / "schemas/agent-research-plan-v1.schema.json").read_text()
    )
    jsonschema.Draft202012Validator.check_schema(schema)
    return jsonschema.Draft202012Validator(schema)


def test_every_reader_known_value_api_has_an_agent_technique():
    for api in APIS_V1 | APIS_V2 | APIS_V3:
        assert technique_of(f"api.{api}") != "unclassified", api


def test_plan_prioritizes_observed_calls_without_claiming_coverage():
    result = agent_plan.plan_evidence_summary(summary())
    validator().validate(result)
    assert result["inventory"]["binding_value_records"] == 159
    assert result["inventory"]["completion_compatible_value_records"] == 159
    assert result["inventory"]["queryable_value_records"] == 159
    assert (
        result["inventory"]["query_target_policy"]
        == "technique-diverse-then-population"
    )
    assert result["inventory"]["query_target_technique_coverage_complete"] is True
    assert result["inventory"]["untargeted_observed_techniques"] == []
    assert result["evidence_quality"]["nonqueryable_binding_records"] == 0
    assert result["inventory"]["observed_apis"] == 3
    assert result["inventory"]["query_targets"][0] == {
        "api": "OffscreenCanvasRenderingContext2D.getImageData",
        "technique": "canvas-raster",
        "completion_compatible_records": 150,
    }
    action = result["next_actions"][0]
    assert action["id"] == "query-observed-values"
    assert action["include_private_values"] is True
    assert action["page_until_cursor_null"] is True
    assert result["semantics"] == {
        "input_was_digest_verified": True,
        "private_values_read": False,
        "browser_launched": False,
        "active_probe": False,
        "not_observed_means_unsupported": False,
        "client_side_coverage_complete": False,
        "server_side_architecture_observed": False,
        "research_plan_is_proof": False,
        "external_interfaces_verified": False,
        "producer_build_is_independently_attested": False,
        "target_authorization_verified": False,
    }
    assert [row["id"] for row in result["next_actions"]] == [
        "query-observed-values",
        "map-versioned-client-artifacts",
        "correlate-broad-client-events",
        "recover-obfuscated-execution",
        "trace-state-and-request-provenance",
        "compare-browser-client-wire",
        "measure-authorized-server-outcome",
    ]
    assert [row["dimension"] for row in result["unresolved_dimensions"]] == [
        "versioned-client-artifacts",
        "whole-client-execution",
        "obfuscated-program-semantics",
        "state-and-request-provenance",
        "renderer-network-causality",
        "transport-fingerprint-equivalence",
        "transport-and-server-decision",
    ]


def test_plan_byte_limit_covers_pretty_printed_windows_output(monkeypatch):
    value = summary()
    result = agent_plan.plan_evidence_summary(value)
    compact = len(json.dumps(result, ensure_ascii=True, allow_nan=False).encode("ascii"))
    rendered = json.dumps(
        result, indent=2, sort_keys=True, ensure_ascii=True, allow_nan=False
    )
    emitted = len(rendered.encode("ascii")) + rendered.count("\n") + 2
    assert compact < emitted - 1
    monkeypatch.setattr(agent_plan, "MAX_OUTPUT_BYTES", emitted - 1)

    with pytest.raises(ContractError, match="output exceeds byte limit"):
        agent_plan.plan_evidence_summary(value)


def test_empty_observation_requests_workload_instead_of_value_query():
    result = agent_plan.plan_evidence_summary(summary(observed=False))
    validator().validate(result)
    assert result["inventory"]["query_targets"] == []
    assert result["next_actions"][0] == {
        "id": "capture-executed-workload",
        "priority": 1,
        "interface": "research-control",
        "reason": "No reader-known value call was observed; execute the intended workload before drawing an absence conclusion.",
        "target_apis": [],
        "include_private_values": False,
        "page_until_cursor_null": False,
    }


def test_plan_rejects_a_missing_reader_known_zero_count_api():
    value = summary()
    value['apis'] = [
        row for row in value['apis'] if row['api'] != 'Permissions.query'
    ]
    with pytest.raises(ContractError, match='API inventory'):
        agent_plan.plan_evidence_summary(value)


def test_paging_accounts_for_the_combined_multi_api_query_population():
    value = summary()
    set_api_counts(value, [
        ('Navigator.userAgent.get', 60),
        ('Navigator.language.get', 50),
    ])
    result = agent_plan.plan_evidence_summary(value)
    assert all(
        target["completion_compatible_records"] <= 100
        for target in result["inventory"]["query_targets"]
    )
    assert result["next_actions"][0]["page_until_cursor_null"] is True


def test_query_targets_preserve_technique_diversity_before_extra_hot_calls():
    value = summary(observed=False)
    rows = [
        ("CanvasRenderingContext2D.getImageData", 100),
        ("CanvasRenderingContext2D.measureText", 99),
        ("HTMLCanvasElement.toDataURL", 98),
        ("ImageData.data.get", 97),
        ("ImageData.height.get", 96),
        ("ImageData.width.get", 95),
        ("TextMetrics.actualBoundingBoxAscent.get", 94),
        ("TextMetrics.actualBoundingBoxDescent.get", 93),
        ("Permissions.query", 1),
    ]
    set_api_counts(value, rows)
    result = agent_plan.plan_evidence_summary(value)
    validator().validate(result)
    targets = result["inventory"]["query_targets"]
    assert len(targets) == 8
    assert targets[0]["api"] == "CanvasRenderingContext2D.getImageData"
    assert {target["technique"] for target in targets} == {
        "canvas-raster",
        "permissions",
    }
    assert any(target["api"] == "Permissions.query" for target in targets)


def test_more_than_eight_observed_techniques_exposes_unselected_families():
    value = summary(observed=False)
    names = [
        "AudioBuffer.duration.get",
        "CanvasRenderingContext2D.getImageData",
        "BatteryManager.level.get",
        "FontFaceSet.check",
        "MediaDevices.enumerateDevices",
        "Navigator.language.get",
        "Permissions.query",
        "Screen.width.get",
        "SpeechSynthesis.getVoices",
    ]
    rows = [(name, 100 - index) for index, name in enumerate(names)]
    set_api_counts(value, rows)
    result = agent_plan.plan_evidence_summary(value)
    validator().validate(result)
    assert len(result["inventory"]["query_targets"]) == 8
    assert result["inventory"]["query_target_technique_coverage_complete"] is False
    assert result["inventory"]["untargeted_observed_techniques"] == ["speech"]


@pytest.mark.parametrize(
    "mutation",
    [
        "schema", "digest", "digest-match", "authenticity", "duplicate", "count",
        "private", "private-payloads", "false-context", "complete", "server", "health-complete", "oversize-count",
        "queryable-too-high", "queryable-too-low", "partition",
        "live-source", "prefix-read", "unsupported-zero",
        "mismatched-capture", "unknown-api",
    ],
)
def test_invalid_or_promoted_summary_is_rejected(mutation):
    value = copy.deepcopy(summary())
    if mutation == "schema":
        value["schema"] = "private-invalid"
    elif mutation == "digest":
        value["bundle"]["sha256"] = "private-invalid"
    elif mutation == "digest-match":
        value["bundle"]["expected_digest_matched"] = False
    elif mutation == "authenticity":
        value["bundle"]["authenticity"] = "private-invalid"
    elif mutation == "duplicate":
        value["apis"].append(copy.deepcopy(value["apis"][0]))
    elif mutation == "count":
        value["counts"]["completion_compatible_records"] += 1
    elif mutation == "private":
        value["semantics"]["private_values_included"] = True
    elif mutation == "private-payloads":
        value["semantics"]["private_payloads_validated"] = True
    elif mutation == "false-context":
        value["semantics"]["thread_process_link_is_context_attribution"] = True
    elif mutation == "complete":
        value["semantics"]["proves_capture_complete"] = True
    elif mutation == "server":
        value["semantics"]["proves_server_behavior"] = True
    elif mutation == "health-complete":
        value["recording_health"]["proves_complete"] = True
    elif mutation == "oversize-count":
        value["apis"][0]["records"] = 2**53
    elif mutation == "queryable-too-high":
        value["counts"]["queryable_records"] += 1
    elif mutation == "queryable-too-low":
        value["counts"]["queryable_records"] -= 1
    elif mutation == "live-source":
        value["semantics"]["source_snapshot"] = "live-page"
    elif mutation == "prefix-read":
        value["semantics"]["decoder_read"] = "prefix"
    elif mutation == "unsupported-zero":
        value["semantics"]["zero_count"] = "unavailable"
    elif mutation == "mismatched-capture":
        value["capture"]["allowlist"] = "research-v3"
    elif mutation == "unknown-api":
        value["apis"][0]["api"] = "Unknown.private.get"
    else:
        value["counts"]["thread_process_unlinked_records"] += 1
    with pytest.raises(ContractError) as raised:
        agent_plan.plan_evidence_summary(value)
    assert "private-invalid" not in str(raised.value)


def test_saved_planner_requires_digest_and_delegates_summary(monkeypatch, tmp_path):
    calls = []

    def read(path, root, reader, *, expected_sha256, include_queryability):
        calls.append((path, root, reader, expected_sha256, include_queryability))
        return summary()

    monkeypatch.setattr(agent_plan, "evidence_summary", read)
    result = agent_plan.plan_saved_evidence(
        tmp_path / "bundle",
        ROOT,
        tmp_path / "chrome.exe",
        expected_sha256="a" * 64,
    )
    assert result["status"] == "ok"
    assert calls == [
        (tmp_path / "bundle", ROOT, tmp_path / "chrome.exe", "a" * 64, True)
    ]
    with pytest.raises(ContractError, match="trusted bundle digest"):
        agent_plan.plan_saved_evidence(
            tmp_path / "bundle", ROOT, tmp_path / "chrome.exe", expected_sha256=""
        )


def test_preserved_nonqueryable_rows_are_quality_evidence_not_a_total_failure():
    value = summary()
    value["apis"][0]["records"] += 4
    for name in (
        "binding_value_records",
        "thread_process_unlinked_records",
        "capture_envelope_matching_records",
        "recognized_api_records",
        "completion_compatible_records",
    ):
        value["counts"][name] += 4
    result = agent_plan.plan_evidence_summary(value)
    validator().validate(result)
    assert result["inventory"]["binding_value_records"] == 163
    assert result["inventory"]["completion_compatible_value_records"] == 163
    assert result["inventory"]["queryable_value_records"] == 159
    assert result["evidence_quality"]["nonqueryable_binding_records"] == 4
    assert result["evidence_quality"]["thread_process_unlinked_records"] == 4
    assert result["next_actions"][0]["id"] == "repair-evidence-quality"
    assert result["next_actions"][1]["id"] == "query-observed-values"


def test_reported_recording_issue_prioritizes_a_clean_recapture():
    value = summary()
    value["recording_health"]["status"] = "issues-reported"
    result = agent_plan.plan_evidence_summary(value)
    validator().validate(result)
    assert result["next_actions"][0]["id"] == "repair-evidence-quality"


@pytest.mark.parametrize(
    "field,value",
    [
        ("capture_stats_seen", False),
        ("counters_truncated", True),
        ("sorter_dropped_events", "1"),
    ],
)
def test_incomplete_or_lossy_diagnostics_prioritize_a_clean_recapture(field, value):
    document = summary()
    document["recording_health"][field] = value
    result = agent_plan.plan_evidence_summary(document)
    validator().validate(result)
    assert result["next_actions"][0]["id"] == "repair-evidence-quality"


def test_cli_success_and_fixed_failures(monkeypatch, capsys, tmp_path):
    from browser_core import cli

    expected = agent_plan.plan_evidence_summary(summary())
    monkeypatch.setattr(agent_plan, "plan_saved_evidence", lambda *a, **k: expected)
    arguments = [
        "agent", "plan", "--bundle", str(tmp_path / "bundle"),
        "--reader-executable", str(tmp_path / "chrome.exe"),
        "--expected-sha256", "a" * 64,
    ]
    assert cli.main(arguments) == 0
    assert json.loads(capsys.readouterr().out) == expected

    def fail(*_args, **_kwargs):
        raise ContractError("private detail")

    monkeypatch.setattr(agent_plan, "plan_saved_evidence", fail)
    assert cli.main(arguments) == 2
    assert json.loads(capsys.readouterr().out) == {
        "schema": agent_plan.SCHEMA,
        "status": "error",
        "code": "plan-unavailable",
    }


def test_schema_rejects_promoted_claim_and_extra_payload():
    result = agent_plan.plan_evidence_summary(summary())
    result["semantics"]["server_side_architecture_observed"] = True
    with pytest.raises(Exception):
        validator().validate(result)
    result = agent_plan.plan_evidence_summary(summary())
    result["private_payload"] = "must not fit"
    with pytest.raises(Exception):
        validator().validate(result)
