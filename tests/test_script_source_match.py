from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from browser_core.contracts import ContractError, validate_trace_event
from browser_core.script_source_match import script_source_match


def _event_rows(source: str, *, runs: int = 1) -> list[dict]:
    encoded = source.encode("utf-16le", "surrogatepass")
    identity = {
        "schema": "browser-core.trace-event/1", "run_id": "script-source-fixture",
        "seq": 0, "ts_monotonic_ns": 10,
        "process": {"pid": 1, "type": "renderer"},
        "event": {"category": "execution", "name": "script.source.identity"},
        "provenance": {"source": "native", "component": "v8.compiler",
                       "trace_category": "browser_core.debug"},
        "detail": {
            "native_name": "BrowserCore.ScriptSourceIdentity", "thread_id": 2,
            "script_id": 7, "source_length": len(encoded) // 2,
            "source_length_unit": "utf16-code-units",
            "compiler_input_hash_status": "observed",
            "compiler_input_utf16le_sha256": hashlib.sha256(encoded).hexdigest(),
        },
    }
    rows = [identity]
    for index in range(runs):
        context = "frame-a" if index % 2 == 0 else "frame-b"
        rows.append({
            "schema": "browser-core.trace-event/1", "run_id": "script-source-fixture",
            "seq": index + 1, "ts_monotonic_ns": index + 11,
            "process": {"pid": 1, "type": "renderer"},
            "execution": {"context_id": context, "frame_id": context,
                          "script_id": f"v8:1:{context}:7"},
            "event": {"category": "execution", "name": "script.run"},
            "provenance": {"source": "native", "component": "blink.v8",
                           "trace_category": "browser_core.debug"},
            "detail": {"native_name": "BrowserCore.ScriptRun", "thread_id": 2},
        })
    return rows


def _write_trace(path: Path, rows: list[dict]) -> str:
    path.write_text("\n".join(json.dumps(row, sort_keys=True) for row in rows) + "\n",
                    encoding="utf-8")
    return hashlib.sha256(path.read_bytes()).hexdigest()


@pytest.mark.parametrize("swapped_scan", [1, 2])
def test_script_source_match_rejects_a_swapped_scan(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, swapped_scan: int,
) -> None:
    import browser_core.script_source_match as module

    trace, alternate, candidate = (
        tmp_path / "trace.jsonl", tmp_path / "alternate.jsonl", tmp_path / "candidate.js"
    )
    trusted_digest = _write_trace(trace, _event_rows("a"))
    _write_trace(alternate, _event_rows("b"))
    candidate.write_text("b" if swapped_scan == 1 else "a", encoding="utf-8")
    original_body, alternate_body = trace.read_bytes(), alternate.read_bytes()
    real_scan = module.scan_validated_trace
    scans = 0

    def swapped_during_scan(path: Path, consume, **kwargs):
        nonlocal scans
        scans += 1
        if scans == swapped_scan:
            path.write_bytes(alternate_body)
        try:
            return real_scan(path, consume, **kwargs)
        finally:
            if scans == swapped_scan:
                path.write_bytes(original_body)

    monkeypatch.setattr(module, "scan_validated_trace", swapped_during_scan)
    with pytest.raises(ContractError, match="trace scan disagrees with trusted digest"):
        script_source_match(trace, candidate_file=candidate,
                            expected_trace_sha256=trusted_digest)
    assert trace.read_bytes() == original_body


def test_script_source_match_rechecks_trace_after_final_candidate_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    import browser_core.script_source_match as module

    trace, alternate, candidate = (
        tmp_path / "trace.jsonl", tmp_path / "alternate.jsonl", tmp_path / "candidate.js"
    )
    _write_trace(trace, _event_rows("a"))
    _write_trace(alternate, _event_rows("b"))
    candidate.write_bytes(b"a")
    alternate_body = alternate.read_bytes()
    original_read = module.read_bounded_control_snapshot_result
    reads = 0

    def replace_trace_on_final_candidate_read(path: Path, **kwargs):
        nonlocal reads
        snapshot = original_read(path, **kwargs)
        reads += 1
        if reads == 1:
            trace.write_bytes(alternate_body)
        return snapshot

    monkeypatch.setattr(
        module, "read_bounded_control_snapshot_result",
        replace_trace_on_final_candidate_read,
    )
    with pytest.raises(ContractError, match="normalized trace changed"):
        script_source_match(trace, candidate_file=candidate)


def test_script_source_match_links_only_compatible_run_sequences(tmp_path: Path) -> None:
    source = "window.fixture = 1;\r\n"
    trace, candidate = tmp_path / "trace.jsonl", tmp_path / "candidate.js"
    digest = _write_trace(trace, _event_rows(source, runs=20))
    candidate.write_bytes(source.encode("utf-8"))
    result = script_source_match(trace, candidate_file=candidate,
                                 expected_trace_sha256=digest)
    assert result["status"] == "matched"
    assert result["trusted_digest_matched"] is True
    assert result["counts"]["matches"] == 1
    assert result["matches"][0]["compatible_run_count"] == 20
    assert result["matches"][0]["compatible_run_seqs"] == list(range(1, 17))
    assert result["matches"][0]["compatible_runs_truncated"] is True
    assert result["matches"][0]["run_link_status"] == "compatible-run-observed"
    assert "numeric-script-id" in result["run_link_scope"]
    rendered = json.dumps(result)
    assert "window.fixture" not in rendered
    assert hashlib.sha256(source.encode("utf-16le")).hexdigest() not in rendered
    candidate.write_bytes(source.replace("\r\n", "\n").encode("utf-8"))
    assert script_source_match(trace, candidate_file=candidate)["status"] == "not-observed"


def test_script_source_match_schema_and_digest_limits(tmp_path: Path) -> None:
    schema = json.loads((Path(__file__).parents[1] /
                         "schemas/script-source-match-v2.schema.json").read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema)
    trace, candidate = tmp_path / "trace.jsonl", tmp_path / "candidate.json"
    rows = _event_rows("a")
    _write_trace(trace, rows)
    candidate.write_text(json.dumps("a"), encoding="utf-8")
    validator.validate(script_source_match(trace, candidate))
    validator.validate({"schema": "browser-core.script-source-match/2",
                        "status": "error", "code": "script-source-match-unavailable"})
    candidate.write_text(json.dumps("x" * 262145), encoding="utf-8")
    assert script_source_match(trace, candidate)["status"] == "candidate-over-limit"
    rows[0]["detail"]["compiler_input_hash_status"] = "unavailable"
    rows[0]["detail"]["compiler_input_utf16le_sha256"] = None
    _write_trace(trace, rows)
    candidate.write_text(json.dumps("a"), encoding="utf-8")
    assert script_source_match(trace, candidate)["status"] == "digest-unavailable"


def test_script_source_match_rejects_timestamp_outside_its_wire_schema(
    tmp_path: Path,
) -> None:
    trace, candidate = tmp_path / "trace.jsonl", tmp_path / "candidate.js"
    rows = _event_rows("a", runs=0)
    rows[0]["ts_monotonic_ns"] = 2**53
    _write_trace(trace, rows)
    candidate.write_bytes(b"a")

    with pytest.raises(ContractError, match="source match output integer exceeds limit"):
        script_source_match(trace, candidate_file=candidate)


def test_script_source_match_rejects_compatible_run_seq_outside_wire_schema(
    tmp_path: Path,
) -> None:
    trace, candidate = tmp_path / "trace.jsonl", tmp_path / "candidate.js"
    rows = _event_rows("a")
    rows[1]["seq"] = 2**53
    _write_trace(trace, rows)
    candidate.write_bytes(b"a")

    with pytest.raises(ContractError, match="source match output integer exceeds limit"):
        script_source_match(trace, candidate_file=candidate)


def test_script_source_match_preserves_source_identity_without_run(tmp_path: Path) -> None:
    trace, candidate = tmp_path / "module.jsonl", tmp_path / "module.js"
    source = "export const answer = 23;\n"
    digest = _write_trace(trace, _event_rows(source, runs=0))
    candidate.write_bytes(source.encode("utf-8"))
    result = script_source_match(trace, candidate_file=candidate,
                                 expected_trace_sha256=digest)
    assert result["status"] == "matched"
    assert result["matches"][0]["script_id"] == 7
    assert result["matches"][0]["compatible_run_count"] == 0
    assert result["matches"][0]["compatible_run_seqs"] == []
    assert result["matches"][0]["run_link_status"] == "no-compatible-run-observed"
    assert "does not prove execution" in result["limits"][0]


def test_script_source_match_drops_prevent_negative_source_claim(tmp_path: Path) -> None:
    trace, candidate = tmp_path / "trace.jsonl", tmp_path / "candidate.js"
    rows = _event_rows("observed source")
    candidate.write_bytes(b"other source")
    _write_trace(trace, rows)
    assert script_source_match(trace, candidate_file=candidate)["status"] == "not-observed"
    rows.append({
        "schema": "browser-core.trace-event/1", "run_id": "script-source-fixture",
        "seq": 2, "ts_monotonic_ns": 12,
        "process": {"pid": 1, "type": "renderer"},
        "event": {"category": "diagnostic", "name": "trace.dropped"},
        "provenance": {"source": "reader", "component": "fixture"},
        "detail": {"count": 3},
    })
    _write_trace(trace, rows)
    result = script_source_match(trace, candidate_file=candidate)
    assert result["status"] == "digest-coverage-limited"
    assert result["dropped_events"] == 3


def test_script_source_match_drops_suppress_run_attribution(tmp_path: Path) -> None:
    trace, candidate = tmp_path / "trace.jsonl", tmp_path / "candidate.js"
    source = "globalThis.observed = 1;\n"
    rows = _event_rows(source)
    rows.append({
        "schema": "browser-core.trace-event/1", "run_id": "script-source-fixture",
        "seq": 2, "ts_monotonic_ns": 12,
        "process": {"pid": 1, "type": "renderer"},
        "event": {"category": "diagnostic", "name": "trace.dropped"},
        "provenance": {"source": "reader", "component": "fixture"},
        "detail": {"count": 1},
    })
    _write_trace(trace, rows)
    candidate.write_bytes(source.encode("utf-8"))
    result = script_source_match(trace, candidate_file=candidate)
    assert result["status"] == "matched"
    assert result["dropped_events"] == 1
    assert result["matches"][0]["run_link_status"] == "run-evidence-incomplete"
    assert result["matches"][0]["compatible_run_count"] == 0
    assert result["matches"][0]["compatible_run_seqs"] == []
    schema = json.loads((Path(__file__).parents[1] /
                         "schemas/script-source-match-v2.schema.json").read_text(
                             encoding="utf-8"))
    Draft202012Validator(schema).validate(result)


def test_script_source_match_drops_skip_unreportable_run_sequence(tmp_path: Path) -> None:
    trace, candidate = tmp_path / "trace.jsonl", tmp_path / "candidate.js"
    rows = _event_rows("source")
    rows[1]["seq"] = 2**53
    rows.append({
        "schema": "browser-core.trace-event/1", "run_id": "script-source-fixture",
        "seq": 2**53 + 1, "ts_monotonic_ns": 12,
        "process": {"pid": 1, "type": "renderer"},
        "event": {"category": "diagnostic", "name": "trace.dropped"},
        "provenance": {"source": "reader", "component": "fixture"},
        "detail": {"count": 1},
    })
    _write_trace(trace, rows)
    candidate.write_bytes(b"source")

    result = script_source_match(trace, candidate_file=candidate)
    assert result["status"] == "matched"
    assert result["matches"][0]["run_link_status"] == "run-evidence-incomplete"
    assert result["matches"][0]["compatible_run_seqs"] == []


def test_script_source_match_does_not_link_earlier_equal_timestamp_run(tmp_path: Path) -> None:
    trace, candidate = tmp_path / "trace.jsonl", tmp_path / "candidate.js"
    source = "same timestamp"
    identity, run = _event_rows(source)
    run["seq"] = 0
    run["ts_monotonic_ns"] = 10
    identity["seq"] = 1
    identity["ts_monotonic_ns"] = 10
    _write_trace(trace, [run, identity])
    candidate.write_bytes(source.encode("utf-8"))
    result = script_source_match(trace, candidate_file=candidate)
    assert result["status"] == "matched"
    assert result["matches"][0]["compatible_run_count"] == 0
    identity["seq"], run["seq"] = 0, 1
    _write_trace(trace, [identity, run])
    assert script_source_match(trace, candidate_file=candidate)["matches"][0][
        "compatible_run_count"] == 0


@pytest.mark.parametrize("same_source", [True, False])
def test_script_source_match_marks_reused_numeric_script_id_ambiguous(
    tmp_path: Path, same_source: bool,
) -> None:
    trace, candidate = tmp_path / "trace.jsonl", tmp_path / "candidate.js"
    source = "globalThis.frameValue = 5;\n"
    identity, run = _event_rows(source)
    other_identity = json.loads(json.dumps(identity))
    other_identity["seq"] = 2
    other_identity["ts_monotonic_ns"] = 12
    if not same_source:
        other = "globalThis.otherValue = 6;\n"
        other_identity["detail"]["source_length"] = len(other.encode("utf-16le")) // 2
        other_identity["detail"]["compiler_input_utf16le_sha256"] = hashlib.sha256(
            other.encode("utf-16le")).hexdigest()
    other_run = json.loads(json.dumps(run))
    other_run["seq"] = 3
    other_run["ts_monotonic_ns"] = 13
    other_run["execution"] = {
        "context_id": "frame-b", "frame_id": "frame-b",
        "script_id": "v8:1:frame-b:7",
    }
    _write_trace(trace, [identity, run, other_identity, other_run])
    candidate.write_bytes(source.encode("utf-8"))
    result = script_source_match(trace, candidate_file=candidate)
    assert result["status"] == "matched"
    assert result["counts"]["matches"] == (2 if same_source else 1)
    for match in result["matches"]:
        assert match["run_link_status"] == "ambiguous-script-id"
        assert match["compatible_run_count"] == 0
        assert match["compatible_run_seqs"] == []


def test_script_source_identity_contract_rejects_false_context_and_digest() -> None:
    event = _event_rows("a")[0]
    assert validate_trace_event(event)["detail"]["script_id"] == 7
    event["execution"] = {"context_id": "frame-a"}
    with pytest.raises(ContractError, match="script source identity metadata"):
        validate_trace_event(event)
    del event["execution"]
    event["detail"]["compiler_input_utf16le_sha256"] = "0" * 64
    event["detail"]["compiler_input_hash_status"] = "over-limit"
    with pytest.raises(ContractError, match="script source identity digest"):
        validate_trace_event(event)
