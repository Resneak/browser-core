from __future__ import annotations

import hashlib
import json
import copy
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from browser_core.contracts import ContractError
from browser_core.source_match import source_match


def _trace(path: Path, source: str, *, hashed: bool = True) -> str:
    encoded = source.encode("utf-16le", errors="surrogatepass")
    script = {
        "schema": "browser-core.trace-event/1", "run_id": "source-match-fixture",
        "seq": 0, "ts_monotonic_ns": 10,
        "process": {"pid": 1, "type": "renderer"},
        "execution": {"context_id": "frame-a", "frame_id": "frame-a",
                      "script_id": "v8:1:frame-a:7"},
        "event": {"category": "execution", "name": "script.run"},
        "provenance": {"source": "native", "component": "blink.v8"},
        "detail": {"native_name": "BrowserCore.ScriptRun", "thread_id": 2},
    }
    detail = {
        "native_name": "BrowserCore.DynamicCodeMaterialized", "thread_id": 2,
        "dynamic_kind": "eval", "cache_status": "compiled",
        "generated_script_id": 8, "caller_script_id": 7,
        "caller_status": "observed", "source_length": len(encoded) // 2,
        "source_length_unit": "utf16-code-units",
    }
    if hashed:
        detail["compiler_input_hash_status"] = "observed"
        detail["compiler_input_utf16le_sha256"] = hashlib.sha256(encoded).hexdigest()
    dynamic = {
        "schema": "browser-core.trace-event/1", "run_id": "source-match-fixture",
        "seq": 1, "ts_monotonic_ns": 11, "causal_parent_seq": 0,
        "process": {"pid": 1, "type": "renderer"},
        "execution": {"context_id": "frame-a", "frame_id": "frame-a",
                      "script_id": "v8:1:frame-a:7"},
        "event": {"category": "execution", "name": "dynamic.code.materialized"},
        "provenance": {"source": "native", "component": "v8.compiler"},
        "detail": detail,
    }
    path.write_text("\n".join(json.dumps(row, sort_keys=True) for row in (script, dynamic))
                    + "\n", encoding="utf-8")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _candidate(path: Path, source: str) -> None:
    path.write_text(json.dumps(source, ensure_ascii=True), encoding="utf-8")


def test_exact_local_match_preserves_lone_surrogate_and_hides_source(tmp_path: Path) -> None:
    source = "var x='" + chr(0xD800) + "';"
    trace, candidate = tmp_path / "trace.jsonl", tmp_path / "candidate.json"
    digest = _trace(trace, source)
    _candidate(candidate, source)
    result = source_match(trace, candidate, expected_trace_sha256=digest)
    assert result["status"] == "matched"
    assert result["trusted_digest_matched"] is True
    assert result["counts"]["matches"] == 1
    assert result["matches"][0]["generated_script_id"] == 8
    assert result["matches"][0]["caller_script_id"] == 7
    rendered = json.dumps(result)
    assert hashlib.sha256(source.encode("utf-16le", "surrogatepass")).hexdigest() not in rendered
    assert "var x=" not in rendered
    _candidate(candidate, source + " ")
    assert source_match(trace, candidate)["status"] == "not-observed"


def test_exact_utf8_source_file_preserves_line_endings_and_hides_source(tmp_path: Path) -> None:
    source = "const sensor = 1;\r\nvoid sensor;\r\n"
    trace, candidate = tmp_path / "trace.jsonl", tmp_path / "candidate.js"
    digest = _trace(trace, source)
    candidate.write_bytes(source.encode("utf-8"))
    result = source_match(trace, candidate_file=candidate, expected_trace_sha256=digest)
    assert result["status"] == "matched"
    assert result["counts"]["matches"] == 1
    rendered = json.dumps(result)
    assert "const sensor" not in rendered
    assert hashlib.sha256(source.encode("utf-16le")).hexdigest() not in rendered
    candidate.write_bytes(source.replace("\r\n", "\n").encode("utf-8"))
    assert source_match(trace, candidate_file=candidate)["status"] == "not-observed"


def test_utf8_source_file_accepts_empty_input_and_rejects_invalid_encoding(
    tmp_path: Path,
) -> None:
    trace, candidate = tmp_path / "trace.jsonl", tmp_path / "candidate.js"
    _trace(trace, "")
    candidate.write_bytes(b"")
    assert source_match(trace, candidate_file=candidate)["status"] == "matched"
    candidate.write_bytes(b"\xff")
    with pytest.raises(ContractError, match="UTF-8 source"):
        source_match(trace, candidate_file=candidate)
    with pytest.raises(ContractError, match="exactly one"):
        source_match(trace)
    with pytest.raises(ContractError, match="exactly one"):
        source_match(trace, candidate, candidate_file=candidate)


def test_source_match_output_has_a_bounded_public_schema(tmp_path: Path) -> None:
    schema_path = Path(__file__).parents[1] / "schemas/source-match-v1.schema.json"
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema)
    trace, candidate = tmp_path / "trace.jsonl", tmp_path / "candidate.json"
    _trace(trace, "a")
    _candidate(candidate, "a")
    validator.validate(source_match(trace, candidate))
    validator.validate({"schema": "browser-core.source-match/1", "status": "error",
                        "code": "source-match-unavailable"})


def test_unavailable_caller_is_not_reported_as_a_negative_script_id(tmp_path: Path) -> None:
    trace, candidate = tmp_path / "trace.jsonl", tmp_path / "candidate.json"
    _trace(trace, "dynamic source")
    rows = [json.loads(line) for line in trace.read_text(encoding="utf-8").splitlines()]
    dynamic = rows[1]
    dynamic.pop("causal_parent_seq")
    dynamic.pop("execution")
    dynamic["detail"]["caller_script_id"] = -1
    dynamic["detail"]["caller_status"] = "unavailable"
    trace.write_text("\n".join(json.dumps(row) for row in rows) + "\n", encoding="utf-8")
    _candidate(candidate, "dynamic source")

    result = source_match(trace, candidate)
    assert result["status"] == "matched"
    assert result["matches"][0]["caller_script_id"] is None
    schema = json.loads((Path(__file__).parents[1] / "schemas/source-match-v1.schema.json")
                        .read_text(encoding="utf-8"))
    Draft202012Validator(schema).validate(result)


def test_source_match_rejects_timestamp_outside_its_wire_schema(tmp_path: Path) -> None:
    trace, candidate = tmp_path / "trace.jsonl", tmp_path / "candidate.json"
    _trace(trace, "a")
    rows = [json.loads(line) for line in trace.read_text(encoding="utf-8").splitlines()]
    rows[1]["ts_monotonic_ns"] = 2**53
    trace.write_text("\n".join(json.dumps(row) for row in rows) + "\n", encoding="utf-8")
    _candidate(candidate, "a")

    with pytest.raises(ContractError, match="source match output integer exceeds limit"):
        source_match(trace, candidate)


def test_legacy_digest_and_candidate_cap_are_distinct_limits(tmp_path: Path) -> None:
    trace, candidate = tmp_path / "trace.jsonl", tmp_path / "candidate.json"
    _trace(trace, "a", hashed=False)
    _candidate(candidate, "a")
    result = source_match(trace, candidate)
    assert result["status"] == "digest-unavailable"
    assert result["counts"]["legacy_without_digest"] == 1
    _candidate(candidate, "x" * 262_145)
    result = source_match(trace, candidate)
    assert result["status"] == "candidate-over-limit"
    assert result["candidate_utf16_code_units"] == 262_145


def test_match_rejects_wrong_binding_and_late_trace_error(tmp_path: Path) -> None:
    trace, candidate = tmp_path / "trace.jsonl", tmp_path / "candidate.json"
    _trace(trace, "a")
    _candidate(candidate, "a")
    with pytest.raises(ContractError, match="trusted digest"):
        source_match(trace, candidate, expected_trace_sha256="0" * 64)
    with trace.open("a", encoding="utf-8") as stream:
        stream.write('{"invalid":true}\n')
    with pytest.raises(ContractError):
        source_match(trace, candidate)


def test_match_rejects_candidate_change_during_trace_scan(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    import browser_core.source_match as module

    trace, candidate = tmp_path / "trace.jsonl", tmp_path / "candidate.json"
    _trace(trace, "a")
    _candidate(candidate, "a")
    real_scan = module.scan_validated_trace

    def changed_during_scan(path: Path, consume, **kwargs):
        result = real_scan(path, consume, **kwargs)
        _candidate(candidate, "b")
        return result

    monkeypatch.setattr(module, "scan_validated_trace", changed_during_scan)
    with pytest.raises(ContractError, match="candidate changed"):
        source_match(trace, candidate)


def test_match_rechecks_trace_after_final_candidate_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    import browser_core.source_match as module

    trace, alternate, candidate = (
        tmp_path / "trace.jsonl", tmp_path / "alternate.jsonl", tmp_path / "candidate.json"
    )
    _trace(trace, "a")
    _trace(alternate, "b")
    _candidate(candidate, "a")
    alternate_body = alternate.read_bytes()
    original_read = module.read_bounded_control_snapshot_result
    reads = 0

    def replace_trace_on_final_candidate_read(path: Path, **kwargs):
        nonlocal reads
        snapshot = original_read(path, **kwargs)
        reads += 1
        if reads == 2:
            trace.write_bytes(alternate_body)
        return snapshot

    monkeypatch.setattr(
        module, "read_bounded_control_snapshot_result",
        replace_trace_on_final_candidate_read,
    )
    with pytest.raises(ContractError, match="normalized trace changed"):
        source_match(trace, candidate)


def test_match_rejects_trace_swapped_only_during_scan(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    import browser_core.source_match as module

    trace, alternate, candidate = (
        tmp_path / "trace.jsonl", tmp_path / "alternate.jsonl", tmp_path / "candidate.json"
    )
    trusted_digest = _trace(trace, "a")
    _trace(alternate, "b")
    _candidate(candidate, "b")
    original_body = trace.read_bytes()
    alternate_body = alternate.read_bytes()
    real_scan = module.scan_validated_trace

    def swapped_during_scan(path: Path, consume, **kwargs):
        path.write_bytes(alternate_body)
        try:
            return real_scan(path, consume, **kwargs)
        finally:
            path.write_bytes(original_body)

    monkeypatch.setattr(module, "scan_validated_trace", swapped_during_scan)
    with pytest.raises(ContractError, match="trace scan disagrees with trusted digest"):
        source_match(trace, candidate, expected_trace_sha256=trusted_digest)
    assert trace.read_bytes() == original_body


def test_mixed_legacy_trace_does_not_report_plain_nonmatch(tmp_path: Path) -> None:
    trace, candidate = tmp_path / "trace.jsonl", tmp_path / "candidate.json"
    _trace(trace, "a")
    rows = [json.loads(line) for line in trace.read_text(encoding="utf-8").splitlines()]
    legacy = copy.deepcopy(rows[1])
    legacy["seq"] = 2
    legacy["ts_monotonic_ns"] = 12
    legacy["detail"]["generated_script_id"] = 9
    del legacy["detail"]["compiler_input_hash_status"]
    del legacy["detail"]["compiler_input_utf16le_sha256"]
    trace.write_text("\n".join(json.dumps(row) for row in [*rows, legacy]) + "\n",
                     encoding="utf-8")
    _candidate(candidate, "b")
    result = source_match(trace, candidate)
    assert result["status"] == "digest-coverage-limited"
    assert result["counts"]["observed_digests"] == 1
    assert result["counts"]["legacy_without_digest"] == 1


def test_dropped_trace_events_limit_negative_source_claim(tmp_path: Path) -> None:
    trace, candidate = tmp_path / "trace.jsonl", tmp_path / "candidate.json"
    _trace(trace, "a")
    rows = [json.loads(line) for line in trace.read_text(encoding="utf-8").splitlines()]
    diagnostic = {
        "schema": "browser-core.trace-event/1", "run_id": "source-match-fixture",
        "seq": 2, "ts_monotonic_ns": 12,
        "process": {"pid": 1, "type": "renderer"},
        "event": {"category": "diagnostic", "name": "trace.dropped"},
        "provenance": {"source": "reader", "component": "fixture"},
        "detail": {"count": 3},
    }
    trace.write_text("\n".join(json.dumps(row) for row in [*rows, diagnostic]) + "\n",
                     encoding="utf-8")
    _candidate(candidate, "b")
    result = source_match(trace, candidate)
    assert result["status"] == "digest-coverage-limited"
    assert result["dropped_events"] == 3
    for bad in (-1, True, "3", None):
        diagnostic["detail"]["count"] = bad
        trace.write_text("\n".join(json.dumps(row) for row in [*rows, diagnostic]) + "\n",
                         encoding="utf-8")
        with pytest.raises(ContractError, match="dropped-event count"):
            source_match(trace, candidate)


def test_oversized_json_integer_is_closed_candidate_error(tmp_path: Path) -> None:
    trace, candidate = tmp_path / "trace.jsonl", tmp_path / "candidate.json"
    _trace(trace, "a")
    candidate.write_text("9" * 5000, encoding="utf-8")
    with pytest.raises(ContractError, match="candidate must be"):
        source_match(trace, candidate)


def test_match_summarizes_only_validated_generated_code_api_children(tmp_path: Path) -> None:
    trace, candidate = tmp_path / "trace.jsonl", tmp_path / "candidate.json"
    _trace(trace, "a")
    rows = [json.loads(line) for line in trace.read_text(encoding="utf-8").splitlines()]
    for seq, name in ((2, "Navigator.hardwareConcurrency.get"),
                      (3, "https://private.example/path")):
        rows.append({
            "schema": "browser-core.trace-event/1", "run_id": "source-match-fixture",
            "seq": seq, "ts_monotonic_ns": 10 + seq,
            "dynamic_code_parent_seq": 1,
            "process": {"pid": 1, "type": "renderer"},
            "execution": {"context_id": "frame-a", "frame_id": "frame-a",
                          "script_id": "v8:1:frame-a:8"},
            "event": {"category": "api", "name": name},
            "provenance": {"source": "native", "component": "fixture"},
            "detail": {"native_name": "Fixture.DynamicChild", "thread_id": 2},
        })
    trace.write_text("\n".join(json.dumps(row) for row in rows) + "\n", encoding="utf-8")
    _candidate(candidate, "a")
    result = source_match(trace, candidate)
    assert result["status"] == "matched"
    assert result["linked_api_events_reported_matches"] == 2
    assert result["matches"][0]["linked_api_event_count"] == 2
    assert {group["api"] for group in result["linked_api_groups"]} == {
        "Navigator.hardwareConcurrency.get", "<other-api>"}
    assert "private.example" not in json.dumps(result)


def test_dropped_events_suppress_linked_api_attribution(tmp_path: Path) -> None:
    trace, candidate = tmp_path / "trace.jsonl", tmp_path / "candidate.json"
    _trace(trace, "a")
    rows = [json.loads(line) for line in trace.read_text(encoding="utf-8").splitlines()]
    rows.extend([
        {
            "schema": "browser-core.trace-event/1", "run_id": "source-match-fixture",
            "seq": 2, "ts_monotonic_ns": 12, "dynamic_code_parent_seq": 1,
            "process": {"pid": 1, "type": "renderer"},
            "execution": {"context_id": "frame-a", "frame_id": "frame-a",
                          "script_id": "v8:1:frame-a:8"},
            "event": {"category": "api", "name": "Navigator.userAgent.get"},
            "provenance": {"source": "native", "component": "fixture"},
            "detail": {"native_name": "Fixture.DynamicChild", "thread_id": 2},
        },
        {
            "schema": "browser-core.trace-event/1", "run_id": "source-match-fixture",
            "seq": 3, "ts_monotonic_ns": 13,
            "process": {"pid": 1, "type": "renderer"},
            "event": {"category": "diagnostic", "name": "trace.dropped"},
            "provenance": {"source": "reader", "component": "fixture"},
            "detail": {"count": 1},
        },
    ])
    trace.write_text("\n".join(json.dumps(row) for row in rows) + "\n",
                     encoding="utf-8")
    _candidate(candidate, "a")

    result = source_match(trace, candidate)
    assert result["status"] == "matched"
    assert result["counts"]["matches"] == 1
    assert result["dropped_events"] == 1
    assert result["matches"][0]["linked_api_event_count"] == 0
    assert result["linked_api_events_reported_matches"] == 0
    assert result["linked_api_groups_total"] == 0
    assert result["linked_api_groups"] == []


def test_linked_api_distinct_group_limit_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    import browser_core.source_match as module

    trace, candidate = tmp_path / "trace.jsonl", tmp_path / "candidate.json"
    _trace(trace, "a")
    rows = [json.loads(line) for line in trace.read_text(encoding="utf-8").splitlines()]
    for seq in (2, 3, 4):
        rows.append({
            "schema": "browser-core.trace-event/1", "run_id": "source-match-fixture",
            "seq": seq, "ts_monotonic_ns": 10 + seq,
            "dynamic_code_parent_seq": 1,
            "process": {"pid": 1, "type": "renderer"},
            "execution": {"context_id": "frame-a", "frame_id": "frame-a",
                          "script_id": "v8:1:frame-a:8"},
            "event": {"category": "api", "name": f"Api.value{seq}"},
            "provenance": {"source": "native", "component": "fixture"},
            "detail": {"native_name": "Fixture.DynamicChild", "thread_id": 2},
        })
    trace.write_text("\n".join(json.dumps(row) for row in rows) + "\n", encoding="utf-8")
    _candidate(candidate, "a")
    monkeypatch.setattr(module, "MAX_LINKED_API_DISTINCT", 2, raising=False)

    with pytest.raises(ContractError, match="linked API groups exceed limit"):
        source_match(trace, candidate)

    rows.append({
        "schema": "browser-core.trace-event/1", "run_id": "source-match-fixture",
        "seq": 5, "ts_monotonic_ns": 15,
        "process": {"pid": 1, "type": "renderer"},
        "event": {"category": "diagnostic", "name": "trace.dropped"},
        "provenance": {"source": "reader", "component": "fixture"},
        "detail": {"count": 1},
    })
    trace.write_text("\n".join(json.dumps(row) for row in rows) + "\n", encoding="utf-8")
    result = source_match(trace, candidate)
    assert result["status"] == "matched"
    assert result["linked_api_events_reported_matches"] == 0
    assert result["linked_api_groups"] == []
