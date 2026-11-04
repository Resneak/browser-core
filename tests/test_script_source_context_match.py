from __future__ import annotations

import hashlib
import json
from pathlib import Path

from jsonschema import Draft202012Validator
import pytest

from browser_core.contracts import ContractError, validate_trace_event
from browser_core.script_source_context_match import script_source_context_match


SOURCE = "globalThis.sharedFrameValue = 5;\n"
DIGEST = hashlib.sha256(SOURCE.encode("utf-16le")).hexdigest()


def _source(seq: int, context: str, *, digest: str = DIGEST) -> dict:
    return {
        "schema": "browser-core.trace-event/1", "run_id": "context-fixture",
        "seq": seq, "ts_monotonic_ns": 10 + seq,
        "process": {"pid": 1, "type": "renderer"},
        "execution": {"context_id": context, "frame_id": context,
                      "script_id": f"v8:1:{context}:7"},
        "event": {"category": "execution", "name": "script.source.context"},
        "provenance": {"source": "native", "component": "blink.v8",
                       "trace_category": "browser_core.debug"},
        "detail": {
            "native_name": "BrowserCore.ScriptSourceContext", "thread_id": 2,
            "script_id": 7, "source_length": len(SOURCE.encode("utf-16le")) // 2,
            "source_length_unit": "utf16-code-units",
            "compiler_input_hash_status": "observed",
            "compiler_input_utf16le_sha256": digest,
        },
    }


def _run(seq: int, context: str) -> dict:
    return {
        "schema": "browser-core.trace-event/1", "run_id": "context-fixture",
        "seq": seq, "ts_monotonic_ns": 10 + seq,
        "process": {"pid": 1, "type": "renderer"},
        "execution": {"context_id": context, "frame_id": context,
                      "script_id": f"v8:1:{context}:7"},
        "event": {"category": "execution", "name": "script.run"},
        "provenance": {"source": "native", "component": "blink.v8",
                       "trace_category": "browser_core.debug"},
        "detail": {"native_name": "BrowserCore.ScriptRun", "thread_id": 2},
    }


def _write(path: Path, rows: list[dict]) -> str:
    path.write_text("\n".join(json.dumps(row, sort_keys=True) for row in rows) + "\n",
                    encoding="utf-8")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_context_match_rejects_trace_changed_during_final_candidate_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import browser_core.script_source_context_match as module

    trace = tmp_path / "trace.jsonl"
    candidate = tmp_path / "source.js"
    rows = [_source(0, "frame-a"), _run(1, "frame-a")]
    trusted_digest = _write(trace, rows)
    candidate.write_bytes(SOURCE.encode("utf-8"))
    alternate_body = (
        "\n".join(
            json.dumps(row, sort_keys=True)
            for row in [*rows, _run(2, "frame-a")]
        ) + "\n"
    ).encode("utf-8")
    original_read = module.read_bounded_control_snapshot_result

    def change_after_candidate_read(path: Path, **kwargs):  # noqa: ANN201
        snapshot = original_read(path, **kwargs)
        if path == candidate:
            trace.write_bytes(alternate_body)
        return snapshot

    monkeypatch.setattr(
        module, "read_bounded_control_snapshot_result", change_after_candidate_read
    )
    with pytest.raises(ContractError, match="normalized trace changed"):
        script_source_context_match(
            trace, candidate_file=candidate, expected_trace_sha256=trusted_digest
        )


@pytest.mark.parametrize("swapped_scan", [1, 2])
def test_context_match_rejects_trace_swapped_during_either_scan(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, swapped_scan: int,
) -> None:
    import browser_core.script_source_context_match as module

    trace, alternate, candidate = (
        tmp_path / "trace.jsonl", tmp_path / "alternate.jsonl", tmp_path / "source.js"
    )
    other_source = SOURCE.replace("5", "6")
    other_digest = hashlib.sha256(other_source.encode("utf-16le")).hexdigest()
    trusted_digest = _write(trace, [_source(0, "frame-a"), _run(1, "frame-a")])
    _write(alternate, [_source(0, "frame-a", digest=other_digest), _run(1, "frame-a")])
    candidate.write_bytes((other_source if swapped_scan == 1 else SOURCE).encode("utf-8"))
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
        script_source_context_match(trace, candidate_file=candidate,
                                    expected_trace_sha256=trusted_digest)
    assert trace.read_bytes() == original_body


def test_context_match_distinguishes_repeated_script_id_across_frames(tmp_path: Path) -> None:
    trace, candidate = tmp_path / "trace.jsonl", tmp_path / "source.js"
    candidate.write_bytes(SOURCE.encode("utf-8"))
    digest = _write(trace, [_source(0, "frame-a"), _run(1, "frame-a"),
                            _source(2, "frame-b"), _run(3, "frame-b")])
    result = script_source_context_match(
        trace, candidate_file=candidate, expected_trace_sha256=digest)
    assert result["status"] == "matched"
    assert result["trusted_digest_matched"] is True
    assert result["counts"]["matches"] == 2
    assert [row["context_id"] for row in result["matches"]] == ["frame-a", "frame-b"]
    assert [row["compatible_run_seqs"] for row in result["matches"]] == [[1], [3]]
    assert all(row["run_link_status"] == "compatible-run-observed"
               for row in result["matches"])
    assert DIGEST not in json.dumps(result)
    assert SOURCE not in json.dumps(result)


def test_context_match_suppresses_reused_key_even_with_different_digest(tmp_path: Path) -> None:
    trace, candidate = tmp_path / "trace.jsonl", tmp_path / "source.js"
    candidate.write_bytes(SOURCE.encode("utf-8"))
    rows = [_source(0, "frame-a"), _run(1, "frame-a"),
            _source(2, "frame-a", digest="0" * 64), _run(3, "frame-a")]
    _write(trace, rows)
    result = script_source_context_match(trace, candidate_file=candidate)
    assert result["counts"]["matches"] == 1
    assert result["matches"][0]["run_link_status"] == "ambiguous-context-script-id"
    assert result["matches"][0]["compatible_run_seqs"] == []


def test_context_match_requires_strictly_later_run(tmp_path: Path) -> None:
    trace, candidate = tmp_path / "trace.jsonl", tmp_path / "source.js"
    candidate.write_bytes(SOURCE.encode("utf-8"))
    rows = [_source(0, "frame-a"), _run(1, "frame-a")]
    rows[1]["ts_monotonic_ns"] = rows[0]["ts_monotonic_ns"]
    _write(trace, rows)
    result = script_source_context_match(trace, candidate_file=candidate)
    assert result["matches"][0]["run_link_status"] == "no-compatible-run-observed"


def test_context_match_drops_suppress_run_attribution(tmp_path: Path) -> None:
    trace, candidate = tmp_path / "trace.jsonl", tmp_path / "source.js"
    candidate.write_bytes(SOURCE.encode("utf-8"))
    rows = [_source(0, "frame-a"), _run(1, "frame-a"), {
        "schema": "browser-core.trace-event/1", "run_id": "context-fixture",
        "seq": 2, "ts_monotonic_ns": 12,
        "process": {"pid": 1, "type": "renderer"},
        "event": {"category": "diagnostic", "name": "trace.dropped"},
        "provenance": {"source": "reader", "component": "fixture"},
        "detail": {"count": 1},
    }]
    _write(trace, rows)
    result = script_source_context_match(trace, candidate_file=candidate)
    assert result["status"] == "matched"
    assert result["dropped_events"] == 1
    assert result["matches"][0]["run_link_status"] == "run-evidence-incomplete"
    assert result["matches"][0]["compatible_run_count"] == 0
    assert result["matches"][0]["compatible_run_seqs"] == []
    schema = json.loads((Path(__file__).parents[1] /
                         "schemas/script-source-context-match-v1.schema.json").read_text(
                             encoding="utf-8"))
    Draft202012Validator(schema).validate(result)


def test_context_match_drops_skip_unreportable_run_sequence(tmp_path: Path) -> None:
    trace, candidate = tmp_path / "trace.jsonl", tmp_path / "source.js"
    candidate.write_bytes(SOURCE.encode("utf-8"))
    run = _run(2**53, "frame-a")
    rows = [_source(0, "frame-a"), run, {
        "schema": "browser-core.trace-event/1", "run_id": "context-fixture",
        "seq": 2**53 + 1, "ts_monotonic_ns": run["ts_monotonic_ns"] + 1,
        "process": {"pid": 1, "type": "renderer"},
        "event": {"category": "diagnostic", "name": "trace.dropped"},
        "provenance": {"source": "reader", "component": "fixture"},
        "detail": {"count": 1},
    }]
    _write(trace, rows)

    result = script_source_context_match(trace, candidate_file=candidate)
    assert result["status"] == "matched"
    assert result["matches"][0]["run_link_status"] == "run-evidence-incomplete"
    assert result["matches"][0]["compatible_run_seqs"] == []


def test_context_match_schema_and_absent_event(tmp_path: Path) -> None:
    schema = json.loads((Path(__file__).parents[1] /
                         "schemas/script-source-context-match-v1.schema.json").read_text(
                             encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema)
    trace, candidate = tmp_path / "trace.jsonl", tmp_path / "source.js"
    candidate.write_bytes(SOURCE.encode("utf-8"))
    _write(trace, [_run(0, "frame-a")])
    result = script_source_context_match(trace, candidate_file=candidate)
    assert result["status"] == "digest-unavailable"
    validator.validate(result)
    validator.validate({"schema": "browser-core.script-source-context-match/1",
                        "status": "error", "code": "script-source-context-match-unavailable"})


@pytest.mark.parametrize("case", ["source-timestamp", "run-seq"])
def test_context_match_rejects_reported_integer_outside_wire_schema(
    tmp_path: Path, case: str,
) -> None:
    trace, candidate = tmp_path / "trace.jsonl", tmp_path / "source.js"
    candidate.write_bytes(SOURCE.encode("utf-8"))
    rows = [_source(0, "frame-a")]
    if case == "source-timestamp":
        rows[0]["ts_monotonic_ns"] = 2**53
    else:
        run = _run(1, "frame-a")
        run["seq"] = 2**53
        rows.append(run)
    _write(trace, rows)

    with pytest.raises(ContractError, match="source match output integer exceeds limit"):
        script_source_context_match(trace, candidate_file=candidate)


def test_context_match_rejects_context_outside_wire_schema(tmp_path: Path) -> None:
    trace, candidate = tmp_path / "trace.jsonl", tmp_path / "source.js"
    candidate.write_bytes(SOURCE.encode("utf-8"))
    source = _source(0, "f" * 257)
    validate_trace_event(source)
    _write(trace, [source])

    with pytest.raises(ContractError, match="source match output context exceeds limit"):
        script_source_context_match(trace, candidate_file=candidate)


def test_context_event_rejects_conflicting_frame_and_digest() -> None:
    event = _source(0, "frame-a")
    assert validate_trace_event(event)["execution"]["context_id"] == "frame-a"
    event["execution"]["frame_id"] = "frame-b"
    with pytest.raises(ContractError, match="script source context metadata"):
        validate_trace_event(event)
    event["execution"]["frame_id"] = "frame-a"
    event["detail"]["compiler_input_hash_status"] = "over-limit"
    with pytest.raises(ContractError, match="script source context digest"):
        validate_trace_event(event)
