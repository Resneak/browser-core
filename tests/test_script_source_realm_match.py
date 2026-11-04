from __future__ import annotations

import hashlib
import json
from pathlib import Path

from jsonschema import Draft202012Validator
import pytest

from browser_core.contracts import ContractError
from browser_core.script_source_realm_match import script_source_realm_match


SOURCE = "globalThis.realmValue = navigator.userAgent.length;\n"
DIGEST = hashlib.sha256(SOURCE.encode("utf-16le")).hexdigest()
A = "A" * 32
B = "B" * 32


def _source(seq: int, token: str | None, *, digest: str = DIGEST) -> dict:
    detail = {
        "native_name": "BrowserCore.ScriptSourceContext", "thread_id": 2,
        "script_id": 7, "source_length": len(SOURCE.encode("utf-16le")) // 2,
        "source_length_unit": "utf16-code-units",
        "compiler_input_hash_status": "observed",
        "compiler_input_utf16le_sha256": digest,
    }
    if token is not None:
        detail.update(v8_context_id=token, realm_id=0)
    return {
        "schema": "browser-core.trace-event/1", "run_id": "realm-fixture",
        "seq": seq, "ts_monotonic_ns": 10 + seq,
        "process": {"pid": 1, "type": "renderer"},
        "execution": {"context_id": "frame-a", "frame_id": "frame-a",
                      "script_id": "v8:1:frame-a:7"},
        "event": {"category": "execution", "name": "script.source.context"},
        "provenance": {"source": "native", "component": "blink.v8",
                       "trace_category": "browser_core.debug"},
        "detail": detail,
    }


def _run(seq: int, token: str | None) -> dict:
    detail = {"native_name": "BrowserCore.ScriptRun", "thread_id": 2}
    if token is not None:
        detail.update(v8_context_id=token, realm_id=0)
    return {
        "schema": "browser-core.trace-event/1", "run_id": "realm-fixture",
        "seq": seq, "ts_monotonic_ns": 10 + seq,
        "process": {"pid": 1, "type": "renderer"},
        "execution": {"context_id": "frame-a", "frame_id": "frame-a",
                      "script_id": "v8:1:frame-a:7"},
        "event": {"category": "execution", "name": "script.run"},
        "provenance": {"source": "native", "component": "blink.v8",
                       "trace_category": "browser_core.debug"},
        "detail": detail,
    }


def _api(seq: int, token: str) -> dict:
    return {
        "schema": "browser-core.trace-event/1", "run_id": "realm-fixture",
        "seq": seq, "ts_monotonic_ns": 10 + seq,
        "process": {"pid": 1, "type": "renderer"},
        "execution": {"context_id": "bindings:1:2", "frame_id": "bindings:1:2",
                      "script_id": "v8:1:bindings:2:7"},
        "event": {"category": "api", "name": "Navigator.userAgent.get"},
        "provenance": {"source": "native", "component": "blink.bindings.generated",
                       "trace_category": "blink.bindings"},
        "detail": {
            "native_name": "Navigator.userAgent.get", "thread_id": 2,
            "completion": "complete", "duration_ns": 10,
            "context_attribution": "unresolved",
            "script_attribution": "script-context-unresolved",
            "js_stack": {
                "schema": "browser-core.js-stack/1", "status": "observed",
                "v8_context_id": token, "realm_id": 0,
                "root_script_number": 7,
            },
        },
    }


def _drop(seq: int) -> dict:
    return {
        "schema": "browser-core.trace-event/1", "run_id": "realm-fixture",
        "seq": seq, "ts_monotonic_ns": 10 + seq,
        "process": {"pid": 1, "type": "renderer"},
        "event": {"category": "diagnostic", "name": "trace.dropped"},
        "provenance": {"source": "reader", "component": "fixture"},
        "detail": {"count": 1},
    }


def _match(tmp_path: Path, rows: list[dict]) -> dict:
    trace, candidate = tmp_path / "trace.jsonl", tmp_path / "source.js"
    trace.write_text("\n".join(json.dumps(row, sort_keys=True) for row in rows) + "\n",
                     encoding="utf-8")
    candidate.write_bytes(SOURCE.encode("utf-8"))
    return script_source_realm_match(
        trace, candidate_file=candidate,
        expected_trace_sha256=hashlib.sha256(trace.read_bytes()).hexdigest())


def test_realm_match_rejects_trace_changed_during_final_candidate_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import browser_core.script_source_realm_match as module

    trace = tmp_path / "trace.jsonl"
    candidate = tmp_path / "source.js"
    rows = [_source(0, A), _run(1, A), _api(2, A)]
    trace.write_text(
        "\n".join(json.dumps(row, sort_keys=True) for row in rows) + "\n",
        encoding="utf-8",
    )
    candidate.write_bytes(SOURCE.encode("utf-8"))
    trusted_digest = hashlib.sha256(trace.read_bytes()).hexdigest()
    alternate_body = (
        "\n".join(json.dumps(row, sort_keys=True) for row in [*rows, _api(3, A)])
        + "\n"
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
        script_source_realm_match(
            trace, candidate_file=candidate, expected_trace_sha256=trusted_digest
        )


@pytest.mark.parametrize("swapped_scan", [1, 2])
def test_realm_match_rejects_trace_swapped_during_either_scan(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, swapped_scan: int,
) -> None:
    import browser_core.script_source_realm_match as module

    trace, alternate, candidate = (
        tmp_path / "trace.jsonl", tmp_path / "alternate.jsonl", tmp_path / "source.js"
    )
    other_source = SOURCE.replace("realmValue", "realmVaLue")
    other_digest = hashlib.sha256(other_source.encode("utf-16le")).hexdigest()
    original_rows = [_source(0, A), _run(1, A), _api(2, A)]
    alternate_rows = [_source(0, A, digest=other_digest), _run(1, A), _api(2, A)]
    trace.write_text("\n".join(json.dumps(row, sort_keys=True) for row in original_rows) + "\n",
                     encoding="utf-8")
    alternate.write_text("\n".join(json.dumps(row, sort_keys=True) for row in alternate_rows)
                         + "\n", encoding="utf-8")
    trusted_digest = hashlib.sha256(trace.read_bytes()).hexdigest()
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
        script_source_realm_match(trace, candidate_file=candidate,
                                  expected_trace_sha256=trusted_digest)
    assert trace.read_bytes() == original_body


def test_realm_match_bounds_distinct_compatible_api_groups(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    import browser_core.script_source_realm_match as module

    apis = [_api(seq, A) for seq in (2, 3, 4)]
    for index, row in enumerate(apis):
        name = f"Navigator.fixture{index}.get"
        row["event"]["name"] = name
        row["detail"]["native_name"] = name
    monkeypatch.setattr(module, "MAX_REALM_API_DISTINCT", 2, raising=False)

    with pytest.raises(ContractError, match="compatible API groups exceed limit"):
        _match(tmp_path, [_source(0, A), _run(1, A), *apis])


def test_realm_match_drops_do_not_exhaust_unused_api_group_budget(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    import browser_core.script_source_realm_match as module

    apis = [_api(seq, A) for seq in (2, 3)]
    for index, row in enumerate(apis):
        name = f"Navigator.fixture{index}.get"
        row["event"]["name"] = name
        row["detail"]["native_name"] = name
    monkeypatch.setattr(module, "MAX_REALM_API_DISTINCT", 1)

    result = _match(tmp_path, [_source(0, A), _run(1, A), *apis, _drop(4)])
    assert result["status"] == "matched"
    row = result["matches"][0]
    assert row["run_link_status"] == "evidence-incomplete"
    assert row["api_link_status"] == "evidence-incomplete"
    assert row["compatible_api_count"] == 0
    assert row["compatible_api_groups"] == []


def test_realm_match_separates_same_frame_script_number_across_worlds(tmp_path: Path) -> None:
    result = _match(tmp_path, [_source(0, A), _run(1, A), _api(2, A),
                               _source(3, B), _run(4, B), _api(5, B)])
    assert result["status"] == "matched"
    assert result["counts"]["matches"] == 2
    assert [row["compatible_run_seqs"] for row in result["matches"]] == [[1], [4]]
    assert [row["compatible_api_seqs"] for row in result["matches"]] == [[2], [5]]
    assert all(row["api_link_status"] == "compatible-api-observed"
               for row in result["matches"])
    assert DIGEST not in json.dumps(result)
    assert SOURCE not in json.dumps(result)
    schema = json.loads((Path(__file__).parents[1] /
                         "schemas/script-source-realm-match-v1.schema.json").read_text(
                             encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(result)


def test_realm_match_excludes_api_from_other_world(tmp_path: Path) -> None:
    row = _match(tmp_path, [_source(0, A), _run(1, A), _api(2, B)])["matches"][0]
    assert row["compatible_run_seqs"] == [1]
    assert row["compatible_api_count"] == 0
    assert row["api_link_status"] == "no-compatible-api-observed"


def test_realm_match_keeps_reported_world_when_other_source_reuses_base(tmp_path: Path) -> None:
    other = _source(3, B, digest="0" * 64)
    row = _match(tmp_path, [_source(0, A), _run(1, A), _api(2, A), other])["matches"][0]
    assert row["compatible_run_seqs"] == [1]
    assert row["compatible_api_seqs"] == [2]
    assert row["run_link_status"] == "compatible-run-observed"
    assert row["api_link_status"] == "compatible-api-observed"


def test_realm_match_ignores_generic_api_stack_metadata(tmp_path: Path) -> None:
    forged = _api(1, A)
    forged["event"]["name"] = "Fixture.read"
    forged["provenance"] = {"source": "fixture", "component": "fixture"}
    forged["detail"]["native_name"] = "Fixture.read"
    row = _match(tmp_path, [_source(0, A), forged])["matches"][0]
    assert row["compatible_api_count"] == 0
    assert row["api_link_status"] == "no-compatible-api-observed"


def test_realm_match_ignores_generic_api_without_detail(tmp_path: Path) -> None:
    generic = _api(1, A)
    generic["event"]["name"] = "Fixture.read"
    generic["provenance"] = {"source": "fixture", "component": "fixture"}
    del generic["detail"]
    row = _match(tmp_path, [_source(0, A), generic])["matches"][0]
    assert row["compatible_api_count"] == 0


def test_realm_match_preserves_old_source_without_claiming_links(tmp_path: Path) -> None:
    row = _match(tmp_path, [_source(0, None), _run(1, None), _api(2, A)])["matches"][0]
    assert row["realm_status"] == "unavailable"
    assert row["run_link_status"] == "realm-unavailable"
    assert row["api_link_status"] == "realm-unavailable"
    assert row["compatible_run_count"] == row["compatible_api_count"] == 0


def test_realm_match_drops_suppress_both_links(tmp_path: Path) -> None:
    result = _match(tmp_path, [_source(0, A), _run(1, A), _api(2, A), _drop(3)])
    assert result["dropped_events"] == 1
    row = result["matches"][0]
    assert row["run_link_status"] == "evidence-incomplete"
    assert row["api_link_status"] == "evidence-incomplete"
    assert row["compatible_run_count"] == row["compatible_api_count"] == 0


def test_realm_match_reused_full_key_suppresses_both_links(tmp_path: Path) -> None:
    rows = [_source(0, A), _run(1, A), _api(2, A),
            _source(3, A, digest="0" * 64), _run(4, A), _api(5, A)]
    row = _match(tmp_path, rows)["matches"][0]
    assert row["run_link_status"] == "ambiguous-realm-script-id"
    assert row["api_link_status"] == "ambiguous-realm-script-id"
    assert row["compatible_run_count"] == row["compatible_api_count"] == 0


def test_realm_match_reused_api_key_across_frames_suppresses_api_only(
    tmp_path: Path,
) -> None:
    other = _source(2, A, digest="0" * 64)
    other["execution"] = {
        "context_id": "frame-b", "frame_id": "frame-b",
        "script_id": "v8:1:frame-b:7",
    }
    row = _match(tmp_path, [_source(0, A), _run(1, A), other, _api(3, A)])["matches"][0]
    assert row["run_link_status"] == "compatible-run-observed"
    assert row["compatible_run_seqs"] == [1]
    assert row["api_link_status"] == "ambiguous-realm-script-id"
    assert row["compatible_api_count"] == 0
    assert row["compatible_api_seqs"] == []


def test_realm_match_unresolved_source_key_suppresses_enriched_links(tmp_path: Path) -> None:
    rows = [_source(0, A), _run(1, A), _api(2, A),
            _source(3, None, digest="0" * 64)]
    row = _match(tmp_path, rows)["matches"][0]
    assert row["run_link_status"] == "ambiguous-realm-script-id"
    assert row["api_link_status"] == "ambiguous-realm-script-id"


@pytest.mark.parametrize("field", ["seq", "ts_monotonic_ns", "pid", "thread_id"])
def test_realm_match_rejects_source_identity_outside_wire_schema(
    tmp_path: Path, field: str
) -> None:
    source = _source(0, A)
    if field == "pid":
        source["process"]["pid"] = 2**53
        source["execution"]["script_id"] = "v8:9007199254740992:frame-a:7"
    elif field == "thread_id":
        source["detail"]["thread_id"] = 2**53
    else:
        source[field] = 2**53
    with pytest.raises(ContractError, match="source match output integer exceeds limit"):
        _match(tmp_path, [source])


def test_realm_match_rejects_context_outside_wire_schema(tmp_path: Path) -> None:
    source = _source(0, A)
    context = "f" * 257
    source["execution"] = {"context_id": context, "frame_id": context,
                           "script_id": f"v8:1:{context}:7"}
    with pytest.raises(ContractError, match="source match output context exceeds limit"):
        _match(tmp_path, [source])


@pytest.mark.parametrize("related", [_run, _api])
def test_realm_match_rejects_related_sequence_outside_wire_schema(
    tmp_path: Path, related
) -> None:
    with pytest.raises(ContractError, match="source match output integer exceeds limit"):
        _match(tmp_path, [_source(0, A), related(2**53, A)])
