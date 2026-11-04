"""Agent-safe exact queries over a verified research-session snapshot."""
from __future__ import annotations

import copy
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from browser_core import session_query as query
from browser_core.contracts import ContractError
from browser_core.inspection_contract import CAPTURE_V1
from test_inspection_history import Decoder


ROOT = Path(__file__).resolve().parents[1]
RUN_ID = "core-20260915T030000Z-session-query"
SESSION = Path(f"C:/research/sessions/{RUN_ID}.json")
BUILD = {
    "provenance": "attested-browser-core",
    "executable_sha256_16": "c" * 16,
    "runtime_bundle_sha256_16": "d" * 16,
    "attestation_created_at": "2026-09-15T03:00:00Z",
}
READER_RUNTIME = {
    "mode": "producer-build",
    "producer_build": BUILD,
    "reader_build": BUILD,
}
HEALTH = {
    "status": "no-issues-reported",
    "capture_stats_seen": True,
    "counters_truncated": False,
    "sorter_dropped_events": 0,
    "proves_complete": False,
    "counters": [],
}


def validator():
    import jsonschema

    schema = json.loads((ROOT / "schemas" / "evidence-query-v1.schema.json").read_text())
    jsonschema.Draft202012Validator.check_schema(schema)
    return jsonschema.Draft202012Validator(schema)


class FakeSource:
    def __init__(self, state):
        self.state = state

    def resolve(self):
        self.state["resolved"] += 1
        return SimpleNamespace(session={"run_id": RUN_ID, "value_capture":CAPTURE_V1})


class FakeInspection:
    def __init__(self, state, source):
        self.state = state
        self.source = source
        self.run_id = RUN_ID
        self.decoder = Decoder()
        for event_id, timestamp, api, value in (
            (1, 10, "Navigator.userAgent.get", "agent"),
            (2, 20, "Navigator.language.get", "en-US"),
            (3, 30, "Navigator.userAgent.get", "agent-two"),
        ):
            self.decoder.add(event_id, timestamp, value=value)
            self.decoder.args[event_id + 1000]["debug.api"] = api

    def read(self, *, limit):
        assert limit == 1
        return {
            **CAPTURE_V1,
            "run_id": RUN_ID,
            "source_sha256": "a" * 64,
            "snapshot_bytes": 4096,
            "source_bytes": 4100,
            "pending_source_bytes": 4,
            "packets": 12,
            "incomplete_tail_bytes": 4,
            "source_phase": "live-prefix",
            "catching_up": False,
            "complete": False,
            "recording_settled": False,
            "browser_running": True,
            "decoder_pending_possible": True,
            "reader_runtime": copy.deepcopy(READER_RUNTIME),
            "recording_health": copy.deepcopy(HEALTH),
        }

    def close(self):
        if not self.decoder.closed:
            self.decoder.close()
        self.state["closed"] += 1


@pytest.fixture
def installed(monkeypatch):
    state = {"source_created": 0, "resolved": 0, "closed": 0}
    sources = []

    def make_source(*args, **kwargs):
        state["source_created"] += 1
        source = FakeSource(state)
        sources.append(source)
        return source

    monkeypatch.setattr(query, "RecordingSource", make_source)
    monkeypatch.setattr(
        query,
        "IncrementalInspection",
        lambda session, root, source: FakeInspection(state, source),
    )
    return state


def run_query(**kwargs):
    return query.session_query(
        SESSION,
        ROOT,
        expected_run_id=RUN_ID,
        **kwargs,
    )


def test_metadata_query_is_exact_bound_and_read_only(installed):
    result = run_query(apis=["Navigator.language.get"])
    validator().validate(result)
    assert result["session"] == {
        "run_id": RUN_ID,
        "binding": "verified-session-and-recording-identity",
    }
    assert result["query"]["matching_events"] == "1"
    assert [event["event_id"] for event in result["events"]] == ["2"]
    assert "parameters" not in result["events"][0]
    assert result["snapshot"]["browser_running"] is True
    assert result["snapshot"]["complete"] is False
    assert result["semantics"]["query_launched_browser"] is False
    assert result["semantics"]["session_reference_authorizes_control"] is False
    assert installed == {"source_created": 1, "resolved": 2, "closed": 1}


def test_private_values_require_explicit_selection(installed):
    result = run_query(apis=["Navigator.language.get"], include_values=True)
    validator().validate(result)
    assert result["events"][0]["parameters"] == {"count": 0, "observed": []}
    assert result["events"][0]["result"]["value"] == "en-US"
    assert result["semantics"]["private_values_included"] is True


def test_no_live_recording_has_an_actionable_mode_error(installed,monkeypatch):
    from browser_core.metadata_query import MetadataQueryError
    def no_recording(self):raise ContractError('session has no live recording')
    monkeypatch.setattr(FakeSource,'resolve',no_recording)
    with pytest.raises(MetadataQueryError,match='session-recording-unavailable'):
        run_query()


def test_run_and_filename_binding_precede_session_access(installed):
    with pytest.raises(ContractError, match="run binding"):
        query.session_query(SESSION, ROOT, expected_run_id="different-run")
    with pytest.raises(ContractError, match="run binding"):
        query.session_query(
            Path("C:/research/sessions/different-name.json"),
            ROOT,
            expected_run_id=RUN_ID,
        )
    assert installed["source_created"] == 0


def test_unknown_api_and_changed_run_close_the_reader(installed, monkeypatch):
    with pytest.raises(ContractError, match="outside"):
        run_query(apis=["Unknown.private.API"])
    assert installed["closed"] == 1

    original = query.IncrementalInspection

    def changed(session, root, source):
        inspector = original(session, root, source)
        inspector.run_id = "different-run"
        return inspector

    monkeypatch.setattr(query, "IncrementalInspection", changed)
    with pytest.raises(ContractError, match="run binding changed"):
        run_query()
    assert installed["closed"] == 2


def test_output_limit_trims_at_an_event_boundary(installed, monkeypatch):
    full = run_query(limit=3, include_values=True)
    monkeypatch.setattr(query, "MAX_OUTPUT_BYTES", query._cli_rendered_size(full) - 1)
    limited = run_query(limit=3, include_values=True)
    validator().validate(limited)
    assert 0 < limited["query"]["returned_events"] < 3
    assert limited["query"]["output_limited"] is True
    assert limited["query"]["more_available"] is True
    assert limited["query"]["continuation"] == "not-available-for-mutable-session-snapshot"
    assert query._cli_rendered_size(limited) <= query.MAX_OUTPUT_BYTES


def test_output_cap_includes_windows_newlines_and_final_line(installed,monkeypatch):
    import json

    full=run_query(limit=3,include_values=True)
    plain=len(json.dumps(full,indent=2,sort_keys=True,ensure_ascii=True,
                         allow_nan=False).encode('ascii'))
    monkeypatch.setattr(query,'MAX_OUTPUT_BYTES',plain)
    limited=run_query(limit=3,include_values=True)
    rendered=json.dumps(limited,indent=2,sort_keys=True,ensure_ascii=True,
                        allow_nan=False).encode('ascii')
    assert len(rendered)+rendered.count(b'\n')+2<=query.MAX_OUTPUT_BYTES
    assert limited['query']['returned_events']<3


@pytest.mark.parametrize("mutation", ["reversed", "highwater"])
def test_session_query_rejects_native_rows_outside_fixed_page(installed, monkeypatch, mutation):
    original = query.decode_rows

    def changed_rows(*args, **kwargs):
        rows, total = original(*args, **kwargs)
        if mutation == "reversed":
            rows.reverse()
        elif rows:
            rows[0]["id"] = 4
        return rows, total

    monkeypatch.setattr(query, "decode_rows", changed_rows)
    with pytest.raises(ContractError, match="order|boundary"):
        run_query(limit=3)
    assert installed == {"source_created": 1, "resolved": 1, "closed": 1}


def test_session_query_rejects_inflated_population_for_a_short_page(installed, monkeypatch):
    original = query.decode_rows

    def inflated_total(*args, **kwargs):
        rows, total = original(*args, **kwargs)
        return rows, total + 1

    monkeypatch.setattr(query, "decode_rows", inflated_total)
    with pytest.raises(ContractError, match="population"):
        run_query(limit=3)
    assert installed == {"source_created": 1, "resolved": 1, "closed": 1}


def test_schema_rejects_private_payload_and_promoted_authority(installed):
    result = run_query()
    changed = copy.deepcopy(result)
    changed["events"][0]["result"] = {"type": "string"}
    with pytest.raises(Exception):
        validator().validate(changed)
    changed = copy.deepcopy(result)
    changed["semantics"]["session_reference_authorizes_control"] = True
    with pytest.raises(Exception):
        validator().validate(changed)


def test_cli_threads_run_binding_scope_and_values(monkeypatch, capsys):
    from browser_core import cli

    seen = []

    def read(*args, **kwargs):
        seen.append((args, kwargs))
        return {"schema": "browser-core.evidence-query/1", "status": "ok"}

    monkeypatch.setattr(query, "session_query", read)
    command = [
        "trace", "session-query", "--session", str(SESSION),
        "--expected-run-id", RUN_ID, "--api", "Navigator.language.get",
        "--pid", "21", "--context-id", "AB" * 16, "--realm-id", "0",
        "--include-values", "--limit", "7",
    ]
    assert cli.main(command) == 0
    assert seen[0][1]["expected_run_id"] == RUN_ID
    assert seen[0][1]["scope"] == {
        "pid": "21",
        "context_id": "AB" * 16,
        "realm_id": "0",
    }
    assert seen[0][1]["include_values"] is True
    assert json.loads(capsys.readouterr().out)["status"] == "ok"

    assert cli.main([
        "trace", "session-query", "--session", str(SESSION),
        "--expected-run-id", RUN_ID, "--pid", "21",
    ]) == 2
    output = capsys.readouterr()
    assert json.loads(output.out) == {
        "schema": "browser-core.evidence-query/1",
        "status": "error",
        "code": "query-unavailable",
    }
    assert output.err == ""
