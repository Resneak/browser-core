"""Bounded, exact, stateless agent queries over saved private evidence."""
from __future__ import annotations

import base64
import copy
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from browser_core import evidence_query as query
from browser_core.contracts import ContractError
from browser_core.control_files import canonical_json_bytes, decode_strict_json_bytes
from browser_core.inspection import decode_rows
from browser_core.inspection_contract import CAPTURE_V1
from browser_core.inspection_history import history_filters, history_sql
from test_inspection_history import Decoder


ROOT = Path(__file__).resolve().parents[1]
BUILD = {
    "provenance": "attested-browser-core",
    "executable_sha256_16": "c" * 16,
    "runtime_bundle_sha256_16": "d" * 16,
    "attestation_created_at": "2026-09-15T00:00:00Z",
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


class FakeBundle:
    def __init__(self, state):
        self.state = state
        self.path = Path("C:/private-copy/recording.pftrace")
        self.sha256 = "a" * 64
        self.metadata = {
            "capture": CAPTURE_V1,
            "health": None,
            "recording": {
                "sha256": "b" * 64,
                "bytes": 123,
                "packets": 4,
                "source_bytes": 123,
                "excluded_tail_bytes": 0,
                "source_phase": "finalized-recording",
            },
        }
        self.source = SimpleNamespace(
            resolve=lambda: SimpleNamespace(
                reader_runtime={
                    "mode": "producer-build",
                    "producer_build": BUILD,
                    "reader_build": BUILD,
                }
            )
        )

    def close(self):
        self.state["bundle_closed"] += 1


class FakeInspection:
    def __init__(self, state, rows):
        self.state = state
        self.decoder = Decoder()
        for spec in rows:
            event_id, timestamp, api, value = spec
            self.decoder.add(event_id, timestamp, value=value)
            self.decoder.args[event_id + 1000]["debug.api"] = api
        self.health = None

    def read(self, *, limit):
        assert limit == 1
        return {
            "schema": CAPTURE_V1["schema"],
            "allowlist": CAPTURE_V1["allowlist"],
            "recording_health": copy.deepcopy(HEALTH),
        }

    def close(self):
        if not self.decoder.closed:
            self.decoder.close()
        self.state["inspector_closed"] += 1


@pytest.fixture
def installed(monkeypatch):
    state = {"bundle_closed": 0, "inspector_closed": 0}
    rows = [
        (1, 10, "Navigator.userAgent.get", "mentions Navigator.language.get"),
        (2, 20, "Navigator.language.get", "en-US"),
        (3, 30, "Navigator.userAgent.get", "fixture-agent"),
    ]

    monkeypatch.setattr(query, "OpenEvidence", lambda *args, **kwargs: FakeBundle(state))
    monkeypatch.setattr(
        query,
        "IncrementalInspection",
        lambda *args, **kwargs: FakeInspection(state, rows),
    )
    return state


def run_query(**kwargs):
    return query.evidence_query(
        Path("bundle.bcevidence"),
        ROOT,
        Path("C:/reader/chrome.exe"),
        expected_sha256="a" * 64,
        **kwargs,
    )


def test_failed_inspector_close_still_releases_verified_bundle(installed,monkeypatch):
    def unavailable(**kwargs):
        raise ContractError('inspector read failed')
    def failed_close():
        installed['inspector_closed'] += 1
        raise OSError('inspector close failed')
    monkeypatch.setattr(query,'IncrementalInspection',
                        lambda *args,**kwargs:SimpleNamespace(read=unavailable,close=failed_close))
    with pytest.raises(OSError,match='inspector close failed'):
        run_query()
    assert installed=={'bundle_closed':1,'inspector_closed':1}


def test_query_cannot_return_rendered_page_after_verified_copy_changes(installed,monkeypatch):
    bundle=FakeBundle(installed)
    original_resolve=bundle.source.resolve
    changed=[False]
    def resolve():
        if changed[0]:
            raise ContractError('verified evidence recording copy changed')
        return original_resolve()
    bundle.source.resolve=resolve
    monkeypatch.setattr(query,'OpenEvidence',lambda *args,**kwargs:bundle)
    original_bound=query._bounded_events
    def render_then_change(*args,**kwargs):
        result=original_bound(*args,**kwargs)
        changed[0]=True
        return result
    monkeypatch.setattr(query,'_bounded_events',render_then_change)
    with pytest.raises(ContractError,match='verified evidence recording copy changed'):
        run_query()
    assert installed=={'bundle_closed':1,'inspector_closed':1}


def test_exact_api_filter_is_not_a_payload_substring_search(installed):
    result = run_query(apis=["Navigator.language.get"])
    validator().validate(result)
    assert result["query"]["matching_events"] == "1"
    assert [event["event_id"] for event in result["events"]] == ["2"]
    assert result["query"]["filters"]["search"] == ""
    assert result["query"]["filters"]["apis"] == ["Navigator.language.get"]
    assert "parameters" not in result["events"][0]
    assert result["events"][0]["binding_realm"] == {
        "status": "not-recorded",
        "kind": "window",
        "reason": "native-context-metadata-not-recorded",
    }
    assert result["semantics"]["binding_realm_is_initiating_caller"] is False
    assert installed == {"bundle_closed": 1, "inspector_closed": 1}


def test_values_are_explicit_and_remain_decoder_validated(installed):
    result = run_query(apis=["Navigator.language.get"], include_values=True)
    validator().validate(result)
    event = result["events"][0]
    assert event["parameters"] == {"count": 0, "observed": []}
    assert event["result"] == {"type": "string", "length": 5, "value": "en-US"}
    assert result["semantics"]["private_values_included"] is True


def test_output_limit_returns_a_lossless_continuation(installed, monkeypatch):
    full = run_query(limit=3, include_values=True)
    monkeypatch.setattr(query, "MAX_OUTPUT_BYTES", query._rendered_size(full) - 1)
    limited = run_query(limit=3, include_values=True)
    validator().validate(limited)
    assert 0 < limited["query"]["returned_events"] < 3
    assert limited["query"]["output_limited"] is True
    assert limited["query"]["more_available"] is True
    assert limited["query"]["next_cursor"]
    assert query._rendered_size(limited) <= query.MAX_OUTPUT_BYTES

    continuation = run_query(
        limit=3,
        include_values=True,
        cursor=limited["query"]["next_cursor"],
    )
    validator().validate(continuation)
    assert {
        event["event_id"] for event in limited["events"]
    }.isdisjoint(event["event_id"] for event in continuation["events"])


def test_output_limit_counts_pretty_printed_windows_cli_bytes(installed,monkeypatch):
    import json

    full=run_query(limit=3,include_values=True)
    plain=len(json.dumps(full,indent=2,sort_keys=True,ensure_ascii=True,
                         allow_nan=False).encode('ascii'))
    monkeypatch.setattr(query,'MAX_OUTPUT_BYTES',plain)
    limited=run_query(limit=3,include_values=True)
    rendered=json.dumps(limited,indent=2,sort_keys=True,ensure_ascii=True,
                        allow_nan=False).encode('ascii')
    delivered=len(rendered)+rendered.count(b'\n')+2
    assert delivered<=query.MAX_OUTPUT_BYTES
    assert limited['query']['returned_events']<3


def test_continuation_is_bound_to_bundle_query_and_immutable_snapshot(installed):
    first = run_query(limit=1)
    assert first["query"]["more_available"] is True
    assert first["query"]["page"] == "first"
    assert first["events"][0]["event_id"] == "3"
    second = run_query(limit=1, cursor=first["query"]["next_cursor"])
    validator().validate(second)
    assert second["query"]["page"] == "continuation"
    assert second["query"]["matching_events"] == "3"
    assert second["events"][0]["event_id"] == "2"
    with pytest.raises(ContractError, match="different evidence"):
        run_query(limit=1, include_values=True, cursor=first["query"]["next_cursor"])


def test_exhausted_continuation_cannot_report_false_zero_population(installed):
    first = run_query(limit=1)
    assert first["query"]["matching_events"] == "3"
    exhausted = query.encode_cursor(
        first["bundle"]["sha256"], first["query"]["query_sha256"],
        int(first["query"]["snapshot_max_id"]), 0, 0)
    with pytest.raises(ContractError, match="cursor"):
        run_query(limit=1, cursor=exhausted)
    empty_first = run_query(start_ns="1000")
    validator().validate(empty_first)
    assert empty_first["events"] == []
    assert empty_first["query"]["matching_events"] == "0"
    assert installed == {"bundle_closed": 3, "inspector_closed": 3}


def test_short_first_page_cannot_claim_unreachable_matches(installed, monkeypatch):
    original = query.decode_rows

    def false_count(*args, **kwargs):
        rows, total = original(*args, **kwargs)
        return rows, total + 1

    monkeypatch.setattr(query, "decode_rows", false_count)
    with pytest.raises(ContractError, match="count disagrees"):
        run_query(apis=["Navigator.language.get"], limit=2)
    assert installed == {"bundle_closed": 1, "inspector_closed": 1}


def test_highwater_rejects_oversized_native_csv_before_accepting_boundary():
    decoder = SimpleNamespace(query=lambda *args, **kwargs: b"highwater\n1\n" + b"\n" * 200)
    with pytest.raises(ContractError, match="high-water"):
        query._highwater(decoder)


def test_continuation_count_must_include_earlier_rows(installed, monkeypatch):
    first = run_query(limit=2)
    original = query.decode_rows

    def false_count(*args, **kwargs):
        rows, _ = original(*args, **kwargs)
        return rows, len(rows)

    monkeypatch.setattr(query, "decode_rows", false_count)
    with pytest.raises(ContractError, match="count disagrees"):
        run_query(limit=2, cursor=first["query"]["next_cursor"])
    assert installed == {"bundle_closed": 2, "inspector_closed": 2}


def test_query_rejects_native_rows_out_of_order(installed, monkeypatch):
    original = query.decode_rows

    def reversed_rows(*args, **kwargs):
        rows, total = original(*args, **kwargs)
        rows.reverse()
        return rows, total

    monkeypatch.setattr(query, "decode_rows", reversed_rows)
    with pytest.raises(ContractError, match="order"):
        run_query(limit=3)
    assert installed == {"bundle_closed": 1, "inspector_closed": 1}


@pytest.mark.parametrize("mutation", ["highwater", "cursor"])
def test_query_rejects_native_rows_outside_page(installed, monkeypatch, mutation):
    first = run_query(limit=1)
    original = query.decode_rows

    def changed_row(*args, **kwargs):
        rows, total = original(*args, **kwargs)
        if rows:
            rows[0]["id"] = 4 if mutation == "highwater" else 3
            rows[0]["ts"] = 40 if mutation == "highwater" else 30
        return rows, total

    monkeypatch.setattr(query, "decode_rows", changed_row)
    with pytest.raises(ContractError, match="boundary"):
        run_query(limit=1, cursor=first["query"]["next_cursor"])


def test_cursor_rejects_modified_bundle_binding_without_echo(installed):
    cursor = run_query(limit=1)["query"]["next_cursor"]
    document = decode_strict_json_bytes(
        base64.urlsafe_b64decode(cursor), label="test cursor"
    )
    document["bundle_sha256"] = "f" * 64
    changed = base64.urlsafe_b64encode(canonical_json_bytes(document)).decode()
    with pytest.raises(ContractError) as exc:
        run_query(limit=1, cursor=changed)
    assert "f" * 64 not in str(exc.value)


def test_unknown_or_duplicate_apis_fail_and_cleanup(installed):
    with pytest.raises(ContractError, match="outside"):
        run_query(apis=["Unknown.private.API"])
    with pytest.raises(ContractError, match="duplicated"):
        run_query(apis=["Navigator.language.get", "Navigator.language.get"])
    assert installed == {"bundle_closed": 1, "inspector_closed": 0}


def test_history_api_literals_are_exact_and_injection_safe():
    decoder = Decoder()
    try:
        decoder.add(1, 1, value="private")
        filters = history_filters(apis=["Navigator.userAgent.get"])
        body = decoder.query(history_sql(filters, 1, limit=1), max_rows=2)
        rows, total = decode_rows(body, limit=2, capture=CAPTURE_V1)
        assert total == 1 and rows[0]["id"] == 1
        sql = history_sql(history_filters(apis=["A.B-C_get"]), 1, limit=1)
        assert "A.B-C_get" not in sql
    finally:
        decoder.close()


@pytest.mark.parametrize("bad", [[], ["a", "a"], ["x" * 257], ["' OR 1=1 --"], None])
def test_api_filter_contract_rejects_ambiguous_shapes(bad):
    if bad == []:
        assert "apis" not in history_filters(apis=bad)
    else:
        with pytest.raises(ContractError):
            history_filters(apis=bad)


def test_schema_rejects_private_payload_without_opt_in_and_promoted_claim(installed):
    result = run_query(apis=["Navigator.language.get"])
    changed = copy.deepcopy(result)
    changed["events"][0]["result"] = {"type": "string"}
    with pytest.raises(Exception):
        validator().validate(changed)
    changed = copy.deepcopy(result)
    changed["semantics"]["server_side_architecture_observed"] = True
    with pytest.raises(Exception):
        validator().validate(changed)


@pytest.mark.parametrize(
    "failure,code,exit_code",
    [
        (ContractError("private value"), "query-unavailable", 2),
        (OSError("private path"), "query-unavailable", 2),
        (KeyboardInterrupt(), "interrupted", 130),
    ],
)
def test_cli_errors_are_fixed_json(monkeypatch, capsys, failure, code, exit_code):
    from browser_core import cli

    def fail(*args, **kwargs):
        raise failure

    monkeypatch.setattr(query, "evidence_query", fail)
    command = [
        "trace", "evidence-query", "--bundle", "private-bundle",
        "--reader-executable", "private-reader",
    ]
    assert cli.main(command) == exit_code
    output = capsys.readouterr()
    assert json.loads(output.out) == {"schema": query.SCHEMA, "status": "error", "code": code}
    assert output.err == ""


def test_cli_threads_exact_scope_and_value_choice(monkeypatch, capsys):
    from browser_core import cli

    seen = []

    def read(*args, **kwargs):
        seen.append((args, kwargs))
        return {"schema": query.SCHEMA, "status": "ok"}

    monkeypatch.setattr(query, "evidence_query", read)
    command = [
        "trace", "evidence-query", "--bundle", "bundle",
        "--reader-executable", "reader", "--api", "Navigator.language.get",
        "--pid", "21", "--context-id", "AB" * 16, "--realm-id", "0",
        "--include-values", "--limit", "7",
    ]
    assert cli.main(command) == 0
    assert seen[0][1]["scope"] == {"pid": "21", "context_id": "AB" * 16, "realm_id": "0"}
    assert seen[0][1]["apis"] == ["Navigator.language.get"]
    assert seen[0][1]["include_values"] is True and seen[0][1]["limit"] == 7
    assert json.loads(capsys.readouterr().out)["status"] == "ok"
    assert cli.main([
        "trace", "evidence-query", "--bundle", "bundle",
        "--reader-executable", "reader", "--pid", "21",
    ]) == 2
    assert json.loads(capsys.readouterr().out)["code"] == "query-unavailable"
