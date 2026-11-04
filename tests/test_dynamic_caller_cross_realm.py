"""Unique caller identity is independent of enclosing callback/Promise context."""
from copy import deepcopy
import hashlib
import json

import pytest

from browser_core import metadata_inventory_query, metadata_query, metadata_rows, perfetto
from browser_core.contracts import ContractError
from browser_core.inspection_history import history_filters
from browser_core.trace import validate_trace
from test_evidence_bundle import BODY
from test_metadata_workflow import source
from test_dynamic_caller_scopes import assert_unresolved
from test_perfetto import (REVISION, csv_rows_fixture, dynamic_code_row,
                          host_callback_row, promise_microtask_row, script_run_row)


def rows(mode="both", kind="eval"):
    population = [
        script_run_row(context_id="A", native_id="script:A:7"),
        script_run_row(ts_monotonic_ns="110", context_id="B", script_id="9",
                       native_id="script:B:9"),
    ]
    if mode in {"promise", "both"}:
        population.append(promise_microtask_row(context_id="B"))
    if mode in {"callback", "both"}:
        population.append(host_callback_row(context_id="B", script_id="9",
                                             native_parent_id="script:B:9", duration_ns="100"))
    population.append(dynamic_code_row(ts_monotonic_ns="220", dynamic_kind=kind))
    return population


def decode(population, run_id="independent-s5-audit", revision=REVISION):
    return perfetto.parse_export_csv(csv_rows_fixture(population), run_id, revision)


def validate(events, tmp_path):
    path = tmp_path / "events.jsonl"
    path.write_text("\n".join(json.dumps(event) for event in events) + "\n", encoding="utf-8")
    return validate_trace(path)


@pytest.mark.parametrize("kind", ["eval", "function-constructor"])
@pytest.mark.parametrize("mode", ["callback", "promise", "both"])
def test_unique_cross_realm_scopes_preserve_caller_and_containment(kind, mode, tmp_path):
    # Reconstruct the six independent P2 witnesses without depending on captures.
    events = decode(rows(mode, kind))
    original = deepcopy(events)
    child = events[-1]
    assert child["causal_parent_seq"] == 0
    assert child["execution"] == events[0]["execution"]
    assert child["execution"]["context_id"] == "A"
    for key in ("callback_parent_seq", "promise_parent_seq"):
        expected = mode == "both" or mode == key.split("_")[0]
        assert (key in child) == expected
        if expected:
            assert events[child[key]]["execution"]["context_id"] == "B"
    assert validate(events, tmp_path)["events"] == len(events)
    assert events == original


@pytest.mark.parametrize("scope", ["callback", "promise"])
@pytest.mark.parametrize("mutation", ["pid", "thread", "missing", "non-scope", "expired", "future", "before-start"])
def test_cross_realm_dynamic_keeps_scope_identity_and_time_checks(scope, mutation, tmp_path):
    events = decode(rows(scope))
    child, parent = events[-1], events[2]
    key = scope + "_parent_seq"
    if mutation == "pid":
        child["process"]["pid"] = 44
        child["execution"]["script_id"] = "v8:44:A:7"
    elif mutation == "thread":
        child["detail"]["thread_id"] = 45
    elif mutation == "missing":
        events.pop(2)
    elif mutation == "non-scope":
        child[key] = 0
    elif mutation == "expired":
        parent["detail"]["duration_ns"] = child["ts_monotonic_ns"] - parent["ts_monotonic_ns"]
    elif mutation == "future":
        child[key] = child["seq"] + 1
    else:
        child["ts_monotonic_ns"] = parent["ts_monotonic_ns"] - 1
    with pytest.raises(ContractError, match="scope|earlier|timestamp regressed"):
        validate(events, tmp_path)


@pytest.mark.parametrize("mutation", ["wrong-parent", "wrong-context", "wrong-script",
                                       "missing-parent", "missing-execution", "wrong-provenance"])
def test_cross_realm_dynamic_still_requires_independent_exact_caller(mutation, tmp_path):
    events = decode(rows())
    child = events[-1]
    if mutation == "wrong-parent":
        child["causal_parent_seq"] = 1
    elif mutation == "wrong-context":
        child["execution"] = {"context_id": "C", "frame_id": "C", "script_id": "v8:42:C:7"}
    elif mutation == "wrong-script":
        child["execution"]["script_id"] = "v8:42:A:9"
    elif mutation == "missing-parent":
        child.pop("causal_parent_seq")
        child.pop("execution")
        child["detail"]["caller_parent_status"] = "script_parent_not_in_trace"
    elif mutation == "missing-execution":
        child.pop("execution")
    else:
        child["provenance"]["source"] = "fixture"
    with pytest.raises(ContractError, match="caller|dynamic code metadata"):
        validate(events, tmp_path)


def test_cross_realm_dynamic_requires_latest_same_realm_script_parent(tmp_path):
    events = decode(rows())
    repeat = deepcopy(events[0])
    repeat.update(seq=1, ts_monotonic_ns=105)
    for event in events[1:]:
        event["seq"] += 1
        for key in ("causal_parent_seq", "callback_parent_seq", "promise_parent_seq"):
            if key in event and event[key] != 0:
                event[key] += 1
    events.insert(1, repeat)
    with pytest.raises(ContractError, match="not its matching script run"):
        validate(events, tmp_path)
    events[-1]["causal_parent_seq"] = 1
    assert validate(events, tmp_path)["events"] == len(events)


@pytest.mark.parametrize("mode", ["callback", "promise", "both"])
def test_cross_realm_scopes_cannot_resolve_multiple_caller_realms(mode, tmp_path):
    population = rows(mode)
    population.insert(2, script_run_row(ts_monotonic_ns="120", context_id="C", native_id="script:C:7"))
    assert_unresolved(decode(population))
    events = decode(population[:-1])
    child = decode(rows(mode))[-1]
    child["seq"] += 1
    for key in ("callback_parent_seq", "promise_parent_seq"):
        if key in child:
            child[key] += 1
    events.append(child)
    with pytest.raises(ContractError, match="not its matching script run"):
        validate(events, tmp_path)


@pytest.mark.parametrize("scope", ["callback", "promise"])
@pytest.mark.parametrize("event_identity", [
    {"category": "execution", "name": "script.run"},
    {"category": "api", "name": "dynamic.code.materialized"},
    {"category": "execution", "name": "dynamic.code.materialized.other"},
])
def test_other_event_kinds_keep_scope_context_equality(scope, event_identity, tmp_path):
    events = decode(rows(scope))[:-1]
    child = deepcopy(events[0])
    child.update(seq=len(events), ts_monotonic_ns=220, event=event_identity)
    child[scope + "_parent_seq"] = 2
    if event_identity["name"] != "script.run":
        child["provenance"].update(source="fixture", component="fixture")
        child["detail"] = {"thread_id": 43}
    events.append(child)
    with pytest.raises(ContractError, match="parent scope is inconsistent"):
        validate(events, tmp_path)
    child["execution"] = dict(events[1]["execution"])
    assert validate(events, tmp_path)["events"] == len(events)


@pytest.mark.parametrize("kind", ["eval", "function-constructor"])
@pytest.mark.parametrize("mode", ["callback", "promise", "both"])
@pytest.mark.parametrize("consumer", ["v1", "v2", "inventory", "rows"])
def test_metadata_consumers_accept_unique_cross_realm_caller(source, monkeypatch, kind, mode, consumer):
    def export(processor, trace, path, run_id, revision):
        events = decode(rows(mode, kind), run_id, revision)
        path.write_text("\n".join(json.dumps(event) for event in events) + "\n", encoding="utf-8")
        return {"report": {"source_trace": {"sha256": hashlib.sha256(BODY).hexdigest()}}}
    monkeypatch.setattr(metadata_query, "export_perfetto", export)
    if consumer in {"v1", "v2"}:
        result = metadata_query.metadata_query(source, filters=history_filters(), limit=25,
                                              metadata_version=int(consumer[-1]))
        child = result["events"][0]
        assert child["execution"]["context_id"] == "A"
        assert child["causal_parent_seq"] == 0
    elif consumer == "inventory":
        result = metadata_inventory_query.metadata_inventory_query(source)
    else:
        result = metadata_rows.metadata_rows(source)
        assert result["rows"][0]["script_id"] == "v8:42:A:7"
    assert result["status"] == "ok"
    assert result["query"]["matching_events"] == str(len(rows(mode, kind)))
