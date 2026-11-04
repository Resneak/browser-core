"""V8 inspector context IDs resolve reused dynamic-code caller ScriptIds exactly."""
import json
from pathlib import Path

import pytest

from browser_core.contracts import ContractError
from browser_core.perfetto import parse_export_csv
from browser_core.trace import validate_trace
from test_perfetto import REVISION, csv_rows_fixture, dynamic_code_row, script_run_row


def reload_rows(caller_id=None, first_id="1", second_id="3"):
    """Two contexts ran ScriptId 7 (same-tab reload), then dynamic code."""
    first = script_run_row(inspector_context_id=first_id) if first_id else script_run_row()
    second = script_run_row(ts_monotonic_ns="110", context_id="reload",
                            native_id="script:reload:7",
                            **({"inspector_context_id": second_id} if second_id else {}))
    dynamic = (dynamic_code_row(caller_inspector_context_id=caller_id)
               if caller_id is not None else dynamic_code_row())
    return [first, second, dynamic]


def decode(rows):
    return parse_export_csv(csv_rows_fixture(rows), "fixture-run", REVISION)


def validate(events, tmp_path):
    path = tmp_path / "events.jsonl"
    path.write_text("\n".join(json.dumps(event) for event in events), encoding="utf-8")
    return validate_trace(path)


@pytest.mark.parametrize("caller_id,parent_seq,context", [("1", 0, "frame-token"), ("3", 1, "reload")])
def test_matching_inspector_id_selects_exactly_the_callers_context(tmp_path, caller_id, parent_seq, context):
    events = decode(reload_rows(caller_id))
    dynamic = events[-1]
    assert dynamic["causal_parent_seq"] == parent_seq
    assert dynamic["execution"]["context_id"] == context
    assert dynamic["detail"]["caller_inspector_context_id"] == int(caller_id)
    assert "caller_parent_status" not in dynamic["detail"]
    assert events[parent_seq]["detail"]["inspector_context_id"] == int(caller_id)
    validate(events, tmp_path)


def test_unmatched_inspector_id_is_not_in_trace(tmp_path):
    events = decode(reload_rows("9"))
    dynamic = events[-1]
    assert dynamic["detail"]["caller_parent_status"] == "script_parent_not_in_trace"
    assert "causal_parent_seq" not in dynamic and "execution" not in dynamic
    validate(events, tmp_path)


def test_runs_without_ids_never_match_an_id(tmp_path):
    # Old-runtime script runs carry no ID: an ID-bearing caller links to none.
    events = decode(reload_rows("1", first_id=None, second_id=None))
    assert events[-1]["detail"]["caller_parent_status"] == "script_parent_not_in_trace"
    validate(events, tmp_path)


def test_without_caller_id_reuse_stays_ambiguous(tmp_path):
    events = decode(reload_rows(None))
    assert events[-1]["detail"]["caller_parent_status"] == "caller_context_ambiguous"
    validate(events, tmp_path)


def test_zero_ids_mean_unassigned_and_are_omitted():
    events = decode(reload_rows("0", first_id="0", second_id="0"))
    assert all("inspector_context_id" not in event["detail"] for event in events[:2])
    assert "caller_inspector_context_id" not in events[-1]["detail"]
    assert events[-1]["detail"]["caller_parent_status"] == "caller_context_ambiguous"


def test_validator_rejects_forged_link_to_the_other_context(tmp_path):
    events = decode(reload_rows("3"))
    forged = events[-1]
    forged["causal_parent_seq"] = 0
    forged["execution"] = dict(events[0]["execution"])
    with pytest.raises(ContractError, match="not its matching script run"):
        validate(events, tmp_path)


def test_validator_rejects_claimed_ambiguity_when_id_resolves(tmp_path):
    events = decode(reload_rows("3"))
    dynamic = events[-1]
    dynamic.pop("causal_parent_seq"); dynamic.pop("execution")
    dynamic["detail"]["caller_parent_status"] = "caller_context_ambiguous"
    with pytest.raises(ContractError, match="caller parent status is inconsistent"):
        validate(events, tmp_path)


@pytest.mark.parametrize("field", ["inspector_context_id", "caller_inspector_context_id"])
def test_ids_on_unrelated_native_events_are_rejected(field):
    row = script_run_row() if field == "caller_inspector_context_id" else dynamic_code_row()
    row[field] = "5"
    with pytest.raises(ContractError, match="unrelated native event"):
        decode([row])


@pytest.mark.parametrize("value", ["-1", "2147483648", "x"])
def test_invalid_ids_are_rejected(value):
    with pytest.raises(ContractError):
        decode([script_run_row(inspector_context_id=value)])
