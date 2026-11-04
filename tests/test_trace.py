from __future__ import annotations

import copy
import json
import os
from pathlib import Path

import pytest

from browser_core.contracts import ContractError
from browser_core.trace import causal_chain, load_index, summarize, validate_trace, who_read


FIXTURE = Path(__file__).parents[1] / "fixtures" / "trace-v1.jsonl"


def test_fixture_validates_and_summarizes() -> None:
    result = validate_trace(FIXTURE)
    assert result == {"run_id": "fixture-run", "events": 5, "dropped_events": 0}
    summary = summarize(FIXTURE)
    assert summary["categories"]["api"] == 1
    assert summary["execution_contexts"] == 2


def test_trace_validation_can_bound_the_event_population() -> None:
    with pytest.raises(ContractError, match="population exceeds"):
        validate_trace(FIXTURE, maximum_events=4)


def test_trace_scan_can_bound_the_event_population() -> None:
    from browser_core.trace import scan_validated_trace

    with pytest.raises(ContractError, match="population exceeds"):
        scan_validated_trace(FIXTURE, lambda _event: None, maximum_events=4)


@pytest.mark.skipif(os.name != "nt", reason="Windows creation time is not change time")
def test_trace_stream_rejects_same_size_edit_with_restored_mtime(
    tmp_path: Path,
) -> None:
    from browser_core.trace import iter_trace

    path = tmp_path / "trace.jsonl"
    path.write_bytes(FIXTURE.read_bytes())
    stamp = path.stat()
    stream = iter_trace(path)
    next(stream)
    with path.open("r+b") as writer:
        writer.seek(0)
        writer.write(b"X")
    os.utime(path, ns=(stamp.st_atime_ns, stamp.st_mtime_ns))

    with pytest.raises(ContractError, match="changed during streaming"):
        list(stream)


@pytest.mark.skipif(os.name != "nt", reason="Windows creation time is not change time")
def test_trace_stream_rejects_same_tick_edit_with_restored_mtime(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    import browser_core.trace as trace_module

    path = tmp_path / "trace.jsonl"
    original = FIXTURE.read_bytes()
    changed = original.replace(b"fixture-run", b"fixture-ruX", 1)
    assert changed != original and len(changed) == len(original)
    path.write_bytes(original)
    stamp = path.stat()
    monkeypatch.setattr(trace_module, "windows_change_time", lambda _handle: 0)
    stream = trace_module.iter_trace(path)
    next(stream)
    with path.open("r+b") as writer:
        writer.write(changed)
    os.utime(path, ns=(stamp.st_atime_ns, stamp.st_mtime_ns))

    with pytest.raises(ContractError, match="changed during streaming"):
        list(stream)


@pytest.mark.parametrize("limit", [0, True, "5"])
def test_trace_validation_rejects_invalid_event_limits(limit) -> None:
    with pytest.raises(ContractError, match="event limit"):
        validate_trace(FIXTURE, maximum_events=limit)


def test_trace_validation_uses_the_runtime_default_event_limit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import browser_core.trace as trace_module

    monkeypatch.setattr(trace_module, "MAX_TRACE_EVENTS", 4)

    with pytest.raises(ContractError, match="population exceeds"):
        validate_trace(FIXTURE)


def test_trace_scan_closes_source_when_consumer_fails(monkeypatch) -> None:
    import browser_core.trace as trace_module

    closed = []
    opened = []

    def events(_path, *, hash_update=None):
        def stream():
            try:
                yield {}
            finally:
                closed.append(True)
        result = stream()
        opened.append(result)
        return result

    def fail(_event):
        raise ContractError("consumer failed")

    monkeypatch.setattr(trace_module, "iter_trace", events)
    with pytest.raises(ContractError, match="consumer failed") as caught:
        trace_module.scan_validated_trace(FIXTURE, fail)
    assert caught.value is not None
    assert closed == [True]


def test_trace_index_closes_source_when_validation_fails(monkeypatch) -> None:
    import browser_core.trace as trace_module

    closed = []
    opened = []
    first = json.loads(FIXTURE.read_text(encoding="utf-8").splitlines()[0])

    def events(_path):
        def stream():
            try:
                yield first
                yield first
            finally:
                closed.append(True)
        result = stream()
        opened.append(result)
        return result

    monkeypatch.setattr(trace_module, "iter_trace", events)
    with pytest.raises(ContractError, match="not strictly increasing") as caught:
        trace_module.load_validated_trace(FIXTURE)
    assert caught.value is not None
    assert closed == [True]


def test_seen_sequences_compact_contiguous_values() -> None:
    import browser_core.trace as trace_module

    seen = trace_module._SeenSequences()
    for sequence in range(100_000):
        seen.add(sequence)

    assert seen._starts == [0]
    assert seen._ends == [99_999]
    assert 0 in seen
    assert 50_000 in seen
    assert 99_999 in seen
    assert 100_000 not in seen


def test_seen_sequences_bound_sparse_ranges(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import browser_core.trace as trace_module

    monkeypatch.setattr(trace_module, "MAX_TRACE_SEQUENCE_RANGES", 1)
    seen = trace_module._SeenSequences()
    seen.add(0)

    with pytest.raises(ContractError, match="range population exceeds"):
        seen.add(2)


def test_who_read_returns_execution_identity() -> None:
    events = who_read(FIXTURE, "navigator.userAgent")
    assert [event["execution"]["script_id"] for event in events] == ["script-a"]


def test_request_query_returns_causal_chain() -> None:
    chain = causal_chain(FIXTURE, "req-1")
    assert [event["seq"] for event in chain] == [0, 1, 2, 3]


def test_index_and_summary_each_use_one_cross_event_validated_population(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import browser_core.trace as trace_module

    real_open = trace_module.os.open
    opens = 0

    def recording_open(path: Path, *args, **kwargs):
        nonlocal opens
        if Path(path) == FIXTURE:
            opens += 1
        return real_open(path, *args, **kwargs)

    monkeypatch.setattr(trace_module.os, "open", recording_open)

    events, index = load_index(FIXTURE)
    assert len(events) == 5
    assert set(index) == {0, 1, 2, 3, 4}
    assert opens == 1

    summary = summarize(FIXTURE)
    assert summary["events"] == 5
    assert opens == 2


def test_missing_parent_is_rejected(tmp_path: Path) -> None:
    event = {
        "schema": "browser-core.trace-event/1",
        "run_id": "broken",
        "seq": 1,
        "ts_monotonic_ns": 1,
        "causal_parent_seq": 0,
        "process": {"pid": 1, "type": "browser"},
        "event": {"category": "diagnostic", "name": "fixture"},
        "provenance": {},
    }
    path = tmp_path / "broken.jsonl"
    path.write_text(json.dumps(event) + "\n", encoding="utf-8")
    with pytest.raises(ContractError, match="parent"):
        validate_trace(path)


def test_stream_result_must_match_its_request_parent(tmp_path: Path) -> None:
    shared = {
        "schema": "browser-core.trace-event/1",
        "run_id": "broken-stream",
        "process": {"pid": 1, "type": "renderer"},
        "execution": {"context_id": "frame-a", "frame_id": "frame-a"},
        "provenance": {"source": "native", "component": "blink.streams"},
    }
    request = {
        **shared,
        "seq": 0,
        "ts_monotonic_ns": 1,
        "event": {"category": "stream", "name": "stream.read.request"},
        "detail": {
            "native_name": "BrowserCore.StreamReadRequest",
            "thread_id": 1,
            "reader_mode": "default",
        },
    }
    result = {
        **shared,
        "seq": 1,
        "ts_monotonic_ns": 2,
        "causal_parent_seq": 0,
        "event": {"category": "stream", "name": "stream.read.result"},
        "detail": {
            "native_name": "BrowserCore.StreamReadResult",
            "thread_id": 1,
            "reader_mode": "byob",
            "result_kind": "closed",
            "chunk_value_type": "none",
            "chunk_bytes": 0,
        },
    }
    path = tmp_path / "broken-stream.jsonl"
    path.write_text(
        json.dumps(request) + "\n" + json.dumps(result) + "\n",
        encoding="utf-8",
    )

    with pytest.raises(ContractError, match="matching read request"):
        validate_trace(path)


def test_stream_request_can_only_be_completed_once(tmp_path: Path) -> None:
    shared = {
        "schema": "browser-core.trace-event/1",
        "run_id": "duplicate-stream-result",
        "process": {"pid": 1, "type": "renderer"},
        "execution": {"context_id": "frame-a", "frame_id": "frame-a"},
        "provenance": {"source": "native", "component": "blink.streams"},
    }
    request = {
        **shared,
        "seq": 0,
        "ts_monotonic_ns": 1,
        "event": {"category": "stream", "name": "stream.read.request"},
        "detail": {
            "native_name": "BrowserCore.StreamReadRequest",
            "thread_id": 1,
            "reader_mode": "default",
        },
    }
    result_detail = {
        "native_name": "BrowserCore.StreamReadResult",
        "thread_id": 1,
        "reader_mode": "default",
        "result_kind": "chunk",
        "chunk_value_type": "bytes",
        "chunk_bytes": 1,
    }
    first_result = {
        **shared,
        "seq": 1,
        "ts_monotonic_ns": 2,
        "causal_parent_seq": 0,
        "event": {"category": "stream", "name": "stream.read.result"},
        "detail": result_detail,
        "value": {"type": "bytes", "length": 1, "redaction": "metadata"},
    }
    duplicate_result = {
        **shared,
        "seq": 2,
        "ts_monotonic_ns": 3,
        "causal_parent_seq": 0,
        "event": {"category": "stream", "name": "stream.read.result"},
        "detail": result_detail,
        "value": {"type": "bytes", "length": 1, "redaction": "metadata"},
    }
    path = tmp_path / "duplicate-stream-result.jsonl"
    path.write_text(
        "\n".join(
            json.dumps(event)
            for event in (request, first_result, duplicate_result)
        )
        + "\n",
        encoding="utf-8",
    )

    with pytest.raises(ContractError, match="matching read request"):
        validate_trace(path)


def body_consumer_population() -> list[dict[str, object]]:
    shared = {
        "schema": "browser-core.trace-event/1",
        "run_id": "body-consumer",
        "process": {"pid": 1, "type": "renderer"},
        "execution": {
            "context_id": "frame-a",
            "frame_id": "frame-a",
            "script_id": "v8:1:frame-a:7",
        },
    }
    return [
        {
            **shared,
            "execution": {**shared["execution"]},
            "seq": 0,
            "ts_monotonic_ns": 1,
            "event": {"category": "execution", "name": "script.run"},
            "provenance": {"source": "native", "component": "blink.v8"},
            "detail": {"native_name": "BrowserCore.ScriptRun", "thread_id": 1},
        },
        {
            **shared,
            "execution": {**shared["execution"]},
            "seq": 1,
            "ts_monotonic_ns": 2,
            "causal_parent_seq": 0,
            "event": {"category": "stream", "name": "body.consume"},
            "provenance": {
                "source": "native",
                "component": "blink.fetch-body",
            },
            "detail": {
                "native_name": "BrowserCore.BodyConsume",
                "thread_id": 1,
                "consumer_mode": "json",
            },
        },
    ]


def test_body_consumer_must_match_its_script_parent(tmp_path: Path) -> None:
    events = body_consumer_population()
    path = tmp_path / "body-consumer.jsonl"
    path.write_text(
        "\n".join(json.dumps(event) for event in events) + "\n",
        encoding="utf-8",
    )

    assert validate_trace(path)["events"] == 2


@pytest.mark.parametrize("mismatch", ["event", "process", "context", "script"])
def test_body_consumer_rejects_forged_script_parent(
    tmp_path: Path,
    mismatch: str,
) -> None:
    events = body_consumer_population()
    parent, body = events
    if mismatch == "event":
        parent["event"] = {"category": "api", "name": "Navigator.userAgent"}
    elif mismatch == "process":
        body["process"] = {"pid": 2, "type": "renderer"}
    elif mismatch == "context":
        body["execution"] = {**body["execution"], "context_id": "frame-b"}
    else:
        body["execution"] = {
            **body["execution"],
            "script_id": "v8:1:frame-a:8",
        }
    path = tmp_path / f"forged-body-parent-{mismatch}.jsonl"
    path.write_text(
        "\n".join(json.dumps(event) for event in events) + "\n",
        encoding="utf-8",
    )

    with pytest.raises(
        ContractError,
        match=(
            "matching script run|script identity|body consumer execution|"
            "script run event identity"
        ),
    ):
        validate_trace(path)


def test_trace_bounds_retained_script_parent_population(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import browser_core.trace as trace_module

    monkeypatch.setattr(trace_module, "MAX_TRACE_SCRIPT_PARENTS", 1)
    events = [body_consumer_population()[0] for _ in range(2)]
    for seq, event in enumerate(events):
        event["seq"] = seq
        event["ts_monotonic_ns"] = seq + 1
        event["execution"] = {
            **event["execution"],
            "script_id": f"v8:1:frame-a:{seq}",
        }
    path = tmp_path / "too-many-script-parents.jsonl"
    path.write_text(
        "\n".join(json.dumps(event) for event in events) + "\n",
        encoding="utf-8",
    )

    with pytest.raises(ContractError, match="script parent population"):
        validate_trace(path)


def callback_population() -> list[dict[str, object]]:
    shared = {
        "schema": "browser-core.trace-event/1",
        "run_id": "callback-chain",
        "process": {"pid": 1, "type": "renderer"},
        "execution": {"context_id": "frame-a", "frame_id": "frame-a"},
    }
    return [
        {
            **shared,
            "process": {**shared["process"]},
            "execution": {
                **shared["execution"],
                "script_id": "v8:1:frame-a:7",
            },
            "seq": 0,
            "ts_monotonic_ns": 1,
            "event": {"category": "execution", "name": "script.run"},
            "provenance": {"source": "native", "component": "blink.v8"},
            "detail": {"native_name": "BrowserCore.ScriptRun", "thread_id": 1},
        },
        {
            **shared,
            "process": {**shared["process"]},
            "execution": {
                **shared["execution"],
                "script_id": "v8:1:frame-a:7",
            },
            "seq": 1,
            "ts_monotonic_ns": 2,
            "causal_parent_seq": 0,
            "event": {
                "category": "execution",
                "name": "host.callback.execution",
            },
            "provenance": {
                "source": "native",
                "component": "blink.bindings.callback",
            },
            "detail": {
                "native_name": "BrowserCore.HostCallbackExecution",
                "thread_id": 1,
                "completion": "complete",
                "duration_ns": 10,
                "callback_interface": "EventListener",
                "callback_operation": "handleEvent",
                "callback_kind": "function",
            },
        },
        {
            **shared,
            "process": {**shared["process"]},
            "execution": {**shared["execution"]},
            "seq": 2,
            "ts_monotonic_ns": 3,
            "callback_parent_seq": 1,
            "event": {"category": "api", "name": "fixture.insideCallback"},
            "provenance": {"source": "native", "component": "fixture"},
            "detail": {"native_name": "Fixture.CallbackChild", "thread_id": 1},
        },
    ]


def test_callback_parent_requires_matching_host_callback_scope(tmp_path: Path) -> None:
    path = tmp_path / "callback-chain.jsonl"
    path.write_text(
        "\n".join(json.dumps(event) for event in callback_population()) + "\n",
        encoding="utf-8",
    )

    assert validate_trace(path)["events"] == 3


def promise_population() -> list[dict[str, object]]:
    promise = {
        "schema": "browser-core.trace-event/1",
        "run_id": "promise-chain",
        "seq": 0,
        "ts_monotonic_ns": 10,
        "process": {"pid": 1, "type": "renderer"},
        "execution": {"context_id": "frame-a", "frame_id": "frame-a"},
        "event": {
            "category": "execution",
            "name": "promise.microtask.execution",
        },
        "provenance": {
            "source": "native",
            "component": "blink.scheduler.promise",
        },
        "detail": {
            "native_name": "BrowserCore.PromiseMicrotaskExecution",
            "thread_id": 1,
            "completion": "complete",
            "duration_ns": 10,
            "boundary": "v8-isolate-promise-hook-before-after",
            "job_kind": "unclassified",
        },
    }
    child = {
        "schema": "browser-core.trace-event/1",
        "run_id": "promise-chain",
        "seq": 1,
        "ts_monotonic_ns": 11,
        "promise_parent_seq": 0,
        "process": {"pid": 1, "type": "renderer"},
        "execution": {"context_id": "frame-a", "frame_id": "frame-a"},
        "event": {"category": "api", "name": "fixture.insidePromise"},
        "provenance": {"source": "native", "component": "fixture"},
        "detail": {"native_name": "Fixture.PromiseChild", "thread_id": 1},
    }
    return [promise, child]


def test_promise_parent_requires_matching_native_scope(tmp_path: Path) -> None:
    path = tmp_path / "promise-chain.jsonl"
    path.write_text(
        "\n".join(json.dumps(event) for event in promise_population()) + "\n",
        encoding="utf-8",
    )

    assert validate_trace(path)["events"] == 2


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (lambda events: events[1].update(promise_parent_seq=1), "not earlier"),
        (lambda events: events[1]["process"].update(pid=2), "parent scope"),
        (lambda events: events[1]["detail"].update(thread_id=2), "parent scope"),
        (
            lambda events: events[1]["execution"].update(
                context_id="frame-b", frame_id="frame-b"
            ),
            "parent scope",
        ),
        (lambda events: events[1].update(ts_monotonic_ns=20), "parent scope"),
        (
            lambda events: events[1].update(seq=10, promise_parent_seq=9),
            "parent scope",
        ),
    ],
)
def test_promise_parent_rejects_forged_scope(
    tmp_path: Path,
    mutation,
    message: str,
) -> None:
    events = promise_population()
    mutation(events)
    path = tmp_path / "forged-promise-chain.jsonl"
    path.write_text(
        "\n".join(json.dumps(event) for event in events) + "\n",
        encoding="utf-8",
    )

    with pytest.raises(ContractError, match=message):
        validate_trace(path)


def test_summary_exposes_promise_execution_and_containment(tmp_path: Path) -> None:
    path = tmp_path / "promise-summary.jsonl"
    path.write_text(
        "\n".join(json.dumps(event) for event in promise_population()) + "\n",
        encoding="utf-8",
    )

    result = summarize(path)["promise_summary"]

    assert result == {
        "promise_microtask_executions": 1,
        "complete_executions": 1,
        "open_executions": 0,
        "contained_events": 1,
        "execution_contexts": 1,
        "edge_groups_total": 1,
        "edge_groups_reported": 1,
        "edge_groups_truncated": False,
        "contained_event_edges": [
            {
                "event_category": "api",
                "event_name": "fixture.insidePromise",
                "count": 1,
            }
        ],
        "semantics": {
            "boundary": "v8-isolate-promise-hook-before-after",
            "edge": "same-track-temporal-containment",
            "job_kind_classified": False,
            "handler_identity_recorded": False,
            "promise_identity_recorded": False,
            "fulfillment_or_rejection_inferred": False,
            "private_values_included": False,
            "observer_effect": "v8-promise-hook-disables-fast-paths",
        },
    }


@pytest.mark.parametrize("limit", [-1, 1025, True, "1"])
def test_summary_rejects_invalid_promise_edge_limits(limit: object) -> None:
    with pytest.raises(ContractError, match="promise summary edge limit"):
        summarize(FIXTURE, promise_edge_limit=limit)  # type: ignore[arg-type]


def dynamic_code_population() -> list[dict[str, object]]:
    script = {
        "schema": "browser-core.trace-event/1",
        "run_id": "dynamic-chain",
        "seq": 0,
        "ts_monotonic_ns": 10,
        "process": {"pid": 1, "type": "renderer"},
        "execution": {
            "context_id": "frame-a",
            "frame_id": "frame-a",
            "script_id": "v8:1:frame-a:7",
        },
        "event": {"category": "execution", "name": "script.run"},
        "provenance": {"source": "native", "component": "blink.v8"},
        "detail": {
            "native_name": "BrowserCore.ScriptRun",
            "thread_id": 2,
        },
    }
    dynamic = {
        "schema": "browser-core.trace-event/1",
        "run_id": "dynamic-chain",
        "seq": 1,
        "ts_monotonic_ns": 11,
        "causal_parent_seq": 0,
        "process": {"pid": 1, "type": "renderer"},
        "execution": {
            "context_id": "frame-a",
            "frame_id": "frame-a",
            "script_id": "v8:1:frame-a:7",
        },
        "event": {
            "category": "execution",
            "name": "dynamic.code.materialized",
        },
        "provenance": {"source": "native", "component": "v8.compiler"},
        "detail": {
            "native_name": "BrowserCore.DynamicCodeMaterialized",
            "thread_id": 2,
            "dynamic_kind": "eval",
            "cache_status": "compiled",
            "generated_script_id": 8,
            "caller_script_id": 7,
            "caller_status": "observed",
            "source_length": 31,
            "source_length_unit": "utf16-code-units",
        },
    }
    child = {
        "schema": "browser-core.trace-event/1",
        "run_id": "dynamic-chain",
        "seq": 2,
        "ts_monotonic_ns": 12,
        "dynamic_code_parent_seq": 1,
        "process": {"pid": 1, "type": "renderer"},
        "execution": {
            "context_id": "frame-a",
            "frame_id": "frame-a",
            "script_id": "v8:1:frame-a:8",
        },
        "event": {"category": "api", "name": "Navigator.userAgent.get"},
        "provenance": {"source": "native", "component": "fixture"},
        "detail": {"native_name": "Fixture.DynamicChild", "thread_id": 2},
    }
    return [script, dynamic, child]


def test_dynamic_code_parent_requires_matching_materialization(
    tmp_path: Path,
) -> None:
    path = tmp_path / "dynamic-chain.jsonl"
    path.write_text(
        "\n".join(json.dumps(event) for event in dynamic_code_population()) + "\n",
        encoding="utf-8",
    )

    assert validate_trace(path)["events"] == 3


def test_dynamic_code_parent_must_be_most_recent_matching_materialization(
    tmp_path: Path,
) -> None:
    events = dynamic_code_population()
    latest = copy.deepcopy(events[1])
    latest["seq"] = 2
    latest["ts_monotonic_ns"] = 12
    latest["detail"]["cache_status"] = "function-cache-hit"
    child = events[2]
    child["seq"] = 3
    child["ts_monotonic_ns"] = 13
    events = [events[0], events[1], latest, child]
    path = tmp_path / "stale-dynamic-parent.jsonl"
    path.write_text(
        "\n".join(json.dumps(event) for event in events) + "\n",
        encoding="utf-8",
    )

    with pytest.raises(ContractError, match="most recent materialization"):
        validate_trace(path)

    child["dynamic_code_parent_seq"] = 2
    path.write_text(
        "\n".join(json.dumps(event) for event in events) + "\n",
        encoding="utf-8",
    )
    assert validate_trace(path)["events"] == 4


def test_dynamic_code_caller_status_cannot_hide_retained_script_run(
    tmp_path: Path,
) -> None:
    events = dynamic_code_population()[:2]
    dynamic = events[1]
    dynamic.pop("causal_parent_seq")
    dynamic.pop("execution")
    dynamic["detail"]["caller_parent_status"] = "script_parent_not_in_trace"
    path = tmp_path / "hidden-retained-caller.jsonl"
    path.write_text(
        "\n".join(json.dumps(event) for event in events) + "\n",
        encoding="utf-8",
    )

    with pytest.raises(ContractError, match="parent status"):
        validate_trace(path)


def test_dynamic_code_caller_rejects_ambiguous_contexts(tmp_path: Path) -> None:
    script, dynamic = dynamic_code_population()[:2]
    other_context = copy.deepcopy(script)
    other_context["seq"] = 1
    other_context["ts_monotonic_ns"] = 11
    other_context["execution"] = {
        "context_id": "frame-b",
        "frame_id": "frame-b",
        "script_id": "v8:1:frame-b:7",
    }
    dynamic["seq"] = 2
    dynamic["ts_monotonic_ns"] = 12
    path = tmp_path / "ambiguous-dynamic-caller.jsonl"
    path.write_text(
        "\n".join(json.dumps(event) for event in (script, other_context, dynamic))
        + "\n",
        encoding="utf-8",
    )

    with pytest.raises(ContractError, match="matching script run"):
        validate_trace(path)


def test_dynamic_code_caller_must_use_latest_matching_script_run(
    tmp_path: Path,
) -> None:
    script, dynamic = dynamic_code_population()[:2]
    latest = copy.deepcopy(script)
    latest["seq"] = 1
    latest["ts_monotonic_ns"] = 11
    dynamic["seq"] = 2
    dynamic["ts_monotonic_ns"] = 12
    path = tmp_path / "stale-dynamic-caller.jsonl"
    path.write_text(
        "\n".join(json.dumps(event) for event in (script, latest, dynamic)) + "\n",
        encoding="utf-8",
    )

    with pytest.raises(ContractError, match="matching script run"):
        validate_trace(path)

    dynamic["causal_parent_seq"] = 1
    path.write_text(
        "\n".join(json.dumps(event) for event in (script, latest, dynamic)) + "\n",
        encoding="utf-8",
    )
    assert validate_trace(path)["events"] == 3


def test_nested_dynamic_code_can_link_without_retained_generated_script_run(
    tmp_path: Path,
) -> None:
    events = dynamic_code_population()[:2]
    nested = {
        "schema": "browser-core.trace-event/1",
        "run_id": "dynamic-chain",
        "seq": 2,
        "ts_monotonic_ns": 12,
        "dynamic_code_parent_seq": 1,
        "process": {"pid": 1, "type": "renderer"},
        "event": {
            "category": "execution",
            "name": "dynamic.code.materialized",
        },
        "provenance": {"source": "native", "component": "v8.compiler"},
        "detail": {
            "native_name": "BrowserCore.DynamicCodeMaterialized",
            "thread_id": 2,
            "dynamic_kind": "function-constructor",
            "cache_status": "compiled",
            "generated_script_id": 9,
            "caller_script_id": 8,
            "caller_status": "observed",
            "caller_parent_status": "script_parent_not_in_trace",
            "source_length": 47,
            "source_length_unit": "utf16-code-units",
        },
    }
    events.append(nested)
    path = tmp_path / "nested-dynamic-chain.jsonl"
    path.write_text(
        "\n".join(json.dumps(event) for event in events) + "\n",
        encoding="utf-8",
    )

    assert validate_trace(path)["events"] == 3


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (lambda events: events[2]["process"].update(pid=2), "parent scope"),
        (lambda events: events[2]["detail"].update(thread_id=3), "parent scope"),
        (
            lambda events: events[2]["execution"].update(
                script_id="v8:1:frame-a:9"
            ),
            "parent scope",
        ),
        (
            lambda events: events[1]["execution"].update(
                script_id="v8:1:frame-a:9"
            ),
            "caller script",
        ),
    ],
)
def test_dynamic_code_parent_rejects_forged_scope(
    tmp_path: Path,
    mutation,
    message: str,
) -> None:
    events = dynamic_code_population()
    mutation(events)
    path = tmp_path / "forged-dynamic-chain.jsonl"
    path.write_text(
        "\n".join(json.dumps(event) for event in events) + "\n",
        encoding="utf-8",
    )

    with pytest.raises(ContractError, match=message):
        validate_trace(path)


def test_summary_exposes_dynamic_code_attribution(tmp_path: Path) -> None:
    path = tmp_path / "dynamic-summary.jsonl"
    path.write_text(
        "\n".join(json.dumps(event) for event in dynamic_code_population()) + "\n",
        encoding="utf-8",
    )

    result = summarize(path)["dynamic_code_summary"]

    assert result == {
        "materializations": 1,
        "generated_scripts": 1,
        "dynamically_attributed_events": 1,
        "caller_links": 1,
        "caller_parent_not_in_trace": 0,
        "caller_context_ambiguous": 0,
        "caller_unavailable": 0,
        "kinds": {"eval": 1},
        "cache_statuses": {"compiled": 1},
        "source_utf16_code_units_total": 31,
        "source_utf16_code_units_max": 31,
        "edge_groups_total": 1,
        "edge_groups_reported": 1,
        "edge_groups_truncated": False,
        "attributed_event_edges": [
            {
                "dynamic_kind": "eval",
                "event_category": "api",
                "event_name": "Navigator.userAgent.get",
                "count": 1,
            }
        ],
        "semantics": {
            "boundary": "successful-v8-dynamic-code-materialization-or-cache-reuse",
            "edge": "same-process-thread-generated-script-id",
            "page_ownership_inferred": False,
            "source_text_included": False,
            "result_value_included": False,
            "execution_success_inferred": False,
            "private_values_included": False,
            "debugger_expression_compilation_included": False,
            "agent_control_descendants_excluded": False,
        },
    }


@pytest.mark.parametrize("limit", [-1, 1025, True, "1"])
def test_summary_rejects_invalid_dynamic_code_edge_limits(limit: object) -> None:
    with pytest.raises(ContractError, match="dynamic code summary edge limit"):
        summarize(FIXTURE, dynamic_code_edge_limit=limit)  # type: ignore[arg-type]


def test_generated_binding_can_use_exact_host_callback_context(tmp_path: Path) -> None:
    events = callback_population()
    events[2].update(
        execution={
            "context_id": "frame-a",
            "frame_id": "frame-a",
            "script_id": "v8:1:frame-a:7",
        },
        event={"category": "api", "name": "Navigator.platform.get"},
        provenance={
            "source": "native",
            "component": "blink.bindings.generated",
            "trace_category": "blink.bindings",
        },
        detail={
            "native_name": "Navigator.platform.get",
            "thread_id": 1,
            "completion": "complete",
            "duration_ns": 1,
            "script_attribution": "callback-contained",
            "context_attribution": "host-callback",
        },
    )
    path = tmp_path / "callback-binding.jsonl"
    path.write_text(
        "\n".join(json.dumps(event) for event in events) + "\n",
        encoding="utf-8",
    )

    assert validate_trace(path)["events"] == 3


def test_summary_exposes_bounded_callback_edges_for_agents(tmp_path: Path) -> None:
    events = callback_population()
    path = tmp_path / "callback-summary.jsonl"
    path.write_text(
        "\n".join(json.dumps(event) for event in events) + "\n",
        encoding="utf-8",
    )

    result = summarize(path)["callback_summary"]

    assert result == {
        "host_callback_executions": 1,
        "callback_contained_events": 1,
        "execution_contexts": 1,
        "interfaces": {"EventListener": 1},
        "operations": {"handleEvent": 1},
        "kinds": {"function": 1},
        "message_dispatch_linked_callbacks": 0,
        "message_dispatch_parent_not_in_trace": 0,
        "message_dispatch_kinds": {},
        "edge_groups_total": 1,
        "edge_groups_reported": 1,
        "edge_groups_truncated": False,
        "contained_event_edges": [
            {
                "callback_interface": "EventListener",
                "callback_operation": "handleEvent",
                "callback_kind": "function",
                "event_category": "api",
                "event_name": "fixture.insideCallback",
                "count": 1,
            }
        ],
        "semantics": {
            "edge": "same-track-temporal-containment",
            "message_dispatch_edge": "native-event-object-identity",
            "page_ownership_inferred": False,
            "callback_success_inferred": False,
            "private_values_included": False,
        },
    }


def message_callback_population() -> list[dict[str, object]]:
    events = callback_population()
    dispatch = {
        "schema": "browser-core.trace-event/1",
        "run_id": "callback-chain",
        "seq": 1,
        "ts_monotonic_ns": 2,
        "process": {"pid": 1, "type": "renderer"},
        "execution": {"context_id": "frame-a", "frame_id": "frame-a"},
        "event": {
            "category": "message",
            "name": "MessagePort.message.dispatch",
        },
        "provenance": {"source": "native", "component": "blink.messaging"},
        "detail": {
            "native_name": "BrowserCore.MessageDispatch",
            "thread_id": 1,
            "dispatch_kind": "message",
            "causal_parent_status": "message_parent_unavailable",
        },
    }
    callback = events[1]
    callback["seq"] = 2
    callback["ts_monotonic_ns"] = 3
    callback["message_dispatch_parent_seq"] = 1
    child = events[2]
    child["seq"] = 3
    child["ts_monotonic_ns"] = 4
    child["callback_parent_seq"] = 2
    return [events[0], dispatch, callback, child]


def test_trace_validates_exact_message_dispatch_callback_link(tmp_path: Path) -> None:
    path = tmp_path / "message-callback.jsonl"
    path.write_text(
        "\n".join(json.dumps(event) for event in message_callback_population())
        + "\n",
        encoding="utf-8",
    )

    assert validate_trace(path)["events"] == 4
    callback_summary = summarize(path)["callback_summary"]
    assert callback_summary["message_dispatch_linked_callbacks"] == 1
    assert callback_summary["message_dispatch_parent_not_in_trace"] == 0
    assert callback_summary["message_dispatch_kinds"] == {"message": 1}


def _mutate_message_callback_process(events: list[dict[str, object]]) -> None:
    events[2]["process"]["pid"] = 2
    events[2]["execution"]["script_id"] = "v8:2:frame-a:7"
    events[2].pop("causal_parent_seq")
    events[2]["detail"]["causal_parent_status"] = "script_parent_not_in_trace"


def _mutate_message_callback_thread(events: list[dict[str, object]]) -> None:
    events[2]["detail"]["thread_id"] = 2
    events[2].pop("causal_parent_seq")
    events[2]["detail"]["causal_parent_status"] = "script_parent_not_in_trace"


def _mutate_message_callback_context(events: list[dict[str, object]]) -> None:
    events[2]["execution"].update(
        context_id="frame-b",
        frame_id="frame-b",
        script_id="v8:1:frame-b:7",
    )
    events[2].pop("causal_parent_seq")
    events[2]["detail"]["causal_parent_status"] = "script_parent_not_in_trace"


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (
            lambda events: events[2].update(message_dispatch_parent_seq=0),
            "message dispatch parent",
        ),
        (
            _mutate_message_callback_process,
            "message dispatch parent",
        ),
        (
            _mutate_message_callback_thread,
            "message dispatch parent",
        ),
        (
            _mutate_message_callback_context,
            "message dispatch parent",
        ),
        (
            lambda events: events[2].update(ts_monotonic_ns=1),
            "timestamp regressed|message dispatch parent",
        ),
    ],
)
def test_trace_rejects_forged_message_dispatch_callback_link(
    tmp_path: Path,
    mutation,
    message: str,
) -> None:
    events = message_callback_population()
    mutation(events)
    path = tmp_path / "forged-message-callback.jsonl"
    path.write_text(
        "\n".join(json.dumps(event) for event in events) + "\n",
        encoding="utf-8",
    )

    with pytest.raises(ContractError, match=message):
        validate_trace(path)


@pytest.mark.parametrize("limit", [-1, 1025, True, "1"])
def test_summary_rejects_invalid_callback_edge_limits(limit: object) -> None:
    with pytest.raises(ContractError, match="callback summary edge limit"):
        summarize(FIXTURE, callback_edge_limit=limit)  # type: ignore[arg-type]


def test_cross_realm_binding_owner_remains_distinct_from_callback_context(
    tmp_path: Path,
) -> None:
    events = callback_population()
    events[2].update(
        execution={"context_id": "frame-b", "frame_id": "frame-b"},
        event={"category": "api", "name": "Navigator.platform.get"},
        provenance={
            "source": "native",
            "component": "blink.bindings.generated",
            "trace_category": "blink.bindings",
        },
        detail={
            "native_name": "Navigator.platform.get",
            "thread_id": 1,
            "completion": "complete",
            "duration_ns": 1,
            "context_attribution": "native-binding-owner",
            "binding_value_slice_id": 9,
        },
    )
    path = tmp_path / "cross-realm-callback-binding.jsonl"
    path.write_text(
        "\n".join(json.dumps(event) for event in events) + "\n",
        encoding="utf-8",
    )

    assert validate_trace(path)["events"] == 3


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (
            lambda events: events[2].update(callback_parent_seq=0),
            "earlier host callback",
        ),
        (
            lambda events: events[2]["process"].update(pid=2),
            "parent scope",
        ),
        (
            lambda events: events[2]["detail"].update(thread_id=2),
            "parent scope",
        ),
        (
            lambda events: events[2]["execution"].update(
                context_id="frame-b", frame_id="frame-b"
            ),
            "parent scope",
        ),
        (
            lambda events: events[2].update(ts_monotonic_ns=12),
            "parent scope",
        ),
    ],
)
def test_callback_parent_rejects_forged_scope(
    tmp_path: Path,
    mutation,
    message: str,
) -> None:
    events = callback_population()
    mutation(events)
    path = tmp_path / "forged-callback-chain.jsonl"
    path.write_text(
        "\n".join(json.dumps(event) for event in events) + "\n",
        encoding="utf-8",
    )

    with pytest.raises(ContractError, match=message):
        validate_trace(path)


def fetch_chain_population() -> list[dict[str, object]]:
    shared = {
        "schema": "browser-core.trace-event/1",
        "run_id": "fetch-chain",
        "process": {"pid": 1, "type": "renderer"},
        "execution": {
            "context_id": "frame-a",
            "frame_id": "frame-a",
            "script_id": "v8:1:frame-a:7",
        },
    }
    return [
        {
            **shared,
            "process": {**shared["process"]},
            "execution": {**shared["execution"]},
            "seq": 0,
            "ts_monotonic_ns": 1,
            "event": {"category": "execution", "name": "script.run"},
            "provenance": {"source": "native", "component": "blink.v8"},
            "detail": {"native_name": "BrowserCore.ScriptRun", "thread_id": 1},
        },
        {
            **shared,
            "process": {**shared["process"]},
            "execution": {**shared["execution"]},
            "seq": 1,
            "ts_monotonic_ns": 2,
            "causal_parent_seq": 0,
            "event": {"category": "api", "name": "fetch"},
            "provenance": {"source": "native", "component": "blink.fetch"},
            "detail": {"native_name": "BrowserCore.FetchCall", "thread_id": 1},
        },
        {
            **shared,
            "process": {**shared["process"]},
            "execution": {**shared["execution"]},
            "seq": 2,
            "ts_monotonic_ns": 3,
            "causal_parent_seq": 1,
            "event": {"category": "network", "name": "fetch.request.start"},
            "provenance": {"source": "native", "component": "blink.fetch"},
            "detail": {
                "native_name": "BrowserCore.FetchRequestStart",
                "thread_id": 1,
            },
            "request": {
                "id": "fetch-request:frame-a:1",
                "method": "GET",
                "url_class": "https:same-origin:/probe",
                "target_scope": "loopback",
                "body_bytes": 0,
            },
        },
    ]


def test_fetch_request_requires_exact_script_and_api_chain(tmp_path: Path) -> None:
    path = tmp_path / "fetch-chain.jsonl"
    path.write_text(
        "\n".join(json.dumps(event) for event in fetch_chain_population()) + "\n",
        encoding="utf-8",
    )

    assert validate_trace(path)["events"] == 3


@pytest.mark.parametrize(
    ("index", "mutation", "message"),
    [
        (
            1,
            lambda event: event["process"].update(pid=2),
            "fetch API parent|script identity",
        ),
        (
            1,
            lambda event: event["detail"].update(thread_id=2),
            "fetch API parent|script identity",
        ),
        (
            1,
            lambda event: event["execution"].update(
                context_id="frame-b", frame_id="frame-b"
            ),
            "fetch API parent|script identity",
        ),
        (
            2,
            lambda event: event["process"].update(pid=2),
            "fetch request parent|script identity",
        ),
        (
            2,
            lambda event: event["detail"].update(thread_id=2),
            "fetch request parent|script identity",
        ),
        (
            2,
            lambda event: event["execution"].update(script_id="v8:1:frame-a:8"),
            "fetch request parent|script identity",
        ),
        (
            2,
            lambda event: event.update(causal_parent_seq=0),
            "fetch request parent|script identity",
        ),
    ],
)
def test_trace_rejects_forged_fetch_chain_parent(
    tmp_path: Path,
    index: int,
    mutation,
    message: str,
) -> None:
    events = fetch_chain_population()
    mutation(events[index])
    path = tmp_path / "forged-fetch-chain.jsonl"
    path.write_text(
        "\n".join(json.dumps(event) for event in events) + "\n",
        encoding="utf-8",
    )

    with pytest.raises(ContractError, match=message):
        validate_trace(path)


def crypto_digest_population() -> list[dict[str, object]]:
    script = fetch_chain_population()[0]
    script["run_id"] = "crypto-chain"
    script["execution"] = {
        "context_id": "worker-a",
        "worker_id": "worker-a",
        "script_id": "v8:1:worker-a:7",
    }
    digest = {
        "schema": "browser-core.trace-event/1",
        "run_id": "crypto-chain",
        "seq": 1,
        "ts_monotonic_ns": 2,
        "causal_parent_seq": 0,
        "process": {"pid": 1, "type": "renderer"},
        "execution": {
            "context_id": "worker-a",
            "worker_id": "worker-a",
            "script_id": "v8:1:worker-a:7",
        },
        "event": {"category": "crypto", "name": "SubtleCrypto.digest"},
        "provenance": {"source": "native", "component": "blink.webcrypto"},
        "detail": {
            "native_name": "BrowserCore.CryptoDigest",
            "thread_id": 1,
            "algorithm": "SHA-256",
            "data_bytes": 32,
        },
        "value": {"type": "bytes", "length": 32, "redaction": "metadata"},
    }
    return [script, digest]


def generated_binding_population() -> list[dict[str, object]]:
    script = fetch_chain_population()[0]
    script["run_id"] = "binding-chain"
    binding = {
        "schema": "browser-core.trace-event/1",
        "run_id": "binding-chain",
        "seq": 1,
        "ts_monotonic_ns": 2,
        "process": {"pid": 1, "type": "renderer"},
        "execution": {
            "context_id": "frame-a",
            "frame_id": "frame-a",
            "script_id": "v8:1:frame-a:7",
        },
        "event": {"category": "api", "name": "Navigator.userAgent.get"},
        "provenance": {
            "source": "native",
            "component": "blink.bindings.generated",
            "trace_category": "blink.bindings",
        },
        "detail": {
            "native_name": "Navigator.userAgent.get",
            "thread_id": 1,
            "completion": "complete",
            "duration_ns": 7,
            "script_attribution": "matched-script-run",
        },
    }
    return [script, binding]


def test_generated_binding_requires_exact_script_match(tmp_path: Path) -> None:
    path = tmp_path / "binding-chain.jsonl"
    path.write_text(
        "\n".join(json.dumps(event) for event in generated_binding_population())
        + "\n",
        encoding="utf-8",
    )

    assert validate_trace(path)["events"] == 2


@pytest.mark.parametrize(
    "mutation",
    [
        lambda event: event["process"].update(pid=2),
        lambda event: event["detail"].update(thread_id=2),
        lambda event: event["execution"].update(
            context_id="frame-b", frame_id="frame-b"
        ),
        lambda event: event["execution"].update(script_id="v8:1:frame-a:8"),
        lambda event: (
            event["detail"].update(
                script_attribution="script-run-not-in-trace"
            ),
            event["execution"].update(
                context_id="bindings:1:1",
                frame_id="bindings:1:1",
                script_id="v8:1:bindings:1:7",
            ),
        ),
    ],
)
def test_trace_rejects_forged_generated_binding_script_match(
    tmp_path: Path,
    mutation,
) -> None:
    events = generated_binding_population()
    mutation(events[1])
    path = tmp_path / "forged-binding-chain.jsonl"
    path.write_text(
        "\n".join(json.dumps(event) for event in events) + "\n",
        encoding="utf-8",
    )

    with pytest.raises(
        ContractError,
        match="generated binding (?:script attribution|script identity)",
    ):
        validate_trace(path)


def test_trace_rejects_generated_binding_match_without_anchor(tmp_path: Path) -> None:
    event = generated_binding_population()[1]
    event["seq"] = 0
    event["ts_monotonic_ns"] = 1
    path = tmp_path / "missing-binding-anchor.jsonl"
    path.write_text(json.dumps(event) + "\n", encoding="utf-8")

    with pytest.raises(
        ContractError,
        match="generated binding (?:script attribution|script identity)",
    ):
        validate_trace(path)


def test_crypto_digest_requires_exact_script_parent(tmp_path: Path) -> None:
    path = tmp_path / "crypto-chain.jsonl"
    path.write_text(
        "\n".join(json.dumps(event) for event in crypto_digest_population()) + "\n",
        encoding="utf-8",
    )

    assert validate_trace(path)["events"] == 2


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (
            lambda event: event["process"].update(pid=2),
            "crypto digest parent|script identity",
        ),
        (
            lambda event: event["detail"].update(thread_id=2),
            "crypto digest parent|script identity",
        ),
        (
            lambda event: event["execution"].update(
                context_id="worker-b", worker_id="worker-b"
            ),
            "crypto digest parent|script identity",
        ),
        (
            lambda event: event["execution"].update(script_id="v8:1:worker-a:8"),
            "crypto digest parent|script identity",
        ),
    ],
)
def test_trace_rejects_forged_crypto_digest_parent(
    tmp_path: Path,
    mutation,
    message: str,
) -> None:
    events = crypto_digest_population()
    mutation(events[1])
    path = tmp_path / "forged-crypto-chain.jsonl"
    path.write_text(
        "\n".join(json.dumps(event) for event in events) + "\n",
        encoding="utf-8",
    )

    with pytest.raises(ContractError, match=message):
        validate_trace(path)


def message_dispatch_population() -> list[dict[str, object]]:
    return [
        {
            "schema": "browser-core.trace-event/1",
            "run_id": "message-dispatch",
            "seq": 0,
            "ts_monotonic_ns": 1,
            "process": {"pid": 1, "type": "renderer"},
            "execution": {
                "context_id": "worker-a",
                "worker_id": "worker-a",
                "script_id": "v8:1:worker-a:7",
            },
            "event": {"category": "execution", "name": "script.run"},
            "provenance": {"source": "native", "component": "blink.v8"},
            "detail": {"native_name": "BrowserCore.ScriptRun", "thread_id": 11},
        },
        {
            "schema": "browser-core.trace-event/1",
            "run_id": "message-dispatch",
            "seq": 1,
            "ts_monotonic_ns": 2,
            "causal_parent_seq": 0,
            "process": {"pid": 1, "type": "renderer"},
            "execution": {
                "context_id": "worker-a",
                "worker_id": "worker-a",
                "script_id": "v8:1:worker-a:7",
            },
            "event": {"category": "message", "name": "MessagePort.postMessage"},
            "provenance": {"source": "native", "component": "blink.messaging"},
            "detail": {"native_name": "BrowserCore.MessagePost", "thread_id": 11},
        },
        {
            "schema": "browser-core.trace-event/1",
            "run_id": "message-dispatch",
            "seq": 2,
            "ts_monotonic_ns": 3,
            "causal_parent_seq": 1,
            "process": {"pid": 2, "type": "renderer"},
            "execution": {"context_id": "frame-a", "frame_id": "frame-a"},
            "event": {
                "category": "message",
                "name": "MessagePort.message.dispatch",
            },
            "provenance": {"source": "native", "component": "blink.messaging"},
            "detail": {
                "native_name": "BrowserCore.MessageDispatch",
                "thread_id": 22,
                "dispatch_kind": "message",
            },
        },
    ]


def test_message_dispatch_may_join_cross_process_message_post(tmp_path: Path) -> None:
    path = tmp_path / "message-dispatch.jsonl"
    path.write_text(
        "\n".join(json.dumps(event) for event in message_dispatch_population()) + "\n",
        encoding="utf-8",
    )

    assert validate_trace(path)["events"] == 3


def test_message_dispatch_rejects_non_message_parent(tmp_path: Path) -> None:
    events = message_dispatch_population()
    events[1]["event"] = {"category": "api", "name": "fetch"}
    events[1]["provenance"] = {"source": "native", "component": "blink.fetch"}
    events[1]["detail"] = {"native_name": "BrowserCore.FetchCall", "thread_id": 11}
    path = tmp_path / "forged-message-dispatch.jsonl"
    path.write_text(
        "\n".join(json.dumps(event) for event in events) + "\n",
        encoding="utf-8",
    )

    with pytest.raises(ContractError, match="matching MessagePort post"):
        validate_trace(path)


@pytest.mark.parametrize("mismatch", ["process", "context", "script"])
def test_message_post_requires_matching_script_parent(
    tmp_path: Path,
    mismatch: str,
) -> None:
    events = message_dispatch_population()
    post = events[1]
    if mismatch == "process":
        post["process"] = {"pid": 2, "type": "renderer"}
    elif mismatch == "context":
        post["execution"] = {
            **post["execution"],
            "context_id": "worker-b",
            "worker_id": "worker-b",
        }
    else:
        post["execution"] = {
            **post["execution"],
            "script_id": "v8:1:worker-a:8",
        }
    path = tmp_path / f"forged-message-post-parent-{mismatch}.jsonl"
    path.write_text(
        "\n".join(json.dumps(event) for event in events) + "\n",
        encoding="utf-8",
    )

    with pytest.raises(ContractError, match="message post parent|script identity"):
        validate_trace(path)


@pytest.mark.parametrize(
    "mutation",
    [
        lambda event: event["detail"].update(native_name="BrowserCore.Forged"),
        lambda event: event["provenance"].update(component="blink.messaging"),
        lambda event: event.update(
            value={"type": "string", "redaction": "dropped"}
        ),
    ],
)
def test_message_post_rejects_forged_script_run_anchor(
    tmp_path: Path,
    mutation,
) -> None:
    events = message_dispatch_population()
    mutation(events[0])
    path = tmp_path / "forged-script-run-anchor.jsonl"
    path.write_text(
        "\n".join(json.dumps(event) for event in events) + "\n",
        encoding="utf-8",
    )

    with pytest.raises(ContractError, match="script run metadata"):
        validate_trace(path)


def test_trace_reader_bounds_one_event_before_json_allocation(tmp_path: Path) -> None:
    import browser_core.trace as trace_module

    path = tmp_path / "oversized.jsonl"
    path.write_bytes(b'{"private":"' + b"x" * trace_module.MAX_TRACE_EVENT_LINE_BYTES)

    with pytest.raises(ContractError, match="line exceeds byte limit"):
        validate_trace(path)


def test_trace_reader_normalizes_invalid_utf8_to_a_contract_error(
    tmp_path: Path,
) -> None:
    path = tmp_path / "invalid-utf8.jsonl"
    path.write_bytes(b"\xff\n")

    with pytest.raises(ContractError, match="not valid UTF-8") as raised:
        validate_trace(path)
    assert ":1:" in str(raised.value)


def test_trace_reader_rejects_duplicate_members_and_hard_links(tmp_path: Path) -> None:
    path = tmp_path / "trace.jsonl"
    body = FIXTURE.read_bytes()
    path.write_bytes(body.replace(b'"schema":', b'"schema":"duplicate","schema":', 1))
    with pytest.raises(ContractError, match="duplicate key"):
        validate_trace(path)

    path.write_bytes(body)
    os.link(path, tmp_path / "trace-alias.jsonl")
    with pytest.raises(ContractError, match="single-link"):
        validate_trace(path)


def test_trace_reader_detects_same_byte_path_replacement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import browser_core.trace as trace_module

    path = tmp_path / "trace.jsonl"
    body = FIXTURE.read_bytes()
    path.write_bytes(body)
    real_lstat = trace_module.os.lstat
    calls = 0

    def drift_after_stream(candidate: Path):
        nonlocal calls
        metadata = real_lstat(candidate)
        if Path(candidate) != path:
            return metadata
        calls += 1
        if calls == 1:
            return metadata
        return type(
            "ChangedStat",
            (),
            {
                "st_dev": metadata.st_dev,
                "st_ino": metadata.st_ino,
                "st_mode": metadata.st_mode,
                "st_size": metadata.st_size,
                "st_mtime_ns": metadata.st_mtime_ns + 1,
                "st_ctime_ns": metadata.st_ctime_ns,
                "st_nlink": metadata.st_nlink,
                "st_file_attributes": getattr(metadata, "st_file_attributes", 0),
            },
        )()

    monkeypatch.setattr(trace_module.os, "lstat", drift_after_stream)
    with pytest.raises(ContractError, match="changed during streaming"):
        validate_trace(path)


def test_trace_reader_caps_aggregate_bytes_and_pending_streams(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import browser_core.trace as trace_module

    path = tmp_path / "trace.jsonl"
    body = FIXTURE.read_bytes()
    path.write_bytes(body)
    monkeypatch.setattr(trace_module, "MAX_TRACE_BYTES", len(body) - 1)
    with pytest.raises(ContractError, match="aggregate byte limit"):
        validate_trace(path)

    monkeypatch.setattr(trace_module, "MAX_TRACE_BYTES", 1024 * 1024)
    monkeypatch.setattr(trace_module, "MAX_PENDING_STREAM_REQUESTS", 1)
    shared = {
        "schema": "browser-core.trace-event/1",
        "run_id": "pending-streams",
        "process": {"pid": 1, "type": "renderer"},
        "execution": {"context_id": "frame-a", "frame_id": "frame-a"},
            "event": {"category": "stream", "name": "stream.read.request"},
            "detail": {
                "native_name": "BrowserCore.StreamReadRequest",
                "thread_id": 1,
                "reader_mode": "default",
            },
        "provenance": {"source": "native", "component": "blink.streams"},
    }
    path.write_text(
        "\n".join(
            json.dumps({**shared, "seq": index, "ts_monotonic_ns": index + 1})
            for index in range(2)
        )
        + "\n",
        encoding="utf-8",
    )
    with pytest.raises(ContractError, match="pending stream request population"):
        validate_trace(path)


def test_trace_reader_requires_an_exact_path_type() -> None:
    with pytest.raises(ContractError, match="path must be a Path"):
        list(trace_module_iter("trace.jsonl"))


def trace_module_iter(path: object):
    from browser_core.trace import iter_trace

    return iter_trace(path)  # type: ignore[arg-type]


@pytest.mark.parametrize("status", ["caller_context_ambiguous", "script_parent_not_in_trace"])
def test_unlinked_dynamic_caller_with_one_candidate_is_rejected(tmp_path: Path, status: str) -> None:
    # The population links exactly one matching script run; claiming either
    # unresolved status for it would hide a resolvable caller.
    events = dynamic_code_population()
    dynamic = next(event for event in events
                   if event["detail"].get("native_name") == "BrowserCore.DynamicCodeMaterialized")
    dynamic.pop("causal_parent_seq", None)
    dynamic.pop("execution", None)
    dynamic["detail"]["caller_parent_status"] = status
    path = tmp_path / "forged-unresolved.jsonl"
    path.write_text("\n".join(json.dumps(event) for event in events) + "\n", encoding="utf-8")
    with pytest.raises(ContractError, match="caller parent status is inconsistent"):
        validate_trace(path)
