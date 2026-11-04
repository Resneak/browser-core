from __future__ import annotations

import hashlib
import json
import os
import stat
from bisect import bisect_right
from collections import Counter
from contextlib import closing
from pathlib import Path
from typing import Any, Callable, Iterable, Iterator

from .contracts import (MAX_SAFE_INTEGER, ContractError, parse_canonical_decimal,
                        validate_trace_event)
from .control_files import decode_strict_json_bytes
from .windows_change_time import windows_change_time


MAX_TRACE_EVENT_LINE_BYTES = 1024 * 1024
TRACE_STREAM_BUFFER_BYTES = 64 * 1024
MAX_TRACE_EVENTS = 10_000_000
MAX_TRACE_SEQUENCE_RANGES = 1_000_000
MAX_TRACE_BYTES = 1024 * 1024 * 1024 * 1024
MAX_TRACE_LINES = 20_000_000
MAX_PENDING_STREAM_REQUESTS = 1_000_000
MAX_TRACE_SCRIPT_PARENTS = 1_000_000
MAX_TRACE_MESSAGE_POSTS = 1_000_000
MAX_TRACE_CALLBACK_PARENTS = 1_000_000
MAX_TRACE_PROMISE_PARENTS = 1_000_000
MAX_TRACE_DYNAMIC_CODE_PARENTS = 1_000_000
MAX_CALLBACK_SUMMARY_EDGES = 1024
DEFAULT_CALLBACK_SUMMARY_EDGES = 64
MAX_PROMISE_SUMMARY_EDGES = 1024
DEFAULT_PROMISE_SUMMARY_EDGES = 64
MAX_DYNAMIC_CODE_SUMMARY_EDGES = 1024
DEFAULT_DYNAMIC_CODE_SUMMARY_EDGES = 64


def _file_identity(metadata: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


class _SeenSequences:
    """Compact membership for monotonically increasing sequence numbers."""

    def __init__(self) -> None:
        self._starts: list[int] = []
        self._ends: list[int] = []

    def add(self, value: int) -> None:
        if self._ends and value == self._ends[-1] + 1:
            self._ends[-1] = value
            return
        self._starts.append(value)
        self._ends.append(value)
        if len(self._starts) > MAX_TRACE_SEQUENCE_RANGES:
            raise ContractError("trace sequence range population exceeds limit")

    def __contains__(self, value: object) -> bool:
        if isinstance(value, bool) or not isinstance(value, int):
            return False
        index = bisect_right(self._starts, value) - 1
        return index >= 0 and value <= self._ends[index]


def iter_trace(
    path: Path, *, hash_update: Callable[[bytes], None] | None = None
) -> Iterator[dict[str, Any]]:
    if not isinstance(path, Path):
        raise ContractError("trace path must be a Path")
    if hash_update is not None and not callable(hash_update):
        raise ContractError("trace hash consumer must be callable")
    try:
        path_before = os.lstat(path)
        if (
            not stat.S_ISREG(path_before.st_mode)
            or bool(getattr(path_before, "st_file_attributes", 0) & 0x400)
            or path_before.st_nlink != 1
        ):
            raise ContractError("trace must be a single-link regular file")
        if path_before.st_size > MAX_TRACE_BYTES:
            raise ContractError("trace exceeds aggregate byte limit")
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
    except ContractError:
        raise
    except OSError:
        raise ContractError("cannot open trace") from None
    # FileIO.readline() on an unbuffered descriptor performs a read per byte.
    # Buffer the reads while retaining the per-line bound and before/after file
    # identity checks; large native recordings otherwise take minutes to inspect.
    with os.fdopen(descriptor, "rb", buffering=TRACE_STREAM_BUFFER_BYTES) as stream:
        before = os.fstat(stream.fileno())
        if (
            _file_identity(before) != _file_identity(path_before)
            or before.st_nlink != 1
        ):
            raise ContractError("trace changed before streaming")
        try:
            change_before = windows_change_time(stream) if os.name == "nt" else None
        except OSError:
            raise ContractError("trace change time could not be inspected") from None
        observed_digest = hashlib.sha256() if os.name == "nt" else None
        line_number = 0
        total_bytes = 0
        while True:
            raw_bytes = stream.readline(MAX_TRACE_EVENT_LINE_BYTES + 1)
            if not raw_bytes:
                break
            line_number += 1
            total_bytes += len(raw_bytes)
            if observed_digest is not None:
                observed_digest.update(raw_bytes)
            if hash_update is not None:
                hash_update(raw_bytes)
            if line_number > MAX_TRACE_LINES:
                raise ContractError("trace line population exceeds limit")
            if total_bytes > MAX_TRACE_BYTES:
                raise ContractError("trace exceeds aggregate byte limit")
            if len(raw_bytes) > MAX_TRACE_EVENT_LINE_BYTES:
                raise ContractError(
                    f"{path}:{line_number}: trace event line exceeds byte limit"
                )
            if not raw_bytes.strip():
                continue
            try:
                raw_bytes.decode("utf-8", errors="strict")
            except UnicodeDecodeError:
                raise ContractError(
                    f"{path}:{line_number}: trace event is not valid UTF-8"
                ) from None
            try:
                document = decode_strict_json_bytes(
                    raw_bytes,
                    label="trace event",
                )
                yield validate_trace_event(document)
            except ContractError as exc:
                raise ContractError(f"{path}:{line_number}: {exc}") from exc
        after = os.fstat(stream.fileno())
        confirmed_after = after
        confirmed_bytes = total_bytes
        bytes_changed = False
        if observed_digest is not None:
            # Native change time can retain one tick across a fast same-size
            # write and mtime restoration. Re-read at most the observed byte
            # count plus one byte on the same handle before accepting events.
            try:
                stream.seek(0)
                confirmed_digest = hashlib.sha256()
                confirmed_bytes = 0
                while confirmed_bytes <= total_bytes:
                    chunk = stream.read(
                        min(1024 * 1024, total_bytes + 1 - confirmed_bytes)
                    )
                    if not chunk:
                        break
                    confirmed_bytes += len(chunk)
                    confirmed_digest.update(chunk)
                confirmed_after = os.fstat(stream.fileno())
                bytes_changed = (
                    confirmed_bytes != total_bytes
                    or confirmed_digest.digest() != observed_digest.digest()
                )
            except OSError:
                raise ContractError("trace changed during streaming") from None
        try:
            change_after = windows_change_time(stream) if os.name == "nt" else None
        except OSError:
            raise ContractError("trace changed during streaming") from None
    try:
        path_after = os.lstat(path)
    except OSError:
        raise ContractError("trace changed during streaming") from None
    if (
        _file_identity(path_before) != _file_identity(before)
        or _file_identity(before) != _file_identity(after)
        or _file_identity(after) != _file_identity(confirmed_after)
        or _file_identity(confirmed_after) != _file_identity(path_after)
        or total_bytes != after.st_size
        or confirmed_bytes != confirmed_after.st_size
        or bytes_changed
        or confirmed_after.st_nlink != 1
        or change_before != change_after
    ):
        raise ContractError("trace changed during streaming")


def _validate_event_population(
    events: Iterator[dict[str, Any]],
    *,
    retained: list[dict[str, Any]] | None = None,
    maximum_events: int = MAX_TRACE_EVENTS,
) -> dict[str, Any]:
    if (
        isinstance(maximum_events, bool)
        or not isinstance(maximum_events, int)
        or not 1 <= maximum_events <= MAX_TRACE_EVENTS
    ):
        raise ContractError("trace event limit is invalid")
    run_id: str | None = None
    previous_seq = -1
    previous_ts = -1
    seen = _SeenSequences()
    stream_requests: dict[int, dict[str, Any]] = {}
    script_parents: dict[int, tuple[int, str, str, str, int]] = {}
    script_anchors: dict[tuple[int, str, int, str], str] = {}
    script_number_anchors: set[tuple[int, str, int, int]] = set()
    script_number_parents: dict[
        tuple[int, str, int, int], dict[str, int]
    ] = {}
    script_run_inspector_ids: dict[int, int] = {}
    fetch_apis: dict[int, tuple[int, str, str, str | None, int]] = {}
    message_posts: set[int] = set()
    message_dispatches: dict[int, dict[str, Any]] = {}
    host_callbacks: dict[int, dict[str, Any]] = {}
    promise_microtasks: dict[int, dict[str, Any]] = {}
    dynamic_code_materializations: dict[int, dict[str, Any]] = {}
    latest_dynamic_materializations: dict[tuple[int, int, int], int] = {}
    count = 0
    drops = 0
    for event in events:
        if count >= maximum_events:
            raise ContractError("trace event population exceeds limit")
        if run_id is None:
            run_id = event["run_id"]
        elif event["run_id"] != run_id:
            raise ContractError("trace contains more than one run_id")
        seq = event["seq"]
        timestamp = event["ts_monotonic_ns"]
        if seq <= previous_seq:
            raise ContractError(f"trace seq {seq} is not strictly increasing")
        if timestamp < previous_ts:
            raise ContractError(f"trace timestamp regressed at seq {seq}")
        parent = event.get("causal_parent_seq")
        if parent is not None and parent not in seen:
            raise ContractError(f"trace causal parent {parent} is missing or not earlier")
        # Dynamic execution identifies the caller, which can differ from an
        # enclosing callback/job's realm. Its unique, exact ScriptRun parent is
        # independently required below; scopes must still match process/thread/time.
        dynamic_caller_event = event["event"] == {
            "category": "execution", "name": "dynamic.code.materialized"
        }
        callback_parent = event.get("callback_parent_seq")
        callback: dict[str, Any] | None = None
        if callback_parent is not None:
            callback = host_callbacks.get(callback_parent)
            if callback is None:
                raise ContractError(
                    "trace callback parent is not an earlier host callback"
                )
            callback_detail = callback.get("detail") or {}
            callback_execution = callback.get("execution") or {}
            child_execution = event.get("execution") or {}
            callback_start = callback["ts_monotonic_ns"]
            callback_duration = callback_detail.get("duration_ns")
            if (
                callback.get("process") != event.get("process")
                or callback_detail.get("thread_id")
                != (event.get("detail") or {}).get("thread_id")
                or (
                    child_execution.get("context_id") is not None
                    and child_execution.get("context_id")
                    != callback_execution.get("context_id")
                    and not dynamic_caller_event
                    and not (
                        event.get("provenance", {}).get("component")
                        == "blink.bindings.generated"
                        and (event.get("detail") or {}).get(
                            "context_attribution"
                        )
                        in {
                            "native-binding-owner",
                            "native-binding-owner-limited",
                        }
                    )
                )
                or timestamp < callback_start
                or callback_duration is not None
                and timestamp >= callback_start + callback_duration
            ):
                raise ContractError("trace callback parent scope is inconsistent")
        promise_parent = event.get("promise_parent_seq")
        promise: dict[str, Any] | None = None
        if promise_parent is not None:
            promise = promise_microtasks.get(promise_parent)
            promise_detail = (promise or {}).get("detail") or {}
            promise_execution = (promise or {}).get("execution") or {}
            child_execution = event.get("execution") or {}
            promise_start = (promise or {}).get("ts_monotonic_ns", timestamp + 1)
            promise_duration = promise_detail.get("duration_ns")
            if (
                promise is None
                or promise.get("process") != event.get("process")
                or promise_detail.get("thread_id")
                != (event.get("detail") or {}).get("thread_id")
                or (
                    child_execution.get("context_id") is not None
                    and child_execution.get("context_id")
                    != promise_execution.get("context_id")
                    and not dynamic_caller_event
                    and not (
                        event.get("provenance", {}).get("component")
                        == "blink.bindings.generated"
                        and (event.get("detail") or {}).get(
                            "context_attribution"
                        )
                        in {
                            "native-binding-owner",
                            "native-binding-owner-limited",
                        }
                    )
                )
                or timestamp < promise_start
                or promise_duration is not None
                and timestamp >= promise_start + promise_duration
            ):
                raise ContractError("trace promise parent scope is inconsistent")
        dynamic_code_parent = event.get("dynamic_code_parent_seq")
        if dynamic_code_parent is not None:
            dynamic_parent = dynamic_code_materializations.get(dynamic_code_parent)
            dynamic_detail = (dynamic_parent or {}).get("detail") or {}
            child_detail = event.get("detail") or {}
            child_execution = event.get("execution") or {}
            child_script_id = child_execution.get("script_id")
            child_script_number = parse_canonical_decimal(
                child_script_id.rsplit(":", 1)[-1]
                if isinstance(child_script_id, str)
                else "",
                minimum=0,
                maximum=2_147_483_647,
            )
            if event.get("event") == {
                "category": "execution",
                "name": "dynamic.code.materialized",
            }:
                caller_script_id = child_detail.get("caller_script_id")
                child_script_number = (
                    caller_script_id
                    if isinstance(caller_script_id, int) and caller_script_id >= 0
                    else None
                )
            if (
                dynamic_parent is None
                or dynamic_parent.get("process") != event.get("process")
                or dynamic_detail.get("thread_id") != child_detail.get("thread_id")
                or child_script_number != dynamic_detail.get("generated_script_id")
            ):
                raise ContractError("trace dynamic code parent scope is inconsistent")
            dynamic_key = (
                event["process"]["pid"],
                child_detail["thread_id"],
                child_script_number,
            )
            if latest_dynamic_materializations.get(dynamic_key) != dynamic_code_parent:
                raise ContractError(
                    "trace dynamic code parent is not the most recent materialization"
                )
        message_dispatch_parent = event.get("message_dispatch_parent_seq")
        if message_dispatch_parent is not None:
            dispatch = message_dispatches.get(message_dispatch_parent)
            callback_detail = event.get("detail") or {}
            dispatch_detail = (dispatch or {}).get("detail") or {}
            callback_execution = event.get("execution") or {}
            dispatch_execution = (dispatch or {}).get("execution") or {}
            if (
                dispatch is None
                or event.get("event")
                != {"category": "execution", "name": "host.callback.execution"}
                or dispatch.get("event")
                != {"category": "message", "name": "MessagePort.message.dispatch"}
                or dispatch.get("process") != event.get("process")
                or dispatch_detail.get("thread_id") != callback_detail.get("thread_id")
                or dispatch_execution.get("context_id")
                != callback_execution.get("context_id")
                or dispatch.get("ts_monotonic_ns", timestamp + 1) > timestamp
                or callback_detail.get("callback_interface") != "EventListener"
                or callback_detail.get("callback_operation") != "handleEvent"
                or callback_detail.get("callback_kind") != "function"
                or callback_detail.get("message_dispatch_parent_status") is not None
            ):
                raise ContractError(
                    "trace host callback message dispatch parent is inconsistent"
                )
        if event["event"] == {
            "category": "stream", "name": "stream.read.result"
        }:
            parent_event = stream_requests.pop(parent, None)
            if parent_event is None:
                raise ContractError(
                    "trace stream result parent is not its matching read request"
                )
            if parent_event["event"] != {
                "category": "stream", "name": "stream.read.request"
            } or parent_event.get("process") != event.get("process") \
                    or (parent_event.get("execution") or {}).get("context_id") != (
                        event.get("execution") or {}
                    ).get("context_id") \
                    or parent_event.get("detail", {}).get("reader_mode") != (
                        event.get("detail", {}).get("reader_mode")
                    ) \
                    or parent_event.get("detail", {}).get("thread_id") != (
                        event.get("detail", {}).get("thread_id")
                    ):
                raise ContractError(
                    "trace stream result parent is not its matching read request"
                )
        if event["event"] == {
            "category": "stream", "name": "stream.read.request"
        }:
            execution = event.get("execution") or {}
            script_id = execution.get("script_id")
            if parent is not None:
                expected_script = (
                    event["process"]["pid"],
                    event["process"]["type"],
                    execution.get("context_id"),
                    script_id,
                    event["detail"]["thread_id"],
                )
                if script_parents.get(parent) != expected_script:
                    raise ContractError(
                        "trace stream request parent is not its matching script run"
                    )
        if event["event"] == {"category": "stream", "name": "body.consume"}:
            execution = event.get("execution") or {}
            script_id = execution.get("script_id")
            if parent is not None:
                parent_script = script_parents.get(parent)
                expected_script = (
                    event["process"]["pid"],
                    event["process"]["type"],
                    execution.get("context_id"),
                    script_id,
                    event["detail"]["thread_id"],
                )
                if parent_script != expected_script:
                    raise ContractError(
                        "trace body consumer parent is not its matching script run"
                    )
        if event["event"] == {"category": "crypto", "name": "SubtleCrypto.digest"}:
            execution = event.get("execution") or {}
            script_id = execution.get("script_id")
            if parent is not None:
                expected_script = (
                    event["process"]["pid"],
                    event["process"]["type"],
                    execution.get("context_id"),
                    script_id,
                    event["detail"]["thread_id"],
                )
                if script_parents.get(parent) != expected_script:
                    raise ContractError(
                        "trace crypto digest parent is not its matching script run"
                    )
        if event["event"] == {
            "category": "execution",
            "name": "dynamic.code.materialized",
        }:
            execution = event.get("execution") or {}
            detail = event["detail"]
            caller_script_number = detail["caller_script_id"]
            caller_key = (
                event["process"]["pid"],
                event["process"]["type"],
                detail["thread_id"],
                caller_script_number,
            )
            caller_candidates = (
                script_number_parents.get(caller_key, {})
                if caller_script_number >= 0
                else {}
            )
            caller_inspector_id = detail.get("caller_inspector_context_id")
            if caller_inspector_id is not None:
                # Only runs observed in the caller frame's own context remain.
                caller_candidates = {
                    script_id: candidate_seq
                    for script_id, candidate_seq in caller_candidates.items()
                    if script_run_inspector_ids.get(candidate_seq) == caller_inspector_id
                }
            if parent is not None:
                expected_script = (
                    event["process"]["pid"],
                    event["process"]["type"],
                    execution.get("context_id"),
                    execution.get("script_id"),
                    event["detail"]["thread_id"],
                )
                # Enclosing callback/Promise scopes do not establish the selected
                # caller frame's realm, even when their contexts and scripts agree.
                # Reject a claimed resolution whenever multiple realms remain.
                if (
                    len(caller_candidates) != 1
                    or caller_candidates.get(execution.get("script_id")) != parent
                    or script_parents.get(parent) != expected_script
                ):
                    raise ContractError(
                        "trace dynamic code caller is not its matching script run"
                    )
            elif (
                (detail.get("caller_parent_status") == "caller_context_ambiguous")
                != (len(caller_candidates) > 1)
                or len(caller_candidates) == 1
            ):
                # "ambiguous" is legal only when at least two earlier script
                # runs share the caller's ScriptId; "not in trace" only when
                # none does. A single candidate must have been linked.
                raise ContractError(
                    "trace dynamic code caller parent status is inconsistent"
                )
        if event["event"] == {"category": "api", "name": "fetch"}:
            execution = event.get("execution") or {}
            script_id = execution.get("script_id")
            if parent is not None:
                expected_script = (
                    event["process"]["pid"],
                    event["process"]["type"],
                    execution.get("context_id"),
                    script_id,
                    event["detail"]["thread_id"],
                )
                if script_parents.get(parent) != expected_script:
                    raise ContractError(
                        "trace fetch API parent is not its matching script run"
                    )
        if (
            event["event"].get("category") == "api"
            and event.get("provenance", {}).get("component")
            == "blink.bindings.generated"
        ):
            execution = event.get("execution") or {}
            detail = event.get("detail") or {}
            script_id = execution.get("script_id")
            attribution = detail.get("script_attribution")
            anchor_key = (
                event["process"]["pid"],
                event["process"]["type"],
                detail.get("thread_id"),
                script_id,
            )
            if attribution == "matched-script-run":
                if script_anchors.get(anchor_key) != execution.get("context_id"):
                    raise ContractError(
                        "trace generated binding script attribution is inconsistent"
                    )
            elif attribution == "callback-contained":
                callback_execution = (callback or {}).get("execution") or {}
                if (
                    callback is None
                    or execution.get("context_id")
                    != callback_execution.get("context_id")
                ):
                    raise ContractError(
                        "trace generated binding callback attribution is inconsistent"
                    )
            elif attribution == "script-run-not-in-trace":
                script_number = parse_canonical_decimal(
                    script_id.rsplit(":", 1)[-1]
                    if isinstance(script_id, str)
                    else "",
                    minimum=0,
                    maximum=2_147_483_647,
                )
                number_key = (
                    event["process"]["pid"],
                    event["process"]["type"],
                    detail.get("thread_id"),
                    script_number,
                )
                if script_number is None or number_key in script_number_anchors:
                    raise ContractError(
                        "trace generated binding script attribution is inconsistent"
                    )
        if event["event"] == {
            "category": "network",
            "name": "fetch.request.start",
        }:
            execution = event.get("execution") or {}
            expected_api = (
                event["process"]["pid"],
                event["process"]["type"],
                execution.get("context_id"),
                execution.get("script_id"),
                event["detail"]["thread_id"],
            )
            if fetch_apis.get(parent) != expected_api:
                raise ContractError(
                    "trace fetch request parent is not its matching fetch API"
                )
        if event["event"] == {
            "category": "message",
            "name": "MessagePort.postMessage",
        }:
            execution = event.get("execution") or {}
            script_id = execution.get("script_id")
            if parent is not None:
                parent_script = script_parents.get(parent)
                expected_script = (
                    event["process"]["pid"],
                    event["process"]["type"],
                    execution.get("context_id"),
                    script_id,
                    event["detail"]["thread_id"],
                )
                if parent_script != expected_script:
                    raise ContractError(
                        "trace message post parent is not its matching script run"
                    )
        if event["event"] == {
            "category": "message",
            "name": "MessagePort.message.dispatch",
        } and parent is not None and parent not in message_posts:
            raise ContractError(
                "trace message dispatch parent is not its matching MessagePort post"
            )
        seen.add(seq)
        if event["event"] == {
            "category": "execution",
            "name": "host.callback.execution",
        }:
            host_callbacks[seq] = event
            if len(host_callbacks) > MAX_TRACE_CALLBACK_PARENTS:
                raise ContractError("trace callback parent population exceeds limit")
        if event["event"] == {
            "category": "execution",
            "name": "promise.microtask.execution",
        }:
            promise_microtasks[seq] = event
            if len(promise_microtasks) > MAX_TRACE_PROMISE_PARENTS:
                raise ContractError("trace promise parent population exceeds limit")
        if event["event"] == {
            "category": "execution",
            "name": "dynamic.code.materialized",
        }:
            dynamic_code_materializations[seq] = event
            dynamic_detail = event["detail"]
            latest_dynamic_materializations[
                (
                    event["process"]["pid"],
                    dynamic_detail["thread_id"],
                    dynamic_detail["generated_script_id"],
                )
            ] = seq
            if (
                len(dynamic_code_materializations)
                > MAX_TRACE_DYNAMIC_CODE_PARENTS
            ):
                raise ContractError(
                    "trace dynamic code parent population exceeds limit"
                )
        if event["event"] == {"category": "execution", "name": "script.run"}:
            execution = event.get("execution") or {}
            context_id = execution.get("context_id")
            script_id = execution.get("script_id")
            if isinstance(context_id, str) and isinstance(script_id, str):
                script_parents[seq] = (
                    event["process"]["pid"],
                    event["process"]["type"],
                    context_id,
                    script_id,
                    event["detail"]["thread_id"],
                )
                if len(script_parents) > MAX_TRACE_SCRIPT_PARENTS:
                    raise ContractError("trace script parent population exceeds limit")
                script_anchors[
                    (
                        event["process"]["pid"],
                        event["process"]["type"],
                        event["detail"]["thread_id"],
                        script_id,
                    )
                ] = context_id
                script_number = parse_canonical_decimal(
                    script_id.rsplit(":", 1)[-1],
                    minimum=0,
                    maximum=2_147_483_647,
                )
                if script_number is not None:
                    number_key = (
                        event["process"]["pid"],
                        event["process"]["type"],
                        event["detail"]["thread_id"],
                        script_number,
                    )
                    script_number_anchors.add(number_key)
                    script_number_parents.setdefault(number_key, {})[
                        script_id
                    ] = seq
                    if "inspector_context_id" in event["detail"]:
                        script_run_inspector_ids[seq] = event["detail"]["inspector_context_id"]
        if event["event"] == {
            "category": "message",
            "name": "MessagePort.postMessage",
        }:
            message_posts.add(seq)
            if len(message_posts) > MAX_TRACE_MESSAGE_POSTS:
                raise ContractError("trace message post population exceeds limit")
        if event["event"] == {
            "category": "message",
            "name": "MessagePort.message.dispatch",
        }:
            message_dispatches[seq] = event
            if len(message_dispatches) > MAX_TRACE_MESSAGE_POSTS:
                raise ContractError("trace message dispatch population exceeds limit")
        if event["event"] == {"category": "api", "name": "fetch"}:
            execution = event.get("execution") or {}
            fetch_apis[seq] = (
                event["process"]["pid"],
                event["process"]["type"],
                execution.get("context_id"),
                execution.get("script_id"),
                event["detail"]["thread_id"],
            )
            if len(fetch_apis) > MAX_TRACE_SCRIPT_PARENTS:
                raise ContractError("trace fetch API population exceeds limit")
        if event["event"] == {
            "category": "stream", "name": "stream.read.request"
        }:
            # Only stream results inspect their parent's content. Every other
            # causal check needs membership/order alone, so retaining hundreds of
            # thousands of complete generated-binding events is unnecessary.
            stream_requests[seq] = event
            if len(stream_requests) > MAX_PENDING_STREAM_REQUESTS:
                raise ContractError("pending stream request population exceeds limit")
        previous_seq = seq
        previous_ts = timestamp
        count += 1
        if event["event"]["category"] == "diagnostic" and event["event"]["name"] == "trace.dropped":
            drop_detail = event.get("detail")
            drop_count = drop_detail.get("count") if isinstance(drop_detail, dict) else None
            if (type(drop_count) is not int or drop_count < 0
                    or drops + drop_count > MAX_SAFE_INTEGER):
                raise ContractError("trace dropped-event count is invalid")
            drops += drop_count
        if retained is not None:
            retained.append(event)
    if count == 0:
        raise ContractError("trace is empty")
    return {"run_id": run_id, "events": count, "dropped_events": drops}


def validate_trace(
    path: Path, *, maximum_events: int | None = None
) -> dict[str, Any]:
    effective_limit = MAX_TRACE_EVENTS if maximum_events is None else maximum_events
    # A population error can leave the suspended generator's file open through
    # its traceback. Close it deterministically before temporary-file cleanup.
    with closing(iter_trace(path)) as events:
        return _validate_event_population(events, maximum_events=effective_limit)


def scan_validated_trace(
    path: Path, consume: Callable[[dict[str, Any]], None],
    *, hash_update: Callable[[bytes], None] | None = None,
    maximum_events: int | None = None,
) -> dict[str, Any]:
    """Accumulate a report during one bounded, validated file snapshot.

    Consumer state is provisional until this function returns successfully:
    late lineage errors and file mutations must discard the entire report.
    Consumers must not publish artifacts or perform external actions.
    """
    if not callable(consume):
        raise ContractError("trace consumer must be callable")
    if hash_update is not None and not callable(hash_update):
        raise ContractError("trace hash consumer must be callable")
    effective_limit = MAX_TRACE_EVENTS if maximum_events is None else maximum_events

    with closing(iter_trace(path, hash_update=hash_update)) as events:
        def observed_events():
            for event in events:
                consume(event)
                yield event

        return _validate_event_population(
            observed_events(), maximum_events=effective_limit
        )


def load_validated_trace(
    path: Path,
    *,
    maximum_events: int | None = None,
) -> tuple[dict[str, Any], list[dict[str, Any]], dict[int, dict[str, Any]]]:
    effective_limit = MAX_TRACE_EVENTS if maximum_events is None else maximum_events
    events: list[dict[str, Any]] = []
    with closing(iter_trace(path)) as source:
        summary = _validate_event_population(
            source,
            retained=events,
            maximum_events=effective_limit,
        )
    return summary, events, {event["seq"]: event for event in events}


def _load_index_with_summary(
    path: Path,
) -> tuple[dict[str, Any], list[dict[str, Any]], dict[int, dict[str, Any]]]:
    return load_validated_trace(path)


def load_index(path: Path) -> tuple[list[dict[str, Any]], dict[int, dict[str, Any]]]:
    _summary, events, index = _load_index_with_summary(path)
    return events, index


def summarize(
    path: Path,
    *,
    callback_edge_limit: int = DEFAULT_CALLBACK_SUMMARY_EDGES,
    promise_edge_limit: int = DEFAULT_PROMISE_SUMMARY_EDGES,
    dynamic_code_edge_limit: int = DEFAULT_DYNAMIC_CODE_SUMMARY_EDGES,
) -> dict[str, Any]:
    if (
        isinstance(callback_edge_limit, bool)
        or not isinstance(callback_edge_limit, int)
        or not 0 <= callback_edge_limit <= MAX_CALLBACK_SUMMARY_EDGES
    ):
        raise ContractError("callback summary edge limit must be from 0 to 1024")
    if (
        isinstance(promise_edge_limit, bool)
        or not isinstance(promise_edge_limit, int)
        or not 0 <= promise_edge_limit <= MAX_PROMISE_SUMMARY_EDGES
    ):
        raise ContractError("promise summary edge limit must be from 0 to 1024")
    if (
        isinstance(dynamic_code_edge_limit, bool)
        or not isinstance(dynamic_code_edge_limit, int)
        or not 0
        <= dynamic_code_edge_limit
        <= MAX_DYNAMIC_CODE_SUMMARY_EDGES
    ):
        raise ContractError("dynamic code summary edge limit must be from 0 to 1024")
    validation, events, by_seq = _load_index_with_summary(path)
    categories = Counter(event["event"]["category"] for event in events)
    processes = Counter(event["process"]["type"] for event in events)
    contexts = {
        value
        for event in events
        if (value := (event.get("execution") or {}).get("context_id")) is not None
    }
    callback_events = [
        event
        for event in events
        if event["event"]
        == {"category": "execution", "name": "host.callback.execution"}
    ]
    callback_interfaces = Counter(
        event["detail"]["callback_interface"] for event in callback_events
    )
    callback_operations = Counter(
        event["detail"]["callback_operation"] for event in callback_events
    )
    callback_kinds = Counter(
        event["detail"]["callback_kind"] for event in callback_events
    )
    callback_contexts = {
        event["execution"]["context_id"] for event in callback_events
    }
    callback_edges: Counter[tuple[str, str, str, str, str]] = Counter()
    message_dispatch_kinds: Counter[str] = Counter()
    message_dispatch_linked_callbacks = 0
    message_dispatch_parent_not_in_trace = 0
    for callback in callback_events:
        message_parent_seq = callback.get("message_dispatch_parent_seq")
        if message_parent_seq is not None:
            message_dispatch_linked_callbacks += 1
            message_dispatch_kinds[
                by_seq[message_parent_seq]["detail"]["dispatch_kind"]
            ] += 1
        elif callback["detail"].get("message_dispatch_parent_status") == (
            "message_dispatch_parent_not_in_trace"
        ):
            message_dispatch_parent_not_in_trace += 1
    callback_contained_events = 0
    for event in events:
        parent_seq = event.get("callback_parent_seq")
        if parent_seq is None:
            continue
        callback_contained_events += 1
        parent = by_seq[parent_seq]
        callback_edges[
            (
                parent["detail"]["callback_interface"],
                parent["detail"]["callback_operation"],
                parent["detail"]["callback_kind"],
                event["event"]["category"],
                event["event"]["name"],
            )
        ] += 1
    ordered_edges = sorted(
        callback_edges.items(),
        key=lambda item: (-item[1], item[0]),
    )
    reported_edges = ordered_edges[:callback_edge_limit]
    promise_events = [
        event
        for event in events
        if event["event"]
        == {"category": "execution", "name": "promise.microtask.execution"}
    ]
    promise_edges: Counter[tuple[str, str]] = Counter()
    promise_contained_events = 0
    for event in events:
        parent_seq = event.get("promise_parent_seq")
        if parent_seq is None:
            continue
        promise_contained_events += 1
        promise_edges[(event["event"]["category"], event["event"]["name"])] += 1
    ordered_promise_edges = sorted(
        promise_edges.items(),
        key=lambda item: (-item[1], item[0]),
    )
    reported_promise_edges = ordered_promise_edges[:promise_edge_limit]
    dynamic_code_events = [
        event
        for event in events
        if event["event"]
        == {"category": "execution", "name": "dynamic.code.materialized"}
    ]
    dynamic_code_kinds = Counter(
        event["detail"]["dynamic_kind"] for event in dynamic_code_events
    )
    dynamic_code_cache_statuses = Counter(
        event["detail"]["cache_status"] for event in dynamic_code_events
    )
    dynamic_code_edges: Counter[tuple[str, str, str]] = Counter()
    dynamically_attributed_events = 0
    for event in events:
        parent_seq = event.get("dynamic_code_parent_seq")
        if parent_seq is None:
            continue
        dynamically_attributed_events += 1
        parent = by_seq[parent_seq]
        dynamic_code_edges[
            (
                parent["detail"]["dynamic_kind"],
                event["event"]["category"],
                event["event"]["name"],
            )
        ] += 1
    ordered_dynamic_code_edges = sorted(
        dynamic_code_edges.items(),
        key=lambda item: (-item[1], item[0]),
    )
    reported_dynamic_code_edges = ordered_dynamic_code_edges[
        :dynamic_code_edge_limit
    ]
    return {
        **validation,
        "categories": dict(sorted(categories.items())),
        "processes": dict(sorted(processes.items())),
        "execution_contexts": len(contexts),
        "callback_summary": {
            "host_callback_executions": len(callback_events),
            "callback_contained_events": callback_contained_events,
            "execution_contexts": len(callback_contexts),
            "interfaces": dict(sorted(callback_interfaces.items())),
            "operations": dict(sorted(callback_operations.items())),
            "kinds": dict(sorted(callback_kinds.items())),
            "message_dispatch_linked_callbacks": message_dispatch_linked_callbacks,
            "message_dispatch_parent_not_in_trace": (
                message_dispatch_parent_not_in_trace
            ),
            "message_dispatch_kinds": dict(sorted(message_dispatch_kinds.items())),
            "edge_groups_total": len(ordered_edges),
            "edge_groups_reported": len(reported_edges),
            "edge_groups_truncated": len(reported_edges) != len(ordered_edges),
            "contained_event_edges": [
                {
                    "callback_interface": key[0],
                    "callback_operation": key[1],
                    "callback_kind": key[2],
                    "event_category": key[3],
                    "event_name": key[4],
                    "count": count,
                }
                for key, count in reported_edges
            ],
            "semantics": {
                "edge": "same-track-temporal-containment",
                "message_dispatch_edge": "native-event-object-identity",
                "page_ownership_inferred": False,
                "callback_success_inferred": False,
                "private_values_included": False,
            },
        },
        "promise_summary": {
            "promise_microtask_executions": len(promise_events),
            "complete_executions": sum(
                event["detail"]["completion"] == "complete"
                for event in promise_events
            ),
            "open_executions": sum(
                event["detail"]["completion"] == "open"
                for event in promise_events
            ),
            "contained_events": promise_contained_events,
            "execution_contexts": len(
                {
                    event["execution"]["context_id"]
                    for event in promise_events
                }
            ),
            "edge_groups_total": len(ordered_promise_edges),
            "edge_groups_reported": len(reported_promise_edges),
            "edge_groups_truncated": (
                len(reported_promise_edges) != len(ordered_promise_edges)
            ),
            "contained_event_edges": [
                {
                    "event_category": key[0],
                    "event_name": key[1],
                    "count": count,
                }
                for key, count in reported_promise_edges
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
        },
        "dynamic_code_summary": {
            "materializations": len(dynamic_code_events),
            "generated_scripts": len(
                {
                    (
                        event["process"]["pid"],
                        event["detail"]["thread_id"],
                        event["detail"]["generated_script_id"],
                    )
                    for event in dynamic_code_events
                }
            ),
            "dynamically_attributed_events": dynamically_attributed_events,
            "caller_links": sum(
                event.get("causal_parent_seq") is not None
                for event in dynamic_code_events
            ),
            "caller_parent_not_in_trace": sum(
                event["detail"].get("caller_parent_status")
                == "script_parent_not_in_trace"
                for event in dynamic_code_events
            ),
            "caller_context_ambiguous": sum(
                event["detail"].get("caller_parent_status")
                == "caller_context_ambiguous"
                for event in dynamic_code_events
            ),
            "caller_unavailable": sum(
                event["detail"]["caller_status"] == "unavailable"
                for event in dynamic_code_events
            ),
            "kinds": dict(sorted(dynamic_code_kinds.items())),
            "cache_statuses": dict(sorted(dynamic_code_cache_statuses.items())),
            "source_utf16_code_units_total": sum(
                event["detail"]["source_length"] for event in dynamic_code_events
            ),
            "source_utf16_code_units_max": max(
                (
                    event["detail"]["source_length"]
                    for event in dynamic_code_events
                ),
                default=0,
            ),
            "edge_groups_total": len(ordered_dynamic_code_edges),
            "edge_groups_reported": len(reported_dynamic_code_edges),
            "edge_groups_truncated": (
                len(reported_dynamic_code_edges) != len(ordered_dynamic_code_edges)
            ),
            "attributed_event_edges": [
                {
                    "dynamic_kind": key[0],
                    "event_category": key[1],
                    "event_name": key[2],
                    "count": count,
                }
                for key, count in reported_dynamic_code_edges
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
        },
    }


def who_read(path: Path, signal: str) -> list[dict[str, Any]]:
    events, _ = load_index(path)
    return [
        event
        for event in events
        if event["event"]["category"] == "api" and event["event"]["name"] == signal
    ]


def causal_chain(path: Path, request_id: str) -> list[dict[str, Any]]:
    events, by_seq = load_index(path)
    candidates = [
        event
        for event in events
        if event["event"]["category"] == "network"
        and (event.get("request") or {}).get("id") == request_id
    ]
    if not candidates:
        raise ContractError(f"request id not found: {request_id}")
    current = candidates[-1]
    chain = [current]
    visited = {current["seq"]}
    while current.get("causal_parent_seq") is not None:
        parent_seq = current["causal_parent_seq"]
        if parent_seq in visited:
            raise ContractError("causal cycle detected")
        current = by_seq[parent_seq]
        chain.append(current)
        visited.add(parent_seq)
    chain.reverse()
    return chain


def json_lines(events: Iterable[dict[str, Any]]) -> str:
    return "\n".join(json.dumps(event, sort_keys=True) for event in events)
