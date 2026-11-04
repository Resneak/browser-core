"""Bounded exact queries over one verified live or stopped research session."""
from __future__ import annotations

import re
from pathlib import Path

from .contracts import ContractError, RUN_ID_RE
from .evidence_query import (
    MAX_EVENTS,
    MAX_OUTPUT_BYTES,
    SCHEMA,
    _highwater,
    _project_event,
    _query_contract,
    _cli_rendered_size,
    _validate_native_page,
)
from .evidence_summary import _health_summary
from .incremental_inspection import IncrementalInspection
from .inspection import decode_rows
from .inspection_contract import capture_apis
from .inspection_history import history_filters, history_sql
from .recording_source import RecordingSource


_SHA256 = re.compile(r"[0-9a-f]{64}")


def _decimal(value: object, *, label: str) -> str:
    if type(value) is not int or not 0 <= value <= 2**63 - 1:
        raise ContractError(f"{label} is invalid")
    return str(value)


def _snapshot(result: dict) -> dict:
    digest = result.get("source_sha256")
    if not isinstance(digest, str) or _SHA256.fullmatch(digest) is None:
        raise ContractError("session query source digest is invalid")
    incomplete = result.get("incomplete_tail_bytes")
    if incomplete is not None:
        incomplete = _decimal(incomplete, label="session query incomplete tail")
    booleans = {
        key: result.get(key)
        for key in (
            "catching_up",
            "complete",
            "recording_settled",
            "browser_running",
            "decoder_pending_possible",
        )
    }
    if any(type(value) is not bool for value in booleans.values()):
        raise ContractError("session query snapshot state is invalid")
    phase = result.get("source_phase")
    if phase not in {
        "live-prefix",
        "finalized-recording",
        "recovered-prefix",
        "interrupted-recording",
        "limited-recording",
    }:
        raise ContractError("session query source phase is invalid")
    return {
        "source_sha256": digest,
        "snapshot_bytes": _decimal(
            result.get("snapshot_bytes"), label="session query snapshot bytes"
        ),
        "source_bytes_observed": _decimal(
            result.get("source_bytes"), label="session query source bytes"
        ),
        "pending_source_bytes": _decimal(
            result.get("pending_source_bytes"), label="session query pending bytes"
        ),
        "packets": _decimal(result.get("packets"), label="session query packets"),
        "incomplete_tail_bytes": incomplete,
        "source_phase": phase,
        **booleans,
    }


def _bounded_result(base: dict, events: list[dict], *, more_after_query: bool) -> dict:
    def candidate(count: int) -> dict:
        output = dict(base)
        output["events"] = events[:count]
        output["query"] = {
            **base["query"],
            "returned_events": count,
            "more_available": more_after_query or count < len(events),
            "output_limited": count < len(events),
            "continuation": "not-available-for-mutable-session-snapshot",
        }
        return output

    output = candidate(len(events))
    if _cli_rendered_size(output) <= MAX_OUTPUT_BYTES:
        return output
    low, high = 0, len(events)
    while low < high:
        middle = (low + high + 1) // 2
        if _cli_rendered_size(candidate(middle)) <= MAX_OUTPUT_BYTES:
            low = middle
        else:
            high = middle - 1
    if low == 0:
        raise ContractError("one session query event exceeds the output limit")
    return candidate(low)


def session_query(
    session_path: Path,
    root: Path,
    *,
    expected_run_id: str,
    reader_executable: Path | None = None,
    apis: list[str] | tuple[str, ...] = (),
    script_id: str = "",
    context_kind: str = "",
    scope: dict | None = None,
    start_ns: str = "",
    end_ns: str = "",
    limit: int = 50,
    include_values: bool = False,
    analyst_activity: list[str] | tuple[str, ...] = (),
    metadata_version: int = 1,
    portable_context: dict | None = None,
) -> dict:
    """Read one fixed ingested prefix without taking browser-control authority."""
    from .metadata_query import metadata_options, portable_context_selector
    _, activities = metadata_options(metadata_version, analyst_activity)
    portable_context = portable_context_selector(portable_context)
    if not isinstance(session_path, Path) or not session_path.is_absolute():
        raise ContractError("session query requires an absolute session path")
    if not isinstance(root, Path) or not root.is_absolute():
        raise ContractError("session query requires an absolute repository root")
    if (
        not isinstance(expected_run_id, str)
        or RUN_ID_RE.fullmatch(expected_run_id) is None
        or session_path.name != expected_run_id + ".json"
    ):
        raise ContractError("session query run binding is invalid")
    if reader_executable is not None and (
        not isinstance(reader_executable, Path) or not reader_executable.is_absolute()
    ):
        raise ContractError("session query reader must be an absolute path")
    if type(limit) is not int or not 1 <= limit <= MAX_EVENTS:
        raise ContractError("session query limit must be from 1 to 100")
    if type(include_values) is not bool:
        raise ContractError("session query value selection is invalid")
    filters = history_filters(
        script=script_id,
        context=context_kind,
        scope=scope,
        start_ns=start_ns,
        end_ns=end_ns,
        apis=apis,
    )
    query_sha256 = _query_contract(filters, limit, include_values)
    source = RecordingSource(session_path, root, reader_executable)
    from .inspection_contract import CAPTURE_OFF, recording_capture
    from .metadata_query import MetadataQueryError
    try:
        capture_mode=recording_capture(source.resolve().session)
    except ContractError as error:
        if str(error)=='session has no live recording':
            raise MetadataQueryError('session-recording-unavailable') from None
        if str(error) in {'unsupported recording capture contract',
                          'session value capture must be an object',
                          'session value capture requires the supported local allowlist'}:
            raise MetadataQueryError('capture-contract-unsupported') from None
        raise
    if capture_mode == CAPTURE_OFF:
        from .metadata_query import metadata_query
        return metadata_query(source, filters=filters, limit=limit, include_values=include_values,
                              expected_run_id=expected_run_id, analyst_activity=activities,
                              metadata_version=metadata_version, portable_context=portable_context)
    if portable_context is not None:
        raise ContractError('portable context selector requires metadata-only queries')
    if metadata_version != 1 or activities:
        raise ContractError('metadata version 2 requires metadata-only queries')
    inspector = IncrementalInspection(session_path, root, source)
    try:
        initial = inspector.read(limit=1)
        if inspector.run_id != expected_run_id or initial.get("run_id") != expected_run_id:
            raise ContractError("session query run binding changed")
        capture = {"schema": initial.get("schema"), "allowlist": initial.get("allowlist")}
        if any(api not in capture_apis(capture) for api in filters.get("apis", ())):
            raise ContractError("session query API is outside the recording contract")
        reader_runtime = initial.get("reader_runtime")
        if not isinstance(reader_runtime, dict):
            raise ContractError("session query reader runtime is unavailable")
        inspector.decoder.timeout = 30
        highwater = _highwater(inspector.decoder)
        inspector.decoder.timeout = 30
        body = inspector.decoder.query(
            history_sql(filters, highwater, limit=limit), max_rows=limit + 1
        )
        rows, total = decode_rows(body, limit=limit + 1, capture=capture)
        _validate_native_page(rows, highwater, None)
        if len(rows) < limit + 1 and total != len(rows):
            raise ContractError("session query native population disagrees with short page")
        more_after_query = len(rows) > limit
        projected = [
            _project_event(event, include_values=include_values)
            for event in rows[:limit]
        ]
        location = source.resolve()
        if location.session.get("run_id") != expected_run_id:
            raise ContractError("session query run binding changed")
        base = {
            "schema": SCHEMA,
            "status": "ok",
            "session": {
                "run_id": expected_run_id,
                "binding": "verified-session-and-recording-identity",
            },
            "snapshot": _snapshot(initial),
            "reader_runtime": reader_runtime,
            "capture": capture,
            "query": {
                "filters": filters,
                "query_sha256": query_sha256,
                "requested_limit": limit,
                "matching_events": str(total),
                "snapshot_max_id": str(highwater),
                "ordering": "timestamp-descending-then-event-id-descending",
            },
            "recording_health": _health_summary(initial.get("recording_health")),
            "semantics": {
                "private_values_included": include_values,
                "api_filter": "exact-native-name",
                "snapshot_scope": "verified-ingested-recording-prefix",
                "continuation_supported": False,
                "event_ids_are_decoder_local": True,
                "session_reference_authorizes_control": False,
                "binding_realm_is_initiating_caller": False,
                "script_source_recorded": False,
                "document_url_is_fetch_provenance": False,
                "proves_capture_complete": False,
                "server_side_architecture_observed": False,
                "query_launched_browser": False,
                "active_probe": False,
            },
        }
        return _bounded_result(base, projected, more_after_query=more_after_query)
    finally:
        inspector.close()
