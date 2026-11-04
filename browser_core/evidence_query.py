"""Bounded, stateless private-value queries over a verified evidence bundle."""
from __future__ import annotations

import base64
import hashlib
import json
import re
from pathlib import Path

from .contracts import ContractError
from .control_files import canonical_json_bytes, decode_strict_json_bytes
from .evidence_bundle import OpenEvidence
from .evidence_summary import _health_summary
from .incremental_inspection import IncrementalInspection
from .inspection import decode_rows
from .inspection_contract import capture_apis
from .inspection_history import decode_highwater, history_filters, history_sql


SCHEMA = "browser-core.evidence-query/1"
CURSOR_SCHEMA = "browser-core.evidence-query-cursor/1"
MAX_EVENTS = 100
MAX_OUTPUT_BYTES = 4 * 1024 * 1024
MAX_CURSOR_BYTES = 1024
_SHA256 = re.compile(r"[0-9a-f]{64}")
_DECIMAL = re.compile(r"0|[1-9][0-9]{0,18}")


def _exact_decimal(value: object, *, label: str, signed: bool = False) -> str:
    pattern = r"-1|0|[1-9][0-9]{0,18}" if signed else _DECIMAL.pattern
    if not isinstance(value, str) or re.fullmatch(pattern, value) is None:
        raise ContractError(f"{label} is invalid")
    if int(value) > 2**63 - 1:
        raise ContractError(f"{label} is invalid")
    return value


def _query_contract(filters: dict, limit: int, include_values: bool) -> str:
    body = canonical_json_bytes(
        {
            "filters": filters,
            "include_values": include_values,
            "limit": limit,
            "ordering": "timestamp-descending-then-event-id-descending",
        }
    )
    return hashlib.sha256(body).hexdigest()


def encode_cursor(
    bundle_sha256: str,
    query_sha256: str,
    highwater: int,
    timestamp: int,
    event_id: int,
) -> str:
    for digest in (bundle_sha256, query_sha256):
        if not isinstance(digest, str) or _SHA256.fullmatch(digest) is None:
            raise ContractError("evidence query cursor digest is invalid")
    for value in (highwater, timestamp, event_id):
        if type(value) is not int or not 0 <= value <= 2**63 - 1:
            raise ContractError("evidence query cursor boundary is invalid")
    if event_id > highwater:
        raise ContractError("evidence query cursor boundary is invalid")
    body = canonical_json_bytes(
        {
            "schema": CURSOR_SCHEMA,
            "bundle_sha256": bundle_sha256,
            "query_sha256": query_sha256,
            "snapshot_max_id": str(highwater),
            "before_timestamp_ns": str(timestamp),
            "before_event_id": str(event_id),
        }
    )
    return base64.urlsafe_b64encode(body).decode("ascii")


def decode_cursor(
    cursor: str,
    *,
    bundle_sha256: str,
    query_sha256: str,
) -> tuple[int, int, int]:
    try:
        if not isinstance(cursor, str) or not 1 <= len(cursor) <= MAX_CURSOR_BYTES:
            raise ValueError
        body = base64.b64decode(cursor.encode("ascii"), altchars=b"-_", validate=True)
        document = decode_strict_json_bytes(body, label="evidence query cursor")
        if not isinstance(document, dict) or set(document) != {
            "schema",
            "bundle_sha256",
            "query_sha256",
            "snapshot_max_id",
            "before_timestamp_ns",
            "before_event_id",
        }:
            raise ValueError
        if (
            document["schema"] != CURSOR_SCHEMA
            or document["bundle_sha256"] != bundle_sha256
            or document["query_sha256"] != query_sha256
        ):
            raise ValueError
        highwater, timestamp, event_id = (
            int(_exact_decimal(document[key], label="evidence query cursor boundary"))
            for key in ("snapshot_max_id", "before_timestamp_ns", "before_event_id")
        )
        if event_id > highwater:
            raise ValueError
        return highwater, timestamp, event_id
    except (ValueError, TypeError, UnicodeError, ContractError):
        raise ContractError(
            "evidence query cursor is invalid or belongs to different evidence"
        ) from None


def _highwater(decoder) -> int:
    try:
        body = decoder.query(
            "SELECT COALESCE(MAX(id), 0) AS highwater FROM __intrinsic_slice",
            max_rows=1,
        )
        return decode_highwater(body)
    except (ValueError, TypeError, UnicodeError, ContractError):
        raise ContractError("evidence query high-water result is invalid") from None


def _validate_native_page(rows: list[dict], highwater: int, before: tuple[int, int] | None) -> None:
    if any(
        (earlier["ts"], earlier["id"]) <= (later["ts"], later["id"])
        for earlier, later in zip(rows, rows[1:])
    ):
        raise ContractError("native query rows are out of order")
    if any(
        row["id"] > highwater
        or (before is not None and (row["ts"], row["id"]) >= before)
        for row in rows
    ):
        raise ContractError("native query rows exceed their page boundary")


def _binding_realm(event: dict) -> dict:
    context = event.get("native_context")
    if context is None:
        return {
            "status": "not-recorded",
            "kind": event["context_kind"],
            "reason": "native-context-metadata-not-recorded",
        }
    if context["schema"] == "browser-core.inspection-context/2":
        return {
            "status": "native-limited",
            "kind": context["context_kind"],
            "v8_context_id": context["v8_context_id"].upper(),
            "reason": context["unavailable"],
        }
    return {
        "status": "native-observed",
        "kind": context["kind"],
        "v8_context_id": context["v8_context_id"].upper(),
        "document_id": context["document_id"].upper() if context["document_id"] else None,
        "frame_id": context["frame_id"].upper() if context["frame_id"] else None,
        "parent_frame_id": context["parent_frame_id"].upper() if context["parent_frame_id"] else None,
        "worker_id": context["worker_id"].upper() if context["worker_id"] else None,
        "parent_context_id": context["parent_context_id"].upper() if context["parent_context_id"] else None,
        "document": context["document_url"],
    }


def _project_event(event: dict, *, include_values: bool) -> dict:
    result = {
        "event_id": str(event["id"]),
        "timestamp_ns": str(event["ts"]),
        "process_id": str(event["pid"]),
        "thread_id": str(event["tid"]),
        "api": event["api"],
        "context": {
            "id": event["context_id"].upper(),
            "kind": event["context_kind"],
            "realm_id": str(event["realm_id"]),
        },
        "script_id": str(event["script_id"]),
        "completion": event["completion"],
        "binding_realm": _binding_realm(event),
    }
    if "js_stack" in event:
        result["js_stack"] = event["js_stack"]
    if include_values:
        result["parameters"] = event["parameters"]
        result["result"] = event["result"]
    return result


def _rendered_size(value: object) -> int:
    try:
        return len(_rendered_ascii(value))
    except (OverflowError, RecursionError, TypeError, ValueError):
        raise ContractError("evidence query output is invalid") from None


def _rendered_ascii(value: object) -> bytes:
    return json.dumps(value,indent=2,sort_keys=True,ensure_ascii=True,
                      allow_nan=False).encode('ascii')


def _cli_rendered_size(value: object) -> int:
    """Bound actual CLI bytes including a final LF and Windows CRLF expansion."""
    try:
        body=_rendered_ascii(value)
    except (OverflowError, RecursionError, TypeError, ValueError):
        raise ContractError('evidence query output is invalid') from None
    return len(body)+body.count(b'\n')+2


def _bounded_events(base: dict, events: list[dict], *, more_after_query: bool) -> dict:
    def candidate(count: int) -> dict:
        selected = events[:count]
        more = more_after_query or count < len(events)
        next_cursor = None
        if more and selected:
            last = selected[-1]
            next_cursor = encode_cursor(
                base["bundle"]["sha256"],
                base["query"]["query_sha256"],
                int(base["query"]["snapshot_max_id"]),
                int(last["timestamp_ns"]),
                int(last["event_id"]),
            )
        output = dict(base)
        output["events"] = selected
        output["query"] = {
            **base["query"],
            "returned_events": count,
            "more_available": more,
            "next_cursor": next_cursor,
            "output_limited": count < len(events),
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
        raise ContractError("one evidence query event exceeds the output limit")
    return candidate(low)


def evidence_query(
    path: Path,
    root: Path,
    reader: Path,
    *,
    expected_sha256: str | None = None,
    apis: list[str] | tuple[str, ...] = (),
    script_id: str = "",
    context_kind: str = "",
    scope: dict | None = None,
    start_ns: str = "",
    end_ns: str = "",
    cursor: str | None = None,
    limit: int = 50,
    include_values: bool = False,
    analyst_activity: list[str] | tuple[str, ...] = (),
    metadata_version: int = 1,
    portable_context: dict | None = None,
) -> dict:
    """Return one exact, bundle-bound page without opening a local web server."""
    from .metadata_query import metadata_options, portable_context_selector
    _, activities = metadata_options(metadata_version, analyst_activity)
    portable_context = portable_context_selector(portable_context)
    if type(limit) is not int or not 1 <= limit <= MAX_EVENTS:
        raise ContractError("evidence query limit must be from 1 to 100")
    if type(include_values) is not bool:
        raise ContractError("evidence query value selection is invalid")
    filters = history_filters(
        script=script_id,
        context=context_kind,
        scope=scope,
        start_ns=start_ns,
        end_ns=end_ns,
        apis=apis,
    )
    query_sha256 = _query_contract(filters, limit, include_values)
    bundle = OpenEvidence(path, root, reader, expected_sha256=expected_sha256)
    inspector = None
    try:
        capture = bundle.metadata["capture"]
        from .inspection_contract import CAPTURE_OFF
        if capture == CAPTURE_OFF:
            from .metadata_query import _metadata_query
            return _metadata_query(bundle.source, filters=filters, limit=limit,
                include_values=include_values, cursor=cursor, bundle_sha256=bundle.sha256,
                expected_digest_matched=expected_sha256 is not None, analyst_activity=activities,
                metadata_version=metadata_version, portable_context=portable_context,
                _source_recording=bundle.metadata.get("recording"))
        if portable_context is not None:
            raise ContractError('portable context selector requires metadata-only queries')
        if metadata_version != 1 or activities:
            raise ContractError('metadata version 2 requires metadata-only queries')
        if any(api not in capture_apis(capture) for api in filters.get("apis", ())):
            raise ContractError("evidence query API is outside the recording contract")
        inspector = IncrementalInspection(bundle.path, root, bundle.source)
        inspector.health = bundle.metadata["health"]
        initial = inspector.read(limit=1)
        inspector.decoder.timeout = 30
        highwater = _highwater(inspector.decoder)
        before = None
        if cursor is not None:
            cursor_highwater, timestamp, event_id = decode_cursor(
                cursor,
                bundle_sha256=bundle.sha256,
                query_sha256=query_sha256,
            )
            if cursor_highwater != highwater:
                raise ContractError("evidence query cursor snapshot is no longer current")
            before = (timestamp, event_id)
        inspector.decoder.timeout = 30
        body = inspector.decoder.query(
            history_sql(filters, highwater, before=before, limit=limit),
            max_rows=limit + 1,
        )
        rows, total = decode_rows(body, limit=limit + 1, capture=capture)
        _validate_native_page(rows, highwater, before)
        if before is not None and not rows:
            # The native count is projected onto each selected row. An empty
            # continuation carries no count, so reporting zero would turn an
            # exhausted caller-supplied cursor into a false population claim.
            raise ContractError("evidence query cursor has no remaining rows")
        if before is None and len(rows) <= limit and total != len(rows):
            raise ContractError("evidence query count disagrees with its short first page")
        if before is not None and total <= len(rows):
            raise ContractError("evidence query count disagrees with its page cursor")
        more_after_query = len(rows) > limit
        projected = [
            _project_event(event, include_values=include_values)
            for event in rows[:limit]
        ]
        location = bundle.source.resolve()
        recording = bundle.metadata["recording"]
        base = {
            "schema": SCHEMA,
            "status": "ok",
            "bundle": {
                "sha256": bundle.sha256,
                "expected_digest_matched": expected_sha256 is not None,
                "authenticity": "unsigned-exporter-metadata",
            },
            "recording": {
                key: str(recording[key]) if type(recording[key]) is int else recording[key]
                for key in (
                    "sha256",
                    "bytes",
                    "packets",
                    "source_bytes",
                    "excluded_tail_bytes",
                    "source_phase",
                )
            },
            "reader_runtime": location.reader_runtime,
            "capture": dict(capture),
            "query": {
                "filters": filters,
                "query_sha256": query_sha256,
                "requested_limit": limit,
                "matching_events": str(total),
                "snapshot_max_id": str(highwater),
                "ordering": "timestamp-descending-then-event-id-descending",
                "page": "continuation" if cursor is not None else "first",
            },
            "recording_health": _health_summary(initial.get("recording_health")),
            "exporter_reported_health": _health_summary(bundle.metadata["health"]),
            "semantics": {
                "private_values_included": include_values,
                "api_filter": "exact-native-name",
                "pagination_snapshot": "verified-immutable-bundle",
                "cursor_authenticated": False,
                "cursor_authorizes_actions": False,
                "event_ids_are_decoder_local": True,
                "binding_realm_is_initiating_caller": False,
                "script_source_recorded": False,
                "document_url_is_fetch_provenance": False,
                "proves_capture_complete": False,
                "server_side_architecture_observed": False,
                "browser_launched": False,
                "active_probe": False,
            },
        }
        result = _bounded_events(base, projected, more_after_query=more_after_query)
        # Page sizing can render several large candidates after the decoder's
        # last copy check. Bind the published page to the same verified copy.
        bundle.source.resolve()
        return result
    finally:
        try:
            if inspector is not None:
                inspector.close()
        finally:
            bundle.close()
