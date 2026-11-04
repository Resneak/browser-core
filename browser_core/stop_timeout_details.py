"""Bounded, saved-recording stop-acknowledgement diagnostics for agents.

The native producer publishes at most 32 indexed rows for the most recent
stop timeout. These run-local labels explain *which* acknowledgement was still
pending, not why it was late or whether the recording is complete.
"""

from __future__ import annotations

import csv
import io
import json
import re
from pathlib import Path

from .bounded_process import run_with_bounded_stdout
from .contracts import ContractError
from .evidence_bundle import OpenEvidence


SCHEMA = "browser-core.evidence-stop-timeouts/1"
MAX_DETAILS = 32
MAX_STATS_ROWS = 4 + 5 * MAX_DETAILS
MAX_QUERY_BYTES = 32 * 1024
MAX_RESULT_BYTES = 16 * 1024

_COUNT = "traced_data_source_stop_timeouts"
_PENDING_INSTANCES = "traced_data_source_stop_timeout_pending_instances"
_PENDING_PRODUCERS = "traced_data_source_stop_timeout_pending_producers"
_TRUNCATED = "traced_data_source_stop_timeout_details_truncated"
_INDEXED = {
    "traced_data_source_stop_timeout_producer_id": "producer_id",
    "traced_data_source_stop_timeout_instance_id": "instance_id",
    "traced_data_source_stop_timeout_producer_name_hash": "producer_name_fnv1a_63",
    "traced_data_source_stop_timeout_data_source_name_hash": "data_source_name_fnv1a_63",
    "traced_data_source_stop_timeout_state": "state",
}
_AGGREGATE = frozenset((_COUNT, _PENDING_INSTANCES, _PENDING_PRODUCERS, _TRUNCATED))
_STATES = ("configured", "starting", "started", "stopping")
_NATURAL = re.compile(r"0|[1-9][0-9]{0,18}\Z")

# A fixed exact-name selection avoids SQL LIKE's '_' wildcard and rejects any
# future stat rather than silently interpreting it as a current field.
_NAMES = sorted(_AGGREGATE | _INDEXED.keys())
STOP_TIMEOUT_SQL = (
    "SELECT name, idx, value FROM stats WHERE name IN ("
    + ",".join("'" + name + "'" for name in _NAMES)
    + ") ORDER BY name, idx LIMIT " + str(MAX_STATS_ROWS + 1) + ";"
)


def _number(raw: str) -> int:
    if not isinstance(raw, str) or _NATURAL.fullmatch(raw) is None:
        raise ContractError("stop-timeout statistics are malformed")
    number = int(raw)
    if number > 2**63 - 1:
        raise ContractError("stop-timeout statistics are malformed")
    return number


def decode_stop_timeout_stats(body: bytes) -> dict:
    """Decode the complete bounded selected stats population, fail closed."""
    try:
        table = csv.DictReader(io.StringIO(body.decode("utf-8")), strict=True)
        if table.fieldnames != ["name", "idx", "value"]:
            raise ValueError()
        aggregate: dict[str, int] = {}
        indexed: dict[int, dict[str, int]] = {}
        seen: set[tuple[str, str]] = set()
        row_count = 0
        for row in table:
            row_count += 1
            if row_count > MAX_STATS_ROWS or set(row) != {"name", "idx", "value"}:
                raise ValueError()
            name, index_raw, value_raw = row["name"], row["idx"], row["value"]
            if name not in _AGGREGATE and name not in _INDEXED:
                raise ValueError()
            if (name, index_raw) in seen:
                raise ValueError()
            seen.add((name, index_raw))
            value = _number(value_raw)
            if name in _AGGREGATE:
                if index_raw != "[NULL]":
                    raise ValueError()
                aggregate[name] = value
            else:
                index = _number(index_raw)
                if index >= MAX_DETAILS:
                    raise ValueError()
                indexed.setdefault(index, {})[_INDEXED[name]] = value

        timeout_count = aggregate.get(_COUNT)
        pending_instances = aggregate.get(_PENDING_INSTANCES)
        pending_producers = aggregate.get(_PENDING_PRODUCERS)
        truncated = aggregate.get(_TRUNCATED)
        if truncated not in (None, 0, 1):
            raise ValueError()
        if (pending_instances is None) != (pending_producers is None) or (
            (pending_instances is None) != (truncated is None)
        ):
            raise ValueError()
        if indexed and (timeout_count is None or timeout_count == 0):
            raise ValueError()
        if sorted(indexed) != list(range(len(indexed))):
            raise ValueError()
        instance_ids: set[int] = set()
        producer_labels: dict[int, int] = {}
        for detail in indexed.values():
            if set(detail) != set(_INDEXED.values()):
                raise ValueError()
            if not 1 <= detail["producer_id"] <= 65535 or detail["instance_id"] == 0:
                raise ValueError()
            if detail["state"] >= len(_STATES):
                raise ValueError()
            if detail["instance_id"] in instance_ids:
                raise ValueError()
            instance_ids.add(detail["instance_id"])
            producer = detail["producer_id"]
            label = detail["producer_name_fnv1a_63"]
            if producer in producer_labels and producer_labels[producer] != label:
                raise ValueError()
            producer_labels[producer] = label

        details_status = "unknown"
        if timeout_count == 0:
            if indexed or (pending_instances not in (None, 0)) or (
                pending_producers not in (None, 0)
            ) or truncated not in (None, 0):
                raise ValueError()
            # The pinned trace processor synthesizes zero scalar stats even
            # when no TraceStats packet/field exists. A zero is not presence.
            timeout_count = pending_instances = pending_producers = truncated = None
        elif timeout_count is not None:
            if pending_instances is None:
                if indexed:
                    raise ValueError()
                details_status = "unavailable"
            elif (pending_instances, pending_producers, truncated) == (0, 0, 0) and not indexed:
                # The importer also supplies default zeros for older positive
                # count-only TraceStats. Do not call these measured detail totals.
                pending_instances = pending_producers = truncated = None
                details_status = "unavailable"
            else:
                if pending_instances == 0 or pending_producers == 0 or (
                    pending_producers > pending_instances or pending_producers > 65535
                ):
                    raise ValueError()
                if truncated:
                    if len(indexed) != MAX_DETAILS or pending_instances <= MAX_DETAILS:
                        raise ValueError()
                    details_status = "truncated-last-timeout"
                else:
                    if len(indexed) != pending_instances:
                        raise ValueError()
                    details_status = "complete-last-timeout"
                listed_producers = len({d["producer_id"] for d in indexed.values()})
                if listed_producers > pending_producers or (
                    not truncated and listed_producers != pending_producers
                ) or (
                    truncated and pending_producers > (
                        listed_producers + pending_instances - len(indexed)
                    )
                ):
                    raise ValueError()
        elif indexed or pending_instances is not None:
            raise ValueError()

        details = []
        for index in sorted(indexed):
            detail = indexed[index]
            details.append({
                "index": index,
                "producer_id": str(detail["producer_id"]),
                "instance_id": str(detail["instance_id"]),
                "state": _STATES[detail["state"]],
                "producer_name_fnv1a_63": str(detail["producer_name_fnv1a_63"]),
                "data_source_name_fnv1a_63": str(detail["data_source_name_fnv1a_63"]),
            })
        return {
            "details_status": details_status,
            "recorded_stop_timeouts": None if timeout_count is None else str(timeout_count),
            "last_timeout_pending_instances": None if pending_instances is None else str(pending_instances),
            "last_timeout_pending_producers": None if pending_producers is None else str(pending_producers),
            "last_timeout_details_truncated": None if truncated is None else bool(truncated),
            "details": details,
        }
    except (ValueError, TypeError, OverflowError, UnicodeError, csv.Error, KeyError):
        raise ContractError("stop-timeout statistics are malformed") from None


def evidence_stop_timeouts(
    bundle_path: Path,
    root: Path,
    reader_executable: Path,
    *,
    expected_sha256: str | None = None,
) -> dict:
    """Read one verified saved bundle; no browser or live session is opened."""
    bundle = OpenEvidence(bundle_path, root, reader_executable,
                          expected_sha256=expected_sha256)
    try:
        location = bundle.source.resolve()
        processor = location.executable.with_name("trace_processor_shell.exe")
        query = run_with_bounded_stdout(
            [str(processor), "query", str(bundle.path), STOP_TIMEOUT_SQL],
            maximum_stdout=MAX_QUERY_BYTES,
            timeout_seconds=30,
            label="saved stop-timeout diagnostics",
        )
        if query.returncode:
            raise ContractError("stop-timeout decoder failed")
        result = decode_stop_timeout_stats(query.stdout)
        bundle.source.resolve()
        response = {
            "schema": SCHEMA,
            "status": "ok",
            "source": {
                "bundle_sha256": bundle.sha256,
                "recording_sha256": bundle.metadata["recording"]["sha256"],
                "expected_digest_matched": expected_sha256 is not None,
            },
            **result,
            "semantics": {
                "detail_scope": "last-reported-timeout-only",
                "producer_and_instance_ids": "run-local",
                "name_labels": "noncryptographic-fnv1a-63-not-authentication-or-confidentiality",
                "cause_identified": False,
                "recording_health_qualified": False,
                "proves_capture_complete": False,
                "browser_launched": False,
                "private_values_included": False,
                "outer_delivery_verified": False,
            },
        }
        rendered = json.dumps(response, indent=2, sort_keys=True, ensure_ascii=True)
        if len(rendered.encode("ascii")) + rendered.count("\n") + 2 > MAX_RESULT_BYTES:
            raise ContractError("stop-timeout response exceeds byte limit")
        return response
    finally:
        bundle.close()
