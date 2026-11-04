"""Match an exact local V8 compiler-input string to a validated portable trace.

The candidate and its unsalted digest remain in process memory. This command
prints only event identities and explicit observation limits.
"""

from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
import re
from pathlib import Path
from typing import Any

from .contracts import ContractError, MAX_SAFE_INTEGER
from .control_files import read_bounded_control_snapshot_result
from .perfetto import bind_perfetto_source_trace
from .trace import scan_validated_trace


SCHEMA = "browser-core.source-match/1"
MAX_CANDIDATE_BYTES = 4 * 1024 * 1024
MAX_COMPILER_INPUT_UNITS = 262_144
MAX_MATCH_ROWS = 32
MAX_LINKED_API_GROUPS = 16
MAX_LINKED_API_DISTINCT = 8192
_HEX_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_API_NAME = re.compile(r"[A-Za-z][A-Za-z0-9_.:-]{0,127}\Z")
_DYNAMIC_EVENT = {"category": "execution", "name": "dynamic.code.materialized"}


def _wire_integer(value: int) -> int:
    if type(value) is not int or not 0 <= value <= MAX_SAFE_INTEGER:
        raise ContractError("source match output integer exceeds limit")
    return value


def _candidate_input(
    path: Path, *, raw_source: bool
) -> tuple[str, int, bytes, tuple[int, int, int, int, int, int]]:
    snapshot = read_bounded_control_snapshot_result(
        path, maximum=MAX_CANDIDATE_BYTES,
        label="compiler-input candidate", require_single_link=True)
    if snapshot.state != "complete" or snapshot.body is None or snapshot.identity is None:
        raise ContractError("compiler-input candidate is unavailable")
    try:
        value = snapshot.body.decode("utf-8", errors="strict")
        if not raw_source:
            value = json.loads(value)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError,
            ValueError, OverflowError):
        requirement = "UTF-8 source" if raw_source else "one UTF-8 JSON string"
        raise ContractError(f"compiler-input candidate must be {requirement}") from None
    if not isinstance(value, str):
        raise ContractError("compiler-input candidate must be one UTF-8 JSON string")
    # surrogatepass preserves JSON-escaped lone surrogates. Supplementary code
    # points encode to the same two UTF-16 code units V8 hashes.
    units = len(value.encode("utf-16le", errors="surrogatepass")) // 2
    return value, units, snapshot.body, snapshot.identity


def source_match(
    trace: Path,
    candidate_json: Path | None = None,
    *,
    candidate_file: Path | None = None,
    expected_trace_sha256: str | None = None,
) -> dict[str, Any]:
    """Return bounded exact matches; nonmatches are observation limits only."""
    if (candidate_json is None) == (candidate_file is None):
        raise ContractError("supply exactly one compiler-input candidate")
    if expected_trace_sha256 is not None and (
        not isinstance(expected_trace_sha256, str)
        or _HEX_SHA256.fullmatch(expected_trace_sha256) is None
    ):
        raise ContractError("expected trace SHA-256 is invalid")
    candidate_path = candidate_file if candidate_file is not None else candidate_json
    assert candidate_path is not None
    candidate, units, candidate_body, candidate_identity = _candidate_input(
        candidate_path, raw_source=candidate_file is not None)
    candidate_digest = (hashlib.sha256(candidate.encode("utf-16le", errors="surrogatepass"))
                        .hexdigest() if units <= MAX_COMPILER_INPUT_UNITS else None)
    binding_before = bind_perfetto_source_trace(trace)
    if (expected_trace_sha256 is not None
            and binding_before["sha256"] != expected_trace_sha256):
        raise ContractError("normalized trace does not match the trusted digest")

    counts = {"dynamic_events": 0, "observed_digests": 0,
              "over_limit": 0, "unavailable": 0, "legacy_without_digest": 0,
              "matches": 0}
    rows: list[dict[str, Any]] = []
    rows_by_seq: dict[int, dict[str, Any]] = {}
    linked_apis: Counter[str] = Counter()
    linked_api_groups_exceeded = False

    def consume(event: dict[str, Any]) -> None:
        nonlocal linked_api_groups_exceeded
        parent = event.get("dynamic_code_parent_seq")
        if parent in rows_by_seq and event["event"]["category"] == "api":
            name = event["event"]["name"]
            group = name if _API_NAME.fullmatch(name) else "<other-api>"
            if group not in linked_apis and len(linked_apis) >= MAX_LINKED_API_DISTINCT:
                linked_api_groups_exceeded = True
            else:
                rows_by_seq[parent]["linked_api_event_count"] += 1
                linked_apis[group] += 1
        if event["event"] != _DYNAMIC_EVENT:
            return
        counts["dynamic_events"] += 1
        detail = event["detail"]
        status = detail.get("compiler_input_hash_status")
        if status is None:
            counts["legacy_without_digest"] += 1
        elif status == "observed":
            counts["observed_digests"] += 1
        elif status == "over-limit":
            counts["over_limit"] += 1
        elif status == "unavailable":
            counts["unavailable"] += 1
        if candidate_digest is None or detail.get("compiler_input_utf16le_sha256") != candidate_digest:
            return
        if detail["source_length"] != units or status != "observed":
            raise ContractError("dynamic-code digest metadata is inconsistent")
        counts["matches"] += 1
        if len(rows) < MAX_MATCH_ROWS:
            row = {
                "seq": _wire_integer(event["seq"]),
                "timestamp_ns": _wire_integer(event["ts_monotonic_ns"]),
                "pid": _wire_integer(event["process"]["pid"]),
                "dynamic_kind": detail["dynamic_kind"],
                "cache_status": detail["cache_status"],
                "generated_script_id": detail.get("generated_script_id"),
                "caller_script_id": (detail["caller_script_id"]
                                     if detail["caller_script_id"] >= 0 else None),
                "caller_status": detail.get("caller_status"),
                "caller_parent_status": detail.get("caller_parent_status"),
                "linked_api_event_count": 0,
            }
            rows.append(row)
            rows_by_seq[event["seq"]] = row

    scan_digest = hashlib.sha256()
    validation = scan_validated_trace(trace, consume, hash_update=scan_digest.update)
    if scan_digest.hexdigest() != binding_before["sha256"]:
        raise ContractError("trace scan disagrees with trusted digest")
    binding_after = bind_perfetto_source_trace(trace)
    if binding_before != binding_after:
        raise ContractError("normalized trace changed during source match")
    candidate_after = read_bounded_control_snapshot_result(
        candidate_path, maximum=MAX_CANDIDATE_BYTES,
        label="compiler-input candidate", require_single_link=True)
    if (candidate_after.state != "complete" or candidate_after.body != candidate_body
            or candidate_after.identity != candidate_identity):
        raise ContractError("compiler-input candidate changed during source match")
    # Candidate revalidation can outlast the earlier trace binding.
    if bind_perfetto_source_trace(trace) != binding_after:
        raise ContractError("normalized trace changed during source match")
    if validation["dropped_events"]:
        # A missing materialization may supersede the observed parent for a
        # reused generated ScriptId. Keep the exact digest match, but do not
        # attribute API children through an incomplete parent sequence.
        for row in rows:
            row["linked_api_event_count"] = 0
        linked_apis.clear()
    elif linked_api_groups_exceeded:
        raise ContractError("linked API groups exceed limit")
    if units > MAX_COMPILER_INPUT_UNITS:
        status = "candidate-over-limit"
    elif counts["matches"]:
        status = "matched"
    elif counts["observed_digests"] and (
        counts["legacy_without_digest"] or counts["unavailable"]
        or validation["dropped_events"]
    ):
        status = "digest-coverage-limited"
    elif counts["observed_digests"]:
        status = "not-observed"
    else:
        status = "digest-unavailable"
    return {
        "schema": SCHEMA,
        "status": status,
        "run_id": validation["run_id"],
        "trace_sha256": binding_after["sha256"],
        "trusted_digest_matched": expected_trace_sha256 is not None,
        "trace_events": validation["events"],
        "dropped_events": validation["dropped_events"],
        "candidate_utf16_code_units": units,
        "compiler_input_limit_units": MAX_COMPILER_INPUT_UNITS,
        "counts": counts,
        "matches": rows,
        "matches_truncated": counts["matches"] > len(rows),
        "linked_api_events_reported_matches": sum(linked_apis.values()),
        "linked_api_groups_total": len(linked_apis),
        "linked_api_groups": [
            {"api": name, "count": count}
            for name, count in sorted(linked_apis.items(), key=lambda item: (-item[1], item[0]))[
                :MAX_LINKED_API_GROUPS]
        ],
        "linked_api_groups_truncated": len(linked_apis) > MAX_LINKED_API_GROUPS,
        "linked_api_scope": "first-32-reported-matches-only",
        "limits": [
            "A match means identical SHA-256 under the pinned UTF-16LE compiler-input algorithm; it does not identify a network response, source URL, or original authoring file.",
            "A nonmatch does not prove that the candidate was never compiled; recording scope, drops, and digest availability may limit observation.",
            "This trace has no recording-phase proof; inspect its session or evidence receipt before making completeness claims.",
            "Linked API totals use validated dynamic_code_parent_seq edges for the reported matches and are suppressed when the trace records drops; they do not prove page ownership or a generated source's final result.",
        ],
    }


def add_source_match_command(trace_sub: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    parser = trace_sub.add_parser(
        "source-match", help="compare one exact local compiler-input string with a validated trace")
    parser.add_argument("--trace", type=Path, required=True)
    candidate = parser.add_mutually_exclusive_group(required=True)
    candidate.add_argument("--candidate-json", type=Path,
                           help="local UTF-8 file containing one JSON string; source stays local")
    candidate.add_argument("--candidate-file", type=Path,
                           help="exact UTF-8 source file; bytes and line endings are not normalized")
    parser.add_argument("--expected-trace-sha256",
                        help="trusted digest from the trace export or collection receipt")

    def run(args: argparse.Namespace) -> int:
        try:
            result = source_match(args.trace, args.candidate_json,
                                  candidate_file=args.candidate_file,
                                  expected_trace_sha256=args.expected_trace_sha256)
        except (ContractError, OSError):
            print(json.dumps({"schema": SCHEMA, "status": "error",
                              "code": "source-match-unavailable"}, sort_keys=True))
            return 2
        print(json.dumps(result, sort_keys=True))
        return 0

    parser.set_defaults(func=run)
