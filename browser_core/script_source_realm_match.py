"""Match an exact source to opt-in V8-realm and compatible API evidence."""

from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
from typing import Any

from .contracts import ContractError
from .control_files import read_bounded_control_snapshot_result
from .perfetto import bind_perfetto_source_trace
from .script_source_match import MAX_COMPATIBLE_RUNS, MAX_MATCH_ROWS
from .source_match import (
    MAX_CANDIDATE_BYTES, MAX_COMPILER_INPUT_UNITS, _API_NAME, _HEX_SHA256,
    _candidate_input, _wire_integer,
)
from .trace import scan_validated_trace


SCHEMA = "browser-core.script-source-realm-match/1"
MAX_COMPATIBLE_APIS = 16
MAX_API_GROUPS = 16
MAX_REALM_API_DISTINCT = 8192
_SOURCE_EVENT = {"category": "execution", "name": "script.source.context"}
_RUN_EVENT = {"category": "execution", "name": "script.run"}


def script_source_realm_match(
    trace: Path,
    candidate_json: Path | None = None,
    *,
    candidate_file: Path | None = None,
    expected_trace_sha256: str | None = None,
) -> dict[str, Any]:
    """Return bounded exact compile and same-realm root-script observations."""
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
    candidate_digest = (
        hashlib.sha256(candidate.encode("utf-16le", "surrogatepass")).hexdigest()
        if units <= MAX_COMPILER_INPUT_UNITS else None
    )
    binding_before = bind_perfetto_source_trace(trace)
    if (expected_trace_sha256 is not None
            and binding_before["sha256"] != expected_trace_sha256):
        raise ContractError("normalized trace does not match the trusted digest")
    counts = {"context_events": 0, "observed_digests": 0,
              "over_limit": 0, "unavailable": 0, "matches": 0,
              "matches_with_realm": 0}
    rows: list[dict[str, Any]] = []

    def consume_source(event: dict[str, Any]) -> None:
        if event["event"] != _SOURCE_EVENT:
            return
        counts["context_events"] += 1
        detail = event["detail"]
        hash_status = detail["compiler_input_hash_status"]
        if hash_status == "observed":
            counts["observed_digests"] += 1
        elif hash_status == "over-limit":
            counts["over_limit"] += 1
        else:
            counts["unavailable"] += 1
        if candidate_digest is None or detail["compiler_input_utf16le_sha256"] != candidate_digest:
            return
        if hash_status != "observed" or detail["source_length"] != units:
            raise ContractError("script source realm digest metadata is inconsistent")
        counts["matches"] += 1
        token = detail.get("v8_context_id")
        world = detail.get("realm_id")
        if token is not None:
            counts["matches_with_realm"] += 1
        if len(rows) < MAX_MATCH_ROWS:
            context_id = event["execution"]["context_id"]
            if len(context_id) > 256:
                raise ContractError("source match output context exceeds limit")
            rows.append({
                "seq": _wire_integer(event["seq"]),
                "timestamp_ns": _wire_integer(event["ts_monotonic_ns"]),
                "pid": _wire_integer(event["process"]["pid"]),
                "thread_id": _wire_integer(detail["thread_id"]),
                "context_id": context_id,
                "script_id": detail["script_id"],
                "source_length": detail["source_length"],
                "realm_status": "observed" if token is not None else "unavailable",
                "v8_context_id": token,
                "realm_id": world,
                "compatible_run_count": 0,
                "compatible_run_seqs": [],
                "compatible_runs_truncated": False,
                "run_link_status": "realm-unavailable",
                "compatible_api_count": 0,
                "compatible_api_seqs": [],
                "compatible_apis_truncated": False,
                "compatible_api_groups_total": 0,
                "compatible_api_groups": [],
                "compatible_api_groups_truncated": False,
                "api_link_status": "realm-unavailable",
            })

    first_digest = hashlib.sha256()
    first = scan_validated_trace(trace, consume_source, hash_update=first_digest.update)
    if first_digest.hexdigest() != binding_before["sha256"]:
        raise ContractError("trace scan disagrees with trusted digest")
    if rows:
        by_base: dict[tuple[int, int, str, int], list[dict[str, Any]]] = {}
        by_realm_api: dict[tuple[int, int, str, int, int], list[dict[str, Any]]] = {}
        for row in rows:
            base = (row["pid"], row["thread_id"], row["context_id"], row["script_id"])
            by_base.setdefault(base, []).append(row)
            if row["v8_context_id"] is not None:
                api_key = (row["pid"], row["thread_id"], row["v8_context_id"],
                           row["realm_id"], row["script_id"])
                by_realm_api.setdefault(api_key, []).append(row)
        # Only reported matches can use these counts. A trace may contain
        # millions of other realm tokens under the same frame/script key.
        reported_full_keys = {
            (row["pid"], row["thread_id"], row["context_id"], row["script_id"],
             row["v8_context_id"], row["realm_id"])
            for row in rows if row["v8_context_id"] is not None
        }
        full_counts = dict.fromkeys(reported_full_keys, 0)
        api_key_counts: Counter[tuple[int, int, str, int, int]] = Counter()
        unresolved_bases: set[tuple[int, int, str, int]] = set()
        api_groups: dict[int, Counter[str]] = {row["seq"]: Counter() for row in rows}
        retained_api_groups = 0

        def later(event: dict[str, Any], row: dict[str, Any]) -> bool:
            return (event["seq"] > row["seq"]
                    and event["ts_monotonic_ns"] > row["timestamp_ns"])

        def consume_related(event: dict[str, Any]) -> None:
            nonlocal retained_api_groups
            # Trace gaps suppress every per-source link below. Keep the
            # independent second scan and digest check, but do not accumulate
            # relationships that cannot appear in the returned evidence.
            if first["dropped_events"]:
                return
            pid = event["process"]["pid"]
            if event["event"] == _SOURCE_EVENT:
                detail = event["detail"]
                base = (pid, detail["thread_id"], event["execution"]["context_id"],
                        detail["script_id"])
                if base in by_base:
                    token = detail.get("v8_context_id")
                    if token is None:
                        unresolved_bases.add(base)
                    else:
                        full = (*base, token, detail["realm_id"])
                        if full in full_counts:
                            full_counts[full] += 1
                token = detail.get("v8_context_id")
                if token is not None:
                    api_key = (pid, detail["thread_id"], token,
                               detail["realm_id"], detail["script_id"])
                    if api_key in by_realm_api:
                        api_key_counts[api_key] += 1
                return
            if event["event"] == _RUN_EVENT:
                detail = event["detail"]
                execution = event["execution"]
                context_id = execution["context_id"]
                prefix = f"v8:{pid}:{context_id}:"
                number = int(execution["script_id"].removeprefix(prefix))
                base = (pid, detail["thread_id"], context_id, number)
                for row in by_base.get(base, ()):
                    if (row["v8_context_id"] is None
                            or detail.get("v8_context_id") != row["v8_context_id"]
                            or detail.get("realm_id") != row["realm_id"]
                            or not later(event, row)):
                        continue
                    row["compatible_run_count"] += 1
                    if len(row["compatible_run_seqs"]) < MAX_COMPATIBLE_RUNS:
                        row["compatible_run_seqs"].append(_wire_integer(event["seq"]))
                    else:
                        row["compatible_runs_truncated"] = True
                return
            if (event["event"]["category"] != "api"
                    or event["provenance"].get("component") != "blink.bindings.generated"):
                return
            detail = event["detail"]
            stack = detail.get("js_stack")
            if not isinstance(stack, dict) or stack.get("status") != "observed":
                return
            api_key = (pid, detail["thread_id"], stack["v8_context_id"],
                       stack["realm_id"], stack["root_script_number"])
            for row in by_realm_api.get(api_key, ()):
                if not later(event, row):
                    continue
                row["compatible_api_count"] += 1
                if len(row["compatible_api_seqs"]) < MAX_COMPATIBLE_APIS:
                    row["compatible_api_seqs"].append(_wire_integer(event["seq"]))
                else:
                    row["compatible_apis_truncated"] = True
                name = event["event"]["name"]
                group = name if _API_NAME.fullmatch(name) else "<other-api>"
                retained = api_groups[row["seq"]]
                if group not in retained:
                    if retained_api_groups >= MAX_REALM_API_DISTINCT:
                        raise ContractError("compatible API groups exceed limit")
                    retained_api_groups += 1
                retained[group] += 1

        second_digest = hashlib.sha256()
        second = scan_validated_trace(trace, consume_related, hash_update=second_digest.update)
        if second_digest.hexdigest() != binding_before["sha256"]:
            raise ContractError("trace scan disagrees with trusted digest")
        if first != second:
            raise ContractError("normalized trace changed during realm matching")
        for row in rows:
            if row["v8_context_id"] is None:
                continue
            base = (row["pid"], row["thread_id"], row["context_id"], row["script_id"])
            full = (*base, row["v8_context_id"], row["realm_id"])
            if first["dropped_events"]:
                reason = "evidence-incomplete"
            elif base in unresolved_bases or full_counts[full] != 1:
                reason = "ambiguous-realm-script-id"
            else:
                reason = None
            if reason is not None:
                row["compatible_run_count"] = 0
                row["compatible_run_seqs"] = []
                row["compatible_runs_truncated"] = False
                row["compatible_api_count"] = 0
                row["compatible_api_seqs"] = []
                row["compatible_apis_truncated"] = False
                row["run_link_status"] = reason
                row["api_link_status"] = reason
                continue
            row["run_link_status"] = (
                "compatible-run-observed" if row["compatible_run_count"]
                else "no-compatible-run-observed")
            api_key = (row["pid"], row["thread_id"], row["v8_context_id"],
                       row["realm_id"], row["script_id"])
            if api_key_counts[api_key] != 1:
                row["compatible_api_count"] = 0
                row["compatible_api_seqs"] = []
                row["compatible_apis_truncated"] = False
                row["api_link_status"] = "ambiguous-realm-script-id"
                continue
            row["api_link_status"] = (
                "compatible-api-observed" if row["compatible_api_count"]
                else "no-compatible-api-observed")
            groups = sorted(api_groups[row["seq"]].items(),
                            key=lambda item: (-item[1], item[0]))
            row["compatible_api_groups_total"] = len(groups)
            row["compatible_api_groups"] = [
                {"api": name, "count": count} for name, count in groups[:MAX_API_GROUPS]
            ]
            row["compatible_api_groups_truncated"] = len(groups) > MAX_API_GROUPS
    binding_after = bind_perfetto_source_trace(trace)
    if binding_before != binding_after:
        raise ContractError("normalized trace changed during realm matching")
    candidate_after = read_bounded_control_snapshot_result(
        candidate_path, maximum=MAX_CANDIDATE_BYTES,
        label="compiler-input candidate", require_single_link=True)
    if (candidate_after.state != "complete" or candidate_after.body != candidate_body
            or candidate_after.identity != candidate_identity):
        raise ContractError("compiler-input candidate changed during realm matching")
    if bind_perfetto_source_trace(trace) != binding_after:
        raise ContractError("normalized trace changed during realm matching")
    if units > MAX_COMPILER_INPUT_UNITS:
        status = "candidate-over-limit"
    elif counts["matches"]:
        status = "matched"
    elif counts["observed_digests"] and (
        counts["unavailable"] or first["dropped_events"]
    ):
        status = "digest-coverage-limited"
    elif counts["observed_digests"]:
        status = "not-observed"
    else:
        status = "digest-unavailable"
    return {
        "schema": SCHEMA,
        "status": status,
        "run_id": first["run_id"],
        "trace_sha256": binding_after["sha256"],
        "trusted_digest_matched": expected_trace_sha256 is not None,
        "trace_events": first["events"],
        "dropped_events": first["dropped_events"],
        "candidate_utf16_code_units": units,
        "compiler_input_limit_units": MAX_COMPILER_INPUT_UNITS,
        "counts": counts,
        "matches": rows,
        "matches_truncated": counts["matches"] > len(rows),
        "run_link_scope": "same-process-thread-frame-realm-script-id-and-later-time-only",
        "api_link_scope": "same-process-thread-v8-context-world-root-script-id-and-later-time-only",
        "limits": [
            "Exact digest and length bind a candidate to an observed Blink compilation input, not a URL, response or original file.",
            "V8 context and world tokens distinguish realms within one frame, but this does not establish hidden server behavior.",
            "Compatible run events are evaluation attempts, not proof of completion. A static module dependency may execute without its own ScriptRun event; no-compatible-run-observed does not mean it did not run.",
            "Compatible generated-binding API events share an observed nearest-visible-JavaScript root script and V8 realm; this is not proof that the matched source directly called each API.",
            "Repeated full realm/ScriptId keys, unresolved same-frame source keys or trace drops suppress per-source run and API links; a reused API key across distinct frame sources suppresses API links alone.",
            "Inspector-injected isolated-world scripts can bypass Blink's compile and run events. Recording scope, timing, omitted hashes and drops limit negative claims; inspect collection and export receipts.",
        ],
    }


def add_script_source_realm_match_command(
    trace_sub: argparse._SubParsersAction[argparse.ArgumentParser],
) -> None:
    parser = trace_sub.add_parser(
        "script-source-realm-match",
        help="compare exact source with opt-in realm-bound compile, run and API evidence")
    candidate = parser.add_mutually_exclusive_group(required=True)
    candidate.add_argument("--candidate-json", type=Path,
                           help="one UTF-8 JSON string, including escaped lone surrogates")
    candidate.add_argument("--candidate-file", type=Path,
                           help="exact UTF-8 source file without normalization")
    parser.add_argument("--trace", type=Path, required=True)
    parser.add_argument("--expected-trace-sha256",
                        help="trusted digest from a trace export or collection receipt")

    def run(args: argparse.Namespace) -> int:
        try:
            result = script_source_realm_match(
                args.trace, args.candidate_json, candidate_file=args.candidate_file,
                expected_trace_sha256=args.expected_trace_sha256)
        except (ContractError, OSError):
            print(json.dumps({"schema": SCHEMA, "status": "error",
                              "code": "script-source-realm-match-unavailable"},
                             sort_keys=True))
            return 2
        print(json.dumps(result, sort_keys=True))
        return 0

    parser.set_defaults(func=run)
