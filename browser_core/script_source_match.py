"""Match exact local source to opt-in ScriptId evidence in a validated trace."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

from .contracts import ContractError
from .control_files import read_bounded_control_snapshot_result
from .perfetto import bind_perfetto_source_trace
from .source_match import (
    MAX_CANDIDATE_BYTES,
    MAX_COMPILER_INPUT_UNITS,
    _HEX_SHA256,
    _candidate_input,
    _wire_integer,
)
from .trace import scan_validated_trace


SCHEMA = "browser-core.script-source-match/2"
MAX_MATCH_ROWS = 32
MAX_COMPATIBLE_RUNS = 16
_SOURCE_EVENT = {"category": "execution", "name": "script.source.identity"}
_RUN_EVENT = {"category": "execution", "name": "script.run"}


def script_source_match(
    trace: Path,
    candidate_json: Path | None = None,
    *,
    candidate_file: Path | None = None,
    expected_trace_sha256: str | None = None,
) -> dict[str, Any]:
    """Return bounded ScriptId evidence without inferring a source URL or realm."""
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
    candidate_digest = (hashlib.sha256(candidate.encode("utf-16le", "surrogatepass"))
                        .hexdigest() if units <= MAX_COMPILER_INPUT_UNITS else None)
    binding_before = bind_perfetto_source_trace(trace)
    if (expected_trace_sha256 is not None
            and binding_before["sha256"] != expected_trace_sha256):
        raise ContractError("normalized trace does not match the trusted digest")

    counts = {"identity_events": 0, "observed_digests": 0,
              "over_limit": 0, "unavailable": 0, "matches": 0}
    rows: list[dict[str, Any]] = []

    def consume_identity(event: dict[str, Any]) -> None:
        if event["event"] != _SOURCE_EVENT:
            return
        counts["identity_events"] += 1
        detail = event["detail"]
        status = detail["compiler_input_hash_status"]
        if status == "observed":
            counts["observed_digests"] += 1
        elif status == "over-limit":
            counts["over_limit"] += 1
        else:
            counts["unavailable"] += 1
        if candidate_digest is None or detail["compiler_input_utf16le_sha256"] != candidate_digest:
            return
        if status != "observed" or detail["source_length"] != units:
            raise ContractError("script source digest metadata is inconsistent")
        counts["matches"] += 1
        if len(rows) < MAX_MATCH_ROWS:
            rows.append({
                "seq": _wire_integer(event["seq"]),
                "timestamp_ns": _wire_integer(event["ts_monotonic_ns"]),
                "pid": _wire_integer(event["process"]["pid"]),
                "thread_id": _wire_integer(detail["thread_id"]),
                "script_id": detail["script_id"],
                "source_length": detail["source_length"],
                "compatible_run_count": 0,
                "compatible_run_seqs": [],
                "compatible_runs_truncated": False,
                "run_link_status": "no-compatible-run-observed",
            })

    first_digest = hashlib.sha256()
    first = scan_validated_trace(trace, consume_identity, hash_update=first_digest.update)
    if first_digest.hexdigest() != binding_before["sha256"]:
        raise ContractError("trace scan disagrees with trusted digest")
    if rows:
        by_key: dict[tuple[int, int, int], list[dict[str, Any]]] = {}
        for row in rows:
            by_key.setdefault((row["pid"], row["thread_id"], row["script_id"]), []).append(row)
        identity_key_counts = {key: 0 for key in by_key}

        def consume_runs(event: dict[str, Any]) -> None:
            if first["dropped_events"]:
                return
            if event["event"] == _SOURCE_EVENT:
                detail = event["detail"]
                key = (event["process"]["pid"], detail["thread_id"],
                       detail["script_id"])
                if key in identity_key_counts:
                    identity_key_counts[key] += 1
                return
            if event["event"] != _RUN_EVENT:
                return
            execution = event["execution"]
            pid = event["process"]["pid"]
            context_id = execution["context_id"]
            prefix = f"v8:{pid}:{context_id}:"
            number = int(execution["script_id"].removeprefix(prefix))
            key = (pid, event["detail"]["thread_id"], number)
            for row in by_key.get(key, ()):
                if (event["seq"] <= row["seq"]
                        or event["ts_monotonic_ns"] <= row["timestamp_ns"]):
                    continue
                row["compatible_run_count"] += 1
                if len(row["compatible_run_seqs"]) < MAX_COMPATIBLE_RUNS:
                    row["compatible_run_seqs"].append(_wire_integer(event["seq"]))
                else:
                    row["compatible_runs_truncated"] = True

        second_digest = hashlib.sha256()
        second = scan_validated_trace(trace, consume_runs, hash_update=second_digest.update)
        if second_digest.hexdigest() != binding_before["sha256"]:
            raise ContractError("trace scan disagrees with trusted digest")
        if first != second:
            raise ContractError("normalized trace changed during ScriptId matching")
        for key, group in by_key.items():
            if first["dropped_events"]:
                for row in group:
                    row["compatible_run_count"] = 0
                    row["compatible_run_seqs"] = []
                    row["compatible_runs_truncated"] = False
                    row["run_link_status"] = "run-evidence-incomplete"
            elif identity_key_counts[key] != 1:
                for row in group:
                    row["compatible_run_count"] = 0
                    row["compatible_run_seqs"] = []
                    row["compatible_runs_truncated"] = False
                    row["run_link_status"] = "ambiguous-script-id"
            else:
                for row in group:
                    if row["compatible_run_count"]:
                        row["run_link_status"] = "compatible-run-observed"
    binding_after = bind_perfetto_source_trace(trace)
    if binding_before != binding_after:
        raise ContractError("normalized trace changed during ScriptId matching")
    candidate_after = read_bounded_control_snapshot_result(
        candidate_path, maximum=MAX_CANDIDATE_BYTES,
        label="compiler-input candidate", require_single_link=True)
    if (candidate_after.state != "complete" or candidate_after.body != candidate_body
            or candidate_after.identity != candidate_identity):
        raise ContractError("compiler-input candidate changed during ScriptId matching")
    # Candidate revalidation can outlast the earlier trace binding.
    if bind_perfetto_source_trace(trace) != binding_after:
        raise ContractError("normalized trace changed during ScriptId matching")
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
        "run_link_scope": "same-process-thread-numeric-script-id-and-later-time-only",
        "limits": [
            "An exact hash match binds the candidate to a V8 compiler input and numeric ScriptId; it does not prove execution, a URL, response, or original file.",
            "Compatible script.run sequences share process, thread, numeric ScriptId and strictly later time; they do not prove one isolate, selected realm, or completed execution.",
            "A nonmatch does not prove that a source never compiled; external-script decoding can strip a response BOM, and recording scope, drops or hash availability can limit observation.",
            "The trace does not prove recording-phase completeness; inspect its session or collection receipt.",
            "Repeated process, thread and numeric ScriptId keys suppress per-source run links because separate contexts can reuse that key. Dropped events also suppress links because an unseen compile event could reuse it.",
        ],
    }


def add_script_source_match_command(
    trace_sub: argparse._SubParsersAction[argparse.ArgumentParser],
) -> None:
    parser = trace_sub.add_parser(
        "script-source-match",
        help="compare exact local source with opt-in V8 ScriptId evidence")
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
            result = script_source_match(
                args.trace, args.candidate_json, candidate_file=args.candidate_file,
                expected_trace_sha256=args.expected_trace_sha256)
        except (ContractError, OSError):
            print(json.dumps({"schema": SCHEMA, "status": "error",
                              "code": "script-source-match-unavailable"}, sort_keys=True))
            return 2
        print(json.dumps(result, sort_keys=True))
        return 0

    parser.set_defaults(func=run)
