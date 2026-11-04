"""Bounded research planning over one verified saved evidence bundle.

The planner turns reader-validated inventory into next evidence questions. It
does not inspect private values, launch a browser, run probes, or infer hidden
server behavior. API absence remains "not observed in this bundle".
"""
from __future__ import annotations

import json
from pathlib import Path
import re
from typing import Any

from .contracts import ContractError
from .evidence_summary import evidence_summary
from .inspection_contract import capture_apis
from .observation_digest import technique_of


SCHEMA = "browser-core.agent-research-plan/1"
MAX_APIS = 256
MAX_TARGETS = 8
MAX_OUTPUT_BYTES = 128 * 1024
MAX_RECORDS = 2**53 - 1
_CAPTURE_SCHEMAS = frozenset(
    {"browser-core.inspection/1", "browser-core.inspection/2", "browser-core.inspection/3"}
)
_ALLOWLISTS = frozenset({"fingerprint-v1", "fingerprint-v2", "research-v3"})
_SOURCE_PHASES = frozenset(
    {"live-prefix", "finalized-recording", "recovered-prefix", "interrupted-recording", "limited-recording"}
)
_HEALTH = frozenset({"issues-reported", "no-issues-reported", "awaiting-capture-stats"})
_SUMMARY_SEMANTICS = {
    "population": "native-binding-value-records",
    "unique_calls": False,
    "api_counts": "matching-envelope-and-compatible-completion",
    "capability_basis": "reader-known-capture-contract",
    "zero_count": "not-observed-in-this-recording",
    "thread_process_link_is_context_attribution": False,
    "private_payloads_validated": False,
    "private_values_included": False,
    "active_probes": False,
    "browser_launched": False,
    "source_snapshot": "fixed-verified-copy",
    "recording_metadata": "unsigned-exporter-claims-except-verified-bytes-and-sha256",
    "attribution_analysis": "not-performed",
    "decoder_read": "end-of-file",
    "live_freshness": "not-applicable",
    "proves_capture_complete": False,
    "proves_server_behavior": False,
}


def _integer(value: Any, *, label: str) -> int:
    if type(value) is not int or not 0 <= value <= MAX_RECORDS:
        raise ContractError(f"agent plan {label} is invalid")
    return value


def _text(value: Any, *, label: str, maximum: int = 256) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > maximum
        or any(ord(character) < 32 for character in value)
    ):
        raise ContractError(f"agent plan {label} is invalid")
    return value


def _choice(value: Any, choices: frozenset[str], *, label: str) -> str:
    value = _text(value, label=label)
    if value not in choices:
        raise ContractError(f"agent plan {label} is invalid")
    return value


def _query_targets(
    observed: list[tuple[str, int, str]],
) -> list[dict[str, Any]]:
    """Choose bounded high-volume targets without losing technique diversity.

    A hot loop can contribute many API names from one family. Taking the first
    eight rows globally would then hide every lower-volume family from the next
    agent step. Choose the highest-population API in each observed technique
    first, ordered globally by population, then use any remaining slots for the
    next highest-population APIs.
    """
    ordered = sorted(observed, key=lambda item: (-item[1], item[0]))
    representatives = []
    represented = set()
    for item in ordered:
        if item[2] not in represented:
            representatives.append(item)
            represented.add(item[2])
    selected = representatives[:MAX_TARGETS]
    if len(selected) < MAX_TARGETS:
        selected_names = {item[0] for item in selected}
        selected.extend(
            item
            for item in ordered
            if item[0] not in selected_names
        )
        selected = selected[:MAX_TARGETS]
    return [
        {
            "api": name,
            "technique": technique,
            "completion_compatible_records": records,
        }
        for name, records, technique in selected
    ]


def plan_evidence_summary(summary: dict[str, Any]) -> dict[str, Any]:
    """Build a deterministic plan from an already verified summary document."""
    if (
        not isinstance(summary, dict)
        or summary.get("schema") != "browser-core.evidence-summary/1"
        or summary.get("status") != "ok"
    ):
        raise ContractError("agent plan evidence summary is invalid")
    bundle = summary.get("bundle")
    capture = summary.get("capture")
    recording = summary.get("recording")
    counts = summary.get("counts")
    health = summary.get("recording_health")
    semantics = summary.get("semantics")
    apis = summary.get("apis")
    if not all(
        isinstance(value, dict)
        for value in (bundle, capture, recording, counts, health, semantics)
    ) or not isinstance(apis, list):
        raise ContractError("agent plan evidence summary is invalid")
    if not 1 <= len(apis) <= MAX_APIS:
        raise ContractError("agent plan API inventory is invalid")
    allowed_apis = capture_apis(capture)
    if not allowed_apis:
        raise ContractError("agent plan capture contract is invalid")

    rows = []
    names = set()
    for item in apis:
        if not isinstance(item, dict):
            raise ContractError("agent plan API inventory is invalid")
        name = _text(item.get("api"), label="API name")
        if (
            re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", name) is None
            or name not in allowed_apis
        ):
            raise ContractError("agent plan API name is invalid")
        records = _integer(item.get("records"), label="API record count")
        if name in names:
            raise ContractError("agent plan API inventory has a duplicate")
        names.add(name)
        taxonomy_name = name if name.startswith("api.") else f"api.{name}"
        rows.append((name, records, technique_of(taxonomy_name)))
    if names != allowed_apis:
        raise ContractError("agent plan API inventory is incomplete")

    techniques: dict[str, dict[str, Any]] = {}
    for name, records, technique in rows:
        row = techniques.setdefault(
            technique,
            {
                "technique": technique,
                "reader_known_apis": 0,
                "observed_apis": 0,
                "not_observed_apis": 0,
                "records": 0,
                "observed_api_names": [],
            },
        )
        row["reader_known_apis"] += 1
        if records:
            row["observed_apis"] += 1
            row["records"] += records
            row["observed_api_names"].append(name)
        else:
            row["not_observed_apis"] += 1
    technique_rows = []
    for name in sorted(techniques):
        row = techniques[name]
        row["observed_api_names"].sort()
        row["status"] = "observed" if row["records"] else "not-observed"
        technique_rows.append(row)

    observed = [(name, records, technique) for name, records, technique in rows if records]
    targets = _query_targets(observed)
    observed_techniques = {technique for _, _, technique in observed}
    targeted_techniques = {target["technique"] for target in targets}
    count_names = (
        "binding_value_records",
        "thread_process_linked_records",
        "thread_process_unlinked_records",
        "capture_envelope_matching_records",
        "capture_envelope_mismatched_records",
        "recognized_api_records",
        "unrecognized_api_records",
        "completion_compatible_records",
        "completion_incompatible_records",
        "queryable_records",
    )
    populations = {
        name: _integer(counts.get(name), label=name.replace("_", " "))
        for name in count_names
    }
    total_records = populations["binding_value_records"]
    completion_compatible_records = populations["completion_compatible_records"]
    queryable_records = populations["queryable_records"]
    if (
        total_records
        != populations["thread_process_linked_records"]
        + populations["thread_process_unlinked_records"]
        or total_records
        != populations["capture_envelope_matching_records"]
        + populations["capture_envelope_mismatched_records"]
        or populations["capture_envelope_matching_records"]
        != populations["recognized_api_records"]
        + populations["unrecognized_api_records"]
        or populations["recognized_api_records"]
        != completion_compatible_records
        + populations["completion_incompatible_records"]
        or sum(records for _, records, _ in rows)
        != completion_compatible_records
        or queryable_records > completion_compatible_records
        or queryable_records > populations["thread_process_linked_records"]
        or queryable_records < max(
            0,
            completion_compatible_records
            + populations["thread_process_linked_records"]
            - total_records,
        )
    ):
        raise ContractError("agent plan API counts do not match the population")
    digest = _text(bundle.get("sha256"), label="bundle digest", maximum=64)
    recording_digest = _text(
        recording.get("sha256"), label="recording digest", maximum=64
    )
    capture_schema = _choice(
        capture.get("schema"), _CAPTURE_SCHEMAS, label="capture schema"
    )
    allowlist = _choice(capture.get("allowlist"), _ALLOWLISTS, label="capture allowlist")
    source_phase = _choice(
        recording.get("source_phase"), _SOURCE_PHASES, label="recording phase"
    )
    health_status = _choice(health.get("status"), _HEALTH, label="health status")
    capture_stats_seen = health.get("capture_stats_seen")
    counters_truncated = health.get("counters_truncated")
    drop_count = _text(
        health.get("sorter_dropped_events"), label="drop counter", maximum=32
    )
    if (
        len(digest) != 64
        or len(recording_digest) != 64
        or any(character not in "0123456789abcdef" for character in digest + recording_digest)
        or bundle.get("expected_digest_matched") is not True
        or bundle.get("authenticity") != "unsigned-exporter-metadata"
        or type(capture_stats_seen) is not bool
        or type(counters_truncated) is not bool
        or health.get("proves_complete") is not False
        or re.fullmatch(r"0|[1-9][0-9]{0,18}", drop_count) is None
    ):
        raise ContractError("agent plan evidence digest is invalid")
    if set(semantics) != set(_SUMMARY_SEMANTICS) or any(
        type(semantics[name]) is not type(expected) or semantics[name] != expected
        for name, expected in _SUMMARY_SEMANTICS.items()
    ):
        raise ContractError("agent plan evidence boundaries are invalid")

    quality_problem = (
        health_status != "no-issues-reported"
        or not capture_stats_seen
        or counters_truncated
        or drop_count != "0"
        or total_records != queryable_records
    )
    query_action = {
        "id": "query-observed-values" if targets else "capture-executed-workload",
        "priority": 2 if quality_problem else 1,
        "interface": "saved-evidence-query" if targets else "research-control",
        "reason": (
            "Inspect high-population calls across observed client technique families with explicit private-value opt-in."
            if targets
            else "No reader-known value call was observed; execute the intended workload before drawing an absence conclusion."
        ),
        "target_apis": [target["api"] for target in targets],
        "include_private_values": bool(targets),
        # Summary rows can include unlinked records, and output byte limits can
        # page even a population below 100. Cursor nullity is the only complete
        # stopping condition for an exact saved-evidence query.
        "page_until_cursor_null": bool(targets),
    }
    actions = []
    if quality_problem:
        actions.append(
            {
                "id": "repair-evidence-quality",
                "priority": 1,
                "interface": "research-control",
                "reason": "Recording health or non-queryable binding rows require a clean matched recapture before strong absence or completeness claims.",
                "target_apis": [],
                "include_private_values": False,
                "page_until_cursor_null": False,
            }
        )
    offset = 1 if quality_problem else 0
    actions.extend([
        query_action,
        {
            "id": "map-versioned-client-artifacts",
            "priority": 2 + offset,
            "interface": "artifact-acquisition-and-hashing",
            "reason": "Pin every delivered script, worker, module, WASM artifact, response dependency, and load edge before treating names or behavior as stable.",
            "target_apis": [],
            "include_private_values": False,
            "page_until_cursor_null": False,
        },
        {
            "id": "correlate-broad-client-events",
            "priority": 3 + offset,
            "interface": "trace-collect-and-scoped-queries",
            "reason": "Value-call evidence alone does not recover listeners, realm transitions, dynamic code, execution order, or renderer-to-network causality.",
            "target_apis": [],
            "include_private_values": False,
            "page_until_cursor_null": False,
        },
        {
            "id": "recover-obfuscated-execution",
            "priority": 4 + offset,
            "interface": "offline-static-and-rehost",
            "reason": "For packed, virtualized, dynamic-code, or WASM paths, recover dispatch, program state, handlers, dependencies, and control flow on the exact pinned artifact.",
            "target_apis": [],
            "include_private_values": False,
            "page_until_cursor_null": False,
        },
        {
            "id": "trace-state-and-request-provenance",
            "priority": 5 + offset,
            "interface": "captured-traffic-analysis",
            "reason": "Trace each dynamic protected-request value backward through responses, cookies or storage, and client computation; an exact-search miss is not absence.",
            "target_apis": [],
            "include_private_values": False,
            "page_until_cursor_null": False,
        },
        {
            "id": "compare-browser-client-wire",
            "priority": 6 + offset,
            "interface": "transport-comparison",
            "reason": "Compare request shape, header and cookie order, connection reuse, HTTP/2, TLS, and negotiated HTTP/3 independently under matched route and state.",
            "target_apis": [],
            "include_private_values": False,
            "page_until_cursor_null": False,
        },
        {
            "id": "measure-authorized-server-outcome",
            "priority": 7 + offset,
            "interface": "external-authorized-experiment",
            "reason": "Only an authorized server-response experiment can test acceptance, enforcement, reuse budget, or hidden server-side decisions.",
            "target_apis": [],
            "include_private_values": False,
            "page_until_cursor_null": False,
        },
    ])
    result = {
        "schema": SCHEMA,
        "status": "ok",
        "basis": {
            "kind": "verified-saved-evidence",
            "bundle_sha256": digest,
            "expected_digest_matched": True,
            "bundle_authenticity": "unsigned-exporter-metadata",
            "capture_schema": capture_schema,
            "allowlist": allowlist,
            "recording_sha256": recording_digest,
            "recording_source_phase": source_phase,
        },
        "inventory": {
            "binding_value_records": total_records,
            "completion_compatible_value_records": completion_compatible_records,
            "queryable_value_records": queryable_records,
            "reader_known_apis": len(rows),
            "observed_apis": len(observed),
            "not_observed_apis": len(rows) - len(observed),
            "query_target_policy": "technique-diverse-then-population",
            "query_target_technique_coverage_complete": (
                targeted_techniques == observed_techniques
            ),
            "untargeted_observed_techniques": sorted(
                observed_techniques - targeted_techniques
            ),
            "query_targets": targets,
            "techniques": technique_rows,
        },
        "evidence_quality": {
            "recording_health": health_status,
            "capture_stats_seen": capture_stats_seen,
            "diagnostic_counters_truncated": counters_truncated,
            "sorter_dropped_events": drop_count,
            "capture_completeness_proved": False,
            "nonqueryable_binding_records": total_records - queryable_records,
            "thread_process_unlinked_records": populations[
                "thread_process_unlinked_records"
            ],
            "capture_envelope_mismatched_records": populations[
                "capture_envelope_mismatched_records"
            ],
            "unrecognized_api_records": populations["unrecognized_api_records"],
            "completion_incompatible_records": populations[
                "completion_incompatible_records"
            ],
        },
        "next_actions": actions,
        "unresolved_dimensions": [
            {
                "dimension": "versioned-client-artifacts",
                "state": "not-established-by-value-bundle",
            },
            {
                "dimension": "whole-client-execution",
                "state": "not-established-by-value-bundle",
            },
            {
                "dimension": "obfuscated-program-semantics",
                "state": "not-established-by-value-bundle",
            },
            {
                "dimension": "state-and-request-provenance",
                "state": "not-established-by-value-bundle",
            },
            {
                "dimension": "renderer-network-causality",
                "state": "not-established-by-value-bundle",
            },
            {
                "dimension": "transport-fingerprint-equivalence",
                "state": "not-observed-by-this-artifact",
            },
            {
                "dimension": "transport-and-server-decision",
                "state": "not-observed-by-this-artifact",
            },
        ],
        "semantics": {
            "input_was_digest_verified": True,
            "private_values_read": False,
            "browser_launched": False,
            "active_probe": False,
            "not_observed_means_unsupported": False,
            "client_side_coverage_complete": False,
            "server_side_architecture_observed": False,
            "research_plan_is_proof": False,
            "external_interfaces_verified": False,
            "producer_build_is_independently_attested": False,
            "target_authorization_verified": False,
        },
    }
    try:
        rendered = json.dumps(
            result, indent=2, sort_keys=True, ensure_ascii=True, allow_nan=False
        )
        # The CLI prints this layout. Count CRLF expansion and the final line.
        size = len(rendered.encode("ascii")) + rendered.count("\n") + 2
    except (OverflowError, TypeError, ValueError):
        raise ContractError("agent plan output is invalid") from None
    if size > MAX_OUTPUT_BYTES:
        raise ContractError("agent plan output exceeds byte limit")
    return result


def plan_saved_evidence(
    path: Path,
    root: Path,
    reader: Path,
    *,
    expected_sha256: str,
) -> dict[str, Any]:
    """Verify a fixed bundle, read only its summary, and produce a plan."""
    if not isinstance(expected_sha256, str) or not expected_sha256:
        raise ContractError("agent plan requires the trusted bundle digest")
    summary = evidence_summary(
        path,
        root,
        reader,
        expected_sha256=expected_sha256,
        include_queryability=True,
    )
    return plan_evidence_summary(summary)
