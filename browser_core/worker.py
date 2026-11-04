from __future__ import annotations

import hashlib
import os
import re
import stat
from pathlib import Path
from typing import Any, Callable, NamedTuple

from .client import ControlClient, _lease_token
from .contracts import RUN_ID_RE, ContractError, reject_sensitive_keys
from .control_files import (
    BoundedControlSnapshot,
    BoundedJsonDirectoryInventory,
    canonical_json_bytes,
    decode_strict_json_bytes,
    inventory_bounded_json_directory,
    publish_json_exclusive_result,
    read_bounded_control_snapshot_result,
)
from .control import ControlStore, WorkerPrincipal
from .kernels import device_from_playwright, discover_kernels, probe_playwright_kernel
from .network import load_network_route, preflight_network_route, resolve_network_route
from .numeric import is_finite_number
from .physical_mobile import probe_physical_android
from .profiles import has_windows_device_basename
from .smoke import NativeCanvasSmoke, run_native_canvas_smoke
from .owned_paths import (
    DirectoryIdentity,
    directory_ancestry_binding,
    directory_identity,
    prepare_owned_directory_parent,
    require_owned_directory_ancestors,
)


MAX_TYPED_OPS_IDENTITIES = 8
MAX_TYPED_OPS_REPORT_BYTES = 16 * 1024 * 1024
MAX_PINWATCH_SOURCE_BYTES = 256 * 1024 * 1024
MAX_PINWATCH_OUTPUT_BYTES = 1024 * 1024 * 1024
PINWATCH_OUTPUT_FILENAMES = {
    "comparison-report.json",
    "comparison-evidence.json",
    "evidence-graph.json",
    "comparison-query.json",
    "receipt.json",
}


class _FleetComparisonSource(NamedTuple):
    path: Path
    snapshot: BoundedControlSnapshot
    parent_ancestry: tuple[DirectoryIdentity, ...]
    maximum: int


def _load_fleet_comparison_source(
    path: Path,
    loader: Callable[[Path], dict[str, Any]],
    *,
    maximum: int,
    bindings: list[_FleetComparisonSource],
) -> dict[str, Any]:
    label = "fleet comparison source"
    parent_ancestry = directory_ancestry_binding(path.parent.absolute(), label=label)
    snapshot = read_bounded_control_snapshot_result(
        path, maximum=maximum, label=label, require_single_link=True
    )
    if snapshot.state != "complete" or snapshot.body is None:
        raise ContractError("fleet comparison source changed")
    document = loader(path)
    if (
        document != decode_strict_json_bytes(snapshot.body, label=label)
        or directory_ancestry_binding(path.parent.absolute(), label=label)
        != parent_ancestry
    ):
        raise ContractError("fleet comparison source changed")
    bindings.append(_FleetComparisonSource(path, snapshot, parent_ancestry, maximum))
    return document


def _recheck_fleet_comparison_sources(bindings: list[_FleetComparisonSource]) -> None:
    for binding in bindings:
        if (
            directory_ancestry_binding(
                binding.path.parent.absolute(), label="fleet comparison source"
            ) != binding.parent_ancestry
            or read_bounded_control_snapshot_result(
                binding.path,
                maximum=binding.maximum,
                label="fleet comparison source",
                require_single_link=True,
            ) != binding.snapshot
        ):
            raise ContractError("fleet comparison source changed")


def _project_multi_identity_ops_report(
    report: Any,
    *,
    job_id: str,
    expected_count: int,
    expected_headless: bool,
    expected_parallel: int,
    expected_network_auto: bool,
) -> dict[str, Any]:
    fields = {
        "schema",
        "batch_id",
        "definition",
        "count",
        "headless",
        "parallel",
        "wall_ms",
        "evaluators",
        "network_auto",
        "network_route_configured",
        "compatibility",
        "host_identity_anchors",
        "identity_alignments",
        "identities",
        "errors",
        "orphans",
        "lifecycle_passed",
        "coherence_summary",
        "passed",
        "non_claims",
        "completed_at",
    }
    expected_batch = f"fleet-{job_id}"
    if (
        not isinstance(report, dict)
        or set(report) != fields
        or report.get("schema") != "browser-core.ops-coherence-cohort/1"
        or report.get("batch_id") != expected_batch
        or report.get("count") != expected_count
        or isinstance(report.get("count"), bool)
        or report.get("headless") is not expected_headless
        or report.get("parallel") != expected_parallel
        or isinstance(report.get("parallel"), bool)
        or report.get("network_auto") is not expected_network_auto
        or report.get("evaluators") != "controlled_coherence"
    ):
        raise ContractError("multi-identity ops report structure is invalid")
    lifecycle_passed = report.get("lifecycle_passed")
    passed = report.get("passed")
    errors = report.get("errors")
    orphans = report.get("orphans")
    identities = report.get("identities")
    if (
        type(lifecycle_passed) is not bool
        or type(passed) is not bool
        or passed is not lifecycle_passed
        or not isinstance(errors, list)
        or len(errors) > expected_count * 4
        or not all(isinstance(item, str) and len(item) <= 4096 for item in errors)
        or not isinstance(orphans, list)
        or len(orphans) > expected_count
        or not all(
            isinstance(item, str) and RUN_ID_RE.fullmatch(item) for item in orphans
        )
        or not isinstance(identities, list)
        or len(identities) != expected_count
    ):
        raise ContractError("multi-identity ops lifecycle result is invalid")

    status_fields = {
        "schema",
        "profile_id",
        "persona_id",
        "state",
        "session_run_id",
        "network_route_id",
        "network_route_sha256_16",
        "timings_ms",
        "error",
    }
    outcomes: list[dict[str, Any]] = []
    persona_ids: set[str] = set()
    verdict_counts = {"pass": 0, "fail": 0, "error": 0}
    for status in identities:
        if (
            not isinstance(status, dict)
            or not status_fields.issubset(status)
            or not set(status).issubset(status_fields | {"coherence", "identity_align"})
        ):
            raise ContractError("multi-identity ops identity status is invalid")
        persona_id = status.get("persona_id")
        state = status.get("state")
        if (
            status.get("schema") != "browser-core.identity-ops-status/1"
            or not isinstance(persona_id, str)
            or RUN_ID_RE.fullmatch(persona_id) is None
            or persona_id in persona_ids
            or not isinstance(state, str)
            or state not in {"disposed", "failed"}
        ):
            raise ContractError("multi-identity ops identity status is invalid")
        identity_error = status.get("error")
        if identity_error is not None and (
            not isinstance(identity_error, str)
            or not 1 <= len(identity_error) <= 4096
            or any(not 0x20 <= ord(character) <= 0x7E for character in identity_error)
            or not any(item.endswith(f": {identity_error}") for item in errors)
        ):
            raise ContractError("multi-identity ops identity status is invalid")
        if state == "failed" and identity_error is None:
            raise ContractError("multi-identity ops identity status is invalid")
        persona_ids.add(persona_id)
        coherence_verdict = None
        if "coherence" in status:
            coherence = status["coherence"]
            if (
                not isinstance(coherence, dict)
                or not isinstance(coherence.get("status"), str)
                or coherence["status"] not in {"ok", "error"}
                or not isinstance(coherence.get("verdict"), str)
                or coherence["verdict"] not in {"pass", "fail", "unknown"}
                or (coherence["status"] == "error" and coherence["verdict"] != "unknown")
            ):
                raise ContractError("multi-identity ops identity status is invalid")
            coherence_verdict = coherence["verdict"]
        verdict_class = (
            coherence_verdict
            if coherence_verdict in {"pass", "fail"}
            else "error"
        )
        verdict_counts[verdict_class] += 1
        outcomes.append(
            {
                "persona_id": persona_id,
                "state": state,
                "coherence_verdict": (
                    verdict_class if verdict_class != "error" else None
                ),
            }
        )

    summary = report.get("coherence_summary")
    if not isinstance(summary, dict) or set(summary) != {
        "arms",
        "pass",
        "fail",
        "error",
        "all_pass",
    }:
        raise ContractError("multi-identity ops coherence summary is invalid")
    for key in ("arms", "pass", "fail", "error"):
        value = summary.get(key)
        if (
            isinstance(value, bool)
            or not isinstance(value, int)
            or not 0 <= value <= expected_count
        ):
            raise ContractError("multi-identity ops coherence summary is invalid")
    expected_lifecycle = (
        not errors
        and not orphans
        and all(outcome["state"] == "disposed" for outcome in outcomes)
    )
    expected_all_pass = (
        expected_lifecycle
        and verdict_counts["pass"] == expected_count
        and verdict_counts["fail"] == 0
        and verdict_counts["error"] == 0
    )
    if (
        summary["arms"] != expected_count
        or sum(summary[key] for key in ("pass", "fail", "error")) != expected_count
        or any(summary[key] != verdict_counts[key] for key in verdict_counts)
        or type(summary.get("all_pass")) is not bool
        or summary["all_pass"] is not expected_all_pass
        or lifecycle_passed is not expected_lifecycle
    ):
        raise ContractError("multi-identity ops report counts are inconsistent")

    reject_sensitive_keys(report)
    body = canonical_json_bytes(report)
    if len(body) > MAX_TYPED_OPS_REPORT_BYTES:
        raise ContractError("multi-identity ops report exceeds the worker limit")
    receipt = {
        "schema": "browser-core.multi-identity-ops-result/1",
        "job_id": job_id,
        "batch_id": expected_batch,
        "count": expected_count,
        "lifecycle_passed": lifecycle_passed,
        "coherence": {
            "pass": summary["pass"],
            "fail": summary["fail"],
            "error": summary["error"],
            "all_pass": summary["all_pass"],
        },
        "outcomes": outcomes,
        "error_count": len(errors),
        "orphan_count": len(orphans),
        "report_sha256_16": hashlib.sha256(body).hexdigest()[:16],
    }
    reject_sensitive_keys(receipt)
    return receipt


def _project_browser_eval_summary(
    summary: Any,
    *,
    job_id: str,
    requested_ids: list[str],
) -> dict[str, Any]:
    if not isinstance(summary, dict):
        raise ContractError("browser-eval summary must be an object")
    run_id = summary.get("run_id")
    if not isinstance(run_id, str) or not RUN_ID_RE.fullmatch(run_id):
        raise ContractError("browser-eval summary run id is invalid")
    rows = summary.get("evaluators")
    if not isinstance(rows, list) or len(rows) != len(requested_ids) or len(rows) > 64:
        raise ContractError("browser-eval summary evaluator population is invalid")
    outcomes: list[dict[str, str]] = []
    seen: set[str] = set()
    for row in rows:
        if not isinstance(row, dict):
            raise ContractError("browser-eval summary evaluator is invalid")
        evaluator_id = row.get("id")
        status = row.get("status")
        verdict = row.get("verdict")
        if (
            not isinstance(evaluator_id, str)
            or evaluator_id not in requested_ids
            or evaluator_id in seen
            or not isinstance(status, str)
            or status not in {"ok", "error"}
            or not isinstance(verdict, str)
            or verdict not in {"pass", "fail", "unknown"}
            or (status == "error" and verdict != "unknown")
        ):
            raise ContractError("browser-eval summary evaluator is invalid")
        outcomes.append({"id": evaluator_id, "status": status, "verdict": verdict})
        seen.add(evaluator_id)
    if seen != set(requested_ids):
        raise ContractError("browser-eval summary evaluator selection changed")
    completed = summary.get("completed")
    failed = summary.get("failed")
    total = summary.get("total")
    for value in (completed, failed, total):
        if (
            isinstance(value, bool)
            or not isinstance(value, int)
            or not 0 <= value <= 64
        ):
            raise ContractError("browser-eval summary counts are invalid")
    if (
        total != len(outcomes)
        or completed != sum(item["status"] == "ok" for item in outcomes)
        or failed != sum(item["status"] == "error" for item in outcomes)
        or completed + failed != total
    ):
        raise ContractError("browser-eval summary counts are inconsistent")
    outcomes.sort(key=lambda item: item["id"])
    receipt = {
        "schema": "browser-core.browser-eval-result/2",
        "job_id": job_id,
        "run_id": run_id,
        "evaluators_requested": sorted(requested_ids),
        "outcomes": outcomes,
        "completed": completed,
        "failed": failed,
        "total": total,
    }
    receipt["summary_sha256_16"] = hashlib.sha256(
        canonical_json_bytes(receipt)
    ).hexdigest()[:16]
    reject_sensitive_keys(receipt)
    return receipt


def _project_pinwatch_drift_result(
    receipt: Any,
    *,
    job_id: str,
    output_id: str,
    producer_sha256_16: str,
) -> dict[str, Any]:
    if (
        not isinstance(receipt, dict)
        or receipt.get("schema") != "webre.pin-drift-flow/1"
        or not isinstance(receipt.get("flow_id"), str)
        or re.fullmatch(r"pin-drift-flow:[0-9a-f]{16}", receipt["flow_id"])
        is None
        or receipt.get("supports_general_compatibility_claim") is not False
        or receipt.get("supports_semantic_equivalence_claim") is not False
        or receipt.get("supports_target_acceptance_claim") is not False
        or receipt.get("supports_behavior_absence_claim") is not False
        or receipt.get("supports_causal_attribution_claim") is not False
    ):
        raise ContractError("PinWatch drift receipt boundary is invalid")
    results = receipt.get("results")
    expected_result_fields = {
        "flow_completed",
        "comparison_id",
        "evidence_level",
        "confidence",
        "verdict",
        "compatible",
        "minimum_baseline_samples_met",
        "runtime_attached",
        "runtime_used_for_verdict",
        "zero_runtime_drops",
        "contract_gates_passed",
        "graph_sources",
        "graph_nodes",
        "graph_edges",
        "check_passed",
    }
    if (
        not isinstance(results, dict)
        or set(results) != expected_result_fields
        or results.get("flow_completed") is not True
        or not isinstance(results.get("comparison_id"), str)
        or re.fullmatch(r"pin-comparison:[0-9a-f]{16}", results["comparison_id"])
        is None
        or not isinstance(results.get("evidence_level"), str)
        or results["evidence_level"] not in {"structural", "mixed"}
        or not isinstance(results.get("confidence"), str)
        or results["confidence"] not in {"low", "medium", "high"}
        or not isinstance(results.get("verdict"), str)
        or results["verdict"]
        not in {
            "unchanged",
            "instance_variation_only",
            "compatible_rotation",
            "review",
            "breaking",
        }
        or any(
            type(results.get(field)) is not bool
            for field in (
                "compatible",
                "minimum_baseline_samples_met",
                "runtime_attached",
                "runtime_used_for_verdict",
                "contract_gates_passed",
                "check_passed",
            )
        )
        or not (
            results.get("zero_runtime_drops") is None
            or type(results.get("zero_runtime_drops")) is bool
        )
    ):
        raise ContractError("PinWatch drift result projection is invalid")
    for field in ("graph_sources", "graph_nodes", "graph_edges"):
        value = results.get(field)
        if isinstance(value, bool) or not isinstance(value, int) or value < 1:
            raise ContractError("PinWatch drift graph counts are invalid")
    compatible_verdicts = {
        "unchanged",
        "instance_variation_only",
        "compatible_rotation",
    }
    runtime_attached = results["runtime_attached"]
    expected_check = (
        results["compatible"]
        and results["minimum_baseline_samples_met"]
        and results["contract_gates_passed"]
        and (
            not runtime_attached
            or (
                results["runtime_used_for_verdict"]
                and results["zero_runtime_drops"] is True
            )
        )
    )
    if (
        results["compatible"]
        is not (results["verdict"] in compatible_verdicts)
        or results["evidence_level"]
        != ("mixed" if runtime_attached else "structural")
        or (
            not runtime_attached
            and (
                results["runtime_used_for_verdict"] is not False
                or results["zero_runtime_drops"] is not None
            )
        )
        or (
            runtime_attached
            and type(results["zero_runtime_drops"]) is not bool
        )
        or results["check_passed"] is not expected_check
    ):
        raise ContractError("PinWatch drift result relationships are inconsistent")
    if not isinstance(producer_sha256_16, str) or re.fullmatch(
        r"[0-9a-f]{16}", producer_sha256_16
    ) is None:
        raise ContractError("PinWatch producer binding is invalid")
    projected = {
        "schema": "browser-core.pinwatch-drift-check-result/1",
        "job_id": job_id,
        "output_id": output_id,
        "flow_id": receipt["flow_id"],
        "comparison_id": results["comparison_id"],
        "evidence_level": results["evidence_level"],
        "confidence": results["confidence"],
        "verdict": results["verdict"],
        "compatible": results["compatible"],
        "minimum_baseline_samples_met": results[
            "minimum_baseline_samples_met"
        ],
        "runtime_attached": results["runtime_attached"],
        "runtime_used_for_verdict": results["runtime_used_for_verdict"],
        "zero_runtime_drops": results["zero_runtime_drops"],
        "contract_gates_passed": results["contract_gates_passed"],
        "check_passed": results["check_passed"],
        "graph": {
            "sources": results["graph_sources"],
            "nodes": results["graph_nodes"],
            "edges": results["graph_edges"],
        },
        "producer": {
            "schema": "webre.pin-drift-flow/1",
            "entry_source_sha256_16": producer_sha256_16,
            "source_attested": False,
        },
        "non_claims": [
            "static and runtime compatibility evidence is not semantic equivalence",
            "a passing drift gate is not protected-target acceptance",
            "the producer digest observes entry source bytes after import; it does not attest loaded code or dependencies",
        ],
    }
    reject_sensitive_keys(projected)
    return projected


def execute_typed_job(
    job: dict[str, Any],
    *,
    repository_root: Path,
    workspace: Path,
) -> dict[str, Any]:
    if not isinstance(repository_root, Path) or not isinstance(workspace, Path):
        raise ContractError("typed worker roots must be Paths")
    if not isinstance(job, dict):
        raise ContractError("leased job must be an object")
    job_id = _require_run_id(job.get("id"), "job id")
    kind = job.get("kind")
    if not isinstance(kind, str):
        raise ContractError("leased job kind is invalid")
    payload = job.get("payload")
    if not isinstance(payload, dict):
        raise ContractError("leased job payload must be an object")
    if kind in {"browser-eval", "multi-identity-ops"} and (
        job_id.endswith(".") or has_windows_device_basename(job_id)
    ):
        raise ContractError("leased job id is invalid")
    if kind != "pinwatch-drift-check":
        workspace = _worker_workspace_path(workspace)
    if kind == "kernel-probe":
        allowed = {"kernel_id", "device_preset", "locale", "timezone"}
        if set(payload) != allowed:
            raise ContractError("kernel-probe payload fields are invalid")
        for field, maximum in (
            ("kernel_id", 128),
            ("device_preset", 128),
            ("locale", 64),
            ("timezone", 128),
        ):
            _require_bounded_text(payload[field], f"kernel-probe {field}", maximum)
        kernels = {item["id"]: item for item in discover_kernels(repository_root)}
        kernel = kernels.get(payload["kernel_id"])
        if kernel is None:
            raise ContractError("kernel-probe requested an unknown kernel")
        device = device_from_playwright(
            payload["device_preset"],
            locale=payload["locale"],
            timezone=payload["timezone"],
        )
        return probe_playwright_kernel(kernel, device)
    if kind == "network-preflight":
        if set(payload) != {"route_id", "probe_url"}:
            raise ContractError("network-preflight payload fields are invalid")
        route_id = _require_run_id(payload["route_id"], "network route id")
        probe_url = _require_bounded_text(
            payload["probe_url"], "network-preflight probe url", 16_384
        )
        route = load_network_route(workspace, route_id)
        if probe_url != route["preflight_url"]:
            raise ContractError(
                "network-preflight probe url does not match the route contract"
            )
        return preflight_network_route(resolve_network_route(route), probe_url)
    if kind == "physical-kernel-probe":
        if (
            set(payload) != {"platform", "timeout_seconds"}
            or payload["platform"] != "android"
        ):
            raise ContractError("physical-kernel-probe payload fields are invalid")
        return probe_physical_android(
            timeout_seconds=_require_timeout(
                payload["timeout_seconds"],
                "physical-kernel-probe timeout",
                maximum=120,
            )
        )
    if kind == "native-smoke":
        if set(payload) != {"executable", "trace_processor", "timeout_seconds"}:
            raise ContractError("native-smoke payload fields are invalid")
        timeout_seconds = _require_timeout(
            payload["timeout_seconds"], "native-smoke timeout", maximum=300
        )
        executable = _require_workspace_file(
            payload["executable"], workspace, "native-smoke executable"
        )
        trace_processor = _require_workspace_file(
            payload["trace_processor"], workspace, "native-smoke trace processor"
        )
        if trace_processor.name.lower() not in {
            "trace_processor_shell",
            "trace_processor_shell.exe",
        }:
            raise ContractError("native-smoke trace processor filename is invalid")
        require_owned_directory_ancestors(workspace, label="native-smoke workspace")
        return run_native_canvas_smoke(
            NativeCanvasSmoke(
                executable=executable,
                trace_processor=trace_processor,
                workspace=workspace,
                timeout_seconds=timeout_seconds,
            ),
            repository_root,
        )
    if kind == "transport-fingerprint":
        if set(payload) != {"executable", "fingerprint_id", "timeout_seconds"}:
            raise ContractError("transport-fingerprint payload fields are invalid")
        from .transport_fingerprint import (
            MAX_TRANSPORT_FINGERPRINT_BYTES,
            capture_attested_client_hello,
            load_transport_fingerprint,
            validate_transport_fingerprint,
        )

        fingerprint_id = _require_portable_output_id(
            payload["fingerprint_id"], "transport fingerprint id"
        )
        timeout_seconds = _require_timeout(
            payload["timeout_seconds"],
            "transport-fingerprint timeout",
            maximum=120,
        )
        executable = _require_workspace_file(
            payload["executable"], workspace, "transport-fingerprint executable"
        )
        transport_root = _prepare_worker_output_root(
            workspace, "transport-fingerprints", label="transport-fingerprint registry"
        )
        transport_root_identity = directory_identity(
            transport_root,
            label="transport-fingerprint registry",
        )
        if transport_root_identity is None:
            raise ContractError("transport-fingerprint registry is unavailable")
        transport_root_ancestry = directory_ancestry_binding(
            transport_root.absolute(), label="transport-fingerprint registry"
        )
        destination = transport_root / f"{fingerprint_id}.json"
        if os.path.lexists(destination):
            raise ContractError("transport fingerprint id already exists")
        result = validate_transport_fingerprint(
            capture_attested_client_hello(
                repository_root,
                executable,
                timeout_seconds=timeout_seconds,
            ),
            require_build=True,
        )
        if (
            directory_identity(
                transport_root,
                label="transport-fingerprint registry",
            )
            != transport_root_identity
            or directory_ancestry_binding(
                transport_root.absolute(), label="transport-fingerprint registry"
            ) != transport_root_ancestry
        ):
            raise ContractError("transport-fingerprint registry authority changed")
        reject_sensitive_keys(result)
        published_snapshot = publish_json_exclusive_result(
            destination,
            result,
            maximum=MAX_TRANSPORT_FINGERPRINT_BYTES,
            label="transport fingerprint",
        )
        published_result = load_transport_fingerprint(destination)
        final_snapshot = read_bounded_control_snapshot_result(
            destination,
            maximum=MAX_TRANSPORT_FINGERPRINT_BYTES,
            label="transport fingerprint",
        )
        transport_root_after_publication = directory_identity(
            transport_root,
            label="transport-fingerprint registry",
        )
        if (
            transport_root_after_publication != transport_root_identity
            or directory_ancestry_binding(
                transport_root.absolute(), label="transport-fingerprint registry"
            ) != transport_root_ancestry
            or published_result != result
            or final_snapshot.state != "complete"
            or final_snapshot.body != published_snapshot.body
            or final_snapshot.identity != published_snapshot.identity
        ):
            raise ContractError("transport fingerprint changed after publication")
        return {
            "schema": "browser-core.transport-fingerprint-publication/1",
            "job_id": job_id,
            "fingerprint_id": fingerprint_id,
            "digest_sha256": result["digest_sha256"],
            "core_build": dict(result["core_build"]),
        }
    if kind == "http2-fingerprint":
        if set(payload) != {
            "executable",
            "certificate",
            "private_key",
            "fingerprint_id",
            "timeout_seconds",
        }:
            raise ContractError("http2-fingerprint payload fields are invalid")
        from .http2_fingerprint import (
            MAX_HTTP2_FINGERPRINT_BYTES,
            capture_attested_http2_fingerprint,
            load_http2_fingerprint,
            validate_http2_fingerprint,
        )

        fingerprint_id = _require_portable_output_id(
            payload["fingerprint_id"], "HTTP/2 fingerprint id"
        )
        timeout_seconds = _require_timeout(
            payload["timeout_seconds"],
            "http2-fingerprint timeout",
            maximum=120,
        )
        executable = _require_workspace_file(
            payload["executable"], workspace, "http2-fingerprint executable"
        )
        certificate = _require_workspace_file(
            payload["certificate"], workspace, "http2-fingerprint certificate"
        )
        private_key = _require_workspace_file(
            payload["private_key"], workspace, "http2-fingerprint private key"
        )
        http2_root = _prepare_worker_output_root(
            workspace, "http2-fingerprints", label="http2-fingerprint registry"
        )
        http2_root_identity = directory_identity(
            http2_root,
            label="http2-fingerprint registry",
        )
        if http2_root_identity is None:
            raise ContractError("http2-fingerprint registry is unavailable")
        http2_root_ancestry = directory_ancestry_binding(
            http2_root.absolute(), label="http2-fingerprint registry"
        )
        destination = http2_root / f"{fingerprint_id}.json"
        if os.path.lexists(destination):
            raise ContractError("HTTP/2 fingerprint id already exists")
        result = validate_http2_fingerprint(
            capture_attested_http2_fingerprint(
                repository_root,
                executable,
                certificate,
                private_key,
                timeout_seconds=timeout_seconds,
            ),
            require_build=True,
        )
        if (
            directory_identity(http2_root, label="http2-fingerprint registry")
            != http2_root_identity
            or directory_ancestry_binding(
                http2_root.absolute(), label="http2-fingerprint registry"
            ) != http2_root_ancestry
        ):
            raise ContractError("http2-fingerprint registry authority changed")
        reject_sensitive_keys(result)
        published_snapshot = publish_json_exclusive_result(
            destination,
            result,
            maximum=MAX_HTTP2_FINGERPRINT_BYTES,
            label="HTTP/2 fingerprint",
        )
        published_result = load_http2_fingerprint(destination)
        final_snapshot = read_bounded_control_snapshot_result(
            destination,
            maximum=MAX_HTTP2_FINGERPRINT_BYTES,
            label="HTTP/2 fingerprint",
        )
        http2_root_after_publication = directory_identity(
            http2_root,
            label="http2-fingerprint registry",
        )
        if (
            http2_root_after_publication != http2_root_identity
            or directory_ancestry_binding(
                http2_root.absolute(), label="http2-fingerprint registry"
            ) != http2_root_ancestry
            or published_result != result
            or final_snapshot.state != "complete"
            or final_snapshot.body != published_snapshot.body
            or final_snapshot.identity != published_snapshot.identity
        ):
            raise ContractError("HTTP/2 fingerprint changed after publication")
        return {
            "schema": "browser-core.http2-fingerprint-publication/1",
            "job_id": job_id,
            "fingerprint_id": fingerprint_id,
            "digest_sha256": result["digest_sha256"],
            "core_build": dict(result["core_build"]),
        }
    if kind == "http2-evidence":
        if set(payload) != {
            "executable",
            "certificate",
            "private_key",
            "evidence_id",
            "timeout_seconds",
        }:
            raise ContractError("http2-evidence payload fields are invalid")
        from .http2_fingerprint import capture_attested_http2_evidence
        from .http2_headers import (
            MAX_HTTP2_EVIDENCE_DOCUMENT_BYTES,
            load_http2_capture_evidence,
            validate_http2_capture_evidence,
        )

        evidence_id = _require_portable_output_id(
            payload["evidence_id"], "HTTP/2 evidence id"
        )
        timeout_seconds = _require_timeout(
            payload["timeout_seconds"],
            "http2-evidence timeout",
            maximum=120,
        )
        executable = _require_workspace_file(
            payload["executable"], workspace, "http2-evidence executable"
        )
        certificate = _require_workspace_file(
            payload["certificate"], workspace, "http2-evidence certificate"
        )
        private_key = _require_workspace_file(
            payload["private_key"], workspace, "http2-evidence private key"
        )
        evidence_root = _prepare_worker_output_root(
            workspace, "http2-evidence", label="http2-evidence registry"
        )
        evidence_root_identity = directory_identity(
            evidence_root,
            label="http2-evidence registry",
        )
        if evidence_root_identity is None:
            raise ContractError("http2-evidence registry is unavailable")
        evidence_root_ancestry = directory_ancestry_binding(
            evidence_root.absolute(), label="http2-evidence registry"
        )
        destination = evidence_root / f"{evidence_id}.json"
        if os.path.lexists(destination):
            raise ContractError("HTTP/2 evidence id already exists")
        result = validate_http2_capture_evidence(
            capture_attested_http2_evidence(
                repository_root,
                executable,
                certificate,
                private_key,
                timeout_seconds=timeout_seconds,
            ),
            require_build=True,
        )
        if (
            directory_identity(evidence_root, label="http2-evidence registry")
            != evidence_root_identity
            or directory_ancestry_binding(
                evidence_root.absolute(), label="http2-evidence registry"
            ) != evidence_root_ancestry
        ):
            raise ContractError("http2-evidence registry authority changed")
        reject_sensitive_keys(result)
        published_snapshot = publish_json_exclusive_result(
            destination,
            result,
            maximum=MAX_HTTP2_EVIDENCE_DOCUMENT_BYTES,
            label="HTTP/2 evidence",
        )
        published_result = load_http2_capture_evidence(destination)
        final_snapshot = read_bounded_control_snapshot_result(
            destination,
            maximum=MAX_HTTP2_EVIDENCE_DOCUMENT_BYTES,
            label="HTTP/2 evidence",
        )
        evidence_root_after_publication = directory_identity(
            evidence_root,
            label="http2-evidence registry",
        )
        if (
            evidence_root_after_publication != evidence_root_identity
            or directory_ancestry_binding(
                evidence_root.absolute(), label="http2-evidence registry"
            ) != evidence_root_ancestry
            or published_result != result
            or final_snapshot.state != "complete"
            or final_snapshot.body != published_snapshot.body
            or final_snapshot.identity != published_snapshot.identity
        ):
            raise ContractError("HTTP/2 evidence changed after publication")
        return {
            "schema": "browser-core.http2-evidence-publication/1",
            "job_id": job_id,
            "evidence_id": evidence_id,
            "digest_sha256": result["digest_sha256"],
            "fingerprint_digest_sha256": result["fingerprint"]["digest_sha256"],
            "header_order_digest_sha256": result["header_order"]["digest_sha256"],
            "core_build": dict(result["fingerprint"]["core_build"]),
        }
    if kind == "http2-evidence-baseline-install":
        if set(payload) != {"baseline"}:
            raise ContractError(
                "http2-evidence-baseline-install payload fields are invalid"
            )
        from .http2_headers import install_http2_evidence_baseline

        baseline = install_http2_evidence_baseline(workspace, payload["baseline"])
        result = {
            "schema": "browser-core.http2-evidence-baseline-installation/1",
            "job_id": job_id,
            "source_evidence_id": baseline["source_evidence_id"],
            "baseline_evidence_id": baseline["baseline_evidence_id"],
            "digest_sha256": baseline["reviewed_digest_sha256"],
            "core_build": dict(baseline["evidence"]["fingerprint"]["core_build"]),
        }
        reject_sensitive_keys(result)
        return result
    if kind == "http2-evidence-check":
        if set(payload) != {"current_id", "baseline_id"}:
            raise ContractError("http2-evidence-check payload fields are invalid")
        from .http2_headers import (
            MAX_HTTP2_EVIDENCE_DOCUMENT_BYTES,
            compare_http2_capture_evidence,
            load_http2_capture_evidence,
            load_http2_evidence_baseline,
        )

        current_id = _require_run_id(payload["current_id"], "HTTP/2 evidence current id")
        baseline_id = _require_run_id(
            payload["baseline_id"],
            "HTTP/2 evidence baseline id",
        )
        source_bindings: list[_FleetComparisonSource] = []
        baseline_document = _load_fleet_comparison_source(
            _http2_evidence_baseline_path(workspace, baseline_id),
            load_http2_evidence_baseline,
            maximum=MAX_HTTP2_EVIDENCE_DOCUMENT_BYTES,
            bindings=source_bindings,
        )
        if baseline_document["baseline_evidence_id"] != baseline_id:
            raise ContractError("HTTP/2 evidence baseline id does not match registry name")
        result = compare_http2_capture_evidence(
            _load_fleet_comparison_source(
                _http2_evidence_path(workspace, current_id, label="current evidence"),
                load_http2_capture_evidence,
                maximum=MAX_HTTP2_EVIDENCE_DOCUMENT_BYTES,
                bindings=source_bindings,
            ),
            baseline_document["evidence"],
        )
        reject_sensitive_keys(result)
        _recheck_fleet_comparison_sources(source_bindings)
        return result
    if kind == "http2-baseline-install":
        if set(payload) != {"baseline"}:
            raise ContractError("http2-baseline-install payload fields are invalid")
        from .http2_fingerprint import install_http2_baseline

        baseline = install_http2_baseline(workspace, payload["baseline"])
        result = {
            "schema": "browser-core.http2-baseline-installation/1",
            "job_id": job_id,
            "source_fingerprint_id": baseline["source_fingerprint_id"],
            "baseline_fingerprint_id": baseline["baseline_fingerprint_id"],
            "digest_sha256": baseline["reviewed_digest_sha256"],
            "core_build": dict(baseline["fingerprint"]["core_build"]),
        }
        reject_sensitive_keys(result)
        return result
    if kind == "http2-check":
        if set(payload) != {"current_id", "baseline_id"}:
            raise ContractError("http2-check payload fields are invalid")
        from .http2_fingerprint import (
            MAX_HTTP2_FINGERPRINT_BYTES,
            compare_http2_fingerprints,
            load_http2_baseline,
            load_http2_fingerprint,
        )

        current_id = _require_run_id(payload["current_id"], "HTTP/2 current id")
        baseline_id = _require_run_id(payload["baseline_id"], "HTTP/2 baseline id")
        current = _http2_fingerprint_path(
            workspace,
            current_id,
            label="HTTP/2 current fingerprint",
        )
        baseline = _http2_baseline_path(workspace, baseline_id)
        source_bindings = []
        baseline_document = _load_fleet_comparison_source(
            baseline,
            load_http2_baseline,
            maximum=MAX_HTTP2_FINGERPRINT_BYTES,
            bindings=source_bindings,
        )
        if baseline_document["baseline_fingerprint_id"] != baseline_id:
            raise ContractError("HTTP/2 baseline id does not match registry name")
        result = compare_http2_fingerprints(
            _load_fleet_comparison_source(
                current,
                load_http2_fingerprint,
                maximum=MAX_HTTP2_FINGERPRINT_BYTES,
                bindings=source_bindings,
            ),
            baseline_document["fingerprint"],
        )
        reject_sensitive_keys(result)
        _recheck_fleet_comparison_sources(source_bindings)
        return result
    if kind == "transport-baseline-install":
        if set(payload) != {"baseline"}:
            raise ContractError("transport-baseline-install payload fields are invalid")
        from .transport_fingerprint import install_transport_baseline

        baseline = install_transport_baseline(workspace, payload["baseline"])
        result = {
            "schema": "browser-core.transport-baseline-installation/1",
            "job_id": job_id,
            "source_fingerprint_id": baseline["source_fingerprint_id"],
            "baseline_fingerprint_id": baseline["baseline_fingerprint_id"],
            "digest_sha256": baseline["reviewed_digest_sha256"],
            "core_build": dict(baseline["fingerprint"]["core_build"]),
        }
        reject_sensitive_keys(result)
        return result
    if kind == "transport-check":
        if set(payload) != {"current_id", "baseline_id"}:
            raise ContractError("transport-check payload fields are invalid")
        from .transport_fingerprint import (
            MAX_TRANSPORT_FINGERPRINT_BYTES,
            compare_transport_fingerprints,
            load_transport_baseline,
            load_transport_fingerprint,
        )

        current_id = _require_run_id(payload["current_id"], "transport current id")
        baseline_id = _require_run_id(
            payload["baseline_id"], "transport baseline id"
        )
        current = _transport_fingerprint_path(workspace, current_id, label="current")
        baseline = _transport_baseline_path(workspace, baseline_id)
        source_bindings = []
        baseline_document = _load_fleet_comparison_source(
            baseline,
            load_transport_baseline,
            maximum=MAX_TRANSPORT_FINGERPRINT_BYTES,
            bindings=source_bindings,
        )
        if baseline_document["baseline_fingerprint_id"] != baseline_id:
            raise ContractError("transport baseline id does not match registry name")
        result = compare_transport_fingerprints(
            _load_fleet_comparison_source(
                current,
                load_transport_fingerprint,
                maximum=MAX_TRANSPORT_FINGERPRINT_BYTES,
                bindings=source_bindings,
            ),
            baseline_document["fingerprint"],
        )
        reject_sensitive_keys(result)
        _recheck_fleet_comparison_sources(source_bindings)
        return result
    if kind == "transport-suite-check":
        fields = {
            "client_hello_current_id",
            "client_hello_baseline_id",
            "http2_current_id",
            "http2_baseline_id",
        }
        if set(payload) != fields:
            raise ContractError("transport-suite-check payload fields are invalid")
        identifiers = {
            field: _require_run_id(payload[field], f"transport-suite-check {field}")
            for field in fields
        }
        from .http2_fingerprint import (
            MAX_HTTP2_FINGERPRINT_BYTES,
            load_http2_baseline,
            load_http2_fingerprint,
        )
        from .transport_fingerprint import (
            MAX_TRANSPORT_FINGERPRINT_BYTES,
            load_transport_baseline,
            load_transport_fingerprint,
        )
        from .transport_suite import compare_transport_suite

        source_bindings = []
        transport_baseline = _load_fleet_comparison_source(
            _transport_baseline_path(
                workspace,
                identifiers["client_hello_baseline_id"],
            ),
            load_transport_baseline,
            maximum=MAX_TRANSPORT_FINGERPRINT_BYTES,
            bindings=source_bindings,
        )
        http2_baseline = _load_fleet_comparison_source(
            _http2_baseline_path(
                workspace,
                identifiers["http2_baseline_id"],
            ),
            load_http2_baseline,
            maximum=MAX_HTTP2_FINGERPRINT_BYTES,
            bindings=source_bindings,
        )
        if (
            transport_baseline["baseline_fingerprint_id"]
            != identifiers["client_hello_baseline_id"]
        ):
            raise ContractError("transport baseline id does not match registry name")
        if (
            http2_baseline["baseline_fingerprint_id"]
            != identifiers["http2_baseline_id"]
        ):
            raise ContractError("HTTP/2 baseline id does not match registry name")
        result = compare_transport_suite(
            _load_fleet_comparison_source(
                _transport_fingerprint_path(
                    workspace,
                    identifiers["client_hello_current_id"],
                    label="suite current",
                ),
                load_transport_fingerprint,
                maximum=MAX_TRANSPORT_FINGERPRINT_BYTES,
                bindings=source_bindings,
            ),
            transport_baseline,
            _load_fleet_comparison_source(
                _http2_fingerprint_path(
                    workspace,
                    identifiers["http2_current_id"],
                    label="suite HTTP/2 current fingerprint",
                ),
                load_http2_fingerprint,
                maximum=MAX_HTTP2_FINGERPRINT_BYTES,
                bindings=source_bindings,
            ),
            http2_baseline,
        )
        reject_sensitive_keys(result)
        _recheck_fleet_comparison_sources(source_bindings)
        return result
    if kind == "transport-evidence-suite-check":
        fields = {
            "client_hello_current_id",
            "client_hello_baseline_id",
            "http2_evidence_current_id",
            "http2_evidence_baseline_id",
        }
        if set(payload) != fields:
            raise ContractError(
                "transport-evidence-suite-check payload fields are invalid"
            )
        identifiers = {
            field: _require_run_id(
                payload[field],
                f"transport-evidence-suite-check {field}",
            )
            for field in fields
        }
        from .http2_headers import (
            MAX_HTTP2_EVIDENCE_DOCUMENT_BYTES,
            load_http2_capture_evidence,
            load_http2_evidence_baseline,
        )
        from .transport_fingerprint import (
            MAX_TRANSPORT_FINGERPRINT_BYTES,
            load_transport_baseline,
            load_transport_fingerprint,
        )
        from .transport_suite import compare_transport_evidence_suite

        source_bindings = []
        transport_baseline = _load_fleet_comparison_source(
            _transport_baseline_path(
                workspace,
                identifiers["client_hello_baseline_id"],
            ),
            load_transport_baseline,
            maximum=MAX_TRANSPORT_FINGERPRINT_BYTES,
            bindings=source_bindings,
        )
        evidence_baseline = _load_fleet_comparison_source(
            _http2_evidence_baseline_path(
                workspace,
                identifiers["http2_evidence_baseline_id"],
            ),
            load_http2_evidence_baseline,
            maximum=MAX_HTTP2_EVIDENCE_DOCUMENT_BYTES,
            bindings=source_bindings,
        )
        if (
            transport_baseline["baseline_fingerprint_id"]
            != identifiers["client_hello_baseline_id"]
        ):
            raise ContractError("transport baseline id does not match registry name")
        if (
            evidence_baseline["baseline_evidence_id"]
            != identifiers["http2_evidence_baseline_id"]
        ):
            raise ContractError(
                "HTTP/2 evidence baseline id does not match registry name"
            )
        result = compare_transport_evidence_suite(
            _load_fleet_comparison_source(
                _transport_fingerprint_path(
                    workspace,
                    identifiers["client_hello_current_id"],
                    label="evidence-suite current",
                ),
                load_transport_fingerprint,
                maximum=MAX_TRANSPORT_FINGERPRINT_BYTES,
                bindings=source_bindings,
            ),
            transport_baseline,
            _load_fleet_comparison_source(
                _http2_evidence_path(
                    workspace,
                    identifiers["http2_evidence_current_id"],
                    label="suite current evidence",
                ),
                load_http2_capture_evidence,
                maximum=MAX_HTTP2_EVIDENCE_DOCUMENT_BYTES,
                bindings=source_bindings,
            ),
            evidence_baseline,
        )
        reject_sensitive_keys(result)
        _recheck_fleet_comparison_sources(source_bindings)
        return result
    if kind == "browser-eval":
        allowed = {"evaluators", "backend", "channel", "headless", "timeout_ms"}
        if set(payload) != allowed:
            raise ContractError("browser-eval payload fields are invalid")
        evaluators = payload["evaluators"]
        if (
            not isinstance(evaluators, list)
            or not 1 <= len(evaluators) <= 64
            or not all(
                isinstance(value, str)
                and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", value)
                for value in evaluators
            )
            or len(set(evaluators)) != len(evaluators)
        ):
            raise ContractError("browser-eval evaluator ids are invalid")
        if not isinstance(payload["backend"], str) or payload["backend"] not in {
            "patchright",
            "playwright",
            "external-cdp",
        }:
            raise ContractError("browser-eval backend is invalid")
        if not isinstance(payload["channel"], str) or payload["channel"] not in {
            "chrome",
            "chromium",
        }:
            raise ContractError("browser-eval channel is invalid")
        if not isinstance(payload["headless"], bool):
            raise ContractError("browser-eval headless flag must be boolean")
        timeout_ms = payload["timeout_ms"]
        if (
            isinstance(timeout_ms, bool)
            or not isinstance(timeout_ms, int)
            or not 1_000 <= timeout_ms <= 300_000
        ):
            raise ContractError(
                "browser-eval timeout must be an integer in [1000, 300000]"
            )
        try:
            from browser_eval.registry import load_registry, select_specs
            from browser_eval.runner import (
                MAX_SAVED_JSON_BYTES,
                RunConfig,
                execute_run,
                load_or_build_summary,
            )
        except ImportError:
            raise ContractError(
                "Browser Eval must be installed on this worker"
            ) from None
        registry = (
            Path(__import__("browser_eval").__file__).resolve().parent
            / "data"
            / "evaluators.json"
        )
        specs = select_specs(load_registry(registry), ",".join(evaluators))
        fleet_runs = _prepare_worker_output_root(
            workspace, "fleet-runs", label="browser-eval output root"
        )
        fleet_runs_identity = directory_identity(
            fleet_runs,
            label="browser-eval output root",
        )
        if fleet_runs_identity is None:
            raise ContractError("browser-eval output root is unavailable")
        fleet_runs_ancestry = directory_ancestry_binding(
            fleet_runs.absolute(), label="browser-eval output root"
        )
        job_output = fleet_runs / job_id
        if (
            directory_identity(job_output, label="browser-eval job output directory")
            is not None
        ):
            raise ContractError("browser-eval job output directory already exists")
        require_owned_directory_ancestors(fleet_runs, label="browser-eval output root")
        if (
            directory_identity(fleet_runs, label="browser-eval output root") != fleet_runs_identity
            or directory_ancestry_binding(
                fleet_runs.absolute(), label="browser-eval output root"
            ) != fleet_runs_ancestry
        ):
            raise ContractError("browser-eval output authority changed")
        try:
            job_output.mkdir()
        except FileExistsError:
            raise ContractError(
                "browser-eval job output directory already exists"
            ) from None
        except OSError:
            raise ContractError(
                "browser-eval job output directory could not be created"
            ) from None
        job_output_identity = directory_identity(
            job_output,
            label="browser-eval job output directory",
        )
        if (
            job_output_identity is None
            or directory_identity(fleet_runs, label="browser-eval output root")
            != fleet_runs_identity
            or directory_ancestry_binding(
                fleet_runs.absolute(), label="browser-eval output root"
            ) != fleet_runs_ancestry
        ):
            raise ContractError("browser-eval output authority changed")
        job_output_ancestry = directory_ancestry_binding(
            job_output.absolute(), label="browser-eval job output directory"
        )
        require_owned_directory_ancestors(job_output, label="browser-eval job output directory")
        expected_run_dir = job_output / "run"
        run_dir, summary = execute_run(
            specs,
            RunConfig(
                backend=payload["backend"],
                channel=payload["channel"],
                headless=payload["headless"],
                profile=None,
                screenshots=False,
                out=expected_run_dir,
                timeout_ms=timeout_ms,
            ),
        )
        if (
            directory_identity(fleet_runs, label="browser-eval output root")
            != fleet_runs_identity
            or directory_ancestry_binding(
                fleet_runs.absolute(), label="browser-eval output root"
            ) != fleet_runs_ancestry
            or directory_identity(
                job_output,
                label="browser-eval job output directory",
            )
            != job_output_identity
            or directory_ancestry_binding(
                job_output.absolute(), label="browser-eval job output directory"
            ) != job_output_ancestry
        ):
            raise ContractError("browser-eval output authority changed")
        run_identity = directory_identity(
            expected_run_dir,
            label="browser-eval run directory",
        )
        if (
            not isinstance(run_dir, Path)
            or run_dir.resolve() != expected_run_dir.resolve()
            or run_identity is None
        ):
            raise ContractError("browser-eval returned an unowned run directory")
        run_ancestry = directory_ancestry_binding(
            expected_run_dir.absolute(), label="browser-eval run directory"
        )
        returned = _project_browser_eval_summary(
            summary,
            job_id=job_id,
            requested_ids=list(evaluators),
        )
        try:
            initial_saved_bindings = _browser_eval_saved_bindings(
                expected_run_dir, list(evaluators), maximum=MAX_SAVED_JSON_BYTES
            )
        except ContractError:
            raise ContractError("browser-eval saved run is unavailable") from None
        summary_path = expected_run_dir / "summary.json"
        try:
            published_snapshot = read_bounded_control_snapshot_result(
                summary_path,
                maximum=MAX_SAVED_JSON_BYTES,
                label="browser-eval saved summary",
                require_single_link=True,
            )
            if published_snapshot.state != "complete" or published_snapshot.body is None:
                raise ContractError("browser-eval saved run is unavailable")
            published_summary = decode_strict_json_bytes(
                published_snapshot.body, label="browser-eval saved summary"
            )
            published = _project_browser_eval_summary(
                published_summary,
                job_id=job_id,
                requested_ids=list(evaluators),
            )
        except ContractError:
            raise ContractError("browser-eval saved run is unavailable") from None
        if published != returned:
            raise ContractError("browser-eval saved run disagrees with returned summary")
        try:
            saved_summary = load_or_build_summary(expected_run_dir)
        except (OSError, ValueError, TypeError, OverflowError, RecursionError, ContractError):
            raise ContractError("browser-eval saved run is unavailable") from None
        saved = _project_browser_eval_summary(
            saved_summary,
            job_id=job_id,
            requested_ids=list(evaluators),
        )
        if saved != returned:
            raise ContractError("browser-eval saved run disagrees with returned summary")
        try:
            final_snapshot = read_bounded_control_snapshot_result(
                summary_path,
                maximum=MAX_SAVED_JSON_BYTES,
                label="browser-eval saved summary",
                require_single_link=True,
            )
        except ContractError:
            raise ContractError("browser-eval saved run is unavailable") from None
        if final_snapshot != published_snapshot:
            raise ContractError("browser-eval saved run changed during validation")
        try:
            final_saved_bindings = _browser_eval_saved_bindings(
                expected_run_dir, list(evaluators), maximum=MAX_SAVED_JSON_BYTES
            )
        except ContractError:
            raise ContractError("browser-eval saved run is unavailable") from None
        if final_saved_bindings != initial_saved_bindings:
            raise ContractError("browser-eval saved run changed during validation")
        # The evaluator inventory can outlast the summary read above. Bind the
        # returned receipt to the saved summary again after that bounded scan.
        try:
            return_snapshot = read_bounded_control_snapshot_result(
                summary_path,
                maximum=MAX_SAVED_JSON_BYTES,
                label="browser-eval saved summary",
                require_single_link=True,
            )
        except ContractError:
            raise ContractError("browser-eval saved run is unavailable") from None
        if return_snapshot != published_snapshot:
            raise ContractError("browser-eval saved run changed during validation")
        if (
            directory_identity(fleet_runs, label="browser-eval output root")
            != fleet_runs_identity
            or directory_ancestry_binding(
                fleet_runs.absolute(), label="browser-eval output root"
            ) != fleet_runs_ancestry
            or directory_identity(job_output, label="browser-eval job output directory")
            != job_output_identity
            or directory_ancestry_binding(
                job_output.absolute(), label="browser-eval job output directory"
            ) != job_output_ancestry
            or directory_identity(expected_run_dir, label="browser-eval run directory")
            != run_identity
            or directory_ancestry_binding(
                expected_run_dir.absolute(), label="browser-eval run directory"
            ) != run_ancestry
        ):
            raise ContractError("browser-eval output authority changed")
        return saved
    if kind == "browser-fact-capture":
        if set(payload) != {
            "session_id",
            "snapshot_id",
            "timeout_seconds",
            "target_url",
        }:
            raise ContractError("browser-fact-capture payload fields are invalid")
        from .browser_facts import capture_browser_fact_from_session

        target_url = payload["target_url"]
        if target_url is not None:
            target_url = _require_bounded_text(
                target_url, "browser-fact-capture target url", 16_384
            )
        # Every identifier is checked for shape before anything touches the
        # filesystem, so a malformed field is refused on its own terms rather
        # than surviving until some earlier lookup happens to fail first.
        snapshot_id = _require_run_id(payload["snapshot_id"], "snapshot id")
        timeout_seconds = _require_timeout(
            payload["timeout_seconds"],
            "browser-fact-capture timeout",
            maximum=120,
        )
        return capture_browser_fact_from_session(
            _session_path(workspace, payload["session_id"]),
            snapshot_id=snapshot_id,
            timeout_seconds=timeout_seconds,
            target_url=target_url,
        )
    if kind == "evidence-pack":
        evidence_pack_fields = {
            "session_id",
            "pack_id",
            "browser_fact_id",
            "transport_fingerprint_id",
            "http2_fingerprint_id",
            "include_session_copy",
        }
        if set(payload) not in {
            frozenset(evidence_pack_fields),
            frozenset({*evidence_pack_fields, "http2_evidence_id"}),
        }:
            raise ContractError("evidence-pack payload fields are invalid")
        from .evidence_pack import build_evidence_pack

        fact_id = payload["browser_fact_id"]
        transport_id = payload["transport_fingerprint_id"]
        http2_id = payload["http2_fingerprint_id"]
        http2_evidence_id = payload.get("http2_evidence_id")
        if not isinstance(payload["include_session_copy"], bool):
            raise ContractError(
                "evidence-pack include-session-copy flag must be boolean"
            )
        session_id = _require_run_id(payload["session_id"], "session id")
        pack_id = _require_portable_output_id(payload["pack_id"], "pack id")
        if pack_id.endswith("."):
            raise ContractError("leased job pack id is invalid")
        for identifier, label in (
            (fact_id, "browser fact id"),
            (transport_id, "transport fingerprint id"),
            (http2_id, "HTTP/2 fingerprint id"),
            (http2_evidence_id, "HTTP/2 evidence id"),
        ):
            if identifier is not None:
                _require_run_id(identifier, label)
        fact_path = None
        if fact_id is not None:
            fact_path = _owned_worker_registry_file(
                workspace,
                registry_name="browser-facts",
                filename=f"{_require_run_id(fact_id, 'browser fact id')}.json",
                label="browser-fact registry",
                unavailable="evidence-pack requested an unknown browser fact",
            )
        transport_path = None
        if transport_id is not None:
            transport_path = _transport_fingerprint_path(
                workspace,
                transport_id,
                label="evidence-pack transport fingerprint",
            )
        http2_path = None
        if http2_id is not None:
            http2_path = _http2_fingerprint_path(
                workspace,
                http2_id,
                label="evidence-pack HTTP/2 fingerprint",
            )
        http2_evidence_path = None
        if http2_evidence_id is not None:
            http2_evidence_path = _http2_evidence_path(
                workspace,
                http2_evidence_id,
                label="evidence-pack evidence",
            )
        return build_evidence_pack(
            session_path=_session_path(workspace, session_id),
            out_dir=workspace / "evidence-packs" / pack_id,
            browser_fact_path=fact_path,
            transport_fingerprint_path=transport_path,
            http2_fingerprint_path=http2_path,
            http2_evidence_path=http2_evidence_path,
            include_session_copy=payload["include_session_copy"],
        )
    if kind == "pinwatch-drift-check":
        fields = {
            "output_id",
            "graph_trace_id",
            "old_baseline_id",
            "new_baseline_id",
            "contract_id",
            "old_runtime_id",
            "new_runtime_id",
            "graph_side",
        }
        if set(payload) != fields:
            raise ContractError("pinwatch-drift-check payload fields are invalid")

        # Validate the complete remote-controlled name population before any
        # filesystem or optional-adapter contact. None is the only omission
        # marker, and runtime attachments are an all-or-nothing pair.
        output_id = _require_run_id(payload["output_id"], "PinWatch output id")
        if output_id.endswith(".") or has_windows_device_basename(output_id):
            raise ContractError("leased job PinWatch output id is invalid")
        graph_trace_id = _require_run_id(
            payload["graph_trace_id"], "PinWatch graph trace id"
        )
        old_baseline_id = _require_run_id(
            payload["old_baseline_id"], "PinWatch old baseline id"
        )
        new_baseline_id = _require_run_id(
            payload["new_baseline_id"], "PinWatch new baseline id"
        )
        optional_ids: dict[str, str | None] = {}
        for field, label in (
            ("contract_id", "PinWatch contract id"),
            ("old_runtime_id", "PinWatch old runtime id"),
            ("new_runtime_id", "PinWatch new runtime id"),
        ):
            value = payload[field]
            optional_ids[field] = (
                None if value is None else _require_run_id(value, label)
            )
        if (optional_ids["old_runtime_id"] is None) != (
            optional_ids["new_runtime_id"] is None
        ):
            raise ContractError(
                "pinwatch-drift-check requires both runtime ids or neither"
            )
        graph_side = payload["graph_side"]
        if not isinstance(graph_side, str) or graph_side not in {"old", "new", "none"}:
            raise ContractError("pinwatch-drift-check graph side is invalid")

        workspace = _worker_workspace_path(workspace)
        pinwatch_root = workspace / "webre-pinwatch"
        require_owned_directory_ancestors(
            pinwatch_root, label="PinWatch worker registry"
        )
        pinwatch_root_identity = directory_identity(
            pinwatch_root,
            label="PinWatch worker registry",
        )
        if pinwatch_root_identity is None:
            raise ContractError("PinWatch worker registry is unavailable")
        pinwatch_root_ancestry = directory_ancestry_binding(
            pinwatch_root.absolute(), label="PinWatch worker registry"
        )
        source_paths: dict[str, Path | None] = {
            "graph_trace": (
                pinwatch_root / "traces" / f"{graph_trace_id}.jsonl"
            ),
            "old_baseline": (
                pinwatch_root / "baselines" / f"{old_baseline_id}.json"
            ),
            "new_baseline": (
                pinwatch_root / "baselines" / f"{new_baseline_id}.json"
            ),
            "contract": (
                None
                if optional_ids["contract_id"] is None
                else pinwatch_root
                / "contracts"
                / f"{optional_ids['contract_id']}.json"
            ),
            "old_runtime": (
                None
                if optional_ids["old_runtime_id"] is None
                else pinwatch_root
                / "runtimes"
                / f"{optional_ids['old_runtime_id']}.json"
            ),
            "new_runtime": (
                None
                if optional_ids["new_runtime_id"] is None
                else pinwatch_root
                / "runtimes"
                / f"{optional_ids['new_runtime_id']}.json"
            ),
        }
        registry_identities: dict[Path, tuple[int, int, int, int]] = {}
        source_snapshots: dict[str, BoundedControlSnapshot] = {}
        for role, source_path in source_paths.items():
            if source_path is None:
                continue
            require_owned_directory_ancestors(
                source_path.parent, label="PinWatch source registry"
            )
            parent_identity = directory_identity(
                source_path.parent,
                label="PinWatch source registry",
            )
            if parent_identity is None:
                raise ContractError("PinWatch source registry is unavailable")
            registry_identities[source_path.parent] = parent_identity
            source_snapshots[role] = _pinwatch_source_snapshot(
                source_path,
                label=f"PinWatch {role.replace('_', ' ')}",
                require_json=role != "graph_trace",
            )

        adapter = _load_webre_pinwatch_adapter()
        flows_root = pinwatch_root / "flows"
        prepare_owned_directory_parent(flows_root, label="PinWatch flow registry")
        require_owned_directory_ancestors(flows_root, label="PinWatch flow registry")
        flows_root_identity = directory_identity(
            flows_root,
            label="PinWatch flow registry",
        )
        if flows_root_identity is None:
            raise ContractError("PinWatch flow registry is unavailable")
        flows_root_ancestry = directory_ancestry_binding(
            flows_root.absolute(), label="PinWatch flow registry"
        )
        output_dir = flows_root / output_id
        if os.path.lexists(output_dir):
            raise ContractError("PinWatch output id already exists")

        run_flow = adapter["run"]
        receipt = run_flow(
            source_paths["graph_trace"],
            source_paths["old_baseline"],
            source_paths["new_baseline"],
            output_dir,
            contract_path=source_paths["contract"],
            old_runtime_path=source_paths["old_runtime"],
            new_runtime_path=source_paths["new_runtime"],
            graph_side=graph_side,
        )
        if (
            directory_ancestry_binding(
                pinwatch_root.absolute(), label="PinWatch worker registry"
            ) != pinwatch_root_ancestry
            or directory_ancestry_binding(
                flows_root.absolute(), label="PinWatch flow registry"
            ) != flows_root_ancestry
        ):
            raise ContractError("PinWatch output authority changed")
        output_identity = directory_identity(
            output_dir,
            label="PinWatch flow output",
        )
        if output_identity is None:
            raise ContractError("PinWatch flow output was not published")
        output_ancestry = directory_ancestry_binding(
            output_dir.absolute(), label="PinWatch flow output"
        )
        initial_inventory = inventory_bounded_json_directory(
            output_dir,
            maximum_entries=5,
            maximum_files=5,
            maximum_file_bytes=MAX_PINWATCH_SOURCE_BYTES,
            maximum_total_bytes=MAX_PINWATCH_OUTPUT_BYTES,
            label="PinWatch flow output",
            require_json_only=True,
        )
        if (
            initial_inventory.state != "complete"
            or {name for name, _identity in initial_inventory.files}
            != PINWATCH_OUTPUT_FILENAMES
        ):
            raise ContractError("PinWatch flow output population is invalid")
        initial_bindings = _pinwatch_output_bindings(output_dir)
        validated = adapter["validate"](
            receipt,
            workspace=output_dir,
            graph_trace_path=source_paths["graph_trace"],
            old_baseline_path=source_paths["old_baseline"],
            new_baseline_path=source_paths["new_baseline"],
            contract_path=source_paths["contract"],
            old_runtime_path=source_paths["old_runtime"],
            new_runtime_path=source_paths["new_runtime"],
        )
        if validated != receipt:
            raise ContractError("PinWatch flow validator changed the receipt")
        projected = _project_pinwatch_drift_result(
            receipt,
            job_id=job_id,
            output_id=output_id,
            producer_sha256_16=adapter["producer_sha256_16"],
        )

        for role, source_path in source_paths.items():
            if source_path is None:
                continue
            require_owned_directory_ancestors(
                source_path.parent, label="PinWatch source registry"
            )
            current = _pinwatch_source_snapshot(
                source_path,
                label=f"PinWatch {role.replace('_', ' ')}",
                require_json=role != "graph_trace",
            )
            if current != source_snapshots[role]:
                raise ContractError("PinWatch source population changed")
        if any(
            directory_identity(parent, label="PinWatch source registry")
            != identity
            for parent, identity in registry_identities.items()
        ):
            raise ContractError("PinWatch source registry authority changed")
        if (
            directory_identity(pinwatch_root, label="PinWatch worker registry")
            != pinwatch_root_identity
            or directory_ancestry_binding(
                pinwatch_root.absolute(), label="PinWatch worker registry"
            ) != pinwatch_root_ancestry
            or directory_identity(flows_root, label="PinWatch flow registry")
            != flows_root_identity
            or directory_ancestry_binding(
                flows_root.absolute(), label="PinWatch flow registry"
            ) != flows_root_ancestry
            or directory_identity(output_dir, label="PinWatch flow output")
            != output_identity
            or directory_ancestry_binding(
                output_dir.absolute(), label="PinWatch flow output"
            ) != output_ancestry
        ):
            raise ContractError("PinWatch output authority changed")
        final_inventory = inventory_bounded_json_directory(
            output_dir,
            maximum_entries=5,
            maximum_files=5,
            maximum_file_bytes=MAX_PINWATCH_SOURCE_BYTES,
            maximum_total_bytes=MAX_PINWATCH_OUTPUT_BYTES,
            label="PinWatch flow output",
            require_json_only=True,
        )
        if (
            final_inventory != initial_inventory
            or {name for name, _identity in final_inventory.files}
            != PINWATCH_OUTPUT_FILENAMES
        ):
            raise ContractError("PinWatch flow output population changed")
        if _pinwatch_output_bindings(output_dir) != initial_bindings:
            raise ContractError("PinWatch flow output population changed")
        return projected
    if kind == "multi-identity-ops":
        fields = {
            "executable",
            "count",
            "persona_ids",
            "headless",
            "parallel",
            "network_auto",
            "network_route_id",
            "device_class",
        }
        if set(payload) != fields:
            raise ContractError("multi-identity-ops payload fields are invalid")
        count = payload["count"]
        parallel = payload["parallel"]
        if (
            isinstance(count, bool)
            or not isinstance(count, int)
            or not 1 <= count <= MAX_TYPED_OPS_IDENTITIES
        ):
            raise ContractError("multi-identity-ops count is invalid")
        if (
            isinstance(parallel, bool)
            or not isinstance(parallel, int)
            or not 1 <= parallel <= min(count, MAX_TYPED_OPS_IDENTITIES)
        ):
            raise ContractError("multi-identity-ops parallel is invalid")
        for key in ("headless", "network_auto"):
            if type(payload[key]) is not bool:
                raise ContractError(f"multi-identity-ops {key} flag is invalid")
        device_class = payload["device_class"]
        if not isinstance(device_class, str) or device_class not in {"desktop", "mobile", "tablet"}:
            raise ContractError("multi-identity-ops device class is invalid")
        persona_ids = payload["persona_ids"]
        if persona_ids is not None:
            if (
                not isinstance(persona_ids, list)
                or len(persona_ids) != count
                or not all(
                    isinstance(value, str) and RUN_ID_RE.fullmatch(value)
                    for value in persona_ids
                )
                or len(set(persona_ids)) != len(persona_ids)
            ):
                raise ContractError("multi-identity-ops persona ids are invalid")
        route_id = payload["network_route_id"]
        if route_id is not None:
            route_id = _require_run_id(route_id, "network route id")
        if payload["network_auto"] and route_id is not None:
            raise ContractError(
                "multi-identity-ops network route controls are ambiguous"
            )
        executable = _require_workspace_file(
            payload["executable"], workspace, "multi-identity-ops executable"
        )
        fleet_root = _prepare_worker_output_root(
            workspace, "fleet-ops", label="multi-identity-ops output root"
        )
        fleet_root_identity = directory_identity(
            fleet_root,
            label="multi-identity-ops output root",
        )
        if fleet_root_identity is None:
            raise ContractError("multi-identity-ops output root is unavailable")
        fleet_root_ancestry = directory_ancestry_binding(
            fleet_root.absolute(), label="multi-identity-ops output root"
        )
        expected_out = fleet_root / job_id
        if (
            directory_identity(
                expected_out,
                label="multi-identity-ops output directory",
            )
            is not None
        ):
            raise ContractError("multi-identity-ops output directory already exists")
        require_owned_directory_ancestors(fleet_root, label="multi-identity-ops output root")
        if (
            directory_identity(fleet_root, label="multi-identity-ops output root")
            != fleet_root_identity
            or directory_ancestry_binding(
                fleet_root.absolute(), label="multi-identity-ops output root"
            ) != fleet_root_ancestry
        ):
            raise ContractError("multi-identity-ops output authority changed")
        try:
            expected_out.mkdir()
        except FileExistsError:
            raise ContractError(
                "multi-identity-ops output directory already exists"
            ) from None
        except OSError:
            raise ContractError(
                "multi-identity-ops output directory could not be created"
            ) from None
        expected_out_identity = directory_identity(
            expected_out,
            label="multi-identity-ops output directory",
        )
        if (
            expected_out_identity is None
            or directory_identity(
                fleet_root,
                label="multi-identity-ops output root",
            )
            != fleet_root_identity
            or directory_ancestry_binding(
                fleet_root.absolute(), label="multi-identity-ops output root"
            ) != fleet_root_ancestry
        ):
            raise ContractError("multi-identity-ops output authority changed")
        expected_out_ancestry = directory_ancestry_binding(
            expected_out.absolute(), label="multi-identity-ops output directory"
        )
        require_owned_directory_ancestors(
            expected_out, label="multi-identity-ops output directory"
        )
        from .multi_identity_ops import run_ops_coherence_cohort

        report = run_ops_coherence_cohort(
            workspace,
            count=count,
            persona_ids=persona_ids,
            executable=executable,
            repository_root=repository_root.resolve(),
            evaluators="controlled_coherence",
            headless=payload["headless"],
            network_auto=payload["network_auto"],
            network_route_id=route_id,
            device_class=device_class,
            batch_id=f"fleet-{job_id}",
            out_dir=expected_out,
            parallel=parallel,
        )
        if (
            directory_identity(
                fleet_root,
                label="multi-identity-ops output root",
            )
            != fleet_root_identity
            or directory_ancestry_binding(
                fleet_root.absolute(), label="multi-identity-ops output root"
            ) != fleet_root_ancestry
            or directory_identity(
                expected_out,
                label="multi-identity-ops output directory",
            )
            != expected_out_identity
            or directory_ancestry_binding(
                expected_out.absolute(), label="multi-identity-ops output directory"
            ) != expected_out_ancestry
        ):
            raise ContractError("multi-identity-ops output authority changed")
        return _project_multi_identity_ops_report(
            report,
            job_id=job_id,
            expected_count=count,
            expected_headless=payload["headless"],
            expected_parallel=parallel,
            expected_network_auto=payload["network_auto"],
        )
    raise ContractError("leased job kind is not implemented by the typed worker")


def _require_run_id(value: Any, label: str) -> str:
    """Accept an identifier, never a path.

    A leased payload is the one place a remote principal chooses a filename, and
    this control plane refuses `shell` precisely so that a job cannot become
    arbitrary local action. Identifiers are resolved inside the workspace; RUN_ID_RE
    admits no separator and cannot begin with a dot, so no payload can walk out of
    it.
    """
    if not isinstance(value, str) or not RUN_ID_RE.fullmatch(value):
        raise ContractError(f"leased job {label} is invalid")
    return value


def _require_portable_output_id(value: Any, label: str) -> str:
    identifier = _require_run_id(value, label)
    if has_windows_device_basename(identifier):
        raise ContractError(f"leased job {label} is invalid")
    return identifier


def _pinwatch_source_snapshot(
    path: Path,
    *,
    label: str,
    require_json: bool,
) -> BoundedControlSnapshot:
    snapshot = read_bounded_control_snapshot_result(
        path,
        maximum=MAX_PINWATCH_SOURCE_BYTES,
        label=label,
        require_single_link=True,
    )
    if snapshot.state != "complete" or snapshot.body is None:
        raise ContractError(f"{label} is unavailable")
    if require_json:
        document = decode_strict_json_bytes(snapshot.body, label=label)
        if not isinstance(document, dict):
            raise ContractError(f"{label} must contain a JSON object")
    return snapshot


def _browser_eval_saved_bindings(
    run_dir: Path,
    evaluator_ids: list[str],
    *,
    maximum: int,
) -> tuple[BoundedJsonDirectoryInventory, dict[str, dict[str, Any]]]:
    """Bind the fresh manifest and exact evaluator files around saved-run validation."""
    from .perfetto import _stable_file_binding

    evaluator_dir = run_dir / "evaluators"
    inventory = inventory_bounded_json_directory(
        evaluator_dir,
        maximum_entries=len(evaluator_ids),
        maximum_files=len(evaluator_ids),
        maximum_file_bytes=maximum,
        maximum_total_bytes=maximum * len(evaluator_ids),
        label="browser-eval saved evaluators",
        require_json_only=True,
    )
    if (
        inventory.state != "complete"
        or {name for name, _identity in inventory.files}
        != {f"{evaluator_id}.json" for evaluator_id in evaluator_ids}
    ):
        raise ContractError("browser-eval saved evaluator population is invalid")
    bindings = {
        "manifest.json": _stable_file_binding(
            run_dir / "manifest.json",
            label="browser-eval saved manifest",
            maximum=maximum,
        )
    }
    for evaluator_id in sorted(evaluator_ids):
        filename = f"{evaluator_id}.json"
        bindings[filename] = _stable_file_binding(
            evaluator_dir / filename,
            label="browser-eval saved evaluator",
            maximum=maximum,
        )
    return inventory, bindings


def _pinwatch_output_bindings(output_dir: Path) -> dict[str, dict[str, Any]]:
    """Bind each validated output body across the dependency validator call."""
    from .perfetto import _stable_file_binding

    return {
        name: _stable_file_binding(
            output_dir / name,
            label="PinWatch flow output",
            maximum=MAX_PINWATCH_SOURCE_BYTES,
        )
        for name in sorted(PINWATCH_OUTPUT_FILENAMES)
    }


def _load_webre_pinwatch_adapter() -> dict[str, Any]:
    try:
        from webre import drift_flow as module
    except Exception:
        raise ContractError(
            "the reviewed WebRE PinWatch adapter is unavailable"
        ) from None
    run_flow = getattr(module, "run_pin_drift_flow", None)
    validate_flow = getattr(module, "validate_pin_drift_flow_receipt", None)
    module_path_value = getattr(module, "__file__", None)
    if (
        getattr(module, "DRIFT_FLOW_SCHEMA", None) != "webre.pin-drift-flow/1"
        or not callable(run_flow)
        or not callable(validate_flow)
        or not isinstance(module_path_value, str)
    ):
        raise ContractError("the reviewed WebRE PinWatch API is incompatible")
    module_snapshot = read_bounded_control_snapshot_result(
        Path(module_path_value).absolute(),
        maximum=4 * 1024 * 1024,
        label="WebRE PinWatch entry module",
    )
    if module_snapshot.state != "complete" or module_snapshot.body is None:
        raise ContractError("the reviewed WebRE PinWatch entry module is unavailable")
    return {
        "run": run_flow,
        "validate": validate_flow,
        "producer_sha256_16": hashlib.sha256(module_snapshot.body).hexdigest()[:16],
    }


def _require_bounded_text(value: Any, label: str, maximum: int) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value.encode("utf-8", errors="surrogatepass")) > maximum
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise ContractError(f"leased job {label} is invalid")
    try:
        value.encode("utf-8", errors="strict")
    except UnicodeEncodeError:
        raise ContractError(f"leased job {label} is invalid") from None
    return value


def _worker_workspace_path(workspace: Path) -> Path:
    """Keep the caller's workspace path lexical so links cannot redefine its root."""
    root = Path(os.path.abspath(workspace))
    for ancestor in reversed((root, *root.parents)):
        directory_identity(ancestor, label="typed worker workspace")
    return root


def _prepare_worker_output_root(workspace: Path, name: str, *, label: str) -> Path:
    root = _worker_workspace_path(workspace) / name
    prepare_owned_directory_parent(root, label=label)
    require_owned_directory_ancestors(root, label=label)
    return root


def _owned_worker_registry_file(
    workspace: Path,
    *,
    registry_name: str,
    filename: str,
    label: str,
    unavailable: str,
) -> Path:
    registry = _worker_workspace_path(workspace) / registry_name
    if directory_identity(registry, label=label) is None:
        raise ContractError(unavailable)
    require_owned_directory_ancestors(registry, label=label)
    path = registry / filename
    try:
        metadata = os.lstat(path)
    except FileNotFoundError:
        raise ContractError(unavailable) from None
    except OSError:
        raise ContractError(f"{label} file inspection failed") from None
    if (
        not stat.S_ISREG(metadata.st_mode)
        or bool(getattr(metadata, "st_file_attributes", 0) & 0x400)
        or metadata.st_nlink != 1
    ):
        raise ContractError(unavailable)
    return path


def _transport_fingerprint_path(
    workspace: Path,
    fingerprint_id: Any,
    *,
    label: str,
) -> Path:
    identifier = _require_run_id(fingerprint_id, f"transport {label} id")
    return _owned_worker_registry_file(
        workspace,
        registry_name="transport-fingerprints",
        filename=f"{identifier}.json",
        label="transport fingerprint registry",
        unavailable=f"transport-check requested an unknown {label}",
    )


def _transport_baseline_path(workspace: Path, baseline_id: str) -> Path:
    return _owned_worker_registry_file(
        workspace,
        registry_name="transport-fingerprints",
        filename=f"{baseline_id}.baseline.json",
        label="transport fingerprint registry",
        unavailable="transport-check requested an unknown baseline",
    )


def _http2_fingerprint_path(
    workspace: Path,
    fingerprint_id: Any,
    *,
    label: str,
) -> Path:
    identifier = _require_run_id(fingerprint_id, f"{label} id")
    return _owned_worker_registry_file(
        workspace,
        registry_name="http2-fingerprints",
        filename=f"{identifier}.json",
        label="HTTP/2 fingerprint registry",
        unavailable=f"{label} is unknown",
    )


def _http2_baseline_path(workspace: Path, baseline_id: str) -> Path:
    return _owned_worker_registry_file(
        workspace,
        registry_name="http2-fingerprints",
        filename=f"{baseline_id}.baseline.json",
        label="HTTP/2 fingerprint registry",
        unavailable="http2-check requested an unknown baseline",
    )


def _http2_evidence_path(
    workspace: Path,
    evidence_id: Any,
    *,
    label: str,
) -> Path:
    identifier = _require_run_id(evidence_id, f"HTTP/2 evidence {label} id")
    return _owned_worker_registry_file(
        workspace,
        registry_name="http2-evidence",
        filename=f"{identifier}.json",
        label="HTTP/2 evidence registry",
        unavailable=f"HTTP/2 evidence {label} is unknown",
    )


def _http2_evidence_baseline_path(workspace: Path, baseline_id: str) -> Path:
    return _owned_worker_registry_file(
        workspace,
        registry_name="http2-evidence",
        filename=f"{baseline_id}.baseline.json",
        label="HTTP/2 evidence registry",
        unavailable="http2-evidence-check requested an unknown baseline",
    )


def _require_timeout(value: Any, label: str, *, maximum: int) -> float:
    if (
        type(maximum) is not int
        or not 1 <= maximum <= 3_600
        or not is_finite_number(value)
        or not 0 < value <= maximum
    ):
        raise ContractError(
            f"leased job {label} must be finite and in (0, {maximum}]"
        )
    return float(value)


def _require_workspace_file(value: Any, workspace: Path, label: str) -> Path:
    raw = _require_bounded_text(value, label, 32_768)
    workspace_root = _worker_workspace_path(workspace)
    requested = Path(os.path.abspath(raw))
    try:
        requested.relative_to(workspace_root)
    except ValueError:
        raise ContractError(
            f"leased job {label} must be inside the worker workspace"
        ) from None
    require_owned_directory_ancestors(
        requested.parent, label=f"leased job {label} parent"
    )
    try:
        metadata = os.lstat(requested)
    except FileNotFoundError:
        raise ContractError(f"leased job {label} is not a file") from None
    except OSError:
        raise ContractError(f"leased job {label} file inspection failed") from None
    if (
        not stat.S_ISREG(metadata.st_mode)
        or bool(getattr(metadata, "st_file_attributes", 0) & 0x400)
        or metadata.st_nlink != 1
    ):
        raise ContractError(f"leased job {label} must be an owned regular file")
    resolved = requested.resolve()
    try:
        resolved.relative_to(workspace_root)
    except ValueError:
        raise ContractError(
            f"leased job {label} must be inside the worker workspace"
        ) from None
    require_owned_directory_ancestors(
        requested.parent, label=f"leased job {label} parent"
    )
    return resolved


def _failure_receipt(error: Exception) -> dict[str, Any]:
    try:
        diagnostic = str(error).encode("utf-8", errors="replace")
    except Exception:
        # Failure reporting must still complete when a dependency supplies a
        # broken exception formatter. The fallback reveals no exception args.
        diagnostic = type(error).__name__.encode("utf-8", errors="replace")
    return {
        "error_type": type(error).__name__,
        "message": (
            "typed job contract rejected"
            if isinstance(error, ContractError)
            else "typed job execution failed"
        ),
        "diagnostic_sha256_16": hashlib.sha256(diagnostic).hexdigest()[:16],
    }


def _session_path(workspace: Path, session_id: Any) -> Path:
    validated_id = _require_run_id(session_id, "session id")
    return _owned_worker_registry_file(
        workspace,
        registry_name="sessions",
        filename=f"{validated_id}.json",
        label="worker session registry",
        unavailable="leased job requested an unknown session",
    )


def run_worker_once(
    store: ControlStore,
    worker: WorkerPrincipal,
    *,
    repository_root: Path,
    workspace: Path,
    lease_seconds: int = 120,
) -> dict[str, Any] | None:
    job = store.lease_job(worker, lease_seconds=lease_seconds)
    if job is None:
        return None
    lease_token = job.pop("lease_token")
    try:
        result = execute_typed_job(
            job, repository_root=repository_root, workspace=workspace
        )
    except Exception as exc:
        failure = _failure_receipt(exc)
        return store.complete_job(
            worker, job["id"], lease_token, succeeded=False, result=failure
        )
    return store.complete_job(
        worker, job["id"], lease_token, succeeded=True, result=result
    )


def run_remote_worker_once(
    client: ControlClient,
    *,
    repository_root: Path,
    workspace: Path,
    lease_seconds: int = 120,
) -> dict[str, Any] | None:
    leased = client.worker_lease(lease_seconds=lease_seconds)
    if leased is None:
        return None
    job = dict(leased)
    lease_token = job.pop("lease_token", None)
    try:
        lease_token = _lease_token(lease_token)
        job_id = _require_run_id(job.get("id"), "job id")
    except ContractError:
        raise ContractError("remote worker lease response is invalid") from None
    try:
        result = execute_typed_job(
            job, repository_root=repository_root, workspace=workspace
        )
    except Exception as exc:
        failure = _failure_receipt(exc)
        return client.worker_complete(
            job_id, lease_token, succeeded=False, result=failure
        )
    return client.worker_complete(job_id, lease_token, succeeded=True, result=result)
