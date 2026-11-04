"""Redacted evidence packs composing existing Core contracts for WebRE intake.

Portable output never includes cookies, proxy credentials, CDP endpoints, or
sensor material. Session digests, optional trace-export receipts, and optional
browser-fact snapshots are bound by full SHA-256.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import stat
import tempfile
import uuid
from contextlib import closing
from datetime import datetime, timezone
from itertools import islice
from pathlib import Path
from typing import Any, Callable

from .browser_facts import build_browser_fact_snapshot, validate_browser_fact_snapshot
from .control_files import (
    canonical_json_bytes,
    decode_strict_json_bytes,
    publish_bytes_exclusive,
    read_bounded_control_snapshot_result,
    remove_control_conditionally,
)
from .contracts import ContractError, load_session_snapshot, reject_sensitive_keys
from .owned_paths import (
    DirectoryIdentity,
    directory_ancestry_binding,
    directory_identity,
    prepare_owned_directory_parent,
    remove_owned_directory_tree,
)
from .numeric import is_finite_number
from .profiles import has_windows_device_basename
from .product_observation import (
    BASELINE_SCHEMA,
    COMPARISON_SCHEMA,
    DRIFT_SCHEMA,
    HOOK_MODES,
    OBSERVATION_SCHEMA,
    RESOURCE_INTENT_CONTRACTS,
    SUBTRACTION_SCHEMA,
    _browser_build_method,
    _driver_metadata,
    _declared_url_metadata,
    _observation_stage_routes,
    _prelude_document_metadata,
    _project_public_url_shape,
    _ready_expression_metadata,
    _reconciled_script_identity,
    _reconciled_subtraction_script_identity,
    _sanitize_ambient_input_report,
    _sanitize_await_report,
    _sanitize_capture_provenance,
    _sanitize_input_probe_report,
    _sanitize_offline_guard,
    _sanitize_request_activity_report,
    _sanitize_request_activity_baseline,
    _sanitize_rehost_contract,
    _sanitize_resource_intent_report,
    _sanitize_script_execution_summary,
    _sanitize_source_provenance,
    _sanitize_startup_document,
    _surface_method,
    _verified_baseline_noise_floor,
    _verified_baseline_receipt,
    _verified_baseline_source_subtraction_lineage,
    _verified_baseline_surface,
    _verified_decision_input_lineage,
    _verified_decision_receipt,
    _verified_decision_semantics,
    _verified_observation_receipt,
    _verified_subtraction_receipt,
    _stored_driver_result_metadata,
    project_product_script_analysis_boundary,
    project_product_script_vendor_hint,
    project_server_request_activity,
)
from .perfetto import validate_trace_export_report
from .http2_fingerprint import validate_http2_fingerprint
from .http2_headers import validate_http2_capture_evidence
from .trace import MAX_TRACE_BYTES, iter_trace, validate_trace
from .trace_scopes import (
    TRACE_CATEGORY_CONTRACTS,
    TRACE_SCOPES,
    valid_trace_categories,
)
from .transport_fingerprint import validate_transport_fingerprint
from .windows_change_time import windows_change_time

EVIDENCE_PACK_SCHEMA = "browser-core.evidence-pack/1"
EVIDENCE_PACK_MANIFEST = "manifest.json"
MAX_EVIDENCE_PACK_MANIFEST_BYTES = 2 * 1024 * 1024
MAX_EVIDENCE_PACK_JSON_ARTIFACT_BYTES = 16 * 1024 * 1024
MAX_EVIDENCE_PACK_BROWSER_FACT_SOURCE_BYTES = 1024 * 1024
MAX_EVIDENCE_PACK_TRANSPORT_SOURCE_BYTES = 2 * 1024 * 1024
MAX_EVIDENCE_PACK_HTTP2_SOURCE_BYTES = 1024 * 1024
MAX_EVIDENCE_PACK_HTTP2_EVIDENCE_SOURCE_BYTES = 1024 * 1024
MAX_EVIDENCE_PACK_TRACE_EXPORT_SOURCE_BYTES = 16 * 1024 * 1024
MAX_EVIDENCE_PACK_OBSERVATION_SOURCE_BYTES = 64 * 1024 * 1024
MAX_EVIDENCE_PACK_TRACE_JSONL_BYTES = 1024 * 1024 * 1024
MAX_EVIDENCE_PACK_DIRECTORY_ENTRIES = 16
WEBRE_INTAKE_NOTE = (
    "Bind this pack into WebRE via existing evidence-graph inputs: a stopped "
    "Browser Core session summary (run/revision/trace_scope/category contract), "
    "optional browser-core.trace-export/1 digests plus normalized JSONL, and "
    "optional browser-core.browser-fact-snapshot/1. See webre/docs/EVIDENCE_GRAPH.md. "
    "Do not feed raw CDP endpoints or profile paths into portable graphs."
)
PORTABLE_OBSERVATION_KEYS = {
    "schema",
    "label",
    "script_sha256_16",
    "control_script_sha256_16",
    "source_arm_label",
    "capture_provenance",
    "control_capture_provenance",
    "capture_provenance_population",
    "script_bytes",
    "api_name_count",
    "surface_sha256",
    "baseline_receipt_sha256",
    "source_subtraction_receipt_population",
    "source_subtraction_lineage",
    "source_subtraction_receipts_complete",
    "subtraction_receipt_sha256",
    "observation_receipt_sha256",
    "arm_observation_receipt_sha256",
    "control_observation_receipt_sha256",
    "input_observation_receipts_complete",
    "input_observation_receipts_comparable",
    "arms",
    "volatile_api_name_count",
    "pairwise_differences",
    "measured_noise_floor",
    "looks_like_built_antibot_script",
    "vendor_hint",
    "analysis_boundary",
    "trace_scope",
    "trace_category_contract",
    "chromium_revision",
    "run_id",
    "dwell_seconds",
    "timeout_seconds",
    "inline_script",
    "reloads",
    "attributed_api_names",
    "script_attribution_comparable",
    "hook_mode",
    "hook_target_names",
    "control_label",
    "clean_subtraction",
    "ready_probe_comparable",
    "arm_control_method_comparable",
    "driver_execution_complete",
    "script_identity_coherent",
    "trace_evidence_coherent",
    "await_method_comparable",
    "arm_readiness_satisfied",
    "input_method_comparable",
    "ambient_input_clean",
    "collector_started",
    "collector_startup_coherent",
    "control_collector_startup_coherent",
    "startup_derivation_coherent",
    "rehost_dependencies_complete",
    "control_rehost_dependencies_complete",
    "rehost_receipts_coherent",
    "request_activity_receipts_coherent",
    "page_load_execution_coherent",
    "surface_claim_ready",
    "offline_guard_comparable",
    "offline_guard",
    "rehost_contract",
    "browser_build",
    "provenance",
    "await_report",
    "source_provenance",
    "declared_script_url_shape",
    "resource_intent_capture",
    "prelude",
    "driver",
    "driver_result",
    "ready_expression",
    "stage_routes",
    "collector_startup",
    "resource_intents",
    "request_activity",
    "request_activity_baseline",
    "browser_shutdown",
    "control_browser_shutdown",
    "trace_flush",
    "control_trace_flush",
    "script_execution",
    "control_script_execution",
    "diagnostic_script_execution",
    "input_probe",
    "control_input_probe",
    "ambient_input",
    "control_ambient_input",
    "driver_supplied",
    "method",
    "total_events",
    "distinct_api_names",
    "attributable_events",
    "distinct_request_classes",
    "attributable_fraction",
    "request_methods",
    "fetch_target_scope",
    "decision_receipt_sha256",
    "baseline_label",
    "baseline_script_sha256_16",
    "observed_label",
    "observed_script_sha256_16",
    "observed_subtraction_receipt_sha256",
    "input_artifact_receipts_complete",
    "input_artifact_receipts_comparable",
    "same_script",
    "baseline_source_sha256",
    "observed_source_sha256",
    "source_custody_comparable",
    "baseline_control_script_sha256_16",
    "observed_control_script_sha256_16",
    "same_control_script",
    "baseline_capture_status",
    "baseline_control_capture_status",
    "observed_capture_status",
    "observed_control_capture_status",
    "capture_receipts_comparable",
    "baseline_count",
    "observed_count",
    "added",
    "removed",
    "drift",
    "tolerance",
    "tolerance_source",
    "baseline_noise_floor",
    "same_method",
    "method_mismatches",
    "request_activity_drift",
    "passed",
    "pairs",
}


class _EvidencePackArtifactCleanupError(ContractError):
    """An ambiguous staged artifact must be retained for operator inspection."""


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _portable_iso_timestamp(value: Any) -> str | None:
    if not isinstance(value, str) or len(value) > 100:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.utcoffset() is None:
        return None
    return parsed.isoformat().replace("+00:00", "Z")


def _file_identity(metadata: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _sha256_stable_file(
    path: Path,
    *,
    maximum: int,
    label: str,
) -> tuple[str, int]:
    if not isinstance(path, Path):
        raise ContractError(f"evidence pack {label} path must be a Path")
    if (
        isinstance(maximum, bool)
        or not isinstance(maximum, int)
        or not 1 <= maximum <= MAX_EVIDENCE_PACK_TRACE_JSONL_BYTES
    ):
        raise ContractError(f"evidence pack {label} byte limit is invalid")
    digest = hashlib.sha256()
    size = 0
    try:
        path_before = os.lstat(path)
        if (
            not stat.S_ISREG(path_before.st_mode)
            or bool(getattr(path_before, "st_file_attributes", 0) & 0x400)
            or path_before.st_nlink != 1
        ):
            raise ContractError(
                f"evidence pack {label} must be a single-link regular file"
            )
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
    except ContractError:
        raise
    except OSError:
        raise ContractError(f"cannot read evidence pack {label}") from None
    try:
        with os.fdopen(descriptor, "rb", buffering=0) as handle:
            before = os.fstat(handle.fileno())
            if (
                not stat.S_ISREG(before.st_mode)
                or before.st_nlink != 1
                or _file_identity(before) != _file_identity(path_before)
            ):
                raise ContractError(f"evidence pack {label} changed before read")
            if before.st_size > maximum:
                raise ContractError(f"evidence pack {label} exceeds {maximum} bytes")
            change_before = windows_change_time(handle) if os.name == "nt" else None
            while True:
                chunk = handle.read(min(1024 * 1024, maximum + 1 - size))
                if not chunk:
                    break
                size += len(chunk)
                if size > maximum:
                    raise ContractError(
                        f"evidence pack {label} exceeds {maximum} bytes"
                    )
                digest.update(chunk)
            after = os.fstat(handle.fileno())
            change_after = windows_change_time(handle) if os.name == "nt" else None
            if os.name == "nt" and change_before == change_after:
                # Fast same-size edits followed by mtime restoration can also
                # evade one native change-time tick. Rehash this same bounded
                # handle before returning a digest for published bytes.
                handle.seek(0)
                second_digest = hashlib.sha256()
                rechecked = 0
                while rechecked < size:
                    chunk = handle.read(min(1024 * 1024, size - rechecked))
                    if not chunk:
                        break
                    second_digest.update(chunk)
                    rechecked += len(chunk)
                if (rechecked != size or handle.read(1)
                        or second_digest.digest() != digest.digest()):
                    raise ContractError(f"evidence pack {label} changed during read")
                change_after = windows_change_time(handle)
        path_after = os.lstat(path)
    except ContractError:
        raise
    except OSError:
        raise ContractError(f"cannot read evidence pack {label}") from None
    if (
        _file_identity(path_before) != _file_identity(before)
        or _file_identity(before) != _file_identity(after)
        or _file_identity(after) != _file_identity(path_after)
        or size != after.st_size
        or after.st_nlink != 1
        or change_before != change_after
    ):
        raise ContractError(f"evidence pack {label} changed during read")
    return digest.hexdigest(), size


def _cleanup_copied_file(
    destination: Path,
    *,
    expected_identity: tuple[int, int, int, int, int, int] | None,
    expected_parent_ancestry: tuple[DirectoryIdentity, ...],
) -> bool:
    if expected_identity is None:
        try:
            os.lstat(destination)
        except FileNotFoundError:
            return True
        except OSError:
            return False
        return False

    def parent_held() -> bool:
        return (directory_ancestry_binding(destination.parent, label="evidence pack copy parent")
                == expected_parent_ancestry)

    try:
        if not parent_held():
            return False
        observed = os.lstat(destination)
    except FileNotFoundError:
        return True
    except (OSError, ContractError):
        return False
    if (
        _file_identity(observed) != expected_identity
        or not stat.S_ISREG(observed.st_mode)
        or bool(getattr(observed, "st_file_attributes", 0) & 0x400)
    ):
        return False
    quarantine = destination.with_name(
        f".{destination.name}.cleanup-{uuid.uuid4().hex}"
    )
    try:
        if not parent_held():
            return False
        os.rename(destination, quarantine)
        if (
            not parent_held()
            or _file_identity(os.lstat(quarantine)) != expected_identity
        ):
            return False
        if not parent_held():
            return False
        os.unlink(quarantine)
    except (OSError, ContractError):
        return False
    return True


def _copy_stable_file(
    source: Path,
    destination: Path,
    *,
    maximum: int,
    label: str,
) -> tuple[str, int]:
    """Copy one stable, single-link source into a new owned destination."""
    if not isinstance(source, Path) or not isinstance(destination, Path):
        raise ContractError(f"evidence pack {label} paths must be Paths")
    if (
        isinstance(maximum, bool)
        or not isinstance(maximum, int)
        or not 1 <= maximum <= MAX_EVIDENCE_PACK_TRACE_JSONL_BYTES
    ):
        raise ContractError(f"evidence pack {label} byte limit is invalid")
    parent_ancestry = directory_ancestry_binding(
        destination.parent, label="evidence pack copy parent",
    )

    def parent_held() -> bool:
        try:
            return (directory_ancestry_binding(destination.parent, label="evidence pack copy parent")
                    == parent_ancestry)
        except ContractError:
            return False

    digest = hashlib.sha256()
    size = 0
    destination_identity: tuple[int, int, int, int, int, int] | None = None
    try:
        source_before = os.lstat(source)
        if (
            not stat.S_ISREG(source_before.st_mode)
            or bool(getattr(source_before, "st_file_attributes", 0) & 0x400)
            or source_before.st_nlink != 1
        ):
            raise ContractError(
                f"evidence pack {label} must be a single-link regular file"
            )
        if source_before.st_size > maximum:
            raise ContractError(f"evidence pack {label} exceeds {maximum} bytes")
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        source_descriptor = os.open(source, flags)
    except ContractError:
        raise
    except OSError:
        raise ContractError(f"cannot read evidence pack {label}") from None
    try:
        with os.fdopen(source_descriptor, "rb", buffering=0) as input_handle:
            source_open = os.fstat(input_handle.fileno())
            if _file_identity(source_open) != _file_identity(source_before):
                raise ContractError(f"evidence pack {label} changed before copy")
            source_change_before = (
                windows_change_time(input_handle) if os.name == "nt" else None
            )
            if not parent_held():
                raise ContractError("evidence pack copy parent changed before copy")
            with destination.open("xb", buffering=0) as output_handle:
                try:
                    while True:
                        chunk = input_handle.read(min(1024 * 1024, maximum + 1 - size))
                        if not chunk:
                            break
                        size += len(chunk)
                        if size > maximum:
                            raise ContractError(
                                f"evidence pack {label} exceeds {maximum} bytes"
                            )
                        written = output_handle.write(chunk)
                        if type(written) is not int or written != len(chunk):
                            raise ContractError(
                                f"evidence pack {label} staged copy wrote incomplete bytes"
                            )
                        digest.update(chunk)
                    output_handle.flush()
                    os.fsync(output_handle.fileno())
                finally:
                    try:
                        destination_identity = _file_identity(
                            os.fstat(output_handle.fileno())
                        )
                    except OSError:
                        pass
            source_after = os.fstat(input_handle.fileno())
            source_change_after = (
                windows_change_time(input_handle) if os.name == "nt" else None
            )
            if os.name == "nt" and source_change_before == source_change_after:
                # A same-size edit with restored mtime can fit in one Windows
                # change-time tick. Bind the staged bytes to this open source
                # handle before claiming that the copy was stable.
                input_handle.seek(0)
                checked_digest = hashlib.sha256()
                checked_size = 0
                while checked_size < size:
                    chunk = input_handle.read(min(1024 * 1024, size - checked_size))
                    if not chunk:
                        break
                    checked_digest.update(chunk)
                    checked_size += len(chunk)
                if (checked_size != size or input_handle.read(1)
                        or checked_digest.digest() != digest.digest()):
                    raise ContractError(f"evidence pack {label} changed during copy")
                source_after = os.fstat(input_handle.fileno())
                source_change_after = windows_change_time(input_handle)
        source_path_after = os.lstat(source)
    except ContractError as exc:
        if not _cleanup_copied_file(
            destination,
            expected_identity=destination_identity,
            expected_parent_ancestry=parent_ancestry,
        ):
            raise _EvidencePackArtifactCleanupError(
                "evidence pack staged artifact cleanup failed"
            ) from exc
        raise
    except OSError:
        primary = ContractError(f"cannot copy evidence pack {label}")
        if not _cleanup_copied_file(
            destination,
            expected_identity=destination_identity,
            expected_parent_ancestry=parent_ancestry,
        ):
            raise _EvidencePackArtifactCleanupError(
                "evidence pack staged artifact cleanup failed"
            ) from primary
        raise primary from None
    if (
        _file_identity(source_before) != _file_identity(source_open)
        or _file_identity(source_open) != _file_identity(source_after)
        or _file_identity(source_after) != _file_identity(source_path_after)
        or size != source_after.st_size
        or source_after.st_nlink != 1
        or source_change_before != source_change_after
    ):
        primary = ContractError(f"evidence pack {label} changed during copy")
        if not _cleanup_copied_file(
            destination,
            expected_identity=destination_identity,
            expected_parent_ancestry=parent_ancestry,
        ):
            raise _EvidencePackArtifactCleanupError(
                "evidence pack staged artifact cleanup failed"
            ) from primary
        raise primary
    try:
        destination_after = os.lstat(destination)
    except OSError:
        destination_after = None
    if (
        destination_identity is None
        or destination_after is None
        or _file_identity(destination_after) != destination_identity
        or not stat.S_ISREG(destination_after.st_mode)
        or bool(getattr(destination_after, "st_file_attributes", 0) & 0x400)
        or destination_after.st_nlink != 1
        or not parent_held()
    ):
        primary = ContractError(
            f"evidence pack {label} destination changed during copy"
        )
        if not _cleanup_copied_file(
            destination,
            expected_identity=destination_identity,
            expected_parent_ancestry=parent_ancestry,
        ):
            raise _EvidencePackArtifactCleanupError(
                "evidence pack staged artifact cleanup failed"
            ) from primary
        raise primary
    return digest.hexdigest(), size


def _inventory_evidence_pack_directory(
    directory: Path,
) -> tuple[
    tuple[int, int, int, int, int, int],
    tuple[tuple[str, tuple[int, int, int, int, int, int]], ...],
]:
    try:
        root_before = os.lstat(directory)
    except OSError:
        raise ContractError("cannot inventory evidence pack directory") from None
    if not stat.S_ISDIR(root_before.st_mode) or bool(
        getattr(root_before, "st_file_attributes", 0) & 0x400
    ):
        raise ContractError("evidence pack root is not a stable directory")
    try:
        with os.scandir(directory) as iterator:
            entries = sorted(
                islice(iterator, MAX_EVIDENCE_PACK_DIRECTORY_ENTRIES + 1),
                key=lambda entry: (entry.name.casefold(), entry.name),
            )
    except OSError:
        raise ContractError("cannot inventory evidence pack directory") from None
    if len(entries) > MAX_EVIDENCE_PACK_DIRECTORY_ENTRIES:
        raise ContractError("evidence pack directory has too many entries")
    retained: list[tuple[str, tuple[int, int, int, int, int, int]]] = []
    for entry in entries:
        try:
            metadata = os.lstat(entry.path)
        except OSError:
            raise ContractError(
                "evidence pack directory changed during inventory"
            ) from None
        if (
            entry.is_symlink()
            or not stat.S_ISREG(metadata.st_mode)
            or bool(getattr(metadata, "st_file_attributes", 0) & 0x400)
            or metadata.st_nlink != 1
        ):
            raise ContractError(
                "evidence pack directory contains an aliased or irregular entry"
            )
        retained.append((entry.name, _file_identity(metadata)))
    try:
        root_after = os.lstat(directory)
    except OSError:
        raise ContractError(
            "evidence pack directory changed during inventory"
        ) from None
    if _file_identity(root_before) != _file_identity(root_after):
        raise ContractError("evidence pack directory changed during inventory")
    return _file_identity(root_after), tuple(retained)


def _rebind_published_evidence_pack(directory: Path, manifest: dict[str, Any],
                                    manifest_body: bytes) -> None:
    """Recheck published bytes after staged semantic validation and rename."""
    expected: dict[str, tuple[str, int, int]] = {}
    for kind, artifact in manifest["artifacts"].items():
        for binding in (artifact, artifact.get("redacted_copy")):
            if not isinstance(binding, dict) or "file" not in binding:
                continue
            name = binding["file"]
            if name in expected:
                raise ContractError("evidence pack publication has duplicate artifact names")
            maximum = (MAX_EVIDENCE_PACK_TRACE_JSONL_BYTES if kind == "trace_jsonl"
                       else MAX_EVIDENCE_PACK_JSON_ARTIFACT_BYTES)
            expected[name] = (binding["sha256"], binding["bytes"], maximum)
    before = _inventory_evidence_pack_directory(directory)
    if {name for name, _ in before[1]} != set(expected) | {EVIDENCE_PACK_MANIFEST}:
        raise ContractError("evidence pack publication artifact inventory changed")
    for name, (digest, size, maximum) in expected.items():
        actual_digest, actual_size = _sha256_stable_file(
            directory / name, maximum=maximum, label=f"published artifact {name}"
        )
        if actual_size != size or not hmac.compare_digest(actual_digest, digest):
            raise ContractError("evidence pack publication artifact digest changed")
    saved_manifest = read_bounded_control_snapshot_result(
        directory / EVIDENCE_PACK_MANIFEST,
        maximum=MAX_EVIDENCE_PACK_MANIFEST_BYTES,
        label="evidence pack published manifest",
        require_single_link=True,
    )
    if saved_manifest.state != "complete" or saved_manifest.body != manifest_body:
        raise ContractError("evidence pack publication manifest changed")
    if _inventory_evidence_pack_directory(directory) != before:
        raise ContractError("evidence pack publication inventory changed during binding")


def _sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _portable_json_bytes(document: Any, label: str, *, max_bytes: int) -> bytes:
    try:
        payload = (
            json.dumps(
                document,
                indent=2,
                sort_keys=True,
                allow_nan=False,
            )
            + "\n"
        ).encode("utf-8")
    except (
        OverflowError,
        RecursionError,
        TypeError,
        ValueError,
        UnicodeEncodeError,
    ) as exc:
        raise ContractError(
            f"cannot encode evidence pack {label}: {type(exc).__name__}"
        ) from None
    if len(payload) > max_bytes:
        raise ContractError(
            f"evidence pack {label} exceeds the {max_bytes}-byte JSON limit"
        )
    return payload


def _read_json_object_bounded(
    path: Path,
    label: str,
    *,
    max_bytes: int,
    expected_sha256: str | None = None,
    expected_bytes: int | None = None,
) -> tuple[dict[str, Any], bytes]:
    if not isinstance(path, Path):
        raise ContractError(f"evidence pack {label} path must be a Path")
    try:
        snapshot = read_bounded_control_snapshot_result(
            path,
            maximum=max_bytes,
            label=f"evidence pack {label}",
            require_single_link=True,
        )
    except ContractError as exc:
        if f"exceeds {max_bytes} bytes" in str(exc):
            raise ContractError(
                f"evidence pack {label} exceeds the {max_bytes}-byte JSON limit"
            ) from None
        raise
    if snapshot.state != "complete" or snapshot.body is None:
        raise ContractError(f"cannot read evidence pack {label}: {snapshot.state}")
    payload = snapshot.body
    if expected_bytes is not None and len(payload) != expected_bytes:
        raise ContractError(f"evidence pack {label} changed after digest verification")
    if expected_sha256 is not None and not hmac.compare_digest(
        _sha256_bytes(payload), expected_sha256
    ):
        raise ContractError(f"evidence pack {label} changed after digest verification")
    document = decode_strict_json_bytes(payload, label=f"evidence pack {label}")
    if not isinstance(document, dict):
        raise ContractError(f"evidence pack {label} must be a JSON object")
    return document, payload


def _load_json_object_bounded(
    path: Path,
    label: str,
    *,
    max_bytes: int,
    expected_sha256: str | None = None,
    expected_bytes: int | None = None,
) -> dict[str, Any]:
    document, _payload = _read_json_object_bounded(
        path,
        label,
        max_bytes=max_bytes,
        expected_sha256=expected_sha256,
        expected_bytes=expected_bytes,
    )
    return document


def _load_bound_json_object(
    path: Path, label: str, binding: dict[str, Any]
) -> dict[str, Any]:
    return _load_json_object_bounded(
        path,
        label,
        max_bytes=MAX_EVIDENCE_PACK_JSON_ARTIFACT_BYTES,
        expected_sha256=binding["sha256"],
        expected_bytes=binding["bytes"],
    )


def _portable_browser_fact_snapshot(fact: dict[str, Any]) -> dict[str, Any]:
    """Remove operator labels/notes while retaining measured browser facts."""
    source = fact["source"]
    source_extra = {
        key: source.get(key)
        for key in (
            "session_run_id",
            "chromium_revision",
            "executable_sha256_16",
            "build_provenance",
            "headless",
            "viewport_mode",
        )
        if key in source
    }
    return build_browser_fact_snapshot(
        snapshot_id=f"portable-{fact['integrity_sha256'][:16]}",
        browser=fact["browser"],
        source_kind=source["kind"],
        source_label=f"evidence-pack:{source['kind']}",
        engine=fact.get("engine"),
        captured_at=fact["captured_at"],
        source_extra=source_extra,
    )


def _browser_fact_capture_method(fact: dict[str, Any]) -> dict[str, Any] | None:
    """Return the validated Playwright capture method, preserving false values."""
    source = fact["source"]
    if "headless" not in source and "viewport_mode" not in source:
        return None
    return {
        "headless": source["headless"],
        "viewport_mode": source["viewport_mode"],
    }


def _require_browser_fact_session_binding(
    fact: dict[str, Any],
    *,
    session_run_id: Any,
    chromium_revision: Any,
    build_provenance: Any,
    executable_sha256_16: Any,
) -> None:
    """Bind session-origin facts to the evidence-pack session identity."""
    source = fact["source"]
    if source["kind"] != "browser-core-session":
        return
    expected = {
        "session_run_id": session_run_id,
        "chromium_revision": chromium_revision,
        "build_provenance": build_provenance,
        "executable_sha256_16": executable_sha256_16,
    }
    actual = {key: source.get(key) for key in expected}
    if actual != expected:
        raise ContractError(
            "browser fact session provenance does not match evidence-pack session"
        )


def _portable_transport_summary(record: Any) -> dict[str, Any]:
    validated = validate_transport_fingerprint(record, require_build=True)
    return {
        "schema": validated["schema"],
        "digest_sha256": validated["digest_sha256"],
        "grease_present": validated["grease_present"],
        "core_build": dict(validated["core_build"]),
    }


def _portable_http2_summary(record: Any) -> dict[str, Any]:
    validated = validate_http2_fingerprint(record, require_build=True)
    return {
        "schema": validated["schema"],
        "digest_sha256": validated["digest_sha256"],
        "headers_started": validated["headers_started"],
        "core_build": dict(validated["core_build"]),
    }


def _portable_http2_evidence_summary(record: Any) -> dict[str, Any]:
    validated = validate_http2_capture_evidence(record, require_build=True)
    fingerprint = validated["fingerprint"]
    header_order = validated["header_order"]
    return {
        "schema": validated["schema"],
        "digest_sha256": validated["digest_sha256"],
        "fingerprint_digest_sha256": fingerprint["digest_sha256"],
        "header_order_digest_sha256": header_order["digest_sha256"],
        "header_name_count": len(header_order["header_names"]),
        "pseudo_header_order": list(header_order["pseudo_header_order"]),
        "same_connection": validated["same_connection"],
        "core_build": dict(fingerprint["core_build"]),
    }


def _session_portable_summary(session: dict[str, Any]) -> dict[str, Any]:
    """Redacted session fields safe for evidence packs (no CDP, no paths)."""
    build = session.get("build") if isinstance(session.get("build"), dict) else {}
    persona = session.get("persona") if isinstance(session.get("persona"), dict) else {}
    network = session.get("network") if isinstance(session.get("network"), dict) else {}
    summary: dict[str, Any] = {
        "schema": session.get("schema"),
        "run_id": session.get("run_id"),
        "state": session.get("state", "active"),
        "chromium_revision": session.get("chromium_revision"),
        "created_at": _portable_iso_timestamp(session.get("created_at")),
        "stopped_at": _portable_iso_timestamp(session.get("stopped_at")),
        "trace_mode": session.get("trace_mode"),
        "trace_scope": session.get("trace_scope"),
        "trace_categories": session.get("trace_categories"),
        "trace_category_contract": session.get("trace_category_contract"),
        "build_provenance": build.get("provenance"),
        "executable_sha256_16": build.get("executable_sha256_16"),
        "runtime_bundle_sha256_16": build.get("runtime_bundle_sha256_16"),
        "has_automation_endpoint": bool(
            isinstance(session.get("automation"), dict)
            and session["automation"].get("cdp_endpoint")
        ),
        "has_trace_path": bool(session.get("trace_path")),
        # IDs are operator-chosen labels and can encode private customer names.
        # Their contract digests preserve exact identity without copying labels.
        "persona_sha256_16": persona.get("sha256_16"),
        "network_route_sha256_16": network.get("route_sha256_16"),
    }
    # Drop empty optionals for compactness
    return {key: value for key, value in summary.items() if value is not None}


def _subtraction_provenance_is_coherent(document: dict[str, Any]) -> bool:
    """Recheck source/capture joins still available in a compact subtraction."""

    pin = document.get("arm_script_sha256_16")
    label = document.get("arm_label")
    if not isinstance(pin, str) or re.fullmatch(r"[0-9a-fA-F]{16}", pin) is None:
        return False
    if not isinstance(label, str):
        return False

    if "source_provenance" in document:
        raw_source = document.get("source_provenance")
        safe_source = _sanitize_source_provenance(raw_source)
        source_status = (
            raw_source.get("status") if isinstance(raw_source, dict) else None
        )
        if not isinstance(source_status, str) or source_status not in {
            "not_supplied",
            "verified_digest",
            "verified_git_inputs_artifact_digest",
        } or safe_source.get("status") != source_status:
            return False
        if source_status in {
            "verified_digest",
            "verified_git_inputs_artifact_digest",
        } and (
            not isinstance(safe_source.get("sha256"), str)
            or safe_source["sha256"][:16] != pin.lower()
        ):
            return False

    if "provenance" in document:
        raw_capture = document.get("provenance")
        safe_capture = _sanitize_capture_provenance(raw_capture)
        capture_status = (
            raw_capture.get("status") if isinstance(raw_capture, dict) else None
        )
        if (
            not isinstance(capture_status, str)
            or capture_status not in {"not_checked", "VERIFIED", "UNVERIFIED", "error"}
            or safe_capture.get("status") != capture_status
            or raw_capture.get("asserted_label") != label
        ):
            return False
    return True


def _portable_baseline_repeat_receipt(document: dict[str, Any]) -> dict[str, Any]:
    """Project only an internally reconciled, name-free repeat receipt."""

    fields = {
        "arms",
        "volatile_api_names",
        "volatile_api_name_count",
        "pairwise_differences",
        "measured_noise_floor",
    }
    if not fields.intersection(document):
        return {}
    arms = document.get("arms")
    pairwise = document.get("pairwise_differences")
    measured = document.get("measured_noise_floor")
    raw_volatile = document.get("volatile_api_names")
    if isinstance(raw_volatile, list):
        if (
            len(raw_volatile) > 1_000_000
            or any(
                not isinstance(name, str)
                or not name
                or len(name) > 1_024
                or any(ord(char) < 32 for char in name)
                for name in raw_volatile
            )
            or len(set(raw_volatile)) != len(raw_volatile)
        ):
            return {}
        volatile_count = len(raw_volatile)
    else:
        volatile_count = document.get("volatile_api_name_count")
    if (
        isinstance(arms, bool)
        or not isinstance(arms, int)
        or not 2 <= arms <= 1_414
        or isinstance(volatile_count, bool)
        or not isinstance(volatile_count, int)
        or not 0 <= volatile_count <= 1_000_000
        or not isinstance(pairwise, list)
        or len(pairwise) != arms * (arms - 1) // 2
        or len(pairwise) > 1_000_000
        or any(
            isinstance(value, bool)
            or not isinstance(value, int)
            or not 0 <= value <= 1_000_000
            for value in pairwise
        )
        or isinstance(measured, bool)
        or not isinstance(measured, int)
        or measured < 0
        or measured != max(pairwise)
        or measured > volatile_count
        or bool(volatile_count) != (measured > 0)
    ):
        return {}
    return {
        "arms": arms,
        "volatile_api_name_count": volatile_count,
        "pairwise_differences": list(pairwise),
        "measured_noise_floor": measured,
    }


def _redacted_session_document(session: dict[str, Any]) -> dict[str, Any]:
    """Project a session copy without retaining paths or operator-owned IDs."""
    automation = (
        session.get("automation") if isinstance(session.get("automation"), dict) else {}
    )
    profile = session.get("profile") if isinstance(session.get("profile"), dict) else {}
    document: dict[str, Any] = {
        "schema": "browser-core.session-redacted/1",
        "source_schema": session.get("schema"),
        "summary": _session_portable_summary(session),
        "automation": {
            "transport": automation.get("transport"),
            "cdp_endpoint": "[redacted-loopback]"
            if automation.get("cdp_endpoint")
            else None,
            "has_managed_target_url": bool(automation.get("managed_target_url")),
        },
        "profile": {
            "persistence": profile.get("persistence"),
            "has_path": bool(profile.get("path")),
            "has_lock_path": bool(profile.get("lock_path")),
        }
        if profile
        else None,
    }
    document["automation"] = {
        key: value for key, value in document["automation"].items() if value is not None
    }
    return {key: value for key, value in document.items() if value is not None}


def _validate_portable_session_summary(
    summary: Any, *, manifest_run_id: str
) -> dict[str, Any]:
    if not isinstance(summary, dict):
        raise ContractError("evidence pack session summary is invalid")
    allowed = {
        "schema",
        "run_id",
        "state",
        "chromium_revision",
        "created_at",
        "stopped_at",
        "trace_mode",
        "trace_scope",
        "trace_categories",
        "trace_category_contract",
        "build_provenance",
        "executable_sha256_16",
        "runtime_bundle_sha256_16",
        "has_automation_endpoint",
        "has_trace_path",
        "persona_sha256_16",
        "network_route_sha256_16",
    }
    required = {
        "schema",
        "run_id",
        "state",
        "chromium_revision",
        "has_automation_endpoint",
        "has_trace_path",
    }
    if not required.issubset(summary) or set(summary) - allowed:
        raise ContractError("evidence pack session summary fields are invalid")
    if (
        summary["schema"] != "browser-core.session/1"
        or summary["run_id"] != manifest_run_id
        or not isinstance(summary["state"], str)
        or summary["state"] not in {"active", "stopped"}
        or not isinstance(summary["chromium_revision"], str)
        or not re.fullmatch(r"[0-9a-f]{40}", summary["chromium_revision"])
        or not isinstance(summary["has_automation_endpoint"], bool)
        or not isinstance(summary["has_trace_path"], bool)
    ):
        raise ContractError("evidence pack session summary identity is invalid")
    for key in ("created_at", "stopped_at"):
        if key in summary and _portable_iso_timestamp(summary[key]) != summary[key]:
            raise ContractError("evidence pack session summary timestamp is invalid")
    trace_mode = summary.get("trace_mode")
    trace_scope = summary.get("trace_scope")
    trace_categories = summary.get("trace_categories")
    trace_contract = summary.get("trace_category_contract")
    if trace_mode is not None and (
        not isinstance(trace_mode, str) or trace_mode not in {"on", "off"}
    ):
        raise ContractError("evidence pack session summary trace mode is invalid")
    if trace_contract is not None and (
        not isinstance(trace_contract, str)
        or trace_contract not in TRACE_CATEGORY_CONTRACTS
    ):
        raise ContractError("evidence pack session summary trace contract is invalid")
    if trace_mode == "on":
        if (
            not isinstance(trace_scope, str)
            or trace_scope not in TRACE_SCOPES
            or not isinstance(trace_categories, list)
        ):
            raise ContractError("evidence pack session summary trace scope is invalid")
        supplied = tuple(trace_categories)
        accepted = valid_trace_categories(trace_scope, trace_contract)
        if supplied not in accepted:
            raise ContractError(
                "evidence pack session summary trace categories are invalid"
            )
    elif trace_mode == "off":
        if trace_scope is not None or (
            trace_categories is not None and trace_categories != []
        ):
            raise ContractError("evidence pack disabled trace summary is invalid")
    elif trace_scope is not None or trace_categories is not None:
        raise ContractError("evidence pack session summary trace fields are invalid")
    provenance = summary.get("build_provenance")
    if provenance is not None and (
        not isinstance(provenance, str)
        or provenance not in {"attested-browser-core", "unverified-external"}
    ):
        raise ContractError("evidence pack session build provenance is invalid")
    for key in (
        "executable_sha256_16",
        "runtime_bundle_sha256_16",
        "persona_sha256_16",
        "network_route_sha256_16",
    ):
        value = summary.get(key)
        if value is not None and (
            not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{16}", value)
        ):
            raise ContractError(f"evidence pack session {key} is invalid")
    return summary


def _validate_redacted_session_document(
    document: dict[str, Any], *, session_summary: dict[str, Any]
) -> None:
    expected_outer = {"schema", "source_schema", "summary", "automation"}
    if "profile" in document:
        expected_outer.add("profile")
    if set(document) != expected_outer:
        raise ContractError("evidence pack redacted session fields are invalid")
    if (
        document.get("schema") != "browser-core.session-redacted/1"
        or document.get("source_schema") != session_summary.get("schema")
        or canonical_json_bytes(document.get("summary")) != canonical_json_bytes(session_summary)
    ):
        raise ContractError(
            "evidence pack session summary does not match the bound JSON"
        )
    automation = document.get("automation")
    if not isinstance(automation, dict) or set(automation) != {
        "transport",
        "cdp_endpoint",
        "has_managed_target_url",
    }:
        raise ContractError("evidence pack redacted automation fields are invalid")
    if (
        automation.get("transport") != "cdp"
        or automation.get("cdp_endpoint") != "[redacted-loopback]"
        or not isinstance(automation.get("has_managed_target_url"), bool)
    ):
        raise ContractError("evidence pack redacted automation values are invalid")
    profile = document.get("profile")
    if profile is not None:
        if not isinstance(profile, dict) or set(profile) != {
            "persistence",
            "has_path",
            "has_lock_path",
        }:
            raise ContractError("evidence pack redacted profile fields are invalid")
        if (
            not isinstance(profile.get("persistence"), str)
            or profile.get("persistence") not in {"ephemeral", "persistent"}
            or not isinstance(profile.get("has_path"), bool)
            or not isinstance(profile.get("has_lock_path"), bool)
        ):
            raise ContractError("evidence pack redacted profile values are invalid")


_PORTABLE_DRIFT_DECISION_KEYS = (
    "baseline_label",
    "baseline_script_sha256_16",
    "observed_label",
    "observed_script_sha256_16",
    "baseline_receipt_sha256",
    "observed_subtraction_receipt_sha256",
    "input_artifact_receipts_complete",
    "input_artifact_receipts_comparable",
    "same_script",
    "baseline_source_sha256",
    "observed_source_sha256",
    "source_custody_comparable",
    "baseline_control_script_sha256_16",
    "observed_control_script_sha256_16",
    "same_control_script",
    "baseline_capture_status",
    "baseline_control_capture_status",
    "observed_capture_status",
    "observed_control_capture_status",
    "capture_receipts_comparable",
    "baseline_count",
    "observed_count",
    "added",
    "removed",
    "drift",
    "tolerance",
    "tolerance_source",
    "baseline_noise_floor",
    "same_method",
    "method_mismatches",
    "clean_subtraction",
    "surface_claim_ready",
    "request_activity_drift",
    "passed",
)

_PORTABLE_COMPARISON_PAIR_KEYS = (
    "a",
    "b",
    "a_script_sha256_16",
    "b_script_sha256_16",
    "same_script",
    "a_subtraction_receipt_sha256",
    "b_subtraction_receipt_sha256",
    "input_artifact_receipts_complete",
    "input_artifact_receipts_comparable",
    "a_source_sha256",
    "b_source_sha256",
    "source_custody_comparable",
    "a_capture_status",
    "b_capture_status",
    "a_control_capture_status",
    "b_control_capture_status",
    "capture_receipts_comparable",
    "a_control_script_sha256_16",
    "b_control_script_sha256_16",
    "same_control_script",
    "a_count",
    "b_count",
    "shared",
    "only_a",
    "only_b",
    "jaccard",
    "same_method",
    "method_mismatches",
    "a_surface_claim_ready",
    "b_surface_claim_ready",
    "surface_comparison_claim_ready",
)


def _strict_detached_decision_value(value: Any) -> Any:
    try:
        reject_sensitive_keys(value)
        body = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8", errors="strict")
        return decode_strict_json_bytes(body, label="portable decision field")
    except (
        ContractError,
        OverflowError,
        RecursionError,
        TypeError,
        UnicodeEncodeError,
        ValueError,
    ):
        raise ContractError("portable decision field is invalid") from None


def _portable_decision_summary(document: dict[str, Any]) -> dict[str, Any]:
    """Project a validated decision without retaining generated timestamps."""

    schema = document.get("schema")
    summary: dict[str, Any] = {"schema": schema}
    decision_receipt = document.get("decision_receipt_sha256")
    if isinstance(decision_receipt, str) and re.fullmatch(
        r"[0-9a-f]{64}", decision_receipt
    ):
        summary["decision_receipt_sha256"] = decision_receipt
    if schema == DRIFT_SCHEMA:
        for key in _PORTABLE_DRIFT_DECISION_KEYS:
            if key in document:
                summary[key] = _strict_detached_decision_value(document[key])
    elif schema == COMPARISON_SCHEMA:
        if "arms" in document:
            summary["arms"] = _strict_detached_decision_value(document["arms"])
        pairs = document.get("pairs")
        if isinstance(pairs, list):
            summary["pairs"] = [
                {
                    key: _strict_detached_decision_value(pair[key])
                    for key in _PORTABLE_COMPARISON_PAIR_KEYS
                    if isinstance(pair, dict) and key in pair
                }
                for pair in pairs
            ]
    _verified_decision_input_lineage(summary)
    _verified_decision_semantics(summary)
    return summary


def _portable_observation_summary(document: dict[str, Any]) -> dict[str, Any]:
    """Redaction-safe view of a product-script observation or subtraction.

    Binds the *pin* a trace was taken against. Without this, an evidence pack proves
    a browser ran but not which product script it ran, and a roll change silently
    invalidates the whole bundle.
    """
    schema = document.get("schema")
    if isinstance(schema, str) and schema in {DRIFT_SCHEMA, COMPARISON_SCHEMA}:
        return _portable_decision_summary(document)
    summary: dict[str, Any] = {
        "schema": document.get("schema"),
        "label": document.get("label") or document.get("arm_label"),
        "script_sha256_16": document.get("script_sha256_16")
        or document.get("arm_script_sha256_16"),
    }
    label = summary["label"]
    if not isinstance(label, str) or not re.fullmatch(
        r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", label
    ):
        summary.pop("label")
    digest = summary["script_sha256_16"]
    if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-fA-F]{16}", digest):
        summary.pop("script_sha256_16")
    control_digest = document.get("control_script_sha256_16")
    if isinstance(control_digest, str) and re.fullmatch(
        r"[0-9a-f]{16}", control_digest
    ):
        summary["control_script_sha256_16"] = control_digest
    if document.get("schema") == BASELINE_SCHEMA:
        api_name_count = document.get("api_name_count")
        surface_sha256 = document.get("surface_sha256")
        if (
            isinstance(api_name_count, int)
            and not isinstance(api_name_count, bool)
            and 0 <= api_name_count <= 1_000_000
        ):
            summary["api_name_count"] = api_name_count
        if isinstance(surface_sha256, str) and re.fullmatch(
            r"[0-9a-fA-F]{64}", surface_sha256
        ):
            summary["surface_sha256"] = surface_sha256.lower()
        baseline_receipt = document.get("baseline_receipt_sha256")
        if isinstance(baseline_receipt, str) and re.fullmatch(
            r"[0-9a-f]{64}", baseline_receipt
        ):
            summary["baseline_receipt_sha256"] = baseline_receipt
        source_population, source_population_complete = (
            _verified_baseline_source_subtraction_lineage(document)
        )
        if source_population_complete is not None:
            summary["source_subtraction_receipt_population"] = source_population
            if "source_subtraction_lineage" in document:
                summary["source_subtraction_lineage"] = document[
                    "source_subtraction_lineage"
                ]
            summary["source_subtraction_receipts_complete"] = (
                source_population_complete
            )
        summary.update(_portable_baseline_repeat_receipt(document))
    if document.get("schema") == SUBTRACTION_SCHEMA:
        subtraction_receipt = document.get("subtraction_receipt_sha256")
        if isinstance(subtraction_receipt, str) and re.fullmatch(
            r"[0-9a-f]{64}", subtraction_receipt
        ):
            summary["subtraction_receipt_sha256"] = subtraction_receipt
        for key in (
            "arm_observation_receipt_sha256",
            "control_observation_receipt_sha256",
        ):
            value = document.get(key)
            if isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value):
                summary[key] = value
        complete = document.get("input_observation_receipts_complete")
        if isinstance(complete, bool):
            summary["input_observation_receipts_complete"] = complete
        comparable = document.get("input_observation_receipts_comparable")
        if isinstance(comparable, bool):
            summary["input_observation_receipts_comparable"] = comparable
    if document.get("schema") == OBSERVATION_SCHEMA:
        observation_receipt = document.get("observation_receipt_sha256")
        if isinstance(observation_receipt, str) and re.fullmatch(
            r"[0-9a-f]{64}", observation_receipt
        ):
            summary["observation_receipt_sha256"] = observation_receipt
    if document.get("schema") == BASELINE_SCHEMA:
        source_arm_label = document.get("source_arm_label")
        if isinstance(source_arm_label, str) and re.fullmatch(
            r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", source_arm_label
        ):
            summary["source_arm_label"] = source_arm_label
        if "capture_provenance" in document:
            summary["capture_provenance"] = _sanitize_capture_provenance(
                document.get("capture_provenance")
            )
        if "control_capture_provenance" in document:
            summary["control_capture_provenance"] = _sanitize_capture_provenance(
                document.get("control_capture_provenance")
            )
        population = document.get("capture_provenance_population")
        if isinstance(population, list) and 0 < len(population) <= 1_414:
            safe_population: list[dict[str, Any]] = []
            for row in population:
                if not isinstance(row, dict):
                    safe_population = []
                    break
                arm_label = row.get("arm_label")
                control_label = row.get("control_label")
                arm_capture = _sanitize_capture_provenance(row.get("provenance"))
                control_capture = _sanitize_capture_provenance(
                    row.get("control_provenance")
                )
                if (
                    not isinstance(arm_label, str)
                    or re.fullmatch(
                        r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", arm_label
                    )
                    is None
                    or not isinstance(control_label, str)
                    or re.fullmatch(
                        r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", control_label
                    )
                    is None
                    or arm_capture.get("asserted_label") != arm_label
                    or control_capture.get("asserted_label") != control_label
                ):
                    safe_population = []
                    break
                safe_population.append(
                    {
                        "arm_label": arm_label,
                        "control_label": control_label,
                        "provenance": arm_capture,
                        "control_provenance": control_capture,
                    }
                )
            if len(safe_population) == len(population):
                summary["capture_provenance_population"] = safe_population
    identity = document.get("script_identity")
    if isinstance(identity, dict):
        if document.get("schema") == OBSERVATION_SCHEMA:
            _, safe_identity, _, _ = _reconciled_script_identity(
                document, current_required=True
            )
        elif document.get("schema") == SUBTRACTION_SCHEMA:
            safe_identity = _reconciled_subtraction_script_identity(document)
        else:
            safe_identity = identity
        if isinstance(safe_identity, dict):
            signals = (
                identity.get("signals")
                if isinstance(identity.get("signals"), dict)
                else {}
            )
            script_bytes = safe_identity.get("bytes", signals.get("bytes"))
            looks_built = safe_identity.get("looks_like_built_antibot_script")
            vendor_hint = safe_identity.get("vendor_hint")
        else:
            script_bytes = None
            looks_built = None
            vendor_hint = object()
    else:
        script_bytes = document.get("script_bytes")
        looks_built = document.get("looks_like_built_antibot_script")
        vendor_hint = document.get("vendor_hint")
    if (
        isinstance(script_bytes, int)
        and not isinstance(script_bytes, bool)
        and 0 <= script_bytes <= 1_000_000_000
    ):
        summary["script_bytes"] = script_bytes
    if isinstance(looks_built, bool):
        summary["looks_like_built_antibot_script"] = looks_built
    safe_vendor_hint = project_product_script_vendor_hint(vendor_hint)
    if vendor_hint is None or safe_vendor_hint is not None:
        summary["vendor_hint"] = safe_vendor_hint
    if looks_built is True and (
        analysis_boundary := project_product_script_analysis_boundary(safe_vendor_hint)
    ):
        summary["analysis_boundary"] = analysis_boundary

    trace_scope = document.get("trace_scope")
    if isinstance(trace_scope, str) and trace_scope in TRACE_SCOPES:
        summary["trace_scope"] = trace_scope
    category_contract = document.get("trace_category_contract")
    if (
        isinstance(category_contract, str)
        and category_contract in TRACE_CATEGORY_CONTRACTS
    ):
        summary["trace_category_contract"] = category_contract
    chromium_revision = document.get("chromium_revision")
    if isinstance(chromium_revision, str) and re.fullmatch(
        r"[0-9a-fA-F]{40}", chromium_revision
    ):
        summary["chromium_revision"] = chromium_revision.lower()
    run_id = document.get("run_id")
    if isinstance(run_id, str) and re.fullmatch(
        r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", run_id
    ):
        summary["run_id"] = run_id
    for key in ("dwell_seconds", "timeout_seconds"):
        value = document.get(key)
        if (
            is_finite_number(value)
            and 0 <= value <= 86_400
        ):
            summary[key] = value
    inline_script = document.get("inline_script")
    if isinstance(inline_script, bool):
        summary["inline_script"] = inline_script
    for key in ("reloads", "attributed_api_names"):
        value = document.get(key)
        if (
            isinstance(value, int)
            and not isinstance(value, bool)
            and 0 <= value <= 1_000_000
        ):
            summary[key] = value
    hook_mode = document.get("hook_mode")
    if isinstance(hook_mode, str) and hook_mode in HOOK_MODES:
        summary["hook_mode"] = hook_mode
    hook_names = document.get("hook_target_names")
    if isinstance(hook_names, list):
        from .argument_capture import HOOK_TARGETS

        known_hook_names = {target.name for target in HOOK_TARGETS}
        safe_hook_names = sorted(
            {
                value
                for value in hook_names[:128]
                if isinstance(value, str) and value in known_hook_names
            }
        )
        if safe_hook_names or not hook_names:
            summary["hook_target_names"] = safe_hook_names
    control_label = document.get("control_label")
    if isinstance(control_label, str) and re.fullmatch(
        r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", control_label
    ):
        summary["control_label"] = control_label
    for key in (
        "clean_subtraction",
        "ready_probe_comparable",
        "arm_control_method_comparable",
        "driver_execution_complete",
        "script_identity_coherent",
        "trace_evidence_coherent",
        "await_method_comparable",
        "arm_readiness_satisfied",
        "input_method_comparable",
        "ambient_input_clean",
        "collector_started",
        "collector_startup_coherent",
        "control_collector_startup_coherent",
        "startup_derivation_coherent",
        "rehost_dependencies_complete",
        "control_rehost_dependencies_complete",
        "rehost_receipts_coherent",
        "request_activity_receipts_coherent",
        "page_load_execution_coherent",
        "surface_claim_ready",
        "script_attribution_comparable",
        "offline_guard_comparable",
    ):
        value = document.get(key)
        if value is None or isinstance(value, bool):
            if key in document:
                summary[key] = value
    if schema != SUBTRACTION_SCHEMA:
        summary.pop("surface_claim_ready", None)
    elif (
        summary.get("surface_claim_ready") is True
        and summary.get("clean_subtraction") is not True
    ):
        summary["surface_claim_ready"] = False
    raw_offline_guard = document.get(
        "offline_guard", document.get("arm_offline_guard")
    )
    if "offline_guard" in document or "arm_offline_guard" in document:
        summary["offline_guard"] = _sanitize_offline_guard(raw_offline_guard)
        if (
            summary["offline_guard"].get("status") == "unverifiable"
            and summary.get("surface_claim_ready") is True
        ):
            summary["surface_claim_ready"] = False
    if (
        "offline_guard_comparable" in document
        and document.get("offline_guard_comparable") is not None
        and document.get("offline_guard_comparable") is not True
        and summary.get("surface_claim_ready") is True
    ):
        summary["surface_claim_ready"] = False
    if (
        "rehost_receipts_coherent" in document
        and document.get("rehost_receipts_coherent") is not None
        and document.get("rehost_receipts_coherent") is not True
        and summary.get("surface_claim_ready") is True
    ):
        summary["surface_claim_ready"] = False
    if (
        "collector_startup_coherent" in document
        and document.get("collector_startup_coherent") is not None
        and document.get("collector_startup_coherent") is not True
        and summary.get("surface_claim_ready") is True
    ):
        summary["surface_claim_ready"] = False
    for gate in (
        "clean_subtraction",
        "ready_probe_comparable",
        "arm_control_method_comparable",
        "driver_execution_complete",
        "script_identity_coherent",
        "trace_evidence_coherent",
        "await_method_comparable",
        "arm_readiness_satisfied",
        "input_method_comparable",
        "ambient_input_clean",
        "collector_started",
        "collector_startup_coherent",
        "control_collector_startup_coherent",
        "startup_derivation_coherent",
        "rehost_dependencies_complete",
        "control_rehost_dependencies_complete",
        "rehost_receipts_coherent",
        "request_activity_receipts_coherent",
        "page_load_execution_coherent",
        "offline_guard_comparable",
    ):
        if (
            gate in document
            and document.get(gate) is not None
            and document.get(gate) is not True
            and summary.get("surface_claim_ready") is True
        ):
            summary["surface_claim_ready"] = False
    analysis = document.get("analysis")
    raw_script_execution = (
        analysis.get("script_execution") if isinstance(analysis, dict) else None
    )
    if raw_script_execution is None:
        raw_script_execution = document.get("arm_script_execution")
    if raw_script_execution is None:
        raw_script_execution = document.get("script_execution")
    if (
        script_execution := _sanitize_script_execution_summary(
            raw_script_execution, label="portable observation"
        )
    ) is not None:
        summary["script_execution"] = script_execution
    if (
        control_script_execution := _sanitize_script_execution_summary(
            document.get("control_script_execution"),
            label="portable observation control",
        )
    ) is not None:
        summary["control_script_execution"] = control_script_execution
    diagnostic_analysis = document.get("diagnostic_trace_analysis")
    diagnostic_value = (
        diagnostic_analysis.get("script_execution")
        if isinstance(diagnostic_analysis, dict)
        else None
    )
    if diagnostic_value is None:
        diagnostic_value = document.get("diagnostic_script_execution")
    if (
        diagnostic_execution := _sanitize_script_execution_summary(
            diagnostic_value, label="portable observation diagnostic"
        )
    ) is not None:
        summary["diagnostic_script_execution"] = diagnostic_execution
    rehost_contract = document.get(
        "rehost_contract", document.get("arm_rehost_contract")
    )
    if (safe_rehost := _sanitize_rehost_contract(rehost_contract)) is not None:
        summary["rehost_contract"] = safe_rehost
    if (build := _browser_build_method(document)) is not None:
        summary["browser_build"] = build
        stamp = _portable_iso_timestamp(
            document["browser_build"].get("attestation_created_at")
        )
        if stamp is not None:
            summary["browser_build"]["attestation_created_at"] = stamp
    if "provenance" in document:
        summary["provenance"] = _sanitize_capture_provenance(document.get("provenance"))
    if (
        await_report := _sanitize_await_report(document.get("await_report"))
    ) is not None:
        summary["await_report"] = await_report
    if "source_provenance" in document:
        summary["source_provenance"] = _sanitize_source_provenance(
            document.get("source_provenance")
        )
    declared_url = document.get(
        "declared_script_url", document.get("arm_declared_script_url")
    )
    if declared_url is not None:
        summary["declared_script_url_shape"] = _project_public_url_shape(declared_url)
    elif isinstance(document.get("declared_script_url_shape"), dict):
        declared_metadata = _declared_url_metadata(
            {
                "supplied": True,
                "sha256_16": None,
                "shape": document["declared_script_url_shape"],
            }
        )
        if declared_metadata.get("shape") is not None:
            summary["declared_script_url_shape"] = declared_metadata["shape"]
    resource_capture = document.get(
        "resource_intent_capture", document.get("arm_resource_intent_capture")
    )
    if resource_capture == "off" or (
        isinstance(resource_capture, str)
        and resource_capture in RESOURCE_INTENT_CONTRACTS
    ):
        summary["resource_intent_capture"] = resource_capture
    if "prelude" in document or "arm_prelude" in document:
        summary["prelude"] = _prelude_document_metadata(document)
    if any(key in document for key in ("driver", "driver_js", "arm_driver")):
        summary["driver"] = _driver_metadata(document)
    if "driver_result" in document:
        summary["driver_result"] = _stored_driver_result_metadata(
            document.get("driver_result")
        )
    if "ready_expression" in document or "arm_ready_expression" in document:
        summary["ready_expression"] = _ready_expression_metadata(document)
    if "stage_routes" in document or "arm_stage_routes" in document:
        summary["stage_routes"] = _observation_stage_routes(document)
    if isinstance(document.get("collector_startup"), dict):
        summary["collector_startup"] = _sanitize_startup_document(
            document["collector_startup"]
        )
    if isinstance(document.get("resource_intents"), dict):
        summary["resource_intents"] = _sanitize_resource_intent_report(
            document["resource_intents"]
        )
    if isinstance(document.get("request_activity"), dict):
        summary["request_activity"] = _sanitize_request_activity_report(
            document["request_activity"]
        )
    elif isinstance(document.get("server_requests"), list):
        summary["request_activity"] = project_server_request_activity(
            document["server_requests"]
        )
    if (
        request_floor := _sanitize_request_activity_baseline(
            document.get("request_activity_baseline")
        )
    ) is not None:
        summary["request_activity_baseline"] = request_floor
    for source_key, output_key in (
        ("browser_shutdown", "browser_shutdown"),
        ("arm_browser_shutdown", "browser_shutdown"),
        ("control_browser_shutdown", "control_browser_shutdown"),
    ):
        shutdown = document.get(source_key)
        mode = shutdown.get("mode") if isinstance(shutdown, dict) else None
        if isinstance(mode, str) and mode in {
            "graceful",
            "forced",
            "exited-before-force",
        }:
            summary[output_key] = {"mode": mode}
    for source_key, output_key in (
        ("trace_flush", "trace_flush"),
        ("arm_trace_flush", "trace_flush"),
        ("control_trace_flush", "control_trace_flush"),
    ):
        flush = document.get(source_key)
        status = flush.get("status") if isinstance(flush, dict) else None
        if not isinstance(status, str) or status not in {
            "settled",
            "missing",
            "present-unsettled",
        }:
            continue
        projected: dict[str, Any] = {"status": status}
        size = flush.get("bytes")
        if (
            isinstance(size, int)
            and not isinstance(size, bool)
            and 0 <= size <= MAX_TRACE_BYTES
        ):
            projected["bytes"] = size
        summary[output_key] = projected
    input_probe = document.get("input_probe", document.get("arm_input_probe"))
    control_input_probe = document.get("control_input_probe")
    ambient_input = document.get("ambient_input", document.get("arm_ambient_input"))
    control_ambient_input = document.get("control_ambient_input")
    if (safe := _sanitize_input_probe_report(input_probe)) is not None:
        summary["input_probe"] = safe
    if (safe := _sanitize_input_probe_report(control_input_probe)) is not None:
        summary["control_input_probe"] = safe
    if (safe := _sanitize_ambient_input_report(ambient_input)) is not None:
        summary["ambient_input"] = safe
    if (safe := _sanitize_ambient_input_report(control_ambient_input)) is not None:
        summary["control_ambient_input"] = safe
    driver_supplied = document.get(
        "arm_driver_supplied", document.get("driver_supplied")
    )
    if isinstance(driver_supplied, bool):
        summary["driver_supplied"] = driver_supplied
    method = document.get("method")
    if isinstance(method, dict):
        summary["method"] = _surface_method(method)
    analysis = document.get("analysis")
    if isinstance(analysis, dict) or analysis is None:
        for source_key, output_key in (
            ("total_events", "total_events"),
            ("distinct_api_names", "distinct_api_names"),
            ("attributable_events", "attributable_events"),
            ("distinct_request_classes", "distinct_request_classes"),
        ):
            value = (
                analysis.get(source_key)
                if isinstance(analysis, dict)
                else document.get(output_key)
            )
            if (
                isinstance(value, int)
                and not isinstance(value, bool)
                and 0 <= value <= 1_000_000_000
            ):
                summary[output_key] = value
        attributable_fraction = (
            analysis.get("attributable_fraction")
            if isinstance(analysis, dict)
            else document.get("attributable_fraction")
        )
        if (
            is_finite_number(attributable_fraction)
            and 0 <= attributable_fraction <= 1
        ):
            summary["attributable_fraction"] = attributable_fraction
        methods = (
            analysis.get("request_methods")
            if isinstance(analysis, dict)
            else document.get("request_methods")
        )
        if isinstance(methods, dict):
            allowed_methods = {
                "GET",
                "HEAD",
                "POST",
                "PUT",
                "DELETE",
                "CONNECT",
                "OPTIONS",
                "TRACE",
                "PATCH",
            }
            summary["request_methods"] = {
                key: min(value, 1_000_000_000)
                for key, value in sorted(methods.items())
                if key in allowed_methods
                and isinstance(value, int)
                and not isinstance(value, bool)
                and value >= 0
            }
        # Carry a typed, value-free receipt for the targets of native fetch
        # events. Legacy raw-URL lists are deliberately not projected: they did
        # not exist in native exports, so accepting [] would invent proof.
        fetch_target_scope = (
            analysis.get("fetch_target_scope")
            if isinstance(analysis, dict)
            else document.get("fetch_target_scope")
        )
        if isinstance(fetch_target_scope, dict):
            coverage = fetch_target_scope.get("coverage")
            count_keys = (
                "requests",
                "loopback",
                "external",
                "non_network",
                "unclassified",
            )
            counts = {key: fetch_target_scope.get(key) for key in count_keys}
            if (
                isinstance(coverage, str)
                and coverage in {"complete", "unknown"}
                and all(
                    isinstance(value, int)
                    and not isinstance(value, bool)
                    and 0 <= value <= 1_000_000_000
                    for value in counts.values()
                )
                and counts["requests"]
                == counts["loopback"]
                + counts["external"]
                + counts["non_network"]
                + counts["unclassified"]
                and (coverage == "complete")
                == (counts["unclassified"] == 0)
            ):
                summary["fetch_target_scope"] = {
                    "coverage": coverage,
                    **counts,
                }
    return {key: value for key, value in summary.items() if value is not None}


def _build_evidence_pack_contents(
    *,
    session_path: Path,
    out_dir: Path,
    require_staging_authority: Callable[[], None],
    browser_fact_path: Path | None = None,
    transport_fingerprint_path: Path | None = None,
    http2_fingerprint_path: Path | None = None,
    http2_evidence_path: Path | None = None,
    trace_export_path: Path | None = None,
    trace_jsonl_path: Path | None = None,
    product_observation_path: Path | None = None,
    include_session_copy: bool = False,
) -> dict[str, Any]:
    """Write a redacted evidence pack directory and return the portable manifest.

    When include_session_copy is False (default), only digests of the session file
    are recorded—not the raw session (which may contain loopback CDP endpoints).
    """
    session_path = Path(session_path).resolve()
    # The caller created and bound this staging directory. Resolving its leaf
    # here would follow a replacement junction into an unrelated directory.
    out = Path(out_dir)
    require_staging_authority()
    if directory_identity(out, label="evidence pack staging directory") is None:
        raise ContractError("evidence pack staging directory is unavailable")
    if any(out.iterdir()):
        raise ContractError("evidence pack output directory must be empty or new")

    session_snapshot = load_session_snapshot(session_path)
    session = session_snapshot.document
    session_digest = _sha256_bytes(session_snapshot.body)
    session_bytes = len(session_snapshot.body)
    portable_session = _session_portable_summary(session)
    reject_sensitive_keys(portable_session)

    artifacts: dict[str, Any] = {
        "session": {
            "sha256": session_digest,
            "bytes": session_bytes,
            "summary": portable_session,
        }
    }

    if include_session_copy:
        redacted = _redacted_session_document(session)
        reject_sensitive_keys(redacted)
        body = _portable_json_bytes(
            redacted,
            "redacted session",
            max_bytes=MAX_EVIDENCE_PACK_JSON_ARTIFACT_BYTES,
        )
        require_staging_authority()
        publish_bytes_exclusive(
            out / "session.redacted.json",
            body,
            maximum=MAX_EVIDENCE_PACK_JSON_ARTIFACT_BYTES,
            label="evidence pack redacted session",
        )
        artifacts["session"]["redacted_copy"] = {
            "file": "session.redacted.json",
            "sha256": _sha256_bytes(body),
            "bytes": len(body),
        }

    if browser_fact_path is not None:
        fact_path = Path(browser_fact_path).resolve()
        fact_document, fact_source_body = _read_json_object_bounded(
            fact_path,
            "browser fact source",
            max_bytes=MAX_EVIDENCE_PACK_BROWSER_FACT_SOURCE_BYTES,
        )
        fact = validate_browser_fact_snapshot(fact_document)
        session_build = (
            session.get("build") if isinstance(session.get("build"), dict) else {}
        )
        _require_browser_fact_session_binding(
            fact,
            session_run_id=session.get("run_id"),
            chromium_revision=session.get("chromium_revision"),
            build_provenance=session_build.get("provenance"),
            executable_sha256_16=session_build.get("executable_sha256_16"),
        )
        portable_fact = _portable_browser_fact_snapshot(fact)
        dest = out / "browser-fact.json"
        body = _portable_json_bytes(
            portable_fact,
            "browser fact",
            max_bytes=MAX_EVIDENCE_PACK_JSON_ARTIFACT_BYTES,
        )
        require_staging_authority()
        publish_bytes_exclusive(
            dest,
            body,
            maximum=MAX_EVIDENCE_PACK_JSON_ARTIFACT_BYTES,
            label="evidence pack browser fact",
        )
        fact_digest, fact_bytes = _sha256_bytes(body), len(body)
        fact_artifact = {
            "file": "browser-fact.json",
            "schema": portable_fact["schema"],
            "snapshot_id": portable_fact["snapshot_id"],
            "integrity_sha256": portable_fact["integrity_sha256"],
            "source_kind": portable_fact["source"]["kind"],
            "source_integrity_sha256": fact["integrity_sha256"],
            "source_sha256": _sha256_bytes(fact_source_body),
            "source_bytes": len(fact_source_body),
            "sha256": fact_digest,
            "bytes": fact_bytes,
        }
        capture_method = _browser_fact_capture_method(portable_fact)
        if capture_method is not None:
            fact_artifact["capture_method"] = capture_method
        artifacts["browser_fact"] = fact_artifact

    if transport_fingerprint_path is not None:
        transport_path = Path(transport_fingerprint_path).resolve()
        transport_document, transport_source_body = _read_json_object_bounded(
            transport_path,
            "transport fingerprint source",
            max_bytes=MAX_EVIDENCE_PACK_TRANSPORT_SOURCE_BYTES,
        )
        transport = validate_transport_fingerprint(
            transport_document,
            require_build=True,
        )
        transport_build = transport["core_build"]
        session_build = session.get("build")
        if (
            not isinstance(session_build, dict)
            or session_build.get("provenance") != "attested-browser-core"
            or transport_build.get("chromium_revision")
            != session.get("chromium_revision")
            or transport_build.get("executable_sha256_16")
            != session_build.get("executable_sha256_16")
            or transport_build.get("runtime_bundle_sha256_16")
            != session_build.get("runtime_bundle_sha256_16")
        ):
            raise ContractError(
                "transport fingerprint build does not match the session"
            )
        reject_sensitive_keys(transport)
        body = _portable_json_bytes(
            transport,
            "transport fingerprint",
            max_bytes=MAX_EVIDENCE_PACK_JSON_ARTIFACT_BYTES,
        )
        require_staging_authority()
        publish_bytes_exclusive(
            out / "transport-fingerprint.json",
            body,
            maximum=MAX_EVIDENCE_PACK_JSON_ARTIFACT_BYTES,
            label="evidence pack transport fingerprint",
        )
        artifacts["transport_fingerprint"] = {
            "file": "transport-fingerprint.json",
            "sha256": _sha256_bytes(body),
            "bytes": len(body),
            "source_sha256": _sha256_bytes(transport_source_body),
            "source_bytes": len(transport_source_body),
            "session_binding": {
                "status": "matched",
                "fields": [
                    "chromium_revision",
                    "executable_sha256_16",
                    "runtime_bundle_sha256_16",
                ],
            },
            "summary": _portable_transport_summary(transport),
        }

    standalone_http2: dict[str, Any] | None = None
    if http2_fingerprint_path is not None:
        http2_path = Path(http2_fingerprint_path).resolve()
        http2_document, http2_source_body = _read_json_object_bounded(
            http2_path,
            "HTTP/2 fingerprint source",
            max_bytes=MAX_EVIDENCE_PACK_HTTP2_SOURCE_BYTES,
        )
        http2 = validate_http2_fingerprint(http2_document, require_build=True)
        standalone_http2 = http2
        http2_build = http2["core_build"]
        session_build = session.get("build")
        if (
            not isinstance(session_build, dict)
            or session_build.get("provenance") != "attested-browser-core"
            or http2_build.get("chromium_revision")
            != session.get("chromium_revision")
            or http2_build.get("executable_sha256_16")
            != session_build.get("executable_sha256_16")
            or http2_build.get("runtime_bundle_sha256_16")
            != session_build.get("runtime_bundle_sha256_16")
        ):
            raise ContractError("HTTP/2 fingerprint build does not match the session")
        reject_sensitive_keys(http2)
        body = _portable_json_bytes(
            http2,
            "HTTP/2 fingerprint",
            max_bytes=MAX_EVIDENCE_PACK_JSON_ARTIFACT_BYTES,
        )
        require_staging_authority()
        publish_bytes_exclusive(
            out / "http2-fingerprint.json",
            body,
            maximum=MAX_EVIDENCE_PACK_JSON_ARTIFACT_BYTES,
            label="evidence pack HTTP/2 fingerprint",
        )
        artifacts["http2_fingerprint"] = {
            "file": "http2-fingerprint.json",
            "sha256": _sha256_bytes(body),
            "bytes": len(body),
            "source_sha256": _sha256_bytes(http2_source_body),
            "source_bytes": len(http2_source_body),
            "session_binding": {
                "status": "matched",
                "fields": [
                    "chromium_revision",
                    "executable_sha256_16",
                    "runtime_bundle_sha256_16",
                ],
            },
            "summary": _portable_http2_summary(http2),
        }

    if http2_evidence_path is not None:
        evidence_path = Path(http2_evidence_path).resolve()
        evidence_document, evidence_source_body = _read_json_object_bounded(
            evidence_path,
            "HTTP/2 evidence source",
            max_bytes=MAX_EVIDENCE_PACK_HTTP2_EVIDENCE_SOURCE_BYTES,
        )
        evidence = validate_http2_capture_evidence(
            evidence_document,
            require_build=True,
        )
        if (
            standalone_http2 is not None
            and evidence["fingerprint"] != standalone_http2
        ):
            raise ContractError(
                "HTTP/2 evidence fingerprint does not match standalone fingerprint"
            )
        evidence_build = evidence["fingerprint"]["core_build"]
        session_build = session.get("build")
        if (
            not isinstance(session_build, dict)
            or session_build.get("provenance") != "attested-browser-core"
            or evidence_build.get("chromium_revision")
            != session.get("chromium_revision")
            or evidence_build.get("executable_sha256_16")
            != session_build.get("executable_sha256_16")
            or evidence_build.get("runtime_bundle_sha256_16")
            != session_build.get("runtime_bundle_sha256_16")
        ):
            raise ContractError("HTTP/2 evidence build does not match the session")
        reject_sensitive_keys(evidence)
        body = _portable_json_bytes(
            evidence,
            "HTTP/2 evidence",
            max_bytes=MAX_EVIDENCE_PACK_JSON_ARTIFACT_BYTES,
        )
        require_staging_authority()
        publish_bytes_exclusive(
            out / "http2-evidence.json",
            body,
            maximum=MAX_EVIDENCE_PACK_JSON_ARTIFACT_BYTES,
            label="evidence pack HTTP/2 evidence",
        )
        artifacts["http2_evidence"] = {
            "file": "http2-evidence.json",
            "sha256": _sha256_bytes(body),
            "bytes": len(body),
            "source_sha256": _sha256_bytes(evidence_source_body),
            "source_bytes": len(evidence_source_body),
            "session_binding": {
                "status": "matched",
                "fields": [
                    "chromium_revision",
                    "executable_sha256_16",
                    "runtime_bundle_sha256_16",
                ],
            },
            "summary": _portable_http2_evidence_summary(evidence),
        }

    trace_export_document: dict[str, Any] | None = None
    if trace_export_path is not None:
        export_path = Path(trace_export_path).resolve()
        export_doc = _load_json_object_bounded(
            export_path,
            "trace export source",
            max_bytes=MAX_EVIDENCE_PACK_TRACE_EXPORT_SOURCE_BYTES,
        )
        trace_export_document = validate_trace_export_report(export_doc)
        if trace_export_document["run_id"] != session["run_id"]:
            raise ContractError("trace export run id does not match the session")
        if trace_export_document["chromium_revision"] != session["chromium_revision"]:
            raise ContractError(
                "trace export Chromium revision does not match the session"
            )
        # The trace-export contract is already path-free and value-free. Preserve
        # the complete nested receipt; selecting obsolete flat field names used to
        # discard both artifact digests, byte counts, events, and categories.
        portable_export = json.loads(json.dumps(trace_export_document))
        reject_sensitive_keys(portable_export)
        dest = out / "trace-export.json"
        body = _portable_json_bytes(
            portable_export,
            "trace export",
            max_bytes=MAX_EVIDENCE_PACK_JSON_ARTIFACT_BYTES,
        )
        require_staging_authority()
        publish_bytes_exclusive(
            dest,
            body,
            maximum=MAX_EVIDENCE_PACK_JSON_ARTIFACT_BYTES,
            label="evidence pack trace export",
        )
        artifacts["trace_export"] = {
            "file": "trace-export.json",
            "sha256": _sha256_bytes(body),
            "bytes": len(body),
            "summary": portable_export,
        }

    if trace_jsonl_path is not None:
        jsonl_path = Path(trace_jsonl_path).resolve()
        # Snapshot into the private staging directory first. Every digest and
        # semantic check below is over the bytes that will actually be
        # published, so a concurrently changing source cannot create a pack
        # whose manifest describes the pre-copy file.
        dest = out / "trace.jsonl"
        require_staging_authority()
        digest, size = _copy_stable_file(
            jsonl_path,
            dest,
            maximum=MAX_EVIDENCE_PACK_TRACE_JSONL_BYTES,
            label="trace JSONL source",
        )
        if trace_export_document is not None:
            normalized = trace_export_document["normalized_trace"]
            if digest != normalized["sha256"] or size != normalized["bytes"]:
                raise ContractError(
                    "trace JSONL does not match the trace export digest binding"
                )
        trace_summary = validate_trace(dest)
        if trace_summary["run_id"] != session["run_id"]:
            raise ContractError("trace JSONL run id does not match the session")
        if trace_export_document is not None:
            normalized = trace_export_document["normalized_trace"]
            if trace_summary["events"] != normalized["events"]:
                raise ContractError(
                    "trace JSONL event count does not match the trace export"
                )
            categories: dict[str, int] = {}
            with closing(iter_trace(dest)) as events:
                for event in events:
                    category = (event.get("provenance") or {}).get("trace_category")
                    if not isinstance(category, str):
                        raise ContractError(
                            "trace JSONL lacks complete trace-category provenance"
                        )
                    categories[category] = categories.get(category, 0) + 1
            if dict(sorted(categories.items())) != normalized["trace_categories"]:
                raise ContractError(
                    "trace JSONL categories do not match the trace export"
                )
        artifacts["trace_jsonl"] = {
            "file": "trace.jsonl",
            "sha256": digest,
            "bytes": size,
        }

    if product_observation_path is not None:
        observation_path = Path(product_observation_path).resolve()
        observation, observation_body = _read_json_object_bounded(
            observation_path,
            "product observation source",
            max_bytes=MAX_EVIDENCE_PACK_OBSERVATION_SOURCE_BYTES,
        )
        observation_schema = observation.get("schema")
        if not isinstance(observation_schema, str) or observation_schema not in {
            OBSERVATION_SCHEMA,
            SUBTRACTION_SCHEMA,
            BASELINE_SCHEMA,
            DRIFT_SCHEMA,
            COMPARISON_SCHEMA,
        }:
            raise ContractError(
                f"not a product-script observation document: {observation_path}"
            )
        portable = _portable_observation_summary(observation)
        if observation.get("schema") == OBSERVATION_SCHEMA:
            identity_and_provenance_coherent, safe_identity, _, _ = (
                _reconciled_script_identity(observation, current_required=True)
            )
            if identity_and_provenance_coherent is not True or safe_identity is None:
                raise ContractError(
                    "product observation script identity or provenance is not coherent"
                )
            if portable.get("run_id") != session["run_id"]:
                raise ContractError(
                    "product observation run id does not match the session"
                )
            if portable.get("chromium_revision") != session["chromium_revision"]:
                raise ContractError(
                    "product observation Chromium revision does not match the session"
                )
            try:
                _verified_observation_receipt(observation)
            except ContractError as exc:
                raise ContractError(
                    "product observation complete receipt is not coherent"
                ) from exc
            session_binding = {
                "status": "matched",
                "fields": ["run_id", "chromium_revision"],
            }
        elif observation_schema == SUBTRACTION_SCHEMA:
            if (
                observation.get("script_identity_coherent") is True
                and _reconciled_subtraction_script_identity(observation) is None
            ):
                raise ContractError(
                    "product subtraction identity does not match its arm pin"
                )
            if not _subtraction_provenance_is_coherent(observation):
                raise ContractError(
                    "product subtraction provenance does not match its arm pin/label"
                )
            try:
                _verified_subtraction_receipt(observation)
            except ContractError as exc:
                raise ContractError(
                    "product subtraction complete receipt is not coherent"
                ) from exc
            session_binding = {
                "status": "not-applicable-aggregate",
                "reason": "subtractions and baselines combine more than one arm",
            }
        elif observation_schema == BASELINE_SCHEMA:
            try:
                stable_surface = _verified_baseline_surface(observation)
            except ContractError as exc:
                raise ContractError(
                    "product baseline surface is not coherent"
                ) from exc
            try:
                _verified_baseline_noise_floor(observation, stable_surface)
            except ContractError as exc:
                raise ContractError(
                    "product baseline repeat receipt is not coherent"
                ) from exc
            try:
                _verified_baseline_receipt(observation)
            except ContractError as exc:
                raise ContractError(
                    "product baseline complete receipt is not coherent"
                ) from exc
            session_binding = {
                "status": "not-applicable-aggregate",
                "reason": "subtractions and baselines combine more than one arm",
            }
        elif observation_schema in {DRIFT_SCHEMA, COMPARISON_SCHEMA}:
            try:
                _verified_decision_receipt(observation)
            except ContractError as exc:
                raise ContractError(
                    "product decision receipt or semantics are not coherent"
                ) from exc
            session_binding = {
                "status": "not-applicable-aggregate",
                "reason": "subtractions and baselines combine more than one arm",
            }
        else:  # pragma: no cover - the schema check above rejects other values
            raise ContractError("unsupported product observation schema")
        reject_sensitive_keys(portable)
        body = _portable_json_bytes(
            portable,
            "product observation",
            max_bytes=MAX_EVIDENCE_PACK_JSON_ARTIFACT_BYTES,
        )
        require_staging_authority()
        publish_bytes_exclusive(
            out / "product-observation.json",
            body,
            maximum=MAX_EVIDENCE_PACK_JSON_ARTIFACT_BYTES,
            label="evidence pack product observation",
        )
        source_digest = _sha256_bytes(observation_body)
        source_bytes = len(observation_body)
        artifacts["product_observation"] = {
            "file": "product-observation.json",
            "sha256": _sha256_bytes(body),
            "bytes": len(body),
            "source_sha256": source_digest,
            "source_bytes": source_bytes,
            "session_binding": session_binding,
            "summary": portable,
        }

    manifest: dict[str, Any] = {
        "schema": EVIDENCE_PACK_SCHEMA,
        "created_at": _utc_now(),
        "run_id": session.get("run_id"),
        "artifacts": artifacts,
        "webre_intake_note": WEBRE_INTAKE_NOTE,
    }
    reject_sensitive_keys(manifest)
    manifest_body = _portable_json_bytes(
        manifest,
        "manifest",
        max_bytes=MAX_EVIDENCE_PACK_MANIFEST_BYTES,
    )
    blob = manifest_body.decode("utf-8").lower()
    for needle in ("cookie", "password", "authorization", "sensor", "ws://", "wss://"):
        if needle in blob:
            raise ContractError(f"evidence pack leaked sensitive material: {needle}")
    # Explicit CDP endpoint shapes
    if "cdp_endpoint" in blob and "[redacted" not in blob:
        # summary may say has_automation_endpoint true — that is fine; ban raw endpoints
        pass
    if "127.0.0.1:" in blob or "localhost:" in blob:
        raise ContractError(
            "evidence pack must not include loopback endpoint addresses"
        )

    manifest_path = out / EVIDENCE_PACK_MANIFEST
    require_staging_authority()
    publish_bytes_exclusive(
        manifest_path,
        manifest_body,
        maximum=MAX_EVIDENCE_PACK_MANIFEST_BYTES,
        label="evidence pack manifest",
    )
    return manifest


def build_evidence_pack(
    *,
    session_path: Path,
    out_dir: Path,
    browser_fact_path: Path | None = None,
    transport_fingerprint_path: Path | None = None,
    http2_fingerprint_path: Path | None = None,
    http2_evidence_path: Path | None = None,
    trace_export_path: Path | None = None,
    trace_jsonl_path: Path | None = None,
    product_observation_path: Path | None = None,
    include_session_copy: bool = False,
) -> dict[str, Any]:
    """Build a complete pack in staging and publish it as one directory."""
    for value, label, optional in (
        (session_path, "session", False),
        (out_dir, "output", False),
        (browser_fact_path, "browser fact", True),
        (transport_fingerprint_path, "transport fingerprint", True),
        (http2_fingerprint_path, "HTTP/2 fingerprint", True),
        (http2_evidence_path, "HTTP/2 evidence", True),
        (trace_export_path, "trace export", True),
        (trace_jsonl_path, "trace JSONL", True),
        (product_observation_path, "product observation", True),
    ):
        if (value is None and optional) or isinstance(value, Path):
            continue
        raise ContractError(f"evidence pack {label} path must be a Path")
    if not isinstance(include_session_copy, bool):
        raise ContractError("evidence pack session-copy policy must be boolean")
    for component in out_dir.parts:
        if component == out_dir.anchor or component == "..":
            continue
        if (
            component.endswith((".", " "))
            or has_windows_device_basename(component.split(".", 1)[0].rstrip(" "))
            or any(
                character in '<>:"\\|?*' or ord(character) < 32
                for character in component
            )
        ):
            raise ContractError("evidence pack output path has an invalid component")
    requested_destination = out_dir.absolute()
    if requested_destination.is_symlink():
        raise ContractError("evidence pack output directory must not be a symlink")
    try:
        requested_metadata = os.lstat(requested_destination)
    except FileNotFoundError:
        pass
    except OSError:
        raise ContractError("evidence pack output directory cannot be inspected") from None
    else:
        if stat.S_ISLNK(requested_metadata.st_mode) or (
            getattr(requested_metadata, "st_file_attributes", 0) & 0x400
        ):
            raise ContractError("evidence pack output directory must not be a reparse point")
    prepare_owned_directory_parent(
        requested_destination.parent, label="evidence pack output parent"
    )
    requested_parent_ancestry = directory_ancestry_binding(
        requested_destination.parent, label="evidence pack output parent"
    )
    requested_parent_identity = requested_parent_ancestry[-1]
    destination_parent = requested_destination.parent.resolve()
    destination = requested_destination.resolve()
    if (directory_ancestry_binding(requested_destination.parent,
                                   label="evidence pack output parent") != requested_parent_ancestry):
        raise ContractError("evidence pack output parent changed during resolution")
    if directory_identity(
        destination_parent, label="evidence pack output parent"
    ) != requested_parent_identity:
        raise ContractError("evidence pack output parent changed during resolution")
    if destination != destination_parent / requested_destination.name:
        raise ContractError("evidence pack output directory became a symlink or reparse point")
    destination_identity: DirectoryIdentity | None = None
    if destination.exists():
        if not destination.is_dir():
            raise ContractError("evidence pack output path must be a directory")
        if any(destination.iterdir()):
            raise ContractError("evidence pack output directory must be empty or new")
        destination_identity = directory_identity(
            destination,
            label="evidence pack output directory",
        )
    destination_parent_ancestry = directory_ancestry_binding(
        destination.parent,
        label="evidence pack output parent",
    )
    if destination_parent_ancestry[-1] != requested_parent_identity:
        raise ContractError("evidence pack output parent changed during resolution")
    if (directory_ancestry_binding(requested_destination.parent,
                                   label="evidence pack output parent") != requested_parent_ancestry):
        raise ContractError("evidence pack output parent changed during resolution")
    staging = Path(
        tempfile.mkdtemp(prefix=f".{destination.name}.staging-", dir=destination.parent)
    )
    staging_ancestry = directory_ancestry_binding(
        staging,
        label="evidence pack staging directory",
    )
    if (staging_ancestry[:-1] != destination_parent_ancestry
            or directory_ancestry_binding(requested_destination.parent,
                                          label="evidence pack output parent")
            != requested_parent_ancestry):
        raise ContractError("evidence pack staging authority changed")
    staging_identity = staging_ancestry[-1]

    def require_staging_authority() -> None:
        if (
            directory_ancestry_binding(requested_destination.parent,
                                       label="evidence pack output parent")
            != requested_parent_ancestry
            or directory_ancestry_binding(staging,
                                          label="evidence pack staging directory")
            != staging_ancestry
        ):
            raise ContractError("evidence pack staging authority changed")

    try:
        manifest = _build_evidence_pack_contents(
            session_path=session_path,
            out_dir=staging,
            require_staging_authority=require_staging_authority,
            browser_fact_path=browser_fact_path,
            transport_fingerprint_path=transport_fingerprint_path,
            http2_fingerprint_path=http2_fingerprint_path,
            http2_evidence_path=http2_evidence_path,
            trace_export_path=trace_export_path,
            trace_jsonl_path=trace_jsonl_path,
            product_observation_path=product_observation_path,
            include_session_copy=include_session_copy,
        )
        require_staging_authority()
        validated_manifest = load_evidence_pack_manifest(
            staging / EVIDENCE_PACK_MANIFEST
        )
        if validated_manifest != manifest:
            raise ContractError("evidence pack staging validation changed the manifest")
        expected_manifest_body = _portable_json_bytes(
            manifest, "manifest", max_bytes=MAX_EVIDENCE_PACK_MANIFEST_BYTES
        )
        published_manifest = read_bounded_control_snapshot_result(
            staging / EVIDENCE_PACK_MANIFEST,
            maximum=MAX_EVIDENCE_PACK_MANIFEST_BYTES,
            label="evidence pack staged manifest",
            require_single_link=True,
        )
        if (
            published_manifest.state != "complete"
            or published_manifest.body != expected_manifest_body
            or published_manifest.identity is None
        ):
            raise ContractError("evidence pack staging manifest changed before publication")
        require_staging_authority()
        if destination_identity is None:
            if os.path.lexists(destination):
                raise ContractError(
                    "evidence pack output path appeared during the build"
                )
        else:
            # The entry contract permits an existing empty directory. Do not
            # remove a directory merely because it currently occupies the same
            # pathname: it must still be the exact empty leaf inspected before
            # staging began. This preserves another process's replacement or
            # newly populated directory on a publication race.
            if destination.is_symlink() or not destination.is_dir():
                raise ContractError(
                    "evidence pack output directory changed during the build"
                )
            if (
                directory_identity(
                    destination,
                    label="evidence pack output directory",
                )
                != destination_identity
            ):
                raise ContractError(
                    "evidence pack output directory changed during the build"
                )
            if any(destination.iterdir()):
                raise ContractError(
                    "evidence pack output directory changed during the build"
                )
            require_staging_authority()
            remove_owned_directory_tree(
                destination,
                expected_identity=destination_identity,
                label="evidence pack output directory",
            )
        require_staging_authority()
        staging.replace(destination)
        def published_authority_held() -> bool:
            try:
                return (
                    directory_ancestry_binding(requested_destination.parent,
                                               label="evidence pack output parent")
                    == requested_parent_ancestry
                    and directory_ancestry_binding(destination,
                                                   label="evidence pack published directory")
                    == destination_parent_ancestry + (staging_identity,)
                )
            except ContractError:
                return False

        try:
            if not published_authority_held():
                raise ContractError("evidence pack publication authority changed")
            _rebind_published_evidence_pack(destination, manifest, expected_manifest_body)
            if not published_authority_held():
                raise ContractError("evidence pack publication authority changed")
        except (Exception, KeyboardInterrupt) as error:
            if not published_authority_held():
                raise ContractError("evidence pack publication authority changed") from error
            try:
                remove_control_conditionally(
                    destination / EVIDENCE_PACK_MANIFEST,
                    expected_body=published_manifest.body,
                    expected_identity=published_manifest.identity,
                    maximum=MAX_EVIDENCE_PACK_MANIFEST_BYTES,
                    label="evidence pack manifest",
                    require_handle_delete=True,
                )
            except (ContractError, OSError):
                raise ContractError(
                    "evidence pack publication validation failed; manifest cleanup incomplete"
                ) from error
            if isinstance(error, KeyboardInterrupt):
                raise
            raise ContractError("evidence pack publication validation failed") from error
        return manifest
    except BaseException as active_error:
        if isinstance(active_error, _EvidencePackArtifactCleanupError):
            raise ContractError(
                "evidence pack staging cleanup failed"
            ) from active_error
        try:
            if directory_identity(staging, label="evidence pack staging directory") is not None:
                if (
                    directory_ancestry_binding(requested_destination.parent,
                                               label="evidence pack output parent")
                    != requested_parent_ancestry
                    or directory_ancestry_binding(destination.parent,
                                                  label="evidence pack output parent")
                    != destination_parent_ancestry
                ):
                    raise ContractError("evidence pack staging ancestry changed")
                remove_owned_directory_tree(
                    staging,
                    expected_identity=staging_identity,
                    label="evidence pack staging directory",
                )
        except ContractError:
            raise ContractError(
                "evidence pack staging cleanup failed"
            ) from active_error
        raise


def load_evidence_pack_manifest(path: Path) -> dict[str, Any]:
    if not isinstance(path, Path):
        raise ContractError("evidence pack manifest path must be a Path")
    try:
        rendered_path = str(path)
        rendered_path.encode("utf-8", errors="strict")
    except (UnicodeError, ValueError):
        raise ContractError("evidence pack manifest path is invalid") from None
    if "\x00" in rendered_path:
        raise ContractError("evidence pack manifest path is invalid")
    requested_manifest = path
    requested_parent = requested_manifest.absolute().parent
    requested_parent_ancestry = directory_ancestry_binding(
        requested_parent, label="evidence pack manifest parent"
    )
    if requested_manifest.is_symlink():
        raise ContractError("evidence pack manifest must not be a symlink")
    manifest_path = requested_manifest.resolve()
    if directory_ancestry_binding(
        requested_parent, label="evidence pack manifest parent"
    ) != requested_parent_ancestry:
        raise ContractError("evidence pack manifest parent changed during resolution")
    document, manifest_body = _read_json_object_bounded(
        manifest_path,
        "manifest",
        max_bytes=MAX_EVIDENCE_PACK_MANIFEST_BYTES,
    )
    if not isinstance(document, dict) or document.get("schema") != EVIDENCE_PACK_SCHEMA:
        raise ContractError("unsupported evidence pack schema")
    if (
        set(document)
        != {
            "schema",
            "created_at",
            "run_id",
            "artifacts",
            "webre_intake_note",
        }
        or document.get("webre_intake_note") != WEBRE_INTAKE_NOTE
    ):
        raise ContractError("evidence pack manifest fields are invalid")
    if not isinstance(document.get("run_id"), str) or not re.fullmatch(
        r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", document["run_id"]
    ):
        raise ContractError("evidence pack run id is invalid")
    created_at = document.get("created_at")
    if not isinstance(created_at, str) or _portable_iso_timestamp(created_at) != created_at:
        raise ContractError("evidence pack creation timestamp is invalid")
    artifacts = document.get("artifacts")
    if not isinstance(artifacts, dict) or not artifacts:
        raise ContractError("evidence pack artifacts are invalid")
    allowed_artifacts = {
        "session",
        "browser_fact",
        "transport_fingerprint",
        "http2_fingerprint",
        "http2_evidence",
        "trace_export",
        "trace_jsonl",
        "product_observation",
    }
    if "session" not in artifacts or set(artifacts) - allowed_artifacts:
        raise ContractError("evidence pack artifact kinds are invalid")
    reject_sensitive_keys(document)

    bindings: list[tuple[str, dict[str, Any]]] = []
    for name, artifact in artifacts.items():
        if not isinstance(name, str) or not isinstance(artifact, dict):
            raise ContractError("evidence pack artifact entry is invalid")
        expected_fields = {
            "session": {"sha256", "bytes", "summary"},
            "browser_fact": {
                "file",
                "schema",
                "snapshot_id",
                "integrity_sha256",
                "source_kind",
                "source_integrity_sha256",
                "source_sha256",
                "source_bytes",
                "sha256",
                "bytes",
            },
            "transport_fingerprint": {
                "file",
                "sha256",
                "bytes",
                "source_sha256",
                "source_bytes",
                "session_binding",
                "summary",
            },
            "http2_fingerprint": {
                "file",
                "sha256",
                "bytes",
                "source_sha256",
                "source_bytes",
                "session_binding",
                "summary",
            },
            "http2_evidence": {
                "file",
                "sha256",
                "bytes",
                "source_sha256",
                "source_bytes",
                "session_binding",
                "summary",
            },
            "trace_export": {"file", "sha256", "bytes", "summary"},
            "trace_jsonl": {"file", "sha256", "bytes"},
            "product_observation": {
                "file",
                "sha256",
                "bytes",
                "source_sha256",
                "source_bytes",
                "session_binding",
                "summary",
            },
        }[name]
        if name == "session" and "redacted_copy" in artifact:
            expected_fields = {*expected_fields, "redacted_copy"}
        if name == "browser_fact" and "capture_method" in artifact:
            expected_fields = {*expected_fields, "capture_method"}
        if set(artifact) != expected_fields:
            raise ContractError(f"evidence pack {name} artifact fields are invalid")
        if name == "browser_fact" and "capture_method" in artifact:
            capture_method = artifact["capture_method"]
            if (
                not isinstance(capture_method, dict)
                or set(capture_method) != {"headless", "viewport_mode"}
                or type(capture_method["headless"]) is not bool
                or capture_method["viewport_mode"]
                != (
                    "synthetic-default"
                    if capture_method["headless"]
                    else "native-window"
                )
            ):
                raise ContractError("evidence pack browser fact capture method is invalid")
        if "file" in artifact:
            bindings.append((name, artifact))
        if "redacted_copy" in artifact:
            redacted_copy = artifact["redacted_copy"]
            if not isinstance(redacted_copy, dict):
                raise ContractError("evidence pack redacted-copy binding is invalid")
            bindings.append((name, redacted_copy))
        for digest_key in ("sha256", "source_sha256", "source_integrity_sha256"):
            if digest_key not in artifact:
                continue
            digest = artifact[digest_key]
            if (
                not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest)
            ):
                raise ContractError(f"evidence pack artifact {digest_key} is invalid")
        for size_key in ("bytes", "source_bytes"):
            if size_key not in artifact:
                continue
            size = artifact[size_key]
            if (
                isinstance(size, bool) or not isinstance(size, int) or size < 0
            ):
                raise ContractError(f"evidence pack artifact {size_key} is invalid")

    listed_files: set[str] = set()
    for artifact_kind, binding in bindings:
        filename = binding.get("file")
        digest = binding.get("sha256")
        size = binding.get("bytes")
        if (
            not isinstance(filename, str)
            or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", filename)
            or filename == manifest_path.name
            or filename in listed_files
            or not isinstance(digest, str)
            or not re.fullmatch(r"[0-9a-f]{64}", digest)
            or isinstance(size, bool)
            or not isinstance(size, int)
            or size < 0
        ):
            raise ContractError("evidence pack file binding is invalid")
        listed_files.add(filename)
        artifact_path = manifest_path.parent / filename
        # A portable pack must contain its bytes, not merely point at bytes in
        # another directory.  ``Path.is_file()`` follows symlinks, so a forged
        # pack could otherwise satisfy the digest binding while remaining
        # dependent on mutable state outside the pack directory.
        if artifact_path.is_symlink():
            raise ContractError(
                f"evidence pack artifact must not be a symlink: {filename}"
            )
        if not artifact_path.is_file():
            raise ContractError(f"evidence pack artifact is missing: {filename}")
        if artifact_path.stat().st_nlink != 1:
            raise ContractError(
                f"evidence pack artifact must not be hard-linked: {filename}"
            )
        maximum = (
            MAX_EVIDENCE_PACK_TRACE_JSONL_BYTES
            if artifact_kind == "trace_jsonl"
            else MAX_EVIDENCE_PACK_JSON_ARTIFACT_BYTES
        )
        if size > maximum:
            if artifact_kind == "trace_jsonl":
                raise ContractError(
                    "evidence pack trace JSONL artifact exceeds its byte limit"
                )
            json_label = {
                "session": "redacted session",
                "browser_fact": "browser fact",
                "transport_fingerprint": "transport fingerprint",
                "http2_fingerprint": "HTTP/2 fingerprint",
                "http2_evidence": "HTTP/2 evidence",
                "trace_export": "trace export",
                "product_observation": "product observation",
            }[artifact_kind]
            raise ContractError(
                f"evidence pack {json_label} exceeds the {maximum}-byte JSON limit"
            )
        actual_digest, actual_size = _sha256_stable_file(
            artifact_path,
            maximum=maximum,
            label=f"artifact {filename}",
        )
        if actual_size != size or not hmac.compare_digest(actual_digest, digest):
            raise ContractError(
                f"evidence pack artifact digest binding failed: {filename}"
            )

    directory_inventory = _inventory_evidence_pack_directory(manifest_path.parent)
    actual_entries = {
        name for name, _identity in directory_inventory[1] if name != manifest_path.name
    }
    if actual_entries != listed_files:
        raise ContractError("evidence pack contains unlisted or non-file artifacts")

    # A digest binds bytes, but the manifest also repeats selected facts from
    # those bytes for indexers. Verify the repeated view on every read so a
    # forged manifest cannot describe one run while binding another valid JSON
    # document. The builder performs these checks too; the loader is a separate
    # trust boundary and must not rely on how a directory says it was created.
    session_artifact = artifacts.get("session")
    if not isinstance(session_artifact, dict):
        raise ContractError("evidence pack session artifact is missing")
    session_summary = _validate_portable_session_summary(
        session_artifact.get("summary"), manifest_run_id=document["run_id"]
    )

    redacted_copy = session_artifact.get("redacted_copy")
    if isinstance(redacted_copy, dict):
        redacted = _load_bound_json_object(
            manifest_path.parent / redacted_copy["file"],
            "redacted session",
            redacted_copy,
        )
        reject_sensitive_keys(redacted)
        _validate_redacted_session_document(redacted, session_summary=session_summary)

    browser_fact_artifact = artifacts.get("browser_fact")
    if isinstance(browser_fact_artifact, dict):
        fact = validate_browser_fact_snapshot(
            _load_bound_json_object(
                manifest_path.parent / browser_fact_artifact["file"],
                "browser fact",
                browser_fact_artifact,
            )
        )
        _require_browser_fact_session_binding(
            fact,
            session_run_id=session_summary.get("run_id"),
            chromium_revision=session_summary.get("chromium_revision"),
            build_provenance=session_summary.get("build_provenance"),
            executable_sha256_16=session_summary.get("executable_sha256_16"),
        )
        if browser_fact_artifact.get(
            "capture_method"
        ) != _browser_fact_capture_method(fact):
            raise ContractError(
                "evidence pack browser fact capture method does not match "
                "the bound JSON"
            )
        expected = {
            "schema": fact.get("schema"),
            "snapshot_id": fact.get("snapshot_id"),
            "integrity_sha256": fact.get("integrity_sha256"),
            "source_kind": (fact.get("source") or {}).get("kind"),
        }
        actual = {key: browser_fact_artifact.get(key) for key in expected}
        if actual != expected:
            raise ContractError(
                "evidence pack browser-fact metadata does not match the bound JSON"
            )
        # The portable snapshot ID carries the original fact's integrity
        # digest prefix. The original bytes are not packed, but this shared
        # prefix must agree with the manifest's source claim.
        if fact["snapshot_id"] != (
            f"portable-{browser_fact_artifact['source_integrity_sha256'][:16]}"
        ):
            raise ContractError(
                "evidence pack browser-fact source integrity does not match the portable snapshot"
            )

    transport_artifact = artifacts.get("transport_fingerprint")
    if isinstance(transport_artifact, dict):
        transport = validate_transport_fingerprint(
            _load_bound_json_object(
                manifest_path.parent / transport_artifact["file"],
                "transport fingerprint",
                transport_artifact,
            ),
            require_build=True,
        )
        reject_sensitive_keys(transport)
        if canonical_json_bytes(transport_artifact.get("summary")) != canonical_json_bytes(
            _portable_transport_summary(transport)
        ):
            raise ContractError(
                "evidence pack transport summary does not match the bound JSON"
            )
        if transport_artifact.get("session_binding") != {
            "status": "matched",
            "fields": [
                "chromium_revision",
                "executable_sha256_16",
                "runtime_bundle_sha256_16",
            ],
        }:
            raise ContractError(
                "evidence pack transport session binding is invalid"
            )
        transport_build = transport["core_build"]
        if (
            session_summary.get("build_provenance") != "attested-browser-core"
            or transport_build.get("chromium_revision")
            != session_summary.get("chromium_revision")
            or transport_build.get("executable_sha256_16")
            != session_summary.get("executable_sha256_16")
            or transport_build.get("runtime_bundle_sha256_16")
            != session_summary.get("runtime_bundle_sha256_16")
        ):
            raise ContractError(
                "evidence pack transport fingerprint does not match the session summary"
            )

    loaded_http2: dict[str, Any] | None = None
    http2_artifact = artifacts.get("http2_fingerprint")
    if isinstance(http2_artifact, dict):
        http2 = validate_http2_fingerprint(
            _load_bound_json_object(
                manifest_path.parent / http2_artifact["file"],
                "HTTP/2 fingerprint",
                http2_artifact,
            ),
            require_build=True,
        )
        loaded_http2 = http2
        reject_sensitive_keys(http2)
        if canonical_json_bytes(http2_artifact.get("summary")) != canonical_json_bytes(
            _portable_http2_summary(http2)
        ):
            raise ContractError(
                "evidence pack HTTP/2 summary does not match the bound JSON"
            )
        if http2_artifact.get("session_binding") != {
            "status": "matched",
            "fields": [
                "chromium_revision",
                "executable_sha256_16",
                "runtime_bundle_sha256_16",
            ],
        }:
            raise ContractError("evidence pack HTTP/2 session binding is invalid")
        http2_build = http2["core_build"]
        if (
            session_summary.get("build_provenance") != "attested-browser-core"
            or http2_build.get("chromium_revision")
            != session_summary.get("chromium_revision")
            or http2_build.get("executable_sha256_16")
            != session_summary.get("executable_sha256_16")
            or http2_build.get("runtime_bundle_sha256_16")
            != session_summary.get("runtime_bundle_sha256_16")
        ):
            raise ContractError(
                "evidence pack HTTP/2 fingerprint does not match the session summary"
            )

    http2_evidence_artifact = artifacts.get("http2_evidence")
    if isinstance(http2_evidence_artifact, dict):
        evidence = validate_http2_capture_evidence(
            _load_bound_json_object(
                manifest_path.parent / http2_evidence_artifact["file"],
                "HTTP/2 evidence",
                http2_evidence_artifact,
            ),
            require_build=True,
        )
        if loaded_http2 is not None and evidence["fingerprint"] != loaded_http2:
            raise ContractError(
                "evidence pack HTTP/2 evidence fingerprint does not match standalone "
                "fingerprint"
            )
        reject_sensitive_keys(evidence)
        if canonical_json_bytes(
            http2_evidence_artifact.get("summary")
        ) != canonical_json_bytes(_portable_http2_evidence_summary(evidence)):
            raise ContractError(
                "evidence pack HTTP/2 evidence summary does not match the bound JSON"
            )
        if http2_evidence_artifact.get("session_binding") != {
            "status": "matched",
            "fields": [
                "chromium_revision",
                "executable_sha256_16",
                "runtime_bundle_sha256_16",
            ],
        }:
            raise ContractError("evidence pack HTTP/2 evidence session binding is invalid")
        evidence_build = evidence["fingerprint"]["core_build"]
        if (
            session_summary.get("build_provenance") != "attested-browser-core"
            or evidence_build.get("chromium_revision")
            != session_summary.get("chromium_revision")
            or evidence_build.get("executable_sha256_16")
            != session_summary.get("executable_sha256_16")
            or evidence_build.get("runtime_bundle_sha256_16")
            != session_summary.get("runtime_bundle_sha256_16")
        ):
            raise ContractError(
                "evidence pack HTTP/2 evidence does not match the session summary"
            )

    loaded_trace_export: dict[str, Any] | None = None
    trace_export_artifact = artifacts.get("trace_export")
    if isinstance(trace_export_artifact, dict):
        export = validate_trace_export_report(
            _load_bound_json_object(
                manifest_path.parent / trace_export_artifact["file"],
                "trace export",
                trace_export_artifact,
            )
        )
        if canonical_json_bytes(trace_export_artifact.get("summary")) != canonical_json_bytes(
            export
        ):
            raise ContractError(
                "evidence pack trace-export summary does not match the bound JSON"
            )
        if export.get("run_id") != session_summary.get("run_id") or export.get(
            "chromium_revision"
        ) != session_summary.get("chromium_revision"):
            raise ContractError(
                "evidence pack trace export does not match the session summary"
            )
        loaded_trace_export = export

    trace_jsonl_artifact = artifacts.get("trace_jsonl")
    if isinstance(trace_jsonl_artifact, dict):
        trace_path = manifest_path.parent / trace_jsonl_artifact["file"]
        trace_summary = validate_trace(trace_path)
        if trace_summary["run_id"] != session_summary.get("run_id"):
            raise ContractError("evidence pack trace JSONL does not match the session")
        if loaded_trace_export is not None:
            normalized = loaded_trace_export["normalized_trace"]
            if trace_jsonl_artifact["bytes"] != normalized[
                "bytes"
            ] or not hmac.compare_digest(
                trace_jsonl_artifact["sha256"], normalized["sha256"]
            ):
                raise ContractError(
                    "evidence pack trace JSONL does not match the trace export binding"
                )
            if trace_summary["events"] != normalized["events"]:
                raise ContractError(
                    "evidence pack trace JSONL event count does not match the trace export"
                )
            categories: dict[str, int] = {}
            with closing(iter_trace(trace_path)) as events:
                for event in events:
                    category = (event.get("provenance") or {}).get("trace_category")
                    if not isinstance(category, str):
                        raise ContractError(
                            "evidence pack trace JSONL lacks trace-category provenance"
                        )
                    categories[category] = categories.get(category, 0) + 1
            if dict(sorted(categories.items())) != normalized["trace_categories"]:
                raise ContractError(
                    "evidence pack trace JSONL categories do not match the trace export"
                )
    observation_artifact = artifacts.get("product_observation")
    if isinstance(observation_artifact, dict):
        portable = _load_bound_json_object(
            manifest_path.parent / observation_artifact["file"],
            "product observation",
            observation_artifact,
        )
        reject_sensitive_keys(portable)
        if (
            not isinstance(portable.get("schema"), str)
            or portable.get("schema")
            not in {
                OBSERVATION_SCHEMA,
                SUBTRACTION_SCHEMA,
                BASELINE_SCHEMA,
                DRIFT_SCHEMA,
                COMPARISON_SCHEMA,
            }
            or set(portable) - PORTABLE_OBSERVATION_KEYS
        ):
            raise ContractError(
                "evidence pack portable product-observation fields are invalid"
            )
        if _portable_observation_summary(portable) != portable:
            raise ContractError(
                "evidence pack portable product-observation values are invalid"
            )
        if canonical_json_bytes(observation_artifact.get("summary")) != canonical_json_bytes(
            portable
        ):
            raise ContractError(
                "evidence pack product-observation summary does not match the bound JSON"
            )
        binding = observation_artifact.get("session_binding")
        if portable["schema"] == OBSERVATION_SCHEMA:
            if binding != {
                "status": "matched",
                "fields": ["run_id", "chromium_revision"],
            }:
                raise ContractError(
                    "evidence pack product-observation session binding is invalid"
                )
            if portable.get("run_id") != session_summary.get("run_id") or portable.get(
                "chromium_revision"
            ) != session_summary.get("chromium_revision"):
                raise ContractError(
                    "evidence pack product observation does not match the session summary"
                )
        elif binding != {
            "status": "not-applicable-aggregate",
            "reason": "subtractions and baselines combine more than one arm",
        }:
            raise ContractError(
                "evidence pack aggregate observation binding is invalid"
            )
    # Metadata can retain the same identity after a fast in-place edit with
    # restored mtime. Rebind every artifact after the last semantic read, not
    # just the manifest and trace JSONL, before returning their summaries.
    for artifact_kind, binding in bindings:
        filename = binding["file"]
        maximum = (
            MAX_EVIDENCE_PACK_TRACE_JSONL_BYTES
            if artifact_kind == "trace_jsonl"
            else MAX_EVIDENCE_PACK_JSON_ARTIFACT_BYTES
        )
        final_digest, final_size = _sha256_stable_file(
            manifest_path.parent / filename,
            maximum=maximum,
            label=f"artifact {filename}",
        )
        if final_size != binding["bytes"] or not hmac.compare_digest(
            final_digest, binding["sha256"]
        ):
            raise ContractError(
                f"evidence pack {artifact_kind} changed during semantic validation"
            )
    try:
        _read_json_object_bounded(
            manifest_path,
            "manifest",
            max_bytes=MAX_EVIDENCE_PACK_MANIFEST_BYTES,
            expected_sha256=_sha256_bytes(manifest_body),
            expected_bytes=len(manifest_body),
        )
    except ContractError:
        raise ContractError("evidence pack manifest changed during validation") from None
    if _inventory_evidence_pack_directory(manifest_path.parent) != directory_inventory:
        raise ContractError("evidence pack directory changed during validation")
    if directory_ancestry_binding(
        requested_parent, label="evidence pack manifest parent"
    ) != requested_parent_ancestry:
        raise ContractError("evidence pack manifest parent changed during validation")
    if requested_manifest.is_symlink() or requested_manifest.resolve() != manifest_path:
        raise ContractError("evidence pack manifest path changed during validation")
    return document
