"""Auditable multi-identity research operations and disposable profile velocity.

Monorepo definition for preference over commercial anti-detect UX:
timed create → bind → ready → stop → dispose of disposable identities with
persona exclusivity and redaction-safe status (no cookies/proxy secrets).
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import statistics
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from .control_files import (
    BoundedJsonDirectoryInventory,
    BoundedControlSnapshot,
    decode_strict_json_bytes,
    inventory_bounded_json_directory,
    publish_json_exclusive,
    read_bounded_control_snapshot_result,
    remove_control_conditionally,
)
from .contracts import ContractError, reject_sensitive_keys
from .errors import (PersonaRealizationError, ProfileCreationRollbackError,
                     safe_failure_receipt as _safe_failure_receipt)
from .contracts import load_session_snapshot
from .owned_paths import (
    DirectoryIdentity,
    directory_ancestry_binding,
    directory_identity,
    prepare_owned_directory_parent,
)
from .numeric import is_finite_number
from .profiles import (
    DISPOSABLE_PROFILE_PREFIX,
    PROFILE_ID_RE,
    acquire_profile_lock,
    attach_network_route,
    attach_persona_identity_for_ops,
    create_profile,
    delete_disposable_profile,
    is_disposable_profile_id,
    list_profiles,
    load_profile,
    release_profile_lock,
)


OPS_BATCH_SCHEMA = "browser-core.multi-identity-ops/1"
VELOCITY_SCHEMA = "browser-core.profile-velocity/1"
COHERENCE_COHORT_SCHEMA = "browser-core.ops-coherence-cohort/1"

# B02. Headed Chromium arms are heavy; this is a research lab pool, not fleet scale.
# The cap is deliberately low so a typo cannot start dozens of browsers.
MAX_COHORT_PARALLEL = 8
PERSONA_CLAIM_SCHEMA = "browser-core.persona-claim/1"
CLAIM_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
MAX_PERSONA_CLAIM_BYTES = 4096
MAX_COHERENCE_EVALUATOR_BYTES = 2 * 1024 * 1024
MAX_COHERENCE_EVALUATOR_FILES = 32
MAX_COHERENCE_EVALUATOR_TOTAL_BYTES = 8 * 1024 * 1024
MAX_OPS_IDENTITIES = 128
EVALUATOR_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
SHA256_16_RE = re.compile(r"^[0-9a-f]{16}$")
# Host leaves Browser Core does not spoof from persona; lab fixtures must match host.
HOST_IDENTITY_ANCHOR_PATHS = (
    "window.platform",
    "window.hardwareConcurrency",
)


def _validated_batch_id(batch_id: str | None, *, prefix: str) -> str:
    if batch_id is None:
        return f"{prefix}-{uuid.uuid4().hex[:12]}"
    if (
        not isinstance(batch_id, str)
        or not CLAIM_ID_RE.fullmatch(batch_id)
        or not PROFILE_ID_RE.fullmatch(f"{DISPOSABLE_PROFILE_PREFIX}{batch_id}-000")
    ):
        raise ContractError("batch_id is invalid")
    return batch_id


def _require_owned_profile_deleted(value: Any, profile_id: str) -> None:
    if (
        not isinstance(value, dict)
        or value.get("id") != profile_id
        or value.get("state") != "deleted"
        or value.get("deleted") is not True
    ):
        raise ContractError("owned disposable profile deletion was not verified")


def is_lab_ops_fixture_persona(persona: dict[str, Any]) -> bool:
    """True when persona is a synthetic ops/lab fixture (not owned host capture)."""
    if not isinstance(persona, dict):
        return False
    provenance = persona.get("provenance") or {}
    source = str(provenance.get("source") or "")
    tags = {str(tag).casefold() for tag in (persona.get("tags") or ())}
    if source.startswith("ops-launch") or "ops-launch-fixture" in source:
        return True
    if source.startswith("ops-fixture:") or source.startswith("ops-fixture"):
        return True
    if "fixture" in tags and (
        source.startswith("ops-") or "ops" in tags or "fixture" in source.casefold()
    ):
        return True
    return False


def resolve_host_identity_anchors(workspace: Path) -> dict[str, Any]:
    """Host-true identity leaves from the best owned-capture-primary persona.

    Used to align lab-fixture contracts for surfaces Core does not rewrite
    (platform / hardwareConcurrency). Fail closed if no anchor exists.
    """
    from .personas import list_personas

    candidates: list[dict[str, Any]] = []
    for persona in list_personas(workspace):
        if persona.get("state") != "active":
            continue
        if is_lab_ops_fixture_persona(persona):
            continue
        if (persona.get("provenance") or {}).get("kind") != "owned-capture":
            continue
        expected = (persona.get("identity_contract") or {}).get("expected") or {}
        if not isinstance(expected, dict):
            continue
        if not all(path in expected for path in HOST_IDENTITY_ANCHOR_PATHS):
            continue
        # Skip kernel-probe matrix bulk if tags mark matrix (prefer real host primary).
        tags = {str(tag).casefold() for tag in (persona.get("tags") or ())}
        source = str((persona.get("provenance") or {}).get("source") or "")
        if "matrix" in tags or source.startswith("kernel-probe:"):
            continue
        candidates.append(persona)
    if not candidates:
        # Fallback: allow kernel-probe owned captures with both anchors.
        for persona in list_personas(workspace):
            if persona.get("state") != "active" or is_lab_ops_fixture_persona(persona):
                continue
            if (persona.get("provenance") or {}).get("kind") != "owned-capture":
                continue
            expected = (persona.get("identity_contract") or {}).get("expected") or {}
            if isinstance(expected, dict) and all(
                path in expected for path in HOST_IDENTITY_ANCHOR_PATHS
            ):
                candidates.append(persona)
    if not candidates:
        raise ContractError(
            "no owned-capture host identity anchors available "
            f"(need {', '.join(HOST_IDENTITY_ANCHOR_PATHS)} on a non-fixture persona)"
        )
    candidates.sort(
        key=lambda item: len(
            (item.get("identity_contract") or {}).get("expected") or {}
        ),
        reverse=True,
    )
    anchor = candidates[0]
    expected = anchor["identity_contract"]["expected"]
    leaves = {path: expected[path] for path in HOST_IDENTITY_ANCHOR_PATHS}
    report = {
        "schema": "browser-core.host-identity-anchors/1",
        "anchor_persona_id": anchor["id"],
        "paths": list(HOST_IDENTITY_ANCHOR_PATHS),
        "leaves": leaves,
    }
    reject_sensitive_keys(report)
    return report


def align_lab_fixture_identity_contract(
    persona: dict[str, Any],
    host_anchors: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Rewrite fixture expected host leaves to match owned host anchors.

    Owned / non-fixture personas are returned unchanged. Does not strip claims
    or skip identity evaluation — only corrects invented fixture host facts.
    """
    if not isinstance(persona, dict):
        raise ContractError("persona must be an object")
    leaves = host_anchors.get("leaves") if isinstance(host_anchors, dict) else None
    if not isinstance(leaves, dict) or not leaves:
        # Allow direct leaves map for tests.
        leaves = {
            path: host_anchors[path]
            for path in HOST_IDENTITY_ANCHOR_PATHS
            if isinstance(host_anchors, dict) and path in host_anchors
        }
    if not all(path in leaves for path in HOST_IDENTITY_ANCHOR_PATHS):
        raise ContractError("host anchors missing required identity leaves")

    contract = persona.get("identity_contract")
    if not isinstance(contract, dict):
        raise ContractError("persona identity_contract missing")
    expected_in = contract.get("expected")
    if not isinstance(expected_in, dict) or not expected_in:
        raise ContractError("persona identity_contract.expected missing")

    expected = dict(expected_in)
    changed: list[str] = []
    unchanged: list[str] = []
    if not is_lab_ops_fixture_persona(persona):
        meta = {
            "schema": "browser-core.fixture-identity-align/1",
            "aligned": False,
            "reason": "not-lab-fixture",
            "persona_id": persona.get("id"),
            "changed_paths": [],
            "unchanged_paths": sorted(expected.keys()),
        }
        reject_sensitive_keys(meta)
        return {"schema_version": 1, "expected": expected}, meta

    for path in HOST_IDENTITY_ANCHOR_PATHS:
        if path not in expected:
            continue
        if expected[path] != leaves[path]:
            expected[path] = leaves[path]
            changed.append(path)
        else:
            unchanged.append(path)

    out_contract = {"schema_version": 1, "expected": expected}
    meta = {
        "schema": "browser-core.fixture-identity-align/1",
        "aligned": bool(changed),
        "reason": "lab-fixture-host-leaves" if changed else "already-matched",
        "persona_id": persona.get("id"),
        "anchor_persona_id": host_anchors.get("anchor_persona_id"),
        "changed_paths": changed,
        "unchanged_paths": unchanged,
    }
    reject_sensitive_keys(meta)
    return out_contract, meta


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _bounded_profile_ids(values: Iterable[str], *, label: str) -> list[str]:
    if isinstance(values, (str, bytes, bytearray, dict)):
        raise ContractError(f"{label} must be an iterable of IDs")
    try:
        iterator = iter(values)
    except TypeError:
        raise ContractError(f"{label} must be an iterable of IDs") from None
    result: list[str] = []
    try:
        for value in iterator:
            if len(result) >= MAX_OPS_IDENTITIES:
                raise ContractError(
                    f"{label} exceeds the {MAX_OPS_IDENTITIES}-identity cap"
                )
            if not isinstance(value, str) or not PROFILE_ID_RE.fullmatch(value):
                raise ContractError(f"{label} contains an invalid ID")
            result.append(value)
    except BaseException:
        try:
            close = getattr(iterator, "close", None)
            if callable(close):
                close()
        except BaseException:  # Preserve the original rejection or interruption.
            pass
        raise
    return result


def _validate_route_map(value: dict[str, str] | None) -> dict[str, str] | None:
    if value is None:
        return None
    if not isinstance(value, dict) or len(value) > MAX_OPS_IDENTITIES:
        raise ContractError("network_route_by_persona must be a bounded mapping")
    try:
        snapshot = dict(value)
    except RuntimeError:
        raise ContractError("network_route_by_persona changed during validation") from None
    if len(snapshot) > MAX_OPS_IDENTITIES:
        raise ContractError("network_route_by_persona must be a bounded mapping")
    for key, route_id in snapshot.items():
        if (
            not isinstance(key, str)
            or not PROFILE_ID_RE.fullmatch(key)
            or not isinstance(route_id, str)
            or not PROFILE_ID_RE.fullmatch(route_id)
        ):
            raise ContractError("network_route_by_persona contains an invalid ID")
    return snapshot


def _validate_device_class(value: Any) -> str:
    if not isinstance(value, str) or not re.fullmatch(
        r"[A-Za-z][A-Za-z0-9_-]{0,31}", value
    ):
        raise ContractError("device_class is invalid")
    return value


def _claims_dir(workspace: Path) -> Path:
    from .personas import _persona_workspace_path

    if not isinstance(workspace, Path):
        raise ContractError("persona claim workspace must be a Path")
    return _persona_workspace_path(workspace) / "personas" / "claims"


def _claim_path(workspace: Path, persona_id: str) -> Path:
    from .personas import _persona_workspace_ancestry, load_persona

    workspace_before = _persona_workspace_ancestry(workspace)
    load_persona(workspace, persona_id)  # validate id exists
    if _persona_workspace_ancestry(workspace) != workspace_before:
        raise ContractError("persona claim workspace changed after validation")
    return _claims_dir(workspace) / f"{persona_id}.json"


def _validate_persona_claim(
    document: Any,
    *,
    persona_id: str,
) -> dict[str, Any]:
    if not isinstance(document, dict) or set(document) != {
        "schema",
        "persona_id",
        "claim_id",
        "claimed_at",
    }:
        raise ContractError("persona claim fields are invalid")
    if document.get("schema") != PERSONA_CLAIM_SCHEMA:
        raise ContractError("persona claim schema is invalid")
    if document.get("persona_id") != persona_id:
        raise ContractError("persona claim identity is invalid")
    claim_id = document.get("claim_id")
    if not isinstance(claim_id, str) or not CLAIM_ID_RE.fullmatch(claim_id):
        raise ContractError("persona claim_id is invalid")
    claimed_at = document.get("claimed_at")
    try:
        parsed = datetime.fromisoformat(
            claimed_at.replace("Z", "+00:00") if isinstance(claimed_at, str) else ""
        )
    except ValueError:
        parsed = None
    if (
        not isinstance(claimed_at, str)
        or len(claimed_at) > 64
        or parsed is None
        or parsed.utcoffset() is None
    ):
        raise ContractError("persona claim timestamp is invalid")
    return document


def _load_persona_claim(
    path: Path,
    *,
    persona_id: str,
) -> tuple[dict[str, Any] | None, BoundedControlSnapshot]:
    snapshot = read_bounded_control_snapshot_result(
        path,
        maximum=MAX_PERSONA_CLAIM_BYTES,
        label="persona claim",
        require_single_link=True,
    )
    if snapshot.state == "missing":
        return None, snapshot
    if snapshot.state != "complete" or snapshot.body is None:
        raise ContractError(f"persona claim is {snapshot.state}")
    document = decode_strict_json_bytes(snapshot.body, label="persona claim")
    return _validate_persona_claim(document, persona_id=persona_id), snapshot


def claim_persona_exclusive(
    workspace: Path,
    persona_id: str,
    claim_id: str,
    *,
    require_new: bool = False,
) -> dict[str, Any]:
    """Exclusive claim so two concurrent ops jobs cannot own the same persona."""
    from .personas import _persona_workspace_ancestry

    if not isinstance(claim_id, str) or not CLAIM_ID_RE.fullmatch(claim_id):
        raise ContractError("persona claim_id is invalid")
    if type(require_new) is not bool:
        raise ContractError("persona claim creation policy must be boolean")
    workspace_before = _persona_workspace_ancestry(workspace)

    def require_claim_workspace() -> None:
        if _persona_workspace_ancestry(workspace) != workspace_before:
            raise ContractError("persona claim workspace changed")

    path = _claim_path(workspace, persona_id)
    require_claim_workspace()
    prepare_owned_directory_parent(path.parent, label="persona claim parent")
    require_claim_workspace()
    document = {
        "schema": PERSONA_CLAIM_SCHEMA,
        "persona_id": persona_id,
        "claim_id": claim_id,
        "claimed_at": _utc_now(),
    }
    _validate_persona_claim(document, persona_id=persona_id)
    existing, _snapshot = _load_persona_claim(path, persona_id=persona_id)
    if existing is not None:
        if existing.get("claim_id") == claim_id and not require_new:
            require_claim_workspace()
            return existing
        raise ContractError(f"persona is already claimed exclusively: {persona_id}")
    require_claim_workspace()
    try:
        publish_json_exclusive(
            path,
            document,
            maximum=MAX_PERSONA_CLAIM_BYTES,
            label="persona claim",
        )
    except ContractError as exc:
        if "cleanup incomplete" in str(exc):
            raise
        observed, _raced_snapshot = _load_persona_claim(path, persona_id=persona_id)
        if observed is None:
            raise
        if observed is not None and observed.get("claim_id") == claim_id and not require_new:
            require_claim_workspace()
            return observed
        raise ContractError(f"persona is already claimed exclusively: {persona_id}")
    observed, _published_snapshot = _load_persona_claim(path, persona_id=persona_id)
    if observed != document:
        raise ContractError("persona claim changed after publication")
    require_claim_workspace()
    return document


def release_persona_claim(
    workspace: Path,
    persona_id: str,
    claim_id: str,
    *,
    missing_ok: bool = False,
) -> dict[str, Any]:
    from .personas import _persona_workspace_ancestry

    if not isinstance(claim_id, str) or not CLAIM_ID_RE.fullmatch(claim_id):
        raise ContractError("persona claim_id is invalid")
    if type(missing_ok) is not bool:
        raise ContractError("persona claim missing policy must be boolean")
    workspace_before = _persona_workspace_ancestry(workspace)

    def require_claim_workspace() -> None:
        if _persona_workspace_ancestry(workspace) != workspace_before:
            raise ContractError("persona claim workspace changed")

    path = _claim_path(workspace, persona_id)
    require_claim_workspace()
    existing, snapshot = _load_persona_claim(path, persona_id=persona_id)
    require_claim_workspace()
    if existing is None:
        if missing_ok:
            return {"persona_id": persona_id, "state": "absent", "released": False}
        raise ContractError(f"persona claim is missing: {persona_id}")
    if existing.get("claim_id") != claim_id:
        raise ContractError("refusing to release a persona claim owned by another job")
    assert snapshot.body is not None and snapshot.identity is not None
    require_claim_workspace()
    remove_control_conditionally(
        path,
        expected_body=snapshot.body,
        expected_identity=snapshot.identity,
        maximum=MAX_PERSONA_CLAIM_BYTES,
        label="persona claim",
        # `missing_ok` applies to the initial read only. Once a claim was
        # accepted, disappearance during removal must not claim release.
        missing_ok=False,
    )
    require_claim_workspace()
    return {"persona_id": persona_id, "state": "released", "released": True}


def redaction_safe_identity_status(
    *,
    profile_id: str,
    persona_id: str | None,
    state: str,
    timings_ms: dict[str, float] | None = None,
    error: str | None = None,
    session_run_id: str | None = None,
    network_route_id: str | None = None,
    network_route_sha256_16: str | None = None,
    substituted_for: str | None = None,
) -> dict[str, Any]:
    status = {
        "schema": "browser-core.identity-ops-status/1",
        "profile_id": profile_id,
        "persona_id": persona_id,
        "state": state,
        "session_run_id": session_run_id,
        "network_route_id": network_route_id,
        "network_route_sha256_16": network_route_sha256_16,
        "substituted_for": substituted_for,
        "timings_ms": timings_ms or {},
        "error": error,
    }
    reject_sensitive_keys(status)
    blob = json.dumps(status).lower()
    for needle in ("cookie", "password", "proxy", "authorization", "sensor"):
        if needle in blob:
            raise ContractError(f"ops status leaked sensitive material: {needle}")
    return status


def _median(values: list[float]) -> float | None:
    if not values:
        return None
    return float(statistics.median(values))


def discover_browser_core_launch_major(repository_root: Path) -> int:
    """Chromium major from the same upstream pin launch_evaluation uses."""
    from .upstream import verify_upstream

    if not isinstance(repository_root, Path):
        raise ContractError("repository_root must be a Path")
    manifest = verify_upstream(repository_root)
    version = manifest["chromium"]["version"]
    if not isinstance(version, str) or not re.fullmatch(
        r"[1-9][0-9]{0,3}(?:\..*)?", version
    ):
        raise ContractError("upstream Chromium version is invalid")
    return int(version.split(".", 1)[0])


def list_launch_compatible_persona_ids(
    workspace: Path,
    *,
    major: int,
    device_class: str = "desktop",
) -> list[str]:
    """Active personas that launch_evaluation can realize on Browser Core chrome."""
    from .personas import compatible_persona_catalog

    if isinstance(major, bool) or not isinstance(major, int) or major < 1:
        raise ContractError("launch major must be a positive integer")
    _validate_device_class(device_class)
    pool, _active_count = compatible_persona_catalog(
        workspace, engine="chromium", product="browser-core", major=major, device_class=device_class
    )
    return pool


def _classify_launch_compatible_personas(
    personas: list[dict[str, Any]], *, major: int, device_class: str
) -> list[str]:
    from .personas import persona_compatible

    return [
        persona["id"] for persona in personas
        if persona_compatible(
            persona, engine="chromium", product="browser-core",
            major=major, device_class=device_class,
        )
    ]


def cached_active_persona_count(workspace: Path) -> int | None:
    """Legacy accelerator API; no receipt is trusted and callers must reload.

    Metadata-only catalog caches and launch-compatible-pool.json were retired
    after the adversarial review. Existing receipt files are left untouched.
    """
    if not isinstance(workspace, Path):
        raise ContractError("persona workspace must be a Path")
    return None


def select_launch_compatible_personas(
    workspace: Path,
    count: int,
    *,
    major: int,
    device_class: str = "desktop",
    persona_ids: Iterable[str] | None = None,
) -> tuple[list[str], dict[str, Any]]:
    """Select personas for launch ops; fail closed on insufficient or incompatible IDs."""
    if (
        isinstance(count, bool)
        or not isinstance(count, int)
        or not 1 <= count <= MAX_OPS_IDENTITIES
    ):
        raise ContractError("persona selection count is outside the supported range")
    from .personas import compatible_persona_catalog

    if isinstance(major, bool) or not isinstance(major, int) or major < 1:
        raise ContractError("launch major must be a positive integer")
    _validate_device_class(device_class)
    requested: list[str] | None = None
    if persona_ids is not None:
        requested = _bounded_profile_ids(persona_ids, label="persona_ids")
        if len(requested) < count:
            raise ContractError("persona_ids shorter than requested count")
        requested = requested[:count]
        if len(requested) != len(set(requested)):
            raise ContractError("multi-identity batch persona IDs must be unique")
    # Classify and count the same freshly validated population. No later
    # inventory or mutable receipt may supply authority for these results.
    pool, active_total = compatible_persona_catalog(
        workspace, engine="chromium", product="browser-core", major=major, device_class=device_class
    )
    if requested is None:
        if len(pool) < count:
            raise ContractError(
                f"not enough launch-compatible personas for Browser Core major "
                f"{major}: need {count}, have {len(pool)}"
            )
        step = max(len(pool) // count, 1)
        selected = pool[::step][:count]
        if len(selected) < count:
            selected = pool[:count]
        skipped_incompatible = max(active_total - len(pool), 0)
    else:
        pool_set = set(pool)
        incompatible = [pid for pid in requested if pid not in pool_set]
        if incompatible:
            raise ContractError(
                "persona is not launch-compatible with this Browser Core build: "
                + ", ".join(incompatible[:8])
            )
        selected = requested
        skipped_incompatible = 0
    report = {
        "schema": "browser-core.ops-compatibility/1",
        "product": "browser-core",
        "engine": "chromium",
        "device_class": device_class,
        "executable_major": major,
        "active_personas": active_total,
        "compatible_pool": len(pool),
        "selected": len(selected),
        "skipped_incompatible": skipped_incompatible,
        "selected_persona_ids": list(selected),
    }
    reject_sensitive_keys(report)
    return selected, report


def ensure_direct_route_for_persona(workspace: Path, persona_id: str) -> str:
    """Create or reuse a geo-aligned direct network route for a persona.

    Credentials are never written (mode=direct). Policies require geo alignment.
    """
    from .network import add_network_route, build_network_route, load_network_route
    from .personas import load_persona
    from .profiles import PROFILE_ID_RE

    persona = load_persona(workspace, persona_id)
    geo = persona["geography"]
    country = str(geo["country"]).strip().lower()
    locale = str(geo["locale"]).strip().lower().replace("_", "-")
    raw = f"direct-{country}-{locale}"
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "-", raw).strip("-._")
    if not cleaned:
        cleaned = "direct-auto"
    route_id = cleaned[:64]
    if not PROFILE_ID_RE.fullmatch(route_id):
        raise ContractError(
            f"cannot derive a valid network route id for persona {persona_id}"
        )

    def require_auto_route(existing: dict[str, Any]) -> None:
        if existing.get("mode") != "direct":
            raise ContractError(
                f"network route {route_id} is not a direct route for {persona_id}"
            )
        policies = existing.get("policies") or {}
        if policies.get("require_alignment") is not True:
            raise ContractError(
                f"network route {route_id} does not require alignment for {persona_id}"
            )
        existing_geo = existing.get("geography") or {}
        for field in ("country", "locale", "timezone"):
            if (
                str(existing_geo.get(field, "")).casefold()
                != str(geo[field]).casefold()
            ):
                raise ContractError(
                    f"network route {route_id} exists with mismatched geography for {persona_id}"
                )

    try:
        existing = load_network_route(workspace, route_id)
    except ContractError:
        existing = None
    if existing is not None:
        require_auto_route(existing)
        return route_id
    # Missing route → create. A competing writer may publish this ID below.
    route = build_network_route(
        route_id=route_id,
        name=f"Direct {geo['country']} {geo['locale']}",
        geography={
            "country": geo["country"],
            "locale": geo["locale"],
            "timezone": geo["timezone"],
        },
        mode="direct",
        policies={"dns": "route", "webrtc": "route-only", "require_alignment": True},
    )
    try:
        add_network_route(workspace, route)
    except ContractError as exc:
        if "conflict" in str(exc).lower():
            require_auto_route(load_network_route(workspace, route_id))
            return route_id
        raise
    return route_id


def _resolve_route_for_persona(
    persona_id: str,
    network_route_id: str | None,
    network_route_by_persona: dict[str, str] | None,
) -> str | None:
    if network_route_by_persona and persona_id in network_route_by_persona:
        return network_route_by_persona[persona_id]
    return network_route_id


def _was_interrupted(error: BaseException) -> bool:
    """Cleanup wrappers must not turn cancellation into another launch slot."""
    seen: set[int] = set()
    while error is not None and id(error) not in seen:
        if isinstance(error, KeyboardInterrupt):
            return True
        seen.add(id(error))
        error = error.__cause__
    return False


def run_multi_identity_batch(
    workspace: Path,
    persona_ids: Iterable[str],
    *,
    batch_id: str | None = None,
    ready_mode: str = "dry-run",
    executable: Path | None = None,
    repository_root: Path | None = None,
    network_route_id: str | None = None,
    network_route_by_persona: dict[str, str] | None = None,
    network_auto: bool = False,
    device_class: str = "desktop",
    enforce_launch_compatibility: bool | None = None,
    allow_persona_substitution: bool = False,
) -> dict[str, Any]:
    """Create, bind, ready, stop, and dispose disposable multi-identity batch.

    ready_mode:
      - dry-run: create+claim+attach(+optional network)+lock then unlock.
        No browser process; stop_to_dispose is dispose-only (no session stop).
      - launch: full Browser Core evaluation launch, then stop_session, then dispose.
        create_to_ready ends when the session is running; stop_to_dispose includes
        stop_session + delete (stop is not counted in create_to_ready).
        Launch mode enforces persona_compatible(product=browser-core) by default.

    allow_persona_substitution: when the launch readiness gate rejects an
    auto-selected persona because its identity claims cannot be realized on
    this build ("selected persona was not realized"), skip that persona,
    dispose its partial profile/claim and retry the same slot with the next
    launch-compatible persona. Skips are recorded in the receipt. Explicitly
    requested persona_ids batches in run_profile_velocity_batch stay strict.
    Direct callers must explicitly opt in here. Only PersonaRealizationError
    permits replacement; cleanup must complete before another attempt starts.
    """
    if not isinstance(workspace, Path):
        raise ContractError("multi-identity workspace must be a Path")
    batch = _validated_batch_id(batch_id, prefix="batch")
    if not isinstance(ready_mode, str) or ready_mode not in {"dry-run", "launch"}:
        raise ContractError("ready_mode must be dry-run or launch")
    if not isinstance(network_auto, bool):
        raise ContractError("network_auto must be boolean")
    if enforce_launch_compatibility is not None and not isinstance(
        enforce_launch_compatibility, bool
    ):
        raise ContractError("enforce_launch_compatibility must be boolean")
    if not isinstance(allow_persona_substitution, bool):
        raise ContractError("allow_persona_substitution must be boolean")
    if executable is not None and not isinstance(executable, Path):
        raise ContractError("multi-identity executable must be a Path")
    if repository_root is not None and not isinstance(repository_root, Path):
        raise ContractError("multi-identity repository_root must be a Path")
    if ready_mode == "launch" and (
        executable is None or repository_root is None
    ):
        raise ContractError("launch ready_mode requires executable and repository_root")
    _validate_device_class(device_class)
    if network_route_id is not None and (
        not isinstance(network_route_id, str)
        or not PROFILE_ID_RE.fullmatch(network_route_id)
    ):
        raise ContractError("network_route_id is invalid")
    network_route_by_persona = _validate_route_map(network_route_by_persona)
    if network_auto and (
        network_route_id is not None or network_route_by_persona is not None
    ):
        raise ContractError(
            "network_auto cannot be combined with explicit network_route_id maps"
        )
    personas = _bounded_profile_ids(persona_ids, label="persona_ids")
    if len(personas) < 1:
        raise ContractError("multi-identity batch requires at least one persona")
    if len(personas) != len(set(personas)):
        raise ContractError("multi-identity batch persona IDs must be unique")
    compatibility: dict[str, Any] | None = None
    enforce = (
        enforce_launch_compatibility
        if enforce_launch_compatibility is not None
        else ready_mode == "launch" or executable is not None
    )
    if enforce:
        if repository_root is None:
            raise ContractError(
                "launch-compatible persona filtering requires repository_root"
            )
        major = discover_browser_core_launch_major(repository_root)
        personas, compatibility = select_launch_compatible_personas(
            workspace,
            len(personas),
            major=major,
            device_class=device_class,
            persona_ids=personas,
        )

    substitution_pool: list[str] = []
    initially_selected = set(personas)
    substitution_pool_loaded = False
    substitution_selection_ms = 0.0
    substitution_pool_error: str | None = None
    substituted_for: dict[int, str] = {}
    skipped_personas: list[dict[str, Any]] = []
    substitution_enabled = (
        allow_persona_substitution
        and ready_mode == "launch"
        and repository_root is not None
    )
    if network_auto:
        network_route_by_persona = {
            persona_id: ensure_direct_route_for_persona(workspace, persona_id)
            for persona_id in personas
        }

    identities: list[dict[str, Any]] = []
    attempts: list[dict[str, Any]] = []
    stop_receipts: list[dict[str, Any]] = []
    cleanup_failures: list[dict[str, str]] = []
    cleanup_receipts: list[dict[str, Any]] = []
    teardown_attempts: list[dict[str, Any]] = []
    owned_profiles: set[str] = set()
    owned_claims: set[tuple[str, str]] = set()
    uncertain_profile_cleanup: set[str] = set()
    interrupted = False
    create_ready_ms: list[float] = []
    stop_dispose_ms: list[float] = []
    errors: list[str] = []
    # session paths keyed by profile_id for launch-mode phase-2 stop
    session_paths: dict[str, Path] = {}
    bound_routes: dict[str, tuple[str, str]] = {}

    def cleanup_identity(profile_id: str, persona_id: str, claim_id: str,
                         phase: str) -> dict[str, Any]:
        nonlocal interrupted
        started = time.perf_counter()
        failures: list[dict[str, str]] = []
        # A colliding batch/profile name is not ownership. Only clean resources
        # successfully acquired by this invocation. Preserve exclusivity while
        # a profile is retained (in particular if launch abort left it locked).
        if profile_id in owned_profiles:
            try:
                _require_owned_profile_deleted(
                    delete_disposable_profile(workspace, profile_id), profile_id
                )
                owned_profiles.remove(profile_id)
            except (Exception, KeyboardInterrupt) as exc:
                interrupted = interrupted or _was_interrupted(exc)
                failures.append({"stage": "delete-profile", "error": _safe_failure_receipt(exc)})
        if profile_id not in owned_profiles and (persona_id, claim_id) in owned_claims:
            try:
                release_persona_claim(workspace, persona_id, claim_id)
                owned_claims.remove((persona_id, claim_id))
            except (Exception, KeyboardInterrupt) as exc:
                interrupted = interrupted or _was_interrupted(exc)
                failures.append({"stage": "release-claim", "error": _safe_failure_receipt(exc)})
        for failure in failures:
            cleanup_failures.append({"profile_id": profile_id, "persona_id": persona_id,
                                     "claim_id": claim_id, "phase": phase, **failure})
            errors.append(f"{phase}-cleanup {profile_id}: {failure['error']}")
        receipt = {
            "profile_id": profile_id, "persona_id": persona_id, "phase": phase,
            "elapsed_ms": (time.perf_counter() - started) * 1000,
            "completed": not failures and profile_id not in owned_profiles
                and (persona_id, claim_id) not in owned_claims,
            "errors": failures,
        }
        cleanup_receipts.append(receipt)
        return receipt

    # Phase 1: create → claim → bind → optional network → ready.
    # A persona whose identity claims the launch gate cannot realize on this
    # build may be substituted from a finite pool; each candidate is used at
    # most once, and every attempt and cleanup outcome is retained.
    index = 0
    while index < len(personas):
        persona_id = personas[index]
        profile_id = f"{DISPOSABLE_PROFILE_PREFIX}{batch}-{index:03d}"
        claim_id = f"{batch}-{persona_id}"
        t_create0 = time.perf_counter()
        timings: dict[str, float] = {}
        session_run_id: str | None = None
        state = "failed"
        error: str | None = None
        route_id = _resolve_route_for_persona(
            persona_id, network_route_id, network_route_by_persona
        )
        route_sha16: str | None = None
        try:
            if network_auto and route_id is None:
                route_id = ensure_direct_route_for_persona(workspace, persona_id)
            t0 = time.perf_counter()
            create_profile(workspace, profile_id, name=f"ops disposable {index}")
            owned_profiles.add(profile_id)
            timings["create_ms"] = (time.perf_counter() - t0) * 1000

            t0 = time.perf_counter()
            claim_persona_exclusive(
                workspace, persona_id, claim_id, require_new=True
            )
            owned_claims.add((persona_id, claim_id))
            timings["claim_ms"] = (time.perf_counter() - t0) * 1000

            t0 = time.perf_counter()
            attach_persona_identity_for_ops(workspace, profile_id, persona_id)
            timings["bind_ms"] = (time.perf_counter() - t0) * 1000

            if route_id is not None:
                t0 = time.perf_counter()
                document = attach_network_route(workspace, profile_id, route_id)
                timings["network_attach_ms"] = (time.perf_counter() - t0) * 1000
                binding = document.get("network_route") or {}
                route_sha16 = binding.get("sha256_16")
                bound_routes[profile_id] = (route_id, route_sha16 or "")
                # Fail closed: re-load profile to ensure binding persisted without secrets.
                reloaded = load_profile(workspace, profile_id)
                if reloaded.get("network_route") != binding:
                    raise ContractError("network route binding did not persist")

            if ready_mode == "dry-run":
                run_id = f"{batch}-ready-{index:03d}"
                lock_path = acquire_profile_lock(workspace, profile_id, run_id)
                release_profile_lock(lock_path, run_id)
                session_run_id = run_id
                state = "ready"
            else:
                if executable is None or repository_root is None:
                    raise ContractError(
                        "launch ready_mode requires executable and repository_root"
                    )
                from .launcher import EvaluationLaunch, launch_evaluation

                path, session = launch_evaluation(
                    EvaluationLaunch(
                        executable=executable,
                        workspace=workspace,
                        headless=True,
                        timeout_seconds=45.0,
                        profile_id=profile_id,
                        trace_mode="off",
                    ),
                    repository_root,
                )
                session_paths[profile_id] = Path(path)
                session_run_id = session.get("run_id")
                _require_launched_route_receipt(session, route_id, route_sha16)
                state = "running"
            # create→ready ends at ready/running — never includes stop_session
            timings["create_to_ready_ms"] = (time.perf_counter() - t_create0) * 1000
            create_ready_ms.append(timings["create_to_ready_ms"])
            attempts.append({
                "profile_id": profile_id, "persona_id": persona_id,
                "outcome": "ready", "elapsed_ms": timings["create_to_ready_ms"],
                "error": None, "unrealized_fields": [],
            })
        except (Exception, KeyboardInterrupt) as exc:  # noqa: BLE001
            interrupted = interrupted or _was_interrupted(exc)
            if isinstance(exc, ProfileCreationRollbackError):
                # The constructor owned a directory but could not confirm its
                # rollback. Do not guess ownership or delete a replacement;
                # explicitly retain this uncertainty for operator recovery.
                uncertain_profile_cleanup.add(profile_id)
                cleanup_failures.append({"profile_id": profile_id, "persona_id": persona_id,
                    "claim_id": claim_id, "phase": "creation", "stage": "create-profile-rollback",
                    "error": _safe_failure_receipt(exc)})
            failed_attempt = {
                "profile_id": profile_id, "persona_id": persona_id,
                "outcome": "interrupted" if _was_interrupted(exc) else "failed",
                "elapsed_ms": (time.perf_counter() - t_create0) * 1000,
                "error": _safe_failure_receipt(exc),
                "unrealized_fields": _unrealized_claim_fields(exc)
                if isinstance(exc, PersonaRealizationError) else [],
            }
            attempts.append(failed_attempt)
            if (
                substitution_enabled
                and isinstance(exc, PersonaRealizationError)
            ):
                # Auto-selected persona cannot be realized on this build: record
                # the skip, clean the partial slot and retry with the next
                # launch-compatible persona. Never silences other failures.
                skip = {
                        "persona_id": persona_id,
                        "slot": profile_id,
                        "reason": _safe_failure_receipt(exc),
                        "unrealized_fields": _unrealized_claim_fields(exc),
                        "attempt_elapsed_ms": failed_attempt["elapsed_ms"],
                        "cleanup_errors": [],
                    }
                skipped_personas.append(skip)
                cleanup = cleanup_identity(profile_id, persona_id, claim_id, "substitution")
                skip["cleanup_errors"] = cleanup["errors"]
                skip["cleanup_elapsed_ms"] = cleanup["elapsed_ms"]
                skip["cleanup_completed"] = cleanup["completed"]
                if skip["cleanup_completed"]:
                    if not substitution_pool_loaded:
                        # A successful batch needs no replacement catalog. On
                        # the first mismatch, clean the failed slot before
                        # reading a fresh, verified pool. A failed lookup stays
                        # in the receipt and cannot escape owned cleanup.
                        substitution_pool_loaded = True
                        t_selection = time.perf_counter()
                        try:
                            substitution_major = discover_browser_core_launch_major(repository_root)
                            substitution_pool = [candidate for candidate in list_launch_compatible_persona_ids(
                                workspace, major=substitution_major, device_class=device_class
                            ) if candidate not in initially_selected]
                        except (Exception, KeyboardInterrupt) as selection_error:
                            interrupted = interrupted or _was_interrupted(selection_error)
                            substitution_pool_error = _safe_failure_receipt(selection_error)
                            errors.append(f"substitution-selection: {substitution_pool_error}")
                        finally:
                            substitution_selection_ms += (time.perf_counter() - t_selection) * 1000
                    if substitution_pool and not interrupted:
                        substituted_for.setdefault(index, persona_id)
                        personas[index] = substitution_pool.pop(0)
                        continue
            error = _safe_failure_receipt(exc)
            errors.append(f"{profile_id}: {error}")
            state = "failed"

        identities.append(
            redaction_safe_identity_status(
                profile_id=profile_id,
                persona_id=persona_id,
                state=state,
                timings_ms=timings,
                error=error,
                session_run_id=session_run_id,
                network_route_id=route_id if route_id is not None else None,
                network_route_sha256_16=route_sha16,
                substituted_for=substituted_for.get(index),
            )
        )
        index += 1
        if interrupted:
            break

    # Phase 2: stop (launch only) → dispose + release claims
    for index, persona_id in enumerate(personas):
        profile_id = f"{DISPOSABLE_PROFILE_PREFIX}{batch}-{index:03d}"
        claim_id = f"{batch}-{persona_id}"
        item = next(
            (row for row in identities if row["profile_id"] == profile_id), None
        )
        if item is None:
            continue
        if item["state"] == "failed":
            if profile_id in session_paths:
                # A launch can return a session and then fail receipt validation.
                # Prove that exact run stopped before deleting its owned profile.
                try:
                    from .lifecycle import stop_session

                    stop_receipt = _validated_ops_stop_receipt(
                        stop_session(session_paths[profile_id], timeout_seconds=30.0),
                        expected_run_id=item["session_run_id"],
                    )
                    stop_receipts.append({"profile_id": profile_id, **stop_receipt})
                except (Exception, KeyboardInterrupt) as exc:  # noqa: BLE001
                    interrupted = interrupted or _was_interrupted(exc)
                    receipt = _safe_failure_receipt(exc)
                    cleanup_failures.append({
                        "profile_id": profile_id, "persona_id": persona_id,
                        "claim_id": claim_id, "phase": "failed-identity",
                        "stage": "stop-session", "error": receipt,
                    })
                    errors.append(f"failed-identity-cleanup {profile_id}: {receipt}")
                    item["state"] = "dispose-failed"
                    continue
            cleanup_identity(profile_id, persona_id, claim_id, "failed-identity")
            continue

        t_stop0 = time.perf_counter()
        try:
            if ready_mode == "launch" and profile_id in session_paths:
                from .lifecycle import stop_session

                t0 = time.perf_counter()
                stop_receipt = _validated_ops_stop_receipt(
                    stop_session(
                        session_paths[profile_id],
                        timeout_seconds=30.0,
                    ),
                    expected_run_id=item["session_run_id"],
                )
                stop_receipts.append({"profile_id": profile_id, **stop_receipt})
                item["timings_ms"]["stop_ms"] = (time.perf_counter() - t0) * 1000
                item["state"] = "stopped"
            elif ready_mode == "dry-run":
                # No session to stop; dispose-only teardown is intentional.
                item["timings_ms"]["stop_ms"] = 0.0

            cleanup = cleanup_identity(profile_id, persona_id, claim_id, "teardown")
            if not cleanup["completed"]:
                raise ContractError("multi-identity resource cleanup incomplete")
            elapsed = (time.perf_counter() - t_stop0) * 1000
            stop_dispose_ms.append(elapsed)
            item["state"] = "disposed"
            item["timings_ms"]["stop_to_dispose_ms"] = elapsed
        except (Exception, KeyboardInterrupt) as exc:  # noqa: BLE001
            interrupted = interrupted or _was_interrupted(exc)
            receipt = _safe_failure_receipt(exc)
            errors.append(f"stop/dispose {profile_id}: {receipt}")
            item["state"] = "dispose-failed"
            item["error"] = receipt
        finally:
            teardown_attempts.append({
                "profile_id": profile_id,
                "elapsed_ms": (time.perf_counter() - t_stop0) * 1000,
                "completed": item["state"] == "disposed",
            })

    cleanup_inventory_verified = not uncertain_profile_cleanup
    try:
        leftovers = sorted(item["id"] for item in list_profiles(workspace)
                           if item["id"] in owned_profiles)
    except (Exception, KeyboardInterrupt) as exc:
        interrupted = interrupted or _was_interrupted(exc)
        errors.append(f"cleanup-inventory: {_safe_failure_receipt(exc)}")
        cleanup_inventory_verified = False
        leftovers = sorted(owned_profiles)
    lifecycle_note = (
        "dry-run ready_mode: create→bind→lock→unlock then dispose; no browser process "
        "and no stop_session (stop_to_dispose is dispose-only)."
        if ready_mode == "dry-run"
        else (
            "launch ready_mode: create→bind→launch (create_to_ready ends at running), "
            "then stop_session + dispose (stop_to_dispose includes stop)."
        )
    )
    report = {
        "schema": OPS_BATCH_SCHEMA,
        "batch_id": batch,
        "ready_mode": ready_mode,
        "lifecycle_note": lifecycle_note,
        "network_auto": network_auto,
        "network_route_configured": bool(
            network_route_id or network_route_by_persona or network_auto
        ),
        "network_routes_bound": len(bound_routes),
        "compatibility": compatibility,
        "persona_substitution": {
            "enabled": substitution_enabled,
            "pool_loaded": substitution_pool_loaded,
            "pool_load_error": substitution_pool_error,
            "skipped": skipped_personas,
        },
        "requested": len(personas),
        "identities": identities,
        "attempts": attempts,
        "stop_receipts": stop_receipts,
        "cleanup_failures": cleanup_failures,
        "cleanup_receipts": cleanup_receipts,
        "cleanup_inventory_verified": cleanup_inventory_verified,
        "uncertain_profile_cleanup": sorted(uncertain_profile_cleanup),
        "unreleased_claims": [{"persona_id": pid, "claim_id": cid}
                              for pid, cid in sorted(owned_claims)],
        "interrupted": interrupted,
        "not_started": len(personas) - len(identities),
        "teardown_attempts": teardown_attempts,
        "errors": errors,
        "orphans": leftovers,
        "passed": len(errors) == 0 and not leftovers and not owned_claims and not interrupted,
        "timing": {
            "create_to_ready_median_ms": _median(create_ready_ms),
            "stop_to_dispose_median_ms": _median(stop_dispose_ms),
            "create_to_ready_samples_ms": create_ready_ms,
            "stop_to_dispose_samples_ms": stop_dispose_ms,
            "all_attempts_ms": sum(attempt["elapsed_ms"] for attempt in attempts),
            "rejected_attempts_ms": sum(
                attempt["elapsed_ms"] for attempt in attempts if attempt["outcome"] != "ready"
            ),
            "substitution_cleanup_ms": sum(skip["cleanup_elapsed_ms"] for skip in skipped_personas),
            "substitution_selection_ms": substitution_selection_ms,
            "failed_identity_cleanup_ms": sum(receipt["elapsed_ms"] for receipt in cleanup_receipts
                                              if receipt["phase"] == "failed-identity"),
            "teardown_attempts_ms": sum(attempt["elapsed_ms"] for attempt in teardown_attempts),
        },
        "completed_at": _utc_now(),
    }
    reject_sensitive_keys(report)
    return report


def run_profile_velocity_batch(
    workspace: Path,
    *,
    count: int = 10,
    persona_ids: Iterable[str] | None = None,
    ready_mode: str = "dry-run",
    executable: Path | None = None,
    repository_root: Path | None = None,
    target_median_ms: float = 30_000.0,
    network_route_id: str | None = None,
    network_route_by_persona: dict[str, str] | None = None,
    network_auto: bool = False,
    device_class: str = "desktop",
    allow_persona_substitution: bool = True,
) -> dict[str, Any]:
    """N disposable identities with velocity thresholds for preference evidence."""
    if not isinstance(workspace, Path):
        raise ContractError("multi-identity workspace must be a Path")
    if (
        isinstance(count, bool)
        or not isinstance(count, int)
        or not 1 <= count <= MAX_OPS_IDENTITIES
    ):
        raise ContractError("velocity count is outside the supported range")
    if not is_finite_number(target_median_ms) or not (
        0 < target_median_ms <= 86_400_000
    ):
        raise ContractError("velocity target must be finite in (0, 86400000]")
    if not isinstance(network_auto, bool):
        raise ContractError("network_auto must be boolean")
    if network_auto and (
        network_route_id is not None or network_route_by_persona is not None
    ):
        raise ContractError(
            "network_auto cannot be combined with explicit network_route_id maps"
        )
    if not isinstance(allow_persona_substitution, bool):
        raise ContractError("allow_persona_substitution must be boolean")
    if not isinstance(ready_mode, str) or ready_mode not in {"dry-run", "launch"}:
        raise ContractError("ready_mode must be dry-run or launch")
    from .personas import list_personas

    enforce = ready_mode == "launch" or executable is not None
    compatibility: dict[str, Any] | None = None
    if enforce:
        if repository_root is None:
            raise ContractError(
                "launch-compatible velocity selection requires repository_root"
            )
        major = discover_browser_core_launch_major(repository_root)
        selected, compatibility = select_launch_compatible_personas(
            workspace,
            count,
            major=major,
            device_class=device_class,
            persona_ids=persona_ids,
        )
    elif persona_ids is None:
        active = [
            item["id"]
            for item in list_personas(workspace)
            if item.get("state") == "active"
        ]
        if len(active) < count:
            raise ContractError("not enough active personas for velocity batch")
        step = max(len(active) // count, 1)
        selected = active[::step][:count]
        if len(selected) < count:
            selected = active[:count]
    else:
        selected = _bounded_profile_ids(persona_ids, label="persona_ids")
        if len(selected) < count:
            raise ContractError("persona_ids shorter than velocity count")
        selected = selected[:count]

    batch = run_multi_identity_batch(
        workspace,
        selected,
        ready_mode=ready_mode,
        executable=executable,
        repository_root=repository_root,
        network_route_id=network_route_id,
        network_route_by_persona=network_route_by_persona,
        network_auto=network_auto,
        device_class=device_class,
        allow_persona_substitution=allow_persona_substitution and persona_ids is None,
        # Selection already enforced for launch; avoid double-check noise.
        enforce_launch_compatibility=False if enforce else None,
    )
    # Attach selection report when we filtered at velocity layer.
    if compatibility is not None:
        batch = {**batch, "compatibility": compatibility}
    create_med = batch["timing"]["create_to_ready_median_ms"]
    dispose_med = batch["timing"]["stop_to_dispose_median_ms"]
    create_ok = create_med is not None and create_med <= target_median_ms
    dispose_ok = dispose_med is not None and dispose_med <= target_median_ms
    velocity = {
        "schema": VELOCITY_SCHEMA,
        "definition": (
            "Auditable multi-identity research operations: timed disposable "
            "create→ready and stop→dispose lifecycle under exclusive persona claims."
        ),
        "count": count,
        "ready_mode": ready_mode,
        "lifecycle_note": batch.get("lifecycle_note"),
        "target_median_ms": target_median_ms,
        "create_to_ready_median_ms": create_med,
        "stop_to_dispose_median_ms": dispose_med,
        "create_to_ready_meets_target": create_ok,
        "stop_to_dispose_meets_target": dispose_ok,
        "functional_batch_passed": batch["passed"],
        "orphans": batch["orphans"],
        "batch_id": batch["batch_id"],
        "network_auto": network_auto,
        "network_route_configured": batch.get("network_route_configured"),
        "compatibility": compatibility or batch.get("compatibility"),
        "meets_velocity_preference_bar": bool(
            ready_mode == "launch" and batch["passed"] and create_ok and dispose_ok
        ),
        "environmental_ceiling_note": None
        if (create_ok and dispose_ok)
        else (
            "Median exceeded target on this host; functional batch success is "
            "recorded without inventing lower timings."
            if batch["passed"]
            else "Functional batch failed; see multi-account ops errors."
        ),
        "ops_batch": batch,
        "completed_at": _utc_now(),
    }
    reject_sensitive_keys(velocity)
    return velocity


def _unrealized_claim_fields(exc: BaseException) -> list[str]:
    """Field names the launch gate reported as unrealized (never their values).

    The launcher's realization failure lists claim keys between the first
    ':' and the first ';'. Anything unparsable yields an empty list; the
    redacted receipt remains the fallback diagnostic.
    """
    try:
        segment = str(exc).split(":", 1)[-1].split(";", 1)[0]
    except Exception:
        return []
    fields = [
        token.strip()
        for token in segment.split(",")
        if token.strip() and CLAIM_ID_RE.fullmatch(token.strip())
    ]
    return fields


def _validated_ops_stop_receipt(
    value: Any,
    *,
    expected_run_id: str,
) -> dict[str, Any]:
    from .lifecycle import validate_stopped_session_receipt

    try:
        retained = validate_stopped_session_receipt(
            value,
            expected_run_id=expected_run_id,
        )
        if retained["identity_protected"] is not True:
            raise ContractError("multi-identity session stop was not verified")
        return retained
    except ContractError:
        raise ContractError("multi-identity session stop was not verified") from None


def _require_launched_route_receipt(
    session: Any,
    route_id: str | None,
    route_sha16: str | None,
) -> None:
    network = session.get("network") if isinstance(session, dict) else None
    if route_id is None:
        if network is not None:
            raise ContractError("launched session route differs from attached binding")
        return
    if (
        not isinstance(network, dict)
        or network.get("route_id") != route_id
        or network.get("route_sha256_16") != route_sha16
    ):
        raise ContractError("launched session route differs from attached binding")


def _bounded_count(value: Any, label: str) -> int | None:
    if value is None:
        return None
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not 0 <= value <= 1_000_000
    ):
        raise ContractError(f"coherence evaluator {label} is invalid")
    return value


def _validate_coherence_summary(value: Any) -> dict[str, Any]:
    required = {
        "evaluator_id",
        "status",
        "verdict",
        "passed_checks",
        "failed_checks",
        "unavailable_checks",
        "failed_check_ids",
        "unavailable_check_ids",
    }
    optional = {
        "identity_passed_claims",
        "identity_failed_claims",
        "identity_unavailable_claims",
        "collector_checkset_sha256_16",
    }
    if (
        not isinstance(value, dict)
        or not required.issubset(value)
        or set(value) - (required | optional)
    ):
        raise ContractError("coherence summary fields are invalid")
    evaluator_id = value.get("evaluator_id")
    if not isinstance(evaluator_id, str) or not EVALUATOR_ID_RE.fullmatch(evaluator_id):
        raise ContractError("coherence summary evaluator identity is invalid")
    if not isinstance(value.get("status"), str) or value["status"] not in {"ok", "error"}:
        raise ContractError("coherence summary status is invalid")
    if not isinstance(value.get("verdict"), str) or value["verdict"] not in {"pass", "fail", "unknown"}:
        raise ContractError("coherence summary verdict is invalid")
    if value["status"] == "error" and value["verdict"] != "unknown":
        raise ContractError("coherence summary status and verdict are inconsistent")
    normalized = dict(value)
    for field in (
        "passed_checks",
        "failed_checks",
        "unavailable_checks",
        "identity_passed_claims",
        "identity_failed_claims",
        "identity_unavailable_claims",
    ):
        normalized[field] = _bounded_count(value.get(field), field)
    for field in ("failed_check_ids", "unavailable_check_ids"):
        identifiers = value.get(field)
        if (
            not isinstance(identifiers, list)
            or len(identifiers) > 512
            or any(
                not isinstance(item, str) or not EVALUATOR_ID_RE.fullmatch(item)
                for item in identifiers
            )
            or len(identifiers) != len(set(identifiers))
        ):
            raise ContractError(f"coherence summary {field} is invalid")
        normalized[field] = sorted(identifiers)
    for count_field, ids_field in (
        ("failed_checks", "failed_check_ids"),
        ("unavailable_checks", "unavailable_check_ids"),
    ):
        count = normalized[count_field]
        if count is not None and count != len(normalized[ids_field]):
            raise ContractError("coherence summary check counts are inconsistent")
    if evaluator_id == "controlled_coherence" and normalized["verdict"] == "pass":
        if any(
            normalized[field] is None
            for field in ("passed_checks", "failed_checks", "unavailable_checks")
        ):
            raise ContractError("controlled coherence pass is missing check counts")
        if normalized["passed_checks"] == 0:
            raise ContractError("controlled coherence pass has no passed checks")
        if any(
            normalized[field] not in (None, 0)
            for field in (
                "failed_checks",
                "identity_failed_claims",
                "identity_unavailable_claims",
            )
        ):
            raise ContractError("controlled coherence pass has nonzero failure counts")
    digest = value.get("collector_checkset_sha256_16")
    if digest is not None and (
        not isinstance(digest, str) or not SHA256_16_RE.fullmatch(digest)
    ):
        raise ContractError("coherence summary checkset digest is invalid")
    normalized["collector_checkset_sha256_16"] = digest
    return normalized


def _summarize_coherence_evaluator(
    doc: dict[str, Any],
    *,
    expected_id: str,
) -> dict[str, Any]:
    """Closed redaction-safe projection of one browser-eval evaluator artifact."""
    if not isinstance(doc, dict) or set(doc) != {
        "evaluator_id",
        "name",
        "url_host",
        "categories",
        "tier",
        "status",
        "started_at",
        "duration_ms",
        "verdict",
        "score",
        "score_scale",
        "metrics",
        "findings",
        "error",
        "screenshot",
    }:
        raise ContractError("coherence evaluator fields are invalid")
    evaluator_id = doc.get("evaluator_id")
    if (
        not isinstance(evaluator_id, str)
        or not EVALUATOR_ID_RE.fullmatch(evaluator_id)
        or evaluator_id != expected_id
    ):
        raise ContractError("coherence evaluator identity is invalid")
    status = doc.get("status")
    if not isinstance(status, str) or status not in {"ok", "error"}:
        raise ContractError("coherence evaluator status is invalid")
    verdict = doc.get("verdict")
    if not isinstance(verdict, str) or verdict not in {"pass", "fail", "unknown"}:
        raise ContractError("coherence evaluator verdict is invalid")
    if status == "error" and verdict != "unknown":
        raise ContractError("coherence evaluator status and verdict are inconsistent")
    metrics = doc.get("metrics")
    if not isinstance(metrics, dict) or len(metrics) > 512:
        raise ContractError("coherence evaluator metrics are invalid")
    checks = metrics.get("checks", {})
    if not isinstance(checks, dict) or len(checks) > 512:
        raise ContractError("coherence evaluator checks are invalid")
    normalized_checks: dict[str, bool | None] = {}
    for key, value in checks.items():
        if (
            not isinstance(key, str)
            or not EVALUATOR_ID_RE.fullmatch(key)
            or (value is not None and not isinstance(value, bool))
        ):
            raise ContractError("coherence evaluator check is invalid")
        normalized_checks[key] = value
    passed_checks = _bounded_count(metrics.get("passed_checks"), "passed_checks")
    if (
        evaluator_id == "controlled_coherence"
        and passed_checks is not None
        and passed_checks != sum(value is True for value in normalized_checks.values())
    ):
        raise ContractError("coherence evaluator passed check count is inconsistent")
    failed_ids = sorted(
        key for key, value in normalized_checks.items() if value is False
    )
    unavailable_ids = sorted(
        key for key, value in normalized_checks.items() if value is None
    )
    digest = metrics.get("collector_checkset_sha256_16")
    if digest is not None and (
        not isinstance(digest, str) or not SHA256_16_RE.fullmatch(digest)
    ):
        raise ContractError("coherence evaluator checkset digest is invalid")
    summary = {
        "evaluator_id": evaluator_id,
        "status": status,
        "verdict": verdict,
        "passed_checks": passed_checks,
        "failed_checks": _bounded_count(metrics.get("failed_checks"), "failed_checks"),
        "unavailable_checks": _bounded_count(
            metrics.get("unavailable_checks"), "unavailable_checks"
        ),
        "identity_passed_claims": _bounded_count(
            metrics.get("identity_passed_claims"), "identity_passed_claims"
        ),
        "identity_failed_claims": _bounded_count(
            metrics.get("identity_failed_claims"), "identity_failed_claims"
        ),
        "identity_unavailable_claims": _bounded_count(
            metrics.get("identity_unavailable_claims"),
            "identity_unavailable_claims",
        ),
        "failed_check_ids": failed_ids,
        "unavailable_check_ids": unavailable_ids,
        "collector_checkset_sha256_16": digest,
    }
    reject_sensitive_keys(summary)
    return _validate_coherence_summary(summary)


@dataclass(frozen=True)
class _CoherenceEvaluatorBinding:
    output_identity: DirectoryIdentity | None
    inventory: BoundedJsonDirectoryInventory
    content_digests: tuple[tuple[str, bytes], ...]


def _coherence_evaluator_inventory(eval_dir: Path) -> BoundedJsonDirectoryInventory:
    try:
        return inventory_bounded_json_directory(
            eval_dir,
            maximum_entries=MAX_COHERENCE_EVALUATOR_FILES * 2,
            maximum_files=MAX_COHERENCE_EVALUATOR_FILES,
            maximum_file_bytes=MAX_COHERENCE_EVALUATOR_BYTES,
            maximum_total_bytes=MAX_COHERENCE_EVALUATOR_TOTAL_BYTES,
            label="coherence evaluator output",
            require_json_only=True,
        )
    except ContractError as exc:
        message = str(exc)
        if "per-file byte limit" in message:
            raise ContractError(
                f"coherence evaluator output exceeds {MAX_COHERENCE_EVALUATOR_BYTES} bytes"
            ) from None
        if "too many JSON files" in message:
            raise ContractError(
                "coherence evaluator output contains too many files"
            ) from None
        raise


def _require_coherence_evaluator_binding(
    out_dir: Path, binding: _CoherenceEvaluatorBinding
) -> None:
    eval_dir = out_dir / "evaluators"
    if (
        _coherence_evaluator_inventory(eval_dir) != binding.inventory
        or directory_identity(out_dir, label="coherence eval output directory")
        != binding.output_identity
    ):
        raise ContractError("coherence evaluator output changed during ingestion")
    expected_digests = dict(binding.content_digests)
    for name, expected_identity in binding.inventory.files:
        snapshot = read_bounded_control_snapshot_result(
            eval_dir / name,
            maximum=MAX_COHERENCE_EVALUATOR_BYTES,
            label="coherence evaluator output",
            require_single_link=True,
        )
        if (
            snapshot.state != "complete"
            or snapshot.body is None
            or snapshot.identity != expected_identity
            or hashlib.sha256(snapshot.body).digest() != expected_digests[name]
        ):
            raise ContractError("coherence evaluator output changed during ingestion")
    if (
        _coherence_evaluator_inventory(eval_dir) != binding.inventory
        or directory_identity(out_dir, label="coherence eval output directory")
        != binding.output_identity
    ):
        raise ContractError("coherence evaluator output changed during ingestion")


def _load_coherence_evaluator_arms(
    out_dir: Path,
    *,
    requested_ids: set[str] | None,
    binding_out: list[_CoherenceEvaluatorBinding] | None = None,
) -> list[dict[str, Any]]:

    eval_dir = out_dir / "evaluators"
    output_identity_before = directory_identity(
        out_dir, label="coherence eval output directory"
    )
    before = _coherence_evaluator_inventory(eval_dir)
    if before.state == "missing":
        binding = _CoherenceEvaluatorBinding(output_identity_before, before, ())
        _require_coherence_evaluator_binding(out_dir, binding)
        if binding_out is not None:
            binding_out.append(binding)
        return []
    if output_identity_before is None:
        raise ContractError("coherence evaluator output directory is missing")
    arms: list[dict[str, Any]] = []
    seen: set[str] = set()
    content_digests: dict[str, bytes] = {}
    for name, expected_identity in before.files:
        evaluator_id = name[:-5]
        if (
            not EVALUATOR_ID_RE.fullmatch(evaluator_id)
            or evaluator_id in seen
            or (requested_ids is not None and evaluator_id not in requested_ids)
        ):
            raise ContractError("coherence evaluator output identity is invalid")
        path = eval_dir / name
        snapshot = read_bounded_control_snapshot_result(
            path,
            maximum=MAX_COHERENCE_EVALUATOR_BYTES,
            label="coherence evaluator output",
            require_single_link=True,
        )
        if snapshot.state != "complete" or snapshot.body is None:
            raise ContractError(f"coherence evaluator output is {snapshot.state}")
        if snapshot.identity != expected_identity:
            raise ContractError("coherence evaluator output changed during ingestion")
        content_digests[name] = hashlib.sha256(snapshot.body).digest()
        document = decode_strict_json_bytes(
            snapshot.body,
            label="coherence evaluator output",
        )
        arms.append(_summarize_coherence_evaluator(document, expected_id=evaluator_id))
        seen.add(evaluator_id)
    binding = _CoherenceEvaluatorBinding(
        output_identity_before, before, tuple(sorted(content_digests.items()))
    )
    # The second bounded byte read catches same-size rewrites with restored
    # metadata; its closing inventory catches additions during those reads.
    _require_coherence_evaluator_binding(out_dir, binding)
    if requested_ids is not None and seen != requested_ids:
        raise ContractError("coherence evaluator output is incomplete")
    if binding_out is not None:
        binding_out.append(binding)
    return arms


def _parse_evaluator_selection(evaluators: Any) -> set[str] | None:
    if not isinstance(evaluators, str) or not evaluators.strip():
        raise ContractError("evaluators must be a bounded non-empty string")
    try:
        encoded = evaluators.encode("utf-8", errors="strict")
    except UnicodeEncodeError:
        raise ContractError("evaluators must be a bounded non-empty string") from None
    if len(encoded) > 2048 or any(
        byte < 32 or byte == 127 for byte in encoded
    ):
        raise ContractError("evaluators must be a bounded non-empty string")
    selections = [item.strip() for item in evaluators.split(",") if item.strip()]
    if evaluators.strip().casefold() == "all":
        return None
    if (
        not 1 <= len(selections) <= 16
        or len(selections) != len(set(selections))
        or any(not EVALUATOR_ID_RE.fullmatch(item) for item in selections)
    ):
        raise ContractError("evaluator selection is invalid")
    return set(selections)


def run_session_coherence_eval(
    session_file: Path,
    *,
    out_dir: Path,
    evaluators: str = "controlled_coherence",
    workspace: Path | None = None,
    timeout_seconds: float = 300.0,
) -> dict[str, Any]:
    """Run browser-eval against an active Core session via external-cdp.

    Returns a redaction-safe arm result. Call sites (and tests) may monkeypatch
    this function at the multi_identity_ops module boundary.
    """
    import subprocess
    import sys

    requested_ids = _parse_evaluator_selection(evaluators)
    if not is_finite_number(timeout_seconds) or not 0 < timeout_seconds <= 600:
        raise ContractError("coherence eval timeout must be finite in (0, 600]")
    if not isinstance(out_dir, Path):
        raise ContractError("coherence eval out_dir must be a Path")
    if not isinstance(session_file, Path):
        raise ContractError("coherence eval session_file must be a Path")
    if workspace is not None and not isinstance(workspace, Path):
        raise ContractError("coherence eval workspace must be a Path")
    out_dir = out_dir.absolute()
    # browser-eval refuses to overwrite an existing run directory — only ensure parent.
    if os.path.lexists(out_dir):
        raise ContractError("coherence eval out_dir already exists")
    session_file = session_file.absolute()
    workspace_before = None
    if workspace is not None:
        from .personas import _persona_workspace_ancestry, _persona_workspace_path

        workspace_before = _persona_workspace_ancestry(workspace)
        workspace = _persona_workspace_path(workspace)

    def require_workspace_authority() -> None:
        if (
            workspace_before is not None
            and _persona_workspace_ancestry(workspace) != workspace_before
        ):
            raise ContractError("coherence eval workspace changed")

    session_parent_ancestry = directory_ancestry_binding(
        session_file.parent, label="coherence eval session parent"
    )
    session_snapshot = load_session_snapshot(session_file)
    session = session_snapshot.document

    def require_session_unchanged() -> None:
        try:
            current = load_session_snapshot(session_file)
        except ContractError:
            raise ContractError("coherence eval session changed during evaluation") from None
        if (
            current.body != session_snapshot.body
            or current.identity != session_snapshot.identity
        ):
            raise ContractError("coherence eval session changed during evaluation")

    require_workspace_authority()
    if session.get("state") != "active":
        raise ContractError("coherence eval requires an active session")
    if workspace is not None:
        expected_session = workspace / "sessions" / f"{session['run_id']}.json"
        if session_file.resolve() != expected_session:
            raise ContractError(
                "coherence eval session is outside its workspace authority"
            )
    def require_session_parent_authority() -> None:
        try:
            current = directory_ancestry_binding(
                session_file.parent, label="coherence eval session parent"
            )
        except ContractError:
            raise ContractError("coherence eval session parent changed") from None
        if current != session_parent_ancestry:
            raise ContractError("coherence eval session parent changed")

    require_session_parent_authority()
    if out_dir.resolve() == session_file.resolve():
        raise ContractError("coherence eval input and output paths must differ")
    prepare_owned_directory_parent(out_dir.parent, label="coherence eval output parent")
    output_parent_identity = directory_identity(
        out_dir.parent, label="coherence eval output parent"
    )
    output_parent_ancestry = directory_ancestry_binding(
        out_dir.parent, label="coherence eval output parent"
    )
    if output_parent_ancestry[-1] != output_parent_identity:
        raise ContractError("coherence eval output parent changed during evaluation")

    def require_output_parent_authority() -> None:
        try:
            current_identity = directory_identity(
                out_dir.parent, label="coherence eval output parent"
            )
            current_ancestry = directory_ancestry_binding(
                out_dir.parent, label="coherence eval output parent"
            )
        except ContractError:
            raise ContractError("coherence eval output parent changed during evaluation") from None
        if (
            current_identity != output_parent_identity
            or current_ancestry != output_parent_ancestry
        ):
            raise ContractError("coherence eval output parent changed during evaluation")

    env = os.environ.copy()
    require_session_parent_authority()
    env["BROWSER_CORE_SESSION_FILE"] = str(session_file.resolve())
    if workspace is not None:
        env["BROWSER_CORE_WORKSPACE"] = str(workspace)
    require_workspace_authority()
    require_session_parent_authority()
    require_output_parent_authority()

    # Prefer installed package; fall back to sibling browser-eval tree.
    cmd = [
        sys.executable,
        "-m",
        "browser_eval",
        "run",
        "--backend",
        "external-cdp",
        "--channel",
        "chromium",
        "--evaluators",
        evaluators,
        "--out",
        str(out_dir),
    ]
    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=env,
            timeout=float(timeout_seconds),
            check=False,
        )
    except subprocess.TimeoutExpired:
        raise ContractError("coherence eval timed out") from None
    except (OSError, ValueError) as exc:
        raise ContractError(
            f"coherence eval could not start ({type(exc).__name__})"
        ) from None
    if isinstance(proc.returncode, bool) or not isinstance(proc.returncode, int):
        raise ContractError("coherence eval process status is invalid")
    require_workspace_authority()
    require_session_parent_authority()
    require_session_unchanged()
    require_session_parent_authority()
    require_workspace_authority()
    require_output_parent_authority()
    evaluator_bindings: list[_CoherenceEvaluatorBinding] = []
    arms = _load_coherence_evaluator_arms(
        out_dir, requested_ids=requested_ids, binding_out=evaluator_bindings
    )
    if len(evaluator_bindings) != 1:
        raise ContractError("coherence evaluator output binding is missing")

    controlled = next(
        (arm for arm in arms if arm.get("evaluator_id") == "controlled_coherence"),
        None,
    )
    controlled_requested = requested_ids is None or "controlled_coherence" in requested_ids
    primary = controlled if controlled_requested else (arms[0] if arms else None)
    if proc.returncode != 0:
        eval_error = "eval-failed"
    elif primary is None and controlled_requested and arms:
        eval_error = "no-controlled-coherence-output"
    elif primary is None:
        eval_error = "no-evaluator-output"
    else:
        eval_error = None
    result = {
        "schema": "browser-core.session-coherence-eval/1",
        "session_run_id": session["run_id"],
        "eval_exit": proc.returncode,
        "evaluators_requested": "all"
        if requested_ids is None
        else sorted(requested_ids),
        "arms": arms,
        "primary": primary,
        "error": eval_error,
        "diagnostic_sha256_16": hashlib.sha256(
            f"exit={proc.returncode};arms={len(arms)}".encode("ascii")
        ).hexdigest()[:16],
    }
    reject_sensitive_keys(result)
    require_session_parent_authority()
    require_session_unchanged()
    require_session_parent_authority()
    require_workspace_authority()
    require_output_parent_authority()
    require_workspace_authority()
    require_session_parent_authority()
    # Final bounded read ties the returned summaries to the saved bytes and
    # inventory after the session and parent checks above. This is sequential,
    # not an atomic guarantee against a later non-cooperating mutation.
    _require_coherence_evaluator_binding(out_dir, evaluator_bindings[0])
    require_output_parent_authority()
    require_session_parent_authority()
    require_session_unchanged()
    require_session_parent_authority()
    require_workspace_authority()
    require_output_parent_authority()
    return result


def run_ops_coherence_cohort(
    workspace: Path,
    *,
    count: int = 3,
    persona_ids: Iterable[str] | None = None,
    executable: Path,
    repository_root: Path,
    evaluators: str = "controlled_coherence",
    headless: bool = False,
    network_auto: bool = False,
    network_route_id: str | None = None,
    network_route_by_persona: dict[str, str] | None = None,
    device_class: str = "desktop",
    batch_id: str | None = None,
    out_dir: Path | None = None,
    evaluate_session: Any | None = None,
    parallel: int = 1,
) -> dict[str, Any]:
    """N disposable launch-compatible identities → owned coherence → stop → dispose (B10).

    Default headless=False (headed): residual lab showed headless fails
    headless_token_absent; multi-identity non-regression should use headed arms.
    evaluate_session, when provided, replaces run_session_coherence_eval (tests).

    parallel (B02) bounds how many arms run concurrently; 1 keeps the historical
    strictly-sequential behaviour. Each arm owns a distinct persona, disposable
    profile, exclusivity claim, profile lock, gateway lease, and OS-assigned CDP
    port, so arms do not share mutable state; results are aggregated serially and
    reported in arm order regardless of completion order.
    """
    if isinstance(count, bool) or not isinstance(count, int) or count < 1:
        raise ContractError("coherence cohort count must be a positive integer")
    if count > MAX_OPS_IDENTITIES:
        raise ContractError("coherence cohort count exceeds the identity cap")
    if isinstance(parallel, bool) or not isinstance(parallel, int) or parallel < 1:
        raise ContractError("coherence cohort parallel must be a positive integer")
    if parallel > MAX_COHORT_PARALLEL:
        raise ContractError(
            f"coherence cohort parallel exceeds the hard cap of {MAX_COHORT_PARALLEL}"
        )
    if not isinstance(headless, bool):
        raise ContractError("coherence cohort headless must be boolean")
    if not isinstance(network_auto, bool):
        raise ContractError("coherence cohort network_auto must be boolean")
    if not isinstance(workspace, Path):
        raise ContractError("coherence cohort workspace must be a Path")
    batch = _validated_batch_id(batch_id, prefix="coh")
    if not isinstance(executable, Path):
        raise ContractError("coherence cohort executable must be a Path")
    if not isinstance(repository_root, Path):
        raise ContractError("coherence cohort repository_root must be a Path")
    if out_dir is not None and not isinstance(out_dir, Path):
        raise ContractError("coherence cohort out_dir must be a Path")
    if evaluate_session is not None and not callable(evaluate_session):
        raise ContractError("coherence cohort evaluator must be callable")
    _validate_device_class(device_class)
    network_route_by_persona = _validate_route_map(network_route_by_persona)
    if network_route_id is not None and (
        not isinstance(network_route_id, str)
        or not PROFILE_ID_RE.fullmatch(network_route_id)
    ):
        raise ContractError("network_route_id is invalid")
    if network_auto and (
        network_route_id is not None or network_route_by_persona is not None
    ):
        raise ContractError(
            "network_auto cannot be combined with explicit network_route_id maps"
        )
    selected_evaluators = _parse_evaluator_selection(evaluators)
    if selected_evaluators is not None and "controlled_coherence" not in selected_evaluators:
        raise ContractError("coherence cohort requires controlled_coherence evaluator")

    major = discover_browser_core_launch_major(repository_root)
    selected, compatibility = select_launch_compatible_personas(
        workspace,
        count,
        major=major,
        device_class=device_class,
        persona_ids=persona_ids,
    )
    arms_out = out_dir.absolute() if out_dir is not None else None
    if arms_out is not None:
        # Reject an already invalid selected output path before network_auto
        # can create a direct route. Missing components are created below,
        # after the read-only admission of every existing ancestor.
        for ancestor in reversed((arms_out, *arms_out.parents)):
            directory_identity(ancestor, label="coherence cohort output directory")
    if network_auto:
        network_route_by_persona = {
            persona_id: ensure_direct_route_for_persona(workspace, persona_id)
            for persona_id in selected
        }

    evaluator = (
        run_session_coherence_eval
        if evaluate_session is None
        else evaluate_session
    )
    arms_out_ancestry = None
    if arms_out is not None:
        prepare_owned_directory_parent(arms_out, label="coherence cohort output directory")
        arms_out_ancestry = directory_ancestry_binding(
            arms_out, label="coherence cohort output directory"
        )

    def require_arms_out_authority() -> None:
        if arms_out is None:
            return
        try:
            current = directory_ancestry_binding(
                arms_out, label="coherence cohort output directory"
            )
        except ContractError:
            raise ContractError("coherence output directory changed") from None
        if current != arms_out_ancestry:
            raise ContractError("coherence output directory changed")

    from .launcher import EvaluationLaunch, launch_evaluation
    from .lifecycle import stop_session
    from .personas import load_persona

    # Resolve host anchors once for lab-fixture identity alignment (residual fix).
    host_anchors = resolve_host_identity_anchors(workspace)

    def _run_arm(index: int, persona_id: str) -> dict[str, Any]:
        """One disposable arm. Returns a record; never mutates shared state.

        Arms are independent by construction -- distinct persona, distinct disposable
        profile, distinct claim, and a launch that owns its own profile lock, gateway
        lease, and OS-assigned CDP port -- which is what makes bounded parallelism
        safe. Aggregation stays serial in the caller so counters cannot race.
        """
        profile_id = f"{DISPOSABLE_PROFILE_PREFIX}{batch}-{index:03d}"
        claim_id = f"{batch}-{persona_id}"
        timings: dict[str, float] = {}
        session_run_id: str | None = None
        session_path: Path | None = None
        state = "failed"
        error: str | None = None
        coherence: dict[str, Any] | None = None
        alignment_meta: dict[str, Any] | None = None
        arm_errors: list[str] = []
        verdict_class: str | None = None
        route_id = _resolve_route_for_persona(
            persona_id, network_route_id, network_route_by_persona
        )
        route_sha16: str | None = None
        profile_owned = False
        claim_owned = False

        try:
            t0 = time.perf_counter()
            create_profile(workspace, profile_id, name=f"ops coherence {index}")
            profile_owned = True
            timings["create_ms"] = (time.perf_counter() - t0) * 1000

            t0 = time.perf_counter()
            claim_persona_exclusive(
                workspace, persona_id, claim_id, require_new=True
            )
            claim_owned = True
            timings["claim_ms"] = (time.perf_counter() - t0) * 1000

            t0 = time.perf_counter()
            persona_doc = load_persona(workspace, persona_id)
            contract, alignment_meta = align_lab_fixture_identity_contract(
                persona_doc, host_anchors
            )
            attach_persona_identity_for_ops(
                workspace,
                profile_id,
                persona_id,
                identity_contract=contract,
            )
            timings["bind_ms"] = (time.perf_counter() - t0) * 1000

            if route_id is not None:
                t0 = time.perf_counter()
                document = attach_network_route(workspace, profile_id, route_id)
                timings["network_attach_ms"] = (time.perf_counter() - t0) * 1000
                binding = document.get("network_route") or {}
                route_sha16 = binding.get("sha256_16")
                reloaded = load_profile(workspace, profile_id)
                if reloaded.get("network_route") != binding:
                    raise ContractError("network route binding did not persist")

            t0 = time.perf_counter()
            path, session = launch_evaluation(
                EvaluationLaunch(
                    executable=executable,
                    workspace=workspace,
                    headless=headless,
                    timeout_seconds=45.0,
                    profile_id=profile_id,
                    trace_mode="off",
                ),
                repository_root,
            )
            timings["launch_ms"] = (time.perf_counter() - t0) * 1000
            session_path = Path(path)
            session_run_id = session.get("run_id")
            _require_launched_route_receipt(session, route_id, route_sha16)
            state = "running"

            t0 = time.perf_counter()
            arm_eval_dir = (
                arms_out / f"arm-{index:03d}-{persona_id}"
                if arms_out is not None
                else workspace / "tmp" / "ops-coherence" / batch / f"arm-{index:03d}"
            )
            # Do not mkdir arm_eval_dir: browser-eval refuses existing run dirs.
            require_arms_out_authority()
            if os.path.lexists(arm_eval_dir):
                raise ContractError(
                    f"coherence arm out_dir already exists: {arm_eval_dir}"
                )
            prepare_owned_directory_parent(arm_eval_dir.parent, label="coherence arm output parent")
            require_arms_out_authority()
            eval_result = evaluator(
                session_path,
                out_dir=arm_eval_dir,
                evaluators=evaluators,
                workspace=workspace,
            )
            require_arms_out_authority()
            timings["eval_ms"] = (time.perf_counter() - t0) * 1000
            if not isinstance(eval_result, dict):
                raise ContractError("evaluate_session must return a dict")
            eval_exit = eval_result.get("eval_exit")
            if type(eval_exit) is not int:
                raise ContractError("coherence eval process status is invalid")
            primary = eval_result.get("primary")
            if eval_exit != 0 or eval_result.get("error") is not None:
                verdict_class = "error"
                error = "coherence-eval-failed"
                arm_errors.append(f"{profile_id}: {error}")
            elif isinstance(primary, dict) and primary.get("evaluator_id") == "controlled_coherence":
                primary = _validate_coherence_summary(primary)
                coherence = {
                    "status": primary.get("status"),
                    "verdict": primary.get("verdict"),
                    "passed_checks": primary.get("passed_checks"),
                    "failed_checks": primary.get("failed_checks"),
                    "unavailable_checks": primary.get("unavailable_checks"),
                    "identity_passed_claims": primary.get("identity_passed_claims"),
                    "identity_failed_claims": primary.get("identity_failed_claims"),
                    "identity_unavailable_claims": primary.get(
                        "identity_unavailable_claims"
                    ),
                    "failed_check_ids": primary.get("failed_check_ids") or [],
                    "unavailable_check_ids": primary.get("unavailable_check_ids") or [],
                }
                reject_sensitive_keys(coherence)
                if primary.get("verdict") == "pass":
                    verdict_class = "pass"
                elif primary.get("verdict") == "fail":
                    verdict_class = "fail"
                else:
                    verdict_class = "error"
            else:
                verdict_class = "error"
                error = "coherence-eval-no-controlled-primary"
                arm_errors.append(f"{profile_id}: {error}")

            t0 = time.perf_counter()
            _validated_ops_stop_receipt(
                stop_session(session_path, timeout_seconds=30.0),
                expected_run_id=session_run_id,
            )
            timings["stop_ms"] = (time.perf_counter() - t0) * 1000
            state = "stopped"
            session_path = None

            _require_owned_profile_deleted(
                delete_disposable_profile(workspace, profile_id), profile_id
            )
            profile_owned = False
            release_persona_claim(workspace, persona_id, claim_id)
            claim_owned = False
            state = "disposed"
        except Exception as exc:  # noqa: BLE001
            error = _safe_failure_receipt(exc)
            arm_errors.append(f"{profile_id}: {error}")
            # Only count as coherence error when eval never produced a primary result.
            if coherence is None:
                verdict_class = "error"
            # Keep the claim/profile when termination cannot be proved. Releasing
            # identity ownership or deleting its profile while the browser may still
            # be active would erase the only durable containment evidence.
            stop_verified = session_path is None
            if session_path is not None:
                try:
                    _validated_ops_stop_receipt(
                        stop_session(session_path, timeout_seconds=30.0),
                        expected_run_id=session_run_id,
                    )
                    session_path = None
                    stop_verified = True
                except Exception as cleanup_exc:  # noqa: BLE001
                    cleanup_error = _safe_failure_receipt(cleanup_exc)
                    arm_errors.append(f"cleanup-stop {profile_id}: {cleanup_error}")
                    verdict_class = "error"
            if stop_verified:
                # Only clean resources acquired by this arm. In particular, a
                # colliding profile or same-ID claim belongs to an earlier run.
                # Retain the claim while an owned profile remains after a
                # failed deletion, as the normal teardown does.
                if profile_owned and is_disposable_profile_id(profile_id):
                    try:
                        _require_owned_profile_deleted(
                            delete_disposable_profile(workspace, profile_id),
                            profile_id,
                        )
                        profile_owned = False
                    except Exception:  # noqa: BLE001 - best-effort cleanup
                        pass
                if not profile_owned and claim_owned:
                    try:
                        release_persona_claim(workspace, persona_id, claim_id)
                        claim_owned = False
                    except ContractError:
                        pass
            state = "failed"

        status = redaction_safe_identity_status(
            profile_id=profile_id,
            persona_id=persona_id,
            state=state,
            timings_ms=timings,
            error=error,
            session_run_id=session_run_id,
            network_route_id=route_id if route_id is not None else None,
            network_route_sha256_16=route_sha16,
        )
        if coherence is not None:
            status = {**status, "coherence": coherence}
        if alignment_meta is not None:
            status = {
                **status,
                "identity_align": {
                    "aligned": alignment_meta.get("aligned"),
                    "reason": alignment_meta.get("reason"),
                    "changed_paths": alignment_meta.get("changed_paths") or [],
                    "anchor_persona_id": alignment_meta.get("anchor_persona_id"),
                },
            }
        reject_sensitive_keys(status)
        return {
            "index": index,
            "status": status,
            "alignment": alignment_meta,
            "verdict_class": verdict_class,
            "errors": arm_errors,
            "retained_owned_profile": profile_id if profile_owned else None,
        }

    identities: list[dict[str, Any]] = []
    errors: list[str] = []
    coherence_pass = 0
    coherence_fail = 0
    coherence_error = 0
    alignments: list[dict[str, Any]] = []

    arm_records: list[dict[str, Any]]
    t_wall = time.perf_counter()
    if parallel <= 1:
        arm_records = [_run_arm(i, p) for i, p in enumerate(selected)]
    else:
        # Bounded pool. A worker that raises would lose its arm record entirely, so
        # _run_arm swallows arm failures into a record and only genuinely unexpected
        # errors escape here -- those are surfaced rather than silently dropped.
        with ThreadPoolExecutor(max_workers=min(parallel, len(selected))) as pool:
            futures = {
                pool.submit(_run_arm, i, p): (i, p) for i, p in enumerate(selected)
            }
            collected: list[dict[str, Any]] = []
            for future in as_completed(futures):
                index, persona_id = futures[future]
                try:
                    collected.append(future.result())
                except Exception as exc:  # noqa: BLE001
                    collected.append(
                        {
                            "index": index,
                            "status": redaction_safe_identity_status(
                                profile_id=(
                                    f"{DISPOSABLE_PROFILE_PREFIX}{batch}-{index:03d}"
                                ),
                                persona_id=persona_id,
                                state="failed",
                                timings_ms={},
                                error=_safe_failure_receipt(exc),
                            ),
                            "alignment": None,
                            "verdict_class": "error",
                            "errors": [
                                f"arm-{index:03d}: {_safe_failure_receipt(exc)}"
                            ],
                        }
                    )
        arm_records = collected
    wall_ms = (time.perf_counter() - t_wall) * 1000

    # Deterministic order regardless of completion order.
    for record in sorted(arm_records, key=lambda r: r["index"]):
        identities.append(record["status"])
        if record["alignment"] is not None:
            alignments.append(record["alignment"])
        errors.extend(record["errors"])
        if record["verdict_class"] == "pass":
            coherence_pass += 1
        elif record["verdict_class"] == "fail":
            coherence_fail += 1
        elif record["verdict_class"] == "error":
            coherence_error += 1

    cohort_profile_ids = {
        record["retained_owned_profile"]
        for record in arm_records
        if record.get("retained_owned_profile") is not None
    }
    leftovers = [
        item["id"] for item in list_profiles(workspace)
        if item["id"] in cohort_profile_ids
    ]
    functional_ok = len(errors) == 0 and not leftovers and len(identities) == count
    # Cohort "passed" means lifecycle clean; coherence_all_pass is separate honesty.
    all_pass = (
        functional_ok
        and coherence_pass == count
        and coherence_fail == 0
        and coherence_error == 0
    )
    report = {
        "schema": COHERENCE_COHORT_SCHEMA,
        "batch_id": batch,
        "definition": (
            "Multi-identity ops → controlled_coherence per disposable arm: "
            "create→bind→launch→eval→stop→dispose (B10); lab-fixture identity "
            "host leaves aligned to owned-capture anchors."
        ),
        "count": count,
        "headless": headless,
        "parallel": parallel,
        "wall_ms": round(wall_ms, 3),
        "evaluators": evaluators,
        "network_auto": network_auto,
        "network_route_configured": bool(
            network_route_id or network_route_by_persona or network_auto
        ),
        "compatibility": compatibility,
        "host_identity_anchors": {
            "anchor_persona_id": host_anchors.get("anchor_persona_id"),
            "paths": host_anchors.get("paths"),
            # leaves intentionally omitted from top-level report values? include for honesty
            "leaves": host_anchors.get("leaves"),
        },
        "identity_alignments": alignments,
        "identities": identities,
        "errors": errors,
        "orphans": leftovers,
        "lifecycle_passed": functional_ok,
        "coherence_summary": {
            "arms": count,
            "pass": coherence_pass,
            "fail": coherence_fail,
            "error": coherence_error,
            "all_pass": all_pass,
        },
        "passed": functional_ok,
        "non_claims": [
            "Coherence pass is not a bot score or protected-site acceptance",
            "Public detectors if requested later remain lab-only",
        ],
        "completed_at": _utc_now(),
    }
    reject_sensitive_keys(report)
    blob = json.dumps(report).lower()
    for needle in ("password", "authorization", "cookie=", "proxy://"):
        if needle in blob:
            raise ContractError(f"coherence cohort leaked sensitive material: {needle}")
    require_arms_out_authority()
    return report


def demonstrate_exclusivity(workspace: Path, persona_id: str) -> dict[str, Any]:
    """Prove two claimers cannot own the same persona."""
    first = claim_persona_exclusive(
        workspace, persona_id, "exclusivity-owner-a", require_new=True
    )
    rejected = False
    error: str | None = None
    try:
        claim_persona_exclusive(workspace, persona_id, "exclusivity-owner-b")
    except ContractError as exc:
        rejected = True
        error = _safe_failure_receipt(exc)
    release_persona_claim(workspace, persona_id, "exclusivity-owner-a")
    result = {
        "schema": "browser-core.persona-exclusivity-demo/1",
        "persona_id": persona_id,
        "first_claim": first,
        "second_claim_rejected": rejected,
        "error": error,
        "passed": rejected,
    }
    reject_sensitive_keys(result)
    return result
