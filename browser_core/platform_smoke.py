from __future__ import annotations

import json
import secrets
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .client import ControlClient
from .contracts import ContractError
from .control import ControlStore
from .network import load_network_route, validate_network_preflight_receipt
from .personas import (
    audit_persona_catalog,
    export_persona_bundle_from_workspace,
    import_persona_bundle,
    list_personas,
)
from .profiles import PROFILE_ID_RE
from .service import serve_control
from .worker import execute_typed_job, run_remote_worker_once


@dataclass(frozen=True)
class ControlPlaneSmoke:
    workspace: Path
    network_route_id: str


CONTROL_PLANE_PREFLIGHT_URL = "https://tls.peet.ws/api/all"


def validate_control_plane_smoke_config(
    config: ControlPlaneSmoke,
    repository_root: Path,
) -> None:
    if type(config) is not ControlPlaneSmoke:
        raise ContractError("control-plane smoke config is invalid")
    if not isinstance(config.workspace, Path) or not isinstance(repository_root, Path):
        raise ContractError("control-plane smoke roots must be Paths")
    if (
        not isinstance(config.network_route_id, str)
        or PROFILE_ID_RE.fullmatch(config.network_route_id) is None
    ):
        raise ContractError("control-plane smoke network route ID is invalid")


def _preflight_control_plane_smoke(
    config: ControlPlaneSmoke,
    repository_root: Path,
) -> dict[str, Any]:
    validate_control_plane_smoke_config(config, repository_root)
    route = load_network_route(config.workspace, config.network_route_id)
    if route.get("preflight_url") != CONTROL_PLANE_PREFLIGHT_URL:
        raise ContractError(
            "control-plane smoke route preflight URL does not match the smoke contract"
        )
    return route


def _complete_leased_job(
    client: ControlClient,
    leased: dict[str, Any],
    *,
    repository_root: Path,
    workspace: Path,
    network_route: dict[str, Any],
) -> dict[str, Any]:
    if not isinstance(leased, dict):
        raise ContractError("control-plane smoke leased job is invalid")
    job = dict(leased)
    lease_token = job.pop("lease_token", None)
    if (
        not isinstance(lease_token, str)
        or not 1 <= len(lease_token) <= 1024
        or any(not 0x21 <= ord(character) <= 0x7E for character in lease_token)
    ):
        raise ContractError("control-plane smoke received an invalid lease")
    result = execute_typed_job(
        job, repository_root=repository_root, workspace=workspace
    )
    result = validate_network_preflight_receipt(result, network_route)
    completed = client.worker_complete(
        job["id"], lease_token, succeeded=True, result=result
    )
    if (
        not isinstance(completed, dict)
        or completed.get("id") != job.get("id")
        or completed.get("state") != "succeeded"
    ):
        raise ContractError("control-plane smoke typed job did not succeed")
    return completed


def run_control_plane_smoke(
    config: ControlPlaneSmoke,
    repository_root: Path,
) -> dict[str, Any]:
    smoke_route = _preflight_control_plane_smoke(config, repository_root)
    smoke_id = f"control-{secrets.token_hex(4)}"
    control_root = config.workspace / "acceptance" / smoke_id
    try:
        store = ControlStore(control_root)
    except ContractError:
        raise
    except (OSError, RuntimeError, ValueError) as exc:
        raise ContractError(
            f"control-plane smoke store could not initialize ({type(exc).__name__})"
        ) from None
    bootstrap = store.bootstrap(
        workspace_id="owned-lab",
        workspace_name="Owned acceptance lab",
        owner_id="owner",
        owner_name="Owner",
        token_ttl_hours=1,
        max_running=2,
        max_queued=10,
    )
    owner_principal = store.authenticate(bootstrap["token"])
    store.create_workspace(
        owner_principal,
        workspace_id="owned-lab-secondary",
        name="Owned secondary acceptance lab",
        max_running=2,
        max_queued=10,
    )
    store.create_workspace(
        owner_principal,
        workspace_id="owned-lab-quota",
        name="Owned quota acceptance lab",
        max_running=1,
        max_queued=1,
    )
    store.add_member(
        owner_principal,
        "owned-lab",
        user_id="operator",
        display_name="Operator",
        role="operator",
    )
    store.add_member(
        owner_principal,
        "owned-lab",
        user_id="viewer",
        display_name="Viewer",
        role="viewer",
    )
    store.add_member(
        owner_principal,
        "owned-lab-secondary",
        user_id="operator",
        display_name="Operator",
        role="operator",
    )
    store.add_member(
        owner_principal,
        "owned-lab-secondary",
        user_id="viewer",
        display_name="Viewer",
        role="viewer",
    )
    store.add_member(
        owner_principal,
        "owned-lab-quota",
        user_id="viewer",
        display_name="Viewer",
        role="viewer",
    )
    operator_token = store.issue_token(
        owner_principal, "owned-lab", "operator", ttl_hours=1
    )
    viewer_token = store.issue_token(
        owner_principal, "owned-lab", "viewer", ttl_hours=1
    )
    worker_registration = store.register_worker(
        owner_principal,
        "owned-lab",
        "network-worker",
        name="Owned network worker",
        capabilities=["network"],
        max_slots=2,
    )
    store.add_worker_scope(owner_principal, "owned-lab-secondary", "network-worker")
    with serve_control(store) as service_url:
        owner = ControlClient(service_url, bootstrap["token"])
        operator = ControlClient(service_url, operator_token)
        viewer = ControlClient(service_url, viewer_token)
        worker = ControlClient(service_url, worker_registration["worker_token"])
        if owner.health().get("status") != "ok":
            raise ContractError("control-plane smoke health check failed")
        first = owner.put_record(
            "owned-lab",
            "persona",
            "shared",
            {"stage": "owner"},
            expected_revision=0,
        )
        second = operator.put_record(
            "owned-lab",
            "persona",
            "shared",
            {"stage": "operator"},
            expected_revision=first["revision"],
        )
        observed_record = viewer.get_record("owned-lab", "persona", "shared")
        if observed_record["revision"] != second["revision"]:
            raise ContractError(
                "control-plane smoke record revision did not synchronize"
            )
        catalog = list_personas(config.workspace, include_deprecated=True)
        if catalog:
            shared_document = export_persona_bundle_from_workspace(
                config.workspace, catalog
            )
            artifact_kind = "persona-bundle"
        else:
            shared_document = {
                "schema": "browser-core.shared-evidence/1",
                "verdict": "passed",
            }
            artifact_kind = "generic-evidence"
        shared_evidence = json.dumps(
            shared_document, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        artifact = owner.put_artifact(
            "owned-lab",
            shared_evidence,
            media_type="application/json",
            visibility="viewer",
        )
        synchronized_evidence = viewer.get_artifact("owned-lab", artifact["sha256"])
        if synchronized_evidence != shared_evidence:
            raise ContractError("control-plane smoke artifact did not synchronize")
        synchronized_personas = 0
        synchronized_catalog_audit: dict[str, Any] | None = None
        if artifact_kind == "persona-bundle":
            persona_sync_target = control_root / "persona-sync-target"
            import_persona_bundle(
                persona_sync_target, json.loads(synchronized_evidence)
            )
            synchronized_catalog_audit = audit_persona_catalog(persona_sync_target)
            synchronized_personas = synchronized_catalog_audit["personas"]
        first_job = owner.enqueue_job(
            "owned-lab",
            kind="network-preflight",
            payload={
                "route_id": config.network_route_id,
                "probe_url": CONTROL_PLANE_PREFLIGHT_URL,
            },
            requirements=["network"],
            idempotency_key=f"{smoke_id}-primary-one",
            max_attempts=2,
            persona_id="shared-persona",
        )
        second_job = owner.enqueue_job(
            "owned-lab",
            kind="network-preflight",
            payload={
                "route_id": config.network_route_id,
                "probe_url": CONTROL_PLANE_PREFLIGHT_URL,
            },
            requirements=["network"],
            idempotency_key=f"{smoke_id}-primary-two",
            max_attempts=2,
            persona_id="shared-persona",
        )
        secondary_job = owner.enqueue_job(
            "owned-lab-secondary",
            kind="network-preflight",
            payload={
                "route_id": config.network_route_id,
                "probe_url": CONTROL_PLANE_PREFLIGHT_URL,
            },
            requirements=["network"],
            idempotency_key=f"{smoke_id}-secondary",
            max_attempts=2,
        )
        incompatible_job = owner.enqueue_job(
            "owned-lab",
            kind="kernel-probe",
            payload={
                "kernel_id": "playwright-webkit",
                "device_preset": "Desktop Safari",
                "locale": "en-US",
                "timezone": "America/Chicago",
            },
            requirements=["webkit"],
            idempotency_key=f"{smoke_id}-incompatible",
        )
        first_lease = worker.worker_lease(lease_seconds=60)
        if first_lease is None or first_lease.get("id") != first_job["id"]:
            raise ContractError(
                "control-plane smoke first fair-dispatch lease is invalid"
            )
        worker.worker_heartbeat(
            first_job["id"], first_lease["lease_token"], extend_seconds=60
        )
        second_lease = worker.worker_lease(lease_seconds=60)
        if second_lease is None or second_lease.get("id") != secondary_job["id"]:
            raise ContractError(
                "control-plane smoke did not enforce persona exclusivity and workspace fairness"
            )
        first_completed = _complete_leased_job(
            worker,
            repository_root=repository_root,
            workspace=config.workspace,
            network_route=smoke_route,
            leased=first_lease,
        )
        secondary_completed = _complete_leased_job(
            worker,
            repository_root=repository_root,
            workspace=config.workspace,
            network_route=smoke_route,
            leased=second_lease,
        )
        third_completed = run_remote_worker_once(
            worker,
            repository_root=repository_root,
            workspace=config.workspace,
            lease_seconds=60,
        )
        if (
            not isinstance(third_completed, dict)
            or third_completed.get("id") != second_job["id"]
            or third_completed.get("state") != "succeeded"
        ):
            raise ContractError(
                "control-plane smoke did not release persona exclusivity"
            )
        third_observed = operator.get_job("owned-lab", second_job["id"])
        validate_network_preflight_receipt(
            third_observed.get("result"), smoke_route
        )
        if worker.worker_lease(lease_seconds=60) is not None:
            raise ContractError(
                "control-plane smoke leased a job to an incompatible worker"
            )

        recovery_job = owner.enqueue_job(
            "owned-lab",
            kind="network-preflight",
            payload={
                "route_id": config.network_route_id,
                "probe_url": CONTROL_PLANE_PREFLIGHT_URL,
            },
            requirements=["network"],
            idempotency_key=f"{smoke_id}-recovery",
            max_attempts=2,
        )
        abandoned_lease = worker.worker_lease(lease_seconds=5)
        if abandoned_lease is None or abandoned_lease.get("id") != recovery_job["id"]:
            raise ContractError("control-plane smoke recovery lease is invalid")
        time.sleep(5.25)
        recovered_lease = worker.worker_lease(lease_seconds=60)
        if (
            recovered_lease is None
            or recovered_lease.get("id") != recovery_job["id"]
            or recovered_lease.get("attempt") != 2
        ):
            raise ContractError("control-plane smoke did not recover an expired lease")
        recovered_completed = _complete_leased_job(
            worker,
            repository_root=repository_root,
            workspace=config.workspace,
            network_route=smoke_route,
            leased=recovered_lease,
        )

        shell_rejected = False
        try:
            owner.enqueue_job(
                "owned-lab",
                kind="shell",
                payload={"command": "whoami"},
                requirements=[],
                idempotency_key=f"{smoke_id}-shell",
            )
        except ContractError:
            shell_rejected = True
        if not shell_rejected:
            raise ContractError("control-plane smoke accepted arbitrary shell work")

        owner.enqueue_job(
            "owned-lab-quota",
            kind="network-preflight",
            payload={
                "route_id": config.network_route_id,
                "probe_url": CONTROL_PLANE_PREFLIGHT_URL,
            },
            requirements=["network"],
            idempotency_key=f"{smoke_id}-quota-one",
        )
        quota_rejected = False
        try:
            owner.enqueue_job(
                "owned-lab-quota",
                kind="network-preflight",
                payload={
                    "route_id": config.network_route_id,
                    "probe_url": CONTROL_PLANE_PREFLIGHT_URL,
                },
                requirements=["network"],
                idempotency_key=f"{smoke_id}-quota-two",
            )
        except ContractError:
            quota_rejected = True
        if not quota_rejected:
            raise ContractError(
                "control-plane smoke did not enforce the queued-job quota"
            )

        fleet = viewer.fleet_status("owned-lab")
        secondary_fleet = viewer.fleet_status("owned-lab-secondary")
        quota_fleet = viewer.fleet_status("owned-lab-quota")
        if (
            fleet.get("jobs", {}).get("succeeded") != 3
            or fleet.get("jobs", {}).get("queued") != 1
        ):
            raise ContractError("control-plane smoke fleet status did not converge")
        if secondary_fleet.get("jobs", {}).get("succeeded") != 1:
            raise ContractError(
                "control-plane smoke secondary fleet status did not converge"
            )
        if quota_fleet.get("jobs", {}).get("queued") != 1:
            raise ContractError(
                "control-plane smoke quota fleet status did not converge"
            )
        listed_job_ids = {item["id"] for item in viewer.list_jobs("owned-lab")["jobs"]}
        if (
            recovered_completed["id"] not in listed_job_ids
            or incompatible_job["id"] not in listed_job_ids
        ):
            raise ContractError("control-plane smoke job listing is incomplete")
        viewer_job = viewer.get_job("owned-lab", recovered_completed["id"])
        operator_job = operator.get_job("owned-lab", recovered_completed["id"])
        if (
            "payload" in viewer_job
            or "result" in viewer_job
            or "result" not in operator_job
        ):
            raise ContractError("control-plane smoke job result role boundary failed")
        audit_before_revoke = viewer.verify_audit("owned-lab")
        secondary_audit = viewer.verify_audit("owned-lab-secondary")
        quota_audit = viewer.verify_audit("owned-lab-quota")
        operator_token_id = operator_token.split(".", 2)[1]
        owner.revoke_token("owned-lab", operator_token_id)
        revoked = False
        try:
            operator.get_record("owned-lab", "persona", "shared")
        except ContractError:
            revoked = True
        if not revoked:
            raise ContractError("control-plane smoke revoked token remained usable")
        audit_after_revoke = viewer.verify_audit("owned-lab")
    if audit_after_revoke.get("valid") is not True:
        raise ContractError("control-plane smoke audit chain is invalid")
    return {
        "schema": "browser-core.control-plane-smoke/2",
        "status": "passed",
        "control_root": str(control_root),
        "clients": ["owner", "operator", "viewer", "worker"],
        "record_revision": second["revision"],
        "artifact": {
            "sha256": artifact["sha256"],
            "kind": artifact_kind,
            "personas": synchronized_personas,
            "catalog_audit": synchronized_catalog_audit,
        },
        "jobs": {
            "fair_dispatch_order": [
                first_completed["id"],
                secondary_completed["id"],
                third_completed["id"],
            ],
            "recovered": {"id": recovered_completed["id"], "attempt": 2},
            "incompatible_queued": incompatible_job["id"],
        },
        "fleet": {
            "primary": fleet,
            "secondary": secondary_fleet,
            "quota": quota_fleet,
        },
        "scheduler": {
            "fairness": True,
            "persona_exclusivity": True,
            "lease_heartbeat": True,
            "lease_recovery": True,
            "capability_rejection": True,
            "queued_quota": True,
            "job_observability": True,
            "result_role_boundary": True,
        },
        "token_revocation": True,
        "audit": {
            "valid": True,
            "events_before_revoke": audit_before_revoke["events"],
            "events_after_revoke": audit_after_revoke["events"],
            "secondary_valid": secondary_audit["valid"],
            "quota_valid": quota_audit["valid"],
        },
        "raw_tokens_serialized": False,
        "arbitrary_shell": False,
    }
