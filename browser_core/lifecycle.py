from __future__ import annotations

import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from .contracts import (
    RUN_ID_RE,
    ContractError,
    load_session_snapshot,
    validate_session,
)
from .control_files import (
    MAX_GATEWAY_CONTROL_BYTES,
    MAX_SESSION_DOCUMENT_BYTES,
    BoundedControlSnapshot,
    load_canonical_json_document,
    read_bounded_control_snapshot_result,
    remove_control_conditionally,
    replace_json_conditionally_result,
)
from .cdp import request_browser_close
from .launcher import reap_launched_process
from .numeric import is_finite_number
from .process import (
    identities_match,
    observe_process,
    terminate_verified,
    validate_process_identity,
    wait_for_verified_exit,
)
from .process_children import observe_browser_children, retain_child_snapshot
from .profiles import release_profile_lock
from .session_stop_guard import session_stop_guard
from .owned_paths import parse_directory_identity, remove_owned_directory_tree


def _require_session_body_identity(
    path: Path,
    body: bytes,
    identity: tuple[int, int, int, int, int, int],
    *,
    changed_message: str,
) -> None:
    final = read_bounded_control_snapshot_result(
        path,
        maximum=MAX_SESSION_DOCUMENT_BYTES,
        label="session contract",
        require_single_link=True,
    )
    if (
        final.state != "complete"
        or final.body != body
        or final.identity != identity
    ):
        raise ContractError(changed_message)


def _stopped_status(session: dict[str, Any]) -> dict[str, Any]:
    return {
        "run_id": session["run_id"],
        "state": "stopped",
        "running": False,
        "identity_protected": session.get("process_identity") is not None,
    }


def _verified_persisted_stopped_status(session: dict[str, Any]) -> dict[str, Any]:
    expected = session.get("process_identity")
    if not isinstance(expected, dict):
        return _stopped_status(session)
    expected = validate_process_identity(expected)
    try:
        actual = validate_process_identity(observe_process(expected["pid"]))
    except ProcessLookupError:
        return _stopped_status(session)
    if identities_match(expected, actual):
        return {
            "run_id": session["run_id"],
            "state": "inconsistent",
            "running": True,
            "identity_protected": True,
        }
    return _stopped_status(session)


def validate_stopped_session_receipt(
    value: Any,
    *,
    expected_run_id: str,
) -> dict[str, Any]:
    """Retain exact proof that the launched session is no longer running."""
    base_fields = {"run_id", "state", "running", "identity_protected"}
    if (
        not isinstance(expected_run_id, str)
        or RUN_ID_RE.fullmatch(expected_run_id) is None
        or not isinstance(value, dict)
        or frozenset(value)
        not in {frozenset(base_fields), frozenset(base_fields | {"shutdown_mode"})}
        or value.get("run_id") != expected_run_id
        or value.get("state") != "stopped"
        or value.get("running") is not False
        or type(value.get("identity_protected")) is not bool
    ):
        raise ContractError("session stop was not verified")
    shutdown_mode = value.get("shutdown_mode")
    if "shutdown_mode" in value and (
        not isinstance(shutdown_mode, str)
        or shutdown_mode not in {"graceful", "forced", "exited-before-force"}
    ):
        raise ContractError("session stop was not verified")
    retained = {
        "run_id": expected_run_id,
        "state": "stopped",
        "running": False,
        "identity_protected": value["identity_protected"],
    }
    if shutdown_mode is not None:
        retained["shutdown_mode"] = shutdown_mode
    return retained


def session_status(path: Path) -> dict[str, Any]:
    source = load_session_snapshot(path)
    session = source.document
    expected = session.get("process_identity")
    if session.get("state", "active") == "stopped":
        result = _verified_persisted_stopped_status(session)
    elif not isinstance(expected, dict):
        result = {
            "run_id": session["run_id"],
            "state": "unknown",
            "running": None,
            "identity_protected": False,
        }
    else:
        try:
            actual = observe_process(session["pid"])
        except ProcessLookupError:
            result = {
                "run_id": session["run_id"],
                "state": "stale",
                "running": False,
                "identity_protected": True,
            }
        else:
            matched = identities_match(expected, actual)
            result = {
                "run_id": session["run_id"],
                "state": "active" if matched else "identity-mismatch",
                "running": matched,
                "identity_protected": True,
            }
    _require_session_body_identity(
        path,
        source.body,
        source.identity,
        changed_message="session contract changed during status",
    )
    return result


def _release_session_profile_lock(
    workspace: Path,
    session: dict[str, Any],
) -> None:
    profile = session.get("profile")
    if not isinstance(profile, dict) or profile.get("persistence") != "persistent":
        return
    profile_source = Path(profile["path"])
    profile_path = profile_source.parent.resolve() / profile_source.name
    expected_profile_path = workspace / "profiles" / "data" / str(profile["id"])
    if profile_path != expected_profile_path:
        raise ContractError("persistent session profile path is outside the workspace")
    lock_raw = profile.get("lock_path")
    if not isinstance(lock_raw, str):
        raise ContractError("persistent session has no profile lock")
    lock_source = Path(lock_raw)
    lock_path = lock_source.parent.resolve() / lock_source.name
    if lock_path.parent != profile_path or lock_path.name != ".browser-core.lock":
        raise ContractError("session profile lock path is outside the managed profile")
    release_profile_lock(lock_path, session["run_id"], missing_ok=True)


def _remove_session_ephemeral_profile(
    session_path: Path,
    session: dict[str, Any],
) -> None:
    profile = session.get("profile")
    if not isinstance(profile, dict) or profile.get("persistence") != "ephemeral":
        return
    identity_document = profile.get("directory_identity")
    if identity_document is None:
        # Legacy session documents did not bind an ephemeral directory object.
        # Refuse to infer ownership from a pathname alone.
        return
    expected_identity = parse_directory_identity(identity_document)
    workspace = session_path.resolve().parent.parent
    expected_path = workspace / "profiles" / "ephemeral" / session["run_id"]
    supplied = Path(profile["path"])
    supplied_without_leaf_resolution = supplied.parent.resolve() / supplied.name
    if supplied_without_leaf_resolution != expected_path:
        raise ContractError("ephemeral session profile path is outside the managed run")
    remove_owned_directory_tree(
        expected_path,
        expected_identity=expected_identity,
        missing_ok=True,
        label="ephemeral session profile",
    )


def _owned_gateway_control(
    path: Path,
    expected: dict[str, Any],
    *,
    label: str,
) -> BoundedControlSnapshot | None:
    snapshot = read_bounded_control_snapshot_result(
        path,
        maximum=MAX_GATEWAY_CONTROL_BYTES,
        label=label,
    )
    if snapshot.state == "missing":
        return None
    if snapshot.state != "complete":
        raise ContractError(f"{label} is {snapshot.state}")
    assert snapshot.body is not None and snapshot.identity is not None
    document = load_canonical_json_document(snapshot.body, label=label)
    if document != expected:
        raise ContractError(f"{label} is not owned by this session")
    return snapshot


def _remove_owned_gateway_control(
    path: Path,
    expected: dict[str, Any],
    *,
    label: str,
) -> None:
    snapshot = _owned_gateway_control(path, expected, label=label)
    if snapshot is None:
        return
    assert snapshot.body is not None and snapshot.identity is not None
    remove_control_conditionally(
        path,
        expected_body=snapshot.body,
        expected_identity=snapshot.identity,
        maximum=MAX_GATEWAY_CONTROL_BYTES,
        label=label,
        missing_ok=True,
    )


def _stop_network_gateway(
    workspace: Path,
    session: dict[str, Any],
    deadline: float,
    *,
    managed_layout: bool,
) -> None:
    network = session.get("network")
    if not isinstance(network, dict):
        return
    gateway = network.get("gateway")
    if not isinstance(gateway, dict):
        return
    expected = gateway.get("process_identity")
    if not isinstance(expected, dict):
        raise ContractError("session network gateway has no process identity")
    lease_source = Path(gateway["lease_path"])
    ready_source = Path(gateway["ready_path"])
    lease_path = lease_source.parent.resolve() / lease_source.name
    ready_path = ready_source.parent.resolve() / ready_source.name
    if lease_path.parent != ready_path.parent:
        raise ContractError("session network gateway control paths disagree")
    if lease_path.parent != workspace / "network" / "gateways":
        raise ContractError(
            "session network gateway controls are outside the workspace"
        )
    if (
        lease_path.name != f"{session['run_id']}.lease"
        or ready_path.name != f"{session['run_id']}.json"
    ):
        raise ContractError(
            "session network gateway control paths are not owned by this run"
        )
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise ContractError(
            "session stop deadline exhausted before network gateway stop"
        )
    network_route_id = network.get("route_id")
    network_route_digest = network.get("route_sha256_16")
    if not isinstance(network_route_id, str) or not isinstance(
        network_route_digest, str
    ):
        raise ContractError("session network gateway route binding is invalid")
    if managed_layout and os.path.normcase(
        str(Path(expected["executable"]).resolve())
    ) != os.path.normcase(str(Path(sys.executable).resolve())):
        raise ContractError(
            "session network gateway executable is not Browser Core's runtime"
        )
    lease_document = {
        "schema": "browser-core.gateway-lease/2",
        "run_id": session["run_id"],
        "route_id": network_route_id,
        "route_sha256_16": network_route_digest,
    }
    _remove_owned_gateway_control(
        lease_path,
        lease_document,
        label="session network gateway lease",
    )
    try:
        remaining = deadline - time.monotonic()
        graceful_budget = min(5.0, max(0.0, remaining - 0.1))
        exited = (
            wait_for_verified_exit(expected, graceful_budget)
            if graceful_budget > 0
            else False
        )
    except ProcessLookupError:
        exited = True
    if not exited:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ContractError(
                "session stop deadline exhausted before network gateway termination"
            )
        try:
            terminate_verified(expected, timeout_seconds=remaining)
        except ProcessLookupError:
            pass
    endpoint = urlparse(gateway["endpoint"])
    if endpoint.hostname != "127.0.0.1" or endpoint.port is None:
        raise ContractError("session network gateway endpoint is invalid")
    ready_document = {
        "schema": "browser-core.gateway-ready/2",
        "run_id": session["run_id"],
        "route_id": network_route_id,
        "route_sha256_16": network_route_digest,
        "host": "127.0.0.1",
        "port": endpoint.port,
    }
    _remove_owned_gateway_control(
        ready_path,
        ready_document,
        label="session network gateway readiness",
    )


def _session_workspace(path: Path, session: dict[str, Any]) -> tuple[Path, bool]:
    source = Path(path)
    normalized = source.parent.resolve() / source.name
    if normalized.parent.name == "sessions":
        if normalized.name != f"{session['run_id']}.json":
            raise ContractError("managed session filename does not match its run ID")
        return normalized.parent.parent, True
    # Backward-compatible location for pre-managed-layout session files. All
    # destructive child paths are still scoped beneath this directory.
    return normalized.parent, False


def stop_session(
    path: Path,
    timeout_seconds: float = 15.0,
    *,
    graceful_timeout_seconds: float = 15.0,
    expected_run_id: str | None = None,
) -> dict[str, Any]:
    if expected_run_id is not None and (
        not isinstance(expected_run_id, str)
        or RUN_ID_RE.fullmatch(expected_run_id) is None
    ):
        raise ContractError("expected session run ID is invalid")
    if not is_finite_number(timeout_seconds) or not 0 < timeout_seconds <= 300:
        raise ContractError(
            "session stop timeout must be finite and > 0 and at most 300 seconds"
        )
    if (
        not is_finite_number(graceful_timeout_seconds)
        or not 0 < graceful_timeout_seconds <= 300
    ):
        raise ContractError(
            "session graceful stop timeout must be finite and > 0 and at most 300 seconds"
        )
    started = time.monotonic()
    deadline = started + float(timeout_seconds)
    with session_stop_guard(path, deadline):
        return _stop_session_serialized(
            path, timeout_seconds=timeout_seconds,
            graceful_timeout_seconds=graceful_timeout_seconds,
            started=started, deadline=deadline, expected_run_id=expected_run_id,
        )


def _stop_session_serialized(
    path: Path, *, timeout_seconds: float, graceful_timeout_seconds: float,
    started: float, deadline: float, expected_run_id: str | None,
) -> dict[str, Any]:
    # Read after acquiring coordination. A waiting caller sees the completed
    # receipt instead of attempting the first caller's publications again.
    source = load_session_snapshot(path)
    session = source.document
    if expected_run_id is not None and session["run_id"] != expected_run_id:
        raise ContractError("session run ID changed before stop")
    workspace, managed_layout = _session_workspace(path, session)
    if session.get("state", "active") == "stopped":
        status = _verified_persisted_stopped_status(session)
        if status["state"] != "stopped":
            raise ContractError(
                "persisted stopped session process is still running"
            )
        reap_launched_process(session["pid"])
        _require_session_body_identity(
            path,
            source.body,
            source.identity,
            changed_message="session contract changed after stop",
        )
        return status
    expected = session.get("process_identity")
    if not isinstance(expected, dict):
        raise ContractError(
            "refusing to stop a legacy session without a process identity"
        )
    child_snapshot = None
    if (sys.platform == 'win32' and
            session.get('build', {}).get('provenance') == 'attested-browser-core'):
        child_snapshot = retain_child_snapshot(
            path, session, source.body, observe_browser_children(expected))
    # Reserve at least half of the overall deadline for verified forced cleanup.
    # Chromium flushes startup Perfetto tracing as it exits. The default allows
    # that flush to finish beyond the old five-second cutoff, while the caller's
    # total deadline and the reserved forced-cleanup budget remain authoritative.
    graceful_deadline = min(
        deadline,
        started + min(float(graceful_timeout_seconds), timeout_seconds / 2),
    )
    gracefully_stopped = False
    close_requested = False
    shutdown_mode = "graceful"
    try:
        remaining = graceful_deadline - time.monotonic()
        if remaining > 0 and (child_snapshot is None or child_snapshot.parent_running):
            request_browser_close(
                session["automation"]["cdp_endpoint"],
                timeout_seconds=remaining,
            )
            close_requested = True
    except (ContractError, ProcessLookupError):
        pass
    try:
        # An unavailable close channel does not establish that the owned
        # process is alive. Verify exit before attempting forced termination,
        # including retries after an earlier profile-cleanup failure.
        remaining = graceful_deadline - time.monotonic()
        if remaining > 0:
            gracefully_stopped = wait_for_verified_exit(expected, remaining)
    except (ContractError, ProcessLookupError):
        pass
    if gracefully_stopped and not close_requested:
        shutdown_mode = "exited-before-force"
    if not gracefully_stopped:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ContractError(
                "session stop deadline exhausted before browser termination"
            )
        try:
            terminate_verified(expected, timeout_seconds=remaining)
            shutdown_mode = "forced"
        except ProcessLookupError:
            shutdown_mode = "exited-before-force"
    if child_snapshot is not None:
        # Chromium's browser process can exit before its storage/utility
        # children release profile files. Wait only on the captured identities;
        # this snapshot never authorizes a child termination. A timeout keeps
        # the profile/lock for a later owned cleanup attempt.
        for child in child_snapshot.identities:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not wait_for_verified_exit(child, remaining):
                raise ContractError('observed browser child exit was not verified before profile cleanup')
    reap_launched_process(session["pid"])
    _stop_network_gateway(
        workspace,
        session,
        deadline,
        managed_layout=managed_layout,
    )
    _release_session_profile_lock(workspace, session)
    _remove_session_ephemeral_profile(path, session)
    session["state"] = "stopped"
    session["stopped_at"] = (
        datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    )
    validate_session(session)
    publication = replace_json_conditionally_result(
        path,
        session,
        expected_body=source.body,
        expected_identity=source.identity,
        maximum=MAX_SESSION_DOCUMENT_BYTES,
        label="session contract",
    )
    published_session = validate_session(
        load_canonical_json_document(
            publication.body,
            label="session contract",
        )
    )
    _require_session_body_identity(
        path,
        publication.body,
        publication.identity,
        changed_message="session contract changed after stop",
    )
    return {
        "run_id": published_session["run_id"],
        "state": "stopped",
        "running": False,
        "identity_protected": True,
        "shutdown_mode": shutdown_mode,
    }
