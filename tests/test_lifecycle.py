from __future__ import annotations

import json
import os
import traceback
from pathlib import Path

import pytest

import browser_core.control_files as control_files
import browser_core.lifecycle as lifecycle_module
from browser_core.contracts import ContractError
from browser_core.control_files import canonical_json_bytes
from browser_core.lifecycle import (
    session_status,
    stop_session,
    validate_stopped_session_receipt,
)
from browser_core.owned_paths import directory_identity, directory_identity_document
from browser_core.profiles import (
    acquire_profile_lock,
    create_profile,
    profile_data_path,
)


def _session(tmp_path: Path, lock: Path) -> tuple[Path, dict]:
    executable = tmp_path / "chrome.exe"
    executable.write_bytes(b"")
    document = {
        "schema": "browser-core.session/1",
        "run_id": "fixture-run",
        "chromium_revision": "a" * 40,
        "pid": 42,
        "state": "active",
        "created_at": "2026-08-02T00:00:00Z",
        "executable": str(executable),
        "build": {
            "provenance": "unverified-external",
            "executable_sha256_16": "0" * 16,
        },
        "process_identity": {
            "pid": 42,
            "executable": str(executable),
            "start_marker": "fixture:1",
        },
        "profile": {
            "id": "persistent",
            "persistence": "persistent",
            "path": str(profile_data_path(tmp_path, "persistent")),
            "lock_path": str(lock),
        },
        "trace_path": str(tmp_path / "trace.jsonl"),
        "automation": {"transport": "cdp", "cdp_endpoint": "http://127.0.0.1:9222"},
    }
    path = tmp_path / "session.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    return path, document


def test_stop_session_rejects_replaced_run_before_process_contact(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path, _ = _session(tmp_path, tmp_path / "unused.lock")
    monkeypatch.setattr(
        lifecycle_module,
        "_session_workspace",
        lambda *_args: pytest.fail("replacement run reached process cleanup"),
    )
    with pytest.raises(ContractError, match="run ID"):
        stop_session(path, expected_run_id="original-run")


def test_stopped_session_receipt_is_exact_same_run_and_detached() -> None:
    source = {
        "run_id": "owned-run",
        "state": "stopped",
        "running": False,
        "identity_protected": True,
        "shutdown_mode": "graceful",
    }
    retained = validate_stopped_session_receipt(
        source,
        expected_run_id="owned-run",
    )
    source["state"] = "active"
    assert retained == {
        "run_id": "owned-run",
        "state": "stopped",
        "running": False,
        "identity_protected": True,
        "shutdown_mode": "graceful",
    }


@pytest.mark.parametrize(
    "receipt",
    [
        None,
        [],
        {
            "run_id": "other-run",
            "state": "stopped",
            "running": False,
            "identity_protected": True,
        },
        {
            "run_id": "owned-run",
            "state": "active",
            "running": True,
            "identity_protected": True,
        },
        {
            "run_id": "owned-run",
            "state": "stopped",
            "running": False,
            "identity_protected": 1,
        },
        {
            "run_id": "owned-run",
            "state": "stopped",
            "running": False,
            "identity_protected": True,
            "shutdown_mode": "open",
        },
        {
            "run_id": "owned-run",
            "state": "stopped",
            "running": False,
            "identity_protected": True,
            "shutdown_mode": [],
        },
        {
            "run_id": "owned-run",
            "state": "stopped",
            "running": False,
            "identity_protected": True,
            "shutdown_mode": {},
        },
        {
            "run_id": "owned-run",
            "state": "stopped",
            "running": False,
            "identity_protected": True,
            "shutdown_mode": None,
        },
        {
            "run_id": "owned-run",
            "state": "stopped",
            "running": False,
            "identity_protected": True,
            "extra": False,
        },
    ],
)
def test_stopped_session_receipt_rejects_unverified_state(receipt: object) -> None:
    with pytest.raises(ContractError, match="stop was not verified"):
        validate_stopped_session_receipt(receipt, expected_run_id="owned-run")


def test_stopped_session_receipt_rejects_invalid_expected_run() -> None:
    with pytest.raises(ContractError, match="stop was not verified"):
        validate_stopped_session_receipt(
            {
                "run_id": "../escape",
                "state": "stopped",
                "running": False,
                "identity_protected": True,
            },
            expected_run_id="../escape",
        )


def test_stop_updates_contract_and_releases_owned_profile_lock(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    create_profile(tmp_path, "persistent")
    lock = acquire_profile_lock(tmp_path, "persistent", "fixture-run")
    path, document = _session(tmp_path, lock)
    monkeypatch.setattr(
        "browser_core.lifecycle.request_browser_close",
        lambda endpoint, timeout_seconds: None,
    )
    monkeypatch.setattr(
        "browser_core.lifecycle.wait_for_verified_exit",
        lambda expected, timeout_seconds: False,
    )
    monkeypatch.setattr(
        "browser_core.lifecycle.terminate_verified",
        lambda expected, timeout_seconds: None,
    )
    result = stop_session(path)
    assert result["state"] == "stopped"
    assert not lock.exists()
    saved = json.loads(path.read_text(encoding="utf-8"))
    assert saved["state"] == "stopped"
    assert saved["stopped_at"].endswith("Z")
    assert path.read_bytes() == canonical_json_bytes(saved)


def test_stop_removes_the_exact_owned_ephemeral_profile(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    run_id = "ephemeral-run"
    profile = workspace / "profiles" / "ephemeral" / run_id
    profile.mkdir(parents=True)
    (profile / "state.bin").write_bytes(b"owned")
    identity = directory_identity(profile, label="ephemeral profile")
    assert identity is not None
    document = {
        "schema": "browser-core.session/1",
        "run_id": run_id,
        "chromium_revision": "a" * 40,
        "pid": 42,
        "state": "active",
        "process_identity": {
            "pid": 42,
            "executable": "chrome.exe",
            "start_marker": "fixture:1",
        },
        "profile": {
            "id": None,
            "persistence": "ephemeral",
            "path": str(profile),
            "lock_path": None,
            "directory_identity": directory_identity_document(identity),
        },
        "automation": {"transport": "cdp", "cdp_endpoint": "http://127.0.0.1:9222"},
    }
    path = workspace / "sessions" / f"{run_id}.json"
    path.parent.mkdir(parents=True)
    path.write_bytes(canonical_json_bytes(document))
    monkeypatch.setattr(
        lifecycle_module, "request_browser_close", lambda *_args, **_kwargs: None
    )
    monkeypatch.setattr(
        lifecycle_module, "wait_for_verified_exit", lambda *_args, **_kwargs: True
    )

    assert stop_session(path)["state"] == "stopped"
    assert not profile.exists()


def test_stop_preserves_a_replaced_ephemeral_profile(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    run_id = "ephemeral-run"
    profile = workspace / "profiles" / "ephemeral" / run_id
    profile.mkdir(parents=True)
    (profile / "original.bin").write_bytes(b"original")
    identity = directory_identity(profile, label="ephemeral profile")
    assert identity is not None
    document = {
        "schema": "browser-core.session/1",
        "run_id": run_id,
        "chromium_revision": "a" * 40,
        "pid": 42,
        "state": "active",
        "process_identity": {
            "pid": 42,
            "executable": "chrome.exe",
            "start_marker": "fixture:1",
        },
        "profile": {
            "id": None,
            "persistence": "ephemeral",
            "path": str(profile),
            "lock_path": None,
            "directory_identity": directory_identity_document(identity),
        },
        "automation": {"transport": "cdp", "cdp_endpoint": "http://127.0.0.1:9222"},
    }
    path = workspace / "sessions" / f"{run_id}.json"
    path.parent.mkdir(parents=True)
    original_session = canonical_json_bytes(document)
    path.write_bytes(original_session)
    holding = workspace / "holding-original"
    profile.rename(holding)
    profile.mkdir()
    (profile / "competitor.bin").write_bytes(b"competitor")
    monkeypatch.setattr(
        lifecycle_module, "request_browser_close", lambda *_args, **_kwargs: None
    )
    monkeypatch.setattr(
        lifecycle_module, "wait_for_verified_exit", lambda *_args, **_kwargs: True
    )

    with pytest.raises(ContractError, match="changed before removal"):
        stop_session(path)
    assert (profile / "competitor.bin").read_bytes() == b"competitor"
    assert (holding / "original.bin").read_bytes() == b"original"
    assert path.read_bytes() == original_session


def test_stop_consumes_the_exact_conditional_replacement_result(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    create_profile(tmp_path, "persistent")
    lock = acquire_profile_lock(tmp_path, "persistent", "fixture-run")
    path, _document = _session(tmp_path, lock)
    monkeypatch.setattr(
        "browser_core.lifecycle.request_browser_close",
        lambda endpoint, timeout_seconds: None,
    )
    monkeypatch.setattr(
        "browser_core.lifecycle.wait_for_verified_exit",
        lambda expected, timeout_seconds: True,
    )
    real_replace = lifecycle_module.replace_json_conditionally_result
    captured: list[control_files.PublishedControlSnapshot] = []

    def recording_replace(*args: object, **kwargs: object):  # type: ignore[no-untyped-def]
        publication = real_replace(*args, **kwargs)
        captured.append(publication)
        return publication

    monkeypatch.setattr(
        lifecycle_module,
        "replace_json_conditionally_result",
        recording_replace,
    )
    result = stop_session(path)
    observed = control_files.read_bounded_control_snapshot_result(
        path,
        maximum=control_files.MAX_SESSION_DOCUMENT_BYTES,
        label="session contract",
    )

    assert result["state"] == "stopped"
    assert len(captured) == 1
    assert observed.state == "complete"
    assert captured[0].body == observed.body
    assert captured[0].identity == observed.identity


def test_stop_rebinds_published_session_after_receipt_validation(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    create_profile(tmp_path, "persistent")
    lock = acquire_profile_lock(tmp_path, "persistent", "fixture-run")
    path, _document = _session(tmp_path, lock)
    monkeypatch.setattr(lifecycle_module, "request_browser_close", lambda *_a, **_k: None)
    monkeypatch.setattr(lifecycle_module, "wait_for_verified_exit", lambda *_a, **_k: True)
    real_load = lifecycle_module.load_canonical_json_document
    replaced: list[bytes] = []

    def replace_during_receipt_validation(body: bytes, *, label: str) -> dict:
        parsed = real_load(body, label=label)
        published = path.read_bytes()
        challenger = canonical_json_bytes({**parsed, "run_id": "swapped-run"})
        assert len(challenger) == len(published)
        before = path.stat()
        with path.open("r+b") as stream:
            stream.write(challenger)
        os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns))
        replaced.append(challenger)
        return parsed

    monkeypatch.setattr(
        lifecycle_module,
        "load_canonical_json_document",
        replace_during_receipt_validation,
    )
    with pytest.raises(ContractError, match="session contract changed after stop"):
        stop_session(path)
    assert len(replaced) == 1
    assert path.read_bytes() == replaced[0]


def test_stop_prefers_graceful_cdp_close(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    create_profile(tmp_path, "persistent")
    lock = acquire_profile_lock(tmp_path, "persistent", "fixture-run")
    path, document = _session(tmp_path, lock)
    calls: list[str] = []
    monkeypatch.setattr(
        "browser_core.lifecycle.request_browser_close",
        lambda endpoint, timeout_seconds: calls.append(endpoint),
    )
    monkeypatch.setattr(
        "browser_core.lifecycle.wait_for_verified_exit",
        lambda expected, timeout_seconds: True,
    )
    monkeypatch.setattr(
        "browser_core.lifecycle.terminate_verified",
        lambda expected, timeout_seconds: pytest.fail(
            "force termination should not be used"
        ),
    )
    result = stop_session(path)
    assert result["state"] == "stopped"
    assert result["shutdown_mode"] == "graceful"
    assert calls == [document["automation"]["cdp_endpoint"]]
    assert not lock.exists()


def test_status_detects_process_identity_mismatch(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    create_profile(tmp_path, "persistent")
    lock = acquire_profile_lock(tmp_path, "persistent", "fixture-run")
    path, document = _session(tmp_path, lock)
    monkeypatch.setattr(
        "browser_core.lifecycle.observe_process",
        lambda pid: {**document["process_identity"], "start_marker": "fixture:reused"},
    )
    result = session_status(path)
    assert result["state"] == "identity-mismatch"
    assert result["running"] is False


def test_status_rebinds_session_after_process_observation(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    path, document = _session(tmp_path, tmp_path / "unused.lock")
    original = path.read_bytes() + b" "
    path.write_bytes(original)
    stopped = json.dumps({**document, "state": "stopped"}).encode("utf-8")
    assert len(stopped) == len(original)
    before = path.stat()

    def stop_during_observation(_pid: int) -> dict:
        with path.open("r+b") as stream:
            stream.write(stopped)
        os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns))
        return document["process_identity"]

    monkeypatch.setattr(lifecycle_module, "observe_process", stop_during_observation)
    with pytest.raises(ContractError, match="session contract changed during status"):
        session_status(path)
    assert path.read_bytes() == stopped


def test_stop_signals_and_identity_stops_network_gateway(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    create_profile(tmp_path, "persistent")
    lock = acquire_profile_lock(tmp_path, "persistent", "fixture-run")
    path, document = _session(tmp_path, lock)
    gateway_dir = tmp_path / "network" / "gateways"
    gateway_dir.mkdir(parents=True)
    lease = gateway_dir / "fixture-run.lease"
    ready = gateway_dir / "fixture-run.json"
    lease.write_bytes(
        canonical_json_bytes(
            {
                "schema": "browser-core.gateway-lease/2",
                "run_id": "fixture-run",
                "route_id": "lab",
                "route_sha256_16": "a" * 16,
            }
        )
    )
    ready.write_bytes(
        canonical_json_bytes(
            {
                "schema": "browser-core.gateway-ready/2",
                "run_id": "fixture-run",
                "route_id": "lab",
                "route_sha256_16": "a" * 16,
                "host": "127.0.0.1",
                "port": 8765,
            }
        )
    )
    preflight = {
        "schema": "browser-core.network-preflight/1",
        "route_id": "lab",
        "route_sha256_16": "a" * 16,
        "passed": True,
    }
    document["network"] = {
        "route_id": "lab",
        "route_sha256_16": "a" * 16,
        "mode": "proxy",
        "policies": {"dns": "route", "webrtc": "route-only", "require_alignment": True},
        "preflight": preflight,
        "runtime_identity": {
            "schema": "browser-core.runtime-identity-observation/1",
            "locale": "en-US",
            "languages": ["en-US"],
            "timezone": "America/Chicago",
            "cdp_domains_enabled": [],
        },
        "realization": {
            "schema": "browser-core.geo-realization/1",
            "route_id": "lab",
            "route_sha256_16": "a" * 16,
            "passed": True,
            "observed": {"ip_sha256_16": "b" * 16},
        },
        "gateway": {
            "endpoint": "http://127.0.0.1:8765",
            "process_identity": {
                "pid": 84,
                "executable": str(tmp_path / "python.exe"),
                "start_marker": "fixture:gateway",
            },
            "lease_path": str(lease),
            "ready_path": str(ready),
            "preflight": preflight,
        },
    }
    path.write_text(json.dumps(document), encoding="utf-8")
    monkeypatch.setattr(
        "browser_core.lifecycle.request_browser_close",
        lambda endpoint, timeout_seconds: None,
    )
    waits = []
    monkeypatch.setattr(
        "browser_core.lifecycle.wait_for_verified_exit",
        lambda expected, timeout_seconds: waits.append(expected["pid"]) or True,
    )
    monkeypatch.setattr(
        "browser_core.lifecycle.terminate_verified",
        lambda expected, timeout_seconds: pytest.fail(
            "verified processes should exit gracefully"
        ),
    )
    result = stop_session(path)
    assert result["state"] == "stopped"
    assert waits == [document["process_identity"]["pid"], 84]
    assert not lease.exists()
    assert not ready.exists()


def test_owned_gateway_control_disappearance_after_acceptance_is_clean(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    control = tmp_path / "owned.lease"
    expected = {
        "schema": "browser-core.gateway-lease/2",
        "run_id": "fixture-run",
        "route_id": "lab",
        "route_sha256_16": "a" * 16,
    }
    control.write_bytes(canonical_json_bytes(expected))
    real_remove = lifecycle_module.remove_control_conditionally

    def disappear_then_remove(path: Path, **kwargs: object) -> None:
        assert kwargs["missing_ok"] is True
        control_files.os.unlink(path)
        real_remove(path, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(
        lifecycle_module,
        "remove_control_conditionally",
        disappear_then_remove,
    )

    lifecycle_module._remove_owned_gateway_control(
        control,
        expected,
        label="session network gateway lease",
    )
    assert not control.exists()


def test_status_and_stop_use_bounded_session_loader_without_read_text(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "stopped-session.json"
    document = {
        "schema": "browser-core.session/1",
        "run_id": "stopped-run",
        "chromium_revision": "a" * 40,
        "pid": 42,
        "state": "stopped",
        "automation": {
            "transport": "cdp",
            "cdp_endpoint": "http://127.0.0.1:9222",
        },
    }
    path.write_bytes(json.dumps(document).encode("utf-8"))
    monkeypatch.setattr(
        Path,
        "read_text",
        lambda *_args, **_kwargs: pytest.fail("Path.read_text used"),
    )

    assert session_status(path)["state"] == "stopped"
    assert stop_session(path)["state"] == "stopped"


def test_idempotent_stop_rechecks_the_selected_stopped_snapshot(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "stopped-session.json"
    document = {
        "schema": "browser-core.session/1",
        "run_id": "stopped-run",
        "chromium_revision": "a" * 40,
        "pid": 42,
        "state": "stopped",
        "automation": {
            "transport": "cdp",
            "cdp_endpoint": "http://127.0.0.1:9222",
        },
    }
    path.write_bytes(json.dumps(document).encode("utf-8"))
    real_open = Path.open
    opens = 0

    def recording_open(self: Path, *args: object, **kwargs: object):  # type: ignore[no-untyped-def]
        nonlocal opens
        if self == path:
            opens += 1
        return real_open(self, *args, **kwargs)

    monkeypatch.setattr(Path, "open", recording_open)
    assert stop_session(path) == {
        "run_id": "stopped-run",
        "state": "stopped",
        "running": False,
        "identity_protected": False,
    }
    assert opens == 2


def _identity_stopped_session(tmp_path: Path) -> tuple[Path, dict[str, object]]:
    executable = tmp_path / "chrome.exe"
    executable.write_bytes(b"")
    identity = {
        "pid": 42,
        "executable": str(executable),
        "start_marker": "fixture:owned",
    }
    document = {
        "schema": "browser-core.session/1",
        "run_id": "stopped-owned-run",
        "chromium_revision": "a" * 40,
        "pid": 42,
        "state": "stopped",
        "process_identity": identity,
        "automation": {
            "transport": "cdp",
            "cdp_endpoint": "http://127.0.0.1:9222",
        },
    }
    path = tmp_path / "stopped-owned-run.json"
    path.write_bytes(json.dumps(document).encode("utf-8"))
    return path, identity


def test_idempotent_stop_rebinds_selected_session_after_process_observation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path, _identity = _identity_stopped_session(tmp_path)
    document = json.loads(path.read_bytes())
    original = path.read_bytes()
    challenger = json.dumps({**document, "state": "active"}).encode("utf-8") + b" "
    assert len(challenger) == len(original)
    before = path.stat()

    def replace_during_observation(_pid: int) -> dict:
        with path.open("r+b") as stream:
            stream.write(challenger)
        os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns))
        raise ProcessLookupError("process exited")

    monkeypatch.setattr(lifecycle_module, "observe_process", replace_during_observation)
    monkeypatch.setattr(lifecycle_module, "reap_launched_process", lambda _pid: True)
    with pytest.raises(ContractError, match="session contract changed after stop"):
        stop_session(path)
    assert path.read_bytes() == challenger


def test_persisted_stopped_session_detects_exact_process_still_running(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path, identity = _identity_stopped_session(tmp_path)
    monkeypatch.setattr(lifecycle_module, "observe_process", lambda _pid: identity)
    monkeypatch.setattr(
        lifecycle_module,
        "reap_launched_process",
        lambda *_args: pytest.fail("contradictory session reached reap"),
    )

    assert session_status(path) == {
        "run_id": "stopped-owned-run",
        "state": "inconsistent",
        "running": True,
        "identity_protected": True,
    }
    with pytest.raises(ContractError, match="still running"):
        stop_session(path)


def test_persisted_stopped_session_accepts_pid_reuse_as_owned_exit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path, identity = _identity_stopped_session(tmp_path)
    monkeypatch.setattr(
        lifecycle_module,
        "observe_process",
        lambda _pid: {**identity, "start_marker": "fixture:reused"},
    )
    reaped: list[int] = []
    monkeypatch.setattr(
        lifecycle_module,
        "reap_launched_process",
        lambda pid: reaped.append(pid) or True,
    )

    assert session_status(path)["state"] == "stopped"
    assert stop_session(path) == {
        "run_id": "stopped-owned-run",
        "state": "stopped",
        "running": False,
        "identity_protected": True,
    }
    assert reaped == [42]


def test_persisted_stopped_session_rejects_malformed_process_observation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path, identity = _identity_stopped_session(tmp_path)
    monkeypatch.setattr(
        lifecycle_module,
        "observe_process",
        lambda _pid: {**identity, "executable": "relative.exe"},
    )
    with pytest.raises(ContractError, match="identity"):
        session_status(path)
    with pytest.raises(ContractError, match="identity"):
        stop_session(path)


def test_stop_preserves_a_session_replaced_during_transition(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    create_profile(tmp_path, "persistent")
    lock = acquire_profile_lock(tmp_path, "persistent", "fixture-run")
    path, document = _session(tmp_path, lock)
    replacement = {**document, "run_id": "replacement-run"}
    replacement_body = canonical_json_bytes(replacement)
    real_rename = control_files.os.rename

    def replace_before_rename(source_path: Path, quarantine: Path) -> None:
        if source_path != path:
            real_rename(source_path, quarantine)
            return
        injected = tmp_path / "injected-session"
        injected.write_bytes(replacement_body)
        control_files.os.replace(injected, source_path)
        real_rename(source_path, quarantine)

    monkeypatch.setattr(control_files.os, "rename", replace_before_rename)
    monkeypatch.setattr(
        "browser_core.lifecycle.request_browser_close",
        lambda endpoint, timeout_seconds: None,
    )
    monkeypatch.setattr(
        "browser_core.lifecycle.wait_for_verified_exit",
        lambda expected, timeout_seconds: True,
    )
    monkeypatch.setattr(
        "browser_core.lifecycle.terminate_verified",
        lambda expected, timeout_seconds: pytest.fail(
            "force termination should not be used"
        ),
    )

    with pytest.raises(ContractError, match="changed during transition") as raised:
        stop_session(path)
    assert str(path) not in str(raised.value)
    assert path.read_bytes() == replacement_body
    assert not list(tmp_path.glob(".session.json.previous-*"))
    assert not lock.exists()


@pytest.mark.parametrize(
    "timeout",
    [True, 0.0, -1.0, 301.0, 10**400, float("nan"), float("inf"), float("-inf"), "1"],
)
def test_stop_rejects_nonpositive_or_nonfinite_timeout_before_loading(
    tmp_path: Path,
    timeout: object,
) -> None:
    path = tmp_path / "missing-session.json"
    with pytest.raises(ContractError, match="timeout must be finite and > 0"):
        stop_session(path, timeout_seconds=timeout)  # type: ignore[arg-type]


def test_stop_graceful_and_forced_browser_phases_share_one_deadline(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    create_profile(tmp_path, "persistent")
    lock = acquire_profile_lock(tmp_path, "persistent", "fixture-run")
    path, _document = _session(tmp_path, lock)
    clock = [50.0]
    close_budgets: list[float] = []
    wait_budgets: list[float] = []
    termination_budgets: list[float] = []

    def close(_endpoint: str, timeout_seconds: float) -> None:
        close_budgets.append(timeout_seconds)
        clock[0] += 2.0

    def wait(_expected: dict[str, object], timeout_seconds: float) -> bool:
        wait_budgets.append(timeout_seconds)
        clock[0] += timeout_seconds
        return False

    monkeypatch.setattr(lifecycle_module.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(lifecycle_module, "request_browser_close", close)
    monkeypatch.setattr(lifecycle_module, "wait_for_verified_exit", wait)
    monkeypatch.setattr(
        lifecycle_module,
        "terminate_verified",
        lambda _expected, timeout_seconds: termination_budgets.append(timeout_seconds),
    )

    result = stop_session(path, timeout_seconds=10.0)
    assert result["state"] == "stopped"
    assert result["shutdown_mode"] == "forced"
    assert close_budgets == [pytest.approx(5.0)]
    assert wait_budgets == [pytest.approx(3.0)]
    assert termination_budgets == [pytest.approx(5.0)]


def test_stop_allows_trace_callers_to_extend_only_the_graceful_phase(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    create_profile(tmp_path, "persistent")
    lock = acquire_profile_lock(tmp_path, "persistent", "fixture-run")
    path, _document = _session(tmp_path, lock)
    clock = [50.0]
    close_budgets: list[float] = []
    wait_budgets: list[float] = []

    def close(_endpoint: str, timeout_seconds: float) -> None:
        close_budgets.append(timeout_seconds)
        clock[0] += 2.0

    def wait(_expected: dict[str, object], timeout_seconds: float) -> bool:
        wait_budgets.append(timeout_seconds)
        return True

    monkeypatch.setattr(lifecycle_module.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(lifecycle_module, "request_browser_close", close)
    monkeypatch.setattr(lifecycle_module, "wait_for_verified_exit", wait)
    monkeypatch.setattr(
        lifecycle_module,
        "terminate_verified",
        lambda *_args, **_kwargs: pytest.fail("graceful exit was force-terminated"),
    )

    result = stop_session(
        path,
        timeout_seconds=60.0,
        graceful_timeout_seconds=15.0,
    )
    assert result["shutdown_mode"] == "graceful"
    assert close_budgets == [pytest.approx(15.0)]
    assert wait_budgets == [pytest.approx(13.0)]


def test_default_graceful_phase_allows_trace_flush_beyond_five_seconds(monkeypatch, tmp_path):
    create_profile(tmp_path, "persistent")
    lock = acquire_profile_lock(tmp_path, "persistent", "fixture-run")
    path, _ = _session(tmp_path, lock)
    clock = [50.0]
    monkeypatch.setattr(lifecycle_module.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(lifecycle_module, "request_browser_close", lambda *a, **k: None)

    def wait(expected, timeout_seconds):
        assert timeout_seconds == pytest.approx(15.0)
        clock[0] += 8.0
        return True

    monkeypatch.setattr(lifecycle_module, "wait_for_verified_exit", wait)
    monkeypatch.setattr(lifecycle_module, "terminate_verified", lambda *a, **k: pytest.fail("trace flush interrupted"))
    result = stop_session(path, timeout_seconds=40.0)
    assert result["shutdown_mode"] == "graceful"


def test_stop_distinguishes_exit_before_the_force_signal(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    create_profile(tmp_path, "persistent")
    lock = acquire_profile_lock(tmp_path, "persistent", "fixture-run")
    path, _document = _session(tmp_path, lock)
    monkeypatch.setattr(
        lifecycle_module, "request_browser_close", lambda *_a, **_k: None
    )
    monkeypatch.setattr(
        lifecycle_module,
        "wait_for_verified_exit",
        lambda *_a, **_k: False,
    )

    def disappeared(*_args: object, **_kwargs: object) -> None:
        raise ProcessLookupError

    monkeypatch.setattr(lifecycle_module, "terminate_verified", disappeared)
    result = stop_session(path)
    assert result["shutdown_mode"] == "exited-before-force"


def test_stop_checks_owned_exit_after_close_channel_failure(monkeypatch, tmp_path):
    create_profile(tmp_path, 'persistent')
    lock = acquire_profile_lock(tmp_path, 'persistent', 'fixture-run')
    path, _ = _session(tmp_path, lock)
    def close(*args, **kwargs):
        raise ContractError('owned browser control endpoint is unavailable')
    waited = []
    monkeypatch.setattr(lifecycle_module, 'request_browser_close', close)
    monkeypatch.setattr(lifecycle_module, 'wait_for_verified_exit', lambda *a, **kw: waited.append(True) or True)
    monkeypatch.setattr(lifecycle_module, 'terminate_verified', lambda *a, **kw: pytest.fail('already exited process was sent to termination'))
    result = stop_session(path)
    assert waited == [True] and result['state'] == 'stopped'
    assert result['shutdown_mode'] == 'exited-before-force' and not lock.exists()


def _attested_child_fixture(tmp_path, monkeypatch):
    create_profile(tmp_path, 'persistent')
    lock = acquire_profile_lock(tmp_path, 'persistent', 'fixture-run')
    path, document = _session(tmp_path, lock)
    document['build'] = {'provenance': 'attested-browser-core', 'executable_sha256_16': 'a' * 16,
        'runtime_bundle_sha256_16': 'b' * 16, 'attestation_created_at': '2026-09-14T00:00:00Z'}
    document['process_identity']['start_marker'] = 'windows-filetime:100'
    path.write_text(json.dumps(document), encoding='utf-8')
    monkeypatch.setattr(lifecycle_module.sys, 'platform', 'win32')
    return path, lock, document


def test_attested_stop_does_not_remove_profile_before_observed_child_exit(tmp_path, monkeypatch):
    from browser_core.process_children import ChildSnapshot
    path, lock, document = _attested_child_fixture(tmp_path, monkeypatch)
    child = {**document['process_identity'], 'pid': 43}
    monkeypatch.setattr(lifecycle_module, 'observe_browser_children', lambda _e: ChildSnapshot(True, (child,)), raising=False)
    monkeypatch.setattr(lifecycle_module, 'request_browser_close', lambda *a, **kw: None)
    monkeypatch.setattr(lifecycle_module, 'wait_for_verified_exit', lambda expected, _t: expected['pid'] != 43)
    monkeypatch.setattr(lifecycle_module, 'terminate_verified', lambda *a, **kw: pytest.fail('child received a termination attempt'))
    with pytest.raises(ContractError, match='child exit'):
        stop_session(path)
    assert lock.exists() and json.loads(path.read_text())['state'] == 'active'


def test_attested_stop_skips_stale_endpoint_and_finishes_owned_cleanup(tmp_path, monkeypatch):
    from browser_core.process_children import ChildSnapshot
    path, lock, _ = _attested_child_fixture(tmp_path, monkeypatch)
    monkeypatch.setattr(lifecycle_module, 'observe_browser_children', lambda _e: ChildSnapshot(False, ()), raising=False)
    monkeypatch.setattr(lifecycle_module, 'request_browser_close', lambda *a, **kw: pytest.fail('stale endpoint contacted'))
    monkeypatch.setattr(lifecycle_module, 'wait_for_verified_exit', lambda *a, **kw: True)
    result = stop_session(path)
    assert result['shutdown_mode'] == 'exited-before-force' and not lock.exists()


def test_attested_cleanup_retry_retains_observed_children_after_parent_exit(tmp_path, monkeypatch):
    from browser_core.process_children import ChildSnapshot
    path, lock, document = _attested_child_fixture(tmp_path, monkeypatch)
    child = {**document['process_identity'], 'pid': 43}
    snapshots = iter([ChildSnapshot(True, (child,)), ChildSnapshot(False, ())])
    monkeypatch.setattr(lifecycle_module, 'observe_browser_children', lambda _e: next(snapshots), raising=False)
    monkeypatch.setattr(lifecycle_module, 'request_browser_close', lambda *a, **kw: None)
    monkeypatch.setattr(lifecycle_module, 'wait_for_verified_exit', lambda expected, _t: expected['pid'] != 43)
    for _ in range(2):
        with pytest.raises(ContractError, match='child exit'):
            stop_session(path)
    assert lock.exists() and json.loads(path.read_text())['state'] == 'active'


@pytest.mark.parametrize(
    "timeout",
    [True, 0.0, -1.0, 301.0, 10**400, float("nan"), float("inf"), float("-inf"), "1"],
)
def test_stop_rejects_invalid_graceful_timeout_before_loading(
    tmp_path: Path,
    timeout: object,
) -> None:
    path = tmp_path / "missing-session.json"
    with pytest.raises(
        ContractError, match="graceful stop timeout must be finite and > 0"
    ):
        stop_session(  # type: ignore[arg-type]
            path,
            graceful_timeout_seconds=timeout,
        )


def test_gateway_graceful_wait_reserves_only_the_same_deadline_remainder(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    gateway_dir = tmp_path / "network" / "gateways"
    gateway_dir.mkdir(parents=True)
    lease = gateway_dir / "fixture-run.lease"
    ready = gateway_dir / "fixture-run.json"
    lease.write_bytes(
        canonical_json_bytes(
            {
                "schema": "browser-core.gateway-lease/2",
                "run_id": "fixture-run",
                "route_id": "lab",
                "route_sha256_16": "a" * 16,
            }
        )
    )
    ready.write_bytes(
        canonical_json_bytes(
            {
                "schema": "browser-core.gateway-ready/2",
                "run_id": "fixture-run",
                "route_id": "lab",
                "route_sha256_16": "a" * 16,
                "host": "127.0.0.1",
                "port": 8765,
            }
        )
    )
    session = {
        "run_id": "fixture-run",
        "network": {
            "route_id": "lab",
            "route_sha256_16": "a" * 16,
            "gateway": {
                "endpoint": "http://127.0.0.1:8765",
                "process_identity": {
                    "pid": 84,
                    "executable": str(tmp_path / "python.exe"),
                    "start_marker": "fixture:gateway",
                },
                "lease_path": str(lease),
                "ready_path": str(ready),
            },
        },
    }
    clock = [70.0]
    waits: list[float] = []
    terminations: list[float] = []

    def wait(_expected: dict[str, object], timeout_seconds: float) -> bool:
        waits.append(timeout_seconds)
        clock[0] += timeout_seconds
        return False

    monkeypatch.setattr(lifecycle_module.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(lifecycle_module, "wait_for_verified_exit", wait)
    monkeypatch.setattr(
        lifecycle_module,
        "terminate_verified",
        lambda _expected, timeout_seconds: terminations.append(timeout_seconds),
    )

    lifecycle_module._stop_network_gateway(
        tmp_path,
        session,
        deadline=73.0,
        managed_layout=False,
    )
    assert waits == [pytest.approx(2.9)]
    assert terminations == [pytest.approx(0.1)]
    assert not lease.exists()
    assert not ready.exists()


def _gateway_controls(tmp_path: Path) -> tuple[dict[str, object], Path, Path]:
    gateway_dir = tmp_path / "network" / "gateways"
    gateway_dir.mkdir(parents=True)
    lease = gateway_dir / "fixture-run.lease"
    ready = gateway_dir / "fixture-run.json"
    lease.write_bytes(
        canonical_json_bytes(
            {
                "schema": "browser-core.gateway-lease/2",
                "run_id": "fixture-run",
                "route_id": "lab",
                "route_sha256_16": "a" * 16,
            }
        )
    )
    ready.write_bytes(
        canonical_json_bytes(
            {
                "schema": "browser-core.gateway-ready/2",
                "run_id": "fixture-run",
                "route_id": "lab",
                "route_sha256_16": "a" * 16,
                "host": "127.0.0.1",
                "port": 8765,
            }
        )
    )
    session: dict[str, object] = {
        "run_id": "fixture-run",
        "network": {
            "route_id": "lab",
            "route_sha256_16": "a" * 16,
            "gateway": {
                "endpoint": "http://127.0.0.1:8765",
                "process_identity": {
                    "pid": 84,
                    "executable": str(tmp_path / "python.exe"),
                    "start_marker": "fixture:gateway",
                },
                "lease_path": str(lease),
                "ready_path": str(ready),
            },
        },
    }
    return session, lease, ready


def test_gateway_stop_preserves_a_lease_replaced_during_removal(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    session, lease, ready = _gateway_controls(tmp_path)
    competitor = canonical_json_bytes(
        {
            "schema": "browser-core.gateway-lease/2",
            "run_id": "competitor",
            "route_id": "other",
            "route_sha256_16": "b" * 16,
        }
    )
    real_rename = control_files.os.rename

    def replace_lease(source_path: Path, quarantine: Path) -> None:
        if source_path == lease:
            injected = tmp_path / "injected-lease"
            injected.write_bytes(competitor)
            control_files.os.replace(injected, source_path)
        real_rename(source_path, quarantine)

    monkeypatch.setattr(control_files.os, "rename", replace_lease)
    monkeypatch.setattr(
        lifecycle_module,
        "wait_for_verified_exit",
        lambda *_args, **_kwargs: pytest.fail(
            "gateway wait began after lease conflict"
        ),
    )

    with pytest.raises(ContractError, match="lease changed during removal") as raised:
        lifecycle_module._stop_network_gateway(
            tmp_path,
            session,
            deadline=lifecycle_module.time.monotonic() + 10.0,
            managed_layout=False,
        )
    assert str(lease) not in str(raised.value)
    assert lease.read_bytes() == competitor
    assert ready.exists()
    assert not list(lease.parent.glob(".fixture-run.lease.removed-*"))


def test_gateway_stop_preserves_readiness_replaced_after_gateway_exit(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    session, lease, ready = _gateway_controls(tmp_path)
    competitor = canonical_json_bytes(
        {
            "schema": "browser-core.gateway-ready/2",
            "run_id": "competitor",
            "route_id": "other",
            "route_sha256_16": "b" * 16,
            "host": "127.0.0.1",
            "port": 9999,
        }
    )
    real_rename = control_files.os.rename

    def replace_ready(source_path: Path, quarantine: Path) -> None:
        if source_path == ready:
            injected = tmp_path / "injected-ready"
            injected.write_bytes(competitor)
            control_files.os.replace(injected, source_path)
        real_rename(source_path, quarantine)

    monkeypatch.setattr(control_files.os, "rename", replace_ready)
    monkeypatch.setattr(
        lifecycle_module,
        "wait_for_verified_exit",
        lambda *_args, **_kwargs: True,
    )
    monkeypatch.setattr(
        lifecycle_module,
        "terminate_verified",
        lambda *_args, **_kwargs: pytest.fail("exited gateway was terminated"),
    )

    with pytest.raises(
        ContractError, match="readiness changed during removal"
    ) as raised:
        lifecycle_module._stop_network_gateway(
            tmp_path,
            session,
            deadline=lifecycle_module.time.monotonic() + 10.0,
            managed_layout=False,
        )
    assert str(ready) not in str(raised.value)
    assert not lease.exists()
    assert ready.read_bytes() == competitor
    assert not list(ready.parent.glob(".fixture-run.json.removed-*"))


def test_managed_session_filename_must_match_run_before_process_contact(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    document = {
        "schema": "browser-core.session/1",
        "run_id": "owned-run",
        "chromium_revision": "a" * 40,
        "pid": 42,
        "process_identity": {
            "pid": 42,
            "executable": "chrome.exe",
            "start_marker": "fixture:1",
        },
        "automation": {"transport": "cdp", "cdp_endpoint": "http://127.0.0.1:9222"},
    }
    path = tmp_path / "sessions" / "wrong-name.json"
    path.parent.mkdir()
    path.write_bytes(canonical_json_bytes(document))
    monkeypatch.setattr(
        lifecycle_module,
        "request_browser_close",
        lambda *_args, **_kwargs: pytest.fail("process contact occurred"),
    )
    with pytest.raises(ContractError, match="filename does not match"):
        stop_session(path)


def test_gateway_controls_outside_workspace_are_preserved(
    tmp_path: Path,
) -> None:
    session, lease, ready = _gateway_controls(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    outside_lease = outside / lease.name
    outside_ready = outside / ready.name
    lease.replace(outside_lease)
    ready.replace(outside_ready)
    gateway = session["network"]["gateway"]  # type: ignore[index]
    gateway["lease_path"] = str(outside_lease)  # type: ignore[index]
    gateway["ready_path"] = str(outside_ready)  # type: ignore[index]

    with pytest.raises(ContractError, match="outside the workspace"):
        lifecycle_module._stop_network_gateway(
            tmp_path,
            session,
            deadline=lifecycle_module.time.monotonic() + 10.0,
            managed_layout=False,
        )
    assert outside_lease.exists() and outside_ready.exists()


def test_persistent_profile_lock_outside_workspace_is_preserved(tmp_path: Path) -> None:
    outside_profile = tmp_path / "outside" / "profile"
    outside_profile.mkdir(parents=True)
    lock = outside_profile / ".browser-core.lock"
    lock.write_bytes(
        canonical_json_bytes(
            {
                "schema": "browser-core.profile-lock/1",
                "run_id": "owned-run",
            }
        )
    )
    session = {
        "run_id": "owned-run",
        "profile": {
            "id": "profile",
            "persistence": "persistent",
            "path": str(outside_profile),
            "lock_path": str(lock),
        },
    }
    with pytest.raises(ContractError, match="outside the workspace"):
        lifecycle_module._release_session_profile_lock(tmp_path, session)
    assert lock.exists()


def test_managed_gateway_requires_browser_core_runtime_executable(
    tmp_path: Path,
) -> None:
    session, lease, ready = _gateway_controls(tmp_path)
    with pytest.raises(ContractError, match="not Browser Core's runtime"):
        lifecycle_module._stop_network_gateway(
            tmp_path,
            session,
            deadline=lifecycle_module.time.monotonic() + 10.0,
            managed_layout=True,
        )
    assert lease.exists() and ready.exists()


def test_stop_fails_before_forced_termination_when_deadline_is_exhausted(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    create_profile(tmp_path, "persistent")
    lock = acquire_profile_lock(tmp_path, "persistent", "fixture-run")
    path, _document = _session(tmp_path, lock)
    original = path.read_bytes()
    clock = [90.0]

    def overrun_close(_endpoint: str, timeout_seconds: float) -> None:
        assert timeout_seconds == pytest.approx(0.5)
        clock[0] += 1.1

    monkeypatch.setattr(lifecycle_module.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(lifecycle_module, "request_browser_close", overrun_close)
    monkeypatch.setattr(
        lifecycle_module,
        "wait_for_verified_exit",
        lambda *_args, **_kwargs: pytest.fail("expired graceful wait was attempted"),
    )
    monkeypatch.setattr(
        lifecycle_module,
        "terminate_verified",
        lambda *_args, **_kwargs: pytest.fail("termination began after deadline"),
    )

    with pytest.raises(
        ContractError, match="deadline exhausted before browser termination"
    ):
        stop_session(path, timeout_seconds=1.0)
    assert path.read_bytes() == original
    assert lock.exists()


def test_status_and_stop_errors_omit_session_path_and_raw_decoder_text(
    tmp_path: Path,
) -> None:
    path = tmp_path / "private-session.json"
    path.write_bytes(b'{"schema":"browser-core.session/1","value":"\xff"}')

    for action in (lambda: session_status(path), lambda: stop_session(path)):
        with pytest.raises(ContractError, match="encoding is invalid") as raised:
            action()
        rendered = "".join(
            traceback.format_exception(
                type(raised.value), raised.value, raised.value.__traceback__
            )
        )
        assert str(path) not in str(raised.value)
        assert str(path) not in rendered
        assert "invalid start byte" not in rendered
