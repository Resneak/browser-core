from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest

import browser_core.worker as worker_module
from browser_core.contracts import ContractError
from browser_core.control import ControlStore
from browser_core.http2_fingerprint import http2_fingerprint_digest
from browser_core.http2_headers import (
    http2_capture_evidence_digest,
    http2_header_order_digest,
)
from browser_core.transport_fingerprint import approve_transport_baseline, transport_digest
from browser_core.worker import (
    _failure_receipt,
    _project_browser_eval_summary,
    _project_multi_identity_ops_report,
    _project_pinwatch_drift_result,
    _require_workspace_file,
    _session_path,
    execute_typed_job,
    run_remote_worker_once,
    run_worker_once,
)


ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize("lease_token", ["", "bad\rvalue", "caf\u00e9", "x" * 1025])
def test_remote_worker_rejects_unusable_lease_before_job_dispatch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, lease_token: str
) -> None:
    class MalformedLeaseClient:
        def worker_lease(self, *, lease_seconds: int) -> dict[str, object]:
            assert lease_seconds == 120
            return {
                "id": "job-1",
                "kind": "kernel-probe",
                "payload": {},
                "lease_token": lease_token,
            }

        def worker_complete(self, *_args: object, **_kwargs: object) -> None:
            pytest.fail("invalid lease reached completion")

    monkeypatch.setattr(
        worker_module,
        "execute_typed_job",
        lambda *_args, **_kwargs: pytest.fail("invalid lease reached job dispatch"),
    )
    with pytest.raises(ContractError, match="remote worker lease response"):
        run_remote_worker_once(
            MalformedLeaseClient(), repository_root=ROOT, workspace=tmp_path
        )


def test_remote_worker_rejects_lease_without_job_id_before_dispatch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class MissingIdClient:
        def worker_lease(self, *, lease_seconds: int) -> dict[str, object]:
            assert lease_seconds == 120
            return {"kind": "kernel-probe", "payload": {}, "lease_token": "token"}

        def worker_complete(self, *_args: object, **_kwargs: object) -> None:
            pytest.fail("missing ID reached completion")

    monkeypatch.setattr(
        worker_module,
        "execute_typed_job",
        lambda *_args, **_kwargs: pytest.fail("missing ID reached job dispatch"),
    )
    with pytest.raises(ContractError, match="remote worker lease response"):
        run_remote_worker_once(MissingIdClient(), repository_root=ROOT, workspace=tmp_path)


def test_typed_worker_rejects_linked_workspace_before_dispatch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    workspace = tmp_path / "workspace"
    if os.name == "nt":
        created = subprocess.run(
            ["cmd", "/c", "mklink", "/J", str(workspace), str(outside)],
            capture_output=True,
            check=False,
        )
        if created.returncode:
            pytest.skip("host could not create an unprivileged directory junction")
    else:
        workspace.symlink_to(outside, target_is_directory=True)
    monkeypatch.setattr(
        worker_module,
        "discover_kernels",
        lambda _root: pytest.fail("linked workspace reached job dispatch"),
    )
    try:
        with pytest.raises(ContractError, match="workspace"):
            execute_typed_job(
                {
                    "id": "job-1",
                    "kind": "kernel-probe",
                    "payload": {
                        "kernel_id": "playwright-webkit",
                        "device_preset": "iPhone 13",
                        "locale": "en-US",
                        "timezone": "America/Chicago",
                    },
                },
                repository_root=ROOT,
                workspace=workspace,
            )
    finally:
        if os.name == "nt":
            workspace.rmdir()
        else:
            workspace.unlink()


def test_transport_worker_rejects_workspace_swap_before_registry_creation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import browser_core.transport_fingerprint as transport_module

    workspace = tmp_path / "workspace"
    workspace.mkdir()
    executable = workspace / "browser.exe"
    executable.write_bytes(b"fixture")
    holding = tmp_path / "holding"
    foreign = tmp_path / "foreign"
    foreign.mkdir()
    linked = False

    def swap_after_file_check(_value: object, _root: Path, _label: str) -> Path:
        nonlocal linked
        workspace.rename(holding)
        if os.name == "nt":
            created = subprocess.run(
                ["cmd", "/c", "mklink", "/J", str(workspace), str(foreign)],
                capture_output=True,
                check=False,
            )
            if created.returncode:
                holding.rename(workspace)
                pytest.skip("host could not create an unprivileged directory junction")
        else:
            workspace.symlink_to(foreign, target_is_directory=True)
        linked = True
        return holding / "browser.exe"

    monkeypatch.setattr(worker_module, "_require_workspace_file", swap_after_file_check)
    monkeypatch.setattr(
        transport_module,
        "capture_attested_client_hello",
        lambda *_args, **_kwargs: pytest.fail("swapped workspace reached capture"),
    )
    try:
        with pytest.raises(ContractError, match="workspace|registry"):
            execute_typed_job(
                {
                    "id": "job-1",
                    "kind": "transport-fingerprint",
                    "payload": {
                        "executable": str(executable),
                        "fingerprint_id": "fingerprint-1",
                        "timeout_seconds": 1.0,
                    },
                },
                repository_root=ROOT,
                workspace=workspace,
            )
        assert not (foreign / "transport-fingerprints").exists()
    finally:
        if linked:
            if os.name == "nt":
                workspace.rmdir()
            else:
                workspace.unlink()


def test_evidence_pack_worker_does_not_create_foreign_output_after_workspace_swap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace = tmp_path / "workspace"
    sessions = workspace / "sessions"
    sessions.mkdir(parents=True)
    (sessions / "session-1.json").write_bytes(b"{}")
    holding = tmp_path / "holding"
    foreign = tmp_path / "foreign"
    foreign.mkdir()
    linked = False

    def swap_after_session_check(_workspace: Path, _session_id: str) -> Path:
        nonlocal linked
        workspace.rename(holding)
        if os.name == "nt":
            created = subprocess.run(
                ["cmd", "/c", "mklink", "/J", str(workspace), str(foreign)],
                capture_output=True,
                check=False,
            )
            if created.returncode:
                holding.rename(workspace)
                pytest.skip("host could not create an unprivileged directory junction")
        else:
            workspace.symlink_to(foreign, target_is_directory=True)
        linked = True
        return holding / "sessions" / "session-1.json"

    monkeypatch.setattr(worker_module, "_session_path", swap_after_session_check)
    try:
        with pytest.raises(ContractError):
            execute_typed_job(
                {
                    "id": "job-1",
                    "kind": "evidence-pack",
                    "payload": {
                        "session_id": "session-1",
                        "pack_id": "pack-1",
                        "browser_fact_id": None,
                        "transport_fingerprint_id": None,
                        "http2_fingerprint_id": None,
                        "include_session_copy": False,
                    },
                },
                repository_root=ROOT,
                workspace=workspace,
            )
        assert not (foreign / "evidence-packs").exists()
    finally:
        if linked:
            if os.name == "nt":
                workspace.rmdir()
            else:
                workspace.unlink()


def test_pinwatch_worker_does_not_read_foreign_sources_after_workspace_swap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    holding = tmp_path / "holding"
    foreign = tmp_path / "foreign"
    pinwatch = foreign / "webre-pinwatch"
    (pinwatch / "traces").mkdir(parents=True)
    (pinwatch / "baselines").mkdir()
    (pinwatch / "traces" / "trace-1.jsonl").write_bytes(b"{}\n")
    for name in ("old-1", "new-1"):
        (pinwatch / "baselines" / f"{name}.json").write_bytes(b"{}")
    original_workspace_check = worker_module._worker_workspace_path
    linked = False

    def swap_after_workspace_check(path: Path) -> Path:
        nonlocal linked
        checked = original_workspace_check(path)
        workspace.rename(holding)
        if os.name == "nt":
            created = subprocess.run(
                ["cmd", "/c", "mklink", "/J", str(workspace), str(foreign)],
                capture_output=True,
                check=False,
            )
            if created.returncode:
                holding.rename(workspace)
                pytest.skip("host could not create an unprivileged directory junction")
        else:
            workspace.symlink_to(foreign, target_is_directory=True)
        linked = True
        return checked

    monkeypatch.setattr(worker_module, "_worker_workspace_path", swap_after_workspace_check)
    monkeypatch.setattr(
        worker_module,
        "_pinwatch_source_snapshot",
        lambda *_args, **_kwargs: pytest.fail("foreign PinWatch source was read"),
    )
    try:
        with pytest.raises(ContractError, match="workspace|PinWatch"):
            execute_typed_job(
                {
                    "id": "job-1",
                    "kind": "pinwatch-drift-check",
                    "payload": {
                        "output_id": "out-1",
                        "graph_trace_id": "trace-1",
                        "old_baseline_id": "old-1",
                        "new_baseline_id": "new-1",
                        "contract_id": None,
                        "old_runtime_id": None,
                        "new_runtime_id": None,
                        "graph_side": "none",
                    },
                },
                repository_root=ROOT,
                workspace=workspace,
            )
        assert not (pinwatch / "flows").exists()
    finally:
        if linked:
            if os.name == "nt":
                workspace.rmdir()
            else:
                workspace.unlink()


def test_multi_identity_worker_does_not_create_foreign_job_output_after_swap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    holding = tmp_path / "holding"
    foreign = tmp_path / "foreign"
    (foreign / "fleet-ops").mkdir(parents=True)
    expected_out = workspace / "fleet-ops" / "job-1"
    original_identity = worker_module.directory_identity
    linked = False

    def swap_before_output_check(path: Path, *, label: str):  # noqa: ANN202
        nonlocal linked
        if path == expected_out and not linked:
            workspace.rename(holding)
            if os.name == "nt":
                created = subprocess.run(
                    ["cmd", "/c", "mklink", "/J", str(workspace), str(foreign)],
                    capture_output=True,
                    check=False,
                )
                if created.returncode:
                    holding.rename(workspace)
                    pytest.skip("host could not create an unprivileged directory junction")
            else:
                workspace.symlink_to(foreign, target_is_directory=True)
            linked = True
        return original_identity(path, label=label)

    monkeypatch.setattr(worker_module, "directory_identity", swap_before_output_check)
    monkeypatch.setattr(
        worker_module,
        "_require_workspace_file",
        lambda *_args, **_kwargs: workspace / "browser.exe",
    )
    try:
        with pytest.raises(ContractError, match="workspace|output root|output authority"):
            execute_typed_job(
                {
                    "id": "job-1",
                    "kind": "multi-identity-ops",
                    "payload": {
                        "executable": str(workspace / "browser.exe"),
                        "count": 1,
                        "persona_ids": None,
                        "headless": True,
                        "parallel": 1,
                        "network_auto": False,
                        "network_route_id": None,
                        "device_class": "desktop",
                    },
                },
                repository_root=ROOT,
                workspace=workspace,
            )
        assert not (foreign / "fleet-ops" / "job-1").exists()
    finally:
        if linked:
            if os.name == "nt":
                workspace.rmdir()
            else:
                workspace.unlink()


def test_native_smoke_worker_rejects_workspace_swap_before_launch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    holding = tmp_path / "holding"
    foreign = tmp_path / "foreign"
    foreign.mkdir()
    checked_files = 0
    linked = False

    def swap_after_file_checks(_value: object, _root: Path, label: str) -> Path:
        nonlocal checked_files, linked
        checked_files += 1
        if checked_files == 2:
            workspace.rename(holding)
            if os.name == "nt":
                created = subprocess.run(
                    ["cmd", "/c", "mklink", "/J", str(workspace), str(foreign)],
                    capture_output=True,
                    check=False,
                )
                if created.returncode:
                    holding.rename(workspace)
                    pytest.skip("host could not create an unprivileged directory junction")
            else:
                workspace.symlink_to(foreign, target_is_directory=True)
            linked = True
        name = "trace_processor_shell.exe" if "trace processor" in label else "browser.exe"
        return (holding if linked else workspace) / name

    monkeypatch.setattr(worker_module, "_require_workspace_file", swap_after_file_checks)
    monkeypatch.setattr(
        worker_module,
        "run_native_canvas_smoke",
        lambda *_args, **_kwargs: pytest.fail("swapped workspace reached native launch"),
    )
    try:
        with pytest.raises(ContractError, match="workspace"):
            execute_typed_job(
                {
                    "id": "job-1",
                    "kind": "native-smoke",
                    "payload": {
                        "executable": str(workspace / "browser.exe"),
                        "trace_processor": str(workspace / "trace_processor_shell.exe"),
                        "timeout_seconds": 1.0,
                    },
                },
                repository_root=ROOT,
                workspace=workspace,
            )
    finally:
        if linked:
            if os.name == "nt":
                workspace.rmdir()
            else:
                workspace.unlink()


def test_worker_executable_rejects_hard_link_outside_workspace(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    outside = tmp_path / "outside.exe"
    outside.write_bytes(b"private executable body")
    alias = workspace / "browser.exe"
    try:
        os.link(outside, alias)
    except OSError:
        pytest.skip("host cannot create a hard-link fixture")
    with pytest.raises(ContractError):
        _require_workspace_file(str(alias), workspace, "executable")
    assert outside.read_bytes() == b"private executable body"


def test_evidence_pack_worker_rejects_linked_browser_fact_registry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import browser_core.evidence_pack as evidence_module

    workspace = tmp_path / "workspace"
    sessions = workspace / "sessions"
    sessions.mkdir(parents=True)
    (sessions / "session-1.json").write_bytes(b"{}")
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "fact-1.json").write_bytes(b"{}")
    registry = workspace / "browser-facts"
    if os.name == "nt":
        created = subprocess.run(
            ["cmd", "/c", "mklink", "/J", str(registry), str(outside)],
            capture_output=True,
            check=False,
        )
        if created.returncode:
            pytest.skip("host could not create an unprivileged directory junction")
    else:
        registry.symlink_to(outside, target_is_directory=True)
    monkeypatch.setattr(
        evidence_module,
        "build_evidence_pack",
        lambda **_kwargs: pytest.fail("linked browser fact reached pack builder"),
    )
    try:
        with pytest.raises(ContractError, match="browser fact|browser-fact"):
            execute_typed_job(
                {
                    "id": "job-1",
                    "kind": "evidence-pack",
                    "payload": {
                        "session_id": "session-1",
                        "pack_id": "pack-1",
                        "browser_fact_id": "fact-1",
                        "transport_fingerprint_id": None,
                        "http2_fingerprint_id": None,
                        "include_session_copy": False,
                    },
                },
                repository_root=ROOT,
                workspace=workspace,
            )
        assert (outside / "fact-1.json").read_bytes() == b"{}"
    finally:
        if os.name == "nt":
            registry.rmdir()
        else:
            registry.unlink()


def test_worker_session_registry_cannot_redirect_outside_workspace(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "session-1.json").write_bytes(b"{}")
    registry = workspace / "sessions"
    if os.name == "nt":
        created = subprocess.run(
            ["cmd", "/c", "mklink", "/J", str(registry), str(outside)],
            capture_output=True,
            check=False,
        )
        if created.returncode:
            pytest.skip("host could not create an unprivileged directory junction")
    else:
        registry.symlink_to(outside, target_is_directory=True)
    try:
        with pytest.raises(ContractError, match="session"):
            _session_path(workspace, "session-1")
    finally:
        if os.name == "nt":
            registry.rmdir()
        else:
            registry.unlink()


@pytest.mark.parametrize(
    ("lookup", "registry_name"),
    [
        ("_transport_fingerprint_path", "transport-fingerprints"),
        ("_http2_fingerprint_path", "http2-fingerprints"),
        ("_http2_evidence_path", "http2-evidence"),
    ],
)
def test_worker_source_registry_cannot_redirect_outside_workspace(
    tmp_path: Path, lookup: str, registry_name: str
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "source-1.json").write_bytes(b"{}")
    registry = workspace / registry_name
    if os.name == "nt":
        created = subprocess.run(
            ["cmd", "/c", "mklink", "/J", str(registry), str(outside)],
            capture_output=True,
            check=False,
        )
        if created.returncode:
            pytest.skip("host could not create an unprivileged directory junction")
    else:
        registry.symlink_to(outside, target_is_directory=True)
    try:
        with pytest.raises(ContractError):
            getattr(worker_module, lookup)(workspace, "source-1", label="source")
    finally:
        if os.name == "nt":
            registry.rmdir()
        else:
            registry.unlink()


def test_typed_worker_executes_real_kernel_probe(tmp_path: Path) -> None:
    store = ControlStore(tmp_path / "control")
    bootstrap = store.bootstrap(
        workspace_id="lab", workspace_name="Lab", owner_id="alice", owner_name="Alice"
    )
    owner = store.authenticate(bootstrap["token"])
    registered = store.register_worker(
        owner,
        "lab",
        "worker-one",
        name="Worker",
        capabilities=["webkit"],
        max_slots=1,
    )
    worker = store.authenticate_worker(registered["worker_token"])
    store.enqueue_job(
        owner,
        "lab",
        kind="kernel-probe",
        payload={
            "kernel_id": "playwright-webkit",
            "device_preset": "iPhone 13",
            "locale": "en-US",
            "timezone": "America/Chicago",
        },
        requirements=["webkit"],
        idempotency_key="webkit-iphone-live",
    )
    result = run_worker_once(
        store,
        worker,
        repository_root=ROOT,
        workspace=tmp_path / "runtime",
    )
    assert result is not None and result["state"] == "succeeded"
    assert store.fleet_status(owner, "lab")["jobs"]["succeeded"] == 1


def test_typed_worker_records_invalid_payload_as_failure(tmp_path: Path) -> None:
    store = ControlStore(tmp_path / "control")
    bootstrap = store.bootstrap(
        workspace_id="lab", workspace_name="Lab", owner_id="alice", owner_name="Alice"
    )
    owner = store.authenticate(bootstrap["token"])
    registered = store.register_worker(
        owner, "lab", "worker-one", name="Worker", capabilities=["webkit"], max_slots=1
    )
    worker = store.authenticate_worker(registered["worker_token"])
    store.enqueue_job(
        owner,
        "lab",
        kind="kernel-probe",
        payload={"unexpected": True},
        requirements=["webkit"],
        idempotency_key="invalid",
    )
    result = run_worker_once(
        store, worker, repository_root=ROOT, workspace=tmp_path / "runtime"
    )
    assert result is not None and result["state"] == "failed"


# -- the two workflows the monorepo actually runs after a probe ----------------
#
# Both were absent from the allowlist, so a fleet had to choose between local
# glue and a `shell` job the control plane refuses. Membership in JOB_KINDS is
# necessary and not sufficient: the worker must also implement the kind, and
# these tests assert both halves rather than the allowlist alone.


def test_the_two_capture_workflows_are_schedulable_and_implemented() -> None:
    from browser_core.control import JOB_KINDS

    for kind in ("browser-fact-capture", "evidence-pack"):
        assert kind in JOB_KINDS
        with pytest.raises(ContractError) as excinfo:
            execute_typed_job(
                {"kind": kind, "payload": {}, "id": "j-1"},
                repository_root=Path("."),
                workspace=Path("."),
            )
        # Rejected for its payload, which means the branch exists. An
        # unimplemented kind raises the catch-all instead.
        assert "not implemented" not in str(excinfo.value)


def test_multi_identity_ops_is_schedulable_and_implemented() -> None:
    from browser_core.control import JOB_KINDS

    assert "multi-identity-ops" in JOB_KINDS
    with pytest.raises(ContractError) as excinfo:
        execute_typed_job(
            {"kind": "multi-identity-ops", "payload": {}, "id": "j-1"},
            repository_root=Path("."),
            workspace=Path("."),
        )
    assert "not implemented" not in str(excinfo.value)


def test_transport_fingerprint_is_schedulable_and_implemented() -> None:
    from browser_core.control import JOB_KINDS

    assert "transport-fingerprint" in JOB_KINDS
    with pytest.raises(ContractError) as excinfo:
        execute_typed_job(
            {"kind": "transport-fingerprint", "payload": {}, "id": "j-1"},
            repository_root=Path("."),
            workspace=Path("."),
        )
    assert "not implemented" not in str(excinfo.value)


def test_transport_check_is_schedulable_and_implemented() -> None:
    from browser_core.control import JOB_KINDS

    assert "transport-check" in JOB_KINDS
    with pytest.raises(ContractError) as excinfo:
        execute_typed_job(
            {"kind": "transport-check", "payload": {}, "id": "j-1"},
            repository_root=Path("."),
            workspace=Path("."),
        )
    assert "not implemented" not in str(excinfo.value)


def test_transport_baseline_install_is_schedulable_and_implemented() -> None:
    from browser_core.control import JOB_KINDS

    assert "transport-baseline-install" in JOB_KINDS
    with pytest.raises(ContractError) as excinfo:
        execute_typed_job(
            {"kind": "transport-baseline-install", "payload": {}, "id": "j-1"},
            repository_root=Path("."),
            workspace=Path("."),
        )
    assert "not implemented" not in str(excinfo.value)


def test_http2_fingerprint_is_schedulable_and_implemented() -> None:
    from browser_core.control import JOB_KINDS

    assert "http2-fingerprint" in JOB_KINDS
    with pytest.raises(ContractError) as excinfo:
        execute_typed_job(
            {"kind": "http2-fingerprint", "payload": {}, "id": "j-1"},
            repository_root=Path("."),
            workspace=Path("."),
        )
    assert "not implemented" not in str(excinfo.value)


@pytest.mark.parametrize(
    "kind",
    [
        "http2-check",
        "http2-baseline-install",
        "http2-evidence",
        "http2-evidence-check",
        "http2-evidence-baseline-install",
    ],
)
def test_http2_baseline_jobs_are_schedulable_and_implemented(kind: str) -> None:
    from browser_core.control import JOB_KINDS

    assert kind in JOB_KINDS
    with pytest.raises(ContractError) as excinfo:
        execute_typed_job(
            {"kind": kind, "payload": {}, "id": "j-1"},
            repository_root=Path("."),
            workspace=Path("."),
        )
    assert "not implemented" not in str(excinfo.value)


def test_transport_suite_check_is_schedulable_and_implemented() -> None:
    from browser_core.control import JOB_KINDS

    assert "transport-suite-check" in JOB_KINDS
    with pytest.raises(ContractError) as excinfo:
        execute_typed_job(
            {"kind": "transport-suite-check", "payload": {}, "id": "j-1"},
            repository_root=Path("."),
            workspace=Path("."),
        )
    assert "not implemented" not in str(excinfo.value)


def test_transport_evidence_suite_check_is_schedulable_and_implemented() -> None:
    from browser_core.control import JOB_KINDS

    assert "transport-evidence-suite-check" in JOB_KINDS
    with pytest.raises(ContractError) as excinfo:
        execute_typed_job(
            {"kind": "transport-evidence-suite-check", "payload": {}, "id": "j-1"},
            repository_root=Path("."),
            workspace=Path("."),
        )
    assert "not implemented" not in str(excinfo.value)


def test_pinwatch_drift_check_is_schedulable_and_implemented() -> None:
    from browser_core.control import JOB_KINDS

    assert "pinwatch-drift-check" in JOB_KINDS
    with pytest.raises(ContractError) as excinfo:
        execute_typed_job(
            {"kind": "pinwatch-drift-check", "payload": {}, "id": "j-1"},
            repository_root=Path("."),
            workspace=Path("."),
        )
    assert "not implemented" not in str(excinfo.value)


def _pinwatch_job_payload() -> dict[str, object]:
    return {
        "output_id": "flow-1",
        "graph_trace_id": "trace-1",
        "old_baseline_id": "old-1",
        "new_baseline_id": "new-1",
        "contract_id": "contract-1",
        "old_runtime_id": None,
        "new_runtime_id": None,
        "graph_side": "new",
    }


def _pinwatch_source_workspace(tmp_path: Path) -> Path:
    workspace = tmp_path / "worker"
    root = workspace / "webre-pinwatch"
    for directory in ("traces", "baselines", "contracts", "runtimes"):
        (root / directory).mkdir(parents=True, exist_ok=True)
    (root / "traces" / "trace-1.jsonl").write_text("{}\n", encoding="utf-8")
    (root / "baselines" / "old-1.json").write_text("{}", encoding="utf-8")
    (root / "baselines" / "new-1.json").write_text("{}", encoding="utf-8")
    (root / "contracts" / "contract-1.json").write_text("{}", encoding="utf-8")
    return workspace


def _pinwatch_receipt() -> dict[str, object]:
    return {
        "schema": "webre.pin-drift-flow/1",
        "flow_id": "pin-drift-flow:" + "1" * 16,
        "results": {
            "flow_completed": True,
            "comparison_id": "pin-comparison:" + "2" * 16,
            "evidence_level": "structural",
            "confidence": "medium",
            "verdict": "compatible_rotation",
            "compatible": True,
            "minimum_baseline_samples_met": True,
            "runtime_attached": False,
            "runtime_used_for_verdict": False,
            "zero_runtime_drops": None,
            "contract_gates_passed": True,
            "graph_sources": 3,
            "graph_nodes": 4,
            "graph_edges": 3,
            "check_passed": True,
        },
        "supports_general_compatibility_claim": False,
        "supports_semantic_equivalence_claim": False,
        "supports_target_acceptance_claim": False,
        "supports_behavior_absence_claim": False,
        "supports_causal_attribution_claim": False,
    }


def _fake_pinwatch_adapter(
    *,
    mutate_source: bool = False,
    hardlink_output: bool = False,
    mutate_output_on_validate: bool = False,
    mutate_output_same_identity_on_validate: bool = False,
    receipt: dict[str, object] | None = None,
) -> dict[str, object]:
    produced_receipt = receipt or _pinwatch_receipt()

    def run_flow(
        graph_trace: Path,
        old_baseline: Path,
        new_baseline: Path,
        output_dir: Path,
        **kwargs: object,
    ) -> dict[str, object]:
        assert graph_trace.name == "trace-1.jsonl"
        assert old_baseline.name == "old-1.json"
        assert new_baseline.name == "new-1.json"
        assert kwargs["graph_side"] == "new"
        output_dir.mkdir()
        filenames = (
            "comparison-report.json",
            "comparison-evidence.json",
            "evidence-graph.json",
            "comparison-query.json",
            "receipt.json",
        )
        first = output_dir / filenames[0]
        first.write_text("{}", encoding="utf-8")
        for filename in filenames[1:]:
            destination = output_dir / filename
            if hardlink_output and filename == filenames[1]:
                os.link(first, destination)
            else:
                destination.write_text("{}", encoding="utf-8")
        if mutate_source:
            old_baseline.write_text('{"changed":true}', encoding="utf-8")
        return produced_receipt

    def validate_flow(
        document: dict[str, object],
        **kwargs: object,
    ) -> dict[str, object]:
        assert kwargs["workspace"].name == "flow-1"
        if mutate_output_on_validate:
            (kwargs["workspace"] / "comparison-report.json").write_text(
                '{"changed":true}',
                encoding="utf-8",
            )
        if mutate_output_same_identity_on_validate:
            output = kwargs["workspace"] / "comparison-report.json"
            before = output.stat()
            with output.open("r+b") as stream:
                stream.write(b"[]")
            os.utime(output, ns=(before.st_atime_ns, before.st_mtime_ns))
        return document

    return {
        "run": run_flow,
        "validate": validate_flow,
        "producer_sha256_16": "3" * 16,
    }


def test_pinwatch_drift_worker_returns_closed_path_free_receipt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = _pinwatch_source_workspace(tmp_path)
    monkeypatch.setattr(
        worker_module,
        "_load_webre_pinwatch_adapter",
        lambda: _fake_pinwatch_adapter(),
    )

    result = execute_typed_job(
        {
            "kind": "pinwatch-drift-check",
            "payload": _pinwatch_job_payload(),
            "id": "job-1",
        },
        repository_root=ROOT,
        workspace=workspace,
    )

    assert result["schema"] == "browser-core.pinwatch-drift-check-result/1"
    assert result["output_id"] == "flow-1"
    assert result["check_passed"] is True
    assert result["producer"]["source_attested"] is False
    assert str(tmp_path) not in str(result)
    assert "old-1" not in str(result)
    assert "trace-1" not in str(result)


@pytest.mark.skipif(os.name != "nt", reason="Windows dangling junction boundary")
def test_pinwatch_drift_worker_refuses_dangling_output_before_flow(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = _pinwatch_source_workspace(tmp_path)
    flows = workspace / "webre-pinwatch" / "flows"
    flows.mkdir()
    destination = flows / "flow-1"
    target = tmp_path / "missing-target"
    created = subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(destination), str(target)],
        capture_output=True,
        check=False,
    )
    if created.returncode:
        pytest.skip("host could not create an unprivileged directory junction")
    assert os.path.lexists(destination)
    assert not destination.exists() and not destination.is_symlink()

    adapter = _fake_pinwatch_adapter()

    def unexpected_flow(*_args: object, **_kwargs: object) -> None:
        pytest.fail("flow ran before the occupied output name was rejected")

    adapter["run"] = unexpected_flow
    monkeypatch.setattr(worker_module, "_load_webre_pinwatch_adapter", lambda: adapter)
    try:
        with pytest.raises(ContractError, match="output id already exists"):
            execute_typed_job(
                {"id": "job-1", "kind": "pinwatch-drift-check", "payload": _pinwatch_job_payload()},
                repository_root=ROOT,
                workspace=workspace,
            )
    finally:
        if os.path.lexists(destination):
            destination.rmdir()
    assert not target.exists()


@pytest.mark.skipif(os.name != "nt", reason="Windows trailing-dot directory alias")
def test_pinwatch_drift_worker_rejects_trailing_dot_output_before_flow(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = _pinwatch_source_workspace(tmp_path)
    adapter = _fake_pinwatch_adapter()

    def unexpected_flow(*_args: object, **_kwargs: object) -> None:
        pytest.fail("trailing-dot alias reached PinWatch flow")

    adapter["run"] = unexpected_flow
    monkeypatch.setattr(worker_module, "_load_webre_pinwatch_adapter", lambda: adapter)
    payload = _pinwatch_job_payload()
    payload["output_id"] = "flow-1."
    with pytest.raises(ContractError, match="output id is invalid"):
        execute_typed_job(
            {"id": "job-1", "kind": "pinwatch-drift-check", "payload": payload},
            repository_root=ROOT,
            workspace=workspace,
        )
    assert not (workspace / "webre-pinwatch" / "flows" / "flow-1").exists()


@pytest.mark.skipif(os.name != "nt", reason="Win32 reserved device basename")
def test_pinwatch_drift_worker_rejects_device_output_before_flow(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = _pinwatch_source_workspace(tmp_path)
    adapter = _fake_pinwatch_adapter()
    adapter["run"] = lambda *_args, **_kwargs: pytest.fail(
        "reserved device output reached PinWatch flow"
    )
    monkeypatch.setattr(worker_module, "_load_webre_pinwatch_adapter", lambda: adapter)
    payload = _pinwatch_job_payload()
    payload["output_id"] = "AUX.txt"
    with pytest.raises(ContractError, match="output id is invalid"):
        execute_typed_job(
            {"id": "job-1", "kind": "pinwatch-drift-check", "payload": payload},
            repository_root=ROOT,
            workspace=workspace,
        )
    assert not (workspace / "webre-pinwatch" / "flows").exists()


@pytest.mark.skipif(os.name != "nt", reason="Windows trailing-dot directory alias")
@pytest.mark.parametrize("kind", ["multi-identity-ops", "browser-eval"])
def test_fleet_worker_rejects_trailing_dot_job_id_before_output_creation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    kind: str,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    if kind == "multi-identity-ops":
        import browser_core.multi_identity_ops as ops_module

        executable = workspace / "browser.exe"
        executable.write_bytes(b"browser")
        payload: dict[str, object] = {
            "executable": str(executable),
            "count": 1,
            "persona_ids": ["persona-0"],
            "headless": True,
            "parallel": 1,
            "network_auto": False,
            "network_route_id": None,
            "device_class": "desktop",
        }
        monkeypatch.setattr(
            ops_module,
            "run_ops_coherence_cohort",
            lambda *_args, **_kwargs: pytest.fail("dotted alias reached cohort execution"),
        )
        output_root = workspace / "fleet-ops"
    else:
        import browser_eval.runner as runner

        payload = {
            "evaluators": ["controlled_coherence"],
            "backend": "playwright",
            "channel": "chromium",
            "headless": True,
            "timeout_ms": 30_000,
        }
        monkeypatch.setattr(
            runner,
            "execute_run",
            lambda *_args, **_kwargs: pytest.fail("dotted alias reached evaluator execution"),
        )
        output_root = workspace / "fleet-runs"

    with pytest.raises(ContractError, match="job id is invalid"):
        execute_typed_job(
            {"id": "job-1.", "kind": kind, "payload": payload},
            repository_root=ROOT,
            workspace=workspace,
        )
    assert not (output_root / "job-1").exists()


@pytest.mark.skipif(os.name != "nt", reason="Win32 reserved device basename")
@pytest.mark.parametrize("kind", ["multi-identity-ops", "browser-eval"])
def test_fleet_worker_rejects_device_job_id_before_output_creation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    kind: str,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    if kind == "multi-identity-ops":
        import browser_core.multi_identity_ops as ops_module

        executable = workspace / "browser.exe"
        executable.write_bytes(b"browser")
        payload: dict[str, object] = {
            "executable": str(executable),
            "count": 1,
            "persona_ids": ["persona-0"],
            "headless": True,
            "parallel": 1,
            "network_auto": False,
            "network_route_id": None,
            "device_class": "desktop",
        }
        monkeypatch.setattr(
            ops_module,
            "run_ops_coherence_cohort",
            lambda *_args, **_kwargs: pytest.fail("device job reached cohort execution"),
        )
        output_root = workspace / "fleet-ops"
    else:
        import browser_eval.runner as runner

        payload = {
            "evaluators": ["controlled_coherence"],
            "backend": "playwright",
            "channel": "chromium",
            "headless": True,
            "timeout_ms": 30_000,
        }
        monkeypatch.setattr(
            runner,
            "execute_run",
            lambda *_args, **_kwargs: pytest.fail("device job reached evaluator execution"),
        )
        output_root = workspace / "fleet-runs"

    with pytest.raises(ContractError, match="job id is invalid"):
        execute_typed_job(
            {"id": "CON", "kind": kind, "payload": payload},
            repository_root=ROOT,
            workspace=workspace,
        )
    assert not output_root.exists()


@pytest.mark.skipif(os.name != "nt", reason="Win32 reserved device basename")
@pytest.mark.parametrize(
    ("kind", "id_field", "output_root"),
    [
        ("transport-fingerprint", "fingerprint_id", "transport-fingerprints"),
        ("http2-fingerprint", "fingerprint_id", "http2-fingerprints"),
        ("http2-evidence", "evidence_id", "http2-evidence"),
    ],
)
def test_fleet_worker_rejects_device_capture_output_id_before_registry_creation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    kind: str,
    id_field: str,
    output_root: str,
) -> None:
    import browser_core.http2_fingerprint as http2_module
    import browser_core.transport_fingerprint as transport_module

    workspace = tmp_path / "workspace"
    workspace.mkdir()
    executable = workspace / "browser.exe"
    executable.write_bytes(b"browser")
    payload: dict[str, object] = {
        "executable": str(executable),
        id_field: "CON",
        "timeout_seconds": 1,
    }
    if kind != "transport-fingerprint":
        certificate = workspace / "cert.pem"
        private_key = workspace / "key.pem"
        certificate.write_bytes(b"cert")
        private_key.write_bytes(b"key")
        payload.update(certificate=str(certificate), private_key=str(private_key))
    monkeypatch.setattr(
        transport_module,
        "capture_attested_client_hello",
        lambda *_args, **_kwargs: pytest.fail("device output reached transport capture"),
    )
    monkeypatch.setattr(
        http2_module,
        "capture_attested_http2_fingerprint",
        lambda *_args, **_kwargs: pytest.fail("device output reached HTTP/2 capture"),
    )
    monkeypatch.setattr(
        http2_module,
        "capture_attested_http2_evidence",
        lambda *_args, **_kwargs: pytest.fail("device output reached HTTP/2 evidence"),
    )

    with pytest.raises(ContractError, match="id is invalid"):
        execute_typed_job(
            {"id": "job-1", "kind": kind, "payload": payload},
            repository_root=ROOT,
            workspace=workspace,
        )
    assert not (workspace / output_root).exists()


def test_pinwatch_drift_worker_rejects_relocated_workspace_ancestor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = _pinwatch_source_workspace(tmp_path)
    adapter = _fake_pinwatch_adapter()
    original_run = adapter["run"]

    def relocate_after_run(
        graph_trace: Path,
        old_baseline: Path,
        new_baseline: Path,
        output_dir: Path,
        **kwargs: object,
    ) -> dict[str, object]:
        receipt = original_run(
            graph_trace, old_baseline, new_baseline, output_dir, **kwargs
        )
        retained = tmp_path / "retained"
        workspace.rename(retained)
        workspace.mkdir()
        (retained / "webre-pinwatch").rename(workspace / "webre-pinwatch")
        return receipt

    adapter["run"] = relocate_after_run
    monkeypatch.setattr(worker_module, "_load_webre_pinwatch_adapter", lambda: adapter)

    with pytest.raises(ContractError, match="PinWatch output authority changed"):
        execute_typed_job(
            {
                "kind": "pinwatch-drift-check",
                "payload": _pinwatch_job_payload(),
                "id": "job-1",
            },
            repository_root=ROOT,
            workspace=workspace,
        )
    assert (workspace / "webre-pinwatch" / "flows" / "flow-1").is_dir()


def test_pinwatch_drift_worker_rechecks_ancestor_after_validation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = _pinwatch_source_workspace(tmp_path)
    adapter = _fake_pinwatch_adapter()
    original_validate = adapter["validate"]

    def relocate_after_validation(
        document: dict[str, object], **kwargs: object
    ) -> dict[str, object]:
        validated = original_validate(document, **kwargs)
        retained = tmp_path / "retained"
        workspace.rename(retained)
        workspace.mkdir()
        (retained / "webre-pinwatch").rename(workspace / "webre-pinwatch")
        return validated

    adapter["validate"] = relocate_after_validation
    monkeypatch.setattr(worker_module, "_load_webre_pinwatch_adapter", lambda: adapter)

    with pytest.raises(ContractError, match="PinWatch output authority changed"):
        execute_typed_job(
            {
                "kind": "pinwatch-drift-check",
                "payload": _pinwatch_job_payload(),
                "id": "job-1",
            },
            repository_root=ROOT,
            workspace=workspace,
        )
    assert (workspace / "webre-pinwatch" / "flows" / "flow-1").is_dir()


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("output_id", "../escape"),
        ("graph_trace_id", "C:/escape"),
        ("old_baseline_id", "old/escape"),
        ("new_baseline_id", ".hidden"),
        ("contract_id", "contract\\escape"),
        ("old_runtime_id", "../runtime"),
        ("new_runtime_id", "runtime/escape"),
    ],
)
def test_pinwatch_drift_worker_validates_every_id_before_filesystem_contact(
    field: str,
    value: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = _pinwatch_job_payload()
    payload[field] = value
    if field == "old_runtime_id":
        payload["new_runtime_id"] = "runtime-2"
    elif field == "new_runtime_id":
        payload["old_runtime_id"] = "runtime-1"
    monkeypatch.setattr(
        worker_module,
        "directory_identity",
        lambda *_args, **_kwargs: pytest.fail("filesystem contacted"),
    )

    with pytest.raises(ContractError, match="id is invalid"):
        execute_typed_job(
            {"kind": "pinwatch-drift-check", "payload": payload, "id": "job-1"},
            repository_root=ROOT,
            workspace=Path("."),
        )


def test_pinwatch_drift_worker_rejects_malformed_graph_side_before_filesystem_contact(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = _pinwatch_job_payload()
    payload["graph_side"] = []
    monkeypatch.setattr(
        worker_module,
        "directory_identity",
        lambda *_args, **_kwargs: pytest.fail("filesystem contacted"),
    )
    with pytest.raises(ContractError, match="graph side"):
        execute_typed_job(
            {"kind": "pinwatch-drift-check", "payload": payload, "id": "job-1"},
            repository_root=ROOT,
            workspace=Path("."),
        )


@pytest.mark.parametrize("field", ["evidence_level", "confidence", "verdict"])
def test_pinwatch_drift_result_rejects_malformed_choices(field: str) -> None:
    receipt = _pinwatch_receipt()
    receipt["results"][field] = []
    with pytest.raises(ContractError, match="result projection"):
        _project_pinwatch_drift_result(
            receipt,
            job_id="job-1",
            output_id="flow-1",
            producer_sha256_16="a" * 16,
        )


def test_pinwatch_drift_worker_rejects_hard_linked_source(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = _pinwatch_source_workspace(tmp_path)
    source = workspace / "webre-pinwatch" / "baselines" / "old-1.json"
    try:
        os.link(source, source.with_name("alias.json"))
    except OSError:
        pytest.skip("host cannot create a hard-link fixture")
    monkeypatch.setattr(
        worker_module,
        "_load_webre_pinwatch_adapter",
        lambda: pytest.fail("adapter contacted"),
    )

    with pytest.raises(ContractError, match="hard links"):
        execute_typed_job(
            {
                "kind": "pinwatch-drift-check",
                "payload": _pinwatch_job_payload(),
                "id": "job-1",
            },
            repository_root=ROOT,
            workspace=workspace,
        )


def test_pinwatch_drift_worker_rejects_source_mutation_during_comparison(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = _pinwatch_source_workspace(tmp_path)
    monkeypatch.setattr(
        worker_module,
        "_load_webre_pinwatch_adapter",
        lambda: _fake_pinwatch_adapter(mutate_source=True),
    )

    with pytest.raises(ContractError, match="source population changed"):
        execute_typed_job(
            {
                "kind": "pinwatch-drift-check",
                "payload": _pinwatch_job_payload(),
                "id": "job-1",
            },
            repository_root=ROOT,
            workspace=workspace,
        )


def test_pinwatch_drift_worker_rejects_hard_linked_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = _pinwatch_source_workspace(tmp_path)
    monkeypatch.setattr(
        worker_module,
        "_load_webre_pinwatch_adapter",
        lambda: _fake_pinwatch_adapter(hardlink_output=True),
    )

    with pytest.raises(ContractError, match="hard links"):
        execute_typed_job(
            {
                "kind": "pinwatch-drift-check",
                "payload": _pinwatch_job_payload(),
                "id": "job-1",
            },
            repository_root=ROOT,
            workspace=workspace,
        )


def test_pinwatch_drift_worker_rejects_output_mutation_during_validation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = _pinwatch_source_workspace(tmp_path)
    monkeypatch.setattr(
        worker_module,
        "_load_webre_pinwatch_adapter",
        lambda: _fake_pinwatch_adapter(mutate_output_on_validate=True),
    )

    with pytest.raises(ContractError, match="output population changed"):
        execute_typed_job(
            {
                "kind": "pinwatch-drift-check",
                "payload": _pinwatch_job_payload(),
                "id": "job-1",
            },
            repository_root=ROOT,
            workspace=workspace,
        )


def test_pinwatch_drift_worker_rejects_same_identity_output_edit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = _pinwatch_source_workspace(tmp_path)
    monkeypatch.setattr(
        worker_module,
        "_load_webre_pinwatch_adapter",
        lambda: _fake_pinwatch_adapter(mutate_output_same_identity_on_validate=True),
    )

    with pytest.raises(ContractError, match="output population changed"):
        execute_typed_job(
            {
                "kind": "pinwatch-drift-check",
                "payload": _pinwatch_job_payload(),
                "id": "job-1",
            },
            repository_root=ROOT,
            workspace=workspace,
        )


def test_pinwatch_drift_worker_preserves_existing_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = _pinwatch_source_workspace(tmp_path)
    output = workspace / "webre-pinwatch" / "flows" / "flow-1"
    output.mkdir(parents=True)
    marker = output / "owner.txt"
    marker.write_text("preserve", encoding="utf-8")
    monkeypatch.setattr(
        worker_module,
        "_load_webre_pinwatch_adapter",
        lambda: _fake_pinwatch_adapter(),
    )

    with pytest.raises(ContractError, match="already exists"):
        execute_typed_job(
            {
                "kind": "pinwatch-drift-check",
                "payload": _pinwatch_job_payload(),
                "id": "job-1",
            },
            repository_root=ROOT,
            workspace=workspace,
        )
    assert marker.read_text(encoding="utf-8") == "preserve"


def test_pinwatch_drift_worker_rejects_malformed_dependency_projection(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = _pinwatch_source_workspace(tmp_path)
    receipt = _pinwatch_receipt()
    receipt["results"]["check_passed"] = "yes"
    monkeypatch.setattr(
        worker_module,
        "_load_webre_pinwatch_adapter",
        lambda: _fake_pinwatch_adapter(receipt=receipt),
    )

    with pytest.raises(ContractError, match="result projection"):
        execute_typed_job(
            {
                "kind": "pinwatch-drift-check",
                "payload": _pinwatch_job_payload(),
                "id": "job-1",
            },
            repository_root=ROOT,
            workspace=workspace,
        )


def test_pinwatch_drift_worker_recomputes_dependency_gate_relationships(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = _pinwatch_source_workspace(tmp_path)
    receipt = _pinwatch_receipt()
    receipt["results"]["compatible"] = False
    monkeypatch.setattr(
        worker_module,
        "_load_webre_pinwatch_adapter",
        lambda: _fake_pinwatch_adapter(receipt=receipt),
    )

    with pytest.raises(ContractError, match="relationships are inconsistent"):
        execute_typed_job(
            {
                "kind": "pinwatch-drift-check",
                "payload": _pinwatch_job_payload(),
                "id": "job-1",
            },
            repository_root=ROOT,
            workspace=workspace,
        )


def test_pinwatch_drift_worker_real_webre_round_trip_when_available(
    tmp_path: Path,
) -> None:
    webre = pytest.importorskip("webre")
    pinwatch = pytest.importorskip("webre.pinwatch")
    if webre.__file__ is None:
        pytest.skip("WebRE namespace package has no fixture root")
    webre_root = Path(webre.__file__).resolve().parent.parent
    trace_fixture = webre_root / "fixtures" / "rehost-demo.trace.jsonl"
    script_fixture = webre_root / "fixtures" / "rehost-demo.js"
    if not trace_fixture.is_file() or not script_fixture.is_file():
        pytest.skip("installed WebRE does not include the monorepo fixtures")

    workspace = _pinwatch_source_workspace(tmp_path)
    pinwatch_root = workspace / "webre-pinwatch"
    (pinwatch_root / "traces" / "trace-1.jsonl").write_bytes(
        trace_fixture.read_bytes()
    )
    sample_source = script_fixture.read_text(encoding="utf-8")
    samples: list[Path] = []
    for index in range(2):
        sample = tmp_path / f"sample-{index}.js"
        sample.write_text(
            sample_source + f"\n/* controlled repeat {index} */\n",
            encoding="utf-8",
        )
        samples.append(sample)
    for role, name in (
        ("old-1", "private-old-name"),
        ("new-1", "private-new-name"),
    ):
        baseline = pinwatch.build_baseline(name, samples)
        (pinwatch_root / "baselines" / f"{role}.json").write_text(
            json.dumps(baseline, sort_keys=True),
            encoding="utf-8",
        )
    payload = _pinwatch_job_payload()
    payload["contract_id"] = None

    result = execute_typed_job(
        {
            "kind": "pinwatch-drift-check",
            "payload": payload,
            "id": "job-real",
        },
        repository_root=ROOT,
        workspace=workspace,
    )

    assert result["schema"] == "browser-core.pinwatch-drift-check-result/1"
    assert result["check_passed"] is True
    assert result["verdict"] == "unchanged"
    assert {path.name for path in (
        pinwatch_root / "flows" / "flow-1"
    ).iterdir()} == worker_module.PINWATCH_OUTPUT_FILENAMES


def _attested_transport_receipt() -> dict[str, object]:
    receipt: dict[str, object] = {
        "schema": "browser-core.transport-fingerprint/1",
        "legacy_version": 0x0303,
        "ciphers": [0x1301],
        "extensions": [],
        "supported_groups": [],
        "compression_methods": [0],
        "ec_point_formats": [],
        "key_share_groups": [],
        "certificate_compression_algorithms": [],
        "psk_key_exchange_modes": [],
        "signature_algorithms": [],
        "supported_versions": [],
        "alpn": [],
        "application_settings_protocols": [],
        "server_padding_request": None,
        "trust_anchor_identifier_lengths": [],
        "trust_anchor_set_sha256": None,
        "status_request_type": None,
        "status_responder_id_lengths": [],
        "status_request_extensions_bytes": None,
        "session_ticket_bytes": None,
        "renegotiation_info_bytes": None,
        "grease_present": False,
        "core_build": {
            "chromium_revision": "1" * 40,
            "executable_sha256_16": "2" * 16,
            "runtime_bundle_sha256_16": "3" * 16,
        },
    }
    receipt["digest_sha256"] = transport_digest(receipt)
    return receipt


def _transport_baseline_wrapper() -> dict[str, object]:
    fingerprint = _attested_transport_receipt()
    return {
        "schema": "browser-core.transport-baseline/1",
        "source_fingerprint_id": "candidate",
        "baseline_fingerprint_id": "golden",
        "reviewed_digest_sha256": fingerprint["digest_sha256"],
        "fingerprint": fingerprint,
        "non_claim": (
            "Operator-approved local TLS ClientHello baseline only; not H2/H3 "
            "or remote edge acceptance"
        ),
    }


def _attested_http2_receipt() -> dict[str, object]:
    receipt: dict[str, object] = {
        "schema": "browser-core.http2-fingerprint/1",
        "settings": [{"id": 1, "value": 65_536}],
        "connection_window_updates": [15_663_105],
        "pre_headers_frame_types": [4, 8],
        "headers_started": True,
        "core_build": {
            "chromium_revision": "1" * 40,
            "executable_sha256_16": "2" * 16,
            "runtime_bundle_sha256_16": "3" * 16,
        },
    }
    receipt["digest_sha256"] = http2_fingerprint_digest(receipt)
    return receipt


def _http2_baseline_wrapper() -> dict[str, object]:
    fingerprint = _attested_http2_receipt()
    return {
        "schema": "browser-core.http2-baseline/1",
        "source_fingerprint_id": "candidate",
        "baseline_fingerprint_id": "golden",
        "reviewed_digest_sha256": fingerprint["digest_sha256"],
        "fingerprint": fingerprint,
        "non_claim": (
            "Operator-approved local HTTP/2 initial-flight baseline only; not "
            "HTTP/3 or remote edge acceptance"
        ),
    }


def _attested_http2_evidence() -> dict[str, object]:
    build = _attested_http2_receipt()["core_build"]
    header_order: dict[str, object] = {
        "schema": "browser-core.http2-header-order/1",
        "header_names": [":method", ":authority", "user-agent", "accept"],
        "pseudo_header_order": [":method", ":authority"],
        "non_claim": (
            "First local HTTP/2 request header-name order only; values are discarded "
            "after bounded decode and no HTTP/3 or edge acceptance is proven"
        ),
        "core_build": dict(build),
    }
    header_order["digest_sha256"] = http2_header_order_digest(header_order)
    evidence: dict[str, object] = {
        "schema": "browser-core.http2-capture-evidence/1",
        "fingerprint": _attested_http2_receipt(),
        "header_order": header_order,
        "same_connection": True,
        "non_claim": (
            "One local negotiated HTTP/2 connection through first complete request "
            "headers; decoded values are discarded and no HTTP/3 or edge acceptance "
            "is proven"
        ),
    }
    evidence["digest_sha256"] = http2_capture_evidence_digest(evidence)
    return evidence


def _http2_evidence_baseline_wrapper() -> dict[str, object]:
    evidence = _attested_http2_evidence()
    return {
        "schema": "browser-core.http2-evidence-baseline/1",
        "source_evidence_id": "candidate",
        "baseline_evidence_id": "golden",
        "reviewed_digest_sha256": evidence["digest_sha256"],
        "evidence": evidence,
        "non_claim": (
            "Operator-approved same-connection local HTTP/2 settings, frame, and "
            "header-name order baseline only; not HTTP/3 or remote edge acceptance"
        ),
    }


def test_http2_evidence_install_and_check_jobs_return_path_free_receipts(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    baseline = _http2_evidence_baseline_wrapper()
    installed = execute_typed_job(
        {
            "id": "install-1",
            "kind": "http2-evidence-baseline-install",
            "payload": {"baseline": baseline},
        },
        repository_root=ROOT,
        workspace=workspace,
    )
    assert installed["schema"] == "browser-core.http2-evidence-baseline-installation/1"
    assert installed["baseline_evidence_id"] == "golden"
    registry = workspace / "http2-evidence"
    (registry / "current.json").write_text(
        json.dumps(baseline["evidence"]),
        encoding="utf-8",
    )
    checked = execute_typed_job(
        {
            "id": "check-1",
            "kind": "http2-evidence-check",
            "payload": {"current_id": "current", "baseline_id": "golden"},
        },
        repository_root=ROOT,
        workspace=workspace,
    )
    assert checked["passed"] is True
    assert checked["changed_components"] == []
    assert str(workspace) not in str(installed)
    assert str(workspace) not in str(checked)


def test_http2_evidence_check_rejects_raw_capture_as_baseline(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    registry = workspace / "http2-evidence"
    registry.mkdir(parents=True)
    evidence = _attested_http2_evidence()
    (registry / "current.json").write_text(json.dumps(evidence), encoding="utf-8")
    (registry / "golden.baseline.json").write_text(
        json.dumps(evidence), encoding="utf-8"
    )
    with pytest.raises(ContractError, match="baseline fields"):
        execute_typed_job(
            {
                "id": "check-1",
                "kind": "http2-evidence-check",
                "payload": {"current_id": "current", "baseline_id": "golden"},
            },
            repository_root=ROOT,
            workspace=workspace,
        )


def test_http2_evidence_check_binds_wrapper_id_to_registry_name(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    registry = workspace / "http2-evidence"
    registry.mkdir(parents=True)
    evidence = _attested_http2_evidence()
    (registry / "current.json").write_text(json.dumps(evidence), encoding="utf-8")
    (registry / "impostor.baseline.json").write_text(
        json.dumps(_http2_evidence_baseline_wrapper()), encoding="utf-8"
    )
    with pytest.raises(ContractError, match="id does not match"):
        execute_typed_job(
            {
                "id": "check-1",
                "kind": "http2-evidence-check",
                "payload": {"current_id": "current", "baseline_id": "impostor"},
            },
            repository_root=ROOT,
            workspace=workspace,
        )


def test_http2_evidence_baseline_install_rejects_edited_wrapper_before_storage(
    tmp_path: Path,
) -> None:
    baseline = _http2_evidence_baseline_wrapper()
    baseline["extra"] = True
    workspace = tmp_path / "workspace"
    with pytest.raises(ContractError, match="baseline fields"):
        execute_typed_job(
            {
                "id": "install-1",
                "kind": "http2-evidence-baseline-install",
                "payload": {"baseline": baseline},
            },
            repository_root=ROOT,
            workspace=workspace,
        )
    assert not workspace.exists()


@pytest.mark.parametrize("field", ["current_id", "baseline_id"])
def test_http2_evidence_check_ids_cannot_escape_registry(
    tmp_path: Path,
    field: str,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    payload = {"current_id": "current", "baseline_id": "golden"}
    payload[field] = "../outside"
    with pytest.raises(ContractError, match="invalid"):
        execute_typed_job(
            {
                "id": "check-1",
                "kind": "http2-evidence-check",
                "payload": payload,
            },
            repository_root=ROOT,
            workspace=workspace,
        )


def test_http2_baseline_install_and_check_jobs_return_path_free_receipts(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    baseline = _http2_baseline_wrapper()
    installed = execute_typed_job(
        {
            "id": "install-1",
            "kind": "http2-baseline-install",
            "payload": {"baseline": baseline},
        },
        repository_root=ROOT,
        workspace=workspace,
    )
    assert installed == {
        "schema": "browser-core.http2-baseline-installation/1",
        "job_id": "install-1",
        "source_fingerprint_id": "candidate",
        "baseline_fingerprint_id": "golden",
        "digest_sha256": baseline["reviewed_digest_sha256"],
        "core_build": baseline["fingerprint"]["core_build"],
    }
    current = workspace / "http2-fingerprints" / "current.json"
    current.write_text(json.dumps(baseline["fingerprint"]), encoding="utf-8")
    checked = execute_typed_job(
        {
            "id": "check-1",
            "kind": "http2-check",
            "payload": {"current_id": "current", "baseline_id": "golden"},
        },
        repository_root=ROOT,
        workspace=workspace,
    )
    assert checked["passed"] is True
    assert checked["changed_fields"] == []
    assert str(workspace) not in str(installed)
    assert str(workspace) not in str(checked)


def test_http2_check_job_refuses_a_raw_capture_named_as_a_baseline(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    registry = workspace / "http2-fingerprints"
    registry.mkdir(parents=True)
    fingerprint = _attested_http2_receipt()
    (registry / "current.json").write_text(json.dumps(fingerprint), encoding="utf-8")
    (registry / "golden.baseline.json").write_text(
        json.dumps(fingerprint), encoding="utf-8"
    )
    with pytest.raises(ContractError, match="baseline fields"):
        execute_typed_job(
            {
                "id": "check-1",
                "kind": "http2-check",
                "payload": {"current_id": "current", "baseline_id": "golden"},
            },
            repository_root=ROOT,
            workspace=workspace,
        )


def test_http2_check_binds_wrapper_id_to_registry_name(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    registry = workspace / "http2-fingerprints"
    registry.mkdir(parents=True)
    fingerprint = _attested_http2_receipt()
    (registry / "current.json").write_text(json.dumps(fingerprint), encoding="utf-8")
    (registry / "impostor.baseline.json").write_text(
        json.dumps(_http2_baseline_wrapper()), encoding="utf-8"
    )

    with pytest.raises(ContractError, match="id does not match"):
        execute_typed_job(
            {
                "id": "check-1",
                "kind": "http2-check",
                "payload": {"current_id": "current", "baseline_id": "impostor"},
            },
            repository_root=ROOT,
            workspace=workspace,
        )


def test_http2_baseline_install_rejects_edited_wrapper_before_storage(
    tmp_path: Path,
) -> None:
    baseline = _http2_baseline_wrapper()
    baseline["extra"] = True
    workspace = tmp_path / "workspace"

    with pytest.raises(ContractError, match="baseline fields"):
        execute_typed_job(
            {
                "id": "install-1",
                "kind": "http2-baseline-install",
                "payload": {"baseline": baseline},
            },
            repository_root=ROOT,
            workspace=workspace,
        )
    assert not workspace.exists()


@pytest.mark.parametrize("field", ["current_id", "baseline_id"])
def test_http2_check_identifiers_cannot_escape_the_owned_registry(
    tmp_path: Path,
    field: str,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    payload = {"current_id": "current", "baseline_id": "baseline"}
    payload[field] = "../outside"

    with pytest.raises(ContractError, match="invalid"):
        execute_typed_job(
            {"id": "check-1", "kind": "http2-check", "payload": payload},
            repository_root=ROOT,
            workspace=workspace,
        )


def test_transport_suite_worker_returns_one_path_free_coherent_verdict(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    transport_registry = workspace / "transport-fingerprints"
    http2_registry = workspace / "http2-fingerprints"
    transport_registry.mkdir(parents=True)
    http2_registry.mkdir()
    transport = _attested_transport_receipt()
    h2 = _attested_http2_receipt()
    (transport_registry / "tls-current.json").write_text(
        json.dumps(transport), encoding="utf-8"
    )
    (transport_registry / "golden.baseline.json").write_text(
        json.dumps(_transport_baseline_wrapper()), encoding="utf-8"
    )
    (http2_registry / "h2-current.json").write_text(
        json.dumps(h2), encoding="utf-8"
    )
    (http2_registry / "golden.baseline.json").write_text(
        json.dumps(_http2_baseline_wrapper()), encoding="utf-8"
    )

    result = execute_typed_job(
        {
            "id": "suite-1",
            "kind": "transport-suite-check",
            "payload": {
                "client_hello_current_id": "tls-current",
                "client_hello_baseline_id": "golden",
                "http2_current_id": "h2-current",
                "http2_baseline_id": "golden",
            },
        },
        repository_root=ROOT,
        workspace=workspace,
    )

    assert result["schema"] == "browser-core.transport-suite-comparison/1"
    assert result["passed"] is True
    assert result["current_build_coherent"] is True
    assert result["baseline_build_coherent"] is True
    assert str(workspace) not in str(result)


def test_transport_evidence_suite_worker_gates_header_order_and_build(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    transport_registry = workspace / "transport-fingerprints"
    evidence_registry = workspace / "http2-evidence"
    transport_registry.mkdir(parents=True)
    evidence_registry.mkdir()
    transport = _attested_transport_receipt()
    evidence = _attested_http2_evidence()
    (transport_registry / "tls-current.json").write_text(
        json.dumps(transport), encoding="utf-8"
    )
    (transport_registry / "golden.baseline.json").write_text(
        json.dumps(_transport_baseline_wrapper()), encoding="utf-8"
    )
    (evidence_registry / "h2e-current.json").write_text(
        json.dumps(evidence), encoding="utf-8"
    )
    (evidence_registry / "golden.baseline.json").write_text(
        json.dumps(_http2_evidence_baseline_wrapper()), encoding="utf-8"
    )

    result = execute_typed_job(
        {
            "id": "suite-1",
            "kind": "transport-evidence-suite-check",
            "payload": {
                "client_hello_current_id": "tls-current",
                "client_hello_baseline_id": "golden",
                "http2_evidence_current_id": "h2e-current",
                "http2_evidence_baseline_id": "golden",
            },
        },
        repository_root=ROOT,
        workspace=workspace,
    )

    assert result["schema"] == "browser-core.transport-evidence-suite-comparison/1"
    assert result["passed"] is True
    assert result["current_build_coherent"] is True
    assert result["http2_evidence"]["passed"] is True
    assert str(workspace) not in str(result)


@pytest.mark.parametrize(
    "kind",
    [
        "transport-check",
        "http2-check",
        "http2-evidence-check",
        "transport-suite-check",
        "transport-evidence-suite-check",
    ],
)
@pytest.mark.parametrize("same_body_replacement", [False, True])
def test_fleet_comparison_rechecks_selected_sources_after_last_load(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    kind: str,
    same_body_replacement: bool,
) -> None:
    import browser_core.http2_fingerprint as h2_module
    import browser_core.http2_headers as headers_module
    import browser_core.transport_fingerprint as transport_module

    workspace = tmp_path / "workspace"
    transport_root = workspace / "transport-fingerprints"
    h2_root = workspace / "http2-fingerprints"
    evidence_root = workspace / "http2-evidence"
    for root in (transport_root, h2_root, evidence_root):
        root.mkdir(parents=True)
    for path, document in (
        (transport_root / "current.json", _attested_transport_receipt()),
        (transport_root / "golden.baseline.json", _transport_baseline_wrapper()),
        (h2_root / "current.json", _attested_http2_receipt()),
        (h2_root / "golden.baseline.json", _http2_baseline_wrapper()),
        (evidence_root / "current.json", _attested_http2_evidence()),
        (evidence_root / "golden.baseline.json", _http2_evidence_baseline_wrapper()),
    ):
        path.write_text(json.dumps(document), encoding="utf-8")

    if kind == "transport-check":
        payload = {"current_id": "current", "baseline_id": "golden"}
        baseline = transport_root / "golden.baseline.json"
        load_module, load_name = transport_module, "load_transport_fingerprint"
    elif kind == "http2-check":
        payload = {"current_id": "current", "baseline_id": "golden"}
        baseline = h2_root / "golden.baseline.json"
        load_module, load_name = h2_module, "load_http2_fingerprint"
    elif kind == "http2-evidence-check":
        payload = {"current_id": "current", "baseline_id": "golden"}
        baseline = evidence_root / "golden.baseline.json"
        load_module, load_name = headers_module, "load_http2_capture_evidence"
    elif kind == "transport-suite-check":
        payload = {
            "client_hello_current_id": "current",
            "client_hello_baseline_id": "golden",
            "http2_current_id": "current",
            "http2_baseline_id": "golden",
        }
        baseline = transport_root / "golden.baseline.json"
        load_module, load_name = h2_module, "load_http2_fingerprint"
    else:
        payload = {
            "client_hello_current_id": "current",
            "client_hello_baseline_id": "golden",
            "http2_evidence_current_id": "current",
            "http2_evidence_baseline_id": "golden",
        }
        baseline = transport_root / "golden.baseline.json"
        load_module, load_name = headers_module, "load_http2_capture_evidence"

    original_load = getattr(load_module, load_name)
    held = baseline.with_name("held.baseline.json")

    def load_then_change(path: Path) -> dict[str, object]:
        document = original_load(path)
        if same_body_replacement:
            baseline.rename(held)
            baseline.write_bytes(held.read_bytes())
        else:
            baseline.write_bytes(b"{}")
        return document

    monkeypatch.setattr(load_module, load_name, load_then_change)
    with pytest.raises(ContractError, match="comparison source changed"):
        execute_typed_job(
            {"id": "job-1", "kind": kind, "payload": payload},
            repository_root=ROOT,
            workspace=workspace,
        )
    if same_body_replacement:
        assert held.read_bytes() == baseline.read_bytes()
    else:
        assert baseline.read_bytes() == b"{}"


@pytest.mark.parametrize(
    "field",
    [
        "client_hello_current_id",
        "client_hello_baseline_id",
        "http2_evidence_current_id",
        "http2_evidence_baseline_id",
    ],
)
def test_transport_evidence_suite_validates_ids_before_registry_contact(
    tmp_path: Path,
    field: str,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    payload = {
        "client_hello_current_id": "tls-current",
        "client_hello_baseline_id": "tls-golden",
        "http2_evidence_current_id": "h2e-current",
        "http2_evidence_baseline_id": "h2e-golden",
    }
    payload[field] = "../outside"
    with pytest.raises(ContractError, match="invalid"):
        execute_typed_job(
            {
                "id": "suite-1",
                "kind": "transport-evidence-suite-check",
                "payload": payload,
            },
            repository_root=ROOT,
            workspace=workspace,
        )


@pytest.mark.parametrize(
    "field",
    [
        "client_hello_current_id",
        "client_hello_baseline_id",
        "http2_current_id",
        "http2_baseline_id",
    ],
)
def test_transport_suite_validates_every_id_before_registry_contact(
    tmp_path: Path,
    field: str,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    payload = {
        "client_hello_current_id": "tls-current",
        "client_hello_baseline_id": "tls-golden",
        "http2_current_id": "h2-current",
        "http2_baseline_id": "h2-golden",
    }
    payload[field] = "../outside"

    with pytest.raises(ContractError, match="invalid"):
        execute_typed_job(
            {"id": "suite-1", "kind": "transport-suite-check", "payload": payload},
            repository_root=ROOT,
            workspace=workspace,
        )


def test_http2_fingerprint_worker_publishes_without_returning_tls_paths(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import browser_core.http2_fingerprint as h2_module

    workspace = tmp_path / "workspace"
    workspace.mkdir()
    executable = workspace / "chrome.exe"
    certificate = workspace / "cert.pem"
    private_key = workspace / "key.pem"
    executable.write_bytes(b"browser")
    certificate.write_bytes(b"certificate")
    private_key.write_bytes(b"private")
    expected = _attested_http2_receipt()
    calls: list[tuple[Path, Path, Path, Path, float]] = []

    def capture(root, binary, cert, key, *, timeout_seconds):  # noqa: ANN001
        calls.append((root, binary, cert, key, timeout_seconds))
        return expected

    monkeypatch.setattr(h2_module, "capture_attested_http2_fingerprint", capture)
    result = execute_typed_job(
        {
            "id": "job-1",
            "kind": "http2-fingerprint",
            "payload": {
                "executable": str(executable),
                "certificate": str(certificate),
                "private_key": str(private_key),
                "fingerprint_id": "h2-current",
                "timeout_seconds": 17,
            },
        },
        repository_root=ROOT,
        workspace=workspace,
    )

    assert result == {
        "schema": "browser-core.http2-fingerprint-publication/1",
        "job_id": "job-1",
        "fingerprint_id": "h2-current",
        "digest_sha256": expected["digest_sha256"],
        "core_build": expected["core_build"],
    }
    assert calls == [
        (
            ROOT,
            executable.resolve(),
            certificate.resolve(),
            private_key.resolve(),
            17.0,
        )
    ]
    assert json.loads(
        (workspace / "http2-fingerprints" / "h2-current.json").read_text(
            encoding="utf-8"
        )
    ) == expected
    assert str(certificate) not in str(result)
    assert str(private_key) not in str(result)


def test_http2_evidence_worker_publishes_value_free_same_connection_receipt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import browser_core.http2_fingerprint as h2_module

    workspace = tmp_path / "workspace"
    workspace.mkdir()
    executable = workspace / "chrome.exe"
    certificate = workspace / "cert.pem"
    private_key = workspace / "key.pem"
    for path in (executable, certificate, private_key):
        path.write_bytes(path.name.encode("ascii"))
    expected = _attested_http2_evidence()
    calls: list[tuple[Path, Path, Path, Path, float]] = []

    def capture(root, binary, cert, key, *, timeout_seconds):  # noqa: ANN001
        calls.append((root, binary, cert, key, timeout_seconds))
        return expected

    monkeypatch.setattr(h2_module, "capture_attested_http2_evidence", capture)
    result = execute_typed_job(
        {
            "id": "job-1",
            "kind": "http2-evidence",
            "payload": {
                "executable": str(executable),
                "certificate": str(certificate),
                "private_key": str(private_key),
                "evidence_id": "h2-current",
                "timeout_seconds": 17,
            },
        },
        repository_root=ROOT,
        workspace=workspace,
    )

    assert result == {
        "schema": "browser-core.http2-evidence-publication/1",
        "job_id": "job-1",
        "evidence_id": "h2-current",
        "digest_sha256": expected["digest_sha256"],
        "fingerprint_digest_sha256": expected["fingerprint"]["digest_sha256"],
        "header_order_digest_sha256": expected["header_order"]["digest_sha256"],
        "core_build": expected["fingerprint"]["core_build"],
    }
    assert calls == [
        (ROOT, executable.resolve(), certificate.resolve(), private_key.resolve(), 17.0)
    ]
    assert json.loads(
        (workspace / "http2-evidence" / "h2-current.json").read_text(
            encoding="utf-8"
        )
    ) == expected
    assert str(workspace) not in str(result)


@pytest.mark.skipif(os.name != "nt", reason="Windows dangling junction boundary")
@pytest.mark.parametrize(
    ("kind", "registry", "capture_name"),
    [
        ("transport-fingerprint", "transport-fingerprints", "capture_attested_client_hello"),
        ("http2-fingerprint", "http2-fingerprints", "capture_attested_http2_fingerprint"),
        ("http2-evidence", "http2-evidence", "capture_attested_http2_evidence"),
    ],
)
def test_fingerprint_workers_refuse_dangling_output_before_capture(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    kind: str,
    registry: str,
    capture_name: str,
) -> None:
    import browser_core.http2_fingerprint as h2_module
    import browser_core.transport_fingerprint as transport_module

    workspace = tmp_path / "workspace"
    workspace.mkdir()
    for name in ("chrome.exe", "cert.pem", "key.pem"):
        (workspace / name).write_bytes(name.encode("ascii"))
    registry_path = workspace / registry
    registry_path.mkdir()
    destination = registry_path / "current-1.json"
    target = tmp_path / "missing-target"
    created = subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(destination), str(target)],
        capture_output=True,
        check=False,
    )
    if created.returncode:
        pytest.skip("host could not create an unprivileged directory junction")
    assert os.path.lexists(destination)
    assert not destination.exists() and not destination.is_symlink()

    module = transport_module if kind == "transport-fingerprint" else h2_module

    def unexpected_capture(*_args: object, **_kwargs: object) -> None:
        pytest.fail("capture ran before the occupied output name was rejected")

    monkeypatch.setattr(module, capture_name, unexpected_capture)
    payload: dict[str, object] = {
        "executable": str(workspace / "chrome.exe"),
        "timeout_seconds": 17,
    }
    if kind == "transport-fingerprint":
        payload["fingerprint_id"] = "current-1"
    else:
        payload["certificate"] = str(workspace / "cert.pem")
        payload["private_key"] = str(workspace / "key.pem")
        payload["fingerprint_id" if kind == "http2-fingerprint" else "evidence_id"] = "current-1"
    try:
        with pytest.raises(ContractError, match="already exists"):
            execute_typed_job(
                {"id": "job-1", "kind": kind, "payload": payload},
                repository_root=ROOT,
                workspace=workspace,
            )
    finally:
        if os.path.lexists(destination):
            destination.rmdir()
    assert not target.exists()


@pytest.mark.parametrize(
    ("kind", "registry", "capture_name"),
    [
        (
            "transport-fingerprint",
            "transport-fingerprints",
            "capture_attested_client_hello",
        ),
        (
            "http2-fingerprint",
            "http2-fingerprints",
            "capture_attested_http2_fingerprint",
        ),
        ("http2-evidence", "http2-evidence", "capture_attested_http2_evidence"),
    ],
)
@pytest.mark.parametrize("phase", ["capture", "load"])
def test_fingerprint_workers_reject_relocated_workspace_ancestor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    kind: str,
    registry: str,
    capture_name: str,
    phase: str,
) -> None:
    import browser_core.http2_fingerprint as h2_module
    import browser_core.http2_headers as headers_module
    import browser_core.transport_fingerprint as transport_module

    workspace = tmp_path / "workspace"
    workspace.mkdir()
    executable = workspace / "chrome.exe"
    executable.write_bytes(b"browser")
    payload: dict[str, object] = {
        "executable": str(executable),
        "timeout_seconds": 17,
    }
    if kind == "transport-fingerprint":
        module = transport_module
        load_module = transport_module
        load_name = "load_transport_fingerprint"
        expected = _attested_transport_receipt()
        payload["fingerprint_id"] = "current-1"
    else:
        module = h2_module
        load_module = h2_module if kind == "http2-fingerprint" else headers_module
        load_name = (
            "load_http2_fingerprint"
            if kind == "http2-fingerprint"
            else "load_http2_capture_evidence"
        )
        expected = (
            _attested_http2_receipt()
            if kind == "http2-fingerprint"
            else _attested_http2_evidence()
        )
        for name in ("cert.pem", "key.pem"):
            (workspace / name).write_bytes(name.encode("ascii"))
        payload.update(
            {
                "certificate": str(workspace / "cert.pem"),
                "private_key": str(workspace / "key.pem"),
                "fingerprint_id" if kind == "http2-fingerprint" else "evidence_id":
                    "h2-current",
            }
        )

    def relocate_registry() -> None:
        retained = tmp_path / "retained"
        workspace.rename(retained)
        workspace.mkdir()
        (retained / registry).rename(workspace / registry)

    if phase == "capture":
        def capture(*_args: object, **_kwargs: object) -> dict[str, object]:
            relocate_registry()
            return expected

        monkeypatch.setattr(module, capture_name, capture)
    else:
        monkeypatch.setattr(
            module, capture_name, lambda *_args, **_kwargs: expected
        )
        original_load = getattr(load_module, load_name)

        def load_then_relocate(path: Path) -> dict[str, object]:
            document = original_load(path)
            relocate_registry()
            return document

        monkeypatch.setattr(load_module, load_name, load_then_relocate)

    message = "registry authority changed" if phase == "capture" else "changed after publication"
    with pytest.raises(ContractError, match=message):
        execute_typed_job(
            {"id": "job-1", "kind": kind, "payload": payload},
            repository_root=ROOT,
            workspace=workspace,
        )
    assert (workspace / registry).is_dir()


@pytest.mark.parametrize(
    ("kind", "registry", "capture_name", "load_name", "source_id"),
    [
        (
            "transport-fingerprint",
            "transport-fingerprints",
            "capture_attested_client_hello",
            "load_transport_fingerprint",
            "fingerprint_id",
        ),
        (
            "http2-fingerprint",
            "http2-fingerprints",
            "capture_attested_http2_fingerprint",
            "load_http2_fingerprint",
            "fingerprint_id",
        ),
        (
            "http2-evidence",
            "http2-evidence",
            "capture_attested_http2_evidence",
            "load_http2_capture_evidence",
            "evidence_id",
        ),
    ],
)
def test_fingerprint_workers_reject_identical_leaf_replacement_after_load(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    kind: str,
    registry: str,
    capture_name: str,
    load_name: str,
    source_id: str,
) -> None:
    import browser_core.http2_fingerprint as h2_module
    import browser_core.http2_headers as headers_module
    import browser_core.transport_fingerprint as transport_module

    workspace = tmp_path / "workspace"
    workspace.mkdir()
    executable = workspace / "chrome.exe"
    executable.write_bytes(b"browser")
    payload: dict[str, object] = {
        "executable": str(executable),
        "timeout_seconds": 17,
        source_id: "current-1",
    }
    if kind == "transport-fingerprint":
        capture_module = load_module = transport_module
        expected = _attested_transport_receipt()
    else:
        capture_module = h2_module
        load_module = h2_module if kind == "http2-fingerprint" else headers_module
        expected = (
            _attested_http2_receipt()
            if kind == "http2-fingerprint"
            else _attested_http2_evidence()
        )
        for name in ("cert.pem", "key.pem"):
            (workspace / name).write_bytes(name.encode("ascii"))
        payload.update(
            {
                "certificate": str(workspace / "cert.pem"),
                "private_key": str(workspace / "key.pem"),
            }
        )
    monkeypatch.setattr(capture_module, capture_name, lambda *_args, **_kwargs: expected)
    original_load = getattr(load_module, load_name)
    held = workspace / registry / "held.json"

    def load_then_replace(path: Path) -> dict[str, object]:
        document = original_load(path)
        path.rename(held)
        path.write_bytes(held.read_bytes())
        return document

    monkeypatch.setattr(load_module, load_name, load_then_replace)
    with pytest.raises(ContractError, match="changed after publication"):
        execute_typed_job(
            {"id": "job-1", "kind": kind, "payload": payload},
            repository_root=ROOT,
            workspace=workspace,
        )
    assert held.read_bytes() == (workspace / registry / "current-1.json").read_bytes()


def test_http2_evidence_worker_refuses_existing_id_before_capture(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import browser_core.http2_fingerprint as h2_module

    workspace = tmp_path / "workspace"
    registry = workspace / "http2-evidence"
    registry.mkdir(parents=True)
    for name in ("chrome.exe", "cert.pem", "key.pem"):
        (workspace / name).write_bytes(name.encode("ascii"))
    existing = registry / "h2-current.json"
    existing.write_bytes(b"reviewed bytes")
    monkeypatch.setattr(
        h2_module,
        "capture_attested_http2_evidence",
        lambda *_args, **_kwargs: pytest.fail("existing id reached H2 capture"),
    )
    with pytest.raises(ContractError, match="already exists"):
        execute_typed_job(
            {
                "id": "job-1",
                "kind": "http2-evidence",
                "payload": {
                    "executable": str(workspace / "chrome.exe"),
                    "certificate": str(workspace / "cert.pem"),
                    "private_key": str(workspace / "key.pem"),
                    "evidence_id": "h2-current",
                    "timeout_seconds": 17,
                },
            },
            repository_root=ROOT,
            workspace=workspace,
        )
    assert existing.read_bytes() == b"reviewed bytes"


def test_http2_evidence_worker_rechecks_registry_after_publication_load(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import browser_core.http2_fingerprint as h2_module
    import browser_core.http2_headers as headers_module

    workspace = tmp_path / "workspace"
    workspace.mkdir()
    for name in ("chrome.exe", "cert.pem", "key.pem"):
        (workspace / name).write_bytes(name.encode("ascii"))
    monkeypatch.setattr(
        h2_module,
        "capture_attested_http2_evidence",
        lambda *_args, **_kwargs: _attested_http2_evidence(),
    )
    original_load = headers_module.load_http2_capture_evidence
    held = workspace / "held-http2-evidence"

    def replace_after_load(path):  # noqa: ANN001, ANN202
        document = original_load(path)
        path.parent.rename(held)
        path.parent.mkdir()
        (path.parent / "competitor.bin").write_bytes(b"competitor")
        return document

    monkeypatch.setattr(
        headers_module,
        "load_http2_capture_evidence",
        replace_after_load,
    )
    with pytest.raises(ContractError, match="changed after publication"):
        execute_typed_job(
            {
                "id": "job-1",
                "kind": "http2-evidence",
                "payload": {
                    "executable": str(workspace / "chrome.exe"),
                    "certificate": str(workspace / "cert.pem"),
                    "private_key": str(workspace / "key.pem"),
                    "evidence_id": "h2-current",
                    "timeout_seconds": 17,
                },
            },
            repository_root=ROOT,
            workspace=workspace,
        )
    assert held.is_dir()
    assert (workspace / "http2-evidence" / "competitor.bin").read_bytes() == b"competitor"


@pytest.mark.parametrize("timeout", [True, 0, 121, float("inf"), 10**400])
def test_http2_evidence_worker_timeout_fails_before_file_lookup(
    tmp_path: Path,
    timeout: object,
) -> None:
    with pytest.raises(ContractError, match="http2-evidence timeout"):
        execute_typed_job(
            {
                "id": "job-1",
                "kind": "http2-evidence",
                "payload": {
                    "executable": str(tmp_path / "missing.exe"),
                    "certificate": str(tmp_path / "missing.crt"),
                    "private_key": str(tmp_path / "missing.key"),
                    "evidence_id": "h2-current",
                    "timeout_seconds": timeout,
                },
            },
            repository_root=ROOT,
            workspace=tmp_path,
        )


def test_http2_fingerprint_worker_refuses_an_existing_id_before_capture(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import browser_core.http2_fingerprint as h2_module

    workspace = tmp_path / "workspace"
    registry = workspace / "http2-fingerprints"
    registry.mkdir(parents=True)
    for name in ("chrome.exe", "cert.pem", "key.pem"):
        (workspace / name).write_bytes(name.encode("ascii"))
    existing = registry / "h2-current.json"
    existing.write_bytes(b"reviewed bytes")
    monkeypatch.setattr(
        h2_module,
        "capture_attested_http2_fingerprint",
        lambda *_args, **_kwargs: pytest.fail("existing id reached H2 capture"),
    )

    with pytest.raises(ContractError, match="already exists"):
        execute_typed_job(
            {
                "id": "job-1",
                "kind": "http2-fingerprint",
                "payload": {
                    "executable": str(workspace / "chrome.exe"),
                    "certificate": str(workspace / "cert.pem"),
                    "private_key": str(workspace / "key.pem"),
                    "fingerprint_id": "h2-current",
                    "timeout_seconds": 17,
                },
            },
            repository_root=ROOT,
            workspace=workspace,
        )
    assert existing.read_bytes() == b"reviewed bytes"


def test_http2_fingerprint_worker_refuses_unvalidated_dependency_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import browser_core.http2_fingerprint as h2_module

    workspace = tmp_path / "workspace"
    workspace.mkdir()
    for name in ("chrome.exe", "cert.pem", "key.pem"):
        (workspace / name).write_bytes(name.encode("ascii"))
    monkeypatch.setattr(
        h2_module,
        "capture_attested_http2_fingerprint",
        lambda *_args, **_kwargs: {"schema": "edited", "private": "value"},
    )

    with pytest.raises(ContractError, match="fields are invalid"):
        execute_typed_job(
            {
                "id": "job-1",
                "kind": "http2-fingerprint",
                "payload": {
                    "executable": str(workspace / "chrome.exe"),
                    "certificate": str(workspace / "cert.pem"),
                    "private_key": str(workspace / "key.pem"),
                    "fingerprint_id": "h2-current",
                    "timeout_seconds": 17,
                },
            },
            repository_root=ROOT,
            workspace=workspace,
        )


@pytest.mark.parametrize("timeout", [True, 0, 121, float("inf"), 10**400])
def test_http2_fingerprint_worker_timeout_fails_before_file_lookup(
    tmp_path: Path,
    timeout: object,
) -> None:
    with pytest.raises(ContractError, match="http2-fingerprint timeout"):
        execute_typed_job(
            {
                "id": "job-1",
                "kind": "http2-fingerprint",
                "payload": {
                    "executable": str(tmp_path / "missing.exe"),
                    "certificate": str(tmp_path / "missing.crt"),
                    "private_key": str(tmp_path / "missing.key"),
                    "fingerprint_id": "h2-current",
                    "timeout_seconds": timeout,
                },
            },
            repository_root=ROOT,
            workspace=tmp_path,
        )


@pytest.mark.parametrize("field", ["executable", "certificate", "private_key"])
def test_http2_fingerprint_worker_tls_inputs_stay_inside_workspace(
    tmp_path: Path,
    field: str,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    outside = tmp_path / "outside.bin"
    outside.write_bytes(b"outside")
    payload = {
        "executable": str(workspace / "chrome.exe"),
        "certificate": str(workspace / "cert.pem"),
        "private_key": str(workspace / "key.pem"),
        "fingerprint_id": "h2-current",
        "timeout_seconds": 17,
    }
    for name in ("chrome.exe", "cert.pem", "key.pem"):
        (workspace / name).write_bytes(name.encode("ascii"))
    payload[field] = str(outside)

    with pytest.raises(ContractError, match="inside the worker workspace"):
        execute_typed_job(
            {"id": "job-1", "kind": "http2-fingerprint", "payload": payload},
            repository_root=ROOT,
            workspace=workspace,
        )


def test_http2_fingerprint_worker_rejects_registry_replacement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import browser_core.http2_fingerprint as h2_module

    workspace = tmp_path / "workspace"
    workspace.mkdir()
    for name in ("chrome.exe", "cert.pem", "key.pem"):
        (workspace / name).write_bytes(name.encode("ascii"))
    monkeypatch.setattr(
        h2_module,
        "capture_attested_http2_fingerprint",
        lambda *_args, **_kwargs: _attested_http2_receipt(),
    )
    held = workspace / "held-http2-registry"

    def replace_registry(path: Path, document: dict, **_kwargs) -> None:
        path.parent.rename(held)
        path.parent.mkdir()
        path.write_text(json.dumps(document), encoding="utf-8")
        (path.parent / "competitor.bin").write_bytes(b"competitor")

    monkeypatch.setattr(worker_module, "publish_json_exclusive_result", replace_registry)

    with pytest.raises(ContractError, match="changed after publication"):
        execute_typed_job(
            {
                "id": "job-1",
                "kind": "http2-fingerprint",
                "payload": {
                    "executable": str(workspace / "chrome.exe"),
                    "certificate": str(workspace / "cert.pem"),
                    "private_key": str(workspace / "key.pem"),
                    "fingerprint_id": "h2-current",
                    "timeout_seconds": 17,
                },
            },
            repository_root=ROOT,
            workspace=workspace,
        )
    assert held.is_dir()
    assert (workspace / "http2-fingerprints" / "competitor.bin").read_bytes() == (
        b"competitor"
    )


def test_transport_baseline_install_worker_returns_a_path_free_receipt(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    baseline = _transport_baseline_wrapper()

    result = execute_typed_job(
        {
            "id": "job-1",
            "kind": "transport-baseline-install",
            "payload": {"baseline": baseline},
        },
        repository_root=ROOT,
        workspace=workspace,
    )

    assert result == {
        "schema": "browser-core.transport-baseline-installation/1",
        "job_id": "job-1",
        "source_fingerprint_id": "candidate",
        "baseline_fingerprint_id": "golden",
        "digest_sha256": baseline["reviewed_digest_sha256"],
        "core_build": baseline["fingerprint"]["core_build"],
    }
    assert str(workspace) not in str(result)
    assert (
        workspace
        / "transport-fingerprints"
        / "golden.baseline.json"
    ).is_file()


def test_transport_baseline_install_worker_rejects_edited_payload_before_storage(
    tmp_path: Path,
) -> None:
    baseline = _transport_baseline_wrapper()
    baseline["extra"] = True
    workspace = tmp_path / "workspace"

    with pytest.raises(ContractError, match="baseline fields"):
        execute_typed_job(
            {
                "id": "job-1",
                "kind": "transport-baseline-install",
                "payload": {"baseline": baseline},
            },
            repository_root=ROOT,
            workspace=workspace,
        )
    assert not workspace.exists()


def test_transport_fingerprint_worker_uses_only_workspace_owned_input(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import browser_core.transport_fingerprint as transport_module

    workspace = tmp_path / "workspace"
    workspace.mkdir()
    executable = workspace / "chrome.exe"
    executable.write_bytes(b"owned browser")
    expected = _attested_transport_receipt()
    calls: list[tuple[Path, Path, float]] = []

    def capture(root: Path, binary: Path, *, timeout_seconds: float) -> dict:
        calls.append((root, binary, timeout_seconds))
        return expected

    monkeypatch.setattr(transport_module, "capture_attested_client_hello", capture)
    result = execute_typed_job(
        {
            "id": "job-1",
            "kind": "transport-fingerprint",
            "payload": {
                "executable": str(executable),
                "fingerprint_id": "current-1",
                "timeout_seconds": 17,
            },
        },
        repository_root=ROOT,
        workspace=workspace,
    )

    assert result == {
        "schema": "browser-core.transport-fingerprint-publication/1",
        "job_id": "job-1",
        "fingerprint_id": "current-1",
        "digest_sha256": expected["digest_sha256"],
        "core_build": expected["core_build"],
    }
    assert calls == [(ROOT, executable.resolve(), 17.0)]
    assert json.loads(
        (workspace / "transport-fingerprints" / "current-1.json").read_text(
            encoding="utf-8"
        )
    ) == expected


def test_transport_fingerprint_worker_refuses_unvalidated_dependency_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import browser_core.transport_fingerprint as transport_module

    workspace = tmp_path / "workspace"
    workspace.mkdir()
    executable = workspace / "chrome.exe"
    executable.write_bytes(b"owned browser")
    monkeypatch.setattr(
        transport_module,
        "capture_attested_client_hello",
        lambda *_args, **_kwargs: {"schema": "edited", "private_path": "secret"},
    )

    with pytest.raises(ContractError, match="fields are invalid"):
        execute_typed_job(
            {
                "id": "job-1",
                "kind": "transport-fingerprint",
                "payload": {
                    "executable": str(executable),
                    "fingerprint_id": "current-1",
                    "timeout_seconds": 17,
                },
            },
            repository_root=ROOT,
            workspace=workspace,
        )


def test_transport_fingerprint_worker_refuses_an_existing_id_before_capture(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import browser_core.transport_fingerprint as transport_module

    workspace = tmp_path / "workspace"
    registry = workspace / "transport-fingerprints"
    registry.mkdir(parents=True)
    executable = workspace / "chrome.exe"
    executable.write_bytes(b"owned browser")
    existing = registry / "current-1.json"
    existing.write_bytes(b"reviewed golden")
    monkeypatch.setattr(
        transport_module,
        "capture_attested_client_hello",
        lambda *_args, **_kwargs: pytest.fail("existing id reached browser capture"),
    )

    with pytest.raises(ContractError, match="already exists"):
        execute_typed_job(
            {
                "id": "job-1",
                "kind": "transport-fingerprint",
                "payload": {
                    "executable": str(executable),
                    "fingerprint_id": "current-1",
                    "timeout_seconds": 17,
                },
            },
            repository_root=ROOT,
            workspace=workspace,
        )
    assert existing.read_bytes() == b"reviewed golden"


def test_transport_fingerprint_worker_rejects_registry_replacement_at_publication(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import browser_core.transport_fingerprint as transport_module

    workspace = tmp_path / "workspace"
    workspace.mkdir()
    executable = workspace / "chrome.exe"
    executable.write_bytes(b"owned browser")
    expected = _attested_transport_receipt()
    monkeypatch.setattr(
        transport_module,
        "capture_attested_client_hello",
        lambda *_args, **_kwargs: expected,
    )
    held = workspace / "held-registry"

    def replace_registry(path: Path, document: dict, **_kwargs) -> None:
        registry = path.parent
        registry.rename(held)
        registry.mkdir()
        path.write_text(json.dumps(document), encoding="utf-8")
        (registry / "competitor.bin").write_bytes(b"competitor")

    monkeypatch.setattr(worker_module, "publish_json_exclusive_result", replace_registry)

    with pytest.raises(ContractError, match="changed after publication"):
        execute_typed_job(
            {
                "id": "job-1",
                "kind": "transport-fingerprint",
                "payload": {
                    "executable": str(executable),
                    "fingerprint_id": "current-1",
                    "timeout_seconds": 17,
                },
            },
            repository_root=ROOT,
            workspace=workspace,
        )
    assert held.is_dir()
    assert (workspace / "transport-fingerprints" / "competitor.bin").read_bytes() == (
        b"competitor"
    )


@pytest.mark.parametrize("timeout", [True, 0, 121, float("inf"), 10**400])
def test_transport_fingerprint_timeout_fails_before_executable_lookup(
    tmp_path: Path,
    timeout: object,
) -> None:
    with pytest.raises(ContractError, match="transport-fingerprint timeout"):
        execute_typed_job(
            {
                "id": "job-1",
                "kind": "transport-fingerprint",
                "payload": {
                    "executable": str(tmp_path / "missing.exe"),
                    "fingerprint_id": "current-1",
                    "timeout_seconds": timeout,
                },
            },
            repository_root=ROOT,
            workspace=tmp_path,
        )


def test_transport_fingerprint_cannot_select_an_executable_outside_workspace(
    tmp_path: Path,
) -> None:
    outside = tmp_path / "outside.exe"
    outside.write_bytes(b"outside browser")
    workspace = tmp_path / "workspace"
    workspace.mkdir()

    with pytest.raises(ContractError, match="inside the worker workspace"):
        execute_typed_job(
            {
                "id": "job-1",
                "kind": "transport-fingerprint",
                "payload": {
                    "executable": str(outside),
                    "fingerprint_id": "current-1",
                    "timeout_seconds": 17,
                },
            },
            repository_root=ROOT,
            workspace=workspace,
        )


def test_transport_check_worker_returns_a_validated_offline_drift_verdict(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    baseline = _attested_transport_receipt()
    current = json.loads(json.dumps(baseline))
    current["ciphers"] = [0x1302]
    current["digest_sha256"] = transport_digest(current)
    transport_root = workspace / "transport-fingerprints"
    transport_root.mkdir()
    current_path = transport_root / "current.json"
    baseline_path = transport_root / "candidate.json"
    current_path.write_text(json.dumps(current), encoding="utf-8")
    baseline_path.write_text(json.dumps(baseline), encoding="utf-8")
    approve_transport_baseline(
        workspace,
        current_id="candidate",
        baseline_id="baseline",
        expected_digest=baseline["digest_sha256"],
    )

    result = execute_typed_job(
        {
            "id": "job-1",
            "kind": "transport-check",
            "payload": {
                "current_id": "current",
                "baseline_id": "baseline",
            },
        },
        repository_root=ROOT,
        workspace=workspace,
    )

    assert result["schema"] == "browser-core.transport-fingerprint-comparison/1"
    assert result["passed"] is False
    assert result["changed_fields"] == ["ciphers"]
    assert str(workspace) not in str(result)


def test_transport_check_worker_refuses_a_raw_capture_named_as_a_baseline(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    registry = workspace / "transport-fingerprints"
    registry.mkdir(parents=True)
    fingerprint = _attested_transport_receipt()
    (registry / "current.json").write_text(json.dumps(fingerprint), encoding="utf-8")
    (registry / "golden.baseline.json").write_text(
        json.dumps(fingerprint), encoding="utf-8"
    )

    with pytest.raises(ContractError, match="baseline fields"):
        execute_typed_job(
            {
                "id": "job-1",
                "kind": "transport-check",
                "payload": {
                    "current_id": "current",
                    "baseline_id": "golden",
                },
            },
            repository_root=ROOT,
            workspace=workspace,
        )


def test_transport_check_binds_wrapper_id_to_registry_name(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    registry = workspace / "transport-fingerprints"
    registry.mkdir(parents=True)
    fingerprint = _attested_transport_receipt()
    (registry / "current.json").write_text(json.dumps(fingerprint), encoding="utf-8")
    (registry / "impostor.baseline.json").write_text(
        json.dumps(_transport_baseline_wrapper()), encoding="utf-8"
    )

    with pytest.raises(ContractError, match="id does not match"):
        execute_typed_job(
            {
                "id": "check-1",
                "kind": "transport-check",
                "payload": {"current_id": "current", "baseline_id": "impostor"},
            },
            repository_root=ROOT,
            workspace=workspace,
        )


@pytest.mark.parametrize("field", ["current_id", "baseline_id"])
def test_transport_check_identifiers_cannot_escape_the_owned_registry(
    tmp_path: Path,
    field: str,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    payload = {"current_id": "current", "baseline_id": "baseline"}
    payload[field] = "../outside"

    with pytest.raises(ContractError, match="invalid"):
        execute_typed_job(
            {"id": "job-1", "kind": "transport-check", "payload": payload},
            repository_root=ROOT,
            workspace=workspace,
        )


def _multi_identity_report(
    *,
    job_id: str = "job-1",
    states: tuple[str, ...] = ("disposed", "disposed"),
    verdicts: tuple[str | None, ...] = ("pass", "pass"),
) -> dict:
    identities = []
    for index, (state, verdict) in enumerate(zip(states, verdicts, strict=True)):
        status = {
            "schema": "browser-core.identity-ops-status/1",
            "profile_id": f"ops-cohort-fleet-{job_id}-{index:03d}",
            "persona_id": f"persona-{index}",
            "state": state,
            "session_run_id": f"run-{index}",
            "network_route_id": None,
            "network_route_sha256_16": None,
            "timings_ms": {"launch_ms": 1.0},
            "error": None if state == "disposed" else "safe-failure-receipt",
        }
        if verdict is not None:
            status["coherence"] = {"status": "ok", "verdict": verdict}
        identities.append(status)
    counts = {
        "pass": sum(verdict == "pass" for verdict in verdicts),
        "fail": sum(verdict == "fail" for verdict in verdicts),
        "error": sum(verdict not in {"pass", "fail"} for verdict in verdicts),
    }
    lifecycle = all(state == "disposed" for state in states)
    all_pass = lifecycle and counts["pass"] == len(states)
    return {
        "schema": "browser-core.ops-coherence-cohort/1",
        "batch_id": f"fleet-{job_id}",
        "definition": "owned controlled cohort",
        "count": len(states),
        "headless": False,
        "parallel": 1,
        "wall_ms": 10.0,
        "evaluators": "controlled_coherence",
        "network_auto": False,
        "network_route_configured": False,
        "compatibility": {},
        "host_identity_anchors": {},
        "identity_alignments": [],
        "identities": identities,
        "errors": [] if lifecycle else ["safe-arm-failure"],
        "orphans": [],
        "lifecycle_passed": lifecycle,
        "coherence_summary": {
            "arms": len(states),
            **counts,
            "all_pass": all_pass,
        },
        "passed": lifecycle,
        "non_claims": ["not acceptance"],
        "completed_at": "2026-08-11T00:00:00Z",
    }


def test_multi_identity_ops_projection_is_closed_and_consistent() -> None:
    report = _multi_identity_report()
    report["identities"][0]["coherence"]["note"] = r"C:\private\profile"

    receipt = _project_multi_identity_ops_report(
        report,
        job_id="job-1",
        expected_count=2,
        expected_headless=False,
        expected_parallel=1,
        expected_network_auto=False,
    )

    assert receipt["schema"] == "browser-core.multi-identity-ops-result/1"
    assert receipt["lifecycle_passed"] is True
    assert receipt["coherence"] == {
        "pass": 2,
        "fail": 0,
        "error": 0,
        "all_pass": True,
    }
    assert receipt["outcomes"] == [
        {
            "persona_id": "persona-0",
            "state": "disposed",
            "coherence_verdict": "pass",
        },
        {
            "persona_id": "persona-1",
            "state": "disposed",
            "coherence_verdict": "pass",
        },
    ]
    assert "private" not in str(receipt)


@pytest.mark.parametrize("identity_error", ["coherence-eval-failed", ["malformed"]])
def test_multi_identity_ops_projection_rejects_unreported_identity_error(
    identity_error: object,
) -> None:
    report = _multi_identity_report()
    report["identities"][0]["error"] = identity_error
    with pytest.raises(ContractError, match="multi-identity ops identity status"):
        _project_multi_identity_ops_report(
            report,
            job_id="job-1",
            expected_count=2,
            expected_headless=False,
            expected_parallel=1,
            expected_network_auto=False,
        )


@pytest.mark.parametrize(
    "mutate",
    [
        lambda report: report.__setitem__("count", True),
        lambda report: report["identities"][1].__setitem__("persona_id", "persona-0"),
        lambda report: report["coherence_summary"].__setitem__("pass", True),
        lambda report: report["coherence_summary"].__setitem__("all_pass", False),
        lambda report: report.__setitem__("errors", ["unexpected"]),
        lambda report: report.__setitem__("private", "value"),
        lambda report: report.__setitem__("headless", True),
        lambda report: report.__setitem__("parallel", True),
        lambda report: report.__setitem__("network_auto", True),
        lambda report: report.__setitem__("evaluators", "other"),
        lambda report: report["identities"][0].__setitem__("state", []),
        lambda report: report["identities"][0]["coherence"].__setitem__("verdict", []),
    ],
)
def test_multi_identity_ops_projection_rejects_inconsistent_dependency_report(
    mutate,
) -> None:
    report = _multi_identity_report()
    mutate(report)
    with pytest.raises(ContractError, match="multi-identity ops"):
        _project_multi_identity_ops_report(
            report,
            job_id="job-1",
            expected_count=2,
            expected_headless=False,
            expected_parallel=1,
            expected_network_auto=False,
        )


@pytest.mark.parametrize("verdict", [[], "unexpected"])
def test_multi_identity_ops_projection_rejects_malformed_coherence_with_matching_counts(
    verdict: object,
) -> None:
    report = _multi_identity_report(verdicts=(None, "pass"))
    report["identities"][0]["coherence"] = {"verdict": verdict}
    with pytest.raises(ContractError, match="multi-identity ops identity status"):
        _project_multi_identity_ops_report(
            report,
            job_id="job-1",
            expected_count=2,
            expected_headless=False,
            expected_parallel=1,
            expected_network_auto=False,
        )


def test_multi_identity_ops_projection_rejects_error_labeled_as_pass() -> None:
    report = _multi_identity_report()
    report["identities"][0]["coherence"]["status"] = "error"
    with pytest.raises(ContractError, match="multi-identity ops identity status"):
        _project_multi_identity_ops_report(
            report,
            job_id="job-1",
            expected_count=2,
            expected_headless=False,
            expected_parallel=1,
            expected_network_auto=False,
        )


def test_multi_identity_ops_worker_returns_only_projected_receipt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import browser_core.multi_identity_ops as ops

    workspace = tmp_path / "workspace"
    workspace.mkdir()
    executable = workspace / "browser.exe"
    executable.write_bytes(b"owned executable")

    def run(workspace_arg: Path, **kwargs):
        assert workspace_arg == workspace.resolve()
        assert kwargs["count"] == 2
        assert kwargs["persona_ids"] == ["persona-0", "persona-1"]
        assert kwargs["evaluators"] == "controlled_coherence"
        assert kwargs["batch_id"] == "fleet-job-1"
        assert kwargs["parallel"] == 2
        assert kwargs["out_dir"].is_dir()
        report = _multi_identity_report()
        report["parallel"] = 2
        report["compatibility"] = {"note": r"C:\private\catalog"}
        return report

    monkeypatch.setattr(ops, "run_ops_coherence_cohort", run)
    result = execute_typed_job(
        {
            "id": "job-1",
            "kind": "multi-identity-ops",
            "payload": {
                "executable": str(executable),
                "count": 2,
                "persona_ids": ["persona-0", "persona-1"],
                "headless": False,
                "parallel": 2,
                "network_auto": False,
                "network_route_id": None,
                "device_class": "desktop",
            },
        },
        repository_root=ROOT,
        workspace=workspace,
    )

    assert result["schema"] == "browser-core.multi-identity-ops-result/1"
    assert result["job_id"] == "job-1"
    assert "private" not in str(result)


def test_multi_identity_ops_worker_rejects_malformed_device_class_before_file_lookup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        worker_module,
        "_require_workspace_file",
        lambda *_args, **_kwargs: pytest.fail("file lookup reached"),
    )
    with pytest.raises(ContractError, match="device class"):
        execute_typed_job(
            {
                "id": "job-1",
                "kind": "multi-identity-ops",
                "payload": {
                    "executable": "missing.exe",
                    "count": 1,
                    "persona_ids": ["persona-0"],
                    "headless": False,
                    "parallel": 1,
                    "network_auto": False,
                    "network_route_id": None,
                    "device_class": [],
                },
            },
            repository_root=ROOT,
            workspace=tmp_path,
        )


def test_multi_identity_ops_worker_rejects_output_directory_replacement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import browser_core.multi_identity_ops as ops

    workspace = tmp_path / "workspace"
    workspace.mkdir()
    executable = workspace / "browser.exe"
    executable.write_bytes(b"owned executable")
    holding = workspace / "fleet-ops" / "holding"
    competitor_body = b"competitor evidence"

    def run(_workspace: Path, **kwargs):
        out_dir = kwargs["out_dir"]
        assert out_dir.is_dir()
        out_dir.rename(holding)
        out_dir.mkdir()
        (out_dir / "competitor.bin").write_bytes(competitor_body)
        return _multi_identity_report()

    monkeypatch.setattr(ops, "run_ops_coherence_cohort", run)
    with pytest.raises(ContractError, match="output authority changed"):
        execute_typed_job(
            {
                "id": "job-1",
                "kind": "multi-identity-ops",
                "payload": {
                    "executable": str(executable),
                    "count": 2,
                    "persona_ids": ["persona-0", "persona-1"],
                    "headless": False,
                    "parallel": 1,
                    "network_auto": False,
                    "network_route_id": None,
                    "device_class": "desktop",
                },
            },
            repository_root=ROOT,
            workspace=workspace,
        )
    assert holding.is_dir()
    assert (workspace / "fleet-ops" / "job-1" / "competitor.bin").read_bytes() == (
        competitor_body
    )


def test_multi_identity_ops_worker_rejects_relocated_workspace_ancestor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import browser_core.multi_identity_ops as ops

    workspace = tmp_path / "workspace"
    workspace.mkdir()
    executable = workspace / "browser.exe"
    executable.write_bytes(b"owned executable")

    def run(_workspace: Path, **_kwargs: object) -> dict[str, object]:
        retained = tmp_path / "retained"
        workspace.rename(retained)
        workspace.mkdir()
        (retained / "fleet-ops").rename(workspace / "fleet-ops")
        return _multi_identity_report()

    monkeypatch.setattr(ops, "run_ops_coherence_cohort", run)
    with pytest.raises(ContractError, match="output authority changed"):
        execute_typed_job(
            {
                "id": "job-1",
                "kind": "multi-identity-ops",
                "payload": {
                    "executable": str(executable),
                    "count": 2,
                    "persona_ids": ["persona-0", "persona-1"],
                    "headless": False,
                    "parallel": 1,
                    "network_auto": False,
                    "network_route_id": None,
                    "device_class": "desktop",
                },
            },
            repository_root=ROOT,
            workspace=workspace,
        )
    assert (workspace / "fleet-ops" / "job-1").is_dir()


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("count", True, "count"),
        ("parallel", True, "parallel"),
        ("headless", 0, "headless"),
        ("network_auto", "false", "network_auto"),
        ("device_class", "../../phone", "device class"),
        ("persona_ids", [["unhashable"]], "persona ids"),
    ],
)
def test_multi_identity_ops_payload_is_typed_before_execution(
    tmp_path: Path,
    field: str,
    value,
    message: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import browser_core.multi_identity_ops as ops

    workspace = tmp_path / "workspace"
    workspace.mkdir()
    executable = workspace / "browser.exe"
    executable.write_bytes(b"owned executable")
    monkeypatch.setattr(
        ops,
        "run_ops_coherence_cohort",
        lambda *_args, **_kwargs: pytest.fail("invalid payload reached execution"),
    )
    payload = {
        "executable": str(executable),
        "count": 1,
        "persona_ids": ["persona-0"],
        "headless": False,
        "parallel": 1,
        "network_auto": False,
        "network_route_id": None,
        "device_class": "desktop",
    }
    payload[field] = value
    with pytest.raises(ContractError, match=message):
        execute_typed_job(
            {"id": "job-1", "kind": "multi-identity-ops", "payload": payload},
            repository_root=ROOT,
            workspace=workspace,
        )


@pytest.mark.parametrize(
    "kind, payload",
    [
        (
            "browser-fact-capture",
            {
                "session_id": "../../etc/passwd",
                "snapshot_id": "s1",
                "timeout_seconds": 1.0,
                "target_url": None,
            },
        ),
        (
            "browser-fact-capture",
            {
                "session_id": "ok",
                "snapshot_id": "a/b",
                "timeout_seconds": 1.0,
                "target_url": None,
            },
        ),
        (
            "evidence-pack",
            {
                "session_id": "ok",
                "pack_id": "../out",
                "browser_fact_id": None,
                "transport_fingerprint_id": None,
                "http2_fingerprint_id": None,
                "include_session_copy": False,
            },
        ),
    ],
)
def test_a_leased_payload_may_name_an_identifier_but_never_a_path(
    kind, payload, tmp_path: Path
) -> None:
    """The one place a remote principal chooses a filename.

    This control plane refuses a `shell` job so that a job cannot become
    arbitrary local action; a payload that could name `../..` would give the
    same reach back through a different door.
    """
    with pytest.raises(ContractError, match="invalid"):
        execute_typed_job(
            {"kind": kind, "payload": payload, "id": "j-1"},
            repository_root=Path("."),
            workspace=tmp_path,
        )


def test_an_unknown_session_is_refused_before_anything_is_opened(
    tmp_path: Path,
) -> None:
    with pytest.raises(ContractError, match="unknown session"):
        execute_typed_job(
            {
                "kind": "browser-fact-capture",
                "payload": {
                    "session_id": "never-created",
                    "snapshot_id": "snap-1",
                    "timeout_seconds": 1.0,
                    "target_url": None,
                },
                "id": "j-1",
            },
            repository_root=Path("."),
            workspace=tmp_path,
        )


def test_browser_eval_job_id_cannot_escape_the_fleet_run_directory(
    tmp_path: Path,
) -> None:
    with pytest.raises(ContractError, match="job id is invalid"):
        execute_typed_job(
            {
                "id": "../../outside",
                "kind": "browser-eval",
                "payload": {
                    "evaluators": ["controlled_coherence"],
                    "backend": "playwright",
                    "channel": "chromium",
                    "headless": True,
                    "timeout_ms": 30_000,
                },
            },
            repository_root=ROOT,
            workspace=tmp_path,
        )
    assert not (tmp_path / "fleet-runs").exists()


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("evaluators", [["not-hashable"]], "evaluator ids"),
        ("backend", ["playwright"], "backend"),
        ("channel", True, "channel"),
        ("headless", "false", "headless flag"),
        ("timeout_ms", True, "timeout"),
    ],
)
def test_browser_eval_payload_is_typed_before_browser_eval_import(
    tmp_path: Path, field: str, value, message: str
) -> None:
    payload = {
        "evaluators": ["controlled_coherence"],
        "backend": "playwright",
        "channel": "chromium",
        "headless": True,
        "timeout_ms": 30_000,
    }
    payload[field] = value

    with pytest.raises(ContractError, match=message):
        execute_typed_job(
            {"id": "job-1", "kind": "browser-eval", "payload": payload},
            repository_root=ROOT,
            workspace=tmp_path,
        )


def _browser_eval_summary(*, status: str = "ok") -> dict:
    return {
        "run_id": "20260810T120000.000000Z",
        "evaluators": [
            {
                "id": "controlled_coherence",
                "status": status,
                "verdict": "pass" if status == "ok" else "unknown",
                "signals": {"private_path": r"C:\private\profile"},
            }
        ],
        "completed": 1 if status == "ok" else 0,
        "failed": 0 if status == "ok" else 1,
        "total": 1,
        "private_root": r"C:\private\profile",
    }


def _publish_browser_eval_stub(run_dir: Path, *, summary: dict | None = None) -> None:
    run_dir.mkdir()
    (run_dir / "evaluators").mkdir()
    (run_dir / "manifest.json").write_text('{"x":1}', encoding="utf-8")
    (run_dir / "evaluators" / "controlled_coherence.json").write_text(
        '{"x":1}', encoding="utf-8"
    )
    if summary is not None:
        (run_dir / "summary.json").write_text(json.dumps(summary), encoding="utf-8")


def test_browser_eval_worker_returns_a_closed_path_free_receipt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import browser_eval.runner as runner

    def execute(_specs, config):  # noqa: ANN001
        assert config.out is not None
        assert config.out.parent.is_dir()
        assert not config.out.exists()
        _publish_browser_eval_stub(config.out, summary=_browser_eval_summary())
        return config.out, _browser_eval_summary()

    monkeypatch.setattr(runner, "execute_run", execute)
    monkeypatch.setattr(runner, "load_or_build_summary", lambda _path: _browser_eval_summary())
    result = execute_typed_job(
        {
            "id": "job-1",
            "kind": "browser-eval",
            "payload": {
                "evaluators": ["controlled_coherence"],
                "backend": "playwright",
                "channel": "chromium",
                "headless": True,
                "timeout_ms": 30_000,
            },
        },
        repository_root=ROOT,
        workspace=tmp_path,
    )
    assert result["schema"] == "browser-core.browser-eval-result/2"
    assert result["outcomes"] == [
        {"id": "controlled_coherence", "status": "ok", "verdict": "pass"}
    ]
    assert "run_dir" not in result and "summary" not in result
    assert str(tmp_path) not in str(result)
    assert len(result["summary_sha256_16"]) == 16


@pytest.mark.parametrize("saved", [None, "different"])
def test_browser_eval_worker_requires_matching_saved_run(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    saved: str | None,
) -> None:
    import browser_eval.runner as runner

    def execute(_specs, config):
        _publish_browser_eval_stub(config.out, summary=_browser_eval_summary())
        return config.out, _browser_eval_summary()

    def read_saved(_path):
        if saved is None:
            raise ValueError("private saved run path")
        return _browser_eval_summary(status="error")

    monkeypatch.setattr(runner, "execute_run", execute)
    monkeypatch.setattr(runner, "load_or_build_summary", read_saved)
    with pytest.raises(ContractError, match="saved run") as raised:
        execute_typed_job(
            {
                "id": "job-1",
                "kind": "browser-eval",
                "payload": {
                    "evaluators": ["controlled_coherence"],
                    "backend": "playwright",
                    "channel": "chromium",
                    "headless": True,
                    "timeout_ms": 30_000,
                },
            },
            repository_root=ROOT,
            workspace=tmp_path,
        )
    assert "private saved run path" not in str(raised.value)


@pytest.mark.parametrize("saved_file", [None, "different", "invalid"])
def test_browser_eval_worker_requires_matching_published_summary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    saved_file: str | None,
) -> None:
    import browser_eval.runner as runner

    def execute(_specs, config):
        _publish_browser_eval_stub(
            config.out,
            summary=(
                _browser_eval_summary(status="error")
                if saved_file == "different"
                else _browser_eval_summary() if saved_file is not None else None
            ),
        )
        if saved_file == "invalid":
            (config.out / "summary.json").write_text("{", encoding="utf-8")
        return config.out, _browser_eval_summary()

    monkeypatch.setattr(runner, "execute_run", execute)
    monkeypatch.setattr(runner, "load_or_build_summary", lambda _path: _browser_eval_summary())
    with pytest.raises(ContractError, match="saved run"):
        execute_typed_job(
            {
                "id": "job-1",
                "kind": "browser-eval",
                "payload": {
                    "evaluators": ["controlled_coherence"],
                    "backend": "playwright",
                    "channel": "chromium",
                    "headless": True,
                    "timeout_ms": 30_000,
                },
            },
            repository_root=ROOT,
            workspace=tmp_path,
        )


@pytest.mark.parametrize("damage", ["missing-manifest", "missing-evaluator", "hardlinked-manifest"])
def test_browser_eval_worker_requires_complete_owned_saved_artifacts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    damage: str,
) -> None:
    import browser_eval.runner as runner

    def execute(_specs, config):
        _publish_browser_eval_stub(config.out, summary=_browser_eval_summary())
        if damage == "missing-manifest":
            (config.out / "manifest.json").unlink()
        elif damage == "missing-evaluator":
            (config.out / "evaluators" / "controlled_coherence.json").unlink()
        else:
            outside = tmp_path / "outside-manifest.json"
            outside.write_text('{"x":1}', encoding="utf-8")
            (config.out / "manifest.json").unlink()
            os.link(outside, config.out / "manifest.json")
        return config.out, _browser_eval_summary()

    monkeypatch.setattr(runner, "execute_run", execute)
    monkeypatch.setattr(runner, "load_or_build_summary", lambda _path: _browser_eval_summary())
    with pytest.raises(ContractError, match="saved run"):
        execute_typed_job(
            {
                "id": "job-1",
                "kind": "browser-eval",
                "payload": {
                    "evaluators": ["controlled_coherence"],
                    "backend": "playwright",
                    "channel": "chromium",
                    "headless": True,
                    "timeout_ms": 30_000,
                },
            },
            repository_root=ROOT,
            workspace=tmp_path,
        )


@pytest.mark.parametrize("changed", ["manifest", "evaluator"])
def test_browser_eval_worker_rebinds_saved_artifacts_after_validation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    changed: str,
) -> None:
    import browser_eval.runner as runner

    def execute(_specs, config):
        _publish_browser_eval_stub(config.out, summary=_browser_eval_summary())
        return config.out, _browser_eval_summary()

    def read_saved(path):
        selected = (
            path / "manifest.json" if changed == "manifest"
            else path / "evaluators" / "controlled_coherence.json"
        )
        prior = selected.stat()
        selected.write_text('{"x":2}', encoding="utf-8")
        os.utime(selected, ns=(prior.st_atime_ns, prior.st_mtime_ns))
        return _browser_eval_summary()

    monkeypatch.setattr(runner, "execute_run", execute)
    monkeypatch.setattr(runner, "load_or_build_summary", read_saved)
    with pytest.raises(ContractError, match="saved run"):
        execute_typed_job(
            {
                "id": "job-1",
                "kind": "browser-eval",
                "payload": {
                    "evaluators": ["controlled_coherence"],
                    "backend": "playwright",
                    "channel": "chromium",
                    "headless": True,
                    "timeout_ms": 30_000,
                },
            },
            repository_root=ROOT,
            workspace=tmp_path,
        )


def test_browser_eval_worker_rebinds_summary_after_final_evaluator_scan(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    import browser_eval.runner as runner

    original = json.dumps(_browser_eval_summary()).encode("utf-8")
    replacement = json.dumps(_browser_eval_summary(status="error")).encode("utf-8")
    length = max(len(original), len(replacement))
    original = original.ljust(length, b" ")
    replacement = replacement.ljust(length, b" ")

    def execute(_specs, config):
        _publish_browser_eval_stub(config.out, summary=_browser_eval_summary())
        (config.out / "summary.json").write_bytes(original)
        return config.out, _browser_eval_summary()

    monkeypatch.setattr(runner, "execute_run", execute)
    monkeypatch.setattr(runner, "load_or_build_summary", lambda _path: _browser_eval_summary())
    original_bind = worker_module._browser_eval_saved_bindings
    scans = 0

    def replace_during_final_scan(*args, **kwargs):
        nonlocal scans
        bindings = original_bind(*args, **kwargs)
        scans += 1
        if scans == 2:
            path = args[0] / "summary.json"
            before = path.stat()
            path.write_bytes(replacement)
            os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns))
        return bindings

    monkeypatch.setattr(worker_module, "_browser_eval_saved_bindings", replace_during_final_scan)
    with pytest.raises(ContractError, match="saved run changed during validation"):
        execute_typed_job(
            {
                "id": "job-1",
                "kind": "browser-eval",
                "payload": {
                    "evaluators": ["controlled_coherence"],
                    "backend": "playwright",
                    "channel": "chromium",
                    "headless": True,
                    "timeout_ms": 30_000,
                },
            },
            repository_root=ROOT,
            workspace=tmp_path,
        )
    assert scans == 2
    assert json.loads((tmp_path / "fleet-runs" / "job-1" / "run" / "summary.json").read_bytes())[
        "evaluators"
    ][0]["status"] == "error"


def test_failure_receipt_survives_unformattable_dependency_error() -> None:
    class UnformattableError(Exception):
        def __str__(self) -> str:
            raise ValueError("private dependency error text")

    receipt = _failure_receipt(UnformattableError())
    assert receipt["error_type"] == "UnformattableError"
    assert receipt["message"] == "typed job execution failed"
    assert len(receipt["diagnostic_sha256_16"]) == 16
    assert "private" not in str(receipt)


def test_browser_eval_worker_rejects_an_unowned_returned_directory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import browser_eval.runner as runner

    outside = tmp_path / "outside"

    def execute(_specs, _config):  # noqa: ANN001
        outside.mkdir()
        return outside, _browser_eval_summary()

    monkeypatch.setattr(runner, "execute_run", execute)
    with pytest.raises(ContractError, match="unowned run directory"):
        execute_typed_job(
            {
                "id": "job-1",
                "kind": "browser-eval",
                "payload": {
                    "evaluators": ["controlled_coherence"],
                    "backend": "playwright",
                    "channel": "chromium",
                    "headless": True,
                    "timeout_ms": 30_000,
                },
            },
            repository_root=ROOT,
            workspace=tmp_path / "workspace",
        )


def test_browser_eval_worker_rejects_job_output_directory_replacement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import browser_eval.runner as runner

    workspace = tmp_path / "workspace"
    displaced = workspace / "fleet-runs" / "displaced"

    def execute(_specs, config):  # noqa: ANN001
        assert config.out is not None
        job_output = config.out.parent
        job_output.rename(displaced)
        job_output.mkdir()
        marker = job_output / "competitor.bin"
        marker.write_bytes(b"competitor")
        config.out.mkdir()
        return config.out, _browser_eval_summary()

    monkeypatch.setattr(runner, "execute_run", execute)
    with pytest.raises(ContractError, match="output authority changed"):
        execute_typed_job(
            {
                "id": "job-1",
                "kind": "browser-eval",
                "payload": {
                    "evaluators": ["controlled_coherence"],
                    "backend": "playwright",
                    "channel": "chromium",
                    "headless": True,
                    "timeout_ms": 30_000,
                },
            },
            repository_root=ROOT,
            workspace=workspace,
        )

    assert displaced.is_dir()
    assert (workspace / "fleet-runs" / "job-1" / "competitor.bin").read_bytes() == (
        b"competitor"
    )


def test_browser_eval_worker_rejects_relocated_workspace_ancestor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import browser_eval.runner as runner

    workspace = tmp_path / "workspace"
    workspace.mkdir()
    retained = tmp_path / "retained"

    def execute(_specs, config):  # noqa: ANN001
        _publish_browser_eval_stub(config.out, summary=_browser_eval_summary())
        workspace.rename(retained)
        workspace.mkdir()
        (retained / "fleet-runs").rename(workspace / "fleet-runs")
        return config.out, _browser_eval_summary()

    monkeypatch.setattr(runner, "execute_run", execute)
    monkeypatch.setattr(runner, "load_or_build_summary", lambda _path: _browser_eval_summary())
    with pytest.raises(ContractError, match="browser-eval output authority changed"):
        execute_typed_job(
            {
                "id": "job-1",
                "kind": "browser-eval",
                "payload": {
                    "evaluators": ["controlled_coherence"],
                    "backend": "playwright",
                    "channel": "chromium",
                    "headless": True,
                    "timeout_ms": 30_000,
                },
            },
            repository_root=ROOT,
            workspace=workspace,
        )

    assert (workspace / "fleet-runs" / "job-1" / "run" / "summary.json").exists()


@pytest.mark.parametrize(
    "mutation",
    [
        lambda summary: summary.__setitem__("completed", True),
        lambda summary: summary.__setitem__("total", 2),
        lambda summary: summary["evaluators"][0].__setitem__("id", "other"),
        lambda summary: summary["evaluators"][0].__setitem__("verdict", "maybe"),
        lambda summary: summary["evaluators"][0].__setitem__("status", []),
        lambda summary: summary["evaluators"][0].__setitem__("verdict", []),
    ],
)
def test_browser_eval_receipt_rejects_inconsistent_dependency_summaries(
    mutation,
) -> None:
    summary = _browser_eval_summary()
    mutation(summary)
    with pytest.raises(ContractError, match="summary"):
        _project_browser_eval_summary(
            summary,
            job_id="job-1",
            requested_ids=["controlled_coherence"],
        )


def test_browser_eval_receipt_rejects_error_labeled_as_pass() -> None:
    summary = _browser_eval_summary(status="error")
    summary["evaluators"][0]["verdict"] = "pass"
    with pytest.raises(ContractError, match="summary evaluator"):
        _project_browser_eval_summary(
            summary,
            job_id="job-1",
            requested_ids=["controlled_coherence"],
        )


def test_typed_worker_requires_exact_root_path_types() -> None:
    with pytest.raises(ContractError, match="roots must be Paths"):
        execute_typed_job(  # type: ignore[arg-type]
            {"id": "job-1", "kind": "unknown", "payload": {}},
            repository_root=".",
            workspace=Path("."),
        )


@pytest.mark.parametrize(
    "timeout", [True, "1", float("nan"), float("inf"), 0, 121, 10**400]
)
def test_physical_probe_timeout_fails_before_device_discovery(
    tmp_path: Path, timeout, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        worker_module,
        "probe_physical_android",
        lambda **_kwargs: pytest.fail("invalid timeout reached device probe"),
    )
    with pytest.raises(ContractError, match="timeout must be finite"):
        execute_typed_job(
            {
                "id": "job-1",
                "kind": "physical-kernel-probe",
                "payload": {"platform": "android", "timeout_seconds": timeout},
            },
            repository_root=ROOT,
            workspace=tmp_path,
        )


@pytest.mark.parametrize("timeout", [301, 10**400])
def test_native_smoke_timeout_fails_before_workspace_file_lookup(
    tmp_path: Path,
    timeout: object,
) -> None:
    with pytest.raises(ContractError, match="native-smoke timeout"):
        execute_typed_job(
            {
                "id": "job-1",
                "kind": "native-smoke",
                "payload": {
                    "executable": str(tmp_path / "missing-browser.exe"),
                    "trace_processor": str(tmp_path / "missing-processor.exe"),
                    "timeout_seconds": timeout,
                },
            },
            repository_root=ROOT,
            workspace=tmp_path,
        )


@pytest.mark.parametrize("timeout", [121, 10**400])
def test_browser_fact_timeout_fails_before_session_lookup(
    tmp_path: Path,
    timeout: object,
) -> None:
    with pytest.raises(ContractError, match="browser-fact-capture timeout"):
        execute_typed_job(
            {
                "id": "job-1",
                "kind": "browser-fact-capture",
                "payload": {
                    "session_id": "missing-session",
                    "snapshot_id": "snapshot-1",
                    "timeout_seconds": timeout,
                    "target_url": None,
                },
            },
            repository_root=ROOT,
            workspace=tmp_path,
        )


def test_native_smoke_cannot_select_an_executable_outside_worker_workspace(
    tmp_path: Path,
) -> None:
    outside = tmp_path / "outside.exe"
    outside.write_bytes(b"not executable")
    workspace = tmp_path / "workspace"
    workspace.mkdir()

    with pytest.raises(ContractError, match="inside the worker workspace"):
        execute_typed_job(
            {
                "id": "job-1",
                "kind": "native-smoke",
                "payload": {
                    "executable": str(outside),
                    "trace_processor": str(outside),
                    "timeout_seconds": 1,
                },
            },
            repository_root=ROOT,
            workspace=workspace,
        )


def test_evidence_pack_flag_requires_a_boolean_before_session_lookup(
    tmp_path: Path,
) -> None:
    with pytest.raises(ContractError, match="flag must be boolean"):
        execute_typed_job(
            {
                "id": "job-1",
                "kind": "evidence-pack",
                "payload": {
                    "session_id": "missing",
                    "pack_id": "pack-1",
                    "browser_fact_id": None,
                    "transport_fingerprint_id": None,
                    "http2_fingerprint_id": None,
                    "include_session_copy": "false",
                },
            },
            repository_root=ROOT,
            workspace=tmp_path,
        )


@pytest.mark.skipif(os.name != "nt", reason="Win32 output path alias")
@pytest.mark.parametrize("pack_id", ["CON", "pack-1."])
def test_evidence_pack_worker_rejects_unsafe_pack_id_before_output_creation(
    tmp_path: Path,
    pack_id: str,
) -> None:
    workspace = tmp_path / "workspace"
    sessions = workspace / "sessions"
    sessions.mkdir(parents=True)
    (sessions / "session-1.json").write_bytes(b"{}")

    with pytest.raises(ContractError, match="pack id is invalid"):
        execute_typed_job(
            {
                "id": "job-1",
                "kind": "evidence-pack",
                "payload": {
                    "session_id": "session-1",
                    "pack_id": pack_id,
                    "browser_fact_id": None,
                    "transport_fingerprint_id": None,
                    "http2_fingerprint_id": None,
                    "http2_evidence_id": None,
                    "include_session_copy": False,
                },
            },
            repository_root=ROOT,
            workspace=workspace,
        )
    assert not (workspace / "evidence-packs").exists()


def test_evidence_pack_worker_passes_an_owned_transport_fingerprint(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import browser_core.evidence_pack as evidence_module

    workspace = tmp_path / "workspace"
    sessions = workspace / "sessions"
    transports = workspace / "transport-fingerprints"
    http2_registry = workspace / "http2-fingerprints"
    http2_evidence_registry = workspace / "http2-evidence"
    sessions.mkdir(parents=True)
    transports.mkdir()
    http2_registry.mkdir()
    http2_evidence_registry.mkdir()
    session = sessions / "session-1.json"
    transport = transports / "transport-1.json"
    http2 = http2_registry / "http2-1.json"
    http2_evidence = http2_evidence_registry / "http2-evidence-1.json"
    session.write_bytes(b"{}")
    transport.write_text(json.dumps(_attested_transport_receipt()), encoding="utf-8")
    http2.write_text(json.dumps(_attested_http2_receipt()), encoding="utf-8")
    http2_evidence.write_text(
        json.dumps(_attested_http2_evidence()),
        encoding="utf-8",
    )
    captured: dict[str, object] = {}

    def build(**kwargs):  # noqa: ANN003
        captured.update(kwargs)
        return {"schema": "browser-core.evidence-pack/1"}

    monkeypatch.setattr(evidence_module, "build_evidence_pack", build)
    result = execute_typed_job(
        {
            "id": "job-1",
            "kind": "evidence-pack",
            "payload": {
                "session_id": "session-1",
                "pack_id": "pack-1",
                "browser_fact_id": None,
                "transport_fingerprint_id": "transport-1",
                "http2_fingerprint_id": "http2-1",
                "http2_evidence_id": "http2-evidence-1",
                "include_session_copy": False,
            },
        },
        repository_root=ROOT,
        workspace=workspace,
    )

    assert result == {"schema": "browser-core.evidence-pack/1"}
    assert captured["session_path"] == session
    assert captured["transport_fingerprint_path"] == transport
    assert captured["http2_fingerprint_path"] == http2
    assert captured["http2_evidence_path"] == http2_evidence
    assert captured["out_dir"] == workspace / "evidence-packs" / "pack-1"


@pytest.mark.parametrize(
    "field",
    [
        "transport_fingerprint_id",
        "http2_fingerprint_id",
        "http2_evidence_id",
    ],
)
def test_evidence_pack_transport_identifier_cannot_escape_its_registry(
    tmp_path: Path,
    field: str,
) -> None:
    payload = {
        "session_id": "session-1",
        "pack_id": "pack-1",
        "browser_fact_id": None,
        "transport_fingerprint_id": None,
        "http2_fingerprint_id": None,
        "http2_evidence_id": None,
        "include_session_copy": False,
    }
    payload[field] = "../outside"
    with pytest.raises(ContractError, match="invalid"):
        execute_typed_job(
            {
                "id": "job-1",
                "kind": "evidence-pack",
                "payload": payload,
            },
            repository_root=ROOT,
            workspace=tmp_path,
        )


@pytest.mark.parametrize(
    "field",
    [
        "session_id",
        "pack_id",
        "browser_fact_id",
        "transport_fingerprint_id",
        "http2_fingerprint_id",
        "http2_evidence_id",
    ],
)
def test_evidence_pack_validates_every_id_before_registry_contact(
    tmp_path: Path,
    field: str,
) -> None:
    payload = {
        "session_id": "missing-session",
        "pack_id": "missing-pack",
        "browser_fact_id": "missing-fact",
        "transport_fingerprint_id": "missing-transport",
        "http2_fingerprint_id": "missing-http2",
        "http2_evidence_id": "missing-http2-evidence",
        "include_session_copy": False,
    }
    payload[field] = "../outside"
    with pytest.raises(ContractError, match=f"{field.replace('_', ' ')}.*invalid|invalid"):
        execute_typed_job(
            {"id": "job-1", "kind": "evidence-pack", "payload": payload},
            repository_root=ROOT,
            workspace=tmp_path,
        )


def test_worker_failure_receipts_hash_but_do_not_echo_local_diagnostics() -> None:
    receipt = _failure_receipt(
        RuntimeError(r"C:\private\worker\profile token=private-worker-token")
    )

    assert receipt["error_type"] == "RuntimeError"
    assert receipt["message"] == "typed job execution failed"
    assert len(receipt["diagnostic_sha256_16"]) == 16
    assert "private" not in str(receipt)


def test_worker_network_probe_cannot_override_the_route_target(tmp_path: Path) -> None:
    from browser_core.network import add_network_route, build_network_route

    route = build_network_route(
        route_id="owned-route",
        name="Owned route",
        geography={
            "country": "US",
            "locale": "en-US",
            "timezone": "America/Chicago",
        },
        preflight_url="https://owned.example/health",
    )
    add_network_route(tmp_path, route)

    with pytest.raises(ContractError, match="does not match the route contract"):
        execute_typed_job(
            {
                "id": "job-1",
                "kind": "network-preflight",
                "payload": {
                    "route_id": "owned-route",
                    "probe_url": "https://127.0.0.1:4444/",
                },
            },
            repository_root=ROOT,
            workspace=tmp_path,
        )
