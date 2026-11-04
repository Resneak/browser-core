from __future__ import annotations

import io
import hashlib
import json
import socket
import ssl
import threading
import time
import urllib.error
import urllib.request
from email.message import Message
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import urlsplit

import pytest

import browser_core.client as client_module
import browser_core.local_http as local_http
import browser_core.service as service_module
from browser_core.client import ControlClient
from browser_core.contracts import ContractError
from browser_core.control import ControlStore
from browser_core.service import ServiceConfig, serve_control, validate_service_config
from browser_core.worker import run_remote_worker_once


def request(
    url: str, method: str = "GET", *, token: str | None = None, body=None, headers=None
):
    data = None
    request_headers = dict(headers or {})
    if body is not None:
        if isinstance(body, bytes):
            data = body
        else:
            data = json.dumps(body).encode("utf-8")
            request_headers["Content-Type"] = "application/json"
    if token:
        request_headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, data=data, method=method, headers=request_headers)
    with urllib.request.urlopen(req, timeout=5) as response:
        payload = response.read()
        return response.status, response.headers, payload


def setup_store(tmp_path: Path):
    store = ControlStore(tmp_path)
    bootstrap = store.bootstrap(
        workspace_id="lab", workspace_name="Lab", owner_id="alice", owner_name="Alice"
    )
    owner = store.authenticate(bootstrap["token"])
    store.add_member(owner, "lab", user_id="eve", display_name="Eve", role="viewer")
    viewer_token = store.issue_token(owner, "lab", "eve")
    worker_registration = store.register_worker(
        owner,
        "lab",
        "worker-one",
        name="Worker",
        capabilities=["chromium"],
        max_slots=1,
    )
    return store, bootstrap["token"], viewer_token, worker_registration["worker_token"]


def raw_request(base: str, request_bytes: bytes) -> tuple[int, bytes]:
    parsed = urlsplit(base)
    assert parsed.hostname is not None and parsed.port is not None
    with socket.create_connection((parsed.hostname, parsed.port), timeout=5) as client:
        client.settimeout(5)
        client.sendall(request_bytes)
        client.shutdown(socket.SHUT_WR)
        response = bytearray()
        while True:
            chunk = client.recv(65536)
            if not chunk:
                break
            response.extend(chunk)
    head, _, body = bytes(response).partition(b"\r\n\r\n")
    status = int(head.split(b"\r\n", 1)[0].split()[1])
    return status, body


def test_control_service_does_not_append_error_after_response_write_failure() -> None:
    writes: list[bytes] = []

    class PartialWriter:
        def write(self, body: bytes) -> None:
            writes.append(body)
            if len(writes) == 2:
                raise OSError("private response write failure")

    handler = object.__new__(service_module._handler_class(object()))
    handler.path = "/v1/health"
    handler.command = "GET"
    handler.requestline = "GET /v1/health HTTP/1.1"
    handler.request_version = "HTTP/1.1"
    handler.close_connection = False
    handler.wfile = PartialWriter()

    handler.do_GET()

    assert len(writes) == 2
    assert writes[0].startswith(b"HTTP/1.0 200")
    assert handler.close_connection is True


def test_control_service_idle_header_has_socket_deadline(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(service_module, "REQUEST_READ_TIMEOUT_SECONDS", 0.1)
    with serve_control(ControlStore(tmp_path)) as base:
        parsed = urlsplit(base)
        assert parsed.hostname is not None and parsed.port is not None
        with socket.create_connection((parsed.hostname, parsed.port), timeout=1) as client:
            client.settimeout(0.5)
            client.sendall(b"GET /v1/health HTTP/1.1\r\nHost: localhost\r\n")
            try:
                result = client.recv(1)
            except OSError as exc:
                assert not isinstance(exc, TimeoutError)
            else:
                assert result == b""


def test_control_service_shutdown_closes_active_header_client(tmp_path: Path) -> None:
    with serve_control(ControlStore(tmp_path)) as base:
        parsed = urlsplit(base)
        assert parsed.hostname is not None and parsed.port is not None
        client = socket.create_connection((parsed.hostname, parsed.port), timeout=1)
        client.sendall(b"GET /v1/health HTTP/1.1\r\nHost: localhost\r\n")
        time.sleep(0.05)
    try:
        client.settimeout(0.2)
        try:
            response = client.recv(1)
        except (ConnectionAbortedError, ConnectionResetError):
            pass
        else:
            assert response == b""
    finally:
        client.close()


def test_control_service_header_trickle_has_total_deadline(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(service_module, "REQUEST_READ_TIMEOUT_SECONDS", 0.5)
    with serve_control(ControlStore(tmp_path)) as base:
        parsed = urlsplit(base)
        assert parsed.hostname is not None and parsed.port is not None
        with socket.create_connection((parsed.hostname, parsed.port), timeout=1) as client:
            client.settimeout(1)
            client.sendall(b"GET /v1/health HTTP/1.1\r\nHost: localhost\r\n")
            for index in range(7):
                time.sleep(0.1)
                try:
                    client.sendall(f"X-Pad-{index}: x\r\n".encode("ascii"))
                except OSError:
                    break
            else:
                try:
                    client.sendall(b"\r\n")
                except OSError:
                    pass
            try:
                response = client.recv(4096)
            except OSError:
                response = b""
            assert b" 200 " not in response


def test_control_service_rejects_aggregate_header_bytes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(local_http, "MAX_HTTP_HEADER_BYTES", 256, raising=False)
    with serve_control(ControlStore(tmp_path)) as base:
        parsed = urlsplit(base)
        assert parsed.hostname is not None and parsed.port is not None
        with socket.create_connection((parsed.hostname, parsed.port), timeout=1) as client:
            client.settimeout(1)
            client.sendall(
                b"GET /v1/health HTTP/1.1\r\nHost: localhost\r\n"
                + b"X-Pad-A: " + b"a" * 120 + b"\r\n"
                + b"X-Pad-B: " + b"b" * 120 + b"\r\n\r\n"
            )
            try:
                response = client.recv(4096)
            except OSError:
                response = b""
            assert b" 200 " not in response


def test_control_service_request_line_trickle_has_total_deadline(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(service_module, "REQUEST_READ_TIMEOUT_SECONDS", 0.5)
    with serve_control(ControlStore(tmp_path)) as base:
        parsed = urlsplit(base)
        assert parsed.hostname is not None and parsed.port is not None
        with socket.create_connection((parsed.hostname, parsed.port), timeout=1) as client:
            client.settimeout(1)
            for chunk in (
                b"G", b"E", b"T", b" ", b"/", b"v1", b"/health HTTP/1.1\r\nHost: localhost\r\n\r\n"
            ):
                time.sleep(0.1)
                try:
                    client.sendall(chunk)
                except OSError:
                    break
            try:
                response = client.recv(4096)
            except OSError:
                response = b""
            assert b" 200 " not in response


def test_control_service_idle_tls_client_does_not_block_listener(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cryptography = pytest.importorskip("cryptography")
    from datetime import datetime, timedelta, timezone

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    del cryptography
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.now(timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(hours=1))
        .sign(key, hashes.SHA256())
    )
    cert_path = tmp_path / "cert.pem"
    key_path = tmp_path / "key.pem"
    cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    key_path.chmod(0o600)
    monkeypatch.setattr(service_module, "REQUEST_READ_TIMEOUT_SECONDS", 5.0)
    config = ServiceConfig(host="127.0.0.1", tls_cert=cert_path, tls_key=key_path)
    idle: socket.socket | None = None
    try:
        with serve_control(ControlStore(tmp_path / "control"), config) as base:
            parsed = urlsplit(base)
            assert parsed.hostname is not None and parsed.port is not None
            idle = socket.create_connection((parsed.hostname, parsed.port), timeout=1)
            time.sleep(0.05)
            context = ssl._create_unverified_context()
            with urllib.request.urlopen(base + "/v1/health", timeout=1.0, context=context) as response:
                assert response.status == 200
                assert json.loads(response.read())["status"] == "ok"
        idle.settimeout(0.2)
        try:
            response = idle.recv(1)
        except (ConnectionAbortedError, ConnectionResetError):
            pass
        else:
            assert response == b""
    finally:
        if idle is not None:
            idle.close()


def test_non_loopback_requires_tls() -> None:
    with pytest.raises(ContractError, match="require TLS"):
        validate_service_config(ServiceConfig(host="0.0.0.0", port=8443))


def test_localhost_service_binds_literal_loopback_address(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bound: list[tuple[str, int]] = []
    real_server = service_module.ThreadingHTTPServer

    def record_bind(address, handler):  # noqa: ANN001
        bound.append(address)
        return real_server(address, handler)

    monkeypatch.setattr(service_module, "ThreadingHTTPServer", record_bind)
    with serve_control(ControlStore(tmp_path), ServiceConfig(host="localhost")) as base:
        assert bound[0][0] == "127.0.0.1"
        assert base.startswith("http://127.0.0.1:")


def test_control_service_rejects_invalid_store_before_listener_contact(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    contacted: list[bool] = []
    monkeypatch.setattr(
        service_module,
        "ThreadingHTTPServer",
        lambda *_args, **_kwargs: contacted.append(True),
    )

    with pytest.raises(ContractError, match="store is invalid"):
        with serve_control(object()):  # type: ignore[arg-type]
            pytest.fail("invalid store reached the service body")

    assert contacted == []


def test_control_service_closes_listener_when_thread_construction_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    holder: dict[str, object] = {}

    class Server:
        server_port = 8123

        def __init__(self, _address, _handler):  # noqa: ANN001
            holder["server"] = self
            self.closed = False
            self.shutdown_called = False

        def serve_forever(self) -> None:
            return

        def shutdown(self) -> None:
            self.shutdown_called = True

        def server_close(self) -> None:
            self.closed = True

    monkeypatch.setattr(service_module, "ThreadingHTTPServer", Server)

    def reject_thread(**_kwargs):  # noqa: ANN003
        raise RuntimeError("private thread constructor")

    monkeypatch.setattr(service_module.threading, "Thread", reject_thread)
    store = ControlStore(tmp_path / "control")

    with pytest.raises(
        ContractError,
        match=r"could not start \(RuntimeError\)",
    ) as raised:
        with serve_control(store):
            pytest.fail("failed thread construction reached the service body")

    server = holder["server"]
    assert server.closed is True
    assert server.shutdown_called is False
    assert "private thread constructor" not in str(raised.value)


def test_control_service_closes_listener_when_thread_start_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    holder: dict[str, object] = {}

    class Server:
        server_port = 8123

        def __init__(self, _address, _handler):  # noqa: ANN001
            holder["server"] = self
            self.closed = False
            self.shutdown_called = False

        def serve_forever(self) -> None:
            return

        def shutdown(self) -> None:
            self.shutdown_called = True

        def server_close(self) -> None:
            self.closed = True

    class Worker:
        def start(self) -> None:
            raise OSError("private thread start")

    monkeypatch.setattr(service_module, "ThreadingHTTPServer", Server)
    monkeypatch.setattr(
        service_module.threading,
        "Thread",
        lambda **_kwargs: Worker(),
    )
    store = ControlStore(tmp_path / "control")

    with pytest.raises(
        ContractError,
        match=r"could not start \(OSError\)",
    ) as raised:
        with serve_control(store):
            pytest.fail("failed thread start reached the service body")

    server = holder["server"]
    assert server.closed is True
    assert server.shutdown_called is False
    assert "private thread start" not in str(raised.value)


def test_control_service_stops_worker_when_start_raises_after_launch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    holder: dict[str, object] = {}

    class Server:
        server_port = 8123

        def __init__(self, _address, _handler):  # noqa: ANN001
            holder["server"] = self
            self.phases: list[str] = []

        def serve_forever(self) -> None:
            return

        def shutdown(self) -> None:
            self.phases.append("shutdown")

        def server_close(self) -> None:
            self.phases.append("close")

    class Worker:
        alive = False

        def start(self) -> None:
            self.alive = True
            raise OSError("private post-start failure")

        def is_alive(self) -> bool:
            return self.alive

        def join(self, *, timeout: float) -> None:
            assert timeout == service_module.CONTROL_SERVICE_CLEANUP_TIMEOUT_SECONDS
            holder["server"].phases.append("join")
            self.alive = False

    real_thread = threading.Thread

    def make_thread(*, name, **kwargs):
        if name == "browser-core-control":
            return Worker()
        return real_thread(name=name, **kwargs)

    monkeypatch.setattr(service_module, "ThreadingHTTPServer", Server)
    monkeypatch.setattr(service_module.threading, "Thread", make_thread)
    with pytest.raises(ContractError, match=r"could not start \(OSError\)") as raised:
        with serve_control(ControlStore(tmp_path / "control")):
            pytest.fail("failed startup reached the service body")
    assert holder["server"].phases == ["shutdown", "close", "join"]
    assert "private" not in str(raised.value)


def test_control_service_cleanup_attempts_every_phase_after_failures() -> None:
    class Server:
        def shutdown(self) -> None:
            raise RuntimeError("private shutdown")

        def server_close(self) -> None:
            raise OSError("private close")

    class Worker:
        def is_alive(self) -> bool:
            return True

        def join(self, *, timeout: float) -> None:
            assert timeout == service_module.CONTROL_SERVICE_CLEANUP_TIMEOUT_SECONDS
            raise RuntimeError("private join")

    failures = service_module._stop_control_server(
        Server(),
        Worker(),
        thread_started=True,
    )

    assert failures == ["server-shutdown", "server-close", "worker-thread"]


def test_control_service_shutdown_is_bounded_and_still_closes_and_joins(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    release = threading.Event()

    class Server:
        closed = False

        def shutdown(self) -> None:
            release.wait(5)

        def server_close(self) -> None:
            self.closed = True
            release.set()

    class Worker:
        joined = False

        def is_alive(self) -> bool:
            return not self.joined

        def join(self, *, timeout: float) -> None:
            self.joined = True

    server = Server()
    worker = Worker()
    monkeypatch.setattr(
        service_module,
        "CONTROL_SERVICE_CLEANUP_TIMEOUT_SECONDS",
        0.01,
    )
    started = time.monotonic()

    failures = service_module._stop_control_server(
        server,
        worker,
        thread_started=True,
    )

    assert time.monotonic() - started < 0.5
    assert failures == ["server-shutdown"]
    assert server.closed is True
    assert worker.joined is True


def test_control_service_reclaims_shutdown_thread_after_late_start_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    release = threading.Event()
    threads: list[object] = []
    real_thread = threading.Thread

    class Server:
        closed = False

        def shutdown(self) -> None:
            release.wait(1)

        def server_close(self) -> None:
            self.closed = True
            release.set()

    class ShutdownThread:
        joined = False

        def __init__(self, *, target, name, daemon):  # noqa: ANN001
            self.worker = real_thread(target=target, name=name, daemon=daemon)
            threads.append(self)

        def start(self) -> None:
            self.worker.start()
            raise RuntimeError("late start error")

        def is_alive(self) -> bool:
            return self.worker.is_alive()

        def join(self, *, timeout: float) -> None:
            self.joined = True
            self.worker.join(timeout=timeout)

    class Worker:
        joined = False

        def is_alive(self) -> bool:
            return not self.joined

        def join(self, *, timeout: float) -> None:
            self.joined = True

    monkeypatch.setattr(service_module.threading, "Thread", ShutdownThread)
    monkeypatch.setattr(service_module, "CONTROL_SERVICE_CLEANUP_TIMEOUT_SECONDS", 0.1)
    server = Server()
    worker = Worker()
    failures = service_module._stop_control_server(server, worker, thread_started=True)

    assert failures == ["server-shutdown"]
    assert server.closed is True
    assert worker.joined is True
    assert threads[0].joined is True
    assert threads[0].is_alive() is False


def test_control_service_cleanup_failure_overrides_body_only_after_all_phases(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    phases: list[str] = []

    class Server:
        server_port = 8123

        def __init__(self, _address, _handler):  # noqa: ANN001
            return

        def serve_forever(self) -> None:
            return

    class Worker:
        def start(self) -> None:
            return

        def is_alive(self) -> bool:
            return True

    def cleanup(_server, _thread, *, thread_started):  # noqa: ANN001
        assert thread_started is True
        phases.extend(["server-shutdown", "server-close", "worker-thread"])
        return list(phases)

    monkeypatch.setattr(service_module, "ThreadingHTTPServer", Server)
    monkeypatch.setattr(
        service_module.threading,
        "Thread",
        lambda **_kwargs: Worker(),
    )
    monkeypatch.setattr(service_module, "_stop_control_server", cleanup)
    store = ControlStore(tmp_path / "control")

    with pytest.raises(
        ContractError,
        match=r"cleanup failed \(server-shutdown,server-close,worker-thread\)",
    ) as raised:
        with serve_control(store):
            raise RuntimeError("private body failure")

    assert phases == ["server-shutdown", "server-close", "worker-thread"]
    assert isinstance(raised.value.__cause__, RuntimeError)
    assert "private body failure" not in str(raised.value)


@pytest.mark.parametrize("host", ["", "bad host", "http://127.0.0.1", "a/b"])
def test_service_config_rejects_malformed_hosts(host: str) -> None:
    with pytest.raises(ContractError, match="host"):
        validate_service_config(ServiceConfig(host=host))


def test_service_config_requires_exact_tls_paths_before_binding(tmp_path: Path) -> None:
    with pytest.raises(ContractError, match="must be Paths"):
        validate_service_config(
            ServiceConfig(
                host="0.0.0.0",
                port=8443,
                tls_cert=str(tmp_path / "cert.pem"),  # type: ignore[arg-type]
                tls_key=str(tmp_path / "key.pem"),  # type: ignore[arg-type]
            )
        )


def test_service_config_bounds_and_refuses_linked_tls_credentials(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cert = tmp_path / "cert.pem"
    key = tmp_path / "key.pem"
    cert.write_bytes(b"cert")
    key.write_bytes(b"key")
    key.chmod(0o600)
    monkeypatch.setattr(service_module, "MAX_TLS_CREDENTIAL_BYTES", 3)

    with pytest.raises(ContractError, match="exceeds"):
        validate_service_config(
            ServiceConfig(host="0.0.0.0", port=8443, tls_cert=cert, tls_key=key)
        )

    monkeypatch.setattr(service_module, "MAX_TLS_CREDENTIAL_BYTES", 1024)
    alias = tmp_path / "key-alias.pem"
    try:
        alias.hardlink_to(key)
    except OSError as exc:
        pytest.skip(f"hard links unavailable: {type(exc).__name__}")
    with pytest.raises(ContractError, match="hard links"):
        validate_service_config(
            ServiceConfig(host="0.0.0.0", port=8443, tls_cert=cert, tls_key=key)
        )


def test_authenticated_record_artifact_and_audit_roundtrip(tmp_path: Path) -> None:
    store, owner_token, viewer_token, _ = setup_store(tmp_path)
    with serve_control(store) as base:
        status, headers, payload = request(base + "/v1/health")
        assert status == 200 and json.loads(payload)["status"] == "ok"
        assert (
            headers["Cache-Control"] == "no-store"
            and headers["X-Frame-Options"] == "DENY"
        )
        status, _, payload = request(
            base + "/v1/workspaces/lab/records/persona/core",
            "PUT",
            token=owner_token,
            body={"expected_revision": 0, "payload": {"sha256": "abc"}},
        )
        assert status == 200 and json.loads(payload)["revision"] == 1
        status, _, payload = request(
            base + "/v1/workspaces/lab/records/persona/core", token=viewer_token
        )
        assert json.loads(payload)["payload"] == {"sha256": "abc"}
        with pytest.raises(urllib.error.HTTPError) as denied:
            request(
                base + "/v1/workspaces/lab/records/persona/core",
                "PUT",
                token=viewer_token,
                body={"expected_revision": 1, "payload": {"sha256": "def"}},
            )
        try:
            assert denied.value.code == 403
        finally:
            denied.value.close()
        status, _, payload = request(
            base + "/v1/workspaces/lab/artifacts",
            "PUT",
            token=owner_token,
            body=b'{"schema":"browser-core.shared-evidence/1","verdict":"pass"}',
            headers={
                "X-Artifact-Visibility": "viewer",
                "X-Artifact-Media-Type": "application/json",
            },
        )
        digest = json.loads(payload)["sha256"]
        status, _, payload = request(
            base + f"/v1/workspaces/lab/artifacts/{digest}", token=viewer_token
        )
        assert (
            payload == b'{"schema":"browser-core.shared-evidence/1","verdict":"pass"}'
        )
        status, _, payload = request(
            base + "/v1/workspaces/lab/audit/verify", token=viewer_token
        )
        assert json.loads(payload)["valid"] is True


def test_remote_worker_lease_and_completion_over_api(tmp_path: Path) -> None:
    store, owner_token, _, worker_token = setup_store(tmp_path)
    with serve_control(store) as base:
        status, _, payload = request(
            base + "/v1/workspaces/lab/jobs",
            "POST",
            token=owner_token,
            body={
                "kind": "browser-eval",
                "payload": {"evaluators": ["controlled_coherence"]},
                "requirements": ["chromium"],
                "idempotency_key": "api-job",
            },
        )
        job_id = json.loads(payload)["id"]
        status, _, payload = request(
            base + "/v1/workers/lease",
            "POST",
            token=worker_token,
            body={"lease_seconds": 30},
        )
        lease = json.loads(payload)
        assert lease["id"] == job_id and lease["payload"] == {
            "evaluators": ["controlled_coherence"]
        }
        status, _, payload = request(
            base + f"/v1/workers/jobs/{job_id}/heartbeat",
            "POST",
            token=worker_token,
            body={"lease_token": lease["lease_token"], "extend_seconds": 60},
        )
        assert json.loads(payload)["job_id"] == job_id
        status, _, payload = request(
            base + f"/v1/workers/jobs/{job_id}/complete",
            "POST",
            token=worker_token,
            body={
                "lease_token": lease["lease_token"],
                "succeeded": True,
                "result": {"passed": True},
            },
        )
        assert json.loads(payload)["state"] == "succeeded"
        status, _, payload = request(
            base + "/v1/workspaces/lab/fleet", token=owner_token
        )
        assert json.loads(payload)["jobs"]["succeeded"] == 1


def test_api_never_accepts_arbitrary_shell_job(tmp_path: Path) -> None:
    store, owner_token, _, _ = setup_store(tmp_path)
    with serve_control(store) as base:
        with pytest.raises(urllib.error.HTTPError) as denied:
            request(
                base + "/v1/workspaces/lab/jobs",
                "POST",
                token=owner_token,
                body={
                    "kind": "shell",
                    "payload": {"argv": ["whoami"]},
                    "requirements": [],
                    "idempotency_key": "bad",
                },
            )
        try:
            assert denied.value.code == 400
        finally:
            denied.value.close()


def test_api_rejects_list_job_kind_as_bad_request(tmp_path: Path) -> None:
    store, owner_token, _, _ = setup_store(tmp_path)
    with serve_control(store) as base:
        with pytest.raises(urllib.error.HTTPError) as denied:
            request(
                base + "/v1/workspaces/lab/jobs",
                "POST",
                token=owner_token,
                body={
                    "kind": [],
                    "payload": {},
                    "requirements": [],
                    "idempotency_key": "bad-kind-type",
                },
            )
        try:
            assert denied.value.code == 400
            assert json.load(denied.value)["error"] == "request_rejected"
        finally:
            denied.value.close()


def test_service_rejects_ambiguous_or_encoded_request_framing(tmp_path: Path) -> None:
    store, _owner, _viewer, worker = setup_store(tmp_path)
    requests = [
        (
            b"POST /v1/workers/lease HTTP/1.1\r\nHost: localhost\r\n"
            + f"Authorization: Bearer {worker}\r\n".encode()
            + b"Content-Type: application/json\r\nContent-Length: 2\r\n"
            + b"Content-Length: 2\r\nConnection: close\r\n\r\n{}"
        ),
        (
            b"POST /v1/workers/lease HTTP/1.1\r\nHost: localhost\r\n"
            + f"Authorization: Bearer {worker}\r\n".encode()
            + b"Content-Type: application/json\r\nContent-Length: 2\r\n"
            + b"Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n{}"
        ),
        (
            b"POST /v1/workers/lease HTTP/1.1\r\nHost: localhost\r\n"
            + f"Authorization: Bearer {worker}\r\n".encode()
            + b"Content-Type: application/json\r\nContent-Length: 02\r\n"
            + b"Connection: close\r\n\r\n{}"
        ),
        (
            b"POST /v1/workers/lease HTTP/1.1\r\nHost: localhost\r\n"
            + f"Authorization: Bearer {worker}\r\n".encode()
            + b"Content-Type: application/json\r\nContent-Length: "
            + b"9" * 5000
            + b"\r\nConnection: close\r\n\r\n{}"
        ),
    ]
    with serve_control(store) as base:
        for body in requests:
            status, response = raw_request(base, body)
            assert status == 400
            assert json.loads(response)["error"] == "request_rejected"


def test_service_rejects_incomplete_declared_body(tmp_path: Path) -> None:
    store, _owner, _viewer, worker = setup_store(tmp_path)
    request_bytes = (
        b"POST /v1/workers/lease HTTP/1.1\r\nHost: localhost\r\n"
        + f"Authorization: Bearer {worker}\r\n".encode()
        + b"Content-Type: application/json\r\nContent-Length: 10\r\n"
        + b"Connection: close\r\n\r\n{}"
    )
    with serve_control(store) as base:
        status, response = raw_request(base, request_bytes)
    assert status == 400
    rejection = json.loads(response)
    assert rejection["message"] == "request contract rejected"
    assert len(rejection["diagnostic_sha256_16"]) == 16


@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("PUT", "/v1/workspaces/lab/records/persona/core"),
        ("POST", "/v1/workspaces/lab/jobs"),
        ("POST", "/v1/workspaces/lab/jobs/job-one/cancel"),
        ("POST", "/v1/workspaces/lab/tokens/token-one/revoke"),
        ("POST", "/v1/workers/lease"),
        ("POST", "/v1/workers/jobs/job-one/heartbeat"),
        ("POST", "/v1/workers/jobs/job-one/complete"),
    ],
)
def test_mutating_service_routes_authenticate_before_reading_body(
    tmp_path: Path, method: str, path: str
) -> None:
    store, _owner, _viewer, _worker = setup_store(tmp_path)
    request_bytes = (
        f"{method} {path} HTTP/1.1\r\n".encode()
        + b"Host: localhost\r\nContent-Type: application/json\r\n"
        + b"Content-Length: 10\r\nConnection: close\r\n\r\n{}"
    )
    with serve_control(store) as base:
        status, response = raw_request(base, request_bytes)
    assert status == 401
    assert json.loads(response)["message"] == "authentication rejected"


def test_scoped_token_wrong_workspace_is_authorization_failure(tmp_path: Path) -> None:
    store, owner_token, viewer_token, _worker = setup_store(tmp_path)
    owner = store.authenticate(owner_token)
    store.create_workspace(owner, workspace_id="other", name="Other")
    store.add_member(owner, "other", user_id="eve", display_name="Eve", role="viewer")

    with serve_control(store) as base:
        with pytest.raises(urllib.error.HTTPError) as denied:
            request(f"{base}/v1/workspaces/other/fleet", token=viewer_token)
        try:
            response = json.loads(denied.value.read())
        finally:
            denied.value.close()

    assert denied.value.code == 403
    assert response["message"] == "authorization role rejected"


def test_service_normalizes_non_utf8_contract_diagnostic(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store, owner_token, _viewer, _worker = setup_store(tmp_path)

    def reject(*_args, **_kwargs):
        raise ContractError("\ud800")

    monkeypatch.setattr(store, "fleet_status", reject)
    with serve_control(store) as base:
        with pytest.raises(urllib.error.HTTPError) as raised:
            request(f"{base}/v1/workspaces/lab/fleet", token=owner_token)
        try:
            rejection = json.loads(raised.value.read())
        finally:
            raised.value.close()

    assert raised.value.code == 400
    assert rejection["error"] == "request_rejected"
    assert rejection["message"] == "request contract rejected"
    assert len(rejection["diagnostic_sha256_16"]) == 16
    assert "\\ud800" not in json.dumps(rejection)


@pytest.mark.parametrize(
    "body",
    [
        b'{"lease_seconds":30,"lease_seconds":31}',
        b'{"lease_seconds":NaN}',
        b'{"lease_seconds":1e400}',
        b'{"lease_seconds":30,"private_marker":"secret"}',
    ],
)
def test_service_rejects_non_strict_or_unknown_json_fields(
    tmp_path: Path,
    body: bytes,
) -> None:
    store, _owner, _viewer, worker = setup_store(tmp_path)
    request_bytes = (
        b"POST /v1/workers/lease HTTP/1.1\r\nHost: localhost\r\n"
        + f"Authorization: Bearer {worker}\r\n".encode()
        + b"Content-Type: application/json\r\n"
        + f"Content-Length: {len(body)}\r\n".encode()
        + b"Connection: close\r\n\r\n"
        + body
    )
    with serve_control(store) as base:
        status, response = raw_request(base, request_bytes)
    assert status == 400
    assert b"secret" not in response


def test_service_rejects_duplicate_authorization_and_unsafe_targets(
    tmp_path: Path,
) -> None:
    store, owner, _viewer, _worker = setup_store(tmp_path)
    duplicate_auth = (
        b"GET /v1/workspaces/lab/fleet HTTP/1.1\r\nHost: localhost\r\n"
        + f"Authorization: Bearer {owner}\r\n".encode()
        + f"Authorization: Bearer {owner}\r\n".encode()
        + b"Connection: close\r\n\r\n"
    )
    targets = [
        b"http://example.invalid/v1/health",
        b"http://[bad",
        b"/v1/workspaces/lab%2Fother/fleet",
        b"/v1//health",
        b"/v1/health?",
        b"/v1/health#",
    ]
    with serve_control(store) as base:
        status, _response = raw_request(base, duplicate_auth)
        assert status == 401
        for target in targets:
            status, _response = raw_request(
                base,
                b"GET "
                + target
                + b" HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
            )
            assert status == 400


def test_control_service_body_read_has_total_deadline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    elapsed = [0.0]
    monkeypatch.setattr(
        service_module, "time", SimpleNamespace(monotonic=lambda: elapsed[0]),
        raising=False,
    )
    monkeypatch.setattr(service_module, "REQUEST_READ_TIMEOUT_SECONDS", 0.1)

    class Connection:
        timeout = None

        def gettimeout(self):
            return self.timeout

        def settimeout(self, value):
            self.timeout = value

    class Body:
        chunks = [b"ab", b"cd"]

        def read(self, _size):
            elapsed[0] += 0.2
            return b"abcd"

        def read1(self, _size):
            elapsed[0] += 0.06
            return self.chunks.pop(0)

    handler_class = service_module._handler_class(object())
    handler = handler_class.__new__(handler_class)
    handler.headers = Message()
    handler.headers["Content-Length"] = "4"
    handler.connection = Connection()
    handler.rfile = Body()

    with pytest.raises(ContractError, match="body read"):
        handler._read(8)
    assert handler.connection.timeout is None


def test_service_normalizes_unexpected_internal_failures_without_disclosure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store, owner, _viewer, _worker = setup_store(tmp_path)
    marker = r"C:\private\tenant\secret-token"

    def fail(*_args: object, **_kwargs: object) -> None:
        raise RuntimeError(marker)

    monkeypatch.setattr(store, "fleet_status", fail)
    request_bytes = (
        b"GET /v1/workspaces/lab/fleet HTTP/1.1\r\nHost: localhost\r\n"
        + f"Authorization: Bearer {owner}\r\n".encode()
        + b"Connection: close\r\n\r\n"
    )

    with serve_control(store) as base:
        status, response = raw_request(base, request_bytes)

    assert status == 500
    assert marker.encode() not in response
    assert json.loads(response)["message"] == "control service request failed"


def test_shipped_clients_complete_multi_role_collaboration_and_remote_worker(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    store, owner_token, viewer_token, worker_token = setup_store(tmp_path)
    with serve_control(store) as base:
        owner = ControlClient(base, owner_token)
        viewer = ControlClient(base, viewer_token)
        worker = ControlClient(base, worker_token)
        assert owner.health()["status"] == "ok"
        created = owner.put_record(
            "lab", "persona", "owned", {"digest": "abc"}, expected_revision=0
        )
        assert created["revision"] == 1
        assert viewer.get_record("lab", "persona", "owned")["payload"] == {
            "digest": "abc"
        }
        with pytest.raises(ContractError, match="HTTP 403"):
            viewer.put_record(
                "lab", "persona", "owned", {"digest": "def"}, expected_revision=1
            )
        shared_evidence = (
            b'{"schema":"browser-core.shared-evidence/1","verdict":"pass"}'
        )
        artifact = owner.put_artifact(
            "lab", shared_evidence, media_type="application/json", visibility="viewer"
        )
        assert viewer.get_artifact("lab", artifact["sha256"]) == shared_evidence
        job = owner.enqueue_job(
            "lab",
            kind="kernel-probe",
            payload={"owned": True},
            requirements=["chromium"],
            idempotency_key="remote-client-job",
        )
        monkeypatch.setattr(
            "browser_core.worker.execute_typed_job",
            lambda job, repository_root, workspace: {
                "schema": "owned-remote-result/1",
                "job_id": job["id"],
            },
        )
        completed = run_remote_worker_once(
            worker,
            repository_root=Path(__file__).resolve().parents[1],
            workspace=tmp_path,
            lease_seconds=30,
        )
        assert (
            completed
            and completed["id"] == job["id"]
            and completed["state"] == "succeeded"
        )
        assert owner.fleet_status("lab")["jobs"]["succeeded"] == 1
        assert [item["id"] for item in viewer.list_jobs("lab")["jobs"]] == [job["id"]]
        viewer_job = viewer.get_job("lab", job["id"])
        owner_job = owner.get_job("lab", job["id"])
        assert (
            viewer_job["result_sha256"]
            and "payload" not in viewer_job
            and "result" not in viewer_job
        )
        assert owner_job["payload"] == {"owned": True}
        assert owner_job["result"]["schema"] == "owned-remote-result/1"
        assert viewer.verify_audit("lab")["valid"] is True
        assert owner_token not in repr(owner) and worker_token not in repr(worker)


def test_client_accepts_service_permitted_large_job_list(tmp_path: Path) -> None:
    store = ControlStore(tmp_path)
    bootstrap = store.bootstrap(
        workspace_id="lab", workspace_name="Lab", owner_id="alice",
        owner_name="Alice", max_queued=50,
    )
    principal = store.authenticate(bootstrap["token"])
    requirements = [f"cap-{index:04d}" for index in range(5000)]
    for index in range(40):
        store.enqueue_job(
            principal, "lab", kind="native-smoke", payload={},
            requirements=requirements, idempotency_key=f"large-list-{index}",
        )
    permitted = store.list_jobs(principal, "lab")
    body = json.dumps(permitted, sort_keys=True, separators=(",", ":")).encode()
    assert 2 * 1024 * 1024 < len(body) < service_module.MAX_JSON_RESPONSE

    with serve_control(store) as base:
        result = ControlClient(base, bootstrap["token"]).list_jobs("lab")
    assert len(result["jobs"]) == 40
    assert result["jobs_truncated"] is False


def test_control_client_rejects_corrupt_artifact_download(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    expected_digest = hashlib.sha256(b"expected").hexdigest()
    monkeypatch.setattr(ControlClient, "_request", lambda *_args, **_kwargs: b"other")

    with pytest.raises(ContractError, match="artifact content integrity"):
        ControlClient("http://127.0.0.1:8766", "token").get_artifact(
            "lab", expected_digest
        )


def test_control_client_rejects_forged_artifact_upload_receipt(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    content = b"expected"
    monkeypatch.setattr(
        ControlClient,
        "_request",
        lambda *_args, **_kwargs: {
            "sha256": "0" * 64,
            "size": len(content),
            "media_type": "application/octet-stream",
            "visibility": "operator",
        },
    )

    with pytest.raises(ContractError, match="artifact receipt integrity"):
        ControlClient("http://127.0.0.1:8766", "token").put_artifact(
            "lab", content
        )


def test_control_client_rejects_plaintext_remote_origins() -> None:
    with pytest.raises(ContractError, match="HTTPS"):
        ControlClient("http://192.0.2.10:8766", "opaque-token")


def test_loopback_control_client_ignores_configured_http_proxy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    proxy_requests: list[str | None] = []

    class TrapProxy(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            proxy_requests.append(self.headers.get("Authorization"))
            self.send_response(200)
            self.send_header("Content-Length", "3")
            self.end_headers()
            self.wfile.write(b"{}\n")

        def log_message(self, *_args: object) -> None:
            pass

    proxy = ThreadingHTTPServer(("127.0.0.1", 0), TrapProxy)
    worker = threading.Thread(target=proxy.serve_forever, daemon=True)
    worker.start()
    try:
        monkeypatch.setattr(
            urllib.request,
            "getproxies",
            lambda: {"http": f"http://127.0.0.1:{proxy.server_port}"},
        )
        monkeypatch.setattr(urllib.request, "proxy_bypass", lambda _host: False)
        with pytest.raises(ContractError, match="unreachable"):
            ControlClient("http://127.0.0.1:1", "private-token").health()
        assert proxy_requests == []
    finally:
        proxy.shutdown()
        proxy.server_close()
        worker.join(timeout=2)


def test_control_service_serves_ipv6_loopback_when_available(tmp_path: Path) -> None:
    try:
        with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as probe:
            probe.bind(("::1", 0))
    except OSError:
        pytest.skip("IPv6 loopback is unavailable")

    store, _owner_token, _viewer_token, _worker_token = setup_store(tmp_path)
    idle: socket.socket | None = None
    try:
        with serve_control(store, ServiceConfig(host="::1")) as base:
            status, _headers, body = request(f"{base}/v1/health")
            parsed = urlsplit(base)
            assert parsed.hostname == "::1" and parsed.port is not None
            idle = socket.create_connection((parsed.hostname, parsed.port), timeout=1)
            idle.sendall(b"GET /v1/health HTTP/1.1\r\nHost: localhost\r\n")
            time.sleep(0.05)
        idle.settimeout(0.2)
        try:
            response = idle.recv(1)
        except (ConnectionAbortedError, ConnectionResetError):
            pass
        else:
            assert response == b""
    finally:
        if idle is not None:
            idle.close()
    assert status == 200
    assert json.loads(body)["status"] == "ok"


def test_control_client_does_not_forward_bearer_token_on_redirect() -> None:
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    target_authorizations: list[str | None] = []

    class Target(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            target_authorizations.append(self.headers.get("Authorization"))
            self.send_response(200)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"{}")

        def log_message(self, *_args: object) -> None:
            pass

    target = ThreadingHTTPServer(("127.0.0.1", 0), Target)

    class Redirect(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            assert self.headers.get("Authorization") == "Bearer opaque-token"
            self.send_response(302)
            self.send_header("Location", f"http://127.0.0.1:{target.server_port}/collect")
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, *_args: object) -> None:
            pass

    source = ThreadingHTTPServer(("127.0.0.1", 0), Redirect)
    threads = [
        threading.Thread(target=server.serve_forever, daemon=True)
        for server in (source, target)
    ]
    try:
        for thread in threads:
            thread.start()
        client = ControlClient(f"http://127.0.0.1:{source.server_port}", "opaque-token")
        with pytest.raises(ContractError, match="HTTP 302"):
            client.get_record("lab", "persona", "owned")
        assert target_authorizations == []
    finally:
        for server in (source, target):
            server.shutdown()
            server.server_close()
        for thread in threads:
            thread.join(timeout=5)


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1:bad",
        "http://user@127.0.0.1:8766",
        "http://@127.0.0.1:8766",
        "http://127.0.0.1:8766/path",
        "http://127.0.0.1:8766/?query=1",
        "http://127.0.0.1:8766?",
        "http://127.0.0.1:8766#",
        "http://127.0.0.1:8766/?",
        "http://127.0.0.1:8766\n",
        "https://snowman-☃.example:443",
        "https://2130706433:443",
        "https://127.1:443",
        "https://0x7f000001:443",
        "https://example.42:443",
        "https://safe.example\\evil:443",
        "https://sa%66e.example:443",
        "http://127.0.0.1:0",
        "https://example.com:0",
    ],
)
def test_control_client_rejects_malformed_origins(url: str) -> None:
    with pytest.raises(ContractError, match="URL"):
        ControlClient(url, "opaque-token")


def test_plain_http_localhost_client_uses_literal_loopback() -> None:
    local = ControlClient("http://localhost:8766", "opaque-token")
    assert local.base_url == "http://127.0.0.1:8766"
    tls = ControlClient("https://localhost:8766", "opaque-token")
    assert tls.base_url == "https://localhost:8766"


@pytest.mark.parametrize("host", ["localhost", "example.com", "127.0.0.2"])
def test_control_request_helper_rejects_plain_http_hostname_before_contact(
    monkeypatch: pytest.MonkeyPatch,
    host: str,
) -> None:
    monkeypatch.setattr(
        client_module.urllib.request,
        "build_opener",
        lambda *_args: pytest.fail("hostname reached transport construction"),
    )
    request_object = urllib.request.Request(f"http://{host}:8766/v1/health")
    with pytest.raises(ContractError, match="literal loopback"):
        client_module._open_control_request(request_object, timeout=1)


@pytest.mark.parametrize(
    "timeout", [0, True, float("nan"), float("inf"), 301, 10**400]
)
def test_control_client_rejects_invalid_timeouts(timeout) -> None:
    with pytest.raises(ContractError, match="timeout"):
        ControlClient(
            "http://127.0.0.1:8766",
            "opaque-token",
            timeout_seconds=timeout,
        )


def test_control_client_rejects_malformed_requests_before_network_contact(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    contacted = False

    def contact(*_args: object, **_kwargs: object) -> None:
        nonlocal contacted
        contacted = True
        raise AssertionError("invalid client request reached the network")

    monkeypatch.setattr(client_module, "_open_control_request", contact)
    client = ControlClient("http://127.0.0.1:8766", "opaque-token")

    with pytest.raises(ContractError, match="strict JSON"):
        client._request("POST", "/v1/workers/lease", json_body={"value": float("nan")})
    with pytest.raises(ContractError, match="strict JSON"):
        client._request("POST", "/v1/workers/lease", json_body={"value": "\ud800"})
    moderately_nested: object = 0
    for _ in range(130):
        moderately_nested = [moderately_nested]
    with pytest.raises(ContractError, match="strict JSON"):
        client._request("POST", "/v1/workers/lease", json_body={"value": moderately_nested})
    deeply_nested: object = 0
    for _ in range(2_000):
        deeply_nested = [deeply_nested]
    with pytest.raises(ContractError, match="strict JSON"):
        client._request(
            "POST",
            "/v1/workers/lease",
            json_body={"value": deeply_nested},
        )
    with pytest.raises(ContractError, match="headers"):
        client._request(
            "POST",
            "/v1/workers/lease",
            json_body={},
            headers={"X-Test": "value\r\nInjected: yes"},
        )
    with pytest.raises(ContractError, match="resource ID"):
        client.get_record("lab/other", "persona", "id")
    with pytest.raises(ContractError, match="response limit"):
        client._request("GET", "/v1/health", maximum=True)

    assert contacted is False


@pytest.mark.parametrize(
    ("method", "path", "headers", "message"),
    [
        ([], "/v1/health", None, "method"),
        ("GET", "/v1/" + chr(0xD800), None, "path"),
        ("GET", "/v1/health", {"X-Test": "value\tprivate"}, "headers"),
        ("GET", "/v1/health", {"X-Test": "snowman-☃"}, "headers"),
    ],
)
def test_control_client_request_metadata_is_closed_before_network_contact(
    monkeypatch: pytest.MonkeyPatch,
    method: object,
    path: str,
    headers: dict[str, str] | None,
    message: str,
) -> None:
    monkeypatch.setattr(
        client_module,
        "_open_control_request",
        lambda *_args, **_kwargs: pytest.fail("invalid metadata reached network"),
    )
    client = ControlClient("http://127.0.0.1:8766", "opaque-token")

    with pytest.raises(ContractError, match=message):
        client._request(method, path, headers=headers)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "header",
    [
        "Host",
        "Content-Length",
        "Transfer-Encoding",
        "Authorization",
        "Accept",
        "content-type",
    ],
)
def test_control_client_rejects_caller_transport_headers_before_contact(
    monkeypatch: pytest.MonkeyPatch, header: str
) -> None:
    monkeypatch.setattr(
        client_module,
        "_open_control_request",
        lambda *_args, **_kwargs: pytest.fail("caller header reached network"),
    )
    client = ControlClient("http://127.0.0.1:8766", "opaque-token")
    with pytest.raises(ContractError, match="headers are invalid"):
        client._request("POST", "/v1/health", raw_body=b"body", headers={header: "value"})


@pytest.mark.parametrize(
    ("method", "args", "kwargs", "message"),
    [
        (
            "put_record",
            ("lab", "persona", "owned", {}),
            {"expected_revision": True},
            "revision",
        ),
        ("worker_lease", (), {"lease_seconds": "30"}, "lease duration"),
        (
            "worker_heartbeat",
            ("job-one", ["private-token"]),
            {"extend_seconds": 60},
            "lease token",
        ),
        (
            "worker_heartbeat",
            ("job-one", "lease-token"),
            {"extend_seconds": True},
            "lease extension",
        ),
        (
            "worker_complete",
            ("job-one", "lease-token"),
            {"succeeded": 1, "result": {}},
            "success flag",
        ),
        (
            "worker_complete",
            ("job-one", "lease-token"),
            {"succeeded": True, "result": []},
            "result must be an object",
        ),
        (
            "put_artifact",
            ("lab", b"artifact"),
            {"visibility": ["viewer"]},
            "visibility",
        ),
        (
            "put_artifact",
            ("lab", b"artifact"),
            {"media_type": "text/plain private"},
            "media type",
        ),
    ],
)
def test_control_client_operation_intent_rejects_before_network_contact(
    monkeypatch: pytest.MonkeyPatch,
    method: str,
    args: tuple[object, ...],
    kwargs: dict[str, object],
    message: str,
) -> None:
    monkeypatch.setattr(
        client_module,
        "_open_control_request",
        lambda *_args, **_kwargs: pytest.fail("invalid operation reached network"),
    )
    client = ControlClient("http://127.0.0.1:8766", "opaque-token")

    with pytest.raises(ContractError, match=message):
        getattr(client, method)(*args, **kwargs)


def test_control_client_normalizes_private_request_constructor_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    private = "private-request-constructor-value"

    def fail_request(*_args: object, **_kwargs: object) -> None:
        raise ValueError(private)

    monkeypatch.setattr(client_module.urllib.request, "Request", fail_request)
    monkeypatch.setattr(
        client_module,
        "_open_control_request",
        lambda *_args, **_kwargs: pytest.fail("failed request reached network"),
    )

    with pytest.raises(ContractError) as captured:
        ControlClient("http://127.0.0.1:8766", None).health()

    assert (
        str(captured.value) == "control client request could not be built (ValueError)"
    )
    assert private not in str(captured.value)


class _Response(io.BytesIO):
    def __init__(self, body: bytes, lengths: list[str]) -> None:
        super().__init__(body)
        headers = Message()
        headers.add_header("Content-Type", "application/json")
        for length in lengths:
            headers.add_header("Content-Length", length)
        self.headers = headers

    def getcode(self) -> int:
        return 200

    def __enter__(self):  # type: ignore[no-untyped-def]
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()


@pytest.mark.parametrize("lengths", [[], ["6"]])
def test_control_response_reader_collects_fragmented_body(lengths: list[str]) -> None:
    class FragmentedResponse(_Response):
        def read1(self, size: int = -1) -> bytes:
            return super().read1(min(size, 2))

    response = FragmentedResponse(b"abcdef", lengths)
    assert client_module._read_control_response_payload(response, maximum=16) == b"abcdef"
    assert response.closed


def test_control_response_reader_rejects_adapter_over_return_before_collection() -> None:
    class OverReturnResponse(_Response):
        def read1(self, size: int = -1) -> bytes:
            return b"x" * (size + 1)

    response = OverReturnResponse(b"{}", [])
    with pytest.raises(ContractError, match="response body is invalid"):
        client_module._read_control_response_payload(response, maximum=4)
    assert response.closed


def test_control_client_rejects_transfer_encoded_response() -> None:
    response = _Response(b"{}", ["2"])
    response.headers.add_header("Transfer-Encoding", "chunked")
    with pytest.raises(ContractError, match="transfer encoding"):
        client_module._read_control_response_payload(response, maximum=16)
    assert response.closed


def test_control_client_rejects_encoded_artifact_response() -> None:
    response = _Response(b"compressed-bytes", ["16"])
    response.headers.add_header("Content-Encoding", "gzip")

    with pytest.raises(ContractError, match="content encoding"):
        client_module._read_control_response_payload(response, maximum=64)
    assert response.closed


def test_control_client_rejects_partial_success_status() -> None:
    class PartialResponse(_Response):
        def getcode(self) -> int:
            return 206

    response = PartialResponse(b"{}", ["2"])
    with pytest.raises(ContractError, match="status is invalid"):
        client_module._read_control_response_payload(response, maximum=16)
    assert response.closed


@pytest.mark.parametrize(
    ("content_types", "expect_json"),
    [
        ([], True),
        (["text/html"], True),
        (["application/json", "application/json"], True),
        (["application/json"], False),
    ],
)
def test_control_client_rejects_wrong_response_media_type(
    monkeypatch: pytest.MonkeyPatch,
    content_types: list[str],
    expect_json: bool,
) -> None:
    response = _Response(b"{}", ["2"])
    response.headers = Message()
    for content_type in content_types:
        response.headers.add_header("Content-Type", content_type)
    monkeypatch.setattr(
        client_module, "_open_control_request", lambda *_args, **_kwargs: response
    )

    with pytest.raises(ContractError, match="content type"):
        ControlClient("http://127.0.0.1:8766", None)._request(
            "GET", "/v1/health", expect_json=expect_json, authenticated=False
        )
    assert response.closed


def test_control_client_response_has_total_deadline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    elapsed = [0.0]
    monkeypatch.setattr(
        client_module, "time", SimpleNamespace(monotonic=lambda: elapsed[0]),
        raising=False,
    )

    class SlowResponse(_Response):
        def read(self, _size: int = -1) -> bytes:
            pytest.fail("blocking response read was used")

        def read1(self, size: int = -1) -> bytes:
            elapsed[0] += 0.06
            return super().read1(min(size, 1))

    response = SlowResponse(b"{}", ["2"])
    monkeypatch.setattr(
        client_module, "_open_control_request", lambda *_args, **_kwargs: response
    )
    client = ControlClient("http://127.0.0.1:8766", None, timeout_seconds=0.1)
    with pytest.raises(ContractError, match="deadline"):
        client._request("GET", "/v1/health", authenticated=False)
    assert response.closed


@pytest.mark.parametrize("status", [200, 503])
def test_control_client_live_response_read_uses_remaining_deadline(status: int) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        listener.settimeout(3)
        sent = threading.Event()
        body_sent = threading.Event()
        release = threading.Event()
        failures: list[BaseException] = []

        def serve() -> None:
            try:
                peer, _ = listener.accept()
                with peer:
                    peer.settimeout(3)
                    peer.recv(4096)
                    reason = b"OK" if status == 200 else b"Service Unavailable"
                    peer.sendall(
                        b"HTTP/1.1 "
                        + str(status).encode("ascii")
                        + b" "
                        + reason
                        + b"\r\nContent-Type: application/json\r\n"
                        b"Content-Length: 2\r\n\r\n"
                    )
                    sent.set()
                    if not release.wait(0.5):
                        peer.sendall(b"{")
                        body_sent.set()
                        release.wait(2)
            except BaseException as exc:
                failures.append(exc)

        worker = threading.Thread(target=serve, daemon=True)
        worker.start()
        start = time.monotonic()
        try:
            with pytest.raises(ContractError):
                ControlClient(
                    f"http://127.0.0.1:{listener.getsockname()[1]}",
                    None,
                    timeout_seconds=1.0,
                ).health()
            elapsed = time.monotonic() - start
        finally:
            release.set()
            worker.join(timeout=2)
        assert sent.is_set()
        assert body_sent.is_set()
        assert not worker.is_alive()
        assert failures == []
        assert elapsed < 1.25


def test_control_client_rejects_cleanup_completed_after_deadline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = [0.0]
    monkeypatch.setattr(
        client_module, "time", SimpleNamespace(monotonic=lambda: clock[0])
    )

    class SlowClose(_Response):
        def close(self) -> None:
            super().close()
            clock[0] = 2.0

    response = SlowClose(b"{}", ["2"])
    monkeypatch.setattr(
        client_module, "_open_control_request", lambda *_args, **_kwargs: response
    )
    with pytest.raises(ContractError, match="response deadline exceeded"):
        ControlClient(
            "http://127.0.0.1:8766", None, timeout_seconds=1.0
        ).health()
    assert response.closed


def test_control_client_rejects_json_decoded_after_deadline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = [0.0]
    monkeypatch.setattr(
        client_module, "time", SimpleNamespace(monotonic=lambda: clock[0])
    )
    response = _Response(b"{}", ["2"])
    monkeypatch.setattr(
        client_module, "_open_control_request", lambda *_args, **_kwargs: response
    )

    def late_decode(*_args, **_kwargs):
        clock[0] = 2.0
        return {"status": "ok"}

    monkeypatch.setattr(client_module, "decode_strict_json_bytes", late_decode)
    with pytest.raises(ContractError, match="response deadline exceeded"):
        ControlClient(
            "http://127.0.0.1:8766", None, timeout_seconds=1.0
        ).health()
    assert response.closed


def test_control_client_rejection_body_has_total_deadline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    elapsed = [0.0]
    monkeypatch.setattr(
        client_module, "time", SimpleNamespace(monotonic=lambda: elapsed[0]),
        raising=False,
    )

    class SlowBody(io.BytesIO):
        def read(self, _size: int = -1) -> bytes:
            pytest.fail("blocking rejection read was used")

        def read1(self, size: int = -1) -> bytes:
            elapsed[0] += 0.06
            return super().read1(min(size, 1))

    body = SlowBody(b"{}")
    error = urllib.error.HTTPError(
        "http://127.0.0.1:8766/v1/health", 503, "unavailable", {}, body
    )

    def reject(*_args, **_kwargs):
        raise error

    monkeypatch.setattr(client_module, "_open_control_request", reject)
    client = ControlClient("http://127.0.0.1:8766", None, timeout_seconds=0.1)
    with pytest.raises(ContractError, match="HTTP 503") as raised:
        client._request("GET", "/v1/health", authenticated=False)
    assert "diagnostic_sha256_16=e3b0c44298fc1c14" in str(raised.value)
    assert body.closed


def test_control_client_rejects_http_status_received_after_deadline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = [0.0]
    monkeypatch.setattr(
        client_module, "time", SimpleNamespace(monotonic=lambda: clock[0])
    )
    body = io.BytesIO(b"private response")
    error = urllib.error.HTTPError(
        "http://127.0.0.1:8766/v1/health", 503, "unavailable", {}, body
    )

    def late_rejection(*_args, **_kwargs):
        clock[0] = 2.0
        raise error

    monkeypatch.setattr(client_module, "_open_control_request", late_rejection)
    with pytest.raises(ContractError, match="response deadline exceeded") as raised:
        ControlClient(
            "http://127.0.0.1:8766", None, timeout_seconds=1.0
        ).health()
    assert "HTTP 503" not in str(raised.value)
    assert body.closed


def test_control_response_reader_bounds_pathological_fragmentation() -> None:
    class EndlessResponse(_Response):
        def read1(self, _size: int = -1) -> bytes:
            return b"x"

    response = EndlessResponse(b"", [])
    with pytest.raises(ContractError, match="too many fragments"):
        client_module._read_control_response_payload(
            response, maximum=client_module.MAX_ARTIFACT_RESPONSE
        )
    assert response.closed


@pytest.mark.parametrize(
    "maximum",
    [True, "1", 0, client_module.MAX_ARTIFACT_RESPONSE + 1],
)
def test_control_response_reader_rejects_invalid_limit_before_adapter_use(
    maximum,
) -> None:
    class Response:
        def getcode(self):
            pytest.fail("invalid response limit reached status")

        @property
        def headers(self):
            pytest.fail("invalid response limit reached headers")

        def read(self, _maximum):
            pytest.fail("invalid response limit reached body")

        def close(self):
            pytest.fail("unowned response was incorrectly acquired")

    with pytest.raises(ContractError, match="response limit"):
        client_module._read_control_response_payload(
            Response(),
            maximum=maximum,
        )


@pytest.mark.parametrize("lengths", [None, [1], ["9" * 21]])
def test_control_client_rejects_malformed_content_length_shapes(
    monkeypatch: pytest.MonkeyPatch,
    lengths: object,
) -> None:
    class Headers:
        def get_all(self, *_args: object) -> object:
            return lengths

    response = _Response(b"{}", [])
    response.headers = Headers()  # type: ignore[assignment]
    monkeypatch.setattr(
        client_module,
        "_open_control_request",
        lambda *_args, **_kwargs: response,
    )

    with pytest.raises(ContractError, match="content length is invalid"):
        ControlClient("http://127.0.0.1:8766", None).health()

    assert response.closed


@pytest.mark.parametrize("failure", [None, OSError("private response read")])
def test_control_client_closes_and_normalizes_invalid_response_reads(
    monkeypatch: pytest.MonkeyPatch,
    failure: OSError | None,
) -> None:
    class Response:
        def __init__(self) -> None:
            self.headers = Message()
            self.headers.add_header("Content-Type", "application/json")
            self.closed = False

        def __enter__(self):  # type: ignore[no-untyped-def]
            return self

        def __exit__(self, *_args: object) -> None:
            self.closed = True

        def close(self) -> None:
            self.closed = True

        def getcode(self) -> int:
            return 200

        def read(self, _maximum: int) -> object:
            if failure is not None:
                raise failure
            return "private non-byte response"

    response = Response()
    monkeypatch.setattr(
        client_module,
        "_open_control_request",
        lambda *_args, **_kwargs: response,
    )

    with pytest.raises(ContractError) as captured:
        ControlClient("http://127.0.0.1:8766", None).health()

    assert response.closed
    assert "private" not in str(captured.value)
    assert str(captured.value) in {
        "control service response body is invalid",
        "control service response failed (OSError)",
    }


@pytest.mark.parametrize("status", [None, True, "200", 199, 300, 503])
def test_control_client_requires_exact_2xx_status_before_reading(
    monkeypatch: pytest.MonkeyPatch,
    status,
) -> None:
    class Response:
        def __init__(self) -> None:
            self.headers = Message()
            self.closed = False
            self.read_called = False

        def getcode(self):
            return status

        def read(self, _maximum: int) -> bytes:
            self.read_called = True
            return b'[{"private":"body"}]'

        def close(self) -> None:
            self.closed = True

    response = Response()
    monkeypatch.setattr(
        client_module,
        "_open_control_request",
        lambda *_args, **_kwargs: response,
    )

    with pytest.raises(ContractError) as raised:
        ControlClient("http://127.0.0.1:8766", None).health()

    assert str(raised.value) == "control service response status is invalid"
    assert response.read_called is False
    assert response.closed is True
    assert "private" not in str(raised.value)


def test_control_client_owns_response_without_entering_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class EnterRejectingResponse(_Response):
        def __enter__(self):  # type: ignore[no-untyped-def]
            raise AssertionError("implicit response context must not be entered")

    response = EnterRejectingResponse(b"{}", ["2"])
    monkeypatch.setattr(
        client_module,
        "_open_control_request",
        lambda *_args, **_kwargs: response,
    )

    assert ControlClient("http://127.0.0.1:8766", None).health() == {}
    assert response.closed


def test_control_client_rejects_valid_reply_when_response_close_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class CloseFailingResponse(_Response):
        def close(self) -> None:
            super().close()
            raise OSError("private response close diagnostic")

    response = CloseFailingResponse(b"{}", ["2"])
    monkeypatch.setattr(
        client_module,
        "_open_control_request",
        lambda *_args, **_kwargs: response,
    )

    with pytest.raises(ContractError) as raised:
        ControlClient("http://127.0.0.1:8766", None).health()
    assert str(raised.value) == (
        "control service response cleanup failed (response-close)"
    )
    assert raised.value.__cause__ is None
    assert "private" not in str(raised.value)


def test_control_client_cleanup_failure_retains_only_safe_body_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class InvalidCloseFailingResponse(_Response):
        def read1(self, _maximum: int) -> object:
            return "private non-byte response"

        def close(self) -> None:
            super().close()
            raise RuntimeError("private response close diagnostic")

    response = InvalidCloseFailingResponse(b"", [])
    monkeypatch.setattr(
        client_module,
        "_open_control_request",
        lambda *_args, **_kwargs: response,
    )

    with pytest.raises(ContractError) as raised:
        ControlClient("http://127.0.0.1:8766", None).health()
    assert str(raised.value) == (
        "control service response cleanup failed (response-close)"
    )
    assert isinstance(raised.value.__cause__, ContractError)
    assert str(raised.value.__cause__) == "control service response body is invalid"
    assert "private" not in str(raised.value)


@pytest.mark.parametrize(
    ("body", "lengths", "message"),
    [
        (b"{}", ["2", "2"], "content length"),
        (b"{}", ["3"], "incomplete"),
        (b'{"a":1,"a":2}', ["13"], "duplicate key"),
        (b'{"a":NaN}', ["9"], "non-finite"),
        (b'{"a":1e400}', ["11"], "non-finite"),
    ],
)
def test_control_client_rejects_ambiguous_or_non_strict_responses(
    monkeypatch: pytest.MonkeyPatch,
    body: bytes,
    lengths: list[str],
    message: str,
) -> None:
    response = _Response(body, lengths)
    monkeypatch.setattr(
        client_module,
        "_open_control_request",
        lambda *_args, **_kwargs: response,
    )

    with pytest.raises(ContractError, match=message):
        ControlClient("http://127.0.0.1:8766", None).health()

    assert response.closed


def test_control_client_closes_rejected_response_stream(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    private = "private-service-rejection-value"
    for body in (f'{{"message":"{private}"}}'.encode(), b"[]"):
        response = io.BytesIO(body)
        error = urllib.error.HTTPError(
            "http://127.0.0.1:8766/v1/health",
            503,
            "unavailable",
            {},
            response,
        )

        def reject(*_args: object, **_kwargs: object) -> None:
            raise error

        monkeypatch.setattr(client_module, "_open_control_request", reject)
        with pytest.raises(
            ContractError, match=r"HTTP 503; diagnostic_sha256_16="
        ) as raised:
            ControlClient("http://127.0.0.1:8766", "token").health()
        assert private not in str(raised.value)
        assert response.closed


def test_control_client_rejection_diagnostic_does_not_hash_adapter_over_return(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Response:
        def __init__(self) -> None:
            self.closed = False

        def read(self, maximum: int) -> bytes:
            assert maximum == 5
            return b"private-over-return"

        def close(self) -> None:
            self.closed = True

    response = Response()
    hashed: list[bytes] = []
    real_sha256 = client_module.hashlib.sha256

    def sha256(body: bytes):
        hashed.append(body)
        return real_sha256(body)

    monkeypatch.setattr(client_module, "MAX_JSON_RESPONSE", 4)
    monkeypatch.setattr(client_module.hashlib, "sha256", sha256)
    diagnostic = client_module._read_rejection_diagnostic(response)

    assert diagnostic == real_sha256(b"").hexdigest()[:16]
    assert hashed == [b""]
    assert response.closed is True


def test_control_client_rejection_diagnostic_does_not_hash_oversize_sentinel(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    response = io.BytesIO(b"12345")
    hashed: list[bytes] = []
    real_sha256 = client_module.hashlib.sha256

    def sha256(body: bytes):
        hashed.append(body)
        return real_sha256(body)

    monkeypatch.setattr(client_module, "MAX_JSON_RESPONSE", 4)
    monkeypatch.setattr(client_module.hashlib, "sha256", sha256)

    diagnostic = client_module._read_rejection_diagnostic(response)

    assert diagnostic == real_sha256(b"").hexdigest()[:16]
    assert hashed == [b""]
    assert response.closed is True


def test_control_client_rejected_response_close_failure_is_fixed_shape(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class CloseFailingHTTPError(urllib.error.HTTPError):
        def close(self) -> None:
            super().close()
            raise OSError("private rejected response close diagnostic")

    error = CloseFailingHTTPError(
        "http://127.0.0.1:8766/v1/health",
        503,
        "unavailable",
        {},
        io.BytesIO(b'{"message":"private"}'),
    )

    def reject(*_args: object, **_kwargs: object) -> None:
        raise error

    monkeypatch.setattr(client_module, "_open_control_request", reject)
    with pytest.raises(ContractError) as raised:
        ControlClient("http://127.0.0.1:8766", "token").health()
    assert str(raised.value) == (
        "control service response cleanup failed (response-close)"
    )
    assert raised.value.__cause__ is None
    assert "private" not in str(raised.value)


@pytest.mark.parametrize("status", [True, "private-status", None, 99, 600])
def test_control_client_rejection_status_is_value_free_and_typed(
    monkeypatch: pytest.MonkeyPatch, status
) -> None:
    response = io.BytesIO(b'{"message":"private-body"}')
    error = urllib.error.HTTPError(
        "http://127.0.0.1:8766/v1/health",
        status,
        "private-reason",
        {},
        response,
    )

    def reject(*_args: object, **_kwargs: object) -> None:
        raise error

    monkeypatch.setattr(client_module, "_open_control_request", reject)
    with pytest.raises(ContractError, match="rejection status is invalid") as failure:
        ControlClient("http://127.0.0.1:8766", "token").health()
    assert "private" not in str(failure.value)
    assert response.closed is True
