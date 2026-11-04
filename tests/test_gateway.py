from __future__ import annotations

import base64
import os
import socket
import subprocess
import sys
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace

import pytest

import browser_core.gateway as gateway_module
from browser_core.contracts import ContractError
from browser_core.control_files import (
    canonical_json_bytes,
    load_canonical_json_document,
    publish_json_exclusive,
)
from browser_core.gateway import (
    _load_lease,
    _parse_connect_request,
    _recv_connect_request,
    serve_gateway,
    sidecar,
)
from browser_core.network import (
    ResolvedNetworkRoute,
    add_network_route,
    build_network_route,
    resolve_network_route,
)


@contextmanager
def upstream_echo_proxy():
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    errors = []

    def run() -> None:
        try:
            connection, _ = listener.accept()
            with connection:
                request = bytearray()
                while b"\r\n\r\n" not in request:
                    request.extend(connection.recv(4096))
                text = request.decode("ascii")
                expected = base64.b64encode(b"alice:wonderland").decode("ascii")
                assert "CONNECT owned.example:443 HTTP/1.1" in text
                assert f"Proxy-Authorization: Basic {expected}" in text
                connection.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
                assert connection.recv(4) == b"ping"
                connection.sendall(b"pong")
        except Exception as exc:  # pragma: no cover - surfaced below
            errors.append(exc)
        finally:
            listener.close()

    thread = threading.Thread(target=run)
    thread.start()
    try:
        yield listener.getsockname()[1]
    finally:
        thread.join(timeout=5)
        assert not thread.is_alive()
        if errors:
            raise errors[0]


@pytest.mark.parametrize("chunk", [bytearray(b"private"), "private"])
def test_gateway_header_reader_requires_exact_byte_chunks(chunk) -> None:
    class Connection:
        def recv(self, _size):
            return chunk

    with pytest.raises(
        ContractError, match="transport returned invalid bytes"
    ) as failure:
        _recv_connect_request(Connection())  # type: ignore[arg-type]
    assert "private" not in str(failure.value)


def test_gateway_header_reader_rejects_adapter_over_return() -> None:
    class Connection:
        def recv(self, size):
            return b"x" * (size + 1)

    with pytest.raises(ContractError, match="transport returned invalid bytes"):
        _recv_connect_request(Connection())  # type: ignore[arg-type]


def test_gateway_header_reader_enforces_total_deadline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = [0.0]
    monkeypatch.setattr(
        gateway_module, "time", SimpleNamespace(monotonic=lambda: clock[0])
    )

    class Connection:
        def __init__(self) -> None:
            self.reads = 0
            self.timeouts: list[float] = []

        def settimeout(self, timeout: float) -> None:
            self.timeouts.append(timeout)

        def recv(self, _size: int) -> bytes:
            self.reads += 1
            clock[0] += 0.06
            return b"x"

    connection = Connection()
    with pytest.raises(gateway_module._GatewayRequestError, match="timed out"):
        _recv_connect_request(connection, deadline=0.1)  # type: ignore[arg-type]
    assert connection.reads == 2
    assert connection.timeouts == pytest.approx([0.1, 0.04])


def test_gateway_keeps_upstream_credentials_away_from_browser() -> None:
    with upstream_echo_proxy() as upstream_port:
        route = build_network_route(
            route_id="lab",
            name="Lab",
            mode="proxy",
            endpoint={"protocol": "http", "host": "127.0.0.1", "port": upstream_port},
            auth={"username_env": "PROXY_USER", "password_env": "PROXY_PASSWORD"},
            geography={
                "country": "US",
                "locale": "en-US",
                "timezone": "America/Chicago",
            },
            preflight_url="https://owned.example/health",
        )
        resolved = resolve_network_route(
            route, {"PROXY_USER": "alice", "PROXY_PASSWORD": "wonderland"}
        )
        with serve_gateway(resolved) as gateway:
            # The server owns the validated population it received at entry.
            resolved.route["endpoint"]["port"] = 9
            browser = socket.create_connection(gateway, timeout=5)
            with browser:
                browser.sendall(
                    b"CONNECT owned.example:443 HTTP/1.1\r\n"
                    b"Host: owned.example:443\r\n\r\nping"
                )
                response = bytearray()
                while b"\r\n\r\n" not in response:
                    response.extend(browser.recv(4096))
                assert response.startswith(b"HTTP/1.1 200")
                assert b"alice" not in response and b"wonderland" not in response
                header_end = response.index(b"\r\n\r\n") + 4
                tunnel = response[header_end:]
                while len(tunnel) < 4:
                    tunnel.extend(browser.recv(4 - len(tunnel)))
                assert tunnel == b"pong"


def test_gateway_shutdown_retires_an_active_tunnel(monkeypatch) -> None:
    upstream_socket, upstream_peer = socket.socketpair()
    monkeypatch.setattr(
        gateway_module,
        "_connect_http_proxy",
        lambda *_args, **_kwargs: upstream_socket,
    )
    route = build_network_route(
        route_id="owned-gateway",
        name="Owned gateway",
        mode="proxy",
        endpoint={"protocol": "http", "host": "proxy.example", "port": 7777},
        geography={
            "country": "US",
            "locale": "en-US",
            "timezone": "America/Chicago",
        },
        preflight_url="https://owned.example/health",
    )
    resolved = resolve_network_route(route, {})
    browser = None
    try:
        with serve_gateway(resolved) as gateway:
            browser = socket.create_connection(gateway, timeout=1)
            browser.settimeout(1)
            browser.sendall(
                b"CONNECT owned.example:443 HTTP/1.1\r\n"
                b"Host: owned.example:443\r\n\r\n"
            )
            assert browser.recv(4096).startswith(b"HTTP/1.1 200")

        try:
            closed = browser.recv(1)
        except TimeoutError:
            pytest.fail("gateway left the tunnel open after shutdown")
        except OSError:
            pass
        else:
            assert closed == b""
    finally:
        if browser is not None:
            browser.close()
        upstream_peer.close()
        upstream_socket.close()


def test_gateway_upstream_tunnel_owns_socket_without_entering_it(monkeypatch) -> None:
    class Client:
        def __init__(self) -> None:
            self.sent = []

        def sendall(self, body: bytes) -> None:
            self.sent.append(body)

    class Upstream:
        def __init__(self) -> None:
            self.sent = []
            self.closed = False

        def __enter__(self):
            raise AssertionError("implicit socket context must not be entered")

        def sendall(self, body: bytes) -> None:
            self.sent.append(body)

        def close(self) -> None:
            self.closed = True

    client = Client()
    upstream = Upstream()
    monkeypatch.setattr(
        gateway_module,
        "_relay",
        lambda left, right: None,
    )

    gateway_module._run_upstream_tunnel(client, upstream, b"initial")

    assert client.sent == [
        b"HTTP/1.1 200 Connection established\r\n"
        b"Proxy-Agent: BrowserCoreGateway\r\n\r\n"
    ]
    assert upstream.sent == [b"initial"]
    assert upstream.closed is True


def test_gateway_upstream_tunnel_supports_owned_smoke_response(monkeypatch) -> None:
    class Connection:
        def __init__(self) -> None:
            self.sent = []
            self.closed = False

        def sendall(self, body: bytes) -> None:
            self.sent.append(body)

        def close(self) -> None:
            self.closed = True

    client = Connection()
    upstream = Connection()
    monkeypatch.setattr(gateway_module, "_relay", lambda left, right: None)
    gateway_module._run_upstream_tunnel(
        client,
        upstream,
        b"",
        established_response=b"HTTP/1.1 200 Connection established\r\n\r\n",
    )

    assert client.sent == [b"HTTP/1.1 200 Connection established\r\n\r\n"]
    assert upstream.closed is True


def test_gateway_relay_preserves_response_after_client_half_closes() -> None:
    client, relay_client = socket.socketpair()
    relay_upstream, upstream = socket.socketpair()
    errors = []

    def relay():
        try:
            gateway_module._relay(relay_client, relay_upstream)
        except Exception as error:
            errors.append(error)

    worker = threading.Thread(target=relay, daemon=True)
    try:
        client.settimeout(5)
        upstream.settimeout(5)
        worker.start()
        client.sendall(b'ping')
        client.shutdown(socket.SHUT_WR)
        assert upstream.recv(4) == b'ping'
        assert upstream.recv(1) == b''
        upstream.sendall(b'pong')
        upstream.shutdown(socket.SHUT_WR)
        assert client.recv(4) == b'pong'
        assert client.recv(1) == b''
        worker.join(5)
        assert not worker.is_alive() and errors == []
    finally:
        for connection in (client, relay_client, relay_upstream, upstream):
            connection.close()
        worker.join(5)


def test_gateway_does_not_send_http_error_inside_established_tunnel(monkeypatch) -> None:
    request = SimpleNamespace(
        settimeout=lambda _timeout: None,
        recv=lambda _count: b'CONNECT owned.example:443 HTTP/1.1\r\nHost: owned.example:443\r\n\r\n',
        sent=[],
    )
    request.sendall = lambda body: request.sent.append(body)
    route = SimpleNamespace(protocol='http')
    monkeypatch.setattr(gateway_module, '_connect_http_proxy', lambda *_args: object())

    def fail_after_establishing(client, _upstream, _initial):
        client.sendall(b'HTTP/1.1 200 Connection established\r\n\r\n')
        raise ContractError('relay failed')

    monkeypatch.setattr(gateway_module, '_run_upstream_tunnel', fail_after_establishing)
    gateway_module._GatewayHandler(request, ('127.0.0.1', 1),
                                   SimpleNamespace(resolved_route=route))
    assert request.sent == [b'HTTP/1.1 200 Connection established\r\n\r\n']


def test_gateway_reports_upstream_failure_before_establishing_tunnel(monkeypatch) -> None:
    request = SimpleNamespace(
        settimeout=lambda _timeout: None,
        recv=lambda _count: b'CONNECT owned.example:443 HTTP/1.1\r\nHost: owned.example:443\r\n\r\n',
        sent=[],
    )
    request.sendall = lambda body: request.sent.append(body)

    def fail_connect(*_args):
        raise ContractError('upstream unavailable')

    monkeypatch.setattr(gateway_module, '_connect_http_proxy', fail_connect)
    gateway_module._GatewayHandler(request, ('127.0.0.1', 1),
                                   SimpleNamespace(resolved_route=SimpleNamespace(protocol='http')))
    assert len(request.sent) == 1
    assert request.sent[0].startswith(b'HTTP/1.1 502 Bad Gateway\r\n')


@pytest.mark.parametrize(
    "chunk",
    [bytearray(b"private"), "private", b"x" * 65537],
    ids=("bytearray", "text", "oversized"),
)
def test_gateway_relay_requires_bounded_exact_bytes(
    monkeypatch: pytest.MonkeyPatch, chunk
) -> None:
    class Source:
        def recv(self, _size):
            return chunk

    class Destination:
        def sendall(self, _body):
            pytest.fail("invalid relay bytes reached destination")

    source = Source()
    destination = Destination()

    class Selector:
        def register(self, *_args):
            return None

        def select(self, **_kwargs):
            class Key:
                fileobj = source
                data = destination

            return [(Key(), object())]

        def close(self):
            return None

    monkeypatch.setattr(gateway_module.selectors, "DefaultSelector", Selector)
    with pytest.raises(ContractError, match="relay returned invalid bytes") as failure:
        gateway_module._relay(source, destination)  # type: ignore[arg-type]
    assert "private" not in str(failure.value)


def test_gateway_relay_requires_complete_sendall_semantics(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Source:
        def recv(self, _size):
            return b"payload"

    class Destination:
        def sendall(self, _body):
            return 7

    source = Source()
    destination = Destination()

    class Selector:
        def register(self, *_args):
            return None

        def select(self, **_kwargs):
            class Key:
                fileobj = source
                data = destination

            return [(Key(), object())]

        def close(self):
            return None

    monkeypatch.setattr(gateway_module.selectors, "DefaultSelector", Selector)
    with pytest.raises(ContractError, match="relay write is invalid"):
        gateway_module._relay(source, destination)  # type: ignore[arg-type]


def test_gateway_tunnel_requires_complete_initial_sendall_semantics(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Client:
        def sendall(self, _body):
            return 1

    class Upstream:
        def __init__(self):
            self.closed = False

        def close(self):
            self.closed = True

    upstream = Upstream()
    monkeypatch.setattr(
        gateway_module,
        "_relay",
        lambda *_args: pytest.fail("invalid write reached relay"),
    )
    with pytest.raises(ContractError, match="relay write is invalid"):
        gateway_module._run_upstream_tunnel(Client(), upstream, b"")
    assert upstream.closed is True


def test_gateway_upstream_tunnel_invalid_input_still_closes_upstream(
    monkeypatch,
) -> None:
    class Connection:
        def __init__(self) -> None:
            self.closed = False

        def sendall(self, _body: bytes) -> None:
            return None

        def close(self) -> None:
            self.closed = True

    client = Connection()
    upstream = Connection()
    monkeypatch.setattr(
        gateway_module,
        "_relay",
        lambda *_args: pytest.fail("invalid tunnel input reached relay"),
    )
    with pytest.raises(ContractError, match="tunnel input"):
        gateway_module._run_upstream_tunnel(
            client,
            upstream,
            b"",
            established_response=b"invalid",
        )
    assert upstream.closed is True


def test_gateway_upstream_close_failure_blocks_clean_tunnel_completion(
    monkeypatch,
) -> None:
    class Connection:
        def sendall(self, _body: bytes) -> None:
            return None

        def close(self) -> None:
            raise OSError("private upstream close diagnostic")

    monkeypatch.setattr(gateway_module, "_relay", lambda left, right: None)
    with pytest.raises(ContractError) as raised:
        gateway_module._run_upstream_tunnel(Connection(), Connection(), b"")
    assert str(raised.value) == (
        "credential gateway upstream cleanup failed (connection-close)"
    )
    assert raised.value.__cause__ is None
    assert "private" not in str(raised.value)


def test_gateway_upstream_cleanup_failure_retains_only_safe_relay_failure(
    monkeypatch,
) -> None:
    class Connection:
        def sendall(self, _body: bytes) -> None:
            return None

        def close(self) -> None:
            raise RuntimeError("private upstream close diagnostic")

    def fail_relay(_left, _right) -> None:
        raise OSError("private relay diagnostic")

    monkeypatch.setattr(gateway_module, "_relay", fail_relay)
    with pytest.raises(ContractError) as raised:
        gateway_module._run_upstream_tunnel(Connection(), Connection(), b"")
    assert str(raised.value) == (
        "credential gateway upstream cleanup failed (connection-close)"
    )
    assert isinstance(raised.value.__cause__, ContractError)
    assert str(raised.value.__cause__) == (
        "credential gateway upstream tunnel failed (OSError)"
    )
    assert "private" not in str(raised.value)


def _unreachable_resolved_route() -> ResolvedNetworkRoute:
    route = build_network_route(
        route_id="unreachable",
        name="Unreachable test endpoint",
        mode="proxy",
        endpoint={"protocol": "http", "host": "127.0.0.1", "port": 9},
        geography={"country": "US", "locale": "en-US", "timezone": "America/Chicago"},
        preflight_url="https://owned.example/health",
    )
    return resolve_network_route(route)


def _gateway_request(request: bytes) -> bytes:
    with serve_gateway(_unreachable_resolved_route()) as endpoint:
        with socket.create_connection(endpoint, timeout=5) as connection:
            connection.sendall(request)
            connection.shutdown(socket.SHUT_WR)
            response = bytearray()
            while b"\r\n\r\n" not in response:
                chunk = connection.recv(4096)
                if not chunk:
                    break
                response.extend(chunk)
    return bytes(response)


@pytest.mark.parametrize(
    ("raw_request", "status"),
    [
        (b"GET owned.example:443 HTTP/1.1\r\nHost: owned.example:443\r\n\r\n", b"405"),
        (
            b"CONNECT owned.example:443 HTTP/1.9\r\nHost: owned.example:443\r\n\r\n",
            b"400",
        ),
        (
            b"CONNECT owned.example:443 HTTP/1.1\r\n"
            b"Host: owned.example:443\r\nHost: owned.example:443\r\n\r\n",
            b"400",
        ),
        (
            b"CONNECT owned.example:443 HTTP/1.1\r\nHost: other.example:443\r\n\r\n",
            b"400",
        ),
        (
            b"CONNECT owned.example:0443 HTTP/1.1\r\nHost: owned.example:0443\r\n\r\n",
            b"400",
        ),
        (
            b"CONNECT 0x7f000001:443 HTTP/1.1\r\nHost: 0x7f000001:443\r\n\r\n",
            b"400",
        ),
        (
            b"CONNECT 127.1:443 HTTP/1.1\r\nHost: 127.1:443\r\n\r\n",
            b"400",
        ),
        (
            b"CONNECT owned.example:443 HTTP/1.1\r\n Host: owned.example:443\r\n\r\n",
            b"400",
        ),
        (b"CONNECT owned.example:443 HTTP/1.1\r\nHost: owned.example:443\r\n", b"400"),
    ],
)
def test_gateway_rejects_ambiguous_connect_requests(
    raw_request: bytes, status: bytes
) -> None:
    response = _gateway_request(raw_request)
    assert response.startswith(b"HTTP/1.1 " + status)
    assert b"Content-Length: 0\r\n" in response


def test_gateway_connect_parser_supports_bracketed_ipv6() -> None:
    assert _parse_connect_request(
        b"CONNECT [2001:db8::1]:443 HTTP/1.1\r\nHost: [2001:db8::1]:443\r\n\r\n"
    ) == ("2001:db8::1", "[2001:db8::1]", 443)


@pytest.mark.parametrize("scope", ["%2", "%25eth0"])
def test_gateway_rejects_scoped_ipv6_connect_authority(scope: str) -> None:
    authority = f"[fe80::1{scope}]:443"
    request = (
        f"CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n"
    ).encode("ascii")
    with pytest.raises(gateway_module._GatewayRequestError, match="authority is invalid"):
        _parse_connect_request(request)


def test_gateway_rejects_invalid_credentials_before_server_contact(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    route = build_network_route(
        route_id="auth",
        name="Auth",
        mode="proxy",
        endpoint={"protocol": "http", "host": "127.0.0.1", "port": 9},
        auth={"username_env": "OWNED_USER", "password_env": "OWNED_PASSWORD"},
        geography={"country": "US", "locale": "en-US", "timezone": "America/Chicago"},
    )
    resolved = ResolvedNetworkRoute(route, username="x" * 4097, password="owned")
    monkeypatch.setattr(
        gateway_module,
        "_GatewayServer",
        lambda *_args: pytest.fail("invalid credentials reached server construction"),
    )
    with pytest.raises(ContractError, match="credentials"):
        with serve_gateway(resolved):
            pass


def test_gateway_closes_listener_when_thread_start_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FakeServer:
        server_address = ("127.0.0.1", 12345)

        def __init__(self) -> None:
            self.closed = False

        def serve_forever(self) -> None:
            return

        def shutdown(self) -> None:
            pytest.fail("unstarted server must not be shut down")

        def server_close(self) -> None:
            self.closed = True

    class FakeThread:
        def start(self) -> None:
            raise RuntimeError("owned start failure")

        def join(self, timeout: float) -> None:
            return

        def is_alive(self) -> bool:
            return False

    server = FakeServer()
    monkeypatch.setattr(gateway_module, "_GatewayServer", lambda _route: server)
    monkeypatch.setattr(
        gateway_module.threading, "Thread", lambda **kwargs: FakeThread()
    )
    with pytest.raises(
        ContractError,
        match=r"could not start \(RuntimeError\)",
    ) as raised:
        with serve_gateway(_unreachable_resolved_route()):
            pass
    assert server.closed is True
    assert "owned start failure" not in str(raised.value)


def test_gateway_stops_worker_when_start_raises_after_launch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Server:
        server_address = ("127.0.0.1", 12345)

        def __init__(self) -> None:
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
            raise RuntimeError("private post-start failure")

        def is_alive(self) -> bool:
            return self.alive

        def join(self, *, timeout: float) -> None:
            assert timeout == gateway_module.GATEWAY_CLEANUP_TIMEOUT_SECONDS
            server.phases.append("join")
            self.alive = False

    server = Server()
    real_thread = threading.Thread

    def make_thread(*, name, **kwargs):
        if name == "browser-core-gateway":
            return Worker()
        return real_thread(name=name, **kwargs)

    monkeypatch.setattr(gateway_module, "_GatewayServer", lambda _route: server)
    monkeypatch.setattr(gateway_module.threading, "Thread", make_thread)
    with pytest.raises(ContractError, match=r"could not start \(RuntimeError\)") as raised:
        with serve_gateway(_unreachable_resolved_route()):
            pytest.fail("failed startup reached the gateway body")
    assert server.phases == ["shutdown", "close", "join"]
    assert "private" not in str(raised.value)


def test_gateway_closes_listener_when_thread_construction_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FakeServer:
        server_address = ("127.0.0.1", 12345)

        def __init__(self) -> None:
            self.closed = False

        def serve_forever(self) -> None:
            return

        def server_close(self) -> None:
            self.closed = True

    server = FakeServer()
    monkeypatch.setattr(gateway_module, "_GatewayServer", lambda _route: server)
    monkeypatch.setattr(
        gateway_module.threading,
        "Thread",
        lambda **_kwargs: (_ for _ in ()).throw(
            RuntimeError("private constructor path")
        ),
    )

    with pytest.raises(
        ContractError,
        match=r"could not start \(RuntimeError\)",
    ) as raised:
        with serve_gateway(_unreachable_resolved_route()):
            pass

    assert server.closed is True
    assert "private constructor path" not in str(raised.value)


def test_gateway_cleanup_attempts_every_phase_after_failures() -> None:
    class Server:
        def shutdown(self) -> None:
            raise RuntimeError("private shutdown")

        def server_close(self) -> None:
            raise OSError("private close")

    class Worker:
        def is_alive(self) -> bool:
            return True

        def join(self, *, timeout: float) -> None:
            assert timeout == gateway_module.GATEWAY_CLEANUP_TIMEOUT_SECONDS
            raise RuntimeError("private join")

    failures = gateway_module._stop_gateway_server(
        Server(),
        Worker(),
        thread_started=True,
    )

    assert failures == ["server-shutdown", "server-close", "worker-thread"]


def test_gateway_shutdown_is_bounded_and_still_closes_and_joins(
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
    monkeypatch.setattr(gateway_module, "GATEWAY_CLEANUP_TIMEOUT_SECONDS", 0.01)
    started = time.monotonic()

    failures = gateway_module._stop_gateway_server(
        server,
        worker,
        thread_started=True,
    )

    assert time.monotonic() - started < 0.5
    assert failures == ["server-shutdown"]
    assert server.closed is True
    assert worker.joined is True


def test_gateway_reclaims_shutdown_thread_after_late_start_error(
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

    monkeypatch.setattr(gateway_module.threading, "Thread", ShutdownThread)
    monkeypatch.setattr(gateway_module, "GATEWAY_CLEANUP_TIMEOUT_SECONDS", 0.1)
    server = Server()
    worker = Worker()
    failures = gateway_module._stop_gateway_server(server, worker, thread_started=True)

    assert failures == ["server-shutdown"]
    assert server.closed is True
    assert worker.joined is True
    assert threads[0].joined is True
    assert threads[0].is_alive() is False


def test_gateway_cleanup_failure_retains_body_failure_only_as_cause(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FakeServer:
        server_address = ("127.0.0.1", 12345)

        def serve_forever(self) -> None:
            return

    class FakeThread:
        def start(self) -> None:
            return

        def is_alive(self) -> bool:
            return True

    monkeypatch.setattr(
        gateway_module,
        "_GatewayServer",
        lambda _route: FakeServer(),
    )
    monkeypatch.setattr(
        gateway_module.threading,
        "Thread",
        lambda **_kwargs: FakeThread(),
    )
    monkeypatch.setattr(
        gateway_module,
        "_stop_gateway_server",
        lambda *_args, **_kwargs: ["server-shutdown", "server-close"],
    )

    with pytest.raises(
        ContractError,
        match=r"cleanup failed \(server-shutdown,server-close\)",
    ) as raised:
        with serve_gateway(_unreachable_resolved_route()):
            raise RuntimeError("private gateway body")

    assert isinstance(raised.value.__cause__, RuntimeError)
    assert "private gateway body" not in str(raised.value)


def _route() -> dict[str, object]:
    return {
        "id": "owned-route",
        "mode": "proxy",
        "integrity_sha256": "1" * 64,
    }


def _lease_document(**changes: object) -> dict[str, object]:
    document: dict[str, object] = {
        "schema": "browser-core.gateway-lease/2",
        "run_id": "owned-run",
        "route_id": "owned-route",
        "route_sha256_16": "1" * 16,
    }
    document.update(changes)
    return document


@pytest.mark.skipif(os.name != "nt", reason="Windows directory junction boundary")
def test_gateway_command_rejects_selected_workspace_junction(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    workspace = tmp_path / "physical-workspace"
    workspace.mkdir()
    route = build_network_route(
        route_id="owned-route",
        name="Owned route",
        geography={"country": "US", "locale": "en-US", "timezone": "America/Chicago"},
    )
    add_network_route(workspace, route)
    selected = tmp_path / "selected-workspace"
    linked = subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(selected), str(workspace)],
        capture_output=True,
        check=False,
    )
    if linked.returncode:
        pytest.skip("host could not create an unprivileged directory junction")
    try:
        monkeypatch.setattr(sys, "argv", [
            "browser-core-gateway", "--workspace", str(selected),
            "--route-id", "owned-route", "--run-id", "owned-run",
            "--ready-file", str(tmp_path / "owned-run.json"),
            "--lease-file", str(tmp_path / "owned-run.lease"),
        ])
        assert gateway_module.main() == 2
        assert "network route directory" in capsys.readouterr().out
        assert not (tmp_path / "owned-run.json").exists()
    finally:
        selected.rmdir()


def test_gateway_lease_is_bounded_canonical_and_exactly_bound(tmp_path: Path) -> None:
    lease = tmp_path / "owned-run.lease"
    publish_json_exclusive(
        lease,
        _lease_document(),
        maximum=4096,
        label="gateway lease",
    )
    loaded = _load_lease(lease, _route(), "owned-run")
    assert loaded is not None and loaded.document == _lease_document()
    assert _load_lease(tmp_path / "missing.lease", _route(), "owned-run") is None

    for invalid in (
        b'{"schema": "browser-core.gateway-lease/2"}\n',
        canonical_json_bytes(_lease_document(run_id="other-run")),
        canonical_json_bytes(_lease_document(route_sha256_16="2" * 16)),
        canonical_json_bytes(_lease_document(extra="not-owned")),
    ):
        lease.write_bytes(invalid)
        with pytest.raises(ContractError):
            _load_lease(lease, _route(), "owned-run")


def test_gateway_lease_rejects_hard_link_alias_and_non_path(tmp_path: Path) -> None:
    lease = tmp_path / "owned-run.lease"
    publish_json_exclusive(
        lease,
        _lease_document(),
        maximum=4096,
        label="gateway lease",
    )
    (tmp_path / "lease-alias").hardlink_to(lease)

    with pytest.raises(ContractError, match="hard links"):
        _load_lease(lease, _route(), "owned-run")
    with pytest.raises(ContractError, match="path must be a Path"):
        _load_lease(str(lease), _route(), "owned-run")  # type: ignore[arg-type]


def test_gateway_sidecar_rejects_linked_control_paths_before_resolution(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    aliases = tmp_path / "aliases"
    targets = tmp_path / "targets"
    aliases.mkdir()
    targets.mkdir()
    target_lease = targets / "owned-run.lease"
    publish_json_exclusive(
        target_lease,
        _lease_document(),
        maximum=4096,
        label="gateway lease",
    )
    lease = aliases / "owned-run.lease"
    ready = aliases / "owned-run.json"
    try:
        lease.symlink_to(target_lease)
        ready.symlink_to(targets / "owned-run.json")
    except (OSError, NotImplementedError):
        pytest.skip("file symlinks are unavailable")
    monkeypatch.setattr(gateway_module, "load_network_route", lambda *_args: _route())
    monkeypatch.setattr(gateway_module, "resolve_network_route", lambda route: route)
    monkeypatch.setattr(
        gateway_module,
        "serve_gateway",
        lambda _resolved: pytest.fail("linked controls reached gateway startup"),
    )
    with pytest.raises(ContractError, match="control paths"):
        sidecar(tmp_path, "owned-route", "owned-run", ready, lease)
    assert not (targets / "owned-run.json").exists()


def test_gateway_sidecar_rejects_redirected_control_paths(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    aliases = tmp_path / "aliases"
    targets = tmp_path / "targets"
    aliases.mkdir()
    targets.mkdir()
    lease = aliases / "owned-run.lease"
    ready = aliases / "owned-run.json"
    target_lease = targets / lease.name
    target_ready = targets / ready.name
    publish_json_exclusive(
        target_lease,
        _lease_document(),
        maximum=4096,
        label="gateway lease",
    )
    original_resolve = Path.resolve

    def redirected(self: Path, *args, **kwargs) -> Path:  # type: ignore[no-untyped-def]
        if self == lease:
            return target_lease
        if self == ready:
            return target_ready
        return original_resolve(self, *args, **kwargs)

    monkeypatch.setattr(Path, "resolve", redirected)
    monkeypatch.setattr(gateway_module, "load_network_route", lambda *_args: _route())
    monkeypatch.setattr(gateway_module, "resolve_network_route", lambda route: route)
    monkeypatch.setattr(
        gateway_module,
        "serve_gateway",
        lambda _resolved: pytest.fail("redirected controls reached gateway startup"),
    )
    with pytest.raises(ContractError, match="control paths"):
        sidecar(tmp_path, "owned-route", "owned-run", ready, lease)
    assert not target_ready.exists()


def test_gateway_sidecar_publishes_ready_exclusively_and_stops_on_lease_removal(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    directory = tmp_path / "gateways"
    directory.mkdir()
    lease = directory / "owned-run.lease"
    ready = directory / "owned-run.json"
    publish_json_exclusive(
        lease,
        _lease_document(),
        maximum=4096,
        label="gateway lease",
    )
    exited: list[bool] = []

    @contextmanager
    def fake_gateway(_resolved):  # type: ignore[no-untyped-def]
        try:
            yield "127.0.0.1", 8765
        finally:
            exited.append(True)

    monkeypatch.setattr(gateway_module, "load_network_route", lambda *_args: _route())
    monkeypatch.setattr(gateway_module, "resolve_network_route", lambda route: route)
    monkeypatch.setattr(gateway_module, "serve_gateway", fake_gateway)
    monkeypatch.setattr(gateway_module.time, "sleep", lambda _duration: lease.unlink())

    assert sidecar(tmp_path, "owned-route", "owned-run", ready, lease) == 0
    document = load_canonical_json_document(
        ready.read_bytes(),
        label="gateway readiness",
    )
    assert document == {
        "schema": "browser-core.gateway-ready/2",
        "run_id": "owned-run",
        "route_id": "owned-route",
        "route_sha256_16": "1" * 16,
        "host": "127.0.0.1",
        "port": 8765,
    }
    assert exited == [True]
    assert not list(directory.glob(".*.tmp-*"))


def test_gateway_sidecar_rejects_control_parent_replacement_before_ready(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    directory = tmp_path / "gateways"
    directory.mkdir()
    lease = directory / "owned-run.lease"
    ready = directory / "owned-run.json"
    publish_json_exclusive(lease, _lease_document(), maximum=4096, label="gateway lease")
    moved = tmp_path / "moved-gateways"

    @contextmanager
    def replace_parent(_resolved):  # type: ignore[no-untyped-def]
        directory.rename(moved)
        directory.mkdir()
        yield "127.0.0.1", 8765

    monkeypatch.setattr(gateway_module, "load_network_route", lambda *_args: _route())
    monkeypatch.setattr(gateway_module, "resolve_network_route", lambda route: route)
    monkeypatch.setattr(gateway_module, "serve_gateway", replace_parent)

    with pytest.raises(ContractError, match="control parent changed"):
        sidecar(tmp_path, "owned-route", "owned-run", ready, lease)
    assert not ready.exists()
    assert (moved / "owned-run.lease").exists()


def test_gateway_sidecar_rejects_control_parent_replacement_during_poll(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    directory = tmp_path / "gateways"
    directory.mkdir()
    lease = directory / "owned-run.lease"
    ready = directory / "owned-run.json"
    publish_json_exclusive(lease, _lease_document(), maximum=4096, label="gateway lease")
    moved = tmp_path / "moved-gateways"

    @contextmanager
    def fake_gateway(_resolved):  # type: ignore[no-untyped-def]
        yield "127.0.0.1", 8765

    def replace_parent(_duration: float) -> None:
        directory.rename(moved)
        directory.mkdir()

    monkeypatch.setattr(gateway_module, "load_network_route", lambda *_args: _route())
    monkeypatch.setattr(gateway_module, "resolve_network_route", lambda route: route)
    monkeypatch.setattr(gateway_module, "serve_gateway", fake_gateway)
    monkeypatch.setattr(gateway_module.time, "sleep", replace_parent)

    with pytest.raises(ContractError, match="control parent changed"):
        sidecar(tmp_path, "owned-route", "owned-run", ready, lease)
    assert not ready.exists()
    assert (moved / "owned-run.json").exists()


def test_gateway_sidecar_fails_closed_when_live_lease_changes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    directory = tmp_path / "private-gateways"
    directory.mkdir()
    lease = directory / "owned-run.lease"
    ready = directory / "owned-run.json"
    publish_json_exclusive(
        lease,
        _lease_document(),
        maximum=4096,
        label="gateway lease",
    )
    exited: list[bool] = []

    @contextmanager
    def fake_gateway(_resolved):  # type: ignore[no-untyped-def]
        try:
            yield "127.0.0.1", 8765
        finally:
            exited.append(True)

    monkeypatch.setattr(gateway_module, "load_network_route", lambda *_args: _route())
    monkeypatch.setattr(gateway_module, "resolve_network_route", lambda route: route)
    monkeypatch.setattr(gateway_module, "serve_gateway", fake_gateway)
    monkeypatch.setattr(
        gateway_module.time,
        "sleep",
        lambda _duration: lease.write_bytes(
            canonical_json_bytes(_lease_document(route_id="replacement-route"))
        ),
    )

    with pytest.raises(ContractError, match="lease document is invalid") as raised:
        sidecar(tmp_path, "owned-route", "owned-run", ready, lease)
    assert str(directory) not in str(raised.value)
    assert exited == [True]


def test_gateway_sidecar_stops_when_lease_is_replaced_with_same_document(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    directory = tmp_path / "private-gateways"
    directory.mkdir()
    lease = directory / "owned-run.lease"
    replacement = directory / "replacement.lease"
    ready = directory / "owned-run.json"
    for path in (lease, replacement):
        publish_json_exclusive(path, _lease_document(), maximum=4096, label="gateway lease")
    exited: list[bool] = []

    @contextmanager
    def fake_gateway(_resolved):  # type: ignore[no-untyped-def]
        try:
            yield "127.0.0.1", 8765
        finally:
            exited.append(True)

    sleeps = 0

    def replace_once(_duration: float) -> None:
        nonlocal sleeps
        sleeps += 1
        if sleeps == 1:
            replacement.replace(lease)
        else:
            pytest.fail("sidecar kept a replaced lease alive")

    monkeypatch.setattr(gateway_module, "load_network_route", lambda *_args: _route())
    monkeypatch.setattr(gateway_module, "resolve_network_route", lambda route: route)
    monkeypatch.setattr(gateway_module, "serve_gateway", fake_gateway)
    monkeypatch.setattr(gateway_module.time, "sleep", replace_once)

    with pytest.raises(ContractError, match="lease document changed"):
        sidecar(tmp_path, "owned-route", "owned-run", ready, lease)
    assert exited == [True]
