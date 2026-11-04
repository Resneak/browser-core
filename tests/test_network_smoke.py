from __future__ import annotations

import io
import os
import socket
import subprocess
import threading
import urllib.error
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

import browser_core.network_smoke as network_smoke
from browser_core.contracts import ContractError
from browser_core.network_smoke import (
    MAX_GEOGRAPHY_RESPONSE_BYTES,
    MAX_SERIALIZED_RECORD_BYTES,
    NetworkGatewaySmoke,
    _AuthenticatedForwardServer,
    _assert_credentials_not_serialized,
    _expected_geography,
    run_network_gateway_smoke,
)


def _request(server: _AuthenticatedForwardServer, request: bytes) -> bytes:
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with socket.create_connection(server.server_address, timeout=5) as connection:
            connection.sendall(request)
            response = connection.recv(4096)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
    return response


def test_owned_forwarder_rejects_missing_credentials() -> None:
    server = _AuthenticatedForwardServer("owned-user", "owned-password")
    response = _request(
        server,
        b"CONNECT ipwho.is:443 HTTP/1.1\r\nHost: ipwho.is:443\r\n\r\n",
    )
    assert response.startswith(b"HTTP/1.1 407")
    assert server.authorized_connects == 0
    assert server.rejected_connects == 1
    assert b"owned-user" not in response and b"owned-password" not in response


def test_owned_forwarder_rejects_hosts_outside_the_smoke_allowlist() -> None:
    server = _AuthenticatedForwardServer("owned-user", "owned-password")
    response = _request(
        server,
        b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n"
        + f"Proxy-Authorization: {server.expected_authorization}\r\n\r\n".encode(
            "ascii"
        ),
    )
    assert response.startswith(b"HTTP/1.1 403")
    assert server.authorized_connects == 0
    assert server.rejected_connects == 1


def test_owned_forwarder_rejects_duplicate_authorization_headers() -> None:
    server = _AuthenticatedForwardServer("owned-user", "owned-password")
    authorization = f"Proxy-Authorization: {server.expected_authorization}\r\n".encode(
        "ascii"
    )
    response = _request(
        server,
        b"CONNECT ipwho.is:443 HTTP/1.1\r\nHost: ipwho.is:443\r\n"
        + authorization
        + authorization
        + b"\r\n",
    )
    assert response.startswith(b"HTTP/1.1 502")
    assert server.authorized_connects == 0
    assert server.rejected_connects == 1


def test_owned_forwarder_rejects_host_header_authority_mismatch() -> None:
    server = _AuthenticatedForwardServer("owned-user", "owned-password")
    response = _request(
        server,
        b"CONNECT ipwho.is:443 HTTP/1.1\r\nHost: tls.peet.ws:443\r\n"
        + f"Proxy-Authorization: {server.expected_authorization}\r\n\r\n".encode(
            "ascii"
        ),
    )
    assert response.startswith(b"HTTP/1.1 403")
    assert server.authorized_connects == 0
    assert server.rejected_connects == 1


def test_owned_forwarder_does_not_append_http_error_after_tunnel_starts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Request:
        writes: list[bytes] = []

        def settimeout(self, _timeout: float) -> None:
            return

        def recv(self, _maximum: int) -> bytes:
            return (
                b"CONNECT ipwho.is:443 HTTP/1.1\r\n"
                b"Host: ipwho.is:443\r\n"
                b"Proxy-Authorization: Basic owned\r\n\r\n"
            )

        def sendall(self, body: bytes) -> None:
            self.writes.append(body)

    class Server:
        allowed_hosts = frozenset({"ipwho.is"})
        expected_authorization = "Basic owned"
        authorized = False

        def count(self, *, authorized: bool, host: str | None = None) -> None:
            assert host == "ipwho.is"
            self.authorized = authorized

    request = Request()
    server = Server()
    handler = object.__new__(network_smoke._AuthenticatedForwardHandler)
    handler.request = request
    handler.server = server
    monkeypatch.setattr(network_smoke.socket, "create_connection", lambda *_args, **_kwargs: object())

    def fail_after_established(client, _upstream, _initial, *, established_response):  # noqa: ANN001
        client.sendall(established_response)
        raise ContractError("tunnel failed after HTTP 200")

    monkeypatch.setattr(network_smoke, "_run_upstream_tunnel", fail_after_established)

    handler.handle()

    assert server.authorized is True
    assert request.writes == [b"HTTP/1.1 200 Connection established\r\n\r\n"]


def test_owned_forwarder_shutdown_retires_an_active_tunnel(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    upstream_socket, upstream_peer = socket.socketpair()
    original_connect = socket.create_connection

    def connect(address, *args, **kwargs):  # type: ignore[no-untyped-def]
        if address == ("ipwho.is", 443):
            return upstream_socket
        return original_connect(address, *args, **kwargs)

    monkeypatch.setattr(network_smoke.socket, "create_connection", connect)
    server = _AuthenticatedForwardServer("owned-user", "owned-password")
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    browser = None
    try:
        browser = original_connect(server.server_address, timeout=1)
        browser.settimeout(1)
        browser.sendall(
            b"CONNECT ipwho.is:443 HTTP/1.1\r\n"
            b"Host: ipwho.is:443\r\n"
            + f"Proxy-Authorization: {server.expected_authorization}\r\n\r\n".encode(
                "ascii"
            )
        )
        assert browser.recv(4096).startswith(b"HTTP/1.1 200")
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
        assert not thread.is_alive()
        try:
            closed = browser.recv(1)
        except TimeoutError:
            pytest.fail("owned forwarder left its tunnel open after shutdown")
        except OSError:
            pass
        else:
            assert closed == b""
    finally:
        if browser is not None:
            browser.close()
        server.server_close()
        upstream_peer.close()
        upstream_socket.close()


def test_owned_forwarder_does_not_shutdown_an_absent_worker() -> None:
    class Server:
        shutdown_calls = 0
        closed = False

        def shutdown(self) -> None:
            self.shutdown_calls += 1

        def server_close(self) -> None:
            self.closed = True

    class Worker:
        joined = False

        def is_alive(self) -> bool:
            return False

        def join(self, *, timeout: float) -> None:
            self.joined = True

    server = Server()
    worker = Worker()
    assert network_smoke._stop_forwarder(server, worker, started=True) == []
    assert server.shutdown_calls == 0
    assert server.closed is True
    assert worker.joined is True


def test_owned_forwarder_tracks_authorized_connects_by_required_host() -> None:
    server = _AuthenticatedForwardServer("owned-user", "owned-password")
    try:
        server.count(authorized=True, host="tls.peet.ws")
        server.count(authorized=True, host="ipwho.is")
        assert server.authorized_connects == 2
        assert server.authorized_connects_by_host == {
            "ipwho.is": 1,
            "tls.peet.ws": 1,
        }
    finally:
        server.server_close()


def test_owned_forwarder_rejects_unclassified_authorized_connect() -> None:
    server = _AuthenticatedForwardServer("owned-user", "owned-password")
    try:
        with pytest.raises(ContractError, match="authorized host"):
            server.count(authorized=True, host=None)
        assert server.authorized_connects == 0
    finally:
        server.server_close()


@pytest.mark.parametrize(
    "counts",
    [
        {"tls.peet.ws": 2, "ipwho.is": 0},
        {"tls.peet.ws": 1},
        {"tls.peet.ws": 1, "ipwho.is": True},
    ],
)
def test_authorized_host_population_must_cover_each_required_host(counts) -> None:
    class Server:
        allowed_hosts = network_smoke.NETWORK_SMOKE_REQUIRED_HOSTS
        authorized_connects_by_host = counts
        authorized_connects = sum(counts.values())

    with pytest.raises(ContractError, match="every required host"):
        network_smoke._validated_authorized_connects_by_host(Server())


@pytest.mark.parametrize(
    ("username", "password"),
    [("", "password"), ("user:name", "password"), ("user", "bad\npassword")],
)
def test_owned_forwarder_rejects_invalid_credentials(
    username: str, password: str
) -> None:
    with pytest.raises(ContractError, match="credentials"):
        _AuthenticatedForwardServer(username, password)


@pytest.mark.parametrize(
    ("username", "password"),
    [("\U0001f642" * 100, "password"), ("user", "\ud800")],
)
def test_owned_forwarder_credentials_use_strict_utf8_bytes(
    username: str,
    password: str,
) -> None:
    with pytest.raises(ContractError, match="credentials"):
        _AuthenticatedForwardServer(username, password)


def test_rejection_probe_owns_connection_without_entering_it(monkeypatch) -> None:
    class Server:
        server_address = ("127.0.0.1", 3128)

    class Connection:
        def __init__(self):
            self.closed = False

        def __enter__(self):
            raise AssertionError("implicit socket context must not be entered")

        def settimeout(self, _timeout):
            return None

        def sendall(self, _request):
            return None

        def recv(self, _maximum):
            return b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n"

        def close(self):
            self.closed = True

    connection = Connection()
    monkeypatch.setattr(
        network_smoke.socket,
        "create_connection",
        lambda *_args, **_kwargs: connection,
    )
    network_smoke._expect_proxy_rejection(
        Server(),
        b"CONNECT ipwho.is:443 HTTP/1.1\r\nHost: ipwho.is:443\r\n\r\n",
        b"HTTP/1.1 407",
    )
    assert connection.closed is True


def test_rejection_probe_rejects_partial_write_and_closes(monkeypatch) -> None:
    class Server:
        server_address = ("127.0.0.1", 3128)

    class Connection:
        def __init__(self):
            self.closed = False

        def settimeout(self, _timeout):
            return None

        def sendall(self, _request):
            return 1

        def recv(self, _maximum):
            pytest.fail("partial request write reached response read")

        def close(self):
            self.closed = True

    connection = Connection()
    monkeypatch.setattr(
        network_smoke.socket,
        "create_connection",
        lambda *_args, **_kwargs: connection,
    )
    with pytest.raises(ContractError, match="transport write is invalid"):
        network_smoke._expect_proxy_rejection(
            Server(),
            b"CONNECT ipwho.is:443 HTTP/1.1\r\nHost: ipwho.is:443\r\n\r\n",
            b"HTTP/1.1 407",
        )
    assert connection.closed is True


@pytest.mark.parametrize("slow_stage", ["connect", "send", "close"])
def test_rejection_probe_uses_one_total_deadline(
    monkeypatch: pytest.MonkeyPatch, slow_stage: str
) -> None:
    clock = [0.0]
    monkeypatch.setattr(
        network_smoke, "time", SimpleNamespace(monotonic=lambda: clock[0])
    )

    class Server:
        server_address = ("127.0.0.1", 3128)

    class Connection:
        def __init__(self) -> None:
            self.closed = False

        def settimeout(self, _timeout: float) -> None:
            return None

        def sendall(self, _body: bytes) -> None:
            if slow_stage == "send":
                clock[0] = 1.01

        def close(self) -> None:
            self.closed = True
            if slow_stage == "close":
                clock[0] = 1.01

    connection = Connection()

    def connect(*_args, **_kwargs):  # noqa: ANN002,ANN003
        if slow_stage == "connect":
            clock[0] = 1.01
        return connection

    monkeypatch.setattr(network_smoke.socket, "create_connection", connect)
    monkeypatch.setattr(
        network_smoke, "_recv_headers",
        lambda *_args, **_kwargs: b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n",
    )
    with pytest.raises(ContractError, match="deadline"):
        network_smoke._expect_proxy_rejection(
            Server(), b"CONNECT ipwho.is:443 HTTP/1.1\r\n\r\n",
            b"HTTP/1.1 407", timeout_seconds=1,
        )
    assert connection.closed


def test_rejection_probe_close_failure_blocks_expected_status(monkeypatch) -> None:
    class Server:
        server_address = ("127.0.0.1", 3128)

    class Connection:
        def settimeout(self, _timeout):
            return None

        def sendall(self, _request):
            return None

        def recv(self, _maximum):
            return b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n"

        def close(self):
            raise OSError("private rejection probe close diagnostic")

    monkeypatch.setattr(
        network_smoke.socket,
        "create_connection",
        lambda *_args, **_kwargs: Connection(),
    )
    with pytest.raises(ContractError) as raised:
        network_smoke._expect_proxy_rejection(
            Server(),
            b"CONNECT ipwho.is:443 HTTP/1.1\r\nHost: ipwho.is:443\r\n\r\n",
            b"HTTP/1.1 407",
        )
    assert str(raised.value) == (
        "network smoke rejection probe cleanup failed (connection-close)"
    )
    assert raised.value.__cause__ is None
    assert "private" not in str(raised.value)


def test_rejection_probe_cleanup_failure_retains_safe_read_failure(monkeypatch) -> None:
    class Server:
        server_address = ("127.0.0.1", 3128)

    class Connection:
        def settimeout(self, _timeout):
            return None

        def sendall(self, _request):
            return None

        def recv(self, _maximum):
            raise OSError("private rejection probe read diagnostic")

        def close(self):
            raise RuntimeError("private rejection probe close diagnostic")

    monkeypatch.setattr(
        network_smoke.socket,
        "create_connection",
        lambda *_args, **_kwargs: Connection(),
    )
    with pytest.raises(ContractError) as raised:
        network_smoke._expect_proxy_rejection(
            Server(),
            b"CONNECT ipwho.is:443 HTTP/1.1\r\nHost: ipwho.is:443\r\n\r\n",
            b"HTTP/1.1 407",
        )
    assert str(raised.value) == (
        "network smoke rejection probe cleanup failed (connection-close)"
    )
    assert isinstance(raised.value.__cause__, ContractError)
    assert str(raised.value.__cause__) == (
        "network smoke rejection probe failed (OSError)"
    )
    assert "private" not in str(raised.value)


def test_rejection_probe_rejects_huge_timeout_before_socket_contact(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        network_smoke.socket,
        "create_connection",
        lambda *_args, **_kwargs: pytest.fail("invalid timeout reached socket"),
    )
    with pytest.raises(ContractError, match="probe input is invalid"):
        network_smoke._expect_proxy_rejection(
            type("Server", (), {"server_address": ("127.0.0.1", 3128)})(),
            b"CONNECT ipwho.is:443 HTTP/1.1\r\nHost: ipwho.is:443\r\n\r\n",
            b"HTTP/1.1 407",
            timeout_seconds=10**400,
        )


def test_serialized_record_scan_proves_credentials_are_absent(tmp_path: Path) -> None:
    (tmp_path / "route.json").write_text(
        '{"username_env":"OWNED_USER"}', encoding="utf-8"
    )
    (tmp_path / "session.json").write_text(
        '{"credentials_serialized":false}', encoding="utf-8"
    )
    assert (
        _assert_credentials_not_serialized(tmp_path, ("owned-user", "owned-password"))
        == 2
    )
    (tmp_path / "session.json").write_text(
        '{"value":"owned-password"}', encoding="utf-8"
    )
    with pytest.raises(ContractError, match="credential"):
        _assert_credentials_not_serialized(tmp_path, ("owned-user", "owned-password"))


def test_serialized_record_scan_fails_closed_on_oversized_json(tmp_path: Path) -> None:
    (tmp_path / "a.json").write_bytes(b"x" * (MAX_SERIALIZED_RECORD_BYTES + 1))
    (tmp_path / "b.json").write_text("{}", encoding="utf-8")
    with pytest.raises(ContractError, match="exceeds"):
        _assert_credentials_not_serialized(tmp_path, ("owned-user", "owned-password"))


def test_serialized_record_scan_rejects_hard_linked_json(tmp_path: Path) -> None:
    first = tmp_path / "a.json"
    first.write_text("{}", encoding="utf-8")
    os.link(first, tmp_path / "b.json")
    with pytest.raises(ContractError, match="hard links"):
        _assert_credentials_not_serialized(tmp_path, ("owned-user", "owned-password"))


def test_serialized_record_scan_bounds_the_workspace_population(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(network_smoke, "MAX_WORKSPACE_ENTRIES", 2)
    for index in range(3):
        (tmp_path / f"{index}.json").write_text("{}", encoding="utf-8")
    with pytest.raises(ContractError, match="too many entries"):
        _assert_credentials_not_serialized(tmp_path, ("owned-user", "owned-password"))


def test_serialized_record_scan_stops_reading_after_remaining_limit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(network_smoke, "MAX_WORKSPACE_ENTRIES", 2)

    class Entries:
        requests = 0

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def __iter__(self):
            return self

        def __next__(self):
            self.requests += 1
            if self.requests > 3:
                pytest.fail("record inventory scanned beyond its limit")
            return SimpleNamespace(name=f"{self.requests}.json")

    entries = Entries()
    monkeypatch.setattr(network_smoke.os, "scandir", lambda _: entries)
    with pytest.raises(ContractError, match="too many entries"):
        network_smoke._serialized_record_inventory(tmp_path)
    assert entries.requests == 3


def test_serialized_record_scan_rejects_population_change(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "a.json").write_text("{}", encoding="utf-8")
    (tmp_path / "b.json").write_text("{}", encoding="utf-8")
    original = network_smoke._serialized_record_inventory
    calls = 0

    def changing_inventory(workspace: Path) -> Any:
        nonlocal calls
        calls += 1
        if calls == 2:
            (workspace / "c.json").write_text("{}", encoding="utf-8")
        return original(workspace)

    monkeypatch.setattr(
        network_smoke, "_serialized_record_inventory", changing_inventory
    )
    with pytest.raises(ContractError, match="population changed"):
        _assert_credentials_not_serialized(tmp_path, ("owned-user", "owned-password"))


def test_serialized_record_scan_rejects_population_change_during_final_rebind(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "a.json").write_text("{}", encoding="utf-8")
    (tmp_path / "b.json").write_text("{}", encoding="utf-8")
    original = network_smoke.read_bounded_control_snapshot_result
    reads = 0

    def add_record_after_final_read(*args: Any, **kwargs: Any) -> Any:
        nonlocal reads
        result = original(*args, **kwargs)
        reads += 1
        if reads == 4:
            (tmp_path / "c.json").write_text(
                '{"value":"owned-user"}', encoding="utf-8"
            )
        return result

    monkeypatch.setattr(
        network_smoke,
        "read_bounded_control_snapshot_result",
        add_record_after_final_read,
    )
    with pytest.raises(ContractError, match="population changed"):
        _assert_credentials_not_serialized(tmp_path, ("owned-user", "owned-password"))


@pytest.mark.skipif(os.name != "nt", reason="Windows creation time survives in-place edit")
def test_serialized_record_scan_rebinds_bytes_after_final_inventory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    record = tmp_path / "a.json"
    record.write_bytes(b'{"v":"safe-value"}')
    (tmp_path / "b.json").write_bytes(b"{}")
    original = network_smoke._serialized_record_inventory
    before = original(tmp_path)
    calls = 0

    def edit_during_inventory(workspace: Path) -> Any:
        nonlocal calls
        calls += 1
        if calls == 2:
            previous = record.stat()
            record.write_bytes(b'{"v":"owned-user"}')
            os.utime(record, ns=(previous.st_atime_ns, previous.st_mtime_ns))
        inventory = original(workspace)
        if calls == 2:
            assert inventory == before
        return inventory

    monkeypatch.setattr(
        network_smoke, "_serialized_record_inventory", edit_during_inventory
    )
    with pytest.raises(ContractError, match="serialized record changed"):
        _assert_credentials_not_serialized(tmp_path, ("owned-user", "owned-password"))


class _GeographyResponse:
    def __init__(self, body: bytes, *, status: int = 200) -> None:
        self.body = body
        self.status = status
        self.requested_size: int | None = None
        self.closed = False

    def __enter__(self) -> _GeographyResponse:
        return self

    def __exit__(self, *args: object) -> None:
        return None

    def close(self) -> None:
        self.closed = True

    def getcode(self) -> int:
        return self.status

    def read(self, size: int) -> bytes:
        self.requested_size = size
        return self.body[:size]


def test_expected_geography_reads_one_byte_past_the_limit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    response = _GeographyResponse(b"x" * (MAX_GEOGRAPHY_RESPONSE_BYTES + 1))
    monkeypatch.setattr(
        network_smoke, "_open_geography_request", lambda *args, **kwargs: response
    )
    with pytest.raises(ContractError, match="too large"):
        _expected_geography(1)
    assert response.requested_size == MAX_GEOGRAPHY_RESPONSE_BYTES + 1
    assert response.closed is True


def test_geography_reader_does_not_follow_an_untrusted_redirect(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target_requests: list[str] = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            if self.path == "/start":
                self.send_response(302)
                self.send_header("Location", "/target")
                self.end_headers()
            else:
                target_requests.append(self.path)
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"{}")

        def log_message(self, *_args: object) -> None:
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    monkeypatch.setenv("NO_PROXY", "127.0.0.1")
    thread.start()
    try:
        request = network_smoke.urllib.request.Request(
            f"http://127.0.0.1:{server.server_port}/start"
        )
        with pytest.raises(ContractError):
            network_smoke._read_geography_response(request, timeout_seconds=2)
        assert target_requests == []
    finally:
        server.shutdown()
        thread.join(timeout=2)
        server.server_close()


def test_expected_geography_transport_ignores_host_proxy_settings(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source_hits: list[str] = []
    proxy_hits: list[str] = []

    class Source(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            source_hits.append(self.path)
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"source")

        def log_message(self, *_args: object) -> None:
            pass

    class Proxy(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            proxy_hits.append(self.path)
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"proxy")

        def log_message(self, *_args: object) -> None:
            pass

    source = HTTPServer(("127.0.0.1", 0), Source)
    proxy = HTTPServer(("127.0.0.1", 0), Proxy)
    source_thread = threading.Thread(target=source.serve_forever, daemon=True)
    proxy_thread = threading.Thread(target=proxy.serve_forever, daemon=True)
    source_thread.start()
    proxy_thread.start()
    proxy_url = f"http://127.0.0.1:{proxy.server_port}"
    monkeypatch.setenv("http_proxy", proxy_url)
    monkeypatch.setenv("HTTP_PROXY", proxy_url)
    monkeypatch.setenv("no_proxy", "")
    monkeypatch.setenv("NO_PROXY", "")
    monkeypatch.setattr(network_smoke.urllib.request, "proxy_bypass", lambda _host: False)
    try:
        request = network_smoke.urllib.request.Request(
            f"http://127.0.0.1:{source.server_port}/geo"
        )
        response = network_smoke._open_geography_request(request, timeout=2)
        try:
            assert response.read() == b"source"
        finally:
            response.close()
        assert source_hits == ["/geo"]
        assert proxy_hits == []
    finally:
        source.shutdown()
        proxy.shutdown()
        source.server_close()
        proxy.server_close()
        source_thread.join(timeout=2)
        proxy_thread.join(timeout=2)


def test_geography_reader_stops_fragmented_body_at_deadline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = [0.0]
    monkeypatch.setattr(
        network_smoke, "time", SimpleNamespace(monotonic=lambda: clock[0])
    )

    class Response(_GeographyResponse):
        def read(self, _size: int) -> bytes:
            pytest.fail("aggregate geography read can outlive the deadline")

        def read1(self, _size: int) -> bytes:
            clock[0] += 0.06
            return b"x"

    response = Response(b"unused")
    monkeypatch.setattr(
        network_smoke,
        "_open_geography_request",
        lambda *_args, **_kwargs: response,
    )
    request = network_smoke.urllib.request.Request("https://ipwho.is/")
    with pytest.raises(ContractError, match="deadline"):
        network_smoke._read_geography_response(request, timeout_seconds=0.1)
    assert response.closed


def test_geography_reader_rejects_response_closed_after_deadline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = [0.0]
    monkeypatch.setattr(
        network_smoke, "time", SimpleNamespace(monotonic=lambda: clock[0])
    )

    class SlowClose(_GeographyResponse):
        def close(self) -> None:
            super().close()
            clock[0] = 1.01

    response = SlowClose(b"{}")
    monkeypatch.setattr(
        network_smoke, "_open_geography_request",
        lambda *_args, **_kwargs: response,
    )
    request = network_smoke.urllib.request.Request("https://ipwho.is/")
    with pytest.raises(ContractError, match="deadline"):
        network_smoke._read_geography_response(request, timeout_seconds=1)
    assert response.closed


def test_geography_reader_rejects_complete_json_in_short_declared_body(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class ShortResponse(_GeographyResponse):
        def __init__(self) -> None:
            super().__init__(b"{}")
            self.length = 4
            self.offset = 0

        def read1(self, maximum: int) -> bytes:
            block = self.body[self.offset : self.offset + maximum]
            self.offset += len(block)
            self.length -= len(block)
            return block

    response = ShortResponse()
    monkeypatch.setattr(
        network_smoke, "_open_geography_request", lambda *_a, **_k: response
    )
    request = network_smoke.urllib.request.Request("https://ipwho.is/")

    with pytest.raises(ContractError, match="declared length"):
        network_smoke._read_geography_response(request, timeout_seconds=1)
    assert response.closed


def test_geography_reader_closes_http_error_response(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    body = io.BytesIO(b"private geography error body")
    error = urllib.error.HTTPError("https://ipwho.is/", 503, "private", {}, body)

    def raise_error(*_args: object, **_kwargs: object) -> None:
        raise error

    monkeypatch.setattr(network_smoke, "_open_geography_request", raise_error)
    request = network_smoke.urllib.request.Request("https://ipwho.is/")
    with pytest.raises(
        ContractError,
        match=r"network smoke could not discover expected geography \(HTTPError\)",
    ):
        network_smoke._read_geography_response(request, timeout_seconds=1)
    assert body.closed


def test_expected_geography_owns_response_without_entering_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class EnterRejectingResponse(_GeographyResponse):
        def __enter__(self) -> _GeographyResponse:
            raise AssertionError("implicit response context must not be entered")

    response = EnterRejectingResponse(
        b'{"country_code":"US","timezone":{"id":"America/Chicago"}}'
    )
    monkeypatch.setattr(
        network_smoke,
        "_open_geography_request",
        lambda *_args, **_kwargs: response,
    )

    assert _expected_geography(1) == {
        "country": "US",
        "locale": "en-US",
        "timezone": "America/Chicago",
    }
    assert response.closed is True


@pytest.mark.parametrize(
    "status",
    [True, "200", 204, None, type("StatusSubclass", (int,), {})(200)],
)
def test_expected_geography_rejects_status_before_body_read(
    monkeypatch: pytest.MonkeyPatch,
    status,
) -> None:
    response = _GeographyResponse(b'[{"private":"body"}]')
    response.status = status
    monkeypatch.setattr(
        network_smoke,
        "_open_geography_request",
        lambda *_args, **_kwargs: response,
    )

    with pytest.raises(ContractError) as raised:
        _expected_geography(1)

    assert str(raised.value) == (
        "network smoke geography discovery returned an unexpected status"
    )
    assert response.requested_size is None
    assert response.closed is True
    assert "private" not in str(raised.value)


@pytest.mark.parametrize("timeout", [True, 0, float("nan"), 301, 10**400])
def test_geography_response_reader_rejects_timeout_before_contact(
    monkeypatch: pytest.MonkeyPatch,
    timeout,
) -> None:
    monkeypatch.setattr(
        network_smoke,
        "_open_geography_request",
        lambda *_args, **_kwargs: pytest.fail("invalid timeout reached transport"),
    )
    with pytest.raises(ContractError, match="timeout"):
        network_smoke._read_geography_response(
            network_smoke.urllib.request.Request("https://ipwho.is/"),
            timeout_seconds=timeout,
        )


def test_expected_geography_rejects_valid_reply_when_close_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class CloseFailingResponse(_GeographyResponse):
        def close(self) -> None:
            raise OSError("private geography close diagnostic")

    response = CloseFailingResponse(
        b'{"country_code":"US","timezone":{"id":"America/Chicago"}}'
    )
    monkeypatch.setattr(
        network_smoke,
        "_open_geography_request",
        lambda *_args, **_kwargs: response,
    )

    with pytest.raises(ContractError) as raised:
        _expected_geography(1)
    assert str(raised.value) == (
        "network smoke geography cleanup failed (response-close)"
    )
    assert raised.value.__cause__ is None
    assert "private" not in str(raised.value)


def test_expected_geography_cleanup_failure_retains_only_safe_read_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class ReadCloseFailingResponse(_GeographyResponse):
        def read(self, _size: int) -> bytes:
            raise RuntimeError("private geography read diagnostic")

        def close(self) -> None:
            raise ValueError("private geography close diagnostic")

    response = ReadCloseFailingResponse(b"")
    monkeypatch.setattr(
        network_smoke,
        "_open_geography_request",
        lambda *_args, **_kwargs: response,
    )

    with pytest.raises(ContractError) as raised:
        _expected_geography(1)
    assert str(raised.value) == (
        "network smoke geography cleanup failed (response-close)"
    )
    assert isinstance(raised.value.__cause__, ContractError)
    assert str(raised.value.__cause__) == (
        "network smoke could not discover expected geography (RuntimeError)"
    )
    assert "private" not in str(raised.value)


@pytest.mark.parametrize(
    "timeout", [True, 0, float("nan"), float("inf"), "1", 10**400]
)
def test_expected_geography_rejects_invalid_timeout_before_contact(
    monkeypatch: pytest.MonkeyPatch,
    timeout: object,
) -> None:
    contacted = False

    def forbidden(*_args, **_kwargs):
        nonlocal contacted
        contacted = True
        raise AssertionError("network contact")

    monkeypatch.setattr(network_smoke, "_open_geography_request", forbidden)
    with pytest.raises(ContractError, match="geography timeout"):
        _expected_geography(timeout)  # type: ignore[arg-type]
    assert contacted is False


def test_expected_geography_requires_byte_body(monkeypatch: pytest.MonkeyPatch) -> None:
    response = _GeographyResponse(b"{}")
    response.read = lambda _size: "private-body"  # type: ignore[method-assign]
    monkeypatch.setattr(
        network_smoke,
        "_open_geography_request",
        lambda *_args, **_kwargs: response,
    )
    with pytest.raises(ContractError, match="response is invalid") as failure:
        _expected_geography(1)
    assert "private-body" not in str(failure.value)


@pytest.mark.parametrize(
    "body",
    [
        b'{"country_code":"US","country_code":"CA","timezone":{"id":"America/Chicago"}}',
        b'{"country_code":"US","timezone":{"id":NaN}}',
        b'{"country_code":"US","latitude":1e400,"timezone":{"id":"America/Chicago"}}',
        b'{"country_code":"us","timezone":{"id":"America/Chicago"}}',
        b'{"country_code":"US","timezone":{"id":"bad timezone"}}',
    ],
)
def test_expected_geography_rejects_ambiguous_or_invalid_json(
    body: bytes, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        network_smoke,
        "_open_geography_request",
        lambda *args, **kwargs: _GeographyResponse(body),
    )
    with pytest.raises(ContractError, match="geography"):
        _expected_geography(1)


@pytest.mark.parametrize(
    "timeout", [True, 0, -1, float("nan"), float("inf"), 301, "1", 10**400]
)
def test_network_gateway_smoke_rejects_invalid_config_before_network_access(
    timeout: object, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        network_smoke,
        "_expected_geography",
        lambda value: pytest.fail("geography lookup must not run"),
    )
    config = NetworkGatewaySmoke(Path("browser"), tmp_path, timeout)  # type: ignore[arg-type]
    with pytest.raises(ContractError, match="timeout"):
        run_network_gateway_smoke(config, tmp_path)


@pytest.mark.skipif(os.name != "nt", reason="Windows directory junction boundary")
def test_network_gateway_smoke_rejects_linked_workspace_before_route_write(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    foreign = tmp_path / "foreign"
    foreign.mkdir()
    workspace = tmp_path / "workspace"
    created = subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(workspace), str(foreign)],
        capture_output=True, check=False,
    )
    if created.returncode:
        pytest.skip("host could not create an unprivileged directory junction")
    started = []

    class FakeForwarder:
        server_address = ("127.0.0.1", 12345)

        def __init__(self, *_args: object) -> None:
            started.append(True)

        def serve_forever(self) -> None:
            pass

        def shutdown(self) -> None:
            pass

        def server_close(self) -> None:
            pass

    monkeypatch.setattr(network_smoke, "_AuthenticatedForwardServer", FakeForwarder)
    monkeypatch.setattr(
        network_smoke,
        "_expected_geography",
        lambda _timeout: {
            "country": "US", "locale": "en-US", "timezone": "America/Chicago"
        },
    )
    monkeypatch.setattr(
        network_smoke,
        "_expect_proxy_rejection",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            ContractError("synthetic probe stop")
        ),
    )
    try:
        with pytest.raises(ContractError):
            run_network_gateway_smoke(
                NetworkGatewaySmoke(Path("browser"), workspace, 5.0), tmp_path
            )
        assert list(foreign.iterdir()) == []
        assert started == []
    finally:
        workspace.rmdir()


def test_network_gateway_smoke_spends_one_shared_deadline(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = [100.0]
    budgets = []

    class FakeServer:
        expected_authorization = "Basic owned"
        server_address = ("127.0.0.1", 12345)
        authorized_connects = 2
        authorized_connects_by_host = {"tls.peet.ws": 1, "ipwho.is": 1}
        rejected_connects = 2
        allowed_hosts = frozenset({"tls.peet.ws", "ipwho.is"})

        def __init__(self, _username: str, _password: str) -> None:
            pass

        def serve_forever(self) -> None:
            return

        def shutdown(self) -> None:
            return

        def server_close(self) -> None:
            return

    monkeypatch.setattr(network_smoke.time, "monotonic", lambda: clock[0])

    def geography(timeout):  # noqa: ANN001
        budgets.append(("geography", timeout))
        clock[0] += 5
        return {"country": "US", "locale": "en-US", "timezone": "America/Chicago"}

    def rejection(_server, _request, _status, *, timeout_seconds):  # noqa: ANN001
        budgets.append(("rejection", timeout_seconds))
        clock[0] += 3

    session = {
        "run_id": "network-smoke-run",
        "network": {
            "realization": {"passed": True},
            "gateway": {
                "lease_path": str(tmp_path / "absent-lease.json"),
                "endpoint": "http://127.0.0.1:12345",
            },
            "runtime_identity": {},
        },
    }

    def launch(config, _root):  # noqa: ANN001
        budgets.append(("launch", config.timeout_seconds))
        clock[0] += 4
        return tmp_path / "session.json", session

    def stop(_path, *, timeout_seconds):  # noqa: ANN001
        budgets.append(("stop", timeout_seconds))
        return {
            "run_id": "network-smoke-run",
            "state": "stopped",
            "running": False,
            "identity_protected": True,
        }

    monkeypatch.setattr(network_smoke, "_expected_geography", geography)
    monkeypatch.setattr(network_smoke, "_AuthenticatedForwardServer", FakeServer)
    monkeypatch.setattr(network_smoke, "_expect_proxy_rejection", rejection)
    monkeypatch.setattr(
        network_smoke,
        "build_network_route",
        lambda **_kwargs: {"integrity_sha256": "a" * 64},
    )
    monkeypatch.setattr(network_smoke, "add_network_route", lambda *_args: None)
    monkeypatch.setattr(network_smoke, "launch_evaluation", launch)
    monkeypatch.setattr(network_smoke, "stop_session", stop)
    validated: list[tuple[object, str]] = []
    real_validate = network_smoke.validate_stopped_session_receipt

    def validate(value, *, expected_run_id):  # noqa: ANN001
        validated.append((value, expected_run_id))
        return real_validate(value, expected_run_id=expected_run_id)

    monkeypatch.setattr(network_smoke, "validate_stopped_session_receipt", validate)
    monkeypatch.setattr(
        network_smoke,
        "_assert_credentials_not_serialized",
        lambda *_args: 2,
    )

    result = run_network_gateway_smoke(
        NetworkGatewaySmoke(Path("browser"), tmp_path, timeout_seconds=20),
        tmp_path,
    )
    assert result["status"] == "passed"
    assert result["upstream"]["authorized_connects_by_host"] == {
        "ipwho.is": 1,
        "tls.peet.ws": 1,
    }
    assert len(validated) == 1
    assert validated[0][1] == "network-smoke-run"
    assert budgets == [
        ("geography", pytest.approx(20.0)),
        ("rejection", pytest.approx(5.0)),
        ("rejection", pytest.approx(5.0)),
        ("launch", pytest.approx(9.0)),
        ("stop", pytest.approx(5.0)),
    ]

    if os.name == "nt":
        target = tmp_path / "lease-target"
        target.mkdir()
        lease = tmp_path / "dangling-lease.json"
        created = subprocess.run(
            ["cmd", "/c", "mklink", "/J", str(lease), str(target)],
            capture_output=True, check=False,
        )
        if created.returncode:
            pytest.skip("host could not create an unprivileged directory junction")
        target.rmdir()
        try:
            assert os.path.lexists(lease) and not lease.exists()
            session["network"]["gateway"]["lease_path"] = str(lease)
            with pytest.raises(ContractError, match="credential sidecar lease"):
                run_network_gateway_smoke(
                    NetworkGatewaySmoke(Path("browser"), tmp_path, timeout_seconds=20),
                    tmp_path,
                )
            assert os.path.lexists(lease)
        finally:
            lease.rmdir()


def test_network_forwarder_construction_failure_closes_listener(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FakeServer:
        def __init__(self, _username: str, _password: str) -> None:
            self.closed = False

        def serve_forever(self) -> None:
            return

        def server_close(self) -> None:
            self.closed = True

    holder = {}

    def server_factory(username, password):  # noqa: ANN001
        holder["server"] = FakeServer(username, password)
        return holder["server"]

    private = "private-thread-constructor"
    monkeypatch.setattr(
        network_smoke,
        "_expected_geography",
        lambda _timeout: {
            "country": "US",
            "locale": "en-US",
            "timezone": "America/Chicago",
        },
    )
    monkeypatch.setattr(network_smoke, "_AuthenticatedForwardServer", server_factory)
    monkeypatch.setattr(
        network_smoke.threading,
        "Thread",
        lambda **_kwargs: (_ for _ in ()).throw(RuntimeError(private)),
    )
    with pytest.raises(ContractError) as failure:
        run_network_gateway_smoke(
            NetworkGatewaySmoke(Path("browser"), tmp_path),
            tmp_path,
        )
    assert (
        str(failure.value) == "network smoke forwarder could not start (RuntimeError)"
    )
    assert private not in str(failure.value)
    assert holder["server"].closed is True


def test_network_forwarder_started_then_reported_failure_is_stopped(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    original_thread = threading.Thread
    holder: dict[str, Any] = {}

    class Server:
        def __init__(self, _username: str, _password: str) -> None:
            self.done = threading.Event()
            self.closed = False
            self.shutdown_called = False

        def serve_forever(self) -> None:
            self.done.wait(5)

        def shutdown(self) -> None:
            self.shutdown_called = True
            self.done.set()

        def server_close(self) -> None:
            self.closed = True

    class StartedThenRaisedThread(original_thread):
        def start(self) -> None:
            super().start()
            raise RuntimeError("thread started but caller saw an error")

    def make_thread(**kwargs):  # noqa: ANN003
        worker = (StartedThenRaisedThread if kwargs.get("name") == "browser-core-owned-auth-proxy"
                  else original_thread)(**kwargs)
        if isinstance(worker, StartedThenRaisedThread):
            holder["worker"] = worker
        return worker

    def make_server(username, password):  # noqa: ANN001
        server = Server(username, password)
        holder["server"] = server
        return server

    monkeypatch.setattr(network_smoke, "_expected_geography", lambda _timeout: {
        "country": "US", "locale": "en-US", "timezone": "America/Chicago",
    })
    monkeypatch.setattr(network_smoke, "_AuthenticatedForwardServer", make_server)
    monkeypatch.setattr(network_smoke.threading, "Thread", make_thread)
    try:
        with pytest.raises(ContractError, match="forwarder could not start"):
            run_network_gateway_smoke(
                NetworkGatewaySmoke(Path("browser"), tmp_path), tmp_path
            )
        assert holder["server"].shutdown_called
        assert holder["server"].closed
        assert not holder["worker"].is_alive()
    finally:
        if "server" in holder:
            holder["server"].done.set()
        if "worker" in holder:
            holder["worker"].join(5)


def test_network_forwarder_cleanup_runs_every_phase() -> None:
    events = []

    class Server:
        def shutdown(self):
            events.append("shutdown")
            raise OSError("private-shutdown")

        def server_close(self):
            events.append("close")
            raise OSError("private-close")

    class Worker:
        def join(self, *, timeout):
            events.append(("join", timeout))

        def is_alive(self):
            return True

    failures = network_smoke._stop_forwarder(Server(), Worker(), started=True)
    assert failures == ["forwarder-shutdown", "forwarder-close", "forwarder-thread"]
    assert events == [
        "shutdown",
        "close",
        ("join", network_smoke.NETWORK_SMOKE_CLEANUP_TIMEOUT_SECONDS),
    ]


def test_network_forwarder_reclaims_shutdown_thread_after_late_start_error(
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

        def join(self, *, timeout: float) -> None:
            self.joined = True

        def is_alive(self) -> bool:
            return not self.joined

    monkeypatch.setattr(network_smoke.threading, "Thread", ShutdownThread)
    monkeypatch.setattr(network_smoke, "NETWORK_SMOKE_CLEANUP_TIMEOUT_SECONDS", 0.1)
    server = Server()
    worker = Worker()
    failures = network_smoke._stop_forwarder(server, worker, started=True)

    assert failures == ["forwarder-shutdown"]
    assert server.closed is True
    assert worker.joined is True
    assert threads[0].joined is True
    assert threads[0].is_alive() is False


def test_network_cleanup_failure_overrides_primary_after_environment_restore(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FakeServer:
        expected_authorization = "Basic owned"
        server_address = ("127.0.0.1", 12345)

        def __init__(self, _username: str, _password: str) -> None:
            pass

        def serve_forever(self) -> None:
            return

    monkeypatch.setattr(
        network_smoke,
        "_expected_geography",
        lambda _timeout: {
            "country": "US",
            "locale": "en-US",
            "timezone": "America/Chicago",
        },
    )
    monkeypatch.setattr(network_smoke, "_AuthenticatedForwardServer", FakeServer)
    monkeypatch.setattr(
        network_smoke,
        "build_network_route",
        lambda **_kwargs: {"integrity_sha256": "a" * 64},
    )
    monkeypatch.setattr(network_smoke, "add_network_route", lambda *_args: None)
    monkeypatch.setattr(
        network_smoke,
        "_expect_proxy_rejection",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            ContractError("private-primary")
        ),
    )
    monkeypatch.setattr(
        network_smoke,
        "_stop_forwarder",
        lambda *_args, **_kwargs: ["forwarder-close"],
    )
    user_env = "BROWSER_CORE_SMOKE_PROXY_USER"
    password_env = "BROWSER_CORE_SMOKE_PROXY_PASSWORD"
    monkeypatch.setenv(user_env, "prior-user")
    monkeypatch.setenv(password_env, "prior-password")
    with pytest.raises(
        ContractError,
        match=r"cleanup failed \(forwarder-close\)",
    ) as failure:
        run_network_gateway_smoke(
            NetworkGatewaySmoke(Path("browser"), tmp_path),
            tmp_path,
        )
    assert "private-primary" not in str(failure.value)
    assert isinstance(failure.value.__cause__, ContractError)
    assert os.environ[user_env] == "prior-user"
    assert os.environ[password_env] == "prior-password"


def test_network_gateway_smoke_restores_environment_and_server_on_probe_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class FakeServer:
        expected_authorization = "Basic owned"
        server_address = ("127.0.0.1", 12345)
        authorized_connects = 0
        rejected_connects = 0
        allowed_hosts = frozenset({"tls.peet.ws", "ipwho.is"})

        def __init__(self, username: str, password: str) -> None:
            self.shutdown_called = False
            self.close_called = False

        def serve_forever(self) -> None:
            return

        def shutdown(self) -> None:
            self.shutdown_called = True

        def server_close(self) -> None:
            self.close_called = True

    holder: dict[str, FakeServer] = {}

    def make_server(username: str, password: str) -> FakeServer:
        holder["server"] = FakeServer(username, password)
        return holder["server"]

    monkeypatch.setattr(network_smoke, "_AuthenticatedForwardServer", make_server)
    monkeypatch.setattr(
        network_smoke,
        "_expected_geography",
        lambda timeout: {
            "country": "US",
            "locale": "en-US",
            "timezone": "America/Chicago",
        },
    )
    monkeypatch.setattr(
        network_smoke,
        "build_network_route",
        lambda **kwargs: {"integrity_sha256": "a" * 64},
    )
    monkeypatch.setattr(network_smoke, "add_network_route", lambda *args: None)
    monkeypatch.setattr(
        network_smoke,
        "_expect_proxy_rejection",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            ContractError("owned probe failure")
        ),
    )
    user_env = "BROWSER_CORE_SMOKE_PROXY_USER"
    password_env = "BROWSER_CORE_SMOKE_PROXY_PASSWORD"
    monkeypatch.setenv(user_env, "prior-user")
    monkeypatch.setenv(password_env, "prior-password")

    with pytest.raises(ContractError, match="owned probe failure"):
        run_network_gateway_smoke(
            NetworkGatewaySmoke(Path("browser"), tmp_path), tmp_path
        )

    assert holder["server"].shutdown_called is False
    assert holder["server"].close_called is True
    assert os.environ[user_env] == "prior-user"
    assert os.environ[password_env] == "prior-password"
