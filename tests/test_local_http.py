from __future__ import annotations

import socket
import threading
import time
from http.server import BaseHTTPRequestHandler

import pytest

import browser_core.local_http as local_http


def test_local_panel_releases_idle_incomplete_header(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(local_http, "LOCAL_PANEL_HEADER_TIMEOUT_SECONDS", 0.1, raising=False)

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args: object) -> None:
            return

        def do_GET(self) -> None:
            self.send_response(200)
            self.end_headers()

    server = local_http.LocalPanelServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with socket.create_connection(server.server_address, timeout=1) as client:
            client.settimeout(0.5)
            client.sendall(b"GET / HTTP/1.1\r\nHost: localhost\r\n")
            try:
                result = client.recv(1)
            except OSError as exc:
                assert not isinstance(exc, TimeoutError)
            else:
                assert result == b""
    finally:
        server.server_close()
        thread.join(timeout=1)
    assert not thread.is_alive()


def test_local_panel_header_trickle_has_total_deadline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(local_http, "LOCAL_PANEL_HEADER_TIMEOUT_SECONDS", 0.5)

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args: object) -> None:
            return

        def do_GET(self) -> None:
            self.send_response(200)
            self.end_headers()

    server = local_http.LocalPanelServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with socket.create_connection(server.server_address, timeout=1) as client:
            client.settimeout(1)
            client.sendall(b"GET / HTTP/1.1\r\nHost: localhost\r\n")
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
    finally:
        server.server_close()
        thread.join(timeout=1)
    assert not thread.is_alive()


def test_local_panel_rejects_aggregate_header_bytes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(local_http, "MAX_HTTP_HEADER_BYTES", 256, raising=False)

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args: object) -> None:
            return

        def do_GET(self) -> None:
            self.send_response(200)
            self.end_headers()

    server = local_http.LocalPanelServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with socket.create_connection(server.server_address, timeout=1) as client:
            client.settimeout(1)
            client.sendall(
                b"GET / HTTP/1.1\r\nHost: localhost\r\n"
                + b"X-Pad-A: " + b"a" * 120 + b"\r\n"
                + b"X-Pad-B: " + b"b" * 120 + b"\r\n\r\n"
            )
            try:
                response = client.recv(4096)
            except OSError:
                response = b""
            assert b" 200 " not in response
    finally:
        server.server_close()
        thread.join(timeout=1)
    assert not thread.is_alive()
