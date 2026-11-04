"""The owned loopback panels must stop without waiting for idle clients."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import socket
from threading import Event, Thread
from types import SimpleNamespace

import pytest

import browser_core.inspection_ui as inspection_ui
import browser_core.research_picker as research_picker
from browser_core.local_http import LocalPanelServer
from browser_core.contracts import ContractError

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(params=['inspector', 'picker'])
def local_panel(request, tmp_path):
    if request.param == 'inspector':
        server, _ = inspection_ui._create_panel(
            None, SimpleNamespace(close=lambda: None), None)
    else:
        server, _ = research_picker.create_research_picker(tmp_path/'workspace', ROOT)
    yield server
    server.server_close()


def test_shutdown_wakes_a_long_idle_server_wait(local_panel):
    server = local_panel
    entered = Event()
    server.service_actions = entered.set
    loop = Thread(target=server.serve_forever, kwargs={'poll_interval': 30}, daemon=True)
    loop.start()
    # One harmless connection proves the server has entered its selector loop.
    with socket.create_connection(server.server_address, timeout=2):
        pass
    assert entered.wait(2)
    finished = Event()
    stopper = Thread(target=lambda: (server.shutdown(), finished.set()), daemon=True)
    stopper.start()
    try:
        assert finished.wait(1), 'shutdown still depends on the idle polling interval'
    finally:
        # Release the old implementation's selector on a failed baseline run.
        if not finished.is_set():
            try:
                with socket.create_connection(server.server_address, timeout=2):
                    pass
            except OSError:
                pass
        stopper.join(3)
        loop.join(3)
        assert not stopper.is_alive() and not loop.is_alive()


@pytest.mark.parametrize('socket_timeout', [None, 30])
def test_close_releases_an_owned_client_waiting_to_send_headers(local_panel, socket_timeout):
    server = local_panel
    accepted = Event()
    handler_finished = Event()
    original = server.RequestHandlerClass.handle

    def handle(handler):
        handler.connection.settimeout(socket_timeout)
        accepted.set()
        try:
            return original(handler)
        finally:
            handler_finished.set()

    server.RequestHandlerClass.handle = handle
    loop = Thread(target=server.serve_forever, kwargs={'poll_interval': .01}, daemon=True)
    loop.start()
    client = socket.create_connection(server.server_address, timeout=2)
    try:
        assert accepted.wait(2)
        server.shutdown()
        server.server_close()
        loop.join(2)
        assert not loop.is_alive()
        assert handler_finished.wait(1), 'closed panel left a request thread and socket alive'
    finally:
        client.close()
        if loop.is_alive():
            server.shutdown()
            loop.join(2)
        handler_finished.wait(2)


def test_shutdown_before_server_thread_starts_is_bounded(local_panel):
    server = local_panel
    finished = Event()
    stopper = Thread(target=lambda: (server.shutdown(), finished.set()), daemon=True)
    stopper.start()
    try:
        assert finished.wait(1), 'shutdown blocks forever if serve_forever never started'
    finally:
        if not finished.is_set():
            loop = Thread(target=server.serve_forever, kwargs={'poll_interval': .01}, daemon=True)
            loop.start()
            loop.join(2)
        stopper.join(2)
        assert not stopper.is_alive()


def test_panel_close_retries_failed_client_detach_without_leaking_wake_sockets():
    server = LocalPanelServer(('127.0.0.1', 0), BaseHTTPRequestHandler)

    class Connection:
        attempts = 0

        def shutdown(self, _how):
            raise OSError('already closed')

        def detach(self):
            self.attempts += 1
            if self.attempts == 1:
                raise OSError('transient detach failure')
            return -1

    connection = Connection()
    server._panel_connections.add(connection)
    with pytest.raises(OSError, match='transient detach failure'):
        server.server_close()
    assert server._panel_wake_read.fileno() == -1
    assert server._panel_wake_write.fileno() == -1
    server.server_close()
    assert connection.attempts == 2
    assert server._panel_closed


def test_panel_close_attempts_all_clients_when_detach_fails():
    server = LocalPanelServer(('127.0.0.1', 0), BaseHTTPRequestHandler)

    class Connection:
        def __init__(self):
            self.attempts = 0

        def shutdown(self, _how):
            pass

        def detach(self):
            self.attempts += 1
            if self.attempts == 1:
                raise OSError('transient detach failure')
            return -1

    connections = [Connection(), Connection()]
    server._panel_connections.update(connections)
    with pytest.raises(OSError, match='transient detach failure'):
        server.server_close()
    assert [connection.attempts for connection in connections] == [1, 1]
    assert not server._panel_closed
    assert server._panel_wake_read.fileno() == -1
    assert server._panel_wake_write.fileno() == -1

    server.server_close()
    assert [connection.attempts for connection in connections] == [2, 2]
    assert server._panel_closed


def test_dispatch_failure_releases_accepted_panel_connection(monkeypatch):
    server = LocalPanelServer(('127.0.0.1', 0), BaseHTTPRequestHandler)
    accepted, peer = socket.socketpair()

    def fail_dispatch(_server, _request, _address):
        raise RuntimeError('request worker could not start')

    monkeypatch.setattr(ThreadingHTTPServer, 'process_request', fail_dispatch)
    try:
        with pytest.raises(RuntimeError, match='request worker could not start'):
            server.process_request(accepted, ('127.0.0.1', 1))
        assert accepted.fileno() == -1
        assert not server._panel_connections
    finally:
        accepted.close()
        peer.close()
        server.server_close()


def test_panel_close_releases_owned_sockets_after_shutdown_failure(monkeypatch):
    server = LocalPanelServer(('127.0.0.1', 0), BaseHTTPRequestHandler)
    accepted, peer = socket.socketpair()
    server._panel_connections.add(accepted)

    def fail_shutdown():
        raise ContractError('panel loop did not stop')

    monkeypatch.setattr(server, 'shutdown', fail_shutdown)
    try:
        with pytest.raises(ContractError, match='panel loop did not stop'):
            server.server_close()
        assert server.fileno() == -1
        assert accepted.fileno() == -1
        assert server._panel_wake_read.fileno() == -1
        assert server._panel_wake_write.fileno() == -1
    finally:
        accepted.close()
        peer.close()


def test_picker_close_runs_after_server_shutdown_failure(monkeypatch, tmp_path):
    server, _ = research_picker.create_research_picker(tmp_path/'workspace', ROOT)
    closed = []
    monkeypatch.setattr(server.picker, 'close', lambda: closed.append(True))

    def fail_shutdown():
        raise ContractError('panel loop did not stop')

    monkeypatch.setattr(server, 'shutdown', fail_shutdown)
    with pytest.raises(ContractError, match='panel loop did not stop'):
        server.server_close()
    assert closed == [True]
