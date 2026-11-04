"""One-use local HTTP servers with explicit loop and connection ownership."""
from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import selectors
import socket
import sys
from threading import Event, Lock, RLock, get_ident
import time
from typing import Any

from .contracts import ContractError


LOCAL_PANEL_HEADER_TIMEOUT_SECONDS = 5.0
MAX_HTTP_HEADER_BYTES = 64 * 1024


class _HeaderDeadlineReader:
    """Apply one deadline across the request line and all header lines."""

    def __init__(self, stream: Any, handler: BaseHTTPRequestHandler) -> None:
        self._stream = stream
        self._handler = handler
        self._header_bytes = 0

    def reset_header_count(self) -> None:
        self._header_bytes = 0

    def readline(self, *args: Any, **kwargs: Any) -> bytes:
        deadline = self._handler._header_deadline
        if deadline is not None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("request header deadline exceeded")
            self._handler.connection.settimeout(remaining)
        line = self._stream.readline(*args, **kwargs)
        if deadline is not None:
            self._header_bytes += len(line)
            if self._header_bytes > MAX_HTTP_HEADER_BYTES:
                raise TimeoutError("request headers exceeded the byte limit")
        if deadline is not None and time.monotonic() >= deadline:
            raise TimeoutError("request header deadline exceeded")
        return line

    def __getattr__(self, name: str) -> Any:
        return getattr(self._stream, name)


class _LocalPanelHeaderDeadline:
    def setup(self) -> None:
        super().setup()
        self._header_deadline = None
        self.rfile = _HeaderDeadlineReader(self.rfile, self)

    def handle_one_request(self) -> None:
        self._header_deadline = time.monotonic() + LOCAL_PANEL_HEADER_TIMEOUT_SECONDS
        self.rfile.reset_header_count()
        try:
            super().handle_one_request()
        finally:
            self._header_deadline = None

    def parse_request(self) -> bool:
        parsed = super().parse_request()
        self._header_deadline = None
        self.connection.settimeout(LOCAL_PANEL_HEADER_TIMEOUT_SECONDS)
        return parsed


class LocalPanelServer(ThreadingHTTPServer):
    """Wake directly on shutdown and release only this server's client sockets.

    These panels have no periodic server-side work. They run once; shutdown
    before serve_forever also retires the server. Request handlers retain their
    own operation deadlines, while incomplete socket reads are interrupted at
    close. Stopping this HTTP loop does not stop or verify a browser.
    """
    daemon_threads = True

    def __init__(self, server_address, RequestHandlerClass, bind_and_activate=True):
        self._panel_state = RLock()
        self._panel_close = Lock()
        self._panel_stopping = Event()
        self._panel_done = Event()
        self._panel_done.set()
        self._panel_loop_owner = None
        self._panel_closed = False
        self._panel_connections = set()
        self._panel_wake_read, self._panel_wake_write = socket.socketpair()
        self._panel_wake_read.setblocking(False)
        self._panel_wake_write.setblocking(False)
        try:
            bounded_handler = type(
                f"Bounded{RequestHandlerClass.__name__}",
                (_LocalPanelHeaderDeadline, RequestHandlerClass),
                {},
            )
            super().__init__(
                server_address, bounded_handler, bind_and_activate=bind_and_activate
            )
        except BaseException:
            self._panel_wake_read.close()
            self._panel_wake_write.close()
            raise

    def serve_forever(self, poll_interval=.5):
        # Keep the BaseServer call signature, but no timer is needed to poll
        # for shutdown: a private socket wakes the same selector immediately.
        with self._panel_state:
            if self._panel_stopping.is_set():
                return
            if self._panel_loop_owner is not None:
                raise ContractError('local panel is already serving')
            self._panel_loop_owner = get_ident()
            self._panel_done.clear()
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(self, selectors.EVENT_READ)
                selector.register(self._panel_wake_read, selectors.EVENT_READ)
                while not self._panel_stopping.is_set():
                    ready = selector.select()
                    if self._panel_stopping.is_set():
                        break
                    for key, _events in ready:
                        if key.fileobj is self:
                            self._handle_request_noblock()
                    self.service_actions()
        finally:
            with self._panel_state:
                self._panel_stopping.set()
                self._panel_loop_owner = None
                self._panel_done.set()

    def shutdown(self):
        with self._panel_state:
            self._panel_stopping.set()
            if self._panel_loop_owner == get_ident():
                # Calling from the loop itself must not wait on itself.
                return
            if self._panel_loop_owner is None:
                return
            try:
                self._panel_wake_write.send(b'\0')
            except BlockingIOError:
                pass  # A pending wake byte already makes the selector ready.
        if not self._panel_done.wait(5):
            raise ContractError('local panel server loop did not stop')

    def process_request(self, request, client_address):
        with self._panel_state:
            if self._panel_stopping.is_set():
                self.shutdown_request(request)
                return
            self._panel_connections.add(request)
        try:
            super().process_request(request, client_address)
        except BaseException:
            # Thread creation can fail after accept. No handler then owns the
            # socket, so release it here instead of retaining it until close.
            self.shutdown_request(request)
            raise

    def get_request(self):
        request, address = super().get_request()
        try:
            # BaseHTTPRequestHandler reads the request line and headers before
            # any endpoint-specific body deadline can run.
            request.settimeout(LOCAL_PANEL_HEADER_TIMEOUT_SECONDS)
        except BaseException:
            request.close()
            raise
        return request, address

    def handle_error(self, request, client_address):
        if self._panel_stopping.is_set():
            return
        # A peer can close while BaseHTTPRequestHandler is reading the next
        # request on a keep-alive socket. This is an ordinary disconnect.
        if isinstance(
            sys.exc_info()[1],
            (BrokenPipeError, ConnectionResetError, ConnectionAbortedError),
        ):
            return
        super().handle_error(request, client_address)

    def shutdown_request(self, request):
        with self._panel_state:
            try:
                super().shutdown_request(request)
            finally:
                self._panel_connections.discard(request)

    def server_close(self):
        with self._panel_close:
            shutdown_error: BaseException | None = None
            try:
                self.shutdown()
            except BaseException as exc:
                shutdown_error = exc
            with self._panel_state:
                if self._panel_closed:
                    if shutdown_error is not None:
                        raise shutdown_error
                    return
                connections = tuple(self._panel_connections)
            connection_error: BaseException | None = None
            try:
                try:
                    super().server_close()
                finally:
                    for connection in connections:
                        try:
                            with self._panel_state:
                                try:
                                    connection.shutdown(socket.SHUT_RDWR)
                                except OSError:
                                    pass
                                # BaseHTTPRequestHandler's makefile objects retain an
                                # I/O reference. close() alone defers the OS close until
                                # those objects finish, leaving Windows recv stuck.
                                # Detach so their eventual close cannot close a reused
                                # descriptor, then close our owned native socket now.
                                descriptor = connection.detach()
                                if descriptor != -1:
                                    socket.close(descriptor)
                        except BaseException as exc:
                            # One stalled client must not strand the other sockets.
                            # Retain every connection for a retry after reporting.
                            if connection_error is None:
                                connection_error = exc
            finally:
                try:
                    self._panel_wake_read.close()
                finally:
                    self._panel_wake_write.close()
            if connection_error is not None:
                raise connection_error
            with self._panel_state:
                self._panel_closed = True
                self._panel_connections.clear()
            if shutdown_error is not None:
                raise shutdown_error
