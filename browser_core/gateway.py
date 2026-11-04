from __future__ import annotations

import argparse
import ipaddress
import re
import selectors
import socket
import socketserver
import sys
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator

from .contracts import ContractError
from .control_files import (
    MAX_GATEWAY_CONTROL_BYTES,
    load_canonical_json_document,
    publish_json_exclusive,
    read_bounded_control_snapshot_result,
)
from .network import (
    ResolvedNetworkRoute,
    _ambiguous_numeric_host_label,
    _connect_http_proxy,
    _connect_socks5_proxy,
    _validated_resolved_network_route,
    load_network_route,
    resolve_network_route,
)
from .owned_paths import directory_ancestry_binding


MAX_CONNECT_HEADER_BYTES = 16 * 1024
MAX_CONNECT_HEADER_FIELDS = 64
GATEWAY_CLEANUP_TIMEOUT_SECONDS = 5.0
_HEADER_NAME = re.compile(rb"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
_DNS_LABEL = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")


class _GatewayRequestError(Exception):
    pass


class _GatewayMethodError(_GatewayRequestError):
    pass


def _recv_connect_request(
    connection: socket.socket,
    *,
    maximum: int = MAX_CONNECT_HEADER_BYTES,
    deadline: float | None = None,
) -> tuple[bytes, bytes]:
    if (
        isinstance(maximum, bool)
        or not isinstance(maximum, int)
        or not 1 <= maximum <= 1024 * 1024
    ):
        raise ContractError("gateway CONNECT header limit is invalid")
    data = bytearray()
    while True:
        remaining = None if deadline is None else deadline - time.monotonic()
        if remaining is not None and remaining <= 0:
            raise _GatewayRequestError("gateway CONNECT headers timed out")
        end = data.find(b"\r\n\r\n")
        if end >= 0:
            header_end = end + 4
            if header_end > maximum:
                raise _GatewayRequestError("gateway CONNECT headers are too large")
            return bytes(data[:header_end]), bytes(data[header_end:])
        if len(data) >= maximum:
            raise _GatewayRequestError("gateway CONNECT headers are too large")
        if remaining is not None:
            connection.settimeout(remaining)
        requested = min(4096, maximum + 4096 - len(data))
        chunk = connection.recv(requested)
        if type(chunk) is not bytes or len(chunk) > requested:
            raise ContractError("gateway transport returned invalid bytes")
        if not chunk:
            raise _GatewayRequestError("gateway CONNECT headers are incomplete")
        data.extend(chunk)


def _connect_host(authority: str) -> tuple[str, str, int]:
    host_text: str
    if authority.startswith("["):
        closing = authority.find("]")
        if closing <= 1 or authority[closing + 1 : closing + 2] != ":":
            raise _GatewayRequestError("gateway CONNECT authority is invalid")
        host_text = authority[1:closing]
        raw_port = authority[closing + 2 :]
        try:
            address = ipaddress.IPv6Address(host_text)
        except ValueError:
            raise _GatewayRequestError("gateway CONNECT authority is invalid") from None
        if address.scope_id is not None:
            raise _GatewayRequestError("gateway CONNECT authority is invalid")
        http_host = f"[{host_text}]"
    else:
        host_text, separator, raw_port = authority.rpartition(":")
        if not separator or not host_text or len(host_text) > 253:
            raise _GatewayRequestError("gateway CONNECT authority is invalid")
        try:
            parsed_ip = ipaddress.ip_address(host_text)
        except ValueError:
            labels = (
                host_text[:-1].split(".")
                if host_text.endswith(".")
                else host_text.split(".")
            )
            if (
                not labels
                or any(_DNS_LABEL.fullmatch(label) is None for label in labels)
                or _ambiguous_numeric_host_label(labels[-1])
            ):
                raise _GatewayRequestError(
                    "gateway CONNECT authority is invalid"
                ) from None
        else:
            if parsed_ip.version != 4:
                raise _GatewayRequestError(
                    "gateway CONNECT IPv6 authority must be bracketed"
                )
        http_host = host_text
    if (
        not raw_port
        or not raw_port.isascii()
        or not raw_port.isdecimal()
        or len(raw_port) > 5
    ):
        raise _GatewayRequestError("gateway CONNECT port is invalid")
    port = int(raw_port)
    if not 1 <= port <= 65535 or raw_port != str(port):
        raise _GatewayRequestError("gateway CONNECT port is invalid")
    return host_text, http_host, port


def _parse_connect_request(headers: bytes) -> tuple[str, str, int]:
    if not isinstance(headers, bytes) or not headers.endswith(b"\r\n\r\n"):
        raise _GatewayRequestError("gateway CONNECT headers are invalid")
    rows = headers[:-4].split(b"\r\n")
    if not rows or len(rows) > MAX_CONNECT_HEADER_FIELDS + 1:
        raise _GatewayRequestError("gateway CONNECT header count is invalid")
    try:
        request_line = rows[0].decode("ascii")
        method, authority, version = request_line.split(" ")
    except (UnicodeError, ValueError):
        raise _GatewayRequestError("gateway CONNECT request line is invalid") from None
    if method != "CONNECT":
        raise _GatewayMethodError("gateway requires CONNECT")
    if version != "HTTP/1.1":
        raise _GatewayRequestError("gateway CONNECT HTTP version is invalid")
    parsed_headers: dict[bytes, bytes] = {}
    for row in rows[1:]:
        if not row or row[:1] in {b" ", b"\t"}:
            raise _GatewayRequestError("gateway CONNECT header is invalid")
        name, separator, value = row.partition(b":")
        normalized_name = name.lower()
        normalized_value = value.strip(b" \t")
        if (
            not separator
            or _HEADER_NAME.fullmatch(name) is None
            or normalized_name in parsed_headers
            or any(byte < 0x20 or byte == 0x7F for byte in normalized_value)
        ):
            raise _GatewayRequestError("gateway CONNECT header is invalid")
        parsed_headers[normalized_name] = normalized_value
    try:
        host_header = parsed_headers[b"host"].decode("ascii")
    except (KeyError, UnicodeError):
        raise _GatewayRequestError("gateway CONNECT Host header is invalid") from None
    if host_header.casefold() != authority.casefold():
        raise _GatewayRequestError(
            "gateway CONNECT Host header does not match authority"
        )
    return _connect_host(authority)


def _validated_resolved_route(resolved: object) -> ResolvedNetworkRoute:
    retained = _validated_resolved_network_route(resolved)
    if retained.route["mode"] != "proxy":
        raise ContractError("credential gateway requires a proxy-mode network route")
    return retained


def _relay(left: socket.socket, right: socket.socket) -> None:
    selector = selectors.DefaultSelector()
    selector.register(left, selectors.EVENT_READ, right)
    selector.register(right, selectors.EVENT_READ, left)
    open_reads = 2
    try:
        while True:
            events = selector.select(timeout=30)
            if not events:
                continue
            for key, _ in events:
                source: socket.socket = key.fileobj
                destination: socket.socket = key.data
                data = source.recv(64 * 1024)
                if type(data) is not bytes or len(data) > 64 * 1024:
                    raise ContractError(
                        "credential gateway relay returned invalid bytes"
                    )
                if not data:
                    # A client may finish writing its request while still
                    # waiting for the response. Forward the half-close and
                    # keep relaying the other direction until it also ends.
                    selector.unregister(source)
                    destination.shutdown(socket.SHUT_WR)
                    open_reads -= 1
                    if open_reads == 0:
                        return
                    continue
                if destination.sendall(data) is not None:
                    raise ContractError("credential gateway relay write is invalid")
    finally:
        selector.close()


def _run_upstream_tunnel(
    client: Any,
    upstream: Any,
    initial_tunnel_bytes: bytes,
    *,
    established_response: bytes = (
        b"HTTP/1.1 200 Connection established\r\n"
        b"Proxy-Agent: BrowserCoreGateway\r\n\r\n"
    ),
) -> None:
    primary_error: BaseException | None = None
    try:
        if (
            type(initial_tunnel_bytes) is not bytes
            or len(initial_tunnel_bytes) > 1024 * 1024
            or type(established_response) is not bytes
            or not 1 <= len(established_response) <= 16 * 1024
            or not established_response.endswith(b"\r\n\r\n")
        ):
            raise ContractError("credential gateway upstream tunnel input is invalid")
        if client.sendall(established_response) is not None:
            raise ContractError("credential gateway relay write is invalid")
        if initial_tunnel_bytes:
            if upstream.sendall(initial_tunnel_bytes) is not None:
                raise ContractError("credential gateway relay write is invalid")
        _relay(client, upstream)
    except BaseException as exc:
        if isinstance(exc, ContractError):
            primary_error = exc
        elif isinstance(
            exc, (AttributeError, OSError, RuntimeError, TypeError, ValueError)
        ):
            primary_error = ContractError(
                f"credential gateway upstream tunnel failed ({type(exc).__name__})"
            )
        else:
            primary_error = exc

    cleanup_error: ContractError | None = None
    try:
        upstream.close()
    except (AttributeError, OSError, RuntimeError, TypeError, ValueError):
        cleanup_error = ContractError(
            "credential gateway upstream cleanup failed (connection-close)"
        )
    if cleanup_error is not None:
        if primary_error is not None:
            raise cleanup_error from primary_error
        raise cleanup_error from None
    if primary_error is not None:
        raise primary_error from None


class _GatewayHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        server = self.server
        resolved: ResolvedNetworkRoute = server.resolved_route  # type: ignore[attr-defined]
        self.request.settimeout(30)
        try:
            headers, initial_tunnel_bytes = _recv_connect_request(
                self.request, deadline=time.monotonic() + 30
            )
            host, http_host, port = _parse_connect_request(headers)
            if resolved.protocol in {"http", "https"}:
                upstream = _connect_http_proxy(resolved, http_host, port, 30)
            elif resolved.protocol == "socks5":
                upstream = _connect_socks5_proxy(resolved, host, port, 30)
            else:
                raise ContractError("gateway requires a proxy-mode route")
            try:
                _run_upstream_tunnel(self.request, upstream, initial_tunnel_bytes)
            except (ContractError, OSError, ValueError):
                # The tunnel may already have sent HTTP 200. Close the socket;
                # a later HTTP error would become corrupt application data.
                return
        except _GatewayMethodError:
            try:
                self.request.sendall(
                    b"HTTP/1.1 405 Method Not Allowed\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"
                )
            except OSError:
                pass
        except _GatewayRequestError:
            try:
                self.request.sendall(
                    b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"
                )
            except OSError:
                pass
        except (ContractError, OSError, ValueError):
            try:
                self.request.sendall(
                    b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"
                )
            except OSError:
                pass


class _GatewayServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = False
    daemon_threads = True

    def __init__(self, resolved_route: ResolvedNetworkRoute) -> None:
        self.resolved_route = resolved_route
        self._connection_lock = threading.Lock()
        self._active_connections: set[socket.socket] = set()
        self._closing = False
        super().__init__(("127.0.0.1", 0), _GatewayHandler)

    def process_request(self, request: socket.socket, client_address: Any) -> None:
        with self._connection_lock:
            closing = self._closing
            if not closing:
                self._active_connections.add(request)
        if closing:
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self.shutdown_request(request)
            raise

    def shutdown_request(self, request: socket.socket) -> None:
        try:
            super().shutdown_request(request)
        finally:
            with self._connection_lock:
                self._active_connections.discard(request)

    def server_close(self) -> None:
        with self._connection_lock:
            self._closing = True
            active = tuple(self._active_connections)
        close_failed = False
        try:
            super().server_close()
        finally:
            for connection in active:
                try:
                    connection.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                try:
                    connection.close()
                except OSError:
                    close_failed = True
        if close_failed:
            raise ContractError("credential gateway connections did not close")


def _stop_gateway_server(
    server: Any | None,
    thread: Any | None,
    *,
    thread_started: bool,
) -> list[str]:
    failures: list[str] = []
    if server is None:
        return failures
    worker_alive = False
    if thread_started and thread is not None:
        try:
            worker_alive = thread.is_alive()
            if type(worker_alive) is not bool:
                failures.append("worker-status")
                worker_alive = True
        except (OSError, RuntimeError):
            failures.append("worker-status")
            worker_alive = True
    shutdown_thread: Any | None = None
    shutdown_deadline = time.monotonic() + GATEWAY_CLEANUP_TIMEOUT_SECONDS
    if worker_alive:
        shutdown_failed: list[bool] = []

        def shutdown() -> None:
            try:
                server.shutdown()
            except Exception:
                shutdown_failed.append(True)

        try:
            shutdown_thread = threading.Thread(
                target=shutdown,
                name="browser-core-gateway-shutdown",
                daemon=True,
            )
            shutdown_thread.start()
            shutdown_thread.join(
                timeout=max(0.0, shutdown_deadline - time.monotonic())
            )
            if shutdown_thread.is_alive() or shutdown_failed:
                failures.append("server-shutdown")
        except (OSError, RuntimeError):
            failures.append("server-shutdown")
    try:
        server.server_close()
    except Exception:
        failures.append("server-close")
    if shutdown_thread is not None:
        try:
            shutdown_thread.join(
                timeout=max(0.0, shutdown_deadline - time.monotonic())
            )
            if shutdown_thread.is_alive() and "server-shutdown" not in failures:
                failures.append("server-shutdown")
        except (OSError, RuntimeError):
            if "server-shutdown" not in failures:
                failures.append("server-shutdown")
    if thread_started and thread is not None:
        try:
            thread.join(timeout=GATEWAY_CLEANUP_TIMEOUT_SECONDS)
            if thread.is_alive():
                failures.append("worker-thread")
        except (OSError, RuntimeError):
            failures.append("worker-thread")
    return failures


@contextmanager
def serve_gateway(resolved_route: ResolvedNetworkRoute) -> Iterator[tuple[str, int]]:
    retained_route = _validated_resolved_route(resolved_route)
    server: _GatewayServer | None = None
    thread: threading.Thread | None = None
    thread_started = False
    try:
        try:
            server = _GatewayServer(retained_route)
            address = server.server_address
            if (
                type(address) is not tuple
                or len(address) != 2
                or address[0] != "127.0.0.1"
                or isinstance(address[1], bool)
                or not isinstance(address[1], int)
                or not 1 <= address[1] <= 65535
            ):
                raise ContractError("credential gateway listener address is invalid")
            thread = threading.Thread(
                target=server.serve_forever,
                name="browser-core-gateway",
                daemon=True,
            )
        except ContractError:
            raise
        except (OSError, RuntimeError, ValueError) as exc:
            raise ContractError(
                f"credential gateway could not start ({type(exc).__name__})"
            ) from None
        try:
            thread.start()
            thread_started = True
        except (OSError, RuntimeError) as exc:
            # A worker may be live even when start reports an error; let the
            # normal shutdown and join phases own that partial startup.
            try:
                thread_started = thread.is_alive() is not False
            except AttributeError:
                thread_started = False
            except (OSError, RuntimeError):
                thread_started = True
            raise ContractError(
                f"credential gateway could not start ({type(exc).__name__})"
            ) from None
        if not thread.is_alive():
            raise ContractError("credential gateway worker did not start")
        yield "127.0.0.1", address[1]
    finally:
        cleanup_failures = _stop_gateway_server(
            server,
            thread,
            thread_started=thread_started,
        )
        if cleanup_failures:
            phases = ",".join(cleanup_failures)
            cleanup_error = ContractError(
                f"credential gateway cleanup failed ({phases})"
            )
            active_error = sys.exc_info()[1]
            if active_error is not None:
                raise cleanup_error from active_error
            raise cleanup_error from None


def _write_ready(path: Path, route: dict, run_id: str, host: str, port: int) -> None:
    if not isinstance(path, Path):
        raise ContractError("gateway readiness path must be a Path")
    document = {
        "schema": "browser-core.gateway-ready/2",
        "run_id": run_id,
        "route_id": route["id"],
        "route_sha256_16": route["integrity_sha256"][:16],
        "host": host,
        "port": port,
    }
    publish_json_exclusive(
        path,
        document,
        maximum=MAX_GATEWAY_CONTROL_BYTES,
        label="network credential gateway readiness document",
    )


@dataclass(frozen=True)
class _GatewayLease:
    document: dict
    identity: tuple[int, int, int, int, int, int]


def _load_lease(
    path: Path,
    route: dict,
    run_id: str,
) -> _GatewayLease | None:
    if not isinstance(path, Path):
        raise ContractError("gateway lease path must be a Path")
    snapshot = read_bounded_control_snapshot_result(
        path,
        maximum=MAX_GATEWAY_CONTROL_BYTES,
        label="network credential gateway lease document",
        require_single_link=True,
    )
    if snapshot.state == "missing":
        return None
    if snapshot.state != "complete" or snapshot.body is None or snapshot.identity is None:
        raise ContractError(
            f"network credential gateway lease document is {snapshot.state}"
        )
    document = load_canonical_json_document(
        snapshot.body,
        label="network credential gateway lease document",
    )
    if (
        set(document) != {"schema", "run_id", "route_id", "route_sha256_16"}
        or document.get("schema") != "browser-core.gateway-lease/2"
        or document.get("run_id") != run_id
        or document.get("route_id") != route["id"]
        or document.get("route_sha256_16") != route["integrity_sha256"][:16]
    ):
        raise ContractError("network credential gateway lease document is invalid")
    return _GatewayLease(document, snapshot.identity)


def sidecar(
    workspace: Path,
    route_id: str,
    run_id: str,
    ready_file: Path,
    lease_file: Path,
    session_key: str | None = None,
) -> int:
    if (
        not isinstance(workspace, Path)
        or not isinstance(ready_file, Path)
        or not isinstance(lease_file, Path)
    ):
        raise ContractError("gateway sidecar paths must be Paths")
    try:
        ready_path = ready_file.absolute()
        lease_path = lease_file.absolute()
        if ready_path != ready_file.resolve() or lease_path != lease_file.resolve():
            raise ContractError("gateway control paths are redirected")
    except (OSError, RuntimeError, ValueError):
        raise ContractError("gateway control paths cannot be inspected") from None
    if (
        ready_path.parent != lease_path.parent
        or ready_path.name != f"{run_id}.json"
        or lease_path.name != f"{run_id}.lease"
    ):
        raise ContractError("gateway control paths are not owned by this run")
    control_parent = ready_path.parent
    control_ancestry = directory_ancestry_binding(
        control_parent, label="gateway control parent"
    )

    def require_control_parent() -> None:
        try:
            current = directory_ancestry_binding(
                control_parent, label="gateway control parent"
            )
        except ContractError:
            raise ContractError("gateway control parent changed") from None
        if current != control_ancestry:
            raise ContractError("gateway control parent changed")

    route = load_network_route(workspace, route_id)
    # Use the workspace secret store only when a secret is actually stored, so
    # every route created before it existed keeps resolving from the environment
    # by exactly the path it always did. ``session_key`` is a profile ID, not a
    # secret, so it is safe on the sidecar's command line; the credential it
    # selects never is.
    from .proxy_import import has_proxy_secret, resolve_route_credentials

    if has_proxy_secret(workspace, route_id):
        resolved = resolve_route_credentials(workspace, route, session_key=session_key)
    else:
        resolved = resolve_network_route(route)
    initial_lease = _load_lease(lease_path, route, run_id)
    require_control_parent()
    if initial_lease is None:
        raise ContractError("gateway lease file does not exist")
    with serve_gateway(resolved) as (host, port):
        require_control_parent()
        _write_ready(ready_path, route, run_id, host, port)
        require_control_parent()
        while True:
            current_lease = _load_lease(lease_path, route, run_id)
            require_control_parent()
            if current_lease is None:
                break
            if current_lease != initial_lease:
                raise ContractError("network credential gateway lease document changed")
            time.sleep(0.25)
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(prog="browser-core-gateway")
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--route-id", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--ready-file", type=Path, required=True)
    parser.add_argument("--lease-file", type=Path, required=True)
    parser.add_argument("--session-key", default=None)
    args = parser.parse_args()
    try:
        return sidecar(
            args.workspace.absolute(),
            args.route_id,
            args.run_id,
            args.ready_file,
            args.lease_file,
            args.session_key,
        )
    except ContractError as exc:
        print(f"browser-core-gateway: {exc}")
        return 2
    except OSError as exc:
        print(f"browser-core-gateway: infrastructure failed ({type(exc).__name__})")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
