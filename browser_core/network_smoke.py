from __future__ import annotations

import base64
import hashlib
import os
import re
import secrets
import socket
import socketserver
import stat
import sys
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from itertools import islice
from pathlib import Path
from typing import Any

from .contracts import ContractError
from .control_files import (
    decode_strict_json_bytes,
    read_bounded_control_snapshot_result,
)
from .gateway import _run_upstream_tunnel
from .http_deadline import (
    clamp_urllib_response_read_timeout,
    urllib_response_has_unread_declared_bytes,
)
from .launcher import EvaluationLaunch, launch_evaluation
from .lifecycle import stop_session, validate_stopped_session_receipt
from .network import (
    _recv_headers,
    _route_workspace_path,
    _send_proxy_bytes,
    add_network_route,
    build_network_route,
)
from .numeric import is_finite_number


@dataclass(frozen=True)
class NetworkGatewaySmoke:
    executable: Path
    workspace: Path
    timeout_seconds: float = 45.0


MAX_GEOGRAPHY_RESPONSE_BYTES = 1024 * 1024
MAX_GEOGRAPHY_READ_CALLS = 65_536
MAX_SERIALIZED_RECORD_BYTES = 2 * 1024 * 1024
MAX_SERIALIZED_RECORD_TOTAL_BYTES = 256 * 1024 * 1024
MAX_WORKSPACE_ENTRIES = 8192
NETWORK_SMOKE_CLEANUP_TIMEOUT_SECONDS = 5.0
NETWORK_SMOKE_REQUIRED_HOSTS = frozenset({"tls.peet.ws", "ipwho.is"})
_HEADER_NAME = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
_COUNTRY_CODE = re.compile(r"^[A-Z]{2}$")
_TIMEZONE_ID = re.compile(r"^[A-Za-z0-9_+./-]{1,128}$")


def _validate_network_smoke_config(
    config: NetworkGatewaySmoke,
    repository_root: Path,
) -> None:
    if type(config) is not NetworkGatewaySmoke:
        raise ContractError("network gateway smoke config is invalid")
    if not isinstance(repository_root, Path) or not all(
        isinstance(value, Path) for value in (config.executable, config.workspace)
    ):
        raise ContractError("network gateway smoke paths must be Paths")
    if not is_finite_number(config.timeout_seconds) or not (
        0 < config.timeout_seconds <= 300
    ):
        raise ContractError("network gateway smoke timeout is invalid")


def _remaining_smoke_time(deadline: float, *, maximum: float = 300.0) -> float:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise ContractError("network gateway smoke timed out")
    return min(remaining, maximum)


def _valid_credential(value: object, *, username: bool) -> bool:
    if not isinstance(value, str) or not value:
        return False
    try:
        encoded = value.encode("utf-8", errors="strict")
    except UnicodeEncodeError:
        return False
    return (
        len(encoded) <= 256
        and not any(
            ord(character) < 0x20 or ord(character) == 0x7F for character in value
        )
        and (not username or ":" not in value)
    )


class _AuthenticatedForwardServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = False
    daemon_threads = True

    def __init__(self, username: str, password: str) -> None:
        if not _valid_credential(username, username=True) or not _valid_credential(
            password, username=False
        ):
            raise ContractError("network smoke forwarder credentials are invalid")
        self.expected_authorization = "Basic " + base64.b64encode(
            f"{username}:{password}".encode("utf-8")
        ).decode("ascii")
        self.allowed_hosts = NETWORK_SMOKE_REQUIRED_HOSTS
        self.authorized_connects = 0
        self.authorized_connects_by_host = {
            host: 0 for host in sorted(self.allowed_hosts)
        }
        self.rejected_connects = 0
        self._stats_lock = threading.Lock()
        self._connection_lock = threading.Lock()
        self._active_connections: set[socket.socket] = set()
        self._closing = False
        super().__init__(("127.0.0.1", 0), _AuthenticatedForwardHandler)

    def count(self, *, authorized: bool, host: str | None = None) -> None:
        with self._stats_lock:
            if authorized:
                if not isinstance(host, str) or host not in self.allowed_hosts:
                    raise ContractError(
                        "network smoke forwarder authorized host is invalid"
                    )
                self.authorized_connects += 1
                self.authorized_connects_by_host[host] += 1
            else:
                self.rejected_connects += 1

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
            raise ContractError("network smoke forwarder connections did not close")


class _AuthenticatedForwardHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        server: _AuthenticatedForwardServer = self.server  # type: ignore[assignment]
        counted = False

        def reject(response: bytes) -> None:
            nonlocal counted
            if not counted:
                server.count(authorized=False)
                counted = True
            _send_proxy_bytes(self.request, response)

        try:
            self.request.settimeout(30)
            raw = _recv_headers(
                self.request,
                maximum=16 * 1024,
                deadline=time.monotonic() + 30,
            )
            if not raw.endswith(b"\r\n\r\n"):
                raise ValueError("incomplete CONNECT headers")
            lines = raw[:-4].decode("ascii").split("\r\n")
            if not lines or len(lines) > 65:
                raise ValueError("invalid CONNECT header count")
            method, authority, version = lines[0].split(" ", 2)
            headers: dict[str, str] = {}
            for line in lines[1:]:
                if not line or line[0] in " \t":
                    raise ValueError("invalid CONNECT header line")
                name, separator, value = line.partition(":")
                normalized_name = name.casefold()
                normalized_value = value.strip(" \t")
                if (
                    not separator
                    or _HEADER_NAME.fullmatch(name) is None
                    or normalized_name in headers
                    or not normalized_value
                    or any(
                        ord(character) < 0x20 or ord(character) == 0x7F
                        for character in normalized_value
                    )
                ):
                    raise ValueError("invalid CONNECT header")
                headers[normalized_name] = normalized_value
            host, separator, raw_port = authority.rpartition(":")
            if (
                method != "CONNECT"
                or version not in {"HTTP/1.0", "HTTP/1.1"}
                or not separator
                or not host
                or host.casefold() not in server.allowed_hosts
                or raw_port != "443"
                or headers.get("host") != authority
            ):
                reject(b"HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n")
                return
            if headers.get("proxy-authorization") != server.expected_authorization:
                reject(
                    b"HTTP/1.1 407 Proxy Authentication Required\r\n"
                    b"Proxy-Authenticate: Basic realm=BrowserCoreOwnedSmoke\r\n"
                    b"Connection: close\r\n\r\n"
                )
                return
            upstream = socket.create_connection((host.casefold(), 443), timeout=30)
            server.count(authorized=True, host=host.casefold())
            counted = True
            try:
                _run_upstream_tunnel(
                    self.request,
                    upstream,
                    b"",
                    established_response=b"HTTP/1.1 200 Connection established\r\n\r\n",
                )
            except (ContractError, OSError, ValueError):
                # A tunnel failure may follow HTTP 200. Closing the connection
                # is the only valid response once application bytes can flow.
                return
        except (
            AttributeError,
            ContractError,
            OSError,
            RuntimeError,
            TypeError,
            UnicodeError,
            ValueError,
        ):
            try:
                reject(b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n")
            except (ContractError, OSError):
                pass


def _expect_proxy_rejection(
    server: _AuthenticatedForwardServer,
    request: bytes,
    expected_status: bytes,
    *,
    timeout_seconds: float = 5.0,
) -> None:
    if (
        not isinstance(request, bytes)
        or not 1 <= len(request) <= 16 * 1024
        or not isinstance(expected_status, bytes)
        or not 1 <= len(expected_status) <= 64
        or not is_finite_number(timeout_seconds)
        or not 0 < timeout_seconds <= 300
    ):
        raise ContractError("network smoke rejection probe input is invalid")
    connection: Any | None = None
    response: bytes | None = None
    primary_error: BaseException | None = None
    deadline: float | None = None
    try:
        deadline = time.monotonic() + float(timeout_seconds)

        def remaining() -> float:
            budget = deadline - time.monotonic()
            if budget <= 0:
                raise ContractError("network smoke rejection probe deadline exceeded")
            return budget

        connection = socket.create_connection(
            server.server_address,
            timeout=remaining(),
        )
        connection.settimeout(remaining())
        remaining()
        _send_proxy_bytes(connection, request)
        remaining()
        response = _recv_headers(
            connection, maximum=16 * 1024, deadline=deadline
        )
        remaining()
    except BaseException as exc:
        if isinstance(exc, ContractError):
            primary_error = exc
        elif isinstance(
            exc, (AttributeError, OSError, RuntimeError, TypeError, ValueError)
        ):
            primary_error = ContractError(
                f"network smoke rejection probe failed ({type(exc).__name__})"
            )
        else:
            primary_error = exc

    cleanup_error: ContractError | None = None
    if connection is not None:
        try:
            connection.close()
        except (AttributeError, OSError, RuntimeError, TypeError, ValueError):
            cleanup_error = ContractError(
                "network smoke rejection probe cleanup failed (connection-close)"
            )
    if primary_error is None and deadline is not None and time.monotonic() >= deadline:
        primary_error = ContractError(
            "network smoke rejection probe deadline exceeded"
        )
    if cleanup_error is not None:
        if primary_error is not None:
            raise cleanup_error from primary_error
        raise cleanup_error from None
    if primary_error is not None:
        raise primary_error from None
    if response is None:
        raise ContractError("network smoke rejection probe failed (invalid-response)")
    if not response.startswith(expected_status):
        raise ContractError(
            "network smoke rejection probe returned an unexpected status"
        )


def _file_identity(metadata: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _serialized_record_inventory(
    workspace: Path,
) -> tuple[tuple[Path, tuple[int, int, int, int, int, int]], ...]:
    try:
        root_before = os.lstat(workspace)
    except OSError as exc:
        raise ContractError(
            f"network smoke could not inventory serialized records ({type(exc).__name__})"
        ) from None
    if not stat.S_ISDIR(root_before.st_mode) or bool(
        getattr(root_before, "st_file_attributes", 0) & 0x400
    ):
        raise ContractError("network smoke workspace is not a stable directory")
    pending = [workspace]
    entries_seen = 0
    records: list[tuple[Path, tuple[int, int, int, int, int, int]]] = []
    while pending:
        directory = pending.pop()
        try:
            with os.scandir(directory) as iterator:
                remaining = MAX_WORKSPACE_ENTRIES - entries_seen
                entries = sorted(
                    islice(iterator, remaining + 1),
                    key=lambda entry: entry.name,
                )
        except OSError as exc:
            raise ContractError(
                f"network smoke could not inventory serialized records ({type(exc).__name__})"
            ) from None
        if len(entries) > remaining:
            raise ContractError("network smoke workspace has too many entries")
        for entry in entries:
            entries_seen += 1
            if entries_seen > MAX_WORKSPACE_ENTRIES:
                raise ContractError("network smoke workspace has too many entries")
            try:
                metadata = os.lstat(entry.path)
            except OSError as exc:
                raise ContractError(
                    f"network smoke could not inventory serialized records ({type(exc).__name__})"
                ) from None
            if entry.is_symlink() or bool(
                getattr(metadata, "st_file_attributes", 0) & 0x400
            ):
                raise ContractError("network smoke workspace contains a link")
            entry_path = Path(entry.path)
            if stat.S_ISDIR(metadata.st_mode):
                pending.append(entry_path)
            elif (
                stat.S_ISREG(metadata.st_mode)
                and entry_path.suffix.casefold() == ".json"
            ):
                records.append((entry_path, _file_identity(metadata)))
    try:
        root_after = os.lstat(workspace)
    except OSError:
        raise ContractError(
            "network smoke workspace changed during inventory"
        ) from None
    if _file_identity(root_before) != _file_identity(root_after):
        raise ContractError("network smoke workspace changed during inventory")
    return tuple(sorted(records, key=lambda item: str(item[0])))


def _assert_credentials_not_serialized(
    workspace: Path, secrets_to_find: tuple[str, str]
) -> int:
    if not isinstance(workspace, Path) or (
        not isinstance(secrets_to_find, tuple)
        or len(secrets_to_find) != 2
        or any(
            not _valid_credential(value, username=False) for value in secrets_to_find
        )
    ):
        raise ContractError("network smoke serialized-record scan input is invalid")
    checked = 0
    encoded = tuple(item.encode("utf-8") for item in secrets_to_find)
    inventory_before = _serialized_record_inventory(workspace)
    total = 0
    first_digests: list[bytes] = []
    for path, expected_identity in inventory_before:
        snapshot = read_bounded_control_snapshot_result(
            path,
            maximum=MAX_SERIALIZED_RECORD_BYTES,
            label="network smoke serialized record",
            require_single_link=True,
        )
        if (
            snapshot.state != "complete"
            or snapshot.body is None
            or snapshot.identity != expected_identity
        ):
            raise ContractError(
                "network smoke serialized record changed during inspection"
            )
        content = snapshot.body
        total += len(content)
        if total > MAX_SERIALIZED_RECORD_TOTAL_BYTES:
            raise ContractError(
                "network smoke serialized records exceed the aggregate byte limit"
            )
        checked += 1
        if any(secret in content for secret in encoded):
            raise ContractError(
                "network smoke found an upstream credential in a serialized record"
            )
        first_digests.append(hashlib.sha256(content).digest())
    if _serialized_record_inventory(workspace) != inventory_before:
        raise ContractError(
            "network smoke serialized-record population changed during inspection"
        )
    # Windows file metadata can remain identical after a same-size in-place
    # edit with restored mtime. Rebind the negative scan to current bytes after
    # the final inventory, using at most one extra aggregate-bounded pass.
    for (path, expected_identity), expected_digest in zip(
        inventory_before, first_digests
    ):
        final = read_bounded_control_snapshot_result(
            path,
            maximum=MAX_SERIALIZED_RECORD_BYTES,
            label="network smoke serialized record",
            require_single_link=True,
        )
        if (
            final.state != "complete"
            or final.body is None
            or final.identity != expected_identity
            or hashlib.sha256(final.body).digest() != expected_digest
        ):
            raise ContractError(
                "network smoke serialized record changed during inspection"
            )
    if _serialized_record_inventory(workspace) != inventory_before:
        raise ContractError(
            "network smoke serialized-record population changed during inspection"
        )
    if checked < 2:
        raise ContractError("network smoke did not inspect enough serialized records")
    return checked


def _strict_json_object(payload: bytes, *, label: str) -> dict[str, Any]:
    try:
        document = decode_strict_json_bytes(payload, label=label)
    except ContractError:
        raise ContractError(f"{label} is not strict JSON") from None
    if not isinstance(document, dict):
        raise ContractError(f"{label} must be a JSON object")
    return document


class _NoGeographyRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_args: Any, **_kwargs: Any) -> None:
        return None


def _open_geography_request(
    request: urllib.request.Request, *, timeout: float
) -> Any:
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}), _NoGeographyRedirectHandler()
    )
    return opener.open(request, timeout=timeout)


def _read_geography_response(
    request: urllib.request.Request,
    *,
    timeout_seconds: float,
) -> tuple[Any, Any]:
    if not is_finite_number(timeout_seconds) or not 0 < timeout_seconds <= 300:
        raise ContractError("network smoke geography timeout is invalid")
    timeout_seconds = float(timeout_seconds)
    response: Any | None = None
    status: Any = None
    body: Any = None
    primary_error: BaseException | None = None
    deadline: float | None = None
    try:
        deadline = time.monotonic() + timeout_seconds
        response = _open_geography_request(request, timeout=timeout_seconds)
        status = response.getcode()
        if type(status) is int and status == 200:
            reader = getattr(response, "read1", None)
            if callable(reader):
                parts = bytearray()
                for _ in range(MAX_GEOGRAPHY_READ_CALLS):
                    if not clamp_urllib_response_read_timeout(
                        response, deadline - time.monotonic()
                    ):
                        raise ContractError(
                            "network smoke geography response deadline exceeded"
                        )
                    remaining = MAX_GEOGRAPHY_RESPONSE_BYTES + 1 - len(parts)
                    try:
                        chunk = reader(remaining)
                    except TimeoutError:
                        raise ContractError(
                            "network smoke geography response deadline exceeded"
                        ) from None
                    if time.monotonic() > deadline:
                        raise ContractError(
                            "network smoke geography response deadline exceeded"
                        )
                    if type(chunk) is not bytes or len(chunk) > remaining:
                        raise ContractError(
                            "network smoke geography response body is invalid"
                        )
                    parts.extend(chunk)
                    if not chunk or len(parts) > MAX_GEOGRAPHY_RESPONSE_BYTES:
                        break
                else:
                    raise ContractError(
                        "network smoke geography response has too many fragments"
                    )
                body = bytes(parts)
            else:
                if not clamp_urllib_response_read_timeout(
                    response, deadline - time.monotonic()
                ):
                    raise ContractError(
                        "network smoke geography response deadline exceeded"
                    )
                try:
                    body = response.read(MAX_GEOGRAPHY_RESPONSE_BYTES + 1)
                except TimeoutError:
                    raise ContractError(
                        "network smoke geography response deadline exceeded"
                    ) from None
                if time.monotonic() > deadline:
                    raise ContractError(
                        "network smoke geography response deadline exceeded"
                    )
            if (
                type(body) is bytes
                and len(body) <= MAX_GEOGRAPHY_RESPONSE_BYTES
                and urllib_response_has_unread_declared_bytes(response)
            ):
                raise ContractError(
                    "network smoke geography response ended before declared length"
                )
    except BaseException as exc:
        if isinstance(exc, urllib.error.HTTPError):
            response = exc
        if isinstance(exc, ContractError):
            primary_error = exc
        elif isinstance(
            exc, (AttributeError, OSError, RuntimeError, TypeError, ValueError)
        ):
            primary_error = ContractError(
                "network smoke could not discover expected geography "
                f"({type(exc).__name__})"
            )
        else:
            primary_error = exc

    cleanup_error: ContractError | None = None
    if response is not None:
        try:
            response.close()
        except (AttributeError, OSError, RuntimeError, TypeError, ValueError):
            cleanup_error = ContractError(
                "network smoke geography cleanup failed (response-close)"
            )
    if primary_error is None and deadline is not None and time.monotonic() >= deadline:
        primary_error = ContractError(
            "network smoke geography response deadline exceeded"
        )
    if cleanup_error is not None:
        if primary_error is not None:
            raise cleanup_error from primary_error
        raise cleanup_error from None
    if primary_error is not None:
        raise primary_error from None
    return status, body


def _expected_geography(timeout_seconds: float) -> dict[str, str]:
    if not is_finite_number(timeout_seconds) or not 0 < timeout_seconds <= 300:
        raise ContractError("network smoke geography timeout is invalid")
    request = urllib.request.Request(
        "https://ipwho.is/",
        headers={
            "Accept": "application/json",
            "User-Agent": "BrowserCoreNetworkSmoke/1",
        },
    )
    status, body = _read_geography_response(
        request,
        timeout_seconds=float(timeout_seconds),
    )
    if type(status) is not int or status != 200:
        raise ContractError(
            "network smoke geography discovery returned an unexpected status"
        )
    if type(body) is not bytes:
        raise ContractError("network smoke geography discovery response is invalid")
    if len(body) > MAX_GEOGRAPHY_RESPONSE_BYTES:
        raise ContractError("network smoke geography discovery response is too large")
    payload = _strict_json_object(
        body, label="network smoke geography discovery response"
    )
    timezone = payload.get("timezone") if isinstance(payload, dict) else None
    timezone_id = timezone.get("id") if isinstance(timezone, dict) else None
    country = payload.get("country_code") if isinstance(payload, dict) else None
    if (
        not isinstance(country, str)
        or _COUNTRY_CODE.fullmatch(country) is None
        or not isinstance(timezone_id, str)
        or _TIMEZONE_ID.fullmatch(timezone_id) is None
    ):
        raise ContractError("network smoke geography discovery response is invalid")
    return {"country": country, "locale": "en-US", "timezone": timezone_id}


def _stop_forwarder(
    server: Any | None,
    server_thread: Any | None,
    *,
    started: bool,
) -> list[str]:
    failures: list[str] = []
    if server is None:
        return failures
    worker_alive = False
    if started and server_thread is not None:
        try:
            worker_alive = server_thread.is_alive()
            if type(worker_alive) is not bool:
                failures.append("forwarder-worker-status")
                worker_alive = True
        except (OSError, RuntimeError):
            failures.append("forwarder-worker-status")
            worker_alive = True
    shutdown_thread: Any | None = None
    shutdown_deadline = time.monotonic() + NETWORK_SMOKE_CLEANUP_TIMEOUT_SECONDS
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
                name="browser-core-owned-auth-proxy-shutdown",
                daemon=True,
            )
            shutdown_thread.start()
            shutdown_thread.join(
                timeout=max(0.0, shutdown_deadline - time.monotonic())
            )
            if shutdown_thread.is_alive() or shutdown_failed:
                failures.append("forwarder-shutdown")
        except (OSError, RuntimeError):
            failures.append("forwarder-shutdown")
    try:
        server.server_close()
    except Exception:
        failures.append("forwarder-close")
    if shutdown_thread is not None:
        try:
            shutdown_thread.join(
                timeout=max(0.0, shutdown_deadline - time.monotonic())
            )
            if shutdown_thread.is_alive() and "forwarder-shutdown" not in failures:
                failures.append("forwarder-shutdown")
        except (OSError, RuntimeError):
            if "forwarder-shutdown" not in failures:
                failures.append("forwarder-shutdown")
    if started and server_thread is not None:
        try:
            server_thread.join(timeout=NETWORK_SMOKE_CLEANUP_TIMEOUT_SECONDS)
            if server_thread.is_alive():
                failures.append("forwarder-thread")
        except (OSError, RuntimeError):
            failures.append("forwarder-thread")
    return failures


def _validated_authorized_connects_by_host(server: object) -> dict[str, int]:
    allowed_hosts = getattr(server, "allowed_hosts", None)
    total = getattr(server, "authorized_connects", None)
    counts = getattr(server, "authorized_connects_by_host", None)
    required_hosts = sorted(NETWORK_SMOKE_REQUIRED_HOSTS)
    if (
        allowed_hosts != NETWORK_SMOKE_REQUIRED_HOSTS
        or isinstance(total, bool)
        or not isinstance(total, int)
        or total < len(required_hosts)
        or not isinstance(counts, dict)
        or set(counts) != set(required_hosts)
        or any(
            isinstance(counts.get(host), bool)
            or not isinstance(counts.get(host), int)
            or counts[host] < 1
            for host in required_hosts
        )
        or sum(counts.values()) != total
    ):
        raise ContractError(
            "network gateway smoke did not prove authenticated CONNECT use "
            "for every required host"
        )
    return {host: counts[host] for host in required_hosts}


def run_network_gateway_smoke(
    config: NetworkGatewaySmoke, repository_root: Path
) -> dict[str, Any]:
    _validate_network_smoke_config(config, repository_root)
    deadline = time.monotonic() + float(config.timeout_seconds)
    try:
        smoke_workspace = (
            _route_workspace_path(config.workspace)
            / "acceptance"
            / f"network-{secrets.token_hex(8)}"
        )
    except (OSError, RuntimeError, ValueError) as exc:
        raise ContractError(
            f"network gateway smoke workspace could not be prepared ({type(exc).__name__})"
        ) from None
    geography = _expected_geography(_remaining_smoke_time(deadline))
    username = secrets.token_urlsafe(18)
    password = secrets.token_urlsafe(24)
    user_env = "BROWSER_CORE_SMOKE_PROXY_USER"
    password_env = "BROWSER_CORE_SMOKE_PROXY_PASSWORD"
    previous_user = os.environ.get(user_env)
    previous_password = os.environ.get(password_env)
    server: _AuthenticatedForwardServer | None = None
    server_thread: threading.Thread | None = None
    server_started = False
    route_id = "owned-auth-forward"
    route: dict[str, Any] | None = None
    session_path: Path | None = None
    session: dict[str, Any] | None = None
    status: dict[str, Any] | None = None
    try:
        try:
            server = _AuthenticatedForwardServer(username, password)
            server_thread = threading.Thread(
                target=server.serve_forever,
                name="browser-core-owned-auth-proxy",
                daemon=True,
            )
        except ContractError:
            raise
        except (OSError, RuntimeError, ValueError) as exc:
            raise ContractError(
                f"network smoke forwarder could not start ({type(exc).__name__})"
            ) from None
        try:
            server_thread.start()
        except (OSError, RuntimeError) as exc:
            # start() may report failure after the forwarder begins serving.
            # Preserve ownership so the shared cleanup shuts it down and joins.
            try:
                server_started = server_thread.is_alive() is not False
            except AttributeError:
                server_started = False
            except (OSError, RuntimeError):
                server_started = True
            raise ContractError(
                f"network smoke forwarder could not start ({type(exc).__name__})"
            ) from None
        server_started = True
        route = build_network_route(
            route_id=route_id,
            name="Owned authenticated forwarding smoke",
            mode="proxy",
            endpoint={
                "protocol": "http",
                "host": "127.0.0.1",
                "port": server.server_address[1],
            },
            auth={"username_env": user_env, "password_env": password_env},
            geography=geography,
            preflight_url="https://tls.peet.ws/api/all",
            policies={
                "dns": "route",
                "webrtc": "route-only",
                "require_alignment": True,
            },
        )
        add_network_route(smoke_workspace, route)
        os.environ[user_env] = username
        os.environ[password_env] = password
        _expect_proxy_rejection(
            server,
            b"CONNECT tls.peet.ws:443 HTTP/1.1\r\nHost: tls.peet.ws:443\r\n\r\n",
            b"HTTP/1.1 407",
            timeout_seconds=min(5.0, _remaining_smoke_time(deadline)),
        )
        forbidden_request = (
            "CONNECT example.com:443 HTTP/1.1\r\n"
            "Host: example.com:443\r\n"
            f"Proxy-Authorization: {server.expected_authorization}\r\n\r\n"
        ).encode("ascii")
        _expect_proxy_rejection(
            server,
            forbidden_request,
            b"HTTP/1.1 403",
            timeout_seconds=min(5.0, _remaining_smoke_time(deadline)),
        )
        session_path, session = launch_evaluation(
            EvaluationLaunch(
                executable=config.executable,
                workspace=smoke_workspace,
                headless=True,
                timeout_seconds=_remaining_smoke_time(deadline),
                network_route_id=route_id,
                trace_mode="off",
            ),
            repository_root,
        )
        status = validate_stopped_session_receipt(
            stop_session(
                session_path,
                timeout_seconds=_remaining_smoke_time(deadline),
            ),
            expected_run_id=session.get("run_id"),
        )
    finally:
        cleanup_failures: list[str] = []
        try:
            cleanup_failures.extend(
                _stop_forwarder(
                    server,
                    server_thread,
                    started=server_started,
                )
            )
        finally:
            if previous_user is None:
                os.environ.pop(user_env, None)
            else:
                os.environ[user_env] = previous_user
            if previous_password is None:
                os.environ.pop(password_env, None)
            else:
                os.environ[password_env] = previous_password
        if cleanup_failures:
            phases = ",".join(cleanup_failures)
            cleanup_error = ContractError(
                f"network gateway smoke cleanup failed ({phases})"
            )
            active_error = sys.exc_info()[1]
            if active_error is not None:
                raise cleanup_error from active_error
            raise cleanup_error from None
    if route is None or session is None or session_path is None or status is None:
        raise ContractError("network gateway smoke did not create a verified session")
    network = session["network"]
    if network["realization"]["passed"] is not True or status["state"] != "stopped":
        raise ContractError(
            "network gateway smoke did not pass its realization and lifecycle gates"
        )
    gateway = network["gateway"]
    try:
        os.lstat(gateway["lease_path"])
    except FileNotFoundError:
        pass
    except OSError:
        raise ContractError(
            "network gateway smoke could not verify credential sidecar lease removal"
        ) from None
    else:
        raise ContractError(
            "network gateway smoke left its credential sidecar lease active"
        )
    if server is None:
        raise ContractError("network gateway smoke forwarder evidence is absent")
    authorized_connects_by_host = _validated_authorized_connects_by_host(server)
    if server.rejected_connects < 2:
        raise ContractError(
            "network gateway smoke did not prove authentication and allowlist rejection"
        )
    serialized_records_checked = _assert_credentials_not_serialized(
        smoke_workspace, (username, password)
    )
    return {
        "schema": "browser-core.network-gateway-smoke/1",
        "status": "passed",
        "session_file": str(session_path),
        "workspace": str(smoke_workspace),
        "route_id": route_id,
        "route_sha256_16": route["integrity_sha256"][:16],
        "upstream": {
            "kind": "owned-restricted-authenticated-forwarder",
            "authorized_connects": server.authorized_connects,
            "authorized_connects_by_host": authorized_connects_by_host,
            "rejected_connects": server.rejected_connects,
            "allowed_hosts": sorted(server.allowed_hosts),
            "credentials_serialized": False,
            "serialized_records_checked": serialized_records_checked,
            "unauthenticated_rejected": True,
            "forbidden_host_rejected": True,
        },
        "gateway_endpoint": gateway["endpoint"],
        "runtime_identity": network["runtime_identity"],
        "realization": network["realization"],
        "lifecycle": status,
    }
