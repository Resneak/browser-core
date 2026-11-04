from __future__ import annotations

import hashlib
import json
import re
import socket
import ssl
import sys
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from typing import Any, Iterator
from urllib.parse import unquote, urlsplit

from .contracts import ContractError
from .control import ControlStore, Principal, WorkerPrincipal
from .control_files import (
    decode_strict_json_bytes,
    read_bounded_control_snapshot_result,
)
from .local_http import LocalPanelServer, _HeaderDeadlineReader


MAX_JSON_BODY = 1024 * 1024
MAX_ARTIFACT_BODY = 64 * 1024 * 1024
MAX_JSON_RESPONSE = 8 * 1024 * 1024
MAX_REQUEST_TARGET_BYTES = 4096
MAX_TLS_CREDENTIAL_BYTES = 1024 * 1024
REQUEST_READ_TIMEOUT_SECONDS = 5.0
CONTROL_SERVICE_CLEANUP_TIMEOUT_SECONDS = 5.0
LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1"}
PATH_SEGMENT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


@dataclass(frozen=True)
class ServiceConfig:
    host: str = "127.0.0.1"
    port: int = 0
    tls_cert: Path | None = None
    tls_key: Path | None = None


class ThreadingHTTPServer(LocalPanelServer):
    """Control listener with explicit ownership of accepted client sockets."""


class _IPv6ThreadingHTTPServer(ThreadingHTTPServer):
    address_family = socket.AF_INET6


def validate_service_config(config: ServiceConfig) -> ServiceConfig:
    if type(config) is not ServiceConfig:
        raise ContractError("control service config is invalid")
    if (
        not isinstance(config.host, str)
        or not 1 <= len(config.host) <= 253
        or any(
            ord(character) < 0x21 or character in "/\\?#@" for character in config.host
        )
    ):
        raise ContractError("control service host is invalid")
    if (
        isinstance(config.port, bool)
        or not isinstance(config.port, int)
        or not 0 <= config.port <= 65535
    ):
        raise ContractError("control service port is invalid")
    has_cert = config.tls_cert is not None
    has_key = config.tls_key is not None
    if has_cert != has_key:
        raise ContractError(
            "control service TLS certificate and key must be supplied together"
        )
    if config.host not in LOOPBACK_HOSTS and not has_cert:
        raise ContractError("non-loopback control service binds require TLS")
    if has_cert:
        if not isinstance(config.tls_cert, Path) or not isinstance(
            config.tls_key, Path
        ):
            raise ContractError("control service TLS certificate and key must be Paths")
        _tls_credential_snapshot(config.tls_cert, label="TLS certificate")
        _tls_credential_snapshot(config.tls_key, label="TLS private key")
    return config


def _tls_credential_snapshot(path: Path, *, label: str):  # type: ignore[no-untyped-def]
    snapshot = read_bounded_control_snapshot_result(
        path,
        maximum=MAX_TLS_CREDENTIAL_BYTES,
        label=f"control service {label}",
        require_private=label == "TLS private key",
    )
    if (
        snapshot.state != "complete"
        or snapshot.body is None
        or snapshot.identity is None
    ):
        raise ContractError(f"control service {label} is {snapshot.state}")
    return snapshot


def _handler_class(store: ControlStore):
    class Handler(BaseHTTPRequestHandler):
        server_version = "BrowserCoreControl/1"

        def setup(self) -> None:
            # The HTTP parser runs before endpoint body deadlines. Bound idle
            # request lines/headers, and perform TLS handshakes in the request
            # thread so one silent peer cannot stall the listener's accept loop.
            self.request.settimeout(REQUEST_READ_TIMEOUT_SECONDS)
            if isinstance(self.request, ssl.SSLSocket):
                self.request.do_handshake()
            super().setup()
            self._header_deadline = None
            self.rfile = _HeaderDeadlineReader(self.rfile, self)

        def handle_one_request(self) -> None:
            self._header_deadline = time.monotonic() + REQUEST_READ_TIMEOUT_SECONDS
            self.rfile.reset_header_count()
            try:
                super().handle_one_request()
            finally:
                self._header_deadline = None

        def parse_request(self) -> bool:
            parsed = super().parse_request()
            self._header_deadline = None
            self.connection.settimeout(REQUEST_READ_TIMEOUT_SECONDS)
            return parsed

        def log_message(self, format: str, *args: object) -> None:
            return

        def end_headers(self) -> None:
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Referrer-Policy", "no-referrer")
            super().end_headers()

        def _json(self, status: int, value: Any) -> None:
            try:
                body = (
                    json.dumps(
                        value,
                        sort_keys=True,
                        separators=(",", ":"),
                        ensure_ascii=True,
                        allow_nan=False,
                    )
                    + "\n"
                ).encode("ascii")
            except (TypeError, ValueError):
                raise ContractError(
                    "control service response is not strict JSON"
                ) from None
            if len(body) > MAX_JSON_RESPONSE:
                raise ContractError("control service JSON response exceeds limit")
            self._response_started = True
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _bytes(self, status: int, value: bytes, media_type: str) -> None:
            self._response_started = True
            self.send_response(status)
            self.send_header("Content-Type", media_type)
            self.send_header("Content-Length", str(len(value)))
            self.end_headers()
            self.wfile.write(value)

        def _read(self, maximum: int) -> bytes:
            if self.headers.get_all("Transfer-Encoding", []):
                raise ContractError("request transfer encoding is not supported")
            lengths = self.headers.get_all("Content-Length", [])
            if len(lengths) != 1:
                raise ContractError("request requires one content length")
            raw_length = lengths[0]
            if (
                len(raw_length) > len(str(maximum))
                or re.fullmatch(r"0|[1-9][0-9]*", raw_length) is None
            ):
                raise ContractError("request content length is invalid")
            length = int(raw_length)
            if length > maximum:
                raise ContractError("request body exceeds the endpoint limit")
            previous_timeout = self.connection.gettimeout()
            deadline = time.monotonic() + REQUEST_READ_TIMEOUT_SECONDS
            try:
                body = bytearray()
                while len(body) < length:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise ContractError("request body read deadline exceeded")
                    self.connection.settimeout(remaining)
                    chunk = self.rfile.read1(min(length - len(body), 65536))
                    if type(chunk) is not bytes or len(chunk) > length - len(body):
                        raise ContractError("request body read failed")
                    if not chunk:
                        break
                    body.extend(chunk)
                    if time.monotonic() > deadline:
                        raise ContractError("request body read deadline exceeded")
            except OSError:
                raise ContractError("request body read failed") from None
            finally:
                try:
                    self.connection.settimeout(previous_timeout)
                except OSError:
                    pass
            if len(body) != length:
                raise ContractError("request body length is incomplete")
            return bytes(body)

        def _read_json(self) -> dict[str, Any]:
            content_types = self.headers.get_all("Content-Type", [])
            if len(content_types) != 1 or content_types[0].lower() not in {
                "application/json",
                "application/json; charset=utf-8",
            }:
                raise ContractError("request content type must be application/json")

            value = decode_strict_json_bytes(
                self._read(MAX_JSON_BODY), label="request JSON"
            )
            if not isinstance(value, dict):
                raise ContractError("request body must be a JSON object")
            return value

        @staticmethod
        def _fields(
            value: dict[str, Any],
            *,
            allowed: set[str],
            label: str,
        ) -> dict[str, Any]:
            if not set(value).issubset(allowed):
                raise ContractError(f"{label} fields are invalid")
            return value

        def _bearer(self) -> str:
            authorizations = self.headers.get_all("Authorization", [])
            if len(authorizations) != 1:
                raise ContractError("bearer authorization is required")
            authorization = authorizations[0]
            token = authorization[7:] if authorization.startswith("Bearer ") else ""
            if not 1 <= len(token) <= 1024 or any(
                character.isspace() or ord(character) < 0x21 for character in token
            ):
                raise ContractError("bearer authorization is required")
            return token

        def _principal(self) -> Principal:
            return store.authenticate(self._bearer())

        def _worker(self) -> WorkerPrincipal:
            return store.authenticate_worker(self._bearer())

        def _parts(self) -> list[str]:
            if (
                len(self.path.encode("utf-8", errors="ignore"))
                > MAX_REQUEST_TARGET_BYTES
            ):
                raise ContractError("control service request target exceeds limit")
            try:
                path = urlsplit(self.path)
            except ValueError:
                raise ContractError("control service request target is invalid") from None
            if (
                path.scheme
                or path.netloc
                or path.query
                or path.fragment
                or "?" in self.path
                or "#" in self.path
                or not path.path.startswith("/")
                or "//" in path.path
                or (len(path.path) > 1 and path.path.endswith("/"))
            ):
                raise ContractError("control service request target is invalid")
            raw_parts = path.path.split("/")[1:]
            if len(raw_parts) > 8:
                raise ContractError(
                    "control service request target has too many segments"
                )
            try:
                parts = [
                    unquote(part, encoding="utf-8", errors="strict")
                    for part in raw_parts
                ]
            except UnicodeDecodeError:
                raise ContractError(
                    "control service request target is not UTF-8"
                ) from None
            if any(
                part in {"", ".", ".."} or PATH_SEGMENT_RE.fullmatch(part) is None
                for part in parts
            ):
                raise ContractError("control service request target segment is invalid")
            return parts

        def _dispatch(self) -> None:
            parts = self._parts()
            if self.command == "GET" and parts == ["v1", "health"]:
                self._json(
                    200, {"schema": "browser-core.control-service/1", "status": "ok"}
                )
                return
            if len(parts) >= 3 and parts[:2] == ["v1", "workspaces"]:
                workspace_id = parts[2]
                if self.command == "GET" and parts[3:] == ["fleet"]:
                    self._json(200, store.fleet_status(self._principal(), workspace_id))
                    return
                if self.command == "GET" and parts[3:] == ["audit", "verify"]:
                    self._json(200, store.verify_audit(self._principal(), workspace_id))
                    return
                if self.command == "GET" and parts[3:] == ["jobs"]:
                    self._json(200, store.list_jobs(self._principal(), workspace_id))
                    return
                if self.command == "GET" and len(parts) == 5 and parts[3] == "jobs":
                    self._json(
                        200, store.get_job(self._principal(), workspace_id, parts[4])
                    )
                    return
                if len(parts) == 6 and parts[3] == "records":
                    kind, record_id = parts[4], parts[5]
                    if self.command == "GET":
                        self._json(
                            200,
                            store.get_record(
                                self._principal(),
                                workspace_id,
                                kind=kind,
                                record_id=record_id,
                            ),
                        )
                        return
                    if self.command == "PUT":
                        principal = self._principal()
                        body = self._fields(
                            self._read_json(),
                            allowed={"payload", "expected_revision"},
                            label="record update",
                        )
                        self._json(
                            200,
                            store.put_record(
                                principal,
                                workspace_id,
                                kind=kind,
                                record_id=record_id,
                                payload=body.get("payload"),
                                expected_revision=body.get("expected_revision"),
                            ),
                        )
                        return
                if self.command == "POST" and parts[3:] == ["jobs"]:
                    principal = self._principal()
                    body = self._fields(
                        self._read_json(),
                        allowed={
                            "kind",
                            "payload",
                            "requirements",
                            "idempotency_key",
                            "priority",
                            "max_attempts",
                            "persona_id",
                            "profile_id",
                        },
                        label="job enqueue",
                    )
                    self._json(
                        201,
                        store.enqueue_job(
                            principal,
                            workspace_id,
                            kind=body.get("kind"),
                            payload=body.get("payload"),
                            requirements=body.get("requirements"),
                            idempotency_key=body.get("idempotency_key"),
                            priority=body.get("priority", 0),
                            max_attempts=body.get("max_attempts", 3),
                            persona_id=body.get("persona_id"),
                            profile_id=body.get("profile_id"),
                        ),
                    )
                    return
                if (
                    self.command == "POST"
                    and len(parts) == 6
                    and parts[3] == "jobs"
                    and parts[5] == "cancel"
                ):
                    principal = self._principal()
                    self._fields(
                        self._read_json(),
                        allowed=set(),
                        label="job cancellation",
                    )
                    self._json(
                        200, store.cancel_job(principal, workspace_id, parts[4])
                    )
                    return
                if (
                    self.command == "POST"
                    and len(parts) == 6
                    and parts[3] == "tokens"
                    and parts[5] == "revoke"
                ):
                    principal = self._principal()
                    self._fields(
                        self._read_json(),
                        allowed=set(),
                        label="token revocation",
                    )
                    store.revoke_token(principal, workspace_id, parts[4])
                    self._json(200, {"token_id": parts[4], "revoked": True})
                    return
                if self.command == "PUT" and parts[3:] == ["artifacts"]:
                    visibility_values = self.headers.get_all(
                        "X-Artifact-Visibility", []
                    )
                    media_type_values = self.headers.get_all(
                        "X-Artifact-Media-Type", []
                    )
                    if len(visibility_values) > 1 or len(media_type_values) > 1:
                        raise ContractError("artifact metadata headers are ambiguous")
                    visibility = (
                        visibility_values[0] if visibility_values else "operator"
                    )
                    media_type = (
                        media_type_values[0]
                        if media_type_values
                        else "application/octet-stream"
                    )
                    self._json(
                        201,
                        store.put_artifact(
                            self._principal(),
                            workspace_id,
                            self._read(MAX_ARTIFACT_BODY),
                            media_type=media_type,
                            visibility=visibility,
                        ),
                    )
                    return
                if (
                    self.command == "GET"
                    and len(parts) == 5
                    and parts[3] == "artifacts"
                ):
                    content = store.get_artifact(
                        self._principal(), workspace_id, parts[4]
                    )
                    self._bytes(200, content, "application/octet-stream")
                    return
            if parts[:2] == ["v1", "workers"]:
                if self.command == "POST" and parts[2:] == ["lease"]:
                    worker = self._worker()
                    body = self._fields(
                        self._read_json(),
                        allowed={"lease_seconds"},
                        label="worker lease",
                    )
                    self._json(
                        200,
                        store.lease_job(
                            worker, lease_seconds=body.get("lease_seconds", 60)
                        ),
                    )
                    return
                if self.command == "POST" and len(parts) == 5 and parts[2] == "jobs":
                    job_id, action = parts[3], parts[4]
                    if action not in {"heartbeat", "complete"}:
                        self._json(404, {"error": "not_found"})
                        return
                    worker = self._worker()
                    body = self._read_json()
                    if action == "heartbeat":
                        self._fields(
                            body,
                            allowed={"lease_token", "extend_seconds"},
                            label="worker heartbeat",
                        )
                        self._json(
                            200,
                            store.heartbeat_lease(
                                worker,
                                job_id,
                                body.get("lease_token"),
                                extend_seconds=body.get("extend_seconds", 60),
                            ),
                        )
                        return
                    if action == "complete":
                        self._fields(
                            body,
                            allowed={"lease_token", "succeeded", "result"},
                            label="worker completion",
                        )
                        self._json(
                            200,
                            store.complete_job(
                                worker,
                                job_id,
                                body.get("lease_token"),
                                succeeded=body.get("succeeded"),
                                result=body.get("result"),
                            ),
                        )
                        return
            self._json(404, {"error": "not_found"})

        def do_GET(self) -> None:
            self._safe_dispatch()

        def do_POST(self) -> None:
            self._safe_dispatch()

        def do_PUT(self) -> None:
            self._safe_dispatch()

        def _safe_dispatch(self) -> None:
            self._response_started = False
            try:
                self._dispatch()
            except ContractError as exc:
                if self._response_started:
                    self.close_connection = True
                    return
                private_message = str(exc)
                status = (
                    403
                    if "scope does not permit" in private_message or any(
                        marker in private_message
                        for marker in ("role", "member", "visibility")
                    )
                    else 401
                    if "token" in private_message or "authorization" in private_message
                    else 400
                )
                message = (
                    "authentication rejected"
                    if status == 401
                    else "authorization role rejected"
                    if status == 403
                    else "request contract rejected"
                )
                try:
                    diagnostic = private_message.encode("utf-8", errors="strict")[:4096]
                except UnicodeEncodeError:
                    diagnostic = b"non-utf8-contract-diagnostic"
                try:
                    self._json(
                        status,
                        {
                            "error": "request_rejected",
                            "message": message,
                            "diagnostic_sha256_16": hashlib.sha256(diagnostic).hexdigest()[
                                :16
                            ],
                        },
                    )
                except Exception:
                    self.close_connection = True
                    return
            except (BrokenPipeError, ConnectionResetError):
                self.close_connection = True
                return
            except Exception as exc:
                if self._response_started:
                    self.close_connection = True
                    return
                try:
                    self._json(
                        500,
                        {
                            "error": "internal_error",
                            "message": "control service request failed",
                            "diagnostic_sha256_16": hashlib.sha256(
                                type(exc).__name__.encode("ascii")
                            ).hexdigest()[:16],
                        },
                    )
                except Exception:
                    self.close_connection = True
                    return

    return Handler


def _stop_control_server(
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
    shutdown_deadline = time.monotonic() + CONTROL_SERVICE_CLEANUP_TIMEOUT_SECONDS
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
                name="browser-core-control-shutdown",
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
            thread.join(timeout=CONTROL_SERVICE_CLEANUP_TIMEOUT_SECONDS)
            if thread.is_alive():
                failures.append("worker-thread")
        except (OSError, RuntimeError):
            failures.append("worker-thread")
    return failures


@contextmanager
def serve_control(
    store: ControlStore, config: ServiceConfig = ServiceConfig()
) -> Iterator[str]:
    validate_service_config(config)
    if not isinstance(store, ControlStore):
        raise ContractError("control service store is invalid")
    server: ThreadingHTTPServer | None = None
    scheme = "http"
    # A hosts-file or resolver override must not turn the no-TLS localhost
    # alias into a bind on another interface.
    bind_host = (
        "127.0.0.1"
        if config.host == "localhost" and config.tls_cert is None
        else config.host
    )
    thread: threading.Thread | None = None
    thread_started = False
    try:
        try:
            server_class = (
                _IPv6ThreadingHTTPServer
                if ":" in bind_host
                else ThreadingHTTPServer
            )
            server = server_class(
                (bind_host, config.port),
                _handler_class(store),
            )
            server.daemon_threads = True
        except (OSError, RuntimeError, ValueError) as exc:
            raise ContractError(
                f"control service could not start ({type(exc).__name__})"
            ) from None
        try:
            if config.tls_cert is not None and config.tls_key is not None:
                cert_before = _tls_credential_snapshot(
                    config.tls_cert,
                    label="TLS certificate",
                )
                key_before = _tls_credential_snapshot(
                    config.tls_key,
                    label="TLS private key",
                )
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                context.minimum_version = ssl.TLSVersion.TLSv1_2
                context.load_cert_chain(str(config.tls_cert), str(config.tls_key))
                cert_after = _tls_credential_snapshot(
                    config.tls_cert,
                    label="TLS certificate",
                )
                key_after = _tls_credential_snapshot(
                    config.tls_key,
                    label="TLS private key",
                )
                if cert_before != cert_after or key_before != key_after:
                    raise ContractError(
                        "control service TLS credentials changed while loading"
                    )
                server.socket = context.wrap_socket(
                    server.socket,
                    server_side=True,
                    do_handshake_on_connect=False,
                )
                scheme = "https"
            port = server.server_port
            if (
                isinstance(port, bool)
                or not isinstance(port, int)
                or not 1 <= port <= 65535
            ):
                raise ContractError("control service listener port is invalid")
            thread = threading.Thread(
                target=server.serve_forever,
                name="browser-core-control",
                daemon=True,
            )
        except ContractError:
            raise
        except (OSError, RuntimeError, ValueError, ssl.SSLError) as exc:
            raise ContractError(
                f"control service could not start ({type(exc).__name__})"
            ) from None
        try:
            thread.start()
            thread_started = True
        except (OSError, RuntimeError) as exc:
            # A worker can become live and still report a startup failure.
            # In that case the normal shutdown and join phases own it.
            try:
                thread_started = thread.is_alive() is not False
            except AttributeError:
                thread_started = False
            except (OSError, RuntimeError):
                thread_started = True
            raise ContractError(
                f"control service could not start ({type(exc).__name__})"
            ) from None
        if not thread.is_alive():
            raise ContractError("control service worker did not start")
        display_host = f"[{bind_host}]" if ":" in bind_host else bind_host
        yield f"{scheme}://{display_host}:{port}"
    finally:
        cleanup_failures = _stop_control_server(
            server,
            thread,
            thread_started=thread_started,
        )
        if cleanup_failures:
            phases = ",".join(cleanup_failures)
            cleanup_error = ContractError(f"control service cleanup failed ({phases})")
            active_error = sys.exc_info()[1]
            if active_error is not None:
                raise cleanup_error from active_error
            raise cleanup_error from None
