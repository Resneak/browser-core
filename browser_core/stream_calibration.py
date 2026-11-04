from __future__ import annotations

import hashlib
import json
import os
import re
import socket
import statistics
import stat
import sys
import time
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Lock, Thread
from typing import Any
from urllib.parse import urlsplit

from .cdp import wait_for_page_target
from .contracts import ContractError, reject_sensitive_keys
from .control_files import (
    decode_strict_json_bytes,
    read_bounded_control_snapshot_result,
)
from .launcher import EvaluationLaunch, launch_evaluation
from .lifecycle import stop_session, validate_stopped_session_receipt
from .local_http import _LocalPanelHeaderDeadline
from .numeric import is_finite_binary64_number, is_finite_number
from .perfetto import bind_perfetto_source_trace, export_perfetto
from .trace import scan_validated_trace
from .windows_change_time import windows_change_time


RESULT_SCHEMA = "browser-core.stream-calibration-result/1"
COHORT_SCHEMA = "browser-core.stream-trace-mode-cohort/1"
SCOPE_GATE_SCHEMA = "browser-core.stream-scope-gate/1"
SCOPE_COHORT_SCHEMA = "browser-core.stream-scope-cohort/1"
FIXTURE_TITLE = "browser-core-stream-calibration-ok"
MAX_RESULT_BYTES = 32 * 1024
MAX_FIXTURE_BYTES = 2 * 1024 * 1024
MAX_STREAM_TRACE_EVENTS = 1_000_000
MAX_STREAM_COHORT_TRIALS = 128
MAX_STREAM_TRACE_BYTES = 1024 * 1024 * 1024 * 1024
MAX_STREAM_REPORT_BYTES = 64 * 1024 * 1024
RESULT_READ_TIMEOUT_SECONDS = 5.0
STREAM_SERVER_CLEANUP_TIMEOUT_SECONDS = 5.0
STREAM_SESSION_CLEANUP_TIMEOUT_SECONDS = 15.0
_STREAM_CLIENTS_LOCK = Lock()


def _track_stream_client(server: Any, connection: socket.socket) -> None:
    with _STREAM_CLIENTS_LOCK:
        clients = getattr(server, '_stream_clients', None)
        if clients is None:
            clients = set()
            server._stream_clients = clients
        clients.add(connection)


def _release_stream_client(server: Any, connection: socket.socket) -> None:
    with _STREAM_CLIENTS_LOCK:
        clients = getattr(server, '_stream_clients', None)
        if clients is not None:
            clients.discard(connection)


def _track_stream_requests(server: Any) -> None:
    original = getattr(server, 'process_request', None)
    original_shutdown = getattr(server, 'shutdown_request', None)
    if not callable(original) or not callable(original_shutdown):
        return

    def process_request(request, address):
        # Register before the daemon handler starts, so shutdown also catches
        # an accepted socket whose handler has not run setup yet.
        _track_stream_client(server, request)
        try:
            return original(request, address)
        except BaseException:
            _release_stream_client(server, request)
            raise

    def shutdown_request(request):
        try:
            return original_shutdown(request)
        finally:
            _release_stream_client(server, request)

    server.process_request = process_request
    server.shutdown_request = shutdown_request


def _remaining_trial_time(deadline: float) -> float:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise ContractError("stream calibration trial timed out")
    return remaining


def _stop_stream_server(
    server: Any | None,
    thread: Any | None,
    *,
    started: bool,
) -> list[str]:
    failures: list[str] = []
    if server is None:
        return failures
    shutdown_thread: Any | None = None
    shutdown_deadline = time.monotonic() + STREAM_SERVER_CLEANUP_TIMEOUT_SECONDS
    if started:
        shutdown_failed: list[bool] = []

        def shutdown() -> None:
            try:
                server.shutdown()
            except Exception:
                shutdown_failed.append(True)

        try:
            shutdown_thread = Thread(
                target=shutdown,
                name="browser-core-stream-calibration-shutdown",
                daemon=True,
            )
            shutdown_thread.start()
            shutdown_thread.join(timeout=max(0.0, shutdown_deadline - time.monotonic()))
            if shutdown_thread.is_alive() or shutdown_failed:
                failures.append("server-shutdown")
        except (OSError, RuntimeError):
            failures.append("server-shutdown")
    try:
        server.server_close()
    except Exception:
        failures.append("server-close")
    if shutdown_thread is not None:
        # start() may raise after launching a live helper. Closing the server
        # can release that helper; always give it a bounded final join.
        try:
            shutdown_thread.join(timeout=max(0.0, shutdown_deadline - time.monotonic()))
            if shutdown_thread.is_alive() and "server-shutdown" not in failures:
                failures.append("server-shutdown")
        except (OSError, RuntimeError):
            if "server-shutdown" not in failures:
                failures.append("server-shutdown")
    if started and thread is not None:
        try:
            thread.join(timeout=STREAM_SERVER_CLEANUP_TIMEOUT_SECONDS)
            if thread.is_alive():
                failures.append("server-thread")
        except (OSError, RuntimeError):
            failures.append("server-thread")
    # ThreadingHTTPServer does not close accepted sockets when daemon_threads
    # is true. Close idle keep-alive and partial-header clients explicitly.
    with _STREAM_CLIENTS_LOCK:
        clients = tuple(getattr(server, '_stream_clients', ()))
    for client in clients:
        try:
            client.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass  # The handler may already have closed this connection.
        try:
            client.close()
        except OSError:
            if 'server-client-close' not in failures:
                failures.append('server-client-close')
    return failures


def _stable_regular_bytes(path: Path, *, maximum: int, label: str) -> bytes:
    snapshot = read_bounded_control_snapshot_result(
        path,
        maximum=maximum,
        label=label,
        require_single_link=True,
    )
    if snapshot.state != "complete" or snapshot.body is None:
        raise ContractError(f"{label} is {snapshot.state}")
    return snapshot.body


def _regular_file_identity(path: Path, *, label: str) -> tuple[int, ...]:
    if not isinstance(path, Path):
        raise ContractError(f"{label} path must be a Path")
    try:
        metadata = os.lstat(path)
    except FileNotFoundError:
        raise ContractError(f"{label} is missing") from None
    except OSError as exc:
        code = getattr(exc, "winerror", None) or exc.errno
        suffix = f" (os_error={code})" if isinstance(code, int) else ""
        raise ContractError(f"{label} inspection failed{suffix}") from None
    attributes = int(getattr(metadata, "st_file_attributes", 0))
    if not stat.S_ISREG(metadata.st_mode) or attributes & 0x400:
        raise ContractError(f"{label} is not a regular file")
    if metadata.st_nlink != 1:
        raise ContractError(f"{label} must not have additional hard links")
    if metadata.st_size > MAX_STREAM_TRACE_BYTES:
        raise ContractError(f"{label} exceeds the byte limit")
    identity = (
        metadata.st_dev,
        metadata.st_ino,
        stat.S_IFMT(metadata.st_mode),
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
        attributes,
    )
    if os.name != "nt":
        return identity
    try:
        with path.open("rb", buffering=0) as stream:
            opened = os.fstat(stream.fileno())
            opened_identity = (
                opened.st_dev, opened.st_ino, stat.S_IFMT(opened.st_mode),
                opened.st_size, opened.st_mtime_ns, opened.st_ctime_ns,
                int(getattr(opened, "st_file_attributes", 0)),
            )
            if opened_identity != identity or opened.st_nlink != 1:
                raise ContractError(f"{label} changed during inspection")
            change_time = windows_change_time(stream)
        if _regular_file_path_identity(path, label=label) != identity:
            raise ContractError(f"{label} changed during inspection")
    except OSError:
        raise ContractError(f"{label} change time could not be inspected") from None
    return (*identity, change_time)


def _regular_file_path_identity(path: Path, *, label: str) -> tuple[int, ...]:
    try:
        metadata = os.lstat(path)
    except OSError:
        raise ContractError(f"{label} changed during inspection") from None
    attributes = int(getattr(metadata, "st_file_attributes", 0))
    if not stat.S_ISREG(metadata.st_mode) or attributes & 0x400 or metadata.st_nlink != 1:
        raise ContractError(f"{label} changed during inspection")
    return (
        metadata.st_dev, metadata.st_ino, stat.S_IFMT(metadata.st_mode),
        metadata.st_size, metadata.st_mtime_ns, metadata.st_ctime_ns, attributes,
    )


def _validate_trial_config(
    config: StreamCalibrationTrial,
    repository_root: Path,
) -> None:
    if type(config) is not StreamCalibrationTrial:
        raise ContractError("stream calibration config is invalid")
    if not all(
        isinstance(value, Path)
        for value in (
            config.executable,
            config.trace_processor,
            config.workspace,
            repository_root,
        )
    ):
        raise ContractError("stream calibration paths must be Paths")
    if not isinstance(config.trace_mode, str) or config.trace_mode not in {"off", "on"}:
        raise ContractError("stream calibration trace mode is invalid")
    if not isinstance(config.trace_scope, str) or config.trace_scope not in {"causal", "causal-stream"}:
        raise ContractError("stream calibration trace scope is invalid")
    if (
        isinstance(config.reads, bool)
        or not isinstance(config.reads, int)
        or not 1 <= config.reads <= 4096
        or isinstance(config.warmup_reads, bool)
        or not isinstance(config.warmup_reads, int)
        or not 1 <= config.warmup_reads <= 256
    ):
        raise ContractError("stream calibration read bounds are invalid")
    if not is_finite_number(config.timeout_seconds) or not (
        0 < config.timeout_seconds <= 300
    ):
        raise ContractError("stream calibration timeout is invalid")


def validate_stream_calibration_trial_config(
    config: StreamCalibrationTrial,
    repository_root: Path,
) -> None:
    """Validate one trial without contacting the browser or filesystem."""
    _validate_trial_config(config, repository_root)


@dataclass(frozen=True)
class StreamCalibrationTrial:
    executable: Path
    trace_processor: Path
    workspace: Path
    trace_mode: str
    trace_scope: str = "causal-stream"
    reads: int = 1024
    warmup_reads: int = 32
    timeout_seconds: float = 45.0


def _number(value: Any, label: str) -> float:
    if type(value) not in {int, float}:
        raise ContractError(f"{label} must be a number")
    if not is_finite_number(value) or not 0 <= value <= 120_000:
        raise ContractError(f"{label} is outside its allowed range")
    return float(value)


def _exact_keys(value: Any, expected: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != expected:
        raise ContractError(f"{label} fields are invalid")
    return value


def validate_stream_calibration_result(
    document: Any,
    *,
    expected_reads: int | None = None,
    expected_warmup_reads: int | None = None,
) -> dict[str, Any]:
    for expected, label in (
        (expected_reads, "expected reads"),
        (expected_warmup_reads, "expected warmup reads"),
    ):
        if expected is not None and (
            isinstance(expected, bool) or not isinstance(expected, int) or expected < 1
        ):
            raise ContractError(f"stream calibration {label} is invalid")
    result = _exact_keys(
        document,
        {
            "schema",
            "verdict",
            "reads",
            "warmup_reads",
            "descriptors",
            "default",
            "byob",
        },
        "stream calibration result",
    )
    if result.get("schema") != RESULT_SCHEMA or result.get("verdict") != "pass":
        raise ContractError("stream calibration result did not pass")
    reads = result.get("reads")
    warmup_reads = result.get("warmup_reads")
    if isinstance(reads, bool) or not isinstance(reads, int) or not 1 <= reads <= 4096:
        raise ContractError("stream calibration reads are invalid")
    if (
        isinstance(warmup_reads, bool)
        or not isinstance(warmup_reads, int)
        or not 1 <= warmup_reads <= 256
    ):
        raise ContractError("stream calibration warmup reads are invalid")
    if expected_reads is not None and reads != expected_reads:
        raise ContractError("stream calibration reads disagree with the trial")
    if expected_warmup_reads is not None and warmup_reads != expected_warmup_reads:
        raise ContractError("stream calibration warmup reads disagree with the trial")

    descriptors = _exact_keys(
        result.get("descriptors"),
        {"default", "byob"},
        "stream calibration descriptors",
    )
    descriptor_fields = {
        "configurable",
        "enumerable",
        "writable",
        "function_name",
        "function_length",
        "native_source",
        "identity_stable",
    }
    expected_descriptors = {
        "default": {
            "configurable": True,
            "enumerable": True,
            "writable": True,
            "function_name": "read",
            "function_length": 0,
            "native_source": True,
            "identity_stable": True,
        },
        "byob": {
            "configurable": True,
            "enumerable": True,
            "writable": True,
            "function_name": "read",
            "function_length": 1,
            "native_source": True,
            "identity_stable": True,
        },
    }
    for mode, expected in expected_descriptors.items():
        descriptor = _exact_keys(
            descriptors.get(mode),
            descriptor_fields,
            f"stream calibration {mode} descriptor",
        )
        if any(
            type(descriptor[field]) is not type(wanted)
            or descriptor[field] != wanted
            for field, wanted in expected.items()
        ):
            raise ContractError(f"stream calibration {mode} descriptor changed")

    common_fields = {"chunks", "bytes", "closed", "lock_released", "duration_ms"}
    default = _exact_keys(
        result.get("default"),
        common_fields | {"close_value_undefined"},
        "stream calibration default result",
    )
    byob = _exact_keys(
        result.get("byob"),
        common_fields | {"close_value_type", "close_value_length"},
        "stream calibration BYOB result",
    )
    for mode, value in (("default", default), ("byob", byob)):
        if (
            type(value.get("chunks")) is not int
            or value["chunks"] != reads
            or type(value.get("bytes")) is not int
            or value["bytes"] != reads * 32
            or value.get("closed") is not True
            or value.get("lock_released") is not True
        ):
            raise ContractError(f"stream calibration {mode} semantics changed")
        _number(value.get("duration_ms"), f"stream calibration {mode} duration")
    if default.get("close_value_undefined") is not True:
        raise ContractError("default reader closure value changed")
    if (
        byob.get("close_value_type") != "[object Uint8Array]"
        or type(byob.get("close_value_length")) is not int
        or byob.get("close_value_length") != 0
    ):
        raise ContractError("BYOB reader closure value changed")
    reject_sensitive_keys(result)
    return result


class _ResultStore:
    def __init__(self, reads: int, warmup_reads: int) -> None:
        self._reads = reads
        self._warmup_reads = warmup_reads
        self._lock = Lock()
        self._result_body: bytes | None = None
        self._error: str | None = None

    def put(self, document: Any) -> None:
        try:
            validated = validate_stream_calibration_result(
                document,
                expected_reads=self._reads,
                expected_warmup_reads=self._warmup_reads,
            )
        except ContractError:
            with self._lock:
                self._error = "invalid fixture result"
            raise
        try:
            body = json.dumps(
                validated,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            ).encode("utf-8")
        except (TypeError, ValueError):
            raise ContractError(
                "stream calibration result is not strict JSON"
            ) from None
        if len(body) > MAX_RESULT_BYTES:
            raise ContractError("stream calibration result exceeds byte limit")
        with self._lock:
            if self._result_body is not None:
                raise ContractError(
                    "stream calibration result was submitted more than once"
                )
            self._result_body = body

    def get(self) -> dict[str, Any] | None:
        with self._lock:
            body = self._result_body
        if body is None:
            return None
        document = decode_strict_json_bytes(body, label="stream calibration result")
        if not isinstance(
            document, dict
        ):  # pragma: no cover - put always stores an object
            raise ContractError("stream calibration result is invalid")
        return document

    def get_error(self) -> str | None:
        with self._lock:
            return self._error


def _handler(fixture: bytes, store: _ResultStore) -> type[BaseHTTPRequestHandler]:
    if type(fixture) is not bytes or not fixture or len(fixture) > MAX_FIXTURE_BYTES:
        raise ContractError("stream calibration fixture bytes are invalid")
    if not isinstance(store, _ResultStore):
        raise ContractError("stream calibration result store is invalid")

    class CalibrationHandler(_LocalPanelHeaderDeadline, BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def handle(self) -> None:
            try:
                super().handle()
            except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
                # Shutdown can interrupt an idle keep-alive read on Windows.
                return

        def setup(self) -> None:
            super().setup()
            _track_stream_client(self.server, self.connection)

        def finish(self) -> None:
            try:
                super().finish()
            finally:
                _release_stream_client(self.server, self.connection)

        def do_GET(self) -> None:
            if urlsplit(self.path).path != "/":
                self.send_error(404)
                return
            body = fixture
            self.send_response(200)
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self) -> None:
            if (
                urlsplit(self.path).path != "/result"
                or self.headers.get_content_type() != "application/json"
                or self.headers.get("Transfer-Encoding") is not None
            ):
                self.close_connection = True
                self.send_error(404)
                return
            try:
                content_lengths = self.headers.get_all("Content-Length", [])
                if (
                    len(content_lengths) != 1
                    or re.fullmatch(r"[1-9][0-9]{0,5}", content_lengths[0]) is None
                ):
                    raise ContractError("stream calibration result size is invalid")
                length = int(content_lengths[0])
                if not 1 <= length <= MAX_RESULT_BYTES:
                    raise ContractError("stream calibration result size is invalid")
                deadline = time.monotonic() + RESULT_READ_TIMEOUT_SECONDS
                payload = bytearray()
                try:
                    while len(payload) < length:
                        remaining = deadline - time.monotonic()
                        if remaining <= 0:
                            raise ContractError("stream calibration result body timed out")
                        self.connection.settimeout(remaining)
                        chunk = self.rfile.read1(length - len(payload))
                        if time.monotonic() >= deadline:
                            raise ContractError("stream calibration result body timed out")
                        if not chunk:
                            break
                        payload.extend(chunk)
                finally:
                    # Preserve the handler's former keep-alive idle timeout.
                    self.connection.settimeout(RESULT_READ_TIMEOUT_SECONDS)
                if len(payload) != length:
                    raise ContractError("stream calibration result body is incomplete")

                document = decode_strict_json_bytes(
                    bytes(payload),
                    label="stream calibration fixture result",
                )
                store.put(document)
            except (
                ValueError,
                json.JSONDecodeError,
                ContractError,
                OSError,
            ):
                self.close_connection = True
                self.send_error(400)
                return
            self.send_response(204)
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, format: str, *args: object) -> None:
            return

    return CalibrationHandler


def _native_stream_summary(
    trace_path: Path,
    reads: int,
    warmup_reads: int,
    *,
    expect_stream_events: bool = True,
) -> dict[str, Any]:
    if (
        not isinstance(trace_path, Path)
        or isinstance(reads, bool)
        or not isinstance(reads, int)
        or not 1 <= reads <= 4096
        or isinstance(warmup_reads, bool)
        or not isinstance(warmup_reads, int)
        or not 1 <= warmup_reads <= 256
        or not isinstance(expect_stream_events, bool)
    ):
        raise ContractError("stream calibration trace summary inputs are invalid")
    trace_identity = _regular_file_identity(
        trace_path,
        label="stream calibration normalized trace",
    )
    request_count = 0
    result_count = 0
    mode_counts = {
        mode: {"requests": 0, "results": 0, "chunks": 0, "closed": 0}
        for mode in ("default", "byob")
    }
    digest = hashlib.sha256()
    observed_bytes = 0

    def hash_observed(raw: bytes) -> None:
        nonlocal observed_bytes
        observed_bytes += len(raw)
        digest.update(raw)

    def count_stream_event(event: dict[str, Any]) -> None:
        nonlocal request_count, result_count
        kind = event["event"]
        if kind not in (
            {"category": "stream", "name": "stream.read.request"},
            {"category": "stream", "name": "stream.read.result"},
        ):
            return
        if not expect_stream_events:
            raise ContractError(
                "causal-only calibration unexpectedly activated stream events"
            )
        detail = event.get("detail")
        mode = detail.get("reader_mode") if isinstance(detail, dict) else None
        if not isinstance(mode, str) or mode not in mode_counts:
            raise ContractError("stream calibration trace reader mode is invalid")
        if kind["name"] == "stream.read.request":
            request_count += 1
            mode_counts[mode]["requests"] += 1
            return
        result_count += 1
        mode_counts[mode]["results"] += 1
        result_kind = detail.get("result_kind") if isinstance(detail, dict) else None
        if result_kind == "chunk":
            value = event.get("value")
            if (
                not isinstance(value, dict)
                or type(value.get("length")) is not int
                or value["length"] != 32
            ):
                raise ContractError("stream calibration trace chunk length is invalid")
            mode_counts[mode]["chunks"] += 1
        elif result_kind == "closed":
            mode_counts[mode]["closed"] += 1
        else:
            raise ContractError("stream calibration trace result kind is invalid")

    validation = scan_validated_trace(
        trace_path,
        count_stream_event,
        hash_update=hash_observed,
        maximum_events=MAX_STREAM_TRACE_EVENTS,
    )
    binding = bind_perfetto_source_trace(trace_path)
    if (
        _regular_file_identity(
            trace_path,
            label="stream calibration normalized trace",
        )
        != trace_identity
        or binding != {"bytes": observed_bytes, "sha256": digest.hexdigest()}
    ):
        raise ContractError(
            "stream calibration normalized trace changed during summary"
        )

    if not expect_stream_events:
        if validation["dropped_events"]:
            raise ContractError("stream calibration trace reported dropped events")
        return {
            "events": validation["events"],
            "dropped_events": validation["dropped_events"],
            "requests": 0,
            "results": 0,
            "modes": {},
        }
    expected_per_mode = reads + warmup_reads + 2
    expected_total = expected_per_mode * 2
    if request_count != expected_total or result_count != expected_total:
        raise ContractError("stream calibration trace has an unexpected read count")
    counts: dict[str, Any] = {}
    for mode in ("default", "byob"):
        observed = mode_counts[mode]
        if (
            observed["requests"] != expected_per_mode
            or observed["results"] != expected_per_mode
            or observed["chunks"] != reads + warmup_reads
            or observed["closed"] != 2
        ):
            raise ContractError(f"stream calibration trace {mode} coverage is invalid")
        counts[mode] = {
            "results": observed["results"],
            "chunks": observed["chunks"],
            "closed": observed["closed"],
        }
    if validation["dropped_events"]:
        raise ContractError("stream calibration trace reported dropped events")
    return {
        "events": validation["events"],
        "dropped_events": validation["dropped_events"],
        "requests": request_count,
        "results": result_count,
        "modes": counts,
    }


def run_stream_calibration_trial(
    config: StreamCalibrationTrial,
    repository_root: Path,
) -> dict[str, Any]:
    _validate_trial_config(config, repository_root)
    fixture = repository_root / "fixtures" / "native-stream-calibration.html"
    fixture_bytes = _stable_regular_bytes(
        fixture,
        maximum=MAX_FIXTURE_BYTES,
        label="stream calibration fixture",
    )
    store = _ResultStore(config.reads, config.warmup_reads)
    deadline = time.monotonic() + float(config.timeout_seconds)
    server: ThreadingHTTPServer | None = None
    thread: Thread | None = None
    server_started = False
    session_path: Path | None = None
    session: dict[str, Any] | None = None
    stop_status: dict[str, Any] | None = None
    perfetto_identity: tuple[int, ...] | None = None
    source_binding: dict[str, Any] | None = None
    try:
        try:
            server = ThreadingHTTPServer(
                ("127.0.0.1", 0),
                _handler(fixture_bytes, store),
            )
            server.daemon_threads = True
            _track_stream_requests(server)
            thread = Thread(
                target=server.serve_forever,
                name="browser-core-stream-calibration",
                daemon=True,
            )
        except (OSError, RuntimeError, ValueError) as exc:
            raise ContractError(
                f"stream calibration server could not start ({type(exc).__name__})"
            ) from None
        try:
            thread.start()
        except (OSError, RuntimeError) as exc:
            # start() can report failure after serve_forever has launched.
            # Reuse the normal bounded shutdown and join for that live worker.
            try:
                server_started = thread.is_alive() is not False
            except AttributeError:
                server_started = False
            except (OSError, RuntimeError):
                server_started = True
            raise ContractError(
                f"stream calibration server could not start ({type(exc).__name__})"
            ) from None
        server_started = True
        url = (
            f"http://127.0.0.1:{server.server_port}/"
            f"?reads={config.reads}&warmup={config.warmup_reads}"
        )
        session_path, session = launch_evaluation(
            EvaluationLaunch(
                executable=config.executable,
                workspace=config.workspace,
                headless=True,
                timeout_seconds=_remaining_trial_time(deadline),
                trace_mode=config.trace_mode,
                trace_scope=config.trace_scope,
                extra_args=(url,),
            ),
            repository_root,
        )
        try:
            wait_for_page_target(
                session["automation"]["cdp_endpoint"],
                url,
                FIXTURE_TITLE,
                timeout_seconds=_remaining_trial_time(deadline),
                failure_title_prefix="browser-core-stream-calibration-failed:",
            )
        except ContractError as exc:
            result_error = store.get_error()
            if result_error is not None:
                raise ContractError(
                    f"stream calibration fixture result was rejected: {result_error}"
                ) from exc
            raise
    finally:
        cleanup_failures: list[str] = []
        if session_path is not None:
            try:
                stop_status = validate_stopped_session_receipt(
                    stop_session(
                        session_path,
                        timeout_seconds=STREAM_SESSION_CLEANUP_TIMEOUT_SECONDS,
                    ),
                    expected_run_id=(
                        session.get("run_id") if session is not None else None
                    ),
                )
            except (ContractError, OSError, ValueError):
                cleanup_failures.append("session-stop")
        if (
            stop_status is not None
            and config.trace_mode == "on"
            and session is not None
        ):
            try:
                perfetto_path = Path(session["trace_path"])
                perfetto_identity = _regular_file_identity(
                    perfetto_path,
                    label="stream calibration Perfetto trace",
                )
                source_binding = bind_perfetto_source_trace(perfetto_path)
                if source_binding["bytes"] != perfetto_identity[3]:
                    raise ContractError(
                        "stream calibration Perfetto trace changed before export"
                    )
            except (ContractError, OSError, TypeError, ValueError):
                cleanup_failures.append("trace-bind")
        cleanup_failures.extend(
            _stop_stream_server(
                server,
                thread,
                started=server_started,
            )
        )
        if cleanup_failures:
            phases = ",".join(cleanup_failures)
            cleanup_error = ContractError(
                f"stream calibration cleanup failed ({phases})"
            )
            active_error = sys.exc_info()[1]
            if active_error is not None:
                raise cleanup_error from active_error
            raise cleanup_error from None
        if sys.exc_info()[1] is None:
            _remaining_trial_time(deadline)
    if session is None or session_path is None:
        raise ContractError("stream calibration session was not created")
    if stop_status is None or stop_status.get("state") != "stopped":
        raise ContractError("stream calibration session stop was not verified")
    fixture_result = store.get()
    if fixture_result is None:
        raise ContractError("stream calibration fixture did not publish a result")

    trace_bytes: int | None = None
    trace_summary: dict[str, Any] | None = None
    if config.trace_mode == "on":
        perfetto_path = Path(session["trace_path"])
        if perfetto_identity is None or source_binding is None:
            raise ContractError("stream calibration Perfetto trace was not bound")
        normalized_path = perfetto_path.with_suffix(".jsonl")
        export_perfetto(
            config.trace_processor,
            perfetto_path,
            normalized_path,
            session["run_id"],
            session["chromium_revision"],
            maximum_events=MAX_STREAM_TRACE_EVENTS,
            expected_source_binding=source_binding,
        )
        if (
            _regular_file_identity(
                perfetto_path,
                label="stream calibration Perfetto trace",
            )
            != perfetto_identity
        ):
            raise ContractError(
                "stream calibration Perfetto trace changed during export"
            )
        trace_bytes = perfetto_identity[3]
        trace_summary = _native_stream_summary(
            normalized_path,
            config.reads,
            config.warmup_reads,
            expect_stream_events=config.trace_scope == "causal-stream",
        )
    elif session.get("trace_path") is not None:
        raise ContractError("trace-off stream calibration retained a trace path")
    return _validated_stream_run(
        {
            "trace_mode": config.trace_mode,
            "trace_scope": session.get("trace_scope"),
            "run_id": session["run_id"],
            "fixture_result": fixture_result,
            "trace_bytes": trace_bytes,
            "trace_summary": trace_summary,
        }
    )


def _median(values: list[float]) -> float:
    return round(float(statistics.median(values)), 3)


def _percent(enabled: float, disabled: float) -> float:
    if disabled <= 0:
        raise ContractError("trace-off stream duration median must be positive")
    result = ((enabled - disabled) / disabled) * 100.0
    if not is_finite_binary64_number(result):
        raise ContractError("stream overhead is outside the finite numeric range")
    return round(result, 3)


def _validated_trace_summary(value: Any) -> dict[str, Any] | None:
    if value is None:
        return None
    summary = _exact_keys(
        value,
        {"events", "dropped_events", "requests", "results", "modes"},
        "stream calibration trace summary",
    )
    for field in ("events", "dropped_events", "requests", "results"):
        count = summary.get(field)
        if (
            isinstance(count, bool)
            or not isinstance(count, int)
            or count < (1 if field == "events" else 0)
            or count > MAX_STREAM_TRACE_EVENTS
        ):
            raise ContractError("stream calibration trace summary count is invalid")
    modes = summary.get("modes")
    if not isinstance(modes, dict) or set(modes) not in (
        set(),
        {"default", "byob"},
    ):
        raise ContractError("stream calibration trace summary modes are invalid")
    safe_modes: dict[str, dict[str, int]] = {}
    for mode in ("default", "byob"):
        if mode not in modes:
            continue
        row = _exact_keys(
            modes[mode],
            {"results", "chunks", "closed"},
            f"stream calibration {mode} trace summary",
        )
        safe_row: dict[str, int] = {}
        for field in ("results", "chunks", "closed"):
            count = row.get(field)
            if (
                isinstance(count, bool)
                or not isinstance(count, int)
                or not 0 <= count <= MAX_STREAM_TRACE_EVENTS
            ):
                raise ContractError("stream calibration trace mode count is invalid")
            safe_row[field] = count
        safe_modes[mode] = safe_row
    return {
        "events": summary["events"],
        "dropped_events": summary["dropped_events"],
        "requests": summary["requests"],
        "results": summary["results"],
        "modes": safe_modes,
    }


def _validated_stream_run(value: Any) -> dict[str, Any]:
    required = {
        "trace_mode",
        "trace_scope",
        "run_id",
        "fixture_result",
        "trace_bytes",
        "trace_summary",
    }
    optional = {"session_file", "pair_index", "position"}
    if (
        type(value) is not dict
        or not required <= set(value)
        or not set(value) <= required | optional
        or (("pair_index" in value) != ("position" in value))
    ):
        raise ContractError("stream calibration run fields are invalid")
    if "session_file" in value:
        session_file = value.get("session_file")
        if (
            not isinstance(session_file, str)
            or not session_file
            or len(session_file.encode("utf-8", errors="replace")) > 16_384
            or any(ord(char) < 32 or ord(char) == 127 for char in session_file)
        ):
            raise ContractError("stream calibration legacy session path is invalid")
    mode = value.get("trace_mode")
    scope = value.get("trace_scope")
    if not isinstance(mode, str) or mode not in {"off", "on"} or (
        (mode == "off" and scope is not None)
        or (mode == "on" and (not isinstance(scope, str) or scope not in {"causal", "causal-stream"}))
    ):
        raise ContractError("stream calibration run trace contract is invalid")
    run_id = value.get("run_id")
    if (
        not isinstance(run_id, str)
        or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", run_id) is None
    ):
        raise ContractError("stream calibration run id is invalid")
    fixture_result = validate_stream_calibration_result(value.get("fixture_result"))
    trace_bytes = value.get("trace_bytes")
    trace_summary = _validated_trace_summary(value.get("trace_summary"))
    if mode == "off":
        if trace_bytes is not None or trace_summary is not None:
            raise ContractError("trace-off stream calibration retained trace evidence")
    elif (
        isinstance(trace_bytes, bool)
        or not isinstance(trace_bytes, int)
        or not 1 <= trace_bytes <= MAX_STREAM_TRACE_BYTES
        or trace_summary is None
    ):
        raise ContractError("trace-on stream calibration evidence is invalid")
    safe = {
        "trace_mode": mode,
        "trace_scope": scope,
        "run_id": run_id,
        "fixture_result": json.loads(
            json.dumps(fixture_result, allow_nan=False, sort_keys=True)
        ),
        "trace_bytes": trace_bytes,
        "trace_summary": trace_summary,
    }
    if "pair_index" in value:
        pair_index = value.get("pair_index")
        position = value.get("position")
        if (
            isinstance(pair_index, bool)
            or not isinstance(pair_index, int)
            or not 0 <= pair_index < MAX_STREAM_COHORT_TRIALS
            or isinstance(position, bool)
            or not isinstance(position, int)
            or position not in {0, 1}
        ):
            raise ContractError("stream calibration run pairing is invalid")
        safe["pair_index"] = pair_index
        safe["position"] = position
    reject_sensitive_keys(safe)
    return safe


def _semantic_vector(run: dict[str, Any]) -> dict[str, Any]:
    result = validate_stream_calibration_result(run.get("fixture_result"))
    return {
        "reads": result["reads"],
        "warmup_reads": result["warmup_reads"],
        "descriptors": result["descriptors"],
        "default": {
            key: value
            for key, value in result["default"].items()
            if key != "duration_ms"
        },
        "byob": {
            key: value for key, value in result["byob"].items() if key != "duration_ms"
        },
    }


def _summarize_stream_scope_runs(runs: dict[str, dict[str, Any]]) -> dict[str, Any]:
    if type(runs) is not dict or set(runs) != {"causal", "causal-stream"}:
        raise ContractError("stream scope gate requires causal and causal-stream runs")
    safe_runs: dict[str, dict[str, Any]] = {}
    for scope, run in runs.items():
        safe_run = _validated_stream_run(run)
        if safe_run.get("trace_mode") != "on" or safe_run.get("trace_scope") != scope:
            raise ContractError(f"stream scope gate {scope} run contract is invalid")
        safe_runs[scope] = safe_run

    causal = safe_runs["causal"]
    stream = safe_runs["causal-stream"]
    vectors_stable = _semantic_vector(causal) == _semantic_vector(stream)
    causal_summary = causal.get("trace_summary")
    stream_summary = stream.get("trace_summary")
    if not isinstance(causal_summary, dict) or not isinstance(stream_summary, dict):
        raise ContractError("stream scope gate trace summary is missing")
    result = validate_stream_calibration_result(stream.get("fixture_result"))
    expected_per_mode = result["reads"] + result["warmup_reads"] + 2
    expected_modes = {
        mode: {
            "results": expected_per_mode,
            "chunks": result["reads"] + result["warmup_reads"],
            "closed": 2,
        }
        for mode in ("default", "byob")
    }
    gates = {
        "stable_descriptor_and_semantic_vector": vectors_stable,
        "causal_trace_nonempty": (
            isinstance(causal_summary.get("events"), int)
            and causal_summary["events"] > 0
        ),
        "causal_scope_zero_stream_events": (
            causal_summary.get("requests") == 0
            and causal_summary.get("results") == 0
            and causal_summary.get("modes") == {}
        ),
        "causal_stream_scope_exact_coverage": (
            stream_summary.get("requests") == expected_per_mode * 2
            and stream_summary.get("results") == expected_per_mode * 2
            and stream_summary.get("modes") == expected_modes
        ),
        "zero_trace_drops": (
            causal_summary.get("dropped_events") == 0
            and stream_summary.get("dropped_events") == 0
        ),
    }
    return {
        "schema": SCOPE_GATE_SCHEMA,
        "passed": all(gates.values()),
        "gates": gates,
        "runs": safe_runs,
        "limitations": [
            "this proves category isolation only on the owned loopback fixture",
            "it is not a zero-overhead, timing-equivalence, or undetectability claim",
        ],
    }


def validate_stream_scope_report(document: Any) -> dict[str, Any]:
    report = _exact_keys(
        document,
        {"schema", "passed", "gates", "runs", "limitations"},
        "stream scope report",
    )
    if report.get("schema") != SCOPE_GATE_SCHEMA:
        raise ContractError("stream scope report schema is invalid")
    gates = _exact_keys(
        report.get("gates"),
        {
            "stable_descriptor_and_semantic_vector",
            "causal_trace_nonempty",
            "causal_scope_zero_stream_events",
            "causal_stream_scope_exact_coverage",
            "zero_trace_drops",
        },
        "stream scope report gates",
    )
    if type(report.get("passed")) is not bool or any(
        type(value) is not bool for value in gates.values()
    ):
        raise ContractError("stream scope report verdict is invalid")
    runs = report.get("runs")
    if type(runs) is not dict:
        raise ContractError("stream scope report runs are invalid")
    expected = _summarize_stream_scope_runs(runs)
    if report != expected:
        raise ContractError("stream scope report is inconsistent")
    reject_sensitive_keys(report)
    return report


def summarize_stream_scope_runs(runs: dict[str, dict[str, Any]]) -> dict[str, Any]:
    return validate_stream_scope_report(_summarize_stream_scope_runs(runs))


def validate_stream_cohort_controls(
    *,
    trials_per_arm: int,
    maximum_overhead_percent: float,
    max_trace_bytes: int,
) -> None:
    """Validate cohort controls before trials or output mutation begin."""
    if (
        isinstance(trials_per_arm, bool)
        or not isinstance(trials_per_arm, int)
        or not 2 <= trials_per_arm <= MAX_STREAM_COHORT_TRIALS
    ):
        raise ContractError("stream calibration cohort trial count is invalid")
    if (
        not is_finite_number(maximum_overhead_percent)
        or not 0 <= maximum_overhead_percent <= 1_000_000
        or isinstance(max_trace_bytes, bool)
        or not isinstance(max_trace_bytes, int)
        or not 1 <= max_trace_bytes <= MAX_STREAM_TRACE_BYTES
    ):
        raise ContractError("stream calibration cohort limits are invalid")


def summarize_stream_scope_cohort(
    runs: list[dict[str, Any]],
    *,
    trials_per_arm: int,
    max_added_overhead_percent: float,
    max_trace_bytes: int,
) -> dict[str, Any]:
    validate_stream_cohort_controls(
        trials_per_arm=trials_per_arm,
        maximum_overhead_percent=max_added_overhead_percent,
        max_trace_bytes=max_trace_bytes,
    )
    if type(runs) is not list or len(runs) != trials_per_arm * 2:
        raise ContractError("stream scope cohort run count is invalid")
    scopes = ("causal", "causal-stream")
    by_scope: dict[str, list[dict[str, Any]]] = {scope: [] for scope in scopes}
    pairs: dict[int, dict[str, dict[str, Any]]] = {}
    vectors: list[dict[str, Any]] = []
    for index, raw_run in enumerate(runs):
        run = _validated_stream_run(raw_run)
        scope = run.get("trace_scope")
        pair_index = run.get("pair_index")
        position = run.get("position")
        if run.get("trace_mode") != "on" or scope not in by_scope:
            raise ContractError(f"stream scope cohort run {index} is invalid")
        if (
            isinstance(pair_index, bool)
            or not isinstance(pair_index, int)
            or not 0 <= pair_index < trials_per_arm
            or position not in {0, 1}
        ):
            raise ContractError(f"stream scope cohort run {index} pairing is invalid")
        pair = pairs.setdefault(pair_index, {})
        if scope in pair:
            raise ContractError("stream scope cohort pair repeats an arm")
        pair[scope] = run
        by_scope[scope].append(run)
        vectors.append(_semantic_vector(run))
    if (
        len(pairs) != trials_per_arm
        or any(len(items) != trials_per_arm for items in by_scope.values())
        or any(set(pair) != set(scopes) for pair in pairs.values())
    ):
        raise ContractError("stream scope cohort arms are unbalanced")

    pair_reports = []
    for pair_index, pair in sorted(pairs.items()):
        expected = (
            {"causal": 0, "causal-stream": 1}
            if pair_index % 2 == 0
            else {"causal-stream": 0, "causal": 1}
        )
        if any(
            pair[scope]["position"] != position for scope, position in expected.items()
        ):
            raise ContractError("stream scope cohort pair order is invalid")
        pair_reports.append(summarize_stream_scope_runs(pair))

    aggregates: dict[str, Any] = {}
    totals: dict[str, list[float]] = {}
    for scope, items in by_scope.items():
        default = [
            _number(
                item["fixture_result"]["default"]["duration_ms"], "default duration"
            )
            for item in items
        ]
        byob = [
            _number(item["fixture_result"]["byob"]["duration_ms"], "BYOB duration")
            for item in items
        ]
        totals[scope] = [left + right for left, right in zip(default, byob)]
        sizes = [item.get("trace_bytes") for item in items]
        if not all(
            isinstance(value, int) and not isinstance(value, bool) and value > 0
            for value in sizes
        ):
            raise ContractError("stream scope cohort trace sizes are invalid")
        aggregates[scope] = {
            "runs": len(items),
            "default_duration_ms_median": _median(default),
            "byob_duration_ms_median": _median(byob),
            "total_duration_ms_median": _median(totals[scope]),
            "trace_bytes_median": _median([float(value) for value in sizes]),
            "trace_bytes_max": max(sizes),
        }

    paired_overheads = [
        _percent(
            sum(
                _number(
                    pairs[index]["causal-stream"]["fixture_result"][mode][
                        "duration_ms"
                    ],
                    f"{mode} duration",
                )
                for mode in ("default", "byob")
            ),
            sum(
                _number(
                    pairs[index]["causal"]["fixture_result"][mode]["duration_ms"],
                    f"{mode} duration",
                )
                for mode in ("default", "byob")
            ),
        )
        for index in sorted(pairs)
    ]
    overhead = _percent(
        aggregates["causal-stream"]["total_duration_ms_median"],
        aggregates["causal"]["total_duration_ms_median"],
    )
    paired_median = _median(paired_overheads)
    gates = {
        "balanced_alternating_arms": True,
        "stable_descriptor_and_semantic_vector": all(
            vector == vectors[0] for vector in vectors[1:]
        ),
        "every_pair_passed_scope_isolation": all(
            report["passed"] for report in pair_reports
        ),
        "trace_size_within_limit": all(
            aggregate["trace_bytes_max"] <= max_trace_bytes
            for aggregate in aggregates.values()
        ),
        "added_stream_overhead_within_declared_limit": (
            overhead <= max_added_overhead_percent
            and paired_median <= max_added_overhead_percent
        ),
    }
    report = {
        "schema": SCOPE_COHORT_SCHEMA,
        "passed": all(gates.values()),
        "gates": gates,
        "limits": {
            "max_added_overhead_percent": max_added_overhead_percent,
            "max_trace_bytes": max_trace_bytes,
        },
        "aggregates": aggregates,
        "delta": {
            "total_median_added_overhead_percent": overhead,
            "paired_added_overhead_percent": paired_overheads,
            "paired_added_overhead_percent_median": paired_median,
        },
        "assessment": {
            "semantics": "stable"
            if gates["stable_descriptor_and_semantic_vector"]
            else "changed",
            "timing_direction": (
                "causal_stream_slower_in_paired_median"
                if paired_median > 0
                else "causal_stream_faster_in_paired_median"
                if paired_median < 0
                else "equal_paired_median"
            ),
        },
        "limitations": [
            "timings describe one owned microbenchmark and one attested build",
            "a passing limit is not a timing-equivalence or undetectability claim",
        ],
    }
    return validate_stream_scope_cohort_report(report)


def validate_stream_scope_cohort_report(document: Any) -> dict[str, Any]:
    report = _exact_keys(
        document,
        {
            "schema",
            "passed",
            "gates",
            "limits",
            "aggregates",
            "delta",
            "assessment",
            "limitations",
        },
        "stream scope cohort report",
    )
    if report.get("schema") != SCOPE_COHORT_SCHEMA:
        raise ContractError("stream scope cohort report schema is invalid")
    aggregates = _exact_keys(
        report.get("aggregates"),
        {"causal", "causal-stream"},
        "stream scope cohort aggregates",
    )
    aggregate_fields = {
        "runs",
        "default_duration_ms_median",
        "byob_duration_ms_median",
        "total_duration_ms_median",
        "trace_bytes_median",
        "trace_bytes_max",
    }
    for scope in ("causal", "causal-stream"):
        aggregate = _exact_keys(
            aggregates.get(scope),
            aggregate_fields,
            f"stream {scope} cohort aggregate",
        )
        runs = aggregate.get("runs")
        if (
            isinstance(runs, bool)
            or not isinstance(runs, int)
            or not 2 <= runs <= MAX_STREAM_COHORT_TRIALS
        ):
            raise ContractError(f"stream {scope} cohort run count is invalid")
        for field in (
            "default_duration_ms_median",
            "byob_duration_ms_median",
            "total_duration_ms_median",
        ):
            _number(aggregate.get(field), f"stream {scope} cohort {field}")
        trace_median = aggregate.get("trace_bytes_median")
        trace_max = aggregate.get("trace_bytes_max")
        if (
            not is_finite_number(trace_median)
            or isinstance(trace_max, bool)
            or not isinstance(trace_max, int)
            or not 0 < trace_median <= trace_max <= MAX_STREAM_TRACE_BYTES
        ):
            raise ContractError(f"stream {scope} cohort trace sizes are invalid")

    delta = _exact_keys(
        report.get("delta"),
        {
            "total_median_added_overhead_percent",
            "paired_added_overhead_percent",
            "paired_added_overhead_percent_median",
        },
        "stream scope cohort delta",
    )
    paired = delta.get("paired_added_overhead_percent")
    if (
        type(paired) is not list
        or len(paired) != aggregates["causal"]["runs"]
        or any(
            not is_finite_binary64_number(value)
            for value in paired
        )
    ):
        raise ContractError("stream scope cohort paired overheads are invalid")
    expected_overhead = _percent(
        float(aggregates["causal-stream"]["total_duration_ms_median"]),
        float(aggregates["causal"]["total_duration_ms_median"]),
    )
    expected_paired_median = _median([float(value) for value in paired])
    if (
        not is_finite_number(delta.get("total_median_added_overhead_percent"))
        or delta["total_median_added_overhead_percent"] != expected_overhead
        or not is_finite_number(delta.get("paired_added_overhead_percent_median"))
        or delta["paired_added_overhead_percent_median"] != expected_paired_median
    ):
        raise ContractError("stream scope cohort overhead is inconsistent")

    limits = _exact_keys(
        report.get("limits"),
        {"max_added_overhead_percent", "max_trace_bytes"},
        "stream scope cohort limits",
    )
    validate_stream_cohort_controls(
        trials_per_arm=aggregates["causal"]["runs"],
        maximum_overhead_percent=limits.get("max_added_overhead_percent"),
        max_trace_bytes=limits.get("max_trace_bytes"),
    )
    gate_fields = {
        "balanced_alternating_arms",
        "stable_descriptor_and_semantic_vector",
        "every_pair_passed_scope_isolation",
        "trace_size_within_limit",
        "added_stream_overhead_within_declared_limit",
    }
    gates = _exact_keys(report.get("gates"), gate_fields, "stream scope cohort gates")
    if any(type(value) is not bool for value in gates.values()):
        raise ContractError("stream scope cohort gates are invalid")
    derived_gates = {
        "balanced_alternating_arms": aggregates["causal"]["runs"]
        == aggregates["causal-stream"]["runs"],
        "trace_size_within_limit": all(
            aggregate["trace_bytes_max"] <= limits["max_trace_bytes"]
            for aggregate in aggregates.values()
        ),
        "added_stream_overhead_within_declared_limit": (
            expected_overhead <= limits["max_added_overhead_percent"]
            and expected_paired_median <= limits["max_added_overhead_percent"]
        ),
    }
    if any(gates[field] is not value for field, value in derived_gates.items()):
        raise ContractError("stream scope cohort gates are inconsistent")

    expected_assessment = {
        "semantics": (
            "stable" if gates["stable_descriptor_and_semantic_vector"] else "changed"
        ),
        "timing_direction": (
            "causal_stream_slower_in_paired_median"
            if expected_paired_median > 0
            else "causal_stream_faster_in_paired_median"
            if expected_paired_median < 0
            else "equal_paired_median"
        ),
    }
    if report.get("assessment") != expected_assessment:
        raise ContractError("stream scope cohort assessment is inconsistent")
    if report.get("limitations") != [
        "timings describe one owned microbenchmark and one attested build",
        "a passing limit is not a timing-equivalence or undetectability claim",
    ]:
        raise ContractError("stream scope cohort limitations are invalid")
    if type(report.get("passed")) is not bool or report["passed"] is not all(
        gates.values()
    ):
        raise ContractError("stream scope cohort verdict is inconsistent")
    reject_sensitive_keys(report)
    return report


def summarize_stream_trace_mode_runs(
    runs: list[dict[str, Any]],
    *,
    trials_per_arm: int,
    max_read_overhead_percent: float,
    max_trace_bytes: int,
) -> dict[str, Any]:
    validate_stream_cohort_controls(
        trials_per_arm=trials_per_arm,
        maximum_overhead_percent=max_read_overhead_percent,
        max_trace_bytes=max_trace_bytes,
    )
    if type(runs) is not list or len(runs) != trials_per_arm * 2:
        raise ContractError("stream calibration cohort run count is invalid")
    by_mode: dict[str, list[dict[str, Any]]] = {"off": [], "on": []}
    pairs: dict[int, dict[str, dict[str, Any]]] = {}
    vectors: list[dict[str, Any]] = []
    for index, raw_run in enumerate(runs):
        run = _validated_stream_run(raw_run)
        if run.get("trace_mode") not in by_mode:
            raise ContractError(f"stream calibration run {index} is invalid")
        pair_index = run.get("pair_index")
        position = run.get("position")
        if (
            isinstance(pair_index, bool)
            or not isinstance(pair_index, int)
            or not 0 <= pair_index < trials_per_arm
            or position not in {0, 1}
        ):
            raise ContractError(f"stream calibration run {index} pairing is invalid")
        mode = run["trace_mode"]
        pair = pairs.setdefault(pair_index, {})
        if mode in pair:
            raise ContractError("stream calibration pair repeats an arm")
        pair[mode] = run
        by_mode[mode].append(run)
        vectors.append(_semantic_vector(run))
    if (
        any(len(items) != trials_per_arm for items in by_mode.values())
        or len(pairs) != trials_per_arm
        or any(set(pair) != {"off", "on"} for pair in pairs.values())
    ):
        raise ContractError("stream calibration cohort arms are unbalanced")
    for pair_index, pair in pairs.items():
        expected_positions = (
            {"off": 0, "on": 1} if pair_index % 2 == 0 else {"on": 0, "off": 1}
        )
        if any(
            pair[mode]["position"] != position
            for mode, position in expected_positions.items()
        ):
            raise ContractError("stream calibration pair order is invalid")

    aggregates: dict[str, Any] = {}
    for mode, items in by_mode.items():
        default = [
            _number(
                item["fixture_result"]["default"]["duration_ms"], "default duration"
            )
            for item in items
        ]
        byob = [
            _number(item["fixture_result"]["byob"]["duration_ms"], "BYOB duration")
            for item in items
        ]
        totals = [left + right for left, right in zip(default, byob)]
        aggregates[mode] = {
            "runs": len(items),
            "default_duration_ms_median": _median(default),
            "byob_duration_ms_median": _median(byob),
            "total_duration_ms_median": _median(totals),
        }
        if mode == "on":
            sizes = [item.get("trace_bytes") for item in items]
            if not all(
                isinstance(value, int) and not isinstance(value, bool) and value > 0
                for value in sizes
            ):
                raise ContractError("trace-on stream calibration sizes are invalid")
            aggregates[mode]["trace_bytes_median"] = _median(
                [float(value) for value in sizes]
            )
            aggregates[mode]["trace_bytes_max"] = max(sizes)

    paired_overheads = []
    for pair_index in sorted(pairs):
        pair = pairs[pair_index]
        off = sum(
            _number(
                pair["off"]["fixture_result"][mode]["duration_ms"], f"{mode} duration"
            )
            for mode in ("default", "byob")
        )
        on = sum(
            _number(
                pair["on"]["fixture_result"][mode]["duration_ms"], f"{mode} duration"
            )
            for mode in ("default", "byob")
        )
        paired_overheads.append(_percent(on, off))
    overhead = _percent(
        aggregates["on"]["total_duration_ms_median"],
        aggregates["off"]["total_duration_ms_median"],
    )
    stable_semantics = all(vector == vectors[0] for vector in vectors[1:])
    expected_results = vectors[0]["reads"] + vectors[0]["warmup_reads"] + 2
    expected_mode_counts = {
        "results": expected_results,
        "chunks": vectors[0]["reads"] + vectors[0]["warmup_reads"],
        "closed": 2,
    }
    exact_native_coverage = all(
        isinstance(run.get("trace_summary"), dict)
        and run["trace_summary"].get("dropped_events") == 0
        and run["trace_summary"].get("requests") == expected_results * 2
        and run["trace_summary"].get("results") == expected_results * 2
        and run["trace_summary"].get("modes")
        == {
            "default": expected_mode_counts,
            "byob": expected_mode_counts,
        }
        for run in by_mode["on"]
    )
    trace_scope_contract = all(
        run.get("trace_scope") == "causal-stream" for run in by_mode["on"]
    ) and all(run.get("trace_scope") is None for run in by_mode["off"])
    gates = {
        "balanced_paired_arms": True,
        "causal_stream_trace_scope_only": trace_scope_contract,
        "stable_descriptor_and_semantic_vector": stable_semantics,
        "trace_on_exact_native_stream_coverage": exact_native_coverage,
        "trace_off_has_no_artifact": all(
            run.get("trace_bytes") is None and run.get("trace_summary") is None
            for run in by_mode["off"]
        ),
        "trace_size_within_limit": aggregates["on"]["trace_bytes_max"]
        <= max_trace_bytes,
        "read_overhead_within_limit": overhead <= max_read_overhead_percent,
    }
    paired_median = _median(paired_overheads)
    if paired_median > 0:
        timing_direction = "trace_on_slower_in_paired_median"
    elif paired_median < 0:
        timing_direction = "trace_on_faster_in_paired_median"
    else:
        timing_direction = "equal_at_reported_resolution"
    report = {
        "schema": COHORT_SCHEMA,
        "arms": aggregates,
        "delta": {
            "total_median_overhead_percent": overhead,
            "paired_overhead_percent": paired_overheads,
            "paired_overhead_percent_median": paired_median,
        },
        "assessment": {
            "semantics": (
                "stable_in_supplied_trials"
                if stable_semantics
                else "changed_across_supplied_trials"
            ),
            "timing_direction": timing_direction,
        },
        "limits": {
            "max_read_overhead_percent": max_read_overhead_percent,
            "max_trace_bytes": max_trace_bytes,
        },
        "gates": gates,
        "passed": all(gates.values()),
        "limitations": [
            "timings are descriptive local measurements, not proof of equivalent distributions",
            "the owned synthetic stream loop is not representative of every application workload",
            "trace-off versus causal-stream-trace-on includes native event serialization overhead",
            "stable descriptors and results do not prove an application cannot detect timing perturbation",
        ],
    }
    return validate_stream_trace_mode_cohort_report(report)


def validate_stream_trace_mode_cohort_report(document: Any) -> dict[str, Any]:
    report = _exact_keys(
        document,
        {
            "schema",
            "arms",
            "delta",
            "assessment",
            "limits",
            "gates",
            "passed",
            "limitations",
        },
        "stream trace-mode cohort report",
    )
    if report.get("schema") != COHORT_SCHEMA:
        raise ContractError("stream trace-mode cohort report schema is invalid")
    arms = _exact_keys(
        report.get("arms"), {"off", "on"}, "stream trace-mode cohort arms"
    )
    common = {
        "runs",
        "default_duration_ms_median",
        "byob_duration_ms_median",
        "total_duration_ms_median",
    }
    off = _exact_keys(arms.get("off"), common, "stream trace-off cohort arm")
    on = _exact_keys(
        arms.get("on"),
        common | {"trace_bytes_median", "trace_bytes_max"},
        "stream trace-on cohort arm",
    )
    for mode, arm in (("off", off), ("on", on)):
        runs = arm.get("runs")
        if (
            isinstance(runs, bool)
            or not isinstance(runs, int)
            or not 2 <= runs <= MAX_STREAM_COHORT_TRIALS
        ):
            raise ContractError(f"stream trace-{mode} cohort run count is invalid")
        for field in (
            "default_duration_ms_median",
            "byob_duration_ms_median",
            "total_duration_ms_median",
        ):
            _number(arm.get(field), f"stream trace-{mode} cohort {field}")
    trace_median = on.get("trace_bytes_median")
    trace_max = on.get("trace_bytes_max")
    if (
        not is_finite_number(trace_median)
        or isinstance(trace_max, bool)
        or not isinstance(trace_max, int)
        or not 0 < trace_median <= trace_max <= MAX_STREAM_TRACE_BYTES
    ):
        raise ContractError("stream trace-mode cohort trace sizes are invalid")

    delta = _exact_keys(
        report.get("delta"),
        {
            "total_median_overhead_percent",
            "paired_overhead_percent",
            "paired_overhead_percent_median",
        },
        "stream trace-mode cohort delta",
    )
    paired = delta.get("paired_overhead_percent")
    if (
        type(paired) is not list
        or len(paired) != off["runs"]
        or any(
            not is_finite_binary64_number(value)
            for value in paired
        )
    ):
        raise ContractError("stream trace-mode paired overheads are invalid")
    expected_overhead = _percent(
        float(on["total_duration_ms_median"]),
        float(off["total_duration_ms_median"]),
    )
    expected_paired_median = _median([float(value) for value in paired])
    if (
        not is_finite_number(delta.get("total_median_overhead_percent"))
        or delta["total_median_overhead_percent"] != expected_overhead
        or not is_finite_number(delta.get("paired_overhead_percent_median"))
        or delta["paired_overhead_percent_median"] != expected_paired_median
    ):
        raise ContractError("stream trace-mode cohort overhead is inconsistent")

    limits = _exact_keys(
        report.get("limits"),
        {"max_read_overhead_percent", "max_trace_bytes"},
        "stream trace-mode cohort limits",
    )
    validate_stream_cohort_controls(
        trials_per_arm=off["runs"],
        maximum_overhead_percent=limits.get("max_read_overhead_percent"),
        max_trace_bytes=limits.get("max_trace_bytes"),
    )
    gate_fields = {
        "balanced_paired_arms",
        "causal_stream_trace_scope_only",
        "stable_descriptor_and_semantic_vector",
        "trace_on_exact_native_stream_coverage",
        "trace_off_has_no_artifact",
        "trace_size_within_limit",
        "read_overhead_within_limit",
    }
    gates = _exact_keys(
        report.get("gates"), gate_fields, "stream trace-mode cohort gates"
    )
    if any(type(value) is not bool for value in gates.values()):
        raise ContractError("stream trace-mode cohort gates are invalid")
    derived_gates = {
        "balanced_paired_arms": off["runs"] == on["runs"],
        "trace_size_within_limit": trace_max <= limits["max_trace_bytes"],
        "read_overhead_within_limit": expected_overhead
        <= limits["max_read_overhead_percent"],
    }
    if any(gates[field] is not value for field, value in derived_gates.items()):
        raise ContractError("stream trace-mode cohort gates are inconsistent")

    expected_assessment = {
        "semantics": (
            "stable_in_supplied_trials"
            if gates["stable_descriptor_and_semantic_vector"]
            else "changed_across_supplied_trials"
        ),
        "timing_direction": (
            "trace_on_slower_in_paired_median"
            if expected_paired_median > 0
            else "trace_on_faster_in_paired_median"
            if expected_paired_median < 0
            else "equal_at_reported_resolution"
        ),
    }
    if report.get("assessment") != expected_assessment:
        raise ContractError("stream trace-mode cohort assessment is inconsistent")
    expected_limitations = [
        "timings are descriptive local measurements, not proof of equivalent distributions",
        "the owned synthetic stream loop is not representative of every application workload",
        "trace-off versus causal-stream-trace-on includes native event serialization overhead",
        "stable descriptors and results do not prove an application cannot detect timing perturbation",
    ]
    if report.get("limitations") != expected_limitations:
        raise ContractError("stream trace-mode cohort limitations are invalid")
    if type(report.get("passed")) is not bool or report["passed"] is not all(
        gates.values()
    ):
        raise ContractError("stream trace-mode cohort verdict is inconsistent")
    reject_sensitive_keys(report)
    return report
