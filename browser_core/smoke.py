from __future__ import annotations

import hashlib
import json
import sys
import time
from contextlib import contextmanager
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from threading import Thread
from typing import Any, Iterator
from urllib.parse import urlsplit

from .cdp import wait_for_page_target
from .contracts import BODY_CONSUMER_MODES, ContractError
from .control_files import read_bounded_control_snapshot_result
from .launcher import EvaluationLaunch, launch_evaluation
from .lifecycle import stop_session, validate_stopped_session_receipt
from .local_http import LocalPanelServer
from .numeric import is_finite_number
from .perfetto import bind_perfetto_source_trace, export_perfetto
from .trace import load_validated_trace


CANVAS_WIDTH = 17
CANVAS_HEIGHT = 19
CANVAS_API = "HTMLCanvasElement.toDataURL"
FIXTURE_TITLE = "browser-core-native-canvas-ok"
MULTICONTEXT_FIXTURE_TITLE = "browser-core-native-multicontext-ok"
OBSERVATION_COMPONENTS = {
    "blink.canvas",
    "blink.fetch",
    "blink.fetch-body",
    "blink.messaging",
    "blink.streams",
    "blink.v8",
    "blink.webcrypto",
    "v8.wasm",
}
MAX_SMOKE_FIXTURE_BYTES = 2 * 1024 * 1024
MAX_SMOKE_FIXTURE_TOTAL_BYTES = 6 * 1024 * 1024
MAX_SMOKE_TRACE_EVENTS = 1_000_000
SMOKE_SERVER_CLEANUP_TIMEOUT_SECONDS = 5.0
SMOKE_SESSION_CLEANUP_TIMEOUT_SECONDS = 15.0


@dataclass(frozen=True)
class NativeCanvasSmoke:
    executable: Path
    trace_processor: Path
    workspace: Path
    timeout_seconds: float = 30.0


@dataclass(frozen=True)
class NativeMultiContextSmoke:
    executable: Path
    trace_processor: Path
    workspace: Path
    timeout_seconds: float = 45.0


def _validate_smoke_config(
    config: NativeCanvasSmoke | NativeMultiContextSmoke,
    repository_root: Path,
    *,
    expected_type: type[NativeCanvasSmoke] | type[NativeMultiContextSmoke],
) -> None:
    if type(config) is not expected_type:
        raise ContractError("native smoke config is invalid")
    if not isinstance(repository_root, Path) or not all(
        isinstance(value, Path)
        for value in (config.executable, config.trace_processor, config.workspace)
    ):
        raise ContractError("native smoke paths must be Paths")
    if not is_finite_number(config.timeout_seconds) or not (
        0 < config.timeout_seconds <= 300
    ):
        raise ContractError("native smoke timeout is invalid")


def _remaining_smoke_time(deadline: float) -> float:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise ContractError("native smoke timed out")
    return remaining


def _validated_smoke_stop_receipt(
    value: Any,
    *,
    expected_run_id: str,
) -> dict[str, Any]:
    try:
        return validate_stopped_session_receipt(
            value,
            expected_run_id=expected_run_id,
        )
    except ContractError:
        raise ContractError("native smoke session stop was not verified") from None


def _stop_native_smoke_session(
    path: Path,
    session: dict[str, Any],
) -> dict[str, Any]:
    raw = stop_session(
        path,
        timeout_seconds=SMOKE_SESSION_CLEANUP_TIMEOUT_SECONDS,
    )
    return _validated_smoke_stop_receipt(
        raw,
        expected_run_id=session["run_id"],
    )


def _fixture_bytes(path: Path, *, label: str) -> bytes:
    snapshot = read_bounded_control_snapshot_result(
        path,
        maximum=MAX_SMOKE_FIXTURE_BYTES,
        label=label,
    )
    if snapshot.state != "complete" or snapshot.body is None:
        raise ContractError(f"{label} is {snapshot.state}")
    return snapshot.body


def _fixture_handler(
    routes: dict[str, tuple[bytes, str]],
) -> type[BaseHTTPRequestHandler]:
    if (
        not isinstance(routes, dict)
        or not 1 <= len(routes) <= 8
        or any(
            not isinstance(path, str)
            or not path.startswith("/")
            or len(path) > 2048
            or not path.isascii()
            or any(ord(character) <= 0x20 or ord(character) == 0x7F for character in path)
            or any(character in path for character in "?#")
            or not isinstance(route, tuple)
            or len(route) != 2
            or not isinstance(route[0], bytes)
            or len(route[0]) > MAX_SMOKE_FIXTURE_BYTES
            or not isinstance(route[1], str)
            or not 1 <= len(route[1]) <= 128
            or not route[1].isascii()
            or any(ord(character) < 0x20 or ord(character) == 0x7F for character in route[1])
            for path, route in routes.items()
        )
        or sum(len(route[0]) for route in routes.values())
        > MAX_SMOKE_FIXTURE_TOTAL_BYTES
    ):
        raise ContractError("native smoke fixture routes are invalid")
    retained_routes = dict(routes)

    class FixtureHandler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_GET(self) -> None:
            path = urlsplit(self.path).path
            if path == "/probe":
                payload = b"ok"
                self.send_response(200)
                self.send_header("Cache-Control", "no-store")
                self.send_header("Content-Type", "application/octet-stream")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
                return
            route = retained_routes.get(path)
            if route is None:
                self.send_error(404)
                return
            payload, content_type = route
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, format: str, *args: object) -> None:
            return

    return FixtureHandler


@contextmanager
def _serve_fixtures(
    routes: dict[str, tuple[bytes, str]],
) -> Iterator[str]:
    handler = _fixture_handler(routes)
    server: LocalPanelServer | None = None
    server_thread: Thread | None = None
    thread_started = False
    try:
        try:
            server = LocalPanelServer(("127.0.0.1", 0), handler)
            port = server.server_port
            if (
                isinstance(port, bool)
                or not isinstance(port, int)
                or not 1 <= port <= 65535
            ):
                raise ContractError("native smoke fixture listener port is invalid")
            server_thread = Thread(
                target=server.serve_forever,
                name="browser-core-native-smoke-fixture",
                daemon=True,
            )
        except ContractError:
            raise
        except (OSError, RuntimeError, ValueError) as exc:
            raise ContractError(
                f"native smoke fixture server could not start ({type(exc).__name__})"
            ) from None
        try:
            server_thread.start()
            thread_started = True
        except (OSError, RuntimeError) as exc:
            # A start error can arrive after the worker begins serving.
            # Retain the live thread for shutdown and join in the finally path.
            try:
                thread_started = server_thread.is_alive() is not False
            except AttributeError:
                thread_started = False
            except (OSError, RuntimeError):
                thread_started = True
            raise ContractError(
                f"native smoke fixture server could not start ({type(exc).__name__})"
            ) from None
        if not server_thread.is_alive():
            raise ContractError("native smoke fixture worker did not start")
        yield f"http://127.0.0.1:{port}/"
    finally:
        cleanup_failures = _stop_fixture_server(
            server,
            server_thread,
            thread_started=thread_started,
        )
        if cleanup_failures:
            phases = ",".join(cleanup_failures)
            cleanup_error = ContractError(
                f"native smoke fixture cleanup failed ({phases})"
            )
            active_error = sys.exc_info()[1]
            if active_error is not None:
                raise cleanup_error from active_error
            raise cleanup_error from None


def _stop_fixture_server(
    server: Any | None,
    server_thread: Any | None,
    *,
    thread_started: bool,
) -> list[str]:
    failures: list[str] = []
    if server is None:
        return failures
    worker_alive = False
    if thread_started and server_thread is not None:
        try:
            worker_alive = server_thread.is_alive()
            if type(worker_alive) is not bool:
                failures.append("worker-status")
                worker_alive = True
        except (OSError, RuntimeError):
            failures.append("worker-status")
            worker_alive = True
    shutdown_thread: Any | None = None
    shutdown_deadline = time.monotonic() + SMOKE_SERVER_CLEANUP_TIMEOUT_SECONDS
    if worker_alive:
        shutdown_failed: list[bool] = []

        def shutdown() -> None:
            try:
                server.shutdown()
            except Exception:
                shutdown_failed.append(True)

        try:
            shutdown_thread = Thread(
                target=shutdown,
                name="browser-core-native-smoke-fixture-shutdown",
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
    if thread_started and server_thread is not None:
        try:
            server_thread.join(timeout=SMOKE_SERVER_CLEANUP_TIMEOUT_SECONDS)
            if server_thread.is_alive():
                failures.append("worker-thread")
        except (OSError, RuntimeError):
            failures.append("worker-thread")
    return failures


def assert_native_canvas_trace(path: Path) -> dict[str, Any]:
    summary, events, _by_seq = load_validated_trace(
        path,
        maximum_events=MAX_SMOKE_TRACE_EVENTS,
    )
    matches = [
        event
        for event in events
        if event["event"] == {"category": "api", "name": CANVAS_API}
        and event.get("detail", {}).get("native_name") == "BrowserCore.CanvasReadback"
        and event.get("detail", {}).get("width") == CANVAS_WIDTH
        and event.get("detail", {}).get("height") == CANVAS_HEIGHT
        and event.get("detail", {}).get("origin_clean") is True
        and event.get("provenance", {}).get("source") == "native"
    ]
    if not matches:
        raise ContractError(
            "normalized trace has no matching native canvas smoke event"
        )
    return {**summary, "matching_canvas_events": len(matches)}


def _native_observation_vector_from_events(
    source_events: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    events = [
        event
        for event in source_events
        if event.get("provenance", {}).get("source") == "native"
        and event.get("provenance", {}).get("component") in OBSERVATION_COMPONENTS
    ]
    sequence = {event["seq"]: index for index, event in enumerate(events)}
    vector: list[dict[str, Any]] = []
    for event in events:
        execution = event.get("execution") or {}
        detail = {
            key: value
            for key, value in event.get("detail", {}).items()
            if key != "thread_id"
        }
        request = event.get("request")
        if request is not None:
            request = {key: value for key, value in request.items() if key != "id"}
        vector.append(
            {
                "event": event["event"],
                "component": event["provenance"]["component"],
                "context": (
                    "frame"
                    if execution.get("frame_id") is not None
                    else "worker"
                    if execution.get("worker_id") is not None
                    else None
                ),
                "script": execution.get("script_id") is not None,
                "causal_parent_index": sequence.get(event.get("causal_parent_seq")),
                "detail": detail,
                "request": request,
                "value": event.get("value"),
            }
        )
    return vector


def native_observation_vector(path: Path) -> list[dict[str, Any]]:
    _summary, events, _by_seq = load_validated_trace(
        path,
        maximum_events=MAX_SMOKE_TRACE_EVENTS,
    )
    return _native_observation_vector_from_events(events)


def native_observation_digest(path: Path) -> tuple[int, str]:
    vector = native_observation_vector(path)
    canonical = json.dumps(
        vector,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return len(vector), hashlib.sha256(canonical).hexdigest()


def assert_native_multicontext_trace(path: Path) -> dict[str, Any]:
    summary, events, by_seq = load_validated_trace(
        path,
        maximum_events=MAX_SMOKE_TRACE_EVENTS,
    )

    def generated_binding_event(event: dict[str, Any]) -> bool:
        return (
            event.get("provenance", {}).get("component") == "blink.bindings.generated"
        )

    frame_contexts = {
        execution["frame_id"]
        for event in events
        if not generated_binding_event(event)
        if (execution := event.get("execution") or {}).get("frame_id") is not None
    }
    worker_contexts = {
        execution["worker_id"]
        for event in events
        if not generated_binding_event(event)
        if (execution := event.get("execution") or {}).get("worker_id") is not None
    }
    frame_renderer_pids = {
        event["process"]["pid"]
        for event in events
        if not generated_binding_event(event)
        if (event.get("execution") or {}).get("frame_id") is not None
        and event["process"].get("type") == "renderer"
    }
    if len(frame_contexts) < 2:
        raise ContractError(
            "native multicontext trace has fewer than two frame contexts"
        )
    if not worker_contexts:
        raise ContractError("native multicontext trace has no worker context")
    if len(frame_renderer_pids) < 2:
        raise ContractError("native multicontext trace did not prove an OOPIF renderer")

    def context_classes(category: str, name: str) -> set[str]:
        classes: set[str] = set()
        for event in events:
            if generated_binding_event(event):
                continue
            if event["event"] != {"category": category, "name": name}:
                continue
            execution = event.get("execution") or {}
            if execution.get("frame_id") is not None:
                classes.add("frame")
            if execution.get("worker_id") is not None:
                classes.add("worker")
        return classes

    required_context_classes = {
        "message": context_classes("message", "MessagePort.postMessage"),
        "crypto": context_classes("crypto", "SubtleCrypto.digest"),
        "wasm": context_classes("wasm", "WebAssembly.compile.completed"),
        "network": context_classes("network", "fetch.request.start"),
        "stream": context_classes("stream", "stream.read.result"),
        "message_delivery": context_classes(
            "message", "MessagePort.message.dispatch"
        ),
    }
    for label, classes in required_context_classes.items():
        if classes != {"frame", "worker"}:
            raise ContractError(
                f"native multicontext trace lacks frame/worker {label} coverage: {sorted(classes)}"
            )

    request_events = [
        event
        for event in events
        if event["event"] == {"category": "network", "name": "fetch.request.start"}
    ]
    if len(request_events) < 3:
        raise ContractError(
            "native multicontext trace has fewer than three fetch requests"
        )
    for request_event in request_events:
        api_seq = request_event.get("causal_parent_seq")
        api_event = by_seq.get(api_seq)
        if api_event is None or api_event["event"] != {
            "category": "api",
            "name": "fetch",
        }:
            raise ContractError(
                "native fetch request lacks an explicit fetch API parent"
            )
        script_seq = api_event.get("causal_parent_seq")
        script_event = by_seq.get(script_seq)
        if script_event is None or script_event["event"] != {
            "category": "execution",
            "name": "script.run",
        }:
            raise ContractError("native fetch API lacks an explicit script parent")
    request_url_classes = {
        (event.get("request") or {}).get("url_class") for event in request_events
    }
    if request_url_classes != {
        "data:cross-origin:<redacted>",
        "http:same-origin:/probe",
    }:
        raise ContractError(
            "native fetch request did not retain the expected scheme-safe URL class"
        )
    request_target_scopes = {
        (event.get("request") or {}).get("target_scope")
        for event in request_events
    }
    if request_target_scopes != {"loopback", "non-network"}:
        raise ContractError(
            "native fetch request did not retain the expected target-scope classes"
        )

    script_execution_events = [
        event
        for event in events
        if event["event"]
        == {"category": "execution", "name": "script.execution"}
    ]
    execution_completion_contexts: set[str] = set()
    for event in script_execution_events:
        if event.get("detail", {}).get("completion") != "complete":
            raise ContractError("native multicontext script execution was not complete")
        execution = event.get("execution") or {}
        if execution.get("frame_id") is not None:
            execution_completion_contexts.add("frame")
        if execution.get("worker_id") is not None:
            execution_completion_contexts.add("worker")
    if len(script_execution_events) < 3 or execution_completion_contexts != {
        "frame",
        "worker",
    }:
        raise ContractError(
            "native multicontext trace lacks frame/worker script completion coverage"
        )

    stream_results = [
        event
        for event in events
        if event["event"] == {"category": "stream", "name": "stream.read.result"}
    ]
    if len(stream_results) < 12:
        raise ContractError(
            "native multicontext trace has fewer than twelve stream results"
        )
    stream_mode_contexts = {"default": set(), "byob": set()}
    for result in stream_results:
        request_event = by_seq.get(result.get("causal_parent_seq"))
        if (
            request_event is None
            or request_event["event"]
            != {"category": "stream", "name": "stream.read.request"}
            or request_event.get("detail", {}).get("reader_mode")
            != result.get("detail", {}).get("reader_mode")
        ):
            raise ContractError("native stream result lacks its exact read parent")
        mode = result.get("detail", {}).get("reader_mode")
        if mode not in stream_mode_contexts:
            raise ContractError(f"native stream result has unsupported mode: {mode!r}")
        execution = result.get("execution") or {}
        if execution.get("frame_id") is not None:
            stream_mode_contexts[mode].add("frame")
        if execution.get("worker_id") is not None:
            stream_mode_contexts[mode].add("worker")
    for mode, classes in stream_mode_contexts.items():
        if classes != {"frame", "worker"}:
            raise ContractError(
                f"native multicontext trace lacks frame/worker {mode} stream coverage: "
                f"{sorted(classes)}"
            )
    default_byte_results = [
        event
        for event in stream_results
        if event.get("detail", {}).get("reader_mode") == "default"
        if (event.get("value") or {}).get("type") == "bytes"
        and (event.get("value") or {}).get("length") == 2
    ]
    default_closed_results = [
        event
        for event in stream_results
        if event.get("detail", {}).get("reader_mode") == "default"
        if event.get("detail", {}).get("result_kind") == "closed"
    ]
    byob_byte_results = [
        event
        for event in stream_results
        if event.get("detail", {}).get("reader_mode") == "byob"
        and event.get("detail", {}).get("result_kind") == "chunk"
        and (event.get("value") or {}).get("type") == "bytes"
        and (event.get("value") or {}).get("length") == 2
    ]
    byob_closed_results = [
        event
        for event in stream_results
        if event.get("detail", {}).get("reader_mode") == "byob"
        and event.get("detail", {}).get("result_kind") == "closed"
    ]
    if any(
        len(results) < 3
        for results in (
            default_byte_results,
            default_closed_results,
            byob_byte_results,
            byob_closed_results,
        )
    ):
        raise ContractError(
            "native stream results lack default/BYOB byte and close coverage"
        )

    body_requests = [
        event
        for event in events
        if event["event"] == {"category": "stream", "name": "body.consume"}
    ]
    if len(body_requests) < 18:
        raise ContractError(
            "native multicontext trace has fewer than eighteen body-consumer requests"
        )
    body_mode_contexts = {
        mode: {"frame": set(), "worker": set()}
        for mode in sorted(BODY_CONSUMER_MODES)
    }
    for request_event in body_requests:
        parent_event = by_seq.get(request_event.get("causal_parent_seq"))
        if parent_event is None or parent_event["event"] != {
            "category": "execution",
            "name": "script.run",
        }:
            raise ContractError(
                "native body-consumer request lacks an explicit script parent"
            )
        mode = request_event["detail"]["consumer_mode"]
        execution = request_event.get("execution") or {}
        frame_id = execution.get("frame_id")
        worker_id = execution.get("worker_id")
        if frame_id is not None:
            body_mode_contexts[mode]["frame"].add(frame_id)
        if worker_id is not None:
            body_mode_contexts[mode]["worker"].add(worker_id)
    for mode, contexts in body_mode_contexts.items():
        if len(contexts["frame"]) < 2 or not contexts["worker"]:
            raise ContractError(
                "native multicontext trace lacks two-frame/worker "
                f"{mode} body-consumer coverage"
            )

    message_posts = [
        event
        for event in events
        if event["event"]
        == {"category": "message", "name": "MessagePort.postMessage"}
    ]
    message_dispatches = [
        event
        for event in events
        if event["event"]
        == {"category": "message", "name": "MessagePort.message.dispatch"}
    ]
    if len(message_posts) < 5 or len(message_dispatches) < 5:
        raise ContractError(
            "native multicontext trace has fewer than five MessagePort send/dispatch pairs"
        )
    cross_context_dispatches = 0
    cross_process_dispatches = 0
    for dispatch_event in message_dispatches:
        post_event = by_seq.get(dispatch_event.get("causal_parent_seq"))
        if post_event is None or post_event["event"] != {
            "category": "message",
            "name": "MessagePort.postMessage",
        }:
            raise ContractError(
                "native MessagePort dispatch lacks an explicit post parent"
            )
        post_context = (post_event.get("execution") or {}).get("context_id")
        dispatch_context = (dispatch_event.get("execution") or {}).get("context_id")
        if post_context != dispatch_context:
            cross_context_dispatches += 1
        if post_event["process"] != dispatch_event["process"]:
            cross_process_dispatches += 1
    if cross_context_dispatches < 2 or cross_process_dispatches < 1:
        raise ContractError(
            "native MessagePort dispatch lacks cross-context/OOPIF causal coverage"
        )

    canvas_dimensions = {
        (event["detail"].get("width"), event["detail"].get("height"))
        for event in events
        if event["event"] == {"category": "api", "name": CANVAS_API}
        and event.get("provenance", {}).get("component") == "blink.canvas"
        and event.get("detail", {}).get("native_name") == "BrowserCore.CanvasReadback"
    }
    if not {(17, 19), (23, 29)}.issubset(canvas_dimensions):
        raise ContractError("native multicontext trace lacks both canvas fixtures")
    if summary["dropped_events"]:
        raise ContractError("native multicontext trace reported dropped events")
    observation_vector = _native_observation_vector_from_events(events)
    canonical = json.dumps(
        observation_vector,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    observation_events = len(observation_vector)
    observation_sha256 = hashlib.sha256(canonical).hexdigest()
    if observation_events != 74:
        raise ContractError(
            f"native multicontext observation vector has {observation_events} events instead of 74"
        )
    return {
        **summary,
        "frame_contexts": len(frame_contexts),
        "worker_contexts": len(worker_contexts),
        "frame_renderer_processes": len(frame_renderer_pids),
        "fetch_causal_chains": len(request_events),
        "fetch_url_classes": sorted(request_url_classes),
        "fetch_target_scopes": sorted(request_target_scopes),
        "script_execution_completions": len(script_execution_events),
        "script_execution_context_coverage": sorted(execution_completion_contexts),
        "stream_read_results": len(stream_results),
        "stream_default_byte_results": len(default_byte_results),
        "stream_default_closed_results": len(default_closed_results),
        "stream_byob_byte_results": len(byob_byte_results),
        "stream_byob_closed_results": len(byob_closed_results),
        "stream_mode_context_coverage": {
            mode: sorted(classes) for mode, classes in stream_mode_contexts.items()
        },
        "body_consumption_requests": len(body_requests),
        "body_consumer_modes": sorted(body_mode_contexts),
        "body_consumer_context_counts": {
            mode: {
                context_kind: len(context_ids)
                for context_kind, context_ids in contexts.items()
            }
            for mode, contexts in sorted(body_mode_contexts.items())
        },
        "message_port_posts": len(message_posts),
        "message_port_dispatches": len(message_dispatches),
        "message_port_cross_context_dispatches": cross_context_dispatches,
        "message_port_cross_process_dispatches": cross_process_dispatches,
        "observation_vector_events": observation_events,
        "observation_vector_sha256": observation_sha256,
        "canvas_dimensions": sorted([list(item) for item in canvas_dimensions]),
        "context_coverage": {
            label: sorted(classes)
            for label, classes in required_context_classes.items()
        },
    }


def run_native_canvas_smoke(
    config: NativeCanvasSmoke, repository_root: Path
) -> dict[str, Any]:
    _validate_smoke_config(
        config,
        repository_root,
        expected_type=NativeCanvasSmoke,
    )
    fixture = _fixture_bytes(
        repository_root / "fixtures" / "native-canvas-smoke.html",
        label="native canvas fixture",
    )
    session_path: Path | None = None
    session: dict[str, Any] | None = None
    stop_receipt: dict[str, Any] | None = None
    trace_source_binding: dict[str, Any] | None = None
    deadline = time.monotonic() + float(config.timeout_seconds)
    with _serve_fixtures({"/": (fixture, "text/html; charset=utf-8")}) as fixture_url:
        try:
            session_path, session = launch_evaluation(
                EvaluationLaunch(
                    executable=config.executable,
                    workspace=config.workspace,
                    headless=True,
                    timeout_seconds=_remaining_smoke_time(deadline),
                    extra_args=(fixture_url,),
                ),
                repository_root,
            )
            wait_for_page_target(
                session["automation"]["cdp_endpoint"],
                fixture_url,
                FIXTURE_TITLE,
                timeout_seconds=_remaining_smoke_time(deadline),
            )
        finally:
            if session_path is not None and session is not None:
                active_error = sys.exc_info()[1]
                try:
                    stop_receipt = _stop_native_smoke_session(
                        session_path,
                        session,
                    )
                    trace_source_binding = bind_perfetto_source_trace(
                        Path(session["trace_path"])
                    )
                except (ContractError, OSError, RuntimeError, ValueError) as exc:
                    cleanup_error = ContractError(
                        "native canvas smoke session cleanup failed"
                    )
                    if active_error is not None:
                        raise cleanup_error from active_error
                    raise cleanup_error from exc
    if session is None or session_path is None:
        raise ContractError("native canvas smoke session was not created")
    if stop_receipt is None:
        raise ContractError("native canvas smoke session stop was not verified")
    if trace_source_binding is None:
        raise ContractError("native canvas smoke trace source was not bound")
    _remaining_smoke_time(deadline)
    trace_path = Path(session["trace_path"])
    output_path = trace_path.with_suffix(".jsonl")
    exported = export_perfetto(
        config.trace_processor,
        trace_path,
        output_path,
        session["run_id"],
        session["chromium_revision"],
        output_path.with_suffix(".export.json"),
        maximum_events=MAX_SMOKE_TRACE_EVENTS,
        expected_source_binding=trace_source_binding,
    )
    assertion = assert_native_canvas_trace(output_path)
    return {
        "schema": "browser-core.smoke-result/1",
        "status": "passed",
        "session_file": str(session_path),
        "trace_file": str(trace_path),
        "normalized_trace_file": str(output_path),
        "export": exported,
        "assertion": assertion,
    }


def run_native_multicontext_smoke(
    config: NativeMultiContextSmoke, repository_root: Path
) -> dict[str, Any]:
    _validate_smoke_config(
        config,
        repository_root,
        expected_type=NativeMultiContextSmoke,
    )
    fixture_root = repository_root / "fixtures"
    routes = {
        "/": (
            _fixture_bytes(
                fixture_root / "native-multicontext-smoke.html",
                label="native multicontext main fixture",
            ),
            "text/html; charset=utf-8",
        ),
        "/frame.html": (
            _fixture_bytes(
                fixture_root / "native-multicontext-frame.html",
                label="native multicontext frame fixture",
            ),
            "text/html; charset=utf-8",
        ),
        "/worker.js": (
            _fixture_bytes(
                fixture_root / "native-multicontext-worker.js",
                label="native multicontext worker fixture",
            ),
            "text/javascript; charset=utf-8",
        ),
    }
    session_path: Path | None = None
    session: dict[str, Any] | None = None
    stop_receipt: dict[str, Any] | None = None
    trace_source_binding: dict[str, Any] | None = None
    deadline = time.monotonic() + float(config.timeout_seconds)
    with _serve_fixtures(routes) as fixture_url:
        try:
            session_path, session = launch_evaluation(
                EvaluationLaunch(
                    executable=config.executable,
                    workspace=config.workspace,
                    headless=True,
                    timeout_seconds=_remaining_smoke_time(deadline),
                    extra_args=(fixture_url,),
                ),
                repository_root,
            )
            wait_for_page_target(
                session["automation"]["cdp_endpoint"],
                fixture_url,
                MULTICONTEXT_FIXTURE_TITLE,
                timeout_seconds=_remaining_smoke_time(deadline),
            )
        finally:
            if session_path is not None and session is not None:
                active_error = sys.exc_info()[1]
                try:
                    stop_receipt = _stop_native_smoke_session(
                        session_path,
                        session,
                    )
                    trace_source_binding = bind_perfetto_source_trace(
                        Path(session["trace_path"])
                    )
                except (ContractError, OSError, RuntimeError, ValueError) as exc:
                    cleanup_error = ContractError(
                        "native multicontext smoke session cleanup failed"
                    )
                    if active_error is not None:
                        raise cleanup_error from active_error
                    raise cleanup_error from exc
    if session is None or session_path is None:
        raise ContractError("native multicontext smoke session was not created")
    if stop_receipt is None:
        raise ContractError("native multicontext smoke session stop was not verified")
    if trace_source_binding is None:
        raise ContractError("native multicontext smoke trace source was not bound")
    _remaining_smoke_time(deadline)
    trace_path = Path(session["trace_path"])
    output_path = trace_path.with_suffix(".jsonl")
    exported = export_perfetto(
        config.trace_processor,
        trace_path,
        output_path,
        session["run_id"],
        session["chromium_revision"],
        output_path.with_suffix(".export.json"),
        maximum_events=MAX_SMOKE_TRACE_EVENTS,
        expected_source_binding=trace_source_binding,
    )
    assertion = assert_native_multicontext_trace(output_path)
    return {
        "schema": "browser-core.smoke-result/1",
        "status": "passed",
        "fixture": "native-multicontext",
        "session_file": str(session_path),
        "trace_file": str(trace_path),
        "normalized_trace_file": str(output_path),
        "export": exported,
        "assertion": assertion,
    }
