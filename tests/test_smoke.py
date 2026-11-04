from __future__ import annotations

import json
import socket
import threading
import time
import urllib.request
from contextlib import contextmanager
from pathlib import Path
from urllib.parse import urlsplit

import pytest

from browser_core.contracts import ContractError
import browser_core.smoke as smoke_module
from browser_core.smoke import (
    NativeCanvasSmoke,
    NativeMultiContextSmoke,
    _fixture_handler,
    _serve_fixtures,
    assert_native_canvas_trace,
    assert_native_multicontext_trace,
    run_native_canvas_smoke,
    run_native_multicontext_smoke,
)


ROOT = Path(__file__).parents[1]


def _stopped_receipt(run_id: str = "smoke-run") -> dict[str, object]:
    return {
        "run_id": run_id,
        "state": "stopped",
        "running": False,
        "identity_protected": True,
        "shutdown_mode": "graceful",
    }


def _install_native_run_fakes(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    clock: list[float],
    *,
    stop_receipt: object | None = None,
) -> tuple[list[tuple[str, float]], list[Path], list[dict[str, object]]]:
    budgets: list[tuple[str, float]] = []
    exported_tools: list[Path] = []
    exported_source_bindings: list[dict[str, object]] = []
    source_binding = {"bytes": 123, "sha256": "b" * 64}

    @contextmanager
    def serve(_routes):  # noqa: ANN001
        yield "http://127.0.0.1:8123/"

    session = {
        "run_id": "smoke-run",
        "chromium_revision": "a" * 40,
        "trace_path": str(tmp_path / "trace.perfetto"),
        "automation": {"cdp_endpoint": "http://127.0.0.1:9222"},
    }

    def launch(config, _root):  # noqa: ANN001
        budgets.append(("launch", config.timeout_seconds))
        clock[0] += 2.0
        return tmp_path / "session.json", session

    def wait(*_args, timeout_seconds, **_kwargs):  # noqa: ANN002, ANN003
        budgets.append(("wait", timeout_seconds))
        clock[0] += 2.0

    def stop(_path, *, timeout_seconds):  # noqa: ANN001
        budgets.append(("stop", timeout_seconds))
        clock[0] += 1.0
        return _stopped_receipt() if stop_receipt is None else stop_receipt

    def export(tool: Path, *_args, **_kwargs):  # noqa: ANN002, ANN003
        exported_tools.append(tool)
        exported_source_bindings.append(_kwargs["expected_source_binding"])
        return {"events": 1}

    monkeypatch.setattr(smoke_module, "_fixture_bytes", lambda *_a, **_k: b"fixture")
    monkeypatch.setattr(smoke_module, "_serve_fixtures", serve)
    monkeypatch.setattr(smoke_module, "launch_evaluation", launch)
    monkeypatch.setattr(smoke_module, "wait_for_page_target", wait)
    monkeypatch.setattr(smoke_module, "stop_session", stop)
    monkeypatch.setattr(
        smoke_module,
        "bind_perfetto_source_trace",
        lambda *_args: source_binding,
    )
    monkeypatch.setattr(smoke_module, "export_perfetto", export)
    monkeypatch.setattr(
        smoke_module,
        "assert_native_canvas_trace",
        lambda *_a, **_k: {"canvas": True},
    )
    monkeypatch.setattr(
        smoke_module,
        "assert_native_multicontext_trace",
        lambda *_a, **_k: {"multicontext": True},
    )
    monkeypatch.setattr(smoke_module.time, "monotonic", lambda: clock[0])
    return budgets, exported_tools, exported_source_bindings


def test_fixture_server_retains_one_immutable_route_population() -> None:
    routes = {"/": (b"first-generation", "text/plain")}

    with _serve_fixtures(routes) as url:
        routes["/"] = (b"second-generation", "text/plain")
        with urllib.request.urlopen(url, timeout=5) as response:
            assert response.read() == b"first-generation"


def test_fixture_handler_rejects_aggregate_overflow_before_server_contact(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(smoke_module, "MAX_SMOKE_FIXTURE_TOTAL_BYTES", 1)

    with pytest.raises(ContractError, match="routes are invalid"):
        _fixture_handler({"/": (b"xx", "text/plain")})


@pytest.mark.parametrize(
    'route',
    [
        {'/': (b'fixture', 'text/plain\r\nX-Injected: yes')},
        {'/bad\npath': (b'fixture', 'text/plain')},
        {'/unreachable#fragment': (b'fixture', 'text/plain')},
        {'/' + 'x' * 2049: (b'fixture', 'text/plain')},
    ],
)
def test_fixture_handler_rejects_unsafe_route_and_header_text(route):
    with pytest.raises(ContractError, match='routes are invalid'):
        _fixture_handler(route)


@pytest.mark.parametrize("failure_phase", ["construct", "start"])
def test_fixture_server_start_failure_closes_without_shutdown(
    monkeypatch: pytest.MonkeyPatch,
    failure_phase: str,
) -> None:
    class Server:
        server_port = 8123

        def __init__(self, _address, _handler):  # noqa: ANN001
            self.closed = False
            self.shutdown_called = False

        def serve_forever(self) -> None:
            return

        def shutdown(self) -> None:
            self.shutdown_called = True

        def server_close(self) -> None:
            self.closed = True

    class Worker:
        def start(self) -> None:
            raise OSError("private start path")

    server = Server(None, None)
    monkeypatch.setattr(
        smoke_module,
        "LocalPanelServer",
        lambda *_args, **_kwargs: server,
    )

    def thread_factory(**_kwargs):  # noqa: ANN003
        if failure_phase == "construct":
            raise RuntimeError("private constructor path")
        return Worker()

    monkeypatch.setattr(smoke_module, "Thread", thread_factory)

    with pytest.raises(ContractError, match="server could not start") as raised:
        with _serve_fixtures({"/": (b"fixture", "text/plain")}):
            pytest.fail("failed fixture server reached body")

    assert "private" not in str(raised.value)
    assert server.closed is True
    assert server.shutdown_called is False


def test_fixture_server_retains_worker_after_late_start_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Server:
        server_port = 8123

        def serve_forever(self) -> None:
            return

    class Worker:
        alive = False

        def start(self) -> None:
            self.alive = True
            raise RuntimeError("late start failure")

        def is_alive(self) -> bool:
            return self.alive

    started: list[bool] = []
    monkeypatch.setattr(smoke_module, "LocalPanelServer", lambda *_args: Server())
    monkeypatch.setattr(smoke_module, "Thread", lambda **_kwargs: Worker())
    monkeypatch.setattr(
        smoke_module,
        "_stop_fixture_server",
        lambda *_args, **kwargs: started.append(kwargs["thread_started"]) or [],
    )
    with pytest.raises(ContractError, match="server could not start"):
        with _serve_fixtures({"/": (b"fixture", "text/plain")}):
            pytest.fail("failed fixture server reached body")
    assert started == [True]


def test_fixture_server_closes_active_keepalive_on_exit() -> None:
    client = None
    try:
        with _serve_fixtures({"/": (b"fixture", "text/plain")}) as url:
            port = urlsplit(url).port
            assert port is not None
            client = socket.create_connection(("127.0.0.1", port), timeout=1)
            client.settimeout(1)
            client.sendall(b"GET /probe HTTP/1.1\r\nHost: localhost\r\n\r\n")
            response = bytearray()
            while not response.endswith(b"\r\n\r\nok"):
                response.extend(client.recv(4096))
            assert response.startswith(b"HTTP/1.1 200")
        try:
            closed = client.recv(1)
        except TimeoutError:
            pytest.fail("native smoke fixture left a keep-alive client open")
        except OSError:
            pass
        else:
            assert closed == b""
    finally:
        if client is not None:
            client.close()


def test_fixture_server_cleanup_attempts_every_phase_after_failures() -> None:
    class Server:
        def shutdown(self) -> None:
            raise RuntimeError("private shutdown")

        def server_close(self) -> None:
            raise OSError("private close")

    class Worker:
        def is_alive(self) -> bool:
            return True

        def join(self, *, timeout: float) -> None:
            assert timeout == smoke_module.SMOKE_SERVER_CLEANUP_TIMEOUT_SECONDS
            raise RuntimeError("private join")

    failures = smoke_module._stop_fixture_server(
        Server(),
        Worker(),
        thread_started=True,
    )

    assert failures == ["server-shutdown", "server-close", "worker-thread"]


def test_fixture_server_shutdown_is_bounded_and_still_closes_and_joins(
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
    monkeypatch.setattr(
        smoke_module,
        "SMOKE_SERVER_CLEANUP_TIMEOUT_SECONDS",
        0.01,
    )
    started = time.monotonic()

    failures = smoke_module._stop_fixture_server(
        server,
        worker,
        thread_started=True,
    )

    assert time.monotonic() - started < 0.5
    assert failures == ["server-shutdown"]
    assert server.closed is True
    assert worker.joined is True


def test_fixture_server_reclaims_shutdown_thread_after_late_start_error(
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

    monkeypatch.setattr(smoke_module, "Thread", ShutdownThread)
    monkeypatch.setattr(smoke_module, "SMOKE_SERVER_CLEANUP_TIMEOUT_SECONDS", 0.1)
    server = Server()
    worker = Worker()
    failures = smoke_module._stop_fixture_server(server, worker, thread_started=True)

    assert failures == ["server-shutdown"]
    assert server.closed is True
    assert worker.joined is True
    assert threads[0].joined is True
    assert threads[0].is_alive() is False


def test_fixture_server_cleanup_failure_retains_body_failure_only_as_cause(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Server:
        server_port = 8123

        def serve_forever(self) -> None:
            return

    class Worker:
        def start(self) -> None:
            return

        def is_alive(self) -> bool:
            return True

    monkeypatch.setattr(
        smoke_module,
        "LocalPanelServer",
        lambda *_args, **_kwargs: Server(),
    )
    monkeypatch.setattr(smoke_module, "Thread", lambda **_kwargs: Worker())
    monkeypatch.setattr(
        smoke_module,
        "_stop_fixture_server",
        lambda *_args, **_kwargs: ["server-close", "worker-thread"],
    )

    with pytest.raises(
        ContractError,
        match=r"cleanup failed \(server-close,worker-thread\)",
    ) as raised:
        with _serve_fixtures({"/": (b"fixture", "text/plain")}):
            raise RuntimeError("private fixture body")

    assert isinstance(raised.value.__cause__, RuntimeError)
    assert "private fixture body" not in str(raised.value)


@pytest.mark.parametrize(
    "timeout", [0, True, float("nan"), float("inf"), 301, 10**400]
)
def test_native_smoke_rejects_invalid_timeout_before_fixture_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    timeout,
) -> None:
    contacted = False

    def fixture_contact(*_args: object, **_kwargs: object) -> bytes:
        nonlocal contacted
        contacted = True
        raise AssertionError("invalid config reached fixture read")

    monkeypatch.setattr(smoke_module, "_fixture_bytes", fixture_contact)
    config = NativeCanvasSmoke(
        executable=tmp_path / "browser",
        trace_processor=tmp_path / "processor",
        workspace=tmp_path / "workspace",
        timeout_seconds=timeout,
    )

    with pytest.raises(ContractError, match="timeout"):
        run_native_canvas_smoke(config, ROOT)

    assert contacted is False


@pytest.mark.parametrize(
    ("runner", "config_type", "assertion_key"),
    [
        (run_native_canvas_smoke, NativeCanvasSmoke, "canvas"),
        (run_native_multicontext_smoke, NativeMultiContextSmoke, "multicontext"),
    ],
)
def test_native_smoke_shares_deadline_verifies_stop_and_keeps_tool_binding(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    runner,
    config_type,
    assertion_key: str,
) -> None:
    clock = [0.0]
    budgets, exported_tools, exported_source_bindings = _install_native_run_fakes(
        monkeypatch,
        tmp_path,
        clock,
    )
    (tmp_path / "binding").mkdir()
    tool = tmp_path / "binding" / ".." / "trace_processor"
    config = config_type(
        executable=tmp_path / "chrome",
        trace_processor=tool,
        workspace=tmp_path / "workspace",
        timeout_seconds=6,
    )

    result = runner(config, ROOT)

    assert budgets == [("launch", 6.0), ("wait", 4.0), ("stop", 15.0)]
    assert exported_tools == [tool]
    assert exported_source_bindings == [{"bytes": 123, "sha256": "b" * 64}]
    assert result["assertion"][assertion_key] is True


def test_native_smoke_cleanup_cannot_refresh_expired_primary_deadline(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    clock = [0.0]
    budgets, exported_tools, exported_source_bindings = _install_native_run_fakes(
        monkeypatch,
        tmp_path,
        clock,
    )
    config = NativeCanvasSmoke(
        executable=tmp_path / "chrome",
        trace_processor=tmp_path / "trace_processor",
        workspace=tmp_path / "workspace",
        timeout_seconds=4,
    )

    with pytest.raises(ContractError, match="native smoke timed out"):
        run_native_canvas_smoke(config, ROOT)

    assert budgets == [("launch", 4.0), ("wait", 2.0), ("stop", 15.0)]
    assert exported_tools == []
    assert exported_source_bindings == []


def test_native_smoke_unverified_stop_blocks_trace_export(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    clock = [0.0]
    budgets, exported_tools, exported_source_bindings = _install_native_run_fakes(
        monkeypatch,
        tmp_path,
        clock,
        stop_receipt={**_stopped_receipt(), "state": "active", "running": True},
    )
    config = NativeCanvasSmoke(
        executable=tmp_path / "chrome",
        trace_processor=tmp_path / "trace_processor",
        workspace=tmp_path / "workspace",
        timeout_seconds=6,
    )

    with pytest.raises(ContractError, match="session cleanup failed"):
        run_native_canvas_smoke(config, ROOT)

    assert budgets[-1] == ("stop", 15.0)
    assert exported_tools == []
    assert exported_source_bindings == []


def test_native_smoke_stop_receipt_is_exact_bound_and_detached() -> None:
    source = _stopped_receipt()
    retained = smoke_module._validated_smoke_stop_receipt(
        source,
        expected_run_id="smoke-run",
    )
    source["state"] = "active"

    assert retained == _stopped_receipt()


@pytest.mark.parametrize(
    "receipt",
    [
        None,
        [],
        {**_stopped_receipt(), "run_id": "other"},
        {**_stopped_receipt(), "state": "active"},
        {**_stopped_receipt(), "running": 0},
        {**_stopped_receipt(), "identity_protected": 1},
        {**_stopped_receipt(), "shutdown_mode": "private"},
        {**_stopped_receipt(), "extra": True},
    ],
)
def test_native_smoke_stop_receipt_rejects_unverified_shapes(receipt) -> None:
    with pytest.raises(ContractError, match="stop was not verified"):
        smoke_module._validated_smoke_stop_receipt(
            receipt,
            expected_run_id="smoke-run",
        )


def event(**detail_overrides: object) -> dict[str, object]:
    detail = {
        "native_name": "BrowserCore.CanvasReadback",
        "thread_id": 43,
        "width": 17,
        "height": 19,
        "origin_clean": True,
    }
    detail.update(detail_overrides)
    return {
        "schema": "browser-core.trace-event/1",
        "run_id": "fixture-run",
        "seq": 0,
        "ts_monotonic_ns": 1234,
        "process": {"pid": 42, "type": "renderer"},
        "event": {"category": "api", "name": "HTMLCanvasElement.toDataURL"},
        "provenance": {
            "source": "native",
            "component": "blink.canvas",
            "chromium_revision": "a" * 40,
        },
        "detail": detail,
    }


def write_trace(path: Path, document: dict[str, object]) -> None:
    path.write_text(json.dumps(document) + "\n", encoding="utf-8")


def write_events(path: Path, documents: list[dict[str, object]]) -> None:
    path.write_text(
        "".join(json.dumps(item) + "\n" for item in documents), encoding="utf-8"
    )


def native_event(
    seq: int,
    category: str,
    name: str,
    *,
    pid: int = 42,
    context_id: str | None = None,
    context_kind: str | None = None,
    script_id: str | None = None,
    parent: int | None = None,
    request: dict[str, object] | None = None,
    value: dict[str, object] | None = None,
    detail: dict[str, object] | None = None,
    component: str | None = None,
) -> dict[str, object]:
    document: dict[str, object] = {
        "schema": "browser-core.trace-event/1",
        "run_id": "multicontext",
        "seq": seq,
        "ts_monotonic_ns": seq,
        "process": {"pid": pid, "type": "renderer"},
        "event": {"category": category, "name": name},
        "provenance": {"source": "native"},
        "detail": detail or {"native_name": f"fixture.{name}", "thread_id": pid},
    }
    if component is None:
        component = {
            "api": "blink.fetch",
            "crypto": "blink.webcrypto",
            "execution": "blink.v8",
            "message": "blink.messaging",
            "network": "blink.fetch",
            "stream": "blink.streams",
            "wasm": "v8.wasm",
        }.get(category)
    if component is not None:
        document["provenance"]["component"] = component
    if context_id is not None:
        execution: dict[str, object] = {"context_id": context_id}
        if context_kind == "frame":
            execution["frame_id"] = context_id
        elif context_kind == "worker":
            execution["worker_id"] = context_id
        if script_id is not None:
            execution["script_id"] = script_id
        document["execution"] = execution
    if parent is not None:
        document["causal_parent_seq"] = parent
    if request is not None:
        document["request"] = request
    if value is not None:
        document["value"] = value
    return document


def multicontext_events(oopif_pid: int = 43) -> list[dict[str, object]]:
    contexts = [
        ("frame-main", "frame", 42, "v8:42:frame-main:7"),
        (
            "frame-oopif",
            "frame",
            oopif_pid,
            f"v8:{oopif_pid}:frame-oopif:8",
        ),
        ("worker", "worker", 42, "v8:42:worker:9"),
    ]
    events: list[dict[str, object]] = []
    for seq, (context_id, kind, pid, script_id) in enumerate(contexts):
        events.append(
            native_event(
                seq,
                "execution",
                "script.run",
                pid=pid,
                context_id=context_id,
                context_kind=kind,
                script_id=script_id,
                detail={
                    "native_name": "BrowserCore.ScriptRun",
                    "thread_id": pid,
                },
            )
        )
    seq = len(events)
    message_post_sequences: dict[str, list[int]] = {
        context_id: [] for context_id, *_rest in contexts
    }
    for context_id, kind, pid, script_id in contexts:
        events.append(
            native_event(
                seq,
                "execution",
                "script.execution",
                pid=pid,
                context_id=context_id,
                context_kind=kind,
                script_id=script_id,
                detail={
                    "native_name": "BrowserCore.ScriptExecution",
                    "thread_id": pid,
                    "completion": "complete",
                    "duration_ns": 1_000,
                },
            )
        )
        seq += 1
    for category, name in (
        ("message", "MessagePort.postMessage"),
        ("crypto", "SubtleCrypto.digest"),
        ("wasm", "WebAssembly.compile.completed"),
    ):
        for script_seq, (context_id, kind, pid, script_id) in enumerate(contexts):
            if category == "message":
                message_post_sequences[context_id].append(seq)
            events.append(
                native_event(
                    seq,
                    category,
                    name,
                    pid=pid,
                    context_id=context_id,
                    context_kind=kind,
                    script_id=None if category == "wasm" else script_id,
                    parent=script_seq if category != "wasm" else None,
                    detail={
                        "native_name": "BrowserCore.MessagePost",
                        "thread_id": pid,
                    }
                    if category == "message"
                    else {
                        "native_name": "BrowserCore.CryptoDigest",
                        "thread_id": pid,
                        "algorithm": "SHA-256",
                        "data_bytes": 32,
                    }
                    if category == "crypto"
                    else {
                        "native_name": "BrowserCore.WasmCompiled",
                        "thread_id": pid,
                        "success": True,
                        "async": True,
                        "cached": False,
                        "code_bytes": 8,
                    },
                    value={"type": "bytes", "length": 32, "redaction": "metadata"}
                    if category == "crypto"
                    else None,
                )
            )
            seq += 1
    for script_seq, context_index in ((1, 1), (2, 2)):
        context_id, kind, pid, script_id = contexts[context_index]
        message_post_sequences[context_id].append(seq)
        events.append(
            native_event(
                seq,
                "message",
                "MessagePort.postMessage",
                pid=pid,
                context_id=context_id,
                context_kind=kind,
                script_id=script_id,
                parent=script_seq,
                detail={
                    "native_name": "BrowserCore.MessagePost",
                    "thread_id": pid,
                },
            )
        )
        seq += 1
    for context_id, kind, pid, _script_id in contexts:
        events.append(
            native_event(
                seq,
                "message",
                "MessagePort.message.dispatch",
                pid=pid,
                context_id=context_id,
                context_kind=kind,
                parent=message_post_sequences[context_id][0],
                detail={
                    "native_name": "BrowserCore.MessageDispatch",
                    "thread_id": pid,
                    "dispatch_kind": "message",
                },
            )
        )
        seq += 1
    main_context_id, main_kind, main_pid, _main_script_id = contexts[0]
    for sender_context in ("frame-oopif", "worker"):
        events.append(
            native_event(
                seq,
                "message",
                "MessagePort.message.dispatch",
                pid=main_pid,
                context_id=main_context_id,
                context_kind=main_kind,
                parent=message_post_sequences[sender_context][1],
                detail={
                    "native_name": "BrowserCore.MessageDispatch",
                    "thread_id": main_pid,
                    "dispatch_kind": "message",
                },
            )
        )
        seq += 1
    for script_seq, (context_id, kind, pid, script_id) in enumerate(contexts):
        api_seq = seq
        events.append(
            native_event(
                seq,
                "api",
                "fetch",
                pid=pid,
                context_id=context_id,
                context_kind=kind,
                script_id=script_id,
                parent=script_seq,
                detail={
                    "native_name": "BrowserCore.FetchCall",
                    "thread_id": pid,
                },
            )
        )
        seq += 1
        events.append(
            native_event(
                seq,
                "network",
                "fetch.request.start",
                pid=pid,
                context_id=context_id,
                context_kind=kind,
                script_id=script_id,
                parent=api_seq,
                detail={
                    "native_name": "BrowserCore.FetchRequestStart",
                    "thread_id": pid,
                },
                request={
                    "id": f"fetch-request:{context_id}:1",
                    "method": "GET",
                    "url_class": "http:same-origin:/probe",
                    "target_scope": "loopback",
                    "body_bytes": 0,
                },
            )
        )
        seq += 1
    context_id, kind, pid, script_id = contexts[0]
    api_seq = seq
    events.append(
        native_event(
            seq,
            "api",
            "fetch",
            pid=pid,
            context_id=context_id,
            context_kind=kind,
            script_id=script_id,
            parent=0,
            detail={
                "native_name": "BrowserCore.FetchCall",
                "thread_id": pid,
            },
        )
    )
    seq += 1
    events.append(
        native_event(
            seq,
            "network",
            "fetch.request.start",
            pid=pid,
            context_id=context_id,
            context_kind=kind,
            script_id=script_id,
            parent=api_seq,
            detail={
                "native_name": "BrowserCore.FetchRequestStart",
                "thread_id": pid,
            },
            request={
                "id": "fetch-request:frame-main:2",
                "method": "GET",
                "url_class": "data:cross-origin:<redacted>",
                "target_scope": "non-network",
                "body_bytes": 0,
            },
        )
    )
    seq += 1
    for script_seq, (context_id, kind, pid, script_id) in enumerate(contexts):
        for reader_mode in ("default", "byob"):
            chunk_request_seq = seq
            events.append(
                native_event(
                    seq,
                    "stream",
                    "stream.read.request",
                    pid=pid,
                    context_id=context_id,
                    context_kind=kind,
                    script_id=script_id,
                    parent=script_seq,
                    detail={
                        "native_name": "BrowserCore.StreamReadRequest",
                        "thread_id": pid,
                        "reader_mode": reader_mode,
                    },
                )
            )
            seq += 1
            events.append(
                native_event(
                    seq,
                    "stream",
                    "stream.read.result",
                    pid=pid,
                    context_id=context_id,
                    context_kind=kind,
                    parent=chunk_request_seq,
                    value={"type": "bytes", "length": 2, "redaction": "metadata"},
                    detail={
                        "native_name": "BrowserCore.StreamReadResult",
                        "thread_id": pid,
                        "reader_mode": reader_mode,
                        "result_kind": "chunk",
                        "chunk_value_type": "bytes",
                        "chunk_bytes": 2,
                    },
                )
            )
            seq += 1
            close_request_seq = seq
            events.append(
                native_event(
                    seq,
                    "stream",
                    "stream.read.request",
                    pid=pid,
                    context_id=context_id,
                    context_kind=kind,
                    script_id=script_id,
                    parent=script_seq,
                    detail={
                        "native_name": "BrowserCore.StreamReadRequest",
                        "thread_id": pid,
                        "reader_mode": reader_mode,
                    },
                )
            )
            seq += 1
            close_value = (
                {"type": "bytes", "length": 0, "redaction": "metadata"}
                if reader_mode == "byob"
                else None
            )
            events.append(
                native_event(
                    seq,
                    "stream",
                    "stream.read.result",
                    pid=pid,
                    context_id=context_id,
                    context_kind=kind,
                    parent=close_request_seq,
                    value=close_value,
                    detail={
                        "native_name": "BrowserCore.StreamReadResult",
                        "thread_id": pid,
                        "reader_mode": reader_mode,
                        "result_kind": "closed",
                        "chunk_value_type": "bytes"
                        if reader_mode == "byob"
                        else "none",
                        "chunk_bytes": 0,
                    },
                )
            )
            seq += 1
    for script_seq, (context_id, kind, pid, script_id) in enumerate(contexts):
        for consumer_mode in (
            "array-buffer",
            "blob",
            "bytes",
            "form-data",
            "json",
            "text",
        ):
            events.append(
                native_event(
                    seq,
                    "stream",
                    "body.consume",
                    pid=pid,
                    context_id=context_id,
                    context_kind=kind,
                    script_id=script_id,
                    parent=script_seq,
                    component="blink.fetch-body",
                    detail={
                        "native_name": "BrowserCore.BodyConsume",
                        "thread_id": pid,
                        "consumer_mode": consumer_mode,
                    },
                )
            )
            seq += 1
    for width, height in ((17, 19), (23, 29)):
        events.append(
            native_event(
                seq,
                "api",
                "HTMLCanvasElement.toDataURL",
                detail={
                    "native_name": "BrowserCore.CanvasReadback",
                    "thread_id": 42,
                    "width": width,
                    "height": height,
                    "origin_clean": True,
                },
                component="blink.canvas",
            )
        )
        seq += 1
    generated_canvas = native_event(
        seq,
        "api",
        "HTMLCanvasElement.toDataURL",
        context_id="bindings:42:42",
        context_kind="frame",
        detail={
            "native_name": "HTMLCanvasElement.toDataURL",
            "thread_id": 42,
            "completion": "complete",
            "duration_ns": 1,
        },
        component="blink.bindings.generated",
    )
    generated_canvas["provenance"]["trace_category"] = "blink.bindings"
    events.append(generated_canvas)
    return events


def test_native_canvas_smoke_assertion_accepts_exact_event(tmp_path: Path) -> None:
    trace = tmp_path / "trace.jsonl"
    write_trace(trace, event())
    result = assert_native_canvas_trace(trace)
    assert result["events"] == 1
    assert result["matching_canvas_events"] == 1


def test_native_canvas_smoke_assertion_rejects_wrong_dimensions(tmp_path: Path) -> None:
    trace = tmp_path / "trace.jsonl"
    write_trace(trace, event(width=18))
    with pytest.raises(ContractError, match="no matching native canvas"):
        assert_native_canvas_trace(trace)


def test_native_multicontext_smoke_accepts_oopif_worker_and_causal_fetches(
    tmp_path: Path,
) -> None:
    trace = tmp_path / "trace.jsonl"
    write_events(trace, multicontext_events())

    result = assert_native_multicontext_trace(trace)

    assert result["frame_contexts"] == 2
    assert result["worker_contexts"] == 1
    assert result["frame_renderer_processes"] == 2
    assert result["fetch_causal_chains"] == 4
    assert result["fetch_url_classes"] == [
        "data:cross-origin:<redacted>",
        "http:same-origin:/probe",
    ]
    assert result["fetch_target_scopes"] == ["loopback", "non-network"]
    assert result["script_execution_completions"] == 3
    assert result["script_execution_context_coverage"] == ["frame", "worker"]
    assert result["stream_default_byte_results"] == 3
    assert result["stream_default_closed_results"] == 3
    assert result["stream_byob_byte_results"] == 3
    assert result["stream_byob_closed_results"] == 3
    assert result["stream_mode_context_coverage"] == {
        "default": ["frame", "worker"],
        "byob": ["frame", "worker"],
    }
    assert result["body_consumption_requests"] == 18
    assert result["body_consumer_modes"] == [
        "array-buffer",
        "blob",
        "bytes",
        "form-data",
        "json",
        "text",
    ]
    assert result["body_consumer_context_counts"] == {
        mode: {"frame": 2, "worker": 1}
        for mode in result["body_consumer_modes"]
    }
    assert result["message_port_posts"] == 5
    assert result["message_port_dispatches"] == 5
    assert result["message_port_cross_context_dispatches"] == 2
    assert result["message_port_cross_process_dispatches"] == 1
    assert result["observation_vector_events"] == 74
    assert len(result["observation_vector_sha256"]) == 64


def test_native_multicontext_assertion_uses_one_validated_trace_population(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import browser_core.trace as trace_module

    trace = tmp_path / "trace.jsonl"
    write_events(trace, multicontext_events())
    real_open = trace_module.os.open
    opens = 0

    def recording_open(path: Path, *args, **kwargs):
        nonlocal opens
        if Path(path) == trace:
            opens += 1
        return real_open(path, *args, **kwargs)

    monkeypatch.setattr(trace_module.os, "open", recording_open)

    assert_native_multicontext_trace(trace)

    assert opens == 1


def test_native_smoke_assertion_applies_its_event_ceiling(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    trace = tmp_path / "trace.jsonl"
    first = event()
    second = event()
    second["seq"] = 1
    second["ts_monotonic_ns"] = 1235
    write_events(trace, [first, second])
    monkeypatch.setattr(smoke_module, "MAX_SMOKE_TRACE_EVENTS", 1)

    with pytest.raises(ContractError, match="population exceeds"):
        assert_native_canvas_trace(trace)


def test_native_multicontext_smoke_rejects_same_process_frames(tmp_path: Path) -> None:
    trace = tmp_path / "trace.jsonl"
    events = multicontext_events(oopif_pid=42)
    generated_binding = native_event(
        len(events),
        "api",
        "Document.querySelector",
        pid=99,
        context_id="bindings:99:99",
        context_kind="frame",
        component="blink.bindings.generated",
        detail={
            "native_name": "Document.querySelector",
            "thread_id": 99,
            "completion": "complete",
            "duration_ns": 1,
        },
    )
    generated_binding["provenance"]["trace_category"] = "blink.bindings"
    events.append(generated_binding)
    write_events(trace, events)

    with pytest.raises(ContractError, match="OOPIF"):
        assert_native_multicontext_trace(trace)


def test_native_multicontext_smoke_rejects_missing_byob_coverage(
    tmp_path: Path,
) -> None:
    events = [
        event
        for event in multicontext_events()
        if event.get("detail", {}).get("reader_mode") != "byob"
    ]
    trace = tmp_path / "trace.jsonl"
    write_events(trace, events)

    with pytest.raises(ContractError, match="twelve stream results"):
        assert_native_multicontext_trace(trace)


def test_native_multicontext_smoke_requires_all_body_consumer_modes(
    tmp_path: Path,
) -> None:
    trace = tmp_path / "trace.jsonl"
    events = [
        event
        for event in multicontext_events()
        if event["event"] != {"category": "stream", "name": "body.consume"}
    ]
    write_events(trace, events)

    with pytest.raises(ContractError, match="body-consumer requests"):
        assert_native_multicontext_trace(trace)


def test_native_multicontext_smoke_requires_each_body_mode_in_both_frames_and_worker(
    tmp_path: Path,
) -> None:
    events = multicontext_events()
    for event in events:
        if (
            event["event"] == {"category": "stream", "name": "body.consume"}
            and event.get("execution", {}).get("worker_id") == "worker"
            and event["detail"]["consumer_mode"] == "text"
        ):
            event["detail"]["consumer_mode"] = "json"
            break
    trace = tmp_path / "trace.jsonl"
    write_events(trace, events)

    with pytest.raises(ContractError, match="text body-consumer coverage"):
        assert_native_multicontext_trace(trace)


def test_native_multicontext_fixtures_exercise_each_body_consumer() -> None:
    fixture_paths = (
        ROOT / "fixtures" / "native-multicontext-smoke.html",
        ROOT / "fixtures" / "native-multicontext-frame.html",
        ROOT / "fixtures" / "native-multicontext-worker.js",
    )
    method_calls = (".arrayBuffer()", ".blob()", ".bytes()", ".formData()", ".json()", ".text()")

    for fixture_path in fixture_paths:
        fixture = fixture_path.read_text(encoding="utf-8")
        assert fixture.count("await exerciseBodyConsumers()") == 1
        assert all(fixture.count(method_call) == 1 for method_call in method_calls)


def test_native_multicontext_smoke_requires_cross_context_message_dispatch(
    tmp_path: Path,
) -> None:
    events = [
        event
        for event in multicontext_events()
        if event["event"]
        != {"category": "message", "name": "MessagePort.message.dispatch"}
    ]
    trace = tmp_path / "trace.jsonl"
    write_events(trace, events)

    with pytest.raises(ContractError, match="message_delivery coverage"):
        assert_native_multicontext_trace(trace)
