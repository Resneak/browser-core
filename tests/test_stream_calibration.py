from __future__ import annotations

import copy
import hashlib
import io
import json
import os
import socket
import threading
from dataclasses import replace
from email.message import Message
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace

import pytest

import browser_core.stream_calibration as stream_calibration
from browser_core.contracts import ContractError
from browser_core.local_http import MAX_HTTP_HEADER_BYTES
from browser_core.stream_calibration import (
    RESULT_SCHEMA,
    StreamCalibrationTrial,
    _native_stream_summary,
    run_stream_calibration_trial,
    summarize_stream_scope_cohort,
    summarize_stream_scope_runs,
    summarize_stream_trace_mode_runs,
    validate_stream_calibration_trial_config,
    validate_stream_cohort_controls,
    validate_stream_calibration_result,
    validate_stream_scope_report,
    validate_stream_scope_cohort_report,
    validate_stream_trace_mode_cohort_report,
)


ROOT = Path(__file__).parents[1]


def test_stream_trial_preflight_is_pure_and_rejects_invalid_controls(
    tmp_path: Path,
) -> None:
    config = StreamCalibrationTrial(
        executable=tmp_path / "missing-browser",
        trace_processor=tmp_path / "missing-processor",
        workspace=tmp_path / "workspace",
        trace_mode="on",
        reads=0,
    )

    with pytest.raises(ContractError, match="read bounds"):
        validate_stream_calibration_trial_config(config, ROOT)

    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("field", ["trace_mode", "trace_scope"])
def test_stream_trial_preflight_rejects_unhashable_trace_choice(tmp_path: Path, field: str) -> None:
    config = StreamCalibrationTrial(
        executable=tmp_path / "missing-browser",
        trace_processor=tmp_path / "missing-processor",
        workspace=tmp_path / "workspace",
        trace_mode="on",
    )
    config = replace(config, **{field: ["on"]})
    with pytest.raises(ContractError, match="trace (mode|scope)"):
        validate_stream_calibration_trial_config(config, ROOT)
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize(
    ("trials", "overhead", "trace_bytes"),
    [
        (1, 10.0, 1024),
        (129, 10.0, 1024),
        (2, float("nan"), 1024),
        (2, 10**400, 1024),
        (2, 10.0, 0),
        (True, 10.0, 1024),
    ],
)
def test_stream_cohort_preflight_rejects_invalid_controls(
    trials,
    overhead,
    trace_bytes,
) -> None:
    with pytest.raises(ContractError, match="cohort"):
        validate_stream_cohort_controls(
            trials_per_arm=trials,
            maximum_overhead_percent=overhead,
            max_trace_bytes=trace_bytes,
        )


def fixture_result(reads: int = 4, warmup: int = 2) -> dict:
    return {
        "schema": RESULT_SCHEMA,
        "verdict": "pass",
        "reads": reads,
        "warmup_reads": warmup,
        "descriptors": {
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
        },
        "default": {
            "chunks": reads,
            "bytes": reads * 32,
            "closed": True,
            "close_value_undefined": True,
            "lock_released": True,
            "duration_ms": 4.0,
        },
        "byob": {
            "chunks": reads,
            "bytes": reads * 32,
            "closed": True,
            "close_value_type": "[object Uint8Array]",
            "close_value_length": 0,
            "lock_released": True,
            "duration_ms": 6.0,
        },
    }


def _install_trial_fakes(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    clock: list[float],
    *,
    stop_state: str = "stopped",
    stop_run_id: str = "stream-run",
    trace_path: Path | None = None,
    trace_scope: str | None = None,
) -> tuple[list[tuple[str, float]], dict[str, object]]:
    budgets: list[tuple[str, float]] = []
    holder: dict[str, object] = {}

    class Store:
        def __init__(self, reads: int, warmup_reads: int) -> None:
            self.reads = reads
            self.warmup_reads = warmup_reads

        def get(self):
            return fixture_result(self.reads, self.warmup_reads)

        def get_error(self):
            return None

    class Server:
        server_port = 8123

        def __init__(self, _address, _handler):  # noqa: ANN001
            holder["server"] = self
            self.closed = False
            self.shutdown_called = False

        def serve_forever(self):
            return

        def shutdown(self):
            self.shutdown_called = True

        def server_close(self):
            self.closed = True

    session = {
        "automation": {"cdp_endpoint": "http://127.0.0.1:9222"},
        "trace_path": str(trace_path) if trace_path is not None else None,
        "trace_scope": trace_scope,
        "run_id": "stream-run",
        "chromium_revision": "b" * 40,
    }

    def launch(config, _root):  # noqa: ANN001
        budgets.append(("launch", config.timeout_seconds))
        clock[0] += 2.0
        return tmp_path / "session.json", session

    def wait(_endpoint, _url, _title, *, timeout_seconds, **_kwargs):  # noqa: ANN001
        budgets.append(("wait", timeout_seconds))
        clock[0] += 2.0
        return {}

    def stop(_path, *, timeout_seconds):  # noqa: ANN001
        budgets.append(("stop", timeout_seconds))
        clock[0] += 1.0
        return {
            "run_id": stop_run_id,
            "state": stop_state,
            "running": stop_state != "stopped",
            "identity_protected": True,
        }

    monkeypatch.setattr(stream_calibration, "_ResultStore", Store)
    monkeypatch.setattr(stream_calibration, "ThreadingHTTPServer", Server)
    monkeypatch.setattr(
        stream_calibration,
        "_stable_regular_bytes",
        lambda *_args, **_kwargs: b"fixture",
    )
    monkeypatch.setattr(stream_calibration, "launch_evaluation", launch)
    monkeypatch.setattr(stream_calibration, "wait_for_page_target", wait)
    monkeypatch.setattr(stream_calibration, "stop_session", stop)
    monkeypatch.setattr(stream_calibration.time, "monotonic", lambda: clock[0])
    return budgets, holder


def run(mode: str, pair_index: int, position: int) -> dict:
    result = fixture_result()
    if mode == "on":
        result["default"]["duration_ms"] = 5.0
        result["byob"]["duration_ms"] = 7.0
    expected_per_mode = result["reads"] + result["warmup_reads"] + 2
    return {
        "trace_mode": mode,
        "trace_scope": "causal-stream" if mode == "on" else None,
        "pair_index": pair_index,
        "position": position,
        "run_id": f"{mode}-{pair_index}",
        "session_file": "local",
        "fixture_result": result,
        "trace_bytes": 4096 if mode == "on" else None,
        "trace_summary": {
            "events": 64,
            "dropped_events": 0,
            "requests": expected_per_mode * 2,
            "results": expected_per_mode * 2,
            "modes": {
                "default": {
                    "results": expected_per_mode,
                    "chunks": result["reads"] + result["warmup_reads"],
                    "closed": 2,
                },
                "byob": {
                    "results": expected_per_mode,
                    "chunks": result["reads"] + result["warmup_reads"],
                    "closed": 2,
                },
            },
        }
        if mode == "on"
        else None,
    }


@pytest.mark.parametrize("field", ["trace_mode", "trace_scope"])
def test_stream_saved_run_rejects_unhashable_trace_choice(field: str) -> None:
    saved = run("on", 0, 0)
    saved[field] = ["on"]
    with pytest.raises(ContractError, match="run trace contract"):
        stream_calibration._validated_stream_run(saved)


def scoped_run(scope: str, pair_index: int, position: int) -> dict:
    value = run("on", pair_index, position)
    value["trace_scope"] = scope
    if scope == "causal":
        value["trace_summary"] = {
            "events": 3,
            "dropped_events": 0,
            "requests": 0,
            "results": 0,
            "modes": {},
        }
    else:
        value["fixture_result"]["default"]["duration_ms"] = 6.0
        value["fixture_result"]["byob"]["duration_ms"] = 8.0
    return value


def test_stream_calibration_result_accepts_exact_safe_semantics() -> None:
    result = validate_stream_calibration_result(
        fixture_result(), expected_reads=4, expected_warmup_reads=2
    )
    assert result["byob"]["close_value_length"] == 0


@pytest.mark.parametrize(
    ('path', 'replacement'),
    [
        (('descriptors', 'default', 'function_length'), False),
        (('descriptors', 'byob', 'function_length'), True),
        (('descriptors', 'default', 'configurable'), 1),
        (('default', 'chunks'), 4.0),
        (('default', 'bytes'), 128.0),
        (('byob', 'chunks'), 4.0),
        (('byob', 'bytes'), 128.0),
        (('byob', 'close_value_length'), False),
    ],
)
def test_stream_calibration_result_requires_exact_json_field_types(
    path, replacement,
) -> None:
    result = fixture_result()
    target = result
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = replacement
    with pytest.raises(ContractError):
        validate_stream_calibration_result(result)


def test_stream_calibration_result_rejects_huge_duration_as_contract_error() -> None:
    result = fixture_result()
    result["default"]["duration_ms"] = 10**400
    with pytest.raises(ContractError, match="allowed range"):
        validate_stream_calibration_result(result)


def test_stream_overhead_rejects_nonfinite_binary64_result() -> None:
    with pytest.raises(ContractError, match="finite numeric range"):
        stream_calibration._percent(120_000.0, 5e-324)


def test_stream_calibration_result_rejects_boolean_expected_counts() -> None:
    with pytest.raises(ContractError, match="expected reads"):
        validate_stream_calibration_result(fixture_result(), expected_reads=True)


def test_result_store_retains_an_immutable_strict_json_population() -> None:
    store = stream_calibration._ResultStore(4, 2)
    source = fixture_result()
    store.put(source)
    source["default"]["duration_ms"] = 999

    first = store.get()
    assert first["default"]["duration_ms"] == 4.0
    first["default"]["duration_ms"] = 888
    assert store.get()["default"]["duration_ms"] == 4.0


def test_result_store_does_not_republish_rejected_private_values() -> None:
    store = stream_calibration._ResultStore(4, 2)
    source = fixture_result()
    source["private_path"] = r"C:\private\fixture-result.json"

    with pytest.raises(ContractError):
        store.put(source)

    assert store.get_error() == "invalid fixture result"
    assert "private" not in store.get_error()


def test_handler_requires_retained_bounded_fixture_bytes() -> None:
    store = stream_calibration._ResultStore(4, 2)
    with pytest.raises(ContractError, match="fixture bytes"):
        stream_calibration._handler(Path("fixture.html"), store)
    with pytest.raises(ContractError, match="fixture bytes"):
        stream_calibration._handler(
            b"x" * (stream_calibration.MAX_FIXTURE_BYTES + 1), store
        )


@pytest.mark.parametrize(
    'error', [BrokenPipeError, ConnectionResetError, ConnectionAbortedError],
)
def test_stream_handler_treats_peer_disconnect_as_normal_close(
    monkeypatch: pytest.MonkeyPatch, error,
) -> None:
    handler = stream_calibration._handler(
        b'fixture', stream_calibration._ResultStore(4, 2),
    )

    def disconnected(self):
        raise error('peer disconnected')

    monkeypatch.setattr(BaseHTTPRequestHandler, 'handle', disconnected)
    handler.handle(object.__new__(handler))


def test_result_handler_rejects_an_incomplete_declared_body() -> None:
    store = stream_calibration._ResultStore(4, 2)
    handler_type = stream_calibration._handler(b"fixture", store)
    handler = object.__new__(handler_type)
    handler.path = "/result"
    handler.headers = Message()
    handler.headers.add_header("Content-Type", "application/json")
    handler.headers.add_header("Content-Length", "10")
    handler.rfile = io.BytesIO(b"{}")
    handler.close_connection = False
    timeouts = []
    handler.connection = SimpleNamespace(
        settimeout=lambda value: timeouts.append(value)
    )
    errors = []
    handler.send_error = lambda status: errors.append(status)

    handler.do_POST()

    assert errors == [400]
    assert handler.close_connection is True
    assert timeouts
    assert all(
        0 < timeout <= stream_calibration.RESULT_READ_TIMEOUT_SECONDS
        for timeout in timeouts
    )
    assert store.get() is None


def test_result_handler_closes_rejected_route_with_unread_body() -> None:
    store = stream_calibration._ResultStore(4, 2)
    handler_type = stream_calibration._handler(b"fixture", store)
    handler = object.__new__(handler_type)
    handler.path = "/wrong-route"
    handler.headers = Message()
    handler.headers.add_header("Content-Type", "application/json")
    handler.headers.add_header("Content-Length", "2")
    handler.rfile = io.BytesIO(b"{}")
    handler.close_connection = False
    errors = []
    handler.send_error = lambda status: errors.append(status)

    handler.do_POST()

    assert errors == [404]
    assert handler.close_connection is True
    assert handler.rfile.read() == b"{}"
    assert store.get() is None


def test_result_handler_rejects_body_exceeding_total_read_deadline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = stream_calibration._ResultStore(4, 2)
    handler_type = stream_calibration._handler(b"fixture", store)
    handler = object.__new__(handler_type)
    handler.path = "/result"
    payload = json.dumps(fixture_result(), separators=(",", ":")).encode("utf-8")
    handler.headers = Message()
    handler.headers.add_header("Content-Type", "application/json")
    handler.headers.add_header("Content-Length", str(len(payload)))

    elapsed = [0.0]
    monkeypatch.setattr(stream_calibration.time, "monotonic", lambda: elapsed[0])

    class SlowBody:
        def __init__(self) -> None:
            self.position = 0

        def read(self, count: int) -> bytes:
            elapsed[0] += 6.0
            return payload[:count]

        def read1(self, count: int) -> bytes:
            elapsed[0] += 3.0
            end = min(self.position + count, self.position + len(payload) // 2)
            chunk = payload[self.position : end]
            self.position = end
            return chunk

    handler.rfile = SlowBody()
    handler.connection = SimpleNamespace(settimeout=lambda _value: None)
    errors = []
    responses = []
    handler.send_error = lambda status: errors.append(status)
    handler.send_response = lambda status: responses.append(status)
    handler.send_header = lambda _name, _value: None
    handler.end_headers = lambda: None

    handler.do_POST()

    assert errors == [400]
    assert responses == []
    assert store.get() is None


def test_result_handler_restores_timeout_after_valid_chunked_body(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = stream_calibration._ResultStore(4, 2)
    handler_type = stream_calibration._handler(b"fixture", store)
    handler = object.__new__(handler_type)
    handler.path = "/result"
    payload = json.dumps(fixture_result(), separators=(",", ":")).encode("utf-8")
    handler.headers = Message()
    handler.headers.add_header("Content-Type", "application/json")
    handler.headers.add_header("Content-Length", str(len(payload)))

    elapsed = [0.0]
    monkeypatch.setattr(stream_calibration.time, "monotonic", lambda: elapsed[0])

    class ChunkedBody:
        def __init__(self) -> None:
            self.position = 0

        def read1(self, count: int) -> bytes:
            first = self.position == 0
            elapsed[0] += 4.0 if first else 0.5
            end = min(len(payload) // 2 if first else len(payload), self.position + count)
            chunk = payload[self.position : end]
            self.position = end
            return chunk

    handler.rfile = ChunkedBody()
    timeouts = []
    handler.connection = SimpleNamespace(
        settimeout=lambda value: timeouts.append(value)
    )
    responses = []
    handler.send_error = lambda status: pytest.fail(f"valid body rejected: {status}")
    handler.send_response = lambda status: responses.append(status)
    handler.send_header = lambda _name, _value: None
    handler.end_headers = lambda: None

    handler.do_POST()

    assert responses == [204]
    assert store.get() == fixture_result()
    assert timeouts[-1] == stream_calibration.RESULT_READ_TIMEOUT_SECONDS


def test_result_handler_rejects_duplicate_content_lengths() -> None:
    store = stream_calibration._ResultStore(4, 2)
    handler_type = stream_calibration._handler(b"fixture", store)
    handler = object.__new__(handler_type)
    handler.path = "/result"
    handler.headers = Message()
    handler.headers.add_header("Content-Type", "application/json")
    handler.headers.add_header("Content-Length", "2")
    handler.headers.add_header("Content-Length", "2")
    handler.rfile = io.BytesIO(b"{}")
    handler.connection = SimpleNamespace(settimeout=lambda _value: None)
    errors = []
    handler.send_error = lambda status: errors.append(status)

    handler.do_POST()

    assert errors == [400]
    assert store.get() is None


def test_result_handler_rejects_duplicate_json_members() -> None:
    store = stream_calibration._ResultStore(4, 2)
    handler_type = stream_calibration._handler(b"fixture", store)
    handler = object.__new__(handler_type)
    handler.path = "/result"
    payload = (
        json.dumps(fixture_result(), separators=(",", ":"))
        .replace(
            '"schema":"browser-core.stream-calibration-result/1",',
            '"schema":"browser-core.stream-calibration-result/1",'
            '"schema":"browser-core.stream-calibration-result/1",',
            1,
        )
        .encode("utf-8")
    )
    handler.headers = Message()
    handler.headers.add_header("Content-Type", "application/json")
    handler.headers.add_header("Content-Length", str(len(payload)))
    handler.rfile = io.BytesIO(payload)
    handler.connection = SimpleNamespace(settimeout=lambda _value: None)
    errors = []
    handler.send_error = lambda status: errors.append(status)
    handler.send_response = lambda status: pytest.fail(
        f"duplicate JSON received success status {status}"
    )

    handler.do_POST()

    assert errors == [400]
    assert store.get() is None


def test_stream_calibration_artifact_helpers_reject_hard_link_aliases(
    tmp_path: Path,
) -> None:
    source = tmp_path / "fixture.html"
    source.write_bytes(b"fixture")
    (tmp_path / "fixture-alias.html").hardlink_to(source)

    with pytest.raises(ContractError, match="hard links"):
        stream_calibration._stable_regular_bytes(
            source,
            maximum=1024,
            label="fixture",
        )
    with pytest.raises(ContractError, match="hard links"):
        stream_calibration._regular_file_identity(source, label="trace")


@pytest.mark.parametrize(
    "mutate",
    [
        lambda value: replace(value, reads=True),
        lambda value: replace(value, warmup_reads=False),
        lambda value: replace(value, timeout_seconds=float("nan")),
        lambda value: replace(value, timeout_seconds=301),
        lambda value: replace(value, timeout_seconds=10**400),
        lambda value: replace(value, executable="chrome"),
    ],
)
def test_trial_config_rejects_malformed_controls_before_server_contact(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mutate
) -> None:
    config = StreamCalibrationTrial(
        executable=tmp_path / "chrome",
        trace_processor=tmp_path / "trace_processor",
        workspace=tmp_path / "workspace",
        trace_mode="on",
        reads=4,
        warmup_reads=2,
    )
    contacted = []
    monkeypatch.setattr(
        stream_calibration,
        "ThreadingHTTPServer",
        lambda *args, **kwargs: contacted.append(True),
    )

    with pytest.raises(ContractError):
        run_stream_calibration_trial(mutate(config), ROOT)

    assert contacted == []


def test_stream_trial_shares_measurement_deadline_and_verifies_cleanup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    clock = [0.0]
    budgets, holder = _install_trial_fakes(monkeypatch, tmp_path, clock)
    config = StreamCalibrationTrial(
        executable=tmp_path / "chrome",
        trace_processor=tmp_path / "trace_processor",
        workspace=tmp_path / "workspace",
        trace_mode="off",
        reads=4,
        warmup_reads=2,
        timeout_seconds=6,
    )

    result = run_stream_calibration_trial(config, ROOT)

    assert budgets == [("launch", 6.0), ("wait", 4.0), ("stop", 15.0)]
    assert result["trace_mode"] == "off"
    server = holder["server"]
    assert server.shutdown_called is True
    assert server.closed is True


def test_stream_trial_timeout_cannot_be_refreshed_by_cleanup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    clock = [0.0]
    budgets, holder = _install_trial_fakes(monkeypatch, tmp_path, clock)
    config = StreamCalibrationTrial(
        executable=tmp_path / "chrome",
        trace_processor=tmp_path / "trace_processor",
        workspace=tmp_path / "workspace",
        trace_mode="off",
        reads=4,
        warmup_reads=2,
        timeout_seconds=4,
    )

    with pytest.raises(ContractError, match="trial timed out"):
        run_stream_calibration_trial(config, ROOT)

    assert budgets == [("launch", 4.0), ("wait", 2.0), ("stop", 15.0)]
    assert holder["server"].closed is True


def test_stream_trial_rejects_unverified_stop_before_trace_processing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    clock = [0.0]
    budgets, holder = _install_trial_fakes(
        monkeypatch,
        tmp_path,
        clock,
        stop_state="active",
    )
    exported: list[bool] = []
    monkeypatch.setattr(
        stream_calibration,
        "export_perfetto",
        lambda *_args, **_kwargs: exported.append(True),
    )
    config = StreamCalibrationTrial(
        executable=tmp_path / "chrome",
        trace_processor=tmp_path / "trace_processor",
        workspace=tmp_path / "workspace",
        trace_mode="off",
        reads=4,
        warmup_reads=2,
        timeout_seconds=6,
    )

    with pytest.raises(ContractError, match=r"cleanup failed \(session-stop\)"):
        run_stream_calibration_trial(config, ROOT)

    assert budgets[-1] == ("stop", 15.0)
    assert exported == []
    assert holder["server"].closed is True


def test_stream_trial_rejects_stop_receipt_for_another_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    clock = [0.0]
    budgets, holder = _install_trial_fakes(
        monkeypatch,
        tmp_path,
        clock,
        stop_run_id="other-stream-run",
    )
    config = StreamCalibrationTrial(
        executable=tmp_path / "chrome",
        trace_processor=tmp_path / "trace_processor",
        workspace=tmp_path / "workspace",
        trace_mode="off",
        reads=4,
        warmup_reads=2,
        timeout_seconds=6,
    )

    with pytest.raises(ContractError, match=r"cleanup failed \(session-stop\)"):
        run_stream_calibration_trial(config, ROOT)

    assert budgets[-1] == ("stop", 15.0)
    assert holder["server"].closed is True


def test_stream_server_cleanup_attempts_every_phase_after_failures() -> None:
    class Server:
        def shutdown(self) -> None:
            raise RuntimeError("private shutdown detail")

        def server_close(self) -> None:
            raise OSError("private close detail")

    class MainThread:
        def join(self, *, timeout: float) -> None:
            assert timeout == stream_calibration.STREAM_SERVER_CLEANUP_TIMEOUT_SECONDS
            raise RuntimeError("private join detail")

    failures = stream_calibration._stop_stream_server(
        Server(),
        MainThread(),
        started=True,
    )

    assert failures == ["server-shutdown", "server-close", "server-thread"]


def test_stream_server_shutdown_closes_accepted_keepalive_client() -> None:
    server = ThreadingHTTPServer(
        ('127.0.0.1', 0),
        stream_calibration._handler(b'fixture', stream_calibration._ResultStore(4, 2)),
    )
    server.daemon_threads = True
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    stopped = False
    try:
        with socket.create_connection(server.server_address, timeout=2) as client:
            client.settimeout(2)
            client.sendall(b'GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n')
            response = b''
            while b'fixture' not in response:
                part = client.recv(4096)
                assert part
                response += part
            assert b'HTTP/1.1 200 OK' in response
            assert stream_calibration._stop_stream_server(server, worker, started=True) == []
            stopped = True
            client.settimeout(0.2)
            assert client.recv(1) == b''
    finally:
        if not stopped:
            stream_calibration._stop_stream_server(server, worker, started=True)


def test_stream_server_rejects_aggregate_oversized_request_headers() -> None:
    server = ThreadingHTTPServer(
        ('127.0.0.1', 0),
        stream_calibration._handler(b'fixture', stream_calibration._ResultStore(4, 2)),
    )
    server.daemon_threads = True
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    request = (
        b'GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n'
        + b''.join(
            f'X-Pad-{index:03d}: '.encode() + b'a' * 900 + b'\r\n'
            for index in range(80)
        )
        + b'\r\n'
    )
    assert len(request) > MAX_HTTP_HEADER_BYTES
    try:
        with socket.create_connection(server.server_address, timeout=2) as client:
            client.settimeout(2)
            try:
                client.sendall(request)
            except (BrokenPipeError, ConnectionResetError):
                pass
            response = bytearray()
            while b'fixture' not in response:
                try:
                    chunk = client.recv(4096)
                except ConnectionResetError:
                    break
                if not chunk:
                    break
                response.extend(chunk)
            assert b'HTTP/1.1 200 OK' not in response
            assert b'fixture' not in response
    finally:
        stream_calibration._stop_stream_server(server, worker, started=True)


def test_stream_server_reclaims_shutdown_thread_after_late_start_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    release = threading.Event()
    threads = []
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

        def __init__(self, *, target, name, daemon):
            self.worker = real_thread(target=target, name=name, daemon=daemon)
            threads.append(self)

        def start(self) -> None:
            self.worker.start()
            raise RuntimeError('late start error')

        def is_alive(self) -> bool:
            return self.worker.is_alive()

        def join(self, *, timeout: float) -> None:
            self.joined = True
            self.worker.join(timeout=timeout)

    monkeypatch.setattr(stream_calibration, 'Thread', ShutdownThread)
    monkeypatch.setattr(stream_calibration, 'STREAM_SERVER_CLEANUP_TIMEOUT_SECONDS', 0.1)
    server = Server()
    failures = stream_calibration._stop_stream_server(server, None, started=True)

    assert failures == ['server-shutdown']
    assert server.closed is True
    assert threads[0].joined is True
    assert threads[0].is_alive() is False


def test_stream_trial_closes_server_when_thread_construction_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    holder: dict[str, object] = {}

    class Server:
        def __init__(self, _address, _handler):  # noqa: ANN001
            holder["server"] = self
            self.closed = False

        def serve_forever(self) -> None:
            return

        def server_close(self) -> None:
            self.closed = True

    monkeypatch.setattr(
        stream_calibration,
        "_stable_regular_bytes",
        lambda *_args, **_kwargs: b"fixture",
    )
    monkeypatch.setattr(stream_calibration, "ThreadingHTTPServer", Server)

    def reject_thread(**_kwargs):  # noqa: ANN003
        raise RuntimeError("private thread detail")

    monkeypatch.setattr(stream_calibration, "Thread", reject_thread)
    config = StreamCalibrationTrial(
        executable=tmp_path / "chrome",
        trace_processor=tmp_path / "trace_processor",
        workspace=tmp_path / "workspace",
        trace_mode="off",
        reads=4,
        warmup_reads=2,
    )

    with pytest.raises(
        ContractError,
        match=r"server could not start \(RuntimeError\)",
    ) as raised:
        run_stream_calibration_trial(config, ROOT)

    assert "private thread detail" not in str(raised.value)
    assert holder["server"].closed is True


def test_stream_trial_stops_worker_when_start_raises_after_launch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class Server:
        server_port = 12345

        def __init__(self):
            self.phases = []

        def serve_forever(self):
            return

        def shutdown(self):
            self.phases.append('shutdown')

        def server_close(self):
            self.phases.append('close')

    class Worker:
        alive = False

        def start(self):
            self.alive = True
            raise RuntimeError('private post-start failure')

        def is_alive(self):
            return self.alive

        def join(self, *, timeout):
            assert timeout == stream_calibration.STREAM_SERVER_CLEANUP_TIMEOUT_SECONDS
            server.phases.append('join')
            self.alive = False

    server = Server()
    real_thread = threading.Thread

    def make_thread(*, name, **kwargs):
        if name == 'browser-core-stream-calibration':
            return Worker()
        return real_thread(name=name, **kwargs)

    monkeypatch.setattr(stream_calibration, '_stable_regular_bytes',
                        lambda *_args, **_kwargs: b'fixture')
    monkeypatch.setattr(stream_calibration, 'ThreadingHTTPServer',
                        lambda *_args, **_kwargs: server)
    monkeypatch.setattr(stream_calibration, 'Thread', make_thread)
    config = StreamCalibrationTrial(
        executable=tmp_path / 'chrome', trace_processor=tmp_path / 'trace_processor',
        workspace=tmp_path / 'workspace', trace_mode='off', reads=4, warmup_reads=2,
    )

    with pytest.raises(ContractError, match=r'server could not start \(RuntimeError\)'):
        run_stream_calibration_trial(config, ROOT)
    assert server.phases == ['shutdown', 'close', 'join']


def test_stream_trial_rejects_symlink_fixture_before_server_contact(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository = tmp_path / "repository"
    fixtures = repository / "fixtures"
    fixtures.mkdir(parents=True)
    source = tmp_path / "fixture.html"
    source.write_bytes(b"fixture")
    fixture = fixtures / "native-stream-calibration.html"
    try:
        fixture.symlink_to(source)
    except OSError as exc:
        pytest.skip(f"symlink creation is unavailable: {type(exc).__name__}")
    contacted: list[bool] = []
    monkeypatch.setattr(
        stream_calibration,
        "ThreadingHTTPServer",
        lambda *_args, **_kwargs: contacted.append(True),
    )
    config = StreamCalibrationTrial(
        executable=tmp_path / "chrome",
        trace_processor=tmp_path / "trace_processor",
        workspace=tmp_path / "workspace",
        trace_mode="off",
        reads=4,
        warmup_reads=2,
    )

    with pytest.raises(ContractError, match="fixture"):
        run_stream_calibration_trial(config, repository)

    assert contacted == []


def test_stream_trial_forwards_unresolved_trace_processor_binding(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    processor = tmp_path / "trace_processor"
    processor.write_bytes(b"processor")
    (tmp_path / "binding").mkdir()
    processor_binding = tmp_path / "binding" / ".." / "trace_processor"
    trace = tmp_path / "trace.perfetto"
    trace.write_bytes(b"perfetto")
    clock = [0.0]
    _budgets, holder = _install_trial_fakes(
        monkeypatch,
        tmp_path,
        clock,
        trace_path=trace,
        trace_scope="causal-stream",
    )
    identity = (1, 2, 3, 8, 4, 5, 0)
    monkeypatch.setattr(
        stream_calibration,
        "_regular_file_identity",
        lambda *_args, **_kwargs: identity,
    )
    source_binding = {"bytes": 8, "sha256": "c" * 64}

    def bind(_path: Path) -> dict[str, object]:
        assert holder["server"].shutdown_called is False
        return source_binding

    monkeypatch.setattr(stream_calibration, "bind_perfetto_source_trace", bind)
    forwarded: list[tuple[Path, object]] = []

    def export(tool: Path, *_args, **_kwargs) -> None:  # noqa: ANN002, ANN003
        forwarded.append((tool, _kwargs["expected_source_binding"]))

    monkeypatch.setattr(stream_calibration, "export_perfetto", export)
    monkeypatch.setattr(
        stream_calibration,
        "_native_stream_summary",
        lambda *_args, **_kwargs: {
            "events": 16,
            "dropped_events": 0,
            "requests": 16,
            "results": 16,
            "modes": {
                "default": {"results": 8, "chunks": 6, "closed": 2},
                "byob": {"results": 8, "chunks": 6, "closed": 2},
            },
        },
    )
    config = StreamCalibrationTrial(
        executable=tmp_path / "chrome",
        trace_processor=processor_binding,
        workspace=tmp_path / "workspace",
        trace_mode="on",
        reads=4,
        warmup_reads=2,
        timeout_seconds=6,
    )

    result = run_stream_calibration_trial(config, ROOT)

    assert result["trace_bytes"] == 8
    assert forwarded == [(processor_binding, source_binding)]
    assert forwarded[0][0] != processor


@pytest.mark.parametrize(
    ("mutation", "error"),
    [
        (
            lambda value: value["descriptors"]["default"].update(native_source=False),
            "descriptor changed",
        ),
        (lambda value: value["default"].update(bytes=31), "semantics changed"),
        (
            lambda value: value["byob"].update(close_value_length=1),
            "closure value changed",
        ),
        (lambda value: value.update(request_body="forbidden"), "fields are invalid"),
    ],
)
def test_stream_calibration_result_rejects_contract_drift(mutation, error: str) -> None:
    result = fixture_result()
    mutation(result)

    with pytest.raises(ContractError, match=error):
        validate_stream_calibration_result(result)


def test_stream_trace_mode_cohort_accepts_balanced_exact_runs() -> None:
    runs = [
        run("off", 0, 0),
        run("on", 0, 1),
        run("on", 1, 0),
        run("off", 1, 1),
    ]
    summary = summarize_stream_trace_mode_runs(
        runs,
        trials_per_arm=2,
        max_read_overhead_percent=50,
        max_trace_bytes=8192,
    )

    assert summary["passed"] is True
    assert summary["delta"]["total_median_overhead_percent"] == 20.0
    assert summary["assessment"]["timing_direction"] == (
        "trace_on_slower_in_paired_median"
    )
    assert summary["gates"]["trace_on_exact_native_stream_coverage"] is True
    assert validate_stream_trace_mode_cohort_report(summary) == summary


def test_stream_trace_mode_cohort_report_rejects_copied_contradictions() -> None:
    summary = summarize_stream_trace_mode_runs(
        [
            run("off", 0, 0),
            run("on", 0, 1),
            run("on", 1, 0),
            run("off", 1, 1),
        ],
        trials_per_arm=2,
        max_read_overhead_percent=50,
        max_trace_bytes=8192,
    )
    mutations = []
    extra = copy.deepcopy(summary)
    extra["private"] = "private-stream-report-marker"
    mutations.append(extra)
    runs = copy.deepcopy(summary)
    runs["arms"]["off"]["runs"] = 3
    mutations.append(runs)
    trace_size = copy.deepcopy(summary)
    trace_size["arms"]["on"]["trace_bytes_max"] = 9000
    mutations.append(trace_size)
    trace_median = copy.deepcopy(summary)
    trace_median["arms"]["on"]["trace_bytes_median"] = 10**400
    mutations.append(trace_median)
    delta = copy.deepcopy(summary)
    delta["delta"]["total_median_overhead_percent"] += 1
    mutations.append(delta)
    paired = copy.deepcopy(summary)
    paired["delta"]["paired_overhead_percent_median"] += 1
    mutations.append(paired)
    huge_paired = copy.deepcopy(summary)
    huge_paired["delta"]["paired_overhead_percent"][0] = 10**400
    mutations.append(huge_paired)
    assessment = copy.deepcopy(summary)
    assessment["assessment"]["semantics"] = "changed_across_supplied_trials"
    mutations.append(assessment)
    limit = copy.deepcopy(summary)
    limit["limits"]["max_trace_bytes"] = 1
    mutations.append(limit)
    gate = copy.deepcopy(summary)
    gate["gates"]["balanced_paired_arms"] = False
    mutations.append(gate)
    verdict = copy.deepcopy(summary)
    verdict["passed"] = False
    mutations.append(verdict)
    limitations = copy.deepcopy(summary)
    limitations["limitations"] = []
    mutations.append(limitations)

    for mutation in mutations:
        with pytest.raises(ContractError) as failure:
            validate_stream_trace_mode_cohort_report(mutation)
        assert "private-stream-report-marker" not in str(failure.value)


def test_stream_trace_mode_cohort_flags_cross_run_semantic_drift() -> None:
    runs = [
        run("off", 0, 0),
        run("on", 0, 1),
        run("on", 1, 0),
        run("off", 1, 1),
    ]
    changed = copy.deepcopy(runs[-1]["fixture_result"])
    changed["reads"] = 5
    changed["default"].update(chunks=5, bytes=160)
    changed["byob"].update(chunks=5, bytes=160)
    runs[-1]["fixture_result"] = changed

    summary = summarize_stream_trace_mode_runs(
        runs,
        trials_per_arm=2,
        max_read_overhead_percent=50,
        max_trace_bytes=8192,
    )

    assert summary["passed"] is False
    assert summary["gates"]["stable_descriptor_and_semantic_vector"] is False


def test_stream_trace_mode_cohort_rejects_non_alternating_pair_order() -> None:
    runs = [
        run("off", 0, 0),
        run("on", 0, 1),
        run("on", 1, 1),
        run("off", 1, 0),
    ]

    with pytest.raises(ContractError, match="pair order"):
        summarize_stream_trace_mode_runs(
            runs,
            trials_per_arm=2,
            max_read_overhead_percent=50,
            max_trace_bytes=8192,
        )


def test_stream_calibration_fixture_uses_public_readers_without_runtime_binding() -> (
    None
):
    source = (ROOT / "fixtures" / "native-stream-calibration.html").read_text(
        encoding="utf-8"
    )
    assert "ReadableStreamDefaultReader.prototype" in source
    assert "ReadableStreamBYOBReader.prototype" in source
    assert "reader.read(" in source
    assert "Runtime." not in source
    assert "addBinding" not in source
    assert "emitCausalReadinessMarker" in source
    assert "canvas.toDataURL()" in source

    patch = (
        ROOT / "patches" / "0004-browser-core-readable-stream-track-events.patch"
    ).read_text(encoding="utf-8")
    assert patch.count('TRACE_EVENT_CATEGORY_ENABLED("browser_core.stream")') == 2
    assert 'TRACE_EVENT_CATEGORY_ENABLED("browser_core.debug")' not in patch
    category_patch = (
        ROOT / "patches" / "0002-browser-core-canvas-track-event.patch"
    ).read_text(encoding="utf-8")
    assert 'perfetto::Category("browser_core.stream")' in category_patch


def test_causal_only_stream_control_requires_zero_reader_events(tmp_path: Path) -> None:
    source = ROOT / "fixtures" / "trace-v1.jsonl"
    summary = _native_stream_summary(source, 1, 1, expect_stream_events=False)
    assert summary["requests"] == 0
    assert summary["results"] == 0

    lines = source.read_text(encoding="utf-8").splitlines()
    request = {
        "schema": "browser-core.trace-event/1",
        "run_id": "fixture-run",
        "seq": len(lines),
        "ts_monotonic_ns": 2000,
        "process": {"pid": 4200, "type": "renderer"},
        "execution": {"context_id": "ctx-main", "frame_id": "ctx-main"},
        "event": {"category": "stream", "name": "stream.read.request"},
        "provenance": {
            "source": "native",
            "component": "blink.streams",
            "chromium_revision": "bf6d8a66b43635a532bdad773407285fac0121e9",
        },
        "detail": {
            "native_name": "BrowserCore.StreamReadRequest",
            "thread_id": 1,
            "reader_mode": "default",
        },
    }
    contaminated = tmp_path / "contaminated.jsonl"
    contaminated.write_text(
        "\n".join([*lines, json.dumps(request)]) + "\n",
        encoding="utf-8",
    )
    with pytest.raises(ContractError, match="unexpectedly activated"):
        _native_stream_summary(contaminated, 1, 1, expect_stream_events=False)


def test_stream_scope_gate_requires_isolated_and_exact_scopes() -> None:
    causal = run("on", 0, 0)
    causal["trace_scope"] = "causal"
    causal["trace_summary"] = {
        "events": 3,
        "dropped_events": 0,
        "requests": 0,
        "results": 0,
        "modes": {},
    }
    causal_stream = run("on", 0, 1)
    causal_stream["trace_scope"] = "causal-stream"

    report = summarize_stream_scope_runs(
        {
            "causal": causal,
            "causal-stream": causal_stream,
        }
    )

    assert report["passed"] is True
    assert report["gates"]["causal_scope_zero_stream_events"] is True
    assert validate_stream_scope_report(report) == report


def test_stream_scope_report_is_fully_rebuilt_from_its_safe_runs() -> None:
    report = summarize_stream_scope_runs(
        {
            "causal": scoped_run("causal", 0, 0),
            "causal-stream": scoped_run("causal-stream", 0, 1),
        }
    )
    mutations = []
    extra = copy.deepcopy(report)
    extra["private"] = "private-scope-report-marker"
    mutations.append(extra)
    gate = copy.deepcopy(report)
    gate["gates"]["causal_scope_zero_stream_events"] = False
    mutations.append(gate)
    verdict = copy.deepcopy(report)
    verdict["passed"] = False
    mutations.append(verdict)
    limitations = copy.deepcopy(report)
    limitations["limitations"] = []
    mutations.append(limitations)
    run_evidence = copy.deepcopy(report)
    run_evidence["runs"]["causal"]["trace_summary"]["requests"] += 1
    mutations.append(run_evidence)

    for mutation in mutations:
        with pytest.raises(ContractError) as failure:
            validate_stream_scope_report(mutation)
        assert "private-scope-report-marker" not in str(failure.value)


@pytest.mark.parametrize('field', ['passed', 'gate'])
def test_stream_scope_report_rejects_integer_in_boolean_claims(field) -> None:
    report = summarize_stream_scope_runs({
        'causal': scoped_run('causal', 0, 0),
        'causal-stream': scoped_run('causal-stream', 0, 1),
    })
    assert report['passed'] is True
    if field == 'passed':
        report['passed'] = 1
    else:
        report['gates']['stable_descriptor_and_semantic_vector'] = 1
    with pytest.raises(ContractError, match='scope report'):
        validate_stream_scope_report(report)


def test_stream_scope_gate_reconstructs_path_free_closed_runs() -> None:
    causal = scoped_run("causal", 0, 0)
    stream = scoped_run("causal-stream", 0, 1)
    private = r"C:\private\session.json"
    causal["session_file"] = private
    stream["session_file"] = private

    report = summarize_stream_scope_runs({"causal": causal, "causal-stream": stream})

    assert private not in json.dumps(report)
    assert all("session_file" not in value for value in report["runs"].values())


def test_stream_scope_gate_rejects_unknown_run_and_trace_summary_fields() -> None:
    causal = scoped_run("causal", 0, 0)
    stream = scoped_run("causal-stream", 0, 1)
    causal["private_path"] = r"C:\private\session.json"
    with pytest.raises(ContractError, match="run fields"):
        summarize_stream_scope_runs({"causal": causal, "causal-stream": stream})

    causal.pop("private_path")
    causal["trace_summary"]["private_path"] = r"C:\private\trace.jsonl"
    with pytest.raises(ContractError, match="trace summary"):
        summarize_stream_scope_runs({"causal": causal, "causal-stream": stream})


def test_stream_scope_cohort_rejects_boolean_pair_coordinates() -> None:
    runs = [
        scoped_run("causal", 0, 0),
        scoped_run("causal-stream", 0, 1),
        scoped_run("causal-stream", 1, 0),
        scoped_run("causal", 1, 1),
    ]
    runs[0]["position"] = True

    with pytest.raises(ContractError, match="pairing"):
        summarize_stream_scope_cohort(
            runs,
            trials_per_arm=2,
            max_added_overhead_percent=50,
            max_trace_bytes=8192,
        )


def test_native_stream_summary_detects_mutation_after_validated_scan(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    trace = tmp_path / "trace.jsonl"
    trace.write_bytes((ROOT / "fixtures" / "trace-v1.jsonl").read_bytes())
    original_scan = stream_calibration.scan_validated_trace

    def mutate_after_scan(path: Path, consumer, **kwargs):
        assert kwargs["maximum_events"] == stream_calibration.MAX_STREAM_TRACE_EVENTS
        result = original_scan(path, consumer, **kwargs)
        path.write_bytes(b"different-size")
        return result

    monkeypatch.setattr(stream_calibration, "scan_validated_trace", mutate_after_scan)

    with pytest.raises(ContractError, match="changed during summary"):
        _native_stream_summary(trace, 1, 1, expect_stream_events=False)


@pytest.mark.skipif(os.name != "nt", reason="Windows creation time is not change time")
def test_native_stream_summary_cannot_accept_changed_invalid_lineage(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    trace = tmp_path / "trace.jsonl"
    original = (ROOT / "fixtures" / "trace-v1.jsonl").read_bytes()
    trace.write_bytes(original)
    stamp = trace.stat()
    original_scan = stream_calibration.scan_validated_trace

    def change_after_scan(path: Path, consumer, **kwargs):
        validated = original_scan(path, consumer, **kwargs)
        changed = original.replace(b'"causal_parent_seq":1', b'"causal_parent_seq":9')
        assert changed != original and len(changed) == len(original)
        with path.open("r+b") as writer:
            writer.write(changed)
        os.utime(path, ns=(stamp.st_atime_ns, stamp.st_mtime_ns))
        return validated

    monkeypatch.setattr(stream_calibration, "scan_validated_trace", change_after_scan)
    monkeypatch.setattr(stream_calibration, "windows_change_time", lambda _handle: 0)

    with pytest.raises(ContractError, match="changed during summary"):
        _native_stream_summary(trace, 1, 1, expect_stream_events=False)


@pytest.mark.skipif(os.name != "nt", reason="Windows creation time is not change time")
def test_native_stream_summary_rejects_restored_mtime_after_scan(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    trace = tmp_path / "trace.jsonl"
    trace.write_bytes((ROOT / "fixtures" / "trace-v1.jsonl").read_bytes())
    stamp = trace.stat()
    original_scan = stream_calibration.scan_validated_trace

    def mutate_after_scan(path: Path, consumer, **kwargs):
        result = original_scan(path, consumer, **kwargs)
        with path.open("r+b") as writer:
            writer.seek(path.read_bytes().index(b"fixture-run") + len(b"fixture-ru"))
            writer.write(b"X")
        os.utime(path, ns=(stamp.st_atime_ns, stamp.st_mtime_ns))
        return result

    monkeypatch.setattr(stream_calibration, "scan_validated_trace", mutate_after_scan)
    monkeypatch.setattr(stream_calibration, "windows_change_time", lambda _handle: 0)
    with pytest.raises(ContractError, match="changed during summary"):
        _native_stream_summary(trace, 1, 1, expect_stream_events=False)


def test_native_stream_summary_closes_retained_iterator_on_semantic_rejection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import browser_core.trace as trace_module

    trace = tmp_path / "trace.jsonl"
    trace.write_bytes(b"fixture")
    retained = []
    closed = []

    def tracked_iter_trace(_path: Path, *, hash_update=None):
        def events():
            try:
                yield {"event": {"category": "stream", "name": "stream.read.request"}}
            finally:
                closed.append(True)
        generator = events()
        retained.append(generator)
        return generator

    monkeypatch.setattr(trace_module, "iter_trace", tracked_iter_trace)
    with pytest.raises(ContractError, match="reader mode is invalid"):
        _native_stream_summary(trace, 1, 1)
    assert len(retained) == 1
    assert closed == [True]


def test_native_stream_summary_rejects_float_chunk_length(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    trace = tmp_path / 'trace.jsonl'
    trace.write_bytes(b'fixture')

    def scan(_path, consumer, **kwargs):
        consumer({
            'event': {'category': 'stream', 'name': 'stream.read.result'},
            'detail': {'reader_mode': 'default', 'result_kind': 'chunk'},
            'value': {'length': 32.0},
        })
        return {'events': 1, 'dropped_events': 0}

    monkeypatch.setattr(stream_calibration, 'scan_validated_trace', scan)
    monkeypatch.setattr(
        stream_calibration, 'bind_perfetto_source_trace',
        lambda _path: {'bytes': 0, 'sha256': hashlib.sha256(b'').hexdigest()},
    )
    with pytest.raises(ContractError, match='chunk length is invalid'):
        _native_stream_summary(trace, 1, 1)


def test_stream_scope_gate_reports_semantic_drift() -> None:
    causal = run("on", 0, 0)
    causal["trace_scope"] = "causal"
    causal["trace_summary"] = {
        "events": 3,
        "dropped_events": 0,
        "requests": 0,
        "results": 0,
        "modes": {},
    }
    causal_stream = run("on", 0, 1)
    causal_stream["trace_scope"] = "causal-stream"
    causal_stream["fixture_result"]["default"]["duration_ms"] = 999.0
    causal_stream["fixture_result"]["default"]["bytes"] = 31

    with pytest.raises(ContractError, match="semantics changed"):
        summarize_stream_scope_runs(
            {
                "causal": causal,
                "causal-stream": causal_stream,
            }
        )


def test_stream_scope_cohort_measures_added_stream_cost() -> None:
    runs = [
        scoped_run("causal", 0, 0),
        scoped_run("causal-stream", 0, 1),
        scoped_run("causal-stream", 1, 0),
        scoped_run("causal", 1, 1),
    ]

    report = summarize_stream_scope_cohort(
        runs,
        trials_per_arm=2,
        max_added_overhead_percent=50,
        max_trace_bytes=8192,
    )

    assert report["passed"] is True
    assert report["delta"]["total_median_added_overhead_percent"] == 16.667
    assert report["assessment"]["timing_direction"] == (
        "causal_stream_slower_in_paired_median"
    )
    assert validate_stream_scope_cohort_report(report) == report


def test_stream_scope_cohort_report_recomputes_portable_aggregates() -> None:
    report = summarize_stream_scope_cohort(
        [
            scoped_run("causal", 0, 0),
            scoped_run("causal-stream", 0, 1),
            scoped_run("causal-stream", 1, 0),
            scoped_run("causal", 1, 1),
        ],
        trials_per_arm=2,
        max_added_overhead_percent=50,
        max_trace_bytes=8192,
    )
    mutations = []
    extra = copy.deepcopy(report)
    extra["private"] = "private-scope-cohort-marker"
    mutations.append(extra)
    runs = copy.deepcopy(report)
    runs["aggregates"]["causal"]["runs"] = 3
    mutations.append(runs)
    size = copy.deepcopy(report)
    size["aggregates"]["causal-stream"]["trace_bytes_max"] = 9000
    mutations.append(size)
    trace_median = copy.deepcopy(report)
    trace_median["aggregates"]["causal-stream"]["trace_bytes_median"] = 10**400
    mutations.append(trace_median)
    delta = copy.deepcopy(report)
    delta["delta"]["total_median_added_overhead_percent"] += 1
    mutations.append(delta)
    paired = copy.deepcopy(report)
    paired["delta"]["paired_added_overhead_percent_median"] += 1
    mutations.append(paired)
    huge_paired = copy.deepcopy(report)
    huge_paired["delta"]["paired_added_overhead_percent"][0] = 10**400
    mutations.append(huge_paired)
    limit = copy.deepcopy(report)
    limit["limits"]["max_trace_bytes"] = 1
    mutations.append(limit)
    gate = copy.deepcopy(report)
    gate["gates"]["balanced_alternating_arms"] = False
    mutations.append(gate)
    assessment = copy.deepcopy(report)
    assessment["assessment"]["semantics"] = "changed"
    mutations.append(assessment)
    verdict = copy.deepcopy(report)
    verdict["passed"] = False
    mutations.append(verdict)
    limitations = copy.deepcopy(report)
    limitations["limitations"] = []
    mutations.append(limitations)

    for mutation in mutations:
        with pytest.raises(ContractError) as failure:
            validate_stream_scope_cohort_report(mutation)
        assert "private-scope-cohort-marker" not in str(failure.value)


def test_stream_scope_cohort_rejects_non_alternating_order() -> None:
    runs = [
        scoped_run("causal", 0, 0),
        scoped_run("causal-stream", 0, 1),
        scoped_run("causal-stream", 1, 1),
        scoped_run("causal", 1, 0),
    ]

    with pytest.raises(ContractError, match="pair order"):
        summarize_stream_scope_cohort(
            runs,
            trials_per_arm=2,
            max_added_overhead_percent=50,
            max_trace_bytes=8192,
        )


@pytest.mark.parametrize("limit", [float("nan"), float("inf"), True, -1.0])
def test_stream_scope_cohort_rejects_invalid_overhead_limit(limit) -> None:
    runs = [
        scoped_run("causal", 0, 0),
        scoped_run("causal-stream", 0, 1),
        scoped_run("causal-stream", 1, 0),
        scoped_run("causal", 1, 1),
    ]
    with pytest.raises(ContractError, match="limits"):
        summarize_stream_scope_cohort(
            runs,
            trials_per_arm=2,
            max_added_overhead_percent=limit,
            max_trace_bytes=8192,
        )
