from __future__ import annotations

import json
import io
import re
import socket
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace
from urllib.error import HTTPError

import pytest

import browser_core.physical_mobile as mobile_module
from browser_core.bounded_process import BoundedProcessResult
from browser_core.contracts import ContractError
from browser_core.physical_mobile import discover_physical_mobile


def test_physical_fixture_reclaims_shutdown_thread_after_late_start_error(
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

        def join(self, *, timeout: float) -> None:
            self.joined = True

        def is_alive(self) -> bool:
            return not self.joined

    monkeypatch.setattr(mobile_module, "Thread", ShutdownThread)
    monkeypatch.setattr(mobile_module, "PHYSICAL_CLEANUP_TIMEOUT_SECONDS", 0.1)
    server = Server()
    worker = Worker()
    failures = mobile_module._stop_fixture_server(server, worker, started=True)

    assert failures == ["fixture-shutdown"]
    assert server.closed is True
    assert worker.joined is True
    assert threads[0].joined is True
    assert threads[0].is_alive() is False


def test_physical_probe_retains_worker_after_start_reports_late_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        mobile_module,
        "_discover_android_capability",
        lambda **_kwargs: ({"available": True}, "owned-device"),
    )

    class Server:
        server_port = 8765

        def serve_forever(self) -> None:
            return

    class LateFailingThread:
        def __init__(self, **_kwargs) -> None:
            self.alive = False

        def start(self) -> None:
            self.alive = True
            raise RuntimeError("late start failure")

        def is_alive(self) -> bool:
            return self.alive

    started: list[bool] = []

    def cleanup(**kwargs) -> None:  # type: ignore[no-untyped-def]
        started.append(kwargs["server_thread_started"])

    monkeypatch.setattr(mobile_module, "_FixtureServer", lambda *_args: Server())
    monkeypatch.setattr(mobile_module, "Thread", LateFailingThread)
    monkeypatch.setattr(mobile_module, "_cleanup_physical_android", cleanup)
    with pytest.raises((ContractError, RuntimeError)):
        mobile_module.probe_physical_android()
    assert started == [True]


def test_physical_fixture_does_not_shutdown_an_absent_worker() -> None:
    class Server:
        closed = False
        shutdown_calls = 0

        def shutdown(self) -> None:
            self.shutdown_calls += 1

        def server_close(self) -> None:
            self.closed = True

    class Worker:
        joined = False

        def is_alive(self) -> bool:
            return False

        def join(self, *, timeout: float) -> None:
            self.joined = True

    server = Server()
    worker = Worker()
    assert mobile_module._stop_fixture_server(server, worker, started=True) == []
    assert server.closed is True
    assert server.shutdown_calls == 0
    assert worker.joined is True


def test_physical_probe_rejects_dead_fixture_before_adb(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        mobile_module,
        "_discover_android_capability",
        lambda **_kwargs: ({"available": True}, "owned-device"),
    )

    class Server:
        server_port = 8765

        def serve_forever(self) -> None:
            return

    class DeadThread:
        def __init__(self, **_kwargs) -> None:
            return

        def start(self) -> None:
            return

        def is_alive(self) -> bool:
            return False

    cleanup_started: list[bool] = []

    def cleanup(**kwargs) -> None:  # type: ignore[no-untyped-def]
        cleanup_started.append(kwargs["server_thread_started"])

    monkeypatch.setattr(mobile_module, "_FixtureServer", lambda *_args: Server())
    monkeypatch.setattr(mobile_module, "Thread", DeadThread)
    monkeypatch.setattr(mobile_module, "_cleanup_physical_android", cleanup)
    monkeypatch.setattr(
        mobile_module,
        "_run_adb",
        lambda *_args, **_kwargs: pytest.fail("ADB ran without a fixture server"),
    )
    with pytest.raises(ContractError, match="fixture server worker did not start"):
        mobile_module.probe_physical_android()
    assert cleanup_started == [True]


def test_physical_fixture_shutdown_retires_an_active_client() -> None:
    entered = threading.Event()

    class Handler(mobile_module._FixtureHandler):
        def setup(self) -> None:
            super().setup()
            entered.set()

    server = mobile_module._FixtureServer(("127.0.0.1", 0), Handler)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    client = None
    try:
        client = socket.create_connection(server.server_address, timeout=1)
        client.settimeout(1)
        client.sendall(b"GET / HTTP/1.1\r\nHost: localhost\r\n")
        assert entered.wait(1)
        assert mobile_module._stop_fixture_server(server, worker, started=True) == []
        try:
            closed = client.recv(1)
        except TimeoutError:
            pytest.fail("physical fixture left an active client open after shutdown")
        except OSError:
            pass
        else:
            assert closed == b""
    finally:
        if client is not None:
            client.close()
        server.server_close()
        worker.join(timeout=1)


def _runtime_observation() -> dict:
    return {
        "title": mobile_module.ANDROID_TITLE,
        "userAgent": "Mozilla/5.0 Android Mobile",
        "platform": "Linux armv8l",
        "languages": ["en-US", "en"],
        "maxTouchPoints": 5,
        "hardwareConcurrency": 8,
        "innerWidth": 412,
        "innerHeight": 915,
        "screenWidth": 412,
        "screenHeight": 915,
        "devicePixelRatio": 2.625,
        "timezone": "America/Chicago",
        "intlLocale": "en-US",
        "coarsePointer": True,
        "webglIdentitySchema": "webgl2-preferred-unmasked-v1",
        "webglVendor": "WebKit",
        "webglRenderer": "GPU",
        "webglVersion": "WebGL 1.0",
    }


def test_physical_mobile_registry_is_explicit_and_redacted() -> None:
    capabilities = {item["id"]: item for item in discover_physical_mobile()}
    assert set(capabilities) == {"physical-android-adb", "physical-ios"}
    assert capabilities["physical-ios"]["available"] is False
    assert capabilities["physical-ios"]["realization"] == "physical-device"
    android = capabilities["physical-android-adb"]
    assert isinstance(android["available"], bool)
    if android["available"]:
        device = android["device"]
        assert set(device) == {
            "serial_sha256_16",
            "model",
            "os_version",
            "sdk",
            "architecture",
            "browser",
            "browser_version",
        }
        assert re.fullmatch(r"[0-9a-f]{16}", device["serial_sha256_16"])
    else:
        assert android["unavailable_reason"]


def test_adb_command_is_output_bounded_and_serial_selected(monkeypatch) -> None:
    calls = []
    monkeypatch.setattr(mobile_module, "_adb_path", lambda: "adb.exe")

    def fake_run(command, **kwargs):  # noqa: ANN001
        calls.append((command, kwargs))
        return BoundedProcessResult(returncode=0, stdout=b"Pixel 9\n")

    monkeypatch.setattr(mobile_module, "run_with_bounded_stdout", fake_run)
    assert (
        mobile_module._run_adb(
            ["shell", "getprop", "ro.product.model"], serial="SERIAL-1"
        )
        == "Pixel 9"
    )
    command, kwargs = calls[0]
    assert command == [
        "adb.exe",
        "-s",
        "SERIAL-1",
        "shell",
        "getprop",
        "ro.product.model",
    ]
    assert kwargs["maximum_stdout"] == mobile_module.MAX_ADB_OUTPUT_BYTES


def test_adb_command_rejects_boolean_process_status(monkeypatch) -> None:
    monkeypatch.setattr(mobile_module, "_adb_path", lambda: "adb.exe")
    monkeypatch.setattr(
        mobile_module,
        "run_with_bounded_stdout",
        lambda *_args, **_kwargs: BoundedProcessResult(
            returncode=False,
            stdout=b"private-output",
        ),
    )

    with pytest.raises(ContractError, match="rejected") as failure:
        mobile_module._run_adb(["devices"])
    assert "private-output" not in str(failure.value)


def test_adb_command_rejects_non_utf8_argument_before_binary_discovery(
    monkeypatch,
) -> None:
    contacted = False

    def forbidden_path():
        nonlocal contacted
        contacted = True
        raise AssertionError("binary discovery")

    monkeypatch.setattr(mobile_module, "_adb_path", forbidden_path)
    with pytest.raises(ContractError, match="arguments"):
        mobile_module._run_adb(["shell", "\ud800"])
    assert contacted is False


@pytest.mark.parametrize("timeout", [True, "1", 0, -1, float("nan"), 121, 10**400])
def test_adb_timeout_fails_before_binary_discovery(monkeypatch, timeout) -> None:
    contacted = False

    def forbidden_path():
        nonlocal contacted
        contacted = True
        return "adb"

    monkeypatch.setattr(mobile_module, "_adb_path", forbidden_path)
    with pytest.raises(ContractError, match="timeout"):
        mobile_module._run_adb(["devices"], timeout_seconds=timeout)
    assert contacted is False


def test_android_discovery_binds_every_device_command_to_one_serial(
    monkeypatch,
) -> None:
    calls = []
    monkeypatch.setattr(mobile_module, "_adb_path", lambda: "adb")

    def fake_adb(arguments, *, timeout_seconds=10.0, serial=None):  # noqa: ANN001
        calls.append((tuple(arguments), serial))
        if arguments == ["devices"]:
            return "List of devices attached\nSERIAL-1\tdevice"
        if arguments[:3] == ["shell", "dumpsys", "package"]:
            return "  versionName=153.0.1.2"
        values = {
            "ro.product.model": "Pixel 9",
            "ro.build.version.release": "16",
            "ro.build.version.sdk": "36",
            "ro.product.cpu.abi": "arm64-v8a",
        }
        return values[arguments[-1]]

    monkeypatch.setattr(mobile_module, "_run_adb", fake_adb)
    capability, serial = mobile_module._discover_android_capability()
    assert capability["available"] is True
    assert serial == "SERIAL-1"
    assert calls[0] == (("devices",), None)
    assert all(selected == "SERIAL-1" for _arguments, selected in calls[1:])
    assert "SERIAL-1" not in json.dumps(capability)


def test_android_discovery_shares_one_deadline_across_adb_phases(monkeypatch) -> None:
    clock = iter([10.0, 10.2, 10.4, 10.6])
    timeouts = []
    monkeypatch.setattr(mobile_module.time, "monotonic", lambda: next(clock))
    monkeypatch.setattr(mobile_module, "_adb_path", lambda: "adb")

    def devices(*, timeout_seconds):  # noqa: ANN001
        timeouts.append(("devices", timeout_seconds))
        return ["SERIAL-1"]

    def version(_serial, *, timeout_seconds):  # noqa: ANN001
        timeouts.append(("version", timeout_seconds))
        return "153.0"

    def prop(_serial, name, *, timeout_seconds):  # noqa: ANN001
        timeouts.append((name, timeout_seconds))
        return "value"

    monkeypatch.setattr(mobile_module, "_android_devices", devices)
    monkeypatch.setattr(mobile_module, "_android_chrome_version", version)
    monkeypatch.setattr(mobile_module, "_android_property", prop)
    with pytest.raises(ContractError, match="timed out"):
        mobile_module._discover_android_capability(deadline=10.5)
    assert [label for label, _timeout in timeouts] == [
        "devices",
        "version",
        "ro.product.model",
    ]
    assert [timeout for _label, timeout in timeouts] == pytest.approx([0.5, 0.3, 0.1])


def test_android_device_inventory_is_capped(monkeypatch) -> None:
    monkeypatch.setattr(
        mobile_module,
        "_run_adb",
        lambda _arguments, **_kwargs: "List of devices attached\nA\tdevice\nB\tdevice",
    )
    monkeypatch.setattr(mobile_module, "MAX_ANDROID_DEVICES", 1)
    with pytest.raises(ContractError, match="device cap"):
        mobile_module._android_devices()


def test_android_inventory_ignores_offline_rows_after_active_device_cap(monkeypatch) -> None:
    monkeypatch.setattr(
        mobile_module,
        "_run_adb",
        lambda _arguments, **_kwargs: (
            "List of devices attached\nSERIAL-1\tdevice\nSERIAL-2\toffline"
        ),
    )
    monkeypatch.setattr(mobile_module, "MAX_ANDROID_DEVICES", 1)

    assert mobile_module._android_devices() == ["SERIAL-1"]


def test_android_inventory_does_not_split_unicode_line_separators(monkeypatch) -> None:
    monkeypatch.setattr(
        mobile_module,
        "_run_adb",
        lambda _arguments, **_kwargs: "List of devices attached\nSERIAL\u2028FAKE\tdevice",
    )

    assert mobile_module._android_devices() == []


def test_android_inventory_does_not_strip_unicode_separator_before_newline(
    monkeypatch,
) -> None:
    monkeypatch.setattr(
        mobile_module,
        "_run_adb",
        lambda _arguments, **_kwargs: "List of devices attached\nSERIAL-1\tdevice\u2028\n",
    )

    assert mobile_module._android_devices() == []


def test_adb_output_does_not_strip_unicode_separator_at_eof(monkeypatch) -> None:
    monkeypatch.setattr(mobile_module, "_adb_path", lambda: "adb.exe")
    monkeypatch.setattr(
        mobile_module,
        "run_with_bounded_stdout",
        lambda *_args, **_kwargs: BoundedProcessResult(
            returncode=0,
            stdout="List of devices attached\nSERIAL-1\tdevice\u2028".encode("utf-8"),
        ),
    )

    assert mobile_module._android_devices() == []


def test_android_chrome_version_reads_crlf_physical_lines(monkeypatch) -> None:
    monkeypatch.setattr(
        mobile_module,
        "_run_adb",
        lambda _arguments, **_kwargs: (
            "Package info\r\n  versionName=153.0.1.2\r\nother field\r\n"
        ),
    )

    assert mobile_module._android_chrome_version("SERIAL-1") == "153.0.1.2"


def test_android_chrome_version_does_not_consume_unicode_line_separator(
    monkeypatch,
) -> None:
    monkeypatch.setattr(
        mobile_module,
        "_run_adb",
        lambda _arguments, **_kwargs: "\u2028versionName=153.0.1.2",
    )

    assert mobile_module._android_chrome_version("SERIAL-1") is None


def test_android_inventory_caps_physical_lines(monkeypatch) -> None:
    monkeypatch.setattr(
        mobile_module,
        "_run_adb",
        lambda _arguments, **_kwargs: (
            "List of devices attached\nSERIAL-1\tdevice\nSERIAL-2\toffline"
        ),
    )
    monkeypatch.setattr(mobile_module, "MAX_ANDROID_DEVICE_LINES", 2)

    with pytest.raises(ContractError, match="physical line cap"):
        mobile_module._android_devices()


def test_android_property_rejects_non_string_before_adb(monkeypatch) -> None:
    contacted = False

    def forbidden_adb(*_args, **_kwargs):
        nonlocal contacted
        contacted = True
        raise AssertionError("ADB")

    monkeypatch.setattr(mobile_module, "_run_adb", forbidden_adb)
    with pytest.raises(ContractError, match="property name"):
        mobile_module._android_property("SERIAL-1", ["ro.product.model"])  # type: ignore[arg-type]
    assert contacted is False


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (lambda value: value.__setitem__("unexpected", True), "fields"),
        (lambda value: value.__setitem__("devicePixelRatio", True), "numeric"),
        (lambda value: value.__setitem__("devicePixelRatio", 10**400), "numeric"),
        (lambda value: value.__setitem__("maxTouchPoints", 2.5), "numeric"),
        (lambda value: value.__setitem__("hardwareConcurrency", 8.5), "numeric"),
        (lambda value: value.__setitem__("innerWidth", 412.5), "numeric"),
        (lambda value: value.__setitem__("screenHeight", 915.5), "numeric"),
        (lambda value: value.__setitem__("languages", [{}]), "languages"),
        (lambda value: value.__setitem__("coarsePointer", "true"), "pointer"),
    ],
)
def test_android_runtime_observation_is_closed_and_typed(mutation, message) -> None:
    observed = _runtime_observation()
    mutation(observed)
    with pytest.raises(ContractError, match=message):
        mobile_module._strict_json_object(json.dumps(observed))


def test_android_runtime_observation_rejects_nonstandard_json_numbers() -> None:
    body = json.dumps(_runtime_observation()).replace("2.625", "NaN")
    with pytest.raises(ContractError, match="invalid"):
        mobile_module._strict_json_object(body)


def test_android_runtime_observation_rejects_duplicate_json_members() -> None:
    body = json.dumps(_runtime_observation(), separators=(",", ":")).replace(
        '"title":"browser-core-physical-android-ok",',
        '"title":"browser-core-physical-android-ok",' '"title":"private-title",',
        1,
    )
    with pytest.raises(ContractError, match="invalid") as failure:
        mobile_module._strict_json_object(body)
    assert "private-title" not in str(failure.value)


def test_android_runtime_observation_rejects_surrogate_text() -> None:
    observed = _runtime_observation()
    observed["webglRenderer"] = "\ud800"
    with pytest.raises(ContractError, match="observation is invalid"):
        mobile_module._strict_json_object(json.dumps(observed))


@pytest.mark.parametrize(
    "response",
    [
        None,
        {"error": {"message": "private"}},
        {
            "result": {
                "exceptionDetails": {},
                "result": {"type": "string", "value": "{}"},
            }
        },
        {"result": {"result": {"type": "object", "value": "{}"}}},
        {"result": {"result": {"type": "string"}}},
        {"result": {"result": {"type": "string", "value": b"{}"}}},
    ],
)
def test_physical_runtime_value_rejects_error_and_wrong_remote_shapes(response) -> None:
    with pytest.raises(ContractError, match="runtime observation") as raised:
        mobile_module._physical_runtime_value(response)
    assert "private" not in str(raised.value)


def test_devtools_target_inventory_is_byte_bounded(monkeypatch) -> None:
    class Response:
        status = 200

        def __init__(self):
            self.closed = False

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def close(self):
            self.closed = True

        def read(self, _maximum):
            return b"x" * (mobile_module.MAX_DEVTOOLS_TARGET_BYTES + 1)

    monkeypatch.setattr(
        mobile_module, "_open_devtools_http_url", lambda *_a, **_k: Response()
    )
    with pytest.raises(ContractError, match="byte limit"):
        mobile_module._wait_for_owned_target(
            "http://127.0.0.1:9222",
            "http://127.0.0.1:8000/",
            1.0,
        )


def test_devtools_inventory_stays_on_exact_loopback_origin(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target_hits: list[str] = []

    class Target(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            target_hits.append(self.path)
            self.send_response(200)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"[]")

        def log_message(self, *_args: object) -> None:
            pass

    target = ThreadingHTTPServer(("127.0.0.1", 0), Target)

    class Redirect(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            self.send_response(302)
            self.send_header(
                "Location", f"http://127.0.0.1:{target.server_port}/json/list"
            )
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, *_args: object) -> None:
            pass

    source = ThreadingHTTPServer(("127.0.0.1", 0), Redirect)
    proxy_url = f"http://127.0.0.1:{target.server_port}"
    monkeypatch.setenv("http_proxy", proxy_url)
    monkeypatch.setenv("HTTP_PROXY", proxy_url)
    monkeypatch.setenv("no_proxy", "")
    monkeypatch.setattr(urllib.request, "proxy_bypass", lambda _host: False)
    source_thread = threading.Thread(target=source.serve_forever, daemon=True)
    target_thread = threading.Thread(target=target.serve_forever, daemon=True)
    source_thread.start()
    target_thread.start()
    try:
        with pytest.raises(ContractError, match="inventory status is invalid"):
            mobile_module._read_devtools_targets(
                f"http://127.0.0.1:{source.server_port}", timeout_seconds=2
            )
        assert target_hits == []
    finally:
        source.shutdown()
        target.shutdown()
        source.server_close()
        target.server_close()
        source_thread.join(timeout=2)
        target_thread.join(timeout=2)


@pytest.mark.parametrize(
    "url",
    [
        "https://127.0.0.1:9222/json/list",
        "http://192.0.2.1:9222/json/list",
        "file:///tmp/local.json",
        "http://127.0.0.1:9222/json/other",
        "http://127.0.0.1:9222/json/list?private=value",
        "http://127.0.0.1:9222/json/close/%2f",
    ],
)
def test_devtools_http_reader_rejects_nonowned_url_before_contact(
    monkeypatch: pytest.MonkeyPatch, url: str
) -> None:
    monkeypatch.setattr(
        mobile_module,
        "_open_devtools_http_url",
        lambda *_args, **_kwargs: pytest.fail("nonowned DevTools URL reached network"),
    )
    with pytest.raises(ContractError, match="HTTP URL is invalid"):
        mobile_module._read_devtools_http_response(
            url, timeout_seconds=1, maximum=1024
        )


def test_devtools_http_reader_closes_rejected_http_response(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    body = io.BytesIO(b"private redirect body")
    error = HTTPError(
        "http://127.0.0.1:9222/json/list", 302, "redirect", {}, body
    )

    def reject(*_args: object, **_kwargs: object) -> None:
        raise error

    monkeypatch.setattr(mobile_module, "_open_devtools_http_url", reject)
    with pytest.raises(ContractError, match="inventory status is invalid"):
        mobile_module._read_devtools_targets(
            "http://127.0.0.1:9222", timeout_seconds=1
        )
    assert body.closed


def test_devtools_http_reader_stops_fragmented_body_at_deadline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = [0.0]
    monkeypatch.setattr(
        mobile_module, "time", SimpleNamespace(monotonic=lambda: clock[0])
    )

    class Response:
        status = 200

        def __init__(self) -> None:
            self.closed = False

        def read(self, _maximum: int) -> bytes:
            pytest.fail("aggregate read can outlive the response deadline")

        def read1(self, _maximum: int) -> bytes:
            clock[0] += 0.06
            return b"x"

        def close(self) -> None:
            self.closed = True

    response = Response()
    monkeypatch.setattr(
        mobile_module, "_open_devtools_http_url", lambda *_a, **_k: response
    )
    with pytest.raises(ContractError, match="deadline"):
        mobile_module._read_devtools_http_response(
            "http://127.0.0.1:9222/json/list",
            timeout_seconds=0.1,
            maximum=1024,
        )
    assert response.closed


def test_devtools_http_reader_rejects_complete_json_in_short_declared_body(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Response:
        status = 200

        def __init__(self) -> None:
            self.length = 4
            self.sent = False
            self.closed = False

        def read1(self, _maximum: int) -> bytes:
            if self.sent:
                return b""
            self.sent = True
            self.length -= 2
            return b"[]"

        def close(self) -> None:
            self.closed = True

    response = Response()
    monkeypatch.setattr(
        mobile_module, "_open_devtools_http_url", lambda *_a, **_k: response
    )

    with pytest.raises(ContractError, match="declared length"):
        mobile_module._read_devtools_http_response(
            "http://127.0.0.1:9222/json/list", timeout_seconds=1, maximum=1024
        )
    assert response.closed


def test_devtools_http_reader_rejects_cleanup_after_deadline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = [0.0]
    monkeypatch.setattr(
        mobile_module, "time", SimpleNamespace(monotonic=lambda: clock[0])
    )

    class Response:
        status = 200
        closed = False

        def read(self, _maximum: int) -> bytes:
            return b"[]"

        def close(self) -> None:
            self.closed = True
            clock[0] = 2.0

    response = Response()
    monkeypatch.setattr(
        mobile_module, "_open_devtools_http_url", lambda *_a, **_k: response
    )
    with pytest.raises(ContractError, match="deadline"):
        mobile_module._read_devtools_http_response(
            "http://127.0.0.1:9222/json/list",
            timeout_seconds=1.0,
            maximum=1024,
        )
    assert response.closed


def test_devtools_target_inventory_rejects_duplicate_json_members(monkeypatch) -> None:
    class Response:
        status = 200

        def __init__(self):
            self.closed = False

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def close(self):
            self.closed = True

        def read(self, _maximum):
            return b'[{"type":"page","type":"private"}]'

    monkeypatch.setattr(
        mobile_module,
        "_open_devtools_http_url",
        lambda *_args, **_kwargs: Response(),
    )
    with pytest.raises(ContractError, match="inventory is invalid") as failure:
        mobile_module._wait_for_owned_target(
            "http://127.0.0.1:9222",
            "http://127.0.0.1:8000/",
            1.0,
        )
    assert "private" not in str(failure.value)


def test_devtools_target_wait_clips_request_and_sleep_to_deadline(monkeypatch) -> None:
    request_timeouts = []

    def unavailable(*_args, **kwargs):
        request_timeouts.append(kwargs["timeout"])
        raise OSError("not ready")

    monkeypatch.setattr(mobile_module, "_open_devtools_http_url", unavailable)
    started = time.monotonic()
    with pytest.raises(ContractError, match="did not appear"):
        mobile_module._wait_for_owned_target(
            "http://127.0.0.1:9222",
            "http://127.0.0.1:8000/",
            0.01,
        )
    elapsed = time.monotonic() - started
    assert request_timeouts
    assert max(request_timeouts) <= 0.011
    assert elapsed < 0.2


def test_devtools_target_wait_rejects_inventory_returned_after_deadline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = [0.0]
    monkeypatch.setattr(
        mobile_module, "time", SimpleNamespace(monotonic=lambda: clock[0])
    )
    target_url = "http://127.0.0.1:8000/"

    def late_inventory(*_args: object, **_kwargs: object) -> list[dict[str, str]]:
        clock[0] = 2.0
        return [{
            "id": "owned-target",
            "type": "page",
            "url": target_url,
            "title": mobile_module.ANDROID_TITLE,
        }]

    monkeypatch.setattr(mobile_module, "_read_devtools_targets", late_inventory)
    with pytest.raises(ContractError, match="did not appear"):
        mobile_module._wait_for_owned_target(
            "http://127.0.0.1:9222", target_url, 1.0
        )


def test_devtools_target_wait_rejects_duplicate_exact_owned_urls(
    monkeypatch,
) -> None:
    target_url = "http://127.0.0.1:8000/"
    targets = [
        {
            "id": "owned-target",
            "type": "page",
            "url": target_url,
            "title": mobile_module.ANDROID_TITLE,
        },
        {
            "id": "competitor-target",
            "type": "page",
            "url": target_url,
            "title": "private competitor title",
        },
    ]

    class Response:
        status = 200

        def __init__(self):
            self.closed = False

        def __enter__(self):
            raise AssertionError("implicit response context must not be entered")

        def read(self, _maximum):
            return json.dumps(targets).encode("utf-8")

        def close(self):
            self.closed = True

    response = Response()
    monkeypatch.setattr(
        mobile_module,
        "_open_devtools_http_url",
        lambda *_args, **_kwargs: response,
    )
    with pytest.raises(ContractError) as raised:
        mobile_module._wait_for_owned_target(
            "http://127.0.0.1:9222",
            target_url,
            1.0,
        )
    assert str(raised.value) == (
        "physical Android target inventory has multiple exact owned URLs"
    )
    assert response.closed is True
    assert "private" not in str(raised.value)


def test_devtools_target_inventory_close_failure_blocks_valid_data(
    monkeypatch,
) -> None:
    class Response:
        def read(self, _maximum):
            return b"[]"

        def close(self):
            raise OSError("private DevTools close diagnostic")

    monkeypatch.setattr(
        mobile_module,
        "_open_devtools_http_url",
        lambda *_args, **_kwargs: Response(),
    )
    with pytest.raises(ContractError) as raised:
        mobile_module._read_devtools_targets(
            "http://127.0.0.1:9222",
            timeout_seconds=1.0,
        )
    assert str(raised.value) == ("Chrome DevTools HTTP cleanup failed (response-close)")
    assert raised.value.__cause__ is None
    assert "private" not in str(raised.value)


@pytest.mark.parametrize("status", [None, True, "200", 199, 201, 206, 300, 503])
def test_devtools_target_inventory_requires_success_status(
    monkeypatch: pytest.MonkeyPatch, status
) -> None:
    class Response:
        def __init__(self) -> None:
            self.status = status
            self.closed = False

        def read(self, _maximum):
            return b"[]"

        def close(self):
            self.closed = True

    response = Response()
    monkeypatch.setattr(
        mobile_module,
        "_open_devtools_http_url",
        lambda *_args, **_kwargs: response,
    )
    with pytest.raises(ContractError, match="inventory status is invalid"):
        mobile_module._read_devtools_targets(
            "http://127.0.0.1:9222",
            timeout_seconds=1.0,
        )
    assert response.closed is True


@pytest.mark.parametrize("phase", ["open", "read"])
def test_devtools_http_response_normalizes_private_transport_failures(
    monkeypatch: pytest.MonkeyPatch, phase: str
) -> None:
    private = "private DevTools adapter diagnostic"

    class Response:
        def __init__(self) -> None:
            self.closed = False

        def read(self, _maximum):
            raise OSError(private)

        def close(self):
            self.closed = True

    response = Response()

    def open_response(*_args, **_kwargs):
        if phase == "open":
            raise OSError(private)
        return response

    monkeypatch.setattr(mobile_module, "_open_devtools_http_url", open_response)
    with pytest.raises(
        ContractError, match=r"HTTP response failed \(OSError\)"
    ) as failure:
        mobile_module._read_devtools_http_response(
            "http://127.0.0.1:9222/json/list",
            timeout_seconds=1.0,
            maximum=1024,
        )
    assert private not in str(failure.value)
    assert response.closed is (phase == "read")


@pytest.mark.parametrize(
    ("url", "timeout", "maximum", "message"),
    [
        (None, 1.0, 1024, "URL"),
        ("http://127.0.0.1:9222/\nprivate", 1.0, 1024, "URL"),
        ("http://127.0.0.1:9222/json/list", True, 1024, "timeout"),
        ("http://127.0.0.1:9222/json/list", float("nan"), 1024, "timeout"),
        ("http://127.0.0.1:9222/json/list", 10**400, 1024, "timeout"),
        ("http://127.0.0.1:9222/json/list", 1.0, True, "byte limit"),
        ("http://127.0.0.1:9222/json/list", 1.0, "1024", "byte limit"),
    ],
)
def test_devtools_http_response_validates_controls_before_contact(
    monkeypatch: pytest.MonkeyPatch,
    url,
    timeout,
    maximum,
    message,
) -> None:
    monkeypatch.setattr(
        mobile_module,
        "_open_devtools_http_url",
        lambda *_args, **_kwargs: pytest.fail("invalid controls reached DevTools"),
    )
    with pytest.raises(ContractError, match=message):
        mobile_module._read_devtools_http_response(
            url,
            timeout_seconds=timeout,
            maximum=maximum,
        )


@pytest.mark.parametrize(
    ("operation", "message"),
    [
        ("inventory", "inventory timeout"),
        ("wait", "target wait"),
        ("close", "target close"),
    ],
)
def test_devtools_operations_reject_huge_timeout_before_contact(
    monkeypatch: pytest.MonkeyPatch,
    operation: str,
    message: str,
) -> None:
    monkeypatch.setattr(
        mobile_module,
        "_open_devtools_http_url",
        lambda *_args, **_kwargs: pytest.fail("invalid timeout reached DevTools"),
    )
    if operation == "inventory":
        call = lambda: mobile_module._read_devtools_targets(  # noqa: E731
            "http://127.0.0.1:9222", timeout_seconds=10**400
        )
    elif operation == "wait":
        call = lambda: mobile_module._wait_for_owned_target(  # noqa: E731
            "http://127.0.0.1:9222",
            "http://127.0.0.1:8000/",
            10**400,
        )
    else:
        call = lambda: mobile_module._ensure_owned_target_closed(  # noqa: E731
            "http://127.0.0.1:9222",
            "owned-target",
            10**400,
        )
    with pytest.raises(ContractError, match=message):
        call()


@pytest.mark.parametrize(
    "target_url",
    [
        "https://127.0.0.1:8000/",
        "http://localhost:8000/",
        "http://127.0.0.1:8000/private",
        "http://127.0.0.1:8000/?token=private",
    ],
)
def test_devtools_target_wait_rejects_non_owned_url_before_contact(
    monkeypatch,
    target_url,
) -> None:
    contacted = False

    def forbidden(*_args, **_kwargs):
        nonlocal contacted
        contacted = True
        raise AssertionError("DevTools contact")

    monkeypatch.setattr(mobile_module, "_open_devtools_http_url", forbidden)
    with pytest.raises(ContractError, match="target wait"):
        mobile_module._wait_for_owned_target(
            "http://127.0.0.1:9222",
            target_url,
            1.0,
        )
    assert contacted is False


def test_owned_target_close_requires_confirmed_inventory_absence(monkeypatch) -> None:
    inventories = iter(
        [
            [{"id": "target:1"}],
            [{"id": "target:1"}],
            [],
        ]
    )
    monkeypatch.setattr(
        mobile_module,
        "_read_devtools_targets",
        lambda *_args, **_kwargs: next(inventories),
    )
    close_calls = []

    class Response:
        status = 200

        def __init__(self):
            self.closed = False

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def close(self):
            self.closed = True

        def read(self, maximum):
            assert maximum == mobile_module.MAX_DEVTOOLS_CLOSE_BYTES + 1
            return b"Target is closing"

    def close_target(url, **kwargs):  # noqa: ANN001
        close_calls.append((url, kwargs))
        return Response()

    monkeypatch.setattr(mobile_module, "_open_devtools_http_url", close_target)
    mobile_module._ensure_owned_target_closed(
        "http://127.0.0.1:9222",
        "target:1",
        1.0,
    )
    assert close_calls[0][0].endswith("/json/close/target%3A1")


def test_owned_target_close_rejects_late_absence_inventory(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = [0.0]
    monkeypatch.setattr(
        mobile_module, "time", SimpleNamespace(monotonic=lambda: clock[0])
    )

    def late_inventory(*_args: object, **_kwargs: object) -> list[dict[str, str]]:
        clock[0] = 2.0
        return []

    monkeypatch.setattr(mobile_module, "_read_devtools_targets", late_inventory)
    with pytest.raises(ContractError, match="did not close"):
        mobile_module._ensure_owned_target_closed(
            "http://127.0.0.1:9222", "owned-target", 1.0
        )


@pytest.mark.parametrize("status", [201, 206])
def test_owned_target_close_rejects_noncomplete_http_status(
    monkeypatch: pytest.MonkeyPatch, status: int
) -> None:
    inventory_calls = [0]

    def inventory(*_args: object, **_kwargs: object) -> list[dict[str, str]]:
        inventory_calls[0] += 1
        return [{"id": "target-1"}] if inventory_calls[0] == 1 else []

    monkeypatch.setattr(mobile_module, "_read_devtools_targets", inventory)
    monkeypatch.setattr(
        mobile_module,
        "_read_devtools_http_response",
        lambda *_args, **_kwargs: (status, b"Target is closing"),
    )
    with pytest.raises(ContractError, match="target close response is invalid"):
        mobile_module._ensure_owned_target_closed(
            "http://127.0.0.1:9222", "target-1", 1.0
        )
    assert inventory_calls == [1]


def test_owned_target_close_rejects_unbounded_response(monkeypatch) -> None:
    monkeypatch.setattr(
        mobile_module,
        "_read_devtools_targets",
        lambda *_args, **_kwargs: [{"id": "target-1"}],
    )

    class Response:
        status = 200

        def __init__(self):
            self.closed = False

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def close(self):
            self.closed = True

        def read(self, _maximum):
            return b"x" * (mobile_module.MAX_DEVTOOLS_CLOSE_BYTES + 1)

    monkeypatch.setattr(
        mobile_module,
        "_open_devtools_http_url",
        lambda *_args, **_kwargs: Response(),
    )
    with pytest.raises(ContractError, match="byte limit"):
        mobile_module._ensure_owned_target_closed(
            "http://127.0.0.1:9222",
            "target-1",
            1.0,
        )


def test_owned_target_close_cleanup_failure_blocks_absence_poll(monkeypatch) -> None:
    inventory_calls = 0

    def inventory(*_args, **_kwargs):
        nonlocal inventory_calls
        inventory_calls += 1
        return [{"id": "target-1"}]

    monkeypatch.setattr(mobile_module, "_read_devtools_targets", inventory)

    class Response:
        status = 200

        def read(self, _maximum):
            return b"Target is closing"

        def close(self):
            raise RuntimeError("private close response diagnostic")

    monkeypatch.setattr(
        mobile_module,
        "_open_devtools_http_url",
        lambda *_args, **_kwargs: Response(),
    )
    with pytest.raises(ContractError) as raised:
        mobile_module._ensure_owned_target_closed(
            "http://127.0.0.1:9222",
            "target-1",
            1.0,
        )
    assert str(raised.value) == ("Chrome DevTools HTTP cleanup failed (response-close)")
    assert inventory_calls == 1
    assert "private" not in str(raised.value)


@pytest.mark.parametrize("timeout", [float("inf"), 10**400])
def test_probe_timeout_fails_before_device_discovery(monkeypatch, timeout) -> None:
    contacted = False

    def forbidden_discovery(**_kwargs):
        nonlocal contacted
        contacted = True
        raise AssertionError("device discovery")

    monkeypatch.setattr(
        mobile_module, "_discover_android_capability", forbidden_discovery
    )
    with pytest.raises(ContractError, match="timeout"):
        mobile_module.probe_physical_android(timeout_seconds=timeout)
    assert contacted is False


def test_probe_does_not_remove_a_reverse_mapping_it_failed_to_create(
    monkeypatch,
) -> None:
    capability = {
        "available": True,
        "device": {"serial_sha256_16": "1" * 16},
    }
    calls = []
    monkeypatch.setattr(
        mobile_module,
        "_discover_android_capability",
        lambda **_kwargs: (capability, "SERIAL-1"),
    )

    def fail_reverse(arguments, **kwargs):  # noqa: ANN001
        calls.append((arguments, kwargs))
        raise ContractError("occupied mapping")

    monkeypatch.setattr(mobile_module, "_run_adb", fail_reverse)
    with pytest.raises(ContractError, match="occupied mapping"):
        mobile_module.probe_physical_android(timeout_seconds=1)
    assert len(calls) == 1
    assert "--remove" not in calls[0][0]


def _install_successful_probe_fakes(monkeypatch, adb):  # noqa: ANN001
    capability = {
        "available": True,
        "device": {"serial_sha256_16": "1" * 16},
    }
    monkeypatch.setattr(
        mobile_module,
        "_discover_android_capability",
        lambda **_kwargs: (capability, "SERIAL-1"),
    )
    monkeypatch.setattr(mobile_module, "_run_adb", adb)
    monkeypatch.setattr(
        mobile_module,
        "_wait_for_owned_target",
        lambda *_args, **_kwargs: {
            "id": "target-1",
            "webSocketDebuggerUrl": "ws://127.0.0.1:9222/devtools/page/target-1",
        },
    )
    monkeypatch.setattr(
        mobile_module,
        "_validate_websocket_url",
        lambda _endpoint, value: value,
    )
    monkeypatch.setattr(
        mobile_module,
        "_websocket_json_command",
        lambda *_args, **_kwargs: {
            "result": {
                "result": {
                    "type": "string",
                    "value": json.dumps(_runtime_observation()),
                }
            }
        },
    )
    monkeypatch.setattr(
        mobile_module,
        "_ensure_owned_target_closed",
        lambda *_args, **_kwargs: None,
    )


def test_probe_rejects_a_unicode_adb_forward_port(monkeypatch) -> None:
    calls = []

    def adb(arguments, **_kwargs):  # noqa: ANN001
        calls.append(tuple(arguments))
        if arguments[:2] == ["forward", "--no-rebind"]:
            return "٩٢٢٢"
        return ""

    _install_successful_probe_fakes(monkeypatch, adb)
    with pytest.raises(ContractError, match="invalid Chrome DevTools forward port"):
        mobile_module.probe_physical_android(timeout_seconds=1)
    assert any(call[:2] == ("reverse", "--remove") for call in calls)


def test_probe_refuses_a_socket_for_a_different_page_target(monkeypatch) -> None:
    def adb(arguments, **_kwargs):  # noqa: ANN001
        if arguments[:2] == ["forward", "--no-rebind"]:
            return "9222"
        return ""

    _install_successful_probe_fakes(monkeypatch, adb)
    monkeypatch.setattr(
        mobile_module,
        "_wait_for_owned_target",
        lambda *_args, **_kwargs: {
            "id": "target-1",
            "webSocketDebuggerUrl": "ws://127.0.0.1:9222/devtools/page/other",
        },
    )
    monkeypatch.setattr(
        mobile_module,
        "_websocket_json_command",
        lambda *_args, **_kwargs: pytest.fail("mismatched page reached CDP"),
    )
    with pytest.raises(ContractError, match="target WebSocket"):
        mobile_module.probe_physical_android(timeout_seconds=1)


def test_probe_cleanup_failure_blocks_success_and_continues_teardown(
    monkeypatch,
) -> None:
    calls = []

    def adb(arguments, **_kwargs):  # noqa: ANN001
        calls.append(tuple(arguments))
        if arguments[:2] == ["forward", "--no-rebind"]:
            return "9222"
        if arguments[:2] == ["forward", "--remove"]:
            raise ContractError("private-forward-removal")
        return ""

    _install_successful_probe_fakes(monkeypatch, adb)
    with pytest.raises(
        ContractError, match=r"cleanup failed \(forward-remove\)"
    ) as failure:
        mobile_module.probe_physical_android(timeout_seconds=1)
    assert "private-forward-removal" not in str(failure.value)
    assert any(call[:2] == ("reverse", "--remove") for call in calls)


def test_probe_cannot_report_success_after_cleanup_deadline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = [0.0]
    monkeypatch.setattr(
        mobile_module, "time", SimpleNamespace(monotonic=lambda: clock[0])
    )

    def adb(arguments: list[str], **_kwargs: object) -> str:
        return "9222" if arguments[:2] == ["forward", "--no-rebind"] else ""

    _install_successful_probe_fakes(monkeypatch, adb)
    original_cleanup = mobile_module._cleanup_physical_android

    def late_cleanup(**kwargs: object) -> ContractError | None:
        result = original_cleanup(**kwargs)
        clock[0] = 2.0
        return result

    monkeypatch.setattr(mobile_module, "_cleanup_physical_android", late_cleanup)
    with pytest.raises(ContractError, match="timed out"):
        mobile_module.probe_physical_android(timeout_seconds=1.0)


def test_probe_failure_closes_discovered_target_before_unmapping(monkeypatch) -> None:
    events = []

    def adb(arguments, **_kwargs):  # noqa: ANN001
        if arguments[:2] == ["forward", "--no-rebind"]:
            return "9222"
        if "--remove" in arguments:
            events.append(tuple(arguments[:2]))
        return ""

    _install_successful_probe_fakes(monkeypatch, adb)
    monkeypatch.setattr(
        mobile_module,
        "_websocket_json_command",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            ContractError("runtime failed")
        ),
    )

    def close_target(*_args, **_kwargs):
        events.append(("target", "close"))

    monkeypatch.setattr(mobile_module, "_ensure_owned_target_closed", close_target)
    with pytest.raises(ContractError, match="runtime failed"):
        mobile_module.probe_physical_android(timeout_seconds=1)
    assert events[0] == ("target", "close")
    assert ("forward", "--remove") in events
    assert ("reverse", "--remove") in events
