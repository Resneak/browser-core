from __future__ import annotations

import hashlib
import io
import json
import re
import shutil
import subprocess
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
from typing import Any
from urllib.error import HTTPError
from urllib.parse import quote, unquote, urlsplit

from .bounded_process import run_with_bounded_stdout
from .cdp import (
    _validate_websocket_url,
    _websocket_json_command,
    urlopen as _open_devtools_http_url,
)
from .contracts import ContractError
from .control_files import decode_strict_json_bytes
from .http_deadline import (
    clamp_urllib_response_read_timeout,
    urllib_response_has_unread_declared_bytes,
)
from .local_http import LocalPanelServer
from .numeric import is_ascii_decimal, is_finite_number


PHYSICAL_CAPABILITY_SCHEMA = "browser-core.physical-mobile-capability/1"
PHYSICAL_PROBE_SCHEMA = "browser-core.physical-mobile-probe/1"
ANDROID_TITLE = "browser-core-physical-android-ok"
MAX_ADB_OUTPUT_BYTES = 1024 * 1024
MAX_DEVTOOLS_TARGET_BYTES = 512 * 1024
MAX_DEVTOOLS_CLOSE_BYTES = 64 * 1024
MAX_DEVTOOLS_HTTP_READ_CALLS = 65_536
MAX_ANDROID_DEVICES = 128
MAX_ANDROID_DEVICE_LINES = 4096
PHYSICAL_CLEANUP_TIMEOUT_SECONDS = 5.0
ADB_SERIAL_RE = re.compile(r"^[\x21-\x7e]{1,256}$")
TARGET_ID_RE = re.compile(r"^[A-Za-z0-9._:-]{1,256}$")


class _PhysicalProbeTimeout(ContractError):
    pass


class _DevToolsTransportError(ContractError):
    pass


def _remaining_probe_time(deadline: float, *, maximum: float = 120.0) -> float:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise _PhysicalProbeTimeout("physical Android probe timed out")
    return min(remaining, maximum)


def _utf8_size(value: str, *, error_message: str) -> int:
    try:
        return len(value.encode("utf-8", errors="strict"))
    except UnicodeEncodeError:
        raise ContractError(error_message) from None


def _adb_path() -> str | None:
    return shutil.which("adb")


def _run_adb(
    arguments: list[str],
    *,
    timeout_seconds: float = 10.0,
    serial: str | None = None,
) -> str:
    if not isinstance(arguments, list) or not 1 <= len(arguments) <= 64:
        raise ContractError("ADB arguments are invalid")
    for item in arguments:
        if (
            not isinstance(item, str)
            or not item
            or "\0" in item
            or _utf8_size(item, error_message="ADB arguments are invalid") > 4096
        ):
            raise ContractError("ADB arguments are invalid")
    if serial is not None and (
        not isinstance(serial, str) or not ADB_SERIAL_RE.fullmatch(serial)
    ):
        raise ContractError("ADB device selector is invalid")
    if not is_finite_number(timeout_seconds) or not 0 < timeout_seconds <= 120:
        raise ContractError("ADB timeout must be finite in (0, 120]")
    adb = _adb_path()
    if adb is None:
        raise ContractError("ADB is not installed")
    command = [adb]
    if serial is not None:
        command.extend(["-s", serial])
    command.extend(arguments)
    completed = run_with_bounded_stdout(
        command,
        maximum_stdout=MAX_ADB_OUTPUT_BYTES,
        timeout_seconds=float(timeout_seconds),
        label="ADB command",
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    if (
        isinstance(completed.returncode, bool)
        or not isinstance(completed.returncode, int)
        or completed.returncode != 0
    ):
        raise ContractError("ADB command was rejected")
    try:
        return completed.stdout.decode("utf-8", errors="strict").strip(" \t\r\n")
    except UnicodeDecodeError:
        raise ContractError("ADB command output encoding is invalid") from None


def _android_devices(*, timeout_seconds: float = 10.0) -> list[str]:
    output = _run_adb(["devices"], timeout_seconds=timeout_seconds)
    devices: list[str] = []
    found_header = False
    for number, line in enumerate(io.StringIO(output, newline=None), start=1):
        if number > MAX_ANDROID_DEVICE_LINES:
            raise ContractError("ADB device inventory exceeds the physical line cap")
        if not found_header:
            found_header = line.rstrip("\n") == "List of devices attached"
            continue
        serial, separator, state = line.strip(" \t\r\n").partition("\t")
        if separator and state == "device" and ADB_SERIAL_RE.fullmatch(serial):
            if len(devices) >= MAX_ANDROID_DEVICES:
                raise ContractError("ADB device inventory exceeds the device cap")
            devices.append(serial)
    if not found_header:
        raise ContractError("ADB device inventory is invalid")
    if len(devices) != len(set(devices)):
        raise ContractError("ADB device inventory contains duplicate serials")
    return devices


def _device_hash(serial: str) -> str:
    return hashlib.sha256(serial.encode("utf-8")).hexdigest()[:16]


def _android_property(
    serial: str,
    name: str,
    *,
    timeout_seconds: float = 10.0,
) -> str:
    if not isinstance(name, str) or not re.fullmatch(r"[a-z0-9._-]{1,128}", name):
        raise ContractError("Android property name is invalid")
    value = _run_adb(
        ["shell", "getprop", name],
        timeout_seconds=timeout_seconds,
        serial=serial,
    )
    if (
        not value
        or _utf8_size(value, error_message="Android property value is invalid") > 512
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise ContractError("Android property value is invalid")
    return value


def _android_chrome_version(
    serial: str,
    *,
    timeout_seconds: float = 20.0,
) -> str | None:
    output = _run_adb(
        ["shell", "dumpsys", "package", "com.android.chrome"],
        timeout_seconds=timeout_seconds,
        serial=serial,
    )
    for line in io.StringIO(output, newline=None):
        match = re.fullmatch(
            r"[ \t]*versionName=([A-Za-z0-9._+-]{1,128})",
            line.rstrip("\n"),
        )
        if match is not None:
            return match.group(1)
    return None


def _discover_android_capability(
    *,
    deadline: float | None = None,
) -> tuple[dict[str, Any], str | None]:
    android: dict[str, Any] = {
        "schema": PHYSICAL_CAPABILITY_SCHEMA,
        "id": "physical-android-adb",
        "platform": "android",
        "realization": "physical-device",
        "available": False,
        "adapter": "adb-chrome-devtools",
        "unavailable_reason": None,
        "device": None,
    }

    def discovery_timeout(maximum: float) -> float:
        if deadline is None:
            return maximum
        return _remaining_probe_time(deadline, maximum=maximum)

    selected_serial: str | None = None
    if _adb_path() is None:
        android["unavailable_reason"] = "ADB is not installed"
    else:
        try:
            devices = _android_devices(timeout_seconds=discovery_timeout(10.0))
            if len(devices) != 1:
                android["unavailable_reason"] = (
                    "no authorized ADB device is attached"
                    if not devices
                    else "multiple ADB devices are attached; an explicit safe selector is required"
                )
            else:
                selected_serial = devices[0]
                version = _android_chrome_version(
                    selected_serial,
                    timeout_seconds=discovery_timeout(20.0),
                )
                if version is None:
                    android["unavailable_reason"] = (
                        "Google Chrome is not installed on the attached device"
                    )
                else:
                    android["available"] = True
                    android["device"] = {
                        "serial_sha256_16": _device_hash(selected_serial),
                        "model": _android_property(
                            selected_serial,
                            "ro.product.model",
                            timeout_seconds=discovery_timeout(10.0),
                        ),
                        "os_version": _android_property(
                            selected_serial,
                            "ro.build.version.release",
                            timeout_seconds=discovery_timeout(10.0),
                        ),
                        "sdk": _android_property(
                            selected_serial,
                            "ro.build.version.sdk",
                            timeout_seconds=discovery_timeout(10.0),
                        ),
                        "architecture": _android_property(
                            selected_serial,
                            "ro.product.cpu.abi",
                            timeout_seconds=discovery_timeout(10.0),
                        ),
                        "browser": "Chrome",
                        "browser_version": version,
                    }
        except _PhysicalProbeTimeout:
            raise
        except ContractError as exc:
            android["available"] = False
            android["device"] = None
            android["unavailable_reason"] = (
                "ADB discovery failed; "
                + hashlib.sha256(
                    str(exc).encode("utf-8", errors="replace")
                ).hexdigest()[:16]
            )
            selected_serial = None
    return android, selected_serial


def discover_physical_mobile() -> list[dict[str, Any]]:
    android, _selected_serial = _discover_android_capability()
    ios = {
        "schema": PHYSICAL_CAPABILITY_SCHEMA,
        "id": "physical-ios",
        "platform": "ios",
        "realization": "physical-device",
        "available": False,
        "adapter": "none",
        "unavailable_reason": "no reviewed physical iOS adapter is configured on this Windows host",
        "device": None,
    }
    return [android, ios]


class _FixtureHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        if self.path != "/":
            self.send_error(404)
            return
        body = (
            "<!doctype html><meta charset=utf-8>"
            "<meta name=viewport content='width=device-width,initial-scale=1'>"
            f"<title>{ANDROID_TITLE}</title><main>Owned Browser Core Android probe</main>"
        ).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        return


class _FixtureServer(LocalPanelServer):
    daemon_threads = True


def _validated_devtools_endpoint(endpoint: str) -> str:
    if not isinstance(endpoint, str):
        raise ContractError("Chrome DevTools endpoint is invalid")
    try:
        parsed = urlsplit(endpoint)
        port = parsed.port
    except ValueError:
        raise ContractError("Chrome DevTools endpoint is invalid") from None
    if (
        parsed.scheme != "http"
        or parsed.hostname != "127.0.0.1"
        or parsed.username is not None
        or parsed.password is not None
        or port is None
        or not 1 <= port <= 65535
        or parsed.path
        or parsed.query
        or parsed.fragment
        or endpoint != f"http://127.0.0.1:{port}"
    ):
        raise ContractError("Chrome DevTools endpoint is invalid")
    return endpoint


def _validated_owned_target_url(target_url: str) -> str:
    if not isinstance(target_url, str):
        raise ContractError("physical Android target wait is invalid")
    try:
        parsed = urlsplit(target_url)
        port = parsed.port
    except ValueError:
        raise ContractError("physical Android target wait is invalid") from None
    if (
        parsed.scheme != "http"
        or parsed.hostname != "127.0.0.1"
        or parsed.username is not None
        or parsed.password is not None
        or port is None
        or not 1 <= port <= 65535
        or parsed.path != "/"
        or parsed.query
        or parsed.fragment
        or target_url != f"http://127.0.0.1:{port}/"
    ):
        raise ContractError("physical Android target wait is invalid")
    return target_url


def _validated_devtools_http_url(url: str) -> str:
    if (
        not isinstance(url, str)
        or not 1 <= len(url) <= 4096
        or any(ord(character) < 0x21 or ord(character) > 0x7E for character in url)
    ):
        raise ContractError("Chrome DevTools HTTP URL is invalid")
    try:
        parsed = urlsplit(url)
        port = parsed.port
    except ValueError:
        raise ContractError("Chrome DevTools HTTP URL is invalid") from None
    close_prefix = "/json/close/"
    close_target = parsed.path[len(close_prefix) :] if parsed.path.startswith(close_prefix) else ""
    decoded_target = unquote(close_target)
    valid_close = (
        bool(close_target)
        and TARGET_ID_RE.fullmatch(decoded_target) is not None
        and quote(decoded_target, safe="") == close_target
    )
    if (
        parsed.scheme != "http"
        or parsed.hostname != "127.0.0.1"
        or parsed.username is not None
        or parsed.password is not None
        or port is None
        or not 1 <= port <= 65535
        or parsed.path != "/json/list" and not valid_close
        or url != f"http://127.0.0.1:{port}{parsed.path}"
    ):
        raise ContractError("Chrome DevTools HTTP URL is invalid")
    return url


def _read_devtools_http_response(
    url: str,
    *,
    timeout_seconds: float,
    maximum: int,
) -> tuple[Any, Any]:
    url = _validated_devtools_http_url(url)
    if not is_finite_number(timeout_seconds) or not 0 < timeout_seconds <= 120:
        raise ContractError("Chrome DevTools HTTP timeout is invalid")
    if (
        isinstance(maximum, bool)
        or not isinstance(maximum, int)
        or not 1 <= maximum <= MAX_DEVTOOLS_TARGET_BYTES
    ):
        raise ContractError("Chrome DevTools HTTP byte limit is invalid")
    response: Any | None = None
    status: Any = None
    body: Any = None
    primary_error: BaseException | None = None
    try:
        deadline = time.monotonic() + float(timeout_seconds)
        response = _open_devtools_http_url(url, timeout=timeout_seconds)
        status = getattr(response, "status", None)
        reader = getattr(response, "read1", None)
        if callable(reader):
            parts = bytearray()
            for _ in range(MAX_DEVTOOLS_HTTP_READ_CALLS):
                if not clamp_urllib_response_read_timeout(
                    response, deadline - time.monotonic()
                ):
                    raise _DevToolsTransportError(
                        "Chrome DevTools HTTP response deadline exceeded"
                    )
                remaining = maximum + 1 - len(parts)
                try:
                    chunk = reader(remaining)
                except TimeoutError:
                    raise _DevToolsTransportError(
                        "Chrome DevTools HTTP response deadline exceeded"
                    ) from None
                if time.monotonic() > deadline:
                    raise _DevToolsTransportError(
                        "Chrome DevTools HTTP response deadline exceeded"
                    )
                if type(chunk) is not bytes or len(chunk) > remaining:
                    raise ContractError("Chrome DevTools HTTP body is invalid")
                parts.extend(chunk)
                if not chunk or len(parts) > maximum:
                    break
            else:
                raise ContractError("Chrome DevTools HTTP body has too many fragments")
            body = bytes(parts)
        else:
            if not clamp_urllib_response_read_timeout(
                response, deadline - time.monotonic()
            ):
                raise _DevToolsTransportError(
                    "Chrome DevTools HTTP response deadline exceeded"
                )
            try:
                body = response.read(maximum + 1)
            except TimeoutError:
                raise _DevToolsTransportError(
                    "Chrome DevTools HTTP response deadline exceeded"
                ) from None
            if time.monotonic() > deadline:
                raise _DevToolsTransportError(
                    "Chrome DevTools HTTP response deadline exceeded"
                )
        if (
            type(body) is bytes
            and len(body) <= maximum
            and urllib_response_has_unread_declared_bytes(response)
        ):
            raise ContractError(
                "Chrome DevTools HTTP response ended before declared length"
            )
    except HTTPError as exc:
        # The no-redirect opener returns rejected statuses as owned responses.
        # Preserve the status for the route validator and close the exact body.
        response = exc
        status = exc.code
        body = b""
    except BaseException as exc:
        primary_error = exc

    cleanup_error: ContractError | None = None
    if response is not None:
        try:
            response.close()
        except (AttributeError, OSError, RuntimeError, TypeError, ValueError):
            cleanup_error = ContractError(
                "Chrome DevTools HTTP cleanup failed (response-close)"
            )
    if cleanup_error is not None:
        if primary_error is not None and isinstance(
            primary_error,
            (AttributeError, OSError, RuntimeError, TypeError, ValueError),
        ):
            raise cleanup_error from ContractError(
                f"Chrome DevTools HTTP response failed ({type(primary_error).__name__})"
            )
        if primary_error is not None:
            raise cleanup_error from primary_error
        raise cleanup_error from None
    if primary_error is not None:
        if isinstance(primary_error, ContractError):
            raise primary_error
        if isinstance(
            primary_error,
            (AttributeError, OSError, RuntimeError, TypeError, ValueError),
        ):
            raise _DevToolsTransportError(
                "Chrome DevTools HTTP response failed "
                f"({type(primary_error).__name__})"
            ) from None
        raise primary_error
    if time.monotonic() >= deadline:
        raise _DevToolsTransportError(
            "Chrome DevTools HTTP response deadline exceeded"
        )
    return status, body


def _read_devtools_targets(
    endpoint: str,
    *,
    timeout_seconds: float,
) -> list[dict[str, Any]]:
    endpoint = _validated_devtools_endpoint(endpoint)
    if not is_finite_number(timeout_seconds) or not 0 < timeout_seconds <= 120:
        raise ContractError("Chrome DevTools inventory timeout is invalid")
    status, body = _read_devtools_http_response(
        endpoint + "/json/list",
        timeout_seconds=float(timeout_seconds),
        maximum=MAX_DEVTOOLS_TARGET_BYTES,
    )
    if (
        isinstance(status, bool)
        or not isinstance(status, int)
        or status != 200
    ):
        raise ContractError("Chrome DevTools target inventory status is invalid")
    if type(body) is not bytes:
        raise ContractError("Chrome DevTools target inventory is invalid")
    if len(body) > MAX_DEVTOOLS_TARGET_BYTES:
        raise ContractError("Chrome DevTools target inventory exceeds the byte limit")
    try:
        targets = decode_strict_json_bytes(
            body,
            label="Chrome DevTools target inventory",
        )
    except ContractError:
        raise ContractError("Chrome DevTools target inventory is invalid") from None
    if not isinstance(targets, list) or len(targets) > 1024:
        raise ContractError("Chrome DevTools target inventory is invalid")
    target_ids: set[str] = set()
    for item in targets:
        if not isinstance(item, dict):
            raise ContractError("Chrome DevTools target inventory is invalid")
        target_id = item.get("id")
        if not isinstance(target_id, str) or not TARGET_ID_RE.fullmatch(target_id):
            raise ContractError("Chrome DevTools target inventory is invalid")
        if target_id in target_ids:
            raise ContractError("Chrome DevTools target inventory is invalid")
        target_ids.add(target_id)
    return targets


def _poll_delay(deadline: float) -> None:
    remaining = deadline - time.monotonic()
    if remaining > 0:
        time.sleep(min(0.1, remaining))


def _wait_for_owned_target(
    endpoint: str,
    target_url: str,
    timeout_seconds: float,
) -> dict[str, Any]:
    endpoint = _validated_devtools_endpoint(endpoint)
    target_url = _validated_owned_target_url(target_url)
    if not is_finite_number(timeout_seconds) or not 0 < timeout_seconds <= 120:
        raise ContractError("physical Android target wait is invalid")
    deadline = time.monotonic() + float(timeout_seconds)
    while True:
        try:
            targets = _read_devtools_targets(
                endpoint,
                timeout_seconds=min(2.0, _remaining_probe_time(deadline)),
            )
            _remaining_probe_time(deadline)
            url_matches = [
                item
                for item in targets
                if item.get("type") == "page" and item.get("url") == target_url
            ]
            if len(url_matches) > 1:
                raise ContractError(
                    "physical Android target inventory has multiple exact owned URLs"
                )
            matches = [
                item for item in url_matches if item.get("title") == ANDROID_TITLE
            ]
            if len(matches) == 1:
                _remaining_probe_time(deadline)
                return matches[0]
        except _PhysicalProbeTimeout:
            break
        except _DevToolsTransportError:
            pass
        except ContractError:
            raise
        except (OSError, ValueError, json.JSONDecodeError):
            pass
        _poll_delay(deadline)
    raise ContractError(
        "physical Android owned fixture did not appear in Chrome DevTools"
    )


def _ensure_owned_target_closed(
    endpoint: str,
    target_id: str,
    timeout_seconds: float,
) -> None:
    endpoint = _validated_devtools_endpoint(endpoint)
    if (
        not isinstance(target_id, str)
        or not TARGET_ID_RE.fullmatch(target_id)
        or not is_finite_number(timeout_seconds)
        or not 0 < timeout_seconds <= 120
    ):
        raise ContractError("physical Android target close is invalid")
    deadline = time.monotonic() + float(timeout_seconds)

    def inventory() -> list[dict[str, Any]]:
        targets = _read_devtools_targets(
            endpoint,
            timeout_seconds=min(2.0, _remaining_probe_time(deadline)),
        )
        _remaining_probe_time(deadline)
        return targets

    while True:
        try:
            initial_targets = inventory()
            break
        except _PhysicalProbeTimeout:
            raise ContractError("physical Android owned target did not close") from None
        except (_DevToolsTransportError, OSError, ValueError):
            _poll_delay(deadline)
    if all(item["id"] != target_id for item in initial_targets):
        return
    request_timeout = min(5.0, _remaining_probe_time(deadline))
    try:
        status, body = _read_devtools_http_response(
            endpoint + "/json/close/" + quote(target_id, safe=""),
            timeout_seconds=request_timeout,
            maximum=MAX_DEVTOOLS_CLOSE_BYTES,
        )
    except _DevToolsTransportError:
        raise ContractError("physical Android target close request failed") from None
    except ContractError:
        raise
    except (OSError, ValueError):
        raise ContractError("physical Android target close request failed") from None
    if (
        isinstance(status, bool)
        or not isinstance(status, int)
        or status != 200
        or type(body) is not bytes
    ):
        raise ContractError("physical Android target close response is invalid")
    if len(body) > MAX_DEVTOOLS_CLOSE_BYTES:
        raise ContractError(
            "physical Android target close response exceeds the byte limit"
        )
    while True:
        try:
            if all(item["id"] != target_id for item in inventory()):
                return
        except _PhysicalProbeTimeout:
            break
        except (_DevToolsTransportError, OSError, ValueError, json.JSONDecodeError):
            pass
        _poll_delay(deadline)
    raise ContractError("physical Android owned target did not close")


def _strict_json_object(value: str) -> dict[str, Any]:
    if not isinstance(value, str):
        raise ContractError("physical Android runtime observation is invalid")
    try:
        document = decode_strict_json_bytes(
            value.encode("utf-8", errors="strict"),
            label="physical Android runtime observation",
        )
    except (UnicodeEncodeError, ContractError):
        raise ContractError("physical Android runtime observation is invalid") from None
    if not isinstance(document, dict) or set(document) != {
        "title",
        "userAgent",
        "platform",
        "languages",
        "maxTouchPoints",
        "hardwareConcurrency",
        "innerWidth",
        "innerHeight",
        "screenWidth",
        "screenHeight",
        "devicePixelRatio",
        "timezone",
        "intlLocale",
        "coarsePointer",
        "webglVendor",
        "webglRenderer",
        "webglVersion",
        "webglIdentitySchema",
    }:
        raise ContractError("physical Android runtime observation fields are invalid")
    if document.get("webglIdentitySchema") != "webgl2-preferred-unmasked-v1":
        raise ContractError("physical Android WebGL identity selector is invalid")
    for field in (
        "title",
        "userAgent",
        "platform",
        "timezone",
        "intlLocale",
        "webglVendor",
        "webglRenderer",
        "webglVersion",
    ):
        text = document.get(field)
        if (
            not isinstance(text, str)
            or not text
            or _utf8_size(
                text,
                error_message="physical Android runtime observation text is invalid",
            )
            > 4096
            or any(ord(character) < 32 or ord(character) == 127 for character in text)
        ):
            raise ContractError("physical Android runtime observation text is invalid")
    languages = document.get("languages")
    if (
        not isinstance(languages, list)
        or not 1 <= len(languages) <= 32
        or any(
            not isinstance(item, str)
            or not item
            or _utf8_size(
                item,
                error_message="physical Android runtime languages are invalid",
            )
            > 128
            or any(ord(character) < 32 or ord(character) == 127 for character in item)
            for item in languages
        )
    ):
        raise ContractError("physical Android runtime languages are invalid")
    for field, lower, upper in (
        ("maxTouchPoints", 0, 100),
        ("hardwareConcurrency", 1, 4096),
        ("innerWidth", 1, 100_000),
        ("innerHeight", 1, 100_000),
        ("screenWidth", 1, 100_000),
        ("screenHeight", 1, 100_000),
        ("devicePixelRatio", 0.01, 1000),
    ):
        number = document.get(field)
        if (
            not is_finite_number(number)
            or (field != "devicePixelRatio" and type(number) is not int)
            or not lower <= number <= upper
        ):
            raise ContractError("physical Android runtime numeric value is invalid")
    if not isinstance(document.get("coarsePointer"), bool):
        raise ContractError("physical Android runtime pointer value is invalid")
    return document


def _physical_runtime_value(response: object) -> str:
    if not isinstance(response, dict) or response.get("error") is not None:
        raise ContractError("physical Android runtime observation is invalid")
    envelope = response.get("result")
    if not isinstance(envelope, dict) or "exceptionDetails" in envelope:
        raise ContractError("physical Android runtime observation is invalid")
    remote_object = envelope.get("result")
    if (
        not isinstance(remote_object, dict)
        or remote_object.get("type") != "string"
        or not isinstance(remote_object.get("value"), str)
    ):
        raise ContractError("physical Android runtime observation is invalid")
    return remote_object["value"]


def _stop_fixture_server(
    server: ThreadingHTTPServer,
    thread: Thread,
    *,
    started: bool,
) -> list[str]:
    failures: list[str] = []
    worker_alive = False
    if started:
        try:
            worker_alive = thread.is_alive()
            if type(worker_alive) is not bool:
                failures.append("fixture-worker-status")
                worker_alive = True
        except (OSError, RuntimeError):
            failures.append("fixture-worker-status")
            worker_alive = True
    shutdown_thread: Any | None = None
    shutdown_deadline = time.monotonic() + PHYSICAL_CLEANUP_TIMEOUT_SECONDS
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
                name="browser-core-android-fixture-shutdown",
                daemon=True,
            )
            shutdown_thread.start()
            shutdown_thread.join(
                timeout=max(0.0, shutdown_deadline - time.monotonic())
            )
            if shutdown_thread.is_alive() or shutdown_failed:
                failures.append("fixture-shutdown")
        except (OSError, RuntimeError):
            failures.append("fixture-shutdown")
    try:
        server.server_close()
    except Exception:
        failures.append("fixture-close")
    if shutdown_thread is not None:
        try:
            shutdown_thread.join(
                timeout=max(0.0, shutdown_deadline - time.monotonic())
            )
            if shutdown_thread.is_alive() and "fixture-shutdown" not in failures:
                failures.append("fixture-shutdown")
        except (OSError, RuntimeError):
            if "fixture-shutdown" not in failures:
                failures.append("fixture-shutdown")
    if started:
        try:
            thread.join(timeout=PHYSICAL_CLEANUP_TIMEOUT_SECONDS)
            if thread.is_alive():
                failures.append("fixture-thread")
        except (OSError, RuntimeError):
            failures.append("fixture-thread")
    return failures


def _cleanup_physical_android(
    *,
    selected_serial: str,
    server: ThreadingHTTPServer,
    server_thread: Thread,
    server_thread_started: bool,
    device_port: int,
    endpoint: str | None,
    target_id: str | None,
    target_closed: bool,
    forward_port: int | None,
    reverse_owned: bool,
) -> ContractError | None:
    failures: list[str] = []
    if endpoint is not None and target_id is not None and not target_closed:
        try:
            _ensure_owned_target_closed(
                endpoint,
                target_id,
                PHYSICAL_CLEANUP_TIMEOUT_SECONDS,
            )
        except (ContractError, OSError, ValueError):
            failures.append("target-close")
    if forward_port is not None:
        try:
            _run_adb(
                ["forward", "--remove", f"tcp:{forward_port}"],
                timeout_seconds=PHYSICAL_CLEANUP_TIMEOUT_SECONDS,
                serial=selected_serial,
            )
        except (ContractError, OSError, ValueError):
            failures.append("forward-remove")
    if reverse_owned:
        try:
            _run_adb(
                ["reverse", "--remove", f"tcp:{device_port}"],
                timeout_seconds=PHYSICAL_CLEANUP_TIMEOUT_SECONDS,
                serial=selected_serial,
            )
        except (ContractError, OSError, ValueError):
            failures.append("reverse-remove")
    failures.extend(
        _stop_fixture_server(
            server,
            server_thread,
            started=server_thread_started,
        )
    )
    if failures:
        phases = ",".join(failures)
        return ContractError(f"physical Android cleanup failed ({phases})")
    return None


def probe_physical_android(*, timeout_seconds: float = 30.0) -> dict[str, Any]:
    if not is_finite_number(timeout_seconds) or not 0 < timeout_seconds <= 120:
        raise ContractError("physical Android timeout must be finite in (0, 120]")
    deadline = time.monotonic() + float(timeout_seconds)
    capability, selected_serial = _discover_android_capability(deadline=deadline)
    if capability["available"] is not True or selected_serial is None:
        raise ContractError("physical Android is unavailable")
    try:
        server = _FixtureServer(("127.0.0.1", 0), _FixtureHandler)
    except (OSError, ValueError):
        raise ContractError("physical Android fixture server start failed") from None
    try:
        thread = Thread(
            target=server.serve_forever,
            name="browser-core-android-fixture",
            daemon=True,
        )
    except (OSError, RuntimeError, ValueError):
        server.server_close()
        raise ContractError("physical Android fixture server start failed") from None
    thread_started = False
    device_port = server.server_port
    forward_port: int | None = None
    reverse_owned = False
    endpoint: str | None = None
    target_id: str | None = None
    target_closed = False
    result: dict[str, Any] | None = None
    try:
        try:
            thread.start()
            thread_started = True
        except (OSError, RuntimeError) as exc:
            # A worker can be live even if start reports an error. Preserve
            # ownership so cleanup still stops and joins that exact thread.
            try:
                thread_started = thread.is_alive() is not False
            except (OSError, RuntimeError):
                thread_started = True
            raise ContractError(
                f"physical Android fixture server could not start ({type(exc).__name__})"
            ) from None
        try:
            worker_alive = thread.is_alive()
        except (OSError, RuntimeError):
            raise ContractError("physical Android fixture server worker state is unavailable") from None
        if worker_alive is not True:
            raise ContractError("physical Android fixture server worker did not start")
        _run_adb(
            ["reverse", "--no-rebind", f"tcp:{device_port}", f"tcp:{device_port}"],
            timeout_seconds=_remaining_probe_time(deadline),
            serial=selected_serial,
        )
        reverse_owned = True
        target_url = f"http://127.0.0.1:{device_port}/"
        _run_adb(
            [
                "shell",
                "am",
                "start",
                "-a",
                "android.intent.action.VIEW",
                "-d",
                target_url,
                "-n",
                "com.android.chrome/com.google.android.apps.chrome.Main",
            ],
            timeout_seconds=_remaining_probe_time(deadline),
            serial=selected_serial,
        )
        raw_forward = _run_adb(
            [
                "forward",
                "--no-rebind",
                "tcp:0",
                "localabstract:chrome_devtools_remote",
            ],
            timeout_seconds=_remaining_probe_time(deadline),
            serial=selected_serial,
        )
        if not is_ascii_decimal(raw_forward):
            raise ContractError("ADB returned an invalid Chrome DevTools forward port")
        parsed_forward_port = int(raw_forward)
        if (
            not 1 <= parsed_forward_port <= 65535
            or raw_forward != str(parsed_forward_port)
        ):
            raise ContractError("ADB returned an invalid Chrome DevTools forward port")
        forward_port = parsed_forward_port
        endpoint = f"http://127.0.0.1:{forward_port}"
        target = _wait_for_owned_target(
            endpoint,
            target_url,
            _remaining_probe_time(deadline),
        )
        target_id_value = target.get("id")
        if not isinstance(target_id_value, str) or not TARGET_ID_RE.fullmatch(
            target_id_value
        ):
            raise ContractError("physical Android target ID is invalid")
        target_id = target_id_value
        websocket_url = target.get("webSocketDebuggerUrl")
        if not isinstance(websocket_url, str):
            raise ContractError("physical Android target has no DevTools WebSocket")
        websocket_url = _validate_websocket_url(endpoint, websocket_url)
        if urlsplit(websocket_url).path != f"/devtools/page/{target_id}":
            raise ContractError("physical Android target WebSocket identity is invalid")
        expression = """JSON.stringify((()=>{const canvas=document.createElement('canvas');const gl=canvas.getContext('webgl2')||canvas.getContext('webgl');const debug=gl?gl.getExtension('WEBGL_debug_renderer_info'):null;return {title:document.title,userAgent:navigator.userAgent,platform:navigator.platform,languages:Array.from(navigator.languages||[]),maxTouchPoints:navigator.maxTouchPoints,hardwareConcurrency:navigator.hardwareConcurrency,innerWidth:innerWidth,innerHeight:innerHeight,screenWidth:screen.width,screenHeight:screen.height,devicePixelRatio:devicePixelRatio,timezone:Intl.DateTimeFormat().resolvedOptions().timeZone,intlLocale:Intl.DateTimeFormat().resolvedOptions().locale,coarsePointer:matchMedia('(pointer: coarse)').matches,webglIdentitySchema:'webgl2-preferred-unmasked-v1',webglVendor:gl?gl.getParameter(debug?debug.UNMASKED_VENDOR_WEBGL:gl.VENDOR):null,webglRenderer:gl?gl.getParameter(debug?debug.UNMASKED_RENDERER_WEBGL:gl.RENDERER):null,webglVersion:gl?gl.getParameter(gl.VERSION):null}})())"""
        response = _websocket_json_command(
            websocket_url,
            {
                "id": 731,
                "method": "Runtime.evaluate",
                "params": {
                    "expression": expression,
                    "returnByValue": True,
                    "silent": True,
                },
            },
            _remaining_probe_time(deadline),
        )
        raw_observed = _physical_runtime_value(response)
        if (
            not isinstance(raw_observed, str)
            or _utf8_size(
                raw_observed,
                error_message="physical Android runtime observation is invalid",
            )
            > 1024 * 1024
        ):
            raise ContractError("physical Android runtime observation is invalid")
        observed = _strict_json_object(raw_observed)
        checks = {
            "owned_fixture": observed.get("title") == ANDROID_TITLE,
            "android_user_agent": "Android" in str(observed.get("userAgent"))
            and "Mobile" in str(observed.get("userAgent")),
            "touch": isinstance(observed.get("maxTouchPoints"), int)
            and observed["maxTouchPoints"] > 0
            and observed.get("coarsePointer") is True,
            "viewport": all(
                isinstance(observed.get(field), (int, float)) and observed[field] > 0
                for field in (
                    "innerWidth",
                    "innerHeight",
                    "screenWidth",
                    "screenHeight",
                    "devicePixelRatio",
                )
            ),
            "locale": isinstance(observed.get("languages"), list)
            and bool(observed["languages"]),
            "timezone": isinstance(observed.get("timezone"), str)
            and bool(observed["timezone"]),
            "rendering": all(
                observed.get(field)
                for field in ("webglVendor", "webglRenderer", "webglVersion")
            ),
        }
        if not all(checks.values()):
            raise ContractError(
                "physical Android did not pass every owned-fixture realization check"
            )
        _ensure_owned_target_closed(
            endpoint,
            target_id,
            _remaining_probe_time(deadline),
        )
        target_closed = True
        result = {
            "schema": PHYSICAL_PROBE_SCHEMA,
            "platform": "android",
            "realization": "physical-device",
            "passed": True,
            "device": capability["device"],
            "checks": checks,
            "observed": observed,
            "transport": {
                "adapter": "adb-chrome-devtools",
                "device_identifier_redacted": True,
                "cdp_domains_enabled": [],
                "owned_target_closed": target_closed,
            },
        }
    finally:
        cleanup_error = _cleanup_physical_android(
            selected_serial=selected_serial,
            server=server,
            server_thread=thread,
            server_thread_started=thread_started,
            device_port=device_port,
            endpoint=endpoint,
            target_id=target_id,
            target_closed=target_closed,
            forward_port=forward_port,
            reverse_owned=reverse_owned,
        )
        if cleanup_error is not None:
            active_error = sys.exc_info()[1]
            if active_error is not None:
                raise cleanup_error from active_error
            raise cleanup_error from None
    if result is None:
        raise ContractError("physical Android probe did not produce a result")
    _remaining_probe_time(deadline)
    return result
