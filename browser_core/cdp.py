from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import os
import re
import socket
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any
from collections.abc import Iterator
from urllib.error import HTTPError
from urllib.parse import SplitResult, unquote_to_bytes, urljoin, urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, build_opener

from .contracts import ContractError
from .control_files import decode_strict_json_bytes
from .errors import safe_failure_receipt
from .http_deadline import (
    clamp_urllib_response_read_timeout,
    urllib_response_has_unread_declared_bytes,
)
from .numeric import is_finite_number


_LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1"}
_WEBSOCKET_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
_CDP_WEBSOCKET_PATH_RE = re.compile(
    r"^/devtools/(?:browser|page)/[A-Za-z0-9_-]{1,256}$"
)
_HTTP_HEADER_NAME_RE = re.compile(rb"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")
_MAX_CDP_HANDSHAKE_BYTES = 64 * 1024
_MAX_CDP_MESSAGE_BYTES = 1024 * 1024
_MAX_CDP_CONTROL_FRAMES = 1024
_MAX_CDP_DATA_FRAMES = 65_536
_MAX_CDP_MESSAGES_PER_COMMAND = 1024
_MAX_CDP_INPUT_EVENTS = 1024
_MAX_CDP_INPUT_BATCH_BYTES = 8 * 1024 * 1024
_MAX_CDP_EXPRESSION_BYTES = 256_000
_MAX_CDP_COMMAND_ID = 2_147_483_647
_MAX_CDP_DISCOVERY_RESPONSE_BYTES = 256 * 1024
_MAX_CDP_DISCOVERY_READ_CALLS = 65_536
MAX_CDP_OPERATION_SECONDS = 300.0
_MAX_BINARY64 = 1.7976931348623157e308


class _NoCdpRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None


def urlopen(url: str, *, timeout: float):
    """Open exact loopback discovery without proxy or redirect substitution."""
    url = _validate_cdp_json_url(url)
    opener = build_opener(ProxyHandler({}), _NoCdpRedirectHandler())
    return opener.open(url, timeout=timeout)


class CdpCommandResponseTimeout(ContractError):
    """A sent CDP command did not produce a response before its deadline.

    This is intentionally narrower than a connection or discovery timeout.  A
    caller may use it as evidence that a command reached an established local
    DevTools transport and then failed to answer, but not that target discovery,
    WebSocket upgrade, or an arbitrary protocol validation failed.
    """


class _CdpSocketReadTimeout(TimeoutError):
    """Internal marker that excludes write-side socket timeouts."""


def _is_visible_ascii(value: str) -> bool:
    return bool(value) and all(0x21 <= ord(character) <= 0x7E for character in value)


def _canonical_authority(hostname: str, port: int) -> str:
    return f"[{hostname}]:{port}" if hostname == "::1" else f"{hostname}:{port}"


def _positive_finite_seconds(value: Any, *, label: str) -> float:
    if (
        not is_finite_number(value)
        or value <= 0
        or value > MAX_CDP_OPERATION_SECONDS
    ):
        raise ContractError(
            f"{label} timeout must be finite and positive and at most 300 seconds"
        )
    return float(value)


def _remaining_deadline_seconds(deadline: float, *, label: str) -> float:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise ContractError(f"{label} deadline expired")
    return remaining


def _parse_loopback_http_endpoint(value: str) -> SplitResult:
    if not isinstance(value, str) or not _is_visible_ascii(value):
        raise ContractError(
            "CDP endpoint must be credential-free loopback HTTP with an explicit port"
        )
    try:
        parsed = urlsplit(value)
        hostname = parsed.hostname
        port = parsed.port
        username = parsed.username
        password = parsed.password
    except (UnicodeError, ValueError):
        raise ContractError(
            "CDP endpoint must be credential-free loopback HTTP with an explicit port"
        ) from None
    if (
        hostname not in _LOOPBACK_HOSTS
        or port is None
        or not 1 <= port <= 65535
        or parsed.scheme != "http"
        or parsed.netloc.lower() != _canonical_authority(hostname, port)
        or username is not None
        or password is not None
        or parsed.query
        or parsed.fragment
        or "?" in value
        or "#" in value
        or parsed.path not in {"", "/"}
    ):
        raise ContractError(
            "CDP endpoint must be credential-free loopback HTTP with an explicit port"
        )
    return parsed


def _parse_loopback_websocket_url(
    value: str,
    *,
    expected_port: int | None = None,
    expected_host: str | None = None,
) -> SplitResult:
    if not isinstance(value, str) or not _is_visible_ascii(value):
        raise ContractError("CDP WebSocket must remain on exact loopback")
    try:
        parsed = urlsplit(value)
        hostname = parsed.hostname
        port = parsed.port
        username = parsed.username
        password = parsed.password
    except (UnicodeError, ValueError):
        raise ContractError("CDP WebSocket must remain on exact loopback") from None
    if (
        hostname not in _LOOPBACK_HOSTS
        or port is None
        or not 1 <= port <= 65535
        or parsed.scheme != "ws"
        or parsed.netloc.lower() != _canonical_authority(hostname, port)
        or username is not None
        or password is not None
        or (expected_port is not None and port != expected_port)
        or (expected_host is not None and hostname != expected_host)
        or parsed.query
        or parsed.fragment
        or "?" in value
        or "#" in value
        or _CDP_WEBSOCKET_PATH_RE.fullmatch(parsed.path) is None
    ):
        raise ContractError("CDP WebSocket must remain on exact loopback")
    return parsed


def _validated_http_endpoint(cdp_endpoint: str) -> str:
    parsed = _parse_loopback_http_endpoint(cdp_endpoint)
    if parsed.hostname == "localhost":
        return f"http://127.0.0.1:{parsed.port}/"
    return cdp_endpoint.rstrip("/") + "/"


def _validate_cdp_json_url(value: Any) -> str:
    if not isinstance(value, str) or len(value) > 2048 or not _is_visible_ascii(value):
        raise ContractError("CDP discovery URL must be an exact loopback JSON endpoint")
    try:
        parsed = urlsplit(value)
        hostname = parsed.hostname
        port = parsed.port
        username = parsed.username
        password = parsed.password
    except (UnicodeError, ValueError):
        raise ContractError(
            "CDP discovery URL must be an exact loopback JSON endpoint"
        ) from None
    if (
        hostname not in _LOOPBACK_HOSTS
        or port is None
        or not 1 <= port <= 65535
        or parsed.scheme != "http"
        or parsed.netloc.lower() != _canonical_authority(hostname, port)
        or username is not None
        or password is not None
        or parsed.path not in {"/json/list", "/json/version"}
        or parsed.query
        or parsed.fragment
        or "?" in value
        or "#" in value
    ):
        raise ContractError("CDP discovery URL must be an exact loopback JSON endpoint")
    if hostname == "localhost":
        return f"http://127.0.0.1:{port}{parsed.path}"
    return value


def _read_bounded_json_response(
    response: Any, *, maximum: int, deadline_monotonic: float | None = None
) -> Any:
    if (
        type(maximum) is not int
        or not 1 <= maximum <= _MAX_CDP_DISCOVERY_RESPONSE_BYTES
    ):
        raise ContractError("CDP discovery response bound is invalid")
    body = bytearray()
    reader = getattr(response, "read1", None)
    if not callable(reader):
        reader = response.read
    read_calls = 0
    while len(body) < maximum + 1:
        read_calls += 1
        if read_calls > _MAX_CDP_DISCOVERY_READ_CALLS:
            raise ContractError("CDP discovery response has too many fragments")
        if deadline_monotonic is not None and not clamp_urllib_response_read_timeout(
            response, deadline_monotonic - time.monotonic()
        ):
            raise ContractError("CDP discovery response deadline expired")
        remaining = maximum + 1 - len(body)
        try:
            block = reader(remaining)
        except TimeoutError:
            if deadline_monotonic is not None:
                raise ContractError("CDP discovery response deadline expired") from None
            raise
        if deadline_monotonic is not None and time.monotonic() > deadline_monotonic:
            raise ContractError("CDP discovery response deadline expired")
        if type(block) is not bytes:
            raise ContractError("CDP discovery response is invalid JSON")
        if not block:
            # HTTPResponse.read1() can return EOF without raising even when
            # Content-Length bytes remain. A complete JSON prefix is still a
            # truncated discovery response in that case.
            if urllib_response_has_unread_declared_bytes(response):
                raise ContractError(
                    "CDP discovery response ended before declared length"
                )
            break
        if len(block) > remaining:
            raise ContractError("CDP discovery response is too large")
        body.extend(block)
    if len(body) > maximum:
        raise ContractError("CDP discovery response is too large")
    try:
        document = decode_strict_json_bytes(
            bytes(body),
            label="CDP discovery response",
        )
    except ContractError:
        raise ContractError("CDP discovery response is invalid JSON") from None
    if deadline_monotonic is not None and time.monotonic() > deadline_monotonic:
        raise ContractError("CDP discovery response deadline expired")
    return document


def _read_cdp_json_url(
    url: str,
    *,
    timeout_seconds: float,
    maximum: int,
) -> Any:
    """Read one bounded CDP document while owning the exact HTTP response."""
    url = _validate_cdp_json_url(url)
    timeout_seconds = _positive_finite_seconds(
        timeout_seconds,
        label="CDP discovery",
    )
    if timeout_seconds > 120:
        raise ContractError("CDP discovery timeout must be at most 120 seconds")
    if (
        type(maximum) is not int
        or not 1 <= maximum <= _MAX_CDP_DISCOVERY_RESPONSE_BYTES
    ):
        raise ContractError("CDP discovery response bound is invalid")
    response: Any | None = None
    document: Any = None
    primary_error: BaseException | None = None
    deadline = time.monotonic() + timeout_seconds
    try:
        response = urlopen(url, timeout=timeout_seconds)
        status = response.getcode()
        if type(status) is not int or status != 200:
            raise ContractError("CDP discovery response status is invalid")
        document = _read_bounded_json_response(
            response, maximum=maximum, deadline_monotonic=deadline
        )
    except HTTPError as exc:
        response = exc
        primary_error = ContractError("CDP discovery response status is invalid")
    except BaseException as exc:
        if (
            response is not None
            and not isinstance(exc, ContractError)
            and isinstance(
                exc,
                (AttributeError, OSError, RuntimeError, TypeError, ValueError),
            )
        ):
            primary_error = ContractError(
                f"CDP discovery response failed ({type(exc).__name__})"
            )
        else:
            primary_error = exc

    cleanup_error: ContractError | None = None
    if response is not None:
        try:
            response.close()
        except (AttributeError, OSError, RuntimeError, TypeError, ValueError):
            cleanup_error = ContractError(
                "CDP discovery cleanup failed (response-close)"
            )
    if cleanup_error is not None:
        if primary_error is not None:
            raise cleanup_error from primary_error
        raise cleanup_error from None
    if primary_error is not None:
        raise primary_error
    if time.monotonic() > deadline:
        raise ContractError("CDP discovery response deadline expired")
    return document


def _decode_strict_cdp_text(value: Any, *, label: str) -> Any:
    if type(value) is bytes:
        body = value
    elif isinstance(value, str):
        try:
            body = value.encode("utf-8", errors="strict")
        except UnicodeEncodeError:
            raise ContractError(f"{label} returned invalid JSON") from None
    else:
        raise ContractError(f"{label} returned invalid JSON")
    if len(body) > _MAX_CDP_MESSAGE_BYTES:
        raise ContractError(f"{label} returned oversized JSON")
    try:
        return decode_strict_json_bytes(body, label=label)
    except ContractError:
        raise ContractError(f"{label} returned invalid JSON") from None


def _browser_websocket_url(cdp_endpoint: str, timeout_seconds: float) -> str:
    timeout_seconds = _positive_finite_seconds(
        timeout_seconds,
        label="CDP browser discovery",
    )
    deadline = time.monotonic() + timeout_seconds
    endpoint = _validated_http_endpoint(cdp_endpoint)
    parsed = _parse_loopback_http_endpoint(endpoint)
    version_url = urljoin(endpoint, "json/version")
    try:
        document = _read_cdp_json_url(
            version_url,
            timeout_seconds=min(
                _remaining_deadline_seconds(deadline, label="CDP browser discovery"),
                120.0,
            ),
            maximum=64 * 1024,
        )
    except ContractError:
        raise
    except (OSError, ValueError) as exc:
        raise ContractError(
            f"cannot discover the loopback CDP browser target ({type(exc).__name__})"
        ) from None
    _remaining_deadline_seconds(deadline, label="CDP browser discovery")
    websocket_url = (
        document.get("webSocketDebuggerUrl") if isinstance(document, dict) else None
    )
    if not isinstance(websocket_url, str):
        raise ContractError("loopback CDP browser target has no WebSocket debugger URL")
    websocket = _parse_loopback_websocket_url(
        websocket_url, expected_port=parsed.port, expected_host=parsed.hostname
    )
    if not websocket.path.startswith("/devtools/browser/"):
        raise ContractError("loopback CDP browser target identity is invalid")
    _remaining_deadline_seconds(deadline, label="CDP browser discovery")
    return websocket_url


def _validate_websocket_url(cdp_endpoint: str, websocket_url: str) -> str:
    endpoint = _validated_http_endpoint(cdp_endpoint)
    parsed = _parse_loopback_http_endpoint(endpoint)
    _parse_loopback_websocket_url(
        websocket_url, expected_port=parsed.port, expected_host=parsed.hostname
    )
    return websocket_url


def _valid_page_target_id(value: Any) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9_-]{1,256}", value) is not None


def _page_websocket_url(
    cdp_endpoint: str, target_url: str, timeout_seconds: float
) -> str:
    target_url = _validated_managed_target_text(
        target_url, label="managed page target URL", maximum=64 * 1024
    )
    timeout_seconds = _positive_finite_seconds(timeout_seconds, label="CDP target")
    endpoint = _validated_http_endpoint(cdp_endpoint)
    target_list_url = urljoin(endpoint, "json/list")
    deadline = time.monotonic() + timeout_seconds
    last_error = "exact managed page target was not present"
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        try:
            document = _read_cdp_json_url(
                target_list_url,
                timeout_seconds=min(remaining, 1.0),
                maximum=256 * 1024,
            )
            _remaining_deadline_seconds(deadline, label="CDP target")
            if not isinstance(document, list):
                raise ValueError("target list is not an array")
            matches = [
                item
                for item in document
                if isinstance(item, dict)
                and item.get("type") == "page"
                and item.get("url") == target_url
            ]
            if len(matches) > 1:
                raise ContractError(
                    "multiple page targets matched the exact managed target URL"
                )
            if len(matches) == 1:
                websocket_url = matches[0].get("webSocketDebuggerUrl")
                if not isinstance(websocket_url, str):
                    raise ContractError(
                        "loopback CDP page target has no WebSocket debugger URL"
                    )
                _validate_websocket_url(cdp_endpoint, websocket_url)
                target_id = matches[0].get("id")
                if (
                    not _valid_page_target_id(target_id)
                    or urlsplit(websocket_url).path != f"/devtools/page/{target_id}"
                ):
                    raise ContractError("loopback CDP page target identity is invalid")
                _remaining_deadline_seconds(deadline, label="CDP target")
                return websocket_url
            last_error = "exact managed page target was not present"
        except ContractError:
            raise
        except (OSError, ValueError) as exc:
            last_error = f"target discovery failed ({type(exc).__name__})"
        time.sleep(min(0.05, max(0.0, deadline - time.monotonic())))
    raise ContractError(
        f"timed out waiting for exact managed page target: {last_error}"
    )


def _validated_managed_target_text(value: Any, *, label: str, maximum: int) -> str:
    """Validate one harness-owned target identity before target-list I/O."""
    if not isinstance(value, str) or not value:
        raise ContractError(f"{label} is invalid")
    try:
        encoded = value.encode("utf-8", errors="strict")
    except UnicodeEncodeError:
        raise ContractError(f"{label} is invalid") from None
    if len(encoded) > maximum or any(
        ord(character) < 32 or ord(character) == 127 for character in value
    ):
        raise ContractError(f"{label} is invalid")
    return value


def wait_for_page_target(
    cdp_endpoint: str,
    target_url: str,
    expected_title: str,
    timeout_seconds: float = 10.0,
    failure_title_prefix: str | None = None,
) -> dict[str, Any]:
    """Wait for one exact fixture page using only CDP's loopback target list."""
    timeout_seconds = _positive_finite_seconds(timeout_seconds, label="CDP target")
    target_url = _validated_managed_target_text(
        target_url, label="managed page target URL", maximum=64 * 1024
    )
    expected_title = _validated_managed_target_text(
        expected_title, label="managed page expected title", maximum=256
    )
    if failure_title_prefix is not None:
        failure_title_prefix = _validated_managed_target_text(
            failure_title_prefix,
            label="fixture failure title prefix",
            maximum=256,
        )
    endpoint = _validated_http_endpoint(cdp_endpoint)
    target_list_url = urljoin(endpoint, "json/list")
    deadline = time.monotonic() + timeout_seconds
    last_error = "target was not present"
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        try:
            document = _read_cdp_json_url(
                target_list_url,
                timeout_seconds=min(remaining, 1.0),
                maximum=256 * 1024,
            )
            _remaining_deadline_seconds(deadline, label="CDP target")
            if not isinstance(document, list):
                raise ValueError("target list is not an array")
            matches = [
                candidate
                for candidate in document
                if isinstance(candidate, dict)
                and candidate.get("type") == "page"
                and candidate.get("url") == target_url
            ]
            if len(matches) > 1:
                raise ContractError(
                    "multiple page targets matched the exact managed target URL"
                )
            for candidate in matches:
                if "id" in candidate and not _valid_page_target_id(candidate["id"]):
                    raise ContractError("loopback CDP page target identity is invalid")
                if candidate.get("title") == expected_title:
                    _remaining_deadline_seconds(deadline, label="CDP target")
                    return candidate
            if failure_title_prefix is not None and any(
                isinstance(candidate.get("title"), str)
                and candidate["title"].startswith(failure_title_prefix)
                for candidate in matches
            ):
                raise ContractError("fixture page reported its failure title")
            last_error = "fixture page did not reach its expected title"
        except ContractError:
            raise
        except (OSError, ValueError) as exc:
            last_error = f"target discovery failed ({type(exc).__name__})"
        time.sleep(min(0.05, max(0.0, deadline - time.monotonic())))
    raise ContractError(f"timed out waiting for Browser Core fixture: {last_error}")


def probe_managed_page_target(
    cdp_endpoint: str,
    target_url: str,
    *,
    expected_title: str,
    timeout_seconds: float = 10.0,
) -> dict[str, Any]:
    """Read one browser-process target-list snapshot without page execution.

    The result is deliberately closed and value-free. It distinguishes a live
    exact managed page from a browser that answered without that page, a transport
    failure, and an invalid target-list response. Page-controlled titles are never
    returned; only equality with the harness-owned expected title is retained.
    """
    timeout = _positive_finite_seconds(
        timeout_seconds, label="CDP managed-target probe"
    )
    endpoint = _validated_http_endpoint(cdp_endpoint)
    target_url = _validated_managed_target_text(
        target_url, label="managed page target URL", maximum=64 * 1024
    )
    expected_title = _validated_managed_target_text(
        expected_title, label="managed page expected title", maximum=256
    )
    deadline = time.monotonic() + timeout
    try:
        document = _read_cdp_json_url(
            urljoin(endpoint, "json/list"),
            timeout_seconds=min(
                _remaining_deadline_seconds(deadline, label="CDP managed-target probe"),
                10.0,
            ),
            maximum=256 * 1024,
        )
        _remaining_deadline_seconds(deadline, label="CDP managed-target probe")
    except ContractError:
        return {"status": "invalid-response", "title_matches": None}
    except (OSError, ValueError):
        return {"status": "unreachable", "title_matches": None}
    if not isinstance(document, list):
        return {"status": "invalid-response", "title_matches": None}
    matches = [
        candidate
        for candidate in document
        if isinstance(candidate, dict)
        and candidate.get("type") == "page"
        and candidate.get("url") == target_url
    ]
    if time.monotonic() >= deadline:
        return {"status": "invalid-response", "title_matches": None}
    if len(matches) > 1:
        return {"status": "invalid-response", "title_matches": None}
    if not matches:
        return {"status": "absent", "title_matches": None}
    if "id" in matches[0] and not _valid_page_target_id(matches[0]["id"]):
        return {"status": "invalid-response", "title_matches": None}
    return {
        "status": "present",
        "title_matches": matches[0].get("title") == expected_title,
    }


class _BoundedSocketReader:
    def __init__(
        self,
        connection: socket.socket,
        *,
        deadline: float | None = None,
    ) -> None:
        self.connection = connection
        self.deadline = deadline
        self._buffer = bytearray()

    @property
    def buffered_bytes(self) -> int:
        return len(self._buffer)

    def _check_deadline(self) -> None:
        if self.deadline is not None and time.monotonic() >= self.deadline:
            raise _CdpSocketReadTimeout("CDP WebSocket read deadline expired")

    def _prepare_write(self) -> None:
        self._check_deadline()
        if self.deadline is not None:
            remaining = self.deadline - time.monotonic()
            if remaining <= 0:
                raise _CdpSocketReadTimeout("CDP WebSocket deadline expired")
            self.connection.settimeout(remaining)
        self._check_deadline()

    def _recv(self, maximum: int) -> bytes:
        if maximum <= 0:
            raise ContractError("CDP WebSocket read bound is invalid")
        if self.deadline is not None:
            remaining = self.deadline - time.monotonic()
            if remaining <= 0:
                raise _CdpSocketReadTimeout("CDP WebSocket deadline expired")
            self.connection.settimeout(remaining)
        try:
            block = self.connection.recv(maximum)
        except TimeoutError:
            raise _CdpSocketReadTimeout("CDP WebSocket read deadline expired") from None
        if type(block) is not bytes:
            raise ContractError("CDP WebSocket returned invalid bytes")
        if len(block) > maximum:
            raise ContractError("CDP WebSocket exceeded its read bound")
        self._check_deadline()
        return block

    def read_exact(self, length: int) -> bytes:
        if length < 0:
            raise ContractError("CDP WebSocket read bound is invalid")
        self._check_deadline()
        while len(self._buffer) < length:
            block = self._recv(length - len(self._buffer))
            if not block:
                raise ContractError("CDP WebSocket closed before a complete response")
            self._buffer.extend(block)
        self._check_deadline()
        result = bytes(self._buffer[:length])
        del self._buffer[:length]
        return result

    def read_until(self, delimiter: bytes, *, maximum: int) -> bytes:
        if not delimiter or maximum < 0:
            raise ContractError("CDP WebSocket read bound is invalid")
        capacity = maximum + len(delimiter)
        while True:
            self._check_deadline()
            index = self._buffer.find(delimiter)
            if index >= 0:
                if index > maximum:
                    raise ContractError("CDP WebSocket handshake response is too large")
                result = bytes(self._buffer[:index])
                del self._buffer[: index + len(delimiter)]
                return result
            if len(self._buffer) >= capacity:
                raise ContractError("CDP WebSocket handshake response is too large")
            block = self._recv(min(4096, capacity - len(self._buffer)))
            if not block:
                raise ContractError("CDP WebSocket closed before a complete response")
            self._buffer.extend(block)


def _masked_frame(payload: bytes, mask: bytes, *, opcode: int) -> bytes:
    if type(payload) is not bytes or len(payload) > _MAX_CDP_MESSAGE_BYTES:
        raise ContractError("CDP WebSocket frame payload is invalid")
    if type(mask) is not bytes or len(mask) != 4:
        raise ContractError("CDP WebSocket frame mask is invalid")
    if isinstance(opcode, bool) or not isinstance(opcode, int) or opcode not in {1, 10}:
        raise ContractError("CDP WebSocket frame opcode is invalid")
    length = len(payload)
    if length < 126:
        header = bytes((0x80 | opcode, 0x80 | length))
    elif length <= 0xFFFF:
        header = bytes((0x80 | opcode, 0xFE)) + length.to_bytes(2, "big")
    else:
        header = bytes((0x80 | opcode, 0xFF)) + length.to_bytes(8, "big")
    masked = bytes(value ^ mask[index % 4] for index, value in enumerate(payload))
    return header + mask + masked


def _masked_text_frame(payload: bytes, mask: bytes) -> bytes:
    return _masked_frame(payload, mask, opcode=0x1)


def _websocket_random_bytes(count: int) -> bytes:
    try:
        value = os.urandom(count)
    except (OSError, RuntimeError, TypeError, ValueError):
        raise ContractError("CDP WebSocket randomness generation failed") from None
    if type(value) is not bytes or len(value) != count:
        raise ContractError("CDP WebSocket randomness output is invalid")
    return value


def _send_websocket_bytes(connection: Any, body: bytes) -> None:
    if type(body) is not bytes or not body:
        raise ContractError("CDP WebSocket write bytes are invalid")
    if connection.sendall(body) is not None:
        raise ContractError("CDP WebSocket transport write is invalid")


def _read_server_frame(
    reader: _BoundedSocketReader,
    *,
    maximum: int,
) -> tuple[bool, int, bytes]:
    first, second = reader.read_exact(2)
    final = bool(first & 0x80)
    opcode = first & 0x0F
    length_code = second & 0x7F
    if first & 0x70 or second & 0x80 or opcode not in {0x0, 0x1, 0x8, 0x9, 0xA}:
        raise ContractError("CDP WebSocket returned an unsupported frame")
    if opcode >= 0x8 and (not final or length_code >= 126):
        raise ContractError("CDP WebSocket returned an unsupported frame")
    length = length_code
    if length_code == 126:
        length = int.from_bytes(reader.read_exact(2), "big")
        if length < 126:
            raise ContractError("CDP WebSocket returned an unsupported frame")
    elif length_code == 127:
        encoded = reader.read_exact(8)
        if encoded[0] & 0x80:
            raise ContractError("CDP WebSocket returned an unsupported frame")
        length = int.from_bytes(encoded, "big")
        if length <= 0xFFFF:
            raise ContractError("CDP WebSocket returned an unsupported frame")
    if opcode < 0x8 and length > maximum:
        raise ContractError("CDP WebSocket response is too large")
    return final, opcode, reader.read_exact(length)


def _read_server_text_message(
    reader: _BoundedSocketReader,
    connection: socket.socket,
    *,
    maximum: int = _MAX_CDP_MESSAGE_BYTES,
) -> bytes:
    payload = bytearray()
    fragmented = False
    control_frames = 0
    data_frames = 0
    while True:
        final, opcode, block = _read_server_frame(
            reader, maximum=maximum - len(payload)
        )
        if opcode >= 0x8:
            control_frames += 1
            if control_frames > _MAX_CDP_CONTROL_FRAMES:
                raise ContractError("CDP WebSocket returned too many control frames")
            if opcode == 0x8:
                raise ContractError("CDP WebSocket closed before a complete response")
            if opcode == 0x9:
                pong = _masked_frame(block, _websocket_random_bytes(4), opcode=0xA)
                reader._prepare_write()
                _send_websocket_bytes(
                    connection,
                    pong,
                )
            continue
        data_frames += 1
        if data_frames > _MAX_CDP_DATA_FRAMES:
            raise ContractError("CDP WebSocket returned too many data frames")
        if opcode == 0x1:
            if fragmented:
                raise ContractError("CDP WebSocket returned an unsupported frame")
            fragmented = not final
        elif not fragmented:
            raise ContractError("CDP WebSocket returned an unsupported frame")
        payload.extend(block)
        if final:
            return bytes(payload)


def _validate_websocket_upgrade(header: bytes, key: str) -> None:
    lines = header.split(b"\r\n")
    status = lines[0].split(b" ", 2) if lines else []
    if len(status) != 3 or status[0] != b"HTTP/1.1" or status[1] != b"101":
        raise ContractError("CDP WebSocket upgrade was rejected")
    if any(byte < 0x20 or byte > 0x7E for byte in status[2]):
        raise ContractError("CDP WebSocket handshake validation failed")
    headers: dict[bytes, list[bytes]] = {}
    for line in lines[1:]:
        name, separator, value = line.partition(b":")
        stripped = value.strip(b" \t")
        if (
            not separator
            or _HTTP_HEADER_NAME_RE.fullmatch(name) is None
            or any(byte not in {0x09} and not 0x20 <= byte <= 0x7E for byte in value)
        ):
            raise ContractError("CDP WebSocket handshake validation failed")
        headers.setdefault(name.lower(), []).append(stripped)
    critical = {b"upgrade", b"connection", b"sec-websocket-accept"}
    if any(len(headers.get(name, [])) != 1 for name in critical):
        raise ContractError("CDP WebSocket handshake validation failed")
    if headers[b"upgrade"][0].lower() != b"websocket":
        raise ContractError("CDP WebSocket handshake validation failed")
    connection_tokens = [
        token.strip().lower() for token in headers[b"connection"][0].split(b",")
    ]
    if (
        not connection_tokens
        or any(
            _HTTP_HEADER_NAME_RE.fullmatch(token) is None for token in connection_tokens
        )
        or b"upgrade" not in connection_tokens
    ):
        raise ContractError("CDP WebSocket handshake validation failed")
    expected = base64.b64encode(
        hashlib.sha1((key + _WEBSOCKET_GUID).encode("ascii")).digest()
    )
    if (
        headers[b"sec-websocket-accept"][0] != expected
        or b"sec-websocket-extensions" in headers
        or b"sec-websocket-protocol" in headers
    ):
        raise ContractError("CDP WebSocket handshake validation failed")


@contextmanager
def _websocket_connection(
    websocket_url: str,
    timeout_seconds: float,
    *,
    os_error_label: str,
) -> Iterator[tuple[socket.socket, _BoundedSocketReader]]:
    timeout_seconds = _positive_finite_seconds(
        timeout_seconds, label="CDP WebSocket"
    )
    deadline = time.monotonic() + timeout_seconds
    parsed = _parse_loopback_websocket_url(websocket_url)
    key = base64.b64encode(_websocket_random_bytes(16)).decode("ascii")
    host_header = _canonical_authority(parsed.hostname, parsed.port)
    request = (
        f"GET {parsed.path} HTTP/1.1\r\n"
        f"Host: {host_header}\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {key}\r\n"
        "Sec-WebSocket-Version: 13\r\n\r\n"
    ).encode("ascii")
    connection: socket.socket | None = None
    primary_error: BaseException | None = None
    try:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ContractError("CDP WebSocket deadline expired")
        connection = socket.create_connection(
            ("127.0.0.1" if parsed.hostname == "localhost" else parsed.hostname,
             parsed.port), timeout=remaining
        )
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ContractError("CDP WebSocket deadline expired")
        connection.settimeout(remaining)
        reader = _BoundedSocketReader(connection, deadline=deadline)
        _send_websocket_bytes(connection, request)
        header = reader.read_until(b"\r\n\r\n", maximum=_MAX_CDP_HANDSHAKE_BYTES)
        _validate_websocket_upgrade(header, key)
        _remaining_deadline_seconds(deadline, label="CDP WebSocket")
        yield connection, reader
    except BaseException as exc:
        primary_error = exc
    cleanup_error: ContractError | None = None
    if connection is not None:
        try:
            connection.close()
        except (AttributeError, OSError, RuntimeError, TypeError, ValueError):
            cleanup_error = ContractError(
                "CDP WebSocket cleanup failed (connection-close)"
            )
    if cleanup_error is not None:
        if primary_error is not None:
            raise cleanup_error from primary_error
        raise cleanup_error from None
    if primary_error is None:
        return
    if isinstance(primary_error, ContractError):
        raise primary_error
    if isinstance(primary_error, (OSError, RuntimeError, TypeError, ValueError)):
        raise ContractError(
            f"{os_error_label} ({type(primary_error).__name__})"
        ) from None
    raise primary_error


def _validate_command_id(value: Any) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not 1 <= value <= _MAX_CDP_COMMAND_ID
    ):
        raise ContractError("CDP command id must be a bounded positive integer")
    return value


def _response_matches_command_id(value: Any, expected: int) -> bool:
    return (
        isinstance(value, dict)
        and type(value.get("id")) is int
        and value["id"] == expected
    )


def _validated_command_response(value: dict[str, Any]) -> dict[str, Any]:
    if "error" in value:
        raise ContractError("CDP command returned a protocol error")
    if not isinstance(value.get("result"), dict):
        raise ContractError("CDP command response is invalid")
    return value


def _encode_cdp_command(command: Any) -> bytes:
    if not isinstance(command, dict):
        raise ContractError("CDP command must be a mapping")
    _validate_command_id(command.get("id"))
    method = command.get("method")
    if (
        not isinstance(method, str)
        or re.fullmatch(r"[A-Za-z][A-Za-z0-9.]{0,127}", method) is None
    ):
        raise ContractError("CDP command method is invalid")
    if "params" in command and not isinstance(command.get("params"), dict):
        raise ContractError("CDP command params must be a mapping")
    try:
        payload = json.dumps(
            command,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (OverflowError, RecursionError, TypeError, ValueError, UnicodeEncodeError):
        raise ContractError("CDP command is not bounded JSON") from None
    if len(payload) > _MAX_CDP_MESSAGE_BYTES:
        raise ContractError("CDP command exceeds the message byte limit")
    return payload


def _websocket_json_command(
    websocket_url: str, command: dict[str, Any], timeout_seconds: float
) -> dict[str, Any]:
    timeout_seconds = _positive_finite_seconds(timeout_seconds, label="CDP command")
    deadline = time.monotonic() + timeout_seconds
    payload = _encode_cdp_command(command)
    matched_response: dict[str, Any] | None = None
    with _websocket_connection(
        websocket_url,
        _remaining_deadline_seconds(deadline, label="CDP command"),
        os_error_label="cannot use loopback CDP",
    ) as (connection, reader):
        _remaining_deadline_seconds(deadline, label="CDP command")
        reader._check_deadline()
        frame = _masked_text_frame(payload, _websocket_random_bytes(4))
        reader._prepare_write()
        _send_websocket_bytes(connection, frame)
        message_count = 0
        while True:
            message_count += 1
            if message_count > _MAX_CDP_MESSAGES_PER_COMMAND:
                raise ContractError("CDP WebSocket returned too many messages")
            try:
                raw = _read_server_text_message(reader, connection)
            except _CdpSocketReadTimeout:
                raise CdpCommandResponseTimeout(
                    "CDP command response deadline expired"
                ) from None
            result = _decode_strict_cdp_text(raw, label="CDP WebSocket")
            if _response_matches_command_id(result, command["id"]):
                if time.monotonic() >= deadline:
                    raise CdpCommandResponseTimeout(
                        "CDP command response deadline expired"
                    )
                matched_response = _validated_command_response(result)
                break
    if time.monotonic() >= deadline:
        raise CdpCommandResponseTimeout("CDP command response deadline expired")
    if matched_response is None:
        raise ContractError("CDP command response is missing")
    return matched_response


# Only the Input domain is reachable through `send_page_input_command`. The CDP
# surface this package exposes is deliberately narrow -- everything else here
# either evaluates an expression or reads a target list -- and an unrestricted
# command sender would quietly widen it to all of CDP.
_ALLOWED_INPUT_METHODS = frozenset(
    {
        "Input.dispatchMouseEvent",
        "Input.dispatchKeyEvent",
        "Input.dispatchTouchEvent",
    }
)

RESOURCE_INTENT_ATTRIBUTES = frozenset({"src", "href", "action", "poster", "data"})
RESOURCE_INTENT_STANDARD_TAGS = frozenset(
    {
        "a",
        "area",
        "audio",
        "base",
        "embed",
        "form",
        "frame",
        "iframe",
        "image",
        "img",
        "input",
        "link",
        "object",
        "portal",
        "script",
        "source",
        "track",
        "use",
        "video",
    }
)
_MAX_RESOURCE_INTENTS = 128
_MAX_SNAPSHOT_DOCUMENTS = 64
_MAX_SNAPSHOT_NODES = 50_000


def project_resource_intent_tag(value: Any) -> str | None:
    """Project a page-controlled node name into a closed structural class."""

    if not isinstance(value, str) or not value:
        return None
    lowered = value.lower()
    return lowered if lowered in RESOURCE_INTENT_STANDARD_TAGS else "other-element"


def _browser_ipv4_number(value: str) -> int | None:
    """Parse one WHATWG special-scheme IPv4 component without DNS resolution."""
    radix = 10
    digits = value
    if value.lower().startswith("0x"):
        radix, digits = 16, value[2:]
    elif len(value) > 1 and value.startswith("0"):
        radix, digits = 8, value[1:]
    if digits == "" and radix != 10:
        return 0
    allowed = (
        r"[0-9]+" if radix == 10 else r"[0-7]+" if radix == 8 else r"[0-9a-fA-F]+"
    )
    if re.fullmatch(allowed, digits) is None:
        return None
    significant = digits.lstrip("0") or "0"
    if len(significant) > {10: 10, 8: 11, 16: 8}[radix]:
        return None
    return int(significant, radix)


def project_resource_intent_origin(
    scheme: str, hostname: str | None, explicit_port: int | None
) -> str | None:
    """Canonicalize numeric IP hosts as a browser does for HTTP origins."""
    if (
        type(scheme) is not str
        or scheme not in {"http", "https"}
        or type(hostname) is not str
        or not hostname
        or (
            explicit_port is not None
            and (type(explicit_port) is not int or not 0 <= explicit_port <= 65535)
        )
    ):
        return None
    if ":" in hostname:
        try:
            host = str(ipaddress.IPv6Address(hostname))
        except ValueError:
            return None
        authority = f"[{host}]"
    else:
        host = hostname.lower()
        if "%" in host:
            try:
                host = unquote_to_bytes(host).decode("utf-8").lower()
            except UnicodeError:
                return None
        # Full UTS-46 processing is outside this value-free projection. Withhold
        # hosts that need it, or whose authority can parse differently in a URL.
        if not host.isascii() or any(
            ord(char) <= 32 or ord(char) == 127 or char in "#/:<>?@[\\]^|%"
            for char in host
        ):
            return None
        parts = host.split(".")
        if len(parts) > 1 and parts[-1] == "":
            parts.pop()
        last = parts[-1]
        ends_in_number = bool(re.fullmatch(r"[0-9]+", last)) or (
            _browser_ipv4_number(last) is not None
        )
        if ends_in_number:
            if len(parts) > 4:
                return None
            numbers = [_browser_ipv4_number(part) for part in parts]
            if any(number is None for number in numbers):
                return None
            if any(number > 255 for number in numbers[:-1]):
                return None
            final_bits = 8 * (5 - len(numbers))
            if numbers[-1] >= 1 << final_bits:
                return None
            address = sum(
                number << (8 * (3 - index))
                for index, number in enumerate(numbers[:-1])
            ) + numbers[-1]
            host = str(ipaddress.IPv4Address(address))
        authority = host
    default_port = 443 if scheme == "https" else 80
    if explicit_port is not None and explicit_port != default_port:
        authority += f":{explicit_port}"
    return f"{scheme}://{authority}"


def _resource_url_projection(
    value: str, *, base_url: str, target_url: str
) -> dict[str, Any] | None:
    """Retain URL structure needed for RE while dropping every URL value."""
    needs_browser_encoding = any(
        ord(char) < 33 or ord(char) > 126 or char in "\"'<>`{}"
        for candidate in (value, base_url)
        for char in candidate
    )
    encoded_dot_segment = any(
        re.search(r"(?i)(?:^|/)(?:%2e|\.){1,2}(?:/|[?#]|$)", candidate)
        for candidate in (value, base_url)
    )
    if (
        needs_browser_encoding
        or encoded_dot_segment
        or "\\" in value
        or "\\" in base_url
        or re.match(r"^[\x00-\x20]*/{3,}", value)
        or any(
            re.match(r"(?i)^[\x00-\x20]*https?:/{3,}", candidate)
            for candidate in (value, base_url)
        )
    ):
        # Browser URL parsing serializes raw path/query characters, resolves
        # encoded dot segments, and treats surplus authority slashes and
        # backslashes as separators. urljoin does not; withhold the shape.
        return None
    try:
        value_parts = urlsplit(value)
        base_parts = urlsplit(base_url)
        if ";" in value_parts.path or ";" in base_parts.path:
            # urljoin treats the last path semicolon as a legacy parameter
            # delimiter and can drop it; browser URL parsing keeps it.
            return None
        parsed = urlsplit(urljoin(base_url, value))
        if value.startswith("?") and not value_parts.query:
            # A bare query marker clears the browser URL's inherited query;
            # urljoin incorrectly keeps the base URL's query in this case.
            parsed = parsed._replace(query="")
        target = urlsplit(target_url)
        hostname = parsed.hostname
        port = parsed.port
        target_hostname = target.hostname
        target_port = target.port
    except (UnicodeError, ValueError):
        return None
    if parsed.scheme not in {"http", "https"} or not hostname:
        return None

    resource_origin = project_resource_intent_origin(parsed.scheme, hostname, port)
    target_origin = project_resource_intent_origin(
        target.scheme, target_hostname, target_port
    )
    if resource_origin is None or target_origin is None:
        return None
    same_origin = resource_origin == target_origin
    segment_lengths = []
    for segment in re.finditer(r"[^/]+", parsed.path):
        segment_length = segment.end() - segment.start()
        if segment_length > 1_000_000:
            # Saved resource-intent shapes cannot represent this length.
            return None
        segment_lengths.append(segment_length)
        if len(segment_lengths) > 32:
            break
    query_parts = parsed.query.split("&", 64)
    query_name_parts = [
        item.partition("=")[0] for item in query_parts[:64] if item.partition("=")[0]
    ]
    query_names = sorted({name[:80] for name in query_name_parts})
    return {
        # Arm and control use different ephemeral ports. Keeping either port makes
        # identical local script/form attributes look different in subtraction.
        "origin": "loopback-rehost" if same_origin else resource_origin,
        "same_origin_as_rehost": same_origin,
        "path_segment_lengths": segment_lengths[:32],
        "path_segments_truncated": len(segment_lengths) > 32,
        "query_names": query_names,
        "query_names_truncated": len(query_parts) > 64
        or any(len(name) > 80 for name in query_name_parts),
    }


def observe_page_resource_intents(
    cdp_endpoint: str,
    *,
    target_url: str,
    timeout_seconds: float = 5.0,
    command_id: int = 958,
) -> dict[str, Any]:
    """Read redacted resource-bearing DOM attributes without page JavaScript.

    This deliberately exposes one CDP command only: ``DOMSnapshot.captureSnapshot``
    with no computed styles or layout extras. The raw snapshot may contain DOM text
    and URL values, so it is parsed in memory and only structural URL projections
    leave this function.
    """
    timeout_seconds = _positive_finite_seconds(
        timeout_seconds, label="CDP resource-intent"
    )
    _validate_command_id(command_id)
    deadline = time.monotonic() + timeout_seconds
    websocket_url = _page_websocket_url(
        cdp_endpoint,
        target_url,
        _remaining_deadline_seconds(deadline, label="CDP resource-intent"),
    )
    response = _websocket_json_command(
        websocket_url,
        {
            "id": command_id,
            "method": "DOMSnapshot.captureSnapshot",
            "params": {
                "computedStyles": [],
                "includePaintOrder": False,
                "includeDOMRects": False,
            },
        },
        _remaining_deadline_seconds(deadline, label="CDP resource-intent"),
    )
    if response.get("error"):
        raise ContractError("CDP DOM snapshot command was rejected")
    result = response.get("result")
    if not isinstance(result, dict):
        raise ContractError("CDP DOM snapshot response is invalid")
    strings = result.get("strings")
    documents = result.get("documents")
    if not isinstance(strings, list) or not isinstance(documents, list):
        raise ContractError("CDP DOM snapshot response is invalid")
    if len(documents) > _MAX_SNAPSHOT_DOCUMENTS:
        raise ContractError("CDP DOM snapshot has too many documents")

    def string_at(index: Any) -> str | None:
        if (
            isinstance(index, bool)
            or not isinstance(index, int)
            or index < 0
            or index >= len(strings)
            or not isinstance(strings[index], str)
        ):
            return None
        return strings[index]

    records: dict[str, dict[str, Any]] = {}
    all_record_keys: set[str] = set()
    candidates = 0
    unprojectable_http = False
    node_count = 0
    for document in documents:
        _remaining_deadline_seconds(deadline, label="CDP resource-intent")
        if not isinstance(document, dict):
            raise ContractError("CDP DOM snapshot response is invalid")
        base_url = string_at(document.get("baseURL"))
        if not base_url:
            raise ContractError("CDP DOM snapshot base URL is invalid")
        nodes = document.get("nodes")
        if not isinstance(nodes, dict):
            raise ContractError("CDP DOM snapshot response is invalid")
        node_names = nodes.get("nodeName")
        attributes = nodes.get("attributes")
        if not isinstance(node_names, list) or not isinstance(attributes, list):
            raise ContractError("CDP DOM snapshot response is invalid")
        if len(node_names) != len(attributes):
            raise ContractError("CDP DOM snapshot node arrays are inconsistent")
        node_count += max(len(node_names), len(attributes))
        if node_count > _MAX_SNAPSHOT_NODES:
            raise ContractError("CDP DOM snapshot has too many nodes")
        for index, encoded_attributes in enumerate(attributes):
            _remaining_deadline_seconds(deadline, label="CDP resource-intent")
            if not isinstance(encoded_attributes, list) or len(encoded_attributes) % 2:
                raise ContractError("CDP DOM snapshot attributes are invalid")
            tag = string_at(node_names[index])
            if not tag:
                raise ContractError("CDP DOM snapshot node name is invalid")
            for offset in range(0, len(encoded_attributes), 2):
                _remaining_deadline_seconds(deadline, label="CDP resource-intent")
                name = string_at(encoded_attributes[offset])
                raw_value = string_at(encoded_attributes[offset + 1])
                if name is None or raw_value is None:
                    raise ContractError("CDP DOM snapshot attribute index is invalid")
                if not name or name.lower() not in RESOURCE_INTENT_ATTRIBUTES:
                    continue
                projection = _resource_url_projection(
                    raw_value, base_url=base_url, target_url=target_url
                )
                if projection is None:
                    try:
                        resolved_scheme = urlsplit(urljoin(base_url, raw_value)).scheme
                        base_scheme = urlsplit(base_url).scheme
                    except (UnicodeError, ValueError):
                        unprojectable_http = True
                    else:
                        if resolved_scheme in {"http", "https"} or (
                            base_scheme in {"http", "https"}
                            and not re.match(
                                r"(?i)^[\x00-\x20]*[a-z][a-z0-9+.-]*:", raw_value
                            )
                        ):
                            # urljoin accepts digit/punctuation-led schemes
                            # that browsers treat as relative HTTP paths.
                            unprojectable_http = True
                    continue
                candidates += 1
                record = {
                    "tag": project_resource_intent_tag(tag),
                    "attribute": name.lower(),
                    **projection,
                }
                key = json.dumps(record, sort_keys=True, separators=(",", ":"))
                all_record_keys.add(key)
                if key in records:
                    records[key]["count"] += 1
                elif len(records) < _MAX_RESOURCE_INTENTS:
                    records[key] = {**record, "count": 1}
    report = {
        "status": "unverifiable" if unprojectable_http else "ok",
        "source": "cdp_dom_snapshot",
        "intents": [records[key] for key in sorted(records)],
        "distinct_intents": len(all_record_keys),
        "candidate_attributes": candidates,
        "truncated": len(all_record_keys) > _MAX_RESOURCE_INTENTS,
        "non_claim": (
            "HTTP resource intent could not be fully projected"
            if unprojectable_http
            else "DOM attributes present at capture time; not proof that a request "
            "was sent, reached DNS, or received a response"
        ),
    }
    _remaining_deadline_seconds(deadline, label="CDP resource-intent")
    return report


def send_page_input_batch(
    cdp_endpoint: str,
    events: list[tuple[str, dict[str, Any]]],
    *,
    target_url: str = "about:blank",
    timeout_seconds: float = 10.0,
    first_command_id: int = 960,
) -> dict[str, Any]:
    """Dispatch a sequence of Input events over a single WebSocket.

    One connection per event is what the obvious implementation does, and it does
    not hold up: measured 2026-08-06, dispatching 20 events as 20 separate
    connections lost 10 of them to timeouts, because each one re-fetches the target
    list, re-opens a socket and re-handshakes. Reusing the connection also makes the
    sequence far closer to contiguous in time, which matters when the point is to
    deliver a *stream* of input rather than isolated events.

    ``timeout_seconds`` is the deadline for the **whole batch**, not per event: the
    underlying connection enforces a single deadline for its lifetime. Sizing it
    per-event is the mistake that makes batching look worse than one-connection-per-
    event -- measured, an 18-event batch on a 10 s budget delivered 1 and then
    reported "deadline expired" for the rest.

    Returns a per-event outcome rather than raising: a probe that cannot deliver is
    a fact about the run, not a reason to fail it.
    """
    if not isinstance(events, list) or len(events) > _MAX_CDP_INPUT_EVENTS:
        raise ContractError(
            f"CDP input batch must contain at most {_MAX_CDP_INPUT_EVENTS} events"
        )
    _validate_command_id(first_command_id)
    timeout_seconds = _positive_finite_seconds(timeout_seconds, label="CDP input")
    deadline = time.monotonic() + timeout_seconds
    payloads: list[bytes] = []
    methods: list[str] = []
    batch_bytes = 0
    for index, event in enumerate(events):
        if not isinstance(event, (list, tuple)) or len(event) != 2:
            raise ContractError("each CDP input event must be a (method, params) pair")
        method, params = event
        if not isinstance(method, str) or method not in _ALLOWED_INPUT_METHODS:
            raise ContractError(
                "CDP method is not on the input allowlist "
                f"(allowed: {sorted(_ALLOWED_INPUT_METHODS)})"
            )
        if not isinstance(params, dict):
            raise ContractError("CDP input params must be a mapping")
        payload = _encode_cdp_command(
            {
                "id": first_command_id + index,
                "method": method,
                "params": params,
            }
        )
        batch_bytes += len(payload)
        if batch_bytes > _MAX_CDP_INPUT_BATCH_BYTES:
            raise ContractError("CDP input batch exceeds the batch byte limit")
        payloads.append(payload)
        methods.append(method)
        _remaining_deadline_seconds(deadline, label="CDP input batch")
    websocket_url = _page_websocket_url(
        cdp_endpoint,
        target_url,
        _remaining_deadline_seconds(deadline, label="CDP input batch"),
    )
    dispatched = 0
    errors: list[str] = []
    with _websocket_connection(
        websocket_url,
        _remaining_deadline_seconds(deadline, label="CDP input batch"),
        os_error_label="cannot use loopback CDP",
    ) as (connection, reader):
        for index, (method, payload) in enumerate(zip(methods, payloads)):
            command_id = first_command_id + index
            try:
                reader._check_deadline()
                frame = _masked_text_frame(payload, _websocket_random_bytes(4))
                reader._prepare_write()
                _send_websocket_bytes(connection, frame)
                seen = 0
                while True:
                    seen += 1
                    if seen > _MAX_CDP_MESSAGES_PER_COMMAND:
                        raise ContractError("CDP WebSocket returned too many messages")
                    message = _decode_strict_cdp_text(
                        _read_server_text_message(reader, connection),
                        label="CDP WebSocket",
                    )
                    if _response_matches_command_id(message, command_id):
                        _validated_command_response(message)
                        break
                _remaining_deadline_seconds(deadline, label="CDP input batch")
                reader._check_deadline()
                dispatched += 1
            except Exception as exc:  # noqa: BLE001 - reported per event
                if len(errors) < 8:
                    errors.append(f"{method}: {safe_failure_receipt(exc)}")
    if time.monotonic() >= deadline and len(errors) < 8:
        errors.append("batch: CDP input batch deadline expired")
    return {"dispatched": dispatched, "attempted": len(events), "errors": errors}


def send_page_input_command(
    cdp_endpoint: str,
    method: str,
    params: dict[str, Any],
    *,
    target_url: str = "about:blank",
    timeout_seconds: float = 10.0,
    command_id: int = 960,
) -> Any:
    """Dispatch one Input-domain event to a page target.

    Input delivered this way goes through the browser's own input pipeline, so the
    resulting DOM events carry ``isTrusted: true`` -- which is the entire reason
    this exists. A page-side ``dispatchEvent`` produces ``isTrusted: false`` and
    therefore cannot answer whether a collector behaves differently when input is
    genuine.

    This is a **measurement probe, not a behaviour model.** It exists to test
    whether an observed surface changes at all under input; it deliberately has no
    notion of realistic timing, curvature, or dwell, and must not be used as though
    it did.
    """
    if not isinstance(method, str) or method not in _ALLOWED_INPUT_METHODS:
        raise ContractError(
            "CDP method is not on the input allowlist "
            f"(allowed: {sorted(_ALLOWED_INPUT_METHODS)})"
        )
    if not isinstance(params, dict):
        raise ContractError("CDP input params must be a mapping")
    _validate_command_id(command_id)
    timeout_seconds = _positive_finite_seconds(timeout_seconds, label="CDP input")
    deadline = time.monotonic() + timeout_seconds
    websocket_url = _page_websocket_url(
        cdp_endpoint,
        target_url,
        _remaining_deadline_seconds(deadline, label="CDP input"),
    )
    return _websocket_json_command(
        websocket_url,
        {"id": command_id, "method": method, "params": params},
        _remaining_deadline_seconds(deadline, label="CDP input"),
    )


def evaluate_page_expression(
    cdp_endpoint: str,
    expression: str,
    *,
    target_url: str = "about:blank",
    timeout_seconds: float = 10.0,
    command_id: int = 942,
) -> Any:
    """Evaluate a silent expression on a page target without enabling CDP domains.

    Prefer returnByValue-friendly expressions. Does not call Runtime.enable.
    """
    timeout_seconds = _positive_finite_seconds(timeout_seconds, label="CDP evaluate")
    if not isinstance(expression, str) or not expression:
        raise ContractError("CDP evaluate expression is invalid")
    try:
        expression_bytes = len(expression.encode("utf-8"))
    except UnicodeEncodeError:
        raise ContractError("CDP evaluate expression is invalid UTF-8 text") from None
    if expression_bytes > _MAX_CDP_EXPRESSION_BYTES:
        raise ContractError("CDP evaluate expression exceeds its byte limit")
    _validate_command_id(command_id)
    deadline = time.monotonic() + timeout_seconds
    websocket_url = _page_websocket_url(
        cdp_endpoint,
        target_url,
        _remaining_deadline_seconds(deadline, label="CDP evaluate"),
    )
    response = _websocket_json_command(
        websocket_url,
        {
            "id": command_id,
            "method": "Runtime.evaluate",
            "params": {
                "expression": expression,
                "returnByValue": True,
                "silent": True,
                "awaitPromise": False,
            },
        },
        _remaining_deadline_seconds(deadline, label="CDP evaluate"),
    )
    return _validated_evaluate_value(response)


def _validated_evaluate_value(response: object) -> Any:
    if not isinstance(response, dict) or "error" in response:
        raise ContractError("CDP evaluate response is invalid")
    envelope = response.get("result")
    if not isinstance(envelope, dict):
        raise ContractError("CDP evaluate response is invalid")
    if "exceptionDetails" in envelope:
        raise ContractError("CDP evaluate reported an exception")
    result = envelope.get("result")
    if not isinstance(result, dict):
        raise ContractError("CDP evaluate response is invalid")
    if result.get("subtype") == "error":
        raise ContractError("CDP evaluate returned an error object")
    result_type = result.get("type")
    if result_type == "undefined" or "value" not in result:
        raise ContractError("CDP evaluate returned no value")
    value = result["value"]
    subtype = result.get("subtype")
    if (subtype == "array" and not (result_type == "object" and isinstance(value, list))) or (
        subtype == "null" and not (result_type == "object" and value is None)
    ):
        raise ContractError("CDP evaluate remote value is invalid")
    type_matches = (
        (result_type == "string" and isinstance(value, str))
        or (result_type == "boolean" and type(value) is bool)
        or (
            result_type == "number"
            and is_finite_number(value)
            and -_MAX_BINARY64 <= value <= _MAX_BINARY64
        )
        or (
            result_type == "object"
            and (value is None or isinstance(value, (dict, list)))
        )
    )
    if not type_matches:
        raise ContractError("CDP evaluate remote value is invalid")
    return value


def navigate_managed_page(
    cdp_endpoint: str,
    destination_url: str,
    *,
    current_target_url: str,
    timeout_seconds: float = 10.0,
    command_id: int = 943,
) -> bool:
    """Navigate the managed page only between inert data and owned loopback URLs."""
    timeout_seconds = _positive_finite_seconds(timeout_seconds, label="CDP navigate")
    if not isinstance(destination_url, str) or not destination_url:
        raise ContractError("CDP navigation destination is invalid")
    try:
        destination_bytes = destination_url.encode("utf-8", errors="strict")
    except UnicodeEncodeError:
        raise ContractError("CDP navigation destination is invalid") from None
    if len(destination_bytes) > 65_536 or any(
        ord(character) < 0x20 or ord(character) == 0x7F for character in destination_url
    ):
        raise ContractError("CDP navigation destination is invalid")
    try:
        parsed = urlsplit(destination_url)
        port = parsed.port
    except (UnicodeError, ValueError):
        raise ContractError("CDP navigation destination is invalid") from None
    owned_loopback = bool(
        parsed.scheme == "http"
        and parsed.hostname in {"127.0.0.1", "::1"}
        and parsed.username is None
        and parsed.password is None
        and isinstance(port, int)
        and 1 <= port <= 65_535
    )
    inert_data = False
    if destination_url.startswith("data:text/html,"):
        # This helper calls its data-page option inert. A MIME prefix alone says
        # nothing about executable HTML, so admit only a plain title document.
        document = unquote_to_bytes(destination_url[len("data:text/html,"):])
        inert_data = re.fullmatch(
            rb"<title>[A-Za-z0-9][A-Za-z0-9 ._-]{0,255}</title>", document
        ) is not None
    if not (owned_loopback or inert_data):
        raise ContractError(
            "CDP navigation destination must be inert data HTML or owned loopback HTTP"
        )
    _validate_command_id(command_id)
    deadline = time.monotonic() + timeout_seconds
    websocket_url = _page_websocket_url(
        cdp_endpoint,
        current_target_url,
        _remaining_deadline_seconds(deadline, label="CDP navigate"),
    )
    response = _websocket_json_command(
        websocket_url,
        {
            "id": command_id,
            "method": "Page.navigate",
            "params": {"url": destination_url},
        },
        _remaining_deadline_seconds(deadline, label="CDP navigate"),
    )
    result = response.get("result") if isinstance(response, dict) else None
    if not isinstance(result, dict):
        raise ContractError("CDP navigation response is invalid")
    error_text = result.get("errorText")
    if error_text is not None and (not isinstance(error_text, str) or error_text):
        raise ContractError("CDP navigation was not accepted")
    frame_id = result.get("frameId")
    if not isinstance(frame_id, str) or len(frame_id) > 256 or not _is_visible_ascii(frame_id):
        raise ContractError("CDP navigation response is invalid")
    return True


def realize_native_viewport(
    cdp_endpoint: str,
    target_url: str,
    width: int,
    height: int,
    timeout_seconds: float = 10.0,
    stable_seconds: float = 0.5,
) -> dict[str, int]:
    """Resize the owned native window, then verify its actual content size.

    Browser.setContentsSize accounts for the real browser chrome. It does not
    install page overrides or change device metrics. Discovery binds every
    command to the already-owned startup target and the existing loopback
    transport. No CDP domain is enabled.

    stable_seconds is the measured interval the requested content size must
    hold before readiness is published. The default 0.5s guards against headed
    toolbar startup animation momentarily matching and then changing; headless
    launches have no such animation and may pass a shorter interval.
    """
    timeout_seconds = _positive_finite_seconds(timeout_seconds, label="CDP viewport")
    if type(stable_seconds) is not float or not 0.05 <= stable_seconds <= 5.0:
        raise ContractError("native viewport stability interval is invalid")
    if any(type(value) is not int or not 200 <= value <= 10000 for value in (width, height)):
        raise ContractError("native viewport dimensions are invalid")
    deadline = time.monotonic() + timeout_seconds
    websocket_url = _page_websocket_url(
        cdp_endpoint, target_url,
        _remaining_deadline_seconds(deadline, label="CDP viewport"),
    )

    def command(method: str, params: dict[str, Any], command_id: int) -> dict:
        response = _websocket_json_command(
            websocket_url, {"id": command_id, "method": method, "params": params},
            _remaining_deadline_seconds(deadline, label="CDP viewport"),
        )
        if not isinstance(response, dict) or "error" in response or not isinstance(response.get("result"), dict):
            raise ContractError("native viewport command failed")
        return response

    window_id = None
    attempts = 0
    last_resize = -1.0
    stable_since = None
    command("Page.bringToFront", {}, 950)
    while True:
        response = command("Runtime.evaluate", {
            "expression": "({width:innerWidth,height:innerHeight,outerWidth,outerHeight})",
            "returnByValue": True, "silent": True,
        }, 951)
        observed = _validated_evaluate_value(response)
        if (not isinstance(observed, dict) or set(observed) != {"width", "height", "outerWidth", "outerHeight"}
                or any(type(value) is not int or not 0 <= value <= 100000 for value in observed.values())):
            raise ContractError("native viewport observation is invalid")
        geometry_ready = all(observed.values())
        matches = geometry_ready and observed['width'] == width and observed['height'] == height
        if matches:
            if stable_since is None:
                stable_since = time.monotonic()
            # Toolbar startup animation can momentarily hit the requested size
            # and subsequently change it. Require a measured stable interval.
            if time.monotonic() - stable_since >= stable_seconds:
                _remaining_deadline_seconds(deadline, label="CDP viewport")
                return {"width": observed["width"], "height": observed["height"]}
        else:
            stable_since = None
        # Renderer outer dimensions can remain zero until the native window is
        # resized. Use independently measured browser bounds to break that
        # startup stall; never treat a resize acknowledgment as page readiness.
        if not matches and observed['width'] > 0 and observed['height'] > 0 and attempts < 3 and time.monotonic() - last_resize >= 0.2:
            native_ready = geometry_ready
            if window_id is None:
                window = command("Browser.getWindowForTarget", {}, 952)["result"]
                candidate_id = window.get("windowId")
                if (type(candidate_id) is not int or not 1 <= candidate_id <= 2147483647
                        or not isinstance(window.get("bounds"), dict)
                        or window["bounds"].get("windowState") != "normal"):
                    raise ContractError("native viewport window is unavailable")
                native_ready = native_ready or all(
                    type(window['bounds'].get(dimension)) is int
                    and 0 < window['bounds'][dimension] <= 100000
                    for dimension in ('width', 'height')
                )
                if native_ready:
                    window_id = candidate_id
            if window_id is not None:
                command("Browser.setContentsSize", {"windowId": window_id, "width": width, "height": height}, 953)
                attempts += 1
                last_resize = time.monotonic()
        time.sleep(min(0.05, _remaining_deadline_seconds(deadline, label="CDP viewport")))


@contextmanager
def temporary_startup_page(
    cdp_endpoint: str, fixture_path: Path, *, timeout_seconds: float = 10.0,
) -> Iterator[str]:
    """Own one temporary background page for a local startup check.

    The caller owns the temporary local document. Only the exact target returned by
    Target.createTarget is closed; restored/user tabs are never selected.
    Cleanup has a separate five-second allowance, including on check failure.
    This helper is used before launch publication, whose abort owns the browser
    if target creation/cleanup cannot be confirmed.
    """
    timeout_seconds = _positive_finite_seconds(timeout_seconds, label="CDP startup check")
    if (not isinstance(fixture_path, Path) or not fixture_path.is_absolute()
            or fixture_path.name != "profile.html"
            or re.fullmatch(r"browser-core-startup-[A-Za-z0-9_-]{1,80}", fixture_path.parent.name) is None
            or '..' in fixture_path.parts):
        raise ContractError("startup fixture path is invalid")
    fixture_url = fixture_path.as_uri()
    if urlsplit(fixture_url).netloc:
        raise ContractError("startup fixture must be a local file")
    deadline = time.monotonic() + timeout_seconds
    websocket = _browser_websocket_url(
        cdp_endpoint, _remaining_deadline_seconds(deadline, label="CDP startup check"),
    )
    response = _websocket_json_command(websocket, {
        "id": 960, "method": "Target.createTarget",
        "params": {"url": fixture_url, "background": True},
    }, _remaining_deadline_seconds(deadline, label="CDP startup check"))
    result = response.get("result") if isinstance(response, dict) and "error" not in response else None
    target_id = result.get("targetId") if isinstance(result, dict) else None
    if not isinstance(target_id, str) or re.fullmatch(r"[A-Za-z0-9_-]{1,256}", target_id) is None:
        raise ContractError("startup fixture page could not be created")
    try:
        yield fixture_url
    finally:
        closed = _websocket_json_command(websocket, {
            "id": 961, "method": "Target.closeTarget", "params": {"targetId": target_id},
        }, 5.0)
        if (not isinstance(closed, dict) or "error" in closed
                or not isinstance(closed.get("result"), dict)
                or closed["result"].get("success") is not True):
            raise ContractError("startup fixture page cleanup failed")


def _valid_runtime_identity_text(value: Any, *, maximum: int) -> bool:
    if (
        not isinstance(value, str)
        or not value
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        return False
    try:
        encoded = value.encode("utf-8", errors="strict")
    except UnicodeEncodeError:
        return False
    return len(encoded) <= maximum


def observe_runtime_identity(
    cdp_endpoint: str,
    target_url: str,
    timeout_seconds: float = 3.0,
) -> dict[str, Any]:
    """Read only locale/time-zone fields without enabling any CDP domain."""
    timeout_seconds = _positive_finite_seconds(timeout_seconds, label="CDP identity")
    expression = (
        "JSON.stringify({locale:Intl.DateTimeFormat().resolvedOptions().locale,"
        "languages:Array.from(navigator.languages||[]),"
        "timezone:Intl.DateTimeFormat().resolvedOptions().timeZone})"
    )
    raw = evaluate_page_expression(
        cdp_endpoint,
        expression,
        target_url=target_url,
        timeout_seconds=timeout_seconds,
        command_id=941,
    )
    observed = (
        _decode_strict_cdp_text(raw, label="CDP runtime identity response")
        if isinstance(raw, str)
        else raw
    )
    if not isinstance(observed, dict):
        raise ContractError("CDP runtime identity response is invalid")
    locale = observed.get("locale")
    languages = observed.get("languages")
    timezone = observed.get("timezone")
    if not _valid_runtime_identity_text(locale, maximum=64):
        raise ContractError("observed browser locale is invalid")
    if (
        not isinstance(languages, list)
        or not languages
        or len(languages) > 16
        or not all(_valid_runtime_identity_text(value, maximum=64) for value in languages)
        or len(set(languages)) != len(languages)
    ):
        raise ContractError("observed browser languages are invalid")
    if not _valid_runtime_identity_text(timezone, maximum=128):
        raise ContractError("observed browser time zone is invalid")
    return {
        "schema": "browser-core.runtime-identity-observation/1",
        "locale": locale,
        "languages": languages,
        "timezone": timezone,
        "cdp_domains_enabled": [],
    }


def request_browser_close(cdp_endpoint: str, timeout_seconds: float = 3.0) -> None:
    """Request a clean Chromium shutdown without exposing a general CDP client."""
    timeout_seconds = _positive_finite_seconds(timeout_seconds, label="CDP close")
    deadline = time.monotonic() + timeout_seconds
    websocket_url = _browser_websocket_url(
        cdp_endpoint,
        _remaining_deadline_seconds(deadline, label="CDP close"),
    )
    remaining = _remaining_deadline_seconds(deadline, label="CDP close")
    with _websocket_connection(
        websocket_url,
        remaining,
        os_error_label="cannot request graceful Chromium shutdown",
    ) as (connection, reader):
        command = json.dumps(
            {"id": 1, "method": "Browser.close"}, separators=(",", ":")
        ).encode("utf-8")
        frame = _masked_text_frame(command, _websocket_random_bytes(4))
        remaining = _remaining_deadline_seconds(deadline, label="CDP close")
        connection.settimeout(remaining)
        _send_websocket_bytes(connection, frame)
        # Do not close the client socket immediately after send. On a busy
        # multi-process trace that can race command dispatch and force the
        # lifecycle fallback to kill Chromium before Perfetto flushes.
        # Browser.close may acknowledge with a result or close/reset the
        # channel as the browser exits; both prove the complete frame was
        # accepted by the validated browser endpoint.
        message_count = 0
        while True:
            message_count += 1
            if message_count > _MAX_CDP_MESSAGES_PER_COMMAND:
                raise ContractError("CDP WebSocket returned too many messages")
            try:
                raw = _read_server_text_message(reader, connection)
            except ConnectionResetError:
                _remaining_deadline_seconds(deadline, label="CDP close")
                break
            except ContractError as exc:
                if "closed before" in str(exc):
                    _remaining_deadline_seconds(deadline, label="CDP close")
                    break
                raise
            result = _decode_strict_cdp_text(raw, label="CDP Browser.close")
            if not _response_matches_command_id(result, 1):
                continue
            if "error" in result:
                raise ContractError("CDP Browser.close was rejected")
            if not isinstance(result.get("result"), dict):
                raise ContractError("CDP Browser.close response is invalid")
            _remaining_deadline_seconds(deadline, label="CDP close")
            break
    _remaining_deadline_seconds(deadline, label="CDP close")
