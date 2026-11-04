from __future__ import annotations

import base64
import hashlib
import io
import json
import threading
import urllib.error
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace

import pytest

from browser_core import cdp as cdp_module
from browser_core.cdp import (
    _masked_text_frame,
    observe_runtime_identity,
    request_browser_close,
    wait_for_page_target,
)
from browser_core.contracts import ContractError


class ChunkedSocket:
    def __init__(self, chunks: list[bytes]) -> None:
        self.chunks = [bytearray(chunk) for chunk in chunks]
        self.sent: list[bytes] = []
        self.recv_calls = 0
        self.closed = False
        self.timeouts: list[float] = []

    @property
    def remaining_bytes(self) -> int:
        return sum(len(chunk) for chunk in self.chunks)

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        self.closed = True
        return False

    def close(self) -> None:
        self.closed = True

    def settimeout(self, timeout: float) -> None:
        assert timeout > 0
        self.timeouts.append(timeout)

    def sendall(self, value: bytes) -> None:
        self.sent.append(value)

    def recv(self, maximum: int) -> bytes:
        self.recv_calls += 1
        if not self.chunks:
            return b""
        chunk = self.chunks[0]
        result = bytes(chunk[:maximum])
        del chunk[:maximum]
        if not chunk:
            self.chunks.pop(0)
        return result


def websocket_handshake() -> bytes:
    key = base64.b64encode(bytes(16)).decode("ascii")
    accept = base64.b64encode(
        hashlib.sha1((key + cdp_module._WEBSOCKET_GUID).encode("ascii")).digest()
    )
    return (
        b"HTTP/1.1 101 Switching Protocols\r\n"
        b"Upgrade: websocket\r\nConnection: Upgrade\r\n"
        b"Sec-WebSocket-Accept: " + accept + b"\r\n\r\n"
    )


@pytest.mark.parametrize("body", [bytearray(b"private"), "private", b""])
def test_websocket_write_gate_requires_nonempty_exact_bytes(body) -> None:
    class Connection:
        def sendall(self, _body):
            pytest.fail("invalid write body reached transport")

    with pytest.raises(ContractError, match="write bytes are invalid") as failure:
        cdp_module._send_websocket_bytes(Connection(), body)
    assert "private" not in str(failure.value)


def test_websocket_write_gate_rejects_partial_write_sentinels() -> None:
    class Connection:
        def sendall(self, _body):
            return 1

    with pytest.raises(ContractError, match="transport write is invalid"):
        cdp_module._send_websocket_bytes(Connection(), b"frame")


def server_frame(payload: bytes, *, opcode: int = 1, final: bool = True) -> bytes:
    first = (0x80 if final else 0) | opcode
    length = len(payload)
    if length < 126:
        return bytes((first, length)) + payload
    if length <= 0xFFFF:
        return bytes((first, 126)) + length.to_bytes(2, "big") + payload
    return bytes((first, 127)) + length.to_bytes(8, "big") + payload


def install_socket(monkeypatch, connection: ChunkedSocket) -> None:
    monkeypatch.setattr(
        cdp_module.socket,
        "create_connection",
        lambda *_args, **_kwargs: connection,
    )
    monkeypatch.setattr(cdp_module.os, "urandom", lambda length: bytes(length))


def test_masked_text_frame_round_trips_short_payload() -> None:
    payload = b'{"id":1,"method":"Browser.close"}'
    mask = b"abcd"
    frame = _masked_text_frame(payload, mask)
    assert frame[0] == 0x81
    assert frame[1] == 0x80 | len(payload)
    assert frame[2:6] == mask
    assert (
        bytes(value ^ mask[index % 4] for index, value in enumerate(frame[6:]))
        == payload
    )


def test_masked_text_frame_requires_four_byte_mask() -> None:
    with pytest.raises(ContractError, match="frame mask"):
        _masked_text_frame(b"value", b"bad")


@pytest.mark.parametrize(
    ("payload", "mask", "opcode", "message"),
    [
        ("private", b"abcd", 1, "payload"),
        (b"value", bytearray(b"abcd"), 1, "mask"),
        (b"value", b"abcd", True, "opcode"),
        (b"value", b"abcd", 2, "opcode"),
    ],
)
def test_masked_frame_normalizes_invalid_runtime_inputs(
    payload, mask, opcode, message
) -> None:
    with pytest.raises(ContractError, match=message) as failure:
        cdp_module._masked_frame(payload, mask, opcode=opcode)
    assert "private" not in str(failure.value)


@pytest.mark.parametrize("value", [bytearray(b"x" * 4), b"x" * 3, b"x" * 5])
def test_websocket_randomness_requires_exact_bytes(
    monkeypatch: pytest.MonkeyPatch, value
) -> None:
    monkeypatch.setattr(cdp_module.os, "urandom", lambda _count: value)
    with pytest.raises(ContractError, match="randomness output"):
        cdp_module._websocket_random_bytes(4)


def test_websocket_randomness_normalizes_provider_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail(_count):
        raise OSError("private-randomness-provider")

    monkeypatch.setattr(cdp_module.os, "urandom", fail)
    with pytest.raises(ContractError, match="generation failed") as failure:
        cdp_module._websocket_random_bytes(4)
    assert "private-randomness-provider" not in str(failure.value)


def test_websocket_command_preserves_coalesced_upgrade_frame(monkeypatch) -> None:
    response = {"id": 7, "result": {"value": "ok"}}
    connection = ChunkedSocket(
        [websocket_handshake() + server_frame(json.dumps(response).encode("utf-8"))]
    )
    install_socket(monkeypatch, connection)
    result = cdp_module._websocket_json_command(
        "ws://127.0.0.1:9222/devtools/page/owned",
        {"id": 7, "method": "Runtime.evaluate"},
        1.0,
    )
    assert result == response
    assert connection.recv_calls == 1
    assert connection.remaining_bytes == 0
    assert connection.closed


def test_websocket_command_rejects_response_after_socket_cleanup_deadline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    now = [0.0]
    monkeypatch.setattr(cdp_module.time, "monotonic", lambda: now[0])
    response = {"id": 7, "result": {"value": "ok"}}

    class LateCloseSocket(ChunkedSocket):
        def close(self) -> None:
            now[0] = 2.0
            super().close()

    connection = LateCloseSocket(
        [websocket_handshake() + server_frame(json.dumps(response).encode("utf-8"))]
    )
    install_socket(monkeypatch, connection)
    with pytest.raises(cdp_module.CdpCommandResponseTimeout):
        cdp_module._websocket_json_command(
            "ws://127.0.0.1:9222/devtools/page/owned",
            {"id": 7, "method": "Runtime.evaluate"},
            1.0,
        )
    assert connection.closed


def test_websocket_command_types_a_post_send_response_timeout(monkeypatch) -> None:
    class ResponseTimeoutSocket(ChunkedSocket):
        def recv(self, maximum: int) -> bytes:
            if self.chunks:
                return super().recv(maximum)
            raise TimeoutError("private renderer timeout detail")

    connection = ResponseTimeoutSocket([websocket_handshake()])
    install_socket(monkeypatch, connection)

    with pytest.raises(cdp_module.CdpCommandResponseTimeout) as raised:
        cdp_module._websocket_json_command(
            "ws://127.0.0.1:9222/devtools/page/owned",
            {"id": 7, "method": "Runtime.evaluate"},
            1.0,
        )

    assert str(raised.value) == "CDP command response deadline expired"
    assert "private renderer timeout detail" not in str(raised.value)
    assert connection.closed


def test_websocket_pong_write_timeout_is_not_a_command_response_timeout(
    monkeypatch,
) -> None:
    class PongTimeoutSocket(ChunkedSocket):
        def sendall(self, value: bytes) -> None:
            if len(self.sent) == 2:
                raise TimeoutError("private pong write timeout")
            super().sendall(value)

    connection = PongTimeoutSocket(
        [websocket_handshake() + server_frame(b"probe", opcode=9)]
    )
    install_socket(monkeypatch, connection)

    with pytest.raises(ContractError) as raised:
        cdp_module._websocket_json_command(
            "ws://127.0.0.1:9222/devtools/page/owned",
            {"id": 7, "method": "Runtime.evaluate"},
            1.0,
        )

    assert type(raised.value) is ContractError
    assert "private pong write timeout" not in str(raised.value)
    assert connection.closed


def test_websocket_command_rejects_duplicate_json_members(monkeypatch) -> None:
    connection = ChunkedSocket(
        [websocket_handshake() + server_frame(b'{"id":7,"id":7,"result":{}}')]
    )
    install_socket(monkeypatch, connection)

    with pytest.raises(ContractError, match="invalid JSON"):
        cdp_module._websocket_json_command(
            "ws://127.0.0.1:9222/devtools/page/owned",
            {"id": 7, "method": "Runtime.evaluate"},
            1.0,
        )


@pytest.mark.parametrize(
    "payload",
    [
        b'{"id":7,"error":{"message":"private-protocol-detail"}}',
        b'{"id":7}',
        b'{"id":7,"result":null}',
        b'{"id":7,"result":[]}',
    ],
)
def test_websocket_command_rejects_error_and_invalid_result_envelopes(
    monkeypatch, payload: bytes
) -> None:
    connection = ChunkedSocket([websocket_handshake() + server_frame(payload)])
    install_socket(monkeypatch, connection)

    with pytest.raises(ContractError) as raised:
        cdp_module._websocket_json_command(
            "ws://127.0.0.1:9222/devtools/page/owned",
            {"id": 7, "method": "Runtime.evaluate"},
            1.0,
        )
    assert "private-protocol-detail" not in str(raised.value)


def test_websocket_command_requires_exact_integer_response_id(monkeypatch) -> None:
    boolean_id = server_frame(b'{"id":true,"result":{"value":"wrong"}}')
    exact_id = server_frame(b'{"id":1,"result":{"value":"owned"}}')
    connection = ChunkedSocket([websocket_handshake() + boolean_id + exact_id])
    install_socket(monkeypatch, connection)

    assert cdp_module._websocket_json_command(
        "ws://127.0.0.1:9222/devtools/page/owned",
        {"id": 1, "method": "Runtime.evaluate"},
        1.0,
    ) == {"id": 1, "result": {"value": "owned"}}
    assert connection.remaining_bytes == 0


def test_cdp_command_encoder_rejects_non_finite_params() -> None:
    with pytest.raises(ContractError, match="bounded JSON"):
        cdp_module._encode_cdp_command(
            {
                "id": 7,
                "method": "Input.dispatchMouseEvent",
                "params": {"x": float("nan")},
            }
        )


def test_websocket_command_rejects_extreme_nesting_before_transport(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        cdp_module.socket,
        "create_connection",
        lambda *_args, **_kwargs: pytest.fail("invalid command reached transport"),
    )
    deeply_nested: object = 0
    for _ in range(2_000):
        deeply_nested = [deeply_nested]

    with pytest.raises(ContractError, match="bounded JSON"):
        cdp_module._websocket_json_command(
            "ws://127.0.0.1:9222/devtools/page/owned",
            {
                "id": 7,
                "method": "Runtime.evaluate",
                "params": {"value": deeply_nested},
            },
            1.0,
        )


def test_websocket_command_handles_fragmented_message_and_ping(monkeypatch) -> None:
    first = server_frame(b'{"id":7,', final=False)
    ping = server_frame(b"probe", opcode=9)
    final = server_frame(b'"result":{}}', opcode=0)
    header = websocket_handshake()
    connection = ChunkedSocket(
        [
            header[:13],
            header[13:-2],
            header[-2:] + first[:1],
            first[1:] + ping + final,
        ]
    )
    install_socket(monkeypatch, connection)
    assert cdp_module._websocket_json_command(
        "ws://127.0.0.1:9222/devtools/page/owned",
        {"id": 7, "method": "Runtime.evaluate"},
        1.0,
    ) == {"id": 7, "result": {}}
    pong = connection.sent[-1]
    assert pong[0] == 0x8A
    mask = pong[2:6]
    assert (
        bytes(value ^ mask[index % 4] for index, value in enumerate(pong[6:]))
        == b"probe"
    )


def test_websocket_fragment_limit_rejects_before_payload_read() -> None:
    connection = ChunkedSocket(
        [
            server_frame(b"abc", final=False),
            server_frame(b"xy", opcode=0),
        ]
    )
    reader = cdp_module._BoundedSocketReader(connection)
    with pytest.raises(ContractError, match="response is too large"):
        cdp_module._read_server_text_message(reader, connection, maximum=4)
    assert connection.remaining_bytes == 2


def test_websocket_rejects_unbounded_empty_data_fragments(monkeypatch) -> None:
    monkeypatch.setattr(cdp_module, "_MAX_CDP_DATA_FRAMES", 2, raising=False)
    connection = ChunkedSocket(
        [
            server_frame(b"", final=False)
            + server_frame(b"", opcode=0, final=False)
            + server_frame(b"", opcode=0)
        ]
    )
    reader = cdp_module._BoundedSocketReader(connection)
    with pytest.raises(ContractError, match="too many data frames"):
        cdp_module._read_server_text_message(reader, connection)


def test_websocket_handshake_bound_and_absolute_deadline(monkeypatch) -> None:
    exact = ChunkedSocket([b"a" * 8 + b"\r\n\r\n"])
    reader = cdp_module._BoundedSocketReader(exact)
    assert reader.read_until(b"\r\n\r\n", maximum=8) == b"a" * 8

    overflow = ChunkedSocket([b"a" * 9 + b"\r\n\r\n"])
    with pytest.raises(ContractError, match="handshake response is too large"):
        cdp_module._BoundedSocketReader(overflow).read_until(
            b"\r\n\r\n",
            maximum=8,
        )

    expired = ChunkedSocket([b"x"])
    monkeypatch.setattr(cdp_module.time, "monotonic", lambda: 2.0)
    with pytest.raises(TimeoutError, match="deadline expired"):
        cdp_module._BoundedSocketReader(expired, deadline=1.0).read_exact(1)
    assert expired.remaining_bytes == 1


def test_websocket_reader_rejects_data_returned_after_deadline(monkeypatch) -> None:
    clock = [0.0]
    monkeypatch.setattr(cdp_module.time, "monotonic", lambda: clock[0])

    class Connection:
        def settimeout(self, _timeout: float) -> None:
            return None

        def recv(self, _maximum: int) -> bytes:
            clock[0] = 2.0
            return b"x"

    with pytest.raises(TimeoutError, match="deadline expired"):
        cdp_module._BoundedSocketReader(
            Connection(), deadline=1.0  # type: ignore[arg-type]
        ).read_exact(1)


@pytest.mark.parametrize("next_read", ["exact", "until"])
def test_websocket_reader_rejects_buffered_data_after_deadline(
    monkeypatch: pytest.MonkeyPatch, next_read: str
) -> None:
    clock = [0.0]
    monkeypatch.setattr(cdp_module.time, "monotonic", lambda: clock[0])
    connection = ChunkedSocket([b"first\r\n\r\nsecond\r\n\r\n"])
    reader = cdp_module._BoundedSocketReader(connection, deadline=1.0)
    assert reader.read_until(b"\r\n\r\n", maximum=16) == b"first"
    clock[0] = 2.0

    with pytest.raises(TimeoutError, match="deadline expired"):
        if next_read == "exact":
            reader.read_exact(1)
        else:
            reader.read_until(b"\r\n\r\n", maximum=16)


def test_websocket_reader_rejects_nonbyte_socket_output() -> None:
    class Connection:
        def recv(self, _maximum: int) -> bytearray:
            return bytearray(b"x")

    with pytest.raises(ContractError, match="invalid bytes"):
        cdp_module._BoundedSocketReader(Connection()).read_exact(1)  # type: ignore[arg-type]


def test_websocket_control_and_message_counts_are_bounded(monkeypatch) -> None:
    monkeypatch.setattr(cdp_module, "_MAX_CDP_CONTROL_FRAMES", 1)
    controls = ChunkedSocket(
        [server_frame(b"a", opcode=9) + server_frame(b"b", opcode=10)]
    )
    with pytest.raises(ContractError, match="too many control frames"):
        cdp_module._read_server_text_message(
            cdp_module._BoundedSocketReader(controls),
            controls,
        )

    monkeypatch.setattr(cdp_module, "_MAX_CDP_MESSAGES_PER_COMMAND", 1)
    event = server_frame(b'{"method":"Runtime.consoleAPICalled"}')
    response = server_frame(b'{"id":7,"result":{}}')
    command_socket = ChunkedSocket([websocket_handshake() + event + response])
    install_socket(monkeypatch, command_socket)
    with pytest.raises(ContractError, match="too many messages"):
        cdp_module._websocket_json_command(
            "ws://127.0.0.1:9222/devtools/page/owned",
            {"id": 7, "method": "Runtime.evaluate"},
            1.0,
        )


@pytest.mark.parametrize("length", [126, 65_536])
def test_websocket_accepts_canonical_extended_lengths(length: int) -> None:
    payload = b"x" * length
    connection = ChunkedSocket([server_frame(payload)])
    reader = cdp_module._BoundedSocketReader(connection)
    assert (
        cdp_module._read_server_text_message(
            reader,
            connection,
            maximum=length,
        )
        == payload
    )


@pytest.mark.parametrize(
    "frame",
    [
        bytes((0x81, 0x80)),
        server_frame(b"binary", opcode=2),
        server_frame(b"orphan", opcode=0),
        server_frame(b"", opcode=9, final=False),
        bytes((0x81, 126, 0, 1, ord("x"))),
        bytes((0xC1, 0)),
    ],
    ids=[
        "masked-server",
        "binary",
        "orphan-continuation",
        "fragmented-ping",
        "noncanonical-length",
        "reserved-bit",
    ],
)
def test_websocket_rejects_unsupported_frames(frame: bytes) -> None:
    connection = ChunkedSocket([frame])
    reader = cdp_module._BoundedSocketReader(connection)
    with pytest.raises(ContractError, match="unsupported frame"):
        cdp_module._read_server_text_message(reader, connection)


@pytest.mark.parametrize(
    "value",
    [
        "ws://127.0.0.1:not-a-port/devtools/page/private",
        "ws://[::1/devtools/page/private",
        "ws://user:pass@127.0.0.1:9222/devtools/page/private",
        "ws://127.0.0.1:9222/devtools/page/../private",
        "ws://127.0.0.1:9222/devtools/page/%70rivate",
        "ws://127.0.0.1:9222/devtools/page/private?secret=raw",
        "ws://127.0.0.1:9222/devtools/page/private?",
        "ws://127.0.0.1:9222/devtools/page/private#",
        "ws://127.0.0.1:9222/devtools/page/caf\N{LATIN SMALL LETTER E WITH ACUTE}",
    ],
)
def test_websocket_endpoint_rejection_is_total_and_value_free(value: str) -> None:
    with pytest.raises(ContractError) as raised:
        cdp_module._parse_loopback_websocket_url(value, expected_port=9222)
    assert str(raised.value) == "CDP WebSocket must remain on exact loopback"
    assert "private" not in str(raised.value)
    assert "secret" not in str(raised.value)


@pytest.mark.parametrize("websocket_host", ["localhost", "[::1]"])
def test_discovered_websocket_must_use_the_same_loopback_host(
    websocket_host: str,
) -> None:
    with pytest.raises(ContractError, match="exact loopback"):
        cdp_module._validate_websocket_url(
            "http://127.0.0.1:9222",
            f"ws://{websocket_host}:9222/devtools/page/owned",
        )


def test_browser_websocket_discovery_rejects_a_different_loopback_listener(
    monkeypatch,
) -> None:
    monkeypatch.setattr(
        cdp_module,
        "_read_cdp_json_url",
        lambda *_args, **_kwargs: {
            "webSocketDebuggerUrl": "ws://[::1]:9222/devtools/browser/owned"
        },
    )
    with pytest.raises(ContractError, match="exact loopback"):
        cdp_module._browser_websocket_url("http://127.0.0.1:9222", 1.0)


def test_browser_websocket_discovery_rejects_a_page_socket(monkeypatch) -> None:
    monkeypatch.setattr(
        cdp_module,
        "_read_cdp_json_url",
        lambda *_args, **_kwargs: {
            "webSocketDebuggerUrl": "ws://127.0.0.1:9222/devtools/page/owned"
        },
    )
    with pytest.raises(ContractError, match="browser target identity"):
        cdp_module._browser_websocket_url("http://127.0.0.1:9222", 1.0)


@pytest.mark.parametrize(
    "value",
    [
        "http://127.0.0.1:not-a-port",
        "http://[::1",
        "http://user:pass@127.0.0.1:9222",
        "http://127.0.0.1:9222/private",
        "http://127.0.0.1:9222?secret=raw",
        "http://127.0.0.1:9222?",
        "http://127.0.0.1:9222#",
        "https://127.0.0.1:9222",
    ],
)
def test_http_endpoint_rejection_is_total_and_value_free(value: str) -> None:
    with pytest.raises(ContractError) as raised:
        cdp_module._validated_http_endpoint(value)
    assert str(raised.value) == (
        "CDP endpoint must be credential-free loopback HTTP with an explicit port"
    )
    assert "private" not in str(raised.value)
    assert "secret" not in str(raised.value)


def test_cdp_localhost_discovery_uses_literal_loopback_before_contact(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert cdp_module._validated_http_endpoint("http://localhost:9222") == (
        "http://127.0.0.1:9222/"
    )
    opened = []

    class Response:
        def __init__(self) -> None:
            self.read_calls = 0

        def getcode(self) -> int:
            return 200

        def read(self, _maximum: int) -> bytes:
            self.read_calls += 1
            return b"{}" if self.read_calls == 1 else b""

        def close(self) -> None:
            return None

    def open_url(url: str, *, timeout: float) -> Response:
        opened.append(url)
        return Response()

    monkeypatch.setattr(cdp_module, "urlopen", open_url)
    assert cdp_module._read_cdp_json_url(
        "http://localhost:9222/json/version", timeout_seconds=1, maximum=1024
    ) == {}
    assert opened == ["http://127.0.0.1:9222/json/version"]


def test_cdp_localhost_websocket_uses_literal_loopback_before_contact(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    addresses = []

    def connect(address: object, *, timeout: float):
        addresses.append(address)
        raise OSError("test socket unavailable")

    monkeypatch.setattr(cdp_module.socket, "create_connection", connect)
    with pytest.raises(ContractError, match="CDP test connection"):
        with cdp_module._websocket_connection(
            "ws://localhost:9222/devtools/page/owned",
            1.0,
            os_error_label="CDP test connection",
        ):
            pytest.fail("failed socket opened a WebSocket")
    assert addresses == [("127.0.0.1", 9222)]


def test_invalid_websocket_endpoint_fails_before_socket_use(monkeypatch) -> None:
    monkeypatch.setattr(
        cdp_module.socket,
        "create_connection",
        lambda *_args, **_kwargs: pytest.fail("socket must not be opened"),
    )
    with pytest.raises(ContractError, match="exact loopback"):
        cdp_module._websocket_json_command(
            "ws://127.0.0.1:not-a-port/devtools/page/private",
            {"id": 7, "method": "Runtime.evaluate"},
            1.0,
        )


@pytest.mark.parametrize(
    "command",
    [
        {"id": 1, "method": "Runtime.evaluate", "params": {"x": object()}},
        {
            "id": 1,
            "method": "Runtime.evaluate",
            "params": {"x": "x" * (cdp_module._MAX_CDP_MESSAGE_BYTES + 1)},
        },
    ],
)
def test_outgoing_cdp_command_is_bounded_before_socket_use(
    monkeypatch, command
) -> None:
    monkeypatch.setattr(
        cdp_module.socket,
        "create_connection",
        lambda *_args, **_kwargs: pytest.fail("socket must not be opened"),
    )
    with pytest.raises(ContractError, match="CDP command"):
        cdp_module._websocket_json_command(
            "ws://127.0.0.1:9222/devtools/page/owned",
            command,
            1.0,
        )


@pytest.mark.parametrize(
    "command",
    [
        {"method": "Runtime.evaluate"},
        {"id": True, "method": "Runtime.evaluate"},
        {"id": 0, "method": "Runtime.evaluate"},
        {"id": 1, "method": "Runtime evaluate"},
        {"id": 1, "method": "Runtime.evaluate", "params": []},
    ],
)
def test_outgoing_cdp_command_envelope_fails_before_socket_use(
    monkeypatch, command
) -> None:
    monkeypatch.setattr(
        cdp_module.socket,
        "create_connection",
        lambda *_args, **_kwargs: pytest.fail("socket must not be opened"),
    )
    with pytest.raises(ContractError, match="CDP command"):
        cdp_module._websocket_json_command(
            "ws://127.0.0.1:9222/devtools/page/owned",
            command,
            1.0,
        )


@pytest.mark.parametrize(
    ("header", "error"),
    [
        (
            websocket_handshake().replace(b"HTTP/1.1 101 ", b"HTTP/1.0 101 "),
            "upgrade was rejected",
        ),
        (
            websocket_handshake().replace(b"Upgrade: websocket\r\n", b""),
            "handshake validation failed",
        ),
        (
            websocket_handshake().replace(
                b"Connection: Upgrade\r\n",
                b"Connection: Upgrade\r\nConnection: Upgrade\r\n",
            ),
            "handshake validation failed",
        ),
        (
            websocket_handshake().replace(
                b"Sec-WebSocket-Accept: ",
                b"Sec-WebSocket-Accept: private\r\nSec-WebSocket-Accept: ",
            ),
            "handshake validation failed",
        ),
        (
            websocket_handshake().replace(
                b"Upgrade: websocket",
                b"Upgrade: websocket\x00private",
            ),
            "handshake validation failed",
        ),
        (
            websocket_handshake().replace(
                b"\r\n\r\n",
                b"\r\nSec-WebSocket-Protocol: private\r\n\r\n",
            ),
            "handshake validation failed",
        ),
    ],
    ids=[
        "status",
        "missing-upgrade",
        "duplicate-connection",
        "duplicate-accept",
        "control-byte",
        "unsolicited-subprotocol",
    ],
)
def test_websocket_upgrade_rejects_ambiguous_headers(
    header: bytes,
    error: str,
) -> None:
    key = base64.b64encode(bytes(16)).decode("ascii")
    with pytest.raises(ContractError, match=error) as raised:
        cdp_module._validate_websocket_upgrade(header[:-4], key)
    assert "private" not in str(raised.value)


def test_websocket_upgrade_accepts_case_insensitive_required_tokens() -> None:
    header = websocket_handshake().replace(
        b"Upgrade: websocket\r\nConnection: Upgrade",
        b"uPgRaDe: WebSocket\r\ncOnNeCtIoN: keep-alive, Upgrade",
    )
    key = base64.b64encode(bytes(16)).decode("ascii")
    cdp_module._validate_websocket_upgrade(header[:-4], key)


class JsonResponse:
    def __init__(self, body: bytes) -> None:
        self.body = body
        self.offset = 0
        self.read_sizes: list[int] = []
        self.closed = False

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def close(self) -> None:
        self.closed = True

    def getcode(self) -> int:
        return 200

    def read(self, maximum: int) -> bytes:
        self.read_sizes.append(maximum)
        block = self.body[self.offset : self.offset + maximum]
        self.offset += len(block)
        return block


def test_cdp_discovery_json_reader_proves_exact_eof_and_utf8() -> None:
    exact = JsonResponse(b"[]" + b" " * 6)
    assert cdp_module._read_bounded_json_response(exact, maximum=8) == []
    assert exact.read_sizes == [9, 1]

    overflow = JsonResponse(b"[]" + b" " * 6 + b"x")
    with pytest.raises(ContractError, match="response is too large"):
        cdp_module._read_bounded_json_response(overflow, maximum=8)
    assert overflow.read_sizes == [9]

    invalid_utf8 = JsonResponse(b'[{"private":"\xff"}]')
    with pytest.raises(ContractError) as raised:
        cdp_module._read_bounded_json_response(invalid_utf8, maximum=64)
    assert str(raised.value) == "CDP discovery response is invalid JSON"
    assert "private" not in str(raised.value)

    class ShortResponse:
        def __init__(self) -> None:
            self.chunks = [b"[", b"]", b""]

        def read(self, _maximum: int) -> bytes:
            return self.chunks.pop(0)

    assert (
        cdp_module._read_bounded_json_response(
            ShortResponse(),
            maximum=8,
        )
        == []
    )

    duplicate = JsonResponse(
        b'{"webSocketDebuggerUrl":"first","webSocketDebuggerUrl":"second"}'
    )
    with pytest.raises(ContractError, match="invalid JSON"):
        cdp_module._read_bounded_json_response(duplicate, maximum=128)


def test_cdp_discovery_reader_rejects_complete_json_in_short_http_body() -> None:
    class ShortDeclaredBody(JsonResponse):
        def __init__(self) -> None:
            super().__init__(b"[]")
            self.length = 4

        def read1(self, maximum: int) -> bytes:
            block = self.read(maximum)
            self.length -= len(block)
            return block

    response = ShortDeclaredBody()
    with pytest.raises(ContractError, match="declared length"):
        cdp_module._read_bounded_json_response(response, maximum=8)


def test_cdp_discovery_reader_rejects_unbounded_tiny_fragments(monkeypatch) -> None:
    monkeypatch.setattr(cdp_module, "_MAX_CDP_DISCOVERY_READ_CALLS", 2, raising=False)

    class TinyChunks:
        def __init__(self) -> None:
            self.chunks = [b"[", b"]", b""]

        def read1(self, _maximum: int) -> bytes:
            return self.chunks.pop(0)

    with pytest.raises(ContractError, match="too many fragments"):
        cdp_module._read_bounded_json_response(TinyChunks(), maximum=64)


def test_browser_discovery_rejects_valid_prefix_overflow(monkeypatch) -> None:
    maximum = 64 * 1024
    body = b"{}" + b" " * (maximum - 2) + b"private"
    response = JsonResponse(body)
    monkeypatch.setattr(cdp_module, "urlopen", lambda *_a, **_k: response)
    with pytest.raises(ContractError) as raised:
        cdp_module._browser_websocket_url("http://127.0.0.1:9222", 1.0)
    assert str(raised.value) == "CDP discovery response is too large"
    assert response.read_sizes == [maximum + 1]
    assert "private" not in str(raised.value)


def test_browser_discovery_accepts_exact_bounded_document(monkeypatch) -> None:
    document = {"webSocketDebuggerUrl": ("ws://127.0.0.1:9222/devtools/browser/owned")}
    response = JsonResponse(json.dumps(document).encode("utf-8"))
    monkeypatch.setattr(cdp_module, "urlopen", lambda *_a, **_k: response)
    assert (
        cdp_module._browser_websocket_url(
            "http://127.0.0.1:9222",
            1.0,
        )
        == document["webSocketDebuggerUrl"]
    )
    assert response.read_sizes[0] == 64 * 1024 + 1
    assert len(response.read_sizes) == 2
    assert response.closed is True


def test_cdp_discovery_owns_response_without_entering_it(monkeypatch) -> None:
    class EnterRejectingResponse(JsonResponse):
        def __enter__(self):
            raise AssertionError("implicit response context must not be entered")

    response = EnterRejectingResponse(b"[]")
    monkeypatch.setattr(cdp_module, "urlopen", lambda *_a, **_k: response)

    assert (
        cdp_module._read_cdp_json_url(
            "http://127.0.0.1:9222/json/list",
            timeout_seconds=1,
            maximum=8,
        )
        == []
    )
    assert response.closed is True


def test_cdp_discovery_read_respects_request_deadline(monkeypatch) -> None:
    elapsed = [0.0]
    monkeypatch.setattr(
        cdp_module, "time", SimpleNamespace(monotonic=lambda: elapsed[0])
    )

    class SlowResponse(JsonResponse):
        def read(self, _maximum: int) -> bytes:
            pytest.fail("blocking discovery read was used")

        def read1(self, maximum: int) -> bytes:
            elapsed[0] += 0.06
            block = self.body[self.offset : self.offset + min(maximum, 1)]
            self.offset += len(block)
            return block

    response = SlowResponse(b"[]")
    monkeypatch.setattr(cdp_module, "urlopen", lambda *_args, **_kwargs: response)
    with pytest.raises(ContractError, match="discovery response deadline"):
        cdp_module._read_cdp_json_url(
            "http://127.0.0.1:9222/json/list",
            timeout_seconds=0.1,
            maximum=64,
        )
    assert response.closed is True


def test_cdp_discovery_rejects_decode_completed_after_deadline(monkeypatch) -> None:
    clock = [0.0]
    monkeypatch.setattr(
        cdp_module, "time", SimpleNamespace(monotonic=lambda: clock[0])
    )
    response = JsonResponse(b"[]")
    monkeypatch.setattr(cdp_module, "urlopen", lambda *_a, **_k: response)

    def late_decode(*_args, **_kwargs):
        clock[0] = 2.0
        return []

    monkeypatch.setattr(cdp_module, "decode_strict_json_bytes", late_decode)
    with pytest.raises(ContractError, match="discovery response deadline expired"):
        cdp_module._read_cdp_json_url(
            "http://127.0.0.1:9222/json/list",
            timeout_seconds=1.0,
            maximum=64,
        )
    assert response.closed is True


def test_cdp_discovery_rejects_cleanup_completed_after_deadline(monkeypatch) -> None:
    clock = [0.0]
    monkeypatch.setattr(
        cdp_module, "time", SimpleNamespace(monotonic=lambda: clock[0])
    )

    class SlowClose(JsonResponse):
        def close(self) -> None:
            super().close()
            clock[0] = 2.0

    response = SlowClose(b"[]")
    monkeypatch.setattr(cdp_module, "urlopen", lambda *_a, **_k: response)
    with pytest.raises(ContractError, match="discovery response deadline expired"):
        cdp_module._read_cdp_json_url(
            "http://127.0.0.1:9222/json/list",
            timeout_seconds=1.0,
            maximum=64,
        )
    assert response.closed is True


def test_browser_discovery_rejects_late_snapshot_and_caps_request(monkeypatch) -> None:
    clock = [0.0]
    monkeypatch.setattr(
        cdp_module, "time", SimpleNamespace(monotonic=lambda: clock[0])
    )
    websocket = "ws://127.0.0.1:9222/devtools/browser/owned"
    seen: list[float] = []

    def late_snapshot(_url: str, *, timeout_seconds: float, maximum: int):
        assert maximum == 64 * 1024
        seen.append(timeout_seconds)
        clock[0] = 301.0
        return {"webSocketDebuggerUrl": websocket}

    monkeypatch.setattr(cdp_module, "_read_cdp_json_url", late_snapshot)
    with pytest.raises(ContractError, match="deadline expired"):
        cdp_module._browser_websocket_url("http://127.0.0.1:9222", 300.0)
    assert seen == [120.0]


def test_page_discovery_rejects_target_returned_after_deadline(monkeypatch) -> None:
    clock = [0.0]
    monkeypatch.setattr(
        cdp_module, "time", SimpleNamespace(monotonic=lambda: clock[0])
    )
    target_url = "http://127.0.0.1:8000/owned"
    websocket = "ws://127.0.0.1:9222/devtools/page/owned"

    def late_snapshot(*_args, **_kwargs):
        clock[0] = 2.0
        return [
            {
                "type": "page",
                "url": target_url,
                "id": "owned",
                "webSocketDebuggerUrl": websocket,
            }
        ]

    monkeypatch.setattr(cdp_module, "_read_cdp_json_url", late_snapshot)
    with pytest.raises(ContractError, match="deadline|timed out"):
        cdp_module._page_websocket_url(
            "http://127.0.0.1:9222", target_url, timeout_seconds=1.0
        )


def test_fixture_discovery_rejects_title_returned_after_deadline(monkeypatch) -> None:
    clock = [0.0]
    monkeypatch.setattr(
        cdp_module, "time", SimpleNamespace(monotonic=lambda: clock[0])
    )
    target_url = "http://127.0.0.1:8000/owned"

    def late_snapshot(*_args, **_kwargs):
        clock[0] = 2.0
        return [{"type": "page", "url": target_url, "title": "ready"}]

    monkeypatch.setattr(cdp_module, "_read_cdp_json_url", late_snapshot)
    with pytest.raises(ContractError, match="deadline|timed out"):
        wait_for_page_target(
            "http://127.0.0.1:9222", target_url, "ready", timeout_seconds=1.0
        )


def test_managed_probe_does_not_report_late_target_as_present(monkeypatch) -> None:
    clock = [0.0]
    monkeypatch.setattr(
        cdp_module, "time", SimpleNamespace(monotonic=lambda: clock[0])
    )
    target_url = "http://127.0.0.1:8000/owned"

    def late_snapshot(*_args, **_kwargs):
        clock[0] = 2.0
        return [{"type": "page", "url": target_url, "title": "ready"}]

    monkeypatch.setattr(cdp_module, "_read_cdp_json_url", late_snapshot)
    result = cdp_module.probe_managed_page_target(
        "http://127.0.0.1:9222",
        target_url,
        expected_title="ready",
        timeout_seconds=1.0,
    )
    assert result == {"status": "invalid-response", "title_matches": None}


def test_cdp_discovery_refuses_redirect_after_loopback_validation() -> None:
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
    source_thread = threading.Thread(target=source.serve_forever, daemon=True)
    target_thread = threading.Thread(target=target.serve_forever, daemon=True)
    source_thread.start()
    target_thread.start()
    try:
        with pytest.raises(ContractError):
            cdp_module._read_cdp_json_url(
                f"http://127.0.0.1:{source.server_port}/json/list",
                timeout_seconds=2,
                maximum=64,
            )
        assert target_hits == []
    finally:
        source.shutdown()
        target.shutdown()
        source.server_close()
        target.server_close()
        source_thread.join(timeout=2)
        target_thread.join(timeout=2)


def test_cdp_discovery_closes_rejected_http_response(monkeypatch) -> None:
    body = io.BytesIO(b"private diagnostic")
    error = urllib.error.HTTPError(
        "http://127.0.0.1:9222/json/list", 302, "redirect", {}, body
    )

    def reject(*_args, **_kwargs):
        raise error

    monkeypatch.setattr(cdp_module, "urlopen", reject)
    with pytest.raises(ContractError, match="response status is invalid"):
        cdp_module._read_cdp_json_url(
            "http://127.0.0.1:9222/json/list", timeout_seconds=1, maximum=64
        )
    assert body.closed


@pytest.mark.parametrize("status", [None, True, "200", 199, 201, 206, 300, 503])
def test_cdp_discovery_requires_exact_2xx_status_before_reading(
    monkeypatch,
    status,
) -> None:
    class StatusResponse(JsonResponse):
        def getcode(self):
            return status

    response = StatusResponse(b'[{"private":"body"}]')
    monkeypatch.setattr(cdp_module, "urlopen", lambda *_a, **_k: response)

    with pytest.raises(ContractError) as raised:
        cdp_module._read_cdp_json_url(
            "http://127.0.0.1:9222/json/list",
            timeout_seconds=1,
            maximum=64,
        )

    assert str(raised.value) == "CDP discovery response status is invalid"
    assert response.read_sizes == []
    assert response.closed is True
    assert "private" not in str(raised.value)


@pytest.mark.parametrize("stage", ["status", "body"])
def test_cdp_discovery_normalizes_acquired_adapter_failures(
    monkeypatch,
    stage,
) -> None:
    class Response(JsonResponse):
        def getcode(self) -> int:
            if stage == "status":
                raise RuntimeError("private status provider detail")
            return 200

        def read(self, maximum: int) -> bytes:
            if stage == "body":
                raise OSError("private body provider detail")
            return super().read(maximum)

    response = Response(b"[]")
    monkeypatch.setattr(cdp_module, "urlopen", lambda *_a, **_k: response)

    with pytest.raises(ContractError) as raised:
        cdp_module._read_cdp_json_url(
            "http://127.0.0.1:9222/json/list",
            timeout_seconds=1,
            maximum=64,
        )

    assert str(raised.value) in {
        "CDP discovery response failed (RuntimeError)",
        "CDP discovery response failed (OSError)",
    }
    assert response.closed is True
    assert "private" not in str(raised.value)


@pytest.mark.parametrize(
    "url",
    [
        None,
        "https://127.0.0.1:9222/json/list",
        "http://example.test:9222/json/list",
        "http://user@127.0.0.1:9222/json/list",
        "http://127.0.0.1:9222/json/list?private=1",
        "http://127.0.0.1:9222/json/list?",
        "http://127.0.0.1:9222/json/list#",
        "http://127.0.0.1:9222/json/new",
        "http://127.0.0.1:9222/json/list\nprivate",
    ],
)
def test_cdp_discovery_rejects_non_owned_url_before_contact(
    monkeypatch,
    url,
) -> None:
    monkeypatch.setattr(
        cdp_module,
        "urlopen",
        lambda *_a, **_k: pytest.fail("invalid discovery URL reached transport"),
    )
    with pytest.raises(ContractError, match="exact loopback JSON endpoint"):
        cdp_module._read_cdp_json_url(
            url,
            timeout_seconds=1,
            maximum=64,
        )


@pytest.mark.parametrize(
    ("timeout", "maximum", "message"),
    [
        (True, 64, "timeout"),
        (float("nan"), 64, "timeout"),
        (121, 64, "timeout"),
        (1, True, "bound"),
        (1, "64", "bound"),
        (1, 0, "bound"),
        (1, 256 * 1024 + 1, "bound"),
    ],
)
def test_cdp_discovery_rejects_invalid_budget_before_contact(
    monkeypatch,
    timeout,
    maximum,
    message,
) -> None:
    monkeypatch.setattr(
        cdp_module,
        "urlopen",
        lambda *_a, **_k: pytest.fail("invalid discovery budget reached transport"),
    )
    with pytest.raises(ContractError, match=message):
        cdp_module._read_cdp_json_url(
            "http://127.0.0.1:9222/json/list",
            timeout_seconds=timeout,
            maximum=maximum,
        )


def test_cdp_discovery_rejects_valid_document_when_response_close_fails(
    monkeypatch,
) -> None:
    class CloseFailingResponse(JsonResponse):
        def close(self) -> None:
            raise OSError("private close diagnostic")

    response = CloseFailingResponse(b"[]")
    monkeypatch.setattr(cdp_module, "urlopen", lambda *_a, **_k: response)

    with pytest.raises(ContractError) as raised:
        cdp_module._read_cdp_json_url(
            "http://127.0.0.1:9222/json/list",
            timeout_seconds=1,
            maximum=8,
        )
    assert str(raised.value) == "CDP discovery cleanup failed (response-close)"
    assert raised.value.__cause__ is None
    assert "private" not in str(raised.value)


def test_cdp_discovery_cleanup_failure_preserves_read_failure_as_cause(
    monkeypatch,
) -> None:
    class InvalidCloseFailingResponse(JsonResponse):
        def close(self) -> None:
            raise RuntimeError("private close diagnostic")

    response = InvalidCloseFailingResponse(b"not-json")
    monkeypatch.setattr(cdp_module, "urlopen", lambda *_a, **_k: response)

    with pytest.raises(ContractError) as raised:
        cdp_module._read_cdp_json_url(
            "http://127.0.0.1:9222/json/list",
            timeout_seconds=1,
            maximum=16,
        )
    assert str(raised.value) == "CDP discovery cleanup failed (response-close)"
    assert isinstance(raised.value.__cause__, ContractError)
    assert str(raised.value.__cause__) == "CDP discovery response is invalid JSON"
    assert "private" not in str(raised.value)


def test_fixture_discovery_uses_remaining_absolute_deadline(monkeypatch) -> None:
    target = {
        "type": "page",
        "url": "file:///fixture.html",
        "title": "fixture-ok",
    }
    response = JsonResponse(json.dumps([target]).encode("utf-8"))
    timeouts: list[float] = []

    def open_response(*_args, **kwargs):
        timeouts.append(kwargs["timeout"])
        return response

    moments = iter([100.0, 100.05])
    monkeypatch.setattr(cdp_module.time, "monotonic", lambda: next(moments, 100.1))
    monkeypatch.setattr(cdp_module, "urlopen", open_response)
    assert (
        cdp_module.wait_for_page_target(
            "http://127.0.0.1:9222",
            target["url"],
            target["title"],
            timeout_seconds=0.2,
        )
        == target
    )
    assert timeouts == [pytest.approx(0.15)]
    assert response.read_sizes[0] == 256 * 1024 + 1
    assert len(response.read_sizes) == 2


def test_managed_target_probe_binds_the_exact_page_without_returning_its_title(
    monkeypatch,
) -> None:
    target_url = "http://127.0.0.1:8000/owned"
    response = JsonResponse(
        json.dumps(
            [
                {
                    "type": "page",
                    "url": target_url,
                    "title": "private-page-controlled-title",
                },
                {"type": "page", "url": "chrome://newtab/", "title": "other"},
            ]
        ).encode("utf-8")
    )
    monkeypatch.setattr(cdp_module, "urlopen", lambda *_a, **_k: response)

    result = cdp_module.probe_managed_page_target(
        "http://127.0.0.1:9222",
        target_url,
        expected_title="browser-core-owned",
        timeout_seconds=1,
    )

    assert result == {"status": "present", "title_matches": False}
    assert "private" not in json.dumps(result)
    assert response.read_sizes[0] == 256 * 1024 + 1
    assert len(response.read_sizes) == 2


def test_managed_target_probe_distinguishes_absent_unreachable_and_invalid(
    monkeypatch,
) -> None:
    endpoint = "http://127.0.0.1:9222"
    target_url = "http://127.0.0.1:8000/owned"

    monkeypatch.setattr(
        cdp_module,
        "urlopen",
        lambda *_a, **_k: JsonResponse(b"[]"),
    )
    assert cdp_module.probe_managed_page_target(
        endpoint, target_url, expected_title="owned"
    ) == {"status": "absent", "title_matches": None}

    monkeypatch.setattr(
        cdp_module,
        "urlopen",
        lambda *_a, **_k: JsonResponse(b'{"not":"a-list"}'),
    )
    assert cdp_module.probe_managed_page_target(
        endpoint, target_url, expected_title="owned"
    ) == {"status": "invalid-response", "title_matches": None}

    def unreachable(*_args, **_kwargs):
        raise OSError("private transport diagnostic")

    monkeypatch.setattr(cdp_module, "urlopen", unreachable)
    assert cdp_module.probe_managed_page_target(
        endpoint, target_url, expected_title="owned"
    ) == {"status": "unreachable", "title_matches": None}


@pytest.mark.parametrize("target_id", [None, "bad\nprivate", "x" * 257])
def test_managed_target_readers_reject_present_malformed_page_id(
    monkeypatch, target_id,
) -> None:
    target_url = "http://127.0.0.1:8000/owned"
    target = {"type": "page", "url": target_url, "title": "ready", "id": target_id}
    monkeypatch.setattr(cdp_module, "_read_cdp_json_url", lambda *_a, **_k: [target])

    with pytest.raises(ContractError, match="page target identity"):
        wait_for_page_target("http://127.0.0.1:9222", target_url, "ready")
    assert cdp_module.probe_managed_page_target(
        "http://127.0.0.1:9222", target_url, expected_title="ready"
    ) == {"status": "invalid-response", "title_matches": None}

    target["id"] = "owned"
    assert wait_for_page_target("http://127.0.0.1:9222", target_url, "ready") == target
    assert cdp_module.probe_managed_page_target(
        "http://127.0.0.1:9222", target_url, expected_title="ready"
    ) == {"status": "present", "title_matches": True}


def test_managed_target_probe_rejects_invalid_inputs_before_network(
    monkeypatch,
) -> None:
    monkeypatch.setattr(
        cdp_module,
        "urlopen",
        lambda *_a, **_k: pytest.fail("network must not be touched"),
    )
    with pytest.raises(ContractError, match="target URL"):
        cdp_module.probe_managed_page_target(
            "http://127.0.0.1:9222", "bad\nurl", expected_title="owned"
        )
    with pytest.raises(ContractError, match="target URL"):
        cdp_module.probe_managed_page_target(
            "http://127.0.0.1:9222", "bad\ud800url", expected_title="owned"
        )
    with pytest.raises(ContractError, match="expected title"):
        cdp_module.probe_managed_page_target(
            "http://127.0.0.1:9222", "http://127.0.0.1/", expected_title=""
        )


@pytest.mark.parametrize(
    "invalid",
    [None, True, 1, 1.5, b"value", [], {}, (), "bad\nvalue", "bad\ud800value"],
)
def test_fixture_wait_rejects_malformed_target_identity_before_network(
    monkeypatch, invalid
) -> None:
    monkeypatch.setattr(
        cdp_module,
        "urlopen",
        lambda *_a, **_k: pytest.fail("network must not be touched"),
    )
    endpoint = "http://127.0.0.1:9222"
    with pytest.raises(ContractError, match="target URL"):
        wait_for_page_target(endpoint, invalid, "owned", timeout_seconds=1)
    with pytest.raises(ContractError, match="expected title"):
        wait_for_page_target(endpoint, "about:blank", invalid, timeout_seconds=1)
    if invalid is not None:
        with pytest.raises(ContractError, match="failure title prefix"):
            wait_for_page_target(
                endpoint,
                "about:blank",
                "owned",
                timeout_seconds=1,
                failure_title_prefix=invalid,
            )


def test_managed_target_identity_byte_limits_apply_before_network(monkeypatch) -> None:
    monkeypatch.setattr(
        cdp_module,
        "urlopen",
        lambda *_a, **_k: pytest.fail("network must not be touched"),
    )
    endpoint = "http://127.0.0.1:9222"
    with pytest.raises(ContractError, match="target URL"):
        wait_for_page_target(endpoint, "x" * (64 * 1024 + 1), "owned")
    with pytest.raises(ContractError, match="expected title"):
        wait_for_page_target(endpoint, "about:blank", "x" * 257)
    with pytest.raises(ContractError, match="failure title prefix"):
        wait_for_page_target(
            endpoint,
            "about:blank",
            "owned",
            failure_title_prefix="x" * 257,
        )
    with pytest.raises(ContractError, match="target URL"):
        cdp_module.probe_managed_page_target(
            endpoint, "x" * (64 * 1024 + 1), expected_title="owned"
        )


def test_runtime_identity_observation_is_bounded_and_enables_no_domain(
    monkeypatch,
) -> None:
    monkeypatch.setattr(
        "browser_core.cdp._page_websocket_url",
        lambda endpoint, target_url, timeout: "ws://127.0.0.1:9222/devtools/page/owned",
    )

    def command(websocket_url, payload, timeout):
        assert payload["method"] == "Runtime.evaluate"
        assert "Runtime.enable" not in str(payload)
        return {
            "id": 941,
            "result": {
                "result": {
                    "type": "string",
                    "value": '{"locale":"en-US","languages":["en-US","en"],"timezone":"America/Chicago"}',
                }
            },
        }

    monkeypatch.setattr("browser_core.cdp._websocket_json_command", command)
    result = observe_runtime_identity(
        "http://127.0.0.1:9222", "about:blank#browser-core-identity-fixture"
    )
    assert result == {
        "schema": "browser-core.runtime-identity-observation/1",
        "locale": "en-US",
        "languages": ["en-US", "en"],
        "timezone": "America/Chicago",
        "cdp_domains_enabled": [],
    }


def test_evaluate_error_drops_page_controlled_diagnostic_text(monkeypatch) -> None:
    monkeypatch.setattr(
        cdp_module,
        "_page_websocket_url",
        lambda *_args: "ws://127.0.0.1:9222/devtools/page/owned",
    )
    monkeypatch.setattr(
        cdp_module,
        "_websocket_json_command",
        lambda *_args: {
            "result": {
                "result": {
                    "type": "object",
                    "subtype": "error",
                    "description": (
                        "SyntaxError: private-tenant-token\nsecret-bearing stack"
                    ),
                }
            }
        },
    )
    with pytest.raises(ContractError) as exc:
        cdp_module.evaluate_page_expression("http://127.0.0.1:9222", "(() =>)()")
    assert str(exc.value) == "CDP evaluate returned an error object"
    assert "private-tenant-token" not in str(exc.value)
    assert "secret-bearing stack" not in str(exc.value)


@pytest.mark.parametrize(
    "response",
    [
        {"error": {"message": "private-protocol-error"}},
        {
            "result": {
                "result": {"type": "string", "value": "apparently-valid"},
                "exceptionDetails": {"text": "private-exception"},
            }
        },
        {"result": {"result": {"type": "number", "value": True}}},
        {"result": {"result": {"type": "boolean", "value": 1}}},
        {"result": {"result": {"type": "object", "value": "not-object"}}},
        {"result": {"result": {"type": "string", "value": 7}}},
        {"result": {"result": {"type": "bigint", "value": "1"}}},
    ],
)
def test_evaluate_rejects_exception_envelopes_and_type_value_mismatches(
    monkeypatch, response
) -> None:
    monkeypatch.setattr(
        cdp_module,
        "_page_websocket_url",
        lambda *_args: "ws://127.0.0.1:9222/devtools/page/owned",
    )
    monkeypatch.setattr(
        cdp_module,
        "_websocket_json_command",
        lambda *_args: response,
    )
    with pytest.raises(ContractError) as raised:
        cdp_module.evaluate_page_expression("http://127.0.0.1:9222", "1")
    assert "private-protocol-error" not in str(raised.value)
    assert "private-exception" not in str(raised.value)


@pytest.mark.parametrize(
    ("remote", "expected"),
    [
        ({"type": "string", "value": "ok"}, "ok"),
        ({"type": "number", "value": 3.5}, 3.5),
        ({"type": "boolean", "value": False}, False),
        ({"type": "object", "subtype": "null", "value": None}, None),
        ({"type": "object", "value": {"owned": True}}, {"owned": True}),
        ({"type": "object", "subtype": "array", "value": [1]}, [1]),
    ],
)
def test_evaluate_accepts_exact_return_by_value_types(remote, expected) -> None:
    assert (
        cdp_module._validated_evaluate_value({"result": {"result": remote}}) == expected
    )


@pytest.mark.parametrize(
    "remote",
    [
        {"type": "object", "subtype": "array", "value": {}},
        {"type": "object", "subtype": "array", "value": None},
        {"type": "object", "subtype": "null", "value": {}},
        {"type": "object", "subtype": "null", "value": []},
    ],
)
def test_evaluate_rejects_contradictory_object_subtype(remote) -> None:
    with pytest.raises(ContractError, match="remote value is invalid"):
        cdp_module._validated_evaluate_value({"result": {"result": remote}})


def test_evaluate_rejects_a_remote_number_too_large_for_binary_float() -> None:
    response = {
        "result": {
            "result": {
                "type": "number",
                "value": 10**1_000,
            }
        }
    }

    with pytest.raises(ContractError, match="remote value is invalid"):
        cdp_module._validated_evaluate_value(response)


@pytest.mark.parametrize(
    "destination",
    [
        "http://127.0.0.1:8123/",
        "data:text/html,%3Ctitle%3Einert%3C/title%3E",
        "data:text/html,%3Ctitle%3Ebrowser-core-identity-owned-run%3C%2Ftitle%3E",
    ],
)
def test_managed_page_navigation_is_narrow_and_uses_page_navigate(
    monkeypatch, destination: str
) -> None:
    seen = {}
    monkeypatch.setattr(
        cdp_module,
        "_page_websocket_url",
        lambda endpoint, target_url, timeout: (
            seen.update(target_url=target_url) or "ws://127.0.0.1/devtools/page/owned"
        ),
    )

    def command(websocket_url, payload, timeout):  # noqa: ANN001
        seen.update(payload=payload, websocket_url=websocket_url)
        return {"id": 943, "result": {"frameId": "frame-1"}}

    monkeypatch.setattr(cdp_module, "_websocket_json_command", command)

    assert (
        cdp_module.navigate_managed_page(
            "http://127.0.0.1:9222",
            destination,
            current_target_url="data:text/html,%3Ctitle%3Ecurrent%3C/title%3E",
        )
        is True
    )
    assert seen["target_url"].startswith("data:text/html,")
    assert seen["payload"] == {
        "id": 943,
        "method": "Page.navigate",
        "params": {"url": destination},
    }


@pytest.mark.parametrize(
    "destination",
    [
        "https://example.invalid/",
        "http://example.invalid/",
        "file:///private/path",
        "data:text/plain,not-html",
        "data:text/html,%3Cscript%3Ealert(1)%3C%2Fscript%3E",
        "data:text/html,%3Ctitle%3Eready%3C%2Ftitle%3E%3Cimg%20src=x%20onerror=alert(1)%3E",
        "javascript:alert(1)",
        "http://127.0.0.1/",
        "\ud800",
    ],
)
def test_managed_page_navigation_rejects_nonowned_destinations_before_cdp(
    monkeypatch, destination: str
) -> None:
    monkeypatch.setattr(
        cdp_module,
        "_page_websocket_url",
        lambda *_args: pytest.fail("rejected destination reached target lookup"),
    )
    with pytest.raises(ContractError, match="navigation destination"):
        cdp_module.navigate_managed_page(
            "http://127.0.0.1:9222",
            destination,
            current_target_url="data:text/html,current",
        )


@pytest.mark.parametrize(
    "response",
    [
        {},
        {"result": {}},
        {"result": {"frameId": ""}},
        {"result": {"frameId": "frame\nprivate"}},
        {"result": {"frameId": "frame id"}},
        {"result": {"frameId": "\U0001f984"}},
        {"result": {"frameId": "frame", "errorText": "private-error"}},
        {"result": {"frameId": "frame", "errorText": []}},
    ],
)
def test_managed_page_navigation_requires_an_acknowledged_frame(
    monkeypatch, response
) -> None:
    monkeypatch.setattr(
        cdp_module,
        "_page_websocket_url",
        lambda *_args: "ws://127.0.0.1/devtools/page/owned",
    )
    monkeypatch.setattr(cdp_module, "_websocket_json_command", lambda *_args: response)
    with pytest.raises(ContractError) as failure:
        cdp_module.navigate_managed_page(
            "http://127.0.0.1:9222",
            "http://127.0.0.1:8123/",
            current_target_url="data:text/html,current",
        )
    assert "private-error" not in str(failure.value)


def test_evaluate_expression_uses_a_utf8_byte_bound_before_target_lookup(
    monkeypatch,
) -> None:
    monkeypatch.setattr(
        cdp_module,
        "_page_websocket_url",
        lambda *_args: pytest.fail("target lookup must not occur"),
    )
    with pytest.raises(ContractError, match="expression"):
        cdp_module.evaluate_page_expression("http://127.0.0.1:9222", "😀" * 64_001)


def test_evaluate_expression_refuses_unencodable_text_before_target_lookup(
    monkeypatch,
) -> None:
    monkeypatch.setattr(
        cdp_module,
        "_page_websocket_url",
        lambda *_args: pytest.fail("target lookup must not occur"),
    )
    with pytest.raises(ContractError, match="UTF-8"):
        cdp_module.evaluate_page_expression("http://127.0.0.1:9222", "\ud800")


@pytest.mark.parametrize("command_id", [0, True, 2_147_483_648])
def test_public_cdp_command_id_fails_before_target_lookup(
    monkeypatch, command_id
) -> None:
    monkeypatch.setattr(
        cdp_module,
        "_page_websocket_url",
        lambda *_args: pytest.fail("target lookup must not occur"),
    )
    with pytest.raises(ContractError, match="command id"):
        cdp_module.evaluate_page_expression(
            "http://127.0.0.1:9222", "1", command_id=command_id
        )
    with pytest.raises(ContractError, match="command id"):
        cdp_module.send_page_input_command(
            "http://127.0.0.1:9222",
            "Input.dispatchMouseEvent",
            {},
            command_id=command_id,
        )
    with pytest.raises(ContractError, match="command id"):
        cdp_module.send_page_input_batch(
            "http://127.0.0.1:9222",
            [],
            first_command_id=command_id,
        )
    with pytest.raises(ContractError, match="command id"):
        cdp_module.navigate_managed_page(
            "http://127.0.0.1:9222",
            "http://127.0.0.1:8123/",
            current_target_url="data:text/html,current",
            command_id=command_id,
        )


def test_runtime_identity_observation_rejects_missing_values(monkeypatch) -> None:
    monkeypatch.setattr(
        "browser_core.cdp._page_websocket_url",
        lambda endpoint, target_url, timeout: "ws://127.0.0.1:1/devtools/page/x",
    )
    monkeypatch.setattr(
        "browser_core.cdp._websocket_json_command",
        lambda websocket_url, payload, timeout: {
            "id": 941,
            "result": {
                "result": {
                    "type": "string",
                    "value": '{"locale":"","languages":[],"timezone":""}',
                }
            },
        },
    )
    with pytest.raises(ContractError, match="locale"):
        observe_runtime_identity("http://127.0.0.1:1", "about:blank#owned")


@pytest.mark.parametrize("field", ["locale", "languages", "timezone"])
@pytest.mark.parametrize("invalid_text", ["en-US\nprivate", "\ud800"])
def test_runtime_identity_observation_rejects_invalid_text(
    monkeypatch, field, invalid_text,
) -> None:
    observed = {"locale": "en-US", "languages": ["en-US"], "timezone": "UTC"}
    observed[field] = [invalid_text] if field == "languages" else invalid_text
    monkeypatch.setattr(
        cdp_module,
        "evaluate_page_expression",
        lambda *_args, **_kwargs: observed,
    )

    with pytest.raises(ContractError, match="observed browser .* invalid"):
        observe_runtime_identity("http://127.0.0.1:1", "about:blank#owned")


@pytest.mark.parametrize("field,maximum", [("locale", 64), ("languages", 64), ("timezone", 128)])
def test_runtime_identity_observation_bounds_utf8_bytes(
    monkeypatch, field, maximum,
) -> None:
    def observe(value: str) -> dict:
        observed = {"locale": "en-US", "languages": ["en-US"], "timezone": "UTC"}
        observed[field] = [value] if field == "languages" else value
        monkeypatch.setattr(
            cdp_module,
            "evaluate_page_expression",
            lambda *_args, **_kwargs: observed,
        )
        return observe_runtime_identity("http://127.0.0.1:1", "about:blank#owned")

    accepted = "é" * (maximum // 2)
    result = observe(accepted)
    assert result[field] == ([accepted] if field == "languages" else accepted)
    with pytest.raises(ContractError, match="observed browser .* invalid"):
        observe(accepted + "é")


def test_runtime_identity_observation_rejects_duplicate_languages(monkeypatch) -> None:
    monkeypatch.setattr(
        cdp_module,
        "evaluate_page_expression",
        lambda *_args, **_kwargs: {
            "locale": "en-US",
            "languages": ["en-US", "en-US"],
            "timezone": "UTC",
        },
    )

    with pytest.raises(ContractError, match="observed browser languages are invalid"):
        observe_runtime_identity("http://127.0.0.1:1", "about:blank#owned")


def test_runtime_identity_observation_rejects_duplicate_json_members(
    monkeypatch,
) -> None:
    monkeypatch.setattr(
        "browser_core.cdp._page_websocket_url",
        lambda *_args: "ws://127.0.0.1:1/devtools/page/x",
    )
    monkeypatch.setattr(
        "browser_core.cdp._websocket_json_command",
        lambda *_args: {
            "id": 941,
            "result": {
                "result": {
                    "type": "string",
                    "value": (
                        '{"locale":"en-US","locale":"private",'
                        '"languages":["en-US"],"timezone":"UTC"}'
                    ),
                }
            },
        },
    )

    with pytest.raises(ContractError, match="invalid JSON"):
        observe_runtime_identity("http://127.0.0.1:1", "about:blank#owned")


def test_browser_close_waits_for_acknowledgement(monkeypatch) -> None:
    connection = ChunkedSocket(
        [websocket_handshake() + server_frame(b'{"id":1,"result":{}}')]
    )
    monkeypatch.setattr(
        "browser_core.cdp._browser_websocket_url",
        lambda endpoint, timeout: "ws://127.0.0.1:9222/devtools/browser/owned",
    )
    install_socket(monkeypatch, connection)

    request_browser_close("http://127.0.0.1:9222")

    assert len(connection.sent) == 2
    assert connection.sent[1][0] == 0x81


def test_browser_close_accepts_close_frame_but_not_protocol_error(monkeypatch) -> None:
    monkeypatch.setattr(
        cdp_module,
        "_browser_websocket_url",
        lambda _endpoint, _timeout: ("ws://127.0.0.1:9222/devtools/browser/owned"),
    )
    closed = ChunkedSocket([websocket_handshake() + server_frame(b"", opcode=8)])
    install_socket(monkeypatch, closed)
    request_browser_close("http://127.0.0.1:9222")

    invalid = ChunkedSocket([websocket_handshake() + server_frame(b"binary", opcode=2)])
    install_socket(monkeypatch, invalid)
    with pytest.raises(ContractError, match="unsupported frame"):
        request_browser_close("http://127.0.0.1:9222")


def test_browser_close_does_not_accept_boolean_command_id(monkeypatch) -> None:
    monkeypatch.setattr(
        cdp_module,
        "_browser_websocket_url",
        lambda _endpoint, _timeout: ("ws://127.0.0.1:9222/devtools/browser/owned"),
    )
    boolean_id = server_frame(b'{"id":true,"result":{}}')
    rejected = server_frame(b'{"id":1,"error":{"message":"rejected"}}')
    connection = ChunkedSocket([websocket_handshake() + boolean_id + rejected])
    install_socket(monkeypatch, connection)

    with pytest.raises(ContractError, match="was rejected"):
        request_browser_close("http://127.0.0.1:9222")
    assert connection.remaining_bytes == 0


@pytest.mark.parametrize(
    "payload",
    [b'{"id":1}', b'{"id":1,"result":null}', b'{"id":1,"result":[]}'],
)
def test_browser_close_rejects_malformed_acknowledgement(
    monkeypatch, payload: bytes
) -> None:
    monkeypatch.setattr(
        cdp_module,
        "_browser_websocket_url",
        lambda *_args: "ws://127.0.0.1:9222/devtools/browser/owned",
    )
    connection = ChunkedSocket([websocket_handshake() + server_frame(payload)])
    install_socket(monkeypatch, connection)
    with pytest.raises(ContractError, match="response is invalid"):
        request_browser_close("http://127.0.0.1:9222")


def test_browser_close_discovery_and_websocket_share_one_deadline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = [100.0]
    connection = ChunkedSocket([server_frame(b'{"id":1,"result":{}}')])
    websocket_budgets: list[float] = []

    def discover(_endpoint: str, timeout: float) -> str:
        assert timeout == 5.0
        clock[0] += 2.0
        return "ws://127.0.0.1:9222/devtools/browser/owned"

    @contextmanager
    def connect(
        _url: str,
        timeout: float,
        *,
        os_error_label: str,
    ):  # type: ignore[no-untyped-def]
        assert os_error_label
        websocket_budgets.append(timeout)
        yield (
            connection,
            cdp_module._BoundedSocketReader(
                connection,
                deadline=clock[0] + timeout,
            ),
        )

    monkeypatch.setattr(cdp_module.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(cdp_module, "_browser_websocket_url", discover)
    monkeypatch.setattr(cdp_module, "_websocket_connection", connect)

    request_browser_close("http://127.0.0.1:9222", timeout_seconds=5.0)

    assert websocket_budgets == [pytest.approx(3.0)]
    assert connection.timeouts
    assert all(timeout == pytest.approx(3.0) for timeout in connection.timeouts)


def test_browser_close_rejects_ack_after_socket_cleanup_deadline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    now = [0.0]
    monkeypatch.setattr(cdp_module.time, "monotonic", lambda: now[0])
    monkeypatch.setattr(
        cdp_module,
        "_browser_websocket_url",
        lambda *_args: "ws://127.0.0.1:9222/devtools/browser/owned",
    )

    class LateCloseSocket(ChunkedSocket):
        def close(self) -> None:
            now[0] = 2.0
            super().close()

    connection = LateCloseSocket(
        [websocket_handshake() + server_frame(b'{"id":1,"result":{}}')]
    )
    install_socket(monkeypatch, connection)
    with pytest.raises(ContractError, match="CDP close deadline expired"):
        request_browser_close("http://127.0.0.1:9222", timeout_seconds=1.0)
    assert connection.closed


def test_page_cdp_operations_share_discovery_and_execution_deadline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = [100.0]
    discovery_budgets = []
    command_budgets = []
    connection_budgets = []

    def discover(_endpoint, _target, timeout):  # noqa: ANN001
        discovery_budgets.append(timeout)
        clock[0] += 2.0
        return "ws://127.0.0.1:9222/devtools/page/owned"

    def command(_websocket_url, payload, timeout):  # noqa: ANN001
        command_budgets.append(timeout)
        method = payload["method"]
        if method == "DOMSnapshot.captureSnapshot":
            return {"result": {"strings": [], "documents": []}}
        if method == "Runtime.evaluate":
            return {"result": {"result": {"type": "number", "value": 1}}}
        return {"result": {}}

    @contextmanager
    def connection(_url, timeout, *, os_error_label):  # noqa: ANN001
        assert os_error_label
        connection_budgets.append(timeout)
        yield object(), object()

    monkeypatch.setattr(cdp_module.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(cdp_module, "_page_websocket_url", discover)
    monkeypatch.setattr(cdp_module, "_websocket_json_command", command)
    monkeypatch.setattr(cdp_module, "_websocket_connection", connection)

    cdp_module.observe_page_resource_intents(
        "http://127.0.0.1:9222",
        target_url="about:blank",
        timeout_seconds=5.0,
    )
    cdp_module.send_page_input_command(
        "http://127.0.0.1:9222",
        "Input.dispatchMouseEvent",
        {},
        timeout_seconds=5.0,
    )
    assert (
        cdp_module.evaluate_page_expression(
            "http://127.0.0.1:9222",
            "1",
            timeout_seconds=5.0,
        )
        == 1
    )
    assert (
        cdp_module.send_page_input_batch(
            "http://127.0.0.1:9222",
            [],
            timeout_seconds=5.0,
        )["attempted"]
        == 0
    )

    assert discovery_budgets == pytest.approx([5.0, 5.0, 5.0, 5.0])
    assert command_budgets == pytest.approx([3.0, 3.0, 3.0])
    assert connection_budgets == pytest.approx([3.0])


def test_page_cdp_deadline_exhaustion_stops_before_execution(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = [10.0]
    executed = False

    def discover(_endpoint, _target, _timeout):  # noqa: ANN001
        clock[0] += 6.0
        return "ws://127.0.0.1:9222/devtools/page/owned"

    def command(*_args, **_kwargs):
        nonlocal executed
        executed = True
        raise AssertionError("command execution")

    monkeypatch.setattr(cdp_module.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(cdp_module, "_page_websocket_url", discover)
    monkeypatch.setattr(cdp_module, "_websocket_json_command", command)
    with pytest.raises(ContractError, match="deadline expired"):
        cdp_module.evaluate_page_expression(
            "http://127.0.0.1:9222",
            "1",
            timeout_seconds=5.0,
        )
    assert executed is False


@pytest.mark.parametrize(
    "timeout",
    [True, 0.0, -1.0, 301.0, float("nan"), float("inf"), "1"],
)
def test_browser_close_rejects_invalid_deadline_before_discovery(
    monkeypatch: pytest.MonkeyPatch,
    timeout: object,
) -> None:
    monkeypatch.setattr(
        cdp_module,
        "_browser_websocket_url",
        lambda *_args, **_kwargs: pytest.fail("invalid timeout reached discovery"),
    )
    with pytest.raises(ContractError, match="finite and positive"):
        request_browser_close(
            "http://127.0.0.1:9222",
            timeout_seconds=timeout,  # type: ignore[arg-type]
        )


def test_browser_close_rejects_a_huge_integer_deadline_before_discovery(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        cdp_module,
        "_browser_websocket_url",
        lambda *_args, **_kwargs: pytest.fail("huge timeout reached discovery"),
    )

    with pytest.raises(ContractError, match="at most 300 seconds"):
        request_browser_close(
            "http://127.0.0.1:9222",
            timeout_seconds=10**10_000,  # type: ignore[arg-type]
        )


def test_websocket_connection_rejects_overlimit_timeout_before_socket_contact(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        cdp_module.socket,
        "create_connection",
        lambda *_args, **_kwargs: pytest.fail("overlimit timeout reached socket"),
    )

    with pytest.raises(ContractError, match="at most 300 seconds"):
        with cdp_module._websocket_connection(
            "ws://127.0.0.1:9222/devtools/page/owned",
            301.0,
            os_error_label="test",
        ):
            pytest.fail("overlimit timeout opened WebSocket context")


@pytest.mark.parametrize("timeout", [True, 0, float("nan"), float("inf"), "1"])
def test_browser_target_discovery_rejects_invalid_timeout_before_contact(
    monkeypatch: pytest.MonkeyPatch,
    timeout: object,
) -> None:
    contacted = False

    def forbidden(*_args, **_kwargs):
        nonlocal contacted
        contacted = True
        raise AssertionError("browser discovery")

    monkeypatch.setattr(cdp_module, "urlopen", forbidden)
    with pytest.raises(ContractError, match="finite and positive"):
        cdp_module._browser_websocket_url(
            "http://127.0.0.1:9222",
            timeout,  # type: ignore[arg-type]
        )
    assert contacted is False


def test_websocket_connect_and_handshake_share_one_deadline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = [10.0]
    connection = ChunkedSocket([websocket_handshake()])
    connect_budgets: list[float] = []

    def connect(_address: object, *, timeout: float) -> ChunkedSocket:
        connect_budgets.append(timeout)
        clock[0] += 2.0
        return connection

    monkeypatch.setattr(cdp_module.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(cdp_module.socket, "create_connection", connect)
    monkeypatch.setattr(cdp_module.os, "urandom", lambda length: bytes(length))

    with cdp_module._websocket_connection(
        "ws://127.0.0.1:9222/devtools/browser/owned",
        5.0,
        os_error_label="owned close",
    ):
        pass

    assert connect_budgets == [pytest.approx(5.0)]
    assert connection.timeouts
    assert all(timeout == pytest.approx(3.0) for timeout in connection.timeouts)


def test_websocket_handshake_cannot_yield_after_deadline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = [0.0]
    connection = ChunkedSocket([websocket_handshake()])
    install_socket(monkeypatch, connection)
    monkeypatch.setattr(cdp_module.time, "monotonic", lambda: clock[0])
    original_validate = cdp_module._validate_websocket_upgrade

    def slow_validate(header: bytes, key: str) -> None:
        original_validate(header, key)
        clock[0] = 2.0

    monkeypatch.setattr(cdp_module, "_validate_websocket_upgrade", slow_validate)
    with pytest.raises(ContractError, match="deadline expired"):
        with cdp_module._websocket_connection(
            "ws://127.0.0.1:9222/devtools/page/owned",
            1.0,
            os_error_label="CDP test",
        ):
            pytest.fail("expired WebSocket handshake reached command caller")
    assert connection.closed


@pytest.mark.parametrize("operation", ["single", "batch"])
@pytest.mark.parametrize("expiry", ["connection", "frame"])
def test_cdp_command_does_not_send_after_connection_deadline(
    monkeypatch: pytest.MonkeyPatch, operation: str, expiry: str
) -> None:
    clock = [0.0]
    sent = []
    monkeypatch.setattr(cdp_module.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(
        cdp_module, "_page_websocket_url", lambda *_args, **_kwargs: "ws://127.0.0.1:9222/devtools/page/owned"
    )

    class Connection:
        def sendall(self, body: bytes) -> None:
            sent.append(body)

    connection = Connection()
    reader = cdp_module._BoundedSocketReader(connection, deadline=1.0)

    def late_mask(length: int) -> bytes:
        if expiry == "frame":
            clock[0] = 2.0
        return bytes(length)

    monkeypatch.setattr(cdp_module, "_websocket_random_bytes", late_mask)

    @contextmanager
    def expired_connection(*_args, **_kwargs):
        if expiry == "connection":
            clock[0] = 2.0
        yield connection, reader

    monkeypatch.setattr(cdp_module, "_websocket_connection", expired_connection)
    if operation == "single":
        with pytest.raises((ContractError, TimeoutError)):
            cdp_module._websocket_json_command(
                "ws://127.0.0.1:9222/devtools/page/owned",
                {"id": 7, "method": "Runtime.evaluate"},
                1.0,
            )
    else:
        report = cdp_module.send_page_input_batch(
            "http://127.0.0.1:9222",
            [("Input.dispatchMouseEvent", {"type": "mouseMoved"})],
            timeout_seconds=1.0,
        )
        assert report["dispatched"] == 0
    assert sent == []


def test_websocket_ping_does_not_send_pong_after_deadline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = [0.0]
    monkeypatch.setattr(cdp_module.time, "monotonic", lambda: clock[0])

    def late_mask(length: int) -> bytes:
        clock[0] = 2.0
        return bytes(length)

    monkeypatch.setattr(cdp_module, "_websocket_random_bytes", late_mask)
    connection = ChunkedSocket([server_frame(b"ping", opcode=9)])
    reader = cdp_module._BoundedSocketReader(connection, deadline=1.0)
    with pytest.raises(TimeoutError):
        cdp_module._read_server_text_message(reader, connection)
    assert connection.sent == []


def test_browser_close_does_not_send_after_frame_preparation_deadline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = [0.0]
    monkeypatch.setattr(cdp_module.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(
        cdp_module,
        "_browser_websocket_url",
        lambda *_args, **_kwargs: "ws://127.0.0.1:9222/devtools/browser/owned",
    )

    def late_mask(length: int) -> bytes:
        clock[0] = 2.0
        return bytes(length)

    monkeypatch.setattr(cdp_module, "_websocket_random_bytes", late_mask)
    connection = ChunkedSocket([])
    reader = cdp_module._BoundedSocketReader(connection, deadline=1.0)

    @contextmanager
    def connection_context(*_args, **_kwargs):
        yield connection, reader

    monkeypatch.setattr(cdp_module, "_websocket_connection", connection_context)
    with pytest.raises(ContractError, match="deadline"):
        request_browser_close("http://127.0.0.1:9222", timeout_seconds=1.0)
    assert connection.sent == []


@pytest.mark.parametrize("operation", ["single", "batch"])
def test_cdp_write_refreshes_remaining_socket_timeout(
    monkeypatch: pytest.MonkeyPatch, operation: str
) -> None:
    clock = [0.0]
    actions: list[tuple[str, float | None]] = []
    monkeypatch.setattr(cdp_module.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(
        cdp_module,
        "_page_websocket_url",
        lambda *_args, **_kwargs: "ws://127.0.0.1:9222/devtools/page/owned",
    )

    class Connection:
        def settimeout(self, value: float) -> None:
            actions.append(("timeout", value))

        def sendall(self, _body: bytes) -> None:
            actions.append(("send", None))
            raise OSError("expected test write failure")

    connection = Connection()
    reader = cdp_module._BoundedSocketReader(connection, deadline=1.0)

    @contextmanager
    def connection_context(*_args, **_kwargs):
        clock[0] = 0.25
        yield connection, reader

    monkeypatch.setattr(cdp_module, "_websocket_connection", connection_context)
    if operation == "single":
        with pytest.raises(OSError, match="expected test write failure"):
            cdp_module._websocket_json_command(
                "ws://127.0.0.1:9222/devtools/page/owned",
                {"id": 7, "method": "Runtime.evaluate"},
                1.0,
            )
    else:
        report = cdp_module.send_page_input_batch(
            "http://127.0.0.1:9222",
            [("Input.dispatchMouseEvent", {"type": "mouseMoved"})],
            timeout_seconds=1.0,
        )
        assert report["dispatched"] == 0
    assert actions == [("timeout", pytest.approx(0.75)), ("send", None)]


def test_cdp_command_encoding_consumes_connection_deadline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = [0.0]
    opened: list[bool] = []
    monkeypatch.setattr(cdp_module.time, "monotonic", lambda: clock[0])

    def slow_encode(_command: object) -> bytes:
        clock[0] = 2.0
        return b'{"id":7,"method":"Runtime.evaluate"}'

    def late_connection(*_args, **_kwargs):
        opened.append(True)
        raise ContractError("connection opened after expired budget")

    monkeypatch.setattr(cdp_module, "_encode_cdp_command", slow_encode)
    monkeypatch.setattr(cdp_module, "_websocket_connection", late_connection)
    with pytest.raises(ContractError, match="deadline expired"):
        cdp_module._websocket_json_command(
            "ws://127.0.0.1:9222/devtools/page/owned",
            {"id": 7, "method": "Runtime.evaluate"},
            1.0,
        )
    assert opened == []


def test_input_batch_rejects_aggregate_payload_before_target_lookup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        cdp_module, "_encode_cdp_command", lambda _command: b"x" * (1024 * 1024)
    )
    monkeypatch.setattr(
        cdp_module,
        "_page_websocket_url",
        lambda *_args, **_kwargs: pytest.fail("oversized batch reached target lookup"),
    )
    event = ("Input.dispatchMouseEvent", {"type": "mouseMoved"})
    with pytest.raises(ContractError, match="batch byte limit"):
        cdp_module.send_page_input_batch("http://127.0.0.1:9222", [event] * 9)


def test_input_batch_preparation_consumes_deadline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = [0.0]
    monkeypatch.setattr(cdp_module.time, "monotonic", lambda: clock[0])

    def slow_encode(_command: object) -> bytes:
        clock[0] = 2.0
        return b'{"id":960,"method":"Input.dispatchMouseEvent"}'

    monkeypatch.setattr(cdp_module, "_encode_cdp_command", slow_encode)
    monkeypatch.setattr(
        cdp_module,
        "_page_websocket_url",
        lambda *_args, **_kwargs: pytest.fail("expired batch reached target lookup"),
    )
    with pytest.raises(ContractError, match="deadline expired"):
        cdp_module.send_page_input_batch(
            "http://127.0.0.1:9222",
            [("Input.dispatchMouseEvent", {"type": "mouseMoved"})],
            timeout_seconds=1.0,
        )


@pytest.mark.parametrize("operation", ["single", "batch"])
def test_cdp_late_response_decode_cannot_claim_success(
    monkeypatch: pytest.MonkeyPatch, operation: str
) -> None:
    clock = [0.0]
    monkeypatch.setattr(cdp_module.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(
        cdp_module,
        "_page_websocket_url",
        lambda *_args, **_kwargs: "ws://127.0.0.1:9222/devtools/page/owned",
    )
    monkeypatch.setattr(
        cdp_module,
        "_read_server_text_message",
        lambda *_args, **_kwargs: b'{"id":7,"result":{}}',
    )

    def late_decode(_raw: bytes, *, label: str) -> dict:
        clock[0] = 2.0
        return {"id": 7 if operation == "single" else 960, "result": {}}

    monkeypatch.setattr(cdp_module, "_decode_strict_cdp_text", late_decode)
    connection = ChunkedSocket([])
    reader = cdp_module._BoundedSocketReader(connection, deadline=1.0)

    @contextmanager
    def connection_context(*_args, **_kwargs):
        yield connection, reader

    monkeypatch.setattr(cdp_module, "_websocket_connection", connection_context)
    if operation == "single":
        with pytest.raises(cdp_module.CdpCommandResponseTimeout):
            cdp_module._websocket_json_command(
                "ws://127.0.0.1:9222/devtools/page/owned",
                {"id": 7, "method": "Runtime.evaluate"},
                1.0,
            )
    else:
        report = cdp_module.send_page_input_batch(
            "http://127.0.0.1:9222",
            [("Input.dispatchMouseEvent", {"type": "mouseMoved"})],
            timeout_seconds=1.0,
        )
        assert report["dispatched"] == 0


@pytest.mark.parametrize("completion", ["ack", "close"])
def test_browser_close_cannot_claim_late_completion(
    monkeypatch: pytest.MonkeyPatch, completion: str
) -> None:
    clock = [0.0]
    monkeypatch.setattr(cdp_module.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(
        cdp_module,
        "_browser_websocket_url",
        lambda *_args, **_kwargs: "ws://127.0.0.1:9222/devtools/browser/owned",
    )
    connection = ChunkedSocket([])
    reader = cdp_module._BoundedSocketReader(connection, deadline=1.0)

    @contextmanager
    def connection_context(*_args, **_kwargs):
        yield connection, reader

    def late_read(*_args, **_kwargs) -> bytes:
        if completion == "close":
            clock[0] = 2.0
            raise ConnectionResetError("late close")
        return b'{"id":1,"result":{}}'

    def late_decode(_raw: bytes, *, label: str) -> dict:
        clock[0] = 2.0
        return {"id": 1, "result": {}}

    monkeypatch.setattr(cdp_module, "_websocket_connection", connection_context)
    monkeypatch.setattr(cdp_module, "_read_server_text_message", late_read)
    monkeypatch.setattr(cdp_module, "_decode_strict_cdp_text", late_decode)
    with pytest.raises(ContractError, match="deadline expired"):
        request_browser_close("http://127.0.0.1:9222", timeout_seconds=1.0)


def test_websocket_connection_close_failure_blocks_success_type_only(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    private = "private-socket-close"

    class Connection(ChunkedSocket):
        def close(self) -> None:
            self.closed = True
            raise OSError(private)

    connection = Connection(
        [websocket_handshake() + server_frame(b'{"id":7,"result":{}}')]
    )
    install_socket(monkeypatch, connection)

    with pytest.raises(ContractError) as captured:
        cdp_module._websocket_json_command(
            "ws://127.0.0.1:9222/devtools/page/owned",
            {"id": 7, "method": "Runtime.evaluate"},
            1.0,
        )
    assert str(captured.value) == ("CDP WebSocket cleanup failed (connection-close)")
    assert private not in str(captured.value)
    assert connection.closed is True


def test_websocket_close_failure_retains_handshake_error_as_cause(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Connection(ChunkedSocket):
        def close(self) -> None:
            raise RuntimeError("private close")

    connection = Connection([b"HTTP/1.1 403 Forbidden\r\n\r\n"])
    install_socket(monkeypatch, connection)

    with pytest.raises(ContractError) as captured:
        with cdp_module._websocket_connection(
            "ws://127.0.0.1:9222/devtools/browser/owned",
            1.0,
            os_error_label="owned CDP",
        ):
            pytest.fail("rejected handshake reached body")
    assert str(captured.value) == ("CDP WebSocket cleanup failed (connection-close)")
    assert isinstance(captured.value.__cause__, ContractError)
    assert "private" not in str(captured.value)


def test_fixture_wait_fails_immediately_on_declared_failure_title(monkeypatch) -> None:
    response = JsonResponse(
        json.dumps(
            [
                {
                    "type": "page",
                    "url": "http://127.0.0.1:8000/fixture",
                    "title": "fixture-failed:Error",
                }
            ]
        ).encode("utf-8")
    )
    monkeypatch.setattr("browser_core.cdp.urlopen", lambda *args, **kwargs: response)

    with pytest.raises(ContractError, match="failure title"):
        wait_for_page_target(
            "http://127.0.0.1:9222",
            "http://127.0.0.1:8000/fixture",
            "fixture-ok",
            timeout_seconds=1,
            failure_title_prefix="fixture-failed:",
        )


def test_input_command_rejects_methods_outside_the_allowlist():
    """The CDP surface this package exposes must stay narrow.

    An unrestricted command sender would widen it from "evaluate an expression and
    read a target list" to all of CDP, through a function whose name suggests it
    only sends input.
    """
    from browser_core.cdp import send_page_input_command

    for method in (
        "Runtime.evaluate",
        "Page.navigate",
        "Network.enable",
        "Browser.close",
        "Input.setIgnoreInputEvents",
    ):
        with pytest.raises(ContractError, match="input allowlist"):
            send_page_input_command("http://127.0.0.1:1/", method, {})


@pytest.mark.parametrize(
    "method",
    [[], ["Input.dispatchMouseEvent"], {}, {"method": "Input.dispatchMouseEvent"}],
)
def test_input_command_rejects_unhashable_methods_cleanly(method):
    from browser_core.cdp import send_page_input_command

    with pytest.raises(ContractError, match="input allowlist"):
        send_page_input_command("http://127.0.0.1:1/", method, {})


@pytest.mark.parametrize(
    "method",
    [[], ["Input.dispatchMouseEvent"], {}, {"method": "Input.dispatchMouseEvent"}],
)
def test_input_batch_rejects_unhashable_methods_cleanly(method):
    from browser_core.cdp import send_page_input_batch

    with pytest.raises(ContractError, match="input allowlist"):
        send_page_input_batch("http://127.0.0.1:1/", [(method, {})])


def test_input_batch_rejects_a_bad_method_before_opening_a_connection():
    """Validation happens up front, so one bad event cannot half-deliver a batch."""
    from browser_core.cdp import send_page_input_batch

    events = [
        ("Input.dispatchMouseEvent", {"type": "mouseMoved", "x": 1, "y": 1}),
        ("Page.reload", {}),
    ]
    with pytest.raises(ContractError, match="input allowlist"):
        send_page_input_batch("http://127.0.0.1:1/", events)


def test_input_command_rejects_non_mapping_params():
    from browser_core.cdp import send_page_input_command

    with pytest.raises(ContractError, match="mapping"):
        send_page_input_command(
            "http://127.0.0.1:1/",
            "Input.dispatchMouseEvent",
            ["x"],  # type: ignore[arg-type]
        )


def test_input_batch_rejects_a_non_positive_timeout():
    from browser_core.cdp import send_page_input_batch

    with pytest.raises(ContractError, match="timeout"):
        send_page_input_batch(
            "http://127.0.0.1:1/",
            [("Input.dispatchMouseEvent", {"type": "mouseMoved"})],
            timeout_seconds=0,
        )


@pytest.mark.parametrize(
    "invalid",
    [float("nan"), float("inf"), True, "1", 301],
)
def test_all_public_cdp_timeouts_fail_before_browser_contact(
    monkeypatch, invalid
) -> None:
    monkeypatch.setattr(
        cdp_module,
        "_page_websocket_url",
        lambda *_args: pytest.fail("target lookup must not occur"),
    )
    calls = [
        lambda: wait_for_page_target(
            "http://127.0.0.1:1", "about:blank", "ready", invalid
        ),
        lambda: cdp_module.observe_page_resource_intents(
            "http://127.0.0.1:1", target_url="about:blank", timeout_seconds=invalid
        ),
        lambda: cdp_module.send_page_input_batch(
            "http://127.0.0.1:1", [], timeout_seconds=invalid
        ),
        lambda: cdp_module.send_page_input_command(
            "http://127.0.0.1:1",
            "Input.dispatchMouseEvent",
            {},
            timeout_seconds=invalid,
        ),
        lambda: cdp_module.evaluate_page_expression(
            "http://127.0.0.1:1", "1", timeout_seconds=invalid
        ),
        lambda: cdp_module.observe_runtime_identity(
            "http://127.0.0.1:1", "about:blank", timeout_seconds=invalid
        ),
    ]
    for call in calls:
        with pytest.raises(ContractError, match="finite and positive"):
            call()


def test_input_batch_bounds_the_complete_plan_before_connection(monkeypatch):
    from browser_core.cdp import send_page_input_batch

    monkeypatch.setattr(
        cdp_module,
        "_page_websocket_url",
        lambda *_args: pytest.fail("target lookup must not occur"),
    )
    event = ("Input.dispatchMouseEvent", {"type": "mouseMoved"})
    with pytest.raises(ContractError, match="at most"):
        send_page_input_batch(
            "http://127.0.0.1:1/",
            [event] * (cdp_module._MAX_CDP_INPUT_EVENTS + 1),
        )

    huge = (
        "Input.dispatchMouseEvent",
        {"type": "mouseMoved", "private": "x" * cdp_module._MAX_CDP_MESSAGE_BYTES},
    )
    with pytest.raises(ContractError, match="message byte limit"):
        send_page_input_batch("http://127.0.0.1:1/", [huge])


@pytest.mark.parametrize("event", [(), ("Input.dispatchMouseEvent",), "bad"])
def test_input_batch_rejects_malformed_event_shape_before_connection(
    monkeypatch, event
) -> None:
    from browser_core.cdp import send_page_input_batch

    monkeypatch.setattr(
        cdp_module,
        "_page_websocket_url",
        lambda *_args: pytest.fail("target lookup must not occur"),
    )
    with pytest.raises(ContractError, match="method, params"):
        send_page_input_batch("http://127.0.0.1:1/", [event])


def test_input_batch_failure_receipts_do_not_echo_socket_diagnostics(monkeypatch):
    from browser_core.cdp import send_page_input_batch

    private = r"socket failed at C:\private\profile with account-token"

    class FailingConnection:
        def sendall(self, _payload):
            raise OSError(private)

    @contextmanager
    def connection(*_args, **_kwargs):
        yield FailingConnection(), object()

    monkeypatch.setattr(
        cdp_module,
        "_page_websocket_url",
        lambda *_args: "ws://127.0.0.1:9222/devtools/page/owned",
    )
    monkeypatch.setattr(cdp_module, "_websocket_connection", connection)
    result = send_page_input_batch(
        "http://127.0.0.1:9222",
        [("Input.dispatchMouseEvent", {"type": "mouseMoved", "x": 1, "y": 1})],
    )
    rendered = json.dumps(result)
    assert result["dispatched"] == 0
    assert result["errors"][0].startswith(
        "Input.dispatchMouseEvent: execution-failure; diagnostic_sha256_16="
    )
    assert private not in rendered


def test_input_batch_does_not_count_protocol_error_as_dispatched(monkeypatch) -> None:
    from browser_core.cdp import send_page_input_batch

    private = "private-input-rejection"
    rejected = server_frame(
        json.dumps({"id": 100, "error": {"message": private}}).encode("utf-8")
    )
    accepted = server_frame(b'{"id":101,"result":{}}')
    connection = ChunkedSocket([websocket_handshake() + rejected + accepted])
    install_socket(monkeypatch, connection)
    monkeypatch.setattr(
        cdp_module,
        "_page_websocket_url",
        lambda *_args: "ws://127.0.0.1:9222/devtools/page/owned",
    )

    result = send_page_input_batch(
        "http://127.0.0.1:9222",
        [
            ("Input.dispatchMouseEvent", {"type": "mouseMoved", "x": 1, "y": 1}),
            ("Input.dispatchMouseEvent", {"type": "mouseMoved", "x": 2, "y": 2}),
        ],
        first_command_id=100,
    )

    assert result["attempted"] == 2
    assert result["dispatched"] == 1
    assert len(result["errors"]) == 1
    assert private not in json.dumps(result)


def test_input_batch_reports_cleanup_after_whole_batch_deadline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = [0.0]
    monkeypatch.setattr(
        cdp_module, "time", SimpleNamespace(monotonic=lambda: clock[0])
    )

    class LateCloseSocket(ChunkedSocket):
        def close(self) -> None:
            clock[0] = 2.0
            super().close()

    connection = LateCloseSocket(
        [websocket_handshake() + server_frame(b'{"id":960,"result":{}}')]
    )
    install_socket(monkeypatch, connection)
    monkeypatch.setattr(
        cdp_module,
        "_page_websocket_url",
        lambda *_args: "ws://127.0.0.1:9222/devtools/page/owned",
    )
    report = cdp_module.send_page_input_batch(
        "http://127.0.0.1:9222",
        [("Input.dispatchMouseEvent", {"type": "mouseMoved", "x": 1, "y": 1})],
        timeout_seconds=1.0,
    )
    assert report["dispatched"] == 1
    assert report["errors"] == ["batch: CDP input batch deadline expired"]
    assert connection.closed


def test_resource_intent_projection_cannot_publish_after_deadline(monkeypatch):
    clock = [0.0]
    monkeypatch.setattr(
        cdp_module, "time", SimpleNamespace(monotonic=lambda: clock[0])
    )
    monkeypatch.setattr(
        cdp_module,
        "_page_websocket_url",
        lambda *_args: "ws://127.0.0.1:9222/devtools/page/owned",
    )
    target_url = "http://127.0.0.1:8000/owned"
    monkeypatch.setattr(
        cdp_module,
        "_websocket_json_command",
        lambda *_args: {
            "result": {
                "strings": [target_url, "A", "href", "/asset.js"],
                "documents": [
                    {
                        "baseURL": 0,
                        "nodes": {
                            "nodeName": [1],
                            "attributes": [[2, 3]],
                        },
                    }
                ],
            }
        },
    )

    def late_projection(*_args, **_kwargs):
        clock[0] = 2.0
        return {"origin": "loopback-rehost"}

    monkeypatch.setattr(cdp_module, "_resource_url_projection", late_projection)
    with pytest.raises(ContractError, match="deadline expired"):
        cdp_module.observe_page_resource_intents(
            "http://127.0.0.1:9222",
            target_url=target_url,
            timeout_seconds=1.0,
        )


def test_resource_intents_stop_projecting_after_deadline(monkeypatch):
    clock = [0.0]
    monkeypatch.setattr(
        cdp_module, "time", SimpleNamespace(monotonic=lambda: clock[0])
    )
    monkeypatch.setattr(
        cdp_module,
        "_page_websocket_url",
        lambda *_args: "ws://127.0.0.1:9222/devtools/page/owned",
    )
    target_url = "http://127.0.0.1:8000/owned"
    monkeypatch.setattr(
        cdp_module,
        "_websocket_json_command",
        lambda *_args: {
            "result": {
                "strings": [target_url, "A", "href", "/first.js", "/second.js"],
                "documents": [
                    {
                        "baseURL": 0,
                        "nodes": {
                            "nodeName": [1],
                            "attributes": [[2, 3, 2, 4]],
                        },
                    }
                ],
            }
        },
    )
    projections = []

    def late_first_projection(value, **_kwargs):
        projections.append(value)
        clock[0] = 2.0
        return {"origin": "loopback-rehost"}

    monkeypatch.setattr(cdp_module, "_resource_url_projection", late_first_projection)
    with pytest.raises(ContractError, match="deadline expired"):
        cdp_module.observe_page_resource_intents(
            "http://127.0.0.1:9222",
            target_url=target_url,
            timeout_seconds=1.0,
        )
    assert projections == ["/first.js"]


def test_resource_url_projection_bounds_separator_processing(monkeypatch):
    class BoundedPath(str):
        def split(self, *_args, **_kwargs):
            pytest.fail("resource path split was unbounded")

    class BoundedQuery(str):
        def split(self, separator=None, maxsplit=-1):
            assert separator == "&" and maxsplit == 64
            return super().split(separator, maxsplit)

    path = BoundedPath("/x" * 1000)
    query = BoundedQuery("safe=x&" * 1000)

    def parsed_url(value):
        if value == "https://target.example/":
            return SimpleNamespace(
                scheme="https", hostname="target.example", port=None,
                path="/", query="",
            )
        return SimpleNamespace(
            scheme="https", hostname="external.example", port=None,
            path=path, query=query,
        )

    monkeypatch.setattr(cdp_module, "urlsplit", parsed_url)
    projected = cdp_module._resource_url_projection(
        "https://external.example/resource",
        base_url="https://target.example/",
        target_url="https://target.example/",
    )
    assert projected is not None
    assert projected["path_segment_lengths"] == [1] * 32
    assert projected["path_segments_truncated"] is True
    assert projected["query_names"] == ["safe"]
    assert projected["query_names_truncated"] is True


@pytest.mark.parametrize(
    "resource_url",
    [
        "http://2130706433:8000/x",
        "http://127.1:8000/x",
        "http://0x7f000001:8000/x",
        "http://0177.0.0.1:8000/x",
        "http://127.0.0.1.:8000/x",
        "http://127%2e0%2e0%2e1:8000/x",
        "http://%31%32%37.0.0.1:8000/x",
    ],
)
def test_resource_url_projection_uses_browser_numeric_ipv4_origin(resource_url):
    projected = cdp_module._resource_url_projection(
        resource_url,
        base_url="http://127.0.0.1:8000/",
        target_url="http://127.0.0.1:8000/",
    )

    assert projected is not None
    assert projected["origin"] == "loopback-rehost"
    assert projected["same_origin_as_rehost"] is True


def test_resource_url_projection_uses_browser_ipv6_origin():
    projected = cdp_module._resource_url_projection(
        "http://[0:0:0:0:0:0:0:1]:8000/x",
        base_url="http://[::1]:8000/",
        target_url="http://[::1]:8000/",
    )

    assert projected is not None
    assert projected["origin"] == "loopback-rehost"
    assert projected["same_origin_as_rehost"] is True


@pytest.mark.parametrize(
    ("scheme", "hostname", "port"),
    [
        ([], "example.com", None),
        ("https", 42, None),
        ("https", "example.com", True),
        ("https", "example.com", False),
        ("https", "example.com", -1),
        ("https", "example.com", 65536),
        ("https", "example.com", "443"),
    ],
)
def test_resource_origin_projection_withholds_invalid_direct_inputs(
    scheme, hostname, port,
):
    assert cdp_module.project_resource_intent_origin(scheme, hostname, port) is None


@pytest.mark.parametrize("host", ["test.42", "127.08", "4294967296"])
def test_resource_url_projection_does_not_publish_invalid_numeric_host(host):
    projected = cdp_module._resource_url_projection(
        f"http://{host}/x",
        base_url="http://127.0.0.1:8000/",
        target_url="http://127.0.0.1:8000/",
    )

    assert projected is None


def test_resource_url_projection_bounds_untrusted_numeric_host():
    projected = cdp_module._resource_url_projection(
        f"http://{'9' * 5000}/x",
        base_url="http://127.0.0.1:8000/",
        target_url="http://127.0.0.1:8000/",
    )

    assert projected is None


@pytest.mark.parametrize(
    "resource_url",
    [
        "http://faß.de:8000/x",
        "http://127.0.0.1\\@external.example:8000/x",
        "http:///external.example/x",
        "http:////external.example/x",
        "http:////?q=x",
        "///external.example/x",
        "////external.example/x",
    ],
)
def test_resource_url_projection_withholds_unsupported_browser_host(resource_url):
    projected = cdp_module._resource_url_projection(
        resource_url,
        base_url="http://127.0.0.1:8000/",
        target_url="http://127.0.0.1:8000/",
    )

    assert projected is None


@pytest.mark.parametrize(
    "resource_url",
    [
        "image with space.js",
        "/café.js",
        '/image"name.js',
        "/x?private\x00name=value",
        "/x?private'name=value",
        "/a/%2e%2e/private.js",
        "a/.%2E/private.js",
        "/a;",
        "/a/b;",
        "/;",
    ],
)
def test_resource_url_projection_withholds_browser_serialization_mismatch(
    resource_url,
):
    projected = cdp_module._resource_url_projection(
        resource_url,
        base_url="http://127.0.0.1:8000/base/",
        target_url="http://127.0.0.1:8000/",
    )

    assert projected is None


@pytest.mark.parametrize(
    "resource_url",
    ["/caf%C3%A9.js", "/image%20name.js", "/a/%2eprivate.js", "/a%3B"],
)
def test_resource_url_projection_keeps_explicitly_encoded_nondot_paths(resource_url):
    projected = cdp_module._resource_url_projection(
        resource_url,
        base_url="http://127.0.0.1:8000/",
        target_url="http://127.0.0.1:8000/",
    )

    assert projected is not None
    assert projected["origin"] == "loopback-rehost"
    assert projected["path_segment_lengths"] == [
        len(segment) for segment in resource_url.split("/") if segment
    ]


def test_resource_url_projection_flags_query_name_length_truncation():
    long_name = "n" * 81
    projected = cdp_module._resource_url_projection(
        f"/image?{long_name}=value",
        base_url="http://127.0.0.1:8000/",
        target_url="http://127.0.0.1:8000/",
    )

    assert projected is not None
    assert projected["query_names"] == [long_name[:80]]
    assert projected["query_names_truncated"] is True


def test_resource_url_projection_keeps_raw_semicolon_in_query_name():
    projected = cdp_module._resource_url_projection(
        "/a?key;part=value",
        base_url="http://127.0.0.1:8000/",
        target_url="http://127.0.0.1:8000/",
    )

    assert projected is not None
    assert projected["path_segment_lengths"] == [1]
    assert projected["query_names"] == ["key;part"]


@pytest.mark.parametrize("resource_url", ["?", "?#fragment"])
def test_resource_url_projection_clears_empty_query_override(resource_url):
    projected = cdp_module._resource_url_projection(
        resource_url,
        base_url="http://127.0.0.1:8000/base/page?old=1",
        target_url="http://127.0.0.1:8000/",
    )
    populated = cdp_module._resource_url_projection(
        "?fresh=1",
        base_url="http://127.0.0.1:8000/base/page?old=1",
        target_url="http://127.0.0.1:8000/",
    )

    assert projected is not None
    assert projected["query_names"] == []
    assert populated is not None
    assert populated["query_names"] == ["fresh"]


def test_resource_url_projection_withholds_path_segment_above_saved_limit():
    at_limit = cdp_module._resource_url_projection(
        "/" + "x" * 1_000_000,
        base_url="http://127.0.0.1:8000/",
        target_url="http://127.0.0.1:8000/",
    )
    over_limit = cdp_module._resource_url_projection(
        "/" + "x" * 1_000_001,
        base_url="http://127.0.0.1:8000/",
        target_url="http://127.0.0.1:8000/",
    )

    assert at_limit is not None
    assert at_limit["path_segment_lengths"] == [1_000_000]
    assert over_limit is None


@pytest.mark.parametrize(
    "resource_url, expected_status",
    [
        ("http://faß.de/image", "unverifiable"),
        ("http:////external.example/image", "unverifiable"),
        ("///external.example/image", "unverifiable"),
        ("/a/%2e%2e/private.js", "unverifiable"),
        ("/x?private\x00name=value", "unverifiable"),
        ("/a;", "unverifiable"),
        ("0:c", "unverifiable"),
        ("+:path", "unverifiable"),
        ("data:text/plain,hello", "ok"),
        ("javascript:void(0)", "ok"),
    ],
)
def test_resource_intents_classify_unprojectable_url_status(
    monkeypatch, resource_url, expected_status
):
    monkeypatch.setattr(
        cdp_module,
        "_page_websocket_url",
        lambda endpoint, target, timeout: "ws://127.0.0.1:9222/devtools/page/owned",
    )
    monkeypatch.setattr(
        cdp_module,
        "_websocket_json_command",
        lambda *args: {
            "result": {
                "strings": [
                    "http://127.0.0.1:8000/",
                    "IMG",
                    "src",
                    resource_url,
                ],
                "documents": [
                    {
                        "baseURL": 0,
                        "nodes": {"nodeName": [1], "attributes": [[2, 3]]},
                    }
                ],
            }
        },
    )

    report = cdp_module.observe_page_resource_intents(
        "http://127.0.0.1:9222/", target_url="http://127.0.0.1:8000/"
    )

    assert report["status"] == expected_status
    assert report["intents"] == []
    assert "private\u0000name" not in json.dumps(report)


def test_resource_intents_use_one_narrow_dom_snapshot_and_redact_values(monkeypatch):
    monkeypatch.setattr(
        cdp_module,
        "_page_websocket_url",
        lambda endpoint, target, timeout: "ws://127.0.0.1:9222/devtools/page/owned",
    )
    seen = {}

    def command(websocket_url, payload, timeout_seconds):
        seen.update(
            websocket_url=websocket_url,
            payload=payload,
            timeout_seconds=timeout_seconds,
        )
        strings = [
            "http://127.0.0.1:8000/",
            "IFRAME",
            "src",
            "https://user:password@challenges.example/tenant/abc?sitekey=secret&lang=en#token",
            "A",
            "href",
            "/private/path?session=opaque-value",
        ]
        return {
            "id": payload["id"],
            "result": {
                "strings": strings,
                "documents": [
                    {
                        "baseURL": 0,
                        "nodes": {
                            "nodeName": [1, 4],
                            "attributes": [[2, 3], [5, 6]],
                        },
                    }
                ],
            },
        }

    monkeypatch.setattr(cdp_module, "_websocket_json_command", command)
    report = cdp_module.observe_page_resource_intents(
        "http://127.0.0.1:9222/",
        target_url="http://127.0.0.1:8000/",
        timeout_seconds=4.0,
    )
    assert seen["payload"] == {
        "id": 958,
        "method": "DOMSnapshot.captureSnapshot",
        "params": {
            "computedStyles": [],
            "includePaintOrder": False,
            "includeDOMRects": False,
        },
    }
    assert seen["timeout_seconds"] == 4.0
    assert report["status"] == "ok"
    assert report["candidate_attributes"] == 2
    external = next(
        row for row in report["intents"] if not row["same_origin_as_rehost"]
    )
    assert external == {
        "tag": "iframe",
        "attribute": "src",
        "count": 1,
        "origin": "https://challenges.example",
        "same_origin_as_rehost": False,
        "path_segment_lengths": [6, 3],
        "path_segments_truncated": False,
        "query_names": ["lang", "sitekey"],
        "query_names_truncated": False,
    }
    local = next(row for row in report["intents"] if row["same_origin_as_rehost"])
    assert local["origin"] == "loopback-rehost"
    assert "8000" not in json.dumps(report)
    rendered = json.dumps(report)
    for secret in (
        "user",
        "password",
        "tenant",
        "abc",
        "secret",
        "opaque-value",
        "token",
    ):
        assert secret not in rendered


def test_resource_intents_preserve_safe_duplicate_shape_counts(monkeypatch):
    monkeypatch.setattr(
        cdp_module,
        "_page_websocket_url",
        lambda *_args: "ws://127.0.0.1:9222/devtools/page/owned",
    )
    monkeypatch.setattr(
        cdp_module,
        "_websocket_json_command",
        lambda *_args: {
            "result": {
                "strings": [
                    "http://127.0.0.1:8000/",
                    "SCRIPT",
                    "src",
                    "https://static.example/v4/challenge.js?sitekey=secret",
                ],
                "documents": [
                    {
                        "baseURL": 0,
                        "nodes": {
                            "nodeName": [1, 1],
                            "attributes": [[2, 3], [2, 3]],
                        },
                    }
                ],
            }
        },
    )

    report = cdp_module.observe_page_resource_intents(
        "http://127.0.0.1:9222/",
        target_url="http://127.0.0.1:8000/",
    )

    assert report["candidate_attributes"] == 2
    assert report["distinct_intents"] == 1
    assert report["intents"][0]["count"] == 2
    assert "secret" not in json.dumps(report)


def test_resource_intents_coarsen_page_controlled_custom_element_names(monkeypatch):
    monkeypatch.setattr(
        cdp_module,
        "_page_websocket_url",
        lambda *_args: "ws://127.0.0.1:9222/devtools/page/owned",
    )
    monkeypatch.setattr(
        cdp_module,
        "_websocket_json_command",
        lambda *_args: {
            "result": {
                "strings": [
                    "http://127.0.0.1:8000/",
                    "PRIVATE-TENANT-WIDGET",
                    "src",
                    "https://static.example/challenge.js",
                ],
                "documents": [
                    {
                        "baseURL": 0,
                        "nodes": {"nodeName": [1], "attributes": [[2, 3]]},
                    }
                ],
            }
        },
    )

    report = cdp_module.observe_page_resource_intents(
        "http://127.0.0.1:9222/",
        target_url="http://127.0.0.1:8000/",
    )

    assert report["intents"][0]["tag"] == "other-element"
    assert "private-tenant" not in json.dumps(report).lower()


def test_resource_intents_declare_when_distinct_shape_cap_truncates(monkeypatch):
    monkeypatch.setattr(
        cdp_module,
        "_page_websocket_url",
        lambda *_args: "ws://127.0.0.1:9222/devtools/page/owned",
    )
    total = cdp_module._MAX_RESOURCE_INTENTS + 1
    strings = ["http://127.0.0.1:8000/", "SCRIPT", "src"] + [
        f"https://r{index}.example.invalid/x" for index in range(total)
    ]
    monkeypatch.setattr(
        cdp_module,
        "_websocket_json_command",
        lambda *_args: {
            "result": {
                "strings": strings,
                "documents": [
                    {
                        "baseURL": 0,
                        "nodes": {
                            "nodeName": [1] * total,
                            "attributes": [[2, 3 + index] for index in range(total)],
                        },
                    }
                ],
            }
        },
    )

    report = cdp_module.observe_page_resource_intents(
        "http://127.0.0.1:9222/",
        target_url="http://127.0.0.1:8000/",
    )

    assert report["candidate_attributes"] == total
    assert report["distinct_intents"] == total
    assert len(report["intents"]) == cdp_module._MAX_RESOURCE_INTENTS
    assert report["truncated"] is True


def test_resource_intents_reject_malformed_snapshot_attributes(monkeypatch):
    monkeypatch.setattr(
        cdp_module, "_page_websocket_url", lambda *_args: "ws://loopback"
    )
    monkeypatch.setattr(
        cdp_module,
        "_websocket_json_command",
        lambda *_args: {
            "result": {
                "strings": ["http://127.0.0.1/", "IMG", "src"],
                "documents": [
                    {
                        "baseURL": 0,
                        "nodes": {"nodeName": [1], "attributes": [[2]]},
                    }
                ],
            }
        },
    )
    with pytest.raises(ContractError, match="attributes are invalid"):
        cdp_module.observe_page_resource_intents(
            "http://127.0.0.1:9222/", target_url="http://127.0.0.1/"
        )


@pytest.mark.parametrize(
    ("base_url", "node_names", "attributes", "error"),
    [
        (99, [1], [[2, 3]], "base URL"),
        (0, [1, 1], [[2, 3]], "node arrays"),
        (0, [99], [[2, 3]], "node name"),
        (0, [1], [[99, 3]], "attribute index"),
        (0, [1], [[2, 99]], "attribute index"),
    ],
)
def test_resource_intents_reject_invalid_parallel_snapshot_indices(
    monkeypatch, base_url, node_names, attributes, error
) -> None:
    monkeypatch.setattr(
        cdp_module,
        "_page_websocket_url",
        lambda *_args: "ws://127.0.0.1:9222/devtools/page/owned",
    )
    monkeypatch.setattr(
        cdp_module,
        "_websocket_json_command",
        lambda *_args: {
            "result": {
                "strings": [
                    "http://127.0.0.1/",
                    "IMG",
                    "src",
                    "/pixel.gif",
                ],
                "documents": [
                    {
                        "baseURL": base_url,
                        "nodes": {
                            "nodeName": node_names,
                            "attributes": attributes,
                        },
                    }
                ],
            }
        },
    )

    with pytest.raises(ContractError, match=error):
        cdp_module.observe_page_resource_intents(
            "http://127.0.0.1:9222/", target_url="http://127.0.0.1/"
        )


def test_resource_intents_reject_non_positive_timeout_before_discovery():
    with pytest.raises(ContractError, match="timeout"):
        cdp_module.observe_page_resource_intents(
            "http://127.0.0.1:9222/",
            target_url="http://127.0.0.1/",
            timeout_seconds=0,
        )
