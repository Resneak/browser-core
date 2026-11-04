"""Value-free projection of an HTTP/2 client's initial connection flight."""

from __future__ import annotations

import hashlib
import json
import re
import secrets
import socket
import ssl
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Callable

from .build import _hash_regular_file, load_build_attestation
from .control_files import (
    decode_strict_json_bytes,
    publish_json_exclusive,
    read_bounded_control_snapshot_result,
    require_bounded_control_snapshot_unchanged,
)
from .contracts import RUN_ID_RE, reject_sensitive_keys
from .profiles import has_windows_device_basename
from .errors import ContractError
from .numeric import is_finite_number
from .owned_paths import directory_ancestry_binding, prepare_owned_directory_parent
from .prepared_download import guarded_temporary_directory
from .transport_fingerprint import _stop_process


HTTP2_FINGERPRINT_SCHEMA = "browser-core.http2-fingerprint/1"
HTTP2_FINGERPRINT_COMPARISON_SCHEMA = (
    "browser-core.http2-fingerprint-comparison/1"
)
HTTP2_BASELINE_SCHEMA = "browser-core.http2-baseline/1"
HTTP2_CONNECTION_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
MAX_HTTP2_CAPTURE_BYTES = 256 * 1024
MAX_HTTP2_FRAME_PAYLOAD_BYTES = 16 * 1024
MAX_HTTP2_SETTINGS = 64
MAX_HTTP2_PRE_HEADER_FRAMES = 256
MAX_HTTP2_WINDOW_UPDATES = 16
MAX_HTTP2_CERTIFICATE_BYTES = 2 * 1024 * 1024
MAX_HTTP2_PRIVATE_KEY_BYTES = 2 * 1024 * 1024
MAX_HTTP2_FINGERPRINT_BYTES = 1024 * 1024

_DATA = 0
_HEADERS = 1
_PRIORITY = 2
_RST_STREAM = 3
_SETTINGS = 4
_PUSH_PROMISE = 5
_PING = 6
_GOAWAY = 7
_WINDOW_UPDATE = 8
_CONTINUATION = 9
_EMPTY_SERVER_SETTINGS_AND_ACK = (
    b"\x00\x00\x00\x04\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x04\x01\x00\x00\x00\x00"
)
_HTTP2_BASELINE_NON_CLAIM = (
    "Operator-approved local HTTP/2 initial-flight baseline only; not HTTP/3 "
    "or remote edge acceptance"
)


def _validate_setting_value(identifier: int, value: int) -> None:
    if identifier == 2 and value not in {0, 1}:
        raise ContractError("HTTP/2 SETTINGS_ENABLE_PUSH value is invalid")
    if identifier == 4 and value > 0x7FFFFFFF:
        raise ContractError("HTTP/2 SETTINGS_INITIAL_WINDOW_SIZE value is invalid")
    if identifier == 5 and not 0x4000 <= value <= 0xFFFFFF:
        raise ContractError("HTTP/2 SETTINGS_MAX_FRAME_SIZE value is invalid")
    if identifier in {8, 9} and value not in {0, 1}:
        raise ContractError("HTTP/2 boolean SETTINGS value is invalid")


def _validate_pre_headers_frame(
    frame_type: int,
    flags: int,
    stream_id: int,
    payload: bytes,
) -> None:
    """Validate standard frame structure visible before the first HEADERS."""
    length = len(payload)
    if frame_type == _DATA:
        raise ContractError("HTTP/2 client sent DATA before HEADERS")
    if frame_type == _PRIORITY:
        if flags != 0 or stream_id == 0 or length != 5:
            raise ContractError("HTTP/2 PRIORITY frame is invalid")
        dependency = int.from_bytes(payload[:4], "big") & 0x7FFFFFFF
        if dependency == stream_id:
            raise ContractError("HTTP/2 stream depends on itself")
        return
    if frame_type == _RST_STREAM:
        if flags != 0 or stream_id == 0 or length != 4:
            raise ContractError("HTTP/2 RST_STREAM frame is invalid")
        return
    if frame_type == _PUSH_PROMISE:
        raise ContractError("HTTP/2 client sent PUSH_PROMISE")
    if frame_type == _PING:
        if flags & ~0x01 or stream_id != 0 or length != 8:
            raise ContractError("HTTP/2 PING frame is invalid")
        return
    if frame_type == _GOAWAY:
        if flags != 0 or stream_id != 0 or length < 8:
            raise ContractError("HTTP/2 GOAWAY frame is invalid")
        return
    if frame_type == _CONTINUATION:
        raise ContractError("HTTP/2 client sent CONTINUATION before HEADERS")


def _validate_headers_frame(flags: int, stream_id: int, payload: bytes) -> None:
    if stream_id == 0:
        raise ContractError("HTTP/2 HEADERS stream is invalid")
    if stream_id % 2 == 0:
        raise ContractError("HTTP/2 client HEADERS stream is not odd")
    if flags & ~0x2D:
        raise ContractError("HTTP/2 HEADERS flags are invalid")
    cursor = 0
    padding = 0
    if flags & 0x08:
        if not payload:
            raise ContractError("HTTP/2 HEADERS padding is invalid")
        padding = payload[0]
        cursor = 1
    if padding > len(payload) - cursor:
        raise ContractError("HTTP/2 HEADERS padding is invalid")
    if flags & 0x20:
        if len(payload) - cursor - padding < 5:
            raise ContractError("HTTP/2 HEADERS priority is invalid")
        dependency = int.from_bytes(payload[cursor : cursor + 4], "big") & 0x7FFFFFFF
        if dependency == stream_id:
            raise ContractError("HTTP/2 stream depends on itself")


def _validate_components(
    record: Any,
    *,
    require_build: bool = False,
) -> dict[str, Any]:
    core_fields = {
        "schema",
        "settings",
        "connection_window_updates",
        "pre_headers_frame_types",
        "headers_started",
    }
    if type(record) is not dict:
        raise ContractError("HTTP/2 fingerprint fields are invalid")
    expected = set(core_fields)
    if "digest_sha256" in record:
        expected.add("digest_sha256")
    if "core_build" in record:
        expected.add("core_build")
    if set(record) != expected or (require_build and "core_build" not in record):
        raise ContractError("HTTP/2 fingerprint fields are invalid")
    if record.get("schema") != HTTP2_FINGERPRINT_SCHEMA:
        raise ContractError("HTTP/2 fingerprint schema is invalid")
    settings = record.get("settings")
    if not isinstance(settings, list) or len(settings) > MAX_HTTP2_SETTINGS:
        raise ContractError("HTTP/2 fingerprint settings are invalid")
    setting_ids: set[int] = set()
    for setting in settings:
        if type(setting) is not dict or set(setting) != {"id", "value"}:
            raise ContractError("HTTP/2 fingerprint setting is invalid")
        identifier = setting.get("id")
        value = setting.get("value")
        if (
            isinstance(identifier, bool)
            or not isinstance(identifier, int)
            or not 0 <= identifier <= 0xFFFF
            or identifier in setting_ids
            or isinstance(value, bool)
            or not isinstance(value, int)
            or not 0 <= value <= 0xFFFFFFFF
        ):
            raise ContractError("HTTP/2 fingerprint setting is invalid")
        _validate_setting_value(identifier, value)
        setting_ids.add(identifier)
    updates = record.get("connection_window_updates")
    if (
        not isinstance(updates, list)
        or len(updates) > MAX_HTTP2_WINDOW_UPDATES
        or any(
            isinstance(value, bool)
            or not isinstance(value, int)
            or not 1 <= value <= 0x7FFFFFFF
            for value in updates
        )
    ):
        raise ContractError("HTTP/2 fingerprint window updates are invalid")
    frame_types = record.get("pre_headers_frame_types")
    if (
        not isinstance(frame_types, list)
        or not 1 <= len(frame_types) <= MAX_HTTP2_PRE_HEADER_FRAMES
        or frame_types[0] != _SETTINGS
        or any(
            isinstance(value, bool)
            or not isinstance(value, int)
            or not 0 <= value <= 0xFF
            for value in frame_types
        )
        or any(value in {_DATA, _HEADERS, _PUSH_PROMISE, _CONTINUATION} for value in frame_types)
    ):
        raise ContractError("HTTP/2 fingerprint pre-HEADERS frame sequence is invalid")
    if len(updates) != frame_types.count(_WINDOW_UPDATE):
        raise ContractError(
            "HTTP/2 fingerprint WINDOW_UPDATE receipts exceed observed frames"
        )
    if type(record.get("headers_started")) is not bool:
        raise ContractError("HTTP/2 fingerprint HEADERS receipt is invalid")
    if require_build and record["headers_started"] is not True:
        raise ContractError("attested HTTP/2 fingerprint has no complete HEADERS flight")
    build = record.get("core_build")
    if "core_build" in record and build is None:
        raise ContractError("HTTP/2 fingerprint build receipt is invalid")
    if build is not None:
        if type(build) is not dict or set(build) != {
            "chromium_revision",
            "executable_sha256_16",
            "runtime_bundle_sha256_16",
        }:
            raise ContractError("HTTP/2 fingerprint build receipt is invalid")
        if (
            not isinstance(build.get("chromium_revision"), str)
            or re.fullmatch(r"[0-9a-f]{40}", build["chromium_revision"]) is None
        ):
            raise ContractError("HTTP/2 fingerprint build receipt is invalid")
        for field in ("executable_sha256_16", "runtime_bundle_sha256_16"):
            if (
                not isinstance(build.get(field), str)
                or re.fullmatch(r"[0-9a-f]{16}", build[field]) is None
            ):
                raise ContractError("HTTP/2 fingerprint build receipt is invalid")
    return record


def http2_fingerprint_digest(record: Any) -> str:
    record = _validate_components(record)
    payload = {
        "settings": record["settings"],
        "connection_window_updates": record["connection_window_updates"],
        "pre_headers_frame_types": record["pre_headers_frame_types"],
        "headers_started": record["headers_started"],
    }
    try:
        body = json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (OverflowError, RecursionError, TypeError, ValueError):
        raise ContractError("HTTP/2 fingerprint cannot be encoded") from None
    return hashlib.sha256(body).hexdigest()


def validate_http2_fingerprint(
    record: Any,
    *,
    require_build: bool = False,
) -> dict[str, Any]:
    record = _validate_components(record, require_build=require_build)
    digest = record.get("digest_sha256")
    if (
        not isinstance(digest, str)
        or re.fullmatch(r"[0-9a-f]{64}", digest) is None
        or digest != http2_fingerprint_digest(record)
    ):
        raise ContractError("HTTP/2 fingerprint digest is invalid")
    return record


def load_http2_fingerprint(path: Path) -> dict[str, Any]:
    if not isinstance(path, Path):
        raise ContractError("HTTP/2 fingerprint path must be a Path")
    selected = path.absolute()
    snapshot = read_bounded_control_snapshot_result(
        selected,
        maximum=MAX_HTTP2_FINGERPRINT_BYTES,
        label="HTTP/2 fingerprint",
        require_single_link=True,
    )
    if snapshot.state != "complete" or snapshot.body is None:
        raise ContractError(f"HTTP/2 fingerprint is {snapshot.state}")
    document = decode_strict_json_bytes(snapshot.body, label="HTTP/2 fingerprint")
    validated = validate_http2_fingerprint(document, require_build=True)
    require_bounded_control_snapshot_unchanged(
        selected,
        snapshot,
        maximum=MAX_HTTP2_FINGERPRINT_BYTES,
        label="HTTP/2 fingerprint",
        require_single_link=True,
    )
    return validated


def _require_http2_fingerprint_id(value: Any, label: str) -> str:
    if (
        not isinstance(value, str)
        or RUN_ID_RE.fullmatch(value) is None
        or has_windows_device_basename(value)
    ):
        raise ContractError(f"HTTP/2 {label} id is invalid")
    return value


def validate_http2_baseline(document: Any) -> dict[str, Any]:
    expected = {
        "schema",
        "source_fingerprint_id",
        "baseline_fingerprint_id",
        "reviewed_digest_sha256",
        "fingerprint",
        "non_claim",
    }
    if type(document) is not dict or set(document) != expected:
        raise ContractError("HTTP/2 baseline fields are invalid")
    if document.get("schema") != HTTP2_BASELINE_SCHEMA:
        raise ContractError("HTTP/2 baseline schema is invalid")
    source_id = _require_http2_fingerprint_id(
        document.get("source_fingerprint_id"), "source fingerprint"
    )
    baseline_id = _require_http2_fingerprint_id(
        document.get("baseline_fingerprint_id"), "baseline fingerprint"
    )
    if source_id == baseline_id:
        raise ContractError("HTTP/2 source and baseline ids must differ")
    reviewed_digest = document.get("reviewed_digest_sha256")
    if (
        not isinstance(reviewed_digest, str)
        or re.fullmatch(r"[0-9a-f]{64}", reviewed_digest) is None
    ):
        raise ContractError("HTTP/2 baseline reviewed digest is invalid")
    fingerprint = validate_http2_fingerprint(
        document.get("fingerprint"), require_build=True
    )
    if fingerprint["digest_sha256"] != reviewed_digest:
        raise ContractError("HTTP/2 baseline reviewed digest does not match")
    if document.get("non_claim") != _HTTP2_BASELINE_NON_CLAIM:
        raise ContractError("HTTP/2 baseline non-claim is invalid")
    reject_sensitive_keys(document)
    return document


def load_http2_baseline(path: Path) -> dict[str, Any]:
    if not isinstance(path, Path):
        raise ContractError("HTTP/2 baseline path must be a Path")
    selected = path.absolute()
    snapshot = read_bounded_control_snapshot_result(
        selected,
        maximum=MAX_HTTP2_FINGERPRINT_BYTES,
        label="HTTP/2 baseline",
        require_single_link=True,
    )
    if snapshot.state != "complete" or snapshot.body is None:
        raise ContractError(f"HTTP/2 baseline is {snapshot.state}")
    document = decode_strict_json_bytes(snapshot.body, label="HTTP/2 baseline")
    validated = validate_http2_baseline(document)
    require_bounded_control_snapshot_unchanged(
        selected,
        snapshot,
        maximum=MAX_HTTP2_FINGERPRINT_BYTES,
        label="HTTP/2 baseline",
        require_single_link=True,
    )
    return validated


def approve_http2_baseline(
    workspace: Path,
    *,
    current_id: str,
    baseline_id: str,
    expected_digest: str,
) -> dict[str, Any]:
    if not isinstance(workspace, Path):
        raise ContractError("HTTP/2 baseline workspace must be a Path")
    current_id = _require_http2_fingerprint_id(current_id, "source fingerprint")
    baseline_id = _require_http2_fingerprint_id(
        baseline_id, "baseline fingerprint"
    )
    if current_id == baseline_id:
        raise ContractError("HTTP/2 source and baseline ids must differ")
    if (
        not isinstance(expected_digest, str)
        or re.fullmatch(r"[0-9a-f]{64}", expected_digest) is None
    ):
        raise ContractError("HTTP/2 reviewed digest is invalid")
    registry = workspace.absolute() / "http2-fingerprints"
    registry_ancestry = directory_ancestry_binding(registry, label="HTTP/2 baseline registry")
    source = registry / f"{current_id}.json"
    destination = registry / f"{baseline_id}.baseline.json"
    if source.is_symlink() or not source.is_file():
        raise ContractError("HTTP/2 baseline source is unknown")
    if destination.exists() or destination.is_symlink():
        raise ContractError("HTTP/2 baseline id already exists")
    record = load_http2_fingerprint(source)
    if record["digest_sha256"] != expected_digest:
        raise ContractError("HTTP/2 baseline does not match reviewed digest")
    if (
        directory_ancestry_binding(registry, label="HTTP/2 baseline registry")
        != registry_ancestry
    ):
        raise ContractError("HTTP/2 baseline registry authority changed")
    baseline = {
        "schema": HTTP2_BASELINE_SCHEMA,
        "source_fingerprint_id": current_id,
        "baseline_fingerprint_id": baseline_id,
        "reviewed_digest_sha256": record["digest_sha256"],
        "fingerprint": record,
        "non_claim": _HTTP2_BASELINE_NON_CLAIM,
    }
    validate_http2_baseline(baseline)
    source_before_publication = load_http2_fingerprint(source)
    registry_before_publication = directory_ancestry_binding(
        registry,
        label="HTTP/2 baseline registry",
    )
    if source_before_publication != record or registry_before_publication != registry_ancestry:
        raise ContractError("HTTP/2 baseline source changed before publication")
    publish_json_exclusive(
        destination,
        baseline,
        maximum=MAX_HTTP2_FINGERPRINT_BYTES,
        label="HTTP/2 baseline",
    )
    published_baseline = load_http2_baseline(destination)
    source_after_publication = load_http2_fingerprint(source)
    registry_after_publication = directory_ancestry_binding(
        registry,
        label="HTTP/2 baseline registry",
    )
    if (
        registry_after_publication != registry_ancestry
        or published_baseline != baseline
        or source_after_publication != record
    ):
        raise ContractError("HTTP/2 baseline source or publication changed")
    return {
        "schema": "browser-core.http2-baseline-approval/1",
        "source_fingerprint_id": current_id,
        "baseline_fingerprint_id": baseline_id,
        "digest_sha256": record["digest_sha256"],
        "core_build": dict(record["core_build"]),
        "non_claim": _HTTP2_BASELINE_NON_CLAIM,
    }


def install_http2_baseline(
    workspace: Path,
    baseline: Any,
) -> dict[str, Any]:
    if not isinstance(workspace, Path):
        raise ContractError("HTTP/2 baseline workspace must be a Path")
    baseline = validate_http2_baseline(baseline)
    registry = workspace.absolute() / "http2-fingerprints"
    prepare_owned_directory_parent(registry, label="HTTP/2 baseline registry")
    registry_ancestry = directory_ancestry_binding(registry, label="HTTP/2 baseline registry")
    destination = registry / f"{baseline['baseline_fingerprint_id']}.baseline.json"
    if destination.exists() or destination.is_symlink():
        raise ContractError("HTTP/2 baseline id already exists")
    publish_json_exclusive(
        destination,
        baseline,
        maximum=MAX_HTTP2_FINGERPRINT_BYTES,
        label="HTTP/2 baseline",
    )
    published_baseline = load_http2_baseline(destination)
    registry_after_publication = directory_ancestry_binding(
        registry,
        label="HTTP/2 baseline registry",
    )
    if (
        published_baseline != baseline
        or registry_after_publication != registry_ancestry
    ):
        raise ContractError("HTTP/2 baseline changed after publication")
    return baseline


def compare_http2_fingerprints(
    current: Any,
    baseline: Any,
) -> dict[str, Any]:
    current = validate_http2_fingerprint(current, require_build=True)
    baseline = validate_http2_fingerprint(baseline, require_build=True)
    compared_fields = {
        "settings",
        "connection_window_updates",
        "pre_headers_frame_types",
        "headers_started",
    }
    changed_fields = sorted(
        field for field in compared_fields if current[field] != baseline[field]
    )
    same_digest = current["digest_sha256"] == baseline["digest_sha256"]
    return {
        "schema": HTTP2_FINGERPRINT_COMPARISON_SCHEMA,
        "passed": same_digest and not changed_fields,
        "same_digest": same_digest,
        "changed_fields": changed_fields,
        "current_digest_sha256": current["digest_sha256"],
        "baseline_digest_sha256": baseline["digest_sha256"],
        "current_core_build": dict(current["core_build"]),
        "baseline_core_build": dict(baseline["core_build"]),
        "non_claim": (
            "Local negotiated HTTP/2 initial-flight equality only; not HTTP/3 "
            "or remote edge acceptance"
        ),
    }


def parse_http2_client_preface(raw: bytes) -> dict[str, Any]:
    """Parse complete bounded frames while discarding all HEADERS payload bytes."""
    if type(raw) is not bytes:
        raise ContractError("HTTP/2 client flight must be bytes")
    if len(raw) > MAX_HTTP2_CAPTURE_BYTES:
        raise ContractError("HTTP/2 client flight exceeds capture limit")
    if not raw.startswith(HTTP2_CONNECTION_PREFACE):
        raise ContractError("HTTP/2 connection preface is invalid")

    cursor = len(HTTP2_CONNECTION_PREFACE)
    first_frame = True
    headers_started = False
    settings: list[dict[str, int]] = []
    setting_ids: set[int] = set()
    connection_window_updates: list[int] = []
    pre_headers_frame_types: list[int] = []

    while cursor < len(raw):
        if len(raw) - cursor < 9:
            raise ContractError("HTTP/2 frame header is truncated")
        length = int.from_bytes(raw[cursor : cursor + 3], "big")
        frame_type = raw[cursor + 3]
        flags = raw[cursor + 4]
        raw_stream_id = int.from_bytes(raw[cursor + 5 : cursor + 9], "big")
        if raw_stream_id & 0x80000000:
            raise ContractError("HTTP/2 frame reserved stream bit is set")
        stream_id = raw_stream_id & 0x7FFFFFFF
        cursor += 9
        if length > MAX_HTTP2_FRAME_PAYLOAD_BYTES:
            raise ContractError("HTTP/2 frame exceeds initial frame limit")
        if cursor + length > len(raw):
            raise ContractError("HTTP/2 frame payload is truncated")
        payload = raw[cursor : cursor + length]
        cursor += length

        was_first_frame = first_frame
        if was_first_frame and frame_type != _SETTINGS:
            raise ContractError("HTTP/2 first frame is not SETTINGS")
        if frame_type == _SETTINGS:
            if stream_id != 0:
                raise ContractError("HTTP/2 initial SETTINGS stream is invalid")
            if flags & ~0x01:
                raise ContractError("HTTP/2 SETTINGS flags are invalid")
            if was_first_frame and flags != 0:
                raise ContractError("HTTP/2 initial SETTINGS flags are invalid")
            if flags & 0x01:
                if length != 0:
                    raise ContractError(
                        "HTTP/2 SETTINGS acknowledgement has a payload"
                    )
            elif length % 6:
                raise ContractError("HTTP/2 initial SETTINGS length is invalid")
            if length // 6 > MAX_HTTP2_SETTINGS:
                raise ContractError("HTTP/2 initial SETTINGS count exceeds limit")
            frame_setting_ids: set[int] = set()
            for offset in range(0, length, 6):
                identifier = int.from_bytes(payload[offset : offset + 2], "big")
                value = int.from_bytes(payload[offset + 2 : offset + 6], "big")
                if identifier in frame_setting_ids:
                    raise ContractError("HTTP/2 initial SETTINGS repeats a setting")
                frame_setting_ids.add(identifier)
                _validate_setting_value(identifier, value)
                if was_first_frame:
                    setting_ids.add(identifier)
                    settings.append({"id": identifier, "value": value})
        if was_first_frame:
            first_frame = False

        if headers_started:
            continue
        if frame_type == _HEADERS:
            _validate_headers_frame(flags, stream_id, payload)
            headers_started = True
            continue
        _validate_pre_headers_frame(frame_type, flags, stream_id, payload)
        if len(pre_headers_frame_types) >= MAX_HTTP2_PRE_HEADER_FRAMES:
            raise ContractError("HTTP/2 pre-HEADERS frame count exceeds limit")
        pre_headers_frame_types.append(frame_type)
        if frame_type == _WINDOW_UPDATE:
            if flags != 0 or length != 4:
                raise ContractError("HTTP/2 WINDOW_UPDATE is invalid")
            raw_increment = int.from_bytes(payload, "big")
            if raw_increment & 0x80000000:
                raise ContractError("HTTP/2 WINDOW_UPDATE reserved bit is set")
            increment = raw_increment & 0x7FFFFFFF
            if increment == 0:
                raise ContractError("HTTP/2 WINDOW_UPDATE is zero")
            if stream_id != 0:
                raise ContractError(
                    "HTTP/2 client sent idle stream WINDOW_UPDATE before HEADERS"
                )
            if stream_id == 0:
                if len(connection_window_updates) >= MAX_HTTP2_WINDOW_UPDATES:
                    raise ContractError(
                        "HTTP/2 connection WINDOW_UPDATE count exceeds limit"
                    )
                connection_window_updates.append(increment)

    if first_frame:
        raise ContractError("HTTP/2 client flight has no first frame")
    record: dict[str, Any] = {
        "schema": HTTP2_FINGERPRINT_SCHEMA,
        "settings": settings,
        "connection_window_updates": connection_window_updates,
        "pre_headers_frame_types": pre_headers_frame_types,
        "headers_started": headers_started,
    }
    record["digest_sha256"] = http2_fingerprint_digest(record)
    return validate_http2_fingerprint(record)


def _apply_capture_deadline(
    connection: Any,
    deadline: float | None,
    clock: Callable[[], float],
) -> None:
    if deadline is None:
        return
    if not is_finite_number(deadline) or not callable(clock):
        raise ContractError("HTTP/2 capture deadline is invalid")
    try:
        now = clock()
    except (OSError, RuntimeError, TypeError, ValueError):
        raise ContractError("HTTP/2 capture clock failed") from None
    if not is_finite_number(now):
        raise ContractError("HTTP/2 capture clock is invalid")
    remaining = float(deadline) - float(now)
    if remaining <= 0:
        raise ContractError("HTTP/2 capture deadline expired")
    try:
        connection.settimeout(remaining)
    except (OSError, RuntimeError, TypeError, ValueError):
        raise ContractError("HTTP/2 transport timeout update failed") from None


def _read_http2_client_flight_bytes(
    connection: Any,
    *,
    complete_header_block: bool,
    deadline: float | None = None,
    clock: Callable[[], float] = time.monotonic,
) -> bytes:
    """Read a bounded client flight, optionally through END_HEADERS."""

    def receive_exact(size: int) -> bytes:
        body = bytearray()
        while len(body) < size:
            requested = min(4096, size - len(body))
            _apply_capture_deadline(connection, deadline, clock)
            try:
                chunk = connection.recv(requested)
            except (OSError, RuntimeError, TypeError, ValueError):
                raise ContractError("HTTP/2 transport read failed") from None
            if type(chunk) is not bytes or len(chunk) > requested:
                raise ContractError("HTTP/2 transport returned an invalid byte chunk")
            _apply_capture_deadline(connection, deadline, clock)
            if not chunk:
                raise ContractError("HTTP/2 peer closed before its flight was complete")
            body.extend(chunk)
        return bytes(body)

    raw = bytearray(receive_exact(len(HTTP2_CONNECTION_PREFACE)))
    if bytes(raw) != HTTP2_CONNECTION_PREFACE:
        raise ContractError("HTTP/2 connection preface is invalid")

    def receive_frame() -> tuple[bytes, int, int, int]:
        header = receive_exact(9)
        length = int.from_bytes(header[:3], "big")
        if length > MAX_HTTP2_FRAME_PAYLOAD_BYTES:
            raise ContractError("HTTP/2 frame exceeds initial frame limit")
        raw_stream_id = int.from_bytes(header[5:9], "big")
        if raw_stream_id & 0x80000000:
            raise ContractError("HTTP/2 reserved stream bit is set")
        return (
            header + receive_exact(length),
            header[3],
            header[4],
            raw_stream_id,
        )

    first, first_type, _first_flags, _first_stream = receive_frame()
    raw.extend(first)
    if first_type != _SETTINGS:
        raise ContractError("HTTP/2 first frame is not SETTINGS")
    parse_http2_client_preface(bytes(raw))
    _apply_capture_deadline(connection, deadline, clock)
    try:
        sent = connection.sendall(_EMPTY_SERVER_SETTINGS_AND_ACK)
    except (OSError, RuntimeError, TypeError, ValueError):
        raise ContractError("HTTP/2 server SETTINGS write failed") from None
    if sent is not None:
        raise ContractError("HTTP/2 server SETTINGS write status is invalid")

    header_stream: int | None = None
    for _ in range(MAX_HTTP2_PRE_HEADER_FRAMES - 1):
        frame, frame_type, flags, stream_id = receive_frame()
        raw.extend(frame)
        if len(raw) > MAX_HTTP2_CAPTURE_BYTES:
            raise ContractError("HTTP/2 client flight exceeds capture limit")
        if header_stream is not None:
            if (
                frame_type != _CONTINUATION
                or stream_id != header_stream
                or flags & ~0x04
            ):
                raise ContractError("HTTP/2 header continuation is invalid")
            if flags & 0x04:
                return bytes(raw)
            continue
        if frame_type == _HEADERS:
            if not complete_header_block or flags & 0x04:
                return bytes(raw)
            header_stream = stream_id
    if header_stream is not None:
        raise ContractError("HTTP/2 header block did not reach END_HEADERS")
    raise ContractError("HTTP/2 client flight did not reach HEADERS")


def _read_http2_client_flight(
    connection: Any,
    *,
    deadline: float | None = None,
    clock: Callable[[], float] = time.monotonic,
) -> dict[str, Any]:
    """Read through the first HEADERS frame, retaining no header values."""
    raw = _read_http2_client_flight_bytes(
        connection,
        complete_header_block=False,
        deadline=deadline,
        clock=clock,
    )
    return parse_http2_client_preface(raw)


def _read_http2_client_evidence(
    connection: Any,
    *,
    deadline: float | None = None,
    clock: Callable[[], float] = time.monotonic,
) -> dict[str, Any]:
    """Read one complete request block and return only value-free evidence."""
    from .http2_headers import (
        HTTP2_CAPTURE_EVIDENCE_SCHEMA,
        http2_capture_evidence_digest,
        parse_http2_header_order,
        validate_http2_capture_evidence,
    )

    raw = _read_http2_client_flight_bytes(
        connection,
        complete_header_block=True,
        deadline=deadline,
        clock=clock,
    )
    evidence = {
        "schema": HTTP2_CAPTURE_EVIDENCE_SCHEMA,
        "fingerprint": parse_http2_client_preface(raw),
        "header_order": parse_http2_header_order(raw),
        "same_connection": True,
        "non_claim": (
            "One local negotiated HTTP/2 connection through first complete request "
            "headers; decoded values are discarded and no HTTP/3 or edge acceptance "
            "is proven"
        ),
    }
    evidence["digest_sha256"] = http2_capture_evidence_digest(evidence)
    return validate_http2_capture_evidence(evidence)


def _capture_http2_measurement(
    executable: Path,
    certificate: Path,
    private_key: Path,
    *,
    timeout_seconds: float = 20.0,
    complete_header_order: bool,
) -> dict[str, Any]:
    """Run one negotiated loopback H2 lifecycle with a selected projection."""
    if not all(
        isinstance(value, Path) for value in (executable, certificate, private_key)
    ):
        raise ContractError("HTTP/2 executable and TLS inputs must be Paths")
    if not is_finite_number(timeout_seconds) or not 0 < timeout_seconds <= 120:
        raise ContractError("HTTP/2 capture timeout is invalid")
    if type(complete_header_order) is not bool:
        raise ContractError("HTTP/2 capture projection is invalid")
    executable = executable.absolute()
    certificate = certificate.absolute()
    private_key = private_key.absolute()
    executable_before = _hash_regular_file(
        executable,
        label="HTTP/2 browser executable",
    )
    certificate_before = _hash_regular_file(
        certificate,
        label="HTTP/2 TLS certificate",
        maximum=MAX_HTTP2_CERTIFICATE_BYTES,
    )
    private_key_before = _hash_regular_file(
        private_key,
        label="HTTP/2 TLS private key",
        maximum=MAX_HTTP2_PRIVATE_KEY_BYTES,
    )
    if not all(item[1] > 0 for item in (executable_before, certificate_before, private_key_before)):
        raise ContractError("HTTP/2 executable and TLS inputs must be nonempty")
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.set_alpn_protocols(["h2"])
        context.load_cert_chain(str(certificate), str(private_key))
    except (OSError, RuntimeError, TypeError, ValueError, ssl.SSLError) as exc:
        raise ContractError(
            f"HTTP/2 TLS server setup failed ({type(exc).__name__})"
        ) from None
    try:
        capture_nonce = secrets.token_hex(16)
    except (OSError, RuntimeError):
        raise ContractError("HTTP/2 capture nonce generation failed") from None
    if re.fullmatch(r"[0-9a-f]{32}", capture_nonce) is None:
        raise ContractError("HTTP/2 capture nonce is invalid")
    capture_hostname = f"bc-h2-{capture_nonce}.invalid"
    observed_server_names: list[Any] = []

    def observe_server_name(_socket: Any, server_name: Any, _context: Any) -> None:
        observed_server_names.append(server_name)

    try:
        context.set_servername_callback(observe_server_name)
    except (OSError, RuntimeError, TypeError, ValueError, ssl.SSLError) as exc:
        raise ContractError(
            f"HTTP/2 TLS server-name setup failed ({type(exc).__name__})"
        ) from None
    deadline = time.monotonic() + float(timeout_seconds)

    try:
        with guarded_temporary_directory(
            tempfile.TemporaryDirectory(prefix="bc-h2-"),
            label="HTTP/2 capture profile directory",
        ) as profile:
            listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            process: subprocess.Popen[Any] | None = None
            raw_connection: Any = None
            tls_connection: Any = None
            record: dict[str, Any] | None = None
            try:
                listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                listener.bind(("127.0.0.1", 0))
                listener.listen(1)
                _apply_capture_deadline(listener, deadline, time.monotonic)
                address = listener.getsockname()
                if (
                    not isinstance(address, tuple)
                    or len(address) != 2
                    or address[0] != "127.0.0.1"
                    or isinstance(address[1], bool)
                    or not isinstance(address[1], int)
                    or not 1 <= address[1] <= 65535
                ):
                    raise ContractError("HTTP/2 listener address is invalid")
                process = subprocess.Popen(
                    [
                        str(executable),
                        "--headless=new",
                        "--no-sandbox",
                        "--disable-gpu",
                        "--disable-background-networking",
                        "--disable-component-update",
                        "--disable-default-apps",
                        "--disable-sync",
                        "--metrics-recording-only",
                        "--no-first-run",
                        "--ignore-certificate-errors",
                        f"--user-data-dir={profile}",
                        "--host-resolver-rules="
                        f"MAP {capture_hostname} 127.0.0.1, MAP * ^NOTFOUND",
                        f"https://{capture_hostname}:{address[1]}/",
                    ],
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                raw_connection, _peer = listener.accept()
                _apply_capture_deadline(raw_connection, deadline, time.monotonic)
                tls_connection = context.wrap_socket(raw_connection, server_side=True)
                raw_connection = None
                if observed_server_names != [capture_hostname]:
                    raise ContractError(
                        "HTTP/2 TLS server name does not match capture target"
                    )
                if tls_connection.selected_alpn_protocol() != "h2":
                    raise ContractError("HTTP/2 ALPN negotiation failed")
                reader = (
                    _read_http2_client_evidence
                    if complete_header_order
                    else _read_http2_client_flight
                )
                record = reader(
                    tls_connection,
                    deadline=deadline,
                    clock=time.monotonic,
                )
            except ContractError:
                raise
            except (OSError, RuntimeError, TypeError, ValueError, ssl.SSLError) as exc:
                raise ContractError(
                    f"HTTP/2 capture failed ({type(exc).__name__})"
                ) from None
            finally:
                cleanup_failures: list[str] = []
                for name, connection in (
                    ("tls-close", tls_connection),
                    ("connection-close", raw_connection),
                ):
                    if connection is not None:
                        try:
                            connection.close()
                        except (OSError, RuntimeError):
                            cleanup_failures.append(name)
                try:
                    listener.close()
                except (OSError, RuntimeError):
                    cleanup_failures.append("listener-close")
                if process is not None:
                    try:
                        _stop_process(process)
                    except ContractError:
                        cleanup_failures.append("browser-stop")
                if cleanup_failures:
                    cleanup_error = ContractError(
                        "HTTP/2 capture cleanup failed "
                        f"({','.join(dict.fromkeys(cleanup_failures))})"
                    )
                    active_error = sys.exc_info()[1]
                    if active_error is not None:
                        raise cleanup_error from active_error
                    raise cleanup_error from None
    except ContractError:
        raise
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        raise ContractError(
            f"HTTP/2 capture lifecycle failed ({type(exc).__name__})"
        ) from None

    if record is None:
        raise ContractError("HTTP/2 capture returned no fingerprint")
    for path, expected, label, maximum in (
        (executable, executable_before, "HTTP/2 browser executable", None),
        (
            certificate,
            certificate_before,
            "HTTP/2 TLS certificate",
            MAX_HTTP2_CERTIFICATE_BYTES,
        ),
        (
            private_key,
            private_key_before,
            "HTTP/2 TLS private key",
            MAX_HTTP2_PRIVATE_KEY_BYTES,
        ),
    ):
        observed = _hash_regular_file(path, label=label, maximum=maximum)
        if observed != expected:
            raise ContractError(f"{label} changed during capture")
    return record


def capture_http2_fingerprint(
    executable: Path,
    certificate: Path,
    private_key: Path,
    *,
    timeout_seconds: float = 20.0,
) -> dict[str, Any]:
    """Capture one negotiated loopback H2 flight without retaining headers."""
    record = _capture_http2_measurement(
        executable,
        certificate,
        private_key,
        timeout_seconds=timeout_seconds,
        complete_header_order=False,
    )
    return validate_http2_fingerprint(record)


def capture_http2_evidence(
    executable: Path,
    certificate: Path,
    private_key: Path,
    *,
    timeout_seconds: float = 20.0,
) -> dict[str, Any]:
    """Capture same-connection H2 settings, frames, and header-name order."""
    from .http2_headers import validate_http2_capture_evidence

    record = _capture_http2_measurement(
        executable,
        certificate,
        private_key,
        timeout_seconds=timeout_seconds,
        complete_header_order=True,
    )
    return validate_http2_capture_evidence(record)


def capture_attested_http2_fingerprint(
    root: Path,
    executable: Path,
    certificate: Path,
    private_key: Path,
    *,
    timeout_seconds: float = 20.0,
) -> dict[str, Any]:
    if not all(
        isinstance(value, Path)
        for value in (root, executable, certificate, private_key)
    ):
        raise ContractError("attested HTTP/2 inputs must be Paths")
    attestation = load_build_attestation(root, executable)
    record = capture_http2_fingerprint(
        executable,
        certificate,
        private_key,
        timeout_seconds=timeout_seconds,
    )
    if load_build_attestation(root, executable) != attestation:
        raise ContractError("Browser Core build attestation changed during HTTP/2 capture")
    record["core_build"] = {
        "chromium_revision": attestation["chromium_revision"],
        "executable_sha256_16": attestation["executable_sha256"][:16],
        "runtime_bundle_sha256_16": attestation["runtime_bundle_sha256"][:16],
    }
    return validate_http2_fingerprint(record, require_build=True)


def capture_attested_http2_evidence(
    root: Path,
    executable: Path,
    certificate: Path,
    private_key: Path,
    *,
    timeout_seconds: float = 20.0,
) -> dict[str, Any]:
    from .http2_headers import validate_http2_capture_evidence

    if not all(
        isinstance(value, Path)
        for value in (root, executable, certificate, private_key)
    ):
        raise ContractError("attested HTTP/2 evidence inputs must be Paths")
    attestation = load_build_attestation(root, executable)
    evidence = capture_http2_evidence(
        executable,
        certificate,
        private_key,
        timeout_seconds=timeout_seconds,
    )
    if load_build_attestation(root, executable) != attestation:
        raise ContractError("Browser Core build attestation changed during HTTP/2 capture")
    build = {
        "chromium_revision": attestation["chromium_revision"],
        "executable_sha256_16": attestation["executable_sha256"][:16],
        "runtime_bundle_sha256_16": attestation["runtime_bundle_sha256"][:16],
    }
    evidence["fingerprint"]["core_build"] = build.copy()
    evidence["header_order"]["core_build"] = build.copy()
    return validate_http2_capture_evidence(evidence, require_build=True)
