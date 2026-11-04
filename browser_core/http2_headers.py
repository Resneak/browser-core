"""Value-free HTTP/2 request header-name order extracted from bounded HPACK."""

from __future__ import annotations

import hashlib
import json
import logging
import re
import threading
from pathlib import Path
from typing import Any, Iterator

from hpack import Decoder
from hpack.exceptions import HPACKError

from .control_files import (
    decode_strict_json_bytes,
    publish_json_exclusive,
    read_bounded_control_snapshot_result,
    require_bounded_control_snapshot_unchanged,
)
from .contracts import RUN_ID_RE, reject_sensitive_keys
from .profiles import has_windows_device_basename
from .errors import ContractError
from .http2_fingerprint import (
    HTTP2_CONNECTION_PREFACE,
    MAX_HTTP2_CAPTURE_BYTES,
    MAX_HTTP2_FRAME_PAYLOAD_BYTES,
    compare_http2_fingerprints,
    parse_http2_client_preface,
    validate_http2_fingerprint,
)
from .owned_paths import directory_ancestry_binding, prepare_owned_directory_parent


HTTP2_HEADER_ORDER_SCHEMA = "browser-core.http2-header-order/1"
HTTP2_CAPTURE_EVIDENCE_SCHEMA = "browser-core.http2-capture-evidence/1"
HTTP2_HEADER_ORDER_COMPARISON_SCHEMA = (
    "browser-core.http2-header-order-comparison/1"
)
HTTP2_CAPTURE_EVIDENCE_COMPARISON_SCHEMA = (
    "browser-core.http2-capture-evidence-comparison/1"
)
HTTP2_EVIDENCE_BASELINE_SCHEMA = "browser-core.http2-evidence-baseline/1"
MAX_HTTP2_HEADER_BLOCK_BYTES = 64 * 1024
MAX_HTTP2_DECOMPRESSED_HEADER_BYTES = 64 * 1024
MAX_HTTP2_HEADER_NAMES = 256
MAX_HTTP2_HEADER_NAME_BYTES = 256
MAX_HTTP2_EVIDENCE_DOCUMENT_BYTES = 1024 * 1024
_HEADERS = 1
_CONTINUATION = 9
_END_HEADERS = 0x04
_PADDED = 0x08
_PRIORITY = 0x20
_ALLOWED_PSEUDO_HEADERS = {
    ":method",
    ":scheme",
    ":authority",
    ":path",
    ":protocol",
}
_HEADER_TOKEN_RE = re.compile(rb"^[!#$%&'*+\-.^_`|~0-9a-z]+$")
_METHOD_TOKEN_RE = re.compile(rb"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")
_SCHEME_RE = re.compile(rb"^[A-Za-z][A-Za-z0-9+.-]*$")
_CONNECTION_SPECIFIC_NAMES = {
    b"connection",
    b"keep-alive",
    b"proxy-connection",
    b"transfer-encoding",
    b"upgrade",
}
_NON_CLAIM = (
    "First local HTTP/2 request header-name order only; values are discarded "
    "after bounded decode and no HTTP/3 or edge acceptance is proven"
)
_CAPTURE_EVIDENCE_NON_CLAIM = (
    "One local negotiated HTTP/2 connection through first complete request "
    "headers; decoded values are discarded and no HTTP/3 or edge acceptance "
    "is proven"
)
_EVIDENCE_BASELINE_NON_CLAIM = (
    "Operator-approved same-connection local HTTP/2 settings, frame, and "
    "header-name order baseline only; not HTTP/3 or remote edge acceptance"
)


class _CurrentThreadHpackLogFilter(logging.Filter):
    """Block upstream HPACK debug records emitted by this decode call."""

    def __init__(self) -> None:
        super().__init__()
        self._thread_id = threading.get_ident()

    def filter(self, record: logging.LogRecord) -> bool:
        return record.thread != self._thread_id


def _validate_header_names(names: Any) -> tuple[list[str], list[str]]:
    if not isinstance(names, list) or not 1 <= len(names) <= MAX_HTTP2_HEADER_NAMES:
        raise ContractError("HTTP/2 header-order names are invalid")
    validated: list[str] = []
    pseudo_names: set[str] = set()
    pseudo_order: list[str] = []
    regular_started = False
    for name in names:
        if not isinstance(name, str):
            raise ContractError("HTTP/2 header-order name is invalid")
        try:
            raw_name = name.encode("ascii", errors="strict")
        except UnicodeEncodeError:
            raise ContractError("HTTP/2 header-order name is invalid") from None
        if not 1 <= len(raw_name) <= MAX_HTTP2_HEADER_NAME_BYTES or name.lower() != name:
            raise ContractError("HTTP/2 header-order name is invalid")
        if name.startswith(":"):
            if regular_started:
                raise ContractError("HTTP/2 pseudo-header follows a regular header")
            token = raw_name[1:]
            if name not in _ALLOWED_PSEUDO_HEADERS or name in pseudo_names:
                raise ContractError("HTTP/2 pseudo-header is invalid")
            pseudo_names.add(name)
            pseudo_order.append(name)
        else:
            regular_started = True
            token = raw_name
            if raw_name in _CONNECTION_SPECIFIC_NAMES:
                raise ContractError("HTTP/2 connection-specific header is invalid")
        if _HEADER_TOKEN_RE.fullmatch(token) is None:
            raise ContractError("HTTP/2 header-order name is invalid")
        validated.append(name)
    if not {":method", ":authority"} <= pseudo_names:
        raise ContractError("HTTP/2 request pseudo-header set is incomplete")
    return validated, pseudo_order


def _validate_components(
    document: Any,
    *,
    require_build: bool = False,
) -> dict[str, Any]:
    expected = {
        "schema",
        "header_names",
        "pseudo_header_order",
        "non_claim",
    }
    if type(document) is not dict:
        raise ContractError("HTTP/2 header-order fields are invalid")
    allowed = set(expected)
    if "digest_sha256" in document:
        allowed.add("digest_sha256")
    if "core_build" in document:
        allowed.add("core_build")
    if require_build and "core_build" not in document:
        raise ContractError("HTTP/2 header-order build receipt is required")
    if set(document) != allowed:
        raise ContractError("HTTP/2 header-order fields are invalid")
    if document.get("schema") != HTTP2_HEADER_ORDER_SCHEMA:
        raise ContractError("HTTP/2 header-order schema is invalid")
    names, pseudo_order = _validate_header_names(document.get("header_names"))
    if document.get("pseudo_header_order") != pseudo_order:
        raise ContractError("HTTP/2 header-order pseudo-header order is invalid")
    if document.get("non_claim") != _NON_CLAIM:
        raise ContractError("HTTP/2 header-order non-claim is invalid")
    build = document.get("core_build")
    if "core_build" in document and build is None:
        raise ContractError("HTTP/2 header-order build receipt is invalid")
    if build is not None:
        if type(build) is not dict or set(build) != {
            "chromium_revision",
            "executable_sha256_16",
            "runtime_bundle_sha256_16",
        }:
            raise ContractError("HTTP/2 header-order build receipt is invalid")
        if (
            not isinstance(build.get("chromium_revision"), str)
            or re.fullmatch(r"[0-9a-f]{40}", build["chromium_revision"]) is None
        ):
            raise ContractError("HTTP/2 header-order build receipt is invalid")
        for field in ("executable_sha256_16", "runtime_bundle_sha256_16"):
            if (
                not isinstance(build.get(field), str)
                or re.fullmatch(r"[0-9a-f]{16}", build[field]) is None
            ):
                raise ContractError("HTTP/2 header-order build receipt is invalid")
    reject_sensitive_keys(document)
    return document


def http2_header_order_digest(document: Any) -> str:
    document = _validate_components(document)
    try:
        canonical = json.dumps(
            document["header_names"],
            ensure_ascii=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("ascii")
    except (OverflowError, RecursionError, TypeError, ValueError):
        raise ContractError("HTTP/2 header-order cannot be encoded") from None
    return hashlib.sha256(canonical).hexdigest()


def validate_http2_header_order(
    document: Any,
    *,
    require_build: bool = False,
) -> dict[str, Any]:
    document = _validate_components(document, require_build=require_build)
    digest = document.get("digest_sha256")
    if (
        not isinstance(digest, str)
        or re.fullmatch(r"[0-9a-f]{64}", digest) is None
        or digest != http2_header_order_digest(document)
    ):
        raise ContractError("HTTP/2 header-order digest is invalid")
    return document


def load_http2_header_order(path: Path) -> dict[str, Any]:
    if not isinstance(path, Path):
        raise ContractError("HTTP/2 header-order path must be a Path")
    selected = path.absolute()
    snapshot = read_bounded_control_snapshot_result(
        selected,
        maximum=MAX_HTTP2_CAPTURE_BYTES,
        label="HTTP/2 header order",
        require_single_link=True,
    )
    if snapshot.state != "complete" or snapshot.body is None:
        raise ContractError(f"HTTP/2 header order is {snapshot.state}")
    document = decode_strict_json_bytes(snapshot.body, label="HTTP/2 header order")
    validated = validate_http2_header_order(document, require_build=True)
    require_bounded_control_snapshot_unchanged(
        selected,
        snapshot,
        maximum=MAX_HTTP2_CAPTURE_BYTES,
        label="HTTP/2 header order",
        require_single_link=True,
    )
    return validated


def _validate_capture_evidence_components(
    document: Any,
    *,
    require_build: bool = False,
) -> dict[str, Any]:
    core_fields = {
        "schema",
        "fingerprint",
        "header_order",
        "same_connection",
        "non_claim",
    }
    if type(document) is not dict:
        raise ContractError("HTTP/2 capture evidence fields are invalid")
    expected = set(core_fields)
    if "digest_sha256" in document:
        expected.add("digest_sha256")
    if set(document) != expected:
        raise ContractError("HTTP/2 capture evidence fields are invalid")
    if document.get("schema") != HTTP2_CAPTURE_EVIDENCE_SCHEMA:
        raise ContractError("HTTP/2 capture evidence schema is invalid")
    if document.get("same_connection") is not True:
        raise ContractError("HTTP/2 capture evidence connection receipt is invalid")
    if document.get("non_claim") != _CAPTURE_EVIDENCE_NON_CLAIM:
        raise ContractError("HTTP/2 capture evidence non-claim is invalid")
    fingerprint = validate_http2_fingerprint(
        document.get("fingerprint"),
        require_build=require_build,
    )
    header_order = validate_http2_header_order(
        document.get("header_order"),
        require_build=require_build,
    )
    fingerprint_build = fingerprint.get("core_build")
    header_order_build = header_order.get("core_build")
    if (fingerprint_build is None) != (header_order_build is None):
        raise ContractError("HTTP/2 capture evidence build receipts are incomplete")
    if fingerprint_build != header_order_build:
        raise ContractError("HTTP/2 capture evidence does not describe the same build")
    reject_sensitive_keys(document)
    return document


def http2_capture_evidence_digest(document: Any) -> str:
    document = _validate_capture_evidence_components(document)
    payload = {
        "fingerprint_digest_sha256": document["fingerprint"]["digest_sha256"],
        "header_order_digest_sha256": document["header_order"]["digest_sha256"],
        "same_connection": document["same_connection"],
    }
    try:
        canonical = json.dumps(
            payload,
            sort_keys=True,
            ensure_ascii=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("ascii")
    except (OverflowError, RecursionError, TypeError, ValueError):
        raise ContractError("HTTP/2 capture evidence cannot be encoded") from None
    return hashlib.sha256(canonical).hexdigest()


def validate_http2_capture_evidence(
    document: Any,
    *,
    require_build: bool = False,
) -> dict[str, Any]:
    document = _validate_capture_evidence_components(
        document,
        require_build=require_build,
    )
    digest = document.get("digest_sha256")
    if (
        not isinstance(digest, str)
        or re.fullmatch(r"[0-9a-f]{64}", digest) is None
        or digest != http2_capture_evidence_digest(document)
    ):
        raise ContractError("HTTP/2 capture evidence digest is invalid")
    return document


def load_http2_capture_evidence(path: Path) -> dict[str, Any]:
    if not isinstance(path, Path):
        raise ContractError("HTTP/2 capture evidence path must be a Path")
    selected = path.absolute()
    snapshot = read_bounded_control_snapshot_result(
        selected,
        maximum=MAX_HTTP2_CAPTURE_BYTES,
        label="HTTP/2 capture evidence",
        require_single_link=True,
    )
    if snapshot.state != "complete" or snapshot.body is None:
        raise ContractError(f"HTTP/2 capture evidence is {snapshot.state}")
    document = decode_strict_json_bytes(
        snapshot.body,
        label="HTTP/2 capture evidence",
    )
    validated = validate_http2_capture_evidence(document, require_build=True)
    require_bounded_control_snapshot_unchanged(
        selected,
        snapshot,
        maximum=MAX_HTTP2_CAPTURE_BYTES,
        label="HTTP/2 capture evidence",
        require_single_link=True,
    )
    return validated


def _require_http2_evidence_id(value: Any, label: str) -> str:
    if (
        not isinstance(value, str)
        or RUN_ID_RE.fullmatch(value) is None
        or has_windows_device_basename(value)
    ):
        raise ContractError(f"HTTP/2 evidence {label} id is invalid")
    return value


def validate_http2_evidence_baseline(document: Any) -> dict[str, Any]:
    expected = {
        "schema",
        "source_evidence_id",
        "baseline_evidence_id",
        "reviewed_digest_sha256",
        "evidence",
        "non_claim",
    }
    if type(document) is not dict or set(document) != expected:
        raise ContractError("HTTP/2 evidence baseline fields are invalid")
    if document.get("schema") != HTTP2_EVIDENCE_BASELINE_SCHEMA:
        raise ContractError("HTTP/2 evidence baseline schema is invalid")
    source_id = _require_http2_evidence_id(
        document.get("source_evidence_id"),
        "source",
    )
    baseline_id = _require_http2_evidence_id(
        document.get("baseline_evidence_id"),
        "baseline",
    )
    if source_id == baseline_id:
        raise ContractError("HTTP/2 evidence source and baseline ids must differ")
    reviewed_digest = document.get("reviewed_digest_sha256")
    if (
        not isinstance(reviewed_digest, str)
        or re.fullmatch(r"[0-9a-f]{64}", reviewed_digest) is None
    ):
        raise ContractError("HTTP/2 evidence baseline reviewed digest is invalid")
    evidence = validate_http2_capture_evidence(
        document.get("evidence"),
        require_build=True,
    )
    if evidence["digest_sha256"] != reviewed_digest:
        raise ContractError("HTTP/2 evidence baseline reviewed digest does not match")
    if document.get("non_claim") != _EVIDENCE_BASELINE_NON_CLAIM:
        raise ContractError("HTTP/2 evidence baseline non-claim is invalid")
    reject_sensitive_keys(document)
    return document


def load_http2_evidence_baseline(path: Path) -> dict[str, Any]:
    if not isinstance(path, Path):
        raise ContractError("HTTP/2 evidence baseline path must be a Path")
    selected = path.absolute()
    snapshot = read_bounded_control_snapshot_result(
        selected,
        maximum=MAX_HTTP2_EVIDENCE_DOCUMENT_BYTES,
        label="HTTP/2 evidence baseline",
        require_single_link=True,
    )
    if snapshot.state != "complete" or snapshot.body is None:
        raise ContractError(f"HTTP/2 evidence baseline is {snapshot.state}")
    document = decode_strict_json_bytes(
        snapshot.body,
        label="HTTP/2 evidence baseline",
    )
    validated = validate_http2_evidence_baseline(document)
    require_bounded_control_snapshot_unchanged(
        selected,
        snapshot,
        maximum=MAX_HTTP2_EVIDENCE_DOCUMENT_BYTES,
        label="HTTP/2 evidence baseline",
        require_single_link=True,
    )
    return validated


def approve_http2_evidence_baseline(
    workspace: Path,
    *,
    current_id: str,
    baseline_id: str,
    expected_digest: str,
) -> dict[str, Any]:
    if not isinstance(workspace, Path):
        raise ContractError("HTTP/2 evidence baseline workspace must be a Path")
    current_id = _require_http2_evidence_id(current_id, "source")
    baseline_id = _require_http2_evidence_id(baseline_id, "baseline")
    if current_id == baseline_id:
        raise ContractError("HTTP/2 evidence source and baseline ids must differ")
    if (
        not isinstance(expected_digest, str)
        or re.fullmatch(r"[0-9a-f]{64}", expected_digest) is None
    ):
        raise ContractError("HTTP/2 evidence reviewed digest is invalid")
    registry = workspace.absolute() / "http2-evidence"
    registry_ancestry = directory_ancestry_binding(
        registry,
        label="HTTP/2 evidence baseline registry",
    )
    source = registry / f"{current_id}.json"
    destination = registry / f"{baseline_id}.baseline.json"
    if source.is_symlink() or not source.is_file():
        raise ContractError("HTTP/2 evidence baseline source is unknown")
    if destination.exists() or destination.is_symlink():
        raise ContractError("HTTP/2 evidence baseline id already exists")
    evidence = load_http2_capture_evidence(source)
    if evidence["digest_sha256"] != expected_digest:
        raise ContractError("HTTP/2 evidence baseline does not match reviewed digest")
    if (
        directory_ancestry_binding(registry, label="HTTP/2 evidence baseline registry")
        != registry_ancestry
    ):
        raise ContractError("HTTP/2 evidence baseline registry authority changed")
    baseline = {
        "schema": HTTP2_EVIDENCE_BASELINE_SCHEMA,
        "source_evidence_id": current_id,
        "baseline_evidence_id": baseline_id,
        "reviewed_digest_sha256": evidence["digest_sha256"],
        "evidence": evidence,
        "non_claim": _EVIDENCE_BASELINE_NON_CLAIM,
    }
    validate_http2_evidence_baseline(baseline)
    source_before_publication = load_http2_capture_evidence(source)
    registry_before_publication = directory_ancestry_binding(
        registry,
        label="HTTP/2 evidence baseline registry",
    )
    if source_before_publication != evidence or registry_before_publication != registry_ancestry:
        raise ContractError("HTTP/2 evidence baseline source changed before publication")
    publish_json_exclusive(
        destination,
        baseline,
        maximum=MAX_HTTP2_EVIDENCE_DOCUMENT_BYTES,
        label="HTTP/2 evidence baseline",
    )
    published_baseline = load_http2_evidence_baseline(destination)
    source_after_publication = load_http2_capture_evidence(source)
    registry_after_publication = directory_ancestry_binding(
        registry,
        label="HTTP/2 evidence baseline registry",
    )
    if (
        registry_after_publication != registry_ancestry
        or published_baseline != baseline
        or source_after_publication != evidence
    ):
        raise ContractError("HTTP/2 evidence baseline source or publication changed")
    return {
        "schema": "browser-core.http2-evidence-baseline-approval/1",
        "source_evidence_id": current_id,
        "baseline_evidence_id": baseline_id,
        "digest_sha256": evidence["digest_sha256"],
        "core_build": dict(evidence["fingerprint"]["core_build"]),
        "non_claim": _EVIDENCE_BASELINE_NON_CLAIM,
    }


def install_http2_evidence_baseline(
    workspace: Path,
    baseline: Any,
) -> dict[str, Any]:
    if not isinstance(workspace, Path):
        raise ContractError("HTTP/2 evidence baseline workspace must be a Path")
    baseline = validate_http2_evidence_baseline(baseline)
    registry = workspace.absolute() / "http2-evidence"
    prepare_owned_directory_parent(registry, label="HTTP/2 evidence baseline registry")
    registry_ancestry = directory_ancestry_binding(
        registry,
        label="HTTP/2 evidence baseline registry",
    )
    destination = registry / f"{baseline['baseline_evidence_id']}.baseline.json"
    if destination.exists() or destination.is_symlink():
        raise ContractError("HTTP/2 evidence baseline id already exists")
    publish_json_exclusive(
        destination,
        baseline,
        maximum=MAX_HTTP2_EVIDENCE_DOCUMENT_BYTES,
        label="HTTP/2 evidence baseline",
    )
    published_baseline = load_http2_evidence_baseline(destination)
    registry_after_publication = directory_ancestry_binding(
        registry,
        label="HTTP/2 evidence baseline registry",
    )
    if (
        published_baseline != baseline
        or registry_after_publication != registry_ancestry
    ):
        raise ContractError("HTTP/2 evidence baseline changed after publication")
    return baseline


def compare_http2_header_orders(current: Any, baseline: Any) -> dict[str, Any]:
    current = validate_http2_header_order(current, require_build=True)
    baseline = validate_http2_header_order(baseline, require_build=True)
    compared_fields = {"header_names", "pseudo_header_order"}
    changed_fields = sorted(
        field for field in compared_fields if current[field] != baseline[field]
    )
    same_digest = current["digest_sha256"] == baseline["digest_sha256"]
    report = {
        "schema": HTTP2_HEADER_ORDER_COMPARISON_SCHEMA,
        "passed": same_digest and not changed_fields,
        "same_digest": same_digest,
        "changed_fields": changed_fields,
        "current_digest_sha256": current["digest_sha256"],
        "baseline_digest_sha256": baseline["digest_sha256"],
        "current_core_build": dict(current["core_build"]),
        "baseline_core_build": dict(baseline["core_build"]),
        "non_claim": (
            "Local first-request HTTP/2 header-name order equality only; values, "
            "HTTP/3, and remote edge acceptance are not measured"
        ),
    }
    reject_sensitive_keys(report)
    return report


def compare_http2_capture_evidence(current: Any, baseline: Any) -> dict[str, Any]:
    current = validate_http2_capture_evidence(current, require_build=True)
    baseline = validate_http2_capture_evidence(baseline, require_build=True)
    fingerprint_report = compare_http2_fingerprints(
        current["fingerprint"],
        baseline["fingerprint"],
    )
    header_order_report = compare_http2_header_orders(
        current["header_order"],
        baseline["header_order"],
    )
    changed_components = []
    if not fingerprint_report["passed"]:
        changed_components.append("fingerprint")
    if not header_order_report["passed"]:
        changed_components.append("header_order")
    same_digest = current["digest_sha256"] == baseline["digest_sha256"]
    report = {
        "schema": HTTP2_CAPTURE_EVIDENCE_COMPARISON_SCHEMA,
        "passed": same_digest and not changed_components,
        "same_digest": same_digest,
        "changed_components": changed_components,
        "current_digest_sha256": current["digest_sha256"],
        "baseline_digest_sha256": baseline["digest_sha256"],
        "fingerprint": fingerprint_report,
        "header_order": header_order_report,
        "non_claim": (
            "Same-connection local HTTP/2 settings, frame, and header-name order "
            "equality only; not HTTP/3 or remote edge acceptance"
        ),
    }
    reject_sensitive_keys(report)
    return report


def _frames(raw: bytes) -> Iterator[tuple[int, int, int, bytes]]:
    cursor = len(HTTP2_CONNECTION_PREFACE)
    while cursor < len(raw):
        if len(raw) - cursor < 9:
            raise ContractError("HTTP/2 header-order frame header is truncated")
        length = int.from_bytes(raw[cursor : cursor + 3], "big")
        frame_type = raw[cursor + 3]
        flags = raw[cursor + 4]
        raw_stream_id = int.from_bytes(raw[cursor + 5 : cursor + 9], "big")
        if raw_stream_id & 0x80000000:
            raise ContractError("HTTP/2 header-order reserved stream bit is set")
        stream_id = raw_stream_id & 0x7FFFFFFF
        cursor += 9
        if length > MAX_HTTP2_FRAME_PAYLOAD_BYTES:
            raise ContractError("HTTP/2 header-order frame exceeds limit")
        if cursor + length > len(raw):
            raise ContractError("HTTP/2 header-order frame payload is truncated")
        payload = raw[cursor : cursor + length]
        cursor += length
        yield frame_type, flags, stream_id, payload


def _headers_fragment(flags: int, stream_id: int, payload: bytes) -> bytes:
    cursor = 0
    padding = 0
    if flags & _PADDED:
        if not payload:
            raise ContractError("HTTP/2 header-order padding is invalid")
        padding = payload[0]
        cursor = 1
    if flags & _PRIORITY:
        if len(payload) - cursor - padding < 5:
            raise ContractError("HTTP/2 header-order priority is invalid")
        dependency = int.from_bytes(payload[cursor : cursor + 4], "big")
        if dependency & 0x7FFFFFFF == stream_id:
            raise ContractError("HTTP/2 header-order stream depends on itself")
        cursor += 5
    end = len(payload) - padding
    if end < cursor:
        raise ContractError("HTTP/2 header-order padding is invalid")
    return payload[cursor:end]


def _first_header_block(raw: bytes) -> bytes:
    expected_stream: int | None = None
    fragments = bytearray()
    for frame_type, flags, stream_id, payload in _frames(raw):
        if expected_stream is None:
            if frame_type != _HEADERS:
                continue
            expected_stream = stream_id
            fragments.extend(_headers_fragment(flags, stream_id, payload))
            if len(fragments) > MAX_HTTP2_HEADER_BLOCK_BYTES:
                raise ContractError("HTTP/2 header block exceeds limit")
            if flags & _END_HEADERS:
                return bytes(fragments)
            continue
        if frame_type != _CONTINUATION:
            raise ContractError("HTTP/2 header block has an interleaved frame")
        if stream_id != expected_stream or flags & ~_END_HEADERS:
            raise ContractError("HTTP/2 CONTINUATION frame is invalid")
        fragments.extend(payload)
        if len(fragments) > MAX_HTTP2_HEADER_BLOCK_BYTES:
            raise ContractError("HTTP/2 header block exceeds limit")
        if flags & _END_HEADERS:
            return bytes(fragments)
    if expected_stream is None:
        raise ContractError("HTTP/2 header block is missing")
    raise ContractError("HTTP/2 header block is incomplete")


def _decode_header_names(block: bytes) -> list[str]:
    decoder = Decoder(max_header_list_size=MAX_HTTP2_DECOMPRESSED_HEADER_BYTES)
    decoder.max_allowed_table_size = 4096
    hpack_loggers = tuple(
        logging.getLogger(name) for name in ("hpack.hpack", "hpack.table")
    )
    value_filter = _CurrentThreadHpackLogFilter()
    for logger in hpack_loggers:
        logger.addFilter(value_filter)
    try:
        try:
            decoded = decoder.decode(block, raw=True)
        except (HPACKError, IndexError, OverflowError, TypeError, ValueError):
            raise ContractError("HTTP/2 HPACK header block is invalid") from None
    finally:
        for logger in hpack_loggers:
            logger.removeFilter(value_filter)
    if not isinstance(decoded, list) or not 1 <= len(decoded) <= MAX_HTTP2_HEADER_NAMES:
        raise ContractError("HTTP/2 decoded header count is invalid")

    names: list[str] = []
    pseudo_names: set[str] = set()
    pseudo_values: dict[str, bytes] = {}
    regular_started = False
    for header in decoded:
        if not isinstance(header, tuple) or len(header) != 2:
            raise ContractError("HTTP/2 decoded header is invalid")
        raw_name, raw_value = header
        if (
            not isinstance(raw_name, bytes)
            or not 1 <= len(raw_name) <= MAX_HTTP2_HEADER_NAME_BYTES
            or raw_name.lower() != raw_name
        ):
            raise ContractError("HTTP/2 header name must be bounded lowercase ASCII")
        if (
            not isinstance(raw_value, bytes)
            or b"\x00" in raw_value
            or b"\r" in raw_value
            or b"\n" in raw_value
            or (raw_value and raw_value[:1] in {b" ", b"\t"})
            or (raw_value and raw_value[-1:] in {b" ", b"\t"})
        ):
            raise ContractError("HTTP/2 field value is invalid")
        if raw_name.startswith(b":"):
            if regular_started:
                raise ContractError("HTTP/2 pseudo-header follows a regular header")
            token = raw_name[1:]
        else:
            regular_started = True
            token = raw_name
        if _HEADER_TOKEN_RE.fullmatch(token) is None:
            raise ContractError("HTTP/2 header name is invalid")
        name = raw_name.decode("ascii")
        if name.startswith(":"):
            if name not in _ALLOWED_PSEUDO_HEADERS or name in pseudo_names:
                raise ContractError("HTTP/2 pseudo-header is invalid")
            pseudo_names.add(name)
            pseudo_values[name] = raw_value
        elif raw_name in _CONNECTION_SPECIFIC_NAMES:
            raise ContractError("HTTP/2 connection-specific header is invalid")
        elif raw_name == b"te" and raw_value.lower() != b"trailers":
            raise ContractError("HTTP/2 TE field value is invalid")
        names.append(name)
    if not {":method", ":authority"} <= pseudo_names:
        raise ContractError("HTTP/2 request pseudo-header set is incomplete")
    method = pseudo_values[":method"]
    authority = pseudo_values[":authority"]
    if _METHOD_TOKEN_RE.fullmatch(method) is None or not authority:
        raise ContractError("HTTP/2 request pseudo-header value is invalid")
    has_protocol = ":protocol" in pseudo_names
    if has_protocol:
        if method != b"CONNECT":
            raise ContractError("HTTP/2 extended CONNECT method is invalid")
        if not {":scheme", ":path"} <= pseudo_names:
            raise ContractError("HTTP/2 extended CONNECT pseudo-header set is incomplete")
        if _HEADER_TOKEN_RE.fullmatch(pseudo_values[":protocol"]) is None:
            raise ContractError("HTTP/2 extended CONNECT protocol is invalid")
    elif method == b"CONNECT":
        if pseudo_names & {":scheme", ":path"}:
            raise ContractError("HTTP/2 CONNECT pseudo-header set is invalid")
    elif not {":scheme", ":path"} <= pseudo_names:
        raise ContractError("HTTP/2 request pseudo-header set is incomplete")
    if ":scheme" in pseudo_names and _SCHEME_RE.fullmatch(pseudo_values[":scheme"]) is None:
        raise ContractError("HTTP/2 request scheme is invalid")
    if ":path" in pseudo_names and not pseudo_values[":path"]:
        raise ContractError("HTTP/2 request path is invalid")
    return names


def parse_http2_header_order(raw: bytes) -> dict[str, Any]:
    """Return ordered header names while retaining no decoded values."""
    if type(raw) is not bytes:
        raise ContractError("HTTP/2 header-order input must be bytes")
    if len(raw) > MAX_HTTP2_CAPTURE_BYTES:
        raise ContractError("HTTP/2 header-order input exceeds capture limit")
    parse_http2_client_preface(raw)
    names = _decode_header_names(_first_header_block(raw))
    pseudo = [name for name in names if name.startswith(":")]
    record = {
        "schema": HTTP2_HEADER_ORDER_SCHEMA,
        "header_names": names,
        "pseudo_header_order": pseudo,
        "non_claim": _NON_CLAIM,
    }
    record["digest_sha256"] = http2_header_order_digest(record)
    return validate_http2_header_order(record)
