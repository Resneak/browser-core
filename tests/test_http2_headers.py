from __future__ import annotations

import io
import json
import logging
import os
import struct
import subprocess
from pathlib import Path

import pytest
from hpack import Encoder

import browser_core.http2_headers as headers_module
from browser_core.contracts import ContractError
from browser_core.http2_fingerprint import (
    HTTP2_CONNECTION_PREFACE,
    _read_http2_client_evidence,
    parse_http2_client_preface,
)
from browser_core.http2_headers import (
    approve_http2_evidence_baseline,
    compare_http2_capture_evidence,
    compare_http2_header_orders,
    http2_capture_evidence_digest,
    http2_header_order_digest,
    install_http2_evidence_baseline,
    load_http2_capture_evidence,
    load_http2_evidence_baseline,
    load_http2_header_order,
    parse_http2_header_order,
    validate_http2_capture_evidence,
    validate_http2_evidence_baseline,
    validate_http2_header_order,
)
from browser_core.worker import _http2_evidence_baseline_path, _http2_evidence_path


def _frame(frame_type: int, flags: int, stream_id: int, payload: bytes) -> bytes:
    return (
        len(payload).to_bytes(3, "big")
        + bytes((frame_type, flags))
        + stream_id.to_bytes(4, "big")
        + payload
    )


def _block(headers: list[tuple[bytes, bytes]]) -> bytes:
    return Encoder().encode(headers, huffman=True)


def _flight(block: bytes, *, flags: int = 4, stream_id: int = 1) -> bytes:
    return HTTP2_CONNECTION_PREFACE + _frame(4, 0, 0, b"") + _frame(
        1, flags, stream_id, block
    )


def _headers(value: bytes = b"private-a") -> list[tuple[bytes, bytes]]:
    return [
        (b":method", b"GET"),
        (b":authority", b"bc.invalid"),
        (b":scheme", b"https"),
        (b":path", b"/private-path"),
        (b"user-agent", value),
        (b"accept", b"*/*"),
    ]


def test_http2_header_order_retains_names_and_discards_values() -> None:
    report = parse_http2_header_order(_flight(_block(_headers())))

    assert report == {
        "schema": "browser-core.http2-header-order/1",
        "header_names": [
            ":method",
            ":authority",
            ":scheme",
            ":path",
            "user-agent",
            "accept",
        ],
        "pseudo_header_order": [":method", ":authority", ":scheme", ":path"],
        "digest_sha256": report["digest_sha256"],
        "non_claim": (
            "First local HTTP/2 request header-name order only; values are "
            "discarded after bounded decode and no HTTP/3 or edge acceptance is proven"
        ),
    }
    assert len(report["digest_sha256"]) == 64
    assert "private" not in str(report)


@pytest.mark.parametrize(
    "name",
    ["connection", "keep-alive", "proxy-connection", "transfer-encoding", "upgrade"],
)
def test_saved_http2_header_order_rejects_connection_specific_names(
    name: str,
) -> None:
    report = parse_http2_header_order(_flight(_block(_headers())))
    report["header_names"].append(name)

    with pytest.raises(ContractError, match="connection-specific"):
        http2_header_order_digest(report)


def test_http2_header_order_suppresses_upstream_hpack_value_logging() -> None:
    headers = _headers(b"private-debug-value") + [
        (f"x-private-{index}".encode("ascii"), b"v" * 1200)
        for index in range(5)
    ]
    raw = _flight(_block(headers))
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    loggers = [logging.getLogger(name) for name in ("hpack.hpack", "hpack.table")]
    previous_levels = [logger.level for logger in loggers]
    for logger in loggers:
        logger.addHandler(handler)
        logger.setLevel(logging.DEBUG)
    try:
        report = parse_http2_header_order(raw)
    finally:
        for logger, previous_level in zip(loggers, previous_levels):
            logger.removeHandler(handler)
            logger.setLevel(previous_level)

    assert report["header_names"][-1] == "x-private-4"
    assert "private-debug-value" not in stream.getvalue()
    assert stream.getvalue() == ""


def test_http2_header_order_digest_ignores_values_but_keeps_name_order() -> None:
    first = parse_http2_header_order(_flight(_block(_headers(b"private-a"))))
    second = parse_http2_header_order(_flight(_block(_headers(b"private-b"))))
    assert first == second

    reordered = _headers(b"private-a")
    reordered[-2:] = reversed(reordered[-2:])
    changed = parse_http2_header_order(_flight(_block(reordered)))
    assert changed["digest_sha256"] != first["digest_sha256"]
    assert changed["header_names"][-2:] == ["accept", "user-agent"]


def test_http2_header_order_reassembles_continuation_frames() -> None:
    block = _block(_headers())
    split = len(block) // 2
    raw = b"".join(
        (
            HTTP2_CONNECTION_PREFACE,
            _frame(4, 0, 0, b""),
            _frame(1, 0, 1, block[:split]),
            _frame(9, 4, 1, block[split:]),
        )
    )

    assert parse_http2_header_order(raw)["header_names"] == [
        name.decode("ascii") for name, _value in _headers()
    ]


def test_http2_header_order_removes_padding_and_priority_fields() -> None:
    block = _block(_headers())
    payload = b"\x02" + struct.pack(">IB", 3, 10) + block + b"\x00\x00"
    report = parse_http2_header_order(_flight(payload, flags=0x2C, stream_id=1))
    assert report["header_names"][0] == ":method"
    assert "private" not in str(report)


@pytest.mark.parametrize(
    ("raw", "message"),
    [
        (
            HTTP2_CONNECTION_PREFACE
            + _frame(4, 0, 0, b"")
            + _frame(1, 0, 1, b"x")
            + _frame(9, 4, 3, b"y"),
            "CONTINUATION",
        ),
        (
            HTTP2_CONNECTION_PREFACE
            + _frame(4, 0, 0, b"")
            + _frame(1, 0, 1, b"x"),
            "incomplete",
        ),
        (
            HTTP2_CONNECTION_PREFACE
            + _frame(4, 0, 0, b"")
            + _frame(1, 0, 1, b"x")
            + _frame(6, 0, 0, b"12345678"),
            "interleaved",
        ),
        (_flight(b"\xff"), "HPACK"),
        (_flight(_block([(b"accept", b"x"), (b":path", b"/")])), "pseudo-header"),
        (_flight(_block([(b":unknown", b"x")])), "pseudo-header"),
        (_flight(_block([(b"X-Upper", b"x")])), "lowercase"),
    ],
)
def test_http2_header_order_rejects_ambiguous_or_invalid_blocks(
    raw: bytes,
    message: str,
) -> None:
    with pytest.raises(ContractError, match=message):
        parse_http2_header_order(raw)


@pytest.mark.parametrize(
    ("headers", "message"),
    [
        (
            [(b":method", b"GET"), (b":authority", b"bc.invalid")],
            "pseudo-header set",
        ),
        (
            [
                (b":method", b"CONNECT"),
                (b":authority", b"bc.invalid"),
                (b":scheme", b"https"),
                (b":path", b"/"),
            ],
            "CONNECT",
        ),
        (
            [
                (b":method", b"GET"),
                (b":authority", b"bc.invalid"),
                (b":scheme", b"https"),
                (b":path", b"/"),
                (b":protocol", b"websocket"),
            ],
            "extended CONNECT",
        ),
        (_headers() + [(b"connection", b"close")], "connection-specific"),
        (_headers() + [(b"te", b"gzip")], "TE"),
        (_headers() + [(b"x-test", b"bad\r\nvalue")], "field value"),
    ],
)
def test_http2_header_order_rejects_invalid_request_semantics(
    headers: list[tuple[bytes, bytes]],
    message: str,
) -> None:
    with pytest.raises(ContractError, match=message):
        parse_http2_header_order(_flight(_block(headers)))


@pytest.mark.parametrize(
    "headers",
    [
        [(b":method", b"CONNECT"), (b":authority", b"bc.invalid")],
        [
            (b":method", b"CONNECT"),
            (b":authority", b"bc.invalid"),
            (b":scheme", b"https"),
            (b":path", b"/chat"),
            (b":protocol", b"websocket"),
            (b"te", b"trailers"),
        ],
    ],
)
def test_http2_header_order_accepts_connect_forms(
    headers: list[tuple[bytes, bytes]],
) -> None:
    assert parse_http2_header_order(_flight(_block(headers)))["header_names"] == [
        name.decode("ascii") for name, _value in headers
    ]


def test_http2_header_order_accepts_case_insensitive_scheme_and_te_tokens() -> None:
    headers = [
        (b":method", b"GET"),
        (b":authority", b"bc.invalid"),
        (b":scheme", b"HTTPS"),
        (b":path", b"/"),
        (b"te", b"Trailers"),
    ]

    assert parse_http2_header_order(_flight(_block(headers)))["header_names"] == [
        name.decode("ascii") for name, _value in headers
    ]


def _attested_report() -> dict:
    report = parse_http2_header_order(_flight(_block(_headers())))
    report["core_build"] = {
        "chromium_revision": "1" * 40,
        "executable_sha256_16": "2" * 16,
        "runtime_bundle_sha256_16": "3" * 16,
    }
    return report


def test_http2_header_order_validator_rederives_all_semantics() -> None:
    report = _attested_report()
    assert validate_http2_header_order(report, require_build=True) == report
    assert http2_header_order_digest(report) == report["digest_sha256"]


    cases = []
    for update in (
        {"unexpected": True},
        {"pseudo_header_order": [":authority", ":method", ":scheme", ":path"]},
        {"digest_sha256": "0" * 64},
        {"header_names": [":method", ":authority", "X-Upper"]},
        {"core_build": {"chromium_revision": "not-a-revision"}},
    ):
        candidate = {**report, **update}
        cases.append(candidate)

    for candidate in cases:
        with pytest.raises(ContractError):
            validate_http2_header_order(candidate, require_build=True)


def test_http2_header_order_requires_non_null_build_receipt() -> None:
    report = _attested_report()
    report["core_build"] = None

    with pytest.raises(ContractError, match="build receipt"):
        validate_http2_header_order(report, require_build=True)


def test_http2_header_order_loader_requires_attested_strict_document(tmp_path) -> None:
    path = tmp_path / "header-order.json"
    path.write_text(__import__("json").dumps(_attested_report()), encoding="utf-8")
    assert load_http2_header_order(path) == _attested_report()

    raw = parse_http2_header_order(_flight(_block(_headers())))
    path.write_text(__import__("json").dumps(raw), encoding="utf-8")
    with pytest.raises(ContractError, match="build"):
        load_http2_header_order(path)

    path.write_bytes(b'{"schema":"x","schema":"y"}')
    with pytest.raises(ContractError, match="duplicate"):
        load_http2_header_order(path)


def _capture_evidence() -> dict:
    raw = _flight(_block(_headers()))
    fingerprint = parse_http2_client_preface(raw)
    header_order = parse_http2_header_order(raw)
    build = {
        "chromium_revision": "1" * 40,
        "executable_sha256_16": "2" * 16,
        "runtime_bundle_sha256_16": "3" * 16,
    }
    fingerprint["core_build"] = build
    header_order["core_build"] = build.copy()
    evidence = {
        "schema": "browser-core.http2-capture-evidence/1",
        "fingerprint": fingerprint,
        "header_order": header_order,
        "same_connection": True,
        "non_claim": (
            "One local negotiated HTTP/2 connection through first complete request "
            "headers; decoded values are discarded and no HTTP/3 or edge acceptance "
            "is proven"
        ),
    }
    evidence["digest_sha256"] = http2_capture_evidence_digest(evidence)
    return evidence


def test_http2_evidence_baseline_rejects_device_id_before_registry_creation(
    tmp_path: Path,
) -> None:
    evidence = _capture_evidence()
    baseline = {
        "schema": headers_module.HTTP2_EVIDENCE_BASELINE_SCHEMA,
        "source_evidence_id": "candidate",
        "baseline_evidence_id": "CON",
        "reviewed_digest_sha256": evidence["digest_sha256"],
        "evidence": evidence,
        "non_claim": headers_module._EVIDENCE_BASELINE_NON_CLAIM,
    }
    with pytest.raises(ContractError):
        install_http2_evidence_baseline(tmp_path, baseline)
    assert not (tmp_path / "http2-evidence").exists()


def test_http2_capture_evidence_requires_same_attested_build() -> None:
    evidence = _capture_evidence()
    assert validate_http2_capture_evidence(evidence, require_build=True) == evidence
    assert http2_capture_evidence_digest(evidence) == evidence["digest_sha256"]

    mismatched = __import__("copy").deepcopy(evidence)
    mismatched["header_order"]["core_build"]["chromium_revision"] = "4" * 40
    with pytest.raises(ContractError, match="same build"):
        validate_http2_capture_evidence(mismatched, require_build=True)

    tampered = __import__("copy").deepcopy(evidence)
    tampered["digest_sha256"] = "0" * 64
    with pytest.raises(ContractError, match="digest"):
        validate_http2_capture_evidence(tampered, require_build=True)


def test_http2_capture_evidence_loader_is_bounded_strict_and_attested(tmp_path) -> None:
    path = tmp_path / "http2-evidence.json"
    path.write_text(__import__("json").dumps(_capture_evidence()), encoding="utf-8")
    assert load_http2_capture_evidence(path) == _capture_evidence()

    path.write_bytes(b'{"schema":"x","schema":"y"}')
    with pytest.raises(ContractError, match="duplicate"):
        load_http2_capture_evidence(path)

    path.write_bytes(b" " * (256 * 1024 + 1))
    with pytest.raises(ContractError, match="exceeds"):
        load_http2_capture_evidence(path)


@pytest.mark.parametrize("kind", ["header-order", "evidence", "baseline"])
def test_http2_header_loader_rechecks_single_link_after_path_check(
    tmp_path: Path, kind: str,
) -> None:
    workspace = tmp_path / "workspace"
    registry = workspace / "http2-evidence"
    registry.mkdir(parents=True)
    evidence = _capture_evidence()
    if kind == "header-order":
        document = _attested_report()
        source = registry / "header-order.json"
        loader = load_http2_header_order
    elif kind == "evidence":
        document = evidence
        source = registry / "candidate.json"
        loader = load_http2_capture_evidence
    else:
        document = {
            "schema": "browser-core.http2-evidence-baseline/1",
            "source_evidence_id": "candidate",
            "baseline_evidence_id": "golden",
            "reviewed_digest_sha256": evidence["digest_sha256"],
            "evidence": evidence,
            "non_claim": (
                "Operator-approved same-connection local HTTP/2 settings, frame, and "
                "header-name order baseline only; not HTTP/3 or remote edge acceptance"
            ),
        }
        source = registry / "golden.baseline.json"
        loader = load_http2_evidence_baseline
    body = json.dumps(document).encode("utf-8")
    source.write_bytes(body)
    if kind == "evidence":
        checked = _http2_evidence_path(workspace, "candidate", label="current")
    elif kind == "baseline":
        checked = _http2_evidence_baseline_path(workspace, "golden")
    else:
        checked = source
    assert loader(checked) == document

    outside = tmp_path / "external.json"
    outside.write_bytes(body)
    source.unlink()
    source.hardlink_to(outside)
    assert source.stat().st_nlink == 2
    with pytest.raises(ContractError, match="hard links"):
        loader(checked)
    assert outside.read_bytes() == body


@pytest.mark.parametrize("kind", ["header-order", "evidence", "baseline"])
def test_http2_header_loaders_rebind_after_validation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, kind: str,
) -> None:
    evidence = _capture_evidence()
    if kind == "header-order":
        document = _attested_report()
        loader = load_http2_header_order
        validator_name = "validate_http2_header_order"
    elif kind == "evidence":
        document = evidence
        loader = load_http2_capture_evidence
        validator_name = "validate_http2_capture_evidence"
    else:
        document = {
            "schema": headers_module.HTTP2_EVIDENCE_BASELINE_SCHEMA,
            "source_evidence_id": "candidate",
            "baseline_evidence_id": "golden",
            "reviewed_digest_sha256": evidence["digest_sha256"],
            "evidence": evidence,
            "non_claim": headers_module._EVIDENCE_BASELINE_NON_CLAIM,
        }
        loader = load_http2_evidence_baseline
        validator_name = "validate_http2_evidence_baseline"
    source = tmp_path / "saved.json"
    body = json.dumps(document).encode("utf-8")
    source.write_bytes(body)
    assert loader(source) == document
    initial = source.stat()
    original_validate = getattr(headers_module, validator_name)

    def rewrite_after_validation(*args, **kwargs):
        validated = original_validate(*args, **kwargs)
        source.write_bytes(b"X" + body[1:])
        os.utime(source, ns=(initial.st_atime_ns, initial.st_mtime_ns))
        return validated

    with monkeypatch.context() as patch:
        patch.setattr(headers_module, validator_name, rewrite_after_validation)
        with pytest.raises(ContractError, match="changed during validation"):
            loader(source)
    assert len(source.read_bytes()) == len(body)
    source.write_bytes(body)
    assert loader(source) == document


@pytest.mark.parametrize(
    "update",
    [
        {"same_connection": False},
        {"unexpected": True},
        {"non_claim": "stronger than measured"},
    ],
)
def test_http2_capture_evidence_rejects_contract_drift(update: dict) -> None:
    with pytest.raises(ContractError):
        validate_http2_capture_evidence({**_capture_evidence(), **update})


def test_http2_header_and_same_connection_comparisons_are_field_level() -> None:
    baseline = _capture_evidence()
    current = __import__("copy").deepcopy(baseline)
    header_report = compare_http2_header_orders(
        current["header_order"],
        baseline["header_order"],
    )
    evidence_report = compare_http2_capture_evidence(current, baseline)
    assert header_report["passed"] is True
    assert evidence_report["passed"] is True
    assert evidence_report["changed_components"] == []

    current["header_order"]["header_names"][-2:] = ["accept", "user-agent"]
    current["header_order"]["digest_sha256"] = http2_header_order_digest(
        current["header_order"]
    )
    current["digest_sha256"] = http2_capture_evidence_digest(current)
    changed = compare_http2_capture_evidence(current, baseline)
    assert changed["passed"] is False
    assert changed["changed_components"] == ["header_order"]
    assert changed["header_order"]["changed_fields"] == ["header_names"]
    assert changed["fingerprint"]["passed"] is True


def test_http2_evidence_baseline_is_digest_reviewed_exclusive_and_portable(
    tmp_path,
) -> None:
    workspace = tmp_path / "source-workspace"
    registry = workspace / "http2-evidence"
    registry.mkdir(parents=True)
    evidence = _capture_evidence()
    (registry / "candidate.json").write_text(
        __import__("json").dumps(evidence),
        encoding="utf-8",
    )

    receipt = approve_http2_evidence_baseline(
        workspace,
        current_id="candidate",
        baseline_id="golden",
        expected_digest=evidence["digest_sha256"],
    )
    assert receipt["schema"] == "browser-core.http2-evidence-baseline-approval/1"
    baseline = load_http2_evidence_baseline(registry / "golden.baseline.json")
    assert validate_http2_evidence_baseline(baseline) == baseline
    assert baseline["evidence"] == evidence
    assert compare_http2_capture_evidence(evidence, baseline["evidence"])["passed"]

    with pytest.raises(ContractError, match="already exists"):
        approve_http2_evidence_baseline(
            workspace,
            current_id="candidate",
            baseline_id="golden",
            expected_digest=evidence["digest_sha256"],
        )

    target = tmp_path / "target-workspace"
    assert install_http2_evidence_baseline(target, baseline) == baseline
    assert load_http2_evidence_baseline(
        target / "http2-evidence" / "golden.baseline.json"
    ) == baseline


@pytest.mark.skipif(os.name != "nt", reason="Windows directory junction boundary")
@pytest.mark.parametrize("action", ["approve", "install"])
def test_http2_evidence_baseline_rejects_linked_workspace_before_foreign_write(
    tmp_path, action: str,
) -> None:
    source_workspace = tmp_path / "source"
    source_registry = source_workspace / "http2-evidence"
    source_registry.mkdir(parents=True)
    evidence = _capture_evidence()
    (source_registry / "candidate.json").write_text(json.dumps(evidence), encoding="utf-8")
    approve_http2_evidence_baseline(source_workspace, current_id="candidate",
                                    baseline_id="golden", expected_digest=evidence["digest_sha256"])
    baseline = load_http2_evidence_baseline(source_registry / "golden.baseline.json")

    foreign = tmp_path / "foreign"
    foreign_registry = foreign / "http2-evidence"
    foreign_registry.mkdir(parents=True)
    (foreign_registry / "candidate.json").write_text(json.dumps(evidence), encoding="utf-8")
    junction = tmp_path / "selected-workspace"
    created = subprocess.run(["cmd", "/c", "mklink", "/J", str(junction), str(foreign)],
                             capture_output=True, check=False)
    if created.returncode:
        pytest.skip("host could not create an unprivileged directory junction")
    try:
        with pytest.raises(ContractError):
            if action == "approve":
                approve_http2_evidence_baseline(junction, current_id="candidate",
                                                baseline_id="linked-approved",
                                                expected_digest=evidence["digest_sha256"])
            else:
                install_http2_evidence_baseline(junction, baseline)
        name = "linked-approved" if action == "approve" else "golden"
        assert not (foreign_registry / f"{name}.baseline.json").exists()
    finally:
        junction.rmdir()


@pytest.mark.parametrize("action", ["approve", "install"])
def test_http2_evidence_baseline_rejects_workspace_ancestor_relocation_after_readback(
    tmp_path, monkeypatch: pytest.MonkeyPatch, action: str,
) -> None:
    source_workspace = tmp_path / "source"
    source_registry = source_workspace / "http2-evidence"
    source_registry.mkdir(parents=True)
    evidence = _capture_evidence()
    (source_registry / "candidate.json").write_text(json.dumps(evidence), encoding="utf-8")
    approve_http2_evidence_baseline(source_workspace, current_id="candidate",
                                    baseline_id="golden", expected_digest=evidence["digest_sha256"])
    baseline = load_http2_evidence_baseline(source_registry / "golden.baseline.json")

    private = tmp_path / "private"
    workspace = private / "selected"
    registry = workspace / "http2-evidence"
    registry.mkdir(parents=True)
    (registry / "candidate.json").write_text(json.dumps(evidence), encoding="utf-8")
    retained = tmp_path / "retained"
    original_load = headers_module.load_http2_evidence_baseline
    swapped = False

    def move_after_read(path):
        nonlocal swapped
        result = original_load(path)
        if not swapped:
            private.rename(retained)
            private.mkdir()
            (retained / "selected").rename(workspace)
            swapped = True
        return result

    monkeypatch.setattr(headers_module, "load_http2_evidence_baseline", move_after_read)
    try:
        message = ("source or publication changed" if action == "approve"
                   else "changed after publication")
        with pytest.raises(ContractError, match=message):
            if action == "approve":
                approve_http2_evidence_baseline(workspace, current_id="candidate",
                                                baseline_id="linked-approved",
                                                expected_digest=evidence["digest_sha256"])
            else:
                install_http2_evidence_baseline(workspace, baseline)
        assert swapped
        name = "linked-approved" if action == "approve" else "golden"
        assert (registry / f"{name}.baseline.json").exists()
    finally:
        if swapped:
            workspace.rename(retained / "selected")
            private.rmdir()
            retained.rename(private)


def test_http2_evidence_approval_rechecks_source_after_destination_readback(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = tmp_path / "workspace"
    registry = workspace / "http2-evidence"
    registry.mkdir(parents=True)
    source = registry / "candidate.json"
    evidence = _capture_evidence()
    source.write_text(__import__("json").dumps(evidence), encoding="utf-8")
    original_load = headers_module.load_http2_evidence_baseline

    def mutate_source(path):  # noqa: ANN001, ANN202
        baseline = original_load(path)
        changed = __import__("copy").deepcopy(evidence)
        for child in (changed["fingerprint"], changed["header_order"]):
            child["core_build"]["executable_sha256_16"] = "4" * 16
        source.write_text(__import__("json").dumps(changed), encoding="utf-8")
        return baseline

    monkeypatch.setattr(headers_module, "load_http2_evidence_baseline", mutate_source)
    with pytest.raises(ContractError, match="source or publication changed"):
        approve_http2_evidence_baseline(
            workspace,
            current_id="candidate",
            baseline_id="golden-raced",
            expected_digest=evidence["digest_sha256"],
        )
    assert (registry / "golden-raced.baseline.json").is_file()


def test_http2_evidence_reader_waits_for_complete_continuation_block() -> None:
    block = _block(_headers(b"private-reader-value"))
    split = len(block) // 2
    raw = b"".join(
        (
            HTTP2_CONNECTION_PREFACE,
            _frame(4, 0, 0, b""),
            _frame(1, 0, 1, block[:split]),
            _frame(9, 4, 1, block[split:]),
        )
    )

    class Connection:
        def __init__(self) -> None:
            self.remaining = raw
            self.sent: list[bytes] = []

        def recv(self, requested: int) -> bytes:
            chunk = self.remaining[: min(requested, 2)]
            self.remaining = self.remaining[len(chunk) :]
            return chunk

        def sendall(self, body: bytes) -> None:
            self.sent.append(body)

    connection = Connection()
    evidence = _read_http2_client_evidence(connection)

    assert evidence["same_connection"] is True
    assert evidence["fingerprint"]["headers_started"] is True
    assert evidence["header_order"]["header_names"][-2:] == ["user-agent", "accept"]
    assert "private-reader-value" not in str(evidence)
    assert connection.remaining == b""
    assert connection.sent == [_frame(4, 0, 0, b"") + _frame(4, 1, 0, b"")]
