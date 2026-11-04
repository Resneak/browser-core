from __future__ import annotations

import hashlib
import json
import os
import struct
import subprocess
import tempfile
from pathlib import Path

import pytest
from hpack import Encoder

import browser_core.http2_fingerprint as h2_module
from browser_core.http2_headers import http2_capture_evidence_digest
from browser_core.contracts import ContractError
from browser_core.http2_fingerprint import (
    HTTP2_CONNECTION_PREFACE,
    _read_http2_client_flight,
    approve_http2_baseline,
    capture_attested_http2_fingerprint,
    capture_attested_http2_evidence,
    capture_http2_evidence,
    capture_http2_fingerprint,
    compare_http2_fingerprints,
    http2_fingerprint_digest,
    load_http2_fingerprint,
    load_http2_baseline,
    install_http2_baseline,
    parse_http2_client_preface,
    validate_http2_fingerprint,
)
from browser_core.worker import _http2_baseline_path, _http2_fingerprint_path


def _frame(frame_type: int, flags: int, stream_id: int, payload: bytes) -> bytes:
    return (
        len(payload).to_bytes(3, "big")
        + bytes([frame_type, flags])
        + stream_id.to_bytes(4, "big")
        + payload
    )


def _settings(*items: tuple[int, int]) -> bytes:
    return b"".join(struct.pack(">HI", identifier, value) for identifier, value in items)


def _flight(
    *,
    settings: tuple[tuple[int, int], ...] = (
        (1, 65_536),
        (2, 0),
        (4, 6_291_456),
        (6, 262_144),
    ),
    window_increment: int = 15_663_105,
    header_payload: bytes = b"private-hpack-block",
) -> bytes:
    return b"".join(
        (
            HTTP2_CONNECTION_PREFACE,
            _frame(4, 0, 0, _settings(*settings)),
            _frame(8, 0, 0, struct.pack(">I", window_increment)),
            _frame(1, 5, 1, header_payload),
        )
    )


def _unchecked_digest(record: dict) -> str:
    body = json.dumps(
        {
            "settings": record["settings"],
            "connection_window_updates": record["connection_window_updates"],
            "pre_headers_frame_types": record["pre_headers_frame_types"],
            "headers_started": record["headers_started"],
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")
    return hashlib.sha256(body).hexdigest()


def test_http2_preface_projects_only_initial_transport_structure() -> None:
    record = parse_http2_client_preface(_flight())

    assert record["schema"] == "browser-core.http2-fingerprint/1"
    assert record["settings"] == [
        {"id": 1, "value": 65_536},
        {"id": 2, "value": 0},
        {"id": 4, "value": 6_291_456},
        {"id": 6, "value": 262_144},
    ]
    assert record["connection_window_updates"] == [15_663_105]
    assert record["pre_headers_frame_types"] == [4, 8]
    assert record["headers_started"] is True
    assert len(record["digest_sha256"]) == 64
    assert "private" not in str(record)
    assert validate_http2_fingerprint(record) == record


def test_http2_digest_ignores_header_values_but_keeps_ordered_settings() -> None:
    first = parse_http2_client_preface(_flight(header_payload=b"first-private"))
    second = parse_http2_client_preface(_flight(header_payload=b"second-private"))
    assert first == second

    reordered = parse_http2_client_preface(
        _flight(
            settings=((2, 0), (1, 65_536), (4, 6_291_456), (6, 262_144))
        )
    )
    assert reordered["digest_sha256"] != first["digest_sha256"]
    assert http2_fingerprint_digest(reordered) == reordered["digest_sha256"]

    changed_window = parse_http2_client_preface(
        _flight(window_increment=15_663_104)
    )
    assert changed_window["digest_sha256"] != first["digest_sha256"]


def test_http2_preface_accepts_valid_auxiliary_and_framed_headers() -> None:
    raw = b"".join(
        (
            HTTP2_CONNECTION_PREFACE,
            _frame(4, 0, 0, b""),
            _frame(6, 1, 0, b"12345678"),
            _frame(2, 0, 3, struct.pack(">IB", 1, 10)),
            _frame(
                1,
                0x2D,
                3,
                b"\x02" + struct.pack(">IB", 1, 10) + b"h" + b"\x00\x00",
            ),
        )
    )

    record = parse_http2_client_preface(raw)
    assert record["pre_headers_frame_types"] == [4, 6, 2]
    assert record["headers_started"] is True


@pytest.mark.parametrize(
    ("raw", "message"),
    [
        (b"not-h2", "connection preface"),
        (
            HTTP2_CONNECTION_PREFACE + _frame(8, 0, 0, struct.pack(">I", 1)),
            "first frame",
        ),
        (
            HTTP2_CONNECTION_PREFACE + _frame(4, 1, 0, b""),
            "initial SETTINGS flags",
        ),
        (
            HTTP2_CONNECTION_PREFACE
            + _frame(4, 0, 0, _settings((1, 1), (1, 2))),
            "repeats a setting",
        ),
        (
            HTTP2_CONNECTION_PREFACE + _frame(4, 0, 1, _settings((1, 1))),
            "SETTINGS stream",
        ),
        (
            HTTP2_CONNECTION_PREFACE + _frame(4, 0, 0, b"\x00"),
            "SETTINGS length",
        ),
        (
            HTTP2_CONNECTION_PREFACE
            + _frame(4, 0, 0, _settings((1, 1)))
            + b"\x00",
            "frame header is truncated",
        ),
        (
            HTTP2_CONNECTION_PREFACE
            + _frame(4, 0, 0, _settings((1, 1)))
            + _frame(4, 1, 0, _settings((2, 0))),
            "SETTINGS acknowledgement",
        ),
        (
            HTTP2_CONNECTION_PREFACE
            + _frame(4, 0, 0, _settings((1, 1)))
            + _frame(8, 0, 1, b"\x00\x00\x00\x00"),
            "WINDOW_UPDATE is zero",
        ),
        (
            HTTP2_CONNECTION_PREFACE
            + _frame(4, 0, 0, _settings((1, 1)))
            + _frame(1, 4, 0, b""),
            "HEADERS stream",
        ),
        (
            HTTP2_CONNECTION_PREFACE + _frame(4, 0, 0, _settings((2, 2))),
            "ENABLE_PUSH",
        ),
        (
            HTTP2_CONNECTION_PREFACE + _frame(4, 0, 0, _settings((5, 16_383))),
            "MAX_FRAME_SIZE",
        ),
        (
            HTTP2_CONNECTION_PREFACE
            + _frame(4, 0, 0, b"")
            + _frame(6, 0, 1, b"12345678"),
            "PING",
        ),
        (
            HTTP2_CONNECTION_PREFACE
            + _frame(4, 0, 0, b"")
            + _frame(6, 0, 0, b"short"),
            "PING",
        ),
        (
            HTTP2_CONNECTION_PREFACE
            + _frame(4, 0, 0, b"")
            + _frame(2, 0, 0, b"12345"),
            "PRIORITY",
        ),
        (
            HTTP2_CONNECTION_PREFACE
            + _frame(4, 0, 0, b"")
            + _frame(2, 0, 3, struct.pack(">IB", 3, 1)),
            "depends on itself",
        ),
        (
            HTTP2_CONNECTION_PREFACE
            + _frame(4, 0, 0, b"")
            + _frame(3, 0, 0, b"1234"),
            "RST_STREAM",
        ),
        (
            HTTP2_CONNECTION_PREFACE
            + _frame(4, 0, 0, b"")
            + _frame(0, 0, 1, b"data"),
            "DATA before HEADERS",
        ),
        (
            HTTP2_CONNECTION_PREFACE
            + _frame(4, 0, 0, b"")
            + _frame(5, 0, 1, b"push"),
            "PUSH_PROMISE",
        ),
        (
            HTTP2_CONNECTION_PREFACE
            + _frame(4, 0, 0, b"")
            + _frame(9, 0, 1, b"continuation"),
            "CONTINUATION before HEADERS",
        ),
        (
            HTTP2_CONNECTION_PREFACE
            + _frame(4, 0, 0, b"")
            + _frame(7, 0, 1, b"12345678"),
            "GOAWAY",
        ),
        (
            HTTP2_CONNECTION_PREFACE
            + _frame(4, 0, 0, b"")
            + _frame(8, 0, 1, struct.pack(">I", 1)),
            "idle stream WINDOW_UPDATE",
        ),
        (
            HTTP2_CONNECTION_PREFACE
            + _frame(4, 0, 0, b"")
            + _frame(1, 0x02, 1, b"headers"),
            "HEADERS flags",
        ),
        (
            HTTP2_CONNECTION_PREFACE
            + _frame(4, 0, 0, b"")
            + _frame(1, 0x08, 1, b""),
            "HEADERS padding",
        ),
        (
            HTTP2_CONNECTION_PREFACE
            + _frame(4, 0, 0, b"")
            + _frame(1, 0x08, 1, b"\x08tiny"),
            "HEADERS padding",
        ),
        (
            HTTP2_CONNECTION_PREFACE
            + _frame(4, 0, 0, b"")
            + _frame(1, 0x20, 1, b"tiny"),
            "HEADERS priority",
        ),
        (
            HTTP2_CONNECTION_PREFACE
            + _frame(4, 0, 0, b"")
            + _frame(1, 0x20, 3, struct.pack(">IB", 3, 1)),
            "depends on itself",
        ),
    ],
)
def test_http2_preface_rejects_malformed_initial_flights(
    raw: bytes,
    message: str,
) -> None:
    with pytest.raises(ContractError, match=message):
        parse_http2_client_preface(raw)


@pytest.mark.parametrize(
    "mutation",
    [
        lambda value: value.__setitem__("extra", True),
        lambda value: value.__setitem__("headers_started", 1),
        lambda value: value.__setitem__("pre_headers_frame_types", [4, True]),
        lambda value: value.__setitem__("pre_headers_frame_types", [4, []]),
        lambda value: value.__setitem__("connection_window_updates", [0]),
        lambda value: value["settings"].append({"id": 1, "value": 2}),
        lambda value: value.__setitem__("digest_sha256", "f" * 64),
    ],
)
def test_http2_fingerprint_validation_is_exact(mutation) -> None:
    record = parse_http2_client_preface(_flight())
    mutation(record)
    with pytest.raises(ContractError):
        validate_http2_fingerprint(record)


@pytest.mark.parametrize(
    ("identifier", "value", "message"),
    [
        (2, 2, "ENABLE_PUSH"),
        (4, 0x80000000, "INITIAL_WINDOW_SIZE"),
        (5, 16_383, "MAX_FRAME_SIZE"),
        (8, 2, "boolean SETTINGS"),
        (9, 2, "boolean SETTINGS"),
    ],
)
def test_http2_document_validation_rechecks_known_setting_semantics(
    identifier: int,
    value: int,
    message: str,
) -> None:
    record = parse_http2_client_preface(_flight())
    record["settings"] = [{"id": identifier, "value": value}]
    record["digest_sha256"] = _unchecked_digest(record)

    with pytest.raises(ContractError, match=message):
        validate_http2_fingerprint(record)


def test_attested_http2_document_must_reach_headers() -> None:
    record = _attested_h2_record()
    record["headers_started"] = False
    record["digest_sha256"] = _unchecked_digest(record)

    with pytest.raises(ContractError, match="complete HEADERS"):
        validate_http2_fingerprint(record, require_build=True)


def test_http2_document_cannot_claim_headers_inside_pre_headers_sequence() -> None:
    record = parse_http2_client_preface(_flight())
    record["pre_headers_frame_types"].append(1)
    record["digest_sha256"] = _unchecked_digest(record)

    with pytest.raises(ContractError, match="pre-HEADERS"):
        validate_http2_fingerprint(record)


@pytest.mark.parametrize("frame_type", [0, 5, 9])
def test_http2_document_rejects_impossible_pre_headers_frame(frame_type: int) -> None:
    record = parse_http2_client_preface(_flight())
    record["pre_headers_frame_types"].append(frame_type)
    record["digest_sha256"] = _unchecked_digest(record)

    with pytest.raises(ContractError, match="pre-HEADERS"):
        validate_http2_fingerprint(record)


def test_http2_document_binds_connection_updates_to_observed_frames() -> None:
    record = parse_http2_client_preface(_flight())
    record["pre_headers_frame_types"] = [4]
    record["digest_sha256"] = _unchecked_digest(record)

    with pytest.raises(ContractError, match="WINDOW_UPDATE receipts"):
        validate_http2_fingerprint(record)


def test_http2_document_cannot_omit_observed_connection_update() -> None:
    record = parse_http2_client_preface(_flight())
    assert record["pre_headers_frame_types"].count(8) == 1
    record["connection_window_updates"] = []
    record["digest_sha256"] = _unchecked_digest(record)

    with pytest.raises(ContractError, match="WINDOW_UPDATE receipts"):
        validate_http2_fingerprint(record)


def _attested_h2_record() -> dict:
    record = parse_http2_client_preface(_flight())
    record["core_build"] = {
        "chromium_revision": "1" * 40,
        "executable_sha256_16": "2" * 16,
        "runtime_bundle_sha256_16": "3" * 16,
    }
    return record


def test_http2_fingerprint_requires_non_null_build_receipt() -> None:
    record = _attested_h2_record()
    record["core_build"] = None

    with pytest.raises(ContractError, match="build receipt"):
        validate_http2_fingerprint(record, require_build=True)


def test_http2_loader_is_stable_bounded_strict_and_attested(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "h2.json"
    expected = _attested_h2_record()
    source.write_text(json.dumps(expected), encoding="utf-8")
    assert load_http2_fingerprint(source) == expected

    source.write_bytes(b'{"schema":"a","schema":"b"}')
    with pytest.raises(ContractError, match="duplicate key"):
        load_http2_fingerprint(source)
    source.write_bytes(b'{"value":NaN}')
    with pytest.raises(ContractError, match="non-finite"):
        load_http2_fingerprint(source)
    source.write_bytes(b"\xff")
    with pytest.raises(ContractError, match="valid UTF-8 JSON"):
        load_http2_fingerprint(source)
    source.write_bytes(b"{}")
    monkeypatch.setattr(h2_module, "MAX_HTTP2_FINGERPRINT_BYTES", 1)
    with pytest.raises(ContractError, match="exceeds"):
        load_http2_fingerprint(source)


@pytest.mark.parametrize("baseline", [False, True])
def test_http2_loaders_rebind_after_validation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, baseline: bool,
) -> None:
    fingerprint = _attested_h2_record()
    if baseline:
        document = {
            "schema": h2_module.HTTP2_BASELINE_SCHEMA,
            "source_fingerprint_id": "candidate",
            "baseline_fingerprint_id": "golden",
            "reviewed_digest_sha256": fingerprint["digest_sha256"],
            "fingerprint": fingerprint,
            "non_claim": h2_module._HTTP2_BASELINE_NON_CLAIM,
        }
        loader = load_http2_baseline
        validator_name = "validate_http2_baseline"
    else:
        document = fingerprint
        loader = load_http2_fingerprint
        validator_name = "validate_http2_fingerprint"
    source = tmp_path / "saved.json"
    body = json.dumps(document).encode("utf-8")
    source.write_bytes(body)
    assert loader(source) == document
    initial = source.stat()
    original_validate = getattr(h2_module, validator_name)

    def rewrite_after_validation(*args, **kwargs):
        validated = original_validate(*args, **kwargs)
        source.write_bytes(b"X" + body[1:])
        os.utime(source, ns=(initial.st_atime_ns, initial.st_mtime_ns))
        return validated

    with monkeypatch.context() as patch:
        patch.setattr(h2_module, validator_name, rewrite_after_validation)
        with pytest.raises(ContractError, match="changed during validation"):
            loader(source)
    assert len(source.read_bytes()) == len(body)
    source.write_bytes(body)
    assert loader(source) == document


@pytest.mark.parametrize("baseline", [False, True])
def test_http2_loader_rechecks_single_link_after_worker_path_check(
    tmp_path: Path, baseline: bool,
) -> None:
    workspace = tmp_path / "workspace"
    registry = workspace / "http2-fingerprints"
    registry.mkdir(parents=True)
    fingerprint = _attested_h2_record()
    document = ({
        "schema": "browser-core.http2-baseline/1",
        "source_fingerprint_id": "candidate",
        "baseline_fingerprint_id": "golden",
        "reviewed_digest_sha256": fingerprint["digest_sha256"],
        "fingerprint": fingerprint,
        "non_claim": (
            "Operator-approved local HTTP/2 initial-flight baseline only; not HTTP/3 "
            "or remote edge acceptance"
        ),
    } if baseline else fingerprint)
    source = registry / ("golden.baseline.json" if baseline else "candidate.json")
    body = json.dumps(document).encode("utf-8")
    source.write_bytes(body)
    if baseline:
        checked = _http2_baseline_path(workspace, "golden")
        loader = load_http2_baseline
    else:
        checked = _http2_fingerprint_path(workspace, "candidate", label="current")
        loader = load_http2_fingerprint
    assert loader(checked) == document

    outside = tmp_path / "external.json"
    outside.write_bytes(body)
    source.unlink()
    source.hardlink_to(outside)
    assert source.stat().st_nlink == 2
    with pytest.raises(ContractError, match="hard links"):
        loader(checked)
    assert outside.read_bytes() == body


def test_http2_comparison_is_an_attested_field_level_golden_gate() -> None:
    baseline = _attested_h2_record()
    identical = json.loads(json.dumps(baseline))
    passed = compare_http2_fingerprints(identical, baseline)
    assert passed["passed"] is True
    assert passed["changed_fields"] == []

    changed = json.loads(json.dumps(baseline))
    changed["connection_window_updates"] = [1]
    changed["digest_sha256"] = http2_fingerprint_digest(changed)
    changed["core_build"] = {
        "chromium_revision": "4" * 40,
        "executable_sha256_16": "5" * 16,
        "runtime_bundle_sha256_16": "6" * 16,
    }
    failed = compare_http2_fingerprints(changed, baseline)
    assert failed["passed"] is False
    assert failed["same_digest"] is False
    assert failed["changed_fields"] == ["connection_window_updates"]
    assert failed["current_core_build"] == changed["core_build"]
    assert failed["baseline_core_build"] == baseline["core_build"]

    with pytest.raises(ContractError, match="fields"):
        compare_http2_fingerprints(parse_http2_client_preface(_flight()), baseline)


def test_http2_baseline_approval_is_typed_digest_confirmed_and_exclusive(
    tmp_path,
) -> None:
    workspace = tmp_path / "workspace"
    registry = workspace / "http2-fingerprints"
    registry.mkdir(parents=True)
    current = _attested_h2_record()
    (registry / "candidate.json").write_text(json.dumps(current), encoding="utf-8")

    receipt = approve_http2_baseline(
        workspace,
        current_id="candidate",
        baseline_id="golden",
        expected_digest=current["digest_sha256"],
    )

    assert receipt["schema"] == "browser-core.http2-baseline-approval/1"
    assert receipt["digest_sha256"] == current["digest_sha256"]
    baseline = load_http2_baseline(registry / "golden.baseline.json")
    assert baseline["schema"] == "browser-core.http2-baseline/1"
    assert baseline["fingerprint"] == current
    assert baseline["reviewed_digest_sha256"] == current["digest_sha256"]

    with pytest.raises(ContractError, match="reviewed digest"):
        approve_http2_baseline(
            workspace,
            current_id="candidate",
            baseline_id="wrong",
            expected_digest="f" * 64,
        )
    assert not (registry / "wrong.baseline.json").exists()
    with pytest.raises(ContractError, match="already exists"):
        approve_http2_baseline(
            workspace,
            current_id="candidate",
            baseline_id="golden",
            expected_digest=current["digest_sha256"],
        )


@pytest.mark.skipif(os.name != "nt", reason="Windows directory junction boundary")
@pytest.mark.parametrize("action", ["approve", "install"])
def test_http2_baseline_rejects_linked_workspace_before_foreign_write(
    tmp_path, action: str,
) -> None:
    source_workspace = tmp_path / "source"
    source_registry = source_workspace / "http2-fingerprints"
    source_registry.mkdir(parents=True)
    current = _attested_h2_record()
    (source_registry / "candidate.json").write_text(json.dumps(current), encoding="utf-8")
    approve_http2_baseline(source_workspace, current_id="candidate",
                           baseline_id="golden", expected_digest=current["digest_sha256"])
    baseline = load_http2_baseline(source_registry / "golden.baseline.json")

    foreign = tmp_path / "foreign"
    foreign_registry = foreign / "http2-fingerprints"
    foreign_registry.mkdir(parents=True)
    (foreign_registry / "candidate.json").write_text(json.dumps(current), encoding="utf-8")
    junction = tmp_path / "selected-workspace"
    created = subprocess.run(["cmd", "/c", "mklink", "/J", str(junction), str(foreign)],
                             capture_output=True, check=False)
    if created.returncode:
        pytest.skip("host could not create an unprivileged directory junction")
    try:
        with pytest.raises(ContractError):
            if action == "approve":
                approve_http2_baseline(junction, current_id="candidate",
                                       baseline_id="linked-approved",
                                       expected_digest=current["digest_sha256"])
            else:
                install_http2_baseline(junction, baseline)
        name = "linked-approved" if action == "approve" else "golden"
        assert not (foreign_registry / f"{name}.baseline.json").exists()
    finally:
        junction.rmdir()


@pytest.mark.parametrize("action", ["approve", "install"])
def test_http2_baseline_rejects_workspace_ancestor_relocation_after_readback(
    tmp_path, monkeypatch: pytest.MonkeyPatch, action: str,
) -> None:
    source_workspace = tmp_path / "source"
    source_registry = source_workspace / "http2-fingerprints"
    source_registry.mkdir(parents=True)
    current = _attested_h2_record()
    (source_registry / "candidate.json").write_text(json.dumps(current), encoding="utf-8")
    approve_http2_baseline(source_workspace, current_id="candidate",
                           baseline_id="golden", expected_digest=current["digest_sha256"])
    baseline = load_http2_baseline(source_registry / "golden.baseline.json")

    private = tmp_path / "private"
    workspace = private / "selected"
    registry = workspace / "http2-fingerprints"
    registry.mkdir(parents=True)
    (registry / "candidate.json").write_text(json.dumps(current), encoding="utf-8")
    retained = tmp_path / "retained"
    original_load = h2_module.load_http2_baseline
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

    monkeypatch.setattr(h2_module, "load_http2_baseline", move_after_read)
    try:
        message = ("source or publication changed" if action == "approve"
                   else "changed after publication")
        with pytest.raises(ContractError, match=message):
            if action == "approve":
                approve_http2_baseline(workspace, current_id="candidate",
                                       baseline_id="linked-approved",
                                       expected_digest=current["digest_sha256"])
            else:
                install_http2_baseline(workspace, baseline)
        assert swapped
        name = "linked-approved" if action == "approve" else "golden"
        assert (registry / f"{name}.baseline.json").exists()
    finally:
        if swapped:
            workspace.rename(retained / "selected")
            private.rmdir()
            retained.rename(private)


def test_http2_baseline_approval_rechecks_source_before_publication(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = tmp_path / "workspace"
    registry = workspace / "http2-fingerprints"
    registry.mkdir(parents=True)
    source = registry / "candidate.json"
    current = _attested_h2_record()
    source.write_text(json.dumps(current), encoding="utf-8")
    original_validate = h2_module.validate_http2_baseline

    def mutate_source(document):  # noqa: ANN001, ANN202
        changed = json.loads(json.dumps(current))
        changed["core_build"]["executable_sha256_16"] = "4" * 16
        source.write_text(json.dumps(changed), encoding="utf-8")
        return original_validate(document)

    monkeypatch.setattr(h2_module, "validate_http2_baseline", mutate_source)
    with pytest.raises(ContractError, match="source changed"):
        approve_http2_baseline(
            workspace,
            current_id="candidate",
            baseline_id="golden-raced",
            expected_digest=current["digest_sha256"],
        )
    assert not (registry / "golden-raced.baseline.json").exists()


def test_http2_baseline_approval_rechecks_source_after_destination_readback(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = tmp_path / "workspace"
    registry = workspace / "http2-fingerprints"
    registry.mkdir(parents=True)
    source = registry / "candidate.json"
    current = _attested_h2_record()
    source.write_text(json.dumps(current), encoding="utf-8")
    original_load = h2_module.load_http2_baseline

    def mutate_source(path):  # noqa: ANN001, ANN202
        baseline = original_load(path)
        changed = json.loads(json.dumps(current))
        changed["core_build"]["executable_sha256_16"] = "4" * 16
        source.write_text(json.dumps(changed), encoding="utf-8")
        return baseline

    monkeypatch.setattr(h2_module, "load_http2_baseline", mutate_source)
    with pytest.raises(ContractError, match="source or publication changed"):
        approve_http2_baseline(
            workspace,
            current_id="candidate",
            baseline_id="golden-raced",
            expected_digest=current["digest_sha256"],
        )
    assert (registry / "golden-raced.baseline.json").is_file()


def test_http2_baseline_installs_on_another_worker_and_rejects_raw_capture(
    tmp_path,
) -> None:
    source_workspace = tmp_path / "source"
    source_registry = source_workspace / "http2-fingerprints"
    source_registry.mkdir(parents=True)
    current = _attested_h2_record()
    (source_registry / "candidate.json").write_text(
        json.dumps(current), encoding="utf-8"
    )
    approve_http2_baseline(
        source_workspace,
        current_id="candidate",
        baseline_id="golden",
        expected_digest=current["digest_sha256"],
    )
    baseline = load_http2_baseline(source_registry / "golden.baseline.json")

    target_workspace = tmp_path / "target"
    assert install_http2_baseline(target_workspace, baseline) == baseline
    target = target_workspace / "http2-fingerprints" / "golden.baseline.json"
    assert load_http2_baseline(target) == baseline
    with pytest.raises(ContractError, match="already exists"):
        install_http2_baseline(target_workspace, baseline)

    target.write_text(json.dumps(current), encoding="utf-8")
    with pytest.raises(ContractError, match="baseline fields"):
        load_http2_baseline(target)


def test_http2_baseline_rejects_device_id_before_registry_creation(
    tmp_path: Path,
) -> None:
    fingerprint = _attested_h2_record()
    baseline = {
        "schema": h2_module.HTTP2_BASELINE_SCHEMA,
        "source_fingerprint_id": "candidate",
        "baseline_fingerprint_id": "CON",
        "reviewed_digest_sha256": fingerprint["digest_sha256"],
        "fingerprint": fingerprint,
        "non_claim": h2_module._HTTP2_BASELINE_NON_CLAIM,
    }
    with pytest.raises(ContractError):
        install_http2_baseline(tmp_path, baseline)
    assert not (tmp_path / "http2-fingerprints").exists()


def test_http2_flight_reader_acknowledges_settings_and_stops_at_headers() -> None:
    raw = _flight(header_payload=b"private-hpack")

    class Connection:
        def __init__(self) -> None:
            self.remaining = raw
            self.sent: list[bytes] = []

        def recv(self, requested: int) -> bytes:
            chunk = self.remaining[: min(requested, 3)]
            self.remaining = self.remaining[len(chunk) :]
            return chunk

        def sendall(self, body: bytes) -> None:
            self.sent.append(body)

    connection = Connection()
    record = _read_http2_client_flight(connection)

    assert record["headers_started"] is True
    assert "private" not in str(record)
    assert connection.remaining == b""
    assert connection.sent == [
        _frame(4, 0, 0, b"") + _frame(4, 1, 0, b"")
    ]


@pytest.mark.parametrize("bad_chunk", [None, "bytes", b"x" * 25])
def test_http2_flight_reader_rejects_invalid_transport_chunks(bad_chunk) -> None:
    class Connection:
        def recv(self, _requested: int):  # noqa: ANN201
            return bad_chunk

        def sendall(self, _body: bytes) -> None:
            pytest.fail("invalid preface reached server response")

    with pytest.raises(ContractError, match="transport returned|closed"):
        _read_http2_client_flight(Connection())


def test_http2_flight_reader_enforces_one_absolute_deadline() -> None:
    class Connection:
        def __init__(self) -> None:
            self.reads = 0
            self.timeouts: list[float] = []

        def settimeout(self, value: float) -> None:
            self.timeouts.append(value)

        def recv(self, _requested: int) -> bytes:
            self.reads += 1
            return b"P"

        def sendall(self, _body: bytes) -> None:
            pytest.fail("expired read reached server response")

    moments = iter((10.25, 11.0))
    connection = Connection()
    with pytest.raises(ContractError, match="deadline expired"):
        _read_http2_client_flight(
            connection,
            deadline=11.0,
            clock=lambda: next(moments),
        )
    assert connection.reads == 1
    assert connection.timeouts == [0.75]


def test_http2_flight_reader_rejects_a_complete_final_frame_after_deadline() -> None:
    raw = _flight()
    now = [10.0]

    class Connection:
        def __init__(self) -> None:
            self.remaining = raw

        def settimeout(self, _value: float) -> None:
            return None

        def recv(self, requested: int) -> bytes:
            chunk = self.remaining[:requested]
            self.remaining = self.remaining[len(chunk) :]
            if not self.remaining:
                now[0] = 11.0
            return chunk

        def sendall(self, _body: bytes) -> None:
            return None

    with pytest.raises(ContractError, match="deadline expired"):
        _read_http2_client_flight(
            Connection(),
            deadline=11.0,
            clock=lambda: now[0],
        )


@pytest.mark.parametrize(
    "server_name",
    ["bc-h2-" + "a" * 32 + ".invalid", "other-local-client.invalid"],
)
@pytest.mark.parametrize("capture_kind", ["fingerprint", "evidence"])
@pytest.mark.parametrize('replace_profile', [False, True])
def test_http2_capture_uses_ephemeral_loopback_tls_and_returns_no_key_material(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
    server_name: str,
    capture_kind: str,
    replace_profile: bool,
) -> None:
    executable = tmp_path / "chrome.exe"
    certificate = tmp_path / "cert.local"
    private_key = tmp_path / "key.local"
    executable.write_bytes(b"browser")
    certificate.write_bytes(b"certificate")
    private_key.write_bytes(b"private-key-material")
    header_payload = Encoder().encode(
        [
            (b":method", b"GET"),
            (b":authority", b"bc.invalid"),
            (b":scheme", b"https"),
            (b":path", b"/private-path"),
            (b"user-agent", b"private-header"),
        ]
    )
    flight = _flight(header_payload=header_payload)

    class Connection:
        def __init__(self) -> None:
            self.remaining = flight
            self.timeout = None
            self.sent: list[bytes] = []
            self.closed = False

        def settimeout(self, value: float) -> None:
            self.timeout = value

        def recv(self, requested: int) -> bytes:
            chunk = self.remaining[: min(requested, 5)]
            self.remaining = self.remaining[len(chunk) :]
            return chunk

        def sendall(self, body: bytes) -> None:
            self.sent.append(body)

        def selected_alpn_protocol(self) -> str:
            return "h2"

        def close(self) -> None:
            self.closed = True

    connection = Connection()

    class Listener:
        def __init__(self) -> None:
            self.closed = False

        def setsockopt(self, *_args) -> None:  # noqa: ANN002
            pass

        def bind(self, address) -> None:  # noqa: ANN001
            assert address == ("127.0.0.1", 0)

        def listen(self, backlog: int) -> None:
            assert backlog == 1

        def settimeout(self, value: float) -> None:
            assert 0 < value <= 7.0

        def getsockname(self):  # noqa: ANN201
            return ("127.0.0.1", 44321)

        def accept(self):  # noqa: ANN201
            return connection, ("127.0.0.1", 50000)

        def close(self) -> None:
            self.closed = True

    listener = Listener()

    class Context:
        def __init__(self) -> None:
            self.alpn = None
            self.chain = None
            self.sni_callback = None

        def set_alpn_protocols(self, protocols) -> None:  # noqa: ANN001
            self.alpn = protocols

        def load_cert_chain(self, cert: str, key: str) -> None:
            self.chain = (cert, key)

        def set_servername_callback(self, callback) -> None:  # noqa: ANN001
            self.sni_callback = callback

        def wrap_socket(self, raw, *, server_side: bool):  # noqa: ANN001, ANN201
            assert raw is connection and server_side is True
            assert self.sni_callback is not None
            self.sni_callback(
                raw,
                server_name,
                self,
            )
            return raw

    context = Context()

    class Process:
        def __init__(self) -> None:
            self.terminated = False

        def terminate(self) -> None:
            self.terminated = True

        def wait(self, *, timeout: float) -> int:
            assert timeout == 10.0
            return 0

    process = Process()
    launches: list[list[str]] = []
    parked = tmp_path / 'original-http2-profile'
    sentinel: Path | None = None
    real_temporary_directory = tempfile.TemporaryDirectory
    monkeypatch.setattr(
        h2_module.tempfile, 'TemporaryDirectory',
        lambda *, prefix: real_temporary_directory(prefix=prefix, dir=tmp_path),
    )
    monkeypatch.setattr(h2_module.socket, "socket", lambda *_args: listener)
    monkeypatch.setattr(
        h2_module.ssl,
        "SSLContext",
        lambda protocol: context
        if protocol == h2_module.ssl.PROTOCOL_TLS_SERVER
        else pytest.fail("wrong TLS protocol"),
    )

    def popen(argv, **_kwargs):  # noqa: ANN001, ANN003
        nonlocal sentinel
        launches.append(argv)
        if replace_profile:
            argument = next(item for item in argv if item.startswith('--user-data-dir='))
            root = Path(argument.split('=', 1)[1])
            assert root.parent == tmp_path
            root.rename(parked)
            root.mkdir()
            sentinel = root / 'replacement.txt'
            sentinel.write_text('replacement', encoding='utf-8')
        return process

    monkeypatch.setattr(h2_module.subprocess, "Popen", popen)
    monkeypatch.setattr(h2_module.secrets, "token_hex", lambda _size: "a" * 32)

    capture = (
        capture_http2_evidence
        if capture_kind == "evidence"
        else capture_http2_fingerprint
    )
    if replace_profile:
        try:
            with pytest.raises(ContractError, match='HTTP/2 capture profile directory changed before cleanup'):
                capture(executable, certificate, private_key, timeout_seconds=7)
            assert sentinel is not None
            assert sentinel.read_text(encoding='utf-8') == 'replacement'
            assert process.terminated is True
            assert listener.closed is True and connection.closed is True
        finally:
            if sentinel is not None and sentinel.exists():
                sentinel.unlink()
                sentinel.parent.rmdir()
            if parked.exists():
                parked.rmdir()
        return
    if server_name == "other-local-client.invalid":
        with pytest.raises(ContractError, match="server name does not match"):
            capture(
                executable,
                certificate,
                private_key,
                timeout_seconds=7,
            )
        assert process.terminated is True
        assert listener.closed is True and connection.closed is True
        return

    record = capture(
        executable,
        certificate,
        private_key,
        timeout_seconds=7,
    )

    fingerprint = record["fingerprint"] if capture_kind == "evidence" else record
    assert fingerprint["headers_started"] is True
    if capture_kind == "evidence":
        assert record["same_connection"] is True
        assert record["header_order"]["header_names"][-1] == "user-agent"
    assert "private" not in str(record).lower()
    assert context.alpn == ["h2"]
    assert context.chain == (str(certificate), str(private_key))
    assert context.sni_callback is not None
    assert len(launches) == 1
    assert "--ignore-certificate-errors" in launches[0]
    assert (
        "--host-resolver-rules=MAP bc-h2-"
        + "a" * 32
        + ".invalid 127.0.0.1, MAP * ^NOTFOUND"
        in launches[0]
    )
    assert launches[0][-1] == "https://bc-h2-" + "a" * 32 + ".invalid:44321/"
    assert process.terminated is True
    assert listener.closed is True and connection.closed is True


def test_attested_http2_capture_binds_and_rechecks_the_build(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "repo"
    executable = tmp_path / "chrome.exe"
    certificate = tmp_path / "cert"
    private_key = tmp_path / "key"
    attestation = {
        "chromium_revision": "1" * 40,
        "executable_sha256": "2" * 64,
        "runtime_bundle_sha256": "3" * 64,
    }
    calls: list[tuple] = []
    monkeypatch.setattr(
        h2_module,
        "load_build_attestation",
        lambda actual_root, actual_executable: (
            calls.append((actual_root, actual_executable)) or attestation
        ),
    )
    monkeypatch.setattr(
        h2_module,
        "capture_http2_fingerprint",
        lambda *args, **kwargs: (
            calls.append((*args, kwargs["timeout_seconds"]))
            or parse_http2_client_preface(_flight())
        ),
    )

    record = capture_attested_http2_fingerprint(
        root,
        executable,
        certificate,
        private_key,
        timeout_seconds=9,
    )

    assert record["core_build"] == {
        "chromium_revision": "1" * 40,
        "executable_sha256_16": "2" * 16,
        "runtime_bundle_sha256_16": "3" * 16,
    }
    assert calls == [
        (root, executable),
        (executable, certificate, private_key, 9),
        (root, executable),
    ]
    assert validate_http2_fingerprint(record, require_build=True) == record


def test_attested_http2_evidence_binds_both_artifacts_to_one_build(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "repo"
    executable = tmp_path / "chrome.exe"
    certificate = tmp_path / "cert"
    private_key = tmp_path / "key"
    attestation = {
        "chromium_revision": "1" * 40,
        "executable_sha256": "2" * 64,
        "runtime_bundle_sha256": "3" * 64,
    }
    raw = _flight(
        header_payload=Encoder().encode(
            [
                (b":method", b"GET"),
                (b":authority", b"bc.invalid"),
                (b":scheme", b"https"),
                (b":path", b"/private-path"),
            ]
        )
    )
    evidence = {
        "schema": "browser-core.http2-capture-evidence/1",
        "fingerprint": parse_http2_client_preface(raw),
        "header_order": __import__(
            "browser_core.http2_headers", fromlist=["parse_http2_header_order"]
        ).parse_http2_header_order(raw),
        "same_connection": True,
        "non_claim": (
            "One local negotiated HTTP/2 connection through first complete request "
            "headers; decoded values are discarded and no HTTP/3 or edge acceptance "
            "is proven"
        ),
    }
    evidence["digest_sha256"] = http2_capture_evidence_digest(evidence)
    monkeypatch.setattr(h2_module, "load_build_attestation", lambda *_args: attestation)
    monkeypatch.setattr(
        h2_module,
        "capture_http2_evidence",
        lambda *_args, **_kwargs: evidence,
    )

    result = capture_attested_http2_evidence(
        root,
        executable,
        certificate,
        private_key,
        timeout_seconds=9,
    )

    expected_build = {
        "chromium_revision": "1" * 40,
        "executable_sha256_16": "2" * 16,
        "runtime_bundle_sha256_16": "3" * 16,
    }
    assert result["fingerprint"]["core_build"] == expected_build
    assert result["header_order"]["core_build"] == expected_build


@pytest.mark.parametrize("timeout", [True, 0, 121, float("inf"), 10**400])
def test_http2_capture_invalid_timeout_fails_before_file_or_socket_contact(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
    timeout,
) -> None:
    monkeypatch.setattr(
        h2_module.socket,
        "socket",
        lambda *_args: pytest.fail("invalid timeout reached socket contact"),
    )
    with pytest.raises(ContractError, match="timeout"):
        capture_http2_fingerprint(
            tmp_path / "missing-browser",
            tmp_path / "missing-cert",
            tmp_path / "missing-key",
            timeout_seconds=timeout,
        )
