"""Gate the TLS ClientHello fingerprint bound to the attested build.

The parsing and digest logic is pure and runs everywhere. The capture needs a
real binary and skips without one.
"""

from __future__ import annotations

import os
import json
import struct
import subprocess
import tempfile
import threading
from pathlib import Path

import pytest

import browser_core.transport_fingerprint as transport_module
from browser_core.errors import ContractError
from browser_core.transport_fingerprint import (
    GREASE_VALUES,
    _read_tls_record,
    approve_transport_baseline,
    capture_attested_client_hello,
    capture_client_hello,
    compare_transport_fingerprints,
    load_transport_fingerprint,
    load_transport_baseline,
    install_transport_baseline,
    parse_client_hello,
    transport_digest,
    validate_transport_baseline,
    validate_transport_fingerprint,
)
from browser_core.worker import _transport_baseline_path, _transport_fingerprint_path


def _client_hello(
    *,
    ciphers,
    extensions,
    alpn=(b"h2", b"http/1.1"),
    groups=(0x001D, 0x0017),
    compression=(0,),
    point_formats=(0,),
    key_shares=(0x001D,),
    server_name=b"browser-core.invalid",
    certificate_compression=(2,),
    psk_modes=(1,),
    application_settings=(b"h2",),
    server_padding=16384,
    trust_anchors=(b"a" * 32, b"b" * 20),
    status_type=1,
    status_responders=(),
    status_extensions=b"",
    session_ticket=b"",
    renegotiation_info=b"",
    sct_payload=b"",
    ems_payload=b"",
) -> bytes:
    """Assemble a syntactically real ClientHello, so the parser is tested on one."""
    body = (
        struct.pack(">H", 0x0303) + b"\x00" * 32 + b"\x00"
    )  # version, random, empty session id
    body += struct.pack(">H", len(ciphers) * 2) + b"".join(
        struct.pack(">H", c) for c in ciphers
    )
    body += bytes([len(compression)]) + bytes(compression)

    blocks = b""
    for ext in extensions:
        if ext == 0:  # server_name
            name = b"\x00" + struct.pack(">H", len(server_name)) + server_name
            payload = struct.pack(">H", len(name)) + name
        elif ext == 5:  # status_request
            responders = b"".join(
                struct.pack(">H", len(responder)) + responder
                for responder in status_responders
            )
            payload = (
                bytes([status_type])
                + struct.pack(">H", len(responders))
                + responders
                + struct.pack(">H", len(status_extensions))
                + status_extensions
            )
        elif ext == 10:  # supported_groups
            payload = struct.pack(">H", len(groups) * 2) + b"".join(
                struct.pack(">H", g) for g in groups
            )
        elif ext == 11:  # ec_point_formats
            payload = bytes([len(point_formats)]) + bytes(point_formats)
        elif ext == 16:  # ALPN
            names = b"".join(bytes([len(n)]) + n for n in alpn)
            payload = struct.pack(">H", len(names)) + names
        elif ext == 18:  # signed_certificate_timestamp
            payload = sct_payload
        elif ext == 23:  # extended_master_secret
            payload = ems_payload
        elif ext == 27:  # compress_certificate
            algorithms = b"".join(
                struct.pack(">H", algorithm) for algorithm in certificate_compression
            )
            payload = bytes([len(algorithms)]) + algorithms
        elif ext == 35:  # session_ticket
            payload = session_ticket
        elif ext == 43:  # supported_versions
            payload = b"\x02\x03\x04"
        elif ext == 45:  # psk_key_exchange_modes
            payload = bytes([len(psk_modes), *psk_modes])
        elif ext == 51:  # key_share
            shares = b"".join(
                struct.pack(">HH", group, 1) + b"k" for group in key_shares
            )
            payload = struct.pack(">H", len(shares)) + shares
        elif ext in (17513, 17613):  # application_settings
            names = b"".join(bytes([len(n)]) + n for n in application_settings)
            payload = struct.pack(">H", len(names)) + names
        elif ext == 4832:  # server_padding
            payload = struct.pack(">H", server_padding)
        elif ext == 51764:  # trust_anchors
            identifiers = b"".join(
                bytes([len(identifier)]) + identifier for identifier in trust_anchors
            )
            payload = struct.pack(">H", len(identifiers)) + identifiers
        elif ext == 65281:  # renegotiation_info
            payload = bytes([len(renegotiation_info)]) + renegotiation_info
        else:
            payload = b""
        blocks += struct.pack(">HH", ext, len(payload)) + payload
    body += struct.pack(">H", len(blocks)) + blocks

    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + struct.pack(">H", len(handshake)) + handshake


def _transport_record() -> dict:
    record = parse_client_hello(
        _client_hello(ciphers=[0x1301, 0x1302], extensions=[10, 16, 43])
    )
    record["digest_sha256"] = transport_digest(record)
    return record


def _attested_transport_record() -> dict:
    record = _transport_record()
    record["core_build"] = {
        "chromium_revision": "1" * 40,
        "executable_sha256_16": "2" * 16,
        "runtime_bundle_sha256_16": "3" * 16,
    }
    return record


def test_transport_comparison_is_an_attested_normalized_golden_gate() -> None:
    baseline = _attested_transport_record()
    identical = {
        **baseline,
        "core_build": dict(baseline["core_build"]),
    }

    passed = compare_transport_fingerprints(identical, baseline)
    assert passed["passed"] is True
    assert passed["changed_fields"] == []
    assert passed["same_digest"] is True

    changed = {
        **baseline,
        "ciphers": list(reversed(baseline["ciphers"])),
        "core_build": {
            **baseline["core_build"],
            "chromium_revision": "4" * 40,
            "executable_sha256_16": "5" * 16,
            "runtime_bundle_sha256_16": "6" * 16,
        },
    }
    changed["digest_sha256"] = transport_digest(changed)

    failed = compare_transport_fingerprints(changed, baseline)
    assert failed["passed"] is False
    assert failed["same_digest"] is False
    assert failed["changed_fields"] == ["ciphers"]
    assert failed["current_core_build"] == changed["core_build"]
    assert failed["baseline_core_build"] == baseline["core_build"]


def test_transport_comparison_requires_attested_inputs() -> None:
    with pytest.raises(ContractError, match="fields"):
        compare_transport_fingerprints(_transport_record(), _attested_transport_record())


def test_transport_comparison_ignores_chromes_permuted_extension_order() -> None:
    baseline = _attested_transport_record()
    permuted = {
        **baseline,
        "extensions": list(reversed(baseline["extensions"])),
    }
    permuted["digest_sha256"] = transport_digest(permuted)

    compared = compare_transport_fingerprints(permuted, baseline)

    assert compared["same_digest"] is True
    assert compared["changed_fields"] == []
    assert compared["passed"] is True


def test_transport_loader_is_stable_bounded_strict_and_attested(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "transport.json"
    expected = _attested_transport_record()
    source.write_text(json.dumps(expected), encoding="utf-8")
    assert load_transport_fingerprint(source) == expected

    source.write_bytes(b'{"schema":"a","schema":"b"}')
    with pytest.raises(ContractError, match="duplicate key"):
        load_transport_fingerprint(source)

    source.write_bytes(b'{"value":NaN}')
    with pytest.raises(ContractError, match="non-finite"):
        load_transport_fingerprint(source)

    source.write_bytes(b"\xff")
    with pytest.raises(ContractError, match="valid UTF-8 JSON"):
        load_transport_fingerprint(source)

    source.write_bytes(b"{}")
    monkeypatch.setattr(transport_module, "MAX_TRANSPORT_FINGERPRINT_BYTES", 1)
    with pytest.raises(ContractError, match="exceeds"):
        load_transport_fingerprint(source)

    with pytest.raises(ContractError, match="path must be a Path"):
        load_transport_fingerprint(str(source))  # type: ignore[arg-type]


@pytest.mark.parametrize("baseline", [False, True])
def test_transport_loaders_rebind_after_validation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, baseline: bool,
) -> None:
    fingerprint = _attested_transport_record()
    if baseline:
        document = {
            "schema": transport_module.TRANSPORT_BASELINE_SCHEMA,
            "source_fingerprint_id": "candidate",
            "baseline_fingerprint_id": "golden",
            "reviewed_digest_sha256": fingerprint["digest_sha256"],
            "fingerprint": fingerprint,
            "non_claim": (
                "Operator-approved local TLS ClientHello baseline only; not H2/H3 "
                "or remote edge acceptance"
            ),
        }
        loader = load_transport_baseline
        validator_name = "validate_transport_baseline"
    else:
        document = fingerprint
        loader = load_transport_fingerprint
        validator_name = "validate_transport_fingerprint"
    source = tmp_path / "saved.json"
    body = json.dumps(document).encode("utf-8")
    source.write_bytes(body)
    assert loader(source) == document
    initial = source.stat()
    original_validate = getattr(transport_module, validator_name)

    def rewrite_after_validation(*args, **kwargs):
        validated = original_validate(*args, **kwargs)
        source.write_bytes(b"X" + body[1:])
        os.utime(source, ns=(initial.st_atime_ns, initial.st_mtime_ns))
        return validated

    with monkeypatch.context() as patch:
        patch.setattr(transport_module, validator_name, rewrite_after_validation)
        with pytest.raises(ContractError, match="changed during validation"):
            loader(source)
    assert len(source.read_bytes()) == len(body)
    source.write_bytes(body)
    assert loader(source) == document


@pytest.mark.parametrize("baseline", [False, True])
def test_transport_loader_rechecks_single_link_after_worker_path_check(
    tmp_path: Path, baseline: bool,
) -> None:
    workspace = tmp_path / "workspace"
    registry = workspace / "transport-fingerprints"
    registry.mkdir(parents=True)
    fingerprint = _attested_transport_record()
    document = ({
        "schema": "browser-core.transport-baseline/1",
        "source_fingerprint_id": "candidate",
        "baseline_fingerprint_id": "golden",
        "reviewed_digest_sha256": fingerprint["digest_sha256"],
        "fingerprint": fingerprint,
        "non_claim": (
            "Operator-approved local TLS ClientHello baseline only; not H2/H3 "
            "or remote edge acceptance"
        ),
    } if baseline else fingerprint)
    source = registry / ("golden.baseline.json" if baseline else "candidate.json")
    body = json.dumps(document).encode("utf-8")
    source.write_bytes(body)
    if baseline:
        checked = _transport_baseline_path(workspace, "golden")
        loader = load_transport_baseline
    else:
        checked = _transport_fingerprint_path(workspace, "candidate", label="current")
        loader = load_transport_fingerprint
    assert loader(checked) == document

    outside = tmp_path / "external.json"
    outside.write_bytes(body)
    source.unlink()
    source.hardlink_to(outside)
    assert source.stat().st_nlink == 2
    with pytest.raises(ContractError, match="hard links"):
        loader(checked)
    assert outside.read_bytes() == body


def test_transport_baseline_approval_requires_the_reviewed_full_digest(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    registry = workspace / "transport-fingerprints"
    registry.mkdir(parents=True)
    current = _attested_transport_record()
    (registry / "candidate.json").write_text(json.dumps(current), encoding="utf-8")

    receipt = approve_transport_baseline(
        workspace,
        current_id="candidate",
        baseline_id="golden-1",
        expected_digest=current["digest_sha256"],
    )

    assert receipt == {
        "schema": "browser-core.transport-baseline-approval/1",
        "source_fingerprint_id": "candidate",
        "baseline_fingerprint_id": "golden-1",
        "digest_sha256": current["digest_sha256"],
        "core_build": current["core_build"],
        "non_claim": (
            "Operator-approved local TLS ClientHello baseline only; not H2/H3 "
            "or remote edge acceptance"
        ),
    }
    baseline = load_transport_baseline(registry / "golden-1.baseline.json")
    assert baseline == {
        "schema": "browser-core.transport-baseline/1",
        "source_fingerprint_id": "candidate",
        "baseline_fingerprint_id": "golden-1",
        "reviewed_digest_sha256": current["digest_sha256"],
        "fingerprint": current,
        "non_claim": (
            "Operator-approved local TLS ClientHello baseline only; not H2/H3 "
            "or remote edge acceptance"
        ),
    }

    with pytest.raises(ContractError, match="reviewed digest"):
        approve_transport_baseline(
            workspace,
            current_id="candidate",
            baseline_id="wrong-digest",
            expected_digest="f" * 64,
        )
    assert not (registry / "wrong-digest.json").exists()


@pytest.mark.skipif(os.name != "nt", reason="Windows directory junction boundary")
@pytest.mark.parametrize("action", ["approve", "install"])
def test_transport_baseline_rejects_linked_workspace_before_foreign_write(
    tmp_path, action: str,
) -> None:
    source_workspace = tmp_path / "source"
    source_registry = source_workspace / "transport-fingerprints"
    source_registry.mkdir(parents=True)
    current = _attested_transport_record()
    (source_registry / "candidate.json").write_text(json.dumps(current), encoding="utf-8")
    approve_transport_baseline(source_workspace, current_id="candidate",
                               baseline_id="golden", expected_digest=current["digest_sha256"])
    baseline = load_transport_baseline(source_registry / "golden.baseline.json")

    foreign = tmp_path / "foreign"
    foreign_registry = foreign / "transport-fingerprints"
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
                approve_transport_baseline(junction, current_id="candidate",
                                           baseline_id="linked-approved",
                                           expected_digest=current["digest_sha256"])
            else:
                install_transport_baseline(junction, baseline)
        name = "linked-approved" if action == "approve" else "golden"
        assert not (foreign_registry / f"{name}.baseline.json").exists()
    finally:
        junction.rmdir()


@pytest.mark.parametrize("action", ["approve", "install"])
def test_transport_baseline_rejects_workspace_ancestor_relocation_after_readback(
    tmp_path, monkeypatch: pytest.MonkeyPatch, action: str,
) -> None:
    source_workspace = tmp_path / "source"
    source_registry = source_workspace / "transport-fingerprints"
    source_registry.mkdir(parents=True)
    current = _attested_transport_record()
    (source_registry / "candidate.json").write_text(json.dumps(current), encoding="utf-8")
    approve_transport_baseline(source_workspace, current_id="candidate",
                               baseline_id="golden", expected_digest=current["digest_sha256"])
    baseline = load_transport_baseline(source_registry / "golden.baseline.json")

    private = tmp_path / "private"
    workspace = private / "selected"
    registry = workspace / "transport-fingerprints"
    registry.mkdir(parents=True)
    (registry / "candidate.json").write_text(json.dumps(current), encoding="utf-8")
    retained = tmp_path / "retained"
    original_load = transport_module.load_transport_baseline
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

    monkeypatch.setattr(transport_module, "load_transport_baseline", move_after_read)
    try:
        message = ("source or publication changed" if action == "approve"
                   else "changed after publication")
        with pytest.raises(ContractError, match=message):
            if action == "approve":
                approve_transport_baseline(workspace, current_id="candidate",
                                           baseline_id="linked-approved",
                                           expected_digest=current["digest_sha256"])
            else:
                install_transport_baseline(workspace, baseline)
        assert swapped
        name = "linked-approved" if action == "approve" else "golden"
        assert (registry / f"{name}.baseline.json").exists()
    finally:
        if swapped:
            workspace.rename(retained / "selected")
            private.rmdir()
            retained.rename(private)


def test_transport_baseline_approval_rechecks_source_before_publication(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = tmp_path / "workspace"
    registry = workspace / "transport-fingerprints"
    registry.mkdir(parents=True)
    source = registry / "candidate.json"
    current = _attested_transport_record()
    source.write_text(json.dumps(current), encoding="utf-8")
    original_validate = transport_module.validate_transport_baseline

    def mutate_source(document):  # noqa: ANN001, ANN202
        changed = json.loads(json.dumps(current))
        changed["core_build"]["executable_sha256_16"] = "4" * 16
        source.write_text(json.dumps(changed), encoding="utf-8")
        return original_validate(document)

    monkeypatch.setattr(
        transport_module,
        "validate_transport_baseline",
        mutate_source,
    )
    with pytest.raises(ContractError, match="source changed"):
        approve_transport_baseline(
            workspace,
            current_id="candidate",
            baseline_id="golden-raced",
            expected_digest=current["digest_sha256"],
        )
    assert not (registry / "golden-raced.baseline.json").exists()


def test_transport_baseline_approval_rechecks_source_after_destination_readback(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = tmp_path / "workspace"
    registry = workspace / "transport-fingerprints"
    registry.mkdir(parents=True)
    source = registry / "candidate.json"
    current = _attested_transport_record()
    source.write_text(json.dumps(current), encoding="utf-8")
    original_load = transport_module.load_transport_baseline

    def mutate_source(path):  # noqa: ANN001, ANN202
        baseline = original_load(path)
        changed = json.loads(json.dumps(current))
        changed["core_build"]["executable_sha256_16"] = "4" * 16
        source.write_text(json.dumps(changed), encoding="utf-8")
        return baseline

    monkeypatch.setattr(transport_module, "load_transport_baseline", mutate_source)
    with pytest.raises(ContractError, match="source or publication changed"):
        approve_transport_baseline(
            workspace,
            current_id="candidate",
            baseline_id="golden-raced",
            expected_digest=current["digest_sha256"],
        )
    assert (registry / "golden-raced.baseline.json").is_file()


def test_transport_baseline_approval_is_exclusive_and_identifier_scoped(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    registry = workspace / "transport-fingerprints"
    registry.mkdir(parents=True)
    current = _attested_transport_record()
    (registry / "candidate.json").write_text(json.dumps(current), encoding="utf-8")
    existing = registry / "golden.baseline.json"
    existing.write_bytes(b"reviewed existing bytes")

    with pytest.raises(ContractError, match="already exists"):
        approve_transport_baseline(
            workspace,
            current_id="candidate",
            baseline_id="golden",
            expected_digest=current["digest_sha256"],
        )
    assert existing.read_bytes() == b"reviewed existing bytes"

    for current_id, baseline_id in (
        ("../candidate", "new"),
        ("candidate", "../new"),
        ("candidate", "candidate"),
    ):
        with pytest.raises(ContractError, match="invalid|must differ"):
            approve_transport_baseline(
                workspace,
                current_id=current_id,
                baseline_id=baseline_id,
                expected_digest=current["digest_sha256"],
            )


@pytest.mark.parametrize(
    "mutation",
    [
        lambda value: value.__setitem__("extra", True),
        lambda value: value.__setitem__("schema", "edited"),
        lambda value: value.__setitem__(
            "baseline_fingerprint_id", value["source_fingerprint_id"]
        ),
        lambda value: value.__setitem__("reviewed_digest_sha256", "f" * 64),
        lambda value: value.__setitem__("non_claim", "acceptance proven"),
    ],
)
def test_transport_baseline_wrapper_is_an_exact_verifiable_approval(
    mutation,
) -> None:
    fingerprint = _attested_transport_record()
    baseline = {
        "schema": "browser-core.transport-baseline/1",
        "source_fingerprint_id": "candidate",
        "baseline_fingerprint_id": "golden",
        "reviewed_digest_sha256": fingerprint["digest_sha256"],
        "fingerprint": fingerprint,
        "non_claim": (
            "Operator-approved local TLS ClientHello baseline only; not H2/H3 "
            "or remote edge acceptance"
        ),
    }
    assert validate_transport_baseline(baseline) == baseline
    edited = json.loads(json.dumps(baseline))
    mutation(edited)
    with pytest.raises(ContractError):
        validate_transport_baseline(edited)


def test_transport_baseline_install_publishes_a_validated_wrapper_exclusively(
    tmp_path: Path,
) -> None:
    fingerprint = _attested_transport_record()
    baseline = {
        "schema": "browser-core.transport-baseline/1",
        "source_fingerprint_id": "candidate",
        "baseline_fingerprint_id": "golden",
        "reviewed_digest_sha256": fingerprint["digest_sha256"],
        "fingerprint": fingerprint,
        "non_claim": (
            "Operator-approved local TLS ClientHello baseline only; not H2/H3 "
            "or remote edge acceptance"
        ),
    }
    workspace = tmp_path / "worker"

    assert install_transport_baseline(workspace, baseline) == baseline
    destination = workspace / "transport-fingerprints" / "golden.baseline.json"
    assert load_transport_baseline(destination) == baseline
    with pytest.raises(ContractError, match="already exists"):
        install_transport_baseline(workspace, baseline)
    assert load_transport_baseline(destination) == baseline


def test_transport_baseline_rejects_device_id_before_registry_creation(
    tmp_path: Path,
) -> None:
    fingerprint = _attested_transport_record()
    baseline = {
        "schema": transport_module.TRANSPORT_BASELINE_SCHEMA,
        "source_fingerprint_id": "candidate",
        "baseline_fingerprint_id": "CON",
        "reviewed_digest_sha256": fingerprint["digest_sha256"],
        "fingerprint": fingerprint,
        "non_claim": (
            "Operator-approved local TLS ClientHello baseline only; not H2/H3 "
            "or remote edge acceptance"
        ),
    }
    with pytest.raises(ContractError):
        install_transport_baseline(tmp_path, baseline)
    assert not (tmp_path / "transport-fingerprints").exists()


def test_transport_baseline_install_refuses_registry_replacement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fingerprint = _attested_transport_record()
    baseline = {
        "schema": "browser-core.transport-baseline/1",
        "source_fingerprint_id": "candidate",
        "baseline_fingerprint_id": "golden",
        "reviewed_digest_sha256": fingerprint["digest_sha256"],
        "fingerprint": fingerprint,
        "non_claim": (
            "Operator-approved local TLS ClientHello baseline only; not H2/H3 "
            "or remote edge acceptance"
        ),
    }
    workspace = tmp_path / "worker"
    registry = workspace / "transport-fingerprints"
    held = workspace / "held-registry"

    def replace(path: Path, document: dict, **_kwargs) -> None:
        path.parent.rename(held)
        path.parent.mkdir()
        path.write_text(json.dumps(document), encoding="utf-8")
        (path.parent / "competitor.bin").write_bytes(b"competitor")

    monkeypatch.setattr(transport_module, "publish_json_exclusive", replace)
    with pytest.raises(ContractError, match="changed after publication"):
        install_transport_baseline(workspace, baseline)
    assert held.is_dir()
    assert (registry / "competitor.bin").read_bytes() == b"competitor"


def test_the_parser_reads_the_fields_a_detector_reads() -> None:
    raw = _client_hello(
        ciphers=[0x1301, 0x1302, 0xC02B],
        extensions=[
            5,
            10,
            11,
            16,
            18,
            23,
            27,
            35,
            43,
            45,
            51,
            4832,
            17613,
            51764,
            65281,
        ],
        key_shares=(0x001D, 0x0017),
    )
    record = parse_client_hello(raw)
    assert record["ciphers"] == [0x1301, 0x1302, 0xC02B]
    assert record["extensions"] == [
        5,
        10,
        11,
        16,
        18,
        23,
        27,
        35,
        43,
        45,
        51,
        4832,
        17613,
        51764,
        65281,
    ]
    assert record["supported_groups"] == [0x001D, 0x0017]
    assert record["compression_methods"] == [0]
    assert record["ec_point_formats"] == [0]
    assert record["key_share_groups"] == [0x001D, 0x0017]
    assert record["certificate_compression_algorithms"] == [2]
    assert record["psk_key_exchange_modes"] == [1]
    assert record["alpn"] == ["h2", "http/1.1"]
    assert record["application_settings_protocols"] == ["h2"]
    assert record["server_padding_request"] == 16384
    assert record["trust_anchor_identifier_lengths"] == [20, 32]
    assert len(record["trust_anchor_set_sha256"]) == 64
    assert record["status_request_type"] == 1
    assert record["status_responder_id_lengths"] == []
    assert record["status_request_extensions_bytes"] == 0
    assert record["session_ticket_bytes"] == 0
    assert record["renegotiation_info_bytes"] == 0


def test_grease_is_stripped_from_every_list_it_appears_in() -> None:
    """Chrome inserts a random GREASE value on every connection, by design.

    A digest that kept them would differ from itself run to run and be useless as
    a drift detector.
    """
    grease = sorted(GREASE_VALUES)[0]
    raw = _client_hello(ciphers=[grease, 0x1301], extensions=[grease, 10, 16])
    record = parse_client_hello(raw)
    assert grease not in record["ciphers"]
    assert grease not in record["extensions"]
    assert record["grease_present"] is True


def test_grease_receipt_covers_non_cipher_vectors_and_grease_alpn() -> None:
    grease = sorted(GREASE_VALUES)[0]
    grease_alpn = bytes([0x0A, 0x0A])
    record = parse_client_hello(
        _client_hello(
            ciphers=[0x1301],
            extensions=[grease, 10, 16, 51],
            alpn=(grease_alpn, b"h2"),
            groups=(grease, 0x001D),
            key_shares=(grease, 0x001D),
        )
    )
    assert record["grease_present"] is True
    assert record["extensions"] == [10, 16, 51]
    assert record["supported_groups"] == [0x001D]
    assert record["key_share_groups"] == [0x001D]
    assert record["alpn"] == ["h2"]


def test_the_digest_ignores_extension_order_and_keeps_cipher_order() -> None:
    """The asymmetry is a measurement, not a preference.

    Chrome permutes its extension list on every connection -- anti-ossification,
    shipped in Chrome 110 -- so three consecutive captures from one binary
    produced three different digests until the extensions were sorted. Cipher
    suites are not permuted, so their order is signal and is kept. This is the
    same reason JA4 sorts extensions and JA3 stopped working on Chrome.
    """
    base = {
        "legacy_version": 0x0303,
        "ciphers": [0x1301, 0x1302],
        "extensions": [10, 11, 13, 16, 27, 43, 45, 51, 17613],
        "supported_groups": [0x001D],
        "compression_methods": [0],
        "ec_point_formats": [0],
        "key_share_groups": [0x001D],
        "certificate_compression_algorithms": [2],
        "psk_key_exchange_modes": [1],
        "signature_algorithms": [0x0403],
        "supported_versions": [0x0304],
        "alpn": ["h2"],
        "application_settings_protocols": ["h2"],
        "server_padding_request": None,
        "trust_anchor_identifier_lengths": [],
        "trust_anchor_set_sha256": None,
        "status_request_type": None,
        "status_responder_id_lengths": [],
        "status_request_extensions_bytes": None,
        "session_ticket_bytes": None,
        "renegotiation_info_bytes": None,
        "grease_present": False,
    }
    shuffled = dict(base, extensions=[17613, 51, 45, 43, 27, 13, 10, 16, 11])
    assert transport_digest(base) == transport_digest(shuffled)

    reordered_ciphers = dict(base, ciphers=[0x1302, 0x1301])
    assert transport_digest(base) != transport_digest(reordered_ciphers)


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("certificate_compression_algorithms", [1]),
        ("psk_key_exchange_modes", [0]),
        ("application_settings_protocols", ["http/1.1"]),
        ("server_padding_request", 1200),
        ("trust_anchor_identifier_lengths", [32, 21]),
        ("trust_anchor_set_sha256", "0" * 64),
    ],
)
def test_the_digest_keeps_structural_extension_body_order(
    field: str, replacement: int | str | list[int] | list[str]
) -> None:
    record = parse_client_hello(
        _client_hello(
            ciphers=[0x1301],
            extensions=[10, 16, 27, 43, 45, 4832, 17613, 51764],
        )
    )
    changed = dict(record, **{field: replacement})

    assert transport_digest(record) != transport_digest(changed)


def test_trust_anchor_identity_is_hashed_without_order_or_value_disclosure() -> None:
    first = parse_client_hello(
        _client_hello(
            ciphers=[0x1301],
            extensions=[51764],
            trust_anchors=(b"public-id-a", b"public-id-bb"),
        )
    )
    second = parse_client_hello(
        _client_hello(
            ciphers=[0x1301],
            extensions=[51764],
            trust_anchors=(b"public-id-bb", b"public-id-a"),
        )
    )

    assert first == second
    assert first["trust_anchor_identifier_lengths"] == [11, 12]
    assert "public-id" not in str(first)


def test_transport_document_rejects_unsorted_trust_anchor_lengths() -> None:
    record = parse_client_hello(
        _client_hello(
            ciphers=[0x1301],
            extensions=[51764],
            trust_anchors=(b"public-id-a", b"public-id-bb"),
        )
    )
    record["trust_anchor_identifier_lengths"].reverse()
    record["digest_sha256"] = transport_digest(record)

    with pytest.raises(ContractError, match="trust anchor list"):
        validate_transport_fingerprint(record)


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("status_responder_id_lengths", [4]),
        ("status_request_extensions_bytes", 1),
        ("session_ticket_bytes", 1),
        ("renegotiation_info_bytes", 1),
    ],
)
def test_digest_keeps_fresh_profile_and_status_shapes(
    field: str, replacement: int | list[int]
) -> None:
    record = parse_client_hello(
        _client_hello(ciphers=[0x1301], extensions=[5, 18, 23, 35, 65281])
    )

    assert transport_digest(record) != transport_digest(
        dict(record, **{field: replacement})
    )


def test_a_record_that_is_not_a_client_hello_is_refused() -> None:
    with pytest.raises(ContractError):
        parse_client_hello(b"\x17\x03\x03\x00\x05hello")
    with pytest.raises(ContractError):
        parse_client_hello(b"")


def test_every_truncated_prefix_fails_as_a_contract_error() -> None:
    raw = _client_hello(
        ciphers=[0x1301, 0x1302],
        extensions=[10, 16, 43],
    )

    for length in range(len(raw)):
        with pytest.raises(ContractError):
            parse_client_hello(raw[:length])

    with pytest.raises(ContractError, match="record length"):
        parse_client_hello(raw + b"extra")


def test_parser_rejects_duplicate_extensions_and_bad_handshake_length() -> None:
    duplicate = _client_hello(
        ciphers=[0x1301],
        extensions=[10, 10],
    )
    with pytest.raises(ContractError, match="repeats an extension"):
        parse_client_hello(duplicate)

    malformed = bytearray(_client_hello(ciphers=[0x1301], extensions=[10, 16]))
    malformed[8] -= 1
    with pytest.raises(ContractError, match="handshake length"):
        parse_client_hello(bytes(malformed))


@pytest.mark.parametrize(
    "kwargs",
    [
        {"ciphers": [0x1301, 0x1301], "extensions": [10]},
        {"ciphers": [0x1301], "extensions": [10], "groups": (0x001D, 0x001D)},
        {
            "ciphers": [0x1301],
            "extensions": [11],
            "point_formats": (0, 0),
        },
        {"ciphers": [0x1301], "extensions": [16], "alpn": (b"h2", b"h2")},
        {
            "ciphers": [0x1301],
            "extensions": [51],
            "key_shares": (0x001D, 0x001D),
        },
        {
            "ciphers": [0x1301],
            "extensions": [27],
            "certificate_compression": (2, 2),
        },
        {"ciphers": [0x1301], "extensions": [45], "psk_modes": (1, 1)},
        {
            "ciphers": [0x1301],
            "extensions": [16, 17613],
            "application_settings": (b"h2", b"h2"),
        },
        {"ciphers": [0x1301], "extensions": [], "compression": (0, 0)},
    ],
)
def test_parser_rejects_duplicate_wire_vectors(kwargs) -> None:
    with pytest.raises(ContractError, match="repeats"):
        parse_client_hello(_client_hello(**kwargs))


@pytest.mark.parametrize(
    "kwargs",
    [
        {"ciphers": [0x1301], "extensions": [], "compression": (1,)},
        {"ciphers": [0x1301], "extensions": [10], "groups": ()},
        {"ciphers": [0x1301], "extensions": [11], "point_formats": ()},
        {"ciphers": [0x1301], "extensions": [11], "point_formats": (1,)},
        {"ciphers": [0x1301], "extensions": [16], "alpn": ()},
        {
            "ciphers": [0x1301],
            "extensions": [27],
            "certificate_compression": (),
        },
        {"ciphers": [0x1301], "extensions": [45], "psk_modes": ()},
        {
            "ciphers": [0x1301],
            "extensions": [16, 17613],
            "application_settings": (),
        },
        {
            "ciphers": [0x1301],
            "extensions": [16, 17613],
            "application_settings": (b"h3",),
        },
        {"ciphers": [0x1301], "extensions": [16, 17513, 17613]},
        {
            "ciphers": [0x1301],
            "extensions": [51764],
            "trust_anchors": (b"",),
        },
        {
            "ciphers": [0x1301],
            "extensions": [5],
            "status_responders": (b"",),
        },
        {"ciphers": [0x1301], "extensions": [18], "sct_payload": b"x"},
        {"ciphers": [0x1301], "extensions": [23], "ems_payload": b"x"},
        {"ciphers": [0x1301], "extensions": [51], "key_shares": (0x0017,)},
    ],
)
def test_parser_rejects_incoherent_wire_vectors(kwargs) -> None:
    with pytest.raises(ContractError):
        parse_client_hello(_client_hello(**kwargs))


def test_parser_strips_binary_grease_alpn_before_ascii_validation() -> None:
    raw = _client_hello(
        ciphers=[0x1301],
        extensions=[16],
        alpn=(b"\xaa\xaa", b"h2"),
    )

    assert parse_client_hello(raw)["alpn"] == ["h2"]


def test_parser_requires_the_expected_capture_server_name_without_echo() -> None:
    raw = _client_hello(
        ciphers=[0x1301],
        extensions=[0, 10, 16],
        server_name=b"bc-11111111111111111111111111111111.invalid",
    )

    parse_client_hello(
        raw, expected_server_name="bc-11111111111111111111111111111111.invalid"
    )
    private = "private-capture-target.invalid"
    with pytest.raises(ContractError) as failure:
        parse_client_hello(raw, expected_server_name=private)
    assert (
        str(failure.value) == "client hello server name does not match capture target"
    )
    assert private not in str(failure.value)


@pytest.mark.parametrize(
    "server_name",
    [b"", b"bad_name.invalid", b"-bad.invalid", b"bad-.invalid", b"\xff.invalid"],
)
def test_parser_rejects_invalid_server_names(server_name: bytes) -> None:
    with pytest.raises(ContractError, match="server name"):
        parse_client_hello(
            _client_hello(
                ciphers=[0x1301],
                extensions=[0, 10, 16],
                server_name=server_name,
            )
        )


class _ChunkedConnection:
    def __init__(self, body: bytes, chunk: int) -> None:
        self._body = body
        self._chunk = chunk

    def recv(self, size: int) -> bytes:
        amount = min(size, self._chunk, len(self._body))
        result = self._body[:amount]
        self._body = self._body[amount:]
        return result

    def settimeout(self, _timeout: float) -> None:
        pass

    def close(self) -> None:
        pass


class _Listener:
    def __init__(self, raw: bytes) -> None:
        self.connection = _ChunkedConnection(raw, 3)
        self.closed = False

    def setsockopt(self, *_args: object) -> None:
        pass

    def bind(self, _address: object) -> None:
        pass

    def listen(self, _count: int) -> None:
        pass

    def settimeout(self, _timeout: float) -> None:
        pass

    def getsockname(self) -> tuple[str, int]:
        return ("127.0.0.1", 43123)

    def accept(self):  # type: ignore[no-untyped-def]
        return self.connection, ("127.0.0.1", 50000)

    def close(self) -> None:
        self.closed = True


class _Process:
    def __init__(self) -> None:
        self.terminated = False
        self.waits: list[float] = []

    def terminate(self) -> None:
        self.terminated = True

    def wait(self, timeout: float) -> int:
        self.waits.append(timeout)
        return 0

    def kill(self) -> None:
        raise AssertionError("cooperative fake process should not be killed")


def test_transport_process_stop_escalates_after_wait_oserror() -> None:
    class Process:
        def __init__(self) -> None:
            self.waits: list[float] = []
            self.killed = False

        def terminate(self) -> None:
            raise OSError("private terminate diagnostic")

        def wait(self, timeout: float) -> int:
            self.waits.append(timeout)
            if len(self.waits) == 1:
                raise OSError("private wait diagnostic")
            return -9

        def kill(self) -> None:
            self.killed = True

    process = Process()
    transport_module._stop_process(process)  # type: ignore[arg-type]

    assert process.killed is True
    assert process.waits == [
        transport_module.TRANSPORT_PROCESS_STOP_TIMEOUT_SECONDS,
        transport_module.TRANSPORT_PROCESS_STOP_TIMEOUT_SECONDS,
    ]


def test_transport_process_stop_rejects_unreapable_child_without_diagnostics() -> None:
    class Process:
        def __init__(self) -> None:
            self.waits = 0
            self.killed = False

        def terminate(self) -> None:
            return None

        def wait(self, timeout: float) -> int:
            self.waits += 1
            raise transport_module.subprocess.TimeoutExpired(
                "private browser command", timeout
            )

        def kill(self) -> None:
            self.killed = True

    process = Process()
    with pytest.raises(ContractError) as captured:
        transport_module._stop_process(process)  # type: ignore[arg-type]

    assert str(captured.value) == "transport browser did not stop"
    assert "private browser command" not in str(captured.value)
    assert process.killed is True
    assert process.waits == 2


def test_record_reader_reassembles_fragmented_socket_reads() -> None:
    raw = _client_hello(ciphers=[0x1301], extensions=[10, 16])

    assert _read_tls_record(_ChunkedConnection(raw, 1)) == raw  # type: ignore[arg-type]


def test_record_reader_enforces_one_absolute_deadline() -> None:
    class Connection:
        def __init__(self) -> None:
            self.reads = 0
            self.timeouts: list[float] = []

        def settimeout(self, value: float) -> None:
            self.timeouts.append(value)

        def recv(self, _size: int) -> bytes:
            self.reads += 1
            return b"\x16"

    moments = iter((20.25, 21.0))
    connection = Connection()
    with pytest.raises(ContractError, match="deadline expired"):
        _read_tls_record(
            connection,  # type: ignore[arg-type]
            deadline=21.0,
            clock=lambda: next(moments),
        )
    assert connection.reads == 1
    assert connection.timeouts == [0.75]


def test_record_reader_rejects_a_complete_record_arriving_after_deadline() -> None:
    now = [0.0]

    class Connection:
        def __init__(self) -> None:
            self.reads = 0

        def settimeout(self, _value: float) -> None:
            pass

        def recv(self, _size: int) -> bytes:
            self.reads += 1
            now[0] = 2.0
            return b"\x16\x03\x01\x00\x00"

    connection = Connection()
    with pytest.raises(ContractError, match="deadline expired"):
        _read_tls_record(
            connection,  # type: ignore[arg-type]
            deadline=1.0,
            clock=lambda: now[0],
        )
    assert connection.reads == 1


def test_record_reader_rejects_declared_overflow_and_early_close() -> None:
    oversized_header = b"\x16\x03\x01\x40\x01"
    with pytest.raises(ContractError, match="exceeds capture limit"):
        _read_tls_record(_ChunkedConnection(oversized_header, 5))  # type: ignore[arg-type]

    with pytest.raises(ContractError, match="record was complete"):
        _read_tls_record(_ChunkedConnection(b"\x16\x03\x01\x00\x02x", 2))  # type: ignore[arg-type]


@pytest.mark.parametrize("chunk", [bytearray(b"private"), "private"])
def test_record_reader_requires_exact_byte_chunks(chunk) -> None:
    class InvalidConnection:
        def recv(self, _size):
            return chunk

    with pytest.raises(ContractError, match="invalid byte chunk") as failure:
        _read_tls_record(InvalidConnection())  # type: ignore[arg-type]
    assert "private" not in str(failure.value)


def test_record_reader_rejects_adapter_chunks_larger_than_requested() -> None:
    class OversizedConnection:
        def recv(self, size):
            return b"x" * (size + 1)

    with pytest.raises(ContractError, match="invalid byte chunk"):
        _read_tls_record(OversizedConnection())  # type: ignore[arg-type]


@pytest.mark.parametrize('replace_profile', [False, True])
def test_capture_uses_exact_record_discards_console_and_removes_profile(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    replace_profile: bool,
) -> None:
    executable = tmp_path / "browser.exe"
    executable.write_bytes(b"browser")
    nonce = "1" * 32
    hostname = f"bc-{nonce}.invalid"
    raw = _client_hello(
        ciphers=[0x1301],
        extensions=[0, 10, 16, 43],
        server_name=hostname.encode("ascii"),
    )
    listener = _Listener(raw)
    process = _Process()
    invocation: dict[str, object] = {}
    parked = tmp_path / 'original-transport-profile'
    sentinel: Path | None = None
    real_temporary_directory = tempfile.TemporaryDirectory
    monkeypatch.setattr(
        transport_module.tempfile, 'TemporaryDirectory',
        lambda *, prefix: real_temporary_directory(prefix=prefix, dir=tmp_path),
    )

    monkeypatch.setattr(
        transport_module.socket,
        "socket",
        lambda *_args, **_kwargs: listener,
    )

    def launch(command, **kwargs):  # type: ignore[no-untyped-def]
        nonlocal sentinel
        invocation.update({"command": command, **kwargs})
        if replace_profile:
            argument = next(item for item in command if item.startswith('--user-data-dir='))
            root = Path(argument.split('=', 1)[1])
            assert root.parent == tmp_path
            root.rename(parked)
            root.mkdir()
            sentinel = root / 'replacement.txt'
            sentinel.write_text('replacement', encoding='utf-8')
        return process

    monkeypatch.setattr(transport_module.subprocess, "Popen", launch)
    monkeypatch.setattr(transport_module.secrets, "token_hex", lambda _size: nonce)

    if replace_profile:
        try:
            with pytest.raises(ContractError, match='transport capture profile directory changed before cleanup'):
                capture_client_hello(executable, timeout_seconds=1.0)
            assert sentinel is not None
            assert sentinel.read_text(encoding='utf-8') == 'replacement'
            assert process.terminated is True
            assert listener.closed is True
        finally:
            if sentinel is not None and sentinel.exists():
                sentinel.unlink()
                sentinel.parent.rmdir()
            if parked.exists():
                parked.rmdir()
        return

    result = capture_client_hello(executable, timeout_seconds=1.0)

    assert result["ciphers"] == [0x1301]
    assert len(result["digest_sha256"]) == 64
    assert listener.closed is True
    assert process.terminated is True
    assert process.waits == [10]
    assert invocation["stdin"] is transport_module.subprocess.DEVNULL
    assert invocation["stdout"] is transport_module.subprocess.DEVNULL
    assert invocation["stderr"] is transport_module.subprocess.DEVNULL
    profile_argument = next(
        item
        for item in invocation["command"]  # type: ignore[union-attr]
        if item.startswith("--user-data-dir=")
    )
    assert not Path(profile_argument.split("=", 1)[1]).exists()
    assert (
        f"--host-resolver-rules=MAP {hostname} 127.0.0.1, MAP * ^NOTFOUND"
        in invocation["command"]
    )
    assert f"https://{hostname}:43123/" in invocation["command"]


def test_capture_still_stops_browser_when_listener_close_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    executable = tmp_path / "browser.exe"
    executable.write_bytes(b"browser")

    class Listener(_Listener):
        def close(self) -> None:
            self.closed = True
            raise OSError("private listener diagnostic")

    listener = Listener(_client_hello(ciphers=[0x1301], extensions=[43]))
    process = _Process()
    monkeypatch.setattr(
        transport_module.socket,
        "socket",
        lambda *_args, **_kwargs: listener,
    )
    monkeypatch.setattr(
        transport_module.subprocess,
        "Popen",
        lambda *_args, **_kwargs: process,
    )

    with pytest.raises(ContractError) as captured:
        capture_client_hello(executable, timeout_seconds=1.0)

    assert str(captured.value) == "transport capture cleanup failed (listener-close)"
    assert "private listener diagnostic" not in str(captured.value)
    assert listener.closed is True
    assert process.terminated is True
    assert process.waits == [transport_module.TRANSPORT_PROCESS_STOP_TIMEOUT_SECONDS]


def test_capture_thread_construction_failure_closes_listener_type_only(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    executable = tmp_path / "browser.exe"
    executable.write_bytes(b"browser")
    listener = _Listener(_client_hello(ciphers=[0x1301], extensions=[43]))
    private = "private-worker-constructor"
    monkeypatch.setattr(
        transport_module.socket,
        "socket",
        lambda *_args, **_kwargs: listener,
    )
    monkeypatch.setattr(
        transport_module.threading,
        "Thread",
        lambda **_kwargs: (_ for _ in ()).throw(RuntimeError(private)),
    )

    with pytest.raises(ContractError) as captured:
        capture_client_hello(executable, timeout_seconds=1.0)

    assert str(captured.value) == "transport capture setup failed (RuntimeError)"
    assert private not in str(captured.value)
    assert listener.closed is True


def test_capture_thread_start_failure_closes_listener_type_only(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    executable = tmp_path / "browser.exe"
    executable.write_bytes(b"browser")
    listener = _Listener(_client_hello(ciphers=[0x1301], extensions=[43]))
    private = "private-worker-start"

    class Worker:
        def __init__(self, **_kwargs) -> None:  # noqa: ANN003
            pass

        def start(self) -> None:
            raise RuntimeError(private)

    monkeypatch.setattr(
        transport_module.socket,
        "socket",
        lambda *_args, **_kwargs: listener,
    )
    monkeypatch.setattr(transport_module.threading, "Thread", Worker)

    with pytest.raises(ContractError) as captured:
        capture_client_hello(executable, timeout_seconds=1.0)

    assert str(captured.value) == (
        "transport capture worker could not start (RuntimeError)"
    )
    assert private not in str(captured.value)
    assert listener.closed is True


def test_capture_thread_late_start_failure_joins_worker(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    executable = tmp_path / "browser.exe"
    executable.write_bytes(b"browser")
    listener = _Listener(_client_hello(ciphers=[0x1301], extensions=[43]))
    real_thread = threading.Thread
    workers: list[object] = []

    class Worker:
        def __init__(self, **kwargs) -> None:  # noqa: ANN003
            self.thread = real_thread(**kwargs)
            self.joined = False
            workers.append(self)

        @property
        def ident(self) -> int | None:
            return self.thread.ident

        def start(self) -> None:
            self.thread.start()
            raise RuntimeError("private late start")

        def join(self, timeout: float) -> None:
            self.joined = True
            self.thread.join(timeout)

        def is_alive(self) -> bool:
            return self.thread.is_alive()

    monkeypatch.setattr(
        transport_module.socket,
        "socket",
        lambda *_args, **_kwargs: listener,
    )
    monkeypatch.setattr(transport_module.threading, "Thread", Worker)

    with pytest.raises(ContractError, match="worker could not start"):
        capture_client_hello(executable, timeout_seconds=1.0)

    assert listener.closed is True
    assert workers[0].joined is True
    assert workers[0].is_alive() is False


def test_capture_rejects_invalid_listener_address_before_browser_start(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    executable = tmp_path / "browser.exe"
    executable.write_bytes(b"browser")

    class Listener(_Listener):
        def getsockname(self):  # noqa: ANN201
            return ("127.0.0.1", True)

    listener = Listener(_client_hello(ciphers=[0x1301], extensions=[43]))
    monkeypatch.setattr(
        transport_module.socket,
        "socket",
        lambda *_args, **_kwargs: listener,
    )
    monkeypatch.setattr(
        transport_module.subprocess,
        "Popen",
        lambda *_args, **_kwargs: pytest.fail("invalid address reached browser start"),
    )

    with pytest.raises(ContractError, match="listener address is invalid"):
        capture_client_hello(executable, timeout_seconds=1.0)

    assert listener.closed is True


def test_capture_cleanup_reports_listener_browser_and_worker_failures(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    executable = tmp_path / "browser.exe"
    executable.write_bytes(b"browser")
    events: list[str] = []

    class Listener(_Listener):
        def close(self) -> None:
            events.append("listener-close")
            raise OSError("private listener")

    class Worker:
        def __init__(self, **_kwargs) -> None:  # noqa: ANN003
            pass

        def start(self) -> None:
            events.append("worker-start")

        def join(self, timeout: float) -> None:
            events.append(f"worker-join:{timeout}")
            raise RuntimeError("private worker")

        def is_alive(self) -> bool:
            return True

    listener = Listener(_client_hello(ciphers=[0x1301], extensions=[43]))
    process = _Process()
    monkeypatch.setattr(
        transport_module.socket,
        "socket",
        lambda *_args, **_kwargs: listener,
    )
    monkeypatch.setattr(transport_module.threading, "Thread", Worker)
    monkeypatch.setattr(
        transport_module.subprocess,
        "Popen",
        lambda *_args, **_kwargs: process,
    )

    def fail_stop(_process) -> None:  # noqa: ANN001
        events.append("browser-stop")
        raise ContractError("private browser")

    monkeypatch.setattr(transport_module, "_stop_process", fail_stop)

    with pytest.raises(ContractError) as captured:
        capture_client_hello(executable, timeout_seconds=1.0)

    assert str(captured.value) == (
        "transport capture cleanup failed " "(listener-close,browser-stop,worker-join)"
    )
    assert "private" not in str(captured.value)
    assert events[0] == "worker-start"
    initial_join_timeout = float(events[1].split(":", 1)[1])
    assert 0 < initial_join_timeout <= 1.0
    assert events[2:] == [
        "listener-close",
        "browser-stop",
        "worker-join:5.0",
    ]


def test_capture_connection_close_failure_does_not_escape_daemon(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    executable = tmp_path / "browser.exe"
    executable.write_bytes(b"browser")
    raw = _client_hello(ciphers=[0x1301], extensions=[10, 16])

    class Connection(_ChunkedConnection):
        def close(self) -> None:
            raise OSError("private connection")

    listener = _Listener(raw)
    listener.connection = Connection(raw, 3)
    process = _Process()
    thread_errors: list[object] = []
    monkeypatch.setattr(
        transport_module.socket,
        "socket",
        lambda *_args, **_kwargs: listener,
    )
    monkeypatch.setattr(
        transport_module.subprocess,
        "Popen",
        lambda *_args, **_kwargs: process,
    )
    monkeypatch.setattr(
        transport_module.threading,
        "excepthook",
        lambda args: thread_errors.append(args),
    )

    with pytest.raises(ContractError) as captured:
        capture_client_hello(executable, timeout_seconds=1.0)

    assert str(captured.value) == (
        "transport capture cleanup failed (connection-close)"
    )
    assert "private" not in str(captured.value)
    assert thread_errors == []
    assert process.terminated is True


@pytest.mark.parametrize(
    "timeout", [0, True, float("nan"), float("inf"), 121, 10**400]
)
def test_capture_rejects_invalid_timeout_before_filesystem_or_socket_contact(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    timeout,
) -> None:
    contacted = False

    def socket_contact(*_args: object, **_kwargs: object) -> None:
        nonlocal contacted
        contacted = True
        raise AssertionError("invalid timeout reached socket creation")

    monkeypatch.setattr(transport_module.socket, "socket", socket_contact)

    with pytest.raises(ContractError, match="timeout"):
        capture_client_hello(tmp_path / "missing", timeout_seconds=timeout)

    assert contacted is False


def test_capture_requires_an_exact_path_before_contact(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    contacted = False

    def socket_contact(*_args: object, **_kwargs: object) -> None:
        nonlocal contacted
        contacted = True

    monkeypatch.setattr(transport_module.socket, "socket", socket_contact)

    with pytest.raises(ContractError, match="must be a Path"):
        capture_client_hello("browser.exe")  # type: ignore[arg-type]

    assert contacted is False


def test_capture_rejects_hard_linked_or_empty_executable_before_socket(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        transport_module.socket,
        "socket",
        lambda *_args, **_kwargs: pytest.fail("invalid executable reached socket"),
    )
    executable = tmp_path / "browser.exe"
    executable.write_bytes(b"browser")
    (tmp_path / "browser-alias.exe").hardlink_to(executable)
    with pytest.raises(ContractError, match="hard links"):
        capture_client_hello(executable)

    executable.unlink()
    executable.write_bytes(b"")
    with pytest.raises(ContractError, match="empty"):
        capture_client_hello(executable)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("legacy_version", True),
        ("ciphers", [True]),
        ("extensions", [65536]),
        ("supported_groups", [0x001D, 0x001D]),
        ("alpn", ["h2\nprivate"]),
        ("alpn", ["h2", "h2"]),
        ("server_padding_request", True),
        ("trust_anchor_identifier_lengths", [0]),
        ("status_request_type", True),
        ("status_responder_id_lengths", [0]),
        ("session_ticket_bytes", True),
    ],
)
def test_transport_digest_rejects_malformed_values(field: str, value) -> None:
    record = {
        "legacy_version": 0x0303,
        "ciphers": [0x1301],
        "extensions": [10, 11, 13, 16, 27, 43, 45, 51, 17613],
        "supported_groups": [0x001D],
        "compression_methods": [0],
        "ec_point_formats": [0],
        "key_share_groups": [0x001D],
        "certificate_compression_algorithms": [2],
        "psk_key_exchange_modes": [1],
        "signature_algorithms": [0x0403],
        "supported_versions": [0x0304],
        "alpn": ["h2"],
        "application_settings_protocols": ["h2"],
        "server_padding_request": None,
        "trust_anchor_identifier_lengths": [],
        "trust_anchor_set_sha256": None,
        "status_request_type": None,
        "status_responder_id_lengths": [],
        "status_request_extensions_bytes": None,
        "session_ticket_bytes": None,
        "renegotiation_info_bytes": None,
        "grease_present": False,
    }
    record[field] = value

    with pytest.raises(ContractError, match="transport fingerprint"):
        transport_digest(record)


def test_transport_digest_binds_the_normalized_grease_receipt() -> None:
    grease = min(GREASE_VALUES)
    without_grease = parse_client_hello(
        _client_hello(ciphers=[0x1301], extensions=[10, 16])
    )
    with_grease = parse_client_hello(
        _client_hello(ciphers=[grease, 0x1301], extensions=[grease, 10, 16])
    )

    assert {
        key: value for key, value in without_grease.items() if key != "grease_present"
    } == {key: value for key, value in with_grease.items() if key != "grease_present"}
    assert transport_digest(without_grease) != transport_digest(with_grease)

    receipt = dict(with_grease)
    receipt["digest_sha256"] = transport_digest(receipt)
    receipt["grease_present"] = False
    with pytest.raises(ContractError, match="digest"):
        validate_transport_fingerprint(receipt)


def test_transport_digest_rejects_missing_required_field_cleanly() -> None:
    record = parse_client_hello(
        _client_hello(ciphers=[0x1301], extensions=[10, 16, 43])
    )
    del record["status_request_type"]

    with pytest.raises(ContractError, match="transport fingerprint fields"):
        transport_digest(record)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("ciphers", [min(GREASE_VALUES), 0x1301]),
        ("extensions", [min(GREASE_VALUES), 10, 16, 43]),
        ("supported_groups", [min(GREASE_VALUES), 0x001D]),
        ("key_share_groups", [min(GREASE_VALUES), 0x001D]),
        ("certificate_compression_algorithms", [min(GREASE_VALUES), 2]),
        ("signature_algorithms", [min(GREASE_VALUES)]),
        ("supported_versions", [min(GREASE_VALUES), 0x0304]),
        ("alpn", ["**", "h2"]),
    ],
)
def test_transport_digest_rejects_reinserted_grease(field: str, value) -> None:
    record = parse_client_hello(
        _client_hello(ciphers=[0x1301], extensions=[10, 16, 43])
    )
    record[field] = value

    with pytest.raises(ContractError, match="retains GREASE"):
        transport_digest(record)


def test_attested_capture_projects_and_revalidates_the_build(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    attestation = {
        "chromium_revision": "1" * 40,
        "executable_sha256": "2" * 64,
        "runtime_bundle_sha256": "3" * 64,
    }
    record = _transport_record()
    loads = 0

    def load(*_args):  # type: ignore[no-untyped-def]
        nonlocal loads
        loads += 1
        return attestation

    monkeypatch.setattr(transport_module, "load_build_attestation", load)
    monkeypatch.setattr(
        transport_module,
        "capture_client_hello",
        lambda *_args, **_kwargs: dict(record),
    )
    result = capture_attested_client_hello(tmp_path, tmp_path / "chrome.exe")
    assert loads == 2
    assert result["core_build"] == {
        "chromium_revision": "1" * 40,
        "executable_sha256_16": "2" * 16,
        "runtime_bundle_sha256_16": "3" * 16,
    }
    assert validate_transport_fingerprint(result, require_build=True) == result


def test_attested_capture_rejects_sparse_or_tampered_lower_receipts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    attestation = {
        "chromium_revision": "1" * 40,
        "executable_sha256": "2" * 64,
        "runtime_bundle_sha256": "3" * 64,
    }
    monkeypatch.setattr(
        transport_module,
        "load_build_attestation",
        lambda *_args: attestation,
    )
    for record in (
        {"schema": transport_module.TRANSPORT_FINGERPRINT_SCHEMA},
        {**_transport_record(), "digest_sha256": "4" * 64},
        {**_transport_record(), "private": "private-transport-marker"},
    ):
        monkeypatch.setattr(
            transport_module,
            "capture_client_hello",
            lambda *_args, _record=record, **_kwargs: dict(_record),
        )
        with pytest.raises(ContractError) as failure:
            capture_attested_client_hello(tmp_path, tmp_path / "chrome.exe")
        assert "private-transport-marker" not in str(failure.value)


def test_attested_capture_rejects_non_path_authority_before_loading(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        transport_module,
        "load_build_attestation",
        lambda *_args: pytest.fail("invalid paths reached attestation"),
    )
    with pytest.raises(ContractError, match="must be Paths"):
        capture_attested_client_hello("root", Path("chrome.exe"))  # type: ignore[arg-type]


def _core_executable() -> Path | None:
    workspace = os.environ.get("BROWSER_CORE_WORKSPACE")
    if not workspace:
        return None
    candidate = (
        Path(workspace) / "chromium" / "src" / "out" / "BrowserCore" / "chrome.exe"
    )
    return candidate if candidate.exists() else None


@pytest.mark.skipif(_core_executable() is None, reason="needs the attested build")
def test_the_attested_build_produces_a_stable_fingerprint() -> None:
    """Two captures, one binary, one digest.

    Stability is the property the gate depends on: a digest that moved on its own
    could not tell a rebuild that changed the network stack from ordinary noise.
    """
    core = _core_executable()
    assert core is not None
    first = capture_attested_client_hello(Path(__file__).resolve().parents[1], core)
    second = capture_attested_client_hello(Path(__file__).resolve().parents[1], core)
    assert first["digest_sha256"] == second["digest_sha256"]
    assert first["alpn"] == ["h2", "http/1.1"]
    assert first["ciphers"] == second["ciphers"]
    assert sorted(first["extensions"]) == sorted(second["extensions"])
    assert first["compression_methods"] == second["compression_methods"] == [0]
    assert first["ec_point_formats"] == second["ec_point_formats"] == [0]
    assert first["key_share_groups"] == second["key_share_groups"]
    assert first["key_share_groups"]
    assert set(first["key_share_groups"]) <= set(first["supported_groups"])
    assert (
        first["certificate_compression_algorithms"]
        == second["certificate_compression_algorithms"]
        == [2]
    )
    assert first["psk_key_exchange_modes"] == second["psk_key_exchange_modes"] == [1]
    assert (
        first["application_settings_protocols"]
        == second["application_settings_protocols"]
        == ["h2"]
    )
    assert first["server_padding_request"] == second["server_padding_request"] == 0
    assert (
        first["trust_anchor_identifier_lengths"]
        == second["trust_anchor_identifier_lengths"]
    )
    assert first["trust_anchor_identifier_lengths"] == sorted(
        first["trust_anchor_identifier_lengths"]
    )
    assert first["trust_anchor_set_sha256"] == second["trust_anchor_set_sha256"]
    assert first["status_request_type"] == second["status_request_type"] == 1
    assert (
        first["status_responder_id_lengths"]
        == second["status_responder_id_lengths"]
        == []
    )
    assert (
        first["status_request_extensions_bytes"]
        == second["status_request_extensions_bytes"]
        == 0
    )
    assert first["session_ticket_bytes"] == second["session_ticket_bytes"] == 0
    assert first["renegotiation_info_bytes"] == second["renegotiation_info_bytes"] == 0
    # The permutation is real and worth asserting: if upstream ever stopped
    # shuffling, sorting would become unnecessary and this test would say so.
    assert first["grease_present"] is True
    assert first["core_build"] == second["core_build"]
