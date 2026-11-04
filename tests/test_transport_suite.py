from __future__ import annotations

import json

import pytest

from browser_core.contracts import ContractError
from browser_core.http2_fingerprint import http2_fingerprint_digest
from browser_core.http2_headers import (
    http2_capture_evidence_digest,
    http2_header_order_digest,
)
from browser_core.transport_fingerprint import transport_digest
from browser_core.transport_suite import (
    compare_transport_evidence_suite,
    compare_transport_suite,
)


def _build(seed: str) -> dict[str, str]:
    return {
        "chromium_revision": seed * 40,
        "executable_sha256_16": seed * 16,
        "runtime_bundle_sha256_16": seed * 16,
    }


def _transport(build: dict[str, str]) -> dict:
    record = {
        "schema": "browser-core.transport-fingerprint/1",
        "legacy_version": 0x0303,
        "ciphers": [0x1301],
        "extensions": [],
        "supported_groups": [],
        "compression_methods": [0],
        "ec_point_formats": [],
        "key_share_groups": [],
        "certificate_compression_algorithms": [],
        "psk_key_exchange_modes": [],
        "signature_algorithms": [],
        "supported_versions": [],
        "alpn": [],
        "application_settings_protocols": [],
        "server_padding_request": None,
        "trust_anchor_identifier_lengths": [],
        "trust_anchor_set_sha256": None,
        "status_request_type": None,
        "status_responder_id_lengths": [],
        "status_request_extensions_bytes": None,
        "session_ticket_bytes": None,
        "renegotiation_info_bytes": None,
        "grease_present": False,
        "core_build": dict(build),
    }
    record["digest_sha256"] = transport_digest(record)
    return record


def _h2(build: dict[str, str]) -> dict:
    record = {
        "schema": "browser-core.http2-fingerprint/1",
        "settings": [{"id": 1, "value": 65_536}],
        "connection_window_updates": [15_663_105],
        "pre_headers_frame_types": [4, 8],
        "headers_started": True,
        "core_build": dict(build),
    }
    record["digest_sha256"] = http2_fingerprint_digest(record)
    return record


def _baseline(kind: str, fingerprint: dict) -> dict:
    if kind == "transport":
        return {
            "schema": "browser-core.transport-baseline/1",
            "source_fingerprint_id": "transport-source",
            "baseline_fingerprint_id": "transport-golden",
            "reviewed_digest_sha256": fingerprint["digest_sha256"],
            "fingerprint": fingerprint,
            "non_claim": (
                "Operator-approved local TLS ClientHello baseline only; not H2/H3 "
                "or remote edge acceptance"
            ),
        }
    return {
        "schema": "browser-core.http2-baseline/1",
        "source_fingerprint_id": "h2-source",
        "baseline_fingerprint_id": "h2-golden",
        "reviewed_digest_sha256": fingerprint["digest_sha256"],
        "fingerprint": fingerprint,
        "non_claim": (
            "Operator-approved local HTTP/2 initial-flight baseline only; not "
            "HTTP/3 or remote edge acceptance"
        ),
    }


def _h2_evidence(build: dict[str, str]) -> dict:
    order = {
        "schema": "browser-core.http2-header-order/1",
        "header_names": [":method", ":authority", ":scheme", ":path", "accept"],
        "pseudo_header_order": [":method", ":authority", ":scheme", ":path"],
        "non_claim": (
            "First local HTTP/2 request header-name order only; values are discarded "
            "after bounded decode and no HTTP/3 or edge acceptance is proven"
        ),
        "core_build": dict(build),
    }
    order["digest_sha256"] = http2_header_order_digest(order)
    evidence = {
        "schema": "browser-core.http2-capture-evidence/1",
        "fingerprint": _h2(build),
        "header_order": order,
        "same_connection": True,
        "non_claim": (
            "One local negotiated HTTP/2 connection through first complete request "
            "headers; decoded values are discarded and no HTTP/3 or edge acceptance "
            "is proven"
        ),
    }
    evidence["digest_sha256"] = http2_capture_evidence_digest(evidence)
    return evidence


def _h2_evidence_baseline(evidence: dict) -> dict:
    return {
        "schema": "browser-core.http2-evidence-baseline/1",
        "source_evidence_id": "h2-source",
        "baseline_evidence_id": "h2-golden",
        "reviewed_digest_sha256": evidence["digest_sha256"],
        "evidence": evidence,
        "non_claim": (
            "Operator-approved same-connection local HTTP/2 settings, frame, and "
            "header-name order baseline only; not HTTP/3 or remote edge acceptance"
        ),
    }


def test_transport_suite_passes_only_one_coherent_two_protocol_population() -> None:
    build = _build("1")
    current_transport = _transport(build)
    current_h2 = _h2(build)

    report = compare_transport_suite(
        current_transport,
        _baseline("transport", json.loads(json.dumps(current_transport))),
        current_h2,
        _baseline("h2", json.loads(json.dumps(current_h2))),
    )

    assert report["schema"] == "browser-core.transport-suite-comparison/1"
    assert report["passed"] is True
    assert report["current_build_coherent"] is True
    assert report["baseline_build_coherent"] is True
    assert report["client_hello"]["passed"] is True
    assert report["http2"]["passed"] is True


@pytest.mark.parametrize("side", ["current", "baseline"])
def test_transport_suite_fails_when_protocol_layers_come_from_different_builds(
    side: str,
) -> None:
    first = _build("1")
    other = _build("2")
    current_transport = _transport(first)
    current_h2 = _h2(other if side == "current" else first)
    baseline_transport = _transport(first)
    baseline_h2 = _h2(other if side == "baseline" else first)

    report = compare_transport_suite(
        current_transport,
        _baseline("transport", baseline_transport),
        current_h2,
        _baseline("h2", baseline_h2),
    )

    assert report["passed"] is False
    assert report[f"{side}_build_coherent"] is False
    assert report["client_hello"]["passed"] is True
    assert report["http2"]["passed"] is True


def test_transport_suite_requires_typed_baseline_wrappers() -> None:
    build = _build("1")
    transport = _transport(build)
    h2 = _h2(build)

    with pytest.raises(ContractError, match="baseline fields"):
        compare_transport_suite(transport, transport, h2, _baseline("h2", h2))


def test_transport_evidence_suite_gates_header_order_and_build_coherence() -> None:
    build = _build("1")
    transport = _transport(build)
    evidence = _h2_evidence(build)
    passed = compare_transport_evidence_suite(
        transport,
        _baseline("transport", json.loads(json.dumps(transport))),
        evidence,
        _h2_evidence_baseline(json.loads(json.dumps(evidence))),
    )
    assert passed["schema"] == "browser-core.transport-evidence-suite-comparison/1"
    assert passed["passed"] is True
    assert passed["http2_evidence"]["passed"] is True

    changed = json.loads(json.dumps(evidence))
    changed["header_order"]["header_names"][-1] = "user-agent"
    changed["header_order"]["digest_sha256"] = http2_header_order_digest(
        changed["header_order"]
    )
    changed["digest_sha256"] = http2_capture_evidence_digest(changed)
    failed = compare_transport_evidence_suite(
        transport,
        _baseline("transport", transport),
        changed,
        _h2_evidence_baseline(evidence),
    )
    assert failed["passed"] is False
    assert failed["current_build_coherent"] is True
    assert failed["http2_evidence"]["changed_components"] == ["header_order"]


@pytest.mark.parametrize("side", ["current", "baseline"])
def test_transport_evidence_suite_rejects_cross_protocol_build_stitching(
    side: str,
) -> None:
    first = _build("1")
    other = _build("2")
    current_transport = _transport(first)
    current_evidence = _h2_evidence(other if side == "current" else first)
    baseline_transport = _transport(first)
    baseline_evidence = _h2_evidence(other if side == "baseline" else first)

    report = compare_transport_evidence_suite(
        current_transport,
        _baseline("transport", baseline_transport),
        current_evidence,
        _h2_evidence_baseline(baseline_evidence),
    )
    assert report["passed"] is False
    assert report[f"{side}_build_coherent"] is False
    assert report["client_hello"]["passed"] is True
    assert report["http2_evidence"]["passed"] is True
