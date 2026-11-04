"""Coherent two-protocol golden gate for local Browser Core transport evidence."""

from __future__ import annotations

from typing import Any

from .contracts import reject_sensitive_keys
from .http2_fingerprint import (
    compare_http2_fingerprints,
    validate_http2_baseline,
    validate_http2_fingerprint,
)
from .http2_headers import (
    compare_http2_capture_evidence,
    validate_http2_capture_evidence,
    validate_http2_evidence_baseline,
)
from .transport_fingerprint import (
    compare_transport_fingerprints,
    validate_transport_baseline,
    validate_transport_fingerprint,
)


TRANSPORT_SUITE_COMPARISON_SCHEMA = "browser-core.transport-suite-comparison/1"
TRANSPORT_EVIDENCE_SUITE_COMPARISON_SCHEMA = (
    "browser-core.transport-evidence-suite-comparison/1"
)


def compare_transport_suite(
    current_client_hello: Any,
    client_hello_baseline: Any,
    current_http2: Any,
    http2_baseline: Any,
) -> dict[str, Any]:
    """Compare TLS and H2 while refusing cross-protocol build stitching."""
    current_client_hello = validate_transport_fingerprint(
        current_client_hello,
        require_build=True,
    )
    client_hello_baseline = validate_transport_baseline(client_hello_baseline)
    current_http2 = validate_http2_fingerprint(current_http2, require_build=True)
    http2_baseline = validate_http2_baseline(http2_baseline)

    baseline_client_hello = client_hello_baseline["fingerprint"]
    baseline_http2 = http2_baseline["fingerprint"]
    client_hello_report = compare_transport_fingerprints(
        current_client_hello,
        baseline_client_hello,
    )
    http2_report = compare_http2_fingerprints(current_http2, baseline_http2)
    current_build_coherent = (
        current_client_hello["core_build"] == current_http2["core_build"]
    )
    baseline_build_coherent = (
        baseline_client_hello["core_build"] == baseline_http2["core_build"]
    )
    report = {
        "schema": TRANSPORT_SUITE_COMPARISON_SCHEMA,
        "passed": (
            client_hello_report["passed"]
            and http2_report["passed"]
            and current_build_coherent
            and baseline_build_coherent
        ),
        "current_build_coherent": current_build_coherent,
        "baseline_build_coherent": baseline_build_coherent,
        "client_hello": client_hello_report,
        "http2": http2_report,
        "non_claim": (
            "Coherent local ClientHello and negotiated HTTP/2 golden equality only; "
            "not same-connection, HTTP/3, egress, or remote edge acceptance"
        ),
    }
    reject_sensitive_keys(report)
    return report


def compare_transport_evidence_suite(
    current_client_hello: Any,
    client_hello_baseline: Any,
    current_http2_evidence: Any,
    http2_evidence_baseline: Any,
) -> dict[str, Any]:
    """Gate ClientHello and same-connection H2 evidence as one build population."""
    current_client_hello = validate_transport_fingerprint(
        current_client_hello,
        require_build=True,
    )
    client_hello_baseline = validate_transport_baseline(client_hello_baseline)
    current_http2_evidence = validate_http2_capture_evidence(
        current_http2_evidence,
        require_build=True,
    )
    http2_evidence_baseline = validate_http2_evidence_baseline(
        http2_evidence_baseline
    )
    baseline_client_hello = client_hello_baseline["fingerprint"]
    baseline_http2_evidence = http2_evidence_baseline["evidence"]
    client_hello_report = compare_transport_fingerprints(
        current_client_hello,
        baseline_client_hello,
    )
    http2_evidence_report = compare_http2_capture_evidence(
        current_http2_evidence,
        baseline_http2_evidence,
    )
    current_build_coherent = (
        current_client_hello["core_build"]
        == current_http2_evidence["fingerprint"]["core_build"]
    )
    baseline_build_coherent = (
        baseline_client_hello["core_build"]
        == baseline_http2_evidence["fingerprint"]["core_build"]
    )
    report = {
        "schema": TRANSPORT_EVIDENCE_SUITE_COMPARISON_SCHEMA,
        "passed": (
            client_hello_report["passed"]
            and http2_evidence_report["passed"]
            and current_build_coherent
            and baseline_build_coherent
        ),
        "current_build_coherent": current_build_coherent,
        "baseline_build_coherent": baseline_build_coherent,
        "client_hello": client_hello_report,
        "http2_evidence": http2_evidence_report,
        "non_claim": (
            "Coherent local ClientHello plus same-connection HTTP/2 settings, frame, "
            "and header-name order equality only; not HTTP/3, egress, response, or "
            "remote edge acceptance"
        ),
    }
    reject_sensitive_keys(report)
    return report
