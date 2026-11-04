"""Binding a product-script pin into an evidence pack.

Without this, a pack proves a browser ran but not *which* product script it ran
against, so a roll change silently invalidates the bundle with nothing to detect it.
"""

from __future__ import annotations

import hashlib
import json
import random
from pathlib import Path

import pytest

import browser_core.product_observation as product_observation
from browser_core import evidence_pack as evidence_pack_module
from browser_core.contracts import ContractError
from browser_core.evidence_pack import (
    PORTABLE_OBSERVATION_KEYS,
    _portable_observation_summary,
    _validate_portable_session_summary,
    build_evidence_pack,
    load_evidence_pack_manifest,
)
from browser_core.product_observation import (
    BASELINE_SCHEMA,
    COMPARISON_SCHEMA,
    DRIFT_SCHEMA,
    OBSERVATION_SCHEMA,
    PRODUCT_SCRIPT_VENDOR_HINTS,
    SUBTRACTION_SCHEMA,
    build_surface_baseline,
    check_surface_drift,
    compare_surfaces,
    write_observation,
)
from browser_core.trace import MAX_TRACE_BYTES


def _session(tmp_path: Path) -> Path:
    # Same shape as tests/test_evidence_pack.py so this file exercises the pack, not
    # a hand-rolled session that drifts from the contract.
    document = {
        "schema": "browser-core.session/1",
        "run_id": "core-20260805T054348Z-292f88e6",
        "chromium_revision": "bf6d8a66b43635a532bdad773407285fac0121e9",
        "pid": 99,
        "state": "stopped",
        "created_at": "2026-08-05T05:43:48Z",
        "stopped_at": "2026-08-05T05:44:20Z",
        "build": {
            "provenance": "attested-browser-core",
            "executable_sha256_16": "b724ca5670da28af",
        },
        "automation": {"transport": "cdp", "cdp_endpoint": "http://127.0.0.1:9333"},
        # Tracing state is irrelevant here -- these tests are about the pin binding.
        "trace_mode": "off",
        "trace_categories": [],
        "trace_category_contract": "browser-core.trace-categories/2",
    }
    path = tmp_path / "session.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


def _observation(tmp_path: Path, **overrides) -> Path:
    document = {
        "schema": OBSERVATION_SCHEMA,
        "generated_at": "2026-08-12T01:02:03Z",
        "label": "bm-pin-0804",
        "script_sha256_16": "24f57ec4386b918c",
        "script_bytes": 552777,
        "trace_scope": "causal",
        "trace_category_contract": "browser-core.trace-categories/2",
        "chromium_revision": "bf6d8a66b43635a532bdad773407285fac0121e9",
        "browser_build": {
            "provenance": "attested-browser-core",
            "executable_sha256_16": "b724ca5670da28af",
        },
        "timeout_seconds": 60.0,
        "run_id": "core-20260805T054348Z-292f88e6",
        "dwell_seconds": 20.0,
        "script_identity": {
            "schema": "browser-core.product-script-identity/1",
            "looks_like_built_antibot_script": True,
            "vendor_hint": "akamai-bmp-web",
            "reasons": [],
            "signals": {
                "bytes": 552777,
                "sha256_16": "24f57ec4386b918c",
                "lines": 1,
                "arrow_functions": 0,
                "string_literals": 100,
                "bmak_literals": 41,
                "kpsdk_literals": 0,
                "istl_literals": 0,
                "px_literals": 0,
                "datadome_literals": 0,
                "turnstile_literals": 0,
                "datadome_markers": 0,
                "turnstile_markers": 0,
                "imperva_apg_markers": 0,
                "geetest_loader_markers": 0,
                "anubis_challenge_markers": 0,
                "akamai_sbsd_markers": 0,
                "function_keywords": 1000,
                "max_line_bytes": 552777,
                "bundler_markers": 0,
                "source_map_markers": 0,
                "distinct_identifier_ratio": 0.05,
            },
        },
        "source_provenance": {
            "status": "not_supplied",
            "note": "no public source URL pin was supplied",
        },
        "provenance": {
            "status": "not_checked",
            "note": "no capture tree was supplied",
            "asserted_label": "bm-pin-0804",
        },
        "analysis": {
            "total_events": 127,
            "distinct_api_names": 4,
            "attributable_events": 127,
            "attributable_fraction": 1.0,
            "request_methods": {"HEAD": 62},
            "distinct_request_classes": 61,
            "fetch_target_scope": {
                "coverage": "complete",
                "requests": 62,
                "loopback": 62,
                "external": 0,
                "non_network": 0,
                "unclassified": 0,
            },
        },
    }
    document.update(overrides)
    return write_observation(
        tmp_path / "observation.json",
        product_observation._seal_observation_document(document),
    )


def test_pack_binds_the_script_pin(tmp_path: Path) -> None:
    manifest = build_evidence_pack(
        session_path=_session(tmp_path),
        out_dir=tmp_path / "pack",
        product_observation_path=_observation(tmp_path),
    )
    summary = manifest["artifacts"]["product_observation"]["summary"]
    assert summary["script_sha256_16"] == "24f57ec4386b918c"
    assert summary["vendor_hint"] == "akamai-bmp-web"
    assert summary["looks_like_built_antibot_script"] is True
    assert summary["trace_scope"] == "causal"
    assert summary["trace_category_contract"] == "browser-core.trace-categories/2"
    assert summary["chromium_revision"] == "bf6d8a66b43635a532bdad773407285fac0121e9"
    assert summary["browser_build"]["executable_sha256_16"] == "b724ca5670da28af"
    assert summary["timeout_seconds"] == 60.0
    assert summary["attributable_fraction"] == 1.0
    assert manifest["artifacts"]["product_observation"]["session_binding"] == {
        "status": "matched",
        "fields": ["run_id", "chromium_revision"],
    }
    assert (tmp_path / "pack" / "product-observation.json").is_file()
    assert load_evidence_pack_manifest(tmp_path / "pack" / "manifest.json")


def test_portable_summary_drops_huge_numeric_fields_without_overflow() -> None:
    huge = 10**10_000
    summary = _portable_observation_summary(
        {
            "schema": OBSERVATION_SCHEMA,
            "dwell_seconds": huge,
            "timeout_seconds": huge,
            "analysis": {"attributable_fraction": huge},
        }
    )

    assert "dwell_seconds" not in summary
    assert "timeout_seconds" not in summary
    assert "attributable_fraction" not in summary


@pytest.mark.parametrize(
    "vendor_hint", sorted(PRODUCT_SCRIPT_VENDOR_HINTS - {"akamai-bmp-web"})
)
def test_pack_rejects_every_allowlisted_hint_that_contradicts_the_signals(
    tmp_path: Path, vendor_hint: str
) -> None:
    observation = _observation(tmp_path)
    document = json.loads(observation.read_text(encoding="utf-8"))
    document["script_identity"]["vendor_hint"] = vendor_hint
    observation.write_text(
        json.dumps(product_observation._seal_observation_document(document)),
        encoding="utf-8",
    )

    with pytest.raises(ContractError, match="script identity"):
        build_evidence_pack(
            session_path=_session(tmp_path),
            out_dir=tmp_path / "pack",
            product_observation_path=observation,
        )


def test_portable_summary_drops_a_page_supplied_vendor_hint() -> None:
    document = {
        "schema": OBSERVATION_SCHEMA,
        "label": "pin",
        "script_identity": {"vendor_hint": "private-vendor.example"},
    }

    summary = _portable_observation_summary(document)

    assert "vendor_hint" not in summary
    assert "analysis_boundary" not in summary


def _compact_subtraction_summary_document(
    label: str, vendor_hint: str, looks_built: bool
) -> dict:
    return {
        "schema": SUBTRACTION_SCHEMA,
        "arm_label": label,
        "arm_script_sha256_16": "1" * 16,
        "script_identity_coherent": True,
        "script_identity": {
            "schema": "browser-core.product-script-identity/1",
            "sha256_16": "1" * 16,
            "bytes": 1024,
            "vendor_hint": vendor_hint,
            "looks_like_built_antibot_script": looks_built,
        },
    }


def test_portable_summary_does_not_attach_a_boundary_to_a_rejected_script() -> None:
    summary = _portable_observation_summary(
        _compact_subtraction_summary_document("host-setup", "kasada", False)
    )

    assert summary["vendor_hint"] == "kasada"
    assert summary["looks_like_built_antibot_script"] is False
    assert "analysis_boundary" not in summary


def test_portable_summary_marks_the_kasada_vm_analysis_boundary() -> None:
    summary = _portable_observation_summary(
        _compact_subtraction_summary_document("kasada-pin", "kasada", True)
    )

    assert summary["analysis_boundary"] == {
        "kind": "bytecode-vm-mediated",
        "basis": "classifier-owned-kasada-hint",
        "interpretation": (
            "binding traces observe host API crossings, not operations performed "
            "inside the collector interpreter"
        ),
        "non_claim": (
            "the hint does not prove this artifact reached the VM or enumerate "
            "fingerprint fields, bytecode operations, payload semantics, or acceptance"
        ),
    }


def test_portable_summary_marks_the_geetest_loader_analysis_boundary() -> None:
    summary = _portable_observation_summary(
        _compact_subtraction_summary_document(
            "geetest-loader-pin", "geetest-v4-loader", True
        )
    )

    assert summary["analysis_boundary"] == {
        "kind": "bootstrap-loader-only",
        "basis": "classifier-owned-geetest-v4-loader-hint",
        "interpretation": (
            "binding and resource-intent evidence covers loader orchestration; "
            "the downstream challenge library is absent unless separately pinned "
            "and staged"
        ),
        "non_claim": (
            "the loader surface does not establish downstream challenge behavior, "
            "token generation, payload semantics, proof completion, or acceptance"
        ),
    }


def test_portable_summary_marks_the_turnstile_challenge_stage_boundary() -> None:
    summary = _portable_observation_summary(
        _compact_subtraction_summary_document(
            "turnstile-loader-pin", "cloudflare-turnstile", True
        )
    )

    assert summary["analysis_boundary"] == {
        "kind": "external-challenge-stage-required",
        "basis": "classifier-owned-cloudflare-turnstile-hint",
        "interpretation": (
            "loader and widget-construction evidence does not include the "
            "vendor-origin challenge-frame internals unless that frame is "
            "separately observed"
        ),
        "non_claim": (
            "the outer-script surface does not establish challenge-frame behavior, "
            "token generation, proof completion, clearance, scoring, or acceptance"
        ),
    }


def test_portable_summary_marks_the_imperva_downstream_script_boundary() -> None:
    summary = _portable_observation_summary(
        _compact_subtraction_summary_document(
            "imperva-apg-first-stage-pin", "imperva-apg-loader", True
        )
    )

    assert summary["analysis_boundary"] == {
        "kind": "nonempty-downstream-script-required",
        "basis": "classifier-owned-imperva-apg-loader-hint",
        "interpretation": (
            "first-stage evidence ends at APG script injection; downstream behavior "
            "requires a separately pinned and nonempty second-stage script"
        ),
        "non_claim": (
            "the first-stage or explicit-empty-stage surface does not establish "
            "second-stage collection, payload semantics, client-state generation, "
            "scoring, or acceptance"
        ),
    }


def test_portable_summary_marks_the_anubis_worker_context_boundary() -> None:
    summary = _portable_observation_summary(
        _compact_subtraction_summary_document(
            "anubis-entry-pin", "anubis-web-challenge", True
        )
    )

    assert summary["analysis_boundary"] == {
        "kind": "proof-worker-context-required",
        "basis": "classifier-owned-anubis-web-challenge-hint",
        "interpretation": (
            "the compact challenge entry orchestrates a selected proof worker; "
            "entry-only evidence is incomplete without worker-context execution"
        ),
        "non_claim": (
            "worker presence and API activity do not establish proof completion, "
            "proof value correctness, submission, challenge passage, or acceptance"
        ),
    }


def test_portable_summary_marks_the_shape_global_enumeration_boundary() -> None:
    summary = _portable_observation_summary(
        _compact_subtraction_summary_document("shape-inline-pin", "shape", True)
    )

    assert summary["analysis_boundary"] == {
        "kind": "global-interface-enumeration-dominated",
        "basis": "classifier-owned-shape-hint",
        "interpretation": (
            "binding surfaces can include broad Window interface enumeration; "
            "an api.Window.<Interface> entry records a global property read, not "
            "active use of that interface"
        ),
        "non_claim": (
            "the hint and enumerated names do not prove the collector used each "
            "interface, identify VM operations or fingerprint fields, establish "
            "payload contribution, or acceptance"
        ),
    }


def test_portable_summary_marks_the_akamai_web_not_mobile_bmp_boundary() -> None:
    summary = _portable_observation_summary(
        _compact_subtraction_summary_document(
            "akamai-web-main-sensor-pin", "akamai-bmp-web", True
        )
    )

    assert summary["analysis_boundary"] == {
        "kind": "web-bot-manager-not-mobile-bmp",
        "basis": "classifier-owned-akamai-bmp-web-hint",
        "interpretation": (
            "the bmak-based hint identifies an Akamai browser-script family; "
            "it must not be interpreted with the mobile BMP request-header contract"
        ),
        "non_claim": (
            "the hint does not identify every Akamai web collector family, a "
            "collector release, field semantics, cryptographic behavior, payload "
            "validity, or acceptance"
        ),
    }


def test_portable_summary_marks_the_akamai_sbsd_not_mobile_bmp_boundary() -> None:
    summary = _portable_observation_summary(
        _compact_subtraction_summary_document(
            "akamai-sbsd-pin", "akamai-sbsd-web", True
        )
    )

    assert summary["analysis_boundary"] == {
        "kind": "web-bot-manager-not-mobile-bmp",
        "basis": "classifier-owned-akamai-sbsd-web-hint",
        "interpretation": (
            "the complete SBSD marker cluster identifies an Akamai browser-script "
            "family; it must not be interpreted with the mobile BMP request-header "
            "contract"
        ),
        "non_claim": (
            "the hint does not make SBSD equivalent to the bmak-based main family, "
            "identify every deployment profile, establish field or payload "
            "semantics, validity, or acceptance"
        ),
    }


def test_pack_retains_the_signal_derived_imperva_apg_hint(tmp_path: Path) -> None:
    observation = _observation(tmp_path)
    document = json.loads(observation.read_text(encoding="utf-8"))
    document["script_identity"]["signals"]["bmak_literals"] = 0
    document["script_identity"]["signals"]["imperva_apg_markers"] = 3
    document["script_identity"]["vendor_hint"] = "imperva-apg-loader"
    write_observation(
        observation,
        product_observation._seal_observation_document(document),
        overwrite=True,
    )

    manifest = build_evidence_pack(
        session_path=_session(tmp_path),
        out_dir=tmp_path / "pack",
        product_observation_path=observation,
    )

    assert (
        manifest["artifacts"]["product_observation"]["summary"]["vendor_hint"]
        == "imperva-apg-loader"
    )


def test_pack_binds_observation_source_digest_to_the_bytes_it_parsed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    session_path = _session(tmp_path)
    observation_path = _observation(tmp_path)
    original_body = observation_path.read_bytes()
    original_reader = evidence_pack_module._read_json_object_bounded

    def _read_then_mutate(path: Path, label: str, **kwargs):
        result = original_reader(path, label, **kwargs)
        if Path(path) == observation_path:
            observation_path.write_text("{}", encoding="utf-8")
        return result

    monkeypatch.setattr(
        evidence_pack_module, "_read_json_object_bounded", _read_then_mutate
    )

    manifest = build_evidence_pack(
        session_path=session_path,
        out_dir=tmp_path / "pack",
        product_observation_path=observation_path,
    )

    entry = manifest["artifacts"]["product_observation"]
    assert entry["source_sha256"] == hashlib.sha256(original_body).hexdigest()
    assert entry["source_bytes"] == len(original_body)


def test_pack_bounds_product_observation_source_before_parsing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    observation_path = _observation(tmp_path)
    monkeypatch.setattr(
        evidence_pack_module,
        "MAX_EVIDENCE_PACK_OBSERVATION_SOURCE_BYTES",
        len(observation_path.read_bytes()) - 1,
    )

    with pytest.raises(ContractError, match="product observation source exceeds"):
        build_evidence_pack(
            session_path=_session(tmp_path),
            out_dir=tmp_path / "pack",
            product_observation_path=observation_path,
        )


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"run_id": "different-run"}, "run id"),
        ({"chromium_revision": "f" * 40}, "Chromium revision"),
        ({"run_id": None}, "run id"),
        ({"chromium_revision": None}, "Chromium revision"),
    ],
)
def test_raw_product_observation_must_match_the_session(
    tmp_path: Path, overrides: dict, message: str
) -> None:
    with pytest.raises(ContractError, match=message):
        build_evidence_pack(
            session_path=_session(tmp_path),
            out_dir=tmp_path / "pack",
            product_observation_path=_observation(tmp_path, **overrides),
        )


def test_pack_carries_value_free_fetch_target_scope_receipt(tmp_path: Path) -> None:
    """The native fetch boundary should be evidenced without retaining targets."""
    manifest = build_evidence_pack(
        session_path=_session(tmp_path),
        out_dir=tmp_path / "pack",
        product_observation_path=_observation(tmp_path),
    )
    summary = manifest["artifacts"]["product_observation"]["summary"]
    assert summary["fetch_target_scope"] == {
        "coverage": "complete",
        "requests": 62,
        "loopback": 62,
        "external": 0,
        "non_network": 0,
        "unclassified": 0,
    }


def test_pack_retains_and_verifies_a_complete_observation_receipt(
    tmp_path: Path,
) -> None:
    observation = _observation(tmp_path)
    document = json.loads(observation.read_text(encoding="utf-8"))
    write_observation(
        observation,
        product_observation._seal_observation_document(document),
        overwrite=True,
    )

    manifest = build_evidence_pack(
        session_path=_session(tmp_path),
        out_dir=tmp_path / "pack",
        product_observation_path=observation,
    )

    summary = manifest["artifacts"]["product_observation"]["summary"]
    assert summary["observation_receipt_sha256"] == document[
        "observation_receipt_sha256"
    ]
    assert load_evidence_pack_manifest(tmp_path / "pack" / "manifest.json")


def test_pack_rejects_an_edited_complete_observation(tmp_path: Path) -> None:
    observation = _observation(tmp_path)
    document = json.loads(observation.read_text(encoding="utf-8"))
    document["observation_receipt_sha256"] = hashlib.sha256(
        json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    document["dwell_seconds"] = 21.0
    observation.write_text(json.dumps(document), encoding="utf-8")

    with pytest.raises(ContractError, match="observation complete receipt"):
        build_evidence_pack(
            session_path=_session(tmp_path),
            out_dir=tmp_path / "pack",
            product_observation_path=observation,
        )


def test_portable_fetch_scope_preserves_explicit_unclassified_population() -> None:
    summary = _portable_observation_summary(
        {
            "schema": OBSERVATION_SCHEMA,
            "analysis": {
                "fetch_target_scope": {
                    "coverage": "unknown",
                    "requests": 3,
                    "loopback": 1,
                    "external": 0,
                    "non_network": 1,
                    "unclassified": 1,
                }
            },
        }
    )

    assert summary["fetch_target_scope"] == {
        "coverage": "unknown",
        "requests": 3,
        "loopback": 1,
        "external": 0,
        "non_network": 1,
        "unclassified": 1,
    }


def test_pack_carries_public_source_and_redacted_lifecycle_method(
    tmp_path: Path,
) -> None:
    source = {
        "status": "verified_digest",
        "source_url": "https://vendor.example/v1/api.js",
        "retrieved_at": "2026-08-09T05:31:00Z",
        "sha256": "24f57ec4386b918c" + "a" * 48,
    }
    rehost_contract = {
        "schema": "browser-core.product-script-rehost-contract/1",
        "sha256": "b" * 64,
        "page_sha256": "c" * 64,
        "hook_catalog_sha256": "d" * 64,
        "observer_js_sha256": "e" * 64,
        "input_probe_catalog_sha256": "f" * 64,
        "observer_sequence": "browser-core.product-script-observer-sequence/1",
        "resource_intent_contract": "cdp_dom_snapshot/1",
    }
    manifest = build_evidence_pack(
        session_path=_session(tmp_path),
        out_dir=tmp_path / "pack",
        product_observation_path=_observation(
            tmp_path,
            source_provenance=source,
            declared_script_url=source["source_url"],
            rehost_contract=rehost_contract,
            prelude={"supplied": True, "bytes": 45, "sha256_16": "1" * 16},
            driver={"supplied": True, "bytes": 232, "sha256_16": "2" * 16},
            driver_result={
                "status": "ok",
                "type": "string",
                "serialized_bytes": 21,
                "length": 19,
            },
        ),
    )
    summary = manifest["artifacts"]["product_observation"]["summary"]
    assert summary["source_provenance"] == {
        "status": "verified_digest",
        "source_url_shape": {
            "origin": "https://vendor.example",
            "path_segment_lengths": [2, 6],
            "path_segments_truncated": False,
            "query_names": [],
            "query_names_truncated": False,
            "fragment_present": False,
        },
        "retrieved_at": source["retrieved_at"],
        "sha256": source["sha256"],
        "note": "the full digest matched the exact observed bytes",
    }
    assert summary["declared_script_url_shape"] == {
        "origin": "https://vendor.example",
        "path_segment_lengths": [2, 6],
        "path_segments_truncated": False,
        "query_names": [],
        "query_names_truncated": False,
        "fragment_present": False,
    }
    assert summary["rehost_contract"] == rehost_contract
    assert summary["prelude"]["sha256_16"] == "1" * 16
    assert summary["driver"]["sha256_16"] == "2" * 16
    assert summary["driver_result"]["type"] == "string"
    assert "prelude_js" not in json.dumps(summary)
    assert "driver_js" not in json.dumps(summary)
    assert load_evidence_pack_manifest(tmp_path / "pack" / "manifest.json")


def test_pack_rejects_a_public_source_digest_for_different_script_bytes(
    tmp_path: Path,
) -> None:
    source = {
        "status": "verified_digest",
        "source_url": "https://vendor.example/v1/api.js",
        "retrieved_at": "2026-08-09T05:31:00Z",
        "sha256": "f" * 64,
    }

    observation = _observation(tmp_path)
    document = json.loads(observation.read_text(encoding="utf-8"))
    document["source_provenance"] = source
    document["declared_script_url"] = source["source_url"]
    observation.write_text(
        json.dumps(product_observation._seal_observation_document(document)),
        encoding="utf-8",
    )

    with pytest.raises(ContractError, match="provenance"):
        build_evidence_pack(
            session_path=_session(tmp_path),
            out_dir=tmp_path / "pack",
            product_observation_path=observation,
        )


def _subtraction_with_public_source(
    tmp_path: Path, source_sha256: str, *, capture_label: str = "akamai-arm"
) -> Path:
    subtraction = tmp_path / "subtraction.json"
    source_provenance = product_observation._sanitize_source_provenance(
        {
            "status": "verified_digest",
            "source_url": "https://vendor.example/v1/api.js",
            "retrieved_at": "2026-08-09T05:31:00Z",
            "sha256": source_sha256,
        }
    )
    capture_provenance = product_observation._sanitize_capture_provenance(
        {
            "status": "not_checked",
            "note": "no capture tree was supplied",
            "asserted_label": capture_label,
        }
    )
    subtraction.write_text(
        json.dumps(
            {
                "schema": SUBTRACTION_SCHEMA,
                "generated_at": "2026-08-12T01:02:03Z",
                "non_claims": [
                    "control subtraction attributes API names in a lab rehost only",
                    "not an acceptance, bypass, evasion, or bot-score claim",
                ],
                "arm_label": "akamai-arm",
                "arm_script_sha256_16": "24f57ec4386b918c",
                "script_identity_coherent": True,
                "script_identity": {
                    "schema": "browser-core.product-script-identity/1",
                    "sha256_16": "24f57ec4386b918c",
                    "bytes": 552777,
                    "looks_like_built_antibot_script": True,
                    "vendor_hint": "akamai-bmp-web",
                },
                "source_provenance": source_provenance,
                "provenance": capture_provenance,
                "clean_subtraction": True,
                "only_in_arm": {"api.Window.fetch": 1},
            }
        ),
        encoding="utf-8",
    )
    return subtraction


def test_pack_rejects_edited_subtraction_source_provenance(tmp_path: Path) -> None:
    subtraction = _subtraction_with_public_source(tmp_path, "f" * 64)

    with pytest.raises(ContractError, match="subtraction provenance"):
        build_evidence_pack(
            session_path=_session(tmp_path),
            out_dir=tmp_path / "pack",
            product_observation_path=subtraction,
        )


@pytest.mark.parametrize("field", ["source_provenance", "provenance"])
def test_pack_rejects_unhashable_subtraction_provenance_status(
    tmp_path: Path, field: str
) -> None:
    subtraction = _subtraction_with_public_source(
        tmp_path, "24f57ec4386b918c" + "a" * 48
    )
    document = json.loads(subtraction.read_text(encoding="utf-8"))
    document[field]["status"] = []
    subtraction.write_text(json.dumps(document), encoding="utf-8")

    with pytest.raises(ContractError, match="subtraction provenance"):
        build_evidence_pack(
            session_path=_session(tmp_path),
            out_dir=tmp_path / "pack",
            product_observation_path=subtraction,
        )


def test_pack_accepts_a_current_subtraction_with_matching_custody(tmp_path: Path) -> None:
    subtraction = _subtraction_with_public_source(
        tmp_path, "24f57ec4386b918c" + "a" * 48
    )

    manifest = build_evidence_pack(
        session_path=_session(tmp_path),
        out_dir=tmp_path / "pack",
        product_observation_path=subtraction,
    )

    summary = manifest["artifacts"]["product_observation"]["summary"]
    assert summary["script_identity_coherent"] is True
    assert summary["source_provenance"]["sha256"].startswith(
        summary["script_sha256_16"]
    )


def test_pack_retains_and_verifies_a_complete_subtraction_receipt(
    tmp_path: Path,
) -> None:
    subtraction = _subtraction_with_public_source(
        tmp_path, "24f57ec4386b918c" + "a" * 48
    )
    document = json.loads(subtraction.read_text(encoding="utf-8"))
    document["subtraction_receipt_sha256"] = hashlib.sha256(
        json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    subtraction.write_text(json.dumps(document), encoding="utf-8")

    manifest = build_evidence_pack(
        session_path=_session(tmp_path),
        out_dir=tmp_path / "pack",
        product_observation_path=subtraction,
    )

    summary = manifest["artifacts"]["product_observation"]["summary"]
    assert summary["subtraction_receipt_sha256"] == document[
        "subtraction_receipt_sha256"
    ]
    assert load_evidence_pack_manifest(tmp_path / "pack" / "manifest.json")


def test_pack_rejects_an_edited_complete_subtraction(tmp_path: Path) -> None:
    subtraction = _subtraction_with_public_source(
        tmp_path, "24f57ec4386b918c" + "a" * 48
    )
    document = json.loads(subtraction.read_text(encoding="utf-8"))
    document["subtraction_receipt_sha256"] = hashlib.sha256(
        json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    document["only_in_arm"] = {"api.Window.fetch": 1, "api.EDITED": 1}
    subtraction.write_text(json.dumps(document), encoding="utf-8")

    with pytest.raises(ContractError, match="subtraction complete receipt"):
        build_evidence_pack(
            session_path=_session(tmp_path),
            out_dir=tmp_path / "pack",
            product_observation_path=subtraction,
        )


def test_pack_rejects_subtraction_identity_for_a_different_arm_pin(
    tmp_path: Path,
) -> None:
    subtraction = _subtraction_with_public_source(
        tmp_path, "24f57ec4386b918c" + "a" * 48
    )
    document = json.loads(subtraction.read_text(encoding="utf-8"))
    document["script_identity"]["sha256_16"] = "f" * 16
    subtraction.write_text(json.dumps(document), encoding="utf-8")

    with pytest.raises(ContractError, match="subtraction identity"):
        build_evidence_pack(
            session_path=_session(tmp_path),
            out_dir=tmp_path / "pack",
            product_observation_path=subtraction,
        )


def test_pack_rejects_extra_subtraction_identity_fields(tmp_path: Path) -> None:
    subtraction = _subtraction_with_public_source(
        tmp_path, "24f57ec4386b918c" + "a" * 48
    )
    document = json.loads(subtraction.read_text(encoding="utf-8"))
    document["script_identity"]["private_note"] = "must not travel"
    subtraction.write_text(json.dumps(document), encoding="utf-8")

    with pytest.raises(ContractError, match="subtraction identity"):
        build_evidence_pack(
            session_path=_session(tmp_path),
            out_dir=tmp_path / "pack",
            product_observation_path=subtraction,
        )


def test_pack_rejects_edited_subtraction_capture_label(tmp_path: Path) -> None:
    subtraction = _subtraction_with_public_source(
        tmp_path,
        "24f57ec4386b918c" + "a" * 48,
        capture_label="different-arm",
    )

    with pytest.raises(ContractError, match="subtraction provenance"):
        build_evidence_pack(
            session_path=_session(tmp_path),
            out_dir=tmp_path / "pack",
            product_observation_path=subtraction,
        )


def _surface_baseline(
    tmp_path: Path,
    *,
    surface_sha256: str | None = None,
    control_script_sha256_16: str | None = None,
) -> Path:
    names = ["api.Navigator.userAgent.get", "api.Window.fetch"]
    canonical = json.dumps(sorted(names), separators=(",", ":")).encode("utf-8")
    baseline = tmp_path / "baseline.json"
    document = {
        "schema": BASELINE_SCHEMA,
        "label": "akamai-baseline",
        "script_sha256_16": "24f57ec4386b918c",
        "api_name_count": len(names),
        "api_names": names,
        "surface_sha256": surface_sha256 or hashlib.sha256(canonical).hexdigest(),
        "non_claims": [
            "a stable surface is not an acceptance or undetectability claim"
        ],
    }
    if control_script_sha256_16 is not None:
        document["control_script_sha256_16"] = control_script_sha256_16
    baseline.write_text(json.dumps(document), encoding="utf-8")
    return baseline


def _repeated_surface_baseline(
    tmp_path: Path, *, measured_noise_floor: int = 1
) -> Path:
    baseline = _surface_baseline(tmp_path)
    document = json.loads(baseline.read_text(encoding="utf-8"))
    document.update(
        {
            "arms": 2,
            "volatile_api_names": ["api.Window.Flaky"],
            "pairwise_differences": [1],
            "measured_noise_floor": measured_noise_floor,
        }
    )
    baseline.write_text(json.dumps(document), encoding="utf-8")
    return baseline


def test_pack_retains_a_verified_baseline_surface_receipt(tmp_path: Path) -> None:
    manifest = build_evidence_pack(
        session_path=_session(tmp_path),
        out_dir=tmp_path / "pack",
        product_observation_path=_surface_baseline(tmp_path),
    )

    summary = manifest["artifacts"]["product_observation"]["summary"]
    assert summary["api_name_count"] == 2
    assert summary["surface_sha256"] == hashlib.sha256(
        b'["api.Navigator.userAgent.get","api.Window.fetch"]'
    ).hexdigest()
    assert load_evidence_pack_manifest(tmp_path / "pack" / "manifest.json")


def test_pack_retains_a_complete_baseline_self_integrity_receipt(
    tmp_path: Path,
) -> None:
    baseline = tmp_path / "complete-baseline.json"
    document = build_surface_baseline(
        {
            "schema": SUBTRACTION_SCHEMA,
            "arm_label": "complete",
            "arm_script_sha256_16": "a" * 16,
            "only_in_arm": ["api.Window.fetch"],
            "clean_subtraction": True,
        }
    )
    baseline.write_text(json.dumps(document), encoding="utf-8")

    manifest = build_evidence_pack(
        session_path=_session(tmp_path),
        out_dir=tmp_path / "pack",
        product_observation_path=baseline,
    )

    summary = manifest["artifacts"]["product_observation"]["summary"]
    assert summary["baseline_receipt_sha256"] == document[
        "baseline_receipt_sha256"
    ]
    assert load_evidence_pack_manifest(tmp_path / "pack" / "manifest.json")


def test_pack_retains_baseline_source_subtraction_lineage(tmp_path: Path) -> None:
    subtraction = product_observation._seal_subtraction_document(
        {
            "schema": SUBTRACTION_SCHEMA,
            "generated_at": "2026-08-12T01:02:03Z",
            "non_claims": [
                "control subtraction attributes API names in a lab rehost only",
                "not an acceptance, bypass, evasion, or bot-score claim",
            ],
            "arm_label": "source",
            "arm_script_sha256_16": "a" * 16,
            "only_in_arm": ["api.Window.fetch"],
            "clean_subtraction": True,
        }
    )
    document = build_surface_baseline(subtraction)

    summary = _portable_observation_summary(document)

    assert summary["source_subtraction_receipt_population"] == [
        subtraction["subtraction_receipt_sha256"]
    ]
    assert summary["source_subtraction_lineage"] == [
        {
            "arm_label": "source",
            "subtraction_receipt_sha256": subtraction[
                "subtraction_receipt_sha256"
            ],
        }
    ]
    assert summary["source_subtraction_receipts_complete"] is True


def test_portable_subtraction_retains_observation_parent_lineage() -> None:
    summary = _portable_observation_summary(
        {
            "schema": SUBTRACTION_SCHEMA,
            "arm_label": "arm",
            "arm_script_sha256_16": "a" * 16,
            "arm_observation_receipt_sha256": "1" * 64,
            "control_observation_receipt_sha256": "2" * 64,
            "input_observation_receipts_complete": True,
            "input_observation_receipts_comparable": True,
        }
    )

    assert summary["arm_observation_receipt_sha256"] == "1" * 64
    assert summary["control_observation_receipt_sha256"] == "2" * 64
    assert summary["input_observation_receipts_complete"] is True
    assert summary["input_observation_receipts_comparable"] is True


def _decision_subtraction(label: str, names: list[str]) -> dict:
    return product_observation._seal_subtraction_document(
        {
            "schema": SUBTRACTION_SCHEMA,
            "generated_at": "2026-08-12T01:02:03Z",
            "non_claims": [
                "control subtraction attributes API names in a lab rehost only",
                "not an acceptance, bypass, evasion, or bot-score claim",
            ],
            "arm_label": label,
            "arm_script_sha256_16": "a" * 16,
            "control_label": f"{label}-control",
            "only_in_arm": names,
            "clean_subtraction": True,
        }
    )


def test_pack_accepts_and_retains_a_portable_drift_decision(tmp_path: Path) -> None:
    frozen = _decision_subtraction("frozen", ["api.A"])
    observed = _decision_subtraction("observed", ["api.A", "api.B"])
    decision = check_surface_drift(observed, build_surface_baseline(frozen))
    path = tmp_path / "drift.json"
    write_observation(path, decision)

    manifest = build_evidence_pack(
        session_path=_session(tmp_path),
        out_dir=tmp_path / "pack",
        product_observation_path=path,
    )

    summary = manifest["artifacts"]["product_observation"]["summary"]
    assert summary["schema"] == DRIFT_SCHEMA
    assert summary["decision_receipt_sha256"] == decision["decision_receipt_sha256"]
    assert summary["baseline_receipt_sha256"] == decision["baseline_receipt_sha256"]
    assert summary["observed_subtraction_receipt_sha256"] == decision[
        "observed_subtraction_receipt_sha256"
    ]
    assert summary["added"] == ["api.B"]
    assert summary["passed"] is False
    assert load_evidence_pack_manifest(tmp_path / "pack" / "manifest.json")


def test_pack_accepts_and_retains_a_portable_comparison_decision(
    tmp_path: Path,
) -> None:
    first = _decision_subtraction("first", ["api.A"])
    second = _decision_subtraction("second", ["api.A", "api.B"])
    decision = compare_surfaces([first, second])
    path = tmp_path / "comparison.json"
    write_observation(path, decision)

    manifest = build_evidence_pack(
        session_path=_session(tmp_path),
        out_dir=tmp_path / "pack",
        product_observation_path=path,
    )

    summary = manifest["artifacts"]["product_observation"]["summary"]
    assert summary["schema"] == COMPARISON_SCHEMA
    assert summary["decision_receipt_sha256"] == decision["decision_receipt_sha256"]
    assert summary["arms"] == ["first", "second"]
    assert summary["pairs"][0]["only_b"] == ["api.B"]
    assert summary["pairs"][0]["surface_comparison_claim_ready"] is True
    assert load_evidence_pack_manifest(tmp_path / "pack" / "manifest.json")


def test_portable_decision_summary_rejects_a_cyclic_field_cleanly() -> None:
    cyclic: dict[str, object] = {}
    cyclic["cycle"] = cyclic

    with pytest.raises(ContractError, match="portable decision"):
        _portable_observation_summary(
            {
                "schema": DRIFT_SCHEMA,
                "method_mismatches": cyclic,
            }
        )


def test_pack_rejects_an_edited_complete_baseline_receipt(tmp_path: Path) -> None:
    baseline = tmp_path / "edited-complete-baseline.json"
    document = build_surface_baseline(
        {
            "schema": SUBTRACTION_SCHEMA,
            "arm_label": "complete",
            "arm_script_sha256_16": "a" * 16,
            "only_in_arm": ["api.Window.fetch"],
            "clean_subtraction": True,
        }
    )
    document["label"] = "edited-but-safe"
    baseline.write_text(json.dumps(document), encoding="utf-8")

    with pytest.raises(ContractError, match="baseline complete receipt"):
        build_evidence_pack(
            session_path=_session(tmp_path),
            out_dir=tmp_path / "pack",
            product_observation_path=baseline,
        )


def test_pack_retains_a_current_baseline_control_script_pin(tmp_path: Path) -> None:
    manifest = build_evidence_pack(
        session_path=_session(tmp_path),
        out_dir=tmp_path / "pack",
        product_observation_path=_surface_baseline(
            tmp_path, control_script_sha256_16="c" * 16
        ),
    )

    summary = manifest["artifacts"]["product_observation"]["summary"]
    assert summary["control_script_sha256_16"] == "c" * 16
    assert load_evidence_pack_manifest(tmp_path / "pack" / "manifest.json")


def test_pack_retains_a_baseline_public_source_digest(tmp_path: Path) -> None:
    baseline = _surface_baseline(tmp_path)
    document = json.loads(baseline.read_text(encoding="utf-8"))
    document["source_provenance"] = {
        "status": "verified_digest",
        "source_url": "https://vendor.example/v1/api.js",
        "retrieved_at": "2026-08-12T00:00:00Z",
        "sha256": "24f57ec4386b918c" + "a" * 48,
    }
    baseline.write_text(json.dumps(document), encoding="utf-8")

    manifest = build_evidence_pack(
        session_path=_session(tmp_path),
        out_dir=tmp_path / "pack",
        product_observation_path=baseline,
    )

    summary = manifest["artifacts"]["product_observation"]["summary"]
    assert summary["source_provenance"]["sha256"] == document["source_provenance"][
        "sha256"
    ]
    assert load_evidence_pack_manifest(tmp_path / "pack" / "manifest.json")


def test_pack_retains_baseline_arm_and_control_capture_custody(tmp_path: Path) -> None:
    baseline = _surface_baseline(tmp_path)
    document = json.loads(baseline.read_text(encoding="utf-8"))
    document.update(
        {
            "source_arm_label": "akamai-arm",
            "control_label": "akamai-control",
            "capture_provenance": {
                "status": "not_checked",
                "asserted_label": "akamai-arm",
            },
            "control_capture_provenance": {
                "status": "not_checked",
                "asserted_label": "akamai-control",
            },
        }
    )
    baseline.write_text(json.dumps(document), encoding="utf-8")

    manifest = build_evidence_pack(
        session_path=_session(tmp_path),
        out_dir=tmp_path / "pack",
        product_observation_path=baseline,
    )

    summary = manifest["artifacts"]["product_observation"]["summary"]
    assert summary["source_arm_label"] == "akamai-arm"
    assert summary["capture_provenance"]["asserted_label"] == "akamai-arm"
    assert (
        summary["control_capture_provenance"]["asserted_label"]
        == "akamai-control"
    )
    assert load_evidence_pack_manifest(tmp_path / "pack" / "manifest.json")


def test_pack_rejects_an_edited_baseline_capture_label(tmp_path: Path) -> None:
    baseline = _surface_baseline(tmp_path)
    document = json.loads(baseline.read_text(encoding="utf-8"))
    document.update(
        {
            "source_arm_label": "akamai-arm",
            "control_label": "akamai-control",
            "capture_provenance": {
                "status": "not_checked",
                "asserted_label": "edited",
            },
            "control_capture_provenance": {
                "status": "not_checked",
                "asserted_label": "akamai-control",
            },
        }
    )
    baseline.write_text(json.dumps(document), encoding="utf-8")

    with pytest.raises(ContractError, match="baseline surface"):
        build_evidence_pack(
            session_path=_session(tmp_path),
            out_dir=tmp_path / "pack",
            product_observation_path=baseline,
        )


def test_pack_rejects_an_edited_baseline_surface_digest(tmp_path: Path) -> None:
    with pytest.raises(ContractError, match="baseline surface"):
        build_evidence_pack(
            session_path=_session(tmp_path),
            out_dir=tmp_path / "pack",
            product_observation_path=_surface_baseline(
                tmp_path, surface_sha256="f" * 64
            ),
        )


def test_pack_retains_a_verified_baseline_repeat_receipt(tmp_path: Path) -> None:
    manifest = build_evidence_pack(
        session_path=_session(tmp_path),
        out_dir=tmp_path / "pack",
        product_observation_path=_repeated_surface_baseline(tmp_path),
    )

    summary = manifest["artifacts"]["product_observation"]["summary"]
    assert summary["arms"] == 2
    assert summary["volatile_api_name_count"] == 1
    assert summary["pairwise_differences"] == [1]
    assert summary["measured_noise_floor"] == 1
    assert load_evidence_pack_manifest(tmp_path / "pack" / "manifest.json")


def test_pack_rejects_an_edited_baseline_noise_floor(tmp_path: Path) -> None:
    with pytest.raises(ContractError, match="baseline repeat"):
        build_evidence_pack(
            session_path=_session(tmp_path),
            out_dir=tmp_path / "pack",
            product_observation_path=_repeated_surface_baseline(
                tmp_path, measured_noise_floor=100
            ),
        )


def test_pack_rejects_an_impossible_request_activity_baseline(tmp_path: Path) -> None:
    baseline = _repeated_surface_baseline(tmp_path)
    document = json.loads(baseline.read_text(encoding="utf-8"))
    document["request_activity_baseline"] = {
        "status": "ok",
        "arms": 2,
        "stable_shapes": 2,
        "union_shapes": 1,
        "variable_shapes": 0,
        "rows": [],
        "rows_truncated": False,
    }
    baseline.write_text(json.dumps(document), encoding="utf-8")

    with pytest.raises(ContractError, match="baseline surface"):
        build_evidence_pack(
            session_path=_session(tmp_path),
            out_dir=tmp_path / "pack",
            product_observation_path=baseline,
        )


@pytest.mark.parametrize(
    ("name", "arms", "volatile", "floor"),
    [
        ("akamai-bm-web", 3, 0, 0),
        ("kasada-driven", 2, 0, 0),
        ("perimeterx", 3, 0, 0),
        ("shape-nordstrom", 3, 15, 11),
    ],
)
def test_portable_repeat_receipts_match_the_frozen_vendor_populations(
    name: str, arms: int, volatile: int, floor: int
) -> None:
    path = Path(__file__).resolve().parents[1] / "fixtures" / "surface-baselines"
    document = json.loads((path / f"{name}.json").read_text(encoding="utf-8"))

    summary = _portable_observation_summary(document)

    assert summary["arms"] == arms
    assert summary["volatile_api_name_count"] == volatile
    assert summary["measured_noise_floor"] == floor
    assert summary["measured_noise_floor"] == max(summary["pairwise_differences"])


def test_pack_redacts_public_source_path_and_query_values(tmp_path: Path) -> None:
    source_url = (
        "https://vendor.example/private-tenant/collector.js?sitekey=private-value"
    )
    source = {
        "status": "verified_digest",
        "source_url": source_url,
        "retrieved_at": "2026-08-09T05:31:00Z",
        "sha256": "24f57ec4386b918c" + "a" * 48,
    }
    manifest = build_evidence_pack(
        session_path=_session(tmp_path),
        out_dir=tmp_path / "pack",
        product_observation_path=_observation(
            tmp_path,
            source_provenance=source,
            declared_script_url=source_url,
        ),
    )

    portable_file = (tmp_path / "pack" / "product-observation.json").read_text()
    serialized = json.dumps(manifest) + portable_file
    assert "private-tenant" not in serialized
    assert "private-value" not in serialized
    assert "sitekey" in serialized
    assert "path_segment_lengths" in serialized


def test_portable_summary_normalizes_legacy_sensitive_lifecycle_fields() -> None:
    summary = _portable_observation_summary(
        {
            "schema": OBSERVATION_SCHEMA,
            "label": "legacy",
            "script_sha256_16": "a" * 16,
            "prelude": "window.__private_tenant_key = 'prelude-secret'",
            "driver_js": "return 'private-driver-secret'",
            "driver_result": {"token": "private-result-secret"},
            "ready_expression": "window.__private_ready_secret === true",
            "stage_routes": [
                {
                    "path_prefix": "/tenant/mfc",
                    "file": r"C:\private\tenant-secret\ips.js",
                    "sha256_16": "b" * 16,
                }
            ],
            "collector_startup": {
                "uncaught_errors": ["TypeError: 'private-error-secret'"],
                "unhandled_rejections": [],
                "probe_error": "Error: 'private-probe-secret'",
                "renderer_blocked": True,
                "browser_target_status": "present",
                "browser_target_title_matches": False,
                "vendor_globals": ["turnstile"],
                "private_extra": "private-startup-extra",
            },
        }
    )
    rendered = json.dumps(summary)
    for secret in (
        "private_tenant_key",
        "private-driver-secret",
        "private-result-secret",
        "private_ready_secret",
        "tenant-secret",
        "private-error-secret",
        "private-probe-secret",
        "private-startup-extra",
    ):
        assert secret not in rendered
    assert summary["prelude"]["supplied"] is True
    assert summary["driver"]["supplied"] is True
    assert summary["driver_result"]["type"] == "object"
    assert summary["ready_expression"]["supplied"] is True
    route = summary["stage_routes"][0]
    assert route["sha256_16"] == "b" * 16
    assert route["path_prefix"]["path_segment_lengths"] == [6, 3]
    startup = summary["collector_startup"]
    assert startup["renderer_blocked"] is True
    assert startup["browser_target_status"] == "present"
    assert startup["browser_target_title_matches"] is False


def test_portable_summary_reallowlists_provenance_readiness_and_method() -> None:
    contract = {
        "schema": "browser-core.product-script-rehost-contract/1",
        "sha256": "a" * 64,
        "page_sha256": "b" * 64,
        "hook_catalog_sha256": "c" * 64,
        "observer_js_sha256": "d" * 64,
        "input_probe_catalog_sha256": "e" * 64,
        "observer_sequence": "browser-core.product-script-observer-sequence/1",
        "resource_intent_contract": "cdp_dom_snapshot/1",
        "private_extra": "private-contract-secret",
    }
    summary = _portable_observation_summary(
        {
            "schema": OBSERVATION_SCHEMA,
            "label": "hostile-edited-artifact",
            "script_sha256_16": "a" * 16,
            "browser_build": {
                "provenance": "attested-browser-core",
                "executable_sha256_16": "b" * 16,
                "private_path": r"C:\private\browser-secret",
            },
            "provenance": {
                "status": "VERIFIED",
                "recorded_hosts": ["vendor.example"],
                "captures_with_manifest": [r"C:\private\capture-secret"],
                "captures_without_manifest": ["private-capture-name"],
                "note": "private-provenance-secret",
            },
            "await_report": {
                "ended_on": "ready",
                "waited_seconds": 12.5,
                "polls": 3,
                "page_ever_answered": True,
                "signal_kind": "builtin",
                "private_extra": "private-await-secret",
            },
            "rehost_contract": contract,
            "method": {
                "arm_driver": "window.__private_driver_secret()",
                "arm_declared_script_url": (
                    "https://vendor.example/private-path/api.js?token=private-value"
                ),
                "arm_trace_scope": "private-trace-secret",
                "arm_trace_category_contract": "private-contract-value",
                "arm_chromium_revision": "private-revision-value",
                "arm_browser_build": {
                    "provenance": "private-build-value",
                    "executable_sha256_16": "private-executable-value",
                },
                "arm_timeout_seconds": "private-timeout-value",
                "arm_viewport": {"inner_width": 800, "private": "private-viewport"},
                "arm_dom_profile": "private-dom-value",
                "arm_hook_mode": "private-hook-mode",
                "arm_hook_target_names": ["private-hook-target"],
                "arm_input_profile": "private-input-value",
                "arm_script_path": "/private-script-path/sample.js?key=value",
                "arm_resource_intent_capture": "private-resource-mode",
                "arm_extra_browser_args": ["--private-flag=private-flag-value"],
                "arm_stage_routes": [
                    {
                        "path_prefix": "/private-tenant/stage",
                        "sha256_16": "f" * 16,
                    }
                ],
                "private_extra": "private-method-secret",
            },
        }
    )

    rendered = json.dumps(summary)
    for secret in (
        "browser-secret",
        "capture-secret",
        "private-capture-name",
        "private-provenance-secret",
        "private-await-secret",
        "private-contract-secret",
        "private_driver_secret",
        "private-path",
        "private-value",
        "private-trace-secret",
        "private-contract-value",
        "private-revision-value",
        "private-build-value",
        "private-executable-value",
        "private-timeout-value",
        "private-viewport",
        "private-dom-value",
        "private-hook-mode",
        "private-hook-target",
        "private-input-value",
        "private-script-path",
        "private-resource-mode",
        "private-flag",
        "private-flag-value",
        "private-tenant",
        "private-method-secret",
    ):
        assert secret not in rendered
    assert summary["provenance"]["recorded_hosts"] == ["vendor.example"]
    assert summary["provenance"]["captures_with_manifest_count"] == 1
    assert summary["await_report"]["ended_on"] == "ready"
    assert summary["rehost_contract"]["sha256"] == "a" * 64
    assert summary["method"]["arm_driver"]["supplied"] is True
    assert summary["method"]["arm_declared_script_url"]["shape"]["query_names"] == [
        "token"
    ]


def test_portable_await_report_enforces_count_types_and_ready_coherence() -> None:
    summary = _portable_observation_summary(
        {
            "schema": OBSERVATION_SCHEMA,
            "label": "edited-await",
            "await_report": {
                "ended_on": "ready",
                "signal_kind": "builtin",
                "page_ever_answered": False,
                "waited_seconds": 3.5,
                "polls": 2.5,
                "unresponsive_polls": 99,
            },
        }
    )

    report = summary["await_report"]
    assert report["ended_on"] == "unknown"
    assert "polls" not in report
    assert "unresponsive_polls" not in report
    assert report["waited_seconds"] == 3.5


def test_portable_await_report_rejects_impossible_partitioned_poll_counts() -> None:
    summary = _portable_observation_summary(
        {
            "schema": OBSERVATION_SCHEMA,
            "label": "edited-await-partition",
            "await_report": {
                "ended_on": "cap",
                "signal_kind": "builtin",
                "page_ever_answered": False,
                "waited_seconds": 3.5,
                "polls": 2,
                "unresponsive_polls": 2,
                "failed_polls": 1,
                "slowest_poll": {
                    "issued_at_seconds": 0.0,
                    "duration_seconds": 1.0,
                    "outcome": "failed",
                },
            },
        }
    )

    report = summary["await_report"]
    assert "unresponsive_polls" not in report
    assert "failed_polls" not in report
    assert report["slowest_poll"]["outcome"] == "unknown"


def test_portable_capture_provenance_does_not_truthiness_coerce_flags() -> None:
    summary = _portable_observation_summary(
        {
            "schema": OBSERVATION_SCHEMA,
            "label": "edited",
            "provenance": {
                "status": "VERIFIED",
                "directory_disagrees_with_manifest": "private-truthy-value",
                "asserted_label_is_unverified": "private-truthy-value",
            },
        }
    )

    provenance = summary["provenance"]
    assert provenance["status"] == "unknown"
    assert provenance["directory_disagrees_with_manifest"] is False
    assert provenance["asserted_label_is_unverified"] is True
    assert "private" not in json.dumps(provenance)


def test_portable_summary_reallowlists_resource_intents() -> None:
    summary = _portable_observation_summary(
        {
            "schema": OBSERVATION_SCHEMA,
            "label": "forged",
            "script_sha256_16": "a" * 16,
            "resource_intents": {
                "status": "ok",
                "intents": [
                    {
                        "tag": "iframe",
                        "attribute": "src",
                        "origin": "https://challenges.example",
                        "same_origin_as_rehost": False,
                        "path_segment_lengths": [7, 3],
                        "path_segments_truncated": False,
                        "query_names": ["lang"],
                        "query_names_truncated": False,
                        "raw_url": "https://challenges.example/private-secret?token=value",
                    },
                    {
                        "tag": "iframe",
                        "attribute": "src",
                        "origin": "https://user:password@example/private?token=value",
                        "path_segment_lengths": [7],
                        "query_names": ["token"],
                    },
                ],
                "private_extra": "private-report-secret",
            },
        }
    )
    rendered = json.dumps(summary)
    assert "private-secret" not in rendered
    assert "private-report-secret" not in rendered
    assert "password" not in rendered
    assert summary["resource_intents"]["intents"] == [
        {
            "tag": "iframe",
            "attribute": "src",
            "origin": "https://challenges.example",
            "same_origin_as_rehost": False,
            "path_segment_lengths": [7, 3],
            "path_segments_truncated": False,
            "query_names": ["lang"],
            "query_names_truncated": False,
        }
    ]


def test_portable_resource_intents_close_status_tag_and_attribute_vocabularies() -> (
    None
):
    shape = {
        "origin": "https://static.example",
        "same_origin_as_rehost": False,
        "path_segment_lengths": [12],
        "path_segments_truncated": False,
        "query_names": [],
        "query_names_truncated": False,
    }
    summary = _portable_observation_summary(
        {
            "schema": OBSERVATION_SCHEMA,
            "label": "forged",
            "resource_intents": {
                "status": "private-status",
                "intents": [
                    {
                        **shape,
                        "tag": "private-tenant-widget",
                        "attribute": "src",
                    },
                    {
                        **shape,
                        "tag": "script",
                        "attribute": "private-secret-attribute",
                    },
                ],
            },
        }
    )

    intents = summary["resource_intents"]
    # The invalid attribute drops a supplied row, so the retained inventory is
    # incomplete even though the private status itself projects to "unknown".
    assert intents["status"] == "unverifiable"
    assert intents["intents"] == [{**shape, "tag": "other-element", "attribute": "src"}]
    assert "private" not in json.dumps(intents)

    complete = _portable_observation_summary(
        {
            "schema": OBSERVATION_SCHEMA,
            "label": "forged",
            "resource_intents": {
                "status": "private-status",
                "intents": [{**shape, "tag": "private-tenant-widget", "attribute": "src"}],
            },
        }
    )
    assert complete["resource_intents"]["status"] == "unknown"


def test_portable_resource_intents_retain_closed_unverifiable_arm_statuses() -> None:
    summary = _portable_observation_summary(
        {
            "schema": SUBTRACTION_SCHEMA,
            "arm_label": "truncated",
            "resource_intents": {
                "status": "unverifiable",
                "arm_status": "truncated",
                "control_status": "ok",
                "only_in_arm": [],
                "only_in_control": [],
            },
        }
    )

    assert summary["resource_intents"] == {
        "status": "unverifiable",
        "arm_status": "truncated",
        "control_status": "ok",
        "only_in_arm": [],
        "only_in_control": [],
        "non_claim": "resource intent could not be fully observed",
    }


def test_portable_summary_projects_request_log_without_paths_or_values() -> None:
    summary = _portable_observation_summary(
        {
            "schema": OBSERVATION_SCHEMA,
            "label": "request-redaction",
            "script_sha256_16": "a" * 16,
            "server_requests": [
                {
                    "method": "POST",
                    "path": "/private-tenant/fingerprint?token=private-value",
                    "served": "post-ack",
                    "request_body_bytes": 4880,
                }
            ],
            "unserved_requests": {
                "paths": ["/private-tenant/fingerprint"],
                "private_extra": "private-value",
            },
        }
    )
    rendered = json.dumps(summary)
    assert "private-tenant" not in rendered
    assert "private-value" not in rendered
    assert "unserved_requests" not in summary
    assert summary["request_activity"]["rows"][0]["path_segment_lengths"] == [14, 11]


def test_portable_request_activity_closes_row_enums_and_boolean_receipts() -> None:
    valid_shape = {
        "method": "POST",
        "served": "post-ack",
        "path_segment_lengths": [7],
        "path_segments_truncated": False,
        "query_names": [],
        "query_names_truncated": False,
    }
    summary = _portable_observation_summary(
        {
            "schema": OBSERVATION_SCHEMA,
            "label": "forged",
            "request_activity": {
                "status": "ok",
                "clean_subtraction": "private-truthy-value",
                "truncated": "private-truthy-value",
                "rows": [
                    valid_shape,
                    {**valid_shape, "method": "PRIVATE"},
                    {**valid_shape, "served": "private-tenant-route"},
                    {
                        **valid_shape,
                        "path_segments_truncated": "private-truthy-value",
                    },
                ],
            },
        }
    )

    activity = summary["request_activity"]
    assert activity["rows"] == [valid_shape]
    assert activity["status"] == "unverifiable"
    assert activity["dropped_requests"] == 3
    assert "clean_subtraction" not in activity
    assert activity["truncated"] is True
    assert "private" not in json.dumps(activity)


def test_portable_summary_carries_redacted_input_delivery() -> None:
    summary = _portable_observation_summary(
        {
            "schema": OBSERVATION_SCHEMA,
            "label": "touch",
            "script_sha256_16": "a" * 16,
            "input_probe": {
                "profile": "probe-touch",
                "dispatched": 3,
                "attempted": 3,
                "errors": ["Error: 'private-input-secret'"],
                "trusted": True,
            },
            "ambient_input": {
                "contaminated": False,
                "events": {"touchstart": 1},
                "reasons": ["private-reason-secret"],
            },
        }
    )
    rendered = json.dumps(summary)
    assert "private-input-secret" not in rendered
    assert "private-reason-secret" not in rendered
    assert summary["input_probe"]["dispatched"] == 3
    assert summary["ambient_input"]["trusted_events"] == {"touchstart": 1}


def test_portable_input_delivery_requires_a_valid_error_list_and_profile_relation() -> (
    None
):
    summary = _portable_observation_summary(
        {
            "schema": OBSERVATION_SCHEMA,
            "label": "edited-input",
            "input_probe": {
                "profile": "probe",
                "dispatched": 1,
                "attempted": 1,
                "errors": "private-error-list",
                "trusted": True,
                "touch_dispatched": True,
                "scroll_commands_dispatched": 99,
            },
        }
    )

    probe = summary["input_probe"]
    assert probe["complete"] is False
    assert probe["touch_dispatched"] is False
    assert probe["scroll_commands_dispatched"] == 0
    assert probe["errors"] == []
    assert "private" not in json.dumps(probe)


def test_portable_summary_revalidates_driver_result_metadata() -> None:
    summary = _portable_observation_summary(
        {
            "schema": OBSERVATION_SCHEMA,
            "label": "driver",
            "script_sha256_16": "a" * 16,
            "driver_result": {
                "status": "ok",
                "type": "private-tenant-type",
                "serialized_bytes": ["private-sized-value"],
                "length": True,
                "private_detail": "private-result-value",
            },
        }
    )

    assert summary["driver_result"] == {
        "status": "ok",
        "type": "unknown",
        "serialized_bytes": None,
    }
    assert "private" not in json.dumps(summary)


def test_portable_summary_caps_edited_stage_route_metadata() -> None:
    summary = _portable_observation_summary(
        {
            "schema": SUBTRACTION_SCHEMA,
            "arm_label": "routes",
            "arm_script_sha256_16": "a" * 16,
            "script_attribution_comparable": True,
            "arm_stage_routes": [
                {
                    "path_prefix": f"/stage-{index}",
                    "sha256_16": f"{index:016x}",
                }
                for index in range(129)
            ],
        }
    )

    assert len(summary["stage_routes"]) == 128


def test_portable_summary_reallowlists_request_activity_noise_floor() -> None:
    summary = _portable_observation_summary(
        {
            "schema": "browser-core.product-script-surface-baseline/1",
            "label": "repeat-floor",
            "script_sha256_16": "a" * 16,
            "request_activity_baseline": {
                "status": "ok",
                "arms": 2,
                "stable_shapes": 1,
                "union_shapes": 1,
                "variable_shapes": 1,
                "rows": [
                    {
                        "shape": {
                            "method": "POST",
                            "served": "post-ack",
                            "path_segment_lengths": [13],
                            "path_segments_truncated": False,
                            "query_names": [],
                            "query_names_truncated": False,
                            "raw_path": "/private-tenant/fingerprint",
                        },
                        "arms_present": 2,
                        "count_min": 1,
                        "count_max": 1,
                        "body_bytes_total_min": 4811,
                        "body_bytes_total_max": 4849,
                        "body_bytes_min_min": 4811,
                        "body_bytes_min_max": 4849,
                        "body_bytes_max_min": 4811,
                        "body_bytes_max_max": 4849,
                        "body_digest_coverage_min": 1,
                        "body_digest_coverage_max": 1,
                        "body_digest_multiset_comparable": True,
                        "body_digest_multiset_varies": True,
                        "varies": True,
                        "private_extra": "private-row-secret",
                    }
                ],
                "rows_truncated": False,
                "note": "private-baseline-secret",
            },
        }
    )
    rendered = json.dumps(summary)

    assert "private-tenant" not in rendered
    assert "private-row-secret" not in rendered
    assert "private-baseline-secret" not in rendered
    floor = summary["request_activity_baseline"]
    assert floor["stable_shapes"] == 1
    assert floor["rows"][0]["body_bytes_total_min"] == 4811
    assert floor["rows"][0]["body_bytes_total_max"] == 4849
    assert floor["rows"][0]["body_digest_coverage_min"] == 1
    assert floor["rows"][0]["body_digest_coverage_max"] == 1
    assert floor["rows"][0]["body_digest_multiset_comparable"] is True
    assert floor["rows"][0]["body_digest_multiset_varies"] is True


def test_portable_request_baseline_does_not_truthiness_coerce_receipts() -> None:
    summary = _portable_observation_summary(
        {
            "schema": "browser-core.product-script-surface-baseline/1",
            "label": "edited-floor",
            "request_activity_baseline": {
                "status": "ok",
                "rows_truncated": "private-truthy-value",
                "rows": [
                    {
                        "shape": {
                            "method": "POST",
                            "served": "post-ack",
                            "path_segment_lengths": [4],
                            "path_segments_truncated": False,
                            "query_names": [],
                            "query_names_truncated": False,
                        },
                        "varies": "private-truthy-value",
                    }
                ],
            },
        }
    )

    floor = summary["request_activity_baseline"]
    assert floor["status"] == "unverifiable"
    assert "rows_truncated" not in floor
    assert "rows" not in floor
    assert "private" not in json.dumps(floor)


def test_portable_request_baseline_retains_stable_body_multiset_identity() -> None:
    digest = hashlib.sha256(b'{"aaaaaaaaaaaaaaaa":1}').hexdigest()
    document = {
            "schema": "browser-core.product-script-surface-baseline/1",
            "label": "stable-body-floor",
            "script_sha256_16": "a" * 16,
            "request_activity_baseline": {
                "status": "ok",
                "arms": 2,
                "stable_shapes": 1,
                "union_shapes": 1,
                "variable_shapes": 0,
                "rows": [
                    {
                        "shape": {
                            "method": "POST",
                            "served": "post-ack",
                            "path_segment_lengths": [13],
                            "path_segments_truncated": False,
                            "query_names": [],
                            "query_names_truncated": False,
                        },
                        "arms_present": 2,
                        "count_min": 1,
                        "count_max": 1,
                        "body_bytes_total_min": 4811,
                        "body_bytes_total_max": 4811,
                        "body_bytes_min_min": 4811,
                        "body_bytes_min_max": 4811,
                        "body_bytes_max_min": 4811,
                        "body_bytes_max_max": 4811,
                        "body_digest_coverage_min": 1,
                        "body_digest_coverage_max": 1,
                        "body_digest_multiset_comparable": True,
                        "body_digest_multiset_varies": False,
                        "body_digest_multiset_sha256": digest,
                        "body_digest_multiset_custody": "self_receipt_only",
                        "varies": False,
                    }
                ],
                "rows_truncated": False,
            },
        }
    floor = document["request_activity_baseline"]
    floor["non_claim"] = (
        "loopback request count, byte-length, and complete-body digest variation "
        "only; no body bytes, field semantics, external requests, product response, "
        "or vendor validity; short unkeyed digests are not a confidentiality claim, "
        "and a stable multiset identity has local self-receipt custody only"
    )
    floor["receipt_sha256"] = hashlib.sha256(
        json.dumps(floor, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()

    summary = _portable_observation_summary(document)

    row = summary["request_activity_baseline"]["rows"][0]
    assert row["body_digest_multiset_sha256"] == digest
    assert summary["request_activity_baseline"]["receipt_sha256"] == floor[
        "receipt_sha256"
    ]


def test_portable_summary_reallowlists_only_the_shutdown_mode() -> None:
    summary = _portable_observation_summary(
        {
            "schema": OBSERVATION_SCHEMA,
            "label": "trace-shutdown",
            "script_sha256_16": "a" * 16,
            "browser_shutdown": {
                "mode": "graceful",
                "diagnostic": "private-shutdown-secret",
            },
        }
    )
    assert summary["browser_shutdown"] == {"mode": "graceful"}
    assert "private-shutdown-secret" not in json.dumps(summary)

    hostile = _portable_observation_summary(
        {
            "schema": OBSERVATION_SCHEMA,
            "label": "trace-shutdown",
            "script_sha256_16": "a" * 16,
            "browser_shutdown": {"mode": "private-shutdown-secret"},
        }
    )
    assert "browser_shutdown" not in hostile

    subtraction = _portable_observation_summary(
        {
            "schema": SUBTRACTION_SCHEMA,
            "arm_label": "trace-shutdown",
            "arm_script_sha256_16": "a" * 16,
            "arm_browser_shutdown": {
                "mode": "forced",
                "diagnostic": "private-arm-secret",
            },
            "control_browser_shutdown": {
                "mode": "graceful",
                "diagnostic": "private-control-secret",
            },
        }
    )
    assert subtraction["browser_shutdown"] == {"mode": "forced"}
    assert subtraction["control_browser_shutdown"] == {"mode": "graceful"}
    assert "private-" not in json.dumps(subtraction)


def test_portable_summary_reallowlists_only_bounded_trace_flush_receipts() -> None:
    summary = _portable_observation_summary(
        {
            "schema": SUBTRACTION_SCHEMA,
            "arm_label": "trace-flush",
            "arm_script_sha256_16": "a" * 16,
            "arm_trace_flush": {
                "status": "settled",
                "bytes": 1234,
                "path": "C:/private/trace",
            },
            "control_trace_flush": {
                "status": "present-unsettled",
                "bytes": MAX_TRACE_BYTES + 1,
                "diagnostic": "private-control-secret",
            },
        }
    )
    assert summary["trace_flush"] == {"status": "settled", "bytes": 1234}
    assert summary["control_trace_flush"] == {"status": "present-unsettled"}
    rendered = json.dumps(summary)
    assert "private" not in rendered
    assert "C:/" not in rendered


def test_portable_summary_carries_closed_script_execution_planes() -> None:
    summary = _portable_observation_summary(
        {
            "schema": SUBTRACTION_SCHEMA,
            "arm_label": "blocked",
            "arm_script_sha256_16": "a" * 16,
            "script_attribution_comparable": True,
            "arm_script_execution": {
                "total": 2,
                "complete": 1,
                "open": 1,
                "max_complete_duration_ns": 123_000,
            },
            "control_script_execution": {
                "total": 1,
                "complete": 1,
                "open": 0,
                "max_complete_duration_ns": 100_000,
            },
        }
    )
    assert summary["script_execution"]["open"] == 1
    assert summary["control_script_execution"]["open"] == 0
    assert summary["script_attribution_comparable"] is True

    diagnostic = _portable_observation_summary(
        {
            "schema": OBSERVATION_SCHEMA,
            "label": "failed-blocked",
            "script_sha256_16": "b" * 16,
            "diagnostic_trace_analysis": {
                "script_execution": {
                    "total": 1,
                    "complete": 0,
                    "open": 1,
                    "max_complete_duration_ns": None,
                },
                "private_path": "C:/private/trace",
            },
        }
    )
    assert diagnostic["diagnostic_script_execution"]["open"] == 1
    assert "private" not in json.dumps(diagnostic)


def test_portable_summary_rejects_malformed_script_execution_plane() -> None:
    with pytest.raises(ContractError, match="script execution counts"):
        _portable_observation_summary(
            {
                "schema": SUBTRACTION_SCHEMA,
                "arm_label": "blocked",
                "arm_script_sha256_16": "a" * 16,
                "arm_script_execution": {
                    "total": 1,
                    "complete": 1,
                    "open": 1,
                    "max_complete_duration_ns": 1,
                },
            }
        )


def test_pack_binds_the_source_file_digest(tmp_path: Path) -> None:
    observation = _observation(tmp_path)
    manifest = build_evidence_pack(
        session_path=_session(tmp_path),
        out_dir=tmp_path / "pack",
        product_observation_path=observation,
    )
    entry = manifest["artifacts"]["product_observation"]
    assert len(entry["source_sha256"]) == 64
    assert entry["source_bytes"] == observation.stat().st_size


def test_pack_accepts_a_subtraction_document(tmp_path: Path) -> None:
    path = write_observation(
        tmp_path / "sub.json",
        product_observation._seal_subtraction_document({
            "schema": SUBTRACTION_SCHEMA,
            "generated_at": "2026-08-12T01:02:03Z",
            "non_claims": [
                "control subtraction attributes API names in a lab rehost only",
                "not an acceptance, bypass, evasion, or bot-score claim",
            ],
            "arm_label": "bm-pin-0804",
            "arm_script_sha256_16": "24f57ec4386b918c",
            "script_bytes": 516,
            "control_label": "control",
            "clean_subtraction": True,
            "ready_probe_comparable": True,
            "collector_started": False,
            "rehost_dependencies_complete": False,
            "surface_claim_ready": False,
            "attributed_api_names": 1,
            "arm_driver": {
                "supplied": True,
                "bytes": 12,
                "sha256_16": "3" * 16,
            },
            "arm_driver_supplied": True,
            "arm_script_execution": {
                "total": 2,
                "complete": 1,
                "open": 1,
                "max_complete_duration_ns": 123_000,
            },
            "control_script_execution": {
                "total": 1,
                "complete": 1,
                "open": 0,
                "max_complete_duration_ns": 100_000,
            },
            "arm_stage_routes": [
                {"path_prefix": "/tenant/mfc", "bytes": 99, "sha256_16": "4" * 16}
            ],
            "arm_resource_intent_capture": "cdp_dom_snapshot/1",
            "resource_intents": product_observation.subtract_resource_intents(
                {
                    "status": "ok",
                    "truncated": False,
                    "intents": [
                        {
                            "tag": "iframe",
                            "attribute": "src",
                            "origin": "https://challenges.example",
                            "path_segment_lengths": [5],
                            "query_names": ["lang"],
                        }
                    ],
                },
                {"status": "ok", "truncated": False, "intents": []},
            ),
            "only_in_arm": {"api.Navigator.webdriver.get": 2},
        }),
    )
    manifest = build_evidence_pack(
        session_path=_session(tmp_path),
        out_dir=tmp_path / "pack",
        product_observation_path=path,
    )
    summary = manifest["artifacts"]["product_observation"]["summary"]
    assert summary["attributed_api_names"] == 1
    assert summary["clean_subtraction"] is True
    assert summary["ready_probe_comparable"] is True
    assert summary["collector_started"] is False
    assert summary["rehost_dependencies_complete"] is False
    assert summary["surface_claim_ready"] is False
    assert summary["script_sha256_16"] == "24f57ec4386b918c"
    assert summary["driver"]["sha256_16"] == "3" * 16
    assert summary["stage_routes"][0]["sha256_16"] == "4" * 16
    assert summary["resource_intent_capture"] == "cdp_dom_snapshot/1"
    assert summary["resource_intents"]["only_in_arm"][0]["tag"] == "iframe"
    assert summary["script_execution"]["open"] == 1
    assert summary["driver_supplied"] is True
    assert load_evidence_pack_manifest(tmp_path / "pack" / "manifest.json")


@pytest.mark.parametrize(
    "schema", ["something-else/1", ["other/1"], {"name": "other/1"}]
)
def test_pack_rejects_a_foreign_document(tmp_path: Path, schema) -> None:
    path = tmp_path / "foreign.json"
    path.write_text(json.dumps({"schema": schema}), encoding="utf-8")
    with pytest.raises(ContractError, match="not a product-script observation"):
        build_evidence_pack(
            session_path=_session(tmp_path),
            out_dir=tmp_path / "pack",
            product_observation_path=path,
        )


def test_pack_without_observation_is_unchanged(tmp_path: Path) -> None:
    manifest = build_evidence_pack(
        session_path=_session(tmp_path), out_dir=tmp_path / "pack"
    )
    assert "product_observation" not in manifest["artifacts"]
    assert load_evidence_pack_manifest(tmp_path / "pack" / "manifest.json")


def test_builder_refuses_to_publish_a_non_idempotent_portable_projection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    original = evidence_pack_module._portable_observation_summary

    def non_idempotent(document: dict) -> dict:
        projected = original(document)
        if "script_identity" in document:
            projected["script_bytes"] = 123
        else:
            projected.pop("script_bytes", None)
        return projected

    monkeypatch.setattr(
        evidence_pack_module,
        "_portable_observation_summary",
        non_idempotent,
    )
    out = tmp_path / "pack"

    with pytest.raises(ContractError, match="portable product-observation values"):
        build_evidence_pack(
            session_path=_session(tmp_path),
            out_dir=out,
            product_observation_path=_observation(tmp_path),
        )

    assert not out.exists()


def test_loader_rejects_rehashed_extra_portable_observation_field(
    tmp_path: Path,
) -> None:
    out = tmp_path / "pack"
    build_evidence_pack(
        session_path=_session(tmp_path),
        out_dir=out,
        product_observation_path=_observation(tmp_path),
    )
    portable_path = out / "product-observation.json"
    portable = json.loads(portable_path.read_text(encoding="utf-8"))
    portable["private_path"] = r"C:\\private\\customer.txt"
    body = (json.dumps(portable, sort_keys=True) + "\n").encode("utf-8")
    portable_path.write_bytes(body)
    manifest_path = out / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    entry = manifest["artifacts"]["product_observation"]
    entry["summary"] = portable
    entry["bytes"] = len(body)
    entry["sha256"] = hashlib.sha256(body).hexdigest()
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(ContractError, match="portable product-observation fields"):
        load_evidence_pack_manifest(manifest_path)


def test_loader_rejects_rehashed_nested_portable_observation_values(
    tmp_path: Path,
) -> None:
    out = tmp_path / "pack"
    build_evidence_pack(
        session_path=_session(tmp_path),
        out_dir=out,
        product_observation_path=_observation(
            tmp_path,
            ambient_input={
                "contaminated": False,
                "events": {"touchstart": 1},
            },
        ),
    )
    portable_path = out / "product-observation.json"
    portable = json.loads(portable_path.read_text(encoding="utf-8"))
    portable["ambient_input"]["private_detail"] = r"C:\private\customer.txt"
    body = (json.dumps(portable, sort_keys=True) + "\n").encode("utf-8")
    portable_path.write_bytes(body)
    manifest_path = out / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    entry = manifest["artifacts"]["product_observation"]
    entry["summary"] = portable
    entry["bytes"] = len(body)
    entry["sha256"] = hashlib.sha256(body).hexdigest()
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(ContractError, match="portable product-observation values"):
        load_evidence_pack_manifest(manifest_path)


@pytest.mark.parametrize("malformed_coverage", [[], {}])
def test_loader_rejects_unhashable_fetch_target_coverage_cleanly(
    tmp_path: Path, malformed_coverage: object
) -> None:
    out = tmp_path / "pack"
    build_evidence_pack(
        session_path=_session(tmp_path),
        out_dir=out,
        product_observation_path=_observation(tmp_path),
    )
    portable_path = out / "product-observation.json"
    portable = json.loads(portable_path.read_text(encoding="utf-8"))
    portable["fetch_target_scope"]["coverage"] = malformed_coverage
    body = (json.dumps(portable, sort_keys=True) + "\n").encode("utf-8")
    portable_path.write_bytes(body)
    manifest_path = out / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    entry = manifest["artifacts"]["product_observation"]
    entry["summary"] = portable
    entry["bytes"] = len(body)
    entry["sha256"] = hashlib.sha256(body).hexdigest()
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(ContractError, match="portable product-observation values"):
        load_evidence_pack_manifest(manifest_path)


def test_summary_drops_absent_fields_rather_than_emitting_nulls() -> None:
    summary = _portable_observation_summary(
        {"schema": OBSERVATION_SCHEMA, "label": "x", "script_sha256_16": "a" * 16}
    )
    assert set(summary) == {"schema", "label", "script_sha256_16"}


def test_portable_claim_receipts_require_boolean_values() -> None:
    summary = _portable_observation_summary(
        {
            "schema": SUBTRACTION_SCHEMA,
            "arm_label": "edited",
            "arm_script_sha256_16": "a" * 16,
            "clean_subtraction": "private-clean-value",
            "ready_probe_comparable": "private-ready-value",
            "collector_started": "private-startup-value",
            "rehost_dependencies_complete": "private-dependency-value",
            "surface_claim_ready": "private-claim-value",
        }
    )

    rendered = json.dumps(summary)
    assert "clean_subtraction" not in summary
    assert "ready_probe_comparable" not in summary
    assert "collector_started" not in summary
    assert "rehost_dependencies_complete" not in summary
    assert "surface_claim_ready" not in summary
    assert "private-" not in rendered


@pytest.mark.parametrize("clean_gate", [None, "missing"])
def test_portable_subtraction_ready_claim_requires_a_clean_receipt(clean_gate) -> None:
    document = {
        "schema": SUBTRACTION_SCHEMA,
        "arm_label": "edited-clean",
        "arm_script_sha256_16": "a" * 16,
        "clean_subtraction": clean_gate,
        "surface_claim_ready": True,
    }
    if clean_gate == "missing":
        document.pop("clean_subtraction")
    summary = _portable_observation_summary(document)
    assert summary["surface_claim_ready"] is False


def test_portable_raw_observation_cannot_claim_subtraction_readiness() -> None:
    summary = _portable_observation_summary({
        "schema": OBSERVATION_SCHEMA,
        "label": "raw",
        "script_sha256_16": "a" * 16,
        "surface_claim_ready": True,
    })
    assert "surface_claim_ready" not in summary


@pytest.mark.parametrize(
    "gate",
    [
        "clean_subtraction",
        "ready_probe_comparable",
        "arm_control_method_comparable",
        "driver_execution_complete",
        "script_identity_coherent",
        "trace_evidence_coherent",
        "await_method_comparable",
        "arm_readiness_satisfied",
        "input_method_comparable",
        "ambient_input_clean",
        "collector_started",
        "collector_startup_coherent",
        "control_collector_startup_coherent",
        "startup_derivation_coherent",
        "rehost_dependencies_complete",
        "control_rehost_dependencies_complete",
        "rehost_receipts_coherent",
        "request_activity_receipts_coherent",
        "page_load_execution_coherent",
        "offline_guard_comparable",
    ],
)
def test_portable_surface_claim_cannot_contradict_a_negative_gate(gate: str) -> None:
    summary = _portable_observation_summary(
        {
            "schema": SUBTRACTION_SCHEMA,
            "arm_label": "edited-gate",
            "arm_script_sha256_16": "a" * 16,
            "surface_claim_ready": True,
            gate: False,
        }
    )

    assert summary[gate] is False
    assert summary["surface_claim_ready"] is False


def test_portable_guard_receipt_is_normalized_idempotent_and_claim_gating() -> None:
    raw_guard = {
        "status": "applied",
        "resolver_rule": (
            "--host-resolver-rules=" "MAP 127.0.0.1 127.0.0.1:43123, MAP * ^NOTFOUND"
        ),
        "proxy_policy": "deny-all-except-owned-loopback-origin",
        "webrtc_policy": "disable-non-proxied-udp",
        "quic_policy": "disabled",
        "proxy_endpoint": "127.0.0.1:43123",
        "bypass_endpoint": "127.0.0.1:43123",
    }
    document = {
        "schema": SUBTRACTION_SCHEMA,
        "arm_label": "guarded",
        "arm_script_sha256_16": "a" * 16,
        "clean_subtraction": True,
        "surface_claim_ready": True,
        "offline_guard_comparable": True,
        "arm_offline_guard": raw_guard,
    }

    summary = _portable_observation_summary(document)

    assert summary["offline_guard"]["status"] == "applied"
    assert summary["offline_guard_comparable"] is True
    assert summary["surface_claim_ready"] is True
    assert "43123" not in json.dumps(summary["offline_guard"])
    assert _portable_observation_summary(summary) == summary
    document["arm_offline_guard"] = dict(raw_guard, bypass_endpoint="127.0.0.1:43124")

    edited = _portable_observation_summary(document)

    assert edited["offline_guard"] == {"status": "unverifiable"}
    assert edited["surface_claim_ready"] is False
    document["arm_offline_guard"] = raw_guard
    document["offline_guard_comparable"] = False
    assert _portable_observation_summary(document)["surface_claim_ready"] is False
    document["offline_guard_comparable"] = True
    document["rehost_receipts_coherent"] = False
    receipt_edited = _portable_observation_summary(document)
    assert receipt_edited["rehost_receipts_coherent"] is False
    assert receipt_edited["surface_claim_ready"] is False
    document["rehost_receipts_coherent"] = True
    document["collector_startup_coherent"] = False
    startup_edited = _portable_observation_summary(document)
    assert startup_edited["collector_startup_coherent"] is False
    assert startup_edited["surface_claim_ready"] is False
    document["collector_startup_coherent"] = True
    for gate in ("input_method_comparable", "ambient_input_clean"):
        document[gate] = False
        gated = _portable_observation_summary(document)
        assert gated[gate] is False
        assert gated["surface_claim_ready"] is False
        document[gate] = True


@pytest.mark.parametrize(
    "trace_category_contract",
    ["browser-core.trace-categories/1", "browser-core.trace-categories/2"],
)
def test_portable_summary_retains_only_supported_trace_category_contracts(
    trace_category_contract: str,
) -> None:
    summary = _portable_observation_summary(
        {
            "schema": OBSERVATION_SCHEMA,
            "label": "pin",
            "trace_scope": "broad",
            "trace_category_contract": trace_category_contract,
        }
    )

    assert summary["trace_scope"] == "broad"
    assert summary["trace_category_contract"] == trace_category_contract


def test_portable_summary_drops_vendor_shaped_trace_contract_text() -> None:
    summary = _portable_observation_summary(
        {
            "schema": OBSERVATION_SCHEMA,
            "label": "pin",
            "trace_category_contract": "private.vendor-contract/9",
        }
    )

    assert "trace_category_contract" not in summary


def test_portable_top_level_method_fields_are_typed_and_allowlisted() -> None:
    summary = _portable_observation_summary(
        {
            "schema": OBSERVATION_SCHEMA,
            "label": "private/label",
            "script_sha256_16": "private-digest",
            "trace_scope": "private-trace-scope",
            "trace_category_contract": "private category contract",
            "chromium_revision": "private-revision",
            "run_id": "private/run-id",
            "dwell_seconds": "private-dwell",
            "timeout_seconds": float("inf"),
            "inline_script": "private-inline",
            "reloads": "private-reloads",
            "hook_mode": "private-hook-mode",
            "hook_target_names": ["private-hook-target"],
            "attributed_api_names": "private-count",
            "control_label": "private/control",
            "resource_intent_capture": "private-resource-contract",
            "browser_build": {
                "provenance": "attested-browser-core",
                "executable_sha256_16": "b" * 16,
                "attestation_created_at": "private-attestation-time",
            },
            "analysis": {
                "total_events": "private-total",
                "distinct_api_names": "private-names",
                "attributable_events": "private-events",
                "attributable_fraction": "private-fraction",
                "request_methods": {"PRIVATE-METHOD": 7},
                "distinct_request_classes": "private-classes",
                "fetch_target_scope": {
                    "coverage": "complete",
                    "requests": 0,
                    "loopback": 0,
                    "external": 0,
                    "non_network": 0,
                    "unclassified": 0,
                },
            },
        }
    )

    assert summary == {
        "schema": OBSERVATION_SCHEMA,
        "browser_build": {
            "provenance": "attested-browser-core",
            "executable_sha256_16": "b" * 16,
        },
        "request_methods": {},
        "fetch_target_scope": {
            "coverage": "complete",
            "requests": 0,
            "loopback": 0,
            "external": 0,
            "non_network": 0,
            "unclassified": 0,
        },
    }


def test_portable_closed_enums_ignore_unhashable_json_values() -> None:
    summary = _portable_observation_summary(
        {
            "schema": OBSERVATION_SCHEMA,
            "label": "edited-enums",
            "trace_scope": {"private": "value"},
            "trace_category_contract": ["private-contract"],
            "resource_intent_capture": {"private": "contract"},
            "arm_stage_routes": 1,
        }
    )

    assert summary == {
        "schema": OBSERVATION_SCHEMA,
        "label": "edited-enums",
        "stage_routes": [],
    }


def test_seeded_hostile_portable_projection_is_idempotent_or_rejects_cleanly() -> None:
    rng = random.Random(20260811)
    strings = [
        "",
        "ok",
        "private-tenant-value",
        "browser-core.trace-categories/2",
        "a" * 16,
        "a" * 64,
        "https://private.example/path?token=value",
        "POST",
        "post-ack",
    ]
    top_keys = sorted(PORTABLE_OBSERVATION_KEYS) + [
        "analysis",
        "arm_driver",
        "arm_stage_routes",
        "arm_trace_flush",
        "diagnostic_trace_analysis",
        "script_identity",
        "server_requests",
    ]
    nested_keys = [
        "attempted",
        "bytes",
        "complete",
        "errors",
        "intents",
        "method",
        "open",
        "path_segment_lengths",
        "profile",
        "query_names",
        "rows",
        "served",
        "shape",
        "status",
        "supplied",
        "total",
        "truncated",
        "varies",
    ]

    def hostile(depth: int = 0):
        kind = rng.randrange(6 if depth < 2 else 4)
        if kind == 0:
            return None
        if kind == 1:
            return rng.choice([True, False])
        if kind == 2:
            return rng.choice([-1, 0, 1, 99, 10**12, 1.5])
        if kind == 3:
            return rng.choice(strings)
        if kind == 4:
            return [hostile(depth + 1) for _ in range(rng.randrange(4))]
        return {
            rng.choice(nested_keys): hostile(depth + 1) for _ in range(rng.randrange(5))
        }

    for _ in range(5_000):
        document = {
            "schema": rng.choice(
                [OBSERVATION_SCHEMA, SUBTRACTION_SCHEMA, BASELINE_SCHEMA]
            )
        }
        for key in rng.sample(top_keys, rng.randrange(min(16, len(top_keys)) + 1)):
            document[key] = hostile()
        try:
            once = _portable_observation_summary(document)
            twice = _portable_observation_summary(once)
        except ContractError:
            continue
        assert twice == once


def test_every_portable_top_level_field_handles_each_json_value_class_cleanly() -> None:
    values = [
        None,
        True,
        False,
        0,
        1,
        -1,
        1.5,
        "",
        "private-value",
        [],
        [1],
        {},
        {"private": "value"},
    ]

    for key in sorted(PORTABLE_OBSERVATION_KEYS):
        for value in values:
            document = {
                "schema": OBSERVATION_SCHEMA,
                "label": "field-matrix",
                "script_sha256_16": "a" * 16,
                key: value,
            }
            try:
                once = _portable_observation_summary(document)
                twice = _portable_observation_summary(once)
            except ContractError:
                continue
            assert twice == once, (key, value)


def test_every_portable_session_field_handles_each_json_value_class_cleanly() -> None:
    base = {
        "schema": "browser-core.session/1",
        "run_id": "field-matrix",
        "state": "stopped",
        "chromium_revision": "a" * 40,
        "has_automation_endpoint": False,
        "has_trace_path": False,
    }
    keys = [
        "schema",
        "run_id",
        "state",
        "chromium_revision",
        "created_at",
        "stopped_at",
        "trace_mode",
        "trace_scope",
        "trace_categories",
        "trace_category_contract",
        "build_provenance",
        "executable_sha256_16",
        "has_automation_endpoint",
        "has_trace_path",
        "persona_sha256_16",
        "network_route_sha256_16",
    ]
    values = [
        None,
        True,
        False,
        0,
        1,
        -1,
        1.5,
        "",
        "on",
        "causal",
        [],
        [1],
        {},
        {"private": "value"},
    ]

    for key in keys:
        for value in values:
            summary = {**base, key: value}
            try:
                _validate_portable_session_summary(
                    summary,
                    manifest_run_id="field-matrix",
                )
            except ContractError:
                pass

    for value in values:
        summary = {
            **base,
            "trace_mode": "on",
            "trace_scope": value,
            "trace_categories": ["disabled-by-default-devtools.timeline"],
            "trace_category_contract": "browser-core.trace-categories/2",
        }
        try:
            _validate_portable_session_summary(
                summary,
                manifest_run_id="field-matrix",
            )
        except ContractError:
            pass


@pytest.mark.parametrize("malformed_scope", [[], ["causal"], {}, {"scope": "causal"}])
def test_portable_session_summary_rejects_unhashable_trace_scopes_cleanly(
    malformed_scope,
) -> None:
    summary = {
        "schema": "browser-core.session/1",
        "run_id": "hostile-session",
        "state": "stopped",
        "chromium_revision": "a" * 40,
        "has_automation_endpoint": False,
        "has_trace_path": True,
        "trace_mode": "on",
        "trace_scope": malformed_scope,
        "trace_categories": ["disabled-by-default-devtools.timeline"],
        "trace_category_contract": "browser-core.trace-categories/2",
    }

    with pytest.raises(ContractError, match="trace scope is invalid"):
        _validate_portable_session_summary(
            summary,
            manifest_run_id="hostile-session",
        )


@pytest.mark.parametrize(
    "malformed_receipt",
    [
        None,
        "not-a-receipt",
        {"coverage": "complete"},
        {
            "coverage": "complete",
            "requests": 0,
            "loopback": 1,
            "external": 0,
            "non_network": 0,
            "unclassified": 0,
        },
        {
            "coverage": "complete",
            "requests": 1,
            "loopback": 0,
            "external": 0,
            "non_network": 0,
            "unclassified": 1,
        },
        {
            "coverage": "unknown",
            "requests": 0,
            "loopback": 0,
            "external": 0,
            "non_network": 0,
            "unclassified": 0,
        },
        0,
        False,
    ],
)
def test_portable_summary_does_not_invent_fetch_target_scope_evidence(
    malformed_receipt,
) -> None:
    summary = _portable_observation_summary(
        {
            "schema": OBSERVATION_SCHEMA,
            "analysis": {"fetch_target_scope": malformed_receipt},
        }
    )

    assert "fetch_target_scope" not in summary


def test_portable_build_timestamp_requires_timezone_aware_iso() -> None:
    summary = _portable_observation_summary(
        {
            "schema": OBSERVATION_SCHEMA,
            "label": "pin",
            "script_sha256_16": "a" * 16,
            "browser_build": {
                "provenance": "attested-browser-core",
                "executable_sha256_16": "b" * 16,
                "attestation_created_at": "2026-08-09T12:34:56-05:00",
            },
        }
    )

    assert summary["browser_build"]["attestation_created_at"] == (
        "2026-08-09T12:34:56-05:00"
    )
