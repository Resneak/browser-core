from __future__ import annotations

import copy
import hashlib
import io
import itertools
import json
import os
import re
import subprocess
import threading
import urllib.error
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace

import pytest

import browser_core.personas as personas_module
from browser_core.control_files import canonical_json_bytes
from browser_core.contracts import ContractError
from browser_core.personas import (
    ALLOWED_PRODUCTS,
    AUDIT_SCHEMA,
    COMMERCIAL_COMPARE_SCHEMA,
    COVERAGE_SCHEMA,
    VOLUME_SCHEMA,
    add_persona,
    assign_persona,
    audit_persona_catalog,
    build_persona,
    bulk_capture_personas,
    bulk_capture_personas_batched,
    capture_kernel_persona,
    capture_physical_android_persona,
    capture_profile_persona,
    catalog_coverage_report,
    catalog_volume_report,
    compare_commercial_volume,
    collect_persona_bundle_evidence,
    count_kameleo_operator_inventory,
    export_persona_bundle,
    export_persona_bundle_from_workspace,
    import_persona_bundle,
    infer_os_from_device_preset,
    list_personas,
    load_persona,
    load_persona_evidence,
    persona_from_kernel_probe,
    persona_compatible,
    persona_digest,
    plan_bulk_capture_matrix,
    search_personas,
    set_persona_state,
    store_persona_evidence,
    validate_catalog_coverage_report,
    validate_catalog_audit_report,
    validate_catalog_volume_report,
    validate_bulk_capture_report,
    validate_commercial_volume_report,
    validate_kameleo_inventory_report,
    validate_persona,
)
from browser_core.profiles import attach_identity_contract, create_profile

PHYSICAL_PROBE_FIXTURE_CHECKS = (
    "owned_fixture", "android_user_agent", "touch", "viewport",
    "locale", "timezone", "rendering",
)


def fixture_persona(
    persona_id: str = "win-core-153", *, product: str = "browser-core"
) -> dict:
    evidence = {"schema": "owned-fixture/1", "source": "controlled-coherence"}
    return build_persona(
        persona_id=persona_id,
        name="Owned Windows Chromium 153",
        tags=("owned", "windows"),
        device={
            "class": "desktop",
            "os_family": "windows",
            "os_version": "11",
            "architecture": "x86_64",
            "is_mobile": False,
            "has_touch": False,
            "viewport": {
                "width": 2560,
                "height": 1440,
                "device_scale_factor": 1,
                "orientation": "landscape",
            },
            "screen": {"width": 2560, "height": 1440},
        },
        kernel={
            "engine": "chromium",
            "product": product,
            "minimum_major": 153,
            "maximum_major": 153,
        },
        geography={
            "country": "US",
            "locale": "en-US",
            "languages": ["en-US"],
            "timezone": "America/Chicago",
        },
        identity_contract={
            "schema_version": 1,
            "expected": {
                "userAgentData.mobile": False,
                "window.platform": "Win32",
            },
        },
        provenance={
            "kind": "owned-capture",
            "source": "controlled-coherence fixture",
            "source_sha256": hashlib.sha256(
                json.dumps(evidence, sort_keys=True, separators=(",", ":")).encode(
                    "utf-8"
                )
            ).hexdigest(),
            "captured_at": "2026-08-03T00:00:00Z",
        },
    )


@pytest.mark.parametrize("persona_id", ["NUL", "con.log", "LPT9.backup"])
def test_persona_builder_rejects_windows_device_basename(persona_id: str) -> None:
    with pytest.raises(ContractError, match="persona ID"):
        fixture_persona(persona_id)


def test_persona_store_rejects_device_basename_before_creating_catalog(
    tmp_path: Path,
) -> None:
    persona = fixture_persona("safe-persona")
    persona["id"] = "NUL"
    persona["integrity_sha256"] = persona_digest(persona)
    with pytest.raises(ContractError, match="persona ID"):
        add_persona(tmp_path, persona)
    assert not (tmp_path / "personas").exists()


def test_build_persona_detaches_caller_owned_inputs() -> None:
    base = fixture_persona("source")
    device = copy.deepcopy(base["device"])
    kernel = copy.deepcopy(base["kernel"])
    geography = copy.deepcopy(base["geography"])
    provenance = copy.deepcopy(base["provenance"])
    persona = build_persona(
        persona_id="detached-builder",
        name="Detached builder",
        tags=base["tags"],
        device=device,
        kernel=kernel,
        geography=geography,
        identity_contract=base["identity_contract"],
        provenance=provenance,
    )
    device["screen"]["width"] = 1
    kernel["product"] = "edge"
    geography["languages"][0] = "fr-FR"
    provenance["source"] = "caller-changed"

    assert persona["device"]["screen"]["width"] == 2560
    assert persona["kernel"]["product"] == "browser-core"
    assert persona["geography"]["languages"] == ["en-US"]
    assert persona["provenance"]["source"] == "controlled-coherence fixture"
    assert persona_digest(persona) == persona["integrity_sha256"]


@pytest.mark.parametrize(
    "path",
    [
        ("state",),
        ("device", "class"),
        ("device", "os_family"),
        ("device", "architecture"),
        ("device", "viewport", "orientation"),
        ("kernel", "engine"),
        ("kernel", "product"),
        ("provenance", "kind"),
    ],
)
def test_persona_contract_rejects_unhashable_json_enums(path: tuple[str, ...]) -> None:
    document = fixture_persona()
    target = document
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = []
    with pytest.raises(ContractError):
        validate_persona(document)


def test_persona_tags_reject_casefold_duplicates() -> None:
    source = fixture_persona()
    with pytest.raises(ContractError, match="tags"):
        build_persona(
            persona_id="duplicate-tags",
            name=source["name"],
            tags=("Owned", "owned"),
            device=source["device"],
            kernel=source["kernel"],
            geography=source["geography"],
            identity_contract=source["identity_contract"],
            provenance=source["provenance"],
        )


def test_catalog_roundtrip_search_and_exact_compatibility(tmp_path: Path) -> None:
    evidence = {"schema": "owned-fixture/1", "source": "controlled-coherence"}
    persona = fixture_persona()
    store_persona_evidence(
        tmp_path,
        evidence,
        expected_sha256=persona["provenance"]["source_sha256"],
    )
    assert add_persona(tmp_path, persona) == persona
    assert add_persona(tmp_path, persona) == persona
    assert list_personas(tmp_path) == [persona]
    assert search_personas(
        tmp_path, engine="chromium", major=153, country="US", tags=("owned",)
    ) == [persona]
    assert search_personas(tmp_path, major=152) == []
    assert search_personas(
        tmp_path, os_family="windows", locale="en-US", language="en-US"
    ) == [persona]
    assert search_personas(tmp_path, os_family="linux") == []
    assert search_personas(tmp_path, locale="de-DE") == []
    assert search_personas(tmp_path, min_major=150, max_major=160) == [persona]
    assert search_personas(tmp_path, min_major=140, max_major=150) == []
    assert persona_compatible(
        persona,
        engine="chromium",
        product="browser-core",
        major=153,
        device_class="desktop",
    )
    assert not persona_compatible(
        persona, engine="chromium", product="chrome", major=153, device_class="desktop"
    )
    coverage = catalog_coverage_report(tmp_path)
    assert coverage["schema"] == COVERAGE_SCHEMA
    assert coverage["active"] == 1
    assert "windows" in coverage["axes"]["os_family"]
    assert coverage["quality_gates"]["provenance_allowed_only"] is True
    assert coverage["quality_gates"]["audit_passed"] is True


def test_catalog_audit_recomputes_population_axes_and_verdict(tmp_path: Path) -> None:
    evidence = {"schema": "owned-fixture/1", "source": "controlled-coherence"}
    persona = fixture_persona()
    store_persona_evidence(
        tmp_path, evidence, expected_sha256=persona["provenance"]["source_sha256"]
    )
    add_persona(tmp_path, persona)
    report = json.loads(json.dumps(audit_persona_catalog(tmp_path)))
    assert report["schema"] == AUDIT_SCHEMA
    assert validate_catalog_audit_report(report) is report

    mutations = []
    for path, replacement in (
        (("schema",), "private-audit-schema-marker"),
        (("passed",), False),
        (("personas",), 2),
        (("active",), 0),
        (("engines",), []),
        (("device_classes",), []),
        (("verified_sha256",), "0" * 64),
        (("verified", 0, "id"), "private-audit-id-marker"),
        (("verified", 0, "persona_sha256_16"), "0" * 16),
        (("verified", 0, "source_sha256_16"), "0" * 16),
        (("verified", 0, "evidence_kind"), "private-audit-kind-marker"),
        (("verified", 0, "state"), "deprecated"),
        (("verified", 0, "engine"), "firefox"),
        (("verified", 0, "device_class"), "mobile"),
    ):
        mutation = copy.deepcopy(report)
        target = mutation
        for segment in path[:-1]:
            target = target[segment]
        target[path[-1]] = replacement
        mutations.append(mutation)
    extra = copy.deepcopy(report)
    extra["private"] = "private-audit-field-marker"
    mutations.append(extra)

    for mutation in mutations:
        with pytest.raises(ContractError) as failure:
            validate_catalog_audit_report(mutation)
        assert "private-audit" not in str(failure.value)


@pytest.mark.parametrize("mutation", ["content", "population"])
@pytest.mark.parametrize("reporter", [audit_persona_catalog, catalog_coverage_report])
def test_catalog_audit_rechecks_saved_catalog_after_evidence_verification(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mutation: str, reporter
) -> None:
    persona = fixture_persona("audit-race")
    evidence = {"schema": "owned-fixture/1", "source": "controlled-coherence"}
    store_persona_evidence(
        tmp_path, evidence, expected_sha256=persona["provenance"]["source_sha256"]
    )
    add_persona(tmp_path, persona)
    path = tmp_path / "personas" / "catalog" / "audit-race.json"
    competitor = copy.deepcopy(persona)
    competitor["name"] = "Competing audit revision"
    competitor["integrity_sha256"] = persona_digest(competitor)
    competitor_bytes = canonical_json_bytes(competitor)
    original_load = personas_module._load_persona_evidence_counted

    def change_after_evidence(workspace: Path, digest: str):
        document = original_load(workspace, digest)
        if mutation == "content":
            path.write_bytes(competitor_bytes)
        else:
            add_persona(tmp_path, fixture_persona("audit-appeared"))
        return document

    monkeypatch.setattr(personas_module, "_load_persona_evidence_counted", change_after_evidence)
    with pytest.raises(ContractError, match="catalog changed during audit"):
        reporter(tmp_path)
    if mutation == "content":
        assert path.read_bytes() == competitor_bytes
    else:
        assert (path.parent / "audit-appeared.json").exists()


def test_catalog_audit_rejects_dangling_profile_registry_entry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    persona = fixture_persona("dangling-profile-source")
    persona["provenance"]["source"] = "profile:missing-source"
    persona["integrity_sha256"] = persona_digest(persona)
    evidence = {"schema": "owned-fixture/1", "source": "controlled-coherence"}
    store_persona_evidence(
        tmp_path, evidence, expected_sha256=persona["provenance"]["source_sha256"]
    )
    add_persona(tmp_path, persona)
    registry = tmp_path / "profiles" / "registry" / "missing-source.json"
    registry.parent.mkdir(parents=True)
    try:
        registry.symlink_to(tmp_path / "nonexistent-profile.json")
    except OSError:
        # Windows hosts without file-symlink privilege still need to exercise
        # the Path.exists()/lexists() split made by a dangling registry link.
        registry.write_bytes(b"invalid registry")
        original_exists = Path.exists

        def follows_missing_target(path: Path) -> bool:
            return False if path == registry else original_exists(path)

        monkeypatch.setattr(Path, "exists", follows_missing_target)

    with pytest.raises(ContractError):
        audit_persona_catalog(tmp_path)
    registry.unlink()
    assert (
        audit_persona_catalog(tmp_path)["verified"][0]["evidence_kind"]
        == "bundled-profile-identity-contract"
    )


def test_catalog_audit_rechecks_live_profile_source_after_final_catalog_scan(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    profile_id = "audit-profile-source"
    persona = fixture_persona("audit-profile-capture")
    identity = persona["identity_contract"]
    canonical_identity = canonical_json_bytes(identity)
    persona["provenance"]["source"] = f"profile:{profile_id}"
    persona["provenance"]["source_sha256"] = hashlib.sha256(
        canonical_identity
    ).hexdigest()
    persona["integrity_sha256"] = persona_digest(persona)
    create_profile(tmp_path, profile_id)
    identity_file = tmp_path / "source-identity.json"
    identity_file.write_bytes(canonical_identity)
    attach_identity_contract(tmp_path, profile_id, identity_file)
    add_persona(tmp_path, persona)
    saved_identity = (
        tmp_path / "profiles" / "data" / profile_id / "identity-contract.json"
    )
    competitor = canonical_json_bytes(
        {"schema_version": 1, "expected": {"window.platform": "changed"}}
    )
    original_check = personas_module._require_persona_report_catalog

    def change_after_catalog_check(*args, **kwargs):
        original_check(*args, **kwargs)
        saved_identity.write_bytes(competitor)

    monkeypatch.setattr(personas_module, "_require_persona_report_catalog", change_after_catalog_check)
    with pytest.raises(ContractError, match="profile"):
        audit_persona_catalog(tmp_path)
    assert saved_identity.read_bytes() == competitor


@pytest.mark.parametrize("reporter", [audit_persona_catalog, catalog_coverage_report])
def test_catalog_audit_rechecks_bundled_evidence_after_final_catalog_scan(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, reporter
) -> None:
    persona = fixture_persona("audit-bundled-source")
    persona["provenance"]["source"] = "profile:missing-source"
    persona["integrity_sha256"] = persona_digest(persona)
    evidence = {"schema": "owned-fixture/1", "source": "controlled-coherence"}
    digest = persona["provenance"]["source_sha256"]
    store_persona_evidence(tmp_path, evidence, expected_sha256=digest)
    add_persona(tmp_path, persona)
    path = tmp_path / "personas" / "evidence" / f"{digest}.json"
    original_check = personas_module._require_persona_report_catalog

    def remove_after_catalog_check(*args, **kwargs):
        original_check(*args, **kwargs)
        path.unlink()

    monkeypatch.setattr(personas_module, "_require_persona_report_catalog", remove_after_catalog_check)
    with pytest.raises(ContractError, match="saved evidence changed during audit"):
        reporter(tmp_path)
    assert not path.exists()


@pytest.mark.parametrize("reporter", [audit_persona_catalog, catalog_coverage_report])
def test_catalog_audit_rechecks_content_evidence_after_final_catalog_scan(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, reporter
) -> None:
    persona = fixture_persona("audit-content-source")
    evidence = {"schema": "owned-fixture/1", "source": "controlled-coherence"}
    digest = persona["provenance"]["source_sha256"]
    store_persona_evidence(tmp_path, evidence, expected_sha256=digest)
    add_persona(tmp_path, persona)
    path = tmp_path / "personas" / "evidence" / f"{digest}.json"
    original_check = personas_module._require_persona_report_catalog

    def remove_after_catalog_check(*args, **kwargs):
        original_check(*args, **kwargs)
        path.unlink()

    monkeypatch.setattr(personas_module, "_require_persona_report_catalog", remove_after_catalog_check)
    with pytest.raises(ContractError, match="saved evidence changed during audit"):
        reporter(tmp_path)
    assert not path.exists()


def test_catalog_audit_bounds_final_bundled_evidence_recheck_bytes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    persona = fixture_persona("audit-bundled-budget")
    persona["provenance"]["source"] = "profile:missing-source"
    persona["integrity_sha256"] = persona_digest(persona)
    evidence = {"schema": "owned-fixture/1", "source": "controlled-coherence"}
    digest = persona["provenance"]["source_sha256"]
    store_persona_evidence(tmp_path, evidence, expected_sha256=digest)
    add_persona(tmp_path, persona)
    monkeypatch.setattr(
        personas_module, "MAX_PERSONA_AUDIT_EVIDENCE_RECHECK_BYTES", 1,
        raising=False,
    )
    with pytest.raises(ContractError, match="saved evidence recheck byte limit"):
        audit_persona_catalog(tmp_path)
    evidence_size = (tmp_path / "personas" / "evidence" / f"{digest}.json").stat().st_size
    monkeypatch.setattr(
        personas_module, "MAX_PERSONA_AUDIT_EVIDENCE_RECHECK_BYTES", 2 * evidence_size,
    )
    assert audit_persona_catalog(tmp_path)["personas"] == 1


def test_catalog_audit_deduplicates_final_bundled_evidence_rechecks(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    evidence = {"schema": "owned-fixture/1", "source": "controlled-coherence"}
    first = fixture_persona("audit-bundled-first")
    digest = first["provenance"]["source_sha256"]
    store_persona_evidence(tmp_path, evidence, expected_sha256=digest)
    for persona_id in ("audit-bundled-first", "audit-bundled-second"):
        persona = fixture_persona(persona_id)
        persona["provenance"]["source"] = "profile:missing-source"
        persona["integrity_sha256"] = persona_digest(persona)
        add_persona(tmp_path, persona)

    original_check = personas_module._require_persona_report_catalog
    original_load = personas_module._load_persona_evidence_counted
    final_loads = 0

    def count_final_load(*args, **kwargs):
        nonlocal final_loads
        final_loads += 1
        return original_load(*args, **kwargs)

    def start_final_pass(*args, **kwargs):
        original_check(*args, **kwargs)
        monkeypatch.setattr(personas_module, "_load_persona_evidence_counted", count_final_load)

    monkeypatch.setattr(personas_module, "_require_persona_report_catalog", start_final_pass)
    assert audit_persona_catalog(tmp_path)["personas"] == 2
    assert final_loads == 1


def test_catalog_audit_deduplicates_initial_saved_evidence_reads(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    evidence = {"schema": "owned-fixture/1", "source": "controlled-coherence"}
    digest = fixture_persona("audit-shared-first")["provenance"]["source_sha256"]
    store_persona_evidence(tmp_path, evidence, expected_sha256=digest)
    for persona_id in ("audit-shared-first", "audit-shared-second"):
        add_persona(tmp_path, fixture_persona(persona_id))
    original_load = personas_module._load_persona_evidence_counted
    loads = 0

    def count_load(*args, **kwargs):
        nonlocal loads
        loads += 1
        return original_load(*args, **kwargs)

    monkeypatch.setattr(personas_module, "_load_persona_evidence_counted", count_load)
    original_check = personas_module._require_persona_report_catalog

    def assert_initial_dedup(*args, **kwargs):
        assert loads == 1
        return original_check(*args, **kwargs)

    monkeypatch.setattr(personas_module, "_require_persona_report_catalog", assert_initial_dedup)
    assert audit_persona_catalog(tmp_path)["personas"] == 2
    assert loads == 2  # One initial verification and one final rebind.


def test_catalog_audit_bounds_initial_saved_evidence_reads(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    persona = fixture_persona("audit-initial-budget")
    evidence = {"schema": "owned-fixture/1", "source": "controlled-coherence"}
    digest = persona["provenance"]["source_sha256"]
    store_persona_evidence(tmp_path, evidence, expected_sha256=digest)
    add_persona(tmp_path, persona)
    monkeypatch.setattr(
        personas_module, "MAX_PERSONA_AUDIT_EVIDENCE_SCAN_BYTES", 1, raising=False
    )
    with pytest.raises(ContractError, match="saved evidence scan byte limit"):
        audit_persona_catalog(tmp_path)
    evidence_size = (tmp_path / "personas" / "evidence" / f"{digest}.json").stat().st_size
    monkeypatch.setattr(personas_module, "MAX_PERSONA_AUDIT_EVIDENCE_SCAN_BYTES", 2 * evidence_size)
    assert audit_persona_catalog(tmp_path)["personas"] == 1


def test_catalog_audit_bounds_final_live_profile_recheck_bytes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    profile_id = "audit-budget-profile"
    persona = fixture_persona("audit-budget-persona")
    canonical_identity = canonical_json_bytes(persona["identity_contract"])
    persona["provenance"]["source"] = f"profile:{profile_id}"
    persona["provenance"]["source_sha256"] = hashlib.sha256(
        canonical_identity
    ).hexdigest()
    persona["integrity_sha256"] = persona_digest(persona)
    create_profile(tmp_path, profile_id)
    identity_file = tmp_path / "source-identity.json"
    identity_file.write_bytes(canonical_identity)
    attach_identity_contract(tmp_path, profile_id, identity_file)
    add_persona(tmp_path, persona)

    monkeypatch.setattr(
        personas_module, "MAX_PERSONA_AUDIT_LIVE_PROFILE_RECHECK_BYTES", 1,
        raising=False,
    )
    with pytest.raises(ContractError, match="live profile recheck byte limit"):
        audit_persona_catalog(tmp_path)
    registry = tmp_path / "profiles" / "registry" / f"{profile_id}.json"
    exact_recheck_bytes = 4 * registry.stat().st_size + (
        tmp_path / "profiles" / "data" / profile_id / "identity-contract.json"
    ).stat().st_size
    monkeypatch.setattr(
        personas_module,
        "MAX_PERSONA_AUDIT_LIVE_PROFILE_RECHECK_BYTES",
        exact_recheck_bytes - 1,
    )
    with pytest.raises(ContractError, match="live profile recheck byte limit"):
        audit_persona_catalog(tmp_path)
    monkeypatch.setattr(
        personas_module,
        "MAX_PERSONA_AUDIT_LIVE_PROFILE_RECHECK_BYTES",
        exact_recheck_bytes,
    )
    assert audit_persona_catalog(tmp_path)["personas"] == 1


def test_catalog_audit_final_live_profile_recheck_uses_one_stable_snapshot(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    profile_id = "audit-shared-profile"
    first = fixture_persona("audit-shared-first")
    canonical_identity = canonical_json_bytes(first["identity_contract"])
    digest = hashlib.sha256(canonical_identity).hexdigest()
    create_profile(tmp_path, profile_id)
    identity_file = tmp_path / "source-identity.json"
    identity_file.write_bytes(canonical_identity)
    attach_identity_contract(tmp_path, profile_id, identity_file)
    for persona_id in ("audit-shared-first", "audit-shared-second"):
        persona = fixture_persona(persona_id)
        persona["provenance"]["source"] = f"profile:{profile_id}"
        persona["provenance"]["source_sha256"] = digest
        persona["integrity_sha256"] = persona_digest(persona)
        add_persona(tmp_path, persona)

    import browser_core.profiles as profiles_module

    original_snapshot = profiles_module._profile_identity_snapshot
    original_catalog_check = personas_module._require_persona_report_catalog
    final_snapshots = 0

    def count_snapshot(*args, **kwargs):
        nonlocal final_snapshots
        final_snapshots += 1
        return original_snapshot(*args, **kwargs)

    def start_final_pass(*args, **kwargs):
        nonlocal final_snapshots
        original_catalog_check(*args, **kwargs)
        final_snapshots = 0
        monkeypatch.setattr(profiles_module, "_profile_identity_snapshot", count_snapshot)

    monkeypatch.setattr(
        personas_module, "_require_persona_report_catalog", start_final_pass
    )
    assert audit_persona_catalog(tmp_path)["personas"] == 2
    assert final_snapshots == 1


def test_catalog_audit_initial_live_profile_scan_deduplicates_profile_reads(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    profile_id = "audit-initial-shared-profile"
    first = fixture_persona("audit-initial-shared-first")
    canonical_identity = canonical_json_bytes(first["identity_contract"])
    digest = hashlib.sha256(canonical_identity).hexdigest()
    create_profile(tmp_path, profile_id)
    source = tmp_path / "source-identity.json"
    source.write_bytes(canonical_identity)
    attach_identity_contract(tmp_path, profile_id, source)
    for persona_id in ("audit-initial-shared-first", "audit-initial-shared-second"):
        persona = fixture_persona(persona_id)
        persona["provenance"]["source"] = f"profile:{profile_id}"
        persona["provenance"]["source_sha256"] = digest
        persona["integrity_sha256"] = persona_digest(persona)
        add_persona(tmp_path, persona)

    import browser_core.profiles as profiles_module

    original_snapshot = profiles_module._profile_identity_snapshot
    initial_snapshots = 0

    def count_snapshot(*args, **kwargs):
        nonlocal initial_snapshots
        initial_snapshots += 1
        return original_snapshot(*args, **kwargs)

    original_check = personas_module._require_persona_report_catalog

    def assert_initial_dedup(*args, **kwargs):
        assert initial_snapshots == 2
        return original_check(*args, **kwargs)

    monkeypatch.setattr(profiles_module, "_profile_identity_snapshot", count_snapshot)
    monkeypatch.setattr(personas_module, "_require_persona_report_catalog", assert_initial_dedup)
    assert audit_persona_catalog(tmp_path)["personas"] == 2


def test_catalog_audit_bounds_initial_live_profile_reads(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    profile_id = "audit-initial-budget-profile"
    persona = fixture_persona("audit-initial-budget-persona")
    canonical_identity = canonical_json_bytes(persona["identity_contract"])
    persona["provenance"]["source"] = f"profile:{profile_id}"
    persona["provenance"]["source_sha256"] = hashlib.sha256(canonical_identity).hexdigest()
    persona["integrity_sha256"] = persona_digest(persona)
    create_profile(tmp_path, profile_id)
    source = tmp_path / "source-identity.json"
    source.write_bytes(canonical_identity)
    attach_identity_contract(tmp_path, profile_id, source)
    add_persona(tmp_path, persona)
    monkeypatch.setattr(
        personas_module, "MAX_PERSONA_AUDIT_PROFILE_SCAN_BYTES", 1, raising=False
    )
    with pytest.raises(ContractError, match="profile scan byte limit"):
        audit_persona_catalog(tmp_path)
    registry = tmp_path / "profiles" / "registry" / f"{profile_id}.json"
    exact_bytes = 8 * registry.stat().st_size + 2 * (
        tmp_path / "profiles" / "data" / profile_id / "identity-contract.json"
    ).stat().st_size
    monkeypatch.setattr(personas_module, "MAX_PERSONA_AUDIT_PROFILE_SCAN_BYTES", exact_bytes)
    assert audit_persona_catalog(tmp_path)["personas"] == 1


@pytest.mark.parametrize("field", ["evidence_kind", "state", "engine", "device_class"])
def test_catalog_audit_rejects_rehashed_unhashable_row_enum(
    tmp_path: Path, field: str
) -> None:
    persona = fixture_persona()
    evidence = {"schema": "owned-fixture/1", "source": "controlled-coherence"}
    store_persona_evidence(
        tmp_path, evidence, expected_sha256=persona["provenance"]["source_sha256"]
    )
    add_persona(tmp_path, persona)
    report = audit_persona_catalog(tmp_path)
    report["verified"][0][field] = []
    verified_body = json.dumps(
        report["verified"], sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    report["verified_sha256"] = hashlib.sha256(verified_body).hexdigest()
    with pytest.raises(ContractError):
        validate_catalog_audit_report(report)


def test_persona_catalog_requires_canonical_name_bound_single_link_documents(
    tmp_path: Path,
) -> None:
    persona = fixture_persona("first-persona")
    add_persona(tmp_path, persona)
    catalog = tmp_path / "personas" / "catalog"
    path = catalog / "first-persona.json"
    canonical = path.read_bytes()
    path.write_bytes(
        canonical.replace(
            b'"id":"first-persona"',
            b'"id":"first-persona","id":"first-persona"',
            1,
        )
    )
    with pytest.raises(ContractError, match="managed document"):
        load_persona(tmp_path, "first-persona")

    path.write_bytes(canonical)
    (catalog / "other-persona.json").write_bytes(canonical)
    with pytest.raises(ContractError, match="filename"):
        load_persona(tmp_path, "other-persona")

    (catalog / "other-persona.json").unlink()
    os.link(path, tmp_path / "persona-hard-link")
    with pytest.raises(ContractError, match="hard links"):
        load_persona(tmp_path, "first-persona")


def test_load_persona_rechecks_saved_bytes_after_validation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    original = add_persona(tmp_path, fixture_persona("validation-race"))
    path = tmp_path / "personas" / "catalog" / "validation-race.json"
    competitor = copy.deepcopy(original)
    competitor["name"] = "Competing catalog revision"
    competitor["integrity_sha256"] = persona_digest(competitor)
    competitor_bytes = canonical_json_bytes(competitor)
    original_validate = personas_module._validated_persona_document

    def change_after_validation(body: bytes) -> dict:
        document = original_validate(body)
        path.write_bytes(competitor_bytes)
        return document

    monkeypatch.setattr(
        personas_module, "_validated_persona_document", change_after_validation
    )
    with pytest.raises(ContractError, match="persona document changed during read"):
        load_persona(tmp_path, "validation-race")
    assert path.read_bytes() == competitor_bytes


@pytest.mark.parametrize("reader", ["load", "list"])
def test_persona_catalog_reads_reject_relocated_workspace_ancestor(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, reader: str
) -> None:
    selected = tmp_path / "selected"
    workspace = selected / "workspace"
    workspace.mkdir(parents=True)
    persona = fixture_persona()
    add_persona(workspace, persona)
    path = workspace / "personas" / "catalog" / f"{persona['id']}.json"
    original_bytes = path.read_bytes()
    retained = tmp_path / "retained-selected"
    moved = False

    def relocate() -> None:
        nonlocal moved
        selected.rename(retained)
        selected.mkdir()
        (retained / "workspace").rename(workspace)
        moved = True

    if reader == "load":
        original = personas_module.read_bounded_control_snapshot_result

        def relocate_after_read(target: Path, **kwargs):
            result = original(target, **kwargs)
            if target == path and not moved:
                relocate()
            return result

        monkeypatch.setattr(
            personas_module, "read_bounded_control_snapshot_result",
            relocate_after_read,
        )
    else:
        original_inventory = personas_module.inventory_bounded_json_directory

        def relocate_after_inventory(directory: Path, **kwargs):
            result = original_inventory(directory, **kwargs)
            if not moved:
                relocate()
            return result

        monkeypatch.setattr(
            personas_module, "inventory_bounded_json_directory",
            relocate_after_inventory,
        )
    with pytest.raises(ContractError, match="changed"):
        if reader == "load":
            load_persona(workspace, persona["id"])
        else:
            list_personas(workspace)
    assert moved
    assert path.read_bytes() == original_bytes


@pytest.mark.skipif(os.name != "nt", reason="Windows directory junction boundary")
@pytest.mark.parametrize(
    "operation", ["add", "load", "list", "evidence-store", "evidence-load"]
)
def test_persona_operations_reject_linked_workspace_before_access(
    tmp_path: Path, operation: str
) -> None:
    foreign = tmp_path / "foreign"
    foreign.mkdir()
    persona = fixture_persona()
    evidence = {"schema": "owned-fixture/1", "source": "linked-workspace-test"}
    digest = hashlib.sha256(canonical_json_bytes(evidence)).hexdigest()
    if operation in {"load", "list"}:
        add_persona(foreign, persona)
    if operation == "evidence-load":
        store_persona_evidence(foreign, evidence, expected_sha256=digest)
    before = {
        str(path.relative_to(foreign)): path.read_bytes()
        for path in foreign.rglob("*") if path.is_file()
    }
    workspace = tmp_path / "workspace"
    created = subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(workspace), str(foreign)],
        capture_output=True, check=False,
    )
    if created.returncode:
        pytest.skip("host could not create an unprivileged directory junction")
    try:
        with pytest.raises(ContractError, match="persona workspace"):
            if operation == "add":
                add_persona(workspace, persona)
            elif operation == "load":
                load_persona(workspace, persona["id"])
            elif operation == "list":
                list_personas(workspace)
            elif operation == "evidence-store":
                store_persona_evidence(workspace, evidence, expected_sha256=digest)
            else:
                load_persona_evidence(workspace, digest)
        assert {
            str(path.relative_to(foreign)): path.read_bytes()
            for path in foreign.rglob("*") if path.is_file()
        } == before
    finally:
        workspace.rmdir()


@pytest.mark.skipif(os.name != "nt", reason="Windows directory junction boundary")
@pytest.mark.parametrize("reader", ["load", "list"])
def test_persona_catalog_reads_reject_preexisting_ancestor_junction(
    tmp_path: Path, reader: str
) -> None:
    foreign = tmp_path / "foreign"
    foreign.mkdir()
    persona = fixture_persona()
    add_persona(foreign, persona)
    catalog = foreign / "personas" / "catalog" / f"{persona['id']}.json"
    original = catalog.read_bytes()
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    junction = workspace / "personas"
    created = subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(junction), str(foreign / "personas")],
        capture_output=True, check=False,
    )
    if created.returncode:
        pytest.skip("host could not create an unprivileged directory junction")
    try:
        with pytest.raises(ContractError, match="persona catalog"):
            if reader == "load":
                load_persona(workspace, persona["id"])
            else:
                list_personas(workspace)
        assert catalog.read_bytes() == original
    finally:
        junction.rmdir()


@pytest.mark.skipif(os.name != "nt", reason="Windows directory junction boundary")
def test_persona_catalog_write_does_not_create_foreign_parent_after_swap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace = tmp_path / "workspace"
    personas = workspace / "personas"
    personas.mkdir(parents=True)
    held = tmp_path / "held-personas"
    foreign = tmp_path / "foreign"
    foreign.mkdir()
    original_load = personas_module._load_persona_snapshot
    swapped = False

    def swap_after_missing(*args, **kwargs):
        nonlocal swapped
        result = original_load(*args, **kwargs)
        if kwargs.get("missing_ok") and result[0] is None and not swapped:
            personas.rename(held)
            created = subprocess.run(
                ["cmd", "/c", "mklink", "/J", str(personas), str(foreign)],
                capture_output=True, check=False,
            )
            if created.returncode:
                pytest.skip("host could not create an unprivileged directory junction")
            swapped = True
        return result

    monkeypatch.setattr(personas_module, "_load_persona_snapshot", swap_after_missing)
    try:
        with pytest.raises(ContractError):
            add_persona(workspace, fixture_persona())
        assert swapped
        assert not (foreign / "catalog").exists()
    finally:
        if personas.exists():
            personas.rmdir()


def test_persona_catalog_bounds_and_rechecks_population(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    add_persona(tmp_path, fixture_persona("first-persona"))
    add_persona(tmp_path, fixture_persona("second-persona"))
    monkeypatch.setattr(personas_module, "MAX_PERSONA_CATALOG_FILES", 1)
    with pytest.raises(ContractError, match="too many JSON files"):
        list_personas(tmp_path)
    monkeypatch.setattr(personas_module, "MAX_PERSONA_CATALOG_FILES", 10_000)
    original = personas_module.inventory_bounded_json_directory
    calls = 0

    def appearing(directory: Path, **kwargs):
        nonlocal calls
        calls += 1
        result = original(directory, **kwargs)
        if calls == 1:
            (directory / "appeared-persona.json").write_text("{}\n", encoding="utf-8")
        return result

    monkeypatch.setattr(personas_module, "inventory_bounded_json_directory", appearing)
    with pytest.raises(ContractError, match="catalog changed"):
        list_personas(tmp_path)


def test_persona_catalog_rejects_appearance_during_final_byte_rebind(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    add_persona(tmp_path, fixture_persona("first-persona"))
    catalog = tmp_path / "personas" / "catalog"
    first = catalog / "first-persona.json"
    second = fixture_persona("second-persona")
    second_path = catalog / "second-persona.json"
    original = personas_module.read_bounded_control_snapshot_result
    reads = 0

    def add_after_final_read(path: Path, **kwargs):
        nonlocal reads
        result = original(path, **kwargs)
        if path == first:
            reads += 1
            if reads == 2:
                second_path.write_bytes(canonical_json_bytes(second))
        return result

    monkeypatch.setattr(
        personas_module, "read_bounded_control_snapshot_result", add_after_final_read
    )
    with pytest.raises(ContractError, match="catalog changed during load"):
        list_personas(tmp_path)
    assert second_path.read_bytes() == canonical_json_bytes(second)


@pytest.mark.skipif(os.name != "nt", reason="Windows restored-mtime persona custody")
def test_persona_catalog_rechecks_same_identity_content_after_inventory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    add_persona(tmp_path, fixture_persona("fixture"))
    path = tmp_path / "personas" / "catalog" / "fixture.json"
    original_inventory = personas_module.inventory_bounded_json_directory
    inventories = 0

    def mutate_before_second_inventory(directory: Path, **kwargs: object):
        nonlocal inventories
        inventories += 1
        if inventories == 2:
            before = path.stat()
            persona = json.loads(path.read_text(encoding="ascii"))
            persona["name"] = "Owned Windows Chromium 154"
            persona["integrity_sha256"] = persona_digest(persona)
            replacement = canonical_json_bytes(persona)
            assert len(replacement) == before.st_size
            path.write_bytes(replacement)
            os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns))
            after = path.stat()
            assert (after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns) == (
                before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns
            )
        return original_inventory(directory, **kwargs)

    monkeypatch.setattr(
        personas_module, "inventory_bounded_json_directory", mutate_before_second_inventory
    )
    with pytest.raises(ContractError, match="persona changed during catalog load"):
        list_personas(tmp_path)
    assert inventories == 2


def test_catalog_over_ten_thousand_remains_searchable_and_assignable(
    tmp_path: Path,
) -> None:
    # Reproduce the planner/loader/assignment mismatch with actual bounded files,
    # including identity and digest validation; mocking the inventory hid it.
    catalog = tmp_path / "personas" / "catalog"
    catalog.mkdir(parents=True)
    prototype = fixture_persona()
    for number in range(10_001):
        persona = dict(prototype, id=f"large-catalog-{number:05}")
        persona["integrity_sha256"] = persona_digest(persona)
        (catalog / f"{persona['id']}.json").write_bytes(
            canonical_json_bytes(persona)
        )
    candidates = search_personas(tmp_path, product="browser-core", major=153)
    assert len(candidates) == 10_001
    assignment = assign_persona(tmp_path, "catalog-capacity-regression", candidates)
    assert assignment["persona_id"] in {item["id"] for item in candidates}
    assert assign_persona(
        tmp_path, "catalog-capacity-regression", reversed(candidates)
    ) == assignment


def test_persona_rejects_tamper_and_incoherent_engine_or_orientation() -> None:
    persona = fixture_persona()
    tampered = copy.deepcopy(persona)
    tampered["geography"]["country"] = "CA"
    with pytest.raises(ContractError, match="integrity"):
        add_persona(Path("unused"), tampered)
    with pytest.raises(ContractError, match="WebKit"):
        fixture_persona(product="safari")
    bad_orientation = copy.deepcopy(persona)
    bad_orientation["device"]["viewport"]["orientation"] = "portrait"
    from browser_core.personas import persona_digest

    bad_orientation["integrity_sha256"] = persona_digest(bad_orientation)
    with pytest.raises(ContractError, match="orientation"):
        add_persona(Path("unused"), bad_orientation)


def test_persona_rejects_cross_device_mobile_desktop_mix() -> None:
    evidence = {"schema": "owned-fixture/1", "source": "cross-device-reject"}
    with pytest.raises(ContractError, match="mobile"):
        build_persona(
            persona_id="bad-mobile",
            name="Bad",
            device={
                "class": "mobile",
                "os_family": "android",
                "os_version": "14",
                "architecture": "arm64",
                "is_mobile": False,
                "has_touch": True,
                "viewport": {
                    "width": 360,
                    "height": 780,
                    "device_scale_factor": 2.5,
                    "orientation": "portrait",
                },
                "screen": {"width": 360, "height": 780},
            },
            kernel={
                "engine": "chromium",
                "product": "chrome",
                "minimum_major": 120,
                "maximum_major": 120,
            },
            geography={
                "country": "US",
                "locale": "en-US",
                "languages": ["en-US"],
                "timezone": "America/Chicago",
            },
            identity_contract={
                "schema_version": 1,
                "expected": {"window.platform": "Linux armv8l"},
            },
            provenance={
                "kind": "owned-capture",
                "source": "bad",
                "source_sha256": hashlib.sha256(
                    json.dumps(evidence, sort_keys=True, separators=(",", ":")).encode(
                        "utf-8"
                    )
                ).hexdigest(),
                "captured_at": "2026-08-03T00:00:00Z",
            },
        )


def test_persona_rejects_huge_device_scale_as_contract_error(tmp_path: Path) -> None:
    persona = fixture_persona()
    persona["device"]["viewport"]["device_scale_factor"] = 10**400
    persona["integrity_sha256"] = persona_digest(persona)
    with pytest.raises(ContractError, match="scale factor"):
        add_persona(tmp_path, persona)


def test_search_rejects_reversed_major_range(tmp_path: Path) -> None:
    add_persona(tmp_path, fixture_persona())
    with pytest.raises(ContractError, match="major range"):
        search_personas(tmp_path, min_major=160, max_major=150)


@pytest.mark.parametrize(
    "arguments",
    [
        {"include_incoherent": 1},
        {"major": True},
        {"min_major": "150", "max_major": 160},
        {"locale": ["en-US"]},
        {"tags": "owned"},
        {"tags": ["owned", {"private": "tag"}]},
        {"tags": (str(index) for index in range(257))},
    ],
)
def test_search_rejects_malformed_public_filters_before_catalog_access(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    arguments: dict,
) -> None:
    touched = False

    def fail_if_touched(*_args, **_kwargs):
        nonlocal touched
        touched = True
        raise AssertionError("catalog must not be read")

    monkeypatch.setattr(personas_module, "list_personas", fail_if_touched)
    with pytest.raises(ContractError):
        search_personas(tmp_path, **arguments)
    assert touched is False


def test_search_closes_retained_tag_iterator_at_population_cap(tmp_path: Path) -> None:
    closed: list[bool] = []

    def tags():
        try:
            for index in range(257):
                yield str(index)
        finally:
            closed.append(True)

    source = tags()
    with pytest.raises(ContractError, match="tag population exceeds"):
        search_personas(tmp_path, tags=source)
    assert closed == [True]


@pytest.mark.parametrize(
    "arguments",
    [
        {"engine": ["chromium"]},
        {"product": {"name": "browser-core"}},
        {"major": "153"},
        {"device_class": True},
    ],
)
def test_persona_compatibility_rejects_malformed_runtime_arguments(
    arguments: dict,
) -> None:
    valid = {
        "engine": "chromium",
        "product": "browser-core",
        "major": 153,
        "device_class": "desktop",
    }
    valid.update(arguments)
    with pytest.raises(ContractError):
        persona_compatible(fixture_persona(), **valid)


def test_volume_report_tracks_growth_against_baseline(tmp_path: Path) -> None:
    evidence = {"schema": "owned-fixture/1", "source": "controlled-coherence"}
    persona = fixture_persona()
    store_persona_evidence(
        tmp_path, evidence, expected_sha256=persona["provenance"]["source_sha256"]
    )
    add_persona(tmp_path, persona)
    report = catalog_volume_report(tmp_path, baseline_active=0)
    assert report["schema"] == VOLUME_SCHEMA
    assert report["active"] == 1
    assert report["growth_delta"] == 1
    assert report["vendor_commercial_millions_claim"] is False
    assert report["generation_method"] == "owned-kernel-probe-matrix"


def test_coverage_report_replays_every_nested_claim_after_json_roundtrip(
    tmp_path: Path,
) -> None:
    evidence = {"schema": "owned-fixture/1", "source": "controlled-coherence"}
    persona = fixture_persona()
    store_persona_evidence(
        tmp_path, evidence, expected_sha256=persona["provenance"]["source_sha256"]
    )
    add_persona(tmp_path, persona)
    report = json.loads(json.dumps(catalog_coverage_report(tmp_path)))
    assert validate_catalog_coverage_report(report) is report

    mutations = []
    for path, replacement in (
        (("schema",), "private-coverage-schema-marker"),
        (("active",), 2),
        (("deprecated",), 1),
        (("total",), 2),
        (("axes", "engine"), []),
        (("axis_diversity", "engine"), 0),
        (("identity_claim_counts", "mean"), 99.0),
        (("quality_gates", "active_at_least_12"), True),
        (("provenance_grades", "by_kind"), {}),
        (("provenance_grades", "high_provenance_ratio"), 0.5),
        (("research_catalog_ready",), True),
        (("lab_scale_volume_ready",), True),
        (("commercial_inventory_ready",), True),
        (("audit", "passed"), False),
        (("audit", "verified", 0, "persona_sha256_16"), "0" * 16),
        (("personas", 0, "claim_count"), 3),
        (("personas", 0, "languages"), ["de-DE"]),
        (("personas", 0, "product"), "firefox"),
        (("personas", 0, "provenance_grade"), "private-coverage-grade-marker"),
    ):
        mutation = copy.deepcopy(report)
        target = mutation
        for segment in path[:-1]:
            target = target[segment]
        target[path[-1]] = replacement
        mutations.append(mutation)
    extra = copy.deepcopy(report)
    extra["private"] = "private-coverage-field-marker"
    mutations.append(extra)

    for mutation in mutations:
        with pytest.raises(ContractError) as failure:
            validate_catalog_coverage_report(mutation)
        assert "private-coverage" not in str(failure.value)


@pytest.mark.parametrize(
    "field",
    [
        "state", "device_class", "os_family", "engine", "product",
        "provenance_kind", "provenance_grade",
    ],
)
def test_coverage_report_rejects_unhashable_row_enum(tmp_path: Path, field: str) -> None:
    persona = fixture_persona()
    evidence = {"schema": "owned-fixture/1", "source": "controlled-coherence"}
    store_persona_evidence(
        tmp_path, evidence, expected_sha256=persona["provenance"]["source_sha256"]
    )
    add_persona(tmp_path, persona)
    report = catalog_coverage_report(tmp_path)
    report["personas"][0][field] = []
    with pytest.raises(ContractError):
        validate_catalog_coverage_report(report)


def test_volume_report_recomputes_growth_gates_and_readiness(tmp_path: Path) -> None:
    evidence = {"schema": "owned-fixture/1", "source": "controlled-coherence"}
    persona = fixture_persona()
    store_persona_evidence(
        tmp_path, evidence, expected_sha256=persona["provenance"]["source_sha256"]
    )
    add_persona(tmp_path, persona)
    report = json.loads(json.dumps(catalog_volume_report(tmp_path, baseline_active=0)))
    assert validate_catalog_volume_report(report) is report

    mutations = []
    for path, replacement in (
        (("schema",), "private-volume-schema-marker"),
        (("baseline_active",), 1),
        (("active",), 2),
        (("deprecated",), 1),
        (("minimum_claim_count",), 3),
        (("claim_count_histogram",), {"3": 1}),
        (("audit_verified",), 0),
        (("growth_delta",), 2),
        (("growth_ratio",), 0.0),
        (("drastic_growth",), True),
        (("lab_scale_volume_ready",), True),
        (("research_catalog_ready",), True),
        (("commercial_inventory_ready",), True),
        (("generation_method",), "private-volume-method-marker"),
        (("provenance_kinds",), []),
        (("axis_diversity", "engine"), 0),
        (("quality_gates", "active_at_least_12"), True),
        (("vendor_commercial_millions_claim",), True),
        (("note",), "private-volume-note-marker"),
    ):
        mutation = copy.deepcopy(report)
        target = mutation
        for segment in path[:-1]:
            target = target[segment]
        target[path[-1]] = replacement
        mutations.append(mutation)
    extra = copy.deepcopy(report)
    extra["private"] = "private-volume-field-marker"
    mutations.append(extra)

    for mutation in mutations:
        with pytest.raises(ContractError) as failure:
            validate_catalog_volume_report(mutation)
        assert "private-volume" not in str(failure.value)


def test_volume_proof_counts_include_deprecated_audit_rows(tmp_path: Path) -> None:
    evidence = {"schema": "owned-fixture/1", "source": "controlled-coherence"}
    active = fixture_persona("active-persona")
    deprecated = fixture_persona("deprecated-persona")
    store_persona_evidence(
        tmp_path, evidence, expected_sha256=active["provenance"]["source_sha256"]
    )
    add_persona(tmp_path, active)
    add_persona(tmp_path, deprecated)
    set_persona_state(
        tmp_path,
        deprecated["id"],
        "deprecated",
        expected_sha256=deprecated["integrity_sha256"],
    )

    report = json.loads(json.dumps(catalog_volume_report(tmp_path)))
    assert report["active"] == 1
    assert report["deprecated"] == 1
    assert report["audit_verified"] == 2
    assert report["claim_count_histogram"] == {"2": 1}
    assert validate_catalog_volume_report(report) is report


def test_coverage_value_domain_rejects_private_device_class(tmp_path: Path) -> None:
    evidence = {"schema": "owned-fixture/1", "source": "controlled-coherence"}
    persona = fixture_persona()
    store_persona_evidence(
        tmp_path, evidence, expected_sha256=persona["provenance"]["source_sha256"]
    )
    add_persona(tmp_path, persona)
    report = catalog_coverage_report(tmp_path)
    report["personas"][0]["device_class"] = "private-coverage-device-marker"
    with pytest.raises(ContractError) as failure:
        validate_catalog_coverage_report(report)
    assert "private-coverage-device-marker" not in str(failure.value)


def test_coverage_and_audit_share_one_catalog_snapshot(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    evidence = {"schema": "owned-fixture/1", "source": "controlled-coherence"}
    persona = fixture_persona()
    store_persona_evidence(
        tmp_path, evidence, expected_sha256=persona["provenance"]["source_sha256"]
    )
    add_persona(tmp_path, persona)
    original = personas_module.list_personas
    calls = 0

    def counted_list(*args, **kwargs):
        nonlocal calls
        calls += 1
        return original(*args, **kwargs)

    monkeypatch.setattr(personas_module, "list_personas", counted_list)
    report = catalog_coverage_report(tmp_path)
    assert report["audit"]["personas"] == report["total"] == 1
    assert calls == 1


def test_browser_major_axis_unions_maximum_intervals_without_row_expansion(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    builtin_range = range
    calls = 0

    def counted_range(*args):
        nonlocal calls
        calls += 1
        return builtin_range(*args)

    monkeypatch.setattr(personas_module, "range", counted_range, raising=False)
    axis = personas_module._browser_major_axis([(1, 999)] * 20_000)
    assert axis == list(builtin_range(1, 1000))
    assert calls == 1, "the 999-value domain is scanned once, not once per persona"


@pytest.mark.parametrize("baseline", [-1, 10_000_001, True, 1.5, "100"])
def test_volume_baseline_is_a_bounded_literal_integer(
    tmp_path: Path, baseline: object
) -> None:
    with pytest.raises(ContractError, match="0 to 10000000"):
        catalog_volume_report(tmp_path, baseline_active=baseline)  # type: ignore[arg-type]


def test_infer_os_and_bulk_matrix_plan_are_host_realizable() -> None:
    assert infer_os_from_device_preset("iPhone 14", device_class="mobile")[0] == "ios"
    assert (
        infer_os_from_device_preset("Desktop Safari", device_class="desktop")[0]
        == "macos"
    )
    assert (
        infer_os_from_device_preset("Galaxy S24", device_class="mobile")[0] == "android"
    )
    assert (
        infer_os_from_device_preset("Desktop Chrome", device_class="desktop")[0]
        == "windows"
    )
    repo = Path(__file__).resolve().parents[1]
    plans = plan_bulk_capture_matrix(repo, target_active=100, existing_ids=())
    assert len(plans) >= 80
    ids = [item["persona_id"] for item in plans]
    assert len(ids) == len(set(ids))
    locales = {item["locale"] for item in plans}
    assert len(locales) >= 8
    engines = {item["kernel_id"] for item in plans}
    assert "playwright-chromium" in engines
    # Every planned id is schema-safe.
    for item in plans[:20]:
        assert re.fullmatch(r"[A-Za-z0-9._-]{1,64}", item["persona_id"])
    full = plan_bulk_capture_matrix(
        repo, target_active=1000, existing_ids=(), full_cross_product=True
    )
    assert len(full) >= 900
    assert len({item["persona_id"] for item in full}) == len(full)


def test_bulk_plan_bounds_controls_before_kernel_discovery(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import browser_core.kernels as kernel_module

    monkeypatch.setattr(
        kernel_module,
        "discover_kernels",
        lambda *_a, **_k: pytest.fail("invalid controls reached kernel discovery"),
    )
    repo = Path(__file__).resolve().parents[1]
    valid_geo = {"country": "US", "locale": "en-US", "timezone": "America/Chicago"}
    cases = (
        {"target_active": 0},
        {"target_active": personas_module.MAX_PERSONA_CATALOG_ENTRIES + 1},
        {"target_active": True},
        {"full_cross_product": 1},
        {"with_device_memory": "false"},
        {"core_variants": 0},
        {"core_variants": personas_module.MAX_BULK_CORE_VARIANTS + 1},
        {"browser_core_executable": "private.exe"},
        {"geographies": "private-geographies-marker"},
        {"geographies": itertools.repeat(valid_geo)},
        {"geographies": [valid_geo, dict(valid_geo)]},
        {"geographies": [{"country": "private", "locale": "x", "timezone": "x"}]},
        {"existing_ids": "private-existing-ids-marker"},
        {"existing_ids": ["duplicate-id", "duplicate-id"]},
        {"existing_ids": ["Existing-ID", "existing-id"]},
        {"existing_ids": ["CON"]},
        {"existing_ids": ["aux.backup"]},
        {"existing_ids": itertools.repeat("existing-id")},
    )
    for controls in cases:
        with pytest.raises(ContractError) as failure:
            plan_bulk_capture_matrix(repo, **controls)
        assert "private" not in str(failure.value)


@pytest.mark.parametrize("field", ["geographies", "existing_ids"])
def test_bulk_plan_closes_retained_input_iterators_at_population_cap(
    field: str,
) -> None:
    closed: list[bool] = []
    limit = (
        personas_module.MAX_BULK_GEOGRAPHIES
        if field == "geographies"
        else personas_module.MAX_PERSONA_CATALOG_ENTRIES
    )

    def values():
        try:
            for _ in range(limit + 1):
                yield (
                    {"country": "US", "locale": "en-US", "timezone": "America/Chicago"}
                    if field == "geographies"
                    else "existing-id"
                )
        finally:
            closed.append(True)

    source = values()
    with pytest.raises(ContractError, match="too many geographies|too many existing IDs"):
        plan_bulk_capture_matrix(
            Path(__file__).resolve().parents[1], **{field: source}
        )
    assert closed == [True]


def test_bulk_plan_uses_validated_geography_snapshot_after_discovery(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import browser_core.kernels as kernel_module

    geography = {"country": "US", "locale": "en-US", "timezone": "America/Chicago"}
    original_discover = kernel_module.discover_kernels

    def change_caller_geography(*args, **kwargs):
        discovered = original_discover(*args, **kwargs)
        geography["country"] = "CA"
        return discovered

    monkeypatch.setattr(kernel_module, "discover_kernels", change_caller_geography)
    plans = plan_bulk_capture_matrix(
        Path(__file__).resolve().parents[1], target_active=1,
        geographies=[geography],
    )
    assert geography["country"] == "CA"
    assert plans and all(plan["country"] == "US" for plan in plans)


def test_maximum_bulk_plan_uses_constant_time_identity_membership(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import browser_core.kernels as kernel_module

    kernel = {
        "id": "mock-chromium",
        "engine": "chromium",
        "available": True,
        "capabilities": [],
        "source": {"kind": "playwright-managed"},
    }
    devices = [
        {
            "name": f"Desktop Mock {index}",
            "default_engine": "chromium",
            "class": "desktop",
            "is_mobile": False,
            "user_agent": "Mock Chromium",
        }
        for index in range(9)
    ]
    geographies = [
        {
            "country": "US",
            "locale": f"en-X{index:03d}",
            "timezone": f"Etc/Zone{index}",
        }
        for index in range(personas_module.MAX_BULK_GEOGRAPHIES)
    ]
    monkeypatch.setattr(kernel_module, "discover_kernels", lambda *_a, **_k: [kernel])
    monkeypatch.setattr(
        kernel_module,
        "playwright_device_contract_catalog",
        lambda **_kwargs: devices,
    )
    builtin_any = any
    any_calls = 0

    def counted_any(values):
        nonlocal any_calls
        any_calls += 1
        return builtin_any(values)

    monkeypatch.setattr(personas_module, "any", counted_any, raising=False)
    plans = plan_bulk_capture_matrix(
        Path(__file__).resolve().parents[1],
        target_active=personas_module.MAX_PERSONA_CATALOG_ENTRIES,
        geographies=geographies,
        full_cross_product=True,
        core_variants=personas_module.MAX_BULK_CORE_VARIANTS,
    )
    assert len(plans) == personas_module.MAX_PERSONA_CATALOG_ENTRIES
    assert len({plan["persona_id"].casefold() for plan in plans}) == len(plans)
    assert any_calls == 1, "existing-ID validation is the only full scan"


def test_bulk_variants_do_not_mint_two_ids_for_the_same_identity_axes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import browser_core.kernels as kernel_module

    kernel = {
        "id": "mock-chromium",
        "engine": "chromium",
        "available": True,
        "capabilities": [],
        "source": {"kind": "playwright-managed"},
    }
    device = {
        "name": "Desktop Mock",
        "default_engine": "chromium",
        "class": "desktop",
        "is_mobile": False,
        "user_agent": "Mock Chromium",
    }
    monkeypatch.setattr(kernel_module, "discover_kernels", lambda *_a, **_k: [kernel])
    monkeypatch.setattr(
        kernel_module,
        "playwright_device_contract_catalog",
        lambda **_kwargs: [device],
    )
    plans = plan_bulk_capture_matrix(
        Path(__file__).resolve().parents[1],
        target_active=100,
        geographies=(
            {
                "country": "US",
                "locale": "en-US",
                "timezone": "America/Chicago",
            },
        ),
        full_cross_product=True,
        core_variants=personas_module.MAX_BULK_CORE_VARIANTS,
    )
    core_values = [plan["hardware_concurrency"] for plan in plans]
    assert len(plans) == len(set(core_values))
    assert len({plan["persona_id"].casefold() for plan in plans}) == len(plans)


def test_bulk_capture_wrappers_preflight_before_catalog_or_browser_contact(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = Path(__file__).resolve().parents[1]
    monkeypatch.setattr(
        personas_module,
        "list_personas",
        lambda *_a, **_k: pytest.fail("invalid controls reached catalog"),
    )
    invalid_single = (
        {"target_active": 0},
        {"max_new": True},
        {"max_new": personas_module.MAX_PERSONA_CATALOG_ENTRIES + 1},
        {"full_cross_product": "false"},
    )
    for controls in invalid_single:
        with pytest.raises(ContractError):
            bulk_capture_personas(tmp_path, repo, **controls)

    invalid_batched = (
        {"engines": "chromium"},
        {"engines": []},
        {"engines": ["chromium", "chromium"]},
        {"engines": ["private-engine-marker"]},
        {"core_variants": 0},
        {"core_variants": personas_module.MAX_BULK_CORE_VARIANTS + 1},
        {"device_memory_executable": "relative.exe"},
    )
    for controls in invalid_batched:
        with pytest.raises(ContractError) as failure:
            bulk_capture_personas_batched(tmp_path, repo, **controls)
        assert "private-engine-marker" not in str(failure.value)


def test_bulk_capture_reports_recompute_lifecycle_and_sample_boundaries(
    tmp_path: Path,
) -> None:
    evidence = {"schema": "owned-fixture/1", "source": "controlled-coherence"}
    persona = fixture_persona("captured-persona")
    store_persona_evidence(
        tmp_path, evidence, expected_sha256=persona["provenance"]["source_sha256"]
    )
    add_persona(tmp_path, persona)
    volume = catalog_volume_report(tmp_path, baseline_active=15)
    captured = [
        {
            "id": persona["id"],
            "locale": persona["geography"]["locale"],
            "engine": persona["kernel"]["engine"],
            "device_class": persona["device"]["class"],
            "claims": len(persona["identity_contract"]["expected"]),
        }
    ]
    safe_error = "contract-failure; diagnostic_sha256_16=" + "a" * 16
    one_failure = [{"persona_id": "failed-persona", "error": safe_error}]
    coverage = {
        "research_catalog_ready": volume["research_catalog_ready"],
        "lab_scale_volume_ready": volume["lab_scale_volume_ready"],
        "commercial_inventory_ready": volume["commercial_inventory_ready"],
        "axis_diversity": volume["axis_diversity"],
        "quality_gates": volume["quality_gates"],
    }
    per_persona = {
        "schema": "browser-core.persona-bulk-capture/1",
        "baseline_active": 0,
        "planned": 2,
        "captured": captured,
        "captured_count": 1,
        "failed": one_failure,
        "failed_count": 1,
        "skipped_existing": 0,
        "active_after": 1,
        "volume": volume,
        "coverage": coverage,
    }
    all_failures = [
        {"persona_id": f"failed-{index}", "error": safe_error} for index in range(51)
    ]
    failed_digest = hashlib.sha256(
        json.dumps(
            all_failures,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
    ).hexdigest()
    batched = {
        "schema": "browser-core.persona-bulk-capture/3",
        "baseline_active": 0,
        "planned": 52,
        "browsers_launched": 1,
        "captured": captured,
        "captured_count": 1,
        "failed": all_failures[:50],
        "failed_count": 51,
        "failed_omitted": 1,
        "failed_sha256": failed_digest,
        "refused_incoherent": 1,
        "active_after": 1,
        "volume": volume,
    }
    assert validate_bulk_capture_report(json.loads(json.dumps(per_persona)))
    assert validate_bulk_capture_report(json.loads(json.dumps(batched)))

    private = "private-bulk-report-marker"
    mutations = []
    for source, path, replacement in (
        (per_persona, ("schema",), private),
        (per_persona, ("baseline_active",), 1),
        (per_persona, ("planned",), 1),
        (per_persona, ("captured_count",), 0),
        (per_persona, ("captured", 0, "id"), "failed-persona"),
        (per_persona, ("captured", 0, "engine"), []),
        (per_persona, ("captured", 0, "device_class"), {}),
        (per_persona, ("failed", 0, "error"), private),
        (per_persona, ("failed_count",), 0),
        (per_persona, ("skipped_existing",), 2),
        (per_persona, ("active_after",), 0),
        (per_persona, ("coverage", "research_catalog_ready"), True),
        (batched, ("browsers_launched",), 0),
        (batched, ("failed_count",), 50),
        (batched, ("failed_omitted",), 0),
        (batched, ("failed_sha256",), "0" * 63),
        (batched, ("refused_incoherent",), 52),
        (batched, ("volume", "active"), 2),
    ):
        mutation = copy.deepcopy(source)
        target = mutation
        for segment in path[:-1]:
            target = target[segment]
        target[path[-1]] = replacement
        mutations.append(mutation)
    extra = copy.deepcopy(batched)
    extra["private"] = private
    mutations.append(extra)

    for mutation in mutations:
        with pytest.raises(ContractError) as failure:
            validate_bulk_capture_report(mutation)
        assert private not in str(failure.value)


def test_commercial_volume_compare_uses_core_count_and_kameleo_path(
    tmp_path: Path,
) -> None:
    evidence = {"schema": "owned-fixture/1", "source": "controlled-coherence"}
    persona = fixture_persona()
    store_persona_evidence(
        tmp_path, evidence, expected_sha256=persona["provenance"]["source_sha256"]
    )
    add_persona(tmp_path, persona)
    unreachable = count_kameleo_operator_inventory(base_url="http://127.0.0.1:1")
    assert unreachable["reachable"] is False
    assert unreachable["count"] is None
    report = compare_commercial_volume(
        tmp_path, kameleo_base_url="http://127.0.0.1:1", baseline_active=0
    )
    assert report["schema"] == COMMERCIAL_COMPARE_SCHEMA
    assert report["core_count"] == 1
    assert report["vendor_global_telemetry_millions_claim"] is False
    assert "operator-accessible" in report["methodology"].casefold()
    assert report["core"]["searchable"] is True
    assert validate_commercial_volume_report(json.loads(json.dumps(report)))


def test_commercial_comparison_recomputes_sources_counts_and_rank(
    tmp_path: Path,
) -> None:
    evidence = {"schema": "owned-fixture/1", "source": "controlled-coherence"}
    persona = fixture_persona()
    store_persona_evidence(
        tmp_path, evidence, expected_sha256=persona["provenance"]["source_sha256"]
    )
    add_persona(tmp_path, persona)
    report = compare_commercial_volume(
        tmp_path, kameleo_base_url="http://127.0.0.1:1", baseline_active=0
    )
    mutations = []
    for path, replacement in (
        (("schema",), "private-commercial-schema-marker"),
        (("methodology",), "private-commercial-method-marker"),
        (("core", "count"), 2),
        (("core", "inventory"), "private-commercial-inventory-marker"),
        (("core", "searchable"), False),
        (("core", "provenance_backed"), False),
        (("core", "commercial_inventory_ready"), True),
        (("core", "research_catalog_ready"), True),
        (("core", "axis_diversity", "engine"), 0),
        (("core", "growth_from_baseline"), 2),
        (("core", "baseline_active"), 1),
        (("core", "volume", "growth_delta"), 2),
        (("kameleo", "product"), "private-commercial-product-marker"),
        (("kameleo", "receipt", "endpoint"), "private-commercial-endpoint-marker"),
        (("core_count",), 2),
        (("kameleo_count",), 0),
        (("core_leads_operator_accessible",), True),
        (("rank_operator_accessible",), "browser-core"),
        (("vendor_global_telemetry_millions_claim",), True),
        (("note",), "private-commercial-note-marker"),
    ):
        mutation = copy.deepcopy(report)
        target = mutation
        for segment in path[:-1]:
            target = target[segment]
        target[path[-1]] = replacement
        mutations.append(mutation)
    extra = copy.deepcopy(report)
    extra["private"] = "private-commercial-field-marker"
    mutations.append(extra)

    for mutation in mutations:
        with pytest.raises(ContractError) as failure:
            validate_commercial_volume_report(mutation)
        assert "private-commercial" not in str(failure.value)


@pytest.mark.parametrize(
    ("body", "expected_rank", "expected_lead"),
    [(b"[]", "browser-core", True), (b"[{},{}]", "kameleo", False)],
)
def test_commercial_comparison_ranks_valid_reachable_receipts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    body: bytes,
    expected_rank: str,
    expected_lead: bool,
) -> None:
    class Response:
        def getcode(self) -> int:
            return 200

        def read(self, _maximum: int) -> bytes:
            return body

        def close(self) -> None:
            return None

    evidence = {"schema": "owned-fixture/1", "source": "controlled-coherence"}
    persona = fixture_persona()
    store_persona_evidence(
        tmp_path, evidence, expected_sha256=persona["provenance"]["source_sha256"]
    )
    add_persona(tmp_path, persona)
    monkeypatch.setattr("browser_core.personas._open_kameleo_operator_url", lambda *_a, **_k: Response())

    report = compare_commercial_volume(
        tmp_path, kameleo_base_url="http://127.0.0.1:5050", baseline_active=0
    )
    assert report["rank_operator_accessible"] == expected_rank
    assert report["core_leads_operator_accessible"] is expected_lead
    assert validate_commercial_volume_report(json.loads(json.dumps(report)))


@pytest.mark.parametrize(
    "base_url",
    [
        "https://127.0.0.1:5050",
        "http://example.com:5050",
        "http://user:password@127.0.0.1:5050",
        "http://127.0.0.1:5050?",
        "http://127.0.0.1:5050#",
        "http://127.0.0.1:5050/?",
        "http://127.0.0.1:5050/private",
        "http://127.0.0.1",
    ],
)
def test_kameleo_inventory_rejects_non_loopback_or_ambiguous_endpoints(
    monkeypatch: pytest.MonkeyPatch,
    base_url: str,
) -> None:
    monkeypatch.setattr(
        "browser_core.personas._open_kameleo_operator_url",
        lambda *_args, **_kwargs: pytest.fail("invalid endpoint reached transport"),
    )
    with pytest.raises(ContractError, match="loopback HTTP"):
        count_kameleo_operator_inventory(base_url=base_url)


def test_kameleo_localhost_is_normalized_before_plaintext_contact(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    contacted: list[str] = []

    class Response:
        def getcode(self) -> int:
            return 200

        def read(self, _maximum: int) -> bytes:
            return b"[]"

        def close(self) -> None:
            pass

    def open_fixture(url: str, *, timeout: float) -> Response:
        contacted.append(url)
        return Response()

    monkeypatch.setattr("browser_core.personas._open_kameleo_operator_url", open_fixture)
    assert count_kameleo_operator_inventory()["count"] == 0
    assert count_kameleo_operator_inventory(base_url="http://LOCALHOST:5051/")["count"] == 0
    assert contacted == [
        "http://127.0.0.1:5050/fingerprints",
        "http://127.0.0.1:5051/fingerprints",
    ]


def test_kameleo_inventory_does_not_follow_operator_redirect() -> None:
    target_hits: list[str] = []

    class Target(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            target_hits.append(self.path)
            self.send_response(200)
            self.send_header("Content-Length", "4")
            self.end_headers()
            self.wfile.write(b"[{}]")

        def log_message(self, *_args: object) -> None:
            pass

    target = ThreadingHTTPServer(("127.0.0.1", 0), Target)

    class Redirect(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            self.send_response(302)
            self.send_header(
                "Location", f"http://127.0.0.1:{target.server_port}/fingerprints"
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
        result = count_kameleo_operator_inventory(
            base_url=f"http://127.0.0.1:{source.server_port}"
        )
        assert result["count"] is None
        assert target_hits == []
    finally:
        source.shutdown()
        target.shutdown()
        source.server_close()
        target.server_close()
        source_thread.join(timeout=2)
        target_thread.join(timeout=2)


@pytest.mark.parametrize("timeout", [True, "1", 0, float("nan"), 121, 10**400])
def test_kameleo_inventory_rejects_invalid_timeout_before_transport(
    monkeypatch: pytest.MonkeyPatch,
    timeout,
) -> None:
    monkeypatch.setattr(
        "browser_core.personas._open_kameleo_operator_url",
        lambda *_args, **_kwargs: pytest.fail("invalid timeout reached transport"),
    )
    with pytest.raises(ContractError, match="timeout"):
        count_kameleo_operator_inventory(timeout_seconds=timeout)


def test_kameleo_inventory_response_is_bounded_strict_and_count_capped(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Response:
        def __init__(self, body: bytes) -> None:
            self.body = body
            self.read_limits = []
            self.closed = False

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def close(self) -> None:
            self.closed = True

        def getcode(self) -> int:
            return 200

        def read(self, maximum: int):
            self.read_limits.append(maximum)
            return self.body

    response = Response(b'[{"id":1,"id":2}]')
    monkeypatch.setattr("browser_core.personas._open_kameleo_operator_url", lambda *_a, **_k: response)
    result = count_kameleo_operator_inventory(base_url="http://127.0.0.1:5050")
    assert result["error"] == "invalid-json"
    assert result["endpoint"] == "http://loopback:5050/fingerprints"
    assert response.read_limits == [
        personas_module.MAX_KAMELEO_INVENTORY_RESPONSE_BYTES + 1
    ]
    assert response.closed is True

    monkeypatch.setattr(personas_module, "MAX_KAMELEO_FINGERPRINTS", 1)
    response.body = b"[{},{}]"
    result = count_kameleo_operator_inventory(base_url="http://localhost:5050")
    assert result["error"] == "inventory-too-large"
    assert result["count"] is None

    response.body = b"x" * (personas_module.MAX_KAMELEO_INVENTORY_RESPONSE_BYTES + 1)
    result = count_kameleo_operator_inventory(base_url="http://[::1]:5050")
    assert result["error"] == "response-too-large"


def test_kameleo_inventory_owns_response_without_entering_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Response:
        def __init__(self) -> None:
            self.closed = False

        def __enter__(self):
            raise AssertionError("implicit response context must not be entered")

        def getcode(self) -> int:
            return 200

        def read(self, _maximum: int) -> bytes:
            return b"[{},{}]"

        def close(self) -> None:
            self.closed = True

    response = Response()
    monkeypatch.setattr("browser_core.personas._open_kameleo_operator_url", lambda *_a, **_k: response)

    result = count_kameleo_operator_inventory(base_url="http://127.0.0.1:5050")
    assert result["reachable"] is True
    assert result["count"] == 2
    assert result["error"] is None
    assert response.closed is True
    assert validate_kameleo_inventory_report(json.loads(json.dumps(result)))


def test_kameleo_inventory_rejects_complete_json_in_short_declared_body(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Response:
        def __init__(self) -> None:
            self.length = 4
            self.sent = False
            self.closed = False

        def getcode(self) -> int:
            return 200

        def read1(self, _maximum: int) -> bytes:
            if self.sent:
                return b""
            self.sent = True
            self.length -= 2
            return b"[]"

        def close(self) -> None:
            self.closed = True

    response = Response()
    monkeypatch.setattr(
        personas_module, "_open_kameleo_operator_url", lambda *_a, **_k: response
    )

    result = count_kameleo_operator_inventory(base_url="http://127.0.0.1:5050")

    assert result["reachable"] is True
    assert result["count"] is None
    assert result["error"] == "invalid-body"
    assert response.closed


def test_kameleo_inventory_stops_fragmented_body_at_deadline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = [0.0]
    monkeypatch.setattr(personas_module, "time", SimpleNamespace(monotonic=lambda: clock[0]))

    class Response:
        closed = False
        read_calls = 0

        def getcode(self) -> int:
            return 200

        def read(self, _maximum: int) -> bytes:
            pytest.fail("aggregate inventory read can outlive the deadline")

        def read1(self, _maximum: int) -> bytes:
            self.read_calls += 1
            clock[0] += 0.06
            return b"x"

        def close(self) -> None:
            self.closed = True

    response = Response()
    monkeypatch.setattr(
        personas_module,
        "_open_kameleo_operator_url",
        lambda *_args, **_kwargs: response,
    )
    result = count_kameleo_operator_inventory(
        base_url="http://127.0.0.1:5050", timeout_seconds=0.1
    )
    assert result["reachable"] is True
    assert result["count"] is None
    assert result["error"] == "invalid-body"
    assert response.read_calls == 2
    assert response.closed


def test_kameleo_inventory_rejects_decode_completed_after_deadline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = [0.0]
    monkeypatch.setattr(personas_module, "time", SimpleNamespace(monotonic=lambda: clock[0]))

    class Response:
        closed = False

        def getcode(self) -> int:
            return 200

        def read(self, _maximum: int) -> bytes:
            return b"[]"

        def close(self) -> None:
            self.closed = True

    response = Response()
    monkeypatch.setattr(
        personas_module,
        "_open_kameleo_operator_url",
        lambda *_args, **_kwargs: response,
    )

    def late_decode(*_args, **_kwargs):
        clock[0] = 2.0
        return []

    monkeypatch.setattr(personas_module, "decode_strict_json_bytes", late_decode)
    result = count_kameleo_operator_inventory(
        base_url="http://127.0.0.1:5050", timeout_seconds=1.0
    )
    assert result["reachable"] is True
    assert result["count"] is None
    assert result["error"] == "invalid-body"
    assert response.closed


def test_kameleo_receipt_validator_closes_success_and_failure_variants(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Response:
        def getcode(self) -> int:
            return 200

        def read(self, _maximum: int) -> bytes:
            return b"[{},{}]"

        def close(self) -> None:
            return None

    monkeypatch.setattr("browser_core.personas._open_kameleo_operator_url", lambda *_a, **_k: Response())
    success = count_kameleo_operator_inventory(base_url="http://127.0.0.1:5050")

    def unreachable(*_args, **_kwargs):
        raise urllib.error.URLError("private unreachable")

    monkeypatch.setattr("browser_core.personas._open_kameleo_operator_url", unreachable)
    failure = count_kameleo_operator_inventory(base_url="http://127.0.0.1:1")
    assert validate_kameleo_inventory_report(success) is success
    assert validate_kameleo_inventory_report(failure) is failure

    private = "private-kameleo-receipt-marker"
    mutations = []
    for source, path, replacement in (
        (success, ("schema",), private),
        (success, ("reachable",), False),
        (success, ("count",), True),
        (success, ("endpoint",), private),
        (success, ("error",), private),
        (success, ("methodology",), private),
        (failure, ("reachable",), True),
        (failure, ("count",), 0),
        (failure, ("error",), private),
    ):
        mutation = copy.deepcopy(source)
        mutation[path[0]] = replacement
        mutations.append(mutation)
    extra = copy.deepcopy(success)
    extra["private"] = private
    mutations.append(extra)

    for mutation in mutations:
        with pytest.raises(ContractError) as error:
            validate_kameleo_inventory_report(mutation)
        assert private not in str(error.value)


def test_kameleo_inventory_close_failure_blocks_a_valid_count(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Response:
        def getcode(self) -> int:
            return 200

        def read(self, _maximum: int) -> bytes:
            return b"[{},{}]"

        def close(self) -> None:
            raise OSError("private inventory close diagnostic")

    monkeypatch.setattr("browser_core.personas._open_kameleo_operator_url", lambda *_a, **_k: Response())

    result = count_kameleo_operator_inventory(base_url="http://127.0.0.1:5050")
    assert result == {
        "schema": "browser-core.kameleo-operator-inventory/1",
        "reachable": True,
        "count": None,
        "endpoint": "http://loopback:5050/fingerprints",
        "error": "response-close",
    }
    assert "private" not in json.dumps(result)


def test_kameleo_inventory_closes_http_error_before_unreachable_receipt(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    stream = io.BytesIO(b"private rejected body")
    error = urllib.error.HTTPError(
        "http://127.0.0.1:5050/fingerprints",
        503,
        "private unavailable",
        {},
        stream,
    )

    def reject(*_args, **_kwargs):
        raise error

    monkeypatch.setattr("browser_core.personas._open_kameleo_operator_url", reject)
    result = count_kameleo_operator_inventory(base_url="http://127.0.0.1:5050")
    assert result["reachable"] is False
    assert result["count"] is None
    assert result["error"] == "HTTPError"
    assert stream.closed is True
    assert "private" not in json.dumps(result)


def test_kameleo_inventory_rejects_non_byte_body_as_closed_receipt(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Response:
        def __init__(self) -> None:
            self.closed = False

        def read(self, _maximum: int) -> str:
            return "private body"

        def getcode(self) -> int:
            return 200

        def close(self) -> None:
            self.closed = True

    response = Response()
    monkeypatch.setattr("browser_core.personas._open_kameleo_operator_url", lambda *_a, **_k: response)
    result = count_kameleo_operator_inventory(base_url="http://127.0.0.1:5050")
    assert result["error"] == "invalid-body"
    assert result["count"] is None
    assert response.closed is True
    assert "private" not in json.dumps(result)


@pytest.mark.parametrize(
    "failure",
    [OSError("private body provider detail"), RuntimeError("private runtime detail")],
)
def test_kameleo_inventory_normalizes_acquired_body_failures(
    monkeypatch: pytest.MonkeyPatch,
    failure,
) -> None:
    class Response:
        def __init__(self) -> None:
            self.closed = False

        def getcode(self) -> int:
            return 200

        def read(self, _maximum: int) -> bytes:
            raise failure

        def close(self) -> None:
            self.closed = True

    response = Response()
    monkeypatch.setattr("browser_core.personas._open_kameleo_operator_url", lambda *_a, **_k: response)

    result = count_kameleo_operator_inventory(base_url="http://127.0.0.1:5050")

    assert result["reachable"] is True
    assert result["count"] is None
    assert result["error"] == "invalid-body"
    assert response.closed is True
    assert "private" not in json.dumps(result)


@pytest.mark.parametrize("status", [True, "200", 204, None])
def test_kameleo_inventory_requires_exact_http_200_before_reading(
    monkeypatch: pytest.MonkeyPatch,
    status,
) -> None:
    class Response:
        def __init__(self) -> None:
            self.closed = False
            self.read_called = False

        def getcode(self):
            return status

        def read(self, _maximum: int) -> bytes:
            self.read_called = True
            return b"[{}]"

        def close(self) -> None:
            self.closed = True

    response = Response()
    monkeypatch.setattr("browser_core.personas._open_kameleo_operator_url", lambda *_a, **_k: response)

    result = count_kameleo_operator_inventory(base_url="http://127.0.0.1:5050")

    assert result["reachable"] is True
    assert result["count"] is None
    assert result["error"] == "invalid-status"
    assert response.read_called is False
    assert response.closed is True


def test_bundle_import_is_integrity_checked_and_conflict_safe(tmp_path: Path) -> None:
    source = tmp_path / "source"
    destination = tmp_path / "destination"
    first = fixture_persona("first")
    second = fixture_persona("second")
    evidence = {"schema": "owned-fixture/1", "source": "controlled-coherence"}
    digest = first["provenance"]["source_sha256"]
    store_persona_evidence(source, evidence, expected_sha256=digest)
    add_persona(source, first)
    add_persona(source, second)
    bundle = export_persona_bundle_from_workspace(source, [second, first])
    assert import_persona_bundle(destination, bundle) == {"imported": 2, "unchanged": 0}
    assert import_persona_bundle(destination, bundle) == {"imported": 0, "unchanged": 2}
    assert audit_persona_catalog(destination)["personas"] == 2
    corrupted = copy.deepcopy(bundle)
    corrupted["personas"][0]["name"] = "changed"
    with pytest.raises(ContractError, match="bundle digest"):
        import_persona_bundle(destination, corrupted)
    forged = copy.deepcopy(bundle)
    forged["evidence"][0]["document"]["source"] = "forged"
    forged_payload = {
        key: value for key, value in forged.items() if key != "bundle_sha256"
    }
    forged["bundle_sha256"] = hashlib.sha256(
        json.dumps(forged_payload, sort_keys=True, separators=(",", ":")).encode(
            "utf-8"
        )
    ).hexdigest()
    with pytest.raises(ContractError, match="evidence digest"):
        import_persona_bundle(destination, forged)


def test_persona_bundle_export_detaches_caller_inputs() -> None:
    persona = fixture_persona("bundle-detached")
    evidence = {"schema": "owned-fixture/1", "source": "controlled-coherence"}
    digest = persona["provenance"]["source_sha256"]
    bundle = export_persona_bundle([persona], evidence_by_sha256={digest: evidence})
    original_bundle = copy.deepcopy(bundle)

    persona["name"] = "Caller changed persona"
    evidence["source"] = "caller-changed-evidence"
    assert bundle == original_bundle


@pytest.mark.parametrize("mutation", ["persona", "sensitive-evidence"])
def test_persona_bundle_export_revalidates_serialized_payload(
    monkeypatch: pytest.MonkeyPatch, mutation: str
) -> None:
    persona = fixture_persona("bundle-mutated-before-serialize")
    evidence = {"schema": "owned-fixture/1", "source": "controlled-coherence"}
    digest = persona["provenance"]["source_sha256"]
    original_canonical = personas_module._canonical
    mutated = False

    def mutate_before_canonicalization(value):
        nonlocal mutated
        if (
            not mutated
            and isinstance(value, dict)
            and value.get("schema") == personas_module.PERSONA_BUNDLE_SCHEMA
        ):
            mutated = True
            if mutation == "persona":
                value["personas"][0]["name"] = "Changed after validation"
            else:
                value["evidence"][0]["document"]["password"] = "private-test-marker"
        return original_canonical(value)

    monkeypatch.setattr(personas_module, "_canonical", mutate_before_canonicalization)
    with pytest.raises(ContractError):
        export_persona_bundle([persona], evidence_by_sha256={digest: evidence})
    assert mutated


def test_persona_bundle_import_uses_digest_checked_snapshot(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    persona = fixture_persona("bundle-snapshot")
    evidence = {"schema": "owned-fixture/1", "source": "controlled-coherence"}
    digest = persona["provenance"]["source_sha256"]
    bundle = export_persona_bundle([persona], evidence_by_sha256={digest: evidence})
    changed = copy.deepcopy(persona)
    changed["name"] = "Changed after digest check"
    changed["integrity_sha256"] = persona_digest(changed)
    original_canonical = personas_module._canonical
    mutated = False

    def mutate_after_canonicalization(value):
        nonlocal mutated
        body = original_canonical(value)
        if (
            not mutated
            and isinstance(value, dict)
            and value.get("schema") == personas_module.PERSONA_BUNDLE_SCHEMA
            and "bundle_sha256" not in value
        ):
            bundle["personas"][0] = changed
            mutated = True
        return body

    monkeypatch.setattr(personas_module, "_canonical", mutate_after_canonicalization)
    assert import_persona_bundle(tmp_path, bundle) == {"imported": 1, "unchanged": 0}
    assert mutated
    assert load_persona(tmp_path, persona["id"]) == persona


@pytest.mark.parametrize("changed_entry", ["persona", "evidence"])
def test_persona_bundle_import_rechecks_earlier_saved_entry_before_success(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, changed_entry: str
) -> None:
    first = fixture_persona("import-first")
    second = fixture_persona("import-second")
    evidence = {"schema": "owned-fixture/1", "source": "controlled-coherence"}
    digest = first["provenance"]["source_sha256"]
    bundle = export_persona_bundle(
        [first, second], evidence_by_sha256={digest: evidence}
    )
    competitor = copy.deepcopy(first)
    competitor["name"] = "Competing imported revision"
    competitor["integrity_sha256"] = persona_digest(competitor)
    competitor_bytes = canonical_json_bytes(competitor)
    first_path = tmp_path / "personas" / "catalog" / "import-first.json"
    evidence_path = tmp_path / "personas" / "evidence" / f"{digest}.json"
    foreign_evidence = b'{"schema":"competitor/1"}\n'
    original_add = personas_module.add_persona
    additions = 0

    def change_first_after_second(workspace: Path, document: dict):
        nonlocal additions
        result = original_add(workspace, document)
        additions += 1
        if additions == 2:
            if changed_entry == "persona":
                first_path.write_bytes(competitor_bytes)
            else:
                evidence_path.write_bytes(foreign_evidence)
        return result

    monkeypatch.setattr(personas_module, "add_persona", change_first_after_second)
    with pytest.raises(ContractError):
        import_persona_bundle(tmp_path, bundle)
    assert additions == 2
    if changed_entry == "persona":
        assert first_path.read_bytes() == competitor_bytes
    else:
        assert evidence_path.read_bytes() == foreign_evidence


def test_persona_bundle_import_rechecks_persona_after_final_evidence_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    persona = fixture_persona("import-final-persona-race")
    digest = persona["provenance"]["source_sha256"]
    evidence = {"schema": "owned-fixture/1", "source": "controlled-coherence"}
    bundle = export_persona_bundle([persona], evidence_by_sha256={digest: evidence})
    competitor = copy.deepcopy(persona)
    competitor["name"] = "Competing imported revision"
    competitor["integrity_sha256"] = persona_digest(competitor)
    path = tmp_path / "personas" / "catalog" / f"{persona['id']}.json"
    original_load = personas_module.load_persona_evidence
    changed = False

    def change_after_final_evidence_read(workspace: Path, evidence_digest: str):
        nonlocal changed
        loaded = original_load(workspace, evidence_digest)
        if not changed and path.exists():
            path.write_bytes(canonical_json_bytes(competitor))
            changed = True
        return loaded

    monkeypatch.setattr(
        personas_module, "load_persona_evidence", change_after_final_evidence_read
    )
    with pytest.raises(ContractError, match="bundle changed during import"):
        import_persona_bundle(tmp_path, bundle)
    assert changed
    assert load_persona(tmp_path, persona["id"]) == competitor


def test_deterministic_assignment_stores_only_key_digest(tmp_path: Path) -> None:
    candidates = [fixture_persona("alpha"), fixture_persona("beta")]
    for persona in candidates:
        add_persona(tmp_path, persona)
    first = assign_persona(tmp_path, "customer-sensitive-key", candidates)
    second = assign_persona(
        tmp_path, "customer-sensitive-key", list(reversed(candidates))
    )
    assert first == second
    assert first["persona_id"] in {"alpha", "beta"}
    assert "customer-sensitive-key" not in str(first)
    assignment_file = next((tmp_path / "personas" / "assignments").glob("*.json"))
    assert "customer-sensitive-key" not in assignment_file.read_text(encoding="utf-8")


def test_persona_bundle_rejects_rehashed_unknown_fields_and_enforces_byte_limit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    persona = fixture_persona("bundle-closed")
    evidence = {"schema": "owned-fixture/1", "source": "controlled-coherence"}
    store_persona_evidence(
        tmp_path,
        evidence,
        expected_sha256=persona["provenance"]["source_sha256"],
    )
    add_persona(tmp_path, persona)
    bundle = export_persona_bundle_from_workspace(tmp_path, [persona])
    forged = {**bundle, "operator_notes": "private"}
    payload = {key: value for key, value in forged.items() if key != "bundle_sha256"}
    forged["bundle_sha256"] = hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    with pytest.raises(ContractError, match="fields are invalid"):
        import_persona_bundle(tmp_path / "forged", forged)

    monkeypatch.setattr(personas_module, "MAX_PERSONA_BUNDLE_BYTES", 1)
    with pytest.raises(ContractError, match="byte limit"):
        import_persona_bundle(tmp_path / "bounded", bundle)


@pytest.mark.parametrize("field", ["personas", "evidence"])
def test_persona_bundle_import_checks_item_limits_before_canonicalization(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    field: str,
) -> None:
    monkeypatch.setattr(personas_module, "MAX_PERSONA_BUNDLE_ITEMS", 2)
    bundle = {
        "schema": personas_module.PERSONA_BUNDLE_SCHEMA,
        "personas": [],
        "evidence": [],
        "bundle_sha256": "0" * 64,
    }
    bundle[field] = [None, None, None]

    def canonicalization_must_not_run(_value):
        raise AssertionError("oversized bundle reached canonicalization")

    monkeypatch.setattr(personas_module, "_canonical", canonicalization_must_not_run)
    with pytest.raises(ContractError, match=rf"bundle {field} must be a list"):
        import_persona_bundle(tmp_path, bundle)


def test_persona_bundle_import_validates_workspace_before_bundle_processing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def canonicalization_must_not_run(_value):
        raise AssertionError("invalid workspace reached bundle canonicalization")

    monkeypatch.setattr(personas_module, "_canonical", canonicalization_must_not_run)
    with pytest.raises(ContractError, match="workspace must be a Path") as failure:
        import_persona_bundle("private-workspace", {})
    assert "private-workspace" not in str(failure.value)


def test_persona_bundle_exports_bound_iterables_before_full_consumption(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(personas_module, "MAX_PERSONA_BUNDLE_ITEMS", 3)
    consumed = 0

    def unbounded_personas():
        nonlocal consumed
        while True:
            consumed += 1
            yield fixture_persona(f"persona-{consumed}")

    with pytest.raises(ContractError, match="too many personas"):
        export_persona_bundle(unbounded_personas(), evidence_by_sha256={})
    assert consumed == 4

    consumed = 0
    with pytest.raises(ContractError, match="too many personas"):
        collect_persona_bundle_evidence(tmp_path, unbounded_personas())
    assert consumed == 4

    consumed = 0
    with pytest.raises(ContractError, match="too many personas"):
        export_persona_bundle_from_workspace(tmp_path, unbounded_personas())
    assert consumed == 4


@pytest.mark.parametrize("personas", [None, 1, True])
def test_persona_bundle_exports_normalize_non_iterable_inputs(personas) -> None:
    with pytest.raises(ContractError, match="personas must be iterable"):
        export_persona_bundle(personas, evidence_by_sha256={})


@pytest.mark.parametrize(
    "operation",
    [collect_persona_bundle_evidence, export_persona_bundle_from_workspace],
)
def test_workspace_bundle_exports_validate_empty_workspace_inputs(operation) -> None:
    with pytest.raises(ContractError, match="workspace must be a Path"):
        operation("private-workspace", [])


def test_workspace_bundle_export_rejects_unowned_persona_selection(
    tmp_path: Path,
) -> None:
    persona = fixture_persona("unowned")
    evidence = {"schema": "owned-fixture/1", "source": "controlled-coherence"}
    store_persona_evidence(
        tmp_path,
        evidence,
        expected_sha256=persona["provenance"]["source_sha256"],
    )

    with pytest.raises(ContractError, match="selection must match"):
        export_persona_bundle_from_workspace(tmp_path, [persona])


def test_workspace_bundle_export_rechecks_catalog_after_evidence_collection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    persona = fixture_persona("export-catalog-race")
    evidence = {"schema": "owned-fixture/1", "source": "controlled-coherence"}
    store_persona_evidence(
        tmp_path, evidence, expected_sha256=persona["provenance"]["source_sha256"]
    )
    add_persona(tmp_path, persona)
    path = tmp_path / "personas" / "catalog" / f"{persona['id']}.json"
    competitor = copy.deepcopy(persona)
    competitor["name"] = "Competing export revision"
    competitor["integrity_sha256"] = persona_digest(competitor)
    competitor_bytes = canonical_json_bytes(competitor)
    original_collect = personas_module.collect_persona_bundle_evidence

    def change_during_collection(workspace: Path, selected):
        collected = original_collect(workspace, selected)
        path.write_bytes(competitor_bytes)
        return collected

    monkeypatch.setattr(
        personas_module, "collect_persona_bundle_evidence", change_during_collection
    )
    with pytest.raises(ContractError, match="selection changed during export"):
        export_persona_bundle_from_workspace(tmp_path, [persona])
    assert path.read_bytes() == competitor_bytes


def test_workspace_bundle_export_rechecks_evidence_after_catalog_validation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    persona = fixture_persona("export-evidence-race")
    digest = persona["provenance"]["source_sha256"]
    evidence = {"schema": "owned-fixture/1", "source": "controlled-coherence"}
    store_persona_evidence(tmp_path, evidence, expected_sha256=digest)
    add_persona(tmp_path, persona)
    path = tmp_path / "personas" / "evidence" / f"{digest}.json"
    changed_bytes = canonical_json_bytes({"schema": "owned-fixture/1", "source": "changed"})
    original_load = personas_module.load_persona
    changed = False

    def change_during_final_catalog_check(workspace: Path, persona_id: str):
        nonlocal changed
        loaded = original_load(workspace, persona_id)
        if not changed:
            path.write_bytes(changed_bytes)
            changed = True
        return loaded

    monkeypatch.setattr(personas_module, "load_persona", change_during_final_catalog_check)
    with pytest.raises(ContractError, match="evidence"):
        export_persona_bundle_from_workspace(tmp_path, [persona])
    assert changed
    assert path.read_bytes() == changed_bytes


def test_workspace_bundle_export_rechecks_persona_after_final_evidence_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    persona = fixture_persona("export-final-persona-race")
    digest = persona["provenance"]["source_sha256"]
    evidence = {"schema": "owned-fixture/1", "source": "controlled-coherence"}
    store_persona_evidence(tmp_path, evidence, expected_sha256=digest)
    add_persona(tmp_path, persona)
    competitor = copy.deepcopy(persona)
    competitor["name"] = "Competing export revision"
    competitor["integrity_sha256"] = persona_digest(competitor)
    path = tmp_path / "personas" / "catalog" / f"{persona['id']}.json"
    original_collect = personas_module.collect_persona_bundle_evidence
    calls = 0

    def change_after_final_evidence_read(workspace: Path, selected):
        nonlocal calls
        collected = original_collect(workspace, selected)
        calls += 1
        if calls == 2:
            path.write_bytes(canonical_json_bytes(competitor))
        return collected

    monkeypatch.setattr(
        personas_module,
        "collect_persona_bundle_evidence",
        change_after_final_evidence_read,
    )
    with pytest.raises(ContractError, match="selection changed during export"):
        export_persona_bundle_from_workspace(tmp_path, [persona])
    assert calls == 2
    assert load_persona(tmp_path, persona["id"]) == competitor


def test_profile_bundle_evidence_falls_back_only_when_saved_file_is_missing(
    tmp_path: Path,
) -> None:
    profile_id = "source-profile"
    persona = fixture_persona("profile-source-evidence")
    identity = persona["identity_contract"]
    digest = hashlib.sha256(canonical_json_bytes(identity)[:-1]).hexdigest()
    persona["provenance"]["source"] = f"profile:{profile_id}"
    persona["provenance"]["source_sha256"] = digest
    persona["integrity_sha256"] = persona_digest(persona)
    create_profile(tmp_path, profile_id)
    identity_file = tmp_path / "source-identity.json"
    identity_file.write_bytes(canonical_json_bytes(identity))
    attach_identity_contract(tmp_path, profile_id, identity_file)
    store_persona_evidence(tmp_path, identity, expected_sha256=digest)
    evidence_file = tmp_path / "personas" / "evidence" / f"{digest}.json"
    evidence_file.write_bytes(canonical_json_bytes({"schema_version": 1, "expected": {"window.platform": "changed"}}))

    with pytest.raises(ContractError, match="integrity"):
        collect_persona_bundle_evidence(tmp_path, [persona])
    evidence_file.unlink()
    assert collect_persona_bundle_evidence(tmp_path, [persona]) == {digest: identity}


@pytest.mark.parametrize("evidence", [None, [], "private", 1])
def test_persona_bundle_export_requires_a_dictionary_evidence_map(evidence) -> None:
    with pytest.raises(ContractError, match="evidence must be a dictionary") as failure:
        export_persona_bundle([], evidence_by_sha256=evidence)
    assert "private" not in str(failure.value)


def test_persona_bundle_rejects_case_insensitive_duplicate_ids() -> None:
    evidence = {"schema": "owned-fixture/1", "source": "controlled-coherence"}
    digest = fixture_persona("Alpha")["provenance"]["source_sha256"]
    with pytest.raises(ContractError, match="duplicate IDs"):
        export_persona_bundle(
            [fixture_persona("Alpha"), fixture_persona("alpha")],
            evidence_by_sha256={digest: evidence},
        )

    payload = {
        "schema": personas_module.PERSONA_BUNDLE_SCHEMA,
        "personas": [fixture_persona("Alpha"), fixture_persona("alpha")],
        "evidence": [{"sha256": digest, "document": evidence}],
    }
    bundle = {
        **payload,
        "bundle_sha256": hashlib.sha256(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest(),
    }
    with pytest.raises(ContractError, match="duplicate IDs"):
        import_persona_bundle(Path("unused"), bundle)


def test_persona_bundle_preflights_local_ids_case_insensitively(tmp_path: Path) -> None:
    source = tmp_path / "source"
    destination = tmp_path / "destination"
    evidence = {"schema": "owned-fixture/1", "source": "controlled-coherence"}
    incoming = fixture_persona("alpha")
    digest = incoming["provenance"]["source_sha256"]
    store_persona_evidence(source, evidence, expected_sha256=digest)
    add_persona(source, incoming)
    bundle = export_persona_bundle_from_workspace(source, [incoming])
    add_persona(destination, fixture_persona("Alpha"))

    with pytest.raises(ContractError, match="conflicts with local ID"):
        import_persona_bundle(destination, bundle)
    assert not (destination / "personas" / "evidence").exists()


def test_catalog_read_fails_closed_on_case_insensitive_duplicate_ids(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    inventory = SimpleNamespace(
        files=(("Alpha.json", "identity-a"), ("alpha.json", "identity-b"))
    )
    personas = {
        "Alpha": fixture_persona("Alpha"),
        "alpha": fixture_persona("alpha"),
    }

    monkeypatch.setattr(
        personas_module,
        "inventory_bounded_json_directory",
        lambda *_args, **_kwargs: inventory,
    )

    def load(_workspace, persona_id, **_kwargs):
        suffix = "a" if persona_id == "Alpha" else "b"
        return personas[persona_id], SimpleNamespace(
            identity=f"identity-{suffix}", body=canonical_json_bytes(personas[persona_id])
        )

    monkeypatch.setattr(personas_module, "_read_persona_snapshot", load)
    with pytest.raises(ContractError, match="catalog contains duplicate IDs"):
        list_personas(tmp_path, include_deprecated=True)


def test_assignment_fails_closed_if_selected_persona_disappears(tmp_path: Path) -> None:
    candidates = [fixture_persona("alpha"), fixture_persona("beta")]
    for candidate in candidates:
        add_persona(tmp_path, candidate)
    assignment = assign_persona(tmp_path, "stable", candidates)
    remaining = [item for item in candidates if item["id"] != assignment["persona_id"]]
    with pytest.raises(ContractError, match="no longer available"):
        assign_persona(tmp_path, "stable", remaining)


def test_assignment_rejects_case_insensitive_duplicate_candidate_ids(
    tmp_path: Path,
) -> None:
    with pytest.raises(ContractError, match="duplicate candidate IDs"):
        assign_persona(
            tmp_path,
            "stable",
            [fixture_persona("Alpha"), fixture_persona("alpha")],
        )
    assert not (tmp_path / "personas" / "assignments").exists()


def test_assignment_rejects_deprecated_candidates_before_persistence(
    tmp_path: Path,
) -> None:
    deprecated = fixture_persona("retired")
    deprecated["state"] = "deprecated"
    deprecated["state_changed_at"] = "2026-08-12T00:00:00Z"
    deprecated["integrity_sha256"] = persona_digest(deprecated)

    with pytest.raises(ContractError, match="candidates must be active"):
        assign_persona(tmp_path, "stable", [deprecated])
    assert not (tmp_path / "personas" / "assignments").exists()


def test_assignment_rejects_active_documents_not_owned_by_the_workspace(
    tmp_path: Path,
) -> None:
    with pytest.raises(ContractError, match="active workspace catalog"):
        assign_persona(tmp_path, "stable", [fixture_persona("unowned")])
    assert not (tmp_path / "personas" / "assignments").exists()


def test_owned_profile_contract_can_be_captured_without_manual_persona_json(
    tmp_path: Path,
) -> None:
    create_profile(tmp_path, "measured")
    contract = tmp_path / "identity.json"
    contract.write_text(
        '{"schema_version":1,"expected":{"userAgentData.mobile":false,"window.platform":"Win32","window.screen.width":2560,"window.screen.height":1440}}',
        encoding="utf-8",
    )
    attach_identity_contract(tmp_path, "measured", contract)
    persona = capture_profile_persona(
        tmp_path,
        profile_id="measured",
        persona_id="owned-win",
        name="Owned Windows",
        os_family="windows",
        os_version="11",
        architecture="x86_64",
        browser_major=153,
        viewport_width=2560,
        viewport_height=1440,
        device_scale_factor=1,
        country="US",
        locale="en-US",
        languages=["en-US"],
        timezone_name="America/Chicago",
        tags=["owned"],
    )
    assert persona["provenance"]["source"] == "profile:measured"
    assert persona["kernel"]["minimum_major"] == 153
    assert persona["identity_contract"]["expected"]["window.platform"] == "Win32"
    assert persona["device"]["screen"] == {"width": 2560, "height": 1440}
    add_persona(tmp_path, persona)
    assert (
        audit_persona_catalog(tmp_path)["verified"][0]["evidence_kind"]
        == "profile-identity-contract"
    )
    destination = tmp_path / "portable"
    bundle = export_persona_bundle_from_workspace(tmp_path, [persona])
    assert import_persona_bundle(destination, bundle) == {"imported": 1, "unchanged": 0}
    assert (
        audit_persona_catalog(destination)["verified"][0]["evidence_kind"]
        == "bundled-profile-identity-contract"
    )


def test_profile_persona_capture_rechecks_source_after_coherence_validation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    create_profile(tmp_path, "measured")
    contract = tmp_path / "identity.json"
    contract.write_text(
        '{"schema_version":1,"expected":{"userAgentData.mobile":false,"window.platform":"Win32","window.screen.width":2560,"window.screen.height":1440}}',
        encoding="utf-8",
    )
    attach_identity_contract(tmp_path, "measured", contract)
    source = tmp_path / "profiles" / "data" / "measured" / "identity-contract.json"
    competitor = canonical_json_bytes(
        {"schema_version": 1, "expected": {"window.platform": "changed"}}
    )
    original_reject = personas_module.reject_incoherent_persona

    def change_after_validation(persona: dict):
        validated = original_reject(persona)
        source.write_bytes(competitor)
        return validated

    monkeypatch.setattr(personas_module, "reject_incoherent_persona", change_after_validation)
    with pytest.raises(ContractError, match="profile identity"):
        capture_profile_persona(
            tmp_path,
            profile_id="measured",
            persona_id="stale-profile-source",
            name="Stale profile source",
            os_family="windows",
            os_version="11",
            architecture="x86_64",
            browser_major=153,
            viewport_width=2560,
            viewport_height=1440,
            device_scale_factor=1,
            country="US",
            locale="en-US",
            languages=["en-US"],
            timezone_name="America/Chicago",
        )
    assert source.read_bytes() == competitor


def test_profile_persona_rejects_a_user_agent_from_another_browser_major(
    tmp_path: Path,
) -> None:
    create_profile(tmp_path, "mismatched-user-agent")
    contract = tmp_path / "identity.json"
    contract.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "expected": {
                    "window.userAgent": "Mozilla/5.0 Chrome/152.0.0.0 Safari/537.36",
                    "window.platform": "Win32",
                    "window.screen.width": 1920,
                    "window.screen.height": 1080,
                },
            }
        ),
        encoding="utf-8",
    )
    attach_identity_contract(tmp_path, "mismatched-user-agent", contract)

    with pytest.raises(ContractError, match="user-agent-major-contradicts-kernel"):
        capture_profile_persona(
            tmp_path,
            profile_id="mismatched-user-agent",
            persona_id="mismatched-user-agent",
            name="Mismatched user agent",
            os_family="windows",
            os_version="11",
            architecture="x86_64",
            browser_major=153,
            viewport_width=1280,
            viewport_height=720,
            device_scale_factor=1,
            country="US",
            locale="en-US",
            languages=["en-US", "en"],
            timezone_name="America/Chicago",
        )


def test_persona_deprecation_uses_optimistic_integrity_revision(tmp_path: Path) -> None:
    persona = add_persona(tmp_path, fixture_persona())
    deprecated = set_persona_state(
        tmp_path,
        persona["id"],
        "deprecated",
        expected_sha256=persona["integrity_sha256"],
    )
    assert deprecated["state"] == "deprecated"
    assert list_personas(tmp_path) == []
    assert list_personas(tmp_path, include_deprecated=True) == [deprecated]
    with pytest.raises(ContractError, match="revision race"):
        set_persona_state(
            tmp_path,
            persona["id"],
            "active",
            expected_sha256=persona["integrity_sha256"],
        )


@pytest.mark.parametrize("operation", ["add", "state"])
def test_persona_catalog_write_rechecks_saved_document_before_success(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, operation: str
) -> None:
    persona = fixture_persona()
    if operation == "state":
        add_persona(tmp_path, persona)
    catalog = tmp_path / "personas" / "catalog" / f"{persona['id']}.json"
    original_write = personas_module._write_json_atomic
    replaced = False

    def replace_after_write(path: Path, document: dict, *, expected=None):
        nonlocal replaced
        result = original_write(path, document, expected=expected)
        replacement = json.loads(path.read_bytes())
        replacement["name"] = "Changed after publication"
        replacement["integrity_sha256"] = persona_digest(replacement)
        path.write_bytes(canonical_json_bytes(replacement))
        replaced = True
        return result

    monkeypatch.setattr(personas_module, "_write_json_atomic", replace_after_write)
    with pytest.raises(ContractError, match="changed after publication"):
        if operation == "add":
            add_persona(tmp_path, persona)
        else:
            set_persona_state(
                tmp_path, persona["id"], "deprecated",
                expected_sha256=persona["integrity_sha256"],
            )
    assert replaced
    assert json.loads(catalog.read_bytes())["name"] == "Changed after publication"


@pytest.mark.parametrize(
    ("state", "revision"),
    [
        ({"private": "state"}, "a" * 64),
        ("removed", "a" * 64),
        ("active", True),
        ("active", "private-revision"),
    ],
)
def test_persona_state_change_validates_intent_before_catalog_access(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    state,
    revision,
) -> None:
    touched = False

    def fail_if_touched(*_args, **_kwargs):
        nonlocal touched
        touched = True
        raise AssertionError("catalog must not be read")

    monkeypatch.setattr(personas_module, "_load_persona_snapshot", fail_if_touched)
    with pytest.raises(ContractError):
        set_persona_state(
            tmp_path,
            "persona-1",
            state,
            expected_sha256=revision,
        )
    assert touched is False


def test_live_owned_kernel_probe_can_be_captured_as_a_persona() -> None:
    root = Path(__file__).resolve().parents[1]
    persona, evidence = capture_kernel_persona(
        root,
        persona_id="owned-pw-chromium",
        name="Owned Playwright Chromium",
        kernel_id="playwright-chromium",
        device_preset="Desktop Chrome HiDPI",
        os_family="windows",
        os_version="11",
        architecture="x86_64",
        country="US",
        locale="en-US",
        timezone_name="America/Chicago",
        tags=("owned", "lab-verified"),
    )
    probe = evidence["probe"]
    assert probe["passed"] is True
    assert persona["provenance"]["source"].startswith(
        "kernel-probe:playwright-chromium:"
    )
    assert persona["kernel"]["engine"] == "chromium"
    assert persona["identity_contract"]["expected"]["rendering.webgl.renderer"]


def test_kernel_persona_rejects_a_non_string_browser_version() -> None:
    kernel = {"id": "owned-core", "engine": "chromium", "product": "browser-core"}
    device = {
        "id": "owned-desktop",
        "realization": "emulated",
        "class": "desktop",
        "is_mobile": False,
        "has_touch": False,
        "viewport": {"width": 1280, "height": 720},
        "device_scale_factor": 1,
        "screen": {"width": 1920, "height": 1080},
    }
    probe = {
        "schema": "browser-core.kernel-probe/1",
        "kernel_id": "owned-core",
        "engine": "chromium",
        "device_id": "owned-desktop",
        "device_realization": "emulated",
        "passed": True,
        "checks": dict.fromkeys((
            "owned_fixture", "secure_context", "viewport", "screen",
            "scale", "touch", "locale", "timezone", "user_agent",
            "user_agent_matches_client_hints", "client_hints_mobile",
        ), True),
        # JSON numbers are valid evidence values, but a browser version is a
        # measured wire string. Coercing this value would erase that boundary.
        "browser_version": 153,
        "observed": {
            "language": "en-US",
            "languages": ["en-US", "en"],
            "platform": "Win32",
            "maxTouchPoints": 0,
            "hardwareConcurrency": 8,
            "pluginsLength": 5,
            "mimeTypesLength": 2,
            "innerWidth": 1280,
            "innerHeight": 720,
            "screenWidth": 1920,
            "screenHeight": 1080,
            "colorDepth": 24,
            "pixelDepth": 24,
            "devicePixelRatio": 1,
            "timezone": "America/Chicago",
            "webglIdentitySchema": "webgl2-preferred-unmasked-v1",
            "intlLocale": "en-US",
            "webglVendor": "Google Inc.",
            "webglRenderer": "ANGLE (GPU)",
            "webglVersion": "WebGL 1.0 (OpenGL ES 2.0 Chromium)",
        },
    }

    with pytest.raises(ContractError, match="browser version"):
        persona_from_kernel_probe(
            kernel,
            device,
            probe,
            persona_id="non-string-version",
            name="Non-string version",
            kernel_id="owned-core",
            os_family="windows",
            os_version="11",
            architecture="x86_64",
            country="US",
            locale="en-US",
            timezone_name="America/Chicago",
        )


def test_kernel_persona_rejects_unhashable_device_class() -> None:
    kernel = {"id": "owned-core", "engine": "chromium"}
    device = {"id": "owned-desktop", "realization": "emulated", "class": []}
    probe = {
        "schema": "browser-core.kernel-probe/1",
        "kernel_id": "owned-core",
        "engine": "chromium",
        "device_id": "owned-desktop",
        "device_realization": "emulated",
        "passed": True,
    }
    with pytest.raises(ContractError, match="device class"):
        persona_from_kernel_probe(
            kernel,
            device,
            probe,
            persona_id="invalid-class",
            name="Invalid class",
            kernel_id="owned-core",
            os_family="windows",
            os_version="11",
            architecture="x86_64",
            country="US",
            locale="en-US",
            timezone_name="America/Chicago",
        )


def test_kernel_persona_detaches_returned_documents_from_probe_inputs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    kernel = {"id": "owned-core", "engine": "chromium", "product": "browser-core"}
    device = {
        "id": "owned-desktop", "realization": "emulated", "class": "desktop",
        "is_mobile": False, "has_touch": False,
        "viewport": {"width": 1280, "height": 720},
        "device_scale_factor": 1,
        "screen": {"width": 1920, "height": 1080},
    }
    probe = {
        "schema": "browser-core.kernel-probe/1",
        "kernel_id": "owned-core", "engine": "chromium",
        "device_id": "owned-desktop", "device_realization": "emulated",
        "passed": True,
        "checks": dict.fromkeys((
            "owned_fixture", "secure_context", "viewport", "screen", "scale",
            "touch", "locale", "timezone", "user_agent",
            "user_agent_matches_client_hints", "client_hints_mobile",
        ), True),
        "browser_version": "153.0.0",
        "observed": {
            "languages": ["en-US", "en"], "platform": "Win32",
            "maxTouchPoints": 0, "hardwareConcurrency": 8,
            "pluginsLength": 5, "mimeTypesLength": 2,
            "innerWidth": 1280, "innerHeight": 720,
            "screenWidth": 1920, "screenHeight": 1080,
            "colorDepth": 24, "pixelDepth": 24, "devicePixelRatio": 1,
            "timezone": "America/Chicago",
            "webglIdentitySchema": "webgl2-preferred-unmasked-v1",
            "intlLocale": "en-US", "webglVendor": "Google Inc.",
            "webglRenderer": "ANGLE (GPU)",
            "webglVersion": "WebGL 1.0 (OpenGL ES 2.0 Chromium)",
        },
    }
    # Coherence is a separate gate; the reference-custody test needs only a
    # schema-valid synthetic probe and its generated persona.
    monkeypatch.setattr(personas_module, "reject_incoherent_persona", lambda value: value)
    persona, evidence = persona_from_kernel_probe(
        kernel, device, probe,
        persona_id="detached-probe", name="Detached probe", kernel_id="owned-core",
        os_family="windows", os_version="11", architecture="x86_64",
        country="US", locale="en-US", timezone_name="America/Chicago",
    )
    original_digest = hashlib.sha256(
        json.dumps(evidence, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    ).hexdigest()
    assert persona["provenance"]["source_sha256"] == original_digest

    kernel["id"] = "caller-changed"
    device["screen"]["width"] = 1
    probe["observed"]["languages"][0] = "caller-changed"
    assert evidence["kernel"]["id"] == "owned-core"
    assert evidence["device"]["screen"]["width"] == 1920
    assert evidence["probe"]["observed"]["languages"][0] == "en-US"
    assert persona["device"]["screen"]["width"] == 1920
    assert persona["geography"]["languages"][0] == "en-US"
    assert persona_digest(persona) == persona["integrity_sha256"]


def test_physical_android_persona_retains_the_measured_user_agent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import browser_core.physical_mobile as physical_module

    user_agent = (
        "Mozilla/5.0 (Linux; Android 14; Pixel 7) AppleWebKit/537.36 "
        "Chrome/153.0.7988.0 Mobile Safari/537.36"
    )
    probe = {
        "schema": physical_module.PHYSICAL_PROBE_SCHEMA,
        "platform": "android",
        "passed": True,
        "realization": "physical-device",
        "checks": dict.fromkeys(PHYSICAL_PROBE_FIXTURE_CHECKS, True),
        "device": {
            "browser_version": "153.0.7988.0",
            "architecture": "arm64-v8a",
            "os_version": "14",
        },
        "observed": {
            "userAgent": user_agent,
            "languages": ["en-US", "en"],
            "platform": "Linux armv8l",
            "maxTouchPoints": 5,
            "hardwareConcurrency": 8,
            "innerWidth": 412,
            "innerHeight": 915,
            "screenWidth": 412,
            "screenHeight": 915,
            "devicePixelRatio": 2.625,
            "timezone": "America/Chicago",
            "webglIdentitySchema": "webgl2-preferred-unmasked-v1",
            "intlLocale": "en-US",
            "webglVendor": "WebKit",
            "webglRenderer": "GPU",
            "webglVersion": "WebGL 1.0 (OpenGL ES 2.0 Chromium)",
        },
    }
    monkeypatch.setattr(
        physical_module,
        "probe_physical_android",
        lambda **_kwargs: probe,
    )

    persona, evidence = capture_physical_android_persona(
        persona_id="physical-user-agent",
        name="Physical user agent",
        country="US",
    )

    assert evidence is probe
    assert persona["identity_contract"]["expected"]["window.userAgent"] == user_agent


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("schema", "unrelated-probe/1"),
        ("platform", "ios"),
        ("checks", {"owned_fixture": False}),
        ("checks", {"owned_fixture": True}),
    ],
)
def test_physical_android_persona_rejects_contradictory_probe_receipt(
    monkeypatch: pytest.MonkeyPatch, field: str, value: object,
) -> None:
    import browser_core.physical_mobile as physical_module

    probe = {
        "schema": physical_module.PHYSICAL_PROBE_SCHEMA,
        "platform": "android",
        "passed": True,
        "realization": "physical-device",
        "checks": dict.fromkeys(PHYSICAL_PROBE_FIXTURE_CHECKS, True),
        "device": {
            "browser_version": "153.0.7988.0",
            "architecture": "arm64-v8a",
            "os_version": "14",
        },
        "observed": {
            "userAgent": "Mozilla/5.0 Android Chrome/153.0.7988.0 Mobile Safari/537.36",
            "languages": ["en-US", "en"],
            "platform": "Linux armv8l",
            "maxTouchPoints": 5,
            "hardwareConcurrency": 8,
            "innerWidth": 412,
            "innerHeight": 915,
            "screenWidth": 412,
            "screenHeight": 915,
            "devicePixelRatio": 2.625,
            "timezone": "America/Chicago",
            "webglIdentitySchema": "webgl2-preferred-unmasked-v1",
            "intlLocale": "en-US",
            "webglVendor": "WebKit",
            "webglRenderer": "GPU",
            "webglVersion": "WebGL 1.0 (OpenGL ES 2.0 Chromium)",
        },
    }
    probe[field] = value
    monkeypatch.setattr(physical_module, "probe_physical_android", lambda **_kwargs: probe)

    with pytest.raises(ContractError, match="physical Android probe receipt"):
        capture_physical_android_persona(
            persona_id="physical-invalid-receipt",
            name="Physical invalid receipt",
            country="US",
        )


def test_physical_android_persona_rejects_a_user_agent_from_another_major(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import browser_core.physical_mobile as physical_module

    probe = {
        "schema": physical_module.PHYSICAL_PROBE_SCHEMA,
        "platform": "android",
        "passed": True,
        "realization": "physical-device",
        "checks": dict.fromkeys(PHYSICAL_PROBE_FIXTURE_CHECKS, True),
        "device": {
            "browser_version": "153.0.7988.0",
            "architecture": "arm64-v8a",
            "os_version": "14",
        },
        "observed": {
            "userAgent": "Mozilla/5.0 Android Chrome/152.0.0.0 Mobile Safari/537.36",
            "languages": ["en-US", "en"],
            "platform": "Linux armv8l",
            "maxTouchPoints": 5,
            "hardwareConcurrency": 8,
            "innerWidth": 412,
            "innerHeight": 915,
            "screenWidth": 412,
            "screenHeight": 915,
            "devicePixelRatio": 2.625,
            "timezone": "America/Chicago",
            "webglIdentitySchema": "webgl2-preferred-unmasked-v1",
            "intlLocale": "en-US",
            "webglVendor": "WebKit",
            "webglRenderer": "GPU",
            "webglVersion": "WebGL 1.0 (OpenGL ES 2.0 Chromium)",
        },
    }
    monkeypatch.setattr(
        physical_module,
        "probe_physical_android",
        lambda **_kwargs: probe,
    )

    with pytest.raises(ContractError, match="user-agent-major-contradicts-kernel"):
        capture_physical_android_persona(
            persona_id="physical-major-mismatch",
            name="Physical major mismatch",
            country="US",
        )


@pytest.mark.parametrize("browser_version", ["١٥٣.0.7988.0", 153])
def test_physical_android_persona_rejects_a_malformed_browser_version(
    monkeypatch: pytest.MonkeyPatch, browser_version,
) -> None:
    import browser_core.physical_mobile as physical_module

    probe = {
        "schema": physical_module.PHYSICAL_PROBE_SCHEMA,
        "platform": "android",
        "passed": True,
        "realization": "physical-device",
        "checks": dict.fromkeys(PHYSICAL_PROBE_FIXTURE_CHECKS, True),
        "device": {
            "browser_version": browser_version,
            "architecture": "arm64-v8a",
            "os_version": "14",
        },
        "observed": {
            "userAgent": "Mozilla/5.0 Android Chrome/153.0.7988.0 Mobile Safari/537.36",
            "languages": ["en-US", "en"],
            "platform": "Linux armv8l",
            "maxTouchPoints": 5,
            "hardwareConcurrency": 8,
            "innerWidth": 412,
            "innerHeight": 915,
            "screenWidth": 412,
            "screenHeight": 915,
            "devicePixelRatio": 2.625,
            "timezone": "America/Chicago",
            "webglIdentitySchema": "webgl2-preferred-unmasked-v1",
            "intlLocale": "en-US",
            "webglVendor": "WebKit",
            "webglRenderer": "GPU",
            "webglVersion": "WebGL 1.0 (OpenGL ES 2.0 Chromium)",
        },
    }
    monkeypatch.setattr(
        physical_module,
        "probe_physical_android",
        lambda **_kwargs: probe,
    )

    with pytest.raises(ContractError, match="browser version"):
        capture_physical_android_persona(
            persona_id="physical-unicode-major",
            name="Physical Unicode major",
            country="US",
        )


def test_persona_evidence_is_content_addressed_and_tamper_checked(
    tmp_path: Path,
) -> None:
    evidence = {"schema": "owned-probe/1", "passed": True, "checks": {"owned": True}}
    digest = hashlib.sha256(
        json.dumps(evidence, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    reference = store_persona_evidence(tmp_path, evidence, expected_sha256=digest)
    assert reference["sha256"] == digest
    assert load_persona_evidence(tmp_path, digest) == evidence
    Path(reference["path"]).write_text('{"tampered":true}\n', encoding="utf-8")
    with pytest.raises(ContractError, match="integrity"):
        load_persona_evidence(tmp_path, digest)


@pytest.mark.parametrize("operation", ["load", "store"])
def test_persona_evidence_rejects_relocated_workspace_ancestor(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, operation: str
) -> None:
    selected = tmp_path / "selected"
    workspace = selected / "workspace"
    workspace.mkdir(parents=True)
    evidence = {"schema": "owned-probe/1", "source": "relocation-test"}
    digest = hashlib.sha256(canonical_json_bytes(evidence)).hexdigest()
    store_persona_evidence(workspace, evidence, expected_sha256=digest)
    path = workspace / "personas" / "evidence" / f"{digest}.json"
    original_bytes = path.read_bytes()
    retained = tmp_path / "retained-selected"
    original_read = personas_module.read_bounded_control_snapshot_result
    moved = False

    def relocate_after_read(target: Path, **kwargs):
        nonlocal moved
        result = original_read(target, **kwargs)
        if target == path and not moved:
            selected.rename(retained)
            selected.mkdir()
            (retained / "workspace").rename(workspace)
            moved = True
        return result

    monkeypatch.setattr(
        personas_module, "read_bounded_control_snapshot_result", relocate_after_read
    )
    with pytest.raises(ContractError, match="workspace changed"):
        if operation == "load":
            load_persona_evidence(workspace, digest)
        else:
            store_persona_evidence(workspace, evidence, expected_sha256=digest)
    assert moved
    assert path.read_bytes() == original_bytes


def test_an_attested_kernel_records_its_own_product_not_its_engine() -> None:
    """`persona_compatible` gates launches on this field.

    Deriving it from the engine alone stamped "chromium" on personas the
    attested Browser Core build had captured, so the build that produced them
    could not launch them. The product is a realization key -- which binary can
    realize this identity -- not something a page can observe; a site sees
    Chrome either way.
    """
    from browser_core.personas import _ENGINE_PRODUCTS

    assert _ENGINE_PRODUCTS == {
        "chromium": "chromium",
        "firefox": "firefox",
        "webkit": "safari",
    }
    assert "browser-core" in ALLOWED_PRODUCTS
    assert "browser-core" not in _ENGINE_PRODUCTS.values()


@pytest.mark.parametrize("field", ["created_at", "provenance.captured_at"])
def test_persona_requires_aware_timestamps(field: str) -> None:
    persona = fixture_persona()
    if field == "created_at":
        persona["created_at"] = "2026-08-10T00:00:00"
    else:
        persona["provenance"]["captured_at"] = "2026-08-10T00:00:00"
    persona["integrity_sha256"] = persona_digest(persona)
    with pytest.raises(ContractError, match="timezone-aware"):
        personas_module.validate_persona(persona)


def test_persona_catalog_is_bounded_and_preserves_a_racing_creator(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    intended = fixture_persona("raced")
    competitor = copy.deepcopy(intended)
    competitor["name"] = "Competitor"
    competitor["integrity_sha256"] = persona_digest(competitor)
    path = tmp_path / "personas" / "catalog" / "raced.json"
    competitor_bytes = canonical_json_bytes(competitor)
    real_publish = personas_module.publish_json_exclusive

    def inject_then_publish(target: Path, document: dict, **kwargs: object) -> bytes:
        target.write_bytes(competitor_bytes)
        return real_publish(target, document, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(personas_module, "publish_json_exclusive", inject_then_publish)
    with pytest.raises(ContractError, match="ID conflict"):
        add_persona(tmp_path, intended)
    assert path.read_bytes() == competitor_bytes

    monkeypatch.setattr(personas_module, "MAX_PERSONA_DOCUMENT_BYTES", 1)
    with pytest.raises(ContractError, match="exceeds 1 bytes"):
        load_persona(tmp_path, "raced")


def test_persona_state_update_preserves_a_racing_revision(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original = add_persona(tmp_path, fixture_persona("state-race"))
    competitor = copy.deepcopy(original)
    competitor["name"] = "Concurrent edit"
    competitor["integrity_sha256"] = persona_digest(competitor)
    path = tmp_path / "personas" / "catalog" / "state-race.json"
    competitor_bytes = canonical_json_bytes(competitor)
    real_replace = personas_module.replace_json_conditionally

    def inject_then_replace(target: Path, document: dict, **kwargs: object) -> None:
        injected = tmp_path / "competitor-persona.json"
        injected.write_bytes(competitor_bytes)
        injected.replace(target)
        real_replace(target, document, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(
        personas_module, "replace_json_conditionally", inject_then_replace
    )
    with pytest.raises(ContractError, match="changed before transition"):
        set_persona_state(
            tmp_path,
            "state-race",
            "deprecated",
            expected_sha256=original["integrity_sha256"],
        )
    assert path.read_bytes() == competitor_bytes


def test_persona_evidence_is_strict_bounded_and_race_safe(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(ContractError, match="strict JSON"):
        store_persona_evidence(
            tmp_path,
            {"measurement": float("nan")},
            expected_sha256="0" * 64,
        )

    for invalid in ({"measurement": "\ud800"}, {"measurement": int("9" * 1025)}):
        with pytest.raises(ContractError):
            store_persona_evidence(
                tmp_path,
                invalid,
                expected_sha256="0" * 64,
            )

    nested: object = 0
    for _ in range(129):
        nested = [nested]
    with pytest.raises(ContractError, match="nesting limit"):
        store_persona_evidence(
            tmp_path,
            {"measurement": nested},
            expected_sha256="0" * 64,
        )

    evidence = {"schema": "owned-probe/1", "value": "intended"}
    body = json.dumps(evidence, sort_keys=True, separators=(",", ":")).encode("utf-8")
    digest = hashlib.sha256(body).hexdigest()
    competitor = b'{"schema":"competitor/1"}\n'
    path = tmp_path / "personas" / "evidence" / f"{digest}.json"
    real_publish = personas_module.publish_bytes_exclusive

    def inject_then_publish(target: Path, intended: bytes, **kwargs: object) -> bytes:
        target.write_bytes(competitor)
        return real_publish(target, intended, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(personas_module, "publish_bytes_exclusive", inject_then_publish)
    with pytest.raises(ContractError, match="content-address collision"):
        store_persona_evidence(tmp_path, evidence, expected_sha256=digest)
    assert path.read_bytes() == competitor

    monkeypatch.setattr(personas_module, "MAX_PERSONA_EVIDENCE_BYTES", 1)
    with pytest.raises(ContractError, match="exceeds 1 bytes"):
        load_persona_evidence(tmp_path, digest)


def test_persona_evidence_requires_typed_address_and_single_link_storage(
    tmp_path: Path,
) -> None:
    evidence = {"schema": "owned-probe/1", "value": "stable"}
    canonical = json.dumps(evidence, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )
    digest = hashlib.sha256(canonical).hexdigest()
    reference = store_persona_evidence(tmp_path, evidence, expected_sha256=digest)
    path = Path(reference["path"])
    os.link(path, tmp_path / "evidence-alias.json")

    with pytest.raises(ContractError, match="hard links"):
        load_persona_evidence(tmp_path, digest)
    with pytest.raises(ContractError, match="hard links"):
        store_persona_evidence(tmp_path, evidence, expected_sha256=digest)
    with pytest.raises(ContractError, match="workspace must be a Path"):
        load_persona_evidence(str(tmp_path), digest)  # type: ignore[arg-type]
    with pytest.raises(ContractError, match="digest is invalid"):
        load_persona_evidence(tmp_path, None)  # type: ignore[arg-type]
    with pytest.raises(ContractError, match="digest is invalid"):
        store_persona_evidence(tmp_path, evidence, expected_sha256=None)  # type: ignore[arg-type]


def test_persona_evidence_store_binds_digest_to_serialized_bytes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    evidence = {"schema": "owned-probe/1", "value": "initial"}
    changed = {**evidence, "value": "changed"}
    digest = hashlib.sha256(canonical_json_bytes(changed)).hexdigest()
    original_canonical = personas_module._canonical
    mutated = False

    def change_after_serializing(value):
        nonlocal mutated
        body = original_canonical(value)
        if value is evidence and not mutated:
            mutated = True
            evidence["value"] = "changed"
        return body

    monkeypatch.setattr(personas_module, "_canonical", change_after_serializing)
    with pytest.raises(ContractError, match="digest does not match"):
        store_persona_evidence(tmp_path, evidence, expected_sha256=digest)
    assert mutated
    assert not (tmp_path / "personas" / "evidence" / f"{digest}.json").exists()


def test_persona_evidence_store_checks_sensitive_keys_in_serialized_bytes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    evidence = {"schema": "owned-probe/1", "value": "initial"}
    digest = hashlib.sha256(
        canonical_json_bytes({**evidence, "password": "private-test-marker"})
    ).hexdigest()
    original_canonical = personas_module._canonical
    injected = False

    def inject_before_serializing(value):
        nonlocal injected
        if value is evidence and not injected:
            injected = True
            evidence["password"] = "private-test-marker"
        return original_canonical(value)

    monkeypatch.setattr(personas_module, "_canonical", inject_before_serializing)
    with pytest.raises(ContractError, match="sensitive"):
        store_persona_evidence(tmp_path, evidence, expected_sha256=digest)
    assert injected
    assert not (tmp_path / "personas" / "evidence" / f"{digest}.json").exists()


@pytest.mark.skipif(os.name != "nt", reason="Windows directory junction boundary")
def test_persona_evidence_store_does_not_create_foreign_parent(
    tmp_path: Path,
) -> None:
    evidence = {"schema": "owned-probe/1", "value": "stable"}
    digest = hashlib.sha256(canonical_json_bytes(evidence)).hexdigest()
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    foreign = tmp_path / "foreign"
    foreign.mkdir()
    junction = workspace / "personas"
    created = subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(junction), str(foreign)],
        capture_output=True, check=False,
    )
    if created.returncode:
        pytest.skip("host could not create an unprivileged directory junction")
    try:
        with pytest.raises(ContractError):
            store_persona_evidence(workspace, evidence, expected_sha256=digest)
        assert not (foreign / "evidence").exists()
    finally:
        junction.rmdir()


@pytest.mark.skipif(os.name != "nt", reason="Windows directory junction boundary")
@pytest.mark.parametrize("operation", ["load", "store-existing"])
def test_persona_evidence_rejects_existing_file_behind_ancestor_junction(
    tmp_path: Path, operation: str
) -> None:
    evidence = {"schema": "owned-probe/1", "value": "stable"}
    digest = hashlib.sha256(canonical_json_bytes(evidence)).hexdigest()
    foreign = tmp_path / "foreign"
    foreign.mkdir()
    store_persona_evidence(foreign, evidence, expected_sha256=digest)
    foreign_path = foreign / "personas" / "evidence" / f"{digest}.json"
    original = foreign_path.read_bytes()
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    junction = workspace / "personas"
    created = subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(junction), str(foreign / "personas")],
        capture_output=True, check=False,
    )
    if created.returncode:
        pytest.skip("host could not create an unprivileged directory junction")
    try:
        with pytest.raises(ContractError, match="persona evidence"):
            if operation == "load":
                load_persona_evidence(workspace, digest)
            else:
                store_persona_evidence(workspace, evidence, expected_sha256=digest)
        assert foreign_path.read_bytes() == original
    finally:
        junction.rmdir()


@pytest.mark.parametrize("operation", ["load", "store"])
def test_persona_evidence_rechecks_saved_bytes_before_success(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, operation: str
) -> None:
    evidence = {"schema": "owned-probe/1", "value": "stable"}
    digest = hashlib.sha256(canonical_json_bytes(evidence)).hexdigest()
    path = tmp_path / "personas" / "evidence" / f"{digest}.json"
    competitor = b'{"schema":"competitor/1"}\n'
    if operation == "load":
        store_persona_evidence(tmp_path, evidence, expected_sha256=digest)
        original_decode = personas_module.decode_strict_json_bytes

        def change_during_decode(body, *, label):
            result = original_decode(body, label=label)
            path.write_bytes(competitor)
            return result

        monkeypatch.setattr(personas_module, "decode_strict_json_bytes", change_during_decode)
        with pytest.raises(ContractError, match="changed before completion"):
            load_persona_evidence(tmp_path, digest)
    else:
        original_publish = personas_module.publish_bytes_exclusive

        def change_after_publish(target, body, **kwargs):
            result = original_publish(target, body, **kwargs)
            path.write_bytes(competitor)
            return result

        monkeypatch.setattr(personas_module, "publish_bytes_exclusive", change_after_publish)
        with pytest.raises(ContractError, match="changed before completion"):
            store_persona_evidence(tmp_path, evidence, expected_sha256=digest)
    assert path.read_bytes() == competitor


def test_persona_evidence_rejects_duplicate_members_before_digest_check(
    tmp_path: Path,
) -> None:
    evidence = {"schema": "owned-probe/1", "value": "stable"}
    canonical = json.dumps(evidence, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )
    digest = hashlib.sha256(canonical).hexdigest()
    path = tmp_path / "personas" / "evidence" / f"{digest}.json"
    path.parent.mkdir(parents=True)
    path.write_bytes(b'{"schema":"owned-probe/1","value":"stable","value":"stable"}\n')
    with pytest.raises(ContractError, match="duplicate key"):
        load_persona_evidence(tmp_path, digest)


def test_persona_assignment_rejects_extra_fields_and_preserves_racing_winner(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidates = [fixture_persona("alpha"), fixture_persona("beta")]
    for candidate in candidates:
        add_persona(tmp_path, candidate)
    key = "racing-assignment"
    key_digest = hashlib.sha256(key.encode("utf-8")).hexdigest()
    path = tmp_path / "personas" / "assignments" / f"{key_digest}.json"
    competitor = {
        "schema": personas_module.PERSONA_ASSIGNMENT_SCHEMA,
        "key_sha256": key_digest,
        "persona_id": candidates[0]["id"],
        "persona_sha256": candidates[0]["integrity_sha256"],
        "created_at": "2026-08-10T00:00:00Z",
    }
    competitor_bytes = canonical_json_bytes(competitor)
    real_publish = personas_module.publish_json_exclusive

    def inject_then_publish(target: Path, document: dict, **kwargs: object) -> bytes:
        target.write_bytes(competitor_bytes)
        return real_publish(target, document, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(personas_module, "publish_json_exclusive", inject_then_publish)
    assert assign_persona(tmp_path, key, candidates) == competitor
    assert path.read_bytes() == competitor_bytes

    path.write_bytes(canonical_json_bytes({**competitor, "operator": "private"}))
    with pytest.raises(ContractError, match="fields are invalid"):
        assign_persona(tmp_path, key, candidates)


def test_persona_assignment_requires_canonical_single_link_state(
    tmp_path: Path,
) -> None:
    candidates = [fixture_persona("alpha"), fixture_persona("beta")]
    for candidate in candidates:
        add_persona(tmp_path, candidate)
    key = "stable-assignment"
    assignment = assign_persona(tmp_path, key, candidates)
    key_digest = hashlib.sha256(key.encode("utf-8")).hexdigest()
    path = tmp_path / "personas" / "assignments" / f"{key_digest}.json"
    path.write_text(json.dumps(assignment, indent=2), encoding="utf-8")
    with pytest.raises(ContractError, match="not canonical JSON"):
        assign_persona(tmp_path, key, candidates)

    path.write_bytes(canonical_json_bytes(assignment))
    os.link(path, tmp_path / "assignment-alias.json")
    with pytest.raises(ContractError, match="additional hard links"):
        assign_persona(tmp_path, key, candidates)


@pytest.mark.skipif(os.name != "nt", reason="Windows directory junction boundary")
def test_persona_assignment_rejects_preexisting_foreign_directory(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    foreign = tmp_path / "foreign"
    candidate = fixture_persona("assigned")
    add_persona(workspace, candidate)
    add_persona(foreign, candidate)
    key = "foreign-assignment"
    assign_persona(foreign, key, [candidate])
    foreign_path = next((foreign / "personas" / "assignments").glob("*.json"))
    original = foreign_path.read_bytes()
    junction = workspace / "personas" / "assignments"
    created = subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(junction), str(foreign_path.parent)],
        capture_output=True, check=False,
    )
    if created.returncode:
        pytest.skip("host could not create an unprivileged directory junction")
    try:
        with pytest.raises(ContractError, match="persona assignment"):
            assign_persona(workspace, key, [candidate])
        assert foreign_path.read_bytes() == original
    finally:
        junction.rmdir()


@pytest.mark.skipif(os.name != "nt", reason="Windows directory junction boundary")
def test_persona_assignment_does_not_create_foreign_parent_after_swap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace = tmp_path / "workspace"
    candidate = fixture_persona("assigned")
    add_persona(workspace, candidate)
    personas = workspace / "personas"
    held = tmp_path / "held-personas"
    foreign = tmp_path / "foreign"
    foreign.mkdir()
    original_load = personas_module._load_persona_assignment
    swapped = False

    def swap_after_missing(path: Path, *, key_sha256: str):
        nonlocal swapped
        result = original_load(path, key_sha256=key_sha256)
        if result is None and not swapped:
            personas.rename(held)
            created = subprocess.run(
                ["cmd", "/c", "mklink", "/J", str(personas), str(foreign)],
                capture_output=True, check=False,
            )
            if created.returncode:
                pytest.skip("host could not create an unprivileged directory junction")
            swapped = True
        return result

    monkeypatch.setattr(personas_module, "_load_persona_assignment", swap_after_missing)
    try:
        with pytest.raises(ContractError):
            assign_persona(workspace, "foreign-parent-race", [candidate])
        assert swapped
        assert not (foreign / "assignments").exists()
    finally:
        if personas.exists():
            personas.rmdir()


def test_persona_assignment_rechecks_saved_document_after_publication(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    candidate = fixture_persona("assigned")
    add_persona(tmp_path, candidate)
    key = "post-publication-race"
    key_digest = hashlib.sha256(key.encode("utf-8")).hexdigest()
    path = tmp_path / "personas" / "assignments" / f"{key_digest}.json"
    original_publish = personas_module.publish_json_exclusive
    competitor_bytes = b""

    def change_after_publish(target: Path, document: dict, **kwargs):
        nonlocal competitor_bytes
        result = original_publish(target, document, **kwargs)
        competitor = {**document, "created_at": "2026-08-10T00:00:00Z"}
        competitor_bytes = canonical_json_bytes(competitor)
        path.write_bytes(competitor_bytes)
        return result

    monkeypatch.setattr(personas_module, "publish_json_exclusive", change_after_publish)
    with pytest.raises(ContractError, match="persona assignment changed after publication"):
        assign_persona(tmp_path, key, [candidate])
    assert path.read_bytes() == competitor_bytes


@pytest.mark.parametrize("operation", ["new", "existing"])
def test_persona_assignment_rechecks_selected_catalog_document_before_success(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, operation: str
) -> None:
    candidate = fixture_persona("selected-race")
    add_persona(tmp_path, candidate)
    key = "selected-persona-race"
    if operation == "existing":
        assign_persona(tmp_path, key, [candidate])
    catalog_path = tmp_path / "personas" / "catalog" / "selected-race.json"
    competitor = copy.deepcopy(candidate)
    competitor["name"] = "Changed selected persona"
    competitor["integrity_sha256"] = persona_digest(competitor)
    competitor_bytes = canonical_json_bytes(competitor)

    if operation == "new":
        original_publish = personas_module.publish_json_exclusive

        def change_after_publish(target: Path, document: dict, **kwargs):
            result = original_publish(target, document, **kwargs)
            catalog_path.write_bytes(competitor_bytes)
            return result

        monkeypatch.setattr(
            personas_module, "publish_json_exclusive", change_after_publish
        )
    else:
        original_load = personas_module._load_persona_assignment
        changed = False

        def change_after_assignment_read(path: Path, *, key_sha256: str):
            nonlocal changed
            result = original_load(path, key_sha256=key_sha256)
            if result is not None and not changed:
                catalog_path.write_bytes(competitor_bytes)
                changed = True
            return result

        monkeypatch.setattr(
            personas_module, "_load_persona_assignment", change_after_assignment_read
        )

    with pytest.raises(ContractError, match="selected persona changed"):
        assign_persona(tmp_path, key, [candidate])
    assert catalog_path.read_bytes() == competitor_bytes


@pytest.mark.parametrize("operation", ["new", "existing"])
def test_persona_assignment_rechecks_saved_choice_after_selected_catalog_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, operation: str
) -> None:
    candidates = [fixture_persona("alpha"), fixture_persona("beta")]
    for candidate in candidates:
        add_persona(tmp_path, candidate)
    key = "assignment-changed-during-selection"
    key_digest = hashlib.sha256(key.encode("utf-8")).hexdigest()
    path = tmp_path / "personas" / "assignments" / f"{key_digest}.json"
    if operation == "existing":
        assign_persona(tmp_path, key, candidates)
    original_load = personas_module.load_persona
    competitor_bytes = b""

    def replace_assignment_after_persona_read(workspace: Path, persona_id: str):
        nonlocal competitor_bytes
        selected = original_load(workspace, persona_id)
        assignment = json.loads(path.read_bytes())
        other = next(item for item in candidates if item["id"] != assignment["persona_id"])
        competitor = {
            **assignment,
            "persona_id": other["id"],
            "persona_sha256": other["integrity_sha256"],
        }
        competitor_bytes = canonical_json_bytes(competitor)
        path.write_bytes(competitor_bytes)
        return selected

    monkeypatch.setattr(
        personas_module, "load_persona", replace_assignment_after_persona_read
    )
    with pytest.raises(ContractError, match="assignment changed during selection"):
        assign_persona(tmp_path, key, candidates)
    assert path.read_bytes() == competitor_bytes


def test_persona_assignment_bounds_public_inputs(tmp_path: Path) -> None:
    candidate = fixture_persona("alpha")
    with pytest.raises(ContractError, match="workspace must be a Path"):
        assign_persona(str(tmp_path), "key", [candidate])  # type: ignore[arg-type]
    with pytest.raises(ContractError, match="too many candidates"):
        assign_persona(
            tmp_path,
            "key",
            (
                candidate
                for _ in range(personas_module.MAX_PERSONA_ASSIGNMENT_CANDIDATES + 1)
            ),
        )


def test_persona_assignment_closes_retained_candidate_iterator_at_cap(
    tmp_path: Path,
) -> None:
    closed: list[bool] = []
    candidate = fixture_persona("alpha")

    def candidates():
        try:
            for _ in range(personas_module.MAX_PERSONA_ASSIGNMENT_CANDIDATES + 1):
                yield candidate
        finally:
            closed.append(True)

    source = candidates()
    with pytest.raises(ContractError, match="too many candidates"):
        assign_persona(tmp_path, "key", source)
    assert closed == [True]


def test_persona_assignment_rejects_non_utf8_key_before_candidates(
    tmp_path: Path,
) -> None:
    def candidates():
        pytest.fail("invalid assignment key reached candidates")
        yield fixture_persona("unreachable")

    with pytest.raises(ContractError, match="assignment key"):
        assign_persona(tmp_path, "\ud800", candidates())

    assert not (tmp_path / "personas").exists()


def test_the_matrix_does_not_plan_handsets_chrome_never_shipped_on() -> None:
    """Playwright's device list is a testing catalog, not a market survey.

    It keeps discontinued presets deliberately, because regression tests want
    them, and walking it unfiltered minted 68 "Chrome 153 on a Nokia Lumia 520"
    personas -- a preset whose user agent is Internet Explorer Mobile on Windows
    Phone 8. The filter reads that user agent rather than an inferred OS,
    because the inference is wrong here in a way worth pinning: it calls the
    Lumia "android", and the persona is only recorded as Windows because
    navigator.platform is measured afterwards and overrides it.
    """
    from browser_core.kernels import device_from_playwright
    from browser_core.personas import infer_os_from_device_preset

    lumia = device_from_playwright("Nokia Lumia 520", locale="en-US", timezone="UTC")
    assert "IEMobile" in lumia["user_agent"]
    assert "Chrome/" not in lumia["user_agent"]
    # The inference this filter deliberately does not rely on.
    assert (
        infer_os_from_device_preset("Nokia Lumia 520", device_class="mobile")[0]
        == "android"
    )

    pixel = device_from_playwright("Pixel 7", locale="en-US", timezone="UTC")
    assert "Chrome/" in pixel["user_agent"]


def _contradicting_persona(persona_id: str) -> dict:
    """A persona claiming a mobile user agent on a desktop device record.

    This is what the catalog's 2,024 legacy contradictions look like: valid
    documents, stored before the rule that judges them existed, still sitting in
    the active pool.
    """
    persona = fixture_persona(persona_id)
    persona["identity_contract"]["expected"]["userAgentData.mobile"] = True
    persona["integrity_sha256"] = persona_digest(persona)
    return persona


def test_search_does_not_hand_out_personas_the_catalog_knows_are_impossible(
    tmp_path: Path,
) -> None:
    """The selection API had nine axis filters and no way to ask for coherence.

    Every caller narrowing by country or device class drew from a pool that
    included identities already flagged as contradictory, because the rules only
    ran in ``persona quality`` and never on the path that picks who to launch.
    """
    evidence = {"schema": "owned-fixture/1", "source": "controlled-coherence"}
    clean = fixture_persona("clean-desktop")
    broken = _contradicting_persona("broken-desktop")
    store_persona_evidence(
        tmp_path, evidence, expected_sha256=clean["provenance"]["source_sha256"]
    )
    add_persona(tmp_path, clean)
    add_persona(tmp_path, broken)

    # Both are stored and active -- add_persona does not judge coherence, which
    # is precisely how the legacy contradictions entered the catalog.
    assert {item["id"] for item in list_personas(tmp_path)} == {
        "clean-desktop",
        "broken-desktop",
    }

    assert [item["id"] for item in search_personas(tmp_path, country="US")] == [
        "clean-desktop"
    ]
    assert {
        item["id"]
        for item in search_personas(tmp_path, country="US", include_incoherent=True)
    } == {
        "clean-desktop",
        "broken-desktop",
    }


def test_implausible_is_not_excluded_by_the_coherence_filter(tmp_path: Path) -> None:
    """Only ``contradiction`` is filtered, and the distinction is load-bearing.

    ``implausible`` means "real but rarely shipped". Excluding it by default
    would make the catalog a record of what we expect rather than what we
    measured -- the error that got both the device-memory and touch-point rules
    retracted after a real browser disagreed with them.
    """
    from browser_core.persona_quality import coherence_findings

    evidence = {"schema": "owned-fixture/1", "source": "controlled-coherence"}
    persona = fixture_persona("odd-but-real")
    persona["identity_contract"]["expected"]["window.hardwareConcurrency"] = 3
    persona["integrity_sha256"] = persona_digest(persona)
    store_persona_evidence(
        tmp_path, evidence, expected_sha256=persona["provenance"]["source_sha256"]
    )
    add_persona(tmp_path, persona)

    severities = {finding["severity"] for finding in coherence_findings(persona)}
    assert "contradiction" not in severities

    assert [item["id"] for item in search_personas(tmp_path)] == ["odd-but-real"]
