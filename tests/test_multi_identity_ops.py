from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess

import pytest
from browser_core.errors import PersonaRealizationError

import browser_core.multi_identity_ops as ops_module
import browser_core.personas as personas_module
from browser_core.control_files import canonical_json_bytes
from browser_core.contracts import ContractError
from browser_core.multi_identity_ops import (
    align_lab_fixture_identity_contract,
    claim_persona_exclusive,
    demonstrate_exclusivity,
    ensure_direct_route_for_persona,
    is_lab_ops_fixture_persona,
    list_launch_compatible_persona_ids,
    redaction_safe_identity_status,
    release_persona_claim,
    resolve_host_identity_anchors,
    run_multi_identity_batch,
    run_ops_coherence_cohort,
    run_profile_velocity_batch,
    run_session_coherence_eval,
    select_launch_compatible_personas,
)
from browser_core.personas import add_persona, build_persona, store_persona_evidence
from browser_core.profiles import create_profile, is_disposable_profile_id, list_profiles


def _coherence_evaluator_document(
    evaluator_id: str = "controlled_coherence",
) -> dict:
    return {
        "evaluator_id": evaluator_id,
        "name": "Controlled coherence",
        "url_host": "collector",
        "categories": ["coherence"],
        "tier": "controlled",
        "status": "ok",
        "started_at": "2026-08-10T00:00:00Z",
        "duration_ms": 10,
        "verdict": "pass",
        "score": None,
        "score_scale": None,
        "metrics": {
            "passed_checks": 1,
            "failed_checks": 0,
            "unavailable_checks": 1,
            "checks": {
                "navigator_consistent": True,
                "speech_available": None,
            },
            "collector_checkset_sha256_16": "1" * 16,
        },
        "findings": [],
        "error": None,
        "screenshot": None,
    }


def _stopped_receipt(path: Path, *, run_id: str | None = None) -> dict:
    return {
        "run_id": run_id or f"run-{path.stem}",
        "state": "stopped",
        "running": False,
        "identity_protected": True,
    }


def _write_coherence_session(path: Path, *, run_id: str = "coherence-run") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "schema": "browser-core.session/1",
                "run_id": run_id,
                "chromium_revision": "a" * 40,
                "pid": 123,
                "state": "active",
                "automation": {
                    "transport": "cdp",
                    "cdp_endpoint": "http://127.0.0.1:9222",
                },
            }
        ),
        encoding="utf-8",
    )


def test_multi_identity_batch_rejects_malformed_ready_mode(tmp_path: Path) -> None:
    with pytest.raises(ContractError, match="ready_mode"):
        run_multi_identity_batch(tmp_path, (), ready_mode=[])  # type: ignore[arg-type]


@pytest.mark.parametrize("batch_id", ["", 0, False, [], 7, ["valid"], "x" * 52])
def test_multi_identity_batch_rejects_invalid_batch_id_before_persona_selection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, batch_id: object
) -> None:
    def fail_selection(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("persona selection ran for invalid batch_id")

    monkeypatch.setattr(ops_module, "_bounded_profile_ids", fail_selection)
    with pytest.raises(ContractError, match="batch_id is invalid"):
        run_multi_identity_batch(tmp_path, ["persona-01"], batch_id=batch_id)  # type: ignore[arg-type]


@pytest.mark.parametrize("batch_id", ["", 0, False, [], 7, ["valid"], "x" * 52])
def test_ops_coherence_cohort_rejects_invalid_batch_id_before_discovery(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, batch_id: object
) -> None:
    def fail_discovery(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("browser discovery ran for invalid batch_id")

    monkeypatch.setattr(ops_module, "discover_browser_core_launch_major", fail_discovery)
    with pytest.raises(ContractError, match="batch_id is invalid"):
        run_ops_coherence_cohort(
            tmp_path,
            executable=tmp_path / "chrome.exe",
            repository_root=tmp_path,
            batch_id=batch_id,  # type: ignore[arg-type]
        )


def test_multi_identity_batch_accepts_longest_generated_profile_id(
    tmp_path: Path,
) -> None:
    persona_id = _seed(tmp_path, count=1)[0]
    batch_id = "x" * 51

    report = run_multi_identity_batch(tmp_path, [persona_id], batch_id=batch_id)

    assert report["passed"] is True
    assert report["batch_id"] == batch_id


def _seed(
    workspace: Path,
    count: int = 12,
    *,
    product: str = "chromium",
    major: int = 147,
    id_prefix: str = "ops-persona",
    country: str = "US",
    locale: str = "en-US",
    timezone: str = "America/Chicago",
    hardware_concurrency: int | None = None,
    provenance_source: str | None = None,
    tags: tuple[str, ...] = ("ops", "fixture"),
) -> list[str]:
    ids: list[str] = []
    for index in range(count):
        persona_id = f"{id_prefix}-{index:02d}"
        evidence = {"schema": "ops-fixture/1", "id": persona_id}
        digest = hashlib.sha256(
            json.dumps(evidence, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        hw = hardware_concurrency if hardware_concurrency is not None else 4 + index
        source = provenance_source or f"ops-fixture:{persona_id}"
        persona = build_persona(
            persona_id=persona_id,
            name=f"Ops {persona_id}",
            tags=tags,
            device={
                "class": "desktop",
                "os_family": "windows",
                "os_version": "11",
                "architecture": "x86_64",
                "is_mobile": False,
                "has_touch": False,
                "viewport": {
                    "width": 1280 + index,
                    "height": 720,
                    "device_scale_factor": 1,
                    "orientation": "landscape",
                },
                "screen": {"width": 1280 + index, "height": 720},
            },
            kernel={
                "engine": "chromium",
                "product": product,
                "minimum_major": major,
                "maximum_major": major,
            },
            geography={
                "country": country,
                "locale": locale,
                "languages": [locale],
                "timezone": timezone,
            },
            identity_contract={
                "schema_version": 1,
                "expected": {
                    "window.platform": "Win32",
                    "window.hardwareConcurrency": hw,
                },
            },
            provenance={
                "kind": "owned-capture",
                "source": source
                if "{id}" not in source
                else source.format(id=persona_id),
                "source_sha256": digest,
                "captured_at": "2026-08-03T00:00:00Z",
            },
        )
        store_persona_evidence(workspace, evidence, expected_sha256=digest)
        add_persona(workspace, persona)
        ids.append(persona_id)
    return ids


def _seed_host_anchor(workspace: Path, *, major: int = 153, hw: int = 32) -> str:
    """Owned-capture-primary persona providing host identity anchors for coherence."""
    ids = _seed(
        workspace,
        count=1,
        product="browser-core",
        major=major,
        id_prefix="owned-host",
        hardware_concurrency=hw,
        provenance_source="profile:eval-windows-native",
        tags=("owned", "primary"),
    )
    return ids[0]


def _seed_launch_mix(workspace: Path) -> tuple[list[str], list[str]]:
    """Return (compatible browser-core/153 ids, incompatible chromium/147 ids)."""
    compatible = _seed(
        workspace,
        count=6,
        product="browser-core",
        major=153,
        id_prefix="ops-core",
    )
    incompatible = _seed(
        workspace,
        count=6,
        product="chromium",
        major=147,
        id_prefix="ops-matrix",
    )
    return compatible, incompatible


def test_exclusivity_rejects_second_claimer(tmp_path: Path) -> None:
    ids = _seed(tmp_path, count=1)
    demo = demonstrate_exclusivity(tmp_path, ids[0])
    assert demo["passed"] is True
    assert demo["second_claim_rejected"] is True


def test_status_rejects_secret_material() -> None:
    with pytest.raises(ContractError):
        redaction_safe_identity_status(
            profile_id="ops-disp-x",
            persona_id="p",
            state="ready",
            error="cookie=abc",
        )


def test_multi_identity_batch_disposes_without_orphans(tmp_path: Path) -> None:
    ids = _seed(tmp_path, count=12)
    batch = run_multi_identity_batch(tmp_path, ids[:5], ready_mode="dry-run")
    assert batch["schema"] == "browser-core.multi-identity-ops/1"
    assert batch["passed"] is True
    assert batch["orphans"] == []
    assert len(batch["identities"]) == 5
    assert all(item["state"] == "disposed" for item in batch["identities"])
    leftovers = [
        p for p in list_profiles(tmp_path) if is_disposable_profile_id(p["id"])
    ]
    assert leftovers == []
    blob = json.dumps(batch).lower()
    assert "password" not in blob
    assert "authorization" not in blob


def test_multi_identity_batch_rejects_disappeared_owned_claim_at_cleanup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    persona_id = _seed(tmp_path, count=1)[0]
    real_release = ops_module.release_persona_claim

    def disappear_before_release(
        workspace: Path, persona_id: str, claim_id: str, *, missing_ok: bool = False
    ) -> dict:
        claim_path = workspace / "personas" / "claims" / f"{persona_id}.json"
        assert claim_path.is_file()
        claim_path.unlink()
        return real_release(workspace, persona_id, claim_id, missing_ok=missing_ok)

    monkeypatch.setattr(ops_module, "release_persona_claim", disappear_before_release)
    report = run_multi_identity_batch(tmp_path, [persona_id], batch_id="claim-vanish")

    assert report["passed"] is False
    assert report["orphans"] == []
    assert report["cleanup_failures"][0]["stage"] == "release-claim"


def test_multi_identity_batch_rejects_disappeared_owned_profile_at_cleanup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    persona_id = _seed(tmp_path, count=1)[0]
    real_delete = ops_module.delete_disposable_profile

    def disappear_before_delete(workspace: Path, profile_id: str) -> dict:
        assert real_delete(workspace, profile_id)["deleted"] is True
        return real_delete(workspace, profile_id)

    monkeypatch.setattr(ops_module, "delete_disposable_profile", disappear_before_delete)
    report = run_multi_identity_batch(tmp_path, [persona_id], batch_id="profile-vanish")

    assert report["passed"] is False
    assert report["orphans"] == []
    assert report["cleanup_failures"][0]["stage"] == "delete-profile"
    assert (tmp_path / "personas" / "claims" / f"{persona_id}.json").is_file()


def test_multi_identity_batch_caps_an_iterable_before_workspace_mutation(
    tmp_path: Path,
) -> None:
    persona_ids = (f"persona-{index:03d}" for index in range(129))
    with pytest.raises(ContractError, match="128-identity cap"):
        run_multi_identity_batch(tmp_path, persona_ids)
    assert not (tmp_path / "profiles").exists()


@pytest.mark.parametrize("rejection", ["invalid", "cap"])
def test_multi_identity_batch_closes_retained_persona_iterator_on_rejection(
    tmp_path: Path, rejection: str
) -> None:
    closed: list[bool] = []

    def persona_ids():  # noqa: ANN202
        try:
            yield "persona-000"
            if rejection == "invalid":
                yield "persona/invalid"
            else:
                for index in range(1, 129):
                    yield f"persona-{index:03d}"
        finally:
            closed.append(True)

    source = persona_ids()
    with pytest.raises(ContractError, match="invalid ID|128-identity cap"):
        run_multi_identity_batch(tmp_path, source)

    assert closed == [True]
    assert not (tmp_path / "profiles").exists()


@pytest.mark.parametrize(
    "kwargs",
    [
        {"network_auto": "false"},
        {"enforce_launch_compatibility": "false"},
        {"executable": "chrome.exe"},
        {"repository_root": "."},
    ],
)
def test_multi_identity_controls_are_typed_before_workspace_mutation(
    tmp_path: Path, kwargs
) -> None:
    with pytest.raises(ContractError):
        run_multi_identity_batch(tmp_path, ["persona-001"], **kwargs)
    assert not (tmp_path / "profiles").exists()


def test_multi_identity_failures_do_not_return_local_exception_text(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    persona_id = _seed(tmp_path, count=1)[0]
    private_marker = f"{tmp_path}/private-token-value"
    monkeypatch.setattr(
        ops_module,
        "create_profile",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError(private_marker)),
    )

    report = run_multi_identity_batch(tmp_path, [persona_id])

    assert report["passed"] is False
    body = json.dumps(report)
    assert private_marker not in body and "private-token-value" not in body
    assert "diagnostic_sha256_16=" in body


def test_multi_identity_failure_formatter_cannot_interrupt_owned_cleanup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    persona_id = _seed(tmp_path, count=1)[0]

    class UnrenderablePersonaError(PersonaRealizationError):
        def __str__(self) -> str:
            raise RuntimeError("private formatter failure")

    def fail_binding(*_args: object, **_kwargs: object) -> None:
        raise UnrenderablePersonaError("private claim value")

    monkeypatch.setattr(ops_module, "attach_persona_identity_for_ops", fail_binding)
    report = run_multi_identity_batch(tmp_path, [persona_id], batch_id="unrenderable")

    assert report["passed"] is False
    assert report["orphans"] == []
    assert list_profiles(tmp_path) == []
    body = json.dumps(report)
    assert "private claim value" not in body
    assert "private formatter failure" not in body
    assert "diagnostic_sha256_16=" in body
    assert report["attempts"][0]["unrealized_fields"] == []


def test_velocity_batch_reports_dry_run_median_without_preference_claim(tmp_path: Path) -> None:
    ids = _seed(tmp_path, count=12)
    report = run_profile_velocity_batch(
        tmp_path,
        count=10,
        persona_ids=ids,
        ready_mode="dry-run",
        target_median_ms=30_000,
    )
    assert report["schema"] == "browser-core.profile-velocity/1"
    assert report["functional_batch_passed"] is True
    assert report["create_to_ready_meets_target"] is True
    assert report["stop_to_dispose_meets_target"] is True
    assert report["meets_velocity_preference_bar"] is False
    assert report["create_to_ready_median_ms"] is not None
    assert report["create_to_ready_median_ms"] < 5_000
    assert report["orphans"] == []


def test_velocity_dry_run_timings_cannot_claim_launch_preference(
    tmp_path: Path,
) -> None:
    persona_id = _seed(tmp_path, count=1)[0]
    report = run_profile_velocity_batch(
        tmp_path,
        count=1,
        persona_ids=[persona_id],
        ready_mode="dry-run",
        target_median_ms=30_000,
    )

    assert report["functional_batch_passed"] is True
    assert report["create_to_ready_meets_target"] is True
    assert report["stop_to_dispose_meets_target"] is True
    assert report["meets_velocity_preference_bar"] is False


@pytest.mark.parametrize(
    "target",
    [True, "1", 0, float("nan"), float("inf"), 86_400_001, 10**400],
)
def test_velocity_target_is_bounded_before_catalog_access(
    tmp_path: Path, target
) -> None:
    with pytest.raises(ContractError, match="velocity target"):
        run_profile_velocity_batch(tmp_path, target_median_ms=target)
    assert not (tmp_path / "personas").exists()


@pytest.mark.parametrize("ready_mode", [[], None, False, "invalid"])
def test_velocity_rejects_invalid_ready_mode_before_catalog_access(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, ready_mode
) -> None:
    monkeypatch.setattr(
        personas_module,
        "list_personas",
        lambda *_args: pytest.fail("persona catalog was scanned"),
    )
    with pytest.raises(ContractError, match="ready_mode must be dry-run or launch"):
        run_profile_velocity_batch(tmp_path, count=1, ready_mode=ready_mode)


def test_velocity_rejects_invalid_workspace_before_catalog_access(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        personas_module,
        "list_personas",
        lambda *_args: pytest.fail("persona catalog was scanned"),
    )
    with pytest.raises(ContractError, match="multi-identity workspace must be a Path"):
        run_profile_velocity_batch("not-a-workspace", count=1)


@pytest.mark.parametrize(
    "route_options",
    [
        {"network_route_id": "route-one"},
        {"network_route_by_persona": {"persona-one": "route-one"}},
    ],
)
def test_velocity_rejects_auto_route_conflict_before_catalog_access(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, route_options: dict
) -> None:
    monkeypatch.setattr(
        personas_module,
        "list_personas",
        lambda *_args: pytest.fail("persona catalog was scanned"),
    )
    with pytest.raises(ContractError, match="network_auto cannot be combined"):
        run_profile_velocity_batch(
            tmp_path,
            count=1,
            network_auto=True,
            **route_options,
        )


@pytest.mark.parametrize("entrypoint", ["batch", "velocity"])
def test_launch_rejects_missing_executable_before_owned_side_effects(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, entrypoint: str
) -> None:
    persona_id = _seed(
        tmp_path, count=1, product="browser-core", major=153, id_prefix="ops-core"
    )[0]
    monkeypatch.setattr(
        ops_module, "discover_browser_core_launch_major", lambda _root: 153
    )
    assert not (tmp_path / "network").exists()
    assert list_profiles(tmp_path) == []

    with pytest.raises(ContractError, match="launch ready_mode requires executable"):
        if entrypoint == "batch":
            run_multi_identity_batch(
                tmp_path,
                [persona_id],
                ready_mode="launch",
                executable=None,
                repository_root=tmp_path,
                network_auto=True,
                batch_id="missing-executable",
            )
        else:
            run_profile_velocity_batch(
                tmp_path,
                count=1,
                persona_ids=[persona_id],
                ready_mode="launch",
                executable=None,
                repository_root=tmp_path,
                network_auto=True,
            )

    assert not (tmp_path / "network").exists()
    assert list_profiles(tmp_path) == []


def test_launch_rejects_missing_repository_even_without_compatibility_filter(
    tmp_path: Path
) -> None:
    persona_id = _seed(
        tmp_path, count=1, product="browser-core", major=153, id_prefix="ops-core"
    )[0]
    assert not (tmp_path / "network").exists()

    with pytest.raises(ContractError, match="launch ready_mode requires executable"):
        run_multi_identity_batch(
            tmp_path,
            [persona_id],
            ready_mode="launch",
            executable=tmp_path / "chrome.exe",
            repository_root=None,
            network_auto=True,
            enforce_launch_compatibility=False,
            batch_id="missing-repository",
        )

    assert not (tmp_path / "network").exists()
    assert list_profiles(tmp_path) == []


def test_claim_release_roundtrip(tmp_path: Path) -> None:
    ids = _seed(tmp_path, count=1)
    first = claim_persona_exclusive(tmp_path, ids[0], "job-1")
    assert claim_persona_exclusive(tmp_path, ids[0], "job-1") == first
    with pytest.raises(ContractError, match="already claimed"):
        claim_persona_exclusive(tmp_path, ids[0], "job-2")
    release_persona_claim(tmp_path, ids[0], "job-1")
    claim_persona_exclusive(tmp_path, ids[0], "job-2")
    release_persona_claim(tmp_path, ids[0], "job-2")


def test_multi_identity_batch_does_not_adopt_same_id_existing_claim(
    tmp_path: Path,
) -> None:
    persona_id = _seed(tmp_path, count=1)[0]
    claim_id = f"reuse-{persona_id}"
    claim_persona_exclusive(tmp_path, persona_id, claim_id)
    claim_path = tmp_path / "personas" / "claims" / f"{persona_id}.json"
    original = claim_path.read_bytes()

    report = run_multi_identity_batch(
        tmp_path, [persona_id], batch_id="reuse", ready_mode="dry-run"
    )

    assert report["passed"] is False
    assert claim_path.read_bytes() == original
    assert not any(
        item["id"] == "ops-disp-reuse-000" for item in list_profiles(tmp_path)
    )


def test_exclusivity_demo_does_not_release_existing_first_claim(
    tmp_path: Path,
) -> None:
    persona_id = _seed(tmp_path, count=1)[0]
    claim_persona_exclusive(tmp_path, persona_id, "exclusivity-owner-a")
    claim_path = tmp_path / "personas" / "claims" / f"{persona_id}.json"
    original = claim_path.read_bytes()

    with pytest.raises(ContractError, match="already claimed"):
        demonstrate_exclusivity(tmp_path, persona_id)

    assert claim_path.read_bytes() == original


@pytest.mark.skipif(os.name != "nt", reason="Windows directory junction boundary")
def test_claim_rejects_personas_junction_without_creating_target_directory(
    tmp_path: Path,
) -> None:
    foreign = tmp_path / "foreign"
    foreign.mkdir()
    persona_id = _seed(foreign, count=1)[0]
    foreign_claims = foreign / "personas" / "claims"
    assert not foreign_claims.exists()
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
        with pytest.raises(ContractError):
            claim_persona_exclusive(workspace, persona_id, "job-one")
        assert not foreign_claims.exists()
    finally:
        if junction.exists():
            junction.rmdir()


@pytest.mark.skipif(os.name != "nt", reason="Windows directory junction boundary")
def test_claim_rechecks_workspace_after_persona_validation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    foreign = tmp_path / "foreign"
    foreign.mkdir()
    probe = tmp_path / "probe"
    created = subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(probe), str(foreign)],
        capture_output=True, check=False,
    )
    if created.returncode:
        pytest.skip("host could not create an unprivileged directory junction")
    probe.rmdir()
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    persona_id = _seed(workspace, count=1)[0]
    retained = tmp_path / "retained-workspace"
    original_load = personas_module.load_persona
    swapped = False

    def redirect_after_validation(*args, **kwargs):
        nonlocal swapped
        result = original_load(*args, **kwargs)
        if not swapped:
            workspace.rename(retained)
            redirect = subprocess.run(
                ["cmd", "/c", "mklink", "/J", str(workspace), str(foreign)],
                capture_output=True, check=False,
            )
            assert redirect.returncode == 0, redirect.stderr
            swapped = True
        return result

    monkeypatch.setattr(personas_module, "load_persona", redirect_after_validation)
    try:
        with pytest.raises(ContractError, match="workspace"):
            claim_persona_exclusive(workspace, persona_id, "owner")
        assert swapped
        assert list(foreign.iterdir()) == []
    finally:
        if workspace.exists():
            workspace.rmdir()
        if retained.exists():
            retained.rename(workspace)


def test_claim_rechecks_workspace_before_parent_creation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    persona_id = _seed(workspace, count=1)[0]
    retained = tmp_path / "retained-workspace"
    original_path = ops_module._claim_path
    moved = False

    def relocate_after_path(*args, **kwargs):
        nonlocal moved
        path = original_path(*args, **kwargs)
        workspace.rename(retained)
        workspace.mkdir()
        moved = True
        return path

    monkeypatch.setattr(ops_module, "_claim_path", relocate_after_path)
    with pytest.raises(ContractError, match="workspace changed"):
        claim_persona_exclusive(workspace, persona_id, "owner")
    assert moved
    assert list(workspace.iterdir()) == []
    assert (retained / "personas" / "catalog" / f"{persona_id}.json").is_file()


def test_claim_release_preserves_replacement_workspace_claim(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    persona_id = _seed(workspace, count=1)[0]
    claim_persona_exclusive(workspace, persona_id, "owner")
    path = workspace / "personas" / "claims" / f"{persona_id}.json"
    claim_bytes = path.read_bytes()
    retained = tmp_path / "retained-workspace"
    original_path = ops_module._claim_path
    moved = False

    def replace_after_path(*args, **kwargs):
        nonlocal moved
        result = original_path(*args, **kwargs)
        workspace.rename(retained)
        path.parent.mkdir(parents=True)
        path.write_bytes(claim_bytes)
        moved = True
        return result

    monkeypatch.setattr(ops_module, "_claim_path", replace_after_path)
    with pytest.raises(ContractError, match="workspace changed"):
        release_persona_claim(workspace, persona_id, "owner")
    assert moved
    assert path.read_bytes() == claim_bytes
    assert (retained / "personas" / "claims" / path.name).read_bytes() == claim_bytes


def test_claim_release_does_not_report_success_if_loaded_claim_disappears(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    persona_id = _seed(tmp_path, count=1)[0]
    claim_persona_exclusive(tmp_path, persona_id, "owner")
    path = tmp_path / "personas" / "claims" / f"{persona_id}.json"
    real_remove = ops_module.remove_control_conditionally

    def unlink_before_removal(target: Path, **kwargs: object) -> None:
        target.unlink()
        real_remove(target, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(ops_module, "remove_control_conditionally", unlink_before_removal)
    with pytest.raises(ContractError, match="changed before removal"):
        release_persona_claim(tmp_path, persona_id, "owner", missing_ok=True)
    assert not path.exists()
    assert release_persona_claim(tmp_path, persona_id, "owner", missing_ok=True) == {
        "persona_id": persona_id,
        "state": "absent",
        "released": False,
    }


def test_persona_claim_rejects_unknown_fields_and_enforces_source_bound(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    persona_id = _seed(tmp_path, count=1)[0]
    claim = claim_persona_exclusive(tmp_path, persona_id, "owner")
    path = tmp_path / "personas" / "claims" / f"{persona_id}.json"
    path.write_bytes(canonical_json_bytes({**claim, "uninterpreted": True}))
    with pytest.raises(ContractError, match="fields are invalid"):
        release_persona_claim(tmp_path, persona_id, "owner")

    path.unlink()
    monkeypatch.setattr(ops_module, "MAX_PERSONA_CLAIM_BYTES", 1)
    with pytest.raises(ContractError, match="exceeds 1 bytes"):
        claim_persona_exclusive(tmp_path, persona_id, "owner")


def test_persona_claim_rejects_duplicate_members_and_hard_link_aliases(
    tmp_path: Path,
) -> None:
    persona_id = _seed(tmp_path, count=1)[0]
    claim_persona_exclusive(tmp_path, persona_id, "owner")
    path = tmp_path / "personas" / "claims" / f"{persona_id}.json"
    document = path.read_text(encoding="utf-8").strip()
    path.write_text(
        document[:-1] + ',"claim_id":"competitor"}\n',
        encoding="utf-8",
    )
    with pytest.raises(ContractError, match="duplicate key"):
        release_persona_claim(tmp_path, persona_id, "owner")

    path.write_text(document + "\n", encoding="utf-8")
    (tmp_path / "claim-alias.json").hardlink_to(path)
    with pytest.raises(ContractError, match="hard links"):
        release_persona_claim(tmp_path, persona_id, "owner")


def test_persona_claim_public_apis_reject_coerced_workspace_and_owner(
    tmp_path: Path,
) -> None:
    persona_id = _seed(tmp_path, count=1)[0]
    with pytest.raises(ContractError, match="workspace must be a Path"):
        claim_persona_exclusive(str(tmp_path), persona_id, "owner")  # type: ignore[arg-type]
    with pytest.raises(ContractError, match="claim_id is invalid"):
        release_persona_claim(tmp_path, persona_id, True)  # type: ignore[arg-type]


@pytest.mark.parametrize("missing_ok", [0, 1, "false", None, []])
def test_persona_claim_release_requires_literal_missing_policy_before_lookup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    missing_ok,
) -> None:
    touched = False

    def fail_if_touched(*_args, **_kwargs):
        nonlocal touched
        touched = True
        raise AssertionError("claim must not be looked up")

    monkeypatch.setattr(ops_module, "_claim_path", fail_if_touched)
    with pytest.raises(ContractError, match="missing policy"):
        release_persona_claim(
            tmp_path,
            "persona-1",
            "owner",
            missing_ok=missing_ok,
        )
    assert touched is False


def test_persona_claim_creation_preserves_a_racing_winner(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    persona_id = _seed(tmp_path, count=1)[0]
    path = tmp_path / "personas" / "claims" / f"{persona_id}.json"
    competitor = {
        "schema": ops_module.PERSONA_CLAIM_SCHEMA,
        "persona_id": persona_id,
        "claim_id": "competitor",
        "claimed_at": "2026-08-10T00:00:00Z",
    }
    competitor_bytes = canonical_json_bytes(competitor)
    real_publish = ops_module.publish_json_exclusive

    def inject_then_publish(target: Path, document: dict, **kwargs: object) -> bytes:
        target.write_bytes(competitor_bytes)
        return real_publish(target, document, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(ops_module, "publish_json_exclusive", inject_then_publish)
    with pytest.raises(ContractError, match="already claimed"):
        claim_persona_exclusive(tmp_path, persona_id, "owner")
    assert path.read_bytes() == competitor_bytes


def test_strict_persona_claim_does_not_adopt_racing_same_id(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    persona_id = _seed(tmp_path, count=1)[0]
    path = tmp_path / "personas" / "claims" / f"{persona_id}.json"
    competitor_bytes = canonical_json_bytes(
        {
            "schema": ops_module.PERSONA_CLAIM_SCHEMA,
            "persona_id": persona_id,
            "claim_id": "owner",
            "claimed_at": "2026-08-10T00:00:00Z",
        }
    )
    real_publish = ops_module.publish_json_exclusive

    def inject_then_publish(target: Path, document: dict, **kwargs: object) -> bytes:
        target.write_bytes(competitor_bytes)
        return real_publish(target, document, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(ops_module, "publish_json_exclusive", inject_then_publish)
    with pytest.raises(ContractError, match="already claimed"):
        claim_persona_exclusive(tmp_path, persona_id, "owner", require_new=True)
    assert path.read_bytes() == competitor_bytes


def test_persona_claim_release_preserves_a_racing_replacement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    persona_id = _seed(tmp_path, count=1)[0]
    claim_persona_exclusive(tmp_path, persona_id, "owner")
    path = tmp_path / "personas" / "claims" / f"{persona_id}.json"
    competitor = {
        "schema": ops_module.PERSONA_CLAIM_SCHEMA,
        "persona_id": persona_id,
        "claim_id": "competitor",
        "claimed_at": "2026-08-10T00:00:00Z",
    }
    competitor_bytes = canonical_json_bytes(competitor)
    real_remove = ops_module.remove_control_conditionally

    def inject_then_remove(target: Path, **kwargs: object) -> None:
        injected = tmp_path / "competitor-claim.json"
        injected.write_bytes(competitor_bytes)
        injected.replace(target)
        real_remove(target, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(ops_module, "remove_control_conditionally", inject_then_remove)
    with pytest.raises(ContractError, match="changed .* removal"):
        release_persona_claim(tmp_path, persona_id, "owner")
    assert path.read_bytes() == competitor_bytes


def test_network_route_attach_on_ops_batch_without_secret_leak(tmp_path: Path) -> None:
    from browser_core.network import add_network_route, build_network_route

    ids = _seed(tmp_path, count=3)
    route = build_network_route(
        route_id="ops-direct-us",
        name="Ops Direct US",
        geography={"country": "US", "locale": "en-US", "timezone": "America/Chicago"},
        mode="direct",
    )
    add_network_route(tmp_path, route)
    batch = run_multi_identity_batch(
        tmp_path,
        ids[:3],
        ready_mode="dry-run",
        network_route_id="ops-direct-us",
    )
    assert batch["passed"] is True
    assert batch["network_route_configured"] is True
    assert batch["network_routes_bound"] == 3
    for item in batch["identities"]:
        assert item["network_route_id"] == "ops-direct-us"
        assert item["network_route_sha256_16"]
        assert item["state"] == "disposed"
        assert item["timings_ms"].get("network_attach_ms", 0) > 0
    blob = json.dumps(batch).lower()
    assert "password" not in blob
    assert "authorization" not in blob
    # endpoint/auth secrets must never appear; direct route has no endpoint body
    assert "socks" not in blob


def test_ops_batch_rejects_same_id_route_digest_change_after_attachment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from browser_core.network import add_network_route, build_network_route

    persona_id = _seed(tmp_path, count=1)[0]
    route_id = "ops-direct-us"
    add_network_route(
        tmp_path,
        build_network_route(
            route_id=route_id,
            name="Ops Direct US",
            geography={"country": "US", "locale": "en-US", "timezone": "America/Chicago"},
            mode="direct",
        ),
    )
    original_attach = ops_module.attach_network_route

    def change_saved_binding(workspace: Path, profile_id: str, selected_route: str):
        attached = original_attach(workspace, profile_id, selected_route)
        path = workspace / "profiles" / "registry" / f"{profile_id}.json"
        saved = json.loads(path.read_text(encoding="utf-8"))
        assert saved["network_route"]["sha256_16"] != "0" * 16
        saved["network_route"]["sha256_16"] = "0" * 16
        path.write_bytes(canonical_json_bytes(saved))
        return attached

    monkeypatch.setattr(ops_module, "attach_network_route", change_saved_binding)
    batch = run_multi_identity_batch(
        tmp_path,
        [persona_id],
        ready_mode="dry-run",
        network_route_id=route_id,
    )
    assert batch["passed"] is False
    assert batch["identities"][0]["state"] == "failed"
    assert any("contract-failure" in error for error in batch["errors"])


def _seed_ops_direct_route(workspace: Path) -> tuple[str, str]:
    from browser_core.network import add_network_route, build_network_route

    route = build_network_route(
        route_id="ops-direct-us",
        name="Ops Direct US",
        geography={"country": "US", "locale": "en-US", "timezone": "America/Chicago"},
        mode="direct",
    )
    add_network_route(workspace, route)
    return route["id"], route["integrity_sha256"][:16]


@pytest.mark.parametrize("stop_verified", [True, False])
@pytest.mark.parametrize("route_configured", [True, False])
def test_ops_batch_rejects_postlaunch_route_receipt_before_owned_cleanup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    stop_verified: bool, route_configured: bool,
) -> None:
    persona_id = _seed(
        tmp_path, count=1, product="browser-core", major=153, id_prefix="ops-core"
    )[0]
    route_id, route_digest = _seed_ops_direct_route(tmp_path)
    assert route_digest != "0" * 16
    events: list[str] = []
    batch_id = (
        f"route-{'bound' if route_configured else 'unexpected'}-"
        f"{'stopped' if stop_verified else 'unverified'}"
    )
    profile_id = f"ops-disp-{batch_id}-000"

    def fake_launch(config, _repository_root):  # noqa: ANN001
        events.append("launch")
        path = tmp_path / "sessions" / f"{config.profile_id}.json"
        path.parent.mkdir(exist_ok=True)
        session = {
            "run_id": f"run-{config.profile_id}",
            "state": "active",
            "network": {"route_id": route_id, "route_sha256_16": "0" * 16},
        }
        path.write_text(json.dumps(session), encoding="utf-8")
        return path, session

    def fake_stop(path, timeout_seconds=15.0):  # noqa: ANN001
        events.append("stop")
        if stop_verified:
            return _stopped_receipt(path)
        return {
            "run_id": f"run-{path.stem}", "state": "active",
            "running": True, "identity_protected": True,
        }

    real_delete = ops_module.delete_disposable_profile

    def track_delete(workspace: Path, selected_profile: str):
        events.append("delete")
        return real_delete(workspace, selected_profile)

    monkeypatch.setattr(ops_module, "discover_browser_core_launch_major", lambda _root: 153)
    monkeypatch.setattr("browser_core.launcher.launch_evaluation", fake_launch)
    monkeypatch.setattr("browser_core.lifecycle.stop_session", fake_stop)
    monkeypatch.setattr(ops_module, "delete_disposable_profile", track_delete)
    report = run_multi_identity_batch(
        tmp_path, [persona_id], ready_mode="launch",
        executable=tmp_path / "chrome.exe", repository_root=tmp_path,
        network_route_id=route_id if route_configured else None,
        batch_id=batch_id,
    )
    assert report["passed"] is False
    assert report["attempts"][0]["outcome"] == "failed"
    assert report["network_route_configured"] is route_configured
    assert events[:2] == ["launch", "stop"]
    if stop_verified:
        assert events == ["launch", "stop", "delete"]
        assert report["orphans"] == []
    else:
        assert "delete" not in events
        assert report["orphans"] == [profile_id]
        assert (tmp_path / "personas" / "claims" / f"{persona_id}.json").is_file()


def test_ops_batch_accepts_matching_postlaunch_route_receipt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    persona_id = _seed(
        tmp_path, count=1, product="browser-core", major=153, id_prefix="ops-core"
    )[0]
    route_id, route_digest = _seed_ops_direct_route(tmp_path)

    def fake_launch(config, _repository_root):  # noqa: ANN001
        path = tmp_path / "sessions" / f"{config.profile_id}.json"
        path.parent.mkdir(exist_ok=True)
        session = {
            "run_id": f"run-{config.profile_id}", "state": "active",
            "network": {"route_id": route_id, "route_sha256_16": route_digest},
        }
        path.write_text(json.dumps(session), encoding="utf-8")
        return path, session

    monkeypatch.setattr(ops_module, "discover_browser_core_launch_major", lambda _root: 153)
    monkeypatch.setattr("browser_core.launcher.launch_evaluation", fake_launch)
    monkeypatch.setattr(
        "browser_core.lifecycle.stop_session",
        lambda path, timeout_seconds=15.0: _stopped_receipt(path),
    )
    report = run_multi_identity_batch(
        tmp_path, [persona_id], ready_mode="launch",
        executable=tmp_path / "chrome.exe", repository_root=tmp_path,
        network_route_id=route_id, batch_id="matching-route",
    )
    assert report["passed"] is True
    assert report["identities"][0]["network_route_sha256_16"] == route_digest


def test_ops_batch_uses_validated_route_map_when_caller_mutates_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from browser_core.network import add_network_route, build_network_route

    persona_id = _seed(tmp_path, count=1)[0]
    for route_id in ("ops-direct-a", "ops-direct-b"):
        add_network_route(
            tmp_path,
            build_network_route(
                route_id=route_id,
                name=route_id,
                geography={
                    "country": "US",
                    "locale": "en-US",
                    "timezone": "America/Chicago",
                },
                mode="direct",
            ),
        )
    route_map = {persona_id: "ops-direct-a"}
    real_bounded = ops_module._bounded_profile_ids

    def mutate_after_validation(*args, **kwargs):  # noqa: ANN002, ANN003, ANN202
        result = real_bounded(*args, **kwargs)
        route_map[persona_id] = "ops-direct-b"
        return result

    monkeypatch.setattr(ops_module, "_bounded_profile_ids", mutate_after_validation)
    batch = run_multi_identity_batch(
        tmp_path,
        [persona_id],
        ready_mode="dry-run",
        network_route_by_persona=route_map,
    )
    assert batch["passed"] is True
    assert batch["identities"][0]["network_route_id"] == "ops-direct-a"
    assert route_map[persona_id] == "ops-direct-b"


def test_launch_mode_calls_launch_then_stop_with_split_timers(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Unit tests drive the shipped launch path; stop is phase-2, not create→ready."""
    ids = _seed(
        tmp_path, count=2, product="browser-core", major=153, id_prefix="ops-core"
    )
    order: list[str] = []
    launch_times: dict[str, float] = {}
    stop_times: dict[str, float] = {}

    def fake_launch(config, repository_root):  # noqa: ANN001
        assert config.profile_id.startswith("ops-disp-")
        order.append(f"launch:{config.profile_id}")
        session_dir = tmp_path / "sessions"
        session_dir.mkdir(exist_ok=True)
        path = session_dir / f"{config.profile_id}.json"
        run_id = f"run-{config.profile_id}"
        session = {
            "schema": "browser-core.session/1",
            "run_id": run_id,
            "state": "active",
            "profile": {"id": config.profile_id, "persistence": "persistent"},
        }
        path.write_text(json.dumps(session), encoding="utf-8")
        launch_times[config.profile_id] = __import__("time").perf_counter()
        return path, session

    def fake_stop(path, timeout_seconds=15.0):  # noqa: ANN001
        profile_id = path.stem
        order.append(f"stop:{profile_id}")
        stop_times[profile_id] = __import__("time").perf_counter()
        return _stopped_receipt(path)

    monkeypatch.setattr(
        "browser_core.multi_identity_ops.discover_browser_core_launch_major",
        lambda _root: 153,
    )
    monkeypatch.setattr("browser_core.launcher.launch_evaluation", fake_launch)
    monkeypatch.setattr("browser_core.lifecycle.stop_session", fake_stop)

    batch = run_multi_identity_batch(
        tmp_path,
        ids[:2],
        ready_mode="launch",
        executable=tmp_path / "fake-chrome.exe",
        repository_root=tmp_path,
    )
    assert batch["passed"] is True
    assert batch["ready_mode"] == "launch"
    assert batch["compatibility"] is not None
    assert batch["compatibility"]["compatible_pool"] == 2
    assert all(item["state"] == "disposed" for item in batch["identities"])
    # All launches before any stop for sequential phase design: each identity
    # launches in phase 1; stops happen in phase 2 after all are ready.
    launch_events = [e for e in order if e.startswith("launch:")]
    stop_events = [e for e in order if e.startswith("stop:")]
    assert len(launch_events) == 2
    assert len(stop_events) == 2
    assert order.index(launch_events[-1]) < order.index(stop_events[0])
    for item in batch["identities"]:
        assert "create_to_ready_ms" in item["timings_ms"]
        assert "stop_ms" in item["timings_ms"]
        assert "stop_to_dispose_ms" in item["timings_ms"]
        # create_to_ready must not include stop (stop runs in later phase)
        profile_id = item["profile_id"]
        assert launch_times[profile_id] < stop_times[profile_id]
    leftovers = [
        p for p in list_profiles(tmp_path) if is_disposable_profile_id(p["id"])
    ]
    assert leftovers == []


def test_ops_stop_receipt_is_exact_same_run_and_detached() -> None:
    source = {
        "run_id": "run-1",
        "state": "stopped",
        "running": False,
        "identity_protected": True,
        "shutdown_mode": "forced",
    }
    retained = ops_module._validated_ops_stop_receipt(
        source,
        expected_run_id="run-1",
    )
    source["state"] = "active"
    assert retained == {
        "run_id": "run-1",
        "state": "stopped",
        "running": False,
        "identity_protected": True,
        "shutdown_mode": "forced",
    }

    malformed = [
        {**retained, "run_id": "other-run"},
        {**retained, "state": "active", "running": True},
        {**retained, "identity_protected": False},
        {**retained, "extra": "not-allowed"},
        {**retained, "shutdown_mode": "unknown"},
    ]
    for receipt in malformed:
        with pytest.raises(ContractError, match="stop was not verified"):
            ops_module._validated_ops_stop_receipt(
                receipt,
                expected_run_id="run-1",
            )


def test_launch_batch_preserves_profile_and_claim_when_stop_is_unverified(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ids = _seed(
        tmp_path,
        count=1,
        product="browser-core",
        major=153,
        id_prefix="ops-core",
    )

    def fake_launch(config, repository_root):  # noqa: ANN001
        path = tmp_path / "sessions" / f"{config.profile_id}.json"
        path.parent.mkdir(exist_ok=True)
        session = {"run_id": f"run-{config.profile_id}", "state": "active"}
        path.write_text(json.dumps(session), encoding="utf-8")
        return path, session

    def unverified_stop(path, timeout_seconds=15.0):  # noqa: ANN001
        return {
            "run_id": f"run-{path.stem}",
            "state": "active",
            "running": True,
            "identity_protected": True,
        }

    monkeypatch.setattr(
        "browser_core.multi_identity_ops.discover_browser_core_launch_major",
        lambda _root: 153,
    )
    monkeypatch.setattr("browser_core.launcher.launch_evaluation", fake_launch)
    monkeypatch.setattr("browser_core.lifecycle.stop_session", unverified_stop)

    report = run_multi_identity_batch(
        tmp_path,
        ids,
        ready_mode="launch",
        executable=tmp_path / "chrome.exe",
        repository_root=tmp_path,
        batch_id="stop-proof",
    )
    profile_id = "ops-disp-stop-proof-000"
    assert report["passed"] is False
    assert report["orphans"] == [profile_id]
    assert report["identities"][0]["state"] == "dispose-failed"
    assert any(p["id"] == profile_id for p in list_profiles(tmp_path))
    assert (tmp_path / "personas" / "claims" / f"{ids[0]}.json").is_file()


def test_launch_batch_retains_owned_identity_on_unprotected_stopped_receipt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    persona_id = _seed(
        tmp_path, count=1, product="browser-core", major=153, id_prefix="ops-core"
    )[0]

    def fake_launch(config, _repository_root):  # noqa: ANN001
        path = tmp_path / "sessions" / f"{config.profile_id}.json"
        path.parent.mkdir(exist_ok=True)
        session = {"run_id": f"run-{config.profile_id}", "state": "active"}
        path.write_text(json.dumps(session), encoding="utf-8")
        return path, session

    def unprotected_stop(path, timeout_seconds=15.0):  # noqa: ANN001
        return {
            **_stopped_receipt(path), "identity_protected": False,
        }

    monkeypatch.setattr(ops_module, "discover_browser_core_launch_major", lambda _root: 153)
    monkeypatch.setattr("browser_core.launcher.launch_evaluation", fake_launch)
    monkeypatch.setattr("browser_core.lifecycle.stop_session", unprotected_stop)
    report = run_multi_identity_batch(
        tmp_path, [persona_id], ready_mode="launch",
        executable=tmp_path / "chrome.exe", repository_root=tmp_path,
        batch_id="unprotected-stop",
    )
    profile_id = "ops-disp-unprotected-stop-000"
    assert report["passed"] is False
    assert report["orphans"] == [profile_id]
    assert report["identities"][0]["state"] == "dispose-failed"
    assert any(p["id"] == profile_id for p in list_profiles(tmp_path))
    assert (tmp_path / "personas" / "claims" / f"{persona_id}.json").is_file()


def test_launch_velocity_batch_uses_shipped_stop(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ids = _seed(
        tmp_path, count=10, product="browser-core", major=153, id_prefix="ops-core"
    )
    stops: list[Path] = []

    def fake_launch(config, repository_root):  # noqa: ANN001
        path = tmp_path / "sessions" / f"{config.profile_id}.json"
        path.parent.mkdir(exist_ok=True)
        session = {"run_id": f"run-{config.profile_id}", "state": "active"}
        path.write_text(json.dumps(session), encoding="utf-8")
        return path, session

    def fake_stop(path, timeout_seconds=15.0):  # noqa: ANN001
        stops.append(path)
        return _stopped_receipt(path)

    monkeypatch.setattr(
        "browser_core.multi_identity_ops.discover_browser_core_launch_major",
        lambda _root: 153,
    )
    monkeypatch.setattr("browser_core.launcher.launch_evaluation", fake_launch)
    monkeypatch.setattr("browser_core.lifecycle.stop_session", fake_stop)

    report = run_profile_velocity_batch(
        tmp_path,
        count=10,
        persona_ids=ids,
        ready_mode="launch",
        executable=tmp_path / "chrome.exe",
        repository_root=tmp_path,
        target_median_ms=30_000,
    )
    assert report["ready_mode"] == "launch"
    assert report["functional_batch_passed"] is True
    assert report["meets_velocity_preference_bar"] is True
    assert report["compatibility"]["compatible_pool"] == 10
    assert len(stops) == 10
    assert report["orphans"] == []


def test_launch_filter_excludes_matrix_chromium_personas(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    compatible, incompatible = _seed_launch_mix(tmp_path)
    launched: list[str] = []

    def fake_launch(config, repository_root):  # noqa: ANN001
        path = tmp_path / "sessions" / f"{config.profile_id}.json"
        path.parent.mkdir(exist_ok=True)
        session = {
            "run_id": f"run-{config.profile_id}",
            "state": "active",
            "persona_probe": True,
        }
        path.write_text(json.dumps(session), encoding="utf-8")
        launched.append(config.profile_id)
        return path, session

    monkeypatch.setattr(
        "browser_core.multi_identity_ops.discover_browser_core_launch_major",
        lambda _root: 153,
    )
    monkeypatch.setattr("browser_core.launcher.launch_evaluation", fake_launch)
    monkeypatch.setattr(
        "browser_core.lifecycle.stop_session",
        lambda path, timeout_seconds=15.0: _stopped_receipt(path),
    )

    report = run_profile_velocity_batch(
        tmp_path,
        count=4,
        ready_mode="launch",
        executable=tmp_path / "chrome.exe",
        repository_root=tmp_path,
        target_median_ms=30_000,
    )
    assert report["functional_batch_passed"] is True
    assert report["compatibility"]["compatible_pool"] == len(compatible)
    assert report["compatibility"]["selected"] == 4
    selected = report["compatibility"]["selected_persona_ids"]
    assert all(pid in compatible for pid in selected)
    assert not any(pid in incompatible for pid in selected)
    assert len(launched) == 4


def test_launch_rejects_explicit_incompatible_persona(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _seed_launch_mix(tmp_path)
    monkeypatch.setattr(
        "browser_core.multi_identity_ops.discover_browser_core_launch_major",
        lambda _root: 153,
    )
    with pytest.raises(ContractError, match="not launch-compatible"):
        run_multi_identity_batch(
            tmp_path,
            ["ops-matrix-00"],
            ready_mode="launch",
            executable=tmp_path / "chrome.exe",
            repository_root=tmp_path,
        )


def test_insufficient_compatible_pool_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _seed(tmp_path, count=2, product="browser-core", major=153, id_prefix="ops-core")
    _seed(tmp_path, count=20, product="chromium", major=147, id_prefix="ops-matrix")
    monkeypatch.setattr(
        "browser_core.multi_identity_ops.discover_browser_core_launch_major",
        lambda _root: 153,
    )
    with pytest.raises(ContractError, match="not enough launch-compatible"):
        run_profile_velocity_batch(
            tmp_path,
            count=10,
            ready_mode="launch",
            executable=tmp_path / "chrome.exe",
            repository_root=tmp_path,
        )


def test_network_auto_binds_geo_aligned_route_without_secrets(tmp_path: Path) -> None:
    ids = _seed(
        tmp_path, count=2, product="browser-core", major=153, id_prefix="ops-core"
    )
    route_id = ensure_direct_route_for_persona(tmp_path, ids[0])
    assert route_id.startswith("direct-")
    # second call reuses
    assert ensure_direct_route_for_persona(tmp_path, ids[0]) == route_id
    batch = run_multi_identity_batch(
        tmp_path,
        ids,
        ready_mode="dry-run",
        network_auto=True,
    )
    assert batch["passed"] is True
    assert batch["network_auto"] is True
    assert batch["network_routes_bound"] == 2
    for item in batch["identities"]:
        assert item["network_route_id"]
        assert item["network_route_sha256_16"]
        assert item["state"] == "disposed"
    blob = json.dumps(batch).lower()
    assert "password" not in blob
    assert "authorization" not in blob
    assert "proxy" not in blob


def test_network_auto_refuses_saved_proxy_route_with_matching_geography(
    tmp_path: Path,
) -> None:
    from browser_core.network import add_network_route, build_network_route

    persona_id = _seed(tmp_path, count=1)[0]
    route = build_network_route(
        route_id="direct-us-en-us",
        name="Competing proxy",
        geography={"country": "US", "locale": "en-US", "timezone": "America/Chicago"},
        mode="proxy",
        endpoint={"protocol": "http", "host": "127.0.0.1", "port": 3128},
    )
    add_network_route(tmp_path, route)

    with pytest.raises(ContractError, match="direct route"):
        ensure_direct_route_for_persona(tmp_path, persona_id)


def test_network_auto_refuses_saved_direct_route_without_alignment(
    tmp_path: Path,
) -> None:
    from browser_core.network import add_network_route, build_network_route

    persona_id = _seed(tmp_path, count=1)[0]
    route = build_network_route(
        route_id="direct-us-en-us",
        name="Competing unaligned direct route",
        geography={"country": "US", "locale": "en-US", "timezone": "America/Chicago"},
        policies={"dns": "route", "webrtc": "route-only", "require_alignment": False},
    )
    add_network_route(tmp_path, route)

    with pytest.raises(ContractError, match="alignment"):
        ensure_direct_route_for_persona(tmp_path, persona_id)


def test_network_auto_rechecks_competing_route_after_create_conflict(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    import browser_core.network as network_module

    persona_id = _seed(tmp_path, count=1)[0]
    real_add = network_module.add_network_route

    def publish_competing_route(workspace: Path, wanted: dict) -> dict:
        competing = network_module.build_network_route(
            route_id=wanted["id"],
            name="Competing geography",
            geography={"country": "CA", "locale": "en-CA", "timezone": "America/Toronto"},
        )
        real_add(workspace, competing)
        return real_add(workspace, wanted)

    monkeypatch.setattr(network_module, "add_network_route", publish_competing_route)

    with pytest.raises(ContractError, match="mismatched geography"):
        ensure_direct_route_for_persona(tmp_path, persona_id)
    assert network_module.load_network_route(tmp_path, "direct-us-en-us")["geography"]["country"] == "CA"


def test_list_launch_compatible_uses_persona_compatible(tmp_path: Path) -> None:
    compatible, incompatible = _seed_launch_mix(tmp_path)
    pool = list_launch_compatible_persona_ids(tmp_path, major=153)
    assert set(pool) == set(compatible)
    assert not set(pool) & set(incompatible)
    selected, report = select_launch_compatible_personas(tmp_path, 3, major=153)
    assert len(selected) == 3
    assert report["compatible_pool"] == 6
    assert report["selected"] == 3


@pytest.mark.parametrize("rejection", ["invalid", "cap"])
def test_launch_selection_rejects_requested_ids_before_catalog_scan(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, rejection: str,
) -> None:
    closed: list[bool] = []

    def requested_ids():  # noqa: ANN202
        try:
            yield "persona-000"
            if rejection == "invalid":
                yield "persona/invalid"
            else:
                for index in range(1, 129):
                    yield f"persona-{index:03d}"
        finally:
            closed.append(True)

    def reject_catalog(*_args: object, **_kwargs: object) -> None:
        pytest.fail("catalog scanned before requested persona IDs were validated")

    monkeypatch.setattr(personas_module, "compatible_persona_catalog", reject_catalog)
    with pytest.raises(ContractError, match="invalid ID|128-identity cap"):
        select_launch_compatible_personas(
            tmp_path, 1, major=153, persona_ids=requested_ids()
        )
    assert closed == [True]


def test_session_coherence_eval_refuses_existing_out_dir(tmp_path: Path) -> None:
    session = tmp_path / "session.json"
    session.write_text(
        json.dumps({"run_id": "x", "schema": "browser-core.session/1"}),
        encoding="utf-8",
    )
    out = tmp_path / "run"
    out.mkdir()
    with pytest.raises(ContractError, match="already exists"):
        run_session_coherence_eval(session, out_dir=out)


@pytest.mark.skipif(os.name != "nt", reason="Windows dangling junction boundary")
def test_session_coherence_eval_refuses_dangling_output_junction_before_launch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    out = tmp_path / "run"
    created = subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(out), str(tmp_path / "missing")],
        capture_output=True, check=False,
    )
    if created.returncode:
        pytest.skip("host could not create an unprivileged directory junction")
    session = tmp_path / "session.json"
    _write_coherence_session(session)
    assert not out.exists() and os.path.lexists(out)

    def forbid_external_eval(*_args: object, **_kwargs: object) -> None:
        pytest.fail("external evaluator started through a dangling output junction")

    monkeypatch.setattr(subprocess, "run", forbid_external_eval)
    try:
        with pytest.raises(ContractError, match="already exists"):
            run_session_coherence_eval(session, out_dir=out)
        assert os.path.lexists(out)
    finally:
        out.rmdir()


@pytest.mark.skipif(os.name != "nt", reason="Windows directory junction boundary")
def test_session_coherence_eval_rejects_output_junction_before_parent_creation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    foreign = tmp_path / "foreign"
    foreign.mkdir()
    junction = tmp_path / "junction"
    created = subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(junction), str(foreign)],
        capture_output=True, check=False,
    )
    if created.returncode:
        pytest.skip("host could not create an unprivileged directory junction")
    session = tmp_path / "session.json"
    _write_coherence_session(session)

    def stop_before_external_eval(*_args: object, **_kwargs: object) -> None:
        raise OSError("synthetic evaluator stop")

    monkeypatch.setattr(subprocess, "run", stop_before_external_eval)
    try:
        with pytest.raises(ContractError):
            run_session_coherence_eval(
                session, out_dir=junction / "new-parent" / "eval-output"
            )
        assert not (foreign / "new-parent").exists()
    finally:
        junction.rmdir()


@pytest.mark.skipif(os.name != "nt", reason="Windows directory junction boundary")
def test_session_coherence_eval_rejects_linked_selected_workspace(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    foreign = tmp_path / "foreign"
    session_file = foreign / "sessions" / "coherence-run.json"
    session_file.parent.mkdir(parents=True)
    session_file.write_text("{}", encoding="utf-8")
    workspace = tmp_path / "workspace"
    created = subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(workspace), str(foreign)],
        capture_output=True, check=False,
    )
    if created.returncode:
        pytest.skip("host could not create an unprivileged directory junction")
    out = tmp_path / "new-parent" / "eval-output"

    def stop_before_external_eval(*_args, **_kwargs):
        pytest.fail("external evaluator must not start for a linked workspace")

    monkeypatch.setattr(subprocess, "run", stop_before_external_eval)
    try:
        with pytest.raises(ContractError, match="workspace"):
            run_session_coherence_eval(
                session_file, out_dir=out, workspace=workspace
            )
        assert not out.parent.exists()
    finally:
        workspace.rmdir()


@pytest.mark.skipif(os.name != "nt", reason="Windows directory junction boundary")
def test_session_coherence_eval_rechecks_output_parent_after_process(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    parent = tmp_path / "output-parent"
    held = tmp_path / "held-parent"
    foreign = tmp_path / "foreign"
    foreign.mkdir()
    original_run = subprocess.run
    session = tmp_path / "session.json"
    _write_coherence_session(session)

    def swap_parent_during_eval(_command, **_kwargs):
        parent.rename(held)
        created = original_run(
            ["cmd", "/c", "mklink", "/J", str(parent), str(foreign)],
            capture_output=True, check=False,
        )
        if created.returncode:
            pytest.skip("host could not create an unprivileged directory junction")
        evaluator_dir = foreign / "eval-output" / "evaluators"
        evaluator_dir.mkdir(parents=True)
        (evaluator_dir / "controlled_coherence.json").write_text(
            json.dumps(_coherence_evaluator_document()), encoding="utf-8"
        )
        return subprocess.CompletedProcess([], 0)

    monkeypatch.setattr(subprocess, "run", swap_parent_during_eval)
    try:
        with pytest.raises(ContractError):
            run_session_coherence_eval(
                session, out_dir=parent / "eval-output"
            )
    finally:
        if parent.exists():
            parent.rmdir()


def test_session_coherence_eval_rechecks_session_after_process(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    session_file = tmp_path / "session.json"
    out = tmp_path / "eval-output"
    _write_coherence_session(session_file, run_id="coherence-run-a")

    def change_session_during_eval(_command, **_kwargs):
        evaluator_dir = out / "evaluators"
        evaluator_dir.mkdir(parents=True)
        (evaluator_dir / "controlled_coherence.json").write_text(
            json.dumps(_coherence_evaluator_document()), encoding="utf-8"
        )
        _write_coherence_session(session_file, run_id="coherence-run-b")
        return subprocess.CompletedProcess([], 0)

    monkeypatch.setattr(subprocess, "run", change_session_during_eval)
    with pytest.raises(ContractError, match="session changed"):
        run_session_coherence_eval(session_file, out_dir=out)


def test_session_coherence_eval_rejects_same_content_session_replacement(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    session_file = tmp_path / "session.json"
    _write_coherence_session(session_file)
    original_body = session_file.read_bytes()
    out = tmp_path / "eval-output"

    def replace_session_during_eval(_command: object, **_kwargs: object) -> subprocess.CompletedProcess:
        evaluator_dir = out / "evaluators"
        evaluator_dir.mkdir(parents=True)
        (evaluator_dir / "controlled_coherence.json").write_text(
            json.dumps(_coherence_evaluator_document()), encoding="utf-8"
        )
        replacement = tmp_path / "replacement.json"
        replacement.write_bytes(original_body)
        session_file.rename(tmp_path / "retained-session.json")
        replacement.replace(session_file)
        assert session_file.read_bytes() == original_body
        return subprocess.CompletedProcess([], 0)

    monkeypatch.setattr(subprocess, "run", replace_session_during_eval)
    with pytest.raises(ContractError, match="session changed"):
        run_session_coherence_eval(session_file, out_dir=out)


@pytest.mark.skipif(os.name != "nt", reason="Windows directory junction boundary")
def test_session_coherence_eval_rejects_parent_swap_without_workspace(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    probe_target = tmp_path / "probe-target"
    probe_target.mkdir()
    probe = tmp_path / "probe-junction"
    original_run = subprocess.run
    created = original_run(
        ["cmd", "/c", "mklink", "/J", str(probe), str(probe_target)],
        capture_output=True,
        check=False,
    )
    if created.returncode:
        pytest.skip("host could not create an unprivileged directory junction")
    probe.rmdir()

    sessions = tmp_path / "sessions"
    session_file = sessions / "coherence-run.json"
    _write_coherence_session(session_file)
    original_body = session_file.read_bytes()
    retained = tmp_path / "retained-sessions"
    out = tmp_path / "eval-output"

    def fake_run(_command: object, **_kwargs: object) -> subprocess.CompletedProcess:
        sessions.rename(retained)
        linked = original_run(
            ["cmd", "/c", "mklink", "/J", str(sessions), str(retained)],
            capture_output=True,
            check=False,
        )
        assert linked.returncode == 0
        evaluator_dir = out / "evaluators"
        evaluator_dir.mkdir(parents=True)
        (evaluator_dir / "controlled_coherence.json").write_text(
            json.dumps(_coherence_evaluator_document()), encoding="utf-8"
        )
        return subprocess.CompletedProcess([], 0)

    monkeypatch.setattr(subprocess, "run", fake_run)
    try:
        with pytest.raises(ContractError, match="session parent changed"):
            run_session_coherence_eval(session_file, out_dir=out)
    finally:
        if os.path.lexists(sessions):
            sessions.rmdir()
        assert (retained / session_file.name).read_bytes() == original_body


def test_session_coherence_eval_rechecks_session_after_evaluator_ingestion(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    session_file = tmp_path / "session.json"
    _write_coherence_session(session_file)
    original_body = session_file.read_bytes()
    out = tmp_path / "eval-output"

    def finish_eval(_command: object, **_kwargs: object) -> subprocess.CompletedProcess:
        evaluator_dir = out / "evaluators"
        evaluator_dir.mkdir(parents=True)
        (evaluator_dir / "controlled_coherence.json").write_text(
            json.dumps(_coherence_evaluator_document()), encoding="utf-8"
        )
        return subprocess.CompletedProcess([], 0)

    read_arms = ops_module._load_coherence_evaluator_arms

    def replace_after_ingestion(*args: object, **kwargs: object) -> list[dict]:
        arms = read_arms(*args, **kwargs)
        replacement = tmp_path / "replacement.json"
        replacement.write_bytes(original_body)
        session_file.rename(tmp_path / "retained-session.json")
        replacement.replace(session_file)
        return arms

    monkeypatch.setattr(subprocess, "run", finish_eval)
    monkeypatch.setattr(ops_module, "_load_coherence_evaluator_arms", replace_after_ingestion)
    with pytest.raises(ContractError, match="session changed"):
        run_session_coherence_eval(session_file, out_dir=out)


@pytest.mark.parametrize("mutation", ["stopped", "same_body_replaced"])
def test_session_coherence_eval_rechecks_session_after_final_output_scan(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mutation: str
) -> None:
    session_file = tmp_path / "session.json"
    _write_coherence_session(session_file, run_id="coherence-run-a")
    original_body = session_file.read_bytes()
    out = tmp_path / "eval-output"

    def finish_eval(_command: object, **_kwargs: object) -> subprocess.CompletedProcess:
        evaluator_dir = out / "evaluators"
        evaluator_dir.mkdir(parents=True)
        (evaluator_dir / "controlled_coherence.json").write_text(
            json.dumps(_coherence_evaluator_document()), encoding="utf-8"
        )
        return subprocess.CompletedProcess([], 0)

    original_binding = ops_module._require_coherence_evaluator_binding
    binding_calls = 0

    def stop_during_final_output_scan(*args: object, **kwargs: object) -> None:
        nonlocal binding_calls
        binding_calls += 1
        original_binding(*args, **kwargs)
        if binding_calls == 2:
            if mutation == "stopped":
                document = json.loads(original_body)
                document["state"] = "stopped"
                session_file.write_text(json.dumps(document), encoding="utf-8")
            else:
                replacement = tmp_path / "replacement.json"
                replacement.write_bytes(original_body)
                session_file.rename(tmp_path / "retained-session.json")
                replacement.replace(session_file)

    monkeypatch.setattr(subprocess, "run", finish_eval)
    monkeypatch.setattr(
        ops_module, "_require_coherence_evaluator_binding", stop_during_final_output_scan
    )
    with pytest.raises(ContractError, match="session changed"):
        run_session_coherence_eval(session_file, out_dir=out)
    assert binding_calls == 2


@pytest.mark.parametrize("mutation", ["same_size_rewrite", "late_file", "late_directory"])
def test_session_coherence_eval_rechecks_output_after_evaluator_ingestion(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mutation: str
) -> None:
    session_file = tmp_path / "session.json"
    _write_coherence_session(session_file)
    out = tmp_path / "eval-output"
    evaluator_dir = out / "evaluators"
    evaluator_file = evaluator_dir / "controlled_coherence.json"

    def finish_eval(_command: object, **_kwargs: object) -> subprocess.CompletedProcess:
        if mutation != "late_directory":
            evaluator_dir.mkdir(parents=True)
            evaluator_file.write_text(
                json.dumps(_coherence_evaluator_document()), encoding="utf-8"
            )
        return subprocess.CompletedProcess([], 0)

    read_arms = ops_module._load_coherence_evaluator_arms

    def change_after_ingestion(*args: object, **kwargs: object) -> list[dict]:
        arms = read_arms(*args, **kwargs)
        if mutation == "same_size_rewrite":
            original = evaluator_file.read_bytes()
            changed = original.replace(b"1" * 16, b"2" * 16, 1)
            assert changed != original and len(changed) == len(original)
            previous = evaluator_file.stat()
            evaluator_file.write_bytes(changed)
            os.utime(
                evaluator_file,
                ns=(previous.st_atime_ns, previous.st_mtime_ns),
            )
        else:
            evaluator_dir.mkdir(parents=True, exist_ok=True)
            (evaluator_dir / "late.json").write_text(
                json.dumps(_coherence_evaluator_document("late")), encoding="utf-8"
            )
        return arms

    monkeypatch.setattr(subprocess, "run", finish_eval)
    monkeypatch.setattr(ops_module, "_load_coherence_evaluator_arms", change_after_ingestion)
    with pytest.raises(ContractError, match="evaluator output changed"):
        run_session_coherence_eval(session_file, out_dir=out)


def test_session_coherence_eval_rechecks_selected_workspace_after_process(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace = tmp_path / "workspace"
    session_file = workspace / "sessions" / "coherence-run.json"
    _write_coherence_session(session_file)
    out = tmp_path / "eval-output"
    retained = tmp_path / "retained-workspace"

    def relocate_workspace_during_eval(_command, **_kwargs):  # noqa: ANN001, ANN202
        workspace.rename(retained)
        workspace.mkdir()
        (retained / "sessions").rename(workspace / "sessions")
        evaluator_dir = out / "evaluators"
        evaluator_dir.mkdir(parents=True)
        (evaluator_dir / "controlled_coherence.json").write_text(
            json.dumps(_coherence_evaluator_document()), encoding="utf-8"
        )
        return subprocess.CompletedProcess([], 0)

    monkeypatch.setattr(subprocess, "run", relocate_workspace_during_eval)
    with pytest.raises(ContractError, match="coherence eval workspace changed"):
        run_session_coherence_eval(session_file, out_dir=out, workspace=workspace)
    assert session_file.is_file()


@pytest.mark.skipif(os.name != "nt", reason="Windows directory junction boundary")
def test_session_coherence_eval_rejects_relocated_session_parent_before_launch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace = tmp_path / "workspace"
    sessions = workspace / "sessions"
    session_file = sessions / "coherence-run.json"
    _write_coherence_session(session_file)
    retained = tmp_path / "retained-sessions"
    out = tmp_path / "eval-output"
    original_prepare = ops_module.prepare_owned_directory_parent
    original_run = subprocess.run
    launched = False

    def relocate_session_parent(parent: Path, *, label: str) -> None:
        original_prepare(parent, label=label)
        if label == "coherence eval output parent":
            sessions.rename(retained)
            created = original_run(
                ["cmd", "/c", "mklink", "/J", str(sessions), str(retained)],
                capture_output=True,
                check=False,
            )
            if created.returncode:
                pytest.skip("host could not create an unprivileged directory junction")

    def fake_run(_command: object, **kwargs: object) -> subprocess.CompletedProcess:
        nonlocal launched
        launched = True
        assert kwargs["env"]["BROWSER_CORE_SESSION_FILE"] == str(retained / session_file.name)
        evaluator_dir = out / "evaluators"
        evaluator_dir.mkdir(parents=True)
        (evaluator_dir / "controlled_coherence.json").write_text(
            json.dumps(_coherence_evaluator_document()), encoding="utf-8"
        )
        return subprocess.CompletedProcess([], 0)

    monkeypatch.setattr(ops_module, "prepare_owned_directory_parent", relocate_session_parent)
    monkeypatch.setattr(subprocess, "run", fake_run)
    try:
        with pytest.raises(ContractError, match="session parent changed"):
            run_session_coherence_eval(session_file, out_dir=out, workspace=workspace)
        assert not launched
    finally:
        if os.path.lexists(sessions):
            sessions.rmdir()
        if retained.exists():
            retained.rename(sessions)


def test_session_coherence_eval_accepts_stable_workspace_session_parent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace = tmp_path / "workspace"
    session_file = workspace / "sessions" / "coherence-run.json"
    _write_coherence_session(session_file)
    out = tmp_path / "eval-output"

    def fake_run(_command: object, **kwargs: object) -> subprocess.CompletedProcess:
        assert kwargs["env"]["BROWSER_CORE_SESSION_FILE"] == str(session_file)
        evaluator_dir = out / "evaluators"
        evaluator_dir.mkdir(parents=True)
        (evaluator_dir / "controlled_coherence.json").write_text(
            json.dumps(_coherence_evaluator_document()), encoding="utf-8"
        )
        return subprocess.CompletedProcess([], 0)

    monkeypatch.setattr(subprocess, "run", fake_run)
    result = run_session_coherence_eval(session_file, out_dir=out, workspace=workspace)
    assert result["error"] is None
    assert result["primary"]["verdict"] == "pass"


def test_session_coherence_eval_rechecks_output_ancestor_after_process(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    authority = tmp_path / "authority"
    parent = authority / "outputs"
    parent.mkdir(parents=True)
    out = parent / "eval-output"
    retained = tmp_path / "retained-authority"
    session = tmp_path / "session.json"
    _write_coherence_session(session)

    def relocate_output_during_eval(_command, **_kwargs):  # noqa: ANN001, ANN202
        evaluator_dir = out / "evaluators"
        evaluator_dir.mkdir(parents=True)
        (evaluator_dir / "controlled_coherence.json").write_text(
            json.dumps(_coherence_evaluator_document()), encoding="utf-8"
        )
        authority.rename(retained)
        authority.mkdir()
        (retained / "outputs").rename(parent)
        return subprocess.CompletedProcess([], 0)

    monkeypatch.setattr(subprocess, "run", relocate_output_during_eval)
    with pytest.raises(ContractError, match="output parent changed"):
        run_session_coherence_eval(session, out_dir=out)
    assert (out / "evaluators" / "controlled_coherence.json").is_file()


def test_session_coherence_eval_discards_console_output_and_returns_no_local_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import subprocess

    session = tmp_path / "private" / "session.json"
    out = tmp_path / "private" / "eval-output"
    _write_coherence_session(session)

    def fake_run(command, **kwargs):  # noqa: ANN001
        assert kwargs["stdout"] is subprocess.DEVNULL
        assert kwargs["stderr"] is subprocess.DEVNULL
        assert "capture_output" not in kwargs and "text" not in kwargs
        evaluator_dir = out / "evaluators"
        evaluator_dir.mkdir(parents=True)
        (evaluator_dir / "controlled_coherence.json").write_text(
            json.dumps(_coherence_evaluator_document()),
            encoding="utf-8",
        )
        return type("Completed", (), {"returncode": 0})()

    monkeypatch.setattr("subprocess.run", fake_run)
    result = run_session_coherence_eval(session, out_dir=out)

    assert result["primary"]["verdict"] == "pass"
    assert result["primary"]["unavailable_check_ids"] == ["speech_available"]
    assert result["session_run_id"] == "coherence-run"
    assert "session_file" not in result and "stderr_tail" not in result
    assert str(tmp_path) not in json.dumps(result)


def test_session_coherence_eval_all_requires_controlled_primary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import subprocess

    session = tmp_path / "session.json"
    out = tmp_path / "eval-output"
    _write_coherence_session(session)

    def fake_run(_command, **_kwargs):
        evaluator_dir = out / "evaluators"
        evaluator_dir.mkdir(parents=True)
        (evaluator_dir / "other.json").write_text(
            json.dumps(_coherence_evaluator_document("other")), encoding="utf-8"
        )
        return subprocess.CompletedProcess([], 0)

    monkeypatch.setattr("subprocess.run", fake_run)
    result = run_session_coherence_eval(session, out_dir=out, evaluators="all")
    assert result["primary"] is None
    assert result["error"] == "no-controlled-coherence-output"


def test_session_coherence_eval_rejects_empty_controlled_pass(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    session = tmp_path / "session.json"
    out = tmp_path / "eval-output"
    _write_coherence_session(session)
    document = _coherence_evaluator_document()
    document["metrics"].update(
        checks={}, passed_checks=0, failed_checks=0, unavailable_checks=0
    )

    def fake_run(_command: object, **_kwargs: object) -> subprocess.CompletedProcess:
        evaluator_dir = out / "evaluators"
        evaluator_dir.mkdir(parents=True)
        (evaluator_dir / "controlled_coherence.json").write_text(
            json.dumps(document), encoding="utf-8"
        )
        return subprocess.CompletedProcess([], 0)

    monkeypatch.setattr(subprocess, "run", fake_run)
    with pytest.raises(ContractError, match="controlled coherence pass"):
        run_session_coherence_eval(session, out_dir=out)


def test_coherence_evaluator_ingestion_requires_every_requested_arm(tmp_path: Path) -> None:
    out = tmp_path / "eval-output"
    evaluator_dir = out / "evaluators"
    evaluator_dir.mkdir(parents=True)
    (evaluator_dir / "other.json").write_text(
        json.dumps(_coherence_evaluator_document("other")), encoding="utf-8"
    )
    with pytest.raises(ContractError, match="incomplete"):
        ops_module._load_coherence_evaluator_arms(
            out, requested_ids={"controlled_coherence", "other"}
        )


@pytest.mark.parametrize("failure", [OSError, ValueError])
def test_session_coherence_eval_normalizes_private_spawn_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure,
) -> None:
    session = tmp_path / "private" / "session.json"
    out = tmp_path / "private" / "eval-output"
    private_marker = str(tmp_path / "private-command")
    _write_coherence_session(session)

    def fail_run(*_args, **_kwargs):
        raise failure(f"cannot execute {private_marker}")

    monkeypatch.setattr("subprocess.run", fail_run)
    with pytest.raises(ContractError) as captured:
        run_session_coherence_eval(session, out_dir=out)

    assert str(captured.value) == f"coherence eval could not start ({failure.__name__})"
    assert private_marker not in str(captured.value)


@pytest.mark.parametrize(
    "timeout", [True, "1", 0, -1, float("nan"), float("inf"), 601, 10**400]
)
def test_session_coherence_eval_rejects_timeout_before_mutation(
    tmp_path: Path, timeout
) -> None:
    out = tmp_path / "new-parent" / "eval-output"
    with pytest.raises(ContractError, match="timeout"):
        run_session_coherence_eval(
            tmp_path / "missing-session.json",
            out_dir=out,
            timeout_seconds=timeout,
        )
    assert not out.parent.exists()


def test_session_coherence_eval_rejects_non_utf8_evaluators_before_mutation(
    tmp_path: Path,
) -> None:
    out = tmp_path / "new-parent" / "eval-output"

    with pytest.raises(ContractError, match="evaluators"):
        run_session_coherence_eval(
            tmp_path / "missing-session.json",
            out_dir=out,
            evaluators="\ud800",
        )

    assert not out.parent.exists()


def test_session_coherence_eval_rejects_an_oversize_artifact_before_json_parse(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    session = tmp_path / "session.json"
    out = tmp_path / "eval-output"
    _write_coherence_session(session)
    monkeypatch.setattr(ops_module, "MAX_COHERENCE_EVALUATOR_BYTES", 1)

    def fake_run(_command, **_kwargs):
        evaluator_dir = out / "evaluators"
        evaluator_dir.mkdir(parents=True)
        (evaluator_dir / "controlled_coherence.json").write_text("{}", encoding="utf-8")
        return type("Completed", (), {"returncode": 0})()

    monkeypatch.setattr("subprocess.run", fake_run)
    with pytest.raises(ContractError, match="exceeds 1 bytes"):
        run_session_coherence_eval(session, out_dir=out)


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (lambda doc: doc.__setitem__("private_path", "C:/private"), "fields"),
        (lambda doc: doc.__setitem__("evaluator_id", "other"), "identity"),
        (lambda doc: doc.__setitem__("verdict", "maybe"), "verdict"),
        (
            lambda doc: doc["metrics"]["checks"].__setitem__("private/path", False),
            "check",
        ),
    ],
)
def test_session_coherence_eval_closes_the_evaluator_projection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mutation, message
) -> None:
    session = tmp_path / "session.json"
    out = tmp_path / "eval-output"
    _write_coherence_session(session)

    def fake_run(_command, **_kwargs):
        document = _coherence_evaluator_document()
        mutation(document)
        evaluator_dir = out / "evaluators"
        evaluator_dir.mkdir(parents=True)
        (evaluator_dir / "controlled_coherence.json").write_text(
            json.dumps(document), encoding="utf-8"
        )
        return type("Completed", (), {"returncode": 0})()

    monkeypatch.setattr("subprocess.run", fake_run)
    with pytest.raises(ContractError, match=message):
        run_session_coherence_eval(session, out_dir=out)


def test_session_coherence_eval_caps_the_output_inventory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    session = tmp_path / "session.json"
    out = tmp_path / "eval-output"
    _write_coherence_session(session)
    monkeypatch.setattr(ops_module, "MAX_COHERENCE_EVALUATOR_FILES", 1)

    def fake_run(_command, **_kwargs):
        evaluator_dir = out / "evaluators"
        evaluator_dir.mkdir(parents=True)
        for evaluator_id in ("controlled_coherence", "second"):
            (evaluator_dir / f"{evaluator_id}.json").write_text(
                json.dumps(_coherence_evaluator_document(evaluator_id)),
                encoding="utf-8",
            )
        return type("Completed", (), {"returncode": 0})()

    monkeypatch.setattr("subprocess.run", fake_run)
    with pytest.raises(ContractError, match="too many files"):
        run_session_coherence_eval(session, out_dir=out, evaluators="all")


def test_coherence_evaluator_ingestion_is_strict_single_link_and_json_only(
    tmp_path: Path,
) -> None:
    out = tmp_path / "eval-output"
    evaluator_dir = out / "evaluators"
    evaluator_dir.mkdir(parents=True)
    path = evaluator_dir / "controlled_coherence.json"
    body = json.dumps(_coherence_evaluator_document()).encode("utf-8")
    path.write_bytes(body.replace(b'"status":', b'"status":"ok","status":', 1))
    with pytest.raises(ContractError, match="duplicate key"):
        ops_module._load_coherence_evaluator_arms(
            out,
            requested_ids={"controlled_coherence"},
        )

    path.write_bytes(body)
    os.link(path, tmp_path / "evaluator-alias.json")
    with pytest.raises(ContractError, match="hard links"):
        ops_module._load_coherence_evaluator_arms(
            out,
            requested_ids={"controlled_coherence"},
        )
    (tmp_path / "evaluator-alias.json").unlink()
    (evaluator_dir / "console.log").write_text("private", encoding="utf-8")
    with pytest.raises(ContractError, match="non-JSON"):
        ops_module._load_coherence_evaluator_arms(
            out,
            requested_ids={"controlled_coherence"},
        )


def test_coherence_evaluator_ingestion_rechecks_the_file_population(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    out = tmp_path / "eval-output"
    evaluator_dir = out / "evaluators"
    evaluator_dir.mkdir(parents=True)
    (evaluator_dir / "controlled_coherence.json").write_text(
        json.dumps(_coherence_evaluator_document()),
        encoding="utf-8",
    )
    original = ops_module.inventory_bounded_json_directory
    calls = 0

    def appear_after_first(directory: Path, **kwargs):
        nonlocal calls
        calls += 1
        inventory = original(directory, **kwargs)
        if calls == 1:
            (directory / "second.json").write_text(
                json.dumps(_coherence_evaluator_document("second")),
                encoding="utf-8",
            )
        return inventory

    monkeypatch.setattr(
        ops_module,
        "inventory_bounded_json_directory",
        appear_after_first,
    )
    with pytest.raises(ContractError, match="changed during ingestion"):
        ops_module._load_coherence_evaluator_arms(out, requested_ids=None)


@pytest.mark.skipif(os.name != "nt", reason="Windows creation-time inventory boundary")
def test_coherence_evaluator_ingestion_rechecks_same_size_content(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    out = tmp_path / "eval-output"
    evaluator_dir = out / "evaluators"
    evaluator_dir.mkdir(parents=True)
    path = evaluator_dir / "controlled_coherence.json"
    original_body = json.dumps(_coherence_evaluator_document()).encode("utf-8")
    changed_body = original_body.replace(b"1" * 16, b"2" * 16, 1)
    assert changed_body != original_body and len(changed_body) == len(original_body)
    path.write_bytes(original_body)
    initial = path.stat()
    summarize = ops_module._summarize_coherence_evaluator

    def change_after_summarizing(document, *, expected_id):
        summary = summarize(document, expected_id=expected_id)
        path.write_bytes(changed_body)
        os.utime(path, ns=(initial.st_atime_ns, initial.st_mtime_ns))
        restored = path.stat()
        assert (restored.st_size, restored.st_mtime_ns, restored.st_ctime_ns) == (
            initial.st_size,
            initial.st_mtime_ns,
            initial.st_ctime_ns,
        )
        return summary

    monkeypatch.setattr(
        ops_module, "_summarize_coherence_evaluator", change_after_summarizing
    )
    with pytest.raises(ContractError, match="changed during ingestion"):
        ops_module._load_coherence_evaluator_arms(
            out, requested_ids={"controlled_coherence"}
        )


@pytest.mark.skipif(os.name != "nt", reason="Windows restored-mtime inventory boundary")
def test_coherence_evaluator_ingestion_rechecks_content_after_final_inventory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    out = tmp_path / "eval-output"
    evaluator_dir = out / "evaluators"
    evaluator_dir.mkdir(parents=True)
    path = evaluator_dir / "controlled_coherence.json"
    original_body = json.dumps(_coherence_evaluator_document()).encode("utf-8")
    changed_body = original_body.replace(b"1" * 16, b"2" * 16, 1)
    assert changed_body != original_body and len(changed_body) == len(original_body)
    path.write_bytes(original_body)
    initial = path.stat()
    original_inventory = ops_module.inventory_bounded_json_directory
    calls = 0

    def change_during_final_inventory(directory: Path, **kwargs):
        nonlocal calls
        calls += 1
        if calls == 2:
            path.write_bytes(changed_body)
            os.utime(path, ns=(initial.st_atime_ns, initial.st_mtime_ns))
            restored = path.stat()
            assert (restored.st_size, restored.st_mtime_ns, restored.st_ctime_ns) == (
                initial.st_size,
                initial.st_mtime_ns,
                initial.st_ctime_ns,
            )
        return original_inventory(directory, **kwargs)

    monkeypatch.setattr(
        ops_module,
        "inventory_bounded_json_directory",
        change_during_final_inventory,
    )
    with pytest.raises(ContractError, match="changed during ingestion"):
        ops_module._load_coherence_evaluator_arms(
            out, requested_ids={"controlled_coherence"}
        )
    assert calls == 2


def test_coherence_evaluator_ingestion_rechecks_population_after_final_file_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    out = tmp_path / "eval-output"
    evaluator_dir = out / "evaluators"
    evaluator_dir.mkdir(parents=True)
    (evaluator_dir / "controlled_coherence.json").write_text(
        json.dumps(_coherence_evaluator_document()), encoding="utf-8"
    )
    original = ops_module.read_bounded_control_snapshot_result
    calls = 0

    def add_after_final_read(path: Path, **kwargs):
        nonlocal calls
        snapshot = original(path, **kwargs)
        calls += 1
        if calls == 2:
            (evaluator_dir / "second.json").write_text(
                json.dumps(_coherence_evaluator_document("second")),
                encoding="utf-8",
            )
        return snapshot

    monkeypatch.setattr(
        ops_module, "read_bounded_control_snapshot_result", add_after_final_read
    )
    with pytest.raises(ContractError, match="changed during ingestion"):
        ops_module._load_coherence_evaluator_arms(
            out, requested_ids={"controlled_coherence"}
        )
    assert calls == 2
    assert (evaluator_dir / "second.json").is_file()


def test_session_coherence_eval_rejects_an_outside_session_before_output_mutation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace = tmp_path / "workspace"
    outside = tmp_path / "outside" / "session.json"
    out = tmp_path / "new-parent" / "eval-output"
    _write_coherence_session(outside)

    with pytest.raises(ContractError, match="workspace authority"):
        run_session_coherence_eval(
            outside,
            out_dir=out,
            workspace=workspace,
        )
    assert not out.parent.exists()


def test_coherence_summary_rejects_unhashable_check_ids_as_a_contract_error() -> None:
    summary = {
        "evaluator_id": "controlled_coherence",
        "status": "ok",
        "verdict": "pass",
        "passed_checks": 1,
        "failed_checks": 1,
        "unavailable_checks": 0,
        "failed_check_ids": [{}],
        "unavailable_check_ids": [],
    }
    with pytest.raises(ContractError, match="failed_check_ids"):
        ops_module._validate_coherence_summary(summary)


@pytest.mark.parametrize("field", ["status", "verdict"])
def test_coherence_summary_rejects_unhashable_outcome(field: str) -> None:
    summary = {
        "evaluator_id": "controlled_coherence",
        "status": "ok",
        "verdict": "pass",
        "passed_checks": 1,
        "failed_checks": 0,
        "unavailable_checks": 0,
        "failed_check_ids": [],
        "unavailable_check_ids": [],
    }
    summary[field] = ["ok"]
    with pytest.raises(ContractError, match=field):
        ops_module._validate_coherence_summary(summary)


@pytest.mark.parametrize("field", ["status", "verdict"])
def test_coherence_evaluator_rejects_unhashable_outcome(field: str) -> None:
    document = _coherence_evaluator_document()
    document[field] = ["ok"]
    with pytest.raises(ContractError, match=field):
        ops_module._summarize_coherence_evaluator(
            document, expected_id="controlled_coherence"
        )


def test_coherence_evaluator_rejects_error_labeled_as_pass() -> None:
    document = _coherence_evaluator_document()
    document["status"] = "error"
    with pytest.raises(ContractError, match="status and verdict"):
        ops_module._summarize_coherence_evaluator(
            document, expected_id="controlled_coherence"
        )


@pytest.mark.parametrize(
    "failed_field",
    ["failed_checks", "identity_failed_claims", "identity_unavailable_claims"],
)
def test_controlled_coherence_saved_pass_rejects_nonzero_failures(
    failed_field: str,
) -> None:
    document = _coherence_evaluator_document()
    metrics = document["metrics"]
    metrics[failed_field] = 1
    if failed_field == "failed_checks":
        metrics["checks"]["navigator_consistent"] = False
        metrics["passed_checks"] = 0

    with pytest.raises(ContractError, match="controlled coherence pass"):
        ops_module._summarize_coherence_evaluator(
            document, expected_id="controlled_coherence"
        )


def test_controlled_coherence_saved_pass_rejects_forged_passed_count() -> None:
    document = _coherence_evaluator_document()
    document["metrics"]["passed_checks"] = 999

    with pytest.raises(ContractError, match="passed check count"):
        ops_module._summarize_coherence_evaluator(
            document, expected_id="controlled_coherence"
        )


@pytest.mark.parametrize(
    "missing_field", ["passed_checks", "failed_checks", "unavailable_checks"]
)
def test_controlled_coherence_saved_pass_requires_check_counts(
    missing_field: str,
) -> None:
    document = _coherence_evaluator_document()
    del document["metrics"][missing_field]

    with pytest.raises(ContractError, match="controlled coherence pass.*check counts"):
        ops_module._summarize_coherence_evaluator(
            document, expected_id="controlled_coherence"
        )


def test_coherence_summary_rejects_error_labeled_as_pass() -> None:
    summary = ops_module._summarize_coherence_evaluator(
        _coherence_evaluator_document(), expected_id="controlled_coherence"
    )
    summary["status"] = "error"
    with pytest.raises(ContractError, match="status and verdict"):
        ops_module._validate_coherence_summary(summary)


def test_align_lab_fixture_identity_rewrites_hardware_concurrency(
    tmp_path: Path,
) -> None:
    fixture_ids = _seed(
        tmp_path,
        count=1,
        product="browser-core",
        major=153,
        id_prefix="ops-launch",
        hardware_concurrency=8,
        provenance_source="ops-launch-fixture:{id}",
    )
    anchor_id = _seed_host_anchor(tmp_path, hw=32)
    from browser_core.personas import load_persona

    fixture = load_persona(tmp_path, fixture_ids[0])
    assert is_lab_ops_fixture_persona(fixture) is True
    anchors = resolve_host_identity_anchors(tmp_path)
    assert anchors["anchor_persona_id"] == anchor_id
    assert anchors["leaves"]["window.hardwareConcurrency"] == 32
    contract, meta = align_lab_fixture_identity_contract(fixture, anchors)
    assert meta["aligned"] is True
    assert "window.hardwareConcurrency" in meta["changed_paths"]
    assert contract["expected"]["window.hardwareConcurrency"] == 32
    assert contract["expected"]["window.platform"] == "Win32"
    # Catalog persona unchanged
    assert fixture["identity_contract"]["expected"]["window.hardwareConcurrency"] == 8


def test_align_skips_owned_primary_persona(tmp_path: Path) -> None:
    anchor_id = _seed_host_anchor(tmp_path, hw=32)
    from browser_core.personas import load_persona

    owned = load_persona(tmp_path, anchor_id)
    assert is_lab_ops_fixture_persona(owned) is False
    anchors = resolve_host_identity_anchors(tmp_path)
    contract, meta = align_lab_fixture_identity_contract(owned, anchors)
    assert meta["aligned"] is False
    assert meta["reason"] == "not-lab-fixture"
    assert contract["expected"]["window.hardwareConcurrency"] == 32


@pytest.mark.parametrize(
    "kwargs",
    [
        {"headless": "false"},
        {"network_auto": 1},
        {"evaluate_session": "not-callable"},
        {"out_dir": "output"},
    ],
)
def test_coherence_cohort_controls_are_typed_before_catalog_or_output_access(
    tmp_path: Path, kwargs
) -> None:
    with pytest.raises(ContractError):
        run_ops_coherence_cohort(
            tmp_path,
            executable=tmp_path / "chrome.exe",
            repository_root=tmp_path,
            **kwargs,
        )
    assert not (tmp_path / "profiles").exists()


def test_coherence_cohort_refuses_same_id_route_digest_change_before_launch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from browser_core.network import add_network_route, build_network_route

    _seed_host_anchor(tmp_path)
    persona_id = _seed(
        tmp_path, count=1, product="browser-core", major=153, id_prefix="ops-core"
    )[0]
    route_id = "ops-direct-us"
    add_network_route(
        tmp_path,
        build_network_route(
            route_id=route_id,
            name="Ops Direct US",
            geography={"country": "US", "locale": "en-US", "timezone": "America/Chicago"},
            mode="direct",
        ),
    )
    original_attach = ops_module.attach_network_route

    def change_saved_binding(workspace: Path, profile_id: str, selected_route: str):
        attached = original_attach(workspace, profile_id, selected_route)
        path = workspace / "profiles" / "registry" / f"{profile_id}.json"
        saved = json.loads(path.read_text(encoding="utf-8"))
        assert saved["network_route"]["sha256_16"] != "0" * 16
        saved["network_route"]["sha256_16"] = "0" * 16
        path.write_bytes(canonical_json_bytes(saved))
        return attached

    launches: list[str] = []

    def forbid_launch(config, _repository_root):
        launches.append(config.profile_id)
        raise RuntimeError("unverified route reached launch")

    monkeypatch.setattr(ops_module, "attach_network_route", change_saved_binding)
    monkeypatch.setattr(ops_module, "discover_browser_core_launch_major", lambda _root: 153)
    monkeypatch.setattr("browser_core.launcher.launch_evaluation", forbid_launch)
    report = run_ops_coherence_cohort(
        tmp_path,
        count=1,
        persona_ids=[persona_id],
        executable=tmp_path / "chrome.exe",
        repository_root=tmp_path,
        network_route_id=route_id,
    )
    assert report["passed"] is False
    assert launches == []


@pytest.mark.parametrize("route_configured", [True, False])
def test_coherence_cohort_rejects_postlaunch_route_receipt_before_evaluation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, route_configured: bool
) -> None:
    _seed_host_anchor(tmp_path)
    persona_id = _seed(
        tmp_path, count=1, product="browser-core", major=153, id_prefix="ops-core"
    )[0]
    route_id, route_digest = _seed_ops_direct_route(tmp_path)
    assert route_digest != "0" * 16
    events: list[str] = []

    def fake_launch(config, _repository_root):  # noqa: ANN001
        events.append("launch")
        path = tmp_path / "sessions" / f"{config.profile_id}.json"
        path.parent.mkdir(exist_ok=True)
        session = {
            "run_id": f"run-{config.profile_id}", "state": "active",
            "network": {"route_id": route_id, "route_sha256_16": "0" * 16},
        }
        path.write_text(json.dumps(session), encoding="utf-8")
        return path, session

    def fake_eval(*_args, **_kwargs):  # noqa: ANN001
        events.append("eval")
        return {
            "eval_exit": 0, "error": None,
            "primary": {
                "evaluator_id": "controlled_coherence", "status": "ok",
                "verdict": "pass", "passed_checks": 1,
                "failed_checks": 0, "unavailable_checks": 0,
                "failed_check_ids": [], "unavailable_check_ids": [],
            },
        }

    def fake_stop(path, timeout_seconds=15.0):  # noqa: ANN001
        events.append("stop")
        return _stopped_receipt(path)

    real_delete = ops_module.delete_disposable_profile

    def track_delete(workspace: Path, selected_profile: str):
        events.append("delete")
        return real_delete(workspace, selected_profile)

    monkeypatch.setattr(ops_module, "discover_browser_core_launch_major", lambda _root: 153)
    monkeypatch.setattr("browser_core.launcher.launch_evaluation", fake_launch)
    monkeypatch.setattr("browser_core.lifecycle.stop_session", fake_stop)
    monkeypatch.setattr(ops_module, "delete_disposable_profile", track_delete)
    report = run_ops_coherence_cohort(
        tmp_path, count=1, persona_ids=[persona_id],
        executable=tmp_path / "chrome.exe", repository_root=tmp_path,
        network_route_id=route_id if route_configured else None,
        evaluate_session=fake_eval,
        batch_id="coh-route-receipt",
    )
    assert report["passed"] is False
    assert events == ["launch", "stop", "delete"]
    assert report["orphans"] == []


@pytest.mark.skipif(os.name != "nt", reason="Windows directory junction boundary")
def test_coherence_cohort_rejects_output_junction_before_creation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    foreign = tmp_path / "foreign"
    foreign.mkdir()
    junction = tmp_path / "junction"
    created = subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(junction), str(foreign)],
        capture_output=True, check=False,
    )
    if created.returncode:
        pytest.skip("host could not create an unprivileged directory junction")
    monkeypatch.setattr(ops_module, "discover_browser_core_launch_major", lambda _root: 153)
    monkeypatch.setattr(
        ops_module, "select_launch_compatible_personas",
        lambda *_args, **_kwargs: (["persona-fixture"], {}),
    )

    def stop_before_launch(_workspace: Path) -> None:
        raise ContractError("synthetic cohort stop")

    monkeypatch.setattr(ops_module, "resolve_host_identity_anchors", stop_before_launch)
    try:
        with pytest.raises(ContractError):
            run_ops_coherence_cohort(
                tmp_path, count=1, persona_ids=["persona-fixture"],
                executable=tmp_path / "chrome.exe", repository_root=tmp_path,
                out_dir=junction / "cohort-output",
            )
        assert not (foreign / "cohort-output").exists()
    finally:
        junction.rmdir()


@pytest.mark.skipif(os.name != "nt", reason="Windows dangling junction boundary")
def test_coherence_cohort_refuses_dangling_arm_output_before_evaluator(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _seed_host_anchor(tmp_path, hw=32)
    ids = _seed(
        tmp_path, count=1, product="browser-core", major=153,
        id_prefix="ops-core", hardware_concurrency=8,
        provenance_source="ops-launch-fixture:{id}",
    )
    out_dir = tmp_path / "cohort-out"
    out_dir.mkdir()
    arm = out_dir / f"arm-000-{ids[0]}"
    created = subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(arm), str(tmp_path / "missing-output")],
        capture_output=True, check=False,
    )
    if created.returncode:
        pytest.skip("host could not create an unprivileged directory junction")
    assert not arm.exists() and os.path.lexists(arm)

    def fake_launch(config, _repository_root):  # noqa: ANN001
        session_path = tmp_path / "sessions" / f"{config.profile_id}.json"
        session_path.parent.mkdir(exist_ok=True)
        session = {"run_id": f"run-{config.profile_id}", "state": "active"}
        session_path.write_text(json.dumps(session), encoding="utf-8")
        return session_path, session

    def forbid_eval(*_args: object, **_kwargs: object) -> None:
        pytest.fail("cohort evaluator received a dangling output junction")

    monkeypatch.setattr(ops_module, "discover_browser_core_launch_major", lambda _root: 153)
    monkeypatch.setattr("browser_core.launcher.launch_evaluation", fake_launch)
    monkeypatch.setattr(
        "browser_core.lifecycle.stop_session",
        lambda path, timeout_seconds=15.0: _stopped_receipt(path),
    )
    try:
        report = run_ops_coherence_cohort(
            tmp_path, count=1, persona_ids=ids,
            executable=tmp_path / "chrome.exe", repository_root=tmp_path,
            out_dir=out_dir, evaluate_session=forbid_eval, batch_id="coh-dangle",
        )
        assert report["passed"] is False
        assert report["identities"][0]["state"] == "failed"
        assert os.path.lexists(arm)
    finally:
        arm.rmdir()


@pytest.mark.parametrize("evaluators", ["\ud800", "not-an-evaluator!"])
def test_coherence_cohort_rejects_invalid_evaluators_before_discovery(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, evaluators: str
) -> None:
    monkeypatch.setattr(
        ops_module,
        "discover_browser_core_launch_major",
        lambda *_args, **_kwargs: pytest.fail("invalid evaluator reached discovery"),
    )

    with pytest.raises(ContractError, match="evaluator"):
        run_ops_coherence_cohort(
            tmp_path,
            executable=tmp_path / "chrome.exe",
            repository_root=tmp_path,
            evaluators=evaluators,
        )

    assert not (tmp_path / "profiles").exists()


def test_ops_coherence_cohort_headed_launch_eval_stop_dispose(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """B10: real run_ops_coherence_cohort path with monkeypatched I/O only."""
    _seed_host_anchor(tmp_path, hw=32)
    ids = _seed(
        tmp_path,
        count=5,
        product="browser-core",
        major=153,
        id_prefix="ops-core",
        hardware_concurrency=8,
        provenance_source="ops-launch-fixture:{id}",
    )
    order: list[str] = []
    launched_headless: list[bool] = []
    attached_contracts: list[dict] = []

    def fake_launch(config, repository_root):  # noqa: ANN001
        order.append(f"launch:{config.profile_id}")
        launched_headless.append(bool(config.headless))
        path = tmp_path / "sessions" / f"{config.profile_id}.json"
        path.parent.mkdir(exist_ok=True)
        session = {
            "schema": "browser-core.session/1",
            "run_id": f"run-{config.profile_id}",
            "state": "active",
            "profile": {"id": config.profile_id},
        }
        path.write_text(json.dumps(session), encoding="utf-8")
        return path, session

    def fake_stop(path, timeout_seconds=15.0):  # noqa: ANN001
        order.append(f"stop:{path.stem}")
        return _stopped_receipt(path)

    def fake_eval(
        session_file,
        *,
        out_dir,
        evaluators="controlled_coherence",
        workspace=None,
        **_kw,
    ):  # noqa: ANN001
        order.append(f"eval:{Path(session_file).stem}")
        assert evaluators == "controlled_coherence"
        # Real run_session_coherence_eval requires out_dir absent; fakes may write under parent only.
        assert not Path(out_dir).exists()
        return {
            "schema": "browser-core.session-coherence-eval/1",
            "session_file": str(session_file),
            "eval_exit": 0,
            "evaluators_requested": evaluators,
            "arms": [
                {
                    "evaluator_id": "controlled_coherence",
                    "status": "ok",
                    "verdict": "pass",
                    "passed_checks": 61,
                    "failed_checks": 0,
                    "unavailable_checks": 1,
                    "identity_passed_claims": 26,
                    "identity_failed_claims": 0,
                    "identity_unavailable_claims": 0,
                    "failed_check_ids": [],
                    "unavailable_check_ids": ["speech_voice_languages_well_formed"],
                }
            ],
            "primary": {
                "evaluator_id": "controlled_coherence",
                "status": "ok",
                "verdict": "pass",
                "passed_checks": 61,
                "failed_checks": 0,
                "unavailable_checks": 1,
                "identity_passed_claims": 26,
                "identity_failed_claims": 0,
                "identity_unavailable_claims": 0,
                "failed_check_ids": [],
                "unavailable_check_ids": ["speech_voice_languages_well_formed"],
            },
            "error": None,
            "stderr_tail": "",
        }

    real_attach = __import__(
        "browser_core.profiles", fromlist=["attach_persona_identity_for_ops"]
    ).attach_persona_identity_for_ops

    def tracking_attach(workspace, profile_id, persona_id, identity_contract=None):  # noqa: ANN001
        if identity_contract is not None:
            attached_contracts.append(identity_contract)
        return real_attach(
            workspace, profile_id, persona_id, identity_contract=identity_contract
        )

    monkeypatch.setattr(
        "browser_core.multi_identity_ops.discover_browser_core_launch_major",
        lambda _root: 153,
    )
    monkeypatch.setattr("browser_core.launcher.launch_evaluation", fake_launch)
    monkeypatch.setattr("browser_core.lifecycle.stop_session", fake_stop)
    monkeypatch.setattr(
        "browser_core.multi_identity_ops.attach_persona_identity_for_ops",
        tracking_attach,
    )

    report = run_ops_coherence_cohort(
        tmp_path,
        count=3,
        persona_ids=ids,
        executable=tmp_path / "chrome.exe",
        repository_root=tmp_path,
        out_dir=tmp_path / "cohort-out",
        evaluate_session=fake_eval,
        headless=False,
        batch_id="coh-test01",
    )
    assert report["schema"] == "browser-core.ops-coherence-cohort/1"
    assert report["lifecycle_passed"] is True
    assert report["passed"] is True
    assert report["headless"] is False
    assert report["coherence_summary"]["pass"] == 3
    assert report["coherence_summary"]["all_pass"] is True
    assert report["compatibility"]["selected"] == 3
    assert len(report["identities"]) == 3
    assert all(item["state"] == "disposed" for item in report["identities"])
    assert all(item["coherence"]["verdict"] == "pass" for item in report["identities"])
    # Fixture contracts aligned to host hw=32 before attach
    assert len(attached_contracts) == 3
    assert all(
        c["expected"]["window.hardwareConcurrency"] == 32 for c in attached_contracts
    )
    assert report["host_identity_anchors"]["leaves"]["window.hardwareConcurrency"] == 32
    assert any(
        (item.get("identity_align") or {}).get("aligned") is True
        for item in report["identities"]
    )
    # Per arm: launch → eval → stop (sequential lifecycle)
    assert order == [
        "launch:ops-disp-coh-test01-000",
        "eval:ops-disp-coh-test01-000",
        "stop:ops-disp-coh-test01-000",
        "launch:ops-disp-coh-test01-001",
        "eval:ops-disp-coh-test01-001",
        "stop:ops-disp-coh-test01-001",
        "launch:ops-disp-coh-test01-002",
        "eval:ops-disp-coh-test01-002",
        "stop:ops-disp-coh-test01-002",
    ]
    assert launched_headless == [False, False, False]
    leftovers = [
        p for p in list_profiles(tmp_path) if is_disposable_profile_id(p["id"])
    ]
    assert leftovers == []
    blob = json.dumps(report).lower()
    assert "password" not in blob
    assert "authorization" not in blob
    assert "cookie=" not in blob


def test_coherence_cohort_rejects_replaced_output_directory_before_evaluation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _seed_host_anchor(tmp_path)
    persona_id = _seed(
        tmp_path, count=1, product="browser-core", major=153, id_prefix="ops-core"
    )[0]
    output = tmp_path / "cohort-out"
    retained = tmp_path / "retained-cohort-out"
    evaluator_calls: list[Path] = []
    summary = ops_module._summarize_coherence_evaluator(
        _coherence_evaluator_document(), expected_id="controlled_coherence"
    )

    def fake_launch(config, _repository_root):  # noqa: ANN001
        output.rename(retained)
        output.mkdir()
        (output / "competitor.txt").write_text("keep", encoding="utf-8")
        path = tmp_path / "sessions" / f"{config.profile_id}.json"
        path.parent.mkdir(exist_ok=True)
        session = {
            "schema": "browser-core.session/1",
            "run_id": f"run-{config.profile_id}",
            "state": "active",
            "profile": {"id": config.profile_id},
        }
        path.write_text(json.dumps(session), encoding="utf-8")
        return path, session

    def fake_eval(_session_file, *, out_dir, **_kwargs):  # noqa: ANN001
        evaluator_calls.append(out_dir)
        return {"eval_exit": 0, "primary": summary, "error": None}

    monkeypatch.setattr(
        ops_module, "discover_browser_core_launch_major", lambda _root: 153
    )
    monkeypatch.setattr("browser_core.launcher.launch_evaluation", fake_launch)
    monkeypatch.setattr(
        "browser_core.lifecycle.stop_session",
        lambda path, **_kwargs: _stopped_receipt(path),
    )
    with pytest.raises(ContractError, match="coherence output directory changed"):
        run_ops_coherence_cohort(
            tmp_path,
            count=1,
            persona_ids=[persona_id],
            executable=tmp_path / "chrome.exe",
            repository_root=tmp_path,
            out_dir=output,
            evaluate_session=fake_eval,
            batch_id="coh-output-swap",
        )

    assert evaluator_calls == []
    assert (output / "competitor.txt").read_text(encoding="utf-8") == "keep"
    assert list_profiles(tmp_path) == []


def test_coherence_cohort_uses_falsey_callable_evaluator_override(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _seed_host_anchor(tmp_path)
    persona_id = _seed(
        tmp_path, count=1, product="browser-core", major=153, id_prefix="ops-core"
    )[0]
    summary = ops_module._summarize_coherence_evaluator(
        _coherence_evaluator_document(), expected_id="controlled_coherence"
    )
    calls: list[Path] = []

    class FalseyEvaluator:
        def __bool__(self) -> bool:
            return False

        def __call__(self, session_file, *, out_dir, **_kwargs):  # noqa: ANN001
            calls.append(Path(session_file))
            assert not Path(out_dir).exists()
            return {"eval_exit": 0, "primary": summary, "error": None}

    def fake_launch(config, _repository_root):  # noqa: ANN001
        path = tmp_path / "sessions" / f"{config.profile_id}.json"
        path.parent.mkdir(exist_ok=True)
        session = {
            "schema": "browser-core.session/1",
            "run_id": f"run-{config.profile_id}",
            "state": "active",
            "profile": {"id": config.profile_id},
        }
        path.write_text(json.dumps(session), encoding="utf-8")
        return path, session

    def unexpected_default(*_args, **_kwargs):
        raise AssertionError("the supplied callable evaluator was ignored")

    monkeypatch.setattr(
        ops_module, "discover_browser_core_launch_major", lambda _root: 153
    )
    monkeypatch.setattr(ops_module, "run_session_coherence_eval", unexpected_default)
    monkeypatch.setattr("browser_core.launcher.launch_evaluation", fake_launch)
    monkeypatch.setattr(
        "browser_core.lifecycle.stop_session",
        lambda path, **_kwargs: _stopped_receipt(path),
    )

    report = run_ops_coherence_cohort(
        tmp_path,
        count=1,
        persona_ids=[persona_id],
        executable=tmp_path / "chrome.exe",
        repository_root=tmp_path,
        out_dir=tmp_path / "cohort-out",
        evaluate_session=FalseyEvaluator(),
        batch_id="coh-falsey-eval",
    )

    assert report["passed"] is True
    assert report["coherence_summary"]["pass"] == 1
    assert len(calls) == 1
    assert list_profiles(tmp_path) == []


def test_coherence_cohort_rejects_invalid_output_before_creating_auto_route(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _seed_host_anchor(tmp_path)
    persona_id = _seed(
        tmp_path, count=1, product="browser-core", major=153, id_prefix="ops-core"
    )[0]
    output = tmp_path / "cohort-out"
    output.write_text("unrelated output", encoding="utf-8")
    assert not (tmp_path / "network").exists()
    monkeypatch.setattr(
        ops_module, "discover_browser_core_launch_major", lambda _root: 153
    )

    with pytest.raises(ContractError, match="coherence cohort output directory"):
        run_ops_coherence_cohort(
            tmp_path,
            count=1,
            persona_ids=[persona_id],
            executable=tmp_path / "chrome.exe",
            repository_root=tmp_path,
            out_dir=output,
            network_auto=True,
            batch_id="coh-invalid-output",
        )

    assert output.read_text(encoding="utf-8") == "unrelated output"
    assert not (tmp_path / "network").exists()


@pytest.mark.parametrize("lost_resource", ["claim", "profile"])
def test_ops_coherence_cohort_rejects_disappeared_owned_resource(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, lost_resource: str
) -> None:
    _seed_host_anchor(tmp_path)
    persona_id = _seed(
        tmp_path, count=1, product="browser-core", major=153, id_prefix="ops-core"
    )[0]
    real_release = ops_module.release_persona_claim

    def disappear_before_release(
        workspace: Path, persona_id: str, claim_id: str, *, missing_ok: bool = False
    ) -> dict:
        claim_path = workspace / "personas" / "claims" / f"{persona_id}.json"
        if claim_path.is_file():
            claim_path.unlink()
        return real_release(workspace, persona_id, claim_id, missing_ok=missing_ok)

    real_delete = ops_module.delete_disposable_profile
    first_delete = True

    def disappear_before_delete(workspace: Path, profile_id: str) -> dict:
        nonlocal first_delete
        if first_delete:
            first_delete = False
            assert real_delete(workspace, profile_id)["deleted"] is True
        return real_delete(workspace, profile_id)

    def fake_launch(config: object, _repository_root: Path) -> tuple[Path, dict]:
        profile_id = config.profile_id  # type: ignore[attr-defined]
        return tmp_path / "sessions" / f"{profile_id}.json", {"run_id": f"run-{profile_id}"}

    def fake_eval(_session_file: Path, **_kwargs: object) -> dict:
        return {
            "eval_exit": 0,
            "error": None,
            "primary": {
                "evaluator_id": "controlled_coherence",
                "status": "ok",
                "verdict": "pass",
                "passed_checks": 1,
                "failed_checks": 0,
                "unavailable_checks": 0,
                "failed_check_ids": [],
                "unavailable_check_ids": [],
            },
        }

    monkeypatch.setattr(ops_module, "discover_browser_core_launch_major", lambda _root: 153)
    monkeypatch.setattr("browser_core.launcher.launch_evaluation", fake_launch)
    monkeypatch.setattr(
        "browser_core.lifecycle.stop_session",
        lambda path, **_kwargs: _stopped_receipt(path),
    )
    if lost_resource == "claim":
        monkeypatch.setattr(ops_module, "release_persona_claim", disappear_before_release)
    else:
        monkeypatch.setattr(ops_module, "delete_disposable_profile", disappear_before_delete)

    report = run_ops_coherence_cohort(
        tmp_path,
        count=1,
        persona_ids=[persona_id],
        executable=tmp_path / "chrome.exe",
        repository_root=tmp_path,
        evaluate_session=fake_eval,
        batch_id="coh-vanish",
    )
    assert report["passed"] is False
    assert report["identities"][0]["state"] == "failed"
    assert report["errors"]


def test_ops_coherence_cohort_does_not_count_unrelated_disposable_profile_as_orphan(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _seed_host_anchor(tmp_path)
    persona_id = _seed(
        tmp_path, count=1, product="browser-core", major=153, id_prefix="ops-core"
    )[0]
    unrelated_id = "ops-disp-other-coh-foreign-999"
    create_profile(tmp_path, unrelated_id, name="unrelated disposable")

    def fake_launch(config: object, _repository_root: Path) -> tuple[Path, dict]:
        profile_id = config.profile_id  # type: ignore[attr-defined]
        return tmp_path / "sessions" / f"{profile_id}.json", {"run_id": f"run-{profile_id}"}

    def fake_eval(_session_file: Path, **_kwargs: object) -> dict:
        return {
            "eval_exit": 0,
            "error": None,
            "primary": {
                "evaluator_id": "controlled_coherence",
                "status": "ok",
                "verdict": "pass",
                "passed_checks": 1,
                "failed_checks": 0,
                "unavailable_checks": 0,
                "failed_check_ids": [],
                "unavailable_check_ids": [],
            },
        }

    monkeypatch.setattr(ops_module, "discover_browser_core_launch_major", lambda _root: 153)
    monkeypatch.setattr("browser_core.launcher.launch_evaluation", fake_launch)
    monkeypatch.setattr(
        "browser_core.lifecycle.stop_session",
        lambda path, **_kwargs: _stopped_receipt(path),
    )
    report = run_ops_coherence_cohort(
        tmp_path,
        count=1,
        persona_ids=[persona_id],
        executable=tmp_path / "chrome.exe",
        repository_root=tmp_path,
        evaluate_session=fake_eval,
        batch_id="coh-foreign",
    )

    assert report["errors"] == []
    assert report["orphans"] == []
    assert report["passed"] is True
    assert any(item["id"] == unrelated_id for item in list_profiles(tmp_path))


def test_coherence_cohort_preserves_competing_profile_and_claim(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _seed_host_anchor(tmp_path)
    persona_id = _seed(
        tmp_path, count=1, product="browser-core", major=153, id_prefix="ops-core"
    )[0]
    batch_id = "coh-occupied"
    profile_id = f"ops-disp-{batch_id}-000"
    claim_id = f"{batch_id}-{persona_id}"
    create_profile(tmp_path, profile_id, name="competing profile")
    claim_persona_exclusive(tmp_path, persona_id, claim_id)
    claim_path = tmp_path / "personas" / "claims" / f"{persona_id}.json"
    original_claim = claim_path.read_bytes()
    monkeypatch.setattr(ops_module, "discover_browser_core_launch_major", lambda _root: 153)

    report = run_ops_coherence_cohort(
        tmp_path,
        count=1,
        persona_ids=[persona_id],
        executable=tmp_path / "chrome.exe",
        repository_root=tmp_path,
        batch_id=batch_id,
    )

    assert report["passed"] is False
    assert report["orphans"] == []
    assert any(item["id"] == profile_id for item in list_profiles(tmp_path))
    assert claim_path.read_bytes() == original_claim


def test_coherence_cohort_does_not_adopt_same_id_existing_claim(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _seed_host_anchor(tmp_path)
    persona_id = _seed(
        tmp_path, count=1, product="browser-core", major=153, id_prefix="ops-core"
    )[0]
    batch_id = "coh-claimed"
    claim_persona_exclusive(tmp_path, persona_id, f"{batch_id}-{persona_id}")
    claim_path = tmp_path / "personas" / "claims" / f"{persona_id}.json"
    original_claim = claim_path.read_bytes()
    monkeypatch.setattr(ops_module, "discover_browser_core_launch_major", lambda _root: 153)

    def stop_before_launch(*_args: object, **_kwargs: object) -> None:
        raise ContractError("synthetic stop before launch")

    monkeypatch.setattr(ops_module, "attach_persona_identity_for_ops", stop_before_launch)
    report = run_ops_coherence_cohort(
        tmp_path,
        count=1,
        persona_ids=[persona_id],
        executable=tmp_path / "chrome.exe",
        repository_root=tmp_path,
        batch_id=batch_id,
    )

    assert report["passed"] is False
    assert claim_path.read_bytes() == original_claim
    assert not any(
        item["id"] == f"ops-disp-{batch_id}-000" for item in list_profiles(tmp_path)
    )


def test_coherence_cohort_retains_claim_when_owned_profile_cannot_be_deleted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _seed_host_anchor(tmp_path)
    persona_id = _seed(
        tmp_path, count=1, product="browser-core", major=153, id_prefix="ops-core"
    )[0]
    batch_id = "coh-retain"
    profile_id = f"ops-disp-{batch_id}-000"
    monkeypatch.setattr(ops_module, "discover_browser_core_launch_major", lambda _root: 153)

    def stop_before_launch(*_args: object, **_kwargs: object) -> None:
        raise ContractError("synthetic stop before launch")

    def refuse_delete(*_args: object, **_kwargs: object) -> None:
        raise ContractError("synthetic delete failure")

    monkeypatch.setattr(ops_module, "attach_persona_identity_for_ops", stop_before_launch)
    monkeypatch.setattr(ops_module, "delete_disposable_profile", refuse_delete)
    report = run_ops_coherence_cohort(
        tmp_path,
        count=1,
        persona_ids=[persona_id],
        executable=tmp_path / "chrome.exe",
        repository_root=tmp_path,
        batch_id=batch_id,
    )

    assert report["passed"] is False
    assert report["orphans"] == [profile_id]
    assert any(item["id"] == profile_id for item in list_profiles(tmp_path))
    assert (
        tmp_path / "personas" / "claims" / f"{persona_id}.json"
    ).is_file()


def test_ops_coherence_cohort_records_fail_verdict_without_lifecycle_fail(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _seed_host_anchor(tmp_path, hw=32)
    _seed(tmp_path, count=3, product="browser-core", major=153, id_prefix="ops-core")

    def fake_launch(config, repository_root):  # noqa: ANN001
        path = tmp_path / "sessions" / f"{config.profile_id}.json"
        path.parent.mkdir(exist_ok=True)
        path.write_text(
            json.dumps({"run_id": f"run-{config.profile_id}", "state": "active"}),
            encoding="utf-8",
        )
        return path, {"run_id": f"run-{config.profile_id}"}

    def fake_eval(
        session_file,
        *,
        out_dir,
        evaluators="controlled_coherence",
        workspace=None,
        **_kw,
    ):  # noqa: ANN001
        return {
            "eval_exit": 0,
            "primary": {
                "evaluator_id": "controlled_coherence",
                "status": "ok",
                "verdict": "fail",
                "passed_checks": 60,
                "failed_checks": 1,
                "unavailable_checks": 1,
                "failed_check_ids": ["headless_token_absent"],
                "unavailable_check_ids": ["speech_voice_languages_well_formed"],
            },
            "error": None,
        }

    monkeypatch.setattr(
        "browser_core.multi_identity_ops.discover_browser_core_launch_major",
        lambda _root: 153,
    )
    monkeypatch.setattr("browser_core.launcher.launch_evaluation", fake_launch)
    monkeypatch.setattr(
        "browser_core.lifecycle.stop_session",
        lambda path, timeout_seconds=15.0: _stopped_receipt(path),
    )

    report = run_ops_coherence_cohort(
        tmp_path,
        count=3,
        executable=tmp_path / "chrome.exe",
        repository_root=tmp_path,
        evaluate_session=fake_eval,
        headless=True,
    )
    assert report["lifecycle_passed"] is True
    assert report["passed"] is True  # lifecycle clean
    assert report["coherence_summary"]["fail"] == 3
    assert report["coherence_summary"]["all_pass"] is False
    assert report["headless"] is True
    assert all(
        "headless_token_absent"
        in (item.get("coherence") or {}).get("failed_check_ids", [])
        for item in report["identities"]
    )


@pytest.mark.parametrize("eval_exit,eval_error", [(2, "eval-failed"), (0, "eval-failed")])
def test_ops_coherence_cohort_does_not_count_failed_eval_artifact_as_pass(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    eval_exit: int,
    eval_error: str,
) -> None:
    persona_id = _seed_host_anchor(tmp_path, hw=32)

    def fake_launch(config, repository_root):  # noqa: ANN001
        path = tmp_path / "sessions" / f"{config.profile_id}.json"
        path.parent.mkdir(exist_ok=True)
        session = {"run_id": f"run-{config.profile_id}", "state": "active"}
        path.write_text(json.dumps(session), encoding="utf-8")
        return path, session

    def fake_eval(*_args, **_kwargs):  # noqa: ANN001
        return {
            "eval_exit": eval_exit,
            "error": eval_error,
            "primary": {
                "evaluator_id": "controlled_coherence",
                "status": "ok",
                "verdict": "pass",
                "passed_checks": 1,
                "failed_checks": 0,
                "unavailable_checks": 0,
                "failed_check_ids": [],
                "unavailable_check_ids": [],
            },
        }

    monkeypatch.setattr(
        "browser_core.multi_identity_ops.discover_browser_core_launch_major",
        lambda _root: 153,
    )
    monkeypatch.setattr("browser_core.launcher.launch_evaluation", fake_launch)
    monkeypatch.setattr(
        "browser_core.lifecycle.stop_session",
        lambda path, timeout_seconds=15.0: _stopped_receipt(path),
    )
    report = run_ops_coherence_cohort(
        tmp_path,
        count=1,
        persona_ids=[persona_id],
        executable=tmp_path / "chrome.exe",
        repository_root=tmp_path,
        evaluate_session=fake_eval,
        batch_id=f"coh-eval-exit-{eval_exit}",
    )
    assert report["identities"][0]["state"] == "disposed"
    assert report["coherence_summary"]["pass"] == 0
    assert report["coherence_summary"]["error"] == 1
    assert report["coherence_summary"]["all_pass"] is False
    assert report["passed"] is False


def test_ops_coherence_cohort_filters_incompatible_and_cleans_on_eval_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _seed_host_anchor(tmp_path, hw=32)
    compatible, _incompatible = _seed_launch_mix(tmp_path)
    launched: list[str] = []
    stopped: list[str] = []

    def fake_launch(config, repository_root):  # noqa: ANN001
        launched.append(config.profile_id)
        path = tmp_path / "sessions" / f"{config.profile_id}.json"
        path.parent.mkdir(exist_ok=True)
        path.write_text(json.dumps({"run_id": "r"}), encoding="utf-8")
        return path, {"run_id": "r"}

    def fake_stop(path, timeout_seconds=15.0):  # noqa: ANN001
        stopped.append(path.stem)
        return _stopped_receipt(path, run_id="r")

    def boom_eval(*_a, **_k):  # noqa: ANN001
        raise RuntimeError("eval-io-down")

    monkeypatch.setattr(
        "browser_core.multi_identity_ops.discover_browser_core_launch_major",
        lambda _root: 153,
    )
    monkeypatch.setattr("browser_core.launcher.launch_evaluation", fake_launch)
    monkeypatch.setattr("browser_core.lifecycle.stop_session", fake_stop)

    report = run_ops_coherence_cohort(
        tmp_path,
        count=3,
        executable=tmp_path / "chrome.exe",
        repository_root=tmp_path,
        evaluate_session=boom_eval,
    )
    # host anchor + launch-mix compatible personas
    assert report["compatibility"]["compatible_pool"] == len(compatible) + 1
    assert report["compatibility"]["selected"] == 3
    assert len(launched) == 3
    # stop still attempted after eval boom
    assert len(stopped) == 3
    assert report["lifecycle_passed"] is False
    assert report["orphans"] == []
    leftovers = [
        p for p in list_profiles(tmp_path) if is_disposable_profile_id(p["id"])
    ]
    assert leftovers == []


@pytest.mark.parametrize("unprotected_stopped", [False, True])
def test_ops_coherence_preserves_containment_when_cleanup_stop_is_unverified(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, unprotected_stopped: bool
) -> None:
    persona_id = _seed_host_anchor(tmp_path, hw=32)
    stop_calls: list[str] = []

    def fake_launch(config, repository_root):  # noqa: ANN001
        path = tmp_path / "sessions" / f"{config.profile_id}.json"
        path.parent.mkdir(exist_ok=True)
        session = {"run_id": f"run-{config.profile_id}", "state": "active"}
        path.write_text(json.dumps(session), encoding="utf-8")
        return path, session

    def unverified_stop(path, timeout_seconds=15.0):  # noqa: ANN001
        stop_calls.append(path.stem)
        if unprotected_stopped:
            return {**_stopped_receipt(path), "identity_protected": False}
        return {
            "run_id": f"run-{path.stem}",
            "state": "active",
            "running": True,
            "identity_protected": True,
        }

    def fake_eval(*_args, **_kwargs):  # noqa: ANN001
        return {
            "eval_exit": 0,
            "primary": {
                "evaluator_id": "controlled_coherence",
                "status": "ok",
                "verdict": "pass",
                "passed_checks": 1,
                "failed_checks": 0,
                "unavailable_checks": 0,
                "failed_check_ids": [],
                "unavailable_check_ids": [],
            },
            "error": None,
        }

    monkeypatch.setattr(
        "browser_core.multi_identity_ops.discover_browser_core_launch_major",
        lambda _root: 153,
    )
    monkeypatch.setattr("browser_core.launcher.launch_evaluation", fake_launch)
    monkeypatch.setattr("browser_core.lifecycle.stop_session", unverified_stop)

    report = run_ops_coherence_cohort(
        tmp_path,
        count=1,
        persona_ids=[persona_id],
        executable=tmp_path / "chrome.exe",
        repository_root=tmp_path,
        evaluate_session=fake_eval,
        batch_id="coh-stop-proof",
    )
    profile_id = "ops-disp-coh-stop-proof-000"
    assert stop_calls == [profile_id, profile_id]
    assert report["lifecycle_passed"] is False
    assert report["passed"] is False
    assert report["orphans"] == [profile_id]
    assert report["identities"][0]["state"] == "failed"
    assert any(
        error.startswith(f"cleanup-stop {profile_id}:") for error in report["errors"]
    )
    assert any(p["id"] == profile_id for p in list_profiles(tmp_path))
    assert (tmp_path / "personas" / "claims" / f"{persona_id}.json").is_file()


def test_launch_batch_substitutes_unrealizable_persona(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Auto-selected unrealizable personas are skipped and replaced, recorded."""
    ids = _seed(tmp_path, count=4, product="browser-core", major=153)
    unrealizable = ids[0]
    order: list[str] = []
    first_launch = {"done": False}

    def fake_launch(config, repository_root):  # noqa: ANN001
        order.append(config.profile_id)
        if config.profile_id.endswith("-000") and not first_launch["done"]:
            first_launch["done"] = True
            raise PersonaRealizationError(
                "selected persona was not realized: rendering.webgl.renderer; "
                "capture a new profile from this browser or choose a compatible one"
            )
        session_dir = tmp_path / "sessions"
        session_dir.mkdir(exist_ok=True)
        path = session_dir / f"{config.profile_id}.json"
        session = {
            "schema": "browser-core.session/1",
            "run_id": f"run-{config.profile_id}",
            "state": "active",
            "profile": {"id": config.profile_id, "persistence": "persistent"},
        }
        path.write_text(json.dumps(session), encoding="utf-8")
        return path, session

    def fake_stop(path, timeout_seconds=15.0):  # noqa: ANN001
        return _stopped_receipt(path)

    monkeypatch.setattr(
        "browser_core.multi_identity_ops.discover_browser_core_launch_major",
        lambda _root: 153,
    )
    monkeypatch.setattr("browser_core.launcher.launch_evaluation", fake_launch)
    monkeypatch.setattr("browser_core.lifecycle.stop_session", fake_stop)

    batch = run_multi_identity_batch(
        tmp_path,
        ids[:2],
        ready_mode="launch",
        executable=tmp_path / "fake-chrome.exe",
        repository_root=tmp_path,
        allow_persona_substitution=True,
    )
    assert batch["passed"] is True
    assert batch["persona_substitution"]["enabled"] is True
    assert [skip["persona_id"] for skip in batch["persona_substitution"]["skipped"]] == [
        unrealizable
    ]
    # The skip record names the unrealized claim fields, not just a digest.
    assert batch["persona_substitution"]["skipped"][0]["unrealized_fields"] == [
        "rendering.webgl.renderer"
    ]
    # Slot 000 was retried with a replacement persona from the compatible pool.
    assert batch["identities"][0]["persona_id"] in ids[1:]
    assert batch["identities"][0]["substituted_for"] == unrealizable
    assert batch["identities"][1]["substituted_for"] is None
    assert all(item["state"] == "disposed" for item in batch["identities"])
    assert not any(
        p["id"].startswith("ops-disp-") for p in list_profiles(tmp_path)
    )
    # The skipped persona's claim is released for future batches.
    assert not (tmp_path / "personas" / "claims" / f"{unrealizable}.json").exists()


def test_launch_batch_substitution_off_keeps_strict_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ids = _seed(tmp_path, count=3, product="browser-core", major=153)

    def fake_launch(config, repository_root):  # noqa: ANN001
        if config.profile_id.endswith("-000"):
            raise PersonaRealizationError(
                "selected persona was not realized: rendering.webgl.renderer"
            )
        session_dir = tmp_path / "sessions"
        session_dir.mkdir(exist_ok=True)
        path = session_dir / f"{config.profile_id}.json"
        path.write_text(
            json.dumps(
                {
                    "schema": "browser-core.session/1",
                    "run_id": f"run-{config.profile_id}",
                    "state": "active",
                    "profile": {"id": config.profile_id},
                }
            ),
            encoding="utf-8",
        )
        return path, {"run_id": f"run-{config.profile_id}", "state": "active"}

    monkeypatch.setattr(
        "browser_core.multi_identity_ops.discover_browser_core_launch_major",
        lambda _root: 153,
    )
    monkeypatch.setattr("browser_core.launcher.launch_evaluation", fake_launch)
    monkeypatch.setattr(
        "browser_core.lifecycle.stop_session",
        lambda path, timeout_seconds=15.0: _stopped_receipt(path),
    )

    batch = run_multi_identity_batch(
        tmp_path,
        ids[:2],
        ready_mode="launch",
        executable=tmp_path / "fake-chrome.exe",
        repository_root=tmp_path,
        allow_persona_substitution=False,
    )
    assert batch["passed"] is False
    assert batch["persona_substitution"]["skipped"] == []
    assert batch["identities"][0]["state"] == "failed"
    assert batch["identities"][1]["state"] == "disposed"
