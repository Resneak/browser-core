"""Regression cases derived from the September 12/13 adversarial review."""
from __future__ import annotations

import json
import importlib.util
import os
from pathlib import Path

import pytest

from browser_core import build, multi_identity_ops as ops, personas, upstream
from browser_core.contracts import ContractError
from browser_core.errors import PersonaRealizationError
from test_build import ROOT, _write_fixture_attestation
from test_multi_identity_ops import _seed, _stopped_receipt
from test_upstream import _copy_upstream_controls


@pytest.mark.parametrize("filename", ["chrome.exe", "chrome.dll", "trace_processor_shell.exe"])
def test_warm_attestation_rejects_restored_timestamp_rewrite(tmp_path, filename):
    exe, _receipt, _document = _write_fixture_attestation(tmp_path)
    build.load_build_attestation(ROOT, exe)
    target = tmp_path / filename
    before = target.stat()
    body = target.read_bytes()
    target.write_bytes(bytes([body[0] ^ 1]) + body[1:])
    os.utime(target, ns=(before.st_atime_ns, before.st_mtime_ns))
    with pytest.raises(ContractError, match="attestation"):
        build.load_build_attestation(ROOT, exe)


def test_patch_cache_store_never_binds_later_bytes(tmp_path, monkeypatch):
    root = _copy_upstream_controls(tmp_path / "root")
    original = upstream._verified_patch_bundle_uncached

    def verify_then_mutate(root):
        bundle = original(root)
        patch = next((root / "patches").glob("*.patch"))
        patch.write_bytes(patch.read_bytes() + b"\n")
        return bundle

    with monkeypatch.context() as race:
        race.setattr(upstream, "_verified_patch_bundle_uncached", verify_then_mutate)
        upstream._verified_patch_bundle(root)
    with pytest.raises(ContractError, match="hash mismatch"):
        upstream._verified_patch_bundle(root)


def test_warm_patch_cache_checks_unlisted_files_and_owned_links(tmp_path):
    root = _copy_upstream_controls(tmp_path / "root")
    upstream._verified_patch_bundle(root)
    extra = root / "patches" / "extra.patch"
    extra.write_bytes(b"extra")
    with pytest.raises(ContractError, match="unlisted"):
        upstream._verified_patch_bundle(root)
    extra.unlink()
    target = next((root / "patches").glob("*.patch"))
    os.link(target, tmp_path / "extra-link")
    with pytest.raises(ContractError, match="hard link"):
        upstream._verified_patch_bundle(root)


def test_cached_patch_mappings_are_not_exposed(tmp_path):
    root = _copy_upstream_controls(tmp_path / "root")
    first = upstream._verified_patch_bundle(root)
    first.report["patches"] = -1
    first.series["patches"].clear()
    second = upstream._verified_patch_bundle(root)
    assert second.report["patches"] > 0
    assert second.series["patches"]
    second.report["patches"] = -2
    assert upstream._verified_patch_bundle(root).report["patches"] > 0


def test_warm_catalog_rejects_same_timestamp_and_has_no_shared_documents(tmp_path):
    ids = _seed(tmp_path, count=2, product="browser-core", major=153)
    first = personas.list_personas(tmp_path)
    first[0]["device"]["viewport"]["width"] = 7
    assert personas.list_personas(tmp_path)[0]["device"]["viewport"]["width"] == 1280
    target = tmp_path / "personas" / "catalog" / f"{ids[0]}.json"
    before = target.stat()
    target.write_bytes(target.read_bytes().replace(b'"Ops ', b'"Xps ', 1))
    os.utime(target, ns=(before.st_atime_ns, before.st_mtime_ns))
    with pytest.raises(ContractError, match="valid managed document"):
        personas.list_personas(tmp_path)


@pytest.mark.parametrize("receipt_kind", ["forged", "malformed", "hardlink"])
def test_retired_pool_receipt_neither_authorizes_nor_is_overwritten(tmp_path, receipt_kind):
    ids = _seed(tmp_path, count=2, product="browser-core", major=153)
    receipt = tmp_path / "personas" / "launch-compatible-pool.json"
    if receipt_kind == "hardlink":
        sentinel = tmp_path / "sentinel"
        sentinel.write_bytes(b"synthetic sentinel")
        os.link(sentinel, receipt)
    else:
        receipt.write_text(json.dumps({"schema": "browser-core.persona-pool/1", "pools": {
            "153:desktop": {"ids": ["absent-persona"], "active_total": 999,
                            "fingerprint": [[]] if receipt_kind == "malformed" else []}
        }}))
    before = receipt.read_bytes()
    selected, report = ops.select_launch_compatible_personas(tmp_path, 2, major=153)
    assert selected == ids
    assert report["active_personas"] == report["compatible_pool"] == 2
    assert ops.cached_active_persona_count(tmp_path) is None
    assert receipt.read_bytes() == before
    if receipt_kind == "hardlink":
        assert sentinel.read_bytes() == before


def test_selection_classifies_and_counts_one_verified_catalog(tmp_path, monkeypatch):
    _seed(tmp_path, count=2, product="browser-core", major=153)
    original = personas.list_personas
    calls = []

    def counted(workspace):
        calls.append(workspace)
        return original(workspace)

    monkeypatch.setattr(personas, "list_personas", counted)
    _selected, report = ops.select_launch_compatible_personas(tmp_path, 1, major=153)
    assert calls == [tmp_path]
    assert report["active_personas"] == report["compatible_pool"] == 2
    doc = personas.load_persona(tmp_path, "ops-persona-00")
    personas.set_persona_state(tmp_path, doc["id"], "deprecated", expected_sha256=doc["integrity_sha256"])
    assert ops.list_launch_compatible_persona_ids(tmp_path, major=153) == ["ops-persona-01"]


def fake_launches(tmp_path, monkeypatch, *, failures=1, error_type=PersonaRealizationError):
    attempts = []

    def launch(config, root):
        attempts.append(config.profile_id)
        if len(attempts) <= failures:
            raise error_type("selected persona was not realized: rendering.webgl.renderer")
        path = tmp_path / "sessions" / f"{config.profile_id}.json"
        path.parent.mkdir(exist_ok=True)
        document = {"run_id": f"run-{config.profile_id}", "state": "active"}
        path.write_text(json.dumps(document))
        return path, document

    monkeypatch.setattr(ops, "discover_browser_core_launch_major", lambda _root: 153)
    monkeypatch.setattr("browser_core.launcher.launch_evaluation", launch)
    monkeypatch.setattr("browser_core.lifecycle.stop_session", lambda path, **_kw: {
        **_stopped_receipt(path), "shutdown_mode": "forced",
    })
    return attempts


@pytest.mark.parametrize("substitution", [False, True])
def test_explicit_velocity_persona_is_strict_even_when_substitution_requested(tmp_path, monkeypatch, substitution):
    ids = _seed(tmp_path, count=3, product="browser-core", major=153)
    attempts = fake_launches(tmp_path, monkeypatch)
    report = ops.run_profile_velocity_batch(tmp_path, count=1, persona_ids=ids[:1],
        ready_mode="launch", executable=tmp_path / "fake.exe", repository_root=tmp_path,
        allow_persona_substitution=substitution)["ops_batch"]
    assert len(attempts) == 1
    assert not report["passed"]
    assert not report["persona_substitution"]["enabled"]
    assert report["identities"][0]["persona_id"] == ids[0]


@pytest.mark.parametrize("failure_count", [1, 2, 3])
def test_automatic_replacements_retain_every_attempt_and_verified_stop(tmp_path, monkeypatch, failure_count):
    _seed(tmp_path, count=3, product="browser-core", major=153)
    attempts = fake_launches(tmp_path, monkeypatch, failures=failure_count)
    report = ops.run_profile_velocity_batch(tmp_path, count=1, ready_mode="launch",
        executable=tmp_path / "fake.exe", repository_root=tmp_path)["ops_batch"]
    assert len(attempts) == min(failure_count + 1, 3)
    assert len(report["attempts"]) == len(attempts)
    assert sum(a["outcome"] == "failed" for a in report["attempts"]) == failure_count
    assert len({a["persona_id"] for a in report["attempts"]}) == len(attempts)
    assert report["passed"] is (failure_count < 3)
    assert report["timing"]["rejected_attempts_ms"] > 0
    if report["passed"]:
        assert report["stop_receipts"][0]["shutdown_mode"] == "forced"
        assert report["stop_receipts"][0]["identity_protected"] is True
        assert report["identities"][0]["substituted_for"] == "ops-persona-00"
    assert all(s["cleanup_completed"] for s in report["persona_substitution"]["skipped"])


@pytest.mark.parametrize("stage", ["release", "delete"])
def test_cleanup_failure_blocks_replacement_and_remains_in_receipt(tmp_path, monkeypatch, stage):
    ids = _seed(tmp_path, count=3, product="browser-core", major=153)
    attempts = fake_launches(tmp_path, monkeypatch)
    if stage == "release":
        original = ops.release_persona_claim
        def release(workspace, persona_id, *args, **kwargs):
            if persona_id == ids[0]:
                raise ContractError("synthetic release failure")
            return original(workspace, persona_id, *args, **kwargs)
        monkeypatch.setattr(ops, "release_persona_claim", release)
    else:
        def fail(*_a, **_kw): raise ContractError("synthetic delete failure")
        monkeypatch.setattr(ops, "delete_disposable_profile", fail)
    report = ops.run_profile_velocity_batch(tmp_path, count=1, ready_mode="launch",
        executable=tmp_path / "fake.exe", repository_root=tmp_path)["ops_batch"]
    assert len(attempts) == 1
    assert not report["passed"]
    assert report["errors"] and report["cleanup_failures"]
    assert report["persona_substitution"]["skipped"][0]["cleanup_completed"] is False
    assert report["cleanup_failures"][0]["persona_id"] == ids[0]


def test_realization_text_in_another_error_does_not_trigger_substitution(tmp_path, monkeypatch):
    _seed(tmp_path, count=2, product="browser-core", major=153)
    attempts = fake_launches(tmp_path, monkeypatch, error_type=ContractError)
    report = ops.run_profile_velocity_batch(tmp_path, count=1, ready_mode="launch",
        executable=tmp_path / "fake.exe", repository_root=tmp_path)["ops_batch"]
    assert len(attempts) == 1
    assert not report["passed"]
    assert not report["persona_substitution"]["skipped"]


def test_measurement_keeps_failed_attempts_and_forced_stop(tmp_path, monkeypatch):
    _seed(tmp_path, count=2, product="browser-core", major=153)
    fake_launches(tmp_path, monkeypatch)
    result = ops.run_profile_velocity_batch(tmp_path, count=1, ready_mode="launch",
        executable=tmp_path / "fake.exe", repository_root=tmp_path)
    spec = importlib.util.spec_from_file_location("review_velocity_measurement", ROOT / "scripts" / "measure_profile_velocity.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    receipt = json.loads(json.dumps(module.evidence_document(result, batch_seconds=3.0, source_sha256="a" * 64)))
    batch = receipt["result"]["ops_batch"]
    assert len(batch["attempts"]) == 2
    assert batch["attempts"][0]["outcome"] == "failed"
    assert batch["persona_substitution"]["skipped"][0]["unrealized_fields"] == ["rendering.webgl.renderer"]
    assert batch["stop_receipts"][0]["shutdown_mode"] == "forced"
    assert receipt["workload"]["competitor_comparison"] is False
    assert receipt["outside_recorded_phases_ms"] == pytest.approx(
        3000 - batch["timing"]["all_attempts_ms"] - batch["timing"]["substitution_cleanup_ms"]
        - batch["timing"]["substitution_selection_ms"]
        - batch["timing"]["failed_identity_cleanup_ms"]
        - batch["timing"]["teardown_attempts_ms"]
    )
