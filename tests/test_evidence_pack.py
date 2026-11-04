from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
from types import SimpleNamespace

import pytest

from browser_core import evidence_pack as evidence_pack_module
from browser_core.browser_facts import (
    build_browser_fact_snapshot,
    write_browser_fact_snapshot,
)
from browser_core.contracts import ContractError
from browser_core.evidence_pack import (
    _redacted_session_document,
    _session_portable_summary,
    build_evidence_pack,
    load_evidence_pack_manifest,
)
from browser_core.http2_fingerprint import http2_fingerprint_digest
from browser_core.http2_headers import (
    http2_capture_evidence_digest,
    http2_header_order_digest,
)
from browser_core.transport_fingerprint import transport_digest


@pytest.mark.skipif(os.name != "nt", reason="Windows creation time is not change time")
def test_evidence_pack_hash_rejects_same_size_edit_with_restored_mtime(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "artifact.json"
    path.write_bytes(b"AAAA")
    stamp = path.stat()
    real_fstat = evidence_pack_module.os.fstat
    calls = 0

    def mutate_after_read(descriptor: int):
        nonlocal calls
        calls += 1
        if calls == 2:
            with path.open("r+b") as writer:
                writer.write(b"BBBB")
            os.utime(path, ns=(stamp.st_atime_ns, stamp.st_mtime_ns))
        return real_fstat(descriptor)

    monkeypatch.setattr(evidence_pack_module.os, "fstat", mutate_after_read)
    # The native change time can retain one tick for a very fast edit. The
    # digest claim must still bind to the bytes left on the opened handle.
    monkeypatch.setattr(evidence_pack_module, "windows_change_time", lambda _handle: 0)
    with pytest.raises(ContractError, match="changed during read"):
        evidence_pack_module._sha256_stable_file(
            path, maximum=4, label="test artifact"
        )
    assert path.read_bytes() == b"BBBB"


@pytest.mark.skipif(os.name != "nt", reason="Windows creation time is not change time")
def test_evidence_pack_copy_rejects_same_size_source_edit_with_restored_mtime(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "source.jsonl"
    destination = tmp_path / "staged.jsonl"
    source.write_bytes(b"A" * (1024 * 1024) + b"B" * (1024 * 1024))
    stamp = source.stat()
    original_open = Path.open
    mutated = False

    class MutatingWriter:
        def __init__(self, stream):
            self.stream = stream

        def __enter__(self):
            self.stream.__enter__()
            return self

        def __exit__(self, *args):
            return self.stream.__exit__(*args)

        def __getattr__(self, name):
            return getattr(self.stream, name)

        def write(self, body):
            nonlocal mutated
            written = self.stream.write(body)
            if not mutated:
                mutated = True
                with original_open(source, "r+b") as handle:
                    handle.write(b"C" * (1024 * 1024))
                os.utime(source, ns=(stamp.st_atime_ns, stamp.st_mtime_ns))
            return written

    def mutate_open(path, mode="r", *args, **kwargs):
        stream = original_open(path, mode, *args, **kwargs)
        return MutatingWriter(stream) if path == destination and mode == "xb" else stream

    monkeypatch.setattr(Path, "open", mutate_open)
    monkeypatch.setattr(evidence_pack_module, "windows_change_time", lambda _handle: 0)
    with pytest.raises(ContractError, match="changed during copy"):
        evidence_pack_module._copy_stable_file(
            source, destination, maximum=2 * 1024 * 1024, label="trace",
        )
    assert mutated
    assert source.stat().st_mtime_ns == stamp.st_mtime_ns
    assert not destination.exists()


def _session_doc(**overrides: object) -> dict:
    base = {
        "schema": "browser-core.session/1",
        "run_id": "core-20260804T120000Z-abcdef01",
        "chromium_revision": "bf6d8a66b43635a532bdad773407285fac0121e9",
        "pid": 99,
        "state": "stopped",
        "created_at": "2026-08-04T12:00:00Z",
        "stopped_at": "2026-08-04T12:01:00Z",
        "build": {
            "provenance": "attested-browser-core",
            "executable_sha256_16": "b724ca5670da28af",
        },
        "automation": {
            "transport": "cdp",
            "cdp_endpoint": "http://127.0.0.1:9333",
        },
        "trace_mode": "off",
        "trace_categories": [],
        "trace_category_contract": "browser-core.trace-categories/2",
    }
    base.update(overrides)
    return base


def _fact(tmp_path: Path) -> Path:
    browser = {
        "ua": "Mozilla/5.0 Test",
        "platform": "Win32",
        "language": "en-US",
        "languages": ["en-US"],
        "timezone": "UTC",
        "locale": "en-US",
        "hardware_concurrency": 4,
        "screen": {
            "width": 800,
            "height": 600,
            "avail_width": 800,
            "avail_height": 600,
            "color_depth": 24,
            "pixel_depth": 24,
        },
        "window": {
            "inner_width": 800,
            "inner_height": 600,
            "outer_width": 800,
            "outer_height": 600,
            "device_pixel_ratio": 1.0,
        },
        "webgl": {
            "webgl1": {"vendor": "v", "renderer": "r"},
            "webgl2": {"vendor": "v2", "renderer": "r2"},
        },
        "automation": {"webdriver": False, "chrome_object": True},
    }
    snap = build_browser_fact_snapshot(
        snapshot_id="pack-fact",
        browser=browser,
        source_kind="fixture",
        source_label="unit",
        engine="chromium",
    )
    path = tmp_path / "fact.json"
    write_browser_fact_snapshot(path, snap)
    return path


def _session_fact(
    tmp_path: Path, *, source_overrides: dict[str, object] | None = None
) -> Path:
    session = _session_doc()
    browser = json.loads(_fact(tmp_path).read_text(encoding="utf-8"))["browser"]
    source_extra: dict[str, object] = {
        "session_run_id": session["run_id"],
        "chromium_revision": session["chromium_revision"],
        "executable_sha256_16": session["build"]["executable_sha256_16"],
        "build_provenance": session["build"]["provenance"],
    }
    source_extra.update(source_overrides or {})
    snapshot = build_browser_fact_snapshot(
        snapshot_id="session-pack-fact",
        browser=browser,
        source_kind="browser-core-session",
        source_label=f"browser-core-session:{source_extra['session_run_id']}",
        engine="browser-core",
        source_extra=source_extra,
    )
    path = tmp_path / "session-fact.json"
    write_browser_fact_snapshot(path, snapshot)
    return path


def _playwright_fact(tmp_path: Path, *, headless: bool = False) -> Path:
    browser = json.loads(_fact(tmp_path).read_text(encoding="utf-8"))["browser"]
    snapshot = build_browser_fact_snapshot(
        snapshot_id="playwright-pack-fact",
        browser=browser,
        source_kind="playwright-kernel",
        source_label="playwright:chromium",
        engine="chromium",
        source_extra={
            "headless": headless,
            "viewport_mode": "synthetic-default" if headless else "native-window",
        },
    )
    path = tmp_path / "playwright-fact.json"
    write_browser_fact_snapshot(path, snapshot)
    return path


def _trace_jsonl_bytes(
    *,
    run_id: str = "core-20260804T120000Z-abcdef01",
    category: str = "browser_core.debug",
) -> bytes:
    event = {
        "schema": "browser-core.trace-event/1",
        "run_id": run_id,
        "seq": 0,
        "ts_monotonic_ns": 1,
        "process": {"pid": 1, "type": "browser"},
        "event": {"category": "diagnostic", "name": "fixture"},
        "provenance": {"trace_category": category},
    }
    return (json.dumps(event, sort_keys=True) + "\n").encode("utf-8")


def test_portable_json_encoder_normalizes_extreme_nesting() -> None:
    deeply_nested: object = 0
    for _ in range(2_000):
        deeply_nested = [deeply_nested]

    with pytest.raises(ContractError, match="cannot encode evidence pack test"):
        evidence_pack_module._portable_json_bytes(
            deeply_nested,
            "test",
            max_bytes=1_024,
        )


def _trace_export_doc(*, jsonl: bytes | None = None, **overrides: object) -> dict:
    payload = jsonl if jsonl is not None else _trace_jsonl_bytes()
    document = {
        "schema": "browser-core.trace-export/1",
        "run_id": "core-20260804T120000Z-abcdef01",
        "chromium_revision": "bf6d8a66b43635a532bdad773407285fac0121e9",
        "source_trace": {
            "format": "perfetto-trace",
            "bytes": 123,
            "sha256": "a" * 64,
        },
        "normalized_trace": {
            "schema": "browser-core.trace-event/1",
            "bytes": len(payload),
            "sha256": hashlib.sha256(payload).hexdigest(),
            "events": 1,
            "trace_categories": {"browser_core.debug": 1},
            "category_provenance": "complete",
        },
    }
    document.update(overrides)
    return document


def _transport_fingerprint_doc() -> dict[str, object]:
    document: dict[str, object] = {
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
        "core_build": {
            "chromium_revision": "bf6d8a66b43635a532bdad773407285fac0121e9",
            "executable_sha256_16": "b724ca5670da28af",
            "runtime_bundle_sha256_16": "d785d5f4a146e84d",
        },
    }
    document["digest_sha256"] = transport_digest(document)
    return document


def _http2_fingerprint_doc() -> dict[str, object]:
    document: dict[str, object] = {
        "schema": "browser-core.http2-fingerprint/1",
        "settings": [
            {"id": 1, "value": 65_536},
            {"id": 2, "value": 0},
            {"id": 4, "value": 6_291_456},
            {"id": 6, "value": 262_144},
        ],
        "connection_window_updates": [15_663_105],
        "pre_headers_frame_types": [4, 8],
        "headers_started": True,
        "core_build": {
            "chromium_revision": "bf6d8a66b43635a532bdad773407285fac0121e9",
            "executable_sha256_16": "b724ca5670da28af",
            "runtime_bundle_sha256_16": "d785d5f4a146e84d",
        },
    }
    document["digest_sha256"] = http2_fingerprint_digest(document)
    return document


def _http2_evidence_doc() -> dict[str, object]:
    fingerprint = _http2_fingerprint_doc()
    order: dict[str, object] = {
        "schema": "browser-core.http2-header-order/1",
        "header_names": [":method", ":authority", ":scheme", ":path", "accept"],
        "pseudo_header_order": [":method", ":authority", ":scheme", ":path"],
        "non_claim": (
            "First local HTTP/2 request header-name order only; values are discarded "
            "after bounded decode and no HTTP/3 or edge acceptance is proven"
        ),
        "core_build": dict(fingerprint["core_build"]),
    }
    order["digest_sha256"] = http2_header_order_digest(order)
    evidence: dict[str, object] = {
        "schema": "browser-core.http2-capture-evidence/1",
        "fingerprint": fingerprint,
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


def test_evidence_pack_composes_session_and_fact(tmp_path: Path) -> None:
    session_path = tmp_path / "session.json"
    session_path.write_text(json.dumps(_session_doc()), encoding="utf-8")
    fact_path = _fact(tmp_path)
    out = tmp_path / "pack"
    manifest = build_evidence_pack(
        session_path=session_path,
        out_dir=out,
        browser_fact_path=fact_path,
        include_session_copy=True,
    )
    assert manifest["schema"] == "browser-core.evidence-pack/1"
    assert manifest["run_id"] == "core-20260804T120000Z-abcdef01"
    assert manifest["artifacts"]["session"]["sha256"]
    assert manifest["artifacts"]["browser_fact"]["source_kind"] == "fixture"
    assert "webre_intake_note" in manifest
    assert "EVIDENCE_GRAPH" in manifest["webre_intake_note"]
    loaded = load_evidence_pack_manifest(out / "manifest.json")
    assert loaded["run_id"] == manifest["run_id"]
    blob = json.dumps(manifest).lower()
    assert "password" not in blob
    assert "cookie" not in blob
    assert "127.0.0.1:" not in blob
    # redacted copy must strip live endpoint address
    redacted = json.loads((out / "session.redacted.json").read_text(encoding="utf-8"))
    assert redacted["automation"]["cdp_endpoint"] == "[redacted-loopback]"
    assert redacted["schema"] == "browser-core.session-redacted/1"
    assert redacted["source_schema"] == "browser-core.session/1"


@pytest.mark.parametrize("replace_manifest", [False, True])
def test_evidence_pack_rechecks_artifacts_after_directory_publication(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, replace_manifest: bool
) -> None:
    session_path = tmp_path / "session.json"
    session_path.write_text(json.dumps(_session_doc()), encoding="utf-8")
    out = tmp_path / "pack"
    original_replace = Path.replace
    competitor = b'{"status":"foreign"}'

    def mutate_at_publication(source: Path, target: Path) -> Path:
        if source.name.startswith(".pack.staging-") and Path(target) == out:
            artifact = source / "session.redacted.json"
            prior = artifact.read_bytes()
            artifact.write_bytes(b"X" + prior[1:])
        moved = original_replace(source, target)
        if source.name.startswith(".pack.staging-") and replace_manifest:
            (out / "manifest.json").rename(out / "retired-manifest.json")
            (out / "manifest.json").write_bytes(competitor)
        return moved

    monkeypatch.setattr(Path, "replace", mutate_at_publication)
    with pytest.raises(ContractError, match="publication"):
        build_evidence_pack(
            session_path=session_path, out_dir=out, include_session_copy=True
        )
    assert (out / "session.redacted.json").read_bytes().startswith(b"X")
    if replace_manifest:
        assert (out / "manifest.json").read_bytes() == competitor
        assert (out / "retired-manifest.json").exists()
    else:
        assert not (out / "manifest.json").exists()


@pytest.mark.skipif(os.name != "nt", reason="Windows directory junction boundary")
def test_evidence_pack_rejects_preexisting_parent_junction_before_staging(tmp_path: Path) -> None:
    target = tmp_path / "unrelated"
    target.mkdir()
    junction = tmp_path / "junction"
    created = subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(junction), str(target)],
        capture_output=True, check=False,
    )
    if created.returncode:
        pytest.skip("host could not create an unprivileged directory junction")
    session_path = tmp_path / "session.json"
    session_path.write_text(json.dumps(_session_doc()), encoding="utf-8")
    try:
        with pytest.raises(ContractError):
            build_evidence_pack(
                session_path=session_path, out_dir=junction / "new-parent" / "pack"
            )
        assert list(target.iterdir()) == []
    finally:
        if junction.exists():
            junction.rmdir()


@pytest.mark.skipif(os.name != "nt", reason="Windows directory junction boundary")
def test_evidence_pack_loader_rejects_preexisting_parent_junction(
    tmp_path: Path,
) -> None:
    session_path = tmp_path / "session.json"
    session_path.write_text(json.dumps(_session_doc()), encoding="utf-8")
    out = tmp_path / "pack"
    build_evidence_pack(
        session_path=session_path, out_dir=out, include_session_copy=True
    )
    junction = tmp_path / "junction"
    created = subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(junction), str(out)],
        capture_output=True, check=False,
    )
    if created.returncode:
        pytest.skip("host could not create an unprivileged directory junction")
    try:
        with pytest.raises(ContractError, match="evidence pack manifest parent"):
            load_evidence_pack_manifest(junction / "manifest.json")
    finally:
        if junction.exists():
            junction.rmdir()


@pytest.mark.skipif(os.name != "nt", reason="Windows directory junction boundary")
def test_evidence_pack_loader_rechecks_requested_parent_after_final_inventory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    session_path = tmp_path / "session.json"
    session_path.write_text(json.dumps(_session_doc()), encoding="utf-8")
    out = tmp_path / "pack"
    moved = tmp_path / "moved-pack"
    build_evidence_pack(
        session_path=session_path, out_dir=out, include_session_copy=True
    )
    probe = tmp_path / "junction-probe"
    created = subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(probe), str(out)],
        capture_output=True, check=False,
    )
    if created.returncode:
        pytest.skip("host could not create an unprivileged directory junction")
    probe.rmdir()

    original_inventory = evidence_pack_module._inventory_evidence_pack_directory
    inventories = 0
    switched = False

    def swap_after_inventory(directory: Path):
        nonlocal inventories, switched
        result = original_inventory(directory)
        if directory == out:
            inventories += 1
            if inventories == 2:
                assert out.parent == moved.parent == tmp_path
                out.rename(moved)
                linked = subprocess.run(
                    ["cmd", "/c", "mklink", "/J", str(out), str(moved)],
                    capture_output=True, check=False,
                )
                assert linked.returncode == 0
                switched = True
        return result

    monkeypatch.setattr(
        evidence_pack_module, "_inventory_evidence_pack_directory", swap_after_inventory
    )
    try:
        with pytest.raises(ContractError, match="evidence pack manifest parent"):
            load_evidence_pack_manifest(out / "manifest.json")
        assert switched
    finally:
        if switched:
            out.rmdir()
        if moved.exists():
            moved.rename(out)


@pytest.mark.skipif(os.name != "nt", reason="Windows directory junction boundary")
def test_evidence_pack_rechecks_ancestors_before_resolving_output_parent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    owned = tmp_path / "owned"
    (owned / "leaf").mkdir(parents=True)
    retired = tmp_path / "retired-owned"
    foreign = tmp_path / "foreign"
    (foreign / "leaf").mkdir(parents=True)
    session_path = tmp_path / "session.json"
    session_path.write_text(json.dumps(_session_doc()), encoding="utf-8")
    probe = tmp_path / "junction-probe"
    created = subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(probe), str(foreign)],
        capture_output=True, check=False,
    )
    if created.returncode:
        pytest.skip("host could not create an unprivileged directory junction")
    probe.rmdir()

    original_prepare = evidence_pack_module.prepare_owned_directory_parent

    def redirect_after_prepare(parent: Path, *, label: str) -> None:
        original_prepare(parent, label=label)
        owned.rename(retired)
        redirect = subprocess.run(
            ["cmd", "/c", "mklink", "/J", str(owned), str(foreign)],
            capture_output=True, check=False,
        )
        assert redirect.returncode == 0, redirect.stderr

    attempted_staging: list[Path] = []

    def observe_staging(*_args, **kwargs):
        attempted_staging.append(Path(kwargs["dir"]))
        raise ContractError("staging reached redirected parent")

    monkeypatch.setattr(evidence_pack_module, "prepare_owned_directory_parent", redirect_after_prepare)
    monkeypatch.setattr(evidence_pack_module.tempfile, "mkdtemp", observe_staging)
    try:
        with pytest.raises(ContractError):
            build_evidence_pack(session_path=session_path, out_dir=owned / "leaf" / "pack")
        assert attempted_staging == []
        assert list((foreign / "leaf").iterdir()) == []
    finally:
        if owned.exists():
            owned.rmdir()


@pytest.mark.skipif(os.name != "nt", reason="Windows directory junction boundary")
def test_evidence_pack_rejects_transient_parent_junction_during_resolve(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    owned = tmp_path / "owned"
    output_parent = owned / "leaf"
    output_parent.mkdir(parents=True)
    retired = tmp_path / "retired-owned"
    foreign = tmp_path / "foreign"
    (foreign / "leaf").mkdir(parents=True)
    session_path = tmp_path / "session.json"
    session_path.write_text(json.dumps(_session_doc()), encoding="utf-8")
    probe = tmp_path / "junction-probe"
    created = subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(probe), str(foreign)],
        capture_output=True, check=False,
    )
    if created.returncode:
        pytest.skip("host could not create an unprivileged directory junction")
    probe.rmdir()

    original_resolve = Path.resolve

    def resolve_during_switch(path: Path, *args, **kwargs) -> Path:
        if path not in {output_parent, output_parent / "pack"}:
            return original_resolve(path, *args, **kwargs)
        owned.rename(retired)
        redirect = subprocess.run(
            ["cmd", "/c", "mklink", "/J", str(owned), str(foreign)],
            capture_output=True, check=False,
        )
        assert redirect.returncode == 0, redirect.stderr
        try:
            return original_resolve(path, *args, **kwargs)
        finally:
            owned.rmdir()
            retired.rename(owned)

    attempted_staging: list[Path] = []

    def observe_staging(*_args, **kwargs):
        attempted_staging.append(Path(kwargs["dir"]))
        raise ContractError("staging reached redirected parent")

    monkeypatch.setattr(Path, "resolve", resolve_during_switch)
    monkeypatch.setattr(evidence_pack_module.tempfile, "mkdtemp", observe_staging)
    with pytest.raises(ContractError):
        build_evidence_pack(session_path=session_path, out_dir=output_parent / "pack")
    assert attempted_staging == []
    assert list((foreign / "leaf").iterdir()) == []


@pytest.mark.skipif(os.name != "nt", reason="Windows directory junction boundary")
def test_evidence_pack_rejects_junction_output_without_replacing_target(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    junction = tmp_path / "junction"
    created = subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(junction), str(target)],
        capture_output=True, check=False,
    )
    if created.returncode:
        pytest.skip("host could not create an unprivileged directory junction")
    try:
        assert not junction.is_symlink() and junction.resolve() == target
        session_path = tmp_path / "session.json"
        session_path.write_text(json.dumps(_session_doc()), encoding="utf-8")
        with pytest.raises(ContractError, match="reparse|junction|symlink"):
            build_evidence_pack(session_path=session_path, out_dir=junction)
        assert target.is_dir() and list(target.iterdir()) == []
    finally:
        junction.rmdir()


@pytest.mark.skipif(os.name != "nt", reason="Windows directory junction boundary")
def test_evidence_pack_rejects_junction_inserted_before_output_resolution(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = tmp_path / "target"
    target.mkdir()
    junction = tmp_path / "junction"
    session_path = tmp_path / "session.json"
    session_path.write_text(json.dumps(_session_doc()), encoding="utf-8")
    original_resolve = Path.resolve

    def resolve_after_swap(path: Path, *args, **kwargs):
        if path == junction:
            created = subprocess.run(
                ["cmd", "/c", "mklink", "/J", str(junction), str(target)],
                capture_output=True, check=False,
            )
            if created.returncode:
                pytest.skip("host could not create an unprivileged directory junction")
        return original_resolve(path, *args, **kwargs)

    monkeypatch.setattr(Path, "resolve", resolve_after_swap)
    try:
        with pytest.raises(ContractError, match="output directory.*reparse|junction|symlink"):
            build_evidence_pack(session_path=session_path, out_dir=junction)
        assert target.is_dir() and list(target.iterdir()) == []
    finally:
        if junction.exists():
            junction.rmdir()


@pytest.mark.skipif(os.name != "nt", reason="Windows directory junction boundary")
def test_evidence_pack_staging_swap_cannot_write_into_junction_target(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = tmp_path / "unrelated"
    target.mkdir()
    session_path = tmp_path / "session.json"
    session_path.write_text(json.dumps(_session_doc()), encoding="utf-8")
    original_build = evidence_pack_module._build_evidence_pack_contents
    swapped: list[Path] = []

    def build_after_swap(**kwargs):
        staging = kwargs["out_dir"]
        assert staging.parent == tmp_path and staging.name.startswith(".pack.staging-")
        staging.rmdir()
        created = subprocess.run(
            ["cmd", "/c", "mklink", "/J", str(staging), str(target)],
            capture_output=True, check=False,
        )
        if created.returncode:
            pytest.skip("host could not create an unprivileged directory junction")
        swapped.append(staging)
        return original_build(**kwargs)

    monkeypatch.setattr(evidence_pack_module, "_build_evidence_pack_contents", build_after_swap)
    try:
        with pytest.raises(ContractError):
            build_evidence_pack(session_path=session_path, out_dir=tmp_path / "pack")
        assert list(target.iterdir()) == []
    finally:
        if swapped and swapped[0].exists():
            swapped[0].rmdir()


@pytest.mark.skipif(os.name != "nt", reason="Windows directory junction boundary")
def test_evidence_pack_copy_cleanup_preserves_file_behind_ancestor_junction(
    tmp_path: Path,
) -> None:
    outer = tmp_path / "owned"
    inner = outer / "inner"
    inner.mkdir(parents=True)
    destination = inner / "artifact.json"
    destination.write_bytes(b"owned-copy")
    expected_identity = evidence_pack_module._file_identity(os.lstat(destination))
    parent_ancestry = evidence_pack_module.directory_ancestry_binding(
        inner, label="evidence pack copy parent"
    )
    foreign = tmp_path / "foreign"
    outer.rename(foreign)
    created = subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(outer), str(foreign)],
        check=False, capture_output=True, text=True,
    )
    if created.returncode:
        pytest.skip("host could not create an unprivileged directory junction")
    try:
        assert evidence_pack_module._cleanup_copied_file(
            destination,
            expected_identity=expected_identity,
            expected_parent_ancestry=parent_ancestry,
        ) is False
        assert (foreign / "inner" / destination.name).read_bytes() == b"owned-copy"
    finally:
        if outer.exists():
            outer.rmdir()


def test_evidence_pack_copy_preserves_file_after_parent_ancestor_relocation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "source.jsonl"
    source.write_bytes(b"owned source")
    private = tmp_path / "private"
    parent = private / "leaf"
    parent.mkdir(parents=True)
    destination = parent / "staged.jsonl"
    retained = tmp_path / "retained"
    original_lstat = evidence_pack_module.os.lstat
    swapped = False

    def relocate_before_final_copy_read(path, *args, **kwargs):
        nonlocal swapped
        if path == destination and not swapped:
            private.rename(retained)
            private.mkdir()
            (retained / "leaf").rename(parent)
            swapped = True
        return original_lstat(path, *args, **kwargs)

    monkeypatch.setattr(evidence_pack_module.os, "lstat", relocate_before_final_copy_read)
    try:
        with pytest.raises(ContractError, match="staged artifact cleanup failed"):
            evidence_pack_module._copy_stable_file(
                source, destination, maximum=1024, label="trace",
            )
        assert swapped
        assert destination.read_bytes() == b"owned source"
    finally:
        if swapped:
            parent.rename(retained / "leaf")
            private.rmdir()
            retained.rename(private)


@pytest.mark.skipif(os.name != "nt", reason="Windows directory junction boundary")
def test_evidence_pack_copy_rejects_preexisting_ancestor_junction_before_write(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source.jsonl"
    source.write_bytes(b"owned source")
    outer = tmp_path / "owned"
    inner = outer / "inner"
    inner.mkdir(parents=True)
    destination = inner / "staged.jsonl"
    foreign = tmp_path / "foreign"
    outer.rename(foreign)
    created = subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(outer), str(foreign)],
        check=False, capture_output=True, text=True,
    )
    if created.returncode:
        pytest.skip("host could not create an unprivileged directory junction")
    try:
        with pytest.raises(ContractError):
            evidence_pack_module._copy_stable_file(
                source, destination, maximum=1024, label="trace"
            )
        assert list((foreign / "inner").iterdir()) == []
    finally:
        if outer.exists():
            outer.rmdir()


@pytest.mark.skipif(os.name != "nt", reason="Windows directory junction boundary")
@pytest.mark.parametrize("swap_timing", ["before-helper", "after-session-read"])
def test_evidence_pack_parent_swap_cannot_write_into_junction_target(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, swap_timing: str,
) -> None:
    target = tmp_path / "unrelated"
    target.mkdir()
    parent = tmp_path / "output-parent"
    retired = tmp_path / "retired-output-parent"
    session_path = tmp_path / "session.json"
    session_path.write_text(json.dumps(_session_doc()), encoding="utf-8")
    original_build = evidence_pack_module._build_evidence_pack_contents
    original_load = evidence_pack_module.load_session_snapshot
    target_staging: list[Path] = []

    def swap_parent(staging: Path) -> None:
        assert staging.parent == parent
        outside_staging = target / staging.name
        outside_staging.mkdir()
        target_staging.append(outside_staging)
        safe_root = tmp_path.resolve()
        assert parent.resolve().is_relative_to(safe_root)
        assert retired.resolve(strict=False).is_relative_to(safe_root)
        parent.rename(retired)
        created = subprocess.run(
            ["cmd", "/c", "mklink", "/J", str(parent), str(target)],
            capture_output=True, check=False,
        )
        if created.returncode:
            retired.rename(parent)
            pytest.skip("host could not create an unprivileged directory junction")

    def load_then_swap(path):
        result = original_load(path)
        swap_parent(target_staging_path[0])
        return result

    target_staging_path: list[Path] = []
    def build_after_parent_swap(**kwargs):
        staging = kwargs["out_dir"]
        target_staging_path.append(staging)
        if swap_timing == "before-helper":
            swap_parent(staging)
        else:
            monkeypatch.setattr(evidence_pack_module, "load_session_snapshot", load_then_swap)
        return original_build(**kwargs)

    monkeypatch.setattr(evidence_pack_module, "_build_evidence_pack_contents", build_after_parent_swap)
    try:
        with pytest.raises(ContractError):
            build_evidence_pack(session_path=session_path, out_dir=parent / "pack")
        assert target_staging and list(target_staging[0].iterdir()) == []
    finally:
        if parent.exists() and parent.resolve() == target:
            parent.rmdir()
        if retired.exists():
            safe_root = tmp_path.resolve()
            assert retired.resolve().is_relative_to(safe_root)
            assert parent.resolve(strict=False).is_relative_to(safe_root)
            retired.rename(parent)


def test_evidence_pack_binds_browser_core_session_fact(tmp_path: Path) -> None:
    session_path = tmp_path / "session.json"
    session_path.write_text(json.dumps(_session_doc()), encoding="utf-8")
    out = tmp_path / "pack"
    manifest = build_evidence_pack(
        session_path=session_path,
        out_dir=out,
        browser_fact_path=_session_fact(tmp_path),
    )

    packed = json.loads((out / "browser-fact.json").read_text(encoding="utf-8"))
    assert manifest["artifacts"]["browser_fact"]["source_kind"] == (
        "browser-core-session"
    )
    assert packed["source"]["session_run_id"] == _session_doc()["run_id"]
    assert packed["source"]["chromium_revision"] == _session_doc()[
        "chromium_revision"
    ]
    assert packed["source"]["executable_sha256_16"] == (
        _session_doc()["build"]["executable_sha256_16"]
    )
    load_evidence_pack_manifest(out / "manifest.json")


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("session_run_id", "core-20260817T000000Z-foreign"),
        ("chromium_revision", "c" * 40),
        ("executable_sha256_16", "d" * 16),
    ],
)
def test_evidence_pack_rejects_browser_fact_from_another_session(
    tmp_path: Path,
    field: str,
    replacement: str,
) -> None:
    session_path = tmp_path / "session.json"
    session_path.write_text(json.dumps(_session_doc()), encoding="utf-8")
    fact_path = _session_fact(
        tmp_path,
        source_overrides={field: replacement},
    )

    with pytest.raises(ContractError, match="browser fact session provenance"):
        build_evidence_pack(
            session_path=session_path,
            out_dir=tmp_path / "pack",
            browser_fact_path=fact_path,
        )


def test_evidence_pack_binds_an_attested_transport_fingerprint(
    tmp_path: Path,
) -> None:
    session = _session_doc()
    session["build"] = {
        **session["build"],
        "runtime_bundle_sha256_16": "d785d5f4a146e84d",
    }
    session_path = tmp_path / "session.json"
    session_path.write_text(json.dumps(session), encoding="utf-8")
    transport = _transport_fingerprint_doc()
    source = tmp_path / "transport.json"
    source.write_text(json.dumps(transport), encoding="utf-8")

    manifest = build_evidence_pack(
        session_path=session_path,
        out_dir=tmp_path / "pack",
        transport_fingerprint_path=source,
    )

    entry = manifest["artifacts"]["transport_fingerprint"]
    packed = json.loads(
        (tmp_path / "pack" / "transport-fingerprint.json").read_text(
            encoding="utf-8"
        )
    )
    assert packed == transport
    assert entry["summary"] == {
        "schema": "browser-core.transport-fingerprint/1",
        "digest_sha256": transport["digest_sha256"],
        "grease_present": False,
        "core_build": transport["core_build"],
    }
    assert entry["session_binding"] == {
        "status": "matched",
        "fields": [
            "chromium_revision",
            "executable_sha256_16",
            "runtime_bundle_sha256_16",
        ],
    }
    assert (
        manifest["artifacts"]["session"]["summary"][
            "runtime_bundle_sha256_16"
        ]
        == "d785d5f4a146e84d"
    )
    assert load_evidence_pack_manifest(tmp_path / "pack" / "manifest.json") == manifest


def test_evidence_pack_binds_an_attested_http2_fingerprint(tmp_path: Path) -> None:
    session = _session_doc()
    session["build"] = {
        **session["build"],
        "runtime_bundle_sha256_16": "d785d5f4a146e84d",
    }
    session_path = tmp_path / "session.json"
    session_path.write_text(json.dumps(session), encoding="utf-8")
    http2 = _http2_fingerprint_doc()
    source = tmp_path / "http2.json"
    source.write_text(json.dumps(http2), encoding="utf-8")

    manifest = build_evidence_pack(
        session_path=session_path,
        out_dir=tmp_path / "pack",
        http2_fingerprint_path=source,
    )

    entry = manifest["artifacts"]["http2_fingerprint"]
    assert json.loads(
        (tmp_path / "pack" / "http2-fingerprint.json").read_text(encoding="utf-8")
    ) == http2
    assert entry["summary"] == {
        "schema": "browser-core.http2-fingerprint/1",
        "digest_sha256": http2["digest_sha256"],
        "headers_started": True,
        "core_build": http2["core_build"],
    }
    assert load_evidence_pack_manifest(tmp_path / "pack" / "manifest.json") == manifest


def test_evidence_pack_binds_same_connection_http2_evidence(tmp_path: Path) -> None:
    session = _session_doc()
    session["build"] = {
        **session["build"],
        "runtime_bundle_sha256_16": "d785d5f4a146e84d",
    }
    session_path = tmp_path / "session.json"
    session_path.write_text(json.dumps(session), encoding="utf-8")
    evidence = _http2_evidence_doc()
    source = tmp_path / "http2-evidence.json"
    source.write_text(json.dumps(evidence), encoding="utf-8")

    manifest = build_evidence_pack(
        session_path=session_path,
        out_dir=tmp_path / "pack",
        http2_evidence_path=source,
    )

    entry = manifest["artifacts"]["http2_evidence"]
    assert json.loads(
        (tmp_path / "pack" / "http2-evidence.json").read_text(encoding="utf-8")
    ) == evidence
    assert entry["summary"] == {
        "schema": "browser-core.http2-capture-evidence/1",
        "digest_sha256": evidence["digest_sha256"],
        "fingerprint_digest_sha256": evidence["fingerprint"]["digest_sha256"],
        "header_order_digest_sha256": evidence["header_order"]["digest_sha256"],
        "header_name_count": 5,
        "pseudo_header_order": [":method", ":authority", ":scheme", ":path"],
        "same_connection": True,
        "core_build": evidence["fingerprint"]["core_build"],
    }
    assert entry["session_binding"]["status"] == "matched"
    assert load_evidence_pack_manifest(tmp_path / "pack" / "manifest.json") == manifest


@pytest.mark.parametrize(
    ("artifact_key", "source_arg", "source_name", "document_factory", "summary_field"),
    [
        (
            "transport_fingerprint",
            "transport_fingerprint_path",
            "transport.json",
            _transport_fingerprint_doc,
            "grease_present",
        ),
        (
            "http2_fingerprint",
            "http2_fingerprint_path",
            "http2.json",
            _http2_fingerprint_doc,
            "headers_started",
        ),
        (
            "http2_evidence",
            "http2_evidence_path",
            "http2-evidence.json",
            _http2_evidence_doc,
            "same_connection",
        ),
    ],
)
def test_evidence_pack_loader_rejects_manifest_boolean_summary_as_number(
    tmp_path: Path,
    artifact_key: str,
    source_arg: str,
    source_name: str,
    document_factory: object,
    summary_field: str,
) -> None:
    session = _session_doc()
    session["build"] = {
        **session["build"],
        "runtime_bundle_sha256_16": "d785d5f4a146e84d",
    }
    session_path = tmp_path / "session.json"
    session_path.write_text(json.dumps(session), encoding="utf-8")
    source = tmp_path / source_name
    source.write_text(json.dumps(document_factory()), encoding="utf-8")
    out = tmp_path / "pack"
    build_evidence_pack(session_path=session_path, out_dir=out, **{source_arg: source})
    manifest_path = out / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    summary = manifest["artifacts"][artifact_key]["summary"]
    assert type(summary[summary_field]) is bool
    summary[summary_field] = int(summary[summary_field])
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(ContractError, match="summary does not match the bound JSON"):
        load_evidence_pack_manifest(manifest_path)


def test_evidence_pack_rejects_http2_evidence_from_another_runtime(
    tmp_path: Path,
) -> None:
    session = _session_doc()
    session["build"] = {
        **session["build"],
        "runtime_bundle_sha256_16": "d785d5f4a146e84d",
    }
    session_path = tmp_path / "session.json"
    session_path.write_text(json.dumps(session), encoding="utf-8")
    evidence = _http2_evidence_doc()
    for child in (evidence["fingerprint"], evidence["header_order"]):
        child["core_build"] = {
            **child["core_build"],
            "runtime_bundle_sha256_16": "e" * 16,
        }
    source = tmp_path / "http2-evidence.json"
    source.write_text(json.dumps(evidence), encoding="utf-8")

    with pytest.raises(ContractError, match="does not match the session"):
        build_evidence_pack(
            session_path=session_path,
            out_dir=tmp_path / "pack",
            http2_evidence_path=source,
        )
    assert not (tmp_path / "pack").exists()


def test_evidence_pack_loader_recomputes_http2_evidence_summary(
    tmp_path: Path,
) -> None:
    session = _session_doc()
    session["build"] = {
        **session["build"],
        "runtime_bundle_sha256_16": "d785d5f4a146e84d",
    }
    session_path = tmp_path / "session.json"
    session_path.write_text(json.dumps(session), encoding="utf-8")
    source = tmp_path / "http2-evidence.json"
    source.write_text(json.dumps(_http2_evidence_doc()), encoding="utf-8")
    out = tmp_path / "pack"
    build_evidence_pack(
        session_path=session_path,
        out_dir=out,
        http2_evidence_path=source,
    )
    manifest_path = out / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["artifacts"]["http2_evidence"]["summary"]["header_name_count"] = 999
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(ContractError, match="HTTP/2 evidence summary"):
        load_evidence_pack_manifest(manifest_path)


def test_evidence_pack_rejects_contradictory_h2_artifacts(tmp_path: Path) -> None:
    session = _session_doc()
    session["build"] = {
        **session["build"],
        "runtime_bundle_sha256_16": "d785d5f4a146e84d",
    }
    session_path = tmp_path / "session.json"
    session_path.write_text(json.dumps(session), encoding="utf-8")
    standalone = _http2_fingerprint_doc()
    evidence = _http2_evidence_doc()
    evidence["fingerprint"]["settings"][0]["value"] = 65_535
    evidence["fingerprint"]["digest_sha256"] = http2_fingerprint_digest(
        evidence["fingerprint"]
    )
    evidence["digest_sha256"] = http2_capture_evidence_digest(evidence)
    standalone_path = tmp_path / "http2.json"
    evidence_path = tmp_path / "http2-evidence.json"
    standalone_path.write_text(json.dumps(standalone), encoding="utf-8")
    evidence_path.write_text(json.dumps(evidence), encoding="utf-8")

    with pytest.raises(ContractError, match="does not match standalone"):
        build_evidence_pack(
            session_path=session_path,
            out_dir=tmp_path / "pack",
            http2_fingerprint_path=standalone_path,
            http2_evidence_path=evidence_path,
        )
    assert not (tmp_path / "pack").exists()


def test_evidence_pack_accepts_matching_legacy_and_extended_h2(tmp_path: Path) -> None:
    session = _session_doc()
    session["build"] = {
        **session["build"],
        "runtime_bundle_sha256_16": "d785d5f4a146e84d",
    }
    session_path = tmp_path / "session.json"
    session_path.write_text(json.dumps(session), encoding="utf-8")
    evidence = _http2_evidence_doc()
    standalone_path = tmp_path / "http2.json"
    evidence_path = tmp_path / "http2-evidence.json"
    standalone_path.write_text(
        json.dumps(evidence["fingerprint"]),
        encoding="utf-8",
    )
    evidence_path.write_text(json.dumps(evidence), encoding="utf-8")

    manifest = build_evidence_pack(
        session_path=session_path,
        out_dir=tmp_path / "pack",
        http2_fingerprint_path=standalone_path,
        http2_evidence_path=evidence_path,
    )
    assert {"http2_fingerprint", "http2_evidence"} <= set(manifest["artifacts"])
    assert load_evidence_pack_manifest(tmp_path / "pack" / "manifest.json") == manifest


def test_evidence_pack_loader_rejects_self_consistent_contradictory_h2(
    tmp_path: Path,
) -> None:
    session = _session_doc()
    session["build"] = {
        **session["build"],
        "runtime_bundle_sha256_16": "d785d5f4a146e84d",
    }
    session_path = tmp_path / "session.json"
    session_path.write_text(json.dumps(session), encoding="utf-8")
    evidence = _http2_evidence_doc()
    standalone_path = tmp_path / "http2.json"
    evidence_path = tmp_path / "http2-evidence.json"
    standalone_path.write_text(json.dumps(evidence["fingerprint"]), encoding="utf-8")
    evidence_path.write_text(json.dumps(evidence), encoding="utf-8")
    out = tmp_path / "pack"
    build_evidence_pack(
        session_path=session_path,
        out_dir=out,
        http2_fingerprint_path=standalone_path,
        http2_evidence_path=evidence_path,
    )

    packed_path = out / "http2-evidence.json"
    packed = json.loads(packed_path.read_text(encoding="utf-8"))
    packed["fingerprint"]["settings"][0]["value"] = 65_535
    packed["fingerprint"]["digest_sha256"] = http2_fingerprint_digest(
        packed["fingerprint"]
    )
    packed["digest_sha256"] = http2_capture_evidence_digest(packed)
    body = json.dumps(packed, sort_keys=True).encode("utf-8")
    packed_path.write_bytes(body)
    manifest_path = out / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    entry = manifest["artifacts"]["http2_evidence"]
    entry["sha256"] = hashlib.sha256(body).hexdigest()
    entry["bytes"] = len(body)
    entry["summary"] = evidence_pack_module._portable_http2_evidence_summary(
        packed
    )
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(ContractError, match="does not match standalone"):
        load_evidence_pack_manifest(manifest_path)


def test_evidence_pack_rejects_http2_from_another_runtime(tmp_path: Path) -> None:
    session = _session_doc()
    session["build"] = {
        **session["build"],
        "runtime_bundle_sha256_16": "d785d5f4a146e84d",
    }
    session_path = tmp_path / "session.json"
    session_path.write_text(json.dumps(session), encoding="utf-8")
    http2 = _http2_fingerprint_doc()
    http2["core_build"] = {
        **http2["core_build"],
        "runtime_bundle_sha256_16": "e" * 16,
    }
    source = tmp_path / "http2.json"
    source.write_text(json.dumps(http2), encoding="utf-8")

    with pytest.raises(ContractError, match="does not match the session"):
        build_evidence_pack(
            session_path=session_path,
            out_dir=tmp_path / "pack",
            http2_fingerprint_path=source,
        )
    assert not (tmp_path / "pack").exists()


def test_evidence_pack_loader_recomputes_the_http2_summary(tmp_path: Path) -> None:
    session = _session_doc()
    session["build"] = {
        **session["build"],
        "runtime_bundle_sha256_16": "d785d5f4a146e84d",
    }
    session_path = tmp_path / "session.json"
    session_path.write_text(json.dumps(session), encoding="utf-8")
    source = tmp_path / "http2.json"
    source.write_text(json.dumps(_http2_fingerprint_doc()), encoding="utf-8")
    out = tmp_path / "pack"
    build_evidence_pack(
        session_path=session_path,
        out_dir=out,
        http2_fingerprint_path=source,
    )
    manifest_path = out / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["artifacts"]["http2_fingerprint"]["summary"][
        "headers_started"
    ] = False
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(ContractError, match="HTTP/2 summary"):
        load_evidence_pack_manifest(manifest_path)


def test_evidence_pack_rejects_transport_from_another_runtime(
    tmp_path: Path,
) -> None:
    session = _session_doc()
    session["build"] = {
        **session["build"],
        "runtime_bundle_sha256_16": "d785d5f4a146e84d",
    }
    session_path = tmp_path / "session.json"
    session_path.write_text(json.dumps(session), encoding="utf-8")
    transport = _transport_fingerprint_doc()
    transport["core_build"] = {
        **transport["core_build"],
        "runtime_bundle_sha256_16": "e" * 16,
    }
    source = tmp_path / "transport.json"
    source.write_text(json.dumps(transport), encoding="utf-8")

    with pytest.raises(ContractError, match="does not match the session"):
        build_evidence_pack(
            session_path=session_path,
            out_dir=tmp_path / "pack",
            transport_fingerprint_path=source,
        )
    assert not (tmp_path / "pack").exists()


def test_evidence_pack_loader_recomputes_the_transport_summary(
    tmp_path: Path,
) -> None:
    session = _session_doc()
    session["build"] = {
        **session["build"],
        "runtime_bundle_sha256_16": "d785d5f4a146e84d",
    }
    session_path = tmp_path / "session.json"
    session_path.write_text(json.dumps(session), encoding="utf-8")
    source = tmp_path / "transport.json"
    source.write_text(json.dumps(_transport_fingerprint_doc()), encoding="utf-8")
    out = tmp_path / "pack"
    build_evidence_pack(
        session_path=session_path,
        out_dir=out,
        transport_fingerprint_path=source,
    )
    manifest_path = out / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["artifacts"]["transport_fingerprint"]["summary"][
        "grease_present"
    ] = True
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(ContractError, match="transport summary"):
        load_evidence_pack_manifest(manifest_path)


def test_evidence_pack_projects_operator_browser_fact_labels_and_notes(
    tmp_path: Path,
) -> None:
    session_path = tmp_path / "session.json"
    session_path.write_text(json.dumps(_session_doc()), encoding="utf-8")
    source_fact = build_browser_fact_snapshot(
        snapshot_id="private-customer-snapshot",
        browser=json.loads(_fact(tmp_path).read_text(encoding="utf-8"))["browser"],
        source_kind="fixture",
        source_label="private-customer-label",
        engine="chromium",
        notes=r"C:\private\customer\profile",
    )
    fact_path = tmp_path / "private-fact.json"
    write_browser_fact_snapshot(fact_path, source_fact)
    source_body = fact_path.read_bytes()

    manifest = build_evidence_pack(
        session_path=session_path,
        out_dir=tmp_path / "pack",
        browser_fact_path=fact_path,
    )

    packed = json.loads(
        (tmp_path / "pack" / "browser-fact.json").read_text(encoding="utf-8")
    )
    entry = manifest["artifacts"]["browser_fact"]
    rendered = json.dumps({"manifest": manifest, "fact": packed})
    assert packed["snapshot_id"].startswith("portable-")
    assert packed["source"]["label"] == "evidence-pack:fixture"
    assert "notes" not in packed
    assert entry["source_integrity_sha256"] == source_fact["integrity_sha256"]
    assert entry["source_sha256"] == hashlib.sha256(source_body).hexdigest()
    assert entry["source_bytes"] == len(source_body)
    assert "private-customer" not in rendered
    assert r"C:\\private" not in rendered
    load_evidence_pack_manifest(tmp_path / "pack" / "manifest.json")


def test_evidence_pack_retains_playwright_capture_method(tmp_path: Path) -> None:
    session_path = tmp_path / "session.json"
    session_path.write_text(json.dumps(_session_doc()), encoding="utf-8")
    out = tmp_path / "pack"

    manifest = build_evidence_pack(
        session_path=session_path,
        out_dir=out,
        browser_fact_path=_playwright_fact(tmp_path),
    )

    packed = json.loads((out / "browser-fact.json").read_text(encoding="utf-8"))
    assert packed["source"]["headless"] is False
    assert packed["source"]["viewport_mode"] == "native-window"
    assert manifest["artifacts"]["browser_fact"]["capture_method"] == {
        "headless": False,
        "viewport_mode": "native-window",
    }
    load_evidence_pack_manifest(out / "manifest.json")


def test_evidence_pack_loader_rechecks_playwright_capture_method(
    tmp_path: Path,
) -> None:
    session_path = tmp_path / "session.json"
    session_path.write_text(json.dumps(_session_doc()), encoding="utf-8")
    out = tmp_path / "pack"
    build_evidence_pack(
        session_path=session_path,
        out_dir=out,
        browser_fact_path=_playwright_fact(tmp_path),
    )

    artifact_path = out / "browser-fact.json"
    fact = json.loads(artifact_path.read_text(encoding="utf-8"))
    forged_source = dict(fact["source"])
    forged_source["headless"] = True
    forged_source["viewport_mode"] = "synthetic-default"
    forged = build_browser_fact_snapshot(
        snapshot_id=fact["snapshot_id"],
        browser=fact["browser"],
        source_kind="playwright-kernel",
        source_label=forged_source.pop("label"),
        engine="chromium",
        captured_at=fact["captured_at"],
        source_extra={
            key: value for key, value in forged_source.items() if key != "kind"
        },
    )
    artifact_body = (
        json.dumps(forged, indent=2, sort_keys=True, allow_nan=False) + "\n"
    ).encode("utf-8")
    artifact_path.write_bytes(artifact_body)

    manifest_path = out / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    entry = manifest["artifacts"]["browser_fact"]
    entry["integrity_sha256"] = forged["integrity_sha256"]
    entry["sha256"] = hashlib.sha256(artifact_body).hexdigest()
    entry["bytes"] = len(artifact_body)
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(ContractError, match="browser fact capture method"):
        load_evidence_pack_manifest(manifest_path)


def test_evidence_pack_builder_binds_session_digest_to_validated_snapshot(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    session_path = tmp_path / "session.json"
    session_path.write_text(json.dumps(_session_doc()), encoding="utf-8")
    original_body = session_path.read_bytes()
    original_loader = evidence_pack_module.load_session_snapshot

    def _load_then_mutate(path: Path):
        snapshot = original_loader(path)
        session_path.write_text(json.dumps(_session_doc(pid=101)), encoding="utf-8")
        return snapshot

    monkeypatch.setattr(
        evidence_pack_module, "load_session_snapshot", _load_then_mutate
    )

    manifest = build_evidence_pack(
        session_path=session_path,
        out_dir=tmp_path / "pack",
    )

    assert (
        manifest["artifacts"]["session"]["sha256"]
        == hashlib.sha256(original_body).hexdigest()
    )
    assert manifest["artifacts"]["session"]["bytes"] == len(original_body)
    assert (
        manifest["artifacts"]["session"]["summary"]["run_id"]
        == _session_doc()["run_id"]
    )


def test_evidence_pack_builder_bounds_browser_fact_source(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    session_path = tmp_path / "session.json"
    session_path.write_text(json.dumps(_session_doc()), encoding="utf-8")
    fact_path = _fact(tmp_path)
    monkeypatch.setattr(
        evidence_pack_module,
        "MAX_EVIDENCE_PACK_BROWSER_FACT_SOURCE_BYTES",
        len(fact_path.read_bytes()) - 1,
    )

    with pytest.raises(ContractError, match="browser fact source exceeds"):
        build_evidence_pack(
            session_path=session_path,
            out_dir=tmp_path / "pack",
            browser_fact_path=fact_path,
        )


def test_evidence_pack_builder_bounds_trace_export_source(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    session_path = tmp_path / "session.json"
    session_path.write_text(json.dumps(_session_doc()), encoding="utf-8")
    report_path = tmp_path / "trace-export.json"
    report_path.write_text(json.dumps(_trace_export_doc()), encoding="utf-8")
    monkeypatch.setattr(
        evidence_pack_module,
        "MAX_EVIDENCE_PACK_TRACE_EXPORT_SOURCE_BYTES",
        len(report_path.read_bytes()) - 1,
    )

    with pytest.raises(ContractError, match="trace export source exceeds"):
        build_evidence_pack(
            session_path=session_path,
            out_dir=tmp_path / "pack",
            trace_export_path=report_path,
        )


def test_evidence_pack_loader_rejects_tampered_artifacts(tmp_path: Path) -> None:
    session_path = tmp_path / "session.json"
    session_path.write_text(json.dumps(_session_doc()), encoding="utf-8")
    fact_path = _fact(tmp_path)
    out = tmp_path / "pack"
    build_evidence_pack(
        session_path=session_path,
        out_dir=out,
        browser_fact_path=fact_path,
    )
    (out / "browser-fact.json").write_text("tampered", encoding="utf-8")

    with pytest.raises(ContractError, match="digest binding failed"):
        load_evidence_pack_manifest(out / "manifest.json")


def test_evidence_pack_loader_revalidates_trace_after_consistent_rehash(
    tmp_path: Path,
) -> None:
    session_path = tmp_path / "session.json"
    session_path.write_text(json.dumps(_session_doc()), encoding="utf-8")
    trace_path = tmp_path / "trace.jsonl"
    trace_path.write_bytes(_trace_jsonl_bytes())
    out = tmp_path / "pack"
    build_evidence_pack(
        session_path=session_path,
        out_dir=out,
        trace_jsonl_path=trace_path,
    )
    bad_trace = b'{"schema":"private"}\n'
    (out / "trace.jsonl").write_bytes(bad_trace)
    manifest_path = out / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    entry = manifest["artifacts"]["trace_jsonl"]
    entry["bytes"] = len(bad_trace)
    entry["sha256"] = hashlib.sha256(bad_trace).hexdigest()
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(ContractError, match="unsupported trace schema"):
        load_evidence_pack_manifest(manifest_path)


def test_evidence_pack_builder_validates_the_staged_trace_snapshot(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    session_path = tmp_path / "session.json"
    session_path.write_text(json.dumps(_session_doc()), encoding="utf-8")
    trace_path = tmp_path / "trace.jsonl"
    original = _trace_jsonl_bytes()
    trace_path.write_bytes(original)
    out = tmp_path / "pack"
    original_validate = evidence_pack_module.validate_trace

    def _validate_then_mutate_source(path: Path) -> dict:
        result = original_validate(path)
        trace_path.write_bytes(b'{"schema":"changed-after-validation"}\n')
        return result

    monkeypatch.setattr(
        evidence_pack_module, "validate_trace", _validate_then_mutate_source
    )
    manifest = build_evidence_pack(
        session_path=session_path,
        out_dir=out,
        trace_jsonl_path=trace_path,
    )

    published = (out / "trace.jsonl").read_bytes()
    assert published == original
    assert (
        manifest["artifacts"]["trace_jsonl"]["sha256"]
        == hashlib.sha256(published).hexdigest()
    )
    load_evidence_pack_manifest(out / "manifest.json")


def test_evidence_pack_preserves_a_replaced_staged_trace_on_copy_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    session_path = tmp_path / "session.json"
    session_path.write_text(json.dumps(_session_doc()), encoding="utf-8")
    trace_path = tmp_path / "trace.jsonl"
    original = _trace_jsonl_bytes()
    trace_path.write_bytes(original)
    out = tmp_path / "pack"
    held = tmp_path / "held-copy.jsonl"
    competitor = b"competitor"
    real_lstat = evidence_pack_module.os.lstat
    source_reads = 0

    def replace_destination_after_copy(path: Path):  # noqa: ANN202
        nonlocal source_reads
        candidate = Path(path)
        if candidate == trace_path:
            source_reads += 1
            if source_reads == 2:
                staging = list(tmp_path.glob(".pack.staging-*"))
                assert len(staging) == 1
                destination = staging[0] / "trace.jsonl"
                destination.rename(held)
                destination.write_bytes(competitor)
        return real_lstat(path)

    monkeypatch.setattr(
        evidence_pack_module.os,
        "lstat",
        replace_destination_after_copy,
    )
    with pytest.raises(ContractError, match="staging cleanup failed") as failure:
        build_evidence_pack(
            session_path=session_path,
            out_dir=out,
            trace_jsonl_path=trace_path,
        )

    assert isinstance(failure.value.__cause__, ContractError)
    assert not out.exists()
    staging = list(tmp_path.glob(".pack.staging-*"))
    assert len(staging) == 1
    assert (staging[0] / "trace.jsonl").read_bytes() == competitor
    assert held.read_bytes() == original


def test_evidence_pack_loader_rejects_trace_changed_during_semantic_validation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    session_path = tmp_path / "session.json"
    session_path.write_text(json.dumps(_session_doc()), encoding="utf-8")
    trace_path = tmp_path / "trace.jsonl"
    trace_path.write_bytes(_trace_jsonl_bytes())
    out = tmp_path / "pack"
    build_evidence_pack(
        session_path=session_path,
        out_dir=out,
        trace_jsonl_path=trace_path,
    )
    published = out / "trace.jsonl"
    original_validate = evidence_pack_module.validate_trace

    def _validate_then_mutate(path: Path) -> dict:
        result = original_validate(path)
        changed = _trace_jsonl_bytes(category="browser_core.api")
        published.write_bytes(changed)
        return result

    monkeypatch.setattr(evidence_pack_module, "validate_trace", _validate_then_mutate)

    with pytest.raises(ContractError, match="changed during semantic validation"):
        load_evidence_pack_manifest(out / "manifest.json")


@pytest.mark.skipif(os.name != "nt", reason="Windows creation time is not change time")
def test_evidence_pack_loader_rebinds_browser_fact_after_semantic_validation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    session_path = tmp_path / "session.json"
    session_path.write_text(json.dumps(_session_doc()), encoding="utf-8")
    out = tmp_path / "pack"
    manifest = build_evidence_pack(
        session_path=session_path,
        out_dir=out,
        browser_fact_path=_fact(tmp_path),
    )
    published = out / manifest["artifacts"]["browser_fact"]["file"]
    original_metadata = os.lstat(published)
    original_validate = evidence_pack_module.validate_browser_fact_snapshot
    changed = False

    def validate_then_mutate(document: object) -> dict:
        nonlocal changed
        result = original_validate(document)
        with published.open("r+b") as stream:
            stream.write(b"!")
        os.utime(
            published,
            ns=(original_metadata.st_atime_ns, original_metadata.st_mtime_ns),
        )
        assert evidence_pack_module._file_identity(os.lstat(published)) == (
            evidence_pack_module._file_identity(original_metadata)
        )
        changed = True
        return result

    monkeypatch.setattr(
        evidence_pack_module,
        "validate_browser_fact_snapshot",
        validate_then_mutate,
    )
    with pytest.raises(ContractError, match="changed during semantic validation"):
        load_evidence_pack_manifest(out / "manifest.json")
    assert changed
    assert published.read_bytes().startswith(b"!")


def test_evidence_pack_loader_rejects_manifest_changed_before_inventory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    session_path = tmp_path / "session.json"
    session_path.write_text(json.dumps(_session_doc()), encoding="utf-8")
    out = tmp_path / "pack"
    build_evidence_pack(session_path=session_path, out_dir=out)
    manifest_path = out / "manifest.json"
    original_inventory = evidence_pack_module._inventory_evidence_pack_directory
    changed = False

    def replace_manifest(directory: Path):
        nonlocal changed
        if not changed:
            changed = True
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["created_at"] = "2020-01-01T00:00:00Z"
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        return original_inventory(directory)

    monkeypatch.setattr(
        evidence_pack_module, "_inventory_evidence_pack_directory", replace_manifest
    )
    with pytest.raises(ContractError, match="manifest changed during validation"):
        load_evidence_pack_manifest(manifest_path)


def test_evidence_pack_loader_rejects_rehashed_extra_redacted_session_field(
    tmp_path: Path,
) -> None:
    session_path = tmp_path / "session.json"
    session_path.write_text(json.dumps(_session_doc()), encoding="utf-8")
    out = tmp_path / "pack"
    build_evidence_pack(
        session_path=session_path,
        out_dir=out,
        include_session_copy=True,
    )
    redacted_path = out / "session.redacted.json"
    redacted = json.loads(redacted_path.read_text(encoding="utf-8"))
    redacted["private_path"] = r"C:\\private\\customer.txt"
    body = (json.dumps(redacted, sort_keys=True) + "\n").encode("utf-8")
    redacted_path.write_bytes(body)
    manifest_path = out / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    entry = manifest["artifacts"]["session"]["redacted_copy"]
    entry["bytes"] = len(body)
    entry["sha256"] = hashlib.sha256(body).hexdigest()
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(ContractError, match="redacted session fields"):
        load_evidence_pack_manifest(manifest_path)


def test_evidence_pack_loader_rejects_redacted_boolean_changed_to_number(
    tmp_path: Path,
) -> None:
    session_path = tmp_path / "session.json"
    session_path.write_text(json.dumps(_session_doc()), encoding="utf-8")
    out = tmp_path / "pack"
    build_evidence_pack(session_path=session_path, out_dir=out, include_session_copy=True)
    redacted_path = out / "session.redacted.json"
    redacted = json.loads(redacted_path.read_text(encoding="utf-8"))
    assert redacted["summary"]["has_trace_path"] is False
    redacted["summary"]["has_trace_path"] = 0
    body = (json.dumps(redacted, sort_keys=True) + "\n").encode("utf-8")
    redacted_path.write_bytes(body)
    manifest_path = out / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    entry = manifest["artifacts"]["session"]["redacted_copy"]
    entry["bytes"] = len(body)
    entry["sha256"] = hashlib.sha256(body).hexdigest()
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(ContractError, match="summary does not match the bound JSON"):
        load_evidence_pack_manifest(manifest_path)


@pytest.mark.parametrize(
    ("artifact_key", "field"),
    [
        ("session", "sha256"),
        ("session", "bytes"),
        ("browser_fact", "source_integrity_sha256"),
        ("browser_fact", "source_sha256"),
        ("browser_fact", "source_bytes"),
    ],
)
def test_evidence_pack_loader_rejects_null_required_source_binding(
    tmp_path: Path, artifact_key: str, field: str
) -> None:
    session_path = tmp_path / "session.json"
    session_path.write_text(json.dumps(_session_doc()), encoding="utf-8")
    out = tmp_path / "pack"
    options = {"browser_fact_path": _fact(tmp_path)} if artifact_key == "browser_fact" else {}
    build_evidence_pack(session_path=session_path, out_dir=out, **options)
    manifest_path = out / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert manifest["artifacts"][artifact_key][field] is not None
    manifest["artifacts"][artifact_key][field] = None
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(ContractError, match="artifact .* is invalid"):
        load_evidence_pack_manifest(manifest_path)


def test_evidence_pack_loader_rejects_null_creation_timestamp(tmp_path: Path) -> None:
    session_path = tmp_path / "session.json"
    session_path.write_text(json.dumps(_session_doc()), encoding="utf-8")
    out = tmp_path / "pack"
    build_evidence_pack(session_path=session_path, out_dir=out)
    manifest_path = out / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["created_at"] = None
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(ContractError, match="creation timestamp is invalid"):
        load_evidence_pack_manifest(manifest_path)


def test_evidence_pack_loader_rejects_null_redacted_copy_declaration(
    tmp_path: Path,
) -> None:
    session_path = tmp_path / "session.json"
    session_path.write_text(json.dumps(_session_doc()), encoding="utf-8")
    out = tmp_path / "pack"
    build_evidence_pack(session_path=session_path, out_dir=out)
    manifest_path = out / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["artifacts"]["session"]["redacted_copy"] = None
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(ContractError, match="redacted-copy binding is invalid"):
        load_evidence_pack_manifest(manifest_path)


def test_evidence_pack_loader_binds_manifest_metadata_to_json_artifact(
    tmp_path: Path,
) -> None:
    session_path = tmp_path / "session.json"
    session_path.write_text(json.dumps(_session_doc()), encoding="utf-8")
    out = tmp_path / "pack"
    build_evidence_pack(
        session_path=session_path,
        out_dir=out,
        browser_fact_path=_fact(tmp_path),
    )
    manifest_path = out / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["artifacts"]["browser_fact"]["snapshot_id"] = "forged"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(ContractError, match="metadata does not match the bound JSON"):
        load_evidence_pack_manifest(manifest_path)


def test_evidence_pack_loader_binds_browser_fact_source_integrity_to_portable_snapshot(
    tmp_path: Path,
) -> None:
    session_path = tmp_path / "session.json"
    session_path.write_text(json.dumps(_session_doc()), encoding="utf-8")
    out = tmp_path / "pack"
    build_evidence_pack(
        session_path=session_path,
        out_dir=out,
        browser_fact_path=_fact(tmp_path),
    )
    manifest_path = out / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    artifact = manifest["artifacts"]["browser_fact"]
    assert artifact["snapshot_id"] == f"portable-{artifact['source_integrity_sha256'][:16]}"
    artifact["source_integrity_sha256"] = (
        "0" * 64 if artifact["source_integrity_sha256"] != "0" * 64 else "1" * 64
    )
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(ContractError, match="source integrity"):
        load_evidence_pack_manifest(manifest_path)


def test_evidence_pack_loader_rechecks_browser_fact_session_join(
    tmp_path: Path,
) -> None:
    session_path = tmp_path / "session.json"
    session_path.write_text(json.dumps(_session_doc()), encoding="utf-8")
    out = tmp_path / "pack"
    build_evidence_pack(
        session_path=session_path,
        out_dir=out,
        browser_fact_path=_session_fact(tmp_path),
    )

    artifact_path = out / "browser-fact.json"
    fact = json.loads(artifact_path.read_text(encoding="utf-8"))
    forged_source = dict(fact["source"])
    forged_source["session_run_id"] = "core-20260817T000000Z-foreign"
    forged = build_browser_fact_snapshot(
        snapshot_id=fact["snapshot_id"],
        browser=fact["browser"],
        source_kind="browser-core-session",
        source_label=forged_source.pop("label"),
        engine="browser-core",
        captured_at=fact["captured_at"],
        source_extra={
            key: value
            for key, value in forged_source.items()
            if key != "kind"
        },
    )
    artifact_body = (
        json.dumps(forged, indent=2, sort_keys=True, allow_nan=False) + "\n"
    ).encode("utf-8")
    artifact_path.write_bytes(artifact_body)

    manifest_path = out / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    entry = manifest["artifacts"]["browser_fact"]
    entry["integrity_sha256"] = forged["integrity_sha256"]
    entry["sha256"] = hashlib.sha256(artifact_body).hexdigest()
    entry["bytes"] = len(artifact_body)
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(ContractError, match="browser fact session provenance"):
        load_evidence_pack_manifest(manifest_path)


def test_evidence_pack_loader_binds_trace_summary_to_json_artifact(
    tmp_path: Path,
) -> None:
    session_path = tmp_path / "session.json"
    session_path.write_text(json.dumps(_session_doc()), encoding="utf-8")
    report_path = tmp_path / "trace-export.json"
    report_path.write_text(json.dumps(_trace_export_doc()), encoding="utf-8")
    out = tmp_path / "pack"
    build_evidence_pack(
        session_path=session_path,
        out_dir=out,
        trace_export_path=report_path,
    )
    manifest_path = out / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["artifacts"]["trace_export"]["summary"]["run_id"] = "forged"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(ContractError, match="summary does not match the bound JSON"):
        load_evidence_pack_manifest(manifest_path)


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (
            lambda document: document["artifacts"].__setitem__(
                "private_note", {"summary": {"path": r"C:\\private\\customer.txt"}}
            ),
            "artifact kinds",
        ),
        (
            lambda document: document["artifacts"]["session"]["summary"].__setitem__(
                "private_path", r"C:\\private\\customer.txt"
            ),
            "session summary fields",
        ),
        (
            lambda document: document.__setitem__("private_path", "secret"),
            "manifest fields",
        ),
    ],
)
def test_evidence_pack_loader_rejects_unknown_manifest_fields(
    tmp_path: Path, mutate, message: str
) -> None:
    session_path = tmp_path / "session.json"
    session_path.write_text(json.dumps(_session_doc()), encoding="utf-8")
    out = tmp_path / "pack"
    build_evidence_pack(session_path=session_path, out_dir=out)
    manifest_path = out / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    mutate(manifest)
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(ContractError, match=message):
        load_evidence_pack_manifest(manifest_path)


def test_evidence_pack_loader_rejects_unlisted_files(tmp_path: Path) -> None:
    session_path = tmp_path / "session.json"
    session_path.write_text(json.dumps(_session_doc()), encoding="utf-8")
    out = tmp_path / "pack"
    build_evidence_pack(session_path=session_path, out_dir=out)
    (out / "private-extra.txt").write_text("private", encoding="utf-8")

    with pytest.raises(ContractError, match="unlisted"):
        load_evidence_pack_manifest(out / "manifest.json")


def test_evidence_pack_loader_bounds_manifest_json_before_parsing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    session_path = tmp_path / "session.json"
    session_path.write_text(json.dumps(_session_doc()), encoding="utf-8")
    out = tmp_path / "pack"
    build_evidence_pack(session_path=session_path, out_dir=out)
    manifest_path = out / "manifest.json"
    payload = manifest_path.read_bytes()
    monkeypatch.setattr(
        evidence_pack_module, "MAX_EVIDENCE_PACK_MANIFEST_BYTES", len(payload) - 1
    )

    with pytest.raises(ContractError, match="manifest exceeds the .* JSON limit"):
        load_evidence_pack_manifest(manifest_path)


def test_evidence_pack_loader_bounds_bound_json_before_parsing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    session_path = tmp_path / "session.json"
    session_path.write_text(json.dumps(_session_doc()), encoding="utf-8")
    out = tmp_path / "pack"
    build_evidence_pack(
        session_path=session_path,
        out_dir=out,
        include_session_copy=True,
    )
    redacted_path = out / "session.redacted.json"
    payload = redacted_path.read_bytes()
    monkeypatch.setattr(
        evidence_pack_module,
        "MAX_EVIDENCE_PACK_JSON_ARTIFACT_BYTES",
        len(payload) - 1,
    )

    with pytest.raises(
        ContractError, match="redacted session exceeds the .* JSON limit"
    ):
        load_evidence_pack_manifest(out / "manifest.json")


def test_evidence_pack_loader_labels_oversized_http2_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    session = _session_doc()
    session["build"] = {
        **session["build"],
        "runtime_bundle_sha256_16": "d785d5f4a146e84d",
    }
    session_path = tmp_path / "session.json"
    session_path.write_text(json.dumps(session), encoding="utf-8")
    source = tmp_path / "http2-evidence.json"
    source.write_text(json.dumps(_http2_evidence_doc()), encoding="utf-8")
    out = tmp_path / "pack"
    build_evidence_pack(
        session_path=session_path,
        out_dir=out,
        http2_evidence_path=source,
    )
    payload = (out / "http2-evidence.json").read_bytes()
    monkeypatch.setattr(
        evidence_pack_module,
        "MAX_EVIDENCE_PACK_JSON_ARTIFACT_BYTES",
        len(payload) - 1,
    )

    with pytest.raises(
        ContractError, match="HTTP/2 evidence exceeds the .* JSON limit"
    ):
        load_evidence_pack_manifest(out / "manifest.json")


def test_evidence_pack_builder_respects_its_manifest_loader_limit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    session_path = tmp_path / "session.json"
    session_path.write_text(json.dumps(_session_doc()), encoding="utf-8")
    out = tmp_path / "pack"
    monkeypatch.setattr(evidence_pack_module, "MAX_EVIDENCE_PACK_MANIFEST_BYTES", 1)

    with pytest.raises(ContractError, match="manifest exceeds the 1-byte JSON limit"):
        build_evidence_pack(session_path=session_path, out_dir=out)

    assert not out.exists()
    assert not list(tmp_path.glob(".pack.staging-*"))


def test_evidence_pack_builder_respects_bound_json_artifact_limit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    session_path = tmp_path / "session.json"
    session_path.write_text(json.dumps(_session_doc()), encoding="utf-8")
    out = tmp_path / "pack"
    monkeypatch.setattr(
        evidence_pack_module, "MAX_EVIDENCE_PACK_JSON_ARTIFACT_BYTES", 1
    )

    with pytest.raises(
        ContractError, match="browser fact exceeds the 1-byte JSON limit"
    ):
        build_evidence_pack(
            session_path=session_path,
            out_dir=out,
            browser_fact_path=_fact(tmp_path),
        )

    assert not out.exists()
    assert not list(tmp_path.glob(".pack.staging-*"))


def test_evidence_pack_loader_rejects_symlinked_artifacts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    session_path = tmp_path / "session.json"
    session_path.write_text(json.dumps(_session_doc()), encoding="utf-8")
    fact_path = _fact(tmp_path)
    out = tmp_path / "pack"
    build_evidence_pack(
        session_path=session_path,
        out_dir=out,
        browser_fact_path=fact_path,
    )
    artifact = out / "browser-fact.json"
    original_is_symlink = Path.is_symlink

    def _is_symlink(path: Path) -> bool:
        return path == artifact or original_is_symlink(path)

    # Windows CI does not necessarily grant SeCreateSymbolicLinkPrivilege.  The
    # patched predicate still exercises the fail-closed branch on every host.
    monkeypatch.setattr(Path, "is_symlink", _is_symlink)

    with pytest.raises(ContractError, match="must not be a symlink"):
        load_evidence_pack_manifest(out / "manifest.json")


def test_evidence_pack_loader_rejects_symlinked_manifest_leaf(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    session_path = tmp_path / "session.json"
    session_path.write_text(json.dumps(_session_doc()), encoding="utf-8")
    out = tmp_path / "pack"
    build_evidence_pack(session_path=session_path, out_dir=out)
    manifest = out / "manifest.json"
    original_is_symlink = Path.is_symlink

    def _is_symlink(path: Path) -> bool:
        return path == manifest or original_is_symlink(path)

    monkeypatch.setattr(Path, "is_symlink", _is_symlink)

    with pytest.raises(ContractError, match="manifest must not be a symlink"):
        load_evidence_pack_manifest(manifest)


def test_evidence_pack_loader_rejects_hard_linked_artifact(tmp_path: Path) -> None:
    session_path = tmp_path / "session.json"
    session_path.write_text(json.dumps(_session_doc()), encoding="utf-8")
    out = tmp_path / "pack"
    build_evidence_pack(
        session_path=session_path,
        out_dir=out,
        browser_fact_path=_fact(tmp_path),
    )
    artifact = out / "browser-fact.json"
    external = tmp_path / "external-browser-fact.json"
    artifact.replace(external)
    os.link(external, artifact)

    with pytest.raises(ContractError, match="must not be hard-linked"):
        load_evidence_pack_manifest(out / "manifest.json")


def test_evidence_pack_loader_rejects_hard_linked_manifest(tmp_path: Path) -> None:
    session_path = tmp_path / "session.json"
    session_path.write_text(json.dumps(_session_doc()), encoding="utf-8")
    out = tmp_path / "pack"
    build_evidence_pack(session_path=session_path, out_dir=out)
    manifest = out / "manifest.json"
    external = tmp_path / "external-manifest.json"
    manifest.replace(external)
    os.link(external, manifest)

    with pytest.raises(ContractError, match="manifest must not have additional hard links"):
        load_evidence_pack_manifest(manifest)


def test_evidence_pack_loader_rejects_path_traversal_bindings(tmp_path: Path) -> None:
    out = tmp_path / "pack"
    session_path = tmp_path / "session.json"
    session_path.write_text(json.dumps(_session_doc()), encoding="utf-8")
    trace_path = tmp_path / "trace.jsonl"
    trace_path.write_bytes(_trace_jsonl_bytes())
    build_evidence_pack(
        session_path=session_path,
        out_dir=out,
        trace_jsonl_path=trace_path,
    )
    path = out / "manifest.json"
    document = json.loads(path.read_text(encoding="utf-8"))
    document["artifacts"]["trace_jsonl"]["file"] = "../private.jsonl"
    path.write_text(json.dumps(document), encoding="utf-8")

    with pytest.raises(ContractError, match="file binding"):
        load_evidence_pack_manifest(path)


def test_portable_session_hashes_operator_ids_and_validates_timestamps() -> None:
    document = _session_doc(
        created_at="private-created-value",
        stopped_at="2026-08-09T12:34:56-05:00",
        persona={"id": "private-customer-persona", "sha256_16": "a" * 16},
        network={
            "route_id": "private-customer-route",
            "route_sha256_16": "b" * 16,
        },
    )

    summary = _session_portable_summary(document)
    rendered = json.dumps(summary)

    assert "created_at" not in summary
    assert summary["stopped_at"] == "2026-08-09T12:34:56-05:00"
    assert summary["persona_sha256_16"] == "a" * 16
    assert summary["network_route_sha256_16"] == "b" * 16
    assert "persona_id" not in summary
    assert "network_route_id" not in summary
    assert "private-" not in rendered


def test_redacted_session_copy_is_an_allowlist_not_a_mutated_raw_copy() -> None:
    document = _session_doc(
        process_identity={
            "pid": 99,
            "executable": "C:/private/customer/chrome.exe",
            "start_marker": "private-process-marker",
        },
        profile={
            "persistence": "ephemeral",
            "id": "private-profile-id",
            "path": "C:/private/customer/profile",
            "lock_path": "C:/private/customer/lock",
        },
        identity_contract={
            "file": "identity-contract.json",
            "path": "C:/private/customer/identity-contract.json",
            "sha256_16": "c" * 16,
            "fields": ["private-field-name"],
        },
        persona={"id": "private-customer-persona", "sha256_16": "a" * 16},
        network={
            "route_id": "private-customer-route",
            "route_sha256_16": "b" * 16,
            "lease_path": "C:/private/customer/lease.json",
        },
        trace_path="C:/private/customer/trace.pftrace",
        automation={
            "transport": "cdp",
            "cdp_endpoint": "http://127.0.0.1:9333",
            "managed_target_url": "https://private-customer.example/account",
        },
    )

    redacted = _redacted_session_document(document)
    rendered = json.dumps(redacted)

    assert redacted["schema"] == "browser-core.session-redacted/1"
    assert redacted["automation"] == {
        "transport": "cdp",
        "cdp_endpoint": "[redacted-loopback]",
        "has_managed_target_url": True,
    }
    assert redacted["profile"] == {
        "persistence": "ephemeral",
        "has_path": True,
        "has_lock_path": True,
    }
    assert "private" not in rendered
    assert "trace_path" not in redacted
    assert "process_identity" not in redacted
    assert "identity_contract" not in redacted


def test_trace_export_receipt_is_retained_and_bound_to_its_jsonl(
    tmp_path: Path,
) -> None:
    session_path = tmp_path / "session.json"
    session_path.write_text(json.dumps(_session_doc()), encoding="utf-8")
    jsonl = _trace_jsonl_bytes()
    jsonl_path = tmp_path / "trace.jsonl"
    jsonl_path.write_bytes(jsonl)
    report_path = tmp_path / "trace-export.json"
    report_path.write_text(json.dumps(_trace_export_doc(jsonl=jsonl)), encoding="utf-8")

    manifest = build_evidence_pack(
        session_path=session_path,
        out_dir=tmp_path / "pack",
        trace_export_path=report_path,
        trace_jsonl_path=jsonl_path,
    )

    summary = manifest["artifacts"]["trace_export"]["summary"]
    assert summary["source_trace"]["sha256"] == "a" * 64
    assert summary["normalized_trace"]["sha256"] == hashlib.sha256(jsonl).hexdigest()
    assert summary["normalized_trace"]["events"] == 1
    assert (
        manifest["artifacts"]["trace_jsonl"]["sha256"]
        == summary["normalized_trace"]["sha256"]
    )


@pytest.mark.parametrize("loading", [False, True])
def test_trace_category_failure_closes_retained_trace_iterator(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, loading: bool
) -> None:
    session_path = tmp_path / "session.json"
    session_path.write_text(json.dumps(_session_doc()), encoding="utf-8")
    jsonl = _trace_jsonl_bytes()
    jsonl_path = tmp_path / "trace.jsonl"
    jsonl_path.write_bytes(jsonl)
    report_path = tmp_path / "trace-export.json"
    report_path.write_text(json.dumps(_trace_export_doc(jsonl=jsonl)), encoding="utf-8")
    out = tmp_path / "pack"
    if loading:
        build_evidence_pack(
            session_path=session_path,
            out_dir=out,
            trace_export_path=report_path,
            trace_jsonl_path=jsonl_path,
        )

    retained = []
    closed = []
    def tracked_iter_trace(_path: Path):
        def events():
            try:
                yield {"provenance": {}}
            finally:
                closed.append(True)
        generator = events()
        retained.append(generator)
        return generator

    monkeypatch.setattr(evidence_pack_module, "iter_trace", tracked_iter_trace)
    with pytest.raises(ContractError, match="trace-category provenance"):
        if loading:
            load_evidence_pack_manifest(out / "manifest.json")
        else:
            build_evidence_pack(
                session_path=session_path,
                out_dir=out,
                trace_export_path=report_path,
                trace_jsonl_path=jsonl_path,
            )
    assert len(retained) == 1
    assert closed == [True]


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("run_id", "other-run", "run id"),
        ("chromium_revision", "f" * 40, "Chromium revision"),
    ],
)
def test_trace_export_must_match_the_session(
    tmp_path: Path, field: str, value: str, message: str
) -> None:
    session_path = tmp_path / "session.json"
    session_path.write_text(json.dumps(_session_doc()), encoding="utf-8")
    report = _trace_export_doc()
    report[field] = value
    report_path = tmp_path / "trace-export.json"
    report_path.write_text(json.dumps(report), encoding="utf-8")

    with pytest.raises(ContractError, match=message):
        build_evidence_pack(
            session_path=session_path,
            out_dir=tmp_path / "pack",
            trace_export_path=report_path,
        )


def test_trace_jsonl_must_match_the_export_receipt(tmp_path: Path) -> None:
    session_path = tmp_path / "session.json"
    session_path.write_text(json.dumps(_session_doc()), encoding="utf-8")
    report_path = tmp_path / "trace-export.json"
    report_path.write_text(json.dumps(_trace_export_doc()), encoding="utf-8")
    jsonl_path = tmp_path / "trace.jsonl"
    jsonl_path.write_bytes(b"different")

    with pytest.raises(ContractError, match="digest binding"):
        build_evidence_pack(
            session_path=session_path,
            out_dir=tmp_path / "pack",
            trace_export_path=report_path,
            trace_jsonl_path=jsonl_path,
        )
    assert not (tmp_path / "pack").exists()


def test_pack_atomically_replaces_an_existing_empty_destination(tmp_path: Path) -> None:
    session_path = tmp_path / "session.json"
    session_path.write_text(json.dumps(_session_doc()), encoding="utf-8")
    out = tmp_path / "pack"
    out.mkdir()

    manifest = build_evidence_pack(session_path=session_path, out_dir=out)

    assert manifest["schema"] == "browser-core.evidence-pack/1"
    assert (out / "manifest.json").is_file()
    assert not list(tmp_path.glob(".pack.staging-*"))


def test_pack_preserves_destination_that_appears_during_build(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    session_path = tmp_path / "session.json"
    session_path.write_text(json.dumps(_session_doc()), encoding="utf-8")
    out = tmp_path / "pack"
    original_builder = evidence_pack_module._build_evidence_pack_contents

    def _build_then_race(**kwargs: object) -> dict:
        manifest = original_builder(**kwargs)
        out.mkdir()
        return manifest

    monkeypatch.setattr(
        evidence_pack_module, "_build_evidence_pack_contents", _build_then_race
    )

    with pytest.raises(ContractError, match="appeared during the build"):
        build_evidence_pack(session_path=session_path, out_dir=out)

    assert out.is_dir()
    assert not list(tmp_path.glob(".pack.staging-*"))


@pytest.mark.skipif(os.name != "nt", reason="Windows directory junction boundary")
def test_pack_preserves_dangling_junction_that_appears_during_build(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    session_path = tmp_path / "session.json"
    session_path.write_text(json.dumps(_session_doc()), encoding="utf-8")
    out = tmp_path / "pack"
    missing_target = tmp_path / "missing-target"
    original_builder = evidence_pack_module._build_evidence_pack_contents

    def _build_then_race(**kwargs: object) -> dict:
        manifest = original_builder(**kwargs)
        created = subprocess.run(
            ["cmd", "/c", "mklink", "/J", str(out), str(missing_target)],
            capture_output=True,
            check=False,
        )
        if created.returncode:
            pytest.skip("host could not create an unprivileged directory junction")
        return manifest

    monkeypatch.setattr(
        evidence_pack_module, "_build_evidence_pack_contents", _build_then_race
    )
    try:
        with pytest.raises(ContractError, match="appeared during the build"):
            build_evidence_pack(session_path=session_path, out_dir=out)
        assert os.path.lexists(out)
        assert not out.exists()
        assert not list(tmp_path.glob(".pack.staging-*"))
    finally:
        if os.path.lexists(out) and (
            getattr(os.lstat(out), "st_file_attributes", 0) & 0x400
        ):
            out.rmdir()


def test_pack_preserves_replacement_for_original_empty_destination(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    session_path = tmp_path / "session.json"
    session_path.write_text(json.dumps(_session_doc()), encoding="utf-8")
    out = tmp_path / "pack"
    out.mkdir()
    original_builder = evidence_pack_module._build_evidence_pack_contents

    def _build_then_replace(**kwargs: object) -> dict:
        manifest = original_builder(**kwargs)
        out.rmdir()
        out.mkdir()
        (out / "foreign.txt").write_text("owned elsewhere", encoding="utf-8")
        return manifest

    monkeypatch.setattr(
        evidence_pack_module, "_build_evidence_pack_contents", _build_then_replace
    )

    with pytest.raises(ContractError, match="changed during the build"):
        build_evidence_pack(session_path=session_path, out_dir=out)

    assert (out / "foreign.txt").read_text(encoding="utf-8") == "owned elsewhere"
    assert not list(tmp_path.glob(".pack.staging-*"))


def test_pack_never_removes_a_late_empty_destination_replacement(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    session_path = tmp_path / "session.json"
    session_path.write_text(json.dumps(_session_doc()), encoding="utf-8")
    out = tmp_path / "pack"
    out.mkdir()
    held = tmp_path / "held-original-pack"
    real_rename = evidence_pack_module.os.rename
    injected = False

    def replace_before_destination_quarantine(source: Path, destination: Path) -> None:
        nonlocal injected
        if not injected and Path(source) == out:
            injected = True
            real_rename(out, held)
            out.mkdir()
            (out / "competitor.bin").write_bytes(b"competitor")
        real_rename(source, destination)

    monkeypatch.setattr(
        evidence_pack_module.os,
        "rename",
        replace_before_destination_quarantine,
    )
    with pytest.raises(ContractError, match="changed during removal"):
        build_evidence_pack(session_path=session_path, out_dir=out)

    assert held.is_dir()
    assert not out.exists()
    competitors = list(tmp_path.glob(".pack.removed-*"))
    assert len(competitors) == 1
    assert (competitors[0] / "competitor.bin").read_bytes() == b"competitor"
    assert not list(tmp_path.glob(".pack.staging-*"))


def test_pack_cleanup_preserves_a_replaced_staging_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    session_path = tmp_path / "session.json"
    session_path.write_text(json.dumps(_session_doc()), encoding="utf-8")
    out = tmp_path / "pack"
    displaced = tmp_path / "displaced-staging"
    original_builder = evidence_pack_module._build_evidence_pack_contents

    def _build_then_replace_staging(**kwargs: object) -> dict:
        original_builder(**kwargs)
        staging = kwargs["out_dir"]
        assert isinstance(staging, Path)
        staging.rename(displaced)
        staging.mkdir()
        (staging / "competitor.bin").write_bytes(b"competitor")
        raise RuntimeError("private staging failure")

    monkeypatch.setattr(
        evidence_pack_module,
        "_build_evidence_pack_contents",
        _build_then_replace_staging,
    )

    with pytest.raises(ContractError, match="staging cleanup failed") as failure:
        build_evidence_pack(session_path=session_path, out_dir=out)

    assert isinstance(failure.value.__cause__, RuntimeError)
    assert displaced.is_dir()
    competitors = list(tmp_path.glob(".pack.staging-*"))
    assert len(competitors) == 1
    assert (competitors[0] / "competitor.bin").read_bytes() == b"competitor"


def test_pack_rejects_output_parent_replacement_without_deleting_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    session_path = tmp_path / "session.json"
    session_path.write_text(json.dumps(_session_doc()), encoding="utf-8")
    parent = tmp_path / "workspace"
    parent.mkdir()
    out = parent / "pack"
    displaced = tmp_path / "displaced-workspace"
    original_builder = evidence_pack_module._build_evidence_pack_contents

    def _build_then_replace_parent(**kwargs: object) -> dict:
        manifest = original_builder(**kwargs)
        parent.rename(displaced)
        parent.mkdir()
        (parent / "competitor.bin").write_bytes(b"competitor")
        return manifest

    monkeypatch.setattr(
        evidence_pack_module,
        "_build_evidence_pack_contents",
        _build_then_replace_parent,
    )

    with pytest.raises(ContractError, match="staging authority changed"):
        build_evidence_pack(session_path=session_path, out_dir=out)

    assert list(displaced.glob(".pack.staging-*"))
    assert (parent / "competitor.bin").read_bytes() == b"competitor"


def test_pack_rejects_relocated_output_ancestor_after_staging_build(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    session_path = tmp_path / "session.json"
    session_path.write_text(json.dumps(_session_doc()), encoding="utf-8")
    private = tmp_path / "private"
    parent = private / "leaf"
    parent.mkdir(parents=True)
    out = parent / "pack"
    retained = tmp_path / "retained"
    original_builder = evidence_pack_module._build_evidence_pack_contents
    staged: list[Path] = []
    swapped = False

    def build_then_relocate(**kwargs):
        nonlocal swapped
        manifest = original_builder(**kwargs)
        staged.append(kwargs["out_dir"])
        private.rename(retained)
        private.mkdir()
        (retained / "leaf").rename(parent)
        swapped = True
        return manifest

    monkeypatch.setattr(evidence_pack_module, "_build_evidence_pack_contents", build_then_relocate)
    try:
        with pytest.raises(ContractError, match="staging cleanup failed"):
            build_evidence_pack(session_path=session_path, out_dir=out)
        assert swapped and len(staged) == 1
        assert (staged[0] / "manifest.json").exists()
        assert not out.exists()
    finally:
        if swapped:
            parent.rename(retained / "leaf")
            private.rmdir()
            retained.rename(private)


def test_pack_preserves_staging_after_ancestor_relocation_during_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    session_path = tmp_path / "session.json"
    session_path.write_text(json.dumps(_session_doc()), encoding="utf-8")
    private = tmp_path / "private"
    parent = private / "leaf"
    parent.mkdir(parents=True)
    out = parent / "pack"
    retained = tmp_path / "retained"
    staged: list[Path] = []
    swapped = False

    def fail_after_relocation(**kwargs):
        nonlocal swapped
        staging = kwargs["out_dir"]
        staged.append(staging)
        (staging / "operator.txt").write_bytes(b"retain me")
        private.rename(retained)
        private.mkdir()
        (retained / "leaf").rename(parent)
        swapped = True
        raise RuntimeError("forced staging failure")

    monkeypatch.setattr(evidence_pack_module, "_build_evidence_pack_contents", fail_after_relocation)
    try:
        with pytest.raises(ContractError, match="staging cleanup failed") as failure:
            build_evidence_pack(session_path=session_path, out_dir=out)
        assert isinstance(failure.value.__cause__, RuntimeError)
        assert swapped and len(staged) == 1
        assert (staged[0] / "operator.txt").read_bytes() == b"retain me"
    finally:
        if swapped:
            parent.rename(retained / "leaf")
            private.rmdir()
            retained.rename(private)


def test_pack_rejects_relocated_output_ancestor_after_published_readback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    session_path = tmp_path / "session.json"
    session_path.write_text(json.dumps(_session_doc()), encoding="utf-8")
    private = tmp_path / "private"
    parent = private / "leaf"
    parent.mkdir(parents=True)
    out = parent / "pack"
    retained = tmp_path / "retained"
    original_rebind = evidence_pack_module._rebind_published_evidence_pack
    swapped = False

    def rebind_then_relocate(*args):
        nonlocal swapped
        original_rebind(*args)
        private.rename(retained)
        private.mkdir()
        (retained / "leaf").rename(parent)
        swapped = True

    monkeypatch.setattr(evidence_pack_module, "_rebind_published_evidence_pack", rebind_then_relocate)
    try:
        with pytest.raises(ContractError, match="publication authority changed"):
            build_evidence_pack(session_path=session_path, out_dir=out)
        assert swapped
        assert (out / "manifest.json").exists()
    finally:
        if swapped:
            parent.rename(retained / "leaf")
            private.rmdir()
            retained.rename(private)


def test_pack_rejects_symlinked_output_leaf_before_resolution(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    session_path = tmp_path / "session.json"
    session_path.write_text(json.dumps(_session_doc()), encoding="utf-8")
    out = tmp_path / "pack"
    original_is_symlink = Path.is_symlink

    def _is_symlink(path: Path) -> bool:
        return path == out or original_is_symlink(path)

    monkeypatch.setattr(Path, "is_symlink", _is_symlink)

    with pytest.raises(ContractError, match="output directory must not be a symlink"):
        build_evidence_pack(session_path=session_path, out_dir=out)
    assert not out.exists()


def test_pack_rejects_existing_nondirectory_output(tmp_path: Path) -> None:
    session_path = tmp_path / "session.json"
    session_path.write_text(json.dumps(_session_doc()), encoding="utf-8")
    out = tmp_path / "pack"
    out.write_text("not a directory", encoding="utf-8")

    with pytest.raises(ContractError, match="output path must be a directory"):
        build_evidence_pack(session_path=session_path, out_dir=out)


@pytest.mark.skipif(os.name != "nt", reason="Win32 output-name aliases")
@pytest.mark.parametrize(
    "leaf",
    ["CON", "AUX.txt", "CON .txt", "pack.", "pack ", "pack:stream", "pack*", "pack?"],
)
def test_pack_rejects_windows_invalid_leaf_before_creating_parent(
    tmp_path: Path, leaf: str,
) -> None:
    session_path = tmp_path / "session.json"
    session_path.write_text(json.dumps(_session_doc()), encoding="utf-8")
    parent = tmp_path / "new-parent"

    with pytest.raises(ContractError):
        build_evidence_pack(session_path=session_path, out_dir=parent / leaf)

    assert not parent.exists()


@pytest.mark.skipif(os.name != "nt", reason="Win32 output-name aliases")
@pytest.mark.parametrize(
    "parent_name", ["CON", "AUX.txt", "CON .txt", "alias.", "alias ", "alias:stream", "alias*"]
)
def test_pack_rejects_windows_invalid_parent_before_creating_prefix(
    tmp_path: Path, parent_name: str,
) -> None:
    session_path = tmp_path / "session.json"
    session_path.write_text(json.dumps(_session_doc()), encoding="utf-8")
    prefix = tmp_path / "new-prefix"

    with pytest.raises(ContractError):
        build_evidence_pack(
            session_path=session_path, out_dir=prefix / parent_name / "pack"
        )

    assert not prefix.exists()


def test_trace_jsonl_is_validated_even_without_an_export_receipt(
    tmp_path: Path,
) -> None:
    session_path = tmp_path / "session.json"
    session_path.write_text(json.dumps(_session_doc()), encoding="utf-8")
    jsonl_path = tmp_path / "trace.jsonl"
    jsonl_path.write_text('{"schema":"private"}\n', encoding="utf-8")

    with pytest.raises(ContractError, match="unsupported trace schema"):
        build_evidence_pack(
            session_path=session_path,
            out_dir=tmp_path / "pack",
            trace_jsonl_path=jsonl_path,
        )


def test_matching_trace_bytes_must_also_match_receipt_semantics(tmp_path: Path) -> None:
    session_path = tmp_path / "session.json"
    session_path.write_text(json.dumps(_session_doc()), encoding="utf-8")
    jsonl = _trace_jsonl_bytes(category="browser_core.stream")
    jsonl_path = tmp_path / "trace.jsonl"
    jsonl_path.write_bytes(jsonl)
    report_path = tmp_path / "trace-export.json"
    report_path.write_text(json.dumps(_trace_export_doc(jsonl=jsonl)), encoding="utf-8")

    with pytest.raises(ContractError, match="stream trace provenance"):
        build_evidence_pack(
            session_path=session_path,
            out_dir=tmp_path / "pack",
            trace_export_path=report_path,
            trace_jsonl_path=jsonl_path,
        )


def test_evidence_pack_rejects_nonempty_out_dir(tmp_path: Path) -> None:
    session_path = tmp_path / "session.json"
    session_path.write_text(json.dumps(_session_doc()), encoding="utf-8")
    out = tmp_path / "pack"
    out.mkdir()
    (out / "junk.txt").write_text("x", encoding="utf-8")
    with pytest.raises(ContractError, match="empty"):
        build_evidence_pack(session_path=session_path, out_dir=out)


def test_evidence_pack_json_sources_and_manifest_are_strict_single_link(
    tmp_path: Path,
) -> None:
    session_path = tmp_path / "session.json"
    session_path.write_text(json.dumps(_session_doc()), encoding="utf-8")
    fact_path = _fact(tmp_path)
    fact_body = fact_path.read_bytes()
    fact_path.write_bytes(
        fact_body.replace(b'"schema":', b'"schema":"duplicate","schema":', 1)
    )
    with pytest.raises(ContractError, match="duplicate key"):
        build_evidence_pack(
            session_path=session_path,
            out_dir=tmp_path / "duplicate-source-pack",
            browser_fact_path=fact_path,
        )

    fact_path.write_bytes(fact_body)
    os.link(fact_path, tmp_path / "fact-alias.json")
    with pytest.raises(ContractError, match="hard links"):
        build_evidence_pack(
            session_path=session_path,
            out_dir=tmp_path / "linked-source-pack",
            browser_fact_path=fact_path,
        )

    out = tmp_path / "pack"
    build_evidence_pack(session_path=session_path, out_dir=out)
    manifest_path = out / "manifest.json"
    manifest_body = manifest_path.read_bytes()
    manifest_path.write_bytes(
        manifest_body.replace(b'"schema":', b'"schema":"duplicate","schema":', 1)
    )
    with pytest.raises(ContractError, match="duplicate key"):
        load_evidence_pack_manifest(manifest_path)

    manifest_path.write_bytes(manifest_body)
    os.link(manifest_path, tmp_path / "manifest-alias.json")
    with pytest.raises(ContractError, match="hard links"):
        load_evidence_pack_manifest(manifest_path)


def test_evidence_pack_trace_copy_is_bounded_and_rejects_hard_links(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session_path = tmp_path / "session.json"
    session_path.write_text(json.dumps(_session_doc()), encoding="utf-8")
    trace_path = tmp_path / "trace.jsonl"
    trace_path.write_bytes(_trace_jsonl_bytes())
    os.link(trace_path, tmp_path / "trace-alias.jsonl")
    with pytest.raises(ContractError, match="single-link"):
        build_evidence_pack(
            session_path=session_path,
            out_dir=tmp_path / "linked-trace-pack",
            trace_jsonl_path=trace_path,
        )

    (tmp_path / "trace-alias.jsonl").unlink()
    monkeypatch.setattr(evidence_pack_module, "MAX_EVIDENCE_PACK_TRACE_JSONL_BYTES", 4)
    with pytest.raises(ContractError, match="exceeds 4 bytes"):
        build_evidence_pack(
            session_path=session_path,
            out_dir=tmp_path / "oversize-trace-pack",
            trace_jsonl_path=trace_path,
        )
    assert not (tmp_path / "oversize-trace-pack").exists()


def test_evidence_pack_rejects_short_staged_copy_write(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "source.jsonl"
    destination = tmp_path / "staged.jsonl"
    source.write_bytes(_trace_jsonl_bytes())
    original_open = Path.open

    class ShortWriter:
        def __init__(self, stream):
            self.stream = stream

        def __enter__(self):
            self.stream.__enter__()
            return self

        def __exit__(self, *args):
            return self.stream.__exit__(*args)

        def __getattr__(self, name):
            return getattr(self.stream, name)

        def write(self, body):
            self.stream.write(body[:-1])
            return len(body) - 1

    def partial_open(path, mode="r", *args, **kwargs):
        stream = original_open(path, mode, *args, **kwargs)
        return ShortWriter(stream) if path == destination and mode == "xb" else stream

    monkeypatch.setattr(Path, "open", partial_open)
    with pytest.raises(ContractError, match="incomplete"):
        evidence_pack_module._copy_stable_file(
            source, destination, maximum=1024, label="trace",
        )
    assert not destination.exists()


def test_evidence_pack_paths_and_directory_population_are_bounded(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session_path = tmp_path / "session.json"
    session_path.write_text(json.dumps(_session_doc()), encoding="utf-8")
    with pytest.raises(ContractError, match="output path must be a Path"):
        build_evidence_pack(
            session_path=session_path,
            out_dir=str(tmp_path / "pack"),  # type: ignore[arg-type]
        )
    with pytest.raises(ContractError, match="manifest path must be a Path"):
        load_evidence_pack_manifest("manifest.json")  # type: ignore[arg-type]

    out = tmp_path / "pack"
    build_evidence_pack(session_path=session_path, out_dir=out)
    monkeypatch.setattr(evidence_pack_module, "MAX_EVIDENCE_PACK_DIRECTORY_ENTRIES", 0)
    with pytest.raises(ContractError, match="too many entries"):
        load_evidence_pack_manifest(out / "manifest.json")


@pytest.mark.parametrize("invalid_character", ["\x00", "\ud800"])
def test_evidence_pack_loader_rejects_invalid_manifest_filename(
    tmp_path: Path, invalid_character: str,
) -> None:
    invalid_path = tmp_path / f"manifest{invalid_character}.json"
    with pytest.raises(ContractError, match="evidence pack manifest path is invalid"):
        load_evidence_pack_manifest(invalid_path)


def test_evidence_pack_inventory_stops_scanning_after_entry_limit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(evidence_pack_module, "MAX_EVIDENCE_PACK_DIRECTORY_ENTRIES", 2)

    class Entries:
        requests = 0

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def __iter__(self):
            return self

        def __next__(self):
            self.requests += 1
            if self.requests > 3:
                pytest.fail("evidence pack inventory scanned beyond its limit")
            return SimpleNamespace(name=f"{self.requests}.json")

    entries = Entries()
    monkeypatch.setattr(evidence_pack_module.os, "scandir", lambda _: entries)
    with pytest.raises(ContractError, match="too many entries"):
        evidence_pack_module._inventory_evidence_pack_directory(tmp_path)
    assert entries.requests == 3


def test_evidence_pack_loader_rechecks_population_after_semantic_validation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session_path = tmp_path / "session.json"
    session_path.write_text(json.dumps(_session_doc()), encoding="utf-8")
    out = tmp_path / "pack"
    build_evidence_pack(
        session_path=session_path,
        out_dir=out,
        browser_fact_path=_fact(tmp_path),
    )
    original = evidence_pack_module.validate_browser_fact_snapshot

    def validate_then_appear(document: object) -> dict:
        result = original(document)
        (out / "appeared.txt").write_text("foreign", encoding="utf-8")
        return result

    monkeypatch.setattr(
        evidence_pack_module,
        "validate_browser_fact_snapshot",
        validate_then_appear,
    )
    with pytest.raises(ContractError, match="changed during validation"):
        load_evidence_pack_manifest(out / "manifest.json")
