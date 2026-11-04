from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest

import browser_core.browser_facts as browser_facts_module
import browser_core.control_files as control_files_module
from browser_core.browser_facts import (
    BROWSER_FACT_SCHEMA,
    browser_fact_from_observed,
    browserless_ordinary_facts_from_snapshot,
    build_browser_fact_snapshot,
    capture_browser_fact_from_session,
    capture_browser_fact_playwright,
    load_browser_fact_snapshot,
    validate_browser_fact_snapshot,
    write_browser_fact_snapshot,
)
from browser_core.contracts import ContractError


def _minimal_browser() -> dict:
    return {
        "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/153.0.0.0",
        "platform": "Win32",
        "language": "en-US",
        "languages": ["en-US", "en"],
        "timezone": "America/Chicago",
        "locale": "en-US",
        "hardware_concurrency": 8,
        "screen": {
            "width": 1920,
            "height": 1080,
            "avail_width": 1920,
            "avail_height": 1040,
            "color_depth": 24,
            "pixel_depth": 24,
        },
        "window": {
            "inner_width": 1280,
            "inner_height": 720,
            "outer_width": 1280,
            "outer_height": 800,
            "device_pixel_ratio": 1.0,
        },
        "webgl": {
            "webgl1": {
                "vendor": "Google Inc. (NVIDIA)",
                "renderer": "ANGLE",
                "version": "WebGL 1.0",
            },
            "webgl2": {
                "vendor": "Google Inc. (NVIDIA)",
                "renderer": "ANGLE",
                "version": "WebGL 2.0",
            },
        },
        "automation": {"webdriver": False, "chrome_object": True},
    }


def test_build_and_validate_snapshot_roundtrip(tmp_path: Path) -> None:
    snapshot = build_browser_fact_snapshot(
        snapshot_id="fixture-windows-chrome",
        browser=_minimal_browser(),
        source_kind="fixture",
        source_label="unit-test",
        engine="chromium",
        notes="synthetic fixture",
    )
    assert snapshot["schema"] == BROWSER_FACT_SCHEMA
    assert len(snapshot["integrity_sha256"]) == 64
    path = write_browser_fact_snapshot(tmp_path / "facts.json", snapshot)
    loaded = load_browser_fact_snapshot(path)
    assert loaded == snapshot


def test_browser_fact_loader_rebinds_selected_body_after_validation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    first = build_browser_fact_snapshot(
        snapshot_id="version-one", browser=_minimal_browser(),
        source_kind="fixture", source_label="unit-test",
    )
    second = build_browser_fact_snapshot(
        snapshot_id="version-two", browser=_minimal_browser(),
        source_kind="fixture", source_label="unit-test",
    )
    selected = write_browser_fact_snapshot(tmp_path / "facts.json", first)
    replacement = write_browser_fact_snapshot(tmp_path / "other.json", second)
    initial = selected.stat()
    replacement_body = replacement.read_bytes()
    assert len(replacement_body) == len(selected.read_bytes())
    original_validate = browser_facts_module.validate_browser_fact_snapshot
    changed = False

    def rewrite_after_validation(document: dict) -> dict:
        nonlocal changed
        validated = original_validate(document)
        if not changed:
            changed = True
            selected.write_bytes(replacement_body)
            os.utime(selected, ns=(initial.st_atime_ns, initial.st_mtime_ns))
        return validated

    with monkeypatch.context() as patch:
        patch.setattr(
            browser_facts_module, "validate_browser_fact_snapshot",
            rewrite_after_validation,
        )
        with pytest.raises(ContractError, match="changed"):
            load_browser_fact_snapshot(selected)
    assert changed
    assert selected.read_bytes() == replacement_body
    assert load_browser_fact_snapshot(selected) == second


def test_builder_retains_a_detached_strict_json_population() -> None:
    browser = _minimal_browser()
    source_extra = {"headless": True, "viewport_mode": "synthetic-default"}
    snapshot = build_browser_fact_snapshot(
        snapshot_id="detached",
        browser=browser,
        source_kind="playwright-kernel",
        source_label="unit-test",
        engine="chromium",
        source_extra=source_extra,
    )
    browser["ua"] = "mutated"
    browser["screen"]["width"] = 1
    source_extra["headless"] = False
    source_extra["viewport_mode"] = "native-window"
    assert snapshot["browser"]["ua"] != "mutated"
    assert snapshot["browser"]["screen"]["width"] == 1920
    assert snapshot["source"]["headless"] is True
    assert snapshot["source"]["viewport_mode"] == "synthetic-default"
    assert validate_browser_fact_snapshot(snapshot) == snapshot


def test_forbidden_browser_fact_key_is_not_echoed_in_error() -> None:
    marker = "private-browser-fact-marker"
    browser = _minimal_browser()
    browser[f"password-{marker}"] = "hidden"
    with pytest.raises(ContractError) as caught:
        build_browser_fact_snapshot(
            snapshot_id="redacted-field",
            browser=browser,
            source_kind="fixture",
            source_label="unit-test",
        )
    assert marker not in str(caught.value)


def test_invalid_speech_language_is_not_echoed_in_error() -> None:
    marker = "private-voice-language-marker"
    browser = _minimal_browser()
    browser["speech"] = {
        "api_present": True,
        "voice_count": 1,
        "languages": [marker],
    }
    with pytest.raises(ContractError) as caught:
        build_browser_fact_snapshot(
            snapshot_id="redacted-language",
            browser=browser,
            source_kind="fixture",
            source_label="unit-test",
        )
    assert marker not in str(caught.value)


@pytest.mark.parametrize("source_extra", [
    {"kind": "playwright-kernel", "headless": True,
     "viewport_mode": "synthetic-default"},
    {"label": "substituted-source"},
])
def test_builder_cannot_override_declared_source_identity(source_extra) -> None:
    with pytest.raises(ContractError, match="source_extra cannot override"):
        build_browser_fact_snapshot(
            snapshot_id="source-identity",
            browser=_minimal_browser(),
            source_kind="fixture",
            source_label="unit-test",
            engine="chromium",
            source_extra=source_extra,
        )


@pytest.mark.parametrize(
    ("source_kind", "engine", "source_extra"),
    [
        (
            "fixture",
            None,
            {"build_provenance": "attested-browser-core"},
        ),
        (
            "playwright-kernel",
            "chromium",
            {
                "headless": True,
                "viewport_mode": "synthetic-default",
                "session_run_id": "core-20260817T000000Z-deadbeef",
            },
        ),
        (
            "browser-core-session",
            "browser-core",
            {
                "session_run_id": "core-20260817T000000Z-deadbeef",
                "chromium_revision": "a" * 40,
                "build_provenance": "attested-browser-core",
            },
        ),
        (
            "browser-core-session",
            "browser-core",
            {
                "session_run_id": "core-20260817T000000Z-deadbeef",
                "chromium_revision": "a" * 40,
                "executable_sha256_16": "b" * 16,
                "build_provenance": "unverified-external",
            },
        ),
        (
            "browser-core-session",
            "chromium",
            {
                "session_run_id": "core-20260817T000000Z-deadbeef",
                "chromium_revision": "a" * 40,
                "executable_sha256_16": "b" * 16,
                "build_provenance": "attested-browser-core",
            },
        ),
        (
            "playwright-kernel",
            "browser-core",
            {"headless": True, "viewport_mode": "synthetic-default"},
        ),
    ],
)
def test_browser_fact_source_kind_rejects_stitched_provenance(
    source_kind: str,
    engine: str | None,
    source_extra: dict[str, object],
) -> None:
    with pytest.raises(ContractError, match="source provenance"):
        build_browser_fact_snapshot(
            snapshot_id="source-stitch",
            browser=_minimal_browser(),
            source_kind=source_kind,
            source_label="unit",
            engine=engine,
            source_extra=source_extra,
        )


def test_builder_rejects_invalid_outer_values_without_coercion() -> None:
    with pytest.raises(ContractError, match="source_extra"):
        build_browser_fact_snapshot(
            snapshot_id="outer-values",
            browser=_minimal_browser(),
            source_kind="fixture",
            source_label="unit",
            source_extra=[],  # type: ignore[arg-type]
        )
    with pytest.raises(ContractError, match="captured_at"):
        build_browser_fact_snapshot(
            snapshot_id="outer-values",
            browser=_minimal_browser(),
            source_kind="fixture",
            source_label="unit",
            captured_at="",
        )
    with pytest.raises(ContractError, match="source.kind"):
        build_browser_fact_snapshot(
            snapshot_id="outer-values",
            browser=_minimal_browser(),
            source_kind=[],  # type: ignore[arg-type]
            source_label="unit",
        )
    with pytest.raises(ContractError, match="engine"):
        build_browser_fact_snapshot(
            snapshot_id="outer-values",
            browser=_minimal_browser(),
            source_kind="fixture",
            source_label="unit",
            engine={},  # type: ignore[arg-type]
        )


def test_browser_fact_text_bounds_use_utf8_bytes() -> None:
    browser = _minimal_browser()
    browser["ua"] = "\U0001f642" * 300
    with pytest.raises(ContractError, match="bounded UTF-8"):
        build_browser_fact_snapshot(
            snapshot_id="utf8-bound",
            browser=browser,
            source_kind="fixture",
            source_label="unit",
        )


def test_browser_fact_loader_bounds_source_before_json_parse(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "facts.json"
    path.write_text("{}", encoding="utf-8")
    monkeypatch.setattr(browser_facts_module, "MAX_SNAPSHOT_SOURCE_BYTES", 1)

    with pytest.raises(ContractError, match="browser-fact snapshot exceeds 1 bytes"):
        load_browser_fact_snapshot(path)


def test_browser_fact_loader_normalizes_input_failures(tmp_path: Path) -> None:
    path = tmp_path / "facts.json"
    path.write_bytes(b"\xff")
    with pytest.raises(ContractError, match="encoding is invalid"):
        load_browser_fact_snapshot(path)

    path.write_text("{", encoding="utf-8")
    with pytest.raises(ContractError, match="JSON is invalid"):
        load_browser_fact_snapshot(path)

    with pytest.raises(ContractError, match="browser-fact snapshot is missing"):
        load_browser_fact_snapshot(tmp_path / "missing.json")


def test_rejects_cookie_and_sensor_material() -> None:
    browser = _minimal_browser()
    with pytest.raises(ContractError, match="forbidden|sensitive"):
        build_browser_fact_snapshot(
            snapshot_id="bad",
            browser={**browser, "cookie": "a=b"},
            source_kind="fixture",
            source_label="unit",
        )
    with pytest.raises(ContractError, match="forbidden|sensitive"):
        build_browser_fact_snapshot(
            snapshot_id="bad2",
            browser={**browser, "sensor_data": "x"},
            source_kind="fixture",
            source_label="unit",
        )


@pytest.mark.parametrize(
    "mutate",
    [
        lambda browser: browser.__setitem__("private_detail", "tenant-a"),
        lambda browser: browser["webgl"]["webgl1"].__setitem__(
            "private_detail", "tenant-a"
        ),
        lambda browser: browser["automation"].__setitem__("private_detail", "tenant-a"),
    ],
)
def test_browser_fact_rejects_unknown_nested_fact_fields(mutate) -> None:
    browser = _minimal_browser()
    mutate(browser)

    with pytest.raises(ContractError, match="fields are invalid|required|is invalid"):
        build_browser_fact_snapshot(
            snapshot_id="nested-extra",
            browser=browser,
            source_kind="fixture",
            source_label="unit",
        )


def test_browser_fact_validator_bounds_cyclic_unknown_fields() -> None:
    snapshot = build_browser_fact_snapshot(
        snapshot_id="cyclic-extra",
        browser=_minimal_browser(),
        source_kind="fixture",
        source_label="unit",
    )
    cyclic: dict[str, object] = {}
    cyclic["nested"] = cyclic
    snapshot["browser"]["unknown"] = cyclic

    with pytest.raises(ContractError, match="nesting|fields are invalid"):
        validate_browser_fact_snapshot(snapshot)


def test_browser_fact_validates_client_hint_shape_and_capture_timestamp() -> None:
    browser = _minimal_browser()
    browser["client_hints"] = {
        "brands": [{"brand": "Chromium", "version": "153"}],
        "mobile": False,
        "platform": "Windows",
    }
    snapshot = build_browser_fact_snapshot(
        snapshot_id="client-hints",
        browser=browser,
        source_kind="fixture",
        source_label="unit",
        captured_at="2026-08-10T20:00:00-05:00",
    )
    assert snapshot["browser"]["client_hints"] == browser["client_hints"]

    browser["client_hints"]["private_detail"] = "tenant-a"
    with pytest.raises(ContractError, match="client_hints fields"):
        build_browser_fact_snapshot(
            snapshot_id="bad-client-hints",
            browser=browser,
            source_kind="fixture",
            source_label="unit",
        )

    with pytest.raises(ContractError, match="timezone-aware timestamp"):
        build_browser_fact_snapshot(
            snapshot_id="bad-time",
            browser=_minimal_browser(),
            source_kind="fixture",
            source_label="unit",
            captured_at="private-time-label",
        )


def test_browser_fact_rejects_incoherent_language_and_geometry_facts() -> None:
    mutations = (
        lambda browser: browser.__setitem__("languages", ["en-US", "en-US"]),
        lambda browser: browser.__setitem__("languages", ["private language"]),
        lambda browser: browser.__setitem__("language", "fr-FR"),
        lambda browser: browser["screen"].__setitem__("width", 0),
        lambda browser: browser["screen"].__setitem__("avail_width", 2_000),
        lambda browser: browser["screen"].__setitem__("color_depth", 0),
        lambda browser: browser["window"].__setitem__("outer_height", 100),
        lambda browser: browser["window"].__setitem__("device_pixel_ratio", 10**10_000),
    )
    for mutate in mutations:
        browser = _minimal_browser()
        mutate(browser)
        with pytest.raises(ContractError):
            build_browser_fact_snapshot(
                snapshot_id="incoherent",
                browser=browser,
                source_kind="fixture",
                source_label="unit",
            )

    browser = _minimal_browser()
    browser["device_memory"] = 0.5
    snapshot = build_browser_fact_snapshot(
        snapshot_id="fractional-memory",
        browser=browser,
        source_kind="fixture",
        source_label="unit",
    )
    assert snapshot["browser"]["device_memory"] == 0.5

def test_tampered_integrity_is_rejected() -> None:
    snapshot = build_browser_fact_snapshot(
        snapshot_id="tamper",
        browser=_minimal_browser(),
        source_kind="fixture",
        source_label="unit",
    )
    snapshot["browser"]["hardware_concurrency"] = 16
    with pytest.raises(ContractError, match="integrity"):
        validate_browser_fact_snapshot(snapshot)


def test_browser_fact_from_observed_normalizes_aliases() -> None:
    observed = {
        "userAgent": "Mozilla/5.0 Test",
        "platform": "Win32",
        "language": "en-US",
        "languages": ["en-US"],
        "timezone": "UTC",
        "locale": "en-US",
        "hardwareConcurrency": 4,
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
            "device_pixel_ratio": 1,
        },
        "webgl": {
            "webgl1": {"vendor": "v", "renderer": "r"},
            "webgl2": {"vendor": "v2", "renderer": "r2"},
        },
        "webdriver": False,
    }
    snapshot = browser_fact_from_observed(
        observed,
        snapshot_id="alias-obs",
        source_kind="fixture",
        source_label="aliases",
        engine="chromium",
    )
    assert snapshot["browser"]["ua"] == "Mozilla/5.0 Test"
    assert snapshot["browser"]["hardware_concurrency"] == 4


def test_observed_aliases_do_not_hide_falsey_or_conflicting_values() -> None:
    observed = _minimal_browser()
    observed["hardware_concurrency"] = 0
    with pytest.raises(ContractError, match="hardware_concurrency"):
        browser_fact_from_observed(
            observed,
            snapshot_id="falsey-primary",
            source_kind="fixture",
            source_label="unit",
        )

    observed = _minimal_browser()
    observed["hardwareConcurrency"] = 16
    with pytest.raises(ContractError, match="aliases conflict"):
        browser_fact_from_observed(
            observed,
            snapshot_id="alias-conflict",
            source_kind="fixture",
            source_label="unit",
        )


def test_observed_automation_is_not_truthiness_coerced() -> None:
    observed = _minimal_browser()
    observed["automation"] = {}
    observed["webdriver"] = False
    with pytest.raises(ContractError, match="webdriver is required"):
        browser_fact_from_observed(
            observed,
            snapshot_id="empty-automation",
            source_kind="fixture",
            source_label="unit",
        )

    observed = _minimal_browser()
    observed.pop("automation")
    observed["webdriver"] = "false"
    with pytest.raises(ContractError, match="webdriver must be boolean"):
        browser_fact_from_observed(
            observed,
            snapshot_id="text-webdriver",
            source_kind="fixture",
            source_label="unit",
        )


def test_live_playwright_capture_is_validated() -> None:
    snapshot = capture_browser_fact_playwright(
        snapshot_id="live-chromium-unit",
        engine="chromium",
        locale="en-US",
        timezone="America/Chicago",
        headless=True,
    )
    assert snapshot["source"]["kind"] == "playwright-kernel"
    assert (
        "Chrome" in snapshot["browser"]["ua"] or "Chromium" in snapshot["browser"]["ua"]
    )
    # Playwright-managed Chromium may report webdriver=true; the snapshot must
    # record the observed value rather than rewrite it into a false pass.
    assert isinstance(snapshot["browser"]["automation"]["webdriver"], bool)
    assert isinstance(
        snapshot["browser"]["webgl"]["webgl1"]["vendor"], (str, type(None))
    )
    assert snapshot["browser"]["timezone"] == "America/Chicago"
    # Re-validate as pure document path.
    assert validate_browser_fact_snapshot(json.loads(json.dumps(snapshot))) == snapshot


def test_capture_from_session_binds_attestation_and_calls_cdp(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    session = {
        "schema": "browser-core.session/1",
        "run_id": "core-20260804T000000Z-deadbeef",
        "chromium_revision": "bf6d8a66b43635a532bdad773407285fac0121e9",
        "pid": 4242,
        "state": "active",
        "created_at": "2026-08-04T00:00:00Z",
        "build": {
            "provenance": "attested-browser-core",
            "executable_sha256_16": "b724ca5670da28af",
        },
        "automation": {
            "transport": "cdp",
            "cdp_endpoint": "http://127.0.0.1:9333",
            "managed_target_url": "data:text/html,%3Ctitle%3Ebrowser-core-identity-test%3C%2Ftitle%3E",
        },
        "trace_mode": "off",
        "trace_categories": [],
    }
    session_path = tmp_path / "session.json"
    session_path.write_text(json.dumps(session), encoding="utf-8")

    observed = {
        "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/153.0.0.0",
        "platform": "Win32",
        "language": "en-US",
        "languages": ["en-US"],
        "timezone": "America/Chicago",
        "locale": "en-US",
        "hardware_concurrency": 8,
        "screen": {
            "width": 1920,
            "height": 1080,
            "avail_width": 1920,
            "avail_height": 1040,
            "color_depth": 24,
            "pixel_depth": 24,
        },
        "window": {
            "inner_width": 1280,
            "inner_height": 720,
            "outer_width": 1280,
            "outer_height": 800,
            "device_pixel_ratio": 1.0,
        },
        "webgl": {
            "webgl1": {"vendor": "v", "renderer": "r", "version": "WebGL 1.0"},
            "webgl2": {"vendor": "v2", "renderer": "r2", "version": "WebGL 2.0"},
        },
        "automation": {"webdriver": False, "chrome_object": True},
    }

    def fake_eval(endpoint, expression, **kwargs):  # noqa: ANN001
        assert endpoint == "http://127.0.0.1:9333"
        assert kwargs.get("target_url") == session["automation"]["managed_target_url"]
        assert "()" in expression
        return observed

    monkeypatch.setattr("browser_core.cdp.evaluate_page_expression", fake_eval)

    snapshot = capture_browser_fact_from_session(
        session_path,
        snapshot_id="core-session-facts",
    )
    assert snapshot["source"]["kind"] == "browser-core-session"
    assert snapshot["source"]["session_run_id"] == session["run_id"]
    assert snapshot["source"]["chromium_revision"] == session["chromium_revision"]
    assert snapshot["source"]["executable_sha256_16"] == "b724ca5670da28af"
    assert snapshot["source"]["build_provenance"] == "attested-browser-core"
    assert "127.0.0.1" not in json.dumps(snapshot)
    assert "cdp_endpoint" not in json.dumps(snapshot)
    mapped = browserless_ordinary_facts_from_snapshot(snapshot)
    assert mapped["ua"] == observed["ua"]
    assert mapped["schema"] == "browser-core.browserless-ordinary-facts/1"


@pytest.mark.parametrize(
    ("arguments", "message"),
    [
        ({"session_path": "session.json"}, "path must be a Path"),
        ({"timeout_seconds": float("inf")}, "timeout must be finite"),
        ({"timeout_seconds": 10**400}, "timeout must be finite"),
        ({"target_url": ""}, "target_url"),
        ({"snapshot_id": "private id"}, "snapshot_id"),
    ],
)
def test_session_capture_preflights_before_session_load(
    monkeypatch,
    arguments,
    message,
) -> None:
    import browser_core.contracts as contracts_module

    contacted = False

    def forbidden_load(_path):
        nonlocal contacted
        contacted = True
        raise AssertionError("session load")

    monkeypatch.setattr(contracts_module, "load_session_snapshot", forbidden_load)
    request = {"session_path": Path("session.json"), "snapshot_id": "snapshot"}
    request.update(arguments)
    with pytest.raises(ContractError, match=message):
        capture_browser_fact_from_session(**request)
    assert contacted is False


def test_session_capture_shares_deadline_with_speech_poll(
    monkeypatch,
) -> None:
    import browser_core.cdp as cdp_module
    import browser_core.contracts as contracts_module

    clock = [10.0]
    budgets = []
    session = {
        "state": "active",
        "run_id": "core-20260804T000000Z-deadbeef",
        "chromium_revision": "b" * 40,
        "build": {
            "provenance": "attested-browser-core",
            "executable_sha256_16": "a" * 16,
        },
        "automation": {
            "cdp_endpoint": "http://127.0.0.1:9333",
            "managed_target_url": "about:blank#owned",
        },
    }
    snapshot = contracts_module.SessionContractSnapshot(
        document=session,
        body=b"session",
        identity=(1, 2, 0o100000, 7, 8, 9),
    )
    monkeypatch.setattr(
        contracts_module,
        "load_session_snapshot",
        lambda _path: snapshot,
    )
    monkeypatch.setattr(browser_facts_module.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(
        browser_facts_module.time,
        "sleep",
        lambda delay: clock.__setitem__(0, clock[0] + delay),
    )

    def evaluate(_endpoint, _expression, *, timeout_seconds, command_id, **_kwargs):
        budgets.append(timeout_seconds)
        if command_id == 943:
            clock[0] += 0.6
            return _minimal_browser()
        clock[0] += 0.3
        return {
            "api_present": True,
            "voice_count": 0,
            "languages": [],
            "local_service_count": 0,
            "default_count": 0,
        }

    monkeypatch.setattr(cdp_module, "evaluate_page_expression", evaluate)
    with pytest.raises(ContractError, match="capture timed out"):
        capture_browser_fact_from_session(
            Path("session.json"),
            snapshot_id="deadline",
            timeout_seconds=1.0,
        )
    assert budgets == pytest.approx([1.0, 0.4])


def test_session_capture_rebinds_the_exact_active_session(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import browser_core.cdp as cdp_module
    import browser_core.contracts as contracts_module

    session = {
        "state": "active",
        "run_id": "core-20260804T000000Z-deadbeef",
        "chromium_revision": "b" * 40,
        "build": {
            "provenance": "attested-browser-core",
            "executable_sha256_16": "a" * 16,
        },
        "automation": {
            "cdp_endpoint": "http://127.0.0.1:9333",
            "managed_target_url": "about:blank#owned",
        },
    }
    initial = contracts_module.SessionContractSnapshot(
        document=session,
        body=b"active-session",
        identity=(1, 2, 0o100000, 14, 15, 16),
    )
    changed = contracts_module.SessionContractSnapshot(
        document={**session, "state": "stopped"},
        body=b"stopped-session",
        identity=(1, 3, 0o100000, 15, 16, 17),
    )
    snapshots = iter((initial, changed))
    monkeypatch.setattr(
        contracts_module,
        "load_session_snapshot",
        lambda _path: next(snapshots),
    )

    def evaluate(_endpoint, _expression, *, command_id, **_kwargs):  # noqa: ANN001
        if command_id == 943:
            return _minimal_browser()
        return {
            "api_present": True,
            "voice_count": 1,
            "languages": ["en-US"],
            "local_service_count": 1,
            "default_count": 1,
        }

    monkeypatch.setattr(cdp_module, "evaluate_page_expression", evaluate)
    with pytest.raises(ContractError, match="session changed during capture"):
        capture_browser_fact_from_session(
            Path("session.json"),
            snapshot_id="session-rebind",
        )


def test_session_capture_deadline_includes_closing_rebind(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import browser_core.cdp as cdp_module
    import browser_core.contracts as contracts_module

    clock = [20.0]
    session = {
        "state": "active",
        "run_id": "core-20260804T000000Z-deadbeef",
        "chromium_revision": "b" * 40,
        "build": {
            "provenance": "attested-browser-core",
            "executable_sha256_16": "a" * 16,
        },
        "automation": {
            "cdp_endpoint": "http://127.0.0.1:9333",
            "managed_target_url": "about:blank#owned",
        },
    }
    snapshot = contracts_module.SessionContractSnapshot(
        document=session,
        body=b"active-session",
        identity=(1, 2, 0o100000, 14, 15, 16),
    )
    loads = 0

    def load(_path: Path):  # noqa: ANN202
        nonlocal loads
        loads += 1
        if loads == 2:
            clock[0] += 2.0
        return snapshot

    monkeypatch.setattr(browser_facts_module.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(contracts_module, "load_session_snapshot", load)

    def evaluate(_endpoint, _expression, *, command_id, **_kwargs):  # noqa: ANN001
        if command_id == 943:
            return _minimal_browser()
        return {
            "api_present": True,
            "voice_count": 1,
            "languages": ["en-US"],
            "local_service_count": 1,
            "default_count": 1,
        }

    monkeypatch.setattr(cdp_module, "evaluate_page_expression", evaluate)
    with pytest.raises(ContractError, match="capture timed out"):
        capture_browser_fact_from_session(
            Path("session.json"),
            snapshot_id="closing-deadline",
            timeout_seconds=1.0,
        )
    assert loads == 2


@pytest.mark.parametrize(
    ("keyword", "value", "message"),
    [
        ("engine", [], "engine is unsupported"),
        ("locale", "\ud800", "bounded UTF-8"),
        ("timezone", "UTC\nprivate", "bounded UTF-8"),
        ("headless", 1, "headless must be boolean"),
        ("timeout_seconds", True, "timeout must be finite"),
        ("timeout_seconds", 10**400, "timeout must be finite"),
    ],
)
def test_playwright_capture_preflights_public_values(keyword, value, message) -> None:
    arguments = {"snapshot_id": "playwright-preflight", keyword: value}
    with pytest.raises(ContractError, match=message):
        capture_browser_fact_playwright(**arguments)


@pytest.mark.parametrize(
    ("headless", "expected_viewport_mode", "expects_no_viewport"),
    [
        (True, "synthetic-default", False),
        (False, "native-window", True),
    ],
)
def test_playwright_capture_binds_launch_and_viewport_method(
    monkeypatch: pytest.MonkeyPatch,
    headless: bool,
    expected_viewport_mode: str,
    expects_no_viewport: bool,
) -> None:
    import playwright.sync_api

    launch_kwargs: dict[str, object] = {}
    context_kwargs: dict[str, object] = {}
    evaluations = 0

    class Page:
        def set_default_timeout(self, _timeout: int) -> None:
            pass

        def set_content(self, _content: str, **_kwargs: object) -> None:
            pass

        def evaluate(self, _expression: str):  # noqa: ANN201
            nonlocal evaluations
            evaluations += 1
            if evaluations == 1:
                return _minimal_browser()
            return {
                "api_present": True,
                "voice_count": 1,
                "languages": ["en-US"],
                "local_service_count": 1,
                "default_count": 1,
            }

    class Context:
        def new_page(self) -> Page:
            return Page()

        def close(self) -> None:
            pass

    class Browser:
        def new_context(self, **kwargs: object) -> Context:
            context_kwargs.update(kwargs)
            return Context()

        def close(self) -> None:
            pass

    class BrowserType:
        def launch(self, **kwargs: object) -> Browser:
            launch_kwargs.update(kwargs)
            return Browser()

    class Playwright:
        chromium = BrowserType()

        def stop(self) -> None:
            pass

    class Manager:
        def start(self) -> Playwright:
            return Playwright()

    monkeypatch.setattr(playwright.sync_api, "sync_playwright", lambda: Manager())
    snapshot = capture_browser_fact_playwright(
        snapshot_id=f"playwright-method-{expected_viewport_mode}",
        headless=headless,
    )

    assert launch_kwargs["headless"] is headless
    assert context_kwargs == {
        "locale": "en-US",
        "timezone_id": "America/Chicago",
        **({"no_viewport": True} if expects_no_viewport else {}),
    }
    assert snapshot["source"]["headless"] is headless
    assert snapshot["source"]["viewport_mode"] == expected_viewport_mode
    assert validate_browser_fact_snapshot(snapshot) == snapshot


def test_playwright_capture_waits_for_observed_window_geometry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import playwright.sync_api

    observations: list[str] = []
    collects = 0

    class Page:
        def set_default_timeout(self, _timeout: int) -> None:
            pass

        def set_content(self, _content: str, **_kwargs: object) -> None:
            pass

        def evaluate(self, expression: str):  # noqa: ANN201
            nonlocal collects
            if "glContext" in expression:
                collects += 1
                observations.append("collect")
                facts = _minimal_browser()
                if collects == 1:
                    facts["window"]["inner_width"] = 0
                return facts
            if expression.startswith("Boolean(window.innerWidth"):
                observations.append("ready")
                return True
            observations.append("speech")
            return {
                "api_present": True,
                "voice_count": 1,
                "languages": ["en-US"],
                "local_service_count": 1,
                "default_count": 1,
            }

    class Context:
        def new_page(self) -> Page:
            return Page()

        def close(self) -> None:
            pass

    class Browser:
        def new_context(self, **_kwargs: object) -> Context:
            return Context()

        def close(self) -> None:
            pass

    class BrowserType:
        def launch(self, **_kwargs: object) -> Browser:
            return Browser()

    class Playwright:
        chromium = BrowserType()

        def stop(self) -> None:
            pass

    class Manager:
        def start(self) -> Playwright:
            return Playwright()

    monkeypatch.setattr(playwright.sync_api, "sync_playwright", lambda: Manager())
    monkeypatch.setattr(browser_facts_module.time, "sleep", lambda _delay: None)
    snapshot = capture_browser_fact_playwright(snapshot_id="startup-window", headless=False)
    assert snapshot["browser"]["window"]["inner_width"] == 1280
    assert observations == ["collect", "ready", "collect", "speech"]


@pytest.mark.parametrize(
    "source_extra",
    [
        {"headless": False},
        {"viewport_mode": "native-window"},
        {"headless": True, "viewport_mode": "native-window"},
        {"headless": False, "viewport_mode": "synthetic-default"},
        {"headless": False, "viewport_mode": "private-mode"},
    ],
)
def test_playwright_capture_method_provenance_is_closed(
    source_extra: dict[str, object],
) -> None:
    with pytest.raises(ContractError, match="source capture method"):
        build_browser_fact_snapshot(
            snapshot_id="playwright-method-invalid",
            browser=_minimal_browser(),
            source_kind="playwright-kernel",
            source_label="playwright:chromium",
            engine="chromium",
            source_extra=source_extra,
        )


def test_playwright_capture_normalizes_private_runtime_failure(monkeypatch) -> None:
    import playwright.sync_api

    private = r"C:\private\browser with tenant-token"
    monkeypatch.setattr(
        playwright.sync_api,
        "sync_playwright",
        lambda: (_ for _ in ()).throw(OSError(private)),
    )
    with pytest.raises(ContractError) as failure:
        capture_browser_fact_playwright(snapshot_id="playwright-failure")
    assert str(failure.value) == "Playwright browser-fact capture failed (OSError)"
    assert private not in str(failure.value)


def test_playwright_capture_runs_all_cleanup_and_retains_safe_active_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import playwright.sync_api

    phases: list[str] = []

    class Page:
        def set_default_timeout(self, _timeout: int) -> None:
            pass

        def set_content(self, _content: str, **_kwargs: object) -> None:
            pass

        def evaluate(self, _expression: str):  # noqa: ANN201
            raise OSError(r"C:\private\collector tenant-token")

    class Context:
        def new_page(self) -> Page:
            return Page()

        def close(self) -> None:
            phases.append("context-close")
            raise RuntimeError("private context close")

    class Browser:
        def new_context(self, **_kwargs: object) -> Context:
            return Context()

        def close(self) -> None:
            phases.append("browser-close")
            raise RuntimeError("private browser close")

    class BrowserType:
        def launch(self, **_kwargs: object) -> Browser:
            return Browser()

    class Playwright:
        chromium = BrowserType()

        def stop(self) -> None:
            phases.append("playwright-stop")
            raise RuntimeError("private playwright stop")

    class Manager:
        def start(self) -> Playwright:
            return Playwright()

    monkeypatch.setattr(playwright.sync_api, "sync_playwright", lambda: Manager())
    with pytest.raises(ContractError) as failure:
        capture_browser_fact_playwright(snapshot_id="cleanup-failure")

    assert str(failure.value) == (
        "Playwright browser-fact cleanup failed "
        "(context-close,browser-close,playwright-stop)"
    )
    assert phases == ["context-close", "browser-close", "playwright-stop"]
    assert isinstance(failure.value.__cause__, ContractError)
    assert str(failure.value.__cause__) == (
        "Playwright browser-fact capture failed (OSError)"
    )
    assert "private" not in str(failure.value)
    assert "private" not in str(failure.value.__cause__)


def test_playwright_capture_deadline_includes_cleanup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import playwright.sync_api

    clock = [50.0]
    launch_timeouts: list[int] = []

    class Page:
        def set_default_timeout(self, _timeout: int) -> None:
            pass

        def set_content(self, _content: str, **_kwargs: object) -> None:
            pass

        def evaluate(self, expression: str):  # noqa: ANN201
            if "speechSynthesis" not in expression:
                return _minimal_browser()
            return {
                "api_present": True,
                "voice_count": 1,
                "languages": ["en-US"],
                "local_service_count": 1,
                "default_count": 1,
            }

    class Context:
        def new_page(self) -> Page:
            return Page()

        def close(self) -> None:
            pass

    class Browser:
        def new_context(self, **_kwargs: object) -> Context:
            return Context()

        def close(self) -> None:
            pass

    class BrowserType:
        def launch(self, **kwargs: object) -> Browser:
            launch_timeouts.append(kwargs["timeout"])  # type: ignore[arg-type]
            return Browser()

    class Playwright:
        chromium = BrowserType()

        def stop(self) -> None:
            clock[0] += 2.0

    class Manager:
        def start(self) -> Playwright:
            return Playwright()

    monkeypatch.setattr(browser_facts_module.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(playwright.sync_api, "sync_playwright", lambda: Manager())
    with pytest.raises(ContractError, match="capture timed out"):
        capture_browser_fact_playwright(
            snapshot_id="cleanup-deadline",
            timeout_seconds=1.0,
        )
    assert launch_timeouts == [1000]


def test_playwright_capture_requires_exact_cleanup_acknowledgments(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import playwright.sync_api

    phases: list[str] = []
    evaluations = 0

    class Page:
        def set_default_timeout(self, _timeout: int) -> None:
            pass

        def set_content(self, _content: str, **_kwargs: object) -> None:
            pass

        def evaluate(self, _expression: str):  # noqa: ANN201
            nonlocal evaluations
            evaluations += 1
            if evaluations == 1:
                return _minimal_browser()
            return {
                "api_present": True,
                "voice_count": 1,
                "languages": ["en-US"],
                "local_service_count": 1,
                "default_count": 1,
            }

    class Context:
        def new_page(self) -> Page:
            return Page()

        def close(self) -> bool:
            phases.append("context-close")
            return True

    class Browser:
        def new_context(self, **_kwargs: object) -> Context:
            return Context()

        def close(self) -> None:
            phases.append("browser-close")

    class BrowserType:
        def launch(self, **_kwargs: object) -> Browser:
            return Browser()

    class Playwright:
        chromium = BrowserType()

        def stop(self) -> bool:
            phases.append("playwright-stop")
            return False

    class Manager:
        def start(self) -> Playwright:
            return Playwright()

    monkeypatch.setattr(playwright.sync_api, "sync_playwright", lambda: Manager())
    with pytest.raises(ContractError) as failure:
        capture_browser_fact_playwright(snapshot_id="cleanup-ack")

    assert str(failure.value) == (
        "Playwright browser-fact cleanup failed (context-close,playwright-stop)"
    )
    assert phases == ["context-close", "browser-close", "playwright-stop"]


def test_session_capture_requires_active_session(tmp_path: Path) -> None:
    session = {
        "schema": "browser-core.session/1",
        "run_id": "core-20260804T000000Z-deadbeef",
        "chromium_revision": "bf6d8a66b43635a532bdad773407285fac0121e9",
        "pid": 1,
        "state": "stopped",
        "automation": {
            "transport": "cdp",
            "cdp_endpoint": "http://127.0.0.1:9333",
        },
        "trace_mode": "off",
        "trace_categories": [],
    }
    path = tmp_path / "stopped.json"
    path.write_text(json.dumps(session), encoding="utf-8")
    with pytest.raises(ContractError, match="active session"):
        capture_browser_fact_from_session(path, snapshot_id="x")


def test_browser_fact_write_preserves_destination_that_wins_publication_race(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    snapshot = build_browser_fact_snapshot(
        snapshot_id="write-race",
        browser=_minimal_browser(),
        source_kind="fixture",
        source_label="unit",
    )
    destination = tmp_path / "facts.json"
    original_link = control_files_module.os.link

    def _racing_link(source: Path, target: Path, **kwargs: object) -> None:
        Path(target).write_bytes(b"foreign snapshot")
        original_link(source, target, **kwargs)

    monkeypatch.setattr(control_files_module.os, "link", _racing_link)

    with pytest.raises(ContractError, match="publication failed"):
        write_browser_fact_snapshot(destination, snapshot)

    assert destination.read_bytes() == b"foreign snapshot"
    assert not list(tmp_path.glob(".facts.json.tmp-*"))


def test_browser_fact_writer_freezes_document_before_final_encoding(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    snapshot = build_browser_fact_snapshot(
        snapshot_id="mutable-input",
        browser=_minimal_browser(),
        source_kind="fixture",
        source_label="unit",
    )
    expected = json.loads(json.dumps(snapshot))
    original_dumps = browser_facts_module.json.dumps

    def mutate_caller_before_pretty_encoding(value, *args, **kwargs):  # noqa: ANN001, ANN201
        if kwargs.get("indent") == 2:
            snapshot["browser"]["ua"] = "changed after validation"
        return original_dumps(value, *args, **kwargs)

    monkeypatch.setattr(
        browser_facts_module.json, "dumps", mutate_caller_before_pretty_encoding
    )
    path = write_browser_fact_snapshot(tmp_path / "facts.json", snapshot)
    assert load_browser_fact_snapshot(path) == expected


@pytest.mark.skipif(os.name != "nt", reason="Windows directory junction boundary")
def test_browser_fact_writer_rejects_junction_output_before_resolution(tmp_path: Path) -> None:
    snapshot = build_browser_fact_snapshot(
        snapshot_id="junction-output",
        browser=_minimal_browser(),
        source_kind="fixture",
        source_label="unit",
    )
    target = tmp_path / "target"
    target.mkdir()
    junction = tmp_path / "facts.json"
    created = subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(junction), str(target)],
        capture_output=True, check=False,
    )
    if created.returncode:
        pytest.skip("host could not create an unprivileged directory junction")
    try:
        assert not junction.is_symlink() and junction.resolve() == target
        with pytest.raises(ContractError, match="reparse|junction"):
            write_browser_fact_snapshot(junction, snapshot)
        assert list(target.iterdir()) == []
    finally:
        junction.rmdir()


@pytest.mark.skipif(os.name != "nt", reason="Windows directory junction boundary")
def test_browser_fact_writer_rejects_junction_parent_without_touching_target(tmp_path: Path) -> None:
    snapshot = build_browser_fact_snapshot(
        snapshot_id="junction-parent",
        browser=_minimal_browser(),
        source_kind="fixture",
        source_label="unit",
    )
    target = tmp_path / "foreign"
    target.mkdir()
    junction = tmp_path / "redirected"
    created = subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(junction), str(target)],
        capture_output=True, check=False,
    )
    if created.returncode:
        pytest.skip("host could not create an unprivileged directory junction")
    try:
        with pytest.raises(ContractError, match="owned regular directory|reparse|junction"):
            write_browser_fact_snapshot(junction / "facts.json", snapshot)
        assert list(target.iterdir()) == []
    finally:
        junction.rmdir()


@pytest.mark.skipif(os.name != "nt", reason="Windows directory junction boundary")
def test_browser_fact_writer_rejects_parent_swapped_after_preparation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    snapshot = build_browser_fact_snapshot(
        snapshot_id="parent-swap",
        browser=_minimal_browser(),
        source_kind="fixture",
        source_label="unit",
    )
    owned = tmp_path / "owned"
    owned.mkdir()
    moved = tmp_path / "moved"
    foreign = tmp_path / "foreign"
    foreign.mkdir()
    original_prepare = browser_facts_module.prepare_owned_directory_parent
    linked = False

    def redirect_after_prepare(parent: Path, *, label: str) -> None:
        nonlocal linked
        original_prepare(parent, label=label)
        owned.rename(moved)
        created = subprocess.run(
            ["cmd", "/c", "mklink", "/J", str(owned), str(foreign)],
            capture_output=True,
            check=False,
        )
        if created.returncode:
            pytest.skip("host could not create an unprivileged directory junction")
        linked = True

    monkeypatch.setattr(
        browser_facts_module, "prepare_owned_directory_parent", redirect_after_prepare
    )
    try:
        with pytest.raises(ContractError):
            write_browser_fact_snapshot(owned / "facts.json", snapshot)
        assert list(foreign.iterdir()) == []
    finally:
        if linked:
            owned.rmdir()


def test_browser_fact_snapshot_is_strict_single_link_and_path_typed(
    tmp_path: Path,
) -> None:
    snapshot = build_browser_fact_snapshot(
        snapshot_id="strict-fixture",
        browser=_minimal_browser(),
        source_kind="fixture",
        source_label="unit",
    )
    path = write_browser_fact_snapshot(tmp_path / "facts.json", snapshot)
    body = path.read_bytes()
    path.write_bytes(body.replace(b'"schema":', b'"schema":"duplicate","schema":', 1))
    with pytest.raises(ContractError, match="duplicate key"):
        load_browser_fact_snapshot(path)

    path.write_bytes(body)
    os.link(path, tmp_path / "facts-alias.json")
    with pytest.raises(ContractError, match="hard links"):
        load_browser_fact_snapshot(path)
    with pytest.raises(ContractError, match="path must be a Path"):
        load_browser_fact_snapshot(str(path))  # type: ignore[arg-type]
    with pytest.raises(ContractError, match="destination must be a Path"):
        write_browser_fact_snapshot(  # type: ignore[arg-type]
            str(tmp_path / "other.json"),
            snapshot,
        )


def test_browser_fact_writer_verifies_the_final_link_population(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    snapshot = build_browser_fact_snapshot(
        snapshot_id="publication-link-race",
        browser=_minimal_browser(),
        source_kind="fixture",
        source_label="unit",
    )
    destination = tmp_path / "facts.json"
    alias = tmp_path / "facts-alias.json"
    original_link = control_files_module.os.link

    def publish_then_alias(source: Path, target: Path, **kwargs: object) -> None:
        original_link(source, target, **kwargs)
        original_link(target, alias)

    monkeypatch.setattr(control_files_module.os, "link", publish_then_alias)
    with pytest.raises(ContractError, match="publication failed"):
        write_browser_fact_snapshot(destination, snapshot)
    assert not destination.exists()
    assert alias.exists()
