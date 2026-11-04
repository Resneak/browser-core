from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

import browser_core.kernels as kernels_module
from browser_core.contracts import ContractError
from browser_core.kernels import (
    KERNEL_SCHEMA,
    REALISTIC_DESKTOP_MEMORY_MB,
    REALISTIC_MOBILE_MEMORY_MB,
    align_user_agent_version,
    approximate_device_memory,
    device_from_playwright,
    discover_kernels,
    playwright_device_catalog,
    playwright_device_contract_catalog,
    probe_playwright_kernel,
    probe_playwright_kernel_batch,
    relocalize_playwright_device,
    validate_device,
    validate_kernel,
)
from test_build import _write_fixture_attestation


ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.skipif(os.name != "nt", reason="Windows directory junction boundary")
def test_kernel_discovery_rejects_selected_browser_core_runtime_junction(
    tmp_path: Path,
) -> None:
    physical_runtime = tmp_path / "physical-runtime"
    physical_runtime.mkdir()
    executable, _receipt, _document = _write_fixture_attestation(physical_runtime)
    selected_runtime = tmp_path / "selected-runtime"
    linked = subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(selected_runtime), str(physical_runtime)],
        capture_output=True,
    )
    if linked.returncode:
        pytest.skip("host could not create an unprivileged directory junction")
    try:
        with pytest.raises(ContractError, match="not a verified Browser Core build"):
            discover_kernels(
                ROOT, browser_core_executable=selected_runtime / executable.name
            )
    finally:
        selected_runtime.rmdir()


def _valid_kernel_contract() -> dict[str, object]:
    return {
        "schema": KERNEL_SCHEMA,
        "id": "kernel-1",
        "engine": "chromium",
        "product": "chromium",
        "available": True,
        "executable": str(Path(__file__).resolve()),
        "executable_sha256_16": "0123456789abcdef",
        "unavailable_reason": None,
        "capabilities": ["desktop"],
        "source": {"kind": "playwright-managed", "playwright_version": "1.0"},
    }


@pytest.mark.parametrize(
    "field, malformed",
    [
        ("engine", []),
        ("product", {}),
        ("capabilities", [[]]),
        ("capabilities", ["desktop", 1]),
    ],
)
def test_kernel_contract_rejects_malformed_json_values(field: str, malformed: object) -> None:
    kernel = _valid_kernel_contract()
    kernel[field] = malformed
    with pytest.raises(ContractError):
        validate_kernel(kernel)


def test_kernel_contract_rejects_unhashable_source_kind() -> None:
    kernel = _valid_kernel_contract()
    kernel["source"] = {"kind": []}
    with pytest.raises(ContractError):
        validate_kernel(kernel)


@pytest.mark.parametrize(
    "changes",
    [
        {"product": "browser-core"},
        {"source": {"kind": "playwright-managed", "playwright_version": "\nprivate"}},
        {"source": {"kind": "playwright-managed"}},
        {"source": {"kind": "attested-browser-core"}},
    ],
)
def test_kernel_contract_rejects_source_and_product_mislabeling(changes: dict[str, object]) -> None:
    kernel = _valid_kernel_contract()
    kernel.update(changes)
    with pytest.raises(ContractError, match="kernel source"):
        validate_kernel(kernel)


def test_attested_kernel_source_digest_must_match_the_capability_digest() -> None:
    kernel = _valid_kernel_contract()
    kernel.update(product="browser-core")
    kernel["source"] = {
        "kind": "attested-browser-core",
        "provenance": "attested-browser-core",
        "executable_sha256_16": "fedcba9876543210",
        "runtime_bundle_sha256_16": "0123456789abcdef",
        "attestation_created_at": "2026-10-24T00:00:00Z",
    }
    with pytest.raises(ContractError, match="kernel source"):
        validate_kernel(kernel)


@pytest.mark.parametrize("field", ["class", "realization", "default_engine"])
def test_device_contract_rejects_unhashable_enums(field: str) -> None:
    device = device_from_playwright("iPhone 13", locale="en-US", timezone="America/Chicago")
    device[field] = []
    with pytest.raises(ContractError):
        validate_device(device)


def test_device_contract_rejects_unhashable_provenance_kind() -> None:
    device = device_from_playwright("iPhone 13", locale="en-US", timezone="America/Chicago")
    device["provenance"]["kind"] = []
    with pytest.raises(ContractError):
        validate_device(device)


@pytest.mark.parametrize(
    "field, malformed",
    [
        ("name", "owned\nprivate"),
        ("user_agent", "Mozilla/5.0\r\nPrivate: value"),
        ("locale", "en\n-US"),
        ("timezone", "America/Chi\ud800cago"),
        ("user_agent", "x" * 4097),
    ],
)
def test_device_contract_rejects_unbounded_or_nonprintable_text(
    field: str, malformed: str
) -> None:
    device = {
        "schema": "browser-core.device/1",
        "id": "owned-device",
        "name": "Owned device",
        "class": "desktop",
        "realization": "emulated",
        "default_engine": "chromium",
        "is_mobile": False,
        "has_touch": False,
        "viewport": {"width": 1280, "height": 720},
        "screen": {"width": 1280, "height": 720},
        "device_scale_factor": 1,
        "user_agent": "Mozilla/5.0",
        "locale": "en-US",
        "timezone": "America/Chicago",
        "provenance": {"kind": "owned"},
    }
    device[field] = malformed
    with pytest.raises(ContractError, match=f"device {field.replace('_', ' ')}"):
        validate_device(device)


@pytest.mark.parametrize(
    "function, kwargs",
    [
        ("device_from_playwright", {"name": "iPhone 13", "locale": "en\n-US", "timezone": "America/Chicago"}),
        ("playwright_device_contract_catalog", {"locale": "en-US", "timezone": "America/Chi\ud800cago"}),
    ],
)
def test_invalid_device_context_text_fails_before_playwright_start(
    monkeypatch: pytest.MonkeyPatch, function: str, kwargs: dict[str, str]
) -> None:
    monkeypatch.setattr(
        kernels_module,
        "_playwright",
        lambda: pytest.fail("invalid device context reached Playwright"),
    )
    with pytest.raises(ContractError):
        getattr(kernels_module, function)(**kwargs)


def test_playwright_catalog_is_real_and_device_contract_is_explicit() -> None:
    catalog = playwright_device_catalog("iPhone 13")
    assert catalog and all("iPhone 13" in item["name"] for item in catalog)
    devices = playwright_device_contract_catalog(
        locale="en-US",
        timezone="America/Chicago",
        pattern="iPhone 13",
    )
    device = next(item for item in devices if item["name"] == "iPhone 13")
    assert device["schema"] == "browser-core.device/1"
    assert device["realization"] == "emulated"
    assert device["default_engine"] == "webkit"
    assert device["is_mobile"] is True and device["has_touch"] is True
    localized = relocalize_playwright_device(
        device,
        locale="fr-FR",
        timezone="Europe/Paris",
    )
    assert localized["locale"] == "fr-FR"
    assert localized["timezone"] == "Europe/Paris"
    assert localized["viewport"] == device["viewport"]
    assert localized["provenance"] == device["provenance"]


def test_device_contract_rejects_mobile_without_touch() -> None:
    device = device_from_playwright("iPhone 13", locale="en-US", timezone="America/Chicago")
    device["has_touch"] = False
    with pytest.raises(ContractError, match="mobile touch"):
        validate_device(device)


def test_discovery_reports_exact_availability() -> None:
    kernels = discover_kernels(ROOT)
    assert {item["id"] for item in kernels} == {
        "playwright-chromium",
        "playwright-firefox",
        "playwright-webkit",
    }
    for item in kernels:
        assert Path(item["executable"]).is_file() is item["available"]
        if item["available"]:
            assert item["executable_sha256_16"]
        else:
            assert item["unavailable_reason"]


def test_available_chromium_executes_owned_device_probe() -> None:
    kernel = next(item for item in discover_kernels(ROOT) if item["id"] == "playwright-chromium")
    if not kernel["available"]:
        pytest.skip("Playwright Chromium is not installed")
    device = device_from_playwright("Desktop Chrome HiDPI", locale="en-US", timezone="America/Chicago")
    result = probe_playwright_kernel(kernel, device)
    assert result["passed"] is True
    assert all(result["checks"].values())


def test_firefox_mobile_contract_fails_closed_even_if_browser_is_installed() -> None:
    kernel = next(item for item in discover_kernels(ROOT) if item["id"] == "playwright-firefox")
    device = device_from_playwright("iPhone 13", locale="en-US", timezone="America/Chicago")
    with pytest.raises(ContractError, match="cannot realize"):
        probe_playwright_kernel(kernel, device)


def test_playwright_preset_cannot_be_probed_on_a_different_engine() -> None:
    kernel = _valid_kernel_contract()
    kernel["capabilities"] = ["desktop", "mobile-emulation"]
    device = device_from_playwright("iPhone 13", locale="en-US", timezone="America/Chicago")
    assert device["default_engine"] == "webkit"
    with pytest.raises(ContractError, match="default engine"):
        probe_playwright_kernel(kernel, device)


def test_playwright_probe_rejects_physical_device_claim_before_driver_start(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    kernel = _valid_kernel_contract()
    kernel["capabilities"] = ["desktop", "mobile-emulation"]
    device = device_from_playwright("Pixel 7", locale="en-US", timezone="America/Chicago")
    device["provenance"] = {"kind": "owned"}
    device["realization"] = "physical-device"
    monkeypatch.setattr(
        kernels_module,
        "_playwright",
        lambda: pytest.fail("a physical-device claim reached the Playwright driver"),
    )

    with pytest.raises(ContractError, match="physical-device"):
        probe_playwright_kernel(kernel, device)


# -- device memory override (native patch 0005) --------------------------------


def test_the_python_mirror_agrees_with_chromiums_arithmetic() -> None:
    """Values measured from the patched build on 2026-08-07, one per case.

    This function only earns its place if it predicts the browser. Each pair
    below was produced by launching the attested build with the switch and
    reading ``navigator.deviceMemory``, so a divergence here is a real
    divergence rather than a restatement of the same assumption twice.
    """
    assert approximate_device_memory(2048) == 2
    assert approximate_device_memory(4096) == 4
    assert approximate_device_memory(8192) == 8
    assert approximate_device_memory(5000) == 4
    assert approximate_device_memory(7000) == 8


@pytest.mark.parametrize("physical_mb, reported", [(6144, 4), (12288, 8), (3072, 2)])
def test_a_tie_rounds_down_because_upstream_compares_with_less_or_equal(
    physical_mb: int, reported: float
) -> None:
    """Exactly halfway is the one case a reader guesses wrong."""
    assert approximate_device_memory(physical_mb) == reported


def test_the_clamp_is_not_a_bypass() -> None:
    """A request outside the desktop range is clamped, never honoured."""
    assert approximate_device_memory(1024) == 2  # below the floor
    assert approximate_device_memory(512) == 2
    assert approximate_device_memory(131072) == 32  # above the ceiling
    assert approximate_device_memory(65536) == 32


@pytest.mark.parametrize("bad", [0, -4096, True, 4096.0, "4096"])
def test_a_size_that_is_not_a_positive_integer_is_refused(bad: object) -> None:
    with pytest.raises(ContractError):
        approximate_device_memory(bad)  # type: ignore[arg-type]


def test_every_realistic_mobile_size_lands_on_the_android_ladder() -> None:
    """Android caps at 8, so the table may not contain a size that exceeds it."""
    reported = {approximate_device_memory(mb) for mb in REALISTIC_MOBILE_MEMORY_MB}
    assert reported == {2, 4, 8}


def test_every_realistic_desktop_size_lands_on_the_desktop_ladder() -> None:
    reported = {approximate_device_memory(mb) for mb in REALISTIC_DESKTOP_MEMORY_MB}
    assert reported == {4, 8, 16, 32}


def test_a_memory_override_without_a_patched_binary_is_refused() -> None:
    """A stock binary ignores the switch silently, so asking is the error."""
    kernel = {
        "schema": KERNEL_SCHEMA,
        "id": "k-1",
        "engine": "chromium",
        "product": "chromium",
        "available": True,
        "executable": str(Path(__file__).resolve()),
        "executable_sha256_16": "0123456789abcdef",
        "capabilities": ["mobile-emulation"],
        "source": {"kind": "playwright-managed", "playwright_version": "1.0"},
    }
    with pytest.raises(ContractError, match="patch 0005"):
        probe_playwright_kernel_batch(
            kernel,
            [device_from_playwright("Pixel 7", locale="en-US", timezone="America/Chicago")],
            None,
            [4096],
        )


def test_an_attested_kernel_accepts_its_own_path_spelled_either_way() -> None:
    """Forward and back slashes name the same binary on Windows.

    A guard that compares the two as strings is checking spelling, not identity,
    and it fails a capture that was in fact configured correctly -- which is
    exactly how this one failed the first live run.
    """
    from browser_core.kernels import _PROBEABLE_KERNEL_SOURCES

    assert "attested-browser-core" in _PROBEABLE_KERNEL_SOURCES
    here = Path(__file__).resolve()
    assert Path(str(here).replace("\\", "/")).resolve() == here


# -- user agent / client hint agreement ----------------------------------------


def test_a_preset_user_agent_takes_the_running_browsers_version() -> None:
    """Playwright bakes its own Chromium version into every device preset.

    Drive a different binary through the same preset and the browser reports two
    versions: the preset's in navigator.userAgent and the real one in the client
    hints. Measured on this host before the fix -- Chrome/147.0.7727.15 against
    brands Chromium 153 -- which is a one-line comparison for any page.
    """
    preset = (
        "Mozilla/5.0 (Linux; Android 14; Pixel 7) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/147.0.7727.15 Mobile Safari/537.36"
    )
    aligned = align_user_agent_version(preset, "153.0.7988.0")
    assert "Chrome/153.0.7988.0" in aligned
    assert "147" not in aligned
    # Everything else about the preset survives untouched.
    assert "Linux; Android 14; Pixel 7" in aligned
    assert aligned.endswith("Mobile Safari/537.36")


def test_alignment_is_a_no_op_when_the_versions_already_agree() -> None:
    preset = "Mozilla/5.0 (X11) AppleWebKit/537.36 Chrome/147.0.7727.15 Safari/537.36"
    assert align_user_agent_version(preset, "147.0.7727.15") == preset


def test_a_user_agent_without_a_chrome_token_is_left_alone() -> None:
    """Firefox and WebKit presets carry no Chrome version to align.

    Inventing one would be worse than leaving the string as measured.
    """
    firefox = "Mozilla/5.0 (Windows NT 10.0; rv:148.0) Gecko/20100101 Firefox/148.0"
    assert align_user_agent_version(firefox, "153.0.7988.0") == firefox


def test_only_the_first_chrome_token_is_rewritten() -> None:
    """Chrome appears once as a version; a stray later mention is not a version."""
    weird = "Mozilla/5.0 Chrome/147.0.1 Safari/537.36 Chrome/999"
    assert align_user_agent_version(weird, "153.0.0.0").count("153.0.0.0") == 1


@pytest.mark.parametrize("bad", [None, 5, b"ua"])
def test_alignment_refuses_anything_that_is_not_a_string(bad: object) -> None:
    with pytest.raises(ContractError):
        align_user_agent_version(bad, "153.0.0.0")  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "bad_version",
    ["", "unknown", "153.x", "v153", " 153", "١٥٣.0.0.0"],
)
def test_alignment_refuses_a_version_that_is_not_one(bad_version: str) -> None:
    """Substituting an empty string would leave a bare "Chrome/" in the agent.

    That is a user agent no browser has ever sent -- a worse outcome than the
    version mismatch this function exists to remove.
    """
    preset = "Mozilla/5.0 Chrome/147.0.7727.15 Safari/537.36"
    with pytest.raises(ContractError):
        align_user_agent_version(preset, bad_version)


def test_invalid_browser_version_diagnostic_does_not_echo_value() -> None:
    private_value = "private-browser-version-marker"
    with pytest.raises(ContractError) as failure:
        align_user_agent_version("Mozilla/5.0 Chrome/147.0.7727.15", private_value)
    assert private_value not in str(failure.value)


def test_alignment_rejects_a_nonascii_chrome_version_in_the_preset() -> None:
    with pytest.raises(ContractError, match="user agent.*version"):
        align_user_agent_version(
            "Mozilla/5.0 Chrome/١٤٧.0.7727.15 Safari/537.36",
            "153.0.7988.0",
        )


def test_a_kernel_may_not_be_pointed_at_a_different_binary() -> None:
    """The kernel names the binary, so an executable path is an assertion.

    Allowing a Playwright kernel to drive some other build would write
    "kernel-probe:playwright-chromium" into the provenance of every persona in
    the batch for a browser that is not Playwright's, and nothing downstream
    could tell.
    """
    kernel = {
        "schema": KERNEL_SCHEMA,
        "id": "k-1",
        "engine": "chromium",
        "product": "chromium",
        "available": True,
        "executable": str(Path(__file__).resolve()),
        "executable_sha256_16": "0123456789abcdef",
        "capabilities": ["mobile-emulation"],
        "source": {"kind": "playwright-managed", "playwright_version": "1.0"},
    }
    device = device_from_playwright("Pixel 7", locale="en-US", timezone="America/Chicago")
    with pytest.raises(ContractError, match="only probe the executable it names"):
        probe_playwright_kernel_batch(
            kernel, [device], None, None, str(Path(__file__).parent.resolve())
        )


@pytest.mark.parametrize("field", ["hardware_concurrencies", "device_memory_mbs"])
def test_batch_rejects_explicit_empty_per_device_values_before_launch(
    monkeypatch: pytest.MonkeyPatch, field: str
) -> None:
    kernel = _valid_kernel_contract()
    device = device_from_playwright("Desktop Chrome HiDPI", locale="en-US", timezone="America/Chicago")
    monkeypatch.setattr(
        kernels_module,
        "_playwright",
        lambda: pytest.fail("misaligned batch reached Playwright"),
    )
    with pytest.raises(ContractError, match="must match devices one-for-one"):
        probe_playwright_kernel_batch(kernel, [device], **{field: []})


@pytest.mark.parametrize(
    "field, malformed",
    [
        ("hardware_concurrencies", 4.5),
        ("hardware_concurrencies", True),
        ("hardware_concurrencies", 0),
        ("hardware_concurrencies", "4"),
        ("device_memory_mbs", 4096.5),
        ("device_memory_mbs", True),
        ("device_memory_mbs", 0),
        ("device_memory_mbs", "4096"),
        ("device_memory_mbs", []),
    ],
)
def test_batch_rejects_noninteger_per_device_values_before_launch(
    monkeypatch: pytest.MonkeyPatch, field: str, malformed: object
) -> None:
    kernel = _valid_kernel_contract()
    kernel["capabilities"] = ["desktop", "device-memory-override"]
    device = device_from_playwright("Desktop Chrome HiDPI", locale="en-US", timezone="America/Chicago")
    monkeypatch.setattr(
        kernels_module,
        "_playwright",
        lambda: pytest.fail("invalid override reached Playwright"),
    )
    with pytest.raises(ContractError, match=field):
        probe_playwright_kernel_batch(kernel, [device], **{field: [malformed]})


@pytest.mark.parametrize("invalid_device", [[], {"id": "private\nmarker"}])
def test_batch_preserves_other_results_when_one_device_is_invalid(
    monkeypatch: pytest.MonkeyPatch, invalid_device: object,
) -> None:
    class FakeBrowser:
        version = "153.0.0.0"

        def close(self) -> None:
            pass

    class FakeBrowserType:
        executable_path = str(Path(__file__).resolve())

        def launch(self, **_kwargs: object) -> FakeBrowser:
            return FakeBrowser()

    class FakePlaywright:
        chromium = FakeBrowserType()

        def __enter__(self) -> FakePlaywright:
            return self

        def __exit__(self, *_args: object) -> None:
            pass

    monkeypatch.setattr(kernels_module, "_playwright", lambda: (lambda: FakePlaywright(), "1"))
    monkeypatch.setattr(
        kernels_module,
        "_probe_with_browser",
        lambda _browser, _version, _kernel, device, *_args, **_kwargs: {"device_id": device["id"]},
    )
    device = {
        "schema": "browser-core.device/1",
        "id": "owned-device",
        "name": "Owned device",
        "class": "desktop",
        "realization": "emulated",
        "default_engine": "chromium",
        "is_mobile": False,
        "has_touch": False,
        "viewport": {"width": 1280, "height": 720},
        "screen": {"width": 1280, "height": 720},
        "device_scale_factor": 1,
        "user_agent": "Mozilla/5.0",
        "locale": "en-US",
        "timezone": "America/Chicago",
        "provenance": {"kind": "owned"},
    }
    kernel = _valid_kernel_contract()
    kernel["executable_sha256_16"] = kernels_module._sha256_16(Path(kernel["executable"]))
    results = probe_playwright_kernel_batch(kernel, [invalid_device, device])
    assert len(results) == 2
    assert "error" in results[0]
    assert results[0]["device_id"] is None
    assert results[1] == {"device_id": "owned-device"}


@pytest.mark.parametrize("batched", [False, True])
@pytest.mark.parametrize("mismatch", ["path", "digest"])
def test_probe_rejects_stale_or_different_playwright_executable_before_launch(
    monkeypatch: pytest.MonkeyPatch, batched: bool, mismatch: str
) -> None:
    kernel = _valid_kernel_contract()
    device = device_from_playwright("Desktop Chrome HiDPI", locale="en-US", timezone="America/Chicago")
    actual_path = str(Path(__file__).resolve())
    kernel["executable"] = str(Path(__file__).parent / "test_network.py") if mismatch == "path" else actual_path

    class FakeBrowserType:
        executable_path = actual_path

        def launch(self, **_kwargs: object) -> None:
            pytest.fail("mismatched executable reached launch")

    class FakePlaywright:
        chromium = FakeBrowserType()

        def __enter__(self) -> FakePlaywright:
            return self

        def __exit__(self, *_args: object) -> None:
            pass

    monkeypatch.setattr(kernels_module, "_playwright", lambda: (lambda: FakePlaywright(), "1"))
    with pytest.raises(ContractError, match="kernel executable"):
        if batched:
            probe_playwright_kernel_batch(kernel, [device])
        else:
            probe_playwright_kernel(kernel, device)
