"""What the catalog is allowed to claim about itself.

Two questions, kept separate on purpose. Coherence asks whether one persona
contradicts itself; uniqueness asks whether the catalog is as large as its file
count. A library can fail either while passing the other, and the number worth
quoting -- ``usable_identities`` -- is the one that survives both.

The rules are only worth having if they fire on real defects and stay silent on
real browsers, so most tests below build a persona that is correct in every
respect, break exactly one thing, and assert that exactly that thing is
reported. A rule that fires on a valid persona costs more than no rule at all:
it teaches whoever reads the report to ignore it.
"""

from __future__ import annotations

import copy
import json
import math

import pytest

import browser_core.persona_quality as persona_quality_module
from browser_core.contracts import ContractError
from browser_core.personas import (
    add_persona,
    build_persona,
    list_personas,
    os_family_from_platform,
    persona_digest,
    reject_incoherent_persona,
)
from browser_core.persona_quality import (
    COHERENCE_SCHEMA,
    QUALITY_SCHEMA,
    RETIREMENT_SCHEMA,
    UNIQUENESS_SCHEMA,
    audit_catalog_coherence,
    catalog_quality_report,
    catalog_uniqueness,
    coherence_findings,
    render_coherence,
    render_uniqueness,
    retire_incoherent_personas,
    validate_catalog_quality_report,
    validate_coherence_report,
    validate_retirement_report,
    validate_uniqueness_report,
)


def _persona(
    persona_id="p-1", *, claims=None, device=None, geography=None, kernel=None
):
    """A persona that no rule should fire on, so tests can break one thing."""
    expected = {
        "window.userAgent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 Chrome/140.0.0.0 Safari/537.36"
        ),
        "window.platform": "Win32",
        "window.locale": "en-US",
        "window.languages": ["en-US", "en"],
        "window.timezone": "America/Chicago",
        "window.maxTouchPoints": 0,
        "window.hardwareConcurrency": 8,
        "window.screen.width": 1920,
        "window.screen.height": 1080,
        "window.screen.devicePixelRatio": 1,
        "window.pluginsLength": 5,
        "window.mimeTypesLength": 2,
        "window.pdfViewerEnabled": True,
        "userAgentData.brands": ["Chromium/140", "Not_A Brand/8"],
        "userAgentData.platform": "Windows",
        "userAgentData.mobile": False,
        "rendering.webgl.vendor": "Google Inc. (NVIDIA)",
        "rendering.webgl.renderer": "ANGLE (NVIDIA GeForce RTX 3080 Direct3D11)",
        "rendering.webgl.version": "WebGL 1.0 (OpenGL ES 2.0 Chromium)",
    }
    expected.update(claims or {})
    base_device = {
        "class": "desktop",
        "os_family": "windows",
        "os_version": "11",
        "architecture": "x86_64",
        "is_mobile": False,
        "has_touch": False,
        "viewport": {
            "width": 1280,
            "height": 720,
            "device_scale_factor": 1,
            "orientation": "landscape",
        },
        "screen": {"width": 1920, "height": 1080},
    }
    base_device.update(device or {})
    base_geography = {
        "country": "US",
        "locale": "en-US",
        "languages": ["en-US", "en"],
        "timezone": "America/Chicago",
    }
    base_geography.update(geography or {})
    base_kernel = {
        "engine": "chromium",
        "product": "chromium",
        "minimum_major": 140,
        "maximum_major": 140,
    }
    base_kernel.update(kernel or {})
    return build_persona(
        persona_id=persona_id,
        name=f"Test {persona_id}",
        device=base_device,
        kernel=base_kernel,
        geography=base_geography,
        identity_contract={"schema_version": 1, "expected": expected},
        provenance={
            "kind": "owned-capture",
            "source": "unit-test",
            "source_sha256": "0" * 64,
            "captured_at": "2026-08-07T00:00:00Z",
        },
    )


def _rules(persona):
    return {finding["rule"] for finding in coherence_findings(persona)}


# --------------------------------------------------------------------------
# The baseline must be silent, or nothing below means anything
# --------------------------------------------------------------------------


def test_a_correct_persona_triggers_no_rule():
    assert coherence_findings(_persona()) == []


# --------------------------------------------------------------------------
# Contradictions
# --------------------------------------------------------------------------


def test_touch_declared_with_zero_touch_points_is_a_contradiction():
    """The defect that put 728 unusable personas in the real catalog."""
    persona = _persona(
        device={
            "class": "mobile",
            "os_family": "ios",
            "is_mobile": True,
            "has_touch": True,
        },
        claims={"window.maxTouchPoints": 0, "window.platform": "iPhone"},
    )
    findings = coherence_findings(persona)
    touch = [f for f in findings if f["rule"] == "touch-declared-but-no-touch-points"]
    assert len(touch) == 1
    assert touch[0]["severity"] == "contradiction"


def test_touch_points_on_a_non_touch_device_is_a_contradiction():
    persona = _persona(claims={"window.maxTouchPoints": 5})
    assert "touch-points-without-touch-device" in _rules(persona)


def test_negative_touch_point_count_cannot_pass_catalog_quality(tmp_path) -> None:
    persona = _persona(
        "negative-touch", claims={"window.maxTouchPoints": -1}
    )
    add_persona(tmp_path, persona)

    assert "negative-touch-point-count" in _rules(persona)
    report = catalog_quality_report(tmp_path)
    assert report["passed"] is False
    assert report["usable_identities"] == 0


@pytest.mark.parametrize("concurrency", [0, -1])
def test_nonpositive_hardware_concurrency_cannot_pass_catalog_quality(
    tmp_path, concurrency: int
) -> None:
    persona = _persona(
        f"invalid-concurrency-{concurrency}",
        claims={"window.hardwareConcurrency": concurrency},
    )
    add_persona(tmp_path, persona)

    findings = [
        finding for finding in coherence_findings(persona)
        if finding["rule"] == "nonpositive-hardware-concurrency"
    ]
    assert len(findings) == 1
    assert findings[0]["severity"] == "contradiction"
    report = catalog_quality_report(tmp_path)
    assert report["passed"] is False
    assert report["usable_identities"] == 0


@pytest.mark.parametrize("memory", [0, -1])
def test_nonpositive_device_memory_cannot_pass_catalog_quality(
    tmp_path, memory: int
) -> None:
    persona = _persona(
        f"invalid-memory-{memory}", claims={"window.deviceMemory": memory}
    )
    add_persona(tmp_path, persona)

    findings = [
        finding for finding in coherence_findings(persona)
        if finding["rule"] == "nonpositive-device-memory"
    ]
    assert len(findings) == 1
    assert findings[0]["severity"] == "contradiction"
    report = catalog_quality_report(tmp_path)
    assert report["passed"] is False
    assert report["usable_identities"] == 0


@pytest.mark.parametrize(
    "claims",
    [
        {"window.screen.availWidth": 0},
        {"window.screen.availHeight": -1},
        {"window.screen.colorDepth": 0, "window.screen.pixelDepth": 0},
        {"window.screen.colorDepth": -1, "window.screen.pixelDepth": -1},
    ],
)
def test_nonpositive_screen_measurements_cannot_pass_catalog_quality(
    tmp_path, claims: dict[str, int]
) -> None:
    persona = _persona("invalid-screen", claims=claims)
    add_persona(tmp_path, persona)

    assert "nonpositive-screen-measurement" in _rules(persona)
    report = catalog_quality_report(tmp_path)
    assert report["passed"] is False
    assert report["usable_identities"] == 0


@pytest.mark.parametrize(
    "claim", ["window.deviceMemory", "userAgentData.mobile", "userAgentData.platform"]
)
def test_a_chromium_only_api_on_another_engine_is_a_contradiction(claim):
    """Firefox does not implement Client Hints; claiming it does is not a persona."""
    persona = _persona(
        kernel={"engine": "firefox", "product": "firefox"},
        claims={claim: 8 if claim.endswith("Memory") else "Windows"},
    )
    assert "chromium-only-claim-on-other-engine" in _rules(persona)


@pytest.mark.parametrize(
    "missing_claim",
    [
        "userAgentData.brands",
        "userAgentData.mobile",
        "userAgentData.platform",
    ],
)
def test_partial_chromium_user_agent_data_is_reported_as_incomplete(
    missing_claim: str,
) -> None:
    persona = _persona(
        claims={"userAgentData.brands": ["Chromium/140", "Not_A Brand/8"]}
    )
    persona["identity_contract"]["expected"].pop(missing_claim)

    findings = [
        finding
        for finding in coherence_findings(persona)
        if finding["rule"] == "chromium-user-agent-data-incomplete"
    ]

    assert len(findings) == 1
    assert findings[0]["severity"] == "anomaly"
    assert findings[0]["detail"]["missing_claims"] == [missing_claim]


def test_a_platform_string_from_the_wrong_operating_system_is_a_contradiction():
    persona = _persona(
        device={"os_family": "macos"}, claims={"window.platform": "Win32"}
    )
    assert "platform-contradicts-os-family" in _rules(persona)


def test_ua_client_hints_disagreeing_with_the_device_is_a_contradiction():
    assert "ua-ch-mobile-contradicts-device" in _rules(
        _persona(claims={"userAgentData.mobile": True})
    )
    assert "ua-ch-platform-contradicts-os-family" in _rules(
        _persona(claims={"userAgentData.platform": "Android"})
    )


def test_user_agent_major_disagreeing_with_the_kernel_is_a_contradiction():
    assert "user-agent-major-contradicts-kernel" in _rules(
        _persona(
            claims={
                "window.userAgent": (
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 Chrome/139.0.0.0 Safari/537.36"
                )
            }
        )
    )


@pytest.mark.parametrize(
    ("engine", "product", "device", "claims"),
    [
        (
            "firefox",
            "firefox",
            {},
            {
                "window.userAgent": (
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 Chrome/140.0.0.0 Safari/537.36"
                ),
                "rendering.webgl.version": "WebGL 1.0",
            },
        ),
        (
            "webkit",
            "safari",
            {"os_family": "macos"},
            {
                "window.userAgent": (
                    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:148.0) "
                    "Gecko/20100101 Firefox/148.0"
                ),
                "window.platform": "MacIntel",
                "rendering.webgl.version": "WebGL 1.0",
            },
        ),
        (
            "chromium",
            "chromium",
            {},
            {
                "window.userAgent": (
                    "Mozilla/5.0 AppleWebKit/537.36 Chrome/140.0.0.0 "
                    "Safari/537.36 Firefox/148.0"
                )
            },
        ),
    ],
)
def test_cross_engine_user_agent_product_markers_are_contradictions(
    engine: str,
    product: str,
    device: dict[str, object],
    claims: dict[str, object],
) -> None:
    persona = _persona(
        kernel={"engine": engine, "product": product},
        device=device,
        claims=claims,
    )
    if engine != "chromium":
        for claim_name in (
            "userAgentData.brands",
            "userAgentData.mobile",
            "userAgentData.platform",
        ):
            persona["identity_contract"]["expected"].pop(claim_name)

    assert "user-agent-product-contradicts-engine" in _rules(persona)


@pytest.mark.parametrize(
    ("device", "user_agent"),
    [
        (
            {},
            "Mozilla/5.0 Chrome/140.0.0.0 Mobile Safari/537.36",
        ),
        (
            {
                "class": "mobile",
                "os_family": "android",
                "is_mobile": True,
                "has_touch": True,
            },
            "Mozilla/5.0 (Linux; Android 14) Chrome/140.0.0.0 Safari/537.36",
        ),
    ],
)
def test_user_agent_mobile_marker_disagreeing_with_device_is_a_contradiction(
    device, user_agent
):
    persona = _persona(
        device=device,
        claims={
            "window.userAgent": user_agent,
            "window.platform": "Linux armv8l" if device else "Win32",
            "window.maxTouchPoints": 5 if device else 0,
            "userAgentData.mobile": bool(device),
            "userAgentData.platform": "Android" if device else "Windows",
        },
    )
    assert "user-agent-mobile-contradicts-device" in _rules(persona)


def test_a_claimed_screen_that_disagrees_with_the_device_record_is_a_contradiction():
    assert "screen-contradicts-device-record" in _rules(
        _persona(claims={"window.screen.width": 1366})
    )


def test_available_screen_larger_than_the_screen_is_a_contradiction():
    assert "available-screen-exceeds-screen" in _rules(
        _persona(claims={"window.screen.availWidth": 2560})
    )


def test_a_pixel_ratio_that_disagrees_with_the_viewport_is_a_contradiction():
    assert "pixel-ratio-contradicts-viewport" in _rules(
        _persona(claims={"window.screen.devicePixelRatio": 2})
    )


def test_geography_disagreements_are_contradictions():
    assert "locale-contradicts-geography" in _rules(
        _persona(claims={"window.locale": "de-DE"})
    )
    assert "timezone-contradicts-geography" in _rules(
        _persona(claims={"window.timezone": "Europe/Berlin"})
    )
    assert "languages-contradict-locale" in _rules(
        _persona(claims={"window.languages": ["fr-FR", "en-US"]})
    )


@pytest.mark.parametrize(
    ("claim_name", "value", "rule", "geography_field"),
    [
        (
            "window.locale",
            "private-locale-sentinel",
            "locale-contradicts-geography",
            "locale",
        ),
        (
            "window.timezone",
            "Private/Timezone_Sentinel",
            "timezone-contradicts-geography",
            "timezone",
        ),
    ],
)
def test_geography_mismatch_findings_do_not_echo_identity_values(
    claim_name: str, value: str, rule: str, geography_field: str
) -> None:
    persona = _persona(claims={claim_name: value})
    finding = next(item for item in coherence_findings(persona) if item["rule"] == rule)

    assert finding["detail"] == {
        "claim": claim_name,
        "geography_field": geography_field,
    }
    assert value not in json.dumps(finding, sort_keys=True)


@pytest.mark.parametrize(
    "languages",
    [[], ["en-US", "fr"], ["en-US", "en", "fr"]],
)
def test_the_complete_language_vector_must_match_geography(languages: list[str]):
    persona = _persona(claims={"window.languages": languages})
    assert "languages-contradict-geography" in _rules(persona)
    with pytest.raises(ContractError, match="languages-contradict-geography"):
        reject_incoherent_persona(persona)


@pytest.mark.parametrize(
    ("languages", "sentinel", "first_entry_is_string"),
    [
        (["private-language-sentinel", "en"], "private-language-sentinel", True),
        ([918273645, "en"], "918273645", False),
    ],
)
def test_language_locale_finding_does_not_echo_the_language_vector(
    languages: list[object], sentinel: str, first_entry_is_string: bool
) -> None:
    persona = _persona(claims={"window.languages": languages})
    finding = next(
        item
        for item in coherence_findings(persona)
        if item["rule"] == "languages-contradict-locale"
    )

    assert finding["detail"] == {
        "claim": "window.languages",
        "language_count": 2,
        "first_entry_is_string": first_entry_is_string,
        "locale_is_string": True,
    }
    assert sentinel not in json.dumps(finding, sort_keys=True)


def test_language_vector_comparison_is_case_insensitive():
    persona = _persona(claims={"window.languages": ["EN-us", "EN"]})
    assert "languages-contradict-geography" not in _rules(persona)


def test_geography_languages_must_be_case_insensitively_unique():
    with pytest.raises(ContractError, match="persona languages"):
        _persona(geography={"languages": ["en-US", "EN-us"]})


def test_an_iana_alias_is_not_a_timezone_disagreement():
    """Asia/Calcutta and Asia/Kolkata are one zone with two names."""
    persona = _persona(
        geography={
            "country": "IN",
            "locale": "en-IN",
            "languages": ["en-IN", "en"],
            "timezone": "Asia/Kolkata",
        },
        claims={
            "window.timezone": "Asia/Calcutta",
            "window.locale": "en-IN",
            "window.languages": ["en-IN", "en"],
        },
    )
    assert "timezone-contradicts-geography" not in _rules(persona)


def test_the_pdf_viewer_and_the_plugin_list_must_agree():
    assert "pdf-viewer-without-plugins" in _rules(
        _persona(claims={"window.pluginsLength": 0, "window.mimeTypesLength": 0})
    )
    assert "plugins-without-pdf-viewer" in _rules(
        _persona(claims={"window.pdfViewerEnabled": False})
    )


@pytest.mark.parametrize(
    ("claim", "rule"),
    [
        ("window.pluginsLength", "negative-plugin-count"),
        ("window.mimeTypesLength", "negative-mime-type-count"),
    ],
)
def test_negative_browser_array_lengths_are_contradictions(
    tmp_path, claim: str, rule: str
) -> None:
    persona = _persona("negative-length", claims={claim: -1})
    add_persona(tmp_path, persona)

    assert rule in _rules(persona)
    assert catalog_quality_report(tmp_path)["passed"] is False


@pytest.mark.parametrize(
    ("claims", "forbidden_rules"),
    [
        (
            {"window.maxTouchPoints": True},
            {"touch-points-without-touch-device"},
        ),
        (
            {
                "window.screen.colorDepth": True,
                "window.screen.pixelDepth": False,
            },
            {"screen-depths-disagree"},
        ),
        (
            {"window.screen.width": True},
            {"screen-contradicts-device-record"},
        ),
        (
            {
                "window.screen.width": False,
                "window.screen.availWidth": True,
            },
            {"available-screen-exceeds-screen"},
        ),
        (
            {"window.pluginsLength": True},
            {"plugin-count-off-specification"},
        ),
        (
            {"window.mimeTypesLength": True},
            {"mime-type-count-off-specification"},
        ),
        (
            {"window.pluginsLength": False},
            {"pdf-viewer-without-plugins"},
        ),
    ],
)
def test_boolean_claims_are_not_interpreted_as_integer_measurements(
    claims: dict[str, bool], forbidden_rules: set[str]
) -> None:
    assert _rules(_persona(claims=claims)).isdisjoint(forbidden_rules)


@pytest.mark.parametrize(
    ("claim", "value"),
    [
        ("window.platform", 7),
        ("userAgentData.platform", ["Windows"]),
        ("window.locale", 7),
        ("window.timezone", False),
        ("window.maxTouchPoints", True),
        ("window.hardwareConcurrency", 8.0),
        ("window.screen.width", True),
        ("window.screen.height", 1080.0),
        ("window.screen.availWidth", False),
        ("window.screen.availHeight", 1040.0),
        ("window.screen.colorDepth", True),
        ("window.screen.pixelDepth", 24.0),
        ("window.pluginsLength", False),
        ("window.mimeTypesLength", 2.0),
        ("window.screen.devicePixelRatio", True),
        ("window.deviceMemory", "8"),
        ("window.pdfViewerEnabled", 1),
        ("userAgentData.mobile", 0),
        ("window.languages", ["en-US", 7]),
        ("userAgentData.brands", "Chromium/140"),
        ("rendering.webgl.version", 1),
        ("rendering.webgl.vendor", False),
        ("rendering.webgl.renderer", ["ANGLE"]),
    ],
)
def test_known_browser_claims_reject_the_wrong_json_value_family(
    claim: str, value,
) -> None:
    persona = _persona(claims={claim: value})
    findings = coherence_findings(persona)
    assert any(
        finding["rule"] == "claim-value-type-invalid"
        and finding["detail"].get("claim") == claim
        and finding["severity"] == "contradiction"
        for finding in findings
    )
    with pytest.raises(ContractError, match="claim-value-type-invalid"):
        reject_incoherent_persona(persona)


@pytest.mark.parametrize(
    "claim",
    [
        "rendering.webgl.version",
        "rendering.webgl.vendor",
        "rendering.webgl.renderer",
    ],
)
def test_nullable_webgl_claims_may_explicitly_be_null(claim: str) -> None:
    persona = _persona(claims={claim: None})

    assert not any(
        finding["rule"] == "claim-value-type-invalid"
        and finding["detail"].get("claim") == claim
        for finding in coherence_findings(persona)
    )


@pytest.mark.parametrize(
    ("claim", "value"),
    [
        ("rendering.webgl.version", ""),
        ("rendering.webgl.version", " \t"),
        ("rendering.webgl.vendor", ""),
        ("rendering.webgl.vendor", " \t"),
        ("rendering.webgl.renderer", ""),
        ("rendering.webgl.renderer", " \t"),
    ],
)
def test_blank_webgl_strings_are_incomplete_evidence(claim: str, value: str) -> None:
    persona = _persona(claims={claim: value})
    findings = [
        finding
        for finding in coherence_findings(persona)
        if finding["rule"] == "webgl-string-is-blank"
    ]

    assert len(findings) == 1
    assert findings[0]["severity"] == "anomaly"
    assert findings[0]["detail"] == {"claim": claim}


@pytest.mark.parametrize(
    ("vendor", "renderer"),
    [
        (None, "ANGLE (NVIDIA GeForce RTX 3080 Direct3D11)"),
        ("Google Inc. (NVIDIA)", None),
    ],
)
def test_webgl_vendor_and_renderer_must_have_matching_presence(
    vendor: str | None, renderer: str | None
) -> None:
    persona = _persona(
        claims={
            "rendering.webgl.vendor": vendor,
            "rendering.webgl.renderer": renderer,
        }
    )
    findings = [
        finding
        for finding in coherence_findings(persona)
        if finding["rule"] == "webgl-vendor-renderer-incomplete"
    ]

    assert len(findings) == 1
    assert findings[0]["severity"] == "anomaly"
    assert findings[0]["detail"] == {
        "vendor_present": vendor is not None,
        "renderer_present": renderer is not None,
    }


def test_webgl_vendor_and_renderer_may_be_both_present_or_both_null() -> None:
    assert "webgl-vendor-renderer-incomplete" not in _rules(_persona())
    both_null = _persona(
        claims={"rendering.webgl.vendor": None, "rendering.webgl.renderer": None}
    )
    assert "webgl-vendor-renderer-incomplete" not in _rules(both_null)


def test_webgl_identity_pair_without_a_context_version_is_incomplete() -> None:
    persona = _persona(claims={"rendering.webgl.version": None})
    findings = [
        finding
        for finding in coherence_findings(persona)
        if finding["rule"] == "webgl-identity-without-version"
    ]

    assert len(findings) == 1
    assert findings[0]["severity"] == "anomaly"
    assert findings[0]["detail"] == {
        "version_present": False,
        "vendor_present": True,
        "renderer_present": True,
    }


def test_webgl_version_may_exist_without_an_unmasked_identity_pair() -> None:
    persona = _persona(
        claims={"rendering.webgl.vendor": None, "rendering.webgl.renderer": None}
    )

    assert "webgl-identity-without-version" not in _rules(persona)


# --------------------------------------------------------------------------
# Implausible and anomalous, which must NOT block a capture
# --------------------------------------------------------------------------


def test_a_software_renderer_is_implausible_not_contradictory():
    persona = _persona(
        claims={"rendering.webgl.renderer": "ANGLE (Vulkan SwiftShader Device)"}
    )
    finding = next(
        f for f in coherence_findings(persona) if f["rule"] == "software-webgl-renderer"
    )
    assert finding["severity"] == "implausible"
    reject_incoherent_persona(persona), "implausible must not block a capture"


@pytest.mark.parametrize(
    ("renderer", "marker"),
    [
        ("SwiftShader private-renderer-sentinel", "swiftshader"),
        ("llvmpipe private-renderer-sentinel", "llvmpipe"),
        ("softpipe private-renderer-sentinel", "softpipe"),
        ("Mesa Offscreen private-renderer-sentinel", "mesa offscreen"),
    ],
)
def test_software_renderer_finding_does_not_echo_the_renderer(
    renderer: str, marker: str
) -> None:
    persona = _persona(claims={"rendering.webgl.renderer": renderer})
    finding = next(
        item
        for item in coherence_findings(persona)
        if item["rule"] == "software-webgl-renderer"
    )

    assert finding["detail"] == {
        "claim": "rendering.webgl.renderer",
        "software_marker": marker,
    }
    assert "private-renderer-sentinel" not in json.dumps(finding, sort_keys=True)


def test_masked_webgl_strings_are_reported_as_an_anomaly():
    persona = _persona(
        claims={
            "rendering.webgl.vendor": "WebKit",
            "rendering.webgl.renderer": "WebKit WebGL",
        }
    )
    finding = next(
        f
        for f in coherence_findings(persona)
        if f["rule"] == "webgl-strings-are-masked"
    )
    assert finding["severity"] == "anomaly"


def test_a_chromium_persona_without_client_hints_is_an_anomaly():
    persona = _persona()
    for claim_name in (
        "userAgentData.brands",
        "userAgentData.mobile",
        "userAgentData.platform",
    ):
        persona["identity_contract"]["expected"].pop(claim_name)
    findings = coherence_findings(persona)
    finding = next(
        f for f in findings if f["rule"] == "chromium-without-user-agent-data"
    )
    assert finding["severity"] == "anomaly"


def test_plain_chromium_without_a_pdf_viewer_is_not_reported():
    """Branded Chrome ships one; a Chromium build does not, and neither claim is wrong."""
    persona = _persona(
        kernel={"product": "chromium"},
        claims={
            "window.pdfViewerEnabled": False,
            "window.pluginsLength": 0,
            "window.mimeTypesLength": 0,
        },
    )
    assert "desktop-chrome-without-pdf-viewer" not in _rules(persona)


def test_branded_desktop_chrome_without_a_pdf_viewer_is_implausible():
    persona = _persona(
        kernel={"product": "chrome"},
        claims={
            "window.pdfViewerEnabled": False,
            "window.pluginsLength": 0,
            "window.mimeTypesLength": 0,
        },
    )
    assert "desktop-chrome-without-pdf-viewer" in _rules(persona)


def _mobile_persona(*, claims=None):
    """An Android persona that trips no contradiction of its own."""
    merged = {
        "window.userAgent": (
            "Mozilla/5.0 (Linux; Android 15; Pixel 7) "
            "AppleWebKit/537.36 Chrome/140.0.0.0 Mobile Safari/537.36"
        ),
        "window.platform": "Linux armv8l",
        "window.maxTouchPoints": 5,
        "userAgentData.platform": "Android",
        "userAgentData.mobile": True,
    }
    merged.update(claims or {})
    return _persona(
        claims=merged,
        device={
            "class": "mobile",
            "os_family": "android",
            "os_version": "15",
            "architecture": "arm64",
            "is_mobile": True,
            "has_touch": True,
        },
    )


@pytest.mark.parametrize("value", [0.25, 0.5, 1, 2, 4, 8, 16, 32])
def test_a_value_the_api_can_produce_is_not_reported(value):
    assert "device-memory-off-ladder" not in _rules(
        _persona(claims={"window.deviceMemory": value})
    )


def test_a_desktop_thirty_two_is_what_this_hosts_browsers_actually_report():
    """Regression: the rule used to call four real browsers non-conformant.

    Chromium clamps desktop Device Memory to [2, 32], not to the [0.25, 8] the
    published specification still documents. Measured 2026-08-07 on one 64 GiB
    host, branded Chrome stable and Playwright Chromium 147 and 149 and the
    attested build all returned 32. A rule may not disagree with four browsers.
    """
    assert _rules(_persona(claims={"window.deviceMemory": 32})) == _rules(_persona())


@pytest.mark.parametrize("value", [3, 12, 24, 64])
def test_a_value_off_the_power_of_two_ladder_is_implausible(value):
    """Positive values off the ladder remain implausible."""
    persona = _persona(claims={"window.deviceMemory": value})
    finding = next(
        f
        for f in coherence_findings(persona)
        if f["rule"] == "device-memory-off-ladder"
    )
    assert finding["severity"] == "implausible"
    reject_incoherent_persona(persona)  # measured, so it must not block a capture


def test_huge_device_memory_claim_is_classified_without_float_conversion() -> None:
    assert "device-memory-off-ladder" in _rules(
        _persona(claims={"window.deviceMemory": 10**400})
    )


def test_huge_device_pixel_ratio_claim_is_classified_without_float_conversion() -> None:
    assert "pixel-ratio-contradicts-viewport" in _rules(
        _persona(claims={"window.screen.devicePixelRatio": 10**400})
    )


@pytest.mark.parametrize("value", [16, 32])
def test_a_phone_above_the_android_cap_is_a_contradiction(value):
    """Chromium clamps Android at 8 in native code, so no phone reports more."""
    persona = _mobile_persona(claims={"window.deviceMemory": value})
    finding = next(
        f
        for f in coherence_findings(persona)
        if f["rule"] == "device-memory-above-android-cap"
    )
    assert finding["severity"] == "contradiction"
    with pytest.raises(ContractError):
        reject_incoherent_persona(persona)


@pytest.mark.parametrize("value", [2, 4, 8])
def test_a_phone_on_the_android_ladder_is_accepted(value):
    persona = _mobile_persona(claims={"window.deviceMemory": value})
    assert "device-memory-above-android-cap" not in _rules(persona)
    reject_incoherent_persona(persona)


def test_the_android_cap_does_not_apply_to_desktops():
    """The same 32 is a defect on a phone and correct on a workstation."""
    assert "device-memory-above-android-cap" not in _rules(
        _persona(claims={"window.deviceMemory": 32})
    )


def test_an_unrecognized_platform_string_is_a_value_free_anomaly():
    """A physical-device measurement is allowed to surprise us."""
    sentinel = "Linux private-platform-sentinel"
    persona = _persona(claims={"window.platform": sentinel})
    finding = next(
        f
        for f in coherence_findings(persona)
        if f["rule"] == "platform-string-unrecognized"
    )
    assert finding["severity"] == "anomaly"
    assert finding["detail"] == {
        "claim": "window.platform",
        "os_family": "windows",
    }
    assert sentinel not in json.dumps(finding, sort_keys=True)


def test_an_unrecognized_ua_ch_platform_is_a_value_free_anomaly() -> None:
    persona = _persona(claims={"userAgentData.platform": "Plan 9"})
    finding = next(
        item
        for item in coherence_findings(persona)
        if item["rule"] == "ua-ch-platform-unrecognized"
    )

    assert finding["severity"] == "anomaly"
    assert finding["detail"] == {
        "claim": "userAgentData.platform",
        "os_family": "windows",
    }
    reject_incoherent_persona(persona)


# --------------------------------------------------------------------------
# The capture gate
# --------------------------------------------------------------------------


def test_the_capture_gate_refuses_a_self_contradicting_persona():
    persona = _persona(
        device={
            "class": "mobile",
            "os_family": "ios",
            "is_mobile": True,
            "has_touch": True,
        },
        claims={"window.maxTouchPoints": 0, "window.platform": "iPhone"},
    )
    with pytest.raises(ContractError, match="contradicts itself"):
        reject_incoherent_persona(persona)


def test_the_capture_gate_passes_a_coherent_persona():
    persona = _persona()
    assert reject_incoherent_persona(persona) is persona


# --------------------------------------------------------------------------
# Believing the measurement over the preset name
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "platform,fallback,expected",
    [
        ("MacIntel", "android", "macos"),
        ("Win32", "android", "windows"),
        ("iPhone", "android", "ios"),
        ("Linux armv8l", "android", "android"),
        ("Linux armv8l", "linux", "linux"),
        ("Something Unheard Of", "android", "android"),
        (None, "windows", "windows"),
    ],
)
def test_os_family_follows_the_measured_platform(platform, fallback, expected):
    assert os_family_from_platform(platform, fallback=fallback) == expected


# --------------------------------------------------------------------------
# Catalog-level reports
# --------------------------------------------------------------------------


def test_the_catalog_audit_counts_and_lists_what_it_found(tmp_path):
    add_persona(tmp_path, _persona("clean-1"))
    add_persona(
        tmp_path,
        _persona("broken-1", claims={"window.maxTouchPoints": 5}),
    )
    report = audit_catalog_coherence(tmp_path)
    assert report["personas"] == 2
    assert report["contradicting"] == 1
    assert report["contradicting_personas"] == ["broken-1"]
    assert report["passed"] is False
    assert report["coherent_ratio"] == 0.5
    assert render_coherence(report)
    assert validate_coherence_report(report) == report


def test_coherence_renderer_recomputes_every_headline_from_findings(tmp_path) -> None:
    add_persona(tmp_path, _persona("clean-1"))
    add_persona(
        tmp_path,
        _persona("broken-1", claims={"window.maxTouchPoints": 5}),
    )
    report = audit_catalog_coherence(tmp_path)
    mutations = []
    extra = copy.deepcopy(report)
    extra["private"] = "private-coherence-report-marker"
    mutations.append(extra)
    population = copy.deepcopy(report)
    population["clean"] += 1
    mutations.append(population)
    total = copy.deepcopy(report)
    total["findings_total"] += 1
    mutations.append(total)
    severity = copy.deepcopy(report)
    severity["by_severity"]["contradiction"] = 0
    mutations.append(severity)
    rules = copy.deepcopy(report)
    rules["by_rule"] = {}
    mutations.append(rules)
    examples = copy.deepcopy(report)
    examples["rule_examples"] = {}
    mutations.append(examples)
    ratio = copy.deepcopy(report)
    ratio["coherent_ratio"] = 1.0
    mutations.append(ratio)
    huge_ratio = copy.deepcopy(report)
    huge_ratio["coherent_ratio"] = 10**400
    mutations.append(huge_ratio)
    contradiction_list = copy.deepcopy(report)
    contradiction_list["contradicting_personas"] = []
    mutations.append(contradiction_list)
    verdict = copy.deepcopy(report)
    verdict["passed"] = True
    mutations.append(verdict)

    for mutation in mutations:
        with pytest.raises(ContractError) as failure:
            render_coherence(mutation)
        assert "private-coherence-report-marker" not in str(failure.value)


def test_coherence_validator_rejects_unbounded_or_non_json_finding_detail(
    tmp_path,
) -> None:
    add_persona(
        tmp_path,
        _persona("broken-1", claims={"window.maxTouchPoints": 5}),
    )
    report = audit_catalog_coherence(tmp_path)
    private_marker = "private-coherence-detail-marker"
    cycle: list[object] = []
    cycle.append(cycle)
    too_deep: object = private_marker
    for _ in range(6):
        too_deep = [too_deep]
    hostile_details = [
        {"value": object()},
        {"value": float("nan")},
        {"value": private_marker * 513},
        {"value": [0] * 33},
        {"value": cycle},
        {"value": too_deep},
    ]

    for detail in hostile_details:
        mutation = copy.deepcopy(report)
        mutation["findings"][0]["detail"] = detail
        with pytest.raises(ContractError) as failure:
            validate_coherence_report(mutation)
        assert private_marker not in str(failure.value)


def test_coherence_validator_requires_exact_derived_summary_shapes(tmp_path) -> None:
    class DictSubclass(dict):
        pass

    class ListSubclass(list):
        pass

    add_persona(
        tmp_path,
        _persona("broken-1", claims={"window.maxTouchPoints": 5}),
    )
    report = audit_catalog_coherence(tmp_path)
    severity_with_one = next(
        severity for severity, count in report["by_severity"].items() if count == 1
    )
    rule_with_one = next(rule for rule, count in report["by_rule"].items() if count == 1)
    mutations = []

    boolean_severity = copy.deepcopy(report)
    boolean_severity["by_severity"][severity_with_one] = True
    mutations.append(boolean_severity)
    boolean_rule = copy.deepcopy(report)
    boolean_rule["by_rule"][rule_with_one] = True
    mutations.append(boolean_rule)
    for field in ("by_severity", "by_rule", "rule_examples"):
        subclassed = copy.deepcopy(report)
        subclassed[field] = DictSubclass(subclassed[field])
        mutations.append(subclassed)
    subclassed_personas = copy.deepcopy(report)
    subclassed_personas["contradicting_personas"] = ListSubclass(
        subclassed_personas["contradicting_personas"]
    )
    mutations.append(subclassed_personas)

    for mutation in mutations:
        with pytest.raises(ContractError):
            validate_coherence_report(mutation)


def test_identical_personas_are_one_identity_not_two(tmp_path):
    add_persona(tmp_path, _persona("twin-a"))
    add_persona(tmp_path, _persona("twin-b"))
    report = catalog_uniqueness(tmp_path)
    assert report["personas"] == 2
    assert report["distinct_identities"] == 1
    assert report["largest_duplicate_group"] == 2
    assert report["passed"] is False
    assert render_uniqueness(report)
    assert validate_uniqueness_report(report) == report
    portable = json.loads(json.dumps(report))
    assert render_uniqueness(portable)


def test_uniqueness_reports_require_exact_derived_counts_and_rankings(tmp_path) -> None:
    class ListSubclass(list):
        pass

    single = tmp_path / "single"
    twins = tmp_path / "twins"
    single.mkdir()
    twins.mkdir()
    add_persona(single, _persona("only"))
    add_persona(twins, _persona("twin-a"))
    add_persona(twins, _persona("twin-b"))

    single_uniqueness = catalog_uniqueness(single)
    twin_uniqueness = catalog_uniqueness(twins)
    uniqueness_mutations = []
    boolean_largest = copy.deepcopy(single_uniqueness)
    boolean_largest["largest_duplicate_group"] = True
    uniqueness_mutations.append(boolean_largest)
    boolean_group_count = copy.deepcopy(twin_uniqueness)
    boolean_group_count["duplicate_group_count"] = True
    uniqueness_mutations.append(boolean_group_count)
    for field in ("most_identifying", "least_identifying"):
        subclassed = copy.deepcopy(single_uniqueness)
        subclassed[field] = ListSubclass(subclassed[field])
        uniqueness_mutations.append(subclassed)

    for mutation in uniqueness_mutations:
        with pytest.raises(ContractError):
            validate_uniqueness_report(mutation)

    single_quality = catalog_quality_report(single)
    twin_quality = catalog_quality_report(twins)
    quality_mutations = []
    nested_largest = copy.deepcopy(single_quality)
    nested_largest["uniqueness"]["largest_duplicate_group"] = True
    quality_mutations.append(nested_largest)
    nested_group_count = copy.deepcopy(twin_quality)
    nested_group_count["uniqueness"]["duplicate_group_count"] = True
    quality_mutations.append(nested_group_count)
    headline_distinct = copy.deepcopy(twin_quality)
    headline_distinct["distinct_identities"] = True
    quality_mutations.append(headline_distinct)
    headline_ranking = copy.deepcopy(single_quality)
    headline_ranking["most_identifying"] = ListSubclass(
        headline_ranking["most_identifying"]
    )
    quality_mutations.append(headline_ranking)

    for mutation in quality_mutations:
        with pytest.raises(ContractError):
            validate_catalog_quality_report(mutation)


def test_quality_reports_require_exact_text_primitives(tmp_path) -> None:
    class TextSubclass(str):
        pass

    add_persona(
        tmp_path,
        _persona("broken-1", claims={"window.maxTouchPoints": 5}),
    )
    coherence = audit_catalog_coherence(tmp_path)
    uniqueness = catalog_uniqueness(tmp_path)
    quality = catalog_quality_report(tmp_path)
    validators_and_mutations = []

    coherence_schema = copy.deepcopy(coherence)
    coherence_schema["schema"] = TextSubclass(coherence_schema["schema"])
    validators_and_mutations.append((validate_coherence_report, coherence_schema))
    coherence_summary = copy.deepcopy(coherence)
    coherence_summary["findings"][0]["summary"] = TextSubclass(
        coherence_summary["findings"][0]["summary"]
    )
    validators_and_mutations.append((validate_coherence_report, coherence_summary))

    uniqueness_schema = copy.deepcopy(uniqueness)
    uniqueness_schema["schema"] = TextSubclass(uniqueness_schema["schema"])
    validators_and_mutations.append((validate_uniqueness_report, uniqueness_schema))
    uniqueness_ranking = copy.deepcopy(uniqueness)
    uniqueness_ranking["most_identifying"][0] = TextSubclass(
        uniqueness_ranking["most_identifying"][0]
    )
    validators_and_mutations.append((validate_uniqueness_report, uniqueness_ranking))

    quality_schema = copy.deepcopy(quality)
    quality_schema["schema"] = TextSubclass(quality_schema["schema"])
    validators_and_mutations.append((validate_catalog_quality_report, quality_schema))
    quality_note = copy.deepcopy(quality)
    quality_note["note"] = TextSubclass(quality_note["note"])
    validators_and_mutations.append((validate_catalog_quality_report, quality_note))
    nested_coherence_schema = copy.deepcopy(quality)
    nested_coherence_schema["coherence"]["schema"] = TextSubclass(
        nested_coherence_schema["coherence"]["schema"]
    )
    validators_and_mutations.append(
        (validate_catalog_quality_report, nested_coherence_schema)
    )
    nested_uniqueness_schema = copy.deepcopy(quality)
    nested_uniqueness_schema["uniqueness"]["schema"] = TextSubclass(
        nested_uniqueness_schema["uniqueness"]["schema"]
    )
    validators_and_mutations.append(
        (validate_catalog_quality_report, nested_uniqueness_schema)
    )

    for validator, mutation in validators_and_mutations:
        with pytest.raises(ContractError):
            validator(mutation)


def test_anonymity_histogram_keys_are_canonical_json_strings(tmp_path) -> None:
    add_persona(tmp_path, _persona("twin-a"))
    add_persona(tmp_path, _persona("twin-b"))
    uniqueness = catalog_uniqueness(tmp_path)
    quality = catalog_quality_report(tmp_path)

    histograms = (
        uniqueness["anonymity_set_sizes"],
        quality["uniqueness"]["anonymity_set_sizes"],
        quality["usable_anonymity_set_sizes"],
    )
    assert all(histogram for histogram in histograms)
    assert all(
        type(key) is str for histogram in histograms for key in histogram
    )

    uniqueness_mutation = copy.deepcopy(uniqueness)
    uniqueness_mutation["anonymity_set_sizes"] = {
        int(key): value
        for key, value in uniqueness_mutation["anonymity_set_sizes"].items()
    }
    with pytest.raises(ContractError):
        validate_uniqueness_report(uniqueness_mutation)

    for path in (
        ("uniqueness", "anonymity_set_sizes"),
        ("usable_anonymity_set_sizes",),
    ):
        mutation = copy.deepcopy(quality)
        target = mutation
        for segment in path[:-1]:
            target = target[segment]
        target[path[-1]] = {
            int(key): value for key, value in target[path[-1]].items()
        }
        with pytest.raises(ContractError):
            validate_catalog_quality_report(mutation)


def test_anonymity_histogram_keys_are_bounded_before_integer_conversion(
    tmp_path,
) -> None:
    add_persona(tmp_path, _persona("twin-a"))
    add_persona(tmp_path, _persona("twin-b"))
    uniqueness = catalog_uniqueness(tmp_path)
    quality = catalog_quality_report(tmp_path)
    huge_decimal = "9" * 5_000

    direct = copy.deepcopy(uniqueness)
    direct["anonymity_set_sizes"] = {huge_decimal: 1}
    cases = [(validate_uniqueness_report, direct)]
    for path in (
        ("uniqueness", "anonymity_set_sizes"),
        ("usable_anonymity_set_sizes",),
    ):
        mutation = copy.deepcopy(quality)
        target = mutation
        for segment in path[:-1]:
            target = target[segment]
        target[path[-1]] = {huge_decimal: 1}
        cases.append((validate_catalog_quality_report, mutation))

    for validator, document in cases:
        with pytest.raises(ContractError):
            validator(document)


def test_usable_anonymity_groups_are_retained_full_catalog_groups(tmp_path) -> None:
    add_persona(tmp_path, _persona("unique-a"))
    add_persona(
        tmp_path,
        _persona("unique-b", claims={"window.hardwareConcurrency": 16}),
    )
    report = catalog_quality_report(tmp_path)
    assert report["uniqueness"]["anonymity_set_sizes"] == {"1": 2}
    assert report["usable_anonymity_set_sizes"] == {"1": 2}

    # Dropping incoherent personas can shrink or remove identity groups, but it
    # cannot merge two distinct full-catalog vectors into a size-two group.
    report["usable_identities"] = 1
    report["usable_anonymity_set_sizes"] = {"2": 1}

    with pytest.raises(ContractError):
        validate_catalog_quality_report(report)


def test_uniqueness_renderer_recomputes_catalog_arithmetic_and_rankings(
    tmp_path,
) -> None:
    add_persona(tmp_path, _persona("twin-a"))
    add_persona(tmp_path, _persona("twin-b"))
    report = catalog_uniqueness(tmp_path)
    mutations = []
    extra = copy.deepcopy(report)
    extra["private"] = "private-uniqueness-report-marker"
    mutations.append(extra)
    population = copy.deepcopy(report)
    population["distinct_identities"] += 1
    mutations.append(population)
    anonymity = copy.deepcopy(report)
    anonymity["anonymity_set_sizes"] = {1: 2}
    mutations.append(anonymity)
    ratio = copy.deepcopy(report)
    ratio["duplicate_ratio"] = 0.0
    mutations.append(ratio)
    entropy = copy.deepcopy(report)
    entropy["catalog_entropy_bits"] = 1.0
    mutations.append(entropy)
    huge_entropy = copy.deepcopy(report)
    huge_entropy["catalog_entropy_bits"] = 10**400
    mutations.append(huge_entropy)
    largest = copy.deepcopy(report)
    largest["largest_duplicate_group"] = 1
    mutations.append(largest)
    group_count = copy.deepcopy(report)
    group_count["duplicate_group_count"] = 0
    mutations.append(group_count)
    group = copy.deepcopy(report)
    group["duplicate_groups"][0]["size"] = 3
    mutations.append(group)
    field = copy.deepcopy(report)
    field["fields"][0]["entropy_bits"] = 999.0
    mutations.append(field)
    huge_field = copy.deepcopy(report)
    huge_field["fields"][0]["largest_share"] = 10**400
    mutations.append(huge_field)
    identifying = copy.deepcopy(report)
    identifying["most_identifying"] = []
    mutations.append(identifying)
    verdict = copy.deepcopy(report)
    verdict["passed"] = True
    mutations.append(verdict)

    for mutation in mutations:
        with pytest.raises(ContractError) as failure:
            render_uniqueness(mutation)
        assert "private-uniqueness-report-marker" not in str(failure.value)


def test_uniqueness_entropy_validates_a_maximum_histogram_without_expansion(
    monkeypatch,
):
    import browser_core.persona_quality as quality_module

    population = 10_000_000
    report = {
        "schema": UNIQUENESS_SCHEMA,
        "personas": population,
        "distinct_identities": population,
        "unique_personas": population,
        "duplicate_ratio": 0.0,
        "catalog_entropy_bits": round(math.log2(population), 4),
        "maximum_entropy_bits": round(math.log2(population), 4),
        "anonymity_set_sizes": {"1": population},
        "largest_duplicate_group": 1,
        "duplicate_groups": [],
        "duplicate_group_count": 0,
        "fields": [
            {
                "claim": "window.synthetic",
                "present_in": population,
                "distinct_values": population,
                "entropy_bits": round(math.log2(population), 4),
                "largest_share": 0.0,
                "most_common_is_absent": False,
            }
        ],
        "most_identifying": ["window.synthetic"],
        "least_identifying": ["window.synthetic"],
        "passed": True,
    }

    def expansion_is_a_bug(*_args, **_kwargs):
        raise AssertionError("histogram validation must not expand group counts")

    monkeypatch.setattr(quality_module, "_entropy", expansion_is_a_bug)
    assert validate_uniqueness_report(report) is report


def test_duplicate_rows_must_match_histogram_multiplicity(tmp_path):
    for persona_id in ("triple-a", "triple-b", "triple-c"):
        add_persona(tmp_path, _persona(persona_id))
    for persona_id in ("pair-a", "pair-b"):
        add_persona(
            tmp_path,
            _persona(persona_id, claims={"window.hardwareConcurrency": 16}),
        )
    report = catalog_uniqueness(tmp_path)
    assert [group["size"] for group in report["duplicate_groups"]] == [3, 2]

    forged = copy.deepcopy(report)
    forged["duplicate_groups"][1] = {
        "size": 3,
        "persona_ids": ["pair-a", "pair-b", "phantom"],
        "truncated": False,
    }
    with pytest.raises(ContractError, match="group sizes"):
        validate_uniqueness_report(forged)


def test_equal_sized_duplicate_groups_follow_first_persona_order(tmp_path) -> None:
    for persona_id in ("a-one", "a-two"):
        add_persona(tmp_path, _persona(persona_id))
    for persona_id in ("z-one", "z-two"):
        add_persona(
            tmp_path,
            _persona(persona_id, claims={"window.hardwareConcurrency": 16}),
        )
    report = catalog_uniqueness(tmp_path)
    assert [group["persona_ids"] for group in report["duplicate_groups"]] == [
        ["a-one", "a-two"],
        ["z-one", "z-two"],
    ]
    report["duplicate_groups"].reverse()

    with pytest.raises(ContractError, match="group order"):
        validate_uniqueness_report(report)


def test_duplicate_group_ids_use_the_persona_id_grammar(tmp_path) -> None:
    private = "private persona ID marker"
    add_persona(tmp_path, _persona("twin-a"))
    add_persona(tmp_path, _persona("twin-b"))
    uniqueness = catalog_uniqueness(tmp_path)
    quality = catalog_quality_report(tmp_path)

    direct = copy.deepcopy(uniqueness)
    direct["duplicate_groups"][0]["persona_ids"] = sorted([private, "twin-b"])
    nested = copy.deepcopy(quality)
    nested["uniqueness"]["duplicate_groups"][0]["persona_ids"] = sorted(
        [private, "twin-b"]
    )

    for validator, document in (
        (validate_uniqueness_report, direct),
        (validate_catalog_quality_report, nested),
    ):
        with pytest.raises(ContractError) as failure:
            validator(document)
        assert private not in str(failure.value)


def test_duplicate_group_ids_are_casefold_unique(tmp_path) -> None:
    add_persona(tmp_path, _persona("twin-a"))
    add_persona(tmp_path, _persona("twin-b"))
    uniqueness = catalog_uniqueness(tmp_path)
    quality = catalog_quality_report(tmp_path)
    collision = ["TWIN-A", "twin-a"]

    direct = copy.deepcopy(uniqueness)
    direct["duplicate_groups"][0]["persona_ids"] = collision
    nested = copy.deepcopy(quality)
    nested["uniqueness"]["duplicate_groups"][0]["persona_ids"] = collision

    for validator, document in (
        (validate_uniqueness_report, direct),
        (validate_catalog_quality_report, nested),
    ):
        with pytest.raises(ContractError):
            validator(document)


def test_quality_ranking_claims_use_the_identity_path_grammar(tmp_path) -> None:
    add_persona(tmp_path, _persona("ranked"))
    report = catalog_quality_report(tmp_path)
    private = "window.private claim marker"
    assert report["uniqueness"]["most_identifying"]

    report["uniqueness"]["most_identifying"][0] = private
    report["most_identifying"][0] = private

    with pytest.raises(ContractError) as failure:
        validate_catalog_quality_report(report)
    assert private not in str(failure.value)


def test_quality_rankings_have_one_producer_feasible_cardinality(tmp_path) -> None:
    add_persona(tmp_path, _persona("ranked"))
    report = catalog_quality_report(tmp_path)
    most = report["uniqueness"]["most_identifying"]
    least = report["uniqueness"]["least_identifying"]
    assert len(most) == len(least) == 8
    assert most[0] != least[0]

    unequal = copy.deepcopy(report)
    unequal["uniqueness"]["most_identifying"] = most[:1]
    unequal["most_identifying"] = most[:1]

    impossible_single_field = copy.deepcopy(report)
    impossible_single_field["uniqueness"]["most_identifying"] = most[:1]
    impossible_single_field["most_identifying"] = most[:1]
    impossible_single_field["uniqueness"]["least_identifying"] = least[:1]

    for document in (unequal, impossible_single_field):
        with pytest.raises(ContractError):
            validate_catalog_quality_report(document)


def test_quality_ranking_overlap_is_one_ordered_slice(tmp_path) -> None:
    add_persona(tmp_path, _persona("ranked"))
    report = catalog_quality_report(tmp_path)
    most = report["uniqueness"]["most_identifying"]
    assert len(most) == 8

    report["uniqueness"]["least_identifying"] = list(reversed(most))

    with pytest.raises(ContractError):
        validate_catalog_quality_report(report)


def test_coherence_ids_use_the_persona_id_grammar(tmp_path) -> None:
    private = "private persona ID marker"
    add_persona(
        tmp_path,
        _persona("broken", claims={"window.maxTouchPoints": 5}),
    )
    coherence = audit_catalog_coherence(tmp_path)
    quality = catalog_quality_report(tmp_path)

    for finding in coherence["findings"]:
        finding["persona_id"] = private
    coherence["rule_examples"] = {
        rule: private for rule in coherence["rule_examples"]
    }
    coherence["contradicting_personas"] = [private]

    quality["coherence"]["rule_examples"] = {
        rule: private for rule in quality["coherence"]["rule_examples"]
    }
    quality["coherence"]["contradicting_personas"] = [private]

    for validator, document in (
        (validate_coherence_report, coherence),
        (validate_catalog_quality_report, quality),
    ):
        with pytest.raises(ContractError) as failure:
            validator(document)
        assert private not in str(failure.value)


def test_coherence_ids_use_one_casefolded_identity_spelling(tmp_path) -> None:
    for persona_id in ("broken-a", "broken-b"):
        add_persona(
            tmp_path,
            _persona(persona_id, claims={"window.maxTouchPoints": 5}),
        )
    coherence = audit_catalog_coherence(tmp_path)
    quality = catalog_quality_report(tmp_path)
    aliases = {"broken-a": "BROKEN-A", "broken-b": "broken-a"}

    for finding in coherence["findings"]:
        finding["persona_id"] = aliases[finding["persona_id"]]
    examples: dict[str, str] = {}
    for finding in coherence["findings"]:
        examples.setdefault(finding["rule"], finding["persona_id"])
    coherence["rule_examples"] = dict(sorted(examples.items()))
    coherence["contradicting_personas"] = sorted(set(aliases.values()))

    quality["coherence"]["rule_examples"] = {
        rule: "BROKEN-A" for rule in quality["coherence"]["rule_examples"]
    }
    quality["coherence"]["contradicting_personas"] = sorted(set(aliases.values()))

    for validator, document in (
        (validate_coherence_report, coherence),
        (validate_catalog_quality_report, quality),
    ):
        with pytest.raises(ContractError):
            validator(document)


def test_one_coherence_rule_cannot_fire_twice_for_one_persona(tmp_path) -> None:
    add_persona(
        tmp_path,
        _persona("broken", claims={"window.maxTouchPoints": 5}),
    )
    coherence = audit_catalog_coherence(tmp_path)
    quality = catalog_quality_report(tmp_path)

    duplicate = copy.deepcopy(coherence["findings"][0])
    coherence["findings"].append(duplicate)
    coherence["findings_total"] += 1
    coherence["by_severity"][duplicate["severity"]] += 1
    coherence["by_rule"][duplicate["rule"]] += 1

    summary = quality["coherence"]
    summary["findings_total"] += 1
    summary["by_severity"][duplicate["severity"]] += 1
    summary["by_rule"][duplicate["rule"]] += 1

    for validator, document in (
        (validate_coherence_report, coherence),
        (validate_catalog_quality_report, quality),
    ):
        with pytest.raises(ContractError):
            validator(document)


def test_compact_rule_count_cannot_exceed_affected_personas(tmp_path) -> None:
    add_persona(
        tmp_path,
        _persona("broken", claims={"window.maxTouchPoints": 5}),
    )
    add_persona(tmp_path, _persona("clean"))
    report = catalog_quality_report(tmp_path)
    summary = report["coherence"]
    assert summary["personas"] == 2
    assert summary["affected"] == 1
    assert summary["findings_total"] == 1

    rule = next(iter(summary["by_rule"]))
    severity = next(
        name for name, count in summary["by_severity"].items() if count == 1
    )
    summary["by_rule"][rule] = 2
    summary["by_severity"][severity] = 2
    summary["findings_total"] = 2

    with pytest.raises(ContractError):
        validate_catalog_quality_report(report)


def test_one_coherence_rule_has_one_severity(tmp_path) -> None:
    for persona_id in ("broken-a", "broken-b"):
        add_persona(
            tmp_path,
            _persona(persona_id, claims={"window.maxTouchPoints": 5}),
        )
    report = audit_catalog_coherence(tmp_path)
    assert len(report["findings"]) == 2
    assert len({finding["rule"] for finding in report["findings"]}) == 1
    assert report["by_severity"]["contradiction"] == 2

    report["findings"][1]["severity"] = "implausible"
    report["by_severity"]["contradiction"] = 1
    report["by_severity"]["implausible"] = 1
    report["contradicting"] = 1
    report["coherent_ratio"] = 0.5
    report["contradicting_personas"] = sorted(
        finding["persona_id"]
        for finding in report["findings"]
        if finding["severity"] == "contradiction"
    )

    with pytest.raises(ContractError):
        validate_coherence_report(report)


def test_compact_severity_counts_cannot_split_one_rule(tmp_path) -> None:
    for persona_id in ("broken-a", "broken-b"):
        add_persona(
            tmp_path,
            _persona(persona_id, claims={"window.maxTouchPoints": 5}),
        )
    report = catalog_quality_report(tmp_path)
    summary = report["coherence"]
    assert summary["affected"] == 2
    assert summary["by_severity"]["contradiction"] == 2
    assert list(summary["by_rule"].values()) == [2]

    summary["by_severity"]["contradiction"] = 1
    summary["by_severity"]["implausible"] = 1
    summary["contradicting"] = 1
    summary["coherent_ratio"] = 0.5
    summary["contradicting_personas"] = summary["contradicting_personas"][:1]
    report["coherent_personas"] = 1
    report["usable_identities"] = 1
    report["usable_anonymity_set_sizes"] = {"1": 1}

    with pytest.raises(ContractError):
        validate_catalog_quality_report(report)


def test_compact_rule_counts_fit_severity_buckets_together(tmp_path) -> None:
    for persona_id in ("broken-a", "broken-b", "broken-c"):
        add_persona(
            tmp_path,
            _persona(
                persona_id,
                claims={
                    "window.maxTouchPoints": 5,
                    "window.platform": "MacIntel",
                },
            ),
        )
    report = catalog_quality_report(tmp_path)
    summary = report["coherence"]
    assert sorted(summary["by_rule"].values(), reverse=True) == [3, 3]
    assert summary["by_severity"]["contradiction"] == 6

    # Each rule must occupy one severity bucket. One bucket can hold a count of
    # three, but the two largest buckets together cannot hold both rules.
    summary["by_severity"]["contradiction"] = 4
    summary["by_severity"]["implausible"] = 1
    summary["by_severity"]["anomaly"] = 1

    with pytest.raises(ContractError):
        validate_catalog_quality_report(report)


def test_compact_severity_buckets_respect_rule_count_gcd(tmp_path) -> None:
    for persona_id in ("broken-a", "broken-b"):
        add_persona(
            tmp_path,
            _persona(
                persona_id,
                claims={
                    "window.maxTouchPoints": 5,
                    "window.platform": "MacIntel",
                    "window.screen.width": 1280,
                },
            ),
        )
    report = catalog_quality_report(tmp_path)
    summary = report["coherence"]
    assert sorted(summary["by_rule"].values(), reverse=True) == [2, 2, 2]
    assert summary["by_severity"]["contradiction"] == 6

    # Whole rule counts must be assigned to severity buckets. Sums of only
    # two-count rules cannot produce either odd bucket, even though ordered
    # capacity majorization succeeds for [2, 2, 2] against [3, 3, 0].
    summary["by_severity"]["contradiction"] = 3
    summary["by_severity"]["implausible"] = 3

    with pytest.raises(ContractError):
        validate_catalog_quality_report(report)


def test_coherence_rule_names_use_the_producer_grammar(tmp_path) -> None:
    add_persona(
        tmp_path,
        _persona("broken", claims={"window.maxTouchPoints": 5}),
    )
    coherence = audit_catalog_coherence(tmp_path)
    quality = catalog_quality_report(tmp_path)
    private = "private rule marker"

    original = coherence["findings"][0]["rule"]
    coherence["findings"][0]["rule"] = private
    coherence["by_rule"] = {private: coherence["by_rule"][original]}
    coherence["rule_examples"] = {
        private: coherence["rule_examples"][original]
    }

    summary = quality["coherence"]
    summary["by_rule"] = {private: summary["by_rule"][original]}
    summary["rule_examples"] = {private: summary["rule_examples"][original]}

    for validator, document in (
        (validate_coherence_report, coherence),
        (validate_catalog_quality_report, quality),
    ):
        with pytest.raises(ContractError) as failure:
            validator(document)
        assert private not in str(failure.value)


def test_quality_validators_reject_unhashable_private_members_without_raw_errors(
    tmp_path,
):
    add_persona(tmp_path, _persona("twin-a"))
    add_persona(tmp_path, _persona("twin-b"))
    add_persona(tmp_path, _persona("broken", claims={"window.maxTouchPoints": 5}))
    uniqueness = catalog_uniqueness(tmp_path)
    quality = catalog_quality_report(tmp_path)
    private = "private-unhashable-quality-marker"

    documents = []
    bad_id = copy.deepcopy(uniqueness)
    bad_id["duplicate_groups"][0]["persona_ids"][0] = {"private": private}
    documents.append((validate_uniqueness_report, bad_id))
    bad_group = copy.deepcopy(uniqueness)
    bad_group["duplicate_groups"][0] = [private]
    documents.append((validate_uniqueness_report, bad_group))
    bad_rank = copy.deepcopy(quality)
    bad_rank["uniqueness"]["most_identifying"][0] = [private]
    documents.append((validate_catalog_quality_report, bad_rank))
    bad_contradiction = copy.deepcopy(quality)
    bad_contradiction["coherence"]["contradicting_personas"][0] = {"private": private}
    documents.append((validate_catalog_quality_report, bad_contradiction))

    for validator, document in documents:
        with pytest.raises(ContractError) as failure:
            validator(document)
        assert private not in str(failure.value)


def test_differing_personas_are_counted_separately(tmp_path):
    add_persona(tmp_path, _persona("a"))
    add_persona(tmp_path, _persona("b", claims={"window.hardwareConcurrency": 16}))
    report = catalog_uniqueness(tmp_path)
    assert report["distinct_identities"] == 2
    assert report["unique_personas"] == 2
    assert report["passed"] is True


@pytest.mark.parametrize(
    ("first", "second"),
    [(True, 1), ([True], [1])],
)
def test_json_boolean_and_number_claims_are_distinct_identities(
    tmp_path, first, second
) -> None:
    add_persona(tmp_path, _persona("boolean", claims={"window.syntheticSignal": first}))
    add_persona(tmp_path, _persona("number", claims={"window.syntheticSignal": second}))

    uniqueness = catalog_uniqueness(tmp_path)
    quality = catalog_quality_report(tmp_path)
    assert uniqueness["distinct_identities"] == 2
    assert uniqueness["unique_personas"] == 2
    assert uniqueness["passed"] is True
    assert quality["usable_identities"] == 2
    assert quality["passed"] is True


def test_field_entropy_ranks_the_claims_that_separate_the_catalog(tmp_path):
    for index in range(4):
        add_persona(
            tmp_path,
            _persona(
                f"p-{index}", claims={"window.hardwareConcurrency": 2 * (index + 1)}
            ),
        )
    report = catalog_uniqueness(tmp_path)
    concurrency = next(
        item
        for item in report["fields"]
        if item["claim"] == "window.hardwareConcurrency"
    )
    platform = next(
        item for item in report["fields"] if item["claim"] == "window.platform"
    )
    assert concurrency["entropy_bits"] == pytest.approx(2.0)
    assert platform["entropy_bits"] == 0.0, "a constant field separates nothing"
    assert report["most_identifying"][0] == "window.hardwareConcurrency"


def test_uniqueness_field_rows_enforce_derivable_distribution_bounds(
    tmp_path,
) -> None:
    add_persona(tmp_path, _persona("twin-a"))
    add_persona(tmp_path, _persona("twin-b"))
    report = catalog_uniqueness(tmp_path)
    row = report["fields"][0]
    assert row["present_in"] == 2
    assert row["distinct_values"] == 1
    assert row["entropy_bits"] == 0.0
    assert row["largest_share"] == 1.0
    assert row["most_common_is_absent"] is False

    mutations = []
    for field, value in (
        ("distinct_values", 0),
        ("entropy_bits", 1.0),
        ("largest_share", 0.5),
        ("most_common_is_absent", True),
    ):
        mutation = copy.deepcopy(report)
        mutation["fields"][0][field] = value
        mutations.append(mutation)

    for mutation in mutations:
        with pytest.raises(ContractError):
            validate_uniqueness_report(mutation)

    split_workspace = tmp_path / "split"
    add_persona(split_workspace, _persona("split-a"))
    add_persona(
        split_workspace,
        _persona("split-b", claims={"window.hardwareConcurrency": 16}),
    )
    split_report = catalog_uniqueness(split_workspace)
    split_row = next(
        item
        for item in split_report["fields"]
        if item["claim"] == "window.hardwareConcurrency"
    )
    assert split_row["distinct_values"] == 2
    assert split_row["largest_share"] == 0.5
    split_row["largest_share"] = 1.0
    with pytest.raises(ContractError):
        validate_uniqueness_report(split_report)


def test_field_categories_cannot_exceed_catalog_identities(tmp_path) -> None:
    add_persona(tmp_path, _persona("twin-a"))
    add_persona(tmp_path, _persona("twin-b"))
    report = catalog_uniqueness(tmp_path)
    assert report["distinct_identities"] == 1
    row = next(
        item for item in report["fields"] if item["claim"] == "window.platform"
    )
    row["distinct_values"] = 2
    row["entropy_bits"] = 1.0
    row["largest_share"] = 0.5
    report["fields"].sort(
        key=lambda item: (-item["entropy_bits"], item["claim"])
    )
    claims = [item["claim"] for item in report["fields"]]
    report["most_identifying"] = claims[:8]
    report["least_identifying"] = claims[-8:]

    with pytest.raises(ContractError):
        validate_uniqueness_report(report)


def test_catalog_identities_cannot_exceed_joint_field_capacity(tmp_path) -> None:
    add_persona(tmp_path, _persona("unique-a"))
    add_persona(
        tmp_path,
        _persona("unique-b", claims={"window.hardwareConcurrency": 16}),
    )
    report = catalog_uniqueness(tmp_path)
    assert report["distinct_identities"] == 2
    row = next(
        item
        for item in report["fields"]
        if item["claim"] == "window.hardwareConcurrency"
    )
    row["distinct_values"] = 1
    row["entropy_bits"] = 0.0
    row["largest_share"] = 1.0
    report["fields"].sort(
        key=lambda item: (-item["entropy_bits"], item["claim"])
    )
    claims = [item["claim"] for item in report["fields"]]
    report["most_identifying"] = claims[:8]
    report["least_identifying"] = claims[-8:]

    with pytest.raises(ContractError):
        validate_uniqueness_report(report)


def test_field_entropy_cannot_exceed_catalog_entropy(tmp_path) -> None:
    for persona_id in ("twin-a", "twin-b", "twin-c"):
        add_persona(tmp_path, _persona(persona_id))
    add_persona(
        tmp_path,
        _persona("unique", claims={"window.hardwareConcurrency": 16}),
    )
    report = catalog_uniqueness(tmp_path)
    assert report["catalog_entropy_bits"] == 0.8113
    row = next(
        item
        for item in report["fields"]
        if item["claim"] == "window.hardwareConcurrency"
    )
    row["entropy_bits"] = 1.0
    row["largest_share"] = 0.5
    report["fields"].sort(
        key=lambda item: (-item["entropy_bits"], item["claim"])
    )
    claims = [item["claim"] for item in report["fields"]]
    report["most_identifying"] = claims[:8]
    report["least_identifying"] = claims[-8:]

    with pytest.raises(ContractError):
        validate_uniqueness_report(report)


def test_field_largest_bucket_cannot_split_an_identity_group(tmp_path) -> None:
    for index in range(5):
        add_persona(tmp_path, _persona(f"twin-{index}"))
    add_persona(
        tmp_path,
        _persona("hardware", claims={"window.hardwareConcurrency": 16}),
    )
    add_persona(
        tmp_path,
        _persona("locale", claims={"window.locale": "fr-FR"}),
    )
    add_persona(
        tmp_path,
        _persona(
            "both",
            claims={
                "window.hardwareConcurrency": 16,
                "window.locale": "fr-FR",
            },
        ),
    )
    report = catalog_uniqueness(tmp_path)
    assert report["anonymity_set_sizes"] == {"1": 3, "5": 1}
    assert report["largest_duplicate_group"] == 5
    row = next(
        item
        for item in report["fields"]
        if item["claim"] == "window.hardwareConcurrency"
    )
    assert row["largest_share"] == 0.75
    row["entropy_bits"] = 1.0
    row["largest_share"] = 0.5
    report["fields"].sort(
        key=lambda item: (-item["entropy_bits"], item["claim"])
    )
    claims = [item["claim"] for item in report["fields"]]
    report["most_identifying"] = claims[:8]
    report["least_identifying"] = claims[-8:]

    with pytest.raises(ContractError):
        validate_uniqueness_report(report)


def _add_size_two_identity_lattice(workspace) -> None:
    personas = (
        ("base-a", {}),
        ("base-b", {}),
        ("hardware-a", {"window.hardwareConcurrency": 16}),
        ("hardware-b", {"window.hardwareConcurrency": 16}),
        ("locale-a", {"window.locale": "fr-FR"}),
        ("locale-b", {"window.locale": "fr-FR"}),
        (
            "both-a",
            {
                "window.hardwareConcurrency": 16,
                "window.locale": "fr-FR",
            },
        ),
        (
            "both-b",
            {
                "window.hardwareConcurrency": 16,
                "window.locale": "fr-FR",
            },
        ),
    )
    for persona_id, claims in personas:
        add_persona(workspace, _persona(persona_id, claims=claims))


def test_field_largest_bucket_respects_identity_group_gcd(tmp_path) -> None:
    _add_size_two_identity_lattice(tmp_path)
    report = catalog_uniqueness(tmp_path)
    assert report["anonymity_set_sizes"] == {"2": 4}
    row = next(
        item
        for item in report["fields"]
        if item["claim"] == "window.hardwareConcurrency"
    )
    row["distinct_values"] = 3
    row["entropy_bits"] = 1.5613
    row["largest_share"] = 0.375
    report["fields"].sort(
        key=lambda item: (-item["entropy_bits"], item["claim"])
    )
    claims = [item["claim"] for item in report["fields"]]
    report["most_identifying"] = claims[:8]
    report["least_identifying"] = claims[-8:]

    with pytest.raises(ContractError):
        validate_uniqueness_report(report)


def test_field_presence_respects_identity_group_gcd(tmp_path) -> None:
    _add_size_two_identity_lattice(tmp_path)
    report = catalog_uniqueness(tmp_path)
    assert report["anonymity_set_sizes"] == {"2": 4}
    row = next(
        item
        for item in report["fields"]
        if item["claim"] == "window.hardwareConcurrency"
    )
    row["present_in"] = 7
    row["entropy_bits"] = 1.4056
    report["fields"].sort(
        key=lambda item: (-item["entropy_bits"], item["claim"])
    )
    claims = [item["claim"] for item in report["fields"]]
    report["most_identifying"] = claims[:8]
    report["least_identifying"] = claims[-8:]

    with pytest.raises(ContractError):
        validate_uniqueness_report(report)


def test_field_distinct_values_fit_gcd_scaled_presence(tmp_path) -> None:
    _add_size_two_identity_lattice(tmp_path)
    report = catalog_uniqueness(tmp_path)
    assert report["anonymity_set_sizes"] == {"2": 4}
    row = next(
        item
        for item in report["fields"]
        if item["claim"] == "window.hardwareConcurrency"
    )
    row["present_in"] = 2
    row["distinct_values"] = 2
    row["entropy_bits"] = 1.0613
    row["largest_share"] = 0.75
    row["most_common_is_absent"] = True
    report["fields"].sort(
        key=lambda item: (-item["entropy_bits"], item["claim"])
    )
    claims = [item["claim"] for item in report["fields"]]
    report["most_identifying"] = claims[:8]
    report["least_identifying"] = claims[-8:]

    with pytest.raises(ContractError):
        validate_uniqueness_report(report)


def test_field_entropy_is_feasible_after_identity_gcd_scaling(tmp_path) -> None:
    _add_size_two_identity_lattice(tmp_path)
    report = catalog_uniqueness(tmp_path)
    assert report["anonymity_set_sizes"] == {"2": 4}
    row = next(
        item
        for item in report["fields"]
        if item["claim"] == "window.hardwareConcurrency"
    )
    row["distinct_values"] = 3
    row["entropy_bits"] = 1.4056
    report["fields"].sort(
        key=lambda item: (-item["entropy_bits"], item["claim"])
    )
    claims = [item["claim"] for item in report["fields"]]
    report["most_identifying"] = claims[:8]
    report["least_identifying"] = claims[-8:]

    with pytest.raises(ContractError):
        validate_uniqueness_report(report)


@pytest.mark.parametrize(
    ("present", "absence_wins"),
    [(1, True), (4, False)],
)
def test_field_presence_sides_fit_smallest_identity_group(
    tmp_path, present: int, absence_wins: bool
) -> None:
    for persona_id in ("base-a", "base-b"):
        add_persona(tmp_path, _persona(persona_id))
    for persona_id in ("hardware-a", "hardware-b", "hardware-c"):
        add_persona(
            tmp_path,
            _persona(persona_id, claims={"window.hardwareConcurrency": 16}),
        )
    report = catalog_uniqueness(tmp_path)
    assert report["anonymity_set_sizes"] == {"2": 1, "3": 1}
    row = next(
        item for item in report["fields"] if item["claim"] == "window.locale"
    )
    row["present_in"] = present
    row["entropy_bits"] = 0.7219
    row["largest_share"] = 0.8
    row["most_common_is_absent"] = absence_wins
    report["fields"].sort(
        key=lambda item: (-item["entropy_bits"], item["claim"])
    )
    claims = [item["claim"] for item in report["fields"]]
    report["most_identifying"] = claims[:8]
    report["least_identifying"] = claims[-8:]

    with pytest.raises(ContractError):
        validate_uniqueness_report(report)


def _add_two_four_five_identity_groups(workspace) -> None:
    for index in range(5):
        add_persona(workspace, _persona(f"base-{index}"))
    for index in range(4):
        add_persona(
            workspace,
            _persona(
                f"hardware-{index}",
                claims={"window.hardwareConcurrency": 16},
            ),
        )
    for index in range(2):
        add_persona(
            workspace,
            _persona(f"locale-{index}", claims={"window.locale": "fr-FR"}),
        )


def _add_two_four_five_six_identity_groups(workspace) -> None:
    _add_two_four_five_identity_groups(workspace)
    for index in range(6):
        add_persona(
            workspace,
            _persona(
                f"plugins-{index}",
                claims={"window.pluginsLength": 4},
            ),
        )


def _add_two_three_four_ten_identity_groups(workspace) -> None:
    for index in range(10):
        add_persona(workspace, _persona(f"base-{index}"))
    for index in range(4):
        add_persona(
            workspace,
            _persona(
                f"hardware-{index}",
                claims={"window.hardwareConcurrency": 16},
            ),
        )
    for index in range(3):
        add_persona(
            workspace,
            _persona(f"locale-{index}", claims={"window.locale": "fr-FR"}),
        )
    for index in range(2):
        add_persona(
            workspace,
            _persona(
                f"plugins-{index}",
                claims={"window.pluginsLength": 4},
            ),
        )


def _add_two_three_four_six_identity_groups(workspace) -> None:
    for index in range(6):
        add_persona(workspace, _persona(f"base-{index}"))
    for index in range(4):
        add_persona(
            workspace,
            _persona(
                f"hardware-{index}",
                claims={"window.hardwareConcurrency": 16},
            ),
        )
    for index in range(3):
        add_persona(
            workspace,
            _persona(f"locale-{index}", claims={"window.locale": "fr-FR"}),
        )
    for index in range(2):
        add_persona(
            workspace,
            _persona(
                f"plugins-{index}",
                claims={"window.pluginsLength": 4},
            ),
        )


def _add_two_three_four_identity_groups(workspace) -> None:
    for index in range(4):
        add_persona(workspace, _persona(f"base-{index}"))
    for index in range(3):
        add_persona(
            workspace,
            _persona(
                f"hardware-{index}",
                claims={"window.hardwareConcurrency": 16},
            ),
        )
    for index in range(2):
        add_persona(
            workspace,
            _persona(f"locale-{index}", claims={"window.locale": "fr-FR"}),
        )


def _add_two_three_four_five_identity_groups(workspace) -> None:
    for index in range(5):
        add_persona(workspace, _persona(f"base-{index}"))
    for index in range(4):
        add_persona(
            workspace,
            _persona(
                f"hardware-{index}",
                claims={"window.hardwareConcurrency": 16},
            ),
        )
    for index in range(3):
        add_persona(
            workspace,
            _persona(f"locale-{index}", claims={"window.locale": "fr-FR"}),
        )
    for index in range(2):
        add_persona(
            workspace,
            _persona(
                f"plugins-{index}",
                claims={"window.pluginsLength": 4},
            ),
        )


def _add_large_conditional_value_capacity_groups(workspace) -> None:
    for index in range(92):
        add_persona(workspace, _persona(f"base-{index}"))
    for index in range(73):
        add_persona(
            workspace,
            _persona(
                f"hardware-{index}",
                claims={"window.hardwareConcurrency": 16},
            ),
        )
    for index in range(55):
        add_persona(
            workspace,
            _persona(f"locale-{index}", claims={"window.locale": "fr-FR"}),
        )
    for index in range(37):
        add_persona(
            workspace,
            _persona(
                f"plugins-{index}",
                claims={"window.pluginsLength": 4},
            ),
        )


def _add_three_singletons_and_two_size_three_identity_groups(workspace) -> None:
    for index in range(3):
        add_persona(workspace, _persona(f"base-{index}"))
    for index in range(3):
        add_persona(
            workspace,
            _persona(
                f"hardware-{index}",
                claims={"window.hardwareConcurrency": 16},
            ),
        )
    for persona_id, claims in (
        ("locale", {"window.locale": "fr-FR"}),
        ("plugins", {"window.pluginsLength": 4}),
        ("timezone", {"window.timezone": "Europe/Paris"}),
    ):
        add_persona(workspace, _persona(persona_id, claims=claims))


def _add_four_five_and_three_size_six_identity_groups(workspace) -> None:
    for index in range(6):
        add_persona(workspace, _persona(f"base-{index}"))
    for prefix, count, claims in (
        ("hardware", 6, {"window.hardwareConcurrency": 16}),
        ("locale", 6, {"window.locale": "fr-FR"}),
        ("plugins", 5, {"window.pluginsLength": 4}),
        ("timezone", 4, {"window.timezone": "Europe/Paris"}),
    ):
        for index in range(count):
            add_persona(
                workspace,
                _persona(f"{prefix}-{index}", claims=claims),
            )


def _add_two_singletons_and_seven_size_four_identity_groups(workspace) -> None:
    for group_index, group_size in enumerate((*([4] * 7), 1, 1)):
        for member_index in range(group_size):
            add_persona(
                workspace,
                _persona(
                    f"group-{group_index}-{member_index}",
                    claims={"window.synthetic": f"group-{group_index}"},
                ),
            )


def _add_two_three_three_four_identity_groups(workspace) -> None:
    for group_index, group_size in enumerate((2, 3, 3, 4)):
        for member_index in range(group_size):
            add_persona(
                workspace,
                _persona(
                    f"group-{group_index}-{member_index}",
                    claims={"window.synthetic": f"group-{group_index}"},
                ),
            )


def _add_two_two_four_four_identity_groups(workspace) -> None:
    for group_index, group_size in enumerate((2, 2, 4, 4)):
        for member_index in range(group_size):
            add_persona(
                workspace,
                _persona(
                    f"group-{group_index}-{member_index}",
                    claims={"window.synthetic": f"group-{group_index}"},
                ),
            )


def _add_one_one_three_three_identity_groups(workspace) -> None:
    for group_index, group_size in enumerate((1, 1, 3, 3)):
        for member_index in range(group_size):
            add_persona(
                workspace,
                _persona(
                    f"group-{group_index}-{member_index}",
                    claims={"window.synthetic": f"group-{group_index}"},
                ),
            )


def _gcd_scaled_two_and_five_histogram_report(workspace) -> dict:
    for group_index, group_size in enumerate((*([2] * 24), 5)):
        for member_index in range(group_size):
            add_persona(
                workspace,
                _persona(
                    f"group-{group_index}-{member_index}",
                    claims={"window.synthetic": f"group-{group_index}"},
                ),
            )
    report = catalog_uniqueness(workspace)
    assert report["anonymity_set_sizes"] == {"2": 24, "5": 1}

    scale = 2_000
    report["personas"] *= scale
    report["duplicate_ratio"] = round(
        1 - report["distinct_identities"] / report["personas"], 4
    )
    report["maximum_entropy_bits"] = round(
        persona_quality_module._maximum_entropy_bits(report["personas"]), 4
    )
    report["anonymity_set_sizes"] = {
        str(int(size) * scale): groups
        for size, groups in report["anonymity_set_sizes"].items()
    }
    report["largest_duplicate_group"] *= scale
    for group_index, group in enumerate(report["duplicate_groups"]):
        group["size"] *= scale
        group["persona_ids"] = [
            f"scaled-{group_index:02d}-{member_index:02d}"
            for member_index in range(12)
        ]
        group["truncated"] = True
    for row in report["fields"]:
        row["present_in"] *= scale
    return report


def _gcd_scaled_two_and_six_histogram_report(workspace) -> dict:
    for group_index, group_size in enumerate((*([2] * 3), *([6] * 23))):
        for member_index in range(group_size):
            add_persona(
                workspace,
                _persona(
                    f"group-{group_index}-{member_index}",
                    claims={"window.synthetic": f"group-{group_index}"},
                ),
            )
    report = catalog_uniqueness(workspace)
    assert report["anonymity_set_sizes"] == {"2": 3, "6": 23}

    scale = 2_000
    report["personas"] *= scale
    report["duplicate_ratio"] = round(
        1 - report["distinct_identities"] / report["personas"], 4
    )
    report["maximum_entropy_bits"] = round(
        persona_quality_module._maximum_entropy_bits(report["personas"]), 4
    )
    report["anonymity_set_sizes"] = {
        str(int(size) * scale): groups
        for size, groups in report["anonymity_set_sizes"].items()
    }
    report["largest_duplicate_group"] *= scale
    for group_index, group in enumerate(report["duplicate_groups"]):
        group["size"] *= scale
        group["persona_ids"] = [
            f"scaled-{group_index:02d}-{member_index:02d}"
            for member_index in range(12)
        ]
        group["truncated"] = True
    for row in report["fields"]:
        row["present_in"] *= scale
    return report


def _add_one_five_six_and_seven_size_nine_identity_groups(workspace) -> None:
    for group_index, group_size in enumerate((*([9] * 7), 6, 5, 1)):
        for member_index in range(group_size):
            add_persona(
                workspace,
                _persona(
                    f"group-{group_index}-{member_index}",
                    claims={"window.synthetic": f"group-{group_index}"},
                ),
            )


def test_field_presence_is_subset_sum_of_small_catalog_groups(tmp_path) -> None:
    _add_two_four_five_identity_groups(tmp_path)
    report = catalog_uniqueness(tmp_path)
    assert report["anonymity_set_sizes"] == {"2": 1, "4": 1, "5": 1}
    row = next(
        item for item in report["fields"] if item["claim"] == "window.platform"
    )
    row["present_in"] = 3
    row["entropy_bits"] = 0.8454
    row["largest_share"] = 0.7273
    row["most_common_is_absent"] = True
    report["fields"].sort(
        key=lambda item: (-item["entropy_bits"], item["claim"])
    )
    claims = [item["claim"] for item in report["fields"]]
    report["most_identifying"] = claims[:8]
    report["least_identifying"] = claims[-8:]

    with pytest.raises(ContractError):
        validate_uniqueness_report(report)


def test_field_largest_bucket_is_subset_sum_of_small_catalog_groups(
    tmp_path,
) -> None:
    _add_two_four_five_identity_groups(tmp_path)
    report = catalog_uniqueness(tmp_path)
    assert report["anonymity_set_sizes"] == {"2": 1, "4": 1, "5": 1}
    row = next(
        item for item in report["fields"] if item["claim"] == "window.platform"
    )
    row["distinct_values"] = 2
    row["entropy_bits"] = 0.8454
    row["largest_share"] = 0.7273
    report["fields"].sort(
        key=lambda item: (-item["entropy_bits"], item["claim"])
    )
    claims = [item["claim"] for item in report["fields"]]
    report["most_identifying"] = claims[:8]
    report["least_identifying"] = claims[-8:]

    with pytest.raises(ContractError):
        validate_uniqueness_report(report)


def test_field_other_present_buckets_are_subset_sum_of_small_catalog_groups(
    tmp_path,
) -> None:
    _add_two_four_five_identity_groups(tmp_path)
    report = catalog_uniqueness(tmp_path)
    assert report["anonymity_set_sizes"] == {"2": 1, "4": 1, "5": 1}
    row = next(
        item for item in report["fields"] if item["claim"] == "window.platform"
    )
    row["present_in"] = 6
    row["distinct_values"] = 2
    row["entropy_bits"] = 1.3486
    row["largest_share"] = 0.4545
    row["most_common_is_absent"] = False
    report["fields"].sort(
        key=lambda item: (-item["entropy_bits"], item["claim"])
    )
    claims = [item["claim"] for item in report["fields"]]
    report["most_identifying"] = claims[:8]
    report["least_identifying"] = claims[-8:]

    with pytest.raises(ContractError):
        validate_uniqueness_report(report)


def test_field_values_fit_minimum_identity_group_capacity(tmp_path) -> None:
    _add_two_four_five_identity_groups(tmp_path)
    report = catalog_uniqueness(tmp_path)
    assert report["anonymity_set_sizes"] == {"2": 1, "4": 1, "5": 1}
    row = next(
        item for item in report["fields"] if item["claim"] == "window.platform"
    )
    row["present_in"] = 2
    row["distinct_values"] = 2
    row["entropy_bits"] = 0.8659
    row["largest_share"] = 0.8182
    row["most_common_is_absent"] = True
    report["fields"].sort(
        key=lambda item: (-item["entropy_bits"], item["claim"])
    )
    claims = [item["claim"] for item in report["fields"]]
    report["most_identifying"] = claims[:8]
    report["least_identifying"] = claims[-8:]

    with pytest.raises(ContractError):
        validate_uniqueness_report(report)


def test_field_values_leave_enough_identity_groups_for_absence(tmp_path) -> None:
    _add_two_four_five_six_identity_groups(tmp_path)
    report = catalog_uniqueness(tmp_path)
    assert report["anonymity_set_sizes"] == {
        "2": 1,
        "4": 1,
        "5": 1,
        "6": 1,
    }
    row = next(
        item for item in report["fields"] if item["claim"] == "window.platform"
    )
    row["present_in"] = 6
    row["distinct_values"] = 3
    row["entropy_bits"] = 1.3784
    row["largest_share"] = 0.6471
    row["most_common_is_absent"] = True
    report["fields"].sort(
        key=lambda item: (-item["entropy_bits"], item["claim"])
    )
    claims = [item["claim"] for item in report["fields"]]
    report["most_identifying"] = claims[:8]
    report["least_identifying"] = claims[-8:]

    with pytest.raises(ContractError):
        validate_uniqueness_report(report)


def test_field_absence_capacity_respects_largest_group_multiplicity(
    tmp_path,
) -> None:
    _add_two_three_four_ten_identity_groups(tmp_path)
    report = catalog_uniqueness(tmp_path)
    assert report["anonymity_set_sizes"] == {
        "2": 1,
        "3": 1,
        "4": 1,
        "10": 1,
    }
    row = next(
        item for item in report["fields"] if item["claim"] == "window.platform"
    )
    row["present_in"] = 4
    row["distinct_values"] = 2
    row["entropy_bits"] = 0.9133
    row["largest_share"] = 0.7895
    row["most_common_is_absent"] = True
    report["fields"].sort(
        key=lambda item: (-item["entropy_bits"], item["claim"])
    )
    claims = [item["claim"] for item in report["fields"]]
    report["most_identifying"] = claims[:8]
    report["least_identifying"] = claims[-8:]

    with pytest.raises(ContractError):
        validate_uniqueness_report(report)


def test_field_values_fit_exact_present_subset_group_count(tmp_path) -> None:
    _add_two_three_four_six_identity_groups(tmp_path)
    report = catalog_uniqueness(tmp_path)
    assert report["anonymity_set_sizes"] == {
        "2": 1,
        "3": 1,
        "4": 1,
        "6": 1,
    }
    row = next(
        item for item in report["fields"] if item["claim"] == "window.platform"
    )
    row["present_in"] = 10
    row["distinct_values"] = 3
    row["entropy_bits"] = 1.8323
    row["largest_share"] = 0.4
    row["most_common_is_absent"] = False
    report["fields"].sort(
        key=lambda item: (-item["entropy_bits"], item["claim"])
    )
    claims = [item["claim"] for item in report["fields"]]
    report["most_identifying"] = claims[:8]
    report["least_identifying"] = claims[-8:]

    with pytest.raises(ContractError):
        validate_uniqueness_report(report)


def test_field_largest_and_other_present_subsets_are_disjoint(tmp_path) -> None:
    _add_two_three_four_identity_groups(tmp_path)
    report = catalog_uniqueness(tmp_path)
    assert report["anonymity_set_sizes"] == {
        "2": 1,
        "3": 1,
        "4": 1,
    }
    row = next(
        item for item in report["fields"] if item["claim"] == "window.platform"
    )
    row["present_in"] = 7
    row["distinct_values"] = 2
    row["entropy_bits"] = 1.4355
    row["largest_share"] = 0.5556
    row["most_common_is_absent"] = False
    report["fields"].sort(
        key=lambda item: (-item["entropy_bits"], item["claim"])
    )
    claims = [item["claim"] for item in report["fields"]]
    report["most_identifying"] = claims[:8]
    report["least_identifying"] = claims[-8:]

    with pytest.raises(ContractError):
        validate_uniqueness_report(report)


def test_field_other_present_subset_has_enough_groups_for_values(
    tmp_path,
) -> None:
    _add_two_three_four_five_identity_groups(tmp_path)
    report = catalog_uniqueness(tmp_path)
    assert report["anonymity_set_sizes"] == {
        "2": 1,
        "3": 1,
        "4": 1,
        "5": 1,
    }
    row = next(
        item for item in report["fields"] if item["claim"] == "window.platform"
    )
    row["present_in"] = 9
    row["distinct_values"] = 3
    row["entropy_bits"] = 1.8092
    row["largest_share"] = 0.3571
    row["most_common_is_absent"] = False
    report["fields"].sort(
        key=lambda item: (-item["entropy_bits"], item["claim"])
    )
    claims = [item["claim"] for item in report["fields"]]
    report["most_identifying"] = claims[:8]
    report["least_identifying"] = claims[-8:]

    with pytest.raises(ContractError):
        validate_uniqueness_report(report)


def test_field_other_present_global_group_capacity_above_joint_count_cap(
    tmp_path,
) -> None:
    _add_large_conditional_value_capacity_groups(tmp_path)
    report = catalog_uniqueness(tmp_path)
    assert report["anonymity_set_sizes"] == {
        "37": 1,
        "55": 1,
        "73": 1,
        "92": 1,
    }
    row = next(
        item for item in report["fields"] if item["claim"] == "window.platform"
    )
    row["present_in"] = 165
    row["distinct_values"] = 3
    row["entropy_bits"] = 1.8609
    row["largest_share"] = 0.358
    row["most_common_is_absent"] = False
    report["fields"].sort(
        key=lambda item: (-item["entropy_bits"], item["claim"])
    )
    claims = [item["claim"] for item in report["fields"]]
    report["most_identifying"] = claims[:8]
    report["least_identifying"] = claims[-8:]

    with pytest.raises(ContractError):
        validate_uniqueness_report(report)


def test_field_conditional_group_capacity_rejects_global_false_positive(
    tmp_path,
) -> None:
    _add_three_singletons_and_two_size_three_identity_groups(tmp_path)
    report = catalog_uniqueness(tmp_path)
    assert report["anonymity_set_sizes"] == {"1": 3, "3": 2}
    row = next(
        item for item in report["fields"] if item["claim"] == "window.platform"
    )
    row["present_in"] = 7
    row["distinct_values"] = 3
    row["entropy_bits"] = 1.8366
    row["largest_share"] = 0.4444
    row["most_common_is_absent"] = False
    report["fields"].sort(
        key=lambda item: (-item["entropy_bits"], item["claim"])
    )
    claims = [item["claim"] for item in report["fields"]]
    report["most_identifying"] = claims[:8]
    report["least_identifying"] = claims[-8:]

    with pytest.raises(ContractError):
        validate_uniqueness_report(report)


def test_field_buckets_cannot_fit_too_many_half_capacity_identity_groups(
    tmp_path,
) -> None:
    _add_four_five_and_three_size_six_identity_groups(tmp_path)
    report = catalog_uniqueness(tmp_path)
    assert report["anonymity_set_sizes"] == {"4": 1, "5": 1, "6": 3}
    row = next(
        item for item in report["fields"] if item["claim"] == "window.platform"
    )
    row["present_in"] = 27
    row["distinct_values"] = 3
    row["entropy_bits"] = 1.585
    row["largest_share"] = 0.3333
    row["most_common_is_absent"] = False
    report["fields"].sort(
        key=lambda item: (-item["entropy_bits"], item["claim"])
    )
    claims = [item["claim"] for item in report["fields"]]
    report["most_identifying"] = claims[:8]
    report["least_identifying"] = claims[-8:]

    with pytest.raises(ContractError):
        validate_uniqueness_report(report)


def test_field_buckets_cannot_fit_too_many_threshold_identity_groups(
    tmp_path,
) -> None:
    _add_two_singletons_and_seven_size_four_identity_groups(tmp_path)
    report = catalog_uniqueness(tmp_path)
    assert report["anonymity_set_sizes"] == {"1": 2, "4": 7}
    row = next(
        item for item in report["fields"] if item["claim"] == "window.platform"
    )
    row["present_in"] = 30
    row["distinct_values"] = 3
    row["entropy_bits"] = 1.585
    row["largest_share"] = 0.3333
    row["most_common_is_absent"] = False
    report["fields"].sort(
        key=lambda item: (-item["entropy_bits"], item["claim"])
    )
    claims = [item["claim"] for item in report["fields"]]
    report["most_identifying"] = claims[:8]
    report["least_identifying"] = claims[-8:]

    with pytest.raises(ContractError):
        validate_uniqueness_report(report)


def test_equal_field_buckets_require_exact_identity_class_partition(
    tmp_path,
) -> None:
    _add_two_three_three_four_identity_groups(tmp_path)
    report = catalog_uniqueness(tmp_path)
    assert report["anonymity_set_sizes"] == {"2": 1, "3": 2, "4": 1}
    row = next(
        item for item in report["fields"] if item["claim"] == "window.platform"
    )
    row["distinct_values"] = 3
    row["entropy_bits"] = 1.585
    row["largest_share"] = 0.3333
    report["fields"].sort(
        key=lambda item: (-item["entropy_bits"], item["claim"])
    )
    claims = [item["claim"] for item in report["fields"]]
    report["most_identifying"] = claims[:8]
    report["least_identifying"] = claims[-8:]

    with pytest.raises(ContractError):
        validate_uniqueness_report(report)


def test_equal_field_buckets_accept_exact_identity_class_partition(
    tmp_path,
) -> None:
    _add_two_two_four_four_identity_groups(tmp_path)
    report = catalog_uniqueness(tmp_path)
    assert report["anonymity_set_sizes"] == {"2": 2, "4": 2}
    row = next(
        item for item in report["fields"] if item["claim"] == "window.platform"
    )
    row["distinct_values"] = 3
    row["entropy_bits"] = 1.585
    row["largest_share"] = 0.3333
    report["fields"].sort(
        key=lambda item: (-item["entropy_bits"], item["claim"])
    )
    claims = [item["claim"] for item in report["fields"]]
    report["most_identifying"] = claims[:8]
    report["least_identifying"] = claims[-8:]

    assert validate_uniqueness_report(report) == report


def test_equal_field_buckets_with_absence_require_exact_identity_partition(
    tmp_path,
) -> None:
    _add_two_three_three_four_identity_groups(tmp_path)
    report = catalog_uniqueness(tmp_path)
    assert report["anonymity_set_sizes"] == {"2": 1, "3": 2, "4": 1}
    row = next(
        item for item in report["fields"] if item["claim"] == "window.platform"
    )
    row["present_in"] = 8
    row["distinct_values"] = 2
    row["entropy_bits"] = 1.585
    row["largest_share"] = 0.3333
    row["most_common_is_absent"] = True
    report["fields"].sort(
        key=lambda item: (-item["entropy_bits"], item["claim"])
    )
    claims = [item["claim"] for item in report["fields"]]
    report["most_identifying"] = claims[:8]
    report["least_identifying"] = claims[-8:]

    with pytest.raises(ContractError):
        validate_uniqueness_report(report)


def test_equal_field_buckets_with_absence_accept_exact_identity_partition(
    tmp_path,
) -> None:
    _add_two_two_four_four_identity_groups(tmp_path)
    report = catalog_uniqueness(tmp_path)
    assert report["anonymity_set_sizes"] == {"2": 2, "4": 2}
    row = next(
        item for item in report["fields"] if item["claim"] == "window.platform"
    )
    row["present_in"] = 8
    row["distinct_values"] = 2
    row["entropy_bits"] = 1.585
    row["largest_share"] = 0.3333
    row["most_common_is_absent"] = True
    report["fields"].sort(
        key=lambda item: (-item["entropy_bits"], item["claim"])
    )
    claims = [item["claim"] for item in report["fields"]]
    report["most_identifying"] = claims[:8]
    report["least_identifying"] = claims[-8:]

    assert validate_uniqueness_report(report) == report


def test_field_histogram_requires_exact_identity_class_partition(
    tmp_path,
) -> None:
    _add_one_one_three_three_identity_groups(tmp_path)
    report = catalog_uniqueness(tmp_path)
    assert report["anonymity_set_sizes"] == {"1": 2, "3": 2}
    row = next(
        item for item in report["fields"] if item["claim"] == "window.platform"
    )
    row["distinct_values"] = 3
    row["entropy_bits"] = 1.5
    row["largest_share"] = 0.5
    report["fields"].sort(
        key=lambda item: (-item["entropy_bits"], item["claim"])
    )
    claims = [item["claim"] for item in report["fields"]]
    report["most_identifying"] = claims[:8]
    report["least_identifying"] = claims[-8:]

    with pytest.raises(ContractError):
        validate_uniqueness_report(report)


def test_field_histogram_accepts_exact_identity_class_partition(tmp_path) -> None:
    _add_one_one_three_three_identity_groups(tmp_path)
    report = catalog_uniqueness(tmp_path)
    assert report["anonymity_set_sizes"] == {"1": 2, "3": 2}
    row = next(
        item for item in report["fields"] if item["claim"] == "window.platform"
    )
    row["distinct_values"] = 3
    row["entropy_bits"] = 1.4056
    row["largest_share"] = 0.5
    report["fields"].sort(
        key=lambda item: (-item["entropy_bits"], item["claim"])
    )
    claims = [item["claim"] for item in report["fields"]]
    report["most_identifying"] = claims[:8]
    report["least_identifying"] = claims[-8:]

    assert validate_uniqueness_report(report) == report


@pytest.mark.parametrize(
    ("group_sizes", "should_reject"),
    [
        ((12, 18, 18, 24), True),
        ((12, 12, 24, 24), False),
    ],
)
def test_exact_partition_search_uses_gcd_scaled_population(
    tmp_path, group_sizes: tuple[int, ...], should_reject: bool
) -> None:
    for group_index, group_size in enumerate(group_sizes):
        for member_index in range(group_size):
            add_persona(
                tmp_path,
                _persona(
                    f"group-{group_index}-{member_index}",
                    claims={"window.synthetic": f"group-{group_index}"},
                ),
            )
    report = catalog_uniqueness(tmp_path)
    row = next(
        item for item in report["fields"] if item["claim"] == "window.platform"
    )
    row["distinct_values"] = 3
    row["entropy_bits"] = 1.585
    row["largest_share"] = 0.3333
    report["fields"].sort(
        key=lambda item: (-item["entropy_bits"], item["claim"])
    )
    claims = [item["claim"] for item in report["fields"]]
    report["most_identifying"] = claims[:8]
    report["least_identifying"] = claims[-8:]

    if should_reject:
        with pytest.raises(ContractError):
            validate_uniqueness_report(report)
    else:
        assert validate_uniqueness_report(report) == report


@pytest.mark.parametrize(
    ("scaled_present", "should_reject"),
    [(50, True), (49, False)],
)
def test_presence_subset_search_uses_gcd_scaled_population_above_raw_cap(
    tmp_path, scaled_present: int, should_reject: bool
) -> None:
    report = _gcd_scaled_two_and_five_histogram_report(tmp_path)
    scale = 2_000
    row = next(
        item for item in report["fields"] if item["claim"] == "window.platform"
    )
    row["present_in"] = scaled_present * scale
    row["distinct_values"] = 1
    row["entropy_bits"] = round(
        persona_quality_module._entropy((scaled_present, 53 - scaled_present)), 4
    )
    row["largest_share"] = round(scaled_present / 53, 4)
    row["most_common_is_absent"] = False
    report["fields"].sort(
        key=lambda item: (-item["entropy_bits"], item["claim"])
    )
    claims = [item["claim"] for item in report["fields"]]
    report["most_identifying"] = claims[:8]
    report["least_identifying"] = claims[-8:]

    if should_reject:
        with pytest.raises(ContractError):
            validate_uniqueness_report(report)
    else:
        assert validate_uniqueness_report(report) == report


@pytest.mark.parametrize(
    ("scaled_largest", "should_reject"),
    [(50, True), (49, False)],
)
def test_largest_bucket_subset_search_uses_gcd_scaled_population_above_raw_cap(
    tmp_path, scaled_largest: int, should_reject: bool
) -> None:
    report = _gcd_scaled_two_and_five_histogram_report(tmp_path)
    row = next(
        item for item in report["fields"] if item["claim"] == "window.platform"
    )
    row["distinct_values"] = 2
    row["entropy_bits"] = round(
        persona_quality_module._entropy((scaled_largest, 53 - scaled_largest)), 4
    )
    row["largest_share"] = round(scaled_largest / 53, 4)
    report["fields"].sort(
        key=lambda item: (-item["entropy_bits"], item["claim"])
    )
    claims = [item["claim"] for item in report["fields"]]
    report["most_identifying"] = claims[:8]
    report["least_identifying"] = claims[-8:]

    if should_reject:
        with pytest.raises(ContractError):
            validate_uniqueness_report(report)
    else:
        assert validate_uniqueness_report(report) == report


@pytest.mark.parametrize(
    ("scaled_present", "bucket_counts", "should_reject"),
    [(5, (48, 3, 2), True), (4, (49, 2, 2), False)],
)
def test_present_value_capacity_uses_gcd_scaled_population_above_raw_cap(
    tmp_path,
    scaled_present: int,
    bucket_counts: tuple[int, ...],
    should_reject: bool,
) -> None:
    report = _gcd_scaled_two_and_five_histogram_report(tmp_path)
    scale = 2_000
    row = next(
        item for item in report["fields"] if item["claim"] == "window.platform"
    )
    row["present_in"] = scaled_present * scale
    row["distinct_values"] = 2
    row["entropy_bits"] = round(
        persona_quality_module._entropy(bucket_counts), 4
    )
    row["largest_share"] = round(bucket_counts[0] / 53, 4)
    row["most_common_is_absent"] = True
    report["fields"].sort(
        key=lambda item: (-item["entropy_bits"], item["claim"])
    )
    claims = [item["claim"] for item in report["fields"]]
    report["most_identifying"] = claims[:8]
    report["least_identifying"] = claims[-8:]

    if should_reject:
        with pytest.raises(ContractError):
            validate_uniqueness_report(report)
    else:
        assert validate_uniqueness_report(report) == report


@pytest.mark.parametrize(
    ("bucket_counts", "should_reject"),
    [((48, 3, 2), True), ((49, 2, 2), False)],
)
def test_other_present_value_capacity_uses_gcd_scaled_population_above_raw_cap(
    tmp_path,
    bucket_counts: tuple[int, ...],
    should_reject: bool,
) -> None:
    report = _gcd_scaled_two_and_five_histogram_report(tmp_path)
    row = next(
        item for item in report["fields"] if item["claim"] == "window.platform"
    )
    row["distinct_values"] = 3
    row["entropy_bits"] = round(
        persona_quality_module._entropy(bucket_counts), 4
    )
    row["largest_share"] = round(bucket_counts[0] / 53, 4)
    report["fields"].sort(
        key=lambda item: (-item["entropy_bits"], item["claim"])
    )
    claims = [item["claim"] for item in report["fields"]]
    report["most_identifying"] = claims[:8]
    report["least_identifying"] = claims[-8:]

    if should_reject:
        with pytest.raises(ContractError):
            validate_uniqueness_report(report)
    else:
        assert validate_uniqueness_report(report) == report


@pytest.mark.parametrize(
    ("scaled_present", "bucket_counts", "should_reject"),
    [(48, (43, 5, 5), True), (49, (45, 4, 4), False)],
)
def test_joint_largest_reachability_uses_gcd_scaled_population_above_raw_cap(
    tmp_path,
    scaled_present: int,
    bucket_counts: tuple[int, ...],
    should_reject: bool,
) -> None:
    report = _gcd_scaled_two_and_five_histogram_report(tmp_path)
    scale = 2_000
    row = next(
        item for item in report["fields"] if item["claim"] == "window.platform"
    )
    row["present_in"] = scaled_present * scale
    row["distinct_values"] = 2
    row["entropy_bits"] = round(
        persona_quality_module._entropy(bucket_counts), 4
    )
    row["largest_share"] = round(bucket_counts[0] / 53, 4)
    row["most_common_is_absent"] = False
    report["fields"].sort(
        key=lambda item: (-item["entropy_bits"], item["claim"])
    )
    claims = [item["claim"] for item in report["fields"]]
    report["most_identifying"] = claims[:8]
    report["least_identifying"] = claims[-8:]

    if should_reject:
        with pytest.raises(ContractError):
            validate_uniqueness_report(report)
    else:
        assert validate_uniqueness_report(report) == report


@pytest.mark.parametrize(
    ("bucket_counts", "should_reject"),
    [((70, 4, 2, 68), True), ((72, 2, 2, 68), False)],
)
def test_joint_other_value_capacity_uses_gcd_scaled_population_above_raw_cap(
    tmp_path,
    bucket_counts: tuple[int, ...],
    should_reject: bool,
) -> None:
    report = _gcd_scaled_two_and_six_histogram_report(tmp_path)
    scale = 2_000
    row = next(
        item for item in report["fields"] if item["claim"] == "window.platform"
    )
    row["present_in"] = 76 * scale
    row["distinct_values"] = 3
    row["entropy_bits"] = round(
        persona_quality_module._entropy(bucket_counts), 4
    )
    row["largest_share"] = round(bucket_counts[0] / 144, 4)
    row["most_common_is_absent"] = False
    report["fields"].sort(
        key=lambda item: (-item["entropy_bits"], item["claim"])
    )
    claims = [item["claim"] for item in report["fields"]]
    report["most_identifying"] = claims[:8]
    report["least_identifying"] = claims[-8:]

    if should_reject:
        with pytest.raises(ContractError):
            validate_uniqueness_report(report)
    else:
        assert validate_uniqueness_report(report) == report


def test_absence_winner_rows_skip_conditional_other_group_search(
    tmp_path, monkeypatch
) -> None:
    for index in range(4):
        persona = _persona(f"sparse-{index}")
        persona["identity_contract"]["expected"] = {
            f"window.sparse{index}": "present"
        }
        persona["integrity_sha256"] = persona_digest(persona)
        add_persona(tmp_path, persona)
    report = catalog_uniqueness(tmp_path)
    assert len(report["fields"]) == 4
    assert all(row["most_common_is_absent"] for row in report["fields"])

    def unexpected_search(*_args, **_kwargs):
        raise AssertionError("unused conditional other-group search ran")

    monkeypatch.setattr(
        "browser_core.persona_quality._bounded_identity_joint_max_other_groups",
        unexpected_search,
    )
    assert validate_uniqueness_report(report) == report


def test_absence_winner_rows_skip_joint_largest_reachability_search(
    tmp_path, monkeypatch
) -> None:
    for index in range(4):
        persona = _persona(f"sparse-{index}")
        persona["identity_contract"]["expected"] = {
            f"window.sparse{index}": "present"
        }
        persona["integrity_sha256"] = persona_digest(persona)
        add_persona(tmp_path, persona)
    report = catalog_uniqueness(tmp_path)
    assert len(report["fields"]) == 4
    assert all(row["most_common_is_absent"] for row in report["fields"])

    def unexpected_search(*_args, **_kwargs):
        raise AssertionError("unused joint-largest search ran")

    monkeypatch.setattr(
        "browser_core.persona_quality._bounded_identity_joint_subset_sums",
        unexpected_search,
    )
    assert validate_uniqueness_report(report) == report


def test_empty_field_rows_reject_before_identity_subset_search(
    tmp_path, monkeypatch
) -> None:
    _add_two_four_five_identity_groups(tmp_path)
    report = catalog_uniqueness(tmp_path)
    report["fields"] = []
    report["most_identifying"] = []
    report["least_identifying"] = []

    def unexpected_search(*_args, **_kwargs):
        raise AssertionError("identity subset search ran before field shape rejection")

    monkeypatch.setattr(
        "browser_core.persona_quality._bounded_identity_subset_sums",
        unexpected_search,
    )
    with pytest.raises(
        ContractError,
        match="persona uniqueness field population is inconsistent",
    ):
        validate_uniqueness_report(report)


def test_duplicate_groups_reject_before_identity_subset_search(
    tmp_path, monkeypatch
) -> None:
    _add_two_four_five_identity_groups(tmp_path)
    report = catalog_uniqueness(tmp_path)
    report["duplicate_groups"] = []

    def unexpected_search(*_args, **_kwargs):
        raise AssertionError("identity subset search ran before duplicate rejection")

    monkeypatch.setattr(
        "browser_core.persona_quality._bounded_identity_subset_sums",
        unexpected_search,
    )
    with pytest.raises(
        ContractError,
        match="persona uniqueness duplicate groups are invalid",
    ):
        validate_uniqueness_report(report)


def test_identifying_rankings_reject_before_identity_subset_search(
    tmp_path, monkeypatch
) -> None:
    _add_two_four_five_identity_groups(tmp_path)
    report = catalog_uniqueness(tmp_path)
    report["most_identifying"] = {}

    def unexpected_search(*_args, **_kwargs):
        raise AssertionError("identity subset search ran before ranking rejection")

    monkeypatch.setattr(
        "browser_core.persona_quality._bounded_identity_subset_sums",
        unexpected_search,
    )
    with pytest.raises(
        ContractError,
        match="persona uniqueness identifying claim is invalid",
    ):
        validate_uniqueness_report(report)


def test_uniqueness_verdict_rejects_before_identity_subset_search(
    tmp_path, monkeypatch
) -> None:
    _add_two_four_five_identity_groups(tmp_path)
    report = catalog_uniqueness(tmp_path)
    report["passed"] = 0

    def unexpected_search(*_args, **_kwargs):
        raise AssertionError("identity subset search ran before verdict rejection")

    monkeypatch.setattr(
        "browser_core.persona_quality._bounded_identity_subset_sums",
        unexpected_search,
    )
    with pytest.raises(
        ContractError,
        match="persona uniqueness verdict is inconsistent",
    ):
        validate_uniqueness_report(report)


def test_field_row_shape_rejects_before_identity_subset_search(
    tmp_path, monkeypatch
) -> None:
    _add_two_four_five_identity_groups(tmp_path)
    report = catalog_uniqueness(tmp_path)
    report["fields"][0] = {}

    def unexpected_search(*_args, **_kwargs):
        raise AssertionError("identity subset search ran before row-shape rejection")

    monkeypatch.setattr(
        "browser_core.persona_quality._bounded_identity_subset_sums",
        unexpected_search,
    )
    with pytest.raises(
        ContractError,
        match="persona uniqueness field 0 is invalid",
    ):
        validate_uniqueness_report(report)


def test_field_row_primitives_reject_before_identity_subset_search(
    tmp_path, monkeypatch
) -> None:
    _add_two_four_five_identity_groups(tmp_path)
    report = catalog_uniqueness(tmp_path)
    report["fields"][0]["present_in"] = "11"

    def unexpected_search(*_args, **_kwargs):
        raise AssertionError("identity subset search ran before primitive rejection")

    monkeypatch.setattr(
        "browser_core.persona_quality._bounded_identity_subset_sums",
        unexpected_search,
    )
    with pytest.raises(
        ContractError,
        match="persona uniqueness presence is invalid",
    ):
        validate_uniqueness_report(report)


def test_field_row_arithmetic_rejects_before_identity_subset_search(
    tmp_path, monkeypatch
) -> None:
    _add_two_four_five_identity_groups(tmp_path)
    report = catalog_uniqueness(tmp_path)
    report["fields"][0]["present_in"] = 12

    def unexpected_search(*_args, **_kwargs):
        raise AssertionError("identity subset search ran before arithmetic rejection")

    monkeypatch.setattr(
        "browser_core.persona_quality._bounded_identity_subset_sums",
        unexpected_search,
    )
    with pytest.raises(
        ContractError,
        match="persona uniqueness field 0 is invalid",
    ):
        validate_uniqueness_report(report)


def test_field_distribution_rejects_before_identity_subset_search(
    tmp_path, monkeypatch
) -> None:
    _add_two_four_five_identity_groups(tmp_path)
    report = catalog_uniqueness(tmp_path)
    row = next(
        item for item in report["fields"] if item["claim"] == "window.platform"
    )
    assert row["present_in"] == report["personas"]
    row["most_common_is_absent"] = True

    def unexpected_search(*_args, **_kwargs):
        raise AssertionError("identity subset search ran before distribution rejection")

    monkeypatch.setattr(
        "browser_core.persona_quality._bounded_identity_subset_sums",
        unexpected_search,
    )
    with pytest.raises(
        ContractError,
        match="persona uniqueness field [0-9]+ is invalid",
    ):
        validate_uniqueness_report(report)


def test_threshold_packing_rejects_before_identity_subset_search(
    tmp_path, monkeypatch
) -> None:
    _add_two_singletons_and_seven_size_four_identity_groups(tmp_path)
    report = catalog_uniqueness(tmp_path)
    row = next(
        item for item in report["fields"] if item["claim"] == "window.platform"
    )
    row["present_in"] = 30
    row["distinct_values"] = 3
    row["entropy_bits"] = 1.585
    row["largest_share"] = 0.3333
    row["most_common_is_absent"] = False
    report["fields"].sort(
        key=lambda item: (-item["entropy_bits"], item["claim"])
    )
    claims = [item["claim"] for item in report["fields"]]
    report["most_identifying"] = claims[:8]
    report["least_identifying"] = claims[-8:]

    def unexpected_search(*_args, **_kwargs):
        raise AssertionError("identity subset search ran before packing rejection")

    monkeypatch.setattr(
        "browser_core.persona_quality._bounded_identity_subset_sums",
        unexpected_search,
    )
    with pytest.raises(
        ContractError,
        match="persona uniqueness field [0-9]+ is invalid",
    ):
        validate_uniqueness_report(report)


def test_paired_entropy_rejects_before_identity_subset_search(
    tmp_path, monkeypatch
) -> None:
    for persona_id, concurrency in (
        ("a", 8),
        ("b", 8),
        ("c", 16),
        ("d", 16),
    ):
        add_persona(
            tmp_path,
            _persona(
                persona_id,
                claims={"window.hardwareConcurrency": concurrency},
            ),
        )
    report = catalog_uniqueness(tmp_path)
    row = next(
        item
        for item in report["fields"]
        if item["claim"] == "window.hardwareConcurrency"
    )
    assert row["largest_share"] == 0.5
    row["entropy_bits"] = 0.8113
    report["fields"].sort(
        key=lambda item: (-item["entropy_bits"], item["claim"])
    )
    claims = [item["claim"] for item in report["fields"]]
    report["most_identifying"] = claims[:8]
    report["least_identifying"] = claims[-8:]

    def unexpected_search(*_args, **_kwargs):
        raise AssertionError("identity subset search ran before entropy rejection")

    monkeypatch.setattr(
        "browser_core.persona_quality._bounded_identity_subset_sums",
        unexpected_search,
    )
    with pytest.raises(
        ContractError,
        match="persona uniqueness field [0-9]+ is invalid",
    ):
        validate_uniqueness_report(report)


def test_field_order_rejects_before_identity_subset_search(
    tmp_path, monkeypatch
) -> None:
    _add_two_four_five_identity_groups(tmp_path)
    report = catalog_uniqueness(tmp_path)
    assert len(report["fields"]) >= 2
    report["fields"][0], report["fields"][1] = (
        report["fields"][1],
        report["fields"][0],
    )

    def unexpected_search(*_args, **_kwargs):
        raise AssertionError("identity subset search ran before field-order rejection")

    monkeypatch.setattr(
        "browser_core.persona_quality._bounded_identity_subset_sums",
        unexpected_search,
    )
    with pytest.raises(
        ContractError,
        match="persona uniqueness field ranking is inconsistent",
    ):
        validate_uniqueness_report(report)


def test_field_coverage_rejects_before_identity_subset_search(
    tmp_path, monkeypatch
) -> None:
    for index in range(4):
        persona = _persona(f"sparse-{index}")
        persona["identity_contract"]["expected"] = {
            f"window.sparse{index}": "present"
        }
        persona["integrity_sha256"] = persona_digest(persona)
        add_persona(tmp_path, persona)
    report = catalog_uniqueness(tmp_path)
    assert len(report["fields"]) == 4
    report["fields"] = [report["fields"][0]]
    claim = report["fields"][0]["claim"]
    report["most_identifying"] = [claim]
    report["least_identifying"] = [claim]

    def unexpected_search(*_args, **_kwargs):
        raise AssertionError("identity subset search ran before coverage rejection")

    monkeypatch.setattr(
        "browser_core.persona_quality._bounded_identity_subset_sums",
        unexpected_search,
    )
    with pytest.raises(
        ContractError,
        match="persona uniqueness field coverage is inconsistent",
    ):
        validate_uniqueness_report(report)


def test_joint_field_capacity_rejects_before_identity_subset_search(
    tmp_path, monkeypatch
) -> None:
    add_persona(tmp_path, _persona("unique-a"))
    add_persona(
        tmp_path,
        _persona("unique-b", claims={"window.hardwareConcurrency": 16}),
    )
    report = catalog_uniqueness(tmp_path)
    assert report["distinct_identities"] == 2
    row = next(
        item
        for item in report["fields"]
        if item["claim"] == "window.hardwareConcurrency"
    )
    row["distinct_values"] = 1
    row["entropy_bits"] = 0.0
    row["largest_share"] = 1.0
    report["fields"].sort(
        key=lambda item: (-item["entropy_bits"], item["claim"])
    )
    claims = [item["claim"] for item in report["fields"]]
    report["most_identifying"] = claims[:8]
    report["least_identifying"] = claims[-8:]

    def unexpected_search(*_args, **_kwargs):
        raise AssertionError("identity subset search ran before capacity rejection")

    monkeypatch.setattr(
        "browser_core.persona_quality._bounded_identity_subset_sums",
        unexpected_search,
    )
    with pytest.raises(
        ContractError,
        match="persona uniqueness field identity capacity is inconsistent",
    ):
        validate_uniqueness_report(report)


def test_empty_catalog_skips_identity_subset_search(
    tmp_path, monkeypatch
) -> None:
    report = catalog_uniqueness(tmp_path)
    assert report["personas"] == 0
    assert report["fields"] == []

    def unexpected_search(*_args, **_kwargs):
        raise AssertionError("identity subset search ran without any field rows")

    monkeypatch.setattr(
        "browser_core.persona_quality._bounded_identity_subset_sums",
        unexpected_search,
    )
    assert validate_uniqueness_report(report) == report


def test_single_value_fields_skip_multi_value_identity_searches(
    tmp_path, monkeypatch
) -> None:
    for persona_id in ("present-a", "present-b", "present-c"):
        add_persona(
            tmp_path,
            _persona(
                persona_id,
                claims={"window.optionalMarker": "same"},
            ),
        )
    add_persona(tmp_path, _persona("absent"))
    report = catalog_uniqueness(tmp_path)
    assert report["distinct_identities"] == 2
    assert report["fields"]
    assert all(row["distinct_values"] == 1 for row in report["fields"])
    sparse_row = next(
        row
        for row in report["fields"]
        if row["claim"] == "window.optionalMarker"
    )
    assert sparse_row["present_in"] == 3
    assert sparse_row["most_common_is_absent"] is False
    real_subset_search = persona_quality_module._bounded_identity_subset_sums
    subset_searches = 0

    def counting_subset_search(*args, **kwargs):
        nonlocal subset_searches
        subset_searches += 1
        return real_subset_search(*args, **kwargs)

    def unexpected_search(*_args, **_kwargs):
        raise AssertionError("multi-value identity search ran for one-value fields")

    monkeypatch.setattr(
        "browser_core.persona_quality._bounded_identity_subset_sums",
        counting_subset_search,
    )
    for name in (
        "_bounded_identity_subset_max_groups",
        "_bounded_identity_joint_subset_sums",
        "_bounded_identity_joint_max_other_groups",
    ):
        monkeypatch.setattr(
            f"browser_core.persona_quality.{name}",
            unexpected_search,
        )
    assert validate_uniqueness_report(report) == report
    assert subset_searches == 1


def test_single_category_fields_skip_base_identity_subset_search(
    tmp_path, monkeypatch
) -> None:
    add_persona(tmp_path, _persona("twin-a"))
    add_persona(tmp_path, _persona("twin-b"))
    report = catalog_uniqueness(tmp_path)
    assert report["distinct_identities"] == 1
    assert report["fields"]
    assert all(
        row["present_in"] == report["personas"]
        and row["distinct_values"] == 1
        for row in report["fields"]
    )

    def unexpected_search(*_args, **_kwargs):
        raise AssertionError("base identity subset search ran for constant fields")

    monkeypatch.setattr(
        "browser_core.persona_quality._bounded_identity_subset_sums",
        unexpected_search,
    )
    assert validate_uniqueness_report(report) == report


def _gcd_one_large_uniqueness_report() -> dict:
    population = 70_000
    entropy = round(math.log2(population), 4)
    return {
        "schema": UNIQUENESS_SCHEMA,
        "personas": population,
        "distinct_identities": population,
        "unique_personas": population,
        "duplicate_ratio": 0.0,
        "catalog_entropy_bits": entropy,
        "maximum_entropy_bits": entropy,
        "anonymity_set_sizes": {"1": population},
        "largest_duplicate_group": 1,
        "duplicate_groups": [],
        "duplicate_group_count": 0,
        "fields": [
            {
                "claim": "window.synthetic",
                "present_in": population,
                "distinct_values": population,
                "entropy_bits": entropy,
                "largest_share": 0.0,
                "most_common_is_absent": False,
            }
        ],
        "most_identifying": ["window.synthetic"],
        "least_identifying": ["window.synthetic"],
        "passed": True,
    }


def test_gcd_one_large_report_skips_duplicate_scaled_subset_search(
    monkeypatch,
) -> None:
    report = _gcd_one_large_uniqueness_report()
    real_subset_search = persona_quality_module._bounded_identity_subset_sums
    subset_searches = 0

    def counting_subset_search(*args, **kwargs):
        nonlocal subset_searches
        subset_searches += 1
        return real_subset_search(*args, **kwargs)

    monkeypatch.setattr(
        "browser_core.persona_quality._bounded_identity_subset_sums",
        counting_subset_search,
    )
    assert validate_uniqueness_report(report) == report
    assert subset_searches == 1


def test_gcd_one_large_report_reuses_raw_distribution_bounds(
    monkeypatch,
) -> None:
    report = _gcd_one_large_uniqueness_report()
    real_share_bounds = persona_quality_module._rounded_share_count_bounds
    real_entropy_bounds = persona_quality_module._present_winner_entropy_bounds
    share_bounds_calls = 0
    entropy_bounds_calls = 0

    def counting_share_bounds(*args, **kwargs):
        nonlocal share_bounds_calls
        share_bounds_calls += 1
        return real_share_bounds(*args, **kwargs)

    def counting_entropy_bounds(*args, **kwargs):
        nonlocal entropy_bounds_calls
        entropy_bounds_calls += 1
        return real_entropy_bounds(*args, **kwargs)

    monkeypatch.setattr(
        "browser_core.persona_quality._rounded_share_count_bounds",
        counting_share_bounds,
    )
    monkeypatch.setattr(
        "browser_core.persona_quality._present_winner_entropy_bounds",
        counting_entropy_bounds,
    )
    assert validate_uniqueness_report(report) == report
    assert share_bounds_calls == 1
    assert entropy_bounds_calls == 1


def test_nontrivial_identity_scale_keeps_independent_distribution_bounds(
    tmp_path, monkeypatch
) -> None:
    for persona_id in ("eight-a", "eight-b"):
        add_persona(tmp_path, _persona(persona_id))
    for persona_id in ("sixteen-a", "sixteen-b"):
        add_persona(
            tmp_path,
            _persona(
                persona_id,
                claims={"window.hardwareConcurrency": 16},
            ),
        )
    report = catalog_uniqueness(tmp_path)
    assert report["anonymity_set_sizes"] == {"2": 2}
    assert all(not row["most_common_is_absent"] for row in report["fields"])
    real_share_bounds = persona_quality_module._rounded_share_count_bounds
    real_entropy_bounds = persona_quality_module._present_winner_entropy_bounds
    share_bounds_calls = 0
    entropy_bounds_calls = 0

    def counting_share_bounds(*args, **kwargs):
        nonlocal share_bounds_calls
        share_bounds_calls += 1
        return real_share_bounds(*args, **kwargs)

    def counting_entropy_bounds(*args, **kwargs):
        nonlocal entropy_bounds_calls
        entropy_bounds_calls += 1
        return real_entropy_bounds(*args, **kwargs)

    monkeypatch.setattr(
        "browser_core.persona_quality._rounded_share_count_bounds",
        counting_share_bounds,
    )
    monkeypatch.setattr(
        "browser_core.persona_quality._present_winner_entropy_bounds",
        counting_entropy_bounds,
    )
    assert validate_uniqueness_report(report) == report
    field_shapes = {
        (
            row["present_in"],
            row["distinct_values"],
            row["largest_share"],
        )
        for row in report["fields"]
    }
    assert share_bounds_calls == 2 * len(field_shapes)
    assert entropy_bounds_calls == 2 * len(field_shapes)


def _two_shape_uniqueness_report(tmp_path) -> dict:
    for persona_id in ("default-a", "default-b"):
        add_persona(tmp_path, _persona(persona_id))
    add_persona(
        tmp_path,
        _persona(
            "different",
            claims={"window.hardwareConcurrency": 16},
        ),
    )
    return catalog_uniqueness(tmp_path)


def test_equal_field_shapes_reuse_report_local_distribution_bounds(
    tmp_path, monkeypatch
) -> None:
    report = _two_shape_uniqueness_report(tmp_path)
    assert report["anonymity_set_sizes"] == {"1": 1, "2": 1}
    assert len(report["fields"]) > 2
    assert all(not row["most_common_is_absent"] for row in report["fields"])
    assert {
        (
            row["present_in"],
            row["distinct_values"],
            row["largest_share"],
        )
        for row in report["fields"]
    } == {(3, 1, 1.0), (3, 2, 0.6667)}
    real_share_bounds = persona_quality_module._rounded_share_count_bounds
    real_entropy_bounds = persona_quality_module._present_winner_entropy_bounds
    share_bounds_calls = 0
    entropy_bounds_calls = 0

    def counting_share_bounds(*args, **kwargs):
        nonlocal share_bounds_calls
        share_bounds_calls += 1
        return real_share_bounds(*args, **kwargs)

    def counting_entropy_bounds(*args, **kwargs):
        nonlocal entropy_bounds_calls
        entropy_bounds_calls += 1
        return real_entropy_bounds(*args, **kwargs)

    monkeypatch.setattr(
        "browser_core.persona_quality._rounded_share_count_bounds",
        counting_share_bounds,
    )
    monkeypatch.setattr(
        "browser_core.persona_quality._present_winner_entropy_bounds",
        counting_entropy_bounds,
    )
    assert validate_uniqueness_report(report) == report
    assert share_bounds_calls == 2
    assert entropy_bounds_calls == 2


def test_equal_field_shapes_reuse_report_local_structural_bounds(
    tmp_path, monkeypatch
) -> None:
    report = _two_shape_uniqueness_report(tmp_path)
    real_minimum_groups = (
        persona_quality_module._minimum_identity_groups_for_count
    )
    real_partition_bounds = persona_quality_module._partition_entropy_bounds
    minimum_group_calls = 0
    partition_bound_calls = 0

    def counting_minimum_groups(*args, **kwargs):
        nonlocal minimum_group_calls
        minimum_group_calls += 1
        return real_minimum_groups(*args, **kwargs)

    def counting_partition_bounds(*args, **kwargs):
        nonlocal partition_bound_calls
        partition_bound_calls += 1
        return real_partition_bounds(*args, **kwargs)

    monkeypatch.setattr(
        "browser_core.persona_quality._minimum_identity_groups_for_count",
        counting_minimum_groups,
    )
    monkeypatch.setattr(
        "browser_core.persona_quality._partition_entropy_bounds",
        counting_partition_bounds,
    )
    assert validate_uniqueness_report(report) == report
    assert minimum_group_calls == 2
    assert partition_bound_calls == 2


def test_equal_field_shapes_reuse_report_local_threshold_capacity(
    tmp_path, monkeypatch
) -> None:
    report = _two_shape_uniqueness_report(tmp_path)
    real_threshold_check = (
        persona_quality_module._identity_threshold_capacity_holds
    )
    threshold_calls = 0

    def counting_threshold_check(*args, **kwargs):
        nonlocal threshold_calls
        threshold_calls += 1
        return real_threshold_check(*args, **kwargs)

    monkeypatch.setattr(
        "browser_core.persona_quality._identity_threshold_capacity_holds",
        counting_threshold_check,
    )
    assert validate_uniqueness_report(report) == report
    assert threshold_calls == 2


def test_identifying_rankings_reuse_validated_field_claim_text(
    tmp_path, monkeypatch
) -> None:
    report = _two_shape_uniqueness_report(tmp_path)
    real_quality_text = persona_quality_module._quality_text
    quality_text_calls = 0

    def counting_quality_text(*args, **kwargs):
        nonlocal quality_text_calls
        quality_text_calls += 1
        return real_quality_text(*args, **kwargs)

    monkeypatch.setattr(
        "browser_core.persona_quality._quality_text",
        counting_quality_text,
    )
    assert validate_uniqueness_report(report) == report
    duplicate_id_count = sum(
        len(group["persona_ids"]) for group in report["duplicate_groups"]
    )
    assert quality_text_calls == len(report["fields"]) + duplicate_id_count


def test_quality_headline_ranking_reuses_validated_nested_claim_text(
    tmp_path, monkeypatch
) -> None:
    _two_shape_uniqueness_report(tmp_path)
    report = catalog_quality_report(tmp_path)
    real_quality_text = persona_quality_module._quality_text
    quality_text_calls = 0

    def counting_quality_text(*args, **kwargs):
        nonlocal quality_text_calls
        quality_text_calls += 1
        return real_quality_text(*args, **kwargs)

    monkeypatch.setattr(
        "browser_core.persona_quality._quality_text",
        counting_quality_text,
    )
    assert validate_catalog_quality_report(report) == report
    uniqueness = report["uniqueness"]
    duplicate_id_count = sum(
        len(group["persona_ids"]) for group in uniqueness["duplicate_groups"]
    )
    assert quality_text_calls == (
        len(uniqueness["most_identifying"])
        + len(uniqueness["least_identifying"])
        + duplicate_id_count
    )


def test_quality_nested_ranking_overlap_reuses_validated_claim_text(
    tmp_path, monkeypatch
) -> None:
    _two_shape_uniqueness_report(tmp_path)
    report = catalog_quality_report(tmp_path)
    uniqueness = report["uniqueness"]
    uniqueness["least_identifying"] = list(uniqueness["most_identifying"])
    real_quality_text = persona_quality_module._quality_text
    quality_text_calls = 0

    def counting_quality_text(*args, **kwargs):
        nonlocal quality_text_calls
        quality_text_calls += 1
        return real_quality_text(*args, **kwargs)

    monkeypatch.setattr(
        "browser_core.persona_quality._quality_text",
        counting_quality_text,
    )
    assert validate_catalog_quality_report(report) == report
    duplicate_id_count = sum(
        len(group["persona_ids"]) for group in uniqueness["duplicate_groups"]
    )
    validated_ranking_claims = set(uniqueness["most_identifying"]).union(
        uniqueness["least_identifying"]
    )
    assert quality_text_calls == len(validated_ranking_claims) + duplicate_id_count


def test_exact_partition_search_runs_after_cheaper_field_gates(
    tmp_path, monkeypatch
) -> None:
    _add_two_four_five_identity_groups(tmp_path)
    report = catalog_uniqueness(tmp_path)
    row = next(
        item for item in report["fields"] if item["claim"] == "window.platform"
    )
    row["distinct_values"] = 3
    row["entropy_bits"] = 1.0958
    row["largest_share"] = 0.7273
    report["fields"] = [row]
    report["most_identifying"] = [row["claim"]]
    report["least_identifying"] = [row["claim"]]

    def unexpected_search(*_args, **_kwargs):
        raise AssertionError("exact partition search ran before a cheaper rejection")

    monkeypatch.setattr(
        "browser_core.persona_quality._bounded_identity_partition_signatures",
        unexpected_search,
    )
    with pytest.raises(ContractError):
        validate_uniqueness_report(report)


def test_absence_bucket_uses_fixed_threshold_capacity_above_exact_cap(
    tmp_path,
) -> None:
    _add_one_five_six_and_seven_size_nine_identity_groups(tmp_path)
    report = catalog_uniqueness(tmp_path)
    assert report["anonymity_set_sizes"] == {
        "1": 1,
        "5": 1,
        "6": 1,
        "9": 7,
    }
    row = next(
        item for item in report["fields"] if item["claim"] == "window.platform"
    )
    row["present_in"] = 70
    row["distinct_values"] = 3
    row["entropy_bits"] = 1.8324
    row["largest_share"] = 0.32
    row["most_common_is_absent"] = False
    report["fields"].sort(
        key=lambda item: (-item["entropy_bits"], item["claim"])
    )
    claims = [item["claim"] for item in report["fields"]]
    report["most_identifying"] = claims[:8]
    report["least_identifying"] = claims[-8:]

    with pytest.raises(ContractError):
        validate_uniqueness_report(report)


def test_uniqueness_reuses_one_sorted_identity_group_profile(
    tmp_path, monkeypatch
) -> None:
    _add_one_five_six_and_seven_size_nine_identity_groups(tmp_path)
    report = catalog_uniqueness(tmp_path)
    histogram_items = {
        (int(size), groups)
        for size, groups in report["anonymity_set_sizes"].items()
    }
    histogram_sizes = {size for size, _groups in histogram_items}
    real_sorted = sorted
    reverse_histogram_sorts = 0

    def counting_sorted(iterable, *args, **kwargs):
        nonlocal reverse_histogram_sorts
        material = list(iterable)
        if kwargs.get("reverse") is True and material:
            material_set = set(material)
            if material_set in (histogram_items, histogram_sizes):
                reverse_histogram_sorts += 1
        return real_sorted(material, *args, **kwargs)

    monkeypatch.setattr(
        "browser_core.persona_quality.sorted",
        counting_sorted,
        raising=False,
    )
    assert validate_uniqueness_report(report) == report
    assert reverse_histogram_sorts == 1


def test_uniqueness_reuses_one_expanded_identity_class_vector(
    tmp_path, monkeypatch
) -> None:
    _add_one_one_three_three_identity_groups(tmp_path)
    report = catalog_uniqueness(tmp_path)
    row = next(
        item for item in report["fields"] if item["claim"] == "window.platform"
    )
    row["distinct_values"] = 2
    row["entropy_bits"] = 1.0
    row["largest_share"] = 0.5
    report["fields"].sort(
        key=lambda item: (-item["entropy_bits"], item["claim"])
    )
    claims = [item["claim"] for item in report["fields"]]
    report["most_identifying"] = claims[:8]
    report["least_identifying"] = claims[-8:]

    histogram_items = {
        (int(size), groups)
        for size, groups in report["anonymity_set_sizes"].items()
    }
    real_sorted = sorted
    reverse_histogram_sorts = 0

    def counting_sorted(iterable, *args, **kwargs):
        nonlocal reverse_histogram_sorts
        material = list(iterable)
        if kwargs.get("reverse") is True and set(material) == histogram_items:
            reverse_histogram_sorts += 1
        return real_sorted(material, *args, **kwargs)

    monkeypatch.setattr(
        "browser_core.persona_quality.sorted",
        counting_sorted,
        raising=False,
    )
    assert validate_uniqueness_report(report) == report
    assert reverse_histogram_sorts == 1


@pytest.mark.parametrize(
    ("present_ids", "expected_flag"),
    [
        (("a",), True),
        (("a", "b", "c"), False),
    ],
)
def test_uniqueness_absence_winner_must_be_distributionally_possible(
    tmp_path, present_ids: tuple[str, ...], expected_flag: bool
) -> None:
    workspace = tmp_path / ("sparse" if expected_flag else "dense")
    for persona_id in ("a", "b", "c", "d"):
        persona = _persona(persona_id)
        if persona_id not in present_ids:
            persona["identity_contract"]["expected"].pop("window.locale")
            persona["integrity_sha256"] = persona_digest(persona)
        add_persona(workspace, persona)
    report = catalog_uniqueness(workspace)
    row = next(item for item in report["fields"] if item["claim"] == "window.locale")
    assert row["most_common_is_absent"] is expected_flag

    row["most_common_is_absent"] = not expected_flag
    with pytest.raises(ContractError):
        validate_uniqueness_report(report)


def test_literal_absence_label_does_not_collide_with_a_missing_claim(tmp_path) -> None:
    add_persona(
        tmp_path,
        _persona("literal", claims={"window.absenceSentinel": "<absent>"}),
    )
    add_persona(tmp_path, _persona("missing"))

    report = catalog_uniqueness(tmp_path)
    row = next(
        item
        for item in report["fields"]
        if item["claim"] == "window.absenceSentinel"
    )

    assert report["distinct_identities"] == 2
    assert report["unique_personas"] == 2
    assert row == {
        "claim": "window.absenceSentinel",
        "present_in": 1,
        "distinct_values": 1,
        "entropy_bits": 1.0,
        "largest_share": 0.5,
        "most_common_is_absent": False,
    }


def test_uniqueness_fields_cover_every_persona_contract(tmp_path) -> None:
    pair_workspace = tmp_path / "pair"
    add_persona(
        pair_workspace,
        _persona("literal", claims={"window.absenceSentinel": "<absent>"}),
    )
    add_persona(pair_workspace, _persona("missing"))
    pair_report = catalog_uniqueness(pair_workspace)
    absence_row = next(
        item
        for item in pair_report["fields"]
        if item["claim"] == "window.absenceSentinel"
    )

    no_fields = copy.deepcopy(pair_report)
    no_fields["fields"] = []
    no_fields["most_identifying"] = []
    no_fields["least_identifying"] = []

    uncovered_persona = copy.deepcopy(pair_report)
    uncovered_persona["fields"] = [absence_row]
    uncovered_persona["most_identifying"] = [absence_row["claim"]]
    uncovered_persona["least_identifying"] = [absence_row["claim"]]

    one_workspace = tmp_path / "one"
    add_persona(one_workspace, _persona("one"))
    overfull_contract = catalog_uniqueness(one_workspace)
    prototype = overfull_contract["fields"][0]
    overfull_contract["fields"] = [
        {**prototype, "claim": f"window.synthetic{index:03d}"}
        for index in range(129)
    ]
    overfull_contract["most_identifying"] = [
        row["claim"] for row in overfull_contract["fields"][:8]
    ]
    overfull_contract["least_identifying"] = [
        row["claim"] for row in overfull_contract["fields"][-8:]
    ]

    for mutation in (no_fields, uncovered_persona, overfull_contract):
        with pytest.raises(ContractError):
            validate_uniqueness_report(mutation)


@pytest.mark.parametrize(
    "invalid_claim",
    [
        "private-claim-marker",
        "unknown.privateClaimMarker",
        "window.privateSessionTokenMarker",
    ],
)
def test_uniqueness_field_claims_use_the_identity_path_grammar(
    tmp_path, invalid_claim: str
) -> None:
    add_persona(tmp_path, _persona("one"))
    report = catalog_uniqueness(tmp_path)
    report["fields"][0]["claim"] = invalid_claim
    report["fields"].sort(key=lambda item: (-item["entropy_bits"], item["claim"]))
    claims = [item["claim"] for item in report["fields"]]
    report["most_identifying"] = claims[:8]
    report["least_identifying"] = claims[-8:]

    with pytest.raises(ContractError) as failure:
        validate_uniqueness_report(report)
    assert invalid_claim not in str(failure.value)


def test_uniqueness_field_entropy_is_achievable_by_its_integer_population(
    tmp_path,
) -> None:
    split_workspace = tmp_path / "split"
    add_persona(split_workspace, _persona("a"))
    add_persona(
        split_workspace,
        _persona("b", claims={"window.hardwareConcurrency": 16}),
    )
    split_report = catalog_uniqueness(split_workspace)
    split_row = next(
        item
        for item in split_report["fields"]
        if item["claim"] == "window.hardwareConcurrency"
    )
    assert split_row["entropy_bits"] == 1.0
    split_row["entropy_bits"] = 0.0
    split_report["fields"].sort(
        key=lambda item: (-item["entropy_bits"], item["claim"])
    )
    split_claims = [item["claim"] for item in split_report["fields"]]
    split_report["most_identifying"] = split_claims[:8]
    split_report["least_identifying"] = split_claims[-8:]

    sparse_workspace = tmp_path / "sparse"
    for persona_id in ("a", "b", "c"):
        claims = {"window.optionalMarker": "same"} if persona_id != "c" else {}
        add_persona(sparse_workspace, _persona(persona_id, claims=claims))
    sparse_report = catalog_uniqueness(sparse_workspace)
    sparse_row = next(
        item
        for item in sparse_report["fields"]
        if item["claim"] == "window.optionalMarker"
    )
    assert sparse_row["entropy_bits"] == pytest.approx(0.9183)
    sparse_row["entropy_bits"] = 0.5
    sparse_report["fields"].sort(
        key=lambda item: (-item["entropy_bits"], item["claim"])
    )
    sparse_claims = [item["claim"] for item in sparse_report["fields"]]
    sparse_report["most_identifying"] = sparse_claims[:8]
    sparse_report["least_identifying"] = sparse_claims[-8:]

    for mutation in (split_report, sparse_report):
        with pytest.raises(ContractError):
            validate_uniqueness_report(mutation)


def test_uniqueness_field_entropy_uses_producer_decimal_precision(tmp_path) -> None:
    values = ("a", "a", "a", "b", "b", "c", "c", "d")
    for index, value in enumerate(values):
        add_persona(
            tmp_path,
            _persona(
                f"p-{index}",
                claims={"window.optionalMarker": value},
            ),
        )
    report = catalog_uniqueness(tmp_path)
    row = next(
        item
        for item in report["fields"]
        if item["claim"] == "window.optionalMarker"
    )
    assert row["entropy_bits"] == 1.9056
    row["entropy_bits"] = 1.90559

    with pytest.raises(ContractError):
        validate_uniqueness_report(report)


def test_uniqueness_field_entropy_and_share_describe_one_distribution(
    tmp_path,
) -> None:
    for persona_id, concurrency in (
        ("a", 8),
        ("b", 8),
        ("c", 16),
        ("d", 16),
    ):
        add_persona(
            tmp_path,
            _persona(
                persona_id,
                claims={"window.hardwareConcurrency": concurrency},
            ),
        )
    report = catalog_uniqueness(tmp_path)
    row_index = next(
        index
        for index, item in enumerate(report["fields"])
        if item["claim"] == "window.hardwareConcurrency"
    )
    assert report["fields"][row_index]["entropy_bits"] == 1.0
    assert report["fields"][row_index]["largest_share"] == 0.5

    wrong_entropy = copy.deepcopy(report)
    wrong_entropy["fields"][row_index]["entropy_bits"] = 0.8113
    wrong_entropy["fields"].sort(
        key=lambda item: (-item["entropy_bits"], item["claim"])
    )
    entropy_claims = [item["claim"] for item in wrong_entropy["fields"]]
    wrong_entropy["most_identifying"] = entropy_claims[:8]
    wrong_entropy["least_identifying"] = entropy_claims[-8:]

    wrong_share = copy.deepcopy(report)
    wrong_share["fields"][row_index]["largest_share"] = 0.75

    nonintegral_share = copy.deepcopy(report)
    nonintegral_share["fields"][row_index]["largest_share"] = 0.6

    for mutation in (wrong_entropy, wrong_share, nonintegral_share):
        with pytest.raises(ContractError):
            validate_uniqueness_report(mutation)


def test_absence_winner_resolves_an_ambiguous_rounded_share() -> None:
    population = 100_000
    report = {
        "schema": UNIQUENESS_SCHEMA,
        "personas": population,
        "distinct_identities": population,
        "unique_personas": population,
        "duplicate_ratio": 0.0,
        "catalog_entropy_bits": round(math.log2(population), 4),
        "maximum_entropy_bits": round(math.log2(population), 4),
        "anonymity_set_sizes": {"1": population},
        "largest_duplicate_group": 1,
        "duplicate_groups": [],
        "duplicate_group_count": 0,
        "fields": [
            {
                "claim": "window.synthetic",
                "present_in": population,
                "distinct_values": population,
                "entropy_bits": round(math.log2(population), 4),
                "largest_share": 0.0,
                "most_common_is_absent": False,
            },
            {
                "claim": "window.optionalMarker",
                "present_in": 60_000,
                "distinct_values": 2,
                # This is feasible only if a present value beats the 40,000
                # absences: 40,000 / 59,999 / 1. An absence winner caps both
                # present buckets at 40,000 and raises the minimum to 1.5219.
                "entropy_bits": 1.5219,
                "largest_share": 0.4,
                "most_common_is_absent": True,
            },
        ],
        "most_identifying": ["window.synthetic", "window.optionalMarker"],
        "least_identifying": ["window.synthetic", "window.optionalMarker"],
        "passed": True,
    }

    assert validate_uniqueness_report(report) is report
    report["fields"][1]["entropy_bits"] = 0.9711
    with pytest.raises(ContractError):
        validate_uniqueness_report(report)


def test_present_winner_bounds_all_ambiguous_rounded_share_counts() -> None:
    population = 100_000
    report = {
        "schema": UNIQUENESS_SCHEMA,
        "personas": population,
        "distinct_identities": population,
        "unique_personas": population,
        "duplicate_ratio": 0.0,
        "catalog_entropy_bits": round(math.log2(population), 4),
        "maximum_entropy_bits": round(math.log2(population), 4),
        "anonymity_set_sizes": {"1": population},
        "largest_duplicate_group": 1,
        "duplicate_groups": [],
        "duplicate_group_count": 0,
        "fields": [
            {
                "claim": "window.synthetic",
                "present_in": population,
                "distinct_values": population,
                "entropy_bits": round(math.log2(population), 4),
                "largest_share": 0.0,
                "most_common_is_absent": False,
            },
            {
                "claim": "window.optionalMarker",
                "present_in": 90_000,
                "distinct_values": 2,
                "entropy_bits": 1.361,
                "largest_share": 0.5,
                "most_common_is_absent": False,
            },
        ],
        "most_identifying": ["window.synthetic", "window.optionalMarker"],
        "least_identifying": ["window.synthetic", "window.optionalMarker"],
        "passed": True,
    }

    assert validate_uniqueness_report(report) is report
    report["fields"][1]["entropy_bits"] = 0.4692
    with pytest.raises(ContractError):
        validate_uniqueness_report(report)


def test_usable_identities_survives_both_questions(tmp_path):
    """Two twins and one contradicting persona are one usable identity."""
    add_persona(tmp_path, _persona("twin-a"))
    add_persona(tmp_path, _persona("twin-b"))
    add_persona(tmp_path, _persona("broken", claims={"window.maxTouchPoints": 5}))
    report = catalog_quality_report(tmp_path)
    assert report["personas"] == 3
    assert report["distinct_identities"] == 2
    assert report["coherent_personas"] == 2
    assert report["usable_identities"] == 1
    assert report["passed"] is False


def test_quality_report_validator_recomputes_every_summary_boundary(tmp_path):
    add_persona(tmp_path, _persona("twin-a"))
    add_persona(tmp_path, _persona("twin-b"))
    add_persona(tmp_path, _persona("broken", claims={"window.maxTouchPoints": 5}))
    report = json.loads(json.dumps(catalog_quality_report(tmp_path)))
    assert validate_catalog_quality_report(report) is report

    mutations = []
    for path, replacement in (
        (("schema",), "private-quality-schema-marker"),
        (("personas",), 4),
        (("usable_identities",), 2),
        (("usable_anonymity_set_sizes",), {"1": 2}),
        (("coherent_personas",), 3),
        (("distinct_identities",), 1),
        (("coherence", "clean"), 3),
        (("coherence", "coherent_ratio"), 1.0),
        (("coherence", "coherent_ratio"), 10**400),
        (("coherence", "findings_total"), 2),
        (("coherence", "by_severity", "contradiction"), 0),
        (("coherence", "by_rule"), {}),
        (("coherence", "rule_examples"), {}),
        (("coherence", "contradicting_personas"), []),
        (("coherence", "passed"), True),
        (("uniqueness", "personas"), 4),
        (("uniqueness", "distinct_identities"), 3),
        (("uniqueness", "duplicate_ratio"), 0.0),
        (("uniqueness", "catalog_entropy_bits"), 2.0),
        (("uniqueness", "catalog_entropy_bits"), 10**400),
        (("uniqueness", "largest_duplicate_group"), 1),
        (("uniqueness", "duplicate_group_count"), 0),
        (("uniqueness", "duplicate_groups", 0, "size"), 3),
        (("uniqueness", "most_identifying"), []),
        (("uniqueness", "passed"), True),
        (("most_identifying",), []),
        (("passed",), True),
        (("note",), "private-quality-note-marker"),
    ):
        mutation = copy.deepcopy(report)
        target = mutation
        for segment in path[:-1]:
            target = target[segment]
        target[path[-1]] = replacement
        mutations.append(mutation)
    extra = copy.deepcopy(report)
    extra["private"] = "private-quality-field-marker"
    mutations.append(extra)

    for mutation in mutations:
        with pytest.raises(ContractError) as failure:
            validate_catalog_quality_report(mutation)
        assert "private-quality" not in str(failure.value)


def test_quality_report_coherence_summary_requires_exact_severity_keys(tmp_path) -> None:
    class TextSubclass(str):
        pass

    add_persona(
        tmp_path,
        _persona("broken-1", claims={"window.maxTouchPoints": 5}),
    )
    report = json.loads(json.dumps(catalog_quality_report(tmp_path)))
    by_severity = report["coherence"]["by_severity"]
    contradiction_count = by_severity.pop("contradiction")
    by_severity[TextSubclass("contradiction")] = contradiction_count

    with pytest.raises(ContractError):
        validate_catalog_quality_report(report)


def test_persona_quality_report_objects_require_exact_field_names(tmp_path) -> None:
    class TextSubclass(str):
        pass

    add_persona(
        tmp_path,
        _persona("broken-1", claims={"window.maxTouchPoints": 5}),
    )
    coherence = json.loads(json.dumps(audit_catalog_coherence(tmp_path)))
    uniqueness = json.loads(json.dumps(catalog_uniqueness(tmp_path)))
    quality = json.loads(json.dumps(catalog_quality_report(tmp_path)))
    retirement = json.loads(
        json.dumps(retire_incoherent_personas(tmp_path, dry_run=True))
    )

    cases = [
        (validate_retirement_report, retirement),
        (validate_coherence_report, coherence),
        (validate_uniqueness_report, uniqueness),
        (validate_catalog_quality_report, quality),
    ]
    nested_coherence = copy.deepcopy(quality)
    nested_uniqueness = copy.deepcopy(quality)
    cases.extend(
        (
            (validate_catalog_quality_report, nested_coherence),
            (validate_catalog_quality_report, nested_uniqueness),
        )
    )

    for document in (
        retirement,
        coherence,
        uniqueness,
        quality,
        nested_coherence["coherence"],
        nested_uniqueness["uniqueness"],
    ):
        schema = document.pop("schema")
        document[TextSubclass("schema")] = schema

    for validator, document in cases:
        with pytest.raises(ContractError):
            validator(document)


def test_persona_quality_nested_rows_require_exact_field_names(tmp_path) -> None:
    class TextSubclass(str):
        pass

    retirement_dir = tmp_path / "retirement"
    coherence_dir = tmp_path / "coherence"
    uniqueness_dir = tmp_path / "uniqueness"
    for directory in (retirement_dir, coherence_dir, uniqueness_dir):
        directory.mkdir()

    add_persona(
        retirement_dir,
        _persona("broken-retirement", claims={"window.maxTouchPoints": 5}),
    )
    retirement = json.loads(
        json.dumps(retire_incoherent_personas(retirement_dir, dry_run=False))
    )
    add_persona(
        coherence_dir,
        _persona("broken-coherence", claims={"window.maxTouchPoints": 5}),
    )
    coherence = json.loads(json.dumps(audit_catalog_coherence(coherence_dir)))
    add_persona(uniqueness_dir, _persona("twin-a"))
    add_persona(uniqueness_dir, _persona("twin-b"))
    uniqueness = json.loads(json.dumps(catalog_uniqueness(uniqueness_dir)))
    quality = json.loads(json.dumps(catalog_quality_report(uniqueness_dir)))

    cases = [
        (validate_retirement_report, retirement, retirement["retired"][0], "persona_id"),
        (validate_coherence_report, coherence, coherence["findings"][0], "rule"),
        (validate_uniqueness_report, uniqueness, uniqueness["fields"][0], "claim"),
        (
            validate_uniqueness_report,
            uniqueness,
            uniqueness["duplicate_groups"][0],
            "size",
        ),
        (
            validate_catalog_quality_report,
            quality,
            quality["uniqueness"]["duplicate_groups"][0],
            "size",
        ),
    ]
    for validator, document, row, field in cases:
        value = row.pop(field)
        row[TextSubclass(field)] = value
        with pytest.raises(ContractError):
            validator(document)


def test_persona_quality_derived_decimals_require_exact_floats(tmp_path) -> None:
    add_persona(tmp_path, _persona("single"))
    coherence = json.loads(json.dumps(audit_catalog_coherence(tmp_path)))
    uniqueness = json.loads(json.dumps(catalog_uniqueness(tmp_path)))
    quality = json.loads(json.dumps(catalog_quality_report(tmp_path)))

    cases = []
    direct_ratio = copy.deepcopy(coherence)
    direct_ratio["coherent_ratio"] = 1
    cases.append((validate_coherence_report, direct_ratio))
    nested_ratio = copy.deepcopy(quality)
    nested_ratio["coherence"]["coherent_ratio"] = 1
    cases.append((validate_catalog_quality_report, nested_ratio))

    for field in (
        "duplicate_ratio",
        "maximum_entropy_bits",
        "catalog_entropy_bits",
    ):
        direct = copy.deepcopy(uniqueness)
        direct[field] = int(direct[field])
        cases.append((validate_uniqueness_report, direct))
        nested = copy.deepcopy(quality)
        nested["uniqueness"][field] = int(nested["uniqueness"][field])
        cases.append((validate_catalog_quality_report, nested))

    for field in ("entropy_bits", "largest_share"):
        row = copy.deepcopy(uniqueness)
        row["fields"][0][field] = int(row["fields"][0][field])
        cases.append((validate_uniqueness_report, row))

    for validator, document in cases:
        with pytest.raises(ContractError):
            validator(document)


def test_uniqueness_decimals_canonicalize_and_reject_negative_zero(tmp_path) -> None:
    add_persona(tmp_path, _persona("single"))
    report = catalog_uniqueness(tmp_path)
    quality = catalog_quality_report(tmp_path)

    assert "-0.0" not in json.dumps(report)
    assert "-0.0" not in json.dumps(quality)

    mutations = []
    for field in (
        "duplicate_ratio",
        "catalog_entropy_bits",
        "maximum_entropy_bits",
    ):
        mutation = copy.deepcopy(report)
        mutation[field] = -0.0
        mutations.append((validate_uniqueness_report, mutation))

        nested = copy.deepcopy(quality)
        nested["uniqueness"][field] = -0.0
        mutations.append((validate_catalog_quality_report, nested))

    field_entropy = copy.deepcopy(report)
    field_entropy["fields"][0]["entropy_bits"] = -0.0
    mutations.append((validate_uniqueness_report, field_entropy))

    for validator, mutation in mutations:
        with pytest.raises(ContractError):
            validator(mutation)


def test_uniqueness_fields_must_exist_in_at_least_one_persona(tmp_path) -> None:
    add_persona(tmp_path, _persona("single"))
    report = catalog_uniqueness(tmp_path)
    row = report["fields"][0]
    row.update(
        {
            "present_in": 0,
            "distinct_values": 0,
            "entropy_bits": 0.0,
            "largest_share": 1.0,
            "most_common_is_absent": True,
        }
    )

    with pytest.raises(ContractError):
        validate_uniqueness_report(report)


def test_coherence_finding_severity_requires_exact_text(tmp_path) -> None:
    class TextSubclass(str):
        pass

    add_persona(
        tmp_path,
        _persona("broken-1", claims={"window.maxTouchPoints": 5}),
    )
    report = json.loads(json.dumps(audit_catalog_coherence(tmp_path)))
    report["findings"][0]["severity"] = TextSubclass(
        report["findings"][0]["severity"]
    )

    with pytest.raises(ContractError):
        validate_coherence_report(report)


def test_quality_coherence_rule_example_keys_require_exact_text(tmp_path) -> None:
    class TextSubclass(str):
        pass

    add_persona(
        tmp_path,
        _persona("broken-1", claims={"window.maxTouchPoints": 5}),
    )
    report = json.loads(json.dumps(catalog_quality_report(tmp_path)))
    examples = report["coherence"]["rule_examples"]
    rule = next(iter(examples))
    persona_id = examples.pop(rule)
    examples[TextSubclass(rule)] = persona_id

    with pytest.raises(ContractError):
        validate_catalog_quality_report(report)


def test_persona_quality_reports_reject_every_string_value_subclass(tmp_path) -> None:
    class TextSubclass(str):
        pass

    def string_paths(value, path=()):
        if type(value) is str:
            yield path
        elif type(value) is dict:
            for key, child in value.items():
                yield from string_paths(child, path + (key,))
        elif type(value) is list:
            for index, child in enumerate(value):
                yield from string_paths(child, path + (index,))

    def replace(document, path):
        target = document
        for segment in path[:-1]:
            target = target[segment]
        target[path[-1]] = TextSubclass(target[path[-1]])

    retirement_dir = tmp_path / "retirement"
    coherence_dir = tmp_path / "coherence"
    identity_dir = tmp_path / "identity"
    for directory in (retirement_dir, coherence_dir, identity_dir):
        directory.mkdir()
    add_persona(
        retirement_dir,
        _persona("broken-retirement", claims={"window.maxTouchPoints": 5}),
    )
    add_persona(
        coherence_dir,
        _persona("broken-coherence", claims={"window.maxTouchPoints": 5}),
    )
    add_persona(identity_dir, _persona("twin-a"))
    add_persona(identity_dir, _persona("twin-b"))

    documents = (
        (
            validate_retirement_report,
            json.loads(
                json.dumps(retire_incoherent_personas(retirement_dir, dry_run=False))
            ),
        ),
        (
            validate_coherence_report,
            json.loads(json.dumps(audit_catalog_coherence(coherence_dir))),
        ),
        (
            validate_uniqueness_report,
            json.loads(json.dumps(catalog_uniqueness(identity_dir))),
        ),
        (
            validate_catalog_quality_report,
            json.loads(json.dumps(catalog_quality_report(identity_dir))),
        ),
    )
    accepted = []
    for validator, document in documents:
        for path in string_paths(document):
            mutation = copy.deepcopy(document)
            replace(mutation, path)
            try:
                validator(mutation)
            except ContractError:
                continue
            except Exception as error:  # pragma: no cover - red-path diagnostic
                pytest.fail(
                    f"{validator.__name__} leaked {type(error).__name__} at {path!r}"
                )
            accepted.append((validator.__name__, path))
    assert accepted == []


def test_empty_quality_report_is_a_valid_zero_population_receipt(tmp_path):
    report = catalog_quality_report(tmp_path)
    assert report["schema"] == QUALITY_SCHEMA
    assert report["personas"] == 0
    assert report["usable_identities"] == 0
    assert validate_catalog_quality_report(json.loads(json.dumps(report)))


def test_combined_quality_uses_one_catalog_snapshot(tmp_path, monkeypatch):
    import browser_core.persona_quality as quality_module

    add_persona(tmp_path, _persona("a"))
    add_persona(tmp_path, _persona("b", claims={"window.hardwareConcurrency": 16}))
    original = quality_module.list_personas
    calls = 0

    def counted_list(*args, **kwargs):
        nonlocal calls
        calls += 1
        return original(*args, **kwargs)

    monkeypatch.setattr(quality_module, "list_personas", counted_list)
    report = catalog_quality_report(tmp_path)
    assert report["personas"] == 2
    assert calls == 1


def test_an_empty_catalog_reports_zero_rather_than_dividing_by_it(tmp_path):
    uniqueness = catalog_uniqueness(tmp_path)
    assert uniqueness["distinct_identities"] == 0
    assert uniqueness["unique_personas"] == 0
    assert uniqueness["duplicate_ratio"] == 0.0
    assert "distinct identities  0" in render_uniqueness(uniqueness)
    assert audit_catalog_coherence(tmp_path)["personas"] == 0


@pytest.mark.parametrize(
    ("renderer", "schema"),
    [
        (render_coherence, COHERENCE_SCHEMA),
        (render_uniqueness, UNIQUENESS_SCHEMA),
    ],
)
def test_persona_renderers_reject_sparse_and_private_foreign_artifacts(
    renderer,
    schema: str,
) -> None:
    private = "private-persona-schema-marker"
    for document in ({"schema": schema}, {"schema": private}, "not-an-object"):
        with pytest.raises(ContractError) as failure:
            renderer(document)
        assert private not in str(failure.value)


# --------------------------------------------------------------------------
# Retirement
# --------------------------------------------------------------------------


def test_retirement_reports_before_it_acts(tmp_path):
    add_persona(tmp_path, _persona("keep"))
    add_persona(tmp_path, _persona("drop", claims={"window.maxTouchPoints": 5}))
    dry = retire_incoherent_personas(tmp_path, dry_run=True)
    assert dry["selected"] == 1
    assert dry["retired_count"] == 0
    assert dry["by_reason"] == {"contradicts-itself": 1}
    assert audit_catalog_coherence(tmp_path)["personas"] == 2, "nothing changed"


@pytest.mark.parametrize("dry_run", [0, 1, "false", None, []])
def test_retirement_requires_a_literal_boolean_before_mutating(
    tmp_path,
    dry_run,
):
    add_persona(tmp_path, _persona("thin"))
    with pytest.raises(ContractError, match="dry-run choice"):
        retire_incoherent_personas(tmp_path, dry_run=dry_run, minimum_claims=100)
    assert [persona["state"] for persona in list_personas(tmp_path)] == ["active"]


def test_retirement_deprecates_rather_than_deletes(tmp_path):
    add_persona(tmp_path, _persona("keep"))
    add_persona(tmp_path, _persona("drop", claims={"window.maxTouchPoints": 5}))
    result = retire_incoherent_personas(tmp_path, dry_run=False)
    assert result["retired_count"] == 1
    assert result["active_after"] == 1
    assert audit_catalog_coherence(tmp_path)["passed"] is True
    still_on_disk = audit_catalog_coherence(tmp_path, include_deprecated=True)
    assert still_on_disk["personas"] == 2, "deprecated personas remain auditable"


def test_retirement_report_is_an_exact_json_portable_receipt(tmp_path):
    add_persona(tmp_path, _persona("keep"))
    add_persona(tmp_path, _persona("drop", claims={"window.maxTouchPoints": 5}))
    report = json.loads(json.dumps(retire_incoherent_personas(tmp_path, dry_run=False)))
    assert report["schema"] == RETIREMENT_SCHEMA
    assert validate_retirement_report(report) is report
    assert report["retired"] == [{"persona_id": "drop", "reason": "contradicts-itself"}]

    mutations = []
    for path, replacement in (
        (("schema",), "private-retirement-schema-marker"),
        (("dry_run",), True),
        (("active_before",), 3),
        (("selected",), 2),
        (("by_reason", "contradicts-itself"), 2),
        (("retired", 0, "persona_id"), "private-retirement-id-marker"),
        (("retired", 0, "reason"), "private-retirement-reason-marker"),
        (("retired_count",), 0),
        (("warning_count",), 1),
        (("failed_count",), 1),
        (("active_after",), 2),
        (("sample",), []),
        (("note",), "private-retirement-note-marker"),
    ):
        mutation = copy.deepcopy(report)
        target = mutation
        for segment in path[:-1]:
            target = target[segment]
        target[path[-1]] = replacement
        mutations.append(mutation)
    extra = copy.deepcopy(report)
    extra["private"] = "private-retirement-field-marker"
    mutations.append(extra)

    for mutation in mutations:
        with pytest.raises(ContractError) as failure:
            validate_retirement_report(mutation)
        assert "private-retirement" not in str(failure.value)


def test_retirement_sample_rows_are_exact_json_arrays(tmp_path) -> None:
    add_persona(tmp_path, _persona("drop", claims={"window.maxTouchPoints": 5}))
    report = retire_incoherent_personas(tmp_path, dry_run=True)

    assert report["sample"]
    assert type(report["sample"][0]) is list
    mutation = copy.deepcopy(report)
    mutation["sample"][0] = tuple(mutation["sample"][0])
    with pytest.raises(ContractError):
        validate_retirement_report(mutation)


def test_retirement_thin_claim_reasons_cannot_exceed_the_generator_boundary(
    tmp_path,
) -> None:
    add_persona(tmp_path, _persona("drop", claims={"window.maxTouchPoints": 5}))
    report = retire_incoherent_personas(tmp_path, dry_run=True)
    impossible = "only-1000000-claims"
    report["by_reason"] = {impossible: 1}
    report["sample"][0][1] = impossible

    with pytest.raises(ContractError, match="retirement reason is invalid"):
        validate_retirement_report(report)


def test_retirement_thin_claim_reasons_cannot_exceed_the_persona_claim_cap(
    tmp_path,
) -> None:
    add_persona(tmp_path, _persona("drop", claims={"window.maxTouchPoints": 5}))
    report = retire_incoherent_personas(tmp_path, dry_run=True)
    impossible = "only-129-claims"
    report["by_reason"] = {impossible: 1}
    report["sample"][0][1] = impossible

    with pytest.raises(ContractError, match="retirement reason is invalid"):
        validate_retirement_report(report)


def test_retirement_thin_claim_reasons_require_a_nonempty_persona_contract(
    tmp_path,
) -> None:
    add_persona(tmp_path, _persona("drop", claims={"window.maxTouchPoints": 5}))
    report = retire_incoherent_personas(tmp_path, dry_run=True)
    impossible = "only-0-claims"
    report["by_reason"] = {impossible: 1}
    report["sample"][0][1] = impossible

    with pytest.raises(ContractError, match="retirement reason is invalid"):
        validate_retirement_report(report)


def test_retirement_ids_use_the_persona_id_grammar(tmp_path) -> None:
    private = "private persona ID marker"

    committed_workspace = tmp_path / "committed"
    add_persona(
        committed_workspace,
        _persona("broken", claims={"window.maxTouchPoints": 5}),
    )
    committed = retire_incoherent_personas(committed_workspace, dry_run=False)
    assert committed["retired_count"] == 1
    committed["retired"][0]["persona_id"] = private
    committed["sample"][0][0] = private

    dry_workspace = tmp_path / "dry"
    add_persona(
        dry_workspace,
        _persona("broken", claims={"window.maxTouchPoints": 5}),
    )
    dry_run = retire_incoherent_personas(dry_workspace, dry_run=True)
    dry_run["sample"][0][0] = private

    for report in (committed, dry_run):
        with pytest.raises(ContractError) as failure:
            validate_retirement_report(report)
        assert private not in str(failure.value)


def test_retirement_ids_use_one_casefolded_identity_spelling(tmp_path) -> None:
    reports = []
    for name, dry_run in (("committed", False), ("dry", True)):
        workspace = tmp_path / name
        for persona_id in ("broken-a", "broken-b"):
            add_persona(
                workspace,
                _persona(persona_id, claims={"window.maxTouchPoints": 5}),
            )
        reports.append(retire_incoherent_personas(workspace, dry_run=dry_run))

    aliases = {"broken-a": "BROKEN-A", "broken-b": "broken-a"}
    for report in reports:
        for label in ("retired", "warnings", "failed"):
            for row in report[label]:
                row["persona_id"] = aliases[row["persona_id"]]
        for row in report["sample"]:
            row[0] = aliases[row[0]]

        with pytest.raises(ContractError):
            validate_retirement_report(report)


def test_retirement_failure_receipt_is_safe_complete_and_validated(
    tmp_path, monkeypatch
):
    import browser_core.personas as persona_module

    add_persona(tmp_path, _persona("drop", claims={"window.maxTouchPoints": 5}))

    def fail_retirement(*_args, **_kwargs):
        raise ContractError("private-retirement-failure-marker")

    monkeypatch.setattr(persona_module, "set_persona_state", fail_retirement)
    report = retire_incoherent_personas(tmp_path, dry_run=False)
    assert report["retired_count"] == 0
    assert report["failed_count"] == 1
    assert report["active_after"] == 1
    assert report["failed"][0]["reason"] == "contradicts-itself"
    assert "private-retirement-failure-marker" not in json.dumps(report)
    assert validate_retirement_report(json.loads(json.dumps(report)))


def test_retirement_failure_receipt_requires_exact_text(tmp_path, monkeypatch) -> None:
    import browser_core.personas as persona_module

    class TextSubclass(str):
        pass

    add_persona(tmp_path, _persona("drop", claims={"window.maxTouchPoints": 5}))

    def fail_retirement(*_args, **_kwargs):
        raise ContractError("private-retirement-failure-marker")

    monkeypatch.setattr(persona_module, "set_persona_state", fail_retirement)
    report = retire_incoherent_personas(tmp_path, dry_run=False)
    report["failed"][0]["error"] = TextSubclass(report["failed"][0]["error"])

    with pytest.raises(ContractError):
        validate_retirement_report(report)


def test_retirement_reconciles_a_committed_transition_with_a_warning(
    tmp_path, monkeypatch
):
    import browser_core.personas as persona_module

    add_persona(tmp_path, _persona("drop", claims={"window.maxTouchPoints": 5}))
    original = persona_module.set_persona_state

    def commit_then_warn(*args, **kwargs):
        original(*args, **kwargs)
        raise OSError("private-post-commit-cleanup-marker")

    monkeypatch.setattr(persona_module, "set_persona_state", commit_then_warn)
    report = retire_incoherent_personas(tmp_path, dry_run=False)
    assert report["retired_count"] == 1
    assert report["warning_count"] == 1
    assert report["failed_count"] == 0
    assert report["active_after"] == 0
    assert report["warnings"][0]["persona_id"] == "drop"
    assert report["warnings"][0]["reason"] == "contradicts-itself"
    assert "private-post-commit-cleanup-marker" not in json.dumps(report)
    assert validate_retirement_report(json.loads(json.dumps(report)))


def test_retirement_aborts_when_a_failed_transition_cannot_be_reconciled(
    tmp_path, monkeypatch
):
    import browser_core.personas as persona_module

    add_persona(tmp_path, _persona("drop", claims={"window.maxTouchPoints": 5}))

    def fail_retirement(*_args, **_kwargs):
        raise OSError("private-transition-marker")

    def fail_reconciliation(*_args, **_kwargs):
        raise OSError("private-reconciliation-marker")

    monkeypatch.setattr(persona_module, "set_persona_state", fail_retirement)
    monkeypatch.setattr(persona_module, "load_persona", fail_reconciliation)
    with pytest.raises(ContractError, match="state could not be reconciled") as failure:
        retire_incoherent_personas(tmp_path, dry_run=False)
    assert "private-transition-marker" not in str(failure.value)
    assert "private-reconciliation-marker" not in str(failure.value)


def test_retirement_also_drops_personas_that_claim_almost_nothing(tmp_path):
    thin = _persona("thin")
    thin["identity_contract"]["expected"] = {"window.platform": "Win32"}
    from browser_core.personas import persona_digest

    thin["integrity_sha256"] = persona_digest(thin)
    add_persona(tmp_path, thin)
    add_persona(tmp_path, _persona("rich"))
    result = retire_incoherent_personas(tmp_path, dry_run=True, minimum_claims=4)
    assert result["by_reason"] == {"only-1-claims": 1}


def test_a_report_never_leaks_a_whole_persona(tmp_path):
    """Reports are summaries; dumping contracts into them would make them unreadable."""
    add_persona(tmp_path, _persona("p"))
    body = json.dumps(catalog_quality_report(tmp_path))
    assert "identity_contract" not in body


@pytest.mark.parametrize("cores", [10, 12, 16, 24, 32])
def test_a_phone_with_a_desktop_core_count_is_implausible(cores: int) -> None:
    """Android SoCs are 4-, 6-, or 8-core. Nobody sells a 24-core handset."""
    persona = _mobile_persona(claims={"window.hardwareConcurrency": cores})
    finding = next(
        f
        for f in coherence_findings(persona)
        if f["rule"] == "mobile-core-count-implausible"
    )
    assert finding["severity"] == "implausible"


def test_the_core_rule_is_implausible_where_the_memory_rule_is_a_contradiction() -> (
    None
):
    """The severities differ because the browsers differ, not for taste.

    Chromium clamps Android device memory in native code, so a phone claiming
    16 GB is impossible. `hardwareConcurrency` returns the raw processor count
    with no ceiling, so a phone claiming 24 cores is only a phone nobody sells.
    A catalog that rated them the same would either block real captures or wave
    through impossible ones.
    """
    persona = _mobile_persona(
        claims={"window.hardwareConcurrency": 24, "window.deviceMemory": 16}
    )
    severities = {f["rule"]: f["severity"] for f in coherence_findings(persona)}
    assert severities["mobile-core-count-implausible"] == "implausible"
    assert severities["device-memory-above-android-cap"] == "contradiction"


@pytest.mark.parametrize("cores", [4, 6, 8])
def test_a_phone_on_a_real_soc_core_count_is_accepted(cores: int) -> None:
    persona = _mobile_persona(claims={"window.hardwareConcurrency": cores})
    assert "mobile-core-count-implausible" not in _rules(persona)


def test_the_mobile_core_rule_does_not_touch_desktops() -> None:
    assert "mobile-core-count-implausible" not in _rules(
        _persona(claims={"window.hardwareConcurrency": 24})
    )


def test_a_single_touch_point_on_a_touch_device_is_implausible() -> None:
    """One is the protocol default, not a measurement of any hardware.

    CDP's Emulation.setTouchEmulationEnabled documents "Defaults to one", and
    Playwright's has_touch never overrides it -- which is how 4,502 phones that
    cannot register a second finger got into the catalog.
    """
    persona = _mobile_persona(claims={"window.maxTouchPoints": 1})
    finding = next(
        f
        for f in coherence_findings(persona)
        if f["rule"] == "single-touch-point-on-a-touch-device"
    )
    assert finding["severity"] == "implausible"
    reject_incoherent_persona(persona)  # measured, so it must not block a capture


def test_five_touch_points_is_what_a_phone_reports() -> None:
    persona = _mobile_persona(claims={"window.maxTouchPoints": 5})
    assert "single-touch-point-on-a-touch-device" not in _rules(persona)
    assert "touch-declared-but-no-touch-points" not in _rules(persona)


def test_zero_and_one_touch_points_are_different_defects() -> None:
    """Zero is emulation that never applied; one is emulation using its default.

    They get different severities because they have different fixes, and a
    catalog that merged them would either block captures it should keep or wave
    through phones that cannot pinch.
    """
    never_applied = _mobile_persona(claims={"window.maxTouchPoints": 0})
    default_applied = _mobile_persona(claims={"window.maxTouchPoints": 1})
    zero = {f["rule"]: f["severity"] for f in coherence_findings(never_applied)}
    one = {f["rule"]: f["severity"] for f in coherence_findings(default_applied)}
    assert zero["touch-declared-but-no-touch-points"] == "contradiction"
    assert one["single-touch-point-on-a-touch-device"] == "implausible"


def test_a_non_touch_device_is_not_asked_about_touch_points() -> None:
    assert "single-touch-point-on-a-touch-device" not in _rules(_persona())


def test_a_chromium_handset_on_windows_phone_is_implausible() -> None:
    """Playwright still ships Nokia Lumia presets; Chrome never shipped there.

    Windows Phone support ended in 2019 and never had a Chrome build at all, so
    "Chrome 153 on a Lumia 520" is internally consistent and not a thing in the
    world -- the definition of `implausible` rather than a contradiction.
    """
    persona = _persona(
        device={
            "class": "mobile",
            "os_family": "windows",
            "is_mobile": True,
            "has_touch": True,
        },
        claims={"window.maxTouchPoints": 5, "userAgentData.mobile": True},
    )
    finding = next(
        f
        for f in coherence_findings(persona)
        if f["rule"] == "mobile-os-never-ran-this-engine"
    )
    assert finding["severity"] == "implausible"


def test_an_android_handset_is_not_flagged_for_its_operating_system() -> None:
    assert "mobile-os-never-ran-this-engine" not in _rules(_mobile_persona())


def test_a_windows_desktop_is_not_flagged_for_its_operating_system() -> None:
    """The rule is about handsets, not about Windows."""
    assert "mobile-os-never-ran-this-engine" not in _rules(_persona())


def test_the_android_memory_cap_is_scoped_to_android_not_to_every_handset() -> None:
    """Chromium's clamp is `BUILDFLAG(IS_ANDROID)`, so the rule must be too.

    A Windows Phone preset is a bad persona for its own reasons, but it is not
    bad *because of Android's clamp*, and a rule that gives the wrong reason is
    the failure mode B23 documents.
    """
    lumia = _persona(
        device={
            "class": "mobile",
            "os_family": "windows",
            "is_mobile": True,
            "has_touch": True,
        },
        claims={
            "window.maxTouchPoints": 5,
            "userAgentData.mobile": True,
            "window.deviceMemory": 32,
        },
    )
    assert "device-memory-above-android-cap" not in _rules(lumia)
    android = _mobile_persona(claims={"window.deviceMemory": 32})
    assert "device-memory-above-android-cap" in _rules(android)


# -- timezone spelling is an engine tell ---------------------------------------


def test_a_firefox_persona_may_not_record_chromiums_timezone_spelling() -> None:
    """Measured 2026-08-07: Firefox reports Asia/Kolkata, Chromium Asia/Calcutta.

    Firefox will not even accept `Asia/Calcutta` as a timezone id, so a Firefox
    persona recording it is claiming a string that engine cannot produce. This
    is the rule a kernel remap would trip first.
    """
    persona = _persona(
        kernel={"engine": "firefox", "product": "firefox"},
        geography={
            "country": "IN",
            "locale": "en-IN",
            "languages": ["en-IN", "en"],
            "timezone": "Asia/Kolkata",
        },
        claims={
            "window.timezone": "Asia/Calcutta",
            "window.locale": "en-IN",
            "window.languages": ["en-IN", "en"],
        },
    )
    finding = next(
        f
        for f in coherence_findings(persona)
        if f["rule"] == "timezone-spelling-contradicts-engine"
    )
    assert finding["severity"] == "contradiction"
    assert finding["detail"]["engine_reports"] == "Asia/Kolkata"


def test_a_chromium_persona_recording_the_legacy_spelling_is_correct() -> None:
    persona = _persona(
        geography={
            "country": "IN",
            "locale": "en-IN",
            "languages": ["en-IN", "en"],
            "timezone": "Asia/Kolkata",
        },
        claims={
            "window.timezone": "Asia/Calcutta",
            "window.locale": "en-IN",
            "window.languages": ["en-IN", "en"],
        },
    )
    assert "timezone-spelling-contradicts-engine" not in _rules(persona)


def test_a_chromium_persona_recording_the_canonical_spelling_is_a_contradiction() -> (
    None
):
    persona = _persona(
        geography={
            "country": "UA",
            "locale": "uk-UA",
            "languages": ["uk-UA", "uk"],
            "timezone": "Europe/Kyiv",
        },
        claims={
            "window.timezone": "Europe/Kyiv",
            "window.locale": "uk-UA",
            "window.languages": ["uk-UA", "uk"],
        },
    )
    assert "timezone-spelling-contradicts-engine" in _rules(persona)


def test_an_unmeasured_zone_gets_no_verdict_either_way() -> None:
    """Silence is not agreement.

    A first version returned the canonical spelling for every zone it had never
    probed, and instantly flagged 254 correct personas recording
    `America/Buenos_Aires` -- which is what all three engines actually report.
    Generalising three measurements to every zone is the exact error the
    device-memory rule made.
    """
    from browser_core.kernels import expected_timezone_spelling

    assert expected_timezone_spelling("chromium", "Europe/Berlin") is None
    assert expected_timezone_spelling("chromium", "America/Chicago") is None
    # Measured, and every engine agrees on the link name here.
    assert (
        expected_timezone_spelling("chromium", "America/Argentina/Buenos_Aires")
        == "America/Buenos_Aires"
    )
    assert (
        expected_timezone_spelling("firefox", "America/Argentina/Buenos_Aires")
        == "America/Buenos_Aires"
    )
    assert "timezone-spelling-contradicts-engine" not in _rules(
        _persona(claims={"window.timezone": "America/Chicago"})
    )


def _rules(persona) -> set[str]:
    return {finding["rule"] for finding in coherence_findings(persona)}


def test_a_chromium_persona_must_carry_the_chromium_webgl_marker() -> None:
    """Measured on four builds, not read from a specification.

    Chromium 153 (attested), Chromium 147 (Playwright), Firefox 148 and WebKit
    26.4 were each asked for gl.VERSION on this host. Both Chromium builds
    answered "WebGL 1.0 (OpenGL ES 2.0 Chromium)"; Firefox and WebKit both
    answered a bare "WebGL 1.0". So the parenthetical is an engine tell in the
    same way the time-zone spelling is, and it is the rule a kernel remap would
    trip first.
    """
    clean = _persona()
    assert "webgl-version-contradicts-engine" not in _rules(clean)

    stripped = _persona(claims={"rendering.webgl.version": "WebGL 1.0"})
    assert "webgl-version-contradicts-engine" in _rules(stripped)


def test_a_firefox_persona_may_not_claim_the_chromium_marker() -> None:
    firefox = _persona(
        kernel={"engine": "firefox", "product": "firefox"},
        claims={"rendering.webgl.version": "WebGL 1.0"},
    )
    assert "webgl-version-contradicts-engine" not in _rules(firefox)

    impostor = _persona(
        kernel={"engine": "firefox", "product": "firefox"},
        claims={"rendering.webgl.version": "WebGL 1.0 (OpenGL ES 2.0 Chromium)"},
    )
    assert "webgl-version-contradicts-engine" in _rules(impostor)


@pytest.mark.parametrize(
    ("engine", "product", "version", "marker_present"),
    [
        ("chromium", "browser-core", "WebGL private-version-sentinel", False),
        (
            "firefox",
            "firefox",
            "WebGL Chromium private-version-sentinel",
            True,
        ),
    ],
)
def test_webgl_version_engine_finding_does_not_echo_the_version(
    engine: str, product: str, version: str, marker_present: bool
) -> None:
    persona = _persona(
        kernel={"engine": engine, "product": product},
        claims={"rendering.webgl.version": version},
    )
    finding = next(
        item
        for item in coherence_findings(persona)
        if item["rule"] == "webgl-version-contradicts-engine"
    )

    assert finding["detail"] == {
        "claim": "rendering.webgl.version",
        "engine": engine,
        "chromium_marker_present": marker_present,
    }
    assert "private-version-sentinel" not in json.dumps(finding, sort_keys=True)


def test_the_rule_does_not_claim_to_separate_firefox_from_webkit() -> None:
    """Both reported the identical bare string, so the rule says nothing here.

    Asserting a difference that was not measured is how the time-zone rule
    flagged 254 correct personas on its first attempt.
    """
    for engine, product in (("firefox", "firefox"), ("webkit", "safari")):
        persona = _persona(
            kernel={"engine": engine, "product": product},
            claims={"rendering.webgl.version": "WebGL 1.0"},
        )
        assert "webgl-version-contradicts-engine" not in _rules(persona)


def test_screen_depths_that_disagree_are_a_contradiction() -> None:
    """All four engines reported colorDepth and pixelDepth as the same number."""
    matched = _persona(
        claims={"window.screen.colorDepth": 24, "window.screen.pixelDepth": 24}
    )
    assert "screen-depths-disagree" not in _rules(matched)

    split = _persona(
        claims={"window.screen.colorDepth": 24, "window.screen.pixelDepth": 32}
    )
    assert "screen-depths-disagree" in _rules(split)


def test_an_unusual_but_matched_depth_gets_no_verdict() -> None:
    """Only the relationship was measured, so only the relationship is asserted.

    24 is all this host's panel can show. A capture from an HDR display would
    legitimately report 30, and a rule that pinned the absolute value would flag
    a correct persona -- the exact failure the device-memory rule was retracted
    for.
    """
    hdr = _persona(
        claims={"window.screen.colorDepth": 30, "window.screen.pixelDepth": 30}
    )
    assert "screen-depths-disagree" not in _rules(hdr)


# The brand vectors below are verbatim measurements, taken on this host in one
# sitting from five browsers in an identical context. They are not invented
# examples, and a rule that disagrees with one of them is wrong about a browser
# that exists.

MEASURED_BRANDS = {
    "attested-browser-core-153": ["Chromium/153", "Not_A Brand/8"],
    "playwright-chromium-147": ["HeadlessChrome/147", "Not.A/Brand/8", "Chromium/147"],
    "retail-google-chrome-150": ["Not;A=Brand/8", "Chromium/150", "Google Chrome/150"],
}


def _measured_brand_claims(name: str) -> dict[str, object]:
    # Only the brand vectors are measured; keep the surrounding test UA's major
    # aligned so a brand rule is not masked by an unrelated UA/CH contradiction.
    major = int(name.rsplit("-", 1)[1])
    return {
        "window.userAgent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            f"AppleWebKit/537.36 Chrome/{major}.0.0.0 Safari/537.36"
        ),
        "userAgentData.brands": MEASURED_BRANDS[name],
    }


def test_the_attested_builds_own_brand_vector_passes_every_brand_rule() -> None:
    persona = _persona(
        kernel={
            "engine": "chromium",
            "product": "browser-core",
            "minimum_major": 153,
            "maximum_major": 153,
        },
        claims=_measured_brand_claims("attested-browser-core-153"),
    )
    assert not {rule for rule in _rules(persona) if rule.startswith("brands-")}


def test_a_capture_on_playwrights_chromium_is_caught_announcing_headless() -> None:
    """The defect this field was added to make visible.

    Playwright's bundled Chromium puts `HeadlessChrome` in its client hints; the
    attested build does not. No persona recorded brands before now, so a capture
    on the wrong kernel carried an automation announcement in a launch-time
    constant that nothing in the catalog could see.
    """
    persona = _persona(
        kernel={
            "engine": "chromium",
            "product": "chromium",
            "minimum_major": 147,
            "maximum_major": 147,
        },
        claims=_measured_brand_claims("playwright-chromium-147"),
    )
    assert "brands-announce-headless" in _rules(persona)


def test_headless_is_graded_implausible_not_impossible() -> None:
    """It is a browser that really exists, so the severity has to say so.

    Grading it a contradiction would block the capture and hide the measurement,
    which is the opposite of what the catalog is for.
    """
    persona = _persona(
        kernel={
            "engine": "chromium",
            "product": "chromium",
            "minimum_major": 147,
            "maximum_major": 147,
        },
        claims=_measured_brand_claims("playwright-chromium-147"),
    )
    severities = {
        finding["severity"]
        for finding in coherence_findings(persona)
        if finding["rule"] == "brands-announce-headless"
    }
    assert severities == {"implausible"}


@pytest.mark.parametrize(
    ("entry", "unexpected_rule"),
    [
        ("NotHeadlessChrome/140", "brands-announce-headless"),
        ("Google Chrome Beta/140", "brands-claim-branding-no-owned-kernel-has"),
    ],
)
def test_reserved_brand_classification_requires_the_exact_brand_component(
    entry: str, unexpected_rule: str
) -> None:
    persona = _persona(
        claims={"userAgentData.brands": [entry, "Chromium/140", "Not_A Brand/8"]}
    )

    assert unexpected_rule not in _rules(persona)


def test_no_owned_kernel_may_claim_google_chrome_branding() -> None:
    """Retail Chrome's vector, on a persona no build here could realize."""
    persona = _persona(
        kernel={
            "engine": "chromium",
            "product": "chromium",
            "minimum_major": 150,
            "maximum_major": 150,
        },
        claims=_measured_brand_claims("retail-google-chrome-150"),
    )
    assert "brands-claim-branding-no-owned-kernel-has" in _rules(persona)


def test_a_brand_major_outside_the_kernel_range_contradicts_it() -> None:
    """B38's defect in stored form: preset says one major, client hints another."""
    matched = _persona(
        claims={"userAgentData.brands": ["Chromium/140", "Not_A Brand/8"]}
    )
    assert "brands-major-contradicts-kernel" not in _rules(matched)

    # The fixture kernel is major 140; the client hints say 153.
    mismatched = _persona(
        claims={"userAgentData.brands": ["Chromium/153", "Not_A Brand/8"]}
    )
    assert "brands-major-contradicts-kernel" in _rules(mismatched)


def test_a_unicode_brand_major_is_not_treated_as_native_decimal_evidence() -> None:
    persona = _persona(
        claims={"userAgentData.brands": ["Chromium/١٤٠", "Not_A Brand/8"]}
    )
    assert "brands-major-is-not-ascii" in _rules(persona)


def test_a_non_string_brand_entry_is_not_coerced_into_version_evidence() -> None:
    persona = _persona(
        claims={"userAgentData.brands": [140, "Not_A Brand/8"]}
    )
    assert "brands-entry-is-not-string" in _rules(persona)


def test_non_string_brand_finding_does_not_echo_the_untrusted_vector() -> None:
    sentinel = 918273645
    persona = _persona(
        claims={
            "userAgentData.brands": [
                sentinel,
                "Chromium/140",
                "Not_A Brand/8",
            ]
        }
    )

    finding = next(
        item
        for item in coherence_findings(persona)
        if item["rule"] == "brands-entry-is-not-string"
    )

    assert finding["detail"] == {"entry_count": 3, "invalid_entry_count": 1}
    assert str(sentinel) not in json.dumps(finding, sort_keys=True)


@pytest.mark.parametrize(
    ("brands", "rule"),
    [
        (
            ["HeadlessChrome/140", "Private Sentinel/140", "Not_A Brand/8"],
            "brands-announce-headless",
        ),
        (
            ["Google Chrome/140", "Private Sentinel/140", "Not_A Brand/8"],
            "brands-claim-branding-no-owned-kernel-has",
        ),
        (
            ["Chromium/١٤٠", "Private Sentinel/140", "Not_A Brand/8"],
            "brands-major-is-not-ascii",
        ),
        (
            ["Chromium/153", "Private Sentinel/140", "Not_A Brand/8"],
            "brands-major-contradicts-kernel",
        ),
    ],
)
def test_string_brand_findings_do_not_echo_the_complete_vector(
    brands: list[str], rule: str
) -> None:
    persona = _persona(claims={"userAgentData.brands": brands})
    finding = next(item for item in coherence_findings(persona) if item["rule"] == rule)

    assert "Private Sentinel/140" not in json.dumps(finding, sort_keys=True)


def test_an_empty_brand_vector_is_a_contradiction() -> None:
    persona = _persona(claims={"userAgentData.brands": []})
    assert "brands-vector-invalid" in _rules(persona)


@pytest.mark.parametrize(
    "entry",
    ["Chromium", "/140", "Chromium/", "Chromium/0140", "Chromium/+140"],
)
def test_malformed_brand_version_entries_are_contradictions(entry: str) -> None:
    persona = _persona(
        claims={"userAgentData.brands": [entry, "Not_A Brand/8"]}
    )
    assert "brands-vector-invalid" in _rules(persona)


@pytest.mark.parametrize("hidden_character", ["\u200b", "\u202e"])
def test_brand_labels_reject_nonprintable_unicode(hidden_character: str) -> None:
    persona = _persona(claims={
        "userAgentData.brands": [f"Chromium{hidden_character}/140", "Not_A Brand/8"],
    })
    assert "brands-vector-invalid" in _rules(persona)


def test_duplicate_brand_entries_are_a_contradiction() -> None:
    persona = _persona(
        claims={
            "userAgentData.brands": [
                "Chromium/140",
                "Chromium/140",
                "Not_A Brand/8",
            ]
        }
    )
    assert "brands-vector-invalid" in _rules(persona)


def test_one_brand_cannot_repeat_with_different_in_range_versions() -> None:
    persona = _persona(
        kernel={"minimum_major": 140, "maximum_major": 141},
        claims={
            "userAgentData.brands": [
                "Chromium/140",
                "Chromium/141",
                "Not_A Brand/8",
            ]
        },
    )

    assert "brands-major-contradicts-kernel" not in _rules(persona)
    assert "brands-vector-invalid" in _rules(persona)


def test_one_matching_brand_major_cannot_hide_a_mismatched_major() -> None:
    persona = _persona(
        claims={
            "userAgentData.brands": [
                "Chromium/140",
                "Other Browser/153",
                "Not_A Brand/8",
            ]
        }
    )
    assert "brands-major-contradicts-kernel" in _rules(persona)


def test_user_agent_and_client_hint_major_must_agree_within_kernel_range(
    tmp_path,
) -> None:
    persona = _persona(
        "split-major",
        kernel={"minimum_major": 140, "maximum_major": 141},
        claims={"userAgentData.brands": ["Chromium/141", "Not_A Brand/8"]},
    )
    add_persona(tmp_path, persona)

    assert "brands-major-contradicts-kernel" not in _rules(persona)
    assert "user-agent-major-contradicts-kernel" not in _rules(persona)
    assert "user-agent-client-hints-major-disagrees" in _rules(persona)
    report = catalog_quality_report(tmp_path)
    assert report["passed"] is False
    assert report["usable_identities"] == 0


def test_user_agent_and_client_hint_major_agreement_within_kernel_range() -> None:
    persona = _persona(
        kernel={"minimum_major": 140, "maximum_major": 141},
        claims={
            "window.userAgent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 Chrome/141.0.0.0 Safari/537.36"
            ),
            "userAgentData.brands": ["Chromium/141", "Not_A Brand/8"],
        },
    )

    assert "user-agent-client-hints-major-disagrees" not in _rules(persona)


def test_measured_brand_vectors_all_have_valid_entry_syntax() -> None:
    for name in MEASURED_BRANDS:
        persona = _persona(
            claims=_measured_brand_claims(name),
            kernel={"minimum_major": int(name.rsplit("-", 1)[1]),
                    "maximum_major": int(name.rsplit("-", 1)[1])},
        )
        assert "brands-vector-invalid" not in _rules(persona)
        assert "user-agent-client-hints-major-disagrees" not in _rules(persona)


def test_a_unicode_user_agent_major_is_not_treated_as_chromium_evidence() -> None:
    persona = _persona(
        claims={
            "window.userAgent": (
                "Mozilla/5.0 AppleWebKit/537.36 Chrome/١٤٠.0.0.0 Safari/537.36"
            )
        }
    )
    assert "user-agent-chromium-version-invalid" in _rules(persona)


@pytest.mark.parametrize(
    "token",
    [
        "Chrome/0140.0.0.0",
        "Chrome/140",
        "Chrome/140.0.0.0 Chrome/153.0.0.0",
        "Chrome/140.00.0.0",
        "Chrome/140.+0.0.0",
    ],
)
def test_noncanonical_chromium_user_agent_tokens_are_contradictions(
    token: str,
) -> None:
    persona = _persona(
        claims={
            "window.userAgent": (
                f"Mozilla/5.0 AppleWebKit/537.36 {token} Safari/537.36"
            )
        }
    )
    assert "user-agent-chromium-version-invalid" in _rules(persona)


@pytest.mark.parametrize(
    "neighbor",
    ["NotChrome/140.0.0.0", "NotHeadlessChrome/140.0.0.0"],
)
def test_neighboring_ua_labels_are_not_malformed_chromium_markers(
    neighbor: str,
) -> None:
    persona = _persona(
        claims={
            "window.userAgent": (
                f"Mozilla/5.0 AppleWebKit/537.36 {neighbor} Safari/537.36"
            )
        }
    )
    rules = _rules(persona)

    assert "user-agent-chromium-version-invalid" not in rules
    assert "user-agent-chromium-major-missing" in rules


@pytest.mark.parametrize("extra_marker", ["Chrome/", "HeadlessChrome/"])
def test_a_valid_chromium_token_cannot_hide_an_extra_bare_marker(
    extra_marker: str,
) -> None:
    persona = _persona(
        claims={
            "window.userAgent": (
                "Mozilla/5.0 AppleWebKit/537.36 Chrome/140.0.7339.0 "
                f"{extra_marker} Safari/537.36"
            )
        }
    )

    assert "user-agent-chromium-version-invalid" in _rules(persona)


def test_a_canonical_four_component_chrome_token_is_valid() -> None:
    persona = _persona(
        claims={
            "window.userAgent": (
                "Mozilla/5.0 AppleWebKit/537.36 "
                "Chrome/140.0.7339.0 Safari/537.36"
            )
        }
    )
    assert "user-agent-chromium-version-invalid" not in _rules(persona)


@pytest.mark.parametrize("suffix", ["\n", "\x7f"])
def test_user_agent_text_must_match_the_capture_boundary(suffix: str) -> None:
    persona = _persona(
        claims={
            "window.userAgent": (
                "Mozilla/5.0 AppleWebKit/537.36 "
                "Chrome/140.0.7339.0 Safari/537.36"
                f"{suffix}"
            )
        }
    )
    findings = [
        item
        for item in coherence_findings(persona)
        if item["rule"] == "user-agent-claim-invalid"
    ]

    assert len(findings) == 1
    assert findings[0]["severity"] == "contradiction"
    assert findings[0]["detail"] == {
        "reason": "control-character",
        "value_type": "str",
    }


@pytest.mark.parametrize("suffix", ["\u200b", "\u202e"])
def test_user_agent_rejects_nonprintable_unicode(suffix: str) -> None:
    persona = _persona(
        claims={
            "window.userAgent": (
                "Mozilla/5.0 AppleWebKit/537.36 "
                "Chrome/140.0.7339.0 Safari/537.36"
                f"{suffix}"
            )
        }
    )
    findings = [
        item for item in coherence_findings(persona)
        if item["rule"] == "user-agent-claim-invalid"
    ]

    assert len(findings) == 1
    assert findings[0]["severity"] == "contradiction"
    assert findings[0]["detail"] == {
        "reason": "nonprintable-character",
        "value_type": "str",
    }


def _firefox_persona(user_agent: str) -> dict:
    persona = _persona(
        kernel={
            "engine": "firefox",
            "product": "firefox",
            "minimum_major": 148,
            "maximum_major": 148,
        },
        claims={
            "window.userAgent": user_agent,
            "rendering.webgl.version": "WebGL 1.0",
        },
    )
    for claim in (
        "userAgentData.brands",
        "userAgentData.mobile",
        "userAgentData.platform",
    ):
        persona["identity_contract"]["expected"].pop(claim)
    return persona


def test_uniform_entropy_bounds_skip_the_empty_remainder_bucket(
    monkeypatch,
) -> None:
    real_entropy_term = persona_quality_module._entropy_term
    calls: list[tuple[int, int]] = []

    def checked_entropy_term(count: int, total: int) -> float:
        assert 0 <= count <= total
        calls.append((count, total))
        return real_entropy_term(count, total)

    monkeypatch.setattr(
        persona_quality_module,
        "_entropy_term",
        checked_entropy_term,
    )
    assert persona_quality_module._partition_entropy_bounds(8, 8, 1) == (
        0.0,
        0.0,
    )
    assert persona_quality_module._capped_partition_entropy_bounds(
        8, 8, 1, 8
    ) == (0.0, 0.0)
    assert calls


def test_entropy_bounds_skip_zero_coefficient_terms(monkeypatch) -> None:
    real_entropy_term = persona_quality_module._entropy_term
    calls: list[tuple[int, int]] = []

    def checked_entropy_term(count: int, total: int) -> float:
        calls.append((count, total))
        return real_entropy_term(count, total)

    monkeypatch.setattr(
        persona_quality_module,
        "_entropy_term",
        checked_entropy_term,
    )
    assert persona_quality_module._partition_entropy_bounds(8, 8, 1) == (
        0.0,
        0.0,
    )
    assert persona_quality_module._capped_partition_entropy_bounds(
        8, 8, 1, 8
    ) == (0.0, 0.0)
    assert calls == [(8, 8), (8, 8), (8, 8), (8, 8)]


def test_capped_entropy_bounds_skip_empty_full_bucket(monkeypatch) -> None:
    real_entropy_term = persona_quality_module._entropy_term
    calls: list[tuple[int, int]] = []

    def checked_entropy_term(count: int, total: int) -> float:
        calls.append((count, total))
        return real_entropy_term(count, total)

    monkeypatch.setattr(
        persona_quality_module,
        "_entropy_term",
        checked_entropy_term,
    )
    assert persona_quality_module._capped_partition_entropy_bounds(
        8, 4, 3, 3
    ) == (1.25, 1.25)
    assert calls == [(2, 8), (1, 8), (2, 8), (1, 8)]


def test_entropy_term_reuses_one_bounded_logarithm(monkeypatch) -> None:
    cache_clear = getattr(persona_quality_module._entropy_term, "cache_clear", None)
    if cache_clear is not None:
        cache_clear()
    real_log2 = persona_quality_module.math.log2
    logarithm_calls = 0

    def counting_log2(value: float) -> float:
        nonlocal logarithm_calls
        logarithm_calls += 1
        return real_log2(value)

    monkeypatch.setattr(persona_quality_module.math, "log2", counting_log2)
    first = persona_quality_module._entropy_term(31_337, 104_729)
    second = persona_quality_module._entropy_term(31_337, 104_729)

    assert first == second
    assert logarithm_calls == 1
    cache_info = getattr(persona_quality_module._entropy_term, "cache_info", None)
    assert cache_info is not None
    assert cache_info().maxsize == 4_096
    persona_quality_module._entropy_term.cache_clear()


def test_anonymity_entropy_reuses_the_entropy_term_cache(monkeypatch) -> None:
    persona_quality_module._entropy_term.cache_clear()
    persona_quality_module._entropy_term(1, 8)
    persona_quality_module._entropy_term(3, 8)

    def unexpected_logarithm(_value: float) -> float:
        raise AssertionError("anonymity entropy bypassed the entropy-term cache")

    monkeypatch.setattr(
        persona_quality_module.math,
        "log2",
        unexpected_logarithm,
    )
    assert round(
        persona_quality_module._anonymity_entropy({1: 2, 3: 2}), 4
    ) == 1.8113
    cache_info = persona_quality_module._entropy_term.cache_info()
    assert cache_info.hits == 2
    assert cache_info.misses == 2
    persona_quality_module._entropy_term.cache_clear()


def test_distribution_entropy_reuses_the_entropy_term_cache(monkeypatch) -> None:
    persona_quality_module._entropy_term.cache_clear()
    persona_quality_module._entropy_term(1, 4)
    persona_quality_module._entropy_term(3, 4)

    def unexpected_logarithm(_value: float) -> float:
        raise AssertionError("distribution entropy bypassed the entropy-term cache")

    monkeypatch.setattr(
        persona_quality_module.math,
        "log2",
        unexpected_logarithm,
    )
    assert round(persona_quality_module._entropy((1, 3)), 4) == 0.8113
    cache_info = persona_quality_module._entropy_term.cache_info()
    assert cache_info.hits == 2
    assert cache_info.misses == 2
    persona_quality_module._entropy_term.cache_clear()


def test_uniqueness_maximum_entropy_reuses_the_population_entropy_key(
    tmp_path, monkeypatch
) -> None:
    _add_one_one_three_three_identity_groups(tmp_path)
    report = catalog_uniqueness(tmp_path)
    persona_quality_module._entropy_term.cache_clear()
    persona_quality_module._entropy_term(1, 1)
    for count in range(1, 9):
        persona_quality_module._entropy_term(count, 8)

    def unexpected_logarithm(_value: float) -> float:
        raise AssertionError("maximum entropy bypassed the entropy-term cache")

    monkeypatch.setattr(
        persona_quality_module.math,
        "log2",
        unexpected_logarithm,
    )
    zero = persona_quality_module._maximum_entropy_bits(1)
    assert zero == 0.0
    assert math.copysign(1.0, zero) > 0
    assert validate_uniqueness_report(report) == report
    cache_info = persona_quality_module._entropy_term.cache_info()
    assert cache_info.misses == 9
    assert cache_info.currsize == 9
    assert cache_info.hits > 0
    persona_quality_module._entropy_term.cache_clear()


@pytest.mark.parametrize(
    "token",
    [
        "Firefox/0148.0",
        "Firefox/148",
        "Firefox/148.00",
        "Firefox/148.+0",
        "Firefox/148.0 Firefox/149.0",
    ],
)
def test_noncanonical_firefox_user_agent_tokens_are_contradictions(
    token: str,
) -> None:
    persona = _firefox_persona(
        f"Mozilla/5.0 (Windows NT 10.0; rv:148.0) Gecko/20100101 {token}"
    )
    assert "user-agent-firefox-version-invalid" in _rules(persona)


def test_a_canonical_two_component_firefox_token_is_valid() -> None:
    persona = _firefox_persona(
        "Mozilla/5.0 (Windows NT 10.0; rv:148.0) "
        "Gecko/20100101 Firefox/148.0"
    )
    assert "user-agent-firefox-version-invalid" not in _rules(persona)
    assert "user-agent-firefox-major-contradicts-kernel" not in _rules(persona)
    assert "user-agent-firefox-rv-invalid" not in _rules(persona)
    assert "user-agent-firefox-rv-disagrees" not in _rules(persona)


def test_firefox_user_agent_major_must_match_the_kernel() -> None:
    persona = _firefox_persona(
        "Mozilla/5.0 (Windows NT 10.0; rv:147.0) "
        "Gecko/20100101 Firefox/147.0"
    )
    assert "user-agent-firefox-major-contradicts-kernel" in _rules(persona)


def test_a_valid_firefox_token_cannot_hide_an_extra_bare_marker() -> None:
    persona = _firefox_persona(
        "Mozilla/5.0 (Windows NT 10.0; rv:148.0) "
        "Gecko/20100101 Firefox/148.0 Firefox/"
    )

    assert "user-agent-firefox-version-invalid" in _rules(persona)


@pytest.mark.parametrize(
    "rv",
    ["rv:0148.0", "rv:148.0 rv:149.0"],
)
def test_noncanonical_firefox_rv_tokens_are_contradictions(rv: str) -> None:
    persona = _firefox_persona(
        f"Mozilla/5.0 (Windows NT 10.0; {rv}) "
        "Gecko/20100101 Firefox/148.0"
    )

    assert "user-agent-firefox-rv-invalid" in _rules(persona)


@pytest.mark.parametrize("rv", ["rv:147.0", "rv:148.1"])
def test_firefox_rv_must_match_the_product_version(rv: str) -> None:
    persona = _firefox_persona(
        f"Mozilla/5.0 (Windows NT 10.0; {rv}) "
        "Gecko/20100101 Firefox/148.0"
    )

    assert "user-agent-firefox-rv-disagrees" in _rules(persona)


def test_a_firefox_persona_without_rv_is_incomplete_not_contradictory() -> None:
    persona = _firefox_persona(
        "Mozilla/5.0 (Windows NT 10.0) Gecko/20100101 Firefox/148.0"
    )
    findings = [
        item
        for item in coherence_findings(persona)
        if item["rule"] == "user-agent-firefox-rv-missing"
    ]

    assert len(findings) == 1
    assert findings[0]["severity"] == "anomaly"
    reject_incoherent_persona(persona)


def test_a_firefox_persona_without_its_product_token_is_incomplete() -> None:
    persona = _firefox_persona(
        "Mozilla/5.0 (Windows NT 10.0; rv:148.0) Gecko/20100101"
    )
    findings = [
        item
        for item in coherence_findings(persona)
        if item["rule"] == "user-agent-firefox-major-missing"
    ]

    assert len(findings) == 1
    assert findings[0]["severity"] == "anomaly"
    reject_incoherent_persona(persona)


def test_headless_chrome_is_reported_from_the_user_agent_itself() -> None:
    persona = _persona(
        claims={
            "window.userAgent": (
                "Mozilla/5.0 AppleWebKit/537.36 "
                "HeadlessChrome/140.0.7339.0 Safari/537.36"
            )
        }
    )
    findings = [
        finding
        for finding in coherence_findings(persona)
        if finding["rule"] == "user-agent-announces-headless"
    ]
    assert {finding["severity"] for finding in findings} == {"implausible"}


def test_the_grease_brand_is_not_read_as_a_version() -> None:
    """All three measured vectors carry a GREASE entry with a junk version.

    Its spelling differs per build -- `Not_A Brand/8`, `Not.A/Brand/8`,
    `Not;A=Brand/8` -- and reading 8 as a browser major would flag every persona
    in the catalog.
    """
    for vector in MEASURED_BRANDS.values():
        greased = [entry for entry in vector if "Not" in entry]
        assert greased, vector
    # 8 is the GREASE version; reading it as a browser major would contradict
    # every kernel range in the catalog.
    persona = _persona(
        claims={"userAgentData.brands": ["Chromium/140", "Not;A=Brand/8"]}
    )
    assert "brands-major-contradicts-kernel" not in _rules(persona)


def test_firefox_and_webkit_may_not_record_brands_at_all() -> None:
    """Both measured `navigator.userAgentData` as absent entirely."""
    for engine, product in (("firefox", "firefox"), ("webkit", "safari")):
        persona = _persona(
            kernel={"engine": engine, "product": product},
            claims={
                "userAgentData.brands": ["Chromium/153"],
                "rendering.webgl.version": "WebGL 1.0",
            },
        )
        assert "brands-on-an-engine-without-client-hints" in _rules(persona)


def test_a_non_chromium_engine_may_not_hide_an_empty_brand_vector() -> None:
    persona = _persona(
        kernel={"engine": "firefox", "product": "firefox"},
        claims={
            "userAgentData.brands": [],
            "rendering.webgl.version": "WebGL 1.0",
        },
    )
    assert "brands-on-an-engine-without-client-hints" in _rules(persona)
