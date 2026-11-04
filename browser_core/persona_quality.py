"""Two questions a fingerprint catalog should be able to answer about itself.

*Is this identity self-consistent?* and *how identifying is it?* Vendors sell
fingerprint libraries by headcount, which answers neither. A catalog of a
thousand identities where seven hundred claim to be iPhones with zero touch
points is not a thousand identities; it is one tell, repeated.

**Coherence** cross-examines each persona against itself. Every rule below
compares two things that a real browser cannot disagree about -- a device that
declares touch against the touch-point count it reports, an engine against an API
only a different engine exposes, a claimed screen against the screen in the
device record. Nothing here re-checks what ``validate_persona`` already enforces;
this is the second opinion, and its whole value is that it can disagree with the
capture that produced the persona.

That is not hypothetical. The kernel probe's own realization check treats
``pointer: coarse`` as sufficient evidence of touch, which is defensible as a
cross-engine signal and means a WebKit iPhone emulation *passes* while recording
``maxTouchPoints: 0``. Both checks are looking at the same persona; only one of
them is looking for a contradiction.

**Uniqueness** measures the opposite failure. Personas that are internally
perfect but identical to four hundred others do not give you four hundred
identities. This report finds exact duplicate claim vectors, sizes each
persona's anonymity set, and ranks fields by how much they actually separate the
catalog -- which, for reverse engineering, doubles as a map of where the
identifying signal lives.

Severities, in the order they should be read:

``contradiction``
    Two claims that cannot both be true of any real browser. Always a defect.
``implausible``
    Internally consistent but not what the named product does in the wild.
``anomaly``
    Unusual or under-specified. Often a gap in the capture rather than an error,
    and reported so it can be judged rather than silently trusted.
"""

from __future__ import annotations

import functools
import math
import re
from array import array
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable

from .contracts import ContractError, parse_canonical_decimal
from .errors import (
    normalize_renderer_failures,
    safe_failure_receipt,
)
from .kernels import (
    PLAUSIBLE_MOBILE_CORE_MAXIMUM,
    TOUCH_POINTS,
    canonical_timezone,
    expected_timezone_spelling,
    timezones_equivalent,
)
from .numeric import is_finite_number
from .personas import CHROMIUM_MOBILE_OS_FAMILIES, PLATFORM_OS_FAMILIES, list_personas
from .profiles import (
    MAX_IDENTITY_CONTRACT_CLAIMS,
    is_valid_identity_claim_path,
    is_valid_profile_id,
)

COHERENCE_SCHEMA = "browser-core.persona-coherence/1"
UNIQUENESS_SCHEMA = "browser-core.persona-uniqueness/1"
QUALITY_SCHEMA = "browser-core.persona-quality/2"
RETIREMENT_SCHEMA = "browser-core.persona-retirement/3"

_MAX_COHERENCE_DETAIL_DEPTH = 4
_MAX_COHERENCE_DETAIL_ITEMS = 32
_MAX_COHERENCE_DETAIL_NODES = 64
_MAX_COHERENCE_DETAIL_TEXT = 512
_MAX_COHERENCE_DETAIL_TEXT_TOTAL = 4096
_MAX_COHERENCE_DETAIL_INTEGER_BITS = 4096
_MAX_EXACT_IDENTITY_SUBSET_SUM_POPULATION = 65_536
_MAX_EXACT_IDENTITY_SUBSET_GROUP_COUNT_POPULATION = 4_096
_MAX_EXACT_IDENTITY_JOINT_SUBSET_POPULATION = 1_024
_MAX_EXACT_IDENTITY_JOINT_GROUP_COUNT_POPULATION = 256
_MAX_EXACT_IDENTITY_PARTITION_POPULATION = 64
_MAX_EXACT_IDENTITY_PARTITION_GROUPS = 24
_MAX_EXACT_IDENTITY_PARTITION_BUCKETS = 8
_MAX_EXACT_IDENTITY_PARTITION_STATES = 100_000

_QUALITY_NOTE = (
    "usable_identities counts distinct claim vectors that contradict "
    "nothing. A catalog's file count is an upper bound on it, never a "
    "substitute for it."
)
_RETIREMENT_NOTE = (
    "Deprecated personas stay on disk and in the audit; they stop being "
    "counted as inventory. Nothing is deleted."
)

SEVERITIES = ("contradiction", "implausible", "anomaly")
_COHERENCE_RULE_RE = re.compile(r"^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$")

# Chromium appends its own name to the WebGL version string; Firefox and WebKit
# report the bare version. Measured on this host across four builds -- attested
# Chromium 153, Playwright Chromium 147, Firefox 148, WebKit 26.4 -- rather than
# read from a specification, because the two rules that were written from specs
# both had to be retracted after a browser disagreed with them.
CHROMIUM_WEBGL_VERSION_MARKER = "Chromium"
_NON_CHROMIUM_ENGINES = frozenset({"firefox", "webkit"})
_CHROMIUM_UA_TOKEN_RE = re.compile(
    r"(?<![A-Za-z0-9])(?P<product>HeadlessChrome|Chrome)/"
    r"(?P<version>[^ \t\r\n;()]+)"
)
_ABSENT_CLAIM = object()
_CHROMIUM_UA_MARKER_RE = re.compile(
    r"(?<![A-Za-z0-9])(?:HeadlessChrome|Chrome)/"
)
_FIREFOX_UA_TOKEN_RE = re.compile(
    r"(?<![A-Za-z0-9])(?P<product>Firefox)/(?P<version>[^ \t\r\n;()]+)"
)
_FIREFOX_UA_MARKER_RE = re.compile(r"(?<![A-Za-z0-9])Firefox/")
_FIREFOX_RV_TOKEN_RE = re.compile(
    r"(?<![A-Za-z0-9])rv:(?P<version>[^ \t\r\n;()]+)"
)
_FIREFOX_RV_MARKER_RE = re.compile(r"(?<![A-Za-z0-9])rv:")
_MOBILE_UA_RE = re.compile(r"(?:^|[ ;(])Mobile(?:[ /;) ]|$)", re.IGNORECASE)


def _is_integer_measurement(value: Any) -> bool:
    """Distinguish JSON integer measurements from boolean claim values."""
    return isinstance(value, int) and not isinstance(value, bool)


# These are API value families, not plausibility rules. Unknown/custom identity
# claims remain generic JSON leaves, while a known browser API may not change its
# JSON type merely because a later relationship check would otherwise ignore it.
_KNOWN_CLAIM_VALUE_FAMILIES = {
    "rendering.webgl.renderer": "nullable-string",
    "rendering.webgl.vendor": "nullable-string",
    "rendering.webgl.version": "nullable-string",
    "userAgentData.brands": "array",
    "userAgentData.mobile": "boolean",
    "userAgentData.platform": "string",
    "window.deviceMemory": "finite-number",
    "window.hardwareConcurrency": "integer",
    "window.languages": "string-array",
    "window.locale": "string",
    "window.maxTouchPoints": "integer",
    "window.mimeTypesLength": "integer",
    "window.pdfViewerEnabled": "boolean",
    "window.platform": "string",
    "window.pluginsLength": "integer",
    "window.screen.availHeight": "integer",
    "window.screen.availWidth": "integer",
    "window.screen.colorDepth": "integer",
    "window.screen.devicePixelRatio": "finite-number",
    "window.screen.height": "integer",
    "window.screen.pixelDepth": "integer",
    "window.screen.width": "integer",
    "window.timezone": "string",
    "window.userAgent": "string",
}

_WEBGL_STRING_CLAIMS = (
    "rendering.webgl.version",
    "rendering.webgl.vendor",
    "rendering.webgl.renderer",
)


def _claim_matches_value_family(value: Any, family: str) -> bool:
    if family == "string":
        return type(value) is str
    if family == "nullable-string":
        return value is None or type(value) is str
    if family == "boolean":
        return type(value) is bool
    if family == "integer":
        return type(value) is int
    if family == "finite-number":
        return is_finite_number(value)
    if family == "array":
        return type(value) is list
    if family == "string-array":
        return type(value) is list and all(type(item) is str for item in value)
    raise AssertionError(f"unknown claim value family: {family}")


def _json_value_family(value: Any) -> str:
    if value is None:
        return "null"
    if type(value) is bool:
        return "boolean"
    if type(value) is int:
        return "integer"
    if type(value) is float:
        return "number"
    if type(value) is str:
        return "string"
    if type(value) is list:
        return "array"
    if type(value) is dict:
        return "object"
    return "non-json"

# Brand entries that decide a persona's fate. `HeadlessChrome` is what
# Playwright's bundled Chromium announces in its client hints and the attested
# build does not; `Google Chrome` is the entry only a Google-branded build may
# carry, which no binary available here is.
HEADLESS_BRAND = "HeadlessChrome"
BRANDED_CHROME_BRAND = "Google Chrome"
_MEASURED_GREASE_BRANDS = frozenset(
    {"Not_A Brand", "Not.A/Brand", "Not;A=Brand"}
)


def _parse_ua_brand_entry(entry: Any) -> tuple[str, int] | None:
    if type(entry) is not str:
        return None
    brand, separator, version = entry.rpartition("/")
    major = parse_canonical_decimal(version, minimum=1, maximum=999)
    if (
        not separator
        or not brand
        or len(brand) > 128
        or not brand.isprintable()
        or major is None
    ):
        return None
    return brand, major


def _parse_chromium_ua_token(user_agent: str) -> tuple[str, int] | None:
    matches = list(_CHROMIUM_UA_TOKEN_RE.finditer(user_agent))
    marker_count = sum(1 for _ in _CHROMIUM_UA_MARKER_RE.finditer(user_agent))
    if len(matches) != 1 or marker_count != 1:
        return None
    match = matches[0]
    parts = match.group("version").split(".")
    if len(parts) != 4:
        return None
    parsed = [
        parse_canonical_decimal(
            part,
            minimum=1 if index == 0 else 0,
            maximum=999 if index == 0 else 2_147_483_647,
        )
        for index, part in enumerate(parts)
    ]
    if any(part is None for part in parsed):
        return None
    return match.group("product"), parsed[0]  # type: ignore[return-value]


def _parse_two_component_version(version: str) -> tuple[int, int] | None:
    parts = version.split(".")
    if len(parts) != 2:
        return None
    major = parse_canonical_decimal(parts[0], minimum=1, maximum=999)
    minor = parse_canonical_decimal(parts[1], minimum=0, maximum=2_147_483_647)
    if major is None or minor is None:
        return None
    return major, minor


def _parse_firefox_ua_token(user_agent: str) -> tuple[int, int] | None:
    matches = list(_FIREFOX_UA_TOKEN_RE.finditer(user_agent))
    marker_count = sum(1 for _ in _FIREFOX_UA_MARKER_RE.finditer(user_agent))
    if len(matches) != 1 or marker_count != 1:
        return None
    return _parse_two_component_version(matches[0].group("version"))


def _parse_firefox_rv_token(user_agent: str) -> tuple[int, int] | None:
    matches = list(_FIREFOX_RV_TOKEN_RE.finditer(user_agent))
    marker_count = sum(1 for _ in _FIREFOX_RV_MARKER_RE.finditer(user_agent))
    if len(matches) != 1 or marker_count != 1:
        return None
    return _parse_two_component_version(matches[0].group("version"))

# navigator.platform strings a real browser reports, mapped to the OS family the
# persona record must agree with. Shared with the capture path so a rule and the
# code that has to satisfy it cannot drift apart. Anything outside this table is
# reported as an anomaly rather than an error -- physical-device captures are
# allowed to be surprising, and a measurement is not wrong just because it is
# unfamiliar.
_PLATFORM_OS = PLATFORM_OS_FAMILIES

_UA_CH_PLATFORM_OS = {
    "Windows": {"windows"},
    "macOS": {"macos"},
    "Linux": {"linux"},
    "Android": {"android"},
    "Chrome OS": {"linux"},
    "Chromium OS": {"linux"},
}

# Only Chromium exposes these. A Firefox or Safari persona carrying one is
# claiming an API its own engine does not implement.
_CHROMIUM_ONLY_CLAIMS = (
    "window.deviceMemory",
    "userAgentData.mobile",
    "userAgentData.platform",
)
_CHROMIUM_USER_AGENT_DATA_CLAIMS = (
    "userAgentData.brands",
    "userAgentData.mobile",
    "userAgentData.platform",
)

# The HTML specification fixes these exact counts: a browser with a PDF viewer
# reports five hard-coded plugins and two MIME types, and one without reports
# none. There is no browser in between.
_SPEC_PLUGIN_COUNTS = {0, 5}
_SPEC_MIME_COUNTS = {0, 2}

# Device Memory rounds physical RAM to the nearer power of two and then clamps
# the result. The clamp belongs to the implementation, not to the published
# specification, and the two have diverged: https://www.w3.org/TR/device-memory/
# still documents a 0.25-8 ladder, while Chromium clamps desktop to [2, 32] and
# Android to [1, 8] (crbug.com/454354290, live in
# third_party/blink/common/device_memory/approximated_device_memory.cc at the
# revision this repository pins).
#
# Measured on the capture host 2026-08-07, four browsers on the same 64 GiB
# machine: branded Chrome stable, Playwright Chromium 147.0.7727.15 and
# 149.0.7827.55, and the attested Browser Core build 153.0.7988.0. Every one
# reports 32. An earlier version of this rule checked the published ladder and
# therefore called all four non-conformant -- a reminder that for a rule of this
# kind the shipping implementation is the authority and the specification is
# only a hypothesis about it.
_DEVICE_MEMORY_LADDER = {0.25, 0.5, 1.0, 2.0, 4.0, 8.0, 16.0, 32.0}

# Chromium's Android build clamps at 8 no matter how much RAM the phone has, so
# a mobile persona above it claims a number Chrome for Android cannot produce.
# Unlike the desktop values this is a real defect, and it is the one the old
# rule was hiding behind 449 false positives.
_DEVICE_MEMORY_MOBILE_MAX = 8.0

# Shared with the capture tables rather than restated, so the numbers a capture
# draws from and the rule that judges them cannot drift apart -- which is exactly
# how the catalog ended up holding 24-core phones.
_PLAUSIBLE_MOBILE_CORES = PLAUSIBLE_MOBILE_CORE_MAXIMUM
_REAL_TOUCH_POINTS = TOUCH_POINTS

# Shared with the capture planner rather than restated here: the devices a
# capture will accept and the devices a rule will pass must be the same set. iOS
# is in it because Chrome exists there, though it is WebKit underneath -- a
# separate problem the engine rules already catch.
_CHROMIUM_MOBILE_OS_FAMILIES = CHROMIUM_MOBILE_OS_FAMILIES

# Renderer substrings that mean the GPU was never involved.
_SOFTWARE_RENDERERS = ("swiftshader", "llvmpipe", "softpipe", "mesa offscreen")

# What gl.getParameter(VENDOR/RENDERER) returns before the debug extension is
# used. Not wrong -- just not the string a fingerprinting script actually reads.
_MASKED_WEBGL = {"webkit", "mozilla", "webkit webgl"}


def _finding(
    persona_id: str, rule: str, severity: str, summary: str, **detail: Any
) -> dict[str, Any]:
    if severity not in SEVERITIES:  # pragma: no cover - guards rule authoring
        raise ContractError(f"unknown coherence severity: {severity}")
    return {
        "persona_id": persona_id,
        "rule": rule,
        "severity": severity,
        "summary": summary,
        "detail": detail,
    }


def coherence_findings(persona: dict[str, Any]) -> list[dict[str, Any]]:
    """Every way this one persona disagrees with itself."""
    persona_id = persona["id"]
    device = persona["device"]
    kernel = persona["kernel"]
    geography = persona["geography"]
    expected = persona["identity_contract"]["expected"]
    engine = kernel["engine"]
    findings: list[dict[str, Any]] = []

    def claim(key: str) -> Any:
        return expected.get(key)

    # Type-check known API claims before applying cross-field rules. Previously
    # most rules began with `isinstance(...)`; a wrong type therefore skipped the
    # rule and could make malformed evidence look coherent. The finding retains
    # only the claim name and a closed JSON-family label, never the supplied value.
    for claim_name, family in _KNOWN_CLAIM_VALUE_FAMILIES.items():
        if claim_name in expected and not _claim_matches_value_family(
            expected[claim_name], family
        ):
            findings.append(
                _finding(
                    persona_id,
                    "claim-value-type-invalid",
                    "contradiction",
                    f"{claim_name} has the wrong JSON value family",
                    claim=claim_name,
                    expected_family=family,
                    observed_family=_json_value_family(expected[claim_name]),
                )
            )

    # The owned probes use null when a context or renderer-info value is not
    # available. A blank string has the right JSON family but is not a measured
    # WebGL value, so keep it visible as incomplete evidence without turning
    # optional WebGL availability into a contradiction.
    for claim_name in _WEBGL_STRING_CLAIMS:
        value = expected.get(claim_name)
        if type(value) is str and not value.strip():
            findings.append(
                _finding(
                    persona_id,
                    "webgl-string-is-blank",
                    "anomaly",
                    f"{claim_name} is a blank string rather than measured WebGL evidence",
                    claim=claim_name,
                )
            )

    # -- touch -------------------------------------------------------------
    touch_points = claim("window.maxTouchPoints")
    if _is_integer_measurement(touch_points):
        if touch_points < 0:
            findings.append(
                _finding(
                    persona_id,
                    "negative-touch-point-count",
                    "contradiction",
                    "navigator.maxTouchPoints cannot be negative",
                    max_touch_points=touch_points,
                )
            )
        if device["has_touch"] and touch_points == 0:
            findings.append(
                _finding(
                    persona_id,
                    "touch-declared-but-no-touch-points",
                    "contradiction",
                    "device declares touch support but the contract reports zero touch points",
                    has_touch=True,
                    max_touch_points=0,
                    device_class=device["class"],
                    note=(
                        "Real touch hardware reports a non-zero count -- iOS Safari "
                        "reports 5. Zero on a touch device is one of the most "
                        "commonly read emulation tells."
                    ),
                )
            )
        if device["has_touch"] and touch_points == 1:
            # Distinct from the zero case above, and a different defect. Zero on
            # a touch device is emulation that failed to apply at all; *one* is
            # emulation that applied its own default. CDP's
            # Emulation.setTouchEmulationEnabled defaults maxTouchPoints to one,
            # so a device that declares touch and reports a single point is a
            # screen that cannot register a second finger -- which no phone or
            # tablet on sale is.
            findings.append(
                _finding(
                    persona_id,
                    "single-touch-point-on-a-touch-device",
                    "implausible",
                    "touch device reports a single touch point; real phones report 5",
                    max_touch_points=1,
                    expected=_REAL_TOUCH_POINTS,
                    device_class=device["class"],
                    note=(
                        "Android Chrome and iOS Safari both report 5. One is the "
                        "protocol default, not a measurement of any hardware."
                    ),
                )
            )
        if not device["has_touch"] and touch_points > 0:
            findings.append(
                _finding(
                    persona_id,
                    "touch-points-without-touch-device",
                    "contradiction",
                    "contract reports touch points on a device that declares no touch",
                    has_touch=False,
                    max_touch_points=touch_points,
                )
            )

    # -- engine-exclusive API surface --------------------------------------
    if engine != "chromium":
        for key in _CHROMIUM_ONLY_CLAIMS:
            if key in expected:
                findings.append(
                    _finding(
                        persona_id,
                        "chromium-only-claim-on-other-engine",
                        "contradiction",
                        f"{key} is exposed only by Chromium but this persona is {engine}",
                        claim=key,
                        engine=engine,
                    )
                )
    else:
        present_user_agent_data = [
            key for key in _CHROMIUM_USER_AGENT_DATA_CLAIMS if key in expected
        ]
        missing_user_agent_data = [
            key for key in _CHROMIUM_USER_AGENT_DATA_CLAIMS if key not in expected
        ]
        if not present_user_agent_data:
            findings.append(
                _finding(
                    persona_id,
                    "chromium-without-user-agent-data",
                    "anomaly",
                    "Chromium persona carries no low-entropy userAgentData claim",
                    engine=engine,
                    note=(
                        "Chromium exposes brands, mobile, and platform together, so "
                        "a contract silent about them under-specifies the identity "
                        "rather than describing a browser that lacks them."
                    ),
                )
            )
        elif missing_user_agent_data:
            findings.append(
                _finding(
                    persona_id,
                    "chromium-user-agent-data-incomplete",
                    "anomaly",
                    "Chromium persona carries only part of its low-entropy userAgentData surface",
                    missing_claims=missing_user_agent_data,
                    present_count=len(present_user_agent_data),
                    required_count=len(_CHROMIUM_USER_AGENT_DATA_CLAIMS),
                    note=(
                        "Chromium exposes brands, mobile, and platform as one "
                        "low-entropy surface; a partial vector is incomplete evidence."
                    ),
                )
            )

    # -- platform vs OS ----------------------------------------------------
    platform = claim("window.platform")
    if isinstance(platform, str):
        allowed = _PLATFORM_OS.get(platform)
        if allowed is None:
            findings.append(
                _finding(
                    persona_id,
                    "platform-string-unrecognized",
                    "anomaly",
                    "navigator.platform is outside the known platform vocabulary",
                    claim="window.platform",
                    os_family=device["os_family"],
                )
            )
        elif device["os_family"] not in allowed:
            findings.append(
                _finding(
                    persona_id,
                    "platform-contradicts-os-family",
                    "contradiction",
                    f"navigator.platform {platform!r} does not belong to {device['os_family']}",
                    platform=platform,
                    os_family=device["os_family"],
                )
            )

    ua_platform = claim("userAgentData.platform")
    if isinstance(ua_platform, str):
        allowed = _UA_CH_PLATFORM_OS.get(ua_platform)
        if allowed is None:
            findings.append(
                _finding(
                    persona_id,
                    "ua-ch-platform-unrecognized",
                    "anomaly",
                    "userAgentData.platform is outside the known low-entropy platform vocabulary",
                    claim="userAgentData.platform",
                    os_family=device["os_family"],
                )
            )
        elif device["os_family"] not in allowed:
            findings.append(
                _finding(
                    persona_id,
                    "ua-ch-platform-contradicts-os-family",
                    "contradiction",
                    f"userAgentData.platform {ua_platform!r} does not belong to {device['os_family']}",
                    ua_platform=ua_platform,
                    os_family=device["os_family"],
                )
            )
    # A Chromium engine on a handset whose OS is not one Chrome ever shipped a
    # mobile build for. Playwright still carries Nokia Lumia presets, so the
    # matrix will happily mint "Chrome 153 on Windows Phone" -- a platform whose
    # support ended in 2019 and which never had a Chrome build at all. Internally
    # consistent, and not a thing in the world, which is precisely `implausible`.
    if (
        engine == "chromium"
        and device["is_mobile"]
        and device["os_family"] not in _CHROMIUM_MOBILE_OS_FAMILIES
    ):
        findings.append(
            _finding(
                persona_id,
                "mobile-os-never-ran-this-engine",
                "implausible",
                (
                    f"mobile persona claims a Chromium engine on {device['os_family']}, "
                    "which has no Chrome mobile build"
                ),
                os_family=device["os_family"],
                device_class=device["class"],
                engine=engine,
                note=(
                    "Chrome for mobile ships on Android and iOS only, and the iOS "
                    "build is WebKit underneath. A Chromium-engine handset on any "
                    "other OS is a device preset nobody can be running."
                ),
            )
        )

    # For three zones the engines disagree about which spelling to report:
    # Chromium and WebKit hand back the deprecated IANA link name, Firefox hands
    # back the canonical one and cannot even be set to the alias. So a persona
    # whose recorded spelling does not match its own engine is claiming a string
    # no browser of that engine produces -- and it is a one-line check. This is
    # the rule a kernel remap (B03) would trip first: move a Chromium persona to
    # Firefox and its `Asia/Calcutta` becomes impossible.
    claimed_zone = claim("window.timezone")
    if isinstance(claimed_zone, str):
        wanted_spelling = expected_timezone_spelling(
            engine, canonical_timezone(claimed_zone)
        )
        # `None` means the zone was never probed on this engine. Silence, not
        # agreement: an unmeasured zone gets no verdict either way.
        if wanted_spelling is not None and claimed_zone != wanted_spelling:
            findings.append(
                _finding(
                    persona_id,
                    "timezone-spelling-contradicts-engine",
                    "contradiction",
                    (
                        f"{engine} reports this zone as {wanted_spelling!r}, "
                        f"but the contract records {claimed_zone!r}"
                    ),
                    claimed=claimed_zone,
                    engine_reports=wanted_spelling,
                    engine=engine,
                    note=(
                        "Measured on this host: Chromium and WebKit return the "
                        "deprecated link name, Firefox returns the canonical name "
                        "and refuses the alias outright. The zone is the same "
                        "either way; the spelling is an engine tell."
                    ),
                )
            )

    # Measured on four engines, same host: Chromium (attested 153 and Playwright
    # 147) reports "WebGL 1.0 (OpenGL ES 2.0 Chromium)", Firefox 148 and WebKit
    # 26.4 both report bare "WebGL 1.0". So the parenthetical is a Chromium
    # marker and its presence or absence separates Chromium from the other two in
    # one string. It does not separate Firefox from WebKit -- those two are
    # identical on this field -- and the rule claims only what was measured.
    webgl_version = claim("rendering.webgl.version")
    if isinstance(webgl_version, str) and webgl_version:
        marks_chromium = CHROMIUM_WEBGL_VERSION_MARKER in webgl_version
        marker_disagrees = (engine == "chromium" and not marks_chromium) or (
            engine in _NON_CHROMIUM_ENGINES and marks_chromium
        )
        if marker_disagrees:
            findings.append(
                _finding(
                    persona_id,
                    "webgl-version-contradicts-engine",
                    "contradiction",
                    "the WebGL version marker disagrees with the declared engine",
                    claim="rendering.webgl.version",
                    engine=engine,
                    chromium_marker_present=marks_chromium,
                )
            )

    # Every engine measured reports colorDepth and pixelDepth as the same number.
    # The absolute value is left alone deliberately: 24 is all this host can show,
    # and a persona from a machine with an HDR panel would legitimately differ.
    # The *relationship* is what held across all four engines, so it is the only
    # thing asserted.
    color_depth = claim("window.screen.colorDepth")
    pixel_depth = claim("window.screen.pixelDepth")
    if (
        _is_integer_measurement(color_depth)
        and _is_integer_measurement(pixel_depth)
        and color_depth != pixel_depth
    ):
        findings.append(
            _finding(
                persona_id,
                "screen-depths-disagree",
                "contradiction",
                f"colorDepth {color_depth} and pixelDepth {pixel_depth} differ",
                color_depth=color_depth,
                pixel_depth=pixel_depth,
                note=(
                    "Measured identical on Chromium 153 and 147, Firefox 148, and "
                    "WebKit 26.4. No engine was observed reporting one without the "
                    "other."
                ),
            )
        )

    # -- client-hint brands ------------------------------------------------
    #
    # Measured on five browsers, same host, same context:
    #   attested Browser Core 153 : ["Chromium/153", "Not_A Brand/8"]
    #   Playwright Chromium 147   : ["HeadlessChrome/147", "Not.A/Brand/8", "Chromium/147"]
    #   retail Google Chrome 150  : ["Not;A=Brand/8", "Chromium/150", "Google Chrome/150"]
    #   Firefox 148, WebKit 26.4  : no userAgentData at all
    brands = claim("userAgentData.brands")
    brands_present = "userAgentData.brands" in expected
    brand_product_majors: set[int] = set()
    if brands_present and engine in _NON_CHROMIUM_ENGINES:
        findings.append(
            _finding(
                persona_id,
                "brands-on-an-engine-without-client-hints",
                "contradiction",
                f"a {engine} persona records userAgentData.brands, and {engine} has no userAgentData",
                engine=engine,
                entry_count=len(brands) if isinstance(brands, list) else None,
            )
        )
    if isinstance(brands, list):
        text_brands = [entry for entry in brands if type(entry) is str]
        if len(text_brands) != len(brands):
            findings.append(
                _finding(
                    persona_id,
                    "brands-entry-is-not-string",
                    "contradiction",
                    "the client-hint brand vector contains a non-string entry",
                    entry_count=len(brands),
                    invalid_entry_count=len(brands) - len(text_brands),
                )
            )
        parsed_brands = [_parse_ua_brand_entry(entry) for entry in text_brands]
        invalid_syntax_count = sum(item is None for item in parsed_brands)
        duplicate_count = len(text_brands) - len(set(text_brands))
        exact_brand_entries = [
            (entry, parsed)
            for entry, parsed in zip(text_brands, parsed_brands, strict=True)
            if parsed is not None
        ]
        parsed_brand_names = [parsed[0] for _, parsed in exact_brand_entries]
        duplicate_brand_count = len(parsed_brand_names) - len(set(parsed_brand_names))
        if (
            not brands
            or invalid_syntax_count
            or duplicate_count
            or duplicate_brand_count
        ):
            findings.append(
                _finding(
                    persona_id,
                    "brands-vector-invalid",
                    "contradiction",
                    "the client-hint brand vector is empty, duplicated, or malformed",
                    entry_count=len(brands),
                    invalid_syntax_count=invalid_syntax_count,
                    duplicate_count=duplicate_count,
                    duplicate_brand_count=duplicate_brand_count,
                    note=(
                        "Each measured entry is bounded control-free brand text, a "
                        "rightmost slash, and one canonical ASCII major version."
                    ),
                )
            )
        if any(parsed[0] == HEADLESS_BRAND for _, parsed in exact_brand_entries):
            findings.append(
                _finding(
                    persona_id,
                    "brands-announce-headless",
                    "implausible",
                    "the client-hint brand vector announces HeadlessChrome",
                    brand=HEADLESS_BRAND,
                    entry_count=len(brands),
                    note=(
                        "Real but nobody browses this way, so it is graded "
                        "implausible rather than impossible. It is the strongest "
                        "single signal that a capture ran on the wrong kernel: "
                        "Playwright's bundled Chromium carries this entry and the "
                        "attested build does not."
                    ),
                )
            )
        branded = [
            entry
            for entry, parsed in exact_brand_entries
            if parsed[0] == BRANDED_CHROME_BRAND
        ]
        if branded:
            findings.append(
                _finding(
                    persona_id,
                    "brands-claim-branding-no-owned-kernel-has",
                    "contradiction",
                    "the brand vector claims a reserved product no owned kernel can emit",
                    brand=BRANDED_CHROME_BRAND,
                    entry_count=len(brands),
                    note=(
                        "`is_chrome_branded` needs internal Google assets, so every "
                        "build available here is unbranded. An identity presenting "
                        "as retail Chrome is contradicted by the browser that would "
                        "realize it, on the first request it makes."
                    ),
                )
            )
        raw_versions = [entry.rpartition("/")[2] for entry in text_brands]
        non_ascii_decimals = sorted(
            item for item in raw_versions if item.isdigit() and not item.isascii()
        )
        if non_ascii_decimals:
            findings.append(
                _finding(
                    persona_id,
                    "brands-major-is-not-ascii",
                    "contradiction",
                    "the client-hint brand major is not ASCII decimal text",
                    entry_count=len(brands),
                    invalid_major_count=len(non_ascii_decimals),
                    note=(
                        "Browser version tokens are emitted as ASCII wire text; "
                        "Unicode decimal aliases are not equivalent evidence."
                    ),
                )
            )
        brand_product_majors = {
            major
            for parsed in parsed_brands
            if parsed is not None
            for brand, major in (parsed,)
            # The three GREASE labels are exact vectors measured on the pinned
            # builds; their deliberately meaningless version does not identify
            # the browser product.
            if brand not in _MEASURED_GREASE_BRANDS
        }
        if brand_product_majors and any(
            not kernel["minimum_major"] <= major <= kernel["maximum_major"]
            for major in brand_product_majors
        ):
            findings.append(
                _finding(
                    persona_id,
                    "brands-major-contradicts-kernel",
                    "contradiction",
                    (
                        f"the brand vector names major(s) {sorted(brand_product_majors)} and the kernel "
                        f"range is {kernel['minimum_major']}-{kernel['maximum_major']}"
                    ),
                    observed_majors=sorted(brand_product_majors),
                    entry_count=len(brands),
                    minimum_major=kernel["minimum_major"],
                    maximum_major=kernel["maximum_major"],
                    note=(
                        "The stored form of the defect a realization check caught "
                        "at capture time: a preset's baked-in version met a "
                        "different binary and the user agent said one major while "
                        "the client hints said another."
                    ),
                )
            )

    ua_mobile = claim("userAgentData.mobile")
    if isinstance(ua_mobile, bool) and ua_mobile != device["is_mobile"]:
        findings.append(
            _finding(
                persona_id,
                "ua-ch-mobile-contradicts-device",
                "contradiction",
                "userAgentData.mobile disagrees with the device record",
                ua_mobile=ua_mobile,
                is_mobile=device["is_mobile"],
            )
        )

    user_agent = claim("window.userAgent")
    if user_agent is not None:
        if not isinstance(user_agent, str) or not user_agent:
            findings.append(
                _finding(
                    persona_id,
                    "user-agent-claim-invalid",
                    "contradiction",
                    "navigator.userAgent must be a non-empty string",
                    value_type=type(user_agent).__name__,
                )
            )
        elif not user_agent.isprintable():
            ascii_control = any(ord(character) < 32 or ord(character) == 127 for character in user_agent)
            findings.append(
                _finding(
                    persona_id,
                    "user-agent-claim-invalid",
                    "contradiction",
                    "navigator.userAgent contains a nonprintable character",
                    reason="control-character" if ascii_control else "nonprintable-character",
                    value_type="str",
                )
            )
        else:
            foreign_products: list[str] = []
            chromium_product = _CHROMIUM_UA_TOKEN_RE.search(user_agent)
            if engine != "chromium" and chromium_product is not None:
                foreign_products.append(chromium_product.group("product"))
            if engine != "firefox" and _FIREFOX_UA_TOKEN_RE.search(user_agent):
                foreign_products.append("Firefox")
            for foreign_product in foreign_products:
                findings.append(
                    _finding(
                        persona_id,
                        "user-agent-product-contradicts-engine",
                        "contradiction",
                        (
                            f"the user agent announces {foreign_product} while the "
                            f"persona kernel engine is {engine}"
                        ),
                        product=foreign_product,
                        engine=engine,
                        note=(
                            "This checks only exact cross-engine product tokens; it "
                            "does not attempt to validate the complete user-agent grammar."
                        ),
                    )
                )
            if engine == "chromium":
                parsed_user_agent = _parse_chromium_ua_token(user_agent)
                if parsed_user_agent is None:
                    malformed_chrome_token = (
                        _CHROMIUM_UA_MARKER_RE.search(user_agent) is not None
                    )
                    findings.append(
                        _finding(
                            persona_id,
                            (
                                "user-agent-chromium-version-invalid"
                                if malformed_chrome_token
                                else "user-agent-chromium-major-missing"
                            ),
                            "contradiction" if malformed_chrome_token else "anomaly",
                            (
                                "Chromium persona user agent has a non-ASCII or malformed Chrome version"
                                if malformed_chrome_token
                                else "Chromium persona user agent has no Chrome major token"
                            ),
                        )
                    )
                else:
                    ua_product, ua_major = parsed_user_agent
                    if any(major != ua_major for major in brand_product_majors):
                        findings.append(
                            _finding(
                                persona_id,
                                "user-agent-client-hints-major-disagrees",
                                "contradiction",
                                "user agent and client-hint product majors disagree",
                                user_agent_major=ua_major,
                                brand_product_majors=sorted(brand_product_majors),
                            )
                        )
                    if ua_product == "HeadlessChrome":
                        findings.append(
                            _finding(
                                persona_id,
                                "user-agent-announces-headless",
                                "implausible",
                                "the user agent announces HeadlessChrome",
                                note=(
                                    "This is a real browser mode, so it is reported "
                                    "as implausible rather than contradictory."
                                ),
                            )
                        )
                    if not (
                        kernel["minimum_major"]
                        <= ua_major
                        <= kernel["maximum_major"]
                    ):
                        findings.append(
                            _finding(
                                persona_id,
                                "user-agent-major-contradicts-kernel",
                                "contradiction",
                                (
                                    f"user agent names major {ua_major} and the kernel "
                                    f"range is {kernel['minimum_major']}-"
                                    f"{kernel['maximum_major']}"
                                ),
                                user_agent_major=ua_major,
                                minimum_major=kernel["minimum_major"],
                                maximum_major=kernel["maximum_major"],
                            )
                        )
            if engine == "firefox":
                firefox_version = _parse_firefox_ua_token(user_agent)
                if firefox_version is None:
                    malformed_firefox_token = (
                        _FIREFOX_UA_MARKER_RE.search(user_agent) is not None
                    )
                    findings.append(
                        _finding(
                            persona_id,
                            (
                                "user-agent-firefox-version-invalid"
                                if malformed_firefox_token
                                else "user-agent-firefox-major-missing"
                            ),
                            (
                                "contradiction"
                                if malformed_firefox_token
                                else "anomaly"
                            ),
                            (
                                "Firefox persona user agent has a malformed Firefox version"
                                if malformed_firefox_token
                                else "Firefox persona user agent has no Firefox major token"
                            ),
                        )
                    )
                else:
                    firefox_major, _ = firefox_version
                    if not (
                        kernel["minimum_major"]
                        <= firefox_major
                        <= kernel["maximum_major"]
                    ):
                        findings.append(
                            _finding(
                                persona_id,
                                "user-agent-firefox-major-contradicts-kernel",
                                "contradiction",
                                (
                                    f"user agent names Firefox major {firefox_major} and the "
                                    f"kernel range is {kernel['minimum_major']}-"
                                    f"{kernel['maximum_major']}"
                                ),
                                user_agent_major=firefox_major,
                                minimum_major=kernel["minimum_major"],
                                maximum_major=kernel["maximum_major"],
                            )
                        )
                firefox_rv = _parse_firefox_rv_token(user_agent)
                if firefox_rv is None:
                    malformed_firefox_rv = (
                        _FIREFOX_RV_MARKER_RE.search(user_agent) is not None
                    )
                    findings.append(
                        _finding(
                            persona_id,
                            (
                                "user-agent-firefox-rv-invalid"
                                if malformed_firefox_rv
                                else "user-agent-firefox-rv-missing"
                            ),
                            "contradiction" if malformed_firefox_rv else "anomaly",
                            (
                                "Firefox persona user agent has a malformed rv version"
                                if malformed_firefox_rv
                                else "Firefox persona user agent has no rv version token"
                            ),
                        )
                    )
                elif firefox_version is not None and firefox_rv != firefox_version:
                    findings.append(
                        _finding(
                            persona_id,
                            "user-agent-firefox-rv-disagrees",
                            "contradiction",
                            "Firefox product and rv versions disagree",
                            firefox_major=firefox_version[0],
                            firefox_minor=firefox_version[1],
                            rv_major=firefox_rv[0],
                            rv_minor=firefox_rv[1],
                        )
                    )
            ua_mobile_marker = _MOBILE_UA_RE.search(user_agent) is not None
            if ua_mobile_marker != device["is_mobile"]:
                findings.append(
                    _finding(
                        persona_id,
                        "user-agent-mobile-contradicts-device",
                        "contradiction",
                        "user-agent Mobile marker disagrees with the device record",
                        user_agent_mobile=ua_mobile_marker,
                        is_mobile=device["is_mobile"],
                    )
                )

    # -- geometry ----------------------------------------------------------
    nonpositive_screen_claims = [
        f"window.screen.{field}"
        for field in ("availWidth", "availHeight", "colorDepth", "pixelDepth")
        if _is_integer_measurement(claim(f"window.screen.{field}"))
        and claim(f"window.screen.{field}") <= 0
    ]
    if nonpositive_screen_claims:
        findings.append(
            _finding(
                persona_id,
                "nonpositive-screen-measurement",
                "contradiction",
                "screen measurements must be positive",
                claims=nonpositive_screen_claims,
            )
        )
    for axis in ("width", "height"):
        claimed = claim(f"window.screen.{axis}")
        recorded = device["screen"][axis]
        if _is_integer_measurement(claimed) and claimed != recorded:
            findings.append(
                _finding(
                    persona_id,
                    "screen-contradicts-device-record",
                    "contradiction",
                    f"contract screen {axis} {claimed} disagrees with the device record {recorded}",
                    claimed=claimed,
                    recorded=recorded,
                    axis=axis,
                )
            )
        available = claim(f"window.screen.avail{axis.capitalize()}")
        if (
            _is_integer_measurement(available)
            and _is_integer_measurement(claimed)
            and available > claimed
        ):
            findings.append(
                _finding(
                    persona_id,
                    "available-screen-exceeds-screen",
                    "contradiction",
                    f"avail{axis.capitalize()} {available} exceeds screen {axis} {claimed}",
                    available=available,
                    screen=claimed,
                )
            )
    scale = claim("window.screen.devicePixelRatio")
    recorded_scale = device["viewport"]["device_scale_factor"]
    if is_finite_number(scale):
        if abs(scale - recorded_scale) > 1e-9:
            findings.append(
                _finding(
                    persona_id,
                    "pixel-ratio-contradicts-viewport",
                    "contradiction",
                    f"devicePixelRatio {scale} disagrees with the recorded scale {recorded_scale}",
                    claimed=scale,
                    recorded=recorded_scale,
                )
            )

    # -- geography ---------------------------------------------------------
    locale = claim("window.locale")
    if isinstance(locale, str) and locale.casefold() != geography["locale"].casefold():
        findings.append(
            _finding(
                persona_id,
                "locale-contradicts-geography",
                "contradiction",
                "navigator.language disagrees with the recorded geography locale",
                claim="window.locale",
                geography_field="locale",
            )
        )
    languages = claim("window.languages")
    if isinstance(languages, list):
        if not languages:
            findings.append(
                _finding(
                    persona_id,
                    "languages-contradict-geography",
                    "contradiction",
                    "navigator.languages is empty while geography records languages",
                    claimed_count=0,
                    geography_count=len(geography["languages"]),
                )
            )
        elif not isinstance(languages[0], str) or (
            isinstance(locale, str) and languages[0].casefold() != locale.casefold()
        ):
            findings.append(
                _finding(
                    persona_id,
                    "languages-contradict-locale",
                    "contradiction",
                    "navigator.languages does not begin with navigator.language",
                    claim="window.languages",
                    language_count=len(languages),
                    first_entry_is_string=type(languages[0]) is str,
                    locale_is_string=type(locale) is str,
                )
            )
        elif all(type(item) is str for item in languages) and [
            item.casefold() for item in languages
        ] != [item.casefold() for item in geography["languages"]]:
            findings.append(
                _finding(
                    persona_id,
                    "languages-contradict-geography",
                    "contradiction",
                    "navigator.languages disagrees with the recorded geography vector",
                    claimed_count=len(languages),
                    geography_count=len(geography["languages"]),
                    note=(
                        "Language order is observable and therefore part of the "
                        "persona identity; comparison is case-insensitive only."
                    ),
                )
            )
    timezone_name = claim("window.timezone")
    if isinstance(timezone_name, str) and not timezones_equivalent(
        timezone_name, geography["timezone"]
    ):
        findings.append(
            _finding(
                persona_id,
                "timezone-contradicts-geography",
                "contradiction",
                "the resolved time zone disagrees with the recorded geography time zone",
                claim="window.timezone",
                geography_field="timezone",
            )
        )

    # -- plugins and the PDF viewer ---------------------------------------
    plugins = claim("window.pluginsLength")
    mime_types = claim("window.mimeTypesLength")
    pdf_viewer = claim("window.pdfViewerEnabled")
    if _is_integer_measurement(plugins):
        if plugins < 0:
            findings.append(
                _finding(
                    persona_id,
                    "negative-plugin-count",
                    "contradiction",
                    "navigator.plugins.length cannot be negative",
                    plugins=plugins,
                )
            )
        elif plugins not in _SPEC_PLUGIN_COUNTS:
            findings.append(
                _finding(
                    persona_id,
                    "plugin-count-off-specification",
                    "implausible",
                    f"navigator.plugins.length {plugins} is neither 0 nor the specified 5",
                    plugins=plugins,
                )
            )
    if _is_integer_measurement(mime_types):
        if mime_types < 0:
            findings.append(
                _finding(
                    persona_id,
                    "negative-mime-type-count",
                    "contradiction",
                    "navigator.mimeTypes.length cannot be negative",
                    mime_types=mime_types,
                )
            )
        elif mime_types not in _SPEC_MIME_COUNTS:
            findings.append(
                _finding(
                    persona_id,
                    "mime-type-count-off-specification",
                    "implausible",
                    f"navigator.mimeTypes.length {mime_types} is neither 0 nor the specified 2",
                    mime_types=mime_types,
                )
            )
    if isinstance(pdf_viewer, bool) and _is_integer_measurement(plugins):
        if pdf_viewer and plugins == 0:
            findings.append(
                _finding(
                    persona_id,
                    "pdf-viewer-without-plugins",
                    "contradiction",
                    "pdfViewerEnabled is true but no plugins are reported",
                    pdf_viewer=True,
                    plugins=0,
                )
            )
        if not pdf_viewer and plugins > 0:
            findings.append(
                _finding(
                    persona_id,
                    "plugins-without-pdf-viewer",
                    "contradiction",
                    "plugins are reported but pdfViewerEnabled is false",
                    pdf_viewer=False,
                    plugins=plugins,
                )
            )
    # Branded desktop Chrome and Edge ship a PDF viewer; plain Chromium builds do
    # not, and neither does the Playwright bundle. Firing this rule on
    # ``product: chromium`` reported a defect for behaviour that is correct for
    # the product the persona actually names.
    if (
        device["class"] == "desktop"
        and kernel["product"] in {"chrome", "edge"}
        and isinstance(pdf_viewer, bool)
        and not pdf_viewer
    ):
        findings.append(
            _finding(
                persona_id,
                "desktop-chrome-without-pdf-viewer",
                "implausible",
                "desktop Chrome ships a PDF viewer, so pdfViewerEnabled false is not stock behaviour",
                product=kernel["product"],
                device_class="desktop",
            )
        )

    # -- rendering ---------------------------------------------------------
    renderer = claim("rendering.webgl.renderer")
    vendor = claim("rendering.webgl.vendor")
    if (
        (renderer is None or type(renderer) is str)
        and (vendor is None or type(vendor) is str)
        and (renderer is None) != (vendor is None)
    ):
        findings.append(
            _finding(
                persona_id,
                "webgl-vendor-renderer-incomplete",
                "anomaly",
                "the nullable WebGL vendor and renderer claims do not have matching presence",
                vendor_present=vendor is not None,
                renderer_present=renderer is not None,
            )
        )
    if type(renderer) is str and type(vendor) is str and webgl_version is None:
        findings.append(
            _finding(
                persona_id,
                "webgl-identity-without-version",
                "anomaly",
                "the WebGL vendor and renderer are present without a context version",
                version_present=False,
                vendor_present=True,
                renderer_present=True,
            )
        )
    if isinstance(renderer, str):
        lowered = renderer.casefold()
        software_marker = next(
            (marker for marker in _SOFTWARE_RENDERERS if marker in lowered), None
        )
        if software_marker is not None:
            findings.append(
                _finding(
                    persona_id,
                    "software-webgl-renderer",
                    "implausible",
                    "the WebGL renderer names a software rasterizer rather than a GPU",
                    claim="rendering.webgl.renderer",
                    software_marker=software_marker,
                )
            )
        elif (
            lowered in _MASKED_WEBGL
            and isinstance(vendor, str)
            and vendor.casefold() in _MASKED_WEBGL
        ):
            findings.append(
                _finding(
                    persona_id,
                    "webgl-strings-are-masked",
                    "anomaly",
                    "contract holds the masked WebGL strings, not the unmasked GPU strings",
                    vendor=vendor,
                    renderer=renderer,
                    note=(
                        "gl.getParameter(VENDOR/RENDERER) returns these constants in "
                        "every browser. Fingerprinting reads the UNMASKED_* pair via "
                        "WEBGL_debug_renderer_info, which this contract does not pin."
                    ),
                )
            )

    # Device Memory is a rounded, clamped power of two, so only two things about
    # it are checkable from the persona alone: whether the number is on the
    # ladder at all, and whether a phone is claiming more than Chrome for Android
    # will ever report. A desktop 16 or 32 is neither -- it is what this host's
    # browsers actually emit.
    device_memory = claim("window.deviceMemory")
    if is_finite_number(device_memory):
        value = device_memory
        if value <= 0:
            findings.append(
                _finding(
                    persona_id,
                    "nonpositive-device-memory",
                    "contradiction",
                    "navigator.deviceMemory must be positive",
                    device_memory=device_memory,
                )
            )
        elif value not in _DEVICE_MEMORY_LADDER:
            findings.append(
                _finding(
                    persona_id,
                    "device-memory-off-ladder",
                    "implausible",
                    f"navigator.deviceMemory {device_memory} is not a value the API can produce",
                    device_memory=device_memory,
                    ladder=sorted(_DEVICE_MEMORY_LADDER),
                    note=(
                        "The value is derived by rounding physical RAM to a power "
                        "of two, so anything else -- 3, 12, 24, 0 -- cannot come "
                        "out of a real browser regardless of version or platform."
                    ),
                )
            )
        elif device["os_family"] == "android" and value > _DEVICE_MEMORY_MOBILE_MAX:
            findings.append(
                _finding(
                    persona_id,
                    "device-memory-above-android-cap",
                    "contradiction",
                    (
                        f"mobile persona reports navigator.deviceMemory {device_memory}, "
                        f"above Chrome for Android's cap of {_DEVICE_MEMORY_MOBILE_MAX:g}"
                    ),
                    device_memory=device_memory,
                    mobile_maximum=_DEVICE_MEMORY_MOBILE_MAX,
                    device_class=device["class"],
                    note=(
                        "Chromium's Android build clamps this value at 8 in native "
                        "code, so no phone reports more however much RAM it has. A "
                        "desktop capture host emulating a phone leaks its own RAM "
                        "here, and the check is a one-liner for anyone reading it. "
                        "Scoped to Android rather than to every mobile device, "
                        "because the clamp is Android's -- a rule is only as true "
                        "as the build it describes."
                    ),
                )
            )

    concurrency = claim("window.hardwareConcurrency")
    if _is_integer_measurement(concurrency):
        if concurrency <= 0:
            findings.append(
                _finding(
                    persona_id,
                    "nonpositive-hardware-concurrency",
                    "contradiction",
                    "navigator.hardwareConcurrency must be positive",
                    hardware_concurrency=concurrency,
                )
            )
        elif concurrency > 128:
            findings.append(
                _finding(
                    persona_id,
                    "hardware-concurrency-implausible",
                    "implausible",
                    f"navigator.hardwareConcurrency {concurrency} is outside any shipping device",
                    hardware_concurrency=concurrency,
                )
            )
        elif device["is_mobile"] and concurrency > _PLAUSIBLE_MOBILE_CORES:
            # Deliberately `implausible` and not `contradiction`, which is the
            # difference between this and the device-memory rule above. Chromium
            # clamps Android memory in native code, so a phone reporting 16 GB is
            # impossible; `hardwareConcurrency` returns the raw processor count
            # with no ceiling at all, so a phone reporting 24 cores is merely a
            # phone nobody sells. The severity has to track which of those it is.
            findings.append(
                _finding(
                    persona_id,
                    "mobile-core-count-implausible",
                    "implausible",
                    (
                        f"mobile persona reports {concurrency} logical cores, above the "
                        f"{_PLAUSIBLE_MOBILE_CORES} of any shipping handset"
                    ),
                    hardware_concurrency=concurrency,
                    plausible_maximum=_PLAUSIBLE_MOBILE_CORES,
                    device_class=device["class"],
                    note=(
                        "Handset SoCs are 4-, 6-, or 8-core -- Android and "
                        "otherwise. A desktop capture host either leaks its own "
                        "count here or draws one from a desktop table, and both "
                        "produce phones that do not exist. Unlike the device-memory "
                        "rule this is not scoped to Android, because the claim is "
                        "about hardware anyone ships rather than about one build."
                    ),
                )
            )
    return findings


def audit_catalog_coherence(
    workspace: Path, *, include_deprecated: bool = False
) -> dict[str, Any]:
    """Cross-examine every persona in the catalog against itself."""
    personas = list_personas(workspace, include_deprecated=include_deprecated)
    return _audit_catalog_coherence_snapshot(personas)


def _audit_catalog_coherence_snapshot(
    personas: list[dict[str, Any]],
) -> dict[str, Any]:
    findings: list[dict[str, Any]] = []
    for persona in personas:
        findings.extend(coherence_findings(persona))
    by_rule: Counter[str] = Counter(item["rule"] for item in findings)
    by_severity: Counter[str] = Counter(item["severity"] for item in findings)
    affected = {item["persona_id"] for item in findings}
    contradicting = {
        item["persona_id"] for item in findings if item["severity"] == "contradiction"
    }
    clean = [persona["id"] for persona in personas if persona["id"] not in affected]
    rule_examples: dict[str, str] = {}
    for item in findings:
        rule_examples.setdefault(item["rule"], item["persona_id"])
    report = {
        "schema": COHERENCE_SCHEMA,
        "personas": len(personas),
        "clean": len(clean),
        "affected": len(affected),
        "contradicting": len(contradicting),
        "coherent_ratio": round((len(personas) - len(contradicting)) / len(personas), 4)
        if personas
        else 0.0,
        "findings_total": len(findings),
        "by_severity": {
            severity: by_severity.get(severity, 0) for severity in SEVERITIES
        },
        "by_rule": dict(sorted(by_rule.items(), key=lambda item: (-item[1], item[0]))),
        "rule_examples": dict(sorted(rule_examples.items())),
        # Every persona that contradicts itself, so the list is actionable rather
        # than a count to feel bad about.
        "contradicting_personas": sorted(contradicting),
        "findings": findings,
        "passed": not contradicting,
    }
    return validate_coherence_report(report)


def _claim_vector(persona: dict[str, Any], keys: Iterable[str]) -> tuple:
    expected = persona["identity_contract"]["expected"]
    return tuple(
        (
            key,
            _hashable(expected[key]) if key in expected else _ABSENT_CLAIM,
        )
        for key in keys
    )


def _hashable(value: Any) -> Any:
    if isinstance(value, list):
        return (list, tuple(_hashable(item) for item in value))
    if isinstance(value, dict):
        return (
            dict,
            tuple(sorted((key, _hashable(item)) for key, item in value.items())),
        )
    # Python equates True with 1, whereas a JSON boolean and number are
    # different observed claim values.
    return (type(value), value)


def _entropy(counts: Iterable[int]) -> float:
    values = [count for count in counts if count > 0]
    total = sum(values)
    if total <= 0:
        return 0.0
    result = sum(_entropy_term(count, total) for count in values)
    return 0.0 if result == 0.0 else result


@functools.lru_cache(maxsize=4_096)
def _entropy_term(count: int, total: int) -> float:
    if count <= 0:
        return 0.0
    probability = count / total
    return -probability * math.log2(probability)


def _maximum_entropy_bits(total: int) -> float:
    """Return log2(total) through the shared singleton entropy term."""
    result = total * _entropy_term(1, total) if total else 0.0
    return 0.0 if result == 0.0 else result


def _partition_entropy_bounds(
    total: int,
    free_population: int,
    free_categories: int,
    *,
    fixed_count: int = 0,
) -> tuple[float, float]:
    """Entropy bounds for positive integer buckets without population expansion."""
    fixed_entropy = _entropy_term(fixed_count, total) if fixed_count else 0.0
    if free_categories == 0:
        exact = round(fixed_entropy, 4)
        return exact, exact

    largest = free_population - free_categories + 1
    minimum = fixed_entropy + _entropy_term(largest, total)
    if free_categories > 1:
        minimum += (free_categories - 1) * _entropy_term(1, total)
    quotient, remainder = divmod(free_population, free_categories)
    maximum = (
        fixed_entropy
        + (
            remainder * _entropy_term(quotient + 1, total)
            if remainder
            else 0.0
        )
        + (free_categories - remainder) * _entropy_term(quotient, total)
    )
    return round(minimum, 4), round(maximum, 4)


def _rounded_share_count_bounds(total: int, share: float) -> tuple[int, int] | None:
    """Integer counts whose ratio rounds to one four-decimal report share."""

    lower, upper = 1, total + 1
    while lower < upper:
        middle = (lower + upper) // 2
        if round(middle / total, 4) < share:
            lower = middle + 1
        else:
            upper = middle
    first = lower
    if first > total or round(first / total, 4) != share:
        return None

    lower, upper = first, total + 1
    while lower < upper:
        middle = (lower + upper) // 2
        if round(middle / total, 4) <= share:
            lower = middle + 1
        else:
            upper = middle
    return first, lower - 1


def _capped_partition_entropy_bounds(
    total: int,
    population: int,
    categories: int,
    maximum_count: int,
) -> tuple[float, float] | None:
    """Entropy contribution bounds for positive buckets capped at one count."""

    if categories == 0:
        return (0.0, 0.0) if population == 0 else None
    if not categories <= population <= categories * maximum_count:
        return None

    extra = population - categories
    if maximum_count == 1:
        minimum = categories * _entropy_term(1, total)
    else:
        full, remainder = divmod(extra, maximum_count - 1)
        partial = int(remainder > 0)
        minimum = 0.0
        if full:
            minimum += full * _entropy_term(maximum_count, total)
        if remainder:
            minimum += _entropy_term(1 + remainder, total)
        singletons = categories - full - partial
        if singletons:
            minimum += singletons * _entropy_term(1, total)

    quotient, remainder = divmod(population, categories)
    maximum = (
        (
            remainder * _entropy_term(quotient + 1, total)
            if remainder
            else 0.0
        )
        + (categories - remainder) * _entropy_term(quotient, total)
    )
    return minimum, maximum


def _exact_largest_share_entropy_bounds(
    total: int,
    present: int,
    values: int,
    *,
    maximum_count: int,
    absence_wins: bool,
) -> tuple[float, float] | None:
    absent = total - present
    fixed_entropy = 0.0
    if absent and absence_wins:
        if maximum_count != absent:
            return None
        fixed_entropy = _entropy_term(absent, total)
        partition = _capped_partition_entropy_bounds(
            total, present, values, maximum_count
        )
    else:
        if values < 1 or (absent and maximum_count < absent):
            return None
        fixed_entropy = _entropy_term(maximum_count, total)
        if absent:
            fixed_entropy += _entropy_term(absent, total)
        partition = _capped_partition_entropy_bounds(
            total,
            present - maximum_count,
            values - 1,
            maximum_count,
        )
    if partition is None:
        return None
    return (
        round(fixed_entropy + partition[0], 4),
        round(fixed_entropy + partition[1], 4),
    )


def _present_winner_entropy_bounds(
    total: int,
    present: int,
    values: int,
    *,
    maximum_count_bounds: tuple[int, int],
) -> tuple[float, float] | None:
    """Entropy envelope over every present maximum matching one rounded share."""

    absent = total - present
    minimum_count = max(
        maximum_count_bounds[0],
        absent,
        math.ceil(present / values),
    )
    maximum_count = min(
        maximum_count_bounds[1],
        present - values + 1,
    )
    if minimum_count > maximum_count:
        return None
    minimum_entropy = _exact_largest_share_entropy_bounds(
        total,
        present,
        values,
        maximum_count=maximum_count,
        absence_wins=False,
    )
    maximum_entropy = _exact_largest_share_entropy_bounds(
        total,
        present,
        values,
        maximum_count=minimum_count,
        absence_wins=False,
    )
    if minimum_entropy is None or maximum_entropy is None:
        return None
    return minimum_entropy[0], maximum_entropy[1]


def _anonymity_entropy(anonymity: dict[int, int]) -> float:
    """Evaluate a size histogram without materializing one item per group."""
    total = sum(size * groups for size, groups in anonymity.items())
    if total <= 0:
        return 0.0
    result = sum(
        groups * _entropy_term(size, total)
        for size, groups in anonymity.items()
    )
    return 0.0 if result == 0.0 else result


def _bounded_identity_subset_sums(
    anonymity: dict[int, int], population: int
) -> int | None:
    """Return a compact exact subset-sum bitset for bounded class histograms."""
    if population > _MAX_EXACT_IDENTITY_SUBSET_SUM_POPULATION:
        return None
    reachable = 1
    mask = (1 << (population + 1)) - 1
    for size, groups in anonymity.items():
        chunk = 1
        remaining = groups
        while remaining:
            take = min(chunk, remaining)
            reachable |= reachable << (size * take)
            reachable &= mask
            remaining -= take
            chunk <<= 1
    return reachable


def _bounded_identity_subset_max_groups(
    anonymity: dict[int, int], population: int
) -> list[int] | None:
    """Return the exact maximum class count for each bounded subset sum."""
    if population > _MAX_EXACT_IDENTITY_SUBSET_GROUP_COUNT_POPULATION:
        return None
    maximum_groups = [-1] * (population + 1)
    maximum_groups[0] = 0
    for size, groups in anonymity.items():
        chunk = 1
        remaining = groups
        while remaining:
            take = min(chunk, remaining)
            weight = size * take
            for total in range(population, weight - 1, -1):
                previous = maximum_groups[total - weight]
                if previous >= 0:
                    maximum_groups[total] = max(
                        maximum_groups[total], previous + take
                    )
            remaining -= take
            chunk <<= 1
    return maximum_groups


def _bounded_identity_joint_subset_sums(
    anonymity: dict[int, int], population: int
) -> list[int] | None:
    """Return exact (present, largest-bucket) reachability for a bounded catalog."""
    if population > _MAX_EXACT_IDENTITY_JOINT_SUBSET_POPULATION:
        return None
    reachable = [0] * (population + 1)
    reachable[0] = 1
    for size, groups in anonymity.items():
        for _ in range(groups):
            updated = reachable.copy()
            for present in range(population - size + 1):
                largest_buckets = reachable[present]
                if largest_buckets:
                    updated[present + size] |= largest_buckets
                    updated[present + size] |= largest_buckets << size
            reachable = updated
    return reachable


def _bounded_identity_joint_max_other_groups(
    anonymity: dict[int, int], population: int
) -> list[array] | None:
    """Return exact joint reachability with maximum other-present class counts."""
    if population > _MAX_EXACT_IDENTITY_JOINT_GROUP_COUNT_POPULATION:
        return None
    maximum_other_groups = [
        array("H", [0]) * (population + 1) for _ in range(population + 1)
    ]
    maximum_other_groups[0][0] = 1
    processed = 0
    for size, groups in anonymity.items():
        for _ in range(groups):
            for present in range(processed, -1, -1):
                source = maximum_other_groups[present]
                destination = maximum_other_groups[present + size]
                for largest_bucket in range(present + 1):
                    encoded_count = source[largest_bucket]
                    if not encoded_count:
                        continue
                    destination[largest_bucket] = max(
                        destination[largest_bucket], encoded_count + 1
                    )
                    destination[largest_bucket + size] = max(
                        destination[largest_bucket + size], encoded_count
                    )
            processed += size
    return maximum_other_groups


def _bounded_identity_partition_signatures(
    identity_classes_descending: tuple[int, ...] | None,
    population: int,
    buckets: int,
) -> dict[tuple[int, int, int, bool], int] | None:
    """Enumerate exact small category-load summaries within a state budget."""
    if (
        identity_classes_descending is None
        or population > _MAX_EXACT_IDENTITY_PARTITION_POPULATION
        or len(identity_classes_descending)
        > _MAX_EXACT_IDENTITY_PARTITION_GROUPS
        or buckets > _MAX_EXACT_IDENTITY_PARTITION_BUCKETS
        or buckets < 2
    ):
        return None
    classes = identity_classes_descending
    signatures: dict[tuple[int, int, int, bool], int] = {}
    seen: set[tuple[int, tuple[int, ...]]] = set()
    explored = 0

    def add_signature(
        present: int,
        values: int,
        entropy_units: int,
        absence_wins: bool,
        maximum_count: int,
    ) -> None:
        key = (present, values, entropy_units, absence_wins)
        signatures[key] = signatures.get(key, 0) | (1 << maximum_count)

    def search(index: int, loads: tuple[int, ...]) -> None:
        nonlocal explored
        state = (index, loads)
        if state in seen:
            return
        seen.add(state)
        explored += 1
        if explored > _MAX_EXACT_IDENTITY_PARTITION_STATES:
            raise OverflowError
        if index == len(classes):
            if not loads[-1]:
                return
            entropy_units = round(
                sum(_entropy_term(load, population) for load in loads) * 10_000
            )
            add_signature(
                population,
                buckets,
                entropy_units,
                False,
                loads[0],
            )
            for absent in set(loads):
                present_loads = list(loads)
                present_loads.remove(absent)
                present_maximum = max(present_loads)
                if absent >= present_maximum:
                    add_signature(
                        population - absent,
                        buckets - 1,
                        entropy_units,
                        True,
                        absent,
                    )
                if present_maximum >= absent:
                    add_signature(
                        population - absent,
                        buckets - 1,
                        entropy_units,
                        False,
                        present_maximum,
                    )
            return
        size = classes[index]
        seen_loads: set[int] = set()
        for bucket, load in enumerate(loads):
            if load in seen_loads:
                continue
            seen_loads.add(load)
            updated = list(loads)
            updated[bucket] += size
            search(index + 1, tuple(sorted(updated, reverse=True)))

    try:
        search(0, (0,) * buckets)
    except OverflowError:
        return None
    return signatures


def _minimum_identity_groups_for_count(
    identity_groups_descending: tuple[tuple[int, int], ...], count: int
) -> int:
    """Lower-bound how many available classes can carry a population count."""
    remaining = count
    used = 0
    for size, groups in identity_groups_descending:
        take = min(groups, (remaining + size - 1) // size)
        used += take
        remaining -= take * size
        if remaining <= 0:
            return used
    return used


def _identity_threshold_capacity_holds(
    identity_groups_descending: tuple[tuple[int, int], ...],
    values: int,
    maximum_present_bucket: int,
    absent_count: int,
) -> bool:
    """Whether every class-size threshold fits the field bucket capacities."""
    threshold_identity_groups = 0
    for size, groups in identity_groups_descending:
        threshold_identity_groups += groups
        threshold_capacity = values * (maximum_present_bucket // size)
        if absent_count:
            threshold_capacity += absent_count // size
        if threshold_identity_groups > threshold_capacity:
            return False
    return True


def catalog_uniqueness(
    workspace: Path, *, include_deprecated: bool = False
) -> dict[str, Any]:
    """How many genuinely distinguishable identities the catalog contains.

    Headcount is the number of files; this is the number of identities. Personas
    sharing a claim vector are one identity wearing several names, and the field
    entropies say which claims are doing the separating -- for a catalog that is
    a quality measure, and for reverse engineering it is a map of where the
    identifying signal lives.
    """
    personas = list_personas(workspace, include_deprecated=include_deprecated)
    return _catalog_uniqueness_snapshot(personas)


def _catalog_uniqueness_snapshot(
    personas: list[dict[str, Any]],
) -> dict[str, Any]:
    if not personas:
        return validate_uniqueness_report(
            {
                "schema": UNIQUENESS_SCHEMA,
                "personas": 0,
                "distinct_identities": 0,
                "unique_personas": 0,
                "duplicate_ratio": 0.0,
                "catalog_entropy_bits": 0.0,
                "maximum_entropy_bits": 0.0,
                "anonymity_set_sizes": {},
                "largest_duplicate_group": 0,
                "duplicate_groups": [],
                "duplicate_group_count": 0,
                "fields": [],
                "most_identifying": [],
                "least_identifying": [],
                "passed": False,
            }
        )
    keys = sorted(
        {
            key
            for persona in personas
            for key in persona["identity_contract"]["expected"]
        }
    )
    vectors: dict[tuple, list[str]] = defaultdict(list)
    for persona in personas:
        vectors[_claim_vector(persona, keys)].append(persona["id"])

    duplicate_groups = sorted(
        (
            {
                "size": len(ids),
                "persona_ids": sorted(ids)[:12],
                "truncated": len(ids) > 12,
            }
            for ids in vectors.values()
            if len(ids) > 1
        ),
        key=lambda group: -group["size"],
    )
    anonymity_sizes = Counter(len(ids) for ids in vectors.values())
    unique_personas = sum(len(ids) for ids in vectors.values() if len(ids) == 1)

    fields: list[dict[str, Any]] = []
    for key in keys:
        counts: Counter = Counter()
        present = 0
        for persona in personas:
            expected = persona["identity_contract"]["expected"]
            if key in expected:
                present += 1
                counts[_hashable(expected[key])] += 1
            else:
                counts[_ABSENT_CLAIM] += 1
        bits = _entropy(counts.values())
        top_value, top_count = counts.most_common(1)[0]
        fields.append(
            {
                "claim": key,
                "present_in": present,
                "distinct_values": len(counts) - int(_ABSENT_CLAIM in counts),
                "entropy_bits": round(bits, 4),
                "largest_share": round(top_count / len(personas), 4),
                "most_common_is_absent": top_value is _ABSENT_CLAIM,
            }
        )
    fields.sort(key=lambda item: (-item["entropy_bits"], item["claim"]))
    total_bits = round(_entropy(len(ids) for ids in vectors.values()), 4)
    report = {
        "schema": UNIQUENESS_SCHEMA,
        "personas": len(personas),
        "distinct_identities": len(vectors),
        "unique_personas": unique_personas,
        "duplicate_ratio": round(1 - len(vectors) / len(personas), 4),
        "catalog_entropy_bits": total_bits,
        # log2(N) is the entropy a catalog of N genuinely distinct identities
        # would carry; the gap is what duplication costs.
        "maximum_entropy_bits": round(_maximum_entropy_bits(len(personas)), 4),
        "anonymity_set_sizes": {
            str(size): groups for size, groups in sorted(anonymity_sizes.items())
        },
        "largest_duplicate_group": duplicate_groups[0]["size"]
        if duplicate_groups
        else 1,
        "duplicate_groups": duplicate_groups[:20],
        "duplicate_group_count": len(duplicate_groups),
        "fields": fields,
        "most_identifying": [item["claim"] for item in fields[:8]],
        "least_identifying": [item["claim"] for item in fields[-8:]],
        "passed": not duplicate_groups,
    }
    return validate_uniqueness_report(report)


def catalog_quality_report(
    workspace: Path, *, include_deprecated: bool = False
) -> dict[str, Any]:
    """Coherence and uniqueness together, with the honest headline number.

    ``usable_identities`` is the one figure worth quoting: distinct claim vectors
    that also contradict nothing. It is the only count that survives both
    questions, and it is always smaller than the file count.
    """
    personas = list_personas(workspace, include_deprecated=include_deprecated)
    coherence = _audit_catalog_coherence_snapshot(personas)
    uniqueness = _catalog_uniqueness_snapshot(personas)
    contradicting = set(coherence["contradicting_personas"])
    keys = sorted(
        {
            key
            for persona in personas
            for key in persona["identity_contract"]["expected"]
        }
    )
    coherent_vectors = Counter(
        _claim_vector(persona, keys)
        for persona in personas
        if persona["id"] not in contradicting
    )
    usable_anonymity = Counter(coherent_vectors.values())
    report = {
        "schema": QUALITY_SCHEMA,
        "personas": len(personas),
        "usable_identities": len(coherent_vectors),
        "usable_anonymity_set_sizes": {
            str(size): groups for size, groups in sorted(usable_anonymity.items())
        },
        "coherent_personas": len(personas) - len(contradicting),
        "distinct_identities": uniqueness["distinct_identities"],
        "coherence": {
            key: value for key, value in coherence.items() if key != "findings"
        },
        "uniqueness": {
            key: value for key, value in uniqueness.items() if key != "fields"
        },
        "most_identifying": uniqueness["most_identifying"],
        "passed": coherence["passed"] and uniqueness["passed"],
        "note": _QUALITY_NOTE,
    }
    return validate_catalog_quality_report(report)


def retire_incoherent_personas(
    workspace: Path,
    *,
    dry_run: bool = True,
    minimum_claims: int = 4,
) -> dict[str, Any]:
    """Deprecate active personas that contradict themselves or claim almost nothing.

    Deprecated, never deleted: the record stays auditable, the evidence stays
    content-addressed, and a persona that turns out to have been retired in error
    can be reactivated. What changes is that it stops being counted as inventory,
    which is the honest thing for an identity no one should deploy.

    ``dry_run`` is the default because this is a bulk state change and the count
    is usually a surprise the first time you run it.
    """
    if not isinstance(workspace, Path):
        raise ContractError("persona retirement workspace must be a Path")
    if type(dry_run) is not bool:
        raise ContractError("persona retirement dry-run choice must be boolean")
    if (
        isinstance(minimum_claims, bool)
        or not isinstance(minimum_claims, int)
        or not 0 <= minimum_claims <= 1_000_000
    ):
        raise ContractError("minimum_claims must be a non-negative integer")
    from .personas import load_persona, set_persona_state

    personas = list_personas(workspace)
    contradicting = {
        finding["persona_id"]
        for persona in personas
        for finding in coherence_findings(persona)
        if finding["severity"] == "contradiction"
    }
    reasons: dict[str, str] = {}
    for persona in personas:
        claims = len(persona["identity_contract"]["expected"])
        if persona["id"] in contradicting:
            reasons[persona["id"]] = "contradicts-itself"
        elif claims < minimum_claims:
            reasons[persona["id"]] = f"only-{claims}-claims"
    retired: list[dict[str, Any]] = []
    warnings: list[dict[str, Any]] = []
    failed: list[dict[str, Any]] = []
    if not dry_run:
        index = {persona["id"]: persona for persona in personas}
        for persona_id, reason in sorted(reasons.items()):
            try:
                set_persona_state(
                    workspace,
                    persona_id,
                    "deprecated",
                    expected_sha256=index[persona_id]["integrity_sha256"],
                )
                retired.append({"persona_id": persona_id, "reason": reason})
            except Exception as exc:  # noqa: BLE001 - reconcile each bulk outcome
                receipt = safe_failure_receipt(exc)
                try:
                    current = load_persona(workspace, persona_id)
                except Exception:  # noqa: BLE001 - uncertain state must fail closed
                    raise ContractError(
                        "persona retirement state could not be reconciled"
                    ) from None
                row = {"persona_id": persona_id, "reason": reason}
                if current["state"] == "deprecated":
                    retired.append(row)
                    warnings.append({**row, "error": receipt})
                else:
                    failed.append({**row, "error": receipt})
    by_reason: Counter[str] = Counter(reasons.values())
    report = {
        "schema": RETIREMENT_SCHEMA,
        "dry_run": dry_run,
        "active_before": len(personas),
        "selected": len(reasons),
        "by_reason": dict(sorted(by_reason.items())),
        "retired": retired,
        "retired_count": len(retired),
        "warnings": warnings,
        "warning_count": len(warnings),
        "failed": failed,
        "failed_count": len(failed),
        "active_after": len(personas) - len(retired),
        "sample": [list(item) for item in sorted(reasons.items())[:12]],
        "note": _RETIREMENT_NOTE,
    }
    return validate_retirement_report(report)


def _quality_count(value: Any, label: str) -> int:
    if type(value) is not int or not 0 <= value <= 10_000_000:
        raise ContractError(f"{label} is invalid")
    return value


def _quality_decimal(value: Any, label: str) -> float:
    if (
        type(value) is not float
        or not math.isfinite(value)
        or (value == 0.0 and math.copysign(1.0, value) < 0)
    ):
        raise ContractError(f"{label} is invalid")
    return value


def _quality_has_exact_fields(value: Any, fields: set[str]) -> bool:
    return (
        type(value) is dict
        and len(value) == len(fields)
        and all(type(field) is str for field in value)
        and set(value) == fields
    )


def _quality_text(value: Any, label: str, *, maximum: int = 4096) -> str:
    if (
        type(value) is not str
        or not 1 <= len(value) <= maximum
        or any(ord(character) < 0x20 or ord(character) == 0x7F for character in value)
    ):
        raise ContractError(f"{label} is invalid")
    return value


def _quality_text_sequence(
    value: Any,
    label: str,
    *,
    maximum_items: int,
    maximum_text: int = 4096,
) -> list[str]:
    if type(value) is not list or len(value) > maximum_items:
        raise ContractError(f"{label} is invalid")
    safe = [_quality_text(item, label, maximum=maximum_text) for item in value]
    if len(safe) != len(set(safe)):
        raise ContractError(f"{label} is not unique")
    return safe


def _quality_bounded_text_sequence(
    value: Any,
    label: str,
    *,
    maximum_items: int,
    maximum_text: int = 4096,
) -> list[str]:
    """Validate primitive bounded strings without rescanning known-safe content."""
    if (
        type(value) is not list
        or len(value) > maximum_items
        or any(
            type(item) is not str or not 1 <= len(item) <= maximum_text
            for item in value
        )
    ):
        raise ContractError(f"{label} is invalid")
    safe = list(value)
    if len(safe) != len(set(safe)):
        raise ContractError(f"{label} is not unique")
    return safe


def _record_profile_id_spelling(
    persona_id: str,
    spellings: dict[str, str],
    label: str,
) -> None:
    folded = persona_id.casefold()
    previous = spellings.setdefault(folded, persona_id)
    if previous != persona_id:
        raise ContractError(f"{label} is inconsistent")


def _quality_finding_detail(value: Any) -> dict[str, Any]:
    """Accept only the small, portable diagnostic objects this report emits."""
    label = "persona coherence finding detail"
    if type(value) is not dict:
        raise ContractError(f"{label} is invalid")
    stack: list[tuple[Any, int]] = [(value, 0)]
    nodes = 0
    text_total = 0
    while stack:
        item, depth = stack.pop()
        nodes += 1
        if nodes > _MAX_COHERENCE_DETAIL_NODES or depth > _MAX_COHERENCE_DETAIL_DEPTH:
            raise ContractError(f"{label} is invalid")
        if item is None or type(item) is bool:
            continue
        if type(item) is int:
            if item.bit_length() > _MAX_COHERENCE_DETAIL_INTEGER_BITS:
                raise ContractError(f"{label} is invalid")
            continue
        if type(item) is float:
            if not math.isfinite(item):
                raise ContractError(f"{label} is invalid")
            continue
        if type(item) is str:
            _quality_text(item, label, maximum=_MAX_COHERENCE_DETAIL_TEXT)
            text_total += len(item)
        elif type(item) is list:
            if len(item) > _MAX_COHERENCE_DETAIL_ITEMS:
                raise ContractError(f"{label} is invalid")
            stack.extend((child, depth + 1) for child in item)
        elif type(item) is dict:
            if len(item) > _MAX_COHERENCE_DETAIL_ITEMS:
                raise ContractError(f"{label} is invalid")
            for key, child in item.items():
                _quality_text(key, label, maximum=128)
                text_total += len(key)
                stack.append((child, depth + 1))
        else:
            raise ContractError(f"{label} is invalid")
        if text_total > _MAX_COHERENCE_DETAIL_TEXT_TOTAL:
            raise ContractError(f"{label} is invalid")
    return value


def _quality_rule(value: Any, label: str) -> str:
    rule = _quality_text(value, label, maximum=256)
    if _COHERENCE_RULE_RE.fullmatch(rule) is None:
        raise ContractError(f"{label} is invalid")
    return rule


def _retirement_reason(value: Any) -> str:
    reason = _quality_text(value, "persona retirement reason", maximum=64)
    if reason != "contradicts-itself":
        match = re.fullmatch(r"only-([1-9][0-9]*)-claims", reason)
        if (
            match is None
            or int(match.group(1)) > MAX_IDENTITY_CONTRACT_CLAIMS
        ):
            raise ContractError("persona retirement reason is invalid")
    return reason


def _retirement_rows(
    value: Any,
    *,
    failed: bool,
    profile_id_spellings: dict[str, str],
) -> list[dict[str, Any]]:
    label = "failed" if failed else "retired"
    fields = (
        {"persona_id", "reason", "error"}
        if failed
        else {
            "persona_id",
            "reason",
        }
    )
    if type(value) is not list or len(value) > 10_000_000:
        raise ContractError(f"persona retirement {label} rows are invalid")
    previous = ""
    rows: list[dict[str, Any]] = []
    for index, row in enumerate(value):
        if not _quality_has_exact_fields(row, fields):
            raise ContractError(f"persona retirement {label} row {index} is invalid")
        persona_id = _quality_text(
            row.get("persona_id"), "persona retirement persona ID", maximum=128
        )
        if not is_valid_profile_id(persona_id):
            raise ContractError(f"persona retirement {label} row {index} is invalid")
        _record_profile_id_spelling(
            persona_id,
            profile_id_spellings,
            "persona retirement persona ID spelling",
        )
        _retirement_reason(row.get("reason"))
        if persona_id <= previous:
            raise ContractError(f"persona retirement {label} rows are not ordered")
        previous = persona_id
        if failed:
            error = _quality_text(
                row.get("error"), "persona retirement failure receipt", maximum=80
            )
            if not re.fullmatch(
                r"(?:contract|execution)-failure; diagnostic_sha256_16=[0-9a-f]{16}",
                error,
            ):
                raise ContractError("persona retirement failure receipt is invalid")
        rows.append(row)
    return rows


def validate_retirement_report(report: Any) -> dict[str, Any]:
    """Validate a retirement plan/receipt without trusting copied totals."""
    fields = {
        "schema",
        "dry_run",
        "active_before",
        "selected",
        "by_reason",
        "retired",
        "retired_count",
        "warnings",
        "warning_count",
        "failed",
        "failed_count",
        "active_after",
        "sample",
        "note",
    }
    if not _quality_has_exact_fields(report, fields):
        raise ContractError("persona retirement report fields are invalid")
    if type(report.get("schema")) is not str or report["schema"] != RETIREMENT_SCHEMA:
        raise ContractError("persona retirement report schema is invalid")
    if type(report.get("dry_run")) is not bool:
        raise ContractError("persona retirement dry-run receipt is invalid")
    active_before = _quality_count(
        report.get("active_before"), "persona retirement active-before count"
    )
    selected = _quality_count(report.get("selected"), "persona retirement selection")
    retired_count = _quality_count(
        report.get("retired_count"), "persona retirement retired count"
    )
    failed_count = _quality_count(
        report.get("failed_count"), "persona retirement failure count"
    )
    warning_count = _quality_count(
        report.get("warning_count"), "persona retirement warning count"
    )
    active_after = _quality_count(
        report.get("active_after"), "persona retirement active-after count"
    )
    if selected > active_before or active_after != active_before - retired_count:
        raise ContractError("persona retirement populations are inconsistent")

    by_reason = report.get("by_reason")
    if type(by_reason) is not dict or len(by_reason) > 1_000_001:
        raise ContractError("persona retirement reason counts are invalid")
    reason_counts: dict[str, int] = {}
    for reason, count in by_reason.items():
        reason = _retirement_reason(reason)
        count = _quality_count(count, "persona retirement reason count")
        if count < 1:
            raise ContractError("persona retirement reason count is invalid")
        reason_counts[reason] = count
    if sum(reason_counts.values()) != selected:
        raise ContractError("persona retirement reason counts are inconsistent")

    profile_id_spellings: dict[str, str] = {}
    retired = _retirement_rows(
        report.get("retired"),
        failed=False,
        profile_id_spellings=profile_id_spellings,
    )
    warnings = _retirement_rows(
        report.get("warnings"),
        failed=True,
        profile_id_spellings=profile_id_spellings,
    )
    failures = _retirement_rows(
        report.get("failed"),
        failed=True,
        profile_id_spellings=profile_id_spellings,
    )
    if (
        len(retired) != retired_count
        or len(warnings) != warning_count
        or len(failures) != failed_count
        or warning_count > retired_count
    ):
        raise ContractError("persona retirement outcome counts are inconsistent")
    outcome_ids = [row["persona_id"] for row in retired + failures]
    if len(outcome_ids) != len(set(outcome_ids)):
        raise ContractError("persona retirement outcome IDs are not unique")
    retired_reasons = {row["persona_id"]: row["reason"] for row in retired}
    if any(retired_reasons.get(row["persona_id"]) != row["reason"] for row in warnings):
        raise ContractError("persona retirement warning outcomes are inconsistent")
    if report["dry_run"]:
        if retired or warnings or failures:
            raise ContractError("persona retirement dry-run outcomes are invalid")
    else:
        outcomes = Counter(row["reason"] for row in retired + failures)
        if retired_count + failed_count != selected or outcomes != Counter(
            reason_counts
        ):
            raise ContractError("persona retirement outcomes are incomplete")

    sample = report.get("sample")
    if type(sample) is not list or len(sample) != min(selected, 12):
        raise ContractError("persona retirement sample is invalid")
    safe_sample: list[tuple[str, str]] = []
    for index, row in enumerate(sample):
        if type(row) is not list or len(row) != 2:
            raise ContractError(f"persona retirement sample row {index} is invalid")
        persona_id = _quality_text(
            row[0], "persona retirement sample persona ID", maximum=128
        )
        if not is_valid_profile_id(persona_id):
            raise ContractError(f"persona retirement sample row {index} is invalid")
        _record_profile_id_spelling(
            persona_id,
            profile_id_spellings,
            "persona retirement persona ID spelling",
        )
        reason = _retirement_reason(row[1])
        if reason not in reason_counts:
            raise ContractError("persona retirement sample reason is inconsistent")
        safe_sample.append((persona_id, reason))
    if safe_sample != sorted(safe_sample) or len(
        {row[0] for row in safe_sample}
    ) != len(safe_sample):
        raise ContractError("persona retirement sample is not canonical")
    sample_reasons = Counter(reason for _persona_id, reason in safe_sample)
    if any(
        count > reason_counts.get(reason, 0) for reason, count in sample_reasons.items()
    ):
        raise ContractError("persona retirement sample reason counts are inconsistent")
    if not report["dry_run"]:
        expected_sample = sorted(
            (row["persona_id"], row["reason"]) for row in retired + failures
        )[:12]
        if safe_sample != expected_sample:
            raise ContractError("persona retirement sample is inconsistent")
    if type(report.get("note")) is not str or report["note"] != _RETIREMENT_NOTE:
        raise ContractError("persona retirement note is invalid")
    return report


def validate_coherence_report(report: Any) -> dict[str, Any]:
    fields = {
        "schema",
        "personas",
        "clean",
        "affected",
        "contradicting",
        "coherent_ratio",
        "findings_total",
        "by_severity",
        "by_rule",
        "rule_examples",
        "contradicting_personas",
        "findings",
        "passed",
    }
    if not _quality_has_exact_fields(report, fields):
        raise ContractError("persona coherence report fields are invalid")
    if type(report.get("schema")) is not str or report["schema"] != COHERENCE_SCHEMA:
        raise ContractError("persona coherence report schema is invalid")
    personas = _quality_count(report.get("personas"), "persona coherence population")
    for field in ("clean", "affected", "contradicting", "findings_total"):
        if (
            _quality_count(report.get(field), f"persona coherence {field}") > personas
            and field != "findings_total"
        ):
            raise ContractError(f"persona coherence {field} is inconsistent")
    findings = report.get("findings")
    if type(findings) is not list or len(findings) > 10_000_000:
        raise ContractError("persona coherence findings are invalid")
    safe_findings: list[dict[str, Any]] = []
    profile_id_spellings: dict[str, str] = {}
    seen_finding_rules: set[tuple[str, str]] = set()
    rule_severities: dict[str, str] = {}
    for index, finding in enumerate(findings):
        if not _quality_has_exact_fields(
            finding,
            {"persona_id", "rule", "severity", "summary", "detail"},
        ):
            raise ContractError(f"persona coherence finding {index} is invalid")
        persona_id = _quality_text(
            finding.get("persona_id"), "persona coherence persona ID", maximum=128
        )
        if not is_valid_profile_id(persona_id):
            raise ContractError("persona coherence persona ID is invalid")
        _record_profile_id_spelling(
            persona_id,
            profile_id_spellings,
            "persona coherence persona ID spelling",
        )
        rule = _quality_rule(finding.get("rule"), "persona coherence rule")
        finding_rule = (persona_id.casefold(), rule)
        if finding_rule in seen_finding_rules:
            raise ContractError("persona coherence finding rule is duplicated")
        seen_finding_rules.add(finding_rule)
        severity = _quality_text(
            finding.get("severity"), "persona coherence severity", maximum=32
        )
        if severity not in SEVERITIES:
            raise ContractError("persona coherence severity is invalid")
        previous_severity = rule_severities.setdefault(rule, severity)
        if previous_severity != severity:
            raise ContractError("persona coherence rule severity is inconsistent")
        _quality_text(finding.get("summary"), "persona coherence summary")
        _quality_finding_detail(finding.get("detail"))
        safe_findings.append(finding)
    if report["findings_total"] != len(safe_findings):
        raise ContractError("persona coherence finding count is inconsistent")

    affected = {finding["persona_id"] for finding in safe_findings}
    contradicting = {
        finding["persona_id"]
        for finding in safe_findings
        if finding["severity"] == "contradiction"
    }
    if (
        report["affected"] != len(affected)
        or report["contradicting"] != len(contradicting)
        or report["clean"] != personas - len(affected)
    ):
        raise ContractError("persona coherence populations are inconsistent")
    expected_ratio = (
        round((personas - len(contradicting)) / personas, 4) if personas else 0.0
    )
    ratio = _quality_decimal(
        report.get("coherent_ratio"), "persona coherence ratio"
    )
    if ratio != expected_ratio:
        raise ContractError("persona coherence ratio is inconsistent")
    expected_severity = {
        severity: sum(finding["severity"] == severity for finding in safe_findings)
        for severity in SEVERITIES
    }
    by_severity = report.get("by_severity")
    if (
        type(by_severity) is not dict
        or len(by_severity) != len(SEVERITIES)
        or any(type(severity) is not str for severity in by_severity)
        or set(by_severity) != set(SEVERITIES)
    ):
        raise ContractError("persona coherence severity counts are invalid")
    for severity, count in by_severity.items():
        if _quality_count(count, "persona coherence severity count") > len(
            safe_findings
        ):
            raise ContractError("persona coherence severity count is inconsistent")
    if by_severity != expected_severity:
        raise ContractError("persona coherence severity counts are inconsistent")
    expected_rules = dict(
        sorted(
            Counter(finding["rule"] for finding in safe_findings).items(),
            key=lambda item: (-item[1], item[0]),
        )
    )
    examples: dict[str, str] = {}
    for finding in safe_findings:
        examples.setdefault(finding["rule"], finding["persona_id"])
    by_rule = report.get("by_rule")
    if type(by_rule) is not dict or len(by_rule) > len(safe_findings):
        raise ContractError("persona coherence rule counts are invalid")
    for rule, count in by_rule.items():
        if type(rule) is not str:
            raise ContractError("persona coherence rule counts are invalid")
        _quality_rule(rule, "persona coherence rule")
        if _quality_count(count, "persona coherence rule count") > personas:
            raise ContractError("persona coherence rule count is inconsistent")
    rule_examples = report.get("rule_examples")
    if type(rule_examples) is not dict or len(rule_examples) > len(expected_rules):
        raise ContractError("persona coherence rule examples are invalid")
    for rule, persona_id in rule_examples.items():
        if type(rule) is not str or type(persona_id) is not str:
            raise ContractError("persona coherence rule examples are invalid")
        _quality_rule(rule, "persona coherence rule example")
        _quality_text(
            persona_id, "persona coherence rule example persona ID", maximum=128
        )
        if not is_valid_profile_id(persona_id):
            raise ContractError("persona coherence rule example persona ID is invalid")
        _record_profile_id_spelling(
            persona_id,
            profile_id_spellings,
            "persona coherence persona ID spelling",
        )
    if by_rule != expected_rules or rule_examples != dict(sorted(examples.items())):
        raise ContractError("persona coherence rule counts are inconsistent")
    contradicting_personas = report.get("contradicting_personas")
    if type(contradicting_personas) is not list or any(
        type(persona_id) is not str for persona_id in contradicting_personas
    ):
        raise ContractError("persona coherence contradiction list is invalid")
    contradiction_ids = _quality_text_sequence(
        contradicting_personas,
        "persona coherence contradiction persona ID",
        maximum_items=personas,
        maximum_text=128,
    )
    if any(not is_valid_profile_id(persona_id) for persona_id in contradiction_ids):
        raise ContractError("persona coherence contradiction list is invalid")
    for persona_id in contradiction_ids:
        _record_profile_id_spelling(
            persona_id,
            profile_id_spellings,
            "persona coherence persona ID spelling",
        )
    if contradicting_personas != sorted(contradicting):
        raise ContractError("persona coherence contradiction list is inconsistent")
    if type(report.get("passed")) is not bool or report["passed"] is not (
        not contradicting
    ):
        raise ContractError("persona coherence verdict is inconsistent")
    return report


@normalize_renderer_failures("persona coherence")
def render_coherence(report: dict[str, Any]) -> str:
    """Human-readable coherence summary."""
    report = validate_coherence_report(report)
    lines = [
        f"personas          {report['personas']}",
        f"clean             {report['clean']}",
        f"contradicting     {report['contradicting']}",
        f"coherent ratio    {report['coherent_ratio']:.4f}",
        "",
        "by severity:",
    ]
    for severity in SEVERITIES:
        lines.append(f"  {severity:<16}{report['by_severity'][severity]}")
    lines.append("")
    lines.append("by rule:")
    for rule, count in report["by_rule"].items():
        example = report["rule_examples"].get(rule, "")
        lines.append(f"  {count:>6}  {rule}  (e.g. {example})")
    return "\n".join(lines)


def validate_uniqueness_report(report: Any) -> dict[str, Any]:
    fields = {
        "schema",
        "personas",
        "distinct_identities",
        "unique_personas",
        "duplicate_ratio",
        "catalog_entropy_bits",
        "maximum_entropy_bits",
        "anonymity_set_sizes",
        "largest_duplicate_group",
        "duplicate_groups",
        "duplicate_group_count",
        "fields",
        "most_identifying",
        "least_identifying",
        "passed",
    }
    if not _quality_has_exact_fields(report, fields):
        raise ContractError("persona uniqueness report fields are invalid")
    if type(report.get("schema")) is not str or report["schema"] != UNIQUENESS_SCHEMA:
        raise ContractError("persona uniqueness report schema is invalid")
    personas = _quality_count(report.get("personas"), "persona uniqueness population")
    distinct = _quality_count(
        report.get("distinct_identities"), "persona uniqueness distinct identities"
    )
    unique = _quality_count(
        report.get("unique_personas"), "persona uniqueness unique personas"
    )
    if distinct > personas or unique > personas:
        raise ContractError("persona uniqueness populations are inconsistent")
    anonymity = _quality_anonymity_sets(
        report.get("anonymity_set_sizes"), population=personas
    )
    if (
        sum(anonymity.values()) != distinct
        or sum(size * groups for size, groups in anonymity.items()) != personas
        or anonymity.get(1, 0) != unique
    ):
        raise ContractError("persona uniqueness anonymity arithmetic is inconsistent")
    field_rows = report.get("fields")
    if type(field_rows) is not list or len(field_rows) > 1_000_000:
        raise ContractError("persona uniqueness fields are invalid")
    if bool(field_rows) is not bool(personas):
        raise ContractError("persona uniqueness field population is inconsistent")
    duplicate_count = _validate_duplicate_groups(
        report.get("duplicate_groups"),
        anonymity=anonymity,
        label="persona uniqueness",
    )
    reported_duplicate_count = _quality_count(
        report.get("duplicate_group_count"),
        "persona uniqueness duplicate group count",
    )
    if reported_duplicate_count != duplicate_count:
        raise ContractError("persona uniqueness duplicate group count is inconsistent")
    expected_passed = personas > 0 and duplicate_count == 0
    if (
        type(report.get("passed")) is not bool
        or report["passed"] is not expected_passed
    ):
        raise ContractError("persona uniqueness verdict is inconsistent")
    most_identifying = _quality_bounded_text_sequence(
        report.get("most_identifying"),
        "persona uniqueness identifying claim",
        maximum_items=8,
    )
    least_identifying = _quality_bounded_text_sequence(
        report.get("least_identifying"),
        "persona uniqueness identifying claim",
        maximum_items=8,
    )
    seen_claims: set[str] = set()
    parsed_field_rows: list[tuple[str, int, int, float, float, bool]] = []
    for index, row in enumerate(field_rows):
        if not _quality_has_exact_fields(
            row,
            {
                "claim",
                "present_in",
                "distinct_values",
                "entropy_bits",
                "largest_share",
                "most_common_is_absent",
            },
        ):
            raise ContractError(f"persona uniqueness field {index} is invalid")
        claim = _quality_text(row.get("claim"), "persona uniqueness claim")
        if not is_valid_identity_claim_path(claim):
            raise ContractError("persona uniqueness claim is invalid")
        if claim in seen_claims:
            raise ContractError("persona uniqueness claims are not unique")
        seen_claims.add(claim)
        present = _quality_count(
            row.get("present_in"), "persona uniqueness presence"
        )
        values = _quality_count(
            row.get("distinct_values"), "persona uniqueness distinct values"
        )
        entropy = _quality_decimal(
            row.get("entropy_bits"), f"persona uniqueness field {index} entropy"
        )
        share = _quality_decimal(
            row.get("largest_share"), f"persona uniqueness field {index} share"
        )
        most_common_is_absent = row.get("most_common_is_absent")
        if type(most_common_is_absent) is not bool:
            raise ContractError(f"persona uniqueness field {index} is invalid")
        parsed_field_rows.append(
            (claim, present, values, entropy, share, most_common_is_absent)
        )
    if any(
        claim not in seen_claims
        for claim in (*most_identifying, *least_identifying)
    ):
        raise ContractError("persona uniqueness identifying claim is invalid")
    expected_ratio = round(1 - distinct / personas, 4) if personas else 0.0
    maximum_entropy = round(_maximum_entropy_bits(personas), 4)
    catalog_entropy = round(_anonymity_entropy(anonymity), 4)
    for field, expected in (
        ("duplicate_ratio", expected_ratio),
        ("maximum_entropy_bits", maximum_entropy),
        ("catalog_entropy_bits", catalog_entropy),
    ):
        value = _quality_decimal(report.get(field), f"persona uniqueness {field}")
        if value != expected:
            raise ContractError(f"persona uniqueness {field} is inconsistent")
    largest = max(anonymity, default=0)
    reported_largest = _quality_count(
        report.get("largest_duplicate_group"),
        "persona uniqueness largest duplicate group",
    )
    if reported_largest != largest:
        raise ContractError("persona uniqueness largest group is inconsistent")
    minimum_field_largest_share = round(largest / personas, 4) if personas else 0.0
    identity_group_gcd = math.gcd(*anonymity)
    has_nontrivial_identity_scale = identity_group_gcd > 1
    minimum_identity_group = min(anonymity, default=0)
    identity_groups_descending = tuple(
        sorted(anonymity.items(), reverse=True)
    )
    scaled_personas = personas // identity_group_gcd if personas else 0
    scaled_anonymity = (
        {
            size // identity_group_gcd: groups
            for size, groups in anonymity.items()
        }
        if scaled_personas
        else {}
    )
    validated_field_rows: list[
        tuple[
            str,
            int,
            int,
            float,
            float,
            bool,
            int,
            int,
            int,
            int,
            int,
            tuple[int, int],
            tuple[int, int],
        ]
    ] = []
    share_count_bounds_cache: dict[
        tuple[int, float], tuple[int, int] | None
    ] = {}
    paired_entropy_bounds_cache: dict[
        tuple[bool, int, int, int, int, int],
        tuple[float, float] | None,
    ] = {}
    minimum_identity_groups_cache: dict[int, int] = {}
    partition_entropy_bounds_cache: dict[
        tuple[int, int, int], tuple[float, float]
    ] = {}
    threshold_capacity_cache: dict[tuple[int, int, int], bool] = {}

    def cached_minimum_identity_groups(count: int) -> int:
        if count not in minimum_identity_groups_cache:
            minimum_identity_groups_cache[count] = (
                _minimum_identity_groups_for_count(
                    identity_groups_descending, count
                )
            )
        return minimum_identity_groups_cache[count]

    def cached_partition_entropy_bounds(
        free_population: int,
        free_categories: int,
        *,
        fixed_count: int,
    ) -> tuple[float, float]:
        key = (free_population, free_categories, fixed_count)
        if key not in partition_entropy_bounds_cache:
            partition_entropy_bounds_cache[key] = _partition_entropy_bounds(
                personas,
                free_population,
                free_categories,
                fixed_count=fixed_count,
            )
        return partition_entropy_bounds_cache[key]

    def cached_threshold_capacity_holds(
        field_values: int,
        maximum_present_bucket: int,
        absent_count: int,
    ) -> bool:
        key = (field_values, maximum_present_bucket, absent_count)
        if key not in threshold_capacity_cache:
            threshold_capacity_cache[key] = _identity_threshold_capacity_holds(
                identity_groups_descending,
                field_values,
                maximum_present_bucket,
                absent_count,
            )
        return threshold_capacity_cache[key]

    def cached_share_count_bounds(
        total: int, reported_share: float
    ) -> tuple[int, int] | None:
        key = (total, reported_share)
        if key not in share_count_bounds_cache:
            share_count_bounds_cache[key] = _rounded_share_count_bounds(
                total, reported_share
            )
        return share_count_bounds_cache[key]

    def cached_paired_entropy_bounds(
        total: int,
        field_present: int,
        field_values: int,
        maximum_count_bounds: tuple[int, int],
        *,
        absence_wins: bool,
    ) -> tuple[float, float] | None:
        if absence_wins:
            maximum_count = total - field_present
            key = (
                True,
                total,
                field_present,
                field_values,
                maximum_count,
                maximum_count,
            )
        else:
            key = (
                False,
                total,
                field_present,
                field_values,
                maximum_count_bounds[0],
                maximum_count_bounds[1],
            )
        if key not in paired_entropy_bounds_cache:
            if absence_wins:
                paired_entropy_bounds_cache[key] = (
                    _exact_largest_share_entropy_bounds(
                        total,
                        field_present,
                        field_values,
                        maximum_count=total - field_present,
                        absence_wins=True,
                    )
                )
            else:
                paired_entropy_bounds_cache[key] = (
                    _present_winner_entropy_bounds(
                        total,
                        field_present,
                        field_values,
                        maximum_count_bounds=maximum_count_bounds,
                    )
                )
        return paired_entropy_bounds_cache[key]

    for index, (
        claim,
        present,
        values,
        entropy,
        share,
        most_common_is_absent,
    ) in enumerate(parsed_field_rows):
        scaled_present = present // identity_group_gcd
        if (
            present > personas
            or present < minimum_identity_group
            or 0 < personas - present < minimum_identity_group
            or present % identity_group_gcd != 0
            or not 1 <= values <= present
            or values > present // identity_group_gcd
            or values > present // minimum_identity_group
            or round(entropy, 4) != entropy
            or entropy > catalog_entropy
            or share < minimum_field_largest_share
        ):
            raise ContractError(f"persona uniqueness field {index} is invalid")
        minimum_present_identity_groups = cached_minimum_identity_groups(
            present
        )
        minimum_absent_identity_groups = cached_minimum_identity_groups(
            personas - present
        )
        if (
            max(values, minimum_present_identity_groups)
            + minimum_absent_identity_groups
            > distinct
        ):
            raise ContractError(f"persona uniqueness field {index} is invalid")
        absent_count = personas - present
        absent_category = absent_count > 0
        category_count = values + int(absent_category)
        if category_count < 1 or category_count > distinct:
            raise ContractError(f"persona uniqueness field {index} is invalid")
        minimum_field_entropy, maximum_field_entropy = (
            cached_partition_entropy_bounds(
            present if absent_category else personas,
            values,
            fixed_count=absent_count if absent_category else 0,
            )
        )
        minimum_largest_share = round(
            math.ceil(personas / category_count) / personas, 4
        )
        maximum_largest_share = round(
            (personas - category_count + 1) / personas, 4
        )
        if (
            not minimum_field_entropy <= entropy <= maximum_field_entropy
            or not (minimum_largest_share <= share <= maximum_largest_share)
            or (not absent_category and most_common_is_absent)
            or (present == 0 and not most_common_is_absent)
        ):
            raise ContractError(f"persona uniqueness field {index} is invalid")
        if absent_category and present:
            absence_share = round(absent_count / personas, 4)
            maximum_present_count = present - values + 1
            if most_common_is_absent:
                if (
                    absent_count < math.ceil(present / values)
                    or share != absence_share
                ):
                    raise ContractError(
                        f"persona uniqueness field {index} is invalid"
                    )
            elif (
                maximum_present_count < absent_count
                or share < absence_share
                or share > round(maximum_present_count / personas, 4)
            ):
                raise ContractError(f"persona uniqueness field {index} is invalid")
        share_count_bounds = cached_share_count_bounds(personas, share)
        if share_count_bounds is None:
            raise ContractError(f"persona uniqueness field {index} is invalid")
        scaled_share_count_bounds = (
            cached_share_count_bounds(scaled_personas, share)
            if has_nontrivial_identity_scale
            else share_count_bounds
        )
        if scaled_share_count_bounds is None:
            raise ContractError(f"persona uniqueness field {index} is invalid")
        maximum_share_count = share_count_bounds[1]
        maximum_present_bucket = (
            absent_count if most_common_is_absent else maximum_share_count
        )
        if not cached_threshold_capacity_holds(
            values,
            maximum_present_bucket,
            absent_count,
        ):
            raise ContractError(f"persona uniqueness field {index} is invalid")
        first_divisible_share_count = (
            (share_count_bounds[0] + identity_group_gcd - 1)
            // identity_group_gcd
            * identity_group_gcd
        )
        if first_divisible_share_count > share_count_bounds[1]:
            raise ContractError(f"persona uniqueness field {index} is invalid")
        paired_entropy_bounds = cached_paired_entropy_bounds(
            personas,
            present,
            values,
            share_count_bounds,
            absence_wins=most_common_is_absent,
        )
        if paired_entropy_bounds is None or not (
            paired_entropy_bounds[0] <= entropy <= paired_entropy_bounds[1]
        ):
            raise ContractError(f"persona uniqueness field {index} is invalid")
        if not has_nontrivial_identity_scale:
            scaled_paired_entropy_bounds = paired_entropy_bounds
        else:
            scaled_paired_entropy_bounds = cached_paired_entropy_bounds(
                scaled_personas,
                scaled_present,
                values,
                scaled_share_count_bounds,
                absence_wins=most_common_is_absent,
            )
        if scaled_paired_entropy_bounds is None or not (
            scaled_paired_entropy_bounds[0]
            <= entropy
            <= scaled_paired_entropy_bounds[1]
        ):
            raise ContractError(f"persona uniqueness field {index} is invalid")
        validated_field_rows.append(
            (
                claim,
                present,
                values,
                entropy,
                share,
                most_common_is_absent,
                scaled_present,
                minimum_present_identity_groups,
                minimum_absent_identity_groups,
                absent_count,
                category_count,
                share_count_bounds,
                scaled_share_count_bounds,
            )
        )
    if field_rows != sorted(
        field_rows, key=lambda item: (-item["entropy_bits"], item["claim"])
    ):
        raise ContractError("persona uniqueness field ranking is inconsistent")
    claims = [row["claim"] for row in field_rows]
    if (
        most_identifying != claims[:8]
        or least_identifying != claims[-8:]
    ):
        raise ContractError("persona uniqueness identifying claims are inconsistent")
    total_presence = sum(row[1] for row in validated_field_rows)
    if not (
        personas
        <= total_presence
        <= personas * MAX_IDENTITY_CONTRACT_CLAIMS
    ):
        raise ContractError("persona uniqueness field coverage is inconsistent")
    joint_category_capacity = 1
    for row in validated_field_rows:
        joint_category_capacity = min(
            distinct, joint_category_capacity * row[10]
        )
    if field_rows and joint_category_capacity < distinct:
        raise ContractError("persona uniqueness field identity capacity is inconsistent")
    if not validated_field_rows:
        return report
    if all(row[10] == 1 for row in validated_field_rows):
        return report
    scaled_identity_classes_descending = (
        tuple(
            size // identity_group_gcd
            for size, groups in identity_groups_descending
            for _ in range(groups)
        )
        if 0 < scaled_personas <= _MAX_EXACT_IDENTITY_PARTITION_POPULATION
        else None
    )
    identity_subset_sums = _bounded_identity_subset_sums(anonymity, personas)
    scaled_identity_subset_sums = (
        _bounded_identity_subset_sums(
            scaled_anonymity,
            scaled_personas,
        )
        if (
            identity_subset_sums is None
            and has_nontrivial_identity_scale
            and scaled_personas
        )
        else None
    )
    has_multi_value_field = any(row[2] > 1 for row in validated_field_rows)
    identity_subset_max_groups = (
        _bounded_identity_subset_max_groups(anonymity, personas)
        if has_multi_value_field
        else None
    )
    scaled_identity_subset_max_groups = (
        _bounded_identity_subset_max_groups(
            scaled_anonymity, scaled_personas
        )
        if (
            has_multi_value_field
            and has_nontrivial_identity_scale
            and identity_subset_max_groups is None
            and scaled_personas
        )
        else None
    )
    identity_joint_subset_sums: list[int] | None = None
    scaled_identity_joint_subset_sums: list[int] | None = None
    identity_joint_subset_sums_ready = False
    identity_joint_max_other_groups: list[array] | None = None
    scaled_identity_joint_max_other_groups: list[array] | None = None
    identity_joint_max_other_groups_ready = False
    partition_signature_cache: dict[
        int, dict[tuple[int, int, int, bool], int] | None
    ] = {}
    for index, (
        claim,
        present,
        values,
        entropy,
        share,
        most_common_is_absent,
        scaled_present,
        minimum_present_identity_groups,
        minimum_absent_identity_groups,
        absent_count,
        category_count,
        share_count_bounds,
        scaled_share_count_bounds,
    ) in enumerate(validated_field_rows):
        if (
            (
                identity_subset_sums is not None
                and not (identity_subset_sums >> present) & 1
            )
            or (
                scaled_identity_subset_sums is not None
                and not (scaled_identity_subset_sums >> scaled_present) & 1
            )
            or (
                identity_subset_max_groups is not None
                and values > identity_subset_max_groups[present]
            )
            or (
                scaled_identity_subset_max_groups is not None
                and values
                > scaled_identity_subset_max_groups[scaled_present]
            )
        ):
            raise ContractError(f"persona uniqueness field {index} is invalid")
        absent_category = absent_count > 0
        exact_subset_sums = identity_subset_sums
        exact_subset_present = present
        exact_subset_share_count_bounds = share_count_bounds
        if exact_subset_sums is None and scaled_identity_subset_sums is not None:
            exact_subset_sums = scaled_identity_subset_sums
            exact_subset_present = scaled_present
            exact_subset_share_count_bounds = scaled_share_count_bounds
        if exact_subset_sums is not None:
            share_count_width = (
                exact_subset_share_count_bounds[1]
                - exact_subset_share_count_bounds[0]
                + 1
            )
            reachable_share_counts = (
                exact_subset_sums >> exact_subset_share_count_bounds[0]
            ) & ((1 << share_count_width) - 1)
            if not reachable_share_counts:
                raise ContractError(f"persona uniqueness field {index} is invalid")
            if not most_common_is_absent and not any(
                maximum_count <= exact_subset_present
                and (exact_subset_sums >> maximum_count) & 1
                and (
                    exact_subset_sums
                    >> (exact_subset_present - maximum_count)
                )
                & 1
                for maximum_count in range(
                    exact_subset_share_count_bounds[0],
                    exact_subset_share_count_bounds[1] + 1,
                )
            ):
                raise ContractError(f"persona uniqueness field {index} is invalid")
        exact_subset_max_groups = identity_subset_max_groups
        exact_max_groups_present = present
        exact_max_groups_share_count_bounds = share_count_bounds
        if (
            exact_subset_max_groups is None
            and scaled_identity_subset_max_groups is not None
        ):
            exact_subset_max_groups = scaled_identity_subset_max_groups
            exact_max_groups_present = scaled_present
            exact_max_groups_share_count_bounds = scaled_share_count_bounds
        if (
            exact_subset_max_groups is not None
            and not most_common_is_absent
            and values > 1
        ):
            if not any(
                maximum_count <= exact_max_groups_present
                and exact_subset_max_groups[
                    exact_max_groups_present - maximum_count
                ]
                >= values - 1
                for maximum_count in range(
                    exact_max_groups_share_count_bounds[0],
                    exact_max_groups_share_count_bounds[1] + 1,
                )
            ):
                raise ContractError(f"persona uniqueness field {index} is invalid")
        if (
            not most_common_is_absent
            and values > 1
            and not identity_joint_subset_sums_ready
        ):
            identity_joint_subset_sums = _bounded_identity_joint_subset_sums(
                anonymity, personas
            )
            scaled_identity_joint_subset_sums = (
                _bounded_identity_joint_subset_sums(
                    scaled_anonymity, scaled_personas
                )
                if (
                    identity_joint_subset_sums is None
                    and has_nontrivial_identity_scale
                    and scaled_personas
                )
                else None
            )
            identity_joint_subset_sums_ready = True
        exact_joint_subset_sums = identity_joint_subset_sums
        exact_joint_present = present
        exact_joint_share_count_bounds = share_count_bounds
        if (
            exact_joint_subset_sums is None
            and scaled_identity_joint_subset_sums is not None
        ):
            exact_joint_subset_sums = scaled_identity_joint_subset_sums
            exact_joint_present = scaled_present
            exact_joint_share_count_bounds = scaled_share_count_bounds
        if (
            exact_joint_subset_sums is not None
            and not most_common_is_absent
            and values > 1
        ):
            joint_share_counts = exact_joint_subset_sums[exact_joint_present]
            joint_share_count_width = (
                exact_joint_share_count_bounds[1]
                - exact_joint_share_count_bounds[0]
                + 1
            )
            if not (
                joint_share_counts >> exact_joint_share_count_bounds[0]
            ) & ((1 << joint_share_count_width) - 1):
                raise ContractError(f"persona uniqueness field {index} is invalid")
        if (
            not most_common_is_absent
            and values > 1
            and not identity_joint_max_other_groups_ready
        ):
            identity_joint_max_other_groups = (
                _bounded_identity_joint_max_other_groups(anonymity, personas)
            )
            scaled_identity_joint_max_other_groups = (
                _bounded_identity_joint_max_other_groups(
                    scaled_anonymity, scaled_personas
                )
                if (
                    identity_joint_max_other_groups is None
                    and has_nontrivial_identity_scale
                    and scaled_personas
                )
                else None
            )
            identity_joint_max_other_groups_ready = True
        exact_joint_max_other_groups = identity_joint_max_other_groups
        exact_joint_max_present = present
        exact_joint_max_share_count_bounds = share_count_bounds
        if (
            exact_joint_max_other_groups is None
            and scaled_identity_joint_max_other_groups is not None
        ):
            exact_joint_max_other_groups = (
                scaled_identity_joint_max_other_groups
            )
            exact_joint_max_present = scaled_present
            exact_joint_max_share_count_bounds = scaled_share_count_bounds
        if (
            exact_joint_max_other_groups is not None
            and not most_common_is_absent
            and values > 1
        ):
            if not any(
                exact_joint_max_other_groups[exact_joint_max_present][
                    maximum_count
                ]
                > values - 1
                for maximum_count in range(
                    exact_joint_max_share_count_bounds[0],
                    exact_joint_max_share_count_bounds[1] + 1,
                )
            ):
                raise ContractError(f"persona uniqueness field {index} is invalid")
        if category_count > 1:
            if category_count not in partition_signature_cache:
                partition_signature_cache[category_count] = (
                    _bounded_identity_partition_signatures(
                        scaled_identity_classes_descending,
                        scaled_personas,
                        category_count,
                    )
                )
            partition_signatures = partition_signature_cache[category_count]
            if partition_signatures is not None:
                possible_maximum_counts = partition_signatures.get(
                    (
                        scaled_present,
                        values,
                        round(entropy * 10_000),
                        most_common_is_absent,
                    ),
                    0,
                )
                share_count_width = (
                    scaled_share_count_bounds[1]
                    - scaled_share_count_bounds[0]
                    + 1
                )
                if not (
                    possible_maximum_counts >> scaled_share_count_bounds[0]
                ) & ((1 << share_count_width) - 1):
                    raise ContractError(
                        f"persona uniqueness field {index} is invalid"
                    )
    return report


def _validate_quality_coherence_summary(summary: Any) -> tuple[int, int]:
    fields = {
        "schema",
        "personas",
        "clean",
        "affected",
        "contradicting",
        "coherent_ratio",
        "findings_total",
        "by_severity",
        "by_rule",
        "rule_examples",
        "contradicting_personas",
        "passed",
    }
    if not _quality_has_exact_fields(summary, fields):
        raise ContractError("persona quality coherence summary fields are invalid")
    if type(summary.get("schema")) is not str or summary["schema"] != COHERENCE_SCHEMA:
        raise ContractError("persona quality coherence summary schema is invalid")
    personas = _quality_count(summary.get("personas"), "persona quality population")
    clean = _quality_count(summary.get("clean"), "persona quality clean count")
    affected = _quality_count(summary.get("affected"), "persona quality affected count")
    contradicting = _quality_count(
        summary.get("contradicting"), "persona quality contradiction count"
    )
    findings_total = _quality_count(
        summary.get("findings_total"), "persona quality finding count"
    )
    if (
        clean + affected != personas
        or contradicting > affected
        or affected > findings_total
        or (affected == 0) is not (findings_total == 0)
    ):
        raise ContractError("persona quality coherence populations are inconsistent")
    expected_ratio = (
        round((personas - contradicting) / personas, 4) if personas else 0.0
    )
    ratio = _quality_decimal(
        summary.get("coherent_ratio"), "persona quality coherence ratio"
    )
    if ratio != expected_ratio:
        raise ContractError("persona quality coherence ratio is inconsistent")

    by_severity = summary.get("by_severity")
    if (
        type(by_severity) is not dict
        or any(type(severity) is not str for severity in by_severity)
        or set(by_severity) != set(SEVERITIES)
    ):
        raise ContractError("persona quality severity counts are invalid")
    severity_counts = {
        severity: _quality_count(
            by_severity[severity], f"persona quality {severity} finding count"
        )
        for severity in SEVERITIES
    }
    if (
        sum(severity_counts.values()) != findings_total
        or severity_counts["contradiction"] < contradicting
        or (severity_counts["contradiction"] == 0) is not (contradicting == 0)
    ):
        raise ContractError("persona quality severity counts are inconsistent")

    by_rule = summary.get("by_rule")
    examples = summary.get("rule_examples")
    if (
        type(by_rule) is not dict
        or type(examples) is not dict
        or any(type(rule) is not str for rule in examples)
        or set(by_rule) != set(examples)
        or len(by_rule) > 1_000_000
    ):
        raise ContractError("persona quality rule summary is invalid")
    rule_total = 0
    rule_count_gcd = 0
    largest_rule_counts: list[int] = []
    profile_id_spellings: dict[str, str] = {}
    for rule, count in by_rule.items():
        _quality_rule(rule, "persona quality rule")
        count = _quality_count(count, "persona quality rule count")
        if not 1 <= count <= affected:
            raise ContractError("persona quality rule count is invalid")
        rule_total += count
        rule_count_gcd = math.gcd(rule_count_gcd, count)
        largest_rule_counts.append(count)
        largest_rule_counts.sort(reverse=True)
        del largest_rule_counts[len(SEVERITIES) :]
        example_id = _quality_text(
            examples[rule], "persona quality rule example", maximum=128
        )
        if not is_valid_profile_id(example_id):
            raise ContractError("persona quality rule example is invalid")
        _record_profile_id_spelling(
            example_id,
            profile_id_spellings,
            "persona quality coherence persona ID spelling",
        )
    ordered_severity_counts = sorted(severity_counts.values(), reverse=True)
    severity_capacity_is_valid = all(
        sum(largest_rule_counts[:width])
        <= sum(ordered_severity_counts[:width])
        for width in range(1, len(largest_rule_counts) + 1)
    )
    severity_divisibility_is_valid = rule_count_gcd == 0 or all(
        count % rule_count_gcd == 0 for count in severity_counts.values()
    )
    if (
        rule_total != findings_total
        or not severity_capacity_is_valid
        or not severity_divisibility_is_valid
    ):
        raise ContractError("persona quality rule counts are inconsistent")

    contradiction_ids = _quality_text_sequence(
        summary.get("contradicting_personas"),
        "persona quality contradiction ID",
        maximum_items=personas,
        maximum_text=128,
    )
    if (
        any(not is_valid_profile_id(persona_id) for persona_id in contradiction_ids)
        or len(contradiction_ids) != contradicting
        or contradiction_ids != sorted(contradiction_ids)
    ):
        raise ContractError("persona quality contradiction list is inconsistent")
    for persona_id in contradiction_ids:
        _record_profile_id_spelling(
            persona_id,
            profile_id_spellings,
            "persona quality coherence persona ID spelling",
        )
    if type(summary.get("passed")) is not bool or summary["passed"] is not (
        contradicting == 0
    ):
        raise ContractError("persona quality coherence verdict is inconsistent")
    return personas, contradicting


def _quality_anonymity_sets(raw: Any, *, population: int) -> dict[int, int]:
    # With distinct positive sizes and at least one group of each size, k keys
    # consume at least 1+2+...+k personas. Reject impossible key counts before
    # iterating a hostile compact report.
    maximum_kinds = (math.isqrt(8 * population + 1) - 1) // 2
    if type(raw) is not dict or len(raw) > maximum_kinds:
        raise ContractError("persona quality anonymity sets are invalid")
    anonymity: dict[int, int] = {}
    for raw_size, raw_groups in raw.items():
        if type(raw_size) is str and re.fullmatch(r"[1-9][0-9]{0,7}", raw_size):
            size = int(raw_size)
        else:
            raise ContractError("persona quality anonymity-set size is invalid")
        if size in anonymity or not 1 <= size <= 10_000_000:
            raise ContractError("persona quality anonymity-set size is invalid")
        groups = _quality_count(raw_groups, "persona quality anonymity-set groups")
        if groups < 1:
            raise ContractError("persona quality anonymity-set groups are invalid")
        anonymity[size] = groups
    return anonymity


def _retained_anonymity_is_possible(
    full: dict[int, int], retained: dict[int, int]
) -> bool:
    """Whether retained groups can come from shrinking distinct full groups."""
    full_at_or_above = 0
    retained_at_or_above = 0
    for size in sorted(set(full).union(retained), reverse=True):
        full_at_or_above += full.get(size, 0)
        retained_at_or_above += retained.get(size, 0)
        if retained_at_or_above > full_at_or_above:
            return False
    return True


def _validate_duplicate_groups(
    value: Any,
    *,
    anonymity: dict[int, int],
    label: str,
) -> int:
    duplicate_count = sum(groups for size, groups in anonymity.items() if size > 1)
    if type(value) is not list or len(value) != min(duplicate_count, 20):
        raise ContractError(f"{label} duplicate groups are invalid")
    expected_sizes: list[int] = []
    for size in sorted((size for size in anonymity if size > 1), reverse=True):
        expected_sizes.extend([size] * min(anonymity[size], 20 - len(expected_sizes)))
        if len(expected_sizes) == 20:
            break
    actual_sizes = [
        group.get("size") if type(group) is dict else None for group in value
    ]
    if actual_sizes != expected_sizes:
        raise ContractError(f"{label} duplicate group sizes are inconsistent")

    seen_folded_ids: set[str] = set()
    previous_complete_size: int | None = None
    previous_complete_first = ""
    for index, group in enumerate(value):
        if not _quality_has_exact_fields(
            group, {"size", "persona_ids", "truncated"}
        ):
            raise ContractError(f"{label} duplicate group {index} is invalid")
        size = _quality_count(group.get("size"), f"{label} group size")
        ids = _quality_text_sequence(
            group.get("persona_ids"),
            f"{label} persona ID",
            maximum_items=12,
            maximum_text=128,
        )
        folded_ids = [persona_id.casefold() for persona_id in ids]
        if (
            size < 2
            or len(ids) != min(size, 12)
            or ids != sorted(ids)
            or len(folded_ids) != len(set(folded_ids))
            or not seen_folded_ids.isdisjoint(folded_ids)
            or any(not is_valid_profile_id(persona_id) for persona_id in ids)
            or type(group.get("truncated")) is not bool
            or group["truncated"] is not (size > 12)
        ):
            raise ContractError(f"{label} duplicate group {index} is invalid")
        if size <= 12:
            first_id = min(folded_ids)
            if (
                previous_complete_size == size
                and first_id <= previous_complete_first
            ):
                raise ContractError(f"{label} duplicate group order is invalid")
            previous_complete_size = size
            previous_complete_first = first_id
        else:
            previous_complete_size = None
            previous_complete_first = ""
        seen_folded_ids.update(folded_ids)
    return duplicate_count


def _validate_quality_uniqueness_summary(
    summary: Any,
) -> tuple[int, int, list[str], dict[int, int]]:
    fields = {
        "schema",
        "personas",
        "distinct_identities",
        "unique_personas",
        "duplicate_ratio",
        "catalog_entropy_bits",
        "maximum_entropy_bits",
        "anonymity_set_sizes",
        "largest_duplicate_group",
        "duplicate_groups",
        "duplicate_group_count",
        "most_identifying",
        "least_identifying",
        "passed",
    }
    if not _quality_has_exact_fields(summary, fields):
        raise ContractError("persona quality uniqueness summary fields are invalid")
    if type(summary.get("schema")) is not str or summary["schema"] != UNIQUENESS_SCHEMA:
        raise ContractError("persona quality uniqueness summary schema is invalid")
    personas = _quality_count(summary.get("personas"), "persona quality population")
    distinct = _quality_count(
        summary.get("distinct_identities"), "persona quality distinct identities"
    )
    unique = _quality_count(
        summary.get("unique_personas"), "persona quality unique personas"
    )
    anonymity = _quality_anonymity_sets(
        summary.get("anonymity_set_sizes"), population=personas
    )
    if (
        distinct > personas
        or unique > personas
        or sum(anonymity.values()) != distinct
        or sum(size * groups for size, groups in anonymity.items()) != personas
        or anonymity.get(1, 0) != unique
    ):
        raise ContractError("persona quality uniqueness populations are inconsistent")
    expected_numbers = {
        "duplicate_ratio": round(1 - distinct / personas, 4) if personas else 0.0,
        "catalog_entropy_bits": round(_anonymity_entropy(anonymity), 4),
        "maximum_entropy_bits": round(_maximum_entropy_bits(personas), 4),
    }
    for field, expected in expected_numbers.items():
        value = _quality_decimal(summary.get(field), f"persona quality {field}")
        if value != expected:
            raise ContractError(f"persona quality {field} is inconsistent")
    largest = max(anonymity, default=0)
    duplicate_count = _validate_duplicate_groups(
        summary.get("duplicate_groups"),
        anonymity=anonymity,
        label="persona quality",
    )
    reported_largest = _quality_count(
        summary.get("largest_duplicate_group"),
        "persona quality largest duplicate group",
    )
    reported_duplicate_count = _quality_count(
        summary.get("duplicate_group_count"),
        "persona quality duplicate group count",
    )
    if (
        reported_largest != largest
        or reported_duplicate_count != duplicate_count
    ):
        raise ContractError("persona quality duplicate-group counts are inconsistent")

    rankings: dict[str, list[str]] = {}
    validated_ranking_claims: set[str] = set()
    for field in ("most_identifying", "least_identifying"):
        value = summary.get(field)
        rankings[field] = _quality_bounded_text_sequence(
            value,
            "persona quality identifying claim",
            maximum_items=8,
        )
        for claim in rankings[field]:
            if claim in validated_ranking_claims:
                continue
            safe_claim = _quality_text(
                claim, "persona quality identifying claim"
            )
            if not is_valid_identity_claim_path(safe_claim):
                raise ContractError("persona quality identifying claim is invalid")
            validated_ranking_claims.add(safe_claim)
    if personas == 0:
        if any(rankings.values()):
            raise ContractError("empty persona quality rankings must be empty")
    elif (
        not rankings["most_identifying"]
        or len(rankings["most_identifying"])
        != len(rankings["least_identifying"])
        or (
            len(rankings["most_identifying"]) < 8
            and rankings["most_identifying"] != rankings["least_identifying"]
        )
    ):
        raise ContractError("persona quality ranking cardinality is inconsistent")
    if personas:
        most = rankings["most_identifying"]
        least = rankings["least_identifying"]
        overlap = len(set(most).intersection(least))
        if overlap and most[-overlap:] != least[:overlap]:
            raise ContractError("persona quality ranking overlap is inconsistent")
    expected_passed = personas > 0 and duplicate_count == 0
    if (
        type(summary.get("passed")) is not bool
        or summary["passed"] is not expected_passed
    ):
        raise ContractError("persona quality uniqueness verdict is inconsistent")
    return personas, distinct, rankings["most_identifying"], anonymity


def validate_catalog_quality_report(report: Any) -> dict[str, Any]:
    """Validate the exact combined quality handoff and all derivable totals."""
    fields = {
        "schema",
        "personas",
        "usable_identities",
        "usable_anonymity_set_sizes",
        "coherent_personas",
        "distinct_identities",
        "coherence",
        "uniqueness",
        "most_identifying",
        "passed",
        "note",
    }
    if not _quality_has_exact_fields(report, fields):
        raise ContractError("persona quality report fields are invalid")
    if type(report.get("schema")) is not str or report["schema"] != QUALITY_SCHEMA:
        raise ContractError("persona quality report schema is invalid")
    personas = _quality_count(report.get("personas"), "persona quality population")
    coherence_personas, contradicting = _validate_quality_coherence_summary(
        report.get("coherence")
    )
    (
        uniqueness_personas,
        distinct,
        identifying,
        full_anonymity,
    ) = _validate_quality_uniqueness_summary(report.get("uniqueness"))
    usable = _quality_count(
        report.get("usable_identities"), "persona quality usable identities"
    )
    coherent = _quality_count(
        report.get("coherent_personas"), "persona quality coherent personas"
    )
    usable_anonymity = _quality_anonymity_sets(
        report.get("usable_anonymity_set_sizes"), population=coherent
    )
    headline_distinct = _quality_count(
        report.get("distinct_identities"),
        "persona quality distinct identities",
    )
    if (
        personas != coherence_personas
        or personas != uniqueness_personas
        or coherent != personas - contradicting
        or headline_distinct != distinct
        or sum(usable_anonymity.values()) != usable
        or sum(size * groups for size, groups in usable_anonymity.items()) != coherent
        or usable > distinct
        or not _retained_anonymity_is_possible(full_anonymity, usable_anonymity)
    ):
        raise ContractError("persona quality headline totals are inconsistent")
    headline_identifying = _quality_bounded_text_sequence(
        report.get("most_identifying"),
        "persona quality identifying claim",
        maximum_items=8,
    )
    if headline_identifying != identifying:
        raise ContractError("persona quality identifying claims are inconsistent")
    expected_passed = report["coherence"]["passed"] and report["uniqueness"]["passed"]
    if (
        type(report.get("passed")) is not bool
        or report["passed"] is not expected_passed
    ):
        raise ContractError("persona quality verdict is inconsistent")
    if type(report.get("note")) is not str or report["note"] != _QUALITY_NOTE:
        raise ContractError("persona quality note is invalid")
    return report


@normalize_renderer_failures("persona uniqueness")
def render_uniqueness(report: dict[str, Any]) -> str:
    """Human-readable uniqueness summary."""
    report = validate_uniqueness_report(report)
    lines = [
        f"personas             {report['personas']}",
        f"distinct identities  {report['distinct_identities']}",
        f"unique personas      {report['unique_personas']}",
        f"duplicate ratio      {report['duplicate_ratio']:.4f}",
        f"catalog entropy      {report['catalog_entropy_bits']:.4f} of "
        f"{report['maximum_entropy_bits']:.4f} bits",
        f"largest duplicate    {report['largest_duplicate_group']}",
        "",
        "most identifying claims:",
    ]
    for field in report["fields"][:10]:
        lines.append(
            f"  {field['entropy_bits']:>8.4f} bits  {field['claim']}"
            f"  ({field['distinct_values']} values)"
        )
    return "\n".join(lines)
