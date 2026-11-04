"""Diff the attested build's observable surface against branded Google Chrome.

This is the cheapest external falsifier the project has. Every other identity
check compares Browser Core against rules we wrote; this one compares it against
a browser we did not build, on the same host, in the same context. If a rebuild
or a GN flag change silently re-opens ``navigator.webdriver``, drops the plugin
list, or swaps the WebGL renderer, nothing else in the suite notices and this
does.

Two design points carried over from the measurement that produced it:

**It refuses to report when both runs land on the same build.** The first version
of this check reported a triumphant zero differences because both launches had
actually used Playwright's bundled Chromium -- the probe helper only honours an
executable path for attested kernels. A comparison that cannot fail is worse
than no comparison, so the version check runs first and raises.

**No device preset.** A preset pins the user agent, which would hide the exact
field this is looking for.

The allowlist below is the contract: any field that differs and is *not* listed
is a regression. Adding an entry is a deliberate act that should come with a
measurement and a note, not a convenience.
"""

from __future__ import annotations

import json
import math
import re
import sys
from pathlib import Path
from typing import Any

from .build import _hash_regular_file, load_build_attestation
from .errors import (
    ContractError,
    normalize_renderer_failures,
)

SURFACE_DIFF_SCHEMA = "browser-core.surface-diff/1"
ROOT = Path(__file__).resolve().parents[1]

#: Fields permitted to differ between the attested build and branded Chrome.
#:
#: ``userAgent`` differs because the two are different Chromium majors, and will
#: differ on any host where the pinned build is not exactly the installed stable.
#: This is expected drift, not a defect.
#:
#: ``brands`` differs because our build is unbranded: it reports ``Chromium/<major>``
#: where retail Chrome adds a ``Google Chrome/<major>`` entry. ``is_chrome_branded``
#: requires internal Google assets, so this cannot be closed by building
#: differently, and closing it by patching in the name is a trademark question
#: rather than a technical one. A page reading ``sec-ch-ua`` can separate the two
#: in one line; that limitation is documented rather than papered over.
#: ``audioSum`` differs, and unlike the two above it is a defect rather than a
#: fact of life. The standard offline audio fingerprint -- a triangle oscillator
#: through a dynamics compressor, rendered without a sound card and summed --
#: was measured twice on each of three builds on this host:
#:
#:     attested Browser Core 153 : 124.04347776696522
#:     Playwright Chromium   147 : 124.04347527516074
#:     retail Google Chrome  151 : 124.04347527516074
#:
#: Every value is deterministic across runs. Two stock builds three majors apart
#: agree exactly and ours does not, which rules out version drift: the difference
#: belongs to how *we* build, not to which Chromium we build.
#:
#: Standing hypothesis, untested: our ``args.gn`` sets ``is_debug = false`` but
#: not ``is_official_build = true``, so the build has neither PGO nor full LTO.
#: Both change floating-point code generation, and a few ULPs of drift in the
#: compressor's accumulation loop is exactly the shape that produces. The
#: decisive experiment is a rebuild with ``is_official_build = true`` and a
#: re-measure; it costs a full Chromium build and has not been run.
#:
#: A collector that rounds or hashes this value sees no difference. One that
#: takes the full double separates our build from both stock Chromium and retail
#: Chrome in a single number.
ALLOWED_DIFFERENCES = frozenset({"userAgent", "brands", "audioSum"})

#: Reserved origin for the probe page. ``navigator.userAgentData`` and several
#: other fields are hidden outside a secure context, so the page is served over
#: https from a routed ``.invalid`` host that never touches the network.
PROBE_URL = "https://surface-diff.invalid/"
_PROBE_BODY = b"<!doctype html><title>surface diff</title><body></body>"

#: Identical context for both browsers, and deliberately not a device preset.
PROBE_CONTEXT: dict[str, Any] = {
    "locale": "en-US",
    "timezone_id": "America/Chicago",
    "viewport": {"width": 1280, "height": 720},
}

#: Faces probed for the font surface. A deliberately mixed list: Windows system
#: faces, faces that ship with Office, and five that ship with nothing on Windows
#: (``Helvetica Neue``, ``SF Pro Text``, ``Ubuntu``, ``Roboto``,
#: ``Noto Sans CJK JP``) whose absence is as much a measurement as any presence.
PROBE_FONTS = [
    "Arial", "Arial Black", "Bahnschrift", "Calibri", "Cambria", "Candara",
    "Comic Sans MS", "Consolas", "Constantia", "Corbel", "Courier New",
    "Ebrima", "Franklin Gothic Medium", "Gabriola", "Gadugi", "Georgia",
    "Impact", "Ink Free", "Javanese Text", "Leelawadee UI", "Lucida Console",
    "Lucida Sans Unicode", "Malgun Gothic", "Marlett", "Microsoft Himalaya",
    "Microsoft JhengHei", "Microsoft New Tai Lue", "Microsoft PhagsPa",
    "Microsoft Sans Serif", "Microsoft Tai Le", "Microsoft YaHei",
    "Microsoft Yi Baiti", "MingLiU-ExtB", "Mongolian Baiti", "MS Gothic",
    "MV Boli", "Myanmar Text", "Nirmala UI", "Palatino Linotype",
    "Segoe MDL2 Assets", "Segoe Print", "Segoe Script", "Segoe UI",
    "Segoe UI Emoji", "Segoe UI Historic", "Segoe UI Symbol", "SimSun",
    "Sitka", "Sylfaen", "Symbol", "Tahoma", "Times New Roman", "Trebuchet MS",
    "Verdana", "Webdings", "Wingdings", "Yu Gothic",
    "Helvetica Neue", "SF Pro Text", "Ubuntu", "Roboto", "Noto Sans CJK JP",
]

READ_SURFACE_JS = """(fonts) => {
  const gl = document.createElement('canvas').getContext('webgl');
  const dbg = gl && gl.getExtension('WEBGL_debug_renderer_info');
  const ua = navigator.userAgentData;
  return {
    userAgent: navigator.userAgent,
    brands: ua ? ua.brands.map(b => b.brand + '/' + b.version).join(', ') : null,
    uaPlatform: ua ? ua.platform : null,
    uaMobile: ua ? ua.mobile : null,
    platform: navigator.platform,
    languages: (navigator.languages || []).join(','),
    language: navigator.language,
    maxTouchPoints: navigator.maxTouchPoints,
    hardwareConcurrency: navigator.hardwareConcurrency,
    deviceMemory: navigator.deviceMemory ?? null,
    plugins: navigator.plugins.length,
    pluginNames: Array.from(navigator.plugins).map(p => p.name).join(' | '),
    mimeTypes: navigator.mimeTypes.length,
    pdfViewerEnabled: navigator.pdfViewerEnabled ?? null,
    webdriver: navigator.webdriver,
    screen: [screen.width, screen.height, screen.availWidth, screen.availHeight].join('x'),
    colorDepth: screen.colorDepth,
    pixelDepth: screen.pixelDepth,
    devicePixelRatio: devicePixelRatio,
    timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
    calendar: Intl.DateTimeFormat().resolvedOptions().calendar,
    numberingSystem: Intl.DateTimeFormat().resolvedOptions().numberingSystem,
    glVendor: gl ? gl.getParameter(gl.VENDOR) : null,
    glRenderer: gl ? gl.getParameter(gl.RENDERER) : null,
    glVersion: gl ? gl.getParameter(gl.VERSION) : null,
    glUnmaskedVendor: dbg ? gl.getParameter(dbg.UNMASKED_VENDOR_WEBGL) : null,
    glUnmaskedRenderer: dbg ? gl.getParameter(dbg.UNMASKED_RENDERER_WEBGL) : null,
    glMaxTexture: gl ? gl.getParameter(gl.MAX_TEXTURE_SIZE) : null,
    chromeObject: typeof window.chrome,
    coarsePointer: matchMedia('(pointer: coarse)').matches,
    isSecureContext: isSecureContext,
    jsHeapLimit: (performance.memory || {}).jsHeapSizeLimit ?? null,

    // -- font surface ------------------------------------------------------
    // Two independent readings, because they disagree and the disagreement is
    // itself the finding: `document.fonts.check` answered true for all 62 faces
    // on both builds, including five that are not installed on Windows, because
    // it reports whether a face is *usable* after fallback rather than present.
    // The width comparison finds 56. A collector using the API gets a useless
    // answer; one using measureText gets the real set.
    fontsViaApi: fonts.filter(f => {
      try { return document.fonts.check(`12px "${f}"`); } catch (e) { return false; }
    }).length,
    fontsViaMetrics: (() => {
      const ctx = document.createElement('canvas').getContext('2d');
      const probe = 'mmmmmmmmmmlli WWWWWWW 0123456789';
      const base = {};
      for (const g of ['monospace', 'sans-serif', 'serif']) {
        ctx.font = `72px ${g}`;
        base[g] = ctx.measureText(probe).width;
      }
      return fonts.filter(f => ['monospace', 'sans-serif', 'serif'].some(g => {
        ctx.font = `72px "${f}", ${g}`;
        return ctx.measureText(probe).width !== base[g];
      })).join(' | ');
    })(),
    // Finer than a presence list: two hosts with the same faces installed can
    // still measure them differently.
    fontWidths: (() => {
      const ctx = document.createElement('canvas').getContext('2d');
      const probe = 'mmmmmmmmmmlli WWWWWWW 0123456789';
      return fonts.map(f => {
        ctx.font = `72px "${f}", monospace`;
        return Math.round(ctx.measureText(probe).width * 100) / 100;
      }).join(',');
    })(),

    audioSampleRate: (() => {
      try { const c = new AudioContext(); const n = c.sampleRate; c.close(); return n; }
      catch (e) { return null; }
    })(),
    audioMaxChannels: (() => {
      try { const c = new AudioContext(); const n = c.destination.maxChannelCount; c.close(); return n; }
      catch (e) { return null; }
    })(),
  };
}"""

#: Rendered separately because it is the only asynchronous field.
READ_AUDIO_JS = """() => new Promise(resolve => {
  try {
    const ctx = new OfflineAudioContext(1, 44100, 44100);
    const osc = ctx.createOscillator();
    osc.type = 'triangle';
    osc.frequency.value = 10000;
    const comp = ctx.createDynamicsCompressor();
    comp.threshold.value = -50;
    comp.knee.value = 40;
    comp.ratio.value = 12;
    comp.attack.value = 0;
    comp.release.value = 0.25;
    osc.connect(comp);
    comp.connect(ctx.destination);
    osc.start(0);
    ctx.startRendering().then(buffer => {
      const data = buffer.getChannelData(0);
      let sum = 0;
      for (let i = 4500; i < 5000; i++) sum += Math.abs(data[i]);
      resolve(sum);
    }).catch(() => resolve(null));
  } catch (e) { resolve(null); }
})"""

_SURFACE_FIELDS = frozenset(
    {
        "userAgent", "brands", "uaPlatform", "uaMobile", "platform",
        "languages", "language", "maxTouchPoints", "hardwareConcurrency",
        "deviceMemory", "plugins", "pluginNames", "mimeTypes",
        "pdfViewerEnabled", "webdriver", "screen", "colorDepth", "pixelDepth",
        "devicePixelRatio", "timezone", "calendar", "numberingSystem",
        "glVendor", "glRenderer", "glVersion", "glUnmaskedVendor",
        "glUnmaskedRenderer", "glMaxTexture", "chromeObject", "coarsePointer",
        "isSecureContext", "jsHeapLimit", "fontsViaApi", "fontsViaMetrics",
        "fontWidths", "audioSampleRate", "audioMaxChannels", "audioSum",
    }
)
_SURFACE_BOOLEAN_FIELDS = frozenset(
    {"uaMobile", "pdfViewerEnabled", "webdriver", "coarsePointer", "isSecureContext"}
)
_SURFACE_INTEGER_RANGES = {
    "maxTouchPoints": (0, 1_024),
    "hardwareConcurrency": (1, 65_536),
    "plugins": (0, 100_000),
    "mimeTypes": (0, 100_000),
    "colorDepth": (1, 1_024),
    "pixelDepth": (1, 1_024),
    "glMaxTexture": (1, 2**31 - 1),
    "jsHeapLimit": (1, 2**53),
    "fontsViaApi": (0, len(PROBE_FONTS)),
    "audioMaxChannels": (1, 65_536),
}
_SURFACE_REAL_RANGES = {
    "deviceMemory": (0.125, 2**20),
    "devicePixelRatio": (0.01, 1_024),
    "audioSampleRate": (1, 1_000_000),
    "audioSum": (0, 1_000_000),
}
_SURFACE_NUMBER_FIELDS = frozenset(
    _SURFACE_INTEGER_RANGES | _SURFACE_REAL_RANGES
)
_SURFACE_TEXT_FIELDS = _SURFACE_FIELDS - _SURFACE_BOOLEAN_FIELDS - _SURFACE_NUMBER_FIELDS
_SURFACE_OPTIONALLY_EMPTY_TEXT_FIELDS = frozenset({"pluginNames", "fontsViaMetrics"})
_UA_VERSION_TOKEN = re.compile(
    r"(?<![A-Za-z0-9])(?:HeadlessChrome|Chrome)/"
    r"(?P<major>[1-9][0-9]{0,3})(?:\.(?:0|[1-9][0-9]{0,9})){0,3}"
    r"(?![A-Za-z0-9.])"
)
_UA_MARKER = re.compile(r"(?<![A-Za-z0-9])(?:HeadlessChrome|Chrome)/")
_BROWSER_VERSION = re.compile(
    r"[1-9][0-9]{0,3}(?:\.(?:0|[1-9][0-9]{0,9})){1,3}"
)
_BRAND_MAJOR = re.compile(r"(?:0|[1-9][0-9]{0,3})")
MAX_SURFACE_DOCUMENT_BYTES = 1024 * 1024
MAX_SURFACE_TEXT_BYTES = 256 * 1024


def _validated_observed_surface(value: Any) -> dict[str, Any]:
    if type(value) is not dict or set(value) != _SURFACE_FIELDS:
        raise ContractError("browser surface observation fields are invalid")
    retained: dict[str, Any] = {}
    for field in sorted(_SURFACE_FIELDS):
        item = value[field]
        if field in _SURFACE_BOOLEAN_FIELDS and type(item) is bool:
            retained[field] = item
        elif field in _SURFACE_INTEGER_RANGES and type(item) is int:
            minimum, maximum = _SURFACE_INTEGER_RANGES[field]
            if not minimum <= item <= maximum:
                raise ContractError("browser surface observation number is invalid")
            retained[field] = item
        elif field in _SURFACE_REAL_RANGES and type(item) in {int, float}:
            minimum, maximum = _SURFACE_REAL_RANGES[field]
            if (
                isinstance(item, float)
                and not math.isfinite(item)
                or not minimum <= item <= maximum
            ):
                raise ContractError("browser surface observation number is invalid")
            retained[field] = item
        elif field in _SURFACE_TEXT_FIELDS and isinstance(item, str):
            try:
                encoded = item.encode("utf-8", errors="strict")
            except UnicodeEncodeError:
                raise ContractError("browser surface observation text is invalid") from None
            if len(encoded) > MAX_SURFACE_TEXT_BYTES or any(
                ord(character) < 0x20 or ord(character) == 0x7F for character in item
            ):
                raise ContractError("browser surface observation text is invalid")
            retained[field] = item
        else:
            raise ContractError(
                f"browser surface observation {field} has an invalid value type"
            )

    if any(
        not retained[field]
        for field in _SURFACE_TEXT_FIELDS - _SURFACE_OPTIONALLY_EMPTY_TEXT_FIELDS
    ):
        raise ContractError("browser surface observation text is invalid")
    screen_match = re.fullmatch(r"([1-9][0-9]{0,6})x([1-9][0-9]{0,6})x([1-9][0-9]{0,6})x([1-9][0-9]{0,6})", retained["screen"])
    if screen_match is None:
        raise ContractError("browser surface observation text is invalid")
    screen_width, screen_height, available_width, available_height = (
        int(part) for part in screen_match.groups()
    )
    if available_width > screen_width or available_height > screen_height:
        raise ContractError("browser surface observation text is invalid")

    plugin_names = retained["pluginNames"].split(" | ") if retained["pluginNames"] else []
    if len(plugin_names) != retained["plugins"] or any(not name for name in plugin_names):
        raise ContractError("browser surface observation text is invalid")

    metric_fonts = (
        retained["fontsViaMetrics"].split(" | ")
        if retained["fontsViaMetrics"]
        else []
    )
    expected_metric_fonts = [font for font in PROBE_FONTS if font in set(metric_fonts)]
    if metric_fonts != expected_metric_fonts:
        raise ContractError("browser surface observation text is invalid")

    font_widths = retained["fontWidths"].split(",")
    if len(font_widths) != len(PROBE_FONTS):
        raise ContractError("browser surface observation text is invalid")
    for width in font_widths:
        if re.fullmatch(r"(?:0|[1-9][0-9]*)(?:\.[0-9]+)?", width) is None:
            raise ContractError("browser surface observation text is invalid")
        if not 0 < float(width) <= 1_000_000:
            raise ContractError("browser surface observation text is invalid")
    try:
        encoded_document = json.dumps(
            retained,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError):
        raise ContractError("browser surface observation is not strict JSON") from None
    if len(encoded_document) > MAX_SURFACE_DOCUMENT_BYTES:
        raise ContractError("browser surface observation exceeds the byte limit")
    return retained


def compare_surfaces(
    core: dict[str, Any],
    branded: dict[str, Any],
    *,
    core_version: str,
    branded_version: str,
) -> dict[str, Any]:
    """Compare two observed surfaces and grade the differences.

    Raises ``ContractError`` when the two versions match or their observed
    client-hint brands do not identify the intended comparison references.
    """
    core = _validated_observed_surface(core)
    branded = _validated_observed_surface(branded)
    for version in (core_version, branded_version):
        if (
            not isinstance(version, str)
            or not 1 <= len(version) <= 128
            or any(ord(character) < 0x21 or ord(character) > 0x7E for character in version)
        ):
            raise ContractError("surface diff needs a bounded ASCII version from each build")
        if _BROWSER_VERSION.fullmatch(version) is None:
            raise ContractError("browser surface reference version is invalid")
    if core_version == branded_version:
        raise ContractError("refusing to report: both runs landed on the same build")

    def reference_brands(value: str, label: str) -> dict[str, str]:
        entries = value.split(", ")
        if not 1 <= len(entries) <= 16:
            raise ContractError(f"{label} surface reference has inconsistent brands")
        parsed: dict[str, str] = {}
        for entry in entries:
            name, separator, version = entry.rpartition("/")
            if (
                not separator or not name or name != name.strip()
                or "," in name or "/" in name
                or _BRAND_MAJOR.fullmatch(version) is None
                or name in parsed
            ):
                raise ContractError(f"{label} surface reference has inconsistent brands")
            parsed[name] = version
        return parsed

    core_major = core_version.partition(".")[0]
    branded_major = branded_version.partition(".")[0]
    core_brands = reference_brands(core["brands"], "Browser Core")
    branded_brands = reference_brands(branded["brands"], "branded Chrome")
    # A different version does not prove that the comparison used retail Chrome.
    # These are observed product claims, not signatures of the binaries.
    if core_brands.get("Chromium") != core_major or "Google Chrome" in core_brands:
        raise ContractError("Browser Core surface reference has inconsistent brands")
    if (branded_brands.get("Chromium") != branded_major
            or branded_brands.get("Google Chrome") != branded_major):
        raise ContractError("branded Chrome surface reference has inconsistent brands")
    for observed, major in ((core, core_major), (branded, branded_major)):
        agent = observed["userAgent"]
        matches = list(_UA_VERSION_TOKEN.finditer(agent))
        if (len(matches) != 1 or len(_UA_MARKER.findall(agent)) != 1
                or matches[0].group("major") != major):
            raise ContractError("browser surface reference user agent major is inconsistent")

    identical: list[str] = []
    differing: list[str] = []
    for field in sorted(set(core) | set(branded)):
        (identical if core.get(field) == branded.get(field) else differing).append(field)

    unexpected = [field for field in differing if field not in ALLOWED_DIFFERENCES]
    return {
        "schema": SURFACE_DIFF_SCHEMA,
        "core_version": core_version,
        "branded_version": branded_version,
        "fields": len(identical) + len(differing),
        "identical": identical,
        "differing": differing,
        "unexpected": unexpected,
        "passed": not unexpected,
    }


def read_surface(executable: Path) -> tuple[str, dict[str, Any]]:
    """Launch one binary and read the observable surface from a secure context."""
    if not isinstance(executable, Path):
        raise ContractError("browser surface executable path must be a Path")
    binding_before = _hash_regular_file(
        executable,
        label="browser surface executable",
    )

    from playwright.sync_api import sync_playwright

    try:
        with sync_playwright() as p:
            browser: Any | None = None
            context: Any | None = None
            try:
                browser = p.chromium.launch(executable_path=str(executable))
                version = browser.version
                context = browser.new_context(**PROBE_CONTEXT)
                context.route(
                    f"{PROBE_URL}**",
                    lambda route: route.fulfill(
                        status=200,
                        content_type="text/html; charset=utf-8",
                        body=_PROBE_BODY,
                    ),
                )
                page = context.new_page()
                page.goto(PROBE_URL, wait_until="domcontentloaded")
                observed = page.evaluate(READ_SURFACE_JS, PROBE_FONTS)
                if not isinstance(observed, dict):
                    raise ContractError(
                        "browser surface observation fields are invalid"
                    )
                observed["audioSum"] = page.evaluate(READ_AUDIO_JS)
                observed = _validated_observed_surface(observed)
            finally:
                cleanup_failures: list[str] = []
                if context is not None:
                    try:
                        context.close()
                    except Exception:  # noqa: BLE001 - normalized owned cleanup
                        cleanup_failures.append("context-close")
                if browser is not None:
                    try:
                        browser.close()
                    except Exception:  # noqa: BLE001 - normalized owned cleanup
                        cleanup_failures.append("browser-close")
                if cleanup_failures:
                    cleanup_error = ContractError(
                        "browser surface observation cleanup failed ("
                        + ",".join(cleanup_failures)
                        + ")"
                    )
                    active_error = sys.exc_info()[1]
                    if active_error is not None:
                        raise cleanup_error from active_error
                    raise cleanup_error from None
    except ContractError:
        raise
    except Exception as exc:  # noqa: BLE001 - normalize Playwright diagnostics
        raise ContractError(
            f"browser surface observation failed ({type(exc).__name__})"
        ) from None
    if (
        not isinstance(version, str)
        or not 1 <= len(version) <= 128
        or any(ord(character) < 0x21 or ord(character) > 0x7E for character in version)
        or _BROWSER_VERSION.fullmatch(version) is None
    ):
        raise ContractError("browser surface version is invalid")
    if _hash_regular_file(executable, label="browser surface executable") != binding_before:
        raise ContractError("browser surface executable changed during observation")
    return version, observed


def diff_against_branded_chrome(core_executable: Path, branded_executable: Path) -> dict[str, Any]:
    """Run both binaries and grade the result. The whole gate, in one call."""
    if not isinstance(core_executable, Path) or not isinstance(branded_executable, Path):
        raise ContractError("surface diff executable paths must be Paths")
    attestation = load_build_attestation(ROOT, core_executable)
    core_version, core = read_surface(core_executable)
    branded_version, branded = read_surface(branded_executable)
    if load_build_attestation(ROOT, core_executable) != attestation:
        raise ContractError("Browser Core build attestation changed during surface diff")
    result = compare_surfaces(
        core, branded, core_version=core_version, branded_version=branded_version
    )
    result["core_build"] = {
        "chromium_revision": attestation["chromium_revision"],
        "executable_sha256_16": attestation["executable_sha256"][:16],
        "runtime_bundle_sha256_16": attestation["runtime_bundle_sha256"][:16],
    }
    return result


_SURFACE_REPORT_FIELDS = frozenset(
    {
        "schema",
        "core_version",
        "branded_version",
        "fields",
        "identical",
        "differing",
        "unexpected",
        "passed",
    }
)


def _validated_surface_diff_report(report: Any) -> dict[str, Any]:
    if type(report) is not dict or frozenset(report) not in {
        _SURFACE_REPORT_FIELDS,
        _SURFACE_REPORT_FIELDS | {"core_build"},
    }:
        raise ContractError("rendered browser surface diff structure is invalid")
    if report.get("schema") != SURFACE_DIFF_SCHEMA:
        raise ContractError("rendered browser surface diff schema is invalid")
    for field in ("core_version", "branded_version"):
        version = report.get(field)
        if (
            not isinstance(version, str)
            or not 1 <= len(version) <= 128
            or any(ord(character) < 0x21 or ord(character) > 0x7E for character in version)
            or _BROWSER_VERSION.fullmatch(version) is None
        ):
            raise ContractError("rendered browser surface diff structure is invalid")
    if report["core_version"] == report["branded_version"]:
        raise ContractError("rendered browser surface diff structure is invalid")
    if (
        isinstance(report.get("fields"), bool)
        or not isinstance(report.get("fields"), int)
        or report["fields"] != len(_SURFACE_FIELDS)
    ):
        raise ContractError("rendered browser surface diff structure is invalid")

    projected: dict[str, list[str]] = {}
    for field in ("identical", "differing", "unexpected"):
        values = report.get(field)
        if (
            type(values) is not list
            or len(values) > len(_SURFACE_FIELDS)
            or any(type(value) is not str or value not in _SURFACE_FIELDS for value in values)
            or values != sorted(values)
            or len(values) != len(set(values))
        ):
            raise ContractError("rendered browser surface diff structure is invalid")
        projected[field] = values

    identical = projected["identical"]
    differing = projected["differing"]
    if set(identical) & set(differing) or set(identical) | set(differing) != _SURFACE_FIELDS:
        raise ContractError("rendered browser surface diff structure is invalid")
    expected_unexpected = [
        field for field in differing if field not in ALLOWED_DIFFERENCES
    ]
    if projected["unexpected"] != expected_unexpected:
        raise ContractError("rendered browser surface diff structure is invalid")
    if type(report.get("passed")) is not bool or report["passed"] is not (
        not expected_unexpected
    ):
        raise ContractError("rendered browser surface diff structure is invalid")

    if "core_build" in report:
        core_build = report["core_build"]
        if type(core_build) is not dict or set(core_build) != {
            "chromium_revision",
            "executable_sha256_16",
            "runtime_bundle_sha256_16",
        }:
            raise ContractError("rendered browser surface diff structure is invalid")
        if not isinstance(core_build.get("chromium_revision"), str) or not re.fullmatch(
            r"[0-9a-f]{40}", core_build["chromium_revision"]
        ):
            raise ContractError("rendered browser surface diff structure is invalid")
        for field in ("executable_sha256_16", "runtime_bundle_sha256_16"):
            if not isinstance(core_build.get(field), str) or not re.fullmatch(
                r"[0-9a-f]{16}", core_build[field]
            ):
                raise ContractError("rendered browser surface diff structure is invalid")
    return report


@normalize_renderer_failures("browser surface diff")
def render_surface_diff(report: dict[str, Any]) -> str:
    report = _validated_surface_diff_report(report)
    lines = [
        f"Browser Core side (reported) : {report['core_version']}",
        f"Chrome reference (reported) : {report['branded_version']}",
        "",
        f"{len(report['identical'])} of {report['fields']} fields identical",
    ]
    if report["differing"]:
        lines.append("")
        lines.append("differing:")
        for field in report["differing"]:
            note = "allowed" if field in ALLOWED_DIFFERENCES else "UNEXPECTED"
            lines.append(f"  {field} ({note})")
    lines.append("")
    lines.append("PASS" if report["passed"] else f"FAIL: {len(report['unexpected'])} unexpected")
    return "\n".join(lines)
