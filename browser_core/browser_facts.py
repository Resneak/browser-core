"""Redaction-safe browser-fact snapshots for offline / browserless RE.

These snapshots intentionally exclude cookies, sensors, challenge tokens, and
request bodies. They capture ordinary browser environment facts that product
constructors (e.g. akamai-web browserless) need as inputs.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .control_files import (
    decode_strict_json_bytes,
    publish_bytes_exclusive_result,
    read_bounded_control_snapshot_result,
)
from .contracts import ContractError, reject_sensitive_keys
from .numeric import is_finite_number
from .owned_paths import prepare_owned_directory_parent


BROWSER_FACT_SCHEMA = "browser-core.browser-fact-snapshot/1"
MAX_SNAPSHOT_BYTES = 64 * 1024
MAX_SNAPSHOT_SOURCE_BYTES = 1024 * 1024
SNAPSHOT_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


class _BrowserFactTimeout(ContractError):
    pass


def _remaining_capture_time(deadline: float) -> float:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise _BrowserFactTimeout("browser-fact session capture timed out")
    return remaining


def _collect_ready_browser_facts(collect: Any, ready: Any, deadline: float) -> dict[str, Any]:
    """Wait only for the observed startup race; never fill in guessed geometry."""
    observed = collect()
    while True:
        if not isinstance(observed, dict):
            raise ContractError("browser-fact session collector returned a non-object")
        window = observed.get("window")
        dimensions = [window.get(key) for key in (
            "inner_width", "inner_height", "outer_width", "outer_height"
        )] if isinstance(window, dict) else []
        pending = (len(dimensions) == 4
                   and all(type(value) is int and 0 <= value <= 100000 for value in dimensions)
                   and 0 in dimensions)
        if not pending:
            return observed
        # Poll only four cheap layout getters. Recreating WebGL contexts in a
        # rapid full-collector loop would change the experiment being measured.
        while True:
            time.sleep(min(0.05, _remaining_capture_time(deadline)))
            _remaining_capture_time(deadline)
            is_ready = ready()
            if type(is_ready) is not bool:
                raise ContractError("browser-fact window readiness returned a non-boolean")
            if is_ready:
                observed = collect()
                break


# Forbidden even if nested — keep snapshot safe for offline constructor input.
FORBIDDEN_FACT_FRAGMENTS = frozenset(
    {
        "abck",
        "bm_sz",
        "sensor",
        "cookie",
        "authorization",
        "password",
        "proxy",
        "secret",
        "token",
        "private-key",
        "request-body",
        "set-cookie",
    }
)

# B11 / residual R04. The observed Akamai BM web SBSD collector calls
# SpeechSynthesis.getVoices() and reads lang, localService, and voiceURI per voice,
# so the installed voice set is a real constructor input rather than a dashboard
# nicety. Browser Eval reports `speech_voice_languages_well_formed` as *unavailable*
# whenever the list is empty, which conflates two different states: "the check did
# not run" and "the API is present and the OS genuinely reports zero voices".
#
# This records the distinction as evidence. It deliberately does NOT synthesise a
# voice list: the collector reads localService and voiceURI per voice, so a
# fabricated list must be internally consistent with the claimed OS to be worth
# anything, and an inconsistent fake is a worse signal than an honest zero.
_SPEECH_JS = """() => {
  const api = typeof window.speechSynthesis === 'object'
    && window.speechSynthesis !== null
    && typeof window.speechSynthesis.getVoices === 'function';
  if (!api) {
    return { api_present: false, voice_count: 0, languages: [],
             local_service_count: 0, default_count: 0 };
  }
  try {
    const reported = window.speechSynthesis.getVoices();
    if (!Array.isArray(reported)) return null;
    const voices = Array.from(reported);
    const languages = Array.from(
      new Set(voices.map((voice) => String(voice.lang || '')).filter(Boolean))
    ).sort();
    return {
      api_present: true,
      voice_count: voices.length,
      languages: languages.slice(0, 64),
      local_service_count: voices.filter((voice) => voice.localService === true).length,
      default_count: voices.filter((voice) => voice.default === true).length,
    };
  } catch (_error) {
    // A failed read is unavailable evidence, not an observed empty list.
    return null;
  }
}"""

_COLLECT_JS = (
    """() => {
  const speechObservation = """
    + _SPEECH_JS
    + """;
  const glContext = (kind) => {
    try {
      const canvas = document.createElement('canvas');
      const gl = canvas.getContext(kind);
      if (!gl) return { vendor: null, renderer: null, version: null };
      const debug = gl.getExtension('WEBGL_debug_renderer_info');
      return {
        vendor: debug ? gl.getParameter(debug.UNMASKED_VENDOR_WEBGL) : gl.getParameter(gl.VENDOR),
        renderer: debug ? gl.getParameter(debug.UNMASKED_RENDERER_WEBGL) : gl.getParameter(gl.RENDERER),
        version: gl.getParameter(gl.VERSION),
      };
    } catch (_error) {
      return { vendor: null, renderer: null, version: null };
    }
  };
  const uaData = navigator.userAgentData;
  const brands = uaData && uaData.brands
    ? Array.from(uaData.brands, (item) => ({ brand: String(item.brand || ''), version: String(item.version || '') }))
    : null;
  return {
    ua: navigator.userAgent,
    app_version: navigator.appVersion || null,
    platform: navigator.platform,
    language: navigator.language,
    languages: Array.from(navigator.languages || []),
    hardware_concurrency: navigator.hardwareConcurrency ?? null,
    device_memory: navigator.deviceMemory ?? null,
    max_touch_points: navigator.maxTouchPoints ?? null,
    plugins_length: navigator.plugins ? navigator.plugins.length : null,
    mime_types_length: navigator.mimeTypes ? navigator.mimeTypes.length : null,
    pdf_viewer_enabled: navigator.pdfViewerEnabled ?? null,
    webdriver: navigator.webdriver === true,
    timezone: Intl.DateTimeFormat().resolvedOptions().timeZone || null,
    locale: Intl.DateTimeFormat().resolvedOptions().locale || null,
    screen: {
      width: screen.width,
      height: screen.height,
      avail_width: screen.availWidth,
      avail_height: screen.availHeight,
      color_depth: screen.colorDepth,
      pixel_depth: screen.pixelDepth,
    },
    window: {
      inner_width: window.innerWidth,
      inner_height: window.innerHeight,
      outer_width: window.outerWidth,
      outer_height: window.outerHeight,
      device_pixel_ratio: window.devicePixelRatio,
    },
    webgl: {
      webgl1: glContext('webgl'),
      webgl2: glContext('webgl2'),
    },
    client_hints: uaData ? {
      brands: brands,
      mobile: uaData.mobile === true,
      platform: uaData.platform || null,
    } : null,
    automation: {
      webdriver: navigator.webdriver === true,
      chrome_object: typeof window.chrome === 'object',
    },
    speech: speechObservation(),
  };
}"""
)

# Voice lists populate asynchronously on Windows/Chromium. Poll a bounded number of
# times before recording an empty list so "empty" means observed-empty, not
# observed-too-early.
SPEECH_POLL_ATTEMPTS = 6
SPEECH_POLL_INTERVAL_SECONDS = 0.25
_WINDOW_READY_JS = (
    "Boolean(window.innerWidth > 0 && window.innerHeight > 0 && "
    "window.outerWidth > 0 && window.outerHeight > 0)"
)
_SPEECH_OBSERVATION_FIELDS = frozenset(
    {
        "api_present",
        "voice_count",
        "languages",
        "local_service_count",
        "default_count",
    }
)


def _is_speech_shaped(candidate: dict[str, Any]) -> bool:
    return (
        isinstance(candidate.get("api_present"), bool)
        and isinstance(candidate.get("voice_count"), int)
        and not isinstance(candidate.get("voice_count"), bool)
    )


def _empty_speech_observation() -> dict[str, Any]:
    return {
        "api_present": False,
        "voice_count": 0,
        "languages": [],
        "local_service_count": 0,
        "default_count": 0,
    }


def poll_speech_observation(
    evaluate: Any,
    *,
    attempts: int = SPEECH_POLL_ATTEMPTS,
    interval_seconds: float = SPEECH_POLL_INTERVAL_SECONDS,
    sleep: Any = None,
) -> dict[str, Any] | None:
    """Re-read the voice list until it is non-empty or the bounded budget is spent.

    ``evaluate`` is a zero-argument callable returning the raw ``_SPEECH_JS`` result.
    The returned observation records how hard we looked, so a consumer can tell an OS
    with no voices from a probe that gave up early.

    Returns ``None`` when a reading fails, including after an earlier empty
    reading. That is deliberately different from an observation reporting zero
    voices after the bounded poll: "we could not finish looking" and "we looked
    and there are none" are different facts.
    """
    import time as _time

    if (
        isinstance(attempts, bool)
        or not isinstance(attempts, int)
        or not 1 <= attempts <= 100
    ):
        raise ContractError("speech poll attempts must be an integer in [1, 100]")
    if not is_finite_number(interval_seconds) or not 0 <= interval_seconds <= 5:
        raise ContractError("speech poll interval must be a finite number in [0, 5]")
    sleeper = sleep if sleep is not None else _time.sleep
    if not callable(evaluate) or not callable(sleeper):
        raise ContractError("speech poll evaluate and sleep hooks must be callable")
    observation: dict[str, Any] | None = None
    used = 0
    for index in range(attempts):
        used = index + 1
        try:
            candidate = evaluate()
        except _BrowserFactTimeout:
            raise
        except Exception:  # noqa: BLE001 - an unreadable probe is recorded, not fatal
            return None
        # Only accept a speech-shaped response. Anything else means the probe did
        # not run what we asked, and inventing a voice record from it would be worse
        # than recording that we could not read one.
        if (
            not isinstance(candidate, dict)
            or set(candidate) != _SPEECH_OBSERVATION_FIELDS
            or not _is_speech_shaped(candidate)
            or not isinstance(candidate.get("languages"), list)
            or len(candidate["languages"]) > 64
        ):
            return None
        try:
            _validate_speech_facts(candidate)
            retained = decode_strict_json_bytes(
                _canonical(candidate),
                label="speech observation",
            )
            checked = _validate_speech_facts(retained)
        except ContractError:
            return None
        if observation is not None and observation["api_present"] != checked["api_present"]:
            return None
        observation = checked
        if not observation.get("api_present"):
            break
        if observation.get("voice_count"):
            break
        if index + 1 < attempts:
            sleeper(interval_seconds)
    if observation is None:
        return None
    result = dict(observation)
    result["poll_attempts"] = used
    result["poll_budget_ms"] = int(
        round(interval_seconds * 1000 * max(attempts - 1, 0))
    )
    # The whole point of B11: say which of the two empty states this is.
    result["voices_observed_empty"] = bool(
        result.get("api_present") and not result.get("voice_count")
    )
    return result


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _canonical(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8", errors="strict")
    except (RecursionError, TypeError, UnicodeEncodeError, ValueError):
        raise ContractError("browser-fact value is not strict bounded JSON") from None


def _reject_forbidden_fragments(value: Any, *, _depth: int = 0) -> None:
    if _depth > 64:
        raise ContractError("browser-fact nesting limit exceeded")
    if isinstance(value, dict):
        for key, child in value.items():
            lowered = str(key).strip().lower().replace("_", "-")
            if lowered in FORBIDDEN_FACT_FRAGMENTS or any(
                part in lowered for part in FORBIDDEN_FACT_FRAGMENTS
            ):
                raise ContractError("forbidden browser-fact field")
            _reject_forbidden_fragments(child, _depth=_depth + 1)
    elif isinstance(value, list):
        for child in value:
            _reject_forbidden_fragments(child, _depth=_depth + 1)


def _require_text(value: Any, label: str, *, maximum: int = 1024) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise ContractError(f"{label} must be non-empty bounded UTF-8 text")
    try:
        encoded = value.encode("utf-8", errors="strict")
    except UnicodeEncodeError:
        raise ContractError(f"{label} must be non-empty bounded UTF-8 text") from None
    if len(encoded) > maximum or any(
        ord(character) < 32 or ord(character) == 127 for character in value
    ):
        raise ContractError(f"{label} must be non-empty bounded UTF-8 text")
    return value


def _require_int(
    value: Any, label: str, *, minimum: int = 0, maximum: int = 100_000
) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not minimum <= value <= maximum
    ):
        raise ContractError(f"{label} must be an integer in [{minimum}, {maximum}]")
    return value


def _require_number(value: Any, label: str, *, minimum: float, maximum: float) -> float:
    if type(value) not in {int, float}:
        raise ContractError(f"{label} must be a number")
    if not is_finite_number(value):
        raise ContractError(f"{label} out of range")
    if not minimum <= value <= maximum:
        raise ContractError(f"{label} out of range")
    return float(value)


_LANGUAGE_TAG_RE = re.compile(r"^[A-Za-z]{2,3}(?:-[A-Za-z0-9]{2,8})*$")


def _validate_speech_facts(speech: Any) -> dict[str, Any]:
    """Validate the honest speech observation (B11).

    The consistency rules are the point: a snapshot may not claim voices it did not
    enumerate, and may not claim more local or default voices than voices.
    """
    if not isinstance(speech, dict):
        raise ContractError("browser.speech must be an object")
    allowed = {
        "api_present",
        "voice_count",
        "languages",
        "local_service_count",
        "default_count",
        "poll_attempts",
        "poll_budget_ms",
        "voices_observed_empty",
    }
    if not set(speech).issubset(allowed):
        raise ContractError("browser.speech fields are invalid")
    for flag in ("api_present", "voices_observed_empty"):
        if flag in speech and not isinstance(speech[flag], bool):
            raise ContractError(f"browser.speech.{flag} must be boolean")
    if not isinstance(speech.get("api_present"), bool):
        raise ContractError("browser.speech.api_present is required")
    count = _require_int(
        speech.get("voice_count"), "browser.speech.voice_count", maximum=4096
    )
    for field in ("local_service_count", "default_count"):
        if field in speech:
            value = _require_int(speech[field], f"browser.speech.{field}", maximum=4096)
            if value > count:
                raise ContractError(f"browser.speech.{field} exceeds voice_count")
    if "poll_attempts" in speech:
        _require_int(
            speech["poll_attempts"], "browser.speech.poll_attempts",
            minimum=1, maximum=600_000,
        )
    if "poll_budget_ms" in speech:
        _require_int(
            speech["poll_budget_ms"], "browser.speech.poll_budget_ms",
            maximum=600_000,
        )
    languages = speech.get("languages")
    if not isinstance(languages, list) or len(languages) > 64:
        raise ContractError(
            "browser.speech.languages must be a list of at most 64 tags"
        )
    for tag in languages:
        _require_text(tag, "browser.speech.languages[]", maximum=32)
        if not _LANGUAGE_TAG_RE.fullmatch(tag):
            raise ContractError("browser.speech.languages[] is not a language tag")
    if len(set(languages)) != len(languages):
        raise ContractError("browser.speech.languages must be unique")
    if languages and not count:
        raise ContractError("browser.speech.languages present with zero voices")
    if not speech["api_present"] and count:
        raise ContractError("browser.speech reports voices without the API present")
    if "voices_observed_empty" in speech:
        expected = bool(speech["api_present"]) and not count
        if speech["voices_observed_empty"] is not expected:
            raise ContractError("browser.speech.voices_observed_empty is inconsistent")
    return speech


def validate_browser_fact_snapshot(document: Any) -> dict[str, Any]:
    if not isinstance(document, dict) or document.get("schema") != BROWSER_FACT_SCHEMA:
        raise ContractError("unsupported browser-fact snapshot schema")
    required = {
        "schema",
        "snapshot_id",
        "captured_at",
        "source",
        "browser",
        "integrity_sha256",
    }
    if not required.issubset(document) or not set(document).issubset(
        required | {"engine", "notes"}
    ):
        raise ContractError("browser-fact snapshot top-level fields are invalid")
    snapshot_id = document.get("snapshot_id")
    if not isinstance(snapshot_id, str) or not SNAPSHOT_ID_RE.fullmatch(snapshot_id):
        raise ContractError("browser-fact snapshot_id is invalid")
    captured_at = _require_text(
        document.get("captured_at"), "browser-fact captured_at", maximum=64
    )
    try:
        captured_at_value = datetime.fromisoformat(captured_at.replace("Z", "+00:00"))
    except ValueError:
        captured_at_value = None
    if captured_at_value is None or captured_at_value.utcoffset() is None:
        raise ContractError(
            "browser-fact captured_at must be a timezone-aware timestamp"
        )
    source = document.get("source")
    source_kind = source.get("kind") if isinstance(source, dict) else None
    if not isinstance(source_kind, str) or source_kind not in {
        "playwright-kernel",
        "browser-core-session",
        "fixture",
    }:
        raise ContractError("browser-fact source.kind is unsupported")
    allowed_source = {
        "kind",
        "label",
        "session_run_id",
        "chromium_revision",
        "executable_sha256_16",
        "build_provenance",
        "headless",
        "viewport_mode",
    }
    if not set(source).issubset(allowed_source):
        raise ContractError("browser-fact source fields are invalid")
    _require_text(source.get("label"), "browser-fact source.label", maximum=128)
    has_headless = "headless" in source
    has_viewport_mode = "viewport_mode" in source
    if has_headless is not has_viewport_mode:
        raise ContractError("browser-fact source capture method is incomplete")
    if has_headless:
        headless = source["headless"]
        viewport_mode = source["viewport_mode"]
        if source_kind != "playwright-kernel" or type(headless) is not bool:
            raise ContractError("browser-fact source capture method is invalid")
        expected_viewport_mode = (
            "synthetic-default" if headless else "native-window"
        )
        if viewport_mode != expected_viewport_mode:
            raise ContractError("browser-fact source capture method is invalid")
    if "session_run_id" in source:
        _require_text(
            source["session_run_id"], "browser-fact source.session_run_id", maximum=128
        )
    if "chromium_revision" in source:
        revision = source["chromium_revision"]
        if not isinstance(revision, str) or not re.fullmatch(r"[0-9a-f]{40}", revision):
            raise ContractError("browser-fact source.chromium_revision is invalid")
    if "executable_sha256_16" in source:
        digest = source["executable_sha256_16"]
        if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{16}", digest):
            raise ContractError("browser-fact source.executable_sha256_16 is invalid")
    if "build_provenance" in source:
        if not isinstance(source["build_provenance"], str) or source[
            "build_provenance"
        ] not in {
            "attested-browser-core",
            "unverified-external",
        }:
            raise ContractError("browser-fact source.build_provenance is invalid")
    if "engine" in document:
        if not isinstance(document["engine"], str) or document["engine"] not in {
            "chromium",
            "firefox",
            "webkit",
            "browser-core",
        }:
            raise ContractError("browser-fact engine is unsupported")
    session_provenance_fields = {
        "session_run_id",
        "chromium_revision",
        "executable_sha256_16",
        "build_provenance",
    }
    present_session_provenance = set(source) & session_provenance_fields
    if source_kind == "browser-core-session":
        if (
            present_session_provenance != session_provenance_fields
            or source.get("build_provenance") != "attested-browser-core"
            or document.get("engine") != "browser-core"
        ):
            raise ContractError(
                "browser-fact source provenance is incoherent with source.kind"
            )
    elif present_session_provenance:
        raise ContractError(
            "browser-fact source provenance is incoherent with source.kind"
        )
    if source_kind == "playwright-kernel" and document.get("engine") not in {
        None,
        "chromium",
        "firefox",
        "webkit",
    }:
        raise ContractError(
            "browser-fact source provenance is incoherent with source.kind"
        )
    if "notes" in document:
        _require_text(document["notes"], "browser-fact notes", maximum=512)

    browser = document.get("browser")
    if not isinstance(browser, dict):
        raise ContractError("browser-fact browser must be an object")
    required_browser = {
        "ua",
        "platform",
        "language",
        "languages",
        "timezone",
        "locale",
        "hardware_concurrency",
        "screen",
        "window",
        "webgl",
        "automation",
    }
    allowed_browser = required_browser | {
        "app_version",
        "device_memory",
        "max_touch_points",
        "plugins_length",
        "mime_types_length",
        "pdf_viewer_enabled",
        "client_hints",
        "speech",
    }
    unknown_browser_fields = set(browser) - allowed_browser
    if unknown_browser_fields:
        _reject_forbidden_fragments(
            {key: browser[key] for key in unknown_browser_fields}
        )
    if not required_browser.issubset(browser) or unknown_browser_fields:
        raise ContractError("browser-fact browser fields are invalid")
    _require_text(browser["ua"], "browser.ua", maximum=1024)
    _require_text(browser["platform"], "browser.platform", maximum=128)
    _require_text(browser["language"], "browser.language", maximum=32)
    languages = browser["languages"]
    if not isinstance(languages, list) or not languages or len(languages) > 16:
        raise ContractError("browser.languages must be a short non-empty list")
    for item in languages:
        _require_text(item, "browser.languages[]", maximum=32)
        if not _LANGUAGE_TAG_RE.fullmatch(item):
            raise ContractError("browser.languages[] is not a language tag")
    if len(set(languages)) != len(languages):
        raise ContractError("browser.languages must be unique")
    if browser["language"] != languages[0]:
        raise ContractError("browser.language must equal browser.languages[0]")
    if not _LANGUAGE_TAG_RE.fullmatch(browser["language"]):
        raise ContractError("browser.language is not a language tag")
    _require_text(browser["timezone"], "browser.timezone", maximum=64)
    _require_text(browser["locale"], "browser.locale", maximum=32)
    _require_int(
        browser["hardware_concurrency"],
        "browser.hardware_concurrency",
        minimum=1,
        maximum=4096,
    )
    if "app_version" in browser:
        _require_text(browser["app_version"], "browser.app_version", maximum=1024)
    if "device_memory" in browser and browser["device_memory"] is not None:
        _require_number(
            browser["device_memory"],
            "browser.device_memory",
            minimum=0.125,
            maximum=4096,
        )
    for optional_int in ("max_touch_points", "plugins_length", "mime_types_length"):
        if optional_int in browser and browser[optional_int] is not None:
            _require_int(
                browser[optional_int],
                f"browser.{optional_int}",
                minimum=0,
                maximum=4096,
            )
    if "pdf_viewer_enabled" in browser and not isinstance(
        browser["pdf_viewer_enabled"], bool
    ):
        raise ContractError("browser.pdf_viewer_enabled must be boolean")

    if "client_hints" in browser:
        client_hints = browser["client_hints"]
        if not isinstance(client_hints, dict) or set(client_hints) != {
            "brands",
            "mobile",
            "platform",
        }:
            raise ContractError("browser.client_hints fields are invalid")
        brands = client_hints["brands"]
        if brands is not None:
            if not isinstance(brands, list) or len(brands) > 32:
                raise ContractError("browser.client_hints.brands is invalid")
            for brand in brands:
                if not isinstance(brand, dict) or set(brand) != {"brand", "version"}:
                    raise ContractError("browser.client_hints brand fields are invalid")
                _require_text(
                    brand["brand"], "browser.client_hints.brands[].brand", maximum=128
                )
                _require_text(
                    brand["version"],
                    "browser.client_hints.brands[].version",
                    maximum=64,
                )
        if not isinstance(client_hints["mobile"], bool):
            raise ContractError("browser.client_hints.mobile must be boolean")
        if client_hints["platform"] is not None:
            _require_text(
                client_hints["platform"],
                "browser.client_hints.platform",
                maximum=128,
            )

    screen = browser["screen"]
    if not isinstance(screen, dict) or set(screen) != {
        "width",
        "height",
        "avail_width",
        "avail_height",
        "color_depth",
        "pixel_depth",
    }:
        raise ContractError("browser.screen fields are invalid")
    for key in ("width", "height", "avail_width", "avail_height"):
        _require_int(screen[key], f"browser.screen.{key}", minimum=1, maximum=100_000)
    for key in ("color_depth", "pixel_depth"):
        _require_int(screen[key], f"browser.screen.{key}", minimum=1, maximum=1_024)
    if screen["avail_width"] > screen["width"] or screen["avail_height"] > screen["height"]:
        raise ContractError("browser.screen available geometry exceeds the screen")

    window_geom = browser["window"]
    if not isinstance(window_geom, dict) or set(window_geom) != {
        "inner_width",
        "inner_height",
        "outer_width",
        "outer_height",
        "device_pixel_ratio",
    }:
        raise ContractError("browser.window fields are invalid")
    for key in ("inner_width", "inner_height", "outer_width", "outer_height"):
        _require_int(
            window_geom[key], f"browser.window.{key}", minimum=1, maximum=100_000
        )
    if (
        window_geom["outer_width"] < window_geom["inner_width"]
        or window_geom["outer_height"] < window_geom["inner_height"]
    ):
        raise ContractError("browser.window outer geometry is smaller than inner geometry")
    _require_number(
        window_geom["device_pixel_ratio"],
        "browser.window.device_pixel_ratio",
        minimum=0.1,
        maximum=16.0,
    )

    webgl = browser["webgl"]
    if not isinstance(webgl, dict) or set(webgl) != {"webgl1", "webgl2"}:
        raise ContractError("browser.webgl must contain webgl1 and webgl2")
    for context_name in ("webgl1", "webgl2"):
        context = webgl[context_name]
        if (
            not isinstance(context, dict)
            or not {"vendor", "renderer"}.issubset(context)
            or set(context) - {"vendor", "renderer", "version"}
        ):
            raise ContractError(f"browser.webgl.{context_name} is invalid")
        for field in ("vendor", "renderer", "version"):
            if field in context and context[field] is not None:
                _require_text(
                    context[field],
                    f"browser.webgl.{context_name}.{field}",
                    maximum=1024,
                )

    automation = browser["automation"]
    if not isinstance(automation, dict) or set(automation) != {
        "webdriver",
        "chrome_object",
    }:
        raise ContractError("browser.automation.webdriver is required")
    if not isinstance(automation["webdriver"], bool):
        raise ContractError("browser.automation.webdriver must be boolean")
    if automation["chrome_object"] is not None and not isinstance(
        automation["chrome_object"], bool
    ):
        raise ContractError("browser.automation.chrome_object must be boolean or null")

    # Optional so snapshots captured before B11 stay valid.
    if "speech" in browser and browser["speech"] is not None:
        _validate_speech_facts(browser["speech"])

    reject_sensitive_keys(document)
    _reject_forbidden_fragments(document)

    payload = {
        key: value for key, value in document.items() if key != "integrity_sha256"
    }
    digest = hashlib.sha256(_canonical(payload)).hexdigest()
    integrity = document.get("integrity_sha256")
    if not isinstance(integrity, str) or integrity != digest:
        raise ContractError("browser-fact integrity_sha256 does not match")

    encoded = _canonical(document)
    if len(encoded) > MAX_SNAPSHOT_BYTES:
        raise ContractError("browser-fact snapshot exceeds size limit")
    return document


def build_browser_fact_snapshot(
    *,
    snapshot_id: str,
    browser: dict[str, Any],
    source_kind: str,
    source_label: str,
    engine: str | None = None,
    notes: str | None = None,
    captured_at: str | None = None,
    source_extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if not isinstance(snapshot_id, str) or not SNAPSHOT_ID_RE.fullmatch(snapshot_id):
        raise ContractError("browser-fact snapshot_id is invalid")
    if not isinstance(browser, dict):
        raise ContractError("browser-fact browser must be an object")
    if source_extra is not None and not isinstance(source_extra, dict):
        raise ContractError("browser-fact source_extra must be an object or null")
    if source_extra is not None and {"kind", "label"} & source_extra.keys():
        raise ContractError("browser-fact source_extra cannot override source identity")
    if not isinstance(source_kind, str) or source_kind not in {
        "playwright-kernel",
        "browser-core-session",
        "fixture",
    }:
        raise ContractError("browser-fact source.kind is unsupported")
    _require_text(source_label, "browser-fact source.label", maximum=128)
    if engine is not None and (
        not isinstance(engine, str)
        or engine not in {"chromium", "firefox", "webkit", "browser-core"}
    ):
        raise ContractError("browser-fact engine is unsupported")
    if notes is not None:
        _require_text(notes, "browser-fact notes", maximum=512)
    if captured_at is not None:
        _require_text(captured_at, "browser-fact captured_at", maximum=64)
    source: dict[str, Any] = {"kind": source_kind, "label": source_label}
    if source_extra is not None:
        for key, value in source_extra.items():
            if value is not None:
                source[key] = value
    document: dict[str, Any] = {
        "schema": BROWSER_FACT_SCHEMA,
        "snapshot_id": snapshot_id,
        "captured_at": _utc_now() if captured_at is None else captured_at,
        "source": source,
        "browser": browser,
    }
    if engine is not None:
        document["engine"] = engine
    if notes is not None:
        document["notes"] = notes
    payload_body = _canonical(document)
    if len(payload_body) > MAX_SNAPSHOT_BYTES:
        raise ContractError("browser-fact snapshot exceeds size limit")
    retained = decode_strict_json_bytes(payload_body, label="browser-fact snapshot")
    if not isinstance(retained, dict):
        raise ContractError("browser-fact snapshot is invalid")
    retained["integrity_sha256"] = hashlib.sha256(payload_body).hexdigest()
    return validate_browser_fact_snapshot(retained)


def browser_fact_from_observed(
    observed: dict[str, Any],
    *,
    snapshot_id: str,
    source_kind: str,
    source_label: str,
    engine: str | None = None,
    source_extra: dict[str, Any] | None = None,
    notes: str | None = None,
) -> dict[str, Any]:
    """Normalize a collector-style observation dict into a validated snapshot."""
    if not isinstance(observed, dict):
        raise ContractError("observed browser facts must be an object")

    def alias(primary: str, legacy: str) -> Any:
        primary_present = primary in observed
        legacy_present = legacy in observed
        if primary_present and legacy_present:
            if _canonical(observed[primary]) != _canonical(observed[legacy]):
                raise ContractError("observed browser fact aliases conflict")
        if primary_present:
            return observed[primary]
        return observed.get(legacy)

    if "automation" in observed:
        automation = observed["automation"]
    else:
        automation = {
            "webdriver": observed.get("webdriver"),
            "chrome_object": None,
        }
    browser = {
        "ua": alias("ua", "userAgent"),
        "app_version": alias("app_version", "appVersion"),
        "platform": observed.get("platform"),
        "language": observed.get("language"),
        "languages": observed.get("languages"),
        "timezone": observed.get("timezone"),
        "locale": observed.get("locale"),
        "hardware_concurrency": alias("hardware_concurrency", "hardwareConcurrency"),
        "device_memory": alias("device_memory", "deviceMemory"),
        "max_touch_points": alias("max_touch_points", "maxTouchPoints"),
        "plugins_length": alias("plugins_length", "pluginsLength"),
        "mime_types_length": alias("mime_types_length", "mimeTypesLength"),
        "pdf_viewer_enabled": alias("pdf_viewer_enabled", "pdfViewerEnabled"),
        "screen": observed.get("screen"),
        "window": observed.get("window"),
        "webgl": observed.get("webgl"),
        "client_hints": alias("client_hints", "clientHints"),
        "automation": automation,
        "speech": observed.get("speech"),
    }
    # Drop Nones for optional leaves only where allowed by validator.
    optional = (
        "app_version",
        "device_memory",
        "max_touch_points",
        "plugins_length",
        "mime_types_length",
        "pdf_viewer_enabled",
        "client_hints",
        "speech",
    )
    for key in optional:
        if browser.get(key) is None:
            browser.pop(key, None)
    return build_browser_fact_snapshot(
        snapshot_id=snapshot_id,
        browser=browser,
        source_kind=source_kind,
        source_label=source_label,
        engine=engine,
        source_extra=source_extra,
        notes=notes,
    )


def capture_browser_fact_from_session(
    session_path: Path,
    *,
    snapshot_id: str,
    timeout_seconds: float = 15.0,
    target_url: str | None = None,
) -> dict[str, Any]:
    """Capture browser facts from an active Browser Core evaluation session via CDP.

    Requires a live session with a loopback automation.cdp_endpoint. Binds
    session run id, chromium revision, and executable digest from the session
    contract into source metadata (no CDP endpoint is stored in the snapshot).
    """
    from .cdp import evaluate_page_expression
    from .contracts import load_session_snapshot

    if not isinstance(session_path, Path):
        raise ContractError("browser-fact session path must be a Path")
    if not isinstance(snapshot_id, str) or not SNAPSHOT_ID_RE.fullmatch(snapshot_id):
        raise ContractError("browser-fact snapshot_id is invalid")
    if not is_finite_number(timeout_seconds) or not 0 < timeout_seconds <= 120:
        raise ContractError("browser-fact session timeout must be finite in (0, 120]")
    if target_url is not None:
        _require_text(target_url, "browser-fact target_url", maximum=64 * 1024)
    deadline = time.monotonic() + float(timeout_seconds)
    session_snapshot = load_session_snapshot(session_path)
    _remaining_capture_time(deadline)
    session = session_snapshot.document
    if session.get("state", "active") != "active":
        raise ContractError("browser-fact session capture requires an active session")
    automation = session.get("automation")
    if not isinstance(automation, dict):
        raise ContractError("browser-fact session is missing automation hand-off")
    cdp_endpoint = automation.get("cdp_endpoint")
    if not isinstance(cdp_endpoint, str) or not cdp_endpoint:
        raise ContractError("browser-fact session is missing automation.cdp_endpoint")
    # Prefer the session's exact managed page target (launch-eval identity page).
    managed = automation.get("managed_target_url")
    page_url = (
        target_url
        if target_url is not None
        else (managed if isinstance(managed, str) and managed else None)
    )
    if not page_url:
        raise ContractError(
            "browser-fact session capture requires automation.managed_target_url "
            "or an explicit target_url"
        )
    # Collector is an arrow function; invoke it for returnByValue.
    expression = f"({_COLLECT_JS})()"
    def collect() -> Any:
        return evaluate_page_expression(
            cdp_endpoint, expression, target_url=page_url,
            timeout_seconds=_remaining_capture_time(deadline), command_id=943,
        )

    def window_ready() -> Any:
        return evaluate_page_expression(
            cdp_endpoint,
            _WINDOW_READY_JS,
            target_url=page_url,
            timeout_seconds=_remaining_capture_time(deadline), command_id=945,
        )

    observed = _collect_ready_browser_facts(collect, window_ready, deadline)

    # B11: an empty voice list may just mean we asked too early, so re-read under a
    # bounded budget before recording it. The record says how hard we looked.
    def evaluate_speech() -> Any:
        return evaluate_page_expression(
            cdp_endpoint,
            f"({_SPEECH_JS})()",
            target_url=page_url,
            timeout_seconds=_remaining_capture_time(deadline),
            command_id=944,
        )

    def bounded_sleep(delay: float) -> None:
        remaining = _remaining_capture_time(deadline)
        time.sleep(min(delay, remaining))
        _remaining_capture_time(deadline)

    observed["speech"] = poll_speech_observation(
        evaluate_speech,
        sleep=bounded_sleep,
    )
    build = session.get("build") if isinstance(session.get("build"), dict) else {}
    source_extra = {
        "session_run_id": session.get("run_id"),
        "chromium_revision": session.get("chromium_revision"),
        "executable_sha256_16": build.get("executable_sha256_16"),
        "build_provenance": build.get("provenance"),
    }
    _remaining_capture_time(deadline)
    fact = browser_fact_from_observed(
        observed,
        snapshot_id=snapshot_id,
        source_kind="browser-core-session",
        source_label=f"browser-core-session:{session.get('run_id')}",
        engine="browser-core",
        source_extra=source_extra,
        notes="captured from attested Browser Core evaluation session",
    )
    _remaining_capture_time(deadline)
    retained_session = load_session_snapshot(session_path)
    _remaining_capture_time(deadline)
    if (
        retained_session.body != session_snapshot.body
        or retained_session.identity != session_snapshot.identity
        or retained_session.document.get("state") != "active"
    ):
        raise ContractError("browser-fact session changed during capture")
    return fact


def browserless_ordinary_facts_from_snapshot(
    document: dict[str, Any],
) -> dict[str, Any]:
    """Map a validated Core browser-fact snapshot to ordinary constructor facts.

    Does not produce product sensor fields. Safe subset for offline profiles.
    """
    validated = validate_browser_fact_snapshot(document)
    browser = validated["browser"]
    return {
        "schema": "browser-core.browserless-ordinary-facts/1",
        "from_snapshot_id": validated["snapshot_id"],
        "from_integrity_sha256": validated["integrity_sha256"],
        "ua": browser["ua"],
        "platform": browser["platform"],
        "language": browser["language"],
        "languages": list(browser["languages"]),
        "timezone": browser["timezone"],
        "locale": browser["locale"],
        "hardware_concurrency": browser["hardware_concurrency"],
        "screen": dict(browser["screen"]),
        "window": dict(browser["window"]),
        "webgl": {
            "webgl1": dict(browser["webgl"]["webgl1"]),
            "webgl2": dict(browser["webgl"]["webgl2"]),
        },
        # B11: forwarded because the product collector reads the voice list. Absent
        # when the snapshot predates B11 -- which is not the same as zero voices.
        "speech": ({**browser["speech"],
                    "languages": list(browser["speech"]["languages"])}
                   if browser.get("speech") else None),
        "source_kind": validated["source"]["kind"],
    }


def capture_browser_fact_playwright(
    *,
    snapshot_id: str,
    engine: str = "chromium",
    locale: str = "en-US",
    timezone: str = "America/Chicago",
    headless: bool = True,
    timeout_seconds: float = 30.0,
) -> dict[str, Any]:
    """Capture a live browser-fact snapshot via Playwright-managed kernel."""
    if not isinstance(snapshot_id, str) or not SNAPSHOT_ID_RE.fullmatch(snapshot_id):
        raise ContractError("browser-fact snapshot_id is invalid")
    if not isinstance(engine, str) or engine not in {"chromium", "firefox", "webkit"}:
        raise ContractError("playwright browser-fact capture engine is unsupported")
    _require_text(locale, "playwright browser-fact locale", maximum=64)
    _require_text(timezone, "playwright browser-fact timezone", maximum=128)
    if type(headless) is not bool:
        raise ContractError("playwright browser-fact headless must be boolean")
    if not is_finite_number(timeout_seconds) or not 0 < timeout_seconds <= 120:
        raise ContractError(
            "playwright browser-fact timeout must be finite in (0, 120]"
        )
    deadline = time.monotonic() + float(timeout_seconds)

    def remaining_ms() -> int:
        return max(1, int(_remaining_capture_time(deadline) * 1000))

    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        raise ContractError("Playwright is required for browser-fact capture") from None
    playwright = None
    browser = None
    context = None
    observed: Any = None
    active_error: BaseException | None = None
    try:
        manager = sync_playwright()
        _remaining_capture_time(deadline)
        playwright = manager.start()
        _remaining_capture_time(deadline)
        browser_type = getattr(playwright, engine)
        browser = browser_type.launch(headless=headless, timeout=remaining_ms())
        _remaining_capture_time(deadline)
        context_options: dict[str, Any] = {
            "locale": locale,
            "timezone_id": timezone,
        }
        viewport_mode = "synthetic-default"
        if not headless:
            # Playwright otherwise injects its 1280x720 default viewport even in a
            # visible browser. That also makes screen.avail* equal the synthetic
            # screen and erases the host window-manager work area we came here to
            # measure. A headed fact capture is host-native evidence, so let the
            # real window choose its viewport and bind that method into the receipt.
            context_options["no_viewport"] = True
            viewport_mode = "native-window"
        context = browser.new_context(**context_options)
        _remaining_capture_time(deadline)
        page = context.new_page()
        page.set_default_timeout(remaining_ms())
        page.set_content(
            "<!doctype html><meta charset=utf-8><title>browser-core-facts</title>",
            timeout=remaining_ms(),
        )
        _remaining_capture_time(deadline)
        def collect() -> Any:
            page.set_default_timeout(remaining_ms())
            result = page.evaluate(_COLLECT_JS)
            _remaining_capture_time(deadline)
            return result

        def window_ready() -> Any:
            page.set_default_timeout(remaining_ms())
            result = page.evaluate(_WINDOW_READY_JS)
            _remaining_capture_time(deadline)
            return result

        observed = _collect_ready_browser_facts(collect, window_ready, deadline)
        if isinstance(observed, dict):
            # B11: same bounded re-read as the session path.
            def evaluate_speech() -> Any:
                _remaining_capture_time(deadline)
                result = page.evaluate(_SPEECH_JS)
                _remaining_capture_time(deadline)
                return result

            def bounded_sleep(delay: float) -> None:
                remaining = _remaining_capture_time(deadline)
                time.sleep(min(delay, remaining))
                _remaining_capture_time(deadline)

            observed["speech"] = poll_speech_observation(
                evaluate_speech,
                sleep=bounded_sleep,
            )
        _remaining_capture_time(deadline)
    except ContractError as exc:
        active_error = exc
    except Exception as exc:
        active_error = ContractError(
            f"Playwright browser-fact capture failed ({type(exc).__name__})"
        )
    except BaseException as exc:
        active_error = exc
    cleanup_failures: list[str] = []
    for resource, phase, method in (
        (context, "context-close", "close"),
        (browser, "browser-close", "close"),
        (playwright, "playwright-stop", "stop"),
    ):
        if resource is None:
            continue
        try:
            result = getattr(resource, method)()
            if result is not None:
                cleanup_failures.append(phase)
        except Exception:
            cleanup_failures.append(phase)
    if cleanup_failures:
        cleanup_error = ContractError(
            "Playwright browser-fact cleanup failed " f"({','.join(cleanup_failures)})"
        )
        if active_error is not None:
            raise cleanup_error from active_error
        raise cleanup_error
    if active_error is not None:
        raise active_error
    _remaining_capture_time(deadline)
    if not isinstance(observed, dict):
        raise ContractError("browser-fact collector returned a non-object")
    fact = browser_fact_from_observed(
        observed,
        snapshot_id=snapshot_id,
        source_kind="playwright-kernel",
        source_label=f"playwright:{engine}",
        engine=engine,
        source_extra={
            "headless": headless,
            "viewport_mode": viewport_mode,
        },
    )
    _remaining_capture_time(deadline)
    return fact


def write_browser_fact_snapshot(path: Path, document: dict[str, Any]) -> Path:
    if not isinstance(path, Path):
        raise ContractError("browser-fact snapshot destination must be a Path")
    # Validate a private JSON copy. The caller can still mutate its nested
    # dictionaries after validation while the publication body is encoded.
    retained = decode_strict_json_bytes(
        _canonical(document), label="browser-fact snapshot"
    )
    validated = validate_browser_fact_snapshot(retained)
    requested_destination = path
    if requested_destination.is_symlink():
        raise ContractError("browser-fact snapshot destination must not be a symlink")
    try:
        requested_metadata = os.lstat(requested_destination)
    except FileNotFoundError:
        pass
    except OSError:
        raise ContractError("browser-fact snapshot destination cannot be inspected") from None
    else:
        if stat.S_ISLNK(requested_metadata.st_mode) or (
            getattr(requested_metadata, "st_file_attributes", 0) & 0x400
        ):
            raise ContractError("browser-fact snapshot destination must not be a reparse point")
    prepare_owned_directory_parent(
        requested_destination.parent, label="browser-fact snapshot output parent",
    )
    # Keep the requested name lexical. Resolving after parent preparation can
    # adopt a junction installed in that interval and publish outside it.
    destination = Path(os.path.abspath(requested_destination))
    if destination.exists():
        raise ContractError("refusing to overwrite an existing browser-fact snapshot")
    try:
        body = (
            json.dumps(validated, indent=2, sort_keys=True, allow_nan=False) + "\n"
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise ContractError(
            f"cannot encode browser-fact snapshot: {type(exc).__name__}"
        ) from None
    if len(body) > MAX_SNAPSHOT_SOURCE_BYTES:
        raise ContractError("browser-fact snapshot exceeds source size limit")

    publication = publish_bytes_exclusive_result(
        destination,
        body,
        maximum=MAX_SNAPSHOT_SOURCE_BYTES,
        label="browser-fact snapshot",
        require_single_link=True,
    )
    if publication.body != body:
        raise ContractError("browser-fact snapshot changed during publication")
    return destination


def load_browser_fact_snapshot(path: Path) -> dict[str, Any]:
    if not isinstance(path, Path):
        raise ContractError("browser-fact snapshot path must be a Path")
    snapshot = read_bounded_control_snapshot_result(
        path,
        maximum=MAX_SNAPSHOT_SOURCE_BYTES,
        label="browser-fact snapshot",
        require_single_link=True,
    )
    if snapshot.state != "complete":
        raise ContractError(f"browser-fact snapshot is {snapshot.state}")
    assert snapshot.body is not None and snapshot.identity is not None
    try:
        snapshot.body.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        raise ContractError("browser-fact snapshot encoding is invalid") from None
    try:
        document = decode_strict_json_bytes(
            snapshot.body, label="browser-fact snapshot"
        )
    except ContractError as exc:
        if "duplicate key" in str(exc) or "non-finite" in str(exc):
            raise
        raise ContractError("browser-fact snapshot JSON is invalid") from None
    validated = validate_browser_fact_snapshot(document)
    try:
        final = read_bounded_control_snapshot_result(
            path,
            maximum=MAX_SNAPSHOT_SOURCE_BYTES,
            label="browser-fact snapshot",
            require_single_link=True,
        )
    except ContractError:
        raise ContractError("browser-fact snapshot changed during validation") from None
    if (
        final.state != "complete"
        or final.body != snapshot.body
        or final.identity != snapshot.identity
    ):
        raise ContractError("browser-fact snapshot changed during validation")
    return validated
