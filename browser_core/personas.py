from __future__ import annotations

import copy
import hashlib
import json
import os
import re
import time
from collections import Counter, OrderedDict
from datetime import datetime, timezone
from itertools import islice
from pathlib import Path
from threading import Lock
from typing import Any, Iterable

from .control_files import (
    BoundedControlSnapshot,
    BoundedJsonDirectoryInventory,
    canonical_json_bytes,
    decode_strict_json_bytes,
    inventory_bounded_json_directory,
    load_canonical_json_document,
    publish_bytes_exclusive,
    publish_json_exclusive,
    read_bounded_control_snapshot_result,
    replace_json_conditionally,
)
from .contracts import ContractError, reject_sensitive_keys
from .errors import safe_failure_receipt
from .http_deadline import (
    clamp_urllib_response_read_timeout,
    urllib_response_has_unread_declared_bytes,
)
from .numeric import is_ascii_decimal, is_finite_number
from .owned_paths import (
    directory_identity,
    prepare_owned_directory_parent,
    require_owned_directory_ancestors,
)
from .profiles import (
    PROFILE_ID_RE,
    canonicalize_identity_contract,
    has_windows_device_basename,
)


PERSONA_SCHEMA = "browser-core.persona/1"
PERSONA_BUNDLE_SCHEMA = "browser-core.persona-bundle/2"
PERSONA_ASSIGNMENT_SCHEMA = "browser-core.persona-assignment/1"
AUDIT_SCHEMA = "browser-core.persona-catalog-audit/2"
COVERAGE_SCHEMA = "browser-core.persona-catalog-coverage/2"
VOLUME_SCHEMA = "browser-core.persona-catalog-volume/2"
KAMELEO_INVENTORY_SCHEMA = "browser-core.kameleo-operator-inventory/1"
COMMERCIAL_COMPARE_SCHEMA = "browser-core.commercial-volume-compare/2"
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
COUNTRY_RE = re.compile(r"^[A-Z]{2}$")
LOCALE_RE = re.compile(r"^[A-Za-z]{2,3}(?:-[A-Za-z0-9]{2,8})*$")
TIMEZONE_RE = re.compile(r"^[A-Za-z_+-]+(?:/[A-Za-z0-9_+.-]+)+$")
ALLOWED_ENGINES = {"chromium", "firefox", "webkit"}
ALLOWED_PRODUCTS = {"browser-core", "chrome", "chromium", "edge", "firefox", "safari"}

# The product a Playwright-managed kernel of each engine realizes. Kernels that
# name their own product -- the attested Browser Core build is the only one --
# override this rather than being derived from it.
_ENGINE_PRODUCTS = {"chromium": "chromium", "firefox": "firefox", "webkit": "safari"}

# Mobile operating systems a Chromium-engine browser actually ships on. Shared
# with the coherence audit so the devices a capture will accept and the devices a
# rule will pass cannot drift apart.
CHROMIUM_MOBILE_OS_FAMILIES = frozenset({"android", "ios"})

# User-agent markers for handset platforms that no longer ship. Playwright keeps
# their presets on purpose -- it is a testing catalog, and regression tests want
# old devices -- but a persona catalog built by walking that list inherits every
# one of them. Ten presets across these four platforms were producing personas:
# Nokia Lumia 520 (Internet Explorer Mobile on Windows Phone 8), Microsoft Lumia
# 550 and 950 (Edge on Windows Phone 10), Nokia N9 (MeeGo), BlackBerry Z30
# (BB10). None of these devices can be running the browser the capture realizes.
DISCONTINUED_MOBILE_PLATFORMS = (
    "Windows Phone",
    "IEMobile",
    "MeeGo",
    "BB10",
    "Symbian",
)
ALLOWED_OS = {"windows", "macos", "linux", "android", "ios"}
ALLOWED_PROVENANCE = {"owned-capture", "reviewed-contract", "imported-bundle"}
KERNEL_PROBE_REQUIRED_CHECKS = frozenset({
    "owned_fixture", "secure_context", "viewport", "screen",
    "scale", "touch", "locale", "timezone",
})
PHYSICAL_PROBE_REQUIRED_CHECKS = frozenset({
    "owned_fixture", "android_user_agent", "touch", "viewport",
    "locale", "timezone", "rendering",
})
MAX_PERSONA_DOCUMENT_BYTES = 256 * 1024
MAX_PERSONA_EVIDENCE_BYTES = 16 * 1024 * 1024
MAX_PERSONA_ASSIGNMENT_BYTES = 4096
MAX_PERSONA_CATALOG_ENTRIES = 20_000
# Planning, enumeration and assignment must accept the same bounded population.
# Bundles retain their smaller independent transport/document limit.
MAX_PERSONA_ASSIGNMENT_CANDIDATES = MAX_PERSONA_CATALOG_ENTRIES
MAX_PERSONA_BUNDLE_BYTES = 64 * 1024 * 1024
MAX_PERSONA_BUNDLE_ITEMS = 10_000
MAX_PERSONA_CATALOG_FILES = MAX_PERSONA_CATALOG_ENTRIES
MAX_PERSONA_CATALOG_BYTES = 512 * 1024 * 1024
# Audit only the live profile sources actually verified, with an explicit
# cumulative budget for the final source rebind. Control snapshots may make a
# second same-handle pass on Windows, so physical reads can be up to twice this.
MAX_PERSONA_AUDIT_LIVE_PROFILE_RECHECK_BYTES = 256 * 1024 * 1024
# Each distinct saved evidence source gets one initial strict read and one
# final rebind. Each read uses two bounded snapshots; one 16-MiB file can
# exceed a cumulative limit by at most 32 MiB before explicit failure.
MAX_PERSONA_AUDIT_EVIDENCE_SCAN_BYTES = 256 * 1024 * 1024
MAX_PERSONA_AUDIT_EVIDENCE_RECHECK_BYTES = 256 * 1024 * 1024
# One initial live identity load has two stable snapshots, each with two
# 64-KiB registry reads and one 64-KiB identity read. At most 384 KiB can
# exceed this cumulative logical limit before explicit failure.
MAX_PERSONA_AUDIT_PROFILE_SCAN_BYTES = 256 * 1024 * 1024

# Retain only immutable, fully validated byte strings. Every lookup still reads
# the complete current file through the strict single-link snapshot boundary.
# Exact byte equality permits reusing schema validation, never filesystem trust.
_VALIDATED_PERSONA_BYTES: OrderedDict[bytes, None] = OrderedDict()
_VALIDATED_PERSONA_BYTES_LOCK = Lock()
_VALIDATED_PERSONA_BYTES_SIZE = 0
_VALIDATED_PERSONA_CACHE_BYTES = 64 * 1024 * 1024
_VALIDATED_PERSONA_CACHE_ENTRIES = MAX_PERSONA_CATALOG_FILES
MAX_KAMELEO_INVENTORY_RESPONSE_BYTES = 16 * 1024 * 1024
MAX_KAMELEO_INVENTORY_READ_CALLS = 65_536
MAX_KAMELEO_FINGERPRINTS = 1_000_000
MAX_BULK_GEOGRAPHIES = 256
MAX_BULK_CORE_VARIANTS = 64

_PROVENANCE_GRADE_NOTE = (
    "Grades are additive honesty signals. research_catalog_ready still "
    "uses diversity + allowed provenance kinds; commercial_inventory_ready "
    "still uses active_at_least_1000. Operators should not claim "
    "high-provenance inventory from matrix/fixture bulk alone."
)
_VOLUME_NOTE = (
    "Volume counts provenance-backed owned lab personas only. "
    "Kameleo/Multilogin/Octo vendor telemetry headcount is a different metric."
)
_KAMELEO_METHODOLOGY = (
    "Operator-accessible GET /fingerprints on the local Kameleo API "
    "(plan/filter limited; not unpublished global vendor telemetry millions)."
)
_COMMERCIAL_METHODOLOGY = (
    "Operator-accessible commercial inventory on this lab host: "
    "Browser Core active searchable personas vs Kameleo local API "
    "GET /fingerprints. Not a claim about unpublished global vendor telemetry millions."
)
_COMMERCIAL_NOTE = (
    "Preference language for 'Fingerprint catalog — vendor commercial volume' "
    "in this monorepo uses this operator-accessible comparison only."
)


class _MissingPersonaEvidence(ContractError):
    """Only an absent saved file permits the profile-source bundle fallback."""


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _allowed_text(value: Any, choices: set[str]) -> bool:
    return isinstance(value, str) and value in choices


def _canonical(value: Any) -> bytes:
    try:
        body = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8", errors="strict")
    except (TypeError, UnicodeEncodeError, ValueError, RecursionError) as exc:
        raise ContractError(
            f"value is not strict JSON ({type(exc).__name__})"
        ) from None
    decode_strict_json_bytes(body, label="persona value")
    return body


def _evidence_digest_matches(document: Any, digest: str) -> bool:
    canonical = _canonical(document)
    return digest in {
        hashlib.sha256(canonical).hexdigest(),
        hashlib.sha256(canonical + b"\n").hexdigest(),
    }


def _write_json_atomic(
    path: Path,
    document: dict[str, Any],
    *,
    expected: BoundedControlSnapshot | None = None,
) -> None:
    prepare_owned_directory_parent(path.parent, label="persona catalog parent")
    if expected is None:
        publish_json_exclusive(
            path,
            document,
            maximum=MAX_PERSONA_DOCUMENT_BYTES,
            label="persona document",
        )
        return
    if (
        expected.state != "complete"
        or expected.body is None
        or expected.identity is None
    ):
        raise ContractError("persona document changed before update")
    replace_json_conditionally(
        path,
        document,
        expected_body=expected.body,
        expected_identity=expected.identity,
        maximum=MAX_PERSONA_DOCUMENT_BYTES,
        label="persona document",
    )


def _require_text(value: Any, label: str, *, maximum: int = 256) -> str:
    if (
        not isinstance(value, str)
        or not value.strip()
        or len(value) > maximum
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise ContractError(f"{label} must be 1-{maximum} characters")
    try:
        value.encode("utf-8", errors="strict")
    except UnicodeEncodeError:
        raise ContractError(f"{label} must be 1-{maximum} characters") from None
    return value


def _require_aware_timestamp(value: Any, label: str) -> str:
    text = _require_text(value, label, maximum=64)
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        parsed = None
    if parsed is None or parsed.utcoffset() is None:
        raise ContractError(f"{label} must be timezone-aware ISO-8601")
    return text


def _require_version(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 999:
        raise ContractError(f"{label} must be an integer from 1 to 999")
    return value


def _persona_payload(document: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in document.items() if key != "integrity_sha256"}


def persona_digest(document: dict[str, Any]) -> str:
    return hashlib.sha256(_canonical(_persona_payload(document))).hexdigest()


def validate_persona(document: Any) -> dict[str, Any]:
    if not isinstance(document, dict) or document.get("schema") != PERSONA_SCHEMA:
        raise ContractError("unsupported persona document")
    required_top_level = {
        "schema",
        "id",
        "name",
        "state",
        "created_at",
        "tags",
        "device",
        "kernel",
        "geography",
        "identity_contract",
        "provenance",
        "integrity_sha256",
    }
    if not required_top_level.issubset(document) or not set(document).issubset(
        required_top_level | {"state_changed_at"}
    ):
        raise ContractError("persona top-level fields are invalid")
    persona_id = document.get("id")
    if (not isinstance(persona_id, str) or not PROFILE_ID_RE.fullmatch(persona_id)
            or has_windows_device_basename(persona_id)):
        raise ContractError("persona ID must be 1-64 safe ASCII characters")
    _require_text(document.get("name"), "persona name", maximum=128)
    _require_aware_timestamp(document.get("created_at"), "persona creation timestamp")
    if "state_changed_at" in document:
        _require_aware_timestamp(
            document.get("state_changed_at"), "persona state timestamp"
        )
    if not isinstance(document.get("state"), str) or document["state"] not in {"active", "deprecated"}:
        raise ContractError("persona state must be active or deprecated")
    tags = document.get("tags")
    if (
        not isinstance(tags, list)
        or len(tags) > 32
        or any(
            not isinstance(tag, str) or not PROFILE_ID_RE.fullmatch(tag) for tag in tags
        )
        or len({tag.casefold() for tag in tags}) != len(tags)
        or tags != sorted(set(tags), key=str.casefold)
    ):
        raise ContractError("persona tags must be sorted unique safe identifiers")

    device = document.get("device")
    if (
        not isinstance(device, dict)
        or not isinstance(device.get("class"), str)
        or device["class"] not in {"desktop", "mobile"}
    ):
        raise ContractError("persona device class must be desktop or mobile")
    if set(device) != {
        "class",
        "os_family",
        "os_version",
        "architecture",
        "is_mobile",
        "has_touch",
        "viewport",
        "screen",
    }:
        raise ContractError("persona device fields are invalid")
    if not isinstance(device.get("os_family"), str) or device["os_family"] not in ALLOWED_OS:
        raise ContractError("persona OS family is unsupported")
    _require_text(device.get("os_version"), "persona OS version", maximum=32)
    if not isinstance(device.get("architecture"), str) or device["architecture"] not in {"x86_64", "arm64"}:
        raise ContractError("persona architecture is unsupported")
    for field in ("is_mobile", "has_touch"):
        if not isinstance(device.get(field), bool):
            raise ContractError(f"persona device.{field} must be boolean")
    if device["class"] == "mobile" and (
        not device["is_mobile"] or not device["has_touch"]
    ):
        raise ContractError("mobile personas must realize mobile and touch input")
    if device["class"] == "desktop" and device["is_mobile"]:
        raise ContractError("desktop personas cannot claim a mobile viewport")
    viewport = device.get("viewport")
    if not isinstance(viewport, dict) or set(viewport) != {
        "width",
        "height",
        "device_scale_factor",
        "orientation",
    }:
        raise ContractError("persona viewport is required")
    for field in ("width", "height"):
        value = viewport.get(field)
        if (
            isinstance(value, bool)
            or not isinstance(value, int)
            or not 200 <= value <= 10000
        ):
            raise ContractError(f"persona viewport {field} is invalid")
    scale = viewport.get("device_scale_factor")
    if not is_finite_number(scale) or not 0.5 <= scale <= 8:
        raise ContractError("persona device scale factor is invalid")
    if not isinstance(viewport.get("orientation"), str) or viewport["orientation"] not in {"portrait", "landscape"}:
        raise ContractError("persona viewport orientation is invalid")
    expected_orientation = (
        "landscape" if viewport["width"] >= viewport["height"] else "portrait"
    )
    if viewport["orientation"] != expected_orientation:
        raise ContractError("persona viewport orientation contradicts its dimensions")
    screen = device.get("screen")
    if not isinstance(screen, dict) or set(screen) != {"width", "height"}:
        raise ContractError("persona screen is invalid")
    for field in ("width", "height"):
        value = screen.get(field)
        if (
            isinstance(value, bool)
            or not isinstance(value, int)
            or not 200 <= value <= 10000
        ):
            raise ContractError(f"persona screen {field} is invalid")
    if device["class"] == "desktop" and (
        viewport["width"] > screen["width"] or viewport["height"] > screen["height"]
    ):
        raise ContractError("desktop persona viewport cannot exceed its screen")

    kernel = document.get("kernel")
    if (
        not isinstance(kernel, dict)
        or not isinstance(kernel.get("engine"), str)
        or kernel["engine"] not in ALLOWED_ENGINES
    ):
        raise ContractError("persona kernel engine is unsupported")
    if set(kernel) != {"engine", "product", "minimum_major", "maximum_major"}:
        raise ContractError("persona kernel fields are invalid")
    if not isinstance(kernel.get("product"), str) or kernel["product"] not in ALLOWED_PRODUCTS:
        raise ContractError("persona kernel product is unsupported")
    minimum = _require_version(
        kernel.get("minimum_major"), "persona minimum kernel major"
    )
    maximum = _require_version(
        kernel.get("maximum_major"), "persona maximum kernel major"
    )
    if minimum > maximum:
        raise ContractError("persona kernel version range is reversed")
    if kernel["product"] in {"firefox"} and kernel["engine"] != "firefox":
        raise ContractError("Firefox personas require the Firefox engine")
    if kernel["product"] == "safari" and kernel["engine"] != "webkit":
        raise ContractError("Safari personas require a real WebKit engine")
    if (
        kernel["product"] in {"browser-core", "chrome", "chromium", "edge"}
        and kernel["engine"] != "chromium"
    ):
        raise ContractError("Chromium-family products require the Chromium engine")

    geography = document.get("geography")
    if not isinstance(geography, dict):
        raise ContractError("persona geography is required")
    if set(geography) != {"country", "locale", "languages", "timezone"}:
        raise ContractError("persona geography fields are invalid")
    if not isinstance(geography.get("country"), str) or not COUNTRY_RE.fullmatch(
        geography["country"]
    ):
        raise ContractError("persona country must be ISO alpha-2 uppercase")
    locale = geography.get("locale")
    if not isinstance(locale, str) or not LOCALE_RE.fullmatch(locale):
        raise ContractError("persona locale is invalid")
    languages = geography.get("languages")
    if (
        not isinstance(languages, list)
        or not languages
        or len(languages) > 8
        or any(
            not isinstance(item, str) or not LOCALE_RE.fullmatch(item)
            for item in languages
        )
        or languages[0].casefold() != locale.casefold()
        or len({item.casefold() for item in languages}) != len(languages)
    ):
        raise ContractError("persona languages must begin with the persona locale")
    timezone_name = geography.get("timezone")
    if not isinstance(timezone_name, str) or not TIMEZONE_RE.fullmatch(timezone_name):
        raise ContractError("persona time zone must be an explicit IANA-style zone")

    identity = document.get("identity_contract")
    try:
        raw_identity = _canonical(identity)
        canonical_identity, _ = canonicalize_identity_contract(raw_identity)
    except (TypeError, ContractError) as exc:
        raise ContractError(f"persona identity contract is invalid: {exc}") from None
    if json.loads(canonical_identity) != identity:
        raise ContractError("persona identity contract is not canonical")

    provenance = document.get("provenance")
    if (
        not isinstance(provenance, dict)
        or not isinstance(provenance.get("kind"), str)
        or provenance["kind"] not in ALLOWED_PROVENANCE
    ):
        raise ContractError("persona provenance is unsupported")
    if set(provenance) != {"kind", "source", "source_sha256", "captured_at"}:
        raise ContractError("persona provenance fields are invalid")
    _require_text(provenance.get("source"), "persona provenance source", maximum=256)
    source_digest = provenance.get("source_sha256")
    if not isinstance(source_digest, str) or not SHA256_RE.fullmatch(source_digest):
        raise ContractError("persona provenance digest must be SHA-256")
    _require_aware_timestamp(
        provenance.get("captured_at"), "persona provenance timestamp"
    )

    integrity = document.get("integrity_sha256")
    if not isinstance(integrity, str) or not SHA256_RE.fullmatch(integrity):
        raise ContractError("persona integrity digest must be SHA-256")
    if integrity != persona_digest(document):
        raise ContractError("persona integrity digest does not match")
    return document


def build_persona(
    *,
    persona_id: str,
    name: str,
    device: dict[str, Any],
    kernel: dict[str, Any],
    geography: dict[str, Any],
    identity_contract: dict[str, Any],
    provenance: dict[str, Any],
    tags: Iterable[str] = (),
) -> dict[str, Any]:
    canonical_identity, _ = canonicalize_identity_contract(
        _canonical(identity_contract)
    )
    document: dict[str, Any] = {
        "schema": PERSONA_SCHEMA,
        "id": persona_id,
        "name": name,
        "state": "active",
        "created_at": _utc_now(),
        "tags": sorted(set(tags), key=str.casefold),
        "device": device,
        "kernel": kernel,
        "geography": geography,
        "identity_contract": json.loads(canonical_identity),
        "provenance": provenance,
    }
    # The returned integrity digest must not be invalidated by callers mutating
    # their device, geography, kernel, or provenance dictionaries afterward.
    document = json.loads(_canonical(document))
    document["integrity_sha256"] = persona_digest(document)
    return validate_persona(document)


def reject_incoherent_persona(persona: dict[str, Any]) -> dict[str, Any]:
    """Refuse a persona that contradicts itself.

    ``validate_persona`` checks that a document is well-formed; this checks that
    the browser it describes could exist. They are different questions, and the
    catalog learned that the hard way: a capture whose realization check accepted
    ``pointer: coarse`` as evidence of touch minted several hundred personas that
    declared touch support and reported zero touch points -- each one individually
    valid, and each one carrying the same tell.

    Contradictions block the capture. Implausibilities and anomalies do not: a
    persona may legitimately be unusual, and refusing to record measurements that
    surprise us is how a catalog becomes a record of expectations instead of
    observations.
    """
    from .persona_quality import coherence_findings

    contradictions = [
        finding
        for finding in coherence_findings(persona)
        if finding["severity"] == "contradiction"
    ]
    if contradictions:
        summary = "; ".join(
            f"{finding['rule']}: {finding['summary']}" for finding in contradictions[:3]
        )
        raise ContractError(
            f"persona contradicts itself ({len(contradictions)}): {summary}"
        )
    return persona


def _browser_major_from_evidence(value: object, label: str) -> int:
    """Parse a measured dotted browser version without erasing its JSON type."""
    if type(value) is not str or not 1 <= len(value) <= 128:
        raise ContractError(f"{label} browser version must be bounded text")
    parts = value.split(".")
    if any(not is_ascii_decimal(part) for part in parts):
        raise ContractError(f"{label} browser version has no numeric major")
    return int(parts[0])


def capture_profile_persona(
    workspace: Path,
    *,
    profile_id: str,
    persona_id: str,
    name: str,
    os_family: str,
    os_version: str,
    architecture: str,
    browser_major: int,
    viewport_width: int,
    viewport_height: int,
    device_scale_factor: float,
    country: str,
    locale: str,
    languages: list[str],
    timezone_name: str,
    tags: Iterable[str] = (),
) -> dict[str, Any]:
    from .profiles import load_profile_identity_document

    loaded_identity = load_profile_identity_document(workspace, profile_id)
    if loaded_identity is None:
        raise ContractError(
            "profile must have a pinned identity contract before persona capture"
        )
    identity_document, _identity_canonical = loaded_identity
    orientation = "landscape" if viewport_width >= viewport_height else "portrait"
    expected_identity = identity_document["expected"]
    try:
        screen = {
            "width": int(expected_identity["window.screen.width"]),
            "height": int(expected_identity["window.screen.height"]),
        }
    except (KeyError, TypeError, ValueError):
        raise ContractError(
            "profile identity must include exact window.screen width and height"
        ) from None
    persona = build_persona(
        persona_id=persona_id,
        name=name,
        tags=tags,
        device={
            "class": "desktop",
            "os_family": os_family,
            "os_version": os_version,
            "architecture": architecture,
            "is_mobile": False,
            "has_touch": False,
            "viewport": {
                "width": viewport_width,
                "height": viewport_height,
                "device_scale_factor": device_scale_factor,
                "orientation": orientation,
            },
            "screen": screen,
        },
        kernel={
            "engine": "chromium",
            "product": "browser-core",
            "minimum_major": browser_major,
            "maximum_major": browser_major,
        },
        geography={
            "country": country,
            "locale": locale,
            "languages": languages,
            "timezone": timezone_name,
        },
        identity_contract=identity_document,
        provenance={
            "kind": "owned-capture",
            "source": f"profile:{profile_id}",
            "source_sha256": hashlib.sha256(
                _canonical(identity_document) + b"\n"
            ).hexdigest(),
            "captured_at": _utc_now(),
        },
    )
    validated = reject_incoherent_persona(persona)
    if load_profile_identity_document(workspace, profile_id) != loaded_identity:
        raise ContractError("profile identity changed during persona capture")
    return validated


def capture_kernel_persona(
    repository_root: Path,
    *,
    persona_id: str,
    name: str,
    kernel_id: str,
    device_preset: str,
    os_family: str,
    os_version: str,
    architecture: str,
    country: str,
    locale: str,
    timezone_name: str,
    tags: Iterable[str] = (),
    browser_core_executable: Path | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Create a provenance-bound persona from a live owned Playwright probe."""
    from .kernels import (
        device_from_playwright,
        discover_kernels,
        probe_playwright_kernel,
    )

    discovery = ({"browser_core_executable": browser_core_executable}
                 if browser_core_executable is not None else {})
    kernels = {item["id"]: item for item in discover_kernels(repository_root, **discovery)}
    kernel = kernels.get(kernel_id)
    if kernel is None:
        raise ContractError("kernel persona capture requested an unknown kernel")
    device = device_from_playwright(
        device_preset, locale=locale, timezone=timezone_name
    )
    if kernel["engine"] != device["default_engine"]:
        raise ContractError(
            "kernel persona capture requires the preset's default engine"
        )
    if device["class"] == "tablet":
        raise ContractError(
            "tablet persona capture is not supported by persona schema version 1"
        )
    probe = probe_playwright_kernel(kernel, device)
    return persona_from_kernel_probe(
        kernel,
        device,
        probe,
        persona_id=persona_id,
        name=name,
        kernel_id=kernel_id,
        os_family=os_family,
        os_version=os_version,
        architecture=architecture,
        country=country,
        locale=locale,
        timezone_name=timezone_name,
        tags=tags,
    )


def persona_from_kernel_probe(
    kernel: dict[str, Any],
    device: dict[str, Any],
    probe: dict[str, Any],
    *,
    persona_id: str,
    name: str,
    kernel_id: str,
    os_family: str,
    os_version: str,
    architecture: str,
    country: str,
    locale: str,
    timezone_name: str,
    tags: Iterable[str] = (),
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Build a persona from a probe result that has already been taken.

    Split out of ``capture_kernel_persona`` so a batch can run many probes
    through one browser and still mint personas by exactly the same rules.
    """
    from .kernels import KERNEL_PROBE_SCHEMA

    if not all(type(value) is dict for value in (kernel, device, probe)):
        raise ContractError("kernel persona inputs must be documents")
    if probe.get("passed") is not True:
        raise ContractError(
            "kernel persona capture probe did not pass every realization check"
        )
    if (
        probe.get("schema") != KERNEL_PROBE_SCHEMA
        or not isinstance(kernel_id, str)
        or not kernel_id
        or kernel.get("id") != kernel_id
        or probe.get("kernel_id") != kernel_id
        or probe.get("engine") != kernel.get("engine")
        or probe.get("device_id") != device.get("id")
        or probe.get("device_realization") != device.get("realization")
    ):
        raise ContractError("kernel probe provenance does not match selected kernel/device")
    device_class = device.get("class")
    if type(device_class) is not str:
        raise ContractError("kernel persona device class is invalid")
    required_checks = set(KERNEL_PROBE_REQUIRED_CHECKS)
    if device_class in {"mobile", "tablet"}:
        required_checks.add("multi_touch")
    if kernel.get("engine") == "chromium":
        required_checks.update(("user_agent_matches_client_hints", "client_hints_mobile"))
    source = kernel.get("source")
    if not (
        isinstance(source, dict)
        and source.get("kind") == "attested-browser-core"
        and device_class == "desktop"
    ):
        required_checks.add("user_agent")
    checks = probe.get("checks")
    if (
        not isinstance(checks, dict)
        or not checks
        or not required_checks.issubset(checks)
        or any(not isinstance(key, str) or not key or value is not True
               for key, value in checks.items())
    ):
        raise ContractError("kernel probe checks contradict its passing result")
    # Work from the exact JSON snapshot whose digest becomes provenance. The
    # caller may retain and mutate its kernel/device/probe dictionaries later.
    evidence_body = _canonical({"kernel": kernel, "device": device, "probe": probe})
    probe_evidence = json.loads(evidence_body)
    kernel = probe_evidence["kernel"]
    device = probe_evidence["device"]
    probe = probe_evidence["probe"]
    observed = probe["observed"]
    viewport = device.get("viewport")
    screen = device.get("screen")
    if (
        not isinstance(observed, dict)
        or not isinstance(viewport, dict)
        or not isinstance(screen, dict)
        or any(
            type(observed.get(observed_field)) is not int
            or observed[observed_field] != expected.get(device_field)
            for observed_field, expected, device_field in (
                ("innerWidth", viewport, "width"),
                ("innerHeight", viewport, "height"),
                ("screenWidth", screen, "width"),
                ("screenHeight", screen, "height"),
            )
        )
        or not is_finite_number(observed.get("devicePixelRatio"))
        or observed["devicePixelRatio"] != device.get("device_scale_factor")
    ):
        raise ContractError("kernel probe observation does not match selected device")
    if observed.get("webglIdentitySchema") != "webgl2-preferred-unmasked-v1":
        raise ContractError("kernel probe requires recapture with canonical WebGL identity semantics")
    if not isinstance(observed.get("intlLocale"), str) or not observed["intlLocale"]:
        raise ContractError("kernel probe requires recapture with measured Intl locale")
    expected = {
        "window.locale": observed["intlLocale"],
        "window.languages": observed["languages"],
        "window.platform": observed["platform"],
        "window.maxTouchPoints": observed["maxTouchPoints"],
        "window.hardwareConcurrency": observed["hardwareConcurrency"],
        "window.pluginsLength": observed["pluginsLength"],
        "window.mimeTypesLength": observed["mimeTypesLength"],
        "window.screen.width": observed["screenWidth"],
        "window.screen.height": observed["screenHeight"],
        "window.screen.colorDepth": observed["colorDepth"],
        "window.screen.pixelDepth": observed["pixelDepth"],
        "window.screen.devicePixelRatio": observed["devicePixelRatio"],
        "window.timezone": observed["timezone"],
        "rendering.webgl.vendor": observed["webglVendor"],
        "rendering.webgl.renderer": observed["webglRenderer"],
        "rendering.webgl.version": observed["webglVersion"],
    }
    optional_fields = {
        # The probe has always measured this value and the evaluator has always
        # exposed it, but persona construction used to drop it. Retain the
        # measured string so the catalog can recheck UA/kernel and UA/device
        # coherence instead of inferring presentation from the capture binary.
        "window.userAgent": observed.get("userAgent"),
        "window.deviceMemory": observed.get("deviceMemory"),
        "window.pdfViewerEnabled": observed.get("pdfViewerEnabled"),
        # Standard fingerprint surface that no capture recorded until now, which
        # is why `available-screen-exceeds-screen` had never fired on a real
        # persona. Under emulation these equal the screen exactly -- correct for
        # a phone, and on a desktop a statement that the window manager showed no
        # taskbar, which is recorded rather than adjusted.
        "window.screen.availWidth": observed.get("availWidth"),
        "window.screen.availHeight": observed.get("availHeight"),
        "userAgentData.mobile": observed.get("userAgentDataMobile"),
        "userAgentData.platform": observed.get("userAgentDataPlatform"),
        # The brand vector is a launch-time constant every navigation emits in
        # `sec-ch-ua`, and until now no persona recorded it -- so the catalog had
        # no way to notice that the binary realizing an identity announces
        # something the identity never claimed. Measured on five browsers here:
        # the attested build reports ["Chromium/153", "Not_A Brand/8"], retail
        # Chrome adds a "Google Chrome/150" entry we have no right to, Playwright's
        # Chromium announces "HeadlessChrome/147", and Firefox and WebKit have no
        # userAgentData at all.
        "userAgentData.brands": observed.get("userAgentDataBrands"),
    }
    expected.update(
        {key: value for key, value in optional_fields.items() if value is not None}
    )
    # The preset name is a guess about the OS; the platform string is a
    # measurement of it. Where they disagree, record what was measured.
    os_family = os_family_from_platform(observed.get("platform"), fallback=os_family)
    source_digest = hashlib.sha256(evidence_body).hexdigest()
    browser_major = _browser_major_from_evidence(
        probe["browser_version"], "kernel probe"
    )
    # The engine says how the browser renders; the kernel says which browser it
    # is. Those coincide for every Playwright kernel and diverge for exactly one:
    # the attested Browser Core build is a Chromium engine and a distinct
    # product. Deriving the product from the engine alone labelled a Core capture
    # "chromium", which is wrong about provenance and -- because
    # `persona_compatible` gates launches on this exact field -- also meant every
    # persona the attested build captured could not be launched by the attested
    # build. Note this is a realization key, not a page-observable claim: a site
    # sees Chrome either way, and what it selects is which binary can realize it.
    product = _ENGINE_PRODUCTS[kernel["engine"]]
    if kernel.get("product") == "browser-core":
        product = "browser-core"
    viewport = device["viewport"]
    persona = build_persona(
        persona_id=persona_id,
        name=name,
        tags=tags,
        device={
            "class": device["class"],
            "os_family": os_family,
            "os_version": os_version,
            "architecture": architecture,
            "is_mobile": device["is_mobile"],
            "has_touch": device["has_touch"],
            "viewport": {
                "width": viewport["width"],
                "height": viewport["height"],
                "device_scale_factor": device["device_scale_factor"],
                "orientation": "landscape"
                if viewport["width"] >= viewport["height"]
                else "portrait",
            },
            "screen": device["screen"],
        },
        kernel={
            "engine": kernel["engine"],
            "product": product,
            "minimum_major": browser_major,
            "maximum_major": browser_major,
        },
        geography={
            "country": country,
            "locale": locale,
            "languages": observed["languages"],
            "timezone": timezone_name,
        },
        identity_contract={"schema_version": 1, "expected": expected},
        provenance={
            "kind": "owned-capture",
            "source": f"kernel-probe:{kernel_id}:{device['id']}",
            "source_sha256": source_digest,
            "captured_at": _utc_now(),
        },
    )
    return reject_incoherent_persona(persona), probe_evidence


def capture_physical_android_persona(
    *,
    persona_id: str,
    name: str,
    country: str,
    tags: Iterable[str] = (),
    timeout_seconds: float = 45.0,
) -> tuple[dict[str, Any], dict[str, Any]]:
    from .physical_mobile import PHYSICAL_PROBE_SCHEMA, probe_physical_android

    probe = probe_physical_android(timeout_seconds=timeout_seconds)
    if probe["passed"] is not True or probe["realization"] != "physical-device":
        raise ContractError("physical Android persona capture probe did not pass")
    checks = probe.get("checks")
    if (
        probe.get("schema") != PHYSICAL_PROBE_SCHEMA
        or probe.get("platform") != "android"
        or not isinstance(checks, dict)
        or not checks
        or not PHYSICAL_PROBE_REQUIRED_CHECKS.issubset(checks)
        or any(not isinstance(key, str) or not key or value is not True
               for key, value in checks.items())
    ):
        raise ContractError("physical Android probe receipt is contradictory")
    observed = probe["observed"]
    if observed.get("webglIdentitySchema") != "webgl2-preferred-unmasked-v1":
        raise ContractError("physical probe requires recapture with canonical WebGL identity semantics")
    if not isinstance(observed.get("intlLocale"), str) or not observed["intlLocale"]:
        raise ContractError("physical probe requires recapture with measured Intl locale")
    device = probe["device"]
    languages = observed["languages"]
    expected = {
        "window.userAgent": observed["userAgent"],
        "window.locale": observed["intlLocale"],
        "window.languages": languages,
        "window.platform": observed["platform"],
        "window.maxTouchPoints": observed["maxTouchPoints"],
        "window.hardwareConcurrency": observed["hardwareConcurrency"],
        "window.screen.width": observed["screenWidth"],
        "window.screen.height": observed["screenHeight"],
        "window.screen.devicePixelRatio": observed["devicePixelRatio"],
        "window.timezone": observed["timezone"],
        "rendering.webgl.vendor": observed["webglVendor"],
        "rendering.webgl.renderer": observed["webglRenderer"],
        "rendering.webgl.version": observed["webglVersion"],
    }
    browser_major = _browser_major_from_evidence(
        device["browser_version"], "physical Android"
    )
    architecture = "arm64" if "arm64" in device["architecture"].casefold() else "x86_64"
    viewport_width = int(observed["innerWidth"])
    viewport_height = int(observed["innerHeight"])
    persona = build_persona(
        persona_id=persona_id,
        name=name,
        tags=tags,
        device={
            "class": "mobile",
            "os_family": "android",
            "os_version": device["os_version"],
            "architecture": architecture,
            "is_mobile": True,
            "has_touch": True,
            "viewport": {
                "width": viewport_width,
                "height": viewport_height,
                "device_scale_factor": observed["devicePixelRatio"],
                "orientation": "landscape"
                if viewport_width >= viewport_height
                else "portrait",
            },
            "screen": {
                "width": int(observed["screenWidth"]),
                "height": int(observed["screenHeight"]),
            },
        },
        kernel={
            "engine": "chromium",
            "product": "chrome",
            "minimum_major": browser_major,
            "maximum_major": browser_major,
        },
        geography={
            "country": country,
            "locale": languages[0],
            "languages": languages,
            "timezone": observed["timezone"],
        },
        identity_contract={"schema_version": 1, "expected": expected},
        provenance={
            "kind": "owned-capture",
            "source": "physical-android-owned-probe",
            "source_sha256": hashlib.sha256(_canonical(probe)).hexdigest(),
            "captured_at": _utc_now(),
        },
    )
    return reject_incoherent_persona(persona), probe


def _persona_workspace_path(workspace: Path) -> Path:
    if not isinstance(workspace, Path):
        raise ContractError("persona workspace must be a Path")
    path = Path(os.path.abspath(workspace))
    for ancestor in reversed((path, *path.parents)):
        directory_identity(ancestor, label="persona workspace")
    return path


def _persona_workspace_ancestry(workspace: Path) -> tuple[Any, ...]:
    path = _persona_workspace_path(workspace)
    return tuple(
        directory_identity(ancestor, label="persona workspace")
        for ancestor in reversed((path, *path.parents))
    )


def _catalog_path(workspace: Path, persona_id: str) -> Path:
    if (not isinstance(persona_id, str) or not PROFILE_ID_RE.fullmatch(persona_id)
            or has_windows_device_basename(persona_id)):
        raise ContractError("persona ID is invalid")
    return _persona_workspace_path(workspace) / "personas" / "catalog" / f"{persona_id}.json"


def store_persona_evidence(
    workspace: Path,
    evidence: Any,
    *,
    expected_sha256: str,
) -> dict[str, Any]:
    if not isinstance(workspace, Path):
        raise ContractError("persona evidence workspace must be a Path")
    if not isinstance(expected_sha256, str) or not SHA256_RE.fullmatch(expected_sha256):
        raise ContractError("persona evidence digest is invalid")
    canonical = _canonical(evidence)
    reject_sensitive_keys(decode_strict_json_bytes(canonical, label="persona evidence"))
    if expected_sha256 not in {
        hashlib.sha256(canonical).hexdigest(),
        hashlib.sha256(canonical + b"\n").hexdigest(),
    }:
        raise ContractError("persona evidence digest does not match its provenance")
    digest = expected_sha256
    path = _persona_workspace_path(workspace) / "personas" / "evidence" / f"{digest}.json"
    workspace_before = _persona_workspace_ancestry(workspace)
    authorities = _persona_read_authorities(path.parent, label="persona evidence")
    body = canonical + b"\n"
    if len(body) > MAX_PERSONA_EVIDENCE_BYTES:
        raise ContractError(
            f"persona evidence exceeds {MAX_PERSONA_EVIDENCE_BYTES} bytes"
        )
    snapshot = read_bounded_control_snapshot_result(
        path,
        maximum=MAX_PERSONA_EVIDENCE_BYTES,
        label="persona evidence",
        require_single_link=True,
    )
    if snapshot.state == "complete":
        if snapshot.body != body:
            raise ContractError("persona evidence content-address collision")
    elif snapshot.state == "missing":
        prepare_owned_directory_parent(path.parent, label="persona evidence parent")
        authorities = _persona_read_authorities(path.parent, label="persona evidence")
        workspace_before = _persona_workspace_ancestry(workspace)
        try:
            publish_bytes_exclusive(
                path,
                body,
                maximum=MAX_PERSONA_EVIDENCE_BYTES,
                label="persona evidence",
            )
        except ContractError as exc:
            if "cleanup incomplete" in str(exc):
                raise
            raced = read_bounded_control_snapshot_result(
                path,
                maximum=MAX_PERSONA_EVIDENCE_BYTES,
                label="persona evidence",
                require_single_link=True,
            )
            if raced.state != "complete" or raced.body != body:
                raise ContractError(
                    "persona evidence content-address collision"
                ) from None
    else:
        raise ContractError(f"persona evidence is {snapshot.state}")
    final = read_bounded_control_snapshot_result(
        path,
        maximum=MAX_PERSONA_EVIDENCE_BYTES,
        label="persona evidence",
        require_single_link=True,
    )
    if (
        final.state != "complete"
        or final.body != body
        or (
            snapshot.state == "complete" and final.identity != snapshot.identity
        )
    ):
        raise ContractError("persona evidence changed before completion")
    if _persona_read_authorities(path.parent, label="persona evidence") != authorities:
        raise ContractError("persona evidence parent changed during store")
    if _persona_workspace_ancestry(workspace) != workspace_before:
        raise ContractError("persona evidence workspace changed during store")
    return {
        "schema": "browser-core.persona-evidence-ref/1",
        "sha256": digest,
        "path": str(path),
        "bytes": len(body),
    }


def load_persona_evidence(workspace: Path, digest: str) -> Any:
    return _load_persona_evidence_counted(workspace, digest)[0]


def _load_persona_evidence_counted(workspace: Path, digest: str) -> tuple[Any, int]:
    if not isinstance(workspace, Path):
        raise ContractError("persona evidence workspace must be a Path")
    if not isinstance(digest, str) or not SHA256_RE.fullmatch(digest):
        raise ContractError("persona evidence digest is invalid")
    path = _persona_workspace_path(workspace) / "personas" / "evidence" / f"{digest}.json"
    workspace_before = _persona_workspace_ancestry(workspace)
    authorities = _persona_read_authorities(path.parent, label="persona evidence")
    snapshot = read_bounded_control_snapshot_result(
        path,
        maximum=MAX_PERSONA_EVIDENCE_BYTES,
        label="persona evidence",
        require_single_link=True,
    )
    if snapshot.state == "missing":
        if _persona_read_authorities(path.parent, label="persona evidence") != authorities:
            raise ContractError("persona evidence parent changed during read")
        if _persona_workspace_ancestry(workspace) != workspace_before:
            raise ContractError("persona evidence workspace changed during read")
        raise _MissingPersonaEvidence("persona evidence is missing")
    if snapshot.state != "complete" or snapshot.body is None:
        raise ContractError(f"persona evidence is {snapshot.state}")
    evidence = decode_strict_json_bytes(snapshot.body, label="persona evidence")
    if not _evidence_digest_matches(evidence, digest):
        raise ContractError("persona evidence integrity does not match")
    if snapshot.body != _canonical(evidence) + b"\n":
        raise ContractError("persona evidence is not canonical")
    reject_sensitive_keys(evidence)
    final = read_bounded_control_snapshot_result(
        path,
        maximum=MAX_PERSONA_EVIDENCE_BYTES,
        label="persona evidence",
        require_single_link=True,
    )
    if (
        final.state != "complete"
        or final.body != snapshot.body
        or final.identity != snapshot.identity
    ):
        raise ContractError("persona evidence changed before completion")
    if _persona_read_authorities(path.parent, label="persona evidence") != authorities:
        raise ContractError("persona evidence parent changed during read")
    if _persona_workspace_ancestry(workspace) != workspace_before:
        raise ContractError("persona evidence workspace changed during read")
    return evidence, len(snapshot.body) + len(final.body)


def _persona_report_inventory(directory: Path) -> BoundedJsonDirectoryInventory:
    return inventory_bounded_json_directory(
        directory,
        maximum_entries=MAX_PERSONA_CATALOG_ENTRIES,
        maximum_files=MAX_PERSONA_CATALOG_FILES,
        maximum_file_bytes=MAX_PERSONA_DOCUMENT_BYTES,
        maximum_total_bytes=MAX_PERSONA_CATALOG_BYTES,
        label="persona catalog",
    )


def _require_persona_report_catalog(
    directory: Path,
    personas: list[dict[str, Any]],
    before: BoundedJsonDirectoryInventory,
    authorities: tuple[Any, Any],
) -> None:
    if _persona_read_authorities(directory, label="persona catalog") != authorities:
        raise ContractError("persona catalog changed during audit")
    # Rebind the verified rows without materializing a second catalog copy.
    for persona in personas:
        snapshot = read_bounded_control_snapshot_result(
            directory / f"{persona['id']}.json",
            maximum=MAX_PERSONA_DOCUMENT_BYTES,
            label="persona document",
            require_single_link=True,
        )
        if snapshot.state != "complete" or snapshot.body != canonical_json_bytes(
            persona
        ):
            raise ContractError("persona catalog changed during audit")
    if (
        _persona_report_inventory(directory) != before
        or _persona_read_authorities(directory, label="persona catalog") != authorities
    ):
        raise ContractError("persona catalog changed during audit")


def _rebind_persona_audit_sources(
    workspace: Path, personas: list[dict[str, Any]], report: dict[str, Any]
) -> None:
    saved_digests = {
        persona["provenance"]["source_sha256"]
        for persona, row in zip(personas, report["verified"])
        if row["evidence_kind"] in {
            "bundled-profile-identity-contract", "content-addressed-evidence"
        }
    }
    saved_recheck_bytes = 0
    for digest in sorted(saved_digests):
        if saved_recheck_bytes >= MAX_PERSONA_AUDIT_EVIDENCE_RECHECK_BYTES:
            raise ContractError(
                "persona catalog audit saved evidence recheck byte limit exceeded"
            )
        try:
            _, logical_bytes = _load_persona_evidence_counted(workspace, digest)
        except ContractError:
            raise ContractError("persona saved evidence changed during audit") from None
        saved_recheck_bytes += logical_bytes
        if saved_recheck_bytes > MAX_PERSONA_AUDIT_EVIDENCE_RECHECK_BYTES:
            raise ContractError(
                "persona catalog audit saved evidence recheck byte limit exceeded"
            )
    # The catalog reread can outlast source verification. Rebind only live
    # profile identities that the report actually labelled as verified.
    live_profiles: dict[str, str] = {}
    for persona, row in zip(personas, report["verified"]):
        if row["evidence_kind"] != "profile-identity-contract":
            continue
        profile_id = persona["provenance"]["source"].split(":", 1)[1]
        digest = persona["provenance"]["source_sha256"]
        previous = live_profiles.setdefault(profile_id, digest)
        if previous != digest:
            raise ContractError("persona source profile changed during audit")
    if live_profiles:
        from .profiles import _profile_identity_snapshot

        # One snapshot contains four bounded registry reads and one identity
        # read. It rechecks the profile after reading its pinned contract;
        # a second full snapshot adds no stronger cross-profile atomicity to
        # this sequential audit.
        recheck_bytes = [0]
        for profile_id, digest in sorted(live_profiles.items()):
            if recheck_bytes[0] >= MAX_PERSONA_AUDIT_LIVE_PROFILE_RECHECK_BYTES:
                raise ContractError(
                    "persona catalog audit live profile recheck byte limit exceeded"
                )
            try:
                snapshot = _profile_identity_snapshot(
                    workspace, profile_id, read_bytes=recheck_bytes
                )
            except ContractError:
                raise ContractError("persona source profile changed during audit") from None
            if recheck_bytes[0] > MAX_PERSONA_AUDIT_LIVE_PROFILE_RECHECK_BYTES:
                raise ContractError(
                    "persona catalog audit live profile recheck byte limit exceeded"
                )
            if snapshot is None or not _evidence_digest_matches(
                load_canonical_json_document(snapshot[2], label="profile identity"),
                digest,
            ):
                raise ContractError("persona source profile changed during audit")


def audit_persona_catalog(workspace: Path) -> dict[str, Any]:
    if not isinstance(workspace, Path):
        raise ContractError("persona workspace must be a Path")
    directory = _persona_workspace_path(workspace) / "personas" / "catalog"
    authorities = _persona_read_authorities(directory, label="persona catalog")
    before = _persona_report_inventory(directory)
    personas = list_personas(workspace, include_deprecated=True)
    report = _audit_persona_snapshot(workspace, personas)
    _require_persona_report_catalog(directory, personas, before, authorities)
    _rebind_persona_audit_sources(workspace, personas, report)
    return report


def _audit_persona_snapshot(
    workspace: Path, personas: list[dict[str, Any]]
) -> dict[str, Any]:
    verified = []
    verified_evidence: set[str] = set()
    evidence_scan_bytes = 0
    verified_profiles: dict[str, tuple[dict[str, Any], bytes]] = {}
    profile_scan_bytes = 0

    def verify_saved_evidence(digest: str) -> None:
        nonlocal evidence_scan_bytes
        if digest in verified_evidence:
            return
        if evidence_scan_bytes >= MAX_PERSONA_AUDIT_EVIDENCE_SCAN_BYTES:
            raise ContractError("persona catalog audit saved evidence scan byte limit exceeded")
        _, logical_bytes = _load_persona_evidence_counted(workspace, digest)
        evidence_scan_bytes += logical_bytes
        if evidence_scan_bytes > MAX_PERSONA_AUDIT_EVIDENCE_SCAN_BYTES:
            raise ContractError("persona catalog audit saved evidence scan byte limit exceeded")
        verified_evidence.add(digest)

    for persona in personas:
        provenance = persona["provenance"]
        source = provenance["source"]
        digest = provenance["source_sha256"]
        if provenance["kind"] == "owned-capture" and source.startswith("profile:"):
            from .profiles import _load_profile_identity_document_counted

            profile_id = source.split(":", 1)[1]
            profile_registry = (
                _persona_workspace_path(workspace) / "profiles" / "registry" / f"{profile_id}.json"
            )
            profile_authorities = _persona_read_authorities(
                profile_registry.parent, label="profile registry"
            )
            profile_present = os.path.lexists(profile_registry)
            loaded_identity = None
            if profile_present:
                loaded_identity = verified_profiles.get(profile_id)
                if loaded_identity is None:
                    if profile_scan_bytes >= MAX_PERSONA_AUDIT_PROFILE_SCAN_BYTES:
                        raise ContractError(
                            "persona catalog audit profile scan byte limit exceeded"
                        )
                    loaded_identity, logical_bytes = _load_profile_identity_document_counted(
                        workspace, profile_id
                    )
                    profile_scan_bytes += logical_bytes
                    if profile_scan_bytes > MAX_PERSONA_AUDIT_PROFILE_SCAN_BYTES:
                        raise ContractError(
                            "persona catalog audit profile scan byte limit exceeded"
                        )
                    if loaded_identity is not None:
                        verified_profiles[profile_id] = loaded_identity
            if loaded_identity is None:
                verify_saved_evidence(digest)
                if (
                    _persona_read_authorities(
                        profile_registry.parent, label="profile registry"
                    ) != profile_authorities
                    or (not profile_present and os.path.lexists(profile_registry))
                ):
                    raise ContractError("persona source profile changed during audit")
                evidence_kind = "bundled-profile-identity-contract"
            else:
                identity_document, _identity_canonical = loaded_identity
                if not _evidence_digest_matches(identity_document, digest):
                    raise ContractError(
                        f"persona source profile digest changed: {persona['id']}"
                    )
                evidence_kind = "profile-identity-contract"
        else:
            verify_saved_evidence(digest)
            evidence_kind = "content-addressed-evidence"
        verified.append(
            {
                "id": persona["id"],
                "persona_sha256_16": persona["integrity_sha256"][:16],
                "source_sha256_16": digest[:16],
                "evidence_kind": evidence_kind,
                "state": persona["state"],
                "engine": persona["kernel"]["engine"],
                "device_class": persona["device"]["class"],
            }
        )
    report = {
        "schema": AUDIT_SCHEMA,
        "passed": True,
        "personas": len(personas),
        "active": sum(item["state"] == "active" for item in personas),
        "engines": sorted({item["kernel"]["engine"] for item in personas}),
        "device_classes": sorted({item["device"]["class"] for item in personas}),
        "verified": verified,
        "verified_sha256": hashlib.sha256(_canonical(verified)).hexdigest(),
    }
    return validate_catalog_audit_report(report)


def validate_catalog_audit_report(report: Any) -> dict[str, Any]:
    """Validate the portable catalog audit from its verified row population."""
    fields = {
        "schema",
        "passed",
        "personas",
        "active",
        "engines",
        "device_classes",
        "verified",
        "verified_sha256",
    }
    if type(report) is not dict or set(report) != fields:
        raise ContractError("persona catalog audit fields are invalid")
    if report.get("schema") != AUDIT_SCHEMA:
        raise ContractError("persona catalog audit schema is invalid")
    if report.get("passed") is not True:
        raise ContractError("persona catalog audit verdict is invalid")
    personas = _coverage_count(
        report.get("personas"),
        "persona catalog audit population",
        maximum=MAX_PERSONA_CATALOG_ENTRIES,
    )
    active = _coverage_count(
        report.get("active"),
        "persona catalog audit active count",
        maximum=MAX_PERSONA_CATALOG_ENTRIES,
    )
    if active > personas:
        raise ContractError("persona catalog audit populations are inconsistent")
    verified = report.get("verified")
    if type(verified) is not list or len(verified) != personas:
        raise ContractError("persona catalog audit verified rows are invalid")
    verified_sha256 = report.get("verified_sha256")
    if (
        not isinstance(verified_sha256, str)
        or not SHA256_RE.fullmatch(verified_sha256)
        or verified_sha256 != hashlib.sha256(_canonical(verified)).hexdigest()
    ):
        raise ContractError("persona catalog audit verified digest is invalid")
    row_fields = {
        "id",
        "persona_sha256_16",
        "source_sha256_16",
        "evidence_kind",
        "state",
        "engine",
        "device_class",
    }
    seen_ids: set[str] = set()
    safe_rows: list[dict[str, Any]] = []
    for index, row in enumerate(verified):
        if type(row) is not dict or set(row) != row_fields:
            raise ContractError(f"persona catalog audit row {index} is invalid")
        persona_id = _require_text(
            row.get("id"), "persona catalog audit ID", maximum=128
        )
        folded_id = persona_id.casefold()
        if folded_id in seen_ids:
            raise ContractError("persona catalog audit IDs are not unique")
        seen_ids.add(folded_id)
        for field in ("persona_sha256_16", "source_sha256_16"):
            digest = row.get(field)
            if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{16}", digest):
                raise ContractError("persona catalog audit digest is invalid")
        if not _allowed_text(row.get("evidence_kind"), {
            "content-addressed-evidence",
            "profile-identity-contract",
            "bundled-profile-identity-contract",
        }):
            raise ContractError("persona catalog audit evidence kind is invalid")
        if not _allowed_text(row.get("state"), {"active", "deprecated"}):
            raise ContractError("persona catalog audit state is invalid")
        if not _allowed_text(row.get("engine"), ALLOWED_ENGINES):
            raise ContractError("persona catalog audit engine is invalid")
        if not _allowed_text(row.get("device_class"), {"desktop", "mobile"}):
            raise ContractError("persona catalog audit device class is invalid")
        safe_rows.append(row)
    if safe_rows != sorted(safe_rows, key=lambda row: row["id"].casefold()):
        raise ContractError("persona catalog audit rows are not canonical")
    expected_engines = sorted({row["engine"] for row in safe_rows})
    expected_classes = sorted({row["device_class"] for row in safe_rows})
    if (
        active != sum(row["state"] == "active" for row in safe_rows)
        or report.get("engines") != expected_engines
        or report.get("device_classes") != expected_classes
    ):
        raise ContractError("persona catalog audit summaries are inconsistent")
    return report


def add_persona(workspace: Path, document: dict[str, Any]) -> dict[str, Any]:
    persona = copy.deepcopy(validate_persona(document))
    path = _catalog_path(workspace, persona["id"])
    existing, _snapshot = _load_persona_snapshot(
        workspace, persona["id"], missing_ok=True
    )
    if existing is not None:
        if existing["integrity_sha256"] == persona["integrity_sha256"]:
            return existing
        raise ContractError(f"persona ID conflict: {persona['id']}")
    try:
        _write_json_atomic(path, persona)
    except ContractError as exc:
        if "cleanup incomplete" in str(exc):
            raise
        raced, _raced_snapshot = _load_persona_snapshot(
            workspace,
            persona["id"],
            missing_ok=True,
        )
        if raced is None:
            raise
        if raced["integrity_sha256"] == persona["integrity_sha256"]:
            return raced
        raise ContractError(f"persona ID conflict: {persona['id']}") from None
    if load_persona(workspace, persona["id"]) != persona:
        raise ContractError("persona changed after publication")
    return persona


def load_persona(workspace: Path, persona_id: str) -> dict[str, Any]:
    document, _snapshot = _load_persona_snapshot(workspace, persona_id)
    assert document is not None
    return document


def _validated_persona_document(body: bytes) -> dict[str, Any]:
    global _VALIDATED_PERSONA_BYTES_SIZE
    with _VALIDATED_PERSONA_BYTES_LOCK:
        cached = body in _VALIDATED_PERSONA_BYTES
        if cached:
            _VALIDATED_PERSONA_BYTES.move_to_end(body)
    if cached:
        # These exact bytes passed strict decoding, canonicality, schema and
        # integrity checks. Parse anew so no mutable document crosses callers.
        return json.loads(body)
    document = validate_persona(load_canonical_json_document(body, label="persona document"))
    if len(body) <= _VALIDATED_PERSONA_CACHE_BYTES:
        with _VALIDATED_PERSONA_BYTES_LOCK:
            if body not in _VALIDATED_PERSONA_BYTES:
                _VALIDATED_PERSONA_BYTES[body] = None
                _VALIDATED_PERSONA_BYTES_SIZE += len(body)
            else:
                _VALIDATED_PERSONA_BYTES.move_to_end(body)
            while (_VALIDATED_PERSONA_BYTES_SIZE > _VALIDATED_PERSONA_CACHE_BYTES
                   or len(_VALIDATED_PERSONA_BYTES) > _VALIDATED_PERSONA_CACHE_ENTRIES):
                evicted, _ = _VALIDATED_PERSONA_BYTES.popitem(last=False)
                _VALIDATED_PERSONA_BYTES_SIZE -= len(evicted)
    return document


def _load_persona_snapshot(
    workspace: Path,
    persona_id: str,
    *,
    missing_ok: bool = False,
) -> tuple[dict[str, Any] | None, BoundedControlSnapshot]:
    path = _catalog_path(workspace, persona_id)
    workspace_before = _persona_workspace_ancestry(workspace)
    authorities = _persona_read_authorities(path.parent, label="persona catalog")
    document, snapshot = _read_persona_snapshot(
        path, persona_id, missing_ok=missing_ok
    )
    final = read_bounded_control_snapshot_result(
        path,
        maximum=MAX_PERSONA_DOCUMENT_BYTES,
        label="persona document",
        require_single_link=True,
    )
    if (
        final.state != snapshot.state
        or final.body != snapshot.body
        or final.identity != snapshot.identity
    ):
        raise ContractError("persona document changed during read")
    if _persona_read_authorities(path.parent, label="persona catalog") != authorities:
        raise ContractError("persona catalog changed during read")
    if _persona_workspace_ancestry(workspace) != workspace_before:
        raise ContractError("persona workspace changed during read")
    return document, snapshot


def _persona_read_authorities(directory: Path, *, label: str) -> tuple[Any, Any]:
    # A missing managed directory is normal in an empty workspace. Existing
    # components must stay inside the selected workspace, including junctions.
    parent = directory.parent
    parent_identity = directory_identity(parent, label=f"{label} parent")
    if parent_identity is not None:
        require_owned_directory_ancestors(parent, label=f"{label} parent")
    directory_id = directory_identity(directory, label=label)
    if directory_id is not None:
        require_owned_directory_ancestors(directory, label=label)
    return parent_identity, directory_id


def _read_persona_snapshot(
    path: Path, persona_id: str, *, missing_ok: bool = False,
) -> tuple[dict[str, Any] | None, BoundedControlSnapshot]:
    snapshot = read_bounded_control_snapshot_result(
        path,
        maximum=MAX_PERSONA_DOCUMENT_BYTES,
        label="persona document",
        require_single_link=True,
    )
    if snapshot.state == "missing" and missing_ok:
        return None, snapshot
    if snapshot.state != "complete" or snapshot.body is None:
        raise ContractError(f"persona document is {snapshot.state}")
    try:
        document = _validated_persona_document(snapshot.body)
    except ContractError:
        raise ContractError(
            "persona document is not a valid managed document"
        ) from None
    if document["id"] != persona_id:
        raise ContractError("persona document filename does not match persona ID")
    return document, snapshot


def set_persona_state(
    workspace: Path,
    persona_id: str,
    state: str,
    *,
    expected_sha256: str,
) -> dict[str, Any]:
    _catalog_path(workspace, persona_id)
    if not isinstance(state, str) or state not in {"active", "deprecated"}:
        raise ContractError("persona state must be active or deprecated")
    if not isinstance(expected_sha256, str) or not SHA256_RE.fullmatch(expected_sha256):
        raise ContractError("persona state expected revision is invalid")
    persona, snapshot = _load_persona_snapshot(workspace, persona_id)
    assert persona is not None
    if expected_sha256 != persona["integrity_sha256"]:
        raise ContractError("persona state change lost an optimistic revision race")
    if persona["state"] == state:
        return persona
    updated = {**persona, "state": state, "state_changed_at": _utc_now()}
    updated["integrity_sha256"] = persona_digest(updated)
    validate_persona(updated)
    _write_json_atomic(_catalog_path(workspace, persona_id), updated, expected=snapshot)
    if load_persona(workspace, persona_id) != updated:
        raise ContractError("persona changed after publication")
    return updated


def list_personas(
    workspace: Path, *, include_deprecated: bool = False
) -> list[dict[str, Any]]:
    if not isinstance(workspace, Path):
        raise ContractError("persona workspace must be a Path")
    if not isinstance(include_deprecated, bool):
        raise ContractError("persona deprecated-state filter is invalid")
    directory = _persona_workspace_path(workspace) / "personas" / "catalog"
    workspace_before = _persona_workspace_ancestry(workspace)
    authorities = _persona_read_authorities(directory, label="persona catalog")
    before = inventory_bounded_json_directory(
        directory,
        maximum_entries=MAX_PERSONA_CATALOG_ENTRIES,
        maximum_files=MAX_PERSONA_CATALOG_FILES,
        maximum_file_bytes=MAX_PERSONA_DOCUMENT_BYTES,
        maximum_total_bytes=MAX_PERSONA_CATALOG_BYTES,
        label="persona catalog",
    )
    # Read current bytes on every call. Schema validation may be reused only
    # for exact previously verified bytes; metadata never authorizes a hit.
    personas = _load_persona_catalog(workspace, directory, before)
    if _persona_read_authorities(directory, label="persona catalog") != authorities:
        raise ContractError("persona catalog changed during load")
    if _persona_workspace_ancestry(workspace) != workspace_before:
        raise ContractError("persona workspace changed during load")
    return sorted(
        (item for item in personas if include_deprecated or item["state"] == "active"),
        key=lambda item: item["id"].casefold(),
    )


def _load_persona_catalog(
    workspace: Path,
    directory: Path,
    before: Any,
) -> list[dict[str, Any]]:
    if not isinstance(workspace, Path):
        raise ContractError("persona workspace must be a Path")
    from concurrent.futures import ThreadPoolExecutor

    def load_one(entry: tuple[str, Any]) -> tuple[dict[str, Any], bytes]:
        name, expected_identity = entry
        persona_id = name[:-5]
        if (PROFILE_ID_RE.fullmatch(persona_id) is None
                or has_windows_device_basename(persona_id)):
            raise ContractError("persona catalog candidate name is invalid")
        # The bounded inventory already resolved this catalog directory once.
        # Use that same directory for every entry, retaining fresh single-link
        # reads and both per-file and final directory identity checks.
        persona, snapshot = _read_persona_snapshot(directory / name, persona_id)
        if snapshot.identity != expected_identity:
            raise ContractError("persona changed during catalog load")
        if persona is None:
            raise ContractError("persona catalog candidate vanished during load")
        return persona, hashlib.sha256(snapshot.body).digest()

    # The catalog is thousands of small strict-snapshot reads; a bounded pool
    # keeps the SATA SSD busy across per-file syscall latency. Per-file
    # identity checks, the surrounding double inventory, duplicate detection
    # and deterministic ordering are unchanged.
    workers = min(16, max(1, len(before.files)))
    if len(before.files) <= 1:
        loaded = [load_one(entry) for entry in before.files]
    else:
        with ThreadPoolExecutor(max_workers=workers) as pool:
            # ThreadPoolExecutor ignores chunksize. Submit bounded batches
            # explicitly, retaining input order and propagating every error.
            loaded = []
            for offset in range(0, len(before.files), workers * 4):
                loaded.extend(pool.map(load_one, before.files[offset:offset + workers * 4]))
    after = inventory_bounded_json_directory(
        directory,
        maximum_entries=MAX_PERSONA_CATALOG_ENTRIES,
        maximum_files=MAX_PERSONA_CATALOG_FILES,
        maximum_file_bytes=MAX_PERSONA_DOCUMENT_BYTES,
        maximum_total_bytes=MAX_PERSONA_CATALOG_BYTES,
        label="persona catalog",
    )
    if after != before:
        raise ContractError("persona catalog changed during load")
    personas = [persona for persona, _digest in loaded]
    if len({item["id"].casefold() for item in personas}) != len(personas):
        raise ContractError("persona catalog contains duplicate IDs")
    # Windows stat identity can survive an in-place edit with restored mtime.
    # Rebind the returned documents to raw bounded bytes after the inventory.
    def recheck_one(entry: tuple[str, Any, bytes]) -> None:
        name, expected_identity, expected_digest = entry
        snapshot = read_bounded_control_snapshot_result(
            directory / name,
            maximum=MAX_PERSONA_DOCUMENT_BYTES,
            label="persona document",
            require_single_link=True,
        )
        if (snapshot.state != "complete" or snapshot.identity != expected_identity
                or hashlib.sha256(snapshot.body).digest() != expected_digest):
            raise ContractError("persona changed during catalog load")

    rechecks = [
        (name, identity, digest)
        for (name, identity), (_persona, digest) in zip(before.files, loaded)
    ]
    if len(rechecks) <= 1:
        for entry in rechecks:
            recheck_one(entry)
    else:
        with ThreadPoolExecutor(max_workers=workers) as pool:
            for offset in range(0, len(rechecks), workers * 4):
                list(pool.map(recheck_one, rechecks[offset:offset + workers * 4]))
    if inventory_bounded_json_directory(
        directory,
        maximum_entries=MAX_PERSONA_CATALOG_ENTRIES,
        maximum_files=MAX_PERSONA_CATALOG_FILES,
        maximum_file_bytes=MAX_PERSONA_DOCUMENT_BYTES,
        maximum_total_bytes=MAX_PERSONA_CATALOG_BYTES,
        label="persona catalog",
    ) != before:
        raise ContractError("persona catalog changed during load")
    return sorted(personas, key=lambda item: item["id"].casefold())


def persona_compatible(
    persona: dict[str, Any],
    *,
    engine: str,
    product: str,
    major: int,
    device_class: str,
) -> bool:
    validate_persona(persona)
    engine = _require_text(engine, "persona compatibility engine")
    product = _require_text(product, "persona compatibility product")
    major = _require_version(major, "persona compatibility major")
    device_class = _require_text(device_class, "persona compatibility device class")
    return _verified_persona_matches(persona, engine, product, major, device_class)


def _verified_persona_matches(
    persona: dict[str, Any], engine: str, product: str, major: int, device_class: str,
) -> bool:
    """Pure predicate; callers own a document they have already validated."""
    kernel = persona["kernel"]
    return bool(
        persona["state"] == "active"
        and persona["device"]["class"] == device_class
        and kernel["engine"] == engine
        and kernel["product"] == product
        and kernel["minimum_major"] <= major <= kernel["maximum_major"]
    )


def compatible_persona_catalog(
    workspace: Path, *, engine: str, product: str, major: int, device_class: str,
) -> tuple[list[str], int]:
    """IDs and active count from one freshly read, validated catalog.

    Documents stay local between validation and classification. Public
    persona_compatible still validates caller-supplied mutable documents.
    """
    engine = _require_text(engine, "persona compatibility engine")
    product = _require_text(product, "persona compatibility product")
    major = _require_version(major, "persona compatibility major")
    device_class = _require_text(device_class, "persona compatibility device class")
    catalog = list_personas(workspace)
    return ([persona["id"] for persona in catalog
             if _verified_persona_matches(persona, engine, product, major, device_class)],
            len(catalog))


def _bounded_public_values(
    values: Iterable[Any], *, maximum: int, invalid: str, excess: str,
    invalid_errors: tuple[type[Exception], ...] = (TypeError,),
) -> list[Any]:
    try:
        iterator = iter(values)
    except invalid_errors:
        raise ContractError(invalid) from None

    def close_rejected() -> None:
        try:
            close = getattr(iterator, "close", None)
            if callable(close):
                close()
        except BaseException:  # Preserve the original rejection or interruption.
            pass

    try:
        result = list(islice(iterator, maximum + 1))
    except BaseException as exc:
        close_rejected()
        if isinstance(exc, invalid_errors):
            raise ContractError(invalid) from None
        raise
    if len(result) > maximum:
        close_rejected()
        raise ContractError(excess)
    return result


def search_personas(
    workspace: Path,
    *,
    engine: str | None = None,
    product: str | None = None,
    major: int | None = None,
    min_major: int | None = None,
    max_major: int | None = None,
    device_class: str | None = None,
    os_family: str | None = None,
    country: str | None = None,
    locale: str | None = None,
    language: str | None = None,
    tags: Iterable[str] = (),
    include_incoherent: bool = False,
) -> list[dict[str, Any]]:
    """Filter active personas on Kameleo-class research axes.

    ``major`` requires the persona kernel range to contain that exact major.
    ``min_major`` / ``max_major`` require the persona range to intersect the
    requested band (inclusive). Locale matches geography.locale case-insensitively;
    language matches any geography.languages entry case-insensitively.

    ``include_incoherent`` decides whether personas carrying a ``contradiction``
    finding are returned. It defaults to ``False``, which is a deliberate change
    of behaviour: this function grew nine axis filters and no way at all to ask
    for personas that do not contradict themselves, so every caller selecting on
    country or device class silently drew from a pool containing identities the
    catalog already knows are impossible. Rules that only run in
    ``persona quality`` do not protect the code path that picks who to launch.

    Only ``contradiction`` is excluded. ``implausible`` personas stay, because
    implausible means "real but rarely shipped" and dropping them by default
    would turn the catalog into a record of expectations rather than
    measurements -- the exact error the touch-points and device-memory rules
    were each retracted for making.
    """
    if not isinstance(workspace, Path):
        raise ContractError("persona search workspace must be a Path")
    if type(include_incoherent) is not bool:
        raise ContractError("persona incoherent-state filter must be boolean")
    optional_text = {
        "engine": engine,
        "product": product,
        "device class": device_class,
        "OS family": os_family,
        "country": country,
        "locale": locale,
        "language": language,
    }
    for label, value in optional_text.items():
        if value is not None:
            _require_text(value, f"persona search {label}")
    for label, value in (
        ("major", major),
        ("minimum major", min_major),
        ("maximum major", max_major),
    ):
        if value is not None:
            _require_version(value, f"persona search {label}")
    if min_major is not None and max_major is not None and min_major > max_major:
        raise ContractError("persona search major range is reversed")
    if isinstance(tags, (str, bytes, bytearray, dict)):
        raise ContractError("persona search tags must be a bounded iterable of text")
    tag_values = _bounded_public_values(
        tags,
        maximum=256,
        invalid="persona search tags must be a bounded iterable of text",
        excess="persona search tag population exceeds the limit",
    )
    required_tags = {_require_text(value, "persona search tag") for value in tag_values}
    results: list[dict[str, Any]] = []
    for persona in list_personas(workspace):
        kernel = persona["kernel"]
        geography = persona["geography"]
        if engine is not None and kernel["engine"] != engine:
            continue
        if product is not None and kernel["product"] != product:
            continue
        if (
            major is not None
            and not kernel["minimum_major"] <= major <= kernel["maximum_major"]
        ):
            continue
        if min_major is not None and kernel["maximum_major"] < min_major:
            continue
        if max_major is not None and kernel["minimum_major"] > max_major:
            continue
        if device_class is not None and persona["device"]["class"] != device_class:
            continue
        if os_family is not None and persona["device"]["os_family"] != os_family:
            continue
        if country is not None and geography["country"] != country:
            continue
        if locale is not None and geography["locale"].casefold() != locale.casefold():
            continue
        if language is not None:
            wanted = language.casefold()
            if not any(item.casefold() == wanted for item in geography["languages"]):
                continue
        if not required_tags.issubset(persona["tags"]):
            continue
        if not include_incoherent and persona_contradicts_itself(persona):
            continue
        results.append(persona)
    return results


def persona_contradicts_itself(persona: dict[str, Any]) -> bool:
    """Does this persona carry at least one ``contradiction`` finding?

    Split out from ``reject_incoherent_persona`` because the two callers want
    different things from the same question: capture wants the reasons, so it can
    say what it refused and why, while selection only wants the verdict and runs
    it over every candidate a search matched.
    """
    from .persona_quality import coherence_findings

    return any(
        finding["severity"] == "contradiction"
        for finding in coherence_findings(persona)
    )


def _browser_major_axis(ranges: Iterable[tuple[int, int]]) -> list[int]:
    """Union bounded inclusive version intervals in O(rows + 999) work."""
    changes = [0] * 1001
    for minimum, maximum in ranges:
        changes[minimum] += 1
        changes[maximum + 1] -= 1
    active = 0
    majors: list[int] = []
    for major in range(1, 1000):
        active += changes[major]
        if active:
            majors.append(major)
    return majors


def catalog_coverage_report(workspace: Path) -> dict[str, Any]:
    """Diversity + provenance report for the owned persona catalog.

    Preference for research catalog depth is scored on diversity and provenance
    integrity, never raw headcount alone.
    """
    if not isinstance(workspace, Path):
        raise ContractError("persona workspace must be a Path")
    directory = _persona_workspace_path(workspace) / "personas" / "catalog"
    authorities = _persona_read_authorities(directory, label="persona catalog")
    before = _persona_report_inventory(directory)
    personas = list_personas(workspace, include_deprecated=True)
    active = [item for item in personas if item["state"] == "active"]
    audit = _audit_persona_snapshot(workspace, personas)

    def _sorted_unique(values: Iterable[str]) -> list[str]:
        return sorted({value for value in values if value}, key=str.casefold)

    device_classes = _sorted_unique(item["device"]["class"] for item in active)
    os_families = _sorted_unique(item["device"]["os_family"] for item in active)
    engines = _sorted_unique(item["kernel"]["engine"] for item in active)
    products = _sorted_unique(item["kernel"]["product"] for item in active)
    locales = _sorted_unique(item["geography"]["locale"] for item in active)
    countries = _sorted_unique(item["geography"]["country"] for item in active)
    languages = _sorted_unique(
        language for item in active for language in item["geography"]["languages"]
    )
    majors = _browser_major_axis(
        (
            item["kernel"]["minimum_major"],
            item["kernel"]["maximum_major"],
        )
        for item in active
    )
    provenance_kinds = _sorted_unique(item["provenance"]["kind"] for item in active)
    claim_counts = [len(item["identity_contract"]["expected"]) for item in active]

    def _provenance_grade(persona: dict[str, Any]) -> str:
        """Honest grade for catalog claims (counts only; additive to kind)."""
        kind = persona["provenance"]["kind"]
        source = str(persona["provenance"].get("source") or "")
        tags = {str(tag).casefold() for tag in persona.get("tags") or ()}
        if kind == "owned-capture":
            if "matrix" in tags or source.startswith("kernel-probe"):
                return "lab-matrix-or-probe"
            if (
                source.startswith("ops-")
                or "fixture" in tags
                or "ops-fixture" in source
                or source.startswith("ops-launch")
            ):
                return "lab-fixture"
            return "owned-capture-primary"
        if kind == "reviewed-contract":
            return "reviewed-contract"
        if kind == "imported-bundle":
            return "imported-bundle"
        return f"other:{kind}"

    grade_counts: dict[str, int] = {}
    kind_counts: dict[str, int] = {}
    for item in active:
        kind = item["provenance"]["kind"]
        kind_counts[kind] = kind_counts.get(kind, 0) + 1
        grade = _provenance_grade(item)
        grade_counts[grade] = grade_counts.get(grade, 0) + 1
    primary_owned = int(grade_counts.get("owned-capture-primary", 0))
    matrix_or_probe = int(grade_counts.get("lab-matrix-or-probe", 0))
    lab_fixture = int(grade_counts.get("lab-fixture", 0))
    low_provenance = matrix_or_probe + lab_fixture
    high_ratio = (primary_owned / len(active)) if active else 0.0
    # Additive honesty gates — do not rewrite historical research_catalog_ready.
    provenance_grades = {
        "schema": "browser-core.persona-provenance-grades/1",
        "by_kind": dict(sorted(kind_counts.items())),
        "by_grade": dict(sorted(grade_counts.items())),
        "owned_capture_primary": primary_owned,
        "lab_matrix_or_probe": matrix_or_probe,
        "lab_fixture": lab_fixture,
        "low_provenance_total": low_provenance,
        "high_provenance_ratio": round(high_ratio, 4),
        "thresholds": {
            "owned_capture_primary_at_least_12": 12,
            "high_provenance_ratio_at_least_0_25": 0.25,
            "note": _PROVENANCE_GRADE_NOTE,
        },
        "gates": {
            "owned_capture_primary_at_least_12": primary_owned >= 12,
            "high_provenance_ratio_at_least_0_25": high_ratio >= 0.25,
        },
        "warn_overcount_risk": bool(
            active
            and (
                primary_owned < 12
                or high_ratio < 0.25
                or low_provenance > primary_owned
            )
        ),
    }

    axis_diversity = {
        "device_class": len(device_classes),
        "os_family": len(os_families),
        "engine": len(engines),
        "product": len(products),
        "locale": len(locales),
        "country": len(countries),
        "language": len(languages),
        "browser_major": len(majors),
        "provenance_kind": len(provenance_kinds),
    }
    # Research catalog quality: multi-axis diversity plus lab-scale volume.
    # Volume alone never makes research_catalog_ready true.
    quality_gates = {
        "active_at_least_12": len(active) >= 12,
        "active_at_least_100": len(active) >= 100,
        "active_at_least_1000": len(active) >= 1000,
        "engines_at_least_3": axis_diversity["engine"] >= 3,
        "device_classes_at_least_2": axis_diversity["device_class"] >= 2,
        "os_families_at_least_3": axis_diversity["os_family"] >= 3,
        "locales_at_least_4": axis_diversity["locale"] >= 4,
        "locales_at_least_8": axis_diversity["locale"] >= 8,
        "countries_at_least_3": axis_diversity["country"] >= 3,
        "countries_at_least_6": axis_diversity["country"] >= 6,
        "browser_majors_at_least_3": axis_diversity["browser_major"] >= 3,
        "provenance_allowed_only": set(provenance_kinds).issubset(ALLOWED_PROVENANCE),
        "audit_passed": audit.get("passed") is True,
        "every_active_has_claims": all(count >= 4 for count in claim_counts)
        if claim_counts
        else False,
    }
    report = {
        "schema": COVERAGE_SCHEMA,
        "active": len(active),
        "deprecated": sum(item["state"] == "deprecated" for item in personas),
        "total": len(personas),
        "axes": {
            "device_class": device_classes,
            "os_family": os_families,
            "engine": engines,
            "product": products,
            "locale": locales,
            "country": countries,
            "language": languages,
            "browser_major": majors,
            "provenance_kind": provenance_kinds,
        },
        "axis_diversity": axis_diversity,
        "identity_claim_counts": {
            "min": min(claim_counts) if claim_counts else 0,
            "max": max(claim_counts) if claim_counts else 0,
            "mean": (sum(claim_counts) / len(claim_counts)) if claim_counts else 0.0,
        },
        "quality_gates": quality_gates,
        "provenance_grades": provenance_grades,
        # Core research readiness: diversity + provenance (volume is reported separately).
        "research_catalog_ready": all(
            quality_gates[key]
            for key in (
                "active_at_least_12",
                "engines_at_least_3",
                "device_classes_at_least_2",
                "os_families_at_least_3",
                "locales_at_least_8",
                "countries_at_least_6",
                "browser_majors_at_least_3",
                "provenance_allowed_only",
                "audit_passed",
                "every_active_has_claims",
            )
        ),
        "lab_scale_volume_ready": bool(
            quality_gates["active_at_least_100"]
            and quality_gates["provenance_allowed_only"]
        ),
        # Operator-accessible commercial-class inventory (lab), not vendor telemetry millions.
        "commercial_inventory_ready": bool(
            quality_gates["active_at_least_1000"]
            and quality_gates["provenance_allowed_only"]
            and quality_gates["locales_at_least_8"]
            and quality_gates["countries_at_least_6"]
            and quality_gates["engines_at_least_3"]
            and quality_gates["audit_passed"]
        ),
        "audit": audit,
        "personas": [
            {
                "id": item["id"],
                "state": item["state"],
                "device_class": item["device"]["class"],
                "os_family": item["device"]["os_family"],
                "engine": item["kernel"]["engine"],
                "product": item["kernel"]["product"],
                "major_range": [
                    item["kernel"]["minimum_major"],
                    item["kernel"]["maximum_major"],
                ],
                "locale": item["geography"]["locale"],
                "country": item["geography"]["country"],
                "languages": item["geography"]["languages"],
                "claim_count": len(item["identity_contract"]["expected"]),
                "provenance_kind": item["provenance"]["kind"],
                "provenance_grade": _provenance_grade(item),
                "integrity_sha256_16": item["integrity_sha256"][:16],
            }
            for item in sorted(personas, key=lambda row: row["id"].casefold())
        ],
    }
    validated = validate_catalog_coverage_report(report)
    _require_persona_report_catalog(directory, personas, before, authorities)
    _rebind_persona_audit_sources(workspace, personas, audit)
    return validated


def _coverage_count(value: Any, label: str, *, maximum: int = 10_000_000) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not 0 <= value <= maximum
    ):
        raise ContractError(f"{label} is invalid")
    return value


def _coverage_rows(value: Any) -> list[dict[str, Any]]:
    fields = {
        "id",
        "state",
        "device_class",
        "os_family",
        "engine",
        "product",
        "major_range",
        "locale",
        "country",
        "languages",
        "claim_count",
        "provenance_kind",
        "provenance_grade",
        "integrity_sha256_16",
    }
    if type(value) is not list or len(value) > MAX_PERSONA_CATALOG_ENTRIES:
        raise ContractError("persona coverage rows are invalid")
    rows: list[dict[str, Any]] = []
    ids: set[str] = set()
    for index, row in enumerate(value):
        if type(row) is not dict or set(row) != fields:
            raise ContractError(f"persona coverage row {index} is invalid")
        persona_id = _require_text(row.get("id"), "persona coverage ID", maximum=128)
        folded_id = persona_id.casefold()
        if folded_id in ids:
            raise ContractError("persona coverage IDs are not unique")
        ids.add(folded_id)
        if not _allowed_text(row.get("state"), {"active", "deprecated"}):
            raise ContractError("persona coverage state is invalid")
        if not _allowed_text(row.get("device_class"), {"desktop", "mobile"}):
            raise ContractError("persona coverage device class is invalid")
        if not _allowed_text(row.get("os_family"), ALLOWED_OS):
            raise ContractError("persona coverage OS family is invalid")
        if not _allowed_text(row.get("engine"), ALLOWED_ENGINES):
            raise ContractError("persona coverage engine is invalid")
        if not _allowed_text(row.get("product"), ALLOWED_PRODUCTS):
            raise ContractError("persona coverage product is invalid")
        if (
            (row["product"] == "firefox" and row["engine"] != "firefox")
            or (row["product"] == "safari" and row["engine"] != "webkit")
            or (
                row["product"] in {"browser-core", "chrome", "chromium", "edge"}
                and row["engine"] != "chromium"
            )
        ):
            raise ContractError("persona coverage product/engine is inconsistent")
        major_range = row.get("major_range")
        if type(major_range) is not list or len(major_range) != 2:
            raise ContractError("persona coverage major range is invalid")
        minimum = _require_version(major_range[0], "persona coverage minimum major")
        maximum = _require_version(major_range[1], "persona coverage maximum major")
        if minimum > maximum:
            raise ContractError("persona coverage major range is invalid")
        locale = _require_text(row.get("locale"), "persona coverage locale", maximum=64)
        country = _require_text(
            row.get("country"), "persona coverage country", maximum=2
        )
        if not LOCALE_RE.fullmatch(locale) or not COUNTRY_RE.fullmatch(country):
            raise ContractError("persona coverage geography is invalid")
        languages = row.get("languages")
        if type(languages) is not list or not 1 <= len(languages) <= 8:
            raise ContractError("persona coverage languages are invalid")
        safe_languages = [
            _require_text(item, "persona coverage language", maximum=64)
            for item in languages
        ]
        if (
            any(not LOCALE_RE.fullmatch(item) for item in safe_languages)
            or safe_languages[0].casefold() != locale.casefold()
            or len(safe_languages)
            != len(set(item.casefold() for item in safe_languages))
        ):
            raise ContractError("persona coverage languages are inconsistent")
        _coverage_count(row.get("claim_count"), "persona coverage claim count")
        kind = row.get("provenance_kind")
        if not _allowed_text(kind, ALLOWED_PROVENANCE):
            raise ContractError("persona coverage provenance kind is invalid")
        grade = row.get("provenance_grade")
        allowed_grades = {
            "owned-capture": {
                "owned-capture-primary",
                "lab-matrix-or-probe",
                "lab-fixture",
            },
            "reviewed-contract": {"reviewed-contract"},
            "imported-bundle": {"imported-bundle"},
        }
        if not _allowed_text(grade, allowed_grades[kind]):
            raise ContractError("persona coverage provenance grade is invalid")
        digest = row.get("integrity_sha256_16")
        if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{16}", digest):
            raise ContractError("persona coverage integrity digest is invalid")
        rows.append(row)
    if rows != sorted(rows, key=lambda row: row["id"].casefold()):
        raise ContractError("persona coverage rows are not canonical")
    return rows


def _coverage_audit(value: Any, rows: list[dict[str, Any]]) -> dict[str, Any]:
    audit = validate_catalog_audit_report(value)
    if (
        audit["personas"] != len(rows)
        or audit["active"] != sum(row["state"] == "active" for row in rows)
        or audit["engines"] != sorted({row["engine"] for row in rows})
        or audit["device_classes"] != sorted({row["device_class"] for row in rows})
    ):
        raise ContractError("persona coverage audit population is inconsistent")
    verified = audit["verified"]
    persona_by_id = {row["id"]: row for row in rows}
    if [row.get("id") if type(row) is dict else None for row in verified] != [
        row["id"] for row in rows
    ]:
        raise ContractError("persona coverage verified rows are not canonical")
    seen: set[str] = set()
    for row in verified:
        persona_id = row["id"]
        if persona_id in seen or persona_id not in persona_by_id:
            raise ContractError("persona coverage verified IDs are inconsistent")
        seen.add(persona_id)
        if (
            row.get("persona_sha256_16")
            != persona_by_id[persona_id]["integrity_sha256_16"]
        ):
            raise ContractError("persona coverage verified digest is inconsistent")
        for field in ("state", "engine", "device_class"):
            if row[field] != persona_by_id[persona_id][field]:
                raise ContractError("persona coverage verified row is inconsistent")
        if (
            row["evidence_kind"] != "content-addressed-evidence"
            and persona_by_id[persona_id]["provenance_kind"] != "owned-capture"
        ):
            raise ContractError("persona coverage evidence kind is inconsistent")
    return audit


def _rebuild_catalog_coverage(
    rows: list[dict[str, Any]], audit: dict[str, Any]
) -> dict[str, Any]:
    active = [row for row in rows if row["state"] == "active"]

    def unique(field: str) -> list[str]:
        return sorted({row[field] for row in active}, key=str.casefold)

    axes = {
        "device_class": unique("device_class"),
        "os_family": unique("os_family"),
        "engine": unique("engine"),
        "product": unique("product"),
        "locale": unique("locale"),
        "country": unique("country"),
        "language": sorted(
            {language for row in active for language in row["languages"]},
            key=str.casefold,
        ),
        "browser_major": _browser_major_axis(
            (row["major_range"][0], row["major_range"][1]) for row in active
        ),
        "provenance_kind": unique("provenance_kind"),
    }
    axis_diversity = {key: len(values) for key, values in axes.items()}
    claims = [row["claim_count"] for row in active]
    kinds = dict(sorted(Counter(row["provenance_kind"] for row in active).items()))
    grades = dict(sorted(Counter(row["provenance_grade"] for row in active).items()))
    primary = grades.get("owned-capture-primary", 0)
    matrix = grades.get("lab-matrix-or-probe", 0)
    fixture = grades.get("lab-fixture", 0)
    low = matrix + fixture
    high_ratio = primary / len(active) if active else 0.0
    provenance_grades = {
        "schema": "browser-core.persona-provenance-grades/1",
        "by_kind": kinds,
        "by_grade": grades,
        "owned_capture_primary": primary,
        "lab_matrix_or_probe": matrix,
        "lab_fixture": fixture,
        "low_provenance_total": low,
        "high_provenance_ratio": round(high_ratio, 4),
        "thresholds": {
            "owned_capture_primary_at_least_12": 12,
            "high_provenance_ratio_at_least_0_25": 0.25,
            "note": _PROVENANCE_GRADE_NOTE,
        },
        "gates": {
            "owned_capture_primary_at_least_12": primary >= 12,
            "high_provenance_ratio_at_least_0_25": high_ratio >= 0.25,
        },
        "warn_overcount_risk": bool(
            active and (primary < 12 or high_ratio < 0.25 or low > primary)
        ),
    }
    gates = {
        "active_at_least_12": len(active) >= 12,
        "active_at_least_100": len(active) >= 100,
        "active_at_least_1000": len(active) >= 1000,
        "engines_at_least_3": axis_diversity["engine"] >= 3,
        "device_classes_at_least_2": axis_diversity["device_class"] >= 2,
        "os_families_at_least_3": axis_diversity["os_family"] >= 3,
        "locales_at_least_4": axis_diversity["locale"] >= 4,
        "locales_at_least_8": axis_diversity["locale"] >= 8,
        "countries_at_least_3": axis_diversity["country"] >= 3,
        "countries_at_least_6": axis_diversity["country"] >= 6,
        "browser_majors_at_least_3": axis_diversity["browser_major"] >= 3,
        "provenance_allowed_only": set(axes["provenance_kind"]).issubset(
            ALLOWED_PROVENANCE
        ),
        "audit_passed": audit["passed"] is True,
        "every_active_has_claims": all(count >= 4 for count in claims)
        if claims
        else False,
    }
    research_keys = (
        "active_at_least_12",
        "engines_at_least_3",
        "device_classes_at_least_2",
        "os_families_at_least_3",
        "locales_at_least_8",
        "countries_at_least_6",
        "browser_majors_at_least_3",
        "provenance_allowed_only",
        "audit_passed",
        "every_active_has_claims",
    )
    return {
        "schema": COVERAGE_SCHEMA,
        "active": len(active),
        "deprecated": len(rows) - len(active),
        "total": len(rows),
        "axes": axes,
        "axis_diversity": axis_diversity,
        "identity_claim_counts": {
            "min": min(claims) if claims else 0,
            "max": max(claims) if claims else 0,
            "mean": sum(claims) / len(claims) if claims else 0.0,
        },
        "quality_gates": gates,
        "provenance_grades": provenance_grades,
        "research_catalog_ready": all(gates[key] for key in research_keys),
        "lab_scale_volume_ready": bool(
            gates["active_at_least_100"] and gates["provenance_allowed_only"]
        ),
        "commercial_inventory_ready": bool(
            gates["active_at_least_1000"]
            and gates["provenance_allowed_only"]
            and gates["locales_at_least_8"]
            and gates["countries_at_least_6"]
            and gates["engines_at_least_3"]
            and gates["audit_passed"]
        ),
        "audit": audit,
        "personas": rows,
    }


def validate_catalog_coverage_report(report: Any) -> dict[str, Any]:
    fields = {
        "schema",
        "active",
        "deprecated",
        "total",
        "axes",
        "axis_diversity",
        "identity_claim_counts",
        "quality_gates",
        "provenance_grades",
        "research_catalog_ready",
        "lab_scale_volume_ready",
        "commercial_inventory_ready",
        "audit",
        "personas",
    }
    if type(report) is not dict or set(report) != fields:
        raise ContractError("persona coverage report fields are invalid")
    if report.get("schema") != COVERAGE_SCHEMA:
        raise ContractError("persona coverage report schema is invalid")
    rows = _coverage_rows(report.get("personas"))
    audit = _coverage_audit(report.get("audit"), rows)
    if report != _rebuild_catalog_coverage(rows, audit):
        raise ContractError("persona coverage report is internally inconsistent")
    return report


def catalog_volume_report(
    workspace: Path,
    *,
    baseline_active: int = 15,
) -> dict[str, Any]:
    """Lab-scale owned catalog volume vs a named baseline.

    This does not claim parity with vendor commercial telemetry millions.
    """
    if (
        isinstance(baseline_active, bool)
        or not isinstance(baseline_active, int)
        or not 0 <= baseline_active <= 10_000_000
    ):
        raise ContractError("baseline_active must be an integer from 0 to 10000000")
    coverage = catalog_coverage_report(workspace)
    active = int(coverage["active"])
    growth = active - baseline_active
    report = {
        "schema": VOLUME_SCHEMA,
        "baseline_active": baseline_active,
        "active": active,
        "deprecated": coverage["deprecated"],
        "minimum_claim_count": coverage["identity_claim_counts"]["min"],
        "claim_count_histogram": dict(
            sorted(
                Counter(
                    row["claim_count"]
                    for row in coverage["personas"]
                    if row["state"] == "active"
                ).items()
            )
        ),
        "audit_verified": len(coverage["audit"]["verified"]),
        "growth_delta": growth,
        "growth_ratio": (active / baseline_active) if baseline_active else None,
        "drastic_growth": growth >= 85 or active >= 100,
        "lab_scale_volume_ready": bool(coverage.get("lab_scale_volume_ready")),
        "research_catalog_ready": bool(coverage.get("research_catalog_ready")),
        "commercial_inventory_ready": bool(coverage.get("commercial_inventory_ready")),
        "generation_method": "owned-kernel-probe-matrix",
        "provenance_kinds": coverage["axes"]["provenance_kind"],
        "axis_diversity": coverage["axis_diversity"],
        "quality_gates": coverage["quality_gates"],
        "vendor_commercial_millions_claim": False,
        "note": _VOLUME_NOTE,
    }
    return validate_catalog_volume_report(report)


def validate_catalog_volume_report(report: Any) -> dict[str, Any]:
    fields = {
        "schema",
        "baseline_active",
        "active",
        "deprecated",
        "minimum_claim_count",
        "claim_count_histogram",
        "audit_verified",
        "growth_delta",
        "growth_ratio",
        "drastic_growth",
        "lab_scale_volume_ready",
        "research_catalog_ready",
        "commercial_inventory_ready",
        "generation_method",
        "provenance_kinds",
        "axis_diversity",
        "quality_gates",
        "vendor_commercial_millions_claim",
        "note",
    }
    if type(report) is not dict or set(report) != fields:
        raise ContractError("persona volume report fields are invalid")
    if report.get("schema") != VOLUME_SCHEMA:
        raise ContractError("persona volume report schema is invalid")
    baseline = _coverage_count(report.get("baseline_active"), "persona volume baseline")
    active = _coverage_count(
        report.get("active"),
        "persona volume active count",
        maximum=MAX_PERSONA_CATALOG_ENTRIES,
    )
    deprecated = _coverage_count(
        report.get("deprecated"),
        "persona volume deprecated count",
        maximum=MAX_PERSONA_CATALOG_ENTRIES,
    )
    if active + deprecated > MAX_PERSONA_CATALOG_ENTRIES:
        raise ContractError("persona volume catalog population is inconsistent")
    minimum_claim_count = _coverage_count(
        report.get("minimum_claim_count"), "persona volume minimum claim count"
    )
    raw_claim_histogram = report.get("claim_count_histogram")
    if type(raw_claim_histogram) is not dict or len(raw_claim_histogram) > active:
        raise ContractError("persona volume claim histogram is invalid")
    claim_histogram: dict[int, int] = {}
    for raw_claims, raw_personas in raw_claim_histogram.items():
        if type(raw_claims) is int:
            claims = raw_claims
        elif isinstance(raw_claims, str) and re.fullmatch(r"0|[1-9][0-9]*", raw_claims):
            claims = int(raw_claims)
        else:
            raise ContractError("persona volume claim histogram key is invalid")
        if claims in claim_histogram:
            raise ContractError("persona volume claim histogram key is duplicated")
        count = _coverage_count(
            raw_personas, "persona volume claim histogram count", maximum=active
        )
        if count < 1:
            raise ContractError("persona volume claim histogram count is invalid")
        claim_histogram[claims] = count
    if sum(claim_histogram.values()) != active or minimum_claim_count != min(
        claim_histogram, default=0
    ):
        raise ContractError("persona volume claim histogram is inconsistent")
    audit_verified = _coverage_count(
        report.get("audit_verified"),
        "persona volume audit verified count",
        maximum=MAX_PERSONA_CATALOG_ENTRIES,
    )
    if audit_verified != active + deprecated:
        raise ContractError("persona volume audit population is inconsistent")
    if active == 0 and minimum_claim_count != 0:
        raise ContractError("persona volume claim population is inconsistent")
    growth_delta = report.get("growth_delta")
    if (
        isinstance(growth_delta, bool)
        or not isinstance(growth_delta, int)
        or growth_delta != active - baseline
    ):
        raise ContractError("persona volume growth delta is inconsistent")
    expected_ratio = active / baseline if baseline else None
    ratio = report.get("growth_ratio")
    if ratio != expected_ratio or isinstance(ratio, bool):
        raise ContractError("persona volume growth ratio is inconsistent")
    for field in (
        "drastic_growth",
        "lab_scale_volume_ready",
        "research_catalog_ready",
        "commercial_inventory_ready",
        "vendor_commercial_millions_claim",
    ):
        if type(report.get(field)) is not bool:
            raise ContractError(f"persona volume {field} is invalid")
    if report["drastic_growth"] is not (active - baseline >= 85 or active >= 100):
        raise ContractError("persona volume growth verdict is inconsistent")
    if report["vendor_commercial_millions_claim"] is not False:
        raise ContractError("persona volume vendor claim is invalid")
    if report.get("generation_method") != "owned-kernel-probe-matrix":
        raise ContractError("persona volume generation method is invalid")

    provenance = report.get("provenance_kinds")
    if (
        type(provenance) is not list
        or len(provenance) > len(ALLOWED_PROVENANCE)
        or any(
            not isinstance(kind, str) or kind not in ALLOWED_PROVENANCE
            for kind in provenance
        )
        or provenance != sorted(set(provenance), key=str.casefold)
    ):
        raise ContractError("persona volume provenance kinds are invalid")
    axis = report.get("axis_diversity")
    axis_fields = {
        "device_class",
        "os_family",
        "engine",
        "product",
        "locale",
        "country",
        "language",
        "browser_major",
        "provenance_kind",
    }
    if type(axis) is not dict or set(axis) != axis_fields:
        raise ContractError("persona volume axis diversity is invalid")
    for key, value in axis.items():
        maximum = 999 if key == "browser_major" else active
        _coverage_count(value, f"persona volume {key} diversity", maximum=maximum)
        if (value == 0) is not (active == 0):
            raise ContractError("persona volume axis population is inconsistent")
    if axis["provenance_kind"] != len(provenance):
        raise ContractError("persona volume provenance diversity is inconsistent")

    gates = report.get("quality_gates")
    gate_fields = {
        "active_at_least_12",
        "active_at_least_100",
        "active_at_least_1000",
        "engines_at_least_3",
        "device_classes_at_least_2",
        "os_families_at_least_3",
        "locales_at_least_4",
        "locales_at_least_8",
        "countries_at_least_3",
        "countries_at_least_6",
        "browser_majors_at_least_3",
        "provenance_allowed_only",
        "audit_passed",
        "every_active_has_claims",
    }
    if (
        type(gates) is not dict
        or set(gates) != gate_fields
        or any(type(value) is not bool for value in gates.values())
    ):
        raise ContractError("persona volume quality gates are invalid")
    expected_gates = {
        "active_at_least_12": active >= 12,
        "active_at_least_100": active >= 100,
        "active_at_least_1000": active >= 1000,
        "engines_at_least_3": axis["engine"] >= 3,
        "device_classes_at_least_2": axis["device_class"] >= 2,
        "os_families_at_least_3": axis["os_family"] >= 3,
        "locales_at_least_4": axis["locale"] >= 4,
        "locales_at_least_8": axis["locale"] >= 8,
        "countries_at_least_3": axis["country"] >= 3,
        "countries_at_least_6": axis["country"] >= 6,
        "browser_majors_at_least_3": axis["browser_major"] >= 3,
        "provenance_allowed_only": set(provenance).issubset(ALLOWED_PROVENANCE),
        "audit_passed": audit_verified == active + deprecated,
        "every_active_has_claims": active > 0 and minimum_claim_count >= 4,
    }
    if any(gates[key] is not value for key, value in expected_gates.items()):
        raise ContractError("persona volume quality gates are inconsistent")
    research_keys = (
        "active_at_least_12",
        "engines_at_least_3",
        "device_classes_at_least_2",
        "os_families_at_least_3",
        "locales_at_least_8",
        "countries_at_least_6",
        "browser_majors_at_least_3",
        "provenance_allowed_only",
        "audit_passed",
        "every_active_has_claims",
    )
    expected_research = all(gates[key] for key in research_keys)
    expected_lab = gates["active_at_least_100"] and gates["provenance_allowed_only"]
    expected_commercial = (
        gates["active_at_least_1000"]
        and gates["provenance_allowed_only"]
        and gates["locales_at_least_8"]
        and gates["countries_at_least_6"]
        and gates["engines_at_least_3"]
        and gates["audit_passed"]
    )
    if (
        report["research_catalog_ready"] is not expected_research
        or report["lab_scale_volume_ready"] is not expected_lab
        or report["commercial_inventory_ready"] is not expected_commercial
    ):
        raise ContractError("persona volume readiness verdict is inconsistent")
    if report.get("note") != _VOLUME_NOTE:
        raise ContractError("persona volume note is invalid")
    return report


# Locale/geography matrix used by bulk owned captures (ISO country + IANA zone).
BULK_GEOGRAPHIES: tuple[dict[str, str], ...] = (
    {"country": "US", "locale": "en-US", "timezone": "America/Chicago"},
    {"country": "GB", "locale": "en-GB", "timezone": "Europe/London"},
    {"country": "DE", "locale": "de-DE", "timezone": "Europe/Berlin"},
    {"country": "FR", "locale": "fr-FR", "timezone": "Europe/Paris"},
    {"country": "ES", "locale": "es-ES", "timezone": "Europe/Madrid"},
    {"country": "IT", "locale": "it-IT", "timezone": "Europe/Rome"},
    {"country": "NL", "locale": "nl-NL", "timezone": "Europe/Amsterdam"},
    {"country": "PL", "locale": "pl-PL", "timezone": "Europe/Warsaw"},
    {"country": "BR", "locale": "pt-BR", "timezone": "America/Sao_Paulo"},
    {"country": "JP", "locale": "ja-JP", "timezone": "Asia/Tokyo"},
    {"country": "KR", "locale": "ko-KR", "timezone": "Asia/Seoul"},
    {"country": "IN", "locale": "en-IN", "timezone": "Asia/Kolkata"},
    # Second band, added to widen the geography axis. Breadth of locale and time
    # zone is where a commercial fingerprint library genuinely competes, and it
    # costs nothing per persona now that a batch shares one browser.
    {"country": "CA", "locale": "en-CA", "timezone": "America/Toronto"},
    {"country": "AU", "locale": "en-AU", "timezone": "Australia/Sydney"},
    {"country": "MX", "locale": "es-MX", "timezone": "America/Mexico_City"},
    {"country": "AR", "locale": "es-AR", "timezone": "America/Argentina/Buenos_Aires"},
    {"country": "SE", "locale": "sv-SE", "timezone": "Europe/Stockholm"},
    {"country": "NO", "locale": "nb-NO", "timezone": "Europe/Oslo"},
    {"country": "FI", "locale": "fi-FI", "timezone": "Europe/Helsinki"},
    {"country": "DK", "locale": "da-DK", "timezone": "Europe/Copenhagen"},
    {"country": "CZ", "locale": "cs-CZ", "timezone": "Europe/Prague"},
    {"country": "PT", "locale": "pt-PT", "timezone": "Europe/Lisbon"},
    {"country": "TR", "locale": "tr-TR", "timezone": "Europe/Istanbul"},
    {"country": "ZA", "locale": "en-ZA", "timezone": "Africa/Johannesburg"},
    {"country": "SG", "locale": "en-SG", "timezone": "Asia/Singapore"},
    {"country": "IE", "locale": "en-IE", "timezone": "Europe/Dublin"},
    {"country": "CH", "locale": "de-CH", "timezone": "Europe/Zurich"},
    {"country": "AT", "locale": "de-AT", "timezone": "Europe/Vienna"},
    {"country": "BE", "locale": "nl-BE", "timezone": "Europe/Brussels"},
    {"country": "RO", "locale": "ro-RO", "timezone": "Europe/Bucharest"},
    {"country": "GR", "locale": "el-GR", "timezone": "Europe/Athens"},
    {"country": "HU", "locale": "hu-HU", "timezone": "Europe/Budapest"},
    {"country": "NZ", "locale": "en-NZ", "timezone": "Pacific/Auckland"},
    {"country": "CL", "locale": "es-CL", "timezone": "America/Santiago"},
    # Third band. Geography is the axis this catalog can actually widen without
    # more machines -- every other axis is bounded by the one host -- and it is
    # the axis a commercial library competes on. Each entry names a locale the
    # country genuinely uses and an IANA zone that country is actually in; the
    # coherence audit cross-checks all three, so a plausible-looking but wrong
    # pairing fails at capture rather than shipping.
    {"country": "CO", "locale": "es-CO", "timezone": "America/Bogota"},
    {"country": "PE", "locale": "es-PE", "timezone": "America/Lima"},
    {"country": "ID", "locale": "id-ID", "timezone": "Asia/Jakarta"},
    {"country": "TH", "locale": "th-TH", "timezone": "Asia/Bangkok"},
    {"country": "VN", "locale": "vi-VN", "timezone": "Asia/Ho_Chi_Minh"},
    {"country": "PH", "locale": "en-PH", "timezone": "Asia/Manila"},
    {"country": "MY", "locale": "ms-MY", "timezone": "Asia/Kuala_Lumpur"},
    {"country": "HK", "locale": "zh-HK", "timezone": "Asia/Hong_Kong"},
    {"country": "TW", "locale": "zh-TW", "timezone": "Asia/Taipei"},
    {"country": "IL", "locale": "he-IL", "timezone": "Asia/Jerusalem"},
    {"country": "AE", "locale": "ar-AE", "timezone": "Asia/Dubai"},
    {"country": "SA", "locale": "ar-SA", "timezone": "Asia/Riyadh"},
    {"country": "EG", "locale": "ar-EG", "timezone": "Africa/Cairo"},
    {"country": "NG", "locale": "en-NG", "timezone": "Africa/Lagos"},
    {"country": "KE", "locale": "en-KE", "timezone": "Africa/Nairobi"},
    {"country": "UA", "locale": "uk-UA", "timezone": "Europe/Kyiv"},
    {"country": "BG", "locale": "bg-BG", "timezone": "Europe/Sofia"},
    {"country": "HR", "locale": "hr-HR", "timezone": "Europe/Zagreb"},
    {"country": "SK", "locale": "sk-SK", "timezone": "Europe/Bratislava"},
    {"country": "SI", "locale": "sl-SI", "timezone": "Europe/Ljubljana"},
    {"country": "LT", "locale": "lt-LT", "timezone": "Europe/Vilnius"},
    {"country": "LV", "locale": "lv-LV", "timezone": "Europe/Riga"},
    {"country": "EE", "locale": "et-EE", "timezone": "Europe/Tallinn"},
    {"country": "RS", "locale": "sr-RS", "timezone": "Europe/Belgrade"},
)


def _safe_persona_token(value: str, *, maximum: int = 40) -> str:
    token = re.sub(r"[^A-Za-z0-9._-]+", "-", value).strip("-.").lower()
    if not token:
        raise ContractError("cannot derive a safe persona token")
    return token[:maximum]


# navigator.platform strings a real browser reports, mapped to the OS families a
# persona may claim alongside them. Single source of truth: persona_quality reads
# this same table when auditing, so a rule and a capture can never drift apart.
PLATFORM_OS_FAMILIES: dict[str, frozenset[str]] = {
    "Win32": frozenset({"windows"}),
    "Win64": frozenset({"windows"}),
    "MacIntel": frozenset({"macos"}),
    "MacPPC": frozenset({"macos"}),
    "Linux x86_64": frozenset({"linux"}),
    "Linux i686": frozenset({"linux"}),
    "Linux aarch64": frozenset({"linux", "android"}),
    "Linux armv8l": frozenset({"android", "linux"}),
    "Linux armv7l": frozenset({"android", "linux"}),
    "iPhone": frozenset({"ios"}),
    "iPad": frozenset({"ios"}),
    "iPod": frozenset({"ios"}),
    "Android": frozenset({"android"}),
}

# Which OS family to record when the measured platform allows more than one.
_PLATFORM_PREFERRED_OS = {
    "Linux aarch64": "linux",
    "Linux armv8l": "android",
    "Linux armv7l": "android",
}


def os_family_from_platform(platform: Any, *, fallback: str) -> str:
    """Believe the measurement over the guess.

    Persona OS family used to be inferred from the Playwright preset's *name* --
    "BlackBerry Z30" reads as a phone, so it was recorded as Android -- while the
    browser under that preset reported ``MacIntel``. The name is a label; the
    platform string is what a fingerprinting script actually reads, so when the
    two disagree the platform wins and the label is discarded.
    """
    if not isinstance(platform, str):
        return fallback
    families = PLATFORM_OS_FAMILIES.get(platform)
    if families is None:
        return fallback
    if fallback in families:
        return fallback
    preferred = _PLATFORM_PREFERRED_OS.get(platform)
    if preferred is not None and preferred in families:
        return preferred
    return sorted(families)[0]


def infer_os_from_device_preset(
    device_name: str, *, device_class: str
) -> tuple[str, str, str]:
    """Return (os_family, os_version, architecture) for a Playwright preset name."""
    name = device_name.casefold()
    if "iphone" in name or "ipad" in name:
        return "ios", "17", "arm64"
    if "desktop safari" in name:
        return "macos", "14", "x86_64"
    if device_class == "desktop":
        return "windows", "11", "x86_64"
    # Mobile non-Apple presets are treated as Android-class emulations.
    return "android", "14", "arm64"


def plan_bulk_capture_matrix(
    repository_root: Path,
    *,
    target_active: int = 100,
    existing_ids: Iterable[str] = (),
    geographies: Iterable[dict[str, str]] = BULK_GEOGRAPHIES,
    full_cross_product: bool = False,
    core_variants: int = 1,
    with_device_memory: bool = False,
    browser_core_executable: Path | None = None,
) -> list[dict[str, Any]]:
    """Plan host-realizable kernel×device×locale captures (no I/O beyond discovery).

    By default, locales round-robin across devices for diversity at smaller targets.
    With ``full_cross_product=True``, every usable device is paired with every
    geography (commercial-class lab volume growth).

    ``with_device_memory`` plans a physical memory size per persona and writes the
    resulting value into the persona ID. It is off by default and, when off, this
    function emits exactly the plans it always did -- the axis only exists if a
    kernel can realize it, and only the attested build can.
    """
    if (
        isinstance(target_active, bool)
        or not isinstance(target_active, int)
        or not 1 <= target_active <= MAX_PERSONA_CATALOG_ENTRIES
    ):
        raise ContractError(
            f"target_active must be an integer from 1 to {MAX_PERSONA_CATALOG_ENTRIES}"
        )
    if type(full_cross_product) is not bool or type(with_device_memory) is not bool:
        raise ContractError("bulk capture planning choices must be boolean")
    if (
        isinstance(core_variants, bool)
        or not isinstance(core_variants, int)
        or not 1 <= core_variants <= MAX_BULK_CORE_VARIANTS
    ):
        raise ContractError(
            f"core_variants must be an integer from 1 to {MAX_BULK_CORE_VARIANTS}"
        )
    if not isinstance(repository_root, Path):
        raise ContractError("bulk capture repository root must be a Path")
    if browser_core_executable is not None and not isinstance(
        browser_core_executable, Path
    ):
        raise ContractError("bulk capture executable must be a Path")
    if isinstance(geographies, (str, bytes, dict)):
        raise ContractError("bulk capture geographies must be a bounded iterable")
    geos = _bounded_public_values(
        geographies,
        maximum=MAX_BULK_GEOGRAPHIES,
        invalid="bulk capture geographies must be a bounded iterable",
        excess="bulk capture has too many geographies",
        invalid_errors=(TypeError, ValueError, RuntimeError),
    )
    if not geos:
        raise ContractError("bulk capture requires at least one geography")
    for index, geo in enumerate(geos):
        if type(geo) is not dict or set(geo) != {"country", "locale", "timezone"}:
            raise ContractError("bulk geography fields are invalid")
        # Discovery can block while a caller still owns the input dictionary.
        # Validate and plan from the same small detached geography snapshot.
        geo = dict(geo)
        geos[index] = geo
        if (
            not isinstance(geo["country"], str)
            or not COUNTRY_RE.fullmatch(geo["country"])
            or not isinstance(geo["locale"], str)
            or not LOCALE_RE.fullmatch(geo["locale"])
            or not isinstance(geo["timezone"], str)
            or not TIMEZONE_RE.fullmatch(geo["timezone"])
        ):
            raise ContractError("bulk geography values are invalid")
    geography_keys = [
        (geo["country"], geo["locale"].casefold(), geo["timezone"]) for geo in geos
    ]
    if len(geography_keys) != len(set(geography_keys)):
        raise ContractError("bulk capture geographies are not unique")
    if isinstance(existing_ids, (str, bytes, dict)):
        raise ContractError("bulk capture existing IDs must be a bounded iterable")
    existing_items = _bounded_public_values(
        existing_ids,
        maximum=MAX_PERSONA_CATALOG_ENTRIES,
        invalid="bulk capture existing IDs must be a bounded iterable",
        excess="bulk capture has too many existing IDs",
        invalid_errors=(TypeError, ValueError, RuntimeError),
    )
    if any(
        not isinstance(persona_id, str)
        or not PROFILE_ID_RE.fullmatch(persona_id)
        or has_windows_device_basename(persona_id)
        or len(persona_id) > 64
        for persona_id in existing_items
    ):
        raise ContractError("bulk capture existing ID is invalid")
    if len(existing_items) != len(
        {persona_id.casefold() for persona_id in existing_items}
    ):
        raise ContractError("bulk capture existing IDs are not unique")

    from .kernels import discover_kernels, playwright_device_contract_catalog

    discovered = discover_kernels(
        repository_root, browser_core_executable=browser_core_executable
    )
    # Keyed by engine, and the attested build shares "chromium" with the
    # Playwright one. Later entries win, so an explicitly supplied Browser Core
    # executable is re-applied afterwards: if the caller named a binary, that is
    # the binary the plan should target, and it is the only one that can realize
    # the memory axis.
    kernels = {item["engine"]: item for item in discovered if item.get("available")}
    if browser_core_executable is not None:
        for item in discovered:
            if item["source"]["kind"] == "attested-browser-core" and item.get(
                "available"
            ):
                kernels[item["engine"]] = item
    existing = {persona_id.casefold() for persona_id in existing_items}
    plans: list[dict[str, Any]] = []
    planned_ids: set[str] = set()
    planned_identity_axes: set[tuple[Any, ...]] = set()
    devices = playwright_device_contract_catalog(
        locale="en-US", timezone="America/Chicago"
    )
    usable: list[tuple[str, dict[str, Any], dict[str, Any]]] = []
    for device in devices:
        name = device["name"]
        engine = device.get("default_engine")
        if engine not in kernels:
            continue
        kernel = kernels[engine]
        if device["class"] == "tablet":
            continue
        if (
            device["class"] in {"mobile", "tablet"}
            and "mobile-emulation" not in kernel["capabilities"]
        ):
            continue
        # Playwright's device list is a *testing* catalog: it keeps discontinued
        # presets on purpose, because regression tests want them. Walking it
        # unfiltered minted 68 "Chrome 153 on a Nokia Lumia 520" personas -- and
        # that preset's user agent is `MSIE 10.0; Windows Phone 8.0;
        # IEMobile/10.0`, so the capture was driving Internet Explorer Mobile's
        # identity through Blink.
        #
        # Filtered on the preset's own user agent rather than on an inferred OS,
        # because the inference is not reliable here: `infer_os_from_device_preset`
        # returns "android" for the Lumia, and the persona only ends up recorded
        # as Windows because `navigator.platform` is measured afterwards and
        # overrides it.
        #
        # An explicit list of platform markers, not a cleverer inference. The
        # first attempt required a `Chrome/` token and let the Microsoft Lumia
        # 550 and 950 straight through, because Edge on Windows Phone 10 carried
        # a Chrome token for compatibility -- and its user agent claims
        # `Windows Phone 10.0` and `Android 4.2.1` in the same string. Naming the
        # platforms is the honest way to be wrong-proof here: the list is short,
        # it is checkable, and adding to it is obvious.
        if device["class"] in {"mobile", "tablet"} and any(
            marker in device["user_agent"] for marker in DISCONTINUED_MOBILE_PLATFORMS
        ):
            continue
        usable.append((name, kernel, device))

    needed = max(target_active - len(existing), 0)
    surplus = 200 if full_cross_product or target_active >= 500 else 20
    plan_cap = min(
        MAX_PERSONA_CATALOG_ENTRIES,
        needed + surplus if needed else target_active,
    )

    def _append_plan(
        name: str,
        kernel: dict[str, Any],
        device: dict[str, Any],
        geo: dict[str, str],
        concurrency: int | None = None,
        variant: int = 0,
    ) -> bool:
        os_family, os_version, architecture = infer_os_from_device_preset(
            name, device_class=device["class"]
        )
        locale_token = _safe_persona_token(geo["locale"], maximum=12)
        device_token = _safe_persona_token(name, maximum=36)
        # Logical-core count is part of the identity, not decoration, so it goes
        # in the ID: two personas differing only by CPU are two personas.
        suffix = f"-c{concurrency}" if concurrency is not None and variant else ""
        # Memory joins the ID for the same reason cores did: two personas that
        # differ only in how much RAM they report are two personas. It also keeps
        # a corrected capture from colliding with the persona it corrects.
        memory_seed = "\0".join((name, geo["locale"]))
        memory_mb = (
            _memory_for(memory_seed, variant, device) if with_device_memory else None
        )
        if memory_mb is not None:
            suffix += f"-m{approximate_device_memory(memory_mb):g}"
        identity_axes = (
            kernel["id"],
            name,
            os_family,
            os_version,
            architecture,
            geo["country"],
            geo["locale"].casefold(),
            geo["timezone"],
            concurrency,
            memory_mb,
        )
        if identity_axes in planned_identity_axes:
            return False
        persona_id = f"owned-mx-{device_token}-{locale_token}{suffix}"
        if not PROFILE_ID_RE.fullmatch(persona_id) or len(persona_id) > 64:
            persona_id = f"owned-mx-{device_token[:24]}-{locale_token}{suffix}"[:64]
        folded_persona_id = persona_id.casefold()
        if folded_persona_id in existing:
            return False
        if folded_persona_id in planned_ids:
            return False
        plans.append(
            {
                "persona_id": persona_id,
                "name": f"Owned {name} {geo['locale']}",
                "kernel_id": kernel["id"],
                "device_preset": name,
                "hardware_concurrency": concurrency,
                "device_memory_mb": _memory_for(
                    f"{name}\0{geo['locale']}", variant, device
                ),
                "os_family": os_family,
                "os_version": os_version,
                "architecture": architecture,
                "country": geo["country"],
                "locale": geo["locale"],
                "timezone": geo["timezone"],
                "tags": (
                    "owned",
                    "matrix",
                    f"locale-{locale_token}",
                    device["class"],
                    kernel["engine"],
                ),
            }
        )
        planned_ids.add(folded_persona_id)
        planned_identity_axes.add(identity_axes)
        return True

    from .kernels import (
        REALISTIC_CORE_COUNTS,
        REALISTIC_DESKTOP_MEMORY_MB,
        REALISTIC_MOBILE_CORE_COUNTS,
        REALISTIC_MOBILE_MEMORY_MB,
        approximate_device_memory,
    )

    def _cores_for(seed: str, variant: int, device: dict[str, Any]) -> int:
        """Deterministic core count, so a re-plan produces the same catalog.

        Drawn from the table the device class allows. A phone and a workstation
        do not share a processor range, and handing a Pixel 24 logical cores is
        the same mistake as handing it a workstation's RAM -- just without a
        native clamp to catch it, since the API has no ceiling.
        """
        table = (
            REALISTIC_MOBILE_CORE_COUNTS
            if device["is_mobile"]
            else REALISTIC_CORE_COUNTS
        )
        digest = hashlib.sha256(f"{seed}\0{variant}".encode("utf-8")).digest()
        return table[digest[0] % len(table)]

    def _memory_for(seed: str, variant: int, device: dict[str, Any]) -> int:
        """Deterministic physical size, drawn from the table the device allows.

        A phone and a workstation do not sample from the same distribution, and
        the difference is not cosmetic: Chromium caps Android at 8, so a mobile
        persona drawing 16 or 32 would be a contradiction by construction.

        Seeded separately from ``_cores_for`` -- a distinct suffix, and a
        distinct digest byte -- so memory does not track core count across the
        catalog. Two axes that move together are one axis to anyone measuring
        entropy, and would buy none of the diversity they appear to.
        """
        table = (
            REALISTIC_MOBILE_MEMORY_MB
            if device["is_mobile"]
            else REALISTIC_DESKTOP_MEMORY_MB
        )
        digest = hashlib.sha256(f"{seed}\0{variant}\0memory".encode("utf-8")).digest()
        return table[digest[1] % len(table)]

    if full_cross_product:
        # Nested loops: every device × every geography × every core variant.
        for name, kernel, device in usable:
            for geo in geos:
                for variant in range(core_variants):
                    seed = f"{name}\0{geo['locale']}"
                    _append_plan(
                        name,
                        kernel,
                        device,
                        geo,
                        _cores_for(seed, variant, device),
                        variant,
                    )
                    if len(plans) >= plan_cap:
                        return plans
        return plans

    # Round-robin locales for smaller targets.
    geo_index = 0
    for name, kernel, device in usable:
        geo = geos[geo_index % len(geos)]
        geo_index += 1
        seed = f"{name}\0{geo['locale']}"
        for variant in range(core_variants):
            _append_plan(
                name, kernel, device, geo, _cores_for(seed, variant, device), variant
            )
        if len(plans) >= plan_cap:
            break
    return plans


def _validate_bulk_capture_limits(
    workspace: Any,
    repository_root: Any,
    *,
    target_active: Any,
    max_new: Any,
    full_cross_product: Any,
) -> None:
    if not isinstance(workspace, Path) or not isinstance(repository_root, Path):
        raise ContractError("bulk capture workspace and repository root must be Paths")
    if (
        isinstance(target_active, bool)
        or not isinstance(target_active, int)
        or not 1 <= target_active <= MAX_PERSONA_CATALOG_ENTRIES
    ):
        raise ContractError(
            f"target_active must be an integer from 1 to {MAX_PERSONA_CATALOG_ENTRIES}"
        )
    if max_new is not None and (
        isinstance(max_new, bool)
        or not isinstance(max_new, int)
        or not 0 <= max_new <= MAX_PERSONA_CATALOG_ENTRIES
    ):
        raise ContractError(
            f"max_new must be an integer from 0 to {MAX_PERSONA_CATALOG_ENTRIES}"
        )
    if type(full_cross_product) is not bool:
        raise ContractError("bulk capture cross-product choice must be boolean")


def _validate_bulk_engines(engines: Any) -> set[str]:
    if isinstance(engines, (str, bytes, dict)):
        raise ContractError("bulk capture engines must be a bounded iterable")
    try:
        values = list(islice(iter(engines), len(ALLOWED_ENGINES) + 1))
    except (TypeError, ValueError, RuntimeError):
        raise ContractError("bulk capture engines must be a bounded iterable") from None
    if (
        not values
        or len(values) > len(ALLOWED_ENGINES)
        or any(
            type(value) is not str or value not in ALLOWED_ENGINES for value in values
        )
        or len(values) != len(set(values))
    ):
        raise ContractError("bulk capture engines are invalid")
    return set(values)


def bulk_capture_personas(
    workspace: Path,
    repository_root: Path,
    *,
    target_active: int = 100,
    max_new: int | None = None,
    full_cross_product: bool = False,
) -> dict[str, Any]:
    """Capture many provenance-backed personas via live kernel probes."""
    _validate_bulk_capture_limits(
        workspace,
        repository_root,
        target_active=target_active,
        max_new=max_new,
        full_cross_product=full_cross_product,
    )
    existing = list_personas(workspace, include_deprecated=True)
    existing_ids = {item["id"] for item in existing}
    baseline_active = sum(item["state"] == "active" for item in existing)
    plans = plan_bulk_capture_matrix(
        repository_root,
        target_active=target_active,
        existing_ids=existing_ids,
        full_cross_product=full_cross_product or target_active >= 500,
    )
    if max_new is not None:
        plans = plans[:max_new]
    captured: list[dict[str, Any]] = []
    failed: list[dict[str, Any]] = []
    skipped = 0
    active_now = baseline_active
    for plan in plans:
        if active_now >= target_active:
            break
        if plan["persona_id"] in existing_ids:
            skipped += 1
            continue
        try:
            persona, evidence = capture_kernel_persona(
                repository_root,
                persona_id=plan["persona_id"],
                name=plan["name"],
                kernel_id=plan["kernel_id"],
                device_preset=plan["device_preset"],
                os_family=plan["os_family"],
                os_version=plan["os_version"],
                architecture=plan["architecture"],
                country=plan["country"],
                locale=plan["locale"],
                timezone_name=plan["timezone"],
                tags=plan["tags"],
            )
            store_persona_evidence(
                workspace,
                evidence,
                expected_sha256=persona["provenance"]["source_sha256"],
            )
            stored = add_persona(workspace, persona)
            existing_ids.add(stored["id"])
            active_now += 1
            captured.append(
                {
                    "id": stored["id"],
                    "locale": stored["geography"]["locale"],
                    "engine": stored["kernel"]["engine"],
                    "device_class": stored["device"]["class"],
                    "claims": len(stored["identity_contract"]["expected"]),
                }
            )
        except ContractError as exc:
            failed.append(
                {"persona_id": plan["persona_id"], "error": safe_failure_receipt(exc)}
            )
        except Exception as exc:  # noqa: BLE001 — bulk must skip wedged probes
            failed.append(
                {
                    "persona_id": plan["persona_id"],
                    "error": safe_failure_receipt(exc),
                }
            )
    volume = catalog_volume_report(workspace, baseline_active=15)
    report = {
        "schema": "browser-core.persona-bulk-capture/1",
        "baseline_active": baseline_active,
        "planned": len(plans),
        "captured": captured,
        "captured_count": len(captured),
        "failed": failed,
        "failed_count": len(failed),
        "skipped_existing": skipped,
        "active_after": volume["active"],
        "volume": volume,
        "coverage": {
            "research_catalog_ready": volume["research_catalog_ready"],
            "lab_scale_volume_ready": volume["lab_scale_volume_ready"],
            "commercial_inventory_ready": volume["commercial_inventory_ready"],
            "axis_diversity": volume["axis_diversity"],
            "quality_gates": volume["quality_gates"],
        },
    }
    return validate_bulk_capture_report(report)


def bulk_capture_personas_batched(
    workspace: Path,
    repository_root: Path,
    *,
    target_active: int = 100,
    max_new: int | None = None,
    full_cross_product: bool = True,
    engines: Iterable[str] = ("chromium",),
    core_variants: int = 1,
    device_memory_executable: str | None = None,
) -> dict[str, Any]:
    """Capture many personas through one browser per engine.

    Same personas, same rules, same provenance as ``bulk_capture_personas`` --
    the difference is that this opens a browser once per engine instead of once
    per persona. That is not a micro-optimisation: a thousand-persona matrix is a
    thousand launches on the per-persona path, and this host stops being able to
    bind loopback sockets after roughly two hundred of them.

    ``engines`` defaults to Chromium alone because it is the only engine here
    that realizes a non-zero ``maxTouchPoints`` under emulation. WebKit reports
    zero however it is asked, so every mobile WebKit persona contradicts itself
    on the most-read mobile signal and is now refused at capture time rather than
    stored and counted.

    ``device_memory_executable`` points at a build carrying native patch 0005 and
    switches on the memory axis. Without it every persona inherits the capture
    host's RAM, which is merely dull on a desktop persona and a contradiction on a
    mobile one: Chromium clamps Android at 8, and a workstation reports far more.

    That has a consequence worth stating plainly rather than discovering. Since
    ``device-memory-above-android-cap`` is a contradiction, a **mobile** capture
    on a high-memory host now *fails* unless this parameter is supplied -- the
    persona would be claiming a number Chrome for Android cannot produce, and
    refusing it is the point. Desktop capture is unaffected either way.
    """
    from .kernels import (
        discover_kernels,
        playwright_device_contract_catalog,
        probe_playwright_kernel_batch,
        relocalize_playwright_device,
    )

    _validate_bulk_capture_limits(
        workspace,
        repository_root,
        target_active=target_active,
        max_new=max_new,
        full_cross_product=full_cross_product,
    )
    if (
        isinstance(core_variants, bool)
        or not isinstance(core_variants, int)
        or not 1 <= core_variants <= MAX_BULK_CORE_VARIANTS
    ):
        raise ContractError(
            f"core_variants must be an integer from 1 to {MAX_BULK_CORE_VARIANTS}"
        )
    wanted = _validate_bulk_engines(engines)
    if device_memory_executable is not None and (
        not isinstance(device_memory_executable, str)
        or not device_memory_executable
        or len(device_memory_executable) > 4096
        or any(ord(character) < 0x20 for character in device_memory_executable)
        or not Path(device_memory_executable).is_absolute()
    ):
        raise ContractError("bulk capture device-memory executable is invalid")

    existing = list_personas(workspace, include_deprecated=True)
    existing_ids = {item["id"] for item in existing}
    baseline_active = sum(item["state"] == "active" for item in existing)
    plans = [
        plan
        for plan in plan_bulk_capture_matrix(
            repository_root,
            target_active=target_active,
            existing_ids=existing_ids,
            full_cross_product=full_cross_product,
            core_variants=core_variants,
            with_device_memory=device_memory_executable is not None,
            browser_core_executable=(
                Path(device_memory_executable) if device_memory_executable else None
            ),
        )
    ]
    kernels = {
        item["id"]: item
        for item in discover_kernels(
            repository_root,
            browser_core_executable=(
                Path(device_memory_executable) if device_memory_executable else None
            ),
        )
    }
    plans = [
        plan
        for plan in plans
        if kernels.get(plan["kernel_id"], {}).get("engine") in wanted
        and plan["persona_id"] not in existing_ids
    ]
    if max_new is not None:
        plans = plans[:max_new]

    by_kernel: dict[str, list[dict[str, Any]]] = {}
    for plan in plans:
        by_kernel.setdefault(plan["kernel_id"], []).append(plan)

    captured: list[dict[str, Any]] = []
    failed: list[dict[str, Any]] = []
    refused_incoherent_count = 0
    active_now = baseline_active
    device_catalog = (
        {
            device["name"]: device
            for device in playwright_device_contract_catalog(
                locale="en-US", timezone="UTC"
            )
        }
        if plans
        else {}
    )
    for kernel_id, kernel_plans in by_kernel.items():
        kernel = kernels.get(kernel_id)
        if kernel is None:
            failed.extend(
                {"persona_id": plan["persona_id"], "error": "unknown kernel"}
                for plan in kernel_plans
            )
            continue
        devices: list[dict[str, Any]] = []
        runnable: list[dict[str, Any]] = []
        concurrencies: list[int | None] = []
        memories: list[int | None] = []
        for plan in kernel_plans:
            try:
                base_device = device_catalog.get(plan["device_preset"])
                if base_device is None:
                    raise ContractError(
                        f"unknown Playwright device preset: {plan['device_preset']}"
                    )
                devices.append(
                    relocalize_playwright_device(
                        base_device,
                        locale=plan["locale"],
                        timezone=plan["timezone"],
                    )
                )
                runnable.append(plan)
                concurrencies.append(plan.get("hardware_concurrency"))
                memories.append(
                    plan.get("device_memory_mb") if device_memory_executable else None
                )
            except ContractError as exc:
                failed.append(
                    {
                        "persona_id": plan["persona_id"],
                        "error": safe_failure_receipt(exc),
                    }
                )
        probes = probe_playwright_kernel_batch(
            kernel,
            devices,
            concurrencies,
            memories,
            device_memory_executable,
        )
        for plan, device, probe in zip(runnable, devices, probes):
            if active_now >= target_active:
                break
            if "error" in probe:
                failed.append(
                    {"persona_id": plan["persona_id"], "error": probe["error"]}
                )
                continue
            try:
                persona, evidence = persona_from_kernel_probe(
                    kernel,
                    device,
                    probe,
                    persona_id=plan["persona_id"],
                    name=plan["name"],
                    kernel_id=kernel_id,
                    os_family=plan["os_family"],
                    os_version=plan["os_version"],
                    architecture=plan["architecture"],
                    country=plan["country"],
                    locale=plan["locale"],
                    timezone_name=plan["timezone"],
                    tags=plan["tags"],
                )
                store_persona_evidence(
                    workspace,
                    evidence,
                    expected_sha256=persona["provenance"]["source_sha256"],
                )
                stored = add_persona(workspace, persona)
                existing_ids.add(stored["id"])
                active_now += 1
                captured.append(
                    {
                        "id": stored["id"],
                        "locale": stored["geography"]["locale"],
                        "engine": stored["kernel"]["engine"],
                        "device_class": stored["device"]["class"],
                        "claims": len(stored["identity_contract"]["expected"]),
                    }
                )
            except ContractError as exc:
                if "contradicts itself" in str(exc):
                    refused_incoherent_count += 1
                failed.append(
                    {
                        "persona_id": plan["persona_id"],
                        "error": safe_failure_receipt(exc),
                    }
                )
            except Exception as exc:  # noqa: BLE001 - one persona must not end the batch
                failed.append(
                    {
                        "persona_id": plan["persona_id"],
                        "error": safe_failure_receipt(exc),
                    }
                )
    volume = catalog_volume_report(workspace, baseline_active=15)
    report = {
        "schema": "browser-core.persona-bulk-capture/3",
        "baseline_active": baseline_active,
        "planned": len(plans),
        "browsers_launched": len(by_kernel),
        "captured": captured,
        "captured_count": len(captured),
        "failed": failed[:50],
        "failed_count": len(failed),
        "failed_omitted": max(len(failed) - 50, 0),
        "failed_sha256": hashlib.sha256(_canonical(failed)).hexdigest(),
        "refused_incoherent": refused_incoherent_count,
        "active_after": volume["active"],
        "volume": volume,
    }
    return validate_bulk_capture_report(report)


def _validate_bulk_captured_rows(value: Any) -> list[dict[str, Any]]:
    fields = {"id", "locale", "engine", "device_class", "claims"}
    if type(value) is not list or len(value) > MAX_PERSONA_CATALOG_ENTRIES:
        raise ContractError("bulk capture success rows are invalid")
    seen: set[str] = set()
    for index, row in enumerate(value):
        if type(row) is not dict or set(row) != fields:
            raise ContractError(f"bulk capture success row {index} is invalid")
        persona_id = row.get("id")
        if (
            not isinstance(persona_id, str)
            or not PROFILE_ID_RE.fullmatch(persona_id)
            or len(persona_id) > 64
            or persona_id.casefold() in seen
        ):
            raise ContractError("bulk capture success ID is invalid")
        seen.add(persona_id.casefold())
        if (
            not isinstance(row.get("locale"), str)
            or not LOCALE_RE.fullmatch(row["locale"])
            or not _allowed_text(row.get("engine"), ALLOWED_ENGINES)
            or not _allowed_text(row.get("device_class"), {"desktop", "mobile"})
        ):
            raise ContractError("bulk capture success metadata is invalid")
        _coverage_count(row.get("claims"), "bulk capture claim count")
    return value


def _validate_bulk_failure_rows(value: Any, *, maximum: int) -> list[dict[str, Any]]:
    if type(value) is not list or len(value) > maximum:
        raise ContractError("bulk capture failure rows are invalid")
    seen: set[str] = set()
    for index, row in enumerate(value):
        if type(row) is not dict or set(row) != {"persona_id", "error"}:
            raise ContractError(f"bulk capture failure row {index} is invalid")
        persona_id = row.get("persona_id")
        if (
            not isinstance(persona_id, str)
            or not PROFILE_ID_RE.fullmatch(persona_id)
            or len(persona_id) > 64
            or persona_id.casefold() in seen
        ):
            raise ContractError("bulk capture failure ID is invalid")
        seen.add(persona_id.casefold())
        error = row.get("error")
        if error != "unknown kernel" and (
            not isinstance(error, str)
            or not re.fullmatch(
                r"(?:contract|execution)-failure; diagnostic_sha256_16=[0-9a-f]{16}",
                error,
            )
        ):
            raise ContractError("bulk capture failure receipt is invalid")
    return value


def validate_bulk_capture_report(report: Any) -> dict[str, Any]:
    """Validate per-persona and batched bulk capture lifecycle receipts."""
    schemas = {
        "browser-core.persona-bulk-capture/1": {
            "schema",
            "baseline_active",
            "planned",
            "captured",
            "captured_count",
            "failed",
            "failed_count",
            "skipped_existing",
            "active_after",
            "volume",
            "coverage",
        },
        "browser-core.persona-bulk-capture/3": {
            "schema",
            "baseline_active",
            "planned",
            "browsers_launched",
            "captured",
            "captured_count",
            "failed",
            "failed_count",
            "failed_omitted",
            "failed_sha256",
            "refused_incoherent",
            "active_after",
            "volume",
        },
    }
    if type(report) is not dict or report.get("schema") not in schemas:
        raise ContractError("bulk capture report schema is invalid")
    schema = report["schema"]
    if set(report) != schemas[schema]:
        raise ContractError("bulk capture report fields are invalid")
    baseline = _coverage_count(
        report.get("baseline_active"),
        "bulk capture baseline",
        maximum=MAX_PERSONA_CATALOG_ENTRIES,
    )
    planned = _coverage_count(
        report.get("planned"),
        "bulk capture planned count",
        maximum=MAX_PERSONA_CATALOG_ENTRIES,
    )
    captured = _validate_bulk_captured_rows(report.get("captured"))
    captured_count = _coverage_count(
        report.get("captured_count"),
        "bulk capture success count",
        maximum=MAX_PERSONA_CATALOG_ENTRIES,
    )
    failed_count = _coverage_count(
        report.get("failed_count"),
        "bulk capture failure count",
        maximum=MAX_PERSONA_CATALOG_ENTRIES,
    )
    failure_limit = failed_count if schema.endswith("/1") else min(failed_count, 50)
    failures = _validate_bulk_failure_rows(report.get("failed"), maximum=failure_limit)
    if (
        captured_count != len(captured)
        or len(failures) != failure_limit
        or captured_count + failed_count > planned
    ):
        raise ContractError("bulk capture outcome populations are inconsistent")
    captured_ids = {row["id"].casefold() for row in captured}
    if not captured_ids.isdisjoint(row["persona_id"].casefold() for row in failures):
        raise ContractError("bulk capture outcome IDs overlap")
    active_after = _coverage_count(
        report.get("active_after"),
        "bulk capture active-after count",
        maximum=MAX_PERSONA_CATALOG_ENTRIES,
    )
    volume = validate_catalog_volume_report(report.get("volume"))
    if active_after != baseline + captured_count or active_after != volume["active"]:
        raise ContractError("bulk capture lifecycle population is inconsistent")

    if schema.endswith("/1"):
        skipped = _coverage_count(
            report.get("skipped_existing"),
            "bulk capture skipped count",
            maximum=MAX_PERSONA_CATALOG_ENTRIES,
        )
        if captured_count + failed_count + skipped > planned:
            raise ContractError("bulk capture attempted population is inconsistent")
        coverage = report.get("coverage")
        expected_coverage = {
            "research_catalog_ready": volume["research_catalog_ready"],
            "lab_scale_volume_ready": volume["lab_scale_volume_ready"],
            "commercial_inventory_ready": volume["commercial_inventory_ready"],
            "axis_diversity": volume["axis_diversity"],
            "quality_gates": volume["quality_gates"],
        }
        if coverage != expected_coverage:
            raise ContractError("bulk capture coverage summary is inconsistent")
    else:
        omitted = _coverage_count(
            report.get("failed_omitted"),
            "bulk capture omitted failure count",
            maximum=MAX_PERSONA_CATALOG_ENTRIES,
        )
        failure_digest = report.get("failed_sha256")
        if (
            omitted != failed_count - len(failures)
            or not isinstance(failure_digest, str)
            or not SHA256_RE.fullmatch(failure_digest)
            or (
                omitted == 0
                and failure_digest != hashlib.sha256(_canonical(failures)).hexdigest()
            )
        ):
            raise ContractError("bulk capture failure population proof is inconsistent")
        browsers = _coverage_count(
            report.get("browsers_launched"),
            "bulk capture browser count",
            maximum=len(ALLOWED_ENGINES),
        )
        if (browsers == 0) is not (planned == 0):
            raise ContractError("bulk capture browser population is inconsistent")
        refused = _coverage_count(
            report.get("refused_incoherent"),
            "bulk capture refused count",
            maximum=MAX_PERSONA_CATALOG_ENTRIES,
        )
        if refused > failed_count:
            raise ContractError("bulk capture refused count is inconsistent")
    return report


def validate_kameleo_inventory_report(report: Any) -> dict[str, Any]:
    base_fields = {"schema", "reachable", "count", "endpoint", "error"}
    if type(report) is not dict:
        raise ContractError("Kameleo inventory report fields are invalid")
    actual_fields = frozenset(report)
    if actual_fields not in {
        frozenset(base_fields),
        frozenset(base_fields | {"methodology"}),
    }:
        raise ContractError("Kameleo inventory report fields are invalid")
    if report.get("schema") != KAMELEO_INVENTORY_SCHEMA:
        raise ContractError("Kameleo inventory report schema is invalid")
    if type(report.get("reachable")) is not bool:
        raise ContractError("Kameleo inventory reachability is invalid")
    endpoint = report.get("endpoint")
    match = (
        re.fullmatch(r"http://loopback:([1-9][0-9]{0,4})/fingerprints", endpoint)
        if isinstance(endpoint, str)
        else None
    )
    if match is None or int(match.group(1)) > 65535:
        raise ContractError("Kameleo inventory endpoint receipt is invalid")

    count = report.get("count")
    error = report.get("error")
    if count is not None:
        count = _coverage_count(
            count,
            "Kameleo inventory count",
            maximum=MAX_KAMELEO_FINGERPRINTS,
        )
        if (
            report["reachable"] is not True
            or error is not None
            or set(report) != base_fields | {"methodology"}
            or report.get("methodology") != _KAMELEO_METHODOLOGY
        ):
            raise ContractError("Kameleo inventory success receipt is inconsistent")
        return report

    if set(report) != base_fields or not isinstance(error, str):
        raise ContractError("Kameleo inventory failure receipt is invalid")
    if report["reachable"]:
        if error not in {
            "response-close",
            "invalid-status",
            "invalid-body",
            "response-too-large",
            "invalid-json",
            "unexpected-payload",
            "inventory-too-large",
        }:
            raise ContractError("Kameleo inventory local failure is invalid")
    elif not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,127}", error):
        raise ContractError("Kameleo inventory transport failure is invalid")
    return report


def _open_kameleo_operator_url(url: str, *, timeout: float):
    import urllib.request

    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, request, fp, code, msg, headers, newurl):
            return None

    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}), NoRedirect()
    )
    return opener.open(url, timeout=timeout)


def count_kameleo_operator_inventory(
    *,
    base_url: str = "http://127.0.0.1:5050",
    timeout_seconds: float = 30.0,
) -> dict[str, Any]:
    """Count Kameleo fingerprints reachable via the local operator API."""
    import urllib.error
    from urllib.parse import urlsplit

    if not is_finite_number(timeout_seconds) or not 0 < timeout_seconds <= 120:
        raise ContractError("Kameleo inventory timeout must be finite in (0, 120]")
    if (
        not isinstance(base_url, str)
        or not base_url
        or any(ord(character) < 0x21 or ord(character) > 0x7E for character in base_url)
    ):
        raise ContractError(
            "Kameleo operator API must be credential-free loopback HTTP"
        )
    try:
        parsed = urlsplit(base_url)
        hostname = parsed.hostname
        port = parsed.port
    except (UnicodeError, ValueError):
        raise ContractError(
            "Kameleo operator API must be credential-free loopback HTTP"
        ) from None
    expected_authority = (
        f"[{hostname}]:{port}" if hostname == "::1" else f"{hostname}:{port}"
    )
    if (
        parsed.scheme != "http"
        or hostname not in {"127.0.0.1", "localhost", "::1"}
        or port is None
        or not 1 <= port <= 65535
        or parsed.netloc.lower() != expected_authority
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
        or "?" in base_url
        or "#" in base_url
    ):
        raise ContractError(
            "Kameleo operator API must be credential-free loopback HTTP"
        )
    contact_host = (
        "127.0.0.1" if hostname == "localhost" else
        "[::1]" if hostname == "::1" else hostname
    )
    url = f"http://{contact_host}:{port}/fingerprints"
    endpoint_label = f"http://loopback:{port}/fingerprints"
    response: Any | None = None
    status: Any = None
    body: Any = None
    primary_error: BaseException | None = None
    try:
        deadline = time.monotonic() + float(timeout_seconds)
        response = _open_kameleo_operator_url(url, timeout=timeout_seconds)
        try:
            status = response.getcode()
        except (AttributeError, OSError, RuntimeError, TypeError, ValueError):
            status = None
        if type(status) is int and status == 200:
            try:
                reader = getattr(response, "read1", None)
                if callable(reader):
                    parts = bytearray()
                    for _ in range(MAX_KAMELEO_INVENTORY_READ_CALLS):
                        if not clamp_urllib_response_read_timeout(
                            response, deadline - time.monotonic()
                        ):
                            raise TimeoutError("inventory response deadline exceeded")
                        remaining = MAX_KAMELEO_INVENTORY_RESPONSE_BYTES + 1 - len(parts)
                        chunk = reader(remaining)
                        if time.monotonic() > deadline:
                            raise TimeoutError("inventory response deadline exceeded")
                        if type(chunk) is not bytes or len(chunk) > remaining:
                            raise ValueError("inventory response body is invalid")
                        parts.extend(chunk)
                        if not chunk or len(parts) > MAX_KAMELEO_INVENTORY_RESPONSE_BYTES:
                            break
                    else:
                        raise ValueError("inventory response has too many fragments")
                    body = bytes(parts)
                else:
                    if not clamp_urllib_response_read_timeout(
                        response, deadline - time.monotonic()
                    ):
                        raise TimeoutError("inventory response deadline exceeded")
                    body = response.read(MAX_KAMELEO_INVENTORY_RESPONSE_BYTES + 1)
                    if time.monotonic() > deadline:
                        raise TimeoutError("inventory response deadline exceeded")
                if (
                    type(body) is bytes
                    and len(body) <= MAX_KAMELEO_INVENTORY_RESPONSE_BYTES
                    and urllib_response_has_unread_declared_bytes(response)
                ):
                    raise ValueError("inventory response ended before declared length")
            except (AttributeError, OSError, RuntimeError, TypeError, ValueError):
                body = None
    except urllib.error.HTTPError as exc:
        response = exc
        primary_error = exc
    except BaseException as exc:
        primary_error = exc

    cleanup_failed = False
    if response is not None:
        try:
            response.close()
        except (AttributeError, OSError, RuntimeError, TypeError, ValueError):
            cleanup_failed = True
    if cleanup_failed:
        return validate_kameleo_inventory_report(
            {
                "schema": KAMELEO_INVENTORY_SCHEMA,
                "reachable": True,
                "count": None,
                "endpoint": endpoint_label,
                "error": "response-close",
            }
        )
    if primary_error is not None:
        if not isinstance(
            primary_error,
            (urllib.error.URLError, TimeoutError, OSError),
        ):
            raise primary_error
        return validate_kameleo_inventory_report(
            {
                "schema": KAMELEO_INVENTORY_SCHEMA,
                "reachable": False,
                "count": None,
                "endpoint": endpoint_label,
                "error": type(primary_error).__name__,
            }
        )
    if type(status) is not int or status != 200:
        return validate_kameleo_inventory_report(
            {
                "schema": KAMELEO_INVENTORY_SCHEMA,
                "reachable": True,
                "count": None,
                "endpoint": endpoint_label,
                "error": "invalid-status",
            }
        )
    if type(body) is not bytes:
        return validate_kameleo_inventory_report(
            {
                "schema": KAMELEO_INVENTORY_SCHEMA,
                "reachable": True,
                "count": None,
                "endpoint": endpoint_label,
                "error": "invalid-body",
            }
        )
    if len(body) > MAX_KAMELEO_INVENTORY_RESPONSE_BYTES:
        return validate_kameleo_inventory_report(
            {
                "schema": KAMELEO_INVENTORY_SCHEMA,
                "reachable": True,
                "count": None,
                "endpoint": endpoint_label,
                "error": "response-too-large",
            }
        )
    try:
        payload = decode_strict_json_bytes(body, label="Kameleo fingerprint inventory")
    except ContractError:
        return validate_kameleo_inventory_report(
            {
                "schema": KAMELEO_INVENTORY_SCHEMA,
                "reachable": True,
                "count": None,
                "endpoint": endpoint_label,
                "error": "invalid-json",
            }
        )
    if time.monotonic() >= deadline:
        return validate_kameleo_inventory_report(
            {
                "schema": KAMELEO_INVENTORY_SCHEMA,
                "reachable": True,
                "count": None,
                "endpoint": endpoint_label,
                "error": "invalid-body",
            }
        )
    if not isinstance(payload, list):
        return validate_kameleo_inventory_report(
            {
                "schema": KAMELEO_INVENTORY_SCHEMA,
                "reachable": True,
                "count": None,
                "endpoint": endpoint_label,
                "error": "unexpected-payload",
            }
        )
    if len(payload) > MAX_KAMELEO_FINGERPRINTS:
        return validate_kameleo_inventory_report(
            {
                "schema": KAMELEO_INVENTORY_SCHEMA,
                "reachable": True,
                "count": None,
                "endpoint": endpoint_label,
                "error": "inventory-too-large",
            }
        )
    return validate_kameleo_inventory_report(
        {
            "schema": KAMELEO_INVENTORY_SCHEMA,
            "reachable": True,
            "count": len(payload),
            "endpoint": endpoint_label,
            "error": None,
            "methodology": _KAMELEO_METHODOLOGY,
        }
    )


def compare_commercial_volume(
    workspace: Path,
    *,
    kameleo_base_url: str = "http://127.0.0.1:5050",
    baseline_active: int = 100,
) -> dict[str, Any]:
    """Side-by-side operator-accessible commercial inventory comparison.

    Ranks lab-queryable Core persona count vs lab-queryable Kameleo fingerprint
    count. Does not claim Core owns Kameleo's unpublished global telemetry corpus.
    """
    volume = catalog_volume_report(workspace, baseline_active=baseline_active)
    core_count = volume["active"]
    kameleo = count_kameleo_operator_inventory(base_url=kameleo_base_url)
    kameleo_count = kameleo["count"]
    core_leads = (
        isinstance(kameleo_count, int)
        and kameleo["reachable"] is True
        and core_count > kameleo_count
    )
    report = {
        "schema": COMMERCIAL_COMPARE_SCHEMA,
        "methodology": _COMMERCIAL_METHODOLOGY,
        "core": {
            "product": "browser-core",
            "count": core_count,
            "inventory": "active-personas",
            "searchable": True,
            "provenance_backed": True,
            "commercial_inventory_ready": volume["commercial_inventory_ready"],
            "research_catalog_ready": volume["research_catalog_ready"],
            "axis_diversity": volume["axis_diversity"],
            "growth_from_baseline": volume["growth_delta"],
            "baseline_active": volume["baseline_active"],
            "volume": volume,
        },
        "kameleo": {
            "product": "kameleo",
            "inventory": "local-api-fingerprints",
            "receipt": kameleo,
        },
        "core_count": core_count,
        "kameleo_count": kameleo_count,
        "core_leads_operator_accessible": core_leads,
        "rank_operator_accessible": (
            "browser-core"
            if core_leads
            else (
                "kameleo"
                if isinstance(kameleo_count, int) and kameleo_count >= core_count
                else "unknown"
            )
        ),
        "vendor_global_telemetry_millions_claim": False,
        "note": _COMMERCIAL_NOTE,
    }
    return validate_commercial_volume_report(report)


def validate_commercial_volume_report(report: Any) -> dict[str, Any]:
    fields = {
        "schema",
        "methodology",
        "core",
        "kameleo",
        "core_count",
        "kameleo_count",
        "core_leads_operator_accessible",
        "rank_operator_accessible",
        "vendor_global_telemetry_millions_claim",
        "note",
    }
    if type(report) is not dict or set(report) != fields:
        raise ContractError("commercial volume comparison fields are invalid")
    if report.get("schema") != COMMERCIAL_COMPARE_SCHEMA:
        raise ContractError("commercial volume comparison schema is invalid")
    if report.get("methodology") != _COMMERCIAL_METHODOLOGY:
        raise ContractError("commercial volume methodology is invalid")

    core = report.get("core")
    core_fields = {
        "product",
        "count",
        "inventory",
        "searchable",
        "provenance_backed",
        "commercial_inventory_ready",
        "research_catalog_ready",
        "axis_diversity",
        "growth_from_baseline",
        "baseline_active",
        "volume",
    }
    if type(core) is not dict or set(core) != core_fields:
        raise ContractError("commercial volume core fields are invalid")
    volume = validate_catalog_volume_report(core.get("volume"))
    if (
        core.get("product") != "browser-core"
        or core.get("inventory") != "active-personas"
        or core.get("searchable") is not True
        or core.get("provenance_backed") is not True
        or core.get("count") != volume["active"]
        or core.get("commercial_inventory_ready")
        is not volume["commercial_inventory_ready"]
        or core.get("research_catalog_ready") is not volume["research_catalog_ready"]
        or core.get("axis_diversity") != volume["axis_diversity"]
        or core.get("growth_from_baseline") != volume["growth_delta"]
        or core.get("baseline_active") != volume["baseline_active"]
    ):
        raise ContractError("commercial volume core summary is inconsistent")

    kameleo = report.get("kameleo")
    if type(kameleo) is not dict or set(kameleo) != {
        "product",
        "inventory",
        "receipt",
    }:
        raise ContractError("commercial volume Kameleo fields are invalid")
    if (
        kameleo.get("product") != "kameleo"
        or kameleo.get("inventory") != "local-api-fingerprints"
    ):
        raise ContractError("commercial volume Kameleo summary is invalid")
    kameleo_receipt = validate_kameleo_inventory_report(kameleo.get("receipt"))

    core_count = volume["active"]
    kameleo_count = kameleo_receipt["count"]
    if (
        report.get("core_count") != core_count
        or report.get("kameleo_count") != kameleo_count
    ):
        raise ContractError("commercial volume headline counts are inconsistent")
    expected_lead = (
        isinstance(kameleo_count, int)
        and kameleo_receipt["reachable"] is True
        and core_count > kameleo_count
    )
    expected_rank = (
        "browser-core"
        if expected_lead
        else (
            "kameleo"
            if isinstance(kameleo_count, int) and kameleo_count >= core_count
            else "unknown"
        )
    )
    if (
        type(report.get("core_leads_operator_accessible")) is not bool
        or report["core_leads_operator_accessible"] is not expected_lead
        or report.get("rank_operator_accessible") != expected_rank
    ):
        raise ContractError("commercial volume ranking is inconsistent")
    if report.get("vendor_global_telemetry_millions_claim") is not False:
        raise ContractError("commercial volume vendor claim is invalid")
    if report.get("note") != _COMMERCIAL_NOTE:
        raise ContractError("commercial volume note is invalid")
    return report


def collect_persona_bundle_evidence(
    workspace: Path,
    personas: Iterable[dict[str, Any]],
) -> dict[str, Any]:
    if not isinstance(workspace, Path):
        raise ContractError("persona bundle workspace must be a Path")
    collected: dict[str, Any] = {}
    for persona in _bounded_persona_bundle_input(personas):
        provenance = persona["provenance"]
        digest = provenance["source_sha256"]
        if digest in collected:
            continue
        try:
            evidence = load_persona_evidence(workspace, digest)
        except _MissingPersonaEvidence:
            source = provenance["source"]
            if provenance["kind"] != "owned-capture" or not source.startswith(
                "profile:"
            ):
                raise ContractError(
                    f"persona evidence is missing for bundle export: {persona['id']}"
                ) from None
            from .profiles import load_profile_identity_document

            profile_id = source.split(":", 1)[1]
            loaded_identity = load_profile_identity_document(workspace, profile_id)
            if loaded_identity is None:
                raise ContractError(
                    f"persona source profile is missing: {persona['id']}"
                )
            evidence, _identity_canonical = loaded_identity
        if not _evidence_digest_matches(evidence, digest):
            raise ContractError(f"persona evidence digest changed: {persona['id']}")
        reject_sensitive_keys(evidence)
        collected[digest] = evidence
    return collected


def _bounded_persona_bundle_input(
    personas: Iterable[dict[str, Any]],
) -> list[dict[str, Any]]:
    try:
        raw = list(islice(iter(personas), MAX_PERSONA_BUNDLE_ITEMS + 1))
    except TypeError:
        raise ContractError("persona bundle personas must be iterable") from None
    if len(raw) > MAX_PERSONA_BUNDLE_ITEMS:
        raise ContractError("persona bundle contains too many personas")
    return [validate_persona(item) for item in raw]


def export_persona_bundle(
    personas: Iterable[dict[str, Any]],
    *,
    evidence_by_sha256: dict[str, Any],
) -> dict[str, Any]:
    if type(evidence_by_sha256) is not dict:
        raise ContractError("persona bundle evidence must be a dictionary")
    if len(evidence_by_sha256) > MAX_PERSONA_BUNDLE_ITEMS:
        raise ContractError("persona bundle contains too much evidence")
    validated = sorted(
        _bounded_persona_bundle_input(personas),
        key=lambda item: item["id"].casefold(),
    )
    ids = [item["id"].casefold() for item in validated]
    if len(ids) != len(set(ids)):
        raise ContractError("persona bundle contains duplicate IDs")
    required_evidence = {item["provenance"]["source_sha256"] for item in validated}
    if set(evidence_by_sha256) != required_evidence:
        raise ContractError("persona bundle evidence set does not match its personas")
    evidence = []
    for digest in evidence_by_sha256:
        if not isinstance(digest, str) or not SHA256_RE.fullmatch(digest):
            raise ContractError("persona bundle evidence digest is invalid")
    for digest in sorted(evidence_by_sha256):
        document = evidence_by_sha256[digest]
        reject_sensitive_keys(document)
        if not SHA256_RE.fullmatch(digest) or not _evidence_digest_matches(
            document, digest
        ):
            raise ContractError("persona bundle evidence digest does not match")
        evidence.append({"sha256": digest, "document": document})
    payload = {
        "schema": PERSONA_BUNDLE_SCHEMA,
        "personas": validated,
        "evidence": evidence,
    }
    canonical_payload = _canonical(payload)
    if len(canonical_payload) > MAX_PERSONA_BUNDLE_BYTES:
        raise ContractError("persona bundle exceeds its byte limit")
    # Return the exact payload whose digest was computed, without references
    # back into caller-owned persona or evidence dictionaries.
    detached_payload = json.loads(canonical_payload)
    if (
        not isinstance(detached_payload, dict)
        or set(detached_payload) != {"schema", "personas", "evidence"}
        or detached_payload["schema"] != PERSONA_BUNDLE_SCHEMA
        or not isinstance(detached_payload["personas"], list)
        or not isinstance(detached_payload["evidence"], list)
        or len(detached_payload["evidence"]) > MAX_PERSONA_BUNDLE_ITEMS
    ):
        raise ContractError("persona bundle changed before export")
    detached_personas = _bounded_persona_bundle_input(detached_payload["personas"])
    detached_ids = [item["id"].casefold() for item in detached_personas]
    if detached_ids != sorted(set(detached_ids)):
        raise ContractError("persona bundle changed before export")
    detached_digests = []
    for entry in detached_payload["evidence"]:
        if not isinstance(entry, dict) or set(entry) != {"sha256", "document"}:
            raise ContractError("persona bundle changed before export")
        digest = entry["sha256"]
        if not isinstance(digest, str) or not SHA256_RE.fullmatch(digest):
            raise ContractError("persona bundle changed before export")
        reject_sensitive_keys(entry["document"])
        if not _evidence_digest_matches(entry["document"], digest):
            raise ContractError("persona bundle evidence digest does not match")
        detached_digests.append(digest)
    if (
        detached_digests != sorted(set(detached_digests))
        or set(detached_digests) != {
            item["provenance"]["source_sha256"] for item in detached_personas
        }
    ):
        raise ContractError("persona bundle changed before export")
    return {
        **detached_payload,
        "bundle_sha256": hashlib.sha256(canonical_payload).hexdigest(),
    }


def export_persona_bundle_from_workspace(
    workspace: Path,
    personas: Iterable[dict[str, Any]],
) -> dict[str, Any]:
    if not isinstance(workspace, Path):
        raise ContractError("persona bundle workspace must be a Path")
    selected = _bounded_persona_bundle_input(personas)
    catalog = list_personas(workspace, include_deprecated=True)
    catalog_by_id = {persona["id"].casefold(): persona for persona in catalog}
    if any(
        (owned := catalog_by_id.get(persona["id"].casefold())) is None
        or owned["integrity_sha256"] != persona["integrity_sha256"]
        for persona in selected
    ):
        raise ContractError("persona bundle selection must match the workspace catalog")
    bundle = export_persona_bundle(
        selected,
        evidence_by_sha256=collect_persona_bundle_evidence(workspace, selected),
    )
    for persona in bundle["personas"]:
        if load_persona(workspace, persona["id"]) != persona:
            raise ContractError("persona bundle selection changed during export")
    expected_evidence = {item["sha256"]: item["document"] for item in bundle["evidence"]}
    checked_digests: set[str] = set()
    for persona in selected:
        digest = persona["provenance"]["source_sha256"]
        if digest in checked_digests:
            continue
        # One bounded source document at a time keeps the final check within
        # the bundle limit without duplicating the entire evidence map.
        try:
            current = collect_persona_bundle_evidence(workspace, (persona,))[digest]
        except ContractError:
            raise ContractError("persona bundle evidence changed during export") from None
        if current != expected_evidence[digest]:
            raise ContractError("persona bundle evidence changed during export")
        checked_digests.add(digest)
    # The last evidence read may outlast the earlier catalog verification.
    for persona in bundle["personas"]:
        if load_persona(workspace, persona["id"]) != persona:
            raise ContractError("persona bundle selection changed during export")
    return bundle


def import_persona_bundle(workspace: Path, bundle: Any) -> dict[str, int]:
    if not isinstance(workspace, Path):
        raise ContractError("persona bundle workspace must be a Path")
    if not isinstance(bundle, dict) or bundle.get("schema") != PERSONA_BUNDLE_SCHEMA:
        raise ContractError("unsupported persona bundle")
    if set(bundle) != {"schema", "personas", "evidence", "bundle_sha256"}:
        raise ContractError("persona bundle fields are invalid")
    raw_personas = bundle.get("personas")
    if (
        not isinstance(raw_personas, list)
        or len(raw_personas) > MAX_PERSONA_BUNDLE_ITEMS
    ):
        raise ContractError("persona bundle personas must be a list")
    raw_evidence = bundle.get("evidence")
    if (
        not isinstance(raw_evidence, list)
        or len(raw_evidence) > MAX_PERSONA_BUNDLE_ITEMS
    ):
        raise ContractError("persona bundle evidence must be a list")
    digest = bundle.get("bundle_sha256")
    payload = {key: value for key, value in bundle.items() if key != "bundle_sha256"}
    canonical_payload = _canonical(payload)
    if len(canonical_payload) > MAX_PERSONA_BUNDLE_BYTES:
        raise ContractError("persona bundle exceeds its byte limit")
    if (
        not isinstance(digest, str)
        or not SHA256_RE.fullmatch(digest)
        or digest != hashlib.sha256(canonical_payload).hexdigest()
    ):
        raise ContractError("persona bundle digest does not match")
    # The caller may mutate nested input containers after canonicalization.
    # Import only the bytes that the verified bundle digest actually covers.
    verified_payload = json.loads(canonical_payload)
    raw_personas = verified_payload["personas"]
    raw_evidence = verified_payload["evidence"]
    if (
        not isinstance(raw_personas, list)
        or len(raw_personas) > MAX_PERSONA_BUNDLE_ITEMS
    ):
        raise ContractError("persona bundle personas must be a list")
    if (
        not isinstance(raw_evidence, list)
        or len(raw_evidence) > MAX_PERSONA_BUNDLE_ITEMS
    ):
        raise ContractError("persona bundle evidence must be a list")
    personas = [validate_persona(item) for item in raw_personas]
    if len({item["id"].casefold() for item in personas}) != len(personas):
        raise ContractError("persona bundle contains duplicate IDs")
    evidence_by_sha256: dict[str, Any] = {}
    for item in raw_evidence:
        if not isinstance(item, dict) or set(item) != {"sha256", "document"}:
            raise ContractError("persona bundle evidence entry is invalid")
        evidence_digest = item["sha256"]
        evidence_document = item["document"]
        if not isinstance(evidence_digest, str) or not SHA256_RE.fullmatch(
            evidence_digest
        ):
            raise ContractError("persona bundle evidence digest is invalid")
        if evidence_digest in evidence_by_sha256:
            raise ContractError("persona bundle contains duplicate evidence")
        reject_sensitive_keys(evidence_document)
        if not _evidence_digest_matches(evidence_document, evidence_digest):
            raise ContractError("persona bundle evidence digest does not match")
        evidence_by_sha256[evidence_digest] = evidence_document
    required_evidence = {item["provenance"]["source_sha256"] for item in personas}
    if set(evidence_by_sha256) != required_evidence:
        raise ContractError("persona bundle evidence set does not match its personas")
    existing_personas = list_personas(workspace, include_deprecated=True)
    existing = {item["id"].casefold(): item for item in existing_personas}
    if len(existing) != len(existing_personas):
        raise ContractError("persona catalog contains duplicate IDs")
    for persona in personas:
        previous = existing.get(persona["id"].casefold())
        if (
            previous is not None
            and previous["integrity_sha256"] != persona["integrity_sha256"]
        ):
            raise ContractError(
                f"persona bundle conflicts with local ID: {persona['id']}"
            )
    for evidence_digest, evidence_document in evidence_by_sha256.items():
        evidence_path = (
            _persona_workspace_path(workspace) / "personas" / "evidence" / f"{evidence_digest}.json"
        )
        if evidence_path.exists() and _canonical(
            load_persona_evidence(workspace, evidence_digest)
        ) != _canonical(evidence_document):
            raise ContractError("persona bundle conflicts with local evidence")
    imported = 0
    unchanged = 0
    for evidence_digest, evidence_document in evidence_by_sha256.items():
        store_persona_evidence(
            workspace, evidence_document, expected_sha256=evidence_digest
        )
    for persona in personas:
        if persona["id"].casefold() in existing:
            unchanged += 1
        else:
            add_persona(workspace, persona)
            imported += 1
    for persona in personas:
        if load_persona(workspace, persona["id"]) != persona:
            raise ContractError("persona bundle changed during import")
    for evidence_digest, evidence_document in evidence_by_sha256.items():
        if _canonical(load_persona_evidence(workspace, evidence_digest)) != _canonical(
            evidence_document
        ):
            raise ContractError("persona bundle evidence changed during import")
    # Evidence verification can outlast the first saved-persona check.
    for persona in personas:
        if load_persona(workspace, persona["id"]) != persona:
            raise ContractError("persona bundle changed during import")
    return {"imported": imported, "unchanged": unchanged}


def assign_persona(
    workspace: Path, assignment_key: str, candidates: Iterable[dict[str, Any]]
) -> dict[str, Any]:
    if not isinstance(workspace, Path):
        raise ContractError("persona assignment workspace must be a Path")
    _require_text(assignment_key, "assignment key", maximum=1024)
    bounded_candidates = _bounded_public_values(
        candidates,
        maximum=MAX_PERSONA_ASSIGNMENT_CANDIDATES,
        invalid="persona assignment candidates must be iterable",
        excess="persona assignment has too many candidates",
    )
    personas = sorted(
        (validate_persona(item) for item in bounded_candidates),
        key=lambda item: item["id"].casefold(),
    )
    if not personas:
        raise ContractError("cannot assign from an empty persona set")
    if len({persona["id"].casefold() for persona in personas}) != len(personas):
        raise ContractError("persona assignment contains duplicate candidate IDs")
    if any(persona["state"] != "active" for persona in personas):
        raise ContractError("persona assignment candidates must be active")
    catalog = list_personas(workspace)
    catalog_by_id = {persona["id"].casefold(): persona for persona in catalog}
    if len(catalog_by_id) != len(catalog):
        raise ContractError("persona catalog contains duplicate IDs")
    if any(
        (owned := catalog_by_id.get(persona["id"].casefold())) is None
        or owned["integrity_sha256"] != persona["integrity_sha256"]
        for persona in personas
    ):
        raise ContractError(
            "persona assignment candidates must match the active workspace catalog"
        )

    def require_selected(assignment: dict[str, Any]) -> dict[str, Any]:
        selected = next(
            (item for item in personas if item["id"] == assignment["persona_id"]),
            None,
        )
        if selected is None or selected["integrity_sha256"] != assignment["persona_sha256"]:
            raise ContractError(
                "stored persona assignment is no longer available or has changed"
            )
        if load_persona(workspace, selected["id"]) != selected:
            raise ContractError("persona assignment selected persona changed")
        # The selected catalog read can outlast the saved assignment read.
        # Reopen the bounded assignment before returning its earlier choice.
        if _load_persona_assignment(path, key_sha256=key_sha256) != assignment:
            raise ContractError("persona assignment changed during selection")
        return assignment

    key_sha256 = hashlib.sha256(assignment_key.encode("utf-8")).hexdigest()
    path = _persona_workspace_path(workspace) / "personas" / "assignments" / f"{key_sha256}.json"
    existing = _load_persona_assignment(path, key_sha256=key_sha256)
    if existing is not None:
        return require_selected(existing)
    winner = max(
        personas,
        key=lambda item: hashlib.sha256(
            f"{key_sha256}\0{item['id']}\0{item['integrity_sha256']}".encode("utf-8")
        ).digest(),
    )
    document = {
        "schema": PERSONA_ASSIGNMENT_SCHEMA,
        "key_sha256": key_sha256,
        "persona_id": winner["id"],
        "persona_sha256": winner["integrity_sha256"],
        "created_at": _utc_now(),
    }
    _validate_persona_assignment(document, key_sha256=key_sha256)
    prepare_owned_directory_parent(path.parent, label="persona assignment parent")
    try:
        publish_json_exclusive(
            path,
            document,
            maximum=MAX_PERSONA_ASSIGNMENT_BYTES,
            label="persona assignment",
        )
    except ContractError as exc:
        if "cleanup incomplete" in str(exc):
            raise
        raced = _load_persona_assignment(path, key_sha256=key_sha256)
        if raced is None:
            raise
        return require_selected(raced)
    if _load_persona_assignment(path, key_sha256=key_sha256) != document:
        raise ContractError("persona assignment changed after publication")
    return require_selected(document)


def _validate_persona_assignment(
    document: Any,
    *,
    key_sha256: str,
) -> dict[str, Any]:
    if not isinstance(document, dict) or set(document) != {
        "schema",
        "key_sha256",
        "persona_id",
        "persona_sha256",
        "created_at",
    }:
        raise ContractError("persona assignment fields are invalid")
    if document.get("schema") != PERSONA_ASSIGNMENT_SCHEMA:
        raise ContractError("persona assignment schema is invalid")
    if document.get("key_sha256") != key_sha256:
        raise ContractError("persona assignment key digest is invalid")
    persona_id = document.get("persona_id")
    if not isinstance(persona_id, str) or not PROFILE_ID_RE.fullmatch(persona_id):
        raise ContractError("persona assignment persona ID is invalid")
    persona_sha256 = document.get("persona_sha256")
    if not isinstance(persona_sha256, str) or not SHA256_RE.fullmatch(persona_sha256):
        raise ContractError("persona assignment persona digest is invalid")
    _require_aware_timestamp(document.get("created_at"), "persona assignment timestamp")
    return document


def _load_persona_assignment(
    path: Path,
    *,
    key_sha256: str,
) -> dict[str, Any] | None:
    authorities = _persona_read_authorities(path.parent, label="persona assignment")
    snapshot = read_bounded_control_snapshot_result(
        path,
        maximum=MAX_PERSONA_ASSIGNMENT_BYTES,
        label="persona assignment",
        require_single_link=True,
    )
    if snapshot.state == "missing":
        if _persona_read_authorities(path.parent, label="persona assignment") != authorities:
            raise ContractError("persona assignment parent changed during read")
        return None
    if snapshot.state != "complete" or snapshot.body is None:
        raise ContractError(f"persona assignment is {snapshot.state}")
    document = load_canonical_json_document(snapshot.body, label="persona assignment")
    assignment = _validate_persona_assignment(document, key_sha256=key_sha256)
    final = read_bounded_control_snapshot_result(
        path,
        maximum=MAX_PERSONA_ASSIGNMENT_BYTES,
        label="persona assignment",
        require_single_link=True,
    )
    if (
        final.state != "complete"
        or final.body != snapshot.body
        or final.identity != snapshot.identity
    ):
        raise ContractError("persona assignment changed during read")
    if _persona_read_authorities(path.parent, label="persona assignment") != authorities:
        raise ContractError("persona assignment parent changed during read")
    return assignment
