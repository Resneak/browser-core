from __future__ import annotations

import importlib.metadata
import re
from pathlib import Path
from typing import Any, Sequence

from .build import _hash_regular_file, executable_evidence
from .contracts import ContractError
from .errors import safe_failure_receipt
from .numeric import is_ascii_decimal
from .profiles import PROFILE_ID_RE


KERNEL_SCHEMA = "browser-core.kernel-capability/1"
DEVICE_SCHEMA = "browser-core.device/1"
KERNEL_PROBE_SCHEMA = "browser-core.kernel-probe/1"

# The probe page is served from a reserved TLD that cannot resolve, and answered
# by request interception. It is an https origin purely so the page counts as a
# secure context; nothing leaves the machine.
_PROBE_URL = "https://owned-kernel-probe.invalid/"
_PROBE_URL_PATTERN = "https://owned-kernel-probe.invalid/**"
_PROBE_PAGE = (
    "<!doctype html><meta charset=utf-8>"
    "<meta name=viewport content='width=device-width,initial-scale=1'>"
    "<title>owned-kernel-probe</title>"
)


def _fulfill_probe_page(route: Any) -> None:
    route.fulfill(status=200, content_type="text/html; charset=utf-8", body=_PROBE_PAGE)


# IANA renames zones and keeps the old name as a link. Chromium's ICU still
# resolves several of them to the *former* spelling, so asking for Asia/Kolkata
# and being handed Asia/Calcutta is one zone with two names, not a failed
# realization. Comparing the strings directly silently rejected every capture in
# these regions -- India and Argentina were simply missing from the catalog.
_TIMEZONE_ALIASES: dict[str, str] = {
    "Asia/Calcutta": "Asia/Kolkata",
    "America/Buenos_Aires": "America/Argentina/Buenos_Aires",
    "America/Argentina/Buenos_Aires": "America/Argentina/Buenos_Aires",
    "Asia/Saigon": "Asia/Ho_Chi_Minh",
    "Europe/Kiev": "Europe/Kyiv",
    "Asia/Rangoon": "Asia/Yangon",
    "Asia/Katmandu": "Asia/Kathmandu",
    "America/Godthab": "America/Nuuk",
    "Europe/Uzhgorod": "Europe/Kyiv",
    "Europe/Zaporozhye": "Europe/Kyiv",
    "Asia/Istanbul": "Europe/Istanbul",
}


# Zones where the engines disagree about which spelling to *report*, measured
# 2026-08-07 on this host by asking each engine for the canonical name and
# reading `Intl.DateTimeFormat().resolvedOptions().timeZone` back:
#
#   requested                       Chromium 147/153   WebKit 26    Firefox 148
#   Asia/Kolkata                    Asia/Calcutta      Asia/Calcutta  Asia/Kolkata
#   Asia/Ho_Chi_Minh                Asia/Saigon        Asia/Saigon    Asia/Ho_Chi_Minh
#   Europe/Kyiv                     Europe/Kiev        Europe/Kiev    Europe/Kyiv
#
# Chromium and WebKit hand back the deprecated link name; Firefox hands back the
# canonical one and **refuses to be set to the alias at all**. So the spelling is
# an engine tell readable in one line, and a persona whose recorded spelling does
# not match its engine is claiming something no browser produces. Only the pairs
# actually measured are listed -- America/Buenos_Aires is deliberately absent
# because all three engines collapse that one identically.
# Keyed by canonical zone, then engine, and it holds **only zones actually
# probed**. That restriction is the point. A first version of this returned the
# canonical spelling for every unmeasured zone and immediately flagged 254
# correct personas recording `America/Buenos_Aires` -- which is what all three
# engines report for Argentina. Generalising from three measured zones to every
# zone is the same error this whole file spent the day correcting.
_MEASURED_TIMEZONE_SPELLINGS: dict[str, dict[str, str]] = {
    "Asia/Kolkata": {
        "chromium": "Asia/Calcutta",
        "webkit": "Asia/Calcutta",
        "firefox": "Asia/Kolkata",
    },
    "Asia/Ho_Chi_Minh": {
        "chromium": "Asia/Saigon",
        "webkit": "Asia/Saigon",
        "firefox": "Asia/Ho_Chi_Minh",
    },
    "Europe/Kyiv": {
        "chromium": "Europe/Kiev",
        "webkit": "Europe/Kiev",
        "firefox": "Europe/Kyiv",
    },
    # Every engine hands back the link name here, so it is listed to record that
    # it was measured and agrees -- not as an exception.
    "America/Argentina/Buenos_Aires": {
        "chromium": "America/Buenos_Aires",
        "webkit": "America/Buenos_Aires",
        "firefox": "America/Buenos_Aires",
    },
}


def expected_timezone_spelling(engine: Any, canonical: Any) -> Any:
    """Which spelling of a zone this engine reports, or ``None`` if unmeasured.

    ``None`` means "no opinion": the zone was never probed on this engine, and a
    caller must not treat silence as agreement or as a defect.
    """
    return _MEASURED_TIMEZONE_SPELLINGS.get(canonical, {}).get(engine)


def canonical_timezone(name: Any) -> Any:
    """Fold IANA link names onto the zone they point at."""
    if not isinstance(name, str):
        return name
    return _TIMEZONE_ALIASES.get(name, name)


def timezones_equivalent(first: Any, second: Any) -> bool:
    """True when two IANA names denote the same zone, alias or not."""
    return canonical_timezone(first) == canonical_timezone(second)


def _sha256_16(path: Path) -> str:
    return _hash_regular_file(path, label="kernel executable")[0][:16]


def _playwright() -> tuple[Any, str]:
    try:
        from playwright.sync_api import sync_playwright

        version = importlib.metadata.version("playwright")
    except (ImportError, importlib.metadata.PackageNotFoundError):
        raise ContractError("Playwright is required for multi-kernel capability discovery") from None
    return sync_playwright, version


def validate_kernel(document: Any) -> dict[str, Any]:
    if not isinstance(document, dict) or document.get("schema") != KERNEL_SCHEMA:
        raise ContractError("unsupported kernel capability")
    if not isinstance(document.get("id"), str) or not PROFILE_ID_RE.fullmatch(document["id"]):
        raise ContractError("kernel capability ID is invalid")
    if not isinstance(document.get("engine"), str) or document["engine"] not in {"chromium", "firefox", "webkit"}:
        raise ContractError("kernel engine is invalid")
    if not isinstance(document.get("product"), str) or document["product"] not in {"browser-core", "chromium", "firefox", "webkit"}:
        raise ContractError("kernel product is invalid")
    if not isinstance(document.get("available"), bool):
        raise ContractError("kernel availability must be boolean")
    executable = document.get("executable")
    if not isinstance(executable, str) or not Path(executable).is_absolute():
        raise ContractError("kernel executable must be absolute")
    digest = document.get("executable_sha256_16")
    if document["available"]:
        if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{16}", digest):
            raise ContractError("available kernel executable digest is invalid")
        if document.get("unavailable_reason") is not None:
            raise ContractError("available kernel cannot have an unavailable reason")
    else:
        if digest is not None:
            raise ContractError("unavailable kernel cannot have an executable digest")
        if not isinstance(document.get("unavailable_reason"), str) or not document["unavailable_reason"]:
            raise ContractError("unavailable kernel requires a reason")
    capabilities = document.get("capabilities")
    if (
        not isinstance(capabilities, list)
        or not capabilities
        or any(not isinstance(item, str) or not PROFILE_ID_RE.fullmatch(item) for item in capabilities)
        or capabilities != sorted(set(capabilities))
    ):
        raise ContractError("kernel capabilities must be sorted unique safe identifiers")
    source = document.get("source")
    if (
        not isinstance(source, dict)
        or not isinstance(source.get("kind"), str)
        or source["kind"] not in {"attested-browser-core", "playwright-managed"}
    ):
        raise ContractError("kernel source is invalid")
    if source["kind"] == "playwright-managed":
        version = source.get("playwright_version")
        if (
            document["product"] != document["engine"]
            or set(source) != {"kind", "playwright_version"}
            or not isinstance(version, str)
            or not version
            or len(version) > 64
            or not version.isprintable()
        ):
            raise ContractError("kernel source is invalid")
    else:
        created_at = source.get("attestation_created_at")
        if (
            document["product"] != "browser-core"
            or document["engine"] != "chromium"
            or not document["available"]
            or set(source)
            != {
                "kind",
                "provenance",
                "executable_sha256_16",
                "runtime_bundle_sha256_16",
                "attestation_created_at",
            }
            or source.get("provenance") != "attested-browser-core"
            or source.get("executable_sha256_16") != digest
            or not isinstance(source.get("runtime_bundle_sha256_16"), str)
            or not re.fullmatch(r"[0-9a-f]{16}", source["runtime_bundle_sha256_16"])
            or not isinstance(created_at, str)
            or not created_at
            or len(created_at) > 64
            or not created_at.isprintable()
        ):
            raise ContractError("kernel source is invalid")
    return document


def discover_kernels(
    repository_root: Path,
    *,
    browser_core_executable: Path | None = None,
) -> list[dict[str, Any]]:
    sync_playwright, playwright_version = _playwright()
    records: list[dict[str, Any]] = []
    if browser_core_executable is not None:
        executable = browser_core_executable.resolve()
        evidence = executable_evidence(
            repository_root, browser_core_executable, allow_unverified=False
        )
        records.append(
            validate_kernel(
                {
                    "schema": KERNEL_SCHEMA,
                    "id": "browser-core-chromium",
                    "engine": "chromium",
                    "product": "browser-core",
                    "available": True,
                    "executable": str(executable),
                    "executable_sha256_16": evidence["executable_sha256_16"],
                    "unavailable_reason": None,
                    # This is Chromium, driven the same way through the same
                    # protocol, so it emulates a mobile device exactly as the
                    # Playwright build does. The capability was absent only
                    # because this kernel used to be launch-only; every claim it
                    # produces is still measured by the probe's realization
                    # check, so the list is a statement about the binary rather
                    # than a promise about any particular capture.
                    "capabilities": [
                        "cdp",
                        "desktop",
                        "device-memory-override",
                        "mobile-emulation",
                        "native-trace",
                        "persistent-profile",
                    ],
                    "source": {"kind": "attested-browser-core", **evidence},
                }
            )
        )
    with sync_playwright() as playwright:
        for engine in ("chromium", "firefox", "webkit"):
            browser_type = getattr(playwright, engine)
            executable = Path(browser_type.executable_path).resolve()
            available = executable.is_file()
            capabilities = ["desktop", "playwright"]
            if engine in {"chromium", "webkit"}:
                capabilities.append("mobile-emulation")
            if engine == "chromium":
                capabilities.append("cdp")
            records.append(
                validate_kernel(
                    {
                        "schema": KERNEL_SCHEMA,
                        "id": f"playwright-{engine}",
                        "engine": engine,
                        "product": engine,
                        "available": available,
                        "executable": str(executable),
                        "executable_sha256_16": _sha256_16(executable) if available else None,
                        "unavailable_reason": None if available else "Playwright browser payload is not installed",
                        "capabilities": sorted(capabilities),
                        "source": {"kind": "playwright-managed", "playwright_version": playwright_version},
                    }
                )
            )
    return records


def _validated_device_text(value: Any, *, field: str, maximum: int) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum or not value.isprintable():
        raise ContractError(f"device {field.replace('_', ' ')} is invalid")
    return value


def validate_device(document: Any) -> dict[str, Any]:
    if not isinstance(document, dict) or document.get("schema") != DEVICE_SCHEMA:
        raise ContractError("unsupported device contract")
    if not isinstance(document.get("id"), str) or not PROFILE_ID_RE.fullmatch(document["id"]):
        raise ContractError("device ID is invalid")
    if not isinstance(document.get("class"), str) or document["class"] not in {"desktop", "mobile", "tablet"}:
        raise ContractError("device class is invalid")
    if not isinstance(document.get("realization"), str) or document["realization"] not in {"native-host", "emulated", "physical-device"}:
        raise ContractError("device realization is invalid")
    if not isinstance(document.get("default_engine"), str) or document["default_engine"] not in {"chromium", "firefox", "webkit"}:
        raise ContractError("device default engine is invalid")
    for field in ("is_mobile", "has_touch"):
        if not isinstance(document.get(field), bool):
            raise ContractError(f"device {field} must be boolean")
    if document["class"] in {"mobile", "tablet"} and (not document["is_mobile"] or not document["has_touch"]):
        raise ContractError("mobile/tablet devices must realize mobile touch")
    viewport = document.get("viewport")
    screen = document.get("screen")
    for label, dimensions in (("viewport", viewport), ("screen", screen)):
        if not isinstance(dimensions, dict) or set(dimensions) != {"width", "height"}:
            raise ContractError(f"device {label} is invalid")
        if any(
            isinstance(dimensions[field], bool)
            or not isinstance(dimensions[field], int)
            or not 100 <= dimensions[field] <= 10000
            for field in ("width", "height")
        ):
            raise ContractError(f"device {label} dimensions are invalid")
    scale = document.get("device_scale_factor")
    if isinstance(scale, bool) or not isinstance(scale, (int, float)) or not 0.5 <= scale <= 8:
        raise ContractError("device scale factor is invalid")
    for field, maximum in (("name", 256), ("user_agent", 4096), ("locale", 128), ("timezone", 128)):
        _validated_device_text(document.get(field), field=field, maximum=maximum)
    provenance = document.get("provenance")
    if (
        not isinstance(provenance, dict)
        or not isinstance(provenance.get("kind"), str)
        or provenance["kind"] not in {"owned", "playwright-preset"}
    ):
        raise ContractError("device provenance is invalid")
    return document


def playwright_device_catalog(pattern: str | None = None) -> list[dict[str, Any]]:
    sync_playwright, version = _playwright()
    with sync_playwright() as playwright:
        results = []
        for name, descriptor in playwright.devices.items():
            if pattern and pattern.casefold() not in name.casefold():
                continue
            results.append(
                {
                    "name": name,
                    "default_engine": descriptor.get("default_browser_type"),
                    "is_mobile": bool(descriptor.get("is_mobile")),
                    "has_touch": bool(descriptor.get("has_touch")),
                    "viewport": descriptor.get("viewport"),
                    "device_scale_factor": descriptor.get("device_scale_factor"),
                    "playwright_version": version,
                }
            )
        return sorted(results, key=lambda item: item["name"].casefold())


def _device_from_playwright_descriptor(
    name: str,
    descriptor: dict[str, Any],
    *,
    version: str,
    locale: str,
    timezone: str,
) -> dict[str, Any]:
    viewport = dict(descriptor["viewport"])
    device_class = "mobile" if descriptor.get("is_mobile") else "desktop"
    if descriptor.get("is_mobile") and min(viewport.values()) >= 600:
        device_class = "tablet"
    safe_id = re.sub(r"[^A-Za-z0-9._-]+", "-", name).strip("-.")[:48].lower()
    document = {
        "schema": DEVICE_SCHEMA,
        "id": f"pw-{safe_id}",
        "name": name,
        "class": device_class,
        "realization": "emulated",
        "default_engine": descriptor["default_browser_type"],
        "is_mobile": bool(descriptor["is_mobile"]),
        "has_touch": bool(descriptor["has_touch"]),
        "viewport": viewport,
        "screen": dict(descriptor.get("screen") or viewport),
        "device_scale_factor": descriptor["device_scale_factor"],
        "user_agent": descriptor["user_agent"],
        "locale": locale,
        "timezone": timezone,
        "provenance": {"kind": "playwright-preset", "preset": name, "playwright_version": version},
    }
    return validate_device(document)


def playwright_device_contract_catalog(
    *,
    locale: str,
    timezone: str,
    pattern: str | None = None,
) -> list[dict[str, Any]]:
    """Materialize every selected Playwright preset through one driver session."""
    _validated_device_text(locale, field="locale", maximum=128)
    _validated_device_text(timezone, field="timezone", maximum=128)
    sync_playwright, version = _playwright()
    with sync_playwright() as playwright:
        devices = [
            _device_from_playwright_descriptor(
                name,
                dict(descriptor),
                version=version,
                locale=locale,
                timezone=timezone,
            )
            for name, descriptor in playwright.devices.items()
            if not pattern or pattern.casefold() in name.casefold()
        ]
    return sorted(devices, key=lambda item: item["name"].casefold())


def relocalize_playwright_device(
    device: dict[str, Any], *, locale: str, timezone: str
) -> dict[str, Any]:
    """Clone a validated preset contract with only its context locale changed."""
    source = validate_device(device)
    provenance = source.get("provenance")
    if not isinstance(provenance, dict) or provenance.get("kind") != "playwright-preset":
        raise ContractError("only Playwright preset devices can be relocalized")
    return validate_device(
        {
            **source,
            "viewport": dict(source["viewport"]),
            "screen": dict(source["screen"]),
            "provenance": dict(provenance),
            "locale": locale,
            "timezone": timezone,
        }
    )


def device_from_playwright(name: str, *, locale: str, timezone: str) -> dict[str, Any]:
    _validated_device_text(locale, field="locale", maximum=128)
    _validated_device_text(timezone, field="timezone", maximum=128)
    sync_playwright, version = _playwright()
    with sync_playwright() as playwright:
        try:
            descriptor = dict(playwright.devices[name])
        except KeyError:
            raise ContractError(f"unknown Playwright device preset: {name}") from None
    return _device_from_playwright_descriptor(
        name,
        descriptor,
        version=version,
        locale=locale,
        timezone=timezone,
    )


# Both are Chromium-family binaries Playwright can drive over CDP. The attested
# build is admitted here because it is the only one carrying native patch 0005,
# and a capture that needs the device-memory switch has nowhere else to run.
_PROBEABLE_KERNEL_SOURCES = frozenset({"playwright-managed", "attested-browser-core"})


def _check_probe_preconditions(kernel: dict[str, Any], device: dict[str, Any]) -> tuple[dict, dict]:
    kernel = validate_kernel(kernel)
    device = validate_device(device)
    if kernel["source"]["kind"] not in _PROBEABLE_KERNEL_SOURCES:
        raise ContractError("this probe accepts only Playwright-driven kernels")
    if device["realization"] == "physical-device":
        raise ContractError("Playwright cannot prove a physical-device realization")
    if device["class"] in {"mobile", "tablet"} and "mobile-emulation" not in kernel["capabilities"]:
        raise ContractError("kernel cannot realize this mobile device contract")
    if (
        device["provenance"]["kind"] == "playwright-preset"
        and kernel["engine"] != device["default_engine"]
    ):
        raise ContractError("Playwright preset default engine does not match kernel")
    if not kernel["available"]:
        raise ContractError(f"kernel is unavailable: {kernel['unavailable_reason']}")
    return kernel, device


def _safe_device_id(device: Any) -> str | None:
    value = device.get("id") if isinstance(device, dict) else None
    return value if isinstance(value, str) and PROFILE_ID_RE.fullmatch(value) else None


def _verify_probe_executable(kernel: dict[str, Any], browser_type: Any) -> None:
    declared = Path(kernel["executable"]).resolve()
    if kernel["source"]["kind"] == "playwright-managed":
        browser_path = getattr(browser_type, "executable_path", None)
        if not isinstance(browser_path, str) or Path(browser_path).resolve() != declared:
            raise ContractError("kernel executable does not match Playwright browser")
    if _sha256_16(declared) != kernel["executable_sha256_16"]:
        raise ContractError("kernel executable digest no longer matches its capability record")


def probe_playwright_kernel(kernel: dict[str, Any], device: dict[str, Any]) -> dict[str, Any]:
    """Probe one device contract, launching a browser for it.

    Convenient for a single capture and ruinous for a thousand: see
    ``probe_playwright_kernel_batch`` when capturing more than a handful.
    """
    kernel, device = _check_probe_preconditions(kernel, device)
    sync_playwright, _ = _playwright()
    with sync_playwright() as playwright:
        browser_type = getattr(playwright, kernel["engine"])
        _verify_probe_executable(kernel, browser_type)
        # Bounded launch so bulk commercial capture cannot hang forever on a
        # wedged browser process.
        launch: dict[str, Any] = {"headless": True, "timeout": 20_000}
        if kernel["source"]["kind"] == "attested-browser-core":
            launch["executable_path"] = kernel["executable"]
            launch["args"] = ["--browser-core-evaluation"]
        browser = browser_type.launch(**launch)
        try:
            return _probe_with_browser(browser, browser.version, kernel, device)
        finally:
            browser.close()


def probe_playwright_kernel_batch(
    kernel: dict[str, Any],
    devices: Sequence[dict[str, Any]],
    hardware_concurrencies: Sequence[int | None] | None = None,
    device_memory_mbs: Sequence[int | None] | None = None,
    executable_path: str | None = None,
) -> list[dict[str, Any]]:
    """Probe many device contracts through a single browser process.

    One browser, many contexts. The per-device path launches and tears down a
    whole browser for each capture, which is fine for one persona and is why the
    catalog could not grow: this host starts refusing to bind loopback sockets
    after roughly two hundred launches -- nonpaged pool, not ports -- and a
    thousand-persona matrix needs a thousand of them. Contexts are isolated
    enough for this measurement and cost milliseconds.

    Yields one entry per device in order. A device that fails is returned as
    ``{"error": ...}`` rather than aborting the batch, because one wedged preset
    should not cost the other nine hundred.
    """
    if not devices:
        return []
    kernel = validate_kernel(kernel)
    if kernel["source"]["kind"] not in _PROBEABLE_KERNEL_SOURCES:
        raise ContractError("this probe accepts only Playwright-driven kernels")
    if not kernel["available"]:
        raise ContractError(f"kernel is unavailable: {kernel['unavailable_reason']}")
    concurrencies = list(
        [None] * len(devices) if hardware_concurrencies is None else hardware_concurrencies
    )
    if len(concurrencies) != len(devices):
        raise ContractError("hardware_concurrencies must match devices one-for-one")
    if any(
        value is not None and (isinstance(value, bool) or not isinstance(value, int) or value <= 0)
        for value in concurrencies
    ):
        raise ContractError("hardware_concurrencies values must be positive integers or null")
    memories = list([None] * len(devices) if device_memory_mbs is None else device_memory_mbs)
    if len(memories) != len(devices):
        raise ContractError("device_memory_mbs must match devices one-for-one")
    if any(
        value is not None and (isinstance(value, bool) or not isinstance(value, int) or value <= 0)
        for value in memories
    ):
        raise ContractError("device_memory_mbs values must be positive integers or null")
    # A kernel names its own binary. Letting a caller point one at a different
    # executable would put the wrong provenance in every persona of the batch --
    # a Playwright kernel driving the attested build would record
    # "kernel-probe:playwright-chromium" for a browser that is not Playwright's,
    # and nothing downstream could tell. So the path is an assertion, not a
    # choice: supply it and it must agree, or leave it out.
    #
    # Compared as resolved paths rather than strings, because "H:/bc/..." and
    # "H:\\bc\\..." name the same binary and a guard that rejects one of them is
    # checking spelling rather than identity.
    if executable_path is not None and (
        Path(executable_path).resolve() != Path(kernel["executable"]).resolve()
    ):
        raise ContractError("a kernel may only probe the executable it names")
    if kernel["source"]["kind"] == "attested-browser-core":
        executable_path = kernel["executable"]
    if any(memory is not None for memory in memories):
        if "device-memory-override" not in kernel["capabilities"]:
            raise ContractError(
                "a device memory override needs a kernel carrying native patch "
                "0005; a stock binary ignores the switch without complaint"
            )

    # Device memory is a process-wide launch switch, not a per-context option, so
    # one browser cannot serve two memory sizes. Group the batch by requested
    # size and launch once per group: a handful of launches for a thousand
    # devices still keeps the batching win that made the catalog growable, and
    # results are reassembled into caller order so the grouping is invisible.
    groups: dict[int | None, list[int]] = {}
    for index, memory in enumerate(memories):
        groups.setdefault(memory, []).append(index)

    results: list[dict[str, Any] | None] = [None] * len(devices)
    sync_playwright, _ = _playwright()
    with sync_playwright() as playwright:
        browser_type = getattr(playwright, kernel["engine"])
        _verify_probe_executable(kernel, browser_type)
        for memory, indexes in groups.items():
            launch: dict[str, Any] = {"headless": True, "timeout": 20_000}
            if executable_path is not None:
                launch["executable_path"] = executable_path
            if memory is not None:
                launch["args"] = [f"{DEVICE_MEMORY_SWITCH}={int(memory)}"]
            if kernel["source"]["kind"] == "attested-browser-core":
                launch.setdefault("args", []).append("--browser-core-evaluation")
            browser = browser_type.launch(**launch)
            try:
                version = browser.version
                for index in indexes:
                    device = devices[index]
                    try:
                        checked_kernel, checked_device = _check_probe_preconditions(kernel, device)
                        results[index] = _probe_with_browser(
                            browser,
                            version,
                            checked_kernel,
                            checked_device,
                            concurrencies[index],
                            device_memory_mb=memory,
                        )
                    except ContractError as exc:
                        results[index] = {
                            "error": safe_failure_receipt(exc),
                            "device_id": _safe_device_id(device),
                        }
                    except Exception as exc:  # noqa: BLE001 - one preset must not end the batch
                        results[index] = {
                            "error": safe_failure_receipt(exc),
                            "device_id": _safe_device_id(device),
                        }
            finally:
                browser.close()
    if any(entry is None for entry in results):
        # Callers zip this list against their own device and plan lists, so a
        # short return would silently attach one persona's probe to another
        # persona's record. Every index is written in the loop above; if that
        # ever stops being true, fail loudly rather than misalign the catalog.
        raise ContractError("probe batch did not produce a result for every device")
    return [entry for entry in results if entry is not None]


# Logical-core counts that real consumer machines actually report. Sampling from
# this instead of inheriting the capture host's value is the difference between a
# catalog of identities and a catalog of one machine wearing costumes.
REALISTIC_CORE_COUNTS: tuple[int, ...] = (2, 4, 4, 6, 8, 8, 8, 10, 12, 12, 16, 16, 20, 24)

# Phones are not small desktops. Android SoCs are essentially all 4-, 6-, or
# 8-core, overwhelmingly 8, and no shipping handset reports 24 the way the table
# above allows. Unlike device memory there is no native clamp to lean on --
# `NavigatorConcurrentHardware::hardwareConcurrency` returns
# `base::SysInfo::NumberOfProcessors()` with no cap at all -- so nothing stops a
# capture host from writing its own core count into a phone persona, and nothing
# but this table stops the catalog from claiming a 24-core Pixel.
REALISTIC_MOBILE_CORE_COUNTS: tuple[int, ...] = (4, 4, 6, 6, 8, 8, 8, 8)

# The largest count seen on a shipping phone. Above it a persona is not
# impossible -- the API has no ceiling -- just not a device anyone sells.
PLAUSIBLE_MOBILE_CORE_MAXIMUM = 8

# What a touch device reports for navigator.maxTouchPoints. Android Chrome and
# iOS Safari both report 5, and CDP's Emulation.setTouchEmulationEnabled
# "Defaults to one" -- which is where 4,502 single-touch phones came from. A
# screen that cannot register a second finger is not a phone.
TOUCH_POINTS = 5

# The switch added by native patch 0005. It replaces the physical memory size
# that navigator.deviceMemory is derived from; the value still passes through
# Chromium's own rounding and clamp, so the property can only report a number
# the build could otherwise produce. Only the attested Browser Core build
# understands it -- a stock binary ignores it silently, which is exactly why the
# realization check below measures the result instead of trusting the request.
DEVICE_MEMORY_SWITCH = "--browser-core-device-memory-mb"

# Physical sizes, in MiB, that map onto the values real machines report. Chromium
# clamps a desktop build to [2, 32], so these are inputs chosen for the value
# they produce, not for realism as raw RAM figures.
REALISTIC_DESKTOP_MEMORY_MB: tuple[int, ...] = (
    4096, 8192, 8192, 8192, 16384, 16384, 16384, 32768, 32768,
)

# Android caps at 8 in native code however much RAM the phone has, so a mobile
# persona may only ever report 2, 4, or 8. A desktop build reaches those same
# three values through its own [2, 32] clamp, which is why a phone captured on
# this host can be made correct without an Android build.
REALISTIC_MOBILE_MEMORY_MB: tuple[int, ...] = (
    2048, 3072, 4096, 4096, 4096, 6144, 8192, 8192, 12288,
)

_DEVICE_MEMORY_DESKTOP_FLOOR = 2.0
_DEVICE_MEMORY_DESKTOP_CEILING = 32.0

_UA_CHROME_VERSION_RE = re.compile(r"(?<=Chrome/)[0-9]+(?:\.[0-9]+)*")


def align_user_agent_version(user_agent: str, browser_version: str) -> str:
    """Put the running browser's version into a preset's user agent string.

    Playwright's device descriptors carry a user agent with *its own* bundled
    Chromium version baked in. Drive a different binary through the same preset
    -- which is exactly what capturing on the attested build does -- and the
    browser tells a page two different versions: ``navigator.userAgent`` repeats
    the preset's, while ``navigator.userAgentData.brands`` reports the truth.

    Measured on this host before the fix: user agent ``Chrome/147.0.7727.15``
    against brands ``Chromium 153``. Comparing those two is a one-line check and
    a standard one, so the emulation has to agree with itself. Only the version
    is rewritten -- platform, device model and the rest of the preset are left
    exactly as they were, and the result is read back from the browser like every
    other claim rather than trusted.
    """
    if not isinstance(user_agent, str) or not isinstance(browser_version, str):
        raise ContractError("user agent alignment needs two strings")
    version_parts = browser_version.split(".")
    if not version_parts or any(not is_ascii_decimal(part) for part in version_parts):
        # An empty or malformed version would substitute into "Chrome/" and leave
        # a user agent no browser has ever sent, which is a worse outcome than
        # the mismatch this function exists to remove.
        raise ContractError("browser version is not a version")
    if not _UA_CHROME_VERSION_RE.search(user_agent):
        if "Chrome/" in user_agent:
            raise ContractError("user agent Chrome version is invalid")
        # Firefox and WebKit presets carry no Chrome token; nothing to align, and
        # inventing one would be worse than leaving it alone.
        return user_agent
    return _UA_CHROME_VERSION_RE.sub(browser_version, user_agent, count=1)


def approximate_device_memory(physical_memory_mb: int) -> float:
    """What a desktop Chromium reports for a host of this size.

    A line-for-line mirror of Chromium's ``ApproximatedDeviceMemory``: round to
    the nearer power of two, ties going *down* because upstream compares with
    ``<=``, then clamp to the desktop range. Kept in Python so a requested
    override has an expected value to be checked against -- the capture asserts
    the browser produced this number rather than assuming the switch took, and a
    stock binary that ignores the switch fails the check instead of silently
    minting a persona carrying the capture host's own RAM.
    """
    if isinstance(physical_memory_mb, bool) or not isinstance(physical_memory_mb, int):
        raise ContractError("physical memory must be an integer number of MiB")
    if physical_memory_mb <= 0:
        raise ContractError("physical memory must be a positive number of MiB")
    power = physical_memory_mb.bit_length() - 1
    lower = 1 << power
    upper = 1 << (power + 1)
    nearer = lower if physical_memory_mb - lower <= upper - physical_memory_mb else upper
    gigabytes = nearer / 1024.0
    if gigabytes < _DEVICE_MEMORY_DESKTOP_FLOOR:
        return _DEVICE_MEMORY_DESKTOP_FLOOR
    if gigabytes > _DEVICE_MEMORY_DESKTOP_CEILING:
        return _DEVICE_MEMORY_DESKTOP_CEILING
    return gigabytes


def _probe_with_browser(
    browser: Any,
    browser_version: str,
    kernel: dict[str, Any],
    device: dict[str, Any],
    hardware_concurrency: int | None = None,
    *,
    device_memory_mb: int | None = None,
) -> dict[str, Any]:
    """Run one device probe inside an already-running browser.

    ``hardware_concurrency`` asks Chromium to report a different logical-core
    count through ``Emulation.setHardwareConcurrencyOverride``. It is applied
    before navigation and then *measured*, never assumed: the persona records
    what the browser reported, and the realization check fails if the override
    did not take. Other engines ignore it, because there is no equivalent and
    writing an unrealizable number into a contract is the defect this whole audit
    exists to catch.

    ``device_memory_mb`` is not applied here -- it is a launch switch owned by the
    caller that started this browser -- but it is *checked* here, for the same
    reason: the persona records what the browser reported, and a binary that does
    not understand the switch must fail the capture rather than pass it.
    """
    options: dict[str, Any] = {
        "viewport": device["viewport"],
        "screen": device["screen"],
        "device_scale_factor": device["device_scale_factor"],
        "has_touch": device["has_touch"],
        # The preset's user agent names Playwright's own Chromium version, which
        # is only correct while Playwright's own Chromium is the browser. See
        # align_user_agent_version.
        "user_agent": align_user_agent_version(device["user_agent"], browser_version),
        "locale": device["locale"],
        "timezone_id": device["timezone"],
    }
    if kernel["engine"] in {"chromium", "webkit"}:
        options["is_mobile"] = device["is_mobile"]
    if kernel["source"]["kind"] == "attested-browser-core" and device["class"] == "desktop":
        # Native desktop profiles must capture the UA that evaluation launch
        # will actually use, including Chromium's reduced minor/build version.
        options.pop("user_agent")
    context = browser.new_context(**options)
    try:
        # Serve the probe page from an https origin that is fulfilled
        # locally, never fetched. `set_content` leaves the page on
        # about:blank, which is not a secure context, and Chromium hides
        # `navigator.userAgentData` outside one -- so every Chromium
        # persona captured that way silently lost its Client Hints and
        # looked like a browser that does not implement them. The
        # `.invalid` TLD is reserved and cannot resolve, so interception
        # is the only way this request can ever be answered.
        context.route(_PROBE_URL_PATTERN, _fulfill_probe_page)
        page = context.new_page()
        page.set_default_timeout(15_000)
        applied_touch_points: int | None = None
        if kernel["engine"] == "chromium" and (
            hardware_concurrency is not None or device["has_touch"]
        ):
            try:
                session = context.new_cdp_session(page)
            except Exception:  # noqa: BLE001 - no CDP is not a probe failure
                session = None
            # Keep the override attempts independent. Even if the processor
            # command fails, the observation must match the requested core
            # count before this planned identity can pass.
            if session is not None and hardware_concurrency is not None:
                try:
                    session.send(
                        "Emulation.setHardwareConcurrencyOverride",
                        {"hardwareConcurrency": int(hardware_concurrency)},
                    )
                except Exception:  # noqa: BLE001 - an unsupported override is not a failure
                    pass
            if session is not None and device["has_touch"]:
                # Playwright's has_touch turns touch on and leaves the count at
                # the protocol default, which is *one*. Every touch device in the
                # catalog therefore reported a single touch point -- a screen that
                # cannot pinch. Real phones report five, on both Android and iOS,
                # so this is a correction rather than an axis: varying it would be
                # inventing hardware.
                try:
                    session.send(
                        "Emulation.setTouchEmulationEnabled",
                        {"enabled": True, "maxTouchPoints": TOUCH_POINTS},
                    )
                    applied_touch_points = TOUCH_POINTS
                except Exception:  # noqa: BLE001 - an unsupported override is not a failure
                    applied_touch_points = None
        page.goto(_PROBE_URL)
        observed = page.evaluate(
            """() => {
              const canvas = document.createElement('canvas');
              const gl = canvas.getContext('webgl2') || canvas.getContext('webgl');
              const debug = gl ? gl.getExtension('WEBGL_debug_renderer_info') : null;
              const uaData = navigator.userAgentData;
              return {
                title: document.title,
                secureContext: isSecureContext,
                userAgent: navigator.userAgent,
                userAgentDataMobile: uaData ? uaData.mobile : null,
                userAgentDataPlatform: uaData ? uaData.platform : null,
                // Brand versions, so the realization check can confirm that the
                // user agent string and the client hints name the same browser.
                // A page can compare these two in one line.
                userAgentDataBrands: uaData
                  ? uaData.brands.map(function (b) { return b.brand + '/' + b.version; })
                  : null,
                platform: navigator.platform,
                languages: Array.from(navigator.languages || []),
                maxTouchPoints: navigator.maxTouchPoints,
                hardwareConcurrency: navigator.hardwareConcurrency,
                deviceMemory: navigator.deviceMemory ?? null,
                pluginsLength: navigator.plugins.length,
                mimeTypesLength: navigator.mimeTypes.length,
                pdfViewerEnabled: navigator.pdfViewerEnabled ?? null,
                innerWidth: innerWidth,
                innerHeight: innerHeight,
                screenWidth: screen.width,
                screenHeight: screen.height,
                // Read by essentially every fingerprinting script, and until now
                // absent from every captured persona -- which left the existing
                // "available screen exceeds screen" rule unable to fire on
                // anything but a hand-written fixture.
                availWidth: screen.availWidth,
                availHeight: screen.availHeight,
                colorDepth: screen.colorDepth,
                pixelDepth: screen.pixelDepth,
                devicePixelRatio: devicePixelRatio,
                language: navigator.language,
                intlLocale: Intl.DateTimeFormat().resolvedOptions().locale,
                timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
                coarsePointer: matchMedia('(pointer: coarse)').matches,
                touchEventSurface: 'ontouchstart' in window,
                chromeObject: typeof window.chrome === 'object',
                // Canonical identity fields use WebGL 2 when available and the
                // actual device strings. Preserve the selector in provenance;
                // older probes used masked WebGL 1 strings under the same names.
                webglIdentitySchema: 'webgl2-preferred-unmasked-v1',
                webglVendor: gl ? gl.getParameter(debug ? debug.UNMASKED_VENDOR_WEBGL : gl.VENDOR) : null,
                webglRenderer: gl ? gl.getParameter(debug ? debug.UNMASKED_RENDERER_WEBGL : gl.RENDERER) : null,
                webglVersion: gl ? gl.getParameter(gl.VERSION) : null,
                // Retain these auxiliary fields for existing evidence readers.
                // A catalog captured on one GPU still represents one GPU.
                webglUnmaskedVendor: (function () {
                  if (!gl) return null;
                  var ext = gl.getExtension('WEBGL_debug_renderer_info');
                  return ext ? gl.getParameter(ext.UNMASKED_VENDOR_WEBGL) : null;
                })(),
                webglUnmaskedRenderer: (function () {
                  if (!gl) return null;
                  var ext = gl.getExtension('WEBGL_debug_renderer_info');
                  return ext ? gl.getParameter(ext.UNMASKED_RENDERER_WEBGL) : null;
                })()
              };
            }"""
        )
    finally:
        context.close()
    checks = {
        "owned_fixture": observed["title"] == "owned-kernel-probe",
        # Client Hints only exist in a secure context. Recording this makes the
        # difference between "this browser has no UA-CH" and "we did not ask from
        # somewhere it would answer" visible in the evidence.
        "secure_context": observed.get("secureContext") is True,
        "viewport": [observed["innerWidth"], observed["innerHeight"]]
        == [device["viewport"]["width"], device["viewport"]["height"]],
        "screen": [observed["screenWidth"], observed["screenHeight"]]
        == [device["screen"]["width"], device["screen"]["height"]],
        "scale": observed["devicePixelRatio"] == device["device_scale_factor"],
        # WebKit exposes ontouchstart on desktop as an API surface, so it is
        # not evidence of a realized touch input model. Pointer coarseness and
        # maxTouchPoints are the cross-engine behavioral signals here.
        "touch": bool(observed["maxTouchPoints"] > 0 or observed["coarsePointer"])
        == device["has_touch"],
        "locale": observed["language"].casefold() == device["locale"].casefold(),
        "timezone": timezones_equivalent(observed["timezone"], device["timezone"]),
    }
    if "user_agent" in options:
        # Client Hints can agree with the browser's native UA even when the
        # requested device UA was ignored. Bind the observation to the request.
        checks["user_agent"] = observed.get("userAgent") == options["user_agent"]
    if device["class"] in {"mobile", "tablet"}:
        # A failed CDP touch override can leave the protocol default of one.
        # The capture must not call that a realized phone or tablet.
        checks["multi_touch"] = (
            type(observed.get("maxTouchPoints")) is int
            and observed["maxTouchPoints"] >= 2
        )
    if hardware_concurrency is not None:
        # A failed command may leave the host count unchanged. Compare the
        # observation with the planned identity even when CDP was unavailable.
        checks["hardware_concurrency"] = (
            observed["hardwareConcurrency"] == hardware_concurrency
        )
    if applied_touch_points is not None:
        checks["max_touch_points"] = observed["maxTouchPoints"] == applied_touch_points
    # The user agent and the client hints must name one browser. They did not
    # when a preset's baked-in version met a different binary, and the two are a
    # one-line comparison for anyone who wants to make it.
    if kernel["engine"] == "chromium":
        # A missing Client Hints surface must not erase the comparison. On a
        # secure Chromium probe origin, that is a failed realization check.
        brands = observed.get("userAgentDataBrands")
        agent = observed.get("userAgent")
        agent_major = _UA_CHROME_VERSION_RE.search(agent) if isinstance(agent, str) else None
        wanted = agent_major.group(0).split(".", 1)[0] if agent_major is not None else None
        checks["user_agent_matches_client_hints"] = bool(
            wanted is not None
            and isinstance(brands, list)
            and any(
                entry.rsplit("/", 1)[-1].split(".", 1)[0] == wanted
                for entry in brands
                if isinstance(entry, str)
                and "Not" not in entry  # the deliberate GREASE brand carries no version
            )
        )
        checks["client_hints_mobile"] = (
            type(observed.get("userAgentDataMobile")) is bool
            and observed["userAgentDataMobile"] == device["is_mobile"]
        )
    if device_memory_mb is not None:
        # The switch is a request, and a binary without patch 0005 ignores it
        # without complaint. Compare what the browser reported against what
        # Chromium's own arithmetic says a host of that size produces, so an
        # ignored switch fails the capture rather than minting a persona that
        # quietly carries this machine's 64 GiB.
        checks["device_memory"] = (
            observed["deviceMemory"] == approximate_device_memory(int(device_memory_mb))
        )
    return {
        "schema": KERNEL_PROBE_SCHEMA,
        "kernel_id": kernel["id"],
        "engine": kernel["engine"],
        "browser_version": browser_version,
        "device_id": device["id"],
        "device_realization": device["realization"],
        "passed": all(checks.values()),
        "checks": checks,
        "observed": observed,
    }
