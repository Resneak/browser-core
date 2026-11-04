#!/usr/bin/env python3
"""Capture additional provenance-backed personas into a Browser Core workspace."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from browser_core.personas import (  # noqa: E402
    add_persona,
    capture_kernel_persona,
    catalog_coverage_report,
    list_personas,
    store_persona_evidence,
)

# Multi-axis owned captures: locale/country/timezone diversity across engines.
CAPTURES: list[dict[str, object]] = [
    {
        "persona_id": "owned-pw-chrome-de-de",
        "name": "Owned Chromium Desktop DE",
        "kernel_id": "playwright-chromium",
        "device_preset": "Desktop Chrome",
        "os_family": "windows",
        "os_version": "11",
        "architecture": "x86_64",
        "country": "DE",
        "locale": "de-DE",
        "timezone": "Europe/Berlin",
        "tags": ("owned", "locale-de", "desktop", "chromium"),
    },
    {
        "persona_id": "owned-pw-chrome-en-gb",
        "name": "Owned Chromium Desktop GB",
        "kernel_id": "playwright-chromium",
        "device_preset": "Desktop Chrome",
        "os_family": "windows",
        "os_version": "11",
        "architecture": "x86_64",
        "country": "GB",
        "locale": "en-GB",
        "timezone": "Europe/London",
        "tags": ("owned", "locale-en-gb", "desktop", "chromium"),
    },
    {
        "persona_id": "owned-pw-chrome-ja-jp",
        "name": "Owned Chromium Desktop JP",
        "kernel_id": "playwright-chromium",
        "device_preset": "Desktop Chrome HiDPI",
        "os_family": "windows",
        "os_version": "11",
        "architecture": "x86_64",
        "country": "JP",
        "locale": "ja-JP",
        "timezone": "Asia/Tokyo",
        "tags": ("owned", "locale-ja", "desktop", "chromium"),
    },
    {
        "persona_id": "owned-pw-firefox-fr-fr",
        "name": "Owned Firefox Desktop FR",
        "kernel_id": "playwright-firefox",
        "device_preset": "Desktop Firefox",
        "os_family": "windows",
        "os_version": "11",
        "architecture": "x86_64",
        "country": "FR",
        "locale": "fr-FR",
        "timezone": "Europe/Paris",
        "tags": ("owned", "locale-fr", "desktop", "firefox"),
    },
    {
        "persona_id": "owned-pw-webkit-en-gb",
        "name": "Owned WebKit Desktop GB",
        "kernel_id": "playwright-webkit",
        "device_preset": "Desktop Safari",
        "os_family": "macos",
        "os_version": "14",
        "architecture": "x86_64",
        "country": "GB",
        "locale": "en-GB",
        "timezone": "Europe/London",
        "tags": ("owned", "locale-en-gb", "desktop", "webkit"),
    },
    {
        "persona_id": "owned-pw-galaxy-s24-es-es",
        "name": "Owned Galaxy S24 ES emulated",
        "kernel_id": "playwright-chromium",
        "device_preset": "Galaxy S24",
        "os_family": "android",
        "os_version": "14",
        "architecture": "arm64",
        "country": "ES",
        "locale": "es-ES",
        "timezone": "Europe/Madrid",
        "tags": ("owned", "locale-es", "mobile", "chromium", "emulated"),
    },
    {
        "persona_id": "owned-pw-iphone14-de-de",
        "name": "Owned iPhone 14 DE emulated",
        "kernel_id": "playwright-webkit",
        "device_preset": "iPhone 14",
        "os_family": "ios",
        "os_version": "17",
        "architecture": "arm64",
        "country": "DE",
        "locale": "de-DE",
        "timezone": "Europe/Berlin",
        "tags": ("owned", "locale-de", "mobile", "webkit", "emulated"),
    },
    {
        "persona_id": "owned-pw-pixel5-en-gb",
        "name": "Owned Pixel 5 GB emulated",
        "kernel_id": "playwright-chromium",
        "device_preset": "Pixel 5",
        "os_family": "android",
        "os_version": "14",
        "architecture": "arm64",
        "country": "GB",
        "locale": "en-GB",
        "timezone": "Europe/London",
        "tags": ("owned", "locale-en-gb", "mobile", "chromium", "emulated"),
    },
]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument(
        "--repository-root",
        type=Path,
        default=ROOT,
        help="browser-core repository root for kernel discovery",
    )
    args = parser.parse_args()
    workspace = args.workspace.resolve()
    repo = args.repository_root.resolve()
    existing = {item["id"] for item in list_personas(workspace, include_deprecated=True)}
    results = []
    for spec in CAPTURES:
        persona_id = str(spec["persona_id"])
        if persona_id in existing:
            results.append({"id": persona_id, "status": "already-present"})
            continue
        persona, evidence = capture_kernel_persona(
            repo,
            persona_id=persona_id,
            name=str(spec["name"]),
            kernel_id=str(spec["kernel_id"]),
            device_preset=str(spec["device_preset"]),
            os_family=str(spec["os_family"]),
            os_version=str(spec["os_version"]),
            architecture=str(spec["architecture"]),
            country=str(spec["country"]),
            locale=str(spec["locale"]),
            timezone_name=str(spec["timezone"]),
            tags=spec["tags"],  # type: ignore[arg-type]
        )
        store_persona_evidence(
            workspace,
            evidence,
            expected_sha256=persona["provenance"]["source_sha256"],
        )
        stored = add_persona(workspace, persona)
        results.append(
            {
                "id": stored["id"],
                "status": "captured",
                "locale": stored["geography"]["locale"],
                "engine": stored["kernel"]["engine"],
                "device_class": stored["device"]["class"],
                "claims": len(stored["identity_contract"]["expected"]),
            }
        )
        existing.add(persona_id)
    coverage = catalog_coverage_report(workspace)
    print(
        json.dumps(
            {"captures": results, "coverage": coverage},
            indent=2,
            sort_keys=True,
        )
    )
    return 0 if coverage["research_catalog_ready"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
