from __future__ import annotations

import hashlib
import json
from pathlib import Path

from browser_core.personas import (
    add_persona,
    build_persona,
    catalog_coverage_report,
    store_persona_evidence,
)


def _add(
    workspace: Path,
    persona_id: str,
    *,
    kind: str,
    source: str,
    tags: tuple[str, ...] = (),
) -> None:
    evidence = {"schema": "prov-fixture/1", "id": persona_id}
    digest = hashlib.sha256(
        json.dumps(evidence, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    persona = build_persona(
        persona_id=persona_id,
        name=persona_id,
        tags=tags,
        device={
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
            "screen": {"width": 1280, "height": 720},
        },
        kernel={
            "engine": "chromium",
            "product": "browser-core",
            "minimum_major": 153,
            "maximum_major": 153,
        },
        geography={
            "country": "US",
            "locale": "en-US",
            "languages": ["en-US"],
            "timezone": "America/Chicago",
        },
        identity_contract={
            "schema_version": 1,
            "expected": {
                "window.platform": "Win32",
                "window.hardwareConcurrency": 8,
                "window.locale": "en-US",
                "window.timezone": "America/Chicago",
            },
        },
        provenance={
            "kind": kind,
            "source": source,
            "source_sha256": digest,
            "captured_at": "2026-08-04T00:00:00Z",
        },
    )
    store_persona_evidence(workspace, evidence, expected_sha256=digest)
    add_persona(workspace, persona)


def test_provenance_grades_break_down_matrix_fixture_and_primary(tmp_path: Path) -> None:
    for index in range(3):
        _add(
            tmp_path,
            f"primary-{index:02d}",
            kind="owned-capture",
            source=f"profile:owned-{index}",
            tags=("owned",),
        )
    for index in range(5):
        _add(
            tmp_path,
            f"matrix-{index:02d}",
            kind="owned-capture",
            source=f"kernel-probe:playwright-chromium:{index}",
            tags=("matrix", "owned"),
        )
    _add(
        tmp_path,
        "fixture-00",
        kind="owned-capture",
        source="ops-fixture:ops-launch-00",
        tags=("ops", "fixture"),
    )
    report = catalog_coverage_report(tmp_path)
    grades = report["provenance_grades"]
    assert grades["schema"] == "browser-core.persona-provenance-grades/1"
    assert grades["owned_capture_primary"] == 3
    assert grades["lab_matrix_or_probe"] == 5
    assert grades["lab_fixture"] == 1
    assert grades["by_kind"]["owned-capture"] == 9
    assert grades["warn_overcount_risk"] is True
    assert "thresholds" in grades
    assert "high_provenance_ratio" in grades
