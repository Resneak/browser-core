"""Durable gate for reverse-engineering preference evaluations.

Drives shipped package entry points used by evaluation sessions:
version pin, upstream pin, patch series integrity, and the hand-authored
trace fixture validator/summarizer. Does not invent live detector scores.
"""

from __future__ import annotations

import json
from pathlib import Path

from browser_core import __version__
from browser_core.trace import summarize, validate_trace
from browser_core.upstream import verify_patch_series, verify_upstream

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "fixtures" / "trace-v1.jsonl"
COMPARISON_DOCS = (
    ROOT / "docs" / "VALIDATION.md",
    ROOT / "docs" / "PLATFORM_ACCEPTANCE.md",
    ROOT / "docs" / "KAMELEO_COMPARISON.md",
    ROOT / "docs" / "ELITE_BROWSER_COMPARISON.md",
)


def test_shipped_version_is_semver_pinned() -> None:
    assert __version__ == "0.5.40"
    parts = __version__.split(".")
    assert len(parts) == 3
    assert all(part.isdigit() for part in parts)


def test_upstream_pin_is_chromium_153_with_bindings_tracing() -> None:
    report = verify_upstream(ROOT)
    assert report["schema"] == "browser-core.upstream/1"
    assert report["chromium"]["version"].startswith("153.")
    assert report["chromium"]["revision"] == (
        "bf6d8a66b43635a532bdad773407285fac0121e9"
    )
    assert "enable_blink_bindings_tracing=true" in report["build"]["gn_args"]


def test_patch_series_is_ordered_and_hash_verified() -> None:
    report = verify_patch_series(ROOT)
    assert report["patches"] == 53
    assert report["postimages"] == 62
    assert report["revision"] == "bf6d8a66b43635a532bdad773407285fac0121e9"
    assert len(report["patch_series_sha256"]) == 64
    # Stable series digest from VALIDATION.md / series packaging. It moves only
    # when the series itself does; native-route schema v8 declares identity, channel,
    # occurrence count, patch ownership, and exact Chromium/V8 source targets.
    assert report["patch_series_sha256"] == (
        "c45a098cb4f1f3288210b5a9a56493077b4216eae44f49721cd75a80ab53fc93"
    )


def test_trace_fixture_validates_via_shipped_api() -> None:
    result = validate_trace(FIXTURE)
    assert result["run_id"] == "fixture-run"
    assert result["events"] == 5
    assert result["dropped_events"] == 0

    summary = summarize(FIXTURE)
    assert summary["events"] == 5
    assert summary["dropped_events"] == 0
    assert summary["execution_contexts"] == 2
    # Causal RE surface: fixture covers the core event families.
    assert set(summary["categories"]) >= {
        "api",
        "crypto",
        "execution",
        "message",
        "network",
    }


def test_comparison_ledgers_exist_and_name_peer_set() -> None:
    for path in COMPARISON_DOCS:
        assert path.is_file(), path
        text = path.read_text(encoding="utf-8")
        assert len(text) > 500

    elite = (ROOT / "docs" / "ELITE_BROWSER_COMPARISON.md").read_text(
        encoding="utf-8"
    )
    for peer in ("Kameleo", "Patchright", "Camoufox", "Octo Browser", "Multilogin"):
        assert peer in elite

    kameleo = (ROOT / "docs" / "KAMELEO_COMPARISON.md").read_text(encoding="utf-8")
    assert "prefer Browser Core" in kameleo or "prefer Browser Core" in elite


def test_session_and_trace_schemas_are_versioned_contracts() -> None:
    session = json.loads(
        (ROOT / "schemas" / "session-v1.schema.json").read_text(encoding="utf-8")
    )
    trace = json.loads(
        (ROOT / "schemas" / "trace-event-v1.schema.json").read_text(encoding="utf-8")
    )
    assert "browser-core.session" in json.dumps(session)
    assert "browser-core.trace-event" in json.dumps(trace)
    assert trace["properties"]["request"]["properties"]["body_bytes"] == {
        "type": "integer",
        "minimum": 0,
        "maximum": 9_007_199_254_740_991,
    }
