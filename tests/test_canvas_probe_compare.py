"""Synthetic, schema-valid saved query pages for the canvas region comparer."""
from __future__ import annotations

import copy
import json
from pathlib import Path

import jsonschema
import pytest

from browser_core.canvas_probe_compare import ComparisonError, _load_run, compare, main


ROOT = Path(__file__).resolve().parents[1]
API = "CanvasRenderingContext2D.getImageData"


def _event(event_id: int, x: int, y: int, rgba: tuple[int, int, int, int]) -> dict:
    return {
        "event_id": str(event_id), "timestamp_ns": str(100 + event_id),
        "process_id": "12", "thread_id": "13", "api": API,
        "context": {"id": "A" * 32, "kind": "window", "realm_id": "1"},
        "script_id": "2", "completion": "returned",
        "binding_realm": {"status": "not-recorded", "kind": "window",
                          "reason": "native-context-metadata-not-recorded"},
        "parameters": {"count": 4, "observed": [
            {"type": "number", "value": number} for number in (x, y, 1, 1)]},
        "result": {"type": "ImageData", "width": 1, "height": 1,
                   "data": {"type": "Uint8ClampedArray", "length": 4,
                            "values": [{"type": "number", "value": channel}
                                       for channel in rgba]}},
    }


def _page(events: list[dict], *, bundle_digest: str = "a" * 64) -> dict:
    build = {"provenance": "attested-browser-core", "executable_sha256_16": "c" * 16,
             "runtime_bundle_sha256_16": "d" * 16,
             "attestation_created_at": "2026-10-29T00:00:00Z"}
    health = {"status": "no-issues-reported", "capture_stats_seen": True,
              "counters_truncated": False, "sorter_dropped_events": "0",
              "proves_complete": False, "counters": []}
    page = {
        "schema": "browser-core.evidence-query/1", "status": "ok",
        "bundle": {"sha256": bundle_digest, "expected_digest_matched": True,
                   "authenticity": "unsigned-exporter-metadata"},
        "recording": {"sha256": "b" * 64, "bytes": "1024", "packets": "1",
                      "source_bytes": "1024", "excluded_tail_bytes": "0",
                      "source_phase": "finalized-recording"},
        "reader_runtime": {"mode": "producer-build", "producer_build": build,
                           "reader_build": build},
        "capture": {"schema": "browser-core.inspection/2",
                    "allowlist": "fingerprint-v2"},
        "query": {"filters": {"search": "", "script": "", "context": "",
                              "apis": [API]},
                  "query_sha256": "e" * 64, "requested_limit": 100,
                  "matching_events": str(len(events)), "snapshot_max_id": "100",
                  "ordering": "timestamp-descending-then-event-id-descending",
                  "page": "first", "returned_events": len(events),
                  "more_available": False, "next_cursor": None,
                  "output_limited": False},
        "recording_health": health, "exporter_reported_health": health,
        "events": events,
        "semantics": {"private_values_included": True,
                      "api_filter": "exact-native-name",
                      "pagination_snapshot": "verified-immutable-bundle",
                      "cursor_authenticated": False,
                      "cursor_authorizes_actions": False,
                      "event_ids_are_decoder_local": True,
                      "binding_realm_is_initiating_caller": False,
                      "script_source_recorded": False,
                      "document_url_is_fetch_provenance": False,
                      "proves_capture_complete": False,
                      "server_side_architecture_observed": False,
                      "browser_launched": False, "active_probe": False},
    }
    schema = json.loads((ROOT / "schemas" / "evidence-query-v1.schema.json").read_text())
    jsonschema.Draft202012Validator(schema).validate(page)
    return page


def _write(tmp_path: Path, name: str, page: dict) -> Path:
    path = tmp_path / name
    path.write_text(json.dumps(page), encoding="utf-8")
    return path


def test_coordinate_keyed_comparison_detects_one_pixel_change(tmp_path, capsys):
    # Two 1x1 probes from a 96x96-sized synthetic scene: the first region
    # differs, the other remains identical. A scene-level visual score would
    # dilute the first change to 1/9216 pixels.
    left = _page([_event(2, 45, 54, (20, 30, 40, 255)),
                  _event(1, 44, 40, (70, 80, 90, 255))])
    right = _page([_event(2, 45, 54, (21, 30, 40, 255)),
                   _event(1, 44, 40, (70, 80, 90, 255))],
                  bundle_digest="f" * 64)
    assert main(["--left", str(_write(tmp_path, "left.json", left)),
                 "--right", str(_write(tmp_path, "right.json", right))]) == 0
    report = json.loads(capsys.readouterr().out)
    assert [(row["rectangle"], row["status"]) for row in report["regions"]] == [
        ([44, 40, 1, 1], "same-value-multiset"),
        ([45, 54, 1, 1], "different-value-multiset"),
    ]
    assert '"values":' not in json.dumps(report)


def test_incomplete_pages_and_unavailable_values_never_compare_equal(tmp_path):
    left = _page([_event(1, 45, 54, (20, 30, 40, 255))])
    right = copy.deepcopy(left)
    right["events"][0]["result"]["data"] = {
        "type": "Uint8ClampedArray", "length": 4,
        "omitted": "buffer-not-readable-or-length-limit"}
    report = compare(_load_run([_write(tmp_path, "l.json", left)]),
                     _load_run([_write(tmp_path, "r.json", right)]))
    assert report["regions"][0]["status"] == "unknown-values"
    left["query"].update(more_available=True, next_cursor="cursor")
    with pytest.raises(ComparisonError, match="incomplete"):
        _load_run([_write(tmp_path, "partial.json", left)])


def test_missing_region_is_not_paired_by_ordinal(tmp_path):
    left = _page([_event(1, 45, 54, (20, 30, 40, 255))])
    right = _page([_event(1, 44, 40, (20, 30, 40, 255))])
    report = compare(_load_run([_write(tmp_path, "l.json", left)]),
                     _load_run([_write(tmp_path, "r.json", right)]))
    assert [item["status"] for item in report["regions"]] == [
        "missing-region", "missing-region"]


def test_complete_continuation_is_accepted_but_mixed_query_is_rejected(tmp_path):
    first = _page([_event(2, 45, 54, (20, 30, 40, 255))])
    second = _page([_event(1, 44, 40, (70, 80, 90, 255))])
    first["query"].update(matching_events="2", more_available=True,
                          next_cursor="synthetic-cursor")
    second["query"].update(matching_events="2", page="continuation")
    paths = [_write(tmp_path, "page1.json", first),
             _write(tmp_path, "page2.json", second)]
    assert len(_load_run(paths)["events"]) == 2
    second["query"]["filters"]["script"] = "3"
    _write(tmp_path, "page2.json", second)
    with pytest.raises(ComparisonError, match="one bound query"):
        _load_run(paths)
