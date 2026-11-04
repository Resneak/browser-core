"""Compare canvas readback regions in saved Browser Core evidence-query pages.

This consumes *already decoded* private-value query output. It never opens a
browser or a bundle, and its report deliberately contains no pixel values.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import hashlib
import json
import math
from pathlib import Path
import re
import sys

from .contracts import ContractError
from .control_files import decode_strict_json_bytes


SCHEMA = "browser-core.canvas-probe-compare/1"
QUERY_SCHEMA = "browser-core.evidence-query/1"
APIS = frozenset({
    "CanvasRenderingContext2D.getImageData",
    "OffscreenCanvasRenderingContext2D.getImageData",
})
MAX_PAGE_BYTES = 4 * 1024 * 1024 + 4096
MAX_PAGES = 64
_DIGEST = re.compile(r"[0-9a-f]{64}")


class ComparisonError(ValueError):
    """Saved query cannot support the requested comparison."""


def _number(item: object) -> int | float | None:
    if not isinstance(item, dict) or item.get("type") != "number":
        return None
    value = item.get("value")
    if type(value) not in (int, float) or not math.isfinite(value):
        return None
    return value


def _region(event: dict) -> tuple[str, int | float, int | float, int | float, int | float] | None:
    parameters = event.get("parameters")
    if not isinstance(parameters, dict):
        return None
    observed = parameters.get("observed")
    if not isinstance(observed, list) or len(observed) != 4:
        return None
    values = tuple(_number(item) for item in observed)
    if any(value is None for value in values):
        return None
    return (event["api"], *values)


def _pixel_digest(event: dict) -> str | None:
    if event.get("completion") != "returned":
        return None
    result = event.get("result")
    if not isinstance(result, dict) or result.get("type") != "ImageData":
        return None
    width, height = result.get("width"), result.get("height")
    if type(width) is not int or type(height) is not int or width < 1 or height < 1:
        raise ComparisonError("ImageData dimensions are invalid")
    data = result.get("data")
    if not isinstance(data, dict) or data.get("type") != "Uint8ClampedArray":
        return None  # Float32 and omitted pixels need their own comparison policy.
    length = width * height * 4
    if data.get("length") != length:
        raise ComparisonError("ImageData buffer length disagrees with dimensions")
    if "values" in data:
        values = data["values"]
        if not isinstance(values, list) or len(values) != length or length > 64:
            raise ComparisonError("ImageData copied values are invalid")
        pixels = []
        for item in values:
            value = _number(item)
            if value is None or int(value) != value or not 0 <= value <= 255:
                raise ComparisonError("ImageData byte is invalid")
            pixels.append(int(value))
        digest = hashlib.sha256(bytes(pixels)).hexdigest()
    elif "sha256" in data:
        digest = data["sha256"]
        if (not isinstance(digest, str) or _DIGEST.fullmatch(digest) is None
                or data.get("byte_length") != length or length <= 64):
            raise ComparisonError("ImageData digest is invalid")
    else:
        return None
    # A result shape change must not compare equal merely because the byte
    # digest coincides. Browser Core's digest is over the buffer, not dimensions.
    return f"{width}x{height}:{digest}"


def _read_page(path: Path) -> dict:
    with path.open("rb") as source:
        body = source.read(MAX_PAGE_BYTES + 1)
    if len(body) > MAX_PAGE_BYTES:
        raise ComparisonError("saved query page is too large")
    try:
        page = decode_strict_json_bytes(body, label="saved evidence query")
    except (ContractError, UnicodeError) as exc:
        raise ComparisonError("saved query page is not valid UTF-8 JSON") from exc
    if not isinstance(page, dict) or page.get("schema") != QUERY_SCHEMA or page.get("status") != "ok":
        raise ComparisonError("expected a successful Browser Core evidence-query page")
    semantics = page.get("semantics")
    if not isinstance(semantics, dict) or semantics.get("private_values_included") is not True:
        raise ComparisonError("query must include private values")
    if not isinstance(page.get("bundle"), dict):
        raise ComparisonError("saved bundle binding is required")
    query, events = page.get("query"), page.get("events")
    if not isinstance(query, dict) or not isinstance(events, list) or len(events) > 100:
        raise ComparisonError("query page shape is invalid")
    filters = query.get("filters")
    if (not isinstance(filters, dict) or not isinstance(filters.get("apis"), list)
            or not filters["apis"] or not set(filters["apis"]) <= APIS):
        raise ComparisonError("query must filter exact getImageData APIs")
    if page.get("capture") not in (
        {"schema": "browser-core.inspection/2", "allowlist": "fingerprint-v2"},
        {"schema": "browser-core.inspection/3", "allowlist": "research-v3"},
    ):
        raise ComparisonError("query capture lacks getImageData values")
    if query.get("returned_events") != len(events):
        raise ComparisonError("query page event count is invalid")
    for event in events:
        if (not isinstance(event, dict) or event.get("api") not in APIS
                or event["api"] not in filters["apis"]
                or "parameters" not in event or "result" not in event
                or not isinstance(event.get("event_id"), str)):
            raise ComparisonError("query contains an unsupported event")
    return page


def _load_run(paths: list[Path]) -> dict:
    if not 1 <= len(paths) <= MAX_PAGES:
        raise ComparisonError("supply 1 to 64 pages per run")
    pages = [_read_page(path) for path in paths]
    first = pages[0]
    binding = (first["bundle"].get("sha256"), first["query"].get("query_sha256"),
               first["query"].get("snapshot_max_id"),
               json.dumps(first["query"].get("filters"), sort_keys=True),
               first["capture"])
    if not isinstance(binding[0], str) or _DIGEST.fullmatch(binding[0]) is None:
        raise ComparisonError("bundle digest is invalid")
    if not isinstance(binding[1], str) or _DIGEST.fullmatch(binding[1]) is None:
        raise ComparisonError("query digest is invalid")
    if first["query"].get("page") != "first":
        raise ComparisonError("first query page is missing")
    expected = first["query"].get("matching_events")
    if (not isinstance(expected, str) or
            re.fullmatch(r"0|[1-9][0-9]{0,18}", expected) is None):
        raise ComparisonError("query population is invalid")
    event_ids = set()
    events = []
    for index, page in enumerate(pages):
        query = page["query"]
        current = (page["bundle"].get("sha256"), query.get("query_sha256"),
                   query.get("snapshot_max_id"),
                   json.dumps(query.get("filters"), sort_keys=True),
                   page["capture"])
        if current != binding or query.get("matching_events") != expected:
            raise ComparisonError("pages are not from one bound query")
        if query.get("page") != ("first" if index == 0 else "continuation"):
            raise ComparisonError("query page order is invalid")
        if index < len(pages) - 1 and (query.get("more_available") is not True
                                        or not query.get("next_cursor")):
            raise ComparisonError("query page continuation is missing")
        for event in page["events"]:
            event_id = event["event_id"]
            if event_id in event_ids:
                raise ComparisonError("duplicate event across query pages")
            event_ids.add(event_id)
            events.append(event)
    if pages[-1]["query"].get("more_available") is not False or len(events) != int(expected):
        raise ComparisonError("query pages are incomplete")
    recording = first.get("recording")
    health = first.get("recording_health")
    if not isinstance(recording, dict) or not isinstance(health, dict):
        raise ComparisonError("recording health metadata is invalid")
    return {"bundle_sha256": binding[0], "events": events,
            "source_phase": recording.get("source_phase"),
            "health_status": health.get("status"),
            "sorter_dropped_events": health.get("sorter_dropped_events")}


def _summarize(run: dict) -> dict:
    groups: dict[tuple, Counter] = defaultdict(Counter)
    unknown: Counter = Counter()
    unkeyed = 0
    for event in run["events"]:
        region = _region(event)
        if region is None:
            unkeyed += 1
            continue
        digest = _pixel_digest(event)
        if digest is None:
            unknown[region] += 1
        else:
            groups[region][digest] += 1
    return {"groups": groups, "unknown": unknown, "unkeyed": unkeyed}


def compare(left: dict, right: dict) -> dict:
    """Compare complete exported query populations by requested region.

    Repeated calls are compared as multisets; call order and canvas state are
    intentionally not inferred from equality of the multiset.
    """
    a, b = _summarize(left), _summarize(right)
    regions = []
    for key in sorted(set(a["groups"]) | set(b["groups"]) | set(a["unknown"]) | set(b["unknown"])):
        ac, bc = a["groups"].get(key, Counter()), b["groups"].get(key, Counter())
        au, bu = a["unknown"][key], b["unknown"][key]
        left_count, right_count = sum(ac.values()) + au, sum(bc.values()) + bu
        if left_count == 0 or right_count == 0:
            status = "missing-region"
        elif au or bu:
            status = "unknown-values"
        elif ac == bc:
            status = "same-value-multiset"
        else:
            status = "different-value-multiset"
        regions.append({"api": key[0], "rectangle": list(key[1:]),
                        "left_calls": left_count, "right_calls": right_count,
                        "left_unknown": au, "right_unknown": bu, "status": status})
    return {"schema": SCHEMA, "left_bundle_sha256": left["bundle_sha256"],
            "right_bundle_sha256": right["bundle_sha256"],
            "left_events": len(left["events"]), "right_events": len(right["events"]),
            "left_source_phase": left["source_phase"],
            "right_source_phase": right["source_phase"],
            "left_health_status": left["health_status"],
            "right_health_status": right["health_status"],
            "left_sorter_dropped_events": left["sorter_dropped_events"],
            "right_sorter_dropped_events": right["sorter_dropped_events"],
            "left_unkeyed": a["unkeyed"], "right_unkeyed": b["unkeyed"],
            "regions": regions,
            "limits": ["saved decoded Browser Core query pages only",
                       "8-bit RGBA bytes only; Float32 and omitted values are unknown",
                       "same-value-multiset does not establish call order, same canvas state, or source attribution",
                       "neither run proves complete capture or server acceptance"]}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--left", type=Path, action="append", required=True,
                        help="complete ordered evidence-query page(s) for first run")
    parser.add_argument("--right", type=Path, action="append", required=True,
                        help="complete ordered evidence-query page(s) for second run")
    args = parser.parse_args(argv)
    try:
        report = compare(_load_run(args.left), _load_run(args.right))
    except (ComparisonError, OSError) as exc:
        # Avoid echoing file paths or private query content in error output.
        parser.exit(2, f"canvas comparison unavailable: {type(exc).__name__}\n")
    print(json.dumps(report, indent=2, sort_keys=True, allow_nan=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
