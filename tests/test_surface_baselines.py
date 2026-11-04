"""The four frozen vendor baselines, and what they are for.

Each is built from repeated arms of one saved script under the offline rehost, so
it carries a stable core, a volatile set, and the noise floor that vendor actually
produced. Committing them makes a later roll or rebuild checkable: run the arm,
subtract the control, and `observe check` against the frozen surface.

These tests do not need a browser. They assert the fixtures are well formed and
that the numbers in them still say what the docs say they say -- which is the part
that rots.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from browser_core.product_observation import BASELINE_SCHEMA, check_surface_drift

BASELINES = Path(__file__).resolve().parents[1] / "fixtures" / "surface-baselines"

# Exact retained repeat evidence measured 2026-08-08 on one host, offline
# rehost, control-subtracted. Keep pairwise drift and union size independent of
# the fixture under test; count-only assertions allowed both to change silently.
EXPECTED = {
    "akamai-bm-web": {
        "arms": 3,
        "core": 121,
        "volatile": 0,
        "floor": 0,
        "pairwise": (0, 0, 0),
        "union": 121,
    },
    "kasada-driven": {
        "arms": 2,
        "core": 29,
        "volatile": 0,
        "floor": 0,
        "pairwise": (0,),
        "union": 29,
    },
    "shape-nordstrom": {
        "arms": 3,
        "core": 1036,
        "volatile": 15,
        "floor": 11,
        "pairwise": (10, 11, 9),
        "union": 1051,
    },
    "perimeterx": {
        "arms": 3,
        "core": 66,
        "volatile": 0,
        "floor": 0,
        "pairwise": (0, 0, 0),
        "union": 66,
    },
}

EXPECTED_WINDOW_INTERFACE_COUNTS = {
    "akamai-bm-web": (19, 16),
    "kasada-driven": (4, 14),
    "shape-nordstrom": (911, 88),
    "perimeterx": (9, 14),
}


@pytest.mark.parametrize("label", sorted(EXPECTED))
def test_each_frozen_baseline_still_says_what_it_said(label: str) -> None:
    doc = json.loads((BASELINES / f"{label}.json").read_text(encoding="utf-8"))
    expected = EXPECTED[label]
    assert doc["schema"] == BASELINE_SCHEMA
    assert doc["arms"] == expected["arms"]
    assert doc["api_name_count"] == expected["core"]
    assert len(doc["api_names"]) == expected["core"]
    assert len(doc["volatile_api_names"]) == expected["volatile"]
    assert doc["measured_noise_floor"] == expected["floor"]
    assert tuple(doc["pairwise_differences"]) == expected["pairwise"]
    # A volatile name is by definition not in the stable core.
    assert not set(doc["volatile_api_names"]) & set(doc["api_names"])
    assert len(set(doc["api_names"]) | set(doc["volatile_api_names"])) == expected[
        "union"
    ]


def test_shape_retraction_witness_is_in_the_retained_volatile_set() -> None:
    doc = json.loads(
        (BASELINES / "shape-nordstrom.json").read_text(encoding="utf-8")
    )

    assert "api.HTMLAudioElement.Audio" in doc["volatile_api_names"]


@pytest.mark.parametrize("label", sorted(EXPECTED_WINDOW_INTERFACE_COUNTS))
def test_exact_window_interface_technique_counts_are_locked(label: str) -> None:
    doc = json.loads((BASELINES / f"{label}.json").read_text(encoding="utf-8"))
    expected_count, expected_rounded_share = EXPECTED_WINDOW_INTERFACE_COUNTS[label]
    count = sum(
        re.fullmatch(r"api\.Window\.[^.]+", name) is not None
        for name in doc["api_names"]
    )

    assert count == expected_count
    assert round(100 * count / len(doc["api_names"])) == expected_rounded_share


def test_three_of_four_vendors_are_deterministic_and_one_is_not() -> None:
    """The fact that made the drift gate's default wrong.

    Akamai, Kasada and PerimeterX all drift 0 across repeats. Shape drifts 9-11.
    A hand-set tolerance cannot be right for both groups, which is why the
    baseline carries the number instead.
    """
    floors = {}
    for label in EXPECTED:
        doc = json.loads((BASELINES / f"{label}.json").read_text(encoding="utf-8"))
        floors[label] = doc["measured_noise_floor"]
    assert sorted(v for v in floors.values() if v == 0) == [0, 0, 0]
    assert floors["shape-nordstrom"] > 0


def test_a_frozen_baseline_can_gate_a_later_run() -> None:
    """What these are for: an arm that matches the core passes, one that does not
    fails, and the measured floor decides how much slack there is."""
    doc = json.loads((BASELINES / "perimeterx.json").read_text(encoding="utf-8"))
    same = {
        "schema": "browser-core.product-script-subtraction/1",
        "only_in_arm": doc["api_names"],
        "clean_subtraction": True,
        "arm_label": "later-run",
        "arm_script_sha256_16": doc["script_sha256_16"],
    }
    assert check_surface_drift(same, doc, tolerance=None)["passed"] is True

    changed = dict(same, only_in_arm=doc["api_names"][:-3])
    verdict = check_surface_drift(changed, doc, tolerance=None)
    assert verdict["passed"] is False
    assert verdict["drift"] == 3
    assert verdict["tolerance"] == 0  # this vendor's own floor


def test_shapes_floor_gives_it_slack_the_others_do_not_get() -> None:
    doc = json.loads((BASELINES / "shape-nordstrom.json").read_text(encoding="utf-8"))
    drifted = {
        "schema": "browser-core.product-script-subtraction/1",
        "only_in_arm": doc["api_names"][:-8],
        "clean_subtraction": True,
        "arm_label": "later-run",
        "arm_script_sha256_16": doc["script_sha256_16"],
    }
    verdict = check_surface_drift(drifted, doc, tolerance=None)
    assert verdict["drift"] == 8
    assert verdict["tolerance"] == 11
    assert verdict["passed"] is True
    # Tolerated is not hidden.
    assert len(verdict["removed"]) == 8


def test_a_dirty_subtraction_cannot_pass_any_floor() -> None:
    doc = json.loads((BASELINES / "shape-nordstrom.json").read_text(encoding="utf-8"))
    dirty = {
        "schema": "browser-core.product-script-subtraction/1",
        "only_in_arm": doc["api_names"],
        "clean_subtraction": False,
        "arm_label": "later-run",
        "arm_script_sha256_16": doc["script_sha256_16"],
    }
    assert check_surface_drift(dirty, doc, tolerance=None)["passed"] is False
