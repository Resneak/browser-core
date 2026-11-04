"""Tests for the technique-level observation digest.

The properties worth defending here are honesty properties, not formatting ones:
a raw surface must never be presentable as attributed, a technique with no calls
must be reported rather than omitted, and the output must stay bounded no matter
how large the input surface is.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

import browser_core.script_provenance as script_provenance
from browser_core.observation_digest import (
    DIFF_SCHEMA,
    DIGEST_SCHEMA,
    GLOBAL_FUNCTIONS,
    TECHNIQUES,
    audit_batch,
    diff_digests,
    digest_observation,
    interface_of,
    render_batch_audit,
    render_digest,
    technique_of,
)
from browser_core.product_observation import (
    OBSERVATION_SCHEMA,
    SUBTRACTION_SCHEMA,
    ContractError,
    _sanitize_startup_document,
)


def _observation(names: dict[str, int], *, label: str = "arm") -> dict:
    return {
        "schema": OBSERVATION_SCHEMA,
        "label": label,
        "script_sha256_16": "0123456789abcdef",
        "analysis": {
            "events_by_name": dict(names),
            "context_coverage": {k: ["main"] for k in names},
        },
    }


def _subtraction(
    names: dict[str, int], *, label: str = "arm", clean: bool = True
) -> dict:
    return {
        "schema": SUBTRACTION_SCHEMA,
        "generated_at": "2026-08-12T01:02:03Z",
        "non_claims": [
            "control subtraction attributes API names in a lab rehost only",
            "not an acceptance, bypass, evasion, or bot-score claim",
        ],
        "arm_label": label,
        "arm_script_sha256_16": "fedcba9876543210",
        "clean_subtraction": clean,
        "script_identity_coherent": True,
        "only_in_arm": dict(names),
    }


def _set_compact_identity(
    document: dict, vendor_hint: str, *, looks_built: bool = True
) -> None:
    document["script_identity"] = {
        "schema": "browser-core.product-script-identity/1",
        "sha256_16": document["arm_script_sha256_16"],
        "bytes": 1024,
        "looks_like_built_antibot_script": looks_built,
        "vendor_hint": vendor_hint,
    }


# --------------------------------------------------------------------------
# taxonomy integrity
# --------------------------------------------------------------------------


def test_taxonomy_has_no_duplicate_interface_across_techniques():
    seen: dict[str, str] = {}
    for technique, interfaces in TECHNIQUES.items():
        for iface in interfaces:
            assert (
                iface not in seen
            ), f"{iface} claimed by {seen.get(iface)} and {technique}"
            seen[iface] = technique


def test_every_technique_is_a_nonempty_tuple():
    for technique, interfaces in TECHNIQUES.items():
        assert isinstance(interfaces, tuple), technique
        assert interfaces, technique


def test_global_functions_map_to_real_techniques():
    for name, technique in GLOBAL_FUNCTIONS.items():
        assert technique in TECHNIQUES, f"{name} -> unknown technique {technique}"


# --------------------------------------------------------------------------
# name parsing
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "name,expected",
    [
        ("api.AnalyserNode.fftSize.get", "AnalyserNode"),
        ("api.Navigator.userAgent.get", "Navigator"),
        ("api.Mojo.bindInterface", "Mojo"),
        ("api.fetch", None),  # bare global, no owning interface
        ("blink.canvas", None),
        ("api.", None),
    ],
)
def test_interface_of_shapes(name, expected):
    assert interface_of(name) == expected


def test_bare_global_resolves_through_global_table():
    # `api.fetch` has no owning interface, so it can only be classified via the
    # explicit global table. It is the highest-traffic transport name in the
    # corpus; leaving it unclassified would hide it from exactly the technique
    # bucket a transport question looks at first.
    assert interface_of("api.fetch") is None
    assert technique_of("api.fetch") == "network-transport"


def test_unknown_interface_is_unclassified_not_guessed():
    assert technique_of("api.TotallyNovelInterface.thing") == "unclassified"


def test_unknown_bare_global_is_unclassified():
    assert technique_of("api.somethingNew") == "unclassified"


@pytest.mark.parametrize("api_name", [None, True, 1, 1.5, [], ["api.fetch"], {}, ()])
def test_taxonomy_helpers_handle_non_text_names_without_raw_exceptions(api_name):
    assert interface_of(api_name) is None
    assert technique_of(api_name) == "unclassified"


@pytest.mark.parametrize("technique", [True, 1, 1.5, [], ["audio-graph"], {}, ()])
def test_corpus_matrix_rejects_non_text_technique_filters_cleanly(technique):
    from browser_core.observation_digest import corpus_matrix

    with pytest.raises(ContractError, match="unknown technique"):
        corpus_matrix([], technique=technique)


def test_substring_collision_does_not_leak_into_a_technique():
    # `AudioBufferThing` is not `AudioBuffer`; membership is by exact name.
    assert technique_of("api.AudioBufferThing.x") == "unclassified"


# --------------------------------------------------------------------------
# digest: attribution honesty
# --------------------------------------------------------------------------


def test_raw_observation_carries_an_attribution_warning():
    digest = digest_observation(_observation({"api.Navigator.userAgent.get": 3}))
    assert digest["attributed"] is False
    assert "attribution_warning" in digest
    assert "subtract" in digest["attribution_warning"]


def test_render_digest_rejects_saved_raw_attribution_contradictions():
    raw = digest_observation(_observation({"api.Navigator.userAgent.get": 3}))
    raw["attributed"] = True
    with pytest.raises(ContractError, match="rendered digest"):
        render_digest(raw)

    raw = digest_observation(_observation({"api.Navigator.userAgent.get": 3}))
    raw.pop("attribution_warning")
    with pytest.raises(ContractError, match="rendered digest"):
        render_digest(raw)


def test_render_digest_rejects_saved_claim_ready_without_clean_subtraction():
    digest = digest_observation(_subtraction({"api.Navigator.a": 1}))
    digest["clean_subtraction"] = False
    digest["surface_claim_ready"] = True
    with pytest.raises(ContractError, match="rendered digest"):
        render_digest(digest)


def test_render_digest_rejects_hidden_or_forged_empty_surface_warning():
    empty = digest_observation(_subtraction({}))
    empty.pop("empty_surface_warning")
    with pytest.raises(ContractError, match="rendered digest"):
        render_digest(empty)

    populated = digest_observation(_subtraction({"api.Navigator.a": 1}))
    populated["empty_surface_warning"] = "private operator text"
    with pytest.raises(ContractError, match="rendered digest"):
        render_digest(populated)


@pytest.mark.parametrize(
    "field,value",
    [
        ("total_api_names", 0),
        ("total_calls", 1),
        ("techniques_observed", 0),
        ("amplified_api_names", 1),
        ("not_observed", []),
    ],
)
def test_render_digest_rejects_saved_totals_that_disagree_with_rows(field, value):
    digest = digest_observation(_subtraction({"api.Navigator.a": 2}))
    digest[field] = value
    with pytest.raises(ContractError, match="rendered digest"):
        render_digest(digest)


@pytest.mark.parametrize(
    "field,value",
    [
        ("api_names", 2),
        ("calls", 1),
        ("amplified", -1),
        ("interfaces_total", 0),
    ],
)
def test_render_digest_rejects_saved_technique_rows_with_impossible_counts(
    field, value
):
    digest = digest_observation(_subtraction({"api.Navigator.a": 2}))
    digest["techniques"]["navigator-identity"][field] = value
    with pytest.raises(ContractError, match="rendered digest"):
        render_digest(digest)


@pytest.mark.parametrize(
    "field,value",
    [
        ("label", "arm\nFORGED VERIFIED"),
        ("script_sha256_16", "private operator route"),
    ],
)
def test_render_digest_rejects_saved_identity_text_outside_producer_contract(
    field, value
):
    digest = digest_observation(_subtraction({"api.Navigator.a": 1}))
    digest[field] = value
    with pytest.raises(ContractError, match="rendered digest"):
        render_digest(digest)


def test_render_digest_rejects_saved_focus_that_disagrees_with_technique():
    digest = digest_observation(
        _subtraction({"api.Navigator.a": 1}), focus="navigator-identity"
    )
    digest["focus"]["api_names"] = ["api.Navigator.a", "api.Screen.private"]
    digest["focus"]["count"] = 2
    with pytest.raises(ContractError, match="rendered digest"):
        render_digest(digest)


def test_render_digest_rechecks_saved_provenance_before_display():
    doc = _observation({"api.Navigator.a": 1})
    doc["provenance"] = {
        "status": "VERIFIED",
        "recorded_hosts": ["example.test"],
    }
    doc["source_provenance"] = {
        "status": "verified_digest",
        "source_url": "https://example.test/public.js",
        "sha256": "a" * 64,
        "retrieved_at": "2026-10-25T00:00:00Z",
    }
    digest = digest_observation(doc)
    digest["provenance"]["recorded_hosts"] = ["example.test/private?token=secret"]
    with pytest.raises(ContractError, match="rendered digest"):
        render_digest(digest)

    digest = digest_observation(doc)
    digest["source_provenance"]["source_url_shape"]["origin"] = (
        "https://example.test/private?token=secret"
    )
    with pytest.raises(ContractError, match="rendered digest"):
        render_digest(digest)


def test_render_digest_rechecks_saved_input_delivery_claims_and_note():
    doc = _subtraction({"api.Navigator.a": 1})
    doc["arm_input_profile"] = "probe"
    digest = digest_observation(doc)
    assert digest["input_delivery"]["verified"] is False
    digest["input_delivery"]["verified"] = True
    with pytest.raises(ContractError, match="rendered digest"):
        render_digest(digest)

    digest = digest_observation(doc)
    digest["input_delivery"]["note"] = "private operator path"
    with pytest.raises(ContractError, match="rendered digest"):
        render_digest(digest)


@pytest.mark.parametrize("document", [None, True, 1, 1.5, "observation", [], [1], ()])
def test_digest_rejects_non_object_documents_cleanly(document) -> None:
    with pytest.raises(ContractError, match="input must be an object"):
        digest_observation(document)


@pytest.mark.parametrize("document", [None, True, 1, 1.5, "document", [], [1], ()])
def test_digest_diff_rejects_non_object_documents_cleanly(document) -> None:
    valid = _subtraction({"api.Navigator.userAgent.get": 1})
    with pytest.raises(ContractError, match="inputs must be objects"):
        diff_digests(document, valid)
    with pytest.raises(ContractError, match="inputs must be objects"):
        diff_digests(valid, document)


@pytest.mark.parametrize("digest", [None, True, 1, 1.5, "digest", [], [1], ()])
def test_render_digest_rejects_non_object_documents_cleanly(digest) -> None:
    with pytest.raises(ContractError, match="input must be an object"):
        render_digest(digest)


@pytest.mark.parametrize("document", [None, True, 1, 1.5, "render", [], [1], ()])
def test_other_digest_renderers_reject_non_object_documents_cleanly(document) -> None:
    from browser_core.observation_digest import (
        render_batch_audit,
        render_claim,
        render_corpus,
    )

    for renderer in (render_claim, render_corpus, render_batch_audit):
        with pytest.raises(ContractError, match="input must be an object"):
            renderer(document)


def test_renderers_normalize_forged_schema_shaped_objects_without_echoing_values() -> (
    None
):
    from browser_core.observation_digest import (
        BATCH_AUDIT_SCHEMA,
        CLAIM_SCHEMA,
        CORPUS_SCHEMA,
        render_batch_audit,
        render_claim,
        render_corpus,
    )

    marker = "PRIVATE_RENDER_MARKER"
    cases = (
        (render_digest, DIGEST_SCHEMA, "rendered digest structure is invalid"),
        (render_claim, CLAIM_SCHEMA, "rendered claim structure is invalid"),
        (render_corpus, CORPUS_SCHEMA, "rendered corpus structure is invalid"),
        (
            render_batch_audit,
            BATCH_AUDIT_SCHEMA,
            "rendered batch audit structure is invalid",
        ),
    )
    for renderer, schema, expected in cases:
        with pytest.raises(ContractError) as failure:
            renderer({"schema": schema, "private": marker})
        assert str(failure.value) == expected
        assert marker not in str(failure.value)


def test_renderers_reject_foreign_schemas_without_echoing_them() -> None:
    from browser_core.observation_digest import (
        render_batch_audit,
        render_claim,
        render_corpus,
    )

    marker = "PRIVATE_SCHEMA_MARKER"
    for renderer in (render_digest, render_claim, render_corpus, render_batch_audit):
        with pytest.raises(ContractError) as failure:
            renderer({"schema": marker})
        assert marker not in str(failure.value)


def test_attributed_subtraction_has_no_attribution_warning():
    digest = digest_observation(_subtraction({"api.Navigator.userAgent.get": 3}))
    assert digest["attributed"] is True
    assert "attribution_warning" not in digest
    assert digest["clean_subtraction"] is True


def test_digest_projects_current_script_attribution_and_open_execution() -> None:
    document = _subtraction({"api.Navigator.userAgent.get": 1})
    document["script_attribution_comparable"] = True
    document["arm_script_execution"] = {
        "total": 2,
        "complete": 1,
        "open": 1,
        "max_complete_duration_ns": 123_000,
    }
    document["control_script_execution"] = {
        "total": 1,
        "complete": 1,
        "open": 0,
        "max_complete_duration_ns": 100_000,
    }
    document["collector_startup"] = {
        "started": None,
        "reasons": ["value-free diagnostic"],
        "renderer_blocked": True,
        "browser_target_status": "present",
        "browser_target_title_matches": True,
    }

    digest = digest_observation(document)
    assert digest["script_attribution_comparable"] is True
    assert "current-script count deltas" in digest["attribution_caveat"]
    assert digest["script_execution"]["open"] == 1
    assert digest["control_script_execution"]["open"] == 0
    assert digest["collector_startup"]["browser_target_status"] == "present"
    rendered = render_digest(digest)
    assert "SCRIPT ACTIVE" in rendered
    assert "arm 1 open, control 0 open" in rendered
    assert "renderer target    present, fixed title matched" in rendered
    assert "positive current-script count deltas" in rendered


def test_digest_render_does_not_hide_an_open_control_execution() -> None:
    document = _subtraction({"api.Navigator.userAgent.get": 1})
    document["arm_script_execution"] = {
        "total": 1,
        "complete": 1,
        "open": 0,
        "max_complete_duration_ns": 123_000,
    }
    document["control_script_execution"] = {
        "total": 2,
        "complete": 1,
        "open": 1,
        "max_complete_duration_ns": 100_000,
    }

    rendered = render_digest(digest_observation(document))
    assert "SCRIPT ACTIVE" in rendered
    assert "arm 0 open, control 1 open" in rendered


def test_render_digest_rechecks_saved_script_execution_and_target_status():
    doc = _subtraction({"api.Navigator.a": 1})
    doc["arm_script_execution"] = {
        "total": 1,
        "complete": 0,
        "open": 1,
        "max_complete_duration_ns": None,
    }
    doc["collector_startup"] = {"browser_target_status": "present"}
    digest = digest_observation(doc)
    digest["script_execution"]["open"] = 0
    with pytest.raises(ContractError, match="rendered digest"):
        render_digest(digest)

    digest = digest_observation(doc)
    digest["collector_startup"]["browser_target_status"] = "private route"
    with pytest.raises(ContractError, match="rendered digest"):
        render_digest(digest)


def test_digest_rejects_malformed_script_execution_projection() -> None:
    document = _subtraction({"api.Navigator.userAgent.get": 1})
    document["arm_script_execution"] = {
        "total": 1,
        "complete": 1,
        "open": 1,
        "max_complete_duration_ns": 1,
    }
    with pytest.raises(ContractError, match="script execution counts"):
        digest_observation(document)


def test_raw_surface_flags_known_mojo_control_noise():
    """Mojo is renderer-internal IPC present identically in the empty control.

    Measured 2026-08-06: it survives control subtraction in 0 of 35 subtraction
    artifacts. A raw digest that showed it without comment would support the
    false claim that the collector probes Mojo.
    """
    digest = digest_observation(
        _observation({"api.Mojo.bindInterface": 12, "api.MojoHandle.watch": 39})
    )
    assert digest["known_control_noise"]["chromium-internal"] == 2
    assert "control" in digest["known_control_noise"]["note"]


def test_attributed_surface_does_not_claim_control_noise():
    digest = digest_observation(_subtraction({"api.Navigator.userAgent.get": 1}))
    assert "known_control_noise" not in digest


def test_render_digest_rechecks_saved_noise_count():
    digest = digest_observation(_observation({"api.Mojo.bindInterface": 1}))
    digest["known_control_noise"]["chromium-internal"] = 0
    with pytest.raises(ContractError, match="rendered digest"):
        render_digest(digest)


def test_dirty_subtraction_is_surfaced_in_text():
    digest = digest_observation(
        _subtraction({"api.Navigator.userAgent.get": 1}, clean=False)
    )
    assert digest["clean_subtraction"] is False
    assert "untrustworthy" in render_digest(digest)


# --------------------------------------------------------------------------
# digest: content
# --------------------------------------------------------------------------


def test_technique_rollup_counts_names_and_calls():
    digest = digest_observation(
        _subtraction(
            {
                "api.AnalyserNode.fftSize.get": 2,
                "api.AnalyserNode.fftSize.set": 3,
                "api.GainNode.constructor": 1,
                "api.Navigator.userAgent.get": 7,
            }
        )
    )
    audio = digest["techniques"]["audio-graph"]
    assert audio["api_names"] == 3
    assert audio["calls"] == 6
    assert audio["interfaces_total"] == 2
    assert digest["total_api_names"] == 4
    assert digest["total_calls"] == 13


def test_not_observed_lists_every_unseen_technique():
    digest = digest_observation(_subtraction({"api.Navigator.userAgent.get": 1}))
    assert "audio-graph" in digest["not_observed"]
    assert "navigator-identity" not in digest["not_observed"]
    # every technique is accounted for exactly once
    assert set(digest["techniques"]) | set(digest["not_observed"]) >= set(TECHNIQUES)


def test_non_api_events_are_excluded():
    digest = digest_observation(
        _observation({"api.Navigator.userAgent.get": 1, "blink.canvas": 99})
    )
    assert digest["total_api_names"] == 1
    assert digest["total_calls"] == 1


def test_techniques_are_ordered_by_descending_name_count():
    digest = digest_observation(
        _subtraction(
            {
                "api.Navigator.userAgent.get": 1,
                "api.AnalyserNode.a": 1,
                "api.AnalyserNode.b": 1,
                "api.AnalyserNode.c": 1,
            }
        )
    )
    assert list(digest["techniques"])[0] == "audio-graph"


# --------------------------------------------------------------------------
# digest: focus
# --------------------------------------------------------------------------


def test_focus_lists_full_name_set_for_one_technique():
    digest = digest_observation(
        _subtraction(
            {
                "api.AnalyserNode.fftSize.get": 1,
                "api.GainNode.constructor": 1,
                "api.Navigator.userAgent.get": 1,
            }
        ),
        focus="audio-graph",
    )
    assert digest["focus"]["count"] == 2
    assert digest["focus"]["api_names"] == [
        "api.AnalyserNode.fftSize.get",
        "api.GainNode.constructor",
    ]


def test_unknown_focus_is_rejected_with_the_valid_set():
    with pytest.raises(ContractError) as excinfo:
        digest_observation(
            _subtraction({"api.Navigator.x": 1}), focus="not-a-technique"
        )
    assert "audio-graph" in str(excinfo.value)


def test_unclassified_is_a_valid_focus():
    digest = digest_observation(
        _subtraction({"api.NovelThing.x": 1}), focus="unclassified"
    )
    assert digest["focus"]["count"] == 1


# --------------------------------------------------------------------------
# digest: contract errors
# --------------------------------------------------------------------------


def test_rejects_a_document_of_the_wrong_schema():
    with pytest.raises(ContractError):
        digest_observation({"schema": "something/1"})


def test_failed_launch_raises_rather_than_reporting_an_empty_surface():
    """An unreadable document and an empty surface must not look alike."""
    with pytest.raises(ContractError) as excinfo:
        digest_observation({"schema": OBSERVATION_SCHEMA, "label": "x"})
    assert "launch failed" in str(excinfo.value)


def test_digest_rejects_non_boolean_subtraction_cleanliness():
    doc = _subtraction({"api.Navigator.a": 1})
    doc["clean_subtraction"] = "false"
    with pytest.raises(ContractError, match="must be a boolean"):
        digest_observation(doc)


@pytest.mark.parametrize("examples", [True, -1, 129, 1.5, "6"])
def test_digest_rejects_unbounded_or_coercive_example_limits(examples):
    with pytest.raises(ContractError, match="examples"):
        digest_observation(_subtraction({"api.Navigator.a": 1}), examples=examples)


def test_digest_rejects_non_text_focus_without_a_runtime_type_error():
    with pytest.raises(ContractError, match="unknown technique"):
        digest_observation(_subtraction({"api.Navigator.a": 1}), focus={})


def test_diff_rejects_non_text_focus_without_a_runtime_type_error():
    doc = _subtraction({"api.Navigator.a": 1})
    with pytest.raises(ContractError, match="unknown technique"):
        diff_digests(doc, doc, focus={})


@pytest.mark.parametrize(
    "field,value", [("arm_label", {}), ("arm_label", "x\nprivate")]
)
def test_digest_rejects_invalid_report_labels(field, value):
    doc = _subtraction({"api.Navigator.a": 1})
    doc[field] = value
    with pytest.raises(ContractError, match="arm_label"):
        digest_observation(doc)


@pytest.mark.parametrize("pin", [True, 123, "A" * 16, "a" * 15, "not-a-script-pin"])
def test_digest_rejects_noncanonical_script_pins(pin):
    doc = _subtraction({"api.Navigator.a": 1})
    doc["arm_script_sha256_16"] = pin
    with pytest.raises(ContractError, match="script_sha256_16"):
        digest_observation(doc)


def test_subtraction_identity_uses_only_schema_specific_fields():
    doc = _subtraction({"api.Navigator.a": 1}, label="bound-arm")
    doc["label"] = {"private": "shadow"}
    doc["script_sha256_16"] = "not-a-shadow-pin"
    digest = digest_observation(doc)
    assert digest["label"] == "bound-arm"
    assert digest["script_sha256_16"] == "fedcba9876543210"


@pytest.mark.parametrize("bad_count", [True, False, 1.5, "1", 0, -1, 1_000_000_001])
def test_digest_rejects_coercive_or_out_of_range_event_counts(bad_count):
    doc = _observation({"api.Navigator.userAgent.get": bad_count})
    with pytest.raises(ContractError, match="event counts"):
        digest_observation(doc)


@pytest.mark.parametrize(
    "bad_name",
    ["", "api.Navigator.x\nsecret", "api." + "x" * 1025, "api.\ud800"],
)
def test_digest_rejects_invalid_event_names(bad_name):
    doc = _observation({bad_name: 1})
    with pytest.raises(ContractError, match="invalid event name"):
        digest_observation(doc)


@pytest.mark.parametrize("bad_surface", [[], "private", 1, None])
def test_digest_rejects_non_map_event_surfaces(bad_surface):
    doc = _observation({"api.Navigator.a": 1})
    doc["analysis"]["events_by_name"] = bad_surface
    with pytest.raises(ContractError, match="count map"):
        digest_observation(doc)


def test_digest_rejects_missing_event_surface_in_success_shaped_analysis():
    doc = _observation({"api.Navigator.a": 1})
    del doc["analysis"]["events_by_name"]
    with pytest.raises(ContractError, match="missing events_by_name"):
        digest_observation(doc)


@pytest.mark.parametrize(
    "bad_row",
    [
        {"arm": True, "control": 1},
        {"arm": "5", "control": 2},
        {"arm": 5},
        {"arm": 5, "control": 2, "private": "secret"},
        {"arm": 4, "control": 2},
        "private",
    ],
)
def test_digest_rejects_malformed_or_non_amplified_elevated_rows(bad_row):
    doc = _subtraction({"api.Navigator.a": 1})
    doc["elevated_in_arm"] = {"api.Performance.now": bad_row}
    with pytest.raises(ContractError, match="elevated_in_arm"):
        digest_observation(doc)


# --------------------------------------------------------------------------
# diff
# --------------------------------------------------------------------------


def test_diff_set_arithmetic_and_jaccard():
    left = _subtraction({"api.Navigator.a": 1, "api.AnalyserNode.b": 1}, label="L")
    right = _subtraction({"api.Navigator.a": 1, "api.GainNode.c": 1}, label="R")
    diff = diff_digests(left, right)
    assert diff["left_api_names"] == 2
    assert diff["right_api_names"] == 2
    assert diff["shared"] == 1
    assert diff["only_left"] == 1
    assert diff["only_right"] == 1
    assert diff["jaccard"] == pytest.approx(1 / 3, abs=1e-4)
    assert diff["identical_surface"] is False


def test_diff_reports_identical_surfaces_explicitly():
    doc = _subtraction({"api.Navigator.a": 1})
    diff = diff_digests(doc, doc)
    assert diff["identical_surface"] is True
    assert diff["jaccard"] == 1.0
    assert "identical" in render_digest(diff)


def test_render_diff_rejects_saved_identical_flag_against_counts():
    left = _subtraction({"api.Navigator.a": 1})
    right = _subtraction({"api.Screen.b": 1})
    diff = diff_digests(left, right)
    diff["identical_surface"] = True
    with pytest.raises(ContractError, match="rendered digest"):
        render_digest(diff)


def test_diff_only_lists_techniques_that_actually_differ():
    left = _subtraction({"api.Navigator.a": 1, "api.AnalyserNode.b": 1})
    right = _subtraction({"api.Navigator.a": 1})
    diff = diff_digests(left, right)
    assert "audio-graph" in diff["techniques_differing"]
    assert "navigator-identity" not in diff["techniques_differing"]


def test_diff_focus_splits_names_by_side():
    left = _subtraction({"api.AnalyserNode.b": 1})
    right = _subtraction({"api.GainNode.c": 1})
    diff = diff_digests(left, right, focus="audio-graph")
    assert diff["focus"]["only_left"] == ["api.AnalyserNode.b"]
    assert diff["focus"]["only_right"] == ["api.GainNode.c"]


def test_render_diff_rechecks_saved_focus_names():
    left = _subtraction({"api.AnalyserNode.a": 1})
    right = _subtraction({"api.Navigator.b": 1})
    diff = diff_digests(left, right, focus="audio-graph")
    diff["focus"]["only_left"] = ["api.Navigator.private"]
    with pytest.raises(ContractError, match="rendered digest"):
        render_digest(diff)


def test_render_diff_rechecks_saved_input_delivery_verdict():
    left = _subtraction({"api.Navigator.a": 1})
    right = _subtraction({"api.Navigator.a": 1})
    left["arm_input_profile"] = "probe"
    right["arm_input_profile"] = "probe"
    diff = diff_digests(left, right)
    assert diff["input_delivery"]["left"]["verified"] is False
    diff["input_delivery"]["left"]["verified"] = True
    with pytest.raises(ContractError, match="rendered digest"):
        render_digest(diff)


def test_render_diff_does_not_publish_edited_comparability_note():
    left = _subtraction({"api.Navigator.a": 1})
    right = _subtraction({"api.Navigator.b": 1})
    provenance = {"status": "VERIFIED", "recorded_hosts": ["example.test"]}
    left["provenance"] = provenance
    right["provenance"] = provenance
    diff = diff_digests(left, right)
    assert diff["comparability"]["status"] == "same-origin"
    diff["comparability"]["note"] = "private operator path /tenant/secret"
    assert "private operator path" not in render_digest(diff)


def test_render_diff_rejects_forged_method_control_gate():
    left = _subtraction({"api.Navigator.a": 1})
    right = _subtraction({"api.Navigator.b": 1})
    left["arm_headed"] = True
    right["arm_headed"] = False
    diff = diff_digests(left, right)
    assert diff["comparability"]["controlled_method_comparison"] is False
    diff["comparability"]["controlled_method_comparison"] = True
    with pytest.raises(ContractError, match="rendered digest"):
        render_digest(diff)


def test_render_diff_rejects_cotampered_unready_method_control():
    left = _subtraction({"api.Navigator.a": 1}, clean=False)
    right = _subtraction({"api.Navigator.b": 1}, clean=False)
    left["arm_headed"] = True
    right["arm_headed"] = False
    diff = diff_digests(left, right, vary_method_axes=("headed",))
    assert diff["comparability"]["controlled_method_comparison"] is False
    diff["comparability"]["status"] = "method-control"
    diff["comparability"]["controlled_method_comparison"] = True
    with pytest.raises(ContractError, match="rendered digest"):
        render_digest(diff)


def test_render_diff_rechecks_saved_responsive_gate_flags():
    left = _subtraction({"api.Navigator.a": 1})
    right = _subtraction({"api.Navigator.b": 1})
    left["arm_viewport"] = {"inner_width": 800, "inner_height": 1}
    right["arm_viewport"] = {"inner_width": 800, "inner_height": 900}
    diff = diff_digests(left, right)
    assert diff["comparability"]["viewport_crosses_responsive_gate"] is True
    diff["comparability"]["viewport_crosses_responsive_gate"] = False
    diff["comparability"]["viewport_differs"] = False
    with pytest.raises(ContractError, match="rendered digest"):
        render_digest(diff)


@pytest.mark.parametrize(
    "forged_viewport",
    [
        {"tenant": "private path that the producer would discard"},
        {"inner_height": True},
    ],
)
def test_render_diff_rejects_noncanonical_saved_viewport(forged_viewport):
    left = _subtraction({"api.Navigator.a": 1})
    right = _subtraction({"api.Navigator.b": 1})
    left["arm_viewport"] = {"inner_width": 800, "inner_height": 700}
    right["arm_viewport"] = {"inner_width": 800, "inner_height": 700}
    diff = diff_digests(left, right)
    assert diff["comparability"]["viewport_values_differ"] is False
    diff["comparability"]["left_viewport"] = forged_viewport
    diff["comparability"]["right_viewport"] = forged_viewport
    with pytest.raises(ContractError, match="rendered digest"):
        render_digest(diff)


def test_render_diff_accepts_producer_unverifiable_viewport():
    left = _subtraction({"api.Navigator.a": 1})
    right = _subtraction({"api.Navigator.b": 1})
    left["arm_viewport"] = "unmeasured"
    right["arm_viewport"] = "unmeasured"
    diff = diff_digests(left, right)
    assert diff["comparability"]["left_viewport"]["status"] == "unverifiable"
    assert diff["comparability"]["right_viewport"]["status"] == "unverifiable"
    assert render_digest(diff)


def test_diff_of_two_empty_surfaces_does_not_divide_by_zero():
    left = _subtraction({"blink.canvas": 1})
    right = _subtraction({"blink.canvas": 1})
    diff = diff_digests(left, right)
    assert diff["jaccard"] == 0.0
    assert diff["identical_surface"] is True


def test_diff_accepts_mixed_observation_and_subtraction_inputs():
    diff = diff_digests(
        _observation({"api.Navigator.a": 1}), _subtraction({"api.Navigator.a": 1})
    )
    assert diff["shared"] == 1
    assert diff["comparability"]["attribution_kinds_differ"] is True
    assert diff["comparability"]["status"] == "not-comparable"
    assert "NOT ATTRIBUTED" in render_digest(diff)


def test_diff_marks_an_unready_subtraction_as_not_comparable_for_claims():
    left = _subtraction({"api.Navigator.a": 1})
    right = _subtraction({"api.Navigator.a": 1})
    left["surface_claim_ready"] = False
    diff = diff_digests(left, right)
    assert diff["shared"] == 1
    comparison = diff["comparability"]
    assert comparison["left_claim_ready"] is False
    assert comparison["right_claim_ready"] is True
    assert comparison["status"] == "not-comparable"
    assert "NOT CLAIM-READY" in render_digest(diff)


# --------------------------------------------------------------------------
# passive resource-intent digest
# --------------------------------------------------------------------------


def _intent(origin: str, *, segment: int = 7, query: str = "lang") -> dict:
    return {
        "tag": "iframe",
        "attribute": "src",
        "origin": origin,
        "same_origin_as_rehost": False,
        "path_segment_lengths": [segment, 18, 1],
        "path_segments_truncated": False,
        "query_names": [query],
        "query_names_truncated": False,
    }


def test_digest_carries_attributed_resource_intent_without_raw_url():
    doc = _subtraction({"api.Navigator.a": 1})
    row = _intent("https://challenges.cloudflare.com")
    row["raw_url"] = "https://challenges.cloudflare.com/private?token=secret"
    doc["resource_intents"] = {
        "status": "ok",
        "arm_count": 3,
        "control_count": 2,
        "shared_count": 2,
        "only_in_arm": [row],
        "only_in_control": [],
        "clean_subtraction": True,
        "private_extra": "secret-report-value",
    }
    digest = digest_observation(doc)
    intents = digest["resource_intents"]
    assert intents["attributed"] is True
    assert intents["row_kind"] == "introduced"
    assert intents["rows_total"] == 1
    rendered_json = json.dumps(digest)
    assert "raw_url" not in rendered_json
    assert "secret-report-value" not in rendered_json
    text = render_digest(digest)
    assert "iframe.src -> https://challenges.cloudflare.com" in text
    assert "query-keys=[lang]" in text
    assert "not proof that a request was sent" in text


def test_raw_resource_intent_is_explicitly_unattributed():
    doc = _observation({"api.Navigator.a": 1})
    doc["resource_intents"] = {
        "status": "ok",
        "intents": [_intent("https://challenges.cloudflare.com")],
    }
    digest = digest_observation(doc)
    assert digest["resource_intents"]["row_kind"] == "raw"
    assert "NOT ATTRIBUTED  resource intents" in render_digest(digest)


def test_resource_intent_digest_is_bounded():
    doc = _subtraction({"api.Navigator.a": 1})
    doc["resource_intents"] = {
        "status": "ok",
        "only_in_arm": [
            _intent(f"https://intent{i}.example", segment=i + 1) for i in range(40)
        ],
        "only_in_control": [],
    }
    digest = digest_observation(doc)
    assert digest["resource_intents"]["rows_total"] == 40
    assert len(digest["resource_intents"]["rows"]) == 16
    assert digest["resource_intents"]["rows_omitted"] == 24
    assert "+24 more (bounded)" in render_digest(digest)


def test_render_digest_rechecks_saved_resource_intent_origin_and_counts():
    doc = _subtraction({"api.Navigator.a": 1})
    doc["resource_intents"] = {
        "status": "ok",
        "only_in_arm": [_intent("https://example.test")],
        "only_in_control": [],
    }
    digest = digest_observation(doc)
    digest["resource_intents"]["rows"][0]["origin"] = (
        "https://example.test/private?token=secret"
    )
    with pytest.raises(ContractError, match="rendered digest"):
        render_digest(digest)

    digest = digest_observation(doc)
    digest["resource_intents"]["rows_total"] = 0
    with pytest.raises(ContractError, match="rendered digest"):
        render_digest(digest)


def test_diff_compares_resource_intents_independently_of_api_surface():
    left = _subtraction({"api.Navigator.a": 1}, label="left")
    right = _subtraction({"api.Navigator.a": 1}, label="right")
    shared = _intent("https://shared.example")
    introduced = _intent("https://challenges.cloudflare.com")
    left["resource_intents"] = {
        "status": "ok",
        "only_in_arm": [shared, introduced],
        "only_in_control": [],
    }
    right["resource_intents"] = {
        "status": "ok",
        "only_in_arm": [shared],
        "only_in_control": [],
    }
    diff = diff_digests(left, right)
    assert diff["identical_surface"] is True
    assert diff["resource_intents"]["shared"] == 1
    assert diff["resource_intents"]["only_left"] == 1
    assert diff["resource_intents"]["only_right"] == 0
    text = render_digest(diff)
    assert "only-left 1" in text
    assert "https://challenges.cloudflare.com" in text


def test_render_diff_rechecks_saved_resource_intent_rows():
    left = _subtraction({"api.Navigator.a": 1}, label="left")
    right = _subtraction({"api.Navigator.a": 1}, label="right")
    left["resource_intents"] = {
        "status": "ok",
        "only_in_arm": [_intent("https://example.test")],
    }
    right["resource_intents"] = {"status": "ok", "only_in_arm": []}
    diff = diff_digests(left, right)
    diff["resource_intents"]["only_left_rows"][0]["origin"] = (
        "https://example.test/private?token=secret"
    )
    with pytest.raises(ContractError, match="rendered digest"):
        render_digest(diff)


def test_resource_intent_diff_refuses_raw_vs_attributed_comparison():
    left = _observation({"api.Navigator.a": 1})
    right = _subtraction({"api.Navigator.a": 1})
    left["resource_intents"] = {
        "status": "ok",
        "intents": [_intent("https://x.example")],
    }
    right["resource_intents"] = {
        "status": "ok",
        "only_in_arm": [_intent("https://x.example")],
        "only_in_control": [],
    }
    diff = diff_digests(left, right)
    assert diff["resource_intents"]["comparable"] is False
    assert "RESOURCE INTENTS NOT COMPARABLE" in render_digest(diff)


def _request_row(
    *, count: int, body_total: int, body_digests: dict[str, int] | None = None
) -> dict:
    return {
        "method": "POST",
        "served": "post-ack",
        "path_segment_lengths": [13],
        "path_segments_truncated": False,
        "query_names": [],
        "query_names_truncated": False,
        "count": count,
        "body_bytes_total": body_total,
        "body_bytes_min": body_total // count,
        "body_bytes_max": body_total // count,
        **({"body_sha256_16_counts": body_digests} if body_digests is not None else {}),
    }


def test_digest_renders_attributed_request_activity_without_path_values():
    doc = _subtraction({"api.Navigator.sendBeacon": 1})
    row = _request_row(count=2, body_total=10530)
    row["raw_path"] = "/private-tenant/fingerprint?token=private-value"
    doc["request_activity"] = {
        "status": "ok",
        "only_in_arm": [row],
        "only_in_control": [],
        "clean_subtraction": True,
    }
    digest = digest_observation(doc)
    rendered = json.dumps(digest)
    assert "raw_path" not in rendered
    assert "private-tenant" not in rendered
    text = render_digest(digest)
    assert "POST post-ack path-lengths=[13]" in text
    assert "x2 bytes=10530" in text
    assert "synthetic lab response" in text


def test_render_digest_rechecks_saved_request_activity_rows_and_non_claim():
    doc = _subtraction({"api.Navigator.sendBeacon": 1})
    doc["request_activity"] = {
        "status": "ok",
        "only_in_arm": [_request_row(count=1, body_total=42)],
        "only_in_control": [],
    }
    digest = digest_observation(doc)
    digest["request_activity"]["rows"][0]["method"] = "PRIVATE METHOD"
    with pytest.raises(ContractError, match="rendered digest"):
        render_digest(digest)

    digest = digest_observation(doc)
    digest["request_activity"]["non_claim"] = "private operator route"
    with pytest.raises(ContractError, match="rendered digest"):
        render_digest(digest)


def test_diff_exposes_request_count_and_size_change_with_identical_shape():
    left = _subtraction({"api.Navigator.sendBeacon": 1}, label="input")
    right = _subtraction({"api.Navigator.sendBeacon": 1}, label="none")
    left["request_activity"] = {
        "status": "ok",
        "only_in_arm": [_request_row(count=2, body_total=10530)],
    }
    right["request_activity"] = {
        "status": "ok",
        "only_in_arm": [_request_row(count=1, body_total=4796)],
    }
    diff = diff_digests(left, right)
    assert diff["identical_surface"] is True
    assert diff["request_activity"]["shared_shapes"] == 1
    assert diff["request_activity"]["changed"] == 1
    text = render_digest(diff)
    assert "changed metrics 1" in text
    assert "left x2/10530 bytes, right x1/4796 bytes" in text


def test_render_diff_rechecks_saved_request_activity_rows():
    left = _subtraction({"api.Navigator.sendBeacon": 1}, label="left")
    right = _subtraction({"api.Navigator.sendBeacon": 1}, label="right")
    left["request_activity"] = {
        "status": "ok",
        "only_in_arm": [_request_row(count=1, body_total=42)],
    }
    right["request_activity"] = {"status": "ok", "only_in_arm": []}
    diff = diff_digests(left, right)
    diff["request_activity"]["only_left_rows"][0]["method"] = "PRIVATE METHOD"
    with pytest.raises(ContractError, match="rendered digest"):
        render_digest(diff)


def test_diff_exposes_same_length_request_body_digest_change():
    left = _subtraction({"api.Navigator.sendBeacon": 1}, label="first")
    right = _subtraction({"api.Navigator.sendBeacon": 1}, label="second")
    left["request_activity"] = {
        "status": "ok",
        "only_in_arm": [
            _request_row(count=1, body_total=4811, body_digests={"a" * 16: 1})
        ],
    }
    right["request_activity"] = {
        "status": "ok",
        "only_in_arm": [
            _request_row(count=1, body_total=4811, body_digests={"b" * 16: 1})
        ],
    }

    diff = diff_digests(left, right)

    assert diff["request_activity"]["changed"] == 1
    assert "body-digest multisets differ" in render_digest(diff)


def test_render_diff_rejects_saved_changed_row_with_identical_metrics():
    left = _subtraction({"api.Navigator.sendBeacon": 1})
    right = _subtraction({"api.Navigator.sendBeacon": 1})
    left["request_activity"] = {
        "status": "ok",
        "only_in_arm": [_request_row(count=2, body_total=42)],
    }
    right["request_activity"] = {
        "status": "ok",
        "only_in_arm": [_request_row(count=1, body_total=21)],
    }
    diff = diff_digests(left, right)
    changed = diff["request_activity"]["changed_rows"][0]
    changed["right"] = dict(changed["left"])
    with pytest.raises(ContractError, match="rendered digest"):
        render_digest(diff)


def test_digest_renders_body_digest_coverage_without_body_bytes():
    doc = _subtraction({"api.Navigator.sendBeacon": 1})
    doc["request_activity"] = {
        "status": "ok",
        "only_in_arm": [
            _request_row(
                count=2,
                body_total=9622,
                body_digests={"a" * 16: 2},
            )
        ],
    }

    text = render_digest(digest_observation(doc))

    assert "body-digests=2/1-distinct" in text


def test_digest_requires_probe_receipt_and_trusted_witness_in_both_arms():
    doc = _subtraction({"api.Event.type.get": 1})
    doc.update(
        arm_input_profile="probe-touch",
        arm_input_probe={
            "profile": "probe-touch",
            "dispatched": 3,
            "attempted": 3,
            "errors": [],
            "trusted_transport": True,
            "touch_dispatched": True,
        },
        control_input_probe={
            "profile": "probe-touch",
            "dispatched": 3,
            "attempted": 3,
            "errors": [],
            "trusted_transport": True,
            "touch_dispatched": True,
        },
        arm_ambient_input={
            "contaminated": False,
            "trusted_events": {"touchstart": 1, "touchmove": 1, "touchend": 1},
        },
        control_ambient_input={
            "contaminated": False,
            "trusted_events": {"touchstart": 1, "touchmove": 1, "touchend": 1},
        },
    )
    digest = digest_observation(doc)
    assert digest["input_delivery"]["verified"] is True
    text = render_digest(digest)
    assert "input delivery  probe-touch  VERIFIED" in text
    assert "touchstart=1" in text


@pytest.mark.parametrize(
    "mutation", ["probe_counts", "ambient_witness", "scroll_count"]
)
def test_digest_does_not_verify_inconsistent_input_receipts(mutation):
    doc = _subtraction({"api.Event.type.get": 1})
    probe = {
        "profile": "probe",
        "dispatched": 3,
        "attempted": 3,
        "errors": [],
        "trusted_transport": True,
    }
    events = {"mousemove": 1, "click": 1, "keydown": 1, "keyup": 1}
    doc.update(
        arm_input_profile="probe",
        arm_input_probe=dict(probe),
        control_input_probe=dict(probe),
        arm_ambient_input={"contaminated": False, "trusted_events": dict(events)},
        control_ambient_input={"contaminated": False, "trusted_events": dict(events)},
    )
    if mutation == "probe_counts":
        doc["arm_input_probe"]["dispatched"] = 10_001
        doc["arm_input_probe"]["attempted"] = 10_002
    elif mutation == "ambient_witness":
        doc["arm_ambient_input"]["trusted_events"]["click"] = 10_001
    else:
        doc["arm_input_profile"] = "probe-scroll"
        for role in ("arm", "control"):
            doc[f"{role}_input_probe"]["profile"] = "probe-scroll"
            doc[f"{role}_input_probe"]["scroll_commands_dispatched"] = 3
            doc[f"{role}_ambient_input"]["trusted_events"] = {
                "wheel": 1,
                "scroll": 1,
            }
        doc["arm_input_probe"]["scroll_commands_dispatched"] = 1

    digest = digest_observation(doc)

    assert digest["input_delivery"]["verified"] is False


@pytest.mark.parametrize(
    "mutation",
    [
        "arm_contaminated",
        "control_contaminated",
        "probe_profile",
        "control_profile",
        "invalid_extra_event",
        "touch_not_dispatched",
    ],
)
def test_digest_reconciles_saved_input_delivery_claims(mutation):
    doc = _subtraction({"api.Event.type.get": 1})
    probe = {
        "profile": "probe-touch",
        "dispatched": 3,
        "attempted": 3,
        "errors": [],
        "trusted_transport": True,
        "touch_dispatched": True,
    }
    events = {"touchstart": 1, "touchmove": 1, "touchend": 1}
    doc.update(
        arm_input_profile="probe-touch",
        control_input_profile="probe-touch",
        arm_input_probe=dict(probe),
        control_input_probe=dict(probe),
        arm_ambient_input={"contaminated": False, "trusted_events": dict(events)},
        control_ambient_input={"contaminated": False, "trusted_events": dict(events)},
    )
    if mutation == "arm_contaminated":
        doc["arm_ambient_input"]["contaminated"] = True
    elif mutation == "control_contaminated":
        doc["control_ambient_input"]["contaminated"] = True
    elif mutation == "probe_profile":
        doc["arm_input_probe"]["profile"] = "probe"
    elif mutation == "control_profile":
        doc["control_input_profile"] = "probe"
    elif mutation == "invalid_extra_event":
        doc["arm_ambient_input"]["trusted_events"]["click"] = -1
    else:
        doc["arm_input_probe"]["touch_dispatched"] = False

    delivery = digest_observation(doc)["input_delivery"]

    assert delivery["verified"] is False
    expected_status = (
        "INPUT CONTAMINATION"
        if mutation in {"arm_contaminated", "control_contaminated"}
        else "UNVERIFIED"
    )
    assert expected_status in render_digest(digest_observation(doc))


def test_digest_surfaces_no_input_control_contamination():
    doc = _subtraction({"api.Event.type.get": 1})
    doc.update(
        arm_input_profile="none",
        control_input_profile="none",
        arm_ambient_input={"contaminated": False, "trusted_events": {}},
        control_ambient_input={
            "contaminated": True,
            "trusted_events": {"click": 1},
        },
    )

    delivery = digest_observation(doc)["input_delivery"]

    assert delivery["verified"] is False
    assert delivery["contaminated"] is True
    rendered = render_digest(digest_observation(doc))
    assert "INPUT CONTAMINATION" in rendered
    assert "control:" in rendered
    assert "click=1" in rendered


@pytest.mark.parametrize(
    "mutation",
    [
        "touch_dispatch",
        "no_input_probe",
        "ambient_contamination",
        "bad_event",
        "conflicting_event_aliases",
        "inconsistent_event_total",
        "conflicting_trust_aliases",
        "false_complete_receipt",
    ],
)
def test_digest_closes_claim_ready_on_incoherent_saved_input_gates(mutation):
    doc = _subtraction({"api.Event.type.get": 1})
    probe = {
        "profile": "probe-touch",
        "dispatched": 3,
        "attempted": 3,
        "errors": [],
        "trusted_transport": True,
        "touch_dispatched": True,
    }
    events = {"touchstart": 1, "touchmove": 1, "touchend": 1}
    doc.update(
        surface_claim_ready=True,
        arm_input_profile="probe-touch",
        control_input_profile="probe-touch",
        arm_input_probe=dict(probe),
        control_input_probe=dict(probe),
        input_method_comparable=True,
        arm_ambient_input={"contaminated": False, "trusted_events": dict(events)},
        control_ambient_input={"contaminated": False, "trusted_events": dict(events)},
        ambient_input_clean=True,
    )
    if mutation == "touch_dispatch":
        doc["arm_input_probe"]["touch_dispatched"] = False
    elif mutation == "no_input_probe":
        doc["arm_input_profile"] = "none"
        doc["control_input_profile"] = "none"
        doc["control_input_probe"] = None
        for role in ("arm", "control"):
            doc[f"{role}_ambient_input"] = {
                "contaminated": False,
                "trusted_events": {},
            }
    elif mutation == "ambient_contamination":
        doc["control_ambient_input"]["contaminated"] = True
    elif mutation == "conflicting_event_aliases":
        doc["arm_ambient_input"]["events"] = {}
    elif mutation == "inconsistent_event_total":
        doc["arm_ambient_input"]["total_trusted_events"] = 0
    elif mutation == "conflicting_trust_aliases":
        doc["arm_input_probe"]["trusted"] = True
        doc["arm_input_probe"]["trusted_transport"] = False
    elif mutation == "false_complete_receipt":
        doc["arm_input_probe"]["complete"] = False
    else:
        doc["arm_ambient_input"]["trusted_events"]["click"] = -1

    digest = digest_observation(doc)

    assert digest["surface_claim_ready"] is False
    assert digest["input_delivery"]["verified"] is False
    if mutation == "no_input_probe":
        assert "UNVERIFIED" in render_digest(digest)
    digest["surface_claim_ready"] = True
    with pytest.raises(ContractError, match="claim readiness"):
        render_digest(digest)


def test_digest_keeps_command_claim_ready_without_event_witnesses():
    doc = _subtraction({"api.Event.type.get": 1})
    probe = {
        "profile": "probe",
        "dispatched": 3,
        "attempted": 3,
        "errors": [],
        "trusted_transport": True,
    }
    doc.update(
        surface_claim_ready=True,
        arm_input_profile="probe",
        control_input_profile="probe",
        arm_input_probe=dict(probe),
        control_input_probe=dict(probe),
        input_method_comparable=True,
        arm_ambient_input={"contaminated": False, "trusted_events": {}},
        control_ambient_input={"contaminated": False, "trusted_events": {}},
        ambient_input_clean=True,
    )

    digest = digest_observation(doc)

    assert digest["surface_claim_ready"] is True
    assert digest["input_delivery"]["verified"] is False


@pytest.mark.parametrize("missing_gate", ["input_method_comparable", "ambient_input_clean"])
def test_digest_withholds_claim_when_saved_input_receipts_lose_their_gate(
    missing_gate,
):
    doc = _subtraction({"api.Event.type.get": 1})
    probe = {
        "profile": "probe",
        "dispatched": 3,
        "attempted": 3,
        "errors": [],
        "trusted_transport": True,
    }
    doc.update(
        surface_claim_ready=True,
        arm_input_profile="probe",
        control_input_profile="probe",
        arm_input_probe=dict(probe),
        control_input_probe=dict(probe),
        input_method_comparable=True,
        arm_ambient_input={"contaminated": False, "trusted_events": {}},
        control_ambient_input={"contaminated": False, "trusted_events": {}},
        ambient_input_clean=True,
    )
    assert digest_observation(doc)["surface_claim_ready"] is True
    del doc[missing_gate]

    digest = digest_observation(doc)

    assert digest["surface_claim_ready"] is False
    assert digest["input_claim_receipts_coherent"] is False


@pytest.mark.parametrize(
    "gate",
    [
        "ready_probe_comparable",
        "collector_started",
        "trace_evidence_coherent",
        "await_method_comparable",
        "arm_readiness_satisfied",
        "offline_guard_comparable",
        "request_activity_receipts_coherent",
        "rehost_dependencies_complete",
        "control_rehost_dependencies_complete",
    ],
)
def test_digest_does_not_promote_explicitly_failed_surface_gate(gate):
    doc = _subtraction({"api.Event.type.get": 1})
    doc.update(surface_claim_ready=True, **{gate: False})

    digest = digest_observation(doc)

    assert digest["surface_claim_ready"] is False


def test_digest_accepts_legacy_ready_probe_gate_without_expression_receipts():
    doc = _subtraction({"api.Event.type.get": 1})
    doc.update(surface_claim_ready=True, ready_probe_comparable=True)

    digest = digest_observation(doc)

    assert digest["surface_claim_ready"] is True
    assert "ready_probe_receipts_coherent" not in digest
    assert render_digest(digest)


def test_digest_accepts_legacy_await_gates_without_wait_receipts():
    doc = _subtraction({"api.Event.type.get": 1})
    doc.update(
        surface_claim_ready=True,
        await_method_comparable=True,
        arm_readiness_satisfied=True,
    )

    digest = digest_observation(doc)

    assert digest["surface_claim_ready"] is True
    assert "await_receipts_coherent" not in digest
    assert render_digest(digest)


def test_digest_accepts_legacy_subtraction_without_self_receipt():
    doc = _subtraction({"api.Event.type.get": 1})
    doc["surface_claim_ready"] = True

    digest = digest_observation(doc)

    assert digest["surface_claim_ready"] is True
    assert "subtraction_receipt_coherent" not in digest
    assert render_digest(digest)


def test_digest_accepts_legacy_request_receipt_shape():
    doc = _subtraction({"api.Event.type.get": 1})
    doc.update(
        surface_claim_ready=True,
        request_activity={
            "status": "unverifiable",
            "only_in_arm": [],
            "only_in_control": [],
        },
    )

    digest = digest_observation(doc)

    assert digest["surface_claim_ready"] is True
    assert digest["request_activity_receipts_valid"] is True
    assert render_digest(digest)


@pytest.mark.parametrize(
    "receipt",
    [
        {
            "status": "ok",
            "count": 1,
            "dependencies_complete": True,
            "paths": ["/missing-stage.js"],
        },
        {"status": "ok", "count": 0, "paths": ["/missing-stage.js"]},
        {
            "status": "ok",
            "count": 0,
            "dependencies_complete": True,
            "paths": [],
            "truncated_paths": 1,
        },
    ],
)
def test_digest_does_not_promote_conflicting_legacy_rehost_dependency_receipt(
    receipt: dict,
):
    doc = _subtraction({"api.Event.type.get": 1})
    doc.update(
        surface_claim_ready=True,
        rehost_dependencies_complete=True,
        unserved_requests=receipt,
    )

    digest = digest_observation(doc)

    assert digest["surface_claim_ready"] is False
    assert digest["rehost_dependency_receipts_coherent"] is False
    digest["surface_claim_ready"] = True
    with pytest.raises(ContractError, match="claim readiness"):
        render_digest(digest)


def test_digest_keeps_coherent_legacy_rehost_dependency_receipt():
    doc = _subtraction({"api.Event.type.get": 1})
    doc.update(
        surface_claim_ready=True,
        rehost_dependencies_complete=True,
        unserved_requests={
            "status": "ok",
            "count": 0,
            "dependencies_complete": True,
            "paths": [],
        },
    )

    digest = digest_observation(doc)

    assert digest["surface_claim_ready"] is True
    assert digest["rehost_dependency_receipts_coherent"] is True
    assert "attributed surface" in render_digest(digest)


@pytest.mark.parametrize("missing", ["unserved_requests", "rehost_dependencies_complete"])
def test_digest_withholds_claim_when_rehost_dependency_receipt_is_unpaired(missing):
    doc = _subtraction({"api.Event.type.get": 1})
    doc.update(
        surface_claim_ready=True,
        rehost_dependencies_complete=True,
        unserved_requests={
            "status": "ok",
            "count": 0,
            "dependencies_complete": True,
            "paths": [],
        },
    )
    del doc[missing]

    digest = digest_observation(doc)

    assert digest["surface_claim_ready"] is False
    assert digest["rehost_dependency_receipts_coherent"] is False


@pytest.mark.parametrize("mutation", ["missing_gate", "missing_arm", "false_comparability"])
def test_digest_withholds_claim_on_incoherent_saved_offline_guard(mutation):
    doc = _subtraction({"api.Event.type.get": 1})
    doc.update(
        surface_claim_ready=True,
        arm_offline_guard={"status": "not-recorded"},
        control_offline_guard={"status": "not-recorded"},
        offline_guard_comparable=None,
    )
    assert digest_observation(doc)["surface_claim_ready"] is True
    if mutation == "missing_gate":
        del doc["offline_guard_comparable"]
    elif mutation == "missing_arm":
        del doc["arm_offline_guard"]
    else:
        doc["offline_guard_comparable"] = True

    digest = digest_observation(doc)

    assert digest["surface_claim_ready"] is False
    assert digest["offline_guard_receipts_coherent"] is False
    digest["surface_claim_ready"] = True
    with pytest.raises(ContractError, match="claim readiness"):
        render_digest(digest)


@pytest.mark.parametrize(
    "mutation",
    ["missing_control", "false_completeness", "unknown_comparability", "malformed_arm"],
)
def test_digest_withholds_claim_on_incoherent_saved_observation_lineage(mutation):
    doc = _subtraction({"api.Event.type.get": 1})
    doc.update(
        surface_claim_ready=True,
        arm_observation_receipt_sha256="a" * 64,
        control_observation_receipt_sha256="b" * 64,
        input_observation_receipts_complete=True,
        input_observation_receipts_comparable=True,
    )
    assert digest_observation(doc)["surface_claim_ready"] is True
    if mutation == "missing_control":
        del doc["control_observation_receipt_sha256"]
    elif mutation == "false_completeness":
        doc["input_observation_receipts_complete"] = False
    elif mutation == "unknown_comparability":
        doc["input_observation_receipts_comparable"] = None
    else:
        doc["arm_observation_receipt_sha256"] = "invalid"

    digest = digest_observation(doc)

    assert digest["surface_claim_ready"] is False
    assert digest["observation_lineage_receipts_coherent"] is False
    digest["surface_claim_ready"] = True
    with pytest.raises(ContractError, match="claim readiness"):
        render_digest(digest)


def test_digest_keeps_fully_legacy_observation_lineage_unknown():
    doc = _subtraction({"api.Event.type.get": 1})
    doc.update(
        surface_claim_ready=True,
        arm_observation_receipt_sha256=None,
        control_observation_receipt_sha256=None,
        input_observation_receipts_complete=False,
        input_observation_receipts_comparable=None,
    )

    digest = digest_observation(doc)

    assert digest["surface_claim_ready"] is True
    assert digest["observation_lineage_receipts_coherent"] is True
    assert "attributed surface" in render_digest(digest)


@pytest.mark.parametrize(
    "mutation",
    ["failed_arm", "unknown_arm_gate", "failed_control_gate", "missing_arm"],
)
def test_digest_withholds_claim_on_incoherent_saved_startup_receipts(mutation):
    startup = _sanitize_startup_document({"started": True, "reasons": []})
    doc = _subtraction({"api.Event.type.get": 1})
    doc.update(
        surface_claim_ready=True,
        collector_started=True,
        collector_startup=dict(startup),
        collector_startup_coherent=True,
        control_collector_startup=dict(startup),
        control_collector_startup_coherent=True,
        startup_derivation_coherent=True,
    )
    assert digest_observation(doc)["surface_claim_ready"] is True
    if mutation == "failed_arm":
        doc["collector_startup"]["started"] = False
    elif mutation == "unknown_arm_gate":
        doc["collector_startup_coherent"] = None
    elif mutation == "failed_control_gate":
        doc["control_collector_startup_coherent"] = False
    else:
        del doc["collector_startup"]

    digest = digest_observation(doc)

    assert digest["surface_claim_ready"] is False
    assert digest["startup_receipts_coherent"] is False
    digest["surface_claim_ready"] = True
    with pytest.raises(ContractError, match="claim readiness"):
        render_digest(digest)


@pytest.mark.parametrize("mutation", ["nonempty", "missing_list", "unhashable"])
def test_digest_withholds_claim_on_incoherent_saved_method_mismatch_verdict(mutation):
    doc = _subtraction({"api.Event.type.get": 1})
    doc.update(
        surface_claim_ready=True,
        arm_control_method_comparable=True,
        arm_control_method_mismatches=[],
    )
    assert digest_observation(doc)["surface_claim_ready"] is True
    if mutation == "nonempty":
        doc["arm_control_method_mismatches"] = ["headed"]
    elif mutation == "missing_list":
        del doc["arm_control_method_mismatches"]
    else:
        doc["arm_control_method_mismatches"] = [{}]

    digest = digest_observation(doc)

    assert digest["surface_claim_ready"] is False
    assert digest["method_mismatch_verdict_coherent"] is False
    digest["surface_claim_ready"] = True
    with pytest.raises(ContractError, match="claim readiness"):
        render_digest(digest)


def test_digest_keeps_legacy_unknown_method_mismatch_verdict():
    doc = _subtraction({"api.Event.type.get": 1})
    doc.update(
        surface_claim_ready=True,
        arm_control_method_comparable=None,
        arm_control_method_mismatches=[],
    )

    digest = digest_observation(doc)

    assert digest["surface_claim_ready"] is True
    assert digest["method_mismatch_verdict_coherent"] is True


@pytest.mark.parametrize(
    "mutation",
    [
        "different_headed",
        "different_hook_mode",
        "missing_control_headed",
        "invalid_equal_headed",
    ],
)
def test_digest_withholds_claim_on_contradictory_retained_method_pair(mutation):
    doc = _subtraction({"api.Event.type.get": 1})
    doc.update(
        surface_claim_ready=True,
        arm_control_method_comparable=True,
        arm_control_method_mismatches=[],
        arm_headed=True,
        control_headed=True,
        arm_hook_mode="off",
        control_hook_mode="off",
    )
    assert digest_observation(doc)["surface_claim_ready"] is True
    if mutation == "different_headed":
        doc["control_headed"] = False
    elif mutation == "different_hook_mode":
        doc["control_hook_mode"] = "on"
    elif mutation == "invalid_equal_headed":
        doc["arm_headed"] = 1
        doc["control_headed"] = 1
    else:
        del doc["control_headed"]

    digest = digest_observation(doc)

    assert digest["surface_claim_ready"] is False
    assert digest["method_mismatch_verdict_coherent"] is False
    digest["surface_claim_ready"] = True
    with pytest.raises(ContractError, match="claim readiness"):
        render_digest(digest)


def test_digest_rejects_saved_method_mismatch_without_retained_difference():
    doc = _subtraction({"api.Event.type.get": 1})
    doc.update(
        surface_claim_ready=True,
        arm_control_method_comparable=False,
        arm_control_method_mismatches=["headed"],
        arm_headed=True,
        control_headed=True,
    )

    digest = digest_observation(doc)

    assert digest["surface_claim_ready"] is False
    assert digest["method_mismatch_verdict_coherent"] is False


@pytest.mark.parametrize(
    "mutation",
    ["arm_digest", "arm_bytes", "control_digest", "orphan_control_identity"],
)
def test_digest_withholds_claim_on_incoherent_saved_script_identity(mutation):
    doc = _subtraction({"api.Event.type.get": 1})
    doc["surface_claim_ready"] = True
    _set_compact_identity(doc, "shape")
    doc["control_script_sha256_16"] = "0123456789abcdef"
    doc["control_script_identity"] = {
        **doc["script_identity"],
        "sha256_16": doc["control_script_sha256_16"],
    }
    assert digest_observation(doc)["surface_claim_ready"] is True
    if mutation == "arm_digest":
        doc["script_identity"]["sha256_16"] = "f" * 16
    elif mutation == "arm_bytes":
        doc["script_identity"]["bytes"] = -1
    elif mutation == "control_digest":
        doc["control_script_identity"]["sha256_16"] = "f" * 16
    else:
        del doc["control_script_sha256_16"]

    digest = digest_observation(doc)

    assert digest["surface_claim_ready"] is False
    assert digest["script_identity_receipts_coherent"] is False
    digest["surface_claim_ready"] = True
    with pytest.raises(ContractError, match="claim readiness"):
        render_digest(digest)


def test_digest_keeps_legacy_unknown_saved_script_identity():
    doc = _subtraction({"api.Event.type.get": 1})
    doc.update(
        surface_claim_ready=True,
        script_identity_coherent=None,
        script_identity=None,
        control_script_identity=None,
        control_script_sha256_16="0123456789abcdef",
    )

    digest = digest_observation(doc)

    assert digest["surface_claim_ready"] is True
    assert digest["script_identity_receipts_coherent"] is True


def test_digest_keeps_legacy_unknown_saved_trace_receipts():
    doc = _subtraction({"api.Event.type.get": 1})
    doc.update(
        surface_claim_ready=True,
        trace_evidence_coherent=None,
        arm_browser_shutdown=None,
        control_browser_shutdown=None,
        arm_trace_flush=None,
        control_trace_flush=None,
        arm_trace_evidence=None,
        control_trace_evidence=None,
    )

    digest = digest_observation(doc)

    assert digest["surface_claim_ready"] is True
    assert digest["trace_evidence_receipts_coherent"] is True


def test_digest_keeps_legacy_unknown_saved_page_load_receipts():
    doc = _subtraction({"api.Event.type.get": 1})
    doc.update(
        surface_claim_ready=True,
        page_load_execution_coherent=None,
        arm_page_load_execution=None,
        control_page_load_execution=None,
    )

    digest = digest_observation(doc)

    assert digest["surface_claim_ready"] is True
    assert digest["page_load_receipts_coherent"] is True


@pytest.mark.parametrize(
    "mutation", ["failed_result", "supplied_flag", "bad_metadata", "missing_result"]
)
def test_digest_withholds_claim_on_incoherent_saved_driver_execution(mutation):
    absent_driver = {"supplied": False, "bytes": 0, "sha256_16": None}
    doc = _subtraction({"api.Event.type.get": 1})
    doc.update(
        surface_claim_ready=True,
        arm_control_method_comparable=True,
        arm_control_method_mismatches=[],
        driver_execution_complete=True,
        arm_driver=dict(absent_driver),
        control_driver=dict(absent_driver),
        arm_driver_supplied=False,
        control_driver_supplied=False,
        arm_driver_result=None,
        control_driver_result=None,
    )
    assert digest_observation(doc)["surface_claim_ready"] is True
    if mutation == "failed_result":
        doc["arm_driver_result"] = {"status": "failed"}
    elif mutation == "supplied_flag":
        doc["arm_driver_supplied"] = True
    elif mutation == "bad_metadata":
        doc["arm_driver"]["bytes"] = 1
    else:
        del doc["control_driver_result"]

    digest = digest_observation(doc)

    assert digest["surface_claim_ready"] is False
    assert digest["driver_execution_receipts_coherent"] is False
    digest["surface_claim_ready"] = True
    with pytest.raises(ContractError, match="claim readiness"):
        render_digest(digest)


def test_touch_delivery_is_unverified_when_move_or_end_witness_is_missing():
    doc = _subtraction({"api.Event.type.get": 1})
    doc.update(
        arm_input_profile="probe-touch",
        arm_input_probe={
            "profile": "probe-touch",
            "dispatched": 3,
            "attempted": 3,
            "errors": [],
            "trusted_transport": True,
            "touch_dispatched": True,
        },
        control_input_probe={
            "profile": "probe-touch",
            "dispatched": 3,
            "attempted": 3,
            "errors": [],
            "trusted_transport": True,
            "touch_dispatched": True,
        },
        arm_ambient_input={
            "contaminated": False,
            "trusted_events": {"touchstart": 1},
        },
        control_ambient_input={
            "contaminated": False,
            "trusted_events": {"touchstart": 1},
        },
    )

    digest = digest_observation(doc)

    assert digest["input_delivery"]["verified"] is False
    assert digest["input_delivery"]["required_witnesses"] == [
        "touchstart",
        "touchmove",
        "touchend",
    ]


def test_digest_marks_input_unverified_when_control_has_no_witness():
    doc = _subtraction({"api.Event.type.get": 1})
    doc.update(
        arm_input_profile="probe-scroll",
        arm_input_probe={
            "profile": "probe-scroll",
            "dispatched": 3,
            "attempted": 3,
            "errors": [],
            "trusted_transport": True,
        },
        control_input_probe={
            "profile": "probe-scroll",
            "dispatched": 3,
            "attempted": 3,
            "errors": [],
            "trusted_transport": True,
        },
        arm_ambient_input={
            "contaminated": False,
            "trusted_events": {"wheel": 3, "scroll": 3},
        },
        control_ambient_input={"contaminated": False, "trusted_events": {"wheel": 3}},
    )
    digest = digest_observation(doc)
    assert digest["input_delivery"]["verified"] is False
    assert "UNVERIFIED" in render_digest(digest)


def test_digest_closes_an_invalid_input_profile_without_stringifying_it():
    doc = _subtraction({"api.Event.type.get": 1})
    doc["arm_input_profile"] = {"private": "tenant-secret"}
    digest = digest_observation(doc)
    delivery = digest["input_delivery"]
    assert delivery["profile"] == "invalid"
    assert delivery["profile_valid"] is False
    assert delivery["verified"] is False
    assert "private" not in json.dumps(digest)
    assert "tenant-secret" not in json.dumps(digest)


def test_declared_input_method_control_labels_none_as_control_not_missing_receipt():
    left = _subtraction({"api.Event.type.get": 1}, label="scroll")
    left.update(
        arm_input_profile="probe-scroll",
        arm_input_probe={
            "profile": "probe-scroll",
            "dispatched": 3,
            "attempted": 3,
            "errors": [],
            "trusted_transport": True,
        },
        arm_ambient_input={
            "contaminated": False,
            "trusted_events": {"wheel": 3, "scroll": 3},
        },
    )
    right = _subtraction({}, label="none")
    right.update(
        arm_input_profile="none",
        arm_ambient_input={"contaminated": False, "trusted_events": {}},
    )

    diff = diff_digests(left, right, vary_method_axes=("input_profile",))

    assert diff["input_delivery"]["right"] == {
        "profile": "none",
        "intentional_no_input": True,
        "verified": None,
        "note": (
            "recorded method requests no synthetic input; this is the declared "
            "control arm, not a missing delivery receipt"
        ),
    }
    text = render_digest(diff)
    assert "none (declared no-input control" in text
    assert "input right   no verified delivery record" not in text


# --------------------------------------------------------------------------
# rendering + bounded output
# --------------------------------------------------------------------------


def test_render_digest_output_is_bounded_for_a_huge_surface():
    """The whole point: output size must not track input size."""
    big = {f"api.HTMLElement.prop{i}.get": 1 for i in range(4000)}
    text = render_digest(digest_observation(_subtraction(big)))
    assert len(text) < 4000, f"digest grew to {len(text)} chars"


def test_render_digest_includes_schema_specific_sections():
    text = render_digest(digest_observation(_subtraction({"api.Navigator.a": 1})))
    assert "technique" in text
    assert "not observed:" in text


def test_render_rejects_an_unknown_schema():
    with pytest.raises(ContractError):
        render_digest({"schema": "nope/1"})


def test_digest_documents_declare_their_schema():
    assert (
        digest_observation(_subtraction({"api.Navigator.a": 1}))["schema"]
        == DIGEST_SCHEMA
    )
    doc = _subtraction({"api.Navigator.a": 1})
    assert diff_digests(doc, doc)["schema"] == DIFF_SCHEMA


def test_digest_is_json_serialisable():
    """Interface sets must be rendered as lists, not left as Python sets."""
    digest = digest_observation(_subtraction({"api.AnalyserNode.a": 1}))
    round_tripped = json.loads(json.dumps(digest))
    assert round_tripped["techniques"]["audio-graph"]["interfaces"] == ["AnalyserNode"]


def test_digest_carries_non_claims():
    digest = digest_observation(_subtraction({"api.Navigator.a": 1}))
    joined = " ".join(digest["non_claims"]).lower()
    assert "bypass" in joined and "bot-score" in joined


def test_kasada_digest_states_the_vm_analysis_boundary() -> None:
    document = _subtraction({"api.Window.fetch": 1})
    _set_compact_identity(document, "kasada")

    digest = digest_observation(document)
    text = render_digest(digest)

    assert digest["analysis_boundary"]["kind"] == "bytecode-vm-mediated"
    assert "host API crossings" in digest["analysis_boundary"]["interpretation"]
    assert "analysis boundary  BYTECODE VM MEDIATED" in text
    assert "not operations performed inside the collector interpreter" in text


def test_digest_drops_a_compact_identity_for_a_different_arm_pin() -> None:
    document = _subtraction({"api.Window.fetch": 1})
    _set_compact_identity(document, "kasada")
    document["script_identity"]["sha256_16"] = "f" * 16

    digest = digest_observation(document)

    assert "analysis_boundary" not in digest


def test_non_kasada_digest_does_not_invent_an_execution_model() -> None:
    document = _subtraction({"api.Window.fetch": 1})
    _set_compact_identity(document, "datadome")

    digest = digest_observation(document)

    assert "analysis_boundary" not in digest


def test_rejected_script_digest_does_not_invent_a_product_boundary() -> None:
    document = _subtraction({"api.Window.fetch": 1})
    _set_compact_identity(document, "kasada", looks_built=False)

    digest = digest_observation(document)

    assert "analysis_boundary" not in digest


def test_geetest_digest_states_the_staged_loader_boundary() -> None:
    document = _subtraction({"api.HTMLScriptElement.src.set": 1})
    _set_compact_identity(document, "geetest-v4-loader")

    digest = digest_observation(document)
    text = render_digest(digest)

    assert digest["analysis_boundary"]["kind"] == "bootstrap-loader-only"
    assert "downstream challenge library is absent" in digest["analysis_boundary"][
        "interpretation"
    ]
    assert "analysis boundary  BOOTSTRAP LOADER ONLY" in text
    assert "loader surface does not establish downstream" in text


def test_turnstile_digest_states_the_external_challenge_stage_boundary() -> None:
    document = _subtraction({"api.HTMLIFrameElement.constructor": 1})
    _set_compact_identity(document, "cloudflare-turnstile")

    digest = digest_observation(document)
    text = render_digest(digest)

    assert (
        digest["analysis_boundary"]["kind"]
        == "external-challenge-stage-required"
    )
    assert "challenge-frame internals" in digest["analysis_boundary"]["interpretation"]
    assert "analysis boundary  EXTERNAL CHALLENGE STAGE REQUIRED" in text
    assert "outer-script surface does not establish" in text


def test_imperva_digest_states_the_nonempty_second_stage_boundary() -> None:
    document = _subtraction({"api.HTMLScriptElement.src.set": 1})
    _set_compact_identity(document, "imperva-apg-loader")

    digest = digest_observation(document)
    text = render_digest(digest)

    assert (
        digest["analysis_boundary"]["kind"]
        == "nonempty-downstream-script-required"
    )
    assert "APG script injection" in digest["analysis_boundary"]["interpretation"]
    assert "analysis boundary  NONEMPTY DOWNSTREAM SCRIPT REQUIRED" in text
    assert "explicit-empty-stage surface does not establish" in text


def test_anubis_digest_states_the_proof_worker_context_boundary() -> None:
    document = _subtraction({"api.WorkerGlobalScope.crypto.get": 1})
    _set_compact_identity(document, "anubis-web-challenge")

    digest = digest_observation(document)
    text = render_digest(digest)

    assert digest["analysis_boundary"]["kind"] == "proof-worker-context-required"
    assert "selected proof worker" in digest["analysis_boundary"]["interpretation"]
    assert "analysis boundary  PROOF WORKER CONTEXT REQUIRED" in text
    assert "proof completion" in text


def test_shape_digest_states_the_global_interface_enumeration_boundary() -> None:
    document = _subtraction(
        {
            "api.Window.AudioContext": 1,
            "api.CanvasRenderingContext2D.getImageData": 1,
        }
    )
    _set_compact_identity(document, "shape")

    digest = digest_observation(document)
    text = render_digest(digest)

    assert (
        digest["analysis_boundary"]["kind"]
        == "global-interface-enumeration-dominated"
    )
    assert "global property read" in digest["analysis_boundary"]["interpretation"]
    assert "analysis boundary  GLOBAL INTERFACE ENUMERATION DOMINATED" in text
    assert "do not prove the collector used each interface" in text


def test_akamai_web_digest_rejects_mobile_bmp_interpretation() -> None:
    document = _subtraction(
        {
            "api.Document.cookie.get": 1,
            "api.WorkerGlobalScope.fetch": 1,
        }
    )
    _set_compact_identity(document, "akamai-bmp-web")

    digest = digest_observation(document)
    text = render_digest(digest)

    assert digest["analysis_boundary"]["kind"] == "web-bot-manager-not-mobile-bmp"
    assert "Akamai browser-script family" in digest["analysis_boundary"][
        "interpretation"
    ]
    assert "analysis boundary  WEB BOT MANAGER NOT MOBILE BMP" in text
    assert "mobile BMP request-header contract" in text


def test_akamai_sbsd_digest_rejects_mobile_bmp_interpretation() -> None:
    document = _subtraction(
        {
            "api.CanvasRenderingContext2D.toDataURL": 1,
            "api.SpeechSynthesis.getVoices": 1,
        }
    )
    _set_compact_identity(document, "akamai-sbsd-web")

    digest = digest_observation(document)
    text = render_digest(digest)

    assert digest["analysis_boundary"]["kind"] == "web-bot-manager-not-mobile-bmp"
    assert "complete SBSD marker cluster" in digest["analysis_boundary"][
        "interpretation"
    ]
    assert "analysis boundary  WEB BOT MANAGER NOT MOBILE BMP" in text
    assert "does not make SBSD equivalent" in text


def test_render_digest_rejects_an_edited_vm_boundary_without_echoing_it() -> None:
    document = _subtraction({"api.Window.fetch": 1})
    _set_compact_identity(document, "kasada")
    digest = digest_observation(document)
    digest["analysis_boundary"]["interpretation"] = "PRIVATE-TENANT\nINJECTION"

    with pytest.raises(ContractError, match="analysis boundary is invalid") as exc:
        render_digest(digest)

    assert "PRIVATE-TENANT" not in str(exc.value)


def test_diff_carries_drift_caveat():
    doc = _subtraction({"api.Navigator.a": 1})
    joined = " ".join(diff_digests(doc, doc)["non_claims"]).lower()
    assert "drift" in joined


# --------------------------------------------------------------------------
# amplified names (present in the control, but called far more by the script)
# --------------------------------------------------------------------------


def _subtraction_with_elevated(
    introduced: dict[str, int], elevated: dict[str, tuple[int, int]]
) -> dict:
    doc = _subtraction(introduced)
    doc["elevated_in_arm"] = {
        k: {"arm": a, "control": c} for k, (a, c) in elevated.items()
    }
    return doc


def test_amplified_names_are_counted_separately_from_introduced():
    digest = digest_observation(
        _subtraction_with_elevated(
            {"api.AnalyserNode.fftSize.get": 1},
            {"api.Performance.now": (127, 1)},
        )
    )
    assert digest["total_api_names"] == 1
    assert digest["amplified_api_names"] == 1
    # introduced count is unchanged by amplification
    assert digest["techniques"]["audio-graph"]["api_names"] == 1
    assert digest["techniques"]["audio-graph"]["amplified"] == 0


def test_technique_reached_only_by_amplification_is_not_reported_as_unobserved():
    """The defect this guards: reading introduced names alone reported the main
    sensor as touching no screen-display at all, when `MediaQueryList.matches`
    is elevated in 35 of 35 measured arms."""
    digest = digest_observation(
        _subtraction_with_elevated(
            {"api.AnalyserNode.fftSize.get": 1},
            {"api.MediaQueryList.matches.get": (5, 2)},
        )
    )
    assert "screen-display" not in digest["not_observed"]
    assert digest["amplified_only_techniques"]["screen-display"] == 1


def test_amplified_within_an_observed_technique_shows_in_that_row():
    digest = digest_observation(
        _subtraction_with_elevated(
            {"api.Performance.mark": 1},
            {"api.Performance.now": (127, 1)},
        )
    )
    assert digest["techniques"]["timing"]["amplified"] == 1
    assert "timing" not in digest.get("amplified_only_techniques", {})


def test_raw_observations_have_no_amplified_names():
    """Amplification is only meaningful against a control, which a raw surface
    has not been compared to."""
    digest = digest_observation(_observation({"api.Performance.now": 127}))
    assert digest["amplified_api_names"] == 0


def test_non_api_elevated_entries_are_ignored():
    digest = digest_observation(
        _subtraction_with_elevated(
            {"api.Navigator.a": 1}, {"execution.script.run": (6, 3)}
        )
    )
    assert digest["amplified_api_names"] == 0


def test_render_marks_amplified_only_techniques():
    text = render_digest(
        digest_observation(
            _subtraction_with_elevated(
                {"api.Navigator.a": 1}, {"api.MediaQueryList.matches.get": (5, 2)}
            )
        )
    )
    assert "amplified only" in text
    assert "screen-display" in text


def test_render_omits_amplified_section_when_there_is_none():
    text = render_digest(digest_observation(_subtraction({"api.Navigator.a": 1})))
    assert "amplified only" not in text


# --------------------------------------------------------------------------
# corpus matrix
# --------------------------------------------------------------------------


from browser_core.observation_digest import (  # noqa: E402
    CORPUS_SCHEMA,
    corpus_matrix,
    render_corpus,
)


def _corpus(*specs):
    """specs: (label, {api name: count})"""
    return [(label, _subtraction(names, label=label)) for label, names in specs]


def test_corpus_groups_by_the_supplied_callable():
    docs = _corpus(
        ("sbsd-a", {"api.AnalyserNode.a": 1}),
        ("main-a", {"api.Navigator.a": 1}),
    )
    matrix = corpus_matrix(
        docs, group_of=lambda label: "sbsd" if "sbsd" in label else "main"
    )
    assert set(matrix["groups"]) == {"sbsd", "main"}
    assert matrix["groups"]["sbsd"]["arms"] == 1
    assert matrix["arms"] == 2


def test_corpus_defaults_to_a_single_group():
    matrix = corpus_matrix(_corpus(("a", {"api.Navigator.a": 1})))
    assert list(matrix["groups"]) == ["all"]


def test_corpus_reports_presence_and_spread():
    docs = _corpus(
        ("a", {"api.AnalyserNode.x": 1, "api.AnalyserNode.y": 1}),
        ("b", {"api.AnalyserNode.x": 1}),
        ("c", {"api.Navigator.x": 1}),
    )
    audio = corpus_matrix(docs)["groups"]["all"]["techniques"]["audio-graph"]
    assert audio["present_in_arms"] == 2
    assert audio["total_arms"] == 3
    assert audio["min_introduced"] == 0  # arm c introduced none
    assert audio["max_introduced"] == 2
    assert audio["varies"] is True


def test_corpus_marks_a_fixed_technique_as_not_varying():
    docs = _corpus(("a", {"api.Navigator.x": 1}), ("b", {"api.Navigator.x": 1}))
    row = corpus_matrix(docs)["groups"]["all"]["techniques"]["navigator-identity"]
    assert row["varies"] is False


def test_corpus_aggregates_resource_intent_presence_with_honest_denominator():
    a = _subtraction({"api.Navigator.x": 1}, label="a")
    b = _subtraction({"api.Navigator.x": 1}, label="b")
    c = _subtraction({"api.Navigator.x": 1}, label="c")
    shared = _intent("https://shared.example")
    a["resource_intents"] = {
        "status": "ok",
        "only_in_arm": [shared, _intent("https://a-only.example")],
        "only_in_control": [],
    }
    b["resource_intents"] = {
        "status": "ok",
        "only_in_arm": [shared],
        "only_in_control": [],
    }
    c["resource_intents"] = {
        "status": "unverifiable",
        "only_in_arm": [],
        "only_in_control": [],
    }
    matrix = corpus_matrix([("a", a), ("b", b), ("c", c)])
    intents = matrix["resource_intents"]
    assert intents["successful_attributed_arms"] == 2
    assert intents["population_arms"] == 3
    assert intents["population_complete"] is False
    assert intents["rows"][0]["present_in_arms"] == 2
    assert intents["rows"][0]["successful_arms"] == 2
    text = render_corpus(matrix)
    assert "2/3 successful + attributed" in text
    assert "(2/2 arms)" in text
    assert "INCOMPLETE RESOURCE POPULATION" in text


def test_render_corpus_rejects_saved_resource_denominator_and_private_origin():
    a = _subtraction({"api.Navigator.a": 1}, label="a")
    b = _subtraction({"api.Navigator.a": 1}, label="b")
    a["resource_intents"] = {
        "status": "ok", "only_in_arm": [_intent("https://example.test")],
        "only_in_control": [],
    }
    b["resource_intents"] = {
        "status": "unverifiable", "only_in_arm": [], "only_in_control": [],
    }
    documents = [("a", a), ("b", b)]

    matrix = corpus_matrix(documents)
    matrix["resource_intents"]["population_complete"] = True
    with pytest.raises(ContractError, match="rendered corpus"):
        render_corpus(matrix)

    matrix = corpus_matrix(documents)
    matrix["resource_intents"]["rows"][0]["successful_arms"] = 0
    with pytest.raises(ContractError, match="rendered corpus"):
        render_corpus(matrix)

    matrix = corpus_matrix(documents)
    matrix["resource_intents"]["rows"][0]["intent"]["origin"] = (
        "https://example.test/private-route?token=secret"
    )
    with pytest.raises(ContractError, match="rendered corpus"):
        render_corpus(matrix)

    matrix = corpus_matrix(documents)
    matrix["resource_intents"] = None
    with pytest.raises(ContractError, match="rendered corpus"):
        render_corpus(matrix)


def test_legacy_corpus_without_resource_contract_does_not_add_empty_section():
    matrix = corpus_matrix(_corpus(("a", {"api.Navigator.x": 1})))
    assert matrix["resource_intents"] is None
    assert "resource intent snapshots" not in render_corpus(matrix)


def test_corpus_skips_undigestible_documents_loudly():
    """A shrinking denominator is how a corpus claim quietly becomes wrong."""
    docs = _corpus(("good", {"api.Navigator.a": 1}))
    docs.append(("broken", {"schema": OBSERVATION_SCHEMA, "label": "broken"}))
    matrix = corpus_matrix(docs)
    assert matrix["arms"] == 1
    assert len(matrix["skipped"]) == 1
    assert matrix["skipped"][0]["label"] == "broken"
    assert matrix["skipped"][0]["reason"].startswith("contract-failure;")
    assert "SKIPPED" in render_corpus(matrix)


def test_corpus_per_technique_view_still_reports_skipped_documents():
    good = _subtraction({"api.Navigator.a": 1})
    broken = {"schema": OBSERVATION_SCHEMA, "label": "broken"}
    matrix = corpus_matrix(
        [("good", good), ("broken", broken)], technique="navigator-identity"
    )
    assert "SKIPPED 1" in render_corpus(matrix)


def test_corpus_marks_unready_and_raw_surfaces_as_descriptive_only():
    ready = _subtraction({"api.Navigator.a": 1})
    unready = _subtraction({"api.Navigator.b": 1})
    unready["surface_claim_ready"] = False
    raw = _observation({"api.Navigator.c": 1})
    matrix = corpus_matrix(
        [("ready", ready), ("unready", unready), ("raw", raw)],
        technique="navigator-identity",
    )
    assert matrix["arms"] == 3
    assert matrix["unready_arms"] == ["unready"]
    assert matrix["raw_surfaces_included"] == ["raw"]
    rendered = render_corpus(matrix)
    assert "UNREADY" in rendered
    assert "NOT ATTRIBUTED" in rendered


def test_corpus_distinct_pins_use_only_the_accepted_arm_population():
    good = _subtraction({"api.Navigator.a": 1}, label="good")
    broken = {
        "schema": "private-secret-schema",
        "arm_script_sha256_16": "a" * 16,
    }
    matrix = corpus_matrix([("good", good), ("broken", broken)])
    assert matrix["arms"] == 1
    assert matrix["observed_pins"] == ["fedcba9876543210"]
    assert matrix["distinct_pins"] == 1
    assert "private-secret" not in matrix["skipped"][0]["reason"]


def test_corpus_rejects_duplicate_labels_before_digesting():
    document = _subtraction({"api.Navigator.a": 1})
    with pytest.raises(ContractError, match="labels must be unique"):
        corpus_matrix([("same", document), ("same", document)])


@pytest.mark.parametrize("group", [None, 7, "bad\ngroup", "x" * 257])
def test_corpus_rejects_invalid_group_identity(group: object):
    with pytest.raises(ContractError, match="corpus group"):
        corpus_matrix(
            _corpus(("a", {"api.Navigator.a": 1})),
            group_of=lambda _label: group,
        )


def test_corpus_caps_the_arm_population_before_digesting():
    documents = [(f"arm-{index}", {}) for index in range(4097)]
    with pytest.raises(ContractError, match="population"):
        corpus_matrix(documents)


def test_corpus_technique_detail_lists_every_arm():
    docs = _corpus(
        ("hi", {f"api.AnalyserNode.n{i}": 1 for i in range(5)}),
        ("lo", {"api.AnalyserNode.n0": 1}),
    )
    detail = corpus_matrix(docs, technique="audio-graph")["technique_detail"]
    assert [r["label"] for r in detail["per_arm"]] == ["hi", "lo"]
    assert detail["distinct_values"] == [1, 5]


def test_corpus_flags_a_two_valued_split_as_bimodal():
    docs = _corpus(
        *[
            (f"hi{i}", {f"api.AnalyserNode.n{j}": 1 for j in range(5)})
            for i in range(3)
        ],
        *[(f"lo{i}", {"api.AnalyserNode.n0": 1}) for i in range(3)],
    )
    detail = corpus_matrix(docs, technique="audio-graph")["technique_detail"]
    assert detail["looks_bimodal"] is True
    rendered = render_corpus(corpus_matrix(docs, technique="audio-graph"))
    assert "BIMODAL" in rendered
    assert "switch, not a dial" not in rendered


def test_corpus_does_not_call_one_outlier_bimodal():
    docs = _corpus(
        *[(f"lo{i}", {"api.AnalyserNode.n0": 1}) for i in range(4)],
        ("outlier", {f"api.AnalyserNode.n{i}": 1 for i in range(5)}),
    )
    detail = corpus_matrix(docs, technique="audio-graph")["technique_detail"]
    assert detail["distinct_values"] == [1, 5]
    assert detail["looks_bimodal"] is False


def test_corpus_does_not_claim_bimodal_for_a_spread():
    docs = _corpus(
        *[
            (f"a{i}", {f"api.AnalyserNode.n{j}": 1 for j in range(i + 1)})
            for i in range(5)
        ]
    )
    detail = corpus_matrix(docs, technique="audio-graph")["technique_detail"]
    assert detail["looks_bimodal"] is False


def test_corpus_does_not_claim_bimodal_on_a_tiny_sample():
    docs = _corpus(
        ("hi", {"api.AnalyserNode.a": 1, "api.AnalyserNode.b": 1}),
        ("lo", {"api.AnalyserNode.a": 1}),
    )
    assert (
        corpus_matrix(docs, technique="audio-graph")["technique_detail"][
            "looks_bimodal"
        ]
        is False
    )


def test_render_corpus_rejects_saved_shape_contradictions():
    docs = _corpus(
        *[(f"lo{i}", {"api.AnalyserNode.n0": 1}) for i in range(4)],
        ("outlier", {f"api.AnalyserNode.n{i}": 1 for i in range(5)}),
    )
    matrix = corpus_matrix(docs, technique="audio-graph")
    matrix["technique_detail"]["looks_bimodal"] = True
    with pytest.raises(ContractError, match="rendered corpus"):
        render_corpus(matrix)

    matrix = corpus_matrix(docs, technique="audio-graph")
    matrix["technique_detail"]["distinct_values"] = [1]
    with pytest.raises(ContractError, match="rendered corpus"):
        render_corpus(matrix)


def test_render_corpus_rejects_saved_group_and_arm_count_contradictions():
    matrix = corpus_matrix(
        _corpus(("a", {"api.AnalyserNode.a": 1}),
                ("b", {"api.AnalyserNode.b": 1})),
        technique="audio-graph",
    )
    matrix["groups"]["all"]["arms"] = 3
    with pytest.raises(ContractError, match="rendered corpus"):
        render_corpus(matrix)

    matrix = corpus_matrix(_corpus(("a", {"api.AnalyserNode.a": 1})),
                           technique="audio-graph")
    matrix["technique_detail"]["per_arm"][0]["label"] = "a\nFORGED CLEAN CORPUS"
    with pytest.raises(ContractError, match="rendered corpus"):
        render_corpus(matrix)


def test_render_corpus_accepts_saved_technique_detail_round_trip():
    matrix = corpus_matrix(
        _corpus(("a", {"api.AnalyserNode.a": 1}),
                ("b", {"api.AnalyserNode.b": 1})),
        technique="audio-graph",
    )
    assert "audio-graph per arm" in render_corpus(json.loads(json.dumps(matrix)))


def test_render_corpus_rejects_saved_method_and_pin_contradictions():
    docs = _corpus(("a", {"api.Navigator.a": 1}),
                   ("b", {"api.Navigator.b": 1}))
    docs[1][1]["arm_headed"] = False
    matrix = corpus_matrix(docs)
    assert matrix["method_population"]["mixed_axes"] == ["headed"]
    matrix["method_population"]["mixed_axes"] = []
    with pytest.raises(ContractError, match="rendered corpus"):
        render_corpus(matrix)

    matrix = corpus_matrix(docs)
    matrix["distinct_pins"] += 1
    with pytest.raises(ContractError, match="rendered corpus"):
        render_corpus(matrix)


def test_render_corpus_rejects_saved_trust_and_skipped_label_contradictions():
    matrix = corpus_matrix([("bad", {})])
    matrix["trustworthy_population"] = True
    with pytest.raises(ContractError, match="rendered corpus"):
        render_corpus(matrix)

    matrix = corpus_matrix([("bad", {})])
    matrix["skipped"][0]["label"] = "bad\nFORGED CLEAN CORPUS"
    with pytest.raises(ContractError, match="rendered corpus"):
        render_corpus(matrix)


def test_render_corpus_rejects_saved_technique_table_contradictions():
    docs = _corpus(
        ("a", {"api.AnalyserNode.a": 1, "api.AnalyserNode.b": 1}),
        ("b", {"api.AnalyserNode.a": 1}),
    )
    matrix = corpus_matrix(docs)
    row = matrix["groups"]["all"]["techniques"]["audio-graph"]
    assert row["varies"] is True
    row["varies"] = False
    with pytest.raises(ContractError, match="rendered corpus"):
        render_corpus(matrix)

    matrix = corpus_matrix(docs)
    matrix["groups"]["all"]["techniques"]["audio-graph"]["total_arms"] = 3
    with pytest.raises(ContractError, match="rendered corpus"):
        render_corpus(matrix)

    matrix = corpus_matrix(docs)
    matrix["groups"]["all"]["techniques"]["\nFORGED CLEAN CORPUS"] = {}
    with pytest.raises(ContractError, match="rendered corpus"):
        render_corpus(matrix)


def test_corpus_rejects_an_unknown_technique():
    with pytest.raises(ContractError):
        corpus_matrix(_corpus(("a", {"api.Navigator.a": 1})), technique="nope")


def test_corpus_declares_its_schema_and_caveats():
    matrix = corpus_matrix(_corpus(("a", {"api.Navigator.a": 1})))
    assert matrix["schema"] == CORPUS_SCHEMA
    joined = " ".join(matrix["non_claims"]).lower()
    assert "hide per-arm structure" in joined
    assert "supplied by the caller" in joined


def test_corpus_flags_a_mixed_execution_method():
    docs = _corpus(
        ("plain", {"api.Navigator.a": 1}),
        ("driven", {"api.Navigator.a": 1}),
    )
    docs[1][1]["arm_driver"] = {
        "supplied": True,
        "bytes": 10,
        "sha256_16": "1" * 16,
    }
    docs[1][1]["arm_driver_supplied"] = True
    matrix = corpus_matrix(docs)
    assert matrix["method_population"]["same_method"] is False
    assert matrix["method_population"]["mixed_axes"] == [
        "driver",
        "driver_supplied",
    ]
    assert "MIXED METHOD" in render_corpus(matrix)


def test_render_corpus_output_stays_bounded():
    docs = _corpus(
        *[
            (f"arm{i}", {f"api.HTMLElement.p{j}.get": 1 for j in range(500)})
            for i in range(40)
        ]
    )
    text = render_corpus(corpus_matrix(docs))
    assert len(text) < 3000, f"corpus render grew to {len(text)} chars"


def test_render_corpus_rejects_a_foreign_schema():
    with pytest.raises(ContractError):
        render_corpus({"schema": "nope/1"})


# --------------------------------------------------------------------------
# absence-claim checker
# --------------------------------------------------------------------------


from browser_core.observation_digest import (  # noqa: E402
    CLAIM_SCHEMA,
    METHOD_BLIND,
    MIN_ARMS_FOR_ABSENCE,
    check_absence_claim,
    render_claim,
)


def _arms(n: int, names: dict[str, int]):
    return [(f"arm{i}", _subtraction(names, label=f"arm{i}")) for i in range(n)]


def test_absence_is_refuted_when_the_technique_appears():
    docs = _arms(4, {"api.AnalyserNode.a": 1})
    result = check_absence_claim(docs, "audio-graph")
    assert result["verdict"] == "REFUTED"
    assert len(result["present_in"]) == 4


def test_absence_is_supported_for_an_observable_technique():
    docs = _arms(5, {"api.Navigator.a": 1})
    result = check_absence_claim(docs, "webrtc")
    assert result["verdict"] == "SUPPORTED"
    assert result["attributed_arms_checked"] == 5


@pytest.mark.parametrize(
    ("clean_subtraction", "surface_claim_ready"),
    [(False, None), (True, False), (True, "true"), (False, True)],
)
def test_absence_does_not_count_subtractions_that_cannot_support_claims(
    clean_subtraction, surface_claim_ready,
):
    docs = _arms(3, {"api.Navigator.a": 1})
    for _, document in docs:
        document["clean_subtraction"] = clean_subtraction
        if surface_claim_ready is not None:
            document["surface_claim_ready"] = surface_claim_ready
    result = check_absence_claim(docs, "webrtc")
    assert result["verdict"] == "UNVERIFIABLE"
    assert result["attributed_arms_checked"] == 0
    assert result["failed_arms"] == []
    assert result["unready_arms"] == [label for label, _ in docs]
    assert "not claim-ready" in result["rationale"]
    assert "UNREADY" in render_claim(result)


def test_absence_separates_failed_and_unready_arms():
    docs = _arms(3, {"api.Navigator.a": 1})
    unready = _subtraction({"api.Navigator.a": 1})
    unready["surface_claim_ready"] = False
    failed = _observation({}, label="dead")
    failed["error"] = "trace export failed"
    result = check_absence_claim(
        [*docs, ("unready.json", unready), ("dead.json", failed)], "webrtc"
    )
    assert result["verdict"] == "UNVERIFIABLE"
    assert result["failed_arms"] == ["dead.json"]
    assert result["unready_arms"] == ["unready.json"]
    assert "produced no data" in result["rationale"]
    assert "not claim-ready" in result["rationale"]
    rendered = render_claim(result)
    assert "FAILED" in rendered and "UNREADY" in rendered


def test_absence_keeps_an_unreadable_file_separate_from_a_failed_capture():
    from browser_core.observation_digest import UNPARSEABLE_JSON_SCHEMA

    documents = _arms(3, {"api.Navigator.a": 1})
    documents.append(("broken.json", {"schema": UNPARSEABLE_JSON_SCHEMA}))
    result = check_absence_claim(documents, "webrtc")
    assert result["verdict"] == "UNVERIFIABLE"
    assert result["failed_arms"] == []
    assert result["unparseable_files"] == ["broken.json"]
    assert "unreadable" in result["rationale"]
    assert "UNPARSEABLE" in render_claim(result)


def test_absence_does_not_label_a_missing_surface_as_unready_data():
    document = {
        "schema": SUBTRACTION_SCHEMA,
        "clean_subtraction": False,
    }
    result = check_absence_claim([("missing.json", document)], "webrtc")
    assert result["verdict"] == "UNVERIFIABLE"
    assert result["failed_arms"] == ["missing.json"]
    assert result["unready_arms"] == []


def test_digest_warns_when_clean_subtraction_is_not_claim_ready():
    document = _subtraction({"api.Navigator.a": 1})
    document["surface_claim_ready"] = False
    digest = digest_observation(document)
    assert digest["clean_subtraction"] is True
    assert digest["surface_claim_ready"] is False
    assert "not claim-ready" in render_digest(digest)


@pytest.mark.parametrize("field", ["clean_subtraction", "surface_claim_ready"])
def test_render_digest_rejects_a_nonboolean_saved_claim_gate(field):
    digest = digest_observation(_subtraction({"api.Navigator.a": 1}))
    digest[field] = "false"
    with pytest.raises(ContractError, match="claim readiness"):
        render_digest(digest)


def test_absence_is_unverifiable_for_a_method_blind_technique():
    """The trap: `input-behaviour` reads identically to a genuine negative.

    An offline rehost has no operator, so these interfaces can never fire.
    Reporting SUPPORTED would launder a method limitation into a finding.
    """
    docs = _arms(30, {"api.Navigator.a": 1})
    result = check_absence_claim(docs, "input-behaviour")
    assert result["verdict"] == "UNVERIFIABLE"
    assert result["method_blind"] is True
    assert "no operator" in result["rationale"]


def test_a_method_blind_technique_is_still_refutable_by_evidence():
    """Blindness only affects absence. If it somehow *did* fire, that is real."""
    docs = _arms(4, {"api.MouseEvent.clientX.get": 1})
    result = check_absence_claim(docs, "input-behaviour")
    assert result["verdict"] == "REFUTED"


def test_absence_needs_a_minimum_number_of_arms():
    docs = _arms(MIN_ARMS_FOR_ABSENCE - 1, {"api.Navigator.a": 1})
    result = check_absence_claim(docs, "webrtc")
    assert result["verdict"] == "UNVERIFIABLE"
    assert "at least" in result["rationale"]


def test_raw_surfaces_are_rejected_not_counted():
    docs = [
        (f"raw-{index}", _observation({"api.Navigator.a": 1})) for index in range(9)
    ]
    docs += _arms(3, {"api.Navigator.a": 1})
    result = check_absence_claim(docs, "webrtc")
    assert result["attributed_arms_checked"] == 3
    assert len(result["raw_surfaces_rejected"]) == 9
    assert "rejected 9 raw surface" in render_claim(result)


def test_a_corpus_of_only_raw_surfaces_cannot_support_absence():
    docs = [
        (f"raw-{index}", _observation({"api.Navigator.a": 1})) for index in range(20)
    ]
    result = check_absence_claim(docs, "webrtc")
    assert result["verdict"] == "UNVERIFIABLE"
    assert result["attributed_arms_checked"] == 0


def test_absence_is_unverifiable_across_mixed_execution_methods():
    docs = _arms(4, {"api.Navigator.a": 1})
    docs[-1][1]["arm_input_profile"] = "mouse-line"
    result = check_absence_claim(docs, "webrtc")
    assert result["verdict"] == "UNVERIFIABLE"
    assert result["method_population"]["mixed_axes"] == ["input_profile"]
    assert "mixed population" in render_claim(result)


def test_mixed_methods_do_not_hide_positive_refutation():
    docs = _arms(4, {"api.AnalyserNode.a": 1})
    docs[-1][1]["arm_input_profile"] = "mouse-line"
    result = check_absence_claim(docs, "audio-graph")
    assert result["verdict"] == "REFUTED"
    assert result["method_population"]["mixed_axes"] == ["input_profile"]


def test_failed_arm_makes_an_otherwise_supported_absence_unverifiable():
    docs = _arms(4, {"api.Navigator.a": 1})
    failed = _observation({}, label="dead")
    failed["error"] = "trace export failed"
    result = check_absence_claim([*docs, ("dead.json", failed)], "webrtc")
    assert result["verdict"] == "UNVERIFIABLE"
    assert result["failed_arms"] == ["dead.json"]
    assert "failed arm is not a negative" in result["rationale"]
    assert "FAILED" in render_claim(result)


def test_failed_arm_does_not_hide_positive_absence_refutation():
    docs = _arms(3, {"api.AnalyserNode.a": 1})
    failed = _observation({}, label="dead")
    failed["error"] = "trace export failed"
    result = check_absence_claim([*docs, ("dead.json", failed)], "audio-graph")
    assert result["verdict"] == "REFUTED"
    assert result["failed_arms"] == ["dead.json"]


def test_amplified_only_presence_still_refutes_absence():
    """A technique reached only by amplification is still used."""
    doc = _subtraction({"api.Navigator.a": 1})
    doc["elevated_in_arm"] = {
        "api.MediaQueryList.matches.get": {"arm": 5, "control": 2}
    }
    result = check_absence_claim(
        [(f"a-{index}", doc) for index in range(4)], "screen-display"
    )
    assert result["verdict"] == "REFUTED"
    assert result["present_in"][0]["amplified"] == 1


def test_method_limited_techniques_carry_a_caveat_but_can_be_supported():
    docs = _arms(5, {"api.Navigator.a": 1})
    result = check_absence_claim(docs, "network-transport")
    assert result["verdict"] == "SUPPORTED"
    assert result["method_limited"]
    assert "CAVEAT" in render_claim(result)


def test_unknown_technique_is_rejected():
    with pytest.raises(ContractError):
        check_absence_claim(_arms(3, {}), "not-a-technique")


def test_absence_claim_rejects_empty_duplicate_or_malformed_population_entries():
    doc = _subtraction({"api.Navigator.a": 1})
    with pytest.raises(ContractError, match="population"):
        check_absence_claim([], "webrtc")
    with pytest.raises(ContractError, match="unique"):
        check_absence_claim([("same", doc), ("same", doc)], "webrtc")
    with pytest.raises(ContractError, match="entry"):
        check_absence_claim([["not", "a tuple"]], "webrtc")


def test_malformed_subtraction_weakens_instead_of_aborting_absence_claim():
    docs = _arms(3, {"api.Navigator.a": 1})
    malformed = _subtraction({"api.Navigator.a": 1})
    malformed["only_in_arm"]["api.Navigator.a"] = "1"
    result = check_absence_claim([*docs, ("malformed", malformed)], "webrtc")
    assert result["verdict"] == "UNVERIFIABLE"
    assert result["attributed_arms_checked"] == 3
    assert result["failed_arms"] == ["malformed"]


def test_foreign_schema_is_a_failed_arm_not_a_raw_observation():
    result = check_absence_claim([("foreign", {"schema": "private-schema"})], "webrtc")
    assert result["verdict"] == "UNVERIFIABLE"
    assert result["failed_arms"] == ["foreign"]
    assert result["raw_surfaces_rejected"] == []


def test_claim_result_declares_schema_and_scoping_non_claim():
    result = check_absence_claim(_arms(4, {"api.Navigator.a": 1}), "webrtc")
    assert result["schema"] == CLAIM_SCHEMA
    joined = " ".join(result["non_claims"]).lower()
    assert "not absent from the product" in joined


def test_every_method_blind_entry_names_a_real_technique():
    for technique in METHOD_BLIND:
        assert technique in TECHNIQUES


def test_render_claim_rejects_a_foreign_schema():
    with pytest.raises(ContractError):
        render_claim({"schema": "nope/1"})


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("failed_arms", ["missing-arm"]),
        ("unparseable_files", ["missing-file"]),
        ("rationale", "absent\nVERDICT  SUPPORTED"),
        ("claim", "the collector does not use webrtc\nPRIVATE_MARKER"),
        ("method_blind", "false"),
    ],
)
def test_render_claim_rejects_incoherent_saved_negative(field, value):
    result = check_absence_claim(_arms(3, {"api.Navigator.a": 1}), "webrtc")
    result[field] = value
    with pytest.raises(ContractError, match="rendered claim"):
        render_claim(result)


@pytest.mark.parametrize("method_population", [None, {"arms": True, "mixed_axes": []}])
def test_render_claim_requires_valid_method_population(method_population):
    result = check_absence_claim(_arms(3, {"api.Navigator.a": 1}), "webrtc")
    if method_population is None:
        result.pop("method_population")
    else:
        result["method_population"] = method_population
    with pytest.raises(ContractError, match="method population"):
        render_claim(result)


def test_render_claim_rejects_cotampered_mixed_method_absence():
    homogeneous = check_absence_claim(_arms(5, {"api.Navigator.a": 1}), "webrtc")
    docs = _arms(5, {"api.Navigator.a": 1})
    docs[-1][1]["arm_input_profile"] = "mouse-line"
    mixed = check_absence_claim(docs, "webrtc")
    assert homogeneous["verdict"] == "SUPPORTED"
    assert mixed["verdict"] == "UNVERIFIABLE"
    mixed["method_population"]["mixed_axes"] = []
    mixed["verdict"] = homogeneous["verdict"]
    mixed["rationale"] = homogeneous["rationale"]
    with pytest.raises(ContractError, match="method population"):
        render_claim(mixed)


# --------------------------------------------------------------------------
# script provenance
# --------------------------------------------------------------------------


from browser_core.script_provenance import (  # noqa: E402
    PROVENANCE_SCHEMA,
    describe_provenance,
    index_capture_manifests,
    render_provenance,
    script_pin,
)


def _capture_tree(tmp_path, captures):
    """captures: {name: (site, [(filename, bytes, url|None)])}"""
    root = tmp_path / "captures"
    for name, (site, files) in captures.items():
        d = root / name / "scripts"
        d.mkdir(parents=True)
        hits = []
        for fn, payload, url in files:
            (d / fn).write_bytes(payload)
            if url is not None:
                import hashlib

                hits.append(
                    {
                        "url": url,
                        "sha256": hashlib.sha256(payload).hexdigest(),
                        "len": len(payload),
                    }
                )
        if site is not None:
            (root / name / "capture-summary.json").write_text(
                json.dumps({"site": site, "script_hits": hits}), encoding="utf-8"
            )
    return root


def test_provenance_is_verified_when_a_manifest_records_the_bytes(tmp_path):
    payload = b"x" * 500
    root = _capture_tree(
        tmp_path, {"cap-a": ("fedex", [("s.js", payload, "https://www.fedex.com/x")])}
    )
    result = describe_provenance(root / "cap-a" / "scripts" / "s.js", root)
    assert result["verdict"] == "VERIFIED"
    assert result["recorded_hosts"] == ["www.fedex.com"]
    assert result["recorded_sites"] == ["fedex"]


def test_capture_manifest_empty_fragment_cannot_establish_script_origin(tmp_path):
    payload = b"x" * 500
    root = _capture_tree(
        tmp_path,
        {
            "fragmented": (
                "example",
                [("s.js", payload, "https://example.test/s.js#")],
            ),
            "plain": (
                "example",
                [("other.js", b"y" * 500, "https://example.test/other.js")],
            ),
        },
    )

    assert describe_provenance(
        root / "fragmented" / "scripts" / "s.js", root
    )["verdict"] == "UNVERIFIED"
    assert describe_provenance(
        root / "plain" / "scripts" / "other.js", root
    )["verdict"] == "VERIFIED"


def test_provenance_is_unverified_without_a_manifest(tmp_path):
    root = _capture_tree(tmp_path, {"cap-a": (None, [("s.js", b"y" * 500, None)])})
    result = describe_provenance(root / "cap-a" / "scripts" / "s.js", root)
    assert result["verdict"] == "UNVERIFIED"
    assert "directory naming" in result["rationale"]


def test_capture_index_rejects_invalid_root_path_cleanly():
    with pytest.raises(ContractError, match="captures root path is invalid"):
        index_capture_manifests(Path("invalid\x00root"))


def test_retained_provenance_rejects_invalid_script_label(tmp_path):
    root = _capture_tree(tmp_path, {"cap": (None, [("s.js", b"x", None)])})

    with pytest.raises(ContractError, match="provenance script label is invalid"):
        describe_provenance(Path("invalid\x00script.js"), root, payload=b"x")


def test_directory_disagreement_is_flagged(tmp_path):
    """The real defect: a script served by site B sitting in site A's directory.

    Measured 2026-08-06 in this monorepo -- `5323ff0ae7525aab` is recorded as
    fetched from www.homedepot.com and is physically present in two FedEx
    capture directories.
    """
    payload = b"z" * 500
    root = _capture_tree(
        tmp_path,
        {
            "cap-hd": ("homedepot", [("s.js", payload, "https://www.homedepot.com/x")]),
            "cap-fx": ("fedex", []),
        },
    )
    # place the same bytes in the FedEx directory without a manifest entry
    (root / "cap-fx" / "scripts").mkdir(parents=True, exist_ok=True)
    (root / "cap-fx" / "scripts" / "copy.js").write_bytes(payload)

    result = describe_provenance(root / "cap-fx" / "scripts" / "copy.js", root)
    assert result["verdict"] == "VERIFIED"
    assert result["recorded_hosts"] == ["www.homedepot.com"]
    assert result["directory_disagrees_with_manifest"] is True
    assert "do not read the directory name as a site" in render_provenance(result)


def test_asserted_label_is_echoed_and_marked_unverified(tmp_path):
    root = _capture_tree(tmp_path, {"cap-a": (None, [("s.js", b"q" * 500, None)])})
    result = describe_provenance(
        root / "cap-a" / "scripts" / "s.js", root, asserted_label="fedex"
    )
    assert result["asserted_label"] == "fedex"
    assert result["asserted_label_is_unverified"] is True
    assert "NOT verified" in render_provenance(result)


def test_manifest_coverage_is_reported(tmp_path):
    root = _capture_tree(
        tmp_path,
        {
            "with": ("fedex", [("a.js", b"a" * 500, "https://www.fedex.com/a")]),
            "without-1": (None, [("b.js", b"b" * 500, None)]),
            "without-2": (None, [("c.js", b"c" * 500, None)]),
        },
    )
    built = index_capture_manifests(root)
    assert built["captures_with_manifest"] == 1
    assert len(built["captures_without_manifest"]) == 2


def test_unreadable_manifest_is_counted_not_crashed(tmp_path):
    root = tmp_path / "captures"
    (root / "broken").mkdir(parents=True)
    (root / "broken" / "capture-summary.json").write_text("{not json", encoding="utf-8")
    built = index_capture_manifests(root)
    assert built["captures_with_manifest"] == 0
    assert "unreadable" in built["captures_without_manifest"][0]


@pytest.mark.parametrize(
    "document",
    [{"site": "claimed"}, {"site": "claimed", "script_hits": None}],
)
def test_manifest_without_script_hit_population_is_unreadable(tmp_path, document):
    root = tmp_path / "captures"
    capture = root / "cap"
    capture.mkdir(parents=True)
    (capture / "capture-summary.json").write_text(
        json.dumps(document), encoding="utf-8"
    )

    built = index_capture_manifests(root)

    assert built["captures_with_manifest"] == 0
    assert built["captures_without_manifest"] == ["cap (unreadable)"]


def test_manifest_with_explicit_empty_script_hit_population_is_counted(tmp_path):
    root = tmp_path / "captures"
    capture = root / "cap"
    capture.mkdir(parents=True)
    (capture / "capture-summary.json").write_text(
        json.dumps({"site": "claimed", "script_hits": []}), encoding="utf-8"
    )

    built = index_capture_manifests(root)

    assert built["captures_with_manifest"] == 1
    assert built["captures_without_manifest"] == []


def test_duplicate_manifest_members_cannot_establish_provenance(tmp_path):
    root = tmp_path / "captures"
    capture = root / "cap"
    capture.mkdir(parents=True)
    (capture / "capture-summary.json").write_text(
        '{"script_hits":[],"script_hits":[{"url":"https://private.invalid",'
        '"sha256":"0000000000000000000000000000000000000000000000000000000000000000"}]}',
        encoding="utf-8",
    )

    built = index_capture_manifests(root)

    assert built["captures_with_manifest"] == 0
    assert built["index"] == {}
    assert built["captures_without_manifest"] == ["cap (unreadable)"]


def test_hard_linked_manifest_is_not_provenance_authority(tmp_path):
    root = _capture_tree(
        tmp_path,
        {"cap": ("example", [("s.js", b"x", "https://example.invalid/s")])},
    )
    manifest = root / "cap" / "capture-summary.json"
    (root / "manifest-alias.json").hardlink_to(manifest)

    with pytest.raises(ContractError, match="hard links"):
        index_capture_manifests(root)


def test_short_manifest_digest_cannot_prove_exact_script_bytes(tmp_path):
    payload = b"prefix-only evidence"
    root = tmp_path / "captures"
    scripts = root / "cap" / "scripts"
    scripts.mkdir(parents=True)
    script = scripts / "s.js"
    script.write_bytes(payload)
    (root / "cap" / "capture-summary.json").write_text(
        json.dumps(
            {
                "site": "example",
                "script_hits": [
                    {
                        "url": "https://example.invalid/s.js",
                        "sha256_16": hashlib.sha256(payload).hexdigest()[:16],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    result = describe_provenance(script, root)

    assert result["verdict"] == "UNVERIFIED"


def test_conflicting_manifest_digests_are_not_interpreted_as_provenance(tmp_path):
    payload = b"conflicting digest evidence"
    root = tmp_path / "captures"
    scripts = root / "cap" / "scripts"
    scripts.mkdir(parents=True)
    script = scripts / "s.js"
    script.write_bytes(payload)
    (root / "cap" / "capture-summary.json").write_text(
        json.dumps(
            {
                "script_hits": [
                    {
                        "url": "https://example.invalid/s.js",
                        "sha256": hashlib.sha256(payload).hexdigest(),
                        "digest": "0" * 64,
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    assert describe_provenance(script, root)["verdict"] == "UNVERIFIED"


@pytest.mark.parametrize(
    "extra",
    [
        {"digest": "not-a-sha256"},
        {"hash": ["not-a-sha256"]},
        {"src": ["https://other.example/s.js"]},
        {"request_url": "https://example.com bad.example/s.js"},
    ],
)
def test_malformed_manifest_alias_cannot_establish_provenance(tmp_path, extra):
    payload = b"manifest alias ambiguity"
    root = _capture_tree(
        tmp_path,
        {"cap": ("example", [("s.js", payload, "https://example.invalid/s.js")])},
    )
    script = root / "cap" / "scripts" / "s.js"
    manifest = root / "cap" / "capture-summary.json"
    document = json.loads(manifest.read_text(encoding="utf-8"))
    document["script_hits"][0].update(extra)
    manifest.write_text(json.dumps(document), encoding="utf-8")

    assert describe_provenance(script, root)["verdict"] == "UNVERIFIED"


@pytest.mark.parametrize(
    "url",
    [
        "https://example.com bad.example/s.js",
        "https://2130706433/s.js",
        "https://127.1/s.js",
        "https://0x7f000001/s.js",
        "https://test.42/s.js",
        "https://faß.example/s.js",
    ],
)
def test_invalid_manifest_origin_hostname_cannot_establish_provenance(tmp_path, url):
    payload = b"invalid origin hostname"
    root = _capture_tree(
        tmp_path,
        {"cap": ("example", [("s.js", payload, url)])},
    )

    result = describe_provenance(root / "cap" / "scripts" / "s.js", root)

    assert result["verdict"] == "UNVERIFIED"


def test_canonical_ipv4_manifest_origin_can_establish_provenance(tmp_path):
    payload = b"canonical IPv4 origin"
    root = _capture_tree(
        tmp_path,
        {"cap": ("example", [("s.js", payload, "https://127.0.0.1/s.js")])},
    )

    result = describe_provenance(root / "cap" / "scripts" / "s.js", root)

    assert result["verdict"] == "VERIFIED"
    assert result["recorded_hosts"] == ["127.0.0.1"]


def test_manifest_provenance_has_a_hard_per_file_byte_limit(
    tmp_path, monkeypatch: pytest.MonkeyPatch
):
    root = _capture_tree(
        tmp_path,
        {"cap": ("example", [("s.js", b"x" * 500, "https://example.invalid/s")])},
    )
    monkeypatch.setattr(script_provenance, "MAX_CAPTURE_MANIFEST_BYTES", 8)

    with pytest.raises(ContractError, match="exceeds"):
        index_capture_manifests(root)


def test_manifest_provenance_caps_capture_directory_inventory(
    tmp_path, monkeypatch: pytest.MonkeyPatch
):
    root = _capture_tree(
        tmp_path,
        {
            "a": (None, [("a.js", b"a", None)]),
            "b": (None, [("b.js", b"b", None)]),
        },
    )
    monkeypatch.setattr(script_provenance, "MAX_CAPTURE_DIRECTORIES", 1)

    with pytest.raises(ContractError, match="inventory exceeds"):
        index_capture_manifests(root)


def test_manifest_mutation_during_index_is_rejected(
    tmp_path, monkeypatch: pytest.MonkeyPatch
):
    payload = b"stable manifest population"
    root = _capture_tree(
        tmp_path,
        {"cap": ("example", [("s.js", payload, "https://example.invalid/s")])},
    )
    manifest = root / "cap" / "capture-summary.json"
    original = script_provenance._read_regular_bytes
    mutated = False

    def mutate_before_final_read(path, **kwargs):
        nonlocal mutated
        if path == manifest and not mutated:
            mutated = True
            manifest.write_text("{}", encoding="utf-8")
        return original(path, **kwargs)

    monkeypatch.setattr(
        script_provenance, "_read_regular_bytes", mutate_before_final_read
    )

    with pytest.raises(ContractError, match="changed during scan"):
        index_capture_manifests(root)


def test_same_byte_manifest_replacement_during_index_is_rejected(
    tmp_path, monkeypatch: pytest.MonkeyPatch
):
    root = _capture_tree(
        tmp_path,
        {"cap": ("example", [("s.js", b"x", "https://example.invalid/s")])},
    )
    manifest = root / "cap" / "capture-summary.json"
    original_body = manifest.read_bytes()
    original = script_provenance._read_regular_bytes
    replaced = False

    def replace_before_final_read(path, **kwargs):
        nonlocal replaced
        if path == manifest and not replaced:
            replaced = True
            replacement = manifest.with_suffix(".replacement")
            replacement.write_bytes(original_body)
            replacement.replace(manifest)
        return original(path, **kwargs)

    monkeypatch.setattr(
        script_provenance, "_read_regular_bytes", replace_before_final_read
    )

    with pytest.raises(ContractError, match="changed during scan"):
        index_capture_manifests(root)


def test_manifest_appearance_during_index_is_rejected(
    tmp_path, monkeypatch: pytest.MonkeyPatch
):
    root = _capture_tree(tmp_path, {"cap": (None, [("s.js", b"x", None)])})
    manifest = root / "cap" / "capture-summary.json"
    original = script_provenance.read_bounded_control_snapshot_result
    calls = 0

    def publish_after_missing_read(path, **kwargs):
        nonlocal calls
        result = original(path, **kwargs)
        if path == manifest:
            calls += 1
            if calls == 1 and result.state == "missing":
                manifest.write_text("{}", encoding="utf-8")
        return result

    monkeypatch.setattr(
        script_provenance,
        "read_bounded_control_snapshot_result",
        publish_after_missing_read,
    )

    with pytest.raises(ContractError, match="inventory changed"):
        index_capture_manifests(root)


def test_manifest_mutation_after_index_cannot_verify_script_origin(
    tmp_path, monkeypatch: pytest.MonkeyPatch
):
    payload = b"stable script population"
    root = _capture_tree(
        tmp_path,
        {"cap": ("example", [("s.js", payload, "https://example.invalid/s")])},
    )
    manifest = root / "cap" / "capture-summary.json"
    original = script_provenance._capture_script_names
    mutated = False

    def mutate_during_script_scan(scripts):
        nonlocal mutated
        names = original(scripts)
        if not mutated:
            mutated = True
            manifest.write_text(
                json.dumps({"site": "example", "script_hits": []}), encoding="utf-8"
            )
        return names

    monkeypatch.setattr(script_provenance, "_capture_script_names", mutate_during_script_scan)

    with pytest.raises(ContractError, match="manifest index changed"):
        describe_provenance(root / "cap" / "scripts" / "s.js", root)


def test_provenance_rechecks_path_read_script_after_manifest_scan(
    tmp_path, monkeypatch: pytest.MonkeyPatch
):
    payload = b"original captured script"
    root = _capture_tree(
        tmp_path,
        {"cap": ("example", [("s.js", payload, "https://example.invalid/s")])},
    )
    script = root / "cap" / "scripts" / "s.js"
    original = script_provenance._capture_script_names
    changed = False

    def replace_during_script_scan(scripts):
        nonlocal changed
        names = original(scripts)
        if not changed:
            changed = True
            script.write_bytes(b"different script content")
        return names

    monkeypatch.setattr(script_provenance, "_capture_script_names", replace_during_script_scan)
    with pytest.raises(ContractError, match="provenance script changed during scan"):
        describe_provenance(script, root)


def test_provenance_rejects_new_scripts_directory_during_inventory(
    tmp_path, monkeypatch: pytest.MonkeyPatch
):
    payload = b"script inventory population"
    root = _capture_tree(
        tmp_path,
        {"cap-a": ("example", [("s.js", payload, "https://example.invalid/s")])},
    )
    (root / "cap-b").mkdir()
    script = root / "cap-a" / "scripts" / "s.js"
    original = script_provenance._read_regular_bytes
    created = False

    def create_after_inventory(path, **kwargs):
        nonlocal created
        body = original(path, **kwargs)
        if path == script and kwargs.get("label") == "capture script candidate" and not created:
            created = True
            new_scripts = root / "cap-b" / "scripts"
            new_scripts.mkdir()
            (new_scripts / "copy.js").write_bytes(payload)
        return body

    monkeypatch.setattr(script_provenance, "_read_regular_bytes", create_after_inventory)
    with pytest.raises(ContractError, match="capture script inventory changed during scan"):
        describe_provenance(script, root)


def test_describe_provenance_can_bind_the_exact_retained_script_population(tmp_path):
    payload = b"the served population"
    root = _capture_tree(
        tmp_path,
        {"cap": ("example", [("s.js", payload, "https://example.invalid/s")])},
    )
    script = root / "cap" / "scripts" / "s.js"
    script.write_bytes(b"later pathname population")

    result = describe_provenance(script, root, payload=payload)

    assert result["verdict"] == "VERIFIED"
    assert result["script_sha256_16"] == hashlib.sha256(payload).hexdigest()[:16]


def test_script_candidate_scan_has_an_aggregate_byte_limit(
    tmp_path, monkeypatch: pytest.MonkeyPatch
):
    root = _capture_tree(tmp_path, {"cap": (None, [("s.js", b"xx", None)])})
    script = root / "cap" / "scripts" / "s.js"
    monkeypatch.setattr(script_provenance, "MAX_CAPTURE_SCRIPT_TOTAL_BYTES", 1)

    with pytest.raises(ContractError, match="aggregate byte limit"):
        describe_provenance(script, root)


def test_hard_linked_script_candidate_is_not_scanned_as_provenance(tmp_path):
    root = _capture_tree(tmp_path, {"cap": (None, [("s.js", b"xx", None)])})
    script = root / "cap" / "scripts" / "s.js"
    (root / "script-alias.js").hardlink_to(script)

    with pytest.raises(ContractError, match="hard links"):
        describe_provenance(script, root)


def test_provenance_rejects_a_missing_script(tmp_path):
    root = _capture_tree(tmp_path, {"cap": (None, [("s.js", b"s" * 500, None)])})
    with pytest.raises(ContractError):
        describe_provenance(root / "cap" / "scripts" / "nope.js", root)


def test_provenance_rejects_a_non_directory_root(tmp_path):
    f = tmp_path / "file.txt"
    f.write_text("x", encoding="utf-8")
    with pytest.raises(ContractError):
        index_capture_manifests(f)


def test_script_pin_is_the_package_wide_16_char_form():
    import hashlib

    payload = b"hello"
    assert script_pin(payload) == hashlib.sha256(payload).hexdigest()[:16]
    assert len(script_pin(payload)) == 16


def test_script_pin_refuses_mutable_or_coerced_payloads():
    with pytest.raises(ContractError, match="must be bytes"):
        script_pin(bytearray(b"hello"))


def test_provenance_declares_schema_and_non_claims(tmp_path):
    root = _capture_tree(
        tmp_path, {"cap": ("fedex", [("s.js", b"s" * 500, "https://www.fedex.com/s")])}
    )
    result = describe_provenance(root / "cap" / "scripts" / "s.js", root)
    assert result["schema"] == PROVENANCE_SCHEMA
    joined = " ".join(result["non_claims"]).lower()
    assert "never evidence of origin" in joined


def test_render_provenance_rejects_a_foreign_schema():
    private = "private-provenance-schema-marker"
    for document in (
        {"schema": PROVENANCE_SCHEMA},
        {"schema": private},
        "not-an-object",
    ):
        with pytest.raises(ContractError) as failure:
            render_provenance(document)
        assert private not in str(failure.value)


def test_render_provenance_requires_a_coherent_closed_report(tmp_path):
    private = "private-provenance-report-marker"
    payload = b"p" * 500
    root = _capture_tree(
        tmp_path,
        {"cap": ("site", [("s.js", payload, "https://example.test/s.js")])},
    )
    result = describe_provenance(root / "cap" / "scripts" / "s.js", root)
    assert "VERDICT   VERIFIED" in render_provenance(result)

    mutations = (
        {**result, "private": private},
        {**result, "verdict": "UNVERIFIED"},
        {**result, "rationale": private},
        {**result, "recorded_hosts": [private]},
        {
            **result,
            "recorded_hosts": [f"{private} invalid"],
            "rationale": f"a capture manifest records these exact bytes fetched from {private} invalid",
        },
        {**result, "recorded_in_captures": []},
        {**result, "directory_disagrees_with_manifest": True},
        {**result, "asserted_label_is_unverified": True},
        {**result, "captures_with_manifest": True},
        {**result, "captures_with_manifest": 0},
        {**result, "non_claims": [private]},
    )
    for mutation in mutations:
        with pytest.raises(ContractError) as failure:
            render_provenance(mutation)
        assert private not in str(failure.value)


def test_provenance_does_not_promote_invisible_site_controls(tmp_path):
    root = _capture_tree(
        tmp_path,
        {"cap": ("site\u2028VERDICT   UNVERIFIED", [
            ("s.js", b"served bytes", "https://example.test/s.js")
        ])},
    )

    result = describe_provenance(root / "cap" / "scripts" / "s.js", root)

    assert result["verdict"] == "VERIFIED"
    assert result["recorded_sites"] == []
    assert "VERDICT   UNVERIFIED" not in render_provenance(result)


def test_render_provenance_rejects_invisible_saved_labels(tmp_path):
    root = _capture_tree(
        tmp_path,
        {"cap": ("site", [("s.js", b"served bytes", "https://example.test/s.js")])},
    )
    result = describe_provenance(root / "cap" / "scripts" / "s.js", root)

    for change in (
        {"script": "s.js\u2028VERDICT   UNVERIFIED"},
        {"recorded_sites": ["site\u202eVERDICT   UNVERIFIED"]},
        {"sits_in_directories": ["cap\u0085VERDICT   UNVERIFIED"]},
    ):
        with pytest.raises(ContractError, match="rendered script provenance"):
            render_provenance({**result, **change})


# --------------------------------------------------------------------------
# provenance bound into the observation at capture time
# --------------------------------------------------------------------------


from browser_core.product_observation import (  # noqa: E402
    ProductScriptObservation,
    _resolve_provenance,
)


def _config(tmp_path, script, captures_root=None, label="asserted"):
    return ProductScriptObservation(
        script=script,
        label=label,
        executable=tmp_path / "chrome.exe",
        trace_processor=tmp_path / "tp.exe",
        workspace=tmp_path / "ws",
        captures_root=captures_root,
    )


def test_unset_captures_root_records_not_checked_not_a_pass(tmp_path):
    """`not_checked` must not read like a clean bill of health."""
    result = _resolve_provenance(_config(tmp_path, tmp_path / "x.js"))
    assert result["status"] == "not_checked"
    assert result["asserted_label"] == "asserted"
    assert "nothing was consulted" in result["note"]


def test_bound_provenance_reports_verified_origin(tmp_path):
    payload = b"k" * 600
    root = _capture_tree(
        tmp_path, {"cap": ("fedex", [("s.js", payload, "https://www.fedex.com/s")])}
    )
    script = root / "cap" / "scripts" / "s.js"
    result = _resolve_provenance(_config(tmp_path, script, captures_root=root))
    assert result["status"] == "VERIFIED"
    assert result["recorded_hosts"] == ["www.fedex.com"]
    assert result["asserted_label_is_unverified"] is True


def test_bound_provenance_uses_the_retained_observation_population(tmp_path):
    payload = b"retained observation population"
    root = _capture_tree(
        tmp_path, {"cap": ("example", [("s.js", payload, "https://example.invalid/s")])}
    )
    script = root / "cap" / "scripts" / "s.js"
    script.write_bytes(b"replacement pathname population")

    result = _resolve_provenance(
        _config(tmp_path, script, captures_root=root),
        payload,
    )

    assert result["status"] == "VERIFIED"
    assert result["recorded_hosts"] == ["example.invalid"]


def test_bound_provenance_reports_unverified(tmp_path):
    root = _capture_tree(tmp_path, {"cap": (None, [("s.js", b"m" * 600, None)])})
    script = root / "cap" / "scripts" / "s.js"
    result = _resolve_provenance(_config(tmp_path, script, captures_root=root))
    assert result["status"] == "UNVERIFIED"


def test_provenance_failure_never_breaks_the_observation(tmp_path):
    """Provenance is metadata about a run; it must not be able to fail the run."""
    result = _resolve_provenance(
        _config(tmp_path, tmp_path / "missing.js", captures_root=tmp_path / "nope")
    )
    assert result["status"] == "error"
    assert "failed" in result["note"]


def test_digest_surfaces_each_provenance_state():
    for status, expected in (
        ("not_checked", "NOT CHECKED"),
        ("UNVERIFIED", "UNVERIFIED"),
        ("VERIFIED", "VERIFIED"),
    ):
        doc = _observation({"api.Navigator.a": 1})
        doc["provenance"] = {"status": status, "recorded_hosts": ["www.fedex.com"]}
        assert expected in render_digest(digest_observation(doc)), status


def test_digest_warns_when_directory_disagrees_with_manifest():
    doc = _observation({"api.Navigator.a": 1})
    doc["provenance"] = {
        "status": "VERIFIED",
        "recorded_hosts": ["www.homedepot.com"],
        "directory_disagrees_with_manifest": True,
    }
    text = render_digest(digest_observation(doc))
    assert "WARNING" in text and "no manifest" in text


def test_digest_of_an_older_artifact_without_provenance_still_renders():
    """Backward compatibility: artifacts predating this field must still digest."""
    doc = _observation({"api.Navigator.a": 1})
    assert "provenance" not in doc
    text = render_digest(digest_observation(doc))
    assert "origin" not in text.split("\n")[1]


# --------------------------------------------------------------------------
# path-type tolerance and corpus pin coverage
# --------------------------------------------------------------------------


from browser_core.product_observation import (  # noqa: E402
    _seal_subtraction_document,
    load_observation,
    write_observation,
)


def test_load_observation_accepts_a_string_path(tmp_path):
    """A str from `glob.glob` must not raise AttributeError.

    The previous signature took only Path and called `path.read_text()`, so a str
    argument raised an error shaped like a bug in the caller's own code. Combined
    with a broad `except Exception: continue` in a corpus scan on 2026-08-06 it
    silently dropped all 123 documents, and the analysis built on the empty result
    reported every technique as absent -- including ones plainly present.
    """
    p = tmp_path / "obs.json"
    document = _subtraction({"api.Navigator.a": 1})
    _set_compact_identity(document, "akamai-bmp-web")
    write_observation(str(p), _seal_subtraction_document(document))
    assert load_observation(str(p))["schema"] == SUBTRACTION_SCHEMA
    assert load_observation(p)["schema"] == SUBTRACTION_SCHEMA


def test_load_observation_still_rejects_a_foreign_document(tmp_path):
    """Type tolerance must not become content tolerance."""
    p = tmp_path / "x.json"
    p.write_text(json.dumps({"schema": "something-else/1"}), encoding="utf-8")
    with pytest.raises(ContractError):
        load_observation(str(p))


def test_load_observation_raises_on_a_missing_path(tmp_path):
    with pytest.raises(OSError):
        load_observation(str(tmp_path / "nope.json"))


def test_corpus_counts_distinct_pins_not_just_arms():
    """One script under five method controls is five arms and one pin.

    A corpus claim is only as strong as its pin count, so both are reported.
    """
    a = _subtraction({"api.Navigator.a": 1}, label="arm-1")
    b = _subtraction({"api.Navigator.a": 1}, label="arm-2")  # same synthetic pin
    c = _subtraction({"api.Navigator.a": 1}, label="arm-3")
    c["arm_script_sha256_16"] = "aaaaaaaaaaaaaaaa"
    matrix = corpus_matrix([("a", a), ("b", b), ("c", c)])
    assert matrix["arms"] == 3
    assert matrix["distinct_pins"] == 2


def test_corpus_render_reports_pins_in_the_header():
    doc = _subtraction({"api.Navigator.a": 1})
    text = render_corpus(corpus_matrix([("a", doc)]))
    assert "distinct script pins" in text


def test_corpus_render_shows_coverage_when_present():
    doc = _subtraction({"api.Navigator.a": 1})
    matrix = corpus_matrix([("a", doc)])
    matrix["pin_coverage"] = {
        "available": 66,
        "observed": 41,
        "unobserved": 25,
        "percent": 62.1,
    }
    text = render_corpus(matrix)
    assert "41 of 66" in text and "25 unobserved" in text


def test_corpus_render_omits_coverage_when_absent():
    text = render_corpus(corpus_matrix([("a", _subtraction({"api.Navigator.a": 1}))]))
    assert "coverage:" not in text


# --------------------------------------------------------------------------
# cross-deployment comparison warning
# --------------------------------------------------------------------------


def _with_origin(doc, hosts):
    doc = dict(doc)
    doc["provenance"] = {"status": "VERIFIED", "recorded_hosts": list(hosts)}
    return doc


def _with_public_source(doc, url, digest="a" * 64, *, status="verified_digest"):
    doc = dict(doc)
    doc["source_provenance"] = {
        "status": status,
        "source_url": url,
        "retrieved_at": "2026-08-09T05:31:00Z",
        "sha256": digest,
    }
    return doc


def test_diff_flags_a_cross_deployment_comparison():
    """Two rolls and two deployments produce identically-shaped diffs.

    Note 144 measured cross-roll Jaccard at 0.987-0.994 and cross-site at
    0.742-0.753, so the same number means opposite things depending on which
    comparison this is. Carrying a marker from one population to the other
    produced a false ordering claim on 2026-08-06.
    """
    left = _with_origin(_subtraction({"api.Navigator.a": 1}), ["www.fedex.com"])
    right = _with_origin(_subtraction({"api.Navigator.b": 1}), ["www.homedepot.com"])
    diff = diff_digests(left, right)
    assert diff["comparability"]["status"] == "cross-origin"
    assert "CROSS-DEPLOYMENT" in render_digest(diff)


def test_diff_reports_same_origin_when_hosts_match():
    left = _with_origin(_subtraction({"api.Navigator.a": 1}), ["www.fedex.com"])
    right = _with_origin(_subtraction({"api.Navigator.b": 1}), ["www.fedex.com"])
    diff = diff_digests(left, right)
    assert diff["comparability"]["status"] == "same-origin"
    assert "CROSS-DEPLOYMENT" not in render_digest(diff)


def test_render_diff_rejects_saved_same_origin_for_different_hosts():
    left = _with_origin(_subtraction({"api.Navigator.a": 1}), ["www.fedex.com"])
    right = _with_origin(_subtraction({"api.Navigator.b": 1}), ["www.homedepot.com"])
    diff = diff_digests(left, right)
    assert diff["comparability"]["status"] == "cross-origin"
    diff["comparability"]["status"] = "same-origin"
    with pytest.raises(ContractError, match="rendered digest"):
        render_digest(diff)


def test_diff_does_not_promote_hosts_from_unverified_capture():
    left = _subtraction({"api.Navigator.a": 1})
    right = _subtraction({"api.Navigator.b": 1})
    left["provenance"] = {
        "status": "UNVERIFIED",
        "recorded_hosts": ["www.fedex.com"],
    }
    right["provenance"] = {
        "status": "UNVERIFIED",
        "recorded_hosts": ["www.fedex.com"],
    }

    comparison = diff_digests(left, right)["comparability"]

    assert comparison["status"] == "unknown"
    assert comparison["left_hosts"] == []
    assert comparison["right_hosts"] == []


def test_digest_downgrades_verified_capture_without_a_valid_host():
    document = _observation({"api.Navigator.a": 1})
    document["provenance"] = {
        "status": "VERIFIED",
        "recorded_hosts": ["malformed host"],
    }

    provenance = digest_observation(document)["provenance"]

    assert provenance["status"] == "unknown"
    assert provenance["recorded_hosts"] == []


@pytest.mark.parametrize(
    "hosts",
    [
        ["good.test", "malformed host"],
        ["good.test", "good.test"],
        [f"host-{index}.test" for index in range(65)],
    ],
)
def test_digest_downgrades_verified_capture_with_incomplete_host_list(hosts):
    document = _observation({"api.Navigator.a": 1})
    document["provenance"] = {"status": "VERIFIED", "recorded_hosts": hosts}

    provenance = digest_observation(document)["provenance"]

    assert provenance["status"] == "unknown"
    assert provenance["recorded_hosts"] == []


def test_digest_marks_asserted_label_unverified_even_with_verified_origin():
    document = _observation({"api.Navigator.a": 1})
    document["provenance"] = {
        "status": "VERIFIED",
        "recorded_hosts": ["good.test"],
        "asserted_label": "operator-label",
    }

    provenance = digest_observation(document)["provenance"]

    assert provenance["status"] == "VERIFIED"
    assert provenance["asserted_label"] == "operator-label"
    assert provenance["asserted_label_is_unverified"] is True


def test_digest_downgrades_saved_asserted_label_marked_verified():
    document = _observation({"api.Navigator.a": 1})
    document["provenance"] = {
        "status": "VERIFIED",
        "recorded_hosts": ["good.test"],
        "asserted_label": "operator-label",
        "asserted_label_is_unverified": False,
    }

    provenance = digest_observation(document)["provenance"]

    assert provenance["status"] == "unknown"
    assert provenance["recorded_hosts"] == []
    assert provenance["asserted_label_is_unverified"] is True


def test_digest_keeps_verified_origin_without_asserted_label():
    document = _observation({"api.Navigator.a": 1})
    document["provenance"] = {"status": "VERIFIED", "recorded_hosts": ["good.test"]}

    provenance = digest_observation(document)["provenance"]

    assert provenance["status"] == "VERIFIED"
    assert provenance["recorded_hosts"] == ["good.test"]
    assert provenance["asserted_label_is_unverified"] is False


@pytest.mark.parametrize("host", ["2130706433", "127.1", "0x7f000001", "test.42"])
def test_digest_downgrades_ambiguous_numeric_capture_host(host):
    document = _observation({"api.Navigator.a": 1})
    document["provenance"] = {"status": "VERIFIED", "recorded_hosts": [host]}

    provenance = digest_observation(document)["provenance"]

    assert provenance["status"] == "unknown"
    assert provenance["recorded_hosts"] == []


def test_digest_preserves_canonical_ipv4_capture_host():
    document = _observation({"api.Navigator.a": 1})
    document["provenance"] = {"status": "VERIFIED", "recorded_hosts": ["127.0.0.1"]}

    provenance = digest_observation(document)["provenance"]

    assert provenance["status"] == "VERIFIED"
    assert provenance["recorded_hosts"] == ["127.0.0.1"]


@pytest.mark.parametrize("host", ["[2001:db8:0:0:0:0:0:1]", "example.test:00443"])
def test_digest_downgrades_noncanonical_capture_host_serialization(host):
    document = _observation({"api.Navigator.a": 1})
    document["provenance"] = {"status": "VERIFIED", "recorded_hosts": [host]}

    provenance = digest_observation(document)["provenance"]

    assert provenance["status"] == "unknown"
    assert provenance["recorded_hosts"] == []


def test_digest_preserves_canonical_capture_host_with_port():
    document = _observation({"api.Navigator.a": 1})
    document["provenance"] = {"status": "VERIFIED", "recorded_hosts": ["example.test:443"]}

    provenance = digest_observation(document)["provenance"]

    assert provenance["status"] == "VERIFIED"
    assert provenance["recorded_hosts"] == ["example.test:443"]


def test_digest_preserves_verified_ipv6_capture_origin(tmp_path):
    payload = b"ipv6 capture provenance"
    root = _capture_tree(
        tmp_path,
        {"cap": ("example", [("s.js", payload, "https://[2001:db8::1]/s.js")])},
    )
    described = describe_provenance(root / "cap" / "scripts" / "s.js", root)
    assert described["verdict"] == "VERIFIED"
    assert described["recorded_hosts"] == ["[2001:db8::1]"]
    document = _observation({"api.Navigator.a": 1})
    document["provenance"] = {
        "status": described["verdict"],
        "recorded_hosts": described["recorded_hosts"],
    }

    provenance = digest_observation(document)["provenance"]

    assert provenance["status"] == "VERIFIED"
    assert provenance["recorded_hosts"] == ["[2001:db8::1]"]


def test_unicode_manifest_hostname_uses_a_stable_ascii_origin(tmp_path):
    payload = b"internationalized capture origin"
    root = _capture_tree(
        tmp_path,
        {"cap": ("example", [("s.js", payload, "https://bücher.example/s.js")])},
    )
    described = describe_provenance(root / "cap" / "scripts" / "s.js", root)
    assert described["verdict"] == "VERIFIED"
    assert described["recorded_hosts"] == ["xn--bcher-kva.example"]
    document = _observation({"api.Navigator.a": 1})
    document["provenance"] = {
        "status": described["verdict"],
        "recorded_hosts": described["recorded_hosts"],
    }

    provenance = digest_observation(document)["provenance"]

    assert provenance["status"] == "VERIFIED"
    assert provenance["recorded_hosts"] == ["xn--bcher-kva.example"]


def test_diff_says_unknown_when_either_origin_is_missing():
    left = _with_origin(_subtraction({"api.Navigator.a": 1}), ["www.fedex.com"])
    right = _subtraction({"api.Navigator.b": 1})
    diff = diff_digests(left, right)
    assert diff["comparability"]["status"] == "unknown"
    assert "--captures-root" in diff["comparability"]["note"]


def test_diff_uses_same_verified_public_source_when_capture_origin_is_missing():
    left = _with_public_source(
        _subtraction({"api.Navigator.a": 1}),
        "https://js.datadome.co/v5.1.13/tags.js",
    )
    right = _with_public_source(
        _subtraction({"api.Navigator.b": 1}),
        "https://js.datadome.co/v5.1.13/tags.js",
    )

    comparison = diff_digests(left, right)["comparability"]

    assert comparison["status"] == "same-source"
    assert comparison["left_public_source"] == {
        "hostname": "js.datadome.co",
        "sha256": "a" * 64,
    }
    assert "same verified public source" in comparison["note"]
    assert "protected deployment" in comparison["note"]
    assert "origin" not in comparison["note"]

    rendered = render_digest(digest_observation(left))
    assert "public source     VERIFIED https://js.datadome.co" in rendered
    assert "path-lengths=[7, 7]" in rendered
    assert "/v5.1.13/tags.js" not in rendered


def test_diff_labels_two_exact_pins_from_one_public_host_as_source_roll():
    left = _with_public_source(
        _subtraction({"api.Navigator.a": 1}),
        "https://challenges.cloudflare.com/turnstile/v0/api.js",
        "a" * 64,
    )
    right = _with_public_source(
        _subtraction({"api.Navigator.b": 1}),
        "https://challenges.cloudflare.com/turnstile/v0/api.js",
        "b" * 64,
    )

    comparison = diff_digests(left, right)["comparability"]

    assert comparison["status"] == "same-source-origin"
    assert "source-roll comparison" in comparison["note"]
    assert "not deployment provenance" in comparison["note"]


def test_diff_flags_verified_public_sources_from_different_hosts():
    left = _with_public_source(
        _subtraction({"api.Navigator.a": 1}),
        "https://js.datadome.co/v5.1.13/tags.js",
    )
    right = _with_public_source(
        _subtraction({"api.Navigator.b": 1}),
        "https://challenges.cloudflare.com/turnstile/v0/api.js",
    )

    comparison = diff_digests(left, right)["comparability"]

    assert comparison["status"] == "cross-origin"
    assert "crosses source populations" in comparison["note"]


@pytest.mark.parametrize(
    ("status", "url", "digest"),
    [
        ("not_supplied", "https://js.datadome.co/tags.js", "a" * 64),
        ("verified_digest", "https://user:pass@example.com/tags.js", "a" * 64),
        ("verified_digest", "https://js.datadome.co/tags.js", "x" * 64),
    ],
)
def test_diff_does_not_promote_unverified_or_malformed_public_source(
    status, url, digest
):
    left = _with_public_source(
        _subtraction({"api.Navigator.a": 1}), url, digest, status=status
    )
    right = _with_public_source(
        _subtraction({"api.Navigator.b": 1}), url, digest, status=status
    )

    comparison = diff_digests(left, right)["comparability"]

    assert comparison["status"] == "unknown"
    assert comparison["left_public_source"] is None


def test_comparability_never_blocks_the_diff():
    """It reports; it does not refuse. The diff is still the answer."""
    left = _with_origin(_subtraction({"api.Navigator.a": 1}), ["a.com"])
    right = _with_origin(_subtraction({"api.Navigator.a": 1}), ["b.com"])
    diff = diff_digests(left, right)
    assert diff["shared"] == 1
    assert diff["identical_surface"] is True


# --------------------------------------------------------------------------
# empty attributed surface
# --------------------------------------------------------------------------


def test_empty_attributed_surface_is_flagged_loudly():
    """`clean_subtraction: true` with nothing introduced is not a finding.

    It means the arm's API set was identical to the empty-script control, so the
    script either never executed or is not a collector. Measured 2026-08-06: pin
    `2123c79ff05a9f72` matched its control exactly at 3,272 events and 179 API
    names, and entered a profile table as a spurious sixth configuration before
    this guard existed.
    """
    digest = digest_observation(_subtraction({}))
    assert digest["total_api_names"] == 0
    assert "empty_surface_warning" in digest
    assert "did not execute" in digest["empty_surface_warning"]
    assert "EMPTY SURFACE" in render_digest(digest)


def test_non_empty_surface_has_no_empty_warning():
    digest = digest_observation(_subtraction({"api.Navigator.a": 1}))
    assert "empty_surface_warning" not in digest
    assert "EMPTY SURFACE" not in render_digest(digest)


def test_raw_observation_with_no_api_names_is_not_flagged_as_empty_attributed():
    """The warning is about attribution, so it only applies to subtractions."""
    digest = digest_observation(_observation({"blink.canvas": 5}))
    assert digest["total_api_names"] == 0
    assert "empty_surface_warning" not in digest


def test_a_surface_that_only_amplified_is_still_flagged_empty():
    """Amplification alone means nothing was introduced; the caveat still holds."""
    doc = _subtraction({})
    doc["elevated_in_arm"] = {"api.Performance.now": {"arm": 127, "control": 1}}
    digest = digest_observation(doc)
    assert digest["amplified_api_names"] == 1
    assert "empty_surface_warning" in digest


# --------------------------------------------------------------------------
# launch-mode comparability
# --------------------------------------------------------------------------


def _sub_mode(names, *, headed, label="arm"):
    doc = _subtraction({n: 1 for n in names}, label=label)
    doc["arm_headed"] = headed
    return doc


def test_diff_warns_when_launch_mode_differs():
    """The confound that invalidated a published finding on 2026-08-06.

    Of four pins observed both headed and headless, two produced different
    surfaces -- the entire 16-name DeviceMotion block appears only headless,
    because the trace records calls and the block is conditionally executed.
    """
    base = [f"api.Navigator.n{i}.get" for i in range(4)]
    motion = [f"api.DeviceMotionEvent.m{i}.get" for i in range(16)]
    diff = diff_digests(
        _sub_mode(base, headed=True), _sub_mode(base + motion, headed=False)
    )
    assert diff["comparability"]["launch_mode_differs"] is True
    assert "LAUNCH MODE DIFFERS" in render_digest(diff)


def test_diff_does_not_warn_when_launch_mode_matches():
    base = ["api.Navigator.a.get"]
    diff = diff_digests(_sub_mode(base, headed=True), _sub_mode(base, headed=True))
    assert diff["comparability"]["launch_mode_differs"] is False
    assert "LAUNCH MODE DIFFERS" not in render_digest(diff)


def test_diff_accepts_launch_mode_as_an_explicit_method_control():
    base = ["api.Navigator.a.get"]
    diff = diff_digests(
        _sub_mode(base, headed=False, label="headless"),
        _sub_mode(base, headed=True, label="headed"),
        vary_method_axes=("headed",),
    )
    comparison = diff["comparability"]

    assert comparison["status"] == "method-control"
    assert comparison["controlled_method_comparison"] is True
    assert comparison["launch_mode_differs"] is True
    assert comparison["unexpected_method_mismatches"] == {}
    assert "METHOD CONTROL  headed" in render_digest(diff)
    assert "LAUNCH MODE DIFFERS" not in render_digest(diff)


def test_diff_accepts_viewport_as_an_explicit_method_control():
    left = _sub_mode(["api.Navigator.a.get"], headed=True, label="short")
    right = _sub_mode(["api.Navigator.a.get"], headed=True, label="tall")
    left["arm_viewport"] = {"inner_width": 800, "inner_height": 1}
    right["arm_viewport"] = {"inner_width": 800, "inner_height": 600}

    diff = diff_digests(left, right, vary_method_axes=("viewport",))
    comparison = diff["comparability"]

    assert comparison["status"] == "method-control"
    assert comparison["controlled_method_comparison"] is True
    assert comparison["viewport_differs"] is True
    assert comparison["viewport_values_differ"] is True
    assert comparison["viewport_crosses_responsive_gate"] is True
    assert "METHOD CONTROL  viewport" in render_digest(diff)


def test_launch_control_requires_declaring_its_geometry_change_too():
    left = _sub_mode(["api.Navigator.a.get"], headed=False, label="headless")
    right = _sub_mode(["api.Navigator.a.get"], headed=True, label="headed")
    left["arm_viewport"] = {"inner_width": 758, "inner_height": 426}
    right["arm_viewport"] = {"inner_width": 1251, "inner_height": 1230}

    confounded = diff_digests(left, right, vary_method_axes=("headed",))
    assert confounded["comparability"]["controlled_method_comparison"] is False
    assert "arm_viewport" in confounded["comparability"]["unexpected_method_mismatches"]

    declared = diff_digests(left, right, vary_method_axes=("headed", "viewport"))
    assert declared["comparability"]["status"] == "method-control"
    assert declared["comparability"]["controlled_method_comparison"] is True
    assert declared["comparability"]["viewport_values_differ"] is True
    assert declared["comparability"]["viewport_crosses_responsive_gate"] is False


def test_diff_warns_on_redacted_driver_method_difference():
    base = {"api.Navigator.a.get": 1}
    left = _subtraction(base, label="left")
    right = _subtraction(base, label="right")
    left["arm_driver"] = {"supplied": True, "bytes": 10, "sha256_16": "1" * 16}
    right["arm_driver"] = {"supplied": True, "bytes": 10, "sha256_16": "2" * 16}
    left["arm_driver_supplied"] = right["arm_driver_supplied"] = True
    diff = diff_digests(left, right)
    assert diff["comparability"]["method_differs"] is True
    assert "arm_driver" in diff["comparability"]["method_mismatches"]
    assert "METHOD DIFFERS" in render_digest(diff)


def test_diff_accepts_one_explicit_method_control_axis():
    left = _subtraction({"api.Event.type.get": 1}, label="input")
    right = _subtraction({}, label="none")
    left["arm_input_profile"] = "probe-touch"
    right["arm_input_profile"] = "none"
    diff = diff_digests(left, right, vary_method_axes=("input_profile",))
    comparison = diff["comparability"]
    assert comparison["status"] == "method-control"
    assert comparison["controlled_method_comparison"] is True
    assert comparison["unexpected_method_mismatches"] == {}
    assert "METHOD CONTROL  input_profile" in render_digest(diff)


def test_method_control_still_rejects_a_second_unexpected_axis():
    left = _subtraction({"api.Event.type.get": 1}, label="input")
    right = _subtraction({}, label="none")
    left["arm_input_profile"] = "probe-touch"
    right["arm_input_profile"] = "none"
    left["arm_driver"] = {"supplied": True, "bytes": 1, "sha256_16": "1" * 16}
    diff = diff_digests(left, right, vary_method_axes=("input_profile",))
    comparison = diff["comparability"]
    assert comparison["controlled_method_comparison"] is False
    assert "arm_driver" in comparison["unexpected_method_mismatches"]
    assert "METHOD DIFFERS" in render_digest(diff)


def test_method_control_rejects_an_axis_that_did_not_change():
    doc = _subtraction({"api.Navigator.a": 1})
    with pytest.raises(ContractError, match="do not differ"):
        diff_digests(doc, doc, vary_method_axes=("input_profile",))


@pytest.mark.parametrize(
    "axes",
    [
        ["input_profile"],
        ("input_profile", "input_profile"),
        (1,),
    ],
)
def test_diff_rejects_noncanonical_method_control_axes(axes):
    doc = _subtraction({"api.Navigator.a": 1})
    with pytest.raises(ContractError, match="unique bounded tuple"):
        diff_digests(doc, doc, vary_method_axes=axes)


def test_missing_launch_mode_does_not_manufacture_agreement():
    """Older subtractions predate the field; unknown must not read as 'same'."""
    base = ["api.Navigator.a.get"]
    diff = diff_digests(
        _sub_mode(base, headed=True), _subtraction({"api.Navigator.a.get": 1})
    )
    assert diff["comparability"]["launch_mode_differs"] is False
    assert diff["comparability"]["right_headed"] is None


def test_launch_mode_warning_survives_alongside_cross_origin():
    base = ["api.Navigator.a.get"]
    left = _sub_mode(base, headed=True)
    right = _sub_mode(base, headed=False)
    left["provenance"] = {"status": "VERIFIED", "recorded_hosts": ["a.com"]}
    right["provenance"] = {"status": "VERIFIED", "recorded_hosts": ["b.com"]}
    diff = diff_digests(left, right)
    assert diff["comparability"]["launch_mode_differs"] is True
    assert "cross-deployment" in diff["comparability"]["note"]


def test_subtraction_carries_launch_mode_forward():
    from browser_core.product_observation import subtract_control

    arm = {
        "schema": OBSERVATION_SCHEMA,
        "label": "arm",
        "script_sha256_16": "a" * 16,
        "headed": False,
        "provenance": {"status": "VERIFIED", "recorded_hosts": ["x.com"]},
        "analysis": {"events_by_name": {"api.Navigator.a": 2}, "context_coverage": {}},
    }
    control = {
        "schema": OBSERVATION_SCHEMA,
        "label": "control",
        "script_sha256_16": "b" * 16,
        "headed": False,
        "analysis": {"events_by_name": {}, "context_coverage": {}},
    }
    out = subtract_control(arm, control)
    assert out["arm_headed"] is False
    assert out["control_headed"] is False
    assert out["provenance"]["recorded_hosts"] == ["x.com"]


# --------------------------------------------------------------------------
# controlled environment flags
# --------------------------------------------------------------------------


def test_extra_browser_args_default_to_empty():
    from pathlib import Path as _P

    cfg = ProductScriptObservation(
        script=_P("s.js"),
        label="l",
        executable=_P("c"),
        trace_processor=_P("t"),
        workspace=_P("w"),
    )
    assert cfg.extra_browser_args == ()


def test_extra_browser_args_are_accepted_and_ordered():
    from pathlib import Path as _P

    cfg = ProductScriptObservation(
        script=_P("s.js"),
        label="l",
        executable=_P("c"),
        trace_processor=_P("t"),
        workspace=_P("w"),
        extra_browser_args=("--window-size=800,1", "--force-device-scale-factor=1"),
    )
    assert cfg.extra_browser_args[0] == "--window-size=800,1"
    assert len(cfg.extra_browser_args) == 2


def test_observation_records_the_flags_it_was_launched_with():
    """An arm launched with unusual flags that does not say so is the next confound.

    Measured 2026-08-06: a headed browser at `--window-size=800,1` reproduces the
    headless surface exactly (motion 18, 117 names) while `--window-size=1,600`
    does not, so the environment an arm ran under is load-bearing evidence and
    must travel with it.
    """
    import inspect

    from browser_core import product_observation as po

    source = inspect.getsource(po.run_product_script_observation)
    assert '"extra_browser_args": list(config.extra_browser_args)' in source
    assert "*config.extra_browser_args" in source


# --------------------------------------------------------------------------
# viewport geometry recorded per arm (B28)
# --------------------------------------------------------------------------


def test_geometry_capture_never_fails_a_run():
    """Geometry is metadata about an observation and must not be able to fail one."""
    from browser_core.product_observation import _capture_geometry

    assert _capture_geometry("http://127.0.0.1:1", "http://x", 0.1) is None


def test_geometry_capture_parses_a_reading(monkeypatch):
    import browser_core.product_observation as po

    monkeypatch.setattr(
        po,
        "evaluate_page_expression",
        lambda *a, **k: json.dumps(
            {
                "inner_width": 1200,
                "inner_height": 815,
                "outer_width": 1216,
                "outer_height": 853,
                "screen_width": 1920,
                "screen_height": 1080,
                "device_pixel_ratio": 1,
            }
        ),
    )
    got = po._capture_geometry("http://127.0.0.1:9", "http://x", 1.0)
    assert got["inner_height"] == 815


def test_subtraction_carries_viewport_forward():
    from browser_core.product_observation import subtract_control

    arm = {
        "schema": OBSERVATION_SCHEMA,
        "label": "arm",
        "script_sha256_16": "a" * 16,
        "headed": True,
        "viewport": {"inner_width": 800, "inner_height": 1},
        "analysis": {"events_by_name": {"api.Navigator.a": 2}, "context_coverage": {}},
    }
    control = {
        "schema": OBSERVATION_SCHEMA,
        "label": "control",
        "script_sha256_16": "b" * 16,
        "headed": True,
        "viewport": {"inner_width": 800, "inner_height": 1},
        "analysis": {"events_by_name": {}, "context_coverage": {}},
    }
    out = subtract_control(arm, control)
    assert out["arm_viewport"]["inner_height"] == 1


def test_observation_records_viewport_even_when_absent():
    """A browser that will not answer yields None -- 'not recorded', never zero."""
    import inspect

    from browser_core import product_observation as po

    src = inspect.getsource(po.run_product_script_observation)
    assert '"viewport": geometry,' in src
    assert "geometry: dict[str, Any] | None = None" in src


def _sub_vp(names, *, height, headed=True, label="arm"):
    doc = _subtraction({n: 1 for n in names}, label=label)
    doc["arm_headed"] = headed
    doc["arm_viewport"] = {"inner_width": 800, "inner_height": height}
    return doc


def test_diff_warns_when_viewport_crosses_the_gate_boundary():
    """Measured: one build runs a 16-name module below ~115 px of viewport height."""
    base = ["api.Navigator.a.get"]
    diff = diff_digests(_sub_vp(base, height=1230), _sub_vp(base, height=1))
    assert diff["comparability"]["viewport_differs"] is True
    assert diff["comparability"]["viewport_values_differ"] is True
    assert diff["comparability"]["viewport_crosses_responsive_gate"] is True
    assert "VIEWPORT DIFFERS" in render_digest(diff)


def test_diff_does_not_warn_for_two_normal_viewports():
    base = ["api.Navigator.a.get"]
    diff = diff_digests(_sub_vp(base, height=1230), _sub_vp(base, height=900))
    assert diff["comparability"]["viewport_differs"] is False
    assert diff["comparability"]["viewport_values_differ"] is True
    assert diff["comparability"]["viewport_crosses_responsive_gate"] is False
    assert "VIEWPORT DIFFERS" not in render_digest(diff)


def test_diff_does_not_warn_for_two_small_viewports():
    """Both below the boundary is comparable; only straddling it is not."""
    base = ["api.Navigator.a.get"]
    diff = diff_digests(_sub_vp(base, height=1), _sub_vp(base, height=50))
    assert diff["comparability"]["viewport_differs"] is False


def test_missing_viewport_does_not_manufacture_a_warning():
    base = ["api.Navigator.a.get"]
    diff = diff_digests(
        _sub_vp(base, height=1), _subtraction({"api.Navigator.a.get": 1})
    )
    assert diff["comparability"]["viewport_differs"] is False
    assert diff["comparability"]["viewport_values_differ"] is False
    assert diff["comparability"]["viewport_crosses_responsive_gate"] is False
    assert diff["comparability"]["right_viewport"] is None


def test_viewport_boundary_constant_matches_the_measurement():
    from browser_core.observation_digest import VIEWPORT_HEIGHT_FLOOR

    # gate observed OPEN at window heights 1/2/50/100/150 (viewport <= ~65)
    # and CLOSED at 200/300/600 (viewport >= ~115)
    assert 65 <= VIEWPORT_HEIGHT_FLOOR <= 120


# ------------------------------------------------------------------ batch audit


def _arm(label: str, **fields) -> dict:
    doc = {
        "schema": "browser-core.product-script-observation/1",
        "label": label,
        "headed": True,
        "hook_mode": "off",
        "input_profile": "none",
        "viewport": {"inner_height": 750},
        "analysis": {"events_by_name": {"api.A.b": 1}},
    }
    doc.update(fields)
    return doc


def test_batch_audit_refuses_to_call_a_failed_run_a_negative():
    """The mistake this exists for.

    A wrapper bisection on 2026-08-07 ran seven subsets and reported "no markers"
    for all seven, but two of the runs had failed outright and were counted as
    clean negatives.
    """
    from browser_core.observation_digest import audit_batch, render_batch_audit

    report = audit_batch(
        {
            "ok-1": _arm("ok-1"),
            "ok-2": _arm("ok-2"),
            "dead": _arm("dead", error="trace export failed: ContractError: missing"),
        }
    )
    assert report["usable"] == 2
    assert report["failed"] == 1
    assert report["failed_labels"] == ["dead"]
    assert report["trustworthy"] is False
    text = render_batch_audit(report)
    assert "not a negative result" in text
    assert "trace export failed" in text


def test_batch_audit_groups_failures_by_cause():
    from browser_core.observation_digest import audit_batch

    report = audit_batch(
        {
            "a": _arm("a", error="trace export failed: ContractError: x"),
            "b": _arm("b", error="trace export failed: ContractError: y"),
            "c": _arm("c", error="ContractError: timed out waiting for transport"),
        }
    )
    assert report["failure_reasons"]["trace export failed"] == 2
    assert report["usable"] == 0


def test_batch_audit_failure_detail_does_not_copy_local_diagnostics():
    from browser_core.observation_digest import audit_batch

    private = r"C:\\private\\tenant-token\\trace.pftrace"
    report = audit_batch(
        {
            "dead": _arm(
                "dead",
                error=f"trace export failed: ContractError: missing {private}",
            )
        }
    )
    rendered = json.dumps(report)

    assert private not in rendered
    assert "tenant-token" not in rendered
    assert report["failure_detail"]["dead"] == {
        "phase": "trace export failed",
        "exception": "ContractError",
    }


def test_batch_audit_classifies_empty_error_without_crashing() -> None:
    report = audit_batch({"dead": _arm("dead", error="")})
    assert report["failed"] == 1
    assert report["failure_detail"]["dead"] == {
        "phase": "observation failed",
        "exception": "unknown",
    }


def test_batch_audit_flags_arms_that_are_not_one_population():
    """Mixing launch modes produced a withdrawn 'configuration ladder' once."""
    from browser_core.observation_digest import audit_batch, render_batch_audit

    report = audit_batch(
        {"headed": _arm("headed"), "headless": _arm("headless", headed=False)}
    )
    assert report["mixed_axes"] == ["headed"]
    assert report["trustworthy"] is False
    assert "not one population" in render_batch_audit(report)


def test_batch_audit_flags_a_mixed_hook_mode():
    from browser_core.observation_digest import audit_batch

    report = audit_batch(
        {"plain": _arm("plain"), "hooked": _arm("hooked", hook_mode="on")}
    )
    assert "hook_mode" in report["mixed_axes"]


def test_batch_audit_uses_driver_and_stage_method_identity():
    from browser_core.observation_digest import audit_batch

    first = _arm(
        "first",
        driver={"supplied": True, "bytes": 10, "sha256_16": "1" * 16},
        stage_routes=[
            {"path_prefix": "/tenant/mfc", "bytes": 10, "sha256_16": "2" * 16}
        ],
    )
    second = _arm(
        "second",
        driver={"supplied": True, "bytes": 10, "sha256_16": "3" * 16},
        stage_routes=[
            {"path_prefix": "/tenant/mfc", "bytes": 10, "sha256_16": "4" * 16}
        ],
    )
    report = audit_batch({"first": first, "second": second})
    assert report["trustworthy"] is False
    assert "driver" in report["mixed_axes"]
    assert "stage_routes" in report["mixed_axes"]


def test_batch_audit_hashes_a_legacy_raw_prelude_before_reporting_axes():
    from browser_core.observation_digest import audit_batch

    private_source = "window.__private_tenant_key = 'secret-value'"
    report = audit_batch({"legacy": _arm("legacy", prelude=private_source)})
    rendered = json.dumps(report)
    assert private_source not in rendered
    assert "private_tenant_key" not in rendered
    prelude_axis = report["axes"]["prelude"]
    assert any('"supplied":true' in key for key in prelude_axis)


def test_batch_audit_json_handles_null_and_numeric_axis_values():
    from browser_core.observation_digest import audit_batch

    report = audit_batch(
        {
            "legacy": _arm("legacy", timeout_seconds=None),
            "bounded": _arm("bounded", timeout_seconds=1.5),
        }
    )
    rendered = json.dumps(report, sort_keys=True)
    assert '"null"' in rendered
    assert '"1.5"' in rendered
    assert report["axes"]["timeout_seconds"] == {"null": 1, "1.5": 1}


def test_batch_audit_passes_a_clean_batch():
    from browser_core.observation_digest import audit_batch

    report = audit_batch({f"a{i}": _arm(f"a{i}") for i in range(4)})
    assert report["trustworthy"] is True
    assert report["failed"] == 0
    assert report["mixed_axes"] == []
    assert len(report["warnings"]) == 1
    assert "not attributed" in report["warnings"][0]


def test_batch_audit_keeps_unready_subtractions_out_of_a_trustworthy_population():
    ready = _subtraction({"api.Navigator.a": 1})
    unready = _subtraction({"api.Navigator.a": 1})
    unready["surface_claim_ready"] = False
    report = audit_batch({"ready": ready, "unready": unready})
    assert report["usable"] == 2
    assert report["failed"] == 0
    assert report["unready_labels"] == ["unready"]
    assert report["trustworthy"] is False
    assert report["claim_ready_population"] is False
    assert "not claim-ready" in render_batch_audit(report)


def test_batch_audit_labels_raw_only_population_as_unattributed():
    report = audit_batch({"raw": _arm("raw")})
    assert report["raw_labels"] == ["raw"]
    assert report["claim_ready_population"] is False
    assert "not attributed" in render_batch_audit(report)


def test_batch_audit_treats_a_missing_analysis_as_failure():
    """An arm with neither analysis nor an attributed surface produced nothing,
    even if it never recorded an error."""
    from browser_core.observation_digest import audit_batch

    silent = _arm("silent")
    del silent["analysis"]
    report = audit_batch({"ok": _arm("ok"), "silent": silent})
    assert report["failed"] == 1
    assert "silent" in report["failed_labels"]


def test_batch_audit_validates_the_surface_instead_of_its_truthiness():
    malformed = _arm("malformed")
    malformed["analysis"]["events_by_name"]["api.A.b"] = "1"
    report = audit_batch({"malformed": malformed})
    assert report["usable"] == 0
    assert report["failed"] == 1
    assert report["failure_detail"]["malformed"] == {
        "phase": "invalid observation",
        "exception": "ContractError",
    }


def test_batch_audit_accepts_a_valid_empty_attributed_surface():
    report = audit_batch({"empty": _subtraction({})})
    assert report["usable"] == 1
    assert report["failed"] == 0


def test_batch_audit_rejects_invalid_population_container_label_and_document():
    with pytest.raises(ContractError, match="batch audit"):
        audit_batch([])
    with pytest.raises(ContractError, match="label"):
        audit_batch({1: _arm("arm")})
    with pytest.raises(ContractError, match="entry"):
        audit_batch({"arm": []})


def test_batch_audit_does_not_stringify_non_text_error_objects():
    report = audit_batch({"dead": _arm("dead", error={"private": "secret"})})
    assert report["failure_detail"]["dead"] == {
        "phase": "observation failed",
        "exception": "unknown",
    }
    assert "private" not in json.dumps(report)
    assert "secret" not in json.dumps(report)


def test_batch_audit_accepts_subtractions_via_their_own_field_names():
    from browser_core.observation_digest import audit_batch

    sub = {
        "schema": "browser-core.product-script-subtraction/1",
        "arm_label": "s1",
        "arm_headed": True,
        "arm_hook_mode": "on",
        "arm_input_profile": "probe",
        "arm_viewport": {"inner_height": 750},
        "only_in_arm": {"api.A.b": 1},
    }
    report = audit_batch({"s1": sub})
    assert report["usable"] == 1
    assert report["axes"]["hook_mode"] == {'"on"': 1}
    assert report["axes"]["input_profile"] == {'"probe"': 1}


def test_batch_audit_refuses_an_empty_batch():
    from browser_core.observation_digest import audit_batch

    with pytest.raises(ContractError, match="at least one document"):
        audit_batch({})


def test_render_batch_audit_rejects_a_foreign_document():
    from browser_core.observation_digest import render_batch_audit

    with pytest.raises(ContractError):
        render_batch_audit({"schema": "nope/1"})


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("trustworthy", True),
        ("failed", 0),
        ("failed_labels", []),
        ("warnings", []),
    ],
)
def test_render_batch_audit_rejects_saved_failure_contradictions(
    field: str, replacement: object
) -> None:
    report = audit_batch(
        {"ok": _arm("ok"), "dead": _arm("dead", error="trace export failed")}
    )
    report[field] = replacement
    with pytest.raises(ContractError, match="rendered batch audit"):
        render_batch_audit(report)


def test_render_batch_audit_rejects_saved_mixed_method_contradictions() -> None:
    report = audit_batch(
        {"headed": _arm("headed"), "headless": _arm("headless", headed=False)}
    )
    report["mixed_axes"] = []
    with pytest.raises(ContractError, match="rendered batch audit"):
        render_batch_audit(report)


def test_render_batch_audit_accepts_a_json_round_trip() -> None:
    report = audit_batch(
        {
            "a": _arm("a", viewport={"inner_height": 750}),
            "b": _arm("b", viewport={"inner_height": 760}),
        }
    )
    assert "MIXED" in render_batch_audit(json.loads(json.dumps(report)))


def test_render_batch_audit_rejects_saved_axis_and_selection_contradictions() -> None:
    report = audit_batch({"a": _arm("a")})
    report["axes"]["headed"] = {'true': 2}
    with pytest.raises(ContractError, match="rendered batch audit"):
        render_batch_audit(report)

    report = audit_batch({"a": _arm("a")})
    report["population_selection"] = {
        "kind": "raw_observations",
        "selected": 7,
        "ignored_successful_intermediates": 0,
        "ignored_labels": [],
    }
    with pytest.raises(ContractError, match="rendered batch audit"):
        render_batch_audit(report)


def test_render_batch_audit_does_not_print_axis_control_characters() -> None:
    report = audit_batch({"a": _arm("a")})
    report["axes"]["hook_mode"] = {json.dumps("off\nFORGED CLEAN BATCH"): 1}
    rendered = render_batch_audit(report)
    assert "\nFORGED CLEAN BATCH" not in rendered


# -- what an attributed count leaves out, said where the count is read ---------
#
# Measured 2026-08-08: the driven Kasada client provably reads
# `navigator.userAgent` -- a page-side probe counted it -- and that read is absent
# from its 29 attributed names, because the browser reads it too and the control
# subtracts it away. Shape's 1,036 survives almost intact because enumerating 911
# `window` interfaces is not something a blank page does. The loss is proportional
# to how ordinary the collector's behaviour looks, so the number misleads most on
# the collectors that try hardest to look ordinary.


def test_an_attributed_digest_says_what_its_count_excludes() -> None:
    from browser_core.observation_digest import digest_observation, render_digest

    subtraction = {
        "schema": SUBTRACTION_SCHEMA,
        "arm_label": "vendor",
        "arm_script_sha256_16": "0" * 16,
        "control_label": "control",
        "clean_subtraction": True,
        "only_in_arm": {"api.Navigator.userAgent.get": 3, "api.Window.fetch": 1},
        "only_in_control": {},
    }
    digest = digest_observation(subtraction)
    assert digest["attributed"] is True
    assert "empty-script control" in digest["attribution_caveat"]
    assert "absence of a name is not evidence" in digest["attribution_caveat"]
    assert "empty-script control did not" in render_digest(digest)


def test_a_raw_digest_carries_no_attribution_caveat() -> None:
    """A raw surface already warns harder, and adding a second caveat would blunt
    the one that matters: the counts are not the script's at all."""
    from browser_core.observation_digest import digest_observation, render_digest

    arm = {
        "schema": OBSERVATION_SCHEMA,
        "label": "vendor",
        "script_sha256_16": "0" * 16,
        "analysis": {
            "events_by_name": {"api.Window.fetch": 2},
            "total_events": 2,
            "distinct_api_names": 1,
            "context_coverage": {},
            "request_classes": {},
        },
    }
    digest = digest_observation(arm)
    assert digest["attributed"] is False
    assert digest["attribution_caveat"] is None
    rendered = render_digest(digest)
    assert "empty-script control did not" not in rendered
    assert "NOT ATTRIBUTED" in rendered
