"""Tests for argument-level observation and its fidelity control.

The tests that matter most here are the redaction ones. This is the only module in
the package that records values a page produced, so the boundary between "the
question the collector asked" and "the answer this host gave" has to be enforced by
something other than the author's intent at the time of writing.
"""

from __future__ import annotations

import json

import pytest

from browser_core.argument_capture import (
    ARG_CORPUS_SCHEMA,
    CAP_HARVEST_BYTES,
    CAP_SAMPLES_PER_NAME,
    CAP_STRING_CHARS,
    CAPTURE_SCHEMA,
    FIDELITY_SCHEMA,
    HOOK_TARGETS,
    NEVER_RECORD_VALUES,
    REALM_SCHEMA,
    SAFE_ARG_PROJECTIONS,
    STRUCTURAL_POSITIONS,
    HookTarget,
    _check_policy,
    build_hook_script,
    compare_hook_fidelity,
    cross_check_realms,
    merge_harvests,
    parse_harvest,
    render_capture,
    render_argument_corpus,
    render_fidelity,
    render_realms,
    resolve_webgl_enum,
    subtract_capture,
    validate_capture,
)
from browser_core.contracts import ContractError
from browser_core.product_observation import (
    HOOK_MODES,
    HOOK_SCRIPT_PATH,
    SUBTRACTION_SCHEMA,
)


# --------------------------------------------------------------- redaction policy


def test_never_record_target_cannot_declare_a_value_position() -> None:
    """The policy is enforced at construction, not merely documented."""
    with pytest.raises(ContractError, match="never-record"):
        _check_policy(
            HookTarget("Storage.prototype", "setItem", record_args=(0, 1))
        )


def test_structural_position_is_still_allowed_on_a_denylisted_target() -> None:
    """`setItem` may record its key. That is the whole reason both lists exist."""
    _check_policy(HookTarget("Storage.prototype", "setItem", record_args=(0,)))


def test_owner_fallback_cannot_bypass_value_redaction_policy() -> None:
    with pytest.raises(ContractError, match="owner alternatives"):
        _check_policy(
            HookTarget(
                "Missing.prototype|Storage.prototype",
                "setItem",
                record_args=(1,),
            )
        )


def test_every_shipped_target_satisfies_the_policy() -> None:
    for target in HOOK_TARGETS:
        _check_policy(target)


def test_denylist_entries_are_reachable_names() -> None:
    """A denylist entry that matches no target name is dead policy.

    Not every entry needs a live target -- the list is deliberately forward-looking
    -- but the ones that *do* have targets must line up, or a rename has quietly
    disarmed the guard.
    """
    names = {t.name for t in HOOK_TARGETS}
    for name in STRUCTURAL_POSITIONS:
        assert name in NEVER_RECORD_VALUES, f"{name} grants positions it never needed"
    overlap = names & NEVER_RECORD_VALUES
    assert "Storage.setItem" in overlap


def test_setitem_target_records_only_the_key() -> None:
    target = next(t for t in HOOK_TARGETS if t.name == "Storage.setItem")
    assert target.record_args == (0,)
    assert 1 not in target.record_args


def test_permissions_target_projects_only_the_descriptor_name() -> None:
    target = next(t for t in HOOK_TARGETS if t.name == "Permissions.query")
    assert target.record_args == ()
    assert target.arg_projections == ((0, "permission-name"),)
    assert SAFE_ARG_PROJECTIONS[target.name] == target.arg_projections


def test_setattribute_projects_only_redacted_src_url_shape() -> None:
    target = next(t for t in HOOK_TARGETS if t.name == "Element.setAttribute")
    assert target.record_args == (0,)
    assert target.arg_projections == ((1, "url-shape-if-arg0-src"),)
    assert SAFE_ARG_PROJECTIONS[target.name] == target.arg_projections


def test_loader_dom_targets_keep_only_selector_and_node_classes() -> None:
    by_name = {target.name: target for target in HOOK_TARGETS}
    locator = by_name["Document.getElementsByTagName"]
    mutation = by_name["Node.insertBefore"]
    assert locator.record_args == (0,)
    assert locator.arg_projections == ()
    assert mutation.record_args == ()
    assert mutation.arg_projections == ()


def test_arbitrary_object_projection_is_rejected() -> None:
    with pytest.raises(ContractError, match="unsafe argument projections"):
        _check_policy(
            HookTarget(
                "Storage.prototype", "getItem",
                arg_projections=((0, "permission-name"),),
            )
        )


def test_same_argument_cannot_be_recorded_and_projected() -> None:
    with pytest.raises(ContractError, match="both records and projects"):
        _check_policy(
            HookTarget(
                "Permissions.prototype", "query",
                record_args=(0,), arg_projections=((0, "permission-name"),),
            )
        )


def test_no_target_records_a_canvas_or_beacon_payload() -> None:
    for target in HOOK_TARGETS:
        if target.name in {
            "HTMLCanvasElement.toDataURL",
            "Navigator.sendBeacon",
            "CanvasRenderingContext2D.getImageData",
        }:
            assert target.record_args == ()


# ------------------------------------------------------------------- hook script


def test_hook_script_is_valid_and_bounded() -> None:
    js = build_hook_script()
    assert "__SPEC__" not in js and "__CAP_N__" not in js
    assert str(CAP_SAMPLES_PER_NAME) in js
    assert str(CAP_STRING_CHARS) in js
    assert len(js) < 64_000


def test_hook_script_rejects_unreviewed_value_capture_targets() -> None:
    with pytest.raises(ContractError, match="curated"):
        build_hook_script((HookTarget("Storage.prototype", "setItem", record_args=(1,)),))

    shipped = next(t for t in HOOK_TARGETS if t.name == "Storage.setItem")
    with pytest.raises(ContractError, match="curated"):
        build_hook_script((HookTarget(shipped.owner, shipped.prop, record_args=(1,)),))


def test_hook_script_rejects_unknown_or_duplicate_targets() -> None:
    with pytest.raises(ContractError, match="curated"):
        build_hook_script((HookTarget("Unknown.prototype", "inspect", record_args=(0,)),))
    with pytest.raises(ContractError, match="unique"):
        build_hook_script((HOOK_TARGETS[0], HOOK_TARGETS[0]))


def test_hook_script_embeds_every_target() -> None:
    js = build_hook_script()
    for target in HOOK_TARGETS:
        assert f'"{target.prop}"' in js


def test_hook_script_spec_is_parseable_json() -> None:
    js = build_hook_script()
    start = js.index("var SPEC = ") + len("var SPEC = ")
    end = js.index(";\n", start)
    spec = json.loads(js[start:end])
    assert len(spec) == len(HOOK_TARGETS)
    assert all(
        {"owner", "prop", "kind", "name", "arg_projections"} <= set(item)
        for item in spec
    )


def test_target_names_are_unique() -> None:
    names = [t.name for t in HOOK_TARGETS]
    assert len(names) == len(set(names))


def test_global_targets_declare_the_prototype_owner() -> None:
    """Global functions live on `Window.prototype`, not on the global object.

    Measured live 2026-08-06: declaring the owner as `Window` reported six targets
    as `prop-absent`, which in a report is indistinguishable from a collector that
    never called them.
    """
    for target in HOOK_TARGETS:
        if target.name.startswith("Window."):
            assert "Window.prototype" in target.owner, target.name


# -------------------------------------------------------------------- enum naming


def test_webgl_enums_resolve_to_names() -> None:
    assert resolve_webgl_enum(0x9246) == "UNMASKED_RENDERER_WEBGL(0x9246)"
    assert resolve_webgl_enum(0x1F00) == "VENDOR(0x1F00)"


def test_unknown_webgl_enum_renders_as_hex_not_as_a_guess() -> None:
    assert resolve_webgl_enum(0x1234) == "0x1234"


def test_non_numeric_enum_is_passed_through() -> None:
    assert resolve_webgl_enum("2d") == "2d"
    assert resolve_webgl_enum(True) == "True"


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (0x9246 + 0.5, "37446.5"),
        (float("inf"), "inf"),
        (-1, "-1"),
        (2**32, str(2**32)),
    ],
)
def test_webgl_enum_renderer_does_not_coerce_non_enum_numbers(
    value: object,
    expected: str,
) -> None:
    assert resolve_webgl_enum(value) == expected


# ----------------------------------------------------------------------- harvest


def _harvest(records: list[dict], **extra) -> str:
    payload = {
        "records": records,
        "total_samples": sum(len(r.get("samples") or []) for r in records),
        "dropped": 0,
        "record_failures": 0,
        "installed": {target.name: "ok" for target in HOOK_TARGETS},
        "self_suppressed": 0,
    }
    payload.update(extra)
    return json.dumps(payload)


def test_parse_harvest_reads_records() -> None:
    raw = _harvest(
        [
            {
                "name": "EventTarget.addEventListener",
                "calls": 6,
                "distinct": 2,
                "dropped": 0,
                "samples": [
                    {"args": ["mousemove", "function", "bool"], "count": 5},
                    {"args": ["touchstart", "function", "bool"], "count": 1},
                ],
            }
        ]
    )
    parsed = parse_harvest(raw)
    assert parsed["schema"] == CAPTURE_SCHEMA
    assert parsed["status"] == "ok"
    assert parsed["distinct_names"] == 1
    assert parsed["total_calls"] == 6


def test_absent_harvest_is_not_an_empty_finding() -> None:
    """"We did not get the arguments" and "there were none" are opposite claims."""
    parsed = parse_harvest(json.dumps({"absent": True}))
    assert parsed["status"] == "absent"
    assert parsed["records"] == []
    assert "distinct_names" not in parsed


def test_error_harvest_is_preserved() -> None:
    private = "TypeError: private-page-value"
    parsed = parse_harvest(json.dumps({"error": private}))
    assert parsed["status"] == "error"
    assert private not in json.dumps(parsed)
    assert parsed["error_digest"].startswith("sha256:")


def test_oversized_harvest_is_refused() -> None:
    with pytest.raises(ContractError, match="exceeded"):
        parse_harvest("x" * (CAP_HARVEST_BYTES + 1))


def test_invalid_harvest_json_is_refused() -> None:
    with pytest.raises(ContractError, match="valid UTF-8 JSON"):
        parse_harvest("{not json")


def test_harvest_must_be_a_string() -> None:
    with pytest.raises(ContractError, match="JSON string"):
        parse_harvest({"records": []})  # type: ignore[arg-type]


def test_uninstalled_targets_are_reported() -> None:
    statuses = {target.name: "ok" for target in HOOK_TARGETS}
    statuses["Document.querySelector"] = "prop-absent"
    statuses["HTMLCanvasElement.toDataURL"] = "not-configurable"
    raw = _harvest([], installed=statuses)
    parsed = parse_harvest(raw)
    assert parsed["targets_installed"] == len(HOOK_TARGETS) - 2
    assert parsed["targets_not_installed"] == {
        "Document.querySelector": "prop-absent",
        "HTMLCanvasElement.toDataURL": "not-configurable",
    }


def test_harvest_is_bounded_in_utf8_bytes_not_python_characters() -> None:
    raw = '"' + ("\u20ac" * (CAP_HARVEST_BYTES // 2)) + '"'
    with pytest.raises(ContractError, match="exceeded"):
        parse_harvest(raw)


def test_harvest_refuses_duplicate_json_members() -> None:
    with pytest.raises(ContractError, match="duplicate key"):
        parse_harvest('{"absent":true,"absent":true}')


@pytest.mark.parametrize(
    "mutation, message",
    [
        (lambda p: p.update(extra=True), "fields are invalid"),
        (lambda p: p.update(total_samples=True), "must be an integer"),
        (lambda p: p.update(installed={}), "every hook target"),
        (lambda p: p.update(dropped=1), "aggregate sample counts"),
    ],
)
def test_harvest_refuses_malformed_success_envelopes(mutation, message: str) -> None:
    payload = json.loads(_harvest([]))
    mutation(payload)
    with pytest.raises(ContractError, match=message):
        parse_harvest(json.dumps(payload))


def test_harvest_refuses_inconsistent_record_counts() -> None:
    payload = json.loads(
        _harvest(
            [{
                "name": "EventTarget.addEventListener",
                "calls": 2,
                "distinct": 1,
                "dropped": 0,
                "samples": [{"args": ["click"], "count": 1}],
            }]
        )
    )
    with pytest.raises(ContractError, match="call counts are inconsistent"):
        parse_harvest(json.dumps(payload))


# ------------------------------------------------------------------------ merge


def test_merge_sums_calls_across_page_loads() -> None:
    def load(count: int) -> dict:
        return parse_harvest(
            _harvest(
                [
                    {
                        "name": "Document.querySelector",
                        "calls": count,
                        "distinct": 1,
                        "dropped": 0,
                        "samples": [{"args": ["form"], "count": count}],
                    }
                ]
            )
        )

    merged = merge_harvests([load(3), load(4)])
    assert merged["total_calls"] == 7
    assert merged["records"][0]["samples"][0]["count"] == 7
    assert merged["page_loads_harvested"] == 2


def test_merge_unions_distinct_values() -> None:
    def load(value: str) -> dict:
        return parse_harvest(
            _harvest(
                [
                    {
                        "name": "Window.matchMedia",
                        "calls": 1,
                        "distinct": 1,
                        "dropped": 0,
                        "samples": [{"args": [value], "count": 1}],
                    }
                ]
            )
        )

    merged = merge_harvests([load("(hover: hover)"), load("(pointer: fine)")])
    assert merged["records"][0]["distinct"] == 2


def test_merged_capture_remains_usable_after_crossing_one_page_sample_caps() -> None:
    names = sorted(target.name for target in HOOK_TARGETS)[:30]
    first_records = [
        {
            "name": name,
            "calls": CAP_SAMPLES_PER_NAME,
            "distinct": CAP_SAMPLES_PER_NAME,
            "dropped": 0,
            "samples": [
                {"args": [f"first-{index}"], "count": 1}
                for index in range(CAP_SAMPLES_PER_NAME)
            ],
        }
        for name in names
    ]
    second_records = [
        {
            "name": names[0],
            "calls": 1,
            "distinct": 1,
            "dropped": 0,
            "samples": [{"args": ["second-page"], "count": 1}],
        }
    ]
    first = parse_harvest(_harvest(first_records))
    second = parse_harvest(_harvest(second_records))
    merged = merge_harvests([first, second])
    assert merged["page_loads_harvested"] == 2
    assert merged["total_samples"] == 30 * CAP_SAMPLES_PER_NAME + 1
    assert validate_capture(merged) == merged
    assert "argument capture:" in render_capture(merged)
    attributed = subtract_capture(merged, parse_harvest(_harvest([])))
    assert attributed["total_calls"] == merged["total_calls"]
    assert "control-subtracted" in render_capture(attributed)


def test_merge_recomputes_all_aggregate_receipts_across_page_loads() -> None:
    statuses = {target.name: "ok" for target in HOOK_TARGETS}
    statuses["Document.querySelector"] = "prop-absent"

    def load(
        *,
        sample_count: int,
        dropped: int,
        failures: int,
        self_suppressed: int,
        installed: dict[str, str] | None = None,
    ) -> dict:
        return parse_harvest(
            _harvest(
                [
                    {
                        "name": "Document.querySelector",
                        "calls": sample_count + dropped,
                        "distinct": 1,
                        "dropped": dropped,
                        "samples": [{"args": ["form"], "count": sample_count}],
                    }
                ],
                dropped=dropped,
                record_failures=failures,
                self_suppressed=self_suppressed,
                installed=installed or {target.name: "ok" for target in HOOK_TARGETS},
            )
        )

    first = load(
        sample_count=2,
        dropped=1,
        failures=2,
        self_suppressed=3,
        installed=statuses,
    )
    second = load(sample_count=2, dropped=2, failures=1, self_suppressed=4)
    merged = merge_harvests([first, second])
    reversed_merge = merge_harvests([second, first])

    expected = {
        "total_calls": 7,
        "total_samples": 1,
        "dropped_samples": 3,
        "record_failures": 3,
        "self_calls_suppressed": 7,
        "targets_installed": len(HOOK_TARGETS) - 1,
        "targets_not_installed": {"Document.querySelector": "prop-absent"},
        "page_loads_harvested": 2,
    }
    for field, value in expected.items():
        assert merged[field] == value
        assert reversed_merge[field] == value
    assert merged["records"] == reversed_merge["records"]
    assert merged["records"][0]["samples"] == [{"args": ["form"], "count": 4}]


def test_merge_of_no_usable_harvest_reports_absence() -> None:
    merged = merge_harvests([parse_harvest(json.dumps({"absent": True}))])
    assert merged["status"] == "absent"


def test_merge_of_nothing_at_all_is_absent_not_empty() -> None:
    merged = merge_harvests([])
    assert merged["status"] == "absent"
    assert merged["records"] == []


def test_merge_rejects_malformed_page_harvest_receipts_without_echo() -> None:
    private = "private-merge-receipt-marker"
    valid = parse_harvest(
        _harvest(
            [
                {
                    "name": "Document.querySelector",
                    "calls": 1,
                    "distinct": 1,
                    "dropped": 0,
                    "samples": [{"args": ["form"], "count": 1}],
                }
            ]
        )
    )
    mutations = (
        {**valid, "private": private},
        {**valid, "distinct_names": 2},
        {**valid, "total_calls": True},
        {**valid, "total_samples": 0},
        {**valid, "targets_installed": 0},
        {**valid, "caps": {"private": private}},
        {**valid, "non_claims": [private]},
        {**valid, "targets_not_installed": {private: "prop-absent"}},
    )
    for mutation in mutations:
        with pytest.raises(ContractError) as failure:
            merge_harvests([mutation])
        assert private not in str(failure.value)

    absent = parse_harvest(json.dumps({"absent": True}))
    with pytest.raises(ContractError):
        merge_harvests([{**absent, "records": [{"private": private}]}])
    error = parse_harvest(json.dumps({"error": private}))
    with pytest.raises(ContractError) as failure:
        merge_harvests([{**error, "error_digest": private}])
    assert private not in str(failure.value)


def test_control_subtraction_recomputes_attributed_call_and_sample_receipts() -> None:
    arm = parse_harvest(
        _harvest(
            [
                {
                    "name": "EventTarget.addEventListener",
                    "calls": 9,
                    "distinct": 2,
                    "dropped": 0,
                    "samples": [
                        {"args": ["click"], "count": 6},
                        {"args": ["mousemove"], "count": 3},
                    ],
                }
            ]
        )
    )
    control = parse_harvest(
        _harvest(
            [
                {
                    "name": "EventTarget.addEventListener",
                    "calls": 2,
                    "distinct": 1,
                    "dropped": 0,
                    "samples": [{"args": ["click"], "count": 2}],
                }
            ]
        )
    )
    attributed = subtract_capture(arm, control)
    assert attributed["records"][0] == {
        "name": "EventTarget.addEventListener",
        "calls": 3,
        "distinct": 1,
        "dropped": 0,
        "samples": [{"args": ["mousemove"], "count": 3}],
    }
    assert attributed["total_calls"] == 3
    assert attributed["total_samples"] == 1
    assert attributed["control_dropped_samples"] == 1
    assert attributed["control_dropped_calls"] == 6
    assert attributed["unattributed_arm_calls"] == 6
    assert attributed["attribution_complete"] is True
    rendered = render_capture(attributed)
    assert "1 distinct sample(s), 6 call(s)" in rendered
    assert "3 calls" in rendered


def test_control_subtraction_marks_capped_population_incomplete() -> None:
    arm = parse_harvest(
        _harvest(
            [
                {
                    "name": "Document.querySelector",
                    "calls": 4,
                    "distinct": 1,
                    "dropped": 1,
                    "samples": [{"args": ["form"], "count": 3}],
                }
            ],
            dropped=1,
        )
    )
    control = parse_harvest(_harvest([]))
    attributed = subtract_capture(arm, control)
    assert attributed["total_calls"] == 3
    assert attributed["arm_capped_calls"] == 1
    assert attributed["unattributed_arm_calls"] == 1
    assert attributed["attribution_complete"] is False
    assert "attribution is incomplete" in render_capture(attributed)


def test_control_subtraction_rejects_malformed_success_receipts_without_echo() -> None:
    private = "private-subtraction-marker"
    capture = parse_harvest(_harvest([]))
    for mutation in (
        {**capture, "private": private},
        {**capture, "total_calls": True},
        {**capture, "non_claims": [private]},
    ):
        with pytest.raises(ContractError) as failure:
            subtract_capture(mutation, capture)
        assert private not in str(failure.value)


# ----------------------------------------------------------------------- render


def test_render_capture_is_bounded_for_a_huge_sample_set() -> None:
    target_names = sorted(target.name for target in HOOK_TARGETS)[:30]
    records = [
        {
            "name": name,
            "calls": CAP_SAMPLES_PER_NAME,
            "distinct": CAP_SAMPLES_PER_NAME,
            "dropped": 0,
            "samples": [
                {"args": [f"v{j}"], "count": 1}
                for j in range(CAP_SAMPLES_PER_NAME)
            ],
        }
        for name in target_names
    ]
    capture = parse_harvest(_harvest(records))
    text = render_capture(capture)
    assert len(text) < 20_000
    assert "more distinct" in text


def test_capture_parser_and_renderer_reject_control_text_without_echo() -> None:
    private = "private-capture-line-marker"
    raw = _harvest(
        [
            {
                "name": "Document.querySelector",
                "calls": 1,
                "distinct": 1,
                "dropped": 0,
                "samples": [{"args": [private + "\nforged line"], "count": 1}],
            }
        ]
    )
    with pytest.raises(ContractError) as failure:
        parse_harvest(raw)
    assert private not in str(failure.value)


def test_render_capture_rejects_sparse_and_forged_receipts_without_echo() -> None:
    private = "private-capture-render-marker"
    valid = parse_harvest(_harvest([]))
    for mutation in (
        {"schema": CAPTURE_SCHEMA, "status": "ok", "records": []},
        {**valid, "private": private},
        {**valid, "total_calls": True},
        {**valid, "non_claims": [private]},
    ):
        with pytest.raises(ContractError) as failure:
            render_capture(mutation)
        assert private not in str(failure.value)


def test_validate_capture_rejects_unhashable_absent_note_cleanly() -> None:
    capture = {
        "schema": CAPTURE_SCHEMA,
        "status": "absent",
        "note": ["private-capture-marker"],
        "records": [],
    }

    with pytest.raises(ContractError) as failure:
        validate_capture(capture)

    assert "private-capture-marker" not in str(failure.value)


def test_validate_capture_rejects_unhashable_install_status_cleanly() -> None:
    capture = parse_harvest(_harvest([]))
    capture["targets_not_installed"] = {
        HOOK_TARGETS[0].name: ["private-capture-marker"]
    }

    with pytest.raises(ContractError) as failure:
        validate_capture(capture)

    assert "private-capture-marker" not in str(failure.value)


def test_parse_harvest_rejects_unhashable_install_status_cleanly() -> None:
    harvest = json.loads(_harvest([]))
    harvest["installed"][HOOK_TARGETS[0].name] = ["private-capture-marker"]

    with pytest.raises(ContractError) as failure:
        parse_harvest(json.dumps(harvest))

    assert "private-capture-marker" not in str(failure.value)


def test_parse_harvest_omits_unknown_field_names_from_diagnostic() -> None:
    harvest = json.loads(_harvest([]))
    harvest["private-capture-marker"] = "private-value"

    with pytest.raises(ContractError, match="fields are invalid") as failure:
        parse_harvest(json.dumps(harvest))

    assert "private-capture-marker" not in str(failure.value)
    assert "private-value" not in str(failure.value)


def test_validate_attributed_capture_rejects_unhashable_dropped_name_cleanly() -> None:
    empty = parse_harvest(_harvest([]))
    attributed = subtract_capture(empty, empty)
    attributed["control_dropped_names"] = [["private-capture-marker"]]

    with pytest.raises(ContractError) as failure:
        validate_capture(attributed)

    assert "private-capture-marker" not in str(failure.value)


def test_render_capture_names_the_webgl_enum() -> None:
    capture = parse_harvest(
        _harvest(
            [
                {
                    "name": "WebGLRenderingContext.getParameter",
                    "calls": 1,
                    "distinct": 1,
                    "dropped": 0,
                    "samples": [{"args": [37446], "count": 1}],
                }
            ]
        )
    )
    assert "UNMASKED_RENDERER_WEBGL" in render_capture(capture)


def test_render_of_absent_capture_says_so_loudly() -> None:
    text = render_capture(parse_harvest(json.dumps({"absent": True})))
    assert "NO ARGUMENT EVIDENCE" in text
    assert "not the same as" in text


def test_render_warns_when_samples_were_dropped() -> None:
    capture = parse_harvest(
        _harvest(
            [{
                "name": "EventTarget.addEventListener",
                "calls": 9,
                "distinct": 1,
                "dropped": 5,
                "samples": [{"args": ["click"], "count": 4}],
            }],
            dropped=5,
        )
    )
    capture["dropped_samples"] = 5
    assert "dropped at the cap" in render_capture(capture)


def test_render_rejects_a_foreign_document() -> None:
    with pytest.raises(ContractError):
        render_capture({"schema": "something/1"})


# --------------------------------------------------------------------- fidelity


def _subtraction(names: dict[str, int], *, label: str, clean: bool = True) -> dict:
    return {
        "schema": SUBTRACTION_SCHEMA,
        "arm_label": label,
        "arm_script_sha256_16": "deadbeefdeadbeef",
        "only_in_arm": names,
        "clean_subtraction": clean,
    }


def test_identical_surfaces_are_transparent() -> None:
    surface = {"api.A.b": 3, "api.C.d": 1}
    report = compare_hook_fidelity(
        _subtraction(surface, label="hook"), _subtraction(dict(surface), label="plain")
    )
    assert report["verdict"] == "TRANSPARENT"
    assert report["argument_evidence_usable"] is True
    assert report["surface_delta"] == 0


def test_a_differing_surface_perturbs_and_names_the_difference() -> None:
    report = compare_hook_fidelity(
        _subtraction({"api.A.b": 1, "api.X.y": 1}, label="hook"),
        _subtraction({"api.A.b": 1}, label="plain"),
    )
    assert report["verdict"] == "PERTURBS"
    assert report["added_by_hook"] == ["api.X.y"]
    assert report["argument_evidence_usable"] is False


def test_a_dirty_subtraction_cannot_yield_a_transparency_verdict() -> None:
    surface = {"api.A.b": 1}
    report = compare_hook_fidelity(
        _subtraction(surface, label="hook", clean=False),
        _subtraction(dict(surface), label="plain"),
    )
    assert report["verdict"] == "UNUSABLE"
    assert report["dirty_subtractions"] == ["with_hook"]
    assert report["argument_evidence_usable"] is False


def test_fidelity_method_mismatch_fails_closed() -> None:
    surface = {"api.A.b": 1}
    hooked = dict(
        _subtraction(surface, label="hook"),
        arm_hook_mode="on",
        arm_dwell_seconds=8.0,
        arm_hook_target_names=["Permissions.query"],
    )
    plain = dict(
        _subtraction(surface, label="plain"),
        arm_hook_mode="inert",
        arm_dwell_seconds=1.0,
        arm_hook_target_names=["Permissions.query"],
    )
    report = compare_hook_fidelity(hooked, plain)
    assert report["verdict"] == "UNUSABLE"
    assert report["argument_evidence_usable"] is False
    assert "arm_dwell_seconds" in report["method_mismatches"]
    assert "different methods" in render_fidelity(report)


def test_fidelity_requires_explicit_modes_to_have_their_expected_roles() -> None:
    surface = {"api.A.b": 1}
    hooked = dict(_subtraction(surface, label="hook"), arm_hook_mode="off")
    plain = dict(_subtraction(surface, label="plain"), arm_hook_mode="inert")
    report = compare_hook_fidelity(hooked, plain)
    assert report["verdict"] == "UNUSABLE"
    assert "arm_hook_mode" in report["method_mismatches"]


def _observation(names: dict[str, int]) -> dict:
    return {"analysis": {"events_by_name": names}}


def test_attribution_loss_is_distinguished_from_perturbation() -> None:
    """The sample is unchanged; the instrument's own footprint ate the name.

    Measured on pin 1e88274539a68be0: the hooked run attributed one name fewer,
    and the name was in the *arm* in every run of both modes. What gained it was
    the control, because the wrappers reach it while resolving a prototype.
    """
    report = compare_hook_fidelity(
        _subtraction({"api.A.b": 1}, label="hook"),
        _subtraction({"api.A.b": 1, "api.Window.Navigator": 1}, label="plain"),
        hooked_arms=(
            _observation({"api.A.b": 1, "api.Window.Navigator": 1}),
            _observation({"api.Window.Navigator": 1}),
        ),
        plain_arms=(
            _observation({"api.A.b": 1, "api.Window.Navigator": 1}),
            _observation({}),
        ),
    )
    assert report["verdict"] == "ATTRIBUTION_LOSS"
    assert report["argument_evidence_usable"] is True
    assert report["arm_surface_changed"] is False
    assert report["instrument_footprint"] == ["api.Window.Navigator"]
    assert report["blind_spots"] == ["api.Window.Navigator"]


def test_a_changed_arm_surface_is_still_perturbation() -> None:
    """A sample-side difference outside the footprint is a real perturbation.

    The hooked arm must contain the footprint (the instrument runs on both pages),
    so the difference here is `api.Sample.s`, which the instrument never touches.
    """
    report = compare_hook_fidelity(
        _subtraction({"api.A.b": 1}, label="hook"),
        _subtraction({"api.A.b": 1, "api.Sample.s": 1}, label="plain"),
        hooked_arms=(
            _observation({"api.A.b": 1, "api.Z.z": 1}),
            _observation({"api.Z.z": 1}),
        ),
        plain_arms=(
            _observation({"api.A.b": 1, "api.Sample.s": 1}),
            _observation({}),
        ),
    )
    assert report["verdict"] == "PERTURBS"
    assert report["arm_surface_changed"] is True
    assert report["sample_delta"] == ["api.Sample.s"]


def test_footprint_is_subtracted_from_both_arms_before_comparing() -> None:
    """Regression: the arm page carries the instrument too.

    Comparing raw arms directly always reports a change -- the hooked arm gains the
    whole footprint by construction -- so the naive check called every run
    PERTURBS. Measured on pin 1e88274539a68be0: a 14-name footprint made the arms
    differ while the sample was provably identical.
    """
    footprint = {f"api.Hook.h{i}": 1 for i in range(14)}
    sample = {"api.A.b": 1, "api.C.d": 1}
    report = compare_hook_fidelity(
        _subtraction(sample, label="hook"),
        _subtraction(sample, label="plain"),
        hooked_arms=(_observation({**sample, **footprint}), _observation(footprint)),
        plain_arms=(_observation(sample), _observation({})),
    )
    assert report["footprint_size"] == 14
    assert report["arm_surface_changed"] is False
    assert report["verdict"] == "TRANSPARENT"


def test_footprint_absent_from_the_hooked_arm_is_an_inconsistent_batch() -> None:
    """The instrument runs on both pages, so this cannot happen in one run.

    Treating it as a blind spot would let mismatched files return a clean verdict.
    """
    report = compare_hook_fidelity(
        _subtraction({"api.A.b": 1}, label="hook"),
        _subtraction({"api.A.b": 1, "api.Z.z": 1}, label="plain"),
        hooked_arms=(_observation({"api.A.b": 1}), _observation({"api.Z.z": 1})),
        plain_arms=(_observation({"api.A.b": 1, "api.Z.z": 1}), _observation({})),
    )
    assert report["verdict"] == "UNUSABLE"
    assert report["inconsistent_footprint"] == ["api.Z.z"]
    assert report["argument_evidence_usable"] is False
    assert "inconsistent arms" in render_fidelity(report)


def test_a_removed_name_outside_the_footprint_is_perturbation() -> None:
    report = compare_hook_fidelity(
        _subtraction({"api.A.b": 1}, label="hook"),
        _subtraction({"api.A.b": 1, "api.Q.q": 1}, label="plain"),
        hooked_arms=(
            _observation({"api.A.b": 1, "api.Other.x": 1}),
            _observation({"api.Other.x": 1}),
        ),
        plain_arms=(
            _observation({"api.A.b": 1, "api.Q.q": 1}),
            _observation({}),
        ),
    )
    # api.Q.q left the attributed surface but the footprint is api.Other.x, so the
    # loss is unexplained and must not be excused.
    assert report["verdict"] == "PERTURBS"
    assert report["instrument_footprint"] == ["api.Other.x"]
    assert report["sample_delta"] == ["api.Q.q"]


def test_added_names_are_never_explained_away_as_attribution_loss() -> None:
    report = compare_hook_fidelity(
        _subtraction({"api.A.b": 1, "api.New.n": 1}, label="hook"),
        _subtraction({"api.A.b": 1}, label="plain"),
        hooked_arms=(_observation({"api.A.b": 1, "api.New.n": 1}), _observation({})),
        plain_arms=(_observation({"api.A.b": 1, "api.New.n": 1}), _observation({})),
    )
    assert report["verdict"] == "PERTURBS"


def test_without_raw_arms_the_verdict_stays_conservative() -> None:
    """An absent explanation must not read as an innocent one."""
    report = compare_hook_fidelity(
        _subtraction({"api.A.b": 1}, label="hook"),
        _subtraction({"api.A.b": 1, "api.C.d": 1}, label="plain"),
    )
    assert report["verdict"] == "PERTURBS"
    assert report["classified"] is False
    assert report["instrument_footprint"] is None
    assert any("no raw arms supplied" in limit for limit in report["limits"])


def test_attribution_loss_renders_its_blind_spots() -> None:
    report = compare_hook_fidelity(
        _subtraction({"api.A.b": 1}, label="hook"),
        _subtraction({"api.A.b": 1, "api.W.n": 1}, label="plain"),
        hooked_arms=(
            _observation({"api.A.b": 1, "api.W.n": 1}), _observation({"api.W.n": 1})
        ),
        plain_arms=(_observation({"api.A.b": 1, "api.W.n": 1}), _observation({})),
    )
    text = render_fidelity(report)
    assert "ATTRIBUTION_LOSS" in text
    assert "blind spot" in text
    assert "raw surface is unchanged" in text


def test_dirty_subtraction_outranks_attribution_loss() -> None:
    report = compare_hook_fidelity(
        _subtraction({"api.A.b": 1}, label="hook", clean=False),
        _subtraction({"api.A.b": 1, "api.W.n": 1}, label="plain"),
        hooked_arms=(
            _observation({"api.A.b": 1, "api.W.n": 1}), _observation({"api.W.n": 1})
        ),
        plain_arms=(_observation({"api.A.b": 1, "api.W.n": 1}), _observation({})),
    )
    assert report["verdict"] == "UNUSABLE"


def test_fidelity_refuses_arms_from_different_scripts() -> None:
    a = _subtraction({"api.A.b": 1}, label="hook")
    b = _subtraction({"api.A.b": 1}, label="plain")
    b["arm_script_sha256_16"] = "0000000000000000"
    with pytest.raises(ContractError, match="same script"):
        compare_hook_fidelity(a, b)


def test_fidelity_refuses_non_subtraction_documents() -> None:
    with pytest.raises(ContractError, match="subtraction schema"):
        compare_hook_fidelity({"schema": "x/1"}, _subtraction({}, label="p"))


def test_fidelity_rejects_truthy_quality_and_malformed_raw_surfaces_without_echo() -> None:
    private = "private-fidelity-input-marker"
    hooked = _subtraction({"api.A.b": 1}, label="hook")
    plain = _subtraction({"api.A.b": 1}, label="plain")
    mutations = (
        ({**hooked, "clean_subtraction": private}, plain, None, None),
        ({**hooked, "only_in_arm": {"api.A.b": True}}, plain, None, None),
        ({**hooked, "arm_script_sha256_16": private}, plain, None, None),
        (hooked, plain, (_observation({"api.A.b": 1}),), None),
        (
            hooked,
            plain,
            (_observation({"api.A.b": True}), _observation({})),
            (_observation({"api.A.b": 1}), _observation({})),
        ),
    )
    for candidate_hooked, candidate_plain, hooked_arms, plain_arms in mutations:
        with pytest.raises(ContractError) as failure:
            compare_hook_fidelity(
                candidate_hooked,
                candidate_plain,
                hooked_arms=hooked_arms,  # type: ignore[arg-type]
                plain_arms=plain_arms,
            )
        assert private not in str(failure.value)


def test_fidelity_report_states_its_own_limits() -> None:
    surface = {"api.A.b": 1}
    report = compare_hook_fidelity(
        _subtraction(surface, label="hook"), _subtraction(dict(surface), label="plain")
    )
    assert report["limits"]
    text = render_fidelity(report)
    assert "TRANSPARENT" in text
    assert "note:" in text


def test_render_fidelity_rejects_a_foreign_document() -> None:
    with pytest.raises(ContractError):
        render_fidelity({"schema": FIDELITY_SCHEMA.replace("/1", "/9")})


def test_render_fidelity_requires_coherent_verdict_and_redacts_method_values() -> None:
    private = "private-fidelity-render-marker"
    report = compare_hook_fidelity(
        _subtraction({"api.A.b": 1}, label="hook"),
        _subtraction({"api.A.b": 1}, label="plain"),
    )
    assert "TRANSPARENT" in render_fidelity(report)
    mutations = (
        {**report, "private": private},
        {**report, "script_sha256_16": private},
        {**report, "with_hook_names": 2},
        {**report, "surface_delta": 1},
        {**report, "jaccard": 0.5},
        {**report, "jaccard": 10**400},
        {**report, "verdict": "PERTURBS"},
        {**report, "argument_evidence_usable": False},
        {**report, "limits": [private]},
    )
    for mutation in mutations:
        with pytest.raises(ContractError) as failure:
            render_fidelity(mutation)
        assert private not in str(failure.value)

    redacted = {
        **report,
        "method_mismatches": {
            "arm_dwell_seconds": {
                "with_hook": private,
                "without_hook": "different-private-value",
            }
        },
        "verdict": "UNUSABLE",
        "argument_evidence_usable": False,
    }
    rendered = render_fidelity(redacted)
    assert "arm_dwell_seconds" in rendered
    assert private not in rendered
    assert "different-private-value" not in rendered


# ------------------------------------------------------- realm cross-check


def _analysis(names: dict[str, int], coverage: dict[str, list[str]] | None = None) -> dict:
    return {
        "label": "arm",
        "analysis": {
            "events_by_name": names,
            "context_coverage": coverage or {},
        },
    }


def _capture_of(calls: dict[str, int]) -> dict:
    return parse_harvest(
        _harvest(
            [
                {
                    "name": n,
                    "calls": c,
                    "distinct": 1,
                    "dropped": 0,
                    "samples": [{"args": [], "count": c}],
                }
                for n, c in calls.items()
            ]
        )
    )


def test_zero_unaccounted_means_the_argument_list_is_complete() -> None:
    """The property that makes argument evidence a set rather than a sample.

    Measured on pin 1e88274539a68be0: addEventListener reads 18 from the hook and
    18 from the control-subtracted trace, so the 18 recorded event types are all of
    them -- not a lower bound.
    """
    report = cross_check_realms(
        _capture_of({"EventTarget.addEventListener": 18}),
        _analysis({"api.EventTarget.addEventListener": 96}, {"api.EventTarget.addEventListener": ["frame"]}),
        _analysis({"api.EventTarget.addEventListener": 78}),
    )
    row = report["rows"][0]
    assert row["trace_delta"] == 18
    assert row["unaccounted"] == 0
    assert row["worker_realm"] is False


def test_control_is_subtracted_before_reconciling() -> None:
    """Without subtracting the control the browser's own calls look like the
    sample's. Element.getAttribute reads 133 raw against 10 from the hook."""
    report = cross_check_realms(
        _capture_of({"Element.getAttribute": 10}),
        _analysis({"api.Element.getAttribute": 133}),
        _analysis({"api.Element.getAttribute": 123}),
    )
    assert report["rows"][0]["trace_delta"] == 10
    assert report["rows"][0]["unaccounted"] == 0


def test_worker_activity_shows_as_unaccounted_with_the_realm_flagged() -> None:
    report = cross_check_realms(
        _capture_of({"Performance.now": 2}),
        _analysis(
            {"api.Performance.now": 127},
            {"api.Performance.now": ["frame", "worker"]},
        ),
        _analysis({"api.Performance.now": 1}),
    )
    row = report["rows"][0]
    assert row["unaccounted"] == 124
    assert row["worker_realm"] is True


def test_ecmascript_builtins_are_marked_as_outside_the_trace() -> None:
    """The passive plane covers Web IDL only, so Function.toString has no trace
    counterpart. That is a coverage fact, not a missing measurement."""
    report = cross_check_realms(
        _capture_of({"Function.toString": 13}), _analysis({}), _analysis({})
    )
    row = report["rows"][0]
    assert row["trace_delta"] is None
    assert row["unaccounted"] is None
    assert "invisible to the passive trace" in row["note"]
    assert "outside the trace" in render_realms(report)


def test_worker_only_names_are_listed_even_though_the_hook_never_saw_them() -> None:
    report = cross_check_realms(
        _capture_of({}),
        _analysis(
            {"api.WorkerGlobalScope.fetch": 62},
            {"api.WorkerGlobalScope.fetch": ["worker"]},
        ),
        _analysis({}),
    )
    assert report["worker_realm_names"] == ["api.WorkerGlobalScope.fetch"]
    assert report["worker_realm_name_count"] == 1


def test_a_worker_name_the_control_also_produces_is_not_attributed() -> None:
    report = cross_check_realms(
        _capture_of({}),
        _analysis({"api.WorkerGlobalScope.fetch": 5}, {"api.WorkerGlobalScope.fetch": ["worker"]}),
        _analysis({"api.WorkerGlobalScope.fetch": 5}),
    )
    assert report["worker_realm_names"] == []


def test_realm_check_refuses_documents_without_analysis() -> None:
    with pytest.raises(ContractError, match="analysis"):
        cross_check_realms(_capture_of({}), {"label": "a"}, _analysis({}))


def test_realm_check_rejects_malformed_capture_and_trace_surfaces_without_echo() -> None:
    private = "private-realm-input-marker"
    capture = _capture_of({"Performance.now": 1})
    arm = _analysis({"api.Performance.now": 1})
    control = _analysis({})
    mutations = (
        ({**capture, "private": private}, arm, control),
        ({**capture, "total_calls": True}, arm, control),
        (capture, _analysis({private + "\n": 1}), control),
        (capture, _analysis({"api.Performance.now": True}), control),
        (
            capture,
            _analysis(
                {"api.Performance.now": 1},
                {"api.Performance.now": ["private"]},
            ),
            control,
        ),
    )
    for candidate_capture, candidate_arm, candidate_control in mutations:
        with pytest.raises(ContractError) as failure:
            cross_check_realms(candidate_capture, candidate_arm, candidate_control)
        assert private not in str(failure.value)


def test_realm_check_states_that_unaccounted_is_not_proof_of_a_worker() -> None:
    report = cross_check_realms(_capture_of({}), _analysis({}), _analysis({}))
    assert any("not proof of worker activity" in limit for limit in report["limits"])


def test_render_realms_requires_coherent_delta_and_worker_receipts() -> None:
    private = "private-realm-render-marker"
    report = cross_check_realms(
        _capture_of({"Performance.now": 2}),
        _analysis(
            {"api.Performance.now": 5},
            {"api.Performance.now": ["frame", "worker"]},
        ),
        _analysis({"api.Performance.now": 1}),
    )
    assert "frame+worker" in render_realms(report)
    row = report["rows"][0]
    mutations = (
        {**report, "private": private},
        {**report, "worker_realm_name_count": 99},
        {**report, "worker_realm_names": [private + "\n"]},
        {**report, "limits": [private]},
        {**report, "rows": [{**row, "name": private}]},
        {**report, "rows": [{**row, "unaccounted": 99}]},
        {**report, "rows": [{**row, "worker_realm": False}]},
        {**report, "rows": [{**row, "contexts": ["private"]}]},
    )
    for mutation in mutations:
        with pytest.raises(ContractError) as failure:
            render_realms(mutation)
        assert private not in str(failure.value)


# ------------------------------------------------------------- page-shape control


def test_hook_modes_are_the_three_expected() -> None:
    assert HOOK_MODES == ("off", "inert", "on")


def test_the_default_page_gained_the_startup_witness_and_nothing_else() -> None:
    """The archived shape was re-anchored deliberately on 2026-08-08.

    This test used to assert the default page was byte-identical to the shape every
    archived observation was taken against, on the reasoning that a second script
    tag would silently turn every cross-session comparison into a comparison of two
    different documents. That reasoning still holds, and the page still changed:
    without a witness installed before the sample, a run cannot tell a collector
    that ran quietly from one that threw on its first line, and two vendors in this
    monorepo differ on exactly that.

    The invariant was re-anchored against measurement rather than assumed away.
    Akamai's web pin attributes the identical 121 API names with and without the
    witness, symmetric difference 0, and three arms of the same bytes drift 0 from
    each other. What did change is `document.scripts.length`, from 1 to 2, and a
    collector that reads it would see the difference. That is recorded here rather
    than hidden, and it is why the witness binds its handlers by property
    assignment instead of making any WebIDL-bound call of its own.
    """
    from browser_core.product_observation import (
        DOM_PROFILES,
        PAGE_TITLE,
        _PAGE_HTML,
        _STARTUP_WITNESS,
        build_rehost_page,
    )

    expected = (
        '<!doctype html>\n<html lang="en"><head><meta charset="utf-8">'
        f"<title>{PAGE_TITLE}</title></head>\n<body>\n"
        f'{_STARTUP_WITNESS}{DOM_PROFILES["minimal"]}\n'
        '<script src="/product-script.js"></script>\n'
        "</body></html>\n"
    )
    rendered = _PAGE_HTML.format(
        title=PAGE_TITLE,
        witness=_STARTUP_WITNESS,
        body=DOM_PROFILES["minimal"],
        script_path="/product-script.js",
        prelude_tag="",
        declared_source_tag="",
        hook_tag="",
    )
    assert rendered == expected

    # The structural delta, stated so it cannot drift further unnoticed.
    assert build_rehost_page().decode("utf-8").count("<script") == 2


def test_inert_and_on_pages_have_the_same_shape() -> None:
    """The fidelity control compares `on` against `inert`, so the two documents
    must differ only in what the hook file contains."""
    from browser_core.product_observation import DOM_PROFILES, PAGE_TITLE, _PAGE_HTML

    tag = f'<script src="{HOOK_SCRIPT_PATH}"></script>\n'
    pages = {
        mode: _PAGE_HTML.format(
            title=PAGE_TITLE,
            witness="",
            body=DOM_PROFILES["minimal"],
            script_path="/product-script.js",
            prelude_tag="",
            declared_source_tag="",
            hook_tag=tag,
        )
        for mode in ("inert", "on")
    }
    assert pages["inert"] == pages["on"]


def test_handler_rejects_an_unknown_hook_mode() -> None:
    from browser_core.product_observation import _RequestLog, _handler

    with pytest.raises(ContractError, match="hook mode"):
        _handler(b"//", _RequestLog(), "minimal", "/s.js", "sideways")


def test_served_page_carries_the_hook_tag_only_when_instrumented() -> None:
    from browser_core.product_observation import build_rehost_page

    off = build_rehost_page(hook_mode="off")
    inert = build_rehost_page(hook_mode="inert")
    on = build_rehost_page(hook_mode="on")
    assert HOOK_SCRIPT_PATH.encode() not in off
    assert HOOK_SCRIPT_PATH.encode() in inert
    assert inert == on, "inert and on must be the same document"


def test_hook_payload_is_the_instrument_only_when_on() -> None:
    from browser_core.product_observation import build_hook_payload

    assert b"__bcArgs" in build_hook_payload("on")
    assert build_hook_payload("inert") == b""
    assert build_hook_payload("off") == b""


def test_page_builders_reject_unknown_modes_and_bad_paths() -> None:
    from browser_core.product_observation import build_hook_payload, build_rehost_page

    with pytest.raises(ContractError, match="hook mode"):
        build_rehost_page(hook_mode="sideways")
    with pytest.raises(ContractError, match="hook mode"):
        build_hook_payload("sideways")
    with pytest.raises(ContractError, match="dom profile"):
        build_rehost_page(dom_profile="enormous")
    with pytest.raises(ContractError, match="script path"):
        build_rehost_page(script_path="not-absolute.js")
    with pytest.raises(ContractError, match="script path"):
        build_rehost_page(script_path='/a".js')


def _serve_or_skip(handler, attempts: int = 8):
    """Bind the rehost server, or skip with a reason that is not a failure.

    Probing a *separate* socket first is not good enough and was tried: on
    2026-08-07 this host reached a state where roughly **1 of 20** bind attempts
    succeeded (`WinError 10055`, nonpaged pool -- with 16,384 free ports and 34 GB
    free RAM), so the probe would pass and the real bind moments later would fail.
    Retry the bind that actually matters, and only skip when every attempt fails.

    A test that cannot run must say so distinctly from a test that failed, or the
    noise eventually hides a real regression.
    """
    from http.server import ThreadingHTTPServer

    last: OSError | None = None
    for _ in range(attempts):
        try:
            return ThreadingHTTPServer(("127.0.0.1", 0), handler)
        except OSError as exc:
            last = exc
    pytest.skip(
        f"host cannot bind a loopback socket after {attempts} attempts ({last}); "
        "this is the one test here that genuinely needs one -- the rest were made "
        "socket-free on purpose"
    )


def _get_or_skip(url: str, attempts: int = 8) -> bytes:
    """Fetch over loopback, or skip. The client needs a socket too.

    Guarding only the server side was not enough: with the bind fixed by retries,
    the failure simply moved to `urlopen` creating its own socket. Both ends of a
    loopback request are subject to the same host condition.
    """
    import urllib.error
    import urllib.request

    last: Exception | None = None
    for _ in range(attempts):
        try:
            with urllib.request.urlopen(url, timeout=5) as response:
                return response.read()
        except (OSError, urllib.error.URLError) as exc:
            last = exc
    pytest.skip(f"host cannot open a loopback client socket ({last})")


def test_handler_serves_the_pages_it_was_built_with() -> None:
    """One end-to-end check that the pure builders are actually wired in.

    Deliberately the only socket-bound test here. Earlier versions bound a listener
    per assertion and failed under host resource pressure (`WinError 10055`) while
    testing questions that are really about strings.
    """
    from threading import Thread

    from browser_core.product_observation import (
        _RequestLog,
        _handler,
        build_rehost_page,
    )

    server = _serve_or_skip(
        _handler(b"// sample\n", _RequestLog(), "minimal", "/s.js", "on")
    )
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        base = f"http://127.0.0.1:{server.server_port}"
        page = _get_or_skip(base + "/")
        hook = _get_or_skip(base + HOOK_SCRIPT_PATH)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)

    assert page == build_rehost_page("minimal", "/s.js", "on")
    assert b"__bcArgs" in hook


# ------------------------------------------------------------------ arg corpus


def _cap(values: dict[str, list]) -> dict:
    return parse_harvest(
        _harvest(
            [
                {
                    "name": name,
                    "calls": len(args_list),
                    "distinct": len(args_list),
                    "dropped": 0,
                    "samples": [{"args": a, "count": 1} for a in args_list],
                }
                for name, args_list in values.items()
            ]
        )
    )


def test_argument_corpus_separates_shared_from_variable_values() -> None:
    """A value on every arm is a builder constant; one on some is roll churn."""
    from browser_core.argument_capture import argument_corpus

    report = argument_corpus(
        {
            "a": _cap({"EventTarget.addEventListener": [["mousemove"], ["click"]]}),
            "b": _cap({"EventTarget.addEventListener": [["mousemove"], ["keydown"]]}),
        }
    )
    row = report["rows"][0]
    assert row["universal"] is True
    assert row["shared_values"] == ['["mousemove"]']
    assert row["variable_count"] == 2


def test_argument_corpus_renders_values_from_many_valid_page_loads() -> None:
    from browser_core.argument_capture import argument_corpus

    name = "Window.matchMedia"
    harvests = []
    for load in range(31):
        samples = [
            {"args": [f"page-{load}-value-{index}"], "count": 1}
            for index in range(CAP_SAMPLES_PER_NAME)
        ]
        harvests.append(parse_harvest(_harvest([{
            "name": name,
            "calls": CAP_SAMPLES_PER_NAME,
            "distinct": CAP_SAMPLES_PER_NAME,
            "dropped": 0,
            "samples": samples,
        }])))
    capture = merge_harvests(harvests)
    report = argument_corpus({"arm": capture}, name=name)
    assert report["rows"][0]["shared_count"] == 31 * CAP_SAMPLES_PER_NAME
    text = render_argument_corpus(report)
    assert "more shared" in text
    assert len(text) < 5_000


def test_argument_corpus_focuses_one_name() -> None:
    from browser_core.argument_capture import argument_corpus

    report = argument_corpus(
        {
            "a": _cap(
                {
                    "Document.querySelector": [["1"]],
                    "Window.matchMedia": [["2"]],
                }
            )
        },
        name="Document.querySelector",
    )
    assert [r["name"] for r in report["rows"]] == ["Document.querySelector"]
    assert report["focus"] == "Document.querySelector"


def test_argument_corpus_marks_a_name_absent_from_some_arms() -> None:
    from browser_core.argument_capture import argument_corpus

    report = argument_corpus(
        {
            "a": _cap({"Document.querySelector": [["1"]]}),
            "b": _cap({"Window.matchMedia": [["2"]]}),
        }
    )
    rows = {r["name"]: r for r in report["rows"]}
    assert rows["Document.querySelector"]["universal"] is False
    assert rows["Document.querySelector"]["arms_present"] == 1
    assert rows["Document.querySelector"]["arms_total"] == 2


def test_argument_corpus_excludes_unusable_captures_and_says_so() -> None:
    """An absent capture is not an empty one, and must not dilute the shared set."""
    from browser_core.argument_capture import argument_corpus, render_argument_corpus

    report = argument_corpus(
        {
            "good": _cap({"Document.querySelector": [["1"]]}),
            "absent": parse_harvest(json.dumps({"absent": True})),
        }
    )
    assert report["excluded_unusable"] == ["absent"]
    assert report["arm_count"] == 1
    assert report["rows"][0]["universal"] is True
    assert "excluded 1 arm" in render_argument_corpus(report)


def test_argument_corpus_flags_mixed_observation_methods() -> None:
    from browser_core.argument_capture import argument_corpus, render_argument_corpus

    captures = {
        "a.json": _cap({"Document.querySelector": [["1"]]}),
        "b.json": _cap({"Document.querySelector": [["1"]]}),
    }
    observations = {
        "a.json": {
            "schema": "browser-core.product-script-observation/1",
            "analysis": {"events_by_name": {"api.Document.querySelector": 1}},
            "hook_mode": "on",
            "input_profile": "none",
        },
        "b.json": {
            "schema": "browser-core.product-script-observation/1",
            "analysis": {"events_by_name": {"api.Document.querySelector": 1}},
            "hook_mode": "on",
            "input_profile": "mouse-line",
        },
    }
    report = argument_corpus(captures, observations=observations)
    assert report["method_population"]["mixed_axes"] == ["input_profile"]
    assert "mixed execution method" in render_argument_corpus(report)


def test_argument_corpus_requires_method_document_for_every_usable_capture() -> None:
    from browser_core.argument_capture import argument_corpus

    with pytest.raises(ContractError, match="missing observation document"):
        argument_corpus(
            {"a": _cap({"Document.querySelector": [["1"]]})}, observations={}
        )


def test_argument_corpus_refuses_a_corpus_with_nothing_usable() -> None:
    from browser_core.argument_capture import argument_corpus

    with pytest.raises(ContractError, match="absent capture is not an empty one"):
        argument_corpus({"a": parse_harvest(json.dumps({"absent": True}))})


def test_argument_corpus_refuses_an_empty_corpus() -> None:
    from browser_core.argument_capture import argument_corpus

    with pytest.raises(ContractError, match="at least one capture"):
        argument_corpus({})


def test_argument_corpus_rejects_malformed_capture_population_without_echo() -> None:
    from browser_core.argument_capture import argument_corpus

    private = "private-corpus-capture-marker"
    valid = _cap({"Document.querySelector": [["form"]]})
    mutations = (
        {"a": {**valid, "private": private}},
        {"a": {**valid, "total_calls": True}},
        {"a": {**valid, "records": [{"private": private}]}},
        {"a": {**valid, "status": True}},
        {private + "\n": valid},
        {"bad\ud800": valid},
    )
    for population in mutations:
        with pytest.raises(ContractError) as failure:
            argument_corpus(population)
        assert private not in str(failure.value)

    with pytest.raises(ContractError, match="focus"):
        argument_corpus({"a": valid}, name=private)


def test_argument_corpus_keeps_a_falsy_argument_value() -> None:
    """Regression: an `and`-based filter dropped samples serialising to `[]` or `0`."""
    from browser_core.argument_capture import argument_corpus

    report = argument_corpus(
        {
            "a": _cap({"Document.querySelector": [[]]}),
            "b": _cap({"Document.querySelector": [[]]}),
        }
    )
    assert report["rows"][0]["shared_values"] == ["[]"]


def test_render_argument_corpus_rejects_a_foreign_document() -> None:
    with pytest.raises(ContractError):
        render_argument_corpus({"schema": "nope/1"})


def test_render_argument_corpus_requires_coherent_rows_and_verdicts() -> None:
    from browser_core.argument_capture import argument_corpus

    private = "private-corpus-render-marker"
    report = argument_corpus(
        {
            "a": _cap({"Document.querySelector": [["form"]]}),
            "b": _cap({"Document.querySelector": [["form"]]}),
        }
    )
    assert "arms=ALL" in render_argument_corpus(report)
    row = report["rows"][0]
    mutations = (
        {**report, "private": private},
        {**report, "arm_count": 3},
        {**report, "arms": ["b", "a"]},
        {**report, "focus": private},
        {**report, "rows": [{**row, "name": private}]},
        {**report, "rows": [{**row, "universal": False}]},
        {**report, "rows": [{**row, "shared_count": 2}]},
        {**report, "rows": [{**row, "shared_values": [private]}]},
        {
            **report,
            "failed_arms": [],
            "trustworthy_population": True,
        },
    )
    for mutation in mutations:
        with pytest.raises(ContractError) as failure:
            render_argument_corpus(mutation)
        assert private not in str(failure.value)


@pytest.mark.parametrize(
    ("renderer", "schema"),
    [
        (render_capture, CAPTURE_SCHEMA),
        (render_argument_corpus, ARG_CORPUS_SCHEMA),
        (render_realms, REALM_SCHEMA),
        (render_fidelity, FIDELITY_SCHEMA),
    ],
)
def test_argument_renderers_reject_sparse_and_private_foreign_artifacts(
    renderer,
    schema: str,
) -> None:
    private = "private-renderer-schema-marker"
    for document in ({"schema": schema}, {"schema": private}, ["not", "an", "object"]):
        with pytest.raises(ContractError) as failure:
            renderer(document)
        assert private not in str(failure.value)


@pytest.mark.parametrize("value", [True, -1, 101, 1.5, "12"])
def test_bounded_argument_renderers_reject_invalid_limits(value) -> None:
    capture = parse_harvest(json.dumps({"absent": True}))
    with pytest.raises(ContractError, match="limit is invalid"):
        render_capture(capture, limit=value)

    report = {
        "schema": ARG_CORPUS_SCHEMA,
        "arms": [],
        "arm_count": 0,
        "excluded_unusable": [],
        "method_population": {},
        "focus": None,
        "rows": [],
    }
    with pytest.raises(ContractError, match="limit is invalid"):
        render_argument_corpus(report, limit=value)
