from __future__ import annotations

import hashlib
import io
import json
import os
import re
import socket
import subprocess
import threading
import time
from email.message import Message
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from types import SimpleNamespace

import pytest

import browser_core.product_observation as product_observation
from browser_core.contracts import ContractError
from browser_core.product_observation import (
    BASELINE_SCHEMA,
    DOM_PROFILES,
    IDENTITY_SCHEMA,
    OBSERVATION_SCHEMA,
    PAGE_TITLE,
    MAX_REHOST_POST_BODY_BYTES,
    REQUEST_BODY_CHUNK_BYTES,
    SUBTRACTION_SCHEMA,
    _RequestLog,
    _handler,
    _driver_error_metadata,
    _driver_result_metadata,
    _ready_expression_metadata,
    _sanitize_ambient_input_report,
    _sanitize_await_report,
    _sanitize_offline_guard,
    _sanitize_source_provenance,
    _sanitize_geometry_document,
    _stage_route_metadata,
    _sanitize_startup_document,
    _surface_method,
    _prelude_metadata,
    build_surface_baseline,
    build_repeated_surface_baseline,
    check_surface_drift,
    analyse_observation_trace,
    DEFAULT_SCRIPT_PATH,
    build_rehost_page,
    classify_product_script,
    grade_ambient_input,
    grade_collector_startup,
    grade_public_source_provenance,
    grade_git_source_provenance,
    grade_unserved_requests,
    project_server_request_activity,
    suggest_driver,
    subtract_resource_intents,
    subtract_request_activity,
    await_collector_ready,
    compare_surfaces,
    load_observation,
    subtract_control,
    write_observation,
)


# ------------------------------------------------------------------ identity guard


def _built_antibot_like(bmak: int = 41) -> bytes:
    # One machine-generated line: large, string-table heavy, no arrow functions.
    body = "function a(){var x='" + ("z" * 60_000) + "';}" * 4
    body += "function b(){}" * 400
    body += ("bmak" * bmak) if bmak else ""
    body += "'" * 1200
    return body.encode("utf-8")


def _app_bundle_like() -> bytes:
    lines = ["const f = () => 1;" for _ in range(2000)]
    lines += ["function g(){ return crypto.randomUUID(); }" for _ in range(300)]
    return "\n".join(lines).encode("utf-8")


def test_built_antibot_script_is_recognised() -> None:
    verdict = classify_product_script(_built_antibot_like())
    assert verdict["looks_like_built_antibot_script"] is True
    assert verdict["reasons"] == []
    assert verdict["vendor_hint"] == "akamai-bmp-web"
    assert verdict["signals"]["arrow_functions"] == 0


@pytest.mark.parametrize(
    "literal",
    ["é" * 25_000, "x" * 30_000 + "\u2028" + "x" * 30_000],
    ids=["multibyte", "unicode-separator"],
)
def test_classifier_measures_physical_utf8_line_bytes(literal: str) -> None:
    payload = ("var x='" + literal + "';").encode("utf-8")
    verdict = classify_product_script(payload)

    assert verdict["signals"]["max_line_bytes"] == len(payload)
    assert "no single machine-generated line" not in verdict["reasons"]


@pytest.mark.parametrize(
    "payload", [None, True, 1, 1.5, "script", bytearray(b"script"), [], {}, ()]
)
def test_classifier_rejects_non_byte_payloads_cleanly(payload) -> None:
    with pytest.raises(ContractError, match="bounded bytes"):
        classify_product_script(payload)


def test_application_bundle_is_rejected_even_when_named_like_a_script() -> None:
    """The tree has held a `bm-script.js` that was really an app bundle."""
    verdict = classify_product_script(_app_bundle_like())
    assert verdict["looks_like_built_antibot_script"] is False
    assert verdict["vendor_hint"] is None
    assert any("arrow functions" in reason for reason in verdict["reasons"])
    assert any("machine-generated line" in reason for reason in verdict["reasons"])


def test_small_file_is_rejected() -> None:
    verdict = classify_product_script(b"console.log(1)")
    assert verdict["looks_like_built_antibot_script"] is False
    assert any("smaller than" in reason for reason in verdict["reasons"])


def test_small_geetest_v4_bootstrap_loader_is_recognised_by_conjoined_markers() -> None:
    payload = (
        '"v4.2.1 Geetest Inc.";\n'
        '(function(window){"use strict";\n'
        "if(typeof window==='undefined'){throw new Error('Geetest requires browser environment');}\n"
        "window.initGeetest4=function(options,callback){\n"
        "var endpoint='https://static.geetest.com/gcaptcha4/load';\n"
        "return endpoint+options.captchaId+String(callback);\n"
        "};\n})(window);\n" + ("// readable loader padding\n" * 400)
    ).encode("utf-8")

    verdict = classify_product_script(payload)

    assert 8_000 <= len(payload) < 50_000
    assert verdict["signals"]["max_line_bytes"] < 50_000
    assert verdict["signals"]["geetest_loader_markers"] == 6
    assert verdict["looks_like_built_antibot_script"] is True
    assert verdict["vendor_hint"] == "geetest-v4-loader"


def test_one_geetest_vendor_marker_does_not_override_the_small_script_guard() -> None:
    verdict = classify_product_script(b"window.initGeetest4 = function () {};")

    assert verdict["looks_like_built_antibot_script"] is False
    assert verdict["vendor_hint"] is None


def test_compact_anubis_challenge_entry_is_recognised_by_conjoined_markers() -> None:
    payload = (
        "(()=>{window.__anubisBooted=true;"
        "const c='anubis_challenge';"
        "console.warn('anubis: could not pre-fetch worker source');"
        "console.debug('anubis: main.mjs already running');"
        "const p='/.within.website/x/cmd/anubis/';"
        "location.replace(p+'api/pass-challenge');})();" + ("x" * 7_200)
    ).encode("utf-8")

    verdict = classify_product_script(payload)

    assert 7_000 <= len(payload) < 50_000
    assert verdict["signals"]["anubis_challenge_markers"] == 6
    assert verdict["looks_like_built_antibot_script"] is True
    assert verdict["vendor_hint"] == "anubis-web-challenge"


def test_one_anubis_runtime_marker_does_not_override_the_small_script_guard() -> None:
    verdict = classify_product_script(b"window.__anubisBooted = true;")

    assert verdict["looks_like_built_antibot_script"] is False
    assert verdict["vendor_hint"] is None


def test_identity_reports_stable_digest() -> None:
    payload = _built_antibot_like()
    first = classify_product_script(payload)
    second = classify_product_script(payload)
    assert first["signals"]["sha256_16"] == second["signals"]["sha256_16"]
    assert len(first["signals"]["sha256_16"]) == 16


def test_absent_vendor_literal_does_not_reject_the_script() -> None:
    """Absence of `bmak` only means this roll did not leak the global name."""
    verdict = classify_product_script(_built_antibot_like(bmak=0))
    assert verdict["looks_like_built_antibot_script"] is True
    assert verdict["vendor_hint"] is None


# -- the veto that hid a whole vendor -----------------------------------------
#
# The identity guard used to reject anything with fewer than 200 `function`
# keywords. That number encodes one obfuscator's habits, and it made every Kasada
# script in this monorepo's corpus invisible -- 8 of 8 across two capture
# directories -- while passing Akamai's. Invisible is the worse failure of the
# two: a misread file gets argued about, a rejected one is never looked at.


def _kasada_like(kpsdk: int = 2) -> bytes:
    """One machine-generated line whose bindings are nearly all unique.

    Modelled on the measured shape of the real script rather than invented: 542 KB
    in a single line, 76 `function` keywords, a 0.63 distinct-identifier ratio, and
    no module-system marker anywhere.
    """
    body = "function k(){" + ";".join(f"var v{i}=w{i}" for i in range(8000)) + "}"
    body += "function j(){}" * 75
    body += ("KPSDK" * kpsdk) if kpsdk else ""
    return body.encode("utf-8")


def _next_chunk_like() -> bytes:
    """A Next.js chunk: one long machine-generated line, but a bundler made it."""
    body = "(self.__next_f=self.__next_f||[]).push([1,'" + ("q" * 60_000) + "']);"
    body += "function m(){}" * 500
    return body.encode("utf-8")


def test_a_collector_that_renames_every_binding_is_still_a_collector() -> None:
    verdict = classify_product_script(_kasada_like())
    assert verdict["looks_like_built_antibot_script"] is True, verdict["reasons"]
    assert verdict["vendor_hint"] == "kasada"
    # The property that broke the old veto, pinned so the regression is legible.
    assert verdict["signals"]["function_keywords"] < 200
    assert verdict["signals"]["distinct_identifier_ratio"] > 0.4


def test_the_two_collector_shapes_sit_at_opposite_ends_of_one_signal() -> None:
    """Both are built collectors; neither keyword count nor entropy alone sorts them.

    This is why the ratio is reported and not used as a veto: a rule keyed on it
    would exclude Akamai exactly as the keyword floor excluded Kasada.
    """
    akamai = classify_product_script(_built_antibot_like())
    kasada = classify_product_script(_kasada_like())
    assert akamai["looks_like_built_antibot_script"] is True
    assert kasada["looks_like_built_antibot_script"] is True
    assert akamai["signals"]["function_keywords"] > 200
    assert kasada["signals"]["function_keywords"] < 200
    assert (
        akamai["signals"]["distinct_identifier_ratio"]
        < kasada["signals"]["distinct_identifier_ratio"]
    )


def test_a_bundler_artifact_is_rejected_however_machine_generated_it_looks() -> None:
    """The replacement veto, and the one the old rule got backwards.

    A Next.js chunk and Stripe's v3.js both pass every structural test the old
    guard applied -- long generated line, few arrows, thousands of `function`
    keywords -- so the keyword floor called them collectors. A collector ships
    standalone because it must run before the application it protects; a bundle
    cannot avoid leaving a module-system marker.
    """
    verdict = classify_product_script(_next_chunk_like())
    assert verdict["looks_like_built_antibot_script"] is False
    assert any("bundler artifact" in reason for reason in verdict["reasons"])


def test_a_kasada_roll_that_leaks_no_vendor_literal_is_still_recognised() -> None:
    """`KPSDK` appears twice in a 542 KB script, so the hint has to stay a hint."""
    verdict = classify_product_script(_kasada_like(kpsdk=0))
    assert verdict["looks_like_built_antibot_script"] is True
    assert verdict["vendor_hint"] is None


# -- did the collector actually start? ----------------------------------------
#
# An offline rehost drives a bare page, which fully exercises a collector that
# starts itself and cannot exercise one that waits to be driven. Both produce a
# surface; only one of them is a measurement of the collector. Measured on two
# vendors:
#
#   Akamai bm-script.js  installs `bmak` on load, reaches 121 attributable names
#   Kasada ips.js        throws `KPSDK is not defined` -- it is the second stage
#   Kasada p.js          installs KPSDK = {configure, isReady}, isReady() false,
#                        makes no network request at all, reaches 6 names
#
# Before this, all three read the same way in every artifact the run produced.


def test_a_collector_that_threw_is_not_reported_as_a_quiet_one() -> None:
    """The Kasada ips.js case: 0 attributable names because it never ran."""
    verdict = grade_collector_startup(
        {
            "uncaught_errors": ["Uncaught ReferenceError: KPSDK is not defined"],
            "unhandled_rejections": [],
            "vendor_globals": [],
            "vendor_reports_ready": None,
        },
        attributable_events=0,
    )
    assert verdict["started"] is False
    assert any("ReferenceError; diagnostic_sha256_16=" in reason for reason in verdict["reasons"])
    assert "KPSDK is not defined" not in json.dumps(verdict)


def test_a_client_that_says_it_is_not_ready_is_believed() -> None:
    """The Kasada p.js case: it loaded cleanly and is still inert.

    `KPSDK.isReady()` answers false until the protected page calls `configure`,
    and a bare rehost page never does. No error, a vendor global present, and a
    surface of six names -- which without this reads as a successful observation
    of a collector that barely does anything.
    """
    verdict = grade_collector_startup(
        {
            "uncaught_errors": [],
            "unhandled_rejections": [],
            "vendor_globals": ["KPSDK"],
            "vendor_reports_ready": False,
        },
        attributable_events=6,
    )
    assert verdict["started"] is False
    assert any("not ready" in reason for reason in verdict["reasons"])


def test_a_self_starting_collector_grades_as_started() -> None:
    verdict = grade_collector_startup(
        {
            "uncaught_errors": [],
            "unhandled_rejections": [],
            "vendor_globals": ["bmak"],
            "vendor_reports_ready": None,
        },
        attributable_events=121,
    )
    assert verdict["started"] is True
    assert verdict["reasons"] == []


@pytest.mark.parametrize(
    "missing_field",
    [
        "uncaught_errors",
        "unhandled_rejections",
        "vendor_globals",
        "vendor_reports_ready",
    ],
)
def test_incomplete_startup_witness_does_not_grade_as_started(
    missing_field: str,
) -> None:
    startup = {
        "uncaught_errors": [],
        "unhandled_rejections": [],
        "vendor_globals": ["KPSDK"],
        "vendor_reports_ready": True,
    }
    startup.pop(missing_field)

    verdict = grade_collector_startup(startup, attributable_events=6)

    assert verdict["started"] is None
    assert verdict["reasons"] == ["startup witness is incomplete or invalid"]


@pytest.mark.parametrize(
    ("field", "malformed"),
    [
        ("uncaught_errors", "hidden errors"),
        ("unhandled_rejections", {"private": "rejection"}),
        ("vendor_globals", "KPSDK"),
        ("vendor_globals", [{"private": "global"}]),
        ("vendor_globals", ["PrivateTenant"]),
        ("vendor_globals", ["KPSDK", "PrivateTenant"]),
        ("vendor_reports_ready", "private-ready"),
    ],
)
def test_malformed_startup_witness_does_not_grade_as_started(
    field: str, malformed,
) -> None:
    startup = {
        "uncaught_errors": [],
        "unhandled_rejections": [],
        "vendor_globals": ["KPSDK"],
        "vendor_reports_ready": True,
    }
    startup[field] = malformed

    verdict = grade_collector_startup(startup, attributable_events=6)

    assert verdict["started"] is None
    assert verdict["reasons"] == ["startup witness is incomplete or invalid"]
    assert "private" not in json.dumps(verdict)


def test_recognized_vendor_prefix_remains_a_valid_startup_witness() -> None:
    verdict = grade_collector_startup(
        {
            "uncaught_errors": [],
            "unhandled_rejections": [],
            "vendor_globals": ["_pxPrivateTenant"],
            "vendor_reports_ready": True,
        },
        attributable_events=6,
    )

    assert verdict["started"] is True
    assert verdict["vendor_globals"] == ["_px*"]


def test_anubis_load_marker_without_a_worker_is_not_started() -> None:
    startup = {
        "uncaught_errors": [],
        "unhandled_rejections": [],
        "vendor_globals": ["__anubisBooted"],
        "vendor_reports_ready": None,
    }

    stopped = grade_collector_startup(
        startup,
        attributable_events=14,
        execution_context_counts={
            "generated_binding": {"worker": 0},
            "native": {"worker": 0},
        },
    )
    running = grade_collector_startup(
        startup,
        attributable_events=30,
        execution_context_counts={
            "generated_binding": {"worker": 1},
            "native": {"worker": 1},
        },
    )

    assert stopped["started"] is False
    assert "module-load marker" in stopped["reasons"][0]
    assert running["started"] is True


@pytest.mark.parametrize("global_name", ["initGeetest4", "__anubisBooted"])
def test_startup_witness_includes_the_new_public_targets(global_name: str) -> None:
    import browser_core.product_observation as po

    assert global_name in po._STARTUP_JS


def test_a_missing_probe_is_unknown_rather_than_started() -> None:
    """A verdict must never be manufactured out of a failed measurement."""
    verdict = grade_collector_startup(None, attributable_events=0)
    assert verdict["started"] is None


def test_a_silent_arm_with_no_vendor_global_is_not_called_started() -> None:
    verdict = grade_collector_startup(
        {
            "uncaught_errors": [],
            "unhandled_rejections": [],
            "vendor_globals": [],
            "vendor_reports_ready": None,
        },
        attributable_events=0,
    )
    assert verdict["started"] is False


# -- ambient input -------------------------------------------------------------


def test_a_mouse_that_crossed_the_window_is_reported() -> None:
    """Found, not anticipated.

    One headed arm reported 128 attributable names where three later arms of the
    same bytes reported 121. The seven extra were MouseEvent.constructor,
    isTrusted, pageX, pageY, toElement, Document.activeElement and
    HTMLFormElement.constructor. Both runs recorded input_profile "none" and a
    clean subtraction, and nothing said a mouse had been over the window --
    which matters most for a collector whose whole business is event authenticity.
    """
    verdict = grade_ambient_input(
        {"ambient_input": {"mousemove": 14, "click": 1}}, input_profile="none"
    )
    assert verdict["contaminated"] is True
    assert "mousemove=14" in verdict["reasons"][0]


def test_input_the_run_asked_for_is_not_contamination() -> None:
    verdict = grade_ambient_input(
        {"ambient_input": {"mousemove": 12, "keydown": 2}}, input_profile="probe"
    )
    assert verdict["contaminated"] is False
    assert verdict["events"] == {"mousemove": 12, "keydown": 2}


def test_an_undisturbed_arm_is_clean() -> None:
    verdict = grade_ambient_input({"ambient_input": {}}, input_profile="none")
    assert verdict["contaminated"] is False
    assert verdict["reasons"] == []


@pytest.mark.parametrize(
    "startup",
    [
        {},
        {"ambient_input": None},
        {"ambient_input": "missing"},
        {"ambient_input": {"click": -1}},
        {"ambient_input": {"private": 1}},
    ],
)
def test_ambient_grade_does_not_call_missing_or_malformed_witness_clean(startup) -> None:
    verdict = grade_ambient_input(startup, input_profile="none")

    assert verdict["contaminated"] is None
    assert verdict["reasons"]


def test_ambient_input_is_reported_never_corrected() -> None:
    """A count is a fact about the run; what a contaminated arm is worth is the
    reader's call, and silently dropping the events would destroy the evidence."""
    verdict = grade_ambient_input({"ambient_input": {"click": 3}}, input_profile="none")
    assert verdict["events"] == {"click": 3}


def test_the_witness_installs_before_the_product_script() -> None:
    """Ordering is the whole point: a listener installed afterwards catches nothing."""
    page = build_rehost_page().decode("utf-8")
    assert page.index("__bc_startup") < page.index(DEFAULT_SCRIPT_PATH)


def test_the_witness_binds_handlers_by_property_not_by_addeventlistener() -> None:
    """addEventListener is WebIDL-bound, so a witness using it lands in the trace
    of every arm including the control that gets subtracted."""
    import re as _re

    page = build_rehost_page().decode("utf-8")
    witness = page[: page.index(DEFAULT_SCRIPT_PATH)]
    # Comments are allowed to name it -- one of them explains why it is avoided.
    code = _re.sub(r"//.*", "", witness)
    assert "addEventListener" not in code
    assert "window.onerror" in code


def test_rehost_contract_changes_when_built_in_witness_bytes_change(
    monkeypatch,
) -> None:
    import browser_core.product_observation as po

    baseline = po.build_rehost_contract()
    assert baseline == po.build_rehost_contract()
    monkeypatch.setattr(po, "_STARTUP_WITNESS", po._STARTUP_WITNESS + "\n<!-- v2 -->")
    changed = po.build_rehost_contract()

    assert baseline["schema"] == po.REHOST_CONTRACT_SCHEMA
    assert len(baseline["sha256"]) == 64
    assert changed["sha256"] != baseline["sha256"]
    assert changed["page_sha256"] != baseline["page_sha256"]


def test_rehost_contract_binds_input_probe_catalog_version(monkeypatch) -> None:
    import browser_core.product_observation as po

    baseline = po.build_rehost_contract()
    monkeypatch.setitem(
        po.INPUT_PROBE_CONTRACTS,
        "probe-touch",
        "browser-core.input-probe/touch/2",
    )
    changed = po.build_rehost_contract()

    assert changed["sha256"] != baseline["sha256"]
    assert (
        changed["input_probe_catalog_sha256"] != baseline["input_probe_catalog_sha256"]
    )


def test_rehost_contract_names_count_preserving_resource_projection() -> None:
    import browser_core.product_observation as po

    contract = po.build_rehost_contract()

    assert po.RESOURCE_INTENT_CONTRACT == "cdp_dom_snapshot/2"
    assert contract["resource_intent_contract"] == po.RESOURCE_INTENT_CONTRACT


def test_rehost_contract_sanitizer_rejects_identifier_shaped_private_contracts() -> (
    None
):
    contract = product_observation.build_rehost_contract()
    contract["observer_sequence"] = "private.vendor-observer/9"
    contract["resource_intent_contract"] = "private_dom_snapshot/9"

    projected = product_observation._sanitize_rehost_contract(contract)

    assert projected["status"] == "unverifiable"
    assert "private" not in json.dumps(projected)


def test_a_declared_source_url_is_visible_but_not_an_executable_tag() -> None:
    """A URL-sensitive loader may inspect the source without the lab fetching it."""
    source = "https://challenges.cloudflare.com/turnstile/v0/api.js"
    page = build_rehost_page(declared_script_url=source).decode("utf-8")
    declared = page.index('data-browser-core-declared-source="true"')
    actual = page.index(f'src="{DEFAULT_SCRIPT_PATH}"')
    assert declared < actual
    assert f'src="{source}"' in page
    assert '<script type="application/json"' in page


def test_a_declared_source_url_stays_https_and_external() -> None:
    with pytest.raises(ContractError, match="credential-free HTTPS"):
        build_rehost_page(declared_script_url="http://127.0.0.1/vendor.js")
    with pytest.raises(ContractError, match="inline packaging"):
        build_rehost_page(
            declared_script_url="https://example.test/vendor.js",
            inline_source=b"console.log(1)",
        )
    with pytest.raises(ContractError, match="credential-free"):
        build_rehost_page(
            declared_script_url="https://user:password@example.test/vendor.js"
        )


def test_rehost_page_validation_errors_do_not_echo_private_paths_or_urls() -> None:
    private_path = "/private tenant/value?token=secret"
    private_url = "https://user:secret@example.test/private?token=secret"

    with pytest.raises(ContractError) as path_error:
        build_rehost_page(script_path=private_path)
    with pytest.raises(ContractError) as url_error:
        build_rehost_page(declared_script_url=private_url)

    assert all(
        private not in str(error.value)
        for private, error in (
            (private_path, path_error),
            (private_url, url_error),
        )
    )
    assert "secret" not in str(path_error.value)
    assert "secret" not in str(url_error.value)


@pytest.mark.parametrize(
    "declared_url",
    [
        "https://[::1",
        "https://example.test:99999/script.js",
        "https://example.test/line\nbreak.js",
        "https://example.test/\ud800",
        "https://example.test/" + "x" * 16_384,
        "https://vendor.example\\@other.example/script.js",
        "https://2130706433/script.js",
        "https://faß.example/script.js",
    ],
)
def test_rehost_page_rejects_malformed_or_overlong_declared_urls_cleanly(
    declared_url,
) -> None:
    with pytest.raises(ContractError, match="credential-free HTTPS") as error:
        build_rehost_page(declared_script_url=declared_url)

    assert declared_url not in str(error.value)


def test_a_prelude_runs_before_the_product_without_being_retained() -> None:
    setup = "window.ddoptions={endpoint:'/configured-js/'}"
    page = build_rehost_page(prelude_js=setup).decode("utf-8")
    assert page.index(setup) < page.index(f'src="{DEFAULT_SCRIPT_PATH}"')
    metadata = _prelude_metadata(setup)
    assert metadata["supplied"] is True
    assert metadata["bytes"] == len(setup.encode("utf-8"))
    assert metadata["sha256_16"]
    assert "ddoptions" not in json.dumps(metadata)


def test_a_prelude_that_would_truncate_its_tag_is_refused() -> None:
    with pytest.raises(ContractError, match="truncate"):
        build_rehost_page(prelude_js="window.x='</script>'")


def test_prelude_limit_counts_utf8_bytes_not_python_characters() -> None:
    assert build_rehost_page(prelude_js="😀" * 64_000)
    with pytest.raises(ContractError, match="256000 bytes"):
        build_rehost_page(prelude_js="😀" * 64_001)


def test_embedded_method_source_refuses_unencodable_text() -> None:
    with pytest.raises(ContractError, match="valid UTF-8"):
        build_rehost_page(prelude_js="\ud800")


def test_inline_source_refuses_replacement_decoding() -> None:
    with pytest.raises(ContractError, match="valid UTF-8 source"):
        build_rehost_page(inline_source=b"const x = '\xff';")


@pytest.mark.parametrize("dom_profile", [None, True, 1, 1.5, [], {}, ()])
def test_rehost_page_rejects_malformed_dom_profiles_cleanly(dom_profile) -> None:
    with pytest.raises(ContractError, match="dom profile must be one of"):
        build_rehost_page(dom_profile=dom_profile)


@pytest.mark.parametrize("hook_mode", [None, True, 1, 1.5, [], {}, ()])
def test_rehost_page_rejects_malformed_hook_modes_cleanly(hook_mode) -> None:
    with pytest.raises(ContractError, match="hook mode must be one of"):
        build_rehost_page(hook_mode=hook_mode)


@pytest.mark.parametrize("inline_source", [True, 1, 1.5, "source", [], {}, ()])
def test_rehost_page_rejects_non_byte_inline_sources_cleanly(inline_source) -> None:
    with pytest.raises(ContractError, match="source must be bytes or null"):
        build_rehost_page(inline_source=inline_source)


@pytest.mark.parametrize("declared_url", [True, 1, 1.5, [], {}, ()])
def test_rehost_page_rejects_non_text_declared_urls_cleanly(declared_url) -> None:
    with pytest.raises(ContractError, match="URL must be text or null"):
        build_rehost_page(declared_script_url=declared_url)


def test_driver_result_keeps_shape_but_not_a_returned_token() -> None:
    token = "private-challenge-token-0123456789"
    metadata = _driver_result_metadata(token)
    assert metadata == {
        "status": "ok",
        "type": "string",
        "serialized_bytes": len(json.dumps(token).encode("utf-8")),
        "length": len(token),
    }
    assert token not in json.dumps(metadata)


def test_driver_result_reduces_non_utf8_text_to_shape() -> None:
    metadata = _driver_result_metadata("\ud800")

    assert metadata == {
        "status": "ok",
        "type": "string",
        "serialized_bytes": None,
        "length": 1,
    }
    json.dumps(metadata, ensure_ascii=False).encode("utf-8")


def test_driver_result_reduces_extreme_nesting_to_shape() -> None:
    deeply_nested: object = 0
    for _ in range(2_000):
        deeply_nested = [deeply_nested]

    assert _driver_result_metadata(deeply_nested) == {
        "status": "ok",
        "type": "array",
        "serialized_bytes": None,
        "length": 1,
    }


def test_driver_error_redacts_page_controlled_fragments() -> None:
    metadata = _driver_error_metadata(
        ContractError(
            "CDP evaluate returned an error object (TypeError: reading "
            "'privateTenantProperty' at https://tenant.example/private)"
        )
    )
    rendered = json.dumps(metadata)
    assert metadata["status"] == "failed"
    assert "privateTenantProperty" not in rendered
    assert "tenant.example" not in rendered
    assert "TypeError" in rendered


def test_diagnostic_receipts_drop_short_paths_emails_and_page_values() -> None:
    import browser_core.product_observation as po

    private_values = [
        r"C:\u\x.js",
        "/p/x.js",
        "a@b.co",
        "tiny-token",
        "tenant.example",
    ]
    receipt = po._failure_receipt(
        "trace export failed",
        ContractError("TypeError: " + " | ".join(private_values)),
    )

    assert receipt.startswith("trace export failed: TypeError;")
    assert all(value not in receipt for value in private_values)
    assert re.search(r"diagnostic_sha256_16=[0-9a-f]{16}$", receipt)


def test_diagnostic_projection_is_idempotent() -> None:
    import browser_core.product_observation as po

    projected = po._redact_diagnostic("TypeError: private value")
    assert po._redact_diagnostic(projected) == projected


def test_startup_errors_keep_diagnostic_class_but_not_page_values() -> None:
    startup = _sanitize_startup_document(
        {
            "uncaught_errors": [
                "TypeError: tenant 'private-key-12345678' failed at "
                "https://tenant.example/private"
            ],
            "unhandled_rejections": ["rejected opaque_token_1234567890"],
            "probe_error": "TypeError: tenant 'probe-private-key-12345678' failed",
            "vendor_globals": ["turnstile"],
        }
    )
    rendered = json.dumps(startup)
    assert "TypeError" in rendered
    assert startup["vendor_globals"] == ["turnstile"]
    assert "private-key" not in rendered
    assert "tenant.example" not in rendered
    assert "opaque_token" not in rendered
    assert "probe-private-key" not in rendered


def test_startup_capture_sanitizes_page_output_before_return(monkeypatch) -> None:
    import browser_core.product_observation as po

    private = r"C:\u\x.js"
    monkeypatch.setattr(
        po,
        "evaluate_page_expression",
        lambda *args, **kwargs: json.dumps(
            {
                "uncaught_errors": [f"TypeError: {private}"],
                "unhandled_rejections": [],
                "ambient_input": {},
                "vendor_globals": ["turnstile"],
                "vendor_reports_ready": None,
                "window_properties": 100,
                "window_properties_before_script": 90,
            }
        ),
    )

    captured = po._capture_startup("http://127.0.0.1:1", "http://127.0.0.1", 1.0)

    assert private not in json.dumps(captured)
    assert captured["uncaught_errors"][0].startswith("TypeError;")


@pytest.mark.parametrize(
    "ambient_input",
    [None, "missing witness", {"click": -1}, {"click": True}, {"private": 1}],
)
def test_startup_capture_does_not_grade_malformed_ambient_witness_cleanly(
    monkeypatch, ambient_input,
) -> None:
    import browser_core.product_observation as po

    monkeypatch.setattr(
        po,
        "evaluate_page_expression",
        lambda *_args, **_kwargs: json.dumps(
            {
                "uncaught_errors": [],
                "unhandled_rejections": [],
                "ambient_input": ambient_input,
                "vendor_globals": ["KPSDK"],
                "vendor_reports_ready": True,
                "window_properties": 100,
                "window_properties_before_script": 90,
            }
        ),
    )
    monkeypatch.setattr(
        po,
        "probe_managed_page_target",
        lambda *_args, **_kwargs: {"status": "present", "title_matches": True},
    )

    captured = po._capture_startup("http://127.0.0.1:1", "http://127.0.0.1", 1.0)

    assert captured is not None and "probe_error" in captured
    assert grade_ambient_input(captured, "none")["contaminated"] is None
    assert grade_collector_startup(captured, 6)["started"] is None


@pytest.mark.parametrize(
    ("error_field", "malformed"),
    [("uncaught_errors", "hidden error"), ("unhandled_rejections", {"hidden": 1})],
)
def test_startup_capture_does_not_drop_malformed_error_witness(
    monkeypatch, error_field: str, malformed,
) -> None:
    import browser_core.product_observation as po

    document = {
        "uncaught_errors": [],
        "unhandled_rejections": [],
        "ambient_input": {},
        "vendor_globals": ["KPSDK"],
        "vendor_reports_ready": True,
        "window_properties": 100,
        "window_properties_before_script": 90,
    }
    document[error_field] = malformed
    monkeypatch.setattr(
        po,
        "evaluate_page_expression",
        lambda *_args, **_kwargs: json.dumps(document),
    )
    monkeypatch.setattr(
        po,
        "probe_managed_page_target",
        lambda *_args, **_kwargs: {"status": "present", "title_matches": True},
    )

    captured = po._capture_startup("http://127.0.0.1:1", "http://127.0.0.1", 1.0)

    assert captured is not None and "probe_error" in captured
    assert grade_collector_startup(captured, 6)["started"] is None


@pytest.mark.parametrize(
    ("field", "malformed", "remove"),
    [
        ("vendor_globals", "KPSDK", False),
        ("vendor_globals", [{"private": "global"}], False),
        ("vendor_globals", ["PrivateTenant"], False),
        ("vendor_globals", ["KPSDK", "PrivateTenant"], False),
        ("vendor_reports_ready", "private-ready", False),
        ("vendor_reports_ready", None, True),
        ("window_properties", None, False),
        ("window_properties", True, False),
        ("window_properties_before_script", -1, False),
        ("window_properties_before_script", None, True),
    ],
)
def test_startup_capture_does_not_smooth_over_malformed_core_witness(
    monkeypatch, field: str, malformed, remove: bool,
) -> None:
    import browser_core.product_observation as po

    document = {
        "uncaught_errors": [],
        "unhandled_rejections": [],
        "ambient_input": {},
        "vendor_globals": ["KPSDK"],
        "vendor_reports_ready": True,
        "window_properties": 100,
        "window_properties_before_script": 90,
    }
    if remove:
        document.pop(field)
    else:
        document[field] = malformed
    monkeypatch.setattr(
        po,
        "evaluate_page_expression",
        lambda *_args, **_kwargs: json.dumps(document),
    )
    monkeypatch.setattr(
        po,
        "probe_managed_page_target",
        lambda *_args, **_kwargs: {"status": "present", "title_matches": True},
    )

    captured = po._capture_startup("http://127.0.0.1:1", "http://127.0.0.1", 1.0)

    assert captured is not None and "probe_error" in captured
    assert grade_collector_startup(captured, 6)["started"] is None


def test_readiness_check_exception_does_not_authorize_started_claim() -> None:
    verdict = grade_collector_startup(
        {
            "uncaught_errors": [],
            "unhandled_rejections": [],
            "vendor_globals": ["KPSDK"],
            "vendor_reports_ready": "threw",
        },
        attributable_events=6,
    )

    assert verdict["started"] is False
    assert any("readiness check threw" in reason for reason in verdict["reasons"])


def test_page_probe_decoder_rejects_duplicates_unknown_fields_and_byte_overflow() -> (
    None
):
    import browser_core.product_observation as po

    with pytest.raises(ContractError, match="duplicate key"):
        po._decode_page_probe(
            '{"ready":true,"ready":false,"t":0}',
            label="readiness probe",
            fields=frozenset({"ready", "t"}),
        )
    with pytest.raises(ContractError, match="fields are invalid"):
        po._decode_page_probe(
            '{"ready":true,"t":0,"private":"value"}',
            label="readiness probe",
            fields=frozenset({"ready", "t"}),
        )
    monkeypatch_limit = po.MAX_PAGE_PROBE_JSON_BYTES
    try:
        po.MAX_PAGE_PROBE_JSON_BYTES = 8
        with pytest.raises(ContractError, match="byte limit"):
            po._decode_page_probe(
                '"' + "\u20ac" * 3 + '"',
                label="readiness probe",
                fields=frozenset({"ready", "t"}),
            )
    finally:
        po.MAX_PAGE_PROBE_JSON_BYTES = monkeypatch_limit


def test_resource_intent_capture_sanitizes_observer_output_before_return(
    monkeypatch,
) -> None:
    import browser_core.product_observation as po

    private = r"C:\u\x.js"
    monkeypatch.setattr(
        po,
        "observe_page_resource_intents",
        lambda *args, **kwargs: {
            "status": "ok",
            "intents": [],
            "diagnostic": f"TypeError: {private}",
            "private_unknown": private,
        },
    )

    captured = po._capture_resource_intents(
        "http://127.0.0.1:1", "http://127.0.0.1", 1.0
    )

    assert private not in json.dumps(captured)
    assert "private_unknown" not in captured
    assert captured["diagnostic"].startswith("TypeError;")


def test_resource_intent_projection_does_not_coerce_boolean_controls() -> None:
    import browser_core.product_observation as po

    captured = po._sanitize_resource_intent_report(
        {
            "status": "ok",
            "truncated": "false",
            "intents": [
                {
                    "tag": "script",
                    "attribute": "src",
                    "origin": "loopback-rehost",
                    "same_origin_as_rehost": "false",
                    "path_segment_lengths": [1],
                    "path_segments_truncated": False,
                    "query_names": [],
                    "query_names_truncated": False,
                }
            ],
        }
    )

    assert "truncated" not in captured
    assert captured["intents"] == []


def test_startup_sanitizer_drops_unknown_page_controlled_fields() -> None:
    startup = _sanitize_startup_document(
        {
            "uncaught_errors": [],
            "unhandled_rejections": [],
            "vendor_globals": [
                "__anubisBooted",
                "KPSDKPrivateTenant",
                "_pxPrivateTenant",
                "bad global",
            ],
            "vendor_reports_ready": None,
            "ambient_input": {"click": 2, "private-event": 99},
            "window_properties": 1234,
            "window_properties_before_script": 1200,
            "private_extra": "private-startup-value",
        }
    )

    assert startup["vendor_globals"] == ["__anubisBooted", "KPSDK*", "_px*"]
    assert startup["ambient_input"] == {"click": 2}
    assert "private_extra" not in startup
    assert "private-startup-value" not in json.dumps(startup)
    assert "PrivateTenant" not in json.dumps(startup)


def test_startup_sanitizer_drops_nested_vendor_global_values_cleanly() -> None:
    startup = _sanitize_startup_document(
        {
            "vendor_globals": [
                [],
                {"private": "tenant"},
                "turnstile",
            ],
        }
    )

    assert startup["vendor_globals"] == ["turnstile"]


@pytest.mark.parametrize("startup", [True, 1, "startup", [], [1]])
def test_startup_graders_reject_non_object_documents_cleanly(startup) -> None:
    with pytest.raises(ContractError, match="object or null"):
        grade_ambient_input(startup, "none")
    with pytest.raises(ContractError, match="object or null"):
        grade_collector_startup(startup, 0)


def test_startup_graders_resanitize_nested_page_values() -> None:
    startup = {
        "uncaught_errors": [[], {"private": "error"}],
        "unhandled_rejections": [1],
        "vendor_globals": [
            [],
            {"private": "global"},
            "KPSDKPrivateTenant",
            "turnstile",
        ],
        "vendor_reports_ready": "private-ready-value",
        "ambient_input": {"click": 2, "private-event": 9},
    }

    graded = grade_collector_startup(startup, 1)
    ambient = grade_ambient_input(startup, "none")

    assert graded["started"] is False
    assert graded["vendor_globals"] == ["KPSDK*", "turnstile"]
    assert graded["vendor_reports_ready"] is None
    assert "private" not in json.dumps(graded)
    assert ambient["events"] == {"click": 2}


@pytest.mark.parametrize(
    "vendor_globals",
    ["KPSDK", [{"private": "global"}], ["PrivateTenant"], ["KPSDK", "PrivateTenant"]],
)
def test_historical_startup_receipt_rejects_unprojectable_vendor_witness(
    vendor_globals,
) -> None:
    import browser_core.product_observation as po

    raw = {
        "started": True,
        "reasons": [],
        "uncaught_errors": [],
        "unhandled_rejections": [],
        "vendor_globals": vendor_globals,
        "vendor_reports_ready": True,
    }

    started, receipt, coherent = po._reconciled_collector_startup(
        {"collector_startup": raw}
    )

    assert started is None
    assert coherent is False
    assert receipt is not None and receipt["started"] is None
    assert "private" not in json.dumps(receipt)


def test_historical_startup_receipt_preserves_recognized_vendor_prefix() -> None:
    import browser_core.product_observation as po

    raw = {
        "started": True,
        "reasons": [],
        "uncaught_errors": [],
        "unhandled_rejections": [],
        "vendor_globals": ["_pxPrivateTenant"],
        "vendor_reports_ready": True,
    }

    started, receipt, coherent = po._reconciled_collector_startup(
        {"collector_startup": raw}
    )

    assert started is True
    assert coherent is True
    assert receipt is not None and receipt["vendor_globals"] == ["_px*"]


def test_startup_grade_redacts_non_string_probe_errors() -> None:
    graded = grade_collector_startup(
        {"probe_error": {"private": "page-value"}},
        0,
    )

    assert graded["started"] is None
    assert "private" not in json.dumps(graded)
    assert "diagnostic_sha256_16=" in graded["reasons"][0]


@pytest.mark.parametrize("probe_error", ["", False, 0, []])
def test_present_falsey_startup_probe_error_is_not_clean(probe_error) -> None:
    startup = {
        "probe_error": probe_error,
        "uncaught_errors": [],
        "unhandled_rejections": [],
        "vendor_globals": ["bmak"],
        "vendor_reports_ready": None,
        "ambient_input": {},
    }

    assert grade_collector_startup(startup, attributable_events=6)["started"] is None
    assert grade_ambient_input(startup, "none")["contaminated"] is None


def test_startup_grade_redacts_raw_probe_error_string_but_preserves_safe_receipt() -> None:
    raw = grade_collector_startup(
        {"probe_error": "TypeError: private-tenant-token"}, 0
    )
    assert raw["started"] is None
    assert "private-tenant-token" not in json.dumps(raw)
    assert "TypeError; diagnostic_sha256_16=" in raw["reasons"][0]

    safe_error = "startup probe failed: TypeError; diagnostic_sha256_16=" + "a" * 16
    safe = grade_collector_startup({"probe_error": safe_error}, 0)
    assert safe["reasons"] == [safe_error]


def test_startup_grade_redacts_raw_page_errors_and_rejections() -> None:
    graded = grade_collector_startup(
        {
            "uncaught_errors": ["TypeError: private-error-token"],
            "unhandled_rejections": ["Error: private-rejection-token"],
            "vendor_globals": ["bmak"],
            "vendor_reports_ready": None,
        },
        attributable_events=6,
    )

    rendered = json.dumps(graded)
    assert graded["started"] is False
    assert "private-error-token" not in rendered
    assert "private-rejection-token" not in rendered
    assert graded["uncaught_errors"][0].startswith("TypeError; diagnostic_sha256_16=")
    assert graded["unhandled_rejections"][0].startswith("Error; diagnostic_sha256_16=")


def test_startup_grade_handles_unhashable_target_status_during_probe_failure() -> None:
    graded = grade_collector_startup(
        {
            "probe_error": "startup probe failed: TypeError; diagnostic_sha256_16=" + "a" * 16,
            "renderer_blocked": True,
            "browser_target_status": [],
        },
        attributable_events=0,
    )

    assert graded["started"] is None
    assert "browser_target_status" not in graded


@pytest.mark.parametrize("attributable_events", [True, False, -1, 1.5, "1", [], {}])
def test_startup_grade_rejects_invalid_attributable_populations(
    attributable_events,
) -> None:
    with pytest.raises(ContractError, match="attributable events are invalid"):
        grade_collector_startup({}, attributable_events)


@pytest.mark.parametrize("context_counts", [True, 1, 1.5, "contexts", [], [1]])
def test_startup_grade_rejects_invalid_execution_context_documents(
    context_counts,
) -> None:
    with pytest.raises(ContractError, match="execution contexts are invalid"):
        grade_collector_startup({}, 0, context_counts)


@pytest.mark.parametrize("namespace_value", [True, 1, 1.5, "workers", [], [1]])
def test_startup_grade_treats_malformed_nested_contexts_as_no_worker_evidence(
    namespace_value,
) -> None:
    graded = grade_collector_startup(
        {"vendor_globals": ["__anubisBooted"]},
        1,
        {"native": namespace_value},
    )

    assert graded["started"] is False
    assert any("no worker execution context" in reason for reason in graded["reasons"])


@pytest.mark.parametrize("startup", [True, 1, 1.5, "startup", [], [1]])
def test_driver_suggestion_rejects_non_object_startup_cleanly(startup) -> None:
    with pytest.raises(ContractError, match="object or null"):
        suggest_driver(startup)


def test_driver_suggestion_ignores_nested_vendor_global_values() -> None:
    assert (
        suggest_driver(
            {
                "vendor_reports_ready": False,
                "vendor_globals": [[], {"private": "global"}, "KPSDK"],
            }
        )
        == product_observation.KNOWN_HOST_ENTRY_POINTS["KPSDK"]
    )


@pytest.mark.parametrize("input_profile", [None, True, 1, [], {}, "private-profile"])
def test_ambient_input_grade_rejects_invalid_profiles(input_profile) -> None:
    with pytest.raises(ContractError, match="invalid input profile"):
        grade_ambient_input({}, input_profile)


@pytest.mark.parametrize(
    "malformed_contract",
    [[], ["cdp_dom_snapshot/2"], {}, {"contract": "cdp_dom_snapshot/2"}],
)
def test_rehost_contract_sanitizer_rejects_unhashable_contract_labels_cleanly(
    malformed_contract,
) -> None:
    contract = product_observation.build_rehost_contract()
    contract["resource_intent_contract"] = malformed_contract

    sanitized = product_observation._sanitize_rehost_contract(contract)

    assert sanitized["status"] == "unverifiable"
    assert "resource_intent_contract" not in sanitized


def test_rehost_contract_sanitizer_normalizes_a_cyclic_contract() -> None:
    contract: dict[str, object] = {}
    contract["cycle"] = contract

    sanitized = product_observation._sanitize_rehost_contract(contract)

    assert sanitized["status"] == "unverifiable"
    assert re.fullmatch(r"[0-9a-f]{16}", sanitized["artifact_sha256_16"])


def test_portable_ambient_input_uses_the_witness_event_allowlist() -> None:
    report = _sanitize_ambient_input_report(
        {
            "contaminated": True,
            "trusted_events": {
                "touchstart": 2,
                "private-tenant-event": 99,
                "click": True,
            },
        }
    )

    assert report == {
        "contaminated": True,
        "trusted_events": {"touchstart": 2},
        "total_trusted_events": 2,
    }


@pytest.mark.parametrize("invalid", [float("nan"), float("inf"), float("-inf")])
def test_await_report_drops_nonfinite_timing_values(invalid: float) -> None:
    report = _sanitize_await_report(
        {
            "ended_on": "cap",
            "signal_kind": "builtin",
            "waited_seconds": invalid,
            "slowest_poll": {
                "outcome": "unresponsive",
                "duration_seconds": invalid,
            },
        }
    )

    assert report is not None
    assert "waited_seconds" not in report
    assert "slowest_poll" not in report


def test_observation_numeric_sanitizers_do_not_overflow_on_huge_json_integers() -> None:
    import browser_core.product_observation as po

    huge = 10**10_000
    method = po._number_method_value(huge)
    assert method["status"] == "unverifiable"

    report = _sanitize_await_report(
        {
            "ended_on": "cap",
            "signal_kind": "builtin",
            "page_ever_answered": False,
            "waited_seconds": huge,
            "polls": 0,
            "unresponsive_polls": 0,
            "failed_polls": 0,
            "poll_timeout_seconds": huge,
        }
    )
    assert report is not None
    assert report["waited_seconds"] == po.MAX_OBSERVATION_SECONDS

    geometry = po._sanitize_geometry_document(
        {"inner_width": huge, "device_pixel_ratio": huge}
    )
    assert geometry == {}


def test_observation_config_normalizes_a_huge_integer_budget(tmp_path: Path) -> None:
    import browser_core.product_observation as po

    sample = tmp_path / "sample.js"
    sample.write_text("// sample", encoding="utf-8")
    config = po.ProductScriptObservation(
        script=sample,
        label="huge-timeout",
        executable=tmp_path / "chrome.exe",
        trace_processor=tmp_path / "trace_processor.exe",
        workspace=tmp_path,
        timeout_seconds=10**10_000,
    )

    with pytest.raises(ContractError, match="timeout seconds"):
        po.validate_product_script_observation_config(config)


def test_method_receipt_normalizes_unserializable_runtime_values() -> None:
    import browser_core.product_observation as po

    cyclic: list[object] = []
    cyclic.append(cyclic)

    receipt = po._enum_method_value(cyclic, set())

    assert receipt["status"] == "unverifiable"
    assert re.fullmatch(r"[0-9a-f]{16}", receipt["artifact_sha256_16"])

    cyclic_argument: dict[str, object] = {}
    cyclic_argument["cycle"] = cyclic_argument
    method, invalid = po._observation_method_receipt(
        {"extra_browser_args": [cyclic_argument]}
    )
    assert "extra_browser_args" in invalid
    assert po._method_value_is_unverifiable(method["extra_browser_args"])


@pytest.mark.parametrize(
    ("field", "value"),
    [
        pytest.param("prelude", "\ud800", id="prelude"),
        pytest.param("driver", "\ud800", id="driver"),
        pytest.param("declared_script_url", "\ud800", id="declared-url"),
        pytest.param(
            "declared_script_url",
            {
                "supplied": True,
                "sha256_16": "a" * 16,
                "shape": {
                    "origin": "https://example.invalid",
                    "path_segment_lengths": [],
                    "path_segments_truncated": False,
                    "query_names": ["\ud800"],
                    "query_names_truncated": False,
                    "fragment_present": False,
                },
            },
            id="stored-declared-url-query-name",
        ),
        pytest.param("script_path", "\ud800", id="script-path"),
        pytest.param("extra_browser_args", ["\ud800"], id="browser-argument"),
    ],
)
def test_method_receipt_marks_non_utf8_method_values_unverifiable(
    field: str, value
) -> None:
    import browser_core.product_observation as po

    receipt, invalid = po._observation_method_receipt({field: value})

    assert field in invalid
    assert po._method_value_is_unverifiable(receipt[field])
    json.dumps(receipt, ensure_ascii=False).encode("utf-8")
    if field == "extra_browser_args":
        projected_again = po._browser_arg_metadata(receipt[field])
        assert po._method_value_is_unverifiable(projected_again)


def test_method_unverifiable_scan_rejects_malformed_nested_status() -> None:
    import browser_core.product_observation as po

    assert po._method_value_is_unverifiable({"method": {"status": []}}) is True


def test_readiness_wait_normalizes_a_huge_integer_budget(monkeypatch) -> None:
    import browser_core.product_observation as po

    monkeypatch.setattr(
        po,
        "evaluate_page_expression",
        lambda *_args, **_kwargs: pytest.fail("huge budget reached CDP"),
    )

    with pytest.raises(ContractError, match="await cap"):
        await_collector_ready(
            "http://127.0.0.1:1/",
            "http://127.0.0.1:2/",
            cap_seconds=10**10_000,
            poll_timeout_seconds=1.0,
        )


@pytest.mark.parametrize(
    ("ended_on", "signal_kind", "page_ever_answered"),
    [
        ("ready", "operator_expression", True),
        ("expression_true", "builtin", True),
        ("ready", "builtin", False),
        ("ready", "builtin", None),
        ("no_signal", "builtin", False),
        ("no_signal", "builtin", None),
    ],
)
def test_await_report_downgrades_impossible_terminal_claims(
    ended_on: str,
    signal_kind: str,
    page_ever_answered: bool | None,
) -> None:
    report = _sanitize_await_report(
        {
            "ended_on": ended_on,
            "signal_kind": signal_kind,
            "page_ever_answered": page_ever_answered,
            "waited_seconds": 1.0,
            "polls": 1,
            "unresponsive_polls": 0,
            "failed_polls": 0,
            "poll_timeout_seconds": 1.0,
        }
    )

    assert report is not None
    assert report["ended_on"] == "unknown"


@pytest.mark.parametrize(
    ("outcome", "unresponsive_polls", "failed_polls"),
    [
        ("unresponsive", 0, 0),
        ("failed", 0, 0),
    ],
)
def test_await_report_downgrades_slowest_outcomes_without_supporting_counts(
    outcome: str,
    unresponsive_polls: int,
    failed_polls: int,
) -> None:
    report = _sanitize_await_report(
        {
            "ended_on": "cap",
            "signal_kind": "builtin",
            "page_ever_answered": False,
            "waited_seconds": 1.0,
            "polls": 1,
            "unresponsive_polls": unresponsive_polls,
            "failed_polls": failed_polls,
            "poll_timeout_seconds": 1.0,
            "slowest_poll": {
                "issued_at_seconds": 0.0,
                "duration_seconds": 1.0,
                "outcome": outcome,
            },
        }
    )

    assert report is not None
    assert report["slowest_poll"]["outcome"] == "unknown"


@pytest.mark.parametrize(
    ("page_ever_answered", "unresponsive_polls", "failed_polls", "expected"),
    [
        (False, 1, 1, None),
        (True, 2, 1, True),
    ],
)
def test_await_report_reconciles_answer_flags_with_poll_partition(
    page_ever_answered: bool,
    unresponsive_polls: int,
    failed_polls: int,
    expected: bool | None,
) -> None:
    report = _sanitize_await_report(
        {
            "ended_on": "cap",
            "signal_kind": "builtin",
            "page_ever_answered": page_ever_answered,
            "waited_seconds": 3.0,
            "polls": 3,
            "unresponsive_polls": unresponsive_polls,
            "failed_polls": failed_polls,
            "poll_timeout_seconds": 1.0,
        }
    )

    assert report is not None
    assert report["page_ever_answered"] is expected


@pytest.mark.parametrize(
    ("failure_field", "expected_answer"),
    [("unresponsive_polls", None), ("failed_polls", True)],
)
def test_await_report_downgrades_ready_when_one_failure_count_covers_all_polls(
    failure_field: str,
    expected_answer: bool | None,
) -> None:
    report = _sanitize_await_report(
        {
            "ended_on": "ready",
            "signal_kind": "builtin",
            "page_ever_answered": True,
            "waited_seconds": 2.0,
            "polls": 2,
            failure_field: 2,
        }
    )

    assert report is not None
    assert report["page_ever_answered"] is expected_answer
    assert report["ended_on"] == "unknown"


def test_await_report_keeps_ready_when_partial_failure_count_allows_answer() -> None:
    report = _sanitize_await_report(
        {
            "ended_on": "ready",
            "signal_kind": "builtin",
            "page_ever_answered": True,
            "waited_seconds": 2.0,
            "polls": 2,
            "failed_polls": 1,
        }
    )

    assert report is not None
    assert report["page_ever_answered"] is True
    assert report["ended_on"] == "ready"


def test_await_report_keeps_page_answer_after_all_decodes_fail() -> None:
    report = _sanitize_await_report(
        {
            "ended_on": "cap",
            "signal_kind": "builtin",
            "page_ever_answered": True,
            "waited_seconds": 2.0,
            "polls": 2,
            "failed_polls": 2,
        }
    )

    assert report is not None
    assert report["page_ever_answered"] is True
    assert report["ended_on"] == "cap"


def test_await_report_rejects_ready_with_overlapping_failure_counts() -> None:
    report = _sanitize_await_report(
        {
            "ended_on": "ready",
            "signal_kind": "builtin",
            "page_ever_answered": True,
            "waited_seconds": 2.0,
            "polls": 2,
            "unresponsive_polls": 2,
            "failed_polls": 1,
        }
    )

    assert report is not None
    assert report["ended_on"] == "unknown"


@pytest.mark.parametrize("outcome", ["ready", "no_signal", "not_ready"])
def test_await_report_downgrades_successful_sample_when_all_polls_failed(
    outcome: str,
) -> None:
    report = _sanitize_await_report(
        {
            "ended_on": "cap",
            "signal_kind": "builtin",
            "page_ever_answered": True,
            "polls": 2,
            "failed_polls": 2,
            "slowest_poll": {
                "issued_at_seconds": 0.0,
                "duration_seconds": 1.0,
                "outcome": outcome,
            },
        }
    )

    assert report is not None
    assert report["page_ever_answered"] is True
    assert report["slowest_poll"]["outcome"] == "unknown"


def test_await_report_keeps_successful_sample_with_partial_failure_count() -> None:
    report = _sanitize_await_report(
        {
            "ended_on": "cap",
            "signal_kind": "builtin",
            "page_ever_answered": True,
            "polls": 2,
            "failed_polls": 1,
            "slowest_poll": {
                "issued_at_seconds": 0.0,
                "duration_seconds": 1.0,
                "outcome": "ready",
            },
        }
    )

    assert report is not None
    assert report["slowest_poll"]["outcome"] == "ready"


def test_await_report_downgrades_answer_without_any_poll() -> None:
    report = _sanitize_await_report(
        {
            "ended_on": "cap",
            "signal_kind": "builtin",
            "page_ever_answered": True,
            "waited_seconds": 0.0,
            "polls": 0,
        }
    )

    assert report is not None
    assert report["page_ever_answered"] is None


def test_await_report_drops_a_slowest_sample_when_no_poll_exists() -> None:
    report = _sanitize_await_report(
        {
            "ended_on": "cap",
            "signal_kind": "builtin",
            "page_ever_answered": False,
            "waited_seconds": 0.0,
            "polls": 0,
            "unresponsive_polls": 0,
            "failed_polls": 0,
            "poll_timeout_seconds": 1.0,
            "slowest_poll": {
                "issued_at_seconds": 0.0,
                "duration_seconds": 0.0,
                "outcome": "not_ready",
            },
        }
    )

    assert report is not None
    assert "slowest_poll" not in report


def test_geometry_has_its_own_bounded_allowlist() -> None:
    geometry = _sanitize_geometry_document(
        {
            "inner_width": 800,
            "inner_height": 600,
            "outer_width": 816,
            "outer_height": 638,
            "screen_width": 1920,
            "screen_height": 1080,
            "device_pixel_ratio": 1.25,
            "private_extra": "private-viewport-value",
        }
    )

    assert geometry["inner_width"] == 800
    assert geometry["device_pixel_ratio"] == 1.25
    assert "private_extra" not in geometry


def test_ready_expression_metadata_hashes_legacy_source_without_retaining_it() -> None:
    source = "window.__private_completion_marker === true"
    metadata = _ready_expression_metadata({"ready_expression": source})
    assert metadata["supplied"] is True
    assert metadata["bytes"] == len(source.encode("utf-8"))
    assert metadata["sha256_16"]
    assert source not in json.dumps(metadata)


def test_stage_route_metadata_binds_bytes_without_local_path(tmp_path: Path) -> None:
    stage = tmp_path / "private-tenant-name" / "ips.js"
    stage.parent.mkdir()
    stage.write_bytes(b"second-stage bytes")
    metadata = _stage_route_metadata((("/tenant/site/mfc", stage),))
    assert metadata[0]["path_prefix"] == "/tenant/site/mfc"
    assert metadata[0]["bytes"] == len(b"second-stage bytes")
    assert metadata[0]["sha256_16"]
    assert str(tmp_path) not in json.dumps(metadata)
    assert "private-tenant-name" not in json.dumps(metadata)


def test_stage_route_metadata_can_bind_the_exact_served_snapshot(
    tmp_path: Path,
) -> None:
    stage = tmp_path / "stage.js"
    stage.write_bytes(b"served snapshot")
    snapshot = stage.read_bytes()
    stage.write_bytes(b"changed after snapshot")

    metadata = _stage_route_metadata((("/worker", snapshot),))

    assert metadata[0]["bytes"] == len(b"served snapshot")
    assert (
        metadata[0]["sha256_16"] == hashlib.sha256(b"served snapshot").hexdigest()[:16]
    )
    assert (
        metadata[0]["sha256_16"] != hashlib.sha256(stage.read_bytes()).hexdigest()[:16]
    )


def test_a_public_source_pin_binds_url_time_and_full_digest() -> None:
    payload = b"public collector bytes"
    digest = hashlib.sha256(payload).hexdigest()
    config = SimpleNamespace(
        source_url="https://vendor.example/v1/collector.js",
        source_retrieved_at="2026-08-09T05:31:00Z",
        source_sha256=digest,
    )
    verdict = grade_public_source_provenance(config, payload)
    assert verdict["status"] == "verified_digest"
    assert verdict["source_url"] == config.source_url
    assert verdict["retrieved_at"] == config.source_retrieved_at
    assert verdict["sha256"] == digest


@pytest.mark.parametrize(
    "config", [None, True, 1, 1.5, "config", b"config", [], {}, ()]
)
def test_public_source_provenance_rejects_invalid_config_shapes_cleanly(config) -> None:
    with pytest.raises(ContractError):
        grade_public_source_provenance(config, b"payload")
    with pytest.raises(ContractError):
        product_observation.grade_script_source_provenance(config, b"payload")


def test_portable_source_provenance_rejects_nonstring_timestamp_without_coercion() -> None:
    class UnexpectedStringConversion:
        def __str__(self) -> str:
            pytest.fail("invalid source timestamp was converted before validation")

    result = _sanitize_source_provenance(
        {
            "status": "verified_digest",
            "source_url": "https://example.test/script.js",
            "sha256": "a" * 64,
            "retrieved_at": UnexpectedStringConversion(),
        }
    )
    assert result["status"] == "unverifiable"


def test_portable_public_source_rejects_raw_url_that_conflicts_with_saved_shape() -> None:
    verified = {
        "status": "verified_digest",
        "source_url": "https://vendor.example/v1/collector.js",
        "retrieved_at": "2026-08-09T05:31:00Z",
        "sha256": "a" * 64,
    }
    portable = _sanitize_source_provenance(verified)
    assert portable["status"] == "verified_digest"
    assert _sanitize_source_provenance(portable) == portable
    assert _sanitize_source_provenance(
        {**verified, "source_url_shape": portable["source_url_shape"]}
    )["status"] == "verified_digest"

    for raw_url in ("file:///local/collector.js", "https://other.example/x.js"):
        contradictory = {
            **verified,
            "source_url": raw_url,
            "source_url_shape": portable["source_url_shape"],
        }
        assert _sanitize_source_provenance(contradictory)["status"] == "unverifiable"


def test_portable_git_source_provenance_rejects_contradictory_verification_fields() -> None:
    verified = {
        "status": "verified_git_inputs_artifact_digest",
        "repository_url": "https://vendor.example/public.git",
        "revision": "a" * 40,
        "sha256": "b" * 64,
        "artifact_relative_path": "web/static/js/main.mjs",
        "artifact_git_state": "ignored-generated",
        "build_recipe_relative_path": "web/build.sh",
        "build_recipe_sha256": "c" * 64,
        "tracked_worktree_clean": True,
        "distinct_checkout_artifact_verified": False,
    }
    portable = _sanitize_source_provenance(verified)
    assert portable["status"] == verified["status"]
    assert _sanitize_source_provenance(
        {**verified, "repository_url_shape": portable["repository_url_shape"]}
    )["status"] == verified["status"]

    for contradiction in (
        {"tracked_worktree_clean": False},
        {"rebuild_artifact_sha256": "b" * 64},
        {"repository_url": "https://vendor.example/public.git?channel=other"},
        {"repository_url": "https://vendor.example/public.git?"},
        {"repository_url": "https://vendor.example/public.git#"},
        {
            "repository_url": "file:///local/public.git",
            "repository_url_shape": portable["repository_url_shape"],
        },
        {
            "repository_url": "https://other.example/public.git",
            "repository_url_shape": portable["repository_url_shape"],
        },
        {
            "repository_url": None,
            "repository_url_shape": {
                **portable["repository_url_shape"],
                "query_names": ["channel"],
            },
        },
    ):
        assert _sanitize_source_provenance(
            {**verified, **contradiction}
        )["status"] == "unverifiable"


def test_a_public_source_pin_accepts_dotnet_round_trip_fractional_seconds() -> None:
    payload = b"public collector bytes"
    config = SimpleNamespace(
        source_url="https://vendor.example/v1/collector.js",
        source_retrieved_at="2026-08-09T14:38:39.7189073-05:00",
        source_sha256=hashlib.sha256(payload).hexdigest(),
    )

    verdict = grade_public_source_provenance(config, payload)

    assert verdict["retrieved_at"] == "2026-08-09T14:38:39.718907-05:00"


def test_a_partial_or_mismatched_public_source_pin_is_refused() -> None:
    partial = SimpleNamespace(
        source_url="https://vendor.example/collector.js",
        source_retrieved_at=None,
        source_sha256=None,
    )
    with pytest.raises(ContractError, match="supplied together"):
        grade_public_source_provenance(partial, b"x")

    mismatch = SimpleNamespace(
        source_url="https://vendor.example/collector.js",
        source_retrieved_at="2026-08-09T05:31:00Z",
        source_sha256="0" * 64,
    )
    with pytest.raises(ContractError, match="mismatch"):
        grade_public_source_provenance(mismatch, b"x")


@pytest.mark.parametrize(
    "source_url",
    [
        "https://user:password@vendor.example/collector.js",
        "https://vendor.example/collector.js#not-part-of-the-request",
        "https://vendor.example/collector.js#",
    ],
)
def test_public_source_pin_refuses_credentials_and_fragments(source_url) -> None:
    payload = b"public collector bytes"
    config = SimpleNamespace(
        source_url=source_url,
        source_retrieved_at="2026-08-09T05:31:00Z",
        source_sha256=hashlib.sha256(payload).hexdigest(),
    )

    with pytest.raises(ContractError, match="credential-free"):
        grade_public_source_provenance(config, payload)


def test_public_source_pin_normalizes_malformed_url_failures_to_contract_error() -> (
    None
):
    payload = b"public collector bytes"
    config = SimpleNamespace(
        source_url="https://[invalid/collector.js",
        source_retrieved_at="2026-08-09T05:31:00Z",
        source_sha256=hashlib.sha256(payload).hexdigest(),
    )

    with pytest.raises(ContractError, match="credential-free"):
        grade_public_source_provenance(config, payload)


@pytest.mark.parametrize(
    "source_url",
    [
        "https://vendor.example\\@other.example/collector.js",
        "https://2130706433/collector.js",
        "https://faß.example/collector.js",
    ],
)
def test_public_source_pin_refuses_ambiguous_browser_origins(source_url) -> None:
    payload = b"public collector bytes"
    config = SimpleNamespace(
        source_url=source_url,
        source_retrieved_at="2026-08-09T05:31:00Z",
        source_sha256=hashlib.sha256(payload).hexdigest(),
    )

    with pytest.raises(ContractError, match="credential-free"):
        grade_public_source_provenance(config, payload)


def test_public_url_shape_uses_the_canonical_browser_origin() -> None:
    shape = product_observation._project_public_url_shape(
        "https://bücher.example/collector.js"
    )

    assert shape is not None
    assert shape["origin"] == "https://xn--bcher-kva.example"


def _git_fixture(tmp_path: Path) -> tuple[Path, Path, Path, str]:
    checkout = tmp_path / "public-checkout"
    checkout.mkdir()
    recipe = checkout / "web" / "build.sh"
    artifact = checkout / "web" / "static" / "js" / "main.mjs"
    recipe.parent.mkdir(parents=True)
    artifact.parent.mkdir(parents=True)
    recipe.write_text("esbuild web/js/main.ts --bundle\n", encoding="utf-8")
    artifact.write_bytes(b"generated public collector")
    (checkout / ".gitignore").write_text("web/static/js/\n", encoding="utf-8")

    def git(*arguments: str) -> str:
        result = subprocess.run(
            ["git", "-C", str(checkout), *arguments],
            capture_output=True,
            text=True,
            check=True,
        )
        return result.stdout.strip()

    git("init", "-q")
    git("add", ".gitignore", "web/build.sh")
    git(
        "-c",
        "user.name=Browser Core Tests",
        "-c",
        "user.email=browser-core@example.invalid",
        "commit",
        "-q",
        "-m",
        "fixture",
    )
    git("remote", "add", "origin", "https://vendor.example/public.git")
    return checkout, recipe, artifact, git("rev-parse", "HEAD")


def test_git_input_pin_distinguishes_generated_artifact_from_tracked_inputs(
    tmp_path: Path,
) -> None:
    checkout, recipe, artifact, revision = _git_fixture(tmp_path)
    payload = artifact.read_bytes()
    config = SimpleNamespace(
        script=artifact,
        source_sha256=hashlib.sha256(payload).hexdigest(),
        source_git_checkout=checkout,
        source_git_repository_url="https://vendor.example/public.git",
        source_git_revision=revision,
        source_build_recipe=recipe,
    )

    verdict = grade_git_source_provenance(config, payload)

    assert verdict["status"] == "verified_git_inputs_artifact_digest"
    assert verdict["revision"] == revision
    assert verdict["artifact_relative_path"] == "web/static/js/main.mjs"
    assert verdict["artifact_git_state"] == "ignored-generated"
    assert verdict["build_recipe_relative_path"] == "web/build.sh"
    assert verdict["tracked_worktree_clean"] is True
    assert verdict["distinct_checkout_artifact_verified"] is False

    portable = _sanitize_source_provenance(verdict)
    assert portable["status"] == "verified_git_inputs_artifact_digest"
    assert portable["artifact_git_state"] == "ignored-generated"
    assert str(checkout) not in json.dumps(portable)
    assert _sanitize_source_provenance(portable) == portable


def test_git_input_pin_requires_literal_tracked_recipe(tmp_path: Path) -> None:
    checkout, recipe, artifact, revision = _git_fixture(tmp_path)
    untracked_recipe = recipe.with_name("build[.]sh")
    untracked_recipe.write_bytes(recipe.read_bytes())
    payload = artifact.read_bytes()
    config = SimpleNamespace(
        script=artifact,
        source_sha256=hashlib.sha256(payload).hexdigest(),
        source_git_checkout=checkout,
        source_git_repository_url="https://vendor.example/public.git",
        source_git_revision=revision,
        source_build_recipe=untracked_recipe,
    )

    with pytest.raises(ContractError, match="build recipe must be tracked"):
        grade_git_source_provenance(config, payload)

    subprocess.run(
        ["git", "-C", str(checkout), "add", "--", ":(literal)web/build[.]sh"],
        check=True,
        capture_output=True,
    )
    subprocess.run(
        [
            "git", "-C", str(checkout), "-c", "user.name=Browser Core Tests",
            "-c", "user.email=browser-core@example.invalid", "commit", "-q",
            "-m", "track literal recipe",
        ],
        check=True,
        capture_output=True,
    )
    revision = subprocess.run(
        ["git", "-C", str(checkout), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    config.source_git_revision = revision
    assert grade_git_source_provenance(config, payload)[
        "build_recipe_relative_path"
    ] == "web/build[.]sh"


def test_git_input_pin_reports_literal_artifact_tracked_state(tmp_path: Path) -> None:
    checkout, recipe, _, revision = _git_fixture(tmp_path)
    artifact = recipe.with_name("build[.]sh")
    artifact.write_bytes(b"untracked generated artifact")
    payload = artifact.read_bytes()
    config = SimpleNamespace(
        script=artifact,
        source_sha256=hashlib.sha256(payload).hexdigest(),
        source_git_checkout=checkout,
        source_git_repository_url="https://vendor.example/public.git",
        source_git_revision=revision,
        source_build_recipe=recipe,
    )

    verdict = grade_git_source_provenance(config, payload)
    assert verdict["artifact_git_state"] == "untracked"


def test_git_input_pin_refuses_failed_artifact_ignore_query(tmp_path: Path) -> None:
    checkout, recipe, artifact, revision = _git_fixture(tmp_path)
    exclude_directory = checkout / "exclude-directory"
    exclude_directory.mkdir()
    subprocess.run(
        [
            "git", "-C", str(checkout), "config", "core.excludesFile",
            str(exclude_directory),
        ],
        check=True,
        capture_output=True,
    )
    payload = artifact.read_bytes()
    config = SimpleNamespace(
        script=artifact,
        source_sha256=hashlib.sha256(payload).hexdigest(),
        source_git_checkout=checkout,
        source_git_repository_url="https://vendor.example/public.git",
        source_git_revision=revision,
        source_build_recipe=recipe,
    )

    with pytest.raises(ContractError, match="artifact ignore state"):
        grade_git_source_provenance(config, payload)

    tracked_payload = recipe.read_bytes()
    config.script = recipe
    config.source_sha256 = hashlib.sha256(tracked_payload).hexdigest()
    assert grade_git_source_provenance(config, tracked_payload)[
        "artifact_git_state"
    ] == "tracked"


def test_git_input_pin_refuses_a_dirty_tracked_checkout(tmp_path: Path) -> None:
    checkout, recipe, artifact, revision = _git_fixture(tmp_path)
    recipe.write_text("changed build recipe\n", encoding="utf-8")
    payload = artifact.read_bytes()
    config = SimpleNamespace(
        script=artifact,
        source_sha256=hashlib.sha256(payload).hexdigest(),
        source_git_checkout=checkout,
        source_git_repository_url="https://vendor.example/public.git",
        source_git_revision=revision,
        source_build_recipe=recipe,
    )

    with pytest.raises(ContractError, match="clean tracked worktree"):
        grade_git_source_provenance(config, payload)


def test_git_input_pin_refuses_changed_tracked_bytes_hidden_from_status(
    tmp_path: Path,
) -> None:
    checkout, recipe, artifact, revision = _git_fixture(tmp_path)
    recipe.write_bytes(b"changed build recipe bytes\n")
    subprocess.run(
        ["git", "-C", str(checkout), "update-index", "--assume-unchanged", "web/build.sh"],
        check=True,
        capture_output=True,
    )
    status = subprocess.run(
        ["git", "-C", str(checkout), "status", "--porcelain=v1", "--untracked-files=no"],
        check=True,
        capture_output=True,
        text=True,
    )
    assert status.stdout == ""
    payload = artifact.read_bytes()
    config = SimpleNamespace(
        script=artifact,
        source_sha256=hashlib.sha256(payload).hexdigest(),
        source_git_checkout=checkout,
        source_git_repository_url="https://vendor.example/public.git",
        source_git_revision=revision,
        source_build_recipe=recipe,
    )

    with pytest.raises(ContractError, match="clean tracked worktree"):
        grade_git_source_provenance(config, payload)


def test_git_input_pin_checks_tracked_files_beyond_the_build_recipe(
    tmp_path: Path,
) -> None:
    checkout, recipe, artifact, _revision = _git_fixture(tmp_path)
    source = checkout / "web" / "source.txt"
    source.write_bytes(b"pinned public source\n")
    subprocess.run(
        ["git", "-C", str(checkout), "add", "web/source.txt"],
        check=True,
        capture_output=True,
    )
    subprocess.run(
        [
            "git", "-C", str(checkout),
            "-c", "user.name=Browser Core Tests",
            "-c", "user.email=browser-core@example.invalid",
            "commit", "-q", "-m", "source input",
        ],
        check=True,
        capture_output=True,
    )
    revision = subprocess.run(
        ["git", "-C", str(checkout), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    source.write_bytes(b"changed public source\n")
    subprocess.run(
        ["git", "-C", str(checkout), "update-index", "--assume-unchanged", "web/source.txt"],
        check=True,
        capture_output=True,
    )
    payload = artifact.read_bytes()
    config = SimpleNamespace(
        script=artifact,
        source_sha256=hashlib.sha256(payload).hexdigest(),
        source_git_checkout=checkout,
        source_git_repository_url="https://vendor.example/public.git",
        source_git_revision=revision,
        source_build_recipe=recipe,
    )

    with pytest.raises(ContractError, match="clean tracked worktree"):
        grade_git_source_provenance(config, payload)


def test_git_input_pin_does_not_normalize_a_binary_attribute_file(
    tmp_path: Path,
) -> None:
    checkout, recipe, artifact, _revision = _git_fixture(tmp_path)
    (checkout / ".gitattributes").write_text(
        "web/build.sh -text\n", encoding="utf-8",
    )
    recipe.write_bytes(b"esbuild web/js/main.ts --bundle\n")
    subprocess.run(
        ["git", "-C", str(checkout), "add", ".gitattributes", "web/build.sh"],
        check=True,
        capture_output=True,
    )
    subprocess.run(
        [
            "git", "-C", str(checkout),
            "-c", "user.name=Browser Core Tests",
            "-c", "user.email=browser-core@example.invalid",
            "commit", "-q", "-m", "binary recipe attribute",
        ],
        check=True,
        capture_output=True,
    )
    subprocess.run(
        ["git", "-C", str(checkout), "config", "core.autocrlf", "true"],
        check=True,
        capture_output=True,
    )
    recipe.write_bytes(b"esbuild web/js/main.ts --bundle\r\n")
    revision = subprocess.run(
        ["git", "-C", str(checkout), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    status = subprocess.run(
        ["git", "-C", str(checkout), "status", "--porcelain=v1", "--untracked-files=no"],
        check=True,
        capture_output=True,
        text=True,
    )
    assert status.stdout
    payload = artifact.read_bytes()
    config = SimpleNamespace(
        script=artifact,
        source_sha256=hashlib.sha256(payload).hexdigest(),
        source_git_checkout=checkout,
        source_git_repository_url="https://vendor.example/public.git",
        source_git_revision=revision,
        source_build_recipe=recipe,
    )

    with pytest.raises(ContractError, match="clean tracked worktree"):
        grade_git_source_provenance(config, payload)


def test_git_input_pin_accepts_configured_text_checkout_conversion(
    tmp_path: Path,
) -> None:
    checkout, recipe, artifact, revision = _git_fixture(tmp_path)
    subprocess.run(
        ["git", "-C", str(checkout), "config", "core.autocrlf", "true"],
        check=True,
        capture_output=True,
    )
    recipe.write_bytes(b"esbuild web/js/main.ts --bundle\n")
    subprocess.run(
        ["git", "-C", str(checkout), "add", "web/build.sh"],
        check=True,
        capture_output=True,
    )
    recipe.write_bytes(b"esbuild web/js/main.ts --bundle\r\n")
    payload = artifact.read_bytes()
    config = SimpleNamespace(
        script=artifact,
        source_sha256=hashlib.sha256(payload).hexdigest(),
        source_git_checkout=checkout,
        source_git_repository_url="https://vendor.example/public.git",
        source_git_revision=revision,
        source_build_recipe=recipe,
    )

    verdict = grade_git_source_provenance(config, payload)

    assert verdict["tracked_worktree_clean"] is True


def test_git_input_pin_rejects_ambiguous_disabled_clean_filter(
    tmp_path: Path,
) -> None:
    checkout, recipe, artifact, _revision = _git_fixture(tmp_path)
    (checkout / ".gitattributes").write_bytes(b"web/build.sh -filter\n")
    subprocess.run(
        ["git", "-C", str(checkout), "add", ".gitattributes"],
        check=True,
        capture_output=True,
    )
    subprocess.run(
        [
            "git", "-C", str(checkout),
            "-c", "user.name=Browser Core Tests",
            "-c", "user.email=browser-core@example.invalid",
            "commit", "-q", "-m", "disabled recipe filter",
        ],
        check=True,
        capture_output=True,
    )
    revision = subprocess.run(
        ["git", "-C", str(checkout), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    payload = artifact.read_bytes()
    config = SimpleNamespace(
        script=artifact,
        source_sha256=hashlib.sha256(payload).hexdigest(),
        source_git_checkout=checkout,
        source_git_repository_url="https://vendor.example/public.git",
        source_git_revision=revision,
        source_build_recipe=recipe,
    )

    with pytest.raises(ContractError, match="clean filter"):
        grade_git_source_provenance(config, payload)


def test_git_input_pin_refuses_named_filter_called_unset(
    tmp_path: Path,
) -> None:
    checkout, recipe, artifact, _revision = _git_fixture(tmp_path)
    (checkout / ".gitattributes").write_bytes(b"web/build.sh filter=unset\n")
    subprocess.run(
        ["git", "-C", str(checkout), "add", ".gitattributes"],
        check=True,
        capture_output=True,
    )
    subprocess.run(
        [
            "git", "-C", str(checkout),
            "-c", "user.name=Browser Core Tests",
            "-c", "user.email=browser-core@example.invalid",
            "commit", "-q", "-m", "named unset filter",
        ],
        check=True,
        capture_output=True,
    )
    revision = subprocess.run(
        ["git", "-C", str(checkout), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    payload = artifact.read_bytes()
    config = SimpleNamespace(
        script=artifact,
        source_sha256=hashlib.sha256(payload).hexdigest(),
        source_git_checkout=checkout,
        source_git_repository_url="https://vendor.example/public.git",
        source_git_revision=revision,
        source_build_recipe=recipe,
    )

    with pytest.raises(ContractError, match="clean filter"):
        grade_git_source_provenance(config, payload)


def test_git_input_pin_accepts_explicit_crlf_attribute_without_autocrlf(
    tmp_path: Path,
) -> None:
    checkout, recipe, artifact, _revision = _git_fixture(tmp_path)
    subprocess.run(
        ["git", "-C", str(checkout), "config", "core.autocrlf", "false"],
        check=True,
        capture_output=True,
    )
    (checkout / ".gitattributes").write_bytes(b"web/build.sh text eol=crlf\n")
    recipe.write_bytes(b"esbuild web/js/main.ts --bundle\n")
    subprocess.run(
        ["git", "-C", str(checkout), "add", ".gitattributes", "web/build.sh"],
        check=True,
        capture_output=True,
    )
    subprocess.run(
        [
            "git", "-C", str(checkout),
            "-c", "user.name=Browser Core Tests",
            "-c", "user.email=browser-core@example.invalid",
            "commit", "-q", "-m", "explicit CRLF recipe",
        ],
        check=True,
        capture_output=True,
    )
    (checkout / ".gitignore").write_bytes(subprocess.run(
        ["git", "-C", str(checkout), "show", "HEAD:.gitignore"],
        check=True,
        capture_output=True,
    ).stdout)
    recipe.write_bytes(b"esbuild web/js/main.ts --bundle\r\n")
    revision = subprocess.run(
        ["git", "-C", str(checkout), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    payload = artifact.read_bytes()
    config = SimpleNamespace(
        script=artifact,
        source_sha256=hashlib.sha256(payload).hexdigest(),
        source_git_checkout=checkout,
        source_git_repository_url="https://vendor.example/public.git",
        source_git_revision=revision,
        source_build_recipe=recipe,
    )

    verdict = grade_git_source_provenance(config, payload)

    assert verdict["tracked_worktree_clean"] is True


def test_git_input_pin_refuses_changed_index_even_with_head_worktree_bytes(
    tmp_path: Path,
) -> None:
    checkout, recipe, artifact, revision = _git_fixture(tmp_path)
    original = recipe.read_bytes()
    recipe.write_bytes(b"staged build recipe\n")
    subprocess.run(
        ["git", "-C", str(checkout), "add", "web/build.sh"],
        check=True,
        capture_output=True,
    )
    recipe.write_bytes(original)
    payload = artifact.read_bytes()
    config = SimpleNamespace(
        script=artifact,
        source_sha256=hashlib.sha256(payload).hexdigest(),
        source_git_checkout=checkout,
        source_git_repository_url="https://vendor.example/public.git",
        source_git_revision=revision,
        source_build_recipe=recipe,
    )

    with pytest.raises(ContractError, match="clean tracked worktree"):
        grade_git_source_provenance(config, payload)


def test_git_input_pin_refuses_a_script_population_mismatch(tmp_path: Path) -> None:
    checkout, recipe, artifact, revision = _git_fixture(tmp_path)
    config = SimpleNamespace(
        script=artifact,
        source_sha256=hashlib.sha256(b"different population").hexdigest(),
        source_git_checkout=checkout,
        source_git_repository_url="https://vendor.example/public.git",
        source_git_revision=revision,
        source_build_recipe=recipe,
    )

    with pytest.raises(ContractError, match="changed before verification"):
        grade_git_source_provenance(config, b"different population")


def test_git_input_pin_refuses_artifact_mutation_during_verification(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    checkout, recipe, artifact, revision = _git_fixture(tmp_path)
    payload = artifact.read_bytes()
    config = SimpleNamespace(
        script=artifact,
        source_sha256=hashlib.sha256(payload).hexdigest(),
        source_git_checkout=checkout,
        source_git_repository_url="https://vendor.example/public.git",
        source_git_revision=revision,
        source_build_recipe=recipe,
    )
    original = product_observation._read_stable_regular_bytes
    artifact_reads = 0

    def mutate_after_first_artifact_read(path: Path, **kwargs) -> bytes:
        nonlocal artifact_reads
        body = original(path, **kwargs)
        if path.resolve() == artifact.resolve():
            artifact_reads += 1
            if artifact_reads == 1:
                artifact.write_bytes(b"mutated after retained population")
        return body

    monkeypatch.setattr(
        product_observation,
        "_read_stable_regular_bytes",
        mutate_after_first_artifact_read,
    )

    with pytest.raises(ContractError, match="changed during verification"):
        grade_git_source_provenance(config, payload)


def test_git_input_pin_refuses_an_insteadof_rewritten_origin(
    tmp_path: Path,
) -> None:
    checkout, recipe, artifact, revision = _git_fixture(tmp_path)
    subprocess.run(
        ["git", "-C", str(checkout), "config", "remote.origin.url", "https://other.example/public.git"],
        check=True,
        capture_output=True,
    )
    subprocess.run(
        [
            "git", "-C", str(checkout), "config", "--add",
            "url.https://vendor.example/public.git.insteadOf",
            "https://other.example/public.git",
        ],
        check=True,
        capture_output=True,
    )
    expanded = subprocess.run(
        ["git", "-C", str(checkout), "remote", "get-url", "origin"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    assert expanded == "https://vendor.example/public.git"
    payload = artifact.read_bytes()
    config = SimpleNamespace(
        script=artifact,
        source_sha256=hashlib.sha256(payload).hexdigest(),
        source_git_checkout=checkout,
        source_git_repository_url=expanded,
        source_git_revision=revision,
        source_build_recipe=recipe,
    )

    with pytest.raises(ContractError, match="repository URL"):
        grade_git_source_provenance(config, payload)


def test_git_input_pin_refuses_multiple_raw_origin_urls(tmp_path: Path) -> None:
    checkout, recipe, artifact, revision = _git_fixture(tmp_path)
    subprocess.run(
        ["git", "-C", str(checkout), "config", "--add", "remote.origin.url", "https://other.example/public.git"],
        check=True,
        capture_output=True,
    )
    payload = artifact.read_bytes()
    config = SimpleNamespace(
        script=artifact,
        source_sha256=hashlib.sha256(payload).hexdigest(),
        source_git_checkout=checkout,
        source_git_repository_url="https://vendor.example/public.git",
        source_git_revision=revision,
        source_build_recipe=recipe,
    )

    with pytest.raises(ContractError, match="repository URL"):
        grade_git_source_provenance(config, payload)


def test_git_input_pin_refuses_different_trailing_slash_origin(tmp_path: Path) -> None:
    checkout, recipe, artifact, revision = _git_fixture(tmp_path)
    subprocess.run(
        [
            "git", "-C", str(checkout), "config", "remote.origin.url",
            "https://vendor.example/public.git/",
        ],
        check=True,
        capture_output=True,
    )
    payload = artifact.read_bytes()
    config = SimpleNamespace(
        script=artifact,
        source_sha256=hashlib.sha256(payload).hexdigest(),
        source_git_checkout=checkout,
        source_git_repository_url="https://vendor.example/public.git",
        source_git_revision=revision,
        source_build_recipe=recipe,
    )

    with pytest.raises(ContractError, match="repository URL"):
        grade_git_source_provenance(config, payload)


@pytest.mark.parametrize("suffix", ["?", "#"])
def test_git_input_pin_refuses_empty_query_or_fragment_delimiter(
    tmp_path: Path, suffix: str,
) -> None:
    checkout, recipe, artifact, revision = _git_fixture(tmp_path)
    repository_url = f"https://vendor.example/public.git{suffix}"
    subprocess.run(
        ["git", "-C", str(checkout), "config", "remote.origin.url", repository_url],
        check=True,
        capture_output=True,
    )
    payload = artifact.read_bytes()
    config = SimpleNamespace(
        script=artifact,
        source_sha256=hashlib.sha256(payload).hexdigest(),
        source_git_checkout=checkout,
        source_git_repository_url=repository_url,
        source_git_revision=revision,
        source_build_recipe=recipe,
    )

    with pytest.raises(ContractError, match="without a query or fragment"):
        grade_git_source_provenance(config, payload)


def test_git_input_pin_refuses_replaced_commit_tree(tmp_path: Path) -> None:
    checkout, recipe, artifact, revision = _git_fixture(tmp_path)
    recipe.write_bytes(b"different tracked recipe\n")
    subprocess.run(
        ["git", "-C", str(checkout), "add", "web/build.sh"],
        check=True,
        capture_output=True,
    )
    subprocess.run(
        [
            "git", "-C", str(checkout), "-c", "user.name=Browser Core Tests",
            "-c", "user.email=browser-core@example.invalid", "commit", "-q",
            "-m", "replacement source",
        ],
        check=True,
        capture_output=True,
    )
    replacement = subprocess.run(
        ["git", "-C", str(checkout), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    subprocess.run(
        ["git", "-C", str(checkout), "replace", revision, replacement],
        check=True,
        capture_output=True,
    )
    subprocess.run(
        ["git", "-C", str(checkout), "reset", "--hard", revision],
        check=True,
        capture_output=True,
    )
    assert recipe.read_bytes() == b"different tracked recipe\n"
    payload = artifact.read_bytes()
    config = SimpleNamespace(
        script=artifact,
        source_sha256=hashlib.sha256(payload).hexdigest(),
        source_git_checkout=checkout,
        source_git_repository_url="https://vendor.example/public.git",
        source_git_revision=revision,
        source_build_recipe=recipe,
    )

    with pytest.raises(ContractError, match="clean tracked worktree"):
        grade_git_source_provenance(config, payload)


def test_git_input_pin_refuses_origin_mutation_during_verification(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    checkout, recipe, artifact, revision = _git_fixture(tmp_path)
    payload = artifact.read_bytes()
    config = SimpleNamespace(
        script=artifact,
        source_sha256=hashlib.sha256(payload).hexdigest(),
        source_git_checkout=checkout,
        source_git_repository_url="https://vendor.example/public.git",
        source_git_revision=revision,
        source_build_recipe=recipe,
    )
    original = product_observation._require_git_output
    origin_reads = 0

    def mutate_after_first_origin_read(path: Path, *args: str, **kwargs) -> str:
        nonlocal origin_reads
        output = original(path, *args, **kwargs)
        if args == ("remote", "get-url", "origin"):
            origin_reads += 1
            if origin_reads == 1:
                subprocess.run(
                    [
                        "git",
                        "-C",
                        str(checkout),
                        "remote",
                        "set-url",
                        "origin",
                        "https://changed.example/public.git",
                    ],
                    check=True,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
        return output

    monkeypatch.setattr(
        product_observation,
        "_require_git_output",
        mutate_after_first_origin_read,
    )

    with pytest.raises(ContractError, match="changed during verification"):
        grade_git_source_provenance(config, payload)


def test_git_input_pin_bounds_tracked_inventory_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    checkout, recipe, artifact, revision = _git_fixture(tmp_path)
    recipe.write_text("dirty tracked recipe\n", encoding="utf-8")
    payload = artifact.read_bytes()
    config = SimpleNamespace(
        script=artifact,
        source_sha256=hashlib.sha256(payload).hexdigest(),
        source_git_checkout=checkout,
        source_git_repository_url="https://vendor.example/public.git",
        source_git_revision=revision,
        source_build_recipe=recipe,
    )
    monkeypatch.setattr(product_observation, "MAX_GIT_PROVENANCE_OUTPUT_BYTES", 1)

    with pytest.raises(ContractError, match="Git provenance query"):
        grade_git_source_provenance(config, payload)


def test_git_provenance_rejects_non_utf8_argument_before_process(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        product_observation,
        "run_with_bounded_stdout",
        lambda *_args, **_kwargs: pytest.fail("invalid argument reached Git"),
    )

    with pytest.raises(ContractError, match="Git provenance query is invalid"):
        product_observation._git_command(tmp_path, "\ud800")


def test_git_provenance_query_ignores_inherited_repository_redirection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    checkout, _recipe, _artifact, _revision = _git_fixture(tmp_path)
    foreign = tmp_path / "foreign"
    foreign.mkdir()
    subprocess.run(
        ["git", "init", "-q", str(foreign)], check=True, capture_output=True,
    )
    monkeypatch.setenv("GIT_DIR", str(foreign / ".git"))
    monkeypatch.setenv("GIT_WORK_TREE", str(foreign))

    result = product_observation._git_command(
        checkout, "rev-parse", "--show-toplevel",
    )
    assert result.returncode == 0
    assert Path(result.stdout.strip()).resolve() == checkout.resolve()


def test_git_provenance_query_disables_repository_fsmonitor(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    checkout, _recipe, _artifact, _revision = _git_fixture(tmp_path)
    for key in list(os.environ):
        if key.upper().startswith("GIT_"):
            monkeypatch.delenv(key)
    marker = tmp_path / "fsmonitor-fired.txt"
    monitor = f"sh -c 'echo invoked >> \"{marker.as_posix()}\"; exit 1'"
    subprocess.run(
        ["git", "-C", str(checkout), "config", "core.fsmonitor", monitor],
        check=True, capture_output=True,
    )
    baseline = subprocess.run(
        ["git", "--no-optional-locks", "-C", str(checkout),
         "status", "--porcelain=v1", "--untracked-files=no"],
        capture_output=True, text=True, timeout=15,
    )
    assert baseline.returncode == 0, baseline.stderr
    if not marker.exists():
        pytest.skip("installed Git does not invoke a configured filesystem monitor")
    marker.unlink()

    result = product_observation._git_command(
        checkout, "status", "--porcelain=v1", "--untracked-files=no",
    )
    assert result.returncode == 0
    assert not marker.exists()


def test_git_input_pin_does_not_execute_checkout_clean_filter(tmp_path: Path) -> None:
    checkout, recipe, artifact, _revision = _git_fixture(tmp_path)
    marker = tmp_path / "clean-filter-fired.txt"
    command = f"sh -c 'echo invoked >> \"{marker.as_posix()}\"; cat'"
    subprocess.run(
        ["git", "-C", str(checkout), "config", "filter.probe.clean", command],
        check=True,
        capture_output=True,
    )
    (checkout / ".gitattributes").write_text(
        "web/build.sh filter=probe\n", encoding="utf-8",
    )
    subprocess.run(
        ["git", "-C", str(checkout), "add", ".gitattributes"],
        check=True,
        capture_output=True,
    )
    subprocess.run(
        [
            "git", "-C", str(checkout),
            "-c", "user.name=Browser Core Tests",
            "-c", "user.email=browser-core@example.invalid",
            "commit", "-q", "-m", "tracked attributes",
        ],
        check=True,
        capture_output=True,
    )
    revision = subprocess.run(
        ["git", "-C", str(checkout), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    recipe.write_bytes(subprocess.run(
        ["git", "-C", str(checkout), "show", "HEAD:web/build.sh"],
        check=True,
        capture_output=True,
    ).stdout)
    original = recipe.stat()
    os.utime(recipe, ns=(original.st_atime_ns, original.st_mtime_ns + 2_000_000_000))
    subprocess.run(
        ["git", "-C", str(checkout), "status", "--porcelain=v1", "--untracked-files=no"],
        check=True,
        capture_output=True,
    )
    if not marker.exists():
        pytest.skip("installed Git did not invoke the configured clean filter")
    marker.unlink()
    payload = artifact.read_bytes()
    config = SimpleNamespace(
        script=artifact,
        source_sha256=hashlib.sha256(payload).hexdigest(),
        source_git_checkout=checkout,
        source_git_repository_url="https://vendor.example/public.git",
        source_git_revision=revision,
        source_build_recipe=recipe,
    )

    with pytest.raises(ContractError, match="clean filter"):
        grade_git_source_provenance(config, payload)

    assert not marker.exists()


def test_git_input_pin_bounds_build_recipe(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    checkout, recipe, artifact, revision = _git_fixture(tmp_path)
    payload = artifact.read_bytes()
    config = SimpleNamespace(
        script=artifact,
        source_sha256=hashlib.sha256(payload).hexdigest(),
        source_git_checkout=checkout,
        source_git_repository_url="https://vendor.example/public.git",
        source_git_revision=revision,
        source_build_recipe=recipe,
    )
    monkeypatch.setattr(product_observation, "MAX_BUILD_RECIPE_BYTES", 4)

    with pytest.raises(ContractError, match="build recipe"):
        grade_git_source_provenance(config, payload)


def test_git_input_pin_normalizes_malformed_repository_url_to_contract_error(
    tmp_path: Path,
) -> None:
    checkout, recipe, artifact, revision = _git_fixture(tmp_path)
    payload = artifact.read_bytes()
    config = SimpleNamespace(
        script=artifact,
        source_sha256=hashlib.sha256(payload).hexdigest(),
        source_git_checkout=checkout,
        source_git_repository_url="https://[invalid/public.git",
        source_git_revision=revision,
        source_build_recipe=recipe,
    )

    with pytest.raises(ContractError, match="repository URL"):
        grade_git_source_provenance(config, payload)


@pytest.mark.parametrize(
    "field",
    [
        "script",
        "source_git_checkout",
        "source_build_recipe",
        "source_rebuild_checkout",
        "source_rebuild_artifact",
    ],
)
def test_git_input_pin_normalizes_invalid_path_resolution(
    tmp_path: Path, field: str,
) -> None:
    checkout, recipe, artifact, revision = _git_fixture(tmp_path)
    payload = artifact.read_bytes()
    values = {
        "script": artifact,
        "source_sha256": hashlib.sha256(payload).hexdigest(),
        "source_git_checkout": checkout,
        "source_git_repository_url": "https://vendor.example/public.git",
        "source_git_revision": revision,
        "source_build_recipe": recipe,
    }
    if field.startswith("source_rebuild_"):
        rebuild = tmp_path / "independent-rebuild"
        subprocess.run(
            ["git", "-C", str(checkout), "worktree", "add", "--detach", str(rebuild), revision],
            capture_output=True,
            text=True,
            check=True,
        )
        values["source_rebuild_checkout"] = rebuild
        values["source_rebuild_artifact"] = rebuild / "web" / "static" / "js" / "main.mjs"
    values[field] = Path("invalid\x00path")

    with pytest.raises(ContractError, match="path is invalid"):
        grade_git_source_provenance(SimpleNamespace(**values), payload)


def test_git_input_pin_verifies_a_distinct_byte_identical_checkout_artifact(
    tmp_path: Path,
) -> None:
    checkout, recipe, artifact, revision = _git_fixture(tmp_path)
    rebuild = tmp_path / "independent-rebuild"
    subprocess.run(
        [
            "git",
            "-C",
            str(checkout),
            "worktree",
            "add",
            "--detach",
            str(rebuild),
            revision,
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    rebuild_artifact = rebuild / "web" / "static" / "js" / "main.mjs"
    rebuild_artifact.parent.mkdir(parents=True)
    rebuild_artifact.write_bytes(artifact.read_bytes())
    payload = artifact.read_bytes()
    config = SimpleNamespace(
        script=artifact,
        source_sha256=hashlib.sha256(payload).hexdigest(),
        source_git_checkout=checkout,
        source_git_repository_url="https://vendor.example/public.git",
        source_git_revision=revision,
        source_build_recipe=recipe,
        source_rebuild_checkout=rebuild,
        source_rebuild_artifact=rebuild_artifact,
    )

    verdict = grade_git_source_provenance(config, payload)

    assert verdict["distinct_checkout_artifact_verified"] is True
    assert verdict["rebuild_artifact_sha256"] == verdict["sha256"]
    portable = _sanitize_source_provenance(verdict)
    assert portable["distinct_checkout_artifact_verified"] is True
    assert portable["rebuild_artifact_sha256"] == portable["sha256"]
    assert str(rebuild) not in json.dumps(portable)
    for field in (
        "tracked_worktree_clean",
        "distinct_checkout_artifact_verified",
    ):
        hostile = {**verdict, field: "private-truthy-value"}
        assert _sanitize_source_provenance(hostile)["status"] == "unverifiable"

    rebuild_recipe = rebuild / "web" / "build.sh"
    rebuild_recipe.write_bytes(b"changed rebuild recipe bytes\n")
    subprocess.run(
        ["git", "-C", str(rebuild), "update-index", "--assume-unchanged", "web/build.sh"],
        check=True,
        capture_output=True,
    )
    with pytest.raises(ContractError, match="rebuild-artifact match requires"):
        grade_git_source_provenance(config, payload)


def test_git_input_pin_rejects_a_hard_link_as_a_distinct_artifact(
    tmp_path: Path,
) -> None:
    checkout, recipe, artifact, revision = _git_fixture(tmp_path)
    rebuild = tmp_path / "independent-rebuild"
    subprocess.run(
        ["git", "-C", str(checkout), "worktree", "add", "--detach", str(rebuild), revision],
        capture_output=True,
        text=True,
        check=True,
    )
    rebuild_artifact = rebuild / "web" / "static" / "js" / "main.mjs"
    rebuild_artifact.parent.mkdir(parents=True)
    os.link(artifact, rebuild_artifact)
    assert os.path.samefile(artifact, rebuild_artifact)
    payload = artifact.read_bytes()
    config = SimpleNamespace(
        script=artifact,
        source_sha256=hashlib.sha256(payload).hexdigest(),
        source_git_checkout=checkout,
        source_git_repository_url="https://vendor.example/public.git",
        source_git_revision=revision,
        source_build_recipe=recipe,
        source_rebuild_checkout=rebuild,
        source_rebuild_artifact=rebuild_artifact,
    )

    with pytest.raises(ContractError, match="physically distinct"):
        grade_git_source_provenance(config, payload)


def test_git_input_pin_refuses_a_rewritten_rebuild_origin(tmp_path: Path) -> None:
    checkout, recipe, artifact, revision = _git_fixture(tmp_path)
    rebuild = tmp_path / "independent-rebuild"
    subprocess.run(
        ["git", "clone", "-q", str(checkout), str(rebuild)],
        check=True,
        capture_output=True,
    )
    subprocess.run(
        ["git", "-C", str(rebuild), "config", "remote.origin.url", "https://other.example/public.git"],
        check=True,
        capture_output=True,
    )
    subprocess.run(
        [
            "git", "-C", str(rebuild), "config", "--add",
            "url.https://vendor.example/public.git.insteadOf",
            "https://other.example/public.git",
        ],
        check=True,
        capture_output=True,
    )
    assert subprocess.run(
        ["git", "-C", str(rebuild), "remote", "get-url", "origin"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip() == "https://vendor.example/public.git"
    rebuild_artifact = rebuild / "web" / "static" / "js" / "main.mjs"
    rebuild_artifact.parent.mkdir(parents=True)
    rebuild_artifact.write_bytes(artifact.read_bytes())
    payload = artifact.read_bytes()
    config = SimpleNamespace(
        script=artifact,
        source_sha256=hashlib.sha256(payload).hexdigest(),
        source_git_checkout=checkout,
        source_git_repository_url="https://vendor.example/public.git",
        source_git_revision=revision,
        source_build_recipe=recipe,
        source_rebuild_checkout=rebuild,
        source_rebuild_artifact=rebuild_artifact,
    )

    with pytest.raises(ContractError, match="rebuild-artifact repository URL"):
        grade_git_source_provenance(config, payload)


def test_git_input_pin_refuses_different_trailing_slash_rebuild_origin(
    tmp_path: Path,
) -> None:
    checkout, recipe, artifact, revision = _git_fixture(tmp_path)
    rebuild = tmp_path / "independent-rebuild"
    subprocess.run(
        ["git", "clone", "-q", str(checkout), str(rebuild)],
        check=True,
        capture_output=True,
    )
    subprocess.run(
        [
            "git", "-C", str(rebuild), "config", "remote.origin.url",
            "https://vendor.example/public.git/",
        ],
        check=True,
        capture_output=True,
    )
    rebuild_artifact = rebuild / "web" / "static" / "js" / "main.mjs"
    rebuild_artifact.parent.mkdir(parents=True)
    rebuild_artifact.write_bytes(artifact.read_bytes())
    payload = artifact.read_bytes()
    config = SimpleNamespace(
        script=artifact,
        source_sha256=hashlib.sha256(payload).hexdigest(),
        source_git_checkout=checkout,
        source_git_repository_url="https://vendor.example/public.git",
        source_git_revision=revision,
        source_build_recipe=recipe,
        source_rebuild_checkout=rebuild,
        source_rebuild_artifact=rebuild_artifact,
    )

    with pytest.raises(ContractError, match="rebuild-artifact repository URL"):
        grade_git_source_provenance(config, payload)


# ------------------------------------------------------------------ trace analysis


def _event(
    category: str,
    name: str,
    *,
    component: str = "blink.bindings.generated",
    context: str = "frame",
    request: dict | None = None,
    script_id: str | None = None,
    detail: dict | None = None,
) -> dict:
    # The trace contract forbids one event naming both a frame and a worker, so
    # frame/worker coverage is proved by two events, exactly as in real traces.
    generated_binding = component == "blink.bindings.generated"
    if generated_binding:
        thread_id = 43 if context == "frame" else 44
        context_id = f"bindings:1234:{thread_id}"
        execution = {"context_id": context_id}
        execution["frame_id" if context == "frame" else "worker_id"] = context_id
        if script_id is not None:
            script_number = script_id.rsplit(":", 1)[-1]
            execution["script_id"] = f"v8:1234:bindings:{thread_id}:{script_number}"
    else:
        context_id = "F1" if context == "frame" else "W1"
        if script_id is not None and script_id.startswith("v8:1234:"):
            context_id = script_id.removeprefix("v8:1234:").rsplit(":", 1)[0]
        execution = {"context_id": context_id}
        execution["frame_id" if context == "frame" else "worker_id"] = context_id
        if script_id is not None:
            execution["script_id"] = script_id
    event: dict[str, object] = {
        "schema": "browser-core.trace-event/1",
        "run_id": "core-test-run",
        "seq": 0,
        "ts_monotonic_ns": 1,
        "process": {"pid": 1234, "type": "renderer"},
        "event": {"category": category, "name": name},
        "provenance": {"component": component, "source": "native"},
        "execution": execution,
    }
    if generated_binding:
        event["provenance"]["trace_category"] = "blink.bindings"
        event["detail"] = {
            "native_name": name,
            "thread_id": thread_id,
            "completion": "complete",
            "duration_ns": 1,
        }
        if script_id is not None:
            event["detail"]["script_attribution"] = "script-run-not-in-trace"
    if request is not None:
        event["request"] = request
    if detail is not None:
        event["detail"] = detail
    return event


def _write_trace(path: Path, events: list[dict]) -> Path:
    for index, event in enumerate(events):
        event["seq"] = index
        event["ts_monotonic_ns"] = 1_000 + index
    path.write_text("\n".join(json.dumps(e) for e in events) + "\n", encoding="utf-8")
    return path


def test_analysis_rejects_late_lineage_error_instead_of_publishing_counts(tmp_path):
    first = _event("api", "Navigator.webdriver.get")
    second = _event("api", "Navigator.webdriver.get")
    second["causal_parent_seq"] = 999
    trace = _write_trace(tmp_path / "late-invalid.jsonl", [first, second])
    with pytest.raises(ContractError):
        analyse_observation_trace(trace)


def _scan_without_population_validation(path, consume):
    from browser_core.trace import iter_trace

    count = 0
    for event in iter_trace(path):
        consume(event)
        count += 1
    return {"events": count, "dropped_events": 0}


def test_analysis_splits_attributable_from_generated(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(
        "browser_core.product_observation.scan_validated_trace",
        _scan_without_population_validation,
    )
    trace = _write_trace(
        tmp_path / "t.jsonl",
        [
            _event("api", "Navigator.webdriver.get"),
            _event("api", "Navigator.webdriver.get"),
            _event(
                "execution",
                "script.run",
                component="blink.v8",
                script_id="v8:1234:F1:7",
                detail={"native_name": "BrowserCore.ScriptRun", "thread_id": 1},
            ),
        ],
    )
    analysis = analyse_observation_trace(trace)
    assert analysis["total_events"] == 3
    assert analysis["attributable_events"] == 1
    assert analysis["attributable_fraction"] == pytest.approx(1 / 3)
    assert analysis["events_by_name"]["api.Navigator.webdriver.get"] == 2
    assert analysis["distinct_api_names"] == 2
    assert analysis["script_attributed_events"] == 0
    assert analysis["script_attributed_events_by_name"] == {}


def test_analysis_counts_script_attributed_generated_bindings(
    tmp_path, monkeypatch
) -> None:
    monkeypatch.setattr(
        "browser_core.product_observation.scan_validated_trace",
        _scan_without_population_validation,
    )
    trace = _write_trace(
        tmp_path / "t.jsonl",
        [
            _event("api", "Navigator.userAgent.get"),
            _event(
                "api",
                "Navigator.userAgent.get",
                script_id="v8:1234:frame-token:7",
            ),
            _event(
                "execution",
                "script.run",
                component="blink.v8",
                script_id="v8:1234:F1:7",
                detail={"native_name": "BrowserCore.ScriptRun", "thread_id": 1},
            ),
        ],
    )

    analysis = analyse_observation_trace(trace)
    assert analysis["attributable_events"] == 2
    assert analysis["script_attributed_events"] == 1
    assert analysis["script_attributed_events_by_name"] == {
        "api.Navigator.userAgent.get": 1
    }


def test_analysis_summarizes_complete_and_open_script_execution_scopes(
    tmp_path, monkeypatch
) -> None:
    monkeypatch.setattr(
        "browser_core.product_observation.scan_validated_trace",
        _scan_without_population_validation,
    )
    trace = _write_trace(
        tmp_path / "t.jsonl",
        [
            _event(
                "execution",
                "script.execution",
                component="blink.v8",
                script_id="v8:1234:frame-token:7",
                detail={
                    "native_name": "BrowserCore.ScriptExecution",
                    "thread_id": 43,
                    "completion": "complete",
                    "duration_ns": 123_456,
                },
            ),
            _event(
                "execution",
                "script.execution",
                component="blink.v8",
                script_id="v8:1234:frame-token:8",
                detail={
                    "native_name": "BrowserCore.ScriptExecution",
                    "thread_id": 43,
                    "completion": "complete",
                    "duration_ns": 789_000,
                },
            ),
            _event(
                "execution",
                "script.execution",
                component="blink.v8",
                script_id="v8:1234:frame-token:9",
                detail={
                    "native_name": "BrowserCore.ScriptExecution",
                    "thread_id": 43,
                    "completion": "open",
                },
            ),
        ],
    )

    analysis = analyse_observation_trace(trace)
    assert analysis["script_execution"] == {
        "total": 3,
        "complete": 2,
        "open": 1,
        "max_complete_duration_ns": 789_000,
    }


def test_analysis_records_worker_context_and_request_classes(
    tmp_path, monkeypatch
) -> None:
    monkeypatch.setattr(
        "browser_core.product_observation.scan_validated_trace",
        _scan_without_population_validation,
    )
    trace = _write_trace(
        tmp_path / "t.jsonl",
        [
            _event(
                "network",
                "fetch.start",
                component="blink.fetch",
                context="worker",
                request={
                    "id": "fetch-request:worker:1",
                    "method": "HEAD",
                    "url_class": "cross-origin:/popup.html",
                    "target_scope": "loopback",
                    "body_bytes": 0,
                },
            ),
            _event("api", "OffscreenCanvas.getContext", context="frame"),
            _event("api", "OffscreenCanvas.getContext", context="worker"),
        ],
    )
    analysis = analyse_observation_trace(trace)
    assert analysis["context_coverage"]["network.fetch.start"] == ["worker"]
    assert analysis["context_coverage"]["api.OffscreenCanvas.getContext"] == [
        "frame",
        "worker",
    ]
    assert analysis["execution_context_counts"] == {
        "generated_binding": {"frame": 1, "worker": 1},
        "native": {"frame": 0, "worker": 1},
    }
    assert "must not be summed" in analysis["execution_context_count_note"]
    assert analysis["request_methods"] == {"HEAD": 1}
    assert analysis["distinct_request_classes"] == 1
    assert analysis["fetch_target_scope"] == {
        "coverage": "complete",
        "requests": 1,
        "loopback": 1,
        "external": 0,
        "non_network": 0,
        "unclassified": 0,
    }


def test_analysis_flags_external_fetch_target_without_retaining_a_url(
    tmp_path, monkeypatch
) -> None:
    """The defense-in-depth receipt is typed metadata, never a target URL."""
    monkeypatch.setattr(
        "browser_core.product_observation.scan_validated_trace",
        _scan_without_population_validation,
    )
    trace = _write_trace(
        tmp_path / "t.jsonl",
        [
            _event(
                "network",
                "fetch.start",
                component="blink.fetch",
                request={
                    "id": "fetch-request:frame:1",
                    "method": "GET",
                    "url_class": "https:cross-origin:/x",
                    "target_scope": "external",
                    "body_bytes": 0,
                },
            )
        ],
    )
    analysis = analyse_observation_trace(trace)
    assert analysis["fetch_target_scope"] == {
        "coverage": "complete",
        "requests": 1,
        "loopback": 0,
        "external": 1,
        "non_network": 0,
        "unclassified": 0,
    }
    assert "example.invalid" not in json.dumps(analysis)


def test_analysis_keeps_legacy_fetch_target_scope_unknown(
    tmp_path, monkeypatch
) -> None:
    monkeypatch.setattr(
        "browser_core.product_observation.scan_validated_trace",
        _scan_without_population_validation,
    )
    trace = _write_trace(
        tmp_path / "legacy.jsonl",
        [
            _event(
                "network",
                "fetch.start",
                component="blink.fetch",
                request={
                    "id": "fetch-request:frame:1",
                    "method": "GET",
                    "url_class": "same-origin:/x",
                    "body_bytes": 0,
                },
            )
        ],
    )
    assert analyse_observation_trace(trace)["fetch_target_scope"] == {
        "coverage": "unknown",
        "requests": 1,
        "loopback": 0,
        "external": 0,
        "non_network": 0,
        "unclassified": 1,
    }


def test_offline_guard_rule_uses_pinned_failure_and_owned_loopback_mapping() -> None:
    import browser_core.product_observation as po

    assert po._offline_resolver_rule(43123) == (
        "--host-resolver-rules=MAP 127.0.0.1 127.0.0.1:43123, " "MAP * ^NOTFOUND"
    )


@pytest.mark.parametrize("port", [None, True, 0, 65536, "43123"])
def test_offline_guard_rule_rejects_invalid_owned_port(port) -> None:
    import browser_core.product_observation as po

    with pytest.raises(ContractError, match="port"):
        po._offline_resolver_rule(port)


def _offline_guard(port: int) -> dict:
    return {
        "status": "applied",
        "resolver_rule": (
            "--host-resolver-rules=" f"MAP 127.0.0.1 127.0.0.1:{port}, MAP * ^NOTFOUND"
        ),
        "proxy_policy": "deny-all-except-owned-loopback-origin",
        "webrtc_policy": "disable-non-proxied-udp",
        "quic_policy": "disabled",
        "proxy_endpoint": f"127.0.0.1:{port}",
        "bypass_endpoint": f"127.0.0.1:{port}",
    }


def test_offline_guard_projection_validates_cross_field_port_arithmetic() -> None:
    projected = _sanitize_offline_guard(_offline_guard(43123))

    assert projected == {
        "status": "applied",
        "resolver_policy": "owned-loopback-port-map-and-not-found-others",
        "proxy_policy": "deny-all-except-owned-loopback-origin",
        "webrtc_policy": "disable-non-proxied-udp",
        "quic_policy": "disabled",
        "endpoint_coherence": "single-owned-loopback-port",
    }
    assert _sanitize_offline_guard(projected) == projected
    assert "43123" not in json.dumps(projected)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("resolver_rule", "--host-resolver-rules=MAP * 203.0.113.1"),
        ("proxy_policy", "direct"),
        ("webrtc_policy", "default"),
        ("quic_policy", "enabled"),
        ("proxy_endpoint", "127.0.0.1:43124"),
        ("bypass_endpoint", "127.0.0.1:43124"),
    ],
)
def test_offline_guard_projection_rejects_edited_policy_or_endpoint(
    field: str,
    value: str,
) -> None:
    edited = _offline_guard(43123)
    edited[field] = value

    assert _sanitize_offline_guard(edited) == {"status": "unverifiable"}


@pytest.mark.parametrize(
    "argument",
    [
        "--host-resolver-rules=MAP * 203.0.113.1",
        "--host-rules=MAP * 203.0.113.1",
        "--no-proxy-server",
        "--proxy-server=http://203.0.113.1:8080",
        "--enable-quic",
        "--origin-to-force-quic-on=203.0.113.1:443",
        "--quic-version=h3",
        "--remote-debugging-port=9222",
        "--trace-startup=disabled",
        "--user-data-dir=elsewhere",
    ],
)
def test_observation_flags_cannot_override_owned_or_offline_policy(
    tmp_path: Path, argument: str
) -> None:
    import browser_core.product_observation as po

    sample = tmp_path / "sample.js"
    sample.write_text("// sample", encoding="utf-8")
    config = po.ProductScriptObservation(
        script=sample,
        label="flag-guard",
        executable=tmp_path / "chrome.exe",
        trace_processor=tmp_path / "trace_processor.exe",
        workspace=tmp_path,
        extra_browser_args=(argument,),
    )

    with pytest.raises(ContractError, match="cannot override"):
        po.validate_product_script_observation_config(config)


@pytest.mark.parametrize(
    "arguments",
    [
        ["--disable-gpu"],
        ("positional-target",),
        ("--window-size=800,600\n--no-proxy-server",),
        ("--custom=" + ("x" * 4_100),),
    ],
)
def test_observation_flags_are_bounded_complete_tuple_members(
    tmp_path: Path, arguments
) -> None:
    import browser_core.product_observation as po

    sample = tmp_path / "sample.js"
    sample.write_text("// sample", encoding="utf-8")
    config = po.ProductScriptObservation(
        script=sample,
        label="flag-shape",
        executable=tmp_path / "chrome.exe",
        trace_processor=tmp_path / "trace_processor.exe",
        workspace=tmp_path,
        extra_browser_args=arguments,
    )

    with pytest.raises(ContractError):
        po.validate_product_script_observation_config(config)


def test_observation_accepts_a_bounded_method_flag(tmp_path: Path) -> None:
    import browser_core.product_observation as po

    sample = tmp_path / "sample.js"
    sample.write_text("// sample", encoding="utf-8")
    config = po.ProductScriptObservation(
        script=sample,
        label="flag-safe",
        executable=tmp_path / "chrome.exe",
        trace_processor=tmp_path / "trace_processor.exe",
        workspace=tmp_path,
        extra_browser_args=("--disable-gpu",),
    )

    assert po.validate_product_script_observation_config(config) is config


def test_observation_rejects_a_timeout_the_cdp_layer_cannot_honor(
    tmp_path: Path,
) -> None:
    import browser_core.product_observation as po

    sample = tmp_path / "sample.js"
    sample.write_text("// sample", encoding="utf-8")
    config = po.ProductScriptObservation(
        script=sample,
        label="timeout-mismatch",
        executable=tmp_path / "chrome.exe",
        trace_processor=tmp_path / "trace_processor.exe",
        workspace=tmp_path,
        timeout_seconds=301.0,
    )

    with pytest.raises(ContractError, match=r"timeout seconds.*\(0, 300\]"):
        po.validate_product_script_observation_config(config)


@pytest.mark.parametrize("field", ["dom_profile", "hook_mode", "input_profile"])
@pytest.mark.parametrize("value", [True, 1, [], {}])
def test_observation_config_rejects_unhashable_or_non_text_method_enums_cleanly(
    tmp_path: Path,
    field,
    value,
) -> None:
    import browser_core.product_observation as po

    sample = tmp_path / "sample.js"
    sample.write_text("// sample", encoding="utf-8")
    kwargs = {
        "script": sample,
        "label": "enum-shape",
        "executable": tmp_path / "chrome.exe",
        "trace_processor": tmp_path / "trace_processor.exe",
        "workspace": tmp_path,
        field: value,
    }

    with pytest.raises(ContractError, match="must be one of"):
        po.validate_product_script_observation_config(
            po.ProductScriptObservation(**kwargs)
        )


# ------------------------------------------------------------------ dom profiles


def test_both_dom_profiles_load_the_script_and_keep_the_title() -> None:
    """The two profiles must differ only in the document, never in the harness."""
    for profile in DOM_PROFILES:
        handler = _handler(b"//script", _RequestLogStub(), profile)
        assert handler is not None
    minimal = DOM_PROFILES["minimal"]
    rich = DOM_PROFILES["rich"]
    assert len(rich) > len(minimal) * 5
    for body in (minimal, rich):
        assert "<form" in body
        assert "<input" in body
        # The script tag and title live in the shared template, not the profile.
        assert "product-script.js" not in body
        assert PAGE_TITLE not in body


def test_rich_profile_adds_surfaces_a_bare_page_lacks() -> None:
    rich = DOM_PROFILES["rich"]
    for token in (
        "<table",
        "<iframe",
        "<canvas",
        "<video",
        "<audio",
        "<select",
        "<textarea",
        'type="password"',
    ):
        assert token in rich, token


def test_tall_profile_has_an_explicit_scroll_range() -> None:
    assert "bc-scroll-space" in DOM_PROFILES["tall"]
    assert "2400px" in DOM_PROFILES["tall"]


def test_unknown_dom_profile_is_rejected() -> None:
    with pytest.raises(ContractError, match="dom profile must be one of"):
        _handler(b"//script", _RequestLogStub(), "enormous")


def test_script_path_is_settable_so_a_rehost_can_mirror_a_real_deployment() -> None:
    """The collector reads its own script src, so the serving path is observable."""
    assert _handler(b"//s", _RequestLogStub(), "minimal", "/akam/13/abc123.js")


@pytest.mark.parametrize(
    "bad",
    [
        "product-script.js",
        "x" * 600,
        "/",
        "//vendor.example/a.js",
        "/a.js?tenant=private",
        "/a.js#fragment",
        "/a\\b.js",
        "/a b.js",
        "/a%ZZ.js",
        "/a<b.js",
        '/a"b.js',
    ],
)
def test_malformed_script_path_is_rejected(bad) -> None:
    with pytest.raises(ContractError, match="script path must be"):
        _handler(b"//s", _RequestLogStub(), "minimal", bad)


def test_script_path_cannot_shadow_the_argument_hook() -> None:
    with pytest.raises(ContractError, match="collides with the observation hook"):
        _handler(
            b"//s",
            _RequestLogStub(),
            "minimal",
            "/bc-observer.js",
            "on",
        )


def test_script_path_html_escape_and_request_route_name_the_same_sample() -> None:
    log = _RequestLog()
    path = "/v1/client&variant.js"
    page = build_rehost_page(script_path=path)
    assert b'src="/v1/client&amp;variant.js"' in page

    handler = object.__new__(_handler(b"// exact sample", log, script_path=path))
    handler.path = path
    responses = []
    handler._send = lambda payload, content_type: responses.append(
        (payload, content_type)
    )

    handler.do_GET()

    assert responses == [(b"// exact sample", "text/javascript; charset=utf-8")]
    assert log.entries == [
        {
            "order": 0,
            "method": "GET",
            "path": path,
            "path_truncated": False,
            "path_sha256_16": None,
            "request_body_bytes": 0,
            "served": "sample",
        }
    ]


def test_handler_retains_query_names_but_never_query_values() -> None:
    log = _RequestLog()
    handler = object.__new__(_handler(b"// sample", log))
    handler.path = "/next/stage.js?token=private-value&lang=en"
    responses = []
    handler._send = lambda payload, content_type: responses.append(
        (payload, content_type)
    )

    handler.do_GET()

    assert responses == [(b"", "application/octet-stream")]
    assert log.entries[0]["path"] == "/next/stage.js"
    assert log.entries[0]["query_names"] == ["lang", "token"]
    assert log.entries[0]["query_names_truncated"] is False
    assert "private-value" not in json.dumps(log.entries)

    report = project_server_request_activity(log.entries)
    assert report["rows"][0]["query_names"] == ["lang", "token"]
    assert "private-value" not in json.dumps(report)


def test_request_shape_omits_non_utf8_query_name() -> None:
    shape = product_observation._request_path_shape("/next?bad\ud800=value")

    assert shape is not None
    assert shape["query_names"] == []
    assert shape["query_names_truncated"] is True


def test_rehost_handler_denies_absolute_form_proxy_request_without_authority() -> None:
    log = _RequestLog()
    handler = object.__new__(_handler(b"// sample", log))
    handler.path = "http://private-host.invalid/private/path?token=private-value"
    statuses = []
    handler._send_empty_status = statuses.append

    handler.do_GET()

    entries, dropped = log.snapshot()
    assert statuses == [502]
    assert dropped == 0
    assert entries[0]["served"] == "proxy-denied"
    assert entries[0]["path"] == "/<proxy-http>"
    assert "query_names" not in entries[0]
    rendered = json.dumps(entries)
    assert "private-host.invalid" not in rendered
    assert "token" not in rendered
    assert "private-value" not in rendered


@pytest.mark.parametrize(
    ("command", "retained_method"),
    [
        ("HEAD", "HEAD"),
        ("PUT", "PUT"),
        ("PATCH", "PATCH"),
        ("DELETE", "DELETE"),
        ("OPTIONS", "OPTIONS"),
        ("TRACE", "TRACE"),
        ("PRIVATE_SECRET_METHOD", "OTHER"),
    ],
)
def test_rehost_handler_accounts_for_every_unsupported_proxy_method_without_values(
    command: str,
    retained_method: str,
) -> None:
    log = _RequestLog()
    handler = object.__new__(_handler(b"// sample", log))
    handler.command = command
    handler.path = "https://private-host.invalid/private/path?private_name=value"
    statuses = []
    handler._send_empty_status = statuses.append

    handler.send_error(501)

    entries, dropped = log.snapshot()
    assert statuses == [502]
    assert dropped == 0
    assert entries[0]["method"] == retained_method
    assert entries[0]["path"] == "/<proxy-http>"
    assert entries[0]["served"] == "proxy-denied"
    assert "query_names" not in entries[0]
    rendered = json.dumps(entries)
    assert "private-host.invalid" not in rendered
    assert "private_name" not in rendered
    assert "PRIVATE_SECRET_METHOD" not in rendered


@pytest.mark.parametrize("command", ["HEAD", "PUT", "PRIVATE_SECRET_METHOD"])
def test_base_http_dispatch_routes_unsupported_proxy_methods_into_the_deny_receipt(
    command: str,
) -> None:
    class RetainedWriter(io.BytesIO):
        def close(self) -> None:
            self.flush()

    class FakeSocket:
        def __init__(self, request: bytes) -> None:
            self.reader = io.BytesIO(request)
            self.writer = RetainedWriter()

        def makefile(self, mode: str, _buffering: int = -1):
            assert mode == "rb"
            return self.reader

        def sendall(self, payload: bytes) -> None:
            self.writer.write(payload)

    target = "http://private-host.invalid/private?private_name=value"
    request = (
        f"{command} {target} HTTP/1.1\r\n"
        "Host: private-host.invalid\r\n"
        "Connection: close\r\n\r\n"
    ).encode("ascii")
    connection = FakeSocket(request)
    log = _RequestLog()

    _handler(b"// sample", log)(
        connection,
        ("127.0.0.1", 12345),
        SimpleNamespace(),
    )

    entries, dropped = log.snapshot()
    assert connection.writer.getvalue().startswith(b"HTTP/1.1 502")
    assert dropped == 0
    assert entries[0]["method"] == (
        command if command != "PRIVATE_SECRET_METHOD" else "OTHER"
    )
    assert entries[0]["path"] == "/<proxy-http>"
    assert entries[0]["served"] == "proxy-denied"
    verdict = grade_unserved_requests(entries)
    assert verdict["status"] == "ok"
    assert verdict["dependencies_complete"] is True
    assert verdict["proxy_denied"]["methods"] == {entries[0]["method"]: 1}
    rendered = json.dumps(entries)
    assert "private-host.invalid" not in rendered
    assert "private_name" not in rendered
    assert "PRIVATE_SECRET_METHOD" not in rendered


def test_rehost_handler_denies_connect_without_retaining_authority() -> None:
    log = _RequestLog()
    handler = object.__new__(_handler(b"// sample", log))
    handler.path = "private-host.invalid:443"
    statuses = []
    handler._send_empty_status = statuses.append

    handler.do_CONNECT()

    entries, dropped = log.snapshot()
    assert statuses == [502]
    assert dropped == 0
    assert entries == [
        {
            "order": 0,
            "method": "CONNECT",
            "path": "/<proxy-connect>",
            "path_truncated": False,
            "path_sha256_16": None,
            "request_body_bytes": 0,
            "served": "proxy-denied",
        }
    ]
    assert "private-host.invalid" not in json.dumps(entries)


@pytest.mark.parametrize(
    "bad_prefix",
    [
        "relative/stage",
        "//vendor.example/stage.js",
        "/stage.js?tenant=private",
        "/stage.js#fragment",
        "/stage\\child.js",
        "/stage child.js",
        "/stage%ZZ.js",
    ],
)
def test_stage_prefix_must_survive_the_browser_request_round_trip(
    bad_prefix: str,
) -> None:
    with pytest.raises(ContractError, match="stage route prefix must be"):
        _handler(
            b"// sample",
            _RequestLogStub(),
            stage_routes=((bad_prefix, b"// stage"),),
        )


def test_root_stage_prefix_remains_an_explicit_catch_all() -> None:
    log = _RequestLog()
    handler = object.__new__(
        _handler(b"// sample", log, stage_routes=(("/", b"// stage"),))
    )
    handler.path = "/dynamic/worker.js"
    responses = []
    handler._send = lambda payload, content_type: responses.append(
        (payload, content_type)
    )

    handler.do_GET()

    assert responses == [(b"// stage", "text/javascript; charset=utf-8")]
    assert log.entries[0]["served"] == "stage"


def test_rehost_post_body_is_consumed_in_bounded_chunks() -> None:
    class RecordingStream(io.BytesIO):
        reads: list[int]

        def __init__(self, payload: bytes) -> None:
            super().__init__(payload)
            self.reads = []

        def read(self, size: int = -1) -> bytes:
            self.reads.append(size)
            return super().read(size)

    log = _RequestLog()
    handler_type = _handler(b"//s", log)
    handler = object.__new__(handler_type)
    payload = b"x" * (REQUEST_BODY_CHUNK_BYTES * 2 + 7)
    stream = RecordingStream(payload)
    handler.path = "/post"
    handler.headers = Message()
    handler.headers["Content-Length"] = str(len(payload))
    handler.rfile = stream
    responses = []
    handler._send = lambda body, content_type: responses.append((body, content_type))

    handler.do_POST()

    assert max(stream.reads) <= REQUEST_BODY_CHUNK_BYTES
    assert log.entries[0]["request_body_bytes"] == len(payload)
    assert (
        log.entries[0]["request_body_sha256_16"]
        == hashlib.sha256(payload).hexdigest()[:16]
    )
    assert log.entries[0]["served"] == "post-ack"
    assert responses == [(b"{}", "application/json")]


def test_rehost_partial_post_never_publishes_a_body_digest() -> None:
    log = _RequestLog()
    handler = object.__new__(_handler(b"//s", log))
    handler.path = "/post"
    handler.headers = Message()
    handler.headers["Content-Length"] = "8"
    handler.rfile = io.BytesIO(b"only")
    statuses = []
    handler._send_empty_status = statuses.append

    handler.do_POST()

    assert statuses == [400]
    assert log.entries[0]["served"] == "incomplete-body"
    assert "request_body_sha256_16" not in log.entries[0]


@pytest.mark.parametrize(
    "lengths",
    [[], ["0", "0"], ["00"], ["+0"]],
)
def test_rehost_rejects_missing_or_ambiguous_post_length(lengths: list[str]) -> None:
    log = _RequestLog()
    handler = object.__new__(_handler(b"//s", log))
    handler.path = "/post"
    headers = Message()
    for length in lengths:
        headers.add_header("Content-Length", length)
    handler.headers = headers
    handler.rfile = io.BytesIO()
    statuses = []
    handler._send_empty_status = statuses.append
    handler._send = lambda *_args: pytest.fail("invalid POST was acknowledged")

    handler.do_POST()

    assert statuses == [400]
    assert handler.close_connection is True
    assert log.entries[0]["served"] == "invalid-body-length"


def test_rehost_rejects_oversized_post_without_reading_the_body() -> None:
    class NoRead:
        def read(self, _size: int = -1) -> bytes:
            pytest.fail("oversized request body must not be read")

    log = _RequestLog()
    handler_type = _handler(b"//s", log)
    handler = object.__new__(handler_type)
    handler.path = "/post"
    handler.headers = Message()
    handler.headers["Content-Length"] = str(MAX_REHOST_POST_BODY_BYTES + 1)
    handler.rfile = NoRead()
    statuses = []
    handler._send_empty_status = statuses.append

    handler.do_POST()

    assert statuses == [413]
    assert handler.close_connection is True
    assert log.entries[0]["served"] == "body-too-large"


def test_rehost_times_out_a_stalled_in_cap_post_body() -> None:
    class StalledBody:
        def read(self, _size: int = -1) -> bytes:
            raise TimeoutError("stalled")

    class Connection:
        timeout = None

        def settimeout(self, value: float) -> None:
            self.timeout = value

    log = _RequestLog()
    handler_type = _handler(b"//s", log)
    handler = object.__new__(handler_type)
    handler.path = "/post"
    handler.headers = Message()
    handler.headers["Content-Length"] = "10"
    handler.rfile = StalledBody()
    handler.connection = Connection()
    statuses = []
    handler._send_empty_status = statuses.append

    handler.do_POST()

    assert statuses == [408]
    assert handler.close_connection is True
    assert handler.connection.timeout == 5.0
    assert log.entries[0]["served"] == "body-read-timeout"


def test_rehost_rejects_body_completed_after_total_deadline(monkeypatch) -> None:
    now = [0.0]

    class SlowBody:
        def read(self, _size: int = -1) -> bytes:
            now[0] = 6.0
            return b"abc"

    class Connection:
        def settimeout(self, _value: float) -> None:
            pass

    monkeypatch.setattr(
        product_observation,
        "time",
        SimpleNamespace(monotonic=lambda: now[0]),
    )
    log = _RequestLog()
    handler = object.__new__(_handler(b"//s", log))
    handler.path = "/post"
    handler.headers = Message()
    handler.headers["Content-Length"] = "3"
    handler.rfile = SlowBody()
    handler.connection = Connection()
    statuses = []
    handler._send_empty_status = statuses.append
    handler._send = lambda *_args: pytest.fail("late POST body was acknowledged")

    handler.do_POST()

    assert statuses == [408]
    assert log.entries[0]["served"] == "body-read-timeout"
    assert "request_body_sha256_16" not in log.entries[0]


def test_bounded_request_log_makes_request_conclusions_unverifiable(
    monkeypatch,
) -> None:
    import browser_core.product_observation as po

    monkeypatch.setattr(po, "MAX_REHOST_REQUEST_LOG_ENTRIES", 2)
    log = po._RequestLog()
    log.add("GET", "/served", 0, served="page")
    log.add("GET", "/missing", 0, served="empty")
    log.add("GET", "/dropped", 0, served="empty")

    entries, activity, unserved, receipt = po._request_log_artifacts(log)

    assert len(entries) == 2
    assert receipt == {
        "limit": 2,
        "retained": 2,
        "dropped": 1,
        "truncated_paths": 0,
        "truncated": True,
        "proxy_denied": 0,
    }
    assert activity["status"] == "unverifiable"
    assert activity["truncated"] is True
    assert activity["dropped_requests"] == 1
    assert unserved["status"] == "unverifiable"
    assert unserved["dependencies_complete"] is None
    assert unserved["paths"] == ["/missing"]
    assert "incomplete" in unserved["note"]


def test_request_log_caps_each_path_and_withholds_exact_stage_conclusions(
    monkeypatch,
) -> None:
    import browser_core.product_observation as po

    monkeypatch.setattr(po, "MAX_REHOST_LOG_PATH_CHARS", 8)
    log = po._RequestLog()
    raw_path = "/private-stage-path"
    log.add("GET", raw_path, 0, served="empty")

    entries, activity, unserved, receipt = po._request_log_artifacts(log)

    assert entries[0]["path"] == raw_path[:8]
    assert entries[0]["path_truncated"] is True
    assert (
        entries[0]["path_sha256_16"]
        == hashlib.sha256(raw_path.encode()).hexdigest()[:16]
    )
    assert receipt["truncated_paths"] == 1
    assert activity["status"] == "unverifiable"
    assert activity["truncated_paths"] == 1
    assert unserved["status"] == "unverifiable"
    assert unserved["paths"] == []


class _RequestLogStub:
    entries: list = []

    def add(self, *_args: object) -> None:
        return


# ------------------------------------------------------------------ subtraction


def _observation(label: str, sha: str, names: dict[str, int], coverage=None) -> dict:
    return {
        "schema": OBSERVATION_SCHEMA,
        "generated_at": "2026-08-12T01:02:03Z",
        "label": label,
        "script_sha256_16": sha,
        "analysis": {
            "events_by_name": names,
            "context_coverage": coverage or {},
        },
        "collector_startup": {"started": True, "reasons": []},
    }


def _current_method_observation(label: str, sha: str, names: dict[str, int]) -> dict:
    complete_names = {"api.ControlBaseline": 1, **names}
    document = _observation(label, sha, complete_names)
    digest = (
        sha.lower()
        if re.fullmatch(r"[0-9a-fA-F]{16}", sha)
        else hashlib.sha256(sha.encode("utf-8")).hexdigest()[:16]
    )
    script_bytes = 100_000
    document["script_sha256_16"] = digest
    document["script_bytes"] = script_bytes
    document["script_identity"] = {
        "schema": IDENTITY_SCHEMA,
        "signals": {
            "bytes": script_bytes,
            "sha256_16": digest,
            "lines": 1,
            "arrow_functions": 0,
            "string_literals": 100,
            "bmak_literals": 0,
            "kpsdk_literals": 0,
            "istl_literals": 0,
            "px_literals": 0,
            "datadome_literals": 0,
            "turnstile_literals": 0,
            "imperva_apg_markers": 0,
            "geetest_loader_markers": 0,
            "anubis_challenge_markers": 0,
            "function_keywords": 100,
            "max_line_bytes": script_bytes,
            "bundler_markers": 0,
            "source_map_markers": 0,
            "distinct_identifier_ratio": 0.5,
        },
        "looks_like_built_antibot_script": True,
        "reasons": [],
        "vendor_hint": None,
    }
    document["source_provenance"] = {
        "status": "not_supplied",
        "note": "no public source URL pin was supplied",
    }
    document["provenance"] = {
        "status": "not_checked",
        "note": "no capture tree was supplied",
        "asserted_label": label,
    }
    events = sum(complete_names.values())
    run_id = f"{label}-run"
    revision = "a" * 40
    document.update(
        headed=True,
        viewport={
            "inner_width": 1280,
            "inner_height": 720,
            "outer_width": 1280,
            "outer_height": 720,
            "screen_width": 1920,
            "screen_height": 1080,
            "device_pixel_ratio": 1,
        },
        trace_scope="broad",
        trace_category_contract="browser-core.trace-categories/2",
        chromium_revision=revision,
        browser_build={
            "provenance": "attested-browser-core",
            "executable_sha256_16": "b" * 16,
            "runtime_bundle_sha256_16": "c" * 16,
        },
        timeout_seconds=60.0,
        dwell_seconds=8.0,
        dom_profile="minimal",
        hook_mode="off",
        hook_target_names=[],
        inline_script=False,
        reloads=0,
        script_path=DEFAULT_SCRIPT_PATH,
        declared_script_url=None,
        prelude={"supplied": False, "bytes": 0, "sha256_16": None},
        driver={"supplied": False, "bytes": 0, "sha256_16": None},
        driver_result=None,
        resource_intent_capture="off",
        extra_browser_args=[],
        stage_routes=[],
        browser_shutdown={"mode": "graceful"},
        trace_flush={"status": "settled", "bytes": 100},
        trace_export_budget={
            "max_source_bytes": product_observation.MAX_OBSERVATION_TRACE_EXPORT_BYTES,
            "source_bytes": 100,
            "bytes_within_budget": True,
            "max_exportable_events": (
                product_observation.MAX_OBSERVATION_TRACE_EXPORT_EVENTS
            ),
            "exportable_events": events,
            "events_within_budget": True,
            "within_budget": True,
            "policy": "skip-automatic-normalization-above-budget",
        },
        run_id=run_id,
    )
    document["analysis"].update(
        trace_summary={"run_id": run_id, "events": events, "dropped_events": 0},
        total_events=events,
        attributable_events=events,
        execution_context_counts={
            "generated_binding": {"frame": 1, "worker": 0},
            "native": {"frame": 1, "worker": 0},
        },
    )
    startup = {
        "uncaught_errors": [],
        "unhandled_rejections": [],
        "vendor_globals": ["KPSDK"],
        "vendor_reports_ready": True,
        "ambient_input": {},
        "window_properties": 100,
        "window_properties_before_script": 99,
        "started": None,
        "renderer_blocked": None,
    }
    document["startup"] = startup
    document["input_profile"] = "none"
    document["input_probe"] = None
    document["ambient_input"] = grade_ambient_input(startup, "none")
    document["collector_startup"] = grade_collector_startup(
        startup,
        events,
        document["analysis"]["execution_context_counts"],
    )
    report = {
        "schema": "browser-core.trace-export/1",
        "run_id": run_id,
        "chromium_revision": revision,
        "source_trace": {
            "format": "perfetto-trace",
            "bytes": 100,
            "sha256": "d" * 64,
        },
        "normalized_trace": {
            "schema": "browser-core.trace-event/1",
            "bytes": 200,
            "sha256": "e" * 64,
            "events": events,
            "trace_categories": {"browser_core.debug": events},
            "category_provenance": "complete",
        },
    }
    document["export"] = {
        "events": events,
        "output": r"C:\private\trace.jsonl",
        "run_id": run_id,
        "report": report,
        "report_output": r"C:\private\trace.export.json",
    }
    document["page_loads"] = 1
    _attach_current_request_receipts(document)
    return document


def test_current_arm_and_control_require_one_exact_observation_method() -> None:
    arm = _current_method_observation("arm", "aaaa", {"api.A": 1})
    control = _current_method_observation("control", "bbbb", {})

    result = subtract_control(arm, control)

    assert result["arm_control_method_comparable"] is True
    assert result["arm_control_method_mismatches"] == []
    assert result["driver_execution_complete"] is True
    assert result["script_identity_coherent"] is True
    assert result["trace_evidence_coherent"] is True
    assert result["page_load_execution_coherent"] is True
    assert result["startup_derivation_coherent"] is True
    assert result["surface_claim_ready"] is True
    assert result["arm_trace_evidence"]["source_trace"] == {
        "bytes": 100,
        "sha256_16": "d" * 16,
    }
    assert "private" not in json.dumps(result["arm_trace_evidence"])


@pytest.mark.parametrize(
    ("section", "field"),
    [
        ("script_identity", "reasons"),
        ("source_provenance", "status"),
        ("provenance", "status"),
        ("browser_build", "provenance"),
        ("browser_shutdown", "mode"),
        ("trace_flush", "status"),
    ],
)
def test_malformed_nested_observation_values_fail_closed(section: str, field: str) -> None:
    arm = _current_method_observation("arm", "aaaa", {"api.A": 1})
    control = _current_method_observation("control", "bbbb", {})
    arm[section][field] = [[]] if field == "reasons" else []

    result = subtract_control(arm, control)

    assert result["surface_claim_ready"] is False


@pytest.mark.parametrize(
    "targets",
    [
        ["Permissions.query", "private-tenant-hook"],
        ["Permissions.query", {"private": "tenant-hook"}],
        17,
    ],
)
def test_subtraction_reduces_invalid_hook_targets_without_copying_values(targets) -> None:
    arm = _current_method_observation("arm", "aaaa", {"api.A": 1})
    control = _current_method_observation("control", "bbbb", {})
    arm["hook_target_names"] = targets

    result = subtract_control(arm, control)

    assert result["surface_claim_ready"] is False
    assert "private" not in json.dumps(result)
    assert "tenant-hook" not in json.dumps(result)


def test_pre_sbsd_signal_observations_remain_identity_coherent() -> None:
    arm = _current_method_observation("arm", "aaaa", {"api.A": 1})
    control = _current_method_observation("control", "bbbb", {})
    for document in (arm, control):
        assert "akamai_sbsd_markers" not in document["script_identity"]["signals"]

    result = subtract_control(arm, control)

    assert result["script_identity_coherent"] is True
    assert result["surface_claim_ready"] is True


def test_pre_distinct_marker_signal_vocabulary_is_identity_coherent() -> None:
    arm = _current_method_observation("arm", "aaaa", {"api.A": 1})
    control = _current_method_observation("control", "bbbb", {})
    for document in (arm, control):
        document["script_identity"]["signals"]["akamai_sbsd_markers"] = 0

    result = subtract_control(arm, control)

    assert result["script_identity_coherent"] is True
    assert result["surface_claim_ready"] is True


def test_current_distinct_marker_signal_vocabulary_is_identity_coherent() -> None:
    arm = _current_method_observation("arm", "aaaa", {"api.A": 1})
    control = _current_method_observation("control", "bbbb", {})
    for document in (arm, control):
        document["script_identity"]["signals"].update(
            akamai_sbsd_markers=0,
            datadome_markers=0,
            turnstile_markers=0,
        )

    result = subtract_control(arm, control)

    assert result["script_identity_coherent"] is True
    assert result["surface_claim_ready"] is True


@pytest.mark.parametrize(
    "mutation",
    [
        "reported_count",
        "missing_report",
        "missing_page_request",
        "missing_sample_request",
        "equal_reload_plan_drift",
        "equal_hook_plan_without_delivery",
        "control_missing_page",
    ],
)
def test_page_load_execution_mutation_closes_claim(mutation: str) -> None:
    arm = _current_method_observation("arm", "aaaa", {"api.A": 1})
    control = _current_method_observation("control", "bbbb", {})
    if mutation == "reported_count":
        arm["page_loads"] = 2
    elif mutation == "missing_report":
        del arm["page_loads"]
    elif mutation in {
        "missing_page_request",
        "missing_sample_request",
        "control_missing_page",
    }:
        target = control if mutation == "control_missing_page" else arm
        served = "sample" if mutation == "missing_sample_request" else "page"
        rows = [row for row in target["server_requests"] if row["served"] != served]
        _set_current_request_receipts(target, rows)
    elif mutation == "equal_reload_plan_drift":
        for document in (arm, control):
            document["reloads"] = 1
    else:
        for document in (arm, control):
            document["hook_mode"] = "inert"

    result = subtract_control(arm, control)

    assert result["page_load_execution_coherent"] is False
    assert result["surface_claim_ready"] is False


@pytest.mark.parametrize(
    ("served_sequence", "hook_mode", "expected", "coherent_expected"),
    [
        (("sample", "page"), "off", 1, False),
        (("page", "sample", "sample", "page"), "off", 2, False),
        (("hook", "page", "sample"), "inert", 1, False),
        (("page", "hook", "sample", "hook", "page", "sample"), "inert", 2, False),
        (("page", "sample", "page", "sample"), "off", 2, True),
        (("page", "hook", "sample", "page", "hook", "sample"), "inert", 2, True),
    ],
)
def test_page_load_execution_requires_per_load_request_order(
    served_sequence: tuple[str, ...],
    hook_mode: str,
    expected: int,
    coherent_expected: bool,
) -> None:
    paths = {
        "page": "/",
        "sample": product_observation.DEFAULT_SCRIPT_PATH,
        "hook": product_observation.HOOK_SCRIPT_PATH,
    }
    document = {
        "reloads": expected - 1,
        "page_loads": expected,
        "hook_mode": hook_mode,
        "inline_script": False,
        "script_path": product_observation.DEFAULT_SCRIPT_PATH,
        "server_requests": [
            {"method": "GET", "path": paths[served], "served": served}
            for served in served_sequence
        ],
    }

    coherent, receipt = product_observation._reconciled_page_load_execution(
        document, current_required=True
    )

    assert coherent is coherent_expected
    assert receipt is not None


def test_subtraction_withholds_claim_when_script_requests_are_duplicated_before_reload() -> None:
    arm = _current_method_observation("arm", "aaaa", {"api.A": 1})
    control = _current_method_observation("control", "bbbb", {})
    for document in (arm, control):
        document["reloads"] = 1
        document["page_loads"] = 2
        page, sample, acknowledgement = document["server_requests"]
        if document is arm:
            rows = [page, sample, dict(sample), dict(page), acknowledgement]
        else:
            rows = [page, sample, dict(page), dict(sample), acknowledgement]
        _set_current_request_receipts(document, rows)

    result = subtract_control(arm, control)

    assert result["arm_control_method_comparable"] is True
    assert result["rehost_receipts_coherent"] is True
    assert result["page_load_execution_coherent"] is False
    assert result["surface_claim_ready"] is False


def test_subtraction_rejects_reordered_numbered_request_rows() -> None:
    arm = _current_method_observation("arm", "aaaa", {"api.A": 1})
    control = _current_method_observation("control", "bbbb", {})
    for index, row in enumerate(arm["server_requests"]):
        row["order"] = index
    arm["server_requests"][0]["order"] = 1
    arm["server_requests"][1]["order"] = 0

    result = subtract_control(arm, control)

    assert result["rehost_receipts_coherent"] is False
    assert result["rehost_dependencies_complete"] is None
    assert result["surface_claim_ready"] is False


@pytest.mark.parametrize(
    ("served", "path", "stage_prefixes", "hook_mode", "coherent_expected"),
    [
        ("stage", "/other.js", (), "off", False),
        ("stage", DEFAULT_SCRIPT_PATH, ("/",), "off", False),
        ("empty", "/served/next.js", ("/served/",), "off", False),
        ("empty", DEFAULT_SCRIPT_PATH, (), "off", False),
        ("stage", product_observation.HOOK_SCRIPT_PATH, ("/",), "inert", False),
        ("empty", product_observation.HOOK_SCRIPT_PATH, (), "inert", False),
        ("stage", "/served/next.js", ("/served/",), "off", True),
        ("empty", "/missing.js", ("/served/",), "off", True),
        ("empty", product_observation.HOOK_SCRIPT_PATH, (), "off", True),
        ("stage", product_observation.HOOK_SCRIPT_PATH, ("/",), "off", True),
    ],
)
def test_page_load_rejects_saved_routes_the_rehost_could_not_serve(
    served: str,
    path: str,
    stage_prefixes: tuple[str, ...],
    hook_mode: str,
    coherent_expected: bool,
) -> None:
    rows = [{"method": "GET", "path": "/", "served": "page"}]
    if hook_mode != "off":
        rows.append(
            {
                "method": "GET",
                "path": product_observation.HOOK_SCRIPT_PATH,
                "served": "hook",
            }
        )
    rows.append({"method": "GET", "path": DEFAULT_SCRIPT_PATH, "served": "sample"})
    rows.append({"method": "GET", "path": path, "served": served})
    document = {
        "reloads": 0,
        "page_loads": 1,
        "hook_mode": hook_mode,
        "inline_script": False,
        "script_path": DEFAULT_SCRIPT_PATH,
        "stage_routes": [
            {"path_prefix": prefix, "bytes": 10, "sha256_16": "a" * 16}
            for prefix in stage_prefixes
        ],
        "server_requests": rows,
    }

    coherent, _receipt = product_observation._reconciled_page_load_execution(
        document, current_required=True
    )

    assert coherent is coherent_expected


def test_subtraction_rejects_unconfigured_stage_as_complete_rehost_evidence() -> None:
    arm = _current_method_observation("arm", "aaaa", {"api.A": 1})
    control = _current_method_observation("control", "bbbb", {})
    rows = arm["server_requests"] + [
        {"method": "GET", "path": "/unconfigured-stage.js", "served": "stage"}
    ]
    _set_current_request_receipts(arm, rows)

    result = subtract_control(arm, control)

    assert result["rehost_receipts_coherent"] is False
    assert result["rehost_dependencies_complete"] is None
    assert result["page_load_execution_coherent"] is False
    assert result["surface_claim_ready"] is False


@pytest.mark.parametrize(
    "route",
    [
        {"path_prefix": "/stage/", "bytes": 5, "sha256_16": "bad"},
        {"path_prefix": "/stage/", "bytes": True, "sha256_16": "a" * 16},
        {"path_prefix": "/stage/", "sha256_16": "a" * 16},
    ],
)
def test_current_stage_metadata_must_bind_bounded_bytes_and_digest(route: dict) -> None:
    arm = _current_method_observation("arm", "aaaa", {"api.A": 1})
    control = _current_method_observation("control", "bbbb", {})
    for document in (arm, control):
        document["stage_routes"] = [route]

    result = subtract_control(arm, control)

    assert result["page_load_execution_coherent"] is False
    assert result["rehost_dependencies_complete"] is None
    assert result["surface_claim_ready"] is False


@pytest.mark.parametrize(
    ("method", "path", "coherent_expected"),
    [
        ("GET", "/background/check", False),
        ("GET", "/<proxy-connect>", False),
        ("CONNECT", "/<proxy-http>", False),
        ("GET", "/<proxy-http>", True),
        ("OTHER", "/<proxy-http>", True),
        ("CONNECT", "/<proxy-connect>", True),
    ],
)
def test_current_rehost_proxy_rows_require_the_handler_sentinel(
    method: str, path: str, coherent_expected: bool
) -> None:
    document = {
        "reloads": 0,
        "page_loads": 1,
        "hook_mode": "off",
        "inline_script": False,
        "script_path": DEFAULT_SCRIPT_PATH,
        "stage_routes": [],
        "server_requests": [
            {"method": "GET", "path": "/", "served": "page"},
            {"method": "GET", "path": DEFAULT_SCRIPT_PATH, "served": "sample"},
            {"method": method, "path": path, "served": "proxy-denied"},
        ],
    }

    coherent, _receipt = product_observation._reconciled_page_load_execution(
        document, current_required=True
    )

    assert coherent is coherent_expected


@pytest.mark.parametrize(
    ("served", "method", "path", "body_bytes", "coherent_expected"),
    [
        ("page", "GET", "/", 1, False),
        ("sample", "GET", DEFAULT_SCRIPT_PATH, 1, False),
        ("empty", "GET", "/missing.js", 1, False),
        ("post-ack", "POST", "/submit", MAX_REHOST_POST_BODY_BYTES + 1, False),
        ("proxy-denied", "CONNECT", "/<proxy-connect>", 1, False),
        ("post-ack", "POST", "/submit", MAX_REHOST_POST_BODY_BYTES, True),
        ("page", "GET", "/", 0, True),
    ],
)
def test_current_rehost_request_body_counts_match_handler_bounds(
    served: str,
    method: str,
    path: str,
    body_bytes: int,
    coherent_expected: bool,
) -> None:
    rows = [
        {"method": "GET", "path": "/", "served": "page"},
        {"method": "GET", "path": DEFAULT_SCRIPT_PATH, "served": "sample"},
    ]
    candidate = {
        "method": method,
        "path": path,
        "served": served,
        "request_body_bytes": body_bytes,
    }
    if served in {"page", "sample"}:
        rows[0 if served == "page" else 1] = candidate
    else:
        rows.append(candidate)
    document = {
        "reloads": 0,
        "page_loads": 1,
        "hook_mode": "off",
        "inline_script": False,
        "script_path": DEFAULT_SCRIPT_PATH,
        "stage_routes": [],
        "server_requests": rows,
    }

    coherent, _receipt = product_observation._reconciled_page_load_execution(
        document, current_required=True
    )

    assert coherent is coherent_expected


def test_subtraction_rejects_impossible_saved_post_body_size() -> None:
    arm = _current_method_observation("arm", "aaaa", {"api.A": 1})
    control = _current_method_observation("control", "bbbb", {})
    rows = arm["server_requests"]
    next(row for row in rows if row["served"] == "post-ack")[
        "request_body_bytes"
    ] = MAX_REHOST_POST_BODY_BYTES + 1
    _set_current_request_receipts(arm, rows)

    result = subtract_control(arm, control)

    assert result["rehost_receipts_coherent"] is False
    assert result["page_load_execution_coherent"] is False
    assert result["surface_claim_ready"] is False


@pytest.mark.parametrize(
    ("path", "valid"),
    [
        ("/plain", True),
        ("/caf\u00e9", True),
        ("/has space", False),
        ("/has\u00a0space", False),
        ("/\U0001f984", False),
    ],
)
def test_logged_rehost_path_respects_http_request_line_encoding(
    path: str, valid: bool
) -> None:
    # BaseHTTPRequestHandler decodes raw request lines as ISO-8859-1 and splits
    # tokens on whitespace before any local route can log the path.
    assert product_observation._valid_rehost_logged_path(path) is valid


def test_subtraction_rejects_saved_post_path_outside_request_line_encoding() -> None:
    arm = _current_method_observation("arm", "aaaa", {"api.A": 1})
    control = _current_method_observation("control", "bbbb", {})
    rows = arm["server_requests"]
    next(row for row in rows if row["served"] == "post-ack")["path"] = "/\U0001f984"
    _set_current_request_receipts(arm, rows)

    result = subtract_control(arm, control)

    assert result["rehost_receipts_coherent"] is False
    assert result["surface_claim_ready"] is False


@pytest.mark.parametrize(
    ("metadata", "coherent_expected"),
    [
        ({"request_body_sha256_16": "bad"}, False),
        ({"request_body_sha256_16": "A" * 16}, False),
        ({"query_names": ["private\nname"], "query_names_truncated": False}, False),
        ({"query_names": ["b", "a"], "query_names_truncated": False}, False),
        ({"query_names": ["token"]}, False),
        ({"query_names_truncated": False}, False),
        ({"path_sha256_16": "a" * 16}, False),
        (
            {
                "request_body_sha256_16": "a" * 16,
                "query_names": ["lang", "token"],
                "query_names_truncated": False,
                "path_sha256_16": None,
            },
            True,
        ),
    ],
)
def test_saved_rehost_metadata_matches_recorder_shape(
    metadata: dict, coherent_expected: bool
) -> None:
    arm = _current_method_observation("arm", "aaaa", {"api.A": 1})
    control = _current_method_observation("control", "bbbb", {})
    rows = arm["server_requests"]
    next(row for row in rows if row["served"] == "post-ack").update(metadata)
    _set_current_request_receipts(arm, rows)

    result = subtract_control(arm, control)

    assert result["rehost_receipts_coherent"] is coherent_expected
    assert result["surface_claim_ready"] is coherent_expected


@pytest.mark.parametrize("served", [[], {"private": "tenant-token"}])
def test_malformed_request_class_closes_page_load_claim(served: object) -> None:
    arm = _current_method_observation("arm", "aaaa", {"api.A": 1})
    control = _current_method_observation("control", "bbbb", {})
    arm["server_requests"][0]["served"] = served

    result = subtract_control(arm, control)

    assert result["page_load_execution_coherent"] is False
    assert result["surface_claim_ready"] is False
    assert "tenant-token" not in json.dumps(result)


@pytest.mark.parametrize(
    ("served", "wrong_path"),
    [
        ("page", "/private-false-page"),
        ("sample", "/private-false-sample.js"),
        ("hook", "/private-false-hook.js"),
    ],
)
def test_page_load_requires_requests_at_the_served_routes(
    served: str, wrong_path: str
) -> None:
    arm = _current_method_observation("arm", "aaaa", {"api.A": 1})
    control = _current_method_observation("control", "bbbb", {})
    if served == "hook":
        for document in (arm, control):
            document["hook_mode"] = "inert"
            rows = document["server_requests"] + [
                {
                    "method": "GET",
                    "path": product_observation.HOOK_SCRIPT_PATH,
                    "served": "hook",
                    "request_body_bytes": 0,
                }
            ]
            _set_current_request_receipts(document, rows)
    rows = arm["server_requests"]
    next(row for row in rows if row["served"] == served)["path"] = wrong_path
    _set_current_request_receipts(arm, rows)

    result = subtract_control(arm, control)

    assert result["page_load_execution_coherent"] is False
    assert result["surface_claim_ready"] is False
    assert "private-false" not in json.dumps(result)


def test_page_load_accepts_configured_sample_and_hook_routes() -> None:
    arm = _current_method_observation("arm", "aaaa", {"api.A": 1})
    control = _current_method_observation("control", "bbbb", {})
    for document in (arm, control):
        document["script_path"] = "/configured/sample.js"
        document["hook_mode"] = "inert"
        rows = document["server_requests"]
        next(row for row in rows if row["served"] == "sample")["path"] = (
            "/configured/sample.js"
        )
        rows.append(
            {
                "method": "GET",
                "path": product_observation.HOOK_SCRIPT_PATH,
                "served": "hook",
                "request_body_bytes": 0,
            }
        )
        _set_current_request_receipts(document, rows)

    result = subtract_control(arm, control)

    assert result["page_load_execution_coherent"] is True
    assert result["surface_claim_ready"] is True


def test_inline_page_load_needs_no_separate_sample_request() -> None:
    arm = _current_method_observation("arm", "aaaa", {"api.A": 1})
    control = _current_method_observation("control", "bbbb", {})
    for document in (arm, control):
        document["inline_script"] = True
        rows = [row for row in document["server_requests"] if row["served"] != "sample"]
        _set_current_request_receipts(document, rows)

    result = subtract_control(arm, control)

    assert result["arm_control_method_comparable"] is True
    assert result["page_load_execution_coherent"] is True
    assert result["surface_claim_ready"] is True


@pytest.mark.parametrize(
    "mutation",
    [
        "top_digest",
        "top_size",
        "signal_digest",
        "extra_signal",
        "verdict_reason",
        "allowed_reason_verdict_mismatch",
        "vendor_hint",
        "allowed_vendor_hint_mismatch",
        "missing_identity",
        "source_malformed",
        "source_digest_mismatch",
        "capture_label",
    ],
)
def test_script_identity_or_provenance_mutation_closes_claim(mutation: str) -> None:
    arm = _current_method_observation("arm", "aaaa", {"api.A": 1})
    control = _current_method_observation("control", "bbbb", {})
    if mutation == "top_digest":
        arm["script_sha256_16"] = "f" * 16
    elif mutation == "top_size":
        arm["script_bytes"] += 1
    elif mutation == "signal_digest":
        arm["script_identity"]["signals"]["sha256_16"] = "f" * 16
    elif mutation == "extra_signal":
        arm["script_identity"]["signals"]["private"] = "must not travel"
    elif mutation == "verdict_reason":
        arm["script_identity"]["reasons"] = [
            "smaller than any observed built anti-bot script"
        ]
    elif mutation == "allowed_reason_verdict_mismatch":
        # The reason and boolean agree with each other but contradict the
        # retained arrow-function count of zero.
        arm["script_identity"]["reasons"] = [
            "arrow functions present at application-bundle density"
        ]
        arm["script_identity"]["looks_like_built_antibot_script"] = False
    elif mutation == "vendor_hint":
        arm["script_identity"]["vendor_hint"] = "private-vendor"
    elif mutation == "allowed_vendor_hint_mismatch":
        # `kasada` is in the closed vocabulary, but these signals contain zero
        # KPSDK literals. Vocabulary membership alone must not make it coherent.
        arm["script_identity"]["vendor_hint"] = "kasada"
    elif mutation == "missing_identity":
        del arm["script_identity"]
    elif mutation == "source_malformed":
        arm["source_provenance"] = {
            "status": "verified_digest",
            "private": "must not travel",
        }
    elif mutation == "source_digest_mismatch":
        arm["source_provenance"] = {
            "status": "verified_digest",
            "source_url": "https://example.invalid/collector.js",
            "retrieved_at": "2026-08-12T00:00:00Z",
            "sha256": "f" * 64,
            "note": "the supplied full digest matches the exact bytes observed",
        }
    else:
        arm["provenance"]["asserted_label"] = "different"

    result = subtract_control(arm, control)

    assert result["script_identity_coherent"] is False
    assert result["surface_claim_ready"] is False
    assert "must not travel" not in json.dumps(result)


def test_equal_malformed_script_identity_is_not_preserved_as_provenance() -> None:
    arm = _current_method_observation("arm", "aaaa", {"api.A": 1})
    control = _current_method_observation("control", "bbbb", {})
    for document in (arm, control):
        document["script_identity"] = {
            "private": "must not travel",
            "signals": {"sha256_16": "private-digest"},
        }

    result = subtract_control(arm, control)

    assert result["script_identity_coherent"] is False
    assert result["script_identity"] is None
    assert result["control_script_identity"] is None
    assert "private" not in json.dumps(result)


@pytest.mark.parametrize(
    "mutation",
    [
        "missing_startup",
        "startup_extra",
        "startup_ready",
        "collector_extra",
        "collector_verdict",
        "trace_count_derivation",
        "ambient_derivation",
        "control_missing_startup",
        "control_collector_verdict",
    ],
)
def test_startup_witness_or_derivation_mutation_closes_claim(mutation: str) -> None:
    arm = _current_method_observation("arm", "aaaa", {"api.A": 1})
    control = _current_method_observation("control", "bbbb", {})
    if mutation == "missing_startup":
        del arm["startup"]
    elif mutation == "startup_extra":
        arm["startup"]["private"] = "must not travel"
    elif mutation == "startup_ready":
        arm["startup"]["vendor_reports_ready"] = False
    elif mutation == "collector_extra":
        arm["collector_startup"]["private"] = "must not travel"
    elif mutation == "collector_verdict":
        arm["collector_startup"] = {
            "started": False,
            "reasons": ["forged reason"],
        }
    elif mutation == "trace_count_derivation":
        arm["startup"]["vendor_globals"] = []
        arm["analysis"]["attributable_events"] = 0
    elif mutation == "ambient_derivation":
        arm["startup"]["ambient_input"] = {"click": 1}
    elif mutation == "control_missing_startup":
        del control["startup"]
    else:
        control["collector_startup"] = {
            "started": False,
            "reasons": ["forged reason"],
        }

    result = subtract_control(arm, control)

    assert result["startup_derivation_coherent"] is False
    assert result["surface_claim_ready"] is False
    assert "must not travel" not in json.dumps(result)


@pytest.mark.parametrize(
    ("field", "value", "mismatch"),
    [
        ("headed", False, "headed"),
        (
            "viewport",
            {
                "inner_width": 1280,
                "inner_height": 721,
                "outer_width": 1280,
                "outer_height": 720,
                "screen_width": 1920,
                "screen_height": 1080,
                "device_pixel_ratio": 1,
            },
            "viewport",
        ),
        ("trace_scope", "causal", "trace_scope"),
        (
            "trace_category_contract",
            "browser-core.trace-categories/1",
            "trace_category_contract",
        ),
        ("chromium_revision", "d" * 40, "chromium_revision"),
        (
            "browser_build",
            {
                "provenance": "attested-browser-core",
                "executable_sha256_16": "e" * 16,
                "runtime_bundle_sha256_16": "c" * 16,
            },
            "browser_build",
        ),
        ("timeout_seconds", 61.0, "timeout_seconds"),
        ("dwell_seconds", 9.0, "dwell_seconds"),
        ("dom_profile", "rich", "dom_profile"),
        ("hook_mode", "inert", "hook_mode"),
        ("inline_script", True, "inline_script"),
        ("reloads", 1, "reloads"),
        ("script_path", "/different.js", "script_path"),
        (
            "declared_script_url",
            "https://example.invalid/different.js",
            "declared_script_url",
        ),
        (
            "prelude",
            {"supplied": True, "bytes": 1, "sha256_16": "f" * 16},
            "prelude",
        ),
        (
            "driver",
            {"supplied": True, "bytes": 1, "sha256_16": "1" * 16},
            "driver",
        ),
        (
            "resource_intent_capture",
            "cdp_dom_snapshot/2",
            "resource_intent_capture",
        ),
        ("extra_browser_args", ["--lang=fr"], "extra_browser_args"),
        (
            "stage_routes",
            [{"path_prefix": "/stage", "sha256_16": "2" * 16}],
            "stage_routes",
        ),
    ],
)
def test_current_arm_control_method_mismatch_closes_claim(
    field: str, value, mismatch: str
) -> None:
    arm = _current_method_observation("arm", "aaaa", {"api.A": 1})
    control = _current_method_observation("control", "bbbb", {})
    control[field] = value

    result = subtract_control(arm, control)

    assert result["arm_control_method_comparable"] is False
    assert mismatch in result["arm_control_method_mismatches"]
    assert result["surface_claim_ready"] is False


def test_current_method_omission_or_malformed_equal_value_fails_closed() -> None:
    arm = _current_method_observation("arm", "aaaa", {"api.A": 1})
    control = _current_method_observation("control", "bbbb", {})
    del arm["driver"]
    control["browser_build"] = {"private": "must not travel"}
    arm["browser_build"] = {"private": "must not travel"}

    result = subtract_control(arm, control)

    assert result["arm_control_method_comparable"] is False
    assert result["arm_control_method_mismatches"] == ["browser_build", "driver"]
    assert result["surface_claim_ready"] is False
    assert "private" not in json.dumps(result["arm_control_method_mismatches"])


@pytest.mark.parametrize(
    "mutation",
    [
        "forced_shutdown",
        "unsettled_trace",
        "flush_size",
        "budget_source_size",
        "budget_event_count",
        "budget_false_grade",
        "export_event_count",
        "export_run_id",
        "report_source_size",
        "report_revision",
        "analysis_run_id",
        "dropped_events",
        "analysis_total",
        "analysis_surface_count",
        "analysis_attributable_overrun",
        "analysis_script_attribution_overrun",
        "analysis_component_count",
        "analysis_distinct_names",
        "missing_export",
    ],
)
def test_trace_lifecycle_export_or_analysis_mutation_closes_claim(
    mutation: str,
) -> None:
    arm = _current_method_observation("arm", "aaaa", {"api.A": 1})
    control = _current_method_observation("control", "bbbb", {})
    if mutation == "forced_shutdown":
        arm["browser_shutdown"]["mode"] = "forced"
    elif mutation == "unsettled_trace":
        arm["trace_flush"]["status"] = "present-unsettled"
    elif mutation == "flush_size":
        arm["trace_flush"]["bytes"] = 101
    elif mutation == "budget_source_size":
        arm["trace_export_budget"]["source_bytes"] = 101
    elif mutation == "budget_event_count":
        arm["trace_export_budget"]["exportable_events"] += 1
    elif mutation == "budget_false_grade":
        arm["trace_export_budget"]["within_budget"] = False
    elif mutation == "export_event_count":
        arm["export"]["events"] += 1
    elif mutation == "export_run_id":
        arm["export"]["run_id"] = "different-run"
    elif mutation == "report_source_size":
        arm["export"]["report"]["source_trace"]["bytes"] = 101
    elif mutation == "report_revision":
        arm["export"]["report"]["chromium_revision"] = "f" * 40
    elif mutation == "analysis_run_id":
        arm["analysis"]["trace_summary"]["run_id"] = "different-run"
    elif mutation == "dropped_events":
        arm["analysis"]["trace_summary"]["dropped_events"] = 1
    elif mutation == "analysis_total":
        arm["analysis"]["total_events"] += 1
    elif mutation == "analysis_surface_count":
        arm["analysis"]["events_by_name"]["api.Forged"] = 1
    elif mutation == "analysis_attributable_overrun":
        arm["analysis"]["attributable_events"] += 1
    elif mutation == "analysis_script_attribution_overrun":
        arm["analysis"]["attributable_events"] = 1
        arm["analysis"]["script_attributed_events_by_name"] = {
            "api.ControlBaseline": 1, "api.A": 1,
        }
        arm["analysis"]["script_attributed_events"] = 2
    elif mutation == "analysis_component_count":
        arm["analysis"]["events_by_component"] = {"native": 3}
    elif mutation == "analysis_distinct_names":
        arm["analysis"]["distinct_api_names"] = 3
    else:
        del arm["export"]

    result = subtract_control(arm, control)

    assert result["trace_evidence_coherent"] is False
    assert result["surface_claim_ready"] is False


@pytest.mark.parametrize(
    ("section", "field", "value"),
    [
        ("export", "events", True),
        ("analysis", "total_events", True),
        ("trace_summary", "events", True),
        ("trace_summary", "dropped_events", False),
        ("trace_export_budget", "source_bytes", True),
    ],
)
def test_boolean_saved_trace_counts_cannot_support_claim(section, field, value) -> None:
    arm = _current_method_observation("arm", "aaaa", {"api.A": 1})
    control = _current_method_observation("control", "bbbb", {})
    if section == "trace_export_budget":
        control["trace_flush"]["bytes"] = 1
        control["export"]["report"]["source_trace"]["bytes"] = 1
    target = control["analysis"]["trace_summary"] if section == "trace_summary" else control[section]
    target[field] = value

    result = subtract_control(arm, control)

    assert result["trace_evidence_coherent"] is False
    assert result["surface_claim_ready"] is False


def test_trace_analysis_optional_population_counts_remain_coherent() -> None:
    arm = _current_method_observation("arm", "aaaa", {"api.A": 1})
    control = _current_method_observation("control", "bbbb", {})
    for document, total, distinct in ((arm, 2, 2), (control, 1, 1)):
        document["analysis"]["events_by_component"] = {"native": total}
        document["analysis"]["distinct_api_names"] = distinct

    result = subtract_control(arm, control)

    assert result["trace_evidence_coherent"] is True
    assert result["surface_claim_ready"] is True


@pytest.mark.parametrize(
    "scope",
    [
        {"coverage": "complete", "requests": 1, "loopback": 0, "external": 1, "non_network": 0, "unclassified": 0},
        {"coverage": "unknown", "requests": 1, "loopback": 0, "external": 0, "non_network": 0, "unclassified": 1},
        {"coverage": "complete", "requests": 4, "loopback": 4, "external": 0, "non_network": 0, "unclassified": 0},
        {"coverage": "complete", "requests": 1, "loopback": 0, "external": 0, "non_network": 0, "unclassified": 0},
        {"coverage": "complete", "requests": 1, "loopback": 1, "external": False, "non_network": 0, "unclassified": 0},
    ],
    ids=["external", "unknown", "overrun", "inconsistent-total", "noninteger-count"],
)
def test_saved_fetch_target_scope_contradiction_closes_claim(scope: dict) -> None:
    arm = _current_method_observation(
        "arm", "aaaa", {"api.A": 1, "network.fetch.request.start": 1}
    )
    control = _current_method_observation("control", "bbbb", {})
    arm["analysis"]["fetch_target_scope"] = scope

    result = subtract_control(arm, control)

    assert result["trace_evidence_coherent"] is False
    assert result["surface_claim_ready"] is False


def test_saved_complete_loopback_fetch_scope_remains_claim_ready() -> None:
    arm = _current_method_observation(
        "arm", "aaaa", {"api.A": 1, "network.fetch.request.start": 1}
    )
    control = _current_method_observation(
        "control", "bbbb", {"network.fetch.request.start": 1}
    )
    for document in (arm, control):
        document["analysis"]["fetch_target_scope"] = {
            "coverage": "complete",
            "requests": 1,
            "loopback": 1,
            "external": 0,
            "non_network": 0,
            "unclassified": 0,
        }

    result = subtract_control(arm, control)

    assert result["trace_evidence_coherent"] is True
    assert result["surface_claim_ready"] is True


def test_saved_request_maps_must_match_network_event_population() -> None:
    arm = _current_method_observation(
        "arm", "aaaa", {"api.A": 1, "network.fetch.request.start": 1}
    )
    control = _current_method_observation("control", "bbbb", {})
    arm["analysis"].update(
        request_methods={"GET": 2},
        request_classes={"same-origin:/x": 1},
        distinct_request_classes=1,
    )

    result = subtract_control(arm, control)

    assert result["trace_evidence_coherent"] is False
    assert result["surface_claim_ready"] is False


def test_saved_matching_request_maps_remain_claim_ready() -> None:
    arm = _current_method_observation(
        "arm", "aaaa", {"api.A": 1, "network.fetch.request.start": 1}
    )
    control = _current_method_observation("control", "bbbb", {})
    arm["analysis"].update(
        request_methods={"GET": 1},
        request_classes={"same-origin:/x": 1},
        distinct_request_classes=1,
    )
    control["analysis"].update(
        request_methods={},
        request_classes={},
        distinct_request_classes=0,
    )

    result = subtract_control(arm, control)

    assert result["trace_evidence_coherent"] is True
    assert result["surface_claim_ready"] is True


def test_saved_script_execution_count_must_match_the_validated_surface() -> None:
    arm = _current_method_observation("arm", "aaaa", {"api.A": 1})
    control = _current_method_observation("control", "bbbb", {})
    arm["analysis"]["script_execution"] = {
        "total": 1,
        "complete": 1,
        "open": 0,
        "max_complete_duration_ns": 5,
    }

    result = subtract_control(arm, control)

    assert result["trace_evidence_coherent"] is False
    assert result["surface_claim_ready"] is False


def test_saved_matching_script_execution_count_remains_claim_ready() -> None:
    arm = _current_method_observation(
        "arm", "aaaa", {"api.A": 1, "execution.script.execution": 1}
    )
    control = _current_method_observation("control", "bbbb", {})
    arm["analysis"]["script_execution"] = {
        "total": 1,
        "complete": 1,
        "open": 0,
        "max_complete_duration_ns": 5,
    }
    control["analysis"]["script_execution"] = {
        "total": 0,
        "complete": 0,
        "open": 0,
        "max_complete_duration_ns": None,
    }

    result = subtract_control(arm, control)

    assert result["trace_evidence_coherent"] is True
    assert result["surface_claim_ready"] is True


def test_saved_generated_attribution_must_match_component_population() -> None:
    arm = _current_method_observation("arm", "aaaa", {"api.A": 1})
    control = _current_method_observation("control", "bbbb", {})
    arm["analysis"].update(
        events_by_component={"native": 2},
        script_attributed_events=1,
        script_attributed_events_by_name={"api.A": 1},
    )

    result = subtract_control(arm, control)

    assert result["trace_evidence_coherent"] is False
    assert result["surface_claim_ready"] is False


def test_saved_matching_generated_attribution_remains_claim_ready() -> None:
    arm = _current_method_observation("arm", "aaaa", {"api.A": 1})
    control = _current_method_observation("control", "bbbb", {})
    arm["analysis"].update(
        events_by_component={"native": 1, "blink.bindings.generated": 1},
        script_attributed_events=1,
        script_attributed_events_by_name={"api.A": 1},
    )

    result = subtract_control(arm, control)

    assert result["trace_evidence_coherent"] is True
    assert result["surface_claim_ready"] is True


def test_equal_malformed_trace_reports_fail_closed_without_retaining_values() -> None:
    arm = _current_method_observation("arm", "aaaa", {"api.A": 1})
    control = _current_method_observation("control", "bbbb", {})
    for document in (arm, control):
        document["export"]["report"] = {
            "private": "must not travel",
            "source_trace": {"sha256": "secret-source-binding"},
        }

    result = subtract_control(arm, control)

    assert result["trace_evidence_coherent"] is False
    assert result["arm_trace_evidence"] is None
    assert result["control_trace_evidence"] is None
    assert "private" not in json.dumps(result)


@pytest.mark.parametrize("budget", [[1], "private-budget", 7])
def test_nonobject_trace_export_budget_fails_closed_without_raw_error(budget) -> None:
    arm = _current_method_observation("arm", "aaaa", {"api.A": 1})
    control = _current_method_observation("control", "bbbb", {})
    arm["trace_export_budget"] = budget

    result = subtract_control(arm, control)

    assert result["trace_evidence_coherent"] is False
    assert result["surface_claim_ready"] is False
    assert "private-budget" not in json.dumps(result)


def test_supplied_driver_must_complete_on_both_arms_but_may_return_different_shapes() -> (
    None
):
    arm = _current_method_observation("arm", "aaaa", {"api.A": 1})
    control = _current_method_observation("control", "bbbb", {})
    for document in (arm, control):
        document["driver"] = {
            "supplied": True,
            "bytes": 12,
            "sha256_16": "3" * 16,
        }
    arm["driver_result"] = {
        "status": "ok",
        "type": "string",
        "serialized_bytes": 8,
        "length": 6,
    }
    control["driver_result"] = {
        "status": "ok",
        "type": "null",
        "serialized_bytes": 4,
    }

    result = subtract_control(arm, control)

    assert result["arm_control_method_comparable"] is True
    assert result["driver_execution_complete"] is True
    assert result["arm_driver_result"] == arm["driver_result"]
    assert result["control_driver_result"] == control["driver_result"]
    assert result["surface_claim_ready"] is True


@pytest.mark.parametrize(
    "mutation",
    [
        "missing",
        "failed",
        "extra_field",
        "invalid_type",
        "missing_length",
        "stray_without_driver",
        "control_failed",
    ],
)
def test_driver_execution_mutation_closes_claim(mutation: str) -> None:
    arm = _current_method_observation("arm", "aaaa", {"api.A": 1})
    control = _current_method_observation("control", "bbbb", {})
    successful = {
        "status": "ok",
        "type": "string",
        "serialized_bytes": 8,
        "length": 6,
    }
    for document in (arm, control):
        document["driver"] = {
            "supplied": True,
            "bytes": 12,
            "sha256_16": "3" * 16,
        }
        document["driver_result"] = dict(successful)
    if mutation == "missing":
        del arm["driver_result"]
    elif mutation == "failed":
        arm["driver_result"] = {
            "status": "failed",
            "error_type": "TypeError",
            "diagnostic": "TypeError; diagnostic_sha256_16=" + "4" * 16,
        }
    elif mutation == "extra_field":
        arm["driver_result"]["private"] = "must not travel"
    elif mutation == "invalid_type":
        arm["driver_result"]["type"] = "private-type"
    elif mutation == "missing_length":
        del arm["driver_result"]["length"]
    elif mutation == "stray_without_driver":
        for document in (arm, control):
            document["driver"] = {
                "supplied": False,
                "bytes": 0,
                "sha256_16": None,
            }
            document["driver_result"] = None
        arm["driver_result"] = dict(successful)
    else:
        control["driver_result"] = {
            "status": "failed",
            "error_type": "Error",
            "diagnostic": "Error; diagnostic_sha256_16=" + "5" * 16,
        }

    result = subtract_control(arm, control)

    assert result["driver_execution_complete"] is False
    assert result["surface_claim_ready"] is False
    assert "must not travel" not in json.dumps(result)


def test_equal_malformed_driver_results_do_not_become_a_comparable_story() -> None:
    arm = _current_method_observation("arm", "aaaa", {"api.A": 1})
    control = _current_method_observation("control", "bbbb", {})
    for document in (arm, control):
        document["driver"] = {
            "supplied": True,
            "bytes": 12,
            "sha256_16": "3" * 16,
        }
        document["driver_result"] = {
            "status": "ok",
            "private": "must not travel",
        }

    result = subtract_control(arm, control)

    assert result["driver_execution_complete"] is False
    assert result["arm_driver_result"] is None
    assert result["control_driver_result"] is None
    assert "private" not in json.dumps(result)


def test_subtract_control_attributes_only_arm_names() -> None:
    arm = _observation(
        "bm",
        "aaaa",
        {"api.Navigator.webdriver.get": 2, "api.Window.navigator.get": 74},
        {"api.Navigator.webdriver.get": ["frame"]},
    )
    control = _observation("control", "bbbb", {"api.Window.navigator.get": 12})
    result = subtract_control(arm, control)
    assert result["schema"] == SUBTRACTION_SCHEMA
    assert result["attributed_api_names"] == 1
    assert "api.Navigator.webdriver.get" in result["only_in_arm"]
    assert result["clean_subtraction"] is True
    assert result["context_coverage"]["api.Navigator.webdriver.get"] == ["frame"]


def test_subtraction_normalizes_dynamic_guard_ports_and_gates_edited_receipts() -> None:
    arm = _observation("arm", "aaaa", {"api.A": 1})
    control = _observation("control", "bbbb", {})
    arm["offline_guard"] = _offline_guard(43123)
    control["offline_guard"] = _offline_guard(43124)

    valid = subtract_control(arm, control)

    assert valid["offline_guard_comparable"] is True
    assert valid["arm_offline_guard"] == valid["control_offline_guard"]
    assert valid["surface_claim_ready"] is True
    arm["offline_guard"]["bypass_endpoint"] = "127.0.0.1:43125"

    edited = subtract_control(arm, control)

    assert edited["offline_guard_comparable"] is False
    assert edited["arm_offline_guard"] == {"status": "unverifiable"}
    assert edited["surface_claim_ready"] is False


def test_script_attribution_recovers_a_binding_shared_with_browser_activity() -> None:
    name = "api.Navigator.userAgent.get"
    arm = _observation("collector", "aaaa", {name: 5})
    control = _observation("control", "bbbb", {name: 4})
    arm["analysis"].update(
        {
            "script_attributed_events": 1,
            "script_attributed_events_by_name": {name: 1},
        }
    )
    control["analysis"].update(
        {
            "script_attributed_events": 0,
            "script_attributed_events_by_name": {},
        }
    )
    arm["analysis"]["script_execution"] = {
        "total": 2,
        "complete": 1,
        "open": 1,
        "max_complete_duration_ns": 123,
    }
    control["analysis"]["script_execution"] = {
        "total": 1,
        "complete": 1,
        "open": 0,
        "max_complete_duration_ns": 100,
    }

    result = subtract_control(arm, control)
    assert result["script_attribution_comparable"] is True
    assert result["script_attributed_only_in_arm"] == {name: 1}
    assert result["only_in_arm"] == {name: 1}
    assert result["clean_subtraction"] is True
    assert result["arm_script_execution"]["open"] == 1
    assert result["control_script_execution"]["open"] == 0


def test_subtraction_retains_the_closed_managed_target_diagnostic() -> None:
    arm = _observation("collector", "aaaa", {"api.A": 1})
    control = _observation("control", "bbbb", {})
    arm["collector_startup"] = grade_collector_startup(
        {
            "probe_error": "startup probe failed: execution-failure",
            "renderer_blocked": True,
            "browser_target_status": "present",
            "browser_target_title_matches": True,
        },
        attributable_events=1,
    )

    result = subtract_control(arm, control)

    startup = result["collector_startup"]
    assert startup["started"] is None
    assert startup["renderer_blocked"] is True
    assert startup["browser_target_status"] == "present"
    assert startup["browser_target_title_matches"] is True


def test_script_attribution_requires_two_current_comparable_surfaces() -> None:
    arm = _observation("collector", "aaaa", {"api.A": 1})
    control = _observation("control", "bbbb", {})
    arm["analysis"].update(
        {
            "script_attributed_events": 1,
            "script_attributed_events_by_name": {"api.A": 1},
        }
    )

    result = subtract_control(arm, control)
    assert result["script_attribution_comparable"] is False
    assert result["script_attributed_only_in_arm"] == {}


@pytest.mark.parametrize(
    ("surface", "total"),
    [
        ({"api.A": 2}, 2),
        ({"api.B": 1}, 1),
        ({"api.A": "1"}, 1),
        ({"api.A": 1}, 2),
        ({}, True),
    ],
)
def test_subtraction_rejects_inconsistent_script_attribution(surface, total) -> None:
    arm = _observation("arm", "aaaa", {"api.A": 1})
    arm["analysis"].update(
        {
            "script_attributed_events": total,
            "script_attributed_events_by_name": surface,
        }
    )
    with pytest.raises(ContractError, match="script-attributed"):
        subtract_control(arm, _observation("control", "bbbb", {}))


@pytest.mark.parametrize(
    "summary",
    [
        {"total": 1, "complete": 1, "open": 1, "max_complete_duration_ns": 1},
        {"total": 1, "complete": 0, "open": 1, "max_complete_duration_ns": 1},
        {"total": 1, "complete": True, "open": 0, "max_complete_duration_ns": 1},
        {"total": 1, "complete": 1, "open": 0, "max_complete_duration_ns": -1},
    ],
)
def test_subtraction_rejects_invalid_script_execution_summary(summary) -> None:
    arm = _observation("arm", "aaaa", {"api.A": 1})
    arm["analysis"]["script_execution"] = summary
    with pytest.raises(ContractError, match="script execution"):
        subtract_control(arm, _observation("control", "bbbb", {}))


def test_subtraction_carries_arm_and_control_shutdown_receipts() -> None:
    arm = _observation("bm", "aaaa", {"api.A": 1})
    control = _observation("control", "bbbb", {})
    arm["browser_shutdown"] = {"mode": "graceful"}
    control["browser_shutdown"] = {"mode": "exited-before-force"}
    arm["trace_flush"] = {"status": "settled", "bytes": 1234}
    control["trace_flush"] = {"status": "settled", "bytes": 567}

    result = subtract_control(arm, control)
    assert result["arm_browser_shutdown"] == {"mode": "graceful"}
    assert result["control_browser_shutdown"] == {"mode": "exited-before-force"}
    assert result["arm_trace_flush"] == {"status": "settled", "bytes": 1234}
    assert result["control_trace_flush"] == {"status": "settled", "bytes": 567}


def test_subtraction_refuses_arm_and_control_from_different_rehost_contracts() -> None:
    arm = _observation("arm", "aaaa", {"api.A": 1})
    control = _observation("control", "bbbb", {})
    arm["rehost_contract"] = {"schema": "contract", "sha256": "a" * 64}
    control["rehost_contract"] = {"schema": "contract", "sha256": "b" * 64}

    with pytest.raises(ContractError, match="different rehost contracts"):
        subtract_control(arm, control)


def test_resource_intent_subtraction_attributes_external_dom_intent() -> None:
    shared = {
        "tag": "script",
        "attribute": "src",
        "origin": "loopback-rehost",
        "same_origin_as_rehost": True,
        "path_segment_lengths": [12],
        "path_segments_truncated": False,
        "query_names": [],
        "query_names_truncated": False,
    }
    external = {
        **shared,
        "tag": "iframe",
        "origin": "https://challenges.example",
        "same_origin_as_rehost": False,
        "path_segment_lengths": [5, 7],
        "query_names": ["lang"],
    }
    report = subtract_resource_intents(
        {"status": "ok", "intents": [shared, external]},
        {"status": "ok", "intents": [shared]},
    )
    assert report["status"] == "ok"
    assert report["shared_count"] == 1
    assert report["only_in_arm"] == [external]
    assert report["only_in_control"] == []
    assert report["clean_subtraction"] is True


def test_resource_intent_subtraction_preserves_shape_multiplicity() -> None:
    shape = {
        "tag": "script",
        "attribute": "src",
        "origin": "https://static.example",
        "same_origin_as_rehost": False,
        "path_segment_lengths": [2, 9],
        "path_segments_truncated": False,
        "query_names": [],
        "query_names_truncated": False,
    }

    report = subtract_resource_intents(
        {"status": "ok", "intents": [{**shape, "count": 2}]},
        {"status": "ok", "intents": [{**shape, "count": 1}]},
    )

    assert report["arm_count"] == 1
    assert report["control_count"] == 1
    assert report["arm_attribute_count"] == 2
    assert report["control_attribute_count"] == 1
    assert report["only_in_arm"] == []
    assert report["only_in_control"] == []
    assert report["multiplicity_deltas"] == [
        {**shape, "arm_occurrences": 2, "control_occurrences": 1}
    ]
    assert report["clean_subtraction"] is True


def test_resource_intent_subtraction_marks_control_excess_multiplicity_dirty() -> None:
    shape = {
        "tag": "form",
        "attribute": "action",
        "origin": "loopback-rehost",
        "same_origin_as_rehost": True,
        "path_segment_lengths": [6],
        "path_segments_truncated": False,
        "query_names": [],
        "query_names_truncated": False,
    }

    report = subtract_resource_intents(
        {"status": "ok", "intents": [{**shape, "count": 1}]},
        {"status": "ok", "intents": [{**shape, "count": 2}]},
    )

    assert report["only_in_control"] == []
    assert report["multiplicity_deltas"] == [
        {**shape, "arm_occurrences": 1, "control_occurrences": 2}
    ]
    assert report["clean_subtraction"] is False


def test_resource_intent_subtraction_fails_closed_when_a_snapshot_failed() -> None:
    report = subtract_resource_intents(
        {"status": "failed", "intents": []},
        {"status": "ok", "intents": []},
    )
    assert report["status"] == "unverifiable"
    assert report["only_in_arm"] == []


@pytest.mark.parametrize(
    "origin",
    [
        "https://static.example:99999",
        "https://static.example:000443",
        "http://2130706433:8000",
        "http://127.1:8000",
        "http://0x7f000001:8000",
        "http://[0:0:0:0:0:0:0:1]:8000",
        "http://test.42",
        "http://127%2e0%2e0%2e1:8000",
        "http://faß.de:8000",
    ],
)
def test_resource_intent_subtraction_rejects_invalid_saved_origins(origin: str) -> None:
    row = {
        "tag": "script",
        "attribute": "src",
        "origin": origin,
        "same_origin_as_rehost": False,
        "path_segment_lengths": [1],
        "path_segments_truncated": False,
        "query_names": [],
        "query_names_truncated": False,
    }
    report = subtract_resource_intents(
        {"status": "ok", "intents": [row]},
        {"status": "ok", "intents": []},
    )

    assert report["status"] == "unverifiable"
    assert report["only_in_arm"] == []


@pytest.mark.parametrize(
    ("origin", "same_origin"),
    [
        ("loopback-rehost", False),
        ("https://static.example", True),
    ],
)
def test_resource_intent_subtraction_rejects_origin_flag_disagreement(
    origin: str, same_origin: bool
) -> None:
    row = {
        "tag": "script",
        "attribute": "src",
        "origin": origin,
        "same_origin_as_rehost": same_origin,
        "path_segment_lengths": [1],
        "path_segments_truncated": False,
        "query_names": [],
        "query_names_truncated": False,
    }
    report = subtract_resource_intents(
        {"status": "ok", "intents": [row]},
        {"status": "ok", "intents": []},
    )

    assert report["status"] == "unverifiable"
    assert report["only_in_arm"] == []


@pytest.mark.parametrize(
    "mutated_fields",
    [
        {"candidate_attributes": 0},
        {"candidate_attributes": 3},
        {"distinct_intents": 0},
    ],
)
def test_resource_intent_subtraction_rejects_snapshot_count_disagreement(
    mutated_fields: dict[str, int],
) -> None:
    row = {
        "tag": "script",
        "attribute": "src",
        "origin": "https://static.example",
        "same_origin_as_rehost": False,
        "path_segment_lengths": [1],
        "path_segments_truncated": False,
        "query_names": ["lang"],
        "query_names_truncated": False,
        "count": 2,
    }
    snapshot = {
        "status": "ok",
        "intents": [row],
        "candidate_attributes": 2,
        "distinct_intents": 1,
        "truncated": False,
        **mutated_fields,
    }
    report = subtract_resource_intents(snapshot, {"status": "ok", "intents": []})

    assert report["status"] == "unverifiable"
    assert report["only_in_arm"] == []


def test_resource_intent_subtraction_rejects_duplicate_saved_shape() -> None:
    row = {
        "tag": "script",
        "attribute": "src",
        "origin": "https://static.example",
        "same_origin_as_rehost": False,
        "path_segment_lengths": [1],
        "path_segments_truncated": False,
        "query_names": [],
        "query_names_truncated": False,
        "count": 1,
    }
    report = subtract_resource_intents(
        {"status": "ok", "intents": [row, row]},
        {"status": "ok", "intents": []},
    )

    assert report["status"] == "unverifiable"
    assert report["only_in_arm"] == []


@pytest.mark.parametrize("names", [["b", "a"], ["a", "a"]])
def test_resource_intent_subtraction_rejects_noncanonical_query_names(names):
    row = {
        "tag": "script",
        "attribute": "src",
        "origin": "https://static.example",
        "same_origin_as_rehost": False,
        "path_segment_lengths": [1],
        "path_segments_truncated": False,
        "query_names": names,
        "query_names_truncated": False,
    }
    report = subtract_resource_intents(
        {"status": "ok", "intents": [row]},
        {"status": "ok", "intents": []},
    )

    assert report["status"] == "unverifiable"
    assert report["only_in_arm"] == []


def test_resource_intent_subtraction_accepts_coherent_snapshot_counts() -> None:
    row = {
        "tag": "script",
        "attribute": "src",
        "origin": "https://static.example",
        "same_origin_as_rehost": False,
        "path_segment_lengths": [1],
        "path_segments_truncated": False,
        "query_names": ["a", "b"],
        "query_names_truncated": False,
        "count": 2,
    }
    report = subtract_resource_intents(
        {
            "status": "ok",
            "intents": [row],
            "candidate_attributes": 2,
            "distinct_intents": 1,
            "truncated": False,
        },
        {"status": "ok", "intents": []},
    )

    assert report["status"] == "ok"
    assert report["only_in_arm"] == [row]


@pytest.mark.parametrize(
    "invalid_field",
    [{"candidate_attributes": True}, {"distinct_intents": "0"}],
)
def test_resource_intent_sanitizer_rejects_malformed_present_counts(invalid_field):
    report = product_observation._sanitize_resource_intent_report(
        {"status": "ok", "intents": [], "truncated": False, **invalid_field}
    )

    assert report["status"] == "unverifiable"


@pytest.mark.parametrize(
    "row_field",
    [{"count": 1_000_001}, {"path_segment_lengths": [1_000_001]}],
)
def test_resource_intent_sanitizer_rejects_clipped_saved_row(row_field):
    row = {
        "tag": "script",
        "attribute": "src",
        "origin": "https://static.example",
        "same_origin_as_rehost": False,
        "path_segment_lengths": [1],
        "path_segments_truncated": False,
        "query_names": [],
        "query_names_truncated": False,
        "count": 1,
        **row_field,
    }
    report = product_observation._sanitize_resource_intent_report(
        {"status": "ok", "intents": [row], "truncated": False}
    )

    assert report["status"] == "unverifiable"
    assert report["intents"] == []


def test_resource_intent_sanitizer_rejects_zero_length_path_segment():
    row = {
        "tag": "script",
        "attribute": "src",
        "origin": "https://static.example",
        "same_origin_as_rehost": False,
        "path_segment_lengths": [0],
        "query_names": [],
        "count": 1,
    }
    report = product_observation._sanitize_resource_intent_report(
        {"status": "ok", "intents": [row]}
    )

    assert report["status"] == "unverifiable"
    assert report["intents"] == []


@pytest.mark.parametrize("snapshot", [{"status": "ok"}, {"status": "ok", "intents": None}])
def test_resource_intent_subtraction_rejects_missing_saved_rows(snapshot) -> None:
    report = subtract_resource_intents(snapshot, {"status": "ok", "intents": []})

    assert report["status"] == "unverifiable"
    assert report["only_in_arm"] == []


def test_resource_intent_sanitizer_rejects_an_empty_success_envelope() -> None:
    report = product_observation._sanitize_resource_intent_report({"status": "ok"})

    assert report["status"] == "unverifiable"


def test_resource_intent_subtraction_rejects_dropped_query_names() -> None:
    row = {
        "tag": "script",
        "attribute": "src",
        "origin": "https://static.example",
        "same_origin_as_rehost": False,
        "path_segment_lengths": [1],
        "path_segments_truncated": False,
        "query_names": ["x" * 81],
        "query_names_truncated": False,
    }
    report = subtract_resource_intents(
        {"status": "ok", "intents": [row]},
        {"status": "ok", "intents": []},
    )

    assert report["status"] == "unverifiable"


def test_resource_intent_subtraction_rejects_non_boolean_truncation_receipt() -> None:
    report = subtract_resource_intents(
        {"status": "ok", "intents": [], "truncated": "false"},
        {"status": "ok", "intents": []},
    )

    assert report["status"] == "unverifiable"


def test_resource_intent_sanitizer_rejects_dropped_multiplicity_delta() -> None:
    report = product_observation._sanitize_resource_intent_report(
        {
            "status": "ok",
            "only_in_arm": [],
            "only_in_control": [],
            "multiplicity_deltas": [{"private": "invalid row"}],
            "clean_subtraction": True,
        }
    )

    assert report["status"] == "unverifiable"
    assert report["multiplicity_deltas"] == []
    assert "private" not in json.dumps(report)


def test_resource_intent_subtraction_fails_closed_when_a_snapshot_was_truncated() -> (
    None
):
    report = subtract_resource_intents(
        {"status": "ok", "truncated": True, "intents": []},
        {"status": "ok", "truncated": False, "intents": []},
    )

    assert report == {
        "status": "unverifiable",
        "arm_status": "truncated",
        "control_status": "ok",
        "only_in_arm": [],
        "only_in_control": [],
        "non_claim": (
            "both DOM snapshots must succeed without truncation before intent "
            "is attributable"
        ),
    }


def test_resource_intent_subtraction_derives_a_missing_truncation_receipt() -> None:
    rows = [
        {
            "tag": "script",
            "attribute": "src",
            "origin": f"https://r{index}.example.invalid",
            "same_origin_as_rehost": False,
            "path_segment_lengths": [1],
            "path_segments_truncated": False,
            "query_names": [],
            "query_names_truncated": False,
        }
        for index in range(129)
    ]

    report = subtract_resource_intents(
        {"status": "ok", "truncated": False, "intents": rows},
        {"status": "ok", "intents": []},
    )

    assert report["status"] == "unverifiable"
    assert report["arm_status"] == "truncated"
    assert report["only_in_arm"] == []


def test_subtraction_carries_public_provenance_and_redacted_method() -> None:
    arm = _current_method_observation("vendor", "a" * 16, {"api.A": 1})
    control = _current_method_observation("control", "b" * 16, {})
    for document in (arm, control):
        document.update(
            script_path="/v1/api.js",
            declared_script_url="https://vendor.example/v1/api.js",
            prelude={
                "supplied": True,
                "bytes": 12,
                "sha256_16": "1234567890abcdef",
            },
            driver={
                "supplied": True,
                "bytes": 27,
                "sha256_16": "abcdef0123456789",
            },
            driver_result={
                "status": "ok",
                "type": "null",
                "serialized_bytes": 4,
            },
        )
    arm["source_provenance"] = {
        "status": "verified_digest",
        "source_url": "https://vendor.example/v1/api.js",
        "retrieved_at": "2026-08-12T00:00:00Z",
        "sha256": arm["script_sha256_16"] + "a" * 48,
        "note": "the supplied full digest matches the exact bytes observed",
    }
    arm["script_identity"]["signals"]["kpsdk_literals"] = 1
    arm["script_identity"]["vendor_hint"] = "kasada"
    result = subtract_control(arm, control)
    assert result["source_provenance"]["status"] == "verified_digest"
    assert result["provenance"]["asserted_label"] == "vendor"
    assert result["script_identity"]["vendor_hint"] == "kasada"
    assert result["arm_declared_script_url"]["shape"]["origin"] == (
        "https://vendor.example"
    )
    assert result["arm_declared_script_url"]["sha256_16"]
    assert result["arm_driver_supplied"] is True
    assert "secret-bearing setup source" not in json.dumps(result)


def test_capture_provenance_retains_only_a_safe_asserted_label() -> None:
    safe = product_observation._sanitize_capture_provenance(
        {"status": "not_checked", "asserted_label": "vendor-arm"}
    )
    unsafe = product_observation._sanitize_capture_provenance(
        {"status": "not_checked", "asserted_label": "../private tenant"}
    )

    assert safe["asserted_label"] == "vendor-arm"
    assert "asserted_label" not in unsafe


def test_current_subtraction_binds_its_complete_public_receipt() -> None:
    result = subtract_control(
        _current_method_observation("vendor", "a" * 16, {"api.A": 1}),
        _current_method_observation("control", "b" * 16, {}),
    )

    assert re.fullmatch(r"[0-9a-f]{64}", result["subtraction_receipt_sha256"])


def test_current_observation_binds_its_complete_public_receipt() -> None:
    document = product_observation._seal_observation_document(
        _current_method_observation("vendor", "a" * 16, {"api.A": 1})
    )

    assert re.fullmatch(r"[0-9a-f]{64}", document["observation_receipt_sha256"])


def test_current_observation_write_rejects_unredacted_side_reports(
    tmp_path: Path,
) -> None:
    row = {
        "tag": "iframe",
        "attribute": "src",
        "origin": "https://collector.example",
        "same_origin_as_rehost": False,
        "path_segment_lengths": [4],
        "path_segments_truncated": False,
        "query_names": [],
        "query_names_truncated": False,
    }
    observation = _current_method_observation("raw", "a" * 16, {"api.A": 1})
    observation["resource_intent_capture"] = "cdp_dom_snapshot/1"
    observation["resource_intents"] = (
        product_observation._sanitize_resource_intent_report(
            {"status": "ok", "intents": [row]}
        )
    )
    product_observation._seal_observation_document(observation)
    write_observation(tmp_path / "canonical.json", observation)

    observation["resource_intents"]["intents"][0]["origin"] = (
        "https://collector.example/private?token=example"
    )
    product_observation._seal_observation_document(observation)
    with pytest.raises(ContractError, match="observation resource intent"):
        write_observation(tmp_path / "private-resource.json", observation)
    resource_path = tmp_path / "private-resource-loaded.json"
    resource_path.write_text(json.dumps(observation), encoding="utf-8")
    with pytest.raises(ContractError, match="observation resource intent"):
        load_observation(resource_path)

    observation["resource_intents"] = (
        product_observation._sanitize_resource_intent_report(
            {"status": "ok", "intents": [row]}
        )
    )
    observation["request_activity"]["rows"][0]["raw_url"] = (
        "https://collector.example/private?token=example"
    )
    product_observation._seal_observation_document(observation)
    with pytest.raises(ContractError, match="observation request activity"):
        write_observation(tmp_path / "private-request.json", observation)
    request_path = tmp_path / "private-request-loaded.json"
    request_path.write_text(json.dumps(observation), encoding="utf-8")
    with pytest.raises(ContractError, match="observation request activity"):
        load_observation(request_path)


def test_current_observation_side_reports_preserve_off_and_failed_producer_shapes(
    tmp_path: Path,
) -> None:
    off = _current_method_observation("off", "a" * 16, {"api.A": 1})
    off["resource_intents"] = {
        "status": "off",
        "source": "cdp_dom_snapshot",
        "intents": [],
        "non_claim": "resource-intent capture disabled for this method arm",
    }
    product_observation._seal_observation_document(off)
    write_observation(tmp_path / "off.json", off)

    failed = _current_method_observation("failed", "a" * 16, {"api.A": 1})
    failed["resource_intent_capture"] = "cdp_dom_snapshot/2"
    failed["resource_intents"] = {
        "status": "failed",
        "source": "cdp_dom_snapshot",
        "diagnostic": product_observation._failure_receipt(
            "resource intent capture failed", RuntimeError("synthetic")
        ),
        "intents": [],
        "non_claim": "resource intent could not be observed",
    }
    product_observation._seal_observation_document(failed)
    write_observation(tmp_path / "failed.json", failed)

    off["resource_intents"]["intents"].append({"origin": "https://private.example"})
    product_observation._seal_observation_document(off)
    with pytest.raises(ContractError, match="observation resource intent"):
        write_observation(tmp_path / "invalid-off.json", off)


def test_subtraction_rejects_a_coherent_edit_to_a_current_observation() -> None:
    arm = product_observation._seal_observation_document(
        _current_method_observation("vendor", "a" * 16, {"api.A": 1})
    )
    control = product_observation._seal_observation_document(
        _current_method_observation("control", "b" * 16, {})
    )
    arm["analysis"]["events_by_name"]["api.EDITED"] = 1

    with pytest.raises(ContractError, match="observation receipt"):
        subtract_control(arm, control)


def test_baseline_rejects_a_coherent_edit_to_a_current_subtraction() -> None:
    result = subtract_control(
        _current_method_observation("vendor", "a" * 16, {"api.A": 1}),
        _current_method_observation("control", "b" * 16, {}),
    )
    result["only_in_arm"]["api.EDITED"] = 1

    with pytest.raises(ContractError, match="subtraction receipt"):
        build_surface_baseline(result)


def test_pairwise_comparison_rejects_an_edited_current_subtraction() -> None:
    first = subtract_control(
        _current_method_observation("first", "a" * 16, {"api.A": 1}),
        _current_method_observation("first-control", "b" * 16, {}),
    )
    second = subtract_control(
        _current_method_observation("second", "a" * 16, {"api.A": 1}),
        _current_method_observation("second-control", "b" * 16, {}),
    )
    second["only_in_arm"]["api.EDITED"] = 1

    with pytest.raises(ContractError, match="subtraction receipt"):
        compare_surfaces([first, second])


def test_subtraction_carries_attributed_resource_intents_and_capture_method() -> None:
    row = {
        "tag": "iframe",
        "attribute": "src",
        "origin": "https://challenges.example",
        "same_origin_as_rehost": False,
        "path_segment_lengths": [5],
        "path_segments_truncated": False,
        "query_names": ["lang"],
        "query_names_truncated": False,
    }
    arm = _observation("vendor", "aaaa", {"api.A": 1})
    control = _observation("control", "bbbb", {})
    arm.update(
        resource_intent_capture="cdp_dom_snapshot/1",
        resource_intents={"status": "ok", "intents": [row]},
    )
    control.update(
        resource_intent_capture="cdp_dom_snapshot/1",
        resource_intents={"status": "ok", "intents": []},
    )
    result = subtract_control(arm, control)
    assert result["arm_resource_intent_capture"] == "cdp_dom_snapshot/1"
    assert result["resource_intents"]["only_in_arm"] == [row]


def test_subtraction_withholds_surface_claim_when_collector_did_not_start() -> None:
    arm = _observation("vendor", "aaaa", {"api.A": 1})
    control = _observation("control", "bbbb", {})
    arm["collector_startup"] = {
        "started": False,
        "reasons": ["module loaded but worker did not start"],
    }

    result = subtract_control(arm, control)

    assert result["clean_subtraction"] is True
    assert result["collector_started"] is False
    assert result["collector_startup_coherent"] is True
    assert result["surface_claim_ready"] is False


@pytest.mark.parametrize(
    "receipt",
    [
        True,
        {"started": True, "reasons": ["edited private reason"]},
        {"started": False, "reasons": []},
        {"started": "true", "reasons": []},
        {
            "started": True,
            "reasons": [],
            "uncaught_errors": ["private startup error"],
        },
        {"started": True, "reasons": [], "uncaught_errors": "hidden error"},
        {"started": True, "reasons": [], "unhandled_rejections": "hidden"},
        {"started": True, "reasons": [], "vendor_reports_ready": False},
        {"started": True, "reasons": [], "vendor_reports_ready": "threw"},
        {"started": True, "reasons": [], "vendor_reports_ready": "private"},
        {"started": True, "reasons": [], "probe_error": "private probe error"},
    ],
)
def test_subtraction_closes_claim_on_incoherent_collector_startup_receipt(
    receipt,
) -> None:
    arm = _observation("vendor", "aaaa", {"api.A": 1})
    control = _observation("control", "bbbb", {})
    arm["collector_startup"] = receipt

    result = subtract_control(arm, control)

    assert result["collector_startup_coherent"] is False
    assert result["collector_started"] is None
    assert result["surface_claim_ready"] is False
    rendered = json.dumps(result["collector_startup"])
    assert "edited private reason" not in rendered
    assert "private startup error" not in rendered
    assert "private probe error" not in rendered


def test_subtraction_withholds_surface_claim_when_a_rehost_stage_is_missing() -> None:
    arm = _observation("vendor", "aaaa", {"api.A": 1})
    control = _observation("control", "bbbb", {})
    arm["unserved_requests"] = {
        "status": "ok",
        "count": 1,
        "dependencies_complete": False,
        "paths": ["/private/deployment/stage.js"],
    }

    result = subtract_control(arm, control)

    assert result["clean_subtraction"] is True
    assert result["collector_started"] is True
    assert result["rehost_dependencies_complete"] is False
    assert result["surface_claim_ready"] is False
    assert result["unserved_requests"]["paths"] == ["/private/deployment/stage.js"]


def test_subtraction_accepts_an_explicitly_complete_rehost_dependency_set() -> None:
    arm = _observation("vendor", "aaaa", {"api.A": 1})
    control = _observation("control", "bbbb", {})
    arm["unserved_requests"] = {
        "status": "ok",
        "count": 0,
        "dependencies_complete": True,
        "paths": [],
    }

    result = subtract_control(arm, control)

    assert result["rehost_dependencies_complete"] is True
    assert result["surface_claim_ready"] is True


def test_subtraction_infers_a_complete_legacy_rehost_dependency_count() -> None:
    arm = _observation("vendor", "aaaa", {"api.A": 1})
    control = _observation("control", "bbbb", {})
    arm["unserved_requests"] = {"status": "ok", "count": 0, "paths": []}

    result = subtract_control(arm, control)

    assert result["rehost_dependencies_complete"] is True
    assert result["surface_claim_ready"] is True


def test_subtraction_projects_only_bounded_legacy_missing_stage_fields() -> None:
    arm = _observation("vendor", "aaaa", {"api.A": 1})
    control = _observation("control", "bbbb", {})
    arm["unserved_requests"] = {
        "status": "ok",
        "count": 0,
        "dependencies_complete": True,
        "paths": [],
        "note": "private legacy note",
        "extra": {"private": "legacy value"},
    }

    result = subtract_control(arm, control)

    assert result["rehost_dependencies_complete"] is True
    assert result["unserved_requests"] == {
        "status": "ok",
        "count": 0,
        "dependencies_complete": True,
        "paths": [],
    }


@pytest.mark.parametrize("path", ["/next?token=private", "/next#private", "/" + "x" * 4096])
def test_subtraction_withholds_invalid_legacy_missing_stage_path(path: str) -> None:
    arm = _observation("vendor", "aaaa", {"api.A": 1})
    control = _observation("control", "bbbb", {})
    arm["unserved_requests"] = {
        "status": "ok",
        "count": 1,
        "dependencies_complete": False,
        "paths": [path],
    }

    result = subtract_control(arm, control)

    assert result["rehost_dependencies_complete"] is None
    assert result["unserved_requests"] == {"status": "unverifiable"}


@pytest.mark.parametrize(
    "receipt",
    [
        {
            "status": "ok",
            "count": 1,
            "dependencies_complete": True,
            "paths": ["/missing-stage.js"],
        },
        {
            "status": "ok",
            "count": 0,
            "dependencies_complete": True,
            "paths": ["/missing-stage.js"],
        },
        {
            "status": "unverifiable",
            "count": 0,
            "dependencies_complete": True,
            "paths": [],
        },
        {
            "status": "ok",
            "count": 0,
            "paths": ["/missing-stage.js"],
        },
        {
            "status": "ok",
            "count": 0,
            "dependencies_complete": "true",
            "paths": [],
        },
        {
            "status": "ok",
            "count": 0,
            "dependencies_complete": 0,
            "paths": [],
        },
        {
            "status": "ok",
            "count": 0,
            "dependencies_complete": True,
            "paths": [],
            "truncated_paths": 1,
        },
        {
            "status": "ok",
            "count": 0,
            "paths": [],
            "malformed_entries": 1,
        },
        {
            "status": "ok",
            "count": 0,
            "dependencies_complete": True,
            "paths": [],
            "dropped_requests": 1,
        },
    ],
)
def test_subtraction_withholds_conflicting_legacy_rehost_dependency_receipt(
    receipt: dict,
) -> None:
    arm = _observation("vendor", "aaaa", {"api.A": 1})
    control = _observation("control", "bbbb", {})
    arm["unserved_requests"] = receipt

    result = subtract_control(arm, control)

    assert result["rehost_dependencies_complete"] is None
    assert result["surface_claim_ready"] is False


def _set_current_request_receipts(document: dict, rows: list[dict]) -> None:
    document["server_requests"] = rows
    document["server_request_log"] = {
        "limit": product_observation.MAX_REHOST_REQUEST_LOG_ENTRIES,
        "retained": len(rows),
        "dropped": 0,
        "truncated_paths": 0,
        "truncated": False,
        "proxy_denied": sum(row.get("served") == "proxy-denied" for row in rows),
    }
    document["request_activity"] = project_server_request_activity(rows)
    document["unserved_requests"] = grade_unserved_requests(rows)


def _attach_current_request_receipts(document: dict) -> None:
    _set_current_request_receipts(
        document,
        [
            {
                "method": "GET",
                "path": "/",
                "served": "page",
                "request_body_bytes": 0,
            },
            {
                "method": "GET",
                "path": "/product-script.js",
                "served": "sample",
                "request_body_bytes": 0,
            },
            {
                "method": "POST",
                "path": "/collector",
                "served": "post-ack",
                "request_body_bytes": 32,
            },
        ],
    )


def test_subtraction_recomputes_and_reconciles_current_dependency_receipts() -> None:
    arm = _observation("vendor", "aaaa", {"api.A": 1})
    control = _observation("control", "bbbb", {})
    _attach_current_request_receipts(arm)
    _attach_current_request_receipts(control)

    result = subtract_control(arm, control)

    assert result["rehost_receipts_coherent"] is True
    assert result["request_activity_receipts_coherent"] is True
    assert result["rehost_dependencies_complete"] is True
    assert result["surface_claim_ready"] is True


@pytest.mark.parametrize("role", ["arm", "control"])
def test_subtraction_withholds_dependency_completeness_without_log_receipt(
    role: str,
) -> None:
    arm = _observation("vendor", "aaaa", {"api.A": 1})
    control = _observation("control", "bbbb", {})
    _attach_current_request_receipts(arm)
    _attach_current_request_receipts(control)
    (arm if role == "arm" else control).pop("server_request_log")

    result = subtract_control(arm, control)

    assert result["rehost_receipts_coherent"] is False
    assert result[f"{'rehost' if role == 'arm' else 'control_rehost'}_dependencies_complete"] is None
    assert result["surface_claim_ready"] is False


@pytest.mark.parametrize(
    "mutation",
    [
        "dependency_boolean",
        "dependency_integer",
        "unserved_count",
        "unserved_count_boolean",
        "unserved_path",
        "unserved_truncated_paths_boolean",
        "unserved_malformed_entries_boolean",
        "unserved_dropped_requests",
        "acknowledgement_count",
        "acknowledgement_count_boolean",
        "acknowledgement_body_bytes",
        "proxy_denied_count",
        "proxy_denied_count_boolean",
        "retained_count",
        "dropped_count",
        "receipt_limit_float",
        "receipt_truncated_paths_boolean",
        "receipt_proxy_denied_boolean",
        "receipt_truncated_integer",
        "retained_rows",
    ],
)
def test_subtraction_closes_claim_on_edited_dependency_population(
    mutation: str,
) -> None:
    arm = _observation("vendor", "aaaa", {"api.A": 1})
    control = _observation("control", "bbbb", {})
    _attach_current_request_receipts(arm)
    _attach_current_request_receipts(control)
    if mutation == "dependency_boolean":
        arm["unserved_requests"]["dependencies_complete"] = False
    elif mutation == "dependency_integer":
        arm["unserved_requests"]["dependencies_complete"] = 1
    elif mutation == "unserved_count":
        arm["unserved_requests"]["count"] = 1
    elif mutation == "unserved_count_boolean":
        arm["unserved_requests"]["count"] = False
    elif mutation == "unserved_path":
        arm["unserved_requests"]["paths"] = ["/fabricated-stage"]
    elif mutation == "unserved_truncated_paths_boolean":
        arm["unserved_requests"]["truncated_paths"] = False
    elif mutation == "unserved_malformed_entries_boolean":
        arm["unserved_requests"]["malformed_entries"] = False
    elif mutation == "unserved_dropped_requests":
        arm["unserved_requests"]["dropped_requests"] = 1
    elif mutation == "acknowledgement_count":
        arm["unserved_requests"]["synthetic_acknowledgements"]["count"] = 0
    elif mutation == "acknowledgement_count_boolean":
        arm["unserved_requests"]["synthetic_acknowledgements"]["count"] = True
    elif mutation == "acknowledgement_body_bytes":
        arm["unserved_requests"]["synthetic_acknowledgements"][
            "request_body_bytes"
        ] = 0
    elif mutation == "proxy_denied_count":
        arm["unserved_requests"]["proxy_denied"]["count"] = 1
    elif mutation == "proxy_denied_count_boolean":
        arm["unserved_requests"]["proxy_denied"]["count"] = False
    elif mutation == "retained_count":
        arm["server_request_log"]["retained"] = 4
    elif mutation == "dropped_count":
        arm["server_request_log"]["dropped"] = 1
        arm["server_request_log"]["truncated"] = True
    elif mutation == "receipt_limit_float":
        arm["server_request_log"]["limit"] = float(
            product_observation.MAX_REHOST_REQUEST_LOG_ENTRIES
        )
    elif mutation == "receipt_truncated_paths_boolean":
        arm["server_request_log"]["truncated_paths"] = False
    elif mutation == "receipt_proxy_denied_boolean":
        arm["server_request_log"]["proxy_denied"] = False
    elif mutation == "receipt_truncated_integer":
        arm["server_request_log"]["truncated"] = 0
    else:
        arm["server_requests"].append(
            {
                "method": "GET",
                "path": "/missing-stage",
                "served": "empty",
                "request_body_bytes": 0,
            }
        )

    result = subtract_control(arm, control)

    assert result["rehost_receipts_coherent"] is False
    assert result["rehost_dependencies_complete"] is None
    assert result["unserved_requests"]["status"] == "unverifiable"
    assert result["surface_claim_ready"] is False


@pytest.mark.parametrize(
    "mutation",
    ["candidate_count", "shape_count", "row_count", "body_total", "status"],
)
def test_subtraction_recomputes_current_request_activity_population(
    mutation: str,
) -> None:
    arm = _observation("vendor", "aaaa", {"api.A": 1})
    control = _observation("control", "bbbb", {})
    _attach_current_request_receipts(arm)
    _attach_current_request_receipts(control)
    activity = arm["request_activity"]
    if mutation == "candidate_count":
        activity["candidate_requests"] += 1
    elif mutation == "shape_count":
        activity["distinct_shapes"] += 1
    elif mutation == "row_count":
        activity["rows"][0]["count"] += 1
    elif mutation == "body_total":
        activity["rows"][0]["body_bytes_total"] += 1
    else:
        activity["status"] = "unverifiable"

    result = subtract_control(arm, control)

    assert result["rehost_receipts_coherent"] is True
    assert result["request_activity_receipts_coherent"] is False
    assert result["request_activity"]["status"] == "unverifiable"
    assert result["surface_claim_ready"] is False


def test_control_dependency_population_also_closes_the_surface_claim() -> None:
    arm = _observation("vendor", "aaaa", {"api.A": 1})
    control = _observation("control", "bbbb", {})
    _attach_current_request_receipts(arm)
    _attach_current_request_receipts(control)
    control["server_requests"].append(
        {
            "method": "GET",
            "path": "/control-missing-stage",
            "served": "empty",
            "request_body_bytes": 0,
        }
    )
    control["server_request_log"]["retained"] += 1
    control["request_activity"] = project_server_request_activity(
        control["server_requests"]
    )
    control["unserved_requests"] = grade_unserved_requests(control["server_requests"])

    result = subtract_control(arm, control)

    assert result["control_rehost_dependencies_complete"] is False
    assert result["rehost_receipts_coherent"] is True
    assert result["surface_claim_ready"] is False


def test_subtraction_projects_legacy_raw_request_logs() -> None:
    arm = _observation("vendor", "aaaa", {"api.Navigator.sendBeacon": 1})
    control = _observation("control", "bbbb", {})
    arm["server_requests"] = [
        {
            "method": "POST",
            "path": "/private-tenant/fingerprint",
            "served": "post-ack",
            "request_body_bytes": 4880,
        }
    ]
    control["server_requests"] = []
    result = subtract_control(arm, control)
    rendered = json.dumps(result["request_activity"])
    assert "private-tenant" not in rendered
    assert result["request_activity"]["only_in_arm"][0]["count"] == 1


def test_subtraction_carries_sanitized_input_delivery_receipts() -> None:
    arm = _observation("touch", "aaaa", {"api.Event.type.get": 1})
    control = _observation("control", "bbbb", {})
    for document in (arm, control):
        document.update(
            input_profile="probe-touch",
            input_probe={
                "profile": "probe-touch",
                "dispatched": 3,
                "attempted": 3,
                "errors": [],
                "trusted": True,
                "touch_dispatched": True,
            },
            ambient_input={
                "contaminated": False,
                "events": {"touchstart": 1, "touchmove": 1, "touchend": 1},
                "reasons": ["private reason must not travel"],
            },
        )
    result = subtract_control(arm, control)
    assert result["arm_input_probe"]["complete"] is True
    assert result["control_input_probe"]["complete"] is True
    assert result["arm_ambient_input"]["trusted_events"] == {
        "touchend": 1,
        "touchmove": 1,
        "touchstart": 1,
    }
    assert "private reason" not in json.dumps(result)
    assert result["input_method_comparable"] is True
    assert result["ambient_input_clean"] is True
    assert result["surface_claim_ready"] is True


def test_ambient_trusted_input_closes_the_surface_claim() -> None:
    arm = _observation("ambient", "aaaa", {"api.Event.isTrusted.get": 1})
    control = _observation("control", "bbbb", {})
    arm.update(
        input_profile="none",
        input_probe=None,
        ambient_input={
            "contaminated": True,
            "events": {"click": 1},
            "reasons": ["private ambient reason"],
        },
    )
    control.update(
        input_profile="none",
        input_probe=None,
        ambient_input={"contaminated": False, "events": {}, "reasons": []},
    )

    result = subtract_control(arm, control)

    assert result["input_method_comparable"] is True
    assert result["ambient_input_clean"] is False
    assert result["surface_claim_ready"] is False
    assert "private ambient reason" not in json.dumps(result)


def test_conflicting_ambient_event_aliases_close_the_surface_claim() -> None:
    arm = _observation("ambient", "aaaa", {"api.Event.isTrusted.get": 1})
    control = _observation("control", "bbbb", {})
    arm.update(
        input_profile="none",
        input_probe=None,
        ambient_input={
            "contaminated": False,
            "events": {},
            "trusted_events": {"click": 1},
        },
    )
    control.update(
        input_profile="none",
        input_probe=None,
        ambient_input={"contaminated": False, "events": {}},
    )

    result = subtract_control(arm, control)

    assert result["ambient_input_clean"] is False
    assert result["surface_claim_ready"] is False


def test_conflicting_ambient_total_closes_the_surface_claim() -> None:
    arm = _observation("ambient", "aaaa", {"api.Event.isTrusted.get": 1})
    control = _observation("control", "bbbb", {})
    arm.update(
        input_profile="none",
        input_probe=None,
        ambient_input={
            "contaminated": False,
            "events": {},
            "total_trusted_events": 1,
        },
    )
    control.update(
        input_profile="none",
        input_probe=None,
        ambient_input={"contaminated": False, "events": {}},
    )

    result = subtract_control(arm, control)

    assert result["ambient_input_clean"] is False
    assert result["surface_claim_ready"] is False


@pytest.mark.parametrize(
    "mutation",
    [
        "missing_probe",
        "incomplete_probe",
        "untrusted_probe",
        "conflicting_trust_aliases",
        "false_complete_receipt",
        "mismatched_profile",
        "false_clean_grade",
        "clipped_counts",
        "clipped_witness",
        "scroll_count_mismatch",
    ],
)
def test_input_method_or_ambient_receipt_mutations_close_claim(mutation: str) -> None:
    arm = _observation("probe", "aaaa", {"api.Event.type.get": 1})
    control = _observation("control", "bbbb", {})
    complete_probe = {
        "profile": "probe",
        "dispatched": 3,
        "attempted": 3,
        "errors": [],
        "trusted": True,
    }
    for document in (arm, control):
        document.update(
            input_profile="probe",
            input_probe=dict(complete_probe),
            ambient_input={
                "contaminated": False,
                "events": {"click": 1},
                "reasons": ["input probe drove this arm deliberately"],
            },
        )
    if mutation == "missing_probe":
        arm["input_probe"] = None
    elif mutation == "incomplete_probe":
        arm["input_probe"]["dispatched"] = 2
    elif mutation == "untrusted_probe":
        arm["input_probe"]["trusted"] = False
    elif mutation == "conflicting_trust_aliases":
        arm["input_probe"]["trusted_transport"] = False
    elif mutation == "false_complete_receipt":
        arm["input_probe"]["complete"] = False
    elif mutation == "mismatched_profile":
        arm["input_profile"] = "probe-scroll"
    elif mutation == "clipped_counts":
        arm["input_probe"]["dispatched"] = 10_001
        arm["input_probe"]["attempted"] = 10_002
    elif mutation == "clipped_witness":
        arm["ambient_input"]["events"]["click"] = 10_001
    elif mutation == "scroll_count_mismatch":
        for document in (arm, control):
            document["input_profile"] = "probe-scroll"
            document["input_probe"]["profile"] = "probe-scroll"
            document["input_probe"]["scroll_commands_dispatched"] = 3
        arm["input_probe"]["scroll_commands_dispatched"] = 1
    else:
        arm["input_profile"] = "none"
        arm["input_probe"] = None
        arm["ambient_input"]["contaminated"] = False

    result = subtract_control(arm, control)

    assert result["surface_claim_ready"] is False
    if mutation in {"false_clean_grade", "clipped_witness"}:
        assert result["ambient_input_clean"] is False
    else:
        assert result["input_method_comparable"] is False


@pytest.mark.parametrize(
    ("profile", "delivery_field", "complete_value", "missing_value"),
    [
        ("probe-touch", "touch_dispatched", True, False),
        ("probe-scroll", "scroll_commands_dispatched", 3, 0),
    ],
)
def test_profile_specific_input_delivery_is_required_for_claims(
    profile: str,
    delivery_field: str,
    complete_value,
    missing_value,
) -> None:
    arm = _observation("profile-input", "aaaa", {"api.Event.type.get": 1})
    control = _observation("control", "bbbb", {})
    for document in (arm, control):
        document.update(
            input_profile=profile,
            input_probe={
                "profile": profile,
                "dispatched": 3,
                "attempted": 3,
                "errors": [],
                "trusted": True,
                delivery_field: complete_value,
            },
            ambient_input={
                "contaminated": False,
                "events": {"click": 1},
                "reasons": ["input probe drove this arm deliberately"],
            },
        )
    arm["input_probe"][delivery_field] = missing_value

    result = subtract_control(arm, control)

    assert result["input_method_comparable"] is False
    assert result["surface_claim_ready"] is False


def test_subtraction_still_reads_legacy_raw_driver_presence() -> None:
    arm = _observation("legacy", "aaaa", {"api.A": 1})
    arm["driver_js"] = "legacy source that must not travel downstream"
    result = subtract_control(arm, _observation("control", "bbbb", {}))
    assert result["arm_driver_supplied"] is True
    assert "legacy source" not in json.dumps(result)


def test_subtraction_hashes_legacy_ready_expression() -> None:
    arm = _observation("legacy-ready", "aaaa", {"api.A": 1})
    arm["ready_expression"] = "window.__private_completion_marker === true"
    result = subtract_control(arm, _observation("control", "bbbb", {}))
    assert result["arm_ready_expression"]["supplied"] is True
    assert "private_completion_marker" not in json.dumps(result)


def test_subtraction_hashes_legacy_raw_prelude() -> None:
    arm = _observation("legacy-prelude", "aaaa", {"api.A": 1})
    arm["prelude"] = "window.__private_tenant_key = 'secret-value'"
    result = subtract_control(arm, _observation("control", "bbbb", {}))
    assert result["arm_prelude"]["supplied"] is True
    assert result["arm_prelude"]["sha256_16"]
    assert "private_tenant_key" not in json.dumps(result)


def test_subtraction_drops_legacy_stage_local_path() -> None:
    arm = _observation("legacy-stage", "aaaa", {"api.A": 1})
    arm["stage_routes"] = [
        {
            "path_prefix": "/tenant/mfc",
            "file": r"C:\private\captures\tenant-secret\ips.js",
            "sha256_16": "a" * 16,
        }
    ]
    result = subtract_control(arm, _observation("control", "bbbb", {}))
    route = result["arm_stage_routes"][0]
    assert route["sha256_16"] == "a" * 16
    assert route["path_prefix"]["path_segment_lengths"] == [6, 3]
    assert route["path_prefix"]["absolute_path"] is True
    assert "tenant-secret" not in json.dumps(result)


def test_subtract_control_reports_elevated_names() -> None:
    arm = _observation("bm", "aaaa", {"api.Performance.now": 127})
    control = _observation("control", "bbbb", {"api.Performance.now": 1})
    result = subtract_control(arm, control)
    assert result["only_in_arm"] == {}
    assert result["elevated_in_arm"]["api.Performance.now"] == {
        "arm": 127,
        "control": 1,
    }


def test_subtract_control_marks_dirty_control() -> None:
    """A control that is not a strict subset invalidates the attribution."""
    arm = _observation("bm", "aaaa", {"api.A": 1})
    control = _observation("control", "bbbb", {"api.B": 1})
    result = subtract_control(arm, control)
    assert result["clean_subtraction"] is False
    assert result["only_in_control"] == {"api.B": 1}


def test_operator_readiness_probe_mismatch_blocks_surface_claims() -> None:
    arm = _observation("bm", "a" * 16, {"api.A": 1})
    control = _observation("control", "b" * 16, {})
    arm["ready_expression"] = {
        "supplied": True,
        "bytes": 47,
        "sha256_16": "a" * 16,
    }

    result = subtract_control(arm, control)

    assert result["clean_subtraction"] is True
    assert result["ready_probe_comparable"] is False
    assert result["surface_claim_ready"] is False
    assert result["control_ready_expression"] == {
        "supplied": False,
        "bytes": 0,
        "sha256_16": None,
    }
    with pytest.raises(ContractError, match="not claim-ready"):
        build_surface_baseline(result)
    second = dict(result, arm_label="bm-r2")
    second.pop("subtraction_receipt_sha256")
    comparison = compare_surfaces([result, second])["pairs"][0]
    assert comparison["surface_comparison_claim_ready"] is False


def _await_report(ended_on: str, *, waited_seconds: float = 1.0) -> dict:
    return {
        "ended_on": ended_on,
        "waited_seconds": waited_seconds,
        "polls": 1,
        "unresponsive_polls": 0,
        "page_ever_answered": True,
        "poll_timeout_seconds": 1.0,
        "slowest_poll": {
            "issued_at_seconds": 0.0,
            "duration_seconds": waited_seconds,
            "outcome": ended_on,
        },
        "signal_kind": "builtin",
    }


def test_successful_builtin_readiness_wait_is_claim_ready() -> None:
    arm = _observation("awaited", "aaaa", {"api.A": 1})
    control = _observation("control", "bbbb", {})
    arm.update(await_ready_seconds=5.0, await_report=_await_report("ready"))
    control.update(
        await_ready_seconds=5.0,
        await_report=_await_report("no_signal"),
    )

    result = subtract_control(arm, control)

    assert result["await_method_comparable"] is True
    assert result["arm_readiness_satisfied"] is True
    assert result["surface_claim_ready"] is True


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("waited_seconds", 86_401.0),
        ("polls", 1_000_001),
        ("unresponsive_polls", -1),
        ("failed_polls", -1),
    ],
)
def test_oversized_or_invalid_readiness_receipt_cannot_support_claim(
    field: str, value: float | int
) -> None:
    arm = _observation("awaited", "aaaa", {"api.A": 1})
    control = _observation("control", "bbbb", {})
    wait_limit = 86_400.0 if field == "waited_seconds" else 5.0
    arm.update(await_ready_seconds=wait_limit, await_report=_await_report("ready"))
    control.update(
        await_ready_seconds=wait_limit,
        await_report=_await_report("no_signal"),
    )
    arm["await_report"][field] = value

    result = subtract_control(arm, control)

    assert result["surface_claim_ready"] is False


@pytest.mark.parametrize(
    "mutation",
    [
        "issue_after_wait",
        "duration_over_wait",
        "oversized_duration",
        "negative_duration",
        "missing_issue",
        "malformed_slowest",
    ],
)
def test_impossible_slowest_readiness_poll_cannot_support_claim(mutation: str) -> None:
    arm = _observation("awaited", "aaaa", {"api.A": 1})
    control = _observation("control", "bbbb", {})
    arm.update(await_ready_seconds=5.0, await_report=_await_report("ready"))
    control.update(await_ready_seconds=5.0, await_report=_await_report("no_signal"))
    slowest = arm["await_report"]["slowest_poll"]
    if mutation == "issue_after_wait":
        slowest["issued_at_seconds"] = 2.0
    elif mutation == "duration_over_wait":
        slowest["duration_seconds"] = 2.0
    elif mutation == "oversized_duration":
        slowest["duration_seconds"] = 86_401.0
    elif mutation == "negative_duration":
        slowest["duration_seconds"] = -1.0
    elif mutation == "missing_issue":
        slowest.pop("issued_at_seconds")
    else:
        arm["await_report"]["slowest_poll"] = "ready"

    result = subtract_control(arm, control)

    assert result["arm_readiness_satisfied"] is False
    assert result["surface_claim_ready"] is False


def test_slowest_readiness_poll_allows_producer_rounding() -> None:
    arm = _observation("awaited", "aaaa", {"api.A": 1})
    control = _observation("control", "bbbb", {})
    arm.update(await_ready_seconds=5.0, await_report=_await_report("ready"))
    control.update(await_ready_seconds=5.0, await_report=_await_report("no_signal"))
    arm["await_report"]["slowest_poll"].update(
        issued_at_seconds=0.055, duration_seconds=0.995
    )

    result = subtract_control(arm, control)

    assert result["arm_readiness_satisfied"] is True
    assert result["surface_claim_ready"] is True


@pytest.mark.parametrize(
    "outcome", ["no_signal", "not_ready", "failed", "unresponsive"]
)
def test_one_poll_readiness_outcome_must_match_terminal(outcome: str) -> None:
    arm = _observation("awaited", "aaaa", {"api.A": 1})
    control = _observation("control", "bbbb", {})
    arm.update(await_ready_seconds=5.0, await_report=_await_report("ready"))
    control.update(await_ready_seconds=5.0, await_report=_await_report("no_signal"))
    arm["await_report"]["slowest_poll"]["outcome"] = outcome

    result = subtract_control(arm, control)

    assert result["arm_readiness_satisfied"] is False
    assert result["surface_claim_ready"] is False


def test_prior_slowest_not_ready_poll_allows_later_ready_terminal() -> None:
    arm = _observation("awaited", "aaaa", {"api.A": 1})
    control = _observation("control", "bbbb", {})
    arm.update(await_ready_seconds=5.0, await_report=_await_report("ready"))
    control.update(await_ready_seconds=5.0, await_report=_await_report("no_signal"))
    arm["await_report"]["polls"] = 2
    arm["await_report"]["waited_seconds"] = 2.0
    arm["await_report"]["slowest_poll"]["outcome"] = "not_ready"

    result = subtract_control(arm, control)

    assert result["arm_readiness_satisfied"] is True
    assert result["surface_claim_ready"] is True


@pytest.mark.parametrize("outcome", ["no_signal", "expression_true"])
def test_earlier_terminal_poll_cannot_precede_later_ready(outcome: str) -> None:
    arm = _observation("awaited", "aaaa", {"api.A": 1})
    control = _observation("control", "bbbb", {})
    arm.update(await_ready_seconds=5.0, await_report=_await_report("ready"))
    control.update(await_ready_seconds=5.0, await_report=_await_report("no_signal"))
    arm["await_report"]["polls"] = 2
    arm["await_report"]["waited_seconds"] = 2.0
    arm["await_report"]["slowest_poll"]["outcome"] = outcome

    result = subtract_control(arm, control)

    assert result["arm_readiness_satisfied"] is False
    assert result["surface_claim_ready"] is False


@pytest.mark.parametrize(
    "outcome", ["failed", "unresponsive"]
)
def test_slowest_failed_poll_requires_matching_failure_count(outcome: str) -> None:
    arm = _observation("awaited", "aaaa", {"api.A": 1})
    control = _observation("control", "bbbb", {})
    arm.update(await_ready_seconds=5.0, await_report=_await_report("ready"))
    control.update(await_ready_seconds=5.0, await_report=_await_report("no_signal"))
    arm["await_report"]["polls"] = 2
    arm["await_report"]["waited_seconds"] = 2.0
    arm["await_report"]["failed_polls"] = 0
    arm["await_report"]["slowest_poll"]["outcome"] = outcome

    result = subtract_control(arm, control)

    assert result["arm_readiness_satisfied"] is False
    assert result["surface_claim_ready"] is False


@pytest.mark.parametrize(
    "mutation",
    ["cap", "no_signal", "missing", "over_budget", "wrong_signal", "mismatched_cap"],
)
def test_unsatisfied_or_incoherent_readiness_wait_closes_claim(mutation: str) -> None:
    arm = _observation("awaited", "aaaa", {"api.A": 1})
    control = _observation("control", "bbbb", {})
    arm.update(await_ready_seconds=5.0, await_report=_await_report("ready"))
    control.update(
        await_ready_seconds=5.0,
        await_report=_await_report("no_signal"),
    )
    if mutation in {"cap", "no_signal"}:
        arm["await_report"]["ended_on"] = mutation
    elif mutation == "missing":
        arm["await_report"] = None
    elif mutation == "over_budget":
        arm["await_report"]["waited_seconds"] = 6.0
    elif mutation == "wrong_signal":
        arm["await_report"]["signal_kind"] = "operator_expression"
    else:
        control["await_ready_seconds"] = 4.0

    result = subtract_control(arm, control)

    assert result["surface_claim_ready"] is False
    if mutation in {"cap", "no_signal", "over_budget"}:
        assert result["await_method_comparable"] is True
        assert result["arm_readiness_satisfied"] is False
    else:
        assert result["await_method_comparable"] is False


def test_subtract_control_rejects_failed_arm() -> None:
    arm = {"schema": OBSERVATION_SCHEMA, "label": "x", "script_sha256_16": "a"}
    control = _observation("control", "bbbb", {})
    with pytest.raises(ContractError, match="no analysis"):
        subtract_control(arm, control)


def test_subtract_control_rejects_wrong_schema() -> None:
    arm = _observation("bm", "aaaa", {"api.A": 1})
    control = dict(_observation("control", "bbbb", {}), schema="something/1")
    with pytest.raises(ContractError, match="not a"):
        subtract_control(arm, control)


@pytest.mark.parametrize("document", [None, True, 1, 1.5, "arm", b"arm", [], ()])
def test_subtract_control_rejects_non_object_arms_cleanly(document) -> None:
    valid = _observation("valid", "aaaa", {})
    with pytest.raises(ContractError, match="observation must be an object"):
        subtract_control(document, valid)
    with pytest.raises(ContractError, match="observation must be an object"):
        subtract_control(valid, document)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("events_by_name", "private-secret"),
        ("events_by_name", {"api.A": "private-count"}),
        ("events_by_name", {"api.A": -1}),
        ("events_by_name", {"api.A\nprivate": 1}),
        ("context_coverage", ["frame"]),
        ("context_coverage", {"api.A": ["private-context"]}),
        ("context_coverage", {"api.A": ["frame", "frame"]}),
    ],
)
def test_subtract_control_rejects_malformed_analysis_surfaces(field, value) -> None:
    arm = _observation("arm", "aaaa", {"api.A": 1})
    control = _observation("control", "bbbb", {})
    arm["analysis"][field] = value

    with pytest.raises(ContractError, match="arm analysis"):
        subtract_control(arm, control)


# ------------------------------------------------------------------ comparison


def _subtraction(label: str, names: list[str]) -> dict:
    return {
        "schema": SUBTRACTION_SCHEMA,
        "generated_at": "2026-08-12T01:02:03Z",
        "non_claims": [
            "control subtraction attributes API names in a lab rehost only",
            "not an acceptance, bypass, evasion, or bot-score claim",
        ],
        "arm_label": label,
        "arm_script_sha256_16": "0" * 16,
        "clean_subtraction": True,
        "only_in_arm": {n: 1 for n in names},
    }


def test_compare_surfaces_detects_identical_arms() -> None:
    a = _subtraction("run1", ["api.A", "api.B"])
    b = _subtraction("run2", ["api.A", "api.B"])
    result = compare_surfaces([a, b])
    pair = result["pairs"][0]
    assert pair["shared"] == 2
    assert pair["only_a"] == [] and pair["only_b"] == []
    assert pair["jaccard"] == 1.0


def test_compare_surfaces_names_the_single_cross_roll_difference() -> None:
    new = _subtraction("pin", ["api.A", "api.B"])
    old = _subtraction("prev", ["api.A", "api.B", "api.Window.XMLHttpRequest"])
    pair = compare_surfaces([new, old])["pairs"][0]
    assert pair["only_b"] == ["api.Window.XMLHttpRequest"]
    assert pair["only_a"] == []
    assert pair["shared"] == 2


def test_compare_surfaces_rejects_claim_readiness_across_different_controls() -> None:
    first = dict(
        _subtraction("first", ["api.A"]),
        surface_claim_ready=True,
        control_script_sha256_16="c" * 16,
    )
    second = dict(
        _subtraction("second", ["api.A"]),
        surface_claim_ready=True,
        control_script_sha256_16="d" * 16,
    )

    pair = compare_surfaces([first, second])["pairs"][0]

    assert pair["same_control_script"] is False
    assert pair["surface_comparison_claim_ready"] is False


def test_compare_surfaces_rejects_partial_control_pin_population() -> None:
    current = dict(
        _subtraction("current", ["api.A"]),
        surface_claim_ready=True,
        control_script_sha256_16="c" * 16,
    )
    missing = dict(
        _subtraction("missing", ["api.A"]), surface_claim_ready=True
    )

    pair = compare_surfaces([current, missing])["pairs"][0]

    assert pair["same_control_script"] is False
    assert pair["surface_comparison_claim_ready"] is False


def test_compare_surfaces_keeps_fully_legacy_control_comparability_unknown() -> None:
    first = dict(_subtraction("first", ["api.A"]), surface_claim_ready=True)
    second = dict(_subtraction("second", ["api.A"]), surface_claim_ready=True)

    pair = compare_surfaces([first, second])["pairs"][0]

    assert pair["same_control_script"] is None
    assert pair["surface_comparison_claim_ready"] is True


def test_compare_surfaces_rejects_same_pin_different_full_source_digests() -> None:
    first = dict(
        _subtraction("first", ["api.A"]),
        surface_claim_ready=True,
        source_provenance={
            "status": "verified_digest",
            "source_url": "https://vendor.example/v1/api.js",
            "retrieved_at": "2026-08-12T00:00:00Z",
            "sha256": "0" * 16 + "a" * 48,
        },
    )
    second = dict(
        _subtraction("second", ["api.A"]),
        surface_claim_ready=True,
        source_provenance={
            "status": "verified_digest",
            "source_url": "https://vendor.example/v1/api.js",
            "retrieved_at": "2026-08-12T00:00:00Z",
            "sha256": "0" * 16 + "b" * 48,
        },
    )

    pair = compare_surfaces([first, second])["pairs"][0]

    assert pair["same_script"] is True
    assert pair["source_custody_comparable"] is False
    assert pair["surface_comparison_claim_ready"] is False


def test_compare_surfaces_accepts_two_verified_cross_roll_sources() -> None:
    first = dict(
        _subtraction("first", ["api.A"]),
        surface_claim_ready=True,
        arm_script_sha256_16="a" * 16,
        source_provenance={
            "status": "verified_digest",
            "source_url": "https://vendor.example/v1/api.js",
            "retrieved_at": "2026-08-12T00:00:00Z",
            "sha256": "a" * 64,
        },
    )
    second = dict(
        _subtraction("second", ["api.A"]),
        surface_claim_ready=True,
        arm_script_sha256_16="b" * 16,
        source_provenance={
            "status": "verified_digest",
            "source_url": "https://vendor.example/v2/api.js",
            "retrieved_at": "2026-08-12T01:00:00Z",
            "sha256": "b" * 64,
        },
    )

    pair = compare_surfaces([first, second])["pairs"][0]

    assert pair["same_script"] is False
    assert pair["source_custody_comparable"] is True
    assert pair["surface_comparison_claim_ready"] is True


def test_compare_surfaces_rejects_unverified_cross_roll_sources() -> None:
    first = dict(
        _subtraction("first", ["api.A"]),
        surface_claim_ready=True,
        arm_script_sha256_16="a" * 16,
    )
    second = dict(
        _subtraction("second", ["api.A"]),
        surface_claim_ready=True,
        arm_script_sha256_16="b" * 16,
    )

    pair = compare_surfaces([first, second])["pairs"][0]

    assert pair["same_script"] is False
    assert pair["source_custody_comparable"] is False
    assert pair["surface_comparison_claim_ready"] is False


def test_compare_surfaces_keeps_unverified_same_pin_source_custody_unknown() -> None:
    first = dict(_subtraction("first", ["api.A"]), surface_claim_ready=True)
    second = dict(_subtraction("second", ["api.A"]), surface_claim_ready=True)

    pair = compare_surfaces([first, second])["pairs"][0]

    assert pair["same_script"] is True
    assert pair["source_custody_comparable"] is None
    assert pair["surface_comparison_claim_ready"] is True


def test_compare_surfaces_rejects_partial_verified_source_custody() -> None:
    verified = dict(
        _subtraction("verified", ["api.A"]),
        surface_claim_ready=True,
        source_provenance={
            "status": "verified_digest",
            "source_url": "https://vendor.example/v1/api.js",
            "retrieved_at": "2026-08-12T00:00:00Z",
            "sha256": "0" * 16 + "a" * 48,
        },
    )
    missing = dict(
        _subtraction("missing", ["api.A"]), surface_claim_ready=True
    )

    pair = compare_surfaces([verified, missing])["pairs"][0]

    assert pair["source_custody_comparable"] is False
    assert pair["surface_comparison_claim_ready"] is False


def test_compare_surfaces_requires_complete_current_capture_receipts() -> None:
    current = _captured_surface("current")
    current["surface_claim_ready"] = True
    legacy = dict(
        _subtraction("legacy", ["api.A"]), surface_claim_ready=True
    )

    pair = compare_surfaces([current, legacy])["pairs"][0]

    assert pair["capture_receipts_comparable"] is False
    assert pair["surface_comparison_claim_ready"] is False


def test_compare_surfaces_rejects_verified_capture_custody_mismatch() -> None:
    verified = _captured_surface(
        "verified", arm_status="VERIFIED", control_status="UNVERIFIED"
    )
    unverified = _captured_surface(
        "unverified", arm_status="UNVERIFIED", control_status="UNVERIFIED"
    )
    verified["surface_claim_ready"] = True
    unverified["surface_claim_ready"] = True

    pair = compare_surfaces([verified, unverified])["pairs"][0]

    assert pair["a_capture_status"] == "VERIFIED"
    assert pair["b_capture_status"] == "UNVERIFIED"
    assert pair["capture_receipts_comparable"] is False
    assert pair["surface_comparison_claim_ready"] is False


def test_compare_surfaces_accepts_two_complete_nonauthorizing_capture_pairs() -> None:
    first = _captured_surface("first")
    second = _captured_surface(
        "second", arm_status="UNVERIFIED", control_status="error"
    )
    first["surface_claim_ready"] = True
    second["surface_claim_ready"] = True

    pair = compare_surfaces([first, second])["pairs"][0]

    assert pair["capture_receipts_comparable"] is True
    assert pair["surface_comparison_claim_ready"] is True


def test_compare_surfaces_keeps_legacy_capture_comparability_unknown() -> None:
    first = dict(_subtraction("first", ["api.A"]), surface_claim_ready=True)
    second = dict(_subtraction("second", ["api.A"]), surface_claim_ready=True)

    pair = compare_surfaces([first, second])["pairs"][0]

    assert pair["capture_receipts_comparable"] is None
    assert pair["surface_comparison_claim_ready"] is True


def test_compare_surfaces_treats_exact_unknown_placeholders_as_legacy() -> None:
    first = subtract_control(
        _observation("first", "a" * 16, {"api.A": 1}),
        _observation("first-control", "b" * 16, {}),
    )
    second = subtract_control(
        _observation("second", "c" * 16, {"api.A": 1}),
        _observation("second-control", "d" * 16, {}),
    )

    pair = compare_surfaces([first, second])["pairs"][0]

    assert pair["capture_receipts_comparable"] is None


def test_compare_surfaces_rejects_partial_capture_pairs() -> None:
    partial = dict(
        _subtraction("partial", ["api.A"]),
        surface_claim_ready=True,
        provenance={"status": "not_checked", "asserted_label": "partial"},
    )
    current = _captured_surface("current")
    current["surface_claim_ready"] = True

    with pytest.raises(ContractError, match="complete arm/control pair"):
        compare_surfaces([partial, current])


def test_compare_surfaces_names_method_mismatches() -> None:
    bare = dict(
        _subtraction("bare", ["api.A"]),
        arm_driver_supplied=False,
        surface_claim_ready=True,
    )
    driven = dict(
        _subtraction("driven", ["api.A"]),
        arm_driver_supplied=True,
        surface_claim_ready=True,
    )
    pair = compare_surfaces([bare, driven])["pairs"][0]
    assert pair["jaccard"] == 1.0
    assert pair["same_method"] is False
    assert pair["a_surface_claim_ready"] is True
    assert pair["b_surface_claim_ready"] is True
    assert pair["surface_comparison_claim_ready"] is False
    assert pair["method_mismatches"]["arm_driver_supplied"] == {
        "a": False,
        "b": True,
    }


def test_compare_surfaces_distinguishes_two_redacted_driver_sources() -> None:
    first = dict(
        _subtraction("first", ["api.A"]),
        arm_driver={"supplied": True, "bytes": 10, "sha256_16": "1" * 16},
        arm_driver_supplied=True,
    )
    second = dict(
        _subtraction("second", ["api.A"]),
        arm_driver={"supplied": True, "bytes": 10, "sha256_16": "2" * 16},
        arm_driver_supplied=True,
    )
    pair = compare_surfaces([first, second])["pairs"][0]
    assert pair["same_method"] is False
    assert pair["method_mismatches"]["arm_driver"]["a"]["sha256_16"] == "1" * 16
    assert pair["method_mismatches"]["arm_driver"]["b"]["sha256_16"] == "2" * 16


def test_compare_surfaces_distinguishes_second_stage_bytes() -> None:
    first = dict(
        _subtraction("first", ["api.A"]),
        arm_stage_routes=[
            {"path_prefix": "/tenant/mfc", "bytes": 100, "sha256_16": "1" * 16}
        ],
    )
    second = dict(
        _subtraction("second", ["api.A"]),
        arm_stage_routes=[
            {"path_prefix": "/tenant/mfc", "bytes": 101, "sha256_16": "2" * 16}
        ],
    )
    pair = compare_surfaces([first, second])["pairs"][0]
    assert pair["same_method"] is False
    assert "arm_stage_routes" in pair["method_mismatches"]


@pytest.mark.parametrize(
    ("field", "a", "b"),
    [
        ("arm_hook_target_names", ["Permissions.query"], ["Element.setAttribute"]),
        ("arm_inline_script", False, True),
        ("arm_reloads", 0, 1),
        ("arm_dwell_seconds", 1.0, 8.0),
        (
            "arm_rehost_contract",
            {
                "schema": "browser-core.product-script-rehost-contract/1",
                "sha256": "a" * 64,
                "page_sha256": "a" * 64,
                "hook_catalog_sha256": "a" * 64,
                "observer_js_sha256": "a" * 64,
                "input_probe_catalog_sha256": "a" * 64,
                "observer_sequence": "browser-core.product-script-observer-sequence/1",
                "resource_intent_contract": "cdp_dom_snapshot/1",
            },
            {
                "schema": "browser-core.product-script-rehost-contract/1",
                "sha256": "b" * 64,
                "page_sha256": "b" * 64,
                "hook_catalog_sha256": "b" * 64,
                "observer_js_sha256": "b" * 64,
                "input_probe_catalog_sha256": "b" * 64,
                "observer_sequence": "browser-core.product-script-observer-sequence/1",
                "resource_intent_contract": "cdp_dom_snapshot/1",
            },
        ),
        ("arm_trace_scope", "causal", "broad"),
        (
            "arm_trace_category_contract",
            "browser-core.trace-categories/1",
            "browser-core.trace-categories/2",
        ),
        ("arm_chromium_revision", "a" * 40, "b" * 40),
        (
            "arm_browser_build",
            {"executable_sha256_16": "1" * 16},
            {"executable_sha256_16": "2" * 16},
        ),
        ("arm_timeout_seconds", 10.0, 60.0),
        ("arm_resource_intent_capture", "off", "cdp_dom_snapshot/1"),
        (
            "arm_viewport",
            {"inner_width": 758, "inner_height": 426},
            {"inner_width": 1024, "inner_height": 768},
        ),
    ],
)
def test_compare_surfaces_rejects_other_execution_method_changes(field, a, b) -> None:
    first = dict(_subtraction("first", ["api.A"]), **{field: a})
    second = dict(_subtraction("second", ["api.A"]), **{field: b})
    pair = compare_surfaces([first, second])["pairs"][0]
    assert pair["same_method"] is False
    assert pair["method_mismatches"][field] == {"a": a, "b": b}


def test_declared_url_method_difference_is_bound_without_retaining_values() -> None:
    left = dict(
        _subtraction("left", ["api.A"]),
        arm_declared_script_url=(
            "https://vendor.example/private-tenant/api.js?sitekey=private-left"
        ),
    )
    right = dict(
        _subtraction("right", ["api.A"]),
        arm_declared_script_url=(
            "https://vendor.example/private-tenant/api.js?sitekey=private-right"
        ),
    )

    pair = compare_surfaces([left, right])["pairs"][0]
    serialized = json.dumps(pair)

    assert pair["same_method"] is False
    assert "arm_declared_script_url" in pair["method_mismatches"]
    assert "private-tenant" not in serialized
    assert "private-left" not in serialized
    assert "private-right" not in serialized
    assert "sitekey" in serialized


def test_browser_argument_method_difference_is_bound_without_retaining_values() -> None:
    left = dict(
        _subtraction("left", ["api.A"]),
        arm_extra_browser_args=["--custom-tenant=private-left"],
    )
    right = dict(
        _subtraction("right", ["api.A"]),
        arm_extra_browser_args=["--custom-tenant=private-right"],
    )

    pair = compare_surfaces([left, right])["pairs"][0]
    serialized = json.dumps(pair)

    assert pair["same_method"] is False
    mismatch = pair["method_mismatches"]["arm_extra_browser_args"]
    assert mismatch["a"][0]["name"] == "<custom>"
    assert mismatch["a"][0]["name_sha256_16"] == mismatch["b"][0]["name_sha256_16"]
    assert mismatch["a"][0]["sha256_16"] != mismatch["b"][0]["sha256_16"]
    assert "custom-tenant" not in serialized
    assert "private-left" not in serialized
    assert "private-right" not in serialized


def test_browser_argument_method_projection_hides_positional_values() -> None:
    left = dict(
        _subtraction("left", ["api.A"]),
        arm_extra_browser_args=[r"C:\\private\\tenant-profile"],
    )
    right = dict(_subtraction("right", ["api.A"]), arm_extra_browser_args=[])

    rendered = json.dumps(compare_surfaces([left, right]))

    assert "tenant-profile" not in rendered
    assert '"kind": "positional"' in rendered


def test_browser_argument_method_projection_names_documented_controls() -> None:
    left = dict(
        _subtraction("left", ["api.A"]),
        arm_extra_browser_args=["--disable-gpu", "--window-size=800,1"],
    )
    right = dict(_subtraction("right", ["api.A"]), arm_extra_browser_args=[])

    mismatch = compare_surfaces([left, right])["pairs"][0]["method_mismatches"]
    projected = mismatch["arm_extra_browser_args"]["a"]

    assert [item["name"] for item in projected] == ["--disable-gpu", "--window-size"]


def test_unknown_hook_target_is_bound_without_retaining_edited_value() -> None:
    left = dict(
        _subtraction("left", ["api.A"]),
        arm_hook_target_names=["private-tenant-hook"],
    )
    right = dict(_subtraction("right", ["api.A"]), arm_hook_target_names=[])

    rendered = json.dumps(compare_surfaces([left, right]))

    assert "private-tenant-hook" not in rendered
    assert "artifact_sha256_16" in rendered


def test_portable_surface_method_projection_is_idempotent_and_value_free() -> None:
    hostile = {
        "arm_trace_scope": "private-trace-value",
        "arm_browser_build": {"provenance": "private-build-value"},
        "arm_timeout_seconds": "private-timeout-value",
        "arm_viewport": {"inner_width": 800, "secret": "private-viewport-value"},
        "arm_dom_profile": "private-dom-value",
        "arm_rehost_contract": {"private": "private-contract-value"},
        "arm_hook_target_names": ["private-hook-value"],
        "arm_script_path": "/private-tenant/sample.js?token=private-value",
        "arm_declared_script_url": (
            "https://vendor.example/private-source/api.js?token=private-value"
        ),
        "arm_prelude": {"supplied": True, "bytes": "private-size-value"},
        "arm_extra_browser_args": ["--private-flag=private-flag-value"],
        "arm_stage_routes": [
            {"path_prefix": "/private-stage/next", "sha256_16": "f" * 16}
        ],
    }

    once = _surface_method(hostile)
    twice = _surface_method(once)
    rendered = json.dumps(twice)

    assert twice == once
    for secret in (
        "private-trace-value",
        "private-build-value",
        "private-timeout-value",
        "private-viewport-value",
        "private-dom-value",
        "private-contract-value",
        "private-hook-value",
        "private-tenant",
        "private-source",
        "private-size-value",
        "private-flag",
        "private-flag-value",
        "private-stage",
        "private-value",
    ):
        assert secret not in rendered


def test_portable_method_metadata_does_not_truthiness_coerce_supply_or_shapes() -> None:
    hostile = {
        "arm_prelude": {
            "supplied": "private-truthy-value",
            "bytes": 12,
            "sha256_16": "a" * 16,
        },
        "arm_driver": {
            "supplied": "private-truthy-value",
            "bytes": 12,
            "sha256_16": "b" * 16,
        },
        "arm_driver_supplied": "private-truthy-value",
        "arm_script_path": {
            "supplied": "private-truthy-value",
            "path_segment_lengths": [True],
        },
        "arm_declared_script_url": {
            "supplied": True,
            "shape": {
                "origin": "https://vendor.example",
                "path_segment_lengths": [4],
                "query_names": [],
                "fragment_present": "private-truthy-value",
            },
        },
    }

    method = _surface_method(hostile)

    assert method["arm_prelude"]["supplied"] is None
    assert method["arm_driver"]["supplied"] is None
    assert method["arm_script_path"]["supplied"] is None
    assert method["arm_declared_script_url"]["status"] == "unverifiable"
    assert product_observation._driver_supplied(hostile) is False
    invalid_path_shape = product_observation._script_path_method_value(
        {
            "supplied": True,
            "path_segment_lengths": [4],
            "fragment_present": "private-truthy-value",
        }
    )
    assert invalid_path_shape["status"] == "unverifiable"
    assert "private" not in json.dumps(method)
    assert "private" not in json.dumps(invalid_path_shape)


def test_attestation_timestamp_is_not_an_execution_method_axis() -> None:
    build = {
        "provenance": "attested-browser-core",
        "executable_sha256_16": "1" * 16,
        "runtime_bundle_sha256_16": "2" * 16,
    }
    arm_a = _observation("a", "a" * 16, {"api.A": 1})
    arm_b = _observation("b", "b" * 16, {"api.A": 1})
    arm_a["browser_build"] = {**build, "attestation_created_at": "2026-08-07T00:00:00Z"}
    arm_b["browser_build"] = {**build, "attestation_created_at": "2026-08-08T00:00:00Z"}
    first = subtract_control(arm_a, _observation("ca", "c" * 16, {}))
    second = subtract_control(arm_b, _observation("cb", "d" * 16, {}))
    pair = compare_surfaces([first, second])["pairs"][0]
    assert pair["same_method"] is True


def test_legacy_missing_method_defaults_equal_explicit_defaults() -> None:
    legacy = _subtraction("legacy", ["api.A"])
    current = dict(
        _subtraction("current", ["api.A"]),
        arm_hook_mode="off",
        arm_input_profile="none",
        arm_script_path=DEFAULT_SCRIPT_PATH,
        arm_prelude={"supplied": False, "bytes": 0, "sha256_16": None},
        arm_driver_supplied=False,
        arm_await_ready_seconds=0.0,
        arm_extra_browser_args=[],
    )
    pair = compare_surfaces([legacy, current])["pairs"][0]
    assert pair["same_method"] is True
    assert pair["method_mismatches"] == {}


def test_compare_surfaces_requires_two_arms() -> None:
    with pytest.raises(ContractError, match="at least two"):
        compare_surfaces([_subtraction("only", ["api.A"])])


@pytest.mark.parametrize("population", [None, True, 1, 1.5, "arms", b"arms", {}, ()])
def test_surface_population_apis_reject_non_list_inputs_cleanly(population) -> None:
    with pytest.raises(ContractError, match="inputs must be a list"):
        compare_surfaces(population)
    with pytest.raises(ContractError, match="inputs must be a list"):
        build_repeated_surface_baseline(population)


@pytest.mark.parametrize("entry", [None, True, 1, 1.5, "arm", b"arm", [], ()])
def test_surface_population_apis_reject_non_object_entries_cleanly(entry) -> None:
    valid = dict(
        _subtraction("valid", ["api.A"]),
        clean_subtraction=True,
        surface_claim_ready=True,
    )
    with pytest.raises(ContractError, match="entries must be objects"):
        compare_surfaces([valid, entry])
    with pytest.raises(ContractError, match="entries must be objects"):
        build_repeated_surface_baseline([valid, entry])


@pytest.mark.parametrize("document", [None, True, 1, 1.5, "arm", b"arm", [], ()])
def test_single_surface_apis_reject_non_object_inputs_cleanly(document) -> None:
    valid = dict(
        _subtraction("valid", ["api.A"]),
        clean_subtraction=True,
        surface_claim_ready=True,
    )
    baseline = build_surface_baseline(valid)
    with pytest.raises(ContractError, match="input must be an object"):
        build_surface_baseline(document)
    with pytest.raises(ContractError, match="inputs must be objects"):
        check_surface_drift(document, baseline)
    with pytest.raises(ContractError, match="inputs must be objects"):
        check_surface_drift(valid, document)


def test_compare_surfaces_rejects_raw_observations() -> None:
    with pytest.raises(ContractError, match="product-script-subtraction"):
        compare_surfaces([_observation("a", "x", {}), _observation("b", "y", {})])


def test_compare_surfaces_rejects_duplicate_arm_labels() -> None:
    first = _subtraction("same", ["api.A"])
    second = _subtraction("same", ["api.B"])

    with pytest.raises(ContractError, match="labels must be unique"):
        compare_surfaces([first, second])


@pytest.mark.parametrize("label", ["../escape", "with space", "", ["bad"]])
def test_compare_surfaces_rejects_unsafe_arm_labels(label) -> None:
    first = dict(_subtraction("first", ["api.A"]), arm_label=label)
    second = _subtraction("second", ["api.B"])

    with pytest.raises(ContractError, match="safe identifiers"):
        compare_surfaces([first, second])


@pytest.mark.parametrize(
    "malformed_surface",
    [
        None,
        "private-secret",
        123,
        True,
        [["nested"]],
        ["api.A", "api.A"],
        ["api.A\nprivate"],
        {7: 1},
    ],
)
def test_all_surface_consumers_reject_malformed_name_containers(
    malformed_surface,
) -> None:
    hostile = dict(
        _subtraction("hostile", ["api.A"]),
        only_in_arm=malformed_surface,
        clean_subtraction=True,
    )
    valid = dict(_subtraction("valid", ["api.A"]), clean_subtraction=True)
    baseline = build_surface_baseline(valid)

    with pytest.raises(ContractError, match="only_in_arm"):
        build_surface_baseline(hostile)
    with pytest.raises(ContractError, match="only_in_arm"):
        build_repeated_surface_baseline([valid, hostile])
    with pytest.raises(ContractError, match="only_in_arm"):
        compare_surfaces([valid, hostile])
    with pytest.raises(ContractError, match="only_in_arm"):
        check_surface_drift(hostile, baseline)


# ------------------------------------------------------------------ drift gate


def test_baseline_freezes_the_surface() -> None:
    base = build_surface_baseline(
        dict(_subtraction("pin", ["api.B", "api.A"]), clean_subtraction=True)
    )
    assert base["schema"] == BASELINE_SCHEMA
    assert base["api_names"] == ["api.A", "api.B"]  # sorted, so the digest is stable
    assert base["api_name_count"] == 2
    assert len(base["surface_sha256"]) == 64


@pytest.mark.parametrize("label", ["../private", "bad label", "x" * 129])
def test_single_baseline_rejects_unsafe_operator_labels(label: str) -> None:
    with pytest.raises(ContractError, match="baseline label"):
        build_surface_baseline(_clean("source", ["api.A"]), label=label)


def test_repeated_baseline_rejects_an_unsafe_operator_label() -> None:
    with pytest.raises(ContractError, match="baseline label"):
        build_repeated_surface_baseline(
            [_clean("first", ["api.A"]), _clean("second", ["api.A"])],
            label="private/path",
        )


def test_drift_rejects_a_rehashed_unsafe_baseline_label() -> None:
    subtraction = product_observation._seal_subtraction_document(
        _clean("source", ["api.A"])
    )
    baseline = build_surface_baseline(subtraction)
    baseline["label"] = "../private"
    canonical = {
        key: value
        for key, value in baseline.items()
        if key != "baseline_receipt_sha256"
    }
    baseline["baseline_receipt_sha256"] = hashlib.sha256(
        json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()

    with pytest.raises(ContractError, match="baseline label"):
        check_surface_drift(subtraction, baseline)


def test_single_baseline_rejects_an_unsafe_inherited_control_label() -> None:
    subtraction = dict(
        _clean("source", ["api.A"]), control_label="private/control path"
    )

    with pytest.raises(ContractError, match="baseline control label"):
        build_surface_baseline(subtraction)


def test_drift_rejects_a_rehashed_unsafe_baseline_control_label() -> None:
    subtraction = product_observation._seal_subtraction_document(
        dict(_clean("source", ["api.A"]), control_label="control")
    )
    baseline = build_surface_baseline(subtraction)
    baseline["control_label"] = "../private"
    canonical = {
        key: value
        for key, value in baseline.items()
        if key != "baseline_receipt_sha256"
    }
    baseline["baseline_receipt_sha256"] = hashlib.sha256(
        json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()

    with pytest.raises(ContractError, match="baseline control label"):
        check_surface_drift(subtraction, baseline)


def test_drift_rejects_a_rehashed_noncanonical_baseline_timestamp() -> None:
    subtraction = product_observation._seal_subtraction_document(
        _clean("source", ["api.A"])
    )
    baseline = build_surface_baseline(subtraction)
    baseline["generated_at"] = "2026-08-12 01:02:03"
    canonical = {
        key: value
        for key, value in baseline.items()
        if key != "baseline_receipt_sha256"
    }
    baseline["baseline_receipt_sha256"] = hashlib.sha256(
        json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()

    with pytest.raises(ContractError, match="baseline generated_at"):
        check_surface_drift(subtraction, baseline)


def test_drift_rejects_a_rehashed_unknown_baseline_field() -> None:
    subtraction = product_observation._seal_subtraction_document(
        _clean("source", ["api.A"])
    )
    baseline = build_surface_baseline(subtraction)
    baseline["private_payload"] = "private-value"
    canonical = {
        key: value
        for key, value in baseline.items()
        if key != "baseline_receipt_sha256"
    }
    baseline["baseline_receipt_sha256"] = hashlib.sha256(
        json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()

    with pytest.raises(ContractError, match="baseline fields"):
        check_surface_drift(subtraction, baseline)


def test_drift_rejects_rehashed_noncanonical_baseline_name_order() -> None:
    subtraction = product_observation._seal_subtraction_document(
        _clean("source", ["api.A", "api.B"])
    )
    baseline = build_surface_baseline(subtraction)
    baseline["api_names"] = list(reversed(baseline["api_names"]))
    canonical = {
        key: value
        for key, value in baseline.items()
        if key != "baseline_receipt_sha256"
    }
    baseline["baseline_receipt_sha256"] = hashlib.sha256(
        json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()

    with pytest.raises(ContractError, match="baseline api_names.*canonical"):
        check_surface_drift(subtraction, baseline)


def test_drift_rejects_rehashed_noncanonical_volatile_name_order() -> None:
    baseline = build_repeated_surface_baseline(
        [
            _clean("first", ["api.A", "api.X"]),
            _clean("second", ["api.A", "api.Y"]),
        ]
    )
    baseline["volatile_api_names"] = list(
        reversed(baseline["volatile_api_names"])
    )
    canonical = {
        key: value
        for key, value in baseline.items()
        if key != "baseline_receipt_sha256"
    }
    baseline["baseline_receipt_sha256"] = hashlib.sha256(
        json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()

    with pytest.raises(ContractError, match="baseline volatile API names.*canonical"):
        check_surface_drift(_clean("later", ["api.A"]), baseline)


def test_drift_rejects_rehashed_unknown_baseline_non_claim() -> None:
    subtraction = product_observation._seal_subtraction_document(
        _clean("source", ["api.A"])
    )
    baseline = build_surface_baseline(subtraction)
    baseline["non_claims"].append("private tenant note")
    canonical = {
        key: value
        for key, value in baseline.items()
        if key != "baseline_receipt_sha256"
    }
    baseline["baseline_receipt_sha256"] = hashlib.sha256(
        json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()

    with pytest.raises(ContractError, match="baseline non-claims"):
        check_surface_drift(subtraction, baseline)


def test_drift_rejects_rehashed_noncanonical_baseline_method() -> None:
    subtraction = product_observation._seal_subtraction_document(
        _clean("source", ["api.A"])
    )
    baseline = build_surface_baseline(subtraction)
    baseline["method"]["private_payload"] = "private-value"
    canonical = {
        key: value
        for key, value in baseline.items()
        if key != "baseline_receipt_sha256"
    }
    baseline["baseline_receipt_sha256"] = hashlib.sha256(
        json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()

    with pytest.raises(ContractError, match="baseline method"):
        check_surface_drift(subtraction, baseline)


def test_drift_rejects_rehashed_unknown_request_baseline_field() -> None:
    baseline = build_repeated_surface_baseline(
        [_request_subtraction(4811), _request_subtraction(4849)]
    )
    baseline["request_activity_baseline"]["private_payload"] = "private-value"
    canonical = {
        key: value
        for key, value in baseline.items()
        if key != "baseline_receipt_sha256"
    }
    baseline["baseline_receipt_sha256"] = hashlib.sha256(
        json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()

    with pytest.raises(ContractError, match="baseline request activity baseline"):
        check_surface_drift(
            _sealed_current_request_subtraction(4811),
            baseline,
        )


def test_drift_rejects_rehashed_noncanonical_request_baseline_row_order() -> None:
    arms = [_request_subtraction(4811), _request_subtraction(4849)]
    for arm in arms:
        arm["request_activity"]["only_in_arm"].append(
            {
                "method": "GET",
                "served": "stage",
                "path_segment_lengths": [],
                "path_segments_truncated": False,
                "query_names": [],
                "query_names_truncated": False,
                "count": 1,
                "body_bytes_total": 0,
                "body_bytes_min": 0,
                "body_bytes_max": 0,
            }
        )
    baseline = build_repeated_surface_baseline(arms)
    request_floor = baseline["request_activity_baseline"]
    assert len(request_floor["rows"]) == 2
    request_floor["rows"] = list(reversed(request_floor["rows"]))
    request_floor.pop("receipt_sha256")
    request_floor["receipt_sha256"] = hashlib.sha256(
        json.dumps(request_floor, sort_keys=True, separators=(",", ":")).encode(
            "utf-8"
        )
    ).hexdigest()
    baseline_canonical = {
        key: value
        for key, value in baseline.items()
        if key != "baseline_receipt_sha256"
    }
    baseline["baseline_receipt_sha256"] = hashlib.sha256(
        json.dumps(
            baseline_canonical, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
    ).hexdigest()

    with pytest.raises(ContractError, match="baseline request activity baseline"):
        check_surface_drift(
            product_observation._seal_subtraction_document(arms[0]), baseline
        )


def test_drift_rejects_rehashed_noncanonical_request_baseline_shape() -> None:
    baseline = build_repeated_surface_baseline(
        [_request_subtraction(4811), _request_subtraction(4849)]
    )
    request_floor = baseline["request_activity_baseline"]
    request_floor["rows"][0]["shape"]["query_names"] = ["tenant", "tenant"]
    request_floor.pop("receipt_sha256")
    request_floor["receipt_sha256"] = hashlib.sha256(
        json.dumps(request_floor, sort_keys=True, separators=(",", ":")).encode(
            "utf-8"
        )
    ).hexdigest()
    baseline_canonical = {
        key: value
        for key, value in baseline.items()
        if key != "baseline_receipt_sha256"
    }
    baseline["baseline_receipt_sha256"] = hashlib.sha256(
        json.dumps(
            baseline_canonical, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
    ).hexdigest()

    with pytest.raises(ContractError, match="baseline request activity baseline"):
        check_surface_drift(
            _sealed_current_request_subtraction(4811),
            baseline,
        )


def test_request_baseline_body_identity_is_explicitly_self_receipt_only() -> None:
    digest = "a" * 16
    baseline = build_repeated_surface_baseline(
        [
            _request_subtraction(4811, body_digest=digest),
            _request_subtraction(4811, body_digest=digest),
        ]
    )
    request_floor = baseline["request_activity_baseline"]
    row = request_floor["rows"][0]
    assert row["body_digest_multiset_varies"] is False
    assert row["body_digest_multiset_custody"] == "self_receipt_only"
    row["body_digest_multiset_sha256"] = hashlib.sha256(
        b'{"bbbbbbbbbbbbbbbb":1}'
    ).hexdigest()
    request_floor.pop("receipt_sha256")
    request_floor["receipt_sha256"] = hashlib.sha256(
        json.dumps(request_floor, sort_keys=True, separators=(",", ":")).encode(
            "utf-8"
        )
    ).hexdigest()
    baseline_canonical = {
        key: value
        for key, value in baseline.items()
        if key != "baseline_receipt_sha256"
    }
    baseline["baseline_receipt_sha256"] = hashlib.sha256(
        json.dumps(
            baseline_canonical, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
    ).hexdigest()

    result = check_surface_drift(
        _sealed_current_request_subtraction(4811, body_digest="b" * 16),
        baseline,
    )

    assert result["request_activity_drift"]["passed"] is True
    assert "self-receipt custody" in request_floor["non_claim"]


def test_baseline_digest_is_order_independent() -> None:
    a = build_surface_baseline(
        dict(_subtraction("x", ["api.A", "api.B"]), clean_subtraction=True)
    )
    b = build_surface_baseline(
        dict(_subtraction("x", ["api.B", "api.A"]), clean_subtraction=True)
    )
    assert a["surface_sha256"] == b["surface_sha256"]


def test_current_baseline_binds_its_complete_public_receipt() -> None:
    baseline = build_surface_baseline(
        dict(_subtraction("current", ["api.A"]), clean_subtraction=True)
    )

    assert re.fullmatch(r"[0-9a-f]{64}", baseline["baseline_receipt_sha256"])


def test_baseline_write_requires_a_complete_receipt(tmp_path: Path) -> None:
    baseline = build_surface_baseline(_clean("current", ["api.A"]))
    baseline.pop("baseline_receipt_sha256")

    with pytest.raises(ContractError, match="baseline write requires"):
        write_observation(tmp_path / "baseline.json", baseline)


def test_single_baseline_binds_its_exact_source_subtraction_receipt() -> None:
    subtraction = _current_subtraction("source", "source-control")

    baseline = build_surface_baseline(subtraction)

    assert baseline["source_subtraction_receipt_population"] == [
        subtraction["subtraction_receipt_sha256"]
    ]
    assert baseline["source_subtraction_lineage"] == [
        {
            "arm_label": "source",
            "subtraction_receipt_sha256": subtraction[
                "subtraction_receipt_sha256"
            ],
        }
    ]
    assert baseline["source_subtraction_receipts_complete"] is True


def test_single_baseline_names_legacy_source_lineage_as_incomplete() -> None:
    baseline = build_surface_baseline(_clean("legacy", ["api.A"]))

    assert baseline["source_subtraction_receipt_population"] == []
    assert baseline["source_subtraction_lineage"] == []
    assert baseline["source_subtraction_receipts_complete"] is False


def test_repeated_baseline_binds_a_canonical_source_receipt_population() -> None:
    first = product_observation._seal_subtraction_document(
        _clean("first", ["api.A"])
    )
    second = product_observation._seal_subtraction_document(
        _clean("second", ["api.A"])
    )

    baseline = build_repeated_surface_baseline([second, first])

    assert baseline["source_subtraction_receipt_population"] == sorted(
        [
            first["subtraction_receipt_sha256"],
            second["subtraction_receipt_sha256"],
        ]
    )
    assert baseline["source_subtraction_lineage"] == [
        {
            "arm_label": "first",
            "subtraction_receipt_sha256": first[
                "subtraction_receipt_sha256"
            ],
        },
        {
            "arm_label": "second",
            "subtraction_receipt_sha256": second[
                "subtraction_receipt_sha256"
            ],
        },
    ]
    assert baseline["source_subtraction_receipts_complete"] is True


def test_repeated_baseline_refuses_mixed_source_receipt_generations() -> None:
    current = product_observation._seal_subtraction_document(
        _clean("current", ["api.A"])
    )

    with pytest.raises(ContractError, match="same subtraction receipt generation"):
        build_repeated_surface_baseline([current, _clean("legacy", ["api.A"])])


def test_repeated_baseline_refuses_duplicate_current_source_labels() -> None:
    first = product_observation._seal_subtraction_document(
        _clean("duplicate", ["api.A"])
    )
    second = product_observation._seal_subtraction_document(
        dict(
            _clean("duplicate", ["api.A"]),
            generated_at="2026-08-12T01:02:04Z",
        )
    )

    with pytest.raises(ContractError, match="unique current arm labels"):
        build_repeated_surface_baseline([first, second])


def test_baseline_rejects_a_rehashed_source_lineage_mapping_edit() -> None:
    subtraction = product_observation._seal_subtraction_document(
        _clean("source", ["api.A"])
    )
    baseline = build_surface_baseline(subtraction)
    baseline["source_subtraction_lineage"][0][
        "subtraction_receipt_sha256"
    ] = "f" * 64
    canonical = {
        key: value
        for key, value in baseline.items()
        if key != "baseline_receipt_sha256"
    }
    baseline["baseline_receipt_sha256"] = hashlib.sha256(
        json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()

    with pytest.raises(ContractError, match="source subtraction lineage"):
        check_surface_drift(subtraction, baseline)


def test_baseline_normalizes_hostile_source_population_types() -> None:
    first = product_observation._seal_subtraction_document(
        _clean("first", ["api.A"])
    )
    second = product_observation._seal_subtraction_document(
        _clean("second", ["api.A"])
    )
    baseline = build_repeated_surface_baseline([first, second])
    baseline["source_subtraction_receipt_population"] = [
        {},
        first["subtraction_receipt_sha256"],
    ]
    canonical = {
        key: value
        for key, value in baseline.items()
        if key != "baseline_receipt_sha256"
    }
    baseline["baseline_receipt_sha256"] = hashlib.sha256(
        json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()

    with pytest.raises(ContractError, match="source subtraction lineage"):
        check_surface_drift(first, baseline)


def test_drift_rejects_a_coherent_baseline_method_edit() -> None:
    baseline = build_surface_baseline(
        dict(
            _subtraction("current", ["api.A"]),
            clean_subtraction=True,
            arm_driver_supplied=False,
        )
    )
    baseline["method"]["arm_driver_supplied"] = True

    with pytest.raises(ContractError, match="baseline receipt"):
        check_surface_drift(
            dict(
                _subtraction("observed", ["api.A"]),
                clean_subtraction=True,
                arm_driver_supplied=True,
            ),
            baseline,
        )


def test_baseline_refuses_a_dirty_subtraction() -> None:
    """An untrustworthy surface must not become the thing everything is judged against."""
    with pytest.raises(ContractError, match="dirty subtraction"):
        build_surface_baseline(
            dict(_subtraction("x", ["api.A"]), clean_subtraction=False)
        )


@pytest.mark.parametrize("clean_gate", [False, "true", None, "missing"])
def test_explicit_ready_flag_cannot_override_an_unclean_subtraction(clean_gate) -> None:
    clean = dict(
        _subtraction("clean", ["api.A"]),
        clean_subtraction=True,
        surface_claim_ready=True,
    )
    unclean = dict(
        _subtraction("unclean", ["api.A"]),
        clean_subtraction=clean_gate,
        surface_claim_ready=True,
    )
    if clean_gate == "missing":
        unclean.pop("clean_subtraction")
    with pytest.raises(ContractError, match="dirty subtraction"):
        build_surface_baseline(unclean)
    pair = compare_surfaces([clean, unclean])["pairs"][0]
    assert pair["a_surface_claim_ready"] is True
    assert pair["b_surface_claim_ready"] is False
    assert pair["surface_comparison_claim_ready"] is False


@pytest.mark.parametrize("malformed_gate", ["true", 1, [True]])
def test_claim_gates_require_the_literal_boolean_true(malformed_gate) -> None:
    """Malformed JSON must not authorize baselines, comparisons, or drift passes."""
    valid = dict(
        _subtraction("valid", ["api.A"]),
        clean_subtraction=True,
        surface_claim_ready=True,
    )
    hostile = dict(
        _subtraction("hostile", ["api.A"]),
        clean_subtraction=True,
        surface_claim_ready=malformed_gate,
    )

    with pytest.raises(ContractError, match="dirty subtraction"):
        build_surface_baseline(hostile)
    with pytest.raises(ContractError, match="dirty subtraction"):
        build_repeated_surface_baseline([valid, hostile])

    baseline = build_surface_baseline(valid)
    drift = check_surface_drift(hostile, baseline)
    assert drift["surface_claim_ready"] is False
    assert drift["passed"] is False

    pair = compare_surfaces([valid, hostile])["pairs"][0]
    assert pair["a_surface_claim_ready"] is True
    assert pair["b_surface_claim_ready"] is False
    assert pair["surface_comparison_claim_ready"] is False


@pytest.mark.parametrize("malformed_gate", ["true", 1, [True]])
def test_legacy_clean_gate_also_requires_the_literal_boolean_true(
    malformed_gate,
) -> None:
    hostile = dict(_subtraction("hostile", ["api.A"]), clean_subtraction=malformed_gate)

    with pytest.raises(ContractError, match="dirty subtraction"):
        build_surface_baseline(hostile)


def test_baseline_refuses_an_empty_surface() -> None:
    with pytest.raises(ContractError, match="empty surface"):
        build_surface_baseline(dict(_subtraction("x", []), clean_subtraction=True))


def test_baseline_rejects_a_malformed_script_pin() -> None:
    document = dict(
        _subtraction("bad-pin", ["api.A"]),
        clean_subtraction=True,
        arm_script_sha256_16="not-a-pin",
    )

    with pytest.raises(ContractError, match="script pin"):
        build_surface_baseline(document)


def test_repeated_baseline_rejects_mixed_script_pins() -> None:
    first = dict(
        _subtraction("first", ["api.A"]),
        clean_subtraction=True,
        arm_script_sha256_16="a" * 16,
    )
    second = dict(
        _subtraction("second", ["api.A", "api.Flaky"]),
        clean_subtraction=True,
        arm_script_sha256_16="b" * 16,
    )

    with pytest.raises(ContractError, match="same script pin"):
        build_repeated_surface_baseline([first, second])


def test_repeated_baseline_rejects_mixed_control_script_pins() -> None:
    first = dict(
        _subtraction("first", ["api.A"]),
        clean_subtraction=True,
        control_script_sha256_16="c" * 16,
    )
    second = dict(
        _subtraction("second", ["api.A", "api.Flaky"]),
        clean_subtraction=True,
        control_script_sha256_16="d" * 16,
    )

    with pytest.raises(ContractError, match="same control-script pin"):
        build_repeated_surface_baseline([first, second])


def test_current_baseline_retains_the_control_script_pin() -> None:
    document = dict(
        _subtraction("current", ["api.A"]),
        clean_subtraction=True,
        control_script_sha256_16="c" * 16,
    )

    baseline = build_surface_baseline(document)

    assert baseline["control_script_sha256_16"] == "c" * 16


def test_current_baseline_retains_matching_public_source_custody() -> None:
    document = dict(
        _subtraction("current", ["api.A"]),
        clean_subtraction=True,
        source_provenance={
            "status": "verified_digest",
            "source_url": "https://vendor.example/v1/api.js",
            "retrieved_at": "2026-08-12T00:00:00Z",
            "sha256": "0" * 16 + "a" * 48,
        },
    )

    baseline = build_surface_baseline(document)

    assert baseline["source_provenance"]["status"] == "verified_digest"
    assert baseline["source_provenance"]["sha256"] == "0" * 16 + "a" * 48


def test_baseline_rejects_public_source_for_different_script_bytes() -> None:
    document = dict(
        _subtraction("current", ["api.A"]),
        clean_subtraction=True,
        source_provenance={
            "status": "verified_digest",
            "source_url": "https://vendor.example/v1/api.js",
            "retrieved_at": "2026-08-12T00:00:00Z",
            "sha256": "f" * 64,
        },
    )

    with pytest.raises(ContractError, match="source provenance"):
        build_surface_baseline(document)


def test_repeated_baseline_rejects_partial_source_provenance() -> None:
    first = dict(
        _subtraction("first", ["api.A"]),
        clean_subtraction=True,
        source_provenance={
            "status": "verified_digest",
            "source_url": "https://vendor.example/v1/api.js",
            "retrieved_at": "2026-08-12T00:00:00Z",
            "sha256": "0" * 16 + "a" * 48,
        },
    )
    second = dict(_subtraction("second", ["api.A"]), clean_subtraction=True)

    with pytest.raises(ContractError, match="complete source provenance"):
        build_repeated_surface_baseline([first, second])


def test_current_baseline_retains_complete_capture_provenance() -> None:
    document = dict(
        _subtraction("current", ["api.A"]),
        clean_subtraction=True,
        control_label="current-control",
        provenance={"status": "not_checked", "asserted_label": "current"},
        control_provenance={
            "status": "not_checked",
            "asserted_label": "current-control",
        },
    )

    baseline = build_surface_baseline(document, label="display-name")

    assert baseline["source_arm_label"] == "current"
    assert baseline["capture_provenance"]["asserted_label"] == "current"
    assert (
        baseline["control_capture_provenance"]["asserted_label"]
        == "current-control"
    )


def test_baseline_rejects_capture_provenance_for_a_different_arm_label() -> None:
    document = dict(
        _subtraction("current", ["api.A"]),
        clean_subtraction=True,
        control_label="current-control",
        provenance={"status": "not_checked", "asserted_label": "different"},
        control_provenance={
            "status": "not_checked",
            "asserted_label": "current-control",
        },
    )

    with pytest.raises(ContractError, match="capture provenance"):
        build_surface_baseline(document)


def test_repeated_baseline_retains_per_arm_capture_provenance() -> None:
    def current(label: str) -> dict:
        return dict(
            _subtraction(label, ["api.A"]),
            clean_subtraction=True,
            control_label=f"{label}-control",
            provenance={"status": "not_checked", "asserted_label": label},
            control_provenance={
                "status": "not_checked",
                "asserted_label": f"{label}-control",
            },
        )

    baseline = build_repeated_surface_baseline([current("run-1"), current("run-2")])

    population = baseline["capture_provenance_population"]
    assert [row["arm_label"] for row in population] == ["run-1", "run-2"]
    assert population[1]["provenance"]["asserted_label"] == "run-2"
    assert (
        population[1]["control_provenance"]["asserted_label"]
        == "run-2-control"
    )


def test_repeated_baseline_rejects_partial_capture_provenance() -> None:
    current = dict(
        _subtraction("current", ["api.A"]),
        clean_subtraction=True,
        control_label="current-control",
        provenance={"status": "not_checked", "asserted_label": "current"},
        control_provenance={
            "status": "not_checked",
            "asserted_label": "current-control",
        },
    )
    legacy = dict(_subtraction("legacy", ["api.A"]), clean_subtraction=True)

    with pytest.raises(ContractError, match="complete capture provenance"):
        build_repeated_surface_baseline([current, legacy])


def test_drift_rejects_an_edited_baseline_capture_label() -> None:
    document = dict(
        _subtraction("current", ["api.A"]),
        clean_subtraction=True,
        control_label="current-control",
        provenance={"status": "not_checked", "asserted_label": "current"},
        control_provenance={
            "status": "not_checked",
            "asserted_label": "current-control",
        },
    )
    baseline = build_surface_baseline(document)
    baseline["capture_provenance"]["asserted_label"] = "edited"

    with pytest.raises(ContractError, match="capture provenance"):
        check_surface_drift(document, baseline)


def _captured_surface(
    label: str, *, arm_status: str = "not_checked", control_status: str = "not_checked"
) -> dict:
    return dict(
        _subtraction(label, ["api.A"]),
        clean_subtraction=True,
        control_label=f"{label}-control",
        provenance={
            "status": arm_status,
            "asserted_label": label,
            "recorded_hosts": ["capture.example"] if arm_status == "VERIFIED" else [],
        },
        control_provenance={
            "status": control_status,
            "asserted_label": f"{label}-control",
            "recorded_hosts": ["capture.example"] if control_status == "VERIFIED" else [],
        },
    )


def test_drift_rejects_missing_capture_receipts_from_a_current_baseline() -> None:
    baseline = build_surface_baseline(_captured_surface("baseline"))
    observed = _clean("observed", ["api.A"])

    result = check_surface_drift(observed, baseline)

    assert result["capture_receipts_comparable"] is False
    assert result["passed"] is False


def test_drift_rejects_downgraded_verified_capture_custody() -> None:
    baseline = build_surface_baseline(
        _captured_surface(
            "baseline", arm_status="VERIFIED", control_status="UNVERIFIED"
        )
    )
    observed = _captured_surface(
        "observed", arm_status="not_checked", control_status="UNVERIFIED"
    )

    result = check_surface_drift(observed, baseline)

    assert result["baseline_capture_status"] == "VERIFIED"
    assert result["observed_capture_status"] == "not_checked"
    assert result["capture_receipts_comparable"] is False
    assert result["passed"] is False


def test_drift_accepts_complete_capture_receipts_with_new_run_labels() -> None:
    baseline = build_surface_baseline(_captured_surface("baseline"))
    observed = product_observation._seal_subtraction_document(
        _captured_surface("observed")
    )

    result = check_surface_drift(observed, baseline)

    assert result["baseline_capture_status"] == "not_checked"
    assert result["observed_capture_status"] == "not_checked"
    assert result["capture_receipts_comparable"] is True
    assert result["passed"] is True


def test_drift_keeps_capture_comparability_unknown_for_a_legacy_baseline() -> None:
    baseline = build_surface_baseline(_clean("baseline", ["api.A"]))
    baseline.pop("baseline_receipt_sha256")
    observed = _captured_surface("observed")

    result = check_surface_drift(observed, baseline)

    assert result["capture_receipts_comparable"] is None
    assert result["passed"] is True


def test_drift_uses_complete_repeated_capture_populations() -> None:
    baseline = build_repeated_surface_baseline(
        [_captured_surface("run-1"), _captured_surface("run-2")]
    )

    result = check_surface_drift(
        product_observation._seal_subtraction_document(
            _captured_surface("observed")
        ),
        baseline,
    )

    assert result["baseline_capture_status"] == "not_checked"
    assert result["capture_receipts_comparable"] is True
    assert result["passed"] is True


def test_drift_preserves_fully_verified_repeated_capture_strength() -> None:
    baseline = build_repeated_surface_baseline(
        [
            _captured_surface(
                "run-1", arm_status="VERIFIED", control_status="UNVERIFIED"
            ),
            _captured_surface(
                "run-2", arm_status="VERIFIED", control_status="UNVERIFIED"
            ),
        ]
    )
    observed = _captured_surface(
        "observed", arm_status="UNVERIFIED", control_status="UNVERIFIED"
    )

    result = check_surface_drift(observed, baseline)

    assert result["baseline_capture_status"] == "VERIFIED"
    assert result["capture_receipts_comparable"] is False
    assert result["passed"] is False


def _clean(label: str, names: list[str]) -> dict:
    return dict(_subtraction(label, names), clean_subtraction=True)


def test_identical_surface_passes() -> None:
    base = build_surface_baseline(_clean("pin", ["api.A", "api.B"]))
    result = check_surface_drift(
        product_observation._seal_subtraction_document(
            _clean("rerun", ["api.B", "api.A"])
        ),
        base,
    )
    assert result["passed"] is True
    assert result["drift"] == 0
    assert result["added"] == [] and result["removed"] == []


def test_drift_decision_has_a_roundtrippable_complete_receipt(tmp_path: Path) -> None:
    result = check_surface_drift(
        _clean("observed", ["api.A"]),
        build_surface_baseline(_clean("baseline", ["api.A"])),
    )
    path = tmp_path / "drift.json"

    write_observation(path, result)
    loaded = product_observation.load_observation(path)

    assert re.fullmatch(r"[0-9a-f]{64}", result["decision_receipt_sha256"])
    assert loaded == result


def test_comparison_decision_has_a_roundtrippable_complete_receipt(
    tmp_path: Path,
) -> None:
    result = compare_surfaces(
        [_subtraction("first", ["api.A"]), _subtraction("second", ["api.A"])]
    )
    path = tmp_path / "comparison.json"

    write_observation(path, result)
    loaded = product_observation.load_observation(path)

    assert re.fullmatch(r"[0-9a-f]{64}", result["decision_receipt_sha256"])
    assert loaded == result


@pytest.mark.parametrize("kind", ["drift", "comparison"])
def test_decision_write_rejects_an_edited_complete_receipt(
    tmp_path: Path, kind: str
) -> None:
    if kind == "drift":
        document = check_surface_drift(
            product_observation._seal_subtraction_document(
                _clean("observed", ["api.A"])
            ),
            build_surface_baseline(_clean("baseline", ["api.A"])),
        )
        document["passed"] = not document["passed"]
    else:
        document = compare_surfaces(
            [_subtraction("first", ["api.A"]), _subtraction("second", ["api.A"])]
        )
        document["pairs"][0]["shared"] = 99

    with pytest.raises(ContractError, match="decision receipt"):
        write_observation(tmp_path / f"{kind}.json", document)


@pytest.mark.parametrize("kind", ["drift", "comparison"])
def test_decision_write_requires_a_complete_receipt(tmp_path: Path, kind: str) -> None:
    if kind == "drift":
        document = check_surface_drift(
            product_observation._seal_subtraction_document(
                _clean("observed", ["api.A"])
            ),
            build_surface_baseline(
                product_observation._seal_subtraction_document(
                    _clean("baseline", ["api.A"])
                )
            ),
        )
    else:
        document = compare_surfaces(
            [_subtraction("first", ["api.A"]), _subtraction("second", ["api.A"])]
        )
    document.pop("decision_receipt_sha256")

    with pytest.raises(ContractError, match="decision write requires"):
        write_observation(tmp_path / f"{kind}.json", document)


def _current_subtraction(arm_label: str, control_label: str) -> dict:
    return subtract_control(
        _current_method_observation(arm_label, "a" * 16, {"api.A": 1}),
        _current_method_observation(control_label, "b" * 16, {}),
    )


@pytest.mark.parametrize(
    ("field", "private_field"),
    [
        ("arm_browser_build", "private_executable_path"),
        ("arm_viewport", "private_window_label"),
    ],
)
def test_subtraction_write_requires_canonical_arm_method_metadata(
    tmp_path: Path, field: str, private_field: str
) -> None:
    document = _current_subtraction("arm", "control")
    document[field][private_field] = "operator-private-value"
    product_observation._seal_subtraction_document(document)

    with pytest.raises(ContractError, match="subtraction arm method metadata"):
        write_observation(tmp_path / "subtraction.json", document)


@pytest.mark.parametrize(
    "field", ["arm_rehost_contract", "control_rehost_contract"]
)
def test_subtraction_write_requires_canonical_rehost_contract(
    tmp_path: Path, field: str
) -> None:
    document = _current_subtraction("arm", "control")
    contract = product_observation.build_rehost_contract()
    document["arm_rehost_contract"] = dict(contract)
    document["control_rehost_contract"] = dict(contract)
    document[field]["private_workspace"] = "operator-private-value"
    product_observation._seal_subtraction_document(document)

    with pytest.raises(ContractError, match="subtraction rehost contract"):
        write_observation(tmp_path / "subtraction.json", document)


@pytest.mark.parametrize("field", ["arm_prelude", "control_prelude"])
def test_subtraction_write_requires_canonical_prelude_metadata(
    tmp_path: Path, field: str
) -> None:
    document = _current_subtraction("arm", "control")
    document[field]["private_source"] = "operator-private-value"
    product_observation._seal_subtraction_document(document)

    with pytest.raises(ContractError, match="subtraction prelude metadata"):
        write_observation(tmp_path / "subtraction.json", document)


@pytest.mark.parametrize("field", ["arm_stage_routes", "control_stage_routes"])
def test_subtraction_write_requires_canonical_stage_route_metadata(
    tmp_path: Path, field: str
) -> None:
    document = _current_subtraction("arm", "control")
    route = [
        {
            "path_prefix": product_observation._script_path_method_value("/stage.js"),
            "sha256_16": "a" * 16,
        }
    ]
    document["arm_stage_routes"] = [dict(route[0])]
    document["control_stage_routes"] = [dict(route[0])]
    document[field][0]["private_source_path"] = "operator-private-value"
    product_observation._seal_subtraction_document(document)

    with pytest.raises(ContractError, match="subtraction stage route metadata"):
        write_observation(tmp_path / "subtraction.json", document)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("arm_trace_scope", "operator-private-scope"),
        ("arm_trace_category_contract", "operator-private-contract"),
        ("arm_chromium_revision", "A" * 40),
    ],
)
def test_subtraction_write_requires_canonical_arm_trace_method(
    tmp_path: Path, field: str, value: str
) -> None:
    document = _current_subtraction("arm", "control")
    document[field] = value
    product_observation._seal_subtraction_document(document)

    with pytest.raises(ContractError, match="subtraction arm trace method"):
        write_observation(tmp_path / "subtraction.json", document)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("arm_headed", 1),
        ("arm_timeout_seconds", "60"),
        ("arm_dwell_seconds", "8"),
        ("arm_dom_profile", "operator-private-profile"),
        ("arm_hook_mode", "operator-private-mode"),
        ("arm_input_profile", "operator-private-input"),
        ("arm_inline_script", 1),
        ("arm_reloads", 1.5),
        ("arm_resource_intent_capture", "operator-private-capture"),
    ],
)
def test_subtraction_write_requires_canonical_arm_execution_control(
    tmp_path: Path, field: str, value
) -> None:
    document = _current_subtraction("arm", "control")
    document[field] = value
    product_observation._seal_subtraction_document(document)

    with pytest.raises(ContractError, match="subtraction arm execution control"):
        write_observation(tmp_path / "subtraction.json", document)


def test_subtraction_projects_private_browser_arguments_at_creation() -> None:
    arm = _current_method_observation("arm", "a" * 16, {"api.A": 1})
    control = _current_method_observation("control", "b" * 16, {})
    arm["extra_browser_args"] = ["--private-tenant=operator-private-value"]

    result = subtract_control(arm, control)
    rendered = json.dumps(result)

    assert result["arm_extra_browser_args"][0]["name"] == "<custom>"
    assert "operator-private-value" not in rendered
    assert "private-tenant" not in rendered


def test_subtraction_rejects_and_omits_extra_viewport_fields() -> None:
    arm = _current_method_observation("arm", "a" * 16, {"api.A": 1})
    control = _current_method_observation("control", "b" * 16, {})
    arm["viewport"]["private_capture"] = "operator-private-value"

    result = subtract_control(arm, control)

    assert result["arm_control_method_comparable"] is False
    assert result["surface_claim_ready"] is False
    assert result["arm_viewport"] == {
        key: value for key, value in arm["viewport"].items() if key != "private_capture"
    }
    assert "operator-private-value" not in json.dumps(result)


@pytest.mark.parametrize(
    ("side", "source_field", "result_field"),
    [
        ("arm", "headed", "arm_headed"),
        ("arm", "trace_scope", "arm_trace_scope"),
        ("arm", "trace_category_contract", "arm_trace_category_contract"),
        ("arm", "chromium_revision", "arm_chromium_revision"),
        ("arm", "timeout_seconds", "arm_timeout_seconds"),
        ("arm", "dwell_seconds", "arm_dwell_seconds"),
        ("arm", "dom_profile", "arm_dom_profile"),
        ("arm", "hook_mode", "arm_hook_mode"),
        ("arm", "inline_script", "arm_inline_script"),
        ("arm", "reloads", "arm_reloads"),
        ("arm", "resource_intent_capture", "arm_resource_intent_capture"),
        ("arm", "input_profile", "arm_input_profile"),
        ("arm", "await_ready_seconds", "arm_await_ready_seconds"),
        ("control", "headed", "control_headed"),
        ("control", "hook_mode", "control_hook_mode"),
        ("control", "input_profile", "control_input_profile"),
        ("control", "dom_profile", "control_dom_profile"),
    ],
)
def test_subtraction_projects_invalid_scalar_method_values(
    side: str, source_field: str, result_field: str
) -> None:
    arm = _current_method_observation("arm", "a" * 16, {"api.A": 1})
    control = _current_method_observation("control", "b" * 16, {})
    document = arm if side == "arm" else control
    document[source_field] = "operator-private-value"

    result = subtract_control(arm, control)

    assert result_field in result
    assert "operator-private-value" not in json.dumps(result)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("arm_extra_browser_args", ["--private-tenant=operator-private-value"]),
        ("arm_hook_target_names", ["operator-private-hook"]),
    ],
)
def test_subtraction_write_requires_canonical_arm_list_method(
    tmp_path: Path, field: str, value
) -> None:
    document = _current_subtraction("arm", "control")
    document[field] = value
    product_observation._seal_subtraction_document(document)

    with pytest.raises(ContractError, match="subtraction arm list method"):
        write_observation(tmp_path / "subtraction.json", document)


def test_subtraction_projects_private_script_locations_at_creation() -> None:
    arm = _current_method_observation("arm", "a" * 16, {"api.A": 1})
    control = _current_method_observation("control", "b" * 16, {})
    private_path = "/private-tenant/sample.js?token=operator-private-value"
    private_url = "https://vendor.example/private-tenant/api.js?token=private"
    for document in (arm, control):
        document["script_path"] = private_path
        document["declared_script_url"] = private_url

    result = subtract_control(arm, control)
    rendered = json.dumps(result)

    assert result["arm_script_path"]["supplied"] is True
    assert result["arm_declared_script_url"]["supplied"] is True
    assert "private-tenant" not in rendered
    assert "operator-private-value" not in rendered


@pytest.mark.parametrize(
    "field",
    [
        "arm_script_path",
        "control_script_path",
        "arm_declared_script_url",
        "control_declared_script_url",
    ],
)
def test_subtraction_write_requires_canonical_script_location(
    tmp_path: Path, field: str
) -> None:
    document = _current_subtraction("arm", "control")
    document[field] = "/private-tenant/sample.js?token=operator-private-value"
    product_observation._seal_subtraction_document(document)

    with pytest.raises(ContractError, match="subtraction script location"):
        write_observation(tmp_path / "subtraction.json", document)


def test_subtraction_write_revalidates_argument_capture(tmp_path: Path) -> None:
    document = _current_subtraction("arm", "control")
    document["arm_argument_capture"] = {
        "schema": "browser-core.product-script-arguments/1",
        "status": "ok",
        "private_argument": "operator-private-value",
    }
    product_observation._seal_subtraction_document(document)

    with pytest.raises(ContractError, match="subtraction argument capture"):
        write_observation(tmp_path / "subtraction.json", document)


def test_subtraction_rejects_invalid_argument_capture_at_creation() -> None:
    arm = _current_method_observation("arm", "a" * 16, {"api.A": 1})
    control = _current_method_observation("control", "b" * 16, {})
    arm["argument_capture"] = {
        "schema": "browser-core.product-script-arguments/1",
        "status": "ok",
        "private_argument": "operator-private-value",
    }

    with pytest.raises(ContractError, match="arm argument capture") as failure:
        subtract_control(arm, control)

    assert "operator-private-value" not in str(failure.value)


@pytest.mark.parametrize(
    "field",
    ["provenance", "control_provenance", "source_provenance", "control_source_provenance"],
)
def test_subtraction_write_requires_canonical_provenance_receipt(
    tmp_path: Path, field: str
) -> None:
    document = _current_subtraction("arm", "control")
    document[field]["private_workspace"] = "operator-private-value"
    product_observation._seal_subtraction_document(document)

    with pytest.raises(ContractError, match="subtraction provenance"):
        write_observation(tmp_path / "subtraction.json", document)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("control_headed", 1),
        ("control_hook_mode", "operator-private-mode"),
        ("control_input_profile", "operator-private-input"),
        ("control_dom_profile", "operator-private-profile"),
    ],
)
def test_subtraction_write_requires_canonical_control_execution_method(
    tmp_path: Path, field: str, value
) -> None:
    document = _current_subtraction("arm", "control")
    document[field] = value
    product_observation._seal_subtraction_document(document)

    with pytest.raises(ContractError, match="subtraction control execution method"):
        write_observation(tmp_path / "subtraction.json", document)


def test_subtraction_write_rejects_sensitive_fields_recursively(tmp_path: Path) -> None:
    document = _current_subtraction("arm", "control")
    document["operator_metadata"] = {
        "access_token": "operator-private-value",
    }
    product_observation._seal_subtraction_document(document)

    with pytest.raises(ContractError, match="sensitive field"):
        write_observation(tmp_path / "subtraction.json", document)


@pytest.mark.parametrize("kind", ["observation", "comparison"])
def test_shared_write_rejects_sensitive_fields_recursively(
    tmp_path: Path, kind: str
) -> None:
    if kind == "observation":
        document = _current_method_observation("arm", "a" * 16, {"api.A": 1})
        document["operator_metadata"] = {
            "refresh_token": "operator-private-value"
        }
        product_observation._seal_observation_document(document)
    else:
        document = compare_surfaces(
            [
                _current_subtraction("first", "first-control"),
                _current_subtraction("second", "second-control"),
            ]
        )
        document["operator_metadata"] = {
            "refresh_token": "operator-private-value"
        }
        product_observation._seal_decision_document(document)

    with pytest.raises(ContractError, match="sensitive field"):
        write_observation(tmp_path / f"{kind}.json", document)


@pytest.mark.parametrize("field", ["api_key", "client_secret", "session_token"])
def test_shared_write_rejects_additional_credential_key_families(
    tmp_path: Path, field: str
) -> None:
    document = _current_method_observation("arm", "a" * 16, {"api.A": 1})
    document["operator_metadata"] = {field: "operator-private-value"}
    product_observation._seal_observation_document(document)

    with pytest.raises(ContractError, match="sensitive field"):
        write_observation(tmp_path / "observation.json", document)


@pytest.mark.parametrize(
    "field", ["vendor_api_key", "oauth_client_secret", "browser_session_token"]
)
def test_shared_write_rejects_namespaced_credential_keys(
    tmp_path: Path, field: str
) -> None:
    document = _current_method_observation("arm", "a" * 16, {"api.A": 1})
    document["operator_metadata"] = {field: "operator-private-value"}
    product_observation._seal_observation_document(document)

    with pytest.raises(ContractError, match="sensitive field"):
        write_observation(tmp_path / "observation.json", document)


@pytest.mark.parametrize("field", ["APIKey", "clientSecret", "sessionToken"])
def test_shared_write_rejects_camel_case_credential_keys(
    tmp_path: Path, field: str
) -> None:
    document = _current_method_observation("arm", "a" * 16, {"api.A": 1})
    document["operator_metadata"] = {field: "operator-private-value"}
    product_observation._seal_observation_document(document)

    with pytest.raises(ContractError, match="sensitive field"):
        write_observation(tmp_path / "observation.json", document)


@pytest.mark.parametrize("field", ["api.key", "client secret", "session/token"])
def test_shared_write_rejects_separator_variant_credential_keys(
    tmp_path: Path, field: str
) -> None:
    document = _current_method_observation("arm", "a" * 16, {"api.A": 1})
    document["operator_metadata"] = {field: "operator-private-value"}
    product_observation._seal_observation_document(document)

    with pytest.raises(ContractError, match="sensitive field"):
        write_observation(tmp_path / "observation.json", document)


def test_shared_write_rejects_sensitive_fields_inside_a_tuple(tmp_path: Path) -> None:
    document = _current_method_observation("arm", "a" * 16, {"api.A": 1})
    document["operator_metadata"] = (
        {"api_key": "operator-private-value"},
    )
    product_observation._seal_observation_document(document)

    with pytest.raises(ContractError, match="sensitive field"):
        write_observation(tmp_path / "observation.json", document)


def test_shared_write_bounds_privacy_scan_nesting(tmp_path: Path) -> None:
    document = _current_method_observation("arm", "a" * 16, {"api.A": 1})
    nested: list = []
    cursor = nested
    for _ in range(70):
        child: list = []
        cursor.append(child)
        cursor = child
    document["operator_metadata"] = nested
    product_observation._seal_observation_document(document)

    with pytest.raises(ContractError, match="nesting limit"):
        write_observation(tmp_path / "observation.json", document)


def test_shared_write_bounds_privacy_scan_field_names(tmp_path: Path) -> None:
    document = _current_method_observation("arm", "a" * 16, {"api.A": 1})
    document["operator_metadata"] = {"x" * 1_025: "value"}
    product_observation._seal_observation_document(document)

    with pytest.raises(ContractError, match="field name is too long"):
        write_observation(tmp_path / "observation.json", document)


def test_shared_write_rejects_non_string_mapping_keys(tmp_path: Path) -> None:
    document = _current_method_observation("arm", "a" * 16, {"api.A": 1})
    document["operator_metadata"] = {1: "first", "1": "second"}

    with pytest.raises(ContractError, match="field name must be text"):
        write_observation(tmp_path / "observation.json", document)


def test_shared_write_rejects_control_characters_in_mapping_keys(
    tmp_path: Path,
) -> None:
    document = _current_method_observation("arm", "a" * 16, {"api.A": 1})
    document["operator\nmetadata"] = "value"
    product_observation._seal_observation_document(document)

    with pytest.raises(ContractError, match="field name contains control characters"):
        write_observation(tmp_path / "observation.json", document)


@pytest.mark.parametrize("field", ["", "   "])
def test_shared_write_rejects_blank_mapping_keys(
    tmp_path: Path, field: str
) -> None:
    document = _current_method_observation("arm", "a" * 16, {"api.A": 1})
    document[field] = "value"
    product_observation._seal_observation_document(document)

    with pytest.raises(ContractError, match="field name is blank"):
        write_observation(tmp_path / "observation.json", document)


def test_shared_write_omits_sensitive_field_paths_from_diagnostic(
    tmp_path: Path,
) -> None:
    document = _current_method_observation("arm", "a" * 16, {"api.A": 1})
    document["operator.metadata"] = {"api.key": "operator-private-value"}
    product_observation._seal_observation_document(document)

    with pytest.raises(ContractError) as failure:
        write_observation(tmp_path / "observation.json", document)

    assert "sensitive field" in str(failure.value)
    assert "operator.metadata" not in str(failure.value)
    assert "api.key" not in str(failure.value)
    assert "operator-private-value" not in str(failure.value)


def test_drift_decision_binds_exact_input_artifact_receipts() -> None:
    baseline = build_surface_baseline(_current_subtraction("baseline", "control"))
    observed = _current_subtraction("observed", "control-rerun")

    result = check_surface_drift(observed, baseline)

    assert result["baseline_receipt_sha256"] == baseline[
        "baseline_receipt_sha256"
    ]
    assert result["observed_subtraction_receipt_sha256"] == observed[
        "subtraction_receipt_sha256"
    ]
    assert result["input_artifact_receipts_complete"] is True


def test_pairwise_decision_binds_both_input_artifact_receipts() -> None:
    first = _current_subtraction("first", "first-control")
    second = _current_subtraction("second", "second-control")

    pair = compare_surfaces([first, second])["pairs"][0]

    assert pair["a_subtraction_receipt_sha256"] == first[
        "subtraction_receipt_sha256"
    ]
    assert pair["b_subtraction_receipt_sha256"] == second[
        "subtraction_receipt_sha256"
    ]
    assert pair["input_artifact_receipts_complete"] is True


def test_drift_file_reconciles_parent_receipts_with_lineage_flags(
    tmp_path: Path,
) -> None:
    baseline = build_surface_baseline(_current_subtraction("baseline", "control"))
    observed = _current_subtraction("observed", "observed-control")
    result = check_surface_drift(observed, baseline)
    result["observed_subtraction_receipt_sha256"] = None
    product_observation._seal_decision_document(result)

    with pytest.raises(ContractError, match="decision input artifact lineage"):
        write_observation(tmp_path / "drift.json", result)


def test_drift_file_rejects_a_rehashed_mixed_lineage_pass(tmp_path: Path) -> None:
    baseline = build_surface_baseline(_current_subtraction("baseline", "control"))
    observed = _current_subtraction("observed", "observed-control")
    result = check_surface_drift(observed, baseline)
    result["observed_subtraction_receipt_sha256"] = None
    result["input_artifact_receipts_complete"] = False
    result["input_artifact_receipts_comparable"] = False
    result["passed"] = True
    product_observation._seal_decision_document(result)

    with pytest.raises(ContractError, match="decision input artifact lineage"):
        write_observation(tmp_path / "drift.json", result)


def test_comparison_file_rejects_a_rehashed_mixed_lineage_claim(
    tmp_path: Path,
) -> None:
    first = _current_subtraction("first", "first-control")
    second = _current_subtraction("second", "second-control")
    result = compare_surfaces([first, second])
    pair = result["pairs"][0]
    pair["b_subtraction_receipt_sha256"] = None
    pair["input_artifact_receipts_complete"] = False
    pair["input_artifact_receipts_comparable"] = False
    pair["surface_comparison_claim_ready"] = True
    product_observation._seal_decision_document(result)

    with pytest.raises(ContractError, match="decision input artifact lineage"):
        write_observation(tmp_path / "comparison.json", result)


def test_drift_file_rejects_rehashed_difference_arithmetic(tmp_path: Path) -> None:
    baseline_input = product_observation._seal_subtraction_document(
        _clean("baseline", ["api.A"])
    )
    observed = product_observation._seal_subtraction_document(
        _clean("observed", ["api.A", "api.B"])
    )
    result = check_surface_drift(observed, build_surface_baseline(baseline_input))
    result["drift"] = 0
    product_observation._seal_decision_document(result)

    with pytest.raises(ContractError, match="drift decision arithmetic"):
        write_observation(tmp_path / "drift.json", result)


def test_drift_file_rejects_a_rehashed_impossible_pass(tmp_path: Path) -> None:
    baseline_input = product_observation._seal_subtraction_document(
        _clean("baseline", ["api.A"])
    )
    observed = product_observation._seal_subtraction_document(
        _clean("observed", ["api.A", "api.B"])
    )
    result = check_surface_drift(observed, build_surface_baseline(baseline_input))
    result["passed"] = True
    product_observation._seal_decision_document(result)

    with pytest.raises(ContractError, match="drift decision verdict"):
        write_observation(tmp_path / "drift.json", result)


def test_drift_file_reconciles_legacy_request_status(tmp_path: Path) -> None:
    baseline_input = product_observation._seal_subtraction_document(
        _clean("baseline", ["api.A"])
    )
    observed = product_observation._seal_subtraction_document(
        _clean("observed", ["api.A"])
    )
    result = check_surface_drift(observed, build_surface_baseline(baseline_input))
    result["request_activity_drift"]["passed"] = True
    product_observation._seal_decision_document(result)

    with pytest.raises(ContractError, match="drift request decision"):
        write_observation(tmp_path / "drift.json", result)


def test_drift_file_reconciles_request_outlier_verdict(tmp_path: Path) -> None:
    baseline = build_repeated_surface_baseline(
        [_request_subtraction(4811), _request_subtraction(4849)]
    )
    observed = _sealed_current_request_subtraction(6000)
    result = check_surface_drift(observed, baseline)
    result["request_activity_drift"]["passed"] = True
    result["passed"] = True
    product_observation._seal_decision_document(result)

    with pytest.raises(ContractError, match="drift request decision"):
        write_observation(tmp_path / "drift.json", result)


def test_drift_file_rejects_a_rehashed_private_request_non_claim(
    tmp_path: Path,
) -> None:
    baseline = build_repeated_surface_baseline(
        [_request_subtraction(4811), _request_subtraction(4849)]
    )
    observed = _sealed_current_request_subtraction(4811)
    result = check_surface_drift(observed, baseline)
    result["request_activity_drift"]["non_claim"] = "private tenant note"
    product_observation._seal_decision_document(result)

    with pytest.raises(ContractError, match="drift request decision non-claim"):
        write_observation(tmp_path / "drift.json", result)


def test_drift_file_rejects_rehashed_noncanonical_request_shape(
    tmp_path: Path,
) -> None:
    baseline = build_repeated_surface_baseline(
        [_request_subtraction(4811), _request_subtraction(4849)]
    )
    observed = _sealed_current_request_subtraction(4811, include=False)
    result = check_surface_drift(observed, baseline)
    result["request_activity_drift"]["removed_shapes"] = [
        {"private": "private-value"}
    ]
    result["request_activity_drift"]["removed_shape_count"] = 1
    product_observation._seal_decision_document(result)

    with pytest.raises(ContractError, match="drift request decision shape evidence"):
        write_observation(tmp_path / "drift.json", result)


def test_drift_file_rejects_request_evidence_when_population_is_not_comparable(
    tmp_path: Path,
) -> None:
    baseline = build_repeated_surface_baseline(
        [_request_subtraction(4811), _request_subtraction(4849)]
    )
    observed = _sealed_current_request_subtraction(4811)
    result = check_surface_drift(observed, baseline)
    request = result["request_activity_drift"]
    request["observed_rows_truncated"] = True
    request["comparable"] = False
    request["removed_shapes"] = [baseline["request_activity_baseline"]["rows"][0]["shape"]]
    request["removed_shape_count"] = 1
    request["passed"] = False
    result["passed"] = False
    product_observation._seal_decision_document(result)

    with pytest.raises(ContractError, match="drift request decision shape evidence"):
        write_observation(tmp_path / "drift.json", result)


def test_drift_file_rejects_a_rehashed_unsafe_decision_label(tmp_path: Path) -> None:
    baseline_input = product_observation._seal_subtraction_document(
        _clean("baseline", ["api.A"])
    )
    observed = product_observation._seal_subtraction_document(
        _clean("observed", ["api.A"])
    )
    result = check_surface_drift(observed, build_surface_baseline(baseline_input))
    result["observed_label"] = "private/path"
    product_observation._seal_decision_document(result)

    with pytest.raises(ContractError, match="drift decision label"):
        write_observation(tmp_path / "drift.json", result)


def test_drift_file_reconciles_script_pin_identity(tmp_path: Path) -> None:
    baseline_input = product_observation._seal_subtraction_document(
        _clean("baseline", ["api.A"])
    )
    observed = product_observation._seal_subtraction_document(
        _clean("observed", ["api.A"])
    )
    result = check_surface_drift(observed, build_surface_baseline(baseline_input))
    result["same_script"] = False
    product_observation._seal_decision_document(result)

    with pytest.raises(ContractError, match="drift decision script identity"):
        write_observation(tmp_path / "drift.json", result)


def test_drift_file_reconciles_full_source_custody(tmp_path: Path) -> None:
    baseline_input = product_observation._seal_subtraction_document(
        _clean("baseline", ["api.A"])
    )
    observed = product_observation._seal_subtraction_document(
        _clean("observed", ["api.A"])
    )
    result = check_surface_drift(observed, build_surface_baseline(baseline_input))
    result["source_custody_comparable"] = True
    product_observation._seal_decision_document(result)

    with pytest.raises(ContractError, match="drift decision source custody"):
        write_observation(tmp_path / "drift.json", result)


def test_drift_file_reconciles_control_script_identity(tmp_path: Path) -> None:
    baseline = build_surface_baseline(_current_subtraction("baseline", "control"))
    observed = _current_subtraction("observed", "observed-control")
    result = check_surface_drift(observed, baseline)
    result["same_control_script"] = False
    product_observation._seal_decision_document(result)

    with pytest.raises(ContractError, match="drift decision control identity"):
        write_observation(tmp_path / "drift.json", result)


def test_drift_file_reconciles_capture_custody_statuses(tmp_path: Path) -> None:
    baseline = build_surface_baseline(_captured_surface("baseline"))
    observed = product_observation._seal_subtraction_document(
        _captured_surface("observed")
    )
    result = check_surface_drift(observed, baseline)
    result["capture_receipts_comparable"] = False
    product_observation._seal_decision_document(result)

    with pytest.raises(ContractError, match="drift decision capture custody"):
        write_observation(tmp_path / "drift.json", result)


def test_comparison_file_rejects_rehashed_overlap_arithmetic(tmp_path: Path) -> None:
    first = _current_subtraction("first", "first-control")
    second = _current_subtraction("second", "second-control")
    result = compare_surfaces([first, second])
    result["pairs"][0]["shared"] = 2
    product_observation._seal_decision_document(result)

    with pytest.raises(ContractError, match="comparison decision arithmetic"):
        write_observation(tmp_path / "comparison.json", result)


def test_comparison_file_rejects_rehashed_counts_beyond_surface_bound(
    tmp_path: Path,
) -> None:
    first = _current_subtraction("first", "first-control")
    second = _current_subtraction("second", "second-control")
    result = compare_surfaces([first, second])
    pair = result["pairs"][0]
    pair["shared"] = 1_000_001
    pair["a_count"] = 1_000_001
    pair["b_count"] = 1_000_001
    pair["jaccard"] = 1.0
    product_observation._seal_decision_document(result)

    with pytest.raises(ContractError, match="comparison decision arithmetic"):
        write_observation(tmp_path / "comparison.json", result)


def test_comparison_file_rejects_a_rehashed_impossible_claim(tmp_path: Path) -> None:
    first = _current_subtraction("first", "first-control")
    second = _current_subtraction("second", "second-control")
    result = compare_surfaces([first, second])
    pair = result["pairs"][0]
    pair["same_method"] = False
    pair["method_mismatches"] = {"arm_headed": {"a": True, "b": False}}
    pair["surface_comparison_claim_ready"] = True
    product_observation._seal_decision_document(result)

    with pytest.raises(ContractError, match="comparison decision verdict"):
        write_observation(tmp_path / "comparison.json", result)


def test_drift_file_rejects_rehashed_noncanonical_method_evidence(
    tmp_path: Path,
) -> None:
    baseline_input = product_observation._seal_subtraction_document(
        _clean("baseline", ["api.A"])
    )
    observed = product_observation._seal_subtraction_document(
        _clean("observed", ["api.A"])
    )
    result = check_surface_drift(observed, build_surface_baseline(baseline_input))
    result["same_method"] = False
    result["method_mismatches"] = {
        "private/method": {"baseline": "private-value", "observed": "other"}
    }
    result["passed"] = False
    product_observation._seal_decision_document(result)

    with pytest.raises(ContractError, match="drift decision method evidence"):
        write_observation(tmp_path / "drift.json", result)


def test_drift_file_rejects_rehashed_unknown_tolerance_provenance(
    tmp_path: Path,
) -> None:
    baseline = build_repeated_surface_baseline(
        [_sub({"api.A"}), _sub({"api.A"})]
    )
    result = check_surface_drift(
        product_observation._seal_subtraction_document(_sub({"api.A"})),
        baseline,
        tolerance=None,
    )
    result["tolerance_source"] = "private-policy"
    product_observation._seal_decision_document(result)

    with pytest.raises(ContractError, match="drift decision tolerance provenance"):
        write_observation(tmp_path / "drift.json", result)


def test_drift_file_reconciles_measured_tolerance_with_noise_floor(
    tmp_path: Path,
) -> None:
    baseline = build_repeated_surface_baseline(
        [_sub({"api.A"}), _sub({"api.A"})]
    )
    result = check_surface_drift(
        product_observation._seal_subtraction_document(_sub({"api.A"})),
        baseline,
        tolerance=None,
    )
    result["baseline_noise_floor"] = result["tolerance"] + 1
    product_observation._seal_decision_document(result)

    with pytest.raises(ContractError, match="drift decision tolerance provenance"):
        write_observation(tmp_path / "drift.json", result)


def test_drift_file_rejects_rehashed_counts_beyond_surface_bound(
    tmp_path: Path,
) -> None:
    baseline_input = product_observation._seal_subtraction_document(
        _clean("baseline", ["api.A"])
    )
    observed = product_observation._seal_subtraction_document(
        _clean("observed", ["api.A"])
    )
    result = check_surface_drift(observed, build_surface_baseline(baseline_input))
    result["baseline_count"] = 1_000_001
    result["observed_count"] = 1_000_001
    product_observation._seal_decision_document(result)

    with pytest.raises(ContractError, match="drift decision arithmetic"):
        write_observation(tmp_path / "drift.json", result)


def test_comparison_file_rejects_rehashed_noncanonical_method_evidence(
    tmp_path: Path,
) -> None:
    first = _current_subtraction("first", "first-control")
    second = _current_subtraction("second", "second-control")
    result = compare_surfaces([first, second])
    pair = result["pairs"][0]
    pair["same_method"] = False
    pair["method_mismatches"] = {
        "arm_headed": {"a": "private-value", "b": "other"}
    }
    pair["surface_comparison_claim_ready"] = False
    product_observation._seal_decision_document(result)

    with pytest.raises(ContractError, match="comparison decision method evidence"):
        write_observation(tmp_path / "comparison.json", result)


def test_drift_file_rejects_rehashed_unknown_envelope_field(tmp_path: Path) -> None:
    baseline_input = product_observation._seal_subtraction_document(
        _clean("baseline", ["api.A"])
    )
    observed = product_observation._seal_subtraction_document(
        _clean("observed", ["api.A"])
    )
    result = check_surface_drift(observed, build_surface_baseline(baseline_input))
    result["private_payload"] = "private-value"
    product_observation._seal_decision_document(result)

    with pytest.raises(ContractError, match="drift decision fields"):
        write_observation(tmp_path / "drift.json", result)


def test_comparison_file_rejects_rehashed_unknown_pair_field(tmp_path: Path) -> None:
    result = compare_surfaces(
        [
            _current_subtraction("first", "first-control"),
            _current_subtraction("second", "second-control"),
        ]
    )
    result["pairs"][0]["private_payload"] = "private-value"
    product_observation._seal_decision_document(result)

    with pytest.raises(ContractError, match="comparison decision pair fields"):
        write_observation(tmp_path / "comparison.json", result)


def test_decision_file_rejects_rehashed_noncanonical_utc_timestamp(
    tmp_path: Path,
) -> None:
    result = compare_surfaces(
        [
            _current_subtraction("first", "first-control"),
            _current_subtraction("second", "second-control"),
        ]
    )
    result["generated_at"] = "2026-08-12 01:02:03"
    product_observation._seal_decision_document(result)

    with pytest.raises(ContractError, match="decision generated_at"):
        write_observation(tmp_path / "comparison.json", result)


def test_comparison_file_rejects_rehashed_missing_pair_matrix(tmp_path: Path) -> None:
    result = compare_surfaces(
        [
            _current_subtraction("first", "first-control"),
            _current_subtraction("second", "second-control"),
        ]
    )
    result.pop("pairs")
    product_observation._seal_decision_document(result)

    with pytest.raises(ContractError, match="comparison decision fields are incomplete"):
        write_observation(tmp_path / "comparison.json", result)


def test_comparison_file_reconciles_script_pin_identity(tmp_path: Path) -> None:
    first = _current_subtraction("first", "first-control")
    second = _current_subtraction("second", "second-control")
    result = compare_surfaces([first, second])
    result["pairs"][0]["same_script"] = False
    product_observation._seal_decision_document(result)

    with pytest.raises(ContractError, match="comparison decision script identity"):
        write_observation(tmp_path / "comparison.json", result)


def test_comparison_file_reconciles_full_source_custody(tmp_path: Path) -> None:
    first = _current_subtraction("first", "first-control")
    second = _current_subtraction("second", "second-control")
    result = compare_surfaces([first, second])
    result["pairs"][0]["source_custody_comparable"] = True
    product_observation._seal_decision_document(result)

    with pytest.raises(ContractError, match="comparison decision source custody"):
        write_observation(tmp_path / "comparison.json", result)


def test_comparison_file_reconciles_control_script_identity(tmp_path: Path) -> None:
    first = _current_subtraction("first", "first-control")
    second = _current_subtraction("second", "second-control")
    result = compare_surfaces([first, second])
    result["pairs"][0]["same_control_script"] = False
    product_observation._seal_decision_document(result)

    with pytest.raises(ContractError, match="comparison decision control identity"):
        write_observation(tmp_path / "comparison.json", result)


def test_comparison_file_reconciles_capture_custody_statuses(
    tmp_path: Path,
) -> None:
    first = product_observation._seal_subtraction_document(
        _captured_surface("first")
    )
    second = product_observation._seal_subtraction_document(
        _captured_surface("second")
    )
    result = compare_surfaces([first, second])
    result["pairs"][0]["capture_receipts_comparable"] = False
    product_observation._seal_decision_document(result)

    with pytest.raises(ContractError, match="comparison decision capture custody"):
        write_observation(tmp_path / "comparison.json", result)


def test_surface_comparison_refuses_an_unbounded_quadratic_arm_set() -> None:
    arms = [_clean(f"arm-{index}", ["api.A"]) for index in range(257)]

    with pytest.raises(ContractError, match="at most 256"):
        compare_surfaces(arms)


def test_repeated_baseline_refuses_an_unbounded_quadratic_arm_set() -> None:
    with pytest.raises(ContractError, match="at most 256"):
        build_repeated_surface_baseline([{} for _ in range(257)])


def test_comparison_file_rejects_a_rehashed_missing_pair(tmp_path: Path) -> None:
    arms = [
        _current_subtraction("first", "first-control"),
        _current_subtraction("second", "second-control"),
        _current_subtraction("third", "third-control"),
    ]
    result = compare_surfaces(arms)
    result["pairs"].pop()
    product_observation._seal_decision_document(result)

    with pytest.raises(ContractError, match="comparison decision matrix"):
        write_observation(tmp_path / "comparison.json", result)


def test_comparison_file_rejects_rehashed_duplicate_pair_identity(
    tmp_path: Path,
) -> None:
    arms = [
        _current_subtraction("first", "first-control"),
        _current_subtraction("second", "second-control"),
        _current_subtraction("third", "third-control"),
    ]
    result = compare_surfaces(arms)
    result["pairs"][1]["a"] = result["pairs"][0]["a"]
    result["pairs"][1]["b"] = result["pairs"][0]["b"]
    product_observation._seal_decision_document(result)

    with pytest.raises(ContractError, match="comparison decision matrix"):
        write_observation(tmp_path / "comparison.json", result)


def test_drift_file_normalizes_hostile_name_types_to_a_contract_error(
    tmp_path: Path,
) -> None:
    baseline = build_surface_baseline(_current_subtraction("baseline", "control"))
    observed = _current_subtraction("observed", "observed-control")
    result = check_surface_drift(observed, baseline)
    result["added"] = [{}, "api.A"]
    product_observation._seal_decision_document(result)

    with pytest.raises(ContractError, match="drift decision name list"):
        write_observation(tmp_path / "drift.json", result)


def test_comparison_file_normalizes_nested_name_types_to_a_contract_error(
    tmp_path: Path,
) -> None:
    first = _current_subtraction("first", "first-control")
    second = _current_subtraction("second", "second-control")
    result = compare_surfaces([first, second])
    result["pairs"][0]["only_a"] = [[], "api.A"]
    product_observation._seal_decision_document(result)

    with pytest.raises(ContractError, match="comparison decision name list"):
        write_observation(tmp_path / "comparison.json", result)


def test_decisions_name_legacy_parent_receipt_absence() -> None:
    baseline = build_surface_baseline(_clean("baseline", ["api.A"]))
    observed = _clean("observed", ["api.A"])
    baseline.pop("baseline_receipt_sha256")

    drift = check_surface_drift(observed, baseline)
    pair = compare_surfaces([observed, _clean("second", ["api.A"])])["pairs"][0]

    assert drift["baseline_receipt_sha256"] is None
    assert drift["observed_subtraction_receipt_sha256"] is None
    assert drift["input_artifact_receipts_complete"] is False
    assert pair["input_artifact_receipts_complete"] is False


def test_drift_rejects_mixed_current_and_legacy_parent_lineage() -> None:
    baseline = build_surface_baseline(_clean("baseline", ["api.A"]))
    observed = _clean("observed", ["api.A"])

    result = check_surface_drift(observed, baseline)

    assert result["input_artifact_receipts_comparable"] is False
    assert result["passed"] is False


def test_drift_keeps_fully_legacy_parent_lineage_unknown() -> None:
    baseline = build_surface_baseline(_clean("baseline", ["api.A"]))
    baseline.pop("baseline_receipt_sha256")

    result = check_surface_drift(_clean("observed", ["api.A"]), baseline)

    assert result["input_artifact_receipts_comparable"] is None
    assert result["passed"] is True


def test_pairwise_rejects_mixed_current_and_legacy_parent_lineage() -> None:
    current = _current_subtraction("current", "current-control")
    legacy = _clean("legacy", ["api.A"])

    pair = compare_surfaces([current, legacy])["pairs"][0]

    assert pair["input_artifact_receipts_comparable"] is False
    assert pair["surface_comparison_claim_ready"] is False


def test_pairwise_keeps_fully_legacy_parent_lineage_unknown() -> None:
    pair = compare_surfaces(
        [_clean("first", ["api.A"]), _clean("second", ["api.A"])]
    )["pairs"][0]

    assert pair["input_artifact_receipts_comparable"] is None
    assert pair["surface_comparison_claim_ready"] is True


def test_subtraction_binds_exact_current_observation_receipts() -> None:
    arm = product_observation._seal_observation_document(
        _current_method_observation("arm", "a" * 16, {"api.A": 1})
    )
    control = product_observation._seal_observation_document(
        _current_method_observation("control", "b" * 16, {})
    )

    subtraction = subtract_control(arm, control)

    assert subtraction["arm_observation_receipt_sha256"] == arm[
        "observation_receipt_sha256"
    ]
    assert subtraction["control_observation_receipt_sha256"] == control[
        "observation_receipt_sha256"
    ]
    assert subtraction["input_observation_receipts_complete"] is True
    assert subtraction["input_observation_receipts_comparable"] is True
    assert subtraction["surface_claim_ready"] is True


def test_subtraction_write_requires_a_complete_receipt(tmp_path: Path) -> None:
    subtraction = _current_subtraction("source", "source-control")
    subtraction.pop("subtraction_receipt_sha256")

    with pytest.raises(ContractError, match="subtraction write requires"):
        write_observation(tmp_path / "subtraction.json", subtraction)


def test_subtraction_write_rejects_a_rehashed_noncanonical_timestamp(
    tmp_path: Path,
) -> None:
    subtraction = _current_subtraction("source", "source-control")
    subtraction["generated_at"] = "2026-08-12 01:02:03"
    product_observation._seal_subtraction_document(subtraction)

    with pytest.raises(ContractError, match="subtraction generated_at"):
        write_observation(tmp_path / "subtraction.json", subtraction)


def test_subtraction_write_rejects_a_rehashed_private_non_claim(
    tmp_path: Path,
) -> None:
    subtraction = _current_subtraction("source", "source-control")
    subtraction["non_claims"] = ["private tenant note"]
    product_observation._seal_subtraction_document(subtraction)

    with pytest.raises(ContractError, match="subtraction non-claims"):
        write_observation(tmp_path / "subtraction.json", subtraction)


def test_subtraction_write_rejects_a_rehashed_unsafe_identity(
    tmp_path: Path,
) -> None:
    subtraction = _current_subtraction("source", "source-control")
    subtraction["arm_label"] = "../private"
    product_observation._seal_subtraction_document(subtraction)

    with pytest.raises(ContractError, match="subtraction arm label"):
        write_observation(tmp_path / "subtraction.json", subtraction)


def test_subtraction_write_rejects_rehashed_attributed_name_count(
    tmp_path: Path,
) -> None:
    subtraction = _current_subtraction("source", "source-control")
    subtraction["attributed_api_names"] += 1
    product_observation._seal_subtraction_document(subtraction)

    with pytest.raises(ContractError, match="subtraction attributed API count"):
        write_observation(tmp_path / "subtraction.json", subtraction)


def test_subtraction_write_rejects_a_rehashed_invalid_api_count(
    tmp_path: Path,
) -> None:
    subtraction = _current_subtraction("source", "source-control")
    subtraction["only_in_arm"]["api.A"] = -1
    product_observation._seal_subtraction_document(subtraction)

    with pytest.raises(ContractError, match="only_in_arm contains an invalid count"):
        write_observation(tmp_path / "subtraction.json", subtraction)


def test_subtraction_write_reconciles_clean_name_subtraction(
    tmp_path: Path,
) -> None:
    subtraction = _current_subtraction("source", "source-control")
    subtraction["only_in_control"] = {"api.ControlLeak": 1}
    product_observation._seal_subtraction_document(subtraction)

    with pytest.raises(ContractError, match="subtraction clean-name verdict"):
        write_observation(tmp_path / "subtraction.json", subtraction)


def test_subtraction_write_rejects_rehashed_overlapping_name_sets(
    tmp_path: Path,
) -> None:
    subtraction = _current_subtraction("source", "source-control")
    subtraction["only_in_control"] = {"api.A": 1}
    subtraction["clean_subtraction"] = False
    product_observation._seal_subtraction_document(subtraction)

    with pytest.raises(ContractError, match="subtraction exclusive name sets"):
        write_observation(tmp_path / "subtraction.json", subtraction)


def test_subtraction_write_rejects_rehashed_invalid_elevation(
    tmp_path: Path,
) -> None:
    subtraction = _current_subtraction("source", "source-control")
    subtraction["elevated_in_arm"] = {
        "api.Shared": {"arm": 1, "control": 1},
    }
    product_observation._seal_subtraction_document(subtraction)

    with pytest.raises(ContractError, match="subtraction elevation evidence"):
        write_observation(tmp_path / "subtraction.json", subtraction)


def test_subtraction_write_rejects_rehashed_context_coverage_drift(
    tmp_path: Path,
) -> None:
    subtraction = _current_subtraction("source", "source-control")
    subtraction["context_coverage"]["api.Private"] = ["frame"]
    product_observation._seal_subtraction_document(subtraction)

    with pytest.raises(ContractError, match="subtraction context coverage"):
        write_observation(tmp_path / "subtraction.json", subtraction)


@pytest.mark.parametrize("invalid_contexts", [[{}], [["frame"]]])
def test_subtraction_write_rejects_unhashable_context_coverage_cleanly(
    tmp_path: Path, invalid_contexts: list,
) -> None:
    subtraction = _current_subtraction("source", "source-control")
    subtraction["context_coverage"]["api.A"] = invalid_contexts
    product_observation._seal_subtraction_document(subtraction)

    with pytest.raises(ContractError, match="subtraction context coverage"):
        write_observation(tmp_path / "subtraction.json", subtraction)


def test_subtraction_write_rejects_rehashed_script_attribution_drift(
    tmp_path: Path,
) -> None:
    subtraction = _current_subtraction("source", "source-control")
    subtraction["script_attributed_only_in_arm"] = {"api.Private": 1}
    subtraction["script_attribution_comparable"] = True
    product_observation._seal_subtraction_document(subtraction)

    with pytest.raises(ContractError, match="subtraction script attribution"):
        write_observation(tmp_path / "subtraction.json", subtraction)


def test_subtraction_write_reconciles_surface_claim_readiness(
    tmp_path: Path,
) -> None:
    subtraction = _current_subtraction("source", "source-control")
    subtraction["surface_claim_ready"] = not subtraction["surface_claim_ready"]
    product_observation._seal_subtraction_document(subtraction)

    with pytest.raises(ContractError, match="subtraction surface readiness"):
        write_observation(tmp_path / "subtraction.json", subtraction)


def test_subtraction_write_reconciles_arm_control_method_verdict(
    tmp_path: Path,
) -> None:
    subtraction = _current_subtraction("source", "source-control")
    subtraction["arm_control_method_mismatches"] = ["driver"]
    subtraction["arm_control_method_comparable"] = True
    subtraction["surface_claim_ready"] = False
    product_observation._seal_subtraction_document(subtraction)

    with pytest.raises(ContractError, match="subtraction arm/control method"):
        write_observation(tmp_path / "subtraction.json", subtraction)


@pytest.mark.parametrize("invalid_mismatches", [[{}], [["driver"]]])
def test_subtraction_write_rejects_unhashable_method_mismatches_cleanly(
    tmp_path: Path, invalid_mismatches: list,
) -> None:
    subtraction = _current_subtraction("source", "source-control")
    subtraction["arm_control_method_mismatches"] = invalid_mismatches
    product_observation._seal_subtraction_document(subtraction)

    with pytest.raises(ContractError, match="subtraction arm/control method"):
        write_observation(tmp_path / "subtraction.json", subtraction)


def test_subtraction_write_reconciles_driver_execution_verdict(
    tmp_path: Path,
) -> None:
    subtraction = _current_subtraction("source", "source-control")
    subtraction["driver_execution_complete"] = not subtraction[
        "driver_execution_complete"
    ]
    subtraction["surface_claim_ready"] = False
    product_observation._seal_subtraction_document(subtraction)

    with pytest.raises(ContractError, match="subtraction driver execution"):
        write_observation(tmp_path / "subtraction.json", subtraction)


def test_subtraction_write_rejects_equal_invalid_unsupplied_driver_metadata(
    tmp_path: Path,
) -> None:
    subtraction = _current_subtraction("source", "source-control")
    for side in ("arm", "control"):
        assert subtraction[f"{side}_driver"]["supplied"] is False
        subtraction[f"{side}_driver"]["bytes"] = 1
    product_observation._seal_subtraction_document(subtraction)

    with pytest.raises(ContractError, match="subtraction driver execution"):
        write_observation(tmp_path / "subtraction.json", subtraction)


def test_subtraction_write_reconciles_compact_script_identities(
    tmp_path: Path,
) -> None:
    subtraction = _current_subtraction("source", "source-control")
    subtraction["script_identity"]["sha256_16"] = "f" * 16
    subtraction["surface_claim_ready"] = False
    product_observation._seal_subtraction_document(subtraction)

    with pytest.raises(ContractError, match="subtraction compact script identity"):
        write_observation(tmp_path / "subtraction.json", subtraction)


def test_subtraction_write_reconciles_ready_probe_comparability(
    tmp_path: Path,
) -> None:
    subtraction = _current_subtraction("source", "source-control")
    subtraction["arm_ready_expression"] = {
        "supplied": True,
        "bytes": 1,
        "sha256_16": "f" * 16,
    }
    product_observation._seal_subtraction_document(subtraction)

    with pytest.raises(ContractError, match="subtraction ready probe"):
        write_observation(tmp_path / "subtraction.json", subtraction)


@pytest.mark.parametrize("mutation", ["different_expression", "missing_control"])
def test_digest_withholds_claim_on_incoherent_saved_ready_probe(mutation):
    from browser_core.observation_digest import digest_observation, render_digest

    subtraction = _current_subtraction("source", "source-control")
    assert subtraction["ready_probe_comparable"] is True
    assert digest_observation(subtraction)["surface_claim_ready"] is True
    if mutation == "different_expression":
        subtraction["arm_ready_expression"] = {
            "supplied": True,
            "bytes": 1,
            "sha256_16": "f" * 16,
        }
    else:
        del subtraction["control_ready_expression"]

    digest = digest_observation(subtraction)

    assert digest["surface_claim_ready"] is False
    assert digest["ready_probe_receipts_coherent"] is False
    digest["surface_claim_ready"] = True
    with pytest.raises(ContractError, match="claim readiness"):
        render_digest(digest)


def test_subtraction_write_rejects_equal_invalid_unsupplied_ready_expressions(
    tmp_path: Path,
) -> None:
    subtraction = _current_subtraction("source", "source-control")
    for side in ("arm", "control"):
        assert subtraction[f"{side}_ready_expression"]["supplied"] is False
        subtraction[f"{side}_ready_expression"]["bytes"] = 1
    product_observation._seal_subtraction_document(subtraction)

    with pytest.raises(ContractError, match="subtraction ready probe"):
        write_observation(tmp_path / "subtraction.json", subtraction)


def test_subtraction_write_reconciles_offline_guard_comparability(
    tmp_path: Path,
) -> None:
    subtraction = _current_subtraction("source", "source-control")
    subtraction["arm_offline_guard"] = dict(
        product_observation._NORMALIZED_OFFLINE_GUARD
    )
    product_observation._seal_subtraction_document(subtraction)

    with pytest.raises(ContractError, match="subtraction offline guard"):
        write_observation(tmp_path / "subtraction.json", subtraction)


def test_subtraction_write_reconciles_arm_readiness_verdict(
    tmp_path: Path,
) -> None:
    subtraction = _current_subtraction("source", "source-control")
    subtraction["arm_readiness_satisfied"] = False
    subtraction["surface_claim_ready"] = False
    product_observation._seal_subtraction_document(subtraction)

    with pytest.raises(ContractError, match="subtraction await evidence"):
        write_observation(tmp_path / "subtraction.json", subtraction)


@pytest.mark.parametrize(
    "mutation", ["longer_wait", "arm_report", "missing_control_report"]
)
def test_digest_withholds_claim_on_incoherent_saved_await_receipts(mutation):
    from browser_core.observation_digest import digest_observation, render_digest

    subtraction = _current_subtraction("source", "source-control")
    assert digest_observation(subtraction)["surface_claim_ready"] is True
    if mutation == "longer_wait":
        subtraction["arm_await_ready_seconds"] = 1.0
    elif mutation == "arm_report":
        subtraction["arm_await_report"] = {}
    else:
        del subtraction["control_await_report"]

    digest = digest_observation(subtraction)

    assert digest["surface_claim_ready"] is False
    assert digest["await_receipts_coherent"] is False
    digest["surface_claim_ready"] = True
    with pytest.raises(ContractError, match="claim readiness"):
        render_digest(digest)


def test_subtraction_write_reconciles_input_method_comparability(
    tmp_path: Path,
) -> None:
    subtraction = _current_subtraction("source", "source-control")
    subtraction["control_input_profile"] = "probe"
    product_observation._seal_subtraction_document(subtraction)

    with pytest.raises(ContractError, match="subtraction input method"):
        write_observation(tmp_path / "subtraction.json", subtraction)


@pytest.mark.parametrize("receipt", ["input_probe", "ambient_input"])
def test_digest_withholds_claim_on_noncanonical_saved_input_receipt(
    tmp_path: Path, receipt
):
    from browser_core.observation_digest import digest_observation, render_digest

    subtraction = _current_subtraction("source", "source-control")
    if receipt == "input_probe":
        probe = product_observation._sanitize_input_probe_report(
            {
                "profile": "probe",
                "dispatched": 1,
                "attempted": 1,
                "errors": [],
                "trusted_transport": True,
            }
        )
        for side in ("arm", "control"):
            subtraction[f"{side}_input_profile"] = "probe"
            subtraction[f"{side}_input_probe"] = dict(probe)
        product_observation._seal_subtraction_document(subtraction)
        assert digest_observation(subtraction)["surface_claim_ready"] is True
        subtraction["arm_input_probe"]["private_field"] = "private-value"
    else:
        assert digest_observation(subtraction)["surface_claim_ready"] is True
        subtraction["arm_ambient_input"]["private_field"] = "private-value"

    digest = digest_observation(subtraction)

    assert digest["surface_claim_ready"] is False
    assert digest["input_claim_receipts_coherent"] is False
    digest["surface_claim_ready"] = True
    with pytest.raises(ContractError, match="claim readiness"):
        render_digest(digest)
    product_observation._seal_subtraction_document(subtraction)
    with pytest.raises(ContractError, match="subtraction (input|ambient input)"):
        write_observation(tmp_path / "subtraction.json", subtraction)


def test_digest_withholds_claim_on_noncanonical_saved_request_activity(
    tmp_path: Path,
) -> None:
    from browser_core.observation_digest import digest_observation, render_digest

    subtraction = _current_subtraction("source", "source-control")
    assert digest_observation(subtraction)["surface_claim_ready"] is True
    subtraction["request_activity"]["private_field"] = "private-value"

    digest = digest_observation(subtraction)

    assert digest["surface_claim_ready"] is False
    assert digest["request_activity_receipts_valid"] is False
    digest["surface_claim_ready"] = True
    with pytest.raises(ContractError, match="claim readiness"):
        render_digest(digest)
    product_observation._seal_subtraction_document(subtraction)
    with pytest.raises(ContractError, match="subtraction request activity"):
        write_observation(tmp_path / "subtraction.json", subtraction)


@pytest.mark.parametrize("mutation", ["stale_surface", "resealed_request_counts"])
def test_digest_withholds_claim_on_invalid_current_subtraction_receipt(mutation):
    from browser_core.observation_digest import digest_observation, render_digest

    subtraction = _current_subtraction("source", "source-control")
    assert digest_observation(subtraction)["surface_claim_ready"] is True
    if mutation == "stale_surface":
        subtraction["only_in_arm"]["api.A"] = 2
    else:
        subtraction["request_activity"]["arm_requests"] = 0
        product_observation._seal_subtraction_document(subtraction)

    digest = digest_observation(subtraction)

    assert digest["surface_claim_ready"] is False
    assert digest["subtraction_receipt_coherent"] is False
    digest["surface_claim_ready"] = True
    with pytest.raises(ContractError, match="claim readiness"):
        render_digest(digest)


@pytest.mark.parametrize(
    "mutation",
    [
        "impossible_total",
        "wrong_delta",
        "false_clean_verdict",
        "duplicate_identity",
        "bad_body_envelope",
    ],
)
def test_digest_withholds_claim_on_legacy_request_receipt_contradiction(mutation):
    from browser_core.observation_digest import digest_observation, render_digest

    subtraction = _current_subtraction("source", "source-control")
    del subtraction["subtraction_receipt_sha256"]
    assert digest_observation(subtraction)["surface_claim_ready"] is True
    activity = subtraction["request_activity"]
    if mutation == "impossible_total":
        activity["arm_requests"] = 0
    elif mutation == "false_clean_verdict":
        activity["clean_subtraction"] = False
    else:
        row = {
            "method": "POST",
            "served": "post-ack",
            "path_segment_lengths": [1],
            "path_segments_truncated": False,
            "query_names": [],
            "query_names_truncated": False,
            "count": 2 if mutation == "wrong_delta" else 1,
            "arm_count": 1,
            "control_count": 0,
        }
        if mutation == "bad_body_envelope":
            row.update(body_bytes_total=7, body_bytes_min=10, body_bytes_max=10)
        activity["only_in_arm"].append(row)
        if mutation == "duplicate_identity":
            activity["only_in_arm"].append(dict(row))

    digest = digest_observation(subtraction)

    assert digest["surface_claim_ready"] is False
    assert digest["request_activity_receipts_valid"] is False
    digest["surface_claim_ready"] = True
    with pytest.raises(ContractError, match="claim readiness"):
        render_digest(digest)


def _current_resource_subtraction() -> dict:
    arm = _current_method_observation("source", "a" * 16, {"api.A": 1})
    control = _current_method_observation("source-control", "b" * 16, {})
    row = {
        "tag": "iframe",
        "attribute": "src",
        "origin": "https://challenge.example",
        "same_origin_as_rehost": False,
        "path_segment_lengths": [5],
        "path_segments_truncated": False,
        "query_names": [],
        "query_names_truncated": False,
    }
    for observation, rows in ((arm, [row]), (control, [])):
        observation["resource_intent_capture"] = "cdp_dom_snapshot/1"
        observation["resource_intents"] = {"status": "ok", "intents": rows}
    return subtract_control(arm, control)


@pytest.mark.parametrize("self_receipt", [True, False])
def test_digest_resource_corpus_excludes_resealed_invalid_current_snapshot(
    self_receipt: bool,
):
    from browser_core.observation_digest import corpus_matrix, digest_observation

    subtraction = _current_resource_subtraction()
    positive = digest_observation(subtraction)
    assert positive["resource_intents"]["status"] == "ok"
    assert positive["resource_intent_receipts_valid"] is True
    assert (
        corpus_matrix([("source", subtraction)])["resource_intents"]["successful_attributed_arms"]
        == 1
    )

    subtraction["resource_intents"]["arm_count"] = 0
    product_observation._seal_subtraction_document(subtraction)
    if not self_receipt:
        del subtraction["subtraction_receipt_sha256"]

    digest = digest_observation(subtraction)
    assert digest["surface_claim_ready"] is False
    assert digest["resource_intents"]["status"] == "unverifiable"
    assert digest["resource_intents"]["rows_total"] == 0
    assert digest["resource_intent_receipts_valid"] is False
    corpus = corpus_matrix([("source", subtraction)])["resource_intents"]
    assert corpus["successful_attributed_arms"] == 0
    assert corpus["unavailable_arms"] == [
        {"label": "source", "status": "unverifiable"}
    ]


def test_current_resource_report_cannot_downgrade_to_legacy_shape(tmp_path: Path):
    from browser_core.observation_digest import digest_observation

    subtraction = _current_resource_subtraction()
    assert digest_observation(subtraction)["surface_claim_ready"] is True
    subtraction["resource_intents"]["arm_count"] = 0
    del subtraction["resource_intents"]["non_claim"]
    product_observation._seal_subtraction_document(subtraction)

    digest = digest_observation(subtraction)
    assert digest["surface_claim_ready"] is False
    with pytest.raises(ContractError, match="resource intent"):
        write_observation(tmp_path / "subtraction.json", subtraction)


def test_stale_current_subtraction_receipt_withholds_side_view_comparisons():
    from browser_core.observation_digest import (
        corpus_matrix,
        digest_observation,
        diff_digests,
    )

    subtraction = _current_resource_subtraction()
    peer = _current_resource_subtraction()
    positive = digest_observation(subtraction)
    assert positive["surface_claim_ready"] is True
    assert positive["resource_intents"]["status"] == "ok"
    assert positive["request_activity"]["status"] == "ok"
    assert diff_digests(subtraction, peer)["resource_intents"]["comparable"] is True
    assert diff_digests(subtraction, peer)["request_activity"]["comparable"] is True

    subtraction["only_in_arm"]["api.A"] = 2  # Leave its saved self receipt stale.

    digest = digest_observation(subtraction)
    assert digest["surface_claim_ready"] is False
    assert digest["subtraction_receipt_coherent"] is False
    assert digest["resource_intents"]["status"] == "unverifiable"
    assert digest["request_activity"]["status"] == "unverifiable"
    assert digest["resource_intents"]["rows_total"] == 0
    assert digest["request_activity"]["rows_total"] == 0
    corpus = corpus_matrix([("stale", subtraction)])["resource_intents"]
    assert corpus["successful_attributed_arms"] == 0
    assert corpus["unavailable_arms"] == [
        {"label": "stale", "status": "unverifiable"}
    ]
    diff = diff_digests(subtraction, peer)
    for side in ("resource_intents", "request_activity"):
        assert diff[side]["left_status"] == "unverifiable"
        assert diff[side]["comparable"] is False


def _current_request_delta(*, count: int = 1) -> dict:
    return {
        "method": "POST",
        "served": "post-ack",
        "path_segment_lengths": [1],
        "path_segments_truncated": False,
        "query_names": [],
        "query_names_truncated": False,
        "count": count,
        "arm_count": 1,
        "control_count": 0,
    }


def test_current_request_activity_cannot_downgrade_to_legacy_shape(tmp_path: Path):
    from browser_core.observation_digest import digest_observation

    subtraction = _current_subtraction("source", "source-control")
    assert digest_observation(subtraction)["surface_claim_ready"] is True
    activity = subtraction["request_activity"]
    activity["only_in_arm"].append(_current_request_delta(count=2))
    for field in (
        "scope",
        "non_claim",
        "arm_requests",
        "control_requests",
        "shared_shapes",
        "clean_subtraction",
    ):
        del activity[field]
    product_observation._seal_subtraction_document(subtraction)

    digest = digest_observation(subtraction)
    assert digest["surface_claim_ready"] is False
    assert digest["request_activity_receipts_valid"] is False
    assert digest["request_activity"]["status"] == "unverifiable"
    assert digest["request_activity"]["rows_total"] == 0
    with pytest.raises(ContractError, match="subtraction request activity"):
        write_observation(tmp_path / "subtraction.json", subtraction)


def test_request_diff_withholds_resealed_invalid_current_row():
    from browser_core.observation_digest import diff_digests, digest_observation

    left = _current_subtraction("left", "left-control")
    right = _current_subtraction("right", "right-control")
    assert diff_digests(right, right)["request_activity"]["comparable"] is True
    left["request_activity"]["only_in_arm"].append(_current_request_delta())
    left["request_activity"]["arm_requests"] = 0
    product_observation._seal_subtraction_document(left)

    digest = digest_observation(left)
    assert digest["surface_claim_ready"] is False
    assert digest["request_activity_receipts_valid"] is False
    assert digest["request_activity"]["status"] == "unverifiable"
    diff = diff_digests(left, right)["request_activity"]
    assert diff["left_status"] == "unverifiable"
    assert diff["comparable"] is False
    assert diff["only_left"] == 0


def test_subtraction_write_reconciles_ambient_input_verdict(
    tmp_path: Path,
) -> None:
    subtraction = _current_subtraction("source", "source-control")
    subtraction["ambient_input_clean"] = False
    subtraction["surface_claim_ready"] = False
    product_observation._seal_subtraction_document(subtraction)

    with pytest.raises(ContractError, match="subtraction ambient input"):
        write_observation(tmp_path / "subtraction.json", subtraction)


def test_subtraction_write_reconciles_arm_collector_startup(
    tmp_path: Path,
) -> None:
    subtraction = _current_subtraction("source", "source-control")
    subtraction["collector_started"] = False
    subtraction["surface_claim_ready"] = False
    product_observation._seal_subtraction_document(subtraction)

    with pytest.raises(ContractError, match="subtraction arm collector startup"):
        write_observation(tmp_path / "subtraction.json", subtraction)


def test_subtraction_write_reconciles_control_collector_startup(
    tmp_path: Path,
) -> None:
    subtraction = _current_subtraction("source", "source-control")
    subtraction["control_collector_startup_coherent"] = False
    product_observation._seal_subtraction_document(subtraction)

    with pytest.raises(ContractError, match="subtraction control collector startup"):
        write_observation(tmp_path / "subtraction.json", subtraction)


def test_subtraction_write_reconciles_startup_derivation_verdict(
    tmp_path: Path,
) -> None:
    subtraction = _current_subtraction("source", "source-control")
    subtraction["startup_derivation_coherent"] = False
    subtraction["surface_claim_ready"] = False
    product_observation._seal_subtraction_document(subtraction)

    with pytest.raises(ContractError, match="subtraction startup derivation"):
        write_observation(tmp_path / "subtraction.json", subtraction)


def test_subtraction_write_reconciles_arm_rehost_dependency_verdict(
    tmp_path: Path,
) -> None:
    subtraction = _current_subtraction("source", "source-control")
    subtraction["rehost_dependencies_complete"] = False
    subtraction["surface_claim_ready"] = False
    product_observation._seal_subtraction_document(subtraction)

    with pytest.raises(ContractError, match="subtraction arm rehost dependencies"):
        write_observation(tmp_path / "subtraction.json", subtraction)


def test_subtraction_write_rejects_conflicting_legacy_rehost_receipt(
    tmp_path: Path,
) -> None:
    subtraction = _current_subtraction("source", "source-control")
    subtraction["unserved_requests"] = {
        "status": "ok",
        "count": 1,
        "dependencies_complete": True,
        "paths": ["/missing-stage.js"],
    }
    subtraction["rehost_dependencies_complete"] = True
    product_observation._seal_subtraction_document(subtraction)

    with pytest.raises(ContractError, match="subtraction arm rehost dependencies"):
        write_observation(tmp_path / "subtraction.json", subtraction)


def test_subtraction_write_reconciles_definite_page_load_execution(
    tmp_path: Path,
) -> None:
    subtraction = _current_subtraction("source", "source-control")
    subtraction["page_load_execution_coherent"] = False
    subtraction["surface_claim_ready"] = False
    product_observation._seal_subtraction_document(subtraction)

    with pytest.raises(ContractError, match="subtraction page-load execution"):
        write_observation(tmp_path / "subtraction.json", subtraction)


@pytest.mark.parametrize("mutation", ["reported", "sample", "missing_control"])
def test_digest_withholds_claim_on_incoherent_saved_page_load_receipts(mutation):
    from browser_core.observation_digest import digest_observation, render_digest

    subtraction = _current_subtraction("source", "source-control")
    assert subtraction["page_load_execution_coherent"] is True
    assert digest_observation(subtraction)["surface_claim_ready"] is True
    if mutation == "reported":
        subtraction["arm_page_load_execution"]["reported_page_loads"] = 0
    elif mutation == "sample":
        subtraction["arm_page_load_execution"]["sample_requests"] = 0
    else:
        del subtraction["control_page_load_execution"]

    digest = digest_observation(subtraction)

    assert digest["surface_claim_ready"] is False
    assert digest["page_load_receipts_coherent"] is False
    digest["surface_claim_ready"] = True
    with pytest.raises(ContractError, match="claim readiness"):
        render_digest(digest)


def test_subtraction_write_requires_true_trace_coherence_to_have_support(
    tmp_path: Path,
) -> None:
    subtraction = _current_subtraction("source", "source-control")
    subtraction["arm_trace_flush"]["bytes"] = 99
    product_observation._seal_subtraction_document(subtraction)

    with pytest.raises(ContractError, match="subtraction trace evidence"):
        write_observation(tmp_path / "subtraction.json", subtraction)


@pytest.mark.parametrize("mutation", ["flush_bytes", "source_digest", "missing_control"])
def test_digest_withholds_claim_on_incoherent_saved_trace_receipts(mutation) -> None:
    from browser_core.observation_digest import digest_observation, render_digest

    subtraction = _current_subtraction("source", "source-control")
    assert subtraction["trace_evidence_coherent"] is True
    assert digest_observation(subtraction)["surface_claim_ready"] is True
    if mutation == "flush_bytes":
        subtraction["arm_trace_flush"]["bytes"] -= 1
    elif mutation == "source_digest":
        subtraction["arm_trace_evidence"]["source_trace"]["sha256_16"] = "bad"
    else:
        del subtraction["control_trace_flush"]

    digest = digest_observation(subtraction)

    assert digest["surface_claim_ready"] is False
    assert digest["trace_evidence_receipts_coherent"] is False
    digest["surface_claim_ready"] = True
    with pytest.raises(ContractError, match="claim readiness"):
        render_digest(digest)


def test_subtraction_write_requires_canonical_request_activity(
    tmp_path: Path,
) -> None:
    subtraction = _current_subtraction("source", "source-control")
    subtraction["request_activity"]["private_path"] = "/tenant/private"
    product_observation._seal_subtraction_document(subtraction)

    with pytest.raises(ContractError, match="subtraction request activity"):
        write_observation(tmp_path / "subtraction.json", subtraction)


def test_subtraction_write_reconciles_request_activity_clean_verdict(
    tmp_path: Path,
) -> None:
    subtraction = _current_subtraction("source", "source-control")
    subtraction["request_activity"]["clean_subtraction"] = False
    product_observation._seal_subtraction_document(subtraction)

    with pytest.raises(ContractError, match="subtraction request activity verdict"):
        write_observation(tmp_path / "subtraction.json", subtraction)


def test_subtraction_write_reconciles_request_activity_row_arithmetic(
    tmp_path: Path,
) -> None:
    subtraction = _current_subtraction("source", "source-control")
    subtraction["request_activity"]["only_in_arm"].append(
        {
            "method": "POST",
            "served": "post-ack",
            "path_segment_lengths": [1],
            "path_segments_truncated": False,
            "query_names": [],
            "query_names_truncated": False,
            "count": 2,
            "arm_count": 1,
            "control_count": 0,
        }
    )
    product_observation._seal_subtraction_document(subtraction)

    with pytest.raises(ContractError, match="subtraction request activity row"):
        write_observation(tmp_path / "subtraction.json", subtraction)


def test_subtraction_write_reconciles_request_activity_aggregate_counts(
    tmp_path: Path,
) -> None:
    subtraction = _current_subtraction("source", "source-control")
    subtraction["request_activity"]["only_in_arm"].append(
        {
            "method": "POST",
            "served": "post-ack",
            "path_segment_lengths": [1],
            "path_segments_truncated": False,
            "query_names": [],
            "query_names_truncated": False,
            "count": 1,
            "arm_count": 1,
            "control_count": 0,
        }
    )
    subtraction["request_activity"]["arm_requests"] = 0
    product_observation._seal_subtraction_document(subtraction)

    with pytest.raises(ContractError, match="subtraction request activity counts"):
        write_observation(tmp_path / "subtraction.json", subtraction)


def test_subtraction_write_rejects_duplicate_request_activity_identity(
    tmp_path: Path,
) -> None:
    subtraction = _current_subtraction("source", "source-control")
    identity = {
        "method": "POST",
        "served": "post-ack",
        "path_segment_lengths": [1],
        "path_segments_truncated": False,
        "query_names": [],
        "query_names_truncated": False,
    }
    subtraction["request_activity"]["only_in_arm"].append(
        {**identity, "count": 1, "arm_count": 1, "control_count": 0}
    )
    subtraction["request_activity"]["only_in_control"].append(
        {**identity, "count": 1, "arm_count": 0, "control_count": 1}
    )
    subtraction["request_activity"]["clean_subtraction"] = False
    product_observation._seal_subtraction_document(subtraction)

    with pytest.raises(ContractError, match="subtraction request activity identity"):
        write_observation(tmp_path / "subtraction.json", subtraction)


def test_subtraction_write_reconciles_request_body_size_envelope(
    tmp_path: Path,
) -> None:
    subtraction = _current_subtraction("source", "source-control")
    subtraction["request_activity"]["only_in_arm"].append(
        {
            "method": "POST",
            "served": "post-ack",
            "path_segment_lengths": [1],
            "path_segments_truncated": False,
            "query_names": [],
            "query_names_truncated": False,
            "count": 1,
            "arm_count": 1,
            "control_count": 0,
            "body_bytes_total": 7,
            "body_bytes_min": 10,
            "body_bytes_max": 5,
        }
    )
    product_observation._seal_subtraction_document(subtraction)

    with pytest.raises(ContractError, match="subtraction request body envelope"):
        write_observation(tmp_path / "subtraction.json", subtraction)


def test_subtraction_write_rejects_ambiguous_request_body_digest_custody(
    tmp_path: Path,
) -> None:
    subtraction = _current_subtraction("source", "source-control")
    subtraction["request_activity"].update(
        arm_requests=3,
        control_requests=2,
        shared_shapes=2,
    )
    subtraction["request_activity"]["only_in_arm"].append(
        {
            "method": "POST",
            "served": "post-ack",
            "path_segment_lengths": [1],
            "path_segments_truncated": False,
            "query_names": [],
            "query_names_truncated": False,
            "count": 1,
            "arm_count": 2,
            "control_count": 1,
            "body_sha256_16_counts": {"a" * 16: 1},
        }
    )
    product_observation._seal_subtraction_document(subtraction)

    with pytest.raises(ContractError, match="subtraction request body digest custody"):
        write_observation(tmp_path / "subtraction.json", subtraction)


def test_subtraction_write_requires_canonical_request_query_identity(
    tmp_path: Path,
) -> None:
    subtraction = _current_subtraction("source", "source-control")
    subtraction["request_activity"].update(arm_requests=2)
    subtraction["request_activity"]["only_in_arm"].append(
        {
            "method": "GET",
            "served": "stage",
            "path_segment_lengths": [1],
            "path_segments_truncated": False,
            "query_names": ["z", "a"],
            "query_names_truncated": False,
            "count": 1,
            "arm_count": 1,
            "control_count": 0,
        }
    )
    product_observation._seal_subtraction_document(subtraction)

    with pytest.raises(ContractError, match="subtraction request activity is not canonical"):
        write_observation(tmp_path / "subtraction.json", subtraction)


def test_subtraction_write_counts_omitted_shared_request_shapes(
    tmp_path: Path,
) -> None:
    subtraction = _current_subtraction("source", "source-control")
    subtraction["request_activity"]["only_in_arm"].append(
        {
            "method": "GET",
            "served": "stage",
            "path_segment_lengths": [1],
            "path_segments_truncated": False,
            "query_names": [],
            "query_names_truncated": False,
            "count": 1,
            "arm_count": 1,
            "control_count": 0,
        }
    )
    product_observation._seal_subtraction_document(subtraction)

    with pytest.raises(ContractError, match="subtraction shared request coverage"):
        write_observation(tmp_path / "subtraction.json", subtraction)


def test_subtraction_write_requires_closed_resource_intent_projection(
    tmp_path: Path,
) -> None:
    subtraction = _current_subtraction("source", "source-control")
    subtraction["resource_intents"]["private_path"] = "/tenant/frame"
    product_observation._seal_subtraction_document(subtraction)

    with pytest.raises(ContractError, match="subtraction resource intents"):
        write_observation(tmp_path / "subtraction.json", subtraction)


def test_subtraction_write_reconciles_resource_intent_clean_verdict(
    tmp_path: Path,
) -> None:
    arm = _current_method_observation("source", "a" * 16, {"api.A": 1})
    control = _current_method_observation("source-control", "b" * 16, {})
    row = {
        "tag": "iframe",
        "attribute": "src",
        "origin": "https://challenge.example",
        "same_origin_as_rehost": False,
        "path_segment_lengths": [5],
        "path_segments_truncated": False,
        "query_names": [],
        "query_names_truncated": False,
    }
    arm["resource_intents"] = {"status": "ok", "intents": [row]}
    control["resource_intents"] = {"status": "ok", "intents": []}
    subtraction = subtract_control(arm, control)
    subtraction["resource_intents"]["clean_subtraction"] = False
    product_observation._seal_subtraction_document(subtraction)

    with pytest.raises(ContractError, match="subtraction resource intent verdict"):
        write_observation(tmp_path / "subtraction.json", subtraction)


def test_subtraction_write_reconciles_resource_intent_multiplicity_delta(
    tmp_path: Path,
) -> None:
    arm = _current_method_observation("source", "a" * 16, {"api.A": 1})
    control = _current_method_observation("source-control", "b" * 16, {})
    row = {
        "tag": "iframe",
        "attribute": "src",
        "origin": "https://challenge.example",
        "same_origin_as_rehost": False,
        "path_segment_lengths": [5],
        "path_segments_truncated": False,
        "query_names": [],
        "query_names_truncated": False,
    }
    arm["resource_intents"] = {"status": "ok", "intents": [row]}
    control["resource_intents"] = {"status": "ok", "intents": []}
    subtraction = subtract_control(arm, control)
    subtraction["resource_intents"]["multiplicity_deltas"] = [
        {**row, "arm_occurrences": 1, "control_occurrences": 1}
    ]
    product_observation._seal_subtraction_document(subtraction)

    with pytest.raises(ContractError, match="subtraction resource multiplicity"):
        write_observation(tmp_path / "subtraction.json", subtraction)


def test_subtraction_write_rejects_duplicate_resource_intent_identity(
    tmp_path: Path,
) -> None:
    arm = _current_method_observation("source", "a" * 16, {"api.A": 1})
    control = _current_method_observation("source-control", "b" * 16, {})
    row = {
        "tag": "iframe",
        "attribute": "src",
        "origin": "https://challenge.example",
        "same_origin_as_rehost": False,
        "path_segment_lengths": [5],
        "path_segments_truncated": False,
        "query_names": [],
        "query_names_truncated": False,
    }
    arm["resource_intents"] = {"status": "ok", "intents": [row]}
    control["resource_intents"] = {"status": "ok", "intents": []}
    subtraction = subtract_control(arm, control)
    subtraction["resource_intents"]["multiplicity_deltas"] = [
        {**row, "arm_occurrences": 2, "control_occurrences": 1}
    ]
    product_observation._seal_subtraction_document(subtraction)

    with pytest.raises(ContractError, match="subtraction resource intent identity"):
        write_observation(tmp_path / "subtraction.json", subtraction)


def test_subtraction_write_reconciles_resource_intent_aggregate_counts(
    tmp_path: Path,
) -> None:
    arm = _current_method_observation("source", "a" * 16, {"api.A": 1})
    control = _current_method_observation("source-control", "b" * 16, {})
    row = {
        "tag": "iframe",
        "attribute": "src",
        "origin": "https://challenge.example",
        "same_origin_as_rehost": False,
        "path_segment_lengths": [5],
        "path_segments_truncated": False,
        "query_names": [],
        "query_names_truncated": False,
    }
    arm["resource_intents"] = {"status": "ok", "intents": [row]}
    control["resource_intents"] = {"status": "ok", "intents": []}
    subtraction = subtract_control(arm, control)
    subtraction["resource_intents"]["arm_count"] = 0
    product_observation._seal_subtraction_document(subtraction)

    with pytest.raises(ContractError, match="subtraction resource intent counts"):
        write_observation(tmp_path / "subtraction.json", subtraction)


def test_subtraction_write_reconciles_resource_intent_origin_label(
    tmp_path: Path,
) -> None:
    arm = _current_method_observation("source", "a" * 16, {"api.A": 1})
    control = _current_method_observation("source-control", "b" * 16, {})
    row = {
        "tag": "iframe",
        "attribute": "src",
        "origin": "loopback-rehost",
        "same_origin_as_rehost": False,
        "path_segment_lengths": [5],
        "path_segments_truncated": False,
        "query_names": [],
        "query_names_truncated": False,
    }
    arm["resource_intents"] = {"status": "ok", "intents": [row]}
    control["resource_intents"] = {"status": "ok", "intents": []}
    subtraction = subtract_control(arm, control)

    with pytest.raises(ContractError, match="subtraction resource intents are not canonical"):
        write_observation(tmp_path / "subtraction.json", subtraction)


def test_subtraction_write_rejects_elevated_exclusive_name_overlap(
    tmp_path: Path,
) -> None:
    subtraction = _current_subtraction("source", "source-control")
    subtraction["elevated_in_arm"]["api.A"] = {"arm": 4, "control": 1}
    product_observation._seal_subtraction_document(subtraction)

    with pytest.raises(ContractError, match="subtraction elevated name partition"):
        write_observation(tmp_path / "subtraction.json", subtraction)


def test_subtraction_write_reconciles_script_execution_summary(
    tmp_path: Path,
) -> None:
    subtraction = _current_subtraction("source", "source-control")
    subtraction["arm_script_execution"] = {
        "total": 2,
        "complete": 1,
        "open": 0,
        "max_complete_duration_ns": 10,
    }
    product_observation._seal_subtraction_document(subtraction)

    with pytest.raises(ContractError, match="subtraction arm script execution"):
        write_observation(tmp_path / "subtraction.json", subtraction)


def test_subtraction_write_requires_true_method_comparability_to_have_support(
    tmp_path: Path,
) -> None:
    subtraction = _current_subtraction("source", "source-control")
    subtraction["control_dom_profile"] = "rich"
    product_observation._seal_subtraction_document(subtraction)

    with pytest.raises(ContractError, match="subtraction retained method pairs"):
        write_observation(tmp_path / "subtraction.json", subtraction)


def test_subtraction_write_requires_retained_method_mismatch_to_have_support(
    tmp_path: Path,
) -> None:
    subtraction = _current_subtraction("source", "source-control")
    subtraction["arm_control_method_comparable"] = False
    subtraction["arm_control_method_mismatches"] = ["dom_profile"]
    subtraction["surface_claim_ready"] = False
    product_observation._seal_subtraction_document(subtraction)

    with pytest.raises(ContractError, match="subtraction retained method mismatch"):
        write_observation(tmp_path / "subtraction.json", subtraction)


def test_observation_write_requires_a_complete_receipt(tmp_path: Path) -> None:
    observation = product_observation._seal_observation_document(
        _current_method_observation("source", "a" * 16, {"api.A": 1})
    )
    observation.pop("observation_receipt_sha256")

    with pytest.raises(ContractError, match="observation write requires"):
        write_observation(tmp_path / "observation.json", observation)


def test_observation_write_rejects_a_rehashed_noncanonical_timestamp(
    tmp_path: Path,
) -> None:
    observation = _current_method_observation("source", "a" * 16, {"api.A": 1})
    observation["generated_at"] = "2026-08-12 01:02:03"
    product_observation._seal_observation_document(observation)

    with pytest.raises(ContractError, match="observation generated_at"):
        write_observation(tmp_path / "observation.json", observation)


def test_observation_write_rejects_a_rehashed_unsafe_identity(
    tmp_path: Path,
) -> None:
    observation = _current_method_observation("source", "a" * 16, {"api.A": 1})
    observation["label"] = "../private"
    product_observation._seal_observation_document(observation)

    with pytest.raises(ContractError, match="observation label"):
        write_observation(tmp_path / "observation.json", observation)


def test_observation_write_rejects_a_rehashed_incoherent_script_identity(
    tmp_path: Path,
) -> None:
    observation = _current_method_observation("source", "a" * 16, {"api.A": 1})
    observation["script_identity"]["signals"]["sha256_16"] = "b" * 16
    product_observation._seal_observation_document(observation)

    with pytest.raises(ContractError, match="observation script identity"):
        write_observation(tmp_path / "observation.json", observation)


def test_subtraction_rejects_mixed_current_and_legacy_observation_lineage() -> None:
    arm = product_observation._seal_observation_document(
        _current_method_observation("arm", "a" * 16, {"api.A": 1})
    )
    control = _current_method_observation("control", "b" * 16, {})

    subtraction = subtract_control(arm, control)

    assert subtraction["input_observation_receipts_complete"] is False
    assert subtraction["input_observation_receipts_comparable"] is False
    assert subtraction["surface_claim_ready"] is False


def test_subtraction_keeps_fully_legacy_observation_lineage_unknown() -> None:
    subtraction = _current_subtraction("arm", "control")

    assert subtraction["input_observation_receipts_complete"] is False
    assert subtraction["input_observation_receipts_comparable"] is None
    assert subtraction["surface_claim_ready"] is True


def test_baseline_reconciles_complete_observation_lineage_flags() -> None:
    arm = product_observation._seal_observation_document(
        _current_method_observation("arm", "a" * 16, {"api.A": 1})
    )
    control = product_observation._seal_observation_document(
        _current_method_observation("control", "b" * 16, {})
    )
    subtraction = subtract_control(arm, control)
    subtraction["input_observation_receipts_complete"] = False
    product_observation._seal_subtraction_document(subtraction)

    with pytest.raises(ContractError, match="observation lineage"):
        build_surface_baseline(subtraction)


def test_baseline_cannot_restore_readiness_on_mixed_observation_lineage() -> None:
    arm = product_observation._seal_observation_document(
        _current_method_observation("arm", "a" * 16, {"api.A": 1})
    )
    control = _current_method_observation("control", "b" * 16, {})
    subtraction = subtract_control(arm, control)
    subtraction["surface_claim_ready"] = True
    product_observation._seal_subtraction_document(subtraction)

    with pytest.raises(ContractError, match="observation lineage"):
        build_surface_baseline(subtraction)


def test_comparison_rejects_a_rehashed_missing_observation_parent() -> None:
    arm = product_observation._seal_observation_document(
        _current_method_observation("arm", "a" * 16, {"api.A": 1})
    )
    control = product_observation._seal_observation_document(
        _current_method_observation("control", "b" * 16, {})
    )
    subtraction = subtract_control(arm, control)
    baseline = build_surface_baseline(subtraction)
    subtraction["control_observation_receipt_sha256"] = None
    product_observation._seal_subtraction_document(subtraction)

    with pytest.raises(ContractError, match="observation lineage"):
        check_surface_drift(subtraction, baseline)


def _edited_bound_artifact(kind: str) -> dict:
    if kind == "observation":
        document = product_observation._seal_observation_document(
            _current_method_observation("vendor", "a" * 16, {"api.A": 1})
        )
        document["dwell_seconds"] = 21.0
        return document
    if kind == "subtraction":
        document = subtract_control(
            _current_method_observation("vendor", "a" * 16, {"api.A": 1}),
            _current_method_observation("control", "b" * 16, {}),
        )
        document["only_in_arm"]["api.EDITED"] = 1
        return document
    document = build_surface_baseline(_clean("baseline", ["api.A"]))
    document["label"] = "edited-baseline"
    return document


def _bound_artifact(kind: str) -> dict:
    if kind == "observation":
        return product_observation._seal_observation_document(
            _current_method_observation("vendor", "a" * 16, {"api.A": 1})
        )
    if kind == "subtraction":
        return subtract_control(
            _current_method_observation("vendor", "a" * 16, {"api.A": 1}),
            _current_method_observation("control", "b" * 16, {}),
        )
    return build_surface_baseline(_clean("baseline", ["api.A"]))


@pytest.mark.parametrize("kind", ["observation", "subtraction", "baseline"])
def test_shared_file_boundary_roundtrips_bound_input_artifacts(
    tmp_path: Path, kind: str
) -> None:
    document = _bound_artifact(kind)
    path = tmp_path / f"{kind}.json"

    write_observation(path, document)

    assert product_observation.load_observation(path) == document


@pytest.mark.parametrize("kind", ["observation", "subtraction", "baseline"])
def test_shared_writer_rejects_edited_bound_input_artifacts(
    tmp_path: Path, kind: str
) -> None:
    with pytest.raises(ContractError, match="receipt integrity"):
        write_observation(tmp_path / f"{kind}.json", _edited_bound_artifact(kind))


@pytest.mark.parametrize("kind", ["observation", "subtraction", "baseline"])
def test_shared_loader_rejects_edited_bound_input_artifacts(
    tmp_path: Path, kind: str
) -> None:
    path = tmp_path / f"{kind}.json"
    path.write_text(json.dumps(_edited_bound_artifact(kind)), encoding="utf-8")

    with pytest.raises(ContractError, match="receipt integrity"):
        product_observation.load_observation(path)


def test_identical_names_do_not_pass_under_a_different_method() -> None:
    bare = dict(_clean("bare", ["api.A"]), arm_driver_supplied=False)
    driven = dict(_clean("driven", ["api.A"]), arm_driver_supplied=True)
    base = build_surface_baseline(bare)
    result = check_surface_drift(driven, base)
    assert result["drift"] == 0
    assert result["same_method"] is False
    assert result["passed"] is False
    assert "arm_driver_supplied" in result["method_mismatches"]


def test_identical_names_do_not_pass_under_different_control_bytes() -> None:
    frozen = dict(
        _clean("frozen", ["api.A"]),
        control_script_sha256_16="c" * 16,
    )
    observed = dict(
        _clean("observed", ["api.A"]),
        control_script_sha256_16="d" * 16,
    )

    result = check_surface_drift(observed, build_surface_baseline(frozen))

    assert result["drift"] == 0
    assert result["same_control_script"] is False
    assert result["passed"] is False


def test_current_control_pin_cannot_degrade_to_missing_on_a_drift_check() -> None:
    frozen = dict(
        _clean("frozen", ["api.A"]),
        control_script_sha256_16="c" * 16,
    )

    result = check_surface_drift(
        _clean("observed", ["api.A"]), build_surface_baseline(frozen)
    )

    assert result["same_control_script"] is False
    assert result["passed"] is False


def test_verified_baseline_source_cannot_degrade_to_missing_on_drift() -> None:
    frozen = dict(
        _clean("frozen", ["api.A"]),
        source_provenance={
            "status": "verified_digest",
            "source_url": "https://vendor.example/v1/api.js",
            "retrieved_at": "2026-08-12T00:00:00Z",
            "sha256": "0" * 16 + "a" * 48,
        },
    )

    result = check_surface_drift(
        _clean("observed", ["api.A"]), build_surface_baseline(frozen)
    )

    assert result["source_custody_comparable"] is False
    assert result["passed"] is False


def test_same_pin_drift_requires_the_same_verified_full_source_digest() -> None:
    frozen = dict(
        _clean("frozen", ["api.A"]),
        source_provenance={
            "status": "verified_digest",
            "source_url": "https://vendor.example/v1/api.js",
            "retrieved_at": "2026-08-12T00:00:00Z",
            "sha256": "0" * 16 + "a" * 48,
        },
    )
    observed = dict(
        _clean("observed", ["api.A"]),
        source_provenance={
            "status": "verified_digest",
            "source_url": "https://vendor.example/v1/api.js",
            "retrieved_at": "2026-08-12T00:00:00Z",
            "sha256": "0" * 16 + "b" * 48,
        },
    )

    result = check_surface_drift(observed, build_surface_baseline(frozen))

    assert result["source_custody_comparable"] is False
    assert result["passed"] is False


def test_cross_roll_drift_accepts_distinct_independently_verified_sources() -> None:
    frozen = dict(
        _clean("frozen", ["api.A"]),
        source_provenance={
            "status": "verified_digest",
            "source_url": "https://vendor.example/v1/api.js",
            "retrieved_at": "2026-08-12T00:00:00Z",
            "sha256": "0" * 16 + "a" * 48,
        },
    )
    observed = product_observation._seal_subtraction_document(
        dict(
            _clean("observed", ["api.A"]),
            arm_script_sha256_16="f" * 16,
            source_provenance={
                "status": "verified_digest",
                "source_url": "https://vendor.example/v2/api.js",
                "retrieved_at": "2026-08-12T01:00:00Z",
                "sha256": "f" * 16 + "b" * 48,
            },
        )
    )

    result = check_surface_drift(observed, build_surface_baseline(frozen))

    assert result["same_script"] is False
    assert result["source_custody_comparable"] is True
    assert result["passed"] is True


def test_cross_roll_drift_rejects_unverified_distinct_sources() -> None:
    frozen = product_observation._seal_subtraction_document(
        _clean("frozen", ["api.A"])
    )
    observed = product_observation._seal_subtraction_document(
        dict(
            _clean("observed", ["api.A"]),
            arm_script_sha256_16="f" * 16,
        )
    )

    result = check_surface_drift(observed, build_surface_baseline(frozen))

    assert result["same_script"] is False
    assert result["source_custody_comparable"] is False
    assert result["passed"] is False


def test_legacy_baseline_reports_unknown_control_pin_without_blocking() -> None:
    baseline = build_surface_baseline(_clean("legacy", ["api.A"]))
    baseline.pop("baseline_receipt_sha256")
    result = check_surface_drift(
        _clean("observed", ["api.A"]),
        baseline,
    )

    assert result["same_control_script"] is None
    assert result["source_custody_comparable"] is None
    assert result["passed"] is True


def test_added_name_fails_and_is_named() -> None:
    base = build_surface_baseline(_clean("pin", ["api.A"]))
    result = check_surface_drift(_clean("newroll", ["api.A", "api.NEW"]), base)
    assert result["passed"] is False
    assert result["added"] == ["api.NEW"]
    assert result["drift"] == 1


def test_removed_name_fails_and_is_named() -> None:
    base = build_surface_baseline(_clean("pin", ["api.A", "api.GONE"]))
    result = check_surface_drift(_clean("newroll", ["api.A"]), base)
    assert result["passed"] is False
    assert result["removed"] == ["api.GONE"]


def test_tolerance_absorbs_measured_roll_jitter_but_still_reports_it() -> None:
    """Cross-roll jitter was measured at 1-2 names; a tolerated diff stays visible."""
    base = build_surface_baseline(_clean("pin", ["api.A", "api.B"]))
    result = check_surface_drift(
        product_observation._seal_subtraction_document(
            _clean("otherroll", ["api.A", "api.B", "api.Window.XMLHttpRequest"])
        ),
        base,
        tolerance=1,
    )
    assert result["passed"] is True
    assert result["added"] == ["api.Window.XMLHttpRequest"]
    assert result["drift"] == 1


def test_dirty_subtraction_can_never_pass_the_gate() -> None:
    base = build_surface_baseline(_clean("pin", ["api.A"]))
    result = check_surface_drift(
        dict(_subtraction("bad", ["api.A"]), clean_subtraction=False), base
    )
    assert result["drift"] == 0
    assert result["passed"] is False


def test_drift_records_whether_the_script_even_matched() -> None:
    base = build_surface_baseline(_clean("pin", ["api.A"]))
    same = check_surface_drift(_clean("pin", ["api.A"]), base)
    assert same["same_script"] is True
    other = dict(_clean("other", ["api.A"]), arm_script_sha256_16="ffffffffffffffff")
    assert check_surface_drift(other, base)["same_script"] is False


def test_negative_tolerance_is_rejected() -> None:
    base = build_surface_baseline(_clean("pin", ["api.A"]))
    with pytest.raises(ContractError, match="non-negative"):
        check_surface_drift(_clean("x", ["api.A"]), base, tolerance=-1)


def test_tolerance_beyond_the_maximum_possible_surface_drift_is_rejected() -> None:
    base = build_surface_baseline(_clean("pin", ["api.A"]))
    with pytest.raises(ContractError, match="no greater than 2000000"):
        check_surface_drift(_clean("x", ["api.A"]), base, tolerance=2_000_001)


def test_check_rejects_a_baseline_that_is_not_a_baseline() -> None:
    with pytest.raises(
        ContractError, match="must be a browser-core.product-script-surface-baseline"
    ):
        check_surface_drift(_clean("x", ["api.A"]), _clean("y", ["api.A"]))


def test_drift_gate_verifies_the_frozen_surface_digest() -> None:
    baseline = build_surface_baseline(_clean("pin", ["api.A", "api.B"]))
    baseline["api_names"] = ["api.A", "api.EDITED"]

    with pytest.raises(ContractError, match="surface_sha256 integrity"):
        check_surface_drift(_clean("later", ["api.A", "api.EDITED"]), baseline)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("api_name_count", 99, "api_name_count"),
        ("api_names", ["api.A", "api.A"], "uniqueness"),
        ("surface_sha256", "not-a-digest", "surface_sha256 integrity"),
        ("measured_noise_floor", "0", "non-negative integer"),
    ],
)
def test_drift_gate_rejects_malformed_baseline_receipts(field, value, message) -> None:
    baseline = build_repeated_surface_baseline(
        [_clean("first", ["api.A"]), _clean("second", ["api.A"])]
    )
    baseline[field] = value

    with pytest.raises(ContractError, match=message):
        check_surface_drift(_clean("later", ["api.A"]), baseline, tolerance=None)


def test_drift_gate_rejects_an_edited_measured_noise_floor() -> None:
    baseline = build_repeated_surface_baseline(
        [
            _clean("first", ["api.A"]),
            _clean("second", ["api.A", "api.Flaky"]),
        ]
    )
    assert baseline["pairwise_differences"] == [1]
    assert baseline["measured_noise_floor"] == 1
    baseline["measured_noise_floor"] = 100

    with pytest.raises(ContractError, match="pairwise differences"):
        check_surface_drift(
            _clean("later", ["api.A", "api.Unrelated"]),
            baseline,
            tolerance=None,
        )


# ------------------------------------------------------------------ round trip


def test_write_and_load_round_trip(tmp_path) -> None:
    document = product_observation._seal_observation_document(
        _current_method_observation("bm", "a" * 16, {"api.A": 1})
    )
    path = write_observation(tmp_path / "nested" / "arm.json", document)
    assert path.is_file()
    assert load_observation(path)["label"] == "bm"


@pytest.mark.skipif(os.name != "nt", reason="Windows directory junction regression")
def test_write_observation_rejects_parent_junction_before_creating_output(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    unrelated = tmp_path / "unrelated"
    unrelated.mkdir()
    junction = workspace / "output"
    subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(junction), str(unrelated)],
        check=True,
        capture_output=True,
        text=True,
    )
    document = product_observation._seal_observation_document(
        _current_method_observation("bm", "a" * 16, {"api.A": 1})
    )

    with pytest.raises(ContractError, match="regular directory"):
        write_observation(junction / "new-parent" / "arm.json", document)
    assert not (unrelated / "new-parent").exists()


def test_write_observation_refuses_and_preserves_previous_artifact(tmp_path) -> None:
    path = tmp_path / "arm.json"
    original = product_observation._seal_observation_document(
        _current_method_observation("old", "a" * 16, {"api.A": 1})
    )
    replacement = product_observation._seal_observation_document(
        _current_method_observation("new", "b" * 16, {"api.B": 1})
    )
    write_observation(path, original)
    original_bytes = path.read_bytes()

    with pytest.raises(ContractError, match="publication failed"):
        write_observation(path, replacement)

    assert path.read_bytes() == original_bytes
    assert list(tmp_path.glob(".arm.json.tmp-*")) == []


def test_write_observation_explicit_overwrite_is_conditional_and_loadable(
    tmp_path,
) -> None:
    path = tmp_path / "arm.json"
    write_observation(
        path,
        product_observation._seal_observation_document(
            _current_method_observation("old", "a" * 16, {"api.A": 1})
        ),
    )
    write_observation(
        path,
        product_observation._seal_observation_document(
            _current_method_observation("new", "b" * 16, {"api.B": 1})
        ),
        overwrite=True,
    )
    assert load_observation(path)["label"] == "new"


def test_write_observation_requires_boolean_overwrite_choice(tmp_path) -> None:
    with pytest.raises(ContractError, match="overwrite choice"):
        write_observation(
            tmp_path / "arm.json",
            product_observation._seal_observation_document(
                _current_method_observation("new", "b" * 16, {"api.B": 1})
            ),
            overwrite=1,  # type: ignore[arg-type]
        )


@pytest.mark.parametrize("path", [None, True, 1, 1.5, b"path", [], {}, ()])
def test_observation_io_rejects_invalid_path_types_cleanly(path) -> None:
    with pytest.raises(ContractError, match="path must be text or a Path"):
        write_observation(path, {})
    with pytest.raises(ContractError, match="path must be text or a Path"):
        load_observation(path)


@pytest.mark.parametrize(
    "document", [None, True, 1, 1.5, "document", b"document", [], ()]
)
def test_write_observation_rejects_non_object_documents(tmp_path, document) -> None:
    path = tmp_path / "invalid.json"
    with pytest.raises(ContractError, match="document must be an object"):
        write_observation(path, document)
    assert not path.exists()


@pytest.mark.parametrize(
    "value",
    [float("nan"), "\ud800"],
)
def test_write_observation_refuses_json_its_loader_cannot_read(tmp_path, value) -> None:
    path = tmp_path / "arm.json"
    with pytest.raises(ContractError):
        write_observation(path, {"schema": OBSERVATION_SCHEMA, "value": value})
    assert not path.exists()


@pytest.mark.parametrize("schema", ["other/1", ["other/1"], {"name": "other/1"}])
def test_load_rejects_foreign_document(tmp_path, schema) -> None:
    path = tmp_path / "x.json"
    path.write_text(json.dumps({"schema": schema}), encoding="utf-8")
    with pytest.raises(ContractError, match="not a product-script observation"):
        load_observation(path)


def test_load_observation_rejects_oversized_document_before_json_parse(
    tmp_path, monkeypatch
) -> None:
    import browser_core.product_observation as po

    path = tmp_path / "arm.json"
    path.write_text("{}", encoding="utf-8")
    monkeypatch.setattr(po, "MAX_OBSERVATION_DOCUMENT_BYTES", 1)

    with pytest.raises(ContractError, match="product observation exceeds 1 bytes"):
        load_observation(path)


def test_load_observation_normalizes_invalid_utf8_and_json_errors(tmp_path) -> None:
    path = tmp_path / "arm.json"
    path.write_bytes(b"\xff")
    with pytest.raises(ContractError, match="valid UTF-8 JSON"):
        load_observation(path)

    path.write_text("{", encoding="utf-8")
    with pytest.raises(ContractError, match="valid UTF-8 JSON"):
        load_observation(path)


@pytest.mark.parametrize(
    ("body", "message"),
    [
        (
            b'{"schema":"browser-core.product-script-observation/1",'
            b'"label":"one","label":"two"}',
            "duplicate key",
        ),
        (
            b'{"schema":"browser-core.product-script-observation/1",' b'"value":NaN}',
            "non-finite",
        ),
        (
            b'{"schema":"browser-core.product-script-observation/1",' b'"value":1e400}',
            "non-finite",
        ),
    ],
)
def test_load_observation_rejects_ambiguous_json(
    tmp_path: Path,
    body: bytes,
    message: str,
) -> None:
    path = tmp_path / "arm.json"
    path.write_bytes(body)

    with pytest.raises(ContractError, match=message):
        load_observation(path)


def test_load_observation_preserves_missing_file_oserror_contract(tmp_path) -> None:
    # Preserve the public loader's documented filesystem contract: callers that
    # distinguish a missing corpus member from a malformed present member still
    # receive OSError/FileNotFoundError after the bounded-reader migration.
    with pytest.raises(FileNotFoundError):
        load_observation(tmp_path / "missing.json")


class _FakeServer:
    """Stands in for the rehost HTTP server.

    These tests are about the runner's failure handling, not about sockets. Binding
    a real one made them fail on a host that had run out of socket buffer space --
    a false negative about code that was fine.
    """

    server_port = 12345

    def __init__(self, *args, **kwargs):
        self.daemon_threads = False

    def serve_forever(self):
        return None

    def shutdown(self):
        return None

    def server_close(self):
        return None


def _stopped_receipt(run_id: str = "r1") -> dict[str, object]:
    return {
        "run_id": run_id,
        "state": "stopped",
        "running": False,
        "identity_protected": True,
        "shutdown_mode": "graceful",
    }


def test_observation_stop_receipt_is_exact_bound_and_detached() -> None:
    import browser_core.product_observation as po

    source = _stopped_receipt()
    retained = po._validated_observation_stop_receipt(
        source,
        expected_run_id="r1",
    )
    source["state"] = "active"

    assert retained == _stopped_receipt()


@pytest.mark.parametrize(
    "receipt",
    [
        None,
        [],
        {**_stopped_receipt(), "run_id": "other-run"},
        {**_stopped_receipt(), "state": "active"},
        {**_stopped_receipt(), "running": True},
        {**_stopped_receipt(), "identity_protected": 1},
        {**_stopped_receipt(), "shutdown_mode": "private-mode"},
        {**_stopped_receipt(), "private": "field"},
    ],
)
def test_observation_stop_receipt_rejects_unverified_runtime_shapes(receipt) -> None:
    import browser_core.product_observation as po

    with pytest.raises(ContractError, match="stop was not verified"):
        po._validated_observation_stop_receipt(
            receipt,
            expected_run_id="r1",
        )


def test_page_probe_failure_retains_native_trace_only_as_diagnostics(
    tmp_path, monkeypatch
) -> None:
    import browser_core.product_observation as po

    script = tmp_path / "s.js"
    script.write_bytes(b"// bounded blocked fixture\n")
    trace = tmp_path / "blocked.perfetto-trace"
    trace.write_bytes(b"settled native trace")
    diagnostic = {
        "fetch_target_scope": {
            "coverage": "complete",
            "requests": 0,
            "loopback": 0,
            "external": 0,
            "non_network": 0,
            "unclassified": 0,
        },
        "script_execution": {
            "total": 1,
            "complete": 0,
            "open": 1,
            "max_complete_duration_ns": None,
        },
    }

    monkeypatch.setattr(po, "_QuietThreadingHTTPServer", _FakeServer)
    monkeypatch.setattr(
        po,
        "launch_evaluation",
        lambda *a, **k: (
            tmp_path / "session.json",
            {
                "run_id": "r1",
                "chromium_revision": "a" * 40,
                "trace_path": str(trace),
                "automation": {"cdp_endpoint": "http://127.0.0.1:9"},
            },
        ),
    )
    monkeypatch.setattr(po, "wait_for_page_target", lambda *a, **k: None)
    monkeypatch.setattr(
        po,
        "_capture_geometry",
        lambda *a, **k: (_ for _ in ()).throw(TimeoutError("page is busy")),
    )
    monkeypatch.setattr(
        po,
        "_stop_observation_session",
        lambda *a, **k: _stopped_receipt(),
    )
    monkeypatch.setattr(po, "_await_trace_file", lambda *a, **k: True)
    monkeypatch.setattr(
        po,
        "bind_perfetto_source_trace",
        lambda *a, **k: {"bytes": len(trace.read_bytes()), "sha256": "b" * 64},
    )
    monkeypatch.setattr(po, "count_exportable_events", lambda *a, **k: 1)
    monkeypatch.setattr(po, "export_perfetto", lambda *a, **k: {"events": 1})
    monkeypatch.setattr(po, "analyse_observation_trace", lambda *a, **k: diagnostic)

    result = po.run_product_script_observation(
        po.ProductScriptObservation(
            script=script,
            label="blocked",
            executable=tmp_path / "chrome.exe",
            trace_processor=tmp_path / "tp.exe",
            workspace=tmp_path,
            dwell_seconds=0.0,
            capture_resource_intents=False,
        ),
        tmp_path,
    )

    assert result["error"].startswith("observation execution failed: TimeoutError;")
    assert result["diagnostic_trace_analysis"] == diagnostic
    assert "analysis" not in result
    assert result["trace_flush"] == {
        "status": "settled",
        "bytes": len(trace.read_bytes()),
    }


def test_export_failure_fails_one_arm_not_the_batch(tmp_path, monkeypatch):
    """A flaky Perfetto export must be recorded, not raised.

    Measured in session-2 batches: 2 of 27 and 1 of 22 arms vanished when the
    export raised, and because the exception escaped the runner, every arm after
    the failure was skipped too.
    """
    import browser_core.product_observation as po

    script = tmp_path / "s.js"
    script.write_bytes(b"// sample\n")

    monkeypatch.setattr(po, "_QuietThreadingHTTPServer", _FakeServer)
    monkeypatch.setattr(
        po,
        "launch_evaluation",
        lambda *a, **k: (
            tmp_path / "session.json",
            {
                "run_id": "r1",
                "chromium_revision": "rev",
                "trace_path": str(tmp_path / "missing.perfetto-trace"),
                "automation": {"cdp_endpoint": "http://127.0.0.1:9"},
            },
        ),
    )
    monkeypatch.setattr(po, "wait_for_page_target", lambda *a, **k: None)
    monkeypatch.setattr(po, "_capture_geometry", lambda *a, **k: None)
    monkeypatch.setattr(po, "_capture_startup", lambda *a, **k: None)
    monkeypatch.setattr(po, "stop_session", lambda *a, **k: _stopped_receipt())
    monkeypatch.setattr(po, "_await_trace_file", lambda *a, **k: True)

    def boom(*a, **k):
        raise ContractError("Perfetto trace does not exist: missing.perfetto-trace")

    monkeypatch.setattr(po, "export_perfetto", boom)
    monkeypatch.setattr(po, "TRACE_SETTLE_TIMEOUT", 0.2)

    result = po.run_product_script_observation(
        po.ProductScriptObservation(
            script=script,
            label="flaky",
            executable=tmp_path / "chrome.exe",
            trace_processor=tmp_path / "tp.exe",
            workspace=tmp_path,
            dwell_seconds=0.0,
            capture_resource_intents=False,
        ),
        tmp_path,
    )
    assert "analysis" not in result
    assert "trace export failed" in result["error"]
    assert result["trace_flush"] == {"status": "settled", "bytes": None}
    assert result["label"] == "flaky"


def test_unsettled_trace_is_never_handed_to_the_exporter(tmp_path, monkeypatch):
    """A present partial trace is a retryable bad arm, not exporter input."""
    import browser_core.product_observation as po

    script = tmp_path / "s.js"
    script.write_bytes(b"// sample\n")
    trace = tmp_path / "partial.perfetto-trace"
    trace.write_bytes(b"partial")
    monkeypatch.setattr(po, "_QuietThreadingHTTPServer", _FakeServer)
    monkeypatch.setattr(
        po,
        "launch_evaluation",
        lambda *a, **k: (
            tmp_path / "session.json",
            {
                "run_id": "r1",
                "chromium_revision": "rev",
                "trace_path": str(trace),
                "automation": {"cdp_endpoint": "http://127.0.0.1:9"},
            },
        ),
    )
    monkeypatch.setattr(po, "wait_for_page_target", lambda *a, **k: None)
    monkeypatch.setattr(po, "_capture_geometry", lambda *a, **k: None)
    monkeypatch.setattr(po, "_capture_startup", lambda *a, **k: None)
    monkeypatch.setattr(po, "stop_session", lambda *a, **k: _stopped_receipt())
    monkeypatch.setattr(po, "_await_trace_file", lambda *a, **k: False)
    monkeypatch.setattr(
        po,
        "export_perfetto",
        lambda *a, **k: pytest.fail("unsettled trace reached exporter"),
    )

    result = po.run_product_script_observation(
        po.ProductScriptObservation(
            script=script,
            label="partial",
            executable=tmp_path / "chrome.exe",
            trace_processor=tmp_path / "tp.exe",
            workspace=tmp_path,
            dwell_seconds=0.0,
            capture_resource_intents=False,
        ),
        tmp_path,
    )
    assert result["error"] == "trace export failed: trace file present-unsettled"
    assert result["trace_flush"] == {"status": "present-unsettled", "bytes": 7}
    assert "analysis" not in result


def test_oversized_trace_is_retained_but_not_automatically_normalized(
    tmp_path, monkeypatch
):
    import browser_core.product_observation as po

    script = tmp_path / "s.js"
    script.write_bytes(b"// sample\n")
    trace = tmp_path / "large.perfetto-trace"
    with trace.open("wb") as handle:
        handle.truncate(po.MAX_OBSERVATION_TRACE_EXPORT_BYTES + 1)

    monkeypatch.setattr(po, "_QuietThreadingHTTPServer", _FakeServer)
    monkeypatch.setattr(
        po,
        "launch_evaluation",
        lambda *a, **k: (
            tmp_path / "session.json",
            {
                "run_id": "r1",
                "chromium_revision": "rev",
                "trace_path": str(trace),
                "automation": {"cdp_endpoint": "http://127.0.0.1:9"},
            },
        ),
    )
    monkeypatch.setattr(po, "wait_for_page_target", lambda *a, **k: None)
    monkeypatch.setattr(po, "_capture_geometry", lambda *a, **k: None)
    monkeypatch.setattr(po, "_capture_startup", lambda *a, **k: None)
    monkeypatch.setattr(po, "stop_session", lambda *a, **k: _stopped_receipt())
    monkeypatch.setattr(po, "_await_trace_file", lambda *a, **k: True)
    monkeypatch.setattr(
        po,
        "export_perfetto",
        lambda *a, **k: pytest.fail("oversized trace reached automatic exporter"),
    )

    result = po.run_product_script_observation(
        po.ProductScriptObservation(
            script=script,
            label="large",
            executable=tmp_path / "chrome.exe",
            trace_processor=tmp_path / "tp.exe",
            workspace=tmp_path,
            dwell_seconds=0.0,
            capture_resource_intents=False,
        ),
        tmp_path,
    )

    assert "analysis" not in result
    assert result["trace_flush"] == {
        "status": "settled",
        "bytes": po.MAX_OBSERVATION_TRACE_EXPORT_BYTES + 1,
    }
    assert result["trace_export_budget"] == {
        "max_source_bytes": po.MAX_OBSERVATION_TRACE_EXPORT_BYTES,
        "source_bytes": po.MAX_OBSERVATION_TRACE_EXPORT_BYTES + 1,
        "bytes_within_budget": False,
        "max_exportable_events": po.MAX_OBSERVATION_TRACE_EXPORT_EVENTS,
        "exportable_events": None,
        "events_within_budget": None,
        "within_budget": False,
        "policy": "skip-automatic-normalization-above-budget",
    }
    assert "safety budget" in result["error"]


def test_highly_compressible_trace_is_bounded_by_event_count_before_export(
    tmp_path, monkeypatch
):
    import browser_core.product_observation as po

    script = tmp_path / "s.js"
    script.write_bytes(b"// sample\n")
    trace = tmp_path / "compressed.perfetto-trace"
    trace.write_bytes(b"small compressed trace")
    monkeypatch.setattr(po, "_QuietThreadingHTTPServer", _FakeServer)
    monkeypatch.setattr(
        po,
        "launch_evaluation",
        lambda *a, **k: (
            tmp_path / "session.json",
            {
                "run_id": "r1",
                "chromium_revision": "rev",
                "trace_path": str(trace),
                "automation": {"cdp_endpoint": "http://127.0.0.1:9"},
            },
        ),
    )
    monkeypatch.setattr(po, "wait_for_page_target", lambda *a, **k: None)
    monkeypatch.setattr(po, "_capture_geometry", lambda *a, **k: None)
    monkeypatch.setattr(po, "_capture_startup", lambda *a, **k: None)
    monkeypatch.setattr(po, "stop_session", lambda *a, **k: _stopped_receipt())
    monkeypatch.setattr(po, "_await_trace_file", lambda *a, **k: True)
    monkeypatch.setattr(
        po,
        "count_exportable_events",
        lambda *a, **k: po.MAX_OBSERVATION_TRACE_EXPORT_EVENTS + 1,
    )
    monkeypatch.setattr(
        po,
        "export_perfetto",
        lambda *a, **k: pytest.fail("over-budget event CSV was requested"),
    )

    result = po.run_product_script_observation(
        po.ProductScriptObservation(
            script=script,
            label="compressed",
            executable=tmp_path / "chrome.exe",
            trace_processor=tmp_path / "tp.exe",
            workspace=tmp_path,
            dwell_seconds=0.0,
            capture_resource_intents=False,
        ),
        tmp_path,
    )

    assert result["trace_export_budget"]["bytes_within_budget"] is True
    assert result["trace_export_budget"]["events_within_budget"] is False
    assert result["trace_export_budget"]["within_budget"] is False
    assert "event count" in result["error"]


def test_offline_guard_still_raises_and_is_not_swallowed(tmp_path, monkeypatch):
    """The export try/except must not turn a safety property into a bad arm."""
    import browser_core.product_observation as po

    script = tmp_path / "s.js"
    script.write_bytes(b"// sample\n")
    (tmp_path / "t.perfetto-trace").write_bytes(b"trace")
    monkeypatch.setattr(po, "_QuietThreadingHTTPServer", _FakeServer)
    monkeypatch.setattr(
        po,
        "launch_evaluation",
        lambda *a, **k: (
            tmp_path / "session.json",
            {
                "run_id": "r1",
                "chromium_revision": "rev",
                "trace_path": str(tmp_path / "t.perfetto-trace"),
                "automation": {"cdp_endpoint": "http://127.0.0.1:9"},
            },
        ),
    )
    monkeypatch.setattr(po, "wait_for_page_target", lambda *a, **k: None)
    monkeypatch.setattr(po, "_capture_geometry", lambda *a, **k: None)
    monkeypatch.setattr(po, "_capture_startup", lambda *a, **k: None)
    monkeypatch.setattr(po, "stop_session", lambda *a, **k: _stopped_receipt())
    monkeypatch.setattr(po, "_await_trace_file", lambda *a, **k: True)
    seen_bindings = {}

    def count(*_args, expected_source_binding=None, **_kwargs):
        seen_bindings["count"] = expected_source_binding
        return 1

    def export(*_args, expected_source_binding=None, **_kwargs):
        seen_bindings["export"] = expected_source_binding
        return {"ok": True}

    monkeypatch.setattr(po, "count_exportable_events", count)
    monkeypatch.setattr(po, "export_perfetto", export)
    monkeypatch.setattr(po, "TRACE_SETTLE_TIMEOUT", 0.2)
    monkeypatch.setattr(
        po,
        "analyse_observation_trace",
        lambda *a, **k: {
            "fetch_target_scope": {
                "coverage": "complete",
                "requests": 1,
                "loopback": 0,
                "external": 1,
                "non_network": 0,
                "unclassified": 0,
            }
        },
    )

    with pytest.raises(ContractError, match="offline guard failed"):
        po.run_product_script_observation(
            po.ProductScriptObservation(
                script=script,
                label="leaky",
                executable=tmp_path / "chrome.exe",
                trace_processor=tmp_path / "tp.exe",
                workspace=tmp_path,
                dwell_seconds=0.0,
                capture_resource_intents=False,
            ),
            tmp_path,
        )

    assert seen_bindings["count"] == seen_bindings["export"]
    assert seen_bindings["count"]["bytes"] == len(b"trace")
    assert len(seen_bindings["count"]["sha256"]) == 64


def test_input_profile_is_validated(tmp_path):
    import browser_core.product_observation as po

    script = tmp_path / "s.js"
    script.write_bytes(b"// sample\n")
    with pytest.raises(ContractError, match="input profile"):
        po.run_product_script_observation(
            po.ProductScriptObservation(
                script=script,
                label="x",
                executable=tmp_path / "c.exe",
                trace_processor=tmp_path / "tp.exe",
                workspace=tmp_path,
                input_profile="humanlike",
            ),
            tmp_path,
        )


def test_input_probe_records_failure_and_never_raises(monkeypatch):
    """A probe that cannot deliver is a fact about the run, not a failed run."""
    import browser_core.product_observation as po

    def boom(*a, **k):
        raise OSError(r"no browser at C:\u\x.js with tiny-token")

    monkeypatch.setattr("browser_core.cdp.send_page_input_batch", boom)
    report = po._drive_input_probe("http://127.0.0.1:1/", "http://127.0.0.1:1/", 5.0)
    assert report["dispatched"] == 0
    assert report["errors"]
    assert r"C:\u\x.js" not in json.dumps(report)
    assert "tiny-token" not in json.dumps(report)
    assert report["profile"] == "probe"


def test_input_probe_declares_it_is_not_a_behaviour_model(monkeypatch):
    import browser_core.product_observation as po

    monkeypatch.setattr(
        "browser_core.cdp.send_page_input_batch",
        lambda *a, **k: {"dispatched": 18, "attempted": 18, "errors": []},
    )
    report = po._drive_input_probe("http://127.0.0.1:1/", "http://127.0.0.1:1/", 5.0)
    assert report["trusted"] is True
    assert report["touch_dispatched"] is False
    assert any("not a behaviour model" in claim for claim in report["non_claims"])
    assert any("touch is not dispatched" in claim for claim in report["non_claims"])


def test_scroll_probe_is_a_separate_fixed_wheel_profile(monkeypatch):
    import browser_core.product_observation as po

    seen = []

    def send(_endpoint, events, **_kwargs):
        seen.extend(events)
        return {"dispatched": len(events), "attempted": len(events), "errors": []}

    monkeypatch.setattr("browser_core.cdp.send_page_input_batch", send)
    report = po._drive_input_probe(
        "http://127.0.0.1:1/",
        "http://127.0.0.1:1/",
        5.0,
        profile="probe-scroll",
    )
    assert report["profile"] == "probe-scroll"
    assert report["scroll_commands_dispatched"] == 3
    assert [params["type"] for _, params in seen] == ["mouseWheel"] * 3
    assert all(method == "Input.dispatchMouseEvent" for method, _ in seen)


def test_touch_probe_is_a_separate_fixed_touch_sequence(monkeypatch):
    import browser_core.product_observation as po

    seen = []

    def send(_endpoint, events, **_kwargs):
        seen.extend(events)
        return {"dispatched": len(events), "attempted": len(events), "errors": []}

    monkeypatch.setattr("browser_core.cdp.send_page_input_batch", send)
    report = po._drive_input_probe(
        "http://127.0.0.1:1/",
        "http://127.0.0.1:1/",
        5.0,
        profile="probe-touch",
    )
    assert report["profile"] == "probe-touch"
    assert report["touch_dispatched"] is True
    assert [params["type"] for _, params in seen] == [
        "touchStart",
        "touchMove",
        "touchEnd",
    ]
    assert all(method == "Input.dispatchTouchEvent" for method, _ in seen)


def test_default_input_profile_leaves_the_run_unchanged():
    """`none` must remain the default so archived arms stay comparable."""
    import browser_core.product_observation as po

    config = po.ProductScriptObservation(
        script=Path("x.js"),
        label="l",
        executable=Path("c.exe"),
        trace_processor=Path("t.exe"),
        workspace=Path("."),
    )
    assert config.input_profile == "none"
    assert config.hook_mode == "off"


def test_await_trace_file_returns_once_the_file_settles(tmp_path):
    """The export race: `stop_session` returns before Chromium finishes flushing.

    Diagnosed 2026-08-07 after six consecutive arms failed with "Perfetto trace does
    not exist" while identical arms had succeeded minutes earlier: the browser
    launched fine (geometry read, requests served) and the trace simply had not
    landed yet. This is almost certainly the undiagnosed "batches drop arms"
    failure from session 2.
    """
    import threading
    import time as _time

    import browser_core.product_observation as po

    trace = tmp_path / "late.perfetto-trace"

    def write_later():
        _time.sleep(0.3)
        trace.write_bytes(b"x" * 1024)

    threading.Thread(target=write_later, daemon=True).start()
    assert po._await_trace_file(trace, 10.0, settle_seconds=0.1) is True
    assert trace.exists()


def test_await_trace_file_waits_for_the_size_to_stop_growing(tmp_path):
    """A partially written trace must not be exported as if it were complete."""
    import threading
    import time as _time

    import browser_core.product_observation as po

    trace = tmp_path / "growing.perfetto-trace"
    trace.write_bytes(b"a")

    def grow():
        for _ in range(5):
            _time.sleep(0.08)
            with trace.open("ab") as handle:
                handle.write(b"b" * 256)

    thread = threading.Thread(target=grow, daemon=True)
    thread.start()
    assert po._await_trace_file(trace, 10.0, settle_seconds=0.2) is True
    thread.join(timeout=5)
    # Settled only after growth stopped, so the whole file is present.
    assert trace.stat().st_size == 1 + 5 * 256


def test_await_trace_file_gives_up_rather_than_hanging(tmp_path):
    """A browser that never wrote a trace must fail the arm, not block the batch."""
    import time as _time

    import browser_core.product_observation as po

    started = _time.monotonic()
    assert po._await_trace_file(tmp_path / "never.perfetto-trace", 1.0) is False
    assert _time.monotonic() - started < 5.0


def test_trace_wait_is_bounded_below_the_run_timeout(monkeypatch, tmp_path):
    """A dead arm must not pay the whole run timeout before it is reported."""
    import time as _time

    import browser_core.product_observation as po

    monkeypatch.setattr(po, "TRACE_SETTLE_TIMEOUT", 0.3)
    started = _time.monotonic()
    assert po._await_trace_file(tmp_path / "absent.perfetto-trace", 600.0) is False
    assert _time.monotonic() - started < 3.0, "run timeout leaked into the trace wait"


def test_trace_wait_does_not_call_a_still_growing_file_settled(monkeypatch, tmp_path):
    """Existence at the deadline is not the same as a completed flush."""
    import browser_core.product_observation as po

    trace = tmp_path / "still-growing.perfetto-trace"
    trace.write_bytes(b"partial")
    monkeypatch.setattr(po, "TRACE_SETTLE_TIMEOUT", 0.2)

    assert po._await_trace_file(trace, 10.0, settle_seconds=1.0) is False
    assert po._trace_flush_receipt(trace, False) == {
        "status": "present-unsettled",
        "bytes": 7,
    }


def test_trace_wait_and_receipt_reject_an_additional_hard_link(monkeypatch, tmp_path):
    import browser_core.product_observation as po

    trace = tmp_path / "aliased.perfetto-trace"
    trace.write_bytes(b"trace")
    os.link(trace, tmp_path / "other-name.perfetto-trace")
    monkeypatch.setattr(po, "TRACE_SETTLE_TIMEOUT", 0.2)

    assert po._await_trace_file(trace, 10.0, settle_seconds=0.01) is False
    assert po._trace_flush_receipt(trace, False) == {
        "status": "present-unsettled",
        "bytes": None,
    }


def test_observation_reserves_a_longer_graceful_trace_flush_window(
    monkeypatch, tmp_path
):
    """The observation runner must not inherit the five-second force boundary."""
    import browser_core.product_observation as po

    seen: dict[str, object] = {}

    def stop(path, timeout_seconds, *, graceful_timeout_seconds):
        seen.update(
            path=path,
            timeout_seconds=timeout_seconds,
            graceful_timeout_seconds=graceful_timeout_seconds,
        )
        return {"state": "stopped"}

    monkeypatch.setattr(po, "stop_session", stop)
    assert po.TRACE_GRACEFUL_STOP_TIMEOUT > 5.0
    assert po._stop_observation_session(tmp_path / "session.json", 60.0) == {
        "state": "stopped"
    }
    assert seen == {
        "path": tmp_path / "session.json",
        "timeout_seconds": 60.0,
        "graceful_timeout_seconds": po.TRACE_GRACEFUL_STOP_TIMEOUT,
    }


def test_hook_target_subset_is_validated_and_filters(tmp_path):
    """Bisection needs subsets, and a typo must not silently install nothing."""
    from browser_core.argument_capture import HOOK_TARGETS
    from browser_core.product_observation import build_hook_payload

    full = build_hook_payload("on")
    subset = build_hook_payload("on", ("EventTarget.addEventListener",))
    assert len(subset) < len(full)
    assert b"addEventListener" in subset
    assert b"getShaderPrecisionFormat" not in subset
    assert len(HOOK_TARGETS) > 1

    with pytest.raises(ContractError, match="unknown hook target") as failure:
        build_hook_payload("on", ("EventTarget.addEventListener", "Nope.nope"))
    assert "Nope.nope" not in str(failure.value)


def test_hook_target_subset_is_ignored_when_capture_is_off():
    from browser_core.product_observation import build_hook_payload

    assert build_hook_payload("off", ("EventTarget.addEventListener",)) == b""
    assert build_hook_payload("inert", ("EventTarget.addEventListener",)) == b""


def test_an_unknown_inert_fidelity_target_is_rejected() -> None:
    from browser_core.product_observation import build_hook_payload

    with pytest.raises(ContractError, match="unknown hook target") as failure:
        build_hook_payload("inert", ("Typo.missing",))
    assert "Typo.missing" not in str(failure.value)


@pytest.mark.parametrize(
    "target_names",
    [None, True, 1, [], ["EventTarget.addEventListener"], {}, ({},)],
)
def test_hook_payload_rejects_malformed_target_containers_cleanly(
    target_names,
) -> None:
    from browser_core.product_observation import build_hook_payload

    with pytest.raises(ContractError, match="bounded tuple of strings"):
        build_hook_payload("on", target_names)


def test_hook_targets_are_rejected_when_hooking_is_off(tmp_path: Path) -> None:
    import browser_core.product_observation as po

    script = tmp_path / "s.js"
    script.write_bytes(b"// sample")
    with pytest.raises(ContractError, match="require hook mode"):
        po.run_product_script_observation(
            po.ProductScriptObservation(
                script=script,
                label="bad-method",
                executable=tmp_path / "chrome.exe",
                trace_processor=tmp_path / "tp.exe",
                workspace=tmp_path,
                hook_mode="off",
                hook_target_names=("Permissions.query",),
            ),
            tmp_path,
        )


def test_rehost_suppresses_only_expected_disconnect_tracebacks(monkeypatch):
    import browser_core.product_observation as po

    delegated = []
    monkeypatch.setattr(
        po.ThreadingHTTPServer,
        "handle_error",
        lambda self, request, address: delegated.append(
            type(__import__("sys").exc_info()[1])
        ),
    )
    server = object.__new__(po._QuietThreadingHTTPServer)

    try:
        raise ConnectionResetError("browser closed an idle socket")
    except ConnectionResetError:
        server.handle_error(None, ("127.0.0.1", 1))
    assert delegated == []

    try:
        raise RuntimeError("real handler defect")
    except RuntimeError:
        server.handle_error(None, ("127.0.0.1", 1))
    assert delegated == [RuntimeError]


def test_a_server_bind_failure_fails_one_arm_not_the_batch(tmp_path, monkeypatch):
    """Hit for real 2026-08-07: `WinError 10055` on bind killed a whole batch.

    The rehost server was constructed outside the try block, so an OSError from
    `bind()` propagated out of the runner and every queued arm was abandoned.
    """
    import browser_core.product_observation as po

    script = tmp_path / "s.js"
    script.write_bytes(b"// sample\n")

    def refuse(*args, **kwargs):
        raise OSError(10055, "An operation on a socket could not be performed")

    monkeypatch.setattr(po, "_QuietThreadingHTTPServer", refuse)
    result = po.run_product_script_observation(
        po.ProductScriptObservation(
            script=script,
            label="unbindable",
            executable=tmp_path / "c.exe",
            trace_processor=tmp_path / "tp.exe",
            workspace=tmp_path,
        ),
        tmp_path,
    )
    assert "analysis" not in result
    assert "could not bind" in result["error"]
    assert result["label"] == "unbindable"
    assert result["schema"] == po.OBSERVATION_SCHEMA


@pytest.mark.parametrize("failure_phase", ["construct", "start"])
def test_rehost_worker_start_failure_is_a_closed_failed_arm(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure_phase: str,
) -> None:
    import browser_core.product_observation as po

    script = tmp_path / "s.js"
    script.write_bytes(b"// sample\n")

    class Server:
        server_port = 12345

        def __init__(self, *_args, **_kwargs):  # noqa: ANN002, ANN003
            self.closed = False
            self.shutdown_called = False

        def serve_forever(self) -> None:
            return

        def shutdown(self) -> None:
            self.shutdown_called = True

        def server_close(self) -> None:
            self.closed = True

    class Worker:
        def start(self) -> None:
            raise OSError("private worker start")

    server = Server()
    monkeypatch.setattr(po, "_QuietThreadingHTTPServer", lambda *_a, **_k: server)

    def thread_factory(**_kwargs):  # noqa: ANN003
        if failure_phase == "construct":
            raise RuntimeError("private worker constructor")
        return Worker()

    monkeypatch.setattr(po, "Thread", thread_factory)

    result = po.run_product_script_observation(
        po.ProductScriptObservation(
            script=script,
            label="worker-failure",
            executable=tmp_path / "c.exe",
            trace_processor=tmp_path / "tp.exe",
            workspace=tmp_path,
        ),
        tmp_path,
    )

    assert result["error"].startswith("rehost server could not start:")
    assert "private" not in result["error"]
    assert "analysis" not in result
    assert server.closed is True
    assert server.shutdown_called is False


def test_rehost_retains_worker_after_start_reports_late_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import browser_core.product_observation as po

    script = tmp_path / "sample.js"
    script.write_bytes(b"// sample\n")

    class Server:
        server_port = 12345

        def serve_forever(self) -> None:
            return

    class Worker:
        alive = False

        def start(self) -> None:
            self.alive = True
            raise RuntimeError("late start failure")

        def is_alive(self) -> bool:
            return self.alive

    started: list[bool] = []
    monkeypatch.setattr(po, "_QuietThreadingHTTPServer", lambda *_a, **_k: Server())
    monkeypatch.setattr(po, "Thread", lambda **_kwargs: Worker())
    monkeypatch.setattr(
        po,
        "_stop_rehost_server",
        lambda *_args, **kwargs: started.append(kwargs["thread_started"]) or [],
    )
    result = po.run_product_script_observation(
        po.ProductScriptObservation(
            script=script,
            label="late-start",
            executable=tmp_path / "c.exe",
            trace_processor=tmp_path / "tp.exe",
            workspace=tmp_path,
        ),
        tmp_path,
    )
    assert result["error"].startswith("rehost server could not start:")
    assert started == [True]


def test_rehost_invalid_runtime_port_closes_as_a_failed_arm(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import browser_core.product_observation as po

    script = tmp_path / "s.js"
    script.write_bytes(b"// sample\n")

    class Server:
        server_port = True
        closed = False

        def server_close(self) -> None:
            self.closed = True

    server = Server()
    monkeypatch.setattr(po, "_QuietThreadingHTTPServer", lambda *_a, **_k: server)

    result = po.run_product_script_observation(
        po.ProductScriptObservation(
            script=script,
            label="bad-port",
            executable=tmp_path / "c.exe",
            trace_processor=tmp_path / "tp.exe",
            workspace=tmp_path,
        ),
        tmp_path,
    )

    assert result["error"].startswith("rehost server could not start:")
    assert server.closed is True


def test_rehost_cleanup_attempts_every_phase_after_failures() -> None:
    import browser_core.product_observation as po

    class Server:
        def shutdown(self) -> None:
            raise RuntimeError("private shutdown")

        def server_close(self) -> None:
            raise OSError("private close")

    class Worker:
        def is_alive(self) -> bool:
            return True

        def join(self, *, timeout: float) -> None:
            assert timeout == po.REHOST_SERVER_CLEANUP_TIMEOUT_SECONDS
            raise RuntimeError("private join")

    failures = po._stop_rehost_server(
        Server(),
        Worker(),
        thread_started=True,
    )

    assert failures == ["server-shutdown", "server-close", "worker-thread"]


def test_rehost_shutdown_retires_an_active_client() -> None:
    import browser_core.product_observation as po

    entered = threading.Event()

    class Handler(BaseHTTPRequestHandler):
        def setup(self) -> None:
            super().setup()
            entered.set()

        def do_GET(self) -> None:
            self.send_response(200)
            self.end_headers()

        def log_message(self, *_args) -> None:  # type: ignore[no-untyped-def]
            return

    server = po._QuietThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    client = None
    try:
        client = socket.create_connection(server.server_address, timeout=1)
        client.settimeout(1)
        client.sendall(b"GET / HTTP/1.1\r\nHost: localhost\r\n")
        assert entered.wait(1)
        assert po._stop_rehost_server(server, worker, thread_started=True) == []
        try:
            closed = client.recv(1)
        except TimeoutError:
            pytest.fail("rehost left an active client open after shutdown")
        except OSError:
            pass
        else:
            assert closed == b""
    finally:
        if client is not None:
            client.close()
        server.server_close()
        worker.join(timeout=1)


def test_rehost_shutdown_is_bounded_and_still_closes_and_joins(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import browser_core.product_observation as po

    release = threading.Event()

    class Server:
        closed = False

        def shutdown(self) -> None:
            release.wait(5)

        def server_close(self) -> None:
            self.closed = True
            release.set()

    class Worker:
        joined = False

        def is_alive(self) -> bool:
            return not self.joined

        def join(self, *, timeout: float) -> None:
            self.joined = True

    server = Server()
    worker = Worker()
    monkeypatch.setattr(po, "REHOST_SERVER_CLEANUP_TIMEOUT_SECONDS", 0.01)
    started = time.monotonic()

    failures = po._stop_rehost_server(
        server,
        worker,
        thread_started=True,
    )

    assert time.monotonic() - started < 0.5
    assert failures == ["server-shutdown"]
    assert server.closed is True
    assert worker.joined is True


def test_rehost_reclaims_shutdown_thread_after_late_start_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import browser_core.product_observation as po

    release = threading.Event()
    threads: list[object] = []
    real_thread = threading.Thread

    class Server:
        closed = False

        def shutdown(self) -> None:
            release.wait(1)

        def server_close(self) -> None:
            self.closed = True
            release.set()

    class ShutdownThread:
        joined = False

        def __init__(self, *, target, name, daemon):  # noqa: ANN001
            self.worker = real_thread(target=target, name=name, daemon=daemon)
            threads.append(self)

        def start(self) -> None:
            self.worker.start()
            raise RuntimeError("late start error")

        def is_alive(self) -> bool:
            return self.worker.is_alive()

        def join(self, *, timeout: float) -> None:
            self.joined = True
            self.worker.join(timeout=timeout)

    class Worker:
        joined = False

        def is_alive(self) -> bool:
            return not self.joined

        def join(self, *, timeout: float) -> None:
            self.joined = True

    monkeypatch.setattr(po, "Thread", ShutdownThread)
    monkeypatch.setattr(po, "REHOST_SERVER_CLEANUP_TIMEOUT_SECONDS", 0.1)
    server = Server()
    worker = Worker()
    failures = po._stop_rehost_server(server, worker, thread_started=True)

    assert failures == ["server-shutdown"]
    assert server.closed is True
    assert worker.joined is True
    assert threads[0].joined is True
    assert threads[0].is_alive() is False


def test_rehost_cleanup_failure_blocks_trace_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import browser_core.product_observation as po

    script = tmp_path / "s.js"
    script.write_bytes(b"// sample\n")

    class Server:
        server_port = 12345

        def serve_forever(self) -> None:
            return

    class Worker:
        def start(self) -> None:
            return

    monkeypatch.setattr(po, "_QuietThreadingHTTPServer", lambda *_a, **_k: Server())
    monkeypatch.setattr(po, "Thread", lambda **_kwargs: Worker())
    monkeypatch.setattr(
        po,
        "launch_evaluation",
        lambda *_a, **_k: (_ for _ in ()).throw(
            RuntimeError("private execution failure")
        ),
    )
    monkeypatch.setattr(
        po,
        "_stop_rehost_server",
        lambda *_a, **_k: ["server-close", "worker-thread"],
    )
    trace_contact: list[bool] = []
    monkeypatch.setattr(
        po,
        "export_perfetto",
        lambda *_a, **_k: trace_contact.append(True),
    )

    result = po.run_product_script_observation(
        po.ProductScriptObservation(
            script=script,
            label="cleanup-failure",
            executable=tmp_path / "c.exe",
            trace_processor=tmp_path / "tp.exe",
            workspace=tmp_path,
        ),
        tmp_path,
    )

    assert (
        result["error"] == "rehost server cleanup failed (server-close,worker-thread)"
    )
    assert "analysis" not in result
    assert trace_contact == []


def test_unverified_session_stop_blocks_trace_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import browser_core.product_observation as po

    script = tmp_path / "s.js"
    script.write_bytes(b"// sample\n")
    trace = tmp_path / "trace.perfetto"
    trace.write_bytes(b"trace")
    monkeypatch.setattr(po, "_QuietThreadingHTTPServer", _FakeServer)
    monkeypatch.setattr(
        po,
        "launch_evaluation",
        lambda *_a, **_k: (
            tmp_path / "session.json",
            {
                "run_id": "r1",
                "chromium_revision": "a" * 40,
                "trace_path": str(trace),
                "automation": {"cdp_endpoint": "http://127.0.0.1:9"},
            },
        ),
    )
    monkeypatch.setattr(
        po,
        "wait_for_page_target",
        lambda *_a, **_k: (_ for _ in ()).throw(RuntimeError("private page failure")),
    )
    monkeypatch.setattr(
        po,
        "_stop_observation_session",
        lambda *_a, **_k: {
            **_stopped_receipt(),
            "state": "active",
            "running": True,
        },
    )
    trace_contact: list[bool] = []
    monkeypatch.setattr(
        po,
        "_await_trace_file",
        lambda *_a, **_k: trace_contact.append(True),
    )

    result = po.run_product_script_observation(
        po.ProductScriptObservation(
            script=script,
            label="unverified-stop",
            executable=tmp_path / "c.exe",
            trace_processor=tmp_path / "tp.exe",
            workspace=tmp_path,
        ),
        tmp_path,
    )

    assert result["error"].startswith("observation stop failed: ContractError;")
    assert "analysis" not in result
    assert trace_contact == []


def test_a_bind_failure_is_auditable_as_a_failed_arm(tmp_path, monkeypatch):
    """It must be countable by batch-audit, not merely absent from the directory."""
    import browser_core.product_observation as po
    from browser_core.observation_digest import audit_batch

    script = tmp_path / "s.js"
    script.write_bytes(b"// sample\n")
    monkeypatch.setattr(
        po,
        "_QuietThreadingHTTPServer",
        lambda *a, **k: (_ for _ in ()).throw(OSError(10055, "no buffer space")),
    )
    failed = po.run_product_script_observation(
        po.ProductScriptObservation(
            script=script,
            label="dead",
            executable=tmp_path / "c.exe",
            trace_processor=tmp_path / "tp.exe",
            workspace=tmp_path,
        ),
        tmp_path,
    )
    report = audit_batch({"dead": failed})
    assert report["failed"] == 1
    assert report["trustworthy"] is False
    assert "rehost server could not bind" in next(iter(report["failure_reasons"]))


def test_a_blocked_renderer_is_distinguished_from_a_dead_browser() -> None:
    """The two failures call for opposite responses.

    The target list is served by the browser process, so it answers while a
    renderer is wedged. Browser alive and page unresponsive means the collector is
    still holding the main thread and the arm needed a longer dwell; browser gone
    means the run died and the surface is not evidence. Measured on the Kasada
    interrogation stage, which holds the thread for ~102 seconds untraced.
    """
    blocked = grade_collector_startup(
        {
            "probe_error": "ContractError: cannot use loopback CDP (TimeoutError)",
            "renderer_blocked": True,
        },
        attributable_events=24,
    )
    assert blocked["started"] is None
    assert "longer dwell" in blocked["reasons"][0]

    dead = grade_collector_startup(
        {
            "probe_error": "ContractError: cannot use loopback CDP (TimeoutError)",
            "renderer_blocked": False,
        },
        attributable_events=24,
    )
    assert dead["started"] is None
    assert "not evidence" in dead["reasons"][0]


def test_startup_failure_requires_the_exact_managed_target_for_blocked_claim() -> None:
    blocked = grade_collector_startup(
        {
            "probe_error": "execution-failure; diagnostic_sha256_16=0",
            "renderer_blocked": True,
            "browser_target_status": "present",
            "browser_target_title_matches": False,
        },
        attributable_events=24,
    )
    assert "exact managed page" in blocked["reasons"][0]
    assert "longer dwell" in blocked["reasons"][0]
    assert blocked["renderer_blocked"] is True
    assert blocked["browser_target_status"] == "present"
    assert blocked["browser_target_title_matches"] is False

    absent = grade_collector_startup(
        {
            "probe_error": "execution-failure; diagnostic_sha256_16=1",
            "renderer_blocked": False,
            "browser_target_status": "absent",
            "browser_target_title_matches": None,
        },
        attributable_events=24,
    )
    assert "browser process answered" in absent["reasons"][0]
    assert "managed page was absent" in absent["reasons"][0]
    assert "not evidence" in absent["reasons"][0]

    unavailable = grade_collector_startup(
        {
            "probe_error": "execution-failure; diagnostic_sha256_16=2",
            "renderer_blocked": None,
            "browser_target_status": "invalid-response",
            "browser_target_title_matches": None,
        },
        attributable_events=24,
    )
    assert "diagnostic was unavailable" in unavailable["reasons"][0]
    assert "longer dwell" not in unavailable["reasons"][0]


def test_startup_probe_failure_uses_the_value_free_managed_target_receipt(
    monkeypatch,
) -> None:
    import browser_core.product_observation as po

    monkeypatch.setattr(
        po,
        "evaluate_page_expression",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            po.CdpCommandResponseTimeout("private page diagnostic")
        ),
    )
    monkeypatch.setattr(
        po,
        "probe_managed_page_target",
        lambda *_args, **_kwargs: {
            "status": "present",
            "title_matches": False,
        },
    )

    result = po._capture_startup(
        "http://127.0.0.1:9222",
        "http://127.0.0.1:8000/owned",
        1,
    )

    assert result is not None
    assert result["renderer_blocked"] is True
    assert result["browser_target_status"] == "present"
    assert result["browser_target_title_matches"] is False
    assert "private" not in json.dumps(result)
    graded = grade_collector_startup(result, attributable_events=24)
    assert graded["reasons"][0].count("startup probe failed:") == 1


def test_non_timeout_startup_failure_does_not_claim_a_blocked_renderer(
    monkeypatch,
) -> None:
    import browser_core.product_observation as po

    monkeypatch.setattr(
        po,
        "evaluate_page_expression",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            ContractError("private malformed CDP response")
        ),
    )
    monkeypatch.setattr(
        po,
        "probe_managed_page_target",
        lambda *_args, **_kwargs: {
            "status": "present",
            "title_matches": True,
        },
    )

    result = po._capture_startup(
        "http://127.0.0.1:9222",
        "http://127.0.0.1:8000/owned",
        1,
    )

    assert result is not None
    assert result["renderer_blocked"] is None
    assert result["browser_target_status"] == "present"
    assert "private" not in json.dumps(result)
    graded = grade_collector_startup(result, attributable_events=24)
    assert "longer dwell" not in graded["reasons"][0]
    assert "not evidence" not in graded["reasons"][0]


def test_an_unanswerable_diagnostic_is_not_reported_as_a_dead_browser() -> None:
    """None is not False. A question that could not be asked has no answer."""
    verdict = grade_collector_startup(
        {"probe_error": "ContractError: x", "renderer_blocked": None},
        attributable_events=0,
    )
    assert verdict["started"] is None
    assert "longer dwell" not in verdict["reasons"][0]
    assert "not evidence" not in verdict["reasons"][0]


# -- waiting for the thing, instead of sleeping ---------------------------------
#
# `dwell_seconds` is a sleep, and a sleep cannot tell you whether what it waited
# for happened. Measured: 20-second and 150-second dwells produced byte-identical
# counts on a driven Kasada arm (3,377 events, 221 API names, 24 attributable),
# while the readback fired mid-solve. With the wait, the same arm headless reports
# ended_on "ready" after 110.8 s and attributes 29 names.


def test_the_wait_rejects_a_nonsense_cap() -> None:
    with pytest.raises(ContractError):
        await_collector_ready(
            "http://127.0.0.1:1/",
            "http://127.0.0.1:2/",
            cap_seconds=0,
            poll_timeout_seconds=1,
        )


@pytest.mark.parametrize("invalid", [float("nan"), float("inf"), True, "1"])
def test_readiness_wait_rejects_non_finite_cap_or_poll_timeout(invalid) -> None:
    with pytest.raises(ContractError, match="finite and positive"):
        await_collector_ready(
            "http://127.0.0.1:1/",
            "http://127.0.0.1:2/",
            cap_seconds=invalid,
            poll_timeout_seconds=1,
        )
    with pytest.raises(ContractError, match="finite and positive"):
        await_collector_ready(
            "http://127.0.0.1:1/",
            "http://127.0.0.1:2/",
            cap_seconds=1,
            poll_timeout_seconds=invalid,
        )


@pytest.mark.parametrize(
    ("cap_seconds", "poll_timeout_seconds", "message"),
    [
        (86_401.0, 1.0, "await cap"),
        (1.0, 301.0, "readiness poll timeout"),
    ],
)
def test_readiness_wait_rejects_budgets_its_dependencies_cannot_honor(
    monkeypatch,
    cap_seconds: float,
    poll_timeout_seconds: float,
    message: str,
) -> None:
    import browser_core.product_observation as po

    monkeypatch.setattr(
        po,
        "evaluate_page_expression",
        lambda *_args, **_kwargs: pytest.fail("invalid budget reached CDP"),
    )

    with pytest.raises(ContractError, match=message):
        await_collector_ready(
            "http://127.0.0.1:1/",
            "http://127.0.0.1:2/",
            cap_seconds=cap_seconds,
            poll_timeout_seconds=poll_timeout_seconds,
        )


def test_a_custom_boolean_readiness_signal_is_polled(monkeypatch) -> None:
    import browser_core.product_observation as po

    expressions: list[str] = []

    def evaluate(_endpoint, expression, **_kwargs):
        expressions.append(expression)
        return json.dumps({"ready": True, "t": 0})

    monkeypatch.setattr(po, "evaluate_page_expression", evaluate)
    clock = iter([0.0, 0.0, 0.4])
    monkeypatch.setattr(po.time, "monotonic", lambda: next(clock))
    report = await_collector_ready(
        "http://127.0.0.1:1/",
        "http://127.0.0.1:2/",
        cap_seconds=10,
        poll_timeout_seconds=1,
        ready_expression="window.__bc_collector_done === true",
    )
    assert report["ended_on"] == "expression_true"
    assert report["waited_seconds"] == 0.4
    assert report["signal_kind"] == "operator_expression"
    assert report["slowest_poll"]["outcome"] == "expression_true"
    assert "window.__bc_collector_done === true" in expressions[0]
    assert "token" not in report


def test_a_custom_readiness_signal_is_bounded() -> None:
    with pytest.raises(ContractError, match="bounded"):
        await_collector_ready(
            "http://127.0.0.1:1/",
            "http://127.0.0.1:2/",
            cap_seconds=1,
            poll_timeout_seconds=1,
            ready_expression="x" * 20_000,
        )


def test_readiness_limit_counts_utf8_bytes_not_python_characters() -> None:
    with pytest.raises(ContractError, match="16384 bytes"):
        await_collector_ready(
            "http://127.0.0.1:1/",
            "http://127.0.0.1:2/",
            cap_seconds=1,
            poll_timeout_seconds=1,
            ready_expression="😀" * 4_097,
        )


def test_a_page_with_no_readiness_signal_does_not_burn_the_cap(monkeypatch) -> None:
    """The poller documentation promised `no_signal`; the implementation did not."""
    import browser_core.product_observation as po

    monkeypatch.setattr(
        po,
        "evaluate_page_expression",
        lambda *_args, **_kwargs: json.dumps({"ready": None, "t": 0}),
    )
    clock = iter([0.0, 0.0, 0.2])
    monkeypatch.setattr(po.time, "monotonic", lambda: next(clock))
    report = await_collector_ready(
        "http://127.0.0.1:1/",
        "http://127.0.0.1:2/",
        cap_seconds=300,
        poll_timeout_seconds=1,
    )
    assert report["ended_on"] == "no_signal"
    assert report["waited_seconds"] == 0.2
    assert report["slowest_poll"]["outcome"] == "no_signal"


def test_an_arm_that_ran_out_of_budget_says_so(monkeypatch) -> None:
    """`cap` and `ready` are different measurements and must not look alike.

    An arm that ended on the cap observed a collector mid-flight. Reporting that
    as a completed observation is the same class of error as reporting a script
    that threw as a quiet one.
    """
    import browser_core.product_observation as po

    monkeypatch.setattr(po.time, "sleep", lambda _s: None)
    monkeypatch.setattr(
        po,
        "evaluate_page_expression",
        lambda *a, **k: json.dumps({"ready": False, "t": 0}),
    )
    clock = iter([0.0, 0.0, 0.25, 1.0, 1.5, 2.0, 2.25, 5.0])
    monkeypatch.setattr(po.time, "monotonic", lambda: next(clock))

    report = await_collector_ready("e", "u", cap_seconds=5.0, poll_timeout_seconds=1.0)
    assert report["ended_on"] == "cap"
    assert report["page_ever_answered"] is True
    assert report["poll_timeout_seconds"] == 1.0
    assert report["slowest_poll"] == {
        "issued_at_seconds": 1.0,
        "duration_seconds": 0.5,
        "outcome": "not_ready",
    }


def test_a_ready_client_stops_the_wait_immediately(monkeypatch) -> None:
    import browser_core.product_observation as po

    monkeypatch.setattr(po.time, "sleep", lambda _s: None)
    monkeypatch.setattr(
        po,
        "evaluate_page_expression",
        lambda *a, **k: json.dumps({"ready": True, "t": 0}),
    )
    clock = iter([0.0, 2.0, 103.766])
    monkeypatch.setattr(po.time, "monotonic", lambda: next(clock))

    report = await_collector_ready(
        "e", "u", cap_seconds=300.0, poll_timeout_seconds=1.0
    )
    assert report["ended_on"] == "ready"
    assert report["polls"] == 1
    assert report["waited_seconds"] == 103.8
    assert report["slowest_poll"] == {
        "issued_at_seconds": 2.0,
        "duration_seconds": 101.766,
        "outcome": "ready",
    }


def test_a_ready_signal_returned_after_the_cap_is_not_called_success(
    monkeypatch,
) -> None:
    import browser_core.product_observation as po

    seen_timeouts = []

    def evaluate(*_args, **kwargs):
        seen_timeouts.append(kwargs["timeout_seconds"])
        return json.dumps({"ready": True, "t": 0})

    monkeypatch.setattr(po, "evaluate_page_expression", evaluate)
    clock = iter([0.0, 4.8, 5.2])
    monkeypatch.setattr(po.time, "monotonic", lambda: next(clock))

    report = await_collector_ready("e", "u", cap_seconds=5.0, poll_timeout_seconds=1.0)

    assert seen_timeouts[0] == pytest.approx(0.2)
    assert report["ended_on"] == "cap"
    assert report["waited_seconds"] == 5.2
    assert report["slowest_poll"]["outcome"] == "ready"


def test_an_unresponsive_poll_is_counted_not_raised(monkeypatch) -> None:
    """A wedged renderer is the normal case here, not an error.

    The collector this was built for holds the main thread for ~102 seconds, so
    polls that time out are the expected shape of a healthy wait.
    """
    import browser_core.product_observation as po

    def boom(*_a, **_k):
        raise po.CdpCommandResponseTimeout("CDP command response deadline expired")

    monkeypatch.setattr(po.time, "sleep", lambda _s: None)
    monkeypatch.setattr(po, "evaluate_page_expression", boom)
    clock = iter([0.0, 0.0, 1.25, 2.0, 3.0, 5.0])
    monkeypatch.setattr(po.time, "monotonic", lambda: next(clock))

    report = await_collector_ready("e", "u", cap_seconds=5.0, poll_timeout_seconds=1.0)
    assert report["ended_on"] == "cap"
    assert report["unresponsive_polls"] >= 1
    assert report["failed_polls"] == 0
    assert report["page_ever_answered"] is False
    assert report["slowest_poll"] == {
        "issued_at_seconds": 0.0,
        "duration_seconds": 1.25,
        "outcome": "unresponsive",
    }


def test_non_timeout_readiness_failure_is_not_called_unresponsive(monkeypatch) -> None:
    import browser_core.product_observation as po

    def boom(*_a, **_k):
        raise ContractError("private malformed readiness response")

    monkeypatch.setattr(po.time, "sleep", lambda _s: None)
    monkeypatch.setattr(po, "evaluate_page_expression", boom)
    clock = iter([0.0, 0.0, 1.25, 2.0, 3.0, 5.0])
    monkeypatch.setattr(po.time, "monotonic", lambda: next(clock))

    report = await_collector_ready("e", "u", cap_seconds=5.0, poll_timeout_seconds=1.0)

    assert report["ended_on"] == "cap"
    assert report["unresponsive_polls"] == 0
    assert report["failed_polls"] >= 1
    assert report["page_ever_answered"] is False
    assert report["slowest_poll"] == {
        "issued_at_seconds": 0.0,
        "duration_seconds": 1.25,
        "outcome": "failed",
    }
    assert "private" not in json.dumps(report)


def test_readiness_failure_at_cap_returns_without_an_extra_sleep(monkeypatch) -> None:
    import browser_core.product_observation as po

    sleeps: list[float] = []
    monkeypatch.setattr(po.time, "sleep", sleeps.append)
    monkeypatch.setattr(
        po,
        "evaluate_page_expression",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            po.CdpCommandResponseTimeout("CDP command response deadline expired")
        ),
    )
    clock = iter([0.0, 4.9, 5.1, 6.1])
    monkeypatch.setattr(po.time, "monotonic", lambda: next(clock))

    report = await_collector_ready("e", "u", cap_seconds=5.0, poll_timeout_seconds=1.0)

    assert report["ended_on"] == "cap"
    assert report["waited_seconds"] == 5.1
    assert sleeps == []


def test_readiness_retry_sleep_is_bounded_by_remaining_cap(monkeypatch) -> None:
    import browser_core.product_observation as po

    sleeps: list[float] = []
    monkeypatch.setattr(po.time, "sleep", sleeps.append)
    monkeypatch.setattr(
        po,
        "evaluate_page_expression",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            ContractError("private failed poll")
        ),
    )
    clock = iter([0.0, 4.8, 4.9, 5.0])
    monkeypatch.setattr(po.time, "monotonic", lambda: next(clock))

    report = await_collector_ready("e", "u", cap_seconds=5.0, poll_timeout_seconds=1.0)

    assert report["ended_on"] == "cap"
    assert sleeps == [pytest.approx(0.1)]


def _collector_that_reads_stack_traces() -> bytes:
    r"""A collector whose error reporter knows what a webpack URL looks like.

    Modelled on PerimeterX's px.main.min.js, which carries
    `(?:file|https?|blob|chrome|webpack|\[native)` to parse stack traces. Naming a
    bundler is not being one, and a substring test cannot tell the difference.
    """
    body = "function p(){var s='" + ("y" * 60_000) + "';}" * 3
    body += "function q(){}" * 500
    body += 'var re=new RegExp("^\\s*at (?:(.+) )?\\(?((?:file|https?|blob|chrome|webpack):.*?)\\)?$","i");'
    body += "var mod=require('nothing');"  # ordinary JavaScript, not a bundle
    return body.encode("utf-8")


def test_a_collector_that_merely_mentions_a_bundler_is_not_one() -> None:
    """The false negative the first version of this veto produced.

    PerimeterX's 233 KB collector was rejected as a "module-bundler artifact"
    because its stack-trace parser contains the word webpack inside a regex, and
    because `require(` -- ordinary JavaScript -- was on the marker list.
    """
    verdict = classify_product_script(_collector_that_reads_stack_traces())
    assert verdict["looks_like_built_antibot_script"] is True, verdict["reasons"]
    assert verdict["signals"]["bundler_markers"] == 0


def test_every_veto_marker_is_a_token_a_module_runtime_emits() -> None:
    """A lock on the distinction, so the list cannot drift back to loose words.

    Bare `webpack` and bare `require(` are what a bundler is *associated with*.
    `__webpack_require__` is what a module runtime writes. A source-map trailer is
    only packaging metadata and is deliberately reported without becoming a veto.
    """
    from browser_core.product_observation import BUNDLER_MARKERS

    assert "webpack" not in BUNDLER_MARKERS
    assert "require(" not in BUNDLER_MARKERS
    assert "__webpack_require__" in BUNDLER_MARKERS
    assert "//# sourceMappingURL=" not in BUNDLER_MARKERS
    for marker in BUNDLER_MARKERS:
        assert (
            len(marker) >= 12
        ), f"marker too generic to be a bundler token: {marker!r}"


def test_a_source_map_trailer_is_reported_but_is_not_a_bundle_veto() -> None:
    verdict = classify_product_script(
        _built_antibot_like() + b"\n//# sourceMappingURL=collector.js.map\n"
    )

    assert verdict["signals"]["source_map_markers"] == 1
    assert verdict["signals"]["bundler_markers"] == 0
    assert verdict["looks_like_built_antibot_script"] is True


def test_a_real_next_chunk_is_still_rejected() -> None:
    """The tightening must not cost the true positives it was built for."""
    verdict = classify_product_script(_next_chunk_like())
    assert verdict["looks_like_built_antibot_script"] is False
    assert any("bundler artifact" in reason for reason in verdict["reasons"])


def test_the_shape_hint_is_a_hint_and_absence_rejects_nothing() -> None:
    """Shape's inline deployment opens with `window['istlWasHere'] = true;`.

    Found in 4 of 4 Shape captures here and 0 files under akamai-web or kasada --
    but all four are Nordstrom-family, so it may be per-deployment rather than
    vendor-wide. A collector without it is still a collector.
    """
    body = "window['istlWasHere'] = true;" + _built_antibot_like(bmak=0).decode("utf-8")
    verdict = classify_product_script(body.encode("utf-8"))
    assert verdict["vendor_hint"] == "shape"
    assert verdict["looks_like_built_antibot_script"] is True

    without = classify_product_script(_built_antibot_like(bmak=0))
    assert without["vendor_hint"] is None
    assert without["looks_like_built_antibot_script"] is True


# -- a stability property that was only ever true of one vendor -----------------
#
# The gate rests on "the collector barely moves, so movement is signal", measured
# on Akamai. Same script, same settings, back-to-back arms on this host:
#
#   Akamai BM web    3 arms, 121 names each,        pairwise difference 0
#   Kasada driven    2 arms,  29 names each,        pairwise difference 0
#   Shape Nordstrom  3 arms, 1041/1047/1042 names,  pairwise 10 / 11 / 9
#
# Shape carries 15 volatile names out of a 1,051 union, so a hand-set tolerance of
# 1 fails constantly on noise there and could never see a two-name roll change
# underneath an eleven-name floor.


def _sub(names, label="a", clean=True):
    return {
        "schema": SUBTRACTION_SCHEMA,
        "generated_at": "2026-08-12T01:02:03Z",
        "non_claims": [
            "control subtraction attributes API names in a lab rehost only",
            "not an acceptance, bypass, evasion, or bot-score claim",
        ],
        "only_in_arm": sorted(names),
        "clean_subtraction": clean,
        "arm_label": label,
        "arm_script_sha256_16": "0" * 16,
        "control_label": "control",
    }


def test_a_baseline_from_repeats_measures_its_own_noise_floor() -> None:
    base = {f"api.X{i}" for i in range(20)}
    arms = [_sub(base), _sub(base | {"api.Flaky"}), _sub(base | {"api.Other"})]
    b = build_repeated_surface_baseline(arms, label="v")
    assert b["api_name_count"] == 20  # stable core, present in every arm
    assert sorted(b["volatile_api_names"]) == ["api.Flaky", "api.Other"]
    assert b["measured_noise_floor"] == 2  # worst observed pair
    assert b["arms"] == 3


def test_a_deterministic_vendor_measures_a_floor_of_zero() -> None:
    """Akamai and driven Kasada both do this; the floor is a measurement, not a
    concession, and it should read zero when the surface really is stable."""
    names = {f"api.X{i}" for i in range(121)}
    b = build_repeated_surface_baseline([_sub(names), _sub(names), _sub(names)])
    assert b["measured_noise_floor"] == 0
    assert b["volatile_api_names"] == []


def _request_subtraction(
    body_bytes: int,
    *,
    include: bool = True,
    body_digest: str | None = None,
) -> dict:
    subtraction = _sub({"api.X"})
    subtraction["request_activity"] = {
        "status": "ok",
        "only_in_arm": (
            [
                {
                    "method": "POST",
                    "served": "post-ack",
                    "path_segment_lengths": [13],
                    "path_segments_truncated": False,
                    "query_names": [],
                    "query_names_truncated": False,
                    "count": 1,
                    "body_bytes_total": body_bytes,
                    "body_bytes_min": body_bytes,
                    "body_bytes_max": body_bytes,
                    **(
                        {"body_sha256_16_counts": {body_digest: 1}}
                        if body_digest is not None
                        else {}
                    ),
                }
            ]
            if include
            else []
        ),
    }
    return subtraction


def _sealed_current_request_subtraction(
    body_bytes: int,
    *,
    include: bool = True,
    body_digest: str | None = None,
) -> dict:
    subtraction = _request_subtraction(
        body_bytes, include=include, body_digest=body_digest
    )
    rows = subtraction["request_activity"]["only_in_arm"]
    subtraction["request_activity"] = subtract_request_activity(
        {"status": "ok", "rows": rows},
        {"status": "ok", "rows": []},
    )
    return product_observation._seal_subtraction_document(subtraction)


def test_repeated_baseline_measures_request_size_jitter_separately() -> None:
    baseline = build_repeated_surface_baseline(
        [_request_subtraction(4811), _request_subtraction(4849)]
    )
    request_floor = baseline["request_activity_baseline"]

    assert baseline["measured_noise_floor"] == 0
    assert request_floor["status"] == "ok"
    assert request_floor["stable_shapes"] == 1
    assert request_floor["variable_shapes"] == 1
    row = request_floor["rows"][0]
    assert row["body_bytes_total_min"] == 4811
    assert row["body_bytes_total_max"] == 4849
    assert row["varies"] is True
    assert "body bytes" in request_floor["non_claim"]


def test_repeated_request_baseline_marks_shape_presence_jitter() -> None:
    baseline = build_repeated_surface_baseline(
        [_request_subtraction(100), _request_subtraction(0, include=False)]
    )
    request_floor = baseline["request_activity_baseline"]

    assert request_floor["stable_shapes"] == 0
    assert request_floor["union_shapes"] == 1
    assert request_floor["variable_shapes"] == 1
    assert request_floor["rows"][0]["arms_present"] == 1


def test_repeated_request_baseline_detects_same_length_body_inequality() -> None:
    baseline = build_repeated_surface_baseline(
        [
            _request_subtraction(4811, body_digest="a" * 16),
            _request_subtraction(4811, body_digest="b" * 16),
        ]
    )
    request_floor = baseline["request_activity_baseline"]
    row = request_floor["rows"][0]

    assert request_floor["variable_shapes"] == 1
    assert row["body_digest_coverage_min"] == 1
    assert row["body_digest_coverage_max"] == 1
    assert row["body_digest_multiset_varies"] is True
    assert row["varies"] is True
    assert "field semantics" in request_floor["non_claim"]


def test_repeated_request_baseline_detects_exact_body_reuse() -> None:
    baseline = build_repeated_surface_baseline(
        [
            _request_subtraction(4811, body_digest="a" * 16),
            _request_subtraction(4811, body_digest="a" * 16),
        ]
    )
    row = baseline["request_activity_baseline"]["rows"][0]

    assert row["body_digest_multiset_varies"] is False
    assert row["body_digest_multiset_sha256"] == hashlib.sha256(
        b'{"aaaaaaaaaaaaaaaa":1}'
    ).hexdigest()
    assert row["varies"] is False


def test_drift_rejects_a_different_complete_body_multiset() -> None:
    baseline = build_repeated_surface_baseline(
        [
            _request_subtraction(4811, body_digest="a" * 16),
            _request_subtraction(4811, body_digest="a" * 16),
        ]
    )

    result = check_surface_drift(
        _request_subtraction(4811, body_digest="b" * 16), baseline
    )

    outlier = result["request_activity_drift"]["metric_outliers"][0]
    assert outlier["fields"] == ["body_digest_multiset"]
    assert result["request_activity_drift"]["passed"] is False
    assert result["passed"] is False


def test_drift_accepts_the_same_complete_body_multiset() -> None:
    baseline = build_repeated_surface_baseline(
        [
            _request_subtraction(4811, body_digest="a" * 16),
            _request_subtraction(4811, body_digest="a" * 16),
        ]
    )

    result = check_surface_drift(
        _sealed_current_request_subtraction(4811, body_digest="a" * 16),
        baseline,
    )

    assert result["request_activity_drift"]["metric_outliers"] == []
    assert result["request_activity_drift"]["passed"] is True
    assert result["passed"] is True


def test_request_activity_baseline_binds_its_redacted_receipt() -> None:
    receipt = build_repeated_surface_baseline(
        [
            _request_subtraction(4811, body_digest="a" * 16),
            _request_subtraction(4811, body_digest="a" * 16),
        ]
    )["request_activity_baseline"]

    assert re.fullmatch(r"[0-9a-f]{64}", receipt["receipt_sha256"])
    assert product_observation._sanitize_request_activity_baseline(receipt) == receipt


def test_drift_rejects_a_coherent_edit_to_the_request_floor() -> None:
    baseline = build_repeated_surface_baseline(
        [
            _request_subtraction(4811, body_digest="a" * 16),
            _request_subtraction(4811, body_digest="a" * 16),
        ]
    )
    baseline["request_activity_baseline"]["rows"][0][
        "body_digest_multiset_sha256"
    ] = "b" * 64

    with pytest.raises(ContractError, match="request activity baseline"):
        check_surface_drift(
            _request_subtraction(4811, body_digest="b" * 16), baseline
        )


def test_repeated_request_baseline_fails_closed_on_a_truncated_arm() -> None:
    first = _request_subtraction(100)
    second = _request_subtraction(100)
    first["request_activity"]["truncated"] = True

    baseline = build_repeated_surface_baseline([first, second])

    assert baseline["request_activity_baseline"]["status"] == "unverifiable"


def test_drift_rejects_an_edited_request_activity_baseline_population() -> None:
    baseline = build_repeated_surface_baseline(
        [_request_subtraction(4811), _request_subtraction(4849)]
    )
    baseline["request_activity_baseline"]["stable_shapes"] = 2

    with pytest.raises(ContractError, match="request activity baseline"):
        check_surface_drift(_sub({"api.X"}), baseline)


def test_request_activity_baseline_sanitizer_rejects_reversed_ranges() -> None:
    baseline = build_repeated_surface_baseline(
        [_request_subtraction(4811), _request_subtraction(4849)]
    )["request_activity_baseline"]
    baseline["rows"][0]["count_min"] = 2
    baseline["rows"][0]["count_max"] = 1

    safe = product_observation._sanitize_request_activity_baseline(baseline)

    assert safe["status"] == "unverifiable"
    assert "rows" not in safe


def test_drift_rejects_request_metrics_outside_the_measured_envelope() -> None:
    baseline = build_repeated_surface_baseline(
        [_request_subtraction(4811), _request_subtraction(4849)]
    )

    result = check_surface_drift(_request_subtraction(6000), baseline)

    request_drift = result["request_activity_drift"]
    assert request_drift["comparable"] is True
    assert request_drift["passed"] is False
    assert request_drift["metric_outliers"][0]["fields"] == [
        "body_bytes_max",
        "body_bytes_min",
        "body_bytes_total",
    ]
    assert result["drift"] == 0
    assert result["passed"] is False


def test_drift_accepts_request_metrics_inside_the_measured_envelope() -> None:
    baseline = build_repeated_surface_baseline(
        [_request_subtraction(4811), _request_subtraction(4849)]
    )

    result = check_surface_drift(
        _sealed_current_request_subtraction(4820),
        baseline,
    )

    assert result["request_activity_drift"]["passed"] is True
    assert result["passed"] is True


def test_drift_rejects_request_shape_presence_changes() -> None:
    baseline = build_repeated_surface_baseline(
        [_request_subtraction(4811), _request_subtraction(4849)]
    )

    result = check_surface_drift(
        _request_subtraction(0, include=False), baseline
    )

    request_drift = result["request_activity_drift"]
    assert request_drift["removed_shape_count"] == 1
    assert request_drift["passed"] is False
    assert result["passed"] is False


def test_drift_keeps_request_activity_unknown_for_a_legacy_baseline() -> None:
    baseline = build_surface_baseline(_clean("baseline", ["api.A"]))
    baseline.pop("baseline_receipt_sha256")

    result = check_surface_drift(_clean("observed", ["api.A"]), baseline)

    assert result["request_activity_drift"]["comparable"] is None
    assert result["request_activity_drift"]["passed"] is None
    assert result["passed"] is True


def test_drift_does_not_upgrade_an_unverifiable_request_floor() -> None:
    baseline = build_repeated_surface_baseline(
        [_sub({"api.X"}), _sub({"api.X"})]
    )

    result = check_surface_drift(
        product_observation._seal_subtraction_document(_sub({"api.X"})),
        baseline,
    )

    assert result["request_activity_drift"]["baseline_status"] == "unverifiable"
    assert result["request_activity_drift"]["comparable"] is None
    assert result["passed"] is True


def test_repeated_baseline_refuses_mixed_observation_methods() -> None:
    first = dict(_sub({"api.A"}), arm_driver_supplied=False)
    second = dict(_sub({"api.A"}), arm_driver_supplied=True)
    with pytest.raises(ContractError, match="different observation methods"):
        build_repeated_surface_baseline([first, second])


def test_one_arm_cannot_establish_a_noise_floor() -> None:
    with pytest.raises(ContractError, match="at least two arms"):
        build_repeated_surface_baseline([_sub({"api.X"})])


def test_a_dirty_arm_cannot_enter_a_repeated_baseline() -> None:
    with pytest.raises(ContractError, match="dirty subtraction"):
        build_repeated_surface_baseline([_sub({"api.X"}), _sub({"api.X"}, clean=False)])


def test_a_check_can_use_the_measured_floor_instead_of_a_chosen_one() -> None:
    base = {f"api.X{i}" for i in range(20)}
    b = build_repeated_surface_baseline([_sub(base), _sub(base | {"api.Flaky"})])
    assert b["measured_noise_floor"] == 1

    # One volatile name: noise on this vendor, and a failure under the old default
    # of zero.
    observed = product_observation._seal_subtraction_document(
        _sub(base | {"api.Other"})
    )
    strict = check_surface_drift(observed, b, tolerance=0)
    assert strict["passed"] is False
    assert strict["tolerance_source"] == "given"

    measured = check_surface_drift(observed, b, tolerance=None)
    assert measured["passed"] is True
    assert measured["tolerance"] == 1
    assert measured["tolerance_source"] == "measured"
    # Tolerated, never hidden.
    assert measured["added"] == ["api.Other"]


def test_a_single_arm_baseline_has_no_floor_to_borrow() -> None:
    """`None` must not silently become zero on a baseline that never measured."""
    b = build_surface_baseline(_sub({"api.X", "api.Y"}))
    with pytest.raises(ContractError, match="no measured noise floor"):
        check_surface_drift(_sub({"api.X"}), b, tolerance=None)


def test_the_perimeterx_hint_is_specific_and_still_only_a_hint() -> None:
    """`_pxAppId` occurs 8 times in px.main.min.js and 0 times in the Akamai,
    Kasada and Shape collectors measured here."""
    body = "var _pxAppId='x';" + _built_antibot_like(bmak=0).decode("utf-8")
    verdict = classify_product_script(body.encode("utf-8"))
    assert verdict["vendor_hint"] == "perimeterx"
    assert verdict["looks_like_built_antibot_script"] is True
    assert classify_product_script(_built_antibot_like(bmak=0))["vendor_hint"] is None


def test_the_akamai_sbsd_hint_requires_the_complete_family_cluster() -> None:
    tokens = (
        b"/.well-known/sbsd ak_cpr_chlg_init ak_cpr_chlg_resp "
        b"cpr_chlge sec-cpr-overlay"
    )
    verdict = classify_product_script(_built_antibot_like(bmak=0) + tokens)

    assert verdict["signals"]["akamai_sbsd_markers"] == 5
    assert verdict["vendor_hint"] == "akamai-sbsd-web"
    assert verdict["looks_like_built_antibot_script"] is True

    for omitted in tokens.split():
        incomplete = b" ".join(token for token in tokens.split() if token != omitted)
        partial = classify_product_script(_built_antibot_like(bmak=0) + incomplete)
        assert partial["signals"]["akamai_sbsd_markers"] == 4
        assert partial["vendor_hint"] is None


def test_multiple_vendor_marker_families_fail_closed_instead_of_using_priority() -> None:
    payload = _built_antibot_like() + b"KPSDK"

    verdict = classify_product_script(payload)

    assert verdict["signals"]["bmak_literals"] >= 20
    assert verdict["signals"]["kpsdk_literals"] >= 1
    assert verdict["vendor_hint"] is None
    assert verdict["looks_like_built_antibot_script"] is False
    assert "multiple product vendor marker families" in verdict["reasons"]


@pytest.mark.parametrize(
    ("tokens", "expected"),
    [
        ("dataDomeOptions dataDomeProcessed ddjskey", "datadome"),
        ("[Cloudflare Turnstile] TurnstileError", "cloudflare-turnstile"),
    ],
)
def test_new_vendor_pins_receive_specific_hints(tokens: str, expected: str) -> None:
    """Measured vendor literals label a structural pass; they never create one."""
    body = _built_antibot_like(bmak=0) + tokens.encode("utf-8")
    verdict = classify_product_script(body)
    assert verdict["looks_like_built_antibot_script"] is True
    assert verdict["vendor_hint"] == expected


@pytest.mark.parametrize(
    ("token", "unexpected_hint"),
    [
        ("dataDomeOptions", "datadome"),
        ("[Cloudflare Turnstile]", "cloudflare-turnstile"),
    ],
)
def test_repeating_one_vendor_literal_does_not_satisfy_a_marker_conjunction(
    token: str, unexpected_hint: str
) -> None:
    body = _built_antibot_like(bmak=0) + f"{token} {token}".encode()

    verdict = classify_product_script(body)

    assert verdict["looks_like_built_antibot_script"] is True
    signal = (
        "datadome_markers"
        if unexpected_hint == "datadome"
        else "turnstile_markers"
    )
    assert verdict["signals"][signal] == 1
    assert verdict["vendor_hint"] != unexpected_hint


def test_vendor_literals_do_not_override_the_structural_guard() -> None:
    verdict = classify_product_script(
        b"dataDomeOptions dataDomeProcessed ddjskey [Cloudflare Turnstile] TurnstileError"
    )
    assert verdict["looks_like_built_antibot_script"] is False


def test_imperva_apg_hint_requires_the_complete_loader_conjunction() -> None:
    """The 2026-08-10 public Nordstrom pin owns all three APG loader names.

    A route mention alone is ordinary application text.  The hint requires the
    injected route, element id, and client-id attribute and remains independent
    of the structural admission decision.
    """
    body = _built_antibot_like(bmak=0) + (
        b"/__imp_apg__/js/sed-client.js _imp_apg_dip_ _imp_apg_cid_"
    )
    verdict = classify_product_script(body)

    assert verdict["looks_like_built_antibot_script"] is True
    assert verdict["signals"]["imperva_apg_markers"] == 3
    assert verdict["vendor_hint"] == "imperva-apg-loader"

    one_marker = classify_product_script(
        _built_antibot_like(bmak=0) + b"/__imp_apg__/js/sed-client.js"
    )
    assert one_marker["signals"]["imperva_apg_markers"] == 1
    assert one_marker["vendor_hint"] is None

    small = classify_product_script(
        b"/__imp_apg__/js/sed-client.js _imp_apg_dip_ _imp_apg_cid_"
    )
    assert small["vendor_hint"] == "imperva-apg-loader"
    assert small["looks_like_built_antibot_script"] is False


# -- the missing stage the server log already knew about ------------------------
#
# The rehost answers an unknown path with an empty 200 so the sample proceeds
# instead of erroring. That is the right default, and it is also exactly how a
# missing later stage looks: the collector fetches its own next stage, gets zero
# bytes, and fails quietly further on.
#
# Finding Kasada's second stage took a hand-written probe to read one fetch URL
# out of the page. The information was already in the server log the whole time.


def test_a_fetch_the_rehost_could_not_answer_is_named() -> None:
    verdict = grade_unserved_requests(
        [
            {"method": "GET", "path": "/", "served": "page"},
            {"method": "GET", "path": "/product-script.js", "served": "sample"},
            {"method": "GET", "path": "/149e9513/2d206a39/mfc", "served": "empty"},
            {"method": "GET", "path": "/149e9513/2d206a39/fp", "served": "empty"},
            {"method": "GET", "path": "/149e9513/2d206a39/mfc", "served": "empty"},
        ]
    )
    assert verdict["count"] == 3
    assert verdict["dependencies_complete"] is False
    assert verdict["paths"] == ["/149e9513/2d206a39/fp", "/149e9513/2d206a39/mfc"]
    assert "--stage" in verdict["note"]


@pytest.mark.parametrize(
    "path",
    [
        "/next?token=private-query-value",
        "/next#private-fragment",
        "/" + "x" * product_observation.MAX_REHOST_LOG_PATH_CHARS,
        "/next\nprivate-control",
        "/next\ud800",
    ],
)
def test_unserved_grade_rejects_paths_the_rehost_cannot_retain(path: str) -> None:
    verdict = grade_unserved_requests(
        [{"method": "GET", "path": path, "served": "empty"}]
    )

    assert verdict["status"] == "unverifiable"
    assert verdict["dependencies_complete"] is None
    assert verdict["paths"] == []
    assert verdict["malformed_entries"] == 1


def test_unserved_grade_keeps_the_exact_path_retention_boundary() -> None:
    path = "/" + "x" * (product_observation.MAX_REHOST_LOG_PATH_CHARS - 1)

    verdict = grade_unserved_requests(
        [{"method": "GET", "path": path, "served": "empty"}]
    )

    assert verdict["status"] == "ok"
    assert verdict["paths"] == [path]


@pytest.mark.parametrize(
    ("method", "path", "served"),
    [
        ("GET", "/private-false-page", "page"),
        ("POST", "/", "page"),
        ("POST", "/private-false-sample", "sample"),
        ("GET", "/", "sample"),
        ("GET", "/bad sample path", "sample"),
        ("GET", "/private-false-hook", "hook"),
        ("POST", "/private-false-stage", "stage"),
        ("GET", "/", "stage"),
        ("GET", "/", "empty"),
        ("GET", "//outside/next.js", "stage"),
        ("GET", "//outside/next.js", "empty"),
        ("POST", "//outside/submit", "post-ack"),
        ("GET", "/private-false-ack", "post-ack"),
    ],
)
def test_unserved_grade_rejects_impossible_served_routes(
    method: str, path: str, served: str
) -> None:
    verdict = grade_unserved_requests(
        [{"method": method, "path": path, "served": served}]
    )

    assert verdict["status"] == "unverifiable"
    assert verdict["dependencies_complete"] is None
    assert verdict["malformed_entries"] == 1
    assert "private-false" not in json.dumps(verdict)


@pytest.mark.parametrize(
    ("orders", "expected_status"),
    [
        ((1, 2), "unverifiable"),
        ((0, 0), "unverifiable"),
        ((0, None), "unverifiable"),
        ((False, 1), "unverifiable"),
        ((0, 1), "ok"),
        ((None, None), "ok"),
    ],
)
def test_unserved_grade_checks_retained_request_order_when_recorded(
    orders: tuple[int | bool | None, ...], expected_status: str
) -> None:
    rows = [
        {"method": "GET", "path": "/", "served": "page"},
        {"method": "GET", "path": DEFAULT_SCRIPT_PATH, "served": "sample"},
    ]
    for row, order in zip(rows, orders):
        if order is not None:
            row["order"] = order

    verdict = grade_unserved_requests(rows)

    assert verdict["status"] == expected_status
    assert verdict["dependencies_complete"] is (
        True if expected_status == "ok" else None
    )


def test_an_arm_that_needed_nothing_says_so_positively() -> None:
    """Silence would read the same as "not checked"; this says it was checked."""
    verdict = grade_unserved_requests(
        [
            {"method": "GET", "path": "/", "served": "page"},
            {"method": "GET", "path": "/product-script.js", "served": "sample"},
        ]
    )
    assert verdict["count"] == 0
    assert verdict["paths"] == []
    assert "served from disk" in verdict["note"]
    assert verdict["scope"] == "loopback_rehost_only"
    assert "blocked before reaching loopback" in verdict["scope_note"]


def test_empty_request_log_does_not_claim_disk_service() -> None:
    verdict = grade_unserved_requests([])

    assert verdict["status"] == "ok"
    assert verdict["count"] == 0
    assert verdict["note"] == "no requests reached the loopback rehost"


def test_denied_proxy_note_does_not_claim_disk_service() -> None:
    verdict = grade_unserved_requests(
        [{"method": "GET", "path": "/<proxy-http>", "served": "proxy-denied"}]
    )

    assert verdict["status"] == "ok"
    assert verdict["count"] == 0
    assert verdict["note"] == (
        "proxy requests were denied; no missing local stage path was observed"
    )


def test_empty_favicon_fallback_does_not_claim_disk_service() -> None:
    verdict = grade_unserved_requests(
        [{"method": "GET", "path": "/favicon.ico", "served": "empty"}]
    )

    assert verdict["status"] == "ok"
    assert verdict["count"] == 0
    assert verdict["note"] == "favicon request received an empty fallback"


def test_synthetic_ack_note_accounts_for_denied_proxy_requests() -> None:
    verdict = grade_unserved_requests(
        [
            {"method": "GET", "path": "/tags.js", "served": "sample"},
            {"method": "POST", "path": "/submit", "served": "post-ack"},
            {"method": "GET", "path": "/<proxy-http>", "served": "proxy-denied"},
        ]
    )

    assert verdict["status"] == "ok"
    assert verdict["count"] == 0
    assert verdict["note"] == (
        "owned-origin GET paths were served from disk; POST requests received "
        "a synthetic lab acknowledgement, not a replayed product response; "
        "proxy requests were denied"
    )


def test_denied_proxy_traffic_is_auditable_but_not_a_missing_rehost_stage() -> None:
    requests = [
        {
            "method": "GET",
            "path": "/background/check",
            "served": "proxy-denied",
            "request_body_bytes": 0,
        },
        {
            "method": "CONNECT",
            "path": "/<proxy-connect>",
            "served": "proxy-denied",
            "request_body_bytes": 0,
        },
    ]

    verdict = grade_unserved_requests(requests)
    activity = project_server_request_activity(requests)

    assert verdict["status"] == "ok"
    assert verdict["dependencies_complete"] is True
    assert verdict["proxy_denied"] == {
        "count": 2,
        "methods": {"GET": 1, "CONNECT": 1},
        "note": (
            "requests sent to the owned deny proxy; target authority is not "
            "retained and no upstream socket was opened"
        ),
    }
    assert activity["status"] == "ok"
    assert activity["candidate_requests"] == 0
    assert activity["dropped_requests"] == 0


def test_a_synthetic_post_ack_is_not_called_a_product_response() -> None:
    verdict = grade_unserved_requests(
        [
            {"method": "GET", "path": "/tags.js", "served": "sample"},
            {
                "method": "POST",
                "path": "/js/",
                "served": "post-ack",
                "request_body_bytes": 4861,
            },
        ]
    )
    assert verdict["dependencies_complete"] is True
    acks = verdict["synthetic_acknowledgements"]
    assert verdict["count"] == 0
    assert acks == {
        "count": 1,
        "paths": ["/js/"],
        "request_body_bytes": 4861,
        "note": (
            "the rehost returned a generic JSON acknowledgement; this does not "
            "reproduce or establish a product endpoint response"
        ),
    }
    assert "not a replayed product response" in verdict["note"]


@pytest.mark.parametrize("request_log", [None, True, 1, 1.5, "requests", {}, ()])
def test_unserved_request_grade_rejects_non_list_logs_cleanly(request_log) -> None:
    with pytest.raises(ContractError, match="request list"):
        grade_unserved_requests(request_log)


def test_unserved_request_grade_drops_malformed_entries_and_bounds_body_counts() -> (
    None
):
    verdict = grade_unserved_requests(
        [
            None,
            True,
            [],
            {"served": "empty", "path": {"private": "stage"}},
            {
                "method": "POST",
                "served": "post-ack",
                "path": "/ack",
                "request_body_bytes": "private-count",
            },
            {
                "method": "POST",
                "served": "post-ack",
                "path": "/bounded",
                "request_body_bytes": MAX_REHOST_POST_BODY_BYTES + 1,
            },
        ]
    )

    assert verdict["count"] == 0
    assert verdict["status"] == "unverifiable"
    assert verdict["dependencies_complete"] is None
    assert verdict["malformed_entries"] == 5
    assert verdict["synthetic_acknowledgements"]["paths"] == ["/bounded"]
    assert (
        verdict["synthetic_acknowledgements"]["request_body_bytes"]
        == MAX_REHOST_POST_BODY_BYTES
    )
    assert "private" not in json.dumps(verdict)


def test_request_activity_projects_path_shape_and_drops_values() -> None:
    report = project_server_request_activity(
        [
            {
                "method": "POST",
                "path": "/private-tenant/fingerprint?token=private-value&lang=en",
                "served": "post-ack",
                "request_body_bytes": 4880,
            }
        ]
    )
    rendered = json.dumps(report)
    assert "private-tenant" not in rendered
    assert "private-value" not in rendered
    assert report["rows"] == [
        {
            "method": "POST",
            "served": "post-ack",
            "path_segment_lengths": [14, 11],
            "path_segments_truncated": False,
            "query_names": ["lang", "token"],
            "query_names_truncated": False,
            "count": 1,
            "body_bytes_total": 4880,
            "body_bytes_min": 4880,
            "body_bytes_max": 4880,
        }
    ]


@pytest.mark.parametrize("query_name", ["n" * 81, "private\x00name"])
def test_request_activity_flags_omitted_logged_query_name(query_name) -> None:
    log = product_observation._RequestLog()
    log.add(
        "GET",
        "/configured/",
        0,
        served="stage",
        request_target=f"/configured/?{query_name}=value",
    )

    report = project_server_request_activity(log.entries)

    assert report["status"] == "ok"
    assert report["rows"][0]["query_names"] == []
    assert report["rows"][0]["query_names_truncated"] is True
    assert "private" not in json.dumps(report)


def test_request_activity_aggregates_only_complete_post_body_digests() -> None:
    first = hashlib.sha256(b"first-private-body").hexdigest()[:16]
    second = hashlib.sha256(b"second-private-body").hexdigest()[:16]
    report = project_server_request_activity(
        [
            {
                "method": "POST",
                "path": "/configured/",
                "served": "post-ack",
                "request_body_bytes": 18,
                "request_body_sha256_16": first,
            },
            {
                "method": "POST",
                "path": "/configured/",
                "served": "post-ack",
                "request_body_bytes": 18,
                "request_body_sha256_16": first,
            },
            {
                "method": "POST",
                "path": "/configured/",
                "served": "post-ack",
                "request_body_bytes": 19,
                "request_body_sha256_16": second,
            },
        ]
    )

    assert report["status"] == "ok"
    assert report["rows"][0]["body_sha256_16_counts"] == {
        first: 2,
        second: 1,
    }
    assert "private-body" not in json.dumps(report)


def test_request_activity_rejects_oversized_body_length_without_clipping() -> None:
    report = project_server_request_activity(
        [
            {
                "method": "POST",
                "path": "/configured/",
                "served": "post-ack",
                "request_body_bytes": 1_000_000_001,
            }
        ]
    )

    assert report["status"] == "unverifiable"
    assert report["rows"] == []
    assert report["dropped_requests"] == 1


@pytest.mark.parametrize(
    "entry",
    [
        {
            "method": "POST",
            "path": "/configured/",
            "served": "post-ack",
            "request_body_sha256_16": "not-a-digest",
        },
        {
            "method": "GET",
            "path": "/configured/",
            "served": "stage",
            "request_body_sha256_16": "a" * 16,
        },
    ],
)
def test_request_activity_rejects_malformed_or_out_of_scope_body_digests(
    entry,
) -> None:
    report = project_server_request_activity([entry])

    assert report["status"] == "unverifiable"
    assert report["rows"] == []
    assert report["dropped_requests"] == 1


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("method", []),
        ("method", {"private": "POST"}),
        ("served", []),
        ("served", {"private": "post-ack"}),
    ],
)
def test_request_activity_drops_unhashable_closed_enum_values_cleanly(
    field,
    value,
) -> None:
    entry = {
        "method": "POST",
        "path": "/configured/",
        "served": "post-ack",
    }
    entry[field] = value

    report = project_server_request_activity([entry])

    assert report["status"] == "unverifiable"
    assert report["candidate_requests"] == 0
    assert report["dropped_requests"] == 1
    assert report["truncated"] is True
    assert report["rows"] == []


def test_request_activity_does_not_truthiness_coerce_query_truncation() -> None:
    report = project_server_request_activity(
        [
            {
                "method": "POST",
                "path": "/configured/?one=1",
                "served": "post-ack",
                "query_names": ["one"],
                "query_names_truncated": "private-truthy-value",
            }
        ]
    )

    assert report["status"] == "unverifiable"
    assert report["rows"] == []
    assert report["dropped_requests"] == 1
    assert report["truncated"] is True


@pytest.mark.parametrize(
    "names",
    [
        ["one", 3],
        ["one", "one"],
        ["two", "one"],
        ["one", "private\nname"],
        ["private\ud800"],
        [f"name{index:02d}" for index in range(65)],
    ],
)
def test_request_activity_rejects_malformed_logged_query_names(names) -> None:
    report = project_server_request_activity(
        [
            {
                "method": "POST",
                "path": "/configured/?one=1",
                "served": "post-ack",
                "query_names": names,
                "query_names_truncated": False,
            }
        ]
    )

    assert report["status"] == "unverifiable"
    assert report["rows"] == []
    assert report["dropped_requests"] == 1


def test_request_activity_sanitizer_invalidates_forged_malformed_rows() -> None:
    valid = {
        "method": "POST",
        "served": "post-ack",
        "path_segment_lengths": [4],
        "path_segments_truncated": False,
        "query_names": ["one"],
        "query_names_truncated": False,
        "count": 1,
    }
    report = product_observation._sanitize_request_activity_report(
        {
            "status": "ok",
            "rows": [
                valid,
                {**valid, "method": {"private": "POST"}},
                {**valid, "query_names_truncated": "private-truthy-value"},
            ],
        }
    )

    assert report["status"] == "unverifiable"
    assert report["truncated"] is True
    assert report["dropped_requests"] == 2
    assert report["rows"] == [valid]


def test_request_activity_sanitizer_drops_non_utf8_query_name() -> None:
    report = product_observation._sanitize_request_activity_report(
        {
            "status": "ok",
            "rows": [
                {
                    "method": "POST",
                    "served": "post-ack",
                    "path_segment_lengths": [4],
                    "path_segments_truncated": False,
                    "query_names": ["private\ud800"],
                    "query_names_truncated": False,
                    "count": 1,
                }
            ],
        }
    )

    assert report["status"] == "unverifiable"
    assert report["truncated"] is True
    assert report["dropped_requests"] == 1
    assert report["rows"] == []
    assert "private" not in json.dumps(report)


def test_request_activity_sanitizer_reallowlists_body_digest_counts() -> None:
    digest = "ABCDEF0123456789"
    report = product_observation._sanitize_request_activity_report(
        {
            "status": "ok",
            "rows": [
                {
                    "method": "POST",
                    "served": "post-ack",
                    "path_segment_lengths": [4],
                    "path_segments_truncated": False,
                    "query_names": [],
                    "query_names_truncated": False,
                    "count": 1,
                    "body_sha256_16_counts": {digest: 1},
                }
            ],
        }
    )

    assert report["status"] == "ok"
    assert report["rows"][0]["body_sha256_16_counts"] == {digest.lower(): 1}


def test_request_activity_sanitizer_fails_closed_on_impossible_digest_coverage() -> (
    None
):
    report = product_observation._sanitize_request_activity_report(
        {
            "status": "ok",
            "rows": [
                {
                    "method": "POST",
                    "served": "post-ack",
                    "path_segment_lengths": [4],
                    "path_segments_truncated": False,
                    "query_names": [],
                    "query_names_truncated": False,
                    "count": 1,
                    "body_sha256_16_counts": {"a" * 16: 2},
                }
            ],
        }
    )

    assert report["status"] == "unverifiable"
    assert report["rows"] == []


@pytest.mark.parametrize(
    "metrics",
    [
        {"count": 1, "body_bytes_total": 7, "body_bytes_min": 10, "body_bytes_max": 10},
        {"count": 2, "body_bytes_total": 10, "body_bytes_min": 10, "body_bytes_max": 10},
        {"count": 1, "body_bytes_total": 7, "body_bytes_min": 10, "body_bytes_max": 5},
        {"count": 1, "body_bytes_total": 10, "body_bytes_min": 10},
    ],
)
def test_request_activity_sanitizer_invalidates_incoherent_body_envelope(metrics):
    row = {
        "method": "POST",
        "served": "post-ack",
        "path_segment_lengths": [4],
        "query_names": [],
        **metrics,
    }
    report = product_observation._sanitize_request_activity_report(
        {"status": "ok", "rows": [row]}
    )

    assert report["status"] == "unverifiable"
    assert report["rows"] == []


def test_request_activity_sanitizer_rejects_zero_count_captured_shape():
    report = product_observation._sanitize_request_activity_report(
        {
            "status": "ok",
            "candidate_requests": 0,
            "distinct_shapes": 1,
            "rows": [
                {
                    "method": "POST",
                    "served": "post-ack",
                    "path_segment_lengths": [4],
                    "query_names": [],
                    "count": 0,
                }
            ],
        }
    )

    assert report["status"] == "unverifiable"
    assert report["rows"] == []


def test_request_activity_sanitizer_rejects_zero_length_path_segment():
    report = product_observation._sanitize_request_activity_report(
        {
            "status": "ok",
            "rows": [
                {
                    "method": "POST",
                    "served": "post-ack",
                    "path_segment_lengths": [0],
                    "query_names": [],
                    "count": 1,
                }
            ],
        }
    )

    assert report["status"] == "unverifiable"
    assert report["rows"] == []


def test_request_activity_subtraction_rejects_incoherent_saved_body_envelope():
    arm = {
        "status": "ok",
        "rows": [
            {
                "method": "POST",
                "served": "post-ack",
                "path_segment_lengths": [4],
                "query_names": [],
                "count": 1,
                "body_bytes_total": 7,
                "body_bytes_min": 10,
                "body_bytes_max": 10,
            }
        ],
    }

    report = subtract_request_activity(arm, {"status": "ok", "rows": []})

    assert report["status"] == "unverifiable"
    assert report["only_in_arm"] == []


def test_request_activity_sanitizer_rejects_digest_count_normalization_overflow() -> (
    None
):
    report = product_observation._sanitize_request_activity_report(
        {
            "status": "ok",
            "rows": [
                {
                    "method": "POST",
                    "served": "post-ack",
                    "path_segment_lengths": [4],
                    "query_names": [],
                    "body_sha256_16_counts": {
                        "abcdef0123456789": 1_000_000_000,
                        "ABCDEF0123456789": 1,
                    },
                }
            ],
        }
    )

    assert report["status"] == "unverifiable"
    assert report["rows"] == []


@pytest.mark.parametrize("rows", [None, True, 1, "rows", {}, ()])
def test_request_activity_sanitizer_invalidates_malformed_row_containers(rows) -> None:
    report = product_observation._sanitize_request_activity_report(
        {"status": "ok", "rows": rows}
    )

    assert report["status"] == "unverifiable"
    assert report["truncated"] is True
    assert report["dropped_requests"] == 1


def test_request_activity_subtraction_preserves_count_delta() -> None:
    arm = project_server_request_activity(
        [
            {
                "method": "POST",
                "path": "/configured/",
                "served": "post-ack",
                "request_body_bytes": 4800,
            },
            {
                "method": "POST",
                "path": "/configured/",
                "served": "post-ack",
                "request_body_bytes": 5600,
            },
            {
                "method": "GET",
                "path": "/favicon.ico",
                "served": "empty",
                "request_body_bytes": 0,
            },
        ]
    )
    control = project_server_request_activity(
        [
            {
                "method": "GET",
                "path": "/favicon.ico",
                "served": "empty",
                "request_body_bytes": 0,
            },
        ]
    )
    report = subtract_request_activity(arm, control)
    assert report["clean_subtraction"] is True
    assert report["shared_shapes"] == 1
    assert report["only_in_control"] == []
    assert report["only_in_arm"][0]["count"] == 2
    assert report["only_in_arm"][0]["body_bytes_total"] == 10400


@pytest.mark.parametrize("snapshot", [{"status": "ok"}, {"status": "ok", "rows": None}])
def test_request_activity_subtraction_rejects_missing_saved_rows(snapshot) -> None:
    report = subtract_request_activity(snapshot, {"status": "ok", "rows": []})

    assert report["status"] == "unverifiable"
    assert report["only_in_arm"] == []


def test_request_activity_sanitizer_rejects_an_empty_success_envelope() -> None:
    report = product_observation._sanitize_request_activity_report({"status": "ok"})

    assert report["status"] == "unverifiable"


def test_request_activity_subtraction_rejects_rows_without_counts() -> None:
    row = {
        "method": "POST",
        "served": "post-ack",
        "path_segment_lengths": [10],
        "path_segments_truncated": False,
        "query_names": [],
        "query_names_truncated": False,
    }
    report = subtract_request_activity(
        {"status": "ok", "rows": [row]},
        {"status": "ok", "rows": []},
    )

    assert report["status"] == "unverifiable"


@pytest.mark.parametrize(
    "mutated_fields",
    [
        {"candidate_requests": 0},
        {"candidate_requests": 3},
        {"distinct_shapes": 0},
    ],
)
def test_request_activity_subtraction_rejects_snapshot_count_disagreement(
    mutated_fields: dict[str, int],
) -> None:
    row = {
        "method": "GET",
        "served": "empty",
        "path_segment_lengths": [1],
        "path_segments_truncated": False,
        "query_names": ["a"],
        "query_names_truncated": False,
        "count": 2,
    }
    snapshot = {
        "status": "ok",
        "rows": [row],
        "candidate_requests": 2,
        "distinct_shapes": 1,
        "truncated": False,
        **mutated_fields,
    }
    report = subtract_request_activity(snapshot, {"status": "ok", "rows": []})

    assert report["status"] == "unverifiable"
    assert report["only_in_arm"] == []


def test_request_activity_subtraction_rejects_duplicate_saved_shape() -> None:
    row = {
        "method": "GET",
        "served": "empty",
        "path_segment_lengths": [1],
        "path_segments_truncated": False,
        "query_names": [],
        "query_names_truncated": False,
        "count": 1,
    }
    report = subtract_request_activity(
        {"status": "ok", "rows": [row, row]},
        {"status": "ok", "rows": []},
    )

    assert report["status"] == "unverifiable"
    assert report["only_in_arm"] == []


@pytest.mark.parametrize("names", [["b", "a"], ["a", "a"]])
def test_request_activity_subtraction_rejects_noncanonical_query_names(names):
    row = {
        "method": "GET",
        "served": "empty",
        "path_segment_lengths": [1],
        "path_segments_truncated": False,
        "query_names": names,
        "query_names_truncated": False,
        "count": 1,
    }
    report = subtract_request_activity(
        {"status": "ok", "rows": [row]},
        {"status": "ok", "rows": []},
    )

    assert report["status"] == "unverifiable"
    assert report["only_in_arm"] == []


def test_request_activity_subtraction_accepts_coherent_snapshot_counts() -> None:
    row = {
        "method": "GET",
        "served": "empty",
        "path_segment_lengths": [1],
        "path_segments_truncated": False,
        "query_names": ["a", "b"],
        "query_names_truncated": False,
        "count": 2,
    }
    report = subtract_request_activity(
        {
            "status": "ok",
            "rows": [row],
            "candidate_requests": 2,
            "distinct_shapes": 1,
            "truncated": False,
        },
        {"status": "ok", "rows": []},
    )

    assert report["status"] == "ok"
    assert report["only_in_arm"][0]["count"] == 2


@pytest.mark.parametrize(
    "invalid_field",
    [{"candidate_requests": True}, {"distinct_shapes": "0"}],
)
def test_request_activity_sanitizer_rejects_malformed_present_counts(invalid_field):
    report = product_observation._sanitize_request_activity_report(
        {"status": "ok", "rows": [], "truncated": False, **invalid_field}
    )

    assert report["status"] == "unverifiable"


@pytest.mark.parametrize(
    "row_field",
    [
        {"count": 1_000_000_001},
        {"body_bytes_total": 1_000_000_001},
        {"path_segment_lengths": [1_000_000_001]},
    ],
)
def test_request_activity_sanitizer_rejects_clipped_saved_row(row_field):
    row = {
        "method": "GET",
        "served": "empty",
        "path_segment_lengths": [1],
        "path_segments_truncated": False,
        "query_names": [],
        "query_names_truncated": False,
        "count": 1,
        **row_field,
    }
    report = product_observation._sanitize_request_activity_report(
        {"status": "ok", "rows": [row], "truncated": False}
    )

    assert report["status"] == "unverifiable"
    assert report["rows"] == []


def test_request_activity_subtraction_rejects_non_boolean_truncation_receipt() -> None:
    report = subtract_request_activity(
        {"status": "ok", "rows": [], "truncated": "false"},
        {"status": "ok", "rows": []},
    )

    assert report["status"] == "unverifiable"


def test_request_activity_subtraction_preserves_arm_only_body_digests() -> None:
    digest = hashlib.sha256(b"arm-only-body").hexdigest()[:16]
    arm = project_server_request_activity(
        [
            {
                "method": "POST",
                "path": "/configured/",
                "served": "post-ack",
                "request_body_bytes": 13,
                "request_body_sha256_16": digest,
            }
        ]
    )
    control = project_server_request_activity([])

    report = subtract_request_activity(arm, control)

    assert report["clean_subtraction"] is True
    assert report["only_in_arm"][0]["body_sha256_16_counts"] == {digest: 1}


@pytest.mark.parametrize("truncated_side", ["arm", "control"])
def test_request_activity_subtraction_fails_closed_on_truncation(
    truncated_side: str,
) -> None:
    arm = project_server_request_activity(
        [{"method": "GET", "path": "/arm", "served": "stage"}]
    )
    control = project_server_request_activity(
        [{"method": "GET", "path": "/control", "served": "page"}]
    )
    {"arm": arm, "control": control}[truncated_side]["truncated"] = True

    report = subtract_request_activity(arm, control)

    assert report["status"] == "unverifiable"
    assert report["only_in_arm"] == []
    assert report["only_in_control"] == []


def test_the_browsers_own_favicon_request_is_not_a_missing_stage() -> None:
    """The browser asks for it, not the script, and it appears in every arm."""
    verdict = grade_unserved_requests(
        [
            {"method": "GET", "path": "/favicon.ico", "served": "empty"},
        ]
    )
    assert verdict["count"] == 0


def test_a_served_stage_stops_being_reported_as_missing() -> None:
    """The point of the report is that it empties out once --stage is supplied."""
    verdict = grade_unserved_requests(
        [
            {"method": "GET", "path": "/149e9513/2d206a39/mfc", "served": "stage"},
        ]
    )
    assert verdict["count"] == 0


# -- suggesting the entry point, keyed on what the client actually installed ----


def test_a_host_driven_client_gets_its_measured_entry_point_suggested() -> None:
    entry = suggest_driver({"vendor_globals": ["KPSDK"], "vendor_reports_ready": False})
    assert entry is not None
    assert "KPSDK.configure" in entry


def test_the_suggestion_keys_on_the_runtime_global_not_a_static_hint() -> None:
    """A correction, not a preference.

    The first version keyed on `classify_product_script`'s vendor hint and never
    fired on the one case it was written for: Kasada's `p.js` is the stage that
    needs driving and contains no `KPSDK` literal at all -- that literal lives in
    `ips.js`, the stage it fetches. The runtime evidence was in the startup record
    the whole time.
    """
    from browser_core.product_observation import classify_product_script

    p_js_like = _kasada_like(kpsdk=0)
    assert classify_product_script(p_js_like)["vendor_hint"] is None
    # ...and the suggestion still fires, because the page installed the global.
    assert suggest_driver({"vendor_globals": ["KPSDK"], "vendor_reports_ready": False})


def test_a_collector_that_started_is_not_offered_a_driver() -> None:
    assert (
        suggest_driver({"vendor_globals": ["KPSDK"], "vendor_reports_ready": True})
        is None
    )
    assert (
        suggest_driver({"vendor_globals": ["bmak"], "vendor_reports_ready": None})
        is None
    )


def test_an_unknown_global_gets_no_invented_entry_point() -> None:
    assert (
        suggest_driver(
            {"vendor_globals": ["_totallyNew"], "vendor_reports_ready": False}
        )
        is None
    )
    assert suggest_driver(None) is None
