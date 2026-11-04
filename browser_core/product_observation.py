"""Offline observation of a saved product script under the native trace plane.

A protected-site script is normally unreadable: the current Akamai Bot Manager web
pin is one 552 KB line with no plaintext literal for any fingerprint-relevant API.
Static reading cannot enumerate what it touches, so the engine has to answer instead.

This module rehosts a *saved* script sample from loopback, runs it under the
attested Browser Core build with passive native tracing, and reports which engine
surfaces it reached.

Two properties make the result usable as evidence:

* **Offline by construction.** Chromium is launched with a host-resolver rule that
  maps every name to NOTFOUND except the owned rehost address, so a rehosted script
  cannot resolve the origin it came from. Native Fetch API starts additionally
  carry a value-free target-scope receipt; incomplete evidence or an external
  target fails the run. This is a lab replay of a stored artifact, never a live
  session.
* **Control subtraction.** Legacy broad-scope generated-binding events carry a
  WebIDL name but no script attribution, so a single run cannot separate the
  sample from the browser's own activity. Patch 0006 adds an optional current-
  script count plane; compatible arm/control documents subtract those counts and
  recover shared names, while older documents retain exact set subtraction.
  `only_in_control` is reported precisely so either subtraction can be audited.

Nothing here is an acceptance, bypass, evasion, or bot-score claim, and no captured
value is retained -- only API names, counts, execution-context classes, and the
redaction-safe request classes the trace contract already exposes.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import os
import re
import stat
import sys
import time
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from html import escape
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Lock, Thread
from typing import Any
from urllib.parse import urlsplit

from .bounded_process import run_with_bounded_stdout
from .cdp import (
    MAX_CDP_OPERATION_SECONDS,
    RESOURCE_INTENT_ATTRIBUTES,
    CdpCommandResponseTimeout,
    evaluate_page_expression,
    observe_page_resource_intents,
    project_resource_intent_origin,
    project_resource_intent_tag,
    probe_managed_page_target,
    wait_for_page_target,
)
from .control_files import (
    decode_strict_json_bytes,
    publish_json_exclusive_result,
    read_bounded_control_snapshot_result,
    replace_json_conditionally_result,
)
from .contracts import MAX_TRACE_EVENT_DURATION_NS, ContractError, reject_sensitive_keys
from .git_executable import (
    decode_portable_git_path,
    git_blob_sha1,
    isolated_git_environment,
    select_git_executable,
)
from .launcher import (
    EvaluationLaunch,
    launch_evaluation,
    validate_evaluation_extra_args,
)
from .lifecycle import stop_session, validate_stopped_session_receipt
from .local_http import LocalPanelServer
from .owned_paths import (
    directory_ancestry_binding,
    directory_identity,
    prepare_owned_directory_parent,
)
from .numeric import is_finite_number
from .script_provenance import _manifest_url
from .perfetto import (
    bind_perfetto_source_trace,
    count_exportable_events,
    export_perfetto,
    validate_trace_export_report,
)
from .trace import scan_validated_trace
from .trace_scopes import TRACE_CATEGORY_CONTRACTS, TRACE_SCOPES

OBSERVATION_SCHEMA = "browser-core.product-script-observation/1"
SUBTRACTION_SCHEMA = "browser-core.product-script-subtraction/1"
IDENTITY_SCHEMA = "browser-core.product-script-identity/1"
REHOST_CONTRACT_SCHEMA = "browser-core.product-script-rehost-contract/1"


def _seal_observation_document(document: dict[str, Any]) -> dict[str, Any]:
    """Attach a complete public self-integrity receipt to producer output."""

    if document.get("schema") != OBSERVATION_SCHEMA:
        raise ContractError("only product observations can be sealed")
    canonical = {
        key: value
        for key, value in document.items()
        if key != "observation_receipt_sha256"
    }
    document["observation_receipt_sha256"] = hashlib.sha256(
        json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return document


def _verified_observation_receipt(document: dict[str, Any]) -> None:
    """Validate the optional whole-document receipt on a current observation."""

    declared = document.get("observation_receipt_sha256")
    if declared is None:
        return
    _validated_surface_label(document.get("label"), "observation")
    _surface_script_pin(document, "script_sha256_16")
    _validated_canonical_utc_timestamp(document.get("generated_at"), "observation")
    identity_coherent, _, _, _ = _reconciled_script_identity(
        document, current_required=True
    )
    if identity_coherent is not True:
        raise ContractError("observation script identity is incoherent")
    canonical = {
        key: value
        for key, value in document.items()
        if key != "observation_receipt_sha256"
    }
    expected = hashlib.sha256(
        json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    if (
        not isinstance(declared, str)
        or re.fullmatch(r"[0-9a-f]{64}", declared) is None
        or not hmac.compare_digest(declared, expected)
    ):
        raise ContractError("observation receipt integrity check failed")
    _verified_observation_side_reports(document)


def _verified_observation_side_reports(document: dict[str, Any]) -> None:
    """Keep current saved page-controlled side reports in their safe projection."""

    resource = document.get("resource_intents")
    if resource is not None:
        if not isinstance(resource, dict):
            raise ContractError("observation resource intent report is invalid")
        status = resource.get("status")
        capture = document.get("resource_intent_capture")
        if status == "off":
            valid = resource == {
                "status": "off",
                "source": "cdp_dom_snapshot",
                "intents": [],
                "non_claim": "resource-intent capture disabled for this method arm",
            } and capture == "off"
        elif status == "failed" and resource.get("source") == "cdp_dom_snapshot":
            diagnostic = resource.get("diagnostic")
            prefix = "resource intent capture failed: "
            valid = (
                capture in RESOURCE_INTENT_CONTRACTS
                and set(resource)
                == {"status", "source", "diagnostic", "intents", "non_claim"}
                and resource.get("intents") == []
                and resource.get("non_claim") == "resource intent could not be observed"
                and isinstance(diagnostic, str)
                and diagnostic.startswith(prefix)
                and diagnostic[len(prefix) :]
                == _redact_diagnostic(diagnostic[len(prefix) :])
            )
        else:
            valid = (
                capture in RESOURCE_INTENT_CONTRACTS
                and resource == _sanitize_resource_intent_report(resource)
            )
        if not valid:
            raise ContractError("observation resource intent report is invalid")

    activity = document.get("request_activity")
    if activity is not None and (
        not isinstance(activity, dict)
        or activity != _sanitize_request_activity_report(activity)
    ):
        raise ContractError("observation request activity report is invalid")

# Closed classifier vocabulary shared with portable consumers. Keep this at the
# producer boundary so adding a classifier cannot require a second, drift-prone
# copy in evidence-pack or digest code.
PRODUCT_SCRIPT_VENDOR_HINTS = frozenset(
    {
        "akamai-bmp-web",
        "akamai-sbsd-web",
        "anubis-web-challenge",
        "cloudflare-turnstile",
        "datadome",
        "geetest-v4-loader",
        "imperva-apg-loader",
        "kasada",
        "perimeterx",
        "shape",
    }
)

_KASADA_VM_ANALYSIS_BOUNDARY = {
    "kind": "bytecode-vm-mediated",
    "basis": "classifier-owned-kasada-hint",
    "interpretation": (
        "binding traces observe host API crossings, not operations performed "
        "inside the collector interpreter"
    ),
    "non_claim": (
        "the hint does not prove this artifact reached the VM or enumerate "
        "fingerprint fields, bytecode operations, payload semantics, or acceptance"
    ),
}

_GEETEST_LOADER_ANALYSIS_BOUNDARY = {
    "kind": "bootstrap-loader-only",
    "basis": "classifier-owned-geetest-v4-loader-hint",
    "interpretation": (
        "binding and resource-intent evidence covers loader orchestration; "
        "the downstream challenge library is absent unless separately pinned "
        "and staged"
    ),
    "non_claim": (
        "the loader surface does not establish downstream challenge behavior, "
        "token generation, payload semantics, proof completion, or acceptance"
    ),
}

_TURNSTILE_CHALLENGE_STAGE_ANALYSIS_BOUNDARY = {
    "kind": "external-challenge-stage-required",
    "basis": "classifier-owned-cloudflare-turnstile-hint",
    "interpretation": (
        "loader and widget-construction evidence does not include the "
        "vendor-origin challenge-frame internals unless that frame is "
        "separately observed"
    ),
    "non_claim": (
        "the outer-script surface does not establish challenge-frame behavior, "
        "token generation, proof completion, clearance, scoring, or acceptance"
    ),
}

_IMPERVA_DOWNSTREAM_SCRIPT_ANALYSIS_BOUNDARY = {
    "kind": "nonempty-downstream-script-required",
    "basis": "classifier-owned-imperva-apg-loader-hint",
    "interpretation": (
        "first-stage evidence ends at APG script injection; downstream behavior "
        "requires a separately pinned and nonempty second-stage script"
    ),
    "non_claim": (
        "the first-stage or explicit-empty-stage surface does not establish "
        "second-stage collection, payload semantics, client-state generation, "
        "scoring, or acceptance"
    ),
}

_ANUBIS_WORKER_CONTEXT_ANALYSIS_BOUNDARY = {
    "kind": "proof-worker-context-required",
    "basis": "classifier-owned-anubis-web-challenge-hint",
    "interpretation": (
        "the compact challenge entry orchestrates a selected proof worker; "
        "entry-only evidence is incomplete without worker-context execution"
    ),
    "non_claim": (
        "worker presence and API activity do not establish proof completion, "
        "proof value correctness, submission, challenge passage, or acceptance"
    ),
}

_SHAPE_GLOBAL_ENUMERATION_ANALYSIS_BOUNDARY = {
    "kind": "global-interface-enumeration-dominated",
    "basis": "classifier-owned-shape-hint",
    "interpretation": (
        "binding surfaces can include broad Window interface enumeration; "
        "an api.Window.<Interface> entry records a global property read, not "
        "active use of that interface"
    ),
    "non_claim": (
        "the hint and enumerated names do not prove the collector used each "
        "interface, identify VM operations or fingerprint fields, establish "
        "payload contribution, or acceptance"
    ),
}

_AKAMAI_WEB_NOT_MOBILE_BMP_ANALYSIS_BOUNDARY = {
    "kind": "web-bot-manager-not-mobile-bmp",
    "basis": "classifier-owned-akamai-bmp-web-hint",
    "interpretation": (
        "the bmak-based hint identifies an Akamai browser-script family; "
        "it must not be interpreted with the mobile BMP request-header contract"
    ),
    "non_claim": (
        "the hint does not identify every Akamai web collector family, a "
        "collector release, field semantics, cryptographic behavior, payload "
        "validity, or acceptance"
    ),
}

_AKAMAI_SBSD_NOT_MOBILE_BMP_ANALYSIS_BOUNDARY = {
    "kind": "web-bot-manager-not-mobile-bmp",
    "basis": "classifier-owned-akamai-sbsd-web-hint",
    "interpretation": (
        "the complete SBSD marker cluster identifies an Akamai browser-script "
        "family; it must not be interpreted with the mobile BMP request-header "
        "contract"
    ),
    "non_claim": (
        "the hint does not make SBSD equivalent to the bmak-based main family, "
        "identify every deployment profile, establish field or payload "
        "semantics, validity, or acceptance"
    ),
}

_PRODUCT_SCRIPT_ANALYSIS_BOUNDARIES = {
    "akamai-bmp-web": _AKAMAI_WEB_NOT_MOBILE_BMP_ANALYSIS_BOUNDARY,
    "akamai-sbsd-web": _AKAMAI_SBSD_NOT_MOBILE_BMP_ANALYSIS_BOUNDARY,
    "kasada": _KASADA_VM_ANALYSIS_BOUNDARY,
    "geetest-v4-loader": _GEETEST_LOADER_ANALYSIS_BOUNDARY,
    "cloudflare-turnstile": _TURNSTILE_CHALLENGE_STAGE_ANALYSIS_BOUNDARY,
    "imperva-apg-loader": _IMPERVA_DOWNSTREAM_SCRIPT_ANALYSIS_BOUNDARY,
    "anubis-web-challenge": _ANUBIS_WORKER_CONTEXT_ANALYSIS_BOUNDARY,
    "shape": _SHAPE_GLOBAL_ENUMERATION_ANALYSIS_BOUNDARY,
}

# Version 2 preserves the number of matching DOM nodes for every redaction-safe
# resource-intent shape. Version 1 projected only the unique shapes, so evidence
# produced before and after that change must not claim the same capture method.
RESOURCE_INTENT_CONTRACT = "cdp_dom_snapshot/2"
RESOURCE_INTENT_CONTRACTS = {"cdp_dom_snapshot/1", RESOURCE_INTENT_CONTRACT}
OBSERVER_SEQUENCE_CONTRACT = "browser-core.product-script-observer-sequence/1"
REQUEST_ACTIVITY_METHODS = frozenset({"GET", "POST"})
REQUEST_ACTIVITY_SERVED_CLASSES = frozenset({"empty", "post-ack", "stage"})
PROXY_DENIED_METHODS = frozenset(
    {
        "CONNECT",
        "DELETE",
        "GET",
        "HEAD",
        "OPTIONS",
        "OTHER",
        "PATCH",
        "POST",
        "PUT",
        "TRACE",
    }
)
REHOST_REQUEST_SERVED_CLASSES = frozenset(
    {"page", "sample", "hook", "empty", "post-ack", "stage", "proxy-denied"}
)
MAX_OBSERVATION_SECONDS = 86_400.0
MAX_OBSERVATION_RELOADS = 1_000
MAX_METHOD_SOURCE_BYTES = 256_000
MAX_READY_EXPRESSION_BYTES = 16_384
MAX_PRODUCT_SCRIPT_BYTES = 128 * 1024 * 1024
MAX_STAGE_ROUTES = 128
MAX_STAGE_BYTES = 128 * 1024 * 1024
MAX_REHOST_POST_BODY_BYTES = 16 * 1024 * 1024
REQUEST_BODY_CHUNK_BYTES = 64 * 1024
MAX_REHOST_REQUEST_LOG_ENTRIES = 10_000
REHOST_BODY_READ_TIMEOUT_SECONDS = 5.0
MAX_REHOST_LOG_PATH_CHARS = 4_096
MAX_DECLARED_SCRIPT_URL_BYTES = 16_384
MAX_OBSERVATION_BROWSER_ARGS = 128
MAX_OBSERVATION_BROWSER_ARG_BYTES = 4_096
MAX_OBSERVATION_DOCUMENT_BYTES = 64 * 1024 * 1024
MAX_PAGE_PROBE_JSON_BYTES = 1024 * 1024
MAX_GIT_PROVENANCE_OUTPUT_BYTES = 2 * 1024 * 1024
MAX_GIT_PROVENANCE_TRACKED_FILES = 16_384
MAX_GIT_PROVENANCE_TRACKED_BYTES = 512 * 1024 * 1024
MAX_GIT_PROVENANCE_TRACKED_FILE_BYTES = 128 * 1024 * 1024
MAX_GIT_PROVENANCE_SCAN_SECONDS = 60.0
MAX_BUILD_RECIPE_BYTES = 16 * 1024 * 1024
REHOST_SERVER_CLEANUP_TIMEOUT_SECONDS = 5.0

PAGE_TITLE = "browser-core-product-script-rehost"
GENERATED_COMPONENT = "blink.bindings.generated"


# This DNS rule rejects every non-loopback hostname with Chromium's pinned
# failure sentinel. IP literals do not traverse the host mapper; the launcher's
# exact-origin proxy bypass and owned deny proxy contain those requests instead.
# The rule is generated only after the exclusive rehost listener owns its port.
def _offline_resolver_rule(port: int) -> str:
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        raise ContractError("offline rehost port is invalid")
    return "--host-resolver-rules=" f"MAP 127.0.0.1 127.0.0.1:{port}, MAP * ^NOTFOUND"


_NORMALIZED_OFFLINE_GUARD = {
    "status": "applied",
    "resolver_policy": "owned-loopback-port-map-and-not-found-others",
    "proxy_policy": "deny-all-except-owned-loopback-origin",
    "webrtc_policy": "disable-non-proxied-udp",
    "quic_policy": "disabled",
    "endpoint_coherence": "single-owned-loopback-port",
}


def _sanitize_offline_guard(value: Any) -> dict[str, str]:
    """Validate raw containment arithmetic and return a port-free method receipt."""
    if value is None:
        return {"status": "not-recorded"}
    if not isinstance(value, dict):
        return {"status": "unverifiable"}
    if value in ({"status": "not-recorded"}, {"status": "unverifiable"}):
        return dict(value)
    if value == {"status": "not-applied"}:
        return {"status": "not-applied"}
    if value == _NORMALIZED_OFFLINE_GUARD:
        return dict(_NORMALIZED_OFFLINE_GUARD)
    if set(value) != {
        "status",
        "resolver_rule",
        "proxy_policy",
        "webrtc_policy",
        "quic_policy",
        "proxy_endpoint",
        "bypass_endpoint",
    }:
        return {"status": "unverifiable"}
    proxy_endpoint = value.get("proxy_endpoint")
    bypass_endpoint = value.get("bypass_endpoint")
    match = (
        re.fullmatch(r"127\.0\.0\.1:([1-9][0-9]{0,4})", proxy_endpoint)
        if isinstance(proxy_endpoint, str)
        else None
    )
    if match is None or bypass_endpoint != proxy_endpoint:
        return {"status": "unverifiable"}
    port = int(match.group(1))
    if port > 65535:
        return {"status": "unverifiable"}
    if (
        value.get("status") != "applied"
        or value.get("resolver_rule") != _offline_resolver_rule(port)
        or value.get("proxy_policy") != _NORMALIZED_OFFLINE_GUARD["proxy_policy"]
        or value.get("webrtc_policy") != _NORMALIZED_OFFLINE_GUARD["webrtc_policy"]
        or value.get("quic_policy") != _NORMALIZED_OFFLINE_GUARD["quic_policy"]
    ):
        return {"status": "unverifiable"}
    return dict(_NORMALIZED_OFFLINE_GUARD)


def _read_stable_regular_bytes(path: Path, *, maximum: int, label: str) -> bytes:
    if not isinstance(path, Path):
        raise ContractError(f"{label} path must be a Path")
    snapshot = read_bounded_control_snapshot_result(
        path,
        maximum=maximum,
        label=label,
    )
    if snapshot.state != "complete" or snapshot.body is None:
        raise ContractError(f"{label} is {snapshot.state}")
    return snapshot.body


class _QuietThreadingHTTPServer(LocalPanelServer):
    """Do not dump expected browser-shutdown disconnects to stderr.

    Chromium can reset idle keep-alive sockets while the session is closing. The
    standard library reports those from its request-reading layer with a full
    traceback even though the observation itself completed. Suppress only the
    disconnect classes; every application/server exception still delegates to the
    standard error reporter.
    """

    def handle_error(self, request: Any, client_address: Any) -> None:
        error = sys.exc_info()[1]
        if isinstance(
            error, (BrokenPipeError, ConnectionAbortedError, ConnectionResetError)
        ):
            return
        stopping = getattr(self, "_panel_stopping", None)
        if stopping is None or not stopping.is_set():
            ThreadingHTTPServer.handle_error(self, request, client_address)


def _stop_rehost_server(
    server: Any | None,
    thread: Any | None,
    *,
    thread_started: bool,
) -> list[str]:
    failures: list[str] = []
    if server is None:
        return failures
    worker_alive = False
    if thread_started and thread is not None:
        try:
            worker_alive = thread.is_alive()
            if type(worker_alive) is not bool:
                failures.append("worker-status")
                worker_alive = True
        except (OSError, RuntimeError):
            failures.append("worker-status")
            worker_alive = True
    shutdown_thread: Any | None = None
    shutdown_deadline = time.monotonic() + REHOST_SERVER_CLEANUP_TIMEOUT_SECONDS
    if worker_alive:
        shutdown_failed: list[bool] = []

        def shutdown() -> None:
            try:
                server.shutdown()
            except Exception:
                shutdown_failed.append(True)

        try:
            shutdown_thread = Thread(
                target=shutdown,
                name="browser-core-product-rehost-shutdown",
                daemon=True,
            )
            shutdown_thread.start()
            shutdown_thread.join(
                timeout=max(0.0, shutdown_deadline - time.monotonic())
            )
            if shutdown_thread.is_alive() or shutdown_failed:
                failures.append("server-shutdown")
        except (OSError, RuntimeError):
            failures.append("server-shutdown")
    try:
        server.server_close()
    except Exception:
        failures.append("server-close")
    if shutdown_thread is not None:
        try:
            shutdown_thread.join(
                timeout=max(0.0, shutdown_deadline - time.monotonic())
            )
            if shutdown_thread.is_alive() and "server-shutdown" not in failures:
                failures.append("server-shutdown")
        except (OSError, RuntimeError):
            if "server-shutdown" not in failures:
                failures.append("server-shutdown")
    if thread_started and thread is not None:
        try:
            thread.join(timeout=REHOST_SERVER_CLEANUP_TIMEOUT_SECONDS)
            if thread.is_alive():
                failures.append("worker-thread")
        except (OSError, RuntimeError):
            failures.append("worker-thread")
    return failures


_MINIMAL_BODY = """
<div id="root">offline rehost</div>
<form id="rehost-form" action="/submit" method="post">
  <input type="text" name="q" id="q" value="">
  <input type="submit" value="go">
</form>
"""

# A collector that walks the DOM could in principle reach surfaces a bare page never
# exercises, which would make a minimal-page result an artifact rather than a finding.
# The rich profile exists to test exactly that: same script, materially larger and more
# varied document, compare the attributed surface. It is synthetic and deterministic,
# so the comparison is about DOM richness and nothing else.
_RICH_BODY = """
<header id="hdr"><nav><ul>
  <li><a href="/a">a</a></li><li><a href="/b">b</a></li><li><a href="/c">c</a></li>
</ul></nav></header>
<main>
  <section id="s1"><h1>heading</h1><p>paragraph one</p><p>paragraph two</p></section>
  <form id="search" action="/submit" method="post">
    <input type="text" name="q" id="q" value="seed">
    <input type="email" name="email" id="email" value="">
    <input type="password" name="pw" id="pw" value="">
    <input type="hidden" name="csrf" id="csrf" value="0">
    <input type="checkbox" name="opt" id="opt" checked>
    <input type="radio" name="r" value="1"><input type="radio" name="r" value="2">
    <select name="sel" id="sel"><option>1</option><option>2</option></select>
    <textarea name="ta" id="ta">text</textarea>
    <button type="submit">go</button>
  </form>
  <form id="login" action="/login" method="post">
    <input type="text" name="user" value=""><input type="password" name="pass" value="">
  </form>
  <table id="t"><thead><tr><th>h</th></tr></thead><tbody>
    <tr><td>1</td></tr><tr><td>2</td></tr><tr><td>3</td></tr></tbody></table>
  <ul id="list">
    <li>1</li><li>2</li><li>3</li><li>4</li><li>5</li><li>6</li><li>7</li><li>8</li>
  </ul>
  <img id="img" width="4" height="4" alt="x"
       src="data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7">
  <video id="vid" width="8" height="8"></video>
  <audio id="aud"></audio>
  <canvas id="cv" width="8" height="8"></canvas>
  <iframe id="ifr" title="ifr" srcdoc="<p>inner</p>" width="8" height="8"></iframe>
  <div id="deep"><div><div><div><div><span>deep</span></div></div></div></div></div>
</main>
<footer id="ftr"><small>footer</small></footer>
"""

_TALL_BODY = (
    _MINIMAL_BODY
    + """
<div id="bc-scroll-space" aria-hidden="true" style="height: 2400px"></div>
"""
)

DOM_PROFILES = {"minimal": _MINIMAL_BODY, "rich": _RICH_BODY, "tall": _TALL_BODY}

DEFAULT_SCRIPT_PATH = "/product-script.js"

# The argument instrument is served from its own path and loaded before the sample,
# so the sample runs against wrapped built-ins.
HOOK_SCRIPT_PATH = "/bc-observer.js"

# A serving path is embedded in an HTML URL and then compared with the request
# target received by ``BaseHTTPRequestHandler``.  Accept only RFC 3986 path
# characters that survive that round trip unchanged.  In particular, ``?`` and
# ``#`` are not part of the request path, ``//host/path`` is a network-path
# reference, and raw whitespace/backslashes are normalized by browsers.  Any of
# those previously produced a plausible observation whose sample request was
# actually answered by the empty fallback.
_SCRIPT_PATH_RE = re.compile(r"/(?:[A-Za-z0-9._~!$&'()*+,;=:@/-]|%[0-9A-Fa-f]{2})*\Z")


def _validate_script_path(script_path: Any, hook_mode: str = "off") -> str:
    if (
        not isinstance(script_path, str)
        or script_path == "/"
        or script_path.startswith("//")
        or len(script_path) > 512
        or _SCRIPT_PATH_RE.fullmatch(script_path) is None
    ):
        raise ContractError("script path must be a short absolute URL path")
    if hook_mode != "off" and script_path == HOOK_SCRIPT_PATH:
        raise ContractError("script path collides with the observation hook path")
    return script_path


def _validate_declared_script_url(value: Any) -> str:
    if not isinstance(value, str):
        raise ContractError("declared script URL must be text")
    try:
        encoded = value.encode("utf-8", errors="strict")
        parsed = urlsplit(value)
        parsed.port
    except (UnicodeEncodeError, UnicodeError, ValueError):
        raise ContractError(
            "declared script URL must be an absolute credential-free HTTPS URL"
        ) from None
    if (
        not encoded
        or len(encoded) > MAX_DECLARED_SCRIPT_URL_BYTES
        or any(byte < 0x20 or byte == 0x7F for byte in encoded)
        or parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or _manifest_url({"url": value.split("#", 1)[0]}) is None
    ):
        raise ContractError(
            "declared script URL must be an absolute credential-free HTTPS URL"
        )
    return value


def _validate_stage_prefix(prefix: Any) -> str:
    if (
        not isinstance(prefix, str)
        or prefix.startswith("//")
        or len(prefix) > 512
        or _SCRIPT_PATH_RE.fullmatch(prefix) is None
    ):
        raise ContractError("stage route prefix must be a short absolute URL path")
    return prefix


def _bounded_utf8_source(
    value: Any, *, label: str, maximum: int, non_empty: bool = False
) -> bytes:
    if not isinstance(value, str) or (non_empty and not value.strip()):
        qualifier = "non-empty " if non_empty else ""
        raise ContractError(f"{label} must be a {qualifier}bounded UTF-8 string")
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ContractError(f"{label} must be valid UTF-8 text") from exc
    if len(encoded) > maximum:
        raise ContractError(f"{label} source exceeds {maximum} bytes (bounded limit)")
    return encoded


def _validate_prelude_source(value: Any) -> str:
    _bounded_utf8_source(value, label="prelude", maximum=MAX_METHOD_SOURCE_BYTES)
    if "</script" in value.lower():
        raise ContractError(
            "prelude refuses '</script': embedding it would truncate the element"
        )
    return value


def _validate_observation_browser_args(value: Any) -> tuple[str, ...]:
    if not isinstance(value, tuple) or len(value) > MAX_OBSERVATION_BROWSER_ARGS:
        raise ContractError(
            f"extra browser arguments must be a tuple of at most "
            f"{MAX_OBSERVATION_BROWSER_ARGS} flags"
        )
    for argument in value:
        if not isinstance(argument, str) or not argument.startswith("--"):
            raise ContractError(
                "each extra browser argument must be one complete long flag"
            )
        _bounded_utf8_source(
            argument,
            label="extra browser argument",
            maximum=MAX_OBSERVATION_BROWSER_ARG_BYTES,
        )
        if any(ord(character) < 32 or ord(character) == 127 for character in argument):
            raise ContractError(
                "extra browser arguments cannot contain control characters"
            )
        name = argument.split("=", 1)[0].lower()
        if name in {
            "--host-resolver-rules",
            "--host-rules",
            "--no-proxy-server",
            "--enable-quic",
            "--disable-quic",
            "--origin-to-force-quic-on",
            "--quic-version",
        }:
            raise ContractError(
                "extra browser arguments cannot override the offline network guard"
            )
    validate_evaluation_extra_args(value)
    return value


# Three page shapes, because two different things change when the instrument is
# switched on and they must be separable.
#
# ``off``   -- no extra tag at all. Byte-identical to the page every archived arm
#              was observed against, so turning this feature on does not silently
#              invalidate the existing corpus. This is and stays the default.
# ``inert`` -- the tag is present and serves an empty file. Same document shape as
#              ``on`` (``document.scripts.length`` agrees) with no wrapping.
# ``on``    -- the tag is present and serves the instrument.
#
# The fidelity control compares ``on`` against ``inert``, which isolates the effect
# of *wrapping built-ins* from the effect of *there being one more script element*.
# Comparing ``on`` against ``off`` would conflate the two and blame the wrappers for
# whatever the tag did.
HOOK_MODES = ("off", "inert", "on")

# Longest wait for Chromium to finish flushing its Perfetto trace after the browser
# has exited. See `_await_trace_file`.
TRACE_SETTLE_TIMEOUT = 15.0

# Perfetto's compact protobuf can expand many-fold when normalized to JSONL. The
# measured Anubis WebCrypto stress arm was 232 MB before export, while a 22.8 MB
# bounded arm expanded to 168 MB. Refuse automatic normalization above 128 MiB so
# one high-rate loop cannot consume unbounded memory/disk; the source trace and
# its flush receipt remain available for an explicit operator decision.
MAX_OBSERVATION_TRACE_EXPORT_BYTES = 128 * 1024 * 1024
MAX_OBSERVATION_TRACE_EXPORT_EVENTS = 500_000

# Browser Core's general lifecycle keeps a five-second graceful-close default.
# Observation runs reserve longer because startup Perfetto tracing is flushed on
# Chromium exit. Three missing-trace arms measured on 2026-08-09 stopped about five
# seconds later than their successful neighbours, matching the force boundary.
TRACE_GRACEFUL_STOP_TIMEOUT = 15.0

AMBIENT_INPUT_EVENT_NAMES = frozenset(
    {
        "mousemove",
        "mousedown",
        "mouseup",
        "click",
        "keydown",
        "keyup",
        "touchstart",
        "touchmove",
        "touchend",
        "wheel",
        "scroll",
    }
)

STARTUP_EXACT_VENDOR_GLOBALS = frozenset(
    {"KPSDK", "__anubisBooted", "bmak", "initGeetest4", "turnstile"}
)
STARTUP_VENDOR_GLOBAL_PREFIXES = (
    ("__pxaction", "__pxAction*"),
    ("_px", "_px*"),
    ("datadome", "datadome*"),
    ("_cf", "_cf*"),
    ("kpsdk", "KPSDK*"),
    ("bmak", "bmak*"),
    ("turnstile", "turnstile*"),
)

#: Installed before anything else on the page, so it is listening when the product
#: script is parsed.
#:
#: Without it a run cannot tell "the collector executed and touched nothing" from
#: "the collector threw on its first line", and those look identical in every
#: artifact the run produces: zero attributable events, a clean subtraction, and a
#: comparison table that reads like a successful measurement of a quiet script.
#: Measured on the Kasada web pin, whose `ips.js` throws `KPSDK is not defined`
#: immediately -- its arm reported exactly the control's 3,276 events and 188 API
#: names, which is what an empty file produces.
#: It uses `window.onerror =` rather than `addEventListener` because an
#: event-handler property is a plain assignment while `addEventListener` is a
#: WebIDL-bound call, and a witness that appears in the trace of every arm --
#: including the control that gets subtracted -- can only mask what the script
#: does. That is a precaution and not a repair: both spellings were measured and
#: attribute the identical 121 names, symmetric difference 0. The 7-name gap that
#: prompted the change came from somewhere else entirely; see `grade_ambient_input`.
_STARTUP_WITNESS = """<script>
(() => {
  const w = (window.__bc_startup = {errors: [], rejections: []});
  window.onerror = function (message) {
    if (w.errors.length < 20) { w.errors.push(String(message).slice(0, 300)); }
    return false;
  };
  window.onunhandledrejection = function (e) {
    if (w.rejections.length < 20) {
      w.rejections.push(String((e && e.reason && e.reason.message) || (e && e.reason) || e).slice(0, 300));
    }
  };
  w.propsBefore = Object.getOwnPropertyNames(window).length;

  // Ambient input. A headed arm is a real window on a real desktop, and a mouse
  // that crosses it delivers trusted events the run never asked for -- which the
  // collector then acts on, because event authenticity is exactly what it is
  // counting. Measured: an arm with input_profile "none" reported 128
  // attributable names where three later arms of the same bytes reported 121,
  // and the seven extra were MouseEvent.constructor / isTrusted / pageX / pageY /
  // toElement, Document.activeElement and HTMLFormElement.constructor. Nothing in
  // that artifact said a mouse had been over the window.
  //
  // Counting is per event type and trusted-only, and the handlers are capturing
  // properties on document rather than addEventListener calls, for the same
  // reason the error handlers are.
  w.ambient = {};
  const note = (type) => (e) => {
    if (e && e.isTrusted) { w.ambient[type] = (w.ambient[type] || 0) + 1; }
  };
  document.onmousemove = note('mousemove');
  document.onmousedown = note('mousedown');
  document.onmouseup = note('mouseup');
  document.onclick = note('click');
  document.onkeydown = note('keydown');
  document.onkeyup = note('keyup');
  document.ontouchstart = note('touchstart');
  document.ontouchmove = note('touchmove');
  document.ontouchend = note('touchend');
  document.onwheel = note('wheel');
  document.onscroll = note('scroll');
})();
</script>
"""

_PAGE_HTML_INLINE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>{title}</title></head>
<body>
{witness}{body}
{prelude_tag}{hook_tag}<script>{source}</script>
</body></html>
"""

_PAGE_HTML = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>{title}</title></head>
<body>
{witness}{body}
{prelude_tag}{declared_source_tag}{hook_tag}<script src="{script_path}"></script>
</body></html>
"""

#: Read back after the dwell. Reports what the witness caught, plus whether any
#: vendor global appeared and -- where the vendor exposes one -- whether it says it
#: is ready. Kasada's client publishes `KPSDK.isReady()`, which answered `false`
#: for the whole dwell of every offline arm: the collector is inert until the host
#: page calls `KPSDK.configure()`, and a bare rehost page never does.
_STARTUP_JS = """
(() => {
  const s = window.__bc_startup || {errors: [], rejections: [], propsBefore: null};
  const names = Object.getOwnPropertyNames(window);
  const vendor = names.filter((n) => /^(bmak|KPSDK|_px|__pxAction|datadome|turnstile|_cf|initGeetest4|__anubisBooted)/i.test(n));
  let ready = null;
  try {
    if (window.KPSDK && typeof window.KPSDK.isReady === 'function') {
      ready = !!window.KPSDK.isReady();
    }
  } catch (e) { ready = 'threw'; }
  return JSON.stringify({
    uncaught_errors: s.errors,
    unhandled_rejections: s.rejections,
    ambient_input: s.ambient === undefined ? null : s.ambient,
    vendor_globals: vendor,
    vendor_reports_ready: ready,
    window_properties: names.length,
    window_properties_before_script: s.propsBefore === undefined ? null : s.propsBefore
  });
})()
"""


@dataclass(frozen=True)
class ProductScriptObservation:
    """One rehost arm."""

    script: Path
    label: str
    executable: Path
    trace_processor: Path
    workspace: Path
    dwell_seconds: float = 20.0
    trace_scope: str = "broad"
    headed: bool = True
    timeout_seconds: float = 60.0
    dom_profile: str = "minimal"
    # Extra page loads after the first, each followed by another dwell. The script
    # then runs against cookies and storage *it* set on the previous load, so a
    # warm-state observation needs no fabricated session material.
    reloads: int = 0
    # Path the sample is served from. The collector reads its own script src, so this
    # can be set to mirror a real deployment's path.
    script_path: str = DEFAULT_SCRIPT_PATH
    # Original public URL represented by a non-executing script element.
    #
    # Some loaders validate their own source URL before doing anything. A loopback
    # path preserves the path but necessarily replaces the hostname; Cloudflare's
    # Turnstile v0 loader then throws before installing `turnstile`. The declared
    # element preserves the URL the saved bytes were fetched from without fetching
    # it or weakening the offline resolver. It is explicit because adding a script
    # element changes the host document and therefore the measurement.
    declared_script_url: str | None = None
    # Capture tree used to resolve where these bytes actually came from.
    #
    # `label` is free text. It is copied into the subtraction, the baseline, the
    # digest, and from there into prose, and nothing ever checks it. Measured
    # 2026-08-06: of eight site attributions carried by two knowledge notes, four
    # rested on nothing but the directory a file happened to sit in -- and one
    # script recorded as served from `www.homedepot.com` sits in two *FedEx*
    # capture directories.
    #
    # Setting this binds a provenance verdict into the observation at capture
    # time, so a downstream reader sees whether the label was ever backed by
    # anything. Left unset, the observation records that provenance was not
    # checked, which is different from checking it and finding nothing.
    captures_root: Path | None = None
    # Public-source provenance for artifacts that did not come from a capture tree.
    # All three values are required together and the full digest is checked before
    # a browser launches. This records a vendor URL pin without pretending that an
    # operator label proves where bytes came from.
    source_url: str | None = None
    source_retrieved_at: str | None = None
    source_sha256: str | None = None
    # Git-input provenance for a generated public artifact.  This is deliberately
    # distinct from ``source_url``: a release tag can bind the tracked source and
    # build recipe, but it does not magically make an ignored bundle a tracked
    # release asset.  The grade therefore records both facts -- verified Git
    # inputs and an exact local artifact digest -- and makes the missing
    # independent rebuild an explicit non-claim.
    source_git_checkout: Path | None = None
    source_git_repository_url: str | None = None
    source_git_revision: str | None = None
    source_build_recipe: Path | None = None
    # Optional second-checkout artifact match. Both values must be supplied
    # together; the verifier requires a distinct clean checkout at the same
    # origin/revision and a byte-identical artifact at the same relative path.
    # It cannot prove how those bytes were produced, so the output never calls
    # this a verified rebuild.
    source_rebuild_checkout: Path | None = None
    source_rebuild_artifact: Path | None = None
    # Host-page configuration evaluated after the deterministic DOM exists and
    # before the product script loads. Only length and digest are retained: setup
    # code can contain a client identifier and must not become an accidental
    # credential sink in observation JSON.
    prelude_js: str | None = None
    # Extra Chromium flags for method controls.
    #
    # Exists because a collector can branch on the environment, and the only way
    # to find the branch is to vary one property at a time. Measured 2026-08-06:
    # the 16-name DeviceMotion block executes on 39 of 39 headless main-sensor
    # pins and only 14 of 30 headed ones, so *something* headless-distinctive
    # gates it -- window geometry, device scale, media-query results. Narrowing
    # that needs a headed browser wearing one headless-like property.
    #
    # Recorded in the observation document, not just applied. An arm launched
    # with unusual flags that does not say so is the next confound; that is the
    # exact failure this session spent an hour unwinding.
    extra_browser_args: tuple[str, ...] = ()
    # Active argument instrumentation. Off by default and deliberately so: it is the
    # only thing in this module that changes the page the sample runs on, and a
    # default-on instrument would make every observation an instrumented one.
    #
    # "off" is byte-identical to the page every archived arm was observed against.
    # "inert" adds the tag without the wrappers, which is the honest partner for
    # "on" in a fidelity comparison. See HOOK_MODES.
    hook_mode: str = "off"
    # Deliver trusted input during the dwell. "none" (default) leaves the run
    # exactly as every archived arm was taken. "probe" fires the collector's bound
    # listeners so the "registration is not collection" caveat becomes testable.
    input_profile: str = "none"
    # Install only these instrumented names (empty = all of them).
    #
    # Exists for bisection. When a fidelity control reports that the instrument
    # changed what a sample did, the next question is *which wrapper* did it, and
    # the only way to answer is to install subsets and re-measure.
    hook_target_names: tuple[str, ...] = ()
    # Additional saved scripts, served at the paths the client asks for.
    #
    # A single-script rehost can only observe a collector that arrives in one
    # piece. Kasada's does not: `p.js` installs a facade, and the interrogation
    # stage is fetched from a first-party tenant path at runtime. Offline that
    # fetch dies, so the arm attributes six API names to a collector that never
    # started -- and every artifact reads like a successful measurement.
    #
    # Both stages are in the corpus, so the fetch can be answered from disk.
    # Measured 2026-08-08: with the second stage served, `KPSDK.isReady()` goes
    # from false to true and the client proceeds to its fingerprint endpoint.
    # Nothing here reaches the network; the offline resolver rule is unchanged and
    # every path is answered locally or 404s.
    stage_routes: tuple[tuple[str, Path], ...] = ()
    # Perform the host page's role, once, after the sample has loaded.
    #
    # A collector that waits to be driven cannot be observed by a page that never
    # drives it. This is the documented client entry point and nothing more -- for
    # Kasada, `KPSDK.configure([...])`, whose own error message ("Configuration
    # endpoints are not an array") states the contract.
    #
    # Recorded as length + digest only, because an arm that was driven is a
    # different measurement from one that was not, but host setup can contain
    # tenant keys or endpoints that do not belong in an observation artifact.
    driver_js: str | None = None
    # Wait for the collector instead of sleeping a fixed dwell.
    #
    # `dwell_seconds` is a sleep, and a sleep cannot tell you whether the thing it
    # was waiting for happened. Measured 2026-08-08: 20-second and 150-second
    # dwells produced byte-identical counts on a driven Kasada arm -- 3,377 events,
    # 221 API names, 24 attributable -- because neither waited for anything, while
    # the readback fired in the middle of a solve that holds the main thread for
    # about 102 seconds.
    #
    # When set, the arm polls the client's own readiness signal where it publishes
    # one and falls back to plain responsiveness where it does not, then records
    # *why* it stopped. An arm that ended on the cap and an arm that ended because
    # the collector finished are different measurements and must not be
    # indistinguishable in the artifact.
    await_ready_seconds: float = 0.0
    # Optional vendor-specific boolean expression for readiness polling. The
    # default probe knows only KPSDK.isReady(); a hard-coded vendor probe made the
    # wait unusable for every new collector. Only its byte count and digest are
    # retained, and it may produce only a boolean signal; no token value is read.
    ready_expression: str | None = None
    # Embed the sample in the page instead of linking it.
    #
    # A collector that shipped inline never had a script URL, and several read
    # `document.currentScript`. Serving an inline sample as `<script src=...>`
    # hands it a URL it never had; serving an external one inline takes away a URL
    # it did have. Neither default is right for both, so the packaging is recorded
    # and settable rather than assumed.
    inline_script: bool = False
    # Passive CDP DOM snapshot after the dwell. It records only redacted
    # resource-bearing attributes and can be disabled for an observer-effect arm.
    capture_resource_intents: bool = True


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _validated_canonical_utc_timestamp(value: Any, role: str) -> str:
    try:
        stamp = datetime.fromisoformat(
            value.replace("Z", "+00:00") if isinstance(value, str) else ""
        )
    except ValueError:
        stamp = None
    canonical = (
        stamp.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
        if stamp is not None
        and stamp.tzinfo is not None
        and stamp.utcoffset() is not None
        else None
    )
    if not isinstance(value, str) or not value.endswith("Z") or value != canonical:
        raise ContractError(f"{role} generated_at must be canonical UTC")
    return value


def _prelude_metadata(prelude_js: str | None) -> dict[str, Any]:
    """Identify pre-load setup without retaining its possibly sensitive source."""
    if prelude_js is None:
        return {"supplied": False, "bytes": 0, "sha256_16": None}
    try:
        payload = prelude_js.encode("utf-8")
    except UnicodeEncodeError:
        return {
            "supplied": True,
            "bytes": 0,
            "sha256_16": None,
            **_unverifiable_method_value(prelude_js),
        }
    return {
        "supplied": True,
        "bytes": len(payload),
        "sha256_16": hashlib.sha256(payload).hexdigest()[:16],
    }


def _stored_js_metadata(value: Any) -> dict[str, Any]:
    """Normalize current metadata and hash a legacy raw JavaScript string."""
    if isinstance(value, dict):
        supplied = value.get("supplied")
        size = value.get("bytes")
        digest = value.get("sha256_16")
        if value.get("status") == "unverifiable":
            return {
                "supplied": supplied if isinstance(supplied, bool) else None,
                "bytes": 0,
                "sha256_16": None,
                **_unverifiable_method_value(value),
            }
        if (
            isinstance(supplied, bool)
            and isinstance(size, int)
            and not isinstance(size, bool)
            and 0 <= size <= 256_000_000
            and (
                digest is None
                or (
                    isinstance(digest, str) and re.fullmatch(r"[0-9a-fA-F]{16}", digest)
                )
            )
        ):
            return {
                "supplied": supplied,
                "bytes": size,
                "sha256_16": digest.lower() if isinstance(digest, str) else None,
            }
        return {
            "supplied": supplied if isinstance(supplied, bool) else None,
            "bytes": 0,
            "sha256_16": None,
            **_unverifiable_method_value(value),
        }
    return _prelude_metadata(value if isinstance(value, str) else None)


def _prelude_document_metadata(document: dict[str, Any]) -> dict[str, Any]:
    """Read current/raw observations and current/legacy subtractions safely."""
    value = document.get("prelude")
    if value is None:
        value = document.get("arm_prelude")
    return _stored_js_metadata(value)


def _driver_result_metadata(value: Any) -> dict[str, Any]:
    """Retain the shape of a driver return, never the returned value.

    A host driver can accidentally return a challenge token, configured key, or
    widget identifier. None is needed to establish that the host call ran; type,
    serialized size, and collection cardinality are enough to distinguish the
    common outcomes without turning an evidence artifact into a value capture.
    """
    if value is None:
        kind = "null"
    elif isinstance(value, bool):
        kind = "boolean"
    elif isinstance(value, str):
        kind = "string"
    elif isinstance(value, (int, float)):
        kind = "number"
    elif isinstance(value, list):
        kind = "array"
    elif isinstance(value, dict):
        kind = "object"
    else:
        kind = type(value).__name__
    try:
        serialized_bytes = len(
            json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        )
    except (OverflowError, RecursionError, TypeError, ValueError):
        serialized_bytes = None
    result = {"status": "ok", "type": kind, "serialized_bytes": serialized_bytes}
    if isinstance(value, (str, list, dict)):
        result["length"] = len(value)
    return result


def _stored_driver_result_metadata(value: Any) -> dict[str, Any]:
    """Allowlist current result metadata; reduce legacy return values to shape."""
    if (
        isinstance(value, dict)
        and isinstance(value.get("status"), str)
        and value.get("status") in {"ok", "failed"}
    ):
        if value.get("status") == "failed":
            error_type = value.get("error_type")
            return {
                "status": "failed",
                "error_type": (
                    error_type
                    if isinstance(error_type, str)
                    and re.fullmatch(r"[A-Za-z_$][A-Za-z0-9_$.-]{0,79}", error_type)
                    else "Error"
                ),
                "diagnostic": _redact_diagnostic(value.get("diagnostic") or "failed"),
            }
        result_type = value.get("type")
        serialized_bytes = value.get("serialized_bytes")
        result = {
            "status": "ok",
            "type": (
                result_type
                if isinstance(result_type, str)
                and result_type
                in {"null", "boolean", "string", "number", "array", "object"}
                else "unknown"
            ),
            "serialized_bytes": (
                serialized_bytes
                if isinstance(serialized_bytes, int)
                and not isinstance(serialized_bytes, bool)
                and 0 <= serialized_bytes <= 1_000_000_000
                else None
            ),
        }
        if "length" in value:
            length = value.get("length")
            if (
                isinstance(length, int)
                and not isinstance(length, bool)
                and 0 <= length <= 1_000_000_000
            ):
                result["length"] = length
        return result
    return _driver_result_metadata(value)


def _current_driver_result_receipt(
    document: dict[str, Any],
) -> tuple[bool, dict[str, Any] | None]:
    """Validate one producer driver outcome without retaining its return value."""
    supplied = _driver_supplied(document)
    if "driver_result" not in document:
        return False, None
    raw = document.get("driver_result")
    if not supplied:
        return raw is None, None
    if not isinstance(raw, dict):
        return False, None
    status = raw.get("status")
    if status == "failed":
        if set(raw) != {"status", "error_type", "diagnostic"}:
            return False, None
        safe = _stored_driver_result_metadata(raw)
        return False, safe
    if status != "ok" or set(raw) not in (
        {"status", "type", "serialized_bytes"},
        {"status", "type", "serialized_bytes", "length"},
    ):
        return False, None
    kind = raw.get("type")
    size = raw.get("serialized_bytes")
    needs_length = kind in {"string", "array", "object"}
    length = raw.get("length")
    coherent = bool(
        kind in {"null", "boolean", "string", "number", "array", "object"}
        and isinstance(size, int)
        and not isinstance(size, bool)
        and 0 <= size <= 1_000_000_000
        and ("length" in raw) == needs_length
        and (
            not needs_length
            or (
                isinstance(length, int)
                and not isinstance(length, bool)
                and 0 <= length <= 1_000_000_000
            )
        )
    )
    return coherent, (_stored_driver_result_metadata(raw) if coherent else None)


def _reconciled_driver_execution(
    arm: dict[str, Any], control: dict[str, Any], *, current_required: bool
) -> tuple[bool | None, dict[str, Any] | None, dict[str, Any] | None]:
    recorded = "driver_result" in arm or "driver_result" in control
    if not recorded and not current_required:
        return None, None, None
    arm_ok, arm_result = _current_driver_result_receipt(arm)
    control_ok, control_result = _current_driver_result_receipt(control)
    return arm_ok and control_ok, arm_result, control_result


def _saved_subtraction_driver_execution_receipts_coherent(
    document: dict[str, Any],
) -> bool:
    """Reconcile the retained arm/control driver receipts with their verdict."""
    fields = {
        "arm_driver",
        "control_driver",
        "arm_driver_supplied",
        "control_driver_supplied",
        "arm_driver_result",
        "control_driver_result",
        "driver_execution_complete",
    }
    if not fields <= document.keys():
        return False
    states: list[tuple[bool, bool, dict[str, Any] | None]] = []
    for side in ("arm", "control"):
        metadata = document.get(f"{side}_driver")
        supplied = document.get(f"{side}_driver_supplied")
        result = document.get(f"{side}_driver_result")
        pseudo = {"driver": metadata, "driver_result": result}
        result_ok, safe_result = _current_driver_result_receipt(pseudo)
        metadata_ok = bool(
            isinstance(metadata, dict)
            and _driver_metadata(pseudo) == metadata
            and _stored_js_method_is_coherent(metadata)
            and isinstance(supplied, bool)
            and _driver_supplied(pseudo) is supplied
        )
        states.append((metadata_ok, result_ok, safe_result))
    no_supplied_driver = bool(
        all(document.get(f"{side}_driver_supplied") is False for side in ("arm", "control"))
        and all(document.get(f"{side}_driver_result") is None for side in ("arm", "control"))
    )
    mismatches = document.get("arm_control_method_mismatches")
    driver_mismatch = isinstance(mismatches, list) and "driver" in mismatches
    expected: bool | None = (
        None
        if document.get("arm_control_method_comparable") is None
        and no_supplied_driver
        else False
        if no_supplied_driver and driver_mismatch
        else all(metadata_ok and result_ok for metadata_ok, result_ok, _ in states)
    )
    return bool(
        document.get("driver_execution_complete") is expected
        and all(
            document.get(f"{side}_driver_result") == states[index][2]
            for index, side in enumerate(("arm", "control"))
        )
    )


def _saved_subtraction_trace_receipts_coherent(document: dict[str, Any]) -> bool:
    """Reconcile a saved trace verdict with compact arm/control export receipts."""
    fields = {
        "arm_browser_shutdown",
        "control_browser_shutdown",
        "arm_trace_flush",
        "control_trace_flush",
        "arm_trace_evidence",
        "control_trace_evidence",
        "trace_evidence_coherent",
    }
    present = fields & document.keys()
    if not present:
        return True
    if present != fields:
        return False

    def compact_trace_supported(
        shutdown: Any, flush: Any, evidence: Any, revision: Any = None
    ) -> bool:
        if (
            not isinstance(shutdown, dict)
            or set(shutdown) != {"mode"}
            or shutdown.get("mode") not in {"graceful", "exited-before-force"}
            or not isinstance(flush, dict)
            or set(flush) != {"status", "bytes"}
            or flush.get("status") != "settled"
            or isinstance(flush.get("bytes"), bool)
            or not isinstance(flush.get("bytes"), int)
            or not 0 < flush["bytes"] <= MAX_OBSERVATION_TRACE_EXPORT_BYTES
            or not isinstance(evidence, dict)
            or set(evidence)
            != {"run_id", "chromium_revision", "source_trace", "normalized_trace"}
        ):
            return False
        source = evidence.get("source_trace")
        normalized = evidence.get("normalized_trace")
        if (
            not isinstance(source, dict)
            or set(source) != {"bytes", "sha256_16"}
            or not isinstance(normalized, dict)
            or set(normalized)
            != {
                "bytes",
                "sha256_16",
                "events",
                "trace_categories",
                "category_provenance",
            }
            or source.get("bytes") != flush["bytes"]
            or (revision is not None and evidence.get("chromium_revision") != revision)
        ):
            return False
        source_digest = source.get("sha256_16")
        normalized_digest = normalized.get("sha256_16")
        if (
            not isinstance(source_digest, str)
            or re.fullmatch(r"[0-9a-f]{16}", source_digest) is None
            or not isinstance(normalized_digest, str)
            or re.fullmatch(r"[0-9a-f]{16}", normalized_digest) is None
        ):
            return False
        expanded = {
            "schema": "browser-core.trace-export/1",
            "run_id": evidence.get("run_id"),
            "chromium_revision": evidence.get("chromium_revision"),
            "source_trace": {
                "format": "perfetto-trace",
                "bytes": source.get("bytes"),
                "sha256": source_digest * 4,
            },
            "normalized_trace": {
                "schema": "browser-core.trace-event/1",
                "bytes": normalized.get("bytes"),
                "sha256": normalized_digest * 4,
                "events": normalized.get("events"),
                "trace_categories": normalized.get("trace_categories"),
                "category_provenance": normalized.get("category_provenance"),
            },
        }
        try:
            validate_trace_export_report(expanded)
        except ContractError:
            return False
        return True

    trace_coherent = document.get("trace_evidence_coherent")
    trace_values = [document.get(field) for field in fields - {"trace_evidence_coherent"}]
    if all(value is None for value in trace_values) and trace_coherent is None:
        return True
    return bool(
        isinstance(trace_coherent, bool)
        and (
            not trace_coherent
            or (
                compact_trace_supported(
                    document.get("arm_browser_shutdown"),
                    document.get("arm_trace_flush"),
                    document.get("arm_trace_evidence"),
                    document.get("arm_chromium_revision"),
                )
                and compact_trace_supported(
                    document.get("control_browser_shutdown"),
                    document.get("control_trace_flush"),
                    document.get("control_trace_evidence"),
                )
            )
        )
    )


def _saved_subtraction_page_load_receipts_coherent(document: dict[str, Any]) -> bool:
    """Reconcile retained page-load counts with their saved execution verdict."""
    fields = {
        "arm_page_load_execution",
        "control_page_load_execution",
        "page_load_execution_coherent",
    }
    present = fields & document.keys()
    if not present:
        return True
    if present != fields:
        return False

    def page_load_grade(
        receipt: Any, *, inline_script: bool | None, hook_mode: Any
    ) -> tuple[bool, bool]:
        receipt_fields = {
            "configured_page_loads",
            "reported_page_loads",
            "page_requests",
            "sample_requests",
            "hook_requests",
        }
        if not isinstance(receipt, dict) or set(receipt) != receipt_fields:
            return False, False
        values = [receipt.get(field) for field in receipt_fields]
        if any(
            isinstance(value, bool)
            or not isinstance(value, int)
            or not 0 <= value <= 1_000_000_000
            for value in values
        ):
            return False, False
        expected = receipt["configured_page_loads"]
        base = bool(
            1 <= expected <= MAX_OBSERVATION_RELOADS + 1
            and receipt["reported_page_loads"] == expected
            and receipt["page_requests"] >= expected
            and isinstance(hook_mode, str)
            and hook_mode in HOOK_MODES
            and receipt["hook_requests"]
            >= (expected if hook_mode != "off" else 0)
        )
        if inline_script is None:
            return base, bool(base and receipt["sample_requests"] >= expected)
        sample_minimum = 0 if inline_script else expected
        coherent = bool(base and receipt["sample_requests"] >= sample_minimum)
        return coherent, coherent

    arm_receipt = document.get("arm_page_load_execution")
    control_receipt = document.get("control_page_load_execution")
    coherent = document.get("page_load_execution_coherent")
    if arm_receipt is None and control_receipt is None and coherent is None:
        return True
    arm_possible, arm_definite = page_load_grade(
        arm_receipt,
        inline_script=document.get("arm_inline_script"),
        hook_mode=document.get("arm_hook_mode"),
    )
    control_possible, control_definite = page_load_grade(
        control_receipt,
        inline_script=None,
        hook_mode=document.get("control_hook_mode"),
    )
    return bool(
        isinstance(coherent, bool)
        and (not coherent or (arm_possible and control_possible))
        and (coherent or not (arm_definite and control_definite))
    )


def _saved_subtraction_ready_probe_receipts_coherent(document: dict[str, Any]) -> bool:
    """Reconcile retained arm/control readiness expressions with their verdict."""
    fields = {
        "arm_ready_expression",
        "control_ready_expression",
        "ready_probe_comparable",
    }
    present = fields & document.keys()
    if not (present & {"arm_ready_expression", "control_ready_expression"}):
        return True
    if present != fields:
        return False
    arm_expression = document.get("arm_ready_expression")
    control_expression = document.get("control_ready_expression")
    comparable = document.get("ready_probe_comparable")
    return bool(
        isinstance(arm_expression, dict)
        and isinstance(control_expression, dict)
        and _ready_expression_metadata({"ready_expression": arm_expression})
        == arm_expression
        and _ready_expression_metadata({"ready_expression": control_expression})
        == control_expression
        and _stored_js_method_is_coherent(arm_expression)
        and _stored_js_method_is_coherent(control_expression)
        and isinstance(comparable, bool)
        and comparable is (arm_expression == control_expression)
    )


def _saved_subtraction_await_receipts_coherent(document: dict[str, Any]) -> bool:
    """Reconcile saved wait reports and timing with their claim verdicts."""
    fields = {
        "arm_await_ready_seconds",
        "arm_ready_expression",
        "control_ready_expression",
        "arm_await_report",
        "control_await_report",
        "await_method_comparable",
        "arm_readiness_satisfied",
    }
    receipt_fields = fields - {"await_method_comparable", "arm_readiness_satisfied"}
    present = fields & document.keys()
    if not (receipt_fields & present):
        return True
    if present != fields:
        return False
    raw_seconds = document.get("arm_await_ready_seconds")
    seconds = 0.0 if raw_seconds is None else raw_seconds
    arm_report = document.get("arm_await_report")
    control_report = document.get("control_await_report")
    arm_pseudo = {
        "await_ready_seconds": seconds,
        "await_report": arm_report,
        "ready_expression": document.get("arm_ready_expression"),
    }
    control_pseudo = {
        "await_ready_seconds": seconds,
        "await_report": control_report,
        "ready_expression": document.get("control_ready_expression"),
    }
    _, expected_arm_ready, safe_arm_report, _ = _reconciled_await_method(
        arm_pseudo, arm_pseudo
    )
    expected_comparable, _, _, safe_control_report = _reconciled_await_method(
        arm_pseudo, control_pseudo
    )
    comparable = document.get("await_method_comparable")
    arm_ready = document.get("arm_readiness_satisfied")
    return bool(
        is_finite_number(seconds)
        and 0 <= seconds <= MAX_OBSERVATION_SECONDS
        and arm_report == safe_arm_report
        and control_report == safe_control_report
        and isinstance(comparable, bool)
        and isinstance(arm_ready, bool)
        and arm_ready is expected_arm_ready
        and (comparable is not True or expected_comparable is True)
    )


def _saved_subtraction_request_activity_canonical(document: dict[str, Any]) -> bool:
    """Apply the writer's current and legacy request receipt shape rules."""
    if "request_activity" not in document:
        return True
    request_activity = document.get("request_activity")
    if not isinstance(request_activity, dict):
        return False
    if (
        document.get("subtraction_receipt_sha256") is not None
        and "non_claim" not in request_activity
    ):
        return False
    safe = _sanitize_request_activity_report(request_activity)
    current_fields = {
        "scope",
        "non_claim",
        "arm_requests",
        "control_requests",
        "shared_shapes",
        "clean_subtraction",
    }
    if current_fields & request_activity.keys():
        return safe == request_activity
    legacy_fields = {"status", "only_in_arm", "only_in_control"}
    return bool(
        request_activity.keys() <= legacy_fields
        and request_activity.get("status") == safe.get("status")
        and all(
            request_activity.get(field) == safe.get(field)
            for field in ("only_in_arm", "only_in_control")
            if field in request_activity
        )
    )


def _redact_diagnostic(value: Any) -> str:
    """Return a bounded diagnostic class plus a value-free correlation digest."""
    known_classes = (
        "AggregateError",
        "ConnectionError",
        "ContractError",
        "EvalError",
        "JSONDecodeError",
        "KeyError",
        "OSError",
        "RangeError",
        "ReferenceError",
        "RuntimeError",
        "SyntaxError",
        "TimeoutError",
        "TypeError",
        "URIError",
        "ValueError",
        "Error",
    )
    if isinstance(value, str) and re.fullmatch(
        rf"(?:{'|'.join(map(re.escape, (*known_classes, 'diagnostic')))})"
        r"; diagnostic_sha256_16=[0-9a-f]{16}",
        value,
    ):
        return value
    if isinstance(value, BaseException):
        class_name = type(value).__name__
        first = value.args[0] if value.args else None
        private = first if isinstance(first, str) else class_name
        embedded = next(
            (
                candidate
                for candidate in known_classes
                if re.search(
                    rf"(?<![A-Za-z0-9_$]){re.escape(candidate)}(?![A-Za-z0-9_$])",
                    private[:512],
                )
            ),
            None,
        )
        if embedded is not None:
            class_name = embedded
    elif isinstance(value, str):
        class_name = next(
            (
                candidate
                for candidate in known_classes
                if re.search(
                    rf"(?<![A-Za-z0-9_$]){re.escape(candidate)}(?![A-Za-z0-9_$])",
                    value[:512],
                )
            ),
            "diagnostic",
        )
        private = value
    else:
        class_name = type(value).__name__
        private = class_name
    if class_name not in known_classes:
        class_name = "diagnostic"
    bounded = private[:4_096].encode("utf-8", errors="replace")
    digest = hashlib.sha256(bounded).hexdigest()[:16]
    return f"{class_name}; diagnostic_sha256_16={digest}"


def _failure_receipt(category: str, error: BaseException) -> str:
    if re.fullmatch(r"[a-z][a-z0-9 -]{0,79}", category) is None:
        raise ContractError("failure receipt category is invalid")
    return f"{category}: {_redact_diagnostic(error)}"


def _is_strict_utf8_text(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    try:
        value.encode("utf-8", errors="strict")
    except UnicodeEncodeError:
        return False
    return True


def _project_public_url_shape(value: Any) -> dict[str, Any] | None:
    """Project a public HTTP(S) URL without retaining path or query values."""
    if (
        not _is_strict_utf8_text(value)
        or not value
        or len(value) > 16_384
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        return None
    try:
        parsed = urlsplit(value)
        parsed.port
    except (UnicodeError, ValueError):
        return None
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
    ):
        return None

    recorded_url = _manifest_url({"url": value.split("#", 1)[0]})
    if recorded_url is None:
        return None
    origin = f"{parsed.scheme}://{recorded_url[1]}"
    segments = [segment for segment in parsed.path.split("/") if segment]
    query_names: list[str] = []
    for item in parsed.query.split("&") if parsed.query else ():
        name = item.split("=", 1)[0]
        if (
            name
            and len(name) <= 80
            and not any(
                ord(character) < 32 or ord(character) == 127 for character in name
            )
        ):
            query_names.append(name)
    distinct_names = sorted(set(query_names))
    return {
        "origin": origin,
        "path_segment_lengths": [len(segment) for segment in segments[:32]],
        "path_segments_truncated": len(segments) > 32,
        "query_names": distinct_names[:64],
        "query_names_truncated": len(distinct_names) > 64,
        "fragment_present": "#" in value,
    }


def _declared_url_metadata(value: Any) -> dict[str, Any]:
    """Bind an exact declared URL while exposing only its structural shape."""
    if value is None:
        return {"supplied": False, "sha256_16": None, "shape": None}
    if isinstance(value, dict):
        supplied = value.get("supplied")
        digest = value.get("sha256_16")
        shape = value.get("shape")
        safe_shape = None
        if isinstance(shape, dict):
            safe_origin = _project_public_url_shape(shape.get("origin"))
            lengths = shape.get("path_segment_lengths")
            names = shape.get("query_names")
            if (
                safe_origin is not None
                and isinstance(lengths, list)
                and len(lengths) <= 32
                and all(
                    isinstance(item, int)
                    and not isinstance(item, bool)
                    and 0 <= item <= 16_384
                    for item in lengths
                )
                and isinstance(names, list)
                and len(names) <= 64
                and all(
                    _is_strict_utf8_text(item)
                    and len(item) <= 80
                    and not any(
                        ord(character) < 32 or ord(character) == 127
                        for character in item
                    )
                    for item in names
                )
                and all(
                    field not in shape or isinstance(shape.get(field), bool)
                    for field in (
                        "path_segments_truncated",
                        "query_names_truncated",
                        "fragment_present",
                    )
                )
            ):
                safe_shape = {
                    "origin": safe_origin["origin"],
                    "path_segment_lengths": list(lengths),
                    "path_segments_truncated": shape.get(
                        "path_segments_truncated", False
                    ),
                    "query_names": sorted(set(names)),
                    "query_names_truncated": shape.get("query_names_truncated", False),
                    "fragment_present": shape.get("fragment_present", False),
                }
        if (
            isinstance(supplied, bool)
            and (
                digest is None
                or (
                    isinstance(digest, str) and re.fullmatch(r"[0-9a-fA-F]{16}", digest)
                )
            )
            and (shape is None or safe_shape is not None)
        ):
            return {
                "supplied": supplied,
                "sha256_16": digest.lower() if isinstance(digest, str) else None,
                "shape": safe_shape,
            }
        return {
            "supplied": supplied if isinstance(supplied, bool) else None,
            "sha256_16": None,
            "shape": None,
            **_unverifiable_method_value(value),
        }
    if not isinstance(value, str):
        return {"supplied": True, "sha256_16": None, "shape": None}
    try:
        payload = value.encode("utf-8")
    except UnicodeEncodeError:
        return {
            "supplied": True,
            "sha256_16": None,
            "shape": None,
            **_unverifiable_method_value(value),
        }
    return {
        "supplied": True,
        "sha256_16": hashlib.sha256(payload).hexdigest()[:16],
        "shape": _project_public_url_shape(value),
    }


def _method_artifact_digest(value: Any) -> str:
    try:
        canonical = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            default=lambda _item: None,
        ).encode("utf-8")
    except (OverflowError, TypeError, ValueError, UnicodeEncodeError):
        canonical = b'{"status":"unserializable"}'
    return hashlib.sha256(canonical).hexdigest()[:16]


def _unverifiable_method_value(value: Any) -> dict[str, str]:
    if (
        isinstance(value, dict)
        and value.get("status") == "unverifiable"
        and isinstance(value.get("artifact_sha256_16"), str)
        and re.fullmatch(r"[0-9a-fA-F]{16}", value["artifact_sha256_16"])
    ):
        return {
            "status": "unverifiable",
            "artifact_sha256_16": value["artifact_sha256_16"].lower(),
        }
    return {
        "status": "unverifiable",
        "artifact_sha256_16": _method_artifact_digest(value),
    }


def _enum_method_value(value: Any, allowed: set[str]) -> Any:
    if value is None:
        return None
    if isinstance(value, str) and value in allowed:
        return value
    return _unverifiable_method_value(value)


def _boolean_method_value(value: Any) -> Any:
    if value is None or isinstance(value, bool):
        return value
    return _unverifiable_method_value(value)


def _number_method_value(
    value: Any, *, minimum: float = 0.0, maximum: float = 86_400.0
) -> Any:
    if (
        is_finite_number(value)
        and minimum <= value <= maximum
    ):
        return value
    if value is None:
        return None
    return _unverifiable_method_value(value)


def _viewport_method_value(value: Any) -> dict[str, Any] | None:
    if value is None:
        return None
    if not isinstance(value, dict):
        return _unverifiable_method_value(value)
    result: dict[str, Any] = {}
    for key in (
        "inner_width",
        "inner_height",
        "outer_width",
        "outer_height",
        "screen_width",
        "screen_height",
        "device_pixel_ratio",
    ):
        if key not in value:
            continue
        projected = _number_method_value(value.get(key), minimum=0, maximum=1_000_000)
        if projected is not None:
            result[key] = projected
    return result


def _script_path_method_value(value: Any) -> dict[str, Any]:
    """Bind an exact rehost path without retaining tenant/path values."""
    if value is None:
        return {"supplied": False, "sha256_16": None, "path_segment_lengths": []}
    if isinstance(value, dict):
        digest = value.get("sha256_16")
        lengths = value.get("path_segment_lengths")
        if (
            isinstance(value.get("supplied"), bool)
            and (
                digest is None
                or (
                    isinstance(digest, str) and re.fullmatch(r"[0-9a-fA-F]{16}", digest)
                )
            )
            and isinstance(lengths, list)
            and len(lengths) <= 32
            and all(
                isinstance(item, int)
                and not isinstance(item, bool)
                and 0 <= item <= 16_384
                for item in lengths
            )
            and all(
                key not in value or isinstance(value.get(key), bool)
                for key in (
                    "absolute_path",
                    "path_segments_truncated",
                    "query_present",
                    "fragment_present",
                )
            )
        ):
            result: dict[str, Any] = {
                "supplied": value["supplied"],
                "sha256_16": digest.lower() if isinstance(digest, str) else None,
                "path_segment_lengths": list(lengths),
            }
            for key in (
                "absolute_path",
                "path_segments_truncated",
                "query_present",
                "fragment_present",
            ):
                if isinstance(value.get(key), bool):
                    result[key] = value[key]
            return result
        return {
            "supplied": (
                value.get("supplied")
                if isinstance(value.get("supplied"), bool)
                else None
            ),
            **_unverifiable_method_value(value),
            "path_segment_lengths": [],
        }
    if not isinstance(value, str):
        return {
            "supplied": True,
            **_unverifiable_method_value(value),
            "path_segment_lengths": [],
        }
    try:
        payload = value.encode("utf-8")
    except UnicodeEncodeError:
        return {
            "supplied": True,
            "sha256_16": None,
            **_unverifiable_method_value(value),
            "path_segment_lengths": [],
        }
    try:
        parsed = urlsplit(value)
    except (UnicodeError, ValueError):
        parsed = None
    segments = (
        [segment for segment in parsed.path.split("/") if segment]
        if parsed is not None
        else []
    )
    return {
        "supplied": True,
        "sha256_16": hashlib.sha256(payload).hexdigest()[:16],
        "absolute_path": value.startswith("/"),
        "path_segment_lengths": [len(segment) for segment in segments[:32]],
        "path_segments_truncated": len(segments) > 32,
        "query_present": bool(parsed.query) if parsed is not None else False,
        "fragment_present": bool(parsed.fragment) if parsed is not None else False,
    }


def _hook_target_method_value(value: Any) -> list[Any]:
    from .argument_capture import HOOK_TARGETS

    known = {target.name for target in HOOK_TARGETS}
    values = (
        value
        if isinstance(value, (list, tuple))
        else ([] if value is None else [value])
    )
    result = []
    for item in values[:256]:
        if isinstance(item, str) and item in known:
            result.append(item)
        else:
            result.append(_unverifiable_method_value(item))
    if len(values) > 256:
        result.append(
            {
                "status": "truncated",
                "count": len(values) - 256,
                "artifact_sha256_16": _method_artifact_digest(list(values[256:])),
            }
        )
    return result


def _browser_arg_metadata(value: Any) -> list[dict[str, Any]]:
    """Bind ordered Chromium arguments without copying their values into reports.

    Observation JSON is local evidence and deliberately records the exact flags an
    arm used.  Pairwise comparisons, batch audits, and evidence packs are portable,
    however, and a Chromium flag is an unrestricted ``--name=value`` string.  A
    custom flag can therefore carry a tenant identifier or credential even though
    Browser Core rejects the well-known proxy and remote-debugging families.

    Keep the safe flag name and a digest of the entire argument.  The digest
    preserves exact method equality (including ordering and values) while the
    report cannot disclose the value.  Positional or malformed arguments receive
    only a coarse kind plus their digest.
    """
    if value is None:
        return []
    public_names = {
        "--disable-gpu",
        "--disable-features",
        "--enable-features",
        "--force-device-scale-factor",
        "--force-color-profile",
        "--lang",
        "--use-angle",
        "--window-position",
        "--window-size",
    }
    arguments = value if isinstance(value, (list, tuple)) else [value]
    result: list[dict[str, Any]] = []
    for argument in arguments[:256]:
        if isinstance(argument, dict):
            kind = argument.get("kind")
            digest = argument.get("sha256_16")
            if argument.get("status") == "unverifiable":
                marker = _unverifiable_method_value(argument)
                result.append(
                    {
                        "kind": (
                            kind
                            if kind
                            in {
                                "long-flag",
                                "short-flag",
                                "positional",
                                "malformed-flag",
                                "non-string",
                                "truncated-tail",
                            }
                            else "malformed-flag"
                        ),
                        "sha256_16": (
                            digest.lower()
                            if isinstance(digest, str)
                            and re.fullmatch(r"[0-9a-fA-F]{16}", digest)
                            else marker["artifact_sha256_16"]
                        ),
                        **marker,
                    }
                )
                continue
            if (
                kind
                in {
                    "long-flag",
                    "short-flag",
                    "positional",
                    "malformed-flag",
                    "non-string",
                    "truncated-tail",
                }
                and isinstance(digest, str)
                and re.fullmatch(r"[0-9a-fA-F]{16}", digest)
            ):
                stored: dict[str, Any] = {
                    "kind": kind,
                    "sha256_16": digest.lower(),
                }
                name = argument.get("name")
                if name in public_names or name == "<custom>":
                    stored["name"] = name
                name_digest = argument.get("name_sha256_16")
                if (
                    name == "<custom>"
                    and isinstance(name_digest, str)
                    and re.fullmatch(r"[0-9a-fA-F]{16}", name_digest)
                ):
                    stored["name_sha256_16"] = name_digest.lower()
                count = argument.get("count")
                if kind == "truncated-tail" and isinstance(count, int) and count >= 0:
                    stored["count"] = count
                if kind == "non-string":
                    stored.update(_unverifiable_method_value(argument))
                result.append(stored)
                continue
        if not isinstance(argument, str):
            marker = _unverifiable_method_value(argument)
            result.append(
                {
                    "kind": "non-string",
                    "sha256_16": marker["artifact_sha256_16"],
                    **marker,
                }
            )
            continue
        try:
            payload = argument.encode("utf-8")
        except UnicodeEncodeError:
            marker = _unverifiable_method_value(argument)
            result.append(
                {
                    "kind": "malformed-flag",
                    "sha256_16": marker["artifact_sha256_16"],
                    **marker,
                }
            )
            continue
        candidate = argument.split("=", 1)[0]
        if re.fullmatch(r"--[A-Za-z0-9][A-Za-z0-9._-]{0,79}", candidate):
            kind = "long-flag"
            name = candidate
        elif re.fullmatch(r"-[A-Za-z0-9][A-Za-z0-9._-]{0,79}", candidate):
            kind = "short-flag"
            name = candidate
        else:
            kind = "positional" if not argument.startswith("-") else "malformed-flag"
            name = None
        item = {
            "kind": kind,
            "sha256_16": hashlib.sha256(payload).hexdigest()[:16],
        }
        if name is not None:
            # A syntactically valid custom flag name can itself contain a tenant
            # label. Only names this tool documents as method controls are public.
            item["name"] = name if name in public_names else "<custom>"
            if name not in public_names:
                item["name_sha256_16"] = hashlib.sha256(
                    name.encode("utf-8")
                ).hexdigest()[:16]
        result.append(item)
    if len(arguments) > 256:
        result.append(
            {
                "kind": "truncated-tail",
                "count": len(arguments) - 256,
                "sha256_16": _method_artifact_digest(list(arguments[256:])),
            }
        )
    return result


def _sanitize_rehost_contract(value: Any) -> dict[str, Any] | None:
    """Allowlist a rehost contract before comparison or portable output."""
    if value is None:
        return None
    source = value if isinstance(value, dict) else {}
    if (
        source.get("schema") == REHOST_CONTRACT_SCHEMA
        and source.get("status") == "unverifiable"
        and isinstance(source.get("artifact_sha256_16"), str)
        and re.fullmatch(r"[0-9a-fA-F]{16}", source["artifact_sha256_16"])
    ):
        return {
            "schema": REHOST_CONTRACT_SCHEMA,
            "status": "unverifiable",
            "artifact_sha256_16": source["artifact_sha256_16"].lower(),
        }
    hash_keys = (
        "sha256",
        "page_sha256",
        "hook_catalog_sha256",
        "observer_js_sha256",
        "input_probe_catalog_sha256",
    )
    valid_hashes = all(
        isinstance(source.get(key), str)
        and re.fullmatch(r"[0-9a-fA-F]{64}", source[key])
        for key in hash_keys
    )
    sequence = source.get("observer_sequence")
    capture = source.get("resource_intent_contract")
    valid_labels = (
        sequence == OBSERVER_SEQUENCE_CONTRACT
        and isinstance(capture, str)
        and capture in RESOURCE_INTENT_CONTRACTS
    )
    if (
        source.get("schema") != REHOST_CONTRACT_SCHEMA
        or not valid_hashes
        or not valid_labels
    ):
        return {
            "schema": REHOST_CONTRACT_SCHEMA,
            "status": "unverifiable",
            "artifact_sha256_16": _method_artifact_digest(value),
        }
    return {
        "schema": REHOST_CONTRACT_SCHEMA,
        **{key: str(source[key]).lower() for key in hash_keys},
        "observer_sequence": sequence,
        "resource_intent_contract": capture,
    }


def _sanitize_source_provenance(value: Any) -> dict[str, Any]:
    """Allowlist public-source provenance for digests and portable packs."""
    source = value if isinstance(value, dict) else {}

    def url_shape(raw_key: str, shape_key: str) -> dict[str, Any] | None:
        raw_url = source.get(raw_key)
        shape = _project_public_url_shape(raw_url) if raw_url is not None else None
        if raw_url is not None and shape is None:
            return None
        existing = source.get(shape_key)
        if existing is None:
            return shape
        if not isinstance(existing, dict):
            return None
        metadata = _declared_url_metadata(
            {"supplied": True, "sha256_16": None, "shape": existing}
        )
        saved_shape = metadata.get("shape")
        if shape is not None and saved_shape != shape:
            return None
        return saved_shape

    status = source.get("status")
    if status == "verified_git_inputs_artifact_digest":
        shape = url_shape("repository_url", "repository_url_shape")
        raw_repository_url = source.get("repository_url")
        revision = source.get("revision")
        digest = source.get("sha256")
        artifact_path = _safe_repository_relative_path(
            source.get("artifact_relative_path")
        )
        recipe_path = _safe_repository_relative_path(
            source.get("build_recipe_relative_path")
        )
        recipe_digest = source.get("build_recipe_sha256")
        artifact_state = source.get("artifact_git_state")
        tracked_worktree_clean = source.get("tracked_worktree_clean")
        distinct_checkout_match = source.get("distinct_checkout_artifact_verified")
        rebuild_digest = source.get("rebuild_artifact_sha256")
        if (
            shape is None
            or shape.get("fragment_present")
            or shape.get("query_names")
            or shape.get("query_names_truncated")
            or (
                isinstance(raw_repository_url, str)
                and any(marker in raw_repository_url for marker in "?#")
            )
            or not isinstance(revision, str)
            or re.fullmatch(r"[0-9a-fA-F]{40}", revision) is None
            or not isinstance(digest, str)
            or re.fullmatch(r"[0-9a-fA-F]{64}", digest) is None
            or artifact_path is None
            or recipe_path is None
            or not isinstance(recipe_digest, str)
            or re.fullmatch(r"[0-9a-fA-F]{64}", recipe_digest) is None
            or not isinstance(artifact_state, str)
            or artifact_state not in {"tracked", "ignored-generated", "untracked"}
            or tracked_worktree_clean is not True
            or not isinstance(distinct_checkout_match, bool)
            or (not distinct_checkout_match and rebuild_digest is not None)
        ):
            return {
                "status": "unverifiable",
                "note": "the Git-input source declaration is malformed or incomplete",
            }
        result = {
            "status": status,
            "repository_url_shape": shape,
            "revision": revision.lower(),
            "sha256": digest.lower(),
            "artifact_relative_path": artifact_path,
            "artifact_git_state": artifact_state,
            "build_recipe_relative_path": recipe_path,
            "build_recipe_sha256": recipe_digest.lower(),
            "tracked_worktree_clean": tracked_worktree_clean,
            "distinct_checkout_artifact_verified": distinct_checkout_match,
            "note": (
                "the public Git inputs, exact observed artifact digest, and a "
                "byte-identical artifact from a distinct matching checkout were "
                "verified; build execution is outside this verifier"
                if distinct_checkout_match
                else "the public Git inputs and exact observed artifact digest were "
                "verified; no distinct-checkout artifact was supplied"
            ),
        }
        if distinct_checkout_match:
            if (
                not isinstance(rebuild_digest, str)
                or re.fullmatch(r"[0-9a-fA-F]{64}", rebuild_digest) is None
                or rebuild_digest.lower() != digest.lower()
            ):
                return {
                    "status": "unverifiable",
                    "note": "the independent-rebuild declaration is malformed",
                }
            result["rebuild_artifact_sha256"] = rebuild_digest.lower()
        return result
    if status != "verified_digest":
        return {
            "status": "not_supplied" if status == "not_supplied" else "unverifiable",
            "note": "no verified public source pin is available",
        }

    shape = url_shape("source_url", "source_url_shape")
    digest = source.get("sha256")
    retrieved = source.get("retrieved_at")
    stamp = None
    if isinstance(retrieved, str) and len(retrieved) <= 128:
        try:
            stamp = datetime.fromisoformat(retrieved.replace("Z", "+00:00"))
        except ValueError:
            pass
    valid_stamp = bool(
        stamp is not None and stamp.tzinfo is not None and stamp.utcoffset() is not None
    )
    valid_digest = bool(
        isinstance(digest, str) and re.fullmatch(r"[0-9a-fA-F]{64}", digest)
    )
    if (
        shape is None
        or shape.get("fragment_present")
        or not valid_stamp
        or not valid_digest
    ):
        return {
            "status": "unverifiable",
            "note": "the public source declaration is malformed or incomplete",
        }
    return {
        "status": "verified_digest",
        "source_url_shape": shape,
        "retrieved_at": stamp.isoformat().replace("+00:00", "Z"),
        "sha256": str(digest).lower(),
        "note": "the full digest matched the exact observed bytes",
    }


def _safe_repository_relative_path(value: Any) -> str | None:
    """Return a path only when it is a bounded, non-local repository path."""
    if not isinstance(value, str) or not value or len(value) > 1_024:
        return None
    normalized = value.replace("\\", "/")
    if normalized.startswith("/") or re.match(r"^[A-Za-z]:", normalized):
        return None
    parts = normalized.split("/")
    if any(
        part in {"", ".", ".."}
        or any(ord(char) < 32 or ord(char) == 127 for char in part)
        for part in parts
    ):
        return None
    return "/".join(parts)


def _safe_capture_host(value: Any) -> str | None:
    if not isinstance(value, str) or not 1 <= len(value) <= 253:
        return None
    try:
        parsed = urlsplit(f"https://{value}")
        hostname = parsed.hostname
        port = parsed.port
    except ValueError:
        return None
    if not hostname or parsed.netloc != value or parsed.path or parsed.query or parsed.fragment:
        return None
    if value.startswith("["):
        if re.fullmatch(r"\[[0-9A-Fa-f:.]+\](?::[0-9]{1,5})?", value) is None:
            return None
        try:
            canonical_host = f"[{ipaddress.IPv6Address(hostname)}]"
        except ValueError:
            return None
    else:
        if re.fullmatch(r"[A-Za-z0-9.-]+(?::[0-9]{1,5})?", value) is None:
            return None
        labels = hostname.rstrip(".").split(".")
        if any(
            re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label)
            is None
            for label in labels
        ):
            return None
        # Browser special-scheme URLs reinterpret numeric-ending hosts as IPv4.
        # The capture reader accepts only canonical four-part decimal spelling.
        if re.fullmatch(r"[0-9]+|0x[0-9a-f]*", labels[-1].lower()):
            try:
                if str(ipaddress.IPv4Address(hostname)) != hostname:
                    return None
            except ValueError:
                return None
        canonical_host = hostname.lower()
    if port is not None and port > 65535:
        return None
    if port is not None:
        canonical_host += f":{port}"
    return canonical_host if value.lower() == canonical_host else None


def _sanitize_capture_provenance(value: Any) -> dict[str, Any]:
    """Keep capture-origin evidence without capture directory names or paths."""
    source = value if isinstance(value, dict) else {}
    status = source.get("status")
    if not isinstance(status, str) or status not in {
        "not_checked",
        "VERIFIED",
        "UNVERIFIED",
        "error",
    }:
        status = "unknown"
    boolean_fields_valid = all(
        key not in source or isinstance(source.get(key), bool)
        for key in (
            "directory_disagrees_with_manifest",
            "asserted_label_is_unverified",
        )
    )
    if not boolean_fields_valid:
        status = "unknown"
    hosts = source.get("recorded_hosts")
    raw_hosts = hosts if isinstance(hosts, list) else []
    safe_hosts = sorted(
        {
            safe_host
            for host in raw_hosts[:64]
            if (safe_host := _safe_capture_host(host)) is not None
        }
    )
    asserted_label = source.get("asserted_label")
    has_asserted_label = isinstance(asserted_label, str) and bool(
        re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", asserted_label)
    )
    if status == "VERIFIED" and (
        not safe_hosts or len(safe_hosts) != len(raw_hosts)
    ):
        # A filtered, duplicate, or truncated host list is incomplete evidence.
        status = "unknown"
    if has_asserted_label and source.get("asserted_label_is_unverified") is False:
        # A caller-provided label cannot become verified by a matching capture.
        status = "unknown"
    if status != "VERIFIED":
        safe_hosts = []

    def count_list(name: str) -> int | None:
        values = source.get(name)
        return min(len(values), 1_000_000) if isinstance(values, list) else None

    directory_disagrees = source.get("directory_disagrees_with_manifest", False)
    asserted_unverified = source.get(
        "asserted_label_is_unverified", has_asserted_label or status != "VERIFIED"
    )
    if has_asserted_label:
        asserted_unverified = True
    result: dict[str, Any] = {
        "status": status,
        "recorded_hosts": safe_hosts,
        "directory_disagrees_with_manifest": (
            directory_disagrees
            if status == "VERIFIED" and isinstance(directory_disagrees, bool)
            else False
        ),
        "asserted_label_is_unverified": (
            asserted_unverified if isinstance(asserted_unverified, bool) else True
        ),
    }
    if has_asserted_label:
        result["asserted_label"] = asserted_label
    for source_key, output_key in (
        ("captures_with_manifest", "captures_with_manifest_count"),
        ("captures_without_manifest", "captures_without_manifest_count"),
    ):
        if (count := count_list(source_key)) is not None:
            result[output_key] = count
    result["note"] = {
        "not_checked": "no capture tree was consulted",
        "VERIFIED": "a capture manifest records the observed bytes",
        "UNVERIFIED": "the searched capture manifests did not record the bytes",
        "error": "capture provenance lookup failed",
        "unknown": "capture provenance is unavailable",
    }[status]
    return result


def _sanitize_await_report(value: Any) -> dict[str, Any] | None:
    """Allowlist bounded readiness timing evidence for portable artifacts."""
    if not isinstance(value, dict):
        return None

    def number(
        name: str, maximum: float, *, integer: bool = False
    ) -> float | int | None:
        item = value.get(name)
        if (
            not is_finite_number(item)
            or (integer and not isinstance(item, int))
            or item < 0
        ):
            return None
        return min(item, maximum)

    ended_on = value.get("ended_on")
    signal_kind = value.get("signal_kind")
    result: dict[str, Any] = {
        "ended_on": ended_on
        if isinstance(ended_on, str)
        and ended_on in {"cap", "no_signal", "ready", "expression_true"}
        else "unknown",
        "signal_kind": signal_kind
        if isinstance(signal_kind, str)
        and signal_kind in {"builtin", "operator_expression"}
        else "unknown",
        "page_ever_answered": (
            value.get("page_ever_answered")
            if isinstance(value.get("page_ever_answered"), bool)
            else None
        ),
    }
    for name, maximum, integer in (
        ("waited_seconds", 86_400.0, False),
        ("polls", 1_000_000, True),
        ("unresponsive_polls", 1_000_000, True),
        ("failed_polls", 1_000_000, True),
        ("poll_timeout_seconds", 86_400.0, False),
    ):
        if (safe := number(name, maximum, integer=integer)) is not None:
            result[name] = safe
    counts_incoherent = any(
        name in value
        and (name not in result or result[name] != value[name])
        for name in ("polls", "unresponsive_polls", "failed_polls")
    )
    timing_incoherent = "waited_seconds" in value and (
        "waited_seconds" not in result
        or result["waited_seconds"] != value["waited_seconds"]
    )
    slowest = value.get("slowest_poll")
    if "slowest_poll" in value and (
        slowest is not None or value.get("polls", 0) != 0
    ):
        if not isinstance(slowest, dict):
            timing_incoherent = True
        else:
            issued_at = slowest.get("issued_at_seconds")
            duration = slowest.get("duration_seconds")
            waited = result.get("waited_seconds")
            if (
                not is_finite_number(issued_at)
                or not is_finite_number(duration)
                or not 0 <= issued_at <= 86_400.0
                or not 0 <= duration <= 86_400.0
                or (
                    is_finite_number(waited)
                    and issued_at + duration > waited + 0.051
                )
            ):
                # The producer rounds issue/duration to milliseconds and the
                # total wait to tenths; allow that rounding gap, not a sample
                # that extends beyond the reported wait.
                timing_incoherent = True
    if isinstance(result.get("unresponsive_polls"), int) and (
        not isinstance(result.get("polls"), int)
        or result["unresponsive_polls"] > result["polls"]
    ):
        result.pop("unresponsive_polls")
        counts_incoherent = True
    if isinstance(result.get("failed_polls"), int) and (
        not isinstance(result.get("polls"), int)
        or result["failed_polls"] > result["polls"]
    ):
        result.pop("failed_polls")
        counts_incoherent = True
    if (
        isinstance(result.get("polls"), int)
        and isinstance(result.get("unresponsive_polls"), int)
        and isinstance(result.get("failed_polls"), int)
        and result["unresponsive_polls"] + result["failed_polls"] > result["polls"]
    ):
        result.pop("unresponsive_polls")
        result.pop("failed_polls")
        counts_incoherent = True
    if (
        result["page_ever_answered"] is True
        and isinstance(result.get("polls"), int)
        and (
            result["polls"] == 0
            or result.get("unresponsive_polls") == result["polls"]
        )
    ):
        result["page_ever_answered"] = None
    if (
        isinstance(result.get("polls"), int)
        and isinstance(result.get("unresponsive_polls"), int)
        and isinstance(result.get("failed_polls"), int)
    ):
        failed_population = result["unresponsive_polls"] + result["failed_polls"]
        if result["page_ever_answered"] is False and failed_population != result["polls"]:
            result["page_ever_answered"] = None
    terminal = result["ended_on"]
    terminal_requires_answer = terminal in {"ready", "expression_true", "no_signal"}
    polls = result.get("polls")
    no_successful_poll = isinstance(polls, int) and (
        any(
            result.get(field) == polls
            for field in ("unresponsive_polls", "failed_polls")
        )
        or (
            isinstance(result.get("unresponsive_polls"), int)
            and isinstance(result.get("failed_polls"), int)
            and result["unresponsive_polls"] + result["failed_polls"] == polls
        )
    )
    signal_mismatch = (terminal == "ready" and result["signal_kind"] != "builtin") or (
        terminal == "expression_true"
        and result["signal_kind"] != "operator_expression"
    )
    terminal_sample_incoherent = bool(
        terminal_requires_answer
        and isinstance(slowest, dict)
        and (
            (polls == 1 and slowest.get("outcome") != terminal)
            or (
                slowest.get("outcome") in {"ready", "expression_true", "no_signal"}
                and slowest.get("outcome") != terminal
            )
            or (
                slowest.get("outcome") == "unresponsive"
                and not (
                    isinstance(result.get("unresponsive_polls"), int)
                    and result["unresponsive_polls"] > 0
                )
            )
            or (
                slowest.get("outcome") == "failed"
                and not (
                    isinstance(result.get("failed_polls"), int)
                    and result["failed_polls"] > 0
                )
            )
        )
    )
    if (
        terminal_requires_answer
        and (
            counts_incoherent
            or timing_incoherent
            or terminal_sample_incoherent
            or no_successful_poll
            or result["page_ever_answered"] is not True
            or not isinstance(result.get("polls"), int)
            or result["polls"] < 1
        )
    ) or signal_mismatch:
        result["ended_on"] = "unknown"
    if (
        isinstance(slowest, dict)
        and isinstance(result.get("polls"), int)
        and result["polls"] > 0
    ):
        outcome = slowest.get("outcome")
        safe_slowest: dict[str, Any] = {
            "outcome": outcome
            if isinstance(outcome, str)
            and outcome
            in {
                "ready",
                "expression_true",
                "no_signal",
                "not_ready",
                "unresponsive",
                "failed",
            }
            else "unknown"
        }
        for name in ("issued_at_seconds", "duration_seconds"):
            item = slowest.get(name)
            if (
                is_finite_number(item)
                and item >= 0
            ):
                safe_slowest[name] = min(item, 86_400.0)
        slowest_outcome = safe_slowest["outcome"]
        if (
            slowest_outcome == "unresponsive"
            and not (
                isinstance(result.get("unresponsive_polls"), int)
                and result["unresponsive_polls"] > 0
            )
        ) or (
            slowest_outcome == "failed"
            and not (
                isinstance(result.get("failed_polls"), int)
                and result["failed_polls"] > 0
            )
        ):
            safe_slowest["outcome"] = "unknown"
        if safe_slowest["outcome"] in {"ready", "expression_true", "no_signal"}:
            outcome = safe_slowest["outcome"]
            if result["page_ever_answered"] is not True or (
                outcome == "ready" and result["signal_kind"] != "builtin"
            ) or (
                outcome == "expression_true"
                and result["signal_kind"] != "operator_expression"
            ):
                safe_slowest["outcome"] = "unknown"
        if (counts_incoherent or timing_incoherent or no_successful_poll) and safe_slowest[
            "outcome"
        ] in {"ready", "expression_true", "no_signal", "not_ready"}:
            safe_slowest["outcome"] = "unknown"
        result["slowest_poll"] = safe_slowest
    return result


def _reconciled_await_method(
    arm: dict[str, Any], control: dict[str, Any]
) -> tuple[bool, bool, dict[str, Any] | None, dict[str, Any] | None]:
    """Validate configured readiness waiting and require the arm's signal."""
    methods: list[tuple[float | None, dict[str, Any] | None, bool, bool]] = []
    for document in (arm, control):
        raw_seconds = document.get("await_ready_seconds", 0.0)
        seconds = (
            float(raw_seconds)
            if is_finite_number(raw_seconds)
            and 0 <= raw_seconds <= MAX_OBSERVATION_SECONDS
            else None
        )
        report = _sanitize_await_report(document.get("await_report"))
        expression_supplied = (
            _ready_expression_metadata(document).get("supplied") is True
        )
        coherent = seconds is not None
        satisfied = False
        if coherent and seconds == 0:
            coherent = document.get("await_report") is None and not expression_supplied
            satisfied = coherent
        elif coherent:
            expected_signal = (
                "operator_expression" if expression_supplied else "builtin"
            )
            coherent = bool(
                report is not None
                and report.get("signal_kind") == expected_signal
                and isinstance(report.get("waited_seconds"), (int, float))
            )
            expected_end = "expression_true" if expression_supplied else "ready"
            satisfied = bool(
                coherent
                and report.get("ended_on") == expected_end
                and report["waited_seconds"] <= seconds
            )
        methods.append((seconds, report, coherent, satisfied))
    arm_method, control_method = methods
    comparable = bool(
        arm_method[2] and control_method[2] and arm_method[0] == control_method[0]
    )
    return comparable, arm_method[3], arm_method[1], control_method[1]


def _sanitize_resource_intent_report(report: Any) -> dict[str, Any]:
    """Allowlist a resource-intent report at every artifact boundary.

    Resource attributes are page controlled.  Even though the CDP capture path
    already projects them, callers may load an edited or legacy observation and
    pass it to subtraction, digest, or evidence-pack code.  Treat that artifact
    as hostile and reconstruct the small public contract here instead of copying
    its dictionaries.
    """

    def bounded_int(value: Any) -> int | None:
        if (
            isinstance(value, bool)
            or not isinstance(value, int)
            or not 0 <= value <= 1_000_000
        ):
            return None
        return value

    def safe_origin(value: Any) -> str | None:
        if value == "loopback-rehost":
            return value
        if (
            not isinstance(value, str)
            or len(value) > 300
            or any(ord(char) < 33 or ord(char) == 127 for char in value)
        ):
            return None
        try:
            parsed = urlsplit(value)
            port = parsed.port
        except (UnicodeError, ValueError):
            return None
        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path
            or parsed.query
            or parsed.fragment
        ):
            return None
        canonical = project_resource_intent_origin(
            parsed.scheme, parsed.hostname, port
        )
        return value if value == canonical else None

    def safe_row(value: Any) -> dict[str, Any] | None:
        if not isinstance(value, dict):
            return None
        origin = safe_origin(value.get("origin"))
        lengths = value.get("path_segment_lengths")
        query_names = value.get("query_names")
        if (
            origin is None
            or not isinstance(lengths, list)
            or not isinstance(query_names, list)
            or len(lengths) > 32
            or len(query_names) > 64
        ):
            return None
        safe_lengths = [bounded_int(item) for item in lengths[:32]]
        if any(item is None or item == 0 for item in safe_lengths):
            return None
        if any(
            field in value and not isinstance(value.get(field), bool)
            for field in (
                "same_origin_as_rehost",
                "path_segments_truncated",
                "query_names_truncated",
            )
        ):
            return None
        same_origin = value.get("same_origin_as_rehost", False)
        if (origin == "loopback-rehost") != same_origin:
            return None
        safe_names = [
            item
            for item in query_names[:64]
            if isinstance(item, str)
            and 0 < len(item) <= 80
            and not any(ord(char) < 32 or ord(char) == 127 for char in item)
        ]
        if len(safe_names) != len(query_names) or safe_names != sorted(set(safe_names)):
            return None
        tag = project_resource_intent_tag(value.get("tag"))
        attribute = value.get("attribute")
        if (
            tag is None
            or not isinstance(attribute, str)
            or attribute.lower() not in RESOURCE_INTENT_ATTRIBUTES
        ):
            return None
        result = {
            "tag": tag,
            "attribute": attribute.lower(),
            "origin": origin,
            "same_origin_as_rehost": value.get("same_origin_as_rehost", False),
            "path_segment_lengths": safe_lengths,
            "path_segments_truncated": value.get("path_segments_truncated", False),
            "query_names": safe_names,
            "query_names_truncated": value.get("query_names_truncated", False),
        }
        if "count" in value:
            count = bounded_int(value.get("count"))
            if count is None or count < 1:
                return None
            result["count"] = count
        return result

    def safe_multiplicity(value: Any) -> dict[str, Any] | None:
        row = safe_row(value)
        if row is None:
            return None
        row.pop("count", None)
        arm_occurrences = bounded_int(
            value.get("arm_occurrences") if isinstance(value, dict) else None
        )
        control_occurrences = bounded_int(
            value.get("control_occurrences") if isinstance(value, dict) else None
        )
        if (
            arm_occurrences is None
            or control_occurrences is None
            or arm_occurrences < 1
            or control_occurrences < 1
        ):
            return None
        row["arm_occurrences"] = arm_occurrences
        row["control_occurrences"] = control_occurrences
        return row

    source = report if isinstance(report, dict) else {}
    status = source.get("status")
    result: dict[str, Any] = {
        "status": status
        if isinstance(status, str) and status in {"ok", "failed", "off", "unverifiable"}
        else "unknown",
    }
    if result["status"] == "ok" and not any(
        key in source for key in ("intents", "only_in_arm", "only_in_control")
    ):
        result["status"] = "unverifiable"
    for key in ("arm_status", "control_status"):
        value = source.get(key)
        if isinstance(value, str) and value in {
            "ok",
            "failed",
            "off",
            "truncated",
            "missing",
            "unknown",
        }:
            result[key] = value
    for key in (
        "arm_count",
        "control_count",
        "shared_count",
        "arm_attribute_count",
        "control_attribute_count",
        "candidate_attributes",
        "distinct_intents",
    ):
        value = bounded_int(source.get(key))
        if value is not None:
            result[key] = value
        elif key in source:
            result["status"] = "unverifiable"
    for key in ("truncated", "clean_subtraction"):
        value = source.get(key)
        if isinstance(value, bool):
            result[key] = value
        elif key in source:
            result["status"] = "unverifiable"
    for key in ("intents", "only_in_arm", "only_in_control"):
        if key not in source:
            continue
        values = source.get(key)
        if not isinstance(values, list):
            result["status"] = "unverifiable"
            continue
        projected = [
            safe for item in values[:128] if (safe := safe_row(item)) is not None
        ]
        result[key] = projected
        if len(projected) != min(len(values), 128):
            result["status"] = "unverifiable"
        if len(values) > 128:
            # Do not trust a caller-controlled `truncated: false` when this
            # artifact boundary itself had to discard rows.
            result["truncated"] = True
            if key != "intents":
                result["status"] = "unverifiable"
    retained_intents = result.get("intents")
    distinct_intents = result.get("distinct_intents")
    if isinstance(retained_intents, list):
        identities = {
            json.dumps(
                {key: item for key, item in row.items() if key != "count"},
                sort_keys=True,
                separators=(",", ":"),
            )
            for row in retained_intents
        }
        if len(identities) != len(retained_intents):
            result["status"] = "unverifiable"
        if isinstance(distinct_intents, int) and distinct_intents < len(retained_intents):
            result["status"] = "unverifiable"
        candidate_attributes = result.get("candidate_attributes")
        if isinstance(candidate_attributes, int) and all(
            "count" in row for row in retained_intents
        ):
            retained_attributes = sum(row["count"] for row in retained_intents)
            if candidate_attributes < retained_attributes or (
                result.get("truncated") is False
                and candidate_attributes != retained_attributes
            ):
                result["status"] = "unverifiable"
    if (
        isinstance(retained_intents, list)
        and isinstance(distinct_intents, int)
        and distinct_intents > len(retained_intents)
    ):
        # The native observer uses this relation when its 128-shape cap fires.
        # Derive it too, so edited or legacy artifacts cannot clear the receipt.
        result["truncated"] = True
    if "multiplicity_deltas" in source:
        values = source["multiplicity_deltas"]
        if not isinstance(values, list):
            result["status"] = "unverifiable"
        else:
            projected = [
                safe
                for item in values[:128]
                if (safe := safe_multiplicity(item)) is not None
            ]
            result["multiplicity_deltas"] = projected
            if len(projected) != len(values):
                result["status"] = "unverifiable"
    if source.get("diagnostic") is not None:
        result["diagnostic"] = _redact_diagnostic(source["diagnostic"])
    result["non_claim"] = (
        "DOM attributes present at capture time; not proof that a request was sent, "
        "reached DNS, or received a response"
        if result["status"] == "ok"
        else "resource intent could not be fully observed"
    )
    return result


def _request_path_shape(value: Any) -> dict[str, Any] | None:
    """Project a loopback request target without retaining path/query values."""
    if not isinstance(value, str) or len(value) > 16_384:
        return None
    try:
        parsed = urlsplit(value)
    except (UnicodeError, ValueError):
        return None
    segments = [segment for segment in parsed.path.split("/") if segment]
    query_names: list[str] = []
    omitted_query_name = False
    for item in parsed.query.split("&") if parsed.query else ():
        name = item.split("=", 1)[0]
        if not name:
            continue
        if len(name) <= 80 and _is_strict_utf8_text(name) and not any(
            ord(char) < 32 or ord(char) == 127 for char in name
        ):
            query_names.append(name)
        else:
            omitted_query_name = True
    return {
        "path_segment_lengths": [len(segment) for segment in segments[:32]],
        "path_segments_truncated": len(segments) > 32,
        "query_names": sorted(set(query_names))[:64],
        "query_names_truncated": omitted_query_name or len(set(query_names)) > 64,
    }


def _sanitize_request_activity_report(report: Any) -> dict[str, Any]:
    """Reconstruct the safe loopback request-activity contract."""

    def bounded_int(value: Any) -> int | None:
        if (
            isinstance(value, bool)
            or not isinstance(value, int)
            or not 0 <= value <= 1_000_000_000
        ):
            return None
        return value

    def safe_row(value: Any, *, is_snapshot: bool) -> dict[str, Any] | None:
        if not isinstance(value, dict):
            return None
        method = value.get("method")
        served = value.get("served")
        lengths = value.get("path_segment_lengths")
        query_names = value.get("query_names")
        if (
            not isinstance(method, str)
            or method not in REQUEST_ACTIVITY_METHODS
            or not isinstance(served, str)
            or served not in REQUEST_ACTIVITY_SERVED_CLASSES
            or not isinstance(lengths, list)
            or not isinstance(query_names, list)
            or len(lengths) > 32
            or len(query_names) > 64
        ):
            return None
        if any(
            field in value and not isinstance(value.get(field), bool)
            for field in ("path_segments_truncated", "query_names_truncated")
        ):
            return None
        safe_lengths = [bounded_int(item) for item in lengths[:32]]
        if any(item is None or item == 0 for item in safe_lengths):
            return None
        safe_names = [
            item
            for item in query_names[:64]
            if _is_strict_utf8_text(item)
            and 0 < len(item) <= 80
            and not any(ord(char) < 32 or ord(char) == 127 for char in item)
        ]
        if len(safe_names) != len(query_names) or safe_names != sorted(set(safe_names)):
            return None
        result: dict[str, Any] = {
            "method": method,
            "served": served,
            "path_segment_lengths": safe_lengths,
            "path_segments_truncated": value.get("path_segments_truncated", False),
            "query_names": safe_names,
            "query_names_truncated": value.get("query_names_truncated", False),
        }
        for key in (
            "count",
            "body_bytes_total",
            "body_bytes_min",
            "body_bytes_max",
            "arm_count",
            "control_count",
        ):
            safe = bounded_int(value.get(key))
            if safe is not None:
                result[key] = safe
            elif key in value:
                return None
        if is_snapshot and result.get("count") == 0:
            return None
        body_fields = {"body_bytes_total", "body_bytes_min", "body_bytes_max"}
        if is_snapshot and body_fields & result.keys():
            if not body_fields <= result.keys():
                return None
            population = result.get("count")
            minimum = result["body_bytes_min"]
            maximum = result["body_bytes_max"]
            total = result["body_bytes_total"]
            if (
                not isinstance(population, int)
                or population < 1
                or minimum > maximum
                or not minimum * population <= total <= maximum * population
            ):
                return None
        digest_counts = value.get("body_sha256_16_counts")
        if "body_sha256_16_counts" in value:
            if (
                method != "POST"
                or served != "post-ack"
                or not isinstance(digest_counts, dict)
                or len(digest_counts) > 128
            ):
                return None
            safe_digest_counts: dict[str, int] = {}
            for digest, occurrences in digest_counts.items():
                if (
                    not isinstance(digest, str)
                    or re.fullmatch(r"[0-9a-fA-F]{16}", digest) is None
                    or isinstance(occurrences, bool)
                    or not isinstance(occurrences, int)
                    or occurrences < 1
                    or occurrences > 1_000_000_000
                ):
                    return None
                normalized = digest.lower()
                combined = safe_digest_counts.get(normalized, 0) + occurrences
                if combined > 1_000_000_000:
                    return None
                safe_digest_counts[normalized] = combined
            count = result.get("count")
            if isinstance(count, int) and sum(safe_digest_counts.values()) > count:
                return None
            result["body_sha256_16_counts"] = dict(sorted(safe_digest_counts.items()))
        return result

    source = report if isinstance(report, dict) else {}
    status = source.get("status")
    result: dict[str, Any] = {
        "status": status
        if isinstance(status, str) and status in {"ok", "unverifiable"}
        else "unknown",
        "scope": "loopback_rehost_only",
    }
    if result["status"] == "ok" and not any(
        key in source for key in ("rows", "only_in_arm", "only_in_control")
    ):
        result["status"] = "unverifiable"
    for key in (
        "candidate_requests",
        "distinct_shapes",
        "arm_requests",
        "control_requests",
        "shared_shapes",
        "retained_requests",
        "dropped_requests",
        "truncated_paths",
    ):
        safe = bounded_int(source.get(key))
        if safe is not None:
            result[key] = safe
        elif key in source:
            result["status"] = "unverifiable"
    for key in ("clean_subtraction", "truncated"):
        if isinstance(source.get(key), bool):
            result[key] = source[key]
        elif key in source:
            result["status"] = "unverifiable"
    for key in ("rows", "only_in_arm", "only_in_control"):
        values = source.get(key)
        if key not in source:
            continue
        if not isinstance(values, list):
            result["status"] = "unverifiable"
            result["truncated"] = True
            result["dropped_requests"] = min(
                result.get("dropped_requests", 0) + 1,
                1_000_000_000,
            )
            continue
        projected = [
            safe
            for item in values[:128]
            if (
                safe := safe_row(item, is_snapshot=key == "rows")
            )
            is not None
        ]
        dropped = len(values) - len(projected)
        result[key] = projected
        if dropped:
            result["status"] = "unverifiable"
            result["truncated"] = True
            result["dropped_requests"] = min(
                result.get("dropped_requests", 0) + dropped,
                1_000_000_000,
            )
    retained_rows = result.get("rows")
    if isinstance(retained_rows, list):
        identity_fields = (
            "method",
            "served",
            "path_segment_lengths",
            "path_segments_truncated",
            "query_names",
            "query_names_truncated",
        )
        identities = {
            json.dumps(
                {field: row[field] for field in identity_fields},
                sort_keys=True,
                separators=(",", ":"),
            )
            for row in retained_rows
        }
        if len(identities) != len(retained_rows):
            result["status"] = "unverifiable"
        distinct_shapes = result.get("distinct_shapes")
        if isinstance(distinct_shapes, int):
            if distinct_shapes < len(retained_rows):
                result["status"] = "unverifiable"
            elif distinct_shapes > len(retained_rows):
                result["truncated"] = True
        candidate_requests = result.get("candidate_requests")
        if isinstance(candidate_requests, int) and all(
            "count" in row for row in retained_rows
        ):
            retained_requests = sum(row["count"] for row in retained_rows)
            if candidate_requests < retained_requests or (
                result.get("truncated") is False
                and candidate_requests != retained_requests
            ):
                result["status"] = "unverifiable"
    result["non_claim"] = (
        "loopback requests that reached the rehost; external requests blocked before "
        "connection are invisible, and post-ack is a synthetic lab response"
    )
    return result


def _sanitize_request_activity_baseline(value: Any) -> dict[str, Any] | None:
    """Allowlist the repeated-arm request noise floor for portable artifacts."""
    if not isinstance(value, dict):
        return None

    def bounded_int(item: Any) -> int | None:
        if (
            isinstance(item, bool)
            or not isinstance(item, int)
            or not 0 <= item <= 1_000_000_000
        ):
            return None
        return item

    status = value.get("status")
    result: dict[str, Any] = {
        "status": status
        if isinstance(status, str) and status in {"ok", "unverifiable"}
        else "unverifiable",
    }
    for key in ("arms", "stable_shapes", "union_shapes", "variable_shapes"):
        if (item := bounded_int(value.get(key))) is not None:
            result[key] = item
    if result["status"] == "ok":
        invalid = any(
            key not in result
            for key in ("arms", "stable_shapes", "union_shapes", "variable_shapes")
        )
        arms = result.get("arms")
        stable_shapes = result.get("stable_shapes")
        union_shapes = result.get("union_shapes")
        variable_shapes = result.get("variable_shapes")
        invalid = invalid or not (
            isinstance(arms, int)
            and 2 <= arms <= 1_414
            and isinstance(stable_shapes, int)
            and isinstance(union_shapes, int)
            and isinstance(variable_shapes, int)
            and stable_shapes <= union_shapes
            and variable_shapes <= union_shapes
        )
        source_rows = value.get("rows")
        invalid = invalid or not isinstance(source_rows, list)
        rows = source_rows if isinstance(source_rows, list) else []
        invalid = invalid or len(rows) > 128
        safe_rows = []
        for row in rows[:128]:
            if not isinstance(row, dict):
                invalid = True
                continue
            projected = (
                _sanitize_request_activity_report(
                    {"status": "ok", "rows": [row.get("shape")]}
                ).get("rows")
                or []
            )
            if not projected:
                invalid = True
                continue
            varies = row.get("varies")
            if "varies" in row and not isinstance(varies, bool):
                invalid = True
                continue
            safe: dict[str, Any] = {
                "shape": {
                    key: projected[0].get(key)
                    for key in (
                        "method",
                        "served",
                        "path_segment_lengths",
                        "path_segments_truncated",
                        "query_names",
                        "query_names_truncated",
                    )
                },
            }
            try:
                _verified_request_decision_shape(safe["shape"])
            except ContractError:
                invalid = True
                continue
            if isinstance(varies, bool):
                safe["varies"] = varies
            digest_varies = row.get("body_digest_multiset_varies")
            if "body_digest_multiset_varies" in row:
                if not isinstance(digest_varies, bool):
                    invalid = True
                    continue
                safe["body_digest_multiset_varies"] = digest_varies
            digest_comparable = row.get("body_digest_multiset_comparable")
            if "body_digest_multiset_comparable" in row:
                if not isinstance(digest_comparable, bool):
                    invalid = True
                    continue
                safe["body_digest_multiset_comparable"] = digest_comparable
            digest_identity = row.get("body_digest_multiset_sha256")
            if "body_digest_multiset_sha256" in row:
                if not isinstance(digest_identity, str) or re.fullmatch(
                    r"[0-9a-f]{64}", digest_identity
                ) is None:
                    invalid = True
                    continue
                safe["body_digest_multiset_sha256"] = digest_identity
            digest_custody = row.get("body_digest_multiset_custody")
            if "body_digest_multiset_custody" in row:
                if digest_custody != "self_receipt_only":
                    invalid = True
                    continue
                safe["body_digest_multiset_custody"] = digest_custody
            for key in (
                "arms_present",
                "count_min",
                "count_max",
                "body_bytes_total_min",
                "body_bytes_total_max",
                "body_bytes_min_min",
                "body_bytes_min_max",
                "body_bytes_max_min",
                "body_bytes_max_max",
                "body_digest_coverage_min",
                "body_digest_coverage_max",
            ):
                if (item := bounded_int(row.get(key))) is not None:
                    safe[key] = item
            required_metric_fields = {
                "arms_present",
                "count_min",
                "count_max",
                "body_bytes_total_min",
                "body_bytes_total_max",
                "body_bytes_min_min",
                "body_bytes_min_max",
                "body_bytes_max_min",
                "body_bytes_max_max",
                "body_digest_coverage_min",
                "body_digest_coverage_max",
            }
            if not required_metric_fields.issubset(safe):
                invalid = True
                continue
            metric_pairs = (
                ("count_min", "count_max"),
                ("body_bytes_total_min", "body_bytes_total_max"),
                ("body_bytes_min_min", "body_bytes_min_max"),
                ("body_bytes_max_min", "body_bytes_max_max"),
                ("body_digest_coverage_min", "body_digest_coverage_max"),
            )
            if (
                not isinstance(arms, int)
                or not 1 <= safe["arms_present"] <= arms
                or safe["count_min"] < 1
                or any(safe[low] > safe[high] for low, high in metric_pairs)
                or safe["body_bytes_min_min"] > safe["body_bytes_max_min"]
                or safe["body_bytes_min_max"] > safe["body_bytes_max_max"]
            ):
                invalid = True
                continue
            coverage_min = safe.get("body_digest_coverage_min")
            coverage_max = safe.get("body_digest_coverage_max")
            if "body_digest_multiset_varies" in safe and (
                safe.get("body_digest_multiset_comparable") is not True
            ):
                invalid = True
                continue
            if safe.get("body_digest_multiset_comparable") is True:
                count_min = safe.get("count_min")
                count_max = safe.get("count_max")
                if (
                    isinstance(count_min, int)
                    and isinstance(coverage_min, int)
                    and count_min != coverage_min
                ) or (
                    isinstance(count_max, int)
                    and isinstance(coverage_max, int)
                    and count_max != coverage_max
                ):
                    invalid = True
                    continue
            if safe.get("body_digest_multiset_comparable") is True:
                if "body_digest_multiset_varies" not in safe:
                    invalid = True
                    continue
            elif "body_digest_multiset_varies" in safe:
                invalid = True
                continue
            if "body_digest_multiset_sha256" in safe and not (
                safe.get("body_digest_multiset_comparable") is True
                and safe.get("body_digest_multiset_varies") is False
                and safe.get("body_digest_multiset_custody")
                == "self_receipt_only"
            ):
                invalid = True
                continue
            if "body_digest_multiset_custody" in safe and (
                "body_digest_multiset_sha256" not in safe
            ):
                invalid = True
                continue
            computed_varies = bool(
                safe["arms_present"] != arms
                or any(safe[low] != safe[high] for low, high in metric_pairs)
                or safe.get("body_digest_multiset_varies") is True
            )
            if safe.get("varies") is not computed_varies:
                invalid = True
                continue
            safe_rows.append(safe)
        rows_truncated = value.get("rows_truncated")
        if "rows_truncated" in value and not isinstance(rows_truncated, bool):
            invalid = True
        if not isinstance(rows_truncated, bool):
            invalid = True
        if (
            isinstance(union_shapes, int)
            and isinstance(rows_truncated, bool)
            and (
                rows_truncated != (union_shapes > 128)
                or len(safe_rows) != min(union_shapes, 128)
            )
        ):
            invalid = True
        shape_keys = [
            json.dumps(row["shape"], sort_keys=True, separators=(",", ":"))
            for row in safe_rows
        ]
        if len(set(shape_keys)) != len(shape_keys) or shape_keys != sorted(shape_keys):
            invalid = True
        if isinstance(stable_shapes, int) and isinstance(variable_shapes, int):
            visible_stable = sum(
                row.get("arms_present") == arms for row in safe_rows
            )
            visible_variable = sum(row.get("varies") is True for row in safe_rows)
            if rows_truncated is False and (
                visible_stable != stable_shapes
                or visible_variable != variable_shapes
            ):
                invalid = True
            if rows_truncated is True and (
                visible_stable > stable_shapes
                or visible_variable > variable_shapes
            ):
                invalid = True
        if invalid:
            result["status"] = "unverifiable"
        else:
            result["rows"] = safe_rows
            if isinstance(rows_truncated, bool):
                result["rows_truncated"] = rows_truncated
    result["non_claim"] = (
        "loopback request count, byte-length, and complete-body digest variation "
        "only; no body bytes, field semantics, external requests, product response, "
        "or vendor validity; short unkeyed digests are not a confidentiality claim, "
        "and a stable multiset identity has local self-receipt custody only"
    )
    declared_receipt = value.get("receipt_sha256")
    if result.get("status") == "ok" and declared_receipt is not None:
        expected_receipt = hashlib.sha256(
            json.dumps(result, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        if (
            not isinstance(declared_receipt, str)
            or re.fullmatch(r"[0-9a-f]{64}", declared_receipt) is None
            or not hmac.compare_digest(declared_receipt, expected_receipt)
        ):
            return {
                "status": "unverifiable",
                "non_claim": result["non_claim"],
            }
        result["receipt_sha256"] = declared_receipt
    return result


def project_server_request_activity(server_requests: Any) -> dict[str, Any]:
    """Aggregate collector-relevant loopback requests into redacted shapes."""

    def valid_logged_query_names(entry: dict[str, Any]) -> bool:
        if "query_names" not in entry:
            return True
        names = entry["query_names"]
        return bool(
            isinstance(names, list)
            and len(names) <= 64
            and all(
                _is_strict_utf8_text(name)
                and 0 < len(name) <= 80
                and not any(ord(char) < 32 or ord(char) == 127 for char in name)
                for name in names
            )
            and names == sorted(set(names))
        )

    entries = server_requests if isinstance(server_requests, list) else []
    buckets: dict[str, dict[str, Any]] = {}
    candidate_requests = 0
    malformed_entries = 0 if isinstance(server_requests, list) else 1
    for entry in entries:
        if not isinstance(entry, dict):
            malformed_entries += 1
            continue
        served_value = entry.get("served")
        method = entry.get("method")
        shape = _request_path_shape(entry.get("path"))
        body_value = entry.get("request_body_bytes")
        body_digest = entry.get("request_body_sha256_16")
        proxy_denied = served_value == "proxy-denied"
        if (
            not isinstance(served_value, str)
            or served_value not in REHOST_REQUEST_SERVED_CLASSES
            or not isinstance(method, str)
            or method
            not in (PROXY_DENIED_METHODS if proxy_denied else REQUEST_ACTIVITY_METHODS)
            or shape is None
            or (
                "request_body_bytes" in entry
                and (
                    isinstance(body_value, bool)
                    or not isinstance(body_value, int)
                    or not 0 <= body_value <= 1_000_000_000
                )
            )
            or (
                "path_truncated" in entry
                and not isinstance(entry.get("path_truncated"), bool)
            )
            or not valid_logged_query_names(entry)
            or (
                "query_names_truncated" in entry
                and not isinstance(entry.get("query_names_truncated"), bool)
            )
            or (
                "request_body_sha256_16" in entry
                and (
                    method != "POST"
                    or served_value != "post-ack"
                    or not isinstance(body_digest, str)
                    or re.fullmatch(r"[0-9a-fA-F]{16}", body_digest) is None
                )
            )
        ):
            malformed_entries += 1
            continue
        if proxy_denied:
            continue
        if served_value not in REQUEST_ACTIVITY_SERVED_CLASSES:
            continue
        served = entry.get("served")
        logged_query_names = entry.get("query_names")
        if isinstance(logged_query_names, list):
            shape["query_names"] = logged_query_names
            shape["query_names_truncated"] = (
                entry.get("query_names_truncated") is True
            )
        candidate_requests += 1
        base = {"method": method, "served": served, **shape}
        key = json.dumps(base, sort_keys=True, separators=(",", ":"))
        bucket = buckets.setdefault(
            key,
            {
                **base,
                "count": 0,
                "body_bytes_total": 0,
                "body_bytes_min": None,
                "body_bytes_max": None,
                "body_sha256_16_counts": {},
            },
        )
        body_bytes = entry.get("request_body_bytes")
        body_bytes = (
            body_bytes
            if isinstance(body_bytes, int)
            and not isinstance(body_bytes, bool)
            and 0 <= body_bytes <= 1_000_000_000
            else 0
        )
        bucket["count"] += 1
        bucket["body_bytes_total"] += body_bytes
        bucket["body_bytes_min"] = (
            body_bytes
            if bucket["body_bytes_min"] is None
            else min(bucket["body_bytes_min"], body_bytes)
        )
        bucket["body_bytes_max"] = (
            body_bytes
            if bucket["body_bytes_max"] is None
            else max(bucket["body_bytes_max"], body_bytes)
        )
        if isinstance(body_digest, str):
            digest = body_digest.lower()
            bucket["body_sha256_16_counts"][digest] = (
                bucket["body_sha256_16_counts"].get(digest, 0) + 1
            )
    for bucket in buckets.values():
        if not bucket["body_sha256_16_counts"]:
            del bucket["body_sha256_16_counts"]
    ordered = [buckets[key] for key in sorted(buckets)]
    truncated_paths = sum(
        1
        for entry in entries
        if isinstance(entry, dict) and entry.get("path_truncated") is True
    )
    return _sanitize_request_activity_report(
        {
            "status": (
                "unverifiable" if truncated_paths or malformed_entries else "ok"
            ),
            "candidate_requests": candidate_requests,
            "distinct_shapes": len(ordered),
            "rows": ordered,
            "truncated": (
                len(ordered) > 128 or bool(truncated_paths) or bool(malformed_entries)
            ),
            "truncated_paths": truncated_paths,
            "dropped_requests": malformed_entries,
        }
    )


def _sanitize_input_probe_report(report: Any) -> dict[str, Any] | None:
    """Allowlist a probe receipt; diagnostics may be browser/page controlled."""
    if not isinstance(report, dict):
        return None

    def count(value: Any) -> int:
        return (
            value
            if isinstance(value, int)
            and not isinstance(value, bool)
            and 0 <= value <= 10_000
            else 0
        )

    profile = report.get("profile")
    if not isinstance(profile, str) or profile not in {
        "probe",
        "probe-scroll",
        "probe-touch",
    }:
        profile = "unknown"
    raw_errors = report.get("errors")
    errors_valid = isinstance(raw_errors, list)
    errors = raw_errors if errors_valid else []
    dispatched = count(report.get("dispatched"))
    attempted = count(report.get("attempted"))
    scroll_commands = count(report.get("scroll_commands_dispatched"))
    complete = bool(
        errors_valid
        and attempted > 0
        and dispatched == attempted
        and not errors
        and (profile != "probe-scroll" or scroll_commands == dispatched)
    )
    if "complete" in report and report["complete"] is not True:
        complete = False
    trusted = report.get("trusted", report.get("trusted_transport"))
    if "trusted" in report and "trusted_transport" in report and (
        report["trusted"] is not report["trusted_transport"]
    ):
        trusted = False
    touch_dispatched = report.get("touch_dispatched")
    return {
        "profile": profile,
        "dispatched": dispatched,
        "attempted": attempted,
        "errors": [_redact_diagnostic(value) for value in errors[:16]],
        "trusted_transport": trusted if isinstance(trusted, bool) else False,
        "touch_dispatched": (
            touch_dispatched is True and profile == "probe-touch" and complete
        ),
        "scroll_commands_dispatched": (
            scroll_commands if profile == "probe-scroll" else 0
        ),
        "complete": complete,
        "non_claim": "fixed method probe, not a human-behavior model",
    }


def _sanitize_ambient_input_report(report: Any) -> dict[str, Any] | None:
    """Retain only bounded trusted-event counts from the startup witness."""
    if not isinstance(report, dict):
        return None
    values = report.get("events")
    if not isinstance(values, dict):
        values = report.get("trusted_events")
    if not isinstance(values, dict):
        values = {}
    events = {
        key: value
        for key, value in values.items()
        if key in AMBIENT_INPUT_EVENT_NAMES
        and isinstance(value, int)
        and not isinstance(value, bool)
        and 0 <= value <= 10_000
    }
    contaminated = report.get("contaminated")
    return {
        "contaminated": contaminated if isinstance(contaminated, bool) else None,
        "trusted_events": dict(sorted(events.items())),
        "total_trusted_events": sum(events.values()),
    }


def _reconciled_ambient_input(
    document: dict[str, Any],
) -> tuple[dict[str, Any] | None, bool | None]:
    """Return a safe ambient receipt and whether the arm is demonstrably clean."""
    if "ambient_input" not in document:
        return None, None
    raw = document.get("ambient_input")
    safe = _sanitize_ambient_input_report(raw)
    profile = document.get("input_profile", "none")
    if not isinstance(raw, dict) or safe is None or profile not in INPUT_PROFILES:
        return None, False
    if "events" in raw and "trusted_events" in raw and (
        not isinstance(raw["events"], dict)
        or not isinstance(raw["trusted_events"], dict)
        or raw["events"] != raw["trusted_events"]
    ):
        return safe, False
    if "total_trusted_events" in raw and (
        type(raw["total_trusted_events"]) is not int
        or raw["total_trusted_events"] != safe["total_trusted_events"]
    ):
        return safe, False
    values = raw.get("events", raw.get("trusted_events"))
    if values is not None and (
        not isinstance(values, dict)
        or any(
            key not in AMBIENT_INPUT_EVENT_NAMES
            or isinstance(value, bool)
            or not isinstance(value, int)
            or value < 0
            or value > 10_000
            for key, value in values.items()
        )
    ):
        return safe, False
    contaminated = raw.get("contaminated")
    total = safe["total_trusted_events"]
    if contaminated is None:
        return safe, False
    if not isinstance(contaminated, bool):
        return safe, False
    expected = profile == "none" and total > 0
    if contaminated is not expected:
        return safe, False
    return safe, contaminated is False


def _reconciled_input_method(
    arm: dict[str, Any], control: dict[str, Any]
) -> tuple[bool, dict[str, Any] | None, dict[str, Any] | None]:
    """Require the same declared input method and complete delivery on both arms."""
    arm_profile = arm.get("input_profile", "none")
    control_profile = control.get("input_profile", "none")
    comparable = bool(
        isinstance(arm_profile, str)
        and arm_profile in INPUT_PROFILES
        and arm_profile == control_profile
    )
    safe_reports: list[dict[str, Any] | None] = []
    for document, profile in ((arm, arm_profile), (control, control_profile)):
        raw = document.get("input_probe")
        safe = _sanitize_input_probe_report(raw)
        safe_reports.append(safe)
        if profile == "none":
            comparable = comparable and raw is None
        else:
            delivery_complete = bool(
                safe is not None
                and safe.get("profile") == profile
                and safe.get("complete") is True
                and safe.get("trusted_transport") is True
                and (profile != "probe-touch" or safe.get("touch_dispatched") is True)
                and (
                    profile != "probe-scroll"
                    or (
                        isinstance(safe.get("scroll_commands_dispatched"), int)
                        and safe["scroll_commands_dispatched"] > 0
                    )
                )
            )
            comparable = bool(comparable and delivery_complete)
    return comparable, safe_reports[0], safe_reports[1]


def _driver_error_metadata(error: Exception) -> dict[str, Any]:
    """Bound a driver diagnostic and redact quoted page-controlled fragments."""
    diagnostic = _redact_diagnostic(error)
    return {
        "status": "failed",
        "error_type": diagnostic.split(";", 1)[0],
        "diagnostic": diagnostic,
    }


def _valid_startup_ambient_witness(value: Any) -> bool:
    return isinstance(value, dict) and all(
        name in AMBIENT_INPUT_EVENT_NAMES and type(count) is int and count >= 0
        for name, count in value.items()
    )


def _project_startup_vendor_global(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    if value in STARTUP_EXACT_VENDOR_GLOBALS:
        return value
    lowered = value.lower()
    return next(
        (
            family
            for prefix, family in STARTUP_VENDOR_GLOBAL_PREFIXES
            if lowered.startswith(prefix)
        ),
        None,
    )


def _valid_startup_vendor_witness(value: Any) -> bool:
    return isinstance(value, list) and all(
        _project_startup_vendor_global(item) is not None for item in value
    )


def _sanitize_startup_document(document: Any) -> dict[str, Any]:
    """Allowlist startup state and redact page-controlled diagnostic content."""
    if not isinstance(document, dict):
        raise ValueError("startup witness did not return an object")
    sanitized: dict[str, Any] = {}
    for field in ("uncaught_errors", "unhandled_rejections"):
        values = document.get(field)
        sanitized[field] = (
            [_redact_diagnostic(value) for value in values[:16]]
            if isinstance(values, list)
            else []
        )
    globals_value = document.get("vendor_globals")
    safe_globals: list[str] = []
    for value in globals_value[:32] if isinstance(globals_value, list) else []:
        projected = _project_startup_vendor_global(value)
        if projected is not None and projected not in safe_globals:
            safe_globals.append(projected)
    sanitized["vendor_globals"] = safe_globals
    ready = document.get("vendor_reports_ready")
    sanitized["vendor_reports_ready"] = (
        ready if ready is None or isinstance(ready, bool) or ready == "threw" else None
    )
    ambient = document.get("ambient_input")
    if isinstance(ambient, dict):
        sanitized["ambient_input"] = {
            name: min(value, 1_000_000)
            for name, value in ambient.items()
            if name in AMBIENT_INPUT_EVENT_NAMES
            and isinstance(value, int)
            and not isinstance(value, bool)
            and value >= 0
        }
    for field in ("window_properties", "window_properties_before_script"):
        value = document.get(field)
        if value is None:
            sanitized[field] = None
        elif isinstance(value, int) and not isinstance(value, bool) and value >= 0:
            sanitized[field] = min(value, 1_000_000)
    started = document.get("started")
    if started is None or isinstance(started, bool):
        sanitized["started"] = started
    reasons = document.get("reasons")
    if isinstance(reasons, list):
        sanitized["reasons"] = [_redact_diagnostic(value) for value in reasons[:16]]
    if document.get("probe_error") is not None:
        sanitized["probe_error"] = _redact_diagnostic(document["probe_error"])
    blocked = document.get("renderer_blocked")
    if blocked is None or isinstance(blocked, bool):
        sanitized["renderer_blocked"] = blocked
    target_status = document.get("browser_target_status")
    if isinstance(target_status, str) and target_status in {
        "present",
        "absent",
        "unreachable",
        "invalid-response",
    }:
        sanitized["browser_target_status"] = target_status
    title_matches = document.get("browser_target_title_matches")
    if title_matches is None or isinstance(title_matches, bool):
        if "browser_target_title_matches" in document:
            sanitized["browser_target_title_matches"] = title_matches
    return sanitized


def _reconciled_collector_startup(
    document: dict[str, Any],
    *,
    current_required: bool = False,
) -> tuple[bool | None, dict[str, Any] | None, bool | None]:
    """Validate the graded startup receipt before it can authorize a claim."""
    if "collector_startup" not in document:
        return None, None, False if current_required else None
    raw = document.get("collector_startup")
    if not isinstance(raw, dict):
        return None, {"started": None, "reasons": []}, False
    try:
        sanitized = _sanitize_startup_document(raw)
    except (TypeError, ValueError):
        return None, {"started": None, "reasons": []}, False
    started = raw.get("started")
    reasons = raw.get("reasons")
    coherent = bool(
        (started is None or isinstance(started, bool))
        and isinstance(reasons, list)
        and len(reasons) <= 16
        and all(isinstance(reason, str) for reason in reasons)
        and ((started is True) == (len(reasons) == 0))
    )
    ready = raw.get("vendor_reports_ready")
    if ready is not None and type(ready) is not bool and ready != "threw":
        coherent = False
    if "vendor_globals" in raw and not _valid_startup_vendor_witness(
        raw["vendor_globals"]
    ):
        coherent = False
    if any(
        field in raw and not isinstance(raw[field], list)
        for field in ("uncaught_errors", "unhandled_rejections")
    ):
        coherent = False
    if started is True:
        coherent = coherent and not any(
            isinstance(raw.get(field), list) and bool(raw.get(field))
            for field in ("uncaught_errors", "unhandled_rejections")
        )
        coherent = (
            coherent
            and raw.get("vendor_reports_ready") is not False
            and raw.get("vendor_reports_ready") != "threw"
        )
        coherent = coherent and raw.get("probe_error") is None
    if raw.get("probe_error") is not None:
        coherent = coherent and started is None and bool(reasons)
    if raw.get("vendor_reports_ready") is False:
        coherent = coherent and started is False and bool(reasons)
    if current_required or "startup" in document:
        startup = document.get("startup")
        analysis = document.get("analysis")
        attributable = (
            analysis.get("attributable_events") if isinstance(analysis, dict) else None
        )
        contexts = (
            analysis.get("execution_context_counts")
            if isinstance(analysis, dict)
            else None
        )
        startup_coherent = False
        if (
            isinstance(startup, dict)
            and isinstance(attributable, int)
            and not isinstance(attributable, bool)
            and attributable >= 0
            and isinstance(contexts, dict)
        ):
            try:
                safe_startup = _sanitize_startup_document(startup)
                recomputed = grade_collector_startup(
                    safe_startup,
                    attributable,
                    contexts,
                )
                expected_ambient = grade_ambient_input(
                    safe_startup, document.get("input_profile", "none")
                )
                startup_coherent = bool(
                    safe_startup == startup
                    and recomputed == raw
                    and document.get("ambient_input") == expected_ambient
                )
            except (ContractError, TypeError, ValueError):
                startup_coherent = False
        coherent = coherent and startup_coherent
    if not coherent:
        sanitized["started"] = None
        sanitized["reasons"] = []
    return started if coherent else None, sanitized, coherent


def _sanitize_geometry_document(document: Any) -> dict[str, Any]:
    """Allowlist the measured viewport without accepting page-controlled extras."""
    if not isinstance(document, dict):
        raise ValueError("geometry probe did not return an object")
    result: dict[str, Any] = {}
    for field in (
        "inner_width",
        "inner_height",
        "outer_width",
        "outer_height",
        "screen_width",
        "screen_height",
    ):
        value = document.get(field)
        if (
            is_finite_number(value)
            and 0 <= value <= 1_000_000
        ):
            result[field] = value
    dpr = document.get("device_pixel_ratio")
    if (
        is_finite_number(dpr)
        and 0 <= dpr <= 1_000
    ):
        result["device_pixel_ratio"] = dpr
    return result


def _decode_page_probe(
    raw: object, *, label: str, fields: frozenset[str]
) -> dict[str, Any]:
    """Decode a bounded page-produced JSON object with one exact producer shape."""
    if not isinstance(raw, str):
        raise ContractError(f"{label} must return a JSON string")
    try:
        body = raw.encode("utf-8", errors="strict")
    except UnicodeEncodeError:
        raise ContractError(f"{label} must return valid UTF-8 text") from None
    if len(body) > MAX_PAGE_PROBE_JSON_BYTES:
        raise ContractError(f"{label} exceeds the page-probe byte limit")
    document = decode_strict_json_bytes(body, label=label)
    if not isinstance(document, dict) or set(document) != fields:
        raise ContractError(f"{label} fields are invalid")
    return document


def _driver_supplied(document: dict[str, Any]) -> bool:
    """Read redacted current artifacts and legacy raw-driver artifacts."""
    driver = document.get("driver")
    if driver is None:
        driver = document.get("arm_driver")
    if isinstance(driver, dict) and "supplied" in driver:
        return driver.get("supplied") is True
    if "arm_driver_supplied" in document:
        return document.get("arm_driver_supplied") is True
    return isinstance(document.get("driver_js"), str)


def _driver_metadata(document: dict[str, Any]) -> dict[str, Any]:
    """Normalize current redacted and legacy raw driver representations."""
    driver = document.get("driver")
    if driver is None:
        driver = document.get("arm_driver")
    if isinstance(driver, (dict, str)):
        return _stored_js_metadata(driver)
    legacy = document.get("driver_js")
    return _prelude_metadata(legacy if isinstance(legacy, str) else None)


def _ready_expression_metadata(document: dict[str, Any]) -> dict[str, Any]:
    """Normalize current metadata and hash legacy raw readiness expressions."""
    expression = document.get("ready_expression")
    if expression is None:
        expression = document.get("arm_ready_expression")
    return _stored_js_metadata(expression)


def _stage_route_metadata(
    stage_routes: tuple[tuple[str, Path | bytes], ...],
) -> list[dict[str, Any]]:
    """Bind ordered stage bytes without retaining local filesystem paths."""
    metadata = []
    total = 0
    for prefix, source in stage_routes:
        if isinstance(source, bytes):
            payload = source
        elif isinstance(source, Path):
            payload = _read_stable_regular_bytes(
                source,
                maximum=MAX_STAGE_BYTES,
                label="stage route source",
            )
        else:
            raise ContractError("stage route source must be Path or bytes")
        total += len(payload)
        if total > MAX_STAGE_BYTES:
            raise ContractError("staged scripts exceed the aggregate byte limit")
        metadata.append(
            {
                "path_prefix": prefix,
                "bytes": len(payload),
                "sha256_16": hashlib.sha256(payload).hexdigest()[:16],
            }
        )
    return metadata


def _observation_stage_routes(document: dict[str, Any]) -> list[dict[str, Any]]:
    """Bind stage route and bytes without local or tenant path values."""
    result = []
    stage_routes = document.get("stage_routes")
    if stage_routes is None:
        stage_routes = document.get("arm_stage_routes")
    values = stage_routes if isinstance(stage_routes, (list, tuple)) else []
    for item in values[:MAX_STAGE_ROUTES]:
        if not isinstance(item, dict):
            continue
        prefix = _script_path_method_value(item.get("path_prefix"))
        digest = item.get("sha256_16")
        result.append(
            {
                "path_prefix": prefix,
                "sha256_16": (
                    str(digest).lower()
                    if isinstance(digest, str)
                    and re.fullmatch(r"[0-9a-fA-F]{16}", digest)
                    else None
                ),
            }
        )
    return result


def _browser_build_method(document: dict[str, Any]) -> dict[str, Any] | None:
    """Execution identity only; attestation time is provenance, not behavior."""
    build = document.get("browser_build")
    if not isinstance(build, dict):
        return None
    provenance = build.get("provenance")
    result: dict[str, Any] = {}
    if isinstance(provenance, str) and provenance in {
        "attested-browser-core",
        "unverified-external",
    }:
        result["provenance"] = provenance
    elif provenance is not None:
        result["provenance"] = _unverifiable_method_value(provenance)
    for key in ("executable_sha256_16", "runtime_bundle_sha256_16"):
        value = build.get(key)
        if value is None:
            continue
        result[key] = (
            value.lower()
            if isinstance(value, str) and re.fullmatch(r"[0-9a-fA-F]{16}", value)
            else _unverifiable_method_value(value)
        )
    return result


_ARM_CONTROL_METHOD_SOURCES = (
    "headed",
    "viewport",
    "trace_scope",
    "trace_category_contract",
    "chromium_revision",
    "browser_build",
    "timeout_seconds",
    "dwell_seconds",
    "dom_profile",
    "hook_mode",
    "hook_target_names",
    "inline_script",
    "reloads",
    "script_path",
    "declared_script_url",
    "prelude",
    "driver",
    "resource_intent_capture",
    "extra_browser_args",
    "stage_routes",
)

_SCRIPT_IDENTITY_SIGNAL_FIELDS = {
    "bytes",
    "sha256_16",
    "lines",
    "arrow_functions",
    "string_literals",
    "bmak_literals",
    "kpsdk_literals",
    "istl_literals",
    "px_literals",
    "datadome_literals",
    "turnstile_literals",
    "datadome_markers",
    "turnstile_markers",
    "imperva_apg_markers",
    "geetest_loader_markers",
    "anubis_challenge_markers",
    "akamai_sbsd_markers",
    "function_keywords",
    "max_line_bytes",
    "bundler_markers",
    "source_map_markers",
    "distinct_identifier_ratio",
}
# The signal vocabulary grew twice without a schema rename: first SBSD, then
# distinct DataDome/Turnstile marker counts. Retain explicit readers for both
# historical generations rather than making unchanged artifacts incoherent.
_SCRIPT_IDENTITY_PRE_DISTINCT_MARKER_SIGNAL_FIELDS = (
    _SCRIPT_IDENTITY_SIGNAL_FIELDS - {"datadome_markers", "turnstile_markers"}
)
_SCRIPT_IDENTITY_PRE_SBSD_SIGNAL_FIELDS = (
    _SCRIPT_IDENTITY_PRE_DISTINCT_MARKER_SIGNAL_FIELDS - {"akamai_sbsd_markers"}
)
_SCRIPT_IDENTITY_SIGNAL_FIELD_SETS = (
    _SCRIPT_IDENTITY_SIGNAL_FIELDS,
    _SCRIPT_IDENTITY_PRE_DISTINCT_MARKER_SIGNAL_FIELDS,
    _SCRIPT_IDENTITY_PRE_SBSD_SIGNAL_FIELDS,
)
_SCRIPT_IDENTITY_REASONS = {
    "smaller than any observed built anti-bot script",
    "no single machine-generated line",
    "arrow functions present at application-bundle density",
    "module-bundler artifact, not a standalone collector",
    "multiple product vendor marker families",
}


def _method_value_is_unverifiable(value: Any) -> bool:
    if isinstance(value, dict):
        status = value.get("status")
        return ("status" in value and not isinstance(status, str)) or status in {
            "unverifiable", "truncated"
        } or any(
            _method_value_is_unverifiable(item) for item in value.values()
        )
    if isinstance(value, list):
        return any(_method_value_is_unverifiable(item) for item in value)
    return False


def _stored_js_method_is_coherent(value: dict[str, Any]) -> bool:
    supplied = value.get("supplied")
    size = value.get("bytes")
    digest = value.get("sha256_16")
    if supplied is False:
        return size == 0 and digest is None
    return bool(
        supplied is True
        and isinstance(size, int)
        and not isinstance(size, bool)
        and size >= 0
        and isinstance(digest, str)
        and re.fullmatch(r"[0-9a-f]{16}", digest)
    )


def _observation_method_receipt(
    document: dict[str, Any],
) -> tuple[dict[str, Any], set[str]]:
    """Project one observation's claim-relevant method without raw values."""
    raw_args = document.get("extra_browser_args")
    safe_args = _browser_arg_metadata(raw_args)
    raw_routes = document.get("stage_routes")
    safe_routes = _observation_stage_routes(document)
    raw_targets = document.get("hook_target_names")
    safe_targets = _hook_target_method_value(raw_targets)
    build = _browser_build_method(document)
    raw_viewport = document.get("viewport")
    viewport = _viewport_method_value(raw_viewport)
    prelude = _prelude_document_metadata(document)
    driver = _driver_metadata(document)
    declared_url = _declared_url_metadata(document.get("declared_script_url"))
    script_path = _script_path_method_value(document.get("script_path"))
    receipt = {
        "headed": _boolean_method_value(document.get("headed")),
        "viewport": viewport,
        "trace_scope": _enum_method_value(
            document.get("trace_scope"), set(TRACE_SCOPES)
        ),
        "trace_category_contract": _enum_method_value(
            document.get("trace_category_contract"),
            set(TRACE_CATEGORY_CONTRACTS),
        ),
        "chromium_revision": (
            str(document.get("chromium_revision")).lower()
            if isinstance(document.get("chromium_revision"), str)
            and re.fullmatch(r"[0-9a-fA-F]{40}", document["chromium_revision"])
            else _unverifiable_method_value(document.get("chromium_revision"))
        ),
        "browser_build": build,
        "timeout_seconds": _number_method_value(document.get("timeout_seconds")),
        "dwell_seconds": _number_method_value(document.get("dwell_seconds")),
        "dom_profile": _enum_method_value(
            document.get("dom_profile"), set(DOM_PROFILES)
        ),
        "hook_mode": _enum_method_value(document.get("hook_mode"), set(HOOK_MODES)),
        "hook_target_names": safe_targets,
        "inline_script": _boolean_method_value(document.get("inline_script")),
        "reloads": _number_method_value(document.get("reloads"), maximum=10_000),
        "script_path": script_path,
        "declared_script_url": declared_url,
        "prelude": prelude,
        "driver": driver,
        "resource_intent_capture": _enum_method_value(
            document.get("resource_intent_capture"),
            {"off", *RESOURCE_INTENT_CONTRACTS},
        ),
        "extra_browser_args": safe_args,
        "stage_routes": safe_routes,
    }
    invalid: set[str] = {
        field
        for field, value in receipt.items()
        if _method_value_is_unverifiable(value)
    }
    invalid.update(
        source for source in _ARM_CONTROL_METHOD_SOURCES if source not in document
    )
    if (
        not isinstance(raw_viewport, dict)
        or not isinstance(viewport, dict)
        or set(raw_viewport) != {
            "inner_width",
            "inner_height",
            "outer_width",
            "outer_height",
            "screen_width",
            "screen_height",
            "device_pixel_ratio",
        }
        or set(viewport) != set(raw_viewport)
    ):
        invalid.add("viewport")
    if (
        not isinstance(build, dict)
        or not isinstance(build.get("provenance"), str)
        or build.get("provenance")
        not in {"attested-browser-core", "unverified-external"}
        or not isinstance(build.get("executable_sha256_16"), str)
        or (
            build.get("provenance") == "attested-browser-core"
            and not isinstance(build.get("runtime_bundle_sha256_16"), str)
        )
    ):
        invalid.add("browser_build")
    if not _stored_js_method_is_coherent(prelude):
        invalid.add("prelude")
    if not _stored_js_method_is_coherent(driver):
        invalid.add("driver")
    if (
        script_path.get("supplied") is not True
        or script_path.get("absolute_path") is not True
        or script_path.get("query_present") is not False
        or script_path.get("fragment_present") is not False
    ):
        invalid.add("script_path")
    if declared_url.get("supplied") is True and declared_url.get("shape") is None:
        invalid.add("declared_script_url")
    if not isinstance(raw_args, (list, tuple)) or len(raw_args) != len(safe_args):
        invalid.add("extra_browser_args")
    if not isinstance(raw_routes, (list, tuple)) or len(raw_routes) != len(safe_routes):
        invalid.add("stage_routes")
    if any(route.get("sha256_16") is None for route in safe_routes):
        invalid.add("stage_routes")
    if not isinstance(raw_targets, (list, tuple)) or len(raw_targets) != len(
        safe_targets
    ):
        invalid.add("hook_target_names")
    if document.get("hook_mode") == "off" and safe_targets:
        invalid.add("hook_target_names")
    if not isinstance(document.get("reloads"), int) or isinstance(
        document.get("reloads"), bool
    ):
        invalid.add("reloads")
    return receipt, invalid


def _reconciled_arm_control_method(
    arm: dict[str, Any], control: dict[str, Any]
) -> tuple[bool | None, list[str]]:
    """Require current arm/control observations to use one exact method."""
    recorded = any(
        source in document
        for document in (arm, control)
        for source in _ARM_CONTROL_METHOD_SOURCES
    )
    if not recorded:
        return None, []
    arm_receipt, arm_invalid = _observation_method_receipt(arm)
    control_receipt, control_invalid = _observation_method_receipt(control)
    mismatches = {
        field for field in arm_receipt if arm_receipt[field] != control_receipt[field]
    }
    mismatches.update(arm_invalid)
    mismatches.update(control_invalid)
    return not mismatches, sorted(mismatches)


def _retained_subtraction_method_pairs(
    document: dict[str, Any],
) -> dict[str, tuple[Any, Any]]:
    """Project the method pairs retained by a saved subtraction."""
    return {
        "headed": (
            _boolean_method_value(document.get("arm_headed")),
            _boolean_method_value(document.get("control_headed")),
        ),
        "hook_mode": (
            _enum_method_value(document.get("arm_hook_mode"), set(HOOK_MODES)),
            _enum_method_value(document.get("control_hook_mode"), set(HOOK_MODES)),
        ),
        "dom_profile": (
            _enum_method_value(document.get("arm_dom_profile"), set(DOM_PROFILES)),
            _enum_method_value(document.get("control_dom_profile"), set(DOM_PROFILES)),
        ),
        "script_path": (
            _script_path_method_value(document.get("arm_script_path")),
            _script_path_method_value(document.get("control_script_path")),
        ),
        "declared_script_url": (
            _declared_url_metadata(document.get("arm_declared_script_url")),
            _declared_url_metadata(document.get("control_declared_script_url")),
        ),
        "prelude": (
            _stored_js_metadata(document.get("arm_prelude")),
            _stored_js_metadata(document.get("control_prelude")),
        ),
        "driver": (
            _stored_js_metadata(document.get("arm_driver")),
            _stored_js_metadata(document.get("control_driver")),
        ),
        "stage_routes": (
            _observation_stage_routes(
                {"stage_routes": document.get("arm_stage_routes")}
            ),
            _observation_stage_routes(
                {"stage_routes": document.get("control_stage_routes")}
            ),
        ),
    }


def _reconciled_script_identity(
    document: dict[str, Any], *, current_required: bool
) -> tuple[
    bool | None,
    dict[str, Any] | None,
    dict[str, Any],
    dict[str, Any],
]:
    """Bind labels and script bytes to closed classifier/provenance receipts."""
    recorded = any(
        field in document
        for field in (
            "script_identity",
            "script_bytes",
            "source_provenance",
            "provenance",
        )
    )
    safe_source = _sanitize_source_provenance(document.get("source_provenance"))
    safe_capture = _sanitize_capture_provenance(document.get("provenance"))
    if not recorded and not current_required:
        return None, None, safe_source, safe_capture
    label = document.get("label")
    digest = document.get("script_sha256_16")
    size = document.get("script_bytes")
    identity = document.get("script_identity")
    signals = identity.get("signals") if isinstance(identity, dict) else None
    reasons = identity.get("reasons") if isinstance(identity, dict) else None
    vendor_hint = identity.get("vendor_hint") if isinstance(identity, dict) else None
    looks_built = (
        identity.get("looks_like_built_antibot_script")
        if isinstance(identity, dict)
        else None
    )
    signal_field_set_valid = bool(
        isinstance(signals, dict)
        and any(set(signals) == fields for fields in _SCRIPT_IDENTITY_SIGNAL_FIELD_SETS)
    )
    integer_signals_valid = bool(
        isinstance(signals, dict)
        and all(
            isinstance(signals.get(field), int)
            and not isinstance(signals.get(field), bool)
            and 0 <= signals[field] <= 1_000_000_000
            for field in set(signals) - {"sha256_16", "distinct_identifier_ratio"}
        )
    )
    ratio = (
        signals.get("distinct_identifier_ratio") if isinstance(signals, dict) else None
    )
    identity_coherent = bool(
        isinstance(label, str)
        and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", label)
        and isinstance(digest, str)
        and re.fullmatch(r"[0-9a-fA-F]{16}", digest)
        and isinstance(size, int)
        and not isinstance(size, bool)
        and 0 <= size <= MAX_PRODUCT_SCRIPT_BYTES
        and isinstance(identity, dict)
        and set(identity)
        == {
            "schema",
            "signals",
            "looks_like_built_antibot_script",
            "reasons",
            "vendor_hint",
        }
        and identity.get("schema") == IDENTITY_SCHEMA
        and isinstance(signals, dict)
        and signal_field_set_valid
        and signals.get("sha256_16") == digest.lower()
        and signals.get("bytes") == size
        and integer_signals_valid
        and is_finite_number(ratio)
        and 0 <= ratio <= 1
        and isinstance(looks_built, bool)
        and isinstance(reasons, list)
        and len(reasons) <= len(_SCRIPT_IDENTITY_REASONS)
        and all(isinstance(reason, str) for reason in reasons)
        and len(reasons) == len(set(reasons))
        and all(reason in _SCRIPT_IDENTITY_REASONS for reason in reasons)
        and reasons == _classifier_reasons(signals)
        and looks_built == (not reasons)
        and vendor_hint == _vendor_hint(signals)
    )
    raw_source = document.get("source_provenance")
    source_status = raw_source.get("status") if isinstance(raw_source, dict) else None
    source_coherent = bool(
        isinstance(raw_source, dict)
        and isinstance(source_status, str)
        and source_status
        in {
            "not_supplied",
            "verified_digest",
            "verified_git_inputs_artifact_digest",
        }
        and safe_source.get("status") == source_status
    )
    if isinstance(source_status, str) and source_status in {
        "verified_digest",
        "verified_git_inputs_artifact_digest",
    }:
        source_coherent = bool(
            source_coherent
            and isinstance(safe_source.get("sha256"), str)
            and safe_source["sha256"][:16] == str(digest).lower()
        )
    raw_capture = document.get("provenance")
    capture_status = (
        raw_capture.get("status") if isinstance(raw_capture, dict) else None
    )
    capture_coherent = bool(
        isinstance(raw_capture, dict)
        and isinstance(capture_status, str)
        and capture_status in {"not_checked", "VERIFIED", "UNVERIFIED", "error"}
        and safe_capture.get("status") == capture_status
        and raw_capture.get("asserted_label") == label
    )
    safe_identity = (
        {
            "schema": IDENTITY_SCHEMA,
            "sha256_16": str(digest).lower(),
            "bytes": size,
            "looks_like_built_antibot_script": looks_built,
            "vendor_hint": vendor_hint,
        }
        if identity_coherent
        else None
    )
    return (
        identity_coherent and source_coherent and capture_coherent,
        safe_identity,
        safe_source,
        safe_capture,
    )


def _saved_fetch_target_scope_coherent(
    analysis: dict[str, Any], report_events: Any, network_event_count: int
) -> bool:
    """A retained native fetch-scope receipt must preserve the offline guard."""
    if "fetch_target_scope" not in analysis:
        # Older saved analyses predate native target-scope classification.
        return True
    scope = analysis["fetch_target_scope"]
    count_keys = ("requests", "loopback", "external", "non_network", "unclassified")
    if (
        type(scope) is not dict
        or set(scope) != {"coverage", *count_keys}
        or scope["coverage"] != "complete"
        or type(report_events) is not int
    ):
        return False
    if any(
        type(scope[key]) is not int or not 0 <= scope[key] <= report_events
        for key in count_keys
    ):
        return False
    return (
        scope["requests"]
        == scope["loopback"]
        + scope["external"]
        + scope["non_network"]
        + scope["unclassified"]
        and scope["external"] == 0
        and scope["unclassified"] == 0
        and scope["requests"] == network_event_count
    )


def _saved_request_population_coherent(
    analysis: dict[str, Any], network_event_count: int
) -> bool:
    """Retained request count maps must describe the validated network events."""
    for field in ("request_methods", "request_classes"):
        if field not in analysis:
            continue
        counts = analysis[field]
        if (
            type(counts) is not dict
            or len(counts) > network_event_count
            or any(
                type(name) is not str
                or not name
                or type(count) is not int
                or not 1 <= count <= network_event_count
                for name, count in counts.items()
            )
            or sum(counts.values()) != network_event_count
        ):
            return False
    if "distinct_request_classes" in analysis:
        classes = analysis.get("request_classes")
        if (
            type(classes) is not dict
            or type(analysis["distinct_request_classes"]) is not int
            or analysis["distinct_request_classes"] != len(classes)
        ):
            return False
    return True


def _reconciled_trace_evidence(
    document: dict[str, Any], *, current_required: bool,
    surface_event_count: int,
    surface_name_count: int,
    surface_script_execution_count: int,
    surface_network_event_count: int,
) -> tuple[bool | None, dict[str, Any]]:
    """Reconcile lifecycle, source, export, and analysis receipts value-free."""
    source_fields = (
        "browser_shutdown",
        "trace_flush",
        "trace_export_budget",
        "export",
        "run_id",
    )
    recorded = any(field in document for field in source_fields) or (
        isinstance(document.get("analysis"), dict)
        and "fetch_target_scope" in document["analysis"]
    )
    if not recorded and not current_required:
        return None, {}

    shutdown = document.get("browser_shutdown")
    mode = shutdown.get("mode") if isinstance(shutdown, dict) else None
    safe_shutdown = (
        {"mode": mode}
        if isinstance(mode, str) and mode in {"graceful", "forced", "exited-before-force"}
        else None
    )
    flush = document.get("trace_flush")
    flush_status = flush.get("status") if isinstance(flush, dict) else None
    flush_bytes = flush.get("bytes") if isinstance(flush, dict) else None
    safe_flush = {
        "status": (
            flush_status
            if isinstance(flush_status, str)
            and flush_status in {"settled", "missing", "present-unsettled"}
            else "unverifiable"
        ),
        "bytes": (
            flush_bytes
            if isinstance(flush_bytes, int)
            and not isinstance(flush_bytes, bool)
            and 0 <= flush_bytes <= MAX_OBSERVATION_TRACE_EXPORT_BYTES
            else None
        ),
    }
    budget = document.get("trace_export_budget")
    export = document.get("export")
    report = export.get("report") if isinstance(export, dict) else None
    validated_report = None
    try:
        validated_report = validate_trace_export_report(report)
    except ContractError:
        pass
    analysis = document.get("analysis")
    trace_summary = (
        analysis.get("trace_summary") if isinstance(analysis, dict) else None
    )
    report_source = (
        validated_report.get("source_trace")
        if isinstance(validated_report, dict)
        else None
    )
    report_normalized = (
        validated_report.get("normalized_trace")
        if isinstance(validated_report, dict)
        else None
    )
    report_events = (
        report_normalized.get("events") if isinstance(report_normalized, dict) else None
    )
    export_events = export.get("events") if isinstance(export, dict) else None
    run_id = document.get("run_id")
    revision = document.get("chromium_revision")
    component_counts = (
        analysis.get("events_by_component") if isinstance(analysis, dict) else None
    )
    component_population_matches = bool(
        isinstance(analysis, dict)
        and (
            "events_by_component" not in analysis
            or (
                type(component_counts) is dict
                and len(component_counts) <= MAX_OBSERVATION_TRACE_EXPORT_EVENTS
                and all(
                    type(count) is int
                    and 1 <= count <= MAX_OBSERVATION_TRACE_EXPORT_EVENTS
                    for count in component_counts.values()
                )
                and sum(component_counts.values()) == report_events
            )
        )
    )
    exact_budget = bool(
        isinstance(budget, dict)
        and set(budget)
        == {
            "max_source_bytes",
            "source_bytes",
            "bytes_within_budget",
            "max_exportable_events",
            "exportable_events",
            "events_within_budget",
            "within_budget",
            "policy",
        }
        and budget.get("max_source_bytes") == MAX_OBSERVATION_TRACE_EXPORT_BYTES
        and type(budget.get("source_bytes")) is int
        and budget.get("source_bytes") == flush_bytes
        and budget.get("bytes_within_budget") is True
        and budget.get("max_exportable_events") == MAX_OBSERVATION_TRACE_EXPORT_EVENTS
        and isinstance(budget.get("exportable_events"), int)
        and not isinstance(budget.get("exportable_events"), bool)
        and 1 <= budget["exportable_events"] <= MAX_OBSERVATION_TRACE_EXPORT_EVENTS
        and budget.get("events_within_budget") is True
        and budget.get("within_budget") is True
        and budget.get("policy") == "skip-automatic-normalization-above-budget"
    )
    exact_export = bool(
        isinstance(export, dict)
        and set(export) == {"events", "output", "run_id", "report", "report_output"}
        and type(export_events) is int
        and export_events == report_events
        and isinstance(budget, dict)
        and export_events == budget.get("exportable_events")
        and export.get("run_id") == run_id
    )
    exact_analysis = bool(
        isinstance(analysis, dict)
        and isinstance(trace_summary, dict)
        and set(trace_summary) == {"run_id", "events", "dropped_events"}
        and trace_summary.get("run_id") == run_id
        and type(trace_summary.get("events")) is int
        and trace_summary.get("events") == report_events
        and type(trace_summary.get("dropped_events")) is int
        and trace_summary.get("dropped_events") == 0
        and type(analysis.get("total_events")) is int
        and analysis.get("total_events") == report_events
        and surface_event_count == report_events
        and component_population_matches
        and _saved_fetch_target_scope_coherent(
            analysis, report_events, surface_network_event_count
        )
        and _saved_request_population_coherent(analysis, surface_network_event_count)
        and (
            "script_execution" not in analysis
            or (
                type(analysis["script_execution"]) is dict
                and type(analysis["script_execution"].get("total")) is int
                and analysis["script_execution"]["total"]
                == surface_script_execution_count
            )
        )
        and (
            "distinct_api_names" not in analysis
            or (
                type(analysis["distinct_api_names"]) is int
                and analysis["distinct_api_names"] == surface_name_count
            )
        )
        and type(analysis.get("attributable_events")) is int
        and 0 <= analysis["attributable_events"] <= report_events
        and (
            analysis.get("script_attributed_events") is None
            or (
                type(analysis["script_attributed_events"]) is int
                and 0 <= analysis["script_attributed_events"]
                <= analysis["attributable_events"]
            )
        )
        and (
            "events_by_component" not in analysis
            or analysis.get("script_attributed_events") is None
            or analysis["attributable_events"]
            == report_events
            - component_counts.get(GENERATED_COMPONENT, 0)
            + analysis["script_attributed_events"]
        )
    )
    coherent = bool(
        set(document) >= set(source_fields)
        and isinstance(shutdown, dict)
        and set(shutdown) == {"mode"}
        and isinstance(mode, str)
        and mode in {"graceful", "exited-before-force"}
        and isinstance(flush, dict)
        and set(flush) == {"status", "bytes"}
        and flush_status == "settled"
        and isinstance(flush_bytes, int)
        and not isinstance(flush_bytes, bool)
        and 0 < flush_bytes <= MAX_OBSERVATION_TRACE_EXPORT_BYTES
        and exact_budget
        and exact_export
        and exact_analysis
        and isinstance(validated_report, dict)
        and validated_report.get("run_id") == run_id
        and validated_report.get("chromium_revision") == revision
        and isinstance(report_source, dict)
        and report_source.get("bytes") == flush_bytes
    )
    safe: dict[str, Any] = {
        "browser_shutdown": safe_shutdown,
        "trace_flush": safe_flush,
    }
    if isinstance(validated_report, dict):
        assert isinstance(report_source, dict)
        assert isinstance(report_normalized, dict)
        safe["export"] = {
            "run_id": validated_report["run_id"],
            "chromium_revision": validated_report["chromium_revision"],
            "source_trace": {
                "bytes": report_source["bytes"],
                "sha256_16": report_source["sha256"][:16],
            },
            "normalized_trace": {
                "bytes": report_normalized["bytes"],
                "sha256_16": report_normalized["sha256"][:16],
                "events": report_normalized["events"],
                "trace_categories": dict(report_normalized["trace_categories"]),
                "category_provenance": report_normalized["category_provenance"],
            },
        }
    return coherent, safe


_GEOMETRY_JS = """
(() => {
  const g = (f) => { try { const v = f(); return v === undefined ? null : v; }
                     catch (e) { return null; } };
  return JSON.stringify({
    inner_width:  g(() => window.innerWidth),
    inner_height: g(() => window.innerHeight),
    outer_width:  g(() => window.outerWidth),
    outer_height: g(() => window.outerHeight),
    screen_width: g(() => screen.width),
    screen_height: g(() => screen.height),
    device_pixel_ratio: g(() => window.devicePixelRatio)
  });
})()
"""


def _capture_geometry(
    endpoint: str, url: str, timeout_seconds: float
) -> dict[str, Any] | None:
    """Record the viewport the page actually saw.

    A collector can gate behaviour on geometry, so two arms with identical recorded
    settings can produce different surfaces with nothing in either artifact
    explaining it. Measured 2026-08-06 on one Akamai BM web build: a 16-name
    DeviceMotion module executes when viewport height falls below roughly 115 px,
    and an archived arm recorded 119 names against the same bytes' 103 today under
    nominally identical settings -- most plausibly a degenerate viewport at capture
    time (locked screen, minimised or off-screen window), which nothing recorded.

    Best-effort by construction. Geometry is metadata about an observation and must
    never be able to fail one; a browser that will not answer yields ``None``,
    which reads as "not recorded" rather than as zero.
    """
    try:
        raw = evaluate_page_expression(
            endpoint, _GEOMETRY_JS, target_url=url, timeout_seconds=timeout_seconds
        )
        return _sanitize_geometry_document(
            _decode_page_probe(
                raw,
                label="geometry probe",
                fields=frozenset(
                    {
                        "inner_width",
                        "inner_height",
                        "outer_width",
                        "outer_height",
                        "screen_width",
                        "screen_height",
                        "device_pixel_ratio",
                    }
                ),
            )
        )
    except Exception:  # noqa: BLE001 - never fail a run over metadata
        return None


INPUT_PROFILES = ("none", "probe", "probe-scroll", "probe-touch")

# Named semantic versions for the fixed CDP command plans. The rehost contract
# below binds these alongside the exact page/witness/hook bytes. A command-plan
# change must mint a new value; otherwise old and new input arms could compare as
# one method even though the browser received a different intervention.
INPUT_PROBE_CONTRACTS = {
    "none": "browser-core.input-probe/none/1",
    "probe": "browser-core.input-probe/mouse-key/1",
    "probe-scroll": "browser-core.input-probe/scroll/1",
    "probe-touch": "browser-core.input-probe/touch/1",
}

# A deliberately small, deliberately obvious input pattern.
#
# The question it answers is binary: does the collector's observed surface change
# at all when input actually occurs? Notes 144-146 all carry the caveat
# "registration is not collection" precisely because an offline rehost has no
# operator, so the 18 bound listeners never fire and nothing downstream of them can
# be observed. This fires them.
#
# It is NOT a behaviour model and must not become one. Straight-line motion, fixed
# steps, no timing distribution, no curvature, no dwell -- everything that would
# make it resemble a person is absent by design. What it establishes is the
# existence of a downstream effect, not the shape of a plausible one.
_INPUT_PROBE_STEPS = 12


def _input_probe_events(profile: str) -> list[tuple[str, dict[str, Any]]]:
    """Return the exact fixed CDP command plan for one input method profile."""
    if profile not in INPUT_PROFILES or profile == "none":
        raise ContractError(f"input probe profile must be one of {INPUT_PROFILES[1:]}")
    events: list[tuple[str, dict[str, Any]]] = []
    if profile == "probe-scroll":
        for delta_y in (180, 180, -120):
            events.append(
                (
                    "Input.dispatchMouseEvent",
                    {
                        "type": "mouseWheel",
                        "x": 300,
                        "y": 220,
                        "deltaX": 0,
                        "deltaY": delta_y,
                    },
                )
            )
    elif profile == "probe-touch":
        touch_point = {
            "x": 260,
            "y": 180,
            "id": 1,
            "radiusX": 1,
            "radiusY": 1,
            "force": 0.5,
        }
        events.extend(
            [
                (
                    "Input.dispatchTouchEvent",
                    {"type": "touchStart", "touchPoints": [touch_point]},
                ),
                (
                    "Input.dispatchTouchEvent",
                    {
                        "type": "touchMove",
                        "touchPoints": [{**touch_point, "x": 285, "y": 205}],
                    },
                ),
                (
                    "Input.dispatchTouchEvent",
                    {"type": "touchEnd", "touchPoints": []},
                ),
            ]
        )
    else:
        for step in range(_INPUT_PROBE_STEPS):
            events.append(
                (
                    "Input.dispatchMouseEvent",
                    {"type": "mouseMoved", "x": 40 + step * 25, "y": 40 + step * 15},
                )
            )
        events.extend(
            [
                (
                    "Input.dispatchMouseEvent",
                    {
                        "type": "mousePressed",
                        "x": 340,
                        "y": 220,
                        "button": "left",
                        "clickCount": 1,
                    },
                ),
                (
                    "Input.dispatchMouseEvent",
                    {
                        "type": "mouseReleased",
                        "x": 340,
                        "y": 220,
                        "button": "left",
                        "clickCount": 1,
                    },
                ),
            ]
        )
        for key, code in (("a", "KeyA"), ("b", "KeyB")):
            events.extend(
                [
                    (
                        "Input.dispatchKeyEvent",
                        {"type": "keyDown", "text": key, "key": key, "code": code},
                    ),
                    (
                        "Input.dispatchKeyEvent",
                        {"type": "keyUp", "key": key, "code": code},
                    ),
                ]
            )
    return events


def _drive_input_probe(
    endpoint: str, url: str, timeout_seconds: float, *, profile: str = "probe"
) -> dict[str, Any]:
    """Deliver one fixed trusted-input method control to the rehost page.

    Trusted matters. A page-side ``dispatchEvent`` sets ``isTrusted: false``, and
    this collector defines ``untrustedClickCount``, ``missingTrustedEvents`` and
    ``trustedCountersDict`` (note 146 §5.3) -- so a synthetic-event probe would
    exercise the branch that notices synthetic events. CDP input goes through the
    browser's real input pipeline instead.

    Best-effort like the other probes: a failure is recorded, never raised.
    """
    from .cdp import send_page_input_batch

    events = _input_probe_events(profile)

    try:
        report = send_page_input_batch(
            endpoint,
            events,
            target_url=url,
            # Whole-batch deadline, not per event. The renderer is running a 552 KB
            # collector while these are delivered, so responses are not instant.
            timeout_seconds=max(timeout_seconds, 30.0),
            first_command_id=960,
        )
    except Exception as exc:  # noqa: BLE001 - recorded, never fatal
        report = {
            "dispatched": 0,
            "attempted": len(events),
            "errors": [exc],
        }

    if not isinstance(report, dict):
        report = {"dispatched": 0, "errors": ["invalid input probe report"]}
    dispatched_value = report.get("dispatched")
    dispatched = (
        dispatched_value
        if isinstance(dispatched_value, int)
        and not isinstance(dispatched_value, bool)
        and 0 <= dispatched_value <= len(events)
        else 0
    )
    report_errors = report.get("errors")
    safe_errors = (
        [_redact_diagnostic(value) for value in report_errors[:16]]
        if isinstance(report_errors, list)
        else [_redact_diagnostic("invalid input probe error list")]
    )

    return {
        "profile": profile,
        "dispatched": dispatched,
        "attempted": len(events),
        "errors": safe_errors,
        "trusted": True,
        "touch_dispatched": (profile == "probe-touch" and dispatched == len(events)),
        "scroll_commands_dispatched": (dispatched if profile == "probe-scroll" else 0),
        "non_claims": [
            "a fixed input probe, not a behaviour model and not usable as one",
            "establishes whether a downstream effect exists, not what a plausible "
            "operator looks like",
            (
                "touch requires an explicitly touch-enabled browser method arm; "
                "verify a trusted touchstart witness before interpretation"
                if profile == "probe-touch"
                else "touch is not dispatched: touch-path behaviour is untested "
                "rather than absent"
            ),
            (
                "wheel commands produce scroll events only on a scrollable page; "
                "use the tall DOM profile and verify ambient scroll counts"
                if profile == "probe-scroll"
                else "scroll is not dispatched by this profile"
            ),
        ],
    }


def _harvest_arguments(
    endpoint: str, url: str, timeout_seconds: float, command_id: int
) -> dict[str, Any] | None:
    """Read the page-side argument store.

    Best-effort in the same sense as geometry: this is evidence *about* a run and
    must not be able to fail one. A harvest that could not be taken is recorded as
    an error state rather than as an empty record set, because "we did not get the
    arguments" and "the collector passed no arguments" are opposite findings.
    """
    from .argument_capture import HARVEST_JS, parse_harvest

    try:
        raw = evaluate_page_expression(
            endpoint,
            HARVEST_JS,
            target_url=url,
            timeout_seconds=timeout_seconds,
            command_id=command_id,
        )
        return parse_harvest(raw)
    except Exception as exc:  # noqa: BLE001 - never fail a run over evidence capture
        from .argument_capture import CAPTURE_SCHEMA

        return {
            "schema": CAPTURE_SCHEMA,
            "status": "error",
            "note": _failure_receipt("harvest failed", exc),
            "records": [],
        }


def _failed_observation(
    config: "ProductScriptObservation",
    identity: dict[str, Any],
    error: str,
    rehost_contract: dict[str, Any],
    script_payload: bytes,
) -> dict[str, Any]:
    """A minimal observation document for an arm that never started.

    Carries the same identifying fields a successful arm does, so a failed arm is
    still countable, attributable and auditable -- `observe batch-audit` reports it
    by label and cause rather than the arm simply being missing from the directory.
    """
    return _seal_observation_document({
        "schema": OBSERVATION_SCHEMA,
        "generated_at": _utc_now(),
        "label": config.label,
        "script_basename": config.script.name,
        "script_sha256_16": identity["signals"]["sha256_16"],
        "script_bytes": identity["signals"]["bytes"],
        "script_identity": identity,
        "trace_scope": config.trace_scope,
        "headed": config.headed,
        "dwell_seconds": config.dwell_seconds,
        "timeout_seconds": config.timeout_seconds,
        "dom_profile": config.dom_profile,
        "rehost_contract": rehost_contract,
        "script_path": config.script_path,
        "declared_script_url": config.declared_script_url,
        "source_provenance": grade_script_source_provenance(config, script_payload),
        "extra_browser_args": list(config.extra_browser_args),
        "hook_mode": config.hook_mode,
        "input_profile": config.input_profile,
        "input_probe": None,
        "ambient_input": None,
        "ready_expression": _prelude_metadata(config.ready_expression),
        "resource_intent_capture": (
            RESOURCE_INTENT_CONTRACT if config.capture_resource_intents else "off"
        ),
        "resource_intents": None,
        "request_activity": None,
        "prelude": _prelude_metadata(config.prelude_js),
        "driver": _prelude_metadata(config.driver_js),
        "stage_routes": _stage_route_metadata(config.stage_routes),
        "viewport": None,
        "offline_guard": {"status": "not-applied"},
        "server_requests": [],
        "error": error,
        "non_claims": [
            "this arm produced no observation; it must not be read as an empty result",
        ],
    })


def _await_trace_file(
    trace_path: Path, timeout_seconds: float, *, settle_seconds: float = 0.4
) -> bool:
    """Wait for Chromium to finish writing its Perfetto trace.

    ``stop_session`` returns when the browser process is gone, but the trace is
    flushed asynchronously and can still be arriving. Exporting immediately is
    therefore a **race**, and it is a race that gets lost more often the busier the
    host is -- which is exactly the shape of the undiagnosed "batches drop arms"
    failure recorded in session 2 (2 of 27, 1 of 22) and of the run that failed
    six times in a row here on 2026-08-07 while succeeding minutes earlier.

    Waits for the file to exist *and* for its size to stop changing, so a
    partially-written trace is not exported as if it were complete. Returns whether
    the file settled; the caller still handles absence, because a browser that
    genuinely never wrote a trace must fail the arm rather than hang.
    """
    # Bounded separately from the run timeout. A trace that is coming lands within
    # a second or two, so a long wait buys nothing -- while an arm whose browser
    # genuinely never wrote one would otherwise pay the full run timeout before
    # failing. Measured: with the run timeout (60 s) two failing unit tests took
    # 120 s between them, which is the same cost a real batch would pay per dead arm.
    deadline = time.monotonic() + min(max(timeout_seconds, 1.0), TRACE_SETTLE_TIMEOUT)
    last_identity: tuple[int, ...] | None = None
    stable_since: float | None = None
    while time.monotonic() < deadline:
        try:
            metadata = os.lstat(trace_path)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or int(getattr(metadata, "st_file_attributes", 0)) & 0x400
                or metadata.st_nlink != 1
                or metadata.st_size <= 0
            ):
                identity = None
            else:
                identity = (
                    metadata.st_dev,
                    metadata.st_ino,
                    stat.S_IFMT(metadata.st_mode),
                    metadata.st_size,
                    metadata.st_mtime_ns,
                    metadata.st_ctime_ns,
                    int(getattr(metadata, "st_file_attributes", 0)),
                )
        except OSError:
            identity = None
        if identity is not None:
            if identity == last_identity:
                if stable_since is None:
                    stable_since = time.monotonic()
                elif time.monotonic() - stable_since >= settle_seconds:
                    return True
            else:
                stable_since = None
            last_identity = identity
        else:
            stable_since = None
            last_identity = None
        time.sleep(0.1)
    return False


def _trace_flush_receipt(trace_path: Path, settled: bool) -> dict[str, Any]:
    """Describe trace readiness without retaining its local path."""
    present = False
    try:
        metadata = os.lstat(trace_path)
        present = True
        if (
            not stat.S_ISREG(metadata.st_mode)
            or int(getattr(metadata, "st_file_attributes", 0)) & 0x400
            or metadata.st_nlink != 1
        ):
            size = None
        else:
            size = metadata.st_size
    except OSError:
        size = None
    if settled:
        status = "settled"
    elif present:
        status = "present-unsettled"
    else:
        status = "missing"
    return {
        "status": status,
        "bytes": size if isinstance(size, int) and size >= 0 else None,
    }


def _trace_export_budget_receipt(
    trace_flush: dict[str, Any], exportable_events: int | None = None
) -> dict[str, Any]:
    source_bytes = trace_flush.get("bytes")
    bytes_within_budget = (
        source_bytes <= MAX_OBSERVATION_TRACE_EXPORT_BYTES
        if isinstance(source_bytes, int)
        else None
    )
    events_within_budget = (
        exportable_events <= MAX_OBSERVATION_TRACE_EXPORT_EVENTS
        if isinstance(exportable_events, int)
        else None
    )
    checks = (bytes_within_budget, events_within_budget)
    within_budget = (
        False
        if False in checks
        else (True if all(check is True for check in checks) else None)
    )
    return {
        "max_source_bytes": MAX_OBSERVATION_TRACE_EXPORT_BYTES,
        "source_bytes": source_bytes if isinstance(source_bytes, int) else None,
        "bytes_within_budget": bytes_within_budget,
        "max_exportable_events": MAX_OBSERVATION_TRACE_EXPORT_EVENTS,
        "exportable_events": exportable_events,
        "events_within_budget": events_within_budget,
        "within_budget": within_budget,
        "policy": "skip-automatic-normalization-above-budget",
    }


def _stop_observation_session(path: Path, timeout_seconds: float) -> dict[str, Any]:
    """Stop a trace-producing browser without the generic five-second cutoff."""
    return stop_session(
        path,
        timeout_seconds=timeout_seconds,
        graceful_timeout_seconds=TRACE_GRACEFUL_STOP_TIMEOUT,
    )


def _validated_observation_stop_receipt(
    value: Any,
    *,
    expected_run_id: str,
) -> dict[str, Any]:
    try:
        return validate_stopped_session_receipt(
            value,
            expected_run_id=expected_run_id,
        )
    except ContractError:
        raise ContractError("observation session stop was not verified") from None


def _merged_harvest(harvests: list[dict[str, Any]]) -> dict[str, Any]:
    from .argument_capture import merge_harvests

    return merge_harvests(harvests)


def _resolve_provenance(
    config: "ProductScriptObservation", script_payload: bytes | None = None
) -> dict[str, Any]:
    """Record what is verifiable about the sample's origin, at capture time.

    Three states, deliberately distinguished. ``not_checked`` means no capture
    tree was supplied, so nothing was looked at; it must not read like a clean
    bill of health. ``VERIFIED`` means a capture manifest records these exact
    bytes fetched from a named host. ``UNVERIFIED`` means a tree was searched and
    nothing in it accounts for these bytes.

    Failure to resolve is reported, never raised: provenance is metadata about an
    observation and must not be able to fail the observation itself.
    """
    if config.captures_root is None:
        return {
            "status": "not_checked",
            "note": (
                "no captures_root supplied; the label is operator-asserted and "
                "nothing was consulted to confirm it"
            ),
            "asserted_label": config.label,
        }
    try:
        from .script_provenance import describe_provenance

        described = describe_provenance(
            config.script,
            config.captures_root,
            asserted_label=config.label,
            payload=script_payload,
        )
    except Exception as exc:  # noqa: BLE001 - never fail a run over metadata
        return {
            "status": "error",
            "note": _failure_receipt("provenance lookup failed", exc),
            "asserted_label": config.label,
        }
    return {
        "status": described["verdict"],
        "recorded_hosts": described["recorded_hosts"],
        "recorded_sites": described["recorded_sites"],
        "directory_disagrees_with_manifest": described[
            "directory_disagrees_with_manifest"
        ],
        "asserted_label": config.label,
        "asserted_label_is_unverified": True,
        "captures_with_manifest": described["captures_with_manifest"],
        "captures_without_manifest": described["captures_without_manifest"],
    }


def grade_public_source_provenance(
    config: "ProductScriptObservation", payload: bytes
) -> dict[str, Any]:
    """Verify a URL/retrieval/digest pin for a public collector artifact.

    Capture manifests and public vendor URLs are different provenance channels.
    The former can resolve a sample back into a local capture tree; the latter
    needs an exact URL, a timezone-aware retrieval time, and a full digest. A
    partial declaration is refused because it would look more authoritative than
    ``not_supplied`` without being independently reproducible.
    """
    if not all(
        hasattr(config, name)
        for name in ("source_url", "source_retrieved_at", "source_sha256")
    ):
        raise ContractError("public source provenance config is invalid")
    supplied = (
        getattr(config, "source_url", None),
        getattr(config, "source_retrieved_at", None),
        getattr(config, "source_sha256", None),
    )
    if all(value is None for value in supplied):
        return {
            "status": "not_supplied",
            "note": "no public source URL pin was supplied",
        }
    if any(value is None for value in supplied):
        raise ContractError(
            "source_url, source_retrieved_at, and source_sha256 must be supplied together"
        )

    if (
        not isinstance(supplied[0], str)
        or not isinstance(supplied[1], str)
        or not isinstance(supplied[2], str)
        or not isinstance(payload, bytes)
        or len(payload) > MAX_PRODUCT_SCRIPT_BYTES
    ):
        raise ContractError("public source provenance inputs have invalid types")
    source_url = supplied[0]
    source_shape = _project_public_url_shape(source_url)
    if source_shape is None or source_shape["fragment_present"]:
        raise ContractError(
            "public source URL must be absolute, credential-free HTTP(S) without "
            "a fragment"
        )

    retrieved_at = supplied[1]
    # .NET's round-trip (``o``) format emits seven fractional digits because it
    # preserves 100 ns ticks.  Python 3.10's ``datetime.fromisoformat`` accepts
    # at most microseconds, even though the value is otherwise valid ISO 8601.
    # Drop only precision that ``datetime`` cannot represent; do not weaken the
    # timezone requirement or accept non-ISO shapes.
    parse_retrieved_at = retrieved_at
    fraction = re.search(
        r"(?<=T[0-9]{2}:[0-9]{2}:[0-9]{2}\.)([0-9]{7,})(?=Z|[+-][0-9]{2}:[0-9]{2}$)",
        retrieved_at,
    )
    if fraction is not None:
        parse_retrieved_at = (
            retrieved_at[: fraction.start()]
            + fraction.group(1)[:6]
            + retrieved_at[fraction.end() :]
        )
    try:
        stamp = datetime.fromisoformat(parse_retrieved_at.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ContractError("public source retrieval time must be ISO 8601") from exc
    if stamp.tzinfo is None or stamp.utcoffset() is None:
        raise ContractError("public source retrieval time must include a UTC offset")

    expected = supplied[2].lower()
    if re.fullmatch(r"[0-9a-f]{64}", expected) is None:
        raise ContractError("public source SHA-256 must be 64 hexadecimal characters")
    actual = hashlib.sha256(payload).hexdigest()
    if actual != expected:
        raise ContractError(
            f"public source SHA-256 mismatch: expected {expected}, observed {actual}"
        )
    return {
        "status": "verified_digest",
        "source_url": source_url,
        "retrieved_at": stamp.isoformat().replace("+00:00", "Z"),
        "sha256": actual,
        "note": "the supplied full digest matches the exact bytes observed",
    }


@dataclass(frozen=True)
class _GitProvenanceResult:
    returncode: int
    stdout: str


def _git_command(
    checkout: Path,
    *arguments: str,
    maximum_stdout: int = MAX_GIT_PROVENANCE_OUTPUT_BYTES,
) -> _GitProvenanceResult:
    """Run one bounded, non-interactive Git provenance query."""
    if not isinstance(checkout, Path) or not 1 <= len(arguments) <= 32:
        raise ContractError("Git provenance query is invalid")
    for item in arguments:
        if not isinstance(item, str) or not item or "\0" in item:
            raise ContractError("Git provenance query is invalid")
        try:
            payload = item.encode("utf-8", errors="strict")
        except UnicodeEncodeError:
            raise ContractError("Git provenance query is invalid") from None
        if len(payload) > 4096:
            raise ContractError("Git provenance query is invalid")
    selected_git = select_git_executable(excluded_checkout=checkout)
    result = run_with_bounded_stdout(
        [
            str(selected_git), "--no-optional-locks", "-c", "core.fsmonitor=false",
            "-c", "core.untrackedCache=false", "-C", str(checkout), *arguments,
        ],
        maximum_stdout=maximum_stdout,
        timeout_seconds=10.0,
        label="Git provenance query",
        environment=isolated_git_environment(),
    )
    try:
        stdout = result.stdout.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        raise ContractError("Git provenance output encoding is invalid") from None
    return _GitProvenanceResult(result.returncode, stdout)


def _require_git_output(
    checkout: Path,
    *arguments: str,
    purpose: str,
    maximum_stdout: int = MAX_GIT_PROVENANCE_OUTPUT_BYTES,
) -> str:
    result = _git_command(
        checkout,
        *arguments,
        maximum_stdout=maximum_stdout,
    )
    if result.returncode != 0:
        raise ContractError(f"Git provenance could not verify {purpose}")
    return result.stdout.strip()


def _git_z_records(
    checkout: Path, *arguments: str, purpose: str,
) -> tuple[bytes, ...]:
    """Read a bounded NUL-delimited Git inventory without path quoting."""
    result = _git_command(
        checkout, *arguments, maximum_stdout=MAX_GIT_PROVENANCE_OUTPUT_BYTES
    )
    if result.returncode != 0:
        raise ContractError(f"Git provenance could not verify {purpose}")
    body = result.stdout.encode("utf-8", errors="strict")
    if not body or not body.endswith(b"\0"):
        raise ContractError(f"Git provenance {purpose} inventory is invalid")
    records = tuple(body[:-1].split(b"\0"))
    if len(records) > MAX_GIT_PROVENANCE_TRACKED_FILES or any(not record for record in records):
        raise ContractError("Git provenance tracked inventory exceeds its limits")
    return records


def _parse_git_tracked_inventory(
    records: tuple[bytes, ...], *, index: bool,
) -> dict[tuple[str, ...], tuple[str, str]]:
    entries: dict[tuple[str, ...], tuple[str, str]] = {}
    folded: set[tuple[str, ...]] = set()
    pattern = (
        rb"(100644|100755|120000) ([0-9a-f]{40}) 0"
        if index else rb"(100644|100755|120000) blob ([0-9a-f]{40})"
    )
    for record in records:
        header, separator, raw_path = record.partition(b"\t")
        match = re.fullmatch(pattern, header)
        if not separator or match is None:
            raise ContractError("Git provenance tracked inventory is invalid")
        parts = decode_portable_git_path(raw_path)
        if any(part.casefold() == ".git" for part in parts):
            raise ContractError("Git provenance tracked path is invalid")
        key = tuple(part.casefold() for part in parts)
        if key in folded:
            raise ContractError("Git provenance tracked paths collide")
        folded.add(key)
        entries[parts] = (match.group(1).decode("ascii"), match.group(2).decode("ascii"))
    return entries


def _git_config_value(checkout: Path, name: str) -> str | None:
    result = _git_command(checkout, "config", "--get", name, maximum_stdout=128)
    if result.returncode == 1 and not result.stdout:
        return None
    if result.returncode != 0:
        raise ContractError("Git provenance could not verify checkout settings")
    value = result.stdout.strip().lower()
    if "\n" in value or "\r" in value:
        raise ContractError("Git provenance checkout setting is invalid")
    return value


def _git_raw_origin_url(checkout: Path, *, label: str) -> str:
    """Require one unexpanded origin URL, including across Git config includes."""
    result = _git_command(
        checkout, "config", "--null", "--get-all", "remote.origin.url",
        maximum_stdout=4096,
    )
    if (
        result.returncode != 0
        or not result.stdout.endswith("\0")
        or result.stdout.count("\0") != 1
        or not result.stdout[:-1]
    ):
        raise ContractError(f"{label} repository URL is missing or ambiguous")
    return result.stdout[:-1]


def _git_tracked_attributes(
    checkout: Path, paths: tuple[tuple[str, ...], ...], *, started: float,
) -> dict[tuple[str, ...], tuple[str, str, str]]:
    """Inspect cached attributes in bounded batches, without running filters."""
    result: dict[tuple[str, ...], tuple[str, str, str]] = {}
    for offset in range(0, len(paths), 24):
        if time.monotonic() - started > MAX_GIT_PROVENANCE_SCAN_SECONDS:
            raise ContractError("Git provenance tracked scan exceeded its time limit")
        batch = paths[offset : offset + 24]
        rendered = tuple("/".join(parts) for parts in batch)
        response = _git_command(
            checkout, "check-attr", "--cached", "-z", "filter", "text", "eol",
            "--", *rendered,
            maximum_stdout=MAX_GIT_PROVENANCE_OUTPUT_BYTES,
        )
        if response.returncode != 0:
            raise ContractError("Git provenance could not verify tracked attributes")
        fields = response.stdout.split("\0")
        if len(fields) != len(batch) * 9 + 1 or fields[-1] != "":
            raise ContractError("Git provenance tracked attributes are invalid")
        for index, parts in enumerate(batch):
            values: list[str] = []
            for step, name in enumerate(("filter", "text", "eol")):
                position = index * 9 + step * 3
                if fields[position] != rendered[index] or fields[position + 1] != name:
                    raise ContractError("Git provenance tracked attributes are invalid")
                values.append(fields[position + 2])
            # Git reports both `-filter` and `filter=unset` as `unset` here.
            # The latter may name a configured clean driver, so reject both.
            if values[0] != "unspecified":
                raise ContractError("Git provenance tracked clean filter is unsupported")
            result[parts] = (values[0], values[1], values[2])
    return result


def _verify_git_tracked_checkout(
    checkout: Path,
) -> tuple[Any, ...]:
    """Match HEAD, index, and literal worktree bytes without running clean filters."""
    started = time.monotonic()
    root_binding = directory_ancestry_binding(
        checkout, label="Git provenance checkout"
    )
    tree = _parse_git_tracked_inventory(
        _git_z_records(
            checkout, "ls-tree", "-r", "-z", "--full-tree", "HEAD",
            purpose="HEAD tree",
        ),
        index=False,
    )
    staged = _parse_git_tracked_inventory(
        _git_z_records(checkout, "ls-files", "--stage", "-z", purpose="index"),
        index=True,
    )
    if tree != staged:
        raise ContractError("Git provenance requires a clean tracked worktree")
    autocrlf = _git_config_value(checkout, "core.autocrlf")
    symlinks = _git_config_value(checkout, "core.symlinks")
    if autocrlf not in (None, "false", "true", "input") or symlinks not in (
        None, "false", "true",
    ):
        raise ContractError("Git provenance checkout setting is invalid")
    attributes = _git_tracked_attributes(
        checkout, tuple(tree), started=started,
    )
    total = 0
    for parts, (mode, oid) in tree.items():
        if time.monotonic() - started > MAX_GIT_PROVENANCE_SCAN_SECONDS:
            raise ContractError("Git provenance tracked scan exceeded its time limit")
        if mode == "120000" and symlinks != "false":
            raise ContractError("Git provenance tracked symlink cannot be verified")
        path = checkout.joinpath(*parts)
        parent_binding = directory_ancestry_binding(
            path.parent, label="Git provenance tracked parent"
        )
        snapshot = read_bounded_control_snapshot_result(
            path,
            maximum=min(
                MAX_GIT_PROVENANCE_TRACKED_FILE_BYTES,
                MAX_GIT_PROVENANCE_TRACKED_BYTES - total,
            ),
            label="Git provenance tracked file",
            require_single_link=True,
        )
        if snapshot.state != "complete" or snapshot.body is None:
            raise ContractError("Git provenance requires a clean tracked worktree")
        if (
            os.name != "nt"
            and mode != "120000"
            and (
                snapshot.identity is None
                or bool(snapshot.identity[2] & 0o111) != (mode == "100755")
            )
        ):
            raise ContractError("Git provenance requires a clean tracked worktree")
        body = snapshot.body
        total += len(body)
        if total > MAX_GIT_PROVENANCE_TRACKED_BYTES:
            raise ContractError("Git provenance tracked bytes exceed the limit")
        if directory_ancestry_binding(
            path.parent, label="Git provenance tracked parent"
        ) != parent_binding:
            raise ContractError("Git provenance tracked parent changed")
        observed = git_blob_sha1(body)
        if (
            observed != oid
            and (autocrlf == "true" or attributes[parts][2] == "crlf")
            and mode != "120000"
            and b"\0" not in body
            and attributes[parts][1] in ("unspecified", "set", "auto")
            and attributes[parts][2] in ("unspecified", "crlf")
        ):
            observed = git_blob_sha1(body.replace(b"\r\n", b"\n"))
        if observed != oid:
            raise ContractError("Git provenance requires a clean tracked worktree")
    if (
        time.monotonic() - started > MAX_GIT_PROVENANCE_SCAN_SECONDS
        or directory_ancestry_binding(
            checkout, label="Git provenance checkout"
        ) != root_binding
    ):
        raise ContractError("Git provenance tracked checkout changed during scan")
    return (
        tuple(sorted(tree.items())),
        autocrlf,
        symlinks,
        tuple(sorted(attributes.items())),
    )


def _resolve_git_provenance_path(path: Path, *, label: str) -> Path:
    try:
        return path.resolve()
    except (OSError, ValueError, RuntimeError) as exc:
        raise ContractError(f"{label} path is invalid") from exc


def _require_distinct_artifact_files(source: Path, rebuild: Path) -> None:
    try:
        same_file = source.samefile(rebuild)
    except OSError as exc:
        raise ContractError(
            "Could not verify that source and rebuild artifacts are physically distinct"
        ) from exc
    if same_file:
        raise ContractError(
            "Source and rebuild artifacts must be physically distinct files"
        )


def grade_git_source_provenance(
    config: "ProductScriptObservation", payload: bytes
) -> dict[str, Any]:
    """Bind a generated artifact to verified public Git inputs and its digest.

    This grade intentionally does *not* infer build execution. A clean checkout
    verifies tracked inputs; an ignored output remains local bytes whose full
    digest is bound into the arm. An optional second checkout can prove only a
    distinct byte-identical artifact, not how that artifact was produced.
    """
    fields = (
        getattr(config, "source_git_checkout", None),
        getattr(config, "source_git_repository_url", None),
        getattr(config, "source_git_revision", None),
        getattr(config, "source_build_recipe", None),
        getattr(config, "source_sha256", None),
    )
    if any(value is None for value in fields):
        raise ContractError(
            "source_git_checkout, source_git_repository_url, source_git_revision, "
            "source_build_recipe, and source_sha256 must be supplied together"
        )
    if (
        not isinstance(payload, bytes)
        or len(payload) > MAX_PRODUCT_SCRIPT_BYTES
        or not isinstance(getattr(config, "script", None), Path)
        or not isinstance(fields[0], Path)
        or not isinstance(fields[1], str)
        or not isinstance(fields[2], str)
        or not isinstance(fields[3], Path)
        or not isinstance(fields[4], str)
    ):
        raise ContractError("Git provenance inputs have invalid types")
    script_path = _resolve_git_provenance_path(
        config.script, label="Git provenance artifact"
    )
    source_bytes = _read_stable_regular_bytes(
        script_path,
        maximum=MAX_PRODUCT_SCRIPT_BYTES,
        label="Git provenance artifact",
    )
    if source_bytes != payload:
        raise ContractError("Git provenance artifact changed before verification")

    checkout = _resolve_git_provenance_path(
        fields[0], label="Git provenance checkout"
    )
    checkout_identity = directory_identity(checkout, label="Git provenance checkout")
    if checkout_identity is None:
        raise ContractError("Git provenance checkout must be an existing directory")
    top = _resolve_git_provenance_path(
        Path(
            _require_git_output(
                checkout,
                "rev-parse",
                "--show-toplevel",
                purpose="checkout root",
                maximum_stdout=32 * 1024,
            )
        ),
        label="Git provenance checkout root",
    )
    if top != checkout:
        raise ContractError("Git provenance checkout must name the repository root")

    repository_url = fields[1]
    repository_shape = _project_public_url_shape(repository_url)
    # Project first: unlike a bare ``urlsplit``, the projector contains malformed
    # IPv6/port and Unicode failures and therefore keeps this verifier's API in
    # the ContractError domain.  Query/fragment absence remains an exact Git
    # remote requirement rather than an inference from the redacted shape.
    if repository_shape is None:
        parsed = None
    else:
        parsed = urlsplit(repository_url)
    if (
        parsed is None
        or parsed.fragment
        or parsed.query
        or any(marker in repository_url for marker in "?#")
        or parsed.scheme not in {"http", "https"}
    ):
        raise ContractError(
            "Git provenance repository URL must be public, credential-free HTTP(S) "
            "without a query or fragment"
        )
    raw_remote = _git_raw_origin_url(checkout, label="Git provenance")
    remote = _require_git_output(
        checkout,
        "remote",
        "get-url",
        "origin",
        purpose="origin remote",
        maximum_stdout=4096,
    )
    if (
        raw_remote != repository_url
        or remote != repository_url
    ):
        raise ContractError("Git provenance repository URL does not match origin")

    revision = fields[2].lower()
    if re.fullmatch(r"[0-9a-f]{40}", revision) is None:
        raise ContractError(
            "Git provenance revision must be a full 40-character commit"
        )
    head = _require_git_output(
        checkout,
        "rev-parse",
        "HEAD",
        purpose="HEAD revision",
        maximum_stdout=128,
    )
    if head.lower() != revision:
        raise ContractError(
            f"Git provenance revision mismatch: expected {revision}, observed {head.lower()}"
        )
    tracked_snapshot = _verify_git_tracked_checkout(checkout)
    tracked_paths = {parts for parts, _ in tracked_snapshot[0]}

    recipe = _resolve_git_provenance_path(
        fields[3], label="Git provenance build recipe"
    )
    try:
        artifact_relative = script_path.relative_to(checkout).as_posix()
        recipe_relative = recipe.relative_to(checkout).as_posix()
    except ValueError as exc:
        raise ContractError(
            "Git provenance artifact and build recipe must be inside the checkout"
        ) from exc
    if (
        _safe_repository_relative_path(artifact_relative) is None
        or _safe_repository_relative_path(recipe_relative) is None
    ):
        raise ContractError("Git provenance repository-relative path is invalid")
    recipe_bytes = _read_stable_regular_bytes(
        recipe,
        maximum=MAX_BUILD_RECIPE_BYTES,
        label="Git provenance build recipe",
    )
    recipe_parts = tuple(recipe_relative.split("/"))
    if recipe_parts not in tracked_paths:
        raise ContractError(
            "Git provenance build recipe must be tracked at the revision"
        )

    artifact_tracked = tuple(artifact_relative.split("/")) in tracked_paths
    if artifact_tracked:
        artifact_state = "tracked"
    else:
        ignore_result = _git_command(
            checkout, "check-ignore", "-q", "--", artifact_relative
        )
        if ignore_result.returncode not in (0, 1):
            raise ContractError("Git provenance could not verify artifact ignore state")
        artifact_state = (
            "ignored-generated" if ignore_result.returncode == 0 else "untracked"
        )

    expected = fields[4].lower()
    if re.fullmatch(r"[0-9a-f]{64}", expected) is None:
        raise ContractError(
            "Git provenance artifact SHA-256 must be 64 hexadecimal characters"
        )
    actual = hashlib.sha256(payload).hexdigest()
    if actual != expected:
        raise ContractError(
            f"Git provenance artifact SHA-256 mismatch: expected {expected}, observed {actual}"
        )
    recipe_digest = hashlib.sha256(recipe_bytes).hexdigest()
    rebuild_checkout_value = getattr(config, "source_rebuild_checkout", None)
    rebuild_artifact_value = getattr(config, "source_rebuild_artifact", None)
    if (rebuild_checkout_value is None) != (rebuild_artifact_value is None):
        raise ContractError(
            "source_rebuild_checkout and source_rebuild_artifact must be supplied together"
        )
    distinct_checkout_match = False
    rebuild_digest: str | None = None
    rebuild_state: dict[str, Any] | None = None
    if rebuild_checkout_value is not None and rebuild_artifact_value is not None:
        if not isinstance(rebuild_checkout_value, Path) or not isinstance(
            rebuild_artifact_value, Path
        ):
            raise ContractError("rebuild-artifact paths must be Paths")
        rebuild_checkout = _resolve_git_provenance_path(
            rebuild_checkout_value, label="rebuild-artifact checkout"
        )
        rebuild_checkout_identity = directory_identity(
            rebuild_checkout,
            label="rebuild-artifact checkout",
        )
        if rebuild_checkout_identity is None or rebuild_checkout == checkout:
            raise ContractError(
                "rebuild-artifact checkout must be an existing, distinct directory"
            )
        rebuild_top = _resolve_git_provenance_path(
            Path(
                _require_git_output(
                    rebuild_checkout,
                    "rev-parse",
                    "--show-toplevel",
                    purpose="rebuild-artifact checkout root",
                    maximum_stdout=32 * 1024,
                )
            ),
            label="rebuild-artifact checkout root",
        )
        if rebuild_top != rebuild_checkout:
            raise ContractError(
                "rebuild-artifact checkout must name the repository root"
            )
        rebuild_raw_remote = _git_raw_origin_url(
            rebuild_checkout, label="rebuild-artifact",
        )
        rebuild_remote = _require_git_output(
            rebuild_checkout,
            "remote",
            "get-url",
            "origin",
            purpose="rebuild-artifact origin remote",
            maximum_stdout=4096,
        )
        if (
            rebuild_raw_remote != repository_url
            or rebuild_remote != repository_url
        ):
            raise ContractError("rebuild-artifact repository URL does not match origin")
        rebuild_head = _require_git_output(
            rebuild_checkout,
            "rev-parse",
            "HEAD",
            purpose="rebuild-artifact HEAD revision",
            maximum_stdout=128,
        )
        if rebuild_head.lower() != revision:
            raise ContractError(
                "rebuild-artifact revision does not match source revision"
            )
        try:
            rebuild_snapshot = _verify_git_tracked_checkout(rebuild_checkout)
        except ContractError as exc:
            raise ContractError(
                "rebuild-artifact match requires a clean tracked worktree"
            ) from exc
        rebuild_artifact = _resolve_git_provenance_path(
            rebuild_artifact_value, label="rebuild artifact"
        )
        try:
            rebuild_relative = rebuild_artifact.relative_to(rebuild_checkout).as_posix()
        except ValueError as exc:
            raise ContractError("rebuild artifact must be inside its checkout") from exc
        if rebuild_relative != artifact_relative:
            raise ContractError(
                "rebuild artifact must have the same repository-relative path"
            )
        rebuild_artifact_bytes = _read_stable_regular_bytes(
            rebuild_artifact,
            maximum=MAX_PRODUCT_SCRIPT_BYTES,
            label="rebuild artifact",
        )
        _require_distinct_artifact_files(script_path, rebuild_artifact)
        rebuild_recipe = rebuild_checkout / recipe_relative
        rebuild_recipe_bytes = _read_stable_regular_bytes(
            rebuild_recipe,
            maximum=MAX_BUILD_RECIPE_BYTES,
            label="rebuild-checkout recipe",
        )
        rebuild_tracked_paths = {parts for parts, _ in rebuild_snapshot[0]}
        if (
            recipe_parts not in rebuild_tracked_paths
            or hashlib.sha256(rebuild_recipe_bytes).hexdigest() != recipe_digest
        ):
            raise ContractError(
                "rebuild-checkout recipe does not match the tracked source recipe"
            )
        rebuild_digest = hashlib.sha256(rebuild_artifact_bytes).hexdigest()
        if rebuild_digest != actual:
            raise ContractError(
                "rebuild artifact does not match the observed artifact digest"
            )
        distinct_checkout_match = True
        rebuild_state = {
            "checkout": rebuild_checkout,
            "checkout_identity": rebuild_checkout_identity,
            "recipe": rebuild_recipe,
            "recipe_bytes": rebuild_recipe_bytes,
            "artifact": rebuild_artifact,
            "artifact_bytes": rebuild_artifact_bytes,
            "head": rebuild_head,
            "tracked_snapshot": rebuild_snapshot,
        }

    if (
        directory_identity(checkout, label="Git provenance checkout")
        != checkout_identity
        or _read_stable_regular_bytes(
            script_path,
            maximum=MAX_PRODUCT_SCRIPT_BYTES,
            label="Git provenance artifact",
        )
        != source_bytes
        or _read_stable_regular_bytes(
            recipe,
            maximum=MAX_BUILD_RECIPE_BYTES,
            label="Git provenance build recipe",
        )
        != recipe_bytes
        or _git_raw_origin_url(checkout, label="Git provenance") != raw_remote
        or _require_git_output(
            checkout,
            "remote",
            "get-url",
            "origin",
            purpose="origin remote",
            maximum_stdout=4096,
        )
        != remote
        or _require_git_output(
            checkout,
            "rev-parse",
            "HEAD",
            purpose="HEAD revision",
            maximum_stdout=128,
        )
        != head
        or _verify_git_tracked_checkout(checkout) != tracked_snapshot
    ):
        raise ContractError("Git provenance inputs changed during verification")
    if rebuild_state is not None:
        _require_distinct_artifact_files(script_path, rebuild_state["artifact"])
        if (
            directory_identity(
                rebuild_state["checkout"],
                label="rebuild-artifact checkout",
            )
            != rebuild_state["checkout_identity"]
            or _read_stable_regular_bytes(
                rebuild_state["recipe"],
                maximum=MAX_BUILD_RECIPE_BYTES,
                label="rebuild-checkout recipe",
            )
            != rebuild_state["recipe_bytes"]
            or _read_stable_regular_bytes(
                rebuild_state["artifact"],
                maximum=MAX_PRODUCT_SCRIPT_BYTES,
                label="rebuild artifact",
            )
            != rebuild_state["artifact_bytes"]
            or _git_raw_origin_url(
                rebuild_state["checkout"], label="rebuild-artifact",
            ) != rebuild_raw_remote
            or _require_git_output(
                rebuild_state["checkout"],
                "remote",
                "get-url",
                "origin",
                purpose="rebuild-artifact origin remote",
                maximum_stdout=4096,
            )
            != rebuild_remote
            or _require_git_output(
                rebuild_state["checkout"],
                "rev-parse",
                "HEAD",
                purpose="rebuild-artifact HEAD revision",
                maximum_stdout=128,
            )
            != rebuild_state["head"]
            or _verify_git_tracked_checkout(rebuild_state["checkout"])
            != rebuild_state["tracked_snapshot"]
        ):
            raise ContractError("rebuild-artifact inputs changed during verification")

    verdict = {
        "status": "verified_git_inputs_artifact_digest",
        "repository_url": repository_url,
        "revision": revision,
        "sha256": actual,
        "artifact_relative_path": artifact_relative,
        "artifact_git_state": artifact_state,
        "build_recipe_relative_path": recipe_relative,
        "build_recipe_sha256": recipe_digest,
        "tracked_worktree_clean": True,
        "distinct_checkout_artifact_verified": distinct_checkout_match,
        "note": (
            "public Git inputs and the tracked build recipe were verified at the "
            "exact revision; the full digest matches both the observed artifact "
            "and an artifact from a distinct matching checkout; the verifier did "
            "not execute the build"
            if distinct_checkout_match
            else "public Git inputs and the tracked build recipe were verified at "
            "the exact revision; the full digest matches the observed artifact; "
            "no distinct-checkout artifact was supplied"
        ),
    }
    if rebuild_digest is not None:
        verdict["rebuild_artifact_sha256"] = rebuild_digest
    return verdict


def grade_script_source_provenance(
    config: "ProductScriptObservation", payload: bytes
) -> dict[str, Any]:
    """Select exactly one public URL or Git-input provenance channel."""
    public_supplied = any(
        getattr(config, name, None) is not None
        for name in ("source_url", "source_retrieved_at")
    )
    git_supplied = any(
        getattr(config, name, None) is not None
        for name in (
            "source_git_checkout",
            "source_git_repository_url",
            "source_git_revision",
            "source_build_recipe",
            "source_rebuild_checkout",
            "source_rebuild_artifact",
        )
    )
    if public_supplied and git_supplied:
        raise ContractError(
            "public URL and Git-input source provenance are mutually exclusive"
        )
    if git_supplied:
        return grade_git_source_provenance(config, payload)
    return grade_public_source_provenance(config, payload)


# ---------------------------------------------------------------- identity guard


def _classifier_reasons(signals: dict[str, Any]) -> list[str]:
    """Derive the closed structural verdict from one retained signal table."""

    geetest_loader_shape = (
        8_000 <= signals["bytes"] < 50_000 and signals["geetest_loader_markers"] == 6
    )
    anubis_challenge_shape = (
        7_000 <= signals["bytes"] < 50_000
        and signals["anubis_challenge_markers"] == 6
    )
    compact_product_entry = geetest_loader_shape or anubis_challenge_shape
    reasons: list[str] = []
    if signals["bytes"] < 50_000 and not compact_product_entry:
        reasons.append("smaller than any observed built anti-bot script")
    if signals["max_line_bytes"] < 50_000 and not compact_product_entry:
        reasons.append("no single machine-generated line")
    if signals["arrow_functions"] > 100:
        reasons.append("arrow functions present at application-bundle density")
    if signals["bundler_markers"] > 0:
        reasons.append("module-bundler artifact, not a standalone collector")
    if len(_vendor_hint_candidates(signals)) > 1:
        reasons.append("multiple product vendor marker families")
    return reasons


def _max_physical_line_bytes(payload: bytes) -> int:
    """Measure raw source lines separated by CR or LF, not Unicode text breaks."""

    start = 0
    maximum = 0
    for ending in re.finditer(rb"\r\n?|\n", payload):
        maximum = max(maximum, ending.start() - start)
        start = ending.end()
    return max(maximum, len(payload) - start)


def classify_product_script(payload: bytes) -> dict[str, Any]:
    """Cheap structural check that a file is an obfuscated anti-bot script.

    A capture directory can contain a file named ``bm-script.js`` that is really an
    ordinary application bundle -- this monorepo has already lost measurements to a
    picker that chose the wrong file. The discriminator does not depend on any
    vendor string for full collectors: a built anti-bot script is one enormous
    machine-generated line that did not come out of a module bundler. Small public
    bootstrap loaders are a separate shape. They pass only through a conjunction
    of specific runtime markers; one vendor word never overrides the guard.

    **The veto used to be a `function` keyword floor, and it was measuring the
    wrong thing.** A floor of 200 encodes one obfuscator's habits: Akamai's web pin
    carries 1,020 `function` keywords, so it passed, and every Kasada script in
    this monorepo's corpus was rejected -- 8 of 8 across two capture directories --
    because Kasada's obfuscator renames nearly every binding uniquely instead of
    reusing a short alphabet. Measured over a 75-file corpus containing one real
    page's whole script set: Kasada's collectors hold 76-159 `function` keywords
    against a 0.51-0.63 distinct-identifier ratio, while Akamai's holds 1,020
    against 0.059. Both are built collectors. The keyword count separates
    *obfuscation styles*, not collectors from applications, and a vendor whose
    style differs is invisible rather than misread -- the worse failure, because
    nothing looks wrong.

    The replacement is a bundler-artifact veto. Every application bundle in that
    corpus -- Next.js chunks, Stripe's v3.js, third-party SDKs -- carries a module
    system marker, and no collector does; a collector ships standalone because it
    must run before the application does. Swapping the vetoes recovered 7 true
    positives and removed 17 false ones, including Stripe's payment SDK, which the
    keyword floor had been calling an anti-bot collector on the strength of its
    5,245 `function` keywords.
    """
    if not isinstance(payload, bytes) or len(payload) > MAX_PRODUCT_SCRIPT_BYTES:
        raise ContractError("product script payload must be bounded bytes")
    text = payload.decode("utf-8", errors="replace")
    newlines = text.count("\n")
    identifiers = _IDENTIFIER_RE.findall(text)
    distinct_identifiers = len(set(identifiers))
    signals = {
        "bytes": len(payload),
        "sha256_16": hashlib.sha256(payload).hexdigest()[:16],
        "lines": newlines + 1,
        "arrow_functions": text.count("=>"),
        "string_literals": text.count("'"),
        "bmak_literals": text.count("bmak"),
        "kpsdk_literals": sum(text.count(token) for token in ("kpsdk", "KPSDK")),
        # Shape's inline deployment opens with `window['istlWasHere'] = true;`.
        # Found in 4 of 4 Shape captures here and 0 files under akamai-web or
        # kasada -- but all four are Nordstrom-family, so it may be a
        # per-deployment marker rather than a vendor-wide one. That is exactly why
        # a hint is never used alone: absence rejects nothing.
        "istl_literals": text.count("istlWasHere"),
        # PerimeterX names its per-tenant app id inline. 8 occurrences in
        # px.main.min.js and 0 in the Akamai, Kasada and Shape collectors here.
        "px_literals": text.count("_pxAppId"),
        # Public vendor pins measured 2026-08-09. These are hints only: they label
        # a positive structural verdict and never make a file pass the guard.
        "datadome_literals": sum(
            text.count(token)
            for token in ("dataDomeOptions", "dataDomeProcessed", "ddjskey")
        ),
        "turnstile_literals": sum(
            text.count(token) for token in ("[Cloudflare Turnstile]", "TurnstileError")
        ),
        # Keep raw occurrences for continuity, but classify on distinct marker
        # presence. Repeating one product word is not a conjunction.
        "datadome_markers": sum(
            token in text
            for token in ("dataDomeOptions", "dataDomeProcessed", "ddjskey")
        ),
        "turnstile_markers": sum(
            token in text for token in ("[Cloudflare Turnstile]", "TurnstileError")
        ),
        # Imperva APG's current Nordstrom loader (public pin 2026-08-10) ends by
        # injecting a deployment-specific ``/__imp_apg__/js/...`` stage.  Bind
        # the hint to all three loader-owned names so an application that merely
        # mentions the route cannot be labelled from one string.  As with every
        # vendor hint, this labels a structural pass and never makes one pass.
        "imperva_apg_markers": sum(
            token in text
            for token in ("/__imp_apg__/js/", "_imp_apg_dip_", "_imp_apg_cid_")
        ),
        # GeeTest's official GT4 bootstrap is a readable 15.9 KiB loader, not the
        # later challenge implementation. It is therefore intentionally outside
        # the >=50 KiB/single-generated-line full-collector shape. Require all six
        # independently useful loader markers before granting that narrow shape;
        # a lone vendor name remains only a hint.
        "geetest_loader_markers": sum(
            token in text
            for token in (
                "Geetest Inc.",
                "Geetest requires browser environment",
                "initGeetest4",
                "gcaptcha4",
                "static.geetest.com",
                "captchaId",
            )
        ),
        # Anubis's tagged esbuild output is another compact standalone entry.
        # These markers span boot state, challenge input, worker selection,
        # product-owned routing, and the final branch; require the complete set.
        "anubis_challenge_markers": sum(
            token in text
            for token in (
                "window.__anubisBooted",
                "anubis_challenge",
                "anubis: could not pre-fetch worker source",
                "anubis: main.mjs already running",
                "/.within.website/x/cmd/anubis/",
                "api/pass-challenge",
            )
        ),
        # The saved SBSD family exposes one exact five-part cluster spanning its
        # well-known route, request/response custom events, challenge label, and
        # overlay label. Across 1,440 stored JavaScript copies / 268 distinct
        # hashes containing the first event, all five markers co-occurred and all
        # passed the independent standalone-collector structural guard. Require
        # the complete conjunction so one ordinary route/event mention labels
        # nothing.
        "akamai_sbsd_markers": sum(
            token in text
            for token in (
                "/.well-known/sbsd",
                "ak_cpr_chlg_init",
                "ak_cpr_chlg_resp",
                "cpr_chlge",
                "sec-cpr-overlay",
            )
        ),
        "function_keywords": text.count("function"),
        "max_line_bytes": _max_physical_line_bytes(payload),
        "bundler_markers": sum(text.count(marker) for marker in BUNDLER_MARKERS),
        "source_map_markers": sum(text.count(marker) for marker in SOURCE_MAP_MARKERS),
        # High when an obfuscator renames every binding uniquely (Kasada, ~0.57),
        # low when it reuses a short alphabet (Akamai, ~0.06). Reported because it
        # explains the two collector shapes; not used as a veto, because both
        # extremes are collectors and application bundles sit across the range.
        "distinct_identifier_ratio": round(
            distinct_identifiers / max(len(identifiers), 1), 3
        ),
    }
    reasons = _classifier_reasons(signals)
    return {
        "schema": IDENTITY_SCHEMA,
        "signals": signals,
        "looks_like_built_antibot_script": not reasons,
        "reasons": reasons,
        # A positive vendor hint, never used alone: absence only means the
        # obfuscator did not leak the global name in this roll. Kasada leaks very
        # little -- `KPSDK` appears twice in a 542 KB script -- so the threshold is
        # 1, and the hint stays a hint.
        "vendor_hint": _vendor_hint(signals),
    }


#: Module-system markers. A collector ships standalone because it has to run
#: before the application it protects; a bundle cannot avoid leaving one of these.
#:
#: Each entry is a token a bundler *emits*, not a word a bundler is associated
#: with, and that distinction cost a false negative before it was made explicit.
#: The first version tested for bare ``webpack`` and bare ``require(``, and
#: rejected PerimeterX's ``px.main.min.js`` -- 233 KB and unmistakably a collector
#: -- because its stack-trace parser carries the regex
#: ``(?:file|https?|blob|chrome|webpack|\\[native)``. A collector that knows how to
#: read a webpack-scheme URL out of an error stack is not a webpack bundle, and a
#: substring test cannot tell the difference between emitting a token and merely
#: naming one.
#:
#: ``require(`` is gone for the same reason and worse: it is ordinary JavaScript.
BUNDLER_MARKERS = (
    "__webpack_require__",
    "webpackJsonp",
    "webpackChunk",
    "self.__next_f",
    "self.__next_s",
    'Object.defineProperty(exports, "__esModule"',
    "Object.defineProperty(exports,'__esModule'",
)

_IDENTIFIER_RE = re.compile(r"[A-Za-z_$][A-Za-z0-9_$]*")


def _vendor_hint_candidates(signals: dict[str, Any]) -> tuple[str, ...]:
    candidates: list[str] = []
    if signals["bmak_literals"] >= 20:
        candidates.append("akamai-bmp-web")
    # Pre-SBSD observations use the same identity schema without this later
    # signal. Treat the absent field as zero so their recorded hint can still be
    # reconciled from the vocabulary that existed when they were produced.
    if signals.get("akamai_sbsd_markers", 0) == 5:
        candidates.append("akamai-sbsd-web")
    if signals["kpsdk_literals"] >= 1:
        candidates.append("kasada")
    if signals["istl_literals"] >= 1:
        candidates.append("shape")
    if signals["px_literals"] >= 1:
        candidates.append("perimeterx")
    if (
        signals.get("datadome_markers") == 3
        if "datadome_markers" in signals
        else signals["datadome_literals"] >= 2
    ):
        candidates.append("datadome")
    if (
        signals.get("turnstile_markers") == 2
        if "turnstile_markers" in signals
        else signals["turnstile_literals"] >= 2
    ):
        candidates.append("cloudflare-turnstile")
    if signals["imperva_apg_markers"] == 3:
        candidates.append("imperva-apg-loader")
    if signals["geetest_loader_markers"] == 6:
        candidates.append("geetest-v4-loader")
    if signals["anubis_challenge_markers"] == 6:
        candidates.append("anubis-web-challenge")
    return tuple(candidates)


def _vendor_hint(signals: dict[str, Any]) -> str | None:
    candidates = _vendor_hint_candidates(signals)
    return candidates[0] if len(candidates) == 1 else None


def project_product_script_vendor_hint(value: Any) -> str | None:
    """Retain only a current classifier-owned, non-page-controlled hint."""

    if isinstance(value, str) and value in PRODUCT_SCRIPT_VENDOR_HINTS:
        return value
    return None


def _reconciled_subtraction_script_identity(
    document: dict[str, Any],
) -> dict[str, Any] | None:
    """Recheck a compact subtraction identity against its exact arm receipt."""

    identity = document.get("script_identity")
    pin = document.get("arm_script_sha256_16")
    if (
        document.get("script_identity_coherent") is not True
        or not isinstance(identity, dict)
        or set(identity)
        != {
            "schema",
            "sha256_16",
            "bytes",
            "looks_like_built_antibot_script",
            "vendor_hint",
        }
        or identity.get("schema") != IDENTITY_SCHEMA
        or not isinstance(pin, str)
        or re.fullmatch(r"[0-9a-fA-F]{16}", pin) is None
        or not isinstance(identity.get("sha256_16"), str)
        or re.fullmatch(r"[0-9a-f]{16}", identity["sha256_16"]) is None
        or identity["sha256_16"] != pin.lower()
        or not isinstance(identity.get("bytes"), int)
        or isinstance(identity.get("bytes"), bool)
        or not 0 <= identity["bytes"] <= MAX_PRODUCT_SCRIPT_BYTES
        or not isinstance(identity.get("looks_like_built_antibot_script"), bool)
    ):
        return None
    vendor_hint = identity.get("vendor_hint")
    if vendor_hint is not None and project_product_script_vendor_hint(vendor_hint) is None:
        return None
    return identity


def project_product_script_analysis_boundary(value: Any) -> dict[str, str] | None:
    """Return a closed interpretation warning for a classifier-owned hint.

    The Kasada second stage measured in this repository performs substantive work
    inside a bytecode interpreter. Generated-binding traces can see the host APIs
    crossed by that interpreter, but not the operations it performs internally.
    The GeeTest v4 entry is only a bootstrap for an absent challenge library,
    while the Turnstile outer script delegates challenge internals to a separate
    vendor-origin frame and the Imperva APG first stage injects a separately
    served script. The compact Anubis entry delegates proof work to a selected
    Worker.
    These are deliberately warnings derived from closed vendor hints, not new
    claims that an arm reached a VM or exercised an unstaged downstream script.
    """

    vendor_hint = project_product_script_vendor_hint(value)
    boundary = _PRODUCT_SCRIPT_ANALYSIS_BOUNDARIES.get(vendor_hint)
    return dict(boundary) if boundary is not None else None


def sanitize_product_script_analysis_boundary(value: Any) -> dict[str, str] | None:
    """Reconstruct the one closed boundary receipt from an edited artifact."""

    for boundary in _PRODUCT_SCRIPT_ANALYSIS_BOUNDARIES.values():
        if value == boundary:
            return dict(boundary)
    return None


# ---------------------------------------------------------------- local rehost


class _RequestLog:
    def __init__(self) -> None:
        self._lock = Lock()
        self.entries: list[dict[str, Any]] = []
        self.dropped_entries = 0

    def add(
        self,
        method: str,
        path: str,
        body_bytes: int,
        *,
        served: str = "page",
        request_target: str | None = None,
        body_sha256_16: str | None = None,
    ) -> None:
        raw_path = path if isinstance(path, str) else ""
        path_truncated = len(raw_path) > MAX_REHOST_LOG_PATH_CHARS
        stored_path = raw_path[:MAX_REHOST_LOG_PATH_CHARS]
        target_shape = (
            _request_path_shape(request_target)
            if isinstance(request_target, str)
            else None
        )
        query_receipt = (
            {
                "query_names": target_shape["query_names"],
                "query_names_truncated": target_shape["query_names_truncated"],
            }
            if target_shape is not None
            and (target_shape["query_names"] or target_shape["query_names_truncated"])
            else {}
        )
        if body_sha256_16 is not None and (
            method != "POST"
            or served != "post-ack"
            or re.fullmatch(r"[0-9a-fA-F]{16}", body_sha256_16) is None
        ):
            raise ContractError(
                "request-body digests are limited to complete loopback post-ack bodies"
            )
        with self._lock:
            if len(self.entries) >= MAX_REHOST_REQUEST_LOG_ENTRIES:
                self.dropped_entries += 1
                return
            self.entries.append(
                {
                    "order": len(self.entries),
                    "method": method,
                    "path": stored_path,
                    "path_truncated": path_truncated,
                    "path_sha256_16": (
                        hashlib.sha256(raw_path.encode("utf-8")).hexdigest()[:16]
                        if path_truncated
                        else None
                    ),
                    "request_body_bytes": body_bytes,
                    # What the rehost actually handed back. `empty` means the path
                    # matched nothing and the fallback returned zero bytes, which
                    # is how a missing later stage looks from the outside.
                    "served": served,
                    **(
                        {"request_body_sha256_16": body_sha256_16.lower()}
                        if body_sha256_16 is not None
                        else {}
                    ),
                    **query_receipt,
                }
            )

    def snapshot(self) -> tuple[list[dict[str, Any]], int]:
        with self._lock:
            return list(self.entries), self.dropped_entries


def build_rehost_page(
    dom_profile: str = "minimal",
    script_path: str = DEFAULT_SCRIPT_PATH,
    hook_mode: str = "off",
    inline_source: bytes | None = None,
    declared_script_url: str | None = None,
    prelude_js: str | None = None,
) -> bytes:
    """Build the rehost document.

    Extracted from the request handler so it can be tested without binding a
    socket. The socket-based version of these tests failed under host resource
    pressure (`WinError 10055`) while testing nothing that needed a network: the
    question "does the page carry the hook tag" is a question about a string.
    """
    if not isinstance(dom_profile, str) or dom_profile not in DOM_PROFILES:
        raise ContractError(f"dom profile must be one of {sorted(DOM_PROFILES)}")
    if not isinstance(hook_mode, str) or hook_mode not in HOOK_MODES:
        raise ContractError(f"hook mode must be one of {HOOK_MODES}")
    if inline_source is not None and not isinstance(inline_source, bytes):
        raise ContractError("inline rehost source must be bytes or null")
    if declared_script_url is not None and not isinstance(declared_script_url, str):
        raise ContractError("declared script URL must be text or null")
    # The observed collector reads its own `document.currentScript.src`, so the path a
    # sample is served from is part of what it sees. Making it settable lets a rehost
    # mirror the real deployment's path, and lets that be tested rather than assumed.
    script_path = _validate_script_path(script_path, hook_mode)
    declared_source_tag = ""
    if declared_script_url is not None:
        declared_script_url = _validate_declared_script_url(declared_script_url)
        if inline_source is not None:
            raise ContractError(
                "declared script URL is incompatible with inline packaging"
            )
        # An unsupported script type is a data block: Chromium exposes its `src`
        # property to DOM inspection but does not fetch or execute it. The actual
        # saved bytes still load from loopback in the following script element.
        declared_source_tag = (
            '<script type="application/json" data-browser-core-declared-source="true" '
            f'src="{escape(declared_script_url, quote=True)}"></script>\n'
        )
    hook_tag = (
        "" if hook_mode == "off" else f'<script src="{HOOK_SCRIPT_PATH}"></script>\n'
    )
    prelude_tag = ""
    if prelude_js is not None:
        prelude_js = _validate_prelude_source(prelude_js)
        prelude_tag = f"<script>{prelude_js}</script>\n"
    if inline_source is None:
        return _PAGE_HTML.format(
            title=PAGE_TITLE,
            witness=_STARTUP_WITNESS,
            body=DOM_PROFILES[dom_profile],
            script_path=escape(script_path, quote=True),
            prelude_tag=prelude_tag,
            declared_source_tag=declared_source_tag,
            hook_tag=hook_tag,
        ).encode("utf-8")

    # Some collectors ship inside the HTML rather than as a file, and the
    # difference is observable to them. Shape's Nordstrom deployment is one
    # 247,795-byte inline script with no external tag, and it reads
    # `document.currentScript` six times -- for an inline script that element has
    # an empty `src`, so serving it as `<script src="...">` hands the collector a
    # URL it never had in production.
    #
    # The bytes are embedded verbatim. A sample containing `</script` would end
    # the element early and silently truncate what runs, so it is refused rather
    # than escaped: escaping changes the bytes being measured, which is the worse
    # of the two failures.
    try:
        text = inline_source.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ContractError(
            "inline rehost requires valid UTF-8 source; replacement decoding would "
            "measure bytes other than the saved sample"
        ) from exc
    if "</script" in text.lower():
        raise ContractError(
            "inline rehost refuses a sample containing '</script': embedding it "
            "would truncate the element and measure something other than the file"
        )
    return _PAGE_HTML_INLINE.format(
        title=PAGE_TITLE,
        witness=_STARTUP_WITNESS,
        body=DOM_PROFILES[dom_profile],
        prelude_tag=prelude_tag,
        hook_tag=hook_tag,
        source=text,
    ).encode("utf-8")


def _capture_startup(
    endpoint: str, url: str, timeout_seconds: float
) -> dict[str, Any] | None:
    """Read back whether the collector actually started.

    Best-effort like the geometry probe: a browser that will not answer yields
    ``None``, which reads as "not recorded" rather than as "did not start".
    """
    try:
        raw = evaluate_page_expression(
            endpoint,
            _STARTUP_JS,
            target_url=url,
            timeout_seconds=timeout_seconds,
            command_id=955,
        )
        document = _decode_page_probe(
            raw,
            label="startup probe",
            fields=frozenset(
                {
                    "uncaught_errors",
                    "unhandled_rejections",
                    "ambient_input",
                    "vendor_globals",
                    "vendor_reports_ready",
                    "window_properties",
                    "window_properties_before_script",
                }
            ),
        )
        if any(
            not isinstance(document.get(field), list)
            for field in ("uncaught_errors", "unhandled_rejections")
        ):
            raise ContractError("startup error witness is invalid")
        if not _valid_startup_ambient_witness(document.get("ambient_input")):
            raise ContractError("startup ambient-input witness is invalid")
        vendor = document.get("vendor_globals")
        if not _valid_startup_vendor_witness(vendor):
            raise ContractError("startup vendor witness is invalid")
        ready = document.get("vendor_reports_ready")
        if "vendor_reports_ready" not in document or not (
            ready is None or type(ready) is bool or ready == "threw"
        ):
            raise ContractError("startup readiness witness is invalid")
        if any(
            type(document.get(field)) is not int or document[field] < 0
            for field in ("window_properties", "window_properties_before_script")
        ):
            raise ContractError("startup window-property witness is invalid")
        return _sanitize_startup_document(document)
    except Exception as exc:  # noqa: BLE001 - never fail a run over metadata
        # Recorded rather than swallowed. "did not answer" with no reason is the
        # same failure this whole probe exists to prevent, one level up: a missing
        # measurement that looks like a measurement.
        #
        # Then asked one question further, because the two ways this fails call
        # for opposite responses. The target list is served by the *browser*
        # process, so it answers even while a renderer is wedged. Browser alive
        # and page unresponsive means the collector is still holding the main
        # thread only when the established command response timed out; browser
        # gone means the run itself died and the surface is worthless. Measured on the Kasada
        # interrogation stage, which holds the thread for about 102 seconds
        # untraced and longer than a 180 second dwell under broad tracing.
        target = probe_managed_page_target(
            endpoint,
            url,
            expected_title=PAGE_TITLE,
            timeout_seconds=10.0,
        )
        status = target["status"]
        response_timed_out = isinstance(exc, CdpCommandResponseTimeout)
        return {
            "probe_error": _failure_receipt("startup probe failed", exc),
            "renderer_blocked": (
                True
                if status == "present" and response_timed_out
                else False
                if status == "absent"
                else None
            ),
            "browser_target_status": status,
            "browser_target_title_matches": target["title_matches"],
        }


def _capture_resource_intents(
    endpoint: str, url: str, timeout_seconds: float
) -> dict[str, Any]:
    """Best-effort passive inventory of DOM resource intent, with no raw URLs."""
    try:
        return _sanitize_resource_intent_report(
            observe_page_resource_intents(
                endpoint,
                target_url=url,
                timeout_seconds=min(float(timeout_seconds), 5.0),
            )
        )
    except Exception as exc:  # noqa: BLE001 - metadata must not fail an arm
        return {
            "status": "failed",
            "source": "cdp_dom_snapshot",
            "diagnostic": _failure_receipt("resource intent capture failed", exc),
            "intents": [],
            "non_claim": "resource intent could not be observed",
        }


_READY_JS = """
(() => {
  let ready = null;
  try {
    if (window.KPSDK && typeof window.KPSDK.isReady === 'function') {
      ready = !!window.KPSDK.isReady();
    }
  } catch (e) { ready = null; }
  return JSON.stringify({ready: ready, t: Date.now()});
})()
"""


def build_ready_probe(ready_expression: str | None = None) -> str:
    """Build the bounded boolean readiness probe used by the poller."""
    if ready_expression is None:
        return _READY_JS
    _bounded_utf8_source(
        ready_expression,
        label="ready expression",
        maximum=MAX_READY_EXPRESSION_BYTES,
        non_empty=True,
    )
    return f"""
(() => {{
  let ready = null;
  try {{ ready = !!({ready_expression}); }} catch (e) {{ ready = null; }}
  return JSON.stringify({{ready: ready, t: Date.now()}});
}})()
"""


def await_collector_ready(
    endpoint: str,
    url: str,
    *,
    cap_seconds: float,
    poll_timeout_seconds: float,
    ready_expression: str | None = None,
) -> dict[str, Any]:
    """Poll until the collector says it is ready, or until the cap.

    Returns why it stopped, which is the whole point. ``ready`` means the built-in
    client readiness API turned true. ``expression_true`` means an operator-supplied
    boolean turned true; it deliberately does *not* claim that the expression marks
    completion. ``cap`` means the budget ran out with the client still working or
    still silent -- an arm that ended this way measured a collector mid-flight and
    should not be read as a finished one. ``no_signal`` means the page answered but
    the probe produced no boolean signal, so responsiveness is all there is to go on.

    ``slowest_poll`` keeps the one timing sample needed to support a main-thread
    blocking claim without turning the artifact into an unbounded poll log. Its
    issue offset, duration, and outcome are measured by the same monotonic clock
    as ``waited_seconds``. Before this existed, an exact 101.766-second CDP stall
    reached three documents but no retained artifact could establish it. Only the
    typed post-send response timeout increments ``unresponsive_polls``; protocol,
    decoding, and other failures increment ``failed_polls`` and use outcome
    ``failed`` so they cannot be cited as renderer-unresponsiveness evidence.
    """
    for value, label, maximum in (
        (cap_seconds, "await cap", MAX_OBSERVATION_SECONDS),
        (
            poll_timeout_seconds,
            "readiness poll timeout",
            MAX_CDP_OPERATION_SECONDS,
        ),
    ):
        if (
            not is_finite_number(value)
            or value <= 0
            or value > maximum
        ):
            raise ContractError(
                f"{label} must be finite and positive and at most {maximum:g} seconds"
            )
    ready_probe = build_ready_probe(ready_expression)
    signal_kind = "operator_expression" if ready_expression is not None else "builtin"
    started = time.monotonic()
    polls = 0
    unresponsive = 0
    failed = 0
    saw_page = False
    slowest_poll: dict[str, Any] | None = None

    def record_poll(*, issued_at: float, completed_at: float, outcome: str) -> None:
        nonlocal slowest_poll
        sample = {
            "issued_at_seconds": round(issued_at, 3),
            "duration_seconds": round(max(completed_at - issued_at, 0.0), 3),
            "outcome": outcome,
        }
        if (
            slowest_poll is None
            or sample["duration_seconds"] > slowest_poll["duration_seconds"]
        ):
            slowest_poll = sample

    while True:
        elapsed = time.monotonic() - started
        if elapsed >= cap_seconds:
            return {
                "ended_on": "cap",
                "waited_seconds": round(elapsed, 1),
                "polls": polls,
                "unresponsive_polls": unresponsive,
                "failed_polls": failed,
                "page_ever_answered": saw_page,
                "poll_timeout_seconds": poll_timeout_seconds,
                "slowest_poll": slowest_poll,
                "signal_kind": signal_kind,
            }
        polls += 1
        try:
            raw = evaluate_page_expression(
                endpoint,
                ready_probe,
                target_url=url,
                timeout_seconds=min(poll_timeout_seconds, cap_seconds - elapsed),
                command_id=957,
            )
            completed_at = time.monotonic() - started
            saw_page = True
            ready_document = _decode_page_probe(
                raw,
                label="readiness probe",
                fields=frozenset({"ready", "t"}),
            )
            ready_value = ready_document["ready"]
            if ready_value is not None and type(ready_value) is not bool:
                raise ContractError("readiness probe ready value is invalid")
            timestamp = ready_document["t"]
            if (
                not is_finite_number(timestamp)
                or not 0 <= timestamp <= (1 << 53) - 1
            ):
                raise ContractError("readiness probe timestamp is invalid")
            ready = ready_value is True
            record_poll(
                issued_at=elapsed,
                completed_at=completed_at,
                outcome=(
                    ("expression_true" if ready_expression is not None else "ready")
                    if ready
                    else "no_signal"
                    if ready_value is None
                    else "not_ready"
                ),
            )
            if completed_at >= cap_seconds:
                return {
                    "ended_on": "cap",
                    "waited_seconds": round(completed_at, 1),
                    "polls": polls,
                    "unresponsive_polls": unresponsive,
                    "failed_polls": failed,
                    "page_ever_answered": True,
                    "poll_timeout_seconds": poll_timeout_seconds,
                    "slowest_poll": slowest_poll,
                    "signal_kind": signal_kind,
                }
            if ready_value is None:
                return {
                    "ended_on": "no_signal",
                    "waited_seconds": round(completed_at, 1),
                    "polls": polls,
                    "unresponsive_polls": unresponsive,
                    "failed_polls": failed,
                    "page_ever_answered": True,
                    "poll_timeout_seconds": poll_timeout_seconds,
                    "slowest_poll": slowest_poll,
                    "signal_kind": signal_kind,
                }
            if ready:
                ended_on = (
                    "expression_true" if ready_expression is not None else "ready"
                )
                return {
                    "ended_on": ended_on,
                    "waited_seconds": round(completed_at, 1),
                    "polls": polls,
                    "unresponsive_polls": unresponsive,
                    "failed_polls": failed,
                    "page_ever_answered": True,
                    "poll_timeout_seconds": poll_timeout_seconds,
                    "slowest_poll": slowest_poll,
                    "signal_kind": signal_kind,
                }
        except Exception as exc:  # noqa: BLE001 - failed polls are retained data
            completed_at = time.monotonic() - started
            outcome = (
                "unresponsive"
                if isinstance(exc, CdpCommandResponseTimeout)
                else "failed"
            )
            if outcome == "unresponsive":
                unresponsive += 1
            else:
                failed += 1
            record_poll(
                issued_at=elapsed,
                completed_at=completed_at,
                outcome=outcome,
            )
            if completed_at >= cap_seconds:
                return {
                    "ended_on": "cap",
                    "waited_seconds": round(completed_at, 1),
                    "polls": polls,
                    "unresponsive_polls": unresponsive,
                    "failed_polls": failed,
                    "page_ever_answered": saw_page,
                    "poll_timeout_seconds": poll_timeout_seconds,
                    "slowest_poll": slowest_poll,
                    "signal_kind": signal_kind,
                }
        remaining = cap_seconds - completed_at
        if remaining <= 0:
            continue
        time.sleep(min(1.0, remaining))


#: Entry points a host page is expected to call, keyed by the global the client
#: actually installed at runtime.
#:
#: Keyed on the *observed* global rather than on a static vendor hint, and that is
#: a correction rather than a preference. The first version keyed on the hint from
#: `classify_product_script`, and it never fired on the one case it was written
#: for: Kasada's `p.js` is the stage that needs driving and it contains no `KPSDK`
#: literal at all -- the literal lives in `ips.js`, the stage it fetches. The
#: runtime evidence was sitting in the startup record the whole time.
#:
#: Only what has been measured goes here. Kasada's client publishes exactly
#: ``{configure, isReady}``, and calling ``configure`` with a non-array throws
#: ``Configuration endpoints are not an array``, which states its own contract.
#: The other vendors measured so far start themselves and need nothing.
#:
#: This is a *suggestion* surface, never applied automatically. An arm that was
#: driven is a different measurement from one that was not, and deciding to drive
#: one is the operator's call.
KNOWN_HOST_ENTRY_POINTS: dict[str, str] = {
    "KPSDK": (
        "window.KPSDK.configure([{domain:'127.0.0.1',method:'POST',path:'/tl'}])"
    ),
}


def suggest_driver(startup: dict[str, Any] | None) -> str | None:
    """Name the documented entry point for a collector that did not start.

    Returns ``None`` unless the client is reporting that it is not ready *and* it
    installed a global whose entry point has been measured. A collector that
    started fine needs no suggestion, and one whose entry point is unknown gets no
    invented one.
    """
    if startup is None:
        return None
    if not isinstance(startup, dict):
        raise ContractError("driver suggestion startup must be an object or null")
    if startup.get("vendor_reports_ready") is not False:
        return None
    vendor_globals = startup.get("vendor_globals")
    for name in vendor_globals if isinstance(vendor_globals, list) else ():
        if not isinstance(name, str):
            continue
        entry = KNOWN_HOST_ENTRY_POINTS.get(name)
        if entry:
            return entry
    return None


def _valid_rehost_logged_path(value: Any) -> bool:
    """Admit only a path the loopback recorder could have retained intact."""
    return bool(
        type(value) is str
        and 1 <= len(value) <= MAX_REHOST_LOG_PATH_CHARS
        and value.startswith("/")
        and not value.startswith("//")
        and "?" not in value
        and "#" not in value
        and not any(
            ord(char) < 32
            or ord(char) == 127
            or ord(char) > 255
            or char.isspace()
            for char in value
        )
    )


def _valid_rehost_served_route(method: Any, path: Any, served: Any) -> bool:
    """Check the request classes the loopback handler can actually emit."""
    if (
        type(method) is not str
        or type(served) is not str
        or served not in REHOST_REQUEST_SERVED_CLASSES
        or not _valid_rehost_logged_path(path)
    ):
        return False
    if served == "proxy-denied":
        return method in PROXY_DENIED_METHODS
    if served == "post-ack":
        return method == "POST"
    if method != "GET":
        return False
    if served == "page":
        return path == "/"
    if served == "hook":
        return path == HOOK_SCRIPT_PATH
    if served == "sample":
        try:
            _validate_script_path(path)
        except ContractError:
            return False
    if served in {"stage", "empty"} and path == "/":
        return False
    return True


def _valid_rehost_row_metadata(row: dict[str, Any]) -> bool:
    """Check optional retained shapes emitted by the bounded request recorder."""
    body_digest = row.get("request_body_sha256_16")
    if "request_body_sha256_16" in row and (
        row.get("served") != "post-ack"
        or type(body_digest) is not str
        or re.fullmatch(r"[0-9a-f]{16}", body_digest) is None
    ):
        return False
    has_names = "query_names" in row
    if has_names != ("query_names_truncated" in row):
        return False
    if has_names:
        names = row["query_names"]
        if (
            type(names) is not list
            or len(names) > 64
            or type(row["query_names_truncated"]) is not bool
            or not all(
                _is_strict_utf8_text(name)
                and 0 < len(name) <= 80
                and not any(ord(char) < 32 or ord(char) == 127 for char in name)
                for name in names
            )
            or names != sorted(set(names))
        ):
            return False
    if "path_sha256_16" in row:
        path_digest = row["path_sha256_16"]
        if row.get("path_truncated") is True:
            if (
                type(path_digest) is not str
                or re.fullmatch(r"[0-9a-f]{16}", path_digest) is None
            ):
                return False
        elif path_digest is not None:
            return False
    return True


def _configured_rehost_routes_coherent(
    document: dict[str, Any], rows: list[Any]
) -> bool:
    """Recheck saved route labels against the handler's route precedence."""
    hook_mode = document.get("hook_mode", "off")
    if type(hook_mode) is not str or hook_mode not in HOOK_MODES:
        return False
    script_path = document.get("script_path", DEFAULT_SCRIPT_PATH)
    try:
        _validate_script_path(script_path, hook_mode)
    except ContractError:
        return False
    stage_routes = document.get("stage_routes", [])
    if type(stage_routes) not in {list, tuple} or len(stage_routes) > MAX_STAGE_ROUTES:
        return False
    stage_prefixes: set[str] = set()
    total_stage_bytes = 0
    for route in stage_routes:
        if type(route) is not dict or set(route) != {
            "path_prefix", "bytes", "sha256_16"
        }:
            return False
        try:
            prefix = _validate_stage_prefix(route.get("path_prefix"))
        except ContractError:
            return False
        byte_count = route["bytes"]
        digest = route["sha256_16"]
        if (
            type(byte_count) is not int
            or not 0 <= byte_count <= MAX_STAGE_BYTES
            or type(digest) is not str
            or re.fullmatch(r"[0-9a-f]{16}", digest) is None
        ):
            return False
        total_stage_bytes += byte_count
        if total_stage_bytes > MAX_STAGE_BYTES:
            return False
        if prefix in stage_prefixes:
            return False
        stage_prefixes.add(prefix)
    for row in rows:
        if not isinstance(row, dict):
            return False
        served = row.get("served")
        path = row.get("path")
        if not _valid_rehost_served_route(row.get("method"), path, served) or not (
            _valid_rehost_row_metadata(row)
        ):
            return False
        body_bytes = row.get("request_body_bytes", 0)
        if (
            type(body_bytes) is not int
            or not 0 <= body_bytes <= (
                MAX_REHOST_POST_BODY_BYTES if served == "post-ack" else 0
            )
        ):
            return False
        if served == "proxy-denied" and path != (
            "/<proxy-connect>" if row.get("method") == "CONNECT" else "/<proxy-http>"
        ):
            return False
        if served == "sample" and path != script_path:
            return False
        if served == "hook" and hook_mode == "off":
            return False
        if served in {"stage", "empty"}:
            if path == script_path or (
                hook_mode != "off" and path == HOOK_SCRIPT_PATH
            ):
                return False
            matches_stage = any(path.startswith(prefix) for prefix in stage_prefixes)
            if matches_stage != (served == "stage"):
                return False
    return True


def grade_unserved_requests(server_requests: list[dict[str, Any]]) -> dict[str, Any]:
    """Which paths did the collector ask for that this rehost had no bytes for?

    The rehost answers an unknown path with an empty 200 so the sample proceeds
    instead of erroring. That is the right default and it is also how a **missing
    later stage** looks from the outside: the collector fetches its own next
    stage, gets zero bytes, and fails quietly somewhere further on.

    Finding Kasada's second stage took a hand-written probe to read one fetch URL
    out of the page. The information was already in the server log and nothing
    pointed at it. It does now: these paths are the `--stage` arguments a fuller
    observation needs.

    `/favicon.ico` is excluded because the browser asks for it, not the script.
    """
    if not isinstance(server_requests, list):
        raise ContractError("unserved-request grade must receive a request list")
    if len(server_requests) > MAX_REHOST_REQUEST_LOG_ENTRIES:
        raise ContractError("unserved-request grade exceeds the request-log limit")
    entries: list[dict[str, Any]] = []
    malformed_entries = 0
    numbered = any(
        isinstance(entry, dict) and "order" in entry for entry in server_requests
    )
    for expected_order, entry in enumerate(server_requests):
        if not isinstance(entry, dict):
            malformed_entries += 1
            continue
        if numbered and (
            type(entry.get("order")) is not int or entry["order"] != expected_order
        ):
            malformed_entries += 1
            continue
        method = entry.get("method")
        path = entry.get("path")
        served = entry.get("served")
        path_truncated = entry.get("path_truncated")
        body = entry.get("request_body_bytes")
        if (
            not _valid_rehost_served_route(method, path, served)
            or ("path_truncated" in entry and not isinstance(path_truncated, bool))
            or (
                "request_body_bytes" in entry
                and (isinstance(body, bool) or not isinstance(body, int) or body < 0)
            )
        ):
            malformed_entries += 1
            continue
        entries.append(entry)
    truncated_paths = sum(1 for entry in entries if entry.get("path_truncated") is True)
    unserved = [
        entry
        for entry in entries
        if entry.get("served") == "empty"
        and isinstance(entry.get("path"), str)
        and entry.get("path") != "/favicon.ico"
        and entry.get("path_truncated") is not True
    ]
    synthetic_acks = [
        entry
        for entry in entries
        if entry.get("served") == "post-ack" and isinstance(entry.get("path"), str)
    ]
    proxy_denied = [entry for entry in entries if entry.get("served") == "proxy-denied"]

    def body_bytes(entry: dict[str, Any]) -> int:
        value = entry.get("request_body_bytes")
        return (
            min(value, MAX_REHOST_POST_BODY_BYTES)
            if isinstance(value, int) and not isinstance(value, bool) and value >= 0
            else 0
        )

    if malformed_entries:
        note = (
            "one or more request-log rows were malformed; dependency completeness "
            "cannot be established from the retained population"
        )
    elif truncated_paths:
        note = (
            "one or more request paths exceeded the retention bound; exact "
            "missing-stage paths are incomplete and cannot support absence"
        )
    elif unserved:
        note = (
            "the collector requested these and the rehost had no bytes for them; "
            "a missing later stage looks exactly like this, and each is a "
            "candidate --stage argument"
        )
    elif not entries:
        note = "no requests reached the loopback rehost"
    elif len(proxy_denied) == len(entries):
        note = "proxy requests were denied; no missing local stage path was observed"
    else:
        note_parts = []
        if any(
            entry["served"] in {"page", "sample", "hook", "stage"}
            for entry in entries
        ):
            note_parts.append("owned-origin GET paths were served from disk")
        if any(entry["served"] == "empty" for entry in entries):
            note_parts.append("favicon request received an empty fallback")
        if synthetic_acks:
            note_parts.append(
                "POST requests received a synthetic lab acknowledgement, "
                "not a replayed product response"
            )
        if proxy_denied:
            note_parts.append("proxy requests were denied")
        note = "; ".join(note_parts)
    return {
        "status": "unverifiable" if truncated_paths or malformed_entries else "ok",
        "count": len(unserved),
        "dependencies_complete": (
            None if truncated_paths or malformed_entries else not bool(unserved)
        ),
        "scope": "loopback_rehost_only",
        "scope_note": (
            "requests blocked before reaching loopback (for example an external "
            "hostname rejected by the offline DNS guard) are not visible here"
        ),
        "paths": sorted({entry["path"] for entry in unserved}),
        "truncated_paths": truncated_paths,
        "malformed_entries": malformed_entries,
        "synthetic_acknowledgements": {
            "count": len(synthetic_acks),
            "paths": sorted({entry["path"] for entry in synthetic_acks}),
            "request_body_bytes": sum(body_bytes(entry) for entry in synthetic_acks),
            "note": (
                "the rehost returned a generic JSON acknowledgement; this does not "
                "reproduce or establish a product endpoint response"
            ),
        },
        "proxy_denied": {
            "count": len(proxy_denied),
            "methods": dict(
                Counter(
                    entry["method"]
                    for entry in proxy_denied
                    if entry.get("method") in PROXY_DENIED_METHODS
                ).most_common()
            ),
            "note": (
                "requests sent to the owned deny proxy; target authority is not "
                "retained and no upstream socket was opened"
            ),
        },
        "note": note,
    }


def _reconciled_rehost_dependencies(
    document: dict[str, Any],
) -> tuple[bool | None, dict[str, Any] | None, bool | None]:
    """Recompute current receipts from retained rows; preserve bounded legacy input."""
    claimed = document.get("unserved_requests")
    if "server_requests" not in document:
        dependencies: bool | None = None
        safe_claimed: dict[str, Any] | None = None
        if isinstance(claimed, dict):
            # Older observations did not retain the source request rows. Their
            # receipt can still convey a bounded count/path claim, but arbitrary
            # notes and extra fields must not cross into a new comparison.
            safe_claimed = {}
            status = claimed.get("status")
            if "status" in claimed:
                if type(status) is not str or status not in {"ok", "unverifiable"}:
                    return None, {"status": "unverifiable"}, None
                safe_claimed["status"] = status
            for key, maximum in (
                ("count", MAX_REHOST_REQUEST_LOG_ENTRIES),
                ("truncated_paths", MAX_REHOST_REQUEST_LOG_ENTRIES),
                ("malformed_entries", MAX_REHOST_REQUEST_LOG_ENTRIES),
                ("retained_requests", MAX_REHOST_REQUEST_LOG_ENTRIES),
                ("dropped_requests", 1_000_000_000),
            ):
                if key in claimed:
                    value = claimed[key]
                    if type(value) is not int or not 0 <= value <= maximum:
                        return None, {"status": "unverifiable"}, None
                    safe_claimed[key] = value
            if "dependencies_complete" in claimed:
                value = claimed["dependencies_complete"]
                if type(value) is not bool:
                    return None, {"status": "unverifiable"}, None
                safe_claimed["dependencies_complete"] = value
            if "paths" in claimed:
                paths = claimed["paths"]
                if (
                    type(paths) is not list
                    or len(paths) > MAX_REHOST_REQUEST_LOG_ENTRIES
                    or not all(_valid_rehost_logged_path(path) for path in paths)
                ):
                    return None, {"status": "unverifiable"}, None
                safe_claimed["paths"] = list(paths)
            if claimed.get("scope") == "loopback_rehost_only":
                safe_claimed["scope"] = "loopback_rehost_only"
            incomplete = any(
                key in claimed
                and (
                    isinstance(claimed[key], bool)
                    or not isinstance(claimed[key], int)
                    or claimed[key] != 0
                )
                for key in ("truncated_paths", "malformed_entries", "dropped_requests")
            )
            explicit = claimed.get("dependencies_complete")
            if isinstance(explicit, bool):
                dependencies = explicit
                count = claimed.get("count")
                paths = claimed.get("paths")
                if explicit and (
                    claimed.get("status") not in (None, "ok")
                    or (
                        "count" in claimed
                        and (
                            isinstance(count, bool)
                            or not isinstance(count, int)
                            or count != 0
                        )
                    )
                    or ("paths" in claimed and paths != [])
                    or incomplete
                ):
                    # A bounded legacy receipt has no retained rows to
                    # regrade. Its own positive/incomplete evidence cannot
                    # support an explicit completeness claim.
                    dependencies = None
            elif "dependencies_complete" in claimed:
                # An explicit but malformed verdict cannot be replaced by a
                # count inference from the same untrusted legacy receipt.
                dependencies = None
            elif claimed.get("status") == "ok":
                count = claimed.get("count")
                if (
                    isinstance(count, int)
                    and not isinstance(count, bool)
                    and count >= 0
                ):
                    dependencies = count == 0
                    if dependencies and (
                        ("paths" in claimed and claimed["paths"] != [])
                        or incomplete
                    ):
                        dependencies = None
        return dependencies, safe_claimed, None

    entries = document.get("server_requests")
    if not isinstance(entries, list):
        return None, {"status": "unverifiable"}, False
    try:
        recomputed = grade_unserved_requests(entries)
    except ContractError:
        return None, {"status": "unverifiable"}, False

    receipt = document.get("server_request_log")
    # Retained rows alone cannot prove that the bounded log dropped no earlier
    # requests. The population receipt is required for a completeness claim.
    receipt_coherent = receipt is not None
    if receipt is not None:
        truncated_paths = sum(
            1
            for entry in entries
            if isinstance(entry, dict) and entry.get("path_truncated") is True
        )
        proxy_denied = sum(
            1
            for entry in entries
            if isinstance(entry, dict) and entry.get("served") == "proxy-denied"
        )

        def bounded_int(name: str) -> int | None:
            value = receipt.get(name) if isinstance(receipt, dict) else None
            return (
                value
                if isinstance(value, int)
                and not isinstance(value, bool)
                and 0 <= value <= 1_000_000_000
                else None
            )

        retained = bounded_int("retained")
        dropped = bounded_int("dropped")
        receipt_coherent = bool(
            isinstance(receipt, dict)
            and set(receipt)
            == {
                "limit",
                "retained",
                "dropped",
                "truncated_paths",
                "truncated",
                "proxy_denied",
            }
            and type(receipt.get("limit")) is int
            and receipt["limit"] == MAX_REHOST_REQUEST_LOG_ENTRIES
            and retained == len(entries)
            and dropped is not None
            and type(receipt.get("truncated_paths")) is int
            and receipt["truncated_paths"] == truncated_paths
            and type(receipt.get("proxy_denied")) is int
            and receipt["proxy_denied"] == proxy_denied
            and type(receipt.get("truncated")) is bool
            and receipt["truncated"] == (dropped > 0 or truncated_paths > 0)
        )
        if receipt_coherent and dropped is not None and dropped > 0:
            recomputed.update(
                {
                    "status": "unverifiable",
                    "dependencies_complete": None,
                    "retained_requests": len(entries),
                    "dropped_requests": dropped,
                    "note": (
                        "request log reached its bound; missing-stage conclusions "
                        "are incomplete"
                    ),
                }
            )

    claimed_coherent = True
    if claimed is not None:
        def same_field(key: str, expected: Any) -> bool:
            value = claimed.get(key)
            return type(value) is type(expected) and value == expected

        claimed_coherent = isinstance(claimed, dict) and all(
            same_field(key, recomputed.get(key))
            for key in ("status", "count", "dependencies_complete", "paths")
        )
        if isinstance(claimed, dict):
            for key in ("truncated_paths", "malformed_entries"):
                if key in claimed:
                    claimed_coherent = claimed_coherent and same_field(
                        key, recomputed.get(key)
                    )
            for key, fields in (
                (
                    "synthetic_acknowledgements",
                    ("count", "paths", "request_body_bytes"),
                ),
                ("proxy_denied", ("count", "methods")),
            ):
                if key in claimed:
                    summary = claimed[key]
                    expected_summary = recomputed[key]
                    claimed_coherent = claimed_coherent and bool(
                        type(summary) is dict
                        and all(
                            field in summary
                            and type(summary[field]) is type(expected_summary[field])
                            and summary[field] == expected_summary[field]
                            for field in fields
                        )
                        and (
                            key != "proxy_denied"
                            or all(type(value) is int for value in summary["methods"].values())
                        )
                    )
            for key, expected in (
                ("retained_requests", recomputed.get("retained_requests", len(entries))),
                ("dropped_requests", recomputed.get("dropped_requests", 0)),
                ("log_truncated", recomputed.get("log_truncated", False)),
            ):
                if key in claimed:
                    claimed_coherent = claimed_coherent and same_field(key, expected)

    route_configuration_recorded = any(
        key in document for key in ("script_path", "hook_mode", "stage_routes")
    )
    configured_routes_coherent = (
        not route_configuration_recorded
        or _configured_rehost_routes_coherent(document, entries)
    )
    coherent = receipt_coherent and claimed_coherent and configured_routes_coherent
    if not coherent:
        recomputed.update(
            {
                "status": "unverifiable",
                "dependencies_complete": None,
                "note": (
                    "retained request rows and dependency receipts do not reconcile"
                ),
            }
        )
    dependencies = recomputed.get("dependencies_complete")
    return (
        dependencies if isinstance(dependencies, bool) else None,
        recomputed,
        coherent,
    )


def _reconciled_request_activity(
    document: dict[str, Any], rehost_receipts_coherent: bool | None
) -> tuple[dict[str, Any], bool | None]:
    """Rebuild current activity evidence from retained rows and bounded counters."""
    raw_activity = document.get("request_activity")
    if "server_requests" not in document:
        return (
            _sanitize_request_activity_report(raw_activity)
            if isinstance(raw_activity, dict)
            else project_server_request_activity([]),
            None,
        )
    rows = document.get("server_requests")
    recomputed = project_server_request_activity(rows)
    if "server_request_log" not in document:
        return recomputed, None
    receipt = document.get("server_request_log")
    dropped = receipt.get("dropped") if isinstance(receipt, dict) else None
    if isinstance(dropped, int) and not isinstance(dropped, bool) and dropped > 0:
        recomputed.update(
            {
                "status": "unverifiable",
                "truncated": True,
                "retained_requests": len(rows) if isinstance(rows, list) else 0,
                "dropped_requests": min(dropped, 1_000_000_000),
            }
        )
    supplied = (
        _sanitize_request_activity_report(raw_activity)
        if isinstance(raw_activity, dict)
        else None
    )
    coherent = rehost_receipts_coherent is True and supplied == recomputed
    if not coherent:
        recomputed.update({"status": "unverifiable", "truncated": True})
    return recomputed, coherent


def _reconciled_page_load_execution(
    document: dict[str, Any], *, current_required: bool
) -> tuple[bool | None, dict[str, Any] | None]:
    """Bind configured reloads to requests for each harness-owned script."""
    recorded = "page_loads" in document
    if not recorded and not current_required:
        return None, None
    reloads = document.get("reloads")
    page_loads = document.get("page_loads")
    rows = document.get("server_requests")
    if not isinstance(rows, list) or len(rows) > MAX_REHOST_REQUEST_LOG_ENTRIES:
        return False, None
    counts: Counter[str] = Counter()
    request_classes_valid = True
    for row in rows:
        if not isinstance(row, dict):
            request_classes_valid = False
            continue
        served = row.get("served")
        method = row.get("method")
        path = row.get("path")
        if not _valid_rehost_served_route(method, path, served):
            request_classes_valid = False
            continue
        if served == "sample" and path != document.get(
            "script_path", DEFAULT_SCRIPT_PATH
        ):
            request_classes_valid = False
            continue
        if served == "hook" and document.get("hook_mode") not in (
            "inert", "on"
        ):
            request_classes_valid = False
            continue
        if method == "GET":
            counts[served] += 1
    expected = (
        reloads + 1
        if isinstance(reloads, int) and not isinstance(reloads, bool)
        else None
    )
    sample_minimum = 0 if document.get("inline_script") is True else expected
    hook_minimum = expected if document.get("hook_mode") != "off" else 0
    # Aggregate counts cannot tell whether one load fetched a script twice
    # while a later load fetched none. Match each required script request to
    # the page request that preceded it in the retained chronological log.
    ordered_page_loads = 0
    page_seen = False
    active_page = False
    hook_seen = False
    sample_seen = False
    early_script_request = False
    for row in rows:
        if not isinstance(row, dict):
            continue
        served = row.get("served")
        if served == "page":
            page_seen = True
            active_page = True
            hook_seen = hook_minimum == 0
            sample_seen = sample_minimum == 0
        elif served == "sample" or served == "hook":
            if not page_seen:
                early_script_request = True
            if active_page:
                if served == "sample":
                    sample_seen = True
                else:
                    hook_seen = True
        if active_page and hook_seen and sample_seen:
            ordered_page_loads += 1
            active_page = False
    coherent = bool(
        request_classes_valid
        and _configured_rehost_routes_coherent(document, rows)
        and not early_script_request
        and isinstance(expected, int)
        and 1 <= expected <= MAX_OBSERVATION_RELOADS + 1
        and isinstance(page_loads, int)
        and not isinstance(page_loads, bool)
        and page_loads == expected
        and counts["page"] >= expected
        and isinstance(sample_minimum, int)
        and counts["sample"] >= sample_minimum
        and isinstance(hook_minimum, int)
        and counts["hook"] >= hook_minimum
        and ordered_page_loads >= expected
    )
    return coherent, {
        "configured_page_loads": expected,
        "reported_page_loads": (
            page_loads
            if isinstance(page_loads, int) and not isinstance(page_loads, bool)
            else None
        ),
        "page_requests": counts["page"],
        "sample_requests": counts["sample"],
        "hook_requests": counts["hook"],
    }


def _request_log_artifacts(
    log: _RequestLog,
) -> tuple[list[dict[str, Any]], dict[str, Any], dict[str, Any], dict[str, Any]]:
    entries, dropped = log.snapshot()
    truncated_paths = sum(1 for entry in entries if entry.get("path_truncated") is True)
    receipt = {
        "limit": MAX_REHOST_REQUEST_LOG_ENTRIES,
        "retained": len(entries),
        "dropped": min(dropped, 1_000_000_000),
        "truncated_paths": truncated_paths,
        "truncated": dropped > 0 or truncated_paths > 0,
        "proxy_denied": sum(
            1 for entry in entries if entry.get("served") == "proxy-denied"
        ),
    }
    activity = project_server_request_activity(entries)
    unserved = grade_unserved_requests(entries)
    if dropped:
        activity.update(
            {
                "status": "unverifiable",
                "truncated": True,
                "retained_requests": len(entries),
                "dropped_requests": min(dropped, 1_000_000_000),
            }
        )
        unserved.update(
            {
                "status": "unverifiable",
                "log_truncated": True,
                "dependencies_complete": None,
                "note": (
                    "the bounded loopback request log dropped entries; retained "
                    "missing-stage rows are incomplete and cannot support absence"
                ),
            }
        )
    return entries, activity, unserved, receipt


def grade_ambient_input(
    startup: dict[str, Any] | None, input_profile: str
) -> dict[str, Any]:
    """Did anything drive this arm that the run did not ask for?

    A headed arm is a real window on a real desktop. A mouse crossing it delivers
    trusted events, and a collector that counts event authenticity acts on them,
    so the arm measures the operator as well as the script. This was found rather
    than anticipated: one arm reported 128 attributable names where three later
    arms of the same bytes reported 121, and the seven extra were all MouseEvent,
    activeElement and form-constructor names. Both runs recorded
    ``input_profile: "none"`` and a clean subtraction.

    Contamination is reported, never corrected. A count is a fact about the run;
    deciding what a contaminated arm is worth is the reader's job.
    """
    if not isinstance(input_profile, str) or input_profile not in INPUT_PROFILES:
        raise ContractError("ambient-input grade has an invalid input profile")
    if startup is not None and not isinstance(startup, dict):
        raise ContractError("ambient-input grade startup must be an object or null")
    if startup is None:
        return {"contaminated": None, "reasons": ["startup probe did not answer"]}
    if startup.get("probe_error") is not None:
        return {"contaminated": None, "reasons": ["startup probe did not answer"]}
    ambient_value = startup.get("ambient_input")
    ambient = (
        {
            key: min(value, 1_000_000)
            for key, value in ambient_value.items()
            if isinstance(key, str)
            and key in AMBIENT_INPUT_EVENT_NAMES
            and isinstance(value, int)
            and not isinstance(value, bool)
            and value >= 0
        }
        if isinstance(ambient_value, dict)
        else {}
    )
    if not _valid_startup_ambient_witness(ambient_value):
        return {
            "contaminated": None,
            "events": ambient,
            "reasons": ["startup ambient-input witness is missing or invalid"],
        }
    if not ambient:
        return {"contaminated": False, "events": {}, "reasons": []}
    if input_profile != "none":
        # The probe drives trusted input through the browser's real pipeline, so
        # these counts are expected and are evidence the probe worked.
        return {
            "contaminated": False,
            "events": ambient,
            "reasons": ["input probe drove this arm deliberately"],
        }
    total = sum(ambient.values())
    return {
        "contaminated": True,
        "events": ambient,
        "reasons": [
            f"{total} trusted input event(s) arrived in an arm that drove none: "
            f"{', '.join(f'{k}={v}' for k, v in sorted(ambient.items()))}"
        ],
    }


def grade_collector_startup(
    startup: dict[str, Any] | None,
    attributable_events: int,
    execution_context_counts: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Did the collector run, and if not, say so instead of reporting a surface.

    An offline rehost drives a bare page. That fully exercises a collector which
    starts itself on load -- Akamai's web pin installs ``bmak`` and reaches 128 API
    names with no help -- and it cannot exercise one that waits to be driven.
    Kasada's client publishes exactly ``{configure, isReady}``, makes no network
    request at all, and answers ``isReady() === false`` until the protected page
    calls ``configure``. Both produce a surface; only one of them is a measurement
    of the collector.

    The verdict is deliberately conservative: ``started`` only when there is
    positive evidence, and ``unknown`` when the readback failed, so a missing probe
    never upgrades itself into a claim.
    """
    if startup is not None and not isinstance(startup, dict):
        raise ContractError("collector-startup grade must receive an object or null")
    if (
        isinstance(attributable_events, bool)
        or not isinstance(attributable_events, int)
        or attributable_events < 0
    ):
        raise ContractError("collector-startup attributable events are invalid")
    if execution_context_counts is not None and not isinstance(
        execution_context_counts, dict
    ):
        raise ContractError("collector-startup execution contexts are invalid")
    if startup is None:
        return {"started": None, "reasons": ["startup probe did not answer"]}
    if startup.get("probe_error") is not None:
        blocked = startup.get("renderer_blocked")
        target_status = startup.get("browser_target_status")
        if blocked is True and (target_status is None or target_status == "present"):
            detail = (
                " -- the browser process still exposed the exact managed page, "
                "so its renderer was still holding the main thread and this arm "
                "needed a longer dwell"
            )
        elif target_status == "present":
            detail = (
                " -- the browser process still exposed the exact managed page, "
                "but the page command did not fail with a response timeout, so "
                "renderer state is unknown"
            )
        elif target_status == "absent":
            detail = (
                " -- the browser process answered but the exact managed page was "
                "absent, so this arm's surface is not evidence"
            )
        elif target_status is None and blocked is False:
            # Historical documents did not distinguish an absent managed page
            # from an endpoint that could not be queried.
            detail = (
                " -- the historical browser diagnostic was negative, so this "
                "arm's surface is not evidence"
            )
        else:
            detail = (
                " -- the browser-process target diagnostic was unavailable"
                if isinstance(target_status, str)
                and target_status in {"unreachable", "invalid-response"}
                else ""
            )
        raw_probe_error = startup["probe_error"]
        probe_error = _redact_diagnostic(raw_probe_error)
        safe_prefix = "startup probe failed: "
        if (
            isinstance(raw_probe_error, str)
            and len(raw_probe_error) <= 128
            and raw_probe_error.startswith(safe_prefix)
        ):
            safe_detail = raw_probe_error[len(safe_prefix):]
            if _redact_diagnostic(safe_detail) == safe_detail:
                probe_error = raw_probe_error
        prefix = (
            ""
            if isinstance(probe_error, str)
            and probe_error.startswith("startup probe failed:")
            else "startup probe failed: "
        )
        result = {
            "started": None,
            "reasons": [f"{prefix}{probe_error}{detail}"],
        }
        if blocked is None or isinstance(blocked, bool):
            result["renderer_blocked"] = blocked
        if isinstance(target_status, str) and target_status in {
            "present",
            "absent",
            "unreachable",
            "invalid-response",
        }:
            result["browser_target_status"] = target_status
        title_matches = startup.get("browser_target_title_matches")
        if title_matches is None or isinstance(title_matches, bool):
            if "browser_target_title_matches" in startup:
                result["browser_target_title_matches"] = title_matches
        return result
    reasons: list[str] = []
    raw_errors = startup.get("uncaught_errors")
    raw_rejections = startup.get("unhandled_rejections")
    raw_vendor = startup.get("vendor_globals")
    errors = (
        [_redact_diagnostic(value) for value in raw_errors[:16]]
        if isinstance(raw_errors, list)
        else []
    )
    rejections = (
        [_redact_diagnostic(value) for value in raw_rejections[:16]]
        if isinstance(raw_rejections, list)
        else []
    )
    vendor = _sanitize_startup_document(
        {"vendor_globals": raw_vendor if isinstance(raw_vendor, list) else []}
    )["vendor_globals"]
    raw_ready = startup.get("vendor_reports_ready")
    ready = (
        raw_ready
        if raw_ready is None or isinstance(raw_ready, bool) or raw_ready == "threw"
        else None
    )

    def worker_contexts() -> int:
        if not isinstance(execution_context_counts, dict):
            return 0
        counts = []
        for namespace in ("generated_binding", "native"):
            namespace_counts = execution_context_counts.get(namespace)
            value = (
                namespace_counts.get("worker")
                if isinstance(namespace_counts, dict)
                else None
            )
            if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
                counts.append(value)
        # The namespaces identify the same logical topology differently and must
        # not be summed. Either one observing a worker is sufficient evidence.
        return max(counts, default=0)

    if errors:
        reasons.append(
            f"the script raised {len(errors)} uncaught error(s): {errors[0]}"
        )
    if rejections:
        reasons.append(f"{len(rejections)} unhandled rejection(s): {rejections[0]}")
    if ready is False:
        reasons.append(
            f"the client reports it is not ready ({vendor[0] if vendor else 'vendor global'}"
            ".isReady() === false), which is what an unconfigured host-driven "
            "collector reports"
        )
    if ready == "threw":
        reasons.append("the client readiness check threw; collector state is unknown")
    if not vendor and attributable_events == 0:
        reasons.append("no vendor global appeared and no API surface was attributable")
    if "__anubisBooted" in vendor and execution_context_counts is not None:
        if worker_contexts() == 0:
            reasons.append(
                "__anubisBooted is a module-load marker, but no worker execution "
                "context appeared; the challenge algorithm did not start"
            )

    witness_complete = bool(
        isinstance(raw_errors, list)
        and isinstance(raw_rejections, list)
        and _valid_startup_vendor_witness(raw_vendor)
        and "vendor_reports_ready" in startup
        and (raw_ready is None or type(raw_ready) is bool or raw_ready == "threw")
    )
    if not reasons and not witness_complete:
        reasons.append("startup witness is incomplete or invalid")
        started = None
    else:
        started = not reasons
    return {
        "started": started,
        "reasons": reasons,
        "vendor_globals": vendor,
        "uncaught_errors": errors,
        "unhandled_rejections": rejections,
        "vendor_reports_ready": ready,
    }


def build_hook_payload(
    hook_mode: str = "off", target_names: tuple[str, ...] = ()
) -> bytes:
    """Bytes served at :data:`HOOK_SCRIPT_PATH` for a given mode.

    ``target_names`` restricts the instrument to a subset, which is what makes a
    perturbation bisectable: install half the wrappers, re-measure, halve again.
    An unknown name is an error rather than a silent no-op -- a typo that quietly
    installs nothing would read as "this subset does not trigger it".
    """
    if not isinstance(hook_mode, str) or hook_mode not in HOOK_MODES:
        raise ContractError(f"hook mode must be one of {HOOK_MODES}")
    if (
        not isinstance(target_names, tuple)
        or len(target_names) > 128
        or any(not isinstance(name, str) for name in target_names)
    ):
        raise ContractError("hook target names must be a bounded tuple of strings")
    from .argument_capture import HOOK_TARGETS, build_hook_script

    known = {t.name for t in HOOK_TARGETS}
    unknown = sorted(set(target_names) - known)
    if unknown:
        raise ContractError("unknown hook target name")
    if hook_mode != "on":
        return b""
    if not target_names:
        return build_hook_script().encode("utf-8")
    subset = tuple(t for t in HOOK_TARGETS if t.name in set(target_names))
    return build_hook_script(subset).encode("utf-8")


def build_rehost_contract() -> dict[str, Any]:
    """Bind method-critical built-in harness bytes and observer semantics.

    Configuration values such as DOM profile, hook mode, input profile, prelude,
    driver, script path and browser flags are already separate method axes. This
    binds the *catalogue implementation* behind those choices, so an intentional
    profile A/B changes only its declared axis while a later built-in harness edit
    invalidates both. Only digests and public contract labels leave this function.
    """
    hook_catalog = build_hook_payload("on", ())
    page_material = "\n".join(
        (
            PAGE_TITLE,
            HOOK_SCRIPT_PATH,
            _PAGE_HTML,
            _PAGE_HTML_INLINE,
            _STARTUP_WITNESS,
            *(f"{name}\n{DOM_PROFILES[name]}" for name in sorted(DOM_PROFILES)),
        )
    ).encode("utf-8")
    observer_material = "\n".join((_GEOMETRY_JS, _STARTUP_JS, _READY_JS)).encode(
        "utf-8"
    )
    input_catalog = json.dumps(
        {
            profile: {
                "contract": INPUT_PROBE_CONTRACTS[profile],
                "events": [] if profile == "none" else _input_probe_events(profile),
            }
            for profile in INPUT_PROFILES
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    components = {
        "page_sha256": hashlib.sha256(page_material).hexdigest(),
        "hook_catalog_sha256": hashlib.sha256(hook_catalog).hexdigest(),
        "observer_js_sha256": hashlib.sha256(observer_material).hexdigest(),
        "input_probe_catalog_sha256": hashlib.sha256(input_catalog).hexdigest(),
        "observer_sequence": OBSERVER_SEQUENCE_CONTRACT,
        "resource_intent_contract": RESOURCE_INTENT_CONTRACT,
    }
    canonical = json.dumps(components, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )
    return {
        "schema": REHOST_CONTRACT_SCHEMA,
        "sha256": hashlib.sha256(canonical).hexdigest(),
        **components,
    }


def _handler(
    script_bytes: bytes,
    log: _RequestLog,
    dom_profile: str = "minimal",
    script_path: str = DEFAULT_SCRIPT_PATH,
    hook_mode: str = "off",
    hook_target_names: tuple[str, ...] = (),
    stage_routes: tuple[tuple[str, Path | bytes], ...] = (),
    inline_script: bool = False,
    declared_script_url: str | None = None,
    prelude_js: str | None = None,
) -> type[BaseHTTPRequestHandler]:
    page = build_rehost_page(
        dom_profile,
        script_path,
        hook_mode,
        inline_source=script_bytes if inline_script else None,
        declared_script_url=declared_script_url,
        prelude_js=prelude_js,
    )
    hook_bytes = build_hook_payload(hook_mode, hook_target_names)
    # Read once, at construction: a stage that vanished mid-run would otherwise
    # turn into an empty body and read as the collector simply stopping.
    if not isinstance(stage_routes, tuple) or len(stage_routes) > MAX_STAGE_ROUTES:
        raise ContractError("stage routes must be a bounded tuple")
    stage_snapshots: list[tuple[str, bytes]] = []
    stage_total = 0
    for item in stage_routes:
        if not isinstance(item, tuple) or len(item) != 2:
            raise ContractError("each stage route must be a prefix/source pair")
        prefix, source = item
        if type(source) is bytes:
            payload = source
        elif isinstance(source, Path):
            payload = _read_stable_regular_bytes(
                source,
                maximum=MAX_STAGE_BYTES,
                label="stage route source",
            )
        else:
            raise ContractError("stage route source must be Path or bytes")
        stage_total += len(payload)
        if stage_total > MAX_STAGE_BYTES:
            raise ContractError("staged scripts exceed the aggregate byte limit")
        stage_snapshots.append((_validate_stage_prefix(prefix), payload))
    stages = tuple(stage_snapshots)

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def _send(self, payload: bytes, content_type: str) -> None:
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def _send_empty_status(self, status: int) -> None:
            self.send_response(status)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def _record(
            self,
            method: str,
            path: str,
            body_bytes: int,
            *,
            served: str,
            body_sha256_16: str | None = None,
        ) -> None:
            # Route on the parsed path but derive query-key evidence from the raw
            # request target. Values are never copied into the request log. A
            # denied proxy target is wholly untrusted and may encode secrets even
            # in query *names*, so retain only the fixed local sentinel for it.
            log.add(
                method,
                path,
                body_bytes,
                served=served,
                request_target=None if served == "proxy-denied" else self.path,
                body_sha256_16=body_sha256_16,
            )

        def _deny_absolute_proxy_request(self, method: str) -> bool:
            try:
                target = urlsplit(self.path)
                absolute = bool(target.scheme or target.netloc)
            except (UnicodeError, ValueError):
                # A malformed absolute URI is still a proxy target. Do not let a
                # parsing failure fall through to an owned-origin route.
                absolute = bool(re.match(r"^[A-Za-z][A-Za-z0-9+.-]*:", self.path))
            if not absolute:
                return False
            retained_method = method if method in PROXY_DENIED_METHODS else "OTHER"
            self._record(
                retained_method,
                "/<proxy-http>",
                0,
                served="proxy-denied",
            )
            self.close_connection = True
            self._send_empty_status(502)
            return True

        def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
            if self._deny_absolute_proxy_request("GET"):
                return
            target = urlsplit(self.path)
            path = target.path or "/"
            if path == "/":
                self._record("GET", path, 0, served="page")
                self._send(page, "text/html; charset=utf-8")
            elif path == script_path:
                self._record("GET", path, 0, served="sample")
                self._send(script_bytes, "text/javascript; charset=utf-8")
            elif hook_mode != "off" and path == HOOK_SCRIPT_PATH:
                self._record("GET", path, 0, served="hook")
                self._send(hook_bytes, "text/javascript; charset=utf-8")
            else:
                # A staged second script, served at the path the client asked for.
                # Longest prefix wins, so a more specific route can sit underneath
                # a broader one.
                match = max(
                    (item for item in stages if path.startswith(item[0])),
                    key=lambda item: len(item[0]),
                    default=None,
                )
                if match is not None:
                    self._record("GET", path, 0, served="stage")
                    self._send(match[1], "text/javascript; charset=utf-8")
                else:
                    # Answer the sample's own probes so it proceeds instead of
                    # erroring -- but record that nothing was actually served.
                    # A collector fetching its own next stage looks exactly like
                    # this, and an empty 200 lets it fail quietly further on.
                    self._record("GET", path, 0, served="empty")
                    self._send(b"", "application/octet-stream")

        def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
            if self._deny_absolute_proxy_request("POST"):
                return
            target = urlsplit(self.path)
            path = target.path or "/"
            if self.headers.get_all("Transfer-Encoding", []):
                self._record("POST", path, 0, served="unsupported-framing")
                self.close_connection = True
                self._send_empty_status(501)
                return
            lengths = self.headers.get_all("Content-Length", [])
            if (
                len(lengths) != 1
                or len(lengths[0]) > 20
                or re.fullmatch(r"0|[1-9][0-9]*", lengths[0]) is None
            ):
                self._record("POST", path, 0, served="invalid-body-length")
                self.close_connection = True
                self._send_empty_status(400)
                return
            length = int(lengths[0])
            if length > MAX_REHOST_POST_BODY_BYTES:
                self._record("POST", path, length, served="body-too-large")
                self.close_connection = True
                self._send_empty_status(413)
                return
            connection = getattr(self, "connection", None)
            deadline = time.monotonic() + REHOST_BODY_READ_TIMEOUT_SECONDS
            consumed = 0
            body_digest = hashlib.sha256()
            read_timed_out = False
            while consumed < length:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    read_timed_out = True
                    break
                try:
                    if connection is not None:
                        connection.settimeout(remaining)
                    chunk = self.rfile.read(
                        min(REQUEST_BODY_CHUNK_BYTES, length - consumed)
                    )
                except (OSError, TimeoutError):
                    read_timed_out = True
                    break
                if not chunk:
                    break
                consumed += len(chunk)
                body_digest.update(chunk)
                if time.monotonic() >= deadline:
                    read_timed_out = True
                    break
            if read_timed_out:
                self._record("POST", path, consumed, served="body-read-timeout")
                self.close_connection = True
                self._send_empty_status(408)
                return
            if consumed != length:
                self._record("POST", path, consumed, served="incomplete-body")
                self.close_connection = True
                self._send_empty_status(400)
                return
            self._record(
                "POST",
                path,
                consumed,
                served="post-ack",
                body_sha256_16=body_digest.hexdigest()[:16],
            )
            self._send(b"{}", "application/json")

        def do_CONNECT(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
            # The CONNECT authority can contain an external host or local service
            # port. Record only a fixed sentinel and never open an upstream socket.
            self._record("CONNECT", "/<proxy-connect>", 0, served="proxy-denied")
            self.close_connection = True
            self._send_empty_status(502)

        def send_error(
            self,
            code: int,
            message: str | None = None,
            explain: str | None = None,
        ) -> None:
            # BaseHTTPRequestHandler routes every method without a do_* handler
            # here. Intercept an absolute-form proxy request before its generic
            # 501 so HEAD/PUT/PATCH/DELETE/OPTIONS/TRACE and custom Fetch methods
            # receive the same deny receipt. Unknown method tokens collapse to
            # OTHER rather than becoming a page-controlled retained value.
            command = getattr(self, "command", "OTHER")
            if code == 501 and self._deny_absolute_proxy_request(command):
                return
            super().send_error(code, message, explain)

        def log_message(self, fmt: str, *args: object) -> None:
            return

    return Handler


# ---------------------------------------------------------------- trace analysis


def analyse_observation_trace(trace_jsonl: Path) -> dict[str, Any]:
    """Reduce a normalized trace to a redaction-safe API-surface vector."""

    by_name: Counter[str] = Counter()
    by_component: Counter[str] = Counter()
    script_attributed_by_name: Counter[str] = Counter()
    script_execution_complete = 0
    script_execution_open = 0
    max_script_execution_duration_ns: int | None = None
    contexts: dict[str, set[str]] = defaultdict(set)
    execution_context_ids: dict[str, dict[str, set[str]]] = {
        "generated_binding": {"frame": set(), "worker": set()},
        "native": {"frame": set(), "worker": set()},
    }
    attributable = 0
    request_classes: Counter[str] = Counter()
    request_methods: Counter[str] = Counter()
    fetch_target_scopes: Counter[str] = Counter()
    fetch_target_scope_unclassified = 0

    def accumulate(event: dict[str, Any]) -> None:
        nonlocal attributable, script_execution_complete, script_execution_open
        nonlocal max_script_execution_duration_ns, fetch_target_scope_unclassified
        name = event.get("event") or {}
        key = f"{name.get('category')}.{name.get('name')}"
        component = (event.get("provenance") or {}).get("component") or "unknown"
        by_name[key] += 1
        by_component[component] += 1

        if name == {"category": "execution", "name": "script.execution"}:
            detail = event.get("detail") or {}
            completion = detail.get("completion")
            duration = detail.get("duration_ns")
            if completion == "open" and duration is None:
                script_execution_open += 1
            elif (
                completion == "complete"
                and isinstance(duration, int)
                and not isinstance(duration, bool)
                and 0 <= duration <= MAX_TRACE_EVENT_DURATION_NS
            ):
                script_execution_complete += 1
                max_script_execution_duration_ns = max(
                    max_script_execution_duration_ns or 0, duration
                )
            else:
                raise ContractError("script execution trace detail is invalid")

        execution = event.get("execution") or {}
        generated_script_attributed = component == GENERATED_COMPONENT and isinstance(
            execution.get("script_id"), str
        )
        if component != GENERATED_COMPONENT or generated_script_attributed:
            attributable += 1
        if generated_script_attributed:
            script_attributed_by_name[key] += 1
        namespace = (
            "generated_binding" if component == GENERATED_COMPONENT else "native"
        )
        if execution.get("frame_id") is not None:
            contexts[key].add("frame")
            execution_context_ids[namespace]["frame"].add(execution["frame_id"])
        if execution.get("worker_id") is not None:
            contexts[key].add("worker")
            execution_context_ids[namespace]["worker"].add(execution["worker_id"])

        request = event.get("request")
        if isinstance(request, dict):
            url_class = request.get("url_class")
            if isinstance(url_class, str):
                request_classes[url_class] += 1
            method = request.get("method")
            if isinstance(method, str):
                request_methods[method] += 1
            target_scope = request.get("target_scope")
            if isinstance(target_scope, str):
                fetch_target_scopes[target_scope] += 1
            else:
                # Pre-B317 normalized traces did not carry the native target
                # classification. Absence is unknown, never evidence of safety.
                fetch_target_scope_unclassified += 1

    # Validation and reduction observe one file identity and one event stream.
    # A late validation failure raises before any report is returned.
    summary = scan_validated_trace(trace_jsonl, accumulate)
    total = sum(by_name.values())
    return {
        "trace_summary": summary,
        "total_events": total,
        "attributable_events": attributable,
        "attributable_fraction": round(attributable / total, 6) if total else 0.0,
        "distinct_api_names": len(by_name),
        "events_by_name": dict(by_name.most_common()),
        "script_attributed_events": sum(script_attributed_by_name.values()),
        "script_attributed_events_by_name": dict(
            script_attributed_by_name.most_common()
        ),
        "script_execution": {
            "total": script_execution_complete + script_execution_open,
            "complete": script_execution_complete,
            "open": script_execution_open,
            "max_complete_duration_ns": max_script_execution_duration_ns,
        },
        "events_by_component": dict(by_component.most_common()),
        "context_coverage": {k: sorted(v) for k, v in sorted(contexts.items())},
        "execution_context_counts": {
            namespace: {kind: len(values) for kind, values in sorted(by_kind.items())}
            for namespace, by_kind in sorted(execution_context_ids.items())
        },
        "execution_context_count_note": (
            "native and generated-binding context ids use separate namespaces; "
            "counts describe each plane independently and must not be summed"
        ),
        "request_methods": dict(request_methods.most_common()),
        "request_classes": dict(request_classes.most_common()),
        "distinct_request_classes": len(request_classes),
        "fetch_target_scope": {
            "coverage": (
                "complete" if fetch_target_scope_unclassified == 0 else "unknown"
            ),
            "requests": (
                sum(fetch_target_scopes.values()) + fetch_target_scope_unclassified
            ),
            "loopback": fetch_target_scopes["loopback"],
            "external": fetch_target_scopes["external"],
            "non_network": fetch_target_scopes["non-network"],
            "unclassified": fetch_target_scope_unclassified,
        },
    }


def subtract_resource_intents(
    arm: dict[str, Any] | None, control: dict[str, Any] | None
) -> dict[str, Any]:
    """Attribute redacted DOM resource intents against the empty-script control."""
    arm = _sanitize_resource_intent_report(arm)
    control = _sanitize_resource_intent_report(control)
    arm_status = (
        "truncated"
        if arm.get("status") == "ok" and arm.get("truncated")
        else "missing"
        if arm.get("status") == "ok" and not isinstance(arm.get("intents"), list)
        else arm.get("status", "missing")
    )
    control_status = (
        "truncated"
        if control.get("status") == "ok" and control.get("truncated")
        else "missing"
        if control.get("status") == "ok"
        and not isinstance(control.get("intents"), list)
        else control.get("status", "missing")
    )
    if arm_status != "ok" or control_status != "ok":
        return {
            "status": "unverifiable",
            "arm_status": arm_status,
            "control_status": control_status,
            "only_in_arm": [],
            "only_in_control": [],
            "non_claim": (
                "both DOM snapshots must succeed without truncation before intent "
                "is attributable"
            ),
        }

    def indexed(report: dict[str, Any]) -> dict[str, dict[str, Any]]:
        rows = {}
        for row in report.get("intents") or []:
            if not isinstance(row, dict):
                continue
            identity = {key: value for key, value in row.items() if key != "count"}
            key = json.dumps(identity, sort_keys=True, separators=(",", ":"))
            rows[key] = row
        return rows

    arm_rows, control_rows = indexed(arm), indexed(control)
    only_arm = sorted(set(arm_rows) - set(control_rows))
    only_control = sorted(set(control_rows) - set(arm_rows))
    shared = sorted(set(arm_rows) & set(control_rows))

    def occurrences(row: dict[str, Any]) -> int:
        value = row.get("count", 1)
        return value if isinstance(value, int) and not isinstance(value, bool) else 1

    multiplicity_deltas = []
    control_excess_multiplicity = False
    for key in shared:
        arm_occurrences = occurrences(arm_rows[key])
        control_occurrences = occurrences(control_rows[key])
        if arm_occurrences == control_occurrences:
            continue
        if control_occurrences > arm_occurrences:
            control_excess_multiplicity = True
        identity = {
            name: value for name, value in arm_rows[key].items() if name != "count"
        }
        multiplicity_deltas.append(
            {
                **identity,
                "arm_occurrences": arm_occurrences,
                "control_occurrences": control_occurrences,
            }
        )
    result = {
        "status": "ok",
        "arm_count": len(arm_rows),
        "control_count": len(control_rows),
        "shared_count": len(shared),
        "arm_attribute_count": sum(occurrences(row) for row in arm_rows.values()),
        "control_attribute_count": sum(
            occurrences(row) for row in control_rows.values()
        ),
        "only_in_arm": [arm_rows[key] for key in only_arm],
        "only_in_control": [control_rows[key] for key in only_control],
        "multiplicity_deltas": multiplicity_deltas,
        "clean_subtraction": not only_control and not control_excess_multiplicity,
        "non_claim": (
            "DOM attributes present at capture time; not proof that a request was "
            "sent, reached DNS, or received a response"
        ),
    }
    return result


def subtract_request_activity(arm: Any, control: Any) -> dict[str, Any]:
    """Attribute redacted loopback request shapes against the control arm."""
    arm = _sanitize_request_activity_report(arm)
    control = _sanitize_request_activity_report(control)
    if (
        arm.get("status") != "ok"
        or control.get("status") != "ok"
        or not isinstance(arm.get("rows"), list)
        or not isinstance(control.get("rows"), list)
        or any(
            not isinstance(row.get("count"), int)
            or isinstance(row.get("count"), bool)
            or row["count"] < 1
            for row in [*(arm.get("rows") or []), *(control.get("rows") or [])]
        )
        or arm.get("truncated") is True
        or control.get("truncated") is True
    ):
        return _sanitize_request_activity_report(
            {
                "status": "unverifiable",
                "only_in_arm": [],
                "only_in_control": [],
            }
        )

    def key_of(row: dict[str, Any]) -> str:
        identity = {
            key: row[key]
            for key in (
                "method",
                "served",
                "path_segment_lengths",
                "path_segments_truncated",
                "query_names",
                "query_names_truncated",
            )
        }
        return json.dumps(identity, sort_keys=True, separators=(",", ":"))

    def indexed(report: dict[str, Any]) -> dict[str, dict[str, Any]]:
        return {
            key_of(row): row
            for row in report.get("rows") or []
            if isinstance(row, dict)
        }

    arm_rows, control_rows = indexed(arm), indexed(control)
    only_arm: list[dict[str, Any]] = []
    only_control: list[dict[str, Any]] = []
    shared_shapes = 0
    for key in sorted(set(arm_rows) | set(control_rows)):
        arm_row, control_row = arm_rows.get(key), control_rows.get(key)
        arm_count = int((arm_row or {}).get("count") or 0)
        control_count = int((control_row or {}).get("count") or 0)
        if arm_row is not None and control_row is not None:
            shared_shapes += 1
        if arm_count > control_count and arm_row is not None:
            attributed = dict(arm_row)
            # A digest is tied to a concrete complete body, not merely to the
            # redacted request shape. If the control emitted the same shape we
            # cannot know which arm digest belongs to the count delta without
            # retaining bodies, so omit the digest multiset rather than
            # misattribute it.
            if control_count:
                attributed.pop("body_sha256_16_counts", None)
            only_arm.append(
                {
                    **attributed,
                    "count": arm_count - control_count,
                    "arm_count": arm_count,
                    "control_count": control_count,
                }
            )
        elif control_count > arm_count and control_row is not None:
            attributed = dict(control_row)
            if arm_count:
                attributed.pop("body_sha256_16_counts", None)
            only_control.append(
                {
                    **attributed,
                    "count": control_count - arm_count,
                    "arm_count": arm_count,
                    "control_count": control_count,
                }
            )
    return _sanitize_request_activity_report(
        {
            "status": "ok",
            "arm_requests": sum(
                int(row.get("count") or 0) for row in arm_rows.values()
            ),
            "control_requests": sum(
                int(row.get("count") or 0) for row in control_rows.values()
            ),
            "shared_shapes": shared_shapes,
            "only_in_arm": only_arm,
            "only_in_control": only_control,
            "clean_subtraction": not only_control,
        }
    )


def _validated_analysis_surface(
    document: dict[str, Any], role: str
) -> tuple[dict[str, int], dict[str, list[str]], dict[str, int], bool]:
    """Validate the trace-reduced name/count plane before subtraction."""
    analysis = document.get("analysis")
    if not isinstance(analysis, dict):
        raise ContractError(f"{role} analysis must be an object")
    events = analysis.get("events_by_name")
    if not isinstance(events, dict):
        raise ContractError(f"{role} analysis events_by_name must be a count map")
    try:
        names = _surface_name_set({"only_in_arm": events})
    except ContractError as exc:
        raise ContractError(
            f"{role} analysis events_by_name is invalid: {exc}"
        ) from exc
    if any(
        isinstance(count, bool)
        or not isinstance(count, int)
        or count < 1
        or count > 1_000_000_000
        for count in events.values()
    ):
        raise ContractError(
            f"{role} analysis event counts must be integers from 1 to 1,000,000,000"
        )

    raw_coverage = analysis.get("context_coverage")
    if not isinstance(raw_coverage, dict):
        raise ContractError(f"{role} analysis context_coverage must be an object")
    coverage: dict[str, list[str]] = {}
    for name in names:
        contexts = raw_coverage.get(name, [])
        if (
            not isinstance(contexts, list)
            or any(
                not isinstance(context, str) or context not in {"frame", "worker"}
                for context in contexts
            )
            or len(set(contexts)) != len(contexts)
        ):
            raise ContractError(
                f"{role} analysis context_coverage contains an invalid context list"
            )
        coverage[name] = sorted(contexts)
    script_surface_value = analysis.get("script_attributed_events_by_name")
    script_total_value = analysis.get("script_attributed_events")
    script_attribution_available = (
        script_surface_value is not None or script_total_value is not None
    )
    if not script_attribution_available:
        return dict(events), coverage, {}, False
    if not isinstance(script_surface_value, dict):
        raise ContractError(
            f"{role} analysis script_attributed_events_by_name must be a count map"
        )
    try:
        script_names = _surface_name_set({"only_in_arm": script_surface_value})
    except ContractError as exc:
        raise ContractError(
            f"{role} analysis script-attributed surface is invalid: {exc}"
        ) from exc
    if any(
        isinstance(count, bool)
        or not isinstance(count, int)
        or count < 1
        or count > 1_000_000_000
        or name not in events
        or count > events[name]
        for name, count in script_surface_value.items()
    ):
        raise ContractError(
            f"{role} analysis script-attributed counts are inconsistent"
        )
    if (
        isinstance(script_total_value, bool)
        or not isinstance(script_total_value, int)
        or not 0 <= script_total_value <= 1_000_000_000
        or script_total_value != sum(script_surface_value.values())
    ):
        raise ContractError(f"{role} analysis script-attributed total is inconsistent")
    return (
        dict(events),
        coverage,
        {name: script_surface_value[name] for name in script_names},
        True,
    )


def _sanitize_script_execution_summary(
    value: Any, *, label: str
) -> dict[str, int | None] | None:
    if value is None:
        return None
    if not isinstance(value, dict) or set(value) != {
        "total",
        "complete",
        "open",
        "max_complete_duration_ns",
    }:
        raise ContractError(f"{label} script execution summary fields are invalid")
    total = value.get("total")
    complete = value.get("complete")
    open_count = value.get("open")
    duration = value.get("max_complete_duration_ns")
    if (
        any(
            isinstance(item, bool)
            or not isinstance(item, int)
            or not 0 <= item <= 1_000_000_000
            for item in (total, complete, open_count)
        )
        or total != complete + open_count
    ):
        raise ContractError(f"{label} script execution counts are invalid")
    if complete == 0:
        if duration is not None:
            raise ContractError(f"{label} script execution duration is inconsistent")
    elif (
        isinstance(duration, bool)
        or not isinstance(duration, int)
        or not 0 <= duration <= MAX_TRACE_EVENT_DURATION_NS
    ):
        raise ContractError(f"{label} script execution duration is invalid")
    return {
        "total": total,
        "complete": complete,
        "open": open_count,
        "max_complete_duration_ns": duration,
    }


def _validated_script_execution_summary(
    document: dict[str, Any], role: str
) -> dict[str, int | None] | None:
    analysis = document.get("analysis")
    if not isinstance(analysis, dict):
        raise ContractError(f"{role} analysis must be an object")
    return _sanitize_script_execution_summary(
        analysis.get("script_execution"), label=role
    )


_SUBTRACTION_NON_CLAIMS = (
    "control subtraction attributes API names in a lab rehost only",
    "not an acceptance, bypass, evasion, or bot-score claim",
)


def subtract_control(arm: dict[str, Any], control: dict[str, Any]) -> dict[str, Any]:
    """Attribute an arm's API surface by subtracting an empty-script control.

    ``only_in_control`` is reported rather than discarded: a non-empty value means
    the two runs were not comparable and the subtraction must not be trusted.
    """
    for document, role in ((arm, "arm"), (control, "control")):
        if not isinstance(document, dict):
            raise ContractError(f"{role} observation must be an object")
        if document.get("schema") != OBSERVATION_SCHEMA:
            raise ContractError(f"{role} is not a {OBSERVATION_SCHEMA} document")
        if "analysis" not in document:
            raise ContractError(f"{role} has no analysis (launch failed?)")
    arm_argument_capture = arm.get("argument_capture")
    if arm_argument_capture is not None:
        from .argument_capture import validate_capture

        try:
            validate_capture(arm_argument_capture)
        except ContractError as exc:
            raise ContractError("arm argument capture is invalid") from exc
    arm_rehost_contract = _sanitize_rehost_contract(arm.get("rehost_contract"))
    control_rehost_contract = _sanitize_rehost_contract(control.get("rehost_contract"))
    if arm_rehost_contract != control_rehost_contract:
        raise ContractError(
            "arm and control use different rehost contracts; subtraction would "
            "attribute harness drift to the product script"
        )

    (
        arm_names,
        coverage,
        arm_script_names,
        arm_script_attribution_available,
    ) = _validated_analysis_surface(arm, "arm")
    (
        control_names,
        _control_coverage,
        control_script_names,
        control_script_attribution_available,
    ) = _validated_analysis_surface(control, "control")
    arm_script_execution = _validated_script_execution_summary(arm, "arm")
    control_script_execution = _validated_script_execution_summary(control, "control")
    _verified_observation_receipt(arm)
    _verified_observation_receipt(control)
    arm_observation_receipt = arm.get("observation_receipt_sha256")
    control_observation_receipt = control.get("observation_receipt_sha256")
    input_observation_receipts_complete = bool(
        isinstance(arm_observation_receipt, str)
        and isinstance(control_observation_receipt, str)
    )
    input_observation_receipts_comparable = (
        None
        if arm_observation_receipt is None and control_observation_receipt is None
        else input_observation_receipts_complete
    )

    only_in_arm = {k: v for k, v in arm_names.items() if k not in control_names}
    only_in_control = {k: v for k, v in control_names.items() if k not in arm_names}
    script_only_in_arm: dict[str, int] = {}
    script_only_in_control: dict[str, int] = {}
    script_attribution_comparable = (
        arm_script_attribution_available and control_script_attribution_available
    )
    if script_attribution_comparable:
        for name in sorted(set(arm_script_names) | set(control_script_names)):
            arm_count = arm_script_names.get(name, 0)
            control_count = control_script_names.get(name, 0)
            if arm_count > control_count:
                delta = arm_count - control_count
                script_only_in_arm[name] = delta
                only_in_arm.setdefault(name, delta)
            elif control_count > arm_count:
                delta = control_count - arm_count
                script_only_in_control[name] = delta
                only_in_control.setdefault(name, delta)
    elevated = {
        k: {"arm": v, "control": control_names[k]}
        for k, v in arm_names.items()
        if k in control_names
        and v >= control_names[k] * 2
        and v - control_names[k] >= 3
    }
    arm_ready_expression = _ready_expression_metadata(arm)
    control_ready_expression = _ready_expression_metadata(control)
    ready_probe_comparable = arm_ready_expression == control_ready_expression
    (
        arm_control_method_comparable,
        arm_control_method_mismatches,
    ) = _reconciled_arm_control_method(arm, control)
    (
        driver_execution_complete,
        arm_driver_result,
        control_driver_result,
    ) = _reconciled_driver_execution(
        arm,
        control,
        current_required=arm_control_method_comparable is not None,
    )
    (
        arm_script_identity_coherent,
        arm_script_identity,
        arm_source_provenance,
        arm_capture_provenance,
    ) = _reconciled_script_identity(
        arm, current_required=arm_control_method_comparable is not None
    )
    (
        control_script_identity_coherent,
        control_script_identity,
        control_source_provenance,
        control_capture_provenance,
    ) = _reconciled_script_identity(
        control, current_required=arm_control_method_comparable is not None
    )
    script_identity_recorded = any(
        value is not None
        for value in (
            arm_script_identity_coherent,
            control_script_identity_coherent,
        )
    )
    script_identity_coherent: bool | None = None
    if script_identity_recorded:
        script_identity_coherent = (
            arm_script_identity_coherent is True
            and control_script_identity_coherent is True
        )
    arm_trace_evidence_coherent, arm_trace_evidence = _reconciled_trace_evidence(
        arm, current_required=arm_control_method_comparable is not None,
        surface_event_count=sum(arm_names.values()),
        surface_name_count=len(arm_names),
        surface_script_execution_count=arm_names.get("execution.script.execution", 0),
        surface_network_event_count=sum(
            count for name, count in arm_names.items() if name.startswith("network.")
        ),
    )
    control_trace_evidence_coherent, control_trace_evidence = (
        _reconciled_trace_evidence(
            control, current_required=arm_control_method_comparable is not None,
            surface_event_count=sum(control_names.values()),
            surface_name_count=len(control_names),
            surface_script_execution_count=control_names.get("execution.script.execution", 0),
            surface_network_event_count=sum(
                count
                for name, count in control_names.items()
                if name.startswith("network.")
            ),
        )
    )
    trace_evidence_recorded = any(
        value is not None
        for value in (
            arm_trace_evidence_coherent,
            control_trace_evidence_coherent,
        )
    )
    trace_evidence_coherent: bool | None = None
    if trace_evidence_recorded:
        trace_evidence_coherent = (
            arm_trace_evidence_coherent is True
            and control_trace_evidence_coherent is True
        )
    (
        await_method_comparable,
        arm_readiness_satisfied,
        arm_await_report,
        control_await_report,
    ) = _reconciled_await_method(arm, control)
    (
        input_method_comparable,
        arm_input_probe,
        control_input_probe,
    ) = _reconciled_input_method(arm, control)
    arm_ambient_input, arm_ambient_clean = _reconciled_ambient_input(arm)
    control_ambient_input, control_ambient_clean = _reconciled_ambient_input(control)
    ambient_recorded = "ambient_input" in arm or "ambient_input" in control
    ambient_input_clean: bool | None = None
    if ambient_recorded:
        ambient_input_clean = (
            arm_ambient_clean is True and control_ambient_clean is True
        )
    clean_name_subtraction = not only_in_control
    (
        collector_started,
        collector_startup,
        collector_startup_coherent,
    ) = _reconciled_collector_startup(
        arm, current_required=arm_control_method_comparable is not None
    )
    (
        _control_collector_started,
        control_collector_startup,
        control_collector_startup_coherent,
    ) = _reconciled_collector_startup(
        control, current_required=arm_control_method_comparable is not None
    )
    startup_derivation_recorded = any(
        value is not None
        for value in (
            collector_startup_coherent,
            control_collector_startup_coherent,
        )
    )
    startup_derivation_coherent: bool | None = None
    if startup_derivation_recorded:
        startup_derivation_coherent = (
            collector_startup_coherent is True
            and control_collector_startup_coherent is True
        )
    (
        dependencies_complete,
        arm_unserved,
        arm_rehost_receipts_coherent,
    ) = _reconciled_rehost_dependencies(arm)
    (
        control_dependencies_complete,
        _control_unserved,
        control_rehost_receipts_coherent,
    ) = _reconciled_rehost_dependencies(control)
    rehost_receipts_recorded = any(
        value is not None
        for value in (
            arm_rehost_receipts_coherent,
            control_rehost_receipts_coherent,
        )
    )
    rehost_receipts_coherent: bool | None = None
    if rehost_receipts_recorded:
        rehost_receipts_coherent = (
            arm_rehost_receipts_coherent is True
            and control_rehost_receipts_coherent is True
        )
    dependency_gate_passes = (
        "unserved_requests" not in arm or dependencies_complete is True
    )
    control_dependency_gate_passes = (
        "unserved_requests" not in control or control_dependencies_complete is True
    )
    arm_request_activity, arm_activity_coherent = _reconciled_request_activity(
        arm, arm_rehost_receipts_coherent
    )
    control_request_activity, control_activity_coherent = _reconciled_request_activity(
        control, control_rehost_receipts_coherent
    )
    arm_page_load_coherent, arm_page_load_execution = _reconciled_page_load_execution(
        arm, current_required=arm_control_method_comparable is not None
    )
    control_page_load_coherent, control_page_load_execution = (
        _reconciled_page_load_execution(
            control, current_required=arm_control_method_comparable is not None
        )
    )
    page_load_execution_recorded = any(
        value is not None
        for value in (arm_page_load_coherent, control_page_load_coherent)
    )
    page_load_execution_coherent: bool | None = None
    if page_load_execution_recorded:
        page_load_execution_coherent = (
            arm_page_load_coherent is True and control_page_load_coherent is True
        )
    activity_receipts_recorded = any(
        value is not None
        for value in (arm_activity_coherent, control_activity_coherent)
    )
    request_activity_receipts_coherent: bool | None = None
    if activity_receipts_recorded:
        request_activity_receipts_coherent = (
            arm_activity_coherent is True and control_activity_coherent is True
        )
    arm_offline_guard = _sanitize_offline_guard(arm.get("offline_guard"))
    control_offline_guard = _sanitize_offline_guard(control.get("offline_guard"))
    guard_recorded = "offline_guard" in arm or "offline_guard" in control
    offline_guard_comparable: bool | None = None
    if guard_recorded:
        offline_guard_comparable = (
            arm_offline_guard.get("status") == "applied"
            and control_offline_guard.get("status") == "applied"
            and arm_offline_guard == control_offline_guard
        )
    arm_scalar_method = _surface_method(
        {
            f"arm_{field}": arm.get(field)
            for field in (
                "headed",
                "trace_scope",
                "trace_category_contract",
                "chromium_revision",
                "timeout_seconds",
                "dwell_seconds",
                "inline_script",
                "reloads",
                "hook_mode",
                "input_profile",
                "dom_profile",
                "resource_intent_capture",
            )
        }
    )
    result = {
        "schema": SUBTRACTION_SCHEMA,
        "generated_at": _utc_now(),
        "arm_label": arm["label"],
        "arm_script_sha256_16": arm["script_sha256_16"],
        "control_label": control["label"],
        "control_script_sha256_16": control["script_sha256_16"],
        "arm_observation_receipt_sha256": arm_observation_receipt,
        "control_observation_receipt_sha256": control_observation_receipt,
        "input_observation_receipts_complete": (
            input_observation_receipts_complete
        ),
        "input_observation_receipts_comparable": (
            input_observation_receipts_comparable
        ),
        # `clean_subtraction` retains its historical set-inclusion meaning.
        # `surface_claim_ready` is the stronger verdict: an operator readiness
        # probe runs JavaScript while tracing and can elevate bindings that the
        # built-in control probe does not. Do not baseline that mismatch.
        "clean_subtraction": clean_name_subtraction,
        "script_attribution_comparable": script_attribution_comparable,
        "script_attributed_only_in_arm": script_only_in_arm,
        "script_attributed_only_in_control": script_only_in_control,
        "arm_script_execution": arm_script_execution,
        "control_script_execution": control_script_execution,
        "ready_probe_comparable": ready_probe_comparable,
        "arm_control_method_comparable": arm_control_method_comparable,
        "arm_control_method_mismatches": arm_control_method_mismatches,
        "driver_execution_complete": driver_execution_complete,
        "script_identity_coherent": script_identity_coherent,
        "trace_evidence_coherent": trace_evidence_coherent,
        "await_method_comparable": await_method_comparable,
        "arm_readiness_satisfied": arm_readiness_satisfied,
        "input_method_comparable": input_method_comparable,
        "ambient_input_clean": ambient_input_clean,
        "collector_started": collector_started,
        "collector_startup_coherent": collector_startup_coherent,
        "control_collector_startup_coherent": control_collector_startup_coherent,
        "startup_derivation_coherent": startup_derivation_coherent,
        "rehost_dependencies_complete": dependencies_complete,
        "control_rehost_dependencies_complete": control_dependencies_complete,
        "rehost_receipts_coherent": rehost_receipts_coherent,
        "request_activity_receipts_coherent": request_activity_receipts_coherent,
        "page_load_execution_coherent": page_load_execution_coherent,
        "offline_guard_comparable": offline_guard_comparable,
        "surface_claim_ready": (
            clean_name_subtraction
            and ready_probe_comparable
            and arm_control_method_comparable is not False
            and driver_execution_complete is not False
            and script_identity_coherent is not False
            and trace_evidence_coherent is not False
            and await_method_comparable
            and arm_readiness_satisfied
            and input_method_comparable
            and ambient_input_clean is not False
            and collector_started is True
            and collector_startup_coherent is not False
            and startup_derivation_coherent is not False
            and dependency_gate_passes
            and control_dependency_gate_passes
            and rehost_receipts_coherent is not False
            and request_activity_receipts_coherent is not False
            and page_load_execution_coherent is not False
            and offline_guard_comparable is not False
            and input_observation_receipts_comparable is not False
        ),
        # Carried forward from the arms so downstream comparison can tell whether
        # two subtractions are even the same kind of measurement. Measured
        # 2026-08-06: of four pins observed both headed and headless, two produced
        # different surfaces -- the entire 16-name DeviceMotion block appears only
        # headless, because the trace records calls and the block is conditionally
        # executed. A whole "configuration ladder" was published off a corpus that
        # mixed the two modes, and nothing in the subtraction recorded that the
        # arms were not comparable.
        "arm_headed": arm_scalar_method["arm_headed"],
        "arm_viewport": _viewport_method_value(arm.get("viewport")),
        "arm_trace_scope": arm_scalar_method["arm_trace_scope"],
        "arm_trace_category_contract": arm_scalar_method[
            "arm_trace_category_contract"
        ],
        "arm_chromium_revision": arm_scalar_method["arm_chromium_revision"],
        "arm_browser_build": _browser_build_method(arm),
        "arm_offline_guard": arm_offline_guard,
        "control_offline_guard": control_offline_guard,
        "arm_timeout_seconds": arm_scalar_method["arm_timeout_seconds"],
        "arm_dwell_seconds": arm_scalar_method["arm_dwell_seconds"],
        "arm_inline_script": arm_scalar_method["arm_inline_script"],
        "arm_reloads": arm_scalar_method["arm_reloads"],
        "control_headed": _boolean_method_value(control.get("headed")),
        "arm_browser_shutdown": arm_trace_evidence.get("browser_shutdown"),
        "control_browser_shutdown": control_trace_evidence.get("browser_shutdown"),
        "arm_trace_flush": arm_trace_evidence.get("trace_flush"),
        "control_trace_flush": control_trace_evidence.get("trace_flush"),
        "arm_trace_evidence": arm_trace_evidence.get("export"),
        "control_trace_evidence": control_trace_evidence.get("export"),
        # Same lesson as the launch mode above, one layer up: an arm observed
        # through active instrumentation and one observed passively are not the
        # same kind of measurement, and a comparison that does not know this will
        # quietly attribute the instrument's effect to the sample.
        "arm_hook_mode": arm_scalar_method["arm_hook_mode"],
        "arm_hook_target_names": sorted(
            _hook_target_method_value(arm.get("hook_target_names")),
            key=lambda item: json.dumps(item, sort_keys=True, separators=(",", ":")),
        ),
        "arm_input_profile": arm_scalar_method["arm_input_profile"],
        "control_input_profile": _enum_method_value(
            control.get("input_profile", "none"), set(INPUT_PROFILES)
        ),
        "arm_input_probe": arm_input_probe,
        "control_input_probe": control_input_probe,
        "arm_ambient_input": arm_ambient_input,
        "control_ambient_input": control_ambient_input,
        "control_hook_mode": _enum_method_value(
            control.get("hook_mode", "off"), set(HOOK_MODES)
        ),
        "arm_dom_profile": arm_scalar_method["arm_dom_profile"],
        "control_dom_profile": _enum_method_value(
            control.get("dom_profile"), set(DOM_PROFILES)
        ),
        "arm_rehost_contract": arm_rehost_contract,
        "control_rehost_contract": control_rehost_contract,
        "arm_script_path": _script_path_method_value(arm.get("script_path")),
        "control_script_path": _script_path_method_value(control.get("script_path")),
        "arm_declared_script_url": _declared_url_metadata(
            arm.get("declared_script_url")
        ),
        "control_declared_script_url": _declared_url_metadata(
            control.get("declared_script_url")
        ),
        "arm_prelude": _prelude_document_metadata(arm),
        "control_prelude": _prelude_document_metadata(control),
        "arm_driver": _driver_metadata(arm),
        "control_driver": _driver_metadata(control),
        "arm_driver_supplied": _driver_supplied(arm),
        "control_driver_supplied": _driver_supplied(control),
        "arm_driver_result": arm_driver_result,
        "control_driver_result": control_driver_result,
        "arm_await_ready_seconds": _number_method_value(
            arm.get("await_ready_seconds")
        ),
        "arm_ready_expression": arm_ready_expression,
        "control_ready_expression": control_ready_expression,
        "arm_resource_intent_capture": arm_scalar_method[
            "arm_resource_intent_capture"
        ],
        "arm_await_report": arm_await_report,
        "control_await_report": control_await_report,
        "arm_extra_browser_args": _browser_arg_metadata(
            arm.get("extra_browser_args")
        ),
        "arm_stage_routes": _observation_stage_routes(arm),
        "control_stage_routes": _observation_stage_routes(control),
        "arm_argument_capture": arm_argument_capture,
        "provenance": arm_capture_provenance,
        "control_provenance": control_capture_provenance,
        "source_provenance": arm_source_provenance,
        "control_source_provenance": control_source_provenance,
        "script_identity": arm_script_identity,
        "control_script_identity": control_script_identity,
        "collector_startup": collector_startup,
        "control_collector_startup": control_collector_startup,
        "unserved_requests": arm_unserved,
        "resource_intents": subtract_resource_intents(
            arm.get("resource_intents"), control.get("resource_intents")
        ),
        "request_activity": subtract_request_activity(
            arm_request_activity,
            control_request_activity,
        ),
        "arm_page_load_execution": arm_page_load_execution,
        "control_page_load_execution": control_page_load_execution,
        "attributed_api_names": len(only_in_arm),
        "only_in_arm": only_in_arm,
        "elevated_in_arm": elevated,
        "only_in_control": only_in_control,
        "context_coverage": {k: coverage.get(k, []) for k in only_in_arm},
        "arm_execution_context_counts": arm["analysis"].get("execution_context_counts"),
        "control_execution_context_counts": control["analysis"].get(
            "execution_context_counts"
        ),
        "non_claims": list(_SUBTRACTION_NON_CLAIMS),
    }
    return _seal_subtraction_document(result)


BASELINE_SCHEMA = "browser-core.product-script-surface-baseline/1"
DRIFT_SCHEMA = "browser-core.product-script-surface-drift/1"
COMPARISON_SCHEMA = "browser-core.product-script-surface-comparison/1"
MAX_SURFACE_COMPARISON_ARMS = 256
MAX_SURFACE_NAMES = 1_000_000
MAX_SURFACE_DRIFT = MAX_SURFACE_NAMES * 2

_BASELINE_FIELDS = {
    "schema",
    "generated_at",
    "label",
    "script_sha256_16",
    "control_label",
    "control_script_sha256_16",
    "method",
    "arms",
    "api_name_count",
    "api_names",
    "volatile_api_names",
    "measured_noise_floor",
    "pairwise_differences",
    "request_activity_baseline",
    "source_provenance",
    "source_subtraction_receipt_population",
    "source_subtraction_lineage",
    "source_subtraction_receipts_complete",
    "source_arm_label",
    "capture_provenance",
    "control_capture_provenance",
    "capture_provenance_population",
    "surface_sha256",
    "non_claims",
    "baseline_receipt_sha256",
}
_BASELINE_NON_CLAIMS = (
    "a stable surface is not an acceptance or undetectability claim",
    "drift means the collector changed, not that anything was bypassed",
    "the noise floor is this host's, measured on these arms, not a vendor constant",
)

_DRIFT_DECISION_FIELDS = {
    "schema",
    "generated_at",
    "baseline_label",
    "baseline_script_sha256_16",
    "observed_label",
    "observed_script_sha256_16",
    "baseline_receipt_sha256",
    "observed_subtraction_receipt_sha256",
    "input_artifact_receipts_complete",
    "input_artifact_receipts_comparable",
    "same_script",
    "baseline_source_sha256",
    "observed_source_sha256",
    "source_custody_comparable",
    "baseline_control_script_sha256_16",
    "observed_control_script_sha256_16",
    "same_control_script",
    "baseline_capture_status",
    "baseline_control_capture_status",
    "observed_capture_status",
    "observed_control_capture_status",
    "capture_receipts_comparable",
    "baseline_count",
    "observed_count",
    "added",
    "removed",
    "drift",
    "tolerance",
    "tolerance_source",
    "baseline_noise_floor",
    "same_method",
    "method_mismatches",
    "clean_subtraction",
    "surface_claim_ready",
    "request_activity_drift",
    "passed",
    "decision_receipt_sha256",
}
_COMPARISON_DECISION_FIELDS = {
    "schema",
    "generated_at",
    "arms",
    "pairs",
    "decision_receipt_sha256",
}
_COMPARISON_PAIR_FIELDS = {
    "a",
    "b",
    "a_script_sha256_16",
    "b_script_sha256_16",
    "same_script",
    "a_subtraction_receipt_sha256",
    "b_subtraction_receipt_sha256",
    "input_artifact_receipts_complete",
    "input_artifact_receipts_comparable",
    "a_source_sha256",
    "b_source_sha256",
    "source_custody_comparable",
    "a_capture_status",
    "b_capture_status",
    "a_control_capture_status",
    "b_control_capture_status",
    "capture_receipts_comparable",
    "a_control_script_sha256_16",
    "b_control_script_sha256_16",
    "same_control_script",
    "a_count",
    "b_count",
    "shared",
    "only_a",
    "only_b",
    "jaccard",
    "same_method",
    "method_mismatches",
    "a_surface_claim_ready",
    "b_surface_claim_ready",
    "surface_comparison_claim_ready",
}


def _validated_surface_label(value: Any, role: str) -> str:
    if not isinstance(value, str) or re.fullmatch(
        r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", value
    ) is None:
        raise ContractError(f"{role} label must be a safe identifier")
    return value


def _validated_optional_surface_label(value: Any, role: str) -> str | None:
    if value is None:
        return None
    return _validated_surface_label(value, role)


def _seal_decision_document(document: dict[str, Any]) -> dict[str, Any]:
    """Give an exported drift/comparison decision one complete public identity."""

    if document.get("schema") not in {DRIFT_SCHEMA, COMPARISON_SCHEMA}:
        raise ContractError("only product surface decisions can be sealed")
    canonical = {
        key: value
        for key, value in document.items()
        if key != "decision_receipt_sha256"
    }
    document["decision_receipt_sha256"] = hashlib.sha256(
        json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return document


def _verified_decision_envelope(document: dict[str, Any]) -> None:
    """Close the v1 decision carrier while permitting known legacy omissions."""

    schema = document.get("schema")
    allowed = (
        _DRIFT_DECISION_FIELDS
        if schema == DRIFT_SCHEMA
        else _COMPARISON_DECISION_FIELDS
    )
    if set(document) - allowed:
        kind = "drift" if schema == DRIFT_SCHEMA else "comparison"
        raise ContractError(f"{kind} decision fields are invalid")
    if schema == COMPARISON_SCHEMA and not {
        "schema",
        "generated_at",
        "arms",
        "pairs",
    } <= set(document):
        raise ContractError("comparison decision fields are incomplete")
    _validated_canonical_utc_timestamp(document.get("generated_at"), "decision")
    if schema == COMPARISON_SCHEMA:
        pairs = document.get("pairs")
        if isinstance(pairs, list) and any(
            isinstance(pair, dict) and set(pair) - _COMPARISON_PAIR_FIELDS
            for pair in pairs
        ):
            raise ContractError("comparison decision pair fields are invalid")


def _verified_decision_parent_lineage(
    holder: dict[str, Any],
    *,
    first_key: str,
    second_key: str,
    claim_key: str,
) -> None:
    fields = (
        first_key,
        second_key,
        "input_artifact_receipts_complete",
        "input_artifact_receipts_comparable",
    )
    present = [field in holder for field in fields]
    if not any(present):
        return
    if not all(present):
        raise ContractError("decision input artifact lineage is incomplete")
    first_receipt = holder.get(first_key)
    second_receipt = holder.get(second_key)
    for receipt in (first_receipt, second_receipt):
        if receipt is not None and (
            not isinstance(receipt, str)
            or re.fullmatch(r"[0-9a-f]{64}", receipt) is None
        ):
            raise ContractError("decision input artifact lineage is invalid")
    expected_complete = bool(
        isinstance(first_receipt, str) and isinstance(second_receipt, str)
    )
    expected_comparable = (
        None
        if first_receipt is None and second_receipt is None
        else expected_complete
    )
    if (
        holder.get("input_artifact_receipts_complete") is not expected_complete
        or holder.get("input_artifact_receipts_comparable") is not expected_comparable
        or (expected_comparable is False and holder.get(claim_key) is not False)
    ):
        raise ContractError("decision input artifact lineage is incoherent")


def _verified_decision_input_lineage(document: dict[str, Any]) -> None:
    schema = document.get("schema")
    if schema == DRIFT_SCHEMA:
        _verified_decision_parent_lineage(
            document,
            first_key="baseline_receipt_sha256",
            second_key="observed_subtraction_receipt_sha256",
            claim_key="passed",
        )
        return
    if schema != COMPARISON_SCHEMA:
        return
    pairs = document.get("pairs")
    if pairs is None:
        return
    if not isinstance(pairs, list) or any(not isinstance(pair, dict) for pair in pairs):
        raise ContractError("decision input artifact lineage pairs are invalid")
    for pair in pairs:
        _verified_decision_parent_lineage(
            pair,
            first_key="a_subtraction_receipt_sha256",
            second_key="b_subtraction_receipt_sha256",
            claim_key="surface_comparison_claim_ready",
        )


def _decision_name_list(holder: dict[str, Any], key: str, label: str) -> list[str]:
    value = holder.get(key)
    if (
        not isinstance(value, list)
        or len(value) > MAX_SURFACE_NAMES
        or any(
            not isinstance(name, str)
            or not name
            or len(name) > 1_024
            or any(ord(char) < 32 for char in name)
            for name in value
        )
        or value != sorted(value)
        or len(set(value)) != len(value)
    ):
        raise ContractError(f"{label} decision name list is invalid")
    return value


def _decision_optional_bool(holder: dict[str, Any], key: str, label: str) -> bool | None:
    value = holder.get(key)
    if value is not None and not isinstance(value, bool):
        raise ContractError(f"{label} decision gate is invalid")
    return value


def _decision_hex_digest(
    holder: dict[str, Any],
    key: str,
    *,
    length: int,
    label: str,
    optional: bool = False,
) -> str | None:
    value = holder.get(key)
    if value is None and optional:
        return None
    if not isinstance(value, str) or re.fullmatch(
        rf"[0-9a-f]{{{length}}}", value
    ) is None:
        raise ContractError(f"{label} decision digest is invalid")
    return value


def _expected_decision_source_custody(
    same_script: bool,
    first_digest: str | None,
    second_digest: str | None,
) -> bool | None:
    if first_digest is None and second_digest is None:
        return None if same_script else False
    if first_digest is None or second_digest is None:
        return False
    return not same_script or first_digest == second_digest


def _decision_capture_status(
    holder: dict[str, Any],
    key: str,
    *,
    label: str,
    allow_mixed: bool = False,
) -> str | None:
    value = holder.get(key)
    allowed = {"not_checked", "VERIFIED", "UNVERIFIED", "error"}
    if allow_mixed:
        allowed.add("mixed")
    if value is not None and (not isinstance(value, str) or value not in allowed):
        raise ContractError(f"{label} decision capture custody status is invalid")
    return value


def _verified_request_decision_shape(value: Any) -> str:
    """Validate and canonically key one value-free loopback request shape."""

    fields = {
        "method",
        "served",
        "path_segment_lengths",
        "path_segments_truncated",
        "query_names",
        "query_names_truncated",
    }
    if not isinstance(value, dict) or set(value) != fields:
        raise ContractError("drift request decision shape evidence is invalid")
    lengths = value.get("path_segment_lengths")
    names = value.get("query_names")
    if (
        value.get("method") not in REQUEST_ACTIVITY_METHODS
        or value.get("served") not in REQUEST_ACTIVITY_SERVED_CLASSES
        or not isinstance(lengths, list)
        or len(lengths) > 32
        or any(
            isinstance(item, bool)
            or not isinstance(item, int)
            or not 1 <= item <= MAX_REHOST_LOG_PATH_CHARS
            for item in lengths
        )
        or not isinstance(value.get("path_segments_truncated"), bool)
        or not isinstance(names, list)
        or len(names) > 64
        or any(
            not isinstance(item, str)
            or not 1 <= len(item) <= 80
            or any(ord(char) < 32 or ord(char) == 127 for char in item)
            for item in names
        )
        or names != sorted(set(names))
        or not isinstance(value.get("query_names_truncated"), bool)
    ):
        raise ContractError("drift request decision shape evidence is invalid")
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


_REQUEST_DRIFT_NON_CLAIMS = {
    "not_available": "this baseline carries no measured request population",
    "unverifiable": (
        "the baseline request population was not verifiable and cannot "
        "authorize a request-drift claim"
    ),
    "ok": (
        "loopback request shape and measured count/byte/digest-coverage envelope "
        "only; no external visibility, body semantics, response validity, or acceptance"
    ),
}


def _verified_drift_request_decision(value: Any) -> bool | None:
    if not isinstance(value, dict):
        raise ContractError("drift request decision must be an object")
    baseline_status = value.get("baseline_status")
    non_claim = value.get("non_claim")
    if (
        not isinstance(baseline_status, str)
        or baseline_status not in _REQUEST_DRIFT_NON_CLAIMS
        or non_claim != _REQUEST_DRIFT_NON_CLAIMS[baseline_status]
    ):
        raise ContractError("drift request decision non-claim is invalid")
    if baseline_status in {"not_available", "unverifiable"}:
        if (
            set(value)
            != {
                "baseline_status",
                "observed_status",
                "comparable",
                "passed",
                "non_claim",
            }
            or value.get("observed_status") is not None
            or value.get("comparable") is not None
            or value.get("passed") is not None
        ):
            raise ContractError("drift request decision legacy state is incoherent")
        return None
    if baseline_status != "ok":
        raise ContractError("drift request decision baseline status is invalid")
    expected_keys = {
        "baseline_status",
        "observed_status",
        "baseline_rows_truncated",
        "observed_rows_truncated",
        "comparable",
        "added_shape_count",
        "removed_shape_count",
        "added_shapes",
        "removed_shapes",
        "metric_outliers",
        "passed",
        "non_claim",
    }
    if set(value) != expected_keys:
        raise ContractError("drift request decision fields are invalid")
    observed_status = value.get("observed_status")
    if observed_status not in {"ok", "unverifiable", "unknown"}:
        raise ContractError("drift request decision observed status is invalid")
    baseline_truncated = value.get("baseline_rows_truncated")
    observed_truncated = value.get("observed_rows_truncated")
    if not isinstance(baseline_truncated, bool) or not isinstance(
        observed_truncated, bool
    ):
        raise ContractError("drift request decision truncation state is invalid")
    expected_comparable = bool(
        not baseline_truncated
        and observed_status == "ok"
        and not observed_truncated
    )
    if value.get("comparable") is not expected_comparable:
        raise ContractError("drift request decision comparability is incoherent")
    added = value.get("added_shapes")
    removed = value.get("removed_shapes")
    outliers = value.get("metric_outliers")
    if (
        not isinstance(added, list)
        or len(added) > 128
        or any(not isinstance(shape, dict) for shape in added)
        or not isinstance(removed, list)
        or len(removed) > 128
        or any(not isinstance(shape, dict) for shape in removed)
        or not isinstance(outliers, list)
        or len(outliers) > 128
    ):
        raise ContractError("drift request decision shape evidence is invalid")
    added_keys = [_verified_request_decision_shape(shape) for shape in added]
    removed_keys = [_verified_request_decision_shape(shape) for shape in removed]
    if (
        added_keys != sorted(set(added_keys))
        or removed_keys != sorted(set(removed_keys))
        or set(added_keys) & set(removed_keys)
    ):
        raise ContractError("drift request decision shape evidence is invalid")
    allowed_outlier_fields = {
        "count",
        "body_bytes_total",
        "body_bytes_min",
        "body_bytes_max",
        "body_digest_coverage",
        "body_digest_multiset",
    }
    outlier_keys: list[str] = []
    for outlier in outliers:
        if (
            not isinstance(outlier, dict)
            or set(outlier) != {"shape", "fields"}
            or not isinstance(outlier.get("shape"), dict)
            or not isinstance(outlier.get("fields"), list)
            or not outlier["fields"]
            or any(
                not isinstance(field, str) or field not in allowed_outlier_fields
                for field in outlier["fields"]
            )
            or outlier["fields"] != sorted(set(outlier["fields"]))
        ):
            raise ContractError("drift request decision outlier evidence is invalid")
        outlier_keys.append(_verified_request_decision_shape(outlier["shape"]))
    if (
        outlier_keys != sorted(set(outlier_keys))
        or set(outlier_keys) & (set(added_keys) | set(removed_keys))
    ):
        raise ContractError("drift request decision shape evidence is invalid")
    added_count = value.get("added_shape_count")
    removed_count = value.get("removed_shape_count")
    if (
        isinstance(added_count, bool)
        or not isinstance(added_count, int)
        or added_count != len(added)
        or isinstance(removed_count, bool)
        or not isinstance(removed_count, int)
        or removed_count != len(removed)
    ):
        raise ContractError("drift request decision shape counts are incoherent")
    if not expected_comparable and (added or removed or outliers):
        raise ContractError("drift request decision shape evidence is incoherent")
    expected_passed = bool(
        expected_comparable and not added and not removed and not outliers
    )
    if value.get("passed") is not expected_passed:
        raise ContractError("drift request decision verdict is incoherent")
    return expected_passed


def _verified_drift_decision_semantics(document: dict[str, Any]) -> None:
    _validated_surface_label(document.get("baseline_label"), "drift decision")
    _validated_surface_label(document.get("observed_label"), "drift decision")
    baseline_pin = _decision_hex_digest(
        document,
        "baseline_script_sha256_16",
        length=16,
        label="drift script identity",
    )
    observed_pin = _decision_hex_digest(
        document,
        "observed_script_sha256_16",
        length=16,
        label="drift script identity",
    )
    same_script = document.get("same_script")
    if not isinstance(same_script, bool) or same_script is not (
        baseline_pin == observed_pin
    ):
        raise ContractError("drift decision script identity is incoherent")
    baseline_source = _decision_hex_digest(
        document,
        "baseline_source_sha256",
        length=64,
        label="drift source custody",
        optional=True,
    )
    observed_source = _decision_hex_digest(
        document,
        "observed_source_sha256",
        length=64,
        label="drift source custody",
        optional=True,
    )
    expected_source_custody = _expected_decision_source_custody(
        same_script, baseline_source, observed_source
    )
    if document.get("source_custody_comparable") is not expected_source_custody:
        raise ContractError("drift decision source custody is incoherent")
    baseline_control_pin = _decision_hex_digest(
        document,
        "baseline_control_script_sha256_16",
        length=16,
        label="drift control identity",
        optional=True,
    )
    observed_control_pin = _decision_hex_digest(
        document,
        "observed_control_script_sha256_16",
        length=16,
        label="drift control identity",
        optional=True,
    )
    expected_same_control = (
        None
        if baseline_control_pin is None
        else observed_control_pin == baseline_control_pin
    )
    if document.get("same_control_script") is not expected_same_control:
        raise ContractError("drift decision control identity is incoherent")
    baseline_capture_status = _decision_capture_status(
        document,
        "baseline_capture_status",
        label="drift",
        allow_mixed=True,
    )
    baseline_control_capture_status = _decision_capture_status(
        document,
        "baseline_control_capture_status",
        label="drift",
        allow_mixed=True,
    )
    observed_capture_status = _decision_capture_status(
        document, "observed_capture_status", label="drift"
    )
    observed_control_capture_status = _decision_capture_status(
        document, "observed_control_capture_status", label="drift"
    )
    if (baseline_capture_status is None) != (
        baseline_control_capture_status is None
    ) or (observed_capture_status is None) != (
        observed_control_capture_status is None
    ):
        raise ContractError("drift decision capture custody is incomplete")
    expected_capture_comparable = (
        None
        if baseline_capture_status is None
        else bool(
            observed_capture_status is not None
            and (
                baseline_capture_status != "VERIFIED"
                or observed_capture_status == "VERIFIED"
            )
            and (
                baseline_control_capture_status != "VERIFIED"
                or observed_control_capture_status == "VERIFIED"
            )
        )
    )
    if (
        document.get("capture_receipts_comparable")
        is not expected_capture_comparable
    ):
        raise ContractError("drift decision capture custody is incoherent")
    added = _decision_name_list(document, "added", "drift")
    removed = _decision_name_list(document, "removed", "drift")
    baseline_count = document.get("baseline_count")
    observed_count = document.get("observed_count")
    drift = document.get("drift")
    tolerance = document.get("tolerance")
    if (
        any(name in set(removed) for name in added)
        or any(
            isinstance(value, bool)
            or not isinstance(value, int)
            or value < 0
            or value > maximum
            for value, maximum in (
                (baseline_count, MAX_SURFACE_NAMES),
                (observed_count, MAX_SURFACE_NAMES),
                (drift, MAX_SURFACE_DRIFT),
                (tolerance, MAX_SURFACE_DRIFT),
            )
        )
        or drift != len(added) + len(removed)
        or observed_count - baseline_count != len(added) - len(removed)
    ):
        raise ContractError("drift decision arithmetic is incoherent")
    tolerance_source = document.get("tolerance_source")
    noise_floor = document.get("baseline_noise_floor")
    if (
        tolerance_source not in {"given", "measured"}
        or (
            noise_floor is not None
            and (
                isinstance(noise_floor, bool)
                or not isinstance(noise_floor, int)
                or not 0 <= noise_floor <= MAX_SURFACE_DRIFT
            )
        )
        or (
            tolerance_source == "measured"
            and (noise_floor is None or noise_floor != tolerance)
        )
    ):
        raise ContractError("drift decision tolerance provenance is incoherent")
    surface_claim_ready = document.get("surface_claim_ready")
    if not isinstance(surface_claim_ready, bool):
        raise ContractError("drift decision verdict is invalid")
    same_method = _verified_decision_method_evidence(
        document,
        sides=("baseline", "observed"),
        label="drift",
        allow_unknown=True,
    )
    request_activity = document.get("request_activity_drift")
    request_passed = _verified_drift_request_decision(request_activity)
    expected_passed = bool(
        drift <= tolerance
        and surface_claim_ready
        and same_method is not False
        and _decision_optional_bool(
            document, "same_control_script", "drift control"
        )
        is not False
        and _decision_optional_bool(
            document, "source_custody_comparable", "drift source custody"
        )
        is not False
        and _decision_optional_bool(
            document, "capture_receipts_comparable", "drift capture custody"
        )
        is not False
        and request_passed is not False
        and _decision_optional_bool(
            document, "input_artifact_receipts_comparable", "drift lineage"
        )
        is not False
    )
    if document.get("passed") is not expected_passed:
        raise ContractError("drift decision verdict is incoherent")


def _verified_comparison_pair_semantics(pair: dict[str, Any]) -> None:
    a_pin = _decision_hex_digest(
        pair,
        "a_script_sha256_16",
        length=16,
        label="comparison script identity",
    )
    b_pin = _decision_hex_digest(
        pair,
        "b_script_sha256_16",
        length=16,
        label="comparison script identity",
    )
    same_script = pair.get("same_script")
    if not isinstance(same_script, bool) or same_script is not (a_pin == b_pin):
        raise ContractError("comparison decision script identity is incoherent")
    a_source = _decision_hex_digest(
        pair,
        "a_source_sha256",
        length=64,
        label="comparison source custody",
        optional=True,
    )
    b_source = _decision_hex_digest(
        pair,
        "b_source_sha256",
        length=64,
        label="comparison source custody",
        optional=True,
    )
    expected_source_custody = _expected_decision_source_custody(
        same_script, a_source, b_source
    )
    if pair.get("source_custody_comparable") is not expected_source_custody:
        raise ContractError("comparison decision source custody is incoherent")
    a_control_pin = _decision_hex_digest(
        pair,
        "a_control_script_sha256_16",
        length=16,
        label="comparison control identity",
        optional=True,
    )
    b_control_pin = _decision_hex_digest(
        pair,
        "b_control_script_sha256_16",
        length=16,
        label="comparison control identity",
        optional=True,
    )
    expected_same_control = (
        None
        if a_control_pin is None and b_control_pin is None
        else a_control_pin is not None
        and b_control_pin is not None
        and a_control_pin == b_control_pin
    )
    if pair.get("same_control_script") is not expected_same_control:
        raise ContractError("comparison decision control identity is incoherent")
    a_capture_status = _decision_capture_status(
        pair, "a_capture_status", label="comparison"
    )
    b_capture_status = _decision_capture_status(
        pair, "b_capture_status", label="comparison"
    )
    a_control_capture_status = _decision_capture_status(
        pair, "a_control_capture_status", label="comparison"
    )
    b_control_capture_status = _decision_capture_status(
        pair, "b_control_capture_status", label="comparison"
    )
    if (a_capture_status is None) != (a_control_capture_status is None) or (
        b_capture_status is None
    ) != (b_control_capture_status is None):
        raise ContractError("comparison decision capture custody is incomplete")
    if a_capture_status is None and b_capture_status is None:
        expected_capture_comparable: bool | None = None
    elif a_capture_status is None or b_capture_status is None:
        expected_capture_comparable = False
    else:
        expected_capture_comparable = bool(
            (a_capture_status == "VERIFIED") == (b_capture_status == "VERIFIED")
            and (a_control_capture_status == "VERIFIED")
            == (b_control_capture_status == "VERIFIED")
        )
    if pair.get("capture_receipts_comparable") is not expected_capture_comparable:
        raise ContractError("comparison decision capture custody is incoherent")
    only_a = _decision_name_list(pair, "only_a", "comparison")
    only_b = _decision_name_list(pair, "only_b", "comparison")
    shared = pair.get("shared")
    if (
        isinstance(shared, bool)
        or not isinstance(shared, int)
        or shared < 0
        or shared > MAX_SURFACE_NAMES
        or any(name in set(only_b) for name in only_a)
    ):
        raise ContractError("comparison decision arithmetic is incoherent")
    a_count = pair.get("a_count")
    b_count = pair.get("b_count")
    if a_count is not None or b_count is not None:
        if (
            isinstance(a_count, bool)
            or not isinstance(a_count, int)
            or a_count < 0
            or a_count > MAX_SURFACE_NAMES
            or isinstance(b_count, bool)
            or not isinstance(b_count, int)
            or b_count < 0
            or b_count > MAX_SURFACE_NAMES
            or a_count != shared + len(only_a)
            or b_count != shared + len(only_b)
        ):
            raise ContractError("comparison decision arithmetic is incoherent")
    union_count = shared + len(only_a) + len(only_b)
    expected_jaccard = round(shared / union_count, 6) if union_count else 1.0
    jaccard = pair.get("jaccard")
    if (
        not is_finite_number(jaccard)
        or jaccard != expected_jaccard
    ):
        raise ContractError("comparison decision arithmetic is incoherent")
    same_method = _verified_decision_method_evidence(
        pair,
        sides=("a", "b"),
        label="comparison",
    )
    a_ready = pair.get("a_surface_claim_ready")
    b_ready = pair.get("b_surface_claim_ready")
    if not isinstance(a_ready, bool) or not isinstance(b_ready, bool):
        raise ContractError("comparison decision verdict is invalid")
    expected_ready = bool(
        a_ready
        and b_ready
        and same_method
        and _decision_optional_bool(
            pair, "same_control_script", "comparison control"
        )
        is not False
        and _decision_optional_bool(
            pair, "source_custody_comparable", "comparison source custody"
        )
        is not False
        and _decision_optional_bool(
            pair, "capture_receipts_comparable", "comparison capture custody"
        )
        is not False
        and _decision_optional_bool(
            pair, "input_artifact_receipts_comparable", "comparison lineage"
        )
        is not False
    )
    if pair.get("surface_comparison_claim_ready") is not expected_ready:
        raise ContractError("comparison decision verdict is incoherent")


def _verified_comparison_decision_matrix(
    document: dict[str, Any], pairs: list[dict[str, Any]]
) -> None:
    arms = document.get("arms")
    if (
        not isinstance(arms, list)
        or not 2 <= len(arms) <= MAX_SURFACE_COMPARISON_ARMS
        or any(
            not isinstance(label, str)
            or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", label) is None
            for label in arms
        )
        or len(set(arms)) != len(arms)
    ):
        raise ContractError("comparison decision matrix arms are invalid")
    expected = [
        (arms[index], other)
        for index in range(len(arms))
        for other in arms[index + 1 :]
    ]
    observed = [(pair.get("a"), pair.get("b")) for pair in pairs]
    if observed != expected:
        raise ContractError("comparison decision matrix is incomplete or duplicated")


def _verified_decision_semantics(document: dict[str, Any]) -> None:
    if document.get("schema") == DRIFT_SCHEMA:
        _verified_drift_decision_semantics(document)
        return
    if document.get("schema") != COMPARISON_SCHEMA:
        return
    pairs = document.get("pairs")
    if pairs is None:
        return
    if not isinstance(pairs, list) or any(not isinstance(pair, dict) for pair in pairs):
        raise ContractError("comparison decision pairs are invalid")
    _verified_comparison_decision_matrix(document, pairs)
    for pair in pairs:
        _verified_comparison_pair_semantics(pair)


def _verified_decision_receipt(document: dict[str, Any]) -> None:
    declared = document.get("decision_receipt_sha256")
    if declared is not None:
        canonical = {
            key: value
            for key, value in document.items()
            if key != "decision_receipt_sha256"
        }
        expected = hashlib.sha256(
            json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode(
                "utf-8"
            )
        ).hexdigest()
        if (
            not isinstance(declared, str)
            or re.fullmatch(r"[0-9a-f]{64}", declared) is None
            or not hmac.compare_digest(declared, expected)
        ):
            raise ContractError("decision receipt integrity check failed")
    _verified_decision_envelope(document)
    _verified_decision_input_lineage(document)
    _verified_decision_semantics(document)

SURFACE_METHOD_FIELDS = (
    "arm_headed",
    "arm_viewport",
    "arm_trace_scope",
    "arm_trace_category_contract",
    "arm_chromium_revision",
    "arm_browser_build",
    "arm_offline_guard",
    "arm_timeout_seconds",
    "arm_dwell_seconds",
    "arm_dom_profile",
    "arm_rehost_contract",
    "arm_hook_mode",
    "arm_hook_target_names",
    "arm_input_profile",
    "arm_inline_script",
    "arm_reloads",
    "arm_script_path",
    "arm_declared_script_url",
    "arm_prelude",
    "arm_driver",
    "arm_driver_supplied",
    "arm_await_ready_seconds",
    "arm_ready_expression",
    "arm_resource_intent_capture",
    "arm_extra_browser_args",
    "arm_stage_routes",
)

# A source-map trailer is packaging metadata, not proof of a module runtime.  The
# Anubis v1.27.0 release build uses esbuild's ``--sourcemap`` flag for a standalone
# browser entry point, so treating the trailer as a bundle veto produced a false
# diagnosis.  Keep it visible as a signal while reserving the veto for runtime
# markers that actually imply an application/module bundle.
SOURCE_MAP_MARKERS = ("//# sourceMappingURL=", "//@ sourceMappingURL=")


def _surface_method(subtraction: dict[str, Any]) -> dict[str, Any]:
    defaults: dict[str, Any] = {
        "arm_hook_mode": "off",
        "arm_hook_target_names": [],
        "arm_input_profile": "none",
        "arm_script_path": DEFAULT_SCRIPT_PATH,
        "arm_prelude": _prelude_metadata(None),
        "arm_driver": _prelude_metadata(None),
        "arm_driver_supplied": False,
        "arm_await_ready_seconds": 0.0,
        "arm_ready_expression": _prelude_metadata(None),
        "arm_resource_intent_capture": None,
        "arm_extra_browser_args": [],
        "arm_stage_routes": [],
        "arm_offline_guard": {"status": "not-recorded"},
    }
    method: dict[str, Any] = {}
    for field in SURFACE_METHOD_FIELDS:
        raw = subtraction.get(field)
        if raw is None and field in defaults:
            raw = defaults[field]
        if field == "arm_prelude":
            value = _prelude_document_metadata(subtraction)
        elif field == "arm_driver":
            value = _driver_metadata(subtraction)
        elif field == "arm_ready_expression":
            value = _ready_expression_metadata(subtraction)
        elif field == "arm_stage_routes":
            value = _observation_stage_routes(subtraction)
        elif field == "arm_declared_script_url":
            value = _declared_url_metadata(raw)
        elif field == "arm_rehost_contract":
            value = _sanitize_rehost_contract(raw)
        elif field == "arm_extra_browser_args":
            value = _browser_arg_metadata(raw)
        elif field == "arm_browser_build":
            value = _browser_build_method({"browser_build": raw})
        elif field == "arm_offline_guard":
            value = _sanitize_offline_guard(raw)
        elif field == "arm_viewport":
            value = _viewport_method_value(raw)
        elif field == "arm_script_path":
            value = _script_path_method_value(raw)
        elif field == "arm_hook_target_names":
            value = _hook_target_method_value(raw)
        elif field in {"arm_trace_scope"}:
            value = _enum_method_value(raw, set(TRACE_SCOPES))
        elif field == "arm_trace_category_contract":
            value = _enum_method_value(raw, set(TRACE_CATEGORY_CONTRACTS))
        elif field == "arm_chromium_revision":
            value = (
                str(raw).lower()
                if isinstance(raw, str) and re.fullmatch(r"[0-9a-fA-F]{40}", raw)
                else (None if raw is None else _unverifiable_method_value(raw))
            )
        elif field in {
            "arm_timeout_seconds",
            "arm_dwell_seconds",
            "arm_await_ready_seconds",
        }:
            value = _number_method_value(raw)
        elif field == "arm_dom_profile":
            value = _enum_method_value(raw, set(DOM_PROFILES))
        elif field == "arm_hook_mode":
            value = _enum_method_value(raw, set(HOOK_MODES))
        elif field == "arm_input_profile":
            value = _enum_method_value(raw, set(INPUT_PROFILES))
        elif field in {"arm_headed", "arm_inline_script", "arm_driver_supplied"}:
            value = _boolean_method_value(raw)
        elif field == "arm_reloads":
            value = (
                raw
                if isinstance(raw, int)
                and not isinstance(raw, bool)
                and 0 <= raw <= 10_000
                else (None if raw is None else _unverifiable_method_value(raw))
            )
        elif field == "arm_resource_intent_capture":
            # Retain v1 so archived evidence remains comparable with evidence
            # produced by the old unique-shape-only projection.
            value = _enum_method_value(raw, {"off", *RESOURCE_INTENT_CONTRACTS})
        else:
            value = raw
        method[field] = value
    return method


def _verified_decision_method_evidence(
    holder: dict[str, Any],
    *,
    sides: tuple[str, str],
    label: str,
    allow_unknown: bool = False,
) -> bool | None:
    """Validate one exported method verdict against its redacted evidence.

    Method mismatch values are already portable projections. Re-running each
    value through the field-specific projector gives us a compact fixed-point
    check: canonical projections remain unchanged, while raw paths, URLs,
    operator values, and malformed nested structures are reduced and therefore
    rejected. The row vocabulary and side names are closed as well.
    """

    same_method = holder.get("same_method")
    if same_method is None:
        if not allow_unknown:
            raise ContractError(f"{label} decision method evidence is invalid")
    elif not isinstance(same_method, bool):
        raise ContractError(f"{label} decision method evidence is invalid")
    mismatches = holder.get("method_mismatches")
    if not isinstance(mismatches, dict) or len(mismatches) > len(
        SURFACE_METHOD_FIELDS
    ):
        raise ContractError(f"{label} decision method evidence is invalid")
    for field, row in mismatches.items():
        if (
            not isinstance(field, str)
            or field not in SURFACE_METHOD_FIELDS
            or not isinstance(row, dict)
            or set(row) != set(sides)
            or row[sides[0]] == row[sides[1]]
        ):
            raise ContractError(f"{label} decision method evidence is invalid")
        for side in sides:
            value = row[side]
            if _surface_method({field: value})[field] != value:
                raise ContractError(f"{label} decision method evidence is invalid")
    if same_method is None:
        if mismatches:
            raise ContractError(f"{label} decision method evidence is invalid")
    elif same_method is not (not mismatches):
        raise ContractError(f"{label} decision method evidence is invalid")
    return same_method


def _method_mismatches(
    a: dict[str, Any], b: dict[str, Any]
) -> dict[str, dict[str, Any]]:
    method_a = _surface_method(a)
    method_b = _surface_method(b)
    return {
        field: {"a": method_a[field], "b": method_b[field]}
        for field in SURFACE_METHOD_FIELDS
        if method_a[field] != method_b[field]
    }


def _surface_claim_is_ready(document: dict[str, Any]) -> bool:
    """Read the claim gate without allowing malformed truthy values through.

    ``surface_claim_ready`` adds a gate to ``clean_subtraction``; it cannot
    override a dirty or missing subtraction. Archived documents lacking the
    newer field still use their clean-subtraction receipt. Only literal JSON
    boolean ``true`` values authorize a baseline, drift pass, or cross-arm claim.
    """
    return document.get("clean_subtraction") is True and document.get(
        "surface_claim_ready", True
    ) is True


def _verified_subtraction_observation_lineage(document: dict[str, Any]) -> None:
    """Reconcile recorded arm/control parent receipts with their claim gates."""

    fields = (
        "arm_observation_receipt_sha256",
        "control_observation_receipt_sha256",
        "input_observation_receipts_complete",
        "input_observation_receipts_comparable",
    )
    present = [field in document for field in fields]
    if not any(present):
        return
    if not all(present):
        raise ContractError("subtraction observation lineage is incomplete")
    arm_receipt = document.get("arm_observation_receipt_sha256")
    control_receipt = document.get("control_observation_receipt_sha256")
    for receipt in (arm_receipt, control_receipt):
        if receipt is not None and (
            not isinstance(receipt, str)
            or re.fullmatch(r"[0-9a-f]{64}", receipt) is None
        ):
            raise ContractError("subtraction observation lineage is invalid")
    expected_complete = bool(
        isinstance(arm_receipt, str) and isinstance(control_receipt, str)
    )
    expected_comparable = (
        None
        if arm_receipt is None and control_receipt is None
        else expected_complete
    )
    if (
        document.get("input_observation_receipts_complete") is not expected_complete
        or document.get("input_observation_receipts_comparable")
        is not expected_comparable
        or (expected_comparable is False and _surface_claim_is_ready(document))
    ):
        raise ContractError("subtraction observation lineage is incoherent")


def _verified_subtraction_request_activity(document: dict[str, Any]) -> None:
    """Validate saved request activity at the writer and digest boundaries."""

    if "request_activity" in document:
        request_activity = document.get("request_activity")
        current_request_fields = {
            "scope",
            "non_claim",
            "arm_requests",
            "control_requests",
            "shared_shapes",
            "clean_subtraction",
        }
        current_request = bool(
            isinstance(request_activity, dict)
            and current_request_fields & set(request_activity)
        )
        if not _saved_subtraction_request_activity_canonical(document):
            raise ContractError("subtraction request activity is not canonical")
        if current_request and request_activity.get("status") == "ok":
            required_request_fields = {
                "status",
                "scope",
                "arm_requests",
                "control_requests",
                "shared_shapes",
                "clean_subtraction",
                "only_in_arm",
                "only_in_control",
                "non_claim",
            }
            only_control_requests = request_activity.get("only_in_control")
            if (
                not required_request_fields <= set(request_activity)
                or not isinstance(only_control_requests, list)
                or request_activity.get("clean_subtraction")
                is not (len(only_control_requests) == 0)
            ):
                raise ContractError(
                    "subtraction request activity verdict is incoherent"
                )
            only_arm_requests = request_activity.get("only_in_arm")
            assert isinstance(only_arm_requests, list)

            def request_delta_is_coherent(
                row: Any, *, arm_excess: bool
            ) -> bool:
                if not isinstance(row, dict):
                    return False
                count = row.get("count")
                arm_count = row.get("arm_count")
                control_count = row.get("control_count")
                if any(
                    isinstance(value, bool)
                    or not isinstance(value, int)
                    or not 0 <= value <= 1_000_000_000
                    for value in (count, arm_count, control_count)
                ):
                    return False
                expected = (
                    arm_count - control_count
                    if arm_excess
                    else control_count - arm_count
                )
                return expected > 0 and count == expected

            if any(
                not request_delta_is_coherent(row, arm_excess=True)
                for row in only_arm_requests
            ) or any(
                not request_delta_is_coherent(row, arm_excess=False)
                for row in only_control_requests
            ):
                raise ContractError(
                    "subtraction request activity row arithmetic is incoherent"
                )
            request_identity_fields = (
                "method",
                "served",
                "path_segment_lengths",
                "path_segments_truncated",
                "query_names",
                "query_names_truncated",
            )
            if any(
                row.get("query_names")
                != sorted(set(row.get("query_names") or []))
                for row in only_arm_requests + only_control_requests
            ):
                raise ContractError(
                    "subtraction request query identity is not canonical"
                )
            request_identities = [
                json.dumps(
                    {field: row[field] for field in request_identity_fields},
                    sort_keys=True,
                    separators=(",", ":"),
                )
                for row in only_arm_requests + only_control_requests
            ]
            if len(request_identities) != len(set(request_identities)):
                raise ContractError(
                    "subtraction request activity identity is duplicated"
                )
            body_fields = {
                "body_bytes_total",
                "body_bytes_min",
                "body_bytes_max",
            }

            def request_body_envelope_is_coherent(
                row: dict[str, Any], *, population_field: str
            ) -> bool:
                if not (body_fields & set(row)):
                    return True
                if not body_fields <= set(row):
                    return False
                total = row.get("body_bytes_total")
                minimum = row.get("body_bytes_min")
                maximum = row.get("body_bytes_max")
                population = row.get(population_field)
                if any(
                    isinstance(value, bool)
                    or not isinstance(value, int)
                    or not 0 <= value <= 1_000_000_000
                    for value in (total, minimum, maximum, population)
                ):
                    return False
                return bool(
                    minimum <= maximum
                    and min(minimum * population, 1_000_000_000)
                    <= total
                    <= min(maximum * population, 1_000_000_000)
                )

            if any(
                not request_body_envelope_is_coherent(
                    row, population_field="arm_count"
                )
                for row in only_arm_requests
            ) or any(
                not request_body_envelope_is_coherent(
                    row, population_field="control_count"
                )
                for row in only_control_requests
            ):
                raise ContractError(
                    "subtraction request body envelope is incoherent"
                )
            if any(
                "body_sha256_16_counts" in row
                and row.get("control_count", 0) > 0
                for row in only_arm_requests
            ) or any(
                "body_sha256_16_counts" in row
                and row.get("arm_count", 0) > 0
                for row in only_control_requests
            ):
                raise ContractError(
                    "subtraction request body digest custody is ambiguous"
                )
            arm_requests = request_activity.get("arm_requests")
            control_requests = request_activity.get("control_requests")
            shared_shapes = request_activity.get("shared_shapes")
            all_difference_rows = only_arm_requests + only_control_requests
            arm_retained = sum(row["arm_count"] for row in all_difference_rows)
            control_retained = sum(
                row["control_count"] for row in all_difference_rows
            )
            shared_difference_shapes = sum(
                1
                for row in all_difference_rows
                if row["arm_count"] > 0 and row["control_count"] > 0
            )
            if (
                not isinstance(shared_shapes, int)
                or isinstance(shared_shapes, bool)
                or shared_shapes < shared_difference_shapes
            ):
                raise ContractError(
                    "subtraction shared request coverage is incoherent"
                )
            omitted_shared_shapes = shared_shapes - shared_difference_shapes
            if (
                not isinstance(arm_requests, int)
                or isinstance(arm_requests, bool)
                or not isinstance(control_requests, int)
                or isinstance(control_requests, bool)
                or arm_requests < arm_retained
                or control_requests < control_retained
                or not 0 <= shared_shapes <= min(arm_requests, control_requests)
            ):
                raise ContractError(
                    "subtraction request activity counts are incoherent"
                )
            if (
                arm_requests < arm_retained + omitted_shared_shapes
                or control_requests < control_retained + omitted_shared_shapes
            ):
                raise ContractError(
                    "subtraction shared request coverage is incoherent"
                )


def _verified_subtraction_resource_intents(document: dict[str, Any]) -> None:
    """Validate the saved subtraction resource-intent report."""
    if "resource_intents" in document:
        resource_intents = document.get("resource_intents")
        safe_resource_intents = _sanitize_resource_intent_report(resource_intents)
        current_resource_intents = bool(
            isinstance(resource_intents, dict) and "non_claim" in resource_intents
        )
        if (
            document.get("subtraction_receipt_sha256") is not None
            and not current_resource_intents
        ):
            raise ContractError("subtraction resource intent receipt is incomplete")
        raw_without_non_claim = (
            {key: value for key, value in resource_intents.items() if key != "non_claim"}
            if isinstance(resource_intents, dict)
            else None
        )
        safe_without_non_claim = {
            key: value
            for key, value in safe_resource_intents.items()
            if key != "non_claim"
        }
        expected_resource_non_claim = (
            "DOM attributes present at capture time; not proof that a request was "
            "sent, reached DNS, or received a response"
            if isinstance(resource_intents, dict)
            and resource_intents.get("status") == "ok"
            else "both DOM snapshots must succeed without truncation before intent "
            "is attributable"
        )
        if not isinstance(resource_intents, dict) or (
            raw_without_non_claim != safe_without_non_claim
            or resource_intents.get("non_claim") != expected_resource_non_claim
            if current_resource_intents
            else bool(set(resource_intents) - set(safe_resource_intents))
        ):
            raise ContractError("subtraction resource intents are not canonical")
        if current_resource_intents and resource_intents.get("status") == "ok":
            required_resource_fields = {
                "status",
                "arm_count",
                "control_count",
                "shared_count",
                "arm_attribute_count",
                "control_attribute_count",
                "only_in_arm",
                "only_in_control",
                "multiplicity_deltas",
                "clean_subtraction",
                "non_claim",
            }
            only_in_control_intents = resource_intents.get("only_in_control")
            multiplicity_deltas = resource_intents.get("multiplicity_deltas")
            if (
                not required_resource_fields <= set(resource_intents)
                or not isinstance(only_in_control_intents, list)
                or not isinstance(multiplicity_deltas, list)
            ):
                raise ContractError(
                    "subtraction resource intent verdict is incomplete"
                )
            control_excess = any(
                isinstance(row, dict)
                and isinstance(row.get("arm_occurrences"), int)
                and isinstance(row.get("control_occurrences"), int)
                and row["control_occurrences"] > row["arm_occurrences"]
                for row in multiplicity_deltas
            )
            if any(
                not isinstance(row, dict)
                or isinstance(row.get("arm_occurrences"), bool)
                or not isinstance(row.get("arm_occurrences"), int)
                or row["arm_occurrences"] < 1
                or isinstance(row.get("control_occurrences"), bool)
                or not isinstance(row.get("control_occurrences"), int)
                or row["control_occurrences"] < 1
                or row["arm_occurrences"] == row["control_occurrences"]
                for row in multiplicity_deltas
            ):
                raise ContractError(
                    "subtraction resource multiplicity delta is incoherent"
                )
            only_in_arm_intents = resource_intents.get("only_in_arm")
            assert isinstance(only_in_arm_intents, list)
            resource_identity_fields = (
                "tag",
                "attribute",
                "origin",
                "same_origin_as_rehost",
                "path_segment_lengths",
                "path_segments_truncated",
                "query_names",
                "query_names_truncated",
            )
            all_resource_rows = (
                only_in_arm_intents
                + only_in_control_intents
                + multiplicity_deltas
            )
            if any(
                row.get("same_origin_as_rehost")
                is not (row.get("origin") == "loopback-rehost")
                for row in all_resource_rows
            ):
                raise ContractError(
                    "subtraction resource intent origin label is incoherent"
                )
            if any(
                row.get("query_names")
                != sorted(set(row.get("query_names") or []))
                for row in all_resource_rows
            ):
                raise ContractError(
                    "subtraction resource intent identity is not canonical"
                )
            resource_identities = [
                json.dumps(
                    {field: row[field] for field in resource_identity_fields},
                    sort_keys=True,
                    separators=(",", ":"),
                )
                for row in all_resource_rows
            ]
            if len(resource_identities) != len(set(resource_identities)):
                raise ContractError(
                    "subtraction resource intent identity is duplicated"
                )
            arm_intent_count = resource_intents.get("arm_count")
            control_intent_count = resource_intents.get("control_count")
            shared_intent_count = resource_intents.get("shared_count")
            arm_attribute_count = resource_intents.get("arm_attribute_count")
            control_attribute_count = resource_intents.get(
                "control_attribute_count"
            )
            aggregate_values = (
                arm_intent_count,
                control_intent_count,
                shared_intent_count,
                arm_attribute_count,
                control_attribute_count,
            )
            visible_arm_attributes = sum(
                row.get("count", 1) for row in only_in_arm_intents
            ) + sum(row["arm_occurrences"] for row in multiplicity_deltas)
            visible_control_attributes = sum(
                row.get("count", 1) for row in only_in_control_intents
            ) + sum(row["control_occurrences"] for row in multiplicity_deltas)
            omitted_shared_intents = (
                shared_intent_count - len(multiplicity_deltas)
                if isinstance(shared_intent_count, int)
                and not isinstance(shared_intent_count, bool)
                else -1
            )
            if (
                any(
                    isinstance(value, bool)
                    or not isinstance(value, int)
                    or not 0 <= value <= 1_000_000
                    for value in aggregate_values
                )
                or shared_intent_count < len(multiplicity_deltas)
                or arm_intent_count
                != len(only_in_arm_intents) + shared_intent_count
                or control_intent_count
                != len(only_in_control_intents) + shared_intent_count
                or arm_attribute_count
                < visible_arm_attributes + omitted_shared_intents
                or control_attribute_count
                < visible_control_attributes + omitted_shared_intents
            ):
                raise ContractError(
                    "subtraction resource intent counts are incoherent"
                )
            expected_resource_clean = not only_in_control_intents and not control_excess
            if (
                resource_intents.get("clean_subtraction")
                is not expected_resource_clean
            ):
                raise ContractError(
                    "subtraction resource intent verdict is incoherent"
                )


def _verified_subtraction_receipt(document: dict[str, Any]) -> None:
    """Validate the optional complete public identity of a current subtraction."""

    _verified_subtraction_observation_lineage(document)
    declared = document.get("subtraction_receipt_sha256")
    if declared is None:
        return
    canonical = {
        key: value
        for key, value in document.items()
        if key != "subtraction_receipt_sha256"
    }
    expected = hashlib.sha256(
        json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    if (
        not isinstance(declared, str)
        or re.fullmatch(r"[0-9a-f]{64}", declared) is None
        or not hmac.compare_digest(declared, expected)
    ):
        raise ContractError("subtraction receipt integrity check failed")
    reject_sensitive_keys(document)
    _validated_surface_label(document.get("arm_label"), "subtraction arm")
    _validated_optional_surface_label(
        document.get("control_label"), "subtraction control"
    )
    arm_script_pin = _surface_script_pin(document, "arm_script_sha256_16")
    control_script_pin = _optional_surface_script_pin(
        document, "control_script_sha256_16"
    )
    _validated_canonical_utc_timestamp(document.get("generated_at"), "subtraction")
    try:
        for field, pin in (
            ("source_provenance", arm_script_pin),
            ("control_source_provenance", control_script_pin),
        ):
            if field not in document:
                continue
            holder = (
                document
                if field == "source_provenance"
                else {"source_provenance": document.get(field)}
            )
            safe = _surface_source_provenance(holder, pin)
            if (
                "script_identity_coherent" in document
                and document.get(field) != safe
            ):
                raise ContractError("non-canonical source receipt")
        for field, label in (
            ("provenance", document.get("arm_label")),
            ("control_provenance", document.get("control_label")),
        ):
            if field not in document:
                continue
            _surface_capture_provenance(document, field, label)
            if (
                "script_identity_coherent" in document
                and document.get(field)
                != _sanitize_capture_provenance(document.get(field))
            ):
                raise ContractError("non-canonical capture receipt")
    except ContractError as exc:
        raise ContractError("subtraction provenance receipt is invalid") from exc
    canonical_arm_method_metadata = {
        "arm_browser_build": _browser_build_method(
            {"browser_build": document.get("arm_browser_build")}
        ),
        "arm_viewport": _viewport_method_value(document.get("arm_viewport")),
    }
    if any(
        field in document and document.get(field) != canonical
        for field, canonical in canonical_arm_method_metadata.items()
    ):
        raise ContractError("subtraction arm method metadata is not canonical")
    if any(
        field in document
        and document.get(field) != _surface_method({field: document.get(field)})[field]
        for field in (
            "arm_trace_scope",
            "arm_trace_category_contract",
            "arm_chromium_revision",
        )
    ):
        raise ContractError("subtraction arm trace method is not canonical")
    if any(
        field in document
        and document.get(field) != _surface_method({field: document.get(field)})[field]
        for field in (
            "arm_headed",
            "arm_timeout_seconds",
            "arm_dwell_seconds",
            "arm_dom_profile",
            "arm_hook_mode",
            "arm_input_profile",
            "arm_inline_script",
            "arm_reloads",
            "arm_resource_intent_capture",
        )
    ):
        raise ContractError("subtraction arm execution control is not canonical")
    canonical_control_execution_method = {
        "control_headed": _boolean_method_value(document.get("control_headed")),
        "control_hook_mode": _enum_method_value(
            document.get("control_hook_mode"), set(HOOK_MODES)
        ),
        "control_input_profile": _enum_method_value(
            document.get("control_input_profile"), set(INPUT_PROFILES)
        ),
        "control_dom_profile": _enum_method_value(
            document.get("control_dom_profile"), set(DOM_PROFILES)
        ),
    }
    if any(
        "script_identity_coherent" in document
        and field in document
        and document.get(field) != canonical
        for field, canonical in canonical_control_execution_method.items()
    ):
        raise ContractError("subtraction control execution method is not canonical")
    if any(
        field in document
        and document.get(field) != _surface_method({field: document.get(field)})[field]
        for field in ("arm_extra_browser_args", "arm_hook_target_names")
    ):
        raise ContractError("subtraction arm list method is not canonical")
    script_location_projections = {
        "arm_script_path": _script_path_method_value(
            document.get("arm_script_path")
        ),
        "control_script_path": _script_path_method_value(
            document.get("control_script_path")
        ),
        "arm_declared_script_url": _declared_url_metadata(
            document.get("arm_declared_script_url")
        ),
        "control_declared_script_url": _declared_url_metadata(
            document.get("control_declared_script_url")
        ),
    }
    if any(
        "script_identity_coherent" in document
        and field in document
        and document.get(field) != canonical
        for field, canonical in script_location_projections.items()
    ):
        raise ContractError("subtraction script location is not canonical")
    argument_capture = document.get("arm_argument_capture")
    if argument_capture is not None:
        from .argument_capture import validate_capture

        try:
            validate_capture(argument_capture)
        except ContractError as exc:
            raise ContractError("subtraction argument capture is invalid") from exc
    if any(
        field in document
        and document.get(field)
        != _sanitize_rehost_contract(document.get(field))
        for field in ("arm_rehost_contract", "control_rehost_contract")
    ):
        raise ContractError("subtraction rehost contract is not canonical")
    if any(
        field in document
        and document.get(field) != _stored_js_metadata(document.get(field))
        for field in ("arm_prelude", "control_prelude")
    ):
        raise ContractError("subtraction prelude metadata is not canonical")
    if any(
        "script_identity_coherent" in document
        and field in document
        and document.get(field)
        != _observation_stage_routes({"stage_routes": document.get(field)})
        for field in ("arm_stage_routes", "control_stage_routes")
    ):
        raise ContractError("subtraction stage route metadata is not canonical")
    if document.get("non_claims") != list(_SUBTRACTION_NON_CLAIMS):
        raise ContractError("subtraction non-claims are invalid")
    surface_names = _surface_name_set(document)
    control_names = (
        _surface_name_set(document, field="only_in_control")
        if "only_in_control" in document
        else set()
    )
    if surface_names & control_names:
        raise ContractError("subtraction exclusive name sets overlap")
    script_fields = {
        "script_attribution_comparable",
        "script_attributed_only_in_arm",
        "script_attributed_only_in_control",
    }
    if script_fields & set(document):
        if not script_fields <= set(document):
            raise ContractError("subtraction script attribution is incomplete")
        script_comparable = document.get("script_attribution_comparable")
        script_arm_names = _surface_name_set(
            document, field="script_attributed_only_in_arm"
        )
        script_control_names = _surface_name_set(
            document, field="script_attributed_only_in_control"
        )
        if (
            not isinstance(script_comparable, bool)
            or not script_arm_names <= surface_names
            or not script_control_names <= control_names
            or script_arm_names & script_control_names
            or (not script_comparable and (script_arm_names or script_control_names))
        ):
            raise ContractError("subtraction script attribution is incoherent")
    elevated = document.get("elevated_in_arm")
    if elevated is not None:
        if not isinstance(elevated, dict) or len(elevated) > MAX_SURFACE_NAMES:
            raise ContractError("subtraction elevation evidence is invalid")
        if set(elevated) & (surface_names | control_names):
            raise ContractError("subtraction elevated name partition overlaps")
        for name, counts in elevated.items():
            if (
                not isinstance(name, str)
                or not name
                or len(name) > 1_024
                or any(ord(char) < 32 for char in name)
                or not isinstance(counts, dict)
                or set(counts) != {"arm", "control"}
            ):
                raise ContractError("subtraction elevation evidence is invalid")
            arm_count = counts.get("arm")
            control_count = counts.get("control")
            if (
                isinstance(arm_count, bool)
                or not isinstance(arm_count, int)
                or isinstance(control_count, bool)
                or not isinstance(control_count, int)
                or not 1 <= arm_count <= 1_000_000_000
                or not 1 <= control_count <= 1_000_000_000
                or arm_count < control_count * 2
                or arm_count - control_count < 3
            ):
                raise ContractError("subtraction elevation evidence is invalid")
    for side in ("arm", "control"):
        field = f"{side}_script_execution"
        if field in document:
            try:
                safe_execution = _sanitize_script_execution_summary(
                    document.get(field), label=f"subtraction {side}"
                )
            except ContractError as exc:
                raise ContractError(
                    f"subtraction {side} script execution is incoherent"
                ) from exc
            if document.get(field) != safe_execution:
                raise ContractError(
                    f"subtraction {side} script execution is incoherent"
                )
    clean_subtraction = document.get("clean_subtraction")
    if (
        not isinstance(clean_subtraction, bool)
        or clean_subtraction is not (not control_names)
    ):
        raise ContractError("subtraction clean-name verdict is incoherent")
    attributed_count = document.get("attributed_api_names")
    if attributed_count is not None and (
        isinstance(attributed_count, bool)
        or not isinstance(attributed_count, int)
        or attributed_count != len(surface_names)
    ):
        raise ContractError("subtraction attributed API count is incoherent")
    context_coverage = document.get("context_coverage")
    if context_coverage is not None and (
        not isinstance(context_coverage, dict)
        or set(context_coverage) != surface_names
        or any(
            not isinstance(contexts, list)
            or any(
                not isinstance(context, str)
                or context not in {"frame", "worker"}
                for context in contexts
            )
            or contexts != sorted(set(contexts))
            for contexts in context_coverage.values()
        )
    ):
        raise ContractError("subtraction context coverage is incoherent")
    method_fields = {
        "arm_control_method_comparable",
        "arm_control_method_mismatches",
    }
    if method_fields & set(document):
        if not method_fields <= set(document):
            raise ContractError("subtraction arm/control method evidence is incomplete")
        method_comparable = document.get("arm_control_method_comparable")
        method_mismatches = document.get("arm_control_method_mismatches")
        if (
            method_comparable is not None
            and not isinstance(method_comparable, bool)
        ) or (
            not isinstance(method_mismatches, list)
            or any(
                not isinstance(field, str)
                or field not in _ARM_CONTROL_METHOD_SOURCES
                for field in method_mismatches
            )
            or method_mismatches != sorted(set(method_mismatches))
            or (method_comparable is False) is not bool(method_mismatches)
        ):
            raise ContractError("subtraction arm/control method evidence is incoherent")
        retained_method_pairs = _retained_subtraction_method_pairs(document)
        if method_comparable is True and any(
            arm_value != control_value
            or _method_value_is_unverifiable(arm_value)
            or _method_value_is_unverifiable(control_value)
            for arm_value, control_value in retained_method_pairs.values()
        ):
            raise ContractError(
                "subtraction retained method pairs contradict comparability"
            )
        if document.get("script_identity_coherent") is True and any(
            field in retained_method_pairs
            and retained_method_pairs[field][0] == retained_method_pairs[field][1]
            and not _method_value_is_unverifiable(retained_method_pairs[field][0])
            and not _method_value_is_unverifiable(retained_method_pairs[field][1])
            for field in method_mismatches
        ):
            raise ContractError(
                "subtraction retained method mismatch has no supporting difference"
            )
    if "driver_execution_complete" in document:
        if not {
            "arm_driver",
            "control_driver",
            "arm_driver_supplied",
            "control_driver_supplied",
            "arm_driver_result",
            "control_driver_result",
        } <= document.keys():
            raise ContractError("subtraction driver execution evidence is incomplete")
        if not _saved_subtraction_driver_execution_receipts_coherent(document):
            raise ContractError("subtraction driver execution evidence is incoherent")
    if "script_identity_coherent" in document:
        identity_verdict = document.get("script_identity_coherent")
        if identity_verdict is not None and not isinstance(identity_verdict, bool):
            raise ContractError("subtraction compact script identity is invalid")
        arm_identity = _reconciled_subtraction_script_identity(document)
        control_pin = document.get("control_script_sha256_16")
        control_identity_raw = document.get("control_script_identity")
        control_identity = None
        if control_pin is not None or control_identity_raw is not None:
            control_identity = _reconciled_subtraction_script_identity(
                {
                    "script_identity_coherent": identity_verdict,
                    "script_identity": control_identity_raw,
                    "arm_script_sha256_16": control_pin,
                }
            )
        if identity_verdict is True and (
            arm_identity is None
            or (control_pin is not None and control_identity is None)
        ):
            raise ContractError("subtraction compact script identity is incoherent")
        if (
            control_pin is not None
            and control_identity_raw is not None
            and identity_verdict is not bool(arm_identity and control_identity)
        ):
            raise ContractError("subtraction compact script identity is incoherent")
        if identity_verdict is None and (
            document.get("script_identity") is not None
            or control_identity_raw is not None
        ):
            raise ContractError("subtraction compact script identity is incoherent")
    ready_expression_fields = {
        "arm_ready_expression",
        "control_ready_expression",
    }
    if ready_expression_fields & set(document):
        if not ready_expression_fields <= set(document):
            raise ContractError("subtraction ready probe evidence is incomplete")
        if not _saved_subtraction_ready_probe_receipts_coherent(document):
            raise ContractError("subtraction ready probe evidence is incoherent")
    offline_guard_fields = {
        "arm_offline_guard",
        "control_offline_guard",
        "offline_guard_comparable",
    }
    if offline_guard_fields & set(document):
        if not offline_guard_fields <= set(document):
            raise ContractError("subtraction offline guard evidence is incomplete")
        arm_guard = document.get("arm_offline_guard")
        control_guard = document.get("control_offline_guard")
        guard_comparable = document.get("offline_guard_comparable")
        expected_guard_comparable: bool | None = (
            None
            if arm_guard == {"status": "not-recorded"}
            and control_guard == {"status": "not-recorded"}
            else bool(
                isinstance(arm_guard, dict)
                and isinstance(control_guard, dict)
                and arm_guard.get("status") == "applied"
                and control_guard.get("status") == "applied"
                and arm_guard == control_guard
            )
        )
        if (
            not isinstance(arm_guard, dict)
            or _sanitize_offline_guard(arm_guard) != arm_guard
            or not isinstance(control_guard, dict)
            or _sanitize_offline_guard(control_guard) != control_guard
            or guard_comparable is not expected_guard_comparable
        ):
            raise ContractError("subtraction offline guard evidence is incoherent")
    await_fields = {
        "arm_await_ready_seconds",
        "arm_ready_expression",
        "control_ready_expression",
        "arm_await_report",
        "control_await_report",
        "await_method_comparable",
        "arm_readiness_satisfied",
    }
    if await_fields & set(document):
        if not await_fields <= set(document):
            raise ContractError("subtraction await evidence is incomplete")
        if not _saved_subtraction_await_receipts_coherent(document):
            raise ContractError("subtraction await evidence is incoherent")
    input_method_fields = {
        "arm_input_profile",
        "control_input_profile",
        "arm_input_probe",
        "control_input_probe",
        "input_method_comparable",
    }
    if input_method_fields & set(document):
        if not input_method_fields <= set(document):
            raise ContractError("subtraction input method evidence is incomplete")
        arm_profile = document.get("arm_input_profile")
        control_profile = document.get("control_input_profile")
        arm_probe = document.get("arm_input_probe")
        control_probe = document.get("control_input_probe")
        expected_comparable, safe_arm_probe, safe_control_probe = (
            _reconciled_input_method(
                {"input_profile": arm_profile, "input_probe": arm_probe},
                {"input_profile": control_profile, "input_probe": control_probe},
            )
        )
        comparable = document.get("input_method_comparable")
        if (
            not isinstance(arm_profile, str)
            or arm_profile not in INPUT_PROFILES
            or not isinstance(control_profile, str)
            or control_profile not in INPUT_PROFILES
            or arm_probe != safe_arm_probe
            or control_probe != safe_control_probe
            or not isinstance(comparable, bool)
            or comparable is not expected_comparable
        ):
            raise ContractError("subtraction input method evidence is incoherent")
    ambient_input_fields = {
        "arm_ambient_input",
        "control_ambient_input",
        "ambient_input_clean",
    }
    if ambient_input_fields & set(document):
        if not ambient_input_fields <= set(document):
            raise ContractError("subtraction ambient input evidence is incomplete")
        arm_ambient = document.get("arm_ambient_input")
        control_ambient = document.get("control_ambient_input")
        if arm_ambient is None and control_ambient is None:
            safe_arm_ambient = None
            safe_control_ambient = None
            expected_ambient_clean: bool | None = None
        else:
            safe_arm_ambient, arm_ambient_clean = _reconciled_ambient_input(
                {
                    "input_profile": document.get("arm_input_profile"),
                    "ambient_input": arm_ambient,
                }
            )
            safe_control_ambient, control_ambient_clean = (
                _reconciled_ambient_input(
                    {
                        "input_profile": document.get("control_input_profile"),
                        "ambient_input": control_ambient,
                    }
                )
            )
            expected_ambient_clean = bool(
                arm_ambient_clean is True and control_ambient_clean is True
            )
        ambient_clean = document.get("ambient_input_clean")
        if (
            arm_ambient != safe_arm_ambient
            or control_ambient != safe_control_ambient
            or ambient_clean is not expected_ambient_clean
        ):
            raise ContractError("subtraction ambient input evidence is incoherent")
    arm_startup_fields = {
        "collector_started",
        "collector_startup",
        "collector_startup_coherent",
    }
    # Historical compact subtractions carried only ``collector_started``.
    # Reconcile the complete receipt once either of the newer witness fields
    # is present without retroactively rejecting that bounded legacy shape.
    if {"collector_startup", "collector_startup_coherent"} & set(document):
        if not arm_startup_fields <= set(document):
            raise ContractError(
                "subtraction arm collector startup evidence is incomplete"
            )
        raw_startup = document.get("collector_startup")
        if raw_startup is None:
            expected_started: bool | None = None
            safe_startup = None
            expected_coherent: bool | None = None
        else:
            expected_started, safe_startup, expected_coherent = (
                _reconciled_collector_startup(
                    {"collector_startup": raw_startup}
                )
            )
        if (
            raw_startup != safe_startup
            or document.get("collector_started") is not expected_started
            or document.get("collector_startup_coherent")
            is not expected_coherent
        ):
            raise ContractError(
                "subtraction arm collector startup evidence is incoherent"
            )
    control_startup_fields = {
        "control_collector_startup",
        "control_collector_startup_coherent",
    }
    if control_startup_fields & set(document):
        if not control_startup_fields <= set(document):
            raise ContractError(
                "subtraction control collector startup evidence is incomplete"
            )
        raw_control_startup = document.get("control_collector_startup")
        if raw_control_startup is None:
            safe_control_startup = None
            expected_control_coherent: bool | None = None
        else:
            _, safe_control_startup, expected_control_coherent = (
                _reconciled_collector_startup(
                    {"collector_startup": raw_control_startup}
                )
            )
        if (
            raw_control_startup != safe_control_startup
            or document.get("control_collector_startup_coherent")
            is not expected_control_coherent
        ):
            raise ContractError(
                "subtraction control collector startup evidence is incoherent"
            )
    if "startup_derivation_coherent" in document:
        arm_coherent = document.get("collector_startup_coherent")
        control_coherent = document.get("control_collector_startup_coherent")
        expected_derivation_coherent: bool | None = (
            None
            if arm_coherent is None and control_coherent is None
            else bool(arm_coherent is True and control_coherent is True)
        )
        if (
            document.get("startup_derivation_coherent")
            is not expected_derivation_coherent
        ):
            raise ContractError("subtraction startup derivation is incoherent")
    if "unserved_requests" in document:
        expected_dependencies, _, _ = _reconciled_rehost_dependencies(
            {"unserved_requests": document.get("unserved_requests")}
        )
        if (
            "rehost_dependencies_complete" not in document
            or document.get("rehost_dependencies_complete")
            is not expected_dependencies
        ):
            raise ContractError(
                "subtraction arm rehost dependencies are incoherent"
            )
    page_load_fields = {
        "arm_page_load_execution",
        "control_page_load_execution",
        "page_load_execution_coherent",
    }
    if page_load_fields & set(document):
        if not page_load_fields <= set(document):
            raise ContractError(
                "subtraction page-load execution evidence is incomplete"
            )
        if not _saved_subtraction_page_load_receipts_coherent(document):
            raise ContractError(
                "subtraction page-load execution evidence is incoherent"
            )
    trace_fields = {
        "arm_browser_shutdown",
        "control_browser_shutdown",
        "arm_trace_flush",
        "control_trace_flush",
        "arm_trace_evidence",
        "control_trace_evidence",
        "trace_evidence_coherent",
    }
    if trace_fields & set(document):
        if not trace_fields <= set(document):
            raise ContractError("subtraction trace evidence is incomplete")
        if not _saved_subtraction_trace_receipts_coherent(document):
            raise ContractError("subtraction trace evidence is incoherent")
    _verified_subtraction_request_activity(document)
    _verified_subtraction_resource_intents(document)
    if "surface_claim_ready" in document:
        required_true = (
            "ready_probe_comparable",
            "await_method_comparable",
            "arm_readiness_satisfied",
            "input_method_comparable",
            "collector_started",
        )
        optional_not_false = (
            "arm_control_method_comparable",
            "driver_execution_complete",
            "script_identity_coherent",
            "trace_evidence_coherent",
            "ambient_input_clean",
            "collector_startup_coherent",
            "startup_derivation_coherent",
            "rehost_dependencies_complete",
            "control_rehost_dependencies_complete",
            "rehost_receipts_coherent",
            "request_activity_receipts_coherent",
            "page_load_execution_coherent",
            "offline_guard_comparable",
            "input_observation_receipts_comparable",
        )
        ready = document.get("surface_claim_ready")
        if (
            not isinstance(ready, bool)
            or any(
                field in document
                and document.get(field) is not None
                and not isinstance(document.get(field), bool)
                for field in required_true
            )
            or any(
                field in document
                and document.get(field) is not None
                and not isinstance(document.get(field), bool)
                for field in optional_not_false
            )
        ):
            raise ContractError("subtraction surface readiness is invalid")
        expected_ready = bool(
            clean_subtraction
            and all(document.get(field) is True for field in required_true)
            and all(document.get(field) is not False for field in optional_not_false)
        )
        if ready is not expected_ready:
            raise ContractError("subtraction surface readiness is incoherent")


def _seal_subtraction_document(document: dict[str, Any]) -> dict[str, Any]:
    """Attach the complete public self-integrity receipt used by production."""

    if document.get("schema") != SUBTRACTION_SCHEMA:
        raise ContractError("only product subtractions can be sealed")
    canonical = {
        key: value
        for key, value in document.items()
        if key != "subtraction_receipt_sha256"
    }
    document["subtraction_receipt_sha256"] = hashlib.sha256(
        json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return document


def _source_subtraction_receipt_population(
    subtractions: list[dict[str, Any]],
) -> tuple[list[str], list[dict[str, str]], bool]:
    """Bind a baseline to all exact source subtractions or to legacy absence."""

    receipts = [item.get("subtraction_receipt_sha256") for item in subtractions]
    present = [isinstance(value, str) for value in receipts]
    if any(present) and not all(present):
        raise ContractError(
            "repeated baseline arms must use the same subtraction receipt generation"
        )
    if not all(present):
        return [], [], False
    labels = [item.get("arm_label") for item in subtractions]
    if (
        any(
            not isinstance(label, str)
            or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", label) is None
            for label in labels
        )
        or len(set(labels)) != len(labels)
    ):
        raise ContractError(
            "receipt-bound repeated baselines require unique current arm labels"
        )
    lineage = sorted(
        (
            {
                "arm_label": label,
                "subtraction_receipt_sha256": receipt,
            }
            for label, receipt in zip(labels, receipts, strict=True)
            if isinstance(label, str) and isinstance(receipt, str)
        ),
        key=lambda row: row["arm_label"],
    )
    return (
        sorted(value for value in receipts if isinstance(value, str)),
        lineage,
        True,
    )


def _surface_name_set(
    document: dict[str, Any], *, field: str = "only_in_arm"
) -> set[str]:
    """Return a validated control-subtracted API-name set.

    Production subtractions store a name-to-count map, while older fixtures and
    portable tests use a list. Those are the only two representations. Generic
    ``set(value)`` is unsafe here: a malformed string becomes a set of characters,
    missing data becomes an empty surface, and nested values raise an unrelated
    ``TypeError`` deep in comparison code.
    """
    if field not in document:
        raise ContractError(f"subtraction is missing {field}")
    raw = document.get(field)
    if isinstance(raw, dict):
        names = list(raw)
        if any(
            isinstance(count, bool)
            or not isinstance(count, int)
            or not 1 <= count <= 1_000_000_000
            for count in raw.values()
        ):
            raise ContractError(f"{field} contains an invalid count")
    elif isinstance(raw, list):
        names = raw
    else:
        raise ContractError(f"{field} must be an API-name list or count map")
    if len(names) > 1_000_000:
        raise ContractError(f"{field} exceeds the 1,000,000-name safety bound")
    if any(
        not isinstance(name, str)
        or not name
        or len(name) > 1_024
        or any(ord(char) < 32 for char in name)
        for name in names
    ):
        raise ContractError(f"{field} contains an invalid API name")
    result = set(names)
    if len(result) != len(names):
        raise ContractError(f"{field} contains duplicate API names")
    return result


def _surface_script_pin(document: dict[str, Any], field: str) -> str:
    """Read one exact, lowercase short script digest from a surface artifact."""

    value = document.get(field)
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{16}", value) is None:
        raise ContractError(f"surface script pin {field} must be 16 lowercase hex")
    return value


def _optional_surface_script_pin(
    document: dict[str, Any], field: str
) -> str | None:
    if field not in document or document.get(field) is None:
        return None
    return _surface_script_pin(document, field)


def _surface_source_provenance(
    document: dict[str, Any], script_pin: str
) -> dict[str, Any] | None:
    """Validate a source receipt against the exact surface script pin."""

    if "source_provenance" not in document:
        return None
    raw = document.get("source_provenance")
    safe = _sanitize_source_provenance(raw)
    status = raw.get("status") if isinstance(raw, dict) else None
    if status not in {
        "unverifiable",
        "not_supplied",
        "verified_digest",
        "verified_git_inputs_artifact_digest",
    } or safe.get("status") != status:
        raise ContractError("surface source provenance is malformed")
    if status in {
        "verified_digest",
        "verified_git_inputs_artifact_digest",
    } and (
        not isinstance(safe.get("sha256"), str)
        or safe["sha256"][:16] != script_pin
    ):
        raise ContractError("surface source provenance does not match its script pin")
    return safe


def _surface_capture_provenance(
    document: dict[str, Any], field: str, expected_label: Any
) -> dict[str, Any] | None:
    """Validate one redacted capture receipt against its asserted arm label."""

    if field not in document:
        return None
    if not isinstance(expected_label, str) or re.fullmatch(
        r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", expected_label
    ) is None:
        raise ContractError("surface capture provenance needs a safe expected label")
    raw = document.get(field)
    safe = _sanitize_capture_provenance(raw)
    status = raw.get("status") if isinstance(raw, dict) else None
    if (
        status == "unknown"
        and isinstance(raw, dict)
        and "asserted_label" not in raw
        and raw == safe
    ):
        # Older subtraction production projected a provenance-free observation
        # into this exact, idempotent placeholder. It is legacy absence, not a
        # current receipt and never authorizes a custody claim.
        return None
    if (
        status not in {"not_checked", "VERIFIED", "UNVERIFIED", "error"}
        or safe.get("status") != status
        or safe.get("asserted_label") != expected_label
    ):
        raise ContractError(
            f"surface capture provenance {field} does not match its arm label"
        )
    return safe


def _verified_baseline_capture_provenance(baseline: dict[str, Any]) -> None:
    """Validate optional single-arm or repeated capture-custody receipts."""

    single_fields = {
        "source_arm_label",
        "capture_provenance",
        "control_capture_provenance",
    }
    single_present = single_fields & set(baseline)
    population_present = "capture_provenance_population" in baseline
    if single_present and population_present:
        raise ContractError(
            "baseline capture provenance cannot mix single and repeated receipts"
        )
    if single_present:
        if single_present != single_fields or "control_label" not in baseline:
            raise ContractError(
                "baseline capture provenance requires complete arm/control receipts"
            )
        _surface_capture_provenance(
            baseline, "capture_provenance", baseline.get("source_arm_label")
        )
        _surface_capture_provenance(
            baseline,
            "control_capture_provenance",
            baseline.get("control_label"),
        )
        return
    if not population_present:
        return

    population = baseline.get("capture_provenance_population")
    if (
        not isinstance(population, list)
        or not population
        or len(population) > 1_414
        or any(not isinstance(row, dict) for row in population)
    ):
        raise ContractError(
            "baseline capture provenance population must be a bounded object list"
        )
    arms = baseline.get("arms")
    if (
        isinstance(arms, bool)
        or not isinstance(arms, int)
        or arms != len(population)
    ):
        raise ContractError(
            "baseline capture provenance population does not match its arm count"
        )
    labels: list[str] = []
    for row in population:
        if set(row) != {
            "arm_label",
            "control_label",
            "provenance",
            "control_provenance",
        }:
            raise ContractError(
                "baseline capture provenance population fields are invalid"
            )
        arm_label = row.get("arm_label")
        control_label = row.get("control_label")
        _surface_capture_provenance(row, "provenance", arm_label)
        _surface_capture_provenance(row, "control_provenance", control_label)
        labels.append(str(arm_label))
    if len(set(labels)) != len(labels):
        raise ContractError(
            "baseline capture provenance population arm labels must be unique"
        )


def _baseline_capture_statuses(
    baseline: dict[str, Any],
) -> tuple[list[str], list[str]] | None:
    """Return validated arm/control status populations for a frozen baseline."""

    _verified_baseline_capture_provenance(baseline)
    if "capture_provenance" in baseline:
        return (
            [baseline["capture_provenance"]["status"]],
            [baseline["control_capture_provenance"]["status"]],
        )
    population = baseline.get("capture_provenance_population")
    if isinstance(population, list):
        return (
            [row["provenance"]["status"] for row in population],
            [row["control_provenance"]["status"] for row in population],
        )
    return None


def _capture_status_summary(statuses: list[str] | None) -> str | None:
    if not statuses:
        return None
    unique = set(statuses)
    return statuses[0] if len(unique) == 1 else "mixed"


def _subtraction_capture_pair(
    document: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]] | None:
    """Return a validated current arm/control capture pair, or legacy absence."""

    arm = _surface_capture_provenance(
        document, "provenance", document.get("arm_label")
    )
    control = _surface_capture_provenance(
        document, "control_provenance", document.get("control_label")
    )
    if (arm is None) != (control is None):
        raise ContractError(
            "surface capture provenance requires a complete arm/control pair"
        )
    return None if arm is None else (arm, control)


def _repeated_request_activity_baseline(
    subtractions: list[dict[str, Any]],
) -> dict[str, Any]:
    """Measure within-method request shape/count/size variation across repeats.

    A request body length is not a value capture, but it is still noisy.  DataDome
    5.1.13 produced an identical 162-name API surface under two rich-DOM repeats
    while its one attributed POST differed by 38 bytes.  Reporting a cross-method
    50-byte delta without that repeat floor would make ordinary run jitter look
    like a DOM-derived payload change.
    """
    reports = [
        _sanitize_request_activity_report(item.get("request_activity"))
        for item in subtractions
    ]
    if any(
        report.get("status") != "ok" or report.get("truncated") is True
        for report in reports
    ):
        return {
            "status": "unverifiable",
            "arms": len(subtractions),
            "note": "every repeated arm needs attributable loopback request activity",
        }

    identity_fields = (
        "method",
        "served",
        "path_segment_lengths",
        "path_segments_truncated",
        "query_names",
        "query_names_truncated",
    )
    metric_fields = (
        "count",
        "body_bytes_total",
        "body_bytes_min",
        "body_bytes_max",
    )

    def key_of(row: dict[str, Any]) -> str:
        return json.dumps(
            {key: row.get(key) for key in identity_fields},
            sort_keys=True,
            separators=(",", ":"),
        )

    indexed: list[dict[str, dict[str, Any]]] = []
    for report in reports:
        indexed.append(
            {
                key_of(row): row
                for row in report.get("only_in_arm") or []
                if isinstance(row, dict)
            }
        )
    union = sorted(set().union(*(set(rows) for rows in indexed)))
    intersection = set(union)
    for rows in indexed:
        intersection &= set(rows)

    rows: list[dict[str, Any]] = []
    variable = 0
    for key in union[:128]:
        present = [arm[key] for arm in indexed if key in arm]
        first = present[0]
        metrics: dict[str, Any] = {}
        varies = len(present) != len(indexed)
        for metric in metric_fields:
            values = [int(row.get(metric) or 0) for row in present]
            metrics[f"{metric}_min"] = min(values)
            metrics[f"{metric}_max"] = max(values)
            varies = varies or min(values) != max(values)
        digest_maps = [
            row.get("body_sha256_16_counts")
            if isinstance(row.get("body_sha256_16_counts"), dict)
            else {}
            for row in present
        ]
        digest_coverage = [sum(item.values()) for item in digest_maps]
        metrics["body_digest_coverage_min"] = min(digest_coverage)
        metrics["body_digest_coverage_max"] = max(digest_coverage)
        varies = varies or min(digest_coverage) != max(digest_coverage)
        digest_comparable = len(present) == len(indexed) and all(
            coverage == int(row.get("count") or 0)
            for coverage, row in zip(digest_coverage, present, strict=True)
        )
        metrics["body_digest_multiset_comparable"] = digest_comparable
        if digest_comparable:
            canonical_digests = [
                json.dumps(item, sort_keys=True, separators=(",", ":"))
                for item in digest_maps
            ]
            digest_varies = len(set(canonical_digests)) > 1
            metrics["body_digest_multiset_varies"] = digest_varies
            if not digest_varies:
                metrics["body_digest_multiset_sha256"] = hashlib.sha256(
                    canonical_digests[0].encode("utf-8")
                ).hexdigest()
                metrics["body_digest_multiset_custody"] = "self_receipt_only"
            varies = varies or digest_varies
        if varies:
            variable += 1
        rows.append(
            {
                "shape": {field: first.get(field) for field in identity_fields},
                "arms_present": len(present),
                **metrics,
                "varies": varies,
            }
        )
    result = {
        "status": "ok",
        "arms": len(subtractions),
        "stable_shapes": len(intersection),
        "union_shapes": len(union),
        "variable_shapes": variable,
        "rows": rows,
        "rows_truncated": len(union) > 128,
        "non_claim": (
            "loopback request count, byte-length, and complete-body digest variation "
            "only; no body bytes, field semantics, external requests, product response, "
            "or vendor validity; short unkeyed digests are not a confidentiality claim, "
            "and a stable multiset identity has local self-receipt custody only"
        ),
    }
    result["receipt_sha256"] = hashlib.sha256(
        json.dumps(result, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return result


def build_repeated_surface_baseline(
    subtractions: list[dict[str, Any]], *, label: str | None = None
) -> dict[str, Any]:
    """Freeze a surface from repeated arms, and measure its own noise floor.

    A single-arm baseline assumes the surface is deterministic, and that
    assumption is vendor-specific rather than general. Measured 2026-08-08 on this
    host, same script, same settings, arms run back to back:

        Akamai BM web pin   3 arms, 121 names each, pairwise difference 0
        Kasada driven       2 arms,  29 names each, pairwise difference 0
        Shape Nordstrom     3 arms, 1041/1047/1042 names, pairwise 10/11/9

    Shape's surface carries **15 volatile names** out of a 1,051 union. A tolerance
    chosen by hand -- the existing gate's default is 1 -- is therefore meaningless
    on that vendor: it fails constantly on noise, and no setting of it can
    distinguish a two-name roll change from a quiet run. Worse, the premise the
    gate rests on ("the collector barely moves across rolls, so movement is
    signal") is an Akamai property that was quietly generalised.

    So the baseline records what repeats actually did: a stable core present in
    every arm, a volatile set present in some, and the observed noise floor. A
    later check can then be judged against a number this vendor produced rather
    than one somebody picked.
    """
    if not isinstance(subtractions, list):
        raise ContractError("repeated baseline inputs must be a list")
    if len(subtractions) < 2:
        raise ContractError("a measured noise floor needs at least two arms")
    if len(subtractions) > MAX_SURFACE_COMPARISON_ARMS:
        raise ContractError("repeated baseline accepts at most 256 subtractions")
    if label is not None:
        _validated_surface_label(label, "baseline")
    surfaces: list[set[str]] = []
    pins: list[str] = []
    control_pins: list[str | None] = []
    source_receipts: list[dict[str, Any] | None] = []
    capture_receipts: list[dict[str, Any] | None] = []
    for item in subtractions:
        if not isinstance(item, dict):
            raise ContractError("repeated baseline entries must be objects")
        if item.get("schema") != SUBTRACTION_SCHEMA:
            raise ContractError(
                f"baseline input must be a {SUBTRACTION_SCHEMA} document"
            )
        if not _surface_claim_is_ready(item):
            raise ContractError(
                "refusing to baseline a dirty subtraction or readiness-probe "
                "mismatch: the surface is not claim-ready"
            )
        _validated_optional_surface_label(
            item.get("control_label"), "baseline control"
        )
        item_pin = _surface_script_pin(item, "arm_script_sha256_16")
        pins.append(item_pin)
        control_pins.append(
            _optional_surface_script_pin(item, "control_script_sha256_16")
        )
        source_receipts.append(_surface_source_provenance(item, item_pin))
        arm_capture = _surface_capture_provenance(
            item, "provenance", item.get("arm_label")
        )
        control_capture = _surface_capture_provenance(
            item, "control_provenance", item.get("control_label")
        )
        if (arm_capture is None) != (control_capture is None):
            raise ContractError(
                "repeated baseline arms must use complete capture provenance"
            )
        capture_receipts.append(
            None
            if arm_capture is None
            else {
                "arm_label": item.get("arm_label"),
                "control_label": item.get("control_label"),
                "provenance": arm_capture,
                "control_provenance": control_capture,
            }
        )
        surfaces.append(_surface_name_set(item))
        _verified_subtraction_receipt(item)
    (
        source_subtraction_receipts,
        source_subtraction_lineage,
        source_subtraction_receipts_complete,
    ) = _source_subtraction_receipt_population(subtractions)
    if not any(surfaces):
        raise ContractError("refusing to baseline an empty surface")
    if len(set(pins)) != 1:
        raise ContractError("repeated baseline arms must use the same script pin")
    control_pin: str | None = None
    if any(value is not None for value in control_pins):
        if any(value is None for value in control_pins) or len(set(control_pins)) != 1:
            raise ContractError(
                "repeated baseline arms must use the same control-script pin"
            )
        control_pin = control_pins[0]
    source_receipt: dict[str, Any] | None = None
    if any(value is not None for value in source_receipts):
        if any(value is None for value in source_receipts):
            raise ContractError(
                "repeated baseline arms must use complete source provenance"
            )
        source_keys = {
            (value.get("status"), value.get("sha256"))
            for value in source_receipts
            if isinstance(value, dict)
        }
        if len(source_keys) != 1:
            raise ContractError(
                "repeated baseline arms must use the same source provenance"
            )
        source_receipt = source_receipts[0]
    capture_population: list[dict[str, Any]] | None = None
    if any(value is not None for value in capture_receipts):
        if any(value is None for value in capture_receipts):
            raise ContractError(
                "repeated baseline arms must use complete capture provenance"
            )
        capture_population = [
            value for value in capture_receipts if isinstance(value, dict)
        ]
        labels = [value["arm_label"] for value in capture_population]
        if len(set(labels)) != len(labels):
            raise ContractError(
                "repeated baseline capture provenance needs unique arm labels"
            )
    method = _surface_method(subtractions[0])
    for item in subtractions[1:]:
        mismatches = _method_mismatches(subtractions[0], item)
        if mismatches:
            raise ContractError(
                "refusing to baseline arms with different observation methods: "
                + ", ".join(sorted(mismatches))
            )

    core = sorted(set.intersection(*surfaces))
    union = sorted(set.union(*surfaces))
    volatile = sorted(set(union) - set(core))
    pairwise = [
        len(surfaces[i] ^ surfaces[j])
        for i in range(len(surfaces))
        for j in range(i + 1, len(surfaces))
    ]
    canonical = json.dumps(core, separators=(",", ":")).encode("utf-8")
    baseline_label = _validated_surface_label(
        label if label is not None else subtractions[0].get("arm_label"),
        "baseline",
    )
    baseline = {
        "schema": BASELINE_SCHEMA,
        "generated_at": _utc_now(),
        "label": baseline_label,
        "script_sha256_16": pins[0],
        "control_label": subtractions[0].get("control_label"),
        "method": method,
        "arms": len(surfaces),
        "api_name_count": len(core),
        "api_names": core,
        "volatile_api_names": volatile,
        # The number a later check should be judged against, not a chosen one.
        "measured_noise_floor": max(pairwise) if pairwise else 0,
        "pairwise_differences": pairwise,
        "request_activity_baseline": _repeated_request_activity_baseline(subtractions),
        "source_subtraction_receipt_population": source_subtraction_receipts,
        "source_subtraction_lineage": source_subtraction_lineage,
        "source_subtraction_receipts_complete": (
            source_subtraction_receipts_complete
        ),
        "surface_sha256": hashlib.sha256(canonical).hexdigest(),
        "non_claims": [
            "a stable surface is not an acceptance or undetectability claim",
            "drift means the collector changed, not that anything was bypassed",
            "the noise floor is this host's, measured on these arms, not a vendor constant",
        ],
    }
    if control_pin is not None:
        baseline["control_script_sha256_16"] = control_pin
    if source_receipt is not None:
        baseline["source_provenance"] = source_receipt
    if capture_population is not None:
        baseline["capture_provenance_population"] = capture_population
    baseline["baseline_receipt_sha256"] = hashlib.sha256(
        json.dumps(baseline, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return baseline


def build_surface_baseline(
    subtraction: dict[str, Any], *, label: str | None = None
) -> dict[str, Any]:
    """Freeze a control-subtracted surface so later runs can be checked against it.

    The measured value of this is that the collector is roll-stable: on the Akamai BM
    web pin, five rolls spanning `v2218` to `2026-08-04` differ by one or two names.
    A surface that *does* move is therefore a high-signal event -- the vendor changed
    what it collects -- rather than routine churn, and worth failing a gate over.
    """
    if not isinstance(subtraction, dict):
        raise ContractError("baseline input must be an object")
    if subtraction.get("schema") != SUBTRACTION_SCHEMA:
        raise ContractError(f"baseline input must be a {SUBTRACTION_SCHEMA} document")
    if not _surface_claim_is_ready(subtraction):
        raise ContractError(
            "refusing to baseline a dirty subtraction or readiness-probe "
            "mismatch: the surface is not claim-ready"
        )
    baseline_label = _validated_surface_label(
        label if label is not None else subtraction.get("arm_label"),
        "baseline",
    )
    _validated_optional_surface_label(
        subtraction.get("control_label"), "baseline control"
    )
    script_pin = _surface_script_pin(subtraction, "arm_script_sha256_16")
    control_pin = _optional_surface_script_pin(
        subtraction, "control_script_sha256_16"
    )
    source_receipt = _surface_source_provenance(subtraction, script_pin)
    arm_capture = _surface_capture_provenance(
        subtraction, "provenance", subtraction.get("arm_label")
    )
    control_capture = _surface_capture_provenance(
        subtraction, "control_provenance", subtraction.get("control_label")
    )
    if (arm_capture is None) != (control_capture is None):
        raise ContractError("baseline requires complete arm/control capture provenance")
    names = sorted(_surface_name_set(subtraction))
    _verified_subtraction_receipt(subtraction)
    (
        source_subtraction_receipts,
        source_subtraction_lineage,
        source_subtraction_receipts_complete,
    ) = _source_subtraction_receipt_population([subtraction])
    if not names:
        raise ContractError("refusing to baseline an empty surface")
    canonical = json.dumps(names, separators=(",", ":")).encode("utf-8")
    baseline = {
        "schema": BASELINE_SCHEMA,
        "generated_at": _utc_now(),
        "label": baseline_label,
        "script_sha256_16": script_pin,
        "control_label": subtraction.get("control_label"),
        "method": _surface_method(subtraction),
        "api_name_count": len(names),
        "api_names": names,
        "source_subtraction_receipt_population": source_subtraction_receipts,
        "source_subtraction_lineage": source_subtraction_lineage,
        "source_subtraction_receipts_complete": (
            source_subtraction_receipts_complete
        ),
        "surface_sha256": hashlib.sha256(canonical).hexdigest(),
        "non_claims": [
            "a stable surface is not an acceptance or undetectability claim",
            "drift means the collector changed, not that anything was bypassed",
        ],
    }
    if control_pin is not None:
        baseline["control_script_sha256_16"] = control_pin
    if source_receipt is not None:
        baseline["source_provenance"] = source_receipt
    if arm_capture is not None:
        baseline["source_arm_label"] = subtraction.get("arm_label")
        baseline["capture_provenance"] = arm_capture
        baseline["control_capture_provenance"] = control_capture
    baseline["baseline_receipt_sha256"] = hashlib.sha256(
        json.dumps(baseline, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return baseline


def _verified_baseline_surface(baseline: dict[str, Any]) -> set[str]:
    """Validate the self-described frozen surface before using it as a gate."""
    if set(baseline) - _BASELINE_FIELDS:
        raise ContractError("baseline fields are invalid")
    non_claims = baseline.get("non_claims")
    if (
        not isinstance(non_claims, list)
        or not 1 <= len(non_claims) <= len(_BASELINE_NON_CLAIMS)
        or any(
            not isinstance(value, str) or value not in _BASELINE_NON_CLAIMS
            for value in non_claims
        )
        or len(set(non_claims)) != len(non_claims)
        or non_claims
        != [value for value in _BASELINE_NON_CLAIMS if value in non_claims]
    ):
        raise ContractError("baseline non-claims are invalid")
    method = baseline.get("method")
    if method is not None and (
        not isinstance(method, dict) or _surface_method(method) != method
    ):
        raise ContractError("baseline method is not a canonical redacted receipt")
    _validated_surface_label(baseline.get("label"), "baseline")
    if "generated_at" in baseline or "baseline_receipt_sha256" in baseline:
        _validated_canonical_utc_timestamp(
            baseline.get("generated_at"), "baseline"
        )
    _validated_optional_surface_label(
        baseline.get("control_label"), "baseline control"
    )
    script_pin = _surface_script_pin(baseline, "script_sha256_16")
    _optional_surface_script_pin(baseline, "control_script_sha256_16")
    _surface_source_provenance(baseline, script_pin)
    _verified_baseline_capture_provenance(baseline)
    _verified_baseline_request_activity(baseline)
    _verified_baseline_source_subtraction_lineage(baseline)
    names = baseline.get("api_names")
    if (
        not isinstance(names, list)
        or len(names) > 1_000_000
        or any(
            not isinstance(name, str)
            or not name
            or len(name) > 1_024
            or any(ord(char) < 32 for char in name)
            for name in names
        )
    ):
        raise ContractError("baseline api_names must be a bounded string list")
    if names != sorted(names):
        raise ContractError("baseline api_names must use canonical sorted order")
    unique = set(names)
    declared_count = baseline.get("api_name_count")
    if (
        isinstance(declared_count, bool)
        or not isinstance(declared_count, int)
        or declared_count != len(names)
        or len(unique) != len(names)
    ):
        raise ContractError("baseline api_name_count or uniqueness check failed")
    canonical = json.dumps(sorted(unique), separators=(",", ":")).encode("utf-8")
    expected_digest = hashlib.sha256(canonical).hexdigest()
    declared_digest = baseline.get("surface_sha256")
    if (
        not isinstance(declared_digest, str)
        or not re.fullmatch(r"[0-9a-fA-F]{64}", declared_digest)
        or not hmac.compare_digest(declared_digest.lower(), expected_digest)
    ):
        raise ContractError("baseline surface_sha256 integrity check failed")
    return unique


def _verified_baseline_source_subtraction_lineage(
    baseline: dict[str, Any],
) -> tuple[list[str] | None, bool | None]:
    """Validate the optional producer-parent population on current baselines."""

    population_present = "source_subtraction_receipt_population" in baseline
    complete_present = "source_subtraction_receipts_complete" in baseline
    if not population_present and not complete_present:
        return None, None
    if population_present != complete_present:
        raise ContractError("baseline source subtraction lineage is incomplete")
    population = baseline.get("source_subtraction_receipt_population")
    complete = baseline.get("source_subtraction_receipts_complete")
    if not isinstance(complete, bool):
        raise ContractError("baseline source subtraction lineage is invalid")
    if complete is False:
        if population != []:
            raise ContractError("baseline source subtraction lineage is invalid")
        if baseline.get("source_subtraction_lineage", []) != []:
            raise ContractError("baseline source subtraction lineage is invalid")
        return [], False
    expected_count = baseline.get("arms", 1)
    if (
        isinstance(expected_count, bool)
        or not isinstance(expected_count, int)
        or expected_count < 1
        or not isinstance(population, list)
        or len(population) != expected_count
        or any(
            not isinstance(value, str)
            or re.fullmatch(r"[0-9a-f]{64}", value) is None
            for value in population
        )
        or population != sorted(population)
    ):
        raise ContractError("baseline source subtraction lineage is invalid")
    if "source_subtraction_lineage" in baseline:
        lineage = baseline.get("source_subtraction_lineage")
        if (
            not isinstance(lineage, list)
            or len(lineage) != expected_count
            or any(
                not isinstance(row, dict)
                or set(row)
                != {"arm_label", "subtraction_receipt_sha256"}
                or not isinstance(row.get("arm_label"), str)
                or re.fullmatch(
                    r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", row["arm_label"]
                )
                is None
                or not isinstance(row.get("subtraction_receipt_sha256"), str)
                or re.fullmatch(
                    r"[0-9a-f]{64}", row["subtraction_receipt_sha256"]
                )
                is None
                for row in lineage
            )
            or lineage != sorted(lineage, key=lambda row: row["arm_label"])
            or len({row["arm_label"] for row in lineage}) != len(lineage)
            or sorted(row["subtraction_receipt_sha256"] for row in lineage)
            != population
        ):
            raise ContractError("baseline source subtraction lineage is invalid")
    return population, True


def _verified_baseline_receipt(baseline: dict[str, Any]) -> None:
    """Check the optional whole-baseline receipt after granular validation."""

    declared_receipt = baseline.get("baseline_receipt_sha256")
    if declared_receipt is not None:
        canonical_receipt = {
            key: value
            for key, value in baseline.items()
            if key != "baseline_receipt_sha256"
        }
        expected_receipt = hashlib.sha256(
            json.dumps(
                canonical_receipt, sort_keys=True, separators=(",", ":")
            ).encode("utf-8")
        ).hexdigest()
        if (
            not isinstance(declared_receipt, str)
            or re.fullmatch(r"[0-9a-f]{64}", declared_receipt) is None
            or not hmac.compare_digest(declared_receipt, expected_receipt)
        ):
            raise ContractError("baseline receipt integrity check failed")


def _verified_baseline_request_activity(
    baseline: dict[str, Any],
) -> dict[str, Any] | None:
    """Reject an edited request-noise receipt before a baseline is trusted."""

    if "request_activity_baseline" not in baseline:
        return None
    raw = baseline.get("request_activity_baseline")
    if not isinstance(raw, dict) or raw.get("status") not in {
        "ok",
        "unverifiable",
    }:
        raise ContractError("baseline request activity baseline is malformed")
    safe = _sanitize_request_activity_baseline(raw)
    if not isinstance(safe, dict) or safe.get("status") != raw.get("status"):
        raise ContractError("baseline request activity baseline is incoherent")
    if raw.get("status") == "ok" and raw != safe:
        raise ContractError("baseline request activity baseline is not canonical")
    if raw.get("status") == "unverifiable":
        arms = raw.get("arms")
        producer_state = {
            "status": "unverifiable",
            "arms": arms,
            "note": "every repeated arm needs attributable loopback request activity",
        }
        if raw != safe and (
            isinstance(arms, bool)
            or not isinstance(arms, int)
            or not 2 <= arms <= MAX_SURFACE_COMPARISON_ARMS
            or raw != producer_state
        ):
            raise ContractError("baseline request activity baseline is not canonical")
    return safe


def _request_activity_drift(
    subtraction: dict[str, Any], baseline: dict[str, Any]
) -> dict[str, Any]:
    """Check a new redacted request population against a measured envelope."""

    baseline_receipt = _verified_baseline_request_activity(baseline)
    if baseline_receipt is None:
        return {
            "baseline_status": "not_available",
            "observed_status": None,
            "comparable": None,
            "passed": None,
            "non_claim": _REQUEST_DRIFT_NON_CLAIMS["not_available"],
        }
    if baseline_receipt.get("status") != "ok":
        return {
            "baseline_status": baseline_receipt.get("status"),
            "observed_status": None,
            "comparable": None,
            "passed": None,
            "non_claim": _REQUEST_DRIFT_NON_CLAIMS["unverifiable"],
        }

    observed = _sanitize_request_activity_report(subtraction.get("request_activity"))
    baseline_truncated = baseline_receipt.get("rows_truncated") is True
    observed_truncated = observed.get("truncated") is True
    comparable = bool(
        not baseline_truncated
        and observed.get("status") == "ok"
        and not observed_truncated
    )
    result: dict[str, Any] = {
        "baseline_status": "ok",
        "observed_status": observed.get("status"),
        "baseline_rows_truncated": baseline_truncated,
        "observed_rows_truncated": observed_truncated,
        "comparable": comparable,
        "added_shape_count": 0,
        "removed_shape_count": 0,
        "added_shapes": [],
        "removed_shapes": [],
        "metric_outliers": [],
        "passed": False,
        "non_claim": _REQUEST_DRIFT_NON_CLAIMS["ok"],
    }
    if not comparable:
        return result

    identity_fields = (
        "method",
        "served",
        "path_segment_lengths",
        "path_segments_truncated",
        "query_names",
        "query_names_truncated",
    )

    def shape_of(row: dict[str, Any]) -> dict[str, Any]:
        source = row.get("shape") if isinstance(row.get("shape"), dict) else row
        return {field: source.get(field) for field in identity_fields}

    def key_of(shape: dict[str, Any]) -> str:
        return json.dumps(shape, sort_keys=True, separators=(",", ":"))

    baseline_rows = {
        key_of(shape_of(row)): row
        for row in baseline_receipt.get("rows") or []
        if isinstance(row, dict)
    }
    observed_rows = {
        key_of(shape_of(row)): row
        for row in observed.get("only_in_arm") or []
        if isinstance(row, dict)
    }
    added = sorted(set(observed_rows) - set(baseline_rows))
    removed = sorted(set(baseline_rows) - set(observed_rows))
    result["added_shapes"] = [shape_of(observed_rows[key]) for key in added]
    result["removed_shapes"] = [shape_of(baseline_rows[key]) for key in removed]
    result["added_shape_count"] = len(added)
    result["removed_shape_count"] = len(removed)

    metric_fields = {
        "count": ("count_min", "count_max"),
        "body_bytes_total": ("body_bytes_total_min", "body_bytes_total_max"),
        "body_bytes_min": ("body_bytes_min_min", "body_bytes_min_max"),
        "body_bytes_max": ("body_bytes_max_min", "body_bytes_max_max"),
    }
    outliers: list[dict[str, Any]] = []
    for key in sorted(set(baseline_rows) & set(observed_rows)):
        expected = baseline_rows[key]
        actual = observed_rows[key]
        fields = [
            field
            for field, (low, high) in metric_fields.items()
            if not expected[low] <= int(actual.get(field) or 0) <= expected[high]
        ]
        digest_counts = actual.get("body_sha256_16_counts")
        digest_coverage = (
            sum(digest_counts.values()) if isinstance(digest_counts, dict) else 0
        )
        if not (
            expected["body_digest_coverage_min"]
            <= digest_coverage
            <= expected["body_digest_coverage_max"]
        ):
            fields.append("body_digest_coverage")
        if (
            expected.get("body_digest_multiset_comparable") is True
            and digest_coverage != int(actual.get("count") or 0)
            and "body_digest_coverage" not in fields
        ):
            fields.append("body_digest_coverage")
        expected_digest_identity = expected.get("body_digest_multiset_sha256")
        if isinstance(expected_digest_identity, str):
            actual_digest_identity = hashlib.sha256(
                json.dumps(
                    digest_counts if isinstance(digest_counts, dict) else {},
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("utf-8")
            ).hexdigest()
            if not hmac.compare_digest(
                actual_digest_identity, expected_digest_identity
            ):
                fields.append("body_digest_multiset")
        if fields:
            outliers.append(
                {
                    "shape": shape_of(actual),
                    "fields": sorted(fields),
                }
            )
    result["metric_outliers"] = outliers
    result["passed"] = not added and not removed and not outliers
    return result


def _verified_baseline_noise_floor(
    baseline: dict[str, Any], stable_surface: set[str]
) -> int | None:
    """Validate the repeat receipts from which a measured drift floor derives."""

    repeat_fields = {
        "arms",
        "volatile_api_names",
        "measured_noise_floor",
        "pairwise_differences",
    }
    present = repeat_fields & set(baseline)
    if not present:
        return None
    if present != repeat_fields:
        raise ContractError(
            "baseline measured noise floor requires complete repeat receipts"
        )

    arms = baseline.get("arms")
    measured = baseline.get("measured_noise_floor")
    pairwise = baseline.get("pairwise_differences")
    volatile = baseline.get("volatile_api_names")
    if (
        isinstance(measured, bool)
        or not isinstance(measured, int)
        or measured < 0
    ):
        raise ContractError(
            "baseline measured_noise_floor must be a non-negative integer"
        )
    if (
        isinstance(arms, bool)
        or not isinstance(arms, int)
        or not 2 <= arms <= 1_414
    ):
        raise ContractError("baseline arms must be an integer from 2 through 1,414")
    expected_pairs = arms * (arms - 1) // 2
    if (
        not isinstance(pairwise, list)
        or len(pairwise) != expected_pairs
        or len(pairwise) > 1_000_000
        or any(
            isinstance(value, bool)
            or not isinstance(value, int)
            or not 0 <= value <= 1_000_000
            for value in pairwise
        )
        or measured != max(pairwise)
    ):
        raise ContractError(
            "baseline measured noise floor does not match its pairwise differences"
        )
    if (
        not isinstance(volatile, list)
        or len(volatile) > 1_000_000
        or any(
            not isinstance(name, str)
            or not name
            or len(name) > 1_024
            or any(ord(char) < 32 for char in name)
            for name in volatile
        )
        or len(set(volatile)) != len(volatile)
        or volatile != sorted(volatile)
        or set(volatile) & stable_surface
        or measured > len(volatile)
        or bool(volatile) != (measured > 0)
    ):
        raise ContractError(
            "baseline volatile API names are not canonical or do not support "
            "its pairwise differences"
        )
    return measured


def check_surface_drift(
    subtraction: dict[str, Any],
    baseline: dict[str, Any],
    *,
    tolerance: int | None = 0,
) -> dict[str, Any]:
    """Compare a fresh surface against a frozen baseline.

    ``tolerance`` allows N added-or-removed names before the check fails. Pass
    ``None`` to use the baseline's own ``measured_noise_floor`` where it has one,
    which is the honest choice when the baseline was built from repeats.

    A hand-set tolerance encodes an assumption that turned out to be
    vendor-specific. Same script, same settings, back-to-back arms on this host:
    Akamai and driven Kasada both drift **0** across three and two arms, while
    Shape's Nordstrom deployment drifts **9-11** with 15 volatile names out of a
    1,051 union. The gate's default of 1 is right for two of those three and
    useless for the other, in both directions -- it fails on noise, and it cannot
    see a real two-name roll change underneath an eleven-name floor.

    The exact names are always reported, so a tolerated difference stays visible
    rather than swallowed.
    """
    if not isinstance(subtraction, dict) or not isinstance(baseline, dict):
        raise ContractError("drift inputs must be objects")
    if subtraction.get("schema") != SUBTRACTION_SCHEMA:
        raise ContractError(f"drift input must be a {SUBTRACTION_SCHEMA} document")
    if baseline.get("schema") != BASELINE_SCHEMA:
        raise ContractError(f"baseline must be a {BASELINE_SCHEMA} document")
    expected = _verified_baseline_surface(baseline)
    measured_floor = _verified_baseline_noise_floor(baseline, expected)
    _verified_baseline_receipt(baseline)
    baseline_script_pin = _surface_script_pin(baseline, "script_sha256_16")
    observed_script_pin = _surface_script_pin(
        subtraction, "arm_script_sha256_16"
    )
    same_script = baseline_script_pin == observed_script_pin
    baseline_source = _surface_source_provenance(baseline, baseline_script_pin)
    observed_source = _surface_source_provenance(subtraction, observed_script_pin)
    verified_source_statuses = {
        "verified_digest",
        "verified_git_inputs_artifact_digest",
    }
    baseline_source_verified = bool(
        isinstance(baseline_source, dict)
        and baseline_source.get("status") in verified_source_statuses
    )
    observed_source_verified = bool(
        isinstance(observed_source, dict)
        and observed_source.get("status") in verified_source_statuses
    )
    if not baseline_source_verified and not observed_source_verified:
        source_custody_comparable: bool | None = None if same_script else False
    elif not baseline_source_verified or not observed_source_verified:
        source_custody_comparable = False
    else:
        source_custody_comparable = bool(
            not same_script
            or observed_source.get("sha256") == baseline_source.get("sha256")
        )
    baseline_control_pin = _optional_surface_script_pin(
        baseline, "control_script_sha256_16"
    )
    observed_control_pin = _optional_surface_script_pin(
        subtraction, "control_script_sha256_16"
    )
    same_control_script = (
        None
        if baseline_control_pin is None
        else observed_control_pin == baseline_control_pin
    )
    baseline_capture_statuses = _baseline_capture_statuses(baseline)
    observed_capture = _surface_capture_provenance(
        subtraction, "provenance", subtraction.get("arm_label")
    )
    observed_control_capture = _surface_capture_provenance(
        subtraction, "control_provenance", subtraction.get("control_label")
    )
    if baseline_capture_statuses is None:
        capture_receipts_comparable: bool | None = None
    else:
        baseline_arm_statuses, baseline_control_statuses = baseline_capture_statuses
        capture_receipts_comparable = bool(
            observed_capture is not None
            and observed_control_capture is not None
            and (
                not all(status == "VERIFIED" for status in baseline_arm_statuses)
                or observed_capture.get("status") == "VERIFIED"
            )
            and (
                not all(
                    status == "VERIFIED" for status in baseline_control_statuses
                )
                or observed_control_capture.get("status") == "VERIFIED"
            )
        )
    tolerance_source = "given"
    if tolerance is None:
        if measured_floor is None:
            raise ContractError(
                "this baseline carries no measured noise floor -- rebuild it from "
                "repeated arms, or pass an explicit tolerance and own the number"
            )
        tolerance = measured_floor
        tolerance_source = "measured"
    if (
        isinstance(tolerance, bool)
        or not isinstance(tolerance, int)
        or not 0 <= tolerance <= MAX_SURFACE_DRIFT
    ):
        raise ContractError(
            "drift tolerance must be a non-negative integer no greater than "
            f"{MAX_SURFACE_DRIFT}"
        )

    observed = _surface_name_set(subtraction)
    _verified_subtraction_receipt(subtraction)
    added = sorted(observed - expected)
    removed = sorted(expected - observed)
    drift = len(added) + len(removed)
    raw_baseline_method = baseline.get("method")
    baseline_method = (
        _surface_method(raw_baseline_method)
        if isinstance(raw_baseline_method, dict)
        else None
    )
    observed_method = _surface_method(subtraction)
    method_mismatches = (
        {
            field: {
                "baseline": baseline_method.get(field),
                "observed": observed_method.get(field),
            }
            for field in SURFACE_METHOD_FIELDS
            if baseline_method.get(field) != observed_method.get(field)
        }
        if isinstance(baseline_method, dict)
        else {}
    )
    same_method = (
        None if not isinstance(baseline_method, dict) else not method_mismatches
    )
    surface_claim_ready = _surface_claim_is_ready(subtraction)
    request_activity_drift = _request_activity_drift(subtraction, baseline)
    baseline_receipt = baseline.get("baseline_receipt_sha256")
    observed_subtraction_receipt = subtraction.get("subtraction_receipt_sha256")
    input_artifact_receipts_complete = bool(
        isinstance(baseline_receipt, str)
        and isinstance(observed_subtraction_receipt, str)
    )
    input_artifact_receipts_comparable = (
        None
        if baseline_receipt is None and observed_subtraction_receipt is None
        else input_artifact_receipts_complete
    )
    return _seal_decision_document({
        "schema": DRIFT_SCHEMA,
        "generated_at": _utc_now(),
        "baseline_label": baseline.get("label"),
        "baseline_script_sha256_16": baseline_script_pin,
        "observed_label": subtraction.get("arm_label"),
        "observed_script_sha256_16": observed_script_pin,
        "baseline_receipt_sha256": baseline_receipt,
        "observed_subtraction_receipt_sha256": observed_subtraction_receipt,
        "input_artifact_receipts_complete": input_artifact_receipts_complete,
        "input_artifact_receipts_comparable": (
            input_artifact_receipts_comparable
        ),
        "same_script": same_script,
        "baseline_source_sha256": (
            baseline_source.get("sha256")
            if isinstance(baseline_source, dict)
            else None
        ),
        "observed_source_sha256": (
            observed_source.get("sha256")
            if isinstance(observed_source, dict)
            else None
        ),
        "source_custody_comparable": source_custody_comparable,
        "baseline_control_script_sha256_16": baseline_control_pin,
        "observed_control_script_sha256_16": observed_control_pin,
        "same_control_script": same_control_script,
        "baseline_capture_status": _capture_status_summary(
            baseline_capture_statuses[0]
            if baseline_capture_statuses is not None
            else None
        ),
        "baseline_control_capture_status": _capture_status_summary(
            baseline_capture_statuses[1]
            if baseline_capture_statuses is not None
            else None
        ),
        "observed_capture_status": (
            observed_capture.get("status")
            if isinstance(observed_capture, dict)
            else None
        ),
        "observed_control_capture_status": (
            observed_control_capture.get("status")
            if isinstance(observed_control_capture, dict)
            else None
        ),
        "capture_receipts_comparable": capture_receipts_comparable,
        "baseline_count": len(expected),
        "observed_count": len(observed),
        "added": added,
        "removed": removed,
        "drift": drift,
        "tolerance": tolerance,
        # Whether the bar was measured on this vendor or chosen by a human. A
        # reader deciding what a pass is worth needs to know which.
        "tolerance_source": tolerance_source,
        "baseline_noise_floor": measured_floor,
        "same_method": same_method,
        "method_mismatches": method_mismatches,
        "clean_subtraction": subtraction.get("clean_subtraction") is True,
        "surface_claim_ready": surface_claim_ready,
        "request_activity_drift": request_activity_drift,
        # A dirty subtraction cannot pass: the surface itself is untrustworthy.
        "passed": (
            drift <= tolerance
            and surface_claim_ready
            and same_method is not False
            and same_control_script is not False
            and source_custody_comparable is not False
            and capture_receipts_comparable is not False
            and request_activity_drift.get("passed") is not False
            and input_artifact_receipts_comparable is not False
        ),
    })


def compare_surfaces(subtractions: list[dict[str, Any]]) -> dict[str, Any]:
    """Pairwise stability/overlap across control-subtracted arms."""
    if not isinstance(subtractions, list):
        raise ContractError("surface comparison inputs must be a list")
    if len(subtractions) < 2:
        raise ContractError("surface comparison needs at least two subtractions")
    if len(subtractions) > MAX_SURFACE_COMPARISON_ARMS:
        raise ContractError("surface comparison accepts at most 256 subtractions")
    for item in subtractions:
        if not isinstance(item, dict):
            raise ContractError("surface comparison entries must be objects")
        if item.get("schema") != SUBTRACTION_SCHEMA:
            raise ContractError(f"expected {SUBTRACTION_SCHEMA} documents")

    labels = [s.get("arm_label") for s in subtractions]
    if any(
        not isinstance(label, str)
        or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", label)
        for label in labels
    ):
        raise ContractError("surface comparison arm labels must be safe identifiers")
    if len(set(labels)) != len(labels):
        raise ContractError("surface comparison arm labels must be unique")
    arm_pins = {
        item["arm_label"]: _surface_script_pin(item, "arm_script_sha256_16")
        for item in subtractions
    }
    control_pins = {
        item["arm_label"]: _optional_surface_script_pin(
            item, "control_script_sha256_16"
        )
        for item in subtractions
    }
    source_receipts = {
        item["arm_label"]: _surface_source_provenance(
            item, arm_pins[item["arm_label"]]
        )
        for item in subtractions
    }
    capture_pairs = {
        item["arm_label"]: _subtraction_capture_pair(item)
        for item in subtractions
    }
    sets = {s["arm_label"]: _surface_name_set(s) for s in subtractions}
    for item in subtractions:
        _verified_subtraction_receipt(item)
    pairs = []
    for i, a in enumerate(labels):
        for b in labels[i + 1 :]:
            a_document = subtractions[i]
            b_document = next(item for item in subtractions if item["arm_label"] == b)
            sa, sb = sets[a], sets[b]
            union = sa | sb
            method_mismatches = _method_mismatches(a_document, b_document)
            a_claim_ready = _surface_claim_is_ready(a_document)
            b_claim_ready = _surface_claim_is_ready(b_document)
            a_control_pin = control_pins[a]
            b_control_pin = control_pins[b]
            same_control_script = (
                None
                if a_control_pin is None and b_control_pin is None
                else a_control_pin is not None
                and b_control_pin is not None
                and a_control_pin == b_control_pin
            )
            same_script = arm_pins[a] == arm_pins[b]
            a_source = source_receipts[a]
            b_source = source_receipts[b]
            verified_statuses = {
                "verified_digest",
                "verified_git_inputs_artifact_digest",
            }
            a_source_verified = bool(
                isinstance(a_source, dict)
                and a_source.get("status") in verified_statuses
            )
            b_source_verified = bool(
                isinstance(b_source, dict)
                and b_source.get("status") in verified_statuses
            )
            if not a_source_verified and not b_source_verified:
                source_custody_comparable: bool | None = (
                    None if same_script else False
                )
            elif a_source_verified and b_source_verified:
                source_custody_comparable = bool(
                    not same_script
                    or a_source.get("sha256") == b_source.get("sha256")
                )
            else:
                source_custody_comparable = False
            a_capture_pair = capture_pairs[a]
            b_capture_pair = capture_pairs[b]
            a_subtraction_receipt = a_document.get("subtraction_receipt_sha256")
            b_subtraction_receipt = b_document.get("subtraction_receipt_sha256")
            input_artifact_receipts_complete = bool(
                isinstance(a_subtraction_receipt, str)
                and isinstance(b_subtraction_receipt, str)
            )
            input_artifact_receipts_comparable = (
                None
                if a_subtraction_receipt is None and b_subtraction_receipt is None
                else input_artifact_receipts_complete
            )
            if a_capture_pair is None and b_capture_pair is None:
                capture_receipts_comparable: bool | None = None
            elif a_capture_pair is None or b_capture_pair is None:
                capture_receipts_comparable = False
            else:
                capture_receipts_comparable = all(
                    (a_receipt.get("status") == "VERIFIED")
                    == (b_receipt.get("status") == "VERIFIED")
                    for a_receipt, b_receipt in zip(
                        a_capture_pair, b_capture_pair, strict=True
                    )
                )
            pairs.append(
                {
                    "a": a,
                    "b": b,
                    "a_script_sha256_16": arm_pins[a],
                    "b_script_sha256_16": arm_pins[b],
                    "same_script": same_script,
                    "a_subtraction_receipt_sha256": a_subtraction_receipt,
                    "b_subtraction_receipt_sha256": b_subtraction_receipt,
                    "input_artifact_receipts_complete": (
                        input_artifact_receipts_complete
                    ),
                    "input_artifact_receipts_comparable": (
                        input_artifact_receipts_comparable
                    ),
                    "a_source_sha256": (
                        a_source.get("sha256")
                        if isinstance(a_source, dict)
                        else None
                    ),
                    "b_source_sha256": (
                        b_source.get("sha256")
                        if isinstance(b_source, dict)
                        else None
                    ),
                    "source_custody_comparable": source_custody_comparable,
                    "a_capture_status": (
                        a_capture_pair[0].get("status")
                        if a_capture_pair is not None
                        else None
                    ),
                    "b_capture_status": (
                        b_capture_pair[0].get("status")
                        if b_capture_pair is not None
                        else None
                    ),
                    "a_control_capture_status": (
                        a_capture_pair[1].get("status")
                        if a_capture_pair is not None
                        else None
                    ),
                    "b_control_capture_status": (
                        b_capture_pair[1].get("status")
                        if b_capture_pair is not None
                        else None
                    ),
                    "capture_receipts_comparable": capture_receipts_comparable,
                    "a_control_script_sha256_16": a_control_pin,
                    "b_control_script_sha256_16": b_control_pin,
                    "same_control_script": same_control_script,
                    "a_count": len(sa),
                    "b_count": len(sb),
                    "shared": len(sa & sb),
                    "only_a": sorted(sa - sb),
                    "only_b": sorted(sb - sa),
                    "jaccard": round(len(sa & sb) / len(union), 6) if union else 1.0,
                    "same_method": not method_mismatches,
                    "method_mismatches": method_mismatches,
                    "a_surface_claim_ready": a_claim_ready,
                    "b_surface_claim_ready": b_claim_ready,
                    "surface_comparison_claim_ready": (
                        a_claim_ready
                        and b_claim_ready
                        and not method_mismatches
                        and same_control_script is not False
                        and source_custody_comparable is not False
                        and capture_receipts_comparable is not False
                        and input_artifact_receipts_comparable is not False
                    ),
                }
            )
    return _seal_decision_document({
        "schema": COMPARISON_SCHEMA,
        "generated_at": _utc_now(),
        "arms": labels,
        "pairs": pairs,
    })


# ---------------------------------------------------------------- runner


def validate_product_script_observation_config(
    config: ProductScriptObservation,
) -> ProductScriptObservation:
    """Validate every operator-controlled bound before server or browser work."""
    if not isinstance(config, ProductScriptObservation):
        raise ContractError("observation config has an invalid type")
    for value, label in (
        (config.script, "script"),
        (config.executable, "executable"),
        (config.trace_processor, "trace processor"),
        (config.workspace, "workspace"),
    ):
        if not isinstance(value, Path):
            raise ContractError(f"observation {label} must be a Path")
    for value, label in (
        (config.headed, "headed"),
        (config.inline_script, "inline_script"),
        (config.capture_resource_intents, "capture_resource_intents"),
    ):
        if not isinstance(value, bool):
            raise ContractError(f"observation {label} must be boolean")
    if not isinstance(config.label, str) or not re.fullmatch(
        r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", config.label
    ):
        raise ContractError("observation label is outside the safe identifier contract")
    _read_stable_regular_bytes(
        config.script,
        maximum=MAX_PRODUCT_SCRIPT_BYTES,
        label="product script",
    )

    def seconds(
        value: Any,
        label: str,
        *,
        positive: bool = False,
        maximum: float = MAX_OBSERVATION_SECONDS,
    ) -> None:
        if (
            not is_finite_number(value)
            or value < 0
            or value > maximum
            or (positive and value <= 0)
        ):
            lower = "(" if positive else "["
            interval = f"{lower}0, {maximum:g}]"
            raise ContractError(f"{label} must be a finite number in {interval}")

    seconds(config.dwell_seconds, "dwell seconds")
    seconds(
        config.timeout_seconds,
        "timeout seconds",
        positive=True,
        maximum=MAX_CDP_OPERATION_SECONDS,
    )
    seconds(config.await_ready_seconds, "await-ready seconds")
    if (
        isinstance(config.reloads, bool)
        or not isinstance(config.reloads, int)
        or not 0 <= config.reloads <= MAX_OBSERVATION_RELOADS
    ):
        raise ContractError(
            f"reloads must be an integer in [0, {MAX_OBSERVATION_RELOADS}]"
        )
    if (
        not isinstance(config.trace_scope, str)
        or config.trace_scope not in TRACE_SCOPES
    ):
        raise ContractError("observation trace scope is invalid")
    if (
        not isinstance(config.dom_profile, str)
        or config.dom_profile not in DOM_PROFILES
    ):
        raise ContractError(f"dom profile must be one of {sorted(DOM_PROFILES)}")
    if not isinstance(config.hook_mode, str) or config.hook_mode not in HOOK_MODES:
        raise ContractError(f"hook mode must be one of {HOOK_MODES}")
    if config.hook_mode == "off" and config.hook_target_names:
        raise ContractError("hook targets require hook mode 'on' or 'inert'")
    build_hook_payload(config.hook_mode, config.hook_target_names)
    if (
        not isinstance(config.input_profile, str)
        or config.input_profile not in INPUT_PROFILES
    ):
        raise ContractError(f"input profile must be one of {INPUT_PROFILES}")
    _validate_observation_browser_args(config.extra_browser_args)
    _validate_script_path(config.script_path, config.hook_mode)
    if config.declared_script_url is not None:
        _validate_declared_script_url(config.declared_script_url)
        if config.inline_script:
            raise ContractError(
                "declared script URL is incompatible with inline packaging"
            )
    for value, label in (
        (config.prelude_js, "prelude"),
        (config.driver_js, "driver"),
    ):
        if value is not None:
            _bounded_utf8_source(value, label=label, maximum=MAX_METHOD_SOURCE_BYTES)
    if config.prelude_js is not None:
        _validate_prelude_source(config.prelude_js)
    if config.ready_expression is not None:
        build_ready_probe(config.ready_expression)
        if config.await_ready_seconds <= 0:
            raise ContractError("a readiness expression requires a positive await cap")

    if (
        not isinstance(config.stage_routes, tuple)
        or len(config.stage_routes) > MAX_STAGE_ROUTES
    ):
        raise ContractError(
            f"stage routes must be a tuple of at most {MAX_STAGE_ROUTES} items"
        )
    seen_prefixes: set[str] = set()
    stage_bytes = 0
    for item in config.stage_routes:
        if not isinstance(item, tuple) or len(item) != 2:
            raise ContractError("each stage route must be a (prefix, file) tuple")
        prefix, path = item
        _validate_stage_prefix(prefix)
        if prefix in seen_prefixes:
            raise ContractError("duplicate stage route prefix")
        seen_prefixes.add(prefix)
        if not isinstance(path, Path):
            raise ContractError("stage route source must be a Path")
        stage_payload = _read_stable_regular_bytes(
            path,
            maximum=MAX_STAGE_BYTES,
            label="stage route source",
        )
        stage_bytes += len(stage_payload)
        if stage_bytes > MAX_STAGE_BYTES:
            raise ContractError("staged scripts exceed the aggregate byte limit")
    return config


def run_product_script_observation(
    config: ProductScriptObservation, repository_root: Path
) -> dict[str, Any]:
    validate_product_script_observation_config(config)
    resource_intent_capture = (
        RESOURCE_INTENT_CONTRACT if config.capture_resource_intents else "off"
    )
    rehost_contract = build_rehost_contract()
    script_bytes = _read_stable_regular_bytes(
        config.script,
        maximum=MAX_PRODUCT_SCRIPT_BYTES,
        label="product script",
    )
    # Snapshot each second stage once. Serving and method metadata must bind the
    # same immutable bytes even if a watched checkout or another process rewrites
    # the source file while Chromium is running.
    stage_payloads: tuple[tuple[str, bytes], ...] = tuple(
        (
            prefix,
            _read_stable_regular_bytes(
                path,
                maximum=MAX_STAGE_BYTES,
                label="stage route source",
            ),
        )
        for prefix, path in config.stage_routes
    )
    if sum(len(payload) for _prefix, payload in stage_payloads) > MAX_STAGE_BYTES:
        raise ContractError("staged scripts exceed the aggregate byte limit")
    identity = classify_product_script(script_bytes)
    source_provenance = grade_script_source_provenance(config, script_bytes)
    log = _RequestLog()

    # A rehost server that cannot bind must fail one arm, not the batch.
    #
    # This sat outside the try block, so an `OSError` from `bind()` propagated
    # straight out of the runner and every arm queued behind it was abandoned --
    # the same failure shape as the trace-export race, one layer earlier. Hit for
    # real on 2026-08-07: after roughly 200 browser launches the host began
    # refusing binds with `WinError 10055` ("insufficient buffer space") while
    # netstat showed only ~45 TIME_WAIT and 16,384 free ports, i.e. nonpaged pool
    # rather than port exhaustion. Nothing in the code can prevent that; what it
    # can do is report it as one bad arm and let the rest proceed.
    server: _QuietThreadingHTTPServer | None = None
    thread: Thread | None = None
    thread_started = False
    try:
        server = _QuietThreadingHTTPServer(
            ("127.0.0.1", 0),
            _handler(
                script_bytes,
                log,
                config.dom_profile,
                config.script_path,
                config.hook_mode,
                config.hook_target_names,
                stage_payloads,
                config.inline_script,
                declared_script_url=config.declared_script_url,
                prelude_js=config.prelude_js,
            ),
        )
        server.daemon_threads = True
        port = server.server_port
        if (
            isinstance(port, bool)
            or not isinstance(port, int)
            or not 1 <= port <= 65535
        ):
            raise ContractError("rehost server listener port is invalid")
        thread = Thread(
            target=server.serve_forever,
            name="browser-core-product-rehost",
            daemon=True,
        )
    except (ContractError, OSError, RuntimeError, ValueError) as exc:
        cleanup_failures = _stop_rehost_server(
            server,
            thread,
            thread_started=False,
        )
        if cleanup_failures:
            error = f"rehost server cleanup failed ({','.join(cleanup_failures)})"
        else:
            category = (
                "rehost server could not bind"
                if server is None
                else "rehost server could not start"
            )
            error = _failure_receipt(category, exc)
        return _failed_observation(
            config,
            identity,
            error,
            rehost_contract,
            script_bytes,
        )
    try:
        thread.start()
        thread_started = True
    except (OSError, RuntimeError) as exc:
        # A worker can be running even when start reports an error. Retain it
        # for the same bounded shutdown and join used after a normal start.
        try:
            thread_started = thread.is_alive() is not False
        except AttributeError:
            thread_started = False
        except (OSError, RuntimeError):
            thread_started = True
        cleanup_failures = _stop_rehost_server(
            server,
            thread,
            thread_started=thread_started,
        )
        error = (
            f"rehost server cleanup failed ({','.join(cleanup_failures)})"
            if cleanup_failures
            else _failure_receipt("rehost server could not start", exc)
        )
        return _failed_observation(
            config,
            identity,
            error,
            rehost_contract,
            script_bytes,
        )
    url = f"http://127.0.0.1:{port}/"
    offline_resolver_rule = _offline_resolver_rule(port)

    session_path: Path | None = None
    session: dict[str, Any] | None = None
    error: str | None = None
    geometry: dict[str, Any] | None = None
    startup: dict[str, Any] | None = None
    resource_intents: dict[str, Any] | None = None
    driver_result: dict[str, Any] | None = None
    await_report: dict[str, Any] | None = None
    harvests: list[dict[str, Any]] = []
    input_report: dict[str, Any] | None = None
    stop_report: dict[str, Any] | None = None
    server_cleanup_error: str | None = None
    session_cleanup_error: str | None = None
    try:
        session_path, session = launch_evaluation(
            EvaluationLaunch(
                executable=config.executable,
                workspace=config.workspace,
                headless=not config.headed,
                timeout_seconds=config.timeout_seconds,
                trace_mode="on",
                trace_scope=config.trace_scope,
                extra_args=(offline_resolver_rule, *config.extra_browser_args, url),
                local_containment_proxy=("127.0.0.1", port, port),
            ),
            repository_root,
        )
        endpoint = session["automation"]["cdp_endpoint"]
        wait_for_page_target(
            endpoint, url, PAGE_TITLE, timeout_seconds=config.timeout_seconds
        )
        geometry = _capture_geometry(endpoint, url, config.timeout_seconds)
        if config.driver_js:
            # After load and before the measured dwell: the collector needs to
            # exist before it can be driven, and everything it does afterwards is
            # what this arm is for.
            try:
                raw_driver_result = evaluate_page_expression(
                    endpoint,
                    config.driver_js,
                    target_url=url,
                    timeout_seconds=config.timeout_seconds,
                    command_id=953,
                )
                driver_result = _driver_result_metadata(raw_driver_result)
            except Exception as exc:  # noqa: BLE001 - recorded, never fatal
                driver_result = _driver_error_metadata(exc)
        if config.await_ready_seconds > 0:
            # Replaces the dwell rather than adding to it: waiting for the thing
            # and then also sleeping a fixed period would make the arm's duration
            # mean two things at once.
            await_report = await_collector_ready(
                endpoint,
                url,
                cap_seconds=config.await_ready_seconds,
                poll_timeout_seconds=config.timeout_seconds,
                ready_expression=config.ready_expression,
            )
        elif config.input_profile != "none":
            # Half the dwell before, half after: the collector needs time to bind
            # its listeners first, and time to act on what they receive.
            time.sleep(config.dwell_seconds / 2)
            input_report = _drive_input_probe(
                endpoint,
                url,
                config.timeout_seconds,
                profile=config.input_profile,
            )
            time.sleep(config.dwell_seconds / 2)
        else:
            time.sleep(config.dwell_seconds)
        startup = _capture_startup(endpoint, url, config.timeout_seconds)
        if config.capture_resource_intents:
            resource_intents = _capture_resource_intents(
                endpoint, url, config.timeout_seconds
            )
        else:
            resource_intents = {
                "status": "off",
                "source": "cdp_dom_snapshot",
                "intents": [],
                "non_claim": "resource-intent capture disabled for this method arm",
            }
        if config.hook_mode == "on":
            harvests.append(
                _harvest_arguments(endpoint, url, config.timeout_seconds, 951)
            )
        for index in range(max(config.reloads, 0)):
            evaluate_page_expression(
                endpoint,
                "(() => { location.reload(); return true; })()",
                target_url=url,
                timeout_seconds=config.timeout_seconds,
                command_id=947,
            )
            wait_for_page_target(
                endpoint, url, PAGE_TITLE, timeout_seconds=config.timeout_seconds
            )
            time.sleep(config.dwell_seconds)
            # Harvested per load, not once at the end: a reload resets the JS heap,
            # so a single final harvest would silently report only the last load.
            if config.hook_mode == "on":
                harvests.append(
                    _harvest_arguments(
                        endpoint, url, config.timeout_seconds, 952 + index
                    )
                )
    except Exception as exc:  # noqa: BLE001 - recorded, arm reports failure
        error = _failure_receipt("observation execution failed", exc)
    finally:
        if session_path is not None:
            try:
                raw_stop_report = _stop_observation_session(
                    session_path,
                    config.timeout_seconds,
                )
                stop_report = _validated_observation_stop_receipt(
                    raw_stop_report,
                    expected_run_id=session["run_id"],
                )
            except Exception as exc:  # noqa: BLE001
                session_cleanup_error = _failure_receipt(
                    "observation stop failed",
                    exc,
                )
        cleanup_failures = _stop_rehost_server(
            server,
            thread,
            thread_started=thread_started,
        )
        if cleanup_failures:
            server_cleanup_error = (
                f"rehost server cleanup failed ({','.join(cleanup_failures)})"
            )

    if server_cleanup_error is not None:
        return _failed_observation(
            config,
            identity,
            server_cleanup_error,
            rehost_contract,
            script_bytes,
        )
    if session_cleanup_error is not None:
        return _failed_observation(
            config,
            identity,
            session_cleanup_error,
            rehost_contract,
            script_bytes,
        )

    server_requests, request_activity, unserved_requests, request_log_receipt = (
        _request_log_artifacts(log)
    )
    result: dict[str, Any] = {
        "schema": OBSERVATION_SCHEMA,
        "generated_at": _utc_now(),
        "label": config.label,
        "script_basename": config.script.name,
        "script_sha256_16": identity["signals"]["sha256_16"],
        "script_bytes": identity["signals"]["bytes"],
        "script_identity": identity,
        "provenance": _resolve_provenance(config, script_bytes),
        "source_provenance": source_provenance,
        "trace_scope": config.trace_scope,
        "headed": config.headed,
        "dwell_seconds": config.dwell_seconds,
        "timeout_seconds": config.timeout_seconds,
        "dom_profile": config.dom_profile,
        "rehost_contract": rehost_contract,
        "script_path": config.script_path,
        "declared_script_url": config.declared_script_url,
        "prelude": _prelude_metadata(config.prelude_js),
        "extra_browser_args": list(config.extra_browser_args),
        "viewport": geometry,
        "hook_mode": config.hook_mode,
        "hook_target_names": list(config.hook_target_names),
        "input_profile": config.input_profile,
        "input_probe": _sanitize_input_probe_report(input_report),
        "startup": startup,
        "ambient_input": grade_ambient_input(startup, config.input_profile),
        "browser_shutdown": (
            {"mode": stop_report.get("shutdown_mode")}
            if isinstance(stop_report, dict)
            and isinstance(stop_report.get("shutdown_mode"), str)
            else None
        ),
        "trace_flush": None,
        "trace_export_budget": None,
        # An arm that was driven is a different measurement from one that was not.
        "driver": _prelude_metadata(config.driver_js),
        "driver_result": driver_result,
        "await_ready_seconds": config.await_ready_seconds,
        "ready_expression": _prelude_metadata(config.ready_expression),
        "resource_intent_capture": resource_intent_capture,
        "resource_intents": resource_intents,
        "inline_script": config.inline_script,
        "await_report": await_report,
        "stage_routes": _stage_route_metadata(stage_payloads),
        "argument_capture": _merged_harvest(harvests)
        if config.hook_mode == "on"
        else None,
        "reloads": config.reloads,
        "page_loads": config.reloads + 1,
        "offline_guard": {
            "status": "applied",
            "resolver_rule": offline_resolver_rule,
            "proxy_policy": "deny-all-except-owned-loopback-origin",
            "webrtc_policy": "disable-non-proxied-udp",
            "quic_policy": "disabled",
            "proxy_endpoint": f"127.0.0.1:{port}",
            "bypass_endpoint": f"127.0.0.1:{port}",
        },
        "server_requests": server_requests,
        "server_request_log": request_log_receipt,
        "request_activity": request_activity,
        "unserved_requests": unserved_requests,
        "chromium_revision": session.get("chromium_revision") if session else None,
        "browser_build": (
            {
                key: session.get("build", {}).get(key)
                for key in (
                    "provenance",
                    "executable_sha256_16",
                    "runtime_bundle_sha256_16",
                    "attestation_created_at",
                )
                if session.get("build", {}).get(key) is not None
            }
            if session and isinstance(session.get("build"), dict)
            else None
        ),
        "trace_category_contract": (
            session.get("trace_category_contract") if session else None
        ),
        "error": error,
        "non_claims": [
            "offline rehost of a stored sample; not a live product session",
            "no acceptance, bypass, evasion, or bot-score claim",
            "no captured value retained: API names, counts, and contexts only",
        ],
    }

    if session is None:
        return _seal_observation_document(result)

    result["run_id"] = session["run_id"]
    trace_path = Path(session["trace_path"])
    out_jsonl = trace_path.with_suffix(".jsonl")

    trace_settled = _await_trace_file(trace_path, config.timeout_seconds)
    result["trace_flush"] = _trace_flush_receipt(trace_path, trace_settled)
    result["trace_export_budget"] = _trace_export_budget_receipt(result["trace_flush"])
    if not trace_settled:
        result["error"] = (
            "trace export failed: trace file " + result["trace_flush"]["status"]
        )
        return _seal_observation_document(result)
    if result["trace_export_budget"]["bytes_within_budget"] is False:
        result["error"] = (
            "trace export skipped: source trace exceeds the automatic "
            f"{MAX_OBSERVATION_TRACE_EXPORT_BYTES}-byte safety budget"
        )
        return _seal_observation_document(result)
    if result["trace_export_budget"]["bytes_within_budget"] is not True:
        result["error"] = (
            "trace export failed: settled trace is not a regular single-link file"
        )
        return _seal_observation_document(result)
    if result["trace_export_budget"]["bytes_within_budget"] is True:
        try:
            source_binding = bind_perfetto_source_trace(trace_path)
            if source_binding["bytes"] != result["trace_flush"]["bytes"]:
                raise ContractError("Perfetto source trace changed after settling")
            exportable_events = count_exportable_events(
                config.trace_processor.resolve(),
                trace_path,
                expected_source_binding=source_binding,
            )
        except Exception as exc:  # noqa: BLE001 - recorded, arm reports failure
            result["error"] = _failure_receipt("trace export preflight failed", exc)
            return _seal_observation_document(result)
        result["trace_export_budget"] = _trace_export_budget_receipt(
            result["trace_flush"], exportable_events
        )
        if result["trace_export_budget"]["events_within_budget"] is False:
            result["error"] = (
                "trace export skipped: exportable event count exceeds the automatic "
                f"{MAX_OBSERVATION_TRACE_EXPORT_EVENTS}-event safety budget"
            )
            return _seal_observation_document(result)

    # A failed export must fail one arm, not a batch.
    #
    # Chromium occasionally exits without having flushed its Perfetto trace, and
    # the export then raises "Perfetto trace does not exist". Previously that
    # propagated out of the runner and killed the whole run: measured across
    # session-2 batches, 2 of 27 and 1 of 22 arms vanished this way, and because
    # the exception escaped, the arms *after* the failure were never attempted
    # either. Re-running them individually worked, which is what made the cause
    # look mysterious rather than merely flaky.
    #
    # An arm with no `analysis` already reads as failed everywhere downstream --
    # `subtract_control` refuses it by name -- so recording the failure is strictly
    # more informative than raising, and it lets the rest of the batch proceed.
    try:
        result["export"] = export_perfetto(
            config.trace_processor.resolve(),
            trace_path,
            out_jsonl,
            session["run_id"],
            session["chromium_revision"],
            out_jsonl.with_suffix(".export.json"),
            maximum_events=MAX_OBSERVATION_TRACE_EXPORT_EVENTS,
            expected_source_binding=source_binding,
        )
        result["normalized_trace_file"] = str(out_jsonl)
        analysis = analyse_observation_trace(out_jsonl)
    except Exception as exc:  # noqa: BLE001 - recorded, arm reports failure
        result["error"] = _failure_receipt("trace export failed", exc)
        return _seal_observation_document(result)

    # Deliberately outside the try: the offline guard is a safety property, not a
    # flake, and must still stop the run rather than be recorded as a bad arm.
    fetch_target_scope = analysis.get("fetch_target_scope")
    if (
        not isinstance(fetch_target_scope, dict)
        or fetch_target_scope.get("coverage") != "complete"
    ):
        raise ContractError("offline rehost fetch target-scope evidence is incomplete")
    if fetch_target_scope.get("external"):
        raise ContractError(
            "offline rehost observed an external fetch target; the offline guard failed"
        )
    if result["error"] is not None:
        # A blocked renderer can prevent every page-world CDP probe while the
        # browser process still flushes a valid native trace. Preserve the arm's
        # failure status, but retain the value-free execution/open-state summary
        # as diagnostics. It must not travel through the ordinary `analysis`
        # field, because downstream subtraction treats that field as claim input.
        result["diagnostic_trace_analysis"] = analysis
        return _seal_observation_document(result)
    result["analysis"] = analysis
    # Graded here rather than with the other metadata: the verdict reads the
    # attributable count, and "nothing attributable" is only damning once the
    # trace has actually been analysed.
    result["collector_startup"] = grade_collector_startup(
        startup,
        analysis["attributable_events"],
        analysis.get("execution_context_counts"),
    )
    return _seal_observation_document(result)


def write_observation(
    path: str | Path,
    document: dict[str, Any],
    *,
    overwrite: bool = False,
) -> Path:
    if not isinstance(path, (str, Path)):
        raise ContractError("product observation path must be text or a Path")
    if not isinstance(document, dict):
        raise ContractError("product observation document must be an object")
    schema = document.get("schema")
    reject_sensitive_keys(document)
    if schema == OBSERVATION_SCHEMA:
        if (
            not isinstance(document.get("observation_receipt_sha256"), str)
            or re.fullmatch(
                r"[0-9a-f]{64}", document["observation_receipt_sha256"]
            )
            is None
        ):
            raise ContractError("observation write requires a complete receipt")
        _verified_observation_receipt(document)
    elif schema == SUBTRACTION_SCHEMA:
        if (
            not isinstance(document.get("subtraction_receipt_sha256"), str)
            or re.fullmatch(
                r"[0-9a-f]{64}", document["subtraction_receipt_sha256"]
            )
            is None
        ):
            raise ContractError("subtraction write requires a complete receipt")
        _verified_subtraction_receipt(document)
    elif schema == BASELINE_SCHEMA:
        if (
            not isinstance(document.get("baseline_receipt_sha256"), str)
            or re.fullmatch(
                r"[0-9a-f]{64}", document["baseline_receipt_sha256"]
            )
            is None
        ):
            raise ContractError("baseline write requires a complete receipt")
        _verified_baseline_receipt(document)
    elif schema in {DRIFT_SCHEMA, COMPARISON_SCHEMA}:
        if (
            not isinstance(document.get("decision_receipt_sha256"), str)
            or re.fullmatch(
                r"[0-9a-f]{64}", document["decision_receipt_sha256"]
            )
            is None
        ):
            raise ContractError("decision write requires a complete receipt")
        _verified_decision_receipt(document)
    if not isinstance(overwrite, bool):
        raise ContractError("product observation overwrite choice must be boolean")
    path = Path(path)
    prepare_owned_directory_parent(path.parent, label="product observation output parent")
    if not overwrite:
        publish_json_exclusive_result(
            path,
            document,
            maximum=MAX_OBSERVATION_DOCUMENT_BYTES,
            label="product observation",
        )
    else:
        current = read_bounded_control_snapshot_result(
            path,
            maximum=MAX_OBSERVATION_DOCUMENT_BYTES,
            label="product observation",
            require_single_link=True,
        )
        if current.state == "missing":
            publish_json_exclusive_result(
                path,
                document,
                maximum=MAX_OBSERVATION_DOCUMENT_BYTES,
                label="product observation",
            )
        elif (
            current.state == "complete"
            and current.body is not None
            and current.identity is not None
        ):
            replace_json_conditionally_result(
                path,
                document,
                expected_body=current.body,
                expected_identity=current.identity,
                maximum=MAX_OBSERVATION_DOCUMENT_BYTES,
                label="product observation",
            )
        else:
            raise ContractError(f"product observation is {current.state}")
    return path


def load_observation(path: str | Path) -> dict[str, Any]:
    """Load an observation, subtraction, baseline, or decision document.

    Accepts a ``str`` as well as a ``Path``. That is not cosmetic: the previous
    signature took only ``Path`` and called ``path.read_text()``, so passing a
    string from ``glob.glob`` raised ``AttributeError`` — an error shaped like a
    bug in the caller's own code rather than a bad argument. On 2026-08-06 that
    combined with a caller's broad ``except Exception: continue`` to silently drop
    all 123 documents in a corpus scan, and the analysis built on the empty result
    looked entirely plausible: every technique came back "absent", including ones
    that are plainly present.

    Coercing here is the fix. A wrong *path* still raises loudly; only the
    argument *type* is forgiving.
    """
    if not isinstance(path, (str, Path)):
        raise ContractError("product observation path must be text or a Path")
    path = Path(path)
    snapshot = read_bounded_control_snapshot_result(
        path,
        maximum=MAX_OBSERVATION_DOCUMENT_BYTES,
        label="product observation",
    )
    if snapshot.state == "missing":
        raise FileNotFoundError(path)
    if snapshot.state == "locked":
        raise PermissionError(path)
    if snapshot.state != "complete":
        raise ContractError(f"product observation is {snapshot.state}")
    assert snapshot.body is not None
    document = decode_strict_json_bytes(snapshot.body, label="product observation")
    if not isinstance(document, dict):
        raise ContractError(f"not a product-script observation document: {path}")
    document_schema = document.get("schema")
    if not isinstance(document_schema, str) or document_schema not in {
        OBSERVATION_SCHEMA,
        SUBTRACTION_SCHEMA,
        BASELINE_SCHEMA,
        DRIFT_SCHEMA,
        COMPARISON_SCHEMA,
    }:
        raise ContractError(f"not a product-script observation document: {path}")
    if document_schema == OBSERVATION_SCHEMA:
        _verified_observation_receipt(document)
    elif document_schema == SUBTRACTION_SCHEMA:
        _verified_subtraction_receipt(document)
    elif document_schema == BASELINE_SCHEMA:
        _verified_baseline_receipt(document)
    elif document_schema in {DRIFT_SCHEMA, COMPARISON_SCHEMA}:
        _verified_decision_receipt(document)
    return document
