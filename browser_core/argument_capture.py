"""Argument-level observation of a rehosted product script, with a fidelity control.

The passive native trace answers *which* engine surfaces a collector reached and
*how many times*. It cannot answer *with what*. That gap is the difference between

    api.EventTarget.addEventListener   19

and

    addEventListener  ->  mousemove, mousedown, touchstart, deviceorientation, ...

Only the second is a finding. The first is a fact about a name that every page on
the web produces. Recovering the arguments is what turns a surface inventory into
an account of what the collector is actually looking at.

Why this module is different from everything else here
------------------------------------------------------
Every other observation path in this package is **passive**: tracing happens in
C++ below the JS heap and the page cannot tell. This one is **active** -- it
replaces functions on built-in prototypes before the sample runs. That is a real
methodological cost and it is stated here rather than buried:

* A wrapped function is not the original object. ``Function.prototype.toString``,
  property descriptors, and function identity all change.
* A collector that checks for wrapping will see it, and if it branches on that
  check, the arguments recorded are the arguments of the *detected* branch.

Two things are done about it, and the second is the one that matters.

**Fidelity.** Wrappers preserve ``name`` and ``length``, live on the same property
with the same descriptor flags, and stringify as native source. This is
observer-effect minimisation for a stored artifact in an offline lab -- the same
reason a probe should not load the circuit it measures. It is not an evasion
capability and cannot be used as one: nothing here runs against a live origin, and
the rehost server is the only origin that exists.

**Measurement of the observer effect, which is the real contribution.** Because
the native trace sees calls at the binding layer regardless of JS wrapping, this
package owns an *independent oracle* for whether the instrument perturbed the
subject. :func:`compare_hook_fidelity` compares the same pin run four times -- arm and
control, hook on and hook off -- subtracts each pair, and compares the two
attributed surfaces. If they are identical, the hook did not change what the script
did, to the resolution the surface can express. If they differ, the argument data
is reported as suspect and the differing names are named.

Most JS hooking in this field is unvalidated: you hook, you get data, and you hope
nothing moved. Here it is checkable, so it is checked.

What is recorded, and what is refused
-------------------------------------
The rule is: **record what the collector asked for, never what this host
answered.** The question is the vendor's and is the finding; the answer is our
machine's private state and is not.

So ``getParameter(UNMASKED_RENDERER_WEBGL)`` is recorded as exactly that -- the
enum the collector chose -- while the returned GPU model string is reduced to
``str(46)``. Arguments are recorded as a *class* by default (type, and length for
strings). A value is retained only at positions on an explicit allowlist, and only
where the value is a vendor-chosen constant rather than user or host data: event
type names, media-query strings, CSS selectors, WebGL enums, storage **keys**,
element tag names, permission names.

Storage values, cookie contents, canvas pixel data, ``postMessage`` payloads, form
field contents and full URLs are never recorded at any position, allowlist or not.
That is enforced in :func:`_check_policy` and tested, not merely intended.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from dataclasses import dataclass
from typing import Any

from .contracts import ContractError
from .control_files import decode_strict_json_bytes
from .errors import normalize_renderer_failures
from .numeric import is_finite_number

CAPTURE_SCHEMA = "browser-core.product-script-arguments/1"
FIDELITY_SCHEMA = "browser-core.argument-capture-fidelity/1"

_FIDELITY_BASE_LIMITS = [
    "a clean result bounds perturbation at the resolution of the API name "
    "set; a different branch reaching the same names would not show",
    "call counts are not compared here because the hook itself calls into "
    "the engine and those calls cancel only approximately",
]
_FIDELITY_UNCLASSIFIED_LIMIT = (
    "no raw arms supplied, so a surface difference cannot be traced to "
    "the sample or to the instrument's own footprint in the control; "
    "pass hooked_arms and plain_arms to classify it"
)

# Bounds are enforced in the page, not just checked afterwards, so a pathological
# sample cannot produce an unbounded harvest. A CDP message is capped at 1 MB and
# the harvest must fit inside one with room to spare.
#
# The per-name cap was 40 and that was too low to be honest with. `defineProperty`
# on the Akamai BM web pin carries 48 distinct argument sets -- the collector's own
# internal signal names -- so a cap of 40 silently truncated the single most
# informative list the instrument produces. The report did say samples had been
# dropped, which is why it was caught, but a bound that routinely bites turns
# "complete set" into "sample" without changing anything a reader sees.
CAP_SAMPLES_PER_NAME = 200
CAP_TOTAL_SAMPLES = 6000
CAP_STRING_CHARS = 120
CAP_HARVEST_BYTES = 400_000
MAX_SAFE_INTEGER = (1 << 53) - 1
MAX_HARVESTS_TO_MERGE = 1_000
MAX_ARGUMENT_CORPUS_ARMS = 10_000

_HARVEST_FIELDS = frozenset(
    {
        "records",
        "total_samples",
        "dropped",
        "record_failures",
        "installed",
        "self_suppressed",
    }
)
_RECORD_FIELDS = frozenset({"name", "calls", "distinct", "dropped", "samples"})
_SAMPLE_FIELDS = frozenset({"args", "count"})
_INSTALL_STATUSES = frozenset(
    {
        "ok",
        "prop-absent",
        "not-configurable",
        "not-a-getter",
        "not-a-function",
        "define-threw",
        "threw",
    }
)
_CAPTURE_NON_CLAIMS = [
    "active instrumentation: wrappers replace built-ins before the sample runs",
    "arguments are the collector's question; returned values are this host's "
    "answer and are not recorded",
    "run `observe validate-hook` to test whether the instrument perturbed "
    "the passively observed surface",
]


# --------------------------------------------------------------- redaction policy

# Positions whose value is *never* retained, whatever a target declares. Keyed by
# the fully-qualified target name. These are the surfaces where the argument is
# user data, host state, or a secret rather than a vendor-chosen constant.
#
# This exists because `record_args` is a per-target declaration and a future
# target could name a position that looks structural but carries a value. The
# denylist is checked at construction time so the mistake cannot ship.
NEVER_RECORD_VALUES: frozenset[str] = frozenset(
    {
        "Storage.setItem",  # key is fine (position 0); the value is not
        "Document.cookie",
        "CanvasRenderingContext2D.getImageData",
        "HTMLCanvasElement.toDataURL",
        "HTMLCanvasElement.toBlob",
        "Window.postMessage",
        "MessagePort.postMessage",
        "Worker.postMessage",
        "Navigator.sendBeacon",
        "XMLHttpRequest.send",
        "TextEncoder.encode",
        "CryptoSubtle.digest",
    }
)

# Positions that may carry a value even for a denylisted target, because the
# position itself is structural. `Storage.setItem` records its key and never its
# value; that distinction is the whole point of having both lists.
STRUCTURAL_POSITIONS: dict[str, tuple[int, ...]] = {
    "Storage.setItem": (0,),
    "Navigator.sendBeacon": (),
    "XMLHttpRequest.send": (),
}

# Object arguments are classed by default (``obj:Object``), never traversed, and
# sensitive string positions are not retained. Tiny named projections are safer
# than either a generic object serializer or a generic URL recorder: each states
# both the transformation and the one target for which it is allowed. Permission
# descriptors and resource routing are collector-authored questions; returned
# permission state and URL values are not retained.
SAFE_ARG_PROJECTIONS: dict[str, tuple[tuple[int, str], ...]] = {
    "Element.setAttribute": ((1, "url-shape-if-arg0-src"),),
    "Permissions.query": ((0, "permission-name"),),
}


@dataclass(frozen=True)
class HookTarget:
    """One instrumented property.

    ``owner`` is a dotted path resolved from ``globalThis`` in the page, e.g.
    ``EventTarget.prototype``. It may list ``|``-separated alternatives, tried in
    order until one carries the property; the resolved one is reported. That is not
    cosmetic robustness -- ``matchMedia`` and friends are *not* own properties of
    the global object, they live on ``Window.prototype``, and a single-path
    resolver reported six of them as ``prop-absent``, which reads exactly like "the
    collector never called them".

    ``kind`` selects how the property is replaced: ``method`` wraps a callable,
    ``getter`` wraps an accessor's get function.

    ``record_args`` names the argument positions whose *value* is retained. Every
    other position is reduced to a class. ``arg_projections`` names a deliberately
    narrow, policy-checked projection for an object argument; it is not a general
    object traversal facility. ``record_this_name`` retains the ``name`` of the
    receiver, which is only meaningful for ``Function.prototype.toString`` where
    the receiver's identity is the finding.
    """

    owner: str
    prop: str
    kind: str = "method"
    record_args: tuple[int, ...] = ()
    arg_projections: tuple[tuple[int, str], ...] = ()
    record_this_name: bool = False
    technique: str = "other"
    note: str = ""

    @property
    def name(self) -> str:
        first = self.owner.split("|")[0]
        base = first.split(".prototype")[0].split(".")[-1]
        if base in {"globalThis", "window", "self"}:
            base = "Window"
        return f"{base}.{self.prop}"


def _check_policy(target: HookTarget) -> None:
    """Refuse a target that would retain a value the policy forbids.

    Called for every target at import time. A redaction rule that is only written
    down in a docstring is a rule that a later edit silently repeals.
    """
    if any(
        HookTarget(owner, target.prop).name != target.name
        for owner in target.owner.split("|")
    ):
        raise ContractError("hook owner alternatives must share one policy identity")
    if target.kind not in {"method", "getter"}:
        raise ContractError(f"unknown hook kind for {target.name}: {target.kind!r}")
    if target.arg_projections:
        allowed = set(SAFE_ARG_PROJECTIONS.get(target.name, ()))
        illegal = [projection for projection in target.arg_projections if projection not in allowed]
        if illegal:
            raise ContractError(
                f"{target.name} declares unsafe argument projections: {illegal}"
            )
        positions = [position for position, _ in target.arg_projections]
        if len(positions) != len(set(positions)):
            raise ContractError(f"{target.name} declares two projections for one argument")
        overlap = sorted(set(positions) & set(target.record_args))
        if overlap:
            raise ContractError(
                f"{target.name} both records and projects argument positions {overlap}"
            )
    if not target.record_args and not target.arg_projections and not target.record_this_name:
        return
    if target.name in NEVER_RECORD_VALUES:
        allowed = STRUCTURAL_POSITIONS.get(target.name, ())
        illegal = [i for i in target.record_args if i not in allowed]
        if illegal:
            raise ContractError(
                f"{target.name} is on the never-record list; positions {illegal} "
                "would retain a value that policy forbids"
            )


# --------------------------------------------------------------------- targets

# Curated deliberately. Wrapping every callable surface would maximise the observer
# effect for no gain: most names carry no argument worth having (`Date.now`,
# `AudioContext.createOscillator`), and the cost of a wrapper is paid on every call.
# Each entry below is here because the *argument* answers a question the name alone
# cannot.
HOOK_TARGETS: tuple[HookTarget, ...] = (
    # --- the residual this module was built for -------------------------------
    HookTarget(
        "EventTarget.prototype", "addEventListener",
        record_args=(0,), technique="input-behaviour",
        note="which events the collector binds; the name alone says only that it binds ~19",
    ),
    HookTarget(
        "EventTarget.prototype", "removeEventListener",
        record_args=(0,), technique="input-behaviour",
    ),
    # --- what the collector looks for in the document -------------------------
    HookTarget("Document.prototype", "querySelector", record_args=(0,), technique="dom-probe"),
    HookTarget("Document.prototype", "querySelectorAll", record_args=(0,), technique="dom-probe"),
    HookTarget("Document.prototype", "getElementById", record_args=(0,), technique="dom-probe"),
    HookTarget(
        "Document.prototype", "getElementsByTagName",
        record_args=(0,), technique="dom-probe",
        note="which element class anchors a loader; APG uses the first script node",
    ),
    HookTarget("Document.prototype", "createElement", record_args=(0,), technique="dom-probe"),
    HookTarget("Element.prototype", "getAttribute", record_args=(0,), technique="dom-probe"),
    HookTarget(
        "Element.prototype", "setAttribute",
        record_args=(0,),
        arg_projections=((1, "url-shape-if-arg0-src"),),
        technique="dom-probe",
        note="for src only, retain origin, path-segment lengths, and query names",
    ),
    HookTarget(
        "Node.prototype", "insertBefore", technique="dom-probe",
        note="argument classes show which node type is injected and which anchor it precedes",
    ),
    # --- media queries are a documented fingerprint vector ---------------------
    HookTarget("Window.prototype|globalThis", "matchMedia", record_args=(0,), technique="screen-display"),
    HookTarget(
        "Window.prototype|globalThis", "getComputedStyle", technique="font-enumeration",
        note="receiver identity matters more than args; args are class-only",
    ),
    HookTarget(
        "CSSStyleDeclaration.prototype", "getPropertyValue",
        record_args=(0,), technique="font-enumeration",
    ),
    # --- canvas: the text and font are the fingerprint input -------------------
    HookTarget(
        "CanvasRenderingContext2D.prototype", "measureText",
        record_args=(0,), technique="font-enumeration",
        note="the measured string is a vendor constant and identifies the technique",
    ),
    HookTarget("CanvasRenderingContext2D.prototype", "fillText", record_args=(0,), technique="canvas-raster"),
    HookTarget("CanvasRenderingContext2D.prototype", "strokeText", record_args=(0,), technique="canvas-raster"),
    HookTarget("CanvasRenderingContext2D.prototype", "font", kind="getter", technique="font-enumeration"),
    HookTarget("HTMLCanvasElement.prototype", "toDataURL", technique="canvas-raster"),
    HookTarget("HTMLCanvasElement.prototype", "getContext", record_args=(0,), technique="canvas-raster"),
    # --- WebGL: which enum was asked for IS the fingerprint --------------------
    HookTarget(
        "WebGLRenderingContext.prototype", "getParameter",
        record_args=(0,), technique="webgl",
        note="enum numbers are resolved to names at render time",
    ),
    HookTarget("WebGLRenderingContext.prototype", "getExtension", record_args=(0,), technique="webgl"),
    HookTarget(
        "WebGLRenderingContext.prototype", "getShaderPrecisionFormat",
        record_args=(0, 1), technique="webgl",
    ),
    HookTarget("WebGL2RenderingContext.prototype", "getParameter", record_args=(0,), technique="webgl"),
    # --- storage: keys only, never values --------------------------------------
    HookTarget("Storage.prototype", "getItem", record_args=(0,), technique="storage"),
    HookTarget("Storage.prototype", "setItem", record_args=(0,), technique="storage"),
    HookTarget("Storage.prototype", "removeItem", record_args=(0,), technique="storage"),
    # --- transport: method and URL class, never the URL ------------------------
    HookTarget("XMLHttpRequest.prototype", "open", record_args=(0,), technique="network-transport"),
    HookTarget("XMLHttpRequest.prototype", "setRequestHeader", record_args=(0,), technique="network-transport"),
    HookTarget("Window.prototype|globalThis", "fetch", technique="network-transport"),
    HookTarget("Navigator.prototype", "sendBeacon", technique="network-transport"),
    # --- audio graph configuration is the audio fingerprint --------------------
    HookTarget("BaseAudioContext.prototype", "createOscillator", technique="audio-graph"),
    HookTarget("BaseAudioContext.prototype", "createAnalyser", technique="audio-graph"),
    HookTarget("BaseAudioContext.prototype", "createDynamicsCompressor", technique="audio-graph"),
    HookTarget("AnalyserNode.prototype", "getFloatFrequencyData", technique="audio-graph"),
    # --- timers: the delay is the behavioural signature ------------------------
    HookTarget("Window.prototype|globalThis", "setTimeout", record_args=(1,), technique="timing"),
    HookTarget("Window.prototype|globalThis", "setInterval", record_args=(1,), technique="timing"),
    HookTarget("Window.prototype|globalThis", "requestAnimationFrame", technique="timing"),
    # --- permissions and sensors ------------------------------------------------
    HookTarget(
        "Permissions.prototype", "query",
        arg_projections=((0, "permission-name"),), technique="permissions",
        note="retain only the descriptor name; never traverse arbitrary object arguments",
    ),
    HookTarget("Performance.prototype", "getEntriesByType", record_args=(0,), technique="timing"),
    HookTarget("Performance.prototype", "now", technique="timing"),
    # --- ECMAScript builtins: invisible to the passive trace at ANY scope -------
    #
    # `blink.bindings.generated` covers Web IDL only, so nothing below is
    # observable by the passive plane no matter what scope it runs at. These are
    # not argument *upgrades* to an existing name, they are the only channel that
    # exists for these calls. Chosen for signal-per-call: each is comparatively
    # cold, so wrapping it costs little, and each answers "what is the collector
    # introspecting" rather than merely "what did it touch".
    HookTarget(
        "Object", "getOwnPropertyDescriptor", record_args=(1,), technique="dom-probe",
        note="which properties the collector examines rather than merely reads; "
             "this is how a tamper check picks its targets",
    ),
    HookTarget(
        "Object", "getOwnPropertyNames", technique="dom-probe",
        note="argument is an object, so its CLASS is the finding: obj:Navigator "
             "says the collector enumerated navigator",
    ),
    HookTarget("Object", "keys", technique="dom-probe"),
    HookTarget(
        "Object", "defineProperty", record_args=(1,), technique="dom-probe",
        note="a collector defending its own surface names the property it protects",
    ),
    HookTarget("Reflect", "get", record_args=(1,), technique="dom-probe"),
    HookTarget("Date.prototype", "getTimezoneOffset", technique="navigator-identity"),
    HookTarget(
        "Intl.DateTimeFormat.prototype", "resolvedOptions",
        technique="navigator-identity",
        note="time zone and locale in one call, and entirely outside the trace",
    ),
    HookTarget(
        "Error", "captureStackTrace", technique="error-stack",
        note="V8-only; stack shape is a known automation-detection surface",
    ),
    HookTarget(
        "FontFaceSet.prototype", "check", record_args=(0,), technique="font-enumeration",
        note="the font spec being tested is the enumeration list itself",
    ),
    # --- the hook-detection probe itself is a finding ---------------------------
    HookTarget(
        "Function.prototype", "toString", record_this_name=True, technique="error-stack",
        note=(
            "a collector calling toString on a built-in is asking whether that built-in "
            "is native; recording the receiver's name says which built-ins it distrusts"
        ),
    ),
)

for _t in HOOK_TARGETS:
    _check_policy(_t)


# WebGL enums that matter for fingerprinting. Resolved at render time so a report
# reads `getParameter(UNMASKED_RENDERER_WEBGL)` rather than `getParameter(37446)`.
WEBGL_ENUMS: dict[int, str] = {
    0x1F00: "VENDOR",
    0x1F01: "RENDERER",
    0x1F02: "VERSION",
    0x8B8C: "SHADING_LANGUAGE_VERSION",
    0x9245: "UNMASKED_VENDOR_WEBGL",
    0x9246: "UNMASKED_RENDERER_WEBGL",
    0x0D33: "MAX_TEXTURE_SIZE",
    0x851C: "MAX_CUBE_MAP_TEXTURE_SIZE",
    0x8869: "MAX_VERTEX_ATTRIBS",
    0x8DFB: "MAX_FRAGMENT_UNIFORM_VECTORS",
    0x8DFA: "MAX_VARYING_VECTORS",
    0x8DFD: "MAX_VERTEX_UNIFORM_VECTORS",
    0x8872: "MAX_TEXTURE_IMAGE_UNITS",
    0x8B4D: "MAX_COMBINED_TEXTURE_IMAGE_UNITS",
    0x8B4C: "MAX_VERTEX_TEXTURE_IMAGE_UNITS",
    0x0D3A: "MAX_VIEWPORT_DIMS",
    0x846E: "ALIASED_LINE_WIDTH_RANGE",
    0x846D: "ALIASED_POINT_SIZE_RANGE",
    0x0D50: "RED_BITS",
    0x0D53: "ALPHA_BITS",
    0x0D56: "DEPTH_BITS",
    0x0D57: "STENCIL_BITS",
    0x8B8A: "IMPLEMENTATION_COLOR_READ_FORMAT",
    0x84E8: "MAX_RENDERBUFFER_SIZE",
    0x84FF: "MAX_TEXTURE_MAX_ANISOTROPY_EXT",
}


def resolve_webgl_enum(value: Any) -> str:
    """Render a WebGL enum as its constant name when it is a known one."""
    if type(value) is int:
        number = value
    elif type(value) is float and is_finite_number(value) and value.is_integer():
        number = int(value)
    else:
        return str(value)
    if not 0 <= number <= 0xFFFFFFFF:
        return str(value)
    name = WEBGL_ENUMS.get(number)
    return f"{name}(0x{number:04X})" if name else f"0x{number:04X}"


# ------------------------------------------------------------------- page script

# The instrument. Written to be inert on failure: every wrapper is wrapped in its
# own try/catch and always calls through to the original, so a sample can never
# break because it was being observed. A recording failure loses a record; it must
# never lose a call.
_HOOK_JS_TEMPLATE = """
(function () {
  'use strict';
  var SPEC = __SPEC__;
  var CAP_N = __CAP_N__, CAP_TOTAL = __CAP_TOTAL__, CAP_STR = __CAP_STR__;

  var store = Object.create(null);
  var total = 0, dropped = 0, failures = 0, suppressed = 0;
  var wrapped = new WeakMap();
  var inToString = false;

  function clip(v) {
    if (v.length <= CAP_STR) return v;
    var end = CAP_STR;
    // JavaScript indexes UTF-16 code units; slicing between a surrogate pair
    // would turn an ordinary emoji into invalid Unicode in the saved harvest.
    var last = v.charCodeAt(end - 1);
    if (last >= 0xD800 && last <= 0xDBFF) end -= 1;
    return v.slice(0, end) + '…';
  }

  // Suppresses recording while the instrument is installing itself.
  //
  // Installation is not passive: resolving an owner calls
  // Object.getOwnPropertyDescriptor, replacing a property calls
  // Object.defineProperty, and preserving a wrapper's identity calls it twice
  // more for `name` and `length`. Once those three are themselves instrumented,
  // every later install is recorded as if the *sample* had made the call.
  //
  // Measured 2026-08-06 before this guard existed: 9 of 14 recorded
  // getOwnPropertyDescriptor targets and roughly 100 of 171 defineProperty calls
  // were the instrument observing itself, including a record of it defining its
  // own harvest global. Read at face value that is a collector introspecting
  // Date, FontFaceSet and Intl -- a finding assembled entirely from self-noise.
  var installing = true;

  // Considered and rejected 2026-08-06: naming well-known globals, so that
  // `Object.keys(obj:Object)` could read `Object.keys(global:navigator)`. Doing so
  // requires resolving `globalThis.navigator`, `screen`, `document` and friends --
  // and if that happens lazily inside cls() it happens *during the sample's call*,
  // post-install, where the trace cannot tell the instrument's read from the
  // sample's. It would inflate exactly the identity surfaces the collector is being
  // measured on, in the arm only, so it would not even cancel in subtraction.
  // Resolving them eagerly at install time avoids the asymmetry but grows the
  // instrument footprint to include `navigator`, costing attribution of a name the
  // collector certainly uses. Either way the price is higher than a nicer label.
  function cls(v) {
    try {
      if (v === null) return 'null';
      var t = typeof v;
      if (t === 'undefined') return 'undefined';
      if (t === 'string') return 'str(' + v.length + ')';
      if (t === 'number') return (v % 1 === 0) ? 'int' : 'float';
      if (t === 'boolean') return 'bool';
      if (t === 'function') return 'function';
      if (t === 'symbol') return 'symbol';
      if (t === 'bigint') return 'bigint';
      var c = v.constructor;
      return clip('obj:' + ((c && c.name) ? c.name : '?'));
    } catch (e) { return 'unreadable'; }
  }

  function val(v) {
    try {
      var t = typeof v;
      if (t === 'string') return clip(v);
      if (t === 'number') {
        if (v !== v) return 'number:NaN';
        if (v === Infinity) return 'number:+Infinity';
        if (v === -Infinity) return 'number:-Infinity';
        if (v === 0 && 1 / v === -Infinity) return 'number:-0';
        if (v % 1 === 0 && (v > 9007199254740991 || v < -9007199254740991)) {
          return 'number:outside-safe-integer';
        }
        return v;
      }
      if (t === 'boolean') return v;
      return cls(v);
    } catch (e) { return 'unreadable'; }
  }

  function urlShape(v) {
    if (typeof v !== 'string') return 'url-shape:' + cls(v);
    try {
      // URL parts are page-controlled. Avoid splitting an arbitrarily large
      // value inside the observed page when the retained shape is capped.
      if (v.length > 16384) return 'url-shape:oversize';
      var match = /^([A-Za-z][A-Za-z0-9+.-]*:\\/\\/[^/?#]*)([^?#]*)(?:\\?([^#]*))?/.exec(v);
      var authority = match ? match[1] : 'relative';
      var path = match ? match[2] : v.split(/[?#]/, 1)[0];
      var query = match ? (match[3] || '') : ((v.split('?', 2)[1] || '').split('#', 1)[0]);
      // Strip credentials before retaining an absolute authority. The origin is
      // collector-authored routing evidence; userinfo never is.
      var schemeEnd = authority.indexOf('://');
      if (schemeEnd >= 0) {
        var prefix = authority.slice(0, schemeEnd + 3);
        var host = authority.slice(schemeEnd + 3);
        var at = host.lastIndexOf('@');
        authority = prefix + (at >= 0 ? host.slice(at + 1) : host);
      }
      var lengths = [];
      var segments = path.split('/');
      for (var i = 0; i < segments.length && lengths.length < 24; i++) {
        if (segments[i]) lengths.push(String(segments[i].length));
      }
      var keys = [];
      if (query) {
        var pairs = query.split('&');
        for (var j = 0; j < pairs.length && keys.length < 24; j++) {
          var key = pairs[j].split('=', 1)[0];
          keys.push(/^[A-Za-z][A-Za-z0-9_-]{0,31}$/.test(key)
                    ? key : 'key(' + key.length + ')');
        }
      }
      return clip('url-shape:' + authority + '|segments:' + lengths.join('.')
                  + (keys.length ? '|query:' + keys.join(',') : ''));
    } catch (e) { return 'url-shape:unreadable'; }
  }

  function project(spec, index, args) {
    var projections = spec.arg_projections || [];
    for (var i = 0; i < projections.length; i++) {
      if (projections[i][0] !== index) continue;
      var v = args[index];
      if (projections[i][1] === 'permission-name') {
        try {
          var name = v && v.name;
          if (typeof name !== 'string') return { matched: true, value: 'permission:' + cls(name) };
          return { matched: true, value: clip('permission:' + name) };
        } catch (e) { return { matched: true, value: 'permission:unreadable' }; }
      }
      if (projections[i][1] === 'url-shape-if-arg0-src') {
        var attribute = args.length > 0 ? args[0] : undefined;
        return { matched: true, value: attribute === 'src' ? urlShape(v) : cls(v) };
      }
    }
    return { matched: false };
  }

  function record(name, sample) {
    if (installing) { suppressed += 1; return; }
    try {
      var slot = store[name];
      if (!slot) { slot = store[name] = { calls: 0, samples: [], distinct: 0, dropped: 0 }; }
      slot.calls += 1;
      if (sample === null) return;
      var key = JSON.stringify(sample);
      for (var i = 0; i < slot.samples.length; i++) {
        if (slot.samples[i].k === key) { slot.samples[i].n += 1; return; }
      }
      if (slot.samples.length >= CAP_N || total >= CAP_TOTAL) {
        slot.dropped += 1; dropped += 1; return;
      }
      slot.samples.push({ k: key, v: sample, n: 1 });
      slot.distinct += 1;
      total += 1;
    } catch (e) { failures += 1; }
  }

  function summarise(spec, args, self) {
    var out = [];
    var keep = spec.record_args || [];
    for (var i = 0; i < args.length && i < 8; i++) {
      var projection = project(spec, i, args);
      out.push(projection.matched ? projection.value
                                 : (keep.indexOf(i) >= 0 ? val(args[i]) : cls(args[i])));
    }
    if (spec.record_this_name) {
      var n = 'unnamed';
      try { if (self && typeof self.name === 'string') n = self.name || 'anonymous'; }
      catch (e) { n = 'unreadable'; }
      out.push(clip('<-' + n));
    }
    return out;
  }

  function resolve(path) {
    var cur = globalThis;
    var parts = path.split('.');
    for (var i = 0; i < parts.length; i++) {
      if (cur === undefined || cur === null) return undefined;
      if (parts[i] === 'window' || parts[i] === 'globalThis') { cur = globalThis; continue; }
      cur = cur[parts[i]];
    }
    return cur;
  }

  // Fidelity: a wrapped built-in must stringify as native source. This is
  // observer-effect minimisation for an offline lab replay -- an instrument that
  // announces itself measures the announcement, not the subject.
  var nativeToString = Function.prototype.toString;
  function markNative(fn, original) {
    try {
      wrapped.set(fn, original);
      Object.defineProperty(fn, 'name', {
        value: original.name, configurable: true, writable: false, enumerable: false });
      Object.defineProperty(fn, 'length', {
        value: original.length, configurable: true, writable: false, enumerable: false });
    } catch (e) { failures += 1; }
  }

  // `owner` may list `|`-separated alternatives. The first one that actually
  // carries the property wins. Global functions such as matchMedia and setTimeout
  // are own properties of Window.prototype, not of the global object, and a
  // resolver that only tried one path reported them absent -- indistinguishable in
  // the output from a collector that never called them.
  function ownerFor(spec) {
    var paths = spec.owner.split('|');
    for (var i = 0; i < paths.length; i++) {
      var candidate;
      try { candidate = resolve(paths[i]); } catch (e) { continue; }
      if (!candidate) continue;
      var d;
      try { d = Object.getOwnPropertyDescriptor(candidate, spec.prop); } catch (e) { continue; }
      if (d) return { owner: candidate, desc: d, path: paths[i] };
    }
    return null;
  }

  function install(spec) {
    var found = ownerFor(spec);
    if (!found) return 'prop-absent';
    var owner = found.owner, desc = found.desc;
    if (desc.configurable === false) return 'not-configurable';

    if (spec.kind === 'getter') {
      var get = desc.get;
      if (typeof get !== 'function') return 'not-a-getter';
      var wg = function () {
        try { record(spec.name, []); } catch (e) { failures += 1; }
        return get.apply(this, arguments);
      };
      markNative(wg, get);
      try {
        Object.defineProperty(owner, spec.prop, {
          get: wg, set: desc.set, configurable: true, enumerable: desc.enumerable });
      } catch (e) { return 'define-threw'; }
      return 'ok';
    }

    var fn = desc.value;
    if (typeof fn !== 'function') return 'not-a-function';
    var wf = function () {
      try { record(spec.name, summarise(spec, arguments, this)); }
      catch (e) { failures += 1; }
      return fn.apply(this, arguments);
    };
    markNative(wf, fn);
    try {
      Object.defineProperty(owner, spec.prop, {
        value: wf, configurable: true, writable: desc.writable !== false,
        enumerable: desc.enumerable });
    } catch (e) { return 'define-threw'; }
    return 'ok';
  }

  var installed = {};
  for (var i = 0; i < SPEC.length; i++) {
    var s = SPEC[i];
    if (s.prop === 'toString' && s.owner === 'Function.prototype') continue;
    try { installed[s.name] = install(s); } catch (e) { installed[s.name] = 'threw'; }
  }

  // Function.prototype.toString is installed last and by hand: it must both record
  // its receiver and serve the native-source answer for everything installed above,
  // and it must not recurse through its own recording path.
  var tsSpec = null;
  for (var j = 0; j < SPEC.length; j++) {
    if (SPEC[j].owner === 'Function.prototype' && SPEC[j].prop === 'toString') tsSpec = SPEC[j];
  }
  if (tsSpec) {
    var wts = function () {
      var original = null;
      try { original = wrapped.get(this) || null; } catch (e) { original = null; }
      if (!inToString) {
        inToString = true;
        try { record(tsSpec.name, summarise(tsSpec, arguments, this)); }
        catch (e) { failures += 1; }
        inToString = false;
      }
      return nativeToString.apply(original || this, arguments);
    };
    markNative(wts, nativeToString);
    try {
      Object.defineProperty(Function.prototype, 'toString', {
        value: wts, configurable: true, writable: true, enumerable: false });
      installed[tsSpec.name] = 'ok';
    } catch (e) { installed[tsSpec.name] = 'define-threw'; }
  }

  Object.defineProperty(globalThis, '__bcArgs', {
    value: {
      dump: function () {
        var names = Object.keys(store).sort();
        var out = [];
        for (var i = 0; i < names.length; i++) {
          var s = store[names[i]];
          var samples = s.samples.slice().sort(function (a, b) { return b.n - a.n; });
          var rendered = [];
          for (var k = 0; k < samples.length; k++) {
            rendered.push({ args: samples[k].v, count: samples[k].n });
          }
          out.push({ name: names[i], calls: s.calls, distinct: s.distinct,
                     dropped: s.dropped, samples: rendered });
        }
        return JSON.stringify({
          records: out, total_samples: total, dropped: dropped,
          record_failures: failures, installed: installed,
          self_suppressed: suppressed });
      }
    },
    configurable: true, enumerable: false, writable: false
  });

  // Installation is over; from here every recorded call is the page's.
  installing = false;
})();
"""


def build_hook_script(targets: tuple[HookTarget, ...] = HOOK_TARGETS) -> str:
    """Render the page-side instrument for a target set."""
    if (
        type(targets) is not tuple
        or len(targets) > len(HOOK_TARGETS)
        or any(type(target) is not HookTarget or target not in HOOK_TARGETS for target in targets)
    ):
        raise ContractError("hook targets must be a bounded subset of curated targets")
    if len({target.name for target in targets}) != len(targets):
        raise ContractError("hook targets must be unique")
    for target in targets:
        _check_policy(target)
    spec = [
        {
            "owner": t.owner,
            "prop": t.prop,
            "kind": t.kind,
            "name": t.name,
            "record_args": list(t.record_args),
            "arg_projections": [list(projection) for projection in t.arg_projections],
            "record_this_name": t.record_this_name,
        }
        for t in targets
    ]
    return (
        _HOOK_JS_TEMPLATE.replace("__SPEC__", json.dumps(spec, separators=(",", ":")))
        .replace("__CAP_N__", str(CAP_SAMPLES_PER_NAME))
        .replace("__CAP_TOTAL__", str(CAP_TOTAL_SAMPLES))
        .replace("__CAP_STR__", str(CAP_STRING_CHARS))
    )


HARVEST_JS = (
    "(() => { try { return globalThis.__bcArgs "
    "? globalThis.__bcArgs.dump() : JSON.stringify({absent: true}); } "
    "catch (e) { return JSON.stringify({error: String(e)}); } })()"
)


# ----------------------------------------------------------------- harvest side


def _exact_fields(value: object, expected: frozenset[str], *, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ContractError(f"{label} must be a JSON object")
    actual = set(value)
    if actual != expected:
        raise ContractError(f"{label} fields are invalid")
    return value


def _counter(value: object, *, label: str, maximum: int = MAX_SAFE_INTEGER) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= maximum:
        raise ContractError(f"{label} must be an integer from 0 through {maximum}")
    return value


def _argument_value(value: object, *, label: str) -> object:
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, str):
        if len(value) > CAP_STRING_CHARS + 1 or any(
            ord(character) < 0x20 or ord(character) == 0x7F for character in value
        ):
            raise ContractError(f"{label} exceeds the page-side string cap")
        return value
    if isinstance(value, int):
        if not -MAX_SAFE_INTEGER <= value <= MAX_SAFE_INTEGER:
            raise ContractError(f"{label} is outside JavaScript's safe integer range")
        return value
    if isinstance(value, float) and math.isfinite(value):
        return value
    raise ContractError(f"{label} must be a bounded JSON scalar")


def _validate_success_harvest(
    payload: object, *, page_loads: int = 1
) -> dict[str, Any]:
    _counter(page_loads, label="argument harvest page loads", maximum=MAX_HARVESTS_TO_MERGE)
    if page_loads < 1:
        raise ContractError("argument harvest page loads must be positive")
    document = _exact_fields(payload, _HARVEST_FIELDS, label="argument harvest")
    records = document["records"]
    installed = document["installed"]
    if not isinstance(records, list) or len(records) > len(HOOK_TARGETS):
        raise ContractError("argument harvest records must be a bounded list")
    if not isinstance(installed, dict):
        raise ContractError("argument harvest installed statuses must be an object")

    target_names = {target.name for target in HOOK_TARGETS}
    if set(installed) != target_names:
        raise ContractError("argument harvest installed statuses do not name every hook target")
    for name, status in installed.items():
        if not isinstance(name, str) or not isinstance(status, str) or status not in _INSTALL_STATUSES:
            raise ContractError("argument harvest contains an invalid hook install status")

    validated_records: list[dict[str, Any]] = []
    prior_name: str | None = None
    distinct_total = 0
    dropped_total = 0
    for index, raw_record in enumerate(records):
        record = _exact_fields(
            raw_record, _RECORD_FIELDS, label=f"argument harvest record {index}"
        )
        name = record["name"]
        if not isinstance(name, str) or name not in target_names:
            raise ContractError(f"argument harvest record {index} names an unknown target")
        if prior_name is not None and name <= prior_name:
            raise ContractError("argument harvest records must have unique sorted names")
        prior_name = name
        calls = _counter(record["calls"], label=f"argument harvest record {name} calls")
        if calls < 1:
            raise ContractError(f"argument harvest record {name} calls must be positive")
        distinct = _counter(
            record["distinct"],
            label=f"argument harvest record {name} distinct",
            maximum=CAP_SAMPLES_PER_NAME * page_loads,
        )
        dropped = _counter(
            record["dropped"], label=f"argument harvest record {name} dropped"
        )
        samples = record["samples"]
        if not isinstance(samples, list) or len(samples) != distinct:
            raise ContractError(f"argument harvest record {name} sample count is inconsistent")
        validated_samples: list[dict[str, Any]] = []
        occurrences = 0
        previous_count: int | None = None
        encoded_args: set[str] = set()
        for sample_index, raw_sample in enumerate(samples):
            sample = _exact_fields(
                raw_sample,
                _SAMPLE_FIELDS,
                label=f"argument harvest record {name} sample {sample_index}",
            )
            args = sample["args"]
            if not isinstance(args, list) or len(args) > 9:
                raise ContractError(f"argument harvest record {name} args must be a bounded list")
            safe_args = [
                _argument_value(value, label=f"argument harvest record {name} argument")
                for value in args
            ]
            count = _counter(
                sample["count"], label=f"argument harvest record {name} sample count"
            )
            if count < 1:
                raise ContractError(f"argument harvest record {name} sample count must be positive")
            if previous_count is not None and count > previous_count:
                raise ContractError(f"argument harvest record {name} samples are not count-sorted")
            previous_count = count
            args_key = json.dumps(safe_args, separators=(",", ":"), ensure_ascii=True)
            if args_key in encoded_args:
                raise ContractError(f"argument harvest record {name} repeats an argument sample")
            encoded_args.add(args_key)
            occurrences += count
            validated_samples.append({"args": safe_args, "count": count})
        if occurrences + dropped != calls:
            raise ContractError(f"argument harvest record {name} call counts are inconsistent")
        distinct_total += distinct
        dropped_total += dropped
        validated_records.append(
            {
                "name": name,
                "calls": calls,
                "distinct": distinct,
                "dropped": dropped,
                "samples": validated_samples,
            }
        )

    total_samples = _counter(
        document["total_samples"],
        label="argument harvest total_samples",
        maximum=CAP_TOTAL_SAMPLES * page_loads,
    )
    dropped_samples = _counter(document["dropped"], label="argument harvest dropped")
    if total_samples != distinct_total or dropped_samples != dropped_total:
        raise ContractError("argument harvest aggregate sample counts are inconsistent")
    return {
        **document,
        "records": validated_records,
        "total_samples": total_samples,
        "dropped": dropped_samples,
        "record_failures": _counter(
            document["record_failures"], label="argument harvest record_failures"
        ),
        "self_suppressed": _counter(
            document["self_suppressed"], label="argument harvest self_suppressed"
        ),
    }


def parse_harvest(raw: str) -> dict[str, Any]:
    """Turn a page-side dump into a capture document.

    A harvest that did not happen must not read as a harvest that found nothing.
    ``absent`` and ``error`` states are preserved rather than normalised into an
    empty record list.
    """
    if not isinstance(raw, str):
        raise ContractError("argument harvest must be a JSON string")
    try:
        body = raw.encode("utf-8", errors="strict")
    except UnicodeEncodeError:
        raise ContractError("argument harvest must be valid UTF-8 text") from None
    if len(body) > CAP_HARVEST_BYTES:
        raise ContractError(
            f"argument harvest exceeded {CAP_HARVEST_BYTES} bytes ({len(body)}); "
            "the page-side caps did not hold"
        )
    payload = decode_strict_json_bytes(body, label="argument harvest")
    if not isinstance(payload, dict):
        raise ContractError("argument harvest must be a JSON object")

    if set(payload) == {"absent"} and payload["absent"] is True:
        return {
            "schema": CAPTURE_SCHEMA,
            "status": "absent",
            "note": "the hook was not installed on the page that was harvested",
            "records": [],
        }
    if set(payload) == {"error"} and isinstance(payload["error"], str):
        diagnostic = hashlib.sha256(payload["error"].encode("utf-8")).hexdigest()
        return {
            "schema": CAPTURE_SCHEMA,
            "status": "error",
            "note": "the page-side harvest raised an error; details were redacted",
            "error_digest": f"sha256:{diagnostic}",
            "records": [],
        }
    if "absent" in payload or "error" in payload:
        raise ContractError("argument harvest state envelope is invalid")

    payload = _validate_success_harvest(payload)
    records = payload["records"]
    installed = payload["installed"]
    absent = sorted(k for k, v in installed.items() if v != "ok")
    return {
        "schema": CAPTURE_SCHEMA,
        "status": "ok",
        "records": records,
        "distinct_names": len(records),
        "total_calls": sum(int(r.get("calls") or 0) for r in records),
        "total_samples": payload.get("total_samples"),
        "dropped_samples": payload.get("dropped"),
        "record_failures": payload.get("record_failures"),
        # Calls the instrument made while installing itself. Recording these would
        # attribute the instrument's own introspection to the sample.
        "self_calls_suppressed": payload.get("self_suppressed"),
        "targets_installed": sum(1 for v in installed.values() if v == "ok"),
        "targets_not_installed": {k: installed[k] for k in absent},
        "caps": {
            "samples_per_name": CAP_SAMPLES_PER_NAME,
            "total_samples": CAP_TOTAL_SAMPLES,
            "string_chars": CAP_STRING_CHARS,
        },
        "non_claims": list(_CAPTURE_NON_CLAIMS),
    }


_MERGE_OK_FIELDS = {
    "schema",
    "status",
    "records",
    "distinct_names",
    "total_calls",
    "total_samples",
    "dropped_samples",
    "record_failures",
    "self_calls_suppressed",
    "targets_installed",
    "targets_not_installed",
    "caps",
    "non_claims",
}
_ATTRIBUTION_FIELDS = {
    "attributed",
    "control_dropped_samples",
    "control_dropped_calls",
    "control_dropped_names",
    "control_record_count",
    "control_record_failures",
    "arm_capped_calls",
    "control_capped_calls",
    "unattributed_arm_calls",
    "attribution_complete",
}


def _validated_merge_harvest(harvest: Any) -> dict[str, Any]:
    if type(harvest) is not dict or harvest.get("schema") != CAPTURE_SCHEMA:
        raise ContractError("argument merge input schema is invalid")
    status = harvest.get("status")
    if status == "absent":
        if set(harvest) != {"schema", "status", "note", "records"} or (
            not isinstance(harvest.get("note"), str)
            or harvest.get("note") not in {
                "the hook was not installed on the page that was harvested",
                "no harvest was taken",
            }
            or harvest.get("records") != []
        ):
            raise ContractError("argument merge absent input is invalid")
        return harvest
    if status == "error":
        digest = harvest.get("error_digest")
        if (
            set(harvest) != {"schema", "status", "note", "error_digest", "records"}
            or harvest.get("note")
            != "the page-side harvest raised an error; details were redacted"
            or harvest.get("records") != []
            or not isinstance(digest, str)
            or re.fullmatch(r"sha256:[0-9a-f]{64}", digest) is None
        ):
            raise ContractError("argument merge error input is invalid")
        return harvest
    if status != "ok" or set(harvest) != _MERGE_OK_FIELDS:
        raise ContractError("argument merge success input is invalid")

    not_installed = harvest.get("targets_not_installed")
    target_names = {target.name for target in HOOK_TARGETS}
    if (
        type(not_installed) is not dict
        or not set(not_installed) <= target_names
        or any(
            not isinstance(status, str)
            or status not in _INSTALL_STATUSES - {"ok"}
            for status in not_installed.values()
        )
    ):
        raise ContractError("argument merge target-install receipt is invalid")
    installed = {
        target: not_installed.get(target, "ok") for target in sorted(target_names)
    }
    validated = _validate_success_harvest(
        {
            "records": harvest.get("records"),
            "total_samples": harvest.get("total_samples"),
            "dropped": harvest.get("dropped_samples"),
            "record_failures": harvest.get("record_failures"),
            "installed": installed,
            "self_suppressed": harvest.get("self_calls_suppressed"),
        }
    )
    records = validated["records"]
    if (
        harvest.get("distinct_names") != len(records)
        or isinstance(harvest.get("distinct_names"), bool)
        or harvest.get("total_calls") != sum(record["calls"] for record in records)
        or isinstance(harvest.get("total_calls"), bool)
        or harvest.get("targets_installed") != len(target_names) - len(not_installed)
        or isinstance(harvest.get("targets_installed"), bool)
        or harvest.get("caps")
        != {
            "samples_per_name": CAP_SAMPLES_PER_NAME,
            "total_samples": CAP_TOTAL_SAMPLES,
            "string_chars": CAP_STRING_CHARS,
        }
        or harvest.get("non_claims") != _CAPTURE_NON_CLAIMS
    ):
        raise ContractError("argument merge aggregate receipt is invalid")
    return harvest


def _validated_unattributed_capture(capture: Any, *, role: str) -> dict[str, Any]:
    expected_fields = _MERGE_OK_FIELDS
    if type(capture) is not dict or capture.get("schema") != CAPTURE_SCHEMA:
        raise ContractError(f"argument subtraction {role} schema is invalid")
    actual_fields = set(capture)
    if capture.get("status") != "ok" or actual_fields not in (
        expected_fields,
        expected_fields | {"page_loads_harvested"},
    ):
        raise ContractError(f"argument subtraction {role} structure is invalid")
    page_loads = capture.get("page_loads_harvested")
    if page_loads is not None and (
        isinstance(page_loads, bool)
        or not isinstance(page_loads, int)
        or not 1 <= page_loads <= MAX_HARVESTS_TO_MERGE
    ):
        raise ContractError(f"argument subtraction {role} structure is invalid")

    not_installed = capture.get("targets_not_installed")
    target_names = {target.name for target in HOOK_TARGETS}
    if type(not_installed) is not dict or not set(not_installed) <= target_names:
        raise ContractError(f"argument subtraction {role} target receipt is invalid")
    non_ok_statuses = _INSTALL_STATUSES - {"ok"}
    for status in not_installed.values():
        if isinstance(status, str) and status in non_ok_statuses:
            continue
        if not isinstance(status, str) or re.fullmatch(
            r"mixed\((?:define-threw|not-a-function|not-a-getter|not-configurable|prop-absent|threw)(?:\|(?:define-threw|not-a-function|not-a-getter|not-configurable|prop-absent|threw))+\)",
            status,
        ) is None:
            raise ContractError(f"argument subtraction {role} target receipt is invalid")

    validated = _validate_success_harvest(
        {
            "records": capture.get("records"),
            "total_samples": capture.get("total_samples"),
            "dropped": capture.get("dropped_samples"),
            "record_failures": capture.get("record_failures"),
            "installed": {target: "ok" for target in sorted(target_names)},
            "self_suppressed": capture.get("self_calls_suppressed"),
        },
        page_loads=page_loads or 1,
    )
    records = validated["records"]
    if (
        capture.get("distinct_names") != len(records)
        or isinstance(capture.get("distinct_names"), bool)
        or capture.get("total_calls") != sum(record["calls"] for record in records)
        or isinstance(capture.get("total_calls"), bool)
        or capture.get("targets_installed") != len(target_names) - len(not_installed)
        or isinstance(capture.get("targets_installed"), bool)
        or capture.get("caps")
        != {
            "samples_per_name": CAP_SAMPLES_PER_NAME,
            "total_samples": CAP_TOTAL_SAMPLES,
            "string_chars": CAP_STRING_CHARS,
        }
        or capture.get("non_claims") != _CAPTURE_NON_CLAIMS
    ):
        raise ContractError(f"argument subtraction {role} aggregate receipt is invalid")
    return capture


def _validated_attributed_capture(capture: Any) -> dict[str, Any]:
    if type(capture) is not dict:
        raise ContractError("attributed argument capture structure is invalid")
    base_fields = set(capture) - _ATTRIBUTION_FIELDS
    if base_fields not in (
        _MERGE_OK_FIELDS,
        _MERGE_OK_FIELDS | {"page_loads_harvested"},
    ) or set(capture) != base_fields | _ATTRIBUTION_FIELDS:
        raise ContractError("attributed argument capture structure is invalid")
    base = {field: capture[field] for field in base_fields}
    _validated_unattributed_capture(base, role="attributed base")
    if capture.get("attributed") is not True:
        raise ContractError("attributed argument capture structure is invalid")
    counters: dict[str, int] = {}
    for field in (
        "control_dropped_samples",
        "control_dropped_calls",
        "control_record_count",
        "control_record_failures",
        "arm_capped_calls",
        "control_capped_calls",
        "unattributed_arm_calls",
    ):
        value = capture.get(field)
        if (
            isinstance(value, bool)
            or not isinstance(value, int)
            or not 0 <= value <= MAX_SAFE_INTEGER
        ):
            raise ContractError("attributed argument capture structure is invalid")
        counters[field] = value
    names = capture.get("control_dropped_names")
    target_names = {target.name for target in HOOK_TARGETS}
    if (
        type(names) is not list
        or any(not isinstance(name, str) or name not in target_names for name in names)
        or names != sorted(names)
        or len(names) != len(set(names))
        or len(names) > counters["control_dropped_samples"]
        or counters["control_dropped_samples"] > counters["control_dropped_calls"]
        or counters["control_record_count"] > len(HOOK_TARGETS)
        or counters["unattributed_arm_calls"]
        != counters["control_dropped_calls"] + counters["arm_capped_calls"]
    ):
        raise ContractError("attributed argument capture structure is invalid")
    expected_complete = (
        counters["arm_capped_calls"] == 0
        and counters["control_capped_calls"] == 0
        and capture["record_failures"] == 0
        and counters["control_record_failures"] == 0
    )
    if type(capture.get("attribution_complete")) is not bool or capture[
        "attribution_complete"
    ] is not expected_complete:
        raise ContractError("attributed argument capture structure is invalid")
    return capture


def validate_capture(capture: Any) -> dict[str, Any]:
    """Validate any public argument-capture representation without rewriting it."""

    if isinstance(capture, dict) and capture.get("status") == "ok":
        if capture.get("attributed") is True:
            return _validated_attributed_capture(capture)
        return _validated_unattributed_capture(capture, role="validation input")
    return _validated_merge_harvest(capture)


def merge_harvests(harvests: list[dict[str, Any]]) -> dict[str, Any]:
    """Combine per-page-load harvests into one capture.

    A page reload resets the JS heap, so a multi-load arm produces one harvest per
    load. Merging keeps the whole arm's evidence instead of only its last load.
    """
    if type(harvests) is not list or len(harvests) > MAX_HARVESTS_TO_MERGE:
        raise ContractError("argument merge input population is invalid")
    harvests = [_validated_merge_harvest(harvest) for harvest in harvests]
    usable = [h for h in harvests if h.get("status") == "ok"]
    if not usable:
        return harvests[-1] if harvests else {
            "schema": CAPTURE_SCHEMA, "status": "absent", "records": [],
            "note": "no harvest was taken",
        }
    if len(usable) == 1:
        merged = dict(usable[0])
        merged["page_loads_harvested"] = len(usable)
        return merged

    by_name: dict[str, dict[str, Any]] = {}
    target_failures: dict[str, set[str]] = {}
    for harvest in usable:
        for target, status in (harvest.get("targets_not_installed") or {}).items():
            target_failures.setdefault(str(target), set()).add(str(status))
        for record in harvest["records"]:
            name = record.get("name")
            if not isinstance(name, str):
                continue
            slot = by_name.setdefault(
                name, {"name": name, "calls": 0, "distinct": 0, "dropped": 0, "_s": {}}
            )
            slot["calls"] += int(record.get("calls") or 0)
            slot["dropped"] += int(record.get("dropped") or 0)
            for sample in record.get("samples") or []:
                key = json.dumps(sample.get("args"), separators=(",", ":"))
                entry = slot["_s"].setdefault(key, {"args": sample.get("args"), "count": 0})
                entry["count"] += int(sample.get("count") or 0)

    records = []
    for name in sorted(by_name):
        slot = by_name[name]
        samples = sorted(
            slot.pop("_s").values(),
            key=lambda sample: (
                -sample["count"],
                json.dumps(sample["args"], separators=(",", ":"), sort_keys=True),
            ),
        )
        slot["samples"] = samples
        slot["distinct"] = len(samples)
        records.append(slot)

    targets_not_installed = {
        target: next(iter(statuses))
        if len(statuses) == 1
        else "mixed(" + "|".join(sorted(statuses)) + ")"
        for target, statuses in sorted(target_failures.items())
    }

    base = dict(usable[0])
    base.update(
        {
            "records": records,
            "distinct_names": len(records),
            "total_calls": sum(r["calls"] for r in records),
            "total_samples": sum(r["distinct"] for r in records),
            "dropped_samples": sum(r["dropped"] for r in records),
            "record_failures": sum(int(h.get("record_failures") or 0) for h in usable),
            "self_calls_suppressed": sum(
                int(h.get("self_calls_suppressed") or 0) for h in usable
            ),
            "targets_installed": len(HOOK_TARGETS) - len(targets_not_installed),
            "targets_not_installed": targets_not_installed,
            "page_loads_harvested": len(usable),
        }
    )
    return base


# ---------------------------------------------------------------------- reporting


def _render_arg(name: str, args: Any) -> str:
    if not isinstance(args, list):
        return str(args)
    if name.endswith(".getParameter") and args:
        rest = [str(a) for a in args[1:]]
        return ", ".join([resolve_webgl_enum(args[0]), *rest])
    return ", ".join(str(a) for a in args)


def _validated_render_limit(value: object, *, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 100:
        raise ContractError(f"rendered {label} limit is invalid")
    return value


@normalize_renderer_failures("argument capture")
def render_capture(capture: dict[str, Any], *, limit: int = 12) -> str:
    """Bounded text report of an argument capture.

    Bounded by construction: a sample set of any size renders in the same envelope,
    because an agent reading this pays for every line of it.
    """
    limit = _validated_render_limit(limit, label="argument capture")
    if isinstance(capture, dict) and capture.get("status") == "ok":
        if capture.get("attributed") is True:
            capture = _validated_attributed_capture(capture)
        else:
            capture = _validated_unattributed_capture(capture, role="render input")
    else:
        capture = _validated_merge_harvest(capture)
    lines: list[str] = []
    status = capture.get("status")
    if status not in {"ok", "absent", "error"}:
        raise ContractError("rendered argument capture status is invalid")
    if status != "ok":
        if not isinstance(capture.get("note"), str):
            raise ContractError("rendered argument capture structure is invalid")
        return (
            f"argument capture: {status}\n"
            f"  {capture.get('note', '')}\n"
            "  !! NO ARGUMENT EVIDENCE -- this is not the same as 'the collector "
            "passed no arguments'\n"
        )

    if not {"distinct_names", "total_calls"} <= set(capture):
        raise ContractError("rendered argument capture structure is invalid")
    lines.append(
        f"argument capture: {capture.get('distinct_names')} instrumented names reached, "
        f"{capture.get('total_calls')} calls"
        + ("  [control-subtracted]" if capture.get("attributed") else "")
    )
    if capture.get("attributed"):
        lines.append(
            f"  control accounted for {capture.get('control_dropped_samples')} distinct "
            f"sample(s), {capture.get('control_dropped_calls')} call(s)"
            + (
                f", removing {len(capture['control_dropped_names'])} name(s) entirely: "
                + ", ".join(capture["control_dropped_names"][:5])
                if capture.get("control_dropped_names")
                else ""
            )
        )
        if not capture.get("attribution_complete"):
            lines.append(
                "  !! attribution is incomplete: capped calls or record failures "
                "exist in the arm/control population"
            )
        if capture.get("unattributed_arm_calls"):
            lines.append(
                f"  {capture['unattributed_arm_calls']} arm call(s) are excluded from "
                "the attributed total"
            )
    if capture.get("self_calls_suppressed"):
        lines.append(
            f"  {capture['self_calls_suppressed']} call(s) the instrument made while "
            "installing itself were suppressed, not recorded as the sample's"
        )
    not_installed = capture.get("targets_not_installed") or {}
    if not_installed:
        lines.append(
            f"  !! {len(not_installed)} target(s) not installed: "
            + ", ".join(f"{k}={v}" for k, v in sorted(not_installed.items())[:6])
        )
    if capture.get("dropped_samples"):
        lines.append(
            f"  !! {capture['dropped_samples']} sample(s) dropped at the cap; "
            "distinct-value lists below are incomplete"
        )
    lines.append("")

    for record in sorted(
        capture.get("records") or [], key=lambda r: -int(r.get("calls") or 0)
    ):
        name = str(record.get("name"))
        lines.append(f"  {name}  ({record.get('calls')} calls, {record.get('distinct')} distinct)")
        samples = record.get("samples") or []
        for sample in samples[:limit]:
            lines.append(f"      {sample.get('count'):>5}x  {_render_arg(name, sample.get('args'))}")
        if len(samples) > limit:
            lines.append(f"      ... {len(samples) - limit} more distinct")
    lines.append("")
    lines.append(
        "  values shown are what the collector asked for; what this host answered "
        "is not recorded"
    )
    return "\n".join(lines) + "\n"


# ------------------------------------------------------------ control subtraction


def subtract_capture(
    arm: dict[str, Any], control: dict[str, Any]
) -> dict[str, Any]:
    """Attribute argument samples by subtracting an empty-script control's.

    The same reasoning that makes ``subtract_control`` necessary for API names
    applies one level down. The instrument records every call the *page* makes, and
    the page is not only the sample: the rehost document, and the instrument's own
    residue, can reach an instrumented name too.

    In practice the contamination here is small -- measured 2026-08-06, an
    empty-script control produced exactly **one** post-install record against the
    arm's 200+ -- but "small" is a measurement, not a guarantee, and the one record
    it did produce (``Object.keys``) also appears in the arm. Publishing it as a
    collector behaviour would be wrong for the same reason publishing an
    unsubtracted API surface is wrong.

    Samples are matched on their exact argument list. A sample present in both is
    dropped; a sample present only in the arm is kept with its arm count.
    """
    arm = _validated_unattributed_capture(arm, role="arm")
    control = _validated_unattributed_capture(control, role="control")

    control_index: dict[str, set[str]] = {}
    for record in control.get("records") or []:
        control_index[str(record.get("name"))] = {
            json.dumps(sample.get("args"), separators=(",", ":"))
            for sample in record.get("samples") or []
        }

    records: list[dict[str, Any]] = []
    dropped_samples = 0
    dropped_calls = 0
    dropped_names: list[str] = []
    for record in arm.get("records") or []:
        name = str(record.get("name"))
        seen = control_index.get(name, set())
        kept = [
            sample
            for sample in record.get("samples") or []
            if json.dumps(sample.get("args"), separators=(",", ":")) not in seen
        ]
        removed = [sample for sample in record["samples"] if sample not in kept]
        dropped_samples += len(removed)
        dropped_calls += sum(sample["count"] for sample in removed)
        if not kept and (record.get("samples") or []):
            dropped_names.append(name)
            continue
        kept_calls = sum(sample["count"] for sample in kept)
        if kept:
            records.append(
                {
                    **record,
                    "calls": kept_calls,
                    "samples": kept,
                    "distinct": len(kept),
                    "dropped": 0,
                }
            )

    attributed_calls = sum(record["calls"] for record in records)
    arm_capped_calls = arm["dropped_samples"]
    unattributed_calls = arm["total_calls"] - attributed_calls

    return {
        **arm,
        "records": records,
        "distinct_names": len(records),
        "total_calls": attributed_calls,
        "total_samples": sum(record["distinct"] for record in records),
        "dropped_samples": 0,
        "attributed": True,
        "control_dropped_samples": dropped_samples,
        "control_dropped_calls": dropped_calls,
        "control_dropped_names": sorted(dropped_names),
        "control_record_count": len(control.get("records") or []),
        "control_record_failures": control["record_failures"],
        "arm_capped_calls": arm_capped_calls,
        "control_capped_calls": control["dropped_samples"],
        "unattributed_arm_calls": unattributed_calls,
        "attribution_complete": (
            arm_capped_calls == 0
            and control["dropped_samples"] == 0
            and arm["record_failures"] == 0
            and control["record_failures"] == 0
        ),
    }


# --------------------------------------------------------------- corpus


ARG_CORPUS_SCHEMA = "browser-core.argument-corpus/1"


def _valid_corpus_label(value: object) -> bool:
    if not isinstance(value, str) or not value:
        return False
    try:
        encoded = value.encode("utf-8", errors="strict")
    except UnicodeEncodeError:
        return False
    return len(encoded) <= 1_024 and not any(
        ord(character) < 0x20 or ord(character) == 0x7F for character in value
    )


def argument_corpus(
    captures: dict[str, dict[str, Any]],
    *,
    name: str | None = None,
    observations: dict[str, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Compare argument evidence across arms, the way `corpus` compares surfaces.

    Written because the alternative was measured: comparing argument captures across
    four pins meant hand-authoring the same ad-hoc JSON walk **four times in one
    session**, which is the identical friction that produced the technique digest.
    An analyst asking "do these collectors bind the same events?" should not have to
    write a script to find out.

    Reports, per instrumented name, the argument values shared by **every** arm and
    the values carried by only some -- which is the distinction that matters, since a
    value common to all pins is a builder constant while a value on one is roll churn.
    """
    if type(captures) is not dict or not captures or len(captures) > MAX_ARGUMENT_CORPUS_ARMS:
        raise ContractError("argument corpus needs at least one capture")
    target_names = {target.name for target in HOOK_TARGETS}
    if name is not None and (not isinstance(name, str) or name not in target_names):
        raise ContractError("argument corpus focus is invalid")
    validated_captures: dict[str, dict[str, Any]] = {}
    for label, capture in captures.items():
        if not _valid_corpus_label(label):
            raise ContractError("argument corpus arm label is invalid")
        if type(capture) is not dict:
            raise ContractError("argument corpus capture is invalid")
        if capture.get("status") == "ok":
            validated_captures[label] = _validated_unattributed_capture(
                capture, role="corpus arm"
            )
        else:
            validated_captures[label] = _validated_merge_harvest(capture)
    captures = validated_captures
    usable = {k: v for k, v in captures.items() if v["status"] == "ok"}
    if not usable:
        raise ContractError(
            "no capture in this corpus has status 'ok'; an absent capture is not an "
            "empty one"
        )

    method_population = None
    if observations is not None:
        if type(observations) is not dict or len(observations) > MAX_ARGUMENT_CORPUS_ARMS:
            raise ContractError("argument corpus observation population is invalid")
        missing = sorted(set(usable) - set(observations))
        if missing:
            raise ContractError(
                "argument corpus method audit is missing observation document(s): "
                + ", ".join(missing[:5])
            )
        # Local import avoids coupling the capture primitive to digest startup.
        # Both consumers still use the one shared surface-method projection.
        from .observation_digest import _method_population

        method_population = _method_population(
            [(label, observations[label]) for label in sorted(usable)]
        )

    per_arm: dict[str, dict[str, set[str]]] = {}
    for label, capture in usable.items():
        by_name: dict[str, set[str]] = {}
        for record in capture.get("records") or []:
            key = str(record.get("name"))
            if name is not None and key != name:
                continue
            by_name[key] = {
                json.dumps(sample.get("args"), separators=(",", ":"))
                for sample in record.get("samples") or []
            }
        per_arm[label] = by_name

    all_names = sorted({n for arm in per_arm.values() for n in arm})
    rows = []
    for key in all_names:
        present = [label for label, arm in per_arm.items() if key in arm]
        value_sets = [per_arm[label][key] for label in present]
        shared = set.intersection(*value_sets) if value_sets else set()
        union = set.union(*value_sets) if value_sets else set()
        rows.append(
            {
                "name": key,
                "arms_present": len(present),
                "arms_total": len(per_arm),
                "universal": len(present) == len(per_arm),
                "shared_values": sorted(shared),
                "shared_count": len(shared),
                "variable_values": sorted(union - shared),
                "variable_count": len(union - shared),
            }
        )
    return {
        "schema": ARG_CORPUS_SCHEMA,
        "arms": sorted(per_arm),
        "arm_count": len(per_arm),
        "excluded_unusable": sorted(set(captures) - set(usable)),
        "method_population": method_population,
        "focus": name,
        "rows": sorted(rows, key=lambda r: (-r["arms_present"], r["name"])),
    }


_ARG_CORPUS_FIELDS = {
    "schema", "arms", "arm_count", "excluded_unusable", "method_population",
    "focus", "rows",
}
_ARG_CORPUS_CLI_FIELDS = _ARG_CORPUS_FIELDS | {
    "failed_arms", "trustworthy_population",
}
_ARG_CORPUS_CLI_FIELDS_WITH_UNPARSEABLE = _ARG_CORPUS_CLI_FIELDS | {
    "unparseable_files",
}
_ARG_CORPUS_ROW_FIELDS = {
    "name", "arms_present", "arms_total", "universal", "shared_values",
    "shared_count", "variable_values", "variable_count",
}


def _validated_canonical_argument_list(value: object) -> str:
    if not isinstance(value, str):
        raise ContractError("rendered argument corpus structure is invalid")
    try:
        body = value.encode("utf-8", errors="strict")
    except UnicodeEncodeError:
        raise ContractError("rendered argument corpus structure is invalid") from None
    if len(body) > 16 * (CAP_STRING_CHARS + 32):
        raise ContractError("rendered argument corpus structure is invalid")
    decoded = decode_strict_json_bytes(body, label="argument corpus value")
    if not isinstance(decoded, list) or len(decoded) > 9:
        raise ContractError("rendered argument corpus structure is invalid")
    safe = [_argument_value(item, label="rendered argument corpus value") for item in decoded]
    if value != json.dumps(safe, separators=(",", ":"), ensure_ascii=True):
        raise ContractError("rendered argument corpus structure is invalid")
    return value


def _validated_corpus_method_population(
    value: object, *, arm_count: int
) -> dict[str, Any] | None:
    if value is None:
        return None
    if type(value) is not dict or set(value) != {"arms", "same_method", "mixed_axes", "axes"}:
        raise ContractError("rendered argument corpus structure is invalid")
    if value.get("arms") != arm_count or isinstance(value.get("arms"), bool):
        raise ContractError("rendered argument corpus structure is invalid")
    if type(value.get("same_method")) is not bool:
        raise ContractError("rendered argument corpus structure is invalid")
    axes = value.get("axes")
    if type(axes) is not dict or not axes:
        raise ContractError("rendered argument corpus structure is invalid")
    computed_mixed: list[str] = []
    for axis, counts in axes.items():
        if not _valid_corpus_label(axis) or type(counts) is not dict or not counts:
            raise ContractError("rendered argument corpus structure is invalid")
        total = 0
        for encoded_value, count in counts.items():
            if not _valid_corpus_label(encoded_value) or (
                isinstance(count, bool) or not isinstance(count, int) or not 1 <= count <= arm_count
            ):
                raise ContractError("rendered argument corpus structure is invalid")
            total += count
        if total != arm_count:
            raise ContractError("rendered argument corpus structure is invalid")
        if len(counts) > 1:
            computed_mixed.append(axis)
    computed_mixed.sort()
    if value.get("mixed_axes") != computed_mixed or value["same_method"] is not (
        not computed_mixed
    ):
        raise ContractError("rendered argument corpus structure is invalid")
    return value


def _validated_argument_corpus_report(report: Any) -> dict[str, Any]:
    if type(report) is not dict or set(report) not in (
        _ARG_CORPUS_FIELDS, _ARG_CORPUS_CLI_FIELDS,
        _ARG_CORPUS_CLI_FIELDS_WITH_UNPARSEABLE,
    ):
        raise ContractError("rendered argument corpus structure is invalid")
    if report.get("schema") != ARG_CORPUS_SCHEMA:
        raise ContractError("rendered argument corpus schema is invalid")
    arms = report.get("arms")
    if (
        type(arms) is not list or not 1 <= len(arms) <= MAX_ARGUMENT_CORPUS_ARMS
        or any(not _valid_corpus_label(label) for label in arms)
        or arms != sorted(arms) or len(arms) != len(set(arms))
    ):
        raise ContractError("rendered argument corpus structure is invalid")
    arm_count = report.get("arm_count")
    if isinstance(arm_count, bool) or arm_count != len(arms):
        raise ContractError("rendered argument corpus structure is invalid")
    excluded = report.get("excluded_unusable")
    if (
        type(excluded) is not list or len(excluded) > MAX_ARGUMENT_CORPUS_ARMS
        or any(not _valid_corpus_label(label) for label in excluded)
        or excluded != sorted(excluded) or len(excluded) != len(set(excluded))
        or set(excluded) & set(arms)
    ):
        raise ContractError("rendered argument corpus structure is invalid")
    focus = report.get("focus")
    target_names = {target.name for target in HOOK_TARGETS}
    if focus is not None and focus not in target_names:
        raise ContractError("rendered argument corpus structure is invalid")
    _validated_corpus_method_population(report.get("method_population"), arm_count=arm_count)

    rows = report.get("rows")
    if type(rows) is not list or len(rows) > len(HOOK_TARGETS):
        raise ContractError("rendered argument corpus structure is invalid")
    seen_names: set[str] = set()
    for row in rows:
        if type(row) is not dict or set(row) != _ARG_CORPUS_ROW_FIELDS:
            raise ContractError("rendered argument corpus structure is invalid")
        row_name = row.get("name")
        if row_name not in target_names or row_name in seen_names:
            raise ContractError("rendered argument corpus structure is invalid")
        seen_names.add(row_name)
        present = row.get("arms_present")
        total = row.get("arms_total")
        if (
            isinstance(present, bool) or not isinstance(present, int)
            or not 1 <= present <= arm_count or isinstance(total, bool)
            or total != arm_count or type(row.get("universal")) is not bool
            or row["universal"] is not (present == arm_count)
        ):
            raise ContractError("rendered argument corpus structure is invalid")
        for values_field, count_field in (
            ("shared_values", "shared_count"),
            ("variable_values", "variable_count"),
        ):
            values = row.get(values_field)
            if (
                type(values) is not list
                or len(values) > CAP_SAMPLES_PER_NAME * MAX_HARVESTS_TO_MERGE * arm_count
                or values != sorted(values) or len(values) != len(set(values))
            ):
                raise ContractError("rendered argument corpus structure is invalid")
            for encoded in values:
                _validated_canonical_argument_list(encoded)
            if row.get(count_field) != len(values) or isinstance(row.get(count_field), bool):
                raise ContractError("rendered argument corpus structure is invalid")
        if set(row["shared_values"]) & set(row["variable_values"]):
            raise ContractError("rendered argument corpus structure is invalid")
        if focus is not None and row_name != focus:
            raise ContractError("rendered argument corpus structure is invalid")
    if rows != sorted(rows, key=lambda row: (-row["arms_present"], row["name"])):
        raise ContractError("rendered argument corpus structure is invalid")

    if set(report) in (
        _ARG_CORPUS_CLI_FIELDS, _ARG_CORPUS_CLI_FIELDS_WITH_UNPARSEABLE,
    ):
        failed = report.get("failed_arms")
        if (
            type(failed) is not list or len(failed) > MAX_ARGUMENT_CORPUS_ARMS
            or any(not _valid_corpus_label(label) for label in failed)
            or failed != sorted(failed) or len(failed) != len(set(failed))
        ):
            raise ContractError("rendered argument corpus structure is invalid")
        unparseable: list[str] = []
        if set(report) == _ARG_CORPUS_CLI_FIELDS_WITH_UNPARSEABLE:
            unparseable = report.get("unparseable_files")
            if (
                type(unparseable) is not list
                or len(unparseable) > MAX_ARGUMENT_CORPUS_ARMS
                or any(not _valid_corpus_label(label) for label in unparseable)
                or unparseable != sorted(unparseable)
                or len(unparseable) != len(set(unparseable))
                or set(unparseable) & (set(arms) | set(excluded) | set(failed))
            ):
                raise ContractError("rendered argument corpus structure is invalid")
        expected_trust = bool(
            not failed and not unparseable and not excluded
            and (report.get("method_population") or {}).get("same_method") is True
        )
        if type(report.get("trustworthy_population")) is not bool or report[
            "trustworthy_population"
        ] is not expected_trust:
            raise ContractError("rendered argument corpus structure is invalid")
    return report


@normalize_renderer_failures("argument corpus")
def render_argument_corpus(report: dict[str, Any], *, limit: int = 8) -> str:
    limit = _validated_render_limit(limit, label="argument corpus")
    report = _validated_argument_corpus_report(report)
    lines = [
        f"argument corpus: {report['arm_count']} arm(s)"
        + (f", focused on {report['focus']}" if report.get("focus") else ""),
    ]
    if report.get("excluded_unusable"):
        lines.append(
            f"  !! excluded {len(report['excluded_unusable'])} arm(s) with no usable "
            "capture: " + ", ".join(report["excluded_unusable"][:5])
        )
    if report.get("failed_arms"):
        lines.append(
            f"  !! {len(report['failed_arms'])} arm(s) produced no data: "
            + ", ".join(report["failed_arms"][:5])
        )
    if report.get("unparseable_files"):
        lines.append(
            f"  !! {len(report['unparseable_files'])} unparseable JSON file(s) "
            "could not be classified: "
            + ", ".join(report["unparseable_files"][:5])
        )
    mixed_method_axes = (report.get("method_population") or {}).get("mixed_axes") or []
    if mixed_method_axes:
        lines.append(
            "  !! mixed execution method on "
            + ", ".join(mixed_method_axes)
            + "; shared/variable values are not attributable to scripts alone"
        )
    lines.append("")
    for row in report["rows"]:
        mark = "ALL" if row["universal"] else f"{row['arms_present']}/{row['arms_total']}"
        lines.append(
            f"  {row['name']:<40} arms={mark:<6} "
            f"shared={row['shared_count']:<4} varies={row['variable_count']}"
        )
        for value in row["shared_values"][:limit]:
            lines.append(f"      = {value}")
        if row["shared_count"] > limit:
            lines.append(f"      ... {row['shared_count'] - limit} more shared")
        for value in row["variable_values"][:limit]:
            lines.append(f"      ~ {value}   (not in every arm)")
        if row["variable_count"] > limit:
            lines.append(f"      ... {row['variable_count'] - limit} more variable")
    lines.append("")
    lines.append(
        "  '=' is carried by every arm (a builder constant); '~' by only some "
        "(roll churn, or a real per-deployment difference)"
    )
    return "\n".join(lines) + "\n"


# ------------------------------------------------------- cross-instrument check

REALM_SCHEMA = "browser-core.argument-realm-crosscheck/1"

# Instrumented names whose page-side count is expected to fall short of the trace
# for a structural reason, so the shortfall is not treated as a defect.
_MAIN_REALM_ONLY_NOTE = (
    "the instrument installs in the main frame realm only; a worker has its own "
    "global object and its own copy of every built-in"
)
_REALM_LIMITS = [
    _MAIN_REALM_ONLY_NOTE,
    "unaccounted calls are not proof of worker activity; a subclass "
    "override or a call path the wrapper does not sit on reads the same",
    "trace_delta subtracts the control, so it is the sample's calls rather "
    "than the raw count the browser also contributes to",
]


def cross_check_realms(
    capture: dict[str, Any],
    arm: dict[str, Any],
    control: dict[str, Any],
    *,
    trace_prefix: str = "api.",
) -> dict[str, Any]:
    """Reconcile page-side call counts against the passive trace, per name.

    The two instruments have complementary blind spots and that is useful rather
    than annoying:

    * The **hook** sees arguments, and sees ECMAScript builtins the trace cannot
      (``blink.bindings.generated`` covers Web IDL only). It is confined to the
      main frame realm.
    * The **trace** sees every realm, including workers, and carries a
      ``context_coverage`` label saying which. It never sees an argument.

    So for one name, ``trace_delta - hook_calls`` is activity the hook could not
    reach. Measured 2026-08-06 on pin ``1e88274539a68be0``: ``Performance.now``
    shows 127 trace events against 2 hook calls, and the trace also carries
    ``WorkerGlobalScope.performance.get`` at 124 -- so the collector's timing work
    happens almost entirely inside its SharedWorker. The same comparison localises
    62 ``WorkerGlobalScope.fetch`` events and the WebGL reads, which run on an
    ``OffscreenCanvas`` in that worker rather than in the frame.

    ``trace_delta`` is the arm's count minus the control's, not the arm's raw
    count. Without that subtraction the browser's own calls are attributed to the
    sample -- ``Element.getAttribute`` reads 133 raw against 10 from the hook, and
    most of the gap is the browser parsing its own document.

    The residual is reported as **unaccounted**, never as "worker". It can also be
    a call path the wrapper does not sit on, such as a subclass that overrides the
    method. ``worker_realm`` says only whether the trace saw that name in a worker
    at all, which is evidence for the reading, not proof of it.
    """
    if isinstance(capture, dict) and capture.get("attributed") is True:
        capture = _validated_attributed_capture(capture)
    else:
        capture = _validated_unattributed_capture(capture, role="realm capture")

    from .product_observation import _validated_analysis_surface

    arm_names, coverage, _arm_script_names, _arm_script_available = (
        _validated_analysis_surface(arm, "realm arm")
    )
    control_names, _control_coverage, _control_script_names, _control_script_available = (
        _validated_analysis_surface(control, "realm control")
    )

    rows = []
    for record in capture.get("records") or []:
        name = record.get("name")
        if not isinstance(name, str):
            continue
        key = f"{trace_prefix}{name}"
        traced = arm_names.get(key)
        contexts = coverage.get(key) or []
        hook_calls = int(record.get("calls") or 0)
        if traced is None:
            rows.append(
                {
                    "name": name,
                    "hook_calls": hook_calls,
                    "trace_delta": None,
                    "unaccounted": None,
                    "worker_realm": False,
                    # A name the hook saw and the trace did not is the interesting
                    # direction: it is an ECMAScript builtin, outside Web IDL and
                    # therefore outside the passive plane entirely.
                    "note": "not a Web IDL name; invisible to the passive trace",
                }
            )
            continue
        delta = traced - control_names.get(key, 0)
        rows.append(
            {
                "name": name,
                "hook_calls": hook_calls,
                "trace_delta": delta,
                "unaccounted": delta - hook_calls,
                "worker_realm": "worker" in contexts,
                "contexts": contexts,
            }
        )

    unreached = sorted(
        key
        for key, contexts in coverage.items()
        if "worker" in contexts and (arm_names.get(key, 0) - control_names.get(key, 0)) > 0
    )
    return {
        "schema": REALM_SCHEMA,
        "arm_label": arm.get("label"),
        "control_label": control.get("label"),
        "rows": sorted(rows, key=lambda r: -(r.get("trace_delta") or 0)),
        "worker_realm_names": unreached,
        "worker_realm_name_count": len(unreached),
        "limits": list(_REALM_LIMITS),
    }


_REALM_REPORT_FIELDS = {
    "schema",
    "arm_label",
    "control_label",
    "rows",
    "worker_realm_names",
    "worker_realm_name_count",
    "limits",
}


def _valid_realm_name(value: object) -> bool:
    return _valid_corpus_label(value) and len(value) <= 512


def _validated_realm_report(report: Any) -> dict[str, Any]:
    if type(report) is not dict or set(report) != _REALM_REPORT_FIELDS:
        raise ContractError("rendered realm cross-check structure is invalid")
    if report.get("schema") != REALM_SCHEMA:
        raise ContractError("rendered realm cross-check schema is invalid")
    for field in ("arm_label", "control_label"):
        if report.get(field) is not None and not _valid_corpus_label(report[field]):
            raise ContractError("rendered realm cross-check structure is invalid")
    worker_names = report.get("worker_realm_names")
    if (
        type(worker_names) is not list
        or len(worker_names) > 100_000
        or any(not _valid_realm_name(name) for name in worker_names)
        or worker_names != sorted(worker_names)
        or len(worker_names) != len(set(worker_names))
        or report.get("worker_realm_name_count") != len(worker_names)
        or isinstance(report.get("worker_realm_name_count"), bool)
        or report.get("limits") != _REALM_LIMITS
    ):
        raise ContractError("rendered realm cross-check structure is invalid")
    rows = report.get("rows")
    if type(rows) is not list or len(rows) > len(HOOK_TARGETS):
        raise ContractError("rendered realm cross-check structure is invalid")
    seen: set[str] = set()
    for row in rows:
        if type(row) is not dict:
            raise ContractError("rendered realm cross-check structure is invalid")
        name = row.get("name")
        if name not in {target.name for target in HOOK_TARGETS} or name in seen:
            raise ContractError("rendered realm cross-check structure is invalid")
        seen.add(name)
        hook_calls = row.get("hook_calls")
        if (
            isinstance(hook_calls, bool)
            or not isinstance(hook_calls, int)
            or not 0 <= hook_calls <= MAX_SAFE_INTEGER
        ):
            raise ContractError("rendered realm cross-check structure is invalid")
        delta = row.get("trace_delta")
        if delta is None:
            if row != {
                "name": name,
                "hook_calls": hook_calls,
                "trace_delta": None,
                "unaccounted": None,
                "worker_realm": False,
                "note": "not a Web IDL name; invisible to the passive trace",
            }:
                raise ContractError("rendered realm cross-check structure is invalid")
            continue
        if set(row) != {
            "name", "hook_calls", "trace_delta", "unaccounted", "worker_realm", "contexts"
        } or (
            isinstance(delta, bool)
            or not isinstance(delta, int)
            or not -1_000_000_000 <= delta <= 1_000_000_000
            or row.get("unaccounted") != delta - hook_calls
            or isinstance(row.get("unaccounted"), bool)
            or type(row.get("worker_realm")) is not bool
        ):
            raise ContractError("rendered realm cross-check structure is invalid")
        contexts = row.get("contexts")
        if (
            type(contexts) is not list
            or any(context not in {"frame", "worker"} for context in contexts)
            or contexts != sorted(contexts)
            or len(contexts) != len(set(contexts))
            or row["worker_realm"] is not ("worker" in contexts)
        ):
            raise ContractError("rendered realm cross-check structure is invalid")
    if rows != sorted(rows, key=lambda row: -(row.get("trace_delta") or 0)):
        raise ContractError("rendered realm cross-check structure is invalid")
    return report


@normalize_renderer_failures("realm cross-check")
def render_realms(report: dict[str, Any]) -> str:
    report = _validated_realm_report(report)
    lines = [
        "realm cross-check: page-side hook vs passive trace",
        f"  {'name':<40}{'hook':>6}{'trace':>7}{'unacct':>8}  realm",
        "  " + "-" * 70,
    ]
    for row in report.get("rows") or []:
        delta = row.get("trace_delta")
        if delta is None:
            lines.append(
                f"  {row['name']:<40}{row['hook_calls']:>6}{'--':>7}{'--':>8}  "
                "ECMAScript builtin, outside the trace"
            )
            continue
        realm = "frame+worker" if row.get("worker_realm") else "frame"
        lines.append(
            f"  {row['name']:<40}{row['hook_calls']:>6}{delta:>7}"
            f"{row['unaccounted']:>8}  {realm}"
        )
    count = report.get("worker_realm_name_count") or 0
    lines.append("")
    lines.append(
        f"  {count} attributed name(s) reach a worker realm, where the hook does "
        "not run:"
    )
    for name in (report.get("worker_realm_names") or [])[:20]:
        lines.append(f"      {name}")
    if count > 20:
        lines.append(f"      ... {count - 20} more")
    for limit in report.get("limits") or []:
        lines.append(f"  note: {limit}")
    return "\n".join(lines) + "\n"


# ------------------------------------------------------------------- fidelity


def _raw_names(observation: dict[str, Any] | None) -> set[str] | None:
    if not isinstance(observation, dict):
        return None
    analysis = observation.get("analysis")
    if not isinstance(analysis, dict):
        return None
    names = analysis.get("events_by_name")
    return set(names) if isinstance(names, dict) else None


def _validated_fidelity_subtraction(
    document: Any, *, role: str
) -> tuple[dict[str, Any], set[str]]:
    from .product_observation import SUBTRACTION_SCHEMA, _surface_name_set

    if type(document) is not dict or document.get("schema") != SUBTRACTION_SCHEMA:
        raise ContractError(f"fidelity {role} subtraction schema is invalid")
    digest = document.get("arm_script_sha256_16")
    if not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{16}", digest) is None:
        raise ContractError(f"fidelity {role} script identity is invalid")
    label = document.get("arm_label")
    if label is not None and not _valid_corpus_label(label):
        raise ContractError(f"fidelity {role} label is invalid")
    if type(document.get("clean_subtraction")) is not bool:
        raise ContractError(f"fidelity {role} clean receipt is invalid")
    names = _surface_name_set(document)
    raw = document["only_in_arm"]
    if isinstance(raw, dict) and any(
        isinstance(count, bool)
        or not isinstance(count, int)
        or not 1 <= count <= 1_000_000_000
        for count in raw.values()
    ):
        raise ContractError(f"fidelity {role} surface counts are invalid")
    return document, names


def _validated_fidelity_raw_arm(document: Any, *, role: str) -> set[str]:
    from .product_observation import _surface_name_set

    if type(document) is not dict or type(document.get("analysis")) is not dict:
        raise ContractError(f"fidelity {role} raw arm is invalid")
    events = document["analysis"].get("events_by_name")
    if type(events) is not dict or any(
        isinstance(count, bool)
        or not isinstance(count, int)
        or not 1 <= count <= 1_000_000_000
        for count in events.values()
    ):
        raise ContractError(f"fidelity {role} raw surface is invalid")
    return _surface_name_set({"only_in_arm": events})


def compare_hook_fidelity(
    with_hook: dict[str, Any],
    without_hook: dict[str, Any],
    *,
    hooked_arms: tuple[dict[str, Any], dict[str, Any]] | None = None,
    plain_arms: tuple[dict[str, Any], dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Did installing the instrument change the passively observed surface?

    ``hooked_arms`` and ``plain_arms`` are optional ``(arm, control)`` observation
    pairs. Supplying them upgrades the verdict from "the attributed surfaces
    differ" to a statement about *why*, and the difference between those two is
    large enough to be worth four extra arguments.

    Measured 2026-08-06 on pin ``1e88274539a68be0``, three replicates per mode with
    **zero** within-mode jitter: the hooked run attributed 116 names and the plain
    run 117, and the missing name was ``api.Window.Navigator``. The arm called it
    in all six runs. What changed was the **control** -- the instrument resolves
    ``Navigator.prototype`` through the global, so the empty-script control now
    reaches that name too, and control subtraction correctly cancels it.

    The sample did not behave differently. The *subtraction lost resolution* on a
    name the instrument happens to touch itself. Those are different failures with
    different consequences: the first invalidates the argument evidence, the second
    leaves it usable and puts a named blind spot in the surface. Reporting both as
    "PERTURBS" would retire a working instrument over a bookkeeping artifact.

    Both inputs are control subtractions of the *same* pin, one arm run with the
    hook installed and one without, each against its own control run the same way.
    Because the native trace observes at the binding layer, it sees the sample's
    calls whether or not JS wrappers sit in front of them -- so a difference here is
    a difference in what the sample *did*, which is the observer effect made
    measurable.

    A clean result is not proof of transparency: the surface is a set of API names,
    so a collector that took a different branch reaching the same names would not
    show up. It is the strongest available check, not a guarantee, and the returned
    document says so.
    """
    from .product_observation import (
        SURFACE_METHOD_FIELDS,
        _surface_method,
    )

    with_hook, hooked = _validated_fidelity_subtraction(with_hook, role="with-hook")
    without_hook, plain = _validated_fidelity_subtraction(
        without_hook, role="without-hook"
    )
    if with_hook.get("arm_script_sha256_16") != without_hook.get("arm_script_sha256_16"):
        raise ContractError(
            "fidelity comparison needs the same script in both arms; "
            f"{with_hook.get('arm_script_sha256_16')} != "
            f"{without_hook.get('arm_script_sha256_16')}"
        )

    added = sorted(hooked - plain)
    removed = sorted(plain - hooked)
    union = hooked | plain

    dirty = [
        role
        for role, document in (("with_hook", with_hook), ("without_hook", without_hook))
        if document["clean_subtraction"] is not True
    ]
    hooked_method = _surface_method(with_hook)
    plain_method = _surface_method(without_hook)
    method_mismatches = {
        field: {"with_hook": hooked_method[field], "without_hook": plain_method[field]}
        for field in SURFACE_METHOD_FIELDS
        if field != "arm_hook_mode" and hooked_method[field] != plain_method[field]
    }
    # Legacy subtractions predate method propagation and omit hook mode. Accept
    # absence for compatibility, but an explicit role reversal or off arm is not a
    # fidelity pair.
    hooked_mode = with_hook.get("arm_hook_mode")
    plain_mode = without_hook.get("arm_hook_mode")
    if hooked_mode not in (None, "on") or plain_mode not in (None, "inert"):
        method_mismatches["arm_hook_mode"] = {
            "with_hook": hooked_mode,
            "without_hook": plain_mode,
            "expected": {"with_hook": "on", "without_hook": "inert"},
        }

    # Optional deeper classification. Without the raw arms this stays None and the
    # verdict stays conservative -- an absent explanation must never read as an
    # innocent one.
    footprint: list[str] | None = None
    arm_surface_changed: bool | None = None
    sample_delta: list[str] | None = None
    inconsistent: list[str] = []
    explained: bool | None = None
    if (hooked_arms is None) != (plain_arms is None):
        raise ContractError("fidelity raw arm populations must be supplied together")
    if hooked_arms is not None and plain_arms is not None:
        if (
            type(hooked_arms) is not tuple
            or len(hooked_arms) != 2
            or type(plain_arms) is not tuple
            or len(plain_arms) != 2
        ):
            raise ContractError("fidelity raw arm populations are invalid")
        hooked_arm, hooked_control = hooked_arms
        plain_arm, plain_control = plain_arms
        h_arm = _validated_fidelity_raw_arm(hooked_arm, role="hooked arm")
        h_ctl = _validated_fidelity_raw_arm(hooked_control, role="hooked control")
        p_arm = _validated_fidelity_raw_arm(plain_arm, role="plain arm")
        p_ctl = _validated_fidelity_raw_arm(plain_control, role="plain control")
        # What the instrument itself reaches: names the empty-script control
        # gained purely by having the wrappers installed.
        footprint = sorted(h_ctl - p_ctl)
        # The arm page carries the instrument too, so its raw surface *must*
        # gain the footprint. Comparing the arms directly therefore always
        # reports a change and says nothing -- the question is whether the arm
        # moved by more than the instrument accounts for. Subtract the
        # footprint from both sides and ask again.
        fp = set(footprint)
        # Consistency check before interpretation. The instrument runs on the
        # arm page and the control page alike, so every footprint name must
        # appear in the hooked arm. One that does not means these four
        # observations did not come from the run they claim to -- mismatched
        # files, a partial export, an arm that died early. Masking that as a
        # blind spot would let a broken comparison return a clean verdict.
        inconsistent = sorted(fp - h_arm)
        sample_delta = sorted((h_arm - fp) ^ (p_arm - fp))
        arm_surface_changed = bool(sample_delta)
        explained = (
            not inconsistent
            and not arm_surface_changed
            and set(removed) <= fp
            and not added
        )

    if dirty or inconsistent or method_mismatches:
        verdict = "UNUSABLE"
    elif not added and not removed:
        verdict = "TRANSPARENT"
    elif explained:
        verdict = "ATTRIBUTION_LOSS"
    else:
        verdict = "PERTURBS"

    return {
        "schema": FIDELITY_SCHEMA,
        "script_sha256_16": with_hook.get("arm_script_sha256_16"),
        "with_hook_label": with_hook.get("arm_label"),
        "without_hook_label": without_hook.get("arm_label"),
        "with_hook_names": len(hooked),
        "without_hook_names": len(plain),
        "added_by_hook": added,
        "removed_by_hook": removed,
        "surface_delta": len(added) + len(removed),
        "jaccard": round(len(hooked & plain) / len(union), 6) if union else 1.0,
        "dirty_subtractions": dirty,
        "method_mismatches": method_mismatches,
        "verdict": verdict,
        # Deliberately phrased so that the falsy value is the safe one. An earlier
        # draft exposed `hook_perturbs_surface`, which reported False for an
        # UNUSABLE comparison -- i.e. it said "the hook is fine" in exactly the case
        # where nothing at all is known. A boolean gate on evidence quality has to
        # fail closed, so this one names usability rather than perturbation and is
        # False for every verdict that has not positively earned trust.
        "argument_evidence_usable": verdict in {"TRANSPARENT", "ATTRIBUTION_LOSS"},
        # The names the instrument reaches on its own, measured as what an
        # empty-script control gains from having the wrappers installed. These are
        # unattributable in any hooked run, because control subtraction cannot tell
        # the instrument's call from the sample's.
        "instrument_footprint": footprint,
        "footprint_size": None if footprint is None else len(footprint),
        "arm_surface_changed": arm_surface_changed,
        "sample_delta": sample_delta,
        # Footprint names missing from the hooked arm: impossible if these four
        # documents came from the run they claim to.
        "inconsistent_footprint": inconsistent,
        "classified": explained is not None,
        "blind_spots": sorted(removed) if verdict == "ATTRIBUTION_LOSS" else [],
        "limits": list(_FIDELITY_BASE_LIMITS)
        + (
            []
            if explained is not None
            else [_FIDELITY_UNCLASSIFIED_LIMIT]
        ),
    }


_FIDELITY_REPORT_FIELDS = {
    "schema", "script_sha256_16", "with_hook_label", "without_hook_label",
    "with_hook_names", "without_hook_names", "added_by_hook", "removed_by_hook",
    "surface_delta", "jaccard", "dirty_subtractions", "method_mismatches",
    "verdict", "argument_evidence_usable", "instrument_footprint", "footprint_size",
    "arm_surface_changed", "sample_delta", "inconsistent_footprint", "classified",
    "blind_spots", "limits",
}


def _validated_name_list(value: object, *, maximum: int = 1_000_000) -> list[str]:
    if (
        type(value) is not list or len(value) > maximum
        or any(not _valid_realm_name(name) for name in value)
        or value != sorted(value) or len(value) != len(set(value))
    ):
        raise ContractError("rendered hook fidelity structure is invalid")
    return value


def _validated_fidelity_report(report: Any) -> dict[str, Any]:
    if type(report) is not dict or set(report) != _FIDELITY_REPORT_FIELDS:
        raise ContractError("rendered hook fidelity structure is invalid")
    if report.get("schema") != FIDELITY_SCHEMA:
        raise ContractError("rendered hook fidelity schema is invalid")
    digest = report.get("script_sha256_16")
    if not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{16}", digest) is None:
        raise ContractError("rendered hook fidelity structure is invalid")
    for field in ("with_hook_label", "without_hook_label"):
        if report.get(field) is not None and not _valid_corpus_label(report[field]):
            raise ContractError("rendered hook fidelity structure is invalid")
    counts: dict[str, int] = {}
    for field in ("with_hook_names", "without_hook_names", "surface_delta"):
        value = report.get(field)
        if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 1_000_000:
            raise ContractError("rendered hook fidelity structure is invalid")
        counts[field] = value
    added = _validated_name_list(report.get("added_by_hook"))
    removed = _validated_name_list(report.get("removed_by_hook"))
    if set(added) & set(removed) or counts["surface_delta"] != len(added) + len(removed):
        raise ContractError("rendered hook fidelity structure is invalid")
    intersection = counts["with_hook_names"] - len(added)
    if intersection < 0 or intersection != counts["without_hook_names"] - len(removed):
        raise ContractError("rendered hook fidelity structure is invalid")
    union_size = intersection + len(added) + len(removed)
    expected_jaccard = round(intersection / union_size, 6) if union_size else 1.0
    jaccard = report.get("jaccard")
    if (
        not is_finite_number(jaccard) or jaccard != expected_jaccard
    ):
        raise ContractError("rendered hook fidelity structure is invalid")
    dirty = report.get("dirty_subtractions")
    if dirty not in (
        [], ["with_hook"], ["without_hook"], ["with_hook", "without_hook"]
    ):
        raise ContractError("rendered hook fidelity structure is invalid")
    mismatches = report.get("method_mismatches")
    if type(mismatches) is not dict or len(mismatches) > 100:
        raise ContractError("rendered hook fidelity structure is invalid")
    from .product_observation import SURFACE_METHOD_FIELDS

    if any(field not in SURFACE_METHOD_FIELDS for field in mismatches):
        raise ContractError("rendered hook fidelity structure is invalid")
    for field, values in mismatches.items():
        expected_keys = {"with_hook", "without_hook"}
        if field == "arm_hook_mode" and isinstance(values, dict) and "expected" in values:
            expected_keys.add("expected")
        if type(values) is not dict or set(values) != expected_keys:
            raise ContractError("rendered hook fidelity structure is invalid")

    inconsistent = _validated_name_list(report.get("inconsistent_footprint"))
    blind_spots = _validated_name_list(report.get("blind_spots"))
    footprint = report.get("instrument_footprint")
    classified = report.get("classified")
    if type(classified) is not bool:
        raise ContractError("rendered hook fidelity structure is invalid")
    if footprint is None:
        if (
            report.get("footprint_size") is not None
            or report.get("arm_surface_changed") is not None
            or report.get("sample_delta") is not None
            or classified is not False
            or inconsistent
            or report.get("limits")
            != _FIDELITY_BASE_LIMITS + [_FIDELITY_UNCLASSIFIED_LIMIT]
        ):
            raise ContractError("rendered hook fidelity structure is invalid")
    else:
        footprint = _validated_name_list(footprint)
        sample_delta = _validated_name_list(report.get("sample_delta"))
        if (
            report.get("footprint_size") != len(footprint)
            or isinstance(report.get("footprint_size"), bool)
            or type(report.get("arm_surface_changed")) is not bool
            or report["arm_surface_changed"] is not bool(sample_delta)
            or classified is not True
            or not set(inconsistent) <= set(footprint)
            or report.get("limits") != _FIDELITY_BASE_LIMITS
        ):
            raise ContractError("rendered hook fidelity structure is invalid")
    if blind_spots and blind_spots != removed:
        raise ContractError("rendered hook fidelity structure is invalid")

    if dirty or inconsistent or mismatches:
        expected_verdict = "UNUSABLE"
    elif not added and not removed:
        expected_verdict = "TRANSPARENT"
    elif (
        classified
        and not added
        and not report["arm_surface_changed"]
        and footprint is not None
        and set(removed) <= set(footprint)
    ):
        expected_verdict = "ATTRIBUTION_LOSS"
    else:
        expected_verdict = "PERTURBS"
    if report.get("verdict") != expected_verdict:
        raise ContractError("rendered hook fidelity structure is invalid")
    if blind_spots != (removed if expected_verdict == "ATTRIBUTION_LOSS" else []):
        raise ContractError("rendered hook fidelity structure is invalid")
    expected_usable = expected_verdict in {"TRANSPARENT", "ATTRIBUTION_LOSS"}
    if type(report.get("argument_evidence_usable")) is not bool or report[
        "argument_evidence_usable"
    ] is not expected_usable:
        raise ContractError("rendered hook fidelity structure is invalid")
    return report


@normalize_renderer_failures("hook fidelity")
def render_fidelity(report: dict[str, Any]) -> str:
    report = _validated_fidelity_report(report)
    verdict = report.get("verdict")
    lines = [
        f"hook fidelity: {verdict}  (script {report.get('script_sha256_16')})",
        f"  with hook    {report.get('with_hook_names')} attributed names",
        f"  without hook {report.get('without_hook_names')} attributed names",
        f"  jaccard      {report.get('jaccard')}",
    ]
    if report.get("inconsistent_footprint"):
        lines.append(
            "  !! inconsistent arms: "
            + ", ".join(report["inconsistent_footprint"][:6])
            + " -- the instrument reaches these on the control but they are absent "
            "from the hooked arm, which cannot happen in one run. Check that all "
            "four documents come from the same batch"
        )
    if report.get("dirty_subtractions"):
        lines.append(
            "  !! dirty subtraction in: "
            + ", ".join(report["dirty_subtractions"])
            + " -- no transparency verdict is possible from these arms"
        )
    if report.get("method_mismatches"):
        lines.append("  !! fidelity arms use different methods on:")
        for field in sorted(report["method_mismatches"])[:12]:
            lines.append(f"      {field}")
    for key, label in (("added_by_hook", "only with hook"), ("removed_by_hook", "only without hook")):
        names = report.get(key) or []
        if names:
            lines.append(f"  {label} ({len(names)}):")
            lines.extend(f"      {n}" for n in names[:20])
            if len(names) > 20:
                lines.append(f"      ... {len(names) - 20} more")
    if report.get("footprint_size") is not None:
        lines.append(
            f"  instrument footprint: {report['footprint_size']} name(s) the "
            "wrappers reach on their own"
        )
        lines.append(
            "  sample's own surface changed (footprint removed from both sides): "
            f"{report.get('arm_surface_changed')}"
        )
        for name in (report.get("sample_delta") or [])[:10]:
            lines.append(f"      {name}   (sample-side difference)")
    if verdict == "TRANSPARENT":
        lines.append(
            "  the instrument did not change the passively observed surface; "
            "argument evidence from this pin is usable"
        )
    elif verdict == "ATTRIBUTION_LOSS":
        lines.append(
            "  the sample behaved identically -- its raw surface is unchanged. The "
            "instrument reaches these names itself, so control subtraction can no "
            "longer attribute them:"
        )
        lines.extend(f"      {n}   (blind spot, not a behaviour change)"
                     for n in report.get("blind_spots") or [])
        lines.append(
            "  argument evidence is usable; the attributed surface from a hooked "
            "run is short by exactly the names above"
        )
    elif verdict == "PERTURBS":
        lines.append(
            "  !! the instrument changed what the sample did; argument evidence "
            "describes the instrumented run, not the plain one"
        )
    for limit in report.get("limits") or []:
        lines.append(f"  note: {limit}")
    return "\n".join(lines) + "\n"
