"""Bounded, technique-level answers over product-script observations.

Why this module exists
----------------------
Observation artifacts are correct and complete, and that makes them unusable as
a direct answer. One arm is ~50 KB / ~12,900 tokens; a two-arm comparison is
~25,000. The intended operator of this tool is an agent whose scarcest resource
is context, so "open the artifact and look" -- the affordance a human relies on
-- is exactly the operation that must be avoided.

Measured on 2026-08-06 while reversing FedEx/HomeDepot/Marriott SBSD arms: every
question asked of an observation required hand-authoring a bespoke JSON walk.
Three questions in one session, three throwaway scripts, one of which failed on a
syntax error and cost an extra round trip. The primitives (`subtract`,
`compare`, `check`) all produce evidence; none of them answer a question.

What makes this a digest rather than a summariser
-------------------------------------------------
Truncating 399 API names to the first 40 would be compression without meaning.
Instead names are rolled up to the *fingerprinting technique* they implement --
audio-graph, canvas, WebGL, font enumeration, worker realm -- because that is
the vocabulary the reverse engineer is actually working in. "Does this collector
do audio fingerprinting, and how deeply?" is answerable in ~30 lines; the raw
name list is only needed once that question has been narrowed.

Honesty rules carried over from the rest of this package: absent is never
reported as zero, and a technique with no observed calls is reported as
`not observed` rather than omitted, because omission reads as absence of the
question rather than absence of the answer.
"""

from __future__ import annotations

from collections import Counter
from functools import wraps
import json
import math
import re

from typing import Any, Iterable
from urllib.parse import urlsplit

from .errors import safe_failure_receipt
from .product_observation import (
    _ARM_CONTROL_METHOD_SOURCES,
    OBSERVATION_SCHEMA,
    SURFACE_METHOD_FIELDS,
    SUBTRACTION_SCHEMA,
    ContractError,
    _browser_build_method,
    _driver_metadata,
    _driver_supplied,
    _method_value_is_unverifiable,
    _observation_stage_routes,
    _prelude_document_metadata,
    _ready_expression_metadata,
    _reconciled_ambient_input,
    _reconciled_collector_startup,
    _reconciled_input_method,
    _reconciled_rehost_dependencies,
    _reconciled_script_identity,
    _reconciled_subtraction_script_identity,
    _retained_subtraction_method_pairs,
    _sanitize_capture_provenance,
    _sanitize_input_probe_report,
    _sanitize_offline_guard,
    _sanitize_request_activity_report,
    _sanitize_resource_intent_report,
    _sanitize_script_execution_summary,
    _sanitize_startup_document,
    _sanitize_source_provenance,
    _saved_subtraction_driver_execution_receipts_coherent,
    _saved_subtraction_await_receipts_coherent,
    _saved_subtraction_page_load_receipts_coherent,
    _saved_subtraction_ready_probe_receipts_coherent,
    _saved_subtraction_trace_receipts_coherent,
    _surface_claim_is_ready,
    _surface_method,
    _unverifiable_method_value,
    _verified_subtraction_receipt,
    _verified_subtraction_request_activity,
    _verified_subtraction_resource_intents,
    _verified_subtraction_observation_lineage,
    _viewport_method_value,
    project_product_script_analysis_boundary,
    project_product_script_vendor_hint,
    sanitize_product_script_analysis_boundary,
)

DIGEST_SCHEMA = "browser-core.product-script-digest/1"
DIFF_SCHEMA = "browser-core.product-script-digest-diff/1"
RAW_ATTRIBUTION_WARNING = (
    "raw surface: counts include browser-internal work not caused by the "
    "script; subtract an empty-script control before attributing anything"
)
EMPTY_SURFACE_WARNING = (
    "attributed surface is EMPTY: the arm's API set was identical to "
    "the empty-script control. The script either did not execute or is "
    "not a collector — this is not evidence that it collects nothing"
)
MAX_CORPUS_ARMS = 4096
MAX_CORPUS_LABEL_BYTES = 1024
MAX_CORPUS_GROUP_BYTES = 256
MAX_API_SURFACE_ENTRIES = 1_000_000
MAX_API_EVENT_COUNT = 1_000_000_000
MAX_API_EVENT_NAME_BYTES = 1024
CONTROL_METHOD_AXES = tuple(
    field.removeprefix("arm_") for field in SURFACE_METHOD_FIELDS
)


def _normalize_renderer_failures(label: str):
    """Turn malformed portable renderer inputs into one value-free failure.

    Renderers are public artifact boundaries. Producer output is already typed,
    but a portable artifact can be edited before rendering; leaking ``KeyError``
    or a supplied nested value makes that boundary depend on implementation
    details. Memory/process failures intentionally remain outside this guard.
    """

    def decorate(function):
        @wraps(function)
        def wrapped(document):
            try:
                return function(document)
            except ContractError:
                raise
            except (
                LookupError,
                AttributeError,
                TypeError,
                ValueError,
                OverflowError,
                UnicodeError,
                RecursionError,
            ):
                raise ContractError(f"rendered {label} structure is invalid") from None

        return wrapped

    return decorate


def _bounded_text(value: object, *, maximum: int, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise ContractError(f"{label} is invalid")
    try:
        encoded = value.encode("utf-8", errors="strict")
    except UnicodeEncodeError:
        raise ContractError(f"{label} is invalid") from None
    if len(encoded) > maximum or any(
        ord(character) < 0x20 or ord(character) == 0x7F for character in value
    ):
        raise ContractError(f"{label} is invalid")
    return value


def _validated_document_population(
    documents: object, *, population: str, require_nonempty: bool
) -> list[tuple[str, dict[str, Any]]]:
    if (
        type(documents) is not list
        or len(documents) > MAX_CORPUS_ARMS
        or (require_nonempty and not documents)
    ):
        raise ContractError(f"{population} document population is invalid")
    checked: list[tuple[str, dict[str, Any]]] = []
    seen_labels: set[str] = set()
    for item in documents:
        if not isinstance(item, tuple) or len(item) != 2:
            raise ContractError(f"{population} document entry is invalid")
        label = _bounded_text(
            item[0], maximum=MAX_CORPUS_LABEL_BYTES, label=f"{population} label"
        )
        document = item[1]
        if not isinstance(document, dict):
            raise ContractError(f"{population} document entry is invalid")
        if label in seen_labels:
            raise ContractError(f"{population} document labels must be unique")
        seen_labels.add(label)
        checked.append((label, document))
    return checked


# Fingerprinting-technique taxonomy.
#
# Keys are techniques an anti-bot collector can implement; values are Web IDL
# interface names as they appear in `api.<Interface>.<member>` trace event names.
# Membership is by exact interface name, never substring, so `AudioBuffer` cannot
# silently absorb an unrelated future `AudioBufferThing`.
TECHNIQUES: dict[str, tuple[str, ...]] = {
    "audio-graph": (
        "AudioContext",
        "OfflineAudioContext",
        "BaseAudioContext",
        "AudioNode",
        "AnalyserNode",
        "GainNode",
        "OscillatorNode",
        "AudioBuffer",
        "AudioBufferSourceNode",
        "DynamicsCompressorNode",
        "AudioDestinationNode",
        "AudioParam",
        "AudioScheduledSourceNode",
        "BiquadFilterNode",
        "ChannelMergerNode",
        "ChannelSplitterNode",
        "ConvolverNode",
        "DelayNode",
        "IIRFilterNode",
        "PannerNode",
        "StereoPannerNode",
        "WaveShaperNode",
        "PeriodicWave",
        "AudioListener",
        "AudioWorklet",
    ),
    "canvas-raster": (
        "HTMLCanvasElement",
        "CanvasRenderingContext2D",
        "OffscreenCanvas",
        "OffscreenCanvasRenderingContext2D",
        "Path2D",
        "ImageData",
        "CanvasGradient",
        "CanvasPattern",
        "TextMetrics",
        "ImageBitmap",
        "ImageBitmapRenderingContext",
    ),
    "webgl": (
        "WebGLRenderingContext",
        "WebGL2RenderingContext",
        "WebGLProgram",
        "WebGLShader",
        "WebGLBuffer",
        "WebGLTexture",
        "WebGLFramebuffer",
        "WebGLRenderbuffer",
        "WebGLUniformLocation",
        "WebGLActiveInfo",
        "WebGLContextEvent",
        "WebGLVertexArrayObject",
        "WebGLQuery",
        "WebGLSync",
        "WebGLSampler",
        "WebGLTransformFeedback",
        "WebGLLoseContext",
        "WebGLShaderPrecisionFormat",
    ),
    "webgpu": (
        "GPU",
        "GPUAdapter",
        "GPUAdapterInfo",
        "GPUSupportedFeatures",
        "GPUSupportedLimits",
        "GPUDevice",
    ),
    "navigator-identity": (
        "Navigator",
        "NavigatorUAData",
        "WorkerNavigator",
        "UserActivation",
    ),
    "screen-display": (
        "Screen",
        "ScreenOrientation",
        "VisualViewport",
        "MediaQueryList",
        "DevicePixelRatio",
    ),
    "font-enumeration": (
        "FontFace",
        "FontFaceSet",
        "FontFaceSetLoadEvent",
        "SyncIterator_FontFaceSet",
    ),
    "timing": (
        "Performance",
        "PerformanceEntry",
        "PerformanceTiming",
        "PerformanceNavigation",
        "PerformanceNavigationTiming",
        "PerformanceResourceTiming",
        "PerformanceObserver",
        "PerformanceMark",
        "PerformanceMeasure",
        "PerformanceServerTiming",
        "PerformancePaintTiming",
    ),
    "storage": (
        "Storage",
        "IDBFactory",
        "IDBDatabase",
        "IDBObjectStore",
        "IDBRequest",
        "IDBTransaction",
        "IDBIndex",
        "IDBCursor",
        "IDBKeyRange",
        "CacheStorage",
        "Cache",
        "StorageManager",
    ),
    "network-transport": (
        "XMLHttpRequest",
        "XMLHttpRequestUpload",
        "Request",
        "Response",
        "Headers",
        "FormData",
        "WebSocket",
        "EventSource",
        "Navigator.sendBeacon",
        "URL",
        "URLSearchParams",
        "Blob",
        "FileReader",
        "ReadableStream",
    ),
    "worker-realm": (
        "Worker",
        "SharedWorker",
        "ServiceWorker",
        "ServiceWorkerContainer",
        "ServiceWorkerRegistration",
        "MessagePort",
        "MessageChannel",
        "MessageEvent",
        "BroadcastChannel",
        "WorkerGlobalScope",
        "DedicatedWorkerGlobalScope",
        "SharedWorkerGlobalScope",
    ),
    "input-behaviour": (
        "MouseEvent",
        "KeyboardEvent",
        "TouchEvent",
        "PointerEvent",
        "WheelEvent",
        "InputEvent",
        "CompositionEvent",
        "FocusEvent",
        "Touch",
        "TouchList",
        "GamepadEvent",
        "Gamepad",
        "GamepadButton",
    ),
    "media-devices": (
        "MediaDevices",
        "MediaStream",
        "MediaStreamTrack",
        "MediaRecorder",
        "MediaSource",
        "HTMLMediaElement",
        "HTMLVideoElement",
        "HTMLAudioElement",
        "MediaCapabilities",
        "MediaKeys",
        "MediaKeySystemAccess",
        "MediaDeviceInfo",
    ),
    "webrtc": (
        "RTCPeerConnection",
        "RTCDataChannel",
        "RTCIceCandidate",
        "RTCSessionDescription",
        "RTCRtpSender",
        "RTCRtpReceiver",
        "RTCDtlsTransport",
        "RTCStatsReport",
    ),
    "crypto": (
        "Crypto",
        "SubtleCrypto",
        "CryptoKey",
    ),
    "device-sensors": (
        "DeviceOrientationEvent",
        "DeviceMotionEvent",
        "DeviceMotionEventAcceleration",
        "DeviceMotionEventRotationRate",
        "Accelerometer",
        "Gyroscope",
        "Magnetometer",
        "AmbientLightSensor",
        "Sensor",
        "BatteryManager",
        "NetworkInformation",
    ),
    "permissions": (
        "Permissions",
        "PermissionStatus",
        "Notification",
        "Geolocation",
        "GeolocationPositionError",
        "GeolocationCoordinates",
    ),
    "speech": (
        "SpeechSynthesis",
        "SpeechSynthesisVoice",
        "SpeechSynthesisUtterance",
        "SpeechRecognition",
    ),
    "plugin-mime": (
        "Plugin",
        "PluginArray",
        "MimeType",
        "MimeTypeArray",
    ),
    "dom-probe": (
        "Document",
        "HTMLDocument",
        "Element",
        "HTMLElement",
        "Node",
        "HTMLIFrameElement",
        "HTMLScriptElement",
        "HTMLDivElement",
        "HTMLParagraphElement",
        "HTMLSpanElement",
        "HTMLBodyElement",
        "HTMLHeadElement",
        "HTMLStyleElement",
        "HTMLLinkElement",
        "HTMLAnchorElement",
        "HTMLImageElement",
        "HTMLInputElement",
        "HTMLTextAreaElement",
        "HTMLTemplateElement",
        "HTMLSlotElement",
        "HTMLHtmlElement",
        "HTMLCollection",
        "SVGElement",
        "CSSStyleDeclaration",
        "CSSStyleSheet",
        "CSS",
        "DOMRect",
        "DOMRectReadOnly",
        "DOMTokenList",
        "DOMImplementation",
        "DOMException",
        "NamedNodeMap",
        "Attr",
        "Range",
        "ShadowRoot",
        "DocumentFragment",
        "MutationObserver",
        "MutationRecord",
        "IntersectionObserver",
        "ResizeObserver",
        "ResizeObserverEntry",
        "TreeWalker",
        "NodeList",
        "CharacterData",
        "Comment",
        "Text",
        "getComputedStyle",
    ),
    "window-globals": (
        "Window",
        "Location",
        "History",
        "Console",
        "CustomElementRegistry",
        "External",
        "BarProp",
        "Selection",
    ),
    "event-plumbing": (
        "EventTarget",
        "Event",
        "CustomEvent",
    ),
    "encoding": (
        "TextEncoder",
        "TextDecoder",
        "TextEncoderStream",
        "TextDecoderStream",
    ),
    "memory-introspection": ("MemoryInfo",),
    "trusted-types": (
        "TrustedTypePolicy",
        "TrustedTypePolicyFactory",
        "TrustedHTML",
        "TrustedScript",
        "TrustedScriptURL",
    ),
    # Chromium-internal IPC bindings reachable from page script. These are not a
    # web-platform fingerprinting technique -- they are an *instrumented-build
    # tell*. `window.Mojo` is absent from stock Chrome unless MojoJS bindings are
    # enabled, so a collector that reaches these names is in a position to
    # distinguish this browser from the one it claims to be. Bucketed separately
    # and never folded into dom-probe, because the security meaning is different.
    "chromium-internal": (
        "Mojo",
        "MojoHandle",
        "MojoWatcher",
        "MojoInterfaceInterceptor",
    ),
    "error-stack": (
        "ErrorEvent",
        "PromiseRejectionEvent",
        "StackFrame",
        "Error",
    ),
}

# Reverse index: interface name -> technique. Built once; a name in two
# techniques is a taxonomy bug, so the build asserts uniqueness rather than
# silently letting the last definition win.
_INTERFACE_TO_TECHNIQUE: dict[str, str] = {}
for _technique, _interfaces in TECHNIQUES.items():
    for _iface in _interfaces:
        if _iface in _INTERFACE_TO_TECHNIQUE:  # pragma: no cover - taxonomy guard
            raise RuntimeError(
                f"interface {_iface!r} claimed by both "
                f"{_INTERFACE_TO_TECHNIQUE[_iface]!r} and {_technique!r}"
            )
        _INTERFACE_TO_TECHNIQUE[_iface] = _technique


# Bare global functions. These arrive as two-segment names (`api.fetch`) rather
# than `api.<Interface>.<member>`, because they hang off the global object and
# have no owning interface. Mapped explicitly: `fetch` is the single most
# load-bearing name in the whole corpus for transport questions, and leaving it
# in `unclassified` would hide it in exactly the technique bucket an analyst
# checks first.
GLOBAL_FUNCTIONS: dict[str, str] = {
    "fetch": "network-transport",
    "atob": "encoding",
    "btoa": "encoding",
    "queueMicrotask": "event-plumbing",
    "requestAnimationFrame": "timing",
    "requestIdleCallback": "timing",
    "structuredClone": "encoding",
}


def interface_of(api_name: str) -> str | None:
    """Return the Web IDL interface in an ``api.<Interface>.<member>`` event name.

    Returns ``None`` for names that do not have that shape rather than guessing,
    so an unexpected event-name format shows up as ``unclassified`` downstream
    instead of being silently attributed to a technique. Bare globals such as
    ``api.fetch`` legitimately have no interface and are resolved by
    :data:`GLOBAL_FUNCTIONS` in :func:`technique_of` instead.
    """
    if not isinstance(api_name, str) or not api_name.startswith("api."):
        return None
    parts = api_name.split(".")
    if len(parts) < 3:
        return None
    return parts[1]


def technique_of(api_name: str) -> str:
    """Map one API event name onto a fingerprinting technique.

    Unknown interfaces map to ``"unclassified"``. That bucket is reported, never
    hidden: a growing unclassified count is the signal that the taxonomy has
    fallen behind the collector, which is exactly the kind of drift worth seeing.
    """
    if not isinstance(api_name, str):
        return "unclassified"
    iface = interface_of(api_name)
    if iface is None:
        parts = api_name.split(".")
        if api_name.startswith("api.") and len(parts) == 2:
            return GLOBAL_FUNCTIONS.get(parts[1], "unclassified")
        return "unclassified"
    return _INTERFACE_TO_TECHNIQUE.get(iface, "unclassified")


def _validated_event_count_map(value: Any, *, field: str) -> dict[str, int]:
    """Validate one trace-reduced name/count plane without coercion.

    These maps are evidence, not friendly CLI inputs.  In particular, JSON
    booleans are integers in Python and ``int("1")`` looks harmless, but either
    would let a malformed artifact quietly become a valid-looking RE result.
    """
    if not isinstance(value, dict):
        raise ContractError(f"{field} must be an event-name count map")
    if len(value) > MAX_API_SURFACE_ENTRIES:
        raise ContractError(
            f"{field} exceeds the {MAX_API_SURFACE_ENTRIES:,}-entry safety bound"
        )
    result: dict[str, int] = {}
    for name, count in value.items():
        try:
            encoded_name = name.encode("utf-8") if isinstance(name, str) else b""
        except UnicodeEncodeError:
            encoded_name = b""
        if (
            not encoded_name
            or len(encoded_name) > MAX_API_EVENT_NAME_BYTES
            or any(ord(character) < 32 or ord(character) == 127 for character in name)
        ):
            raise ContractError(f"{field} contains an invalid event name")
        if (
            isinstance(count, bool)
            or not isinstance(count, int)
            or not 1 <= count <= MAX_API_EVENT_COUNT
        ):
            raise ContractError(
                f"{field} event counts must be integers from 1 to "
                f"{MAX_API_EVENT_COUNT:,}"
            )
        result[name] = count
    return result


def _api_names(document: dict[str, Any]) -> dict[str, int]:
    """Pull the API-name -> call-count map out of either document shape.

    Accepts an observation (raw surface) or a subtraction (attributed surface).
    Raises rather than returning an empty dict when the document is neither,
    because an empty surface and an unreadable document must not look alike.

    For a subtraction this returns only the *introduced* names. Amplified names
    are deliberately kept separate -- see :func:`_amplified_names`.
    """
    if not isinstance(document, dict):
        raise ContractError("observation digest input must be an object")
    schema = document.get("schema")
    if schema == OBSERVATION_SCHEMA:
        analysis = document.get("analysis")
        if not isinstance(analysis, dict):
            raise ContractError(
                "observation has no analysis (the launch failed); "
                "there is no surface to digest"
            )
        if "events_by_name" not in analysis:
            raise ContractError("observation analysis is missing events_by_name")
        source = _validated_event_count_map(
            analysis.get("events_by_name"), field="analysis.events_by_name"
        )
    elif schema == SUBTRACTION_SCHEMA:
        if "only_in_arm" not in document:
            raise ContractError("subtraction is missing only_in_arm")
        source = _validated_event_count_map(
            document.get("only_in_arm"), field="only_in_arm"
        )
    else:
        raise ContractError(
            f"expected a {OBSERVATION_SCHEMA} or {SUBTRACTION_SCHEMA} document, "
            f"got {schema!r}"
        )
    return {name: count for name, count in source.items() if name.startswith("api.")}


def _subtraction_claim_ready(document: dict[str, Any]) -> bool:
    """Require both the clean name subtraction and its stronger claim gate."""
    if "surface_claim_ready" in document:
        required_true = (
            "ready_probe_comparable",
            "await_method_comparable",
            "arm_readiness_satisfied",
            "input_method_comparable",
            "collector_started",
        )
        optional_coherent = (
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
        if any(
            field in document and document[field] is not True
            for field in required_true
        ) or any(
            field in document
            and document[field] is not True
            and document[field] is not None
            for field in optional_coherent
        ):
            return False
    if not _saved_input_claim_receipts_coherent(document):
        return False
    if not _saved_rehost_dependency_receipts_coherent(document):
        return False
    if not _saved_offline_guard_receipts_coherent(document):
        return False
    if not _saved_observation_lineage_receipts_coherent(document):
        return False
    if not _saved_startup_receipts_coherent(document):
        return False
    if not _saved_method_mismatch_verdict_coherent(document):
        return False
    if not _saved_script_identity_receipts_coherent(document):
        return False
    if "driver_execution_complete" in document and not (
        _saved_subtraction_driver_execution_receipts_coherent(document)
    ):
        return False
    if not _saved_subtraction_trace_receipts_coherent(document):
        return False
    if not _saved_subtraction_page_load_receipts_coherent(document):
        return False
    if not _saved_subtraction_ready_probe_receipts_coherent(document):
        return False
    if not _saved_subtraction_await_receipts_coherent(document):
        return False
    if not _saved_request_activity_receipts_valid(document):
        return False
    if not _saved_resource_intent_receipts_valid(document):
        return False
    if not _saved_current_subtraction_receipt_coherent(document):
        return False
    return (
        document.get("schema") == SUBTRACTION_SCHEMA
        and document.get("clean_subtraction") is True
        and _surface_claim_is_ready(document)
    )


def _saved_current_subtraction_receipt_coherent(document: dict[str, Any]) -> bool:
    """Require current producer receipts to satisfy the saved writer contract."""
    if (
        document.get("schema") != SUBTRACTION_SCHEMA
        or document.get("subtraction_receipt_sha256") is None
    ):
        return True
    try:
        _verified_subtraction_receipt(document)
    except (ContractError, TypeError, ValueError, OverflowError):
        return False
    return True


def _saved_request_activity_receipts_valid(document: dict[str, Any]) -> bool:
    """Apply the saved writer's full request receipt contract to a digest."""
    try:
        _verified_subtraction_request_activity(document)
    except (ContractError, TypeError, ValueError, OverflowError):
        return False
    return True


def _saved_resource_intent_receipts_valid(document: dict[str, Any]) -> bool:
    """Recheck current resource reports without changing legacy digest views."""
    source = document.get("resource_intents")
    if (
        document.get("schema") != SUBTRACTION_SCHEMA
        or not isinstance(source, dict)
        or (
            "non_claim" not in source
            and document.get("subtraction_receipt_sha256") is None
        )
    ):
        return True
    try:
        _verified_subtraction_resource_intents(document)
    except (ContractError, TypeError, ValueError, OverflowError):
        return False
    return True


def _saved_rehost_dependency_receipts_coherent(document: dict[str, Any]) -> bool:
    """Reconcile a retained legacy dependency verdict with its saved gate."""
    if document.get("schema") != SUBTRACTION_SCHEMA:
        return True
    has_gate = "rehost_dependencies_complete" in document
    has_receipt = "unserved_requests" in document
    if has_gate != has_receipt:
        return False
    if not has_gate:
        return True
    expected, _, _ = _reconciled_rehost_dependencies(
        {"unserved_requests": document["unserved_requests"]}
    )
    return expected is document["rehost_dependencies_complete"]


def _saved_offline_guard_receipts_coherent(document: dict[str, Any]) -> bool:
    """Reconcile saved containment method receipts before a current claim."""
    if document.get("schema") != SUBTRACTION_SCHEMA:
        return True
    fields = {"arm_offline_guard", "control_offline_guard", "offline_guard_comparable"}
    present = fields & document.keys()
    if not present:
        return True
    if present != fields:
        return (
            "surface_claim_ready" not in document
            and "offline_guard_comparable" not in document
        )
    arm = document["arm_offline_guard"]
    control = document["control_offline_guard"]
    if (
        not isinstance(arm, dict)
        or not isinstance(control, dict)
        or _sanitize_offline_guard(arm) != arm
        or _sanitize_offline_guard(control) != control
    ):
        return False
    expected = (
        None
        if arm == {"status": "not-recorded"} and control == {"status": "not-recorded"}
        else arm.get("status") == "applied"
        and control.get("status") == "applied"
        and arm == control
    )
    return document["offline_guard_comparable"] is expected


def _saved_observation_lineage_receipts_coherent(document: dict[str, Any]) -> bool:
    """Reuse the subtraction parent-receipt rule for saved digest claims."""
    if document.get("schema") != SUBTRACTION_SCHEMA:
        return True
    try:
        _verified_subtraction_observation_lineage(document)
    except ContractError:
        return False
    return True


def _saved_startup_receipts_coherent(document: dict[str, Any]) -> bool:
    """Reconcile retained startup witnesses with their saved claim gates."""
    if document.get("schema") != SUBTRACTION_SCHEMA:
        return True
    arm_fields = {"collector_started", "collector_startup", "collector_startup_coherent"}
    control_fields = {
        "control_collector_startup",
        "control_collector_startup_coherent",
    }
    witness_fields = (arm_fields - {"collector_started"}) | control_fields | {
        "startup_derivation_coherent"
    }
    present_witness = witness_fields & document.keys()
    if not present_witness:
        return True
    if "surface_claim_ready" in document and not (
        arm_fields | control_fields | {"startup_derivation_coherent"}
    ) <= document.keys():
        return False
    if present_witness & arm_fields:
        if not arm_fields <= document.keys():
            return False
        raw = document["collector_startup"]
        started, safe, coherent = (
            _reconciled_collector_startup({"collector_startup": raw})
            if raw is not None
            else (None, None, None)
        )
        if (
            raw != safe
            or document["collector_started"] is not started
            or document["collector_startup_coherent"] is not coherent
        ):
            return False
    if present_witness & control_fields:
        if not control_fields <= document.keys():
            return False
        raw = document["control_collector_startup"]
        _, safe, coherent = (
            _reconciled_collector_startup({"collector_startup": raw})
            if raw is not None
            else (None, None, None)
        )
        if (
            raw != safe
            or document["control_collector_startup_coherent"] is not coherent
        ):
            return False
    if "startup_derivation_coherent" in document:
        arm = document.get("collector_startup_coherent")
        control = document.get("control_collector_startup_coherent")
        expected = None if arm is None and control is None else arm is True and control is True
        if document["startup_derivation_coherent"] is not expected:
            return False
    return True


def _saved_method_mismatch_verdict_coherent(document: dict[str, Any]) -> bool:
    """Keep a saved arm/control method verdict paired with its mismatch list."""
    if document.get("schema") != SUBTRACTION_SCHEMA:
        return True
    fields = {"arm_control_method_comparable", "arm_control_method_mismatches"}
    present = fields & document.keys()
    if not present:
        return True
    if present != fields:
        return False
    comparable = document["arm_control_method_comparable"]
    mismatches = document["arm_control_method_mismatches"]
    if not (
        (comparable is None or type(comparable) is bool)
        and type(mismatches) is list
        and all(
            type(field) is str and field in _ARM_CONTROL_METHOD_SOURCES
            for field in mismatches
        )
        and mismatches == sorted(set(mismatches))
        and (comparable is False) is bool(mismatches)
    ):
        return False
    # Historical subtraction summaries may retain only the verdict. When a
    # method pair is saved, it must still support that verdict at read time.
    pairs = _retained_subtraction_method_pairs(document)
    for field, (arm_value, control_value) in pairs.items():
        arm_present = f"arm_{field}" in document
        control_present = f"control_{field}" in document
        if not arm_present and not control_present:
            continue
        if arm_present != control_present:
            return False
        unverifiable = _method_value_is_unverifiable(
            arm_value
        ) or _method_value_is_unverifiable(control_value)
        if comparable is True and (arm_value != control_value or unverifiable):
            return False
        if (
            document.get("script_identity_coherent") is True
            and field in mismatches
            and arm_value == control_value
            and not unverifiable
        ):
            return False
    return True


def _saved_script_identity_receipts_coherent(document: dict[str, Any]) -> bool:
    """Bind retained compact script identities to their saved arm/control pins."""
    if document.get("schema") != SUBTRACTION_SCHEMA:
        return True
    arm_present = "script_identity" in document
    control_present = (
        "control_script_identity" in document
        or "control_script_sha256_16" in document
    )
    if not arm_present and not control_present:
        return True
    if (
        document.get("script_identity_coherent") is None
        and document.get("script_identity") is None
        and document.get("control_script_identity") is None
    ):
        return True
    if document.get("script_identity_coherent") is not True:
        return False
    if arm_present and _reconciled_subtraction_script_identity(document) is None:
        return False
    if control_present:
        if (
            not arm_present
            or "control_script_identity" not in document
            or "control_script_sha256_16" not in document
        ):
            return False
        control = {
            "script_identity_coherent": True,
            "script_identity": document["control_script_identity"],
            "arm_script_sha256_16": document["control_script_sha256_16"],
        }
        if _reconciled_subtraction_script_identity(control) is None:
            return False
    return True


def _saved_input_claim_receipts_coherent(document: dict[str, Any]) -> bool:
    """Recheck explicit input gates without requiring a digest event witness."""
    if document.get("schema") != SUBTRACTION_SCHEMA:
        return True
    current_receipts = bool(
        "arm_observation_receipt_sha256" in document
        or "subtraction_receipt_sha256" in document
    )
    input_fields = {
        "arm_input_profile",
        "control_input_profile",
        "arm_input_probe",
        "control_input_probe",
        "input_method_comparable",
    }
    present_input = input_fields & document.keys()
    if present_input and present_input != input_fields and (
        "input_method_comparable" in document or "surface_claim_ready" in document
    ):
        return False
    if "input_method_comparable" in document:
        if document["input_method_comparable"] is not True:
            return False
        comparable, safe_arm_probe, safe_control_probe = _reconciled_input_method(
            {
                "input_profile": document["arm_input_profile"],
                "input_probe": document.get("arm_input_probe"),
            },
            {
                "input_profile": document["control_input_profile"],
                "input_probe": document.get("control_input_probe"),
            },
        )
        if not comparable:
            return False
        if current_receipts and (
            document["arm_input_probe"] != safe_arm_probe
            or document["control_input_probe"] != safe_control_probe
        ):
            return False

    ambient_fields = {
        "arm_ambient_input",
        "control_ambient_input",
        "ambient_input_clean",
    }
    present_ambient = ambient_fields & document.keys()
    if present_ambient and present_ambient != ambient_fields and (
        "ambient_input_clean" in document or "surface_claim_ready" in document
    ):
        return False
    if "ambient_input_clean" not in document:
        return True
    arm_ambient = document.get("arm_ambient_input")
    control_ambient = document.get("control_ambient_input")
    ambient_grade = document["ambient_input_clean"]
    if ambient_grade is None:
        return arm_ambient is None and control_ambient is None
    if ambient_grade is not True:
        return False
    for profile, receipt in (
        (document.get("arm_input_profile", "none"), arm_ambient),
        (document.get("control_input_profile", "none"), control_ambient),
    ):
        safe, clean = _reconciled_ambient_input(
            {"input_profile": profile, "ambient_input": receipt}
        )
        if clean is not True or (current_receipts and receipt != safe):
            return False
    return True


def _amplified_names(document: dict[str, Any]) -> dict[str, dict[str, int]]:
    """Names the script *amplified* rather than introduced.

    A collector reaches a web API in two distinguishable ways. It can call
    something the host page never touches -- that lands in ``only_in_arm`` and is
    unambiguous. Or it can call something the page already uses, much harder:
    subtraction cancels the name entirely and the technique disappears from the
    digest even though the collector is plainly using it.

    Measured 2026-08-06 across 35 clean subtractions, this second class is not a
    rounding error. ``api.Performance.now`` runs 127 calls in the arm against 1
    in the control, in 30 of 35 arms; ``api.MediaQueryList.matches.get`` is
    elevated in 35 of 35. Reading introduced names alone reported the main sensor
    as touching one timing name and no screen-display at all -- both wrong.

    Amplified names are reported in their own column rather than merged into the
    introduced count, because the evidence for them is weaker: elevation is a
    threshold judgement (``arm >= 2x control`` and ``arm - control >= 3``), not
    the clean set difference that introduced names get.
    """
    if document.get("schema") != SUBTRACTION_SCHEMA:
        return {}
    elevated = document.get("elevated_in_arm", {})
    if not isinstance(elevated, dict):
        raise ContractError("elevated_in_arm must be an event-name comparison map")
    if len(elevated) > MAX_API_SURFACE_ENTRIES:
        raise ContractError(
            "elevated_in_arm exceeds the "
            f"{MAX_API_SURFACE_ENTRIES:,}-entry safety bound"
        )
    result: dict[str, dict[str, int]] = {}
    for name, row in elevated.items():
        # Reuse the exact same key contract as the primary evidence plane.
        _validated_event_count_map({name: 1}, field="elevated_in_arm")
        if not isinstance(row, dict) or set(row) != {"arm", "control"}:
            raise ContractError(
                "elevated_in_arm rows must contain exactly arm and control"
            )
        arm, control = row["arm"], row["control"]
        for role, count in (("arm", arm), ("control", control)):
            if (
                isinstance(count, bool)
                or not isinstance(count, int)
                or not 1 <= count <= MAX_API_EVENT_COUNT
            ):
                raise ContractError(
                    f"elevated_in_arm {role} counts must be integers from 1 to "
                    f"{MAX_API_EVENT_COUNT:,}"
                )
        if arm < control * 2 or arm - control < 3:
            raise ContractError(
                "elevated_in_arm row does not satisfy the amplification threshold"
            )
        if name.startswith("api."):
            result[name] = {"arm": arm, "control": control}
    return result


def _label_of(document: dict[str, Any]) -> str:
    field = "arm_label" if document.get("schema") == SUBTRACTION_SCHEMA else "label"
    value = document.get(field)
    if value is None:
        return "unlabelled"
    return _bounded_text(value, maximum=MAX_CORPUS_LABEL_BYTES, label=field)


def _pin_of(document: dict[str, Any]) -> str | None:
    field = (
        "arm_script_sha256_16"
        if document.get("schema") == SUBTRACTION_SCHEMA
        else "script_sha256_16"
    )
    pin = document.get(field)
    if pin is None:
        return None
    if not isinstance(pin, str) or re.fullmatch(r"[0-9a-f]{16}", pin) is None:
        raise ContractError(f"{field} is invalid")
    return pin


def _validated_focus(focus: object) -> str | None:
    if focus is None:
        return None
    if not isinstance(focus, str) or (
        focus not in TECHNIQUES and focus != "unclassified"
    ):
        raise ContractError(
            f"unknown technique; known: {', '.join(sorted(TECHNIQUES))}"
        )
    return focus


RESOURCE_INTENT_ROWS_LIMIT = 16
RESOURCE_INTENT_CORPUS_NON_CLAIM = (
    "DOM attributes present at capture time; not proof that a request was "
    "sent, reached DNS, or received a response"
)


def _resource_intent_view(
    document: dict[str, Any], *, limit: int = RESOURCE_INTENT_ROWS_LIMIT
) -> dict[str, Any] | None:
    """Return a bounded, allowlisted resource-intent view for a digest."""
    source = document.get("resource_intents")
    if not isinstance(source, dict):
        return None
    attributed = document.get("schema") == SUBTRACTION_SCHEMA
    report = _sanitize_resource_intent_report(source)
    if attributed and (
        not _saved_resource_intent_receipts_valid(document)
        or not _saved_current_subtraction_receipt_coherent(document)
    ):
        report = _sanitize_resource_intent_report({"status": "unverifiable"})
    row_key = "only_in_arm" if attributed else "intents"
    rows = report.get(row_key) if isinstance(report.get(row_key), list) else []
    control_rows = (
        report.get("only_in_control")
        if isinstance(report.get("only_in_control"), list)
        else []
    )
    bounded_limit = max(0, min(int(limit), 128))
    result: dict[str, Any] = {
        "status": report["status"],
        "attributed": attributed,
        "row_kind": "introduced" if attributed else "raw",
        "rows_total": len(rows),
        "rows": rows[:bounded_limit],
        "rows_omitted": max(0, len(rows) - bounded_limit),
        "control_only_total": len(control_rows),
        "control_only": control_rows[:bounded_limit],
        "control_only_omitted": max(0, len(control_rows) - bounded_limit),
        "non_claim": report["non_claim"],
    }
    for key in ("arm_count", "control_count", "shared_count", "clean_subtraction"):
        if key in report:
            result[key] = report[key]
    if "diagnostic" in report:
        result["diagnostic"] = report["diagnostic"]
    return result


def _resource_row_key(row: dict[str, Any]) -> str:
    return json.dumps(row, sort_keys=True, separators=(",", ":"))


def _request_activity_view(
    document: dict[str, Any], *, limit: int = RESOURCE_INTENT_ROWS_LIMIT
) -> dict[str, Any] | None:
    source = document.get("request_activity")
    if not isinstance(source, dict):
        return None
    attributed = document.get("schema") == SUBTRACTION_SCHEMA
    report = _sanitize_request_activity_report(source)
    if attributed and (
        not _saved_current_subtraction_receipt_coherent(document)
        or (
            (
                "non_claim" in source
                or document.get("subtraction_receipt_sha256") is not None
            )
            and not _saved_request_activity_receipts_valid(document)
        )
    ):
        report = _sanitize_request_activity_report({"status": "unverifiable"})
    row_key = "only_in_arm" if attributed else "rows"
    rows = report.get(row_key) if isinstance(report.get(row_key), list) else []
    control_rows = (
        report.get("only_in_control")
        if isinstance(report.get("only_in_control"), list)
        else []
    )
    bounded_limit = max(0, min(int(limit), 128))
    return {
        "status": report["status"],
        "attributed": attributed,
        "row_kind": "introduced" if attributed else "raw",
        "rows_total": len(rows),
        "rows": rows[:bounded_limit],
        "rows_omitted": max(0, len(rows) - bounded_limit),
        "control_only_total": len(control_rows),
        "clean_subtraction": report.get("clean_subtraction"),
        "non_claim": report["non_claim"],
    }


def _request_shape_key(row: dict[str, Any]) -> str:
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


def _input_delivery_view(document: dict[str, Any]) -> dict[str, Any] | None:
    """Bind a named input method to its command receipt and trusted witness."""
    attributed = document.get("schema") == SUBTRACTION_SCHEMA
    raw_profile = document.get("arm_input_profile" if attributed else "input_profile")
    if raw_profile is None:
        profile = "none"
        profile_valid = True
    elif isinstance(raw_profile, str) and raw_profile in {
        "none",
        "probe",
        "probe-scroll",
        "probe-touch",
    }:
        profile = raw_profile
        profile_valid = True
    else:
        profile = "invalid"
        profile_valid = False
    raw_control_profile = (
        document.get("control_input_profile", profile) if attributed else profile
    )
    control_profile = (
        raw_control_profile
        if isinstance(raw_control_profile, str)
        and raw_control_profile in {"none", "probe", "probe-scroll", "probe-touch"}
        else "invalid"
    )
    arm_probe_raw = document.get("arm_input_probe" if attributed else "input_probe")
    control_probe_raw = document.get("control_input_probe") if attributed else None
    arm_probe = _sanitize_input_probe_report(arm_probe_raw)
    arm_ambient_key = "arm_ambient_input" if attributed else "ambient_input"
    arm_ambient_document = {"input_profile": profile}
    if arm_ambient_key in document:
        arm_ambient_document["ambient_input"] = document[arm_ambient_key]
    arm_ambient, arm_ambient_clean = _reconciled_ambient_input(
        arm_ambient_document
    )
    control_probe = (
        _sanitize_input_probe_report(control_probe_raw)
        if attributed
        else None
    )
    control_ambient_document = {"input_profile": control_profile}
    if "control_ambient_input" in document:
        control_ambient_document["ambient_input"] = document[
            "control_ambient_input"
        ]
    control_ambient, control_ambient_clean = (
        _reconciled_ambient_input(control_ambient_document)
        if attributed
        else (None, None)
    )

    # A bounded projection can discard an invalid extra event. Carry only the
    # affected role so portable digest validation cannot promote that receipt.
    saved_replay_errors = document.get("_input_delivery_ambient_replay_errors", [])
    replay_errors = (
        {
            role
            for role in saved_replay_errors
            if isinstance(role, str) and role in {"arm", "control"}
        }
        if isinstance(saved_replay_errors, list)
        else set()
    )
    for role, safe, clean, role_profile in (
        ("arm", arm_ambient, arm_ambient_clean, profile),
        ("control", control_ambient, control_ambient_clean, control_profile),
    ):
        if safe is None or clean is True:
            continue
        _, safe_clean = _reconciled_ambient_input(
            {"input_profile": role_profile, "ambient_input": safe}
        )
        if safe_clean is True:
            replay_errors.add(role)
    if "arm" in replay_errors:
        arm_ambient_clean = False
    if "control" in replay_errors:
        control_ambient_clean = False

    extras: dict[str, Any] = {}
    if attributed and control_profile != profile:
        extras["control_profile"] = control_profile
    if replay_errors:
        extras["ambient_receipt_inconsistent_roles"] = sorted(replay_errors)

    if profile == "none":
        saved_probe_roles = document.get("_input_delivery_no_input_probe_roles", [])
        no_input_probe_roles = {
            role
            for role, receipt in (
                ("arm", arm_probe_raw),
                ("control", control_probe_raw),
            )
            if receipt is not None
        }
        if isinstance(saved_probe_roles, list):
            no_input_probe_roles.update(
                role
                for role in saved_probe_roles
                if isinstance(role, str) and role in {"arm", "control"}
            )
        if no_input_probe_roles:
            extras["no_input_probe_roles"] = sorted(no_input_probe_roles)
        contaminated = any(
            (ambient or {}).get("contaminated") is True
            for ambient in (arm_ambient, control_ambient)
        )
        ambient_inconsistent = (
            arm_ambient_clean is False or control_ambient_clean is False
        )
        if (
            not contaminated
            and not ambient_inconsistent
            and not no_input_probe_roles
            and control_profile == profile
        ):
            return None
        return {
            "profile": profile,
            "attributed": attributed,
            "verified": False,
            "contaminated": contaminated,
            "arm_probe": arm_probe,
            "arm_ambient": arm_ambient,
            "control_probe": control_probe,
            "control_ambient": control_ambient,
            "note": "saved no-input receipt reports trusted input contamination"
            if contaminated
            else "saved no-input receipt is inconsistent",
            **extras,
        }

    required = {
        "probe": ("mousemove", "click", "keydown", "keyup"),
        "probe-scroll": ("wheel", "scroll"),
        "probe-touch": ("touchstart", "touchmove", "touchend"),
    }.get(profile, ())

    def role_verified(
        probe: dict[str, Any] | None,
        ambient: dict[str, Any] | None,
        ambient_clean: bool | None,
        expected_profile: str,
    ) -> bool:
        events = (ambient or {}).get("trusted_events") or {}
        return bool(
            probe
            and probe.get("profile") == expected_profile
            and probe.get("complete")
            and probe.get("trusted_transport")
            and ambient_clean is True
            and (
                expected_profile != "probe-touch"
                or probe.get("touch_dispatched") is True
            )
            and required
            and all(int(events.get(name) or 0) > 0 for name in required)
        )

    arm_verified = role_verified(arm_probe, arm_ambient, arm_ambient_clean, profile)
    control_verified = (
        role_verified(
            control_probe, control_ambient, control_ambient_clean, control_profile
        )
        if attributed and control_profile == profile
        else not attributed
    )
    contaminated = any(
        (ambient or {}).get("contaminated") is True
        for ambient in (arm_ambient, control_ambient)
    )
    return {
        "profile": profile,
        "profile_valid": profile_valid,
        "attributed": attributed,
        "verified": bool(arm_verified and control_verified),
        "contaminated": contaminated,
        "required_witnesses": list(required),
        "arm_probe": arm_probe,
        "arm_ambient": arm_ambient,
        "control_probe": control_probe,
        "control_ambient": control_ambient,
        "note": (
            "saved ambient receipt contradicts delivered input"
            if contaminated
            else (
                "fixed method probe, not a human-behavior model; both sample and "
                "control require complete commands and trusted event witnesses"
                if profile_valid
                else "recorded input profile is invalid; delivery cannot be verified"
            )
        ),
        **extras,
    }


def _resource_intent_corpus(entries: list[dict[str, Any]]) -> dict[str, Any] | None:
    """Aggregate intent-row presence without laundering failed snapshots.

    The denominator is successful attributed snapshots, never total arms.  A
    disabled/failed/missing capture is reported separately so a row present in
    2/2 successful snapshots cannot be misread as 2/5 product prevalence.
    """
    contract_arms = 0
    successful = 0
    unavailable: list[dict[str, str]] = []
    raw: list[str] = []
    counts: Counter[str] = Counter()
    rows: dict[str, dict[str, Any]] = {}
    labels: dict[str, list[str]] = {}
    for entry in entries:
        label = str(entry["label"])
        view = _resource_intent_view(entry["document"], limit=128)
        if view is None:
            unavailable.append({"label": label, "status": "missing"})
            continue
        contract_arms += 1
        if not view["attributed"]:
            raw.append(label)
            continue
        if view["status"] != "ok":
            unavailable.append({"label": label, "status": view["status"]})
            continue
        successful += 1
        # Presence, not duplicate count: one arm contributes at most once to a
        # row's denominator even if a hand-edited artifact repeats the row.
        keyed = {_resource_row_key(row): row for row in view["rows"]}
        for key, row in keyed.items():
            counts[key] += 1
            rows[key] = row
            labels.setdefault(key, []).append(label)

    if contract_arms == 0:
        return None
    ordered = sorted(counts, key=lambda key: (-counts[key], key))
    limit = 32
    return {
        "population_arms": len(entries),
        "contract_arms": contract_arms,
        "successful_attributed_arms": successful,
        "unavailable_arms": unavailable[:32],
        "unavailable_arms_omitted": max(0, len(unavailable) - 32),
        "raw_arms": raw[:32],
        "raw_arms_omitted": max(0, len(raw) - 32),
        "population_complete": successful == len(entries),
        "unique_rows": len(ordered),
        "rows": [
            {
                "intent": rows[key],
                "present_in_arms": counts[key],
                "successful_arms": successful,
                "example_labels": sorted(labels[key])[:8],
                "example_labels_omitted": max(0, len(labels[key]) - 8),
            }
            for key in ordered[:limit]
        ],
        "rows_omitted": max(0, len(ordered) - limit),
        "non_claim": RESOURCE_INTENT_CORPUS_NON_CLAIM,
    }


def _roll_up(names: Iterable[str], counts: dict[str, int]) -> dict[str, dict[str, Any]]:
    """Group API names by technique, keeping counts and a bounded example set."""
    buckets: dict[str, dict[str, Any]] = {}
    for name in names:
        tech = technique_of(name)
        bucket = buckets.setdefault(
            tech, {"api_names": 0, "calls": 0, "interfaces": set(), "examples": []}
        )
        bucket["api_names"] += 1
        bucket["calls"] += counts.get(name, 0)
        iface = interface_of(name)
        if iface:
            bucket["interfaces"].add(iface)
    for bucket in buckets.values():
        bucket["interfaces"] = sorted(bucket["interfaces"])
    return buckets


def digest_observation(
    document: dict[str, Any], *, focus: str | None = None, examples: int = 6
) -> dict[str, Any]:
    """Reduce an observation or subtraction to a technique-level answer.

    ``focus`` narrows to a single technique and switches the digest into detail
    mode, where the full API-name list for that technique is included. This is
    the intended drill-down path: ask the bounded question first, then spend
    context only on the technique that turned out to matter.
    """
    if not isinstance(document, dict):
        raise ContractError("observation digest input must be an object")
    if (
        isinstance(examples, bool)
        or not isinstance(examples, int)
        or not 0 <= examples <= 128
    ):
        raise ContractError("examples must be an integer from 0 to 128")
    focus = _validated_focus(focus)
    counts = _api_names(document)

    amplified = _amplified_names(document)
    amp_by_technique: dict[str, int] = {}
    for name in amplified:
        tech = technique_of(name)
        amp_by_technique[tech] = amp_by_technique.get(tech, 0) + 1

    buckets = _roll_up(counts, counts)
    observed = {t: b for t, b in buckets.items() if b["api_names"]}

    # Techniques with no observed calls are listed explicitly. Omitting them
    # would make "we did not look" and "it is not there" indistinguishable.
    # A technique reached only through amplified names is *observed*, so it must
    # not fall into not_observed just because it introduced nothing.
    not_observed = sorted(set(TECHNIQUES) - set(observed) - set(amp_by_technique))

    attributed = document.get("schema") == SUBTRACTION_SCHEMA
    script_attribution_comparable: bool | None = None
    if attributed and "script_attribution_comparable" in document:
        candidate = document.get("script_attribution_comparable")
        if not isinstance(candidate, bool):
            raise ContractError("script_attribution_comparable must be a boolean")
        script_attribution_comparable = candidate
    result: dict[str, Any] = {
        "schema": DIGEST_SCHEMA,
        "label": _label_of(document),
        "script_sha256_16": _pin_of(document),
        "source_schema": document.get("schema"),
        "attributed": attributed,
        # Carried through untouched. A digest is what a reader actually looks
        # at, so an unverified origin has to be visible here or it is invisible.
        "provenance": _sanitize_capture_provenance(document.get("provenance")),
        "source_provenance": _sanitize_source_provenance(
            document.get("source_provenance")
        ),
        "total_api_names": len(counts),
        "total_calls": sum(counts.values()),
        "techniques_observed": len(observed),
        "amplified_api_names": len(amplified),
        "techniques": {
            t: {
                "api_names": b["api_names"],
                "calls": b["calls"],
                "amplified": amp_by_technique.get(t, 0),
                "interfaces": b["interfaces"][:examples],
                "interfaces_total": len(b["interfaces"]),
            }
            for t, b in sorted(
                observed.items(), key=lambda kv: (-kv[1]["api_names"], kv[0])
            )
        },
        # Techniques the script only ever amplified. These would otherwise be
        # invisible: nothing was introduced, so the rollup has no bucket for them.
        "amplified_only_techniques": {
            t: n for t, n in sorted(amp_by_technique.items()) if t not in observed
        },
        "not_observed": not_observed,
        # What the counts leave out, carried in the document and not only in the
        # rendered text, because a programmatic consumer reads this one.
        #
        # An attributed count is what the arm touched *and an empty-script control
        # did not*, so it omits everything a collector and an idle browser both do
        # -- which is exactly where ambient-property fingerprinting lives. Measured
        # 2026-08-08: the driven Kasada client provably reads `navigator.userAgent`
        # and that read is absent from its 29 attributed names, while Shape's 1,036
        # survives almost intact because enumerating 911 `window` interfaces is not
        # something a blank page does. The loss is proportional to how ordinary the
        # collector's behaviour looks.
        "script_attribution_comparable": script_attribution_comparable,
        "attribution_caveat": (
            (
                "shared names use current-script count deltas when both arms are "
                "comparable; absence of a name is still not evidence the script "
                "did not touch it"
            )
            if script_attribution_comparable is True
            else (
                "attributed counts exclude anything an empty-script control also "
                "did; absence of a name is not evidence the script did not touch it"
            )
        )
        if attributed
        else None,
        "non_claims": [
            "a technique appearing here means the API was called in a lab rehost",
            "call presence is not proof the value reached any network request",
            "not an acceptance, bypass, evasion, or bot-score claim",
        ],
    }
    raw_identity = document.get("script_identity")
    if (
        isinstance(raw_identity, dict)
        and document.get("schema") == OBSERVATION_SCHEMA
    ):
        _, identity, _, _ = _reconciled_script_identity(
            document, current_required=True
        )
    elif (
        isinstance(raw_identity, dict)
        and document.get("schema") == SUBTRACTION_SCHEMA
    ):
        identity = _reconciled_subtraction_script_identity(document)
    else:
        identity = raw_identity
    vendor_hint = (
        identity.get("vendor_hint")
        if isinstance(identity, dict)
        else document.get("vendor_hint")
    )
    looks_built = (
        identity.get("looks_like_built_antibot_script")
        if isinstance(identity, dict)
        else document.get("looks_like_built_antibot_script")
    )
    safe_vendor_hint = project_product_script_vendor_hint(vendor_hint)
    if looks_built is True and (
        analysis_boundary := project_product_script_analysis_boundary(safe_vendor_hint)
    ):
        result["analysis_boundary"] = analysis_boundary

    # A raw surface is not attributable to the script and must not be read as if
    # it were. Measured 2026-08-06: the `chromium-internal` technique (Mojo IPC)
    # shows 7 names / 236 calls on a Marriott SBSD raw surface, and *identically*
    # on the empty-script control -- it survives control subtraction in zero of
    # 35 subtraction artifacts. It is renderer-internal IPC that the broad
    # binding category traces regardless of page script. Reading the raw digest
    # alone would support the false claim "this collector probes Mojo".
    #
    # This warning exists because that near-miss happened to the author of this
    # module while writing it.
    if not attributed:
        result["attribution_warning"] = RAW_ATTRIBUTION_WARNING
        internal = result["techniques"].get("chromium-internal")
        if internal:
            result["known_control_noise"] = {
                "chromium-internal": internal["api_names"],
                "note": "measured identical in the empty-script control",
            }
    else:
        clean_subtraction = document.get("clean_subtraction", False)
        if not isinstance(clean_subtraction, bool):
            raise ContractError("clean_subtraction must be a boolean")
        result["clean_subtraction"] = clean_subtraction
        result["surface_claim_ready"] = _subtraction_claim_ready(document)
        if (
            "input_method_comparable" in document
            or "ambient_input_clean" in document
            or (
                "surface_claim_ready" in document
                and any(
                    field in document
                    for field in (
                        "arm_input_profile",
                        "control_input_profile",
                        "arm_input_probe",
                        "control_input_probe",
                        "arm_ambient_input",
                        "control_ambient_input",
                    )
                )
            )
        ):
            result["input_claim_receipts_coherent"] = (
                _saved_input_claim_receipts_coherent(document)
            )
        if (
            "rehost_dependencies_complete" in document
            or "unserved_requests" in document
        ):
            result["rehost_dependency_receipts_coherent"] = (
                _saved_rehost_dependency_receipts_coherent(document)
            )
        if "offline_guard_comparable" in document or (
            "surface_claim_ready" in document
            and ("arm_offline_guard" in document or "control_offline_guard" in document)
        ):
            result["offline_guard_receipts_coherent"] = (
                _saved_offline_guard_receipts_coherent(document)
            )
        if any(
            field in document
            for field in (
                "arm_observation_receipt_sha256",
                "control_observation_receipt_sha256",
                "input_observation_receipts_complete",
                "input_observation_receipts_comparable",
            )
        ):
            result["observation_lineage_receipts_coherent"] = (
                _saved_observation_lineage_receipts_coherent(document)
            )
        if any(
            field in document
            for field in (
                "collector_startup",
                "collector_startup_coherent",
                "control_collector_startup",
                "control_collector_startup_coherent",
                "startup_derivation_coherent",
            )
        ):
            result["startup_receipts_coherent"] = _saved_startup_receipts_coherent(
                document
            )
        if (
            "arm_control_method_comparable" in document
            or "arm_control_method_mismatches" in document
        ):
            result["method_mismatch_verdict_coherent"] = (
                _saved_method_mismatch_verdict_coherent(document)
            )
        if any(
            field in document
            for field in (
                "script_identity",
                "control_script_identity",
                "control_script_sha256_16",
            )
        ):
            result["script_identity_receipts_coherent"] = (
                _saved_script_identity_receipts_coherent(document)
            )
        if "driver_execution_complete" in document:
            result["driver_execution_receipts_coherent"] = (
                _saved_subtraction_driver_execution_receipts_coherent(document)
            )
        if any(
            field in document
            for field in (
                "arm_browser_shutdown",
                "control_browser_shutdown",
                "arm_trace_flush",
                "control_trace_flush",
                "arm_trace_evidence",
                "control_trace_evidence",
                "trace_evidence_coherent",
            )
        ):
            result["trace_evidence_receipts_coherent"] = (
                _saved_subtraction_trace_receipts_coherent(document)
            )
        if any(
            field in document
            for field in (
                "arm_page_load_execution",
                "control_page_load_execution",
                "page_load_execution_coherent",
            )
        ):
            result["page_load_receipts_coherent"] = (
                _saved_subtraction_page_load_receipts_coherent(document)
            )
        if any(
            field in document
            for field in ("arm_ready_expression", "control_ready_expression")
        ):
            result["ready_probe_receipts_coherent"] = (
                _saved_subtraction_ready_probe_receipts_coherent(document)
            )
        if any(
            field in document
            for field in (
                "arm_await_ready_seconds",
                "arm_ready_expression",
                "control_ready_expression",
                "arm_await_report",
                "control_await_report",
            )
        ):
            result["await_receipts_coherent"] = (
                _saved_subtraction_await_receipts_coherent(document)
            )
        if "request_activity" in document:
            result["request_activity_receipts_valid"] = (
                _saved_request_activity_receipts_valid(document)
            )
        if (
            isinstance(document.get("resource_intents"), dict)
            and (
                "non_claim" in document["resource_intents"]
                or document.get("subtraction_receipt_sha256") is not None
            )
        ):
            result["resource_intent_receipts_valid"] = (
                _saved_resource_intent_receipts_valid(document)
            )
        if "subtraction_receipt_sha256" in document:
            result["subtraction_receipt_coherent"] = (
                _saved_current_subtraction_receipt_coherent(document)
            )
        # An attributed surface of zero is never the finding it looks like.
        # `clean_subtraction: true` with nothing in `only_in_arm` means the arm's
        # API set was *identical* to the empty-script control — so either the
        # script never executed, or it is not a collector. "This collector
        # collects nothing" is not an available reading.
        #
        # Measured 2026-08-06: pin `2123c79ff05a9f72` (126 KB, provenance
        # VERIFIED) produced arm and control totals matching exactly at 3,272
        # events and 179 API names, zero introduced, zero elevated. Its identity
        # signals show `bmak_literals: 0` and no vendor hint, unlike every real
        # collector in the corpus at 400–550 KB. Left unflagged it entered a
        # profile table as a sixth configuration.
        if not counts:
            result["empty_surface_warning"] = EMPTY_SURFACE_WARNING

    analysis = document.get("analysis")
    script_execution_value = (
        analysis.get("script_execution") if isinstance(analysis, dict) else None
    )
    if script_execution_value is None and attributed:
        script_execution_value = document.get("arm_script_execution")
    if (
        script_execution := _sanitize_script_execution_summary(
            script_execution_value, label="observation digest"
        )
    ) is not None:
        result["script_execution"] = script_execution
    if (
        attributed
        and (
            control_script_execution := _sanitize_script_execution_summary(
                document.get("control_script_execution"),
                label="observation digest control",
            )
        )
        is not None
    ):
        result["control_script_execution"] = control_script_execution

    collector_startup = document.get("collector_startup")
    if isinstance(collector_startup, dict):
        result["collector_startup"] = _sanitize_startup_document(collector_startup)

    resource_intents = _resource_intent_view(document)
    if resource_intents is not None:
        result["resource_intents"] = resource_intents
    request_activity = _request_activity_view(document)
    if request_activity is not None:
        result["request_activity"] = request_activity
    input_delivery = _input_delivery_view(document)
    if input_delivery is not None:
        result["input_delivery"] = input_delivery

    if focus is not None:
        focused = sorted(n for n in counts if technique_of(n) == focus)
        result["focus"] = {
            "technique": focus,
            "api_names": focused,
            "count": len(focused),
        }
    return result


def _hosts_of(document: dict[str, Any]) -> list[str]:
    provenance = _sanitize_capture_provenance(document.get("provenance"))
    return sorted(provenance.get("recorded_hosts") or [])


def _public_source_identity(document: dict[str, Any]) -> dict[str, str] | None:
    """Return a verified public-source hostname + digest, never a deployment claim."""
    source = _sanitize_source_provenance(document.get("source_provenance"))
    if source.get("status") != "verified_digest":
        return None
    url = (source.get("source_url_shape") or {}).get("origin")
    digest = source.get("sha256")
    if (
        not isinstance(url, str)
        or not isinstance(digest, str)
        or len(digest) != 64
        or any(character not in "0123456789abcdefABCDEF" for character in digest)
    ):
        return None
    try:
        parsed = urlsplit(url)
    except (UnicodeError, ValueError):
        return None
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
    ):
        return None
    return {"hostname": parsed.hostname.lower(), "sha256": digest.lower()}


# Measured gate boundary: one Akamai BM web build runs a 16-name DeviceMotion
# module below roughly this viewport height, and not above it. Used only to decide
# whether two arms are comparable -- never to make a claim about a collector.
VIEWPORT_HEIGHT_FLOOR = 115


def _viewport_of(document: dict[str, Any]) -> dict[str, Any] | None:
    """Viewport reading from an observation (`viewport`) or subtraction (`arm_viewport`)."""
    return _batch_method(document).get("arm_viewport")


def _launch_mode_of(document: dict[str, Any]) -> bool | None:
    """``True`` headed, ``False`` headless, ``None`` when the arm did not record it.

    Reads ``headed`` on an observation and ``arm_headed`` on a subtraction. Older
    subtractions predate the field and return ``None``, which is treated as
    unknown rather than as agreement — a missing value must not manufacture a
    clean comparison.
    """
    value = _batch_method(document).get("arm_headed")
    return value if isinstance(value, bool) else None


def _comparability(
    left: dict[str, Any],
    right: dict[str, Any],
    *,
    vary_method_axes: tuple[str, ...] = (),
) -> dict[str, Any]:
    """Say whether two arms are the same *kind* of thing before differencing them.

    Two rolls of one deployment and two different deployments produce the same
    shaped diff, and the interesting number (how much moved) means opposite things
    in each case: small movement between rolls is stability, small movement across
    deployments is similarity of configuration. Note 144 measured cross-roll
    Jaccard at 0.987-0.994 and cross-site at 0.742-0.753 for exactly this reason.

    Launch mode is checked for the same reason and it is not hypothetical.
    Measured 2026-08-06: of four pins observed both headed and headless, **two
    produced different surfaces** -- `1e88274539a68be0` reads 101 API names headed
    and 117 headless, the difference being the entire 16-name DeviceMotion block,
    because the trace records calls rather than code and the block is
    conditionally executed. A whole "configuration ladder" was published off a
    corpus that mixed the two modes before the control was run.

    This does not block anything. It reports what is known so an inference made on
    one population is not silently carried to another.
    """
    left_hosts, right_hosts = _hosts_of(left), _hosts_of(right)
    left_source = _public_source_identity(left)
    right_source = _public_source_identity(right)
    left_attributed = left.get("schema") == SUBTRACTION_SCHEMA
    right_attributed = right.get("schema") == SUBTRACTION_SCHEMA
    left_claim_ready = _subtraction_claim_ready(left) if left_attributed else None
    right_claim_ready = _subtraction_claim_ready(right) if right_attributed else None
    left_mode, right_mode = _launch_mode_of(left), _launch_mode_of(right)
    left_method, right_method = _batch_method(left), _batch_method(right)
    method_mismatches = {
        field: {"left": left_method[field], "right": right_method[field]}
        for field in SURFACE_METHOD_FIELDS
        if left_method[field] != right_method[field]
    }

    unknown_axes = sorted(set(vary_method_axes) - set(CONTROL_METHOD_AXES))
    if unknown_axes:
        raise ContractError(
            f"unknown method-control axes {unknown_axes}; known: "
            f"{', '.join(CONTROL_METHOD_AXES)}"
        )
    expected_fields = {f"arm_{axis}" for axis in vary_method_axes}
    unchanged_declared = sorted(expected_fields - set(method_mismatches))
    if unchanged_declared:
        raise ContractError(
            "declared method-control axes do not differ: "
            + ", ".join(field.removeprefix("arm_") for field in unchanged_declared)
        )
    expected_mismatches = {
        field: values
        for field, values in method_mismatches.items()
        if field in expected_fields
    }
    unexpected_mismatches = {
        field: values
        for field, values in method_mismatches.items()
        if field not in expected_fields
    }

    warnings: list[str] = []
    if left_claim_ready is False or right_claim_ready is False:
        sides = ", ".join(
            side
            for side, ready in (("left", left_claim_ready), ("right", right_claim_ready))
            if ready is False
        )
        warnings.append(
            f"{sides} subtraction surface is not claim-ready; the set difference "
            "is descriptive and cannot support a collector absence claim"
        )
    if not left_attributed or not right_attributed:
        warnings.append(
            "at least one raw surface includes browser and host work that cannot "
            "be attributed to the script"
        )
    viewport_crosses_gate = False

    # Geometry, for the same reason as launch mode and with a sharper threshold.
    # Measured 2026-08-06 on one Akamai BM web build: a 16-name DeviceMotion module
    # executes when viewport height falls below roughly 115 px, and `800x1` opens it
    # while `1x600` does not -- height only, width irrelevant. Two arms differing in
    # viewport height across that boundary are not comparable for that module.
    left_vp, right_vp = _viewport_of(left), _viewport_of(right)
    viewport_values_differ = bool(
        left_vp is not None and right_vp is not None and left_vp != right_vp
    )
    if left_vp is not None and right_vp is not None:
        lh, rh = left_vp.get("inner_height"), right_vp.get("inner_height")
        if isinstance(lh, int) and isinstance(rh, int):
            small = VIEWPORT_HEIGHT_FLOOR
            viewport_crosses_gate = (lh < small) != (rh < small)
            if viewport_crosses_gate and "arm_viewport" not in expected_fields:
                warnings.append(
                    f"viewport height differs across the measured gate boundary "
                    f"({lh} px vs {rh} px; a collector build was observed running a "
                    f"16-name module below ~{small} px). Re-run both arms at the same "
                    "geometry before attributing this difference to the scripts"
                )

    if (
        left_mode is not None
        and right_mode is not None
        and left_mode != right_mode
        and "arm_headed" not in expected_fields
    ):
        warnings.append(
            f"launch mode differs ({'headed' if left_mode else 'headless'} vs "
            f"{'headed' if right_mode else 'headless'}). Measured: 2 of 4 pins "
            "checked in both modes produced different surfaces, the whole "
            "DeviceMotion block appearing only headless. Re-run both arms in one "
            "mode before attributing this difference to the scripts"
        )

    if left_hosts and right_hosts and left_hosts != right_hosts:
        status = "cross-origin"
        note = (
            f"{', '.join(left_hosts)} vs {', '.join(right_hosts)} - this is a "
            "cross-deployment comparison, not a cross-roll one; do not carry a "
            "marker established on one deployment to the other"
        )
    elif left_hosts and right_hosts:
        status = "same-origin"
        note = f"both arms recorded from {', '.join(left_hosts)}"
    elif left_source and right_source:
        if left_source["hostname"] != right_source["hostname"]:
            status = "cross-origin"
            note = (
                f"verified public sources use {left_source['hostname']} vs "
                f"{right_source['hostname']}; this crosses source populations"
            )
        elif left_source["sha256"] == right_source["sha256"]:
            status = "same-source"
            note = (
                f"both arms bind the same verified public source from "
                f"{left_source['hostname']} at pin {left_source['sha256'][:16]}; "
                "this identifies source bytes, not a protected deployment"
            )
        else:
            status = "same-source-origin"
            note = (
                f"both arms bind verified public sources from "
                f"{left_source['hostname']}, at different exact pins; this is a "
                "source-roll comparison, not deployment provenance"
            )
    else:
        status = "unknown"
        note = (
            "at least one arm has no recorded origin, so whether this compares two "
            "rolls or two deployments is unknown; re-run with --captures-root"
        )

    if warnings:
        status = "not-comparable" if status != "cross-origin" else status
        note = f"{note}. " + " ".join(warnings)
    if expected_mismatches:
        if not warnings and status != "cross-origin" and not unexpected_mismatches:
            status = "method-control"
        note = (
            f"{note}. Intentional method control on "
            + ", ".join(field.removeprefix("arm_") for field in expected_mismatches)
            + "; attribute differences to this method axis, not to script bytes"
        )
    if unexpected_mismatches:
        if status != "cross-origin":
            status = "not-comparable"
        note = (
            f"{note}. Unexpected execution method differences on "
            + ", ".join(field.removeprefix("arm_") for field in unexpected_mismatches)
            + "; re-run with one method before attributing the diff to scripts"
        )

    return {
        "status": status,
        "note": note,
        "left_hosts": left_hosts,
        "right_hosts": right_hosts,
        "left_public_source": left_source,
        "right_public_source": right_source,
        "left_claim_ready": left_claim_ready,
        "right_claim_ready": right_claim_ready,
        "attribution_kinds_differ": left_attributed != right_attributed,
        "raw_surfaces_involved": not left_attributed or not right_attributed,
        "left_headed": left_mode,
        "right_headed": right_mode,
        "launch_mode_differs": bool(
            left_mode is not None and right_mode is not None and left_mode != right_mode
        ),
        # Historical field meaning: the measured responsive gate is crossed,
        # not merely that two exact viewport dictionaries differ. Keep it for
        # schema compatibility, but give new consumers unambiguous fields.
        "viewport_differs": viewport_crosses_gate,
        "viewport_values_differ": viewport_values_differ,
        "viewport_crosses_responsive_gate": viewport_crosses_gate,
        "method_differs": bool(method_mismatches),
        "method_mismatches": method_mismatches,
        "controlled_method_comparison": bool(expected_mismatches)
        and not unexpected_mismatches
        and not warnings
        and status != "cross-origin",
        "expected_method_mismatches": expected_mismatches,
        "unexpected_method_mismatches": unexpected_mismatches,
        "left_viewport": left_vp,
        "right_viewport": right_vp,
    }


def diff_digests(
    left: dict[str, Any],
    right: dict[str, Any],
    *,
    focus: str | None = None,
    vary_method_axes: tuple[str, ...] = (),
) -> dict[str, Any]:
    """Compare two surfaces at technique level, bounded by construction.

    Answers the question this tool was repeatedly asked by hand: *what does one
    collector do that the other does not?* Set arithmetic is reported per
    technique so a 28-name difference reads as "Marriott's SBSD builds a GainNode
    and reads AudioNode topology" rather than as 28 unsorted strings.
    """
    if not isinstance(left, dict) or not isinstance(right, dict):
        raise ContractError("digest diff inputs must be objects")
    focus = _validated_focus(focus)
    if (
        type(vary_method_axes) is not tuple
        or len(vary_method_axes) > len(CONTROL_METHOD_AXES)
        or any(not isinstance(axis, str) for axis in vary_method_axes)
        or len(set(vary_method_axes)) != len(vary_method_axes)
    ):
        raise ContractError("method-control axes must be a unique bounded tuple")
    lc, rc = _api_names(left), _api_names(right)
    ln, rn = set(lc), set(rc)
    only_left, only_right, shared = ln - rn, rn - ln, ln & rn
    union = ln | rn
    jaccard = (len(shared) / len(union)) if union else 0.0

    per_technique: dict[str, dict[str, int]] = {}
    for name in union:
        tech = technique_of(name)
        row = per_technique.setdefault(
            tech, {"only_left": 0, "only_right": 0, "shared": 0}
        )
        if name in only_left:
            row["only_left"] += 1
        elif name in only_right:
            row["only_right"] += 1
        else:
            row["shared"] += 1

    # Only techniques that actually differ are worth the reader's context.
    differing = {
        t: r for t, r in per_technique.items() if r["only_left"] or r["only_right"]
    }

    # Comparing two rolls of one deployment and comparing two deployments are
    # different questions, and the diff looks identical either way. Measured
    # 2026-08-06: a marker established across Marriott rolls
    # (`Window.XMLHttpRequest` disappearing) was carried over to FedEx responses
    # and produced a false ordering claim. The tool now knows each arm's recorded
    # origin, so it can at least say when a comparison crosses populations.
    comparability = _comparability(left, right, vary_method_axes=vary_method_axes)

    left_intents = _resource_intent_view(left, limit=128)
    right_intents = _resource_intent_view(right, limit=128)
    resource_diff: dict[str, Any] | None = None
    if left_intents is not None or right_intents is not None:
        left_rows = {
            _resource_row_key(row): row for row in (left_intents or {}).get("rows", [])
        }
        right_rows = {
            _resource_row_key(row): row for row in (right_intents or {}).get("rows", [])
        }
        only_left_keys = sorted(set(left_rows) - set(right_rows))
        only_right_keys = sorted(set(right_rows) - set(left_rows))
        shared_keys = set(left_rows) & set(right_rows)
        same_attribution = (
            left_intents is not None
            and right_intents is not None
            and left_intents["attributed"] == right_intents["attributed"]
        )
        both_ok = (
            left_intents is not None
            and right_intents is not None
            and left_intents["status"] == "ok"
            and right_intents["status"] == "ok"
        )
        resource_diff = {
            "left_status": (left_intents or {}).get("status", "missing"),
            "right_status": (right_intents or {}).get("status", "missing"),
            "left_row_kind": (left_intents or {}).get("row_kind", "missing"),
            "right_row_kind": (right_intents or {}).get("row_kind", "missing"),
            "comparable": bool(both_ok and same_attribution),
            "shared": len(shared_keys),
            "only_left": len(only_left_keys),
            "only_right": len(only_right_keys),
            "only_left_rows": [
                left_rows[key] for key in only_left_keys[:RESOURCE_INTENT_ROWS_LIMIT]
            ],
            "only_right_rows": [
                right_rows[key] for key in only_right_keys[:RESOURCE_INTENT_ROWS_LIMIT]
            ],
            "only_left_omitted": max(
                0, len(only_left_keys) - RESOURCE_INTENT_ROWS_LIMIT
            ),
            "only_right_omitted": max(
                0, len(only_right_keys) - RESOURCE_INTENT_ROWS_LIMIT
            ),
            "non_claim": (
                "DOM attributes present at capture time; not proof that a request "
                "was sent, reached DNS, or received a response"
            ),
        }

    left_requests = _request_activity_view(left, limit=128)
    right_requests = _request_activity_view(right, limit=128)
    request_diff: dict[str, Any] | None = None
    if left_requests is not None or right_requests is not None:
        left_rows = {
            _request_shape_key(row): row
            for row in (left_requests or {}).get("rows", [])
        }
        right_rows = {
            _request_shape_key(row): row
            for row in (right_requests or {}).get("rows", [])
        }
        only_left_keys = sorted(set(left_rows) - set(right_rows))
        only_right_keys = sorted(set(right_rows) - set(left_rows))
        shared_keys = sorted(set(left_rows) & set(right_rows))
        metric_keys = (
            "count",
            "body_bytes_total",
            "body_bytes_min",
            "body_bytes_max",
            "body_sha256_16_counts",
        )
        changed_keys = [
            key
            for key in shared_keys
            if tuple(left_rows[key].get(metric) for metric in metric_keys)
            != tuple(right_rows[key].get(metric) for metric in metric_keys)
        ]
        same_attribution = (
            left_requests is not None
            and right_requests is not None
            and left_requests["attributed"] == right_requests["attributed"]
        )
        both_ok = (
            left_requests is not None
            and right_requests is not None
            and left_requests["status"] == "ok"
            and right_requests["status"] == "ok"
        )
        request_diff = {
            "left_status": (left_requests or {}).get("status", "missing"),
            "right_status": (right_requests or {}).get("status", "missing"),
            "left_row_kind": (left_requests or {}).get("row_kind", "missing"),
            "right_row_kind": (right_requests or {}).get("row_kind", "missing"),
            "comparable": bool(both_ok and same_attribution),
            "shared_shapes": len(shared_keys),
            "only_left": len(only_left_keys),
            "only_right": len(only_right_keys),
            "changed": len(changed_keys),
            "only_left_rows": [
                left_rows[key] for key in only_left_keys[:RESOURCE_INTENT_ROWS_LIMIT]
            ],
            "only_right_rows": [
                right_rows[key] for key in only_right_keys[:RESOURCE_INTENT_ROWS_LIMIT]
            ],
            "changed_rows": [
                {
                    "shape": left_rows[key],
                    "left": left_rows[key],
                    "right": right_rows[key],
                }
                for key in changed_keys[:RESOURCE_INTENT_ROWS_LIMIT]
            ],
            "rows_omitted": (
                max(0, len(only_left_keys) - RESOURCE_INTENT_ROWS_LIMIT)
                + max(0, len(only_right_keys) - RESOURCE_INTENT_ROWS_LIMIT)
                + max(0, len(changed_keys) - RESOURCE_INTENT_ROWS_LIMIT)
            ),
            "non_claim": (
                "loopback requests that reached the rehost; external requests "
                "blocked before connection are invisible, and post-ack is a "
                "synthetic lab response"
            ),
        }

    left_delivery = _input_delivery_view(left)
    right_delivery = _input_delivery_view(right)
    profile_control = comparability.get("expected_method_mismatches", {}).get(
        "arm_input_profile"
    )
    if comparability.get("controlled_method_comparison") and isinstance(
        profile_control, dict
    ):
        # A clean ``none`` profile deliberately has no command receipt, so
        # _input_delivery_view returns None.  In a declared input-profile
        # control, describe that as the experimental control instead of making
        # it sound like lost evidence.  This is not a claim that absence of
        # human input was proven; it only states the recorded method.
        no_input = {
            "profile": "none",
            "intentional_no_input": True,
            "verified": None,
            "note": (
                "recorded method requests no synthetic input; this is the "
                "declared control arm, not a missing delivery receipt"
            ),
        }
        if left_delivery is None and profile_control.get("left") == "none":
            left_delivery = dict(no_input)
        if right_delivery is None and profile_control.get("right") == "none":
            right_delivery = dict(no_input)
    input_delivery_diff = (
        {"left": left_delivery, "right": right_delivery}
        if left_delivery is not None or right_delivery is not None
        else None
    )

    result: dict[str, Any] = {
        "schema": DIFF_SCHEMA,
        "left_label": _label_of(left),
        "right_label": _label_of(right),
        "left_pin": _pin_of(left),
        "right_pin": _pin_of(right),
        "comparability": comparability,
        "left_api_names": len(ln),
        "right_api_names": len(rn),
        "shared": len(shared),
        "only_left": len(only_left),
        "only_right": len(only_right),
        "jaccard": round(jaccard, 4),
        "techniques_differing": dict(
            sorted(
                differing.items(),
                key=lambda kv: (-(kv[1]["only_left"] + kv[1]["only_right"]), kv[0]),
            )
        ),
        "identical_surface": not only_left and not only_right,
        "non_claims": [
            "surface difference between two arms is not by itself vendor intent",
            "compare against measured roll drift before calling a difference real",
            "not an acceptance, bypass, evasion, or bot-score claim",
        ],
    }
    if resource_diff is not None:
        result["resource_intents"] = resource_diff
    if request_diff is not None:
        result["request_activity"] = request_diff
    if input_delivery_diff is not None:
        result["input_delivery"] = input_delivery_diff
    if focus is not None:
        result["focus"] = {
            "technique": focus,
            "only_left": sorted(n for n in only_left if technique_of(n) == focus),
            "only_right": sorted(n for n in only_right if technique_of(n) == focus),
        }
    return result


CORPUS_SCHEMA = "browser-core.product-script-corpus/1"
CLAIM_SCHEMA = "browser-core.product-script-absence-claim/1"
UNPARSEABLE_JSON_SCHEMA = "browser-core.unparseable-json/1"

# Techniques an offline rehost cannot observe, and why.
#
# This table is the whole point of the claim checker. Absence of evidence and
# evidence of absence are different, and the difference is not visible in the
# data -- it lives in how the observation was produced. An agent reading a digest
# sees an empty cell either way.
#
# Measured 2026-08-06 while writing note 145: the corpus shows zero
# `input-behaviour` names across all 35 arms, which reads exactly like the
# genuine `webrtc` and `crypto` negatives sitting beside it. It is not the same
# finding, and stating it as one would be wrong.
METHOD_BLIND: dict[str, str] = {
    "input-behaviour": (
        "an offline rehost has no operator, so mouse/key/touch/pointer events are "
        "never delivered and their interfaces never fire. Listener *registration* "
        "is traced as api.EventTarget.addEventListener but the host page uses it "
        "heavily too, so it cancels in control subtraction. Absence here is a "
        "property of the method, not of the collector"
    ),
}

# Techniques whose absence is observable but weakened by the offline guard.
METHOD_LIMITED: dict[str, str] = {
    "network-transport": (
        "the loopback-only resolver guard blocks real requests, so a transport "
        "that only manifests against a reachable origin would not appear. "
        "Constructor and URL-building calls are still visible"
    ),
    "media-devices": (
        "device enumeration returns an empty set without granted permissions, so "
        "a collector that bails out early on an empty list may under-report"
    ),
}

MIN_ARMS_FOR_ABSENCE = 3


def _absence_decision(
    technique: str,
    checked: int,
    present_count: int,
    failed_count: int,
    unready_count: int,
    unparseable_count: int,
    mixed_axes: list[str],
) -> tuple[str, str]:
    if present_count:
        return "REFUTED", f"{technique} appears in {present_count} of {checked} attributed arms"
    if unparseable_count:
        other = (
            (f", {failed_count} arm(s) produced no data" if failed_count else "")
            + (f", and {unready_count} arm(s) were not claim-ready" if unready_count else "")
        )
        return (
            "UNVERIFIABLE",
            f"absent in {checked} attributed arms, but {unparseable_count} unreadable "
            f"JSON file(s) could not be classified{other}; an unreadable file "
            "cannot supply a negative observation",
        )
    if failed_count and unready_count:
        return (
            "UNVERIFIABLE",
            f"absent in {checked} attributed arms, but {failed_count} arm(s) "
            f"produced no data and {unready_count} arm(s) were not claim-ready; "
            "neither supplies a negative observation",
        )
    if failed_count:
        return (
            "UNVERIFIABLE",
            f"absent in {checked} attributed arms, but {failed_count} arm(s) "
            "produced no data; a failed arm is not a negative observation",
        )
    if unready_count:
        return (
            "UNVERIFIABLE",
            f"absent in {checked} attributed arms, but {unready_count} arm(s) "
            "were not claim-ready; an unready arm is not a negative observation",
        )
    if blind_reason := METHOD_BLIND.get(technique):
        return "UNVERIFIABLE", f"absent in all {checked} arms, but {blind_reason}"
    if mixed_axes:
        return (
            "UNVERIFIABLE",
            f"absent in all {checked} arms, but the arms differ on execution method "
            f"axes {', '.join(mixed_axes)}; re-run one method "
            "before treating the negative as a product finding",
        )
    if checked < MIN_ARMS_FOR_ABSENCE:
        return (
            "UNVERIFIABLE",
            f"only {checked} attributed arm(s); an absence claim needs at least "
            f"{MIN_ARMS_FOR_ABSENCE} to distinguish a real negative from one "
            "unlucky capture",
        )
    return (
        "SUPPORTED",
        f"absent in all {checked} attributed arms, and the method can observe "
        f"this technique",
    )


def check_absence_claim(
    documents: list[tuple[str, dict[str, Any]]], technique: str
) -> dict[str, Any]:
    """Test the claim "this collector does not use <technique>" against a corpus.

    Wrong claims, not missing data, are the failure mode this tool exists to
    prevent -- an agent's output is prose, and prose asserting a negative is the
    easiest thing in the world to get wrong from a digest full of empty cells.

    Three verdicts, and the third is the one worth having:

    ``REFUTED``       the technique appears in at least one attributed arm.
    ``SUPPORTED``     absent across enough attributed arms, and the method could
                      have seen it.
    ``UNVERIFIABLE``  absent, but the method is structurally incapable of
                      observing it, so the absence says nothing. Returning
                      SUPPORTED here would launder a limitation into a finding.

    Raw surfaces are rejected outright rather than counted: an absence claim
    checked against unattributed data is not weak evidence, it is the wrong
    evidence.
    """
    if not isinstance(technique, str) or (
        technique not in TECHNIQUES and technique != "unclassified"
    ):
        raise ContractError(
            f"unknown technique; known: {', '.join(sorted(TECHNIQUES))}"
        )

    entries = _validated_document_population(
        documents, population="absence-claim", require_nonempty=True
    )
    attributed: list[tuple[str, dict[str, Any], dict[str, Any]]] = []
    rejected_raw: list[str] = []
    failed_arms: list[str] = []
    unready_arms: list[str] = []
    unparseable_files: list[str] = []
    for label, document in entries:
        schema = document.get("schema")
        if schema == UNPARSEABLE_JSON_SCHEMA:
            unparseable_files.append(label)
        elif "error" in document and document.get("error") is not None:
            failed_arms.append(label)
        elif schema == SUBTRACTION_SCHEMA:
            try:
                digest = digest_observation(document)
            except ContractError:
                # A broken arm supplied no usable surface. It must weaken a
                # negative claim rather than disappear from the denominator.
                failed_arms.append(label)
            else:
                if digest["surface_claim_ready"] is False:
                    unready_arms.append(label)
                else:
                    attributed.append((label, document, digest))
        elif schema == OBSERVATION_SCHEMA:
            rejected_raw.append(label)
        else:
            failed_arms.append(label)

    method_population = _method_population(
        [(label, document) for label, document, _digest in attributed]
    )

    present_in: list[dict[str, Any]] = []
    checked = 0
    for label, _document, digest in attributed:
        row = digest["techniques"].get(technique)
        amplified = digest.get("amplified_only_techniques", {}).get(technique, 0) + (
            row["amplified"] if row else 0
        )
        introduced = row["api_names"] if row else 0
        checked += 1
        if introduced or amplified:
            present_in.append(
                {"label": label, "introduced": introduced, "amplified": amplified}
            )

    blind_reason = METHOD_BLIND.get(technique)
    limited_reason = METHOD_LIMITED.get(technique)

    verdict, rationale = _absence_decision(
        technique, checked, len(present_in), len(failed_arms), len(unready_arms),
        len(unparseable_files),
        method_population["mixed_axes"],
    )

    result: dict[str, Any] = {
        "schema": CLAIM_SCHEMA,
        "claim": f"the collector does not use {technique}",
        "technique": technique,
        "verdict": verdict,
        "rationale": rationale,
        "attributed_arms_checked": checked,
        "present_in": present_in,
        "raw_surfaces_rejected": rejected_raw,
        "failed_arms": failed_arms,
        "unready_arms": unready_arms,
        "unparseable_files": unparseable_files,
        "method_population": method_population,
        "method_blind": bool(blind_reason),
        "method_limited": limited_reason,
        "non_claims": [
            "SUPPORTED means absent from this corpus under this method, not absent "
            "from the product",
            "not an acceptance, bypass, evasion, or bot-score claim",
        ],
    }
    return result


def _validate_rendered_claim(result: dict[str, Any]) -> None:
    """Reconcile an unsigned saved verdict before presenting it as prose."""
    technique = result.get("technique")
    checked = result.get("attributed_arms_checked")
    present = result.get("present_in")
    failed = result.get("failed_arms")
    unready = result.get("unready_arms", [])
    unparseable = result.get("unparseable_files", [])
    raw = result.get("raw_surfaces_rejected")
    if (
        type(technique) is not str
        or (technique not in TECHNIQUES and technique != "unclassified")
        or type(checked) is not int
        or not 0 <= checked <= MAX_CORPUS_ARMS
        or type(present) is not list
        or len(present) > checked
        or type(failed) is not list
        or type(unready) is not list
        or type(unparseable) is not list
        or type(raw) is not list
        or checked + len(failed) + len(unready) + len(unparseable) + len(raw)
        > MAX_CORPUS_ARMS
    ):
        raise ContractError("rendered claim structure is invalid")
    labels: list[str] = []
    for row in present:
        if type(row) is not dict or set(row) != {"label", "introduced", "amplified"}:
            raise ContractError("rendered claim presence is invalid")
        label = _bounded_text(
            row["label"], maximum=MAX_CORPUS_LABEL_BYTES, label="rendered claim label"
        )
        introduced, amplified = row["introduced"], row["amplified"]
        if (
            type(introduced) is not int
            or type(amplified) is not int
            or not 0 <= introduced <= MAX_API_SURFACE_ENTRIES
            or not 0 <= amplified <= MAX_API_SURFACE_ENTRIES
            or introduced + amplified == 0
        ):
            raise ContractError("rendered claim presence is invalid")
        labels.append(label)
    for group in (failed, unready, unparseable, raw):
        for label in group:
            labels.append(_bounded_text(
                label, maximum=MAX_CORPUS_LABEL_BYTES, label="rendered claim label"
            ))
    if len(labels) != len(set(labels)):
        raise ContractError("rendered claim labels are duplicated")
    population = result.get("method_population")
    try:
        _validate_rendered_corpus_method_population(population, checked)
    except ContractError:
        raise ContractError("rendered claim method population is invalid") from None
    mixed_axes = population["mixed_axes"]
    expected_verdict, expected_rationale = _absence_decision(
        technique, checked, len(present), len(failed), len(unready),
        len(unparseable), mixed_axes,
    )
    if (
        result.get("claim") != f"the collector does not use {technique}"
        or result.get("verdict") != expected_verdict
        or result.get("rationale") != expected_rationale
        or result.get("method_blind") is not bool(METHOD_BLIND.get(technique))
        or result.get("method_limited") != METHOD_LIMITED.get(technique)
    ):
        raise ContractError("rendered claim verdict is inconsistent")


@_normalize_renderer_failures("claim")
def render_claim(result: dict[str, Any]) -> str:
    """Render an absence-claim verdict as short text."""
    if not isinstance(result, dict):
        raise ContractError("rendered claim input must be an object")
    if result.get("schema") != CLAIM_SCHEMA:
        raise ContractError("rendered claim schema is invalid")
    _validate_rendered_claim(result)
    out = [
        f"CLAIM    {result['claim']}",
        f"VERDICT  {result['verdict']}",
        f"         {result['rationale']}",
    ]
    if result["present_in"]:
        out.append("")
        out.append("found in:")
        for row in result["present_in"][:10]:
            extra = f" (+{row['amplified']} amplified)" if row["amplified"] else ""
            out.append(f"  {row['label']}: {row['introduced']} names{extra}")
        if len(result["present_in"]) > 10:
            out.append(f"  ... +{len(result['present_in']) - 10} more arms")
    if result.get("method_limited"):
        out.append("")
        out.append(f"CAVEAT   {result['method_limited']}")
    mixed_method_axes = (result.get("method_population") or {}).get("mixed_axes") or []
    if mixed_method_axes:
        out.append("")
        out.append(
            "METHOD   mixed population on "
            + ", ".join(mixed_method_axes)
            + "; absence is not comparable across these arms"
        )
    if result["raw_surfaces_rejected"]:
        out.append("")
        out.append(
            f"rejected {len(result['raw_surfaces_rejected'])} raw surface(s): an "
            "absence claim cannot be checked against unattributed data"
        )
    if result.get("failed_arms"):
        out.append("")
        out.append(
            f"FAILED   {len(result['failed_arms'])} arm(s) produced no data: "
            + ", ".join(result["failed_arms"][:5])
        )
    if result.get("unready_arms"):
        out.append("")
        out.append(
            f"UNREADY  {len(result['unready_arms'])} arm(s) were not claim-ready: "
            + ", ".join(result["unready_arms"][:5])
        )
    if result.get("unparseable_files"):
        out.append("")
        out.append(
            f"UNPARSEABLE  {len(result['unparseable_files'])} JSON file(s) "
            "could not be classified: "
            + ", ".join(result["unparseable_files"][:5])
        )
    return "\n".join(out)


def corpus_matrix(
    documents: list[tuple[str, dict[str, Any]]],
    *,
    group_of: Any = None,
    technique: str | None = None,
) -> dict[str, Any]:
    """Roll a whole corpus of surfaces into one technique x group matrix.

    The digest answers "what does this collector do" and diff answers "how do
    these two differ". Neither answers "how do these thirty-five compare", which
    is the question that actually produces product conclusions -- and which cost
    three separate hand-written JSON walks in one session on 2026-08-06 before
    this existed.

    ``group_of`` is a callable mapping a label to a group name. It is injected
    rather than inferred because grouping is a question about the corpus, not a
    property of the tool: splitting by collector family, by site, or by roll are
    all legitimate and the tool has no business guessing which one is meant.

    ``technique`` switches to per-arm mode for a single technique, which is how a
    bimodal distribution becomes visible. Aggregates hide exactly the structure
    worth finding: the median audio-graph count across main-sensor arms is 35,
    which is true of 25 arms and false of the other 5, and those 5 turned out to
    be a clean per-site switch rather than noise.
    """
    checked_documents = _validated_document_population(
        documents, population="corpus", require_nonempty=False
    )
    if group_of is not None and not callable(group_of):
        raise ContractError("corpus grouper must be callable")
    technique = _validated_focus(technique)
    grouper = group_of or (lambda _label: "all")

    per_group: dict[str, list[dict[str, Any]]] = {}
    skipped: list[dict[str, str]] = []
    unready_arms: list[str] = []
    raw_surfaces_included: list[str] = []
    digested_documents: list[tuple[str, dict[str, Any]]] = []
    accepted_pins: set[str] = set()
    for label, document in checked_documents:
        try:
            digest = digest_observation(document)
        except ContractError as exc:
            # A document that cannot be digested is reported, never dropped
            # silently: a shrinking denominator is how a corpus claim quietly
            # becomes wrong.
            skipped.append({"label": label, "reason": safe_failure_receipt(exc)})
            continue
        pin = digest.get("script_sha256_16")
        if pin is not None:
            if not isinstance(pin, str) or re.fullmatch(r"[0-9a-f]{16}", pin) is None:
                skipped.append(
                    {
                        "label": label,
                        "reason": safe_failure_receipt(
                            ContractError("corpus document script pin is invalid")
                        ),
                    }
                )
                continue
            accepted_pins.add(pin)
        if digest["attributed"]:
            if digest["surface_claim_ready"] is False:
                unready_arms.append(label)
        else:
            raw_surfaces_included.append(label)
        group = _bounded_text(
            grouper(label), maximum=MAX_CORPUS_GROUP_BYTES, label="corpus group"
        )
        per_group.setdefault(group, []).append(
            {"label": label, "digest": digest, "document": document}
        )
        digested_documents.append((label, document))

    def _counts(digest: dict[str, Any], tech: str) -> tuple[int, int]:
        row = digest["techniques"].get(tech)
        introduced = row["api_names"] if row else 0
        amplified = (row["amplified"] if row else 0) + digest.get(
            "amplified_only_techniques", {}
        ).get(tech, 0)
        return introduced, amplified

    groups: dict[str, Any] = {}
    for name, entries in sorted(per_group.items()):
        techniques: dict[str, Any] = {}
        for tech in sorted(TECHNIQUES):
            intro = [_counts(e["digest"], tech)[0] for e in entries]
            amp = [_counts(e["digest"], tech)[1] for e in entries]
            present = sum(1 for i, a in zip(intro, amp) if i or a)
            if not present:
                continue
            ordered = sorted(intro)
            techniques[tech] = {
                "present_in_arms": present,
                "total_arms": len(entries),
                "median_introduced": ordered[len(ordered) // 2],
                "min_introduced": min(intro),
                "max_introduced": max(intro),
                "median_amplified": sorted(amp)[len(amp) // 2],
                # A technique whose min and max differ is configured, not fixed.
                "varies": min(intro) != max(intro),
            }
        groups[name] = {
            "arms": len(entries),
            "techniques": techniques,
            "resource_intents": _resource_intent_corpus(entries),
            "method_population": _method_population(
                [(entry["label"], entry["document"]) for entry in entries]
            ),
        }

    # Distinct script pins, not just arm count. Arms over-count: one script
    # observed under five method controls is five arms and one pin, and a corpus
    # claim ("no sixth profile appeared") is only as strong as its pin count.
    observed_pins = sorted(accepted_pins)

    result: dict[str, Any] = {
        "schema": CORPUS_SCHEMA,
        "arms": sum(len(v) for v in per_group.values()),
        "distinct_pins": len(observed_pins),
        "observed_pins": observed_pins,
        "groups": groups,
        "skipped": skipped,
        "unready_arms": sorted(unready_arms),
        "raw_surfaces_included": sorted(raw_surfaces_included),
        "method_population": _method_population(digested_documents),
        "resource_intents": _resource_intent_corpus(
            [
                {"label": label, "document": document}
                for label, document in digested_documents
            ]
        ),
        "non_claims": [
            "aggregates across arms hide per-arm structure; use --technique to check",
            "group membership is supplied by the caller, not inferred from evidence",
            "not an acceptance, bypass, evasion, or bot-score claim",
        ],
    }
    if technique is not None:
        per_arm = []
        for name, entries in sorted(per_group.items()):
            for entry in entries:
                intro, amp = _counts(entry["digest"], technique)
                per_arm.append(
                    {
                        "group": name,
                        "label": entry["label"],
                        "introduced": intro,
                        "amplified": amp,
                    }
                )
        per_arm.sort(key=lambda r: (-r["introduced"], r["group"], r["label"]))
        distinct = sorted({r["introduced"] for r in per_arm})
        value_counts = Counter(r["introduced"] for r in per_arm)
        result["technique_detail"] = {
            "technique": technique,
            "per_arm": per_arm,
            "distinct_values": distinct,
            # Two repeated values are a descriptive sample shape; one outlier
            # is not a second mode, and neither shape establishes a cause.
            "looks_bimodal": len(distinct) == 2
            and len(per_arm) > 4
            and min(value_counts.values()) >= 2,
        }
    return result


def _validate_rendered_resource_intents(resource: Any, arms: int) -> None:
    if resource is None:
        return
    if type(resource) is not dict:
        raise ContractError("rendered corpus resource population is invalid")
    contract = resource.get("contract_arms")
    successful = resource.get("successful_attributed_arms")
    unavailable = resource.get("unavailable_arms")
    unavailable_omitted = resource.get("unavailable_arms_omitted")
    raw = resource.get("raw_arms")
    raw_omitted = resource.get("raw_arms_omitted")
    rows = resource.get("rows")
    rows_omitted = resource.get("rows_omitted")
    unique_rows = resource.get("unique_rows")
    if (
        type(resource.get("population_arms")) is not int
        or resource["population_arms"] != arms
        or any(type(value) is not int for value in (
            contract, successful, unavailable_omitted, raw_omitted,
            rows_omitted, unique_rows,
        ))
        or not 1 <= contract <= arms
        or not 0 <= successful <= contract
        or type(unavailable) is not list
        or type(raw) is not list
        or type(rows) is not list
        or len(unavailable) > 32
        or len(raw) > 32
        or len(rows) > 32
        or min(unavailable_omitted, raw_omitted, rows_omitted) < 0
        or rows_omitted > arms * 128
        or successful + len(unavailable) + unavailable_omitted
        + len(raw) + raw_omitted != arms
        or unique_rows != len(rows) + rows_omitted
        or type(resource.get("population_complete")) is not bool
        or resource["population_complete"] is not (successful == arms)
        or resource.get("non_claim") != RESOURCE_INTENT_CORPUS_NON_CLAIM
    ):
        raise ContractError("rendered corpus resource population is inconsistent")
    labels: set[str] = set()
    for item in unavailable:
        if (
            type(item) is not dict
            or set(item) != {"label", "status"}
            or item["status"] not in {
                "missing", "failed", "off", "unverifiable", "unknown"
            }
        ):
            raise ContractError("rendered corpus unavailable resource arm is invalid")
        label = _bounded_text(
            item["label"], maximum=MAX_CORPUS_LABEL_BYTES,
            label="rendered corpus resource label",
        )
        if label in labels:
            raise ContractError("rendered corpus resource labels are duplicated")
        labels.add(label)
    for item in raw:
        label = _bounded_text(
            item, maximum=MAX_CORPUS_LABEL_BYTES,
            label="rendered corpus resource label",
        )
        if label in labels:
            raise ContractError("rendered corpus resource labels are duplicated")
        labels.add(label)
    for item in rows:
        if type(item) is not dict or set(item) != {
            "intent", "present_in_arms", "successful_arms",
            "example_labels", "example_labels_omitted",
        }:
            raise ContractError("rendered corpus resource row is invalid")
        present = item["present_in_arms"]
        examples = item["example_labels"]
        omitted = item["example_labels_omitted"]
        if (
            type(present) is not int
            or not 1 <= present <= successful
            or type(item["successful_arms"]) is not int
            or item["successful_arms"] != successful
            or type(examples) is not list
            or len(examples) > 8
            or type(omitted) is not int
            or omitted < 0
            or len(examples) + omitted != present
        ):
            raise ContractError("rendered corpus resource row is inconsistent")
        checked_examples = [
            _bounded_text(label, maximum=MAX_CORPUS_LABEL_BYTES,
                          label="rendered corpus resource example")
            for label in examples
        ]
        if checked_examples != sorted(set(checked_examples)):
            raise ContractError("rendered corpus resource examples are invalid")
        projected = _sanitize_resource_intent_report({
            "status": "ok", "intents": [item["intent"]],
        }).get("intents")
        if projected != [item["intent"]]:
            raise ContractError("rendered corpus resource intent is invalid")


def _validate_rendered_corpus_method_population(
    population: Any, arms: int
) -> None:
    if (
        type(population) is not dict
        or type(population.get("arms")) is not int
        or population["arms"] != arms
    ):
        raise ContractError("rendered corpus method population is invalid")
    axes = population.get("axes")
    if type(axes) is not dict or set(axes) != set(CONTROL_METHOD_AXES):
        raise ContractError("rendered corpus method population is invalid")
    mixed: list[str] = []
    for axis, counts in axes.items():
        if type(counts) is not dict or len(counts) > arms:
            raise ContractError("rendered corpus method population is invalid")
        total = 0
        for key, count in counts.items():
            if type(key) is not str or type(count) is not int or not 0 < count <= arms:
                raise ContractError("rendered corpus method population is invalid")
            try:
                decoded = json.loads(key)
            except ValueError:
                raise ContractError("rendered corpus method population is invalid") from None
            if _axis_value(decoded) != key:
                raise ContractError("rendered corpus method population is invalid")
            total += count
        if total != arms:
            raise ContractError("rendered corpus method population contradicts arms")
        if len(counts) > 1:
            mixed.append(axis)
    mixed.sort()
    if (
        population.get("mixed_axes") != mixed
        or type(population.get("same_method")) is not bool
        or population["same_method"] is not (bool(arms) and not mixed)
    ):
        raise ContractError("rendered corpus method population is inconsistent")


def _validate_rendered_corpus(matrix: dict[str, Any]) -> None:
    """Check the saved denominator and descriptive per-arm shape."""
    arms = matrix.get("arms")
    groups = matrix.get("groups")
    if (
        type(arms) is not int
        or not 0 <= arms <= MAX_CORPUS_ARMS
        or type(groups) is not dict
    ):
        raise ContractError("rendered corpus structure is invalid")
    group_sizes: dict[str, int] = {}
    group_resources: list[dict[str, Any]] = []
    for name, group in groups.items():
        checked_name = _bounded_text(
            name, maximum=MAX_CORPUS_GROUP_BYTES, label="rendered corpus group"
        )
        if (
            type(group) is not dict
            or type(group.get("arms")) is not int
            or not 1 <= group["arms"] <= MAX_CORPUS_ARMS
        ):
            raise ContractError("rendered corpus group is invalid")
        techniques = group.get("techniques")
        if (
            type(techniques) is not dict
            or len(techniques) > len(TECHNIQUES)
            or any(tech not in TECHNIQUES for tech in techniques)
        ):
            raise ContractError("rendered corpus techniques are invalid")
        for row in techniques.values():
            if type(row) is not dict or set(row) != {
                "present_in_arms", "total_arms", "median_introduced",
                "min_introduced", "max_introduced", "median_amplified", "varies",
            }:
                raise ContractError("rendered corpus technique row is invalid")
            present = row["present_in_arms"]
            total = row["total_arms"]
            minimum = row["min_introduced"]
            median = row["median_introduced"]
            maximum = row["max_introduced"]
            amplified = row["median_amplified"]
            if (
                any(type(value) is not int for value in (
                    present, total, minimum, median, maximum, amplified
                ))
                or not 1 <= present <= group["arms"]
                or total != group["arms"]
                or not 0 <= minimum <= median <= maximum <= MAX_API_SURFACE_ENTRIES
                or not 0 <= amplified <= MAX_API_SURFACE_ENTRIES
                or type(row["varies"]) is not bool
                or row["varies"] is not (minimum != maximum)
            ):
                raise ContractError("rendered corpus technique row is inconsistent")
        group_sizes[checked_name] = group["arms"]
        _validate_rendered_corpus_method_population(
            group.get("method_population"), group["arms"]
        )
        group_resource = group.get("resource_intents")
        _validate_rendered_resource_intents(group_resource, group["arms"])
        if group_resource is not None:
            group_resources.append(group_resource)
    if sum(group_sizes.values()) != arms:
        raise ContractError("rendered corpus group counts contradict arms")
    _validate_rendered_corpus_method_population(matrix.get("method_population"), arms)
    resource = matrix.get("resource_intents")
    _validate_rendered_resource_intents(resource, arms)
    if (resource is None) != (not group_resources):
        raise ContractError("rendered corpus resource groups are inconsistent")
    if resource is not None:
        for field in ("contract_arms", "successful_attributed_arms"):
            if resource[field] != sum(group[field] for group in group_resources):
                raise ContractError("rendered corpus resource groups are inconsistent")
        for labels, omitted in (
            ("unavailable_arms", "unavailable_arms_omitted"),
            ("raw_arms", "raw_arms_omitted"),
        ):
            total = len(resource[labels]) + resource[omitted]
            group_total = sum(
                len(group[labels]) + group[omitted] for group in group_resources
            )
            if total != group_total:
                raise ContractError("rendered corpus resource groups are inconsistent")
    pins = matrix.get("observed_pins")
    if (
        type(pins) is not list
        or len(pins) > arms
        or any(type(pin) is not str or re.fullmatch(r"[0-9a-f]{16}", pin) is None
               for pin in pins)
        or pins != sorted(set(pins))
        or type(matrix.get("distinct_pins")) is not int
        or matrix["distinct_pins"] != len(pins)
    ):
        raise ContractError("rendered corpus script pins are inconsistent")

    skipped = matrix.get("skipped")
    if type(skipped) is not list or len(skipped) > MAX_CORPUS_ARMS - arms:
        raise ContractError("rendered corpus skipped documents are invalid")
    skipped_labels: set[str] = set()
    for item in skipped:
        if type(item) is not dict or set(item) != {"label", "reason"}:
            raise ContractError("rendered corpus skipped documents are invalid")
        label = _bounded_text(
            item["label"], maximum=MAX_CORPUS_LABEL_BYTES,
            label="rendered corpus skipped label",
        )
        if (
            label in skipped_labels
            or type(item["reason"]) is not str
            or re.fullmatch(
                r"(?:contract-failure|execution-failure); "
                r"diagnostic_sha256_16=[0-9a-f]{16}", item["reason"]
            ) is None
        ):
            raise ContractError("rendered corpus skipped documents are invalid")
        skipped_labels.add(label)

    label_groups: dict[str, list[str]] = {}
    for field in (
        "failed_arms", "unparseable_files", "unready_arms",
        "raw_surfaces_included", "raw_observations_excluded",
    ):
        value = matrix.get(field, [])
        if type(value) is not list or len(value) > MAX_CORPUS_ARMS:
            raise ContractError("rendered corpus population labels are invalid")
        checked = [
            _bounded_text(item, maximum=MAX_CORPUS_LABEL_BYTES,
                          label="rendered corpus population label")
            for item in value
        ]
        if checked != sorted(set(checked)):
            raise ContractError("rendered corpus population labels are invalid")
        label_groups[field] = checked
    unready = set(label_groups["unready_arms"])
    raw = set(label_groups["raw_surfaces_included"])
    if len(unready | raw) > arms or unready & raw:
        raise ContractError("rendered corpus population labels contradict arms")
    if "trustworthy_population" in matrix:
        expected_trust = not any((
            label_groups["failed_arms"], label_groups["unparseable_files"],
            skipped, unready, raw,
        )) and matrix["method_population"]["same_method"]
        if (
            type(matrix["trustworthy_population"]) is not bool
            or matrix["trustworthy_population"] is not expected_trust
        ):
            raise ContractError("rendered corpus trust flag is inconsistent")

    detail = matrix.get("technique_detail")
    if detail is None:
        return
    if type(detail) is not dict or detail.get("technique") not in TECHNIQUES:
        raise ContractError("rendered corpus technique detail is invalid")
    rows = detail.get("per_arm")
    if type(rows) is not list or len(rows) != arms:
        raise ContractError("rendered corpus technique rows contradict arms")
    seen_labels: set[str] = set()
    row_groups: Counter[str] = Counter()
    values: Counter[int] = Counter()
    checked_rows: list[dict[str, Any]] = []
    for row in rows:
        if type(row) is not dict or set(row) != {
            "group", "label", "introduced", "amplified"
        }:
            raise ContractError("rendered corpus technique row is invalid")
        group = _bounded_text(
            row["group"], maximum=MAX_CORPUS_GROUP_BYTES,
            label="rendered corpus group",
        )
        label = _bounded_text(
            row["label"], maximum=MAX_CORPUS_LABEL_BYTES,
            label="rendered corpus label",
        )
        introduced, amplified = row["introduced"], row["amplified"]
        if (
            group not in group_sizes
            or label in seen_labels
            or type(introduced) is not int
            or type(amplified) is not int
            or not 0 <= introduced <= MAX_API_SURFACE_ENTRIES
            or not 0 <= amplified <= MAX_API_SURFACE_ENTRIES
        ):
            raise ContractError("rendered corpus technique row is invalid")
        seen_labels.add(label)
        row_groups[group] += 1
        values[introduced] += 1
        checked_rows.append(row)
    if (
        dict(row_groups) != group_sizes
        or seen_labels & skipped_labels
        or not unready <= seen_labels
        or not raw <= seen_labels
        or checked_rows != sorted(
            checked_rows,
            key=lambda row: (-row["introduced"], row["group"], row["label"]),
        )
        or detail.get("distinct_values") != sorted(values)
        or type(detail.get("looks_bimodal")) is not bool
        or detail["looks_bimodal"] is not (
            len(values) == 2 and arms > 4 and min(values.values()) >= 2
        )
    ):
        raise ContractError("rendered corpus technique shape is inconsistent")


@_normalize_renderer_failures("corpus")
def render_corpus(matrix: dict[str, Any]) -> str:
    """Render a corpus matrix as bounded fixed-width text."""
    if not isinstance(matrix, dict):
        raise ContractError("rendered corpus input must be an object")
    if matrix.get("schema") != CORPUS_SCHEMA:
        raise ContractError("rendered corpus schema is invalid")
    _validate_rendered_corpus(matrix)
    names = list(matrix["groups"])
    header = (
        f"{matrix['arms']} arms over {matrix.get('distinct_pins', '?')} distinct "
        f"script pins, in {len(names)} group(s): "
        + ", ".join(f"{n} (n={matrix['groups'][n]['arms']})" for n in names)
    )
    out = [header]
    failed_arms = matrix.get("failed_arms") or []
    if failed_arms:
        out.append(
            f"!! FAILED ARMS: {len(failed_arms)} produced no data; this population "
            "cannot support a negative conclusion"
        )
    unparseable_files = matrix.get("unparseable_files") or []
    if unparseable_files:
        out.append(
            f"!! UNPARSEABLE FILES: {len(unparseable_files)} JSON file(s) could not "
            "be classified; this population cannot support a negative conclusion"
        )
    unready_arms = matrix.get("unready_arms") or []
    if unready_arms:
        out.append(
            f"!! UNREADY ARMS: {len(unready_arms)} produced data but were not "
            "claim-ready; this population cannot support a negative conclusion"
        )
    raw_included = matrix.get("raw_surfaces_included") or []
    if raw_included:
        out.append(
            f"!! NOT ATTRIBUTED: {len(raw_included)} raw surface(s) are included; "
            "their API calls cannot be attributed to the script"
        )
    raw_excluded = matrix.get("raw_observations_excluded") or []
    if raw_excluded:
        out.append(
            f"excluded {len(raw_excluded)} raw observation(s) as unattributed "
            "(--include-raw to inspect them explicitly)"
        )
    mixed_method_axes = (matrix.get("method_population") or {}).get("mixed_axes") or []
    if mixed_method_axes:
        out.append(
            "!! MIXED METHOD: arms differ on "
            + ", ".join(mixed_method_axes)
            + "; aggregate differences are not attributable to scripts alone"
        )
    coverage = matrix.get("pin_coverage")
    if coverage:
        out.append(
            f"coverage: {coverage['observed']} of {coverage['available']} collector "
            f"pins in the capture tree observed ({coverage['percent']}%); "
            f"{coverage['unobserved']} unobserved"
        )
    resource_intents = matrix.get("resource_intents")
    if resource_intents:
        out.append(
            "resource intent snapshots: "
            f"{resource_intents['successful_attributed_arms']}/"
            f"{resource_intents['population_arms']} successful + attributed; "
            f"{resource_intents['unique_rows']} unique introduced row(s)"
        )
        if not resource_intents["population_complete"]:
            unavailable = len(resource_intents["unavailable_arms"]) + int(
                resource_intents["unavailable_arms_omitted"]
            )
            raw = len(resource_intents["raw_arms"]) + int(
                resource_intents["raw_arms_omitted"]
            )
            out.append(
                f"!! INCOMPLETE RESOURCE POPULATION  unavailable {unavailable}; "
                f"raw/unattributed {raw}; prevalence denominator is successful "
                "snapshots only"
            )
        for row in resource_intents["rows"][:12]:
            out.append(
                "  "
                + _format_resource_intent_row(row["intent"])
                + f"  ({row['present_in_arms']}/{row['successful_arms']} arms)"
            )
        hidden = max(0, len(resource_intents["rows"]) - 12) + int(
            resource_intents["rows_omitted"]
        )
        if hidden:
            out.append(f"  +{hidden} more resource row(s) (bounded)")
        out.append("  non-claim: " + resource_intents["non_claim"])
    if matrix["skipped"]:
        out.append(f"SKIPPED {len(matrix['skipped'])} undigestible document(s):")
        for skipped in matrix["skipped"][:5]:
            out.append(f"  {skipped['label']}: {skipped['reason'][:60]}")
    out.append("")

    detail = matrix.get("technique_detail")
    if detail:
        out.append(f"--- {detail['technique']} per arm ---")
        out.append(f"{'group':<14}{'arm':<30}{'introduced':>11}{'amplified':>11}")
        out.append("-" * 66)
        for row in detail["per_arm"]:
            out.append(
                f"{row['group'][:13]:<14}{row['label'][:29]:<30}"
                f"{row['introduced']:>11}{row['amplified'] or '':>11}"
            )
        out.append("-" * 66)
        out.append(f"distinct values: {detail['distinct_values']}")
        if detail["looks_bimodal"]:
            out.append(
                "shape: BIMODAL -- two repeated values in this sample; inspect "
                "method and script pins before interpreting the split"
            )
        return "\n".join(out)

    width = max(14, max((len(n) for n in names), default=14) + 2)
    header = f"{'technique':<22}" + "".join(f"{n[:width-2]:>{width}}" for n in names)
    out.append(header)
    out.append("-" * len(header))
    all_techs = sorted({t for g in matrix["groups"].values() for t in g["techniques"]})
    for tech in all_techs:
        cells = []
        for n in names:
            row = matrix["groups"][n]["techniques"].get(tech)
            if not row:
                cells.append(f"{'--':>{width}}")
                continue
            cell = str(row["median_introduced"])
            if row["median_amplified"]:
                cell += f"+{row['median_amplified']}"
            cell += f" ({row['present_in_arms']}/{row['total_arms']})"
            if row["varies"]:
                cell += "*"
            cells.append(f"{cell:>{width}}")
        out.append(f"{tech:<22}" + "".join(cells))
    out.append("-" * len(header))
    out.append(
        "median introduced (+amplified) names, (arms present / total); * = varies across arms"
    )
    return "\n".join(out)


def _format_resource_intent_row(row: dict[str, Any]) -> str:
    """Render one already-allowlisted row without reconstructing a raw URL."""
    lengths = ",".join(str(value) for value in row["path_segment_lengths"])
    if row.get("path_segments_truncated"):
        lengths += ",..."
    query = ",".join(row["query_names"]) or "-"
    if row.get("query_names_truncated"):
        query += ",..."
    return (
        f"{row['tag']}.{row['attribute']} -> {row['origin']} "
        f"path-lengths=[{lengths}] query-keys=[{query}]"
    )


def _format_request_activity_row(row: dict[str, Any]) -> str:
    """Render a structural loopback request row without reconstructing its path."""
    lengths = ",".join(str(value) for value in row["path_segment_lengths"])
    if row.get("path_segments_truncated"):
        lengths += ",..."
    query = ",".join(row["query_names"]) or "-"
    if row.get("query_names_truncated"):
        query += ",..."
    body = (
        f"bytes={row.get('body_bytes_total', 0)} "
        f"[{row.get('body_bytes_min', 0)}..{row.get('body_bytes_max', 0)}]"
    )
    digest_counts = row.get("body_sha256_16_counts")
    digest_summary = ""
    if isinstance(digest_counts, dict):
        digest_summary = (
            f" body-digests={sum(digest_counts.values())}/"
            f"{len(digest_counts)}-distinct"
        )
    return (
        f"{row['method']} {row['served']} path-lengths=[{lengths}] "
        f"query-keys=[{query}] x{row.get('count', 0)} {body}{digest_summary}"
    )


def _format_input_delivery_role(
    role: str, probe: dict[str, Any] | None, ambient: dict[str, Any] | None
) -> str:
    receipt = (
        f"{probe.get('dispatched', 0)}/{probe.get('attempted', 0)} commands"
        if probe
        else "no command receipt"
    )
    events = (ambient or {}).get("trusted_events") or {}
    witness = ", ".join(f"{name}={count}" for name, count in events.items()) or "none"
    return f"{role}: {receipt}; trusted witnesses {witness}"


def _validate_rendered_digest_attribution(digest: dict[str, Any]) -> None:
    source_schema = digest.get("source_schema")
    attributed = digest.get("attributed")
    if (
        source_schema not in (OBSERVATION_SCHEMA, SUBTRACTION_SCHEMA)
        or type(attributed) is not bool
        or attributed is not (source_schema == SUBTRACTION_SCHEMA)
    ):
        raise ContractError("rendered digest attribution is inconsistent")
    if attributed:
        if (
            type(digest.get("clean_subtraction")) is not bool
            or type(digest.get("surface_claim_ready")) is not bool
            or (digest["surface_claim_ready"] and not digest["clean_subtraction"])
            or "attribution_warning" in digest
        ):
            raise ContractError("rendered digest claim readiness is inconsistent")
        input_coherent = digest.get("input_claim_receipts_coherent")
        if "input_claim_receipts_coherent" in digest and (
            type(input_coherent) is not bool
            or (digest["surface_claim_ready"] and not input_coherent)
        ):
            raise ContractError("rendered digest claim readiness is inconsistent")
        rehost_coherent = digest.get("rehost_dependency_receipts_coherent")
        if "rehost_dependency_receipts_coherent" in digest and (
            type(rehost_coherent) is not bool
            or (digest["surface_claim_ready"] and not rehost_coherent)
        ):
            raise ContractError("rendered digest claim readiness is inconsistent")
        offline_coherent = digest.get("offline_guard_receipts_coherent")
        if "offline_guard_receipts_coherent" in digest and (
            type(offline_coherent) is not bool
            or (digest["surface_claim_ready"] and not offline_coherent)
        ):
            raise ContractError("rendered digest claim readiness is inconsistent")
        lineage_coherent = digest.get("observation_lineage_receipts_coherent")
        if "observation_lineage_receipts_coherent" in digest and (
            type(lineage_coherent) is not bool
            or (digest["surface_claim_ready"] and not lineage_coherent)
        ):
            raise ContractError("rendered digest claim readiness is inconsistent")
        startup_coherent = digest.get("startup_receipts_coherent")
        if "startup_receipts_coherent" in digest and (
            type(startup_coherent) is not bool
            or (digest["surface_claim_ready"] and not startup_coherent)
        ):
            raise ContractError("rendered digest claim readiness is inconsistent")
        method_coherent = digest.get("method_mismatch_verdict_coherent")
        if "method_mismatch_verdict_coherent" in digest and (
            type(method_coherent) is not bool
            or (digest["surface_claim_ready"] and not method_coherent)
        ):
            raise ContractError("rendered digest claim readiness is inconsistent")
        identity_coherent = digest.get("script_identity_receipts_coherent")
        if "script_identity_receipts_coherent" in digest and (
            type(identity_coherent) is not bool
            or (digest["surface_claim_ready"] and not identity_coherent)
        ):
            raise ContractError("rendered digest claim readiness is inconsistent")
        driver_coherent = digest.get("driver_execution_receipts_coherent")
        if "driver_execution_receipts_coherent" in digest and (
            type(driver_coherent) is not bool
            or (digest["surface_claim_ready"] and not driver_coherent)
        ):
            raise ContractError("rendered digest claim readiness is inconsistent")
        trace_coherent = digest.get("trace_evidence_receipts_coherent")
        if "trace_evidence_receipts_coherent" in digest and (
            type(trace_coherent) is not bool
            or (digest["surface_claim_ready"] and not trace_coherent)
        ):
            raise ContractError("rendered digest claim readiness is inconsistent")
        page_load_coherent = digest.get("page_load_receipts_coherent")
        if "page_load_receipts_coherent" in digest and (
            type(page_load_coherent) is not bool
            or (digest["surface_claim_ready"] and not page_load_coherent)
        ):
            raise ContractError("rendered digest claim readiness is inconsistent")
        ready_probe_coherent = digest.get("ready_probe_receipts_coherent")
        if "ready_probe_receipts_coherent" in digest and (
            type(ready_probe_coherent) is not bool
            or (digest["surface_claim_ready"] and not ready_probe_coherent)
        ):
            raise ContractError("rendered digest claim readiness is inconsistent")
        await_coherent = digest.get("await_receipts_coherent")
        if "await_receipts_coherent" in digest and (
            type(await_coherent) is not bool
            or (digest["surface_claim_ready"] and not await_coherent)
        ):
            raise ContractError("rendered digest claim readiness is inconsistent")
        request_receipts_valid = digest.get("request_activity_receipts_valid")
        if "request_activity_receipts_valid" in digest and (
            type(request_receipts_valid) is not bool
            or (digest["surface_claim_ready"] and not request_receipts_valid)
        ):
            raise ContractError("rendered digest claim readiness is inconsistent")
        resource_receipts_valid = digest.get("resource_intent_receipts_valid")
        if "resource_intent_receipts_valid" in digest and (
            type(resource_receipts_valid) is not bool
            or (digest["surface_claim_ready"] and not resource_receipts_valid)
        ):
            raise ContractError("rendered digest claim readiness is inconsistent")
        subtraction_receipt_coherent = digest.get("subtraction_receipt_coherent")
        if "subtraction_receipt_coherent" in digest and (
            type(subtraction_receipt_coherent) is not bool
            or (digest["surface_claim_ready"] and not subtraction_receipt_coherent)
        ):
            raise ContractError("rendered digest claim readiness is inconsistent")
    elif (
        digest.get("attribution_warning") != RAW_ATTRIBUTION_WARNING
        or "clean_subtraction" in digest
        or "surface_claim_ready" in digest
        or "input_claim_receipts_coherent" in digest
        or "rehost_dependency_receipts_coherent" in digest
        or "offline_guard_receipts_coherent" in digest
        or "observation_lineage_receipts_coherent" in digest
        or "startup_receipts_coherent" in digest
        or "method_mismatch_verdict_coherent" in digest
        or "script_identity_receipts_coherent" in digest
        or "driver_execution_receipts_coherent" in digest
        or "trace_evidence_receipts_coherent" in digest
        or "page_load_receipts_coherent" in digest
        or "ready_probe_receipts_coherent" in digest
        or "await_receipts_coherent" in digest
        or "request_activity_receipts_valid" in digest
        or "resource_intent_receipts_valid" in digest
        or "subtraction_receipt_coherent" in digest
    ):
        raise ContractError("rendered digest raw warning is inconsistent")
    expected_empty = (
        EMPTY_SURFACE_WARNING
        if attributed and digest.get("total_api_names") == 0
        else None
    )
    if digest.get("empty_surface_warning") != expected_empty:
        raise ContractError("rendered digest empty-surface warning is inconsistent")


def _validate_rendered_digest_counts(digest: dict[str, Any]) -> None:
    """Reconcile a saved summary with the bounded technique rows it displays."""
    invalid = "rendered digest counts are inconsistent"
    techniques = digest.get("techniques")
    amplified_only = digest.get("amplified_only_techniques")
    if (
        type(techniques) is not dict
        or type(amplified_only) is not dict
        or len(techniques) > len(TECHNIQUES) + 1
        or len(amplified_only) > len(TECHNIQUES) + 1
    ):
        raise ContractError(invalid)
    limits = {
        "total_api_names": MAX_API_SURFACE_ENTRIES,
        "total_calls": MAX_API_SURFACE_ENTRIES * MAX_API_EVENT_COUNT,
        "techniques_observed": len(TECHNIQUES) + 1,
        "amplified_api_names": MAX_API_SURFACE_ENTRIES,
    }
    if any(
        type(digest.get(field)) is not int or not 0 <= digest[field] <= maximum
        for field, maximum in limits.items()
    ):
        raise ContractError(invalid)

    names_total = calls_total = amplified_total = 0
    allowed = set(TECHNIQUES) | {"unclassified"}
    for technique, row in techniques.items():
        if technique not in allowed or type(row) is not dict:
            raise ContractError(invalid)
        names = row.get("api_names")
        calls = row.get("calls")
        amplified = row.get("amplified")
        interfaces = row.get("interfaces")
        interfaces_total = row.get("interfaces_total")
        if (
            type(names) is not int
            or not 1 <= names <= MAX_API_SURFACE_ENTRIES
            or type(calls) is not int
            or not names <= calls <= names * MAX_API_EVENT_COUNT
            or type(amplified) is not int
            or not 0 <= amplified <= MAX_API_SURFACE_ENTRIES
            or type(interfaces) is not list
            or len(interfaces) > 128
            or type(interfaces_total) is not int
            or not len(interfaces) <= interfaces_total <= names
        ):
            raise ContractError(invalid)
        if any(type(item) is not str for item in interfaces):
            raise ContractError(invalid)
        for item in interfaces:
            _bounded_text(
                item,
                maximum=MAX_API_EVENT_NAME_BYTES,
                label="rendered digest interface",
            )
        if interfaces != sorted(set(interfaces)):
            raise ContractError(invalid)
        names_total += names
        calls_total += calls
        amplified_total += amplified

    for technique, count in amplified_only.items():
        if (
            technique not in allowed
            or technique in techniques
            or type(count) is not int
            or not 1 <= count <= MAX_API_SURFACE_ENTRIES
        ):
            raise ContractError(invalid)
        amplified_total += count
    if (
        digest["total_api_names"] != names_total
        or digest["total_calls"] != calls_total
        or digest["techniques_observed"] != len(techniques)
        or digest["amplified_api_names"] != amplified_total
        or digest.get("not_observed")
        != sorted(set(TECHNIQUES) - set(techniques) - set(amplified_only))
    ):
        raise ContractError(invalid)


def _validate_rendered_digest_side_view(
    view: Any, *, attributed: bool, resource: bool
) -> None:
    """Re-project saved page-controlled rows before allowing text output."""
    invalid = "rendered digest side view is inconsistent"
    if type(view) is not dict or type(view.get("attributed")) is not bool:
        raise ContractError(invalid)
    if view["attributed"] is not attributed or view.get("row_kind") != (
        "introduced" if attributed else "raw"
    ):
        raise ContractError(invalid)
    rows = view.get("rows")
    total = view.get("rows_total")
    omitted = view.get("rows_omitted")
    if (
        type(rows) is not list
        or len(rows) > RESOURCE_INTENT_ROWS_LIMIT
        or type(total) is not int
        or not len(rows) <= total <= 128
        or type(omitted) is not int
        or omitted != total - len(rows)
    ):
        raise ContractError(invalid)
    row_key = ("only_in_arm" if attributed else "intents") if resource else (
        "only_in_arm" if attributed else "rows"
    )
    source: dict[str, Any] = {"status": view.get("status"), row_key: rows}
    if resource:
        control = view.get("control_only")
        control_total = view.get("control_only_total")
        control_omitted = view.get("control_only_omitted")
        if (
            type(control) is not list
            or len(control) > RESOURCE_INTENT_ROWS_LIMIT
            or type(control_total) is not int
            or not len(control) <= control_total <= 128
            or type(control_omitted) is not int
            or control_omitted != control_total - len(control)
        ):
            raise ContractError(invalid)
        source["only_in_control"] = control
        for key in (
            "arm_count",
            "control_count",
            "shared_count",
            "clean_subtraction",
            "diagnostic",
        ):
            if key in view:
                source[key] = view[key]
        projected = _sanitize_resource_intent_report(source)
        for key in (
            "only_in_control",
            "arm_count",
            "control_count",
            "shared_count",
            "clean_subtraction",
            "diagnostic",
        ):
            if projected.get(key) != view.get("control_only" if key == "only_in_control" else key):
                raise ContractError(invalid)
    else:
        control_total = view.get("control_only_total")
        if type(control_total) is not int or not 0 <= control_total <= 128:
            raise ContractError(invalid)
        if view.get("clean_subtraction") is not None:
            source["clean_subtraction"] = view["clean_subtraction"]
        projected = _sanitize_request_activity_report(source)
        if projected.get("clean_subtraction") != view.get("clean_subtraction"):
            raise ContractError(invalid)
    if (
        projected.get("status") != view.get("status")
        or projected.get(row_key) != rows
        or projected.get("non_claim") != view.get("non_claim")
    ):
        raise ContractError(invalid)


def _validate_rendered_digest_identity_and_focus(digest: dict[str, Any]) -> None:
    invalid = "rendered digest identity or focus is inconsistent"
    try:
        _bounded_text(
            digest.get("label"), maximum=MAX_CORPUS_LABEL_BYTES, label="digest label"
        )
    except ContractError:
        raise ContractError(invalid) from None
    pin = digest.get("script_sha256_16")
    if pin is not None and (
        type(pin) is not str or re.fullmatch(r"[0-9a-f]{16}", pin) is None
    ):
        raise ContractError(invalid)
    if "focus" not in digest:
        return
    focus = digest["focus"]
    if type(focus) is not dict:
        raise ContractError(invalid)
    technique = focus.get("technique")
    names = focus.get("api_names")
    count = focus.get("count")
    expected = digest["techniques"].get(technique, {}).get("api_names", 0)
    if (
        technique not in set(TECHNIQUES) | {"unclassified"}
        or type(names) is not list
        or type(count) is not int
        or count != expected
        or len(names) != count
        or names != sorted(set(names))
    ):
        raise ContractError(invalid)
    for name in names:
        try:
            _bounded_text(name, maximum=MAX_API_EVENT_NAME_BYTES, label="API name")
        except ContractError:
            raise ContractError(invalid) from None
        if not name.startswith("api.") or technique_of(name) != technique:
            raise ContractError(invalid)


def _validate_rendered_digest_provenance(digest: dict[str, Any]) -> None:
    invalid = "rendered digest provenance is inconsistent"
    source = digest.get("source_provenance")
    capture = digest.get("provenance")
    if type(source) is not dict or type(capture) is not dict:
        raise ContractError(invalid)
    if _sanitize_source_provenance(source) != source:
        raise ContractError(invalid)
    projected = _sanitize_capture_provenance(capture)
    for field in ("status", "recorded_hosts", "directory_disagrees_with_manifest"):
        if projected[field] != capture.get(field):
            raise ContractError(invalid)


def _validate_rendered_digest_input_delivery(digest: dict[str, Any]) -> None:
    if "input_delivery" not in digest:
        return
    invalid = "rendered digest input delivery is inconsistent"
    view = digest["input_delivery"]
    attributed = digest["attributed"]
    if type(view) is not dict or view.get("attributed") is not attributed:
        raise ContractError(invalid)
    document: dict[str, Any] = {
        "schema": SUBTRACTION_SCHEMA if attributed else OBSERVATION_SCHEMA,
        "arm_input_profile" if attributed else "input_profile": view.get("profile"),
        "arm_input_probe" if attributed else "input_probe": view.get("arm_probe"),
        "arm_ambient_input" if attributed else "ambient_input": view.get(
            "arm_ambient"
        ),
    }
    if attributed:
        document["control_input_probe"] = view.get("control_probe")
        document["control_ambient_input"] = view.get("control_ambient")
        if "control_profile" in view:
            document["control_input_profile"] = view["control_profile"]
    if "no_input_probe_roles" in view:
        document["_input_delivery_no_input_probe_roles"] = view[
            "no_input_probe_roles"
        ]
    if "ambient_receipt_inconsistent_roles" in view:
        document["_input_delivery_ambient_replay_errors"] = view[
            "ambient_receipt_inconsistent_roles"
        ]
    if _input_delivery_view(document) != view:
        raise ContractError(invalid)
    if digest.get("input_claim_receipts_coherent") is True and (
        view.get("ambient_receipt_inconsistent_roles")
        or view.get("no_input_probe_roles")
        or view.get("contaminated")
        or view.get("control_profile", view.get("profile")) != view.get("profile")
    ):
        raise ContractError(invalid)


def _validate_rendered_digest_execution(digest: dict[str, Any]) -> None:
    invalid = "rendered digest execution is inconsistent"
    for field in ("script_execution", "control_script_execution"):
        if field not in digest:
            continue
        if field == "control_script_execution" and not digest["attributed"]:
            raise ContractError(invalid)
        try:
            projected = _sanitize_script_execution_summary(
                digest[field], label="rendered digest"
            )
        except ContractError:
            raise ContractError(invalid) from None
        if projected != digest[field]:
            raise ContractError(invalid)
    if "collector_startup" in digest:
        startup = digest["collector_startup"]
        if type(startup) is not dict:
            raise ContractError(invalid)
        projected = _sanitize_startup_document(startup)
        for field in ("browser_target_status", "browser_target_title_matches"):
            if projected.get(field) != startup.get(field):
                raise ContractError(invalid)


def _validate_rendered_digest_noise(digest: dict[str, Any]) -> None:
    invalid = "rendered digest control noise is inconsistent"
    internal = digest["techniques"].get("chromium-internal")
    expected = (
        {
            "chromium-internal": internal["api_names"],
            "note": "measured identical in the empty-script control",
        }
        if not digest["attributed"] and internal
        else None
    )
    if digest.get("known_control_noise") != expected:
        raise ContractError(invalid)


def _validate_rendered_diff_counts(diff: dict[str, Any]) -> None:
    invalid = "rendered digest comparison counts are inconsistent"
    for field in ("left_label", "right_label"):
        try:
            _bounded_text(
                diff.get(field), maximum=MAX_CORPUS_LABEL_BYTES, label=field
            )
        except ContractError:
            raise ContractError(invalid) from None
    for field in ("left_pin", "right_pin"):
        pin = diff.get(field)
        if pin is not None and (
            type(pin) is not str or re.fullmatch(r"[0-9a-f]{16}", pin) is None
        ):
            raise ContractError(invalid)
    fields = ("left_api_names", "right_api_names", "shared", "only_left", "only_right")
    if any(
        type(diff.get(field)) is not int
        or not 0 <= diff[field] <= MAX_API_SURFACE_ENTRIES
        for field in fields
    ):
        raise ContractError(invalid)
    left = diff["left_api_names"]
    right = diff["right_api_names"]
    shared = diff["shared"]
    left_only = diff["only_left"]
    right_only = diff["only_right"]
    union = shared + left_only + right_only
    expected_jaccard = round(shared / union, 4) if union else 0.0
    if (
        left != shared + left_only
        or right != shared + right_only
        or type(diff.get("identical_surface")) is not bool
        or diff["identical_surface"] is not (left_only == right_only == 0)
        or type(diff.get("jaccard")) is not float
        or diff["jaccard"] != expected_jaccard
    ):
        raise ContractError(invalid)
    differing = diff.get("techniques_differing")
    if type(differing) is not dict or len(differing) > len(TECHNIQUES) + 1:
        raise ContractError(invalid)
    summed_left = summed_right = summed_shared = 0
    for technique, row in differing.items():
        if technique not in set(TECHNIQUES) | {"unclassified"} or type(row) is not dict:
            raise ContractError(invalid)
        if any(
            type(row.get(field)) is not int
            or not 0 <= row[field] <= MAX_API_SURFACE_ENTRIES
            for field in ("only_left", "only_right", "shared")
        ):
            raise ContractError(invalid)
        if row["only_left"] + row["only_right"] == 0:
            raise ContractError(invalid)
        summed_left += row["only_left"]
        summed_right += row["only_right"]
        summed_shared += row["shared"]
    if summed_left != left_only or summed_right != right_only or summed_shared > shared:
        raise ContractError(invalid)


def _validate_rendered_diff_focus(diff: dict[str, Any]) -> None:
    if "focus" not in diff:
        return
    invalid = "rendered digest comparison focus is inconsistent"
    focus = diff["focus"]
    if type(focus) is not dict:
        raise ContractError(invalid)
    technique = focus.get("technique")
    if technique not in set(TECHNIQUES) | {"unclassified"}:
        raise ContractError(invalid)
    row = diff["techniques_differing"].get(technique, {})
    for side in ("only_left", "only_right"):
        names = focus.get(side)
        if (
            type(names) is not list
            or len(names) != row.get(side, 0)
            or names != sorted(set(names))
        ):
            raise ContractError(invalid)
        for name in names:
            try:
                _bounded_text(name, maximum=MAX_API_EVENT_NAME_BYTES, label="API name")
            except ContractError:
                raise ContractError(invalid) from None
            if not name.startswith("api.") or technique_of(name) != technique:
                raise ContractError(invalid)


def _validate_rendered_diff_input_delivery(diff: dict[str, Any]) -> None:
    if "input_delivery" not in diff:
        return
    invalid = "rendered digest comparison input delivery is inconsistent"
    view = diff["input_delivery"]
    if type(view) is not dict or set(view) != {"left", "right"}:
        raise ContractError(invalid)
    if view["left"] is None and view["right"] is None:
        raise ContractError(invalid)
    for side in ("left", "right"):
        delivery = view[side]
        if delivery is None:
            continue
        if type(delivery) is not dict:
            raise ContractError(invalid)
        if delivery.get("intentional_no_input") is True:
            if delivery != {
                "profile": "none",
                "intentional_no_input": True,
                "verified": None,
                "note": (
                    "recorded method requests no synthetic input; this is the "
                    "declared control arm, not a missing delivery receipt"
                ),
            }:
                raise ContractError(invalid)
            continue
        attributed = delivery.get("attributed")
        if type(attributed) is not bool:
            raise ContractError(invalid)
        _validate_rendered_digest_input_delivery(
            {"input_delivery": delivery, "attributed": attributed}
        )


def _validate_rendered_diff_comparability(diff: dict[str, Any]) -> None:
    invalid = "rendered digest comparison method is inconsistent"
    comparison = diff.get("comparability")
    if type(comparison) is not dict or comparison.get("status") not in {
        "unknown",
        "same-origin",
        "cross-origin",
        "same-source",
        "same-source-origin",
        "not-comparable",
        "method-control",
    }:
        raise ContractError(invalid)
    mismatches = comparison.get("method_mismatches")
    expected = comparison.get("expected_method_mismatches")
    unexpected = comparison.get("unexpected_method_mismatches")
    if any(type(value) is not dict for value in (mismatches, expected, unexpected)):
        raise ContractError(invalid)
    if (
        any(field not in SURFACE_METHOD_FIELDS for field in mismatches)
        or any(
            type(values) is not dict
            or set(values) != {"left", "right"}
            or values["left"] == values["right"]
            for values in mismatches.values()
        )
        or set(expected) | set(unexpected) != set(mismatches)
        or set(expected) & set(unexpected)
        or any(mismatches[field] != value for field, value in expected.items())
        or any(mismatches[field] != value for field, value in unexpected.items())
        or type(comparison.get("method_differs")) is not bool
        or comparison["method_differs"] is not bool(mismatches)
        or type(comparison.get("controlled_method_comparison")) is not bool
    ):
        raise ContractError(invalid)
    left_ready = comparison.get("left_claim_ready")
    right_ready = comparison.get("right_claim_ready")
    if any(value is not None and type(value) is not bool for value in (left_ready, right_ready)):
        raise ContractError(invalid)
    left_attributed = left_ready is not None
    right_attributed = right_ready is not None
    left_headed = comparison.get("left_headed")
    right_headed = comparison.get("right_headed")
    if any(value is not None and type(value) is not bool for value in (left_headed, right_headed)):
        raise ContractError(invalid)
    expected_launch = (
        left_headed is not None
        and right_headed is not None
        and left_headed != right_headed
    )
    left_viewport = comparison.get("left_viewport")
    right_viewport = comparison.get("right_viewport")
    if any(
        viewport is not None and type(viewport) is not dict
        for viewport in (left_viewport, right_viewport)
    ):
        raise ContractError(invalid)
    if any(
        viewport is not None
        and _viewport_method_value(viewport) != viewport
        and _unverifiable_method_value(viewport) != viewport
        for viewport in (left_viewport, right_viewport)
    ):
        raise ContractError(invalid)
    expected_viewport_values_differ = bool(
        left_viewport is not None
        and right_viewport is not None
        and left_viewport != right_viewport
    )
    expected_viewport_gate = False
    if left_viewport is not None and right_viewport is not None:
        left_height = left_viewport.get("inner_height")
        right_height = right_viewport.get("inner_height")
        if isinstance(left_height, int) and isinstance(right_height, int):
            expected_viewport_gate = (left_height < VIEWPORT_HEIGHT_FLOOR) != (
                right_height < VIEWPORT_HEIGHT_FLOOR
            )
    for side in ("left", "right"):
        hosts = comparison.get(f"{side}_hosts")
        if (
            type(hosts) is not list
            or hosts
            != _sanitize_capture_provenance(
                {"status": "VERIFIED", "recorded_hosts": hosts}
            )["recorded_hosts"]
        ):
            raise ContractError(invalid)
        source = comparison.get(f"{side}_public_source")
        if source is None:
            continue
        if (
            type(source) is not dict
            or set(source) != {"hostname", "sha256"}
            or type(source["hostname"]) is not str
            or type(source["sha256"]) is not str
            or re.fullmatch(r"[0-9a-f]{64}", source["sha256"]) is None
        ):
            raise ContractError(invalid)
        try:
            _bounded_text(
                source["hostname"], maximum=253, label="public source hostname"
            )
        except ContractError:
            raise ContractError(invalid) from None
        if source["hostname"] != source["hostname"].lower():
            raise ContractError(invalid)
    left_hosts = comparison["left_hosts"]
    right_hosts = comparison["right_hosts"]
    left_source = comparison.get("left_public_source")
    right_source = comparison.get("right_public_source")
    if left_hosts and right_hosts:
        expected_status = "same-origin" if left_hosts == right_hosts else "cross-origin"
    elif left_source is not None and right_source is not None:
        if left_source["hostname"] != right_source["hostname"]:
            expected_status = "cross-origin"
        elif left_source["sha256"] == right_source["sha256"]:
            expected_status = "same-source"
        else:
            expected_status = "same-source-origin"
    else:
        expected_status = "unknown"
    has_warning = bool(
        left_ready is False
        or right_ready is False
        or not left_attributed
        or not right_attributed
        or (expected_viewport_gate and "arm_viewport" not in expected)
        or (expected_launch and "arm_headed" not in expected)
    )
    if has_warning and expected_status != "cross-origin":
        expected_status = "not-comparable"
    if expected and not has_warning and expected_status != "cross-origin" and not unexpected:
        expected_status = "method-control"
    if unexpected and expected_status != "cross-origin":
        expected_status = "not-comparable"
    if comparison["status"] != expected_status:
        raise ContractError(invalid)
    if "arm_headed" in mismatches:
        headed = mismatches["arm_headed"]
        if any(
            (headed[side] if isinstance(headed[side], bool) else None)
            is not comparison[f"{side}_headed"]
            for side in ("left", "right")
        ):
            raise ContractError(invalid)
    if "arm_viewport" in mismatches and any(
        mismatches["arm_viewport"][side] != comparison[f"{side}_viewport"]
        for side in ("left", "right")
    ):
        raise ContractError(invalid)
    if expected_viewport_values_differ and "arm_viewport" not in mismatches:
        raise ContractError(invalid)
    expected_control = bool(
        comparison["status"] == "method-control"
        and expected
        and not unexpected
        and left_ready is True
        and right_ready is True
        and not (
            comparison.get("viewport_crosses_responsive_gate") is True
            and "arm_viewport" not in expected
        )
        and not (expected_launch and "arm_headed" not in expected)
    )
    if (
        type(comparison.get("raw_surfaces_involved")) is not bool
        or comparison["raw_surfaces_involved"]
        is not (not left_attributed or not right_attributed)
        or type(comparison.get("attribution_kinds_differ")) is not bool
        or comparison["attribution_kinds_differ"] is not (
            left_attributed != right_attributed
        )
        or comparison["controlled_method_comparison"] is not expected_control
        or (comparison["status"] == "method-control" and not expected_control)
        or type(comparison.get("launch_mode_differs")) is not bool
        or comparison["launch_mode_differs"] is not expected_launch
        or type(comparison.get("viewport_differs")) is not bool
        or type(comparison.get("viewport_values_differ")) is not bool
        or comparison["viewport_values_differ"] is not expected_viewport_values_differ
        or type(comparison.get("viewport_crosses_responsive_gate")) is not bool
        or comparison["viewport_crosses_responsive_gate"] is not expected_viewport_gate
        or comparison["viewport_differs"]
        is not comparison["viewport_crosses_responsive_gate"]
    ):
        raise ContractError(invalid)


def _validate_rendered_diff_rows(diff: dict[str, Any], *, resource: bool) -> None:
    field = "resource_intents" if resource else "request_activity"
    if field not in diff:
        return
    invalid = "rendered digest comparison rows are inconsistent"
    report = diff[field]
    if type(report) is not dict:
        raise ContractError(invalid)
    statuses = (
        {"missing", "ok", "failed", "off", "unverifiable", "unknown"}
        if resource
        else {"missing", "ok", "unverifiable", "unknown"}
    )
    left_status = report.get("left_status")
    right_status = report.get("right_status")
    left_kind = report.get("left_row_kind")
    right_kind = report.get("right_row_kind")
    if (
        left_status not in statuses
        or right_status not in statuses
        or left_kind not in {"missing", "raw", "introduced"}
        or right_kind not in {"missing", "raw", "introduced"}
        or (left_status == "missing") is not (left_kind == "missing")
        or (right_status == "missing") is not (right_kind == "missing")
    ):
        raise ContractError(invalid)
    comparable = left_status == right_status == "ok" and left_kind == right_kind
    if type(report.get("comparable")) is not bool or report["comparable"] is not comparable:
        raise ContractError(invalid)
    row_key = "intents" if resource else "rows"
    sanitizer = (
        _sanitize_resource_intent_report if resource else _sanitize_request_activity_report
    )

    def checked_rows(rows: Any, count: int) -> None:
        if type(rows) is not list or len(rows) != min(count, RESOURCE_INTENT_ROWS_LIMIT):
            raise ContractError(invalid)
        projected = sanitizer({"status": "ok", row_key: rows})
        if projected.get("status") != "ok" or projected.get(row_key) != rows:
            raise ContractError(invalid)

    for side in ("left", "right"):
        count = report.get(f"only_{side}")
        if type(count) is not int or not 0 <= count <= 128:
            raise ContractError(invalid)
        checked_rows(report.get(f"only_{side}_rows"), count)
    if resource:
        shared = report.get("shared")
        if type(shared) is not int or not 0 <= shared <= 128:
            raise ContractError(invalid)
        if any(
            type(report.get(f"only_{side}_omitted")) is not int
            or report[f"only_{side}_omitted"]
            != max(0, report[f"only_{side}"] - RESOURCE_INTENT_ROWS_LIMIT)
            for side in ("left", "right")
        ):
            raise ContractError(invalid)
        expected_non_claim = RESOURCE_INTENT_CORPUS_NON_CLAIM
    else:
        shared = report.get("shared_shapes")
        changed = report.get("changed")
        if (
            type(shared) is not int
            or not 0 <= shared <= 128
            or type(changed) is not int
            or not 0 <= changed <= shared
        ):
            raise ContractError(invalid)
        changed_rows = report.get("changed_rows")
        if type(changed_rows) is not list or len(changed_rows) != min(
            changed, RESOURCE_INTENT_ROWS_LIMIT
        ):
            raise ContractError(invalid)
        for row in changed_rows:
            if type(row) is not dict or any(
                type(row.get(key)) is not dict for key in ("shape", "left", "right")
            ):
                raise ContractError(invalid)
            # A comparison deliberately repeats one shape across its three
            # positions. Validate each row as a row, not as a capture snapshot.
            for key in ("shape", "left", "right"):
                checked_rows([row[key]], 1)
            if (
                row["shape"] != row["left"]
                or _request_shape_key(row["left"])
                != _request_shape_key(row["right"])
                or all(
                    row["left"].get(metric) == row["right"].get(metric)
                    for metric in (
                        "count",
                        "body_bytes_total",
                        "body_bytes_min",
                        "body_bytes_max",
                        "body_sha256_16_counts",
                    )
                )
            ):
                raise ContractError(invalid)
        omitted = sum(
            max(0, report[field] - RESOURCE_INTENT_ROWS_LIMIT)
            for field in ("only_left", "only_right", "changed")
        )
        if type(report.get("rows_omitted")) is not int or report["rows_omitted"] != omitted:
            raise ContractError(invalid)
        expected_non_claim = _sanitize_request_activity_report(
            {"status": "ok", "rows": []}
        )["non_claim"]
    if report.get("non_claim") != expected_non_claim:
        raise ContractError(invalid)


@_normalize_renderer_failures("digest")
def render_digest(digest: dict[str, Any]) -> str:
    """Render a digest as compact fixed-width text.

    Text rather than JSON is the default rendering because the consumer reads it
    directly; JSON stays available for programmatic use. Output is bounded: the
    technique table cannot exceed the taxonomy size regardless of input.
    """
    if not isinstance(digest, dict):
        raise ContractError("rendered digest input must be an object")
    schema = digest.get("schema")
    out: list[str] = []
    if schema == DIGEST_SCHEMA:
        if "source_schema" not in digest or "attributed" not in digest:
            raise ContractError("rendered digest structure is invalid")
        _validate_rendered_digest_attribution(digest)
        _validate_rendered_digest_counts(digest)
        _validate_rendered_digest_identity_and_focus(digest)
        _validate_rendered_digest_provenance(digest)
        _validate_rendered_digest_input_delivery(digest)
        _validate_rendered_digest_execution(digest)
        _validate_rendered_digest_noise(digest)
        for field, resource in (("resource_intents", True), ("request_activity", False)):
            if field in digest:
                _validate_rendered_digest_side_view(
                    digest[field], attributed=digest["attributed"], resource=resource
                )
        if any(
            key in digest and type(digest[key]) is not bool
            for key in ("clean_subtraction", "surface_claim_ready")
        ):
            raise ContractError("rendered digest claim readiness is invalid")
        kind = "attributed surface" if digest["attributed"] else "RAW surface"
        out.append(f"{digest['label']}  [{kind}]")
        pin = digest.get("script_sha256_16")
        if pin:
            out.append(f"script pin        {pin}")
        raw_boundary = digest.get("analysis_boundary")
        boundary = sanitize_product_script_analysis_boundary(raw_boundary)
        if raw_boundary is not None and boundary is None:
            raise ContractError("rendered digest analysis boundary is invalid")
        if boundary is not None:
            # The producer-owned sanitizer has already reconstructed one exact
            # closed receipt, so the hyphenated kind is safe to render and does
            # not need a second drift-prone vocabulary in this consumer.
            heading = boundary["kind"].replace("-", " ").upper()
            out.append("analysis boundary  " + heading)
            out.append("  " + boundary["interpretation"])
            out.append("  non-claim: " + boundary["non_claim"])
        source = digest.get("source_provenance") or {}
        if source.get("status") == "verified_digest":
            shape = source["source_url_shape"]
            query_names = ",".join(shape["query_names"]) or "-"
            out.append(
                f"public source     VERIFIED {shape['origin']} "
                f"path-lengths={shape['path_segment_lengths']} "
                f"query-keys=[{query_names}] retrieved={source['retrieved_at']}"
            )
        prov = digest.get("provenance") or {}
        status = prov.get("status")
        if status == "not_checked":
            out.append("origin    NOT CHECKED - label is operator-asserted")
        elif status == "UNVERIFIED":
            out.append("origin    UNVERIFIED - no capture manifest records these bytes")
        elif status == "VERIFIED":
            hosts = ", ".join(prov.get("recorded_hosts") or []) or "recorded"
            out.append(f"origin    VERIFIED {hosts}")
            if prov.get("directory_disagrees_with_manifest"):
                out.append(
                    "          WARNING bytes also sit in directories no manifest "
                    "ties them to"
                )
        if digest.get("attribution_warning"):
            out.append("!! NOT ATTRIBUTED  " + digest["attribution_warning"])
            noise = digest.get("known_control_noise")
            if noise:
                out.append(
                    f"!! known noise     chromium-internal "
                    f"({noise['chromium-internal']} names) is present identically "
                    f"in the empty-script control"
                )
        if digest.get("empty_surface_warning"):
            out.append("!! EMPTY SURFACE   " + digest["empty_surface_warning"])
        if "clean_subtraction" in digest and not digest["clean_subtraction"]:
            out.append(
                "WARNING          subtraction was not clean; surface is untrustworthy"
            )
        elif digest.get("surface_claim_ready") is False:
            out.append(
                "WARNING          subtraction is not claim-ready; surface is untrustworthy"
            )
        collector_startup = digest.get("collector_startup")
        if isinstance(collector_startup, dict) and collector_startup.get(
            "browser_target_status"
        ):
            status = collector_startup["browser_target_status"]
            title_match = collector_startup.get("browser_target_title_matches")
            title_suffix = (
                ", fixed title matched"
                if title_match is True
                else ", fixed title did not match"
                if title_match is False
                else ""
            )
            out.append(f"renderer target    {status}{title_suffix}")
        script_execution = digest.get("script_execution")
        control_script_execution = digest.get("control_script_execution")
        if isinstance(script_execution, dict):
            arm_open = script_execution.get("open", 0)
            control_open = (
                control_script_execution.get("open", 0)
                if isinstance(control_script_execution, dict)
                else None
            )
            if arm_open > 0 or (control_open is not None and control_open > 0):
                comparison = f"arm {arm_open} open"
                if control_open is not None:
                    comparison += f", control {control_open} open"
                out.append(
                    "!! SCRIPT ACTIVE    "
                    f"{comparison}; top-level execution scope(s) "
                    "were still open when tracing stopped"
                )
            elif script_execution.get("complete", 0) > 0 or (
                isinstance(control_script_execution, dict)
                and control_script_execution.get("complete", 0) > 0
            ):
                comparison = (
                    f"arm {script_execution['complete']} complete, "
                    f"{script_execution['open']} open"
                )
                if isinstance(control_script_execution, dict):
                    comparison += (
                        f"; control {control_script_execution['complete']} complete, "
                        f"{control_script_execution['open']} open"
                    )
                out.append("script execution   " + comparison)
        amp_total = digest.get("amplified_api_names", 0)
        summary = (
            f"{digest['total_api_names']} api names introduced, "
            f"{digest['total_calls']} calls, {digest['techniques_observed']} techniques"
        )
        if amp_total:
            summary += f"; {amp_total} amplified"
        out.append(summary)
        # What "introduced" means, said where the number is read.
        #
        # The count is what the arm touched **and an empty-script control did
        # not**, so it omits everything the collector and an idle browser both do
        # -- which is exactly where ambient-property fingerprinting lives.
        # Measured 2026-08-08: the driven Kasada client provably reads
        # `navigator.userAgent`, and that read is absent from its 29 attributed
        # names. A reader who takes the number as "what this collector reads" will
        # be most wrong about the collectors that work hardest to look ordinary.
        if digest.get("attributed"):
            if digest.get("script_attribution_comparable") is True:
                out.append(
                    "                  = arm-only names plus positive current-script "
                    "count deltas shared with control"
                )
            else:
                out.append(
                    "                  = what the script touched that an empty-script "
                    "control did not"
                )
        out.append("")
        out.append(f"{'technique':<20}{'names':>7}{'calls':>8}{'ampl':>6}  interfaces")
        out.append("-" * 76)
        for tech, row in digest["techniques"].items():
            ifaces = ", ".join(row["interfaces"])
            more = row["interfaces_total"] - len(row["interfaces"])
            if more > 0:
                ifaces += f", +{more} more"
            amp = row.get("amplified", 0)
            out.append(
                f"{tech:<20}{row['api_names']:>7}{row['calls']:>8}"
                f"{(amp or ''):>6}  {ifaces[:42]}"
            )
        out.append("-" * 76)
        amp_only = digest.get("amplified_only_techniques") or {}
        if amp_only:
            out.append(
                "amplified only (introduced nothing, but called far more than the "
                "control): " + ", ".join(f"{t} x{n}" for t, n in amp_only.items())
            )
        if digest["not_observed"]:
            out.append("not observed: " + ", ".join(digest["not_observed"]))
        focus = digest.get("focus")
        if focus:
            out.append("")
            out.append(f"--- {focus['technique']} ({focus['count']} names) ---")
            out.extend(f"  {n}" for n in focus["api_names"])
        input_delivery = digest.get("input_delivery")
        if input_delivery:
            out.append("")
            if input_delivery.get("contaminated"):
                out.append("!! INPUT CONTAMINATION  " + input_delivery["note"])
                out.append(
                    "  "
                    + _format_input_delivery_role(
                        "arm",
                        input_delivery.get("arm_probe"),
                        input_delivery.get("arm_ambient"),
                    )
                )
                if input_delivery["attributed"]:
                    out.append(
                        "  "
                        + _format_input_delivery_role(
                            "control",
                            input_delivery.get("control_probe"),
                            input_delivery.get("control_ambient"),
                        )
                    )
            else:
                status = "VERIFIED" if input_delivery["verified"] else "UNVERIFIED"
                out.append(f"input delivery  {input_delivery['profile']}  {status}")
                out.append(
                    "  "
                    + _format_input_delivery_role(
                        "arm",
                        input_delivery.get("arm_probe"),
                        input_delivery.get("arm_ambient"),
                    )
                )
                if input_delivery["attributed"]:
                    out.append(
                        "  "
                        + _format_input_delivery_role(
                            "control",
                            input_delivery.get("control_probe"),
                            input_delivery.get("control_ambient"),
                        )
                    )
                out.append("  non-claim: " + input_delivery["note"])
        intents = digest.get("resource_intents")
        if intents:
            out.append("")
            if intents["status"] != "ok":
                out.append(
                    "resource intents  UNVERIFIABLE "
                    f"(snapshot status {intents['status']})"
                )
                if intents.get("diagnostic"):
                    out.append(f"  diagnostic: {intents['diagnostic']}")
            else:
                kind = intents["row_kind"]
                prefix = "!! NOT ATTRIBUTED  " if not intents["attributed"] else ""
                out.append(
                    f"{prefix}resource intents  {intents['rows_total']} {kind} "
                    "DOM attribute(s)"
                )
                if intents.get("control_only_total"):
                    out.append(
                        f"  WARNING {intents['control_only_total']} control-only "
                        "attribute(s); subtraction is not clean"
                    )
                for row in intents["rows"]:
                    out.append("  " + _format_resource_intent_row(row))
                if intents["rows_omitted"]:
                    out.append(f"  +{intents['rows_omitted']} more (bounded)")
                out.append("  non-claim: " + intents["non_claim"])
        requests = digest.get("request_activity")
        if requests:
            out.append("")
            if requests["status"] != "ok":
                out.append(
                    "loopback request activity  UNVERIFIABLE "
                    f"(status {requests['status']})"
                )
            else:
                prefix = "!! NOT ATTRIBUTED  " if not requests["attributed"] else ""
                out.append(
                    f"{prefix}loopback request activity  {requests['rows_total']} "
                    f"{requests['row_kind']} shape(s)"
                )
                if requests.get("control_only_total"):
                    out.append(
                        f"  WARNING {requests['control_only_total']} control-only "
                        "shape(s); subtraction is not clean"
                    )
                for row in requests["rows"]:
                    out.append("  " + _format_request_activity_row(row))
                if requests["rows_omitted"]:
                    out.append(f"  +{requests['rows_omitted']} more (bounded)")
                out.append("  non-claim: " + requests["non_claim"])
    elif schema == DIFF_SCHEMA:
        _validate_rendered_diff_counts(digest)
        _validate_rendered_diff_focus(digest)
        _validate_rendered_diff_input_delivery(digest)
        _validate_rendered_diff_comparability(digest)
        _validate_rendered_diff_rows(digest, resource=True)
        _validate_rendered_diff_rows(digest, resource=False)
        out.append(f"{digest['left_label']}  vs  {digest['right_label']}")
        comparability = digest.get("comparability") or {}
        if comparability.get("left_claim_ready") is False or comparability.get(
            "right_claim_ready"
        ) is False:
            out.append(
                "!! NOT CLAIM-READY  at least one subtraction cannot support a "
                "collector absence claim"
            )
        if comparability.get("raw_surfaces_involved"):
            out.append(
                "!! NOT ATTRIBUTED  at least one raw surface includes browser "
                "and host work"
            )
        if comparability.get("controlled_method_comparison"):
            axes = ", ".join(
                field.removeprefix("arm_")
                for field in comparability.get("expected_method_mismatches", {})
            )
            out.append(
                f"METHOD CONTROL  {axes}. Declared method axes differ; "
                "interpret this as a method control"
            )
        elif comparability.get(
            "viewport_crosses_responsive_gate",
            comparability.get("viewport_differs"),
        ):
            out.append(
                "!! VIEWPORT DIFFERS  heights cross the measured responsive "
                "boundary; repeat at matching geometry"
            )
        elif comparability.get("launch_mode_differs"):
            out.append(
                "!! LAUNCH MODE DIFFERS  repeat with one launch mode before "
                "attributing a surface difference"
            )
        elif comparability.get("method_differs"):
            axes = ", ".join(
                field.removeprefix("arm_")
                for field in comparability.get("method_mismatches", {})
            )
            out.append(
                f"!! METHOD DIFFERS  {axes}. Repeat with one method before "
                "attributing a surface difference"
            )
        elif comparability.get("status") == "cross-origin":
            out.append(
                "!! CROSS-DEPLOYMENT  recorded origins differ; compare within "
                "one deployment before making a roll claim"
            )
        elif comparability.get("status") == "same-origin":
            out.append("origin    same recorded origin")
        input_delivery = digest.get("input_delivery")
        if input_delivery:
            for side in ("left", "right"):
                delivery = input_delivery.get(side)
                if not delivery:
                    out.append(f"input {side:<7} no verified delivery record")
                    continue
                if delivery.get("intentional_no_input"):
                    out.append(
                        f"input {side:<7} none (declared no-input control; "
                        "no delivery receipt expected)"
                    )
                    continue
                status = "VERIFIED" if delivery.get("verified") else "UNVERIFIED"
                out.append(
                    f"input {side:<7} {delivery['profile']} {status}; "
                    + _format_input_delivery_role(
                        "arm",
                        delivery.get("arm_probe"),
                        delivery.get("arm_ambient"),
                    )
                )
        out.append(
            f"{digest['left_api_names']} vs {digest['right_api_names']} api names; "
            f"shared {digest['shared']}; jaccard {digest['jaccard']}"
        )
        if digest["identical_surface"]:
            out.append("surfaces are identical")
        else:
            out.append(
                f"only-left {digest['only_left']}   only-right {digest['only_right']}"
            )
            out.append("")
            out.append(
                f"{'technique':<20}{'only-left':>11}{'only-right':>12}{'shared':>8}"
            )
            out.append("-" * 51)
            for tech, row in digest["techniques_differing"].items():
                out.append(
                    f"{tech:<20}{row['only_left']:>11}{row['only_right']:>12}"
                    f"{row['shared']:>8}"
                )
            out.append("-" * 51)
        focus = digest.get("focus")
        if focus:
            out.append("")
            out.append(f"--- {focus['technique']} ---")
            for n in focus["only_left"]:
                out.append(f"  left-only   {n}")
            for n in focus["only_right"]:
                out.append(f"  right-only  {n}")
        intents = digest.get("resource_intents")
        if intents:
            out.append("")
            out.append(
                "resource intents  "
                f"left {intents['left_status']}/{intents['left_row_kind']}, "
                f"right {intents['right_status']}/{intents['right_row_kind']}"
            )
            if not intents["comparable"]:
                out.append(
                    "!! RESOURCE INTENTS NOT COMPARABLE  both snapshots must be "
                    "successful and have the same attribution kind"
                )
            else:
                out.append(
                    f"shared {intents['shared']}; only-left {intents['only_left']}; "
                    f"only-right {intents['only_right']}"
                )
                for row in intents["only_left_rows"]:
                    out.append("  left-only   " + _format_resource_intent_row(row))
                for row in intents["only_right_rows"]:
                    out.append("  right-only  " + _format_resource_intent_row(row))
                if intents["only_left_omitted"] or intents["only_right_omitted"]:
                    out.append(
                        "  bounded: "
                        f"{intents['only_left_omitted']} additional left, "
                        f"{intents['only_right_omitted']} additional right"
                    )
                out.append("  non-claim: " + intents["non_claim"])
        requests = digest.get("request_activity")
        if requests:
            out.append("")
            out.append(
                "loopback request activity  "
                f"left {requests['left_status']}/{requests['left_row_kind']}, "
                f"right {requests['right_status']}/{requests['right_row_kind']}"
            )
            if not requests["comparable"]:
                out.append(
                    "!! REQUEST ACTIVITY NOT COMPARABLE  both reports must be "
                    "successful and have the same attribution kind"
                )
            else:
                out.append(
                    f"shared shapes {requests['shared_shapes']}; changed metrics "
                    f"{requests['changed']}; only-left {requests['only_left']}; "
                    f"only-right {requests['only_right']}"
                )
                for row in requests["only_left_rows"]:
                    out.append("  left-only   " + _format_request_activity_row(row))
                for row in requests["only_right_rows"]:
                    out.append("  right-only  " + _format_request_activity_row(row))
                for row in requests["changed_rows"]:
                    left_row, right_row = row["left"], row["right"]
                    digest_change = (
                        "; body-digest multisets differ"
                        if left_row.get("body_sha256_16_counts")
                        != right_row.get("body_sha256_16_counts")
                        else ""
                    )
                    out.append(
                        "  changed     "
                        + _format_request_activity_row(row["shape"])
                        + f"; left x{left_row.get('count', 0)}/"
                        f"{left_row.get('body_bytes_total', 0)} bytes, right "
                        f"x{right_row.get('count', 0)}/"
                        f"{right_row.get('body_bytes_total', 0)} bytes" + digest_change
                    )
                if requests["rows_omitted"]:
                    out.append(
                        f"  +{requests['rows_omitted']} more change(s) (bounded)"
                    )
                out.append("  non-claim: " + requests["non_claim"])
    else:  # pragma: no cover - defensive
        raise ContractError("rendered digest schema is invalid")
    return "\n".join(out)


# ---------------------------------------------------------------- batch audit

BATCH_AUDIT_SCHEMA = "browser-core.observation-batch-audit/1"


def _batch_method(document: dict[str, Any]) -> dict[str, Any]:
    """The shared surface-method signature for raw arms and subtractions."""
    if document.get("schema") == SUBTRACTION_SCHEMA:
        return _surface_method(document)
    projected = {
        "arm_headed": document.get("headed"),
        "arm_viewport": document.get("viewport"),
        "arm_trace_scope": document.get("trace_scope"),
        "arm_trace_category_contract": document.get("trace_category_contract"),
        "arm_chromium_revision": document.get("chromium_revision"),
        "arm_browser_build": _browser_build_method(document),
        "arm_timeout_seconds": document.get("timeout_seconds"),
        "arm_dwell_seconds": document.get("dwell_seconds"),
        "arm_dom_profile": document.get("dom_profile"),
        "arm_rehost_contract": document.get("rehost_contract"),
        "arm_hook_mode": document.get("hook_mode", "off"),
        "arm_hook_target_names": sorted(document.get("hook_target_names") or []),
        "arm_input_profile": document.get("input_profile", "none"),
        "arm_inline_script": document.get("inline_script"),
        "arm_reloads": document.get("reloads"),
        "arm_script_path": document.get("script_path"),
        "arm_declared_script_url": document.get("declared_script_url"),
        "arm_prelude": _prelude_document_metadata(document),
        "arm_driver": _driver_metadata(document),
        "arm_driver_supplied": _driver_supplied(document),
        "arm_await_ready_seconds": document.get("await_ready_seconds"),
        "arm_ready_expression": _ready_expression_metadata(document),
        "arm_resource_intent_capture": document.get("resource_intent_capture"),
        "arm_extra_browser_args": document.get("extra_browser_args"),
        "arm_stage_routes": _observation_stage_routes(document),
    }
    return _surface_method(projected)


def _axis_value(value: Any) -> str:
    """Canonical, typed JSON key for one method value.

    JSON reports use axis values as object keys. Leaving scalars in their native
    Python types makes ``json.dumps(sort_keys=True)`` crash when one legacy arm
    records ``None`` and another records a number. Canonical JSON strings remain
    sortable and distinguish the string ``"null"`` from the null value ``null``.
    """
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _axis_display(value: str) -> str:
    """Render a canonical axis key without JSON quotes around ordinary strings."""
    try:
        decoded = json.loads(value)
    except (TypeError, ValueError):
        return str(value)
    if isinstance(decoded, str):
        return decoded if decoded.isprintable() else json.dumps(decoded, ensure_ascii=True)
    return json.dumps(decoded, sort_keys=True, separators=(",", ":"))


def _method_population(
    documents: list[tuple[str, dict[str, Any]]],
) -> dict[str, Any]:
    """Audit one population against the shared, redaction-safe method signature."""
    axes: dict[str, Counter] = {
        field.removeprefix("arm_"): Counter() for field in SURFACE_METHOD_FIELDS
    }
    for _label, document in documents:
        method = _batch_method(document)
        for field in SURFACE_METHOD_FIELDS:
            axes[field.removeprefix("arm_")][_axis_value(method[field])] += 1
    mixed = sorted(axis for axis, counts in axes.items() if len(counts) > 1)
    return {
        "arms": len(documents),
        "same_method": bool(documents) and not mixed,
        "mixed_axes": mixed,
        "axes": {axis: dict(counts.most_common()) for axis, counts in axes.items()},
    }


def _failure_kind(value: Any) -> dict[str, str]:
    """Project a local arm diagnostic into a path- and value-free category."""
    if not isinstance(value, str):
        return {"phase": "observation failed", "exception": "unknown"}
    lines = value[:4096].splitlines()
    text = lines[0].strip() if lines else ""
    phase = "observation failed"
    for known in (
        "trace export failed",
        "rehost server could not bind",
        "stop failed",
        "stop",
    ):
        if text.lower().startswith(known):
            phase = known
            break
    exception_match = re.search(
        r"\b([A-Za-z][A-Za-z0-9_]{0,79}(?:Error|Exception))\b", text
    )
    exception = exception_match.group(1) if exception_match else "unknown"
    return {"phase": phase, "exception": exception}


def _batch_audit_warnings(
    failed: int,
    unparseable: int,
    unready: int,
    raw: int,
    mixed_axes: list[str],
) -> list[str]:
    warnings: list[str] = []
    if failed:
        warnings.append(
            f"{failed} arm(s) produced no data; any negative result "
            "computed over this batch is not a negative result"
        )
    if unparseable:
        warnings.append(
            f"{unparseable} JSON file(s) could not be classified; an unreadable "
            "file cannot support a negative claim"
        )
    if unready:
        warnings.append(
            f"{unready} subtraction arm(s) produced data but were not claim-ready; "
            "they cannot support a negative claim"
        )
    if raw:
        warnings.append(
            f"{raw} raw surface(s) are not attributed to the script; this batch "
            "cannot support a collector absence claim"
        )
    if mixed_axes:
        warnings.append(
            f"arms differ on {', '.join(mixed_axes)}; they are not one population"
        )
    return warnings


def audit_batch(documents: dict[str, dict[str, Any]]) -> dict[str, Any]:
    """Report which arms in a run directory are usable, and why the rest are not.

    Written from a measured mistake. A wrapper-bisection on 2026-08-07 ran seven
    subsets and reported "no markers" for every one -- but **two of the seven runs
    had failed outright** (`Perfetto trace does not exist`) and were counted as
    clean negatives. A negative result from a run that never produced data is not a
    negative result, and nothing in the artifacts made that visible without a
    hand-written script.

    So this answers "is this batch trustworthy?" before anyone reads conclusions out
    of it. It uses the same method signature as pairwise comparison and drift
    gates. A batch that mixes any execution axis is not one population, and such
    mixing produced a withdrawn "configuration ladder" in an earlier session.
    """
    if type(documents) is not dict or not 1 <= len(documents) <= MAX_CORPUS_ARMS:
        raise ContractError(
            "batch audit needs at least one document and at most "
            f"{MAX_CORPUS_ARMS:,} documents"
        )
    checked_documents: list[tuple[str, dict[str, Any]]] = []
    for raw_label, document in documents.items():
        label = _bounded_text(
            raw_label,
            maximum=MAX_CORPUS_LABEL_BYTES,
            label="batch audit label",
        )
        if not isinstance(document, dict):
            raise ContractError("batch audit document entry is invalid")
        checked_documents.append((label, document))

    usable: list[str] = []
    unready_labels: list[str] = []
    raw_labels: list[str] = []
    unparseable_labels: list[str] = []
    failure_detail: dict[str, dict[str, str]] = {}
    axes: dict[str, Counter] = {
        field.removeprefix("arm_"): Counter() for field in SURFACE_METHOD_FIELDS
    }
    # Retain the compact historical height view alongside the exact viewport
    # method value; operators learned the responsive gate in terms of this number.
    axes["viewport_height"] = Counter()
    for label, document in sorted(checked_documents):
        if document.get("schema") == UNPARSEABLE_JSON_SCHEMA:
            unparseable_labels.append(label)
            continue
        if "error" in document and document.get("error") is not None:
            failure_detail[label] = _failure_kind(document.get("error"))
            continue
        try:
            digest_observation(document)
        except (
            ContractError,
            TypeError,
            ValueError,
            OverflowError,
            UnicodeError,
            RecursionError,
        ):
            failure_detail[label] = {
                "phase": "invalid observation",
                "exception": "ContractError",
            }
            continue
        try:
            method = _batch_method(document)
            encoded_method = {
                field: _axis_value(method[field]) for field in SURFACE_METHOD_FIELDS
            }
        except (
            ContractError,
            TypeError,
            ValueError,
            OverflowError,
            UnicodeError,
            RecursionError,
        ):
            failure_detail[label] = {
                "phase": "invalid method",
                "exception": "ContractError",
            }
            continue
        usable.append(label)
        if document.get("schema") == SUBTRACTION_SCHEMA:
            if not _subtraction_claim_ready(document):
                unready_labels.append(label)
        else:
            raw_labels.append(label)
        for field, value in encoded_method.items():
            axes[field.removeprefix("arm_")][value] += 1
        viewport = method.get("arm_viewport") or {}
        axes["viewport_height"][viewport.get("inner_height")] += 1

    reasons: Counter = Counter(detail["phase"] for detail in failure_detail.values())
    mixed = sorted(k for k, counter in axes.items() if len(counter) > 1)
    return {
        "schema": BATCH_AUDIT_SCHEMA,
        "total": len(checked_documents),
        "usable": len(usable),
        "failed": len(failure_detail),
        "unparseable": len(unparseable_labels),
        "usable_labels": usable,
        "unready_labels": unready_labels,
        "raw_labels": raw_labels,
        "unparseable_labels": unparseable_labels,
        "failed_labels": sorted(failure_detail),
        "failure_reasons": dict(reasons.most_common()),
        "failure_detail": {k: v for k, v in sorted(failure_detail.items())},
        "axes": {k: dict(v.most_common()) for k, v in axes.items()},
        "mixed_axes": mixed,
        "trustworthy": not failure_detail and not unparseable_labels
        and not mixed and not unready_labels,
        "claim_ready_population": bool(usable)
        and not failure_detail
        and not unparseable_labels
        and not mixed
        and not unready_labels
        and not raw_labels,
        "warnings": _batch_audit_warnings(
            len(failure_detail),
            len(unparseable_labels),
            len(unready_labels),
            len(raw_labels),
            mixed,
        ),
    }


def _validate_rendered_batch_audit(report: dict[str, Any]) -> None:
    """Reconcile a portable audit before it can present a clean population."""
    if not {"total", "usable", "failed"} <= report.keys():
        raise ContractError("rendered batch audit structure is invalid")
    total = report.get("total")
    usable = report.get("usable")
    failed = report.get("failed")
    unparseable = report.get("unparseable", 0)
    if (
        any(type(value) is not int for value in (total, usable, failed, unparseable))
        or not 1 <= total <= MAX_CORPUS_ARMS
        or min(usable, failed, unparseable) < 0
        or usable + failed + unparseable != total
    ):
        raise ContractError("rendered batch audit counts are inconsistent")

    label_groups: dict[str, list[str]] = {}
    for field in (
        "usable_labels",
        "failed_labels",
        "unparseable_labels",
        "unready_labels",
        "raw_labels",
    ):
        value = report.get(field, [] if field != "usable_labels" else None)
        if type(value) is not list or len(value) > total:
            raise ContractError("rendered batch audit labels are invalid")
        checked = [
            _bounded_text(item, maximum=MAX_CORPUS_LABEL_BYTES,
                          label="rendered batch audit label")
            for item in value
        ]
        if checked != sorted(set(checked)):
            raise ContractError("rendered batch audit labels are invalid")
        label_groups[field] = checked
    usable_labels = set(label_groups["usable_labels"])
    failed_labels = set(label_groups["failed_labels"])
    unparseable_labels = set(label_groups["unparseable_labels"])
    unready_labels = set(label_groups["unready_labels"])
    raw_labels = set(label_groups["raw_labels"])
    if (
        len(usable_labels) != usable
        or len(failed_labels) != failed
        or len(unparseable_labels) != unparseable
        or usable_labels & failed_labels
        or usable_labels & unparseable_labels
        or failed_labels & unparseable_labels
        or not unready_labels <= usable_labels
        or not raw_labels <= usable_labels
        or unready_labels & raw_labels
    ):
        raise ContractError("rendered batch audit labels contradict counts")

    detail = report.get("failure_detail")
    reasons = report.get("failure_reasons")
    if type(detail) is not dict or set(detail) != failed_labels or type(reasons) is not dict:
        raise ContractError("rendered batch audit failures are invalid")
    allowed_phases = {
        "trace export failed", "rehost server could not bind", "stop failed",
        "stop", "observation failed", "invalid observation", "invalid method",
    }
    expected_reasons: Counter[str] = Counter()
    for item in detail.values():
        if type(item) is not dict or set(item) != {"phase", "exception"}:
            raise ContractError("rendered batch audit failures are invalid")
        phase, exception = item["phase"], item["exception"]
        if (
            phase not in allowed_phases
            or type(exception) is not str
            or not (
                exception == "unknown"
                or re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,79}(?:Error|Exception)", exception)
            )
        ):
            raise ContractError("rendered batch audit failures are invalid")
        expected_reasons[phase] += 1
    if reasons != dict(expected_reasons):
        raise ContractError("rendered batch audit failures contradict counts")

    axes = report.get("axes")
    expected_axes = set(CONTROL_METHOD_AXES) | {"viewport_height"}
    if type(axes) is not dict or set(axes) != expected_axes:
        raise ContractError("rendered batch audit axes are invalid")
    mixed: list[str] = []
    for axis, counts in axes.items():
        if type(counts) is not dict or len(counts) > usable:
            raise ContractError("rendered batch audit axes are invalid")
        axis_total = 0
        for key, count in counts.items():
            if type(count) is not int or not 0 < count <= usable:
                raise ContractError("rendered batch audit axes are invalid")
            axis_total += count
            if axis == "viewport_height" and (key is None or type(key) in (int, float)):
                if type(key) is float and not math.isfinite(key):
                    raise ContractError("rendered batch audit axes are invalid")
                continue
            if type(key) is not str:
                raise ContractError("rendered batch audit axes are invalid")
            try:
                decoded = json.loads(key)
            except ValueError:
                raise ContractError("rendered batch audit axes are invalid") from None
            if _axis_value(decoded) != key or (
                axis == "viewport_height"
                and decoded is not None
                and (type(decoded) not in (int, float) or not math.isfinite(decoded))
            ):
                raise ContractError("rendered batch audit axes are invalid")
        if axis_total != usable:
            raise ContractError("rendered batch audit axes contradict counts")
        if len(counts) > 1:
            mixed.append(axis)
    mixed.sort()
    if report.get("mixed_axes") != mixed:
        raise ContractError("rendered batch audit mixed axes are inconsistent")

    trustworthy = not failed and not unparseable and not mixed and not unready_labels
    claim_ready = bool(usable) and trustworthy and not raw_labels
    if (
        type(report.get("trustworthy")) is not bool
        or report["trustworthy"] is not bool(trustworthy)
        or (
            "claim_ready_population" in report
            and (
                type(report["claim_ready_population"]) is not bool
                or report["claim_ready_population"] is not bool(claim_ready)
            )
        )
    ):
        raise ContractError("rendered batch audit trust flags are inconsistent")
    if report.get("warnings") != _batch_audit_warnings(
        failed, unparseable, len(unready_labels), len(raw_labels), mixed
    ):
        raise ContractError("rendered batch audit warnings are inconsistent")
    selection = report.get("population_selection")
    if selection is not None:
        if type(selection) is not dict:
            raise ContractError("rendered batch audit selection is invalid")
        if selection:
            ignored = selection.get("ignored_labels")
            if (
                selection.get("kind") not in {
                    "attributed_subtractions", "raw_observations", "unparseable_files"
                }
                or type(selection.get("selected")) is not int
                or selection["selected"] != total
                or type(selection.get("ignored_successful_intermediates")) is not int
                or type(ignored) is not list
                or len(ignored) > MAX_CORPUS_ARMS - total
            ):
                raise ContractError("rendered batch audit selection is invalid")
            checked_ignored = [
                _bounded_text(item, maximum=MAX_CORPUS_LABEL_BYTES,
                              label="rendered batch audit selection label")
                for item in ignored
            ]
            if (
                checked_ignored != sorted(set(checked_ignored))
                or len(checked_ignored)
                != selection["ignored_successful_intermediates"]
                or set(checked_ignored)
                & (usable_labels | failed_labels | unparseable_labels)
            ):
                raise ContractError("rendered batch audit selection is invalid")


@_normalize_renderer_failures("batch audit")
def render_batch_audit(report: dict[str, Any]) -> str:
    if not isinstance(report, dict):
        raise ContractError("rendered batch audit input must be an object")
    if report.get("schema") != BATCH_AUDIT_SCHEMA:
        raise ContractError(f"not a {BATCH_AUDIT_SCHEMA} document")
    _validate_rendered_batch_audit(report)
    lines = [
        f"batch audit: {report['usable']} usable / {report['total']} "
        + ("selected files" if report.get("unparseable") else "arms")
        + (f", {report['failed']} FAILED" if report["failed"] else ""),
    ]
    selection = report.get("population_selection") or {}
    if selection:
        lines.append(
            f"  population: {selection.get('kind')}"
            f" ({selection.get('selected', report['total'])} selected, "
            f"{selection.get('ignored_successful_intermediates', 0)} successful "
            "intermediate(s) ignored)"
        )
    for warning in report.get("warnings") or []:
        lines.append(f"  !! {warning}")
    if report.get("failure_reasons"):
        lines.append("")
        lines.append("  failures by cause:")
        for reason, count in report["failure_reasons"].items():
            lines.append(f"      {count:>3}x  {reason}")
        lines.append("  failed arms: " + ", ".join(report["failed_labels"][:10]))
    lines.append("")
    lines.append("  comparability axes across usable arms:")
    for axis, counts in report["axes"].items():
        rendered = (
            ", ".join(f"{_axis_display(k)}={v}" for k, v in counts.items()) or "-"
        )
        flag = "  <- MIXED" if axis in report.get("mixed_axes", []) else ""
        lines.append(f"      {axis:<16} {rendered}{flag}")
    if report["trustworthy"]:
        lines.append("")
        lines.append(
            "  every arm produced data and they agree on every comparability axis"
        )
    return "\n".join(lines) + "\n"
