from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from .control_files import (
    MAX_SESSION_DOCUMENT_BYTES,
    decode_strict_json_bytes,
    read_bounded_control_snapshot_result,
)
from .errors import ContractError
from .binding_context import validate_js_stack
from .numeric import is_finite_number
from .owned_paths import parse_directory_identity
from .trace_scopes import (
    TRACE_CATEGORY_CONTRACTS,
    TRACE_SCOPES,
    valid_trace_categories,
)


SESSION_SCHEMA = "browser-core.session/1"
TRACE_SCHEMA = "browser-core.trace-event/1"
REVISION_RE = re.compile(r"^[0-9a-f]{40}$")
RUN_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
MAX_TRACE_EVENT_DURATION_NS = 7 * 24 * 60 * 60 * 1_000_000_000
MAX_SAFE_INTEGER = (1 << 53) - 1
MAX_GEO_DISTANCE_KM = 21_000.0
MAX_URL_CLASS_CHARS = 4_192
URL_CLASS_RE = re.compile(
    r"^(?:[a-z][a-z0-9+.-]{0,63}:)?(?:same-origin|cross-origin):"
    r"(?:/(?!/)[^\x00-\x1f\x7f?#]{0,4095}|<redacted>)$"
)
HTTP_METHOD_RE = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]{1,64}$")
FETCH_TARGET_SCOPES = frozenset({"loopback", "external", "non-network"})
WEBCRYPTO_DIGEST_ALGORITHMS = frozenset({"SHA-1", "SHA-256", "SHA-384", "SHA-512"})
# Pinned Chromium enables the V8 sandbox, whose ArrayBuffer ceiling is 32 GiB - 1.
MAX_TRACE_BUFFER_BYTES = 32 * 1024 * 1024 * 1024 - 1
MAX_WASM_MODULE_BYTES = 1024 * 1024 * 1024
# HTMLCanvasElement normalizes parsed width/height values above signed-int max
# back to its defaults before the pinned native trace point observes Size().
MAX_CANVAS_DIMENSION = 2_147_483_647
GENERATED_BINDING_NAME_RE = re.compile(
    r"^[A-Za-z_][A-Za-z0-9_]{0,127}\."
    r"[A-Za-z_][A-Za-z0-9_]{0,127}(?:\.(?:get|set))?$"
)
CALLBACK_DESCRIPTOR_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")
CALLBACK_KINDS = frozenset({"constructor", "function"})
GENERATED_BINDING_TRACE_CATEGORIES = frozenset(
    {"blink.bindings", "blink.bindings.encoding"}
)
ENCODING_BINDING_INTERFACES = frozenset(
    {"TextDecoder", "TextDecoderStream", "TextEncoder", "TextEncoderStream"}
)
BODY_CONSUMER_MODES = frozenset(
    {"array-buffer", "blob", "bytes", "form-data", "json", "text"}
)
EXACT_NATIVE_EVENT_ROUTES = {
    "BrowserCore.ScriptRun": ("execution", "script.run", "script run"),
    "BrowserCore.ScriptSourceIdentity": (
        "execution", "script.source.identity", "script source identity"
    ),
    "BrowserCore.ScriptSourceContext": (
        "execution", "script.source.context", "script source context"
    ),
    "BrowserCore.ScriptExecution": (
        "execution", "script.execution", "script execution"
    ),
    "BrowserCore.HostCallbackExecution": (
        "execution", "host.callback.execution", "host callback execution"
    ),
    "BrowserCore.PromiseMicrotaskExecution": (
        "execution", "promise.microtask.execution", "promise microtask execution"
    ),
    "BrowserCore.DynamicCodeMaterialized": (
        "execution", "dynamic.code.materialized", "dynamic code materialization"
    ),
    "BrowserCore.CanvasReadback": (
        "api", "HTMLCanvasElement.toDataURL", "canvas readback"
    ),
    "BrowserCore.CryptoDigest": ("crypto", "SubtleCrypto.digest", "crypto digest"),
    "BrowserCore.WasmCompiled": (
        "wasm", "WebAssembly.compile.completed", "WASM compile"
    ),
    "BrowserCore.FetchCall": ("api", "fetch", "fetch API"),
    "BrowserCore.FetchRequestStart": (
        "network", "fetch.request.start", "fetch request"
    ),
    "BrowserCore.MessagePost": (
        "message", "MessagePort.postMessage", "message post"
    ),
    "BrowserCore.MessageDispatch": (
        "message", "MessagePort.message.dispatch", "message dispatch"
    ),
    "BrowserCore.StreamReadRequest": (
        "stream", "stream.read.request", "stream request"
    ),
    "BrowserCore.StreamReadResult": (
        "stream", "stream.read.result", "stream result"
    ),
    "BrowserCore.BodyConsume": ("stream", "body.consume", "body consumer"),
}
# Accepted by the exporter for isolated traces, but absent from the pinned
# native patch series. Keep these out of that series' route attestation.
UNPROMOTED_NATIVE_EVENT_ROUTES = frozenset({
    "BrowserCore.ScriptSourceIdentity", "BrowserCore.ScriptSourceContext",
})
EXACT_NATIVE_EVENT_COMPONENTS = {
    "BrowserCore.ScriptRun": "blink.v8",
    "BrowserCore.ScriptSourceIdentity": "v8.compiler",
    "BrowserCore.ScriptSourceContext": "blink.v8",
    "BrowserCore.ScriptExecution": "blink.v8",
    "BrowserCore.HostCallbackExecution": "blink.bindings.callback",
    "BrowserCore.PromiseMicrotaskExecution": "blink.scheduler.promise",
    "BrowserCore.DynamicCodeMaterialized": "v8.compiler",
    "BrowserCore.CanvasReadback": "blink.canvas",
    "BrowserCore.CryptoDigest": "blink.webcrypto",
    "BrowserCore.WasmCompiled": "v8.wasm",
    "BrowserCore.FetchCall": "blink.fetch",
    "BrowserCore.FetchRequestStart": "blink.fetch",
    "BrowserCore.MessagePost": "blink.messaging",
    "BrowserCore.MessageDispatch": "blink.messaging",
    "BrowserCore.StreamReadRequest": "blink.streams",
    "BrowserCore.StreamReadResult": "blink.streams",
    "BrowserCore.BodyConsume": "blink.fetch-body",
}
EXACT_NATIVE_TRACE_CATEGORIES = {
    native_name: (
        "browser_core.stream"
        if native_name in {
            "BrowserCore.StreamReadRequest",
            "BrowserCore.StreamReadResult",
            "BrowserCore.BodyConsume",
        }
        else "browser_core.debug"
    )
    for native_name in EXACT_NATIVE_EVENT_ROUTES
}
SENSITIVE_KEYS = {
    "authorization",
    "cookie",
    "set-cookie",
    "password",
    "proxy",
    "secret",
    "token",
    "api-key",
    "client-secret",
    "session-token",
    "access-token",
    "refresh-token",
    "raw-key",
    "private-key",
    "request-body",
}


def _require_dict(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ContractError(f"{label} must be an object")
    return value


def _require_int(value: Any, label: str, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise ContractError(f"{label} must be an integer >= {minimum}")
    return value


def _allowed_string(value: Any, choices: set[str] | frozenset[str]) -> bool:
    return isinstance(value, str) and value in choices


def parse_canonical_decimal(
    value: Any,
    *,
    minimum: int,
    maximum: int,
) -> int | None:
    """Parse an ASCII decimal emitted by Chromium's NumberToString."""
    if (
        not isinstance(value, str)
        or re.fullmatch(r"(?:0|[1-9][0-9]*)", value) is None
        or len(value) > len(str(maximum))
    ):
        return None
    parsed = int(value)
    return parsed if minimum <= parsed <= maximum else None


def _require_v8_script_identity(
    value: Any,
    *,
    pid: int,
    context_id: str,
    label: str,
) -> int:
    prefix = f"v8:{pid}:{context_id}:"
    suffix = (
        value.removeprefix(prefix)
        if isinstance(value, str) and value.startswith(prefix)
        else ""
    )
    parsed = parse_canonical_decimal(
        suffix,
        minimum=0,
        maximum=2_147_483_647,
    )
    if parsed is None:
        raise ContractError(f"{label} script identity is invalid")
    return parsed


def _require_optional_realm_detail(detail: dict[str, Any], label: str) -> set[str]:
    fields = {"v8_context_id", "realm_id"}
    present = set(detail) & fields
    if present and present != fields:
        raise ContractError(f"{label} realm metadata is incomplete")
    if present:
        token = detail["v8_context_id"]
        if (not isinstance(token, str)
                or re.fullmatch(r"[0-9A-F]{32}", token) is None
                or token == "0" * 32):
            raise ContractError(f"{label} realm token is invalid")
        world = _require_int(detail["realm_id"], f"{label} realm ID")
        if world > 2_147_483_647:
            raise ContractError(f"{label} realm ID is invalid")
    return present


def _require_exact_fields(
    value: dict[str, Any],
    *,
    required: set[str],
    allowed: set[str],
    label: str,
) -> None:
    if not required.issubset(value) or set(value) - allowed:
        raise ContractError(f"{label} fields are invalid")


def _require_bounded_text(value: Any, label: str, *, maximum: int = 4096) -> str:
    if not isinstance(value, str) or not value:
        raise ContractError(f"{label} is invalid")
    try:
        encoded = value.encode("utf-8", errors="strict")
    except UnicodeEncodeError:
        raise ContractError(f"{label} is invalid") from None
    if len(encoded) > maximum or any(
        ord(character) < 32 or ord(character) == 127 for character in value
    ):
        raise ContractError(f"{label} is invalid")
    return value


def validate_url_class(value: Any) -> str:
    if (
        not isinstance(value, str)
        or len(value) > MAX_URL_CLASS_CHARS
        or URL_CLASS_RE.fullmatch(value) is None
    ):
        raise ContractError("trace URL class is not scheme-safe metadata")
    return value


def _require_aware_timestamp(value: Any, label: str) -> str:
    text = _require_bounded_text(value, label, maximum=64)
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        parsed = None
    if parsed is None or parsed.utcoffset() is None:
        raise ContractError(f"{label} is invalid")
    return text


def reject_sensitive_keys(value: Any, path: str = "$", *, _depth: int = 0) -> None:
    # Field names can be private data, so diagnostics must not include paths.
    if _depth > 64:
        raise ContractError("portable document nesting limit exceeded")
    if isinstance(value, dict):
        for key, child in value.items():
            if not isinstance(key, str):
                raise ContractError("portable document field name must be text")
            key_text = key
            if not key_text.strip():
                raise ContractError("portable document field name is blank")
            try:
                encoded_key = key_text.encode("utf-8", errors="strict")
            except UnicodeEncodeError:
                raise ContractError(
                    "portable document field name is not valid UTF-8"
                ) from None
            if len(encoded_key) > 1_024:
                raise ContractError("portable document field name is too long")
            if any(ord(character) < 32 or ord(character) == 127 for character in key_text):
                raise ContractError(
                    "portable document field name contains control characters"
                )
            raw_key = re.sub(r"[\s_.:/]+", "-", key_text.strip())
            camel_split = re.sub(r"(.)([A-Z][a-z]+)", r"\1-\2", raw_key)
            normalized = re.sub(
                r"([a-z0-9])([A-Z])", r"\1-\2", camel_split
            ).lower()
            if normalized in SENSITIVE_KEYS or any(
                part in normalized
                for part in (
                    "password",
                    "authorization",
                    "private-key",
                    "api-key",
                    "client-secret",
                    "session-token",
                    "access-token",
                    "refresh-token",
                )
            ):
                raise ContractError("sensitive field is forbidden")
            reject_sensitive_keys(child, _depth=_depth + 1)
    elif isinstance(value, (list, tuple)):
        for child in value:
            reject_sensitive_keys(child, _depth=_depth + 1)
    elif isinstance(value, str):
        try:
            value.encode("utf-8", errors="strict")
        except UnicodeEncodeError:
            raise ContractError(
                "portable document text is not valid UTF-8"
            ) from None


def validate_session(document: Any) -> dict[str, Any]:
    data = _require_dict(document, "session")
    allowed_session_fields = {
        "schema",
        "run_id",
        "chromium_revision",
        "pid",
        "state",
        "created_at",
        "stopped_at",
        "executable",
        "build",
        "process_identity",
        "profile",
        "identity_contract",
        "persona",
        "network",
        "trace_mode",
        "trace_category_contract",
        "trace_scope",
        "trace_categories",
        "trace_path",
        "live_trace",
        "value_capture",
        "automation",
    }
    _require_exact_fields(
        data,
        required={"schema", "run_id", "chromium_revision", "pid", "automation"},
        allowed=allowed_session_fields,
        label="session",
    )
    if data.get("schema") != SESSION_SCHEMA:
        raise ContractError("unsupported session schema")
    run_id = data.get("run_id")
    if not isinstance(run_id, str) or not RUN_ID_RE.fullmatch(run_id):
        raise ContractError("session.run_id is invalid")
    revision = data.get("chromium_revision")
    if not isinstance(revision, str) or not REVISION_RE.fullmatch(revision):
        raise ContractError("session.chromium_revision must be a 40-hex revision")
    _require_int(data.get("pid"), "session.pid", 1)
    state = data.get("state", "active")
    if not isinstance(state, str) or state not in {"active", "stopped"}:
        raise ContractError("session state is invalid")
    created_at = data.get("created_at")
    if created_at is not None:
        _require_aware_timestamp(created_at, "session.created_at")
    stopped_at = data.get("stopped_at")
    if stopped_at is not None:
        _require_aware_timestamp(stopped_at, "session.stopped_at")
    if state == "active" and stopped_at is not None:
        raise ContractError("active session cannot have stopped_at")
    if data.get("executable") is not None:
        _require_bounded_text(data["executable"], "session.executable")
    process_identity = data.get("process_identity")
    if process_identity is not None:
        process_identity = _require_dict(process_identity, "session.process_identity")
        _require_exact_fields(
            process_identity,
            required={"pid", "executable", "start_marker"},
            allowed={"pid", "executable", "start_marker"},
            label="session process identity",
        )
        if _require_int(process_identity.get("pid"), "session.process_identity.pid", 1) != data["pid"]:
            raise ContractError("session process identity PID does not match")
        _require_bounded_text(
            process_identity.get("executable"),
            "session process identity executable",
        )
        _require_bounded_text(
            process_identity.get("start_marker"),
            "session process identity start marker",
        )
    build = data.get("build")
    if build is not None:
        build = _require_dict(build, "session.build")
        _require_exact_fields(
            build,
            required={"provenance", "executable_sha256_16"},
            allowed={
                "provenance",
                "executable_sha256_16",
                "runtime_bundle_sha256_16",
                "attestation_created_at",
            },
            label="session build",
        )
        if not isinstance(build.get("provenance"), str) or build["provenance"] not in {
            "attested-browser-core", "unverified-external"
        }:
            raise ContractError("session build provenance is invalid")
        digest = build.get("executable_sha256_16")
        if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{16}", digest):
            raise ContractError("session executable digest is invalid")
        runtime_digest = build.get("runtime_bundle_sha256_16")
        if runtime_digest is not None and (
            not isinstance(runtime_digest, str)
            or not re.fullmatch(r"[0-9a-f]{16}", runtime_digest)
        ):
            raise ContractError("session runtime bundle digest is invalid")
        if build.get("attestation_created_at") is not None:
            _require_aware_timestamp(
                build["attestation_created_at"],
                "session build attestation timestamp",
            )
    profile = data.get("profile")
    if profile is not None:
        profile = _require_dict(profile, "session.profile")
        if not {"id", "persistence", "path", "lock_path"}.issubset(profile) or set(
            profile
        ) - {"id", "persistence", "path", "lock_path", "directory_identity"}:
            raise ContractError("session profile fields are invalid")
        if not isinstance(profile.get("persistence"), str) or profile["persistence"] not in {
            "ephemeral", "persistent"
        }:
            raise ContractError("session profile persistence is invalid")
        if profile.get("id") is not None and not isinstance(profile.get("id"), str):
            raise ContractError("session profile ID is invalid")
        if not isinstance(profile.get("path"), str) or not profile["path"]:
            raise ContractError("session profile path is invalid")
        _require_bounded_text(profile["path"], "session profile path")
        if profile.get("lock_path") is not None and not isinstance(profile["lock_path"], str):
            raise ContractError("session profile lock path is invalid")
        if profile.get("lock_path") is not None:
            _require_bounded_text(profile["lock_path"], "session profile lock path")
        if profile["persistence"] == "ephemeral" and (
            profile.get("id") is not None or profile.get("lock_path") is not None
        ):
            raise ContractError("ephemeral session profile cannot have an ID or lock")
        if profile["persistence"] == "persistent" and (
            not isinstance(profile.get("id"), str)
            or not profile["id"]
            or not isinstance(profile.get("lock_path"), str)
            or not profile["lock_path"]
        ):
            raise ContractError("persistent session profile requires an ID and lock")
        if "directory_identity" in profile:
            parse_directory_identity(profile["directory_identity"])
    identity = data.get("identity_contract")
    if identity is not None:
        identity = _require_dict(identity, "session.identity_contract")
        _require_exact_fields(
            identity,
            required={"file", "path", "sha256_16", "fields"},
            allowed={"file", "path", "sha256_16", "fields"},
            label="session identity contract",
        )
        if identity.get("file") != "identity-contract.json":
            raise ContractError("session identity contract filename is invalid")
        _require_bounded_text(identity.get("path"), "session identity contract path")
        digest = identity.get("sha256_16")
        if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{16}", digest):
            raise ContractError("session identity contract digest is invalid")
        fields = identity.get("fields")
        if (
            not isinstance(fields, list)
            or not 1 <= len(fields) <= 128
            or not all(isinstance(item, str) and 0 < len(item) <= 256 for item in fields)
            or len(set(fields)) != len(fields)
        ):
            raise ContractError("session identity contract fields are invalid")
    persona = data.get("persona")
    if persona is not None:
        persona = _require_dict(persona, "session.persona")
        if set(persona) != {"id", "sha256_16"}:
            raise ContractError("session persona binding is invalid")
        if not isinstance(persona.get("id"), str) or not persona["id"]:
            raise ContractError("session persona ID is invalid")
        if not isinstance(persona.get("sha256_16"), str) or not re.fullmatch(r"[0-9a-f]{16}", persona["sha256_16"]):
            raise ContractError("session persona digest is invalid")
    network = data.get("network")
    if network is not None:
        network = _require_dict(network, "session.network")
        _require_exact_fields(
            network,
            required={
                "route_id",
                "route_sha256_16",
                "mode",
                "policies",
                "preflight",
                "runtime_identity",
                "realization",
            },
            allowed={
                "route_id",
                "route_sha256_16",
                "mode",
                "policies",
                "preflight",
                "runtime_identity",
                "realization",
                "gateway",
            },
            label="session network",
        )
        if not isinstance(network.get("mode"), str) or network["mode"] not in {
            "direct", "proxy"
        }:
            raise ContractError("session network mode is invalid")
        if not isinstance(network.get("route_id"), str) or not network["route_id"]:
            raise ContractError("session network route ID is invalid")
        if not isinstance(network.get("route_sha256_16"), str) or not re.fullmatch(r"[0-9a-f]{16}", network["route_sha256_16"]):
            raise ContractError("session network route digest is invalid")
        policies = _require_dict(network.get("policies"), "session.network.policies")
        if (
            set(policies) != {"dns", "webrtc", "require_alignment"}
            or not isinstance(policies.get("dns"), str)
            or policies["dns"] not in {"route", "system"}
            or not isinstance(policies.get("webrtc"), str)
            or policies["webrtc"] not in {"route-only", "default"}
            or not isinstance(policies.get("require_alignment"), bool)
        ):
            raise ContractError("session network policies are invalid")
        preflight = _require_dict(network.get("preflight"), "session.network.preflight")
        _require_exact_fields(
            preflight,
            required={"schema", "route_id", "route_sha256_16", "passed"},
            allowed={
                "schema",
                "route_id",
                "route_sha256_16",
                "endpoint_sha256_16",
                "protocol",
                "credential_refs_resolved",
                "target_host",
                "target_port",
                "latency_ms",
                "passed",
            },
            label="session network preflight",
        )
        if (
            preflight.get("schema") != "browser-core.network-preflight/1"
            or preflight.get("passed") is not True
            or preflight.get("route_id") != network["route_id"]
            or preflight.get("route_sha256_16") != network["route_sha256_16"]
        ):
            raise ContractError("session network preflight is invalid")
        endpoint_digest = preflight.get("endpoint_sha256_16")
        if endpoint_digest is not None and (
            not isinstance(endpoint_digest, str)
            or not re.fullmatch(r"[0-9a-f]{16}", endpoint_digest)
        ):
            raise ContractError("session network preflight endpoint digest is invalid")
        if preflight.get("protocol") is not None and (
            not isinstance(preflight["protocol"], str)
            or preflight["protocol"] not in {"direct", "http", "https", "socks5"}
        ):
            raise ContractError("session network preflight protocol is invalid")
        if preflight.get("credential_refs_resolved") is not None and not isinstance(
            preflight["credential_refs_resolved"], bool
        ):
            raise ContractError("session network preflight credential receipt is invalid")
        if preflight.get("target_host") is not None:
            _require_bounded_text(
                preflight["target_host"],
                "session network preflight target host",
                maximum=253,
            )
        for field, minimum, maximum in (
            ("target_port", 1, 65535),
            ("latency_ms", 0, 86_400_000),
        ):
            value = preflight.get(field)
            if value is not None and (
                isinstance(value, bool)
                or not isinstance(value, int)
                or not minimum <= value <= maximum
            ):
                raise ContractError(f"session network preflight {field} is invalid")
        runtime_identity = _require_dict(
            network.get("runtime_identity"), "session.network.runtime_identity"
        )
        _require_exact_fields(
            runtime_identity,
            required={"schema", "locale", "languages", "timezone", "cdp_domains_enabled"},
            allowed={"schema", "locale", "languages", "timezone", "cdp_domains_enabled"},
            label="session network runtime identity",
        )
        if runtime_identity.get("schema") != "browser-core.runtime-identity-observation/1":
            raise ContractError("session network runtime identity schema is invalid")
        for field in ("locale", "timezone"):
            _require_bounded_text(
                runtime_identity.get(field),
                f"session network runtime identity {field}",
                maximum=128,
            )
        languages = runtime_identity.get("languages")
        if (
            not isinstance(languages, list)
            or not 1 <= len(languages) <= 16
            or not all(isinstance(value, str) and 0 < len(value) <= 64 for value in languages)
            or len(set(languages)) != len(languages)
        ):
            raise ContractError("session network runtime identity languages are invalid")
        for language in languages:
            _require_bounded_text(
                language, "session network runtime identity language", maximum=64
            )
        if runtime_identity.get("cdp_domains_enabled") != []:
            raise ContractError("session network runtime identity unexpectedly enabled a CDP domain")
        realization = _require_dict(network.get("realization"), "session.network.realization")
        _require_exact_fields(
            realization,
            required={"schema", "route_id", "route_sha256_16", "passed", "observed"},
            allowed={
                "schema",
                "route_id",
                "route_sha256_16",
                "required",
                "passed",
                "checks",
                "distance_km",
                "observed",
                "egress_timezone",
                "preflight",
                "observer",
            },
            label="session network realization",
        )
        if (
            realization.get("schema") != "browser-core.geo-realization/1"
            or realization.get("route_id") != network["route_id"]
            or realization.get("route_sha256_16") != network["route_sha256_16"]
            or not isinstance(realization.get("passed"), bool)
        ):
            raise ContractError("session network geography realization is invalid")
        observed = _require_dict(realization.get("observed"), "session.network.realization.observed")
        _require_exact_fields(
            observed,
            required={"ip_sha256_16"},
            allowed={
                "ip_sha256_16",
                "country",
                "timezone",
                "locale",
                "latitude",
                "longitude",
            },
            label="session network geography observation",
        )
        if not isinstance(observed.get("ip_sha256_16"), str) or not re.fullmatch(
            r"[0-9a-f]{16}", observed["ip_sha256_16"]
        ):
            raise ContractError("session network geography observation digest is invalid")
        for field in ("country", "timezone", "locale"):
            if observed.get(field) is not None:
                _require_bounded_text(
                    observed[field],
                    f"session network geography observation {field}",
                    maximum=128,
                )
        for field, lower, upper in (
            ("latitude", -90.0, 90.0),
            ("longitude", -180.0, 180.0),
        ):
            value = observed.get(field)
            if value is not None and (
                not is_finite_number(value)
                or not lower <= value <= upper
            ):
                raise ContractError(
                    f"session network geography observation {field} is invalid"
                )
        if realization.get("required") is not None and not isinstance(
            realization["required"], bool
        ):
            raise ContractError("session network realization required flag is invalid")
        checks = realization.get("checks")
        if checks is not None:
            checks = _require_dict(checks, "session.network.realization.checks")
            if set(checks) - {
                "country",
                "timezone",
                "locale",
                "coordinates",
                "egress_timezone",
            } or any(
                value is not True and value is not False and value is not None
                for value in checks.values()
            ):
                raise ContractError("session network realization checks are invalid")
        if realization.get("distance_km") is not None and (
            not is_finite_number(realization["distance_km"])
            or not 0 <= realization["distance_km"] <= MAX_GEO_DISTANCE_KM
        ):
            raise ContractError("session network realization distance is invalid")
        if realization.get("egress_timezone") is not None:
            _require_bounded_text(
                realization["egress_timezone"],
                "session network realization egress timezone",
                maximum=128,
            )
        if realization.get("preflight") is not None and realization["preflight"] != preflight:
            raise ContractError("session network realization preflight disagrees")
        if realization.get("observer") is not None and realization["observer"] != "ipwho.is":
            raise ContractError("session network realization observer is invalid")
        gateway = network.get("gateway")
        if network["mode"] == "direct" and gateway is not None:
            raise ContractError("direct session network cannot contain a gateway")
        if network["mode"] == "proxy":
            gateway = _require_dict(gateway, "session.network.gateway")
            _require_exact_fields(
                gateway,
                required={"process_identity", "endpoint", "lease_path", "ready_path", "preflight"},
                allowed={"process_identity", "endpoint", "lease_path", "ready_path", "preflight"},
                label="session network gateway",
            )
            endpoint = gateway.get("endpoint")
            if not isinstance(endpoint, str):
                raise ContractError("session network gateway endpoint is invalid")
            try:
                gateway_url = urlparse(endpoint)
                gateway_port = gateway_url.port
            except ValueError:
                raise ContractError("session network gateway endpoint is invalid") from None
            if (
                gateway_port is None
                or gateway_port < 1
                or endpoint != f"http://127.0.0.1:{gateway_port}"
            ):
                raise ContractError("session network gateway must be loopback HTTP")
            process = _require_dict(gateway.get("process_identity"), "session.network.gateway.process_identity")
            _require_exact_fields(
                process,
                required={"pid", "executable", "start_marker"},
                allowed={"pid", "executable", "start_marker"},
                label="session network gateway process identity",
            )
            _require_int(process.get("pid"), "session.network.gateway.process_identity.pid", 1)
            _require_bounded_text(
                process.get("executable"),
                "session network gateway executable",
            )
            _require_bounded_text(
                process.get("start_marker"),
                "session network gateway start marker",
            )
            for field in ("lease_path", "ready_path"):
                _require_bounded_text(
                    gateway.get(field),
                    f"session network gateway {field}",
                )
            preflight = _require_dict(gateway.get("preflight"), "session.network.gateway.preflight")
            if preflight.get("passed") is not True:
                raise ContractError("session network gateway preflight did not pass")
            if preflight != network["preflight"]:
                raise ContractError("session network gateway preflight disagrees with the route preflight")
    trace_mode = data.get("trace_mode")
    trace_path = data.get("trace_path")
    trace_scope = data.get("trace_scope")
    trace_categories = data.get("trace_categories")
    trace_category_contract = data.get("trace_category_contract")
    if (
        trace_category_contract is not None
        and (not isinstance(trace_category_contract, str)
             or trace_category_contract not in TRACE_CATEGORY_CONTRACTS)
    ):
        raise ContractError("session trace category contract is unsupported")
    if trace_mode is not None:
        if not isinstance(trace_mode, str) or trace_mode not in {"on", "off"}:
            raise ContractError("session trace mode is invalid")
        if trace_mode == "on" and (not isinstance(trace_path, str) or not trace_path):
            raise ContractError("session trace mode on requires a trace path")
        if trace_mode == "off" and trace_path is not None:
            raise ContractError("session trace mode off cannot contain a trace path")
        if trace_scope is not None or trace_categories is not None:
            if trace_mode == "on":
                if not isinstance(trace_scope, str) or trace_scope not in TRACE_SCOPES:
                    raise ContractError("session trace scope is invalid")
                if not isinstance(trace_categories, list) or not all(
                    isinstance(category, str) for category in trace_categories
                ):
                    raise ContractError("session trace categories disagree with its scope")
                supplied = tuple(trace_categories)
                allowed = valid_trace_categories(
                    trace_scope,
                    trace_category_contract,
                )
                if supplied not in allowed:
                    raise ContractError("session trace categories disagree with its scope")
            elif trace_scope is not None or trace_categories != []:
                raise ContractError("session trace mode off cannot contain a trace scope")
    elif trace_path is not None and (not isinstance(trace_path, str) or not trace_path):
        raise ContractError("session trace path is invalid")
    if "live_trace" in data:
        live_trace = _require_dict(data["live_trace"], "session live trace")
        _require_exact_fields(live_trace, required={"schema", "path"},
                              allowed={"schema", "path", "file_binding", "byte_limit", "parts"}, label="session live trace")
        if live_trace["schema"] != "browser-core.live-trace/1" or trace_mode != "on":
            raise ContractError("session live trace requires its supported schema and recording on")
        _require_bounded_text(live_trace["path"], "session live trace path")
        if live_trace["path"] != trace_path + ".live":
            raise ContractError("session live trace path does not match the completed artifact")
        if 'file_binding' in live_trace:
            from .recording_source import validate_recording_binding
            validate_recording_binding(live_trace['file_binding'])
        if 'byte_limit' in live_trace:
            from .recording_limits import validate_byte_limit
            validate_byte_limit(live_trace['byte_limit'])
        if 'parts' in live_trace:
            from .recording_parts import validate_parts
            if 'file_binding' not in live_trace:
                raise ContractError('recording parts require a persisted source binding')
            validate_parts(live_trace['parts'],live_trace.get('byte_limit'))
    if "value_capture" in data:
        capture = _require_dict(data["value_capture"], "session value capture")
        from .inspection_contract import supported_capture
        if not supported_capture(capture):
            raise ContractError("session value capture requires the supported local allowlist")
        if trace_mode != "on":
            raise ContractError("session value capture requires recording on")
    automation = _require_dict(data.get("automation"), "session.automation")
    _require_exact_fields(
        automation,
        required={"transport", "cdp_endpoint"},
        allowed={"transport", "cdp_endpoint", "managed_target_url"},
        label="session automation",
    )
    if automation.get("transport") != "cdp":
        raise ContractError("session automation transport must be cdp")
    endpoint = automation.get("cdp_endpoint")
    if (
        not isinstance(endpoint, str)
        or not 1 <= len(endpoint) <= 2048
        or any(not 0x21 <= ord(character) <= 0x7E for character in endpoint)
    ):
        raise ContractError("session CDP endpoint must be a string")
    try:
        parsed = urlparse(endpoint)
    except ValueError:
        raise ContractError("session CDP endpoint is invalid") from None
    if parsed.scheme not in {"http", "https", "ws", "wss"}:
        raise ContractError("session CDP endpoint scheme is invalid")
    if parsed.hostname not in {"127.0.0.1", "localhost", "::1"}:
        raise ContractError("session CDP endpoint must be loopback")
    if (
        parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or "?" in endpoint
        or "#" in endpoint
    ):
        raise ContractError("session CDP endpoint cannot contain credentials, query, or fragment")
    try:
        endpoint_port = parsed.port
    except ValueError:
        raise ContractError("session CDP endpoint port is invalid") from None
    if endpoint_port is None or endpoint_port < 1:
        raise ContractError("session CDP endpoint port is required")
    managed_target_url = automation.get("managed_target_url")
    if managed_target_url is not None and (
        not isinstance(managed_target_url, str) or not managed_target_url
    ):
        raise ContractError("session managed target URL is invalid")
    if isinstance(managed_target_url, str):
        _require_bounded_text(
            managed_target_url,
            "session managed target URL",
            maximum=8192,
        )
    reject_sensitive_keys(data)
    return data


def load_session(path: Path) -> dict[str, Any]:
    selected = load_session_snapshot(path)
    # Direct callers receive the current validated document, not the earlier
    # fixed snapshot. Rebind after validation, which may outlast its first read.
    final = read_bounded_control_snapshot_result(
        path,
        maximum=MAX_SESSION_DOCUMENT_BYTES,
        label="session contract",
        require_single_link=True,
    )
    if (
        final.state != "complete"
        or final.body != selected.body
        or final.identity != selected.identity
    ):
        raise ContractError("session contract changed during load")
    return selected.document


@dataclass(frozen=True)
class SessionContractSnapshot:
    document: dict[str, Any]
    body: bytes
    identity: tuple[int, int, int, int, int, int]


def load_session_snapshot(path: Path) -> SessionContractSnapshot:
    if not isinstance(path, Path):
        raise ContractError("session contract path must be a Path")
    snapshot = read_bounded_control_snapshot_result(
        path,
        maximum=MAX_SESSION_DOCUMENT_BYTES,
        label="session contract",
        require_single_link=True,
    )
    if snapshot.state != "complete":
        raise ContractError(f"session contract is {snapshot.state}")
    assert snapshot.body is not None and snapshot.identity is not None
    try:
        snapshot.body.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        raise ContractError("session contract encoding is invalid") from None
    try:
        document = decode_strict_json_bytes(snapshot.body, label="session contract")
    except ContractError as exc:
        if "duplicate key" in str(exc) or "non-finite" in str(exc):
            raise
        raise ContractError("session contract JSON is invalid") from None
    return SessionContractSnapshot(
        document=validate_session(document),
        body=snapshot.body,
        identity=snapshot.identity,
    )


def validate_trace_event(document: Any) -> dict[str, Any]:
    data = _require_dict(document, "trace event")
    if data.get("schema") != TRACE_SCHEMA:
        raise ContractError("unsupported trace schema")
    run_id = data.get("run_id")
    if not isinstance(run_id, str) or not RUN_ID_RE.fullmatch(run_id):
        raise ContractError("trace run_id is invalid")
    _require_int(data.get("seq"), "trace seq")
    _require_int(data.get("ts_monotonic_ns"), "trace timestamp")
    parent = data.get("causal_parent_seq")
    if parent is not None:
        _require_int(parent, "trace causal parent")
    callback_parent = data.get("callback_parent_seq")
    if callback_parent is not None:
        _require_int(callback_parent, "trace callback parent")
        if callback_parent >= data["seq"]:
            raise ContractError("trace callback parent is not earlier")
    promise_parent = data.get("promise_parent_seq")
    if promise_parent is not None:
        _require_int(promise_parent, "trace promise parent")
        if promise_parent >= data["seq"]:
            raise ContractError("trace promise parent is not earlier")
    dynamic_code_parent = data.get("dynamic_code_parent_seq")
    if dynamic_code_parent is not None:
        _require_int(dynamic_code_parent, "trace dynamic code parent")
        if dynamic_code_parent >= data["seq"]:
            raise ContractError("trace dynamic code parent is not earlier")
    message_dispatch_parent = data.get("message_dispatch_parent_seq")
    if message_dispatch_parent is not None:
        _require_int(message_dispatch_parent, "trace message dispatch parent")
        if message_dispatch_parent >= data["seq"]:
            raise ContractError("trace message dispatch parent is not earlier")
    process = _require_dict(data.get("process"), "trace process")
    _require_int(process.get("pid"), "trace process.pid", 1)
    if not isinstance(process.get("type"), str) or process["type"] not in {
        "browser", "renderer", "gpu", "utility"
    }:
        raise ContractError("trace process.type is invalid")
    event = _require_dict(data.get("event"), "trace event.event")
    if not isinstance(event.get("category"), str) or event["category"] not in {
        "execution", "api", "crypto", "wasm", "message", "network",
        "stream", "diagnostic"
    }:
        raise ContractError("trace event category is invalid")
    if not isinstance(event.get("name"), str) or not event["name"]:
        raise ContractError("trace event name is required")
    if message_dispatch_parent is not None and event != {
        "category": "execution",
        "name": "host.callback.execution",
    }:
        raise ContractError("trace message dispatch parent is on an unrelated event")
    execution = data.get("execution")
    if execution is not None:
        execution = _require_dict(execution, "trace execution")
        if any(
            field in execution and execution[field] is not None
            and type(execution[field]) is not str
            for field in ("context_id", "frame_id", "worker_id", "script_id")
        ):
            raise ContractError("trace execution identity is invalid")
        if execution.get("frame_id") is not None and execution.get("worker_id") is not None:
            raise ContractError("trace execution cannot identify both frame and worker")
    value = data.get("value")
    if value is not None:
        value = _require_dict(value, "trace value")
        if not isinstance(value.get("redaction"), str) or value["redaction"] not in {
            "none", "metadata", "digest", "dropped"
        }:
            raise ContractError("trace value.redaction is invalid")
    request = data.get("request")
    if event["category"] == "network":
        request = _require_dict(request, "trace request")
        _require_exact_fields(
            request,
            required={"id", "method", "url_class", "body_bytes"},
            allowed={
                "id",
                "method",
                "url_class",
                "target_scope",
                "body_bytes",
                "body_sha256_16",
            },
            label="trace request",
        )
        _require_bounded_text(request.get("id"), "trace request id", maximum=512)
        method = request.get("method")
        if not isinstance(method, str) or HTTP_METHOD_RE.fullmatch(method) is None:
            raise ContractError("trace request method is invalid")
        validate_url_class(request.get("url_class"))
        target_scope = request.get("target_scope")
        if target_scope is not None and (
            not isinstance(target_scope, str) or target_scope not in FETCH_TARGET_SCOPES
        ):
            raise ContractError("trace request target_scope is invalid")
        body_bytes = _require_int(
            request.get("body_bytes"), "trace request body_bytes"
        )
        if body_bytes > MAX_SAFE_INTEGER:
            raise ContractError(
                "trace request body_bytes exceeds the maximum safe integer"
            )
        body_digest = request.get("body_sha256_16")
        if body_digest is not None and (
            not isinstance(body_digest, str)
            or re.fullmatch(r"[0-9a-f]{16}", body_digest) is None
        ):
            raise ContractError("trace request body digest is invalid")
    elif request is not None:
        raise ContractError("non-network trace event cannot carry a request")
    provenance = _require_dict(data.get("provenance"), "trace provenance")
    trace_category = provenance.get("trace_category")
    if trace_category is not None and not isinstance(trace_category, str):
        raise ContractError("trace provenance category is invalid")
    canvas_detail = data.get("detail")
    native_name = (
        canvas_detail.get("native_name")
        if isinstance(canvas_detail, dict)
        else None
    )
    if native_name is not None and not isinstance(native_name, str):
        raise ContractError("trace native name is invalid")
    native_route = EXACT_NATIVE_EVENT_ROUTES.get(native_name)
    if native_route is not None:
        category, name, label = native_route
        if event != {"category": category, "name": name}:
            raise ContractError(f"trace {label} event identity is invalid")
    is_native_canvas_readback = (
        event == {"category": "api", "name": "HTMLCanvasElement.toDataURL"}
        and (
            isinstance(canvas_detail, dict)
            and canvas_detail.get("native_name") == "BrowserCore.CanvasReadback"
            or provenance.get("component")
            == EXACT_NATIVE_EVENT_COMPONENTS["BrowserCore.CanvasReadback"]
        )
    )
    if is_native_canvas_readback:
        detail = _require_dict(canvas_detail, "trace canvas readback detail")
        if (
            set(detail)
            != {"native_name", "thread_id", "width", "height", "origin_clean"}
            or detail.get("native_name") != "BrowserCore.CanvasReadback"
            or provenance.get("source") != "native"
            or provenance.get("component")
            != EXACT_NATIVE_EVENT_COMPONENTS["BrowserCore.CanvasReadback"]
            or value is not None
        ):
            raise ContractError("trace canvas readback metadata is invalid")
        _require_int(detail.get("thread_id"), "trace canvas readback thread_id", 1)
        for dimension in ("width", "height"):
            size = _require_int(
                detail.get(dimension), f"trace canvas readback {dimension}"
            )
            if size > MAX_CANVAS_DIMENSION:
                raise ContractError(
                    f"trace canvas readback {dimension} exceeds limit"
                )
        if type(detail.get("origin_clean")) is not bool:
            raise ContractError("trace canvas readback origin-clean flag is invalid")
        if process.get("type") != "renderer":
            raise ContractError("trace canvas readback process is invalid")
        if execution is not None:
            raise ContractError("trace canvas readback execution is invalid")
        if parent is not None:
            raise ContractError("trace canvas readback parent is invalid")
    if (
        event.get("category") == "api"
        and provenance.get("component") == "blink.bindings.generated"
    ):
        detail = _require_dict(data.get("detail"), "trace generated binding detail")
        name = event.get("name")
        if not isinstance(name, str) or GENERATED_BINDING_NAME_RE.fullmatch(name) is None:
            raise ContractError("trace generated binding name is invalid")
        if (
            detail.get("native_name") != name
            or provenance.get("source") != "native"
            or trace_category not in GENERATED_BINDING_TRACE_CATEGORIES
            or value is not None
        ):
            raise ContractError("trace generated binding metadata is invalid")
        interface_name = name.partition(".")[0]
        if (trace_category == "blink.bindings.encoding") != (
            interface_name in ENCODING_BINDING_INTERFACES
        ):
            raise ContractError("trace generated binding category is invalid")
        thread_id = _require_int(
            detail.get("thread_id"), "trace generated binding thread_id", 1
        )
        completion = detail.get("completion")
        duration = detail.get("duration_ns")
        if completion == "open":
            if duration is not None:
                raise ContractError("trace generated binding completion is invalid")
            expected_detail = {"native_name", "thread_id", "completion"}
        elif completion == "complete":
            duration = _require_int(
                duration, "trace generated binding duration_ns"
            )
            if duration > MAX_TRACE_EVENT_DURATION_NS:
                raise ContractError("trace generated binding duration exceeds limit")
            expected_detail = {
                "native_name",
                "thread_id",
                "completion",
                "duration_ns",
            }
        else:
            raise ContractError("trace generated binding completion is invalid")
        if 'js_stack' in detail:
            validate_js_stack(detail['js_stack'])
            expected_detail.add('js_stack')
        attribution = detail.get("script_attribution")
        if attribution is not None:
            if not isinstance(attribution, str):
                raise ContractError('trace generated binding script attribution is invalid')
            expected_detail.add("script_attribution")
        context_attribution = detail.get('context_attribution')
        if context_attribution is not None:
            if not isinstance(context_attribution, str):
                raise ContractError('trace generated binding context attribution is invalid')
            expected_detail.add('context_attribution')
            if context_attribution in {'native-binding-owner', 'native-binding-owner-limited'}:
                expected_detail.add('binding_value_slice_id')
                _require_int(detail.get('binding_value_slice_id'), 'binding value slice id')
                if context_attribution == 'native-binding-owner-limited':
                    expected_detail.add('context_unavailable')
                    if detail.get('context_unavailable') != 'invalid-script-context':
                        raise ContractError('binding limited context reason is invalid')
                if 'script_number' in detail:
                    expected_detail.add('script_number')
                    number = _require_int(detail['script_number'], 'binding script number')
                    if number > 2_147_483_647:
                        raise ContractError('binding script number is invalid')
            elif context_attribution == 'ambiguous-native-binding-owner':
                expected_detail.add('binding_value_count')
                _require_int(detail.get('binding_value_count'), 'binding value count', 2)
            elif context_attribution not in {
                'unresolved',
                'host-callback',
                'promise-microtask',
            }:
                raise ContractError('trace generated binding context attribution is invalid')
        if set(detail) != expected_detail:
            raise ContractError("trace generated binding metadata is invalid")
        if process.get("type") != "renderer":
            raise ContractError("trace generated binding process is invalid")
        if not isinstance(execution, dict) or set(execution) - {
            "context_id",
            "frame_id",
            "worker_id",
            "script_id",
        }:
            raise ContractError("trace generated binding execution is invalid")
        context_id = execution.get("context_id")
        if not isinstance(context_id, str) or not context_id:
            raise ContractError("trace generated binding execution is invalid")
        for context_key in ("frame_id", "worker_id"):
            context_value = execution.get(context_key)
            if context_value is not None and context_value != context_id:
                raise ContractError("trace generated binding execution is invalid")
        script_id = execution.get("script_id")
        synthetic_context = f"bindings:{process['pid']}:{thread_id}"
        if context_attribution in {'unresolved', 'ambiguous-native-binding-owner'} and attribution == 'matched-script-run':
            raise ContractError('trace generated binding context attribution is contradictory')
        if context_attribution in {'native-binding-owner', 'native-binding-owner-limited'}:
            if attribution is not None or script_id is not None or context_id.startswith('bindings:'):
                raise ContractError('trace generated binding owner attribution is invalid')
            if context_attribution == 'native-binding-owner-limited' and set(execution) != {'context_id'}:
                raise ContractError('trace generated binding limited context has invented aliases')
        elif context_attribution == 'host-callback':
            if (
                attribution != 'callback-contained'
                or callback_parent is None
                or context_id == synthetic_context
            ):
                raise ContractError(
                    'trace generated binding callback attribution is invalid'
                )
            if script_id is not None:
                _require_v8_script_identity(
                    script_id,
                    pid=process['pid'],
                    context_id=context_id,
                    label='trace generated binding callback',
                )
        elif context_attribution == 'promise-microtask':
            if (
                attribution != 'promise-contained'
                or promise_parent is None
                or context_id == synthetic_context
            ):
                raise ContractError(
                    'trace generated binding promise attribution is invalid'
                )
            if script_id is not None:
                _require_v8_script_identity(
                    script_id,
                    pid=process['pid'],
                    context_id=context_id,
                    label='trace generated binding promise',
                )
        elif attribution is None:
            if script_id is not None or context_id != synthetic_context:
                raise ContractError("trace generated binding execution is invalid")
        elif attribution in {"script-run-not-in-trace", "script-context-unresolved"}:
            script_prefix = f"v8:{process['pid']}:bindings:{thread_id}:"
            script_number = (
                script_id.removeprefix(script_prefix)
                if isinstance(script_id, str) and script_id.startswith(script_prefix)
                else ""
            )
            if context_id != synthetic_context or parse_canonical_decimal(
                script_number,
                minimum=0,
                maximum=2_147_483_647,
            ) is None:
                raise ContractError("trace generated binding execution is invalid")
        elif attribution == "matched-script-run":
            if not isinstance(script_id, str) or not script_id:
                raise ContractError("trace generated binding execution is invalid")
            _require_v8_script_identity(
                script_id,
                pid=process["pid"],
                context_id=context_id,
                label="trace generated binding",
            )
        else:
            raise ContractError("trace generated binding script attribution is invalid")
        if parent is not None:
            raise ContractError("trace generated binding parent is invalid")
    if event == {"category": "crypto", "name": "SubtleCrypto.digest"}:
        detail = _require_dict(data.get("detail"), "trace crypto digest detail")
        required_detail = {"native_name", "thread_id", "algorithm", "data_bytes"}
        parent_status = detail.get("causal_parent_status")
        script_id = (execution or {}).get("script_id")
        if (
            set(detail)
            not in (required_detail, required_detail | {"causal_parent_status"})
            or detail.get("native_name") != "BrowserCore.CryptoDigest"
            or provenance.get("source") != "native"
            or provenance.get("component")
            != EXACT_NATIVE_EVENT_COMPONENTS["BrowserCore.CryptoDigest"]
            or parent_status not in (None, "script_parent_not_in_trace")
        ):
            raise ContractError("trace crypto digest metadata is invalid")
        _require_int(detail.get("thread_id"), "trace crypto digest thread_id", 1)
        if not _allowed_string(detail.get("algorithm"), WEBCRYPTO_DIGEST_ALGORITHMS):
            raise ContractError("trace crypto digest algorithm is invalid")
        data_bytes = _require_int(
            detail.get("data_bytes"), "trace crypto digest data_bytes"
        )
        if data_bytes > MAX_TRACE_BUFFER_BYTES:
            raise ContractError("trace crypto digest data_bytes exceeds limit")
        if (
            not isinstance(value, dict)
            or set(value) != {"type", "length", "redaction"}
            or value.get("type") != "bytes"
            or value.get("length") != data_bytes
            or value.get("redaction") != "metadata"
        ):
            raise ContractError("trace crypto digest value is invalid")
        if process.get("type") != "renderer":
            raise ContractError("trace crypto digest process is invalid")
        if not isinstance(execution, dict) or set(execution) - {
            "context_id",
            "frame_id",
            "worker_id",
            "script_id",
        }:
            raise ContractError("trace crypto digest execution is invalid")
        context_id = (execution or {}).get("context_id")
        if not isinstance(context_id, str) or not context_id:
            raise ContractError("trace crypto digest context is invalid")
        for context_key in ("frame_id", "worker_id"):
            context_value = (execution or {}).get(context_key)
            if context_value is not None and context_value != context_id:
                raise ContractError("trace crypto digest context is invalid")
        if script_id is not None and (
            not isinstance(script_id, str) or not script_id
        ):
            raise ContractError("trace crypto digest script is invalid")
        if script_id is not None:
            _require_v8_script_identity(
                script_id,
                pid=process["pid"],
                context_id=context_id,
                label="trace crypto digest",
            )
        if script_id is None:
            if parent is not None or parent_status is not None:
                raise ContractError("trace crypto digest parent is invalid")
        elif (parent is None) == (parent_status is None):
            raise ContractError("trace crypto digest parent is invalid")
    if event == {"category": "wasm", "name": "WebAssembly.compile.completed"}:
        detail = _require_dict(data.get("detail"), "trace WASM compile detail")
        required_detail = {
            "native_name",
            "thread_id",
            "success",
            "async",
            "cached",
            "code_bytes",
        }
        if (
            set(detail) != required_detail
            or detail.get("native_name") != "BrowserCore.WasmCompiled"
            or provenance.get("source") != "native"
            or provenance.get("component")
            != EXACT_NATIVE_EVENT_COMPONENTS["BrowserCore.WasmCompiled"]
            or value is not None
        ):
            raise ContractError("trace WASM compile metadata is invalid")
        _require_int(detail.get("thread_id"), "trace WASM compile thread_id", 1)
        if any(type(detail.get(field)) is not bool for field in ("success", "async", "cached")):
            raise ContractError("trace WASM compile flags are invalid")
        code_bytes = _require_int(
            detail.get("code_bytes"), "trace WASM compile code_bytes"
        )
        if code_bytes > MAX_WASM_MODULE_BYTES:
            raise ContractError("trace WASM compile code_bytes exceeds limit")
        if process.get("type") != "renderer":
            raise ContractError("trace WASM compile process is invalid")
        if not isinstance(execution, dict) or set(execution) - {
            "context_id",
            "frame_id",
            "worker_id",
            "script_id",
        }:
            raise ContractError("trace WASM compile execution is invalid")
        context_id = (execution or {}).get("context_id")
        if not isinstance(context_id, str) or not context_id:
            raise ContractError("trace WASM compile context is invalid")
        for context_key in ("frame_id", "worker_id"):
            context_value = (execution or {}).get(context_key)
            if context_value is not None and context_value != context_id:
                raise ContractError("trace WASM compile context is invalid")
        if (execution or {}).get("script_id") is not None:
            raise ContractError("trace WASM compile script is invalid")
        if parent is not None:
            raise ContractError("trace WASM compile parent is invalid")
    if event == {"category": "api", "name": "fetch"}:
        detail = _require_dict(data.get("detail"), "trace fetch API detail")
        required_detail = {"native_name", "thread_id"}
        parent_status = detail.get("causal_parent_status")
        script_id = (execution or {}).get("script_id")
        if (
            set(detail)
            not in (required_detail, required_detail | {"causal_parent_status"})
            or detail.get("native_name") != "BrowserCore.FetchCall"
            or provenance.get("source") != "native"
            or provenance.get("component")
            != EXACT_NATIVE_EVENT_COMPONENTS["BrowserCore.FetchCall"]
            or parent_status not in (None, "script_parent_not_in_trace")
            or value is not None
        ):
            raise ContractError("trace fetch API metadata is invalid")
        _require_int(detail.get("thread_id"), "trace fetch API thread_id", 1)
        if process.get("type") != "renderer":
            raise ContractError("trace fetch API process is invalid")
        if not isinstance(execution, dict) or set(execution) - {
            "context_id",
            "frame_id",
            "worker_id",
            "script_id",
        }:
            raise ContractError("trace fetch API execution is invalid")
        context_id = execution.get("context_id")
        if not isinstance(context_id, str) or not context_id:
            raise ContractError("trace fetch API context is invalid")
        for context_key in ("frame_id", "worker_id"):
            context_value = (execution or {}).get(context_key)
            if context_value is not None and context_value != context_id:
                raise ContractError("trace fetch API context is invalid")
        if script_id is not None and (
            not isinstance(script_id, str) or not script_id
        ):
            raise ContractError("trace fetch API script is invalid")
        if script_id is not None:
            _require_v8_script_identity(
                script_id,
                pid=process["pid"],
                context_id=context_id,
                label="trace fetch API",
            )
        if script_id is None:
            if parent is not None or parent_status is not None:
                raise ContractError("trace fetch API parent is invalid")
        elif (parent is None) == (parent_status is None):
            raise ContractError("trace fetch API parent is invalid")
    if event == {"category": "network", "name": "fetch.request.start"}:
        detail = _require_dict(data.get("detail"), "trace fetch request detail")
        request_fields = {"id", "method", "url_class", "target_scope", "body_bytes"}
        if (
            set(detail) != {"native_name", "thread_id"}
            or detail.get("native_name") != "BrowserCore.FetchRequestStart"
            or provenance.get("source") != "native"
            or provenance.get("component")
            != EXACT_NATIVE_EVENT_COMPONENTS["BrowserCore.FetchRequestStart"]
            or value is not None
        ):
            raise ContractError("trace fetch request metadata is invalid")
        _require_int(detail.get("thread_id"), "trace fetch request thread_id", 1)
        if process.get("type") != "renderer":
            raise ContractError("trace fetch request process is invalid")
        if not isinstance(execution, dict) or set(execution) - {
            "context_id",
            "frame_id",
            "worker_id",
            "script_id",
        }:
            raise ContractError("trace fetch request execution is invalid")
        context_id = execution.get("context_id")
        if not isinstance(context_id, str) or not context_id:
            raise ContractError("trace fetch request context is invalid")
        for context_key in ("frame_id", "worker_id"):
            context_value = (execution or {}).get(context_key)
            if context_value is not None and context_value != context_id:
                raise ContractError("trace fetch request context is invalid")
        script_id = (execution or {}).get("script_id")
        if script_id is not None and (
            not isinstance(script_id, str) or not script_id
        ):
            raise ContractError("trace fetch request script is invalid")
        if script_id is not None:
            _require_v8_script_identity(
                script_id,
                pid=process["pid"],
                context_id=context_id,
                label="trace fetch request",
            )
        if parent is None:
            raise ContractError("trace fetch request parent is invalid")
        if set(request or {}) != request_fields:
            raise ContractError("trace fetch request fields are invalid")
        request_id = request["id"]
        request_prefix = f"fetch-request:{context_id}:"
        operation = (
            request_id.removeprefix(request_prefix)
            if isinstance(request_id, str) and request_id.startswith(request_prefix)
            else ""
        )
        if (
            not isinstance(request_id, str)
            or not request_id.startswith(request_prefix)
            or parse_canonical_decimal(
                operation,
                minimum=1,
                maximum=2_147_483_647,
            )
            is None
        ):
            raise ContractError("trace fetch request id is invalid")
    if event["category"] == "stream":
        detail = _require_dict(data.get("detail"), "trace stream detail")
        name = event["name"]
        if name == "body.consume":
            required_body_detail = {"native_name", "thread_id", "consumer_mode"}
            body_detail_fields = set(detail)
            parent_status = detail.get("causal_parent_status")
            script_id = (execution or {}).get("script_id")
            if (
                body_detail_fields
                not in (
                    required_body_detail,
                    required_body_detail | {"causal_parent_status"},
                )
                or detail.get("native_name") != "BrowserCore.BodyConsume"
                or not _allowed_string(detail.get("consumer_mode"), BODY_CONSUMER_MODES)
                or provenance.get("source") != "native"
                or provenance.get("component")
                != EXACT_NATIVE_EVENT_COMPONENTS["BrowserCore.BodyConsume"]
                or parent_status
                not in (None, "script_parent_not_in_trace")
                or value is not None
            ):
                raise ContractError("trace body consumer metadata is invalid")
            _require_int(
                detail.get("thread_id"),
                "trace body consumer thread_id",
                1,
            )
            if process.get("type") != "renderer":
                raise ContractError("trace body consumer process is invalid")
            if not isinstance(execution, dict) or set(execution) - {
                "context_id",
                "frame_id",
                "worker_id",
                "script_id",
            }:
                raise ContractError("trace body consumer execution is invalid")
            context_id = execution.get("context_id")
            if not isinstance(context_id, str) or not context_id:
                raise ContractError("trace body consumer context is invalid")
            for context_key in ("frame_id", "worker_id"):
                context_value = execution.get(context_key)
                if context_value is not None and context_value != context_id:
                    raise ContractError("trace body consumer execution is invalid")
            if script_id is not None and (
                not isinstance(script_id, str) or not script_id
            ):
                raise ContractError("trace body consumer script is invalid")
            if script_id is not None:
                _require_v8_script_identity(
                    script_id,
                    pid=process["pid"],
                    context_id=context_id,
                    label="trace body consumer",
                )
            if script_id is None:
                if parent is not None or parent_status is not None:
                    raise ContractError("trace body consumer parent is invalid")
            elif (parent is None) == (parent_status is None):
                raise ContractError("trace body consumer parent is invalid")
        elif name == "stream.read.request":
            reader_mode = detail.get("reader_mode")
            if not _allowed_string(reader_mode, {"default", "byob"}):
                raise ContractError("trace stream reader mode is invalid")
            parent_status = detail.get("causal_parent_status")
            expected_detail = {"native_name", "thread_id", "reader_mode"}
            if parent_status is not None:
                expected_detail.add("causal_parent_status")
            if (
                set(detail) != expected_detail
                or detail.get("native_name") != "BrowserCore.StreamReadRequest"
                or provenance.get("source") != "native"
                or provenance.get("component")
                != EXACT_NATIVE_EVENT_COMPONENTS["BrowserCore.StreamReadRequest"]
                or parent_status not in (None, "script_parent_not_in_trace")
                or value is not None
            ):
                raise ContractError("trace stream request metadata is invalid")
            _require_int(
                detail.get("thread_id"), "trace stream request thread_id", 1
            )
            if process.get("type") != "renderer":
                raise ContractError("trace stream request process is invalid")
            if not isinstance(execution, dict) or set(execution) - {
                "context_id",
                "frame_id",
                "worker_id",
                "script_id",
            }:
                raise ContractError("trace stream request execution is invalid")
            context_id = execution.get("context_id")
            if not isinstance(context_id, str) or not context_id:
                raise ContractError("trace stream request execution is invalid")
            for context_key in ("frame_id", "worker_id"):
                context_value = execution.get(context_key)
                if context_value is not None and context_value != context_id:
                    raise ContractError("trace stream request execution is invalid")
            script_id = execution.get("script_id")
            if script_id is not None:
                _require_v8_script_identity(
                    script_id,
                    pid=process["pid"],
                    context_id=context_id,
                    label="trace stream request",
                )
            if script_id is None:
                if parent is not None or parent_status is not None:
                    raise ContractError("trace stream request parent is invalid")
            elif (parent is None) == (parent_status is None):
                raise ContractError("trace stream request parent is invalid")
        elif name == "stream.read.result":
            reader_mode = detail.get("reader_mode")
            if not _allowed_string(reader_mode, {"default", "byob"}):
                raise ContractError("trace stream reader mode is invalid")
            result_kind = detail.get("result_kind")
            chunk_value_type = detail.get("chunk_value_type")
            chunk_bytes = detail.get("chunk_bytes")
            if (
                set(detail)
                != {
                    "native_name",
                    "thread_id",
                    "reader_mode",
                    "result_kind",
                    "chunk_value_type",
                    "chunk_bytes",
                }
                or detail.get("native_name") != "BrowserCore.StreamReadResult"
                or provenance.get("source") != "native"
                or provenance.get("component")
                != EXACT_NATIVE_EVENT_COMPONENTS["BrowserCore.StreamReadResult"]
            ):
                raise ContractError("trace stream result metadata is invalid")
            _require_int(
                detail.get("thread_id"), "trace stream result thread_id", 1
            )
            if process.get("type") != "renderer":
                raise ContractError("trace stream result process is invalid")
            if not isinstance(execution, dict) or set(execution) - {
                "context_id",
                "frame_id",
                "worker_id",
            }:
                raise ContractError("trace stream result execution is invalid")
            context_id = execution.get("context_id")
            if not isinstance(context_id, str) or not context_id:
                raise ContractError("trace stream result execution is invalid")
            for context_key in ("frame_id", "worker_id"):
                context_value = execution.get(context_key)
                if context_value is not None and context_value != context_id:
                    raise ContractError("trace stream result execution is invalid")
            if not _allowed_string(result_kind, {"chunk", "closed", "error"}) \
                    or not _allowed_string(chunk_value_type, {"bytes", "other", "none"}):
                raise ContractError("trace stream result classification is invalid")
            _require_int(chunk_bytes, "trace stream chunk_bytes")
            if chunk_bytes > MAX_TRACE_BUFFER_BYTES:
                raise ContractError("trace stream chunk_bytes exceeds limit")
            if data.get("causal_parent_seq") is None:
                raise ContractError("trace stream result requires a causal parent")
            if (
                result_kind == "chunk" and chunk_value_type == "none"
            ) or (
                result_kind == "closed" and chunk_value_type == "other"
            ) or (
                result_kind == "error"
                and (chunk_value_type != "none" or chunk_bytes != 0)
            ) or (
                chunk_value_type != "bytes" and chunk_bytes != 0
            ) or (
                reader_mode == "byob" and chunk_value_type == "other"
            ) or (
                reader_mode == "default" and result_kind == "closed"
                and chunk_value_type != "none"
            ):
                raise ContractError("trace stream result metadata is inconsistent")
            if chunk_value_type == "bytes":
                if value is None or value.get("type") != "bytes" \
                        or value.get("length") != chunk_bytes \
                        or value.get("redaction") != "metadata":
                    raise ContractError("trace stream byte value is inconsistent")
            elif value is not None:
                raise ContractError("trace stream non-byte result cannot carry a value")
        else:
            raise ContractError("trace stream event name is invalid")
    if event == {"category": "message", "name": "MessagePort.postMessage"}:
        detail = _require_dict(data.get("detail"), "trace message post detail")
        required_post_detail = {"native_name", "thread_id"}
        parent_status = detail.get("causal_parent_status")
        script_id = (execution or {}).get("script_id")
        if (
            set(detail)
            not in (
                required_post_detail,
                required_post_detail | {"causal_parent_status"},
            )
            or detail.get("native_name") != "BrowserCore.MessagePost"
            or provenance.get("source") != "native"
            or provenance.get("component")
            != EXACT_NATIVE_EVENT_COMPONENTS["BrowserCore.MessagePost"]
            or parent_status not in (None, "script_parent_not_in_trace")
            or value is not None
        ):
            raise ContractError("trace message post metadata is invalid")
        _require_int(detail.get("thread_id"), "trace message post thread_id", 1)
        if process.get("type") != "renderer":
            raise ContractError("trace message post process is invalid")
        if not isinstance(execution, dict) or set(execution) - {
            "context_id",
            "frame_id",
            "worker_id",
            "script_id",
        }:
            raise ContractError("trace message post execution is invalid")
        context_id = execution.get("context_id")
        if not isinstance(context_id, str) or not context_id:
            raise ContractError("trace message post context is invalid")
        for context_key in ("frame_id", "worker_id"):
            context_value = execution.get(context_key)
            if context_value is not None and context_value != context_id:
                raise ContractError("trace message post execution is invalid")
        if script_id is not None and (
            not isinstance(script_id, str) or not script_id
        ):
            raise ContractError("trace message post script is invalid")
        if script_id is not None:
            _require_v8_script_identity(
                script_id,
                pid=process["pid"],
                context_id=context_id,
                label="trace message post",
            )
        if script_id is None:
            if parent is not None or parent_status is not None:
                raise ContractError("trace message post parent is invalid")
        elif (parent is None) == (parent_status is None):
            raise ContractError("trace message post parent is invalid")
    if event == {"category": "message", "name": "MessagePort.message.dispatch"}:
        detail = _require_dict(data.get("detail"), "trace message dispatch detail")
        required_dispatch_detail = {"native_name", "thread_id", "dispatch_kind"}
        parent_status = detail.get("causal_parent_status")
        if (
            set(detail)
            not in (
                required_dispatch_detail,
                required_dispatch_detail | {"causal_parent_status"},
            )
            or detail.get("native_name") != "BrowserCore.MessageDispatch"
            or not _allowed_string(detail.get("dispatch_kind"), {"message", "messageerror"})
            or provenance.get("source") != "native"
            or provenance.get("component")
            != EXACT_NATIVE_EVENT_COMPONENTS["BrowserCore.MessageDispatch"]
            or parent_status
            not in (
                None,
                "message_parent_unavailable",
                "message_parent_not_in_trace",
            )
            or value is not None
            or (execution or {}).get("script_id") is not None
        ):
            raise ContractError("trace message dispatch metadata is invalid")
        _require_int(
            detail.get("thread_id"),
            "trace message dispatch thread_id",
            1,
        )
        if process.get("type") != "renderer":
            raise ContractError("trace message dispatch process is invalid")
        if not isinstance(execution, dict) or set(execution) - {
            "context_id",
            "frame_id",
            "worker_id",
        }:
            raise ContractError("trace message dispatch execution is invalid")
        context_id = execution.get("context_id")
        if not isinstance(context_id, str) or not context_id:
            raise ContractError("trace message dispatch context is invalid")
        for context_key in ("frame_id", "worker_id"):
            context_value = execution.get(context_key)
            if context_value is not None and context_value != context_id:
                raise ContractError("trace message dispatch execution is invalid")
        if parent is None:
            if parent_status not in {
                "message_parent_unavailable",
                "message_parent_not_in_trace",
            }:
                raise ContractError("trace message dispatch parent is invalid")
        elif parent_status is not None:
            raise ContractError("trace message dispatch parent is invalid")
    if event == {"category": "execution", "name": "script.run"}:
        detail = _require_dict(data.get("detail"), "trace script run detail")
        realm_fields = _require_optional_realm_detail(detail, "trace script run")
        if "inspector_context_id" in detail:
            inspector_id = _require_int(
                detail["inspector_context_id"], "trace script run inspector context id", 1)
            if inspector_id > 2_147_483_647:
                raise ContractError("trace script run inspector context id is invalid")
            realm_fields = realm_fields | {"inspector_context_id"}
        if (
            set(detail) != {"native_name", "thread_id"} | realm_fields
            or detail.get("native_name") != "BrowserCore.ScriptRun"
            or provenance.get("source") != "native"
            or provenance.get("component")
            != EXACT_NATIVE_EVENT_COMPONENTS["BrowserCore.ScriptRun"]
            or value is not None
        ):
            raise ContractError("trace script run metadata is invalid")
        _require_int(detail.get("thread_id"), "trace script run thread_id", 1)
        if process.get("type") != "renderer":
            raise ContractError("trace script run process is invalid")
        context_id = (execution or {}).get("context_id")
        if not isinstance(context_id, str) or not context_id:
            raise ContractError("trace script run context is invalid")
        for context_key in ("frame_id", "worker_id"):
            context_value = (execution or {}).get(context_key)
            if context_value is not None and context_value != context_id:
                raise ContractError("trace script run context is invalid")
        script_id = (execution or {}).get("script_id")
        if not isinstance(script_id, str) or not script_id:
            raise ContractError("trace script run script is invalid")
        _require_v8_script_identity(
            script_id,
            pid=process["pid"],
            context_id=context_id,
            label="trace script run",
        )
        if parent is not None:
            raise ContractError("trace script run parent is invalid")
    if event == {"category": "execution", "name": "script.source.identity"}:
        detail = _require_dict(data.get("detail"), "trace script source identity detail")
        if (
            set(detail) != {
                "native_name", "thread_id", "script_id", "source_length",
                "source_length_unit", "compiler_input_hash_status",
                "compiler_input_utf16le_sha256",
            }
            or detail.get("native_name") != "BrowserCore.ScriptSourceIdentity"
            or provenance.get("source") != "native"
            or provenance.get("component")
            != EXACT_NATIVE_EVENT_COMPONENTS["BrowserCore.ScriptSourceIdentity"]
            or execution is not None
            or parent is not None
            or callback_parent is not None
            or promise_parent is not None
            or dynamic_code_parent is not None
            or message_dispatch_parent is not None
            or value is not None
        ):
            raise ContractError("trace script source identity metadata is invalid")
        _require_int(detail.get("thread_id"), "trace script source identity thread", 1)
        script_number = _require_int(
            detail.get("script_id"), "trace script source identity script_id"
        )
        source_length = _require_int(
            detail.get("source_length"), "trace script source identity source_length"
        )
        if (script_number > 2_147_483_647 or source_length > 2_147_483_647
                or detail.get("source_length_unit") != "utf16-code-units"):
            raise ContractError("trace script source identity size or ID is invalid")
        hash_status = detail.get("compiler_input_hash_status")
        source_hash = detail.get("compiler_input_utf16le_sha256")
        if (
            not _allowed_string(hash_status, {"observed", "over-limit", "unavailable"})
            or (hash_status == "observed" and (
                not isinstance(source_hash, str)
                or re.fullmatch(r"[0-9a-f]{64}", source_hash) is None
            ))
            or (hash_status != "observed" and source_hash is not None)
            or (hash_status == "over-limit" and source_length <= 262_144)
            or (hash_status == "observed" and source_length > 262_144)
        ):
            raise ContractError("trace script source identity digest is invalid")
    if event == {"category": "execution", "name": "script.source.context"}:
        detail = _require_dict(data.get("detail"), "trace script source context detail")
        realm_fields = _require_optional_realm_detail(
            detail, "trace script source context")
        context = _require_dict(execution, "trace script source context execution")
        context_id = context.get("context_id")
        if (
            set(detail) != ({
                "native_name", "thread_id", "script_id", "source_length",
                "source_length_unit", "compiler_input_hash_status",
                "compiler_input_utf16le_sha256",
            } | realm_fields)
            or detail.get("native_name") != "BrowserCore.ScriptSourceContext"
            or provenance.get("source") != "native"
            or provenance.get("component")
            != EXACT_NATIVE_EVENT_COMPONENTS["BrowserCore.ScriptSourceContext"]
            or not isinstance(context_id, str)
            or not context_id
            or not set(context) <= {"context_id", "frame_id", "worker_id", "script_id"}
            or ("frame_id" in context and "worker_id" in context)
            or ("frame_id" in context and context["frame_id"] != context_id)
            or ("worker_id" in context and context["worker_id"] != context_id)
            or parent is not None
            or callback_parent is not None
            or promise_parent is not None
            or dynamic_code_parent is not None
            or message_dispatch_parent is not None
            or value is not None
        ):
            raise ContractError("trace script source context metadata is invalid")
        _require_int(detail.get("thread_id"), "trace script source context thread", 1)
        script_number = _require_int(
            detail.get("script_id"), "trace script source context script_id"
        )
        source_length = _require_int(
            detail.get("source_length"), "trace script source context source_length"
        )
        if (
            script_number > 2_147_483_647
            or source_length > 2_147_483_647
            or detail.get("source_length_unit") != "utf16-code-units"
        ):
            raise ContractError("trace script source context size or ID is invalid")
        _require_v8_script_identity(
            context.get("script_id"), pid=process["pid"],
            context_id=context_id, label="trace script source context",
        )
        if context["script_id"] != f"v8:{process['pid']}:{context_id}:{script_number}":
            raise ContractError("trace script source context script ID is invalid")
        hash_status = detail.get("compiler_input_hash_status")
        source_hash = detail.get("compiler_input_utf16le_sha256")
        if (
            not _allowed_string(hash_status, {"observed", "over-limit", "unavailable"})
            or (hash_status == "observed" and (
                not isinstance(source_hash, str)
                or re.fullmatch(r"[0-9a-f]{64}", source_hash) is None
            ))
            or (hash_status != "observed" and source_hash is not None)
            or (hash_status == "over-limit" and source_length <= 262_144)
            or (hash_status == "observed" and source_length > 262_144)
        ):
            raise ContractError("trace script source context digest is invalid")
    if event == {
        "category": "execution",
        "name": "dynamic.code.materialized",
    }:
        detail = _require_dict(data.get("detail"), "trace dynamic code detail")
        expected = {
            "native_name",
            "thread_id",
            "dynamic_kind",
            "cache_status",
            "generated_script_id",
            "caller_script_id",
            "caller_status",
            "source_length",
            "source_length_unit",
        }
        caller_parent_status = detail.get("caller_parent_status")
        if caller_parent_status is not None:
            expected.add("caller_parent_status")
        if "caller_inspector_context_id" in detail:
            caller_inspector_id = _require_int(
                detail["caller_inspector_context_id"],
                "trace dynamic code caller inspector context id", 1)
            if (caller_inspector_id > 2_147_483_647
                    or detail.get("caller_script_id") == -1):
                raise ContractError("trace dynamic code caller inspector context id is invalid")
            expected.add("caller_inspector_context_id")
        if "compiler_input_hash_status" in detail:
            expected.update({
                "compiler_input_hash_status",
                "compiler_input_utf16le_sha256",
            })
        if (
            set(detail) != expected
            or detail.get("native_name") != "BrowserCore.DynamicCodeMaterialized"
            or not _allowed_string(detail.get("dynamic_kind"), {"eval", "function-constructor"})
            or not _allowed_string(detail.get("cache_status"),
                                   {"compiled", "function-cache-hit", "shared-cache-hit"})
            or detail.get("source_length_unit") != "utf16-code-units"
            or provenance.get("source") != "native"
            or provenance.get("component")
            != EXACT_NATIVE_EVENT_COMPONENTS["BrowserCore.DynamicCodeMaterialized"]
            or value is not None
        ):
            raise ContractError("trace dynamic code metadata is invalid")
        _require_int(detail.get("thread_id"), "trace dynamic code thread_id", 1)
        generated_script_id = _require_int(
            detail.get("generated_script_id"),
            "trace dynamic code generated_script_id",
        )
        if generated_script_id > 2_147_483_647:
            raise ContractError("trace dynamic code generated_script_id exceeds limit")
        source_length = _require_int(
            detail.get("source_length"),
            "trace dynamic code source_length",
        )
        if source_length > 2_147_483_647:
            raise ContractError("trace dynamic code source_length exceeds limit")
        if "compiler_input_hash_status" in detail:
            hash_status = detail["compiler_input_hash_status"]
            source_hash = detail["compiler_input_utf16le_sha256"]
            if (
                not isinstance(hash_status, str)
                or hash_status not in {"observed", "over-limit", "unavailable"}
                or (hash_status == "observed" and (
                    not isinstance(source_hash, str)
                    or re.fullmatch(r"[0-9a-f]{64}", source_hash) is None
                ))
                or (hash_status != "observed" and source_hash is not None)
                or (hash_status == "over-limit" and source_length <= 262_144)
                or (hash_status == "observed" and source_length > 262_144)
            ):
                raise ContractError("trace dynamic code compiler input hash is invalid")
        caller_script_id = detail.get("caller_script_id")
        if (
            isinstance(caller_script_id, bool)
            or not isinstance(caller_script_id, int)
            or not -1 <= caller_script_id <= 2_147_483_647
        ):
            raise ContractError("trace dynamic code caller_script_id is invalid")
        if process.get("type") != "renderer":
            raise ContractError("trace dynamic code process is invalid")
        caller_status = detail.get("caller_status")
        if caller_script_id == -1:
            if (
                caller_status != "unavailable"
                or caller_parent_status is not None
                or parent is not None
                or execution is not None
            ):
                raise ContractError("trace dynamic code caller is invalid")
        else:
            if caller_status != "observed":
                raise ContractError("trace dynamic code caller is invalid")
            if parent is None:
                if (
                    caller_parent_status not in {
                        "script_parent_not_in_trace",
                        "caller_context_ambiguous",
                    }
                    or execution is not None
                ):
                    raise ContractError("trace dynamic code caller parent is invalid")
            elif caller_parent_status is not None:
                raise ContractError("trace dynamic code caller parent is invalid")
            if parent is not None and execution is None:
                raise ContractError("trace dynamic code caller context is invalid")
            if execution is not None:
                context_id = execution.get("context_id")
                if not isinstance(context_id, str) or not context_id:
                    raise ContractError("trace dynamic code caller context is invalid")
                for context_key in ("frame_id", "worker_id"):
                    context_value = execution.get(context_key)
                    if context_value is not None and context_value != context_id:
                        raise ContractError("trace dynamic code caller context is invalid")
                script_id = execution.get("script_id")
                if _require_v8_script_identity(
                    script_id,
                    pid=process["pid"],
                    context_id=context_id,
                    label="trace dynamic code caller",
                ) != caller_script_id:
                    raise ContractError("trace dynamic code caller script is invalid")
    if event == {"category": "execution", "name": "host.callback.execution"}:
        detail = _require_dict(data.get("detail"), "trace host callback detail")
        completion = detail.get("completion")
        duration = detail.get("duration_ns")
        parent_status = detail.get("causal_parent_status")
        message_dispatch_parent_status = detail.get(
            "message_dispatch_parent_status"
        )
        expected = {
            "native_name",
            "thread_id",
            "completion",
            "callback_interface",
            "callback_operation",
            "callback_kind",
        }
        if completion == "open":
            if duration is not None:
                raise ContractError("open host callback cannot carry a duration")
        elif completion == "complete":
            _require_int(duration, "trace host callback duration_ns")
            if duration > MAX_TRACE_EVENT_DURATION_NS:
                raise ContractError("trace host callback duration exceeds limit")
            expected.add("duration_ns")
        else:
            raise ContractError("trace host callback completion is invalid")
        if parent_status is not None:
            expected.add("causal_parent_status")
        if message_dispatch_parent_status is not None:
            expected.add("message_dispatch_parent_status")
        if (
            set(detail) != expected
            or detail.get("native_name") != "BrowserCore.HostCallbackExecution"
            or provenance.get("source") != "native"
            or provenance.get("component")
            != EXACT_NATIVE_EVENT_COMPONENTS["BrowserCore.HostCallbackExecution"]
            or value is not None
        ):
            raise ContractError("trace host callback metadata is invalid")
        _require_int(detail.get("thread_id"), "trace host callback thread_id", 1)
        for field in ("callback_interface", "callback_operation"):
            value_text = detail.get(field)
            if (
                not isinstance(value_text, str)
                or CALLBACK_DESCRIPTOR_RE.fullmatch(value_text) is None
            ):
                raise ContractError("trace host callback descriptor is invalid")
        if not _allowed_string(detail.get("callback_kind"), CALLBACK_KINDS):
            raise ContractError("trace host callback kind is invalid")
        if (
            message_dispatch_parent is not None
            or message_dispatch_parent_status is not None
        ) and (
            detail.get("callback_interface") != "EventListener"
            or detail.get("callback_operation") != "handleEvent"
            or detail.get("callback_kind") != "function"
        ):
            raise ContractError("trace host callback message dispatch link is invalid")
        if message_dispatch_parent is not None:
            if message_dispatch_parent_status is not None:
                raise ContractError(
                    "trace host callback message dispatch parent is invalid"
                )
        elif message_dispatch_parent_status is not None and (
            message_dispatch_parent_status != "message_dispatch_parent_not_in_trace"
        ):
            raise ContractError(
                "trace host callback message dispatch parent is invalid"
            )
        if process.get("type") != "renderer":
            raise ContractError("trace host callback process is invalid")
        context_id = (execution or {}).get("context_id")
        if not isinstance(context_id, str) or not context_id:
            raise ContractError("trace host callback context is invalid")
        for context_key in ("frame_id", "worker_id"):
            context_value = (execution or {}).get(context_key)
            if context_value is not None and context_value != context_id:
                raise ContractError("trace host callback context is invalid")
        script_id = (execution or {}).get("script_id")
        if script_id is None:
            if parent is not None or parent_status is not None:
                raise ContractError("trace host callback script parent is invalid")
        else:
            if not isinstance(script_id, str) or not script_id:
                raise ContractError("trace host callback script is invalid")
            _require_v8_script_identity(
                script_id,
                pid=process["pid"],
                context_id=context_id,
                label="trace host callback",
            )
            if parent is None:
                if parent_status != "script_parent_not_in_trace":
                    raise ContractError("trace host callback script parent is invalid")
            elif parent_status is not None:
                raise ContractError("trace host callback script parent is invalid")
    if event == {
        "category": "execution",
        "name": "promise.microtask.execution",
    }:
        detail = _require_dict(data.get("detail"), "trace promise microtask detail")
        completion = detail.get("completion")
        duration = detail.get("duration_ns")
        expected = {
            "native_name",
            "thread_id",
            "completion",
            "boundary",
            "job_kind",
        }
        if completion == "open":
            if duration is not None:
                raise ContractError("open promise microtask cannot carry a duration")
        elif completion == "complete":
            _require_int(duration, "trace promise microtask duration_ns")
            if duration > MAX_TRACE_EVENT_DURATION_NS:
                raise ContractError("trace promise microtask duration exceeds limit")
            expected.add("duration_ns")
        else:
            raise ContractError("trace promise microtask completion is invalid")
        if (
            set(detail) != expected
            or detail.get("native_name")
            != "BrowserCore.PromiseMicrotaskExecution"
            or detail.get("boundary") != "v8-isolate-promise-hook-before-after"
            or detail.get("job_kind") != "unclassified"
            or provenance.get("source") != "native"
            or provenance.get("component")
            != EXACT_NATIVE_EVENT_COMPONENTS[
                "BrowserCore.PromiseMicrotaskExecution"
            ]
            or value is not None
            or parent is not None
        ):
            raise ContractError("trace promise microtask metadata is invalid")
        _require_int(
            detail.get("thread_id"),
            "trace promise microtask thread_id",
            1,
        )
        if process.get("type") != "renderer":
            raise ContractError("trace promise microtask process is invalid")
        if not isinstance(execution, dict) or set(execution) - {
            "context_id",
            "frame_id",
            "worker_id",
        }:
            raise ContractError("trace promise microtask execution is invalid")
        context_id = execution.get("context_id")
        if not isinstance(context_id, str) or not context_id:
            raise ContractError("trace promise microtask context is invalid")
        for context_key in ("frame_id", "worker_id"):
            context_value = execution.get(context_key)
            if context_value is not None and context_value != context_id:
                raise ContractError("trace promise microtask context is invalid")
    if event == {"category": "execution", "name": "script.execution"}:
        detail = _require_dict(data.get("detail"), "trace script execution detail")
        completion = detail.get("completion")
        duration = detail.get("duration_ns")
        if detail.get("native_name") != "BrowserCore.ScriptExecution":
            raise ContractError("trace script execution native name is invalid")
        _require_int(detail.get("thread_id"), "trace script execution thread_id", 1)
        if completion == "open":
            if duration is not None:
                raise ContractError("open script execution cannot carry a duration")
            expected = {"native_name", "thread_id", "completion"}
        elif completion == "complete":
            _require_int(duration, "trace script execution duration_ns")
            if duration > MAX_TRACE_EVENT_DURATION_NS:
                raise ContractError("trace script execution duration exceeds limit")
            expected = {"native_name", "thread_id", "completion", "duration_ns"}
        else:
            raise ContractError("trace script execution completion is invalid")
        if set(detail) != expected:
            raise ContractError("trace script execution detail fields are invalid")
        if (
            provenance.get("source") != "native"
            or provenance.get("component")
            != EXACT_NATIVE_EVENT_COMPONENTS["BrowserCore.ScriptExecution"]
            or value is not None
        ):
            raise ContractError("trace script execution metadata is invalid")
        if process.get("type") != "renderer":
            raise ContractError("trace script execution process is invalid")
        context_id = (execution or {}).get("context_id")
        if not isinstance(context_id, str) or not context_id:
            raise ContractError("trace script execution context is invalid")
        for context_key in ("frame_id", "worker_id"):
            context_value = (execution or {}).get(context_key)
            if context_value is not None and context_value != context_id:
                raise ContractError("trace script execution context is invalid")
        script_id = (execution or {}).get("script_id")
        if not isinstance(script_id, str) or not script_id:
            raise ContractError("trace script execution script is invalid")
        _require_v8_script_identity(
            script_id,
            pid=process["pid"],
            context_id=context_id,
            label="trace script execution",
        )
        if parent is not None:
            raise ContractError("trace script execution parent is invalid")
    trace_category = provenance.get("trace_category")
    expected_trace_category = EXACT_NATIVE_TRACE_CATEGORIES.get(native_name)
    if (
        trace_category is not None
        and expected_trace_category is not None
        and trace_category != expected_trace_category
    ):
        raise ContractError("exact native trace provenance category is invalid")
    if trace_category is not None and trace_category not in {
        "browser_core.debug",
        "browser_core.stream",
        "blink.bindings",
        "blink.bindings.encoding",
    }:
        raise ContractError("trace provenance category is invalid")
    if trace_category == "browser_core.stream" and event["category"] != "stream":
        raise ContractError("stream trace provenance carried a non-stream event")
    if trace_category in {
        "blink.bindings",
        "blink.bindings.encoding",
    } and event["category"] != "api":
        raise ContractError("binding trace provenance carried a non-API event")
    reject_sensitive_keys(data)
    return data
