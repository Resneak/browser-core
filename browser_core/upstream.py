from __future__ import annotations

import ast
import copy
import hashlib
import json
import os
import re
import stat
import subprocess
import time
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from pathlib import PurePosixPath
from pathlib import PureWindowsPath
from typing import Any, Callable
from urllib.parse import urlparse

from .bounded_process import run_with_bounded_stdout
from .control_files import decode_strict_json_bytes, read_bounded_control_snapshot_result
from .contracts import (
    EXACT_NATIVE_EVENT_COMPONENTS,
    EXACT_NATIVE_EVENT_ROUTES,
    EXACT_NATIVE_TRACE_CATEGORIES,
    UNPROMOTED_NATIVE_EVENT_ROUTES,
    ContractError,
    REVISION_RE,
)
from .git_executable import (
    decode_portable_git_path,
    git_blob_sha1,
    git_executable_binding,
    isolated_git_environment,
    select_git_executable,
)
from .owned_paths import directory_ancestry_binding, directory_identity
from .windows_change_time import windows_change_time


UPSTREAM_SCHEMA = "browser-core.upstream/1"
LEGACY_PATCH_SCHEMA = "browser-core.patch-series/1"
PATCH_SCHEMA = "browser-core.patch-series/2"
LEGACY_NATIVE_EVENT_ROUTES_SCHEMA = "browser-core.native-event-routes/5"
MESSAGE_CALLBACK_NATIVE_EVENT_ROUTES_SCHEMA = "browser-core.native-event-routes/6"
PROMISE_NATIVE_EVENT_ROUTES_SCHEMA = "browser-core.native-event-routes/7"
NATIVE_EVENT_ROUTES_SCHEMA = "browser-core.native-event-routes/8"
SHA256_RE = re.compile(r"[0-9a-f]{64}")
MAX_UPSTREAM_MANIFEST_BYTES = 1024 * 1024
MAX_GCLIENT_CONFIG_BYTES = 64 * 1024
MAX_DEPOT_INDEX_BYTES = 8 * 1024 * 1024
MAX_DEPOT_STATUS_BYTES = 1024 * 1024
MAX_DEPOT_WRAPPER_BYTES = 1024 * 1024
MAX_DEPOT_TRACKED_FILES = 4096
MAX_DEPOT_TRACKED_BYTES = 64 * 1024 * 1024
MAX_DEPOT_TRACKED_FILE_BYTES = 8 * 1024 * 1024
MAX_DEPOT_TRACKED_SCAN_SECONDS = 60.0
DEPOT_TOOL_WRAPPERS = frozenset({
    b"bootstrap/win_tools.bat", b"gclient.bat", b"autoninja.bat",
})
MAX_PATCH_SERIES_BYTES = 2 * 1024 * 1024
MAX_PATCH_BYTES = 64 * 1024 * 1024
MAX_PATCHES = 1024
MAX_POSTIMAGES = 4096
MAX_PATCH_TOTAL_BYTES = 256 * 1024 * 1024
MAX_CHANGED_PATH_BYTES = 8 * 1024 * 1024
MAX_CHANGED_PATHS = 100_000
MAX_PATCHED_INDEX_BYTES = 64 * 1024 * 1024
MAX_POSTIMAGE_BYTES = 256 * 1024 * 1024
MAX_TOTAL_POSTIMAGE_BYTES = 256 * 1024 * 1024
MAX_GIT_FILTER_CONFIG_BYTES = 64 * 1024
MAX_GIT_FILTER_OVERRIDES = 64
MAX_GIT_FILTER_OVERRIDE_BYTES = 8 * 1024
SAFE_TEXT_RE = re.compile(r"^[\x20-\x7e]{1,4096}$")


def _windows_unsafe_component(component: str) -> bool:
    return (
        component.casefold() == ".git"
        or component.endswith((".", " "))
        or PureWindowsPath(component).is_reserved()
        # NTFS counts UTF-16 code units, so one astral character uses two.
        or len(component.encode("utf-16-le")) > 255 * 2
        or any(
            character in '\\/:*?"<>|'
            or ord(character) < 0x20
            or ord(character) == 0x7F
            for character in component
        )
    )


@dataclass(frozen=True)
class VerifiedPatchBundle:
    upstream: dict[str, Any]
    upstream_body: bytes
    series: dict[str, Any]
    series_body: bytes
    patch_bodies: tuple[tuple[str, bytes], ...]
    report: dict[str, Any]


def _load_json_with_body(
    path: Path,
    *,
    maximum: int = MAX_UPSTREAM_MANIFEST_BYTES,
    label: str = "JSON control document",
) -> tuple[dict[str, Any], bytes, tuple[int, int, int, int, int, int]]:
    if not isinstance(path, Path):
        raise ContractError(f"{label} path must be a Path")
    snapshot = read_bounded_control_snapshot_result(
        path,
        maximum=maximum,
        label=label,
        require_single_link=True,
    )
    if snapshot.state != "complete" or snapshot.body is None or snapshot.identity is None:
        raise ContractError(f"{label} is {snapshot.state}")
    data = decode_strict_json_bytes(snapshot.body, label=label)
    if not isinstance(data, dict):
        raise ContractError(f"{label} must contain an object")
    return data, snapshot.body, snapshot.identity


def load_json(
    path: Path,
    *,
    maximum: int = MAX_UPSTREAM_MANIFEST_BYTES,
    label: str = "JSON control document",
) -> dict[str, Any]:
    document, _body, _identity = _load_json_with_body(
        path,
        maximum=maximum,
        label=label,
    )
    return document


def _validate_https_repository(value: Any, label: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) > 2048
        or any(ord(character) <= 0x20 or ord(character) == 0x7F for character in value)
    ):
        raise ContractError(f"upstream {label} repository must be HTTPS")
    parsed = None
    try:
        parsed = urlparse(value)
        hostname = parsed.hostname
        port = parsed.port
    except ValueError:
        hostname = None
        port = None
    if (
        parsed is None
        or parsed.scheme != "https"
        or not hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or "?" in value
        or "#" in value
        or (port is not None and port != 443)
    ):
        raise ContractError(f"upstream {label} repository must be credential-free HTTPS")
    return value


def verify_upstream(
    root: Path, *, expected_manifest_sha256: str | None = None,
) -> dict[str, Any]:
    if not isinstance(root, Path):
        raise ContractError("upstream root must be a Path")
    if expected_manifest_sha256 is not None and (
        not isinstance(expected_manifest_sha256, str)
        or not SHA256_RE.fullmatch(expected_manifest_sha256.lower())
    ):
        raise ContractError("upstream manifest digest is invalid")
    manifest_path = (root / "upstream.json").absolute()
    parent_before = directory_ancestry_binding(
        manifest_path.parent, label="upstream manifest parent"
    )
    data, manifest_body, manifest_identity = _load_json_with_body(
        manifest_path,
        maximum=MAX_UPSTREAM_MANIFEST_BYTES,
        label="upstream manifest",
    )
    if (
        expected_manifest_sha256 is not None
        and hashlib.sha256(manifest_body).hexdigest() != expected_manifest_sha256.lower()
    ):
        raise ContractError("upstream manifest digest does not match expected bytes")
    if data.get("schema") != UPSTREAM_SCHEMA:
        raise ContractError("unsupported upstream manifest schema")
    if set(data) != {"schema", "captured_at", "chromium", "depot_tools", "build"}:
        raise ContractError("upstream manifest fields are invalid")
    captured_at = data.get("captured_at")
    try:
        parsed_capture_date = date.fromisoformat(captured_at)
    except (TypeError, ValueError):
        parsed_capture_date = None
    if not isinstance(captured_at, str) or parsed_capture_date is None:
        raise ContractError("upstream capture date is invalid")
    for name in ("chromium", "depot_tools"):
        item = data.get(name)
        expected_fields = (
            {"repository", "revision", "version"}
            if name == "chromium"
            else {"repository", "revision"}
        )
        if not isinstance(item, dict) or set(item) != expected_fields:
            raise ContractError(f"upstream {name} entry is missing")
        _validate_https_repository(item.get("repository"), name)
        if not isinstance(item.get("revision"), str) or not REVISION_RE.fullmatch(item["revision"]):
            raise ContractError(f"upstream {name} revision must be 40-hex")
    version = data["chromium"].get("version")
    if not isinstance(version, str) or not re.fullmatch(r"[1-9][0-9]{0,2}(?:\.[0-9]+){3}", version):
        raise ContractError("upstream Chromium version must be an exact four-part version")
    build = data.get("build")
    if not isinstance(build, dict) or set(build) != {
        "target",
        "support_targets",
        "output_directory",
        "gn_args",
    } or build.get("target") != "chrome":
        raise ContractError("upstream build target must be chrome")
    support_targets = build.get("support_targets", [])
    if (
        not isinstance(support_targets, list)
        or len(support_targets) > 128
        or any(
            not isinstance(target, str)
            or not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", target)
            # These values follow the fixed target on the autoninja command.
            or target.startswith("-")
            for target in support_targets
        )
        or len(set(support_targets)) != len(support_targets)
    ):
        raise ContractError("upstream support_targets must be unique non-empty strings")
    output_directory = build.get("output_directory")
    output_parts = (
        PurePosixPath(output_directory).parts
        if isinstance(output_directory, str)
        else ()
    )
    if (
        not isinstance(output_directory, str)
        or not output_parts
        # GN receives this directory as a positional command argument.
        or output_parts[0].startswith("-")
        or PurePosixPath(output_directory).is_absolute()
        or PurePosixPath(output_directory).as_posix() != output_directory
        or "\\" in output_directory
        or ":" in output_directory
        or any(part in {"", ".", ".."} for part in output_parts)
        or any(part.casefold() == ".git" for part in output_parts)
        or any(_windows_unsafe_component(part) for part in output_parts)
    ):
        raise ContractError("upstream output directory is invalid")
    gn_args = build.get("gn_args")
    if (
        not isinstance(gn_args, list)
        or not 1 <= len(gn_args) <= 256
        or any(not isinstance(item, str) or not SAFE_TEXT_RE.fullmatch(item) for item in gn_args)
        or len(gn_args) != len(set(gn_args))
    ):
        raise ContractError("upstream GN arguments are invalid")
    assignment_names: list[str] = []
    for item in gn_args:
        name, separator, value = item.partition("=")
        name = name.strip(" \t")
        if (
            not separator
            or re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name) is None
            or not value.strip(" \t")
        ):
            raise ContractError("upstream GN arguments are invalid")
        assignment_names.append(name)
    if len(assignment_names) != len(set(assignment_names)):
        raise ContractError("upstream GN arguments are invalid")
    final = read_bounded_control_snapshot_result(
        manifest_path,
        maximum=MAX_UPSTREAM_MANIFEST_BYTES,
        label="upstream manifest",
        require_single_link=True,
    )
    if (
        final.state != "complete"
        or final.body != manifest_body
        or final.identity != manifest_identity
        or directory_ancestry_binding(
            manifest_path.parent, label="upstream manifest parent"
        ) != parent_before
    ):
        raise ContractError("upstream manifest changed during verification")
    return data


def verify_gclient_config(config_path: Path, expected_repository: str) -> dict[str, str]:
    """Verify the single pinned Chromium solution without executing `.gclient`."""
    if not isinstance(config_path, Path) or config_path.name != ".gclient":
        raise ContractError("gclient configuration path is invalid")
    _validate_https_repository(expected_repository, "Chromium")
    config_path = config_path.absolute()
    parent_before = directory_ancestry_binding(
        config_path.parent, label="gclient configuration parent"
    )
    first = read_bounded_control_snapshot_result(
        config_path,
        maximum=MAX_GCLIENT_CONFIG_BYTES,
        label="gclient configuration",
        require_single_link=True,
    )
    if first.state != "complete" or first.body is None or first.identity is None:
        raise ContractError(f"gclient configuration is {first.state}")
    try:
        module = ast.parse(first.body.decode("utf-8", errors="strict"), mode="exec")
    except (UnicodeDecodeError, SyntaxError, RecursionError, ValueError):
        raise ContractError("gclient configuration is invalid") from None

    # A .gclient file is Python, so inspect only the syntax tree of the two
    # supported literal shapes. Never evaluate expressions or execute code.
    if len(module.body) != 1 or not isinstance(module.body[0], ast.Assign):
        raise ContractError("gclient configuration must declare one solution")
    assignment = module.body[0]
    if (
        len(assignment.targets) != 1
        or not isinstance(assignment.targets[0], ast.Name)
        or assignment.targets[0].id != "solutions"
        or not isinstance(assignment.value, ast.List)
        or len(assignment.value.elts) != 1
        or not isinstance(assignment.value.elts[0], ast.Dict)
    ):
        raise ContractError("gclient configuration must declare one solution")
    solution = assignment.value.elts[0]
    fields: dict[str, ast.expr] = {}
    for key, value in zip(solution.keys, solution.values):
        if (
            not isinstance(key, ast.Constant)
            or not isinstance(key.value, str)
            or key.value in fields
        ):
            raise ContractError("gclient configuration solution fields are invalid")
        fields[key.value] = value
    required = {"name", "url", "custom_deps", "custom_vars"}
    defaulted = {"deps_file", "managed"}
    if set(fields) not in (required, required | defaulted):
        raise ContractError("gclient configuration solution fields are invalid")

    def literal_equals(name: str, expected: object) -> bool:
        value = fields[name]
        return isinstance(value, ast.Constant) and type(value.value) is type(expected) and value.value == expected

    if (
        not literal_equals("name", "src")
        or not literal_equals("url", expected_repository)
        or any(
            not isinstance(fields[name], ast.Dict)
            or bool(fields[name].keys)
            for name in ("custom_deps", "custom_vars")
        )
        or (
            "deps_file" in fields
            and (not literal_equals("deps_file", "DEPS") or not literal_equals("managed", False))
        )
    ):
        raise ContractError("gclient configuration does not match the pinned solution")

    final = read_bounded_control_snapshot_result(
        config_path,
        maximum=MAX_GCLIENT_CONFIG_BYTES,
        label="gclient configuration",
        require_single_link=True,
    )
    if (
        final.state != "complete"
        or final.body != first.body
        or final.identity != first.identity
        or directory_ancestry_binding(config_path.parent, label="gclient configuration parent")
        != parent_before
    ):
        raise ContractError("gclient configuration changed during verification")
    return {"status": "verified", "solution": "src"}


def _bounded_text(value: Any, *, label: str, maximum: int = 4096) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value.encode("utf-8")) > maximum
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise ContractError(f"{label} is invalid")
    return value


_NATIVE_EVENT_NAME_RE = re.compile(r"BrowserCore\.[A-Za-z][A-Za-z0-9]*")
_NATIVE_EVENT_CATEGORY_FIELD_RE = re.compile(
    r'"event_category"\s*,\s*"([^"]+)"'
)
_NATIVE_EVENT_NAME_FIELD_RE = re.compile(r'"event_name"\s*,\s*"([^"]+)"')
_NATIVE_EVENT_SCHEMA_RE = re.compile(r'"schema"\s*,\s*"([^"]+)"')
_NATIVE_EVENT_COMPONENT_RE = re.compile(r'"component"\s*,\s*"([^"]+)"')
_NATIVE_EVENT_LEGACY_ROUTE_RE = re.compile(
    r'"schema"\s*,\s*"browser-core\.native/1"\s*,\s*'
    r'"([^"]+)"\s*,\s*"([^"]+)"'
)
_NATIVE_TRACE_CALL_START_RE = re.compile(
    r"(?m)^[ \t]*TRACE_EVENT(?:_INSTANT|_BEGIN)?\s*\("
)
_NATIVE_TRACE_CATEGORY_RE = re.compile(
    r'^[ \t]*TRACE_EVENT(?:_INSTANT|_BEGIN)?\s*\(\s*"([^"]+)"'
)
_NATIVE_EVENT_SOURCE_LOCATIONS = {
    "BrowserCore.ScriptRun": (
        "0003-browser-core-context-and-causality-track-events.patch",
        ("third_party/blink/renderer/bindings/core/v8/v8_script_runner.cc",),
    ),
    "BrowserCore.ScriptExecution": (
        "0007-browser-core-script-execution-scope.patch",
        ("third_party/blink/renderer/bindings/core/v8/v8_script_runner.cc",),
    ),
    "BrowserCore.HostCallbackExecution": (
        "0050-browser-core-host-callback-execution.patch",
        (
            "third_party/blink/renderer/bindings/core/v8/"
            "callback_invoke_helper.cc",
        ),
    ),
    "BrowserCore.PromiseMicrotaskExecution": (
        "0053-browser-core-promise-microtask-execution.patch",
        (
            "third_party/blink/renderer/core/scheduler/"
            "task_attribution_tracker_impl.cc",
        ),
    ),
    "BrowserCore.DynamicCodeMaterialized": (
        "0054-browser-core-dynamic-code-materialization.patch",
        ("src/codegen/compiler.cc",),
    ),
    "BrowserCore.CanvasReadback": (
        "0002-browser-core-canvas-track-event.patch",
        ("third_party/blink/renderer/core/html/canvas/html_canvas_element.cc",),
    ),
    "BrowserCore.CryptoDigest": (
        "0003-browser-core-context-and-causality-track-events.patch",
        ("third_party/blink/renderer/modules/crypto/subtle_crypto.cc",),
    ),
    "BrowserCore.WasmCompiled": (
        "0003-browser-core-context-and-causality-track-events.patch",
        ("third_party/blink/renderer/bindings/core/v8/v8_metrics.cc",),
    ),
    "BrowserCore.FetchCall": (
        "0003-browser-core-context-and-causality-track-events.patch",
        ("third_party/blink/renderer/core/fetch/fetch_manager.cc",),
    ),
    "BrowserCore.FetchRequestStart": (
        "0003-browser-core-context-and-causality-track-events.patch",
        ("third_party/blink/renderer/core/fetch/fetch_manager.cc",),
    ),
    "BrowserCore.MessagePost": (
        "0003-browser-core-context-and-causality-track-events.patch",
        ("third_party/blink/renderer/core/messaging/message_port.cc",),
    ),
    "BrowserCore.MessageDispatch": (
        "0010-browser-core-messageport-delivery-correlation.patch",
        ("third_party/blink/renderer/core/messaging/message_port.cc",),
    ),
    "BrowserCore.StreamReadRequest": (
        "0004-browser-core-readable-stream-track-events.patch",
        (
            "third_party/blink/renderer/core/streams/readable_stream_default_reader.cc",
            "third_party/blink/renderer/core/streams/readable_stream_byob_reader.cc",
        ),
    ),
    "BrowserCore.StreamReadResult": (
        "0004-browser-core-readable-stream-track-events.patch",
        (
            "third_party/blink/renderer/core/streams/readable_stream_default_reader.cc",
            "third_party/blink/renderer/core/streams/readable_stream_byob_reader.cc",
        ),
    ),
    "BrowserCore.BodyConsume": (
        "0009-browser-core-body-consumer-track-event.patch",
        ("third_party/blink/renderer/core/fetch/body.cc",),
    ),
}


def _added_patch_sources(body: bytes) -> list[tuple[str, str]]:
    sources: list[tuple[str, str]] = []
    source_path: str | None = None
    added_lines: list[str] = []

    def flush() -> None:
        nonlocal added_lines
        if source_path is not None:
            sources.append((source_path, "\n".join(added_lines)))
        added_lines = []

    for line in body.splitlines():
        if line.startswith(b"diff --git a/"):
            flush()
            try:
                header = line.decode("utf-8", errors="strict")
            except UnicodeDecodeError:
                raise ContractError("patch diff target is not UTF-8") from None
            match = re.fullmatch(r"diff --git a/(\S+) b/(\S+)", header)
            if match is None or match.group(1) != match.group(2):
                raise ContractError("patch diff target is invalid")
            source_path = match.group(2)
        elif (
            source_path is not None
            and line.startswith(b"+")
            and not line.startswith(b"+++")
        ):
            try:
                added_lines.append(line[1:].decode("utf-8", errors="strict"))
            except UnicodeDecodeError:
                raise ContractError("native event route source is not UTF-8") from None
    flush()
    return sources


def _mask_cpp_noncode(source: str) -> str:
    masked = list(source)
    index = 0

    def mask(start: int, end: int) -> None:
        for position in range(start, end):
            if source[position] != "\n":
                masked[position] = " "

    while index < len(source):
        character = source[index]
        following = source[index + 1] if index + 1 < len(source) else ""
        if character == "/" and following == "/":
            end = source.find("\n", index + 2)
            while end >= 0 and end > index and source[end - 1] == "\\":
                continued_end = source.find("\n", end + 1)
                if continued_end < 0:
                    end = len(source)
                    break
                end = continued_end
            end = len(source) if end < 0 else end
            mask(index, end)
            index = end
            continue
        if character == "/" and following == "*":
            end = source.find("*/", index + 2)
            end = len(source) if end < 0 else end + 2
            mask(index, end)
            index = end
            continue
        if character == "R" and following == '"':
            open_paren = source.find("(", index + 2, min(len(source), index + 19))
            delimiter = source[index + 2 : open_paren] if open_paren >= 0 else ""
            if open_paren >= 0 and len(delimiter) <= 16 and not any(
                item.isspace() or item in "()\\" for item in delimiter
            ):
                close_token = ")" + delimiter + '"'
                close = source.find(close_token, open_paren + 1)
                end = len(source) if close < 0 else close + len(close_token)
                mask(index, end)
                index = end
                continue
        if character in {'"', "'"}:
            quote = character
            end = index + 1
            escaped = False
            while end < len(source):
                item = source[end]
                end += 1
                if escaped:
                    escaped = False
                elif item == "\\":
                    escaped = True
                elif item == quote:
                    break
            mask(index, end)
            index = end
            continue
        index += 1
    return _mask_cpp_literal_if_zero("".join(masked))


def _mask_cpp_literal_if_zero(source: str) -> str:
    """Mask branches that the preprocessor proves dead from literal ``#if 0``.

    Other conditions remain visible because evaluating build flags or macros here
    would turn the patch verifier into an incomplete C++ preprocessor. Nested
    conditionals are tracked so an ``#else`` belonging to an inner condition
    cannot accidentally reactivate an outer dead branch.
    """

    masked = list(source)
    frames: list[dict[str, bool]] = []
    active = True
    offset = 0

    def is_literal_zero(expression: str) -> bool:
        return re.fullmatch(r"\s*\(?\s*0\s*\)?\s*", expression) is not None

    for line in source.splitlines(keepends=True):
        content = line.rstrip("\r\n")
        directive = re.match(
            r"^[ \t]*#[ \t]*(if|ifdef|ifndef|elif|else|endif)\b(.*)$",
            content,
        )
        if directive is not None:
            name = directive.group(1)
            expression = directive.group(2)
            if name == "if":
                parent_active = active
                dead_chain = is_literal_zero(expression)
                frames.append(
                    {"parent_active": parent_active, "dead_chain": dead_chain}
                )
                active = parent_active and not dead_chain
            elif name in {"ifdef", "ifndef"}:
                frames.append({"parent_active": active, "dead_chain": False})
            elif name == "elif" and frames:
                frame = frames[-1]
                if frame["dead_chain"] and is_literal_zero(expression):
                    active = False
                else:
                    active = frame["parent_active"]
                    frame["dead_chain"] = False
            elif name == "else" and frames:
                active = frames[-1]["parent_active"]
                frames[-1]["dead_chain"] = False
            elif name == "endif" and frames:
                active = frames.pop()["parent_active"]
        if not active:
            for position in range(offset, offset + len(line)):
                if source[position] not in "\r\n":
                    masked[position] = " "
        offset += len(line)
    return "".join(masked)


def _native_trace_calls(added_source: str) -> list[str]:
    searchable_source = _mask_cpp_noncode(added_source)
    calls: list[str] = []
    for match in _NATIVE_TRACE_CALL_START_RE.finditer(searchable_source):
        open_index = searchable_source.find("(", match.start(), match.end())
        depth = 0
        quote: str | None = None
        escaped = False
        for index in range(open_index, len(searchable_source)):
            character = searchable_source[index]
            if quote is not None:
                if escaped:
                    escaped = False
                elif character == "\\":
                    escaped = True
                elif character == quote:
                    quote = None
                continue
            if character in {'"', "'"}:
                quote = character
            elif character == "(":
                depth += 1
            elif character == ")":
                depth -= 1
                if depth == 0:
                    calls.append(added_source[match.start() : index + 1])
                    break
        else:
            raise ContractError("native event trace call is truncated")
    return calls


def _verify_native_event_route_sources(
    patch_bodies: list[tuple[str, bytes]],
    declared_routes: dict[
        str, tuple[str, str, str, int, str | None, tuple[str, ...]]
    ]
    | None,
) -> None:
    """Bind every reserved native event name to its pinned source route."""

    observed: dict[str, list[tuple[str, str, str, str, str]]] = {}
    for patch_name, body in patch_bodies:
        for source_path, added_source in _added_patch_sources(body):
            for emitter in _native_trace_calls(added_source):
                _record_native_event_route_source(
                    observed,
                    emitter=emitter,
                    patch_name=patch_name,
                    source_path=source_path,
                )

    expected_routes = declared_routes or {
        native_name: (
            EXACT_NATIVE_TRACE_CATEGORIES[native_name],
            category,
            name,
            1,
            None,
            (),
        )
        for native_name, (category, name, _label) in EXACT_NATIVE_EVENT_ROUTES.items()
        if native_name not in UNPROMOTED_NATIVE_EVENT_ROUTES
    }
    expected_names = set(expected_routes)
    observed_names = set(observed)
    # The patch tooling is also used by synthetic/unit-test patch bundles that
    # do not contain Browser Core trace emitters. Once any reserved namespace
    # member is present, however, the population is an all-or-nothing contract.
    if not observed_names and declared_routes is None:
        return
    if observed_names != expected_names:
        raise ContractError(
            "native event route inventory differs from the reserved contract; "
            f"missing_count={len(expected_names - observed_names)}; "
            f"extra_count={len(observed_names - expected_names)}"
        )
    for native_name, (
        expected_trace_category,
        expected_category,
        expected_name,
        expected_emitters,
        expected_patch,
        expected_sources,
    ) in expected_routes.items():
        routes = observed[native_name]
        if (
            len(routes) != expected_emitters
            or {route[:3] for route in routes}
            != {(expected_trace_category, expected_category, expected_name)}
            or expected_patch is not None
            and {route[3] for route in routes} != {expected_patch}
            or expected_sources
            and {route[4] for route in routes} != set(expected_sources)
        ):
            raise ContractError(f"native event route differs from contract: {native_name}")


def _record_native_event_route_source(
    observed: dict[str, list[tuple[str, str, str, str, str]]],
    *,
    emitter: str,
    patch_name: str,
    source_path: str,
) -> None:
    matches = list(_NATIVE_EVENT_NAME_RE.finditer(emitter))
    if len(matches) > 1:
        raise ContractError("native event trace call has multiple reserved names")
    if not matches:
        return
    native_name = matches[0].group(0)
    trace_category_match = _NATIVE_TRACE_CATEGORY_RE.search(emitter)
    schema_match = _NATIVE_EVENT_SCHEMA_RE.search(emitter)
    component_match = _NATIVE_EVENT_COMPONENT_RE.search(emitter)
    category_match = _NATIVE_EVENT_CATEGORY_FIELD_RE.search(emitter)
    name_match = _NATIVE_EVENT_NAME_FIELD_RE.search(emitter)
    legacy_match = _NATIVE_EVENT_LEGACY_ROUTE_RE.search(emitter)
    if trace_category_match is None:
        raise ContractError(f"native event trace category is missing: {native_name}")
    component = component_match.group(1) if component_match else None
    if (
        schema_match is None
        or schema_match.group(1) != "browser-core.native/1"
        or component
        != (
            None
            if native_name == "BrowserCore.CanvasReadback"
            else EXACT_NATIVE_EVENT_COMPONENTS.get(native_name)
        )
    ):
        raise ContractError(
            f"native event route source identity differs: {native_name}"
        )
    if category_match is not None and name_match is not None:
        route = (
            trace_category_match.group(1),
            category_match.group(1),
            name_match.group(1),
        )
    elif legacy_match is not None:
        route = (
            trace_category_match.group(1),
            legacy_match.group(1),
            legacy_match.group(2),
        )
    else:
        raise ContractError(f"native event route fields are missing: {native_name}")
    observed.setdefault(native_name, []).append((*route, patch_name, source_path))


def _declared_native_event_routes(
    series: dict[str, Any],
) -> dict[str, tuple[str, str, str, int, str | None, tuple[str, ...]]]:
    declaration = series.get("native_event_routes")
    if not isinstance(declaration, dict) or set(declaration) != {"schema", "routes"}:
        raise ContractError("native event route declaration is invalid")
    routes_schema = declaration.get("schema")
    if not isinstance(routes_schema, str) or routes_schema not in {
        LEGACY_NATIVE_EVENT_ROUTES_SCHEMA,
        MESSAGE_CALLBACK_NATIVE_EVENT_ROUTES_SCHEMA,
        PROMISE_NATIVE_EVENT_ROUTES_SCHEMA,
        NATIVE_EVENT_ROUTES_SCHEMA,
    }:
        raise ContractError("unsupported native event route declaration schema")
    routes = declaration.get("routes")
    if not isinstance(routes, list) or len(routes) > 128:
        raise ContractError("native event routes must be a bounded list")
    declared: dict[
        str, tuple[str, str, str, int, str | None, tuple[str, ...]]
    ] = {}
    for index, item in enumerate(routes):
        if not isinstance(item, dict) or set(item) != {
            "native_name",
            "trace_category",
            "category",
            "name",
            "emitters",
            "patch",
            "sources",
        }:
            raise ContractError(f"native event route {index} is invalid")
        native_name = _bounded_text(
            item.get("native_name"), label=f"native event route {index} name"
        )
        trace_category = _bounded_text(
            item.get("trace_category"),
            label=f"native event route {index} trace category",
        )
        category = _bounded_text(
            item.get("category"), label=f"native event route {index} category"
        )
        name = _bounded_text(
            item.get("name"), label=f"native event route {index} event name"
        )
        emitters = item.get("emitters")
        if isinstance(emitters, bool) or not isinstance(emitters, int) or not 1 <= emitters <= 16:
            raise ContractError(f"native event route {index} emitter count is invalid")
        patch = item.get("patch")
        if (
            not isinstance(patch, str)
            or Path(patch).name != patch
            or not patch.endswith(".patch")
            or len(patch) > 255
        ):
            raise ContractError(f"native event route {index} patch is invalid")
        sources = item.get("sources")
        if (
            not isinstance(sources, list)
            or not 1 <= len(sources) <= 16
            or any(not isinstance(source, str) for source in sources)
            or len(sources) != len(set(sources))
        ):
            raise ContractError(f"native event route {index} sources are invalid")
        source_paths: list[str] = []
        for source in sources:
            parsed_source = PurePosixPath(source) if isinstance(source, str) else None
            if (
                parsed_source is None
                or parsed_source.is_absolute()
                or not parsed_source.parts
                or any(part in {"", ".", ".."} for part in parsed_source.parts)
                or "\\" in source
                or len(source.encode("utf-8")) > 4096
            ):
                raise ContractError(
                    f"native event route {index} source path is invalid"
                )
            source_paths.append(source)
        if native_name in declared:
            raise ContractError(f"duplicate native event route: {native_name}")
        declared[native_name] = (
            trace_category,
            category,
            name,
            emitters,
            patch,
            tuple(source_paths),
        )
    expected_names = set(EXACT_NATIVE_EVENT_ROUTES) - UNPROMOTED_NATIVE_EVENT_ROUTES
    if routes_schema in {
        LEGACY_NATIVE_EVENT_ROUTES_SCHEMA,
        MESSAGE_CALLBACK_NATIVE_EVENT_ROUTES_SCHEMA,
        PROMISE_NATIVE_EVENT_ROUTES_SCHEMA,
    }:
        expected_names.remove("BrowserCore.DynamicCodeMaterialized")
    if routes_schema in {
        LEGACY_NATIVE_EVENT_ROUTES_SCHEMA,
        MESSAGE_CALLBACK_NATIVE_EVENT_ROUTES_SCHEMA,
    }:
        expected_names.remove("BrowserCore.PromiseMicrotaskExecution")
    if routes_schema == LEGACY_NATIVE_EVENT_ROUTES_SCHEMA:
        expected_names.remove("BrowserCore.HostCallbackExecution")
    expected = {
        native_name: (
            EXACT_NATIVE_TRACE_CATEGORIES[native_name],
            category,
            name,
            2 if native_name in {
                "BrowserCore.StreamReadRequest",
                "BrowserCore.StreamReadResult",
            } else 1,
            _NATIVE_EVENT_SOURCE_LOCATIONS[native_name][0],
            _NATIVE_EVENT_SOURCE_LOCATIONS[native_name][1],
        )
        for native_name, (category, name, _label) in EXACT_NATIVE_EVENT_ROUTES.items()
        if native_name in expected_names
    }
    if declared != expected:
        raise ContractError("declared native event routes differ from the importer contract")
    return declared


def _verified_patch_bundle(root: Path) -> VerifiedPatchBundle:
    if not isinstance(root, Path):
        raise ContractError("upstream root must be a Path")
    root_ancestry = directory_ancestry_binding(
        root.absolute(), label="patch series root"
    )
    patch_dir = root / "patches"
    patch_ancestry = directory_ancestry_binding(
        patch_dir.absolute(), label="patch series directory"
    )

    def require_root_authority() -> None:
        if directory_ancestry_binding(
            root.absolute(), label="patch series root"
        ) != root_ancestry:
            raise ContractError("patch series root authority changed")
        if directory_ancestry_binding(
            patch_dir.absolute(), label="patch series directory"
        ) != patch_ancestry:
            raise ContractError("patch series directory authority changed")

    bundle = _cached_verified_patch_bundle(root)
    if bundle is not None:
        require_root_authority()
        return bundle
    bundle = _verified_patch_bundle_uncached(root)
    require_root_authority()
    _store_verified_patch_bundle(root, bundle)
    require_root_authority()
    return bundle


# Reuse expensive patch parsing only after fresh bounded reads establish exact
# byte equality with the verified snapshots. File timestamps are not content
# identities (notably, Windows permits same-length edits with restored mtime).
# Stored keys never come from a later stat of a different file population.
_BUNDLE_CACHE: dict[Path, VerifiedPatchBundle] = {}
_BUNDLE_CACHE_LOCK = __import__("threading").Lock()


def _cached_verified_patch_bundle(root: Path) -> VerifiedPatchBundle | None:
    with _BUNDLE_CACHE_LOCK:
        bundle = _BUNDLE_CACHE.get(root)
    if bundle is None:
        return None
    patch_dir = root / "patches"
    try:
        directory_before = directory_identity(patch_dir, label="patch directory")
        if directory_before is None:
            return None
        # A newly added, unlisted patch must invalidate a hit too. Filenames
        # used for reads below come only from the already verified bundle.
        names = set()
        with os.scandir(patch_dir) as entries:
            for index, entry in enumerate(entries):
                if index >= MAX_PATCHES + 1024:
                    return None
                if entry.name.endswith(".patch"):
                    names.add(entry.name)
        if names != {name for name, _body in bundle.patch_bodies}:
            return None
        inputs = (
            (root / "upstream.json", bundle.upstream_body, MAX_UPSTREAM_MANIFEST_BYTES),
            (patch_dir / "series.json", bundle.series_body, MAX_PATCH_SERIES_BYTES),
            *((patch_dir / name, body, MAX_PATCH_BYTES) for name, body in bundle.patch_bodies),
        )
        identities = []
        for path, expected_body, maximum in inputs:
            snapshot = read_bounded_control_snapshot_result(
                path, maximum=maximum, label="verified patch bundle input",
                require_single_link=True,
            )
            if snapshot.state != "complete" or snapshot.body != expected_body:
                return None
            identities.append((path, snapshot.identity))
        for path, identity in identities:
            metadata = os.lstat(path)
            if metadata.st_nlink != 1 or _file_identity(metadata) != identity:
                return None
        if directory_identity(patch_dir, label="patch directory") != directory_before:
            return None
    except (ContractError, OSError):
        return None
    return copy.deepcopy(bundle)


def _store_verified_patch_bundle(root: Path, bundle: VerifiedPatchBundle) -> None:
    # Bound retained bytes; callers never receive the cached mutable mappings.
    size = len(bundle.upstream_body) + len(bundle.series_body) + sum(
        len(body) for _name, body in bundle.patch_bodies
    )
    if size > MAX_PATCH_BYTES:
        return
    with _BUNDLE_CACHE_LOCK:
        if root not in _BUNDLE_CACHE and len(_BUNDLE_CACHE) >= 4:
            _BUNDLE_CACHE.pop(next(iter(_BUNDLE_CACHE)))
        _BUNDLE_CACHE[root] = copy.deepcopy(bundle)


def _verified_patch_bundle_uncached(root: Path) -> VerifiedPatchBundle:
    upstream = verify_upstream(root)
    upstream_snapshot, upstream_body, upstream_identity = _load_json_with_body(
        root / "upstream.json",
        maximum=MAX_UPSTREAM_MANIFEST_BYTES,
        label="upstream manifest",
    )
    if upstream_snapshot != upstream:
        raise ContractError("upstream manifest changed during verification")
    patch_dir = root / "patches"
    series, series_body, series_identity = _load_json_with_body(
        patch_dir / "series.json",
        maximum=MAX_PATCH_SERIES_BYTES,
        label="patch series manifest",
    )
    schema = series.get("schema")
    if not isinstance(schema, str) or schema not in {LEGACY_PATCH_SCHEMA, PATCH_SCHEMA}:
        raise ContractError("unsupported patch series schema")
    expected_series_fields = {"schema", "chromium_revision", "patches", "postimages"}
    if "dependencies" in series:
        expected_series_fields.add("dependencies")
    if schema == PATCH_SCHEMA:
        expected_series_fields.add("native_event_routes")
    if set(series) != expected_series_fields:
        raise ContractError("patch series fields are invalid")
    declared_routes = (
        _declared_native_event_routes(series) if schema == PATCH_SCHEMA else None
    )
    if series.get("chromium_revision") != upstream["chromium"]["revision"]:
        raise ContractError("patch series revision does not match upstream pin")
    patches = series.get("patches")
    if not isinstance(patches, list) or len(patches) > MAX_PATCHES:
        raise ContractError("patches must be a bounded list")
    names: set[str] = set()
    patch_bodies: list[tuple[str, bytes]] = []
    patch_identities: dict[str, tuple[int, int, int, int, int, int]] = {}
    total_patch_bytes = 0
    for index, item in enumerate(patches):
        if not isinstance(item, dict) or set(item) - {"checkout"} != {
            "file",
            "sha256",
            "purpose",
            "component",
            "classification",
        }:
            raise ContractError(f"patch entry {index} must be an object")
        name = item.get("file")
        digest = item.get("sha256")
        if (
            not isinstance(name, str)
            or len(name) > 255
            or Path(name).name != name
            or not name.endswith(".patch")
            or any(ord(character) < 33 or ord(character) == 127 for character in name)
        ):
            raise ContractError(f"patch entry {index} has an invalid filename")
        if name in names:
            raise ContractError(f"duplicate patch entry: {name}")
        names.add(name)
        for field in ("purpose", "component", "classification"):
            _bounded_text(item.get(field), label=f"patch entry {index} {field}")
        path = patch_dir / name
        snapshot = read_bounded_control_snapshot_result(
            path,
            maximum=MAX_PATCH_BYTES,
            label="patch source",
            require_single_link=True,
        )
        if snapshot.state != "complete" or snapshot.body is None or snapshot.identity is None:
            raise ContractError(f"listed patch is {snapshot.state}: {name}")
        total_patch_bytes += len(snapshot.body)
        if total_patch_bytes > MAX_PATCH_TOTAL_BYTES:
            raise ContractError("patch series exceeds the total byte limit")
        actual = hashlib.sha256(snapshot.body).hexdigest()
        if not isinstance(digest, str) or not SHA256_RE.fullmatch(digest) or digest != actual:
            raise ContractError(f"patch hash mismatch: {name}")
        patch_bodies.append((name, snapshot.body))
        patch_identities[name] = snapshot.identity

    if declared_routes is None and any(
        b'"browser-core.native/1"' in body for _name, body in patch_bodies
    ):
        raise ContractError(
            "native event route declaration is required for Browser Core native patches"
        )
    _verify_native_event_route_sources(patch_bodies, declared_routes)

    patch_dir_before = directory_identity(patch_dir, label="patch directory")
    if patch_dir_before is None:
        raise ContractError("patch directory is missing")
    discovered: set[str] = set()
    entry_count = 0
    try:
        with os.scandir(patch_dir) as entries:
            for entry in entries:
                entry_count += 1
                if entry_count > MAX_PATCHES + 1024:
                    raise ContractError("patch directory contains too many entries")
                if entry.name.endswith(".patch"):
                    if not entry.is_file(follow_symlinks=False):
                        raise ContractError("patch directory contains a non-regular patch")
                    try:
                        metadata = os.lstat(entry.path)
                    except OSError:
                        raise ContractError("patch directory changed during verification") from None
                    if metadata.st_nlink != 1:
                        raise ContractError("patch source must not have additional hard links")
                    if entry.name in patch_identities and _file_identity(metadata) != patch_identities[entry.name]:
                        raise ContractError("patch source changed during verification")
                    discovered.add(entry.name)
    except OSError as exc:
        raise ContractError(
            f"patch directory inventory failed ({type(exc).__name__})"
        ) from None
    if directory_identity(patch_dir, label="patch directory") != patch_dir_before:
        raise ContractError("patch directory changed during verification")
    unlisted = sorted(discovered - names)
    if unlisted:
        raise ContractError(f"patch directory contains {len(unlisted)} unlisted patches")
    missing = sorted(names - discovered)
    if missing:
        raise ContractError(f"patch directory is missing {len(missing)} listed patches")
    postimages = series.get("postimages")
    if (
        not isinstance(postimages, list)
        or len(postimages) > MAX_POSTIMAGES
        or (patches and not postimages)
    ):
        raise ContractError("postimages must be a non-empty list when patches are present")
    paths: set[str] = set()
    for index, item in enumerate(postimages):
        if not isinstance(item, dict) or set(item) != {"path", "sha256"}:
            raise ContractError(f"postimage entry {index} must be an object")
        name = item.get("path")
        digest = item.get("sha256")
        if (
            not isinstance(name, str)
            or len(name.encode("utf-8")) > 4096
            or "\\" in name
            or ":" in name
            or any(ord(character) < 33 or ord(character) == 127 for character in name)
        ):
            raise ContractError(f"postimage entry {index} has an invalid path")
        parsed = PurePosixPath(name)
        if (parsed.is_absolute() or not parsed.parts or name != parsed.as_posix()
                or any(part in ("", ".", "..") or _windows_unsafe_component(part)
                       for part in parsed.parts)):
            raise ContractError(f"postimage entry {index} has an invalid path")
        folded_name = name.casefold()
        if folded_name in paths:
            raise ContractError(f"duplicate postimage path: {name}")
        if not isinstance(digest, str) or not SHA256_RE.fullmatch(digest):
            raise ContractError(f"postimage entry {index} has an invalid hash")
        paths.add(folded_name)

    from .dependency_patches import dependency_scopes
    dependency_scopes(series)

    current_series = read_bounded_control_snapshot_result(
        patch_dir / "series.json",
        maximum=MAX_PATCH_SERIES_BYTES,
        label="patch series manifest",
        require_single_link=True,
    )
    if (
        current_series.state != "complete"
        or current_series.body != series_body
        or current_series.identity != series_identity
    ):
        raise ContractError("patch series manifest changed during verification")
    for name, body in patch_bodies:
        current_patch = read_bounded_control_snapshot_result(
            patch_dir / name,
            maximum=MAX_PATCH_BYTES,
            label="patch source",
            require_single_link=True,
        )
        if (
            current_patch.state != "complete"
            or current_patch.body != body
            or current_patch.identity != patch_identities[name]
        ):
            raise ContractError("patch source changed during verification")
    final_upstream, final_upstream_body, final_upstream_identity = _load_json_with_body(
        root / "upstream.json",
        maximum=MAX_UPSTREAM_MANIFEST_BYTES,
        label="upstream manifest",
    )
    if (
        final_upstream != upstream
        or final_upstream_body != upstream_body
        or final_upstream_identity != upstream_identity
    ):
        raise ContractError("upstream manifest changed during patch verification")

    digest_builder = hashlib.sha256()
    digest_builder.update(b"browser-core.patch-series\0")
    digest_builder.update(series_body)
    for name, body in patch_bodies:
        digest_builder.update(b"\0patch\0")
        digest_builder.update(name.encode("utf-8"))
        digest_builder.update(b"\0")
        digest_builder.update(body)
    report = {
        "revision": series["chromium_revision"],
        "patches": len(patches),
        "postimages": len(postimages),
        "patch_series_sha256": digest_builder.hexdigest(),
    }
    return VerifiedPatchBundle(
        upstream=upstream,
        upstream_body=upstream_body,
        series=series,
        series_body=series_body,
        patch_bodies=tuple(patch_bodies),
        report=report,
    )


def verify_patch_series(root: Path) -> dict[str, Any]:
    return dict(_verified_patch_bundle(root).report)


def verified_patch_names(root: Path) -> frozenset[str]:
    """Names from the freshly verified bundle used by executable attestation."""
    return frozenset(name for name, _ in _verified_patch_bundle(root).patch_bodies)


def verified_native_event_routes(root: Path) -> dict[str, Any]:
    """Return a copy of the native route declaration from verified resources."""
    bundle = _verified_patch_bundle(root)
    declaration = bundle.series.get("native_event_routes")
    # The bundle verifier has already checked the closed declaration and every
    # source emitter. Keep this guard so a future schema revision cannot turn a
    # missing declaration into an apparently empty capability inventory.
    _declared_native_event_routes(bundle.series)
    if not isinstance(declaration, dict):
        raise ContractError("native event route declaration is unavailable")
    return copy.deepcopy(declaration)


def patch_series_digest(root: Path, *, verified: bool = False) -> str:
    # `verified=True` is retained for source compatibility but never bypasses
    # verification: the former bypass could digest a different population than
    # the one whose declared per-patch hashes had just been checked.
    if not isinstance(verified, bool):
        raise ContractError("verified flag must be boolean")
    return _verified_patch_bundle(root).report["patch_series_sha256"]


def _run_apply(
    checkout: Path,
    arguments: list[str],
    patches: list[bytes],
) -> subprocess.CompletedProcess[bytes]:
    body = b"\n".join(patches)
    selected_git = select_git_executable()
    filter_options = _neutral_git_filter_options(checkout, selected_git)
    try:
        return subprocess.run(
            [
                str(selected_git), f"--work-tree={checkout.absolute()}",
                "-c", "core.fsmonitor=false",
                *filter_options,
                "-C", str(checkout), "apply", *arguments, "-",
            ],
            input=body,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=120.0,
            check=False,
            env=isolated_git_environment(),
        )
    except subprocess.TimeoutExpired:
        raise ContractError("Git patch operation timed out") from None
    except (OSError, ValueError) as exc:
        raise ContractError(
            f"Git patch operation could not start ({type(exc).__name__})"
        ) from None


def _apply_succeeded(result: subprocess.CompletedProcess[bytes]) -> bool:
    if isinstance(result.returncode, bool) or not isinstance(result.returncode, int):
        raise ContractError("Git patch operation status is invalid")
    return result.returncode == 0


def _classify_patch_population(
    checkout: Path,
    patches: list[bytes],
) -> tuple[list[bytes], int]:
    """Return one collectively applicable pending subset and applied count."""
    pending: list[bytes] = []
    already_applied = 0
    for patch in patches:
        reverse = _run_apply(checkout, ["--reverse", "--check"], [patch])
        if _apply_succeeded(reverse):
            already_applied += 1
        else:
            pending.append(patch)
    if pending and not _apply_succeeded(_run_apply(checkout, ["--check"], pending)):
        from .ordered_patches import classify
        pending, already_applied = classify(checkout, patches)
        if pending and not _apply_succeeded(_run_apply(checkout, ["--check"], pending)):
            raise ContractError("patch series does not apply cleanly")
    return pending, already_applied


def _reverse_patch_population(checkout: Path, patches: list[bytes]) -> bool:
    if _apply_succeeded(_run_apply(checkout, ["--reverse", "--check"], list(reversed(patches)))):
        return True
    from .ordered_patches import reverse_check
    return reverse_check(checkout, patches)


def _apply_pending_population(checkout: Path, patches: list[bytes]) -> None:
    if patches and not _apply_succeeded(_run_apply(checkout, [], patches)):
        raise ContractError("cannot atomically apply declared patch population")


def _patch_target_guard(checkout: Path, patches: list[bytes]) -> Callable[[], None]:
    """Retain ordinary target paths before any Git apply check or write.

    New directories are allowed, but an existing parent may not be replaced
    and no target component may become a link or reparse point.
    """
    from .ordered_patches import _paths

    checkout = checkout.absolute()
    parents: dict[Path, tuple[Path, tuple[object, ...], tuple[Path, ...]]] = {}
    targets: set[Path] = set()
    for name in _paths(patches):
        target = checkout.joinpath(*PurePosixPath(name).parts)
        targets.add(target)
        parent = target.parent
        if parent in parents:
            continue
        ancestor = parent
        missing: list[Path] = []
        while directory_identity(ancestor, label="patch target") is None:
            if ancestor == checkout:
                raise ContractError("patch target checkout is unavailable")
            missing.append(ancestor)
            ancestor = ancestor.parent
        parents[parent] = (
            ancestor,
            directory_ancestry_binding(ancestor, label="patch target"),
            tuple(reversed(missing)),
        )

    def require() -> None:
        for ancestor, binding, missing in parents.values():
            if directory_ancestry_binding(ancestor, label="patch target") != binding:
                raise ContractError("patch target authority changed")
            for component in missing:
                # A patch may create an absent directory. Every component that
                # appears must still be an ordinary directory in this tree.
                directory_identity(component, label="patch target")
        for target in targets:
            try:
                metadata = os.lstat(target)
            except FileNotFoundError:
                continue
            except OSError:
                raise ContractError("patch target inspection failed") from None
            if (
                not stat.S_ISREG(metadata.st_mode)
                or bool(getattr(metadata, "st_file_attributes", 0) & 0x400)
                or metadata.st_nlink != 1
            ):
                raise ContractError("patch target is not an ordinary file")

    require()
    return require


def _require_git_worktree_shape(checkout: Path) -> None:
    try:
        root = os.lstat(checkout)
        metadata = os.lstat(checkout / ".git")
    except OSError:
        raise ContractError("Chromium checkout is not a Git worktree") from None
    root_attributes = int(getattr(root, "st_file_attributes", 0))
    git_attributes = int(getattr(metadata, "st_file_attributes", 0))
    if not stat.S_ISDIR(root.st_mode) or root_attributes & 0x400:
        raise ContractError("Chromium checkout must be a regular directory")
    if git_attributes & 0x400 or not (
        stat.S_ISDIR(metadata.st_mode) or stat.S_ISREG(metadata.st_mode)
    ):
        raise ContractError("Chromium checkout Git metadata is irregular")
    if stat.S_ISREG(metadata.st_mode) and (
        metadata.st_nlink != 1 or metadata.st_size > 4096
    ):
        raise ContractError("Chromium checkout Git metadata file is invalid")


def verify_depot_tools_checkout(
    checkout: Path,
    expected_revision: str,
    *,
    git_executable: Path | None = None,
) -> dict[str, str]:
    """Check pinned HEAD, index, and bounded direct tracked worktree bytes.

    Named or ambiguous cached filters are rejected without executing them.
    Ignored downloaded tools, other Git configuration effects, and changes
    after this check are outside this non-atomic source-checkout result.
    """
    if not isinstance(checkout, Path):
        raise ContractError("depot_tools checkout must be a Path")
    if not isinstance(expected_revision, str) or not REVISION_RE.fullmatch(
        expected_revision
    ):
        raise ContractError("depot_tools revision is invalid")
    checkout = checkout.absolute()
    ancestry = directory_ancestry_binding(checkout, label="depot_tools checkout")
    _require_git_worktree_shape(checkout)
    selected_git = select_git_executable(
        git_executable, excluded_checkout=checkout,
    )
    selected_git_binding = git_executable_binding(selected_git)
    marker = checkout / ".bleeding_edge"

    def require_authority() -> None:
        if git_executable_binding(selected_git) != selected_git_binding:
            raise ContractError("depot_tools Git executable changed")
        if (
            directory_ancestry_binding(checkout, label="depot_tools checkout")
            != ancestry
        ):
            raise ContractError("depot_tools checkout authority changed")
        try:
            os.lstat(marker)
        except FileNotFoundError:
            pass
        except OSError:
            raise ContractError("depot_tools bleeding-edge marker is unverifiable") from None
        else:
            # This ignored marker changes the bootstrap CIPD manifest. lstat
            # treats even a dangling link as a present control entry.
            raise ContractError("depot_tools bleeding-edge marker is not allowed")

    def query(arguments: list[str], *, maximum: int):
        require_authority()
        result = run_with_bounded_stdout(
            [
                str(selected_git), "--no-optional-locks", f"--work-tree={checkout}",
                "-c", "core.fsmonitor=false", "-c",
                "core.untrackedCache=false", "-C", str(checkout), *arguments,
            ],
            maximum_stdout=maximum,
            timeout_seconds=30.0,
            label="depot_tools Git check",
            environment=isolated_git_environment(),
        )
        require_authority()
        return result

    def capture(arguments: list[str], *, maximum: int) -> bytes:
        result = query(arguments, maximum=maximum)
        if result.returncode != 0:
            raise ContractError("depot_tools Git verification failed")
        return result.stdout

    def tracked_inventory() -> dict[bytes, tuple[bytes, bytes, tuple[str, ...]]]:
        tree = capture(["ls-tree", "-r", "-z", "HEAD"], maximum=MAX_DEPOT_INDEX_BYTES)
        staged = capture(["ls-files", "--stage", "-z"], maximum=MAX_DEPOT_INDEX_BYTES)
        if not tree.endswith(b"\0") or not staged.endswith(b"\0"):
            raise ContractError("depot_tools tracked inventory is invalid")
        head: dict[bytes, tuple[bytes, bytes, tuple[str, ...]]] = {}
        folded_paths: set[str] = set()
        for record in tree[:-1].split(b"\0"):
            if b"\t" not in record:
                raise ContractError("depot_tools tracked inventory is invalid")
            metadata, name = record.split(b"\t", 1)
            fields = metadata.split(b" ")
            if len(fields) != 3 or fields[0] not in (b"100644", b"100755", b"120000"):
                raise ContractError("depot_tools tracked inventory is invalid")
            mode, kind, object_id = fields
            if kind != b"blob" or re.fullmatch(rb"[0-9a-f]{40}", object_id) is None:
                raise ContractError("depot_tools tracked inventory is invalid")
            parts = decode_portable_git_path(name)
            folded = "/".join(parts).casefold()
            if folded in folded_paths or len(head) >= MAX_DEPOT_TRACKED_FILES:
                raise ContractError("depot_tools tracked inventory is invalid")
            folded_paths.add(folded)
            head[name] = (mode, object_id, parts)
        index: dict[bytes, tuple[bytes, bytes]] = {}
        for record in staged[:-1].split(b"\0"):
            if b"\t" not in record:
                raise ContractError("depot_tools tracked inventory is invalid")
            metadata, name = record.split(b"\t", 1)
            fields = metadata.split(b" ")
            if len(fields) != 3 or fields[2] != b"0" or name in index:
                raise ContractError("depot_tools tracked inventory is invalid")
            index[name] = (fields[0], fields[1])
        if {name: (mode, oid) for name, (mode, oid, _parts) in head.items()} != index:
            raise ContractError("depot_tools tracked inventory differs from HEAD")
        return head

    def require_tracked_content(
        inventory: dict[bytes, tuple[bytes, bytes, tuple[str, ...]]],
    ) -> None:
        symlinks = query(["config", "--get", "core.symlinks"], maximum=32)
        autocrlf = query(["config", "--get", "core.autocrlf"], maximum=32)
        if symlinks.returncode not in (0, 1) or autocrlf.returncode not in (0, 1):
            raise ContractError("depot_tools checkout configuration is invalid")
        symlink_payloads = symlinks.returncode == 0 and symlinks.stdout.strip() == b"false"
        allow_crlf = autocrlf.returncode == 0 and autocrlf.stdout.strip() == b"true"
        deadline = time.monotonic() + MAX_DEPOT_TRACKED_SCAN_SECONDS
        total = 0
        normalized_paths: set[bytes] = set()
        for mode, object_id, parts in inventory.values():
            if time.monotonic() >= deadline:
                raise ContractError("depot_tools tracked scan timed out")
            require_authority()
            path = checkout.joinpath(*parts)
            parent = directory_ancestry_binding(path.parent, label="depot_tools tracked directory")
            remaining = MAX_DEPOT_TRACKED_BYTES - total
            snapshot = read_bounded_control_snapshot_result(
                path,
                maximum=min(MAX_DEPOT_TRACKED_FILE_BYTES, remaining),
                label="depot_tools tracked file",
                require_single_link=True,
            )
            if snapshot.state != "complete" or snapshot.body is None:
                raise ContractError("depot_tools tracked content is unavailable")
            if directory_ancestry_binding(path.parent, label="depot_tools tracked directory") != parent:
                raise ContractError("depot_tools tracked directory changed")
            require_authority()
            if os.name != "nt":
                if snapshot.identity is None:
                    raise ContractError("depot_tools tracked content is unavailable")
                actual_mode = snapshot.identity[2]
                if bool(actual_mode & 0o111) != (mode == b"100755"):
                    raise ContractError("depot_tools tracked mode differs from HEAD")
            body = snapshot.body
            total += len(body)
            if total > MAX_DEPOT_TRACKED_BYTES or time.monotonic() >= deadline:
                raise ContractError("depot_tools tracked scan exceeded its limit")
            expected = object_id.decode("ascii")
            if mode == b"120000":
                if os.name != "nt" or not symlink_payloads or git_blob_sha1(body) != expected:
                    raise ContractError("depot_tools tracked content differs from HEAD")
            elif git_blob_sha1(body) != expected:
                normalized = body.replace(b"\r\n", b"\n")
                if (
                    b"\r\n" not in body or b"\0" in body
                    or b"\r" in normalized or git_blob_sha1(normalized) != expected
                ):
                    raise ContractError("depot_tools tracked content differs from HEAD")
                normalized_paths.add("/".join(parts).encode("utf-8"))

        # Git's cached attributes identify filters and text conversion without
        # invoking a configured clean filter. A named filter can make Git's
        # own clean view differ even when literal worktree bytes match HEAD.
        attribute_paths = list(inventory)
        offset = 0
        while offset < len(attribute_paths):
            if time.monotonic() >= deadline:
                raise ContractError("depot_tools tracked scan timed out")
            batch: list[bytes] = []
            argument_bytes = 0
            while offset < len(attribute_paths) and len(batch) < 64:
                name = attribute_paths[offset]
                if batch and argument_bytes + len(name) > 16 * 1024:
                    break
                batch.append(name)
                argument_bytes += len(name)
                offset += 1
            result = capture(
                ["check-attr", "--cached", "-z", "text", "eol", "filter", "--",
                 *(name.decode("utf-8") for name in batch)],
                maximum=MAX_DEPOT_INDEX_BYTES,
            )
            if not result.endswith(b"\0"):
                raise ContractError("depot_tools tracked attributes are invalid")
            fields = result[:-1].split(b"\0")
            if len(fields) != len(batch) * 9:
                raise ContractError("depot_tools tracked attributes are invalid")
            for position, name in enumerate(batch):
                values = []
                for attribute_position, attribute in enumerate((b"text", b"eol", b"filter")):
                    start = (position * 3 + attribute_position) * 3
                    if fields[start:start + 2] != [name, attribute]:
                        raise ContractError("depot_tools tracked attributes are invalid")
                    values.append(fields[start + 2])
                text_attr, eol_attr, filter_attr = values
                # Git renders both `-filter` and the named driver
                # `filter=unset` as `unset` here. The latter can execute a
                # configured clean command, so only no filter is admissible.
                if filter_attr != b"unspecified":
                    raise ContractError("depot_tools tracked filter is not allowed")
                if name in normalized_paths and (
                    text_attr not in (b"unspecified", b"set", b"auto")
                    or eol_attr not in (b"unspecified", b"unset", b"crlf")
                    or (eol_attr != b"crlf" and not allow_crlf)
                ):
                    raise ContractError("depot_tools tracked content differs from HEAD")
            if time.monotonic() >= deadline:
                raise ContractError("depot_tools tracked scan timed out")
        if (
            query(["config", "--get", "core.symlinks"], maximum=32) != symlinks
            or query(["config", "--get", "core.autocrlf"], maximum=32) != autocrlf
        ):
            raise ContractError("depot_tools checkout configuration changed")

    def wrapper_body(name: bytes) -> bytes:
        require_authority()
        relative = name.decode("ascii")
        path = checkout / relative
        parent = directory_ancestry_binding(path.parent, label="depot_tools wrapper directory")

        def regular(metadata: os.stat_result) -> bool:
            return (
                stat.S_ISREG(metadata.st_mode)
                and not bool(getattr(metadata, "st_file_attributes", 0) & 0x400)
                and metadata.st_nlink == 1
            )

        try:
            path_before = os.lstat(path)
            if not regular(path_before):
                raise ContractError("depot_tools required wrapper is irregular")
            with path.open("rb", buffering=0) as handle:
                opened = os.fstat(handle.fileno())
                if not regular(opened):
                    raise ContractError("depot_tools required wrapper is irregular")
                if opened.st_size > MAX_DEPOT_WRAPPER_BYTES:
                    raise ContractError("depot_tools required wrapper exceeds byte limit")
                body = handle.read(MAX_DEPOT_WRAPPER_BYTES + 1)
                after = os.fstat(handle.fileno())
                handle.seek(0)
                repeated = handle.read(MAX_DEPOT_WRAPPER_BYTES + 1)
            path_after = os.lstat(path)
        except ContractError:
            raise
        except OSError:
            raise ContractError("depot_tools required wrapper is unavailable") from None
        if directory_ancestry_binding(path.parent, label="depot_tools wrapper directory") != parent:
            raise ContractError("depot_tools wrapper directory changed")
        require_authority()
        identities = [path_before, opened, after, path_after]
        if any(not regular(item) for item in identities):
            raise ContractError("depot_tools required wrapper is irregular")
        # Windows lstat adds executable permission bits for .bat paths while
        # fstat does not; retain the file type and real read/write bits.
        def stable(item: os.stat_result) -> tuple[int, int, int, int, int, int, int]:
            mode = item.st_mode & ~0o111 if os.name == "nt" else item.st_mode
            return (
                item.st_dev, item.st_ino, mode,
                item.st_size, item.st_mtime_ns, item.st_ctime_ns, item.st_nlink,
            )
        if (
            len(body) > MAX_DEPOT_WRAPPER_BYTES
            or body != repeated
            or len(body) != opened.st_size
            or any(stable(item) != stable(opened) for item in identities)
        ):
            raise ContractError("depot_tools required wrapper changed while reading")
        return body

    def matches_head_blob(body: bytes, blob: bytes) -> bool:
        if body == blob:
            return True
        # Git for Windows may check out LF blobs as CRLF batch files. This
        # permits only that newline conversion, without invoking clean filters.
        return b"\r" not in blob and b"\n" in blob and body == blob.replace(b"\n", b"\r\n")

    head = capture(["rev-parse", "--verify", "HEAD"], maximum=128)
    if head.splitlines() != [expected_revision.encode("ascii")]:
        raise ContractError("depot_tools checkout revision does not match pin")
    inventory = tracked_inventory()
    index = capture(["ls-files", "--cached", "-v", "-z"], maximum=MAX_DEPOT_INDEX_BYTES)
    if not index.endswith(b"\0"):
        raise ContractError("depot_tools tracked-file inventory is invalid")
    wrappers = set()
    flagged_paths = set()
    for record in index[:-1].split(b"\0"):
        if not record.startswith(b"H ") or len(record) <= 2:
            raise ContractError("depot_tools checkout has unverifiable index flags")
        if record[2:] in flagged_paths:
            raise ContractError("depot_tools tracked-file inventory is invalid")
        flagged_paths.add(record[2:])
        if record[2:] in DEPOT_TOOL_WRAPPERS:
            wrappers.add(record[2:])
    if wrappers != DEPOT_TOOL_WRAPPERS:
        raise ContractError("depot_tools required wrapper is not tracked")
    if flagged_paths != set(inventory):
        raise ContractError("depot_tools tracked-file inventory is invalid")
    if capture(
        ["ls-files", "--others", "--exclude-standard", "-z"],
        maximum=MAX_DEPOT_STATUS_BYTES,
    ):
        raise ContractError("depot_tools checkout has changes")
    worktree_config = query(["config", "--get-all", "core.worktree"], maximum=4096)
    if worktree_config.returncode != 1 or worktree_config.stdout:
        raise ContractError("depot_tools core.worktree override is not allowed")
    wrapper_blobs = {}
    for name in sorted(DEPOT_TOOL_WRAPPERS):
        blob = capture(["cat-file", "blob", "HEAD:" + name.decode("ascii")], maximum=MAX_DEPOT_WRAPPER_BYTES)
        wrapper_blobs[name] = blob
        if not matches_head_blob(wrapper_body(name), blob):
            raise ContractError("depot_tools required wrapper differs from HEAD")
    final_head = capture(["rev-parse", "--verify", "HEAD"], maximum=128)
    if final_head != head:
        raise ContractError("depot_tools checkout revision changed")
    if tracked_inventory() != inventory or capture(
        ["ls-files", "--cached", "-v", "-z"], maximum=MAX_DEPOT_INDEX_BYTES,
    ) != index:
        raise ContractError("depot_tools tracked inventory changed")
    if capture(
        ["ls-files", "--others", "--exclude-standard", "-z"],
        maximum=MAX_DEPOT_STATUS_BYTES,
    ):
        raise ContractError("depot_tools checkout has changes")
    final_worktree_config = query(["config", "--get-all", "core.worktree"], maximum=4096)
    if final_worktree_config.returncode != 1 or final_worktree_config.stdout:
        raise ContractError("depot_tools core.worktree override is not allowed")
    for name, blob in wrapper_blobs.items():
        if not matches_head_blob(wrapper_body(name), blob):
            raise ContractError("depot_tools required wrapper differs from HEAD")
    require_tracked_content(inventory)
    if capture(["rev-parse", "--verify", "HEAD"], maximum=128) != head:
        raise ContractError("depot_tools checkout revision changed")
    if tracked_inventory() != inventory or capture(
        ["ls-files", "--cached", "-v", "-z"], maximum=MAX_DEPOT_INDEX_BYTES,
    ) != index:
        raise ContractError("depot_tools tracked inventory changed")
    if capture(
        ["ls-files", "--others", "--exclude-standard", "-z"],
        maximum=MAX_DEPOT_STATUS_BYTES,
    ):
        raise ContractError("depot_tools checkout has changes")
    if query(["config", "--get-all", "core.worktree"], maximum=4096) != worktree_config:
        raise ContractError("depot_tools core.worktree override changed")
    require_authority()
    return {"status": "verified", "revision": expected_revision}


def apply_patch_series(root: Path, checkout: Path, check_only: bool) -> dict[str, int]:
    if not isinstance(root, Path) or not isinstance(checkout, Path):
        raise ContractError("patch roots must be Paths")
    if not isinstance(check_only, bool):
        raise ContractError("patch check_only flag must be boolean")
    _require_git_worktree_shape(checkout)
    checkout_ancestry = directory_ancestry_binding(
        checkout.absolute(), label="patch checkout"
    )

    def require_checkout_authority() -> None:
        if (
            directory_ancestry_binding(checkout.absolute(), label="patch checkout")
            != checkout_ancestry
        ):
            raise ContractError("patch checkout authority changed")

    bundle = _verified_patch_bundle(root)
    require_checkout_authority()
    if bundle.series.get("dependencies"):
        from .dependency_patches import apply_dependency_series
        result = apply_dependency_series(checkout, bundle, check_only=check_only)
        require_checkout_authority()
        return result
    patch_bodies = [body for _name, body in bundle.patch_bodies]
    if not patch_bodies:
        return {"applied": 0, "already_applied": 0, "checked": 0}
    require_targets = _patch_target_guard(checkout, patch_bodies)
    if check_only:
        _pending, already_applied = _classify_patch_population(
            checkout,
            patch_bodies,
        )
        require_checkout_authority()
        require_targets()
        return {
            "applied": 0,
            "already_applied": already_applied,
            "checked": len(patch_bodies),
        }

    pending, already_applied = _classify_patch_population(checkout, patch_bodies)
    require_checkout_authority()
    require_targets()
    _apply_pending_population(checkout, pending)
    require_checkout_authority()
    require_targets()
    return {
        "applied": len(pending),
        "already_applied": already_applied,
        "checked": len(patch_bodies),
    }


def _neutral_git_filter_options(checkout: Path, selected_git: Path) -> list[str]:
    """Disable configured external filters for a bounded Git patch/diff query."""
    result = run_with_bounded_stdout(
        [
            str(selected_git), "--no-optional-locks", f"--work-tree={checkout.absolute()}",
            "-c", "core.fsmonitor=false", "-C", str(checkout),
            "config", "--name-only", "--null", "--list",
        ],
        maximum_stdout=MAX_GIT_FILTER_CONFIG_BYTES,
        timeout_seconds=10.0,
        label="Git filter configuration",
        environment=isolated_git_environment(),
    )
    body = result.stdout
    if result.returncode != 0 or (body and not body.endswith(b"\0")):
        raise ContractError("Git filter configuration is invalid")
    options: list[str] = []
    seen: set[str] = set()
    total = 0
    for raw in body[:-1].split(b"\0") if body else ():
        try:
            key = raw.decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            raise ContractError("Git filter configuration is invalid") from None
        if not key:
            raise ContractError("Git filter configuration is invalid")
        lower = key.lower()
        if not lower.startswith("filter."):
            continue
        suffix = next(
            (item for item in (".clean", ".process", ".smudge") if lower.endswith(item)),
            None,
        )
        if suffix is None:
            continue
        if (
            not key[len("filter."):-len(suffix)]
            or len(raw) > 256
            or "=" in key
            or any(ord(character) < 0x20 or ord(character) == 0x7f for character in key)
        ):
            raise ContractError("Git filter configuration is invalid")
        if key in seen:
            continue
        seen.add(key)
        total += len(raw) + 3
        if len(seen) > MAX_GIT_FILTER_OVERRIDES or total > MAX_GIT_FILTER_OVERRIDE_BYTES:
            raise ContractError("Git filter configuration exceeds its limit")
        options.extend(("-c", f"{key}="))
    return options


def _run_git_no_output(checkout: Path, arguments: list[str]) -> int:
    try:
        # Git does not accept --work-tree while creating a repository. The
        # scratch initialization is still isolated from inherited GIT_* state.
        work_tree = [] if arguments[:1] == ["init"] else [f"--work-tree={checkout.absolute()}"]
        selected_git = select_git_executable()
        is_diff = arguments[:1] == ["diff"]
        filter_options = _neutral_git_filter_options(checkout, selected_git) if is_diff else []
        selected_arguments = (
            ["diff", "--no-ext-diff", "--no-textconv", *arguments[1:]]
            if is_diff else arguments
        )
        result = subprocess.run(
            [
                str(selected_git), *work_tree,
                "-c", "core.fsmonitor=false",
                *filter_options,
                "-C", str(checkout), *selected_arguments,
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=120.0,
            check=False,
            env=isolated_git_environment(),
        )
    except subprocess.TimeoutExpired:
        raise ContractError("Git operation timed out") from None
    except (OSError, ValueError) as exc:
        raise ContractError(
            f"Git operation could not start ({type(exc).__name__})"
        ) from None
    if isinstance(result.returncode, bool) or not isinstance(result.returncode, int):
        raise ContractError("Git operation status is invalid")
    return result.returncode


def _run_git_capture(
    checkout: Path,
    arguments: list[str],
    *,
    maximum: int,
) -> tuple[int, bytes]:
    selected_git = select_git_executable()
    is_diff = arguments[:1] == ["diff"]
    filter_options = _neutral_git_filter_options(checkout, selected_git) if is_diff else []
    selected_arguments = (
        ["diff", "--no-ext-diff", "--no-textconv", *arguments[1:]]
        if is_diff else arguments
    )
    result = run_with_bounded_stdout(
        [
            str(selected_git), f"--work-tree={checkout.absolute()}",
            "-c", "core.fsmonitor=false",
            *filter_options,
            "-C", str(checkout), *selected_arguments,
        ],
        maximum_stdout=maximum,
        timeout_seconds=120.0,
        label="Git operation",
        environment=isolated_git_environment(),
    )
    return result.returncode, result.stdout


def _patched_index_binding(checkout: Path) -> bytes:
    returncode, body = _run_git_capture(
        checkout,
        ["--no-optional-locks", "ls-files", "--cached", "-v", "-z"],
        maximum=MAX_PATCHED_INDEX_BYTES,
    )
    if returncode or not body or body[-1:] != b"\0":
        raise ContractError("patched checkout tracked index is invalid")
    start = 0
    while start < len(body):
        end = body.find(b"\0", start)
        if end < 0 or end - start < 3:
            raise ContractError("patched checkout tracked index is invalid")
        if not body.startswith(b"H ", start, end):
            raise ContractError("patched checkout has unverifiable index flags")
        start = end + 1
    return hashlib.sha256(body).digest()


def _file_identity(metadata: os.stat_result) -> tuple[int, int, int, int, int, int]:
    # Windows path stat adds executable bits for batch/exe basenames, while
    # fstat on the same open file omits them. Preserve type and write bits.
    mode = metadata.st_mode & ~0o111 if os.name == "nt" else metadata.st_mode
    return (
        metadata.st_dev,
        metadata.st_ino,
        mode,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _stable_file_sha256(path: Path, *, label: str, maximum: int) -> str:
    try:
        path_before = os.lstat(path)
        if not stat.S_ISREG(path_before.st_mode) or bool(
            getattr(path_before, "st_file_attributes", 0) & 0x400
        ):
            raise ContractError(f"{label} is not a regular file")
        if path_before.st_nlink != 1:
            raise ContractError(f"{label} must not have additional hard links")
        if path_before.st_size > maximum:
            raise ContractError(f"{label} exceeds {maximum} bytes")
        digest = hashlib.sha256()
        count = 0
        with path.open("rb", buffering=0) as source:
            before = os.fstat(source.fileno())
            change_before = windows_change_time(source) if os.name == "nt" else None
            if not stat.S_ISREG(before.st_mode) or bool(
                getattr(before, "st_file_attributes", 0) & 0x400
            ):
                raise ContractError(f"{label} is not a regular file")
            if before.st_nlink != 1:
                raise ContractError(f"{label} must not have additional hard links")
            if before.st_size > maximum:
                raise ContractError(f"{label} exceeds {maximum} bytes")
            while True:
                chunk = source.read(min(1024 * 1024, maximum + 1 - count))
                if not chunk:
                    break
                count += len(chunk)
                if count > maximum:
                    raise ContractError(f"{label} exceeds {maximum} bytes")
                digest.update(chunk)
            after = os.fstat(source.fileno())
            change_after = windows_change_time(source) if os.name == "nt" else None
        path_after = os.lstat(path)
    except FileNotFoundError:
        raise ContractError(f"{label} is missing") from None
    except ContractError:
        raise
    except OSError as exc:
        raise ContractError(f"{label} read failed ({type(exc).__name__})") from None
    if (
        _file_identity(path_before) != _file_identity(before)
        or _file_identity(before) != _file_identity(after)
        or _file_identity(after) != _file_identity(path_after)
        or count != after.st_size
        or after.st_nlink != 1
        or path_after.st_nlink != 1
        or change_before != change_after
    ):
        raise ContractError(f"{label} changed while hashing")
    return digest.hexdigest()


def verify_patched_checkout(root: Path, checkout: Path) -> dict[str, Any]:
    """Verify pinned revision, declared postimages, and Git-observed changed paths.

    Git may omit an undeclared tracked edit whose size and cached stat fields
    are restored. The result therefore does not claim whole-tree content parity.
    """

    if not isinstance(root, Path) or not isinstance(checkout, Path):
        raise ContractError("patched checkout roots must be Paths")
    selected_checkout = checkout.absolute()
    selected_ancestry = directory_ancestry_binding(
        selected_checkout, label="patched checkout"
    )
    _require_git_worktree_shape(checkout)
    checkout = checkout.resolve()
    _require_git_worktree_shape(checkout)
    checkout_ancestry = directory_ancestry_binding(
        checkout.absolute(), label="patched checkout"
    )
    bundle = _verified_patch_bundle(root)
    if (
        directory_ancestry_binding(selected_checkout, label="patched checkout")
        != selected_ancestry
        or directory_ancestry_binding(checkout.absolute(), label="patched checkout")
        != checkout_ancestry
    ):
        raise ContractError("patched checkout authority changed")
    verified = bundle.report
    series = bundle.series

    from .dependency_patches import dependency_scopes, grouped_bodies, verify_dependency_deltas

    scopes = dependency_scopes(series)
    authority = {selected_checkout: selected_ancestry, checkout: checkout_ancestry}
    authority.update({
        checkout / scope: directory_ancestry_binding(
            (checkout / scope).absolute(), label="patched checkout"
        )
        for scope in scopes
    })
    index_binding = _patched_index_binding(checkout)

    revision_returncode, revision_body = _run_git_capture(
        checkout,
        ["rev-parse", "HEAD"],
        maximum=128,
    )
    try:
        revision = revision_body.decode("ascii", errors="strict").strip()
    except UnicodeDecodeError:
        revision = ""
    if revision_returncode or revision != series["chromium_revision"]:
        raise ContractError("patched checkout does not match the pinned Chromium revision")

    dependencies_before = verify_dependency_deltas(checkout, bundle) if scopes else {}
    patch_bodies = grouped_bodies(bundle)['']
    if patch_bodies:
        if not _reverse_patch_population(checkout, patch_bodies):
            raise ContractError("declared patch series is not fully applied")

    if _run_git_no_output(checkout, ["diff", "--check", "HEAD", "--"]):
        raise ContractError("patched checkout has an invalid tracked delta")
    inventory_command = ["diff", "--name-only", "-z",
                         *(["--ignore-submodules=none"] if scopes else []), "HEAD", "--"]
    changed_returncode, changed_body = _run_git_capture(
        checkout,
        inventory_command,
        maximum=MAX_CHANGED_PATH_BYTES,
    )
    if changed_returncode:
        raise ContractError("cannot enumerate patched checkout changes")
    try:
        changed_parts = [
            part.decode("utf-8", errors="strict")
            for part in changed_body.split(b"\0")
            if part
        ]
    except UnicodeDecodeError:
        raise ContractError("patched checkout change path encoding is invalid") from None
    if len(changed_parts) > MAX_CHANGED_PATHS or len(changed_parts) != len(
        set(changed_parts)
    ):
        raise ContractError("patched checkout change inventory is invalid")
    changed = set(changed_parts)
    expected = {next((scope for scope in scopes if item['path'].startswith(scope+'/')), item['path'])
                for item in series["postimages"]}
    if changed != expected:
        missing = sorted(expected - changed)
        extra = sorted(changed - expected)
        receipt = hashlib.sha256(
            json.dumps(
                {"missing": missing, "extra": extra},
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
            ).encode("ascii")
        ).hexdigest()[:16]
        raise ContractError(
            "patched checkout delta mismatch; "
            f"missing_count={len(missing)}; extra_count={len(extra)}; "
            f"diagnostic_sha256_16={receipt}"
        )

    postimage_parents = {
        checkout.joinpath(*PurePosixPath(item["path"]).parts).parent
        for item in series["postimages"]
    }
    postimage_parent_authority = {
        parent: directory_ancestry_binding(
            parent.absolute(), label="patched source postimage parent"
        )
        for parent in postimage_parents
    }

    def require_postimage_parent(parent: Path) -> None:
        if directory_ancestry_binding(
            parent.absolute(), label="patched source postimage parent"
        ) != postimage_parent_authority[parent]:
            raise ContractError("patched checkout authority changed")

    postimage_sizes: dict[str, int] = {}
    remaining_postimage_bytes = MAX_TOTAL_POSTIMAGE_BYTES
    for item in series["postimages"]:
        target = checkout.joinpath(*PurePosixPath(item["path"]).parts)
        require_postimage_parent(target.parent)
        try:
            size = os.lstat(target).st_size
        except FileNotFoundError:
            raise ContractError("patched source postimage is missing") from None
        except OSError:
            raise ContractError("patched source postimage inspection failed") from None
        if size > remaining_postimage_bytes:
            raise ContractError("aggregate postimage bytes exceed verification limit")
        remaining_postimage_bytes -= size
        postimage_sizes[item["path"]] = size

    postimages: list[dict[str, str]] = []
    for item in series["postimages"]:
        target = checkout.joinpath(*PurePosixPath(item["path"]).parts)
        require_postimage_parent(target.parent)
        actual = _stable_file_sha256(
            target,
            label="patched source postimage",
            maximum=min(MAX_POSTIMAGE_BYTES, postimage_sizes[item["path"]]),
        )
        require_postimage_parent(target.parent)
        if actual != item["sha256"]:
            raise ContractError(f"patched source postimage hash mismatch: {item['path']}")
        postimages.append({"path": item["path"], "sha256": actual})

    final_changed_returncode, final_changed_body = _run_git_capture(
        checkout,
        inventory_command,
        maximum=MAX_CHANGED_PATH_BYTES,
    )
    if final_changed_returncode or final_changed_body != changed_body:
        raise ContractError("patched checkout delta changed during verification")
    final_revision_returncode, final_revision_body = _run_git_capture(
        checkout,
        ["rev-parse", "HEAD"],
        maximum=128,
    )
    if final_revision_returncode or final_revision_body != revision_body:
        raise ContractError("patched checkout revision changed during verification")
    if scopes and verify_dependency_deltas(checkout, bundle) != dependencies_before:
        raise ContractError('patch dependency changed during verification')
    if _patched_index_binding(checkout) != index_binding:
        raise ContractError("patched checkout tracked index changed during verification")
    for target, binding in authority.items():
        if directory_ancestry_binding(target.absolute(), label="patched checkout") != binding:
            raise ContractError("patched checkout authority changed")
    for parent in postimage_parents:
        require_postimage_parent(parent)
    # Bind the exact postimages after Git's final inventory and index queries.
    # This is the existing second bounded pass, placed at the final read seam.
    for item in series["postimages"]:
        target = checkout.joinpath(*PurePosixPath(item["path"]).parts)
        require_postimage_parent(target.parent)
        if _stable_file_sha256(
            target,
            label="patched source postimage",
            maximum=min(MAX_POSTIMAGE_BYTES, postimage_sizes[item["path"]]),
        ) != item["sha256"]:
            raise ContractError("patched source postimage changed during verification")
        require_postimage_parent(target.parent)

    state_digest = hashlib.sha256(
        json.dumps(postimages, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    ).hexdigest()
    return {
        **verified,
        "status": "declared-postimages-verified",
        "changed_path_inventory": "git-observed",
        "undeclared_tracked_content": "unverified",
        "chromium_revision": revision,
        "patched_sources_sha256": state_digest,
    }
