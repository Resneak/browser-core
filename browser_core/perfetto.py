from __future__ import annotations

import csv
import hashlib
import io
import json
import os
import re
import stat
import subprocess
import threading
import uuid
from collections import Counter
from pathlib import Path
from typing import Any, Iterator, TextIO

from .bounded_process import run_with_bounded_stdout
from .contracts import (
    BODY_CONSUMER_MODES,
    ENCODING_BINDING_INTERFACES,
    EXACT_NATIVE_EVENT_COMPONENTS,
    EXACT_NATIVE_EVENT_ROUTES,
    EXACT_NATIVE_TRACE_CATEGORIES,
    FETCH_TARGET_SCOPES,
    GENERATED_BINDING_NAME_RE,
    MAX_CANVAS_DIMENSION,
    MAX_TRACE_BUFFER_BYTES,
    MAX_TRACE_EVENT_DURATION_NS,
    MAX_WASM_MODULE_BYTES,
    ContractError,
    REVISION_RE,
    RUN_ID_RE,
    WEBCRYPTO_DIGEST_ALGORITHMS,
    parse_canonical_decimal,
    validate_url_class,
    validate_trace_event,
)
from .owned_paths import (
    DirectoryIdentity,
    directory_ancestry_binding,
    directory_identity,
    prepare_owned_directory_parent,
)
from .inspection_context import LIMITED_CONTEXT_SCHEMA, decode_context
from .binding_context import JS_STACK_COLUMNS, decode_js_stack
from .windows_change_time import windows_change_time


NATIVE_EVENT_SCHEMA = "browser-core.native/1"
TRACE_EXPORT_SCHEMA = "browser-core.trace-export/1"
NULL_VALUE = "[NULL]"


class DynamicCallerAmbiguity(ContractError):
    """First rejected group, with numeric selectors only; no partial success."""
    def __init__(self, *, pid, thread_id, caller_script_id, seq, timestamp, matches):
        candidates = sorted(event['seq'] for event in matches.values())
        self.diagnostic = {
            'schema': 'browser-core.attribution-conflict/1',
            'reason': 'multiple-contexts-for-caller-script',
            'locator_scope': 'provisional-export-sequences-not-a-validated-query',
            'pid': pid, 'thread_id': thread_id, 'caller_script_id': caller_script_id,
            'materialization_seq': seq, 'ts_monotonic_ns': timestamp,
            'candidate_parent_count': len(candidates), 'candidate_parent_seqs': candidates[:8],
            'candidates_truncated': len(candidates) > 8, 'first_conflict_only': True,
            'attribution_resolved': False,
        }
        super().__init__('native dynamic code caller script is ambiguous')


GENERATED_BINDING_CATEGORIES = frozenset(
    {"blink.bindings", "blink.bindings.encoding"}
)
MAX_COUNT_QUERY_BYTES = 4096
COUNT_QUERY_TIMEOUT_SECONDS = 30.0
EXPORT_QUERY_TIMEOUT_SECONDS = 300.0
TRACE_PROCESSOR_REAP_TIMEOUT_SECONDS = 5.0
MAX_EXPORT_EVENTS = 10_000_000
MAX_PERFETTO_ARTIFACT_BYTES = 1024 * 1024 * 1024 * 1024
MAX_TRACE_PROCESSOR_BYTES = 4 * 1024 * 1024 * 1024
MAX_TRACE_EXPORT_REPORT_BYTES = 64 * 1024 * 1024
MAX_NORMALIZED_TRACE_BYTES = MAX_PERFETTO_ARTIFACT_BYTES
MAX_EXPORT_CSV_LINE_CHARS = 1024 * 1024
MAX_EXPORT_CSV_CHARS = MAX_PERFETTO_ARTIFACT_BYTES
MAX_EXPORT_CSV_LINES = 20_000_000
EXPORT_COLUMNS = (
    "ts_monotonic_ns",
    "duration_ns",
    "trace_category",
    "native_name",
    "pid",
    "process_name",
    "tid",
    "thread_name",
    "track_id",
    "native_schema",
    "event_category",
    "event_name",
    "component",
    "api",
    "context_id",
    "context_kind",
    "script_id",
    "realm_v8_context_id",
    "realm_world_id",
    "inspector_context_id",
    "native_id",
    "native_parent_id",
    "message_dispatch_id",
    "callback_interface",
    "callback_operation",
    "callback_kind",
    "dynamic_kind",
    "cache_status",
    "generated_script_id",
    "caller_script_id",
    "caller_inspector_context_id",
    "source_length",
    "compiler_input_hash_status",
    "compiler_input_utf16le_sha256",
    "algorithm",
    "data_bytes",
    "success",
    "async",
    "cached",
    "code_bytes",
    "request_id",
    "method",
    "url_class",
    "target_scope",
    "body_bytes",
    "reader_mode",
    "consumer_mode",
    "dispatch_kind",
    "result_kind",
    "chunk_value_type",
    "chunk_bytes",
    "width",
    "height",
    "origin_clean",
    "binding_value_count",
    "binding_value_slice_id",
    "binding_value_context_id",
    "binding_value_context_kind",
    "binding_value_context_metadata",
    "binding_value_realm_id",
    *JS_STACK_COLUMNS,
)
_COMPILER_INPUT_HASH_COLUMNS = (
    "compiler_input_hash_status", "compiler_input_utf16le_sha256",
)
_REALM_COLUMNS = ("realm_v8_context_id", "realm_world_id")
PRIOR_EXPORT_COLUMNS = tuple(
    column for column in EXPORT_COLUMNS if column not in _REALM_COLUMNS
)
LEGACY_EXPORT_COLUMNS = tuple(
    column for column in PRIOR_EXPORT_COLUMNS if column not in _COMPILER_INPUT_HASH_COLUMNS
)


def _reap_trace_processor(
    process: subprocess.Popen[str],
    *,
    kill: bool,
) -> int:
    """Bound trace-processor exit and cleanup without exposing child diagnostics."""
    if kill:
        try:
            process.kill()
        except ProcessLookupError:
            pass
        except OSError as exc:
            raise ContractError(
                f"trace processor cleanup failed ({type(exc).__name__})"
            ) from None
    try:
        returncode = process.wait(timeout=TRACE_PROCESSOR_REAP_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired:
        phase = "cleanup" if kill else "exit"
        raise ContractError(f"trace processor {phase} timed out") from None
    except OSError as exc:
        phase = "cleanup" if kill else "exit"
        raise ContractError(
            f"trace processor {phase} failed ({type(exc).__name__})"
        ) from None
    if isinstance(returncode, bool) or not isinstance(returncode, int):
        raise ContractError("trace processor query status is invalid")
    return returncode


def _file_object_identity(metadata: os.stat_result) -> tuple[int, int, int, int]:
    attributes = int(getattr(metadata, "st_file_attributes", 0))
    if not stat.S_ISREG(metadata.st_mode) or attributes & 0x400:
        raise ContractError("owned temporary is not a regular file")
    return (
        metadata.st_dev,
        metadata.st_ino,
        stat.S_IFMT(metadata.st_mode),
        attributes,
    )


def _owned_file_object_identity(metadata: os.stat_result) -> tuple[int, int, int, int]:
    identity = _file_object_identity(metadata)
    if metadata.st_nlink != 1:
        raise ContractError("owned temporary is not a single-link regular file")
    return identity


def _remove_owned_temporary(
    path: Path,
    *,
    expected_identity: tuple[int, int, int, int],
    expected_parent_ancestry: tuple[DirectoryIdentity, ...] | None = None,
    label: str,
) -> bool:
    """Remove only the exact temporary object; preserve a competing replacement."""
    parent = path.parent.absolute()
    parent_ancestry = expected_parent_ancestry
    if parent_ancestry is None:
        if directory_identity(parent, label=label) is None:
            return False
        parent_ancestry = directory_ancestry_binding(parent, label=label)

    def parent_held() -> bool:
        return directory_ancestry_binding(parent, label=label) == parent_ancestry

    if not parent_held():
        raise ContractError(f"{label} parent changed during cleanup")
    quarantine = path.with_name(f".{path.name}.cleanup-{uuid.uuid4().hex}")
    try:
        current = os.lstat(path)
    except FileNotFoundError:
        return True
    except OSError:
        raise ContractError(f"{label} cleanup inspection failed") from None
    try:
        current_identity = _file_object_identity(current)
    except ContractError:
        return False
    if current_identity != expected_identity:
        return False
    try:
        if not parent_held():
            raise ContractError(f"{label} parent changed during cleanup")
        os.rename(path, quarantine)
    except FileNotFoundError:
        return True
    except OSError:
        raise ContractError(f"{label} cleanup quarantine failed") from None
    if not parent_held():
        raise ContractError(f"{label} parent changed during cleanup")
    try:
        moved = os.lstat(quarantine)
        moved_identity = _file_object_identity(moved)
    except (ContractError, OSError):
        try:
            if (
                parent_held()
                and not path.exists()
            ):
                os.rename(quarantine, path)
        except (ContractError, OSError):
            pass
        raise ContractError(f"{label} changed during cleanup") from None
    if moved_identity != expected_identity:
        try:
            if (
                parent_held()
                and not path.exists()
            ):
                os.rename(quarantine, path)
        except (ContractError, OSError):
            pass
        raise ContractError(f"{label} changed during cleanup")
    if not parent_held():
        raise ContractError(f"{label} parent changed during cleanup")
    try:
        quarantine.unlink()
    except OSError:
        raise ContractError(f"{label} cleanup failed") from None
    if not parent_held():
        raise ContractError(f"{label} parent changed during cleanup")
    return True


EXPORT_SQL = r"""
WITH binding_values AS (
  SELECT v.parent_id, COUNT(*) AS value_count, MIN(v.id) AS value_slice_id,
    MIN(EXTRACT_ARG(v.arg_set_id, 'debug.context_id')) AS context_id,
    MIN(EXTRACT_ARG(v.arg_set_id, 'debug.context_kind')) AS context_kind,
    MIN(hex(EXTRACT_ARG(v.arg_set_id, 'debug.context_metadata_json'))) AS context_metadata,
    MIN(EXTRACT_ARG(v.arg_set_id, 'debug.realm_id')) AS realm_id
  FROM slice v JOIN slice b ON b.id = v.parent_id
  WHERE v.category = 'browser_core.debug'
    AND v.name = 'BrowserCoreInspection.BindingValue'
    AND b.category IN ('blink.bindings', 'blink.bindings.encoding')
    AND EXTRACT_ARG(v.arg_set_id, 'debug.api') = b.name
    AND v.track_id = b.track_id AND v.ts >= b.ts
    AND (b.dur = -1 OR v.ts <= b.ts + b.dur)
  GROUP BY v.parent_id
)
SELECT
  s.ts AS ts_monotonic_ns,
  s.dur AS duration_ns,
  s.category AS trace_category,
  s.name AS native_name,
  p.pid AS pid,
  p.name AS process_name,
  t.tid AS tid,
  t.name AS thread_name,
  s.track_id AS track_id,
  EXTRACT_ARG(s.arg_set_id, 'debug.schema') AS native_schema,
  EXTRACT_ARG(s.arg_set_id, 'debug.event_category') AS event_category,
  EXTRACT_ARG(s.arg_set_id, 'debug.event_name') AS event_name,
  EXTRACT_ARG(s.arg_set_id, 'debug.component') AS component,
  EXTRACT_ARG(s.arg_set_id, 'debug.api') AS api,
  EXTRACT_ARG(s.arg_set_id, 'debug.context_id') AS context_id,
  EXTRACT_ARG(s.arg_set_id, 'debug.context_kind') AS context_kind,
  EXTRACT_ARG(s.arg_set_id, 'debug.script_id') AS script_id,
  EXTRACT_ARG(s.arg_set_id, 'debug.v8_context_id') AS realm_v8_context_id,
  EXTRACT_ARG(s.arg_set_id, 'debug.realm_id') AS realm_world_id,
  EXTRACT_ARG(s.arg_set_id, 'debug.inspector_context_id') AS inspector_context_id,
  EXTRACT_ARG(s.arg_set_id, 'debug.native_id') AS native_id,
  EXTRACT_ARG(s.arg_set_id, 'debug.native_parent_id') AS native_parent_id,
  EXTRACT_ARG(s.arg_set_id, 'debug.message_dispatch_id') AS message_dispatch_id,
  EXTRACT_ARG(s.arg_set_id, 'debug.callback_interface') AS callback_interface,
  EXTRACT_ARG(s.arg_set_id, 'debug.callback_operation') AS callback_operation,
  EXTRACT_ARG(s.arg_set_id, 'debug.callback_kind') AS callback_kind,
  EXTRACT_ARG(s.arg_set_id, 'debug.dynamic_kind') AS dynamic_kind,
  EXTRACT_ARG(s.arg_set_id, 'debug.cache_status') AS cache_status,
  EXTRACT_ARG(s.arg_set_id, 'debug.generated_script_id') AS generated_script_id,
  EXTRACT_ARG(s.arg_set_id, 'debug.caller_script_id') AS caller_script_id,
  EXTRACT_ARG(s.arg_set_id, 'debug.caller_inspector_context_id') AS caller_inspector_context_id,
  EXTRACT_ARG(s.arg_set_id, 'debug.source_length') AS source_length,
  EXTRACT_ARG(s.arg_set_id, 'debug.compiler_input_hash_status') AS compiler_input_hash_status,
  EXTRACT_ARG(s.arg_set_id, 'debug.compiler_input_utf16le_sha256') AS compiler_input_utf16le_sha256,
  EXTRACT_ARG(s.arg_set_id, 'debug.algorithm') AS algorithm,
  EXTRACT_ARG(s.arg_set_id, 'debug.data_bytes') AS data_bytes,
  EXTRACT_ARG(s.arg_set_id, 'debug.success') AS success,
  EXTRACT_ARG(s.arg_set_id, 'debug.async') AS async,
  EXTRACT_ARG(s.arg_set_id, 'debug.cached') AS cached,
  EXTRACT_ARG(s.arg_set_id, 'debug.code_bytes') AS code_bytes,
  EXTRACT_ARG(s.arg_set_id, 'debug.request_id') AS request_id,
  EXTRACT_ARG(s.arg_set_id, 'debug.method') AS method,
  EXTRACT_ARG(s.arg_set_id, 'debug.url_class') AS url_class,
  EXTRACT_ARG(s.arg_set_id, 'debug.target_scope') AS target_scope,
  EXTRACT_ARG(s.arg_set_id, 'debug.body_bytes') AS body_bytes,
  EXTRACT_ARG(s.arg_set_id, 'debug.reader_mode') AS reader_mode,
  EXTRACT_ARG(s.arg_set_id, 'debug.consumer_mode') AS consumer_mode,
  EXTRACT_ARG(s.arg_set_id, 'debug.dispatch_kind') AS dispatch_kind,
  EXTRACT_ARG(s.arg_set_id, 'debug.result_kind') AS result_kind,
  EXTRACT_ARG(s.arg_set_id, 'debug.chunk_value_type') AS chunk_value_type,
  EXTRACT_ARG(s.arg_set_id, 'debug.chunk_bytes') AS chunk_bytes,
  EXTRACT_ARG(s.arg_set_id, 'debug.width') AS width,
  EXTRACT_ARG(s.arg_set_id, 'debug.height') AS height,
  EXTRACT_ARG(s.arg_set_id, 'debug.origin_clean') AS origin_clean,
  bv.value_count AS binding_value_count,
  bv.value_slice_id AS binding_value_slice_id,
  bv.context_id AS binding_value_context_id,
  bv.context_kind AS binding_value_context_kind,
  bv.context_metadata AS binding_value_context_metadata,
  bv.realm_id AS binding_value_realm_id,
  EXTRACT_ARG(s.arg_set_id, 'debug.stack_context_schema') AS stack_context_schema,
  EXTRACT_ARG(s.arg_set_id, 'debug.stack_context_status') AS stack_context_status,
  EXTRACT_ARG(s.arg_set_id, 'debug.stack_v8_context_id') AS stack_v8_context_id,
  EXTRACT_ARG(s.arg_set_id, 'debug.stack_realm_id') AS stack_realm_id,
  EXTRACT_ARG(s.arg_set_id, 'debug.stack_root_script_id') AS stack_root_script_id
FROM slice s
LEFT JOIN binding_values bv ON bv.parent_id = s.id
LEFT JOIN thread_track tt ON s.track_id = tt.id
LEFT JOIN thread t ON tt.utid = t.utid
LEFT JOIN process p ON t.upid = p.upid
WHERE s.category IN (
  'browser_core.debug',
  'browser_core.stream',
  'blink.bindings',
  'blink.bindings.encoding'
)
AND NOT (s.category='browser_core.debug'
  AND s.name='BrowserCoreInspection.BindingValue')
ORDER BY s.ts, s.id;
""".strip()

EXPORT_COUNT_SQL = r"""
SELECT COUNT(*) AS events
FROM slice s
WHERE s.category IN (
  'browser_core.debug',
  'browser_core.stream',
  'blink.bindings',
  'blink.bindings.encoding'
)
AND NOT (s.category='browser_core.debug'
  AND s.name='BrowserCoreInspection.BindingValue');
""".strip()


def _process_type(process_name: str, thread_name: str) -> str:
    lowered = f"{process_name} {thread_name}".casefold()
    if "renderer" in lowered or "worker" in lowered or "worklet" in lowered:
        return "renderer"
    if "gpu" in lowered:
        return "gpu"
    if "utility" in lowered:
        return "utility"
    return "browser"


def _bindings_execution(
    pid: int,
    thread_id: int,
    thread_name: str,
    *,
    script_id: str | None = None,
) -> dict[str, Any]:
    context_id = f"bindings:{pid}:{thread_id}"
    execution: dict[str, Any] = {"context_id": context_id}
    lowered = thread_name.casefold()
    if "worker" in lowered or "worklet" in lowered:
        execution["worker_id"] = context_id
    elif "renderer" in lowered:
        execution["frame_id"] = context_id
    if script_id is not None:
        execution["script_id"] = script_id
    return execution


def _integer(value: Any, label: str, minimum: int = 0) -> int:
    if type(value) is not str or re.fullmatch(r"0|[1-9][0-9]*|-[1-9][0-9]*", value) is None:
        raise ContractError(f"Perfetto {label} is not an integer")
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise ContractError(f"Perfetto {label} is not an integer") from exc
    if parsed < minimum:
        raise ContractError(f"Perfetto {label} must be >= {minimum}")
    return parsed


def _boolean(value: str, label: str) -> bool:
    normalized = value.casefold()
    if normalized in {"1", "true"}:
        return True
    if normalized in {"0", "false"}:
        return False
    raise ContractError(f"Perfetto {label} is not boolean")


def _optional(value: str | None) -> str | None:
    if value is None or value in {"", NULL_VALUE}:
        return None
    return value


def _url_class(value: str | None) -> str:
    normalized = _optional(value)
    if normalized is None:
        raise ContractError("Perfetto URL class is not scheme-safe metadata")
    try:
        return validate_url_class(normalized)
    except ContractError:
        raise ContractError("Perfetto URL class is not scheme-safe metadata") from None


def _iter_export_csv_stream(stream: TextIO) -> Iterator[dict[str, str]]:
    """Yield validated Perfetto CSV rows from a text stream."""

    def bounded_lines() -> Iterator[str]:
        total = 0
        lines = 0
        while True:
            line = stream.readline(MAX_EXPORT_CSV_LINE_CHARS + 1)
            if not line:
                return
            lines += 1
            total += len(line)
            if len(line) > MAX_EXPORT_CSV_LINE_CHARS:
                raise ContractError("Perfetto export CSV line exceeds limit")
            if lines > MAX_EXPORT_CSV_LINES or total > MAX_EXPORT_CSV_CHARS:
                raise ContractError("Perfetto export CSV population exceeds limit")
            yield line

    try:
        reader = csv.DictReader(bounded_lines(), strict=True)
        fieldnames = tuple(reader.fieldnames or ())
        legacy = fieldnames == LEGACY_EXPORT_COLUMNS
        prior = fieldnames == PRIOR_EXPORT_COLUMNS
        expected_columns = (LEGACY_EXPORT_COLUMNS if legacy else
                            PRIOR_EXPORT_COLUMNS if prior else EXPORT_COLUMNS)
        missing = set(expected_columns) - set(fieldnames)
        if missing:
            raise ContractError(
                f"Perfetto export is missing columns: {', '.join(sorted(missing))}"
            )
        if fieldnames != expected_columns:
            raise ContractError(
                "Perfetto export columns are duplicated, reordered, or unexpected"
            )
        yielded = False
        for row in reader:
            if None in row or any(row.get(field) is None for field in expected_columns):
                raise ContractError("Perfetto export row width is invalid")
            if legacy:
                row.update({column: NULL_VALUE for column in _COMPILER_INPUT_HASH_COLUMNS})
            if legacy or prior:
                row.update({column: NULL_VALUE for column in _REALM_COLUMNS})
            yielded = True
            yield row
    except csv.Error as exc:
        raise ContractError(f"cannot parse Perfetto CSV: {exc}") from exc
    if not yielded:
        raise ContractError("Perfetto trace contains no supported Browser Core events")


def _iter_export_csv_rows(csv_text: str) -> Iterator[dict[str, str]]:
    """Yield Perfetto rows without duplicating the entire CSV as dictionaries."""
    yield from _iter_export_csv_stream(io.StringIO(csv_text))


def _optional_integer(value: str | None, label: str, minimum: int = 0) -> int | None:
    normalized = _optional(value)
    return None if normalized is None else _integer(normalized, label, minimum)


def _optional_script_number(value: str | None) -> int | None:
    number = _optional_integer(value, "script id", -1)
    if number == -1:
        return None
    if number is not None and number > 2_147_483_647:
        raise ContractError("Perfetto script id exceeds limit")
    return number


def _optional_boolean(value: str | None, label: str) -> bool | None:
    normalized = _optional(value)
    return None if normalized is None else _boolean(normalized, label)


def _valid_instant_slice_duration(value: str | None) -> bool:
    """Accept only the two exact Perfetto instant-slice encodings."""
    return value is None or value in {NULL_VALUE, "0"}


def _execution(row: dict[str, str], pid: int) -> dict[str, Any] | None:
    context_id = _optional(row["context_id"])
    context_kind = _optional(row["context_kind"])
    script_number = _optional_script_number(row["script_id"])
    if context_id is None and script_number is None:
        return None
    execution: dict[str, Any] = {}
    if context_id is not None:
        execution["context_id"] = context_id
        if context_kind == "frame":
            execution["frame_id"] = context_id
        elif context_kind == "worker":
            execution["worker_id"] = context_id
    if script_number is not None:
        execution["script_id"] = f"v8:{pid}:{context_id or 'unknown'}:{script_number}"
    return execution


def _detail(row: dict[str, str], native_name: str, thread_id: int) -> dict[str, Any]:
    detail: dict[str, Any] = {"native_name": native_name, "thread_id": thread_id}
    if native_name in {"BrowserCore.ScriptSourceContext", "BrowserCore.ScriptRun"}:
        token = _optional(row["realm_v8_context_id"])
        raw_world = _optional(row["realm_world_id"])
        if token is None and raw_world == "-1":
            raw_world = None
        if (token is None) != (raw_world is None):
            raise ContractError("Perfetto script realm metadata is incomplete")
        if token is not None:
            if re.fullmatch(r"[0-9A-F]{32}", token) is None or token == "0" * 32:
                raise ContractError("Perfetto script realm token is invalid")
            detail["v8_context_id"] = token
            detail["realm_id"] = _integer(raw_world, "script realm world id")
    if native_name == "BrowserCore.ScriptRun":
        # V8 inspector execution-context ID (per isolate; 0 = unassigned).
        # Opaque and recording-local; used only to join dynamic-code callers.
        inspector = _optional(row["inspector_context_id"])
        if inspector is not None:
            inspector_id = _integer(inspector, "script run inspector context id")
            if inspector_id > 2_147_483_647:
                raise ContractError("Perfetto script run inspector context id is invalid")
            if inspector_id > 0:
                detail["inspector_context_id"] = inspector_id
    integer_fields = {
        "width": "canvas width",
        "height": "canvas height",
        "data_bytes": "crypto data bytes",
        "code_bytes": "WASM code bytes",
        "chunk_bytes": "stream chunk bytes",
    }
    for field, label in integer_fields.items():
        value = _optional_integer(row[field], label)
        if value is not None:
            detail[field] = value
    for field in ("origin_clean", "success", "async", "cached"):
        value = _optional_boolean(row[field], field)
        if value is not None:
            detail[field] = value
    algorithm = _optional(row["algorithm"])
    if algorithm is not None:
        detail["algorithm"] = algorithm
    for field in (
        "reader_mode",
        "consumer_mode",
        "dispatch_kind",
        "result_kind",
        "chunk_value_type",
    ):
        value = _optional(row[field])
        if value is not None:
            detail[field] = value
    if native_name == "BrowserCore.HostCallbackExecution":
        for field in (
            "callback_interface",
            "callback_operation",
            "callback_kind",
        ):
            value = _optional(row[field])
            if value is None:
                raise ContractError(f"Perfetto host callback {field} is missing")
            detail[field] = value
    if native_name == "BrowserCore.PromiseMicrotaskExecution":
        detail["boundary"] = "v8-isolate-promise-hook-before-after"
        detail["job_kind"] = "unclassified"
    if native_name == "BrowserCore.DynamicCodeMaterialized":
        for field in ("dynamic_kind", "cache_status"):
            value = _optional(row[field])
            if value is None:
                raise ContractError(f"Perfetto dynamic code {field} is missing")
            detail[field] = value
        detail["generated_script_id"] = _integer(
            row["generated_script_id"],
            "dynamic code generated script id",
        )
        detail["caller_script_id"] = _integer(
            row["caller_script_id"],
            "dynamic code caller script id",
            -1,
        )
        detail["caller_status"] = (
            "unavailable" if detail["caller_script_id"] == -1 else "observed"
        )
        caller_inspector = _optional(row["caller_inspector_context_id"])
        if caller_inspector is not None:
            caller_inspector_id = _integer(
                caller_inspector, "dynamic code caller inspector context id")
            if caller_inspector_id > 2_147_483_647:
                raise ContractError(
                    "Perfetto dynamic code caller inspector context id is invalid")
            if caller_inspector_id > 0 and detail["caller_script_id"] != -1:
                detail["caller_inspector_context_id"] = caller_inspector_id
        detail["source_length"] = _integer(
            row["source_length"],
            "dynamic code source length",
        )
        detail["source_length_unit"] = "utf16-code-units"
        hash_status = _optional(row["compiler_input_hash_status"])
        source_hash = _optional(row["compiler_input_utf16le_sha256"])
        if hash_status is not None or source_hash is not None:
            if (
                hash_status not in {"observed", "over-limit", "unavailable"}
                or (hash_status == "observed" and (
                    source_hash is None
                    or re.fullmatch(r"[0-9a-f]{64}", source_hash) is None
                ))
                or (hash_status != "observed" and source_hash is not None)
            ):
                raise ContractError("Perfetto dynamic code compiler input hash is invalid")
            detail["compiler_input_hash_status"] = hash_status
            detail["compiler_input_utf16le_sha256"] = source_hash
    if native_name in {"BrowserCore.ScriptSourceIdentity", "BrowserCore.ScriptSourceContext"}:
        detail["script_id"] = _integer(row["script_id"], "script source identity script id")
        detail["source_length"] = _integer(
            row["source_length"], "script source identity source length"
        )
        detail["source_length_unit"] = "utf16-code-units"
        hash_status = _optional(row["compiler_input_hash_status"])
        source_hash = _optional(row["compiler_input_utf16le_sha256"])
        if (
            hash_status not in {"observed", "over-limit", "unavailable"}
            or (hash_status == "observed" and (
                source_hash is None
                or re.fullmatch(r"[0-9a-f]{64}", source_hash) is None
            ))
            or (hash_status != "observed" and source_hash is not None)
        ):
            raise ContractError("Perfetto script source identity digest is invalid")
        detail["compiler_input_hash_status"] = hash_status
        detail["compiler_input_utf16le_sha256"] = source_hash
    if native_name in {
        "BrowserCore.ScriptExecution",
        "BrowserCore.HostCallbackExecution",
        "BrowserCore.PromiseMicrotaskExecution",
    }:
        label = {
            "BrowserCore.ScriptExecution": "script execution",
            "BrowserCore.HostCallbackExecution": "host callback",
            "BrowserCore.PromiseMicrotaskExecution": "promise microtask",
        }[native_name]
        raw_duration = _optional(row["duration_ns"])
        if raw_duration is None:
            raise ContractError(f"Perfetto {label} duration is missing")
        duration = _integer(raw_duration, f"{label} duration", -1)
        if duration > MAX_TRACE_EVENT_DURATION_NS:
            raise ContractError(f"Perfetto {label} duration exceeds limit")
        if duration == -1:
            detail["completion"] = "open"
        else:
            detail["completion"] = "complete"
            detail["duration_ns"] = duration
    return detail


def _is_message_post_native_id(native_id: str, context_id: str) -> bool:
    prefix = "message:"
    if not native_id.startswith(prefix):
        return False
    suffix = native_id.removeprefix(prefix)
    legacy_prefix = f"{context_id}:"
    if suffix.startswith(legacy_prefix):
        suffix = suffix.removeprefix(legacy_prefix)
        return (
            parse_canonical_decimal(
                suffix,
                minimum=1,
                maximum=2_147_483_647,
            )
            is not None
        )
    return _is_transport_message_id(native_id)


def _is_transport_message_id(native_id: str) -> bool:
    prefix = "message:"
    if not native_id.startswith(prefix):
        return False
    suffix = native_id.removeprefix(prefix)
    return (
        parse_canonical_decimal(
            suffix,
            minimum=1,
            maximum=18_446_744_073_709_551_615,
        )
        is not None
    )


def _context_operation_id(
    native_id: str,
    kind: str,
    context_id: str,
) -> int | None:
    prefix = f"{kind}:{context_id}:"
    if not native_id.startswith(prefix):
        return None
    suffix = native_id.removeprefix(prefix)
    return parse_canonical_decimal(
        suffix,
        minimum=1,
        maximum=2_147_483_647,
    )


def _iter_normalized_export_rows(
    rows: Iterator[dict[str, str]], run_id: str, chromium_revision: str
) -> Iterator[dict[str, Any]]:
    if not RUN_ID_RE.fullmatch(run_id):
        raise ContractError("export run_id is invalid")
    if not REVISION_RE.fullmatch(chromium_revision):
        raise ContractError("export Chromium revision must be 40-hex")
    native_sequences: dict[str, int] = {}
    stream_requests: dict[str, dict[str, Any]] = {}
    script_runs: dict[tuple[int, int, str, int], str] = {}
    script_run_events: dict[
        tuple[int, int, int], dict[str, dict[str, Any]]
    ] = {}
    dynamic_materializations: dict[tuple[int, int, int], dict[str, Any]] = {}
    fetch_apis: dict[str, tuple[int, int, str, str | None]] = {}
    message_posts: set[str] = set()
    message_dispatches: dict[str, dict[str, Any]] = {}
    active_callbacks: dict[
        int,
        list[tuple[int | None, int, dict[str, Any]]],
    ] = {}
    active_callback_count = 0
    active_promise_microtasks: dict[
        int,
        list[tuple[int | None, int, dict[str, Any]]],
    ] = {}
    active_promise_count = 0
    previous_timestamp: int | None = None
    for seq, row in enumerate(rows):
        pid = _integer(row["pid"], "pid", 1)
        thread_id = _integer(row["tid"], "tid", 1)
        timestamp = _integer(row["ts_monotonic_ns"], "timestamp")
        if previous_timestamp is not None and timestamp < previous_timestamp:
            raise ContractError("Perfetto export timestamp order is invalid")
        previous_timestamp = timestamp
        track_id = _optional_integer(row["track_id"], "track id", 1)
        callback_parent_seq: int | None = None
        callback_parent_event: dict[str, Any] | None = None
        promise_parent_seq: int | None = None
        promise_parent_event: dict[str, Any] | None = None
        if track_id is not None:
            active = active_callbacks.get(track_id, [])
            retained_active = [
                callback
                for callback in active
                if callback[0] is None or timestamp < callback[0]
            ]
            active_callback_count -= len(active) - len(retained_active)
            if retained_active:
                active_callbacks[track_id] = retained_active
                callback_parent_seq = retained_active[-1][1]
                callback_parent_event = retained_active[-1][2]
            else:
                active_callbacks.pop(track_id, None)
            active_promises = active_promise_microtasks.get(track_id, [])
            retained_promises = [
                promise
                for promise in active_promises
                if promise[0] is None or timestamp < promise[0]
            ]
            active_promise_count -= len(active_promises) - len(retained_promises)
            if retained_promises:
                active_promise_microtasks[track_id] = retained_promises
                promise_parent_seq = retained_promises[-1][1]
                promise_parent_event = retained_promises[-1][2]
            else:
                active_promise_microtasks.pop(track_id, None)
        script_number = _optional_script_number(row["script_id"])
        trace_category = row["trace_category"]
        expected_trace_category = EXACT_NATIVE_TRACE_CATEGORIES.get(
            row["native_name"]
        )
        if (
            expected_trace_category is not None
            and trace_category != expected_trace_category
        ):
            raise ContractError("exact native event trace category is invalid")
        if (row["native_name"] not in {
                "BrowserCore.ScriptSourceContext", "BrowserCore.ScriptRun"}
                and (_optional(row["realm_v8_context_id"]) is not None
                     or _optional(row["realm_world_id"]) is not None)):
            raise ContractError("script realm metadata is on an unrelated native event")
        if (row["native_name"] != "BrowserCore.ScriptRun"
                and _optional(row["inspector_context_id"]) is not None):
            raise ContractError("inspector context metadata is on an unrelated native event")
        if (row["native_name"] != "BrowserCore.DynamicCodeMaterialized"
                and _optional(row["caller_inspector_context_id"]) is not None):
            raise ContractError(
                "caller inspector context metadata is on an unrelated native event")
        is_generated_binding = trace_category in GENERATED_BINDING_CATEGORIES
        if is_generated_binding:
            if _optional(row["native_schema"]) is not None:
                raise ContractError(
                    "generated Blink binding event unexpectedly carries a native schema"
                )
            category = "api"
            name = row["native_name"]
            component = "blink.bindings.generated"
        else:
            if (
                trace_category not in {"browser_core.debug", "browser_core.stream"}
                or row["native_schema"] != NATIVE_EVENT_SCHEMA
            ):
                raise ContractError("unsupported native event schema")
            category = _optional(row["event_category"])
            name = _optional(row["event_name"])
            component = _optional(row["component"])
            if category is None and name is None and _optional(row["api"]) is not None:
                category = "api"
                name = _optional(row["api"])
                component = component or EXACT_NATIVE_EVENT_COMPONENTS[
                    "BrowserCore.CanvasReadback"
                ]
            if trace_category == "browser_core.stream" and category != "stream":
                raise ContractError(
                    "dedicated stream trace category carried a non-stream event"
                )
        if category not in {
            "execution",
            "api",
            "message",
            "crypto",
            "wasm",
            "network",
            "stream",
        }:
            raise ContractError("unsupported native event category")
        if name is None:
            raise ContractError("native event name is missing")
        native_route = EXACT_NATIVE_EVENT_ROUTES.get(row["native_name"])
        if native_route is not None:
            expected_category, expected_name, label = native_route
            if category != expected_category or name != expected_name:
                raise ContractError(
                    f"native {label} event identity is invalid"
                )
        native_id = None if is_generated_binding else _optional(row["native_id"])
        native_parent_id = (
            None if is_generated_binding else _optional(row["native_parent_id"])
        )
        callback_fields = (
            "callback_interface",
            "callback_operation",
            "callback_kind",
        )
        if (
            row["native_name"] != "BrowserCore.HostCallbackExecution"
            and any(_optional(row[field]) is not None for field in callback_fields)
        ):
            raise ContractError(
                "host callback metadata is on an unrelated native event"
            )
        dynamic_code_fields = (
            "dynamic_kind",
            "cache_status",
            "generated_script_id",
            "caller_script_id",
        )
        source_identity_fields = (
            "source_length",
            "compiler_input_hash_status",
            "compiler_input_utf16le_sha256",
        )
        if (
            row["native_name"] != "BrowserCore.DynamicCodeMaterialized"
            and any(_optional(row[field]) is not None for field in dynamic_code_fields)
        ):
            raise ContractError(
                "dynamic code metadata is on an unrelated native event"
            )
        if (
            row["native_name"] not in {
                "BrowserCore.DynamicCodeMaterialized",
                "BrowserCore.ScriptSourceIdentity",
                "BrowserCore.ScriptSourceContext",
            }
            and any(_optional(row[field]) is not None for field in source_identity_fields)
        ):
            raise ContractError(
                "dynamic code metadata is on an unrelated native event"
            )
        message_dispatch_id = _optional(row["message_dispatch_id"])
        if (
            row["native_name"] != "BrowserCore.HostCallbackExecution"
            and message_dispatch_id is not None
        ):
            raise ContractError(
                "message dispatch callback metadata is on an unrelated native event"
            )
        if native_id is not None and native_id in native_sequences:
            raise ContractError(f"duplicate native event id: {native_id}")
        parent_seq = None
        if native_parent_id is not None:
            parent_seq = native_sequences.get(native_parent_id)
            if parent_seq is None:
                # A newly started worker can emit API events carrying a valid V8
                # script id even when the matching ScriptRun instant is absent from
                # the trace (for example when the trace category reaches the worker
                # after script evaluation). Rejecting the whole trace turns that
                # bounded observation gap into total evidence loss. Keep strict
                # pairing for every other native edge (especially stream
                # request/result pairs), while making an absent script parent an
                # explicit, value-free diagnostic on the retained child.
                if native_parent_id.startswith("script:"):
                    parent_seq = None
                elif (
                    category == "message"
                    and name == "MessagePort.message.dispatch"
                    and native_parent_id.startswith("message:")
                ):
                    parent_seq = None
                else:
                    raise ContractError(
                        f"native causal parent is missing or not earlier: {native_parent_id}"
                    )
        event = {
            "schema": "browser-core.trace-event/1",
            "run_id": run_id,
            "seq": seq,
            "ts_monotonic_ns": timestamp,
            "process": {
                "pid": pid,
                "type": _process_type(row["process_name"], row["thread_name"]),
            },
            "event": {"category": category, "name": name},
            "provenance": {
                "source": "native",
                "component": component or "chromium",
                "chromium_revision": chromium_revision,
                "trace_category": trace_category,
            },
            "detail": _detail(row, row["native_name"], thread_id),
        }
        js_stack = decode_js_stack(row)
        if js_stack is not None:
            if not is_generated_binding:
                raise ContractError('JavaScript stack metadata is on an unrelated native event')
            event['detail']['js_stack'] = js_stack
        if is_generated_binding:
            raw_duration = _optional(row["duration_ns"])
            if raw_duration is None:
                raise ContractError("native generated binding duration is missing")
            duration = _integer(raw_duration, "generated binding duration", -1)
            if duration > MAX_TRACE_EVENT_DURATION_NS:
                raise ContractError("native generated binding duration exceeds limit")
            if duration == -1:
                event["detail"]["completion"] = "open"
            else:
                event["detail"]["completion"] = "complete"
                event["detail"]["duration_ns"] = duration
        if native_parent_id is not None and parent_seq is None:
            event["detail"]["causal_parent_status"] = (
                "message_parent_not_in_trace"
                if category == "message"
                and name == "MessagePort.message.dispatch"
                else "script_parent_not_in_trace"
            )
        if is_generated_binding:
            # A compiled script number can be reused in several realms, and a
            # ScriptRun instant does not bound a later callback's execution.
            # Never promote the last observed script/realm pair to call truth.
            value_count = _optional_integer(row['binding_value_count'], 'binding value count')
            if value_count == 1:
                context_id = _optional(row['binding_value_context_id'])
                context_kind = _optional(row['binding_value_context_kind'])
                value_id = _optional_integer(row['binding_value_slice_id'], 'binding value slice')
                if not context_id or context_kind not in {'window', 'worker', 'other'} or value_id is None:
                    raise ContractError('generated binding value context is invalid')
                metadata = decode_context(
                    _optional(row['binding_value_context_metadata']) or '',
                    context_id=context_id, context_kind=context_kind,
                    realm_id=_optional_integer(row['binding_value_realm_id'], 'binding realm id'))
                limited = metadata is not None and metadata['schema'] == LIMITED_CONTEXT_SCHEMA
                # This direct child records the binding owner's realm. It does
                # not identify the caller realm of a borrowed cross-realm API.
                execution = {'context_id': context_id}
                if context_kind == 'window' and not limited:
                    execution['frame_id'] = context_id
                elif context_kind == 'worker' and not limited:
                    execution['worker_id'] = context_id
                event['detail']['context_attribution'] = 'native-binding-owner-limited' if limited else 'native-binding-owner'
                if limited:
                    event['detail']['context_unavailable'] = metadata['unavailable']
                event['detail']['binding_value_slice_id'] = value_id
                if script_number is not None:
                    event['detail']['script_number'] = script_number
            else:
                if callback_parent_event is not None:
                    callback_execution = callback_parent_event["execution"]
                    context_id = callback_execution["context_id"]
                    execution = {
                        key: value
                        for key, value in callback_execution.items()
                        if key != "script_id"
                    }
                    if script_number is not None:
                        execution["script_id"] = (
                            f"v8:{pid}:{context_id}:{script_number}"
                        )
                    event["detail"]["script_attribution"] = "callback-contained"
                    event["detail"]["context_attribution"] = "host-callback"
                elif promise_parent_event is not None:
                    promise_execution = promise_parent_event["execution"]
                    context_id = promise_execution["context_id"]
                    execution = dict(promise_execution)
                    if script_number is not None:
                        execution["script_id"] = (
                            f"v8:{pid}:{context_id}:{script_number}"
                        )
                    event["detail"]["script_attribution"] = "promise-contained"
                    event["detail"]["context_attribution"] = "promise-microtask"
                else:
                    binding_script_id = None
                    if script_number is not None:
                        binding_script_id = f'v8:{pid}:bindings:{thread_id}:{script_number}'
                        event['detail']['script_attribution'] = 'script-context-unresolved'
                    execution = _bindings_execution(pid, thread_id, row['thread_name'], script_id=binding_script_id)
                    event['detail']['context_attribution'] = 'unresolved'
                if value_count is not None and callback_parent_event is None:
                    if value_count < 2:
                        raise ContractError('generated binding value count is invalid')
                    event['detail']['context_attribution'] = 'ambiguous-native-binding-owner'
                    event['detail']['binding_value_count'] = value_count
        else:
            execution = (None if row["native_name"] == "BrowserCore.ScriptSourceIdentity"
                         else _execution(row, pid))
        if row["native_name"] == "BrowserCore.DynamicCodeMaterialized":
            caller_script_id = event["detail"]["caller_script_id"]
            if caller_script_id != -1:
                matches = script_run_events.get(
                    (pid, thread_id, caller_script_id),
                    {},
                )
                caller = None
                caller_inspector_id = event["detail"].get("caller_inspector_context_id")
                if caller_inspector_id is not None:
                    # V8 recorded the calling frame's own context ID. Keep
                    # only script runs observed in that exact context; a run
                    # without an ID can never be selected by this rule.
                    matches = {
                        script_id: candidate
                        for script_id, candidate in matches.items()
                        if candidate["detail"].get("inspector_context_id")
                        == caller_inspector_id
                    }
                ambiguous = len(matches) > 1
                if not ambiguous and matches:
                    caller = next(iter(matches.values()))
                if caller is not None:
                    execution = dict(caller["execution"])
                    parent_seq = caller["seq"]
                else:
                    # Callback/Promise contexts identify enclosing scopes, not
                    # the selected caller frame: a retained cross-realm function
                    # can share their numeric ScriptId (same-tab reloads do this
                    # routinely). Without an independent caller-frame context
                    # observation none may select a realm, so the event keeps
                    # no context or parent and says why. Previously this case
                    # rejected the entire export, leaving an agent with zero
                    # evidence from an otherwise valid recording.
                    event["detail"]["caller_parent_status"] = (
                        "caller_context_ambiguous" if ambiguous
                        else "script_parent_not_in_trace"
                    )
        if execution is not None:
            event["execution"] = execution
        if parent_seq is not None:
            event["causal_parent_seq"] = parent_seq
        if callback_parent_seq is not None:
            event["callback_parent_seq"] = callback_parent_seq
        if promise_parent_seq is not None:
            event["promise_parent_seq"] = promise_parent_seq
        if message_dispatch_id is not None:
            message_dispatch_parent = message_dispatches.get(message_dispatch_id)
            if message_dispatch_parent is None:
                event["detail"]["message_dispatch_parent_status"] = (
                    "message_dispatch_parent_not_in_trace"
                )
            else:
                event["message_dispatch_parent_seq"] = message_dispatch_parent["seq"]
        if category == "crypto" and "data_bytes" in event["detail"]:
            event["value"] = {
                "type": "bytes",
                "length": event["detail"]["data_bytes"],
                "redaction": "metadata",
            }
        if category == "network":
            request_id = _optional(row["request_id"])
            method = _optional(row["method"])
            url_class = _url_class(row["url_class"])
            target_scope = _optional(row["target_scope"])
            body_bytes = _optional_integer(row["body_bytes"], "request body bytes")
            if request_id is None or method is None:
                raise ContractError("native network event is missing request metadata")
            if target_scope is not None and target_scope not in FETCH_TARGET_SCOPES:
                raise ContractError("native network target scope is invalid")
            event["request"] = {
                "id": request_id,
                "method": method,
                "url_class": url_class,
                "body_bytes": body_bytes or 0,
            }
            if target_scope is not None:
                event["request"]["target_scope"] = target_scope
        if category == "execution" and name == "script.run":
            detail = event["detail"]
            execution = event.get("execution") or {}
            context_id = execution.get("context_id")
            if native_parent_id is not None:
                raise ContractError("native script run parent is invalid")
            if (
                component != EXACT_NATIVE_EVENT_COMPONENTS["BrowserCore.ScriptRun"]
                or row["native_name"] != "BrowserCore.ScriptRun"
                or not isinstance(context_id, str)
                or not context_id
                or script_number is None
                or native_id != f"script:{context_id}:{script_number}"
                or execution.get("script_id")
                != f"v8:{pid}:{context_id}:{script_number}"
                or not _valid_instant_slice_duration(row["duration_ns"])
                or set(detail) != ({"native_name", "thread_id"} |
                    ({"v8_context_id", "realm_id"} if "v8_context_id" in detail else set()) |
                    ({"inspector_context_id"} if "inspector_context_id" in detail else set()))
            ):
                raise ContractError("native script run event is invalid")
        if category == "execution" and name == "script.source.identity":
            detail = event["detail"]
            if (
                component != EXACT_NATIVE_EVENT_COMPONENTS["BrowserCore.ScriptSourceIdentity"]
                or row["native_name"] != "BrowserCore.ScriptSourceIdentity"
                or track_id is None
                or not _valid_instant_slice_duration(row["duration_ns"])
                or native_id is not None
                or native_parent_id is not None
                or _optional(row["context_id"]) is not None
                or _optional(row["context_kind"]) is not None
                or _optional(row["realm_v8_context_id"]) is not None
                or _optional(row["realm_world_id"]) is not None
                or set(detail) != {
                    "native_name", "thread_id", "script_id", "source_length",
                    "source_length_unit", "compiler_input_hash_status",
                    "compiler_input_utf16le_sha256",
                }
                or event.get("execution") is not None
            ):
                raise ContractError("native script source identity event is invalid")
        if category == "execution" and name == "script.source.context":
            detail = event["detail"]
            execution = event.get("execution") or {}
            context_id = execution.get("context_id")
            if (
                component != EXACT_NATIVE_EVENT_COMPONENTS["BrowserCore.ScriptSourceContext"]
                or row["native_name"] != "BrowserCore.ScriptSourceContext"
                or track_id is None
                or not _valid_instant_slice_duration(row["duration_ns"])
                or native_id is not None
                or native_parent_id is not None
                or _optional(row["context_kind"])
                not in {"frame", "worker", "worklet", "other"}
                or not isinstance(context_id, str)
                or not context_id
                or script_number is None
                or execution.get("script_id")
                != f"v8:{pid}:{context_id}:{script_number}"
                or set(detail) != ({
                    "native_name", "thread_id", "script_id", "source_length",
                    "source_length_unit", "compiler_input_hash_status",
                    "compiler_input_utf16le_sha256",
                } | ({"v8_context_id", "realm_id"}
                     if "v8_context_id" in detail else set()))
            ):
                raise ContractError("native script source context event is invalid")
        if category == "execution" and name == "script.execution":
            execution = event.get("execution") or {}
            context_id = execution.get("context_id")
            if native_parent_id is not None:
                raise ContractError("native script execution parent is invalid")
            if (
                component
                != EXACT_NATIVE_EVENT_COMPONENTS["BrowserCore.ScriptExecution"]
                or row["native_name"] != "BrowserCore.ScriptExecution"
                or not isinstance(context_id, str)
                or not context_id
                or script_number is None
                or native_id is not None
                or execution.get("script_id")
                != f"v8:{pid}:{context_id}:{script_number}"
            ):
                raise ContractError("native script execution event is invalid")
        if category == "execution" and name == "host.callback.execution":
            detail = event["detail"]
            execution = event.get("execution") or {}
            context_id = execution.get("context_id")
            expected_parent_id = (
                None
                if script_number is None or not isinstance(context_id, str)
                else f"script:{context_id}:{script_number}"
            )
            unexpected_fields = (
                "api",
                "native_id",
                "algorithm",
                "data_bytes",
                "success",
                "async",
                "cached",
                "code_bytes",
                "request_id",
                "method",
                "url_class",
                "target_scope",
                "body_bytes",
                "reader_mode",
                "consumer_mode",
                "dispatch_kind",
                "result_kind",
                "chunk_value_type",
                "chunk_bytes",
                "width",
                "height",
                "origin_clean",
                "binding_value_count",
                "binding_value_slice_id",
                "binding_value_context_id",
                "binding_value_context_kind",
                "binding_value_context_metadata",
                "binding_value_realm_id",
                *JS_STACK_COLUMNS,
            )
            expected_detail = {
                "native_name",
                "thread_id",
                "completion",
                "callback_interface",
                "callback_operation",
                "callback_kind",
            }
            if detail.get("completion") == "complete":
                expected_detail.add("duration_ns")
            if parent_seq is None and native_parent_id is not None:
                expected_detail.add("causal_parent_status")
            if message_dispatch_id is not None and (
                message_dispatch_id not in message_dispatches
            ):
                expected_detail.add("message_dispatch_parent_status")
            message_dispatch_parent = (
                message_dispatches.get(message_dispatch_id)
                if message_dispatch_id is not None
                else None
            )
            message_dispatch_context = (
                (message_dispatch_parent.get("execution") or {}).get("context_id")
                if message_dispatch_parent is not None
                else None
            )
            if (
                component
                != EXACT_NATIVE_EVENT_COMPONENTS[
                    "BrowserCore.HostCallbackExecution"
                ]
                or row["native_name"] != "BrowserCore.HostCallbackExecution"
                or event["process"]["type"] != "renderer"
                or track_id is None
                or not isinstance(context_id, str)
                or not context_id
                or _optional(row["context_kind"])
                not in {"frame", "worker", "other"}
                or native_id is not None
                or native_parent_id != expected_parent_id
                or script_number is not None
                and execution.get("script_id")
                != f"v8:{pid}:{context_id}:{script_number}"
                or set(detail) != expected_detail
                or message_dispatch_id is not None
                and (
                    detail.get("callback_interface") != "EventListener"
                    or detail.get("callback_operation") != "handleEvent"
                    or detail.get("callback_kind") != "function"
                    or _context_operation_id(
                        message_dispatch_id,
                        "message-dispatch",
                        context_id,
                    )
                    is None
                )
                or message_dispatch_parent is not None
                and (
                    message_dispatch_parent.get("process") != event.get("process")
                    or message_dispatch_parent.get("detail", {}).get("thread_id")
                    != thread_id
                    or message_dispatch_context != context_id
                    or message_dispatch_parent.get("ts_monotonic_ns", timestamp + 1)
                    > timestamp
                )
                or any(
                    _optional(row[field]) is not None
                    for field in unexpected_fields
                )
            ):
                raise ContractError("native host callback event is invalid")
        if category == "execution" and name == "promise.microtask.execution":
            detail = event["detail"]
            execution = event.get("execution") or {}
            context_id = execution.get("context_id")
            unexpected_fields = (
                "api",
                "script_id",
                "native_id",
                "native_parent_id",
                "message_dispatch_id",
                "callback_interface",
                "callback_operation",
                "callback_kind",
                "algorithm",
                "data_bytes",
                "success",
                "async",
                "cached",
                "code_bytes",
                "request_id",
                "method",
                "url_class",
                "target_scope",
                "body_bytes",
                "reader_mode",
                "consumer_mode",
                "dispatch_kind",
                "result_kind",
                "chunk_value_type",
                "chunk_bytes",
                "width",
                "height",
                "origin_clean",
                "binding_value_count",
                "binding_value_slice_id",
                "binding_value_context_id",
                "binding_value_context_kind",
                "binding_value_context_metadata",
                "binding_value_realm_id",
                *JS_STACK_COLUMNS,
            )
            expected_detail = {
                "native_name",
                "thread_id",
                "completion",
                "boundary",
                "job_kind",
            }
            if detail.get("completion") == "complete":
                expected_detail.add("duration_ns")
            if (
                component
                != EXACT_NATIVE_EVENT_COMPONENTS[
                    "BrowserCore.PromiseMicrotaskExecution"
                ]
                or row["native_name"]
                != "BrowserCore.PromiseMicrotaskExecution"
                or event["process"]["type"] != "renderer"
                or track_id is None
                or not isinstance(context_id, str)
                or not context_id
                or _optional(row["context_kind"])
                not in {"frame", "worker", "other"}
                or native_id is not None
                or native_parent_id is not None
                or set(detail) != expected_detail
                or any(
                    _optional(row[field]) is not None
                    for field in unexpected_fields
                )
            ):
                raise ContractError("native promise microtask event is invalid")
        if category == "execution" and name == "dynamic.code.materialized":
            detail = event["detail"]
            unexpected_fields = (
                "api",
                "context_id",
                "context_kind",
                "script_id",
                "native_id",
                "native_parent_id",
                "message_dispatch_id",
                "callback_interface",
                "callback_operation",
                "callback_kind",
                "algorithm",
                "data_bytes",
                "success",
                "async",
                "cached",
                "code_bytes",
                "request_id",
                "method",
                "url_class",
                "target_scope",
                "body_bytes",
                "reader_mode",
                "consumer_mode",
                "dispatch_kind",
                "result_kind",
                "chunk_value_type",
                "chunk_bytes",
                "width",
                "height",
                "origin_clean",
                "binding_value_count",
                "binding_value_slice_id",
                "binding_value_context_id",
                "binding_value_context_kind",
                "binding_value_context_metadata",
                "binding_value_realm_id",
                *JS_STACK_COLUMNS,
            )
            expected_detail = {
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
            if "compiler_input_hash_status" in detail:
                expected_detail.update({
                    "compiler_input_hash_status",
                    "compiler_input_utf16le_sha256",
                })
            if parent_seq is None and detail.get("caller_script_id") != -1:
                expected_detail.add("caller_parent_status")
            if "caller_inspector_context_id" in detail:
                expected_detail.add("caller_inspector_context_id")
            if (
                component
                != EXACT_NATIVE_EVENT_COMPONENTS[
                    "BrowserCore.DynamicCodeMaterialized"
                ]
                or row["native_name"] != "BrowserCore.DynamicCodeMaterialized"
                or event["process"]["type"] != "renderer"
                or track_id is None
                or not _valid_instant_slice_duration(row["duration_ns"])
                or native_id is not None
                or native_parent_id is not None
                or set(detail) != expected_detail
                or any(
                    _optional(row[field]) is not None
                    for field in unexpected_fields
                )
            ):
                raise ContractError("native dynamic code event is invalid")
        if is_generated_binding:
            detail = event["detail"]
            interface_name = name.partition(".")[0]
            unexpected_fields = (
                "event_category",
                "event_name",
                "component",
                "api",
                "context_id",
                "context_kind",
                "native_id",
                "native_parent_id",
                "algorithm",
                "data_bytes",
                "success",
                "async",
                "cached",
                "code_bytes",
                "request_id",
                "method",
                "url_class",
                "target_scope",
                "body_bytes",
                "reader_mode",
                "consumer_mode",
                "dispatch_kind",
                "result_kind",
                "chunk_value_type",
                "chunk_bytes",
                "width",
                "height",
                "origin_clean",
            )
            if (
                GENERATED_BINDING_NAME_RE.fullmatch(name) is None
                or (trace_category == "blink.bindings.encoding")
                != (interface_name in ENCODING_BINDING_INTERFACES)
                or any(_optional(row[field]) is not None for field in unexpected_fields)
                or event["process"]["type"] != "renderer"
                or native_id is not None
                or native_parent_id is not None
            ):
                raise ContractError("native generated binding event is invalid")
        if (
            not is_generated_binding
            and category == "api"
            and name == "HTMLCanvasElement.toDataURL"
        ):
            detail = event["detail"]
            legacy_only_fields = (
                "event_category",
                "event_name",
                "component",
                "context_id",
                "context_kind",
                "script_id",
                "native_id",
                "native_parent_id",
                "algorithm",
                "data_bytes",
                "success",
                "async",
                "cached",
                "code_bytes",
                "request_id",
                "method",
                "url_class",
                "target_scope",
                "body_bytes",
                "reader_mode",
                "consumer_mode",
                "dispatch_kind",
                "result_kind",
                "chunk_value_type",
                "chunk_bytes",
            )
            if (
                trace_category
                != EXACT_NATIVE_TRACE_CATEGORIES["BrowserCore.CanvasReadback"]
                or row["native_name"] != "BrowserCore.CanvasReadback"
                or _optional(row["api"])
                != "HTMLCanvasElement.toDataURL"
                or not _valid_instant_slice_duration(row["duration_ns"])
                or any(_optional(row[field]) is not None for field in legacy_only_fields)
                or set(detail)
                != {
                    "native_name",
                    "thread_id",
                    "width",
                    "height",
                    "origin_clean",
                }
                or any(
                    isinstance(detail.get(field), bool)
                    or not isinstance(detail.get(field), int)
                    or not 0 <= detail[field] <= MAX_CANVAS_DIMENSION
                    for field in ("width", "height")
                )
                or type(detail.get("origin_clean")) is not bool
                or event["process"]["type"] != "renderer"
                or event.get("execution") is not None
                or parent_seq is not None
            ):
                raise ContractError("native canvas readback event is invalid")
        if category == "crypto" and name == "SubtleCrypto.digest":
            detail = event["detail"]
            execution = event.get("execution") or {}
            context_id = execution.get("context_id")
            script_id = execution.get("script_id")
            expected_parent_id = (
                None
                if script_number is None or not isinstance(context_id, str)
                else f"script:{context_id}:{script_number}"
            )
            required_detail = {"native_name", "thread_id", "algorithm", "data_bytes"}
            unexpected_fields = (
                "api",
                "success",
                "async",
                "cached",
                "code_bytes",
                "request_id",
                "method",
                "url_class",
                "target_scope",
                "body_bytes",
                "reader_mode",
                "consumer_mode",
                "dispatch_kind",
                "result_kind",
                "chunk_value_type",
                "chunk_bytes",
                "width",
                "height",
                "origin_clean",
            )
            if (
                trace_category
                != EXACT_NATIVE_TRACE_CATEGORIES["BrowserCore.CryptoDigest"]
                or component
                != EXACT_NATIVE_EVENT_COMPONENTS["BrowserCore.CryptoDigest"]
                or row["native_name"] != "BrowserCore.CryptoDigest"
                or event["process"]["type"] != "renderer"
                or not isinstance(context_id, str)
                or not context_id
                or _optional(row["context_kind"])
                not in {"frame", "worker", "other"}
                or native_id is None
                or _context_operation_id(native_id, "crypto", context_id) is None
                or native_parent_id != expected_parent_id
                or script_number is not None
                and script_id != f"v8:{pid}:{context_id}:{script_number}"
                or parent_seq is not None
                and script_runs.get((pid, thread_id, context_id, script_number or 0)) != script_id
                or set(detail)
                not in (required_detail, required_detail | {"causal_parent_status"})
                or detail.get("algorithm") not in WEBCRYPTO_DIGEST_ALGORITHMS
                or not isinstance(detail.get("data_bytes"), int)
                or not 0 <= detail["data_bytes"] <= MAX_TRACE_BUFFER_BYTES
                or not _valid_instant_slice_duration(row["duration_ns"])
                or any(
                    _optional(row[field]) is not None
                    for field in unexpected_fields
                )
            ):
                raise ContractError("native crypto digest event is invalid")
        if category == "wasm" and name == "WebAssembly.compile.completed":
            detail = event["detail"]
            execution = event.get("execution") or {}
            context_id = execution.get("context_id")
            required_detail = {
                "native_name",
                "thread_id",
                "success",
                "async",
                "cached",
                "code_bytes",
            }
            unexpected_fields = (
                "api",
                "algorithm",
                "data_bytes",
                "request_id",
                "method",
                "url_class",
                "target_scope",
                "body_bytes",
                "reader_mode",
                "consumer_mode",
                "dispatch_kind",
                "result_kind",
                "chunk_value_type",
                "chunk_bytes",
                "width",
                "height",
                "origin_clean",
            )
            if (
                trace_category
                != EXACT_NATIVE_TRACE_CATEGORIES["BrowserCore.WasmCompiled"]
                or component
                != EXACT_NATIVE_EVENT_COMPONENTS["BrowserCore.WasmCompiled"]
                or row["native_name"] != "BrowserCore.WasmCompiled"
                or event["process"]["type"] != "renderer"
                or not isinstance(context_id, str)
                or not context_id
                or _optional(row["context_kind"])
                not in {"frame", "worker", "other"}
                or native_id is None
                or _context_operation_id(native_id, "wasm", context_id) is None
                or native_parent_id is not None
                or script_number is not None
                or set(detail) != required_detail
                or any(
                    type(detail.get(field)) is not bool
                    for field in ("success", "async", "cached")
                )
                or not isinstance(detail.get("code_bytes"), int)
                or not 0 <= detail["code_bytes"] <= MAX_WASM_MODULE_BYTES
                or not _valid_instant_slice_duration(row["duration_ns"])
                or any(
                    _optional(row[field]) is not None
                    for field in unexpected_fields
                )
            ):
                raise ContractError("native WASM compile event is invalid")
        if category == "api" and name == "fetch":
            detail = event["detail"]
            execution = event.get("execution") or {}
            context_id = execution.get("context_id")
            script_id = execution.get("script_id")
            expected_parent_id = (
                None
                if script_number is None or not isinstance(context_id, str)
                else f"script:{context_id}:{script_number}"
            )
            unexpected_fields = (
                "api",
                "algorithm",
                "data_bytes",
                "success",
                "async",
                "cached",
                "code_bytes",
                "request_id",
                "method",
                "url_class",
                "target_scope",
                "body_bytes",
                "reader_mode",
                "consumer_mode",
                "dispatch_kind",
                "result_kind",
                "chunk_value_type",
                "chunk_bytes",
                "width",
                "height",
                "origin_clean",
            )
            if (
                trace_category
                != EXACT_NATIVE_TRACE_CATEGORIES["BrowserCore.FetchCall"]
                or component != EXACT_NATIVE_EVENT_COMPONENTS["BrowserCore.FetchCall"]
                or row["native_name"] != "BrowserCore.FetchCall"
                or event["process"]["type"] != "renderer"
                or not isinstance(context_id, str)
                or not context_id
                or _optional(row["context_kind"])
                not in {"frame", "worker", "other"}
                or native_id is None
                or _context_operation_id(native_id, "fetch-api", context_id) is None
                or native_parent_id != expected_parent_id
                or script_number is not None
                and script_id != f"v8:{pid}:{context_id}:{script_number}"
                or parent_seq is not None
                and script_runs.get((pid, thread_id, context_id, script_number or 0))
                != script_id
                or set(detail)
                not in (
                    {"native_name", "thread_id"},
                    {"native_name", "thread_id", "causal_parent_status"},
                )
                or not _valid_instant_slice_duration(row["duration_ns"])
                or any(
                    _optional(row[field]) is not None
                    for field in unexpected_fields
                )
            ):
                raise ContractError("native fetch API event is invalid")
        if category == "network" and name == "fetch.request.start":
            detail = event["detail"]
            execution = event.get("execution") or {}
            context_id = execution.get("context_id")
            script_id = execution.get("script_id")
            operation_id = (
                _context_operation_id(native_id, "fetch-request", context_id)
                if native_id is not None and isinstance(context_id, str)
                else None
            )
            expected_parent_id = (
                None
                if operation_id is None or not isinstance(context_id, str)
                else f"fetch-api:{context_id}:{operation_id}"
            )
            expected_parent = (
                pid,
                thread_id,
                context_id,
                script_id,
            )
            unexpected_fields = (
                "api",
                "algorithm",
                "data_bytes",
                "success",
                "async",
                "cached",
                "code_bytes",
                "reader_mode",
                "consumer_mode",
                "dispatch_kind",
                "result_kind",
                "chunk_value_type",
                "chunk_bytes",
                "width",
                "height",
                "origin_clean",
            )
            if (
                trace_category
                != EXACT_NATIVE_TRACE_CATEGORIES["BrowserCore.FetchRequestStart"]
                or component
                != EXACT_NATIVE_EVENT_COMPONENTS["BrowserCore.FetchRequestStart"]
                or row["native_name"] != "BrowserCore.FetchRequestStart"
                or event["process"]["type"] != "renderer"
                or not isinstance(context_id, str)
                or not context_id
                or _optional(row["context_kind"])
                not in {"frame", "worker", "other"}
                or operation_id is None
                or native_parent_id != expected_parent_id
                or fetch_apis.get(native_parent_id or "") != expected_parent
                or (event.get("request") or {}).get("id") != native_id
                or script_number is not None
                and script_id != f"v8:{pid}:{context_id}:{script_number}"
                or set(detail) != {"native_name", "thread_id"}
                or not _valid_instant_slice_duration(row["duration_ns"])
                or any(
                    _optional(row[field]) is not None
                    for field in unexpected_fields
                )
            ):
                raise ContractError("native fetch request event is invalid")
        if category == "message" and name == "MessagePort.postMessage":
            detail = event["detail"]
            execution = event.get("execution") or {}
            context_id = execution.get("context_id")
            script_id = execution.get("script_id")
            expected_parent_id = (
                None
                if script_number is None or not isinstance(context_id, str)
                else f"script:{context_id}:{script_number}"
            )
            unexpected_fields = (
                "api",
                "algorithm",
                "data_bytes",
                "success",
                "async",
                "cached",
                "code_bytes",
                "request_id",
                "method",
                "url_class",
                "target_scope",
                "body_bytes",
                "reader_mode",
                "consumer_mode",
                "dispatch_kind",
                "result_kind",
                "chunk_value_type",
                "chunk_bytes",
                "width",
                "height",
                "origin_clean",
            )
            if (script_number is None) != (native_parent_id is None):
                raise ContractError("native message post parent is invalid")
            if (
                trace_category
                != EXACT_NATIVE_TRACE_CATEGORIES["BrowserCore.MessagePost"]
                or component
                != EXACT_NATIVE_EVENT_COMPONENTS["BrowserCore.MessagePost"]
                or row["native_name"] != "BrowserCore.MessagePost"
                or event["process"]["type"] != "renderer"
                or not isinstance(context_id, str)
                or not context_id
                or _optional(row["context_kind"])
                not in {"frame", "worker", "other"}
                or native_id is None
                or not _is_message_post_native_id(native_id, context_id)
                or native_parent_id != expected_parent_id
                or script_number is not None
                and script_id != f"v8:{pid}:{context_id}:{script_number}"
                or parent_seq is not None
                and (pid, thread_id, context_id, script_number) not in script_runs
                or not _valid_instant_slice_duration(row["duration_ns"])
                or any(
                    _optional(row[field]) is not None
                    for field in unexpected_fields
                )
            ):
                raise ContractError("native message post event is invalid")
            if set(detail) not in (
                {"native_name", "thread_id"},
                {"native_name", "thread_id", "causal_parent_status"},
            ):
                raise ContractError("native message post metadata is invalid")
        if category == "message" and name == "MessagePort.message.dispatch":
            detail = event["detail"]
            execution = event.get("execution") or {}
            context_id = execution.get("context_id")
            dispatch_kind = detail.get("dispatch_kind")
            operation_id = (
                _context_operation_id(native_id, "message-dispatch", context_id)
                if native_id is not None and isinstance(context_id, str)
                else None
            )
            unexpected_fields = (
                "api",
                "algorithm",
                "data_bytes",
                "success",
                "async",
                "cached",
                "code_bytes",
                "request_id",
                "method",
                "url_class",
                "target_scope",
                "body_bytes",
                "reader_mode",
                "consumer_mode",
                "result_kind",
                "chunk_value_type",
                "chunk_bytes",
                "width",
                "height",
                "origin_clean",
            )
            if native_parent_id is None:
                detail["causal_parent_status"] = "message_parent_unavailable"
            if (
                trace_category
                != EXACT_NATIVE_TRACE_CATEGORIES["BrowserCore.MessageDispatch"]
                or component
                != EXACT_NATIVE_EVENT_COMPONENTS["BrowserCore.MessageDispatch"]
                or row["native_name"] != "BrowserCore.MessageDispatch"
                or event["process"]["type"] != "renderer"
                or not isinstance(context_id, str)
                or not context_id
                or _optional(row["context_kind"])
                not in {"frame", "worker", "other"}
                or script_number is not None
                or operation_id is None
                or dispatch_kind not in {"message", "messageerror"}
                or native_parent_id is not None
                and not _is_transport_message_id(native_parent_id)
                or parent_seq is not None
                and native_parent_id not in message_posts
                or not _valid_instant_slice_duration(row["duration_ns"])
                or any(
                    _optional(row[field]) is not None
                    for field in unexpected_fields
                )
            ):
                raise ContractError("native message dispatch event is invalid")
        if category == "stream":
            detail = event["detail"]
            execution = event.get("execution") or {}
            reader_mode = detail.get("reader_mode")
            consumer_mode = detail.get("consumer_mode")
            result_kind = detail.get("result_kind")
            chunk_value_type = detail.get("chunk_value_type")
            chunk_bytes = detail.get("chunk_bytes")
            if not isinstance(execution.get("context_id"), str):
                raise ContractError("native stream event context is invalid")
            if name == "body.consume":
                context_id = execution.get("context_id")
                script_id = execution.get("script_id")
                operation_id = (
                    _context_operation_id(native_id, "body-consume", context_id)
                    if native_id is not None and isinstance(context_id, str)
                    else None
                )
                expected_parent_id = (
                    None
                    if script_number is None or not isinstance(context_id, str)
                    else f"script:{context_id}:{script_number}"
                )
                unexpected_fields = (
                    "api",
                    "algorithm",
                    "data_bytes",
                    "success",
                    "async",
                    "cached",
                    "code_bytes",
                    "request_id",
                    "method",
                    "url_class",
                    "target_scope",
                    "body_bytes",
                    "reader_mode",
                    "dispatch_kind",
                    "result_kind",
                    "chunk_value_type",
                    "chunk_bytes",
                    "width",
                    "height",
                    "origin_clean",
                )
                if (
                    trace_category
                    != EXACT_NATIVE_TRACE_CATEGORIES["BrowserCore.BodyConsume"]
                    or component
                    != EXACT_NATIVE_EVENT_COMPONENTS["BrowserCore.BodyConsume"]
                    or row["native_name"] != "BrowserCore.BodyConsume"
                    or event["process"]["type"] != "renderer"
                    or not isinstance(context_id, str)
                    or not context_id
                    or _optional(row["context_kind"])
                    not in {"frame", "worker", "worklet", "other"}
                    or operation_id is None
                    or script_number is not None
                    and script_id != f"v8:{pid}:{context_id}:{script_number}"
                    or consumer_mode not in BODY_CONSUMER_MODES
                    or not _valid_instant_slice_duration(row["duration_ns"])
                    or any(
                        _optional(row[field]) is not None
                        for field in unexpected_fields
                    )
                ):
                    raise ContractError("native body consumer event is invalid")
                if (
                    (script_number is None) != (native_parent_id is None)
                    or native_parent_id != expected_parent_id
                ):
                    raise ContractError("native body consumer parent is invalid")
                if parent_seq is not None:
                    script_parent = script_runs.get(
                        (pid, thread_id, context_id, script_number or 0)
                    )
                    if script_parent != execution.get("script_id"):
                        raise ContractError("native body consumer parent is invalid")
            elif name == "stream.read.request":
                context_id = execution.get("context_id")
                script_id = execution.get("script_id")
                operation_id = (
                    _context_operation_id(native_id, "stream-read", context_id)
                    if native_id is not None and isinstance(context_id, str)
                    else None
                )
                expected_parent_id = (
                    None
                    if script_number is None or not isinstance(context_id, str)
                    else f"script:{context_id}:{script_number}"
                )
                unexpected_fields = (
                    "api",
                    "algorithm",
                    "data_bytes",
                    "success",
                    "async",
                    "cached",
                    "code_bytes",
                    "request_id",
                    "method",
                    "url_class",
                    "target_scope",
                    "body_bytes",
                    "consumer_mode",
                    "dispatch_kind",
                    "result_kind",
                    "chunk_value_type",
                    "chunk_bytes",
                    "width",
                    "height",
                    "origin_clean",
                )
                if (
                    component
                    != EXACT_NATIVE_EVENT_COMPONENTS["BrowserCore.StreamReadRequest"]
                    or row["native_name"] != "BrowserCore.StreamReadRequest"
                    or event["process"]["type"] != "renderer"
                    or not isinstance(context_id, str)
                    or not context_id
                    or operation_id is None
                    or native_parent_id != expected_parent_id
                    or script_number is not None
                    and script_id != f"v8:{pid}:{context_id}:{script_number}"
                    or parent_seq is not None
                    and script_runs.get((pid, thread_id, context_id, script_number or 0))
                    != script_id
                    or reader_mode not in {"default", "byob"}
                    or consumer_mode is not None
                    or any(
                        value is not None
                        for value in (result_kind, chunk_value_type, chunk_bytes)
                    )
                    or not _valid_instant_slice_duration(row["duration_ns"])
                    or any(
                        _optional(row[field]) is not None
                        for field in unexpected_fields
                    )
                ):
                    raise ContractError("native stream read request is invalid")
            elif name == "stream.read.result":
                context_id = execution.get("context_id")
                unexpected_fields = (
                    "api",
                    "script_id",
                    "algorithm",
                    "data_bytes",
                    "success",
                    "async",
                    "cached",
                    "code_bytes",
                    "request_id",
                    "method",
                    "url_class",
                    "target_scope",
                    "body_bytes",
                    "consumer_mode",
                    "dispatch_kind",
                    "width",
                    "height",
                    "origin_clean",
                )
                if (
                    component
                    != EXACT_NATIVE_EVENT_COMPONENTS["BrowserCore.StreamReadResult"]
                    or row["native_name"] != "BrowserCore.StreamReadResult"
                    or event["process"]["type"] != "renderer"
                    or not isinstance(context_id, str)
                    or not context_id
                    or native_id is None
                    or native_parent_id is None
                    or native_id != f"{native_parent_id}:result"
                    or parent_seq is None
                    or reader_mode not in {"default", "byob"}
                    or consumer_mode is not None
                    or result_kind not in {"chunk", "closed", "error"}
                    or chunk_value_type not in {"bytes", "other", "none"}
                    or not isinstance(chunk_bytes, int)
                    or not 0 <= chunk_bytes <= MAX_TRACE_BUFFER_BYTES
                    or not _valid_instant_slice_duration(row["duration_ns"])
                    or any(
                        _optional(row[field]) is not None
                        for field in unexpected_fields
                    )
                ):
                    raise ContractError("native stream read result is invalid")
                parent = stream_requests.get(native_parent_id or "")
                if parent is None:
                    raise ContractError(
                        "native stream read result parent is inconsistent"
                    )
                if (
                    parent["event"]
                    != {"category": "stream", "name": "stream.read.request"}
                    or parent["detail"].get("reader_mode") != reader_mode
                    or (parent.get("execution") or {}).get("context_id")
                    != (execution.get("context_id"))
                    or parent["process"] != event["process"]
                    or parent["detail"].get("thread_id") != thread_id
                    or execution.get("script_id") is not None
                ):
                    raise ContractError(
                        "native stream read result parent is inconsistent"
                    )
                if (
                    (result_kind == "chunk" and chunk_value_type == "none")
                    or (result_kind == "closed" and chunk_value_type == "other")
                    or (
                        result_kind == "error"
                        and (chunk_value_type != "none" or chunk_bytes != 0)
                    )
                    or (chunk_value_type != "bytes" and chunk_bytes != 0)
                    or (reader_mode == "byob" and chunk_value_type == "other")
                    or (
                        reader_mode == "default"
                        and result_kind == "closed"
                        and chunk_value_type != "none"
                    )
                ):
                    raise ContractError("native stream result metadata is inconsistent")
                if chunk_value_type == "bytes":
                    event["value"] = {
                        "type": "bytes",
                        "length": chunk_bytes,
                        "redaction": "metadata",
                    }
            else:
                raise ContractError("native stream event name is invalid")
        event_script_number: int | None = script_number
        if row["native_name"] == "BrowserCore.DynamicCodeMaterialized":
            caller_script_id = event["detail"].get("caller_script_id")
            event_script_number = (
                caller_script_id if caller_script_id != -1 else None
            )
        elif row["native_name"] in {
            "BrowserCore.ScriptSourceIdentity", "BrowserCore.ScriptSourceContext",
        }:
            event_script_number = None
        if event_script_number is not None:
            dynamic_parent = dynamic_materializations.get(
                (pid, thread_id, event_script_number)
            )
            if dynamic_parent is not None:
                event["dynamic_code_parent_seq"] = dynamic_parent["seq"]
        event = validate_trace_event(event)
        if event["event"] == {
            "category": "execution",
            "name": "host.callback.execution",
        }:
            assert track_id is not None
            duration = event["detail"].get("duration_ns")
            callback_end = None if duration is None else timestamp + duration
            active_callbacks.setdefault(track_id, []).append(
                (callback_end, seq, event)
            )
            active_callback_count += 1
            if active_callback_count > MAX_EXPORT_EVENTS:
                raise ContractError("active host callback population exceeds limit")
        if event["event"] == {
            "category": "execution",
            "name": "promise.microtask.execution",
        }:
            assert track_id is not None
            duration = event["detail"].get("duration_ns")
            promise_end = None if duration is None else timestamp + duration
            active_promise_microtasks.setdefault(track_id, []).append(
                (promise_end, seq, event)
            )
            active_promise_count += 1
            if active_promise_count > MAX_EXPORT_EVENTS:
                raise ContractError("active promise microtask population exceeds limit")
        if event['event'] == {'category': 'execution', 'name': 'script.run'} and script_number is not None:
            execution = event['execution']
            script_runs[(pid, thread_id, execution['context_id'], script_number)] = execution['script_id']
            script_run_events.setdefault((pid, thread_id, script_number), {})[
                execution["script_id"]
            ] = event
        if event["event"] == {
            "category": "execution",
            "name": "dynamic.code.materialized",
        }:
            generated_script_id = event["detail"]["generated_script_id"]
            dynamic_materializations[(pid, thread_id, generated_script_id)] = event
        if native_id is not None:
            native_sequences[native_id] = seq
        if (
            event["event"] == {"category": "api", "name": "fetch"}
            and native_id is not None
        ):
            execution = event.get("execution") or {}
            fetch_apis[native_id] = (
                pid,
                thread_id,
                execution.get("context_id"),
                execution.get("script_id"),
            )
        if (
            event["event"]
            == {"category": "message", "name": "MessagePort.postMessage"}
            and native_id is not None
        ):
            message_posts.add(native_id)
        if (
            event["event"]
            == {"category": "message", "name": "MessagePort.message.dispatch"}
            and native_id is not None
        ):
            message_dispatches[native_id] = event
        if (
            event["event"] == {"category": "stream", "name": "stream.read.request"}
            and native_id is not None
        ):
            stream_requests[native_id] = event
        yield event


def parse_export_csv(
    csv_text: str, run_id: str, chromium_revision: str
) -> list[dict[str, Any]]:
    """Normalize a complete CSV string for callers that need an in-memory list."""
    return list(
        _iter_normalized_export_rows(
            _iter_export_csv_rows(csv_text), run_id, chromium_revision
        )
    )


def _require_source_binding(value: Any) -> dict[str, Any]:
    if type(value) is not dict or set(value) != {"bytes", "sha256"}:
        raise ContractError("Perfetto expected source binding is invalid")
    size = value.get("bytes")
    digest = value.get("sha256")
    if (
        isinstance(size, bool)
        or not isinstance(size, int)
        or not 0 <= size <= MAX_PERFETTO_ARTIFACT_BYTES
        or not isinstance(digest, str)
        or len(digest) != 64
        or any(character not in "0123456789abcdef" for character in digest)
    ):
        raise ContractError("Perfetto expected source binding is invalid")
    return {"bytes": size, "sha256": digest}


def bind_perfetto_source_trace(trace_path: Path) -> dict[str, Any]:
    """Return the closed content binding accepted by count and export operations."""
    return _stable_file_binding(trace_path, label="Perfetto source trace")


def count_exportable_events(
    trace_processor: Path,
    trace_path: Path,
    *,
    expected_source_binding: dict[str, Any] | None = None,
) -> int:
    """Count normalized rows before requesting the potentially huge export CSV."""
    if not isinstance(trace_processor, Path) or not isinstance(trace_path, Path):
        raise ContractError("Perfetto count-query paths must be Paths")
    processor_binding = _stable_file_binding(
        trace_processor,
        label="trace processor",
        maximum=MAX_TRACE_PROCESSOR_BYTES,
    )
    trace_binding = bind_perfetto_source_trace(trace_path)
    if expected_source_binding is not None and trace_binding != _require_source_binding(
        expected_source_binding
    ):
        raise ContractError("Perfetto source trace does not match expected binding")
    result = run_with_bounded_stdout(
        [str(trace_processor), "query", str(trace_path), EXPORT_COUNT_SQL],
        maximum_stdout=MAX_COUNT_QUERY_BYTES,
        timeout_seconds=COUNT_QUERY_TIMEOUT_SECONDS,
        label="Perfetto count query",
    )
    if isinstance(result.returncode, bool) or not isinstance(result.returncode, int):
        raise ContractError("trace processor count query status is invalid")
    if result.returncode:
        raise ContractError(
            f"trace processor count query failed with exit code {result.returncode}"
        )
    if (
        _stable_file_binding(
            trace_processor,
            label="trace processor",
            maximum=MAX_TRACE_PROCESSOR_BYTES,
        )
        != processor_binding
        or bind_perfetto_source_trace(trace_path) != trace_binding
    ):
        raise ContractError("Perfetto count-query inputs changed during query")
    try:
        stdout = result.stdout.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        raise ContractError("Perfetto count query returned invalid UTF-8") from None
    try:
        reader = csv.DictReader(io.StringIO(stdout), strict=True)
        rows = list(reader)
    except csv.Error:
        raise ContractError("cannot parse Perfetto count CSV") from None
    if reader.fieldnames != ["events"] or len(rows) != 1 or set(rows[0]) != {"events"}:
        raise ContractError("Perfetto count query returned an invalid result")
    return _integer(rows[0]["events"], "exportable event count")


def _require_valid_perfetto_path_text(path: Path, *, label: str) -> None:
    try:
        rendered_path = str(path)
        rendered_path.encode("utf-8", errors="strict")
    except (UnicodeError, ValueError):
        raise ContractError(f"{label} path is invalid") from None
    if "\x00" in rendered_path or not path.name:
        raise ContractError(f"{label} path is invalid")


def _require_distinct_artifact_paths(
    paths: list[tuple[str, Path]],
) -> None:
    seen: dict[Path, str] = {}
    for label, path in paths:
        _require_valid_perfetto_path_text(path, label=label)
        try:
            resolved = path.resolve()
        except (OSError, ValueError, RuntimeError):
            raise ContractError(f"{label} path is invalid") from None
        previous = seen.get(resolved)
        if previous is not None:
            raise ContractError(
                f"trace export paths must be distinct: {previous} and {label} alias"
            )
        seen[resolved] = label


def _stable_file_binding(
    path: Path,
    *,
    label: str,
    maximum: int | None = None,
) -> dict[str, Any]:
    if not isinstance(path, Path):
        raise ContractError(f"{label} path must be a Path")
    if maximum is None:
        maximum = MAX_PERFETTO_ARTIFACT_BYTES
    if (
        isinstance(maximum, bool)
        or not isinstance(maximum, int)
        or not 1 <= maximum <= MAX_PERFETTO_ARTIFACT_BYTES
    ):
        raise ContractError(f"{label} byte limit is invalid")
    _require_valid_perfetto_path_text(path, label=label)

    def identity(metadata: os.stat_result) -> tuple[int, ...]:
        return (
            metadata.st_dev,
            metadata.st_ino,
            stat.S_IFMT(metadata.st_mode),
            metadata.st_size,
            metadata.st_mtime_ns,
            metadata.st_ctime_ns,
            int(getattr(metadata, "st_file_attributes", 0)),
        )

    try:
        path_before = os.lstat(path)
        if (
            not stat.S_ISREG(path_before.st_mode)
            or int(getattr(path_before, "st_file_attributes", 0)) & 0x400
        ):
            raise ContractError(f"{label} is not a regular file")
        if path_before.st_nlink != 1:
            raise ContractError(f"{label} must not have additional hard links")
        if path_before.st_size > maximum:
            raise ContractError(f"{label} exceeds {maximum} bytes")
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        with os.fdopen(descriptor, "rb") as handle:
            before = os.fstat(handle.fileno())
            if (
                not stat.S_ISREG(before.st_mode)
                or int(getattr(before, "st_file_attributes", 0)) & 0x400
            ):
                raise ContractError(f"{label} is not a regular file")
            if before.st_nlink != 1:
                raise ContractError(f"{label} must not have additional hard links")
            if before.st_size > maximum:
                raise ContractError(f"{label} exceeds {maximum} bytes")
            change_before = windows_change_time(handle) if os.name == "nt" else None
            digest = hashlib.sha256()
            size = 0
            for chunk in iter(
                lambda: handle.read(min(1024 * 1024, maximum + 1 - size)),
                b"",
            ):
                size += len(chunk)
                if size > maximum:
                    raise ContractError(f"{label} exceeds {maximum} bytes")
                digest.update(chunk)
            after = os.fstat(handle.fileno())
            confirmed_size = size
            confirmed_digest = digest
            confirmed_after = after
            change_after = change_before
            if os.name == "nt":
                # Windows st_ctime is creation time on the supported runtime.
                # A same-size edit followed by mtime restoration can evade stat
                # checks, and native change time can retain the same tick.
                handle.seek(0)
                confirmed_size = 0
                confirmed_digest = hashlib.sha256()
                for chunk in iter(
                    lambda: handle.read(min(1024 * 1024, maximum + 1 - confirmed_size)),
                    b"",
                ):
                    confirmed_size += len(chunk)
                    if confirmed_size > maximum:
                        raise ContractError(f"{label} exceeds {maximum} bytes")
                    confirmed_digest.update(chunk)
                confirmed_after = os.fstat(handle.fileno())
                change_after = windows_change_time(handle)
        path_after = os.lstat(path)
    except ContractError:
        raise
    except OSError as exc:
        code = getattr(exc, "winerror", None) or exc.errno
        suffix = f" (os_error={code})" if isinstance(code, int) else ""
        raise ContractError(f"{label} could not be bound{suffix}") from None
    if (
        identity(path_before) != identity(before)
        or identity(before) != identity(after)
        or identity(after) != identity(confirmed_after)
        or identity(confirmed_after) != identity(path_after)
        or size != after.st_size
        or confirmed_size != size
        or confirmed_digest.digest() != digest.digest()
        or confirmed_size != confirmed_after.st_size
        or change_before != change_after
        or confirmed_after.st_nlink != 1
        or path_after.st_nlink != 1
    ):
        raise ContractError(f"{label} changed while its digest was computed")
    return {"bytes": size, "sha256": digest.hexdigest()}


def validate_trace_processor(path: Path) -> dict[str, Any]:
    """Bind a non-empty single-link trace processor before an expensive trial."""
    binding = _stable_file_binding(
        path,
        label="trace processor",
        maximum=MAX_TRACE_PROCESSOR_BYTES,
    )
    if binding["bytes"] <= 0:
        raise ContractError("trace processor is empty")
    return binding


def _publish_temporary_exclusive(
    temporary: Path,
    destination: Path,
    *,
    expected_binding: dict[str, Any],
    expected_parent_ancestry: tuple[DirectoryIdentity, ...] | None = None,
    label: str,
) -> None:
    parent = destination.parent.absolute()
    parent_ancestry = expected_parent_ancestry
    if parent_ancestry is None:
        parent_ancestry = directory_ancestry_binding(parent, label=label)

    def require_publication_parent() -> None:
        if directory_ancestry_binding(parent, label=label) != parent_ancestry:
            raise ContractError(f"{label} parent changed during publication")

    require_publication_parent()
    if _stable_file_binding(temporary, label=f"{label} temporary") != expected_binding:
        raise ContractError(f"{label} temporary changed before publication")
    try:
        source_identity = _owned_file_object_identity(os.lstat(temporary))
    except (ContractError, OSError):
        raise ContractError(f"{label} temporary changed before publication") from None
    require_publication_parent()
    try:
        os.link(temporary, destination, follow_symlinks=False)
    except FileExistsError:
        raise ContractError(f"{label} destination became occupied") from None
    except OSError as exc:
        code = getattr(exc, "winerror", None) or exc.errno
        suffix = f" (os_error={code})" if isinstance(code, int) else ""
        raise ContractError(f"{label} publication failed{suffix}") from None
    try:
        require_publication_parent()
        source_link = os.lstat(temporary)
        destination_link = os.lstat(destination)
        if (
            _file_object_identity(source_link) != source_identity
            or _file_object_identity(destination_link) != source_identity
            or source_link.st_nlink != 2
            or destination_link.st_nlink != 2
        ):
            raise ContractError(f"{label} linked object changed during publication")
        if not _remove_owned_temporary(
            temporary,
            expected_identity=source_identity,
            expected_parent_ancestry=parent_ancestry,
            label=f"{label} temporary",
        ):
            raise ContractError(f"{label} temporary changed during publication")
        require_publication_parent()
        if (
            _stable_file_binding(destination, label=f"{label} destination")
            != expected_binding
        ):
            raise ContractError(f"{label} destination changed during publication")
    except BaseException as exc:
        rollback_failure = False
        try:
            # Only the originally bound temporary object is ours to remove.
            # A post-link lookup may already see a competitor's replacement.
            _remove_owned_temporary(
                destination,
                expected_identity=source_identity,
                expected_parent_ancestry=parent_ancestry,
                label=f"{label} destination",
            )
        except ContractError:
            rollback_failure = True
        if rollback_failure:
            raise ContractError(f"{label} publication rollback failed") from exc
        raise


def _publish_export_report(
    report: dict[str, Any], report_temporary: Path, report_path: Path
) -> dict[str, Any]:
    parent_ancestry = directory_ancestry_binding(
        report_path.parent.absolute(), label="trace export report parent"
    )
    temporary_created = False
    temporary_identity: tuple[int, int, int, int] | None = None
    try:
        if directory_ancestry_binding(
            report_path.parent.absolute(), label="trace export report parent"
        ) != parent_ancestry:
            raise ContractError("trace export report parent changed during publication")
        rendered_report = json.dumps(report, indent=2, sort_keys=True) + "\n"
        expected_bytes = rendered_report.replace("\n", os.linesep).encode("utf-8")
        with report_temporary.open("x", encoding="utf-8") as stream:
            temporary_created = True
            temporary_identity = _owned_file_object_identity(os.fstat(stream.fileno()))
            stream.write(rendered_report)
        binding = _stable_file_binding(
            report_temporary,
            label="trace export report temporary",
            maximum=MAX_TRACE_EXPORT_REPORT_BYTES,
        )
        if binding != {
            "bytes": len(expected_bytes),
            "sha256": hashlib.sha256(expected_bytes).hexdigest(),
        }:
            raise ContractError("trace export report bytes changed during export")
        _publish_temporary_exclusive(
            report_temporary,
            report_path,
            expected_binding=binding,
            expected_parent_ancestry=parent_ancestry,
            label="trace export report",
        )
    except BaseException as exc:
        if temporary_created:
            if temporary_identity is None:
                raise ContractError(
                    "trace export report temporary ownership is unavailable"
                ) from exc
            _remove_owned_temporary(
                report_temporary,
                expected_identity=temporary_identity,
                expected_parent_ancestry=parent_ancestry,
                label="trace export report temporary",
            )
        if isinstance(exc, FileExistsError):
            raise ContractError(
                "trace export report temporary path became occupied"
            ) from None
        raise
    return binding


def export_perfetto(
    trace_processor: Path,
    trace_path: Path,
    output_path: Path,
    run_id: str,
    chromium_revision: str,
    report_path: Path | None = None,
    *,
    maximum_events: int = MAX_EXPORT_EVENTS,
    expected_source_binding: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if (
        not isinstance(trace_processor, Path)
        or not isinstance(trace_path, Path)
        or not isinstance(output_path, Path)
        or (report_path is not None and not isinstance(report_path, Path))
    ):
        raise ContractError("trace export paths must be Paths")
    if not isinstance(run_id, str) or RUN_ID_RE.fullmatch(run_id) is None:
        raise ContractError("export run_id is invalid")
    if (
        not isinstance(chromium_revision, str)
        or REVISION_RE.fullmatch(chromium_revision) is None
    ):
        raise ContractError("export Chromium revision must be 40-hex")
    if (
        isinstance(maximum_events, bool)
        or not isinstance(maximum_events, int)
        or not 1 <= maximum_events <= MAX_EXPORT_EVENTS
    ):
        raise ContractError("trace export event limit is invalid")
    _require_valid_perfetto_path_text(output_path, label="normalized output")
    if report_path is not None:
        _require_valid_perfetto_path_text(report_path, label="report output")
    temporary = output_path.with_suffix(output_path.suffix + ".tmp")
    path_roles = [
        ("trace processor", trace_processor),
        ("source trace", trace_path),
        ("normalized output", output_path),
        ("normalized temporary", temporary),
    ]
    report_temporary = None
    if report_path is not None:
        report_temporary = report_path.with_suffix(report_path.suffix + ".tmp")
        path_roles.extend(
            [
                ("report output", report_path),
                ("report temporary", report_temporary),
            ]
        )
    _require_distinct_artifact_paths(path_roles)
    occupied_temporaries = [
        label for label, path in path_roles if "temporary" in label and path.exists()
    ]
    if occupied_temporaries:
        raise ContractError(
            "trace export temporary path already exists: "
            + ", ".join(occupied_temporaries)
        )
    occupied_outputs = [
        label for label, path in path_roles if "output" in label and path.exists()
    ]
    if occupied_outputs:
        raise ContractError(
            "trace export destination already exists: " + ", ".join(occupied_outputs)
        )
    processor_binding_before = _stable_file_binding(
        trace_processor,
        label="trace processor",
        maximum=MAX_TRACE_PROCESSOR_BYTES,
    )
    source_binding_before = bind_perfetto_source_trace(trace_path)
    if (
        expected_source_binding is not None
        and source_binding_before != _require_source_binding(expected_source_binding)
    ):
        raise ContractError("Perfetto source trace does not match expected binding")
    try:
        prepare_owned_directory_parent(output_path.parent, label="trace export output parent")
        if report_path is not None:
            prepare_owned_directory_parent(report_path.parent, label="trace export report parent")
    except ContractError:
        raise ContractError("trace export destination directory could not be prepared") from None
    output_parent_ancestry = directory_ancestry_binding(
        output_path.parent.absolute(), label="trace export output parent"
    )
    report_parent_ancestry = (
        directory_ancestry_binding(report_path.parent.absolute(), label="trace export report parent")
        if report_path is not None else None
    )

    def require_export_parent(
        path: Path, expected_ancestry: tuple[DirectoryIdentity, ...], *, label: str
    ) -> None:
        if directory_ancestry_binding(path.parent.absolute(), label=label) != expected_ancestry:
            raise ContractError(f"{label} changed during export")

    try:
        process = subprocess.Popen(
            [str(trace_processor), "query", str(trace_path), EXPORT_SQL],
            stdin=subprocess.DEVNULL,
            text=True,
            encoding="utf-8",
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
    except (OSError, ValueError) as exc:
        raise ContractError(
            f"trace processor query could not start ({type(exc).__name__})"
        ) from None
    if process.stdout is None:  # pragma: no cover - guaranteed by PIPE
        _reap_trace_processor(process, kill=True)
        raise ContractError("trace processor query did not expose stdout")
    event_count = 0
    output_bytes = 0
    output_digest = hashlib.sha256()
    encoded_newline = os.linesep.encode("utf-8")
    categories: Counter[str] = Counter()
    temporary_created = False
    temporary_identity: tuple[int, int, int, int] | None = None
    report: dict[str, Any] | None = None
    timed_out = threading.Event()
    watchdog_failures: list[str] = []
    watchdog: threading.Timer | None = None

    def kill_after_deadline() -> None:
        timed_out.set()
        try:
            process.kill()
        except ProcessLookupError:
            return
        except OSError:
            watchdog_failures.append("watchdog-kill")
            try:
                process.stdout.close()
            except (OSError, RuntimeError, ValueError):
                watchdog_failures.append("watchdog-stdout-close")

    try:
        try:
            watchdog = threading.Timer(
                EXPORT_QUERY_TIMEOUT_SECONDS,
                kill_after_deadline,
            )
            watchdog.daemon = True
            watchdog.start()
        except (OSError, RuntimeError, ValueError) as exc:
            raise ContractError(
                f"trace processor watchdog could not start ({type(exc).__name__})"
            ) from None
        # Stream both sides of the conversion. A 201k-event pure-JS trace measured
        # a 718 MB Python allocation peak when stdout and every normalized event
        # remained resident together. Only native-id indexes and the atomic output
        # file now grow with the trace; generated binding rows stay constant-space.
        # Preserve the platform newline behavior of the previous ``write_text``
        # path so existing Windows JSONL digests remain stable.
        require_export_parent(
            output_path, output_parent_ancestry, label="trace export output parent"
        )
        with temporary.open("x", encoding="utf-8") as stream:
            temporary_created = True
            temporary_identity = _owned_file_object_identity(os.fstat(stream.fileno()))
            for event in _iter_normalized_export_rows(
                _iter_export_csv_stream(process.stdout), run_id, chromium_revision
            ):
                rendered = json.dumps(event, sort_keys=True)
                encoded_event = rendered.encode("utf-8")
                output_bytes += len(encoded_event) + len(encoded_newline)
                if output_bytes > MAX_NORMALIZED_TRACE_BYTES:
                    raise ContractError("normalized trace exceeds byte limit")
                stream.write(rendered)
                stream.write("\n")
                output_digest.update(encoded_event)
                output_digest.update(encoded_newline)
                event_count += 1
                if event_count > maximum_events:
                    raise ContractError("trace export event population exceeds limit")
                categories[event["provenance"]["trace_category"]] += 1
        try:
            process.stdout.close()
        except (OSError, RuntimeError, ValueError):
            raise ContractError("trace processor stdout did not close") from None
        returncode = _reap_trace_processor(process, kill=False)
        try:
            watchdog.cancel()
        except (OSError, RuntimeError, ValueError):
            raise ContractError("trace processor watchdog did not cancel") from None
        watchdog = None
        if watchdog_failures:
            phases = ",".join(dict.fromkeys(watchdog_failures))
            raise ContractError(f"trace processor watchdog failed ({phases})")
        if timed_out.is_set():
            raise ContractError("trace processor query timed out")
        if returncode:
            raise ContractError(
                f"trace processor query failed with exit code {returncode}"
            )
        source_binding_after = bind_perfetto_source_trace(trace_path)
        if source_binding_after != source_binding_before:
            raise ContractError("Perfetto source trace changed during export")
        if (
            _stable_file_binding(
                trace_processor,
                label="trace processor",
                maximum=MAX_TRACE_PROCESSOR_BYTES,
            )
            != processor_binding_before
        ):
            raise ContractError("trace processor changed during export")
        report = _build_trace_export_report_from_counts(
            trace_path,
            temporary,
            event_count,
            categories,
            run_id,
            chromium_revision,
        )
        if (
            report["normalized_trace"]["bytes"] != output_bytes
            or report["normalized_trace"]["sha256"] != output_digest.hexdigest()
        ):
            raise ContractError("normalized trace bytes changed during export")
        if report["source_trace"] != {
            "format": "perfetto-trace",
            **source_binding_before,
        }:
            raise ContractError("Perfetto source trace changed before report binding")
    except BaseException as exc:
        cleanup_failures: list[str] = []
        if watchdog is not None:
            try:
                watchdog.cancel()
            except (OSError, RuntimeError, ValueError):
                cleanup_failures.append("watchdog-cancel")
        try:
            process.stdout.close()
        except (OSError, RuntimeError, ValueError):
            cleanup_failures.append("stdout-close")
        try:
            status = process.poll()
            running = (
                status is None
                or isinstance(status, bool)
                or not isinstance(status, int)
            )
        except OSError:
            running = True
        if running:
            try:
                _reap_trace_processor(process, kill=True)
            except ContractError:
                cleanup_failures.append("process-reap")
        if temporary_created:
            if temporary_identity is None:
                cleanup_failures.append("temporary-ownership")
            else:
                try:
                    _remove_owned_temporary(
                        temporary,
                        expected_identity=temporary_identity,
                        expected_parent_ancestry=output_parent_ancestry,
                        label="normalized trace temporary",
                    )
                except ContractError:
                    cleanup_failures.append("temporary-remove")
        cleanup_failures.extend(watchdog_failures)
        if cleanup_failures:
            phases = ",".join(dict.fromkeys(cleanup_failures))
            raise ContractError(f"trace processor cleanup failed ({phases})") from exc
        if isinstance(exc, FileExistsError):
            raise ContractError("trace export temporary path became occupied") from None
        if timed_out.is_set():
            raise ContractError("trace processor query timed out") from None
        raise
    finally:
        if watchdog is not None:
            try:
                watchdog.cancel()
            except (OSError, RuntimeError, ValueError):
                pass
    assert report is not None
    normalized_binding = {
        "bytes": report["normalized_trace"]["bytes"],
        "sha256": report["normalized_trace"]["sha256"],
    }
    source_binding = {
        "bytes": report["source_trace"]["bytes"],
        "sha256": report["source_trace"]["sha256"],
    }
    require_export_parent(
        output_path, output_parent_ancestry, label="trace export output parent"
    )
    _publish_temporary_exclusive(
        temporary,
        output_path,
        expected_binding=normalized_binding,
        expected_parent_ancestry=output_parent_ancestry,
        label="normalized trace",
    )
    report_binding = None
    if report_path is not None:
        assert report_temporary is not None
        try:
            require_export_parent(
                report_path, report_parent_ancestry, label="trace export report parent"
            )
            report_binding = _publish_export_report(
                report, report_temporary, report_path
            )
        except BaseException as exc:
            if temporary_identity is None:
                raise ContractError(
                    "normalized trace rollback ownership is unavailable"
                ) from exc
            try:
                removed = _remove_owned_temporary(
                    output_path,
                    expected_identity=temporary_identity,
                    expected_parent_ancestry=output_parent_ancestry,
                    label="normalized trace output",
                )
            except ContractError:
                raise ContractError("normalized trace rollback failed") from exc
            if not removed:
                raise ContractError(
                    "normalized trace output changed before rollback"
                ) from exc
            raise
    if (
        _stable_file_binding(
            output_path,
            label="normalized trace output",
            maximum=MAX_NORMALIZED_TRACE_BYTES,
        )
        != normalized_binding
    ):
        raise ContractError("normalized trace changed after publication")
    if report_path is not None:
        assert report_binding is not None
        if (
            _stable_file_binding(
                report_path,
                label="trace export report output",
                maximum=MAX_TRACE_EXPORT_REPORT_BYTES,
            )
            != report_binding
        ):
            raise ContractError("trace export report changed after publication")
    if _stable_file_binding(trace_path, label="Perfetto source trace") != source_binding:
        raise ContractError("source trace changed after publication")
    require_export_parent(
        output_path, output_parent_ancestry, label="trace export output parent"
    )
    if report_path is not None:
        require_export_parent(
            report_path, report_parent_ancestry, label="trace export report parent"
        )
    return {
        "events": event_count,
        "output": str(output_path),
        "run_id": run_id,
        "report": report,
        "report_output": str(report_path) if report_path is not None else None,
    }


def build_trace_export_report(
    trace_path: Path,
    output_path: Path,
    events: list[dict[str, Any]],
    run_id: str,
    chromium_revision: str,
) -> dict[str, Any]:
    if not isinstance(trace_path, Path) or not isinstance(output_path, Path):
        raise ContractError("trace export report inputs must be Paths")
    if (
        not isinstance(events, list)
        or not 1 <= len(events) <= MAX_EXPORT_EVENTS
        or any(
            not isinstance(event, dict) or event.get("run_id") != run_id
            for event in events
        )
    ):
        raise ContractError("trace export report events disagree with the run id")
    output_digest = hashlib.sha256()
    output_bytes = 0
    newline = os.linesep.encode("utf-8")
    for event in events:
        validate_trace_event(event)
        rendered = json.dumps(event, sort_keys=True).encode("utf-8")
        output_bytes += len(rendered) + len(newline)
        if output_bytes > MAX_NORMALIZED_TRACE_BYTES:
            raise ContractError("trace export report normalized output exceeds byte limit")
        output_digest.update(rendered)
        output_digest.update(newline)
    if (
        not isinstance(chromium_revision, str)
        or REVISION_RE.fullmatch(chromium_revision) is None
    ):
        raise ContractError("trace export report Chromium revision is invalid")
    if {
        (event.get("provenance") or {}).get("chromium_revision") for event in events
    } != {chromium_revision}:
        raise ContractError(
            "trace export report events disagree with the Chromium revision"
        )
    categories = Counter(
        (event.get("provenance") or {}).get("trace_category") for event in events
    )
    if None in categories:
        raise ContractError(
            "trace export report requires complete trace-category provenance"
        )
    report = _build_trace_export_report_from_counts(
        trace_path,
        output_path,
        len(events),
        categories,
        run_id,
        chromium_revision,
    )
    if (
        report["normalized_trace"]["bytes"] != output_bytes
        or report["normalized_trace"]["sha256"] != output_digest.hexdigest()
    ):
        raise ContractError("trace export report events disagree with normalized output")
    return report


def _build_trace_export_report_from_counts(
    trace_path: Path,
    output_path: Path,
    event_count: int,
    categories: Counter[str],
    run_id: str,
    chromium_revision: str,
) -> dict[str, Any]:
    """Bind an already-validated streaming export without retaining its events."""
    if not isinstance(trace_path, Path) or not isinstance(output_path, Path):
        raise ContractError("trace export report inputs must be Paths")
    if (
        not isinstance(event_count, int)
        or isinstance(event_count, bool)
        or not 1 <= event_count <= MAX_EXPORT_EVENTS
    ):
        raise ContractError("trace export report requires at least one event")
    if not RUN_ID_RE.fullmatch(run_id):
        raise ContractError("trace export report run id is invalid")
    if not REVISION_RE.fullmatch(chromium_revision):
        raise ContractError("trace export report Chromium revision is invalid")
    source_binding = _stable_file_binding(
        trace_path,
        label="Perfetto source trace",
    )
    normalized_binding = _stable_file_binding(
        output_path,
        label="normalized trace",
    )
    report = {
        "schema": TRACE_EXPORT_SCHEMA,
        "run_id": run_id,
        "chromium_revision": chromium_revision,
        "source_trace": {
            "format": "perfetto-trace",
            **source_binding,
        },
        "normalized_trace": {
            "schema": "browser-core.trace-event/1",
            **normalized_binding,
            "events": event_count,
            "trace_categories": dict(sorted(categories.items())),
            "category_provenance": "complete",
        },
    }
    return validate_trace_export_report(report)


def validate_trace_export_report(document: Any) -> dict[str, Any]:
    if (
        not isinstance(document, dict)
        or set(document)
        != {
            "schema",
            "run_id",
            "chromium_revision",
            "source_trace",
            "normalized_trace",
        }
        or document.get("schema") != TRACE_EXPORT_SCHEMA
    ):
        raise ContractError("trace export report structure is invalid")
    if (
        not isinstance(document.get("run_id"), str)
        or RUN_ID_RE.fullmatch(document["run_id"]) is None
    ):
        raise ContractError("trace export report run id is invalid")
    if (
        not isinstance(document.get("chromium_revision"), str)
        or REVISION_RE.fullmatch(document["chromium_revision"]) is None
    ):
        raise ContractError("trace export report Chromium revision is invalid")
    source = document.get("source_trace")
    normalized = document.get("normalized_trace")
    if (
        not isinstance(source, dict)
        or set(source) != {"format", "bytes", "sha256"}
        or source.get("format") != "perfetto-trace"
    ):
        raise ContractError("trace export report source binding is invalid")
    if (
        not isinstance(normalized, dict)
        or set(normalized)
        != {
            "schema",
            "bytes",
            "sha256",
            "events",
            "trace_categories",
            "category_provenance",
        }
        or normalized.get("schema") != "browser-core.trace-event/1"
        or normalized.get("category_provenance") != "complete"
    ):
        raise ContractError("trace export report normalized binding is invalid")
    for label, binding in (("source", source), ("normalized", normalized)):
        size = binding.get("bytes")
        digest = binding.get("sha256")
        maximum = (
            MAX_PERFETTO_ARTIFACT_BYTES
            if label == "source"
            else MAX_NORMALIZED_TRACE_BYTES
        )
        if (
            not isinstance(size, int)
            or isinstance(size, bool)
            or not 1 <= size <= maximum
            or not isinstance(digest, str)
            or len(digest) != 64
            or any(character not in "0123456789abcdef" for character in digest)
        ):
            raise ContractError(
                f"trace export report {label} digest binding is invalid"
            )
    events = normalized.get("events")
    categories = normalized.get("trace_categories")
    if (
        not isinstance(events, int)
        or isinstance(events, bool)
        or not 1 <= events <= MAX_EXPORT_EVENTS
        or not isinstance(categories, dict)
        or not categories
        or set(categories)
        - {
            "browser_core.debug",
            "browser_core.stream",
            "blink.bindings",
            "blink.bindings.encoding",
        }
        or any(
            not isinstance(value, int) or isinstance(value, bool) or value <= 0
            for value in categories.values()
        )
        or sum(categories.values()) != events
    ):
        raise ContractError("trace export report category counts are invalid")
    return document
