"""Read-only, machine-readable capabilities for research agents.

This reports verified package contracts. It never launches a browser, opens a
profile, reads a trace, or turns a declared hook into an observation claim.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from .contracts import ContractError
from .control_files import (
    decode_strict_json_bytes,
    read_bounded_control_snapshot_result,
)
from .inspection_contract import (
    APIS_V1,
    APIS_V2,
    APIS_V3,
    CAPTURE_V1,
    CAPTURE_V2,
    CAPTURE_V3,
    CRYPTO_INPUT_PATCH,
)
from .owned_paths import directory_ancestry_binding
from .runtime_check import check_runtime
from .trace_scopes import TRACE_CATEGORY_CONTRACT, TRACE_SCOPES
from .upstream import (
    MAX_UPSTREAM_MANIFEST_BYTES,
    verified_native_event_routes,
    verified_patch_names,
    verify_patch_series,
    verify_upstream,
)


SCHEMA = "browser-core.agent-capabilities/1"
SCHEMA_V2 = "browser-core.agent-capabilities/2"
MAX_SCHEMA_BYTES = 128 * 1024
MAX_OUTPUT_BYTES = 256 * 1024

_CONTRACTS = (
    ('metadata-query','metadata-query-v1.schema.json','urn:browser-core:metadata-query:1'),
    (
        "agent-capabilities",
        "agent-capabilities-v1.schema.json",
        "urn:browser-core:agent-capabilities:1",
    ),
    (
        "agent-channel-receipt",
        "agent-channel-receipt-v1.schema.json",
        "urn:browser-core:agent-channel-receipt:1",
    ),
    (
        "agent-command",
        "agent-command-v1.schema.json",
        "urn:browser-core:agent-command:1",
    ),
    (
        "agent-process",
        "agent-process-v1.schema.json",
        "urn:browser-core:agent-process:1",
    ),
    (
        "agent-research",
        "agent-research-v1.schema.json",
        "urn:browser-core:agent-research:1",
    ),
    (
        "agent-research-plan",
        "agent-research-plan-v1.schema.json",
        "urn:browser-core:agent-research-plan:1",
    ),
    (
        "evidence-summary",
        "evidence-summary-v1.schema.json",
        "urn:browser-core:evidence-summary:1",
    ),
    (
        "evidence-query",
        "evidence-query-v1.schema.json",
        "urn:browser-core:evidence-query:1",
    ),
    ("session", "session-v1.schema.json", "browser-core.session/1"),
    ("trace-event", "trace-event-v1.schema.json", "browser-core.trace-event/1"),
)

# V1 remains byte-for-byte stable for callers that pin its closed schema. The
# opt-in V2 catalog exposes later read-only metadata interfaces and their exact
# installed schema digests instead of implying that V1 already advertised them.
_CONTRACTS_V2 = _CONTRACTS + (
    (
        "agent-capabilities-v2",
        "agent-capabilities-v2.schema.json",
        "urn:browser-core:agent-capabilities:2",
    ),
    (
        "metadata-query-v2",
        "metadata-query-v2.schema.json",
        "urn:browser-core:metadata-query:2",
    ),
    (
        "metadata-inventory-query",
        "metadata-inventory-query-v1.schema.json",
        "urn:browser-core:metadata-inventory-query:1",
    ),
    (
        "metadata-rows",
        "metadata-rows-v1.schema.json",
        "urn:browser-core:metadata-rows:1",
    ),
    (
        "evidence-stop-timeouts",
        "evidence-stop-timeouts-v1.schema.json",
        "urn:browser-core:evidence-stop-timeouts:1",
    ),
)

_CAPTURES = (
    (CAPTURE_V1, APIS_V1, ("0018-browser-core-native-binding-values.patch",)),
    (
        CAPTURE_V2,
        APIS_V2,
        (
            "0018-browser-core-native-binding-values.patch",
            "0020-browser-core-extended-native-values.patch",
        ),
    ),
    (
        CAPTURE_V3,
        APIS_V3,
        (
            "0018-browser-core-native-binding-values.patch",
            "0020-browser-core-extended-native-values.patch",
            CRYPTO_INPUT_PATCH,
        ),
    ),
)

_RUNTIME_CODES = frozenset(
    {
        "verified",
        "invalid-selection",
        "resources-unavailable",
        "package-mismatch",
        "missing-file",
        "access-unavailable",
        "artifact-mismatch",
        "unverified",
    }
)


def _contract(
    root: Path,
    name: str,
    filename: str,
    identifier: str,
    *,
    validate_schema: bool = False,
) -> dict:
    snapshot = read_bounded_control_snapshot_result(
        root / "schemas" / filename,
        maximum=MAX_SCHEMA_BYTES,
        label="agent capability schema",
        require_single_link=True,
    )
    if snapshot.state != "complete" or snapshot.body is None:
        raise ContractError("agent capability schema is unavailable")
    try:
        document = decode_strict_json_bytes(
            snapshot.body, label="agent capability schema"
        )
    except ContractError:
        raise ContractError("agent capability schema is invalid") from None
    if (
        not isinstance(document, dict)
        or document.get("$schema") != "https://json-schema.org/draft/2020-12/schema"
        or document.get("$id") != identifier
    ):
        raise ContractError("agent capability schema is invalid")
    if validate_schema:
        try:
            from jsonschema import Draft202012Validator
            from jsonschema.exceptions import SchemaError
        except (ImportError, OSError):
            raise ContractError("agent capability schema validator is unavailable") from None
        try:
            Draft202012Validator.check_schema(document)
        except (SchemaError, RecursionError, OverflowError, TypeError, ValueError):
            raise ContractError("agent capability schema is invalid") from None
    final = read_bounded_control_snapshot_result(
        root / "schemas" / filename,
        maximum=MAX_SCHEMA_BYTES,
        label="agent capability schema",
        require_single_link=True,
    )
    if (
        final.state != "complete"
        or final.body != snapshot.body
        or final.identity != snapshot.identity
    ):
        raise ContractError("agent capability schema changed during read")
    return {
        "name": name,
        "bytes": len(snapshot.body),
        "sha256": hashlib.sha256(snapshot.body).hexdigest(),
    }


def _runtime(root: Path, executable: Path | None, package: dict) -> dict:
    if executable is None:
        return {
            "requested": False,
            "runtime_verified": None,
            "code": None,
            "runtime_bundle_sha256": None,
        }
    result = check_runtime(root, executable)
    if not isinstance(result, dict) or result.get("code") not in _RUNTIME_CODES:
        raise ContractError("agent runtime capability check is invalid")
    verified = result.get("runtime_verified") is True
    if verified != (result["code"] == "verified"):
        raise ContractError("agent runtime capability check is invalid")
    digest = None
    if verified:
        runtime = result.get("runtime")
        checked_package = result.get("package")
        if (
            not isinstance(runtime, dict)
            or not isinstance(checked_package, dict)
            or checked_package.get("chromium_revision") != package["chromium_revision"]
            or checked_package.get("patch_series_sha256")
            != package["patch_series_sha256"]
            or checked_package.get("patches") != package["native_patches"]
        ):
            raise ContractError("agent runtime capability binding is invalid")
        digest = runtime.get("runtime_bundle_sha256")
        if (
            not isinstance(digest, str)
            or len(digest) != 64
            or any(character not in "0123456789abcdef" for character in digest)
        ):
            raise ContractError("agent runtime capability binding is invalid")
    return {
        "requested": True,
        "runtime_verified": verified,
        "code": result["code"],
        "runtime_bundle_sha256": digest,
    }


def _interfaces(schema_version: int) -> dict:
    interfaces = {
        'metadata_queries': {
            'available':True, 'input_schema':None,
            'output_schema':'browser-core.metadata-query/1', 'browser_effect':'none',
        },
        'workspace_admission': {
            'available':True, 'input_schema':None,
            'output_schema':'browser-core.workspace-check/1', 'browser_effect':'none',
        },
        'effort_accounting': {
            'available':True, 'input_schema':'browser-core.effort/1',
            'output_schema':'browser-core.effort-summary/1', 'browser_effect':'none',
        },
        "research_control": {
            "available": True,
            "input_schema": "browser-core.agent-command/1",
            "output_schema": "browser-core.agent-research/1",
            "browser_effect": "starts-only-after-explicit-command",
        },
        "direct_process_transport": {
            "available": True,
            "input_schema": "browser-core.agent-command/1",
            "output_schema": "browser-core.agent-process/1",
            "browser_effect": "creator-owned-cooperative-lifetime",
        },
        "runtime_check": {
            "available": True,
            "input_schema": None,
            "output_schema": "browser-core.runtime-check/1",
            "browser_effect": "none-unless-explicit-launch-check",
        },
        "saved_evidence_summary": {
            "available": True,
            "input_schema": None,
            "output_schema": "browser-core.evidence-summary/1",
            "browser_effect": "none",
        },
        "saved_evidence_query": {
            "available": True,
            "input_schema": None,
            "output_schema": "browser-core.evidence-query/1",
            "browser_effect": "none",
        },
        "session_evidence_query": {
            "available": True,
            "input_schema": None,
            "output_schema": "browser-core.evidence-query/1",
            "browser_effect": "none",
        },
        "saved_evidence_research_plan": {
            "available": True,
            "input_schema": None,
            "output_schema": "browser-core.agent-research-plan/1",
            "browser_effect": "none",
        },
        "scoped_trace_queries": {
            "available": True,
            "input_schema": "browser-core.trace-event/1",
            "output_schema": None,
            "browser_effect": "none",
        },
    }
    if schema_version == 2:
        interfaces["saved_evidence_research_plan"]["capture_requirement"] = (
            "supported-private-value-capture"
        )
        interfaces["saved_evidence_stop_timeouts"] = {
            "available": True,
            "input_schema": None,
            "output_schema": "browser-core.evidence-stop-timeouts/1",
            "browser_effect": "none",
        }
        for name, command, output_schema, source_kind, event_rows in (
            (
                "metadata_session_inventory",
                ("trace", "session-inventory"),
                "browser-core.metadata-inventory-query/1",
                "session",
                False,
            ),
            (
                "metadata_evidence_inventory",
                ("trace", "evidence-inventory"),
                "browser-core.metadata-inventory-query/1",
                "immutable-evidence-bundle",
                False,
            ),
            (
                "metadata_session_rows",
                ("trace", "session-rows"),
                "browser-core.metadata-rows/1",
                "session",
                True,
            ),
            (
                "metadata_evidence_rows",
                ("trace", "evidence-rows"),
                "browser-core.metadata-rows/1",
                "immutable-evidence-bundle",
                True,
            ),
        ):
            session = source_kind == "session"
            interfaces[name] = {
                "available": True,
                "input_schema": None,
                "output_schema": output_schema,
                "browser_effect": "none",
                "cli_argv_prefix": list(command),
                "source_kind": source_kind,
                "required_flags": (
                    ["--session", "--expected-run-id"]
                    if session else ["--bundle", "--reader-executable"]
                ),
                "recommended_binding_flags": [] if session else ["--expected-sha256"],
                "selector_flags": [
                    "--api", "--script-id", "--context-kind", "--portable-pid",
                    "--portable-context-id", "--start-ns", "--end-ns",
                ] + (["--limit"] if event_rows else ["--analyst-activity"]),
                "event_rows": event_rows,
                "row_policy": "complete-only" if event_rows else "no-event-rows",
                "capture_requirement": "metadata-only-zero-private-values",
                "full_population_validated": True,
                "identity_and_health_retained": True,
                "private_values_included": False,
                "portable_context_pair_required": True,
                "cursor_flag": "--cursor" if event_rows and not session else None,
                "cursor_is_authority": False,
                "cursor_binding": (
                    "same-verified-bundle-digest-selectors-limit-and-snapshot"
                    if event_rows and not session else None
                ),
                "request_metadata_event": "fetch.request.start" if event_rows else None,
                "max_emitted_json_bytes": 16 * 1024,
                "outer_delivery_verified": False,
            }
    return interfaces


def agent_capabilities(
    root: Path,
    executable: Path | None = None,
    schema_version: int = 1,
    scope: str | None = None,
) -> dict:
    """Describe verified static support and optional runtime compatibility."""
    if not isinstance(root, Path) or not root.is_absolute():
        raise ContractError("agent capability root is invalid")
    if type(schema_version) is not int or schema_version not in (1, 2):
        raise ContractError("agent capability schema version is invalid")
    if scope is None:
        scope = "full" if schema_version == 1 else "metadata"
    if scope not in (("full",) if schema_version == 1 else ("full", "metadata")):
        raise ContractError("agent capability scope is invalid")
    root_ancestry = directory_ancestry_binding(root, label="agent capability root")
    schemas_ancestry = directory_ancestry_binding(
        root / "schemas", label="agent capability schema directory"
    )
    manifest_snapshot = read_bounded_control_snapshot_result(
        root / "upstream.json",
        maximum=MAX_UPSTREAM_MANIFEST_BYTES,
        label="agent capability upstream manifest",
        require_single_link=True,
    )
    if (
        manifest_snapshot.state != "complete"
        or manifest_snapshot.body is None
        or manifest_snapshot.identity is None
    ):
        raise ContractError("agent capability package is unavailable")
    upstream = verify_upstream(root)
    series = verify_patch_series(root)
    patch_names = verified_patch_names(root)
    route_declaration = verified_native_event_routes(root)
    package = {
        "chromium_version": upstream["chromium"]["version"],
        "chromium_revision": upstream["chromium"]["revision"],
        "native_patches": series["patches"],
        "native_postimages": series["postimages"],
        "patch_series_sha256": series["patch_series_sha256"],
    }
    captures = []
    for capture, apis, required in _CAPTURES:
        captures.append(
            {
                "schema": capture["schema"],
                "allowlist": capture["allowlist"],
                "reader_known": True,
                "native_recording_available": all(
                    name in patch_names for name in required
                ),
                "required_patches": list(required),
                "api_count": len(apis),
                "apis": sorted(apis),
            }
        )
    generated_patch = "0039-browser-core-extended-family-observation.patch"
    contracts = _CONTRACTS if schema_version == 1 else _CONTRACTS_V2
    result = {
        "schema": SCHEMA if schema_version == 1 else SCHEMA_V2,
        "status": "ok",
        "package": package,
        "runtime_check": _runtime(root, executable, package),
        "contracts": [
            _contract(
                root, name, filename, identifier,
                validate_schema=schema_version == 2,
            )
            for name, filename, identifier in contracts
        ],
        "interfaces": _interfaces(schema_version),
        "native_observation": {
            "trace_schema": "browser-core.trace-event/1",
            "trace_category_contract": TRACE_CATEGORY_CONTRACT,
            "scopes": [
                {"name": name, "categories": list(categories)}
                for name, categories in TRACE_SCOPES.items()
            ],
            "routes_schema": route_declaration["schema"],
            "routes": route_declaration["routes"],
            "generated_bindings": {
                "available": generated_patch in patch_names,
                "required_patch": generated_patch,
                "categories": ["blink.bindings", "blink.bindings.encoding"],
                "name_population": "build-generated-runtime-observations",
            },
            "compiler_input_identity": {
                "native_recording_available": False,
                "availability_basis": "not-in-native-series",
                "required_scope": "source-identity",
                "algorithm": "sha256-utf16le-compiler-input-v1",
                "maximum_code_units": 262144,
                "unsalted": True,
            },
            "compiler_input_context_identity": {
                "native_recording_available": False,
                "availability_basis": "not-in-native-series",
                "required_scope": "source-context",
                "native_event": "BrowserCore.ScriptSourceContext",
                "algorithm": "sha256-utf16le-compiler-input-v1",
                "maximum_code_units": 262144,
                "unsalted": True,
                "known_candidate_gap": "inspector-injected-isolated-world-scripts",
            },
            "compiler_input_realm_identity": {
                "native_recording_available": False,
                "availability_basis": "not-in-native-series",
                "required_scope": "source-context",
                "native_events": ["BrowserCore.ScriptSourceContext", "BrowserCore.ScriptRun"],
                "match_command": "script-source-realm-match",
                "api_link_basis": "same-v8-context-world-root-script-and-thread",
                "module_run_coverage": "module-root-evaluation-attempt;static-dependencies-not-individual",
                "known_candidate_gap": "inspector-injected-isolated-world-scripts",
            },
        },
        "value_observation": {"captures": captures},
        "semantics": {
            "capability_basis": "verified-package-resources",
            "native_route_is_runtime_observation": False,
            "reader_known_api_is_runtime_observation": False,
            "zero_observations_mean_unsupported": False,
            "client_side_coverage_complete": False,
            "server_side_architecture_observed": False,
            "browser_launched": False,
            "trace_read": False,
            "active_probe": False,
            "private_values_included": False,
        },
    }
    if schema_version == 2:
        result["projection"] = scope
        if scope == "metadata":
            del result["native_observation"]
            del result["value_observation"]
            result["omitted_from_projection"] = [
                "native_observation", "value_observation"
            ]
    try:
        # The CLI pretty-prints every projection. Count its Windows CRLF form
        # and final print newline before reporting a bounded capability result.
        emitted = json.dumps(
            result, indent=2, sort_keys=True, ensure_ascii=True, allow_nan=False
        )
        size = len(emitted.encode("ascii")) + emitted.count("\n") + 2
    except (OverflowError, TypeError, ValueError):
        raise ContractError("agent capability output is invalid") from None
    if size > (16 * 1024 if scope == "metadata" else MAX_OUTPUT_BYTES):
        raise ContractError("agent capability output exceeds byte limit")
    # Each schema was stable at its own validation point. Rebind the advertised
    # digests after the full catalog so an earlier schema cannot change while
    # later resources are read. This is at most 16 bounded 128 KiB snapshots.
    for row, (_name, filename, _identifier) in zip(result["contracts"], contracts):
        final = read_bounded_control_snapshot_result(
            root / "schemas" / filename,
            maximum=MAX_SCHEMA_BYTES,
            label="agent capability schema",
            require_single_link=True,
        )
        if (
            final.state != "complete"
            or final.body is None
            or len(final.body) != row["bytes"]
            or hashlib.sha256(final.body).hexdigest() != row["sha256"]
        ):
            raise ContractError("agent capability schema inventory changed")
    if directory_ancestry_binding(
        root / "schemas", label="agent capability schema directory"
    ) != schemas_ancestry:
        raise ContractError("agent capability schema inventory changed")
    try:
        if (
            directory_ancestry_binding(root, label="agent capability root")
            != root_ancestry
            or verify_patch_series(root) != series
            or verify_upstream(root) != upstream
        ):
            raise ContractError("agent capability package changed")
        current_manifest = read_bounded_control_snapshot_result(
            root / "upstream.json",
            maximum=MAX_UPSTREAM_MANIFEST_BYTES,
            label="agent capability upstream manifest",
            require_single_link=True,
        )
        if (
            current_manifest.state != "complete"
            or current_manifest.body != manifest_snapshot.body
            or current_manifest.identity != manifest_snapshot.identity
            or directory_ancestry_binding(root, label="agent capability root")
            != root_ancestry
        ):
            raise ContractError("agent capability package changed")
    except ContractError:
        raise ContractError("agent capability package changed") from None
    return result
