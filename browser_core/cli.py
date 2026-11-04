from __future__ import annotations

import argparse
import json
import os
import shutil
import stat
import sys
import sysconfig
from pathlib import Path

from .build import create_build_attestation
from .contracts import ContractError, load_session
from .control_files import (
    decode_strict_json_bytes,
    read_bounded_control_snapshot_result,
)
from .lifecycle import session_status, stop_session
from .launcher import EvaluationLaunch, launch_evaluation
from .network_smoke import NetworkGatewaySmoke, run_network_gateway_smoke
from .platform_smoke import ControlPlaneSmoke, run_control_plane_smoke
from .perfetto import export_perfetto
from .profiles import (
    attach_identity_contract,
    attach_network_route,
    attach_persona,
    create_profile,
    list_profiles,
)
from .profile_state import capture_profile_state, list_profile_state_receipts
from .smoke import (
    NativeCanvasSmoke,
    NativeMultiContextSmoke,
    run_native_canvas_smoke,
    run_native_multicontext_smoke,
)
from .stream_calibration import (
    StreamCalibrationTrial,
    run_stream_calibration_trial,
    summarize_stream_scope_runs,
)
from .browser_facts import (
    capture_browser_fact_from_session,
    capture_browser_fact_playwright,
    load_browser_fact_snapshot,
    validate_browser_fact_snapshot,
    write_browser_fact_snapshot,
)
from .evidence_pack import build_evidence_pack, load_evidence_pack_manifest
from .network import list_network_routes
from .proxy_import import (
    SUPPORTED_PROTOCOLS as PROXY_PROTOCOLS,
    check_route,
    delete_proxy_secret,
    describe_route,
    has_proxy_secret,
    import_proxy_file,
    import_proxy_route,
    load_proxy_secret,
    realign_route,
    sticky_session_id,
)
from .worker_coherence import check_worker_realm_coherence
from .argument_capture import (
    argument_corpus,
    compare_hook_fidelity,
    cross_check_realms,
    render_capture,
    render_fidelity,
    render_argument_corpus,
    render_realms,
    subtract_capture,
)
from .product_observation import (
    DOM_PROFILES,
    HOOK_MODES,
    INPUT_PROFILES,
    OBSERVATION_SCHEMA,
    SUBTRACTION_SCHEMA,
    ProductScriptObservation,
    build_surface_baseline,
    build_repeated_surface_baseline,
    check_surface_drift,
    classify_product_script,
    compare_surfaces,
    load_observation,
    run_product_script_observation,
    subtract_control,
    write_observation,
)
from .observation_digest import (
    CONTROL_METHOD_AXES,
    TECHNIQUES,
    UNPARSEABLE_JSON_SCHEMA,
    audit_batch,
    check_absence_claim,
    corpus_matrix,
    diff_digests,
    digest_observation,
    render_claim,
    render_batch_audit,
    render_corpus,
    render_digest,
)
from .script_provenance import describe_provenance, render_provenance, script_pin
from .multi_identity_ops import (
    demonstrate_exclusivity,
    run_multi_identity_batch,
    run_ops_coherence_cohort,
    run_profile_velocity_batch,
)
from .trace import causal_chain, json_lines, summarize, validate_trace, who_read
from .trace_scopes import TRACE_SCOPES
from .upstream import (
    apply_patch_series,
    verify_depot_tools_checkout,
    verify_gclient_config,
    verify_patch_series,
    verify_patched_checkout,
    verify_upstream,
)


def _resource_root() -> Path:
    source_root = Path(__file__).resolve().parents[1]
    if (source_root / "upstream.json").is_file():
        return source_root
    installed_root = Path(sysconfig.get_path("data")) / "browser_core_resources"
    if (installed_root / "upstream.json").is_file():
        return installed_root
    return source_root


ROOT = _resource_root()
MAX_CLI_DOCUMENT_BYTES = 64 * 1024 * 1024
MAX_CLI_SCRIPT_BYTES = 16 * 1024 * 1024
MAX_CLI_POPULATION_FILES = 4096
MAX_CLI_POPULATION_BYTES = 512 * 1024 * 1024
MAX_CLI_STDOUT_BYTES = 64 * 1024 * 1024
_OBSERVATION_POPULATION_SCHEMAS = (OBSERVATION_SCHEMA, SUBTRACTION_SCHEMA)
MAX_PROXY_STDIN_BYTES = 16 * 1024


class _MalformedJsonDocument(ContractError):
    pass


def _file_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        stat.S_IFMT(metadata.st_mode),
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
        int(getattr(metadata, "st_file_attributes", 0)),
    )


def _has_windows_normalized_component(path: Path) -> bool:
    return os.name == "nt" and any(
        component != path.anchor
        and component not in {".", ".."}
        and component.endswith((".", " "))
        for component in path.parts
    )


def _stable_cli_bytes(path: Path, *, maximum: int, label: str) -> bytes:
    if not isinstance(path, Path):
        raise ContractError(f"{label} path must be a Path")
    if _has_windows_normalized_component(path):
        raise ContractError(f"{label} path has an invalid component")
    snapshot = read_bounded_control_snapshot_result(
        path.absolute(),
        maximum=maximum,
        label=label,
    )
    if snapshot.state != "complete" or snapshot.body is None:
        raise ContractError(f"{label} is {snapshot.state}")
    return snapshot.body


def _load_cli_json(path: Path) -> object:
    body = _stable_cli_bytes(
        path,
        maximum=MAX_CLI_DOCUMENT_BYTES,
        label="CLI JSON document",
    )
    try:
        return decode_strict_json_bytes(body, label="JSON document")
    except ContractError as exc:
        message = str(exc)
        if "duplicate key" in message:
            raise _MalformedJsonDocument(
                "JSON document contains a duplicate key"
            ) from None
        if "non-finite" in message:
            raise _MalformedJsonDocument(
                "JSON document contains a non-finite number"
            ) from None
        raise _MalformedJsonDocument("JSON document is not valid UTF-8 JSON") from None


def _relative_population_label(path: Path, directory: Path) -> str:
    return path.relative_to(directory.absolute()).as_posix()


def _bounded_population_paths(
    directory: Path,
    pattern: str,
    *,
    per_file_maximum: int,
    label: str,
    recursive: bool = True,
) -> list[Path]:
    if not isinstance(directory, Path):
        raise ContractError(f"{label} directory must be a Path")
    root = directory.absolute()
    try:
        before = os.lstat(root)
    except OSError as exc:
        raise ContractError(
            f"{label} directory inspection failed ({type(exc).__name__})"
        ) from None
    attributes = int(getattr(before, "st_file_attributes", 0))
    if not stat.S_ISDIR(before.st_mode) or attributes & 0x400:
        raise ContractError(f"{label} is not a regular directory")

    def inventory() -> tuple[list[Path], list[tuple[str, tuple[int, ...]]]]:
        paths: list[Path] = []
        signatures: list[tuple[str, tuple[int, ...]]] = []
        total = 0
        iterator = root.rglob(pattern) if recursive else root.glob(pattern)
        for path in iterator:
            if len(paths) >= MAX_CLI_POPULATION_FILES:
                raise ContractError(f"{label} file population exceeds limit")
            metadata = os.lstat(path)
            path_attributes = int(getattr(metadata, "st_file_attributes", 0))
            if not stat.S_ISREG(metadata.st_mode) or path_attributes & 0x400:
                raise ContractError(f"{label} contains a non-regular file")
            if metadata.st_size > per_file_maximum:
                raise ContractError(f"{label} file exceeds byte limit")
            relative = path.relative_to(root).as_posix()
            try:
                relative_bytes = len(relative.encode("utf-8", errors="strict"))
            except UnicodeEncodeError:
                raise ContractError(f"{label} relative path encoding is invalid") from None
            if relative_bytes > 1024:
                raise ContractError(f"{label} relative path exceeds limit")
            total += metadata.st_size + relative_bytes
            if total > MAX_CLI_POPULATION_BYTES:
                raise ContractError(f"{label} aggregate bytes exceed limit")
            paths.append(path)
            signatures.append((relative, _file_identity(metadata)))
        paired = sorted(
            zip(paths, signatures),
            key=lambda pair: pair[1][0],
        )
        return (
            [path for path, _signature in paired],
            [signature for _path, signature in paired],
        )

    try:
        paths, first_signatures = inventory()
        middle = os.lstat(root)
        _second_paths, second_signatures = inventory()
        after = os.lstat(root)
    except ContractError:
        raise
    except OSError as exc:
        raise ContractError(
            f"{label} inventory failed ({type(exc).__name__})"
        ) from None
    if (
        _file_identity(before) != _file_identity(middle)
        or _file_identity(middle) != _file_identity(after)
        or first_signatures != second_signatures
    ):
        raise ContractError(f"{label} directory changed during inventory")
    return paths


def command_stream_scope_smoke(args: argparse.Namespace) -> int:
    workspace = _required_workspace(args.workspace)
    runs = {
        scope: run_stream_calibration_trial(
            StreamCalibrationTrial(
                executable=args.executable,
                trace_processor=args.trace_processor,
                workspace=workspace,
                trace_mode="on",
                trace_scope=scope,
                reads=args.reads,
                warmup_reads=args.warmup_reads,
                timeout_seconds=args.timeout_seconds,
            ),
            ROOT,
        )
        for scope in ("causal", "causal-stream")
    }
    report = summarize_stream_scope_runs(runs)
    _json(report)
    return 0 if report["passed"] else 1


def _json(value: object) -> None:
    try:
        rendered = json.dumps(
            value,
            indent=2,
            sort_keys=True,
            ensure_ascii=True,
            allow_nan=False,
        )
    except (OverflowError, RecursionError, TypeError, ValueError):
        raise ContractError("CLI output is not strict JSON") from None
    # print adds a final newline, and a Windows text stream can expand every
    # LF to CRLF. Bound the emitted bytes, not just the serialized object.
    emitted = rendered + "\n"
    if len(emitted.encode("ascii")) + emitted.count("\n") > MAX_CLI_STDOUT_BYTES:
        raise ContractError("CLI output exceeds byte limit")
    print(rendered)


def _workspace() -> Path | None:
    raw = os.environ.get("BROWSER_CORE_WORKSPACE", "")
    if not raw.strip():
        return None
    try:
        selected = _explicit_workspace_path(raw)
    except argparse.ArgumentTypeError as exc:
        raise ContractError("workspace environment path is invalid") from exc
    return Path(os.path.abspath(selected))


def _explicit_workspace_path(value: str) -> Path:
    if not value:
        raise argparse.ArgumentTypeError("workspace path is empty")
    path = Path(value)
    if _has_windows_normalized_component(path):
        raise argparse.ArgumentTypeError("workspace path has an invalid component")
    return path


def _required_workspace(value: Path | None = None) -> Path:
    workspace = Path(os.path.abspath(value)) if value is not None else _workspace()
    if workspace is None:
        raise ContractError("set BROWSER_CORE_WORKSPACE or pass --workspace")
    return workspace


def _read_secret_line() -> str:
    """Read one proxy line from stdin.

    Preferred over passing the string as an argument: command lines are visible
    to every other process on the machine and land in shell history, and a
    residential proxy password is worth money.
    """
    raw = sys.stdin.readline(MAX_PROXY_STDIN_BYTES + 1)
    try:
        encoded = raw.encode("utf-8", errors="strict")
    except UnicodeEncodeError:
        raise ContractError("proxy line on stdin encoding is invalid") from None
    if len(encoded) > MAX_PROXY_STDIN_BYTES:
        raise ContractError("proxy line on stdin exceeds byte limit")
    line = raw.strip(" \t\r\n")
    if not line:
        raise ContractError("no proxy line on stdin")
    return line


def _session_preview(args: argparse.Namespace) -> dict[str, object]:
    """Show which sticky session an identity pins, without the username.

    Printing the derived ID alone is enough to confirm two profiles will land on
    different exits; printing the rebuilt username would put the account name on
    the terminal for no extra information.
    """
    workspace = _required_workspace(args.workspace)
    summary = describe_route(workspace, args.route_id)
    if not has_proxy_secret(workspace, args.route_id):
        return {
            "route_id": args.route_id,
            "session_key_supplied": True,
            "sticky_capable": False,
            "reason": "no credential is stored for this route",
        }
    session = load_proxy_secret(workspace, args.route_id)["session"]
    if not summary["sticky_capable"]:
        return {
            "route_id": args.route_id,
            "session_key_supplied": True,
            "sticky_capable": False,
            "reason": f"credential grammar is {session.get('grammar')}; nothing to pin",
        }
    length = int(session.get("session_id_length") or 10)
    return {
        "route_id": args.route_id,
        "session_key_supplied": True,
        "sticky_capable": True,
        "session_id": sticky_session_id(args.session_key, length=length),
        "session_field": session.get("session_key"),
        "session_minutes": session.get("session_minutes"),
    }


def _maybe_write_observation(
    document: dict[str, object], out: Path | None
) -> dict[str, object]:
    if out is not None:
        write_observation(out, document)
    return document


def _emit_digest(document: dict[str, object], *, as_json: bool) -> None:
    """Print a digest as text by default, JSON on request.

    Text is the default because the consumer reads this output directly and the
    whole point of a digest is to cost less context than the artifact it
    summarises; pretty-printed JSON would give back a chunk of what was saved.
    """
    if as_json:
        _json(document)
    else:
        print(render_digest(document))


def _failed_arm_labels(directory: Path) -> list[str]:
    """Return artifact identities with explicit failed-capture receipts."""
    failed = []
    for path in _bounded_population_paths(
        directory,
        "*.json",
        per_file_maximum=MAX_CLI_DOCUMENT_BYTES,
        label="observation population",
    ):
        try:
            document = _load_cli_json(path)
        except _MalformedJsonDocument:
            continue
        if (
            isinstance(document, dict)
            and document.get("schema") in _OBSERVATION_POPULATION_SCHEMAS
            and "error" in document
            and document.get("error") is not None
        ):
            failed.append(_relative_population_label(path, directory))
    return failed


def _warn_failed_arms(directory: Path, *, stream=None) -> list[str]:
    """Surface dead arms wherever a directory is read as a population.

    `observe batch-audit` answers this on demand, but a guard you have to remember
    to run is a guard that gets skipped -- which is exactly how a bisection came to
    report clean negatives from two runs that had produced no data at all. Any
    command that aggregates a directory prints the warning itself.
    """
    failed = _failed_arm_labels(directory)
    if failed:
        print(
            f"# !! {len(failed)} arm(s) in this directory produced NO data "
            f"({', '.join(failed[:5])}{'...' if len(failed) > 5 else ''}). "
            "They are absent from what follows -- an absence computed over a batch "
            "with dead arms is not evidence of absence. See `observe batch-audit`.",
            file=stream,
        )
    return failed


def _emit_corpus(
    directory: Path,
    *,
    group_by: str | None,
    technique: str | None,
    as_json: bool,
    include_raw: bool = False,
    captures_root: Path | None = None,
) -> None:
    """Digest every attributed surface under a directory into one matrix.

    **Attributed surfaces only, by default.** Mixing control-subtracted arms with
    raw ones silently averages collector behaviour together with browser-internal
    work, and the resulting table looks entirely plausible: measured 2026-08-06,
    the mixed corpus reported SBSD `dom-probe` at 121 names against the attributed
    truth of 21. Nothing in the output marked those columns as different kinds of
    evidence.

    `--include-raw` opts back in and labels the groups, because "compare every
    surface I have" is a legitimate question -- it just must not be the default
    answer to "compare my corpus".
    """
    import re as _re

    if not directory.is_dir():
        raise ContractError(f"not a directory: {directory}")
    if group_by is not None and (
        not isinstance(group_by, str) or len(group_by) > 1024
    ):
        raise ContractError("corpus group pattern is invalid")
    try:
        pattern = _re.compile(group_by) if group_by else None
    except _re.error:
        raise ContractError("corpus group pattern is invalid") from None

    attributed: list[tuple[str, dict[str, object]]] = []
    raw: list[tuple[str, dict[str, object]]] = []
    raw_identities: list[str] = []
    group_labels: dict[str, str] = {}
    population = _bounded_population_paths(
        directory,
        "*.json",
        per_file_maximum=MAX_CLI_DOCUMENT_BYTES,
        label="observation corpus",
    )
    failed_arms = []
    unparseable_files = []
    for path in population:
        try:
            document = _load_cli_json(path)
        except _MalformedJsonDocument:
            unparseable_files.append(_relative_population_label(path, directory))
            continue
        if not isinstance(document, dict):
            continue
        schema = document.get("schema")
        if schema not in _OBSERVATION_POPULATION_SCHEMAS:
            continue
        identity = _relative_population_label(path, directory)
        if "error" in document and document.get("error") is not None:
            failed_arms.append(identity)
        human_label = document.get("arm_label") or document.get("label") or path.stem
        if not isinstance(human_label, str) or len(human_label) > 1024:
            human_label = path.stem
        group_labels[identity] = (
            f"RAW:{human_label}" if schema == OBSERVATION_SCHEMA else human_label
        )
        if schema == SUBTRACTION_SCHEMA:
            attributed.append((identity, document))
        else:
            raw.append((identity, document))
            raw_identities.append(identity)

    if include_raw:
        documents = attributed + raw
    else:
        documents = attributed

    if not documents:
        if raw and not include_raw:
            raise ContractError(
                f"found {len(raw)} raw observation(s) under {directory} but no "
                "control-subtracted ones. Raw surfaces are not attributable to the "
                "script; run `observe subtract` first, or pass --include-raw if you "
                "explicitly want an unattributed comparison"
            )
        raise ContractError(
            f"no observation or subtraction documents under {directory}"
        )

    def grouper(label: str) -> str:
        if pattern is None:
            return "all"
        match = pattern.search(group_labels[label])
        return (
            match.group(1)
            if match and match.groups()
            else (match.group(0) if match else "ungrouped")
        )

    matrix = corpus_matrix(documents, group_of=grouper, technique=technique)
    matrix["failed_arms"] = failed_arms
    matrix["unparseable_files"] = unparseable_files
    matrix["raw_observations_excluded"] = [] if include_raw else sorted(raw_identities)
    matrix["trustworthy_population"] = bool(
        not failed_arms
        and not unparseable_files
        and not matrix.get("skipped")
        and not matrix.get("unready_arms")
        and not matrix.get("raw_surfaces_included")
        and (matrix.get("method_population") or {}).get("same_method")
    )

    if captures_root is not None:
        # "How much of what I hold have I actually looked at?" was asked four
        # separate times in one session, each answered by a hand-written glob.
        # A corpus conclusion is only as strong as its denominator, so the
        # denominator belongs in the output next to the conclusion.
        available: set[str] = set()
        for script in _bounded_population_paths(
            Path(captures_root),
            "*/scripts/*.js",
            per_file_maximum=MAX_CLI_SCRIPT_BYTES,
            label="capture script population",
            recursive=False,
        ):
            payload = _stable_cli_bytes(
                script,
                maximum=MAX_CLI_SCRIPT_BYTES,
                label="capture script",
            )
            if classify_product_script(payload)["looks_like_built_antibot_script"]:
                available.add(script_pin(payload))
        observed = set(matrix.get("observed_pins") or [])
        seen = len(available & observed)
        matrix["pin_coverage"] = {
            "available": len(available),
            "observed": seen,
            "unobserved": len(available - observed),
            "percent": round(100 * seen / len(available), 1) if available else 0.0,
        }

    if as_json:
        _json(matrix)
    else:
        print(render_corpus(matrix))


def _emit_claim(directory: Path, technique: str, *, as_json: bool) -> int:
    """Check "the collector does not use <technique>" against a corpus directory.

    Returns 1 for REFUTED and for UNVERIFIABLE, 0 only for SUPPORTED, so a script
    that gates on this cannot mistake "we could not tell" for "we checked".
    """
    if not directory.is_dir():
        raise ContractError(f"not a directory: {directory}")
    documents: list[tuple[str, dict[str, object]]] = []
    for path in _bounded_population_paths(
        directory,
        "*.json",
        per_file_maximum=MAX_CLI_DOCUMENT_BYTES,
        label="observation claim population",
    ):
        try:
            document = _load_cli_json(path)
        except _MalformedJsonDocument:
            documents.append(
                (
                    _relative_population_label(path, directory),
                    {"schema": UNPARSEABLE_JSON_SCHEMA},
                )
            )
            continue
        if not isinstance(document, dict):
            continue
        if document.get("schema") in _OBSERVATION_POPULATION_SCHEMAS:
            documents.append(
                (
                    _relative_population_label(path, directory),
                    document,
                )
            )
    if not documents:
        raise ContractError(f"no observation documents under {directory}")
    result = check_absence_claim(documents, technique)
    if as_json:
        _json(result)
    else:
        print(render_claim(result))
    return 0 if result["verdict"] == "SUPPORTED" else 1


def _emit_provenance(
    script: Path, captures_root: Path, *, asserted_label: str | None, as_json: bool
) -> int:
    """Exit non-zero when origin is UNVERIFIED, so a pipeline cannot ignore it."""
    result = describe_provenance(script, captures_root, asserted_label=asserted_label)
    if as_json:
        _json(result)
    else:
        print(render_provenance(result))
    return 0 if result["verdict"] == "VERIFIED" else 1


def _emit_capture(args: object) -> int:
    """Render argument evidence, refusing to invent it when there is none."""
    document = _load_cli_json(Path(args.observation))  # type: ignore[attr-defined]
    if not isinstance(document, dict):
        raise ContractError("argument capture source must be a JSON object")
    capture = document.get("argument_capture")
    if capture is None:
        mode = document.get("hook_mode", "off")
        raise ContractError(
            f"{args.observation} carries no argument capture (hook_mode={mode!r}). "  # type: ignore[attr-defined]
            "Re-run `observe product-script --hook-mode on` to record arguments; "
            "an observation taken without the instrument has none to show."
        )
    control = getattr(args, "control", None)
    if control is not None:
        control_doc = load_observation(control)
        control_capture = control_doc.get("argument_capture")
        if control_capture is not None and capture.get("status") == "ok":
            capture = subtract_capture(capture, control_capture)
        print(render_capture(capture, limit=args.limit))  # type: ignore[attr-defined]
        print(render_realms(cross_check_realms(capture, document, control_doc)))
    else:
        print(render_capture(capture, limit=args.limit))  # type: ignore[attr-defined]
    # A run whose instrument never installed is not a run that found nothing.
    return 0 if capture.get("status") == "ok" else 1


def _emit_batch_audit(args: object) -> int:
    """Exit non-zero when a batch is not trustworthy as a population."""
    directory = Path(args.directory)  # type: ignore[attr-defined]
    if not directory.is_dir():
        raise ContractError(f"not a directory: {directory}")
    candidates: dict[str, dict[str, object]] = {}
    malformed: dict[str, dict[str, object]] = {}
    for path in _bounded_population_paths(
        directory,
        "*.json",
        per_file_maximum=MAX_CLI_DOCUMENT_BYTES,
        label="batch audit population",
    ):
        try:
            document = _load_cli_json(path)
        except _MalformedJsonDocument:
            malformed[_relative_population_label(path, directory)] = {
                "schema": UNPARSEABLE_JSON_SCHEMA,
            }
            continue
        if not isinstance(document, dict):
            continue
        schema = document.get("schema")
        if schema in _OBSERVATION_POPULATION_SCHEMAS:
            candidates[_relative_population_label(path, directory)] = document
    if not candidates and not malformed:
        raise ContractError(
            f"no observation or subtraction documents under {directory}"
        )
    attributed = {
        label: document
        for label, document in candidates.items()
        if document.get("schema") == SUBTRACTION_SCHEMA
    }
    failed = {
        label: document
        for label, document in candidates.items()
        if "error" in document and document.get("error") is not None
    }
    if attributed:
        # A run directory normally contains raw sample/control intermediates and
        # their derived subtractions. Auditing all of them as one population makes
        # a healthy directory fail on role differences by construction. Prefer
        # attributed evidence, but inject every failed raw arm so failure cannot
        # disappear merely because no subtraction could be produced from it.
        documents = {**attributed, **failed, **malformed}
        population_kind = "attributed_subtractions"
    else:
        documents = {**candidates, **malformed}
        population_kind = "raw_observations" if candidates else "unparseable_files"
    ignored = sorted(set(candidates) - set(documents))
    report = audit_batch(documents)
    report["population_selection"] = {
        "kind": population_kind,
        "selected": len(documents),
        "ignored_successful_intermediates": len(ignored),
        "ignored_labels": ignored,
    }
    if args.json:  # type: ignore[attr-defined]
        _json(report)
    else:
        print(render_batch_audit(report))
    return 0 if report["trustworthy"] else 1


def _emit_argument_corpus(args: object) -> int:
    """Compare argument evidence across every hooked arm in a directory."""
    directory = Path(args.directory)  # type: ignore[attr-defined]
    if not directory.is_dir():
        raise ContractError(f"not a directory: {directory}")
    captures: dict[str, dict[str, object]] = {}
    observations: dict[str, dict[str, object]] = {}
    population = _bounded_population_paths(
        directory,
        "*.json",
        per_file_maximum=MAX_CLI_DOCUMENT_BYTES,
        label="argument corpus population",
    )
    failed_arms: list[str] = []
    unparseable_files: list[str] = []
    for path in population:
        try:
            document = _load_cli_json(path)
        except _MalformedJsonDocument:
            unparseable_files.append(_relative_population_label(path, directory))
            continue
        if not isinstance(document, dict):
            continue
        if document.get("schema") not in _OBSERVATION_POPULATION_SCHEMAS:
            continue
        if "error" in document and document.get("error") is not None:
            failed_arms.append(_relative_population_label(path, directory))
            continue
        capture = document.get("argument_capture")
        if isinstance(capture, dict):
            key = _relative_population_label(path, directory)
            captures[key] = capture
            observations[key] = document
    if not captures:
        raise ContractError(
            f"no observation under {directory} carries an argument capture; "
            "re-run with `--hook-mode on`"
        )
    report = argument_corpus(  # type: ignore[arg-type]
        captures,
        name=args.name,  # type: ignore[attr-defined]
        observations=observations,
    )
    report["failed_arms"] = failed_arms
    report["unparseable_files"] = unparseable_files
    report["trustworthy_population"] = bool(
        not failed_arms
        and not unparseable_files
        and not report.get("excluded_unusable")
        and (report.get("method_population") or {}).get("same_method")
    )
    if args.json:  # type: ignore[attr-defined]
        _json(report)
    else:
        print(render_argument_corpus(report, limit=args.limit))  # type: ignore[attr-defined]
    return 0 if report["trustworthy_population"] else 1


def _emit_fidelity(args: object) -> int:
    """Exit non-zero unless the instrument was shown not to change the sample.

    ``ATTRIBUTION_LOSS`` exits 0 because it is a *proven* benign state, not a
    tolerated one: it is only reached when the sample's raw surface is byte-for-byte
    identical across modes and every missing name is accounted for by the
    instrument's own footprint in the control. The blind spots are printed by name.
    """
    pairs: dict[str, tuple | None] = {"hooked_arms": None, "plain_arms": None}
    for key, arm_attr, control_attr in (
        ("hooked_arms", "hooked_arm", "hooked_control"),
        ("plain_arms", "plain_arm", "plain_control"),
    ):
        arm = getattr(args, arm_attr, None)
        control = getattr(args, control_attr, None)
        if arm and control:
            pairs[key] = (load_observation(arm), load_observation(control))

    report = compare_hook_fidelity(
        load_observation(args.with_hook),  # type: ignore[attr-defined]
        load_observation(args.without_hook),  # type: ignore[attr-defined]
        hooked_arms=pairs["hooked_arms"],
        plain_arms=pairs["plain_arms"],
    )
    if args.out:  # type: ignore[attr-defined]
        write_observation(args.out, report)  # type: ignore[attr-defined]
    if args.json:  # type: ignore[attr-defined]
        _json(report)
    else:
        print(render_fidelity(report))
    return 0 if report["verdict"] in {"TRANSPARENT", "ATTRIBUTION_LOSS"} else 1


def _emit_triage(directory: Path, *, as_json: bool) -> None:
    """Classify every ``.js`` in one directory in a single invocation.

    Triaging a capture directory previously meant one process launch per file
    (measured: 7 launches for one FedEx capture). Capture directories are the
    unit an analyst actually receives, so the directory is the right argument.
    """
    if not directory.is_dir():
        raise ContractError(f"not a directory: {directory}")
    scripts = _bounded_population_paths(
        directory,
        "*.js",
        per_file_maximum=MAX_CLI_SCRIPT_BYTES,
        label="script triage population",
    )
    if not scripts:
        raise ContractError(f"no .js files under {directory}")
    rows = []
    for path in scripts:
        verdict = classify_product_script(
            _stable_cli_bytes(
                path,
                maximum=MAX_CLI_SCRIPT_BYTES,
                label="triage script",
            )
        )
        rows.append(
            {
                "file": path.name,
                "bytes": verdict["signals"]["bytes"],
                "sha256_16": verdict["signals"]["sha256_16"],
                "is_collector": verdict["looks_like_built_antibot_script"],
                "vendor_hint": verdict["vendor_hint"],
                "reasons": verdict["reasons"],
            }
        )
    collectors = [r for r in rows if r["is_collector"]]
    document = {
        "schema": "browser-core.product-script-triage/1",
        "directory": directory.name,
        "scanned": len(rows),
        "collectors": len(collectors),
        "results": rows,
    }
    if as_json:
        _json(document)
        return
    print(f"{directory.name}: {len(rows)} scripts, {len(collectors)} collectors")
    print()
    print(f"{'file':<38}{'bytes':>9}  {'collector':<10}{'vendor':<18}reason")
    print("-" * 100)
    for row in rows:
        mark = "YES" if row["is_collector"] else "no"
        reason = "" if row["is_collector"] else (row["reasons"][:1] or [""])[0]
        print(
            f"{row['file'][:37]:<38}{row['bytes']:>9}  {mark:<10}"
            f"{str(row['vendor_hint'] or ''):<18}{reason[:34]}"
        )
    print("-" * 100)


def _doctor_command(name: str, workspace: Path | None) -> str | None:
    """Find a tool on PATH or in the workspace-local Chromium toolchain."""
    found = shutil.which(name)
    if found or workspace is None or name not in {"gclient", "gn", "autoninja"}:
        return found
    return shutil.which(name, path=str(workspace / "depot_tools"))


def command_doctor(args: argparse.Namespace) -> int:
    if getattr(args,'workspace_check',None) is not None:
        from .workspace_check import check_workspace
        if (not getattr(args,'profile_id',None) or getattr(args,'launch_check',None)
                or getattr(args,'executable',None) or getattr(args,'headless',False)):
            raise ContractError('doctor --workspace-check requires --profile-id and runs separately from runtime checks')
        result=check_workspace(args.workspace_check,ROOT,args.profile_id)
        _json(result)
        return 0 if result['workspace_ready'] else 2
    if getattr(args,'profile_id',None):
        raise ContractError('doctor --profile-id requires --workspace-check')
    launch_out=getattr(args,'launch_check',None)
    headless=bool(getattr(args,'headless',False))
    if launch_out is not None and getattr(args,'executable',None) is None:
        raise ContractError('doctor --launch-check requires --executable')
    if headless and launch_out is None:
        raise ContractError('doctor --headless requires --launch-check')
    if getattr(args, 'executable', None) is not None:
        from .runtime_check import check_runtime, check_runtime_launch
        if launch_out is not None:
            result=check_runtime_launch(ROOT,args.executable,launch_out,headless=headless)
            _json(result)
            if result['code']=='interrupted':
                return 130
            return 0 if result['launch_verified'] else 2
        result = check_runtime(ROOT, args.executable)
        _json(result)
        return 0 if result['runtime_verified'] else 2
    workspace = _workspace()
    workspace_is_separate = bool(
        workspace
        and workspace.is_absolute()
        and ROOT not in workspace.parents
        and workspace != ROOT
        and workspace not in ROOT.parents
    )
    workspace_exists = bool(workspace and workspace.is_dir())
    chromium_source_exists = bool(
        workspace_exists and (workspace / "chromium" / "src").is_dir()
    )
    depot_tools_exists = bool(
        workspace_exists and (workspace / "depot_tools").is_dir()
    )
    checks = {
        name: _doctor_command(name, workspace)
        for name in ("git", "python", "gclient", "gn", "autoninja")
    }
    result = {
        "workspace": str(workspace) if workspace else None,
        "workspace_is_absolute": bool(workspace and workspace.is_absolute()),
        "workspace_outside_repository": workspace_is_separate,
        "workspace_exists": workspace_exists,
        "chromium_source_exists": chromium_source_exists,
        "depot_tools_exists": depot_tools_exists,
        "commands": checks,
        "ready_for_checkout": bool(
            workspace_is_separate
            and checks["git"]
            and checks["python"]
        ),
        "ready_for_build": bool(
            workspace_is_separate
            and workspace_exists
            and chromium_source_exists
            and depot_tools_exists
            and checks["git"]
            and checks["python"]
            and checks["gclient"]
            and checks["gn"]
            and checks["autoninja"]
        ),
    }
    _json(result)
    return 0 if result["ready_for_build"] else 2


def build_parser(*, _parser_class=None) -> argparse.ArgumentParser:
    parser = (_parser_class or argparse.ArgumentParser)(prog="browser-core")
    sub = parser.add_subparsers(dest="command", required=True)
    from .record import add_record_command
    add_record_command(sub, ROOT)
    doctor = sub.add_parser(
        "doctor", help="check build setup, or verify a selected prebuilt browser"
    )
    doctor.add_argument('--executable', type=Path,
                        help='verify this absolute browser path against the installed package; file-only unless --launch-check is given')
    doctor.add_argument('--launch-check',type=Path,metavar='FRESH_DIRECTORY',
                        help='also start and close one owned blank-page browser; retain JSON/session receipts in a new directory outside the package')
    doctor.add_argument('--headless',action='store_true',
                        help='request headless mode for --launch-check; default check uses visible mode')
    doctor.add_argument('--workspace-check',type=Path,
                        help='probe exact workspace write/read/delete and Windows native-path admission; launches nothing')
    doctor.add_argument('--profile-id',help='exact named profile for --workspace-check')
    doctor.set_defaults(func=command_doctor)

    agent = sub.add_parser(
        "agent", help="machine-readable Browser Core interfaces for research agents"
    )
    agent_sub = agent.add_subparsers(dest="agent_command", required=True)
    agent_capability = agent_sub.add_parser(
        "capabilities",
        help="report verified package observation contracts without launching a browser",
    )
    agent_capability.add_argument(
        "--executable",
        type=Path,
        help="also verify that this native browser matches the package; still does not launch it",
    )
    agent_capability.add_argument(
        "--schema-version",
        type=int,
        choices=(1, 2),
        default=1,
        help="capability contract: 1 (default) preserves existing output; 2 discovers bounded metadata inventory and focused rows",
    )
    agent_capability.add_argument(
        "--scope",
        choices=("metadata", "full"),
        help="version 2 defaults to compact metadata discovery; request full for native/value catalogs",
    )

    def run_agent_capabilities(args: argparse.Namespace) -> int:
        from .agent_capabilities import SCHEMA, SCHEMA_V2, agent_capabilities

        schema = SCHEMA if args.schema_version == 1 else SCHEMA_V2
        try:
            result = agent_capabilities(
                ROOT, args.executable, args.schema_version, args.scope
            )
        except (ContractError, OSError):
            _json(
                {
                    "schema": schema,
                    "status": "error",
                    "code": "capabilities-unavailable",
                }
            )
            return 2
        except KeyboardInterrupt:
            _json({"schema": schema, "status": "error", "code": "interrupted"})
            return 130
        _json(result)
        runtime = result["runtime_check"]
        return 0 if not runtime["requested"] or runtime["runtime_verified"] else 2

    agent_capability.set_defaults(func=run_agent_capabilities)

    agent_plan = agent_sub.add_parser(
        "plan",
        help="turn one digest-verified saved evidence bundle into bounded next research actions",
    )
    agent_plan.add_argument("--bundle", type=Path, required=True)
    agent_plan.add_argument("--reader-executable", type=Path, required=True)
    agent_plan.add_argument(
        "--expected-sha256",
        required=True,
        help="trusted whole-bundle digest from the export or collection receipt",
    )

    def run_agent_plan(args: argparse.Namespace) -> int:
        from .agent_plan import SCHEMA, plan_saved_evidence

        try:
            result = plan_saved_evidence(
                args.bundle,
                ROOT,
                args.reader_executable.absolute(),
                expected_sha256=args.expected_sha256,
            )
        except (ContractError, OSError):
            _json({"schema": SCHEMA, "status": "error", "code": "plan-unavailable"})
            return 2
        except KeyboardInterrupt:
            _json({"schema": SCHEMA, "status": "error", "code": "interrupted"})
            return 130
        _json(result)
        return 0

    agent_plan.set_defaults(func=run_agent_plan)

    effort_contract_parser = agent_sub.add_parser('effort-contract', help='discover effort kinds, stages and caller accounting boundaries')
    def run_effort_contract(args):
        from .effort import effort_contract
        _json(effort_contract())
        return 0
    effort_contract_parser.set_defaults(func=run_effort_contract)
    effort = agent_sub.add_parser('effort-summary', help='reconcile caller-recorded operation IDs, nested actions and exact visible bytes')
    effort.add_argument('--ledger',type=Path,required=True)
    effort.add_argument('--operation-limit',type=int)
    effort.add_argument('--visible-byte-limit',type=int)
    def run_effort(args):
        from .effort import summarize_effort
        _json(summarize_effort(args.ledger,operation_limit=args.operation_limit,
                              visible_byte_limit=args.visible_byte_limit))
        return 0
    effort.set_defaults(func=run_effort)

    research = sub.add_parser(
        "research", help="open a saved research profile with live recording and its inspector")
    research.add_argument("profile_id", nargs="?", help="saved profile name; omit to open the profile picker")
    research.add_argument("--workspace", type=_explicit_workspace_path, default=None)
    research.add_argument("--persona-id", help="persona to bind when creating a new profile")
    research.add_argument("--executable", type=Path, help="optional attested browser path")
    research.add_argument("--headless", action="store_true")
    research.add_argument("--inspect-hash-inputs", action="store_true",
                          help="also record bounded fingerprints of copied WebCrypto digest inputs; requires a supporting attested build")
    research.add_argument("--recording-limit-mib", type=int, help="recording budget per file (4-1024 MiB; default 1024); the browser stays open at the total limit")
    research.add_argument("--recording-parts", type=int, help="continue across this many recording files (1-16; at most 4096 MiB total)")
    research.add_argument("--no-open", action="store_true", help="print the inspector address without opening it")
    research.add_argument("--exit-with-browser", action="store_true", help="close the inspector when the browser exits instead of keeping it open for review")
    research.add_argument('--agent-control', action='store_true',
                          help='use bounded JSON start/stop messages on stdin; requires explicit profile, workspace and executable; emits no inspector URL')
    research.add_argument('--metadata-only', action='store_true',
                          help='agent-control only: broad passive metadata recording with all private values off and no inspector')
    research.add_argument('--extra-arg', action='append', default=[],
                          help='agent-control only: repeat explicit authorized browser arguments; managed ownership arguments remain forbidden')

    def run_research(args: argparse.Namespace) -> int:
        if (args.metadata_only or args.extra_arg) and not args.agent_control:
            raise ContractError('--metadata-only and --extra-arg require --agent-control')
        if args.agent_control:
            from .agent_research import run_agent_research
            return run_agent_research(args.workspace, ROOT, args.profile_id,
                executable=args.executable, input_stream=getattr(sys.stdin, 'buffer', None),
                output_stream=sys.stdout, headless=args.headless, persona_id=args.persona_id,
                recording_limit_mib=args.recording_limit_mib, recording_parts=args.recording_parts,
                inspect_hash_inputs=args.inspect_hash_inputs, exit_with_browser=args.exit_with_browser,
                **({'metadata_only':True} if args.metadata_only else {}),
                **({'extra_args':tuple(args.extra_arg)} if args.extra_arg else {}))
        import webbrowser
        from .research import start_research
        if args.profile_id is None:
            from .research_picker import serve_research_picker
            if args.persona_id or args.exit_with_browser:
                raise ContractError('--persona-id and --exit-with-browser require a profile name')
            serve_research_picker(_required_workspace(args.workspace), ROOT,
                                  headless=args.headless, executable=args.executable,
                                  recording_limit_mib=args.recording_limit_mib,
                                  open_browser=not args.no_open,
                                  **({'inspect_hash_inputs':True} if args.inspect_hash_inputs else {}),
                                  **({'recording_parts':args.recording_parts} if args.recording_parts is not None else {}))
            return 0
        with start_research(_required_workspace(args.workspace), ROOT, args.profile_id,
                            persona_id=args.persona_id, headless=args.headless,
                            executable=args.executable,recording_limit_mib=args.recording_limit_mib,
                            **({'inspect_hash_inputs':True} if args.inspect_hash_inputs else {}),
                            **({'recording_parts':args.recording_parts} if args.recording_parts is not None else {})) as run:
            _json({"session_file":str(run.session_path), "inspector_url":run.url,
                   "profile_id":args.profile_id, "created_profile":run.created_profile,
                   "profile_retained_on_exit":True, "stop":"Press Ctrl+C when finished; closing the browser keeps its recording available for review" if not args.exit_with_browser else "Close the research browser or press Ctrl+C"})
            sys.stdout.flush()
            try:
                if not args.no_open:
                    webbrowser.open(run.url)
                run.wait()
                if not args.exit_with_browser:
                    run.finish_browser()
                    _json({"recording_review_available":True,"inspector_url":run.url,
                           "session_file":str(run.session_path),"stop":"Press Ctrl+C when finished reviewing"})
                    sys.stdout.flush()
                    run.wait_for_review()
            except KeyboardInterrupt:
                pass
        _json({"session_file":str(run.session_path), "shutdown":run.stop_receipt,
               "reopen_recording_argv":["python","-m","browser_core","trace","inspect",
                                        "--session",str(run.session_path),"--open"]})
        return 0

    research.set_defaults(func=run_research)

    launch = sub.add_parser(
        "launch-eval",
        help="launch the attested browser and write a session contract for Browser Eval",
    )
    launch.add_argument("--executable", type=Path, required=True)
    launch.add_argument("--workspace", type=_explicit_workspace_path, default=None)
    launch.add_argument("--headless", action="store_true")
    launch.add_argument("--timeout-seconds", type=float, default=30.0)
    launch.add_argument("--extra-arg", action="append", default=[])
    launch.add_argument("--profile-id")
    launch.add_argument("--persona-id")
    launch.add_argument("--network-route-id")
    launch.add_argument("--trace-mode", choices=("on", "off"), default="on")
    launch.add_argument("--live-trace", action="store_true",
                        help="make native observations available while recording continues")
    launch.add_argument("--recording-limit-mib", type=int, help="live recording budget per file (4-1024 MiB; default 1024)")
    launch.add_argument("--recording-parts", type=int, help="continue across 1-16 files, with at most 4096 MiB total")
    launch.add_argument("--inspect-values", action="store_true",
                        help="record selected native browser, graphics, canvas and audio values")
    launch.add_argument("--inspect-hash-inputs", action="store_true",
                        help="include native values and bounded copied WebCrypto input fingerprints; requires a supporting attested build")
    launch.add_argument(
        "--trace-scope",
        choices=tuple(TRACE_SCOPES),
        default="broad",
        help=(
            "causal: script/canvas debug only (stream reader events usually empty); "
            "causal-stream: debug+stream (pays stream cost; see docs/STREAM_OBSERVATION.md); "
            "encoding: debug+generated text-encoding bindings; "
            "broad: debug+stream+both generated-binding categories; "
            "source-identity: opt-in V8 digests; "
            "source-context: opt-in Blink context digests through a separate gate. "
            "Contract: browser-core.trace-categories/8."
        ),
    )
    launch.add_argument(
        "--allow-unverified-executable",
        action="store_true",
        help="explicitly label a stock/external executable as an unverified control",
    )

    def run_launch(args: argparse.Namespace) -> int:
        workspace = _required_workspace(args.workspace)
        path, session_document = launch_evaluation(
            EvaluationLaunch(
                executable=args.executable,
                workspace=workspace,
                headless=args.headless,
                timeout_seconds=args.timeout_seconds,
                extra_args=tuple(args.extra_arg),
                profile_id=args.profile_id,
                persona_id=args.persona_id,
                network_route_id=args.network_route_id,
                trace_mode=args.trace_mode,
                trace_scope=args.trace_scope,
                live_trace=args.live_trace,
                recording_limit_mib=args.recording_limit_mib,
                recording_parts=args.recording_parts,
                inspect_values=args.inspect_values or args.inspect_hash_inputs,
                inspection_allowlist='research-v3' if args.inspect_hash_inputs else 'fingerprint-v2',
                allow_unverified_executable=args.allow_unverified_executable,
            ),
            ROOT,
        )
        _json({"session_file": str(path), "session": session_document})
        return 0

    launch.set_defaults(func=run_launch)

    profile = sub.add_parser(
        "profile",
        help="managed browser profiles (named, disposable, identity/persona/route bound)",
    )
    profile_sub = profile.add_subparsers(dest="profile_command", required=True)
    profile_create = profile_sub.add_parser(
        "create", help="create a named or disposable managed profile"
    )
    profile_create.add_argument("profile_id")
    profile_create.add_argument("--name")
    profile_create.add_argument("--workspace", type=_explicit_workspace_path, default=None)
    profile_create.set_defaults(
        func=lambda args: (
            _json(
                create_profile(
                    _required_workspace(args.workspace), args.profile_id, args.name
                )
            )
            or 0
        )
    )
    profile_list = profile_sub.add_parser(
        "list", help="list managed profiles in the workspace"
    )
    profile_list.add_argument("--workspace", type=_explicit_workspace_path, default=None)
    profile_normalize = profile_sub.add_parser(
        "normalize-format", help="back up and normalize validated legacy profile metadata"
    )
    profile_normalize.add_argument("--workspace", type=_explicit_workspace_path, default=None)
    profile_normalize.add_argument("--apply", action="store_true")

    def run_profile_normalize(args: argparse.Namespace) -> int:
        from .profile_migration import normalize_profile_registry

        _json(normalize_profile_registry(_required_workspace(args.workspace), apply=args.apply))
        return 0

    profile_normalize.set_defaults(func=run_profile_normalize)
    profile_list.set_defaults(
        func=lambda args: (
            _json({"profiles": list_profiles(_required_workspace(args.workspace))}) or 0
        )
    )
    profile_identity = profile_sub.add_parser(
        "attach-identity", help="bind an identity contract to a profile"
    )
    profile_identity.add_argument("profile_id")
    profile_identity.add_argument("contract", type=Path)
    profile_identity.add_argument("--workspace", type=_explicit_workspace_path, default=None)
    profile_identity.set_defaults(
        func=lambda args: (
            _json(
                attach_identity_contract(
                    _required_workspace(args.workspace),
                    args.profile_id,
                    args.contract,
                )
            )
            or 0
        )
    )
    profile_persona = profile_sub.add_parser(
        "attach-persona", help="bind a provenance-verified persona to a profile"
    )
    profile_persona.add_argument("profile_id")
    profile_persona.add_argument("persona_id")
    profile_persona.add_argument("--workspace", type=_explicit_workspace_path, default=None)
    profile_persona.set_defaults(
        func=lambda args: (
            _json(
                attach_persona(
                    _required_workspace(args.workspace),
                    args.profile_id,
                    args.persona_id,
                )
            )
            or 0
        )
    )
    profile_network = profile_sub.add_parser(
        "attach-network",
        help="bind a proxy route to a profile (credentials stay out of records)",
    )
    profile_network.add_argument("profile_id")
    profile_network.add_argument("route_id")
    profile_network.add_argument("--workspace", type=_explicit_workspace_path, default=None)
    profile_network.set_defaults(
        func=lambda args: (
            _json(
                attach_network_route(
                    _required_workspace(args.workspace), args.profile_id, args.route_id
                )
            )
            or 0
        )
    )
    profile_state_digest = profile_sub.add_parser(
        "state-digest",
        help=(
            "publish a redacted, hash-chained state receipt for a stopped named profile"
        ),
    )
    profile_state_digest.add_argument("profile_id")
    profile_state_digest.add_argument("snapshot_id")
    profile_state_digest.add_argument("--workspace", type=_explicit_workspace_path, default=None)
    profile_state_digest.set_defaults(
        func=lambda args: (
            _json(
                capture_profile_state(
                    _required_workspace(args.workspace),
                    args.profile_id,
                    args.snapshot_id,
                )
            )
            or 0
        )
    )
    profile_state_list = profile_sub.add_parser(
        "state-list",
        help="list and verify the redacted state-receipt chain for a named profile",
    )
    profile_state_list.add_argument("profile_id")
    profile_state_list.add_argument("--workspace", type=_explicit_workspace_path, default=None)
    profile_state_list.set_defaults(
        func=lambda args: (
            _json(
                {
                    "profile_id": args.profile_id,
                    "receipts": list_profile_state_receipts(
                        _required_workspace(args.workspace),
                        args.profile_id,
                    ),
                }
            )
            or 0
        )
    )

    network = sub.add_parser(
        "network",
        help="proxy routes from pasted provider strings (credentials never enter a record)",
    )
    network_sub = network.add_subparsers(dest="network_command", required=True)

    network_import = network_sub.add_parser(
        "import",
        help="import one pasted proxy line as a verifiable route",
    )
    network_import.add_argument("route_id", help="ID for the new route")
    network_import.add_argument(
        "line",
        nargs="?",
        default=None,
        help=(
            "proxy string (host:port:user:pass, user:pass@host:port, or a URL). "
            "Omit it to read one line from stdin, which keeps the password out of "
            "your shell history and the process table."
        ),
    )
    network_import.add_argument(
        "--name", default=None, help="human-readable route name"
    )
    network_import.add_argument(
        "--country",
        default=None,
        help="ISO alpha-2 exit country; inferred from the username when the vendor encodes it",
    )
    network_import.add_argument(
        "--locale", default=None, help="override the default locale for the country"
    )
    network_import.add_argument(
        "--timezone",
        default=None,
        help="override the default IANA zone for the country",
    )
    network_import.add_argument(
        "--protocol",
        choices=PROXY_PROTOCOLS,
        default="http",
        help="protocol to assume when the line carries no scheme (default: http)",
    )
    network_import.add_argument(
        "--no-store",
        action="store_true",
        help="do not write the credential; resolve it from the environment instead",
    )
    network_import.add_argument(
        "--overwrite",
        action="store_true",
        help="replace a credential already stored for this route",
    )
    network_import.add_argument(
        "--allow-mismatch",
        action="store_true",
        help="do not require the observed exit country to match the route geography",
    )
    network_import.add_argument("--workspace", type=_explicit_workspace_path, default=None)
    network_import.set_defaults(
        func=lambda args: (
            _json(
                import_proxy_route(
                    _required_workspace(args.workspace),
                    args.line if args.line is not None else _read_secret_line(),
                    route_id=args.route_id,
                    name=args.name,
                    country=args.country,
                    locale=args.locale,
                    timezone_name=args.timezone,
                    default_protocol=args.protocol,
                    store_credentials=not args.no_store,
                    overwrite_secret=bool(args.overwrite),
                    require_alignment=not args.allow_mismatch,
                )
            )
            or 0
        )
    )

    network_import_file = network_sub.add_parser(
        "import-file",
        help="import a provider list, collapsing lines that differ only by session",
    )
    network_import_file.add_argument(
        "path", type=Path, help="provider list, one proxy per line"
    )
    network_import_file.add_argument(
        "--prefix", default="res", help="route ID prefix (default: res)"
    )
    network_import_file.add_argument(
        "--limit", type=int, default=None, help="stop after N lines"
    )
    network_import_file.add_argument(
        "--locale", default=None, help="override the default locale for the country"
    )
    network_import_file.add_argument(
        "--timezone",
        default=None,
        help="override the default IANA zone for the country",
    )
    network_import_file.add_argument(
        "--protocol",
        choices=PROXY_PROTOCOLS,
        default="http",
        help="protocol to assume when lines carry no scheme (default: http)",
    )
    network_import_file.add_argument(
        "--no-store",
        action="store_true",
        help="do not write credentials; resolve them from the environment instead",
    )
    network_import_file.add_argument("--workspace", type=_explicit_workspace_path, default=None)
    network_import_file.set_defaults(
        func=lambda args: (
            _json(
                import_proxy_file(
                    _required_workspace(args.workspace),
                    args.path,
                    prefix=args.prefix,
                    limit=args.limit,
                    locale=args.locale,
                    timezone_name=args.timezone,
                    default_protocol=args.protocol,
                    store_credentials=not args.no_store,
                )
            )
            or 0
        )
    )

    network_list = network_sub.add_parser(
        "list", help="list network routes and their credential state"
    )
    network_list.add_argument("--workspace", type=_explicit_workspace_path, default=None)
    network_list.set_defaults(
        func=lambda args: (
            _json(
                {
                    "routes": [
                        describe_route(_required_workspace(args.workspace), route["id"])
                        for route in list_network_routes(
                            _required_workspace(args.workspace)
                        )
                    ]
                }
            )
            or 0
        )
    )

    network_show = network_sub.add_parser(
        "show", help="describe one route without revealing its credential"
    )
    network_show.add_argument("route_id")
    network_show.add_argument("--workspace", type=_explicit_workspace_path, default=None)
    network_show.set_defaults(
        func=lambda args: (
            _json(describe_route(_required_workspace(args.workspace), args.route_id))
            or 0
        )
    )

    network_check = network_sub.add_parser(
        "check",
        help="preflight a route and report the exit country (never the exit IP)",
    )
    network_check.add_argument("route_id")
    network_check.add_argument(
        "--session-key",
        default=None,
        help="pin a sticky exit for this identity (usually a profile or persona ID)",
    )
    network_check.add_argument(
        "--timeout", type=float, default=20.0, help="seconds (default: 20)"
    )
    network_check.add_argument("--workspace", type=_explicit_workspace_path, default=None)
    network_check.set_defaults(
        func=lambda args: (
            _json(
                check_route(
                    _required_workspace(args.workspace),
                    args.route_id,
                    session_key=args.session_key,
                    timeout_seconds=args.timeout,
                )
            )
            or 0
        )
    )

    network_session = network_sub.add_parser(
        "session",
        help="show the session ID an identity would pin, to confirm two profiles differ",
    )
    network_session.add_argument("route_id")
    network_session.add_argument("session_key", help="profile or persona ID")
    network_session.add_argument("--workspace", type=_explicit_workspace_path, default=None)
    network_session.set_defaults(func=lambda args: (_json(_session_preview(args)) or 0))

    network_align = network_sub.add_parser(
        "align",
        help="write a corrected copy of a route whose declared time zone missed its exit",
    )
    network_align.add_argument("route_id")
    network_align.add_argument(
        "--session-key",
        default=None,
        help="observe through this identity's pinned exit rather than a rotating one",
    )
    network_align.add_argument(
        "--new-route-id", default=None, help="ID for the corrected route"
    )
    network_align.add_argument(
        "--locale", default=None, help="locale for the corrected route"
    )
    network_align.add_argument(
        "--timeout", type=float, default=20.0, help="seconds (default: 20)"
    )
    network_align.add_argument("--workspace", type=_explicit_workspace_path, default=None)
    network_align.set_defaults(
        func=lambda args: (
            _json(
                realign_route(
                    _required_workspace(args.workspace),
                    args.route_id,
                    session_key=args.session_key,
                    new_route_id=args.new_route_id,
                    locale=args.locale,
                    timeout_seconds=args.timeout,
                )
            )
            or 0
        )
    )

    network_forget = network_sub.add_parser(
        "forget",
        help="delete a route's stored credential (the route itself is kept)",
    )
    network_forget.add_argument("route_id")
    network_forget.add_argument("--workspace", type=_explicit_workspace_path, default=None)
    network_forget.set_defaults(
        func=lambda args: (
            _json(
                {
                    "route_id": args.route_id,
                    "deleted": delete_proxy_secret(
                        _required_workspace(args.workspace), args.route_id
                    ),
                }
            )
            or 0
        )
    )

    build = sub.add_parser("build", help="pinned Chromium build provenance")
    build_sub = build.add_subparsers(dest="build_command", required=True)
    build_attest = build_sub.add_parser(
        "attest",
        help="bind launcher/runtime/trace-processor hashes to the pinned revisions",
    )
    build_attest.add_argument("--executable", type=Path, required=True)
    build_attest.add_argument("--workspace", type=_explicit_workspace_path, default=None)
    build_attest.add_argument("--git-executable", type=Path, default=None)
    build_attest.add_argument(
        "--expected-manifest-sha256",
        default=None,
        help="SHA-256 of the upstream.json bytes used to start this build",
    )
    build_attest.set_defaults(
        func=lambda args: (
            _json(
                create_build_attestation(
                    ROOT,
                    _required_workspace(args.workspace),
                    args.executable,
                    expected_manifest_sha256=args.expected_manifest_sha256,
                    git_executable=args.git_executable,
                )
            )
            or 0
        )
    )

    upstream = sub.add_parser("upstream", help="pinned upstream Chromium checkout")
    upstream_sub = upstream.add_subparsers(dest="upstream_command", required=True)
    upstream_verify = upstream_sub.add_parser(
        "verify",
        help="verify the checkout matches the pinned Chromium/depot_tools revisions",
    )
    upstream_verify.add_argument(
        "--expected-manifest-sha256",
        help="require these exact bounded upstream.json bytes before native build work",
    )
    upstream_verify.set_defaults(
        func=lambda args: (
            _json(
                verify_upstream(
                    ROOT, expected_manifest_sha256=args.expected_manifest_sha256
                )
            )
            or 0
        )
    )
    upstream_gclient = upstream_sub.add_parser(
        "verify-gclient",
        help="verify a .gclient file has only the pinned Chromium solution",
    )
    upstream_gclient.add_argument("--config", type=Path, required=True)
    upstream_gclient.add_argument(
        "--expected-manifest-sha256",
        help="require the same upstream.json bytes used by the setup script",
    )
    upstream_gclient.set_defaults(
        func=lambda args: (
            _json(
                verify_gclient_config(
                    args.config,
                    verify_upstream(
                        ROOT,
                        expected_manifest_sha256=args.expected_manifest_sha256,
                    )["chromium"]["repository"],
                )
            )
            or 0
        )
    )
    upstream_depot = upstream_sub.add_parser(
        "verify-depot-tools",
        help="verify pinned depot_tools Git revision and invoked wrappers",
    )
    upstream_depot.add_argument("--checkout", type=Path, required=True)
    upstream_depot.add_argument("--git-executable", type=Path, default=None)
    upstream_depot.add_argument(
        "--expected-manifest-sha256",
        help="require the same upstream.json bytes used by the setup script",
    )
    upstream_depot.set_defaults(
        func=lambda args: (
            _json(
                verify_depot_tools_checkout(
                    args.checkout,
                    verify_upstream(
                        ROOT,
                        expected_manifest_sha256=args.expected_manifest_sha256,
                    )["depot_tools"]["revision"],
                    git_executable=args.git_executable,
                )
            )
            or 0
        )
    )

    patches = sub.add_parser("patches", help="the ordered Chromium patch series")
    patch_sub = patches.add_subparsers(dest="patch_command", required=True)
    patch_verify = patch_sub.add_parser(
        "verify", help="verify patch-series digest and exact patched-source postimages"
    )
    patch_verify.set_defaults(func=lambda _: (_json(verify_patch_series(ROOT)) or 0))
    patch_apply = patch_sub.add_parser(
        "apply", help="apply the ordered patch series to the checkout"
    )
    patch_apply.add_argument("--checkout", type=Path, required=True)
    patch_apply.add_argument("--check", action="store_true")
    patch_apply.set_defaults(
        func=lambda args: (
            _json(apply_patch_series(ROOT, args.checkout, args.check)) or 0
        )
    )
    patch_state = patch_sub.add_parser(
        "state", help="report which patches are currently applied"
    )
    patch_state.add_argument("--checkout", type=Path, required=True)
    patch_state.set_defaults(
        func=lambda args: (
            _json(verify_patched_checkout(ROOT, args.checkout)) or 0
        )
    )

    session = sub.add_parser(
        "session", help="session contract files handed to evaluation automation"
    )
    session_sub = session.add_subparsers(dest="session_command", required=True)
    session_validate = session_sub.add_parser(
        "validate", help="validate a session file against browser-core.session/1"
    )
    session_validate.add_argument("path", type=Path)
    session_validate.set_defaults(
        func=lambda args: (_json(load_session(args.path)) or 0)
    )
    session_status_parser = session_sub.add_parser(
        "status", help="report whether the session's browser process is still alive"
    )
    session_status_parser.add_argument("path", type=Path)
    session_status_parser.set_defaults(
        func=lambda args: (_json(session_status(args.path)) or 0)
    )
    session_stop = session_sub.add_parser(
        "stop",
        help="stop a session by verified identity, preserving the native trace flush",
    )
    session_stop.add_argument("path", type=Path)
    session_stop.add_argument("--timeout-seconds", type=float, default=15.0)
    session_stop.set_defaults(
        func=lambda args: (
            _json(stop_session(args.path, timeout_seconds=args.timeout_seconds)) or 0
        )
    )

    smoke = sub.add_parser("smoke", help="native instrumentation smoke tests")
    smoke_sub = smoke.add_subparsers(dest="smoke_command", required=True)
    smoke_canvas = smoke_sub.add_parser(
        "native-canvas", help="canvas binding events reach the native trace plane"
    )
    smoke_canvas.add_argument("--executable", type=Path, required=True)
    smoke_canvas.add_argument("--trace-processor", type=Path, required=True)
    smoke_canvas.add_argument("--workspace", type=_explicit_workspace_path, default=None)
    smoke_canvas.add_argument("--timeout-seconds", type=float, default=30.0)
    smoke_canvas.set_defaults(
        func=lambda args: (
            _json(
                run_native_canvas_smoke(
                    NativeCanvasSmoke(
                        executable=args.executable,
                        trace_processor=args.trace_processor,
                        workspace=_required_workspace(args.workspace),
                        timeout_seconds=args.timeout_seconds,
                    ),
                    ROOT,
                )
            )
            or 0
        )
    )
    smoke_multicontext = smoke_sub.add_parser(
        "native-multicontext",
        help="main/OOPIF/worker causal vector is emitted deterministically",
    )
    smoke_multicontext.add_argument("--executable", type=Path, required=True)
    smoke_multicontext.add_argument("--trace-processor", type=Path, required=True)
    smoke_multicontext.add_argument("--workspace", type=_explicit_workspace_path, default=None)
    smoke_multicontext.add_argument("--timeout-seconds", type=float, default=45.0)
    smoke_multicontext.set_defaults(
        func=lambda args: (
            _json(
                run_native_multicontext_smoke(
                    NativeMultiContextSmoke(
                        executable=args.executable,
                        trace_processor=args.trace_processor,
                        workspace=_required_workspace(args.workspace),
                        timeout_seconds=args.timeout_seconds,
                    ),
                    ROOT,
                )
            )
            or 0
        )
    )
    smoke_stream_scope = smoke_sub.add_parser(
        "stream-scope-isolation",
        help="stream category stays off unless explicitly opted in",
    )
    smoke_stream_scope.add_argument("--executable", type=Path, required=True)
    smoke_stream_scope.add_argument("--trace-processor", type=Path, required=True)
    smoke_stream_scope.add_argument("--workspace", type=_explicit_workspace_path, default=None)
    smoke_stream_scope.add_argument("--reads", type=int, default=128)
    smoke_stream_scope.add_argument("--warmup-reads", type=int, default=8)
    smoke_stream_scope.add_argument("--timeout-seconds", type=float, default=45.0)
    smoke_stream_scope.set_defaults(func=command_stream_scope_smoke)
    smoke_network = smoke_sub.add_parser(
        "network-gateway",
        help="proxy gateway isolates credentials and fails closed on mismatch",
    )
    smoke_network.add_argument("--executable", type=Path, required=True)
    smoke_network.add_argument("--workspace", type=_explicit_workspace_path, default=None)
    smoke_network.add_argument("--timeout-seconds", type=float, default=45.0)
    smoke_network.set_defaults(
        func=lambda args: (
            _json(
                run_network_gateway_smoke(
                    NetworkGatewaySmoke(
                        executable=args.executable,
                        workspace=_required_workspace(args.workspace),
                        timeout_seconds=args.timeout_seconds,
                    ),
                    ROOT,
                )
            )
            or 0
        )
    )
    smoke_control = smoke_sub.add_parser(
        "control-plane", help="control-plane roles, expiring tokens, and audit chain"
    )
    smoke_control.add_argument("--workspace", type=_explicit_workspace_path, default=None)
    smoke_control.add_argument("--network-route-id", required=True)
    smoke_control.set_defaults(
        func=lambda args: (
            _json(
                run_control_plane_smoke(
                    ControlPlaneSmoke(
                        workspace=_required_workspace(args.workspace),
                        network_route_id=args.network_route_id,
                    ),
                    ROOT,
                )
            )
            or 0
        )
    )

    trace = sub.add_parser(
        "trace", help="portable trace validation, summary, export, and causal queries"
    )
    trace_sub = trace.add_subparsers(dest="trace_command", required=True)
    trace_live = trace_sub.add_parser(
        "live-summary", help="read native API activity while the research browser runs"
    )
    trace_live.add_argument("--session", type=Path, required=True)
    trace_live.add_argument("--limit", type=int, default=100)

    def run_live_summary(args: argparse.Namespace) -> int:
        from .live_trace import live_trace_summary

        _json(live_trace_summary(args.session, ROOT, limit=args.limit))
        return 0

    trace_live.set_defaults(func=run_live_summary)
    inspect_live = trace_sub.add_parser('live-values', help='inspect selected native inputs and results while recording')
    inspect_live.add_argument('--session', type=Path, required=True)
    inspect_live.add_argument('--limit', type=int, default=100)

    def run_live_values(args: argparse.Namespace) -> int:
        from .inspection import live_inspection
        _json(live_inspection(args.session, ROOT, limit=args.limit))
        return 0

    inspect_live.set_defaults(func=run_live_values)
    inspect_panel = trace_sub.add_parser('inspect', help='open a live, saved or recovered recording in a read-only panel')
    inspect_panel.add_argument('--session', type=Path, required=True)
    inspect_panel.add_argument('--open', action='store_true', help='open the local panel in your default browser')
    inspect_panel.add_argument('--reader-executable', type=Path,
                              help='current verified browser build to read a stopped recording when its original installation moved')

    def run_inspector(args: argparse.Namespace) -> int:
        from .inspection_ui import serve_inspector
        serve_inspector(args.session, ROOT, open_browser=args.open,
                        reader_executable=args.reader_executable.absolute() if args.reader_executable else None)
        return 0

    inspect_panel.set_defaults(func=run_inspector)
    evidence_panel = trace_sub.add_parser('evidence', help='reopen a portable evidence bundle without its browser or original session')
    evidence_panel.add_argument('--bundle', type=Path, required=True)
    evidence_panel.add_argument('--reader-executable', type=Path, required=True,
                                help='locally installed, verified Browser Core executable; never taken from the bundle')
    evidence_panel.add_argument('--expected-sha256', help='optional trusted whole-bundle SHA-256 from the export receipt')
    evidence_panel.add_argument('--open', action='store_true')

    def run_evidence(args: argparse.Namespace) -> int:
        from .inspection_ui import serve_evidence
        serve_evidence(args.bundle,ROOT,args.reader_executable.absolute(),open_browser=args.open,
                       expected_sha256=args.expected_sha256)
        return 0

    evidence_panel.set_defaults(func=run_evidence)
    evidence_inventory = trace_sub.add_parser(
        'evidence-summary', help='verified metadata-only inventory of a saved evidence bundle for agents')
    evidence_inventory.add_argument('--bundle', type=Path, required=True)
    evidence_inventory.add_argument('--reader-executable', type=Path, required=True)
    evidence_inventory.add_argument('--expected-sha256', help='trusted whole-bundle digest from a receipt')

    def run_evidence_summary(args: argparse.Namespace) -> int:
        from .evidence_summary import SCHEMA, evidence_summary
        try:
            result = evidence_summary(args.bundle, ROOT, args.reader_executable.absolute(),
                                      expected_sha256=args.expected_sha256)
        except (ContractError, OSError):
            _json({'schema': SCHEMA, 'status': 'error', 'code': 'summary-unavailable'})
            return 2
        except KeyboardInterrupt:
            _json({'schema': SCHEMA, 'status': 'error', 'code': 'interrupted'})
            return 130
        _json(result)
        return 0

    evidence_inventory.set_defaults(func=run_evidence_summary)
    stop_details_parser = trace_sub.add_parser(
        'evidence-stop-timeouts',
        help='bounded producer/instance diagnostics for saved recording stop timeouts')
    stop_details_parser.add_argument('--bundle', type=Path, required=True)
    stop_details_parser.add_argument('--reader-executable', type=Path, required=True)
    stop_details_parser.add_argument('--expected-sha256',
                                     help='trusted whole-bundle digest from a receipt')

    def run_evidence_stop_timeouts(args: argparse.Namespace) -> int:
        from .stop_timeout_details import SCHEMA, evidence_stop_timeouts
        try:
            result = evidence_stop_timeouts(
                args.bundle, ROOT, args.reader_executable.absolute(),
                expected_sha256=args.expected_sha256)
        except (ContractError, OSError):
            _json({'schema': SCHEMA, 'status': 'error',
                   'code': 'stop-timeout-details-unavailable'})
            return 2
        except KeyboardInterrupt:
            _json({'schema': SCHEMA, 'status': 'error', 'code': 'interrupted'})
            return 130
        _json(result)
        return 0

    stop_details_parser.set_defaults(func=run_evidence_stop_timeouts)
    evidence_query_parser = trace_sub.add_parser(
        'evidence-query', help='bounded exact private-evidence query for research agents')
    evidence_query_parser.add_argument('--bundle', type=Path, required=True)
    evidence_query_parser.add_argument('--reader-executable', type=Path, required=True)
    evidence_query_parser.add_argument('--expected-sha256', help='trusted whole-bundle digest from a receipt')
    evidence_query_parser.add_argument('--api', action='append', default=[], help='exact native API name; repeat up to 32 times')
    evidence_query_parser.add_argument('--script-id', default='')
    evidence_query_parser.add_argument('--context-kind', choices=('window', 'worker', 'other'), default='')
    evidence_query_parser.add_argument('--pid')
    evidence_query_parser.add_argument('--context-id')
    evidence_query_parser.add_argument('--realm-id')
    evidence_query_parser.add_argument('--portable-pid',
        help='metadata-only exact recorded process ID; requires --portable-context-id')
    evidence_query_parser.add_argument('--portable-context-id',
        help='metadata-only exact recorded context ID; requires --portable-pid; no realm selection')
    evidence_query_parser.add_argument('--start-ns', default='')
    evidence_query_parser.add_argument('--end-ns', default='')
    evidence_query_parser.add_argument('--cursor')
    evidence_query_parser.add_argument('--limit', type=int, default=50)
    evidence_query_parser.add_argument('--include-values', action='store_true',
                                       help='include validated private parameters/results; default is attribution metadata only')
    evidence_query_parser.add_argument('--analyst-activity', action='append', default=[],
        choices=('browser-control','page-evaluation','source-acquisition'),
        help='requires --metadata-version 2; caller declaration never assigns event ownership')
    evidence_query_parser.add_argument('--metadata-version', type=int, choices=(1, 2), default=1,
        help='metadata-only response contract: 1 (default) preserves v1; 2 includes bounded inventory')

    def run_evidence_query(args: argparse.Namespace) -> int:
        from .evidence_query import SCHEMA, evidence_query
        from .metadata_query import MetadataQueryError
        try:
            scope_values = (args.pid, args.context_id, args.realm_id)
            if any(value is not None for value in scope_values):
                if not all(value is not None for value in scope_values):
                    raise ContractError('evidence query scope requires pid, context-id and realm-id')
                scope = {'pid': args.pid, 'context_id': args.context_id, 'realm_id': args.realm_id}
            else:
                scope = None
            portable_context = None
            if args.portable_pid is not None or args.portable_context_id is not None:
                portable_context = {'pid': args.portable_pid, 'context_id': args.portable_context_id}
            result = evidence_query(
                args.bundle, ROOT, args.reader_executable.absolute(),
                expected_sha256=args.expected_sha256, apis=args.api,
                script_id=args.script_id, context_kind=args.context_kind,
                scope=scope, start_ns=args.start_ns, end_ns=args.end_ns,
                cursor=args.cursor, limit=args.limit, include_values=args.include_values,
                analyst_activity=args.analyst_activity, metadata_version=args.metadata_version,
                portable_context=portable_context)
        except MetadataQueryError as error:
            _json({'schema': SCHEMA, 'status': 'error', 'code': error.code})
            return 2
        except (ContractError, OSError):
            _json({'schema': SCHEMA, 'status': 'error', 'code': 'query-unavailable'})
            return 2
        except KeyboardInterrupt:
            _json({'schema': SCHEMA, 'status': 'error', 'code': 'interrupted'})
            return 130
        _json(result)
        return 0

    evidence_query_parser.set_defaults(func=run_evidence_query)
    session_query_parser = trace_sub.add_parser(
        'session-query', help='bounded exact query over one verified live or stopped research session')
    session_query_parser.add_argument('--session', type=Path, required=True)
    session_query_parser.add_argument('--expected-run-id', required=True,
                                      help='bind the read to the run ID returned by the owning agent process')
    session_query_parser.add_argument('--reader-executable', type=Path,
                                      help='verified compatible reader for a stopped session whose original runtime moved')
    session_query_parser.add_argument('--api', action='append', default=[],
                                      help='exact native API name; repeat up to 32 times')
    session_query_parser.add_argument('--script-id', default='')
    session_query_parser.add_argument('--context-kind', choices=('window', 'worker', 'other'), default='')
    session_query_parser.add_argument('--pid')
    session_query_parser.add_argument('--context-id')
    session_query_parser.add_argument('--realm-id')
    session_query_parser.add_argument('--portable-pid',
        help='metadata-only exact recorded process ID; requires --portable-context-id')
    session_query_parser.add_argument('--portable-context-id',
        help='metadata-only exact recorded context ID; requires --portable-pid; no realm selection')
    session_query_parser.add_argument('--start-ns', default='')
    session_query_parser.add_argument('--end-ns', default='')
    session_query_parser.add_argument('--limit', type=int, default=50)
    session_query_parser.add_argument('--include-values', action='store_true',
                                      help='include validated private parameters/results; default is attribution metadata only')
    session_query_parser.add_argument('--analyst-activity', action='append', default=[],
        choices=('browser-control','page-evaluation','source-acquisition'),
        help='requires --metadata-version 2; caller declaration never assigns event ownership')
    session_query_parser.add_argument('--metadata-version', type=int, choices=(1, 2), default=1,
        help='metadata-only response contract: 1 (default) preserves v1; 2 includes bounded inventory')

    def run_session_query(args: argparse.Namespace) -> int:
        from .evidence_query import SCHEMA
        from .session_query import session_query
        from .metadata_query import MetadataQueryError
        try:
            scope_values = (args.pid, args.context_id, args.realm_id)
            if any(value is not None for value in scope_values):
                if not all(value is not None for value in scope_values):
                    raise ContractError('session query scope requires pid, context-id and realm-id')
                scope = {'pid': args.pid, 'context_id': args.context_id, 'realm_id': args.realm_id}
            else:
                scope = None
            portable_context = None
            if args.portable_pid is not None or args.portable_context_id is not None:
                portable_context = {'pid': args.portable_pid, 'context_id': args.portable_context_id}
            result = session_query(
                args.session.absolute(), ROOT, expected_run_id=args.expected_run_id,
                reader_executable=args.reader_executable.absolute() if args.reader_executable else None,
                apis=args.api, script_id=args.script_id, context_kind=args.context_kind,
                scope=scope, start_ns=args.start_ns, end_ns=args.end_ns,
                limit=args.limit, include_values=args.include_values,
                analyst_activity=args.analyst_activity, metadata_version=args.metadata_version,
                portable_context=portable_context)
        except MetadataQueryError as error:
            _json({'schema': SCHEMA, 'status': 'error', 'code': error.code})
            return 2
        except (ContractError, OSError):
            _json({'schema': SCHEMA, 'status': 'error', 'code': 'query-unavailable'})
            return 2
        except KeyboardInterrupt:
            _json({'schema': SCHEMA, 'status': 'error', 'code': 'interrupted'})
            return 130
        _json(result)
        return 0

    session_query_parser.set_defaults(func=run_session_query)
    from .metadata_inventory_query import add_inventory_commands
    add_inventory_commands(trace_sub, ROOT)
    from .metadata_rows import add_rows_commands
    add_rows_commands(trace_sub, ROOT)
    from .metadata_bookmark import add_bookmark_commands
    add_bookmark_commands(trace_sub, ROOT)
    from .metadata_compare import add_compare_commands
    add_compare_commands(trace_sub, ROOT)
    collect = trace_sub.add_parser('collect', help='save an owned recording, normalized events and a searchable evidence report together')
    collect.add_argument('--session', type=Path, required=True)
    collect.add_argument('--out', type=Path, required=True, help='new output directory; preserves the session capture mode; private sessions contain private values')
    collect.add_argument('--reader-executable', type=Path, help='optional attested reader for a saved recording')

    def run_collect(args: argparse.Namespace) -> int:
        from .collect_evidence import collect_evidence, collection_failure
        try:
            result = collect_evidence(args.session, ROOT, args.out,
                reader_executable=args.reader_executable.absolute() if args.reader_executable else None)
        except (Exception,KeyboardInterrupt) as error:
            _json(getattr(error,'collection_failure_receipt',None) or collection_failure(error))
            return 130 if isinstance(error,KeyboardInterrupt) else 2
        _json(result)
        return 0

    collect.set_defaults(func=run_collect)
    trace_assemble = trace_sub.add_parser('assemble', help='copy a recording or its parts into a new flat Perfetto file')
    trace_assemble.add_argument('--session', type=Path, required=True)
    trace_assemble.add_argument('--output', type=Path, required=True)
    trace_assemble.add_argument('--allow-incomplete', action='store_true', help='explicitly copy a provisional, limited or recovered complete-packet prefix')
    trace_assemble.add_argument('--reader-executable', type=Path)

    def run_assemble(args: argparse.Namespace) -> int:
        from .recording_assembly import assemble_recording
        _json(assemble_recording(args.session,ROOT,args.output,allow_incomplete=args.allow_incomplete,
                                reader_executable=args.reader_executable.absolute() if args.reader_executable else None))
        return 0

    trace_assemble.set_defaults(func=run_assemble)
    trace_validate = trace_sub.add_parser(
        "validate", help="check cross-record invariants JSON Schema cannot express"
    )
    trace_validate.add_argument("path", type=Path)
    trace_validate.set_defaults(
        func=lambda args: (_json(validate_trace(args.path)) or 0)
    )
    from .source_match import add_source_match_command
    add_source_match_command(trace_sub)
    from .script_source_match import add_script_source_match_command
    add_script_source_match_command(trace_sub)
    from .script_source_context_match import add_script_source_context_match_command
    add_script_source_context_match_command(trace_sub)
    from .script_source_realm_match import add_script_source_realm_match_command
    add_script_source_realm_match_command(trace_sub)
    trace_summary = trace_sub.add_parser(
        "summary",
        help="event, callback, Promise, dynamic-code, and category counts",
    )
    trace_summary.add_argument("path", type=Path)
    trace_summary.add_argument(
        "--callback-edge-limit",
        type=int,
        default=64,
        help="include the top 0..1024 callback-to-event edge groups (default: 64)",
    )
    trace_summary.add_argument(
        "--promise-edge-limit",
        type=int,
        default=64,
        help="include the top 0..1024 Promise-to-event edge groups (default: 64)",
    )
    trace_summary.add_argument(
        "--dynamic-code-edge-limit",
        type=int,
        default=64,
        help=(
            "include the top 0..1024 dynamic-code-to-event edge groups "
            "(default: 64)"
        ),
    )
    trace_summary.set_defaults(
        func=lambda args: (
            _json(
                summarize(
                    args.path,
                    callback_edge_limit=args.callback_edge_limit,
                    promise_edge_limit=args.promise_edge_limit,
                    dynamic_code_edge_limit=args.dynamic_code_edge_limit,
                )
            )
            or 0
        )
    )
    trace_report = trace_sub.add_parser(
        "report", help="write a searchable HTML view of a validated native recording"
    )
    trace_report.add_argument("path", type=Path)
    trace_report.add_argument("--out", type=Path, required=True)

    def run_trace_report(args: argparse.Namespace) -> int:
        from .trace_report import research_trace_report

        _json(research_trace_report(args.path, args.out))
        return 0

    trace_report.set_defaults(func=run_trace_report)
    trace_export = trace_sub.add_parser(
        "export-perfetto",
        help="convert a raw Perfetto artifact to JSONL plus a binding receipt",
    )
    trace_export.add_argument("path", type=Path)
    trace_export.add_argument("--trace-processor", type=Path, required=True)
    trace_export.add_argument("--output", type=Path, required=True)
    trace_export.add_argument("--run-id", required=True)
    trace_export.add_argument("--chromium-revision", required=True)
    trace_export.add_argument("--report-output", type=Path)
    trace_export.set_defaults(
        func=lambda args: (
            _json(
                export_perfetto(
                    args.trace_processor,
                    args.path,
                    args.output,
                    args.run_id,
                    args.chromium_revision,
                    args.report_output,
                )
            )
            or 0
        )
    )
    trace_read = trace_sub.add_parser(
        "who-read", help="which execution context read a given signal"
    )
    trace_read.add_argument("path", type=Path)
    trace_read.add_argument("--signal", required=True)
    trace_read.set_defaults(
        func=lambda args: (print(json_lines(who_read(args.path, args.signal))) or 0)
    )
    trace_request = trace_sub.add_parser(
        "caused-request", help="the script-to-fetch causal chain behind one request id"
    )
    trace_request.add_argument("path", type=Path)
    trace_request.add_argument("--request-id", required=True)
    trace_request.set_defaults(
        func=lambda args: (
            print(json_lines(causal_chain(args.path, args.request_id))) or 0
        )
    )

    facts = sub.add_parser(
        "browser-fact",
        help="redaction-safe browser environment facts for offline constructors",
    )
    facts_sub = facts.add_subparsers(dest="facts_command", required=True)
    facts_validate = facts_sub.add_parser(
        "validate", help="integrity and schema validation of a snapshot file"
    )
    facts_validate.add_argument("path", type=Path)
    facts_validate.set_defaults(
        func=lambda args: (_json(load_browser_fact_snapshot(args.path)) or 0)
    )
    facts_capture = facts_sub.add_parser(
        "capture", help="capture facts from a live Playwright browser"
    )
    facts_capture.add_argument("--snapshot-id", required=True)
    facts_capture.add_argument(
        "--engine", choices=("chromium", "firefox", "webkit"), default="chromium"
    )
    facts_capture.add_argument("--locale", default="en-US")
    facts_capture.add_argument("--timezone", default="America/Chicago")
    facts_capture.add_argument("--headed", action="store_true")
    facts_capture.add_argument("--timeout-seconds", type=float, default=30.0)
    facts_capture.add_argument("--output", type=Path, required=True)
    facts_capture.set_defaults(
        func=lambda args: (
            _json(
                {
                    "path": str(
                        write_browser_fact_snapshot(
                            args.output,
                            capture_browser_fact_playwright(
                                snapshot_id=args.snapshot_id,
                                engine=args.engine,
                                locale=args.locale,
                                timezone=args.timezone,
                                headless=not args.headed,
                                timeout_seconds=args.timeout_seconds,
                            ),
                        )
                    ),
                    "snapshot": load_browser_fact_snapshot(args.output),
                }
            )
            or 0
        )
    )
    facts_session = facts_sub.add_parser(
        "capture-session",
        help="capture browser-fact snapshot from an active Browser Core session (B07)",
    )
    facts_session.add_argument("--session", type=Path, required=True)
    facts_session.add_argument("--snapshot-id", required=True)
    facts_session.add_argument("--output", type=Path, required=True)
    facts_session.add_argument("--timeout-seconds", type=float, default=15.0)
    facts_session.set_defaults(
        func=lambda args: (
            _json(
                {
                    "path": str(
                        write_browser_fact_snapshot(
                            args.output,
                            capture_browser_fact_from_session(
                                args.session,
                                snapshot_id=args.snapshot_id,
                                timeout_seconds=args.timeout_seconds,
                            ),
                        )
                    ),
                    "snapshot": load_browser_fact_snapshot(args.output),
                }
            )
            or 0
        )
    )
    facts_worker = facts_sub.add_parser(
        "worker-coherence",
        help=(
            "read identity on the main thread and inside a real worker realm and diff "
            "them - the exact cross-check the observed Akamai BM web collector performs"
        ),
    )
    facts_worker.add_argument("--session", type=Path, required=True)
    facts_worker.add_argument("--timeout-seconds", type=float, default=15.0)
    facts_worker.add_argument(
        "--use-managed-page",
        action="store_true",
        help=(
            "measure on the launcher's managed data: page instead of a loopback "
            "origin; weaker, because SharedWorker is disallowed and userAgentData "
            "is null on an opaque origin"
        ),
    )
    facts_worker.set_defaults(
        func=lambda args: (
            _json(
                result := check_worker_realm_coherence(
                    args.session,
                    timeout_seconds=args.timeout_seconds,
                    use_loopback_page=not args.use_managed_page,
                )
            )
            or (0 if result.get("worker_coherence_claim_ready") is True else 1)
        )
    )

    facts_from_json = facts_sub.add_parser(
        "validate-document", help="validate an already-loaded snapshot document"
    )
    facts_from_json.add_argument("path", type=Path)
    facts_from_json.set_defaults(
        func=lambda args: (
            _json(validate_browser_fact_snapshot(_load_cli_json(args.path))) or 0
        )
    )

    evidence = sub.add_parser(
        "evidence",
        help="redacted evidence packs for downstream intake (no live CDP endpoints)",
    )
    evidence_sub = evidence.add_subparsers(dest="evidence_command", required=True)
    evidence_pack = evidence_sub.add_parser(
        "pack",
        help="write redacted Core evidence pack for WebRE intake (B09)",
    )
    evidence_pack.add_argument("--session", type=Path, required=True)
    evidence_pack.add_argument("--out", type=Path, required=True)
    evidence_pack.add_argument("--browser-fact", type=Path, default=None)
    evidence_pack.add_argument("--transport-fingerprint", type=Path, default=None)
    evidence_pack.add_argument("--http2-fingerprint", type=Path, default=None)
    evidence_pack.add_argument("--http2-evidence", type=Path, default=None)
    evidence_pack.add_argument("--trace-export", type=Path, default=None)
    evidence_pack.add_argument("--trace-jsonl", type=Path, default=None)
    evidence_pack.add_argument(
        "--product-observation",
        type=Path,
        default=None,
        help="bind the product-script pin this evidence was captured against",
    )
    evidence_pack.add_argument(
        "--include-session-copy",
        action="store_true",
        help=(
            "include an allowlisted redacted-session receipt with no raw paths, "
            "operator IDs, managed-target values, or CDP endpoint"
        ),
    )
    evidence_pack.set_defaults(
        func=lambda args: (
            _json(
                build_evidence_pack(
                    session_path=args.session,
                    out_dir=args.out,
                    browser_fact_path=args.browser_fact,
                    transport_fingerprint_path=args.transport_fingerprint,
                    http2_fingerprint_path=args.http2_fingerprint,
                    http2_evidence_path=args.http2_evidence,
                    trace_export_path=args.trace_export,
                    trace_jsonl_path=args.trace_jsonl,
                    product_observation_path=args.product_observation,
                    include_session_copy=args.include_session_copy,
                )
            )
            or 0
        )
    )
    evidence_show = evidence_sub.add_parser(
        "show", help="print an evidence pack manifest"
    )
    evidence_show.add_argument("manifest", type=Path)
    evidence_show.set_defaults(
        func=lambda args: (_json(load_evidence_pack_manifest(args.manifest)) or 0)
    )

    observe = sub.add_parser(
        "observe",
        help=(
            "offline rehost of a saved product script under the native trace plane "
            "(lab replay of a stored artifact; never a live product session)"
        ),
    )
    observe_sub = observe.add_subparsers(dest="observe_command", required=True)

    observe_identity = observe_sub.add_parser(
        "script-identity",
        help="structural check that a file really is a built anti-bot script",
    )
    observe_identity.add_argument("script", type=Path)
    observe_identity.set_defaults(
        func=lambda args: (
            _json(
                classify_product_script(
                    _stable_cli_bytes(
                        args.script,
                        maximum=MAX_CLI_SCRIPT_BYTES,
                        label="product script identity input",
                    )
                )
            )
            or 0
        )
    )

    observe_run = observe_sub.add_parser(
        "product-script",
        help="rehost ONE saved script offline and report its native API surface. "
        "For several scripts sharing one control arm (the usual case, and the only "
        "way a subtraction is comparable across them) use "
        "`scripts/run_product_script_observation.py`, which drives control + arms + "
        "subtraction + comparison in a single command",
    )
    observe_run.add_argument("--script", type=Path, required=True)
    observe_run.add_argument("--label", required=True)
    observe_run.add_argument("--executable", type=Path, required=True)
    observe_run.add_argument("--trace-processor", type=Path, required=True)
    observe_run.add_argument("--workspace", type=_explicit_workspace_path, default=None)
    observe_run.add_argument("--out", type=Path, required=True)
    observe_run.add_argument("--dwell-seconds", type=float, default=20.0)
    observe_run.add_argument(
        "--trace-scope", choices=tuple(TRACE_SCOPES), default="broad"
    )
    observe_run.add_argument(
        "--headless",
        action="store_true",
        help="use headless launch (default is headed, matching identity work)",
    )
    observe_run.add_argument(
        "--dom-profile",
        choices=tuple(sorted(DOM_PROFILES)),
        default="minimal",
        help=(
            "host document richness; run both to check a result is a property of the "
            "script rather than of the test page"
        ),
    )
    observe_run.add_argument(
        "--script-path",
        default="/product-script.js",
        help=(
            "path the sample is served from; the collector reads its own script src, "
            "so this can mirror a real deployment's path"
        ),
    )
    observe_run.add_argument(
        "--reloads",
        type=int,
        default=0,
        help=(
            "extra page loads after the first, each with its own dwell; the script "
            "then sees cookies and storage it set itself, so warm-state observation "
            "needs no fabricated session material"
        ),
    )
    observe_run.set_defaults(
        func=lambda args: (
            _json(
                {
                    "path": str(
                        write_observation(
                            args.out,
                            run_product_script_observation(
                                ProductScriptObservation(
                                    script=args.script,
                                    label=args.label,
                                    executable=args.executable,
                                    trace_processor=args.trace_processor,
                                    workspace=_required_workspace(args.workspace),
                                    dwell_seconds=args.dwell_seconds,
                                    trace_scope=args.trace_scope,
                                    headed=not args.headless,
                                    dom_profile=args.dom_profile,
                                    script_path=args.script_path,
                                    captures_root=args.captures_root,
                                    hook_mode=args.hook_mode,
                                    input_profile=args.input_profile,
                                    reloads=args.reloads,
                                    capture_resource_intents=args.capture_resource_intents,
                                ),
                                ROOT,
                            ),
                        )
                    )
                }
            )
            or 0
        )
    )

    observe_run.add_argument(
        "--captures-root",
        type=Path,
        default=None,
        help="capture tree used to resolve where the sample actually came from; "
        "binds a provenance verdict into the observation so the label cannot "
        "travel downstream unchecked",
    )
    observe_run.add_argument(
        "--hook-mode",
        choices=tuple(HOOK_MODES),
        default="off",
        help=(
            "active argument instrumentation. 'off' (default) leaves the page "
            "byte-identical to every archived arm. 'on' wraps built-ins before the "
            "sample runs and records the ARGUMENTS it passes -- which event types it "
            "binds, which WebGL enums it reads -- so a name becomes a finding. "
            "'inert' adds the script tag without the wrappers and exists so "
            "`observe validate-hook` can separate the tag's effect from the "
            "wrappers'. Always validate before trusting argument evidence"
        ),
    )

    observe_run.add_argument(
        "--input-profile",
        choices=tuple(INPUT_PROFILES),
        default="none",
        help=(
            "deliver TRUSTED mouse and key events through CDP during the dwell. "
            "'none' (default) leaves the run as every archived arm was taken. "
            "'probe' fires the collector's bound listeners so that 'registration is "
            "not collection' becomes testable -- measured, it adds MouseEvent "
            "isTrusted/pageX/pageY/toElement and Document.activeElement. A fixed "
            "straight-line pattern: a measurement probe, NOT a behaviour model"
        ),
    )
    observe_run.add_argument(
        "--no-resource-intents",
        action="store_false",
        dest="capture_resource_intents",
        help=(
            "disable the passive redacted CDP DOM resource inventory; use only for "
            "an observer-effect control arm"
        ),
    )

    observe_capture = observe_sub.add_parser(
        "capture",
        help="render the argument evidence recorded in an observation run with "
        "--hook-mode on: which event types were bound, which selectors queried, "
        "which WebGL enums read. Reports what the collector asked for, never what "
        "this host answered",
    )
    observe_capture.add_argument("observation", type=Path)
    observe_capture.add_argument(
        "--control",
        type=Path,
        default=None,
        help="control observation from the same batch. Adds a realm cross-check: "
        "the hook runs in the main frame only while the trace sees every realm, so "
        "the difference per name localises work to a worker. This is how the "
        "collector's 62 extension probes were placed inside its SharedWorker",
    )
    observe_capture.add_argument(
        "--limit",
        type=int,
        default=12,
        help="distinct values shown per name before truncating (default 12)",
    )
    observe_capture.set_defaults(func=_emit_capture)

    observe_audit = observe_sub.add_parser(
        "batch-audit",
        help="is this run directory trustworthy as a population? Reports how many "
        "arms produced no data at all, groups the failures by cause, and flags "
        "comparability axes the arms disagree on (launch mode, hook mode, input "
        "profile, viewport). Exits 1 unless every arm produced data and all agree. "
        "Run this BEFORE reading conclusions out of a batch: a negative result "
        "computed over arms that failed is not a negative result",
    )
    observe_audit.add_argument("directory", type=Path)
    observe_audit.add_argument("--json", action="store_true")
    observe_audit.set_defaults(func=_emit_batch_audit)

    observe_arg_corpus = observe_sub.add_parser(
        "arg-corpus",
        help="compare ARGUMENT evidence across every hooked arm in a directory, the "
        "way `corpus` compares surfaces. Separates values carried by every arm (a "
        "builder constant) from values on only some (roll churn or a real "
        "per-deployment difference)",
    )
    observe_arg_corpus.add_argument("directory", type=Path)
    observe_arg_corpus.add_argument(
        "--name",
        default=None,
        help="focus one instrumented name, e.g. EventTarget.addEventListener",
    )
    observe_arg_corpus.add_argument("--limit", type=int, default=8)
    observe_arg_corpus.add_argument("--json", action="store_true")
    observe_arg_corpus.set_defaults(func=_emit_argument_corpus)

    observe_validate = observe_sub.add_parser(
        "validate-hook",
        help="did the argument instrument change what the sample did? Compares two "
        "control subtractions of the SAME script -- one arm hooked, one inert -- "
        "using the passive native trace as an independent oracle. Exits 1 unless "
        "the verdict is TRANSPARENT, because argument evidence from a perturbed run "
        "describes the instrumented browser rather than the collector",
    )
    observe_validate.add_argument("--with-hook", type=Path, required=True)
    observe_validate.add_argument("--without-hook", type=Path, required=True)
    for _flag, _help in (
        ("--hooked-arm", "raw arm observation from the hooked run"),
        ("--hooked-control", "raw control observation from the hooked run"),
        ("--plain-arm", "raw arm observation from the inert run"),
        ("--plain-control", "raw control observation from the inert run"),
    ):
        observe_validate.add_argument(
            _flag,
            type=Path,
            default=None,
            help=(
                f"{_help}. Supplying all four raw observations lets a surface "
                "difference be traced to the sample or to the instrument's own "
                "footprint in the control -- the difference between a broken "
                "instrument and a named blind spot. Without them the verdict stays "
                "conservative"
            ),
        )
    observe_validate.add_argument("--out", type=Path, default=None)
    observe_validate.add_argument(
        "--json", action="store_true", help="emit the report document instead of text"
    )
    observe_validate.set_defaults(func=_emit_fidelity)

    observe_subtract = observe_sub.add_parser(
        "subtract",
        help="attribute an arm's API surface by subtracting an empty-script control",
    )
    observe_subtract.add_argument("--arm", type=Path, required=True)
    observe_subtract.add_argument("--control", type=Path, required=True)
    observe_subtract.add_argument("--out", type=Path, default=None)
    observe_subtract.set_defaults(
        func=lambda args: (
            _json(
                _maybe_write_observation(
                    subtract_control(
                        load_observation(args.arm), load_observation(args.control)
                    ),
                    args.out,
                )
            )
            or 0
        )
    )

    observe_baseline = observe_sub.add_parser(
        "baseline",
        help="freeze a control-subtracted surface so later runs can be checked against it",
    )
    observe_baseline.add_argument("--subtraction", type=Path, required=True)
    observe_baseline.add_argument("--label", default=None)
    observe_baseline.add_argument("--out", type=Path, required=True)
    observe_baseline.set_defaults(
        func=lambda args: (
            _json(
                _maybe_write_observation(
                    build_surface_baseline(
                        load_observation(args.subtraction), label=args.label
                    ),
                    args.out,
                )
            )
            or 0
        )
    )

    observe_baseline_repeats = observe_sub.add_parser(
        "baseline-repeats",
        help=(
            "freeze a surface from N arms of the same script and measure its own "
            "noise floor; the drift gate's stability premise is vendor-specific"
        ),
    )
    observe_baseline_repeats.add_argument(
        "--subtraction",
        type=Path,
        action="append",
        required=True,
        help="repeat per arm; at least two are needed to measure a floor",
    )
    observe_baseline_repeats.add_argument("--label", default=None)
    observe_baseline_repeats.add_argument("--out", type=Path, required=True)
    observe_baseline_repeats.set_defaults(
        func=lambda args: (
            _json(
                _maybe_write_observation(
                    build_repeated_surface_baseline(
                        [load_observation(path) for path in args.subtraction],
                        label=args.label,
                    ),
                    args.out,
                )
            )
            or 0
        )
    )

    observe_check = observe_sub.add_parser(
        "check",
        help=(
            "fail when the collector surface drifts from a frozen baseline "
            "(exit 1 on drift); the collector is roll-stable, so movement is signal"
        ),
    )
    observe_check.add_argument("--subtraction", type=Path, required=True)
    observe_check.add_argument("--baseline", type=Path, required=True)
    observe_check.add_argument(
        "--tolerance",
        type=int,
        default=None,
        help=(
            "added-or-removed names allowed before failing. Omitted, a baseline "
            "built from repeats supplies its own measured floor; a single-arm "
            "baseline has none and says so rather than defaulting to zero"
        ),
    )
    observe_check.add_argument("--out", type=Path, default=None)
    observe_check.set_defaults(
        func=lambda args: (
            _json(
                result := _maybe_write_observation(
                    check_surface_drift(
                        load_observation(args.subtraction),
                        load_observation(args.baseline),
                        tolerance=args.tolerance,
                    ),
                    args.out,
                )
            )
            or (0 if result["passed"] else 1)
        )
    )

    observe_compare = observe_sub.add_parser(
        "compare",
        help="pairwise stability/overlap across control-subtracted arms",
    )
    observe_compare.add_argument("subtraction", type=Path, nargs="+")
    observe_compare.add_argument("--out", type=Path, default=None)
    observe_compare.set_defaults(
        func=lambda args: (
            _json(
                _maybe_write_observation(
                    compare_surfaces([load_observation(p) for p in args.subtraction]),
                    args.out,
                )
            )
            or 0
        )
    )

    observe_digest = observe_sub.add_parser(
        "digest",
        help="answer what a collector does, by fingerprinting technique, in ~500 "
        "tokens instead of the ~13k an artifact costs to read",
    )
    observe_digest.add_argument("observation", type=Path)
    observe_digest.add_argument(
        "--focus",
        default=None,
        help="drill into one technique and list its full API-name set "
        f"(one of: {', '.join(sorted(TECHNIQUES))})",
    )
    observe_digest.add_argument(
        "--json", action="store_true", help="emit the digest document instead of text"
    )
    observe_digest.set_defaults(
        func=lambda args: (
            _emit_digest(
                digest_observation(
                    load_observation(args.observation), focus=args.focus
                ),
                as_json=args.json,
            )
            or 0
        )
    )

    observe_diff = observe_sub.add_parser(
        "diff",
        help="what does collector A do that B does not, rolled up by technique",
    )
    observe_diff.add_argument("left", type=Path)
    observe_diff.add_argument("right", type=Path)
    observe_diff.add_argument(
        "--focus", default=None, help="list the differing API names for one technique"
    )
    observe_diff.add_argument(
        "--vary-method-axis",
        action="append",
        choices=CONTROL_METHOD_AXES,
        default=[],
        help=(
            "declare one intentional method difference (for example input_profile); "
            "every other method axis must still match"
        ),
    )
    observe_diff.add_argument("--json", action="store_true")
    observe_diff.set_defaults(
        func=lambda args: (
            _emit_digest(
                diff_digests(
                    load_observation(args.left),
                    load_observation(args.right),
                    focus=args.focus,
                    vary_method_axes=tuple(args.vary_method_axis),
                ),
                as_json=args.json,
            )
            or 0
        )
    )

    observe_corpus = observe_sub.add_parser(
        "corpus",
        help="compare many surfaces at once as a technique x group matrix",
    )
    observe_corpus.add_argument("directory", type=Path)
    observe_corpus.add_argument(
        "--group-by",
        default=None,
        help="regex with one capture group; its match on each arm label names the "
        "group (e.g. '(sbsd|main)'). Unmatched labels group as 'ungrouped'.",
    )
    observe_corpus.add_argument(
        "--technique",
        default=None,
        help="switch to per-arm detail for one technique, which is how a bimodal "
        "split becomes visible; aggregates hide it",
    )
    observe_corpus.add_argument(
        "--captures-root",
        type=Path,
        default=None,
        help="capture tree to measure pin coverage against, i.e. how many of the "
        "collector scripts you actually hold have been observed",
    )
    observe_corpus.add_argument(
        "--include-raw",
        action="store_true",
        help="also include un-subtracted surfaces (labelled RAW:); off by default because raw surfaces are not attributable to the script",
    )
    observe_corpus.add_argument("--json", action="store_true")
    observe_corpus.set_defaults(
        func=lambda args: (
            _emit_corpus(
                args.directory,
                group_by=args.group_by,
                technique=args.technique,
                as_json=args.json,
                include_raw=args.include_raw,
                captures_root=args.captures_root,
            )
            or 0
        )
    )

    observe_claim = observe_sub.add_parser(
        "check-claim",
        help="test 'the collector does not use X' against a corpus; distinguishes "
        "a real negative from one the method cannot see (exit 0 only if SUPPORTED)",
    )
    observe_claim.add_argument("directory", type=Path)
    observe_claim.add_argument(
        "--technique",
        required=True,
        help=f"one of: {', '.join(sorted(TECHNIQUES))}",
    )
    observe_claim.add_argument("--json", action="store_true")
    observe_claim.set_defaults(
        func=lambda args: _emit_claim(args.directory, args.technique, as_json=args.json)
    )

    observe_prov = observe_sub.add_parser(
        "provenance",
        help="what is actually verifiable about a captured script's origin; a "
        "directory name is not provenance and a label is not evidence",
    )
    observe_prov.add_argument("script", type=Path)
    observe_prov.add_argument(
        "--captures-root",
        type=Path,
        required=True,
        help="directory containing capture folders with capture-summary.json",
    )
    observe_prov.add_argument(
        "--asserted-label",
        default=None,
        help="a label you were about to attach; echoed back marked unverified",
    )
    observe_prov.add_argument("--json", action="store_true")
    observe_prov.set_defaults(
        func=lambda args: _emit_provenance(
            args.script,
            args.captures_root,
            asserted_label=args.asserted_label,
            as_json=args.json,
        )
    )

    observe_triage = observe_sub.add_parser(
        "triage",
        help="classify every .js in a directory as collector or not, in one call",
    )
    observe_triage.add_argument("directory", type=Path)
    observe_triage.add_argument(
        "--json", action="store_true", help="emit the triage document instead of text"
    )
    observe_triage.set_defaults(
        func=lambda args: (_emit_triage(args.directory, as_json=args.json) or 0)
    )

    ops = sub.add_parser(
        "ops", help="operational benchmarks and multi-identity batches"
    )
    ops_sub = ops.add_subparsers(dest="ops_command", required=True)
    velocity = ops_sub.add_parser(
        "velocity", help="launch-latency benchmark against a target median"
    )
    velocity.add_argument("--workspace", type=_explicit_workspace_path, default=None)
    velocity.add_argument("--count", type=int, default=10)
    velocity.add_argument(
        "--ready-mode", choices=("dry-run", "launch"), default="dry-run"
    )
    velocity.add_argument("--executable", type=Path)
    velocity.add_argument("--target-median-ms", type=float, default=30_000.0)
    velocity.add_argument("--persona-id", action="append", default=[])
    velocity.add_argument(
        "--network-route-id",
        default=None,
        help="optional fail-closed network route attached to each disposable profile",
    )
    velocity.add_argument(
        "--network",
        choices=("auto",),
        default=None,
        help="auto: create/reuse geo-aligned direct routes per persona (B05)",
    )
    velocity.set_defaults(
        func=lambda args: (
            _json(
                run_profile_velocity_batch(
                    _required_workspace(args.workspace),
                    count=args.count,
                    persona_ids=args.persona_id or None,
                    ready_mode=args.ready_mode,
                    executable=args.executable,
                    repository_root=ROOT
                    if (args.ready_mode == "launch" or args.executable is not None)
                    else None,
                    target_median_ms=args.target_median_ms,
                    network_route_id=args.network_route_id,
                    network_auto=args.network == "auto",
                )
            )
            or 0
        )
    )
    multi = ops_sub.add_parser(
        "multi-identity", help="run a cohort of identity arms, optionally in parallel"
    )
    multi.add_argument("--workspace", type=_explicit_workspace_path, default=None)
    multi.add_argument("--persona-id", action="append", required=True)
    multi.add_argument("--ready-mode", choices=("dry-run", "launch"), default="dry-run")
    multi.add_argument("--executable", type=Path)
    multi.add_argument("--batch-id")
    multi.add_argument(
        "--network-route-id",
        default=None,
        help="optional fail-closed network route attached to each disposable profile",
    )
    multi.add_argument(
        "--network",
        choices=("auto",),
        default=None,
        help="auto: create/reuse geo-aligned direct routes per persona (B05)",
    )
    multi.set_defaults(
        func=lambda args: (
            _json(
                run_multi_identity_batch(
                    _required_workspace(args.workspace),
                    args.persona_id,
                    batch_id=args.batch_id,
                    ready_mode=args.ready_mode,
                    executable=args.executable,
                    repository_root=ROOT
                    if (args.ready_mode == "launch" or args.executable is not None)
                    else None,
                    network_route_id=args.network_route_id,
                    network_auto=args.network == "auto",
                )
            )
            or 0
        )
    )
    exclusivity = ops_sub.add_parser(
        "exclusivity-demo",
        help="demonstrate that a persona cannot be held by two profiles at once",
    )
    exclusivity.add_argument("--workspace", type=_explicit_workspace_path, default=None)
    exclusivity.add_argument("--persona-id", required=True)
    exclusivity.set_defaults(
        func=lambda args: (
            _json(
                demonstrate_exclusivity(
                    _required_workspace(args.workspace), args.persona_id
                )
            )
            or 0
        )
    )
    cohort = ops_sub.add_parser(
        "coherence-cohort",
        help=(
            "B10: N launch-compatible disposable identities -> controlled_coherence "
            "-> stop/dispose (default headed; not a bot-score claim)"
        ),
    )
    cohort.add_argument("--workspace", type=_explicit_workspace_path, default=None)
    cohort.add_argument("--count", type=int, default=3)
    cohort.add_argument("--persona-id", action="append", default=[])
    cohort.add_argument(
        "--executable",
        type=Path,
        required=True,
        help="Browser Core chrome.exe path",
    )
    cohort.add_argument(
        "--evaluators",
        default="controlled_coherence",
        help="comma-separated browser-eval evaluator ids (default controlled_coherence)",
    )
    cohort.add_argument(
        "--headless",
        action="store_true",
        help="use headless launch (default is headed; residual fails headless_token_absent)",
    )
    cohort.add_argument("--batch-id")
    cohort.add_argument(
        "--parallel",
        type=int,
        default=1,
        help=(
            "B02: bounded concurrent arms (default 1 = sequential). Each arm owns a "
            "distinct persona, disposable profile, claim, profile lock, gateway lease, "
            "and CDP port; results stay in arm order. Hard cap 8 - headed Chromium "
            "arms are heavy and this is a research pool, not fleet scale."
        ),
    )
    cohort.add_argument(
        "--out",
        type=Path,
        default=None,
        help="optional directory for per-arm browser-eval outputs",
    )
    cohort.add_argument(
        "--network-route-id",
        default=None,
        help="optional fail-closed network route attached to each disposable profile",
    )
    cohort.add_argument(
        "--network",
        choices=("auto",),
        default=None,
        help="auto: create/reuse geo-aligned direct routes per persona (B05)",
    )
    cohort.set_defaults(
        func=lambda args: (
            _json(
                run_ops_coherence_cohort(
                    _required_workspace(args.workspace),
                    count=args.count,
                    persona_ids=args.persona_id or None,
                    executable=args.executable,
                    repository_root=ROOT,
                    evaluators=args.evaluators,
                    headless=bool(args.headless),
                    network_route_id=args.network_route_id,
                    network_auto=args.network == "auto",
                    batch_id=args.batch_id,
                    out_dir=args.out,
                    parallel=args.parallel,
                )
            )
            or 0
        )
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    from .metadata_rows import RowsArgumentError, RowsArgumentParser, emit_argument_error, rows_command
    from .metadata_bookmark import bookmark_command, emit_argument_error as bookmark_argument_error
    from .metadata_compare import compare_command, emit_compare_argument_error
    from .metadata_inventory_query import inventory_command, emit_inventory_argument_error
    # Select by exact canonical route before integer/choice/unknown-argument
    # validation can format or echo user text. argparse propagates this class
    # to subparsers, so errors raised by either the root or rows parser are closed.
    selected_argv = sys.argv[1:] if argv is None else argv
    if bookmark_command(selected_argv):
        try:
            args = build_parser(_parser_class=RowsArgumentParser).parse_args(selected_argv)
        except RowsArgumentError:
            return bookmark_argument_error()
    elif rows_command(selected_argv):
        try:
            args = build_parser(_parser_class=RowsArgumentParser).parse_args(selected_argv)
        except RowsArgumentError:
            return emit_argument_error()
    elif compare_command(selected_argv):
        try:
            args = build_parser(_parser_class=RowsArgumentParser).parse_args(selected_argv)
        except RowsArgumentError:
            return emit_compare_argument_error()
    elif inventory_command(selected_argv):
        try:
            args = build_parser(_parser_class=RowsArgumentParser).parse_args(selected_argv)
        except RowsArgumentError:
            return emit_inventory_argument_error()
    elif len(selected_argv) >= 2 and selected_argv[:2] == ["trace", "evidence-stop-timeouts"]:
        from .stop_timeout_details import SCHEMA as STOP_TIMEOUT_SCHEMA

        try:
            args = build_parser(_parser_class=RowsArgumentParser).parse_args(selected_argv)
        except RowsArgumentError:
            _json({"schema": STOP_TIMEOUT_SCHEMA, "status": "error",
                   "code": "stop-timeout-details-unavailable"})
            return 2
    elif selected_argv[:1] == ["network"]:
        # A network command can contain a proxy password or a private session
        # key. argparse includes invalid values in its default diagnostics.
        try:
            args = build_parser(_parser_class=RowsArgumentParser).parse_args(selected_argv)
        except RowsArgumentError:
            print("browser-core: network arguments are invalid", file=sys.stderr)
            return 2
    elif len(selected_argv) >= 2 and selected_argv[:2] == ["agent", "capabilities"]:
        # Only an explicitly versioned/new-scope call opts into a closed parse
        # boundary. Bare V1 keeps its historical argparse bytes and behavior.
        from .agent_capabilities import SCHEMA, SCHEMA_V2

        options = selected_argv[2:]
        if "--" in options:
            options = options[: options.index("--")]
        versions = []
        scope_count = 0
        abbreviated_selector = False
        selectors = ("--schema-version", "--scope")
        for index, option in enumerate(options):
            spelling, separator, joined_value = option.partition("=")
            if not spelling.startswith("--") or spelling == "--":
                continue
            if spelling not in selectors and any(
                name.startswith(spelling) for name in selectors
            ):
                # argparse accepts these abbreviations, including ambiguous
                # prefixes. Never let its permissive parser choose a version or
                # scope before the fixed diagnostic boundary is selected.
                abbreviated_selector = True
            if "--schema-version".startswith(spelling):
                versions.append(
                    joined_value if separator else
                    (options[index + 1] if index + 1 < len(options) else "")
                )
            if spelling == "--scope":
                scope_count += 1
        def requested_v2(value: str) -> bool:
            try:
                return int(value) == 2
            except ValueError:
                return False

        if versions or scope_count or abbreviated_selector:
            error_schema = SCHEMA_V2 if any(requested_v2(value) for value in versions) else SCHEMA
            if abbreviated_selector or len(versions) > 1 or scope_count > 1:
                _json({"schema": error_schema, "status": "error", "code": "capabilities-unavailable"})
                return 2
            try:
                args = build_parser(_parser_class=RowsArgumentParser).parse_args(selected_argv)
            except RowsArgumentError:
                _json({"schema": error_schema, "status": "error", "code": "capabilities-unavailable"})
                return 2
        else:
            parser = build_parser()
            args = parser.parse_args(argv)
    else:
        # Keep the original parser and output behavior for every legacy route.
        parser = build_parser()
        args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except ContractError as exc:
        print(f"browser-core: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
