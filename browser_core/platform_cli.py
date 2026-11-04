from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path
from typing import Any, Sequence

from . import control_files as control_files_module
from .cli import ROOT
from .client import ControlClient
from .contracts import ContractError
from .control import JOB_KINDS, ControlStore
from .control_files import (
    PublishedControlSnapshot,
    decode_strict_json_bytes,
    publish_bytes_exclusive_result,
    publish_json_exclusive_result,
    read_bounded_control_snapshot_result,
)
from .owned_paths import directory_ancestry_binding, prepare_owned_directory_parent
from .profiles import has_windows_device_basename
from .kernels import (
    device_from_playwright,
    discover_kernels,
    playwright_device_catalog,
    probe_playwright_kernel,
)
from .http2_fingerprint import (
    approve_http2_baseline,
    capture_attested_http2_evidence,
    capture_attested_http2_fingerprint,
    compare_http2_fingerprints,
    load_http2_baseline,
    load_http2_fingerprint,
)
from .http2_headers import (
    approve_http2_evidence_baseline,
    compare_http2_capture_evidence,
    load_http2_capture_evidence,
    load_http2_evidence_baseline,
)
from .network import (
    add_network_route,
    build_network_route,
    list_network_routes,
    load_network_route,
    observe_geo_alignment,
    preflight_network_route,
    resolve_network_route,
    validate_geo_alignment,
)
from .physical_mobile import discover_physical_mobile, probe_physical_android
from .personas import (
    add_persona,
    assign_persona,
    audit_persona_catalog,
    capture_kernel_persona,
    capture_physical_android_persona,
    capture_profile_persona,
    bulk_capture_personas,
    bulk_capture_personas_batched,
    catalog_coverage_report,
    catalog_volume_report,
    compare_commercial_volume,
    export_persona_bundle_from_workspace,
    import_persona_bundle,
    list_personas,
    load_persona_evidence,
    search_personas,
    set_persona_state,
    store_persona_evidence,
)
from .persona_quality import (
    audit_catalog_coherence,
    catalog_quality_report,
    catalog_uniqueness,
    render_coherence,
    render_uniqueness,
    retire_incoherent_personas,
)
from .service import ServiceConfig, serve_control
from .transport_fingerprint import (
    approve_transport_baseline,
    capture_attested_client_hello,
    compare_transport_fingerprints,
    load_transport_baseline,
    load_transport_fingerprint,
)
from .transport_suite import compare_transport_evidence_suite, compare_transport_suite
from .worker import run_remote_worker_once, run_worker_once


MAX_CLI_JSON_INPUT_BYTES = 64 * 1024 * 1024
MAX_CLI_JSON_OUTPUT_BYTES = 64 * 1024 * 1024
MAX_CLI_ARTIFACT_BYTES = 64 * 1024 * 1024
MAX_CLI_SECRET_BYTES = 4096
ENVIRONMENT_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")


def _json(value: Any) -> None:
    try:
        rendered = json.dumps(
            value,
            indent=2,
            sort_keys=True,
            ensure_ascii=True,
            allow_nan=False,
        )
    except (OverflowError, RecursionError, TypeError, ValueError):
        raise ContractError("CLI result is not strict JSON") from None
    # print adds a final line, and Windows text streams can expand LF to CRLF.
    emitted_bytes = len(rendered.encode("ascii")) + rendered.count("\n") + 2
    if emitted_bytes > MAX_CLI_JSON_OUTPUT_BYTES:
        raise ContractError("CLI JSON result exceeds output limit")
    print(rendered)


def _stable_bytes(path: Path, *, maximum: int, label: str) -> bytes:
    if not isinstance(path, Path):
        raise ContractError(f"{label} path must be a Path")
    _require_cli_path(path, label=label)
    snapshot = read_bounded_control_snapshot_result(
        path.absolute(),
        maximum=maximum,
        label=label,
    )
    if snapshot.state != "complete" or snapshot.body is None:
        raise ContractError(f"{label} is {snapshot.state}")
    return snapshot.body


def _load(path: Path) -> Any:
    return decode_strict_json_bytes(
        _stable_bytes(
            path,
            maximum=MAX_CLI_JSON_INPUT_BYTES,
            label="CLI JSON input",
        ),
        label="JSON document",
    )


def _require_cli_path(destination: Path, *, label: str) -> None:
    # Win32 normalizes trailing dots/spaces and treats device basenames as
    # special files. Refuse every such component before creating a parent.
    try:
        rendered = str(destination)
        rendered.encode("utf-8", errors="strict")
    except (UnicodeError, ValueError):
        raise ContractError(f"{label} path is invalid") from None
    if "\x00" in rendered:
        raise ContractError(f"{label} path is invalid")
    if os.name != "nt":
        return
    for component in destination.parts:
        if component == destination.anchor or component in {".", ".."}:
            continue
        if (
            not component
            or component.endswith((".", " "))
            or has_windows_device_basename(component)
            or any(
                character in '<>:"\\|?*' or ord(character) < 32
                for character in component
            )
        ):
            raise ContractError(f"{label} path has an invalid component")


def _write_json(path: Path, value: Any) -> PublishedControlSnapshot:
    if not isinstance(path, Path) or not isinstance(value, dict):
        raise ContractError("CLI JSON output contract is invalid")
    destination = path.absolute()
    _require_cli_path(destination, label="CLI JSON output")
    prepare_owned_directory_parent(destination.parent, label="CLI JSON output parent")
    return publish_json_exclusive_result(
        destination,
        value,
        maximum=MAX_CLI_JSON_OUTPUT_BYTES,
        label="CLI JSON output",
    )


def _write_transport_json_checked(path: Path, value: Any) -> Path:
    if not isinstance(path, Path):
        raise ContractError("transport output path is invalid")
    destination = path.absolute()
    _require_cli_path(destination, label="transport output")
    prepare_owned_directory_parent(destination.parent, label="transport output parent")
    parent_binding = directory_ancestry_binding(
        destination.parent, label="transport output parent",
    )
    published = _write_json(destination, value)
    if directory_ancestry_binding(
        destination.parent, label="transport output parent",
    ) != parent_binding:
        raise ContractError("transport output parent changed")
    current = read_bounded_control_snapshot_result(
        destination,
        maximum=MAX_CLI_JSON_OUTPUT_BYTES,
        label="transport output",
        require_single_link=True,
    )
    if (
        current.state != "complete"
        or current.body != published.body
        or current.identity != published.identity
    ):
        raise ContractError("transport output changed after publication")
    if directory_ancestry_binding(
        destination.parent, label="transport output parent",
    ) != parent_binding:
        raise ContractError("transport output parent changed")
    return destination


def _publish_remote_artifact_checked(path: Path, content: bytes) -> Path:
    if not isinstance(path, Path):
        raise ContractError("remote artifact output path is invalid")
    destination = path.absolute()
    _require_cli_path(destination, label="remote artifact output")
    prepare_owned_directory_parent(destination.parent, label="remote artifact output parent")
    parent_binding = directory_ancestry_binding(
        destination.parent, label="remote artifact output parent",
    )
    published = control_files_module.publish_bytes_exclusive_result(
        destination,
        content,
        maximum=MAX_CLI_ARTIFACT_BYTES,
        label="remote artifact output",
        require_single_link=True,
    )
    if directory_ancestry_binding(
        destination.parent, label="remote artifact output parent",
    ) != parent_binding:
        raise ContractError("remote artifact output parent changed")
    current = read_bounded_control_snapshot_result(
        destination,
        maximum=MAX_CLI_ARTIFACT_BYTES,
        label="remote artifact output",
        require_single_link=True,
    )
    if (
        current.state != "complete"
        or current.body != published.body
        or current.identity != published.identity
    ):
        raise ContractError("remote artifact output changed after publication")
    if directory_ancestry_binding(
        destination.parent, label="remote artifact output parent",
    ) != parent_binding:
        raise ContractError("remote artifact output parent changed")
    return destination


def _write_secret(path: Path, value: str) -> PublishedControlSnapshot:
    if (
        not isinstance(path, Path)
        or not isinstance(value, str)
        or not value
        or any(ord(character) < 0x21 or ord(character) > 0x7E for character in value)
    ):
        raise ContractError("CLI secret output contract is invalid")
    body = (value + "\n").encode("ascii")
    if len(body) > MAX_CLI_SECRET_BYTES:
        raise ContractError("CLI secret output exceeds limit")
    destination = path.absolute()
    _require_cli_path(destination, label="CLI secret output")
    prepare_owned_directory_parent(destination.parent, label="CLI secret output parent")
    return publish_bytes_exclusive_result(
        destination,
        body,
        maximum=MAX_CLI_SECRET_BYTES,
        label="CLI secret output",
        require_single_link=True,
    )


def _publish_secret_checked(path: Path, token: str) -> None:
    if not isinstance(path, Path):
        raise ContractError("CLI secret output contract is invalid")
    destination = path.absolute()
    _require_cli_path(destination, label="CLI secret output")
    prepare_owned_directory_parent(destination.parent, label="CLI secret output parent")
    parent_binding = directory_ancestry_binding(
        destination.parent, label="CLI secret output parent",
    )
    published = _write_secret(path, token)
    if directory_ancestry_binding(
        destination.parent, label="CLI secret output parent",
    ) != parent_binding:
        raise ContractError("CLI secret output parent changed")
    current = read_bounded_control_snapshot_result(
        destination,
        maximum=MAX_CLI_SECRET_BYTES,
        label="CLI secret output",
        require_private=True,
        require_single_link=True,
    )
    if (
        current.state != "complete"
        or current.body != published.body
        or current.identity != published.identity
    ):
        raise ContractError("CLI secret output changed after publication")
    if directory_ancestry_binding(
        destination.parent, label="CLI secret output parent",
    ) != parent_binding:
        raise ContractError("CLI secret output parent changed")


def _token(environment_name: str) -> str:
    if (
        not isinstance(environment_name, str)
        or ENVIRONMENT_NAME_RE.fullmatch(environment_name) is None
    ):
        raise ContractError("token environment variable name is invalid")
    value = os.environ.get(environment_name, "")
    try:
        encoded = value.encode("utf-8", errors="strict")
    except UnicodeEncodeError:
        encoded = None
    if (
        not value
        or encoded is None
        or len(encoded) > MAX_CLI_SECRET_BYTES
        or any(ord(character) < 0x21 or character.isspace() for character in value)
    ):
        raise ContractError(f"token environment variable is unset: {environment_name}")
    return value


def _store(args: argparse.Namespace) -> ControlStore:
    if args.control_root is None:
        raise ContractError("direct control operations require --control-root")
    return ControlStore(args.control_root)


class _ClosedParser(argparse.ArgumentParser):
    def __init__(self, *args, **kwargs):
        kwargs.setdefault("allow_abbrev", False)
        super().__init__(*args, **kwargs)

    def error(self, _message):
        raise ContractError("invalid options")


def _explicit_path_argument(value: str) -> Path:
    if not value:
        raise argparse.ArgumentTypeError("path is empty")
    path = Path(value)
    if os.name == "nt" and any(
        component != path.anchor
        and component not in {".", ".."}
        and component.endswith((".", " "))
        for component in path.parts
    ):
        raise argparse.ArgumentTypeError("path has an invalid component")
    return path


def parser() -> argparse.ArgumentParser:
    result = _ClosedParser(prog="browser-platform")
    result.add_argument(
        "--workspace",
        type=_explicit_path_argument,
        default=None,
    )
    sub = result.add_subparsers(dest="area", required=True)

    persona = sub.add_parser("persona")
    persona_sub = persona.add_subparsers(dest="command", required=True)
    add = persona_sub.add_parser("add")
    add.add_argument("document", type=Path)
    capture = persona_sub.add_parser("capture-profile")
    capture.add_argument("profile_id")
    capture.add_argument("persona_id")
    capture.add_argument("name")
    capture.add_argument("--os-family", default="windows")
    capture.add_argument("--os-version", required=True)
    capture.add_argument(
        "--architecture", choices=("x86_64", "arm64"), default="x86_64"
    )
    capture.add_argument("--browser-major", type=int, required=True)
    capture.add_argument("--viewport-width", type=int, required=True)
    capture.add_argument("--viewport-height", type=int, required=True)
    capture.add_argument("--device-scale-factor", type=float, default=1)
    capture.add_argument("--country", required=True)
    capture.add_argument("--locale", required=True)
    capture.add_argument("--language", action="append", required=True)
    capture.add_argument("--timezone", required=True)
    capture.add_argument("--tag", action="append", default=[])
    kernel_capture = persona_sub.add_parser("capture-kernel")
    kernel_capture.add_argument("persona_id")
    kernel_capture.add_argument("name")
    kernel_capture.add_argument("kernel_id")
    kernel_capture.add_argument("device_preset")
    kernel_capture.add_argument("--os-family", required=True)
    kernel_capture.add_argument("--os-version", required=True)
    kernel_capture.add_argument(
        "--architecture", choices=("x86_64", "arm64"), required=True
    )
    kernel_capture.add_argument("--country", required=True)
    kernel_capture.add_argument("--locale", required=True)
    kernel_capture.add_argument("--timezone", required=True)
    kernel_capture.add_argument("--tag", action="append", default=[])
    kernel_capture.add_argument("--executable", type=Path,
                                help="attested Browser Core executable to include in kernel discovery")
    physical_capture = persona_sub.add_parser("capture-physical-android")
    physical_capture.add_argument("persona_id")
    physical_capture.add_argument("name")
    physical_capture.add_argument("--country", required=True)
    physical_capture.add_argument("--tag", action="append", default=[])
    physical_capture.add_argument("--timeout-seconds", type=float, default=45.0)
    persona_list = persona_sub.add_parser("list")
    persona_list.add_argument("--include-deprecated", action="store_true")
    persona_state = persona_sub.add_parser("state")
    persona_state.add_argument("persona_id")
    persona_state.add_argument("state", choices=("active", "deprecated"))
    persona_state.add_argument("expected_sha256")
    evidence_get = persona_sub.add_parser("evidence-get")
    evidence_get.add_argument("sha256")
    persona_sub.add_parser("audit")
    normalize = persona_sub.add_parser("normalize-format")
    normalize.add_argument(
        "--apply", action="store_true",
        help="back up and normalize validated legacy JSON; default is a dry run",
    )
    persona_sub.add_parser("coverage")
    volume = persona_sub.add_parser("volume")
    volume.add_argument("--baseline-active", type=int, default=15)
    commercial = persona_sub.add_parser("commercial-compare")
    commercial.add_argument("--baseline-active", type=int, default=100)
    commercial.add_argument("--kameleo-base-url", default="http://127.0.0.1:5050")
    coherence = persona_sub.add_parser("coherence")
    coherence.add_argument("--include-deprecated", action="store_true")
    coherence.add_argument("--json", action="store_true", dest="as_json")
    uniqueness = persona_sub.add_parser("uniqueness")
    uniqueness.add_argument("--include-deprecated", action="store_true")
    uniqueness.add_argument("--json", action="store_true", dest="as_json")
    quality = persona_sub.add_parser("quality")
    quality.add_argument("--include-deprecated", action="store_true")
    retire = persona_sub.add_parser("retire-incoherent")
    retire.add_argument(
        "--apply",
        action="store_true",
        help="actually deprecate; without it this only reports what would be retired",
    )
    retire.add_argument("--minimum-claims", type=int, default=4)

    bulk = persona_sub.add_parser("bulk-capture")
    bulk.add_argument("--target-active", type=int, default=100)
    bulk.add_argument("--max-new", type=int, default=None)
    bulk.add_argument(
        "--batched",
        action="store_true",
        help="one browser per engine instead of one per persona (needed above ~200)",
    )
    bulk.add_argument(
        "--engine",
        action="append",
        default=None,
        help="restrict batched capture to these engines (default: chromium)",
    )
    bulk.add_argument(
        "--full-cross-product",
        action="store_true",
        help="pair every usable device with every geography (commercial-class volume)",
    )
    bulk.add_argument(
        "--core-variants",
        type=int,
        default=1,
        help="capture N logical-core counts per device and locale (batched only)",
    )
    bulk.add_argument(
        "--device-memory-executable",
        type=Path,
        default=None,
        help=(
            "attested Browser Core chrome.exe carrying native patch 0005; turns on "
            "the device-memory axis, without which every persona inherits this "
            "host's RAM and every mobile one contradicts Chrome for Android"
        ),
    )
    bulk.add_argument(
        "--repository-root",
        type=Path,
        default=None,
        help="browser-core repo root for kernel discovery (default: package root)",
    )
    search = persona_sub.add_parser("search")
    search.add_argument("--engine")
    search.add_argument("--product")
    search.add_argument("--major", type=int)
    search.add_argument("--min-major", type=int)
    search.add_argument("--max-major", type=int)
    search.add_argument("--device-class")
    search.add_argument("--os-family")
    search.add_argument("--country")
    search.add_argument("--locale")
    search.add_argument("--language")
    search.add_argument("--tag", action="append", default=[])
    search.add_argument(
        "--include-incoherent",
        action="store_true",
        help="also return personas carrying a contradiction finding (excluded by default)",
    )
    export = persona_sub.add_parser("export")
    export.add_argument("output", type=Path)
    import_parser = persona_sub.add_parser("import")
    import_parser.add_argument("bundle", type=Path)
    assign = persona_sub.add_parser("assign")
    assign.add_argument("assignment_key_env")
    assign.add_argument("--engine")
    assign.add_argument("--product")
    assign.add_argument("--major", type=int)
    assign.add_argument("--min-major", type=int)
    assign.add_argument("--max-major", type=int)
    assign.add_argument("--device-class")
    assign.add_argument("--os-family")
    assign.add_argument("--country")
    assign.add_argument("--locale")
    assign.add_argument("--language")
    assign.add_argument("--tag", action="append", default=[])
    assign.add_argument(
        "--include-incoherent",
        action="store_true",
        help="also consider personas carrying a contradiction finding (excluded by default)",
    )

    network = sub.add_parser("network")
    network_sub = network.add_subparsers(dest="command", required=True)
    route_add = network_sub.add_parser("add")
    route_add.add_argument("document", type=Path)
    direct = network_sub.add_parser("create-direct")
    direct.add_argument("route_id")
    direct.add_argument("name")
    direct.add_argument("--country", required=True)
    direct.add_argument("--locale", required=True)
    direct.add_argument("--timezone", required=True)
    direct.add_argument("--preflight-url", default="https://tls.peet.ws/api/all")
    proxied = network_sub.add_parser("create-proxy")
    proxied.add_argument("route_id")
    proxied.add_argument("name")
    proxied.add_argument("protocol", choices=("http", "https", "socks5"))
    proxied.add_argument("host")
    proxied.add_argument("port", type=int)
    proxied.add_argument("--username-env")
    proxied.add_argument("--password-env")
    proxied.add_argument("--country", required=True)
    proxied.add_argument("--locale", required=True)
    proxied.add_argument("--timezone", required=True)
    proxied.add_argument("--preflight-url", default="https://tls.peet.ws/api/all")
    network_sub.add_parser("list")
    preflight = network_sub.add_parser("preflight")
    preflight.add_argument("route_id")
    preflight.add_argument("probe_url")
    align = network_sub.add_parser("align")
    align.add_argument("route_id")
    align.add_argument("observation", type=Path)
    observe = network_sub.add_parser("observe-align")
    observe.add_argument("route_id")
    observe.add_argument("--browser-locale", required=True)
    observe.add_argument("--browser-timezone", required=True)

    transport = sub.add_parser("transport")
    transport_sub = transport.add_subparsers(dest="command", required=True)
    fingerprint = transport_sub.add_parser("fingerprint")
    fingerprint.add_argument("executable", type=Path)
    fingerprint.add_argument("--repository-root", type=Path, default=ROOT)
    fingerprint.add_argument("--timeout-seconds", type=float, default=20.0)
    fingerprint.add_argument("--output", type=Path)
    transport_check = transport_sub.add_parser("check")
    transport_check.add_argument("current", type=Path)
    transport_check.add_argument("baseline", type=Path)
    http2_fingerprint = transport_sub.add_parser("http2-fingerprint")
    http2_fingerprint.add_argument("executable", type=Path)
    http2_fingerprint.add_argument("--certificate", type=Path, required=True)
    http2_fingerprint.add_argument("--private-key", type=Path, required=True)
    http2_fingerprint.add_argument("--repository-root", type=Path, default=ROOT)
    http2_fingerprint.add_argument("--timeout-seconds", type=float, default=20.0)
    http2_fingerprint.add_argument("--output", type=Path)
    http2_evidence = transport_sub.add_parser("http2-evidence")
    http2_evidence.add_argument("executable", type=Path)
    http2_evidence.add_argument("--certificate", type=Path, required=True)
    http2_evidence.add_argument("--private-key", type=Path, required=True)
    http2_evidence.add_argument("--repository-root", type=Path, default=ROOT)
    http2_evidence.add_argument("--timeout-seconds", type=float, default=20.0)
    http2_evidence.add_argument("--output", type=Path)
    http2_evidence_check = transport_sub.add_parser("http2-evidence-check")
    http2_evidence_check.add_argument("current", type=Path)
    http2_evidence_check.add_argument("baseline", type=Path)
    http2_evidence_approve = transport_sub.add_parser(
        "approve-http2-evidence-baseline"
    )
    http2_evidence_approve.add_argument("current_id")
    http2_evidence_approve.add_argument("baseline_id")
    http2_evidence_approve.add_argument("--expected-digest", required=True)
    http2_check = transport_sub.add_parser("http2-check")
    http2_check.add_argument("current", type=Path)
    http2_check.add_argument("baseline", type=Path)
    http2_approve = transport_sub.add_parser("approve-http2-baseline")
    http2_approve.add_argument("current_id")
    http2_approve.add_argument("baseline_id")
    http2_approve.add_argument("--expected-digest", required=True)
    suite_check = transport_sub.add_parser("suite-check")
    suite_check.add_argument("current_client_hello", type=Path)
    suite_check.add_argument("client_hello_baseline", type=Path)
    suite_check.add_argument("current_http2", type=Path)
    suite_check.add_argument("http2_baseline", type=Path)
    evidence_suite_check = transport_sub.add_parser("evidence-suite-check")
    evidence_suite_check.add_argument("current_client_hello", type=Path)
    evidence_suite_check.add_argument("client_hello_baseline", type=Path)
    evidence_suite_check.add_argument("current_http2_evidence", type=Path)
    evidence_suite_check.add_argument("http2_evidence_baseline", type=Path)
    transport_approve = transport_sub.add_parser("approve-baseline")
    transport_approve.add_argument("current_id")
    transport_approve.add_argument("baseline_id")
    transport_approve.add_argument("--expected-digest", required=True)

    kernel = sub.add_parser("kernel")
    kernel_sub = kernel.add_subparsers(dest="command", required=True)
    kernel_list = kernel_sub.add_parser("list")
    kernel_list.add_argument("--browser-core-executable", type=Path)
    devices = kernel_sub.add_parser("devices")
    devices.add_argument("--pattern")
    probe = kernel_sub.add_parser("probe")
    probe.add_argument("kernel_id")
    probe.add_argument("device_preset")
    probe.add_argument("--locale", default="en-US")
    probe.add_argument("--timezone", default="America/Chicago")
    kernel_sub.add_parser("physical-list")
    physical_probe = kernel_sub.add_parser("physical-probe")
    physical_probe.add_argument("platform", choices=("android",))
    physical_probe.add_argument("--timeout-seconds", type=float, default=30.0)

    control = sub.add_parser("control")
    control.add_argument("--control-root", type=_explicit_path_argument)
    control_sub = control.add_subparsers(dest="command", required=True)
    bootstrap = control_sub.add_parser("bootstrap")
    bootstrap.add_argument("workspace_id")
    bootstrap.add_argument("workspace_name")
    bootstrap.add_argument("owner_id")
    bootstrap.add_argument("owner_name")
    bootstrap.add_argument("--token-out", type=Path, required=True)
    bootstrap.add_argument("--token-ttl-hours", type=int, default=24)
    bootstrap.add_argument("--max-running", type=int, default=4)
    bootstrap.add_argument("--max-queued", type=int, default=100)
    serve = control_sub.add_parser("serve")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8766)
    serve.add_argument("--tls-cert", type=Path)
    serve.add_argument("--tls-key", type=Path)
    workspace_create = control_sub.add_parser("workspace-create")
    workspace_create.add_argument("workspace_id")
    workspace_create.add_argument("name")
    workspace_create.add_argument("--token-env", default="BROWSER_PLATFORM_TOKEN")
    member = control_sub.add_parser("member-add")
    member.add_argument("workspace_id")
    member.add_argument("user_id")
    member.add_argument("display_name")
    member.add_argument("role", choices=("owner", "operator", "viewer"))
    member.add_argument("--token-env", default="BROWSER_PLATFORM_TOKEN")
    issue = control_sub.add_parser("token-issue")
    issue.add_argument("workspace_id")
    issue.add_argument("user_id")
    issue.add_argument("--token-env", default="BROWSER_PLATFORM_TOKEN")
    issue.add_argument("--token-out", type=Path, required=True)
    issue.add_argument("--ttl-hours", type=int, default=24)
    revoke = control_sub.add_parser("token-revoke")
    revoke.add_argument("workspace_id")
    revoke.add_argument("token_id")
    revoke.add_argument("--token-env", default="BROWSER_PLATFORM_TOKEN")
    remote_health = control_sub.add_parser("remote-health")
    remote_health.add_argument("service_url")
    remote_get = control_sub.add_parser("remote-record-get")
    remote_get.add_argument("service_url")
    remote_get.add_argument("workspace_id")
    remote_get.add_argument("kind")
    remote_get.add_argument("record_id")
    remote_get.add_argument("--token-env", default="BROWSER_PLATFORM_TOKEN")
    remote_put = control_sub.add_parser("remote-record-put")
    remote_put.add_argument("service_url")
    remote_put.add_argument("workspace_id")
    remote_put.add_argument("kind")
    remote_put.add_argument("record_id")
    remote_put.add_argument("payload", type=Path)
    remote_put.add_argument("expected_revision", type=int)
    remote_put.add_argument("--token-env", default="BROWSER_PLATFORM_TOKEN")
    remote_artifact_put = control_sub.add_parser("remote-artifact-put")
    remote_artifact_put.add_argument("service_url")
    remote_artifact_put.add_argument("workspace_id")
    remote_artifact_put.add_argument("path", type=Path)
    remote_artifact_put.add_argument("--media-type", default="application/octet-stream")
    remote_artifact_put.add_argument(
        "--visibility", choices=("viewer", "operator", "owner"), default="operator"
    )
    remote_artifact_put.add_argument("--token-env", default="BROWSER_PLATFORM_TOKEN")
    remote_artifact_get = control_sub.add_parser("remote-artifact-get")
    remote_artifact_get.add_argument("service_url")
    remote_artifact_get.add_argument("workspace_id")
    remote_artifact_get.add_argument("digest")
    remote_artifact_get.add_argument("output", type=Path)
    remote_artifact_get.add_argument("--token-env", default="BROWSER_PLATFORM_TOKEN")
    remote_audit = control_sub.add_parser("remote-audit-verify")
    remote_audit.add_argument("service_url")
    remote_audit.add_argument("workspace_id")
    remote_audit.add_argument("--token-env", default="BROWSER_PLATFORM_TOKEN")
    remote_revoke = control_sub.add_parser("remote-token-revoke")
    remote_revoke.add_argument("service_url")
    remote_revoke.add_argument("workspace_id")
    remote_revoke.add_argument("token_id")
    remote_revoke.add_argument("--token-env", default="BROWSER_PLATFORM_TOKEN")

    fleet = sub.add_parser("fleet")
    fleet.add_argument("--control-root", type=_explicit_path_argument)
    fleet_sub = fleet.add_subparsers(dest="command", required=True)
    register = fleet_sub.add_parser("worker-register")
    register.add_argument("workspace_id")
    register.add_argument("worker_id")
    register.add_argument("name")
    register.add_argument("--capability", action="append", required=True)
    register.add_argument("--max-slots", type=int, default=1)
    register.add_argument("--token-env", default="BROWSER_PLATFORM_TOKEN")
    register.add_argument("--worker-token-out", type=Path, required=True)
    scope = fleet_sub.add_parser("worker-scope")
    scope.add_argument("workspace_id")
    scope.add_argument("worker_id")
    scope.add_argument("--token-env", default="BROWSER_PLATFORM_TOKEN")
    enqueue = fleet_sub.add_parser("enqueue")
    enqueue.add_argument("workspace_id")
    enqueue.add_argument(
        "kind",
        choices=tuple(sorted(JOB_KINDS)),
    )
    enqueue.add_argument("payload", type=Path)
    enqueue.add_argument("idempotency_key_env")
    enqueue.add_argument("--requirement", action="append", default=[])
    enqueue.add_argument("--token-env", default="BROWSER_PLATFORM_TOKEN")
    status = fleet_sub.add_parser("status")
    status.add_argument("workspace_id")
    status.add_argument("--token-env", default="BROWSER_PLATFORM_TOKEN")
    jobs = fleet_sub.add_parser("jobs")
    jobs.add_argument("workspace_id")
    jobs.add_argument("--token-env", default="BROWSER_PLATFORM_TOKEN")
    job_get = fleet_sub.add_parser("job-get")
    job_get.add_argument("workspace_id")
    job_get.add_argument("job_id")
    job_get.add_argument("--token-env", default="BROWSER_PLATFORM_TOKEN")
    once = fleet_sub.add_parser("worker-once")
    once.add_argument("--worker-token-env", default="BROWSER_PLATFORM_WORKER_TOKEN")
    once.add_argument("--lease-seconds", type=int, default=120)
    remote_enqueue = fleet_sub.add_parser("remote-enqueue")
    remote_enqueue.add_argument("service_url")
    remote_enqueue.add_argument("workspace_id")
    remote_enqueue.add_argument(
        "kind",
        choices=tuple(sorted(JOB_KINDS)),
    )
    remote_enqueue.add_argument("payload", type=Path)
    remote_enqueue.add_argument("idempotency_key_env")
    remote_enqueue.add_argument("--requirement", action="append", default=[])
    remote_enqueue.add_argument("--token-env", default="BROWSER_PLATFORM_TOKEN")
    remote_status = fleet_sub.add_parser("remote-status")
    remote_status.add_argument("service_url")
    remote_status.add_argument("workspace_id")
    remote_status.add_argument("--token-env", default="BROWSER_PLATFORM_TOKEN")
    remote_jobs = fleet_sub.add_parser("remote-jobs")
    remote_jobs.add_argument("service_url")
    remote_jobs.add_argument("workspace_id")
    remote_jobs.add_argument("--token-env", default="BROWSER_PLATFORM_TOKEN")
    remote_job_get = fleet_sub.add_parser("remote-job-get")
    remote_job_get.add_argument("service_url")
    remote_job_get.add_argument("workspace_id")
    remote_job_get.add_argument("job_id")
    remote_job_get.add_argument("--token-env", default="BROWSER_PLATFORM_TOKEN")
    remote_once = fleet_sub.add_parser("remote-worker-once")
    remote_once.add_argument("service_url")
    remote_once.add_argument(
        "--worker-token-env", default="BROWSER_PLATFORM_WORKER_TOKEN"
    )
    remote_once.add_argument("--lease-seconds", type=int, default=120)
    return result


def _workspace(args: argparse.Namespace) -> Path:
    value = args.workspace
    if value is None:
        raw = os.environ.get("BROWSER_CORE_WORKSPACE", "")
        if not raw.strip():
            raise ContractError("set BROWSER_CORE_WORKSPACE or pass --workspace")
        try:
            value = _explicit_path_argument(raw)
        except argparse.ArgumentTypeError as exc:
            raise ContractError("workspace environment path is invalid") from exc
    return value.absolute()


def main(argv: Sequence[str] | None = None) -> int:
    try:
        args = parser().parse_args(argv)
    except ContractError:
        print("browser-platform: invalid options", file=sys.stderr)
        return 2
    try:
        if args.area == "persona":
            workspace = _workspace(args)
            if args.command == "add":
                _json(add_persona(workspace, _load(args.document)))
            elif args.command == "capture-profile":
                persona = capture_profile_persona(
                    workspace,
                    profile_id=args.profile_id,
                    persona_id=args.persona_id,
                    name=args.name,
                    os_family=args.os_family,
                    os_version=args.os_version,
                    architecture=args.architecture,
                    browser_major=args.browser_major,
                    viewport_width=args.viewport_width,
                    viewport_height=args.viewport_height,
                    device_scale_factor=args.device_scale_factor,
                    country=args.country,
                    locale=args.locale,
                    languages=args.language,
                    timezone_name=args.timezone,
                    tags=args.tag,
                )
                _json(add_persona(workspace, persona))
            elif args.command == "capture-kernel":
                persona, evidence = capture_kernel_persona(
                    ROOT,
                    persona_id=args.persona_id,
                    name=args.name,
                    kernel_id=args.kernel_id,
                    device_preset=args.device_preset,
                    browser_core_executable=args.executable,
                    os_family=args.os_family,
                    os_version=args.os_version,
                    architecture=args.architecture,
                    country=args.country,
                    locale=args.locale,
                    timezone_name=args.timezone,
                    tags=args.tag,
                )
                evidence_ref = store_persona_evidence(
                    workspace,
                    evidence,
                    expected_sha256=persona["provenance"]["source_sha256"],
                )
                stored = add_persona(workspace, persona)
                _json(
                    {
                        "persona": stored,
                        "probe": evidence["probe"],
                        "evidence": evidence_ref,
                    }
                )
            elif args.command == "capture-physical-android":
                persona, probe = capture_physical_android_persona(
                    persona_id=args.persona_id,
                    name=args.name,
                    country=args.country,
                    tags=args.tag,
                    timeout_seconds=args.timeout_seconds,
                )
                evidence_ref = store_persona_evidence(
                    workspace,
                    probe,
                    expected_sha256=persona["provenance"]["source_sha256"],
                )
                stored = add_persona(workspace, persona)
                _json({"persona": stored, "probe": probe, "evidence": evidence_ref})
            elif args.command == "list":
                _json(
                    {
                        "personas": list_personas(
                            workspace, include_deprecated=args.include_deprecated
                        )
                    }
                )
            elif args.command == "state":
                _json(
                    set_persona_state(
                        workspace,
                        args.persona_id,
                        args.state,
                        expected_sha256=args.expected_sha256,
                    )
                )
            elif args.command == "evidence-get":
                _json(load_persona_evidence(workspace, args.sha256))
            elif args.command == "audit":
                _json(audit_persona_catalog(workspace))
            elif args.command == "coverage":
                _json(catalog_coverage_report(workspace))
            elif args.command == "volume":
                _json(
                    catalog_volume_report(
                        workspace, baseline_active=args.baseline_active
                    )
                )
            elif args.command == "commercial-compare":
                _json(
                    compare_commercial_volume(
                        workspace,
                        kameleo_base_url=args.kameleo_base_url,
                        baseline_active=args.baseline_active,
                    )
                )
            elif args.command == "bulk-capture":
                repo = args.repository_root.absolute() if args.repository_root else ROOT
                if args.batched:
                    _json(
                        bulk_capture_personas_batched(
                            workspace,
                            repo,
                            target_active=args.target_active,
                            max_new=args.max_new,
                            full_cross_product=args.full_cross_product,
                            engines=tuple(args.engine or ("chromium",)),
                            core_variants=args.core_variants,
                            device_memory_executable=(
                                str(args.device_memory_executable.absolute())
                                if args.device_memory_executable
                                else None
                            ),
                        )
                    )
                else:
                    _json(
                        bulk_capture_personas(
                            workspace,
                            repo,
                            target_active=args.target_active,
                            max_new=args.max_new,
                            full_cross_product=args.full_cross_product,
                        )
                    )
            elif args.command == "normalize-format":
                from .persona_migration import normalize_persona_catalog

                _json(normalize_persona_catalog(workspace, apply=args.apply))
            elif args.command == "coherence":
                report = audit_catalog_coherence(
                    workspace, include_deprecated=args.include_deprecated
                )
                if args.as_json:
                    _json(report)
                else:
                    print(render_coherence(report))
                return 0 if report["passed"] else 1
            elif args.command == "uniqueness":
                report = catalog_uniqueness(
                    workspace, include_deprecated=args.include_deprecated
                )
                if args.as_json:
                    _json(report)
                else:
                    print(render_uniqueness(report))
                return 0 if report["passed"] else 1
            elif args.command == "quality":
                report = catalog_quality_report(
                    workspace, include_deprecated=args.include_deprecated
                )
                _json(report)
                return 0 if report["passed"] else 1
            elif args.command == "retire-incoherent":
                report = retire_incoherent_personas(
                    workspace,
                    dry_run=not args.apply,
                    minimum_claims=args.minimum_claims,
                )
                _json(report)
                return 1 if report["warning_count"] or report["failed_count"] else 0
            elif args.command == "search":
                _json(
                    {
                        "personas": search_personas(
                            workspace,
                            engine=args.engine,
                            product=args.product,
                            major=args.major,
                            min_major=args.min_major,
                            max_major=args.max_major,
                            device_class=args.device_class,
                            os_family=args.os_family,
                            country=args.country,
                            locale=args.locale,
                            language=args.language,
                            tags=args.tag,
                            include_incoherent=args.include_incoherent,
                        )
                    }
                )
            elif args.command == "export":
                bundle = export_persona_bundle_from_workspace(
                    workspace, list_personas(workspace, include_deprecated=True)
                )
                destination = args.output.absolute()
                _require_cli_path(destination, label="persona export output")
                prepare_owned_directory_parent(
                    destination.parent, label="persona export output parent",
                )
                parent_binding = directory_ancestry_binding(
                    destination.parent, label="persona export output parent",
                )
                published = _write_json(destination, bundle)
                if directory_ancestry_binding(
                    destination.parent, label="persona export output parent",
                ) != parent_binding:
                    raise ContractError("persona export output parent changed")
                current = read_bounded_control_snapshot_result(
                    destination,
                    maximum=MAX_CLI_JSON_OUTPUT_BYTES,
                    label="persona export output",
                    require_single_link=True,
                )
                if (
                    current.state != "complete"
                    or current.body != published.body
                    or current.identity != published.identity
                ):
                    raise ContractError("persona export output changed after publication")
                if directory_ancestry_binding(
                    destination.parent, label="persona export output parent",
                ) != parent_binding:
                    raise ContractError("persona export output parent changed")
                _json(
                    {
                        "output": str(destination),
                        "personas": len(bundle["personas"]),
                        "bundle_sha256": bundle["bundle_sha256"],
                    }
                )
            elif args.command == "import":
                _json(import_persona_bundle(workspace, _load(args.bundle)))
            elif args.command == "assign":
                key = _token(args.assignment_key_env)
                candidates = search_personas(
                    workspace,
                    engine=args.engine,
                    product=args.product,
                    major=args.major,
                    min_major=args.min_major,
                    max_major=args.max_major,
                    device_class=args.device_class,
                    os_family=args.os_family,
                    country=args.country,
                    locale=args.locale,
                    language=args.language,
                    tags=args.tag,
                    include_incoherent=args.include_incoherent,
                )
                _json(assign_persona(workspace, key, candidates))
            return 0
        if args.area == "network":
            workspace = _workspace(args)
            if args.command == "add":
                _json(add_network_route(workspace, _load(args.document)))
            elif args.command == "create-direct":
                _json(
                    add_network_route(
                        workspace,
                        build_network_route(
                            route_id=args.route_id,
                            name=args.name,
                            geography={
                                "country": args.country,
                                "locale": args.locale,
                                "timezone": args.timezone,
                            },
                            preflight_url=args.preflight_url,
                        ),
                    )
                )
            elif args.command == "create-proxy":
                if bool(args.username_env) != bool(args.password_env):
                    raise ContractError(
                        "proxy username/password environment references must be supplied together"
                    )
                auth = (
                    {
                        "username_env": args.username_env,
                        "password_env": args.password_env,
                    }
                    if args.username_env
                    else None
                )
                _json(
                    add_network_route(
                        workspace,
                        build_network_route(
                            route_id=args.route_id,
                            name=args.name,
                            mode="proxy",
                            endpoint={
                                "protocol": args.protocol,
                                "host": args.host,
                                "port": args.port,
                            },
                            auth=auth,
                            geography={
                                "country": args.country,
                                "locale": args.locale,
                                "timezone": args.timezone,
                            },
                            preflight_url=args.preflight_url,
                        ),
                    )
                )
            elif args.command == "list":
                _json({"routes": list_network_routes(workspace)})
            elif args.command == "preflight":
                _json(
                    preflight_network_route(
                        resolve_network_route(
                            load_network_route(workspace, args.route_id)
                        ),
                        args.probe_url,
                    )
                )
            elif args.command == "align":
                _json(
                    validate_geo_alignment(
                        load_network_route(workspace, args.route_id),
                        _load(args.observation),
                    )
                )
            elif args.command == "observe-align":
                _json(
                    observe_geo_alignment(
                        load_network_route(workspace, args.route_id),
                        browser_locale=args.browser_locale,
                        browser_timezone=args.browser_timezone,
                    )
                )
            return 0
        if args.area == "transport":
            if args.command == "fingerprint":
                record = capture_attested_client_hello(
                    args.repository_root.absolute(),
                    args.executable.absolute(),
                    timeout_seconds=args.timeout_seconds,
                )
                if args.output is None:
                    _json(record)
                else:
                    destination = _write_transport_json_checked(args.output, record)
                    _json(
                        {
                            "schema": (
                                "browser-core.transport-fingerprint-publication/1"
                            ),
                            "output": str(destination),
                            "digest_sha256": record["digest_sha256"],
                            "core_build": record["core_build"],
                        }
                    )
                return 0
            if args.command == "http2-fingerprint":
                record = capture_attested_http2_fingerprint(
                    args.repository_root.absolute(),
                    args.executable.absolute(),
                    args.certificate.resolve(),
                    args.private_key.resolve(),
                    timeout_seconds=args.timeout_seconds,
                )
                if args.output is None:
                    _json(record)
                else:
                    destination = _write_transport_json_checked(args.output, record)
                    _json(
                        {
                            "schema": (
                                "browser-core.http2-fingerprint-publication/1"
                            ),
                            "output": str(destination),
                            "digest_sha256": record["digest_sha256"],
                            "core_build": record["core_build"],
                        }
                    )
                return 0
            if args.command == "http2-evidence":
                evidence = capture_attested_http2_evidence(
                    args.repository_root.absolute(),
                    args.executable.absolute(),
                    args.certificate.resolve(),
                    args.private_key.resolve(),
                    timeout_seconds=args.timeout_seconds,
                )
                if args.output is None:
                    _json(evidence)
                else:
                    destination = _write_transport_json_checked(args.output, evidence)
                    _json(
                        {
                            "schema": "browser-core.http2-evidence-publication/1",
                            "output": str(destination),
                            "fingerprint_digest_sha256": evidence["fingerprint"][
                                "digest_sha256"
                            ],
                            "header_order_digest_sha256": evidence["header_order"][
                                "digest_sha256"
                            ],
                            "core_build": evidence["fingerprint"]["core_build"],
                        }
                    )
                return 0
            if args.command == "http2-evidence-check":
                report = compare_http2_capture_evidence(
                    load_http2_capture_evidence(args.current),
                    load_http2_evidence_baseline(args.baseline)["evidence"],
                )
                _json(report)
                return 0 if report["passed"] else 1
            if args.command == "approve-http2-evidence-baseline":
                _json(
                    approve_http2_evidence_baseline(
                        _workspace(args),
                        current_id=args.current_id,
                        baseline_id=args.baseline_id,
                        expected_digest=args.expected_digest,
                    )
                )
                return 0
            if args.command == "http2-check":
                report = compare_http2_fingerprints(
                    load_http2_fingerprint(args.current),
                    load_http2_baseline(args.baseline)["fingerprint"],
                )
                _json(report)
                return 0 if report["passed"] else 1
            if args.command == "approve-http2-baseline":
                _json(
                    approve_http2_baseline(
                        _workspace(args),
                        current_id=args.current_id,
                        baseline_id=args.baseline_id,
                        expected_digest=args.expected_digest,
                    )
                )
                return 0
            if args.command == "suite-check":
                report = compare_transport_suite(
                    load_transport_fingerprint(args.current_client_hello),
                    load_transport_baseline(args.client_hello_baseline),
                    load_http2_fingerprint(args.current_http2),
                    load_http2_baseline(args.http2_baseline),
                )
                _json(report)
                return 0 if report["passed"] else 1
            if args.command == "evidence-suite-check":
                report = compare_transport_evidence_suite(
                    load_transport_fingerprint(args.current_client_hello),
                    load_transport_baseline(args.client_hello_baseline),
                    load_http2_capture_evidence(args.current_http2_evidence),
                    load_http2_evidence_baseline(args.http2_evidence_baseline),
                )
                _json(report)
                return 0 if report["passed"] else 1
            if args.command == "approve-baseline":
                _json(
                    approve_transport_baseline(
                        _workspace(args),
                        current_id=args.current_id,
                        baseline_id=args.baseline_id,
                        expected_digest=args.expected_digest,
                    )
                )
                return 0
            report = compare_transport_fingerprints(
                load_transport_fingerprint(args.current),
                load_transport_fingerprint(args.baseline),
            )
            _json(report)
            return 0 if report["passed"] else 1
        if args.area == "kernel":
            if args.command == "list":
                _json(
                    {
                        "kernels": discover_kernels(
                            ROOT, browser_core_executable=args.browser_core_executable
                        ),
                        "physical_mobile": discover_physical_mobile(),
                    }
                )
            elif args.command == "devices":
                _json({"devices": playwright_device_catalog(args.pattern)})
            elif args.command == "probe":
                kernels = {item["id"]: item for item in discover_kernels(ROOT)}
                if args.kernel_id not in kernels:
                    raise ContractError("unknown kernel ID")
                _json(
                    probe_playwright_kernel(
                        kernels[args.kernel_id],
                        device_from_playwright(
                            args.device_preset,
                            locale=args.locale,
                            timezone=args.timezone,
                        ),
                    )
                )
            elif args.command == "physical-list":
                _json({"physical_mobile": discover_physical_mobile()})
            elif args.command == "physical-probe":
                _json(probe_physical_android(timeout_seconds=args.timeout_seconds))
            return 0
        if args.area == "control":
            if args.command == "remote-health":
                _json(ControlClient(args.service_url).health())
                return 0
            if args.command.startswith("remote-"):
                client = ControlClient(args.service_url, _token(args.token_env))
                if args.command == "remote-record-get":
                    _json(
                        client.get_record(args.workspace_id, args.kind, args.record_id)
                    )
                elif args.command == "remote-record-put":
                    _json(
                        client.put_record(
                            args.workspace_id,
                            args.kind,
                            args.record_id,
                            _load(args.payload),
                            expected_revision=args.expected_revision,
                        )
                    )
                elif args.command == "remote-artifact-put":
                    _json(
                        client.put_artifact(
                            args.workspace_id,
                            _stable_bytes(
                                args.path,
                                maximum=MAX_CLI_ARTIFACT_BYTES,
                                label="remote artifact input",
                            ),
                            media_type=args.media_type,
                            visibility=args.visibility,
                        )
                    )
                elif args.command == "remote-artifact-get":
                    content = client.get_artifact(args.workspace_id, args.digest)
                    destination = _publish_remote_artifact_checked(args.output, content)
                    _json({"output": str(destination), "bytes": len(content)})
                elif args.command == "remote-audit-verify":
                    _json(client.verify_audit(args.workspace_id))
                elif args.command == "remote-token-revoke":
                    _json(client.revoke_token(args.workspace_id, args.token_id))
                return 0
            store = _store(args)
            if args.command == "bootstrap":
                token_destination = args.token_out.absolute()
                result = store.bootstrap(
                    workspace_id=args.workspace_id,
                    workspace_name=args.workspace_name,
                    owner_id=args.owner_id,
                    owner_name=args.owner_name,
                    token_ttl_hours=args.token_ttl_hours,
                    max_running=args.max_running,
                    max_queued=args.max_queued,
                    publish_secret=lambda token: _publish_secret_checked(token_destination, token),
                )
                result.pop("token")
                _json({**result, "token_file": str(token_destination)})
            elif args.command == "serve":
                with serve_control(
                    store,
                    ServiceConfig(args.host, args.port, args.tls_cert, args.tls_key),
                ) as url:
                    print(url, flush=True)
                    import threading

                    threading.Event().wait()
            else:
                principal = store.authenticate(_token(args.token_env))
                if args.command == "workspace-create":
                    _json(
                        store.create_workspace(
                            principal, workspace_id=args.workspace_id, name=args.name
                        )
                    )
                elif args.command == "member-add":
                    store.add_member(
                        principal,
                        args.workspace_id,
                        user_id=args.user_id,
                        display_name=args.display_name,
                        role=args.role,
                    )
                    _json({"added": args.user_id, "role": args.role})
                elif args.command == "token-issue":
                    token_destination = args.token_out.absolute()
                    store.issue_token(
                        principal,
                        args.workspace_id,
                        args.user_id,
                        ttl_hours=args.ttl_hours,
                        publish_secret=lambda token: _publish_secret_checked(token_destination, token),
                    )
                    _json(
                        {
                            "user_id": args.user_id,
                            "token_file": str(token_destination),
                        }
                    )
                elif args.command == "token-revoke":
                    store.revoke_token(principal, args.workspace_id, args.token_id)
                    _json({"token_id": args.token_id, "revoked": True})
            return 0
        if args.area == "fleet":
            if args.command == "remote-worker-once":
                client = ControlClient(args.service_url, _token(args.worker_token_env))
                result = run_remote_worker_once(
                    client,
                    repository_root=ROOT,
                    workspace=_workspace(args),
                    lease_seconds=args.lease_seconds,
                )
                _json({"leased": result is not None, "job": result})
                return 0
            if args.command in {
                "remote-enqueue",
                "remote-status",
                "remote-jobs",
                "remote-job-get",
            }:
                client = ControlClient(args.service_url, _token(args.token_env))
                if args.command == "remote-enqueue":
                    _json(
                        client.enqueue_job(
                            args.workspace_id,
                            kind=args.kind,
                            payload=_load(args.payload),
                            requirements=sorted(set(args.requirement)),
                            idempotency_key=_token(args.idempotency_key_env),
                        )
                    )
                elif args.command == "remote-status":
                    _json(client.fleet_status(args.workspace_id))
                elif args.command == "remote-jobs":
                    _json(client.list_jobs(args.workspace_id))
                else:
                    _json(client.get_job(args.workspace_id, args.job_id))
                return 0
            store = _store(args)
            if args.command == "worker-once":
                worker = store.authenticate_worker(_token(args.worker_token_env))
                result = run_worker_once(
                    store,
                    worker,
                    repository_root=ROOT,
                    workspace=_workspace(args),
                    lease_seconds=args.lease_seconds,
                )
                _json({"leased": result is not None, "job": result})
                return 0
            principal = store.authenticate(_token(args.token_env))
            if args.command == "worker-register":
                token_destination = args.worker_token_out.absolute()
                result = store.register_worker(
                    principal,
                    args.workspace_id,
                    args.worker_id,
                    name=args.name,
                    capabilities=sorted(set(args.capability)),
                    max_slots=args.max_slots,
                    publish_secret=lambda token: _publish_secret_checked(
                        token_destination, token,
                    ),
                )
                result.pop("worker_token")
                _json(
                    {
                        **result,
                        "worker_token_file": str(token_destination),
                    }
                )
            elif args.command == "worker-scope":
                store.add_worker_scope(principal, args.workspace_id, args.worker_id)
                _json({"worker_id": args.worker_id, "workspace_id": args.workspace_id})
            elif args.command == "enqueue":
                _json(
                    store.enqueue_job(
                        principal,
                        args.workspace_id,
                        kind=args.kind,
                        payload=_load(args.payload),
                        requirements=sorted(set(args.requirement)),
                        idempotency_key=_token(args.idempotency_key_env),
                    )
                )
            elif args.command == "status":
                _json(store.fleet_status(principal, args.workspace_id))
            elif args.command == "jobs":
                _json(store.list_jobs(principal, args.workspace_id))
            elif args.command == "job-get":
                _json(store.get_job(principal, args.workspace_id, args.job_id))
            return 0
    except ContractError as exc:
        print(f"browser-platform: {exc}", file=sys.stderr)
        return 2
    except (OSError, ValueError) as exc:
        print(f"browser-platform: operation failed ({type(exc).__name__})", file=sys.stderr)
        return 2
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
