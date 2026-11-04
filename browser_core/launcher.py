from __future__ import annotations

import json
import os
import re
import stat
import subprocess
import sys
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock
from typing import Any

from .build import executable_evidence
from .chromium_arguments import classify_arguments
from .cdp import observe_runtime_identity, realize_native_viewport
from .control_files import (
    MAX_GATEWAY_CONTROL_BYTES,
    MAX_SESSION_DOCUMENT_BYTES,
    load_canonical_json_document,
    publish_bytes_exclusive,
    publish_json_exclusive_result,
    read_bounded_control_snapshot_result,
    remove_control_conditionally,
)
from .contracts import ContractError, RUN_ID_RE, validate_session
from .process import observe_process
from .network import (
    load_network_route,
    observe_geo_alignment,
    preflight_network_route,
    resolve_network_route,
)
from .numeric import is_finite_number
from .native_paths import native_browser_path
from .owned_paths import (
    DirectoryIdentity,
    directory_ancestry_binding,
    directory_identity,
    directory_identity_document,
    prepare_owned_directory_parent,
    require_owned_directory_ancestors,
    remove_owned_directory_tree,
)
from .personas import load_persona, persona_compatible
from .profiles import (
    PROFILE_ID_RE,
    acquire_profile_lock,
    load_profile,
    profile_data_path,
    profile_identity_contract,
    profile_bindings,
    release_profile_lock,
)
from .upstream import verify_upstream
from .inspection_contract import capture_for_allowlist, require_inspection_support
from .trace_scopes import TRACE_CATEGORY_CONTRACT, TRACE_SCOPES
from .recording_limits import MIB, recording_limit_bytes


MAX_DEVTOOLS_ACTIVE_PORT_BYTES = 4096
_DEVTOOLS_BROWSER_PATH = b"/devtools/browser"
_DEVTOOLS_BROWSER_UUID_V4_RE = re.compile(
    rb"^/devtools/browser/[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-"
    rb"[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)
_CONTAINMENT_OVERRIDE_SWITCHES = frozenset(
    {
        "disable-quic",
        "enable-quic",
        "host-resolver-rules",
        "host-rules",
        "no-proxy-server",
        "origin-to-force-quic-on",
        "quic-version",
    }
)

# ``launch_evaluation`` deliberately returns while Chromium is still running.
# Retain the Popen handle until the same-process lifecycle stop has verified exit;
# otherwise CPython destroys the local handle immediately and emits a misleading
# ``subprocess ... is still running`` ResourceWarning on every successful arm.
_LAUNCHED_PROCESS_HANDLES: dict[int, subprocess.Popen[Any]] = {}
_LAUNCHED_PROCESS_HANDLES_LOCK = Lock()


def _retain_launched_process(process: subprocess.Popen[Any]) -> None:
    pid = process.pid
    if isinstance(pid, bool) or not isinstance(pid, int) or pid <= 0:
        raise ContractError("launched-process handle has an invalid pid")
    with _LAUNCHED_PROCESS_HANDLES_LOCK:
        existing = _LAUNCHED_PROCESS_HANDLES.get(pid)
        if existing is not None and existing is not process:
            try:
                status = existing.poll()
            except OSError:
                raise ContractError(
                    "existing launched-process handle status is unavailable"
                ) from None
            if status is None:
                raise ContractError(
                    "live launched-process handle already exists for pid"
                )
            if isinstance(status, bool) or not isinstance(status, int):
                raise ContractError(
                    "existing launched-process handle status is invalid"
                )
        _LAUNCHED_PROCESS_HANDLES[pid] = process


def reap_launched_process(
    pid: int,
    *,
    expected_process: subprocess.Popen[Any] | None = None,
) -> bool:
    """Reap a Browser Core child retained by this interpreter after verified exit."""
    if isinstance(pid, bool) or not isinstance(pid, int) or pid <= 0:
        raise ContractError("launched-process reap pid is invalid")
    with _LAUNCHED_PROCESS_HANDLES_LOCK:
        process = _LAUNCHED_PROCESS_HANDLES.get(pid)
        if process is None or (
            expected_process is not None and process is not expected_process
        ):
            return False
        del _LAUNCHED_PROCESS_HANDLES[pid]
    try:
        status = process.wait(timeout=0)
    except (OSError, subprocess.TimeoutExpired):
        with _LAUNCHED_PROCESS_HANDLES_LOCK:
            _LAUNCHED_PROCESS_HANDLES.setdefault(pid, process)
        return False
    if isinstance(status, bool) or not isinstance(status, int):
        with _LAUNCHED_PROCESS_HANDLES_LOCK:
            _LAUNCHED_PROCESS_HANDLES.setdefault(pid, process)
        return False
    return True


@dataclass(frozen=True)
class EvaluationLaunch:
    executable: Path
    workspace: Path
    headless: bool = False
    timeout_seconds: float = 30.0
    extra_args: tuple[str, ...] = ()
    profile_id: str | None = None
    persona_id: str | None = None
    network_route_id: str | None = None
    trace_mode: str = "on"
    trace_scope: str = "broad"
    allow_unverified_executable: bool = False
    # Internal deny-proxy endpoint plus the one exact loopback origin port that
    # may bypass it. User-supplied proxy flags remain forbidden.
    local_containment_proxy: tuple[str, int, int] | None = None
    live_trace: bool = False
    inspect_values: bool = False
    inspection_allowlist: str = 'fingerprint-v2'
    recording_limit_mib: int | None = None
    recording_parts: int | None = None


@dataclass
class _OwnedControl:
    path: Path
    body: bytes
    identity: tuple[int, int, int, int, int, int]
    maximum: int


@dataclass
class _OwnedDirectory:
    path: Path
    identity: DirectoryIdentity
    ancestry: tuple[DirectoryIdentity, ...]


@dataclass(frozen=True)
class _GatewayReadiness:
    document: dict[str, Any]
    control: _OwnedControl


@dataclass
class _LaunchOwnership:
    run_id: str | None = None
    profile_lock: Path | None = None
    gateway_process: subprocess.Popen[Any] | None = None
    gateway_lease: _OwnedControl | None = None
    gateway_ready: _OwnedControl | None = None
    browser_process: subprocess.Popen[Any] | None = None
    session_path: _OwnedControl | None = None
    ephemeral_profile: _OwnedDirectory | None = None


def new_run_id() -> str:
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return f"core-{timestamp}-{uuid.uuid4().hex[:8]}"


def managed_startup_target(
    extra_args: tuple[str, ...], run_id: str
) -> tuple[tuple[str, ...], str]:
    """Return launch arguments and the one page URL owned by this run."""
    validate_evaluation_extra_args(extra_args)
    if not isinstance(run_id, str) or not RUN_ID_RE.fullmatch(run_id):
        raise ContractError("evaluation run ID is invalid")
    positional = classify_arguments(extra_args).positional
    if len(positional) > 1:
        raise ContractError(
            "evaluation launch accepts at most one positional startup target"
        )
    if positional:
        return extra_args, positional[0]
    # Chromium canonicalizes an explicit about:blank launch to chrome://newtab/,
    # which destroys the nonce and makes restored tabs ambiguous. A fully
    # percent-encoded, inert data document is retained verbatim in /json/list.
    target_url = (
        "data:text/html,%3Ctitle%3Ebrowser-core-identity-" f"{run_id}%3C%2Ftitle%3E"
    )
    return (*extra_args, target_url), target_url


def _validated_launch_path(value: Any, *, label: str) -> str:
    if not isinstance(value, Path):
        raise ContractError(f"evaluation {label} must be a Path")
    rendered = str(value)
    try:
        encoded = rendered.encode("utf-8")
    except UnicodeEncodeError:
        raise ContractError(f"evaluation {label} is invalid") from None
    if (
        not rendered
        or len(encoded) > 32 * 1024
        or any(ord(character) < 32 or ord(character) == 127 for character in rendered)
    ):
        raise ContractError(f"evaluation {label} is invalid")
    return rendered


def validate_workspace(workspace: Path, repository_root: Path) -> Path:
    _validated_launch_path(workspace, label="workspace")
    _validated_launch_path(repository_root, label="repository root")
    if not workspace.is_absolute():
        raise ContractError("Browser Core workspace must be absolute")
    if ".." in workspace.parts:
        raise ContractError("Browser Core workspace path is ambiguous")
    selected = workspace.absolute()
    ancestors = tuple(reversed((selected, *selected.parents)))
    initial_ancestors = tuple(
        directory_identity(ancestor, label="evaluation workspace")
        for ancestor in ancestors
    )
    try:
        resolved = workspace.resolve()
        root = repository_root.resolve()
    except (OSError, ValueError) as exc:
        raise ContractError(
            f"evaluation workspace resolution failed ({type(exc).__name__})"
        ) from None
    if not resolved.is_absolute():
        raise ContractError("Browser Core workspace must be absolute")
    if any(
        directory_identity(ancestor, label="evaluation workspace") != expected
        for ancestor, expected in zip(ancestors, initial_ancestors)
    ):
        raise ContractError("evaluation workspace changed during resolution")
    if resolved == root or root in resolved.parents or resolved in root.parents:
        raise ContractError("Browser Core workspace must be outside the repository")
    return resolved


def validate_evaluation_extra_args(extra_args: tuple[str, ...]) -> None:
    """Reject arguments that override resources owned by the launcher."""
    if not isinstance(extra_args, tuple) or len(extra_args) > 128:
        raise ContractError(
            "evaluation extra arguments must be a tuple of at most 128 items"
        )
    for argument in extra_args:
        if not isinstance(argument, str) or not argument:
            raise ContractError("evaluation extra argument is invalid")
        try:
            encoded = argument.encode("utf-8")
        except UnicodeEncodeError:
            raise ContractError("evaluation extra argument is invalid") from None
        if len(encoded) > 4096 or any(
            ord(character) < 32 or ord(character) == 127 for character in argument
        ):
            raise ContractError("evaluation extra argument is invalid")
    parsed = classify_arguments(extra_args)
    switches = set(parsed.switches)
    if any(not argument for argument in parsed.positional):
        raise ContractError("evaluation extra argument is invalid")
    if switches & {"user-data-dir", "profile-directory"}:
        raise ContractError(
            "extra arguments cannot override the managed user-data directory"
        )
    if switches & {"remote-debugging-port", "remote-debugging-pipe", "remote-debugging-io-pipes",
                   "remote-debugging-address", "remote-debugging-socket-name",
                   "remote-debugging-targets", "remote-allow-origins"}:
        raise ContractError(
            "extra arguments cannot override the managed evaluation transport"
        )
    if switches & {"proxy-server", "proxy-auto-detect", "proxy-bypass-list", "proxy-pac-url",
                   "no-proxy-server"}:
        raise ContractError("extra arguments cannot override the managed network route")
    if switches & {"force-webrtc-ip-handling-policy", "webrtc-ip-handling-policy"}:
        raise ContractError("extra arguments cannot override the managed WebRTC policy")
    if switches & {"trace-startup", "trace-startup-duration", "trace-startup-file",
                   "trace-startup-format", "trace-startup-record-mode", "trace-startup-owner",
                   "trace-config-file", "trace-perfetto-config-file", "trace-config-handle",
                   "enable-tracing", "enable-tracing-output", "enable-tracing-format"}:
        raise ContractError("extra arguments cannot override the managed trace mode")
    if "browser-core-live-trace" in switches:
        raise ContractError("use the managed live-trace option")
    if "browser-core-recording-limit-mib" in switches:
        raise ContractError("use the managed recording-limit option")
    if "browser-core-recording-parts" in switches:
        raise ContractError("use the managed recording-parts option")
    if "browser-core-inspect-values" in switches:
        raise ContractError("use the managed inspect-values option")
    if switches & {"browser-core-evaluation", "single-argument", "type"}:
        raise ContractError("extra arguments cannot override managed process or target ownership")


def evaluation_command(
    executable: Path,
    profile: Path,
    trace_path: Path | None,
    run_id: str,
    *,
    headless: bool,
    extra_args: tuple[str, ...],
    local_gateway: tuple[str, int] | None = None,
    local_containment_proxy: tuple[str, int, int] | None = None,
    webrtc_policy: str | None = None,
    trace_mode: str = "on",
    trace_scope: str = "broad",
    live_trace: bool = False,
    inspect_values: bool = False,
    inspection_allowlist: str = 'fingerprint-v2',
    recording_limit_mib: int | None = None,
    recording_parts: int | None = None,
) -> list[str]:
    executable_text = _validated_launch_path(executable, label="executable")
    profile_text = _validated_launch_path(profile, label="profile")
    trace_text = (
        None
        if trace_path is None
        else _validated_launch_path(trace_path, label="trace path")
    )
    validate_evaluation_extra_args(extra_args)
    if local_containment_proxy is not None and any(
        switch in _CONTAINMENT_OVERRIDE_SWITCHES
        for switch in classify_arguments(extra_args).switches
    ):
        raise ContractError(
            "extra arguments cannot override the managed local containment policy"
        )
    if not isinstance(run_id, str) or not RUN_ID_RE.fullmatch(run_id):
        raise ContractError("evaluation run ID is invalid")
    if not isinstance(headless, bool):
        raise ContractError("evaluation headless flag must be boolean")
    if not isinstance(trace_mode, str) or trace_mode not in {"on", "off"}:
        raise ContractError("trace mode must be on or off")
    if not isinstance(trace_scope, str) or trace_scope not in TRACE_SCOPES:
        raise ContractError(
            "trace scope must be causal, causal-stream, encoding, broad, source-identity, or source-context"
        )
    if trace_mode == "on" and trace_path is None:
        raise ContractError("trace mode on requires a managed trace path")
    if trace_mode == "off" and trace_path is not None:
        raise ContractError("trace mode off cannot retain a trace path")
    if not isinstance(live_trace, bool) or (live_trace and trace_mode != "on"):
        raise ContractError("live trace must be boolean and requires recording on")
    byte_limit=recording_limit_bytes(recording_limit_mib,live=live_trace)
    from .recording_parts import recording_parts as validate_recording_parts
    part_count=validate_recording_parts(recording_parts,byte_limit,live=live_trace)
    if not isinstance(inspect_values, bool) or (inspect_values and trace_mode != "on"):
        raise ContractError("value inspection must be boolean and requires recording on")
    if capture_for_allowlist(inspection_allowlist) is None:
        raise ContractError('unsupported native inspection version')
    command = [
        executable_text,
        f"--user-data-dir={profile_text}",
        "--remote-debugging-port=0",
        "--no-first-run",
        "--no-default-browser-check",
        "--browser-core-evaluation",
        # Research must continue when an inspector or another app covers the
        # window. Chromium otherwise defers native screen-rectangle updates,
        # leaving a newly created renderer's outer dimensions at zero.
        "--disable-backgrounding-occluded-windows",
    ]
    if trace_mode == "on":
        if live_trace:
            command.append("--browser-core-live-trace")
            command.append(f"--browser-core-recording-limit-mib={byte_limit//MIB}")
            if part_count>1:
                command.append(f"--browser-core-recording-parts={part_count}")
        if inspect_values:
            command.append('--browser-core-inspect-values='+inspection_allowlist)
        categories = ",".join(TRACE_SCOPES[trace_scope])
        command.extend(
            [
                f"--trace-startup={categories}",
                "--trace-startup-format=proto",
                "--trace-startup-duration=0",
                "--trace-startup-record-mode=record-continuously",
                f"--trace-startup-file={trace_text}",
            ]
        )
    if headless:
        command.append("--headless=new")
    if local_containment_proxy is not None and (
        local_gateway is not None or webrtc_policy is not None
    ):
        raise ContractError("managed network route and containment proxy are incompatible")
    if local_gateway is not None:
        if not isinstance(local_gateway, tuple) or len(local_gateway) != 2:
            raise ContractError("managed local gateway is invalid")
        host, port = local_gateway
        if (
            host != "127.0.0.1"
            or isinstance(port, bool)
            or not isinstance(port, int)
            or not 1 <= port <= 65535
        ):
            raise ContractError("managed local gateway is invalid")
        command.append(f"--proxy-server=http://{host}:{port}")
    if local_containment_proxy is not None:
        if (
            not isinstance(local_containment_proxy, tuple)
            or len(local_containment_proxy) != 3
        ):
            raise ContractError("managed local containment proxy is invalid")
        host, proxy_port, bypass_port = local_containment_proxy
        if (
            host != "127.0.0.1"
            or any(
                isinstance(port, bool)
                or not isinstance(port, int)
                or not 1 <= port <= 65535
                for port in (proxy_port, bypass_port)
            )
        ):
            raise ContractError("managed local containment proxy is invalid")
        command.extend(
            (
                f"--proxy-server=http://{host}:{proxy_port}",
                f"--proxy-bypass-list=<-loopback>;127.0.0.1:{bypass_port}",
                "--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
                "--disable-quic",
            )
        )
    if webrtc_policy is not None and (
        not isinstance(webrtc_policy, str)
        or webrtc_policy not in {"default", "route-only"}
    ):
        raise ContractError("managed WebRTC policy is invalid")
    if webrtc_policy == "route-only":
        command.append("--force-webrtc-ip-handling-policy=disable_non_proxied_udp")
    command.extend(extra_args)
    # Current Chromium rejects multiple positional targets in headless mode.
    # Keep the deterministic blank target only when the caller did not supply
    # an explicit startup target of its own (for example, the native smoke
    # fixture URL).
    if not classify_arguments(extra_args).positional:
        command.append("about:blank")
    if os.name == "nt":
        # CreateProcessW counts the fully quoted UTF-16 command line and NUL.
        try:
            command_units = len(subprocess.list2cmdline(command).encode("utf-16-le")) // 2
        except UnicodeEncodeError:
            raise ContractError("evaluation command line is invalid") from None
        if command_units > 32766:
            raise ContractError("evaluation command line exceeds the Windows limit")
    return command


def validate_evaluation_launch(config: EvaluationLaunch) -> EvaluationLaunch:
    if not isinstance(config, EvaluationLaunch):
        raise ContractError("evaluation launch configuration is invalid")
    if not isinstance(config.executable, Path) or not isinstance(
        config.workspace, Path
    ):
        raise ContractError("evaluation executable and workspace must be paths")
    if not isinstance(config.headless, bool):
        raise ContractError("evaluation headless flag must be boolean")
    if not isinstance(config.allow_unverified_executable, bool):
        raise ContractError("allow-unverified-executable must be boolean")
    if not isinstance(config.live_trace, bool) or (config.live_trace and config.trace_mode != "on"):
        raise ContractError("live trace must be boolean and requires recording on")
    from .recording_parts import recording_parts as validate_recording_parts
    validate_recording_parts(config.recording_parts,
                            recording_limit_bytes(config.recording_limit_mib,live=config.live_trace),
                            live=config.live_trace)
    if config.live_trace and config.allow_unverified_executable:
        raise ContractError("live trace requires an attested Browser Core executable")
    if not isinstance(config.inspect_values, bool) or (config.inspect_values and config.trace_mode != "on"):
        raise ContractError("value inspection must be boolean and requires recording on")
    if config.inspect_values and config.allow_unverified_executable:
        raise ContractError("value inspection requires an attested Browser Core executable")
    if capture_for_allowlist(config.inspection_allowlist) is None:
        raise ContractError('unsupported native inspection version')
    if not is_finite_number(config.timeout_seconds) or not (
        0 < config.timeout_seconds <= 300
    ):
        raise ContractError("evaluation timeout must be finite and in (0, 300]")
    validate_evaluation_extra_args(config.extra_args)
    if config.local_containment_proxy is not None:
        # Reuse command construction's exact closed endpoint contract without
        # touching the filesystem or starting a process.
        evaluation_command(
            config.executable,
            config.workspace,
            None,
            "containment-validation",
            headless=False,
            extra_args=config.extra_args,
            local_containment_proxy=config.local_containment_proxy,
            trace_mode="off",
        )
    for value, label in (
        (config.profile_id, "profile"),
        (config.persona_id, "persona"),
        (config.network_route_id, "network route"),
    ):
        if value is not None and (
            not isinstance(value, str) or not PROFILE_ID_RE.fullmatch(value)
        ):
            raise ContractError(f"evaluation {label} ID is invalid")
    if not isinstance(config.trace_mode, str) or config.trace_mode not in {"on", "off"}:
        raise ContractError("trace mode must be on or off")
    if not isinstance(config.trace_scope, str) or config.trace_scope not in TRACE_SCOPES:
        raise ContractError(
            "trace scope must be causal, causal-stream, encoding, broad, source-identity, or source-context"
        )
    return config


def _snapshot_identity(
    metadata: os.stat_result,
) -> tuple[int, int, int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
        int(getattr(metadata, "st_file_attributes", 0)),
    )


def _is_partial_devtools_target(value: bytes) -> bool:
    if not value or _DEVTOOLS_BROWSER_PATH.startswith(value):
        return True
    prefix = _DEVTOOLS_BROWSER_PATH + b"/"
    if not value.startswith(prefix):
        return False
    suffix = value[len(prefix) :]
    if len(suffix) >= 36:
        return False
    for index, byte in enumerate(suffix):
        if index in {8, 13, 18, 23}:
            if byte != ord("-"):
                return False
        elif index == 14:
            if byte != ord("4"):
                return False
        elif index == 19:
            if byte not in b"89ab":
                return False
        elif byte not in b"0123456789abcdef":
            return False
    return True


def _read_devtools_active_port(active_port: Path) -> int | None:
    if not isinstance(active_port, Path):
        raise ContractError("Chromium DevToolsActivePort path must be a Path")
    bytes_changed = False
    try:
        path_before = os.lstat(active_port)
        attributes = int(getattr(path_before, "st_file_attributes", 0))
        if not stat.S_ISREG(path_before.st_mode) or attributes & 0x400:
            raise ContractError("Chromium DevToolsActivePort is not a regular file")
        if path_before.st_nlink != 1:
            raise ContractError(
                "Chromium DevToolsActivePort must not have additional hard links"
            )
        if path_before.st_size > MAX_DEVTOOLS_ACTIVE_PORT_BYTES:
            raise ContractError("Chromium DevToolsActivePort exceeds 4096 bytes")
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(active_port, flags)
        with os.fdopen(descriptor, "rb", buffering=0) as handle:
            before = os.fstat(handle.fileno())
            attributes = int(getattr(before, "st_file_attributes", 0))
            if not stat.S_ISREG(before.st_mode) or attributes & 0x400:
                raise ContractError("Chromium DevToolsActivePort is not a regular file")
            if before.st_nlink != 1:
                raise ContractError(
                    "Chromium DevToolsActivePort must not have additional hard links"
                )
            if before.st_size > MAX_DEVTOOLS_ACTIVE_PORT_BYTES:
                raise ContractError("Chromium DevToolsActivePort exceeds 4096 bytes")
            body = bytearray()
            while len(body) <= MAX_DEVTOOLS_ACTIVE_PORT_BYTES:
                chunk = handle.read(MAX_DEVTOOLS_ACTIVE_PORT_BYTES + 1 - len(body))
                if not chunk:
                    break
                body.extend(chunk)
            after = os.fstat(handle.fileno())
            if os.name == "nt" and after.st_size == len(body):
                # On Python 3.10 Windows st_ctime is creation time. A writer
                # can restore mtime after a same-size edit, leaving the stat
                # identity unchanged while the bytes we read are stale.
                handle.seek(0)
                offset = 0
                original = memoryview(body)
                while offset < len(body):
                    observed = handle.read(min(4096, len(body) - offset))
                    if not observed or observed != original[offset:offset + len(observed)]:
                        bytes_changed = True
                        break
                    offset += len(observed)
                if not bytes_changed and handle.read(1):
                    bytes_changed = True
        path_after = os.lstat(active_port)
    except (FileNotFoundError, PermissionError):
        return None
    except ContractError:
        raise
    except OSError as exc:
        raise ContractError(
            f"cannot read Chromium DevToolsActivePort ({type(exc).__name__})"
        ) from None

    if len(body) > MAX_DEVTOOLS_ACTIVE_PORT_BYTES:
        raise ContractError("Chromium DevToolsActivePort exceeds 4096 bytes")
    if after.st_nlink != 1 or path_after.st_nlink != 1:
        raise ContractError(
            "Chromium DevToolsActivePort must not have additional hard links"
        )
    if (
        bytes_changed
        or _snapshot_identity(path_before) != _snapshot_identity(before)
        or _snapshot_identity(before) != _snapshot_identity(after)
        or _snapshot_identity(after) != _snapshot_identity(path_after)
        or after.st_size != len(body)
    ):
        return None
    if not body:
        return None

    lines = bytes(body).split(b"\n")
    if len(lines) == 1:
        if len(lines[0]) <= 5 and lines[0].isdigit():
            return None
        raise ContractError("Chromium DevToolsActivePort is malformed")
    if len(lines) != 2 or not lines[0]:
        raise ContractError("Chromium DevToolsActivePort is malformed")
    if len(lines[0]) > 5 or not lines[0].isdigit():
        raise ContractError("Chromium DevToolsActivePort port is invalid")
    port = int(lines[0])
    if not 1 <= port <= 65535:
        raise ContractError("Chromium DevToolsActivePort port is invalid")

    target = lines[1]
    if target == _DEVTOOLS_BROWSER_PATH or _DEVTOOLS_BROWSER_UUID_V4_RE.fullmatch(
        target
    ):
        rebound = read_bounded_control_snapshot_result(
            active_port,
            maximum=MAX_DEVTOOLS_ACTIVE_PORT_BYTES,
            label="Chromium DevToolsActivePort",
            require_single_link=True,
        )
        expected_identity = (
            after.st_dev,
            after.st_ino,
            after.st_mode & ~0o111 if os.name == "nt" else after.st_mode,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        )
        if (
            rebound.state != "complete"
            or rebound.body != bytes(body)
            or rebound.identity != expected_identity
        ):
            return None
        return port
    if _is_partial_devtools_target(target):
        return None
    raise ContractError("Chromium DevToolsActivePort target is invalid")


def _wait_for_cdp(
    profile: Path, process: subprocess.Popen[Any], timeout_seconds: float
) -> int:
    active_port = profile / "DevToolsActivePort"
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        exit_code = process.poll()
        if exit_code is not None:
            raise ContractError(
                f"Chromium exited before CDP became ready (exit {exit_code})"
            )
        port = _read_devtools_active_port(active_port)
        if port is not None:
            exit_code = process.poll()
            if exit_code is not None:
                raise ContractError(
                    f"Chromium exited before CDP became ready (exit {exit_code})"
                )
            if time.monotonic() >= deadline:
                raise ContractError("timed out waiting for Chromium evaluation transport")
            return port
        remaining = deadline - time.monotonic()
        if remaining > 0:
            time.sleep(min(0.05, remaining))
    raise ContractError("timed out waiting for Chromium evaluation transport")


def clear_stale_evaluation_transport(profile: Path) -> None:
    """Remove only the exact bounded stale readiness entry accepted here."""
    active_port = profile / "DevToolsActivePort"
    snapshot = read_bounded_control_snapshot_result(
        active_port,
        maximum=MAX_DEVTOOLS_ACTIVE_PORT_BYTES,
        label="managed DevToolsActivePort",
        require_single_link=True,
    )
    if snapshot.state == "missing":
        return
    if snapshot.state != "complete":
        raise ContractError(f"managed DevToolsActivePort is {snapshot.state}")
    assert snapshot.body is not None and snapshot.identity is not None
    remove_control_conditionally(
        active_port,
        expected_body=snapshot.body,
        expected_identity=snapshot.identity,
        maximum=MAX_DEVTOOLS_ACTIVE_PORT_BYTES,
        label="managed DevToolsActivePort",
        missing_ok=True,
    )


def _wait_for_gateway(
    ready_path: Path,
    process: subprocess.Popen[Any],
    timeout_seconds: float,
    route: dict[str, Any],
) -> _GatewayReadiness:
    if not is_finite_number(timeout_seconds) or not 0 < timeout_seconds <= 300:
        raise ContractError("network credential gateway readiness timeout is invalid")
    deadline = time.monotonic() + float(timeout_seconds)

    def require_running() -> None:
        try:
            exit_code = process.poll()
        except OSError as exc:
            raise ContractError(
                f"network credential gateway status failed ({type(exc).__name__})"
            ) from None
        if exit_code is not None:
            if isinstance(exit_code, bool) or not isinstance(exit_code, int):
                raise ContractError(
                    "network credential gateway process status is invalid"
                )
            raise ContractError(
                f"network credential gateway exited before readiness (exit {exit_code})"
            )

    while time.monotonic() < deadline:
        require_running()
        snapshot = read_bounded_control_snapshot_result(
            ready_path,
            maximum=MAX_GATEWAY_CONTROL_BYTES,
            label="network credential gateway readiness document",
            require_single_link=True,
        )
        if snapshot.state != "complete":
            remaining = deadline - time.monotonic()
            if remaining > 0:
                time.sleep(min(0.05, remaining))
            continue
        assert snapshot.body is not None and snapshot.identity is not None
        document = load_canonical_json_document(
            snapshot.body,
            label="network credential gateway readiness document",
        )
        if (
            set(document)
            != {"schema", "run_id", "route_id", "route_sha256_16", "host", "port"}
            or document.get("schema") != "browser-core.gateway-ready/2"
            or document.get("run_id") != ready_path.stem
            or document.get("route_id") != route["id"]
            or document.get("route_sha256_16") != route["integrity_sha256"][:16]
            or document.get("host") != "127.0.0.1"
            or isinstance(document.get("port"), bool)
            or not isinstance(document.get("port"), int)
            or not 1 <= document["port"] <= 65535
        ):
            raise ContractError(
                "network credential gateway readiness document is invalid"
            )
        rebound = read_bounded_control_snapshot_result(
            ready_path,
            maximum=MAX_GATEWAY_CONTROL_BYTES,
            label="network credential gateway readiness document",
            require_single_link=True,
        )
        if (
            rebound.state != "complete"
            or rebound.body != snapshot.body
            or rebound.identity != snapshot.identity
        ):
            raise ContractError(
                "network credential gateway readiness document changed during validation"
            )
        require_running()
        if time.monotonic() >= deadline:
            raise ContractError("timed out waiting for the network credential gateway")
        return _GatewayReadiness(
            document=document,
            control=_OwnedControl(
                path=ready_path,
                body=snapshot.body,
                identity=snapshot.identity,
                maximum=MAX_GATEWAY_CONTROL_BYTES,
            ),
        )
    raise ContractError("timed out waiting for the network credential gateway")


def _start_gateway(
    workspace: Path,
    route: dict[str, Any],
    run_id: str,
    timeout_seconds: float,
    ownership: _LaunchOwnership,
    session_key: str | None = None,
) -> tuple[subprocess.Popen[Any], dict[str, Any]]:
    from .proxy_import import has_proxy_secret, resolve_route_credentials

    if not isinstance(run_id, str) or RUN_ID_RE.fullmatch(run_id) is None:
        raise ContractError("network credential gateway run ID is invalid")
    if not isinstance(ownership, _LaunchOwnership) or ownership.run_id != run_id:
        raise ContractError("network credential gateway ownership is invalid")
    if not is_finite_number(timeout_seconds) or not 0 < timeout_seconds <= 300:
        raise ContractError("network credential gateway start timeout is invalid")
    directory = workspace / "network" / "gateways"
    lease_path = directory / f"{run_id}.lease"
    ready_path = directory / f"{run_id}.json"
    command = [
        sys.executable,
        "-m",
        "browser_core.gateway",
        "--workspace",
        str(workspace),
        "--route-id",
        route["id"],
        "--run-id",
        run_id,
        "--ready-file",
        str(ready_path),
        "--lease-file",
        str(lease_path),
        *(() if session_key is None else ("--session-key", session_key)),
    ]
    if os.name == "nt":
        try:
            command_units = len(subprocess.list2cmdline(command).encode("utf-16-le")) // 2
        except UnicodeEncodeError:
            raise ContractError("network credential gateway command line is invalid") from None
        if command_units > 32766:
            raise ContractError("network credential gateway command line exceeds the Windows limit")
    require_owned_directory_ancestors(
        workspace, label="network credential gateway workspace"
    )
    workspace_identity = directory_identity(
        workspace, label="network credential gateway workspace"
    )
    if workspace_identity is None:
        raise ContractError("network credential gateway workspace is unavailable")
    network_directory = directory.parent
    network_before = directory_identity(
        network_directory, label="network credential gateway directory"
    )
    gateway_before = directory_identity(
        directory, label="network credential gateway directory"
    )
    deadline = time.monotonic() + float(timeout_seconds)

    def remaining_time() -> float:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ContractError("network credential gateway start timed out")
        return remaining

    # The preflight has to use the same credential and the same pinned session
    # the sidecar will use, or it proves nothing about the connection the browser
    # actually gets. Routes with no stored secret take the original path.
    if has_proxy_secret(workspace, route["id"]):
        resolved = resolve_route_credentials(workspace, route, session_key=session_key)
    else:
        resolved = resolve_network_route(route)
    preflight = preflight_network_route(
        resolved,
        route["preflight_url"],
        timeout_seconds=remaining_time(),
    )
    require_owned_directory_ancestors(
        workspace, label="network credential gateway workspace"
    )
    if (
        directory_identity(workspace, label="network credential gateway workspace")
        != workspace_identity
    ):
        raise ContractError("network credential gateway workspace changed after preflight")
    prepare_owned_directory_parent(
        network_directory, label="network credential gateway directory"
    )
    require_owned_directory_ancestors(
        network_directory, label="network credential gateway directory"
    )
    network_after = directory_identity(
        network_directory, label="network credential gateway directory"
    )
    if network_after is None or (network_before is not None and network_after != network_before):
        raise ContractError("network credential gateway directory changed before publication")
    prepare_owned_directory_parent(
        directory, label="network credential gateway directory"
    )
    require_owned_directory_ancestors(
        directory, label="network credential gateway directory"
    )
    gateway_after = directory_identity(
        directory, label="network credential gateway directory"
    )
    if (
        gateway_after is None
        or (gateway_before is not None and gateway_after != gateway_before)
        or directory_identity(
            network_directory, label="network credential gateway directory"
        ) != network_after
    ):
        raise ContractError("network credential gateway directory changed before publication")
    for control_path in (lease_path, ready_path):
        try:
            os.lstat(control_path)
        except FileNotFoundError:
            continue
        except OSError as exc:
            code = getattr(exc, "winerror", None) or exc.errno
            suffix = f" (os_error={code})" if isinstance(code, int) else ""
            raise ContractError(
                "network credential gateway control path inspection failed" + suffix
            ) from None
        raise ContractError("network credential gateway control path already exists")
    lease_publication = publish_json_exclusive_result(
        lease_path,
        {
            "schema": "browser-core.gateway-lease/2",
            "run_id": run_id,
            "route_id": route["id"],
            "route_sha256_16": route["integrity_sha256"][:16],
        },
        maximum=MAX_GATEWAY_CONTROL_BYTES,
        label="network credential gateway lease document",
    )
    ownership.gateway_lease = _OwnedControl(
        path=lease_path,
        body=lease_publication.body,
        identity=lease_publication.identity,
        maximum=MAX_GATEWAY_CONTROL_BYTES,
    )
    creation_flags = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
    process = subprocess.Popen(
        command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        creationflags=creation_flags,
    )
    ownership.gateway_process = process
    identity = observe_process(process.pid)
    readiness = _wait_for_gateway(ready_path, process, remaining_time(), route)
    ready = readiness.document
    ownership.gateway_ready = readiness.control
    return process, {
        "process_identity": identity,
        "endpoint": f"http://127.0.0.1:{ready['port']}",
        "lease_path": str(lease_path.resolve()),
        "ready_path": str(ready_path.resolve()),
        "preflight": preflight,
    }


def _validate_persona_route_pair(
    persona: dict[str, Any] | None, route: dict[str, Any] | None
) -> None:
    if persona is None or route is None:
        return
    for field in ("country", "locale", "timezone"):
        if (
            persona["geography"][field].casefold()
            != route["geography"][field].casefold()
        ):
            raise ContractError(f"persona and network route disagree on {field}")


def _claim_owned_control(
    path: Path,
    expected_body: bytes,
    *,
    maximum: int,
    label: str,
) -> _OwnedControl:
    snapshot = read_bounded_control_snapshot_result(
        path,
        maximum=maximum,
        label=label,
    )
    if (
        snapshot.state != "complete"
        or snapshot.body != expected_body
        or snapshot.identity is None
    ):
        raise ContractError(f"{label} changed before ownership claim")
    return _OwnedControl(
        path=path,
        body=expected_body,
        identity=snapshot.identity,
        maximum=maximum,
    )


def _remove_owned_launch_file(
    control: _OwnedControl | None,
    label: str,
    failures: list[str],
) -> None:
    if control is None:
        return
    try:
        remove_control_conditionally(
            control.path,
            expected_body=control.body,
            expected_identity=control.identity,
            maximum=control.maximum,
            label=label,
            missing_ok=True,
        )
    except ContractError:
        failures.append(f"{label}:conditional-remove")


def _stop_owned_launch_process(
    process: subprocess.Popen[Any] | None,
    label: str,
    deadline: float,
    failures: list[str],
) -> bool:
    if process is None:
        return True
    try:
        status = process.poll()
        if status is not None:
            if not isinstance(status, bool) and isinstance(status, int):
                return True
    except OSError:
        # An unusable status handle is not evidence of exit. Continue through
        # the bounded terminate/kill path and report only final incompleteness.
        pass
    try:
        process.terminate()
    except ProcessLookupError:
        return True
    except OSError:
        # The process may still have exited concurrently. A bounded wait proves
        # that case; otherwise cleanup escalates to kill below.
        pass
    remaining = max(0.0, deadline - time.monotonic())
    try:
        status = process.wait(timeout=remaining)
        if not isinstance(status, bool) and isinstance(status, int):
            return True
    except subprocess.TimeoutExpired:
        pass
    except ProcessLookupError:
        return True
    except OSError:
        # Waiting failed to prove exit. Escalate rather than leaking a child.
        pass
    try:
        process.kill()
    except ProcessLookupError:
        return True
    except OSError as exc:
        code = getattr(exc, "winerror", None)
        if not isinstance(code, int):
            code = exc.errno
        failures.append(f"{label}:kill:{code if isinstance(code, int) else 'unknown'}")
        return False
    remaining = max(0.0, deadline - time.monotonic())
    try:
        status = process.wait(timeout=remaining)
    except (OSError, ProcessLookupError, subprocess.TimeoutExpired) as exc:
        if isinstance(exc, ProcessLookupError):
            return True
        code = getattr(exc, "winerror", None)
        if not isinstance(code, int):
            code = getattr(exc, "errno", None)
        failures.append(
            f"{label}:kill-wait:{code if isinstance(code, int) else 'timeout'}"
        )
        return False
    if isinstance(status, bool) or not isinstance(status, int):
        failures.append(f"{label}:kill-wait:invalid-status")
        return False
    return True


def _abort_evaluation_launch(ownership: _LaunchOwnership) -> tuple[str, ...]:
    failures: list[str] = []
    browser_deadline = time.monotonic() + 5.0
    browser_stopped = _stop_owned_launch_process(
        ownership.browser_process,
        "browser-process",
        browser_deadline,
        failures,
    )
    if ownership.browser_process is not None and browser_stopped:
        if not reap_launched_process(
            ownership.browser_process.pid,
            expected_process=ownership.browser_process,
        ):
            failures.append("browser-process:handle-reap")
    _remove_owned_launch_file(ownership.gateway_lease, "gateway-lease", failures)
    gateway_deadline = time.monotonic() + 5.0
    gateway_stopped = _stop_owned_launch_process(
        ownership.gateway_process,
        "gateway-process",
        gateway_deadline,
        failures,
    )
    if gateway_stopped:
        _remove_owned_launch_file(
            ownership.gateway_ready,
            "gateway-ready",
            failures,
        )
    if browser_stopped:
        _remove_owned_launch_file(
            ownership.session_path,
            "session-document",
            failures,
        )
    if (
        browser_stopped
        and ownership.profile_lock is not None
        and ownership.run_id is not None
    ):
        try:
            release_profile_lock(
                ownership.profile_lock,
                ownership.run_id,
                missing_ok=True,
            )
        except ContractError:
            failures.append("profile-lock:release")
    if browser_stopped and ownership.ephemeral_profile is not None:
        try:
            claimed = ownership.ephemeral_profile
            parent_ancestry = directory_ancestry_binding(
                claimed.path.parent.absolute(), label="ephemeral profile parent"
            )
            if parent_ancestry != claimed.ancestry[:-1]:
                raise ContractError("ephemeral profile parent changed before removal")
            if directory_identity(claimed.path, label="ephemeral profile") is not None:
                if directory_ancestry_binding(
                    claimed.path.absolute(), label="ephemeral profile"
                ) != claimed.ancestry:
                    raise ContractError("ephemeral profile changed before removal")
            remove_owned_directory_tree(
                claimed.path,
                expected_identity=claimed.identity,
                missing_ok=True,
                label="ephemeral profile",
            )
        except ContractError:
            failures.append("ephemeral-profile:conditional-remove")
    return tuple(failures)


def _publish_session_document(
    path: Path,
    session: dict[str, Any],
    ownership: _LaunchOwnership,
) -> dict[str, Any]:
    prepare_owned_directory_parent(path.parent, label="Browser Core session parent")
    publication = publish_json_exclusive_result(
        path,
        session,
        maximum=MAX_SESSION_DOCUMENT_BYTES,
        label="Browser Core session document",
    )
    ownership.session_path = _OwnedControl(
        path=path,
        body=publication.body,
        identity=publication.identity,
        maximum=MAX_SESSION_DOCUMENT_BYTES,
    )
    return validate_session(
        load_canonical_json_document(
            publication.body,
            label="Browser Core session document",
        )
    )


def launch_evaluation(
    config: EvaluationLaunch, repository_root: Path
) -> tuple[Path, dict[str, Any]]:
    ownership = _LaunchOwnership()
    try:
        return _launch_evaluation_owned(config, repository_root, ownership)
    except BaseException as exc:
        cleanup_failures = _abort_evaluation_launch(ownership)
        cleanup_suffix = (
            f"; launch cleanup incomplete ({','.join(cleanup_failures)})"
            if cleanup_failures
            else ""
        )
        if isinstance(exc, ContractError):
            if cleanup_suffix:
                raise ContractError(f"{exc}{cleanup_suffix}") from exc
            raise
        if isinstance(exc, (OSError, ValueError)):
            raise ContractError(
                f"evaluation launch infrastructure failed ({type(exc).__name__})"
                f"{cleanup_suffix}"
            ) from None
        raise


def _launch_evaluation_owned(
    config: EvaluationLaunch,
    repository_root: Path,
    ownership: _LaunchOwnership,
) -> tuple[Path, dict[str, Any]]:
    validate_evaluation_launch(config)
    if config.inspect_values:
        require_inspection_support(repository_root, config.inspection_allowlist)
    executable = config.executable.resolve()
    if not executable.is_file():
        raise ContractError(f"Chromium executable does not exist: {executable}")
    workspace = validate_workspace(config.workspace, repository_root)
    manifest = verify_upstream(repository_root)
    build = executable_evidence(
        repository_root,
        config.executable,
        allow_unverified=config.allow_unverified_executable,
    )
    run_id = new_run_id()
    ownership.run_id = run_id
    profile_lock: Path | None = None
    managed_profile_identity: DirectoryIdentity
    persona = None
    route = None
    if config.profile_id is None:
        profile = workspace / "profiles" / "ephemeral" / run_id
        profile_document = {
            "id": None,
            "persistence": "ephemeral",
            "path": str(profile),
            "lock_path": None,
        }
        identity_contract = None
        if config.persona_id is not None:
            persona = load_persona(workspace, config.persona_id)
        if config.network_route_id is not None:
            route = load_network_route(workspace, config.network_route_id)
    else:
        profile_registry = load_profile(workspace, config.profile_id)
        bindings = profile_bindings(workspace, config.profile_id)
        persona = bindings.get("persona")
        route = bindings.get("network_route")
        if config.persona_id is not None and (
            persona is None or persona["id"] != config.persona_id
        ):
            raise ContractError(
                "launch persona does not match the named profile binding"
            )
        if config.network_route_id is not None and (
            route is None or route["id"] != config.network_route_id
        ):
            raise ContractError(
                "launch network route does not match the named profile binding"
            )
        profile = profile_data_path(workspace, config.profile_id)
        profile_lock = acquire_profile_lock(workspace, config.profile_id, run_id)
        ownership.profile_lock = profile_lock
        profile_document = {
            "id": config.profile_id,
            "persistence": "persistent",
            "path": str(profile),
            "lock_path": str(profile_lock),
        }
        persistent_identity = directory_identity(
            profile,
            label="persistent profile",
        )
        if persistent_identity is None:
            raise ContractError("persistent profile is missing")
        managed_profile_identity = persistent_identity
        managed_profile_ancestry = directory_ancestry_binding(
            profile.absolute(), label="managed browser profile"
        )
        profile_document["directory_identity"] = directory_identity_document(
            persistent_identity
        )
        identity_contract = profile_identity_contract(workspace, config.profile_id)
    _validate_persona_route_pair(persona, route)
    if config.local_containment_proxy is not None and route is not None:
        raise ContractError("network route and local containment are incompatible")
    if persona is not None:
        major = int(manifest["chromium"]["version"].split(".", 1)[0])
        if not persona_compatible(
            persona,
            engine="chromium",
            product="browser-core",
            major=major,
            device_class="desktop",
        ):
            raise ContractError("persona cannot be realized by this Browser Core build")
    if config.trace_mode not in {"on", "off"}:
        raise ContractError("trace mode must be on or off")
    if config.trace_scope not in TRACE_SCOPES:
        raise ContractError(
            "trace scope must be causal, causal-stream, encoding, broad, source-identity, or source-context"
        )
    trace_path = (
        workspace / "traces" / f"{run_id}.perfetto-trace"
        if config.trace_mode == "on"
        else None
    )
    if config.live_trace:
        from .live_trace import require_new_live_artifacts

        require_new_live_artifacts(trace_path,**({'recording_parts':config.recording_parts} if config.recording_parts is not None else {}))
    session_path = workspace / "sessions" / f"{run_id}.json"
    if config.profile_id is None:
        prepare_owned_directory_parent(profile.parent, label="ephemeral profile parent")
        require_owned_directory_ancestors(
            profile.parent, label="ephemeral profile parent"
        )
        profile.mkdir(exist_ok=False)
        require_owned_directory_ancestors(profile, label="ephemeral profile")
        ephemeral_identity = directory_identity(profile, label="ephemeral profile")
        if ephemeral_identity is None:
            raise ContractError("ephemeral profile creation did not persist")
        managed_profile_identity = ephemeral_identity
        managed_profile_ancestry = directory_ancestry_binding(
            profile.absolute(), label="managed browser profile"
        )
        ownership.ephemeral_profile = _OwnedDirectory(
            path=profile,
            identity=ephemeral_identity,
            ancestry=managed_profile_ancestry,
        )
        profile_document["directory_identity"] = directory_identity_document(
            ephemeral_identity
        )
        if persona is not None:
            from .profiles import canonicalize_identity_contract

            canonical, metadata = canonicalize_identity_contract(
                json.dumps(
                    persona["identity_contract"], sort_keys=True, separators=(",", ":")
                ).encode("utf-8")
            )
            identity_path = profile / metadata["file"]
            publish_bytes_exclusive(
                identity_path,
                canonical,
                maximum=64 * 1024,
                label="ephemeral identity contract",
            )
            identity_contract = {**metadata, "path": str(identity_path.resolve())}
    trace_parent_identity: DirectoryIdentity | None = None
    if trace_path is not None:
        prepare_owned_directory_parent(trace_path.parent, label="live trace parent")
        require_owned_directory_ancestors(trace_path.parent, label="live trace parent")
        trace_parent_identity = directory_identity(
            trace_path.parent, label="live trace parent"
        )
        if trace_parent_identity is None:
            raise ContractError("live trace parent is unavailable")
    gateway_process: subprocess.Popen[Any] | None = None
    gateway_document: dict[str, Any] | None = None
    route_preflight: dict[str, Any] | None = None
    local_gateway: tuple[str, int] | None = None
    if route is not None:
        if route["mode"] == "proxy":
            # Pin the sticky exit to the identity, not the run: a named profile
            # must come back to the same IP tomorrow, and a disposable one must
            # not inherit the last disposable's.
            session_key = config.profile_id or (
                persona["id"] if persona is not None else run_id
            )
            gateway_process, gateway_document = _start_gateway(
                workspace, route, run_id, config.timeout_seconds, ownership, session_key
            )
            route_preflight = gateway_document["preflight"]
            endpoint = gateway_document["endpoint"].rsplit(":", 1)
            local_gateway = ("127.0.0.1", int(endpoint[1]))
        else:
            route_preflight = preflight_network_route(
                resolve_network_route(route),
                route["preflight_url"],
                timeout_seconds=config.timeout_seconds,
            )
    launch_args, startup_target_url = managed_startup_target(config.extra_args, run_id)
    if persona is not None:
        from .persona_projection import native_persona_arguments

        # Managed settings must precede any caller's switch terminator.
        launch_args = native_persona_arguments(persona, launch_args) + launch_args
    native_profile = native_browser_path(profile, profile=True)
    native_trace = None if trace_path is None else native_browser_path(trace_path, profile=False)

    def require_managed_profile_identity(phase: str) -> None:
        require_owned_directory_ancestors(profile, label="managed browser profile")
        require_owned_directory_ancestors(
            native_profile, label="native browser profile"
        )
        if (
            directory_ancestry_binding(
                profile.absolute(), label="managed browser profile"
            ) != managed_profile_ancestry
            or directory_identity(profile, label="managed browser profile")
            != managed_profile_identity
            or directory_identity(native_profile, label="native browser profile")
            != managed_profile_identity
        ):
            raise ContractError(f"managed browser profile changed {phase}")
        if trace_path is not None and native_trace is not None:
            require_owned_directory_ancestors(
                trace_path.parent, label="managed browser trace parent"
            )
            require_owned_directory_ancestors(
                native_trace.parent, label="native browser trace parent"
            )
            if (
                directory_identity(
                    trace_path.parent, label="managed browser trace parent"
                )
                != trace_parent_identity
                or directory_identity(
                    native_trace.parent, label="native browser trace parent"
                )
                != trace_parent_identity
            ):
                raise ContractError(f"managed browser trace parent changed {phase}")

    command = evaluation_command(
        executable,
        native_profile,
        native_trace,
        run_id,
        headless=config.headless,
        extra_args=launch_args,
        local_gateway=local_gateway,
        local_containment_proxy=config.local_containment_proxy,
        webrtc_policy=route["policies"]["webrtc"] if route is not None else None,
        trace_mode=config.trace_mode,
        trace_scope=config.trace_scope,
        live_trace=config.live_trace,
        inspect_values=config.inspect_values,
        inspection_allowlist=config.inspection_allowlist,
        recording_limit_mib=config.recording_limit_mib,
        recording_parts=config.recording_parts,
    )
    require_managed_profile_identity("before launch")
    if (
        config.profile_id is not None
        and load_profile(workspace, config.profile_id) != profile_registry
    ):
        raise ContractError("named profile registry changed before launch")
    clear_stale_evaluation_transport(profile)
    creation_flags = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
    process = subprocess.Popen(
        command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        creationflags=creation_flags,
    )
    ownership.browser_process = process
    _retain_launched_process(process)
    try:
        process_identity = observe_process(process.pid)
        port = _wait_for_cdp(profile, process, config.timeout_seconds)
        if persona is not None:
            from .persona_preflight import verify_native_persona

            verify_native_persona(
                persona, f"http://127.0.0.1:{port}", timeout_seconds=config.timeout_seconds,
            )
            viewport = persona["device"]["viewport"]
            realize_native_viewport(
                f"http://127.0.0.1:{port}", startup_target_url,
                viewport["width"], viewport["height"],
                timeout_seconds=config.timeout_seconds,
                # Headless has no toolbar startup animation, so the headed
                # 0.5s anti-animation guard can use a shorter interval there.
                stable_seconds=0.1 if config.headless else 0.5,
            )
        runtime_identity: dict[str, Any] | None = None
        geo_realization: dict[str, Any] | None = None
        if route is not None or persona is not None:
            runtime_identity = observe_runtime_identity(
                f"http://127.0.0.1:{port}",
                startup_target_url,
                timeout_seconds=config.timeout_seconds,
            )
        if persona is not None:
            from .persona_projection import require_native_geography

            require_native_geography(persona, runtime_identity)
        if route is not None:
            geo_realization = observe_geo_alignment(
                route,
                browser_locale=runtime_identity["locale"],
                browser_timezone=runtime_identity["timezone"],
                timeout_seconds=config.timeout_seconds,
                gateway_endpoint=(gateway_document or {}).get("endpoint"),
                preflight=route_preflight,
            )
            if (
                route["policies"]["require_alignment"]
                and geo_realization["passed"] is not True
            ):
                raise ContractError("required network geography could not be realized")
        if config.live_trace:
            from .live_trace import wait_for_live_trace

            wait_for_live_trace(Path(str(trace_path) + ".live"), process,
                                timeout_seconds=config.timeout_seconds)
        session_document = {
            "schema": "browser-core.session/1",
            "run_id": run_id,
            "chromium_revision": manifest["chromium"]["revision"],
            "pid": process.pid,
            "state": "active",
            "created_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "executable": str(executable),
            "build": build,
            "process_identity": process_identity,
            "profile": profile_document,
            "trace_mode": config.trace_mode,
            "trace_category_contract": TRACE_CATEGORY_CONTRACT,
            "trace_scope": config.trace_scope if config.trace_mode == "on" else None,
            "trace_categories": (
                list(TRACE_SCOPES[config.trace_scope])
                if config.trace_mode == "on"
                else []
            ),
            "trace_path": str(trace_path) if trace_path is not None else None,
            "automation": {
                "transport": "cdp",
                "cdp_endpoint": f"http://127.0.0.1:{port}",
                "managed_target_url": startup_target_url,
            },
        }
        if config.live_trace:
            from .recording_source import bind_recording_file
            session_document["live_trace"] = {
                "schema": "browser-core.live-trace/1",
                "path": str(trace_path) + ".live",
                "file_binding": bind_recording_file(Path(str(trace_path)+'.live')),
                "byte_limit": recording_limit_bytes(config.recording_limit_mib,live=True),
            }
            if config.recording_parts is not None and config.recording_parts>1:
                session_document['live_trace']['parts']={
                    'schema':'browser-core.recording-parts/1','max_parts':config.recording_parts}
            if process.poll() is not None:
                raise ContractError('browser stopped before recording binding publication')
        if config.inspect_values:
            session_document["value_capture"] = capture_for_allowlist(config.inspection_allowlist)
        if persona is not None:
            session_document["persona"] = {
                "id": persona["id"],
                "sha256_16": persona["integrity_sha256"][:16],
            }
        if route is not None:
            session_document["network"] = {
                "route_id": route["id"],
                "route_sha256_16": route["integrity_sha256"][:16],
                "mode": route["mode"],
                "policies": route["policies"],
                "preflight": route_preflight,
                "runtime_identity": runtime_identity,
                "realization": geo_realization,
            }
            if gateway_document is not None:
                session_document["network"]["gateway"] = gateway_document
        if identity_contract is not None:
            session_document["identity_contract"] = identity_contract
        require_managed_profile_identity("before session publication")
        session = validate_session(session_document)
        if process.poll() is not None:
            raise ContractError("browser stopped before session publication")
        if gateway_process is not None and gateway_process.poll() is not None:
            raise ContractError(
                "network credential gateway stopped before session publication"
            )
        published_session = _publish_session_document(
            session_path,
            session,
            ownership,
        )
        require_managed_profile_identity("after session publication")
        if process.poll() is not None:
            raise ContractError("browser stopped before session return")
        if gateway_process is not None and gateway_process.poll() is not None:
            raise ContractError(
                "network credential gateway stopped before session return"
            )
        return session_path, published_session
    except Exception:
        raise
