from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

import browser_core.control_files as control_files
import browser_core.launcher as launcher_module
from browser_core.contracts import ContractError
from browser_core.launcher import (
    MAX_DEVTOOLS_ACTIVE_PORT_BYTES,
    _read_devtools_active_port,
    _publish_session_document,
    _wait_for_gateway,
    _wait_for_cdp,
    clear_stale_evaluation_transport,
    evaluation_command,
    managed_startup_target,
    validate_workspace,
)
from browser_core.control_files import (
    BoundedControlSnapshot,
    canonical_json_bytes,
    publish_json_exclusive,
)
from test_build import _write_fixture_attestation


@pytest.mark.skipif(os.name != "nt", reason="Windows directory junction boundary")
def test_launch_rejects_selected_runtime_junction_before_run_id(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    physical_runtime = tmp_path / "physical-runtime"
    physical_runtime.mkdir()
    executable, _receipt, _document = _write_fixture_attestation(physical_runtime)
    selected_runtime = tmp_path / "selected-runtime"
    linked = subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(selected_runtime), str(physical_runtime)],
        capture_output=True,
    )
    if linked.returncode:
        pytest.skip("host could not create an unprivileged directory junction")
    try:
        workspace = tmp_path / "workspace"
        workspace.mkdir()
        monkeypatch.setattr(
            launcher_module, "validate_workspace", lambda selected, _root: selected
        )
        monkeypatch.setattr(
            launcher_module,
            "verify_upstream",
            lambda _root: {"chromium": {"version": "153.0.7988.0", "revision": "a" * 40}},
        )
        monkeypatch.setattr(
            launcher_module,
            "new_run_id",
            lambda: pytest.fail("linked executable reached run creation"),
        )
        config = launcher_module.EvaluationLaunch(
            executable=selected_runtime / executable.name,
            workspace=workspace,
            trace_mode="off",
        )
        with pytest.raises(ContractError, match="not a verified Browser Core build"):
            launcher_module._launch_evaluation_owned(
                config, Path(__file__).resolve().parents[1], launcher_module._LaunchOwnership()
            )
    finally:
        selected_runtime.rmdir()


def test_evaluation_command_keeps_trace_and_cdp_separate(tmp_path: Path) -> None:
    executable = tmp_path / "chrome.exe"
    profile = tmp_path / "profile"
    trace = tmp_path / "trace.jsonl"
    command = evaluation_command(
        executable,
        profile,
        trace,
        "fixture-run",
        headless=True,
        extra_args=("--disable-background-networking",),
    )
    assert "--remote-debugging-port=0" in command
    assert "--browser-core-evaluation" in command
    assert f"--trace-startup-file={trace}" in command
    assert (
        "--trace-startup=browser_core.debug,browser_core.stream,blink.bindings,blink.bindings.encoding"
        in command
    )
    assert "--trace-startup-record-mode=record-continuously" in command
    assert "--headless=new" in command
    assert command[-1] == "about:blank"


@pytest.mark.skipif(sys.platform != "win32", reason="Windows command line limit")
def test_evaluation_command_rejects_quoted_windows_overflow_before_launch(
    tmp_path: Path,
) -> None:
    with pytest.raises(ContractError, match="command line"):
        evaluation_command(
            tmp_path / "chrome.exe", tmp_path / "profile", None, "fixture-run",
            headless=False, trace_mode="off",
            extra_args=tuple("--fixture=" + '"' * 3000 for _ in range(6)),
        )


def test_evaluation_command_can_select_causal_trace_scope(tmp_path: Path) -> None:
    command = evaluation_command(
        tmp_path / "chrome.exe",
        tmp_path / "profile",
        tmp_path / "trace.jsonl",
        "fixture-run",
        headless=False,
        extra_args=(),
        trace_scope="causal",
    )

    assert "--trace-startup=browser_core.debug" in command
    assert not any("browser_core.stream" in argument for argument in command)
    assert not any("blink.bindings" in argument for argument in command)


def test_evaluation_command_can_select_causal_stream_trace_scope(
    tmp_path: Path,
) -> None:
    command = evaluation_command(
        tmp_path / "chrome.exe",
        tmp_path / "profile",
        tmp_path / "trace.jsonl",
        "fixture-run",
        headless=False,
        extra_args=(),
        trace_scope="causal-stream",
    )

    assert "--trace-startup=browser_core.debug,browser_core.stream" in command
    assert not any("blink.bindings" in argument for argument in command)


def test_evaluation_command_can_select_encoding_trace_scope(tmp_path: Path) -> None:
    command = evaluation_command(
        tmp_path / "chrome.exe",
        tmp_path / "profile",
        tmp_path / "trace.jsonl",
        "fixture-run",
        headless=False,
        extra_args=(),
        trace_scope="encoding",
    )

    assert (
        "--trace-startup=browser_core.debug,blink.bindings.encoding" in command
    )
    assert not any("browser_core.stream" in argument for argument in command)
    assert not any(
        argument.endswith("blink.bindings") for argument in command
    )


def test_evaluation_command_uses_only_explicit_headless_target(tmp_path: Path) -> None:
    target = (tmp_path / "fixture.html").as_uri()
    command = evaluation_command(
        tmp_path / "chrome.exe",
        tmp_path / "profile",
        tmp_path / "trace.jsonl",
        "fixture-run",
        headless=True,
        extra_args=(target,),
    )

    assert "--headless=new" in command
    assert command[-1] == target
    assert "about:blank" not in command


def test_evaluation_command_trace_off_omits_trace_switches(tmp_path: Path) -> None:
    command = evaluation_command(
        tmp_path / "chrome.exe",
        tmp_path / "profile",
        None,
        "fixture-run",
        headless=False,
        extra_args=(),
        trace_mode="off",
    )

    assert not any(argument.startswith("--trace-startup") for argument in command)
    assert "--remote-debugging-port=0" in command


def test_evaluation_command_rejects_trace_mode_mismatch(tmp_path: Path) -> None:
    with pytest.raises(ContractError, match="cannot retain"):
        evaluation_command(
            tmp_path / "chrome.exe",
            tmp_path / "profile",
            tmp_path / "trace.perfetto-trace",
            "fixture-run",
            headless=False,
            extra_args=(),
            trace_mode="off",
        )


@pytest.mark.parametrize(
    "argument",
    [
        "--remote-debugging-port=9222",
        "--user-data-dir=elsewhere",
        "--proxy-server=http://elsewhere:1",
        "--trace-startup=disabled-by-user",
    ],
)
def test_evaluation_command_rejects_managed_argument_override(
    tmp_path: Path, argument: str
) -> None:
    with pytest.raises(ContractError):
        evaluation_command(
            tmp_path / "chrome.exe",
            tmp_path / "profile",
            tmp_path / "trace.jsonl",
            "fixture-run",
            headless=False,
            extra_args=(argument,),
        )


def test_workspace_cannot_contain_or_be_parent_of_repository(tmp_path: Path) -> None:
    repository = tmp_path / "repo"
    repository.mkdir()
    with pytest.raises(ContractError):
        validate_workspace(repository / "workspace", repository)
    with pytest.raises(ContractError):
        validate_workspace(tmp_path, repository)
    external = tmp_path.parent / "external-browser-core-fixture"
    assert validate_workspace(external, repository) == external.resolve()


def test_workspace_must_be_absolute_before_resolution(tmp_path: Path) -> None:
    repository = tmp_path / "repo"
    repository.mkdir()
    with pytest.raises(ContractError, match="workspace must be absolute"):
        validate_workspace(Path("relative-browser-workspace"), repository)


@pytest.mark.skipif(os.name != "nt", reason="Windows directory junction boundary")
def test_evaluation_workspace_rejects_selected_junction(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    physical_workspace = tmp_path / "physical-workspace"
    physical_workspace.mkdir()
    selected_workspace = tmp_path / "selected-workspace"
    linked = subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(selected_workspace), str(physical_workspace)],
        capture_output=True,
        check=False,
    )
    if linked.returncode:
        pytest.skip("host could not create an unprivileged directory junction")
    try:
        assert validate_workspace(physical_workspace, repository) == physical_workspace
        with pytest.raises(ContractError, match="workspace"):
            validate_workspace(selected_workspace, repository)
    finally:
        selected_workspace.rmdir()


def test_evaluation_workspace_rechecks_ancestor_during_resolution(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    parent = tmp_path / "workspace-parent"
    parent.mkdir()
    workspace = parent / "workspace"
    workspace.mkdir()
    moved_parent = tmp_path / "moved-workspace-parent"
    original_resolve = Path.resolve

    def replace_parent(self: Path, *args, **kwargs) -> Path:  # type: ignore[no-untyped-def]
        if self == workspace:
            parent.rename(moved_parent)
            parent.mkdir()
            workspace.mkdir()
        return original_resolve(self, *args, **kwargs)

    monkeypatch.setattr(Path, "resolve", replace_parent)
    with pytest.raises(ContractError, match="workspace changed during resolution"):
        validate_workspace(workspace, repository)


def test_stale_evaluation_transport_is_cleared_before_relaunch(tmp_path: Path) -> None:
    profile = tmp_path / "profile"
    profile.mkdir()
    control = profile / "DevToolsActivePort"
    control.write_text("9222\n/devtools/browser/stale\n", encoding="utf-8")
    clear_stale_evaluation_transport(profile)
    assert not control.exists()
    assert not list(profile.glob(".DevToolsActivePort.removed-*"))


def test_stale_evaluation_transport_refuses_non_file(tmp_path: Path) -> None:
    profile = tmp_path / "profile"
    (profile / "DevToolsActivePort").mkdir(parents=True)
    with pytest.raises(ContractError, match="not a regular file"):
        clear_stale_evaluation_transport(profile)


def test_stale_evaluation_transport_refuses_a_hard_link_alias(tmp_path: Path) -> None:
    profile = tmp_path / "profile"
    profile.mkdir()
    active = profile / "DevToolsActivePort"
    active.write_bytes(b"9222\n/devtools/browser")
    (tmp_path / "active-port-alias").hardlink_to(active)

    with pytest.raises(ContractError, match="hard links"):
        clear_stale_evaluation_transport(profile)


def test_stale_evaluation_transport_rejects_locked_changed_and_oversize(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    profile = tmp_path / "private-profile"
    profile.mkdir()
    active = profile / "DevToolsActivePort"
    active.write_bytes(b"9222\n/devtools/browser")
    real_read = launcher_module.read_bounded_control_snapshot_result

    for state in ("locked", "changed"):
        monkeypatch.setattr(
            launcher_module,
            "read_bounded_control_snapshot_result",
            lambda *_args, _state=state, **_kwargs: BoundedControlSnapshot(_state),
        )
        with pytest.raises(ContractError, match=f"is {state}"):
            clear_stale_evaluation_transport(profile)

    monkeypatch.setattr(
        launcher_module,
        "read_bounded_control_snapshot_result",
        real_read,
    )
    active.write_bytes(b"x" * (MAX_DEVTOOLS_ACTIVE_PORT_BYTES + 1))
    with pytest.raises(ContractError, match="exceeds 4096 bytes") as raised:
        clear_stale_evaluation_transport(profile)
    assert str(profile) not in str(raised.value)


def test_stale_evaluation_transport_preserves_a_replacement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    profile = tmp_path / "private-profile"
    profile.mkdir()
    active = profile / "DevToolsActivePort"
    active.write_bytes(b"9222\n/devtools/browser/old")
    replacement = profile / "replacement"
    replacement_body = b"9333\n/devtools/browser/replacement"
    replacement.write_bytes(replacement_body)
    real_rename = launcher_module.os.rename
    real_replace = launcher_module.os.replace
    swapped = False

    def replace_before_rename(source: Path, target: Path) -> None:
        nonlocal swapped
        if not swapped and Path(source) == active:
            real_replace(replacement, active)
            swapped = True
        real_rename(source, target)

    monkeypatch.setattr(launcher_module.os, "rename", replace_before_rename)
    with pytest.raises(ContractError, match="changed during removal") as raised:
        clear_stale_evaluation_transport(profile)

    assert str(profile) not in str(raised.value)
    assert active.read_bytes() == replacement_body
    assert not list(profile.glob(".DevToolsActivePort.removed-*"))


def test_stale_evaluation_transport_retries_a_disappearing_entry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    profile = tmp_path / "profile"
    profile.mkdir()
    active = profile / "DevToolsActivePort"
    active.write_bytes(b"9222\n/devtools/browser")
    real_unlink = launcher_module.os.unlink

    def disappear_before_rename(source: Path, _target: Path) -> None:
        real_unlink(source)
        raise FileNotFoundError(2, "private path")

    monkeypatch.setattr(launcher_module.os, "rename", disappear_before_rename)
    clear_stale_evaluation_transport(profile)
    assert not active.exists()


@pytest.mark.parametrize(
    ("phase", "error_class"),
    [
        ("read", "read failed"),
        ("quarantine", "removal quarantine failed"),
        ("verification", "quarantined source read failed"),
        ("removal", "removal failed"),
    ],
)
def test_stale_evaluation_transport_normalizes_os_failures_and_restores_name(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    phase: str,
    error_class: str,
) -> None:
    profile = tmp_path / "secret-profile"
    profile.mkdir()
    active = profile / "DevToolsActivePort"
    body = b"9222\n/devtools/browser"
    active.write_bytes(body)
    real_lstat = launcher_module.os.lstat
    real_rename = launcher_module.os.rename
    real_unlink = launcher_module.os.unlink
    failed = False

    def controlled_lstat(path: Path):  # type: ignore[no-untyped-def]
        nonlocal failed
        if phase == "read" and not failed and Path(path) == active:
            failed = True
            raise OSError(5, str(active))
        if phase == "verification" and not failed and ".removed-" in str(path):
            failed = True
            raise OSError(5, str(path))
        return real_lstat(path)

    def controlled_rename(source: Path, target: Path) -> None:
        nonlocal failed
        if phase == "quarantine" and not failed:
            failed = True
            raise OSError(5, str(source))
        real_rename(source, target)

    def controlled_unlink(path: Path) -> None:
        nonlocal failed
        if phase == "removal" and not failed and ".removed-" in str(path):
            failed = True
            raise OSError(5, str(path))
        real_unlink(path)

    monkeypatch.setattr(launcher_module.os, "lstat", controlled_lstat)
    monkeypatch.setattr(launcher_module.os, "rename", controlled_rename)
    monkeypatch.setattr(launcher_module.os, "unlink", controlled_unlink)

    with pytest.raises(ContractError, match=error_class) as raised:
        clear_stale_evaluation_transport(profile)
    assert "os_error=5" in str(raised.value)
    assert str(profile) not in str(raised.value)
    if phase in {"verification", "removal"}:
        assert active.read_bytes() == body
        assert not list(profile.glob(".DevToolsActivePort.removed-*"))


def test_stale_evaluation_transport_does_not_use_multi_lookup_path_methods(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    profile = tmp_path / "profile"
    profile.mkdir()
    active = profile / "DevToolsActivePort"
    active.write_bytes(b"9222\n/devtools/browser")
    monkeypatch.setattr(Path, "exists", lambda *_args: pytest.fail("exists used"))
    monkeypatch.setattr(Path, "is_file", lambda *_args: pytest.fail("is_file used"))
    monkeypatch.setattr(Path, "unlink", lambda *_args: pytest.fail("Path.unlink used"))

    clear_stale_evaluation_transport(profile)
    assert launcher_module.os.path.lexists(active) is False


def test_devtools_active_port_retries_partial_states_and_accepts_exact_writer_forms(
    tmp_path: Path,
) -> None:
    active = tmp_path / "DevToolsActivePort"
    for body in (
        b"",
        b"9",
        b"9222",
        b"9222\n",
        b"9222\n/devtools/brows",
        b"9222\n/devtools/browser/01234567-89ab-4def-a123-",
    ):
        active.write_bytes(body)
        assert _read_devtools_active_port(active) is None

    active.write_bytes(b"9222\n/devtools/browser")
    assert _read_devtools_active_port(active) == 9222
    active.write_bytes(b"9222\n/devtools/browser/01234567-89ab-4def-a123-456789abcdef")
    assert _read_devtools_active_port(active) == 9222


def test_devtools_active_port_retries_missing_and_writer_share_lock(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    active = tmp_path / "private-profile" / "DevToolsActivePort"
    assert _read_devtools_active_port(active) is None

    def locked_open(_self: Path, *_args: object, **_kwargs: object) -> object:
        raise PermissionError(13, "private writer path")

    monkeypatch.setattr(Path, "open", locked_open)
    assert _read_devtools_active_port(active) is None


def test_devtools_active_port_uses_one_handle_and_retries_a_changing_snapshot(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    active = tmp_path / "DevToolsActivePort"
    active.write_bytes(b"9222\n/devtools/browser")
    real_fstat = launcher_module.os.fstat
    file_descriptors: list[int] = []

    def recording_fstat(file_descriptor: int):  # type: ignore[no-untyped-def]
        file_descriptors.append(file_descriptor)
        return real_fstat(file_descriptor)

    identities = iter(
        [
            (1, 1, 1, 1, 1, 1, 0),
            (1, 1, 1, 1, 1, 1, 0),
            (1, 1, 1, 1, 1, 1, 0),
            (1, 1, 1, 2, 1, 1, 0),
        ]
    )
    monkeypatch.setattr(launcher_module.os, "fstat", recording_fstat)
    monkeypatch.setattr(
        launcher_module,
        "_snapshot_identity",
        lambda _metadata: next(identities),
    )

    assert _read_devtools_active_port(active) is None
    assert len(file_descriptors) == 2
    assert file_descriptors[0] == file_descriptors[1]


@pytest.mark.skipif(os.name != "nt", reason="Windows creation time is not change time")
def test_devtools_active_port_retries_same_size_edit_with_restored_mtime(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    active = tmp_path / "DevToolsActivePort"
    active.write_bytes(b"9222\n/devtools/browser")
    stamp = active.stat()
    real_fstat = launcher_module.os.fstat
    calls = 0

    def write_after_first_read(descriptor: int):
        nonlocal calls
        calls += 1
        if calls == 2:
            with active.open("r+b") as writer:
                writer.write(b"9333\n/devtools/browser")
            os.utime(active, ns=(stamp.st_atime_ns, stamp.st_mtime_ns))
        return real_fstat(descriptor)

    monkeypatch.setattr(launcher_module.os, "fstat", write_after_first_read)
    assert _read_devtools_active_port(active) is None
    assert active.read_bytes() == b"9333\n/devtools/browser"


def test_devtools_active_port_retries_edit_during_target_validation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    active = tmp_path / "DevToolsActivePort"
    target = b"/devtools/browser/00000000-0000-4000-8000-000000000000"
    active.write_bytes(b"9222\n" + target)
    stamp = active.stat()
    real_pattern = launcher_module._DEVTOOLS_BROWSER_UUID_V4_RE

    class MutatingPattern:
        def fullmatch(self, value: bytes):  # type: ignore[no-untyped-def]
            with active.open("r+b") as writer:
                writer.write(b"9333\n" + target)
            os.utime(active, ns=(stamp.st_atime_ns, stamp.st_mtime_ns))
            return real_pattern.fullmatch(value)

    monkeypatch.setattr(
        launcher_module, "_DEVTOOLS_BROWSER_UUID_V4_RE", MutatingPattern()
    )

    assert _read_devtools_active_port(active) is None
    assert active.read_bytes() == b"9333\n" + target


def test_devtools_active_port_rejects_links_and_non_path_input(tmp_path: Path) -> None:
    active = tmp_path / "DevToolsActivePort"
    active.write_bytes(b"9222\n/devtools/browser")
    alias = tmp_path / "DevToolsActivePort-alias"
    alias.hardlink_to(active)
    with pytest.raises(ContractError, match="hard links"):
        _read_devtools_active_port(active)

    alias.unlink()
    link = tmp_path / "DevToolsActivePort-link"
    try:
        link.symlink_to(active)
    except OSError:
        pass
    else:
        with pytest.raises(ContractError, match="regular file"):
            _read_devtools_active_port(link)

    with pytest.raises(ContractError, match="path must be a Path"):
        _read_devtools_active_port(str(active))  # type: ignore[arg-type]


def test_devtools_active_port_rejects_oversize_before_content_admission(
    tmp_path: Path,
) -> None:
    active = tmp_path / "secret-profile" / "DevToolsActivePort"
    active.parent.mkdir()
    active.write_bytes(b"0" * (MAX_DEVTOOLS_ACTIVE_PORT_BYTES + 1))
    with pytest.raises(ContractError, match="exceeds 4096 bytes") as raised:
        _read_devtools_active_port(active)
    assert str(active) not in str(raised.value)


@pytest.mark.parametrize(
    "body",
    [
        b"not-a-port\n/devtools/browser",
        b"0\n/devtools/browser",
        b"65536\n/devtools/browser",
        b"9222\n/not-devtools/browser",
        b"9222\n/devtools/browser/01234567-89ab-1def-a123-456789abcdef",
        b"9222\n/devtools/browser/01234567-89ab-4def-7123-456789abcdef",
        b"9222\n/devtools/browser/01234567-89AB-4DEF-A123-456789ABCDEF",
        b"9222\n/devtools/browser\nextra",
        b"9222\r\n/devtools/browser",
        b"9222\n/devtools/browser\n",
    ],
)
def test_devtools_active_port_rejects_impossible_completed_states(
    tmp_path: Path,
    body: bytes,
) -> None:
    active = tmp_path / "secret-profile" / "DevToolsActivePort"
    active.parent.mkdir(exist_ok=True)
    active.write_bytes(body)
    with pytest.raises(ContractError) as raised:
        _read_devtools_active_port(active)
    assert str(active) not in str(raised.value)


def test_wait_for_cdp_retries_snapshot_states_without_path_read_text(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    states = iter([None, None, 9222])

    class RunningProcess:
        def poll(self) -> None:
            return None

    monkeypatch.setattr(
        launcher_module,
        "_read_devtools_active_port",
        lambda _active: next(states),
    )
    monkeypatch.setattr(
        Path,
        "read_text",
        lambda *_args, **_kwargs: pytest.fail("read_text used"),
    )
    monkeypatch.setattr(launcher_module.time, "sleep", lambda _duration: None)

    assert (
        _wait_for_cdp(
            tmp_path,
            RunningProcess(),  # type: ignore[arg-type]
            1.0,
        )
        == 9222
    )


def test_wait_for_cdp_rejects_port_returned_after_deadline(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    clock = [0.0]
    monkeypatch.setattr(
        launcher_module.time, "monotonic", lambda: clock[0]
    )

    class Process:
        def poll(self) -> None:
            return None

    def late_port(_path: Path) -> int:
        clock[0] = 2.0
        return 9222

    monkeypatch.setattr(launcher_module, "_read_devtools_active_port", late_port)
    with pytest.raises(ContractError, match="timed out"):
        _wait_for_cdp(tmp_path, Process(), 1.0)  # type: ignore[arg-type]


def test_wait_for_cdp_rejects_process_exiting_during_port_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class Process:
        polls = 0

        def poll(self) -> int | None:
            self.polls += 1
            return None if self.polls == 1 else 7

    monkeypatch.setattr(
        launcher_module, "_read_devtools_active_port", lambda _path: 9222
    )
    with pytest.raises(ContractError, match="exited before CDP became ready"):
        _wait_for_cdp(tmp_path, Process(), 1.0)  # type: ignore[arg-type]


def test_evaluation_command_routes_only_through_managed_loopback_gateway(
    tmp_path: Path,
) -> None:
    command = evaluation_command(
        tmp_path / "chrome.exe",
        tmp_path / "profile",
        tmp_path / "trace.jsonl",
        "fixture-run",
        headless=False,
        extra_args=(),
        local_gateway=("127.0.0.1", 8765),
        webrtc_policy="route-only",
    )
    assert "--proxy-server=http://127.0.0.1:8765" in command
    assert "--force-webrtc-ip-handling-policy=disable_non_proxied_udp" in command
    with pytest.raises(ContractError, match="gateway"):
        evaluation_command(
            tmp_path / "chrome.exe",
            tmp_path / "profile",
            tmp_path / "trace.jsonl",
            "fixture-run",
            headless=False,
            extra_args=(),
            local_gateway=("0.0.0.0", 8765),
        )


def test_evaluation_command_routes_every_non_owned_target_to_containment_proxy(
    tmp_path: Path,
) -> None:
    command = evaluation_command(
        tmp_path / "chrome.exe",
        tmp_path / "profile",
        None,
        "fixture-run",
        headless=True,
        extra_args=("http://127.0.0.1:43123/",),
        local_containment_proxy=("127.0.0.1", 43123, 43123),
        trace_mode="off",
    )

    assert "--proxy-server=http://127.0.0.1:43123" in command
    assert "--proxy-bypass-list=<-loopback>;127.0.0.1:43123" in command
    assert "--force-webrtc-ip-handling-policy=disable_non_proxied_udp" in command
    assert "--disable-quic" in command


@pytest.mark.parametrize(
    "argument",
    [
        "--host-resolver-rules=MAP * 203.0.113.1",
        "--host-rules=MAP * 203.0.113.1",
        "--no-proxy-server",
        "--enable-quic",
        "--disable-quic",
        "--origin-to-force-quic-on=203.0.113.1:443",
        "--quic-version=h3",
    ],
)
def test_evaluation_command_rejects_direct_containment_policy_overrides(
    tmp_path: Path,
    argument: str,
) -> None:
    with pytest.raises(ContractError, match="managed (network route|local containment)"):
        evaluation_command(
            tmp_path / "chrome.exe",
            tmp_path / "profile",
            None,
            "fixture-run",
            headless=True,
            extra_args=(argument,),
            local_containment_proxy=("127.0.0.1", 43123, 43123),
            trace_mode="off",
        )


@pytest.mark.parametrize(
    "containment",
    [
        ("0.0.0.0", 43123, 43123),
        ("127.0.0.1", True, 43123),
        ("127.0.0.1", 0, 43123),
        ("127.0.0.1", 43123, 65536),
        ("127.0.0.1", 43123),
        ["127.0.0.1", 43123, 43123],
    ],
)
def test_evaluation_command_rejects_invalid_containment_proxy(
    tmp_path: Path, containment
) -> None:
    with pytest.raises(ContractError, match="containment proxy"):
        evaluation_command(
            tmp_path / "chrome.exe",
            tmp_path / "profile",
            None,
            "fixture-run",
            headless=True,
            extra_args=(),
            local_containment_proxy=containment,
            trace_mode="off",
        )


def test_evaluation_command_rejects_two_managed_proxy_routes(tmp_path: Path) -> None:
    with pytest.raises(ContractError, match="network route.*incompatible"):
        evaluation_command(
            tmp_path / "chrome.exe",
            tmp_path / "profile",
            None,
            "fixture-run",
            headless=True,
            extra_args=(),
            local_gateway=("127.0.0.1", 8765),
            local_containment_proxy=("127.0.0.1", 43123, 43123),
            trace_mode="off",
        )


def test_evaluation_command_rejects_unmanaged_webrtc_override(tmp_path: Path) -> None:
    with pytest.raises(ContractError, match="WebRTC"):
        evaluation_command(
            tmp_path / "chrome.exe",
            tmp_path / "profile",
            tmp_path / "trace.jsonl",
            "fixture-run",
            headless=False,
            extra_args=("--force-webrtc-ip-handling-policy=default",),
        )


def test_managed_startup_target_owns_nonce_target_when_unspecified() -> None:
    arguments, target = managed_startup_target(
        ("--disable-background-networking",), "owned-run"
    )
    assert target == (
        "data:text/html,%3Ctitle%3Ebrowser-core-identity-owned-run%3C%2Ftitle%3E"
    )
    assert arguments[-1] == target


def test_managed_startup_target_preserves_one_explicit_target() -> None:
    arguments, target = managed_startup_target(
        ("--headless=new", "file:///fixture.html"), "owned-run"
    )
    assert arguments == ("--headless=new", "file:///fixture.html")
    assert target == "file:///fixture.html"


def test_managed_startup_target_rejects_multiple_positional_targets() -> None:
    with pytest.raises(ContractError, match="at most one"):
        managed_startup_target(("https://one.test/", "https://two.test/"), "owned-run")


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("headless", "false", "headless"),
        ("allow_unverified_executable", "false", "allow-unverified"),
        ("timeout_seconds", True, "timeout"),
        ("timeout_seconds", float("nan"), "timeout"),
        ("timeout_seconds", float("inf"), "timeout"),
        ("timeout_seconds", 0, "timeout"),
        ("timeout_seconds", 301, "timeout"),
        ("timeout_seconds", 10**400, "timeout"),
        ("extra_args", ["--headless=new"], "extra arguments"),
        ("extra_args", ("--flag=bad\x00value",), "extra argument"),
        ("profile_id", ["profile"], "profile ID"),
        ("trace_mode", [], "trace mode"),
        ("trace_scope", [], "trace scope"),
    ],
)
def test_evaluation_launch_control_values_fail_before_contact(
    tmp_path: Path,
    field: str,
    value: object,
    message: str,
) -> None:
    values: dict[str, object] = {
        "executable": tmp_path / "chrome.exe",
        "workspace": tmp_path / "workspace",
    }
    values[field] = value
    config = launcher_module.EvaluationLaunch(**values)  # type: ignore[arg-type]
    with pytest.raises(ContractError, match=message):
        launcher_module.validate_evaluation_launch(config)


def test_evaluation_command_rejects_nonboolean_headless_and_invalid_run_id(
    tmp_path: Path,
) -> None:
    with pytest.raises(ContractError, match="headless"):
        evaluation_command(
            tmp_path / "chrome.exe",
            tmp_path / "profile",
            None,
            "owned-run",
            headless="false",  # type: ignore[arg-type]
            extra_args=(),
            trace_mode="off",
        )
    with pytest.raises(ContractError, match="run ID"):
        evaluation_command(
            tmp_path / "chrome.exe",
            tmp_path / "profile",
            None,
            "../escape",
            headless=False,
            extra_args=(),
            trace_mode="off",
        )


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"executable": "chrome.exe"}, "executable"),
        ({"profile": "profile"}, "profile"),
        ({"trace_path": "trace.bin"}, "trace path"),
        ({"executable": Path(chr(0xD800))}, "executable"),
        ({"extra_args": (chr(0xD800),)}, "extra argument"),
        ({"trace_mode": []}, "trace mode"),
        ({"trace_scope": []}, "trace scope"),
        ({"local_gateway": ["127.0.0.1", 8765]}, "gateway"),
        ({"local_gateway": ("127.0.0.1", True)}, "gateway"),
        ({"local_gateway": ("127.0.0.1", "8765")}, "gateway"),
        ({"webrtc_policy": []}, "WebRTC"),
    ],
)
def test_evaluation_command_closes_every_outer_argument_shape(
    tmp_path: Path,
    overrides: dict[str, object],
    message: str,
) -> None:
    values: dict[str, object] = {
        "executable": tmp_path / "chrome.exe",
        "profile": tmp_path / "profile",
        "trace_path": None,
        "run_id": "owned-run",
        "headless": False,
        "extra_args": (),
        "trace_mode": "off",
    }
    values.update(overrides)

    with pytest.raises(ContractError, match=message):
        evaluation_command(**values)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("workspace", "repository"),
    [
        ("workspace", Path("repository")),
        (Path("workspace"), "repository"),
        (Path(chr(0xD800)), Path("repository")),
    ],
)
def test_workspace_validation_closes_path_shape_before_resolution(
    workspace: object,
    repository: object,
) -> None:
    with pytest.raises(ContractError, match="workspace|repository"):
        validate_workspace(workspace, repository)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("stage", "expected"),
    [
        ("invalid-command", "cannot override"),
        ("stale-cleanup", "stale cleanup failed"),
        ("popen", "infrastructure failed"),
        ("popen-value", "infrastructure failed"),
        ("post-popen", "identity observation failed"),
    ],
)
def test_evaluation_launch_aborts_every_owned_resource_before_session(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    stage: str,
    expected: str,
) -> None:
    monkeypatch.setattr(launcher_module, 'native_browser_path', lambda path, **kwargs: path)
    executable = tmp_path / "chrome.exe"
    executable.write_bytes(b"fixture")
    workspace = tmp_path / "workspace"
    profile = workspace / "profiles" / "owned" / "data"
    profile.mkdir(parents=True)
    lock = profile / ".browser-core.lock"
    gateway_directory = workspace / "network" / "gateways"
    gateway_directory.mkdir(parents=True)
    gateway_processes: list[subprocess.Popen[bytes]] = []
    browser_processes: list[subprocess.Popen[bytes]] = []
    real_popen = subprocess.Popen
    route = {
        "id": "route",
        "mode": "proxy",
        "integrity_sha256": "1" * 64,
        "geography": {"country": "US", "locale": "en-US", "timezone": "UTC"},
        "policies": {"webrtc": "default", "require_alignment": False},
    }

    monkeypatch.setattr(
        launcher_module,
        "verify_upstream",
        lambda _root: {"chromium": {"version": "153.0.7988.0", "revision": "a" * 40}},
    )
    monkeypatch.setattr(
        launcher_module,
        "executable_evidence",
        lambda *_args, **_kwargs: {"verified": True},
    )
    monkeypatch.setattr(launcher_module, "new_run_id", lambda: "owned-run")
    monkeypatch.setattr(launcher_module, "load_profile", lambda *_args: {"id": "owned"})
    monkeypatch.setattr(
        launcher_module,
        "profile_bindings",
        lambda *_args: {"network_route": route},
    )
    monkeypatch.setattr(launcher_module, "profile_data_path", lambda *_args: profile)
    monkeypatch.setattr(
        launcher_module, "profile_identity_contract", lambda *_args: None
    )

    def acquire_lock(_workspace: Path, _profile_id: str, run_id: str) -> Path:
        lock.write_text(
            json.dumps({"schema": "browser-core.profile-lock/1", "run_id": run_id})
            + "\n",
            encoding="utf-8",
        )
        return lock

    monkeypatch.setattr(launcher_module, "acquire_profile_lock", acquire_lock)

    def start_gateway(
        _workspace: Path,
        _route: dict[str, object],
        run_id: str,
        _timeout: float,
        ownership: launcher_module._LaunchOwnership,
        _session_key: str | None = None,
    ) -> tuple[subprocess.Popen[bytes], dict[str, object]]:
        lease = gateway_directory / f"{run_id}.lease"
        ready = gateway_directory / f"{run_id}.json"
        lease_body = b"lease"
        ready_body = b"ready"
        lease.write_bytes(lease_body)
        ready.write_bytes(ready_body)
        process = real_popen(
            [sys.executable, "-c", "import time; time.sleep(60)"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        gateway_processes.append(process)
        ownership.gateway_lease = launcher_module._claim_owned_control(
            lease,
            lease_body,
            maximum=4096,
            label="gateway lease",
        )
        ownership.gateway_ready = launcher_module._claim_owned_control(
            ready,
            ready_body,
            maximum=4096,
            label="gateway readiness",
        )
        ownership.gateway_process = process
        return process, {
            "process_identity": {"pid": process.pid},
            "endpoint": "http://127.0.0.1:8765",
            "lease_path": str(lease),
            "ready_path": str(ready),
            "preflight": {},
        }

    monkeypatch.setattr(launcher_module, "_start_gateway", start_gateway)
    if stage == "stale-cleanup":
        monkeypatch.setattr(
            launcher_module,
            "clear_stale_evaluation_transport",
            lambda _profile: (_ for _ in ()).throw(
                ContractError("stale cleanup failed")
            ),
        )
    elif stage in {"popen", "popen-value"}:

        def fail_browser_start(*_args: object, **_kwargs: object) -> None:
            private_path = str(tmp_path / "private-browser-path")
            if stage == "popen-value":
                raise ValueError(private_path)
            raise OSError(5, private_path)

        monkeypatch.setattr(
            launcher_module.subprocess,
            "Popen",
            fail_browser_start,
        )
    elif stage == "post-popen":

        def start_browser(*_args: object, **_kwargs: object) -> subprocess.Popen[bytes]:
            process = real_popen(
                [sys.executable, "-c", "import time; time.sleep(60)"],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            browser_processes.append(process)
            return process

        monkeypatch.setattr(launcher_module.subprocess, "Popen", start_browser)
        monkeypatch.setattr(
            launcher_module,
            "observe_process",
            lambda _pid: (_ for _ in ()).throw(
                ContractError("identity observation failed")
            ),
        )

    extra_args = ("--remote-debugging-port=9222",) if stage == "invalid-command" else ()
    config = launcher_module.EvaluationLaunch(
        executable=executable,
        workspace=workspace,
        trace_mode="off",
        profile_id="owned",
        extra_args=extra_args,
    )
    with pytest.raises(ContractError, match=expected) as raised:
        launcher_module.launch_evaluation(config, tmp_path / "repository")

    assert str(tmp_path / "private-browser-path") not in str(raised.value)
    assert not lock.exists()
    assert not list(gateway_directory.glob("owned-run.*"))
    if stage == "invalid-command":
        assert gateway_processes == []
    else:
        assert gateway_processes and all(
            process.poll() is not None for process in gateway_processes
        )
    assert all(process.poll() is not None for process in browser_processes)
    assert not (workspace / "sessions" / "owned-run.json").exists()


def test_evaluation_launch_keeps_primary_error_when_cleanup_is_incomplete(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    private_lock = tmp_path / "private-profile" / ".browser-core.lock"

    def fail_with_owned_lock(
        _config: launcher_module.EvaluationLaunch,
        _root: Path,
        ownership: launcher_module._LaunchOwnership,
    ) -> tuple[Path, dict[str, object]]:
        ownership.run_id = "owned-run"
        ownership.profile_lock = private_lock
        raise ContractError("primary validation failure")

    monkeypatch.setattr(
        launcher_module, "_launch_evaluation_owned", fail_with_owned_lock
    )
    monkeypatch.setattr(
        launcher_module,
        "release_profile_lock",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            ContractError("private lock path")
        ),
    )
    config = launcher_module.EvaluationLaunch(
        executable=tmp_path / "chrome.exe",
        workspace=tmp_path / "workspace",
    )
    with pytest.raises(ContractError) as raised:
        launcher_module.launch_evaluation(config, tmp_path / "repository")

    message = str(raised.value)
    assert message.startswith("primary validation failure;")
    assert "profile-lock:release" in message
    assert str(private_lock) not in message
    assert "private lock path" not in message


@pytest.mark.parametrize(
    "mutation",
    ["leaf_identity", "ancestor_relocation", "prelaunch_ancestor_relocation"],
)
def test_launch_rechecks_managed_profile_identity_before_session_publication(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mutation: str
) -> None:
    executable = tmp_path / "chrome.exe"
    executable.write_bytes(b"fixture")
    workspace = tmp_path / "workspace"
    profile = workspace / "profiles" / "ephemeral" / "owned-run"
    changed = [False]
    original_identity = launcher_module.directory_identity

    def observed_identity(path: Path, *, label: str):
        identity = original_identity(path, label=label)
        if mutation == "leaf_identity" and changed[0] and path == profile:
            return object()
        return identity

    def relocate_profiles() -> None:
        profiles = workspace / "profiles"
        moved = workspace / "profiles-old"
        profiles.rename(moved)
        profiles.mkdir()
        (moved / "ephemeral").rename(profiles / "ephemeral")
        assert profile.exists()
        changed[0] = True

    def native_path(path: Path, **_kwargs: object) -> Path:
        if mutation == "prelaunch_ancestor_relocation" and not changed[0]:
            relocate_profiles()
        return path

    class Process:
        pid = 424245

        def __init__(self) -> None:
            self.returncode: int | None = None

        def poll(self) -> int | None:
            return self.returncode

        def terminate(self) -> None:
            self.returncode = 0

        def wait(self, timeout: float) -> int:
            assert timeout >= 0
            assert self.returncode is not None
            return self.returncode

        def kill(self) -> None:
            self.returncode = -9

    monkeypatch.setattr(launcher_module, "verify_upstream", lambda _root: {
        "chromium": {"version": "153.0.7988.0", "revision": "a" * 40}
    })
    monkeypatch.setattr(
        launcher_module, "executable_evidence",
        lambda *_args, **_kwargs: {"verified": True},
    )
    monkeypatch.setattr(launcher_module, "new_run_id", lambda: "owned-run")
    monkeypatch.setattr(
        launcher_module, "native_browser_path", native_path
    )
    monkeypatch.setattr(launcher_module, "directory_identity", observed_identity)
    monkeypatch.setattr(launcher_module.subprocess, "Popen", lambda *_a, **_k: Process())
    monkeypatch.setattr(launcher_module, "_retain_launched_process", lambda _p: None)
    monkeypatch.setattr(launcher_module, "reap_launched_process", lambda *_a, **_k: True)
    monkeypatch.setattr(
        launcher_module,
        "observe_process",
        lambda _pid: {
            "pid": 424245,
            "executable": str(executable),
            "start_marker": "owned-start",
        },
    )

    def ready(_profile: Path, _process: Process, _timeout: float) -> int:
        if mutation == "ancestor_relocation":
            relocate_profiles()
        changed[0] = True
        return 9222

    monkeypatch.setattr(launcher_module, "_wait_for_cdp", ready)
    monkeypatch.setattr(launcher_module, "validate_session", lambda value: value)
    monkeypatch.setattr(
        launcher_module,
        "_publish_session_document",
        lambda *_args: pytest.fail("changed profile reached session publication"),
    )
    config = launcher_module.EvaluationLaunch(
        executable=executable,
        workspace=workspace,
        trace_mode="off",
    )
    with pytest.raises(ContractError, match="managed browser profile changed"):
        launcher_module.launch_evaluation(config, tmp_path / "repository")
    assert not (workspace / "sessions" / "owned-run.json").exists()
    if mutation != "leaf_identity":
        assert profile.exists()


@pytest.mark.parametrize("exit_stage", ["validation", "publication"])
def test_launch_rejects_browser_exit_before_active_session_return(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, exit_stage: str
) -> None:
    executable = tmp_path / "chrome.exe"
    executable.write_bytes(b"fixture")
    workspace = tmp_path / "workspace"

    class Process:
        pid = 424245
        returncode: int | None = None

        def poll(self) -> int | None:
            return self.returncode

        def terminate(self) -> None:
            self.returncode = 0

        def wait(self, timeout: float) -> int:
            assert timeout >= 0
            assert self.returncode is not None
            return self.returncode

        def kill(self) -> None:
            self.returncode = -9

    process = Process()
    monkeypatch.setattr(launcher_module, "verify_upstream", lambda _root: {
        "chromium": {"version": "153.0.7988.0", "revision": "a" * 40}
    })
    monkeypatch.setattr(
        launcher_module, "executable_evidence",
        lambda *_args, **_kwargs: {"verified": True},
    )
    monkeypatch.setattr(launcher_module, "new_run_id", lambda: "owned-run")
    monkeypatch.setattr(
        launcher_module, "native_browser_path", lambda path, **_kwargs: path
    )
    monkeypatch.setattr(launcher_module.subprocess, "Popen", lambda *_a, **_k: process)
    monkeypatch.setattr(launcher_module, "_retain_launched_process", lambda _p: None)
    monkeypatch.setattr(launcher_module, "reap_launched_process", lambda *_a, **_k: True)
    monkeypatch.setattr(
        launcher_module,
        "observe_process",
        lambda _pid: {
            "pid": 424245,
            "executable": str(executable),
            "start_marker": "owned-start",
        },
    )
    monkeypatch.setattr(launcher_module, "_wait_for_cdp", lambda *_args: 9222)

    def validate(session: dict[str, object]) -> dict[str, object]:
        if exit_stage == "validation":
            process.returncode = 1
        return session

    def publish(
        _path: Path, session: dict[str, object], _ownership: object
    ) -> dict[str, object]:
        if exit_stage == "validation":
            pytest.fail("stopped browser reached session publication")
        process.returncode = 1
        return session

    monkeypatch.setattr(launcher_module, "validate_session", validate)
    monkeypatch.setattr(launcher_module, "_publish_session_document", publish)
    config = launcher_module.EvaluationLaunch(
        executable=executable,
        workspace=workspace,
        trace_mode="off",
    )
    with pytest.raises(ContractError, match="browser stopped before session"):
        launcher_module.launch_evaluation(config, tmp_path / "repository")


@pytest.mark.parametrize("exit_stage", ["readiness", "publication"])
def test_launch_rejects_gateway_exit_before_active_session_return(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, exit_stage: str
) -> None:
    executable = tmp_path / "chrome.exe"
    executable.write_bytes(b"fixture")
    workspace = tmp_path / "workspace"
    route = {
        "id": "owned-route",
        "mode": "proxy",
        "integrity_sha256": "1" * 64,
        "policies": {"webrtc": "route-only", "require_alignment": False},
    }

    class Process:
        def __init__(self, pid: int) -> None:
            self.pid = pid
            self.returncode: int | None = None

        def poll(self) -> int | None:
            return self.returncode

        def terminate(self) -> None:
            self.returncode = 0

        def wait(self, timeout: float) -> int:
            assert timeout >= 0
            assert self.returncode is not None
            return self.returncode

        def kill(self) -> None:
            self.returncode = -9

    browser = Process(424245)
    gateway = Process(424246)
    monkeypatch.setattr(launcher_module, "verify_upstream", lambda _root: {
        "chromium": {"version": "153.0.7988.0", "revision": "a" * 40}
    })
    monkeypatch.setattr(
        launcher_module, "executable_evidence",
        lambda *_args, **_kwargs: {"verified": True},
    )
    monkeypatch.setattr(launcher_module, "new_run_id", lambda: "owned-run")
    monkeypatch.setattr(
        launcher_module, "native_browser_path", lambda path, **_kwargs: path
    )
    monkeypatch.setattr(launcher_module, "load_network_route", lambda *_args: route)
    monkeypatch.setattr(launcher_module.subprocess, "Popen", lambda *_a, **_k: browser)
    monkeypatch.setattr(launcher_module, "_retain_launched_process", lambda _p: None)
    monkeypatch.setattr(launcher_module, "reap_launched_process", lambda *_a, **_k: True)
    monkeypatch.setattr(
        launcher_module,
        "observe_process",
        lambda _pid: {
            "pid": browser.pid,
            "executable": str(executable),
            "start_marker": "owned-start",
        },
    )

    def start_gateway(
        _workspace: Path,
        _route: dict[str, object],
        _run_id: str,
        _timeout: float,
        ownership: launcher_module._LaunchOwnership,
        _session_key: str | None,
    ) -> tuple[Process, dict[str, object]]:
        ownership.gateway_process = gateway
        return gateway, {
            "endpoint": "http://127.0.0.1:8765",
            "preflight": {},
            "process_identity": {"pid": gateway.pid},
        }

    def ready(*_args: object) -> int:
        if exit_stage == "readiness":
            gateway.returncode = 1
        return 9222

    def publish(
        _path: Path, session: dict[str, object], _ownership: object
    ) -> dict[str, object]:
        if exit_stage == "readiness":
            pytest.fail("stopped gateway reached session publication")
        gateway.returncode = 1
        return session

    monkeypatch.setattr(launcher_module, "_start_gateway", start_gateway)
    monkeypatch.setattr(launcher_module, "_wait_for_cdp", ready)
    monkeypatch.setattr(
        launcher_module,
        "observe_runtime_identity",
        lambda *_args, **_kwargs: {"locale": "en-US", "timezone": "UTC"},
    )
    monkeypatch.setattr(
        launcher_module, "observe_geo_alignment", lambda *_args, **_kwargs: {
            "passed": True
        }
    )
    monkeypatch.setattr(launcher_module, "validate_session", lambda value: value)
    monkeypatch.setattr(launcher_module, "_publish_session_document", publish)
    config = launcher_module.EvaluationLaunch(
        executable=executable,
        workspace=workspace,
        trace_mode="off",
        network_route_id="owned-route",
    )
    with pytest.raises(ContractError, match="network credential gateway stopped before session"):
        launcher_module.launch_evaluation(config, tmp_path / "repository")
    assert browser.returncode is not None
    assert not (workspace / "sessions" / "owned-run.json").exists()


def _gateway_route() -> dict[str, object]:
    return {
        "id": "owned-route",
        "integrity_sha256": "1" * 64,
    }


def _gateway_ready_document(**changes: object) -> dict[str, object]:
    document: dict[str, object] = {
        "schema": "browser-core.gateway-ready/2",
        "run_id": "owned-run",
        "route_id": "owned-route",
        "route_sha256_16": "1" * 16,
        "host": "127.0.0.1",
        "port": 8765,
    }
    document.update(changes)
    return document


def test_wait_for_gateway_admits_consistent_bounded_snapshots_without_read_text(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ready = tmp_path / "owned-run.json"
    publish_json_exclusive(
        ready,
        _gateway_ready_document(),
        maximum=4096,
        label="gateway readiness",
    )

    class RunningProcess:
        def poll(self) -> None:
            return None

    monkeypatch.setattr(
        Path, "read_text", lambda *_args, **_kwargs: pytest.fail("read_text used")
    )
    readiness = _wait_for_gateway(
        ready,
        RunningProcess(),  # type: ignore[arg-type]
        1.0,
        _gateway_route(),
    )
    assert readiness.document == _gateway_ready_document()
    assert readiness.control.path == ready
    assert readiness.control.body == canonical_json_bytes(_gateway_ready_document())


def test_wait_for_gateway_rejects_ready_change_during_validation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ready = tmp_path / "owned-run.json"
    publish_json_exclusive(
        ready, _gateway_ready_document(), maximum=4096, label="gateway readiness"
    )
    original_load = launcher_module.load_canonical_json_document

    def mutate_after_decode(body: bytes, *, label: str) -> dict:
        document = original_load(body, label=label)
        previous = ready.stat()
        ready.write_bytes(canonical_json_bytes(_gateway_ready_document(port=8766)))
        os.utime(ready, ns=(previous.st_atime_ns, previous.st_mtime_ns))
        return document

    class RunningProcess:
        def poll(self) -> None:
            return None

    monkeypatch.setattr(
        launcher_module, "load_canonical_json_document", mutate_after_decode
    )
    with pytest.raises(ContractError, match="readiness document changed"):
        _wait_for_gateway(
            ready, RunningProcess(), 1.0, _gateway_route()  # type: ignore[arg-type]
        )


def test_wait_for_gateway_rejects_readiness_returned_after_deadline(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ready = tmp_path / "owned-run.json"
    body = canonical_json_bytes(_gateway_ready_document())
    identity = (1, 2, 0o100600, len(body), 3, 4)
    clock = [0.0]
    monkeypatch.setattr(launcher_module.time, "monotonic", lambda: clock[0])

    class Process:
        def poll(self) -> None:
            return None

    def late_snapshot(*_args, **_kwargs):
        clock[0] = 2.0
        return BoundedControlSnapshot("complete", body, identity)

    monkeypatch.setattr(
        launcher_module, "read_bounded_control_snapshot_result", late_snapshot
    )
    with pytest.raises(ContractError, match="timed out"):
        _wait_for_gateway(
            ready, Process(), 1.0, _gateway_route()  # type: ignore[arg-type]
        )


def test_wait_for_gateway_rejects_process_exiting_during_readiness_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ready = tmp_path / "owned-run.json"
    body = canonical_json_bytes(_gateway_ready_document())
    identity = (1, 2, 0o100600, len(body), 3, 4)

    class Process:
        polls = 0

        def poll(self) -> int | None:
            self.polls += 1
            return None if self.polls == 1 else 7

    monkeypatch.setattr(
        launcher_module,
        "read_bounded_control_snapshot_result",
        lambda *_args, **_kwargs: BoundedControlSnapshot("complete", body, identity),
    )
    with pytest.raises(ContractError, match="exited before readiness"):
        _wait_for_gateway(
            ready, Process(), 1.0, _gateway_route()  # type: ignore[arg-type]
        )


def test_wait_for_gateway_rejects_a_hard_linked_readiness_document(
    tmp_path: Path,
) -> None:
    ready = tmp_path / "owned-run.json"
    publish_json_exclusive(
        ready,
        _gateway_ready_document(),
        maximum=4096,
        label="gateway readiness",
    )
    (tmp_path / "ready-alias.json").hardlink_to(ready)

    class RunningProcess:
        def poll(self) -> None:
            return None

    with pytest.raises(ContractError, match="hard links"):
        _wait_for_gateway(
            ready,
            RunningProcess(),  # type: ignore[arg-type]
            1.0,
            _gateway_route(),
        )


@pytest.mark.parametrize(
    "timeout", [True, 0, -1, float("nan"), float("inf"), 301, 10**400]
)
def test_wait_for_gateway_rejects_invalid_timeout_before_process_contact(
    tmp_path: Path,
    timeout: object,
) -> None:
    class Process:
        def poll(self):  # noqa: ANN201
            pytest.fail("invalid timeout reached gateway process")

    with pytest.raises(ContractError, match="readiness timeout is invalid"):
        _wait_for_gateway(
            tmp_path / "owned-run.json",
            Process(),  # type: ignore[arg-type]
            timeout,  # type: ignore[arg-type]
            _gateway_route(),
        )


@pytest.mark.parametrize("status", [False, "0", 0.0])
def test_wait_for_gateway_rejects_malformed_process_status(
    tmp_path: Path,
    status: object,
) -> None:
    class Process:
        def poll(self):  # noqa: ANN201
            return status

    with pytest.raises(ContractError, match="process status is invalid"):
        _wait_for_gateway(
            tmp_path / "owned-run.json",
            Process(),  # type: ignore[arg-type]
            1.0,
            _gateway_route(),
        )


def test_wait_for_gateway_status_failure_is_type_only(tmp_path: Path) -> None:
    private = "private-gateway-poll"

    class Process:
        def poll(self):  # noqa: ANN201
            raise OSError(private)

    with pytest.raises(ContractError) as captured:
        _wait_for_gateway(
            tmp_path / "owned-run.json",
            Process(),  # type: ignore[arg-type]
            1.0,
            _gateway_route(),
        )
    assert str(captured.value) == ("network credential gateway status failed (OSError)")
    assert private not in str(captured.value)


def test_gateway_start_preflight_and_readiness_share_one_deadline(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = [100.0]
    budgets: list[tuple[str, float]] = []
    route = {
        **_gateway_route(),
        "preflight_url": "https://probe.invalid/",
    }
    ownership = launcher_module._LaunchOwnership(run_id="owned-run")

    class Process:
        pid = 42

    process = Process()
    monkeypatch.setattr(launcher_module.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(
        "browser_core.proxy_import.has_proxy_secret",
        lambda *_args, **_kwargs: False,
    )
    monkeypatch.setattr(launcher_module, "resolve_network_route", lambda value: value)

    def preflight(_route, _url, *, timeout_seconds):  # noqa: ANN001
        budgets.append(("preflight", timeout_seconds))
        clock[0] += 3.0
        return {"passed": True}

    def observe(_pid: int) -> dict[str, object]:
        clock[0] += 1.0
        return {"pid": 42}

    def wait(ready_path, _process, timeout_seconds, _route):  # noqa: ANN001
        budgets.append(("readiness", timeout_seconds))
        document = _gateway_ready_document()
        ready_path.write_bytes(canonical_json_bytes(document))
        control = launcher_module._claim_owned_control(
            ready_path,
            canonical_json_bytes(document),
            maximum=4096,
            label="gateway readiness",
        )
        return launcher_module._GatewayReadiness(document=document, control=control)

    monkeypatch.setattr(launcher_module, "preflight_network_route", preflight)
    monkeypatch.setattr(launcher_module.subprocess, "Popen", lambda *_a, **_k: process)
    monkeypatch.setattr(launcher_module, "observe_process", observe)
    monkeypatch.setattr(launcher_module, "_wait_for_gateway", wait)

    returned_process, result = launcher_module._start_gateway(
        tmp_path,
        route,
        "owned-run",
        5.0,
        ownership,
    )

    assert returned_process is process
    assert result["endpoint"] == "http://127.0.0.1:8765"
    assert budgets == [
        ("preflight", pytest.approx(5.0)),
        ("readiness", pytest.approx(1.0)),
    ]


def test_gateway_start_rejects_huge_timeout_before_route_contact(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        launcher_module,
        "resolve_network_route",
        lambda _route: pytest.fail("invalid timeout reached route resolution"),
    )

    with pytest.raises(ContractError, match="gateway start timeout is invalid"):
        launcher_module._start_gateway(
            tmp_path,
            _gateway_route(),
            "owned-run",
            10**400,
            launcher_module._LaunchOwnership(run_id="owned-run"),
        )


def test_gateway_start_rejects_run_id_path_before_preflight(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        "browser_core.proxy_import.has_proxy_secret", lambda *_a, **_k: False
    )
    monkeypatch.setattr(launcher_module, "resolve_network_route", lambda route: route)
    monkeypatch.setattr(
        launcher_module,
        "preflight_network_route",
        lambda *_a, **_k: pytest.fail("invalid run ID reached preflight"),
    )

    with pytest.raises(ContractError, match="gateway run ID is invalid"):
        launcher_module._start_gateway(
            tmp_path,
            {**_gateway_route(), "preflight_url": "https://probe.invalid/"},
            "../outside",
            5.0,
            launcher_module._LaunchOwnership(run_id="../outside"),
        )
    assert not (tmp_path / "network").exists()


@pytest.mark.skipif(os.name != "nt", reason="Windows directory junction regression")
@pytest.mark.parametrize("junction_parent", ["network", "gateways"])
def test_gateway_start_rejects_control_directory_junction(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    junction_parent: str,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    external = tmp_path / "external"
    external.mkdir()
    network = workspace / "network"
    if junction_parent == "gateways":
        network.mkdir()
        junction = network / "gateways"
    else:
        junction = network
    created = subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(junction), str(external)],
        capture_output=True,
        check=False,
    )
    if created.returncode != 0:
        pytest.skip("directory junction creation is unavailable")
    try:
        monkeypatch.setattr(
            "browser_core.proxy_import.has_proxy_secret", lambda *_a, **_k: False
        )
        monkeypatch.setattr(launcher_module, "resolve_network_route", lambda route: route)
        monkeypatch.setattr(
            launcher_module,
            "preflight_network_route",
            lambda *_a, **_k: {"passed": True},
        )
        monkeypatch.setattr(
            launcher_module.subprocess,
            "Popen",
            lambda *_a, **_k: pytest.fail("junction reached process spawn"),
        )
        with pytest.raises(ContractError, match="gateway.*directory"):
            launcher_module._start_gateway(
                workspace,
                {**_gateway_route(), "preflight_url": "https://probe.invalid/"},
                "owned-run",
                5.0,
                launcher_module._LaunchOwnership(run_id="owned-run"),
            )
        assert list(external.iterdir()) == []
    finally:
        junction.rmdir()


@pytest.mark.skipif(os.name != "nt", reason="Windows directory junction regression")
def test_gateway_start_rejects_workspace_swapped_after_preflight(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    moved_workspace = tmp_path / "moved-workspace"
    unrelated = tmp_path / "unrelated"
    unrelated.mkdir()
    junction_created = False

    def swap_during_preflight(*_args: object, **_kwargs: object) -> dict[str, bool]:
        nonlocal junction_created
        workspace.rename(moved_workspace)
        result = subprocess.run(
            ["cmd", "/c", "mklink", "/J", str(workspace), str(unrelated)],
            capture_output=True,
            check=False,
        )
        if result.returncode != 0:
            pytest.skip("directory junction creation is unavailable")
        junction_created = True
        return {"passed": True}

    monkeypatch.setattr(
        "browser_core.proxy_import.has_proxy_secret", lambda *_args, **_kwargs: False
    )
    monkeypatch.setattr(launcher_module, "resolve_network_route", lambda route: route)
    monkeypatch.setattr(launcher_module, "preflight_network_route", swap_during_preflight)
    try:
        with pytest.raises(ContractError, match="regular directory"):
            launcher_module._start_gateway(
                workspace,
                {**_gateway_route(), "preflight_url": "https://probe.invalid/"},
                "owned-run",
                5.0,
                launcher_module._LaunchOwnership(run_id="owned-run"),
            )
        assert list(unrelated.iterdir()) == []
    finally:
        if junction_created:
            workspace.rmdir()


def test_gateway_start_rejects_oversized_windows_command_before_preflight(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = tmp_path / ("long" * 2700)
    monkeypatch.setattr(
        "browser_core.proxy_import.has_proxy_secret",
        lambda *_args, **_kwargs: pytest.fail("oversized command reached route lookup"),
    )

    with pytest.raises(ContractError, match="gateway command line exceeds the Windows limit"):
        launcher_module._start_gateway(
            workspace,
            _gateway_route(),
            "owned-run",
            5.0,
            launcher_module._LaunchOwnership(run_id="owned-run"),
        )


def test_wait_for_gateway_retries_missing_or_changing_then_uses_absolute_sleep(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ready = tmp_path / "owned-run.json"
    body = canonical_json_bytes(_gateway_ready_document())
    identity = (1, 2, 0o100600, len(body), 3, 4)
    states = iter(
        [
            BoundedControlSnapshot("missing"),
            BoundedControlSnapshot("changed"),
            BoundedControlSnapshot("complete", body, identity),
            BoundedControlSnapshot("complete", body, identity),
        ]
    )
    sleeps: list[float] = []

    class RunningProcess:
        def poll(self) -> None:
            return None

    monkeypatch.setattr(
        launcher_module,
        "read_bounded_control_snapshot_result",
        lambda *_args, **_kwargs: next(states),
    )
    monkeypatch.setattr(launcher_module.time, "sleep", sleeps.append)
    assert (
        _wait_for_gateway(
            ready,
            RunningProcess(),  # type: ignore[arg-type]
            1.0,
            _gateway_route(),
        ).document
        == _gateway_ready_document()
    )
    assert len(sleeps) == 2 and all(0 < duration <= 0.05 for duration in sleeps)


@pytest.mark.parametrize(
    "body",
    [
        b'{"host":"127.0.0.1"}\n',
        b'{"host": "127.0.0.1"}\n',
        canonical_json_bytes(
            _gateway_ready_document(schema="browser-core.gateway-ready/1")
        ),
        canonical_json_bytes(_gateway_ready_document(run_id="another-run")),
        canonical_json_bytes(_gateway_ready_document(route_sha256_16="2" * 16)),
        canonical_json_bytes(_gateway_ready_document(host="0.0.0.0")),
        canonical_json_bytes(_gateway_ready_document(port=True)),
        canonical_json_bytes(_gateway_ready_document(extra="not-owned")),
    ],
)
def test_wait_for_gateway_rejects_noncanonical_or_mismatched_completed_state(
    tmp_path: Path,
    body: bytes,
) -> None:
    ready = tmp_path / "private-profile" / "owned-run.json"
    ready.parent.mkdir()
    ready.write_bytes(body)

    class RunningProcess:
        def poll(self) -> None:
            return None

    with pytest.raises(ContractError) as raised:
        _wait_for_gateway(
            ready,
            RunningProcess(),  # type: ignore[arg-type]
            1.0,
            _gateway_route(),
        )
    assert str(ready) not in str(raised.value)


def _minimal_session() -> dict[str, object]:
    return {
        "schema": "browser-core.session/1",
        "run_id": "owned-run",
        "chromium_revision": "a" * 40,
        "pid": 123,
        "automation": {
            "transport": "cdp",
            "cdp_endpoint": "http://127.0.0.1:9222",
        },
    }


def test_session_publication_returns_the_exact_exclusive_bytes(tmp_path: Path) -> None:
    session_path = tmp_path / "sessions" / "owned-run.json"
    ownership = launcher_module._LaunchOwnership(run_id="owned-run")
    session = _minimal_session()

    published = _publish_session_document(
        session_path,
        session,  # type: ignore[arg-type]
        ownership,
    )
    assert published == session
    assert session_path.read_bytes() == canonical_json_bytes(session)  # type: ignore[arg-type]
    assert ownership.session_path is not None
    assert ownership.session_path.path == session_path
    assert not list(session_path.parent.glob(".owned-run.json.tmp-*"))


@pytest.mark.skipif(os.name != "nt", reason="Windows directory junction regression")
def test_session_publication_rejects_junction_ancestor_before_creating_parent(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    unrelated = tmp_path / "unrelated"
    unrelated.mkdir()
    junction = workspace / "sessions"
    subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(junction), str(unrelated)],
        check=True,
        capture_output=True,
        text=True,
    )
    ownership = launcher_module._LaunchOwnership(run_id="owned-run")

    with pytest.raises(ContractError, match="regular directory"):
        _publish_session_document(
            junction / "nested" / "owned-run.json",
            _minimal_session(),  # type: ignore[arg-type]
            ownership,
        )
    assert not (unrelated / "nested").exists()
    assert ownership.session_path is None


@pytest.mark.skipif(os.name != "nt", reason="Windows directory junction regression")
@pytest.mark.parametrize("destination", ["ephemeral", "traces"])
def test_launch_rejects_junction_output_parent_before_browser_start(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    destination: str,
) -> None:
    executable = tmp_path / "chrome.exe"
    executable.write_bytes(b"fixture")
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    unrelated = tmp_path / "unrelated"
    unrelated.mkdir()
    if destination == "ephemeral":
        (workspace / "profiles").mkdir()
        junction = workspace / "profiles" / "ephemeral"
    else:
        junction = workspace / "traces"
    subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(junction), str(unrelated)],
        check=True,
        capture_output=True,
        text=True,
    )
    monkeypatch.setattr(
        launcher_module,
        "verify_upstream",
        lambda _root: {
            "chromium": {"version": "153.0.7988.0", "revision": "a" * 40}
        },
    )
    monkeypatch.setattr(
        launcher_module,
        "executable_evidence",
        lambda *_args, **_kwargs: {"verified": True},
    )
    monkeypatch.setattr(launcher_module, "new_run_id", lambda: "owned-run")
    monkeypatch.setattr(
        launcher_module.subprocess,
        "Popen",
        lambda *_args, **_kwargs: pytest.fail("junction reached browser spawn"),
    )
    config = launcher_module.EvaluationLaunch(
        executable=executable,
        workspace=workspace,
        trace_mode="off" if destination == "ephemeral" else "on",
    )

    with pytest.raises(ContractError, match="regular directory"):
        launcher_module._launch_evaluation_owned(
            config,
            tmp_path / "repository",
            launcher_module._LaunchOwnership(),
        )
    assert list(unrelated.iterdir()) == []


@pytest.mark.skipif(os.name != "nt", reason="Windows directory junction regression")
@pytest.mark.parametrize("destination", ["ephemeral", "traces"])
def test_launch_rejects_output_parent_swapped_after_preparation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    destination: str,
) -> None:
    executable = tmp_path / "chrome.exe"
    executable.write_bytes(b"fixture")
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    unrelated = tmp_path / "unrelated"
    unrelated.mkdir()
    moved_parent = tmp_path / "moved-parent"
    selected_label = (
        "ephemeral profile parent" if destination == "ephemeral" else "live trace parent"
    )
    original_prepare = launcher_module.prepare_owned_directory_parent
    junction: Path | None = None

    def swap_after_preparation(parent: Path, *, label: str) -> None:
        nonlocal junction
        original_prepare(parent, label=label)
        if label != selected_label:
            return
        parent.rename(moved_parent)
        result = subprocess.run(
            ["cmd", "/c", "mklink", "/J", str(parent), str(unrelated)],
            capture_output=True,
            check=False,
        )
        if result.returncode != 0:
            pytest.skip("directory junction creation is unavailable")
        junction = parent

    monkeypatch.setattr(
        launcher_module, "prepare_owned_directory_parent", swap_after_preparation
    )
    monkeypatch.setattr(
        launcher_module,
        "verify_upstream",
        lambda _root: {
            "chromium": {"version": "153.0.7988.0", "revision": "a" * 40}
        },
    )
    monkeypatch.setattr(
        launcher_module,
        "executable_evidence",
        lambda *_args, **_kwargs: {"verified": True},
    )
    monkeypatch.setattr(launcher_module, "new_run_id", lambda: "owned-run")
    monkeypatch.setattr(
        launcher_module,
        "evaluation_command",
        lambda *_args, **_kwargs: pytest.fail("swapped parent reached command build"),
    )
    config = launcher_module.EvaluationLaunch(
        executable=executable,
        workspace=workspace,
        trace_mode="off" if destination == "ephemeral" else "on",
    )

    try:
        with pytest.raises(ContractError, match="regular directory"):
            launcher_module._launch_evaluation_owned(
                config,
                tmp_path / "repository",
                launcher_module._LaunchOwnership(),
            )
        assert list(unrelated.iterdir()) == []
    finally:
        if junction is not None:
            junction.rmdir()


def test_session_publication_consumes_publisher_claim_without_reopening(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session_path = tmp_path / "sessions" / "owned-run.json"
    ownership = launcher_module._LaunchOwnership(run_id="owned-run")
    monkeypatch.setattr(
        launcher_module,
        "_claim_owned_control",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("session publication reopened its final path")
        ),
    )

    assert (
        _publish_session_document(
            session_path,
            _minimal_session(),  # type: ignore[arg-type]
            ownership,
        )
        == _minimal_session()
    )
    assert ownership.session_path is not None
    assert ownership.session_path.identity == control_files._identity(
        launcher_module.os.lstat(session_path)
    )


def test_session_publication_preserves_preexisting_target_and_does_not_claim_it(
    tmp_path: Path,
) -> None:
    session_path = tmp_path / "sessions" / "owned-run.json"
    session_path.parent.mkdir()
    existing = b"preexisting-session"
    session_path.write_bytes(existing)
    ownership = launcher_module._LaunchOwnership(run_id="owned-run")

    with pytest.raises(ContractError, match="publication failed") as raised:
        _publish_session_document(
            session_path,
            _minimal_session(),  # type: ignore[arg-type]
            ownership,
        )
    assert str(session_path) not in str(raised.value)
    assert session_path.read_bytes() == existing
    assert ownership.session_path is None


def test_session_publication_claims_final_before_postpublication_validation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session_path = tmp_path / "sessions" / "owned-run.json"
    ownership = launcher_module._LaunchOwnership(run_id="owned-run")
    monkeypatch.setattr(
        launcher_module,
        "load_canonical_json_document",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            ContractError("post-publication validation failed")
        ),
    )

    with pytest.raises(ContractError, match="post-publication"):
        _publish_session_document(
            session_path,
            _minimal_session(),  # type: ignore[arg-type]
            ownership,
        )
    assert ownership.session_path is not None
    assert ownership.session_path.path == session_path
    assert session_path.exists()
    assert launcher_module._abort_evaluation_launch(ownership) == ()
    assert not session_path.exists()


def test_owned_control_claim_binds_exact_bytes_and_identity(tmp_path: Path) -> None:
    path = tmp_path / "owned.control"
    body = b"owned-control"
    path.write_bytes(body)

    claim = launcher_module._claim_owned_control(
        path,
        body,
        maximum=4096,
        label="owned control",
    )
    assert claim.path == path
    assert claim.body == body
    assert claim.maximum == 4096

    path.write_bytes(b"changed-control")
    with pytest.raises(ContractError, match="changed before ownership claim"):
        launcher_module._claim_owned_control(
            path,
            body,
            maximum=4096,
            label="owned control",
        )


def test_launch_abort_removes_only_exact_claimed_controls(tmp_path: Path) -> None:
    ownership = launcher_module._LaunchOwnership(run_id="owned-run")
    controls = []
    for field, maximum in (
        ("gateway_lease", 4096),
        ("gateway_ready", 4096),
        ("session_path", 1024 * 1024),
    ):
        path = tmp_path / f"{field}.control"
        body = f"owned-{field}".encode("ascii")
        path.write_bytes(body)
        claim = launcher_module._claim_owned_control(
            path,
            body,
            maximum=maximum,
            label=field,
        )
        setattr(ownership, field, claim)
        controls.append(path)

    assert launcher_module._abort_evaluation_launch(ownership) == ()
    assert all(not path.exists() for path in controls)
    assert not list(tmp_path.glob(".*.removed-*"))


def test_launch_abort_removes_only_the_owned_ephemeral_profile(tmp_path: Path) -> None:
    profile = tmp_path / "ephemeral-profile"
    profile.mkdir()
    (profile / "state.bin").write_bytes(b"owned")
    identity = launcher_module.directory_identity(profile, label="ephemeral profile")
    assert identity is not None
    ownership = launcher_module._LaunchOwnership(
        run_id="owned-run",
        ephemeral_profile=launcher_module._OwnedDirectory(
            profile,
            identity,
            launcher_module.directory_ancestry_binding(
                profile.absolute(), label="ephemeral profile"
            ),
        ),
    )
    assert launcher_module._abort_evaluation_launch(ownership) == ()
    assert not profile.exists()


def test_launch_abort_preserves_a_replaced_ephemeral_profile(tmp_path: Path) -> None:
    profile = tmp_path / "ephemeral-profile"
    profile.mkdir()
    identity = launcher_module.directory_identity(profile, label="ephemeral profile")
    assert identity is not None
    ancestry = launcher_module.directory_ancestry_binding(
        profile.absolute(), label="ephemeral profile"
    )
    holding = tmp_path / "holding"
    profile.rename(holding)
    profile.mkdir()
    (profile / "competitor.bin").write_bytes(b"competitor")
    ownership = launcher_module._LaunchOwnership(
        run_id="owned-run",
        ephemeral_profile=launcher_module._OwnedDirectory(profile, identity, ancestry),
    )
    assert launcher_module._abort_evaluation_launch(ownership) == (
        "ephemeral-profile:conditional-remove",
    )
    assert (profile / "competitor.bin").read_bytes() == b"competitor"


def test_launch_abort_treats_claimed_control_disappearance_as_clean(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ownership = launcher_module._LaunchOwnership(
        run_id="owned-run",
        profile_lock=tmp_path / "already-missing.lock",
    )
    for field, maximum in (
        ("gateway_lease", 4096),
        ("gateway_ready", 4096),
        ("session_path", 1024 * 1024),
    ):
        path = tmp_path / f"{field}.control"
        body = f"owned-{field}".encode("ascii")
        path.write_bytes(body)
        setattr(
            ownership,
            field,
            launcher_module._claim_owned_control(
                path,
                body,
                maximum=maximum,
                label=field,
            ),
        )
    real_remove = launcher_module.remove_control_conditionally

    def disappear_then_remove(path: Path, **kwargs: object) -> None:
        assert kwargs["missing_ok"] is True
        launcher_module.os.unlink(path)
        real_remove(path, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(
        launcher_module,
        "remove_control_conditionally",
        disappear_then_remove,
    )

    assert launcher_module._abort_evaluation_launch(ownership) == ()
    assert not list(tmp_path.glob("*.control"))


def test_launch_abort_preserves_every_competing_control_replacement(
    tmp_path: Path,
) -> None:
    ownership = launcher_module._LaunchOwnership(run_id="owned-run")
    expected_failures = []
    controls: list[tuple[Path, bytes]] = []
    for field, label, maximum in (
        ("gateway_lease", "gateway-lease", 4096),
        ("gateway_ready", "gateway-ready", 4096),
        ("session_path", "session-document", 1024 * 1024),
    ):
        path = tmp_path / f"{field}.control"
        body = f"owned-{field}".encode("ascii")
        competitor = f"competitor-{field}".encode("ascii")
        path.write_bytes(body)
        setattr(
            ownership,
            field,
            launcher_module._claim_owned_control(
                path,
                body,
                maximum=maximum,
                label=label,
            ),
        )
        injected = tmp_path / f"injected-{field}"
        injected.write_bytes(competitor)
        launcher_module.os.replace(injected, path)
        expected_failures.append(f"{label}:conditional-remove")
        controls.append((path, competitor))

    assert launcher_module._abort_evaluation_launch(ownership) == tuple(
        expected_failures
    )
    assert all(path.read_bytes() == body for path, body in controls)
    assert not list(tmp_path.glob(".*.removed-*"))


def test_postpublication_abort_preserves_replaced_session_and_reports_cleanup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session_path = tmp_path / "sessions" / "owned-run.json"
    ownership = launcher_module._LaunchOwnership(run_id="owned-run")
    competitor = b"competitor-session"

    def replace_then_fail(*_args: object, **_kwargs: object) -> dict[str, object]:
        injected = tmp_path / "injected-session"
        injected.write_bytes(competitor)
        launcher_module.os.replace(injected, session_path)
        raise ContractError("post-publication validation failed")

    monkeypatch.setattr(
        launcher_module,
        "load_canonical_json_document",
        replace_then_fail,
    )
    with pytest.raises(ContractError, match="post-publication"):
        _publish_session_document(
            session_path,
            _minimal_session(),  # type: ignore[arg-type]
            ownership,
        )
    assert ownership.session_path is not None

    failures = launcher_module._abort_evaluation_launch(ownership)
    assert failures == ("session-document:conditional-remove",)
    assert session_path.read_bytes() == competitor
    assert not list(session_path.parent.glob(".owned-run.json.removed-*"))


def test_launched_process_handle_is_retained_until_reaped() -> None:
    class Process:
        pid = 424242

        def poll(self):
            return 0

        def wait(self, timeout):
            assert timeout == 0
            return 0

    process = Process()
    launcher_module._retain_launched_process(process)
    assert launcher_module._LAUNCHED_PROCESS_HANDLES[process.pid] is process
    assert launcher_module.reap_launched_process(process.pid) is True
    assert process.pid not in launcher_module._LAUNCHED_PROCESS_HANDLES


def test_launched_process_reap_failure_preserves_exact_handle() -> None:
    class Process:
        pid = 424243

        def wait(self, timeout):  # noqa: ANN001
            assert timeout == 0
            raise OSError("private wait diagnostic")

    process = Process()
    launcher_module._retain_launched_process(process)  # type: ignore[arg-type]

    assert launcher_module.reap_launched_process(process.pid) is False
    assert launcher_module._LAUNCHED_PROCESS_HANDLES[process.pid] is process
    launcher_module._LAUNCHED_PROCESS_HANDLES.pop(process.pid)


def test_launched_process_reap_rejects_boolean_status_and_invalid_pid() -> None:
    class Process:
        pid = 424244

        def wait(self, timeout):  # noqa: ANN001
            assert timeout == 0
            return False

    process = Process()
    launcher_module._retain_launched_process(process)  # type: ignore[arg-type]
    assert launcher_module.reap_launched_process(process.pid) is False
    assert launcher_module._LAUNCHED_PROCESS_HANDLES[process.pid] is process
    launcher_module._LAUNCHED_PROCESS_HANDLES.pop(process.pid)

    with pytest.raises(ContractError, match="reap pid is invalid"):
        launcher_module.reap_launched_process(True)


def test_launched_process_collision_status_failure_is_type_only() -> None:
    class Existing:
        pid = 424245

        def poll(self):  # noqa: ANN201
            raise OSError("private existing handle")

    class Replacement:
        pid = 424245

    existing = Existing()
    launcher_module._LAUNCHED_PROCESS_HANDLES[existing.pid] = existing  # type: ignore[assignment]
    try:
        with pytest.raises(ContractError) as captured:
            launcher_module._retain_launched_process(Replacement())  # type: ignore[arg-type]
        assert str(captured.value) == (
            "existing launched-process handle status is unavailable"
        )
        assert "private" not in str(captured.value)
        assert launcher_module._LAUNCHED_PROCESS_HANDLES[existing.pid] is existing
    finally:
        launcher_module._LAUNCHED_PROCESS_HANDLES.pop(existing.pid, None)


def test_launch_abort_process_stop_escalates_after_wait_oserror() -> None:
    class Process:
        def __init__(self) -> None:
            self.waits: list[float] = []
            self.killed = False

        def poll(self):  # noqa: ANN201
            raise OSError("private poll diagnostic")

        def terminate(self) -> None:
            raise OSError("private terminate diagnostic")

        def wait(self, timeout: float) -> int:
            self.waits.append(timeout)
            if len(self.waits) == 1:
                raise OSError("private wait diagnostic")
            return -9

        def kill(self) -> None:
            self.killed = True

    process = Process()
    failures: list[str] = []
    launcher_module._stop_owned_launch_process(
        process,  # type: ignore[arg-type]
        "browser-process",
        launcher_module.time.monotonic() + 5.0,
        failures,
    )

    assert process.killed is True
    assert len(process.waits) == 2
    assert all(0 <= timeout <= 5.0 for timeout in process.waits)
    assert failures == []


def test_launch_abort_process_stop_reports_only_final_unreapable_state() -> None:
    class Process:
        def __init__(self) -> None:
            self.waits = 0
            self.killed = False

        def poll(self):  # noqa: ANN201
            return None

        def terminate(self) -> None:
            return None

        def wait(self, timeout: float) -> int:
            self.waits += 1
            raise launcher_module.subprocess.TimeoutExpired(
                "private browser command", timeout
            )

        def kill(self) -> None:
            self.killed = True

    process = Process()
    failures: list[str] = []
    launcher_module._stop_owned_launch_process(
        process,  # type: ignore[arg-type]
        "browser-process",
        launcher_module.time.monotonic() + 5.0,
        failures,
    )

    assert process.killed is True
    assert process.waits == 2
    assert failures == ["browser-process:kill-wait:timeout"]


def test_launch_abort_preserves_browser_containment_when_exit_is_unverified(
    tmp_path: Path,
) -> None:
    class Process:
        pid = 424246

        def __init__(self) -> None:
            self.waits = 0
            self.killed = False

        def poll(self):  # noqa: ANN201
            return None

        def terminate(self) -> None:
            return None

        def wait(self, timeout: float) -> int:
            self.waits += 1
            raise launcher_module.subprocess.TimeoutExpired("private command", timeout)

        def kill(self) -> None:
            self.killed = True

    process = Process()
    launcher_module._retain_launched_process(process)  # type: ignore[arg-type]
    session = tmp_path / "session.json"
    session.write_bytes(b"owned-session")
    lock = tmp_path / "profile.lock"
    lock.write_bytes(b"owned-lock")
    profile = tmp_path / "ephemeral-profile"
    profile.mkdir()
    (profile / "state.bin").write_bytes(b"owned")
    profile_identity = launcher_module.directory_identity(
        profile,
        label="ephemeral profile",
    )
    assert profile_identity is not None
    lease = tmp_path / "gateway.lease"
    lease.write_bytes(b"owned-lease")
    ready = tmp_path / "gateway.ready"
    ready.write_bytes(b"owned-ready")
    ownership = launcher_module._LaunchOwnership(
        run_id="owned-run",
        gateway_lease=launcher_module._claim_owned_control(
            lease,
            b"owned-lease",
            maximum=4096,
            label="gateway lease",
        ),
        gateway_ready=launcher_module._claim_owned_control(
            ready,
            b"owned-ready",
            maximum=4096,
            label="gateway readiness",
        ),
        browser_process=process,  # type: ignore[arg-type]
        session_path=launcher_module._claim_owned_control(
            session,
            b"owned-session",
            maximum=4096,
            label="session",
        ),
        profile_lock=lock,
        ephemeral_profile=launcher_module._OwnedDirectory(
            profile,
            profile_identity,
            launcher_module.directory_ancestry_binding(
                profile.absolute(), label="ephemeral profile"
            ),
        ),
    )
    try:
        assert launcher_module._abort_evaluation_launch(ownership) == (
            "browser-process:kill-wait:timeout",
        )
        assert process.killed is True
        assert process.waits == 2
        assert session.read_bytes() == b"owned-session"
        assert lock.read_bytes() == b"owned-lock"
        assert (profile / "state.bin").read_bytes() == b"owned"
        assert not lease.exists()
        assert not ready.exists()
        assert launcher_module._LAUNCHED_PROCESS_HANDLES[process.pid] is process
    finally:
        launcher_module._LAUNCHED_PROCESS_HANDLES.pop(process.pid, None)


def test_launch_abort_gives_browser_and_gateway_independent_stop_budgets(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = [10.0]
    budgets: list[tuple[str, float]] = []

    def stop(process, label, deadline, failures):  # noqa: ANN001
        budgets.append((label, deadline - clock[0]))
        clock[0] += 5.0
        return False

    monkeypatch.setattr(launcher_module.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(launcher_module, "_stop_owned_launch_process", stop)
    ownership = launcher_module._LaunchOwnership(
        browser_process=object(),  # type: ignore[arg-type]
        gateway_process=object(),  # type: ignore[arg-type]
    )

    assert launcher_module._abort_evaluation_launch(ownership) == ()
    assert budgets == [
        ("browser-process", pytest.approx(5.0)),
        ("gateway-process", pytest.approx(5.0)),
    ]


def test_launch_abort_preserves_gateway_readiness_when_stop_is_unverified(
    tmp_path: Path,
) -> None:
    class Process:
        def poll(self):  # noqa: ANN201
            return None

        def terminate(self) -> None:
            return None

        def wait(self, timeout: float) -> int:
            raise launcher_module.subprocess.TimeoutExpired("private gateway", timeout)

        def kill(self) -> None:
            return None

    lease = tmp_path / "owned-run.lease"
    ready = tmp_path / "owned-run.json"
    lease.write_bytes(b"owned-lease")
    ready.write_bytes(b"owned-ready")
    ownership = launcher_module._LaunchOwnership(
        gateway_process=Process(),  # type: ignore[arg-type]
        gateway_lease=launcher_module._claim_owned_control(
            lease,
            b"owned-lease",
            maximum=4096,
            label="gateway lease",
        ),
        gateway_ready=launcher_module._claim_owned_control(
            ready,
            b"owned-ready",
            maximum=4096,
            label="gateway readiness",
        ),
    )

    assert launcher_module._abort_evaluation_launch(ownership) == (
        "gateway-process:kill-wait:timeout",
    )
    assert not lease.exists()
    assert ready.read_bytes() == b"owned-ready"
