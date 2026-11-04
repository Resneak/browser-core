from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

import browser_core.process as process_module
from browser_core.contracts import ContractError
from browser_core.process import (
    MAX_PROC_STAT_BYTES,
    ProcessQueryUnavailable,
    _parse_proc_stat,
    identities_match,
    observe_process,
    terminate_verified,
    wait_for_verified_exit,
)


def _mock_pidfd(
    monkeypatch: pytest.MonkeyPatch,
    send: object,
) -> None:
    monkeypatch.setattr(process_module.sys, "platform", "linux")
    monkeypatch.setattr(
        process_module.os, "pidfd_open", lambda _pid, _flags: 99, raising=False
    )
    monkeypatch.setattr(process_module.signal, "pidfd_send_signal", send, raising=False)
    monkeypatch.setattr(process_module.os, "close", lambda _fd: None)


def test_process_identity_includes_pid_marker_and_executable(tmp_path: Path) -> None:
    executable = tmp_path / "chrome.exe"
    executable.write_bytes(b"")
    expected = {"pid": 42, "executable": str(executable), "start_marker": "fixture:1"}
    assert identities_match(expected, dict(expected))
    assert not identities_match(expected, {**expected, "start_marker": "fixture:2"})
    assert not identities_match(expected, {**expected, "pid": 43})


def test_process_identity_comparison_is_lexical_and_does_not_require_the_path(
    tmp_path: Path,
) -> None:
    expected = {
        "pid": 42,
        "executable": str(tmp_path / "missing" / ".." / "chrome.exe"),
        "start_marker": "fixture:1",
    }
    actual = {
        "pid": 42,
        "executable": str(tmp_path / "chrome.exe"),
        "start_marker": "fixture:1",
    }
    assert not (tmp_path / "chrome.exe").exists()
    assert identities_match(expected, actual)


@pytest.mark.parametrize(
    "identity",
    [
        None,
        {},
        {"pid": True, "executable": "C:/chrome.exe", "start_marker": "fixture:1"},
        {"pid": 0, "executable": "C:/chrome.exe", "start_marker": "fixture:1"},
        {"pid": 42, "executable": "relative.exe", "start_marker": "fixture:1"},
        {"pid": 42, "executable": "C:/chrome.exe", "start_marker": "bad\nmarker"},
    ],
)
def test_process_identity_comparison_rejects_malformed_values(identity: object) -> None:
    valid = {"pid": 42, "executable": "C:/chrome.exe", "start_marker": "fixture:1"}
    assert identities_match(valid, identity) is False  # type: ignore[arg-type]


def test_proc_stat_parser_handles_spaces_and_parentheses_in_comm() -> None:
    fields = [b"S"] + [b"0"] * 18 + [b"987654"]
    body = b"42 (worker ) name) " + b" ".join(fields) + b"\n"
    assert _parse_proc_stat(body, 42) == "987654"


@pytest.mark.parametrize(
    "body",
    [
        b"43 (worker) S " + b" ".join([b"0"] * 19),
        b"42 worker) S " + b" ".join([b"0"] * 19),
        b"42 (worker) S 0",
        b"42 (worker) S " + b" ".join([b"0"] * 18 + [b"not-a-number"]),
        b"x" * (MAX_PROC_STAT_BYTES + 1),
    ],
)
def test_proc_stat_parser_rejects_ambiguous_or_oversized_rows(body: bytes) -> None:
    with pytest.raises(ProcessQueryUnavailable):
        _parse_proc_stat(body, 42)


def test_proc_permission_denial_does_not_prove_process_exit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def denied(*_args: object, **_kwargs: object) -> int:
        raise PermissionError(13, "private query diagnostic")

    monkeypatch.setattr(process_module.os, "open", denied)
    with pytest.raises(ProcessQueryUnavailable) as failure:
        process_module._proc_process_identity(42)
    assert "private" not in str(failure.value)


def test_proc_missing_process_remains_a_verified_absence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def missing(*_args: object, **_kwargs: object) -> int:
        raise FileNotFoundError(2, "no process")

    monkeypatch.setattr(process_module.os, "open", missing)
    with pytest.raises(ProcessLookupError):
        process_module._proc_process_identity(42)


def test_stop_refuses_pid_reuse(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    executable = tmp_path / "chrome.exe"
    executable.write_bytes(b"")
    expected = {"pid": 42, "executable": str(executable), "start_marker": "fixture:1"}
    monkeypatch.setattr(
        "browser_core.process.observe_process",
        lambda pid: {
            "pid": pid,
            "executable": str(executable),
            "start_marker": "fixture:reused",
        },
    )
    _mock_pidfd(
        monkeypatch,
        lambda *_args: pytest.fail("mismatched process received a signal"),
    )
    with pytest.raises(ContractError, match="identity does not match"):
        terminate_verified(expected)


def test_wait_for_exit_tolerates_transient_query_denial(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    expected = {"pid": 42, "executable": "C:/chrome.exe", "start_marker": "fixture:1"}
    outcomes = iter((ContractError("Windows error 5"), ProcessLookupError(42)))

    def observe(_pid: int) -> dict[str, object]:
        raise next(outcomes)

    monkeypatch.setattr("browser_core.process.observe_process", observe)
    monkeypatch.setattr("browser_core.process.time.sleep", lambda _duration: None)
    assert wait_for_verified_exit(expected, 1.0) is True


def test_zero_budget_wait_still_observes_current_process_state(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    expected = {"pid": 42, "executable": "C:/chrome.exe", "start_marker": "fixture:1"}
    observed: list[int] = []

    def absent(pid: int) -> dict[str, object]:
        observed.append(pid)
        raise ProcessLookupError(pid)

    monkeypatch.setattr(process_module, "observe_process", absent)
    assert wait_for_verified_exit(expected, 0.0) is True
    assert observed == [42]


def test_wait_for_exit_caps_its_final_sleep_at_the_deadline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    expected = {"pid": 42, "executable": "C:/chrome.exe", "start_marker": "fixture:1"}
    clock = [20.0]
    sleeps: list[float] = []

    def sleep(duration: float) -> None:
        sleeps.append(duration)
        clock[0] += duration

    monkeypatch.setattr(process_module.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(process_module.time, "sleep", sleep)
    monkeypatch.setattr(process_module, "observe_process", lambda _pid: dict(expected))

    assert wait_for_verified_exit(expected, 0.02) is False
    assert sleeps == [pytest.approx(0.02)]
    assert clock[0] == pytest.approx(20.02)


def test_wait_for_exit_does_not_treat_malformed_observation_as_exit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    expected = {
        "pid": 42,
        "executable": "C:/chrome.exe",
        "start_marker": "fixture:1",
    }
    clock = [20.0]
    observations = 0

    def observe(_pid: int) -> dict[str, object]:
        nonlocal observations
        observations += 1
        return {"pid": 42, "executable": "relative.exe"}

    def sleep(duration: float) -> None:
        clock[0] += duration

    monkeypatch.setattr(process_module.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(process_module.time, "sleep", sleep)
    monkeypatch.setattr(process_module, "observe_process", observe)

    assert wait_for_verified_exit(expected, 0.02) is False
    assert observations == 1


def test_proc_identity_close_attempts_both_descriptors_type_only(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    opens = iter((10, 11))
    reads = iter(
        (
            b"42 (worker) S " + b" ".join([b"0"] * 18 + [b"123"]),
            b"",
        )
    )
    closed: list[int] = []
    monkeypatch.setattr(
        process_module.os, "open", lambda *_args, **_kwargs: next(opens)
    )
    monkeypatch.setattr(
        process_module.os,
        "fstat",
        lambda fd: SimpleNamespace(st_dev=1, st_ino=fd),
    )
    monkeypatch.setattr(
        process_module.os,
        "readlink",
        lambda *_args, **_kwargs: "/owned/chrome",
    )
    monkeypatch.setattr(process_module.os, "read", lambda *_args: next(reads))

    def close(fd: int) -> None:
        closed.append(fd)
        if fd == 11:
            raise OSError("private stat close")

    monkeypatch.setattr(process_module.os, "close", close)

    with pytest.raises(ProcessQueryUnavailable):
        process_module._proc_process_identity(42)
    assert closed == [11, 10]


def test_proc_identity_rejects_executable_change_during_observation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    opens = iter((10, 11))
    reads = iter((
        b"42 (worker) S " + b" ".join([b"0"] * 18 + [b"123"]), b"",
    ))
    executable_paths = iter(("/owned/chrome", "/foreign/other"))
    closed: list[int] = []
    monkeypatch.setattr(process_module.os, "open", lambda *_args, **_kwargs: next(opens))
    monkeypatch.setattr(process_module.os, "fstat",
        lambda fd: SimpleNamespace(st_dev=1, st_ino=fd))
    monkeypatch.setattr(process_module.os, "readlink",
        lambda *_args, **_kwargs: next(executable_paths))
    monkeypatch.setattr(process_module.os, "read", lambda *_args: next(reads))
    monkeypatch.setattr(process_module.os, "close", lambda fd: closed.append(fd))

    with pytest.raises(ProcessQueryUnavailable):
        process_module._proc_process_identity(42)
    assert closed == [11, 10]


def test_termination_observation_and_exit_wait_share_one_deadline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    expected = {"pid": 42, "executable": "C:/chrome.exe", "start_marker": "fixture:1"}
    clock = [30.0]
    waits: list[float] = []

    def observe(_pid: int) -> dict[str, object]:
        clock[0] += 0.4
        return dict(expected)

    def terminate(_pidfd: int, _signal: int, _siginfo: object, _flags: int) -> None:
        clock[0] += 0.3

    monkeypatch.setattr(process_module.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(process_module, "observe_process", observe)
    _mock_pidfd(monkeypatch, terminate)
    monkeypatch.setattr(
        process_module,
        "wait_for_verified_exit",
        lambda _expected, timeout: waits.append(timeout) or True,
    )

    terminate_verified(expected, timeout_seconds=1.0)
    assert waits == [pytest.approx(0.3)]


def test_posix_termination_handle_close_failure_is_fixed_and_blocks_wait(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    expected = {
        "pid": 42,
        "executable": "/owned/chrome",
        "start_marker": "fixture:1",
    }
    signals: list[int] = []
    monkeypatch.setattr(process_module, "observe_process", lambda _pid: dict(expected))
    _mock_pidfd(
        monkeypatch,
        lambda _fd, sent, _info, _flags: signals.append(sent),
    )
    monkeypatch.setattr(
        process_module.os,
        "close",
        lambda _fd: (_ for _ in ()).throw(OSError("private pidfd close")),
    )
    monkeypatch.setattr(
        process_module,
        "wait_for_verified_exit",
        lambda *_args, **_kwargs: pytest.fail("close failure reached exit wait"),
    )

    with pytest.raises(ContractError) as captured:
        terminate_verified(expected, timeout_seconds=1.0)
    assert str(captured.value) == "cannot close identity-bound process handle"
    assert "private" not in str(captured.value)
    assert signals == [process_module.signal.SIGTERM]


def test_windows_query_handle_close_failure_blocks_identity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Kernel:
        def OpenProcess(self, *_args):  # noqa: ANN002, ANN201
            return 99

        def CloseHandle(self, _handle: int) -> bool:
            return False

    kernel = Kernel()
    monkeypatch.setattr(
        process_module.ctypes, "WinDLL", lambda *_args, **_kwargs: kernel, raising=False
    )
    monkeypatch.setattr(
        process_module, "_configure_windows_process_api", lambda _kernel: None
    )
    monkeypatch.setattr(
        process_module,
        "_windows_process_identity_from_handle",
        lambda *_args: {
            "pid": 42,
            "executable": "C:/chrome.exe",
            "start_marker": "windows-filetime:1",
        },
    )

    with pytest.raises(
        ContractError, match="cannot close browser process query handle"
    ):
        process_module._windows_process_identity(42)


@pytest.mark.parametrize("stage", ["image", "times"])
@pytest.mark.parametrize("code", [6, 31, 87, 1168])
def test_windows_handle_query_failure_does_not_prove_exit(
    monkeypatch: pytest.MonkeyPatch, stage: str, code: int
) -> None:
    kernel = SimpleNamespace(
        QueryFullProcessImageNameW=lambda *_args: stage != "image",
        GetProcessTimes=lambda *_args: stage != "times",
    )
    monkeypatch.setattr(process_module.ctypes, "get_last_error", lambda: code)
    with pytest.raises(ProcessQueryUnavailable):
        process_module._windows_process_identity_from_handle(kernel, 99, 42)


def test_windows_exited_handle_proves_exit_before_identity_query() -> None:
    class Kernel:
        def GetExitCodeProcess(self, _handle: int, output: object) -> bool:
            code = process_module.ctypes.cast(
                output, process_module.ctypes.POINTER(process_module.wintypes.DWORD)
            )
            code.contents.value = 0
            return True

        def QueryFullProcessImageNameW(self, *_args: object) -> bool:
            pytest.fail("exited handle reached identity query")

    with pytest.raises(ProcessLookupError):
        process_module._windows_process_identity_from_handle(Kernel(), 99, 42)


def test_windows_still_active_exit_code_does_not_prove_exit() -> None:
    class Kernel:
        def GetExitCodeProcess(self, _handle: int, output: object) -> bool:
            code = process_module.ctypes.cast(
                output, process_module.ctypes.POINTER(process_module.wintypes.DWORD)
            )
            code.contents.value = 259
            return True

        def QueryFullProcessImageNameW(self, *_args: object) -> bool:
            return False

    with pytest.raises(ProcessQueryUnavailable):
        process_module._windows_process_identity_from_handle(Kernel(), 99, 42)


def test_windows_signaled_handle_proves_exit_with_still_active_code() -> None:
    class Kernel:
        def WaitForSingleObject(self, _handle: int, _milliseconds: int) -> int:
            return 0

        def GetExitCodeProcess(self, _handle: int, output: object) -> bool:
            code = process_module.ctypes.cast(
                output, process_module.ctypes.POINTER(process_module.wintypes.DWORD)
            )
            code.contents.value = 259
            return True

        def QueryFullProcessImageNameW(self, *_args: object) -> bool:
            pytest.fail("signaled handle reached identity query")

    with pytest.raises(ProcessLookupError):
        process_module._windows_process_identity_from_handle(Kernel(), 99, 42)


@pytest.mark.parametrize("state", [False, True, 0.0, None, -1, 128, 0xFFFFFFFF])
def test_windows_invalid_wait_result_does_not_prove_exit(state: object) -> None:
    class Kernel:
        def WaitForSingleObject(self, _handle: int, _milliseconds: int) -> object:
            return state

        def GetExitCodeProcess(self, *_args: object) -> bool:
            pytest.fail("invalid wait result reached exit-code query")

    with pytest.raises(ProcessQueryUnavailable, match="wait state"):
        process_module._windows_process_identity_from_handle(Kernel(), 99, 42)


@pytest.mark.skipif(sys.platform != "win32", reason="Windows process exit semantics")
def test_windows_exit_code_259_is_a_verified_exit() -> None:
    process = subprocess.Popen(
        [sys.executable, "-c", "import sys, time; time.sleep(0.5); sys.exit(259)"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        expected = observe_process(process.pid)
        assert process.wait(timeout=5.0) == 259
        assert wait_for_verified_exit(expected, 0.2) is True
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5.0)


def test_windows_failed_exit_status_query_does_not_prove_exit() -> None:
    class Kernel:
        def GetExitCodeProcess(self, *_args: object) -> bool:
            return False

        def QueryFullProcessImageNameW(self, *_args: object) -> bool:
            pytest.fail("failed exit status query reached identity query")

    with pytest.raises(ProcessQueryUnavailable, match="exit status"):
        process_module._windows_process_identity_from_handle(Kernel(), 99, 42)


def test_windows_termination_handle_close_failure_blocks_success(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    expected = {
        "pid": 42,
        "executable": "C:/chrome.exe",
        "start_marker": "windows-filetime:1",
    }

    class Callable:
        def __init__(self, result: object) -> None:
            self.result = result

        def __call__(self, *_args):  # noqa: ANN002, ANN204
            return self.result

    kernel = SimpleNamespace(
        OpenProcess=Callable(99),
        TerminateProcess=Callable(True),
        CloseHandle=Callable(False),
    )
    monkeypatch.setattr(process_module.sys, "platform", "win32")
    monkeypatch.setattr(
        process_module.ctypes, "WinDLL", lambda *_args, **_kwargs: kernel, raising=False
    )
    monkeypatch.setattr(
        process_module, "_configure_windows_process_api", lambda _kernel: None
    )
    monkeypatch.setattr(
        process_module,
        "_windows_process_identity_from_handle",
        lambda *_args: dict(expected),
    )
    monkeypatch.setattr(
        process_module,
        "wait_for_verified_exit",
        lambda *_args, **_kwargs: pytest.fail("close failure reached exit wait"),
    )

    with pytest.raises(ContractError) as captured:
        terminate_verified(expected, timeout_seconds=1.0)
    assert str(captured.value) == "cannot close verified browser process handle"


@pytest.mark.parametrize(
    "timeout", [True, -1.0, float("nan"), float("inf"), 301.0, 10**400]
)
def test_process_wait_rejects_invalid_timeout(timeout: object) -> None:
    with pytest.raises(ContractError, match="wait timeout"):
        wait_for_verified_exit({}, timeout)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "timeout", [True, 0.0, -1.0, float("nan"), float("inf"), 301.0, 10**400]
)
def test_process_termination_rejects_invalid_timeout_before_observation(
    monkeypatch: pytest.MonkeyPatch,
    timeout: object,
) -> None:
    monkeypatch.setattr(
        process_module,
        "observe_process",
        lambda _pid: pytest.fail("invalid timeout reached process observation"),
    )
    with pytest.raises(ContractError, match="termination timeout"):
        terminate_verified({}, timeout_seconds=timeout)  # type: ignore[arg-type]


def test_process_wait_rejects_invalid_identity_before_observation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        process_module,
        "observe_process",
        lambda _pid: pytest.fail("invalid identity reached process observation"),
    )
    with pytest.raises(ContractError, match="identity"):
        wait_for_verified_exit({}, 1.0)


def test_process_termination_does_not_start_a_fresh_exit_wait_after_deadline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    expected = {"pid": 42, "executable": "C:/chrome.exe", "start_marker": "fixture:1"}
    clock = [40.0]

    def observe(_pid: int) -> dict[str, object]:
        clock[0] += 0.6
        return dict(expected)

    def terminate(_pidfd: int, _signal: int, _siginfo: object, _flags: int) -> None:
        clock[0] += 0.5

    monkeypatch.setattr(process_module.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(process_module, "observe_process", observe)
    _mock_pidfd(monkeypatch, terminate)
    monkeypatch.setattr(
        process_module,
        "wait_for_verified_exit",
        lambda *_args, **_kwargs: pytest.fail("fresh exit wait began after deadline"),
    )

    with pytest.raises(ContractError, match="did not stop before the timeout"):
        terminate_verified(expected, timeout_seconds=1.0)


def test_identity_bound_termination_stops_the_exact_spawned_process() -> None:
    process = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(60)"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        expected = observe_process(process.pid)
        terminate_verified(expected, timeout_seconds=5.0)
        process.wait(timeout=5.0)
        assert process.poll() is not None
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5.0)


def test_posix_termination_refuses_pid_only_fallback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    expected = {"pid": 42, "executable": "/owned/chrome", "start_marker": "fixture:1"}
    monkeypatch.setattr(process_module.sys, "platform", "linux")
    monkeypatch.setattr(process_module.os, "pidfd_open", None, raising=False)
    monkeypatch.setattr(process_module.signal, "pidfd_send_signal", None, raising=False)
    with pytest.raises(ContractError, match="identity-bound.*unsupported"):
        terminate_verified(expected)
