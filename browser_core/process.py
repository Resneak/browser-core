from __future__ import annotations

import ctypes
import errno
import os
import signal
import sys
import time
from ctypes import wintypes
from pathlib import Path
from typing import Any

from .contracts import ContractError
from .numeric import is_finite_number


MAX_PROCESS_TIMEOUT_SECONDS = 300.0
MAX_PROC_STAT_BYTES = 16 * 1024
MAX_EXECUTABLE_PATH_CHARACTERS = 32768
MAX_START_MARKER_CHARACTERS = 128


class ProcessQueryUnavailable(ContractError):
    """A process query failed; this never establishes process exit."""


def _canonical_executable(value: object) -> str:
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= MAX_EXECUTABLE_PATH_CHARACTERS
        or "\x00" in value
        or not os.path.isabs(value)
    ):
        raise ContractError("process executable identity is invalid")
    return os.path.normcase(os.path.abspath(os.path.normpath(value)))


def _validated_identity(identity: object) -> tuple[int, str, str]:
    if not isinstance(identity, dict):
        raise ContractError("expected process identity is invalid")
    pid = identity.get("pid")
    start_marker = identity.get("start_marker")
    if (
        isinstance(pid, bool)
        or not isinstance(pid, int)
        or not 1 <= pid <= 0xFFFFFFFF
        or not isinstance(start_marker, str)
        or not 1 <= len(start_marker) <= MAX_START_MARKER_CHARACTERS
        or any(
            ord(character) < 0x20 or ord(character) == 0x7F
            for character in start_marker
        )
    ):
        raise ContractError("expected process identity is invalid")
    try:
        executable = _canonical_executable(identity.get("executable"))
    except ContractError:
        raise ContractError("expected process identity is invalid") from None
    return pid, executable, start_marker


def validate_process_identity(identity: object) -> dict[str, Any]:
    """Return the exact normalized identity used for ownership decisions."""

    pid, executable, start_marker = _validated_identity(identity)
    return {
        "pid": pid,
        "executable": executable,
        "start_marker": start_marker,
    }


def _validate_timeout(value: object, *, allow_zero: bool, label: str) -> float:
    if not is_finite_number(value) or (
        value < 0 if allow_zero else value <= 0
    ) or value > MAX_PROCESS_TIMEOUT_SECONDS:
        interval = "[0, 300]" if allow_zero else "(0, 300]"
        raise ContractError(f"{label} must be finite and in {interval}")
    return float(value)


def _configure_windows_process_api(kernel32: Any) -> None:
    kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.QueryFullProcessImageNameW.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        wintypes.LPWSTR,
        ctypes.POINTER(wintypes.DWORD),
    ]
    kernel32.QueryFullProcessImageNameW.restype = wintypes.BOOL
    kernel32.GetProcessTimes.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(wintypes.FILETIME),
        ctypes.POINTER(wintypes.FILETIME),
        ctypes.POINTER(wintypes.FILETIME),
        ctypes.POINTER(wintypes.FILETIME),
    ]
    kernel32.GetProcessTimes.restype = wintypes.BOOL
    kernel32.GetExitCodeProcess.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(wintypes.DWORD),
    ]
    kernel32.GetExitCodeProcess.restype = wintypes.BOOL
    kernel32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    kernel32.WaitForSingleObject.restype = wintypes.DWORD
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL


def _windows_process_identity_from_handle(
    kernel32: Any,
    handle: Any,
    pid: int,
) -> dict[str, Any]:
    # A failed identity query alone cannot establish process exit. An opened
    # handle can still report its final status after the process terminates.
    wait_query = getattr(kernel32, "WaitForSingleObject", None)
    if wait_query is not None:
        try:
            wait_state = wait_query(handle, 0)
        except (OSError, RuntimeError, TypeError, ValueError):
            raise ProcessQueryUnavailable("cannot inspect browser process wait state") from None
        if type(wait_state) is not int or wait_state not in {0, 258}:
            raise ProcessQueryUnavailable("cannot inspect browser process wait state")
        if wait_state == 0:  # WAIT_OBJECT_0; unlike an exit code of 259, unambiguous.
            raise ProcessLookupError(pid)
    exit_query = getattr(kernel32, "GetExitCodeProcess", None)
    if exit_query is not None:
        exit_code = wintypes.DWORD()
        try:
            checked = exit_query(handle, ctypes.byref(exit_code))
        except (OSError, RuntimeError, TypeError, ValueError):
            checked = False
        if not checked:
            raise ProcessQueryUnavailable("cannot inspect browser process exit status")
        if exit_code.value != 259:  # STILL_ACTIVE can also be an explicit exit code.
            raise ProcessLookupError(pid)
    buffer = ctypes.create_unicode_buffer(32768)
    size = wintypes.DWORD(len(buffer))
    if not kernel32.QueryFullProcessImageNameW(handle, 0, buffer, ctypes.byref(size)):
        error = ctypes.get_last_error()
        raise ProcessQueryUnavailable(
            f"cannot inspect browser executable path (Windows error {error})"
        )
    created = wintypes.FILETIME()
    exited = wintypes.FILETIME()
    kernel = wintypes.FILETIME()
    user = wintypes.FILETIME()
    if not kernel32.GetProcessTimes(
        handle,
        ctypes.byref(created),
        ctypes.byref(exited),
        ctypes.byref(kernel),
        ctypes.byref(user),
    ):
        error = ctypes.get_last_error()
        raise ProcessQueryUnavailable(
            f"cannot inspect browser process creation time (Windows error {error})"
        )
    marker = (created.dwHighDateTime << 32) | created.dwLowDateTime
    return {
        "pid": pid,
        "executable": _canonical_executable(buffer.value),
        "start_marker": f"windows-filetime:{marker}",
    }


def _windows_process_identity(pid: int) -> dict[str, Any]:
    process_query_limited_information = 0x1000
    synchronize = 0x00100000
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _configure_windows_process_api(kernel32)
    handle = kernel32.OpenProcess(
        process_query_limited_information | synchronize, False, pid
    )
    if not handle:
        error = ctypes.get_last_error()
        if error in {87, 1168}:
            raise ProcessLookupError(pid)
        error_type = ProcessQueryUnavailable if error == 5 else ContractError
        raise error_type(f"cannot inspect browser process (Windows error {error})")
    try:
        return _windows_process_identity_from_handle(kernel32, handle, pid)
    finally:
        try:
            closed = kernel32.CloseHandle(handle)
        except (OSError, RuntimeError, ValueError):
            raise ContractError("cannot close browser process query handle") from None
        if not closed:
            raise ContractError("cannot close browser process query handle")


def _parse_proc_stat(body: bytes, pid: int) -> str:
    if not body or len(body) > MAX_PROC_STAT_BYTES or b"\x00" in body:
        raise ProcessQueryUnavailable("process stat could not establish identity")
    row = body[:-1] if body.endswith(b"\n") else body
    first_space = row.find(b" ")
    final_parenthesis = row.rfind(b")")
    if (
        first_space < 1
        or row[:first_space] != str(pid).encode("ascii")
        or first_space + 1 >= len(row)
        or row[first_space + 1 : first_space + 2] != b"("
        or final_parenthesis <= first_space + 1
        or row[final_parenthesis + 1 : final_parenthesis + 2] != b" "
    ):
        raise ProcessQueryUnavailable("process stat could not establish identity")
    fields = row[final_parenthesis + 2 :].split()
    if len(fields) < 20 or len(fields[0]) != 1:
        raise ProcessQueryUnavailable("process stat could not establish identity")
    marker = fields[19]
    if not marker or not marker.isdigit() or len(marker) > 32:
        raise ProcessQueryUnavailable("process stat could not establish identity")
    return marker.decode("ascii")


def _proc_process_identity(pid: int) -> dict[str, Any]:
    process_root = Path("/proc") / str(pid)
    directory_fd: int | None = None
    stat_fd: int | None = None
    try:
        directory_flags = (
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0)
        )
        directory_fd = os.open(process_root, directory_flags)
        root_before = os.fstat(directory_fd)
        executable_target = os.readlink("exe", dir_fd=directory_fd)
        stat_flags = (
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        )
        stat_fd = os.open("stat", stat_flags, dir_fd=directory_fd)
        stat_before = os.fstat(stat_fd)
        chunks = bytearray()
        while len(chunks) <= MAX_PROC_STAT_BYTES:
            chunk = os.read(stat_fd, MAX_PROC_STAT_BYTES + 1 - len(chunks))
            if not chunk:
                break
            chunks.extend(chunk)
        stat_after = os.fstat(stat_fd)
        executable_after = os.readlink("exe", dir_fd=directory_fd)
        root_after = os.fstat(directory_fd)
        if (
            (root_before.st_dev, root_before.st_ino)
            != (root_after.st_dev, root_after.st_ino)
            or (stat_before.st_dev, stat_before.st_ino)
            != (stat_after.st_dev, stat_after.st_ino)
            or executable_after != executable_target
            or len(chunks) > MAX_PROC_STAT_BYTES
        ):
            raise ProcessQueryUnavailable("process identity changed during query")
        marker = _parse_proc_stat(bytes(chunks), pid)
        executable = _canonical_executable(executable_target)
    except ProcessQueryUnavailable:
        raise
    except ProcessLookupError:
        raise
    except OSError as exc:
        if exc.errno in {errno.ENOENT, errno.ESRCH}:
            raise ProcessLookupError(pid) from None
        raise ProcessQueryUnavailable("cannot inspect process identity") from None
    except (ContractError, UnicodeError, ValueError):
        raise ProcessQueryUnavailable("cannot inspect process identity") from None
    finally:
        close_failed = False
        if stat_fd is not None:
            try:
                os.close(stat_fd)
            except OSError:
                close_failed = True
        if directory_fd is not None:
            try:
                os.close(directory_fd)
            except OSError:
                close_failed = True
        if close_failed:
            raise ProcessQueryUnavailable("cannot close process query handles") from None
    return {
        "pid": pid,
        "executable": executable,
        "start_marker": f"proc-start-ticks:{marker}",
    }


def observe_process(pid: int) -> dict[str, Any]:
    if isinstance(pid, bool) or not isinstance(pid, int) or not 1 <= pid <= 0xFFFFFFFF:
        raise ContractError("process PID is invalid")
    if sys.platform == "win32":
        return _windows_process_identity(pid)
    if Path("/proc").is_dir():
        return _proc_process_identity(pid)
    raise ContractError("safe process identity is unsupported on this platform")


def identities_match(expected: dict[str, Any], actual: dict[str, Any]) -> bool:
    try:
        expected_pid, expected_executable, expected_marker = _validated_identity(
            expected
        )
        actual_pid, actual_executable, actual_marker = _validated_identity(actual)
        return (expected_pid, expected_executable, expected_marker) == (
            actual_pid,
            actual_executable,
            actual_marker,
        )
    except ContractError:
        return False


def wait_for_verified_exit(expected: dict[str, Any], timeout_seconds: float) -> bool:
    timeout = _validate_timeout(
        timeout_seconds,
        allow_zero=True,
        label="process wait timeout",
    )
    pid, _, _ = _validated_identity(expected)
    deadline = time.monotonic() + timeout
    checked = False
    while True:
        if checked and time.monotonic() >= deadline:
            return False
        checked = True
        try:
            current = observe_process(pid)
            _validated_identity(current)
        except ProcessLookupError:
            return True
        except ContractError:
            # Windows can briefly deny process-query access while a verified
            # process is tearing down. Keep waiting; a persistent denial
            # still times out and never authorizes forced termination.
            time.sleep(min(0.05, max(0.0, deadline - time.monotonic())))
            continue
        if not identities_match(expected, current):
            return True
        time.sleep(min(0.05, max(0.0, deadline - time.monotonic())))


def terminate_verified(expected: dict[str, Any], timeout_seconds: float = 15.0) -> None:
    timeout = _validate_timeout(
        timeout_seconds,
        allow_zero=False,
        label="process termination timeout",
    )
    pid, _, _ = _validated_identity(expected)
    deadline = time.monotonic() + timeout
    if sys.platform == "win32":
        process_terminate = 0x0001
        process_query_limited_information = 0x1000
        synchronize = 0x00100000
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        _configure_windows_process_api(kernel32)
        kernel32.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
        kernel32.TerminateProcess.restype = wintypes.BOOL
        handle = kernel32.OpenProcess(
            process_terminate | process_query_limited_information | synchronize,
            False,
            pid,
        )
        if not handle:
            raise ContractError(
                "cannot open the verified browser process for termination"
            )
        try:
            actual = _windows_process_identity_from_handle(kernel32, handle, pid)
            if not identities_match(expected, actual):
                raise ContractError(
                    "refusing to stop a process whose identity does not match the session"
                )
            if not kernel32.TerminateProcess(handle, 0):
                raise ContractError("cannot terminate the verified browser process")
        finally:
            try:
                closed = kernel32.CloseHandle(handle)
            except (OSError, RuntimeError, ValueError):
                raise ContractError(
                    "cannot close verified browser process handle"
                ) from None
            if not closed:
                raise ContractError("cannot close verified browser process handle")
    else:
        pidfd_open = getattr(os, "pidfd_open", None)
        pidfd_send_signal = getattr(signal, "pidfd_send_signal", None)
        if not callable(pidfd_open) or not callable(pidfd_send_signal):
            raise ContractError("identity-bound process termination is unsupported")
        try:
            pidfd = pidfd_open(pid, 0)
        except ProcessLookupError:
            raise
        except OSError as exc:
            code = exc.errno
            suffix = f" (os_error={code})" if isinstance(code, int) else ""
            raise ContractError(
                f"cannot open identity-bound process handle{suffix}"
            ) from None
        try:
            actual = observe_process(pid)
            if not identities_match(expected, actual):
                raise ContractError(
                    "refusing to stop a process whose identity does not match the session"
                )
            pidfd_send_signal(pidfd, signal.SIGTERM, None, 0)
        finally:
            try:
                os.close(pidfd)
            except OSError:
                raise ContractError(
                    "cannot close identity-bound process handle"
                ) from None
    remaining = deadline - time.monotonic()
    if remaining <= 0 or not wait_for_verified_exit(expected, remaining):
        raise ContractError("verified browser process did not stop before the timeout")
