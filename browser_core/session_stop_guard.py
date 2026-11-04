"""Coordinate cooperating Windows stop callers; never authorize file changes."""
from __future__ import annotations

from contextlib import contextmanager
import ctypes
from ctypes import wintypes
import hashlib
import os
from pathlib import Path
import threading
import time

from .contracts import ContractError
from .numeric import is_finite_number

_threads = threading.local()


def _name(path: Path) -> str:
    try:
        if not isinstance(path, Path):
            raise ValueError()
        # Windows realpath expands ordinary short-name aliases. The hash is a
        # coordination key, not file identity or evidence of ownership.
        canonical = os.path.normcase(str(path.resolve()))
        digest = hashlib.sha256(canonical.encode('utf-8')).hexdigest()
    except (OSError, ValueError, UnicodeError, RuntimeError):
        raise ContractError('session stop coordination path is unavailable') from None
    return 'Local\\BrowserCore.SessionStop.v1.' + digest


def _kernel():
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    for name, args, result in (
        ('CreateMutexW', [ctypes.c_void_p, wintypes.BOOL, wintypes.LPCWSTR], wintypes.HANDLE),
        ('WaitForSingleObject', [wintypes.HANDLE, wintypes.DWORD], wintypes.DWORD),
        ('ReleaseMutex', [wintypes.HANDLE], wintypes.BOOL),
        ('CloseHandle', [wintypes.HANDLE], wintypes.BOOL),
    ):
        function = getattr(kernel, name)
        function.argtypes, function.restype = args, result
    return kernel


@contextmanager
def session_stop_guard(path: Path, deadline: float):
    """Wait within the caller's original budget, then reload all session state.

    Scope: cooperating callers in the same Windows logon session. No lock file
    or trusted cleanup receipt is created. Abandoned ownership permits retry of
    normal validation; it never treats the previous stop as complete.
    """
    if os.name != 'nt':
        yield
        return
    if not is_finite_number(deadline):
        raise ContractError('session stop coordination deadline is invalid')
    name = _name(path)
    active = getattr(_threads, 'active', None)
    if active is None:
        active = _threads.active = set()
    if name in active:
        raise ContractError('recursive stop of the same session is unsupported')
    active.add(name)
    handle = None
    acquired = False
    try:
        kernel = _kernel()
        # NULL attributes use the caller's default ACL and a noninherited handle.
        handle = kernel.CreateMutexW(None, False, name)
        if not handle:
            raise ContractError('session stop coordination is unavailable')
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ContractError('session stop deadline exhausted while waiting for another caller')
            # Short waits let Python process cancellation between native calls.
            state = kernel.WaitForSingleObject(handle, max(1, min(50, int(remaining * 1000))))
            if state in (0, 0x80):  # acquired / abandoned by an exited owner
                acquired = True
                if time.monotonic() >= deadline:
                    raise ContractError('session stop deadline exhausted while waiting for another caller')
                break
            if state != 0x102:
                raise ContractError('session stop coordination wait failed')
        yield
    finally:
        try:
            if handle:
                # A pending Python interrupt can be delivered after the native
                # wait acquired ownership but before `acquired` was assigned.
                # Attempt release either way. Reentry is prohibited above, so
                # this cannot release an outer acquisition for the same name.
                try:
                    released = kernel.ReleaseMutex(handle)
                    release_error = ctypes.get_last_error() if not released else 0
                finally:
                    closed = kernel.CloseHandle(handle)
                if not released and (acquired or release_error != 288):  # ERROR_NOT_OWNER
                    raise ContractError('session stop coordination ownership could not be released')
                if not closed:
                    raise ContractError('session stop coordination handle could not be closed')
        finally:
            active.discard(name)
