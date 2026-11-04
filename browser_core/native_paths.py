"""Keep Chromium's Windows data paths within its legacy storage path budget.

An NTFS short name is another name for the same directory, not a relocated
profile. Session receipts and lifecycle ownership always keep the original path.
No short names, junctions, or global Windows settings are created here.
"""
from __future__ import annotations

import os
from pathlib import Path

from .errors import ContractError
from .owned_paths import directory_identity


# Leave space for Chromium's nested cache/origin/database filenames. These are
# conservative admission budgets, not a universal Windows maximum path claim.
MAX_NATIVE_PROFILE_UNITS = 120
MAX_NATIVE_RECORDING_UNITS = 220


def _windows_units(path: Path) -> int:
    return len(str(path).encode('utf-16-le')) // 2


def _short_directory(path: Path) -> Path:
    import ctypes

    function = ctypes.WinDLL('kernel32', use_last_error=True).GetShortPathNameW
    function.argtypes = [ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_uint32]
    function.restype = ctypes.c_uint32
    buffer = ctypes.create_unicode_buffer(32768)
    length = function(str(path), buffer, len(buffer))
    if not 0 < length < len(buffer):
        raise ContractError('Windows native path alias is unavailable; choose a shorter workspace')
    return Path(buffer.value)


def native_browser_path(path: Path, *, profile: bool) -> Path:
    """Return a verified existing alias when a native path needs shortening."""
    if os.name != 'nt':
        return path
    budget = MAX_NATIVE_PROFILE_UNITS if profile else MAX_NATIVE_RECORDING_UNITS
    if _windows_units(path) <= budget:
        return path
    directory = path if profile else path.parent
    before = directory_identity(directory, label='native browser directory')
    if before is None:
        raise ContractError('native browser directory is missing')
    alias = _short_directory(directory)
    if (
        not alias.is_absolute()
        or directory_identity(alias, label='native browser alias') != before
        or directory_identity(directory, label='native browser directory') != before
    ):
        raise ContractError('native browser directory changed while selecting its alias')
    result = alias if profile else alias / path.name
    if _windows_units(result) > budget:
        raise ContractError('Windows native path is too deep; choose a shorter workspace')
    return result
