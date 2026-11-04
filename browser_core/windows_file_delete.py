"""Delete an owned Windows file through the handle used to verify its identity.

The caller checks metadata and parent identity while this exclusive handle is
held. Opening the handle alone never deletes anything. No reparse point is
followed, and deletion is marked only after the caller's checks succeed.
"""
from contextlib import contextmanager
from functools import lru_cache
import os
from pathlib import Path
from typing import Iterator


@lru_cache(maxsize=1)
def _api():
    import ctypes
    from ctypes import wintypes

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    create = kernel.CreateFileW
    create.argtypes = (wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                       wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE)
    create.restype = wintypes.HANDLE
    close = kernel.CloseHandle
    close.argtypes = (wintypes.HANDLE,)
    close.restype = wintypes.BOOL
    dispose = kernel.SetFileInformationByHandle
    dispose.argtypes = (wintypes.HANDLE, ctypes.c_int, wintypes.LPVOID, wintypes.DWORD)
    dispose.restype = wintypes.BOOL
    return create, close, dispose


@contextmanager
def exclusive_file(path: Path, *, read_contents: bool = False) -> Iterator[int]:
    import ctypes
    import msvcrt

    create, close, _dispose = _api()
    if type(read_contents) is not bool:
        raise TypeError('file-content access selection must be boolean')
    # FILE_READ_ATTRIBUTES | DELETE by default; bounded control-file verification
    # explicitly requests GENERIC_READ as well, through this same held handle.
    # Share mode zero rejects existing or subsequent
    # readers/writers/renamers. OPEN_EXISTING never creates an entry.
    # FILE_FLAG_OPEN_REPARSE_POINT opens a link itself, not its target.
    filename = os.path.abspath(path)
    if not filename.startswith("\\\\?\\"):
        filename = ("\\\\?\\UNC\\" + filename[2:] if filename.startswith("\\\\")
                    else "\\\\?\\" + filename)
    access = 0x00010080 | (0x80000000 if read_contents else 0)
    handle = create(filename, access, 0, None, 3, 0x00200000, None)
    if handle == ctypes.c_void_p(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        descriptor = msvcrt.open_osfhandle(handle, os.O_RDONLY | os.O_BINARY)
    except BaseException:
        close(handle)
        raise
    try:
        yield descriptor
    finally:
        os.close(descriptor)


def mark_for_delete(descriptor: int) -> None:
    import ctypes
    import msvcrt

    _create, _close, dispose = _api()
    # FILE_DISPOSITION_INFO contains a one-byte BOOLEAN. FileDispositionInfo=4
    # deletes the opened name when this exclusive handle closes.
    disposition = ctypes.c_ubyte(1)
    if not dispose(msvcrt.get_osfhandle(descriptor), 4,
                   ctypes.byref(disposition), ctypes.sizeof(disposition)):
        raise ctypes.WinError(ctypes.get_last_error())
