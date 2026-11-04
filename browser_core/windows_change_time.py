"""Read the native Windows file change time from an open file handle."""
from __future__ import annotations

def windows_change_time(handle) -> int:
    import ctypes
    import msvcrt

    # Python 3.10 exposes creation time as st_ctime on Windows. The native
    # change time also records same-size writes followed by mtime restoration.
    class FileBasicInfo(ctypes.Structure):
        _fields_ = [
            ("creation", ctypes.c_longlong),
            ("access", ctypes.c_longlong),
            ("write", ctypes.c_longlong),
            ("change", ctypes.c_longlong),
            ("attributes", ctypes.c_uint32),
        ]

    query = ctypes.WinDLL("kernel32", use_last_error=True).GetFileInformationByHandleEx
    query.argtypes = (ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32)
    query.restype = ctypes.c_int
    info = FileBasicInfo()
    if not query(msvcrt.get_osfhandle(handle.fileno()), 0, ctypes.byref(info), ctypes.sizeof(info)):
        raise OSError(ctypes.get_last_error(), "cannot inspect file change time")
    return info.change
