"""Windows child observation and retained identities for owned profile cleanup.

This is not process-tree containment. Processes created after the snapshot and
descendants running another executable are outside this observation. Never use
this snapshot to authorize termination of a child process.
"""
from __future__ import annotations

import ctypes
import hashlib
from ctypes import wintypes
from dataclasses import dataclass
import re
from pathlib import Path

from .errors import ContractError
from .process import identities_match, observe_process, validate_process_identity
from .control_files import (
    load_canonical_json_document, publish_json_exclusive,
    read_bounded_control_snapshot_result, replace_json_conditionally_result,
)

MAX_PROCESS_SNAPSHOT_ROWS = 65536
MAX_RETAINED_CHILDREN = 1024
MAX_CHILD_RECEIPT_BYTES = 512 * 1024


class _ProcessEntry(ctypes.Structure):
    _fields_ = [
        ('dwSize', wintypes.DWORD), ('cntUsage', wintypes.DWORD),
        ('th32ProcessID', wintypes.DWORD), ('th32DefaultHeapID', ctypes.c_size_t),
        ('th32ModuleID', wintypes.DWORD), ('cntThreads', wintypes.DWORD),
        ('th32ParentProcessID', wintypes.DWORD), ('pcPriClassBase', wintypes.LONG),
        ('dwFlags', wintypes.DWORD), ('szExeFile', wintypes.WCHAR * 260),
    ]


@dataclass(frozen=True)
class ChildSnapshot:
    parent_running: bool
    identities: tuple[dict, ...]


def _windows_parent_rows() -> dict[int, int]:
    # TH32CS_SNAPPROCESS only: no modules, memory, command lines or handles from
    # other processes are copied. The snapshot handle is closed on every path.
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    create = kernel.CreateToolhelp32Snapshot
    create.argtypes = (wintypes.DWORD, wintypes.DWORD)
    create.restype = wintypes.HANDLE
    first = kernel.Process32FirstW
    following = kernel.Process32NextW
    for function in (first, following):
        function.argtypes = (wintypes.HANDLE, ctypes.POINTER(_ProcessEntry))
        function.restype = wintypes.BOOL
    close = kernel.CloseHandle
    close.argtypes = (wintypes.HANDLE,)
    close.restype = wintypes.BOOL
    handle = create(0x00000002, 0)
    if not handle or handle == ctypes.c_void_p(-1).value:
        raise ContractError('browser child process snapshot is unavailable')
    rows = {}
    try:
        entry = _ProcessEntry()
        entry.dwSize = ctypes.sizeof(entry)
        available = first(handle, ctypes.byref(entry))
        while available:
            pid, parent = int(entry.th32ProcessID), int(entry.th32ParentProcessID)
            if pid in rows or len(rows) >= MAX_PROCESS_SNAPSHOT_ROWS:
                raise ContractError('browser child process snapshot is invalid or exceeds its bound')
            rows[pid] = parent
            available = following(handle, ctypes.byref(entry))
        if ctypes.get_last_error() != 18:  # ERROR_NO_MORE_FILES
            raise ContractError('browser child process snapshot enumeration failed')
    finally:
        if not close(handle):
            raise ContractError('browser child process snapshot handle could not be closed')
    return rows


def _start_time(identity: dict) -> int:
    match = re.fullmatch(r'windows-filetime:([0-9]{1,20})', identity['start_marker'])
    if match is None:
        raise ContractError('browser child snapshot requires a Windows process identity')
    return int(match.group(1))


def observe_browser_children(expected: dict) -> ChildSnapshot:
    """Bind an active parent and a same-executable descendant snapshot by identity.

    An absent or replaced parent forbids contacting its old control endpoint.
    Access/query errors propagate; they never become an empty successful scan.
    The returned identities are for verified exit waits, never termination.
    """
    expected = validate_process_identity(expected)
    earliest = _start_time(expected)
    try:
        before = observe_process(expected['pid'])
    except ProcessLookupError:
        return ChildSnapshot(False, ())
    if not identities_match(expected, before):
        return ChildSnapshot(False, ())
    rows = _windows_parent_rows()
    by_parent = {}
    for pid, parent in rows.items():
        by_parent.setdefault(parent, []).append(pid)
    seen = {expected['pid']}
    pending = list(by_parent.get(expected['pid'], ()))
    candidates = []
    while pending:
        pid = pending.pop()
        if pid in seen:
            raise ContractError('browser child process snapshot contains a cycle')
        seen.add(pid)
        candidates.append(pid)
        pending.extend(by_parent.get(pid, ()))
    children = []
    for pid in sorted(candidates):
        try:
            child = validate_process_identity(observe_process(pid))
        except ProcessLookupError:
            continue
        if child['executable'] == expected['executable'] and _start_time(child) >= earliest:
            children.append(child)
            if len(children) > MAX_RETAINED_CHILDREN:
                raise ContractError('browser child process snapshot exceeds its child bound')
    try:
        parent_running = identities_match(expected, observe_process(expected['pid']))
    except ProcessLookupError:
        parent_running = False
    return ChildSnapshot(parent_running, tuple(children))


def retain_child_snapshot(session_path: Path, session: dict, session_body: bytes,
                          snapshot: ChildSnapshot) -> ChildSnapshot:
    """Write observed identities before close; retain them across cleanup retries.

    This internal sidecar leaves the public session-v1 schema unchanged. Its
    digest binds the exact active session bytes and each identity is validated.
    An old receipt never authorizes contacting the parent's control endpoint.
    """
    path = session_path.with_name(f'.{session_path.stem}.child-exit')
    parent = validate_process_identity(session['process_identity'])
    earliest = _start_time(parent)
    header = {
        'schema': 'browser-core.child-exit-snapshot/1', 'run_id': session['run_id'],
        'session_sha256': hashlib.sha256(session_body).hexdigest(), 'parent_identity': parent,
    }
    saved = read_bounded_control_snapshot_result(
        path, maximum=MAX_CHILD_RECEIPT_BYTES, label='browser child exit receipt',
        require_single_link=True)
    prior = []
    if saved.state == 'complete':
        document = load_canonical_json_document(saved.body, label='browser child exit receipt')
        if set(document) != set(header) | {'children'} or any(document[k] != v for k, v in header.items()):
            raise ContractError('browser child exit receipt does not match the active session')
        prior = document['children']
        if not isinstance(prior, list) or len(prior) > MAX_RETAINED_CHILDREN:
            raise ContractError('browser child exit receipt has invalid child identities')
    elif saved.state != 'missing':
        raise ContractError('browser child exit receipt is unavailable or changed')
    retained = {}
    for value in (*prior, *snapshot.identities):
        child = validate_process_identity(value)
        if (child['pid'] == parent['pid'] or child['executable'] != parent['executable']
                or _start_time(child) < earliest):
            raise ContractError('browser child exit receipt has an unrelated identity')
        retained[(child['pid'], child['start_marker'])] = child
        if len(retained) > MAX_RETAINED_CHILDREN:
            raise ContractError('browser child exit receipt exceeds its child bound')
    values = [retained[key] for key in sorted(retained)]
    document = {**header, 'children': values}
    if saved.state == 'missing':
        publish_json_exclusive(path, document, maximum=MAX_CHILD_RECEIPT_BYTES,
                               label='browser child exit receipt')
    elif values != prior:
        replace_json_conditionally_result(
            path, document, expected_body=saved.body, expected_identity=saved.identity,
            maximum=MAX_CHILD_RECEIPT_BYTES, label='browser child exit receipt')
    return ChildSnapshot(snapshot.parent_running, tuple(values))
