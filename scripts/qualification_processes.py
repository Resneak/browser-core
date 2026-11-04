"""Snapshot evidence is never process-control authority.

Observation functions perform no host queries or signaling. CreatedProcess
retains the Popen object it created and never opens a process by PID. This API
separation prevents ordinary caller mistakes; it does not sandbox hostile Python.
"""
from __future__ import annotations

from dataclasses import dataclass
import math
import ntpath
import os
from pathlib import Path
import subprocess
from types import MappingProxyType
from typing import Mapping

from browser_core.errors import ContractError

MAX_ROWS = 65_536
MAX_IMAGE_CHARS = 32_768
MAX_SNAPSHOT_CHARS = 8 * 1024 * 1024


def _integer(value, minimum, maximum):
    if type(value) is not int or not minimum <= value <= maximum:
        raise ContractError('process observation integer is invalid')
    return value


def _image(value):
    if (not isinstance(value, str) or not 1 <= len(value) <= MAX_IMAGE_CHARS
            or any(ord(c) < 32 for c in value)):
        raise ContractError('process observation executable is invalid')
    try:
        value.encode('utf-8', errors='strict')
    except UnicodeError:
        raise ContractError('process observation executable is invalid') from None
    drive, tail = ntpath.splitdrive(value)
    if not drive or not tail.startswith(('\\', '/')):
        raise ContractError('process observation requires an absolute Windows executable')
    return ntpath.normcase(ntpath.normpath(value))


@dataclass(frozen=True)
class ObservedProcess:
    """Copied metadata only, with no terminate or stop method."""
    pid: int
    parent_pid: int
    created: int
    executable: str

    def __post_init__(self):
        _integer(self.pid, 1, 0xFFFFFFFF)
        _integer(self.parent_pid, 0, 0xFFFFFFFF)
        _integer(self.created, 1, 0xFFFFFFFFFFFFFFFF)
        object.__setattr__(self, 'executable', _image(self.executable))


def snapshot(rows):
    """Copy bounded, duplicate-free metadata into a read-only mapping."""
    if not isinstance(rows, (list, tuple)) or len(rows) > MAX_ROWS:
        raise ContractError('process snapshot row count is invalid')
    values = {}
    total = 0
    for row in rows:
        if type(row) is not ObservedProcess or row.pid in values:
            raise ContractError('process snapshot contains an invalid or duplicate row')
        total += len(row.executable)
        if total > MAX_SNAPSHOT_CHARS:
            raise ContractError('process snapshot metadata exceeds its bound')
        values[row.pid] = row
    return MappingProxyType(values)


@dataclass(frozen=True)
class DescendantObservations:
    root_state: str
    processes: tuple[ObservedProcess, ...]
    excluded_counts: Mapping[str, int]


def observe_descendant_frames(root, before, after, *, allowed_images):
    """Require stable instances/edges and creation ordering at each ancestor.

    Frames are caller-supplied observations, not authentication. Rejected
    branches are not traversed. Only candidates in the first frame are examined;
    this is not an atomic or complete process-tree inventory. Admitted rows never
    authorize termination or console signaling.
    """
    if type(root) is not ObservedProcess:
        raise ContractError('process snapshot root is invalid')
    for frame in (before, after):
        if not isinstance(frame, Mapping) or len(frame) > MAX_ROWS:
            raise ContractError('process snapshot mapping is invalid')
        if any(type(key) is not int or type(row) is not ObservedProcess or key != row.pid
               for key, row in frame.items()):
            raise ContractError('process snapshot keys do not match their rows')
    before, after = snapshot(list(before.values())), snapshot(list(after.values()))
    if not isinstance(allowed_images, (list, tuple, set, frozenset)) or not 1 <= len(allowed_images) <= 32:
        raise ContractError('process observation executable policy is invalid')
    images = frozenset(_image(value) for value in allowed_images)
    if root.executable not in images:
        raise ContractError('process observation root executable is outside the policy')
    if root.pid not in before or root.pid not in after:
        return DescendantObservations('unavailable', (), MappingProxyType({}))
    if before[root.pid] != root or after[root.pid] != root:
        return DescendantObservations('changed', (), MappingProxyType({}))
    by_parent = {}
    for row in before.values():
        by_parent.setdefault(row.parent_pid, []).append(row.pid)
    pending = [root]
    seen = {root.pid}
    accepted = []
    excluded = {}
    while pending:
        parent = pending.pop()
        for pid in sorted(by_parent.get(parent.pid, ())):
            if pid in seen:
                raise ContractError('process observation ancestry contains a cycle')
            seen.add(pid)
            row = before[pid]
            current = after.get(pid)
            if current is None:
                reason = 'unavailable'
            elif (row.pid, row.created, row.executable) != (current.pid, current.created, current.executable):
                reason = 'changed-instance'
            elif row.parent_pid != current.parent_pid:
                reason = 'changed-parent'
            elif row.created < parent.created:
                reason = 'created-before-parent'
            elif row.executable not in images:
                reason = 'unexpected-executable'
            else:
                accepted.append(row)
                pending.append(row)
                continue
            excluded[reason] = excluded.get(reason, 0) + 1
    return DescendantObservations('stable', tuple(sorted(accepted, key=lambda row: row.pid)),
                                  MappingProxyType(dict(sorted(excluded.items()))))


def _timeout(value):
    if type(value) not in (int, float) or not 0 < value <= 60 or not math.isfinite(value):
        raise ContractError('created-process wait timeout must be finite and in (0, 60]')
    return float(value)


class CreatedProcess:
    """Control only the process object returned by this constructor's launch.

    Windows Popen retains its process handle. A PID, observation, receipt or
    externally supplied process object cannot be passed as cleanup authority.
    Descendants are outside this object's authority. Output is discarded; this
    helper is not a complete research-CLI harness or a bounded output reader.
    """
    __slots__ = ('__process',)

    def __init__(self, command, *, cwd):
        if os.name != 'nt':
            raise ContractError('created-process qualification requires Windows')
        if (not isinstance(command, (list, tuple)) or not 1 <= len(command) <= 256
                or any(not isinstance(arg, str) or not arg or '\0' in arg
                       or len(arg) > 32_768 for arg in command)
                or sum(map(len, command)) > 1024 * 1024):
            raise ContractError('created-process command is invalid')
        _image(command[0])
        if ntpath.splitext(command[0])[1].lower() != '.exe':
            raise ContractError('created-process qualification requires a direct EXE launch')
        if not isinstance(cwd, Path) or not cwd.is_absolute() or not cwd.is_dir():
            raise ContractError('created-process working directory is invalid')
        self.__process = subprocess.Popen(list(command), cwd=cwd,
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            creationflags=subprocess.CREATE_NO_WINDOW, shell=False)

    @property
    def diagnostic_pid(self):
        return self.__process.pid

    def poll(self):
        return self.__process.poll()

    def wait(self, *, timeout_seconds):
        return self.__process.wait(timeout=_timeout(timeout_seconds))

    def _stop_direct_process(self, timeout_seconds):
        timeout = _timeout(timeout_seconds)
        if self.__process.poll() is None:
            try:
                self.__process.kill()
            except ProcessLookupError:
                pass
        return self.__process.wait(timeout=timeout)


def stop_created_process(owner, *, timeout_seconds=5):
    """Stop the direct launch without searching for or killing descendants."""
    if type(owner) is not CreatedProcess:
        raise ContractError('cleanup requires a directly created process owner')
    return owner._stop_direct_process(timeout_seconds)
