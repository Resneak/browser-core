"""Check overlapping patch chains on bounded copies, never on the real sources.

Git's combined reverse check can reject overlapping diffs that were applied
successfully in order. Keep the cheap combined path for independent hunks;
use these helpers when a later patch changes an earlier patch's postimage.
"""
from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path
import os
import re
import tempfile

from .contracts import ContractError
from .control_files import read_bounded_control_snapshot_result
from .owned_paths import directory_ancestry_binding, directory_identity
from .prepared_download import guarded_temporary_directory_with_check


MAX_COPY_BYTES = 256 * 1024 * 1024
MAX_COPY_FILES = 4096
_PATH = re.compile(r"[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*")


def _paths(patches: list[bytes]) -> list[str]:
    names: set[str] = set()
    if len(patches) > 1024 or sum(map(len, patches)) > MAX_COPY_BYTES:
        raise ContractError('ordered patch population exceeds its bound')
    for patch in patches:
        current = None
        in_hunk = False
        for line in patch.splitlines():
            if line.startswith(b'diff --git '):
                in_hunk = False
                match = re.fullmatch(rb'diff --git a/(\S+) b/(\S+)', line)
                if not match or match[1] != match[2]:
                    raise ContractError('ordered patch target is invalid')
                try:
                    current = match[1].decode('ascii')
                except UnicodeError:
                    raise ContractError('ordered patch target is invalid') from None
                if (not _PATH.fullmatch(current) or len(current) > 512
                        or any(part in ('.', '..') or part.lower() == '.git'
                               or part.endswith('.') for part in current.split('/'))):
                    raise ContractError('ordered patch target is invalid')
                names.add(current)
            elif line.startswith(b'@@ '):
                in_hunk = True
            elif not in_hunk and line.startswith((b'--- ', b'+++ ')):
                side = b'a/' if line.startswith(b'--- ') else b'b/'
                if current is None or line[4:] not in (b'/dev/null', side + current.encode('ascii')):
                    raise ContractError('ordered patch file header is invalid')
            elif not in_hunk and line.startswith((b'rename ', b'copy ')):
                raise ContractError('ordered patch renames are unsupported')
            elif not in_hunk and line.startswith((b'new file mode ', b'deleted file mode ', b'old mode ', b'new mode ')):
                if line.rsplit(b' ', 1)[-1] not in (b'100644', b'100755'):
                    raise ContractError('ordered patch file mode is invalid')
        if current is None:
            raise ContractError('ordered patch contains no file diff')
    if len(names) > MAX_COPY_FILES or len({name.lower() for name in names}) != len(names):
        raise ContractError('ordered patch file population is invalid')
    return sorted(names)


def _snapshot(checkout: Path, names: list[str]):
    directories = {checkout: directory_identity(checkout, label='patch checkout')}
    if directories[checkout] is None:
        raise ContractError('patch checkout is missing')
    checkout_ancestry = directory_ancestry_binding(
        checkout.absolute(), label='patch checkout'
    )
    files = {}
    remaining = MAX_COPY_BYTES
    for name in names:
        path = checkout / name
        parent = checkout
        for component in Path(name).parts[:-1]:
            parent /= component
            if parent not in directories:
                directories[parent] = directory_identity(parent, label='patch source parent')
            if directories[parent] is None:
                break
        snapshot = read_bounded_control_snapshot_result(path, maximum=remaining,
            label='ordered patch source', require_single_link=True)
        if snapshot.state not in ('missing', 'complete'):
            raise ContractError('ordered patch source is not stable')
        remaining -= len(snapshot.body or b'')
        files[name] = snapshot
    return directories, files, checkout_ancestry


def _unchanged(checkout, names, before):
    if _snapshot(checkout, names) != before:
        raise ContractError('ordered patch sources changed during preflight')


def _restore(scratch, files, check):
    for name, snapshot in files.items():
        check()
        path = scratch / name
        # All names are validated relative paths in this owned temporary tree.
        path.unlink(missing_ok=True)
        if snapshot.body is not None:
            check()
            path.parent.mkdir(parents=True, exist_ok=True)
            check()
            path.write_bytes(snapshot.body)


@contextmanager
def _copy(checkout, patches):
    from . import upstream as up
    names = _paths(patches)
    before = _snapshot(checkout, names)
    with guarded_temporary_directory_with_check(
            tempfile.TemporaryDirectory(prefix='browser-core-patch-check-'),
            label='ordered patch scratch directory',
    ) as (scratch, check):
        # Own repository prevents discovery of an unrelated parent repository.
        check()
        if up._run_git_no_output(scratch, ['init', '-q']):
            raise ContractError('cannot initialize ordered patch scratch repository')
        for key, value in [('core.autocrlf', 'false'), ('core.filemode', 'false'),
                           ('core.attributesFile', 'NUL' if os.name == 'nt' else '/dev/null')]:
            check()
            if up._run_git_no_output(scratch, ['config', key, value]):
                raise ContractError('cannot configure ordered patch scratch repository')
        _restore(scratch, before[1], check)
        check()
        yield scratch, names, before, check
        check()
        _unchanged(checkout, names, before)


def _step(scratch, patch, check, *, reverse=False):
    from . import upstream as up
    arguments = ['--reverse'] if reverse else []
    check()
    checked = up._run_apply(scratch, arguments + ['--check'], [patch])
    check()
    if not up._apply_succeeded(checked):
        return False
    applied = up._run_apply(scratch, arguments, [patch])
    check()
    return up._apply_succeeded(applied)


def reverse_check(checkout: Path, patches: list[bytes]) -> bool:
    with _copy(checkout, patches) as (scratch, _names, _before, check):
        return all(_step(scratch, patch, check, reverse=True) for patch in reversed(patches))


def classify(checkout: Path, patches: list[bytes]) -> tuple[list[bytes], int]:
    with _copy(checkout, patches) as (scratch, _names, before, check):
        pending_indices = set()
        for index in reversed(range(len(patches))):
            if not _step(scratch, patches[index], check, reverse=True):
                pending_indices.add(index)
        pending = [patch for index, patch in enumerate(patches) if index in pending_indices]
        # Test the actual transition from current files, not just the reversed
        # baseline. A divergent or incompatible partial population must fail.
        _restore(scratch, before[1], check)
        if not all(_step(scratch, patch, check) for patch in pending):
            raise ContractError('patch series does not apply cleanly in declared order')
        if not all(_step(scratch, patch, check, reverse=True) for patch in reversed(patches)):
            raise ContractError('patch series does not apply cleanly in declared order')
        return pending, len(patches) - len(pending)
