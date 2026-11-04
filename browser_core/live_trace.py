"""Stable packet-boundary snapshots of the native append-only live trace.

Snapshots are provisional prefixes, never completed export receipts. Chromium
owns the writer; append-only behavior is a producer assumption. No CDP tracing
or page hooks are used. The normal exporter can consume the temporary snapshot.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import hashlib
import csv
import io
import os
from pathlib import Path
import stat
import time
from tempfile import TemporaryDirectory
from typing import BinaryIO, Iterator

from .contracts import ContractError, parse_canonical_decimal
from .owned_paths import directory_ancestry_binding
from .prepared_download import require_temporary_cleanup_authority

MAX_LIVE_SNAPSHOT_BYTES = 1024 * 1024 * 1024
MAX_LIVE_PACKET_BYTES = 16 * 1024 * 1024
MAX_LIVE_PACKETS = 10_000_000
COPY_BLOCK_BYTES = 1024 * 1024


@dataclass(frozen=True)
class LiveTraceSnapshot:
    path: Path
    bytes: int
    packets: int
    source_bytes: int
    incomplete_tail_bytes: int
    sha256: str


def _open_shared_source(path: Path) -> BinaryIO:
    if os.name != 'nt':
        descriptor = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
        return os.fdopen(descriptor, 'rb')

    # Ordinary Python open() can deny rename on Windows. Readers must not make
    # Chromium's final live -> completed publication fail at shutdown.
    import ctypes
    from ctypes import wintypes
    import msvcrt

    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    create = kernel.CreateFileW
    create.argtypes = (wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                       wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD,
                       wintypes.HANDLE)
    create.restype = wintypes.HANDLE
    close = kernel.CloseHandle
    close.argtypes = (wintypes.HANDLE,)
    close.restype = wintypes.BOOL
    handle = create(str(path), 0x80000000, 7, None, 3, 0x08200000, None)
    if handle == ctypes.c_void_p(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        descriptor = msvcrt.open_osfhandle(handle, os.O_RDONLY | os.O_BINARY)
    except BaseException:
        close(handle)
        raise
    return os.fdopen(descriptor, 'rb')


def _identity(value: os.stat_result) -> tuple[int, int]:
    return value.st_dev, value.st_ino


def _require_regular(value: os.stat_result) -> None:
    if (not stat.S_ISREG(value.st_mode) or value.st_nlink != 1
            or getattr(value, 'st_file_attributes', 0) & 0x400):
        raise ContractError('live trace must be one regular non-reparse file')


def _copy_packets(source: BinaryIO, destination: BinaryIO,
                  source_bytes: int, *, packet_limit=None) -> tuple[int, int, str]:
    """Validate each packet envelope and hash every copied byte in larger blocks."""
    packet_limit = MAX_LIVE_PACKETS if packet_limit is None else packet_limit
    if type(packet_limit) is not int or not 1 <= packet_limit <= 40_000_000:
        raise ContractError('live trace packet budget is invalid')
    buffer = bytearray()
    read_bytes = committed = packets = 0
    digest = hashlib.sha256()
    while read_bytes < source_bytes:
        chunk = source.read(min(COPY_BLOCK_BYTES, source_bytes - read_bytes))
        if not chunk:
            raise ContractError('live trace shrank during snapshot')
        read_bytes += len(chunk)
        buffer.extend(chunk)
        position = 0
        incomplete_tail = False
        while position < len(buffer):
            if buffer[position] != 0x0a:
                raise ContractError('live trace has an invalid packet envelope')
            header_end = position + 1
            length = 0
            for index in range(10):
                if header_end == len(buffer):
                    break
                byte = buffer[header_end]
                header_end += 1
                if index == 9 and byte > 1:
                    raise ContractError('live trace packet length overflows')
                length |= (byte & 0x7f) << (7 * index)
                if not byte & 0x80:
                    break
            if header_end == len(buffer) and (header_end == position + 1 or byte & 0x80):
                break
            if length > MAX_LIVE_PACKET_BYTES:
                raise ContractError('live trace packet exceeds snapshot limit')
            packet_end = header_end + length
            if packet_end > source_bytes - committed:
                incomplete_tail = True
                break
            if packet_end > len(buffer):
                break
            if packets >= packet_limit:
                raise ContractError('live trace packet count exceeds snapshot limit')
            position = packet_end
            packets += 1
        if position:
            view = memoryview(buffer)[:position]
            try:
                if destination.write(view) != len(view):
                    raise ContractError('live trace snapshot short write')
                digest.update(view)
            finally:
                view.release()
            committed += position
            del buffer[:position]
        if incomplete_tail:
            break
        # Only an incomplete packet can remain. It is bounded by the maximum
        # packet size plus its header and one input block, independent of trace size.
    return committed, packets, digest.hexdigest()


@contextmanager
def snapshot_live_trace(source_path: Path, *, parts=None) -> Iterator[LiveTraceSnapshot]:
    """Yield a temporary, immutable-on-return prefix for one analysis operation.

    A growing final packet is omitted. A renamed source remains readable through
    the original shared handle. Empty snapshots are valid but contain no evidence.
    Missing files mean the producer has not opened the live artifact or has
    already published its final artifact; callers must distinguish session state.
    """
    if not isinstance(source_path, Path) or not source_path.is_absolute():
        raise ContractError('live trace requires an absolute path')
    if parts is not None:
        from .recording_parts import snapshot_parts
        if parts.source != source_path:
            raise ContractError('recording parts do not match their original source')
        with snapshot_parts(parts) as snapshot:
            yield snapshot
        return
    try:
        source_parent_ancestry = directory_ancestry_binding(
            source_path.parent, label='live trace source parent'
        )
        named = os.lstat(source_path)
        _require_regular(named)
        with _open_shared_source(source_path) as source:
            before = os.fstat(source.fileno())
            _require_regular(before)
            if _identity(named) != _identity(before):
                raise ContractError('live trace changed before snapshot')
            if before.st_size > MAX_LIVE_SNAPSHOT_BYTES:
                raise ContractError('live trace exceeds snapshot byte limit')
            folder = TemporaryDirectory(prefix='browser-core-live-snapshot-')
            root = Path(folder.name)
            authority = None
            try:
                ancestry = directory_ancestry_binding(root, label='live snapshot directory')
                authority = (root, ancestry[-1], ancestry)
                require_temporary_cleanup_authority(
                    folder, authority, label='live snapshot directory',
                )
                path = root / 'prefix.pftrace'
                with path.open('xb') as destination:
                    size, packets, digest = _copy_packets(source, destination, before.st_size)
                after = os.fstat(source.fileno())
                _require_regular(after)
                if _identity(before) != _identity(after) or after.st_size < before.st_size:
                    raise ContractError('live trace changed during snapshot')
                if directory_ancestry_binding(
                    source_path.parent, label='live trace source parent'
                ) != source_parent_ancestry:
                    raise ContractError('live trace source parent changed during snapshot')
                yield LiveTraceSnapshot(path, size, packets, before.st_size,
                                        before.st_size - size, digest)
                if directory_ancestry_binding(
                    source_path.parent, label='live trace source parent'
                ) != source_parent_ancestry:
                    raise ContractError('live trace source parent changed during query')
            finally:
                require_temporary_cleanup_authority(
                    folder, authority, label='live snapshot directory',
                )
                folder.cleanup()
    except ContractError:
        raise
    except OSError as error:
        # Do not include capture paths or raw operating-system text.
        raise ContractError(f'live trace snapshot failed ({type(error).__name__})') from None


def require_live_session_binding(session_path: Path, session: dict) -> None:
    """Recheck the immutable session fields after bounded one-shot work."""
    from .contracts import load_session

    current = load_session(session_path)

    def immutable(document):
        return {
            key: value for key, value in document.items()
            if key not in ('state', 'stopped_at')
        }

    if immutable(current) != immutable(session):
        raise ContractError('live recording session binding changed during verification')


def verified_live_source(session_path: Path, repository_root: Path) -> tuple[dict, Path, Path]:
    """Bind a live source to its original running browser and exact runtime."""
    from .build import executable_evidence
    from .contracts import load_session
    from .lifecycle import session_status

    session = load_session(session_path)
    live = session.get('live_trace')
    if live is None:
        raise ContractError('session was not launched with live recording')
    state = session_status(session_path)
    if state['run_id'] != session['run_id'] or state['running'] is not True:
        raise ContractError('live recording requires the original running browser')
    session_build = session.get('build')
    if (not isinstance(session.get('executable'), str)
            or not isinstance(session_build, dict)
            or session_build.get('provenance') != 'attested-browser-core'):
        raise ContractError('live recording requires an attested executable binding')
    executable = Path(session['executable'])
    actual_build = executable_evidence(repository_root, executable, allow_unverified=False)
    if actual_build != session['build']:
        raise ContractError('live recording executable no longer matches its session')
    if 'file_binding' in live:
        from .recording_source import bind_recording_file
        try:
            bind_recording_file(Path(live['path']),live['file_binding'])
        except OSError:
            raise ContractError('bound live recording is not readable') from None
    directory_ancestry_binding(
        Path(live['path']).parent, label='live trace source parent'
    )
    if session_status(session_path) != state:
        raise ContractError('live recording requires the original running browser')
    require_live_session_binding(session_path, session)
    return session, executable, Path(live['path'])


def reconcile_live_source_phase(session, source, parts, before, *, running):
    """Reobserve completion after a one-shot query without relabeling its bytes."""
    from .recording_interruption import observe_interruption
    from .recording_limits import observe_recording_limit
    from .recording_source import bind_recording_file

    prior_phase, prior_limit, prior_limit_binding, prior_interruption = before
    if parts is not None:
        phase, limit, _ = parts.describe(running=running)
        if prior_phase != 'live-prefix' and (phase != prior_phase or limit != prior_limit):
            raise ContractError('recording phase changed during live query')
        return phase, limit

    final = Path(session['trace_path'])
    original_exists = os.path.lexists(source)
    final_exists = os.path.lexists(final)
    if original_exists == final_exists:
        raise ContractError('recording names changed during live query')
    selected = final if final_exists else source
    directory_ancestry_binding(selected.parent, label='live trace source parent')
    expected = session['live_trace'].get('file_binding')
    if final_exists and expected is None:
        raise ContractError('finalized recording has no persisted source binding')
    # A live name can be replaced during the decoder query without changing
    # either the name population or its completion markers. Rebind all phases
    # that have a persisted startup identity, not only a final rename.
    if expected is not None:
        bind_recording_file(selected, expected)
    limit, limit_binding = observe_recording_limit(session, selected)
    interrupted = observe_interruption(final)
    if limit is not None and interrupted is not None:
        raise ContractError('recording has conflicting completion markers')
    if final_exists:
        if interrupted is not None:
            raise ContractError('recording has conflicting completion markers')
        phase = 'finalized-recording'
    elif limit is not None:
        phase = 'limited-recording'
    elif interrupted is not None:
        phase = 'interrupted-recording'
    else:
        phase = 'live-prefix' if running else 'recovered-prefix'
    if prior_phase != 'live-prefix' and (
        phase != prior_phase or limit != prior_limit
        or limit_binding != prior_limit_binding or interrupted != prior_interruption
    ):
        raise ContractError('recording phase changed during live query')
    if (os.path.lexists(source), os.path.lexists(final)) != (original_exists, final_exists):
        raise ContractError('recording names changed during live query')
    return phase, limit


def live_trace_summary(session_path: Path, repository_root: Path, *, limit: int = 100) -> dict:
    """Read bounded, provisional native event-name counts during a live session."""
    from .bounded_process import run_with_bounded_stdout
    from .lifecycle import session_status

    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 1000:
        raise ContractError('live summary limit must be from 1 to 1000')
    session, executable, source = verified_live_source(session_path, repository_root)
    from .recording_limits import observe_recording_limit
    recording_limit,limit_binding=observe_recording_limit(session,source)
    parts=None
    phase='limited-recording' if recording_limit else 'live-prefix'
    from .recording_interruption import observe_interruption
    interrupted=observe_interruption(Path(session['trace_path']))
    if interrupted is not None:
        if recording_limit:
            raise ContractError('recording has conflicting completion markers')
        phase='interrupted-recording'
    if 'parts' in session['live_trace']:
        from .recording_parts import PartsSource
        parts=PartsSource(session)
        phase,recording_limit,_=parts.describe(running=True)
    with snapshot_live_trace(source,**({'parts':parts} if parts is not None else {})) as snapshot:
        rows = []
        if snapshot.bytes:
            # Only the validated integer limit is interpolated. No page value,
            # operator filter, source path, or JavaScript enters this SQL.
            sql = f"""SELECT name, category, COUNT(*) AS events,
COUNT(*) OVER () AS total_groups, SUM(COUNT(*)) OVER () AS total_events
FROM slice WHERE category IN ('browser_core.debug', 'browser_core.stream',
'blink.bindings', 'blink.bindings.encoding')
GROUP BY name, category ORDER BY events DESC, name, category LIMIT {limit}"""
            result = run_with_bounded_stdout(
                [str(executable.with_name('trace_processor_shell.exe')), 'query', str(snapshot.path), sql],
                maximum_stdout=1024 * 1024, timeout_seconds=30, label='native live summary')
            if result.returncode:
                raise ContractError('native live summary query failed')
            try:
                reader = csv.DictReader(io.StringIO(result.stdout.decode('utf-8')), strict=True)
                if reader.fieldnames != ['name', 'category', 'events', 'total_groups', 'total_events']:
                    raise ValueError()
                raw = []
                for row in reader:
                    raw.append(row)
                    if len(raw) > limit:
                        raise ValueError()
                def count(text):
                    value=parse_canonical_decimal(text,minimum=1,maximum=2**63-1)
                    if value is None:
                        raise ValueError()
                    return value
                prior_order = None
                for row in raw:
                    if set(row) != {'name', 'category', 'events', 'total_groups', 'total_events'}:
                        raise ValueError()
                    if (len(row['name']) > 512 or row['category'] not in
                            ('browser_core.debug', 'browser_core.stream',
                             'blink.bindings', 'blink.bindings.encoding')):
                        raise ValueError()
                    events = count(row['events'])
                    order = (-events, row['name'], row['category'])
                    if prior_order is not None and order <= prior_order:
                        raise ValueError()
                    prior_order = order
                    rows.append({'name': row['name'], 'category': row['category'], 'events': events})
                if raw and any(row['total_groups'] != raw[0]['total_groups']
                               or row['total_events'] != raw[0]['total_events'] for row in raw[1:]):
                    raise ValueError()
                total_groups = count(raw[0]['total_groups']) if raw else 0
                total_events = count(raw[0]['total_events']) if raw else 0
                shown_events = sum(row['events'] for row in rows)
                if (len(rows) > limit or total_groups < len(rows)
                        or any(r['events'] <= 0 for r in rows)
                        or total_events < shown_events
                        or (len(rows) < limit and total_groups != len(rows))
                        or (total_groups == len(rows) and total_events != shown_events)):
                    raise ValueError()
            except (UnicodeError, ValueError, TypeError, csv.Error):
                raise ContractError('native live summary returned invalid counters') from None
        else:
            total_groups = total_events = 0
        after = session_status(session_path)
        browser_running = after['run_id'] == session['run_id'] and after['running'] is True
        phase, recording_limit = reconcile_live_source_phase(
            session, source, parts, (phase, recording_limit, limit_binding, interrupted),
            running=browser_running,
        )
        require_live_session_binding(session_path, session)
        return {'schema': 'browser-core.live-summary/1', 'run_id': session['run_id'],
                'complete': False, 'browser_running': browser_running,
                'source_phase': phase, 'bytes': snapshot.bytes, 'packets': snapshot.packets,
                'incomplete_tail_bytes': snapshot.incomplete_tail_bytes,
                'source_sha256': snapshot.sha256, 'total_events': total_events,
                'total_groups': total_groups, 'shown_groups': len(rows), 'groups': rows,
                # What this summary cannot show, stated where agents read the counts.
                'limits': {'names_omitted_below_display_limit': total_groups > len(rows),
                    'counts_scope': 'cumulative since recording start, not per action or trial',
                    'missing_name': ('not recorded in this committed prefix of the enabled native '
                                     'categories; not proof that the code did not run'),
                    'absence_proves_nonexecution': False,
                    'per_window_counts': 'use trace session-compare'},
                **({'recording_limit':recording_limit} if recording_limit else {})}


def require_new_live_artifacts(final_path: Path, *, recording_parts=None) -> None:
    """Refuse existing recording names before creating a browser process."""
    from .recording_parts import MAX_PARTS,part_path,done_marker_path
    from .recording_interruption import interruption_marker_path
    candidates=[final_path,Path(str(final_path)+'.live'),Path(str(final_path)+'.limit'),done_marker_path(final_path),interruption_marker_path(final_path)]
    if recording_parts is not None and recording_parts>1:
        candidates.extend(part_path(Path(str(final_path)+'.live'),number) for number in range(2,MAX_PARTS+1))
        # The reader rejects this first unsupported continuation. A leftover
        # name must not survive preflight and invalidate the new recording.
        candidates.append(Path(str(final_path)+f'.live.part{MAX_PARTS+1}'))
    for path in candidates:
        try:
            os.lstat(path)
        except FileNotFoundError:
            continue
        except OSError as error:
            raise ContractError(f'live trace destination check failed ({type(error).__name__})') from None
        raise ContractError('live trace destination already exists')


def wait_for_live_trace(source_path: Path, process, *, timeout_seconds: float) -> None:
    """Publish readiness only after the owned process produces a whole packet."""
    from .numeric import is_finite_number

    if not is_finite_number(timeout_seconds) or not 0 < timeout_seconds <= 300:
        raise ContractError('live trace startup timeout must be in (0, 300]')
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        exit_code = process.poll()
        if exit_code is not None:
            raise ContractError(f'browser stopped before live recording became ready (exit_code={exit_code})')
        try:
            metadata = os.lstat(source_path)
        except FileNotFoundError:
            metadata = None
        if metadata is not None and metadata.st_size:
            with snapshot_live_trace(source_path) as snapshot:
                if snapshot.packets:
                    if process.poll() is not None:
                        raise ContractError('browser stopped during live recording startup')
                    return
        time.sleep(min(0.05, max(0, deadline-time.monotonic())))
    raise ContractError('native live recording did not become ready before its deadline')
