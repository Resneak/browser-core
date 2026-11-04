"""Read consecutive native recording parts as one identity-bound byte stream.

Part boundaries have no packet meaning. The native producer never resets its
Perfetto session while rotating files. Local append-only production remains an
assumption; these bindings are not signatures against a hostile local writer.
"""
from __future__ import annotations

from contextlib import ExitStack, contextmanager
from copy import deepcopy
from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
from tempfile import TemporaryDirectory

from .contracts import ContractError
from .live_trace import (_copy_packets, _identity, _open_shared_source,
                         _require_regular, LiveTraceSnapshot, MAX_LIVE_PACKETS)
from .recording_limits import MIB, validate_byte_limit, limit_marker_path
from .recording_interruption import interruption_marker_path
from .trace_rpc import DecoderInterrupted
from .owned_paths import directory_ancestry_binding
from .prepared_download import require_temporary_cleanup_authority

MAX_PARTS = 16
MAX_TOTAL_BYTES = 4096 * MIB


def recording_parts(part_count, byte_limit, *, live):
    count = 1 if part_count is None else part_count
    if type(count) is not int or not 1 <= count <= MAX_PARTS:
        raise ContractError('recording parts must be an integer from 1 to 16')
    if part_count is not None and not live:
        raise ContractError('recording parts require live recording')
    if live and count * validate_byte_limit(byte_limit) > MAX_TOTAL_BYTES:
        raise ContractError('recording parts must total at most 4096 MiB')
    return count


def validate_parts(value, byte_limit):
    if (type(value) is not dict or set(value) != {'schema', 'max_parts'} or
            value['schema'] != 'browser-core.recording-parts/1' or
            recording_parts(value['max_parts'], byte_limit, live=True) < 2):
        raise ContractError('recording parts contract is invalid')
    return value['max_parts']


def part_path(source: Path, number: int):
    if type(number) is not int or not 1 <= number <= MAX_PARTS:
        raise ContractError('recording part number is invalid')
    return source if number == 1 else Path(str(source) + f'.part{number}')


def done_marker_path(final: Path):
    return Path(str(final) + '.parts-done')


def _metadata(stat):
    return (*_identity(stat), stat.st_size, stat.st_mtime_ns)


def _marker(path):
    try:
        named = os.lstat(path)
    except FileNotFoundError:
        return None
    _require_regular(named)
    with _open_shared_source(path) as stream:
        actual = os.fstat(stream.fileno())
        _require_regular(actual)
        if _metadata(named) != _metadata(actual) or actual.st_size != 0:
            raise ContractError('recording parts marker is invalid')
    return _metadata(actual)


@dataclass(frozen=True)
class PartsView:
    rows: tuple
    source_bytes: int
    parent_ancestry: tuple


class _JoinedReader:
    def __init__(self, streams, sizes, part_bytes):
        self.streams = streams
        self.sizes = sizes
        self.part_bytes = part_bytes
        self.size = sum(sizes)
        self.position = 0
        # These handles belong exclusively to this view. Remember their
        # positions so each one-byte packet header read does not seek again.
        self.stream_positions = [stream.tell() for stream in streams]

    def seek(self, offset, whence=0):
        if whence != 0 or not 0 <= offset <= self.size:
            raise ContractError('invalid recording parts seek')
        self.position = offset
        return offset

    def read(self, count):
        if type(count) is not int or count < 0:
            raise ContractError('recording parts reads require a bounded count')
        count = min(count, self.size - self.position)
        result = bytearray()
        while count:
            index, offset = divmod(self.position, self.part_bytes)
            take = min(count, self.sizes[index] - offset)
            stream = self.streams[index]
            if self.stream_positions[index] != offset:
                stream.seek(offset)
            body = stream.read(take)
            self.stream_positions[index] = offset + len(body)
            if len(body) != take:
                raise ContractError('recording part shrank during read')
            result.extend(body)
            self.position += take
            count -= take
        return bytes(result)


class PartsSource:
    def __init__(self, session):
        live = session['live_trace']
        self.part_bytes = validate_byte_limit(live['byte_limit'])
        self.max_parts = validate_parts(live['parts'], self.part_bytes)
        # Keep the original 10M-per-GiB allowance as the explicit aggregate
        # byte policy grows, up to 40M packets for the supported 4 GiB total.
        gib = 1024 * MIB
        self.packet_limit = ((self.part_bytes*self.max_parts + gib-1)//gib) * MAX_LIVE_PACKETS
        self.source = Path(live['path'])
        self.final = Path(session['trace_path'])
        self.first_binding = deepcopy(live.get('file_binding'))
        if not self.source.is_absolute() or not self.final.is_absolute() or not self.first_binding:
            raise ContractError('recording parts require the original persisted source binding')
        if (not isinstance(live['path'], str)
                or not isinstance(session['trace_path'], str)
                or live['path'] != session['trace_path'] + '.live'):
            raise ContractError('recording parts require the original live source')
        self.identities = {}
        self.sealed = {}
        self.minimum_count = 0
        self.retired = None
        self.markers = {}

    def observe(self, *, settled=False):
        from .recording_source import bind_recording_file
        try:
            parent_ancestry = directory_ancestry_binding(
                self.source.parent, label='recording parts source parent'
            )
            bound = bind_recording_file(self.source, self.first_binding)
            rows = []
            missing = False
            # Also reject unexpected trailing parts outside the session policy.
            for number in range(1, MAX_PARTS + 1):
                path = part_path(self.source, number)
                try:
                    stat = os.lstat(path)
                except FileNotFoundError:
                    missing = True
                    continue
                if missing or number > self.max_parts:
                    raise ContractError('recording parts are missing or outside their policy')
                _require_regular(stat)
                if not 0 <= stat.st_size <= self.part_bytes:
                    raise ContractError('recording part exceeds its byte limit')
                rows.append((path, _metadata(stat)))
            # Native parts are consecutive. Detect the first unsupported
            # continuation even when the session permits all 16 known parts.
            if os.path.lexists(Path(str(self.source) + f'.part{MAX_PARTS + 1}')):
                raise ContractError('recording parts are missing or outside their policy')
            if directory_ancestry_binding(
                self.source.parent, label='recording parts source parent'
            ) != parent_ancestry:
                raise ContractError('recording parts source parent changed during observation')
            if not rows or len(rows) < self.minimum_count:
                raise ContractError('previously observed recording parts disappeared')
            if rows[0][1][:2] != (int(bound['device']), int(bound['inode'])):
                raise ContractError('recording first part changed after binding')
            if any(row[1][2] != self.part_bytes for row in rows[:-1]):
                raise ContractError('recording has an incomplete earlier part')
            for index, (path, metadata) in enumerate(rows):
                old = self.identities.get(index)
                if old is not None and old != metadata[:2]:
                    raise ContractError('recording part was replaced')
                frozen = self.sealed.get(index)
                if frozen is not None and frozen != metadata:
                    raise ContractError('sealed recording part changed')
                self.identities[index] = metadata[:2]
                if settled or index < len(rows)-1:
                    self.sealed[index] = metadata
            metadata = tuple(row[1] for row in rows)
            if self.retired is not None and self.retired != metadata:
                raise ContractError('retired recording parts changed')
            if settled:
                self.retired = metadata
            self.minimum_count = len(rows)
            return PartsView(tuple(rows), sum(row[1][2] for row in rows), parent_ancestry)
        except OSError:
            raise ContractError('recording parts are no longer readable') from None

    def describe(self, *, running):
        if type(running) is not bool:
            raise ContractError('recording parts running state must be boolean')
        try:
            parent_ancestry = directory_ancestry_binding(
                self.source.parent, label='recording parts source parent'
            )
            if os.path.lexists(self.final):
                raise ContractError('segmented recording cannot also have a single finalized trace')
            marker_paths = {'done': done_marker_path(self.final),
                            'limit': limit_marker_path(self.final),
                            'interrupted': interruption_marker_path(self.final)}
            current = {name: _marker(path) for name, path in marker_paths.items()}
            if sum(value is not None for value in current.values()) > 1:
                raise ContractError('recording parts have conflicting completion markers')
            for name, previous in self.markers.items():
                if current[name] != previous:
                    raise ContractError('recording parts marker changed')
            self.markers.update({key: value for key, value in current.items() if value is not None})
            phase = ('finalized-recording' if current['done'] is not None else
                     'limited-recording' if current['limit'] is not None else
                     'interrupted-recording' if current['interrupted'] is not None else
                     'live-prefix' if running else 'recovered-prefix')
            view = self.observe(settled=phase != 'live-prefix')
            for name, value in current.items():
                if _marker(marker_paths[name]) != value:
                    raise ContractError('recording parts marker changed during observation')
            limit = None
            if current['limit'] is not None:
                if view.source_bytes != self.part_bytes * self.max_parts:
                    raise ContractError('recording parts limit disagrees with the total budget')
                limit = {'reason': 'byte-limit', 'byte_limit': self.part_bytes*self.max_parts,
                         'written_bytes': view.source_bytes}
            if os.path.lexists(self.final):
                raise ContractError('segmented recording cannot also have a single finalized trace')
            if directory_ancestry_binding(
                self.source.parent, label='recording parts source parent'
            ) != parent_ancestry:
                raise ContractError('recording parts source parent changed during description')
            return phase, limit, view
        except OSError:
            raise ContractError('recording parts markers are not readable') from None

    @contextmanager
    def open_view(self, view):
        if directory_ancestry_binding(
            self.source.parent, label='recording parts source parent'
        ) != view.parent_ancestry:
            raise ContractError('recording parts source parent changed before reading')
        with ExitStack() as stack:
            streams = []
            for path, expected in view.rows:
                stream = stack.enter_context(_open_shared_source(path))
                stat = os.fstat(stream.fileno())
                _require_regular(stat)
                if _identity(stat) != expected[:2] or stat.st_size < expected[2]:
                    raise ContractError('recording part changed before reading')
                streams.append(stream)
            if directory_ancestry_binding(
                self.source.parent, label='recording parts source parent'
            ) != view.parent_ancestry:
                raise ContractError('recording parts source parent changed before reading')
            reader = _JoinedReader(streams, [row[1][2] for row in view.rows], self.part_bytes)
            yield reader
            for index, ((path, expected), stream) in enumerate(zip(view.rows, streams)):
                named = os.lstat(path)
                actual = os.fstat(stream.fileno())
                _require_regular(named)
                _require_regular(actual)
                if _identity(named) != expected[:2] or _identity(actual) != expected[:2] or actual.st_size < expected[2]:
                    raise ContractError('recording part changed during reading')
                if index in self.sealed and (_metadata(actual) != expected or _metadata(named) != expected):
                    raise ContractError('sealed recording part changed during reading')
            if directory_ancestry_binding(
                self.source.parent, label='recording parts source parent'
            ) != view.parent_ancestry:
                raise ContractError('recording parts source parent changed during reading')


class PartsCursor:
    def __init__(self, parts):
        self.parts = parts
        self.source = parts.source
        self.offset = self.packets = self.source_bytes = 0
        self.digest = hashlib.sha256()
        self.closed = False
        self.frozen = None

    def consume(self, consumer, *, relocate=None, stable=None, replay_boundary=None):
        from .incremental_inspection import MAX_REFRESH_BYTES, _AppendSink
        if self.closed:
            raise ContractError('recording parts cursor is closed')
        try:
            view = self.parts.observe(settled=stable is not None and stable())
            if self.parts.retired is not None:
                if self.frozen is not None and self.frozen != self.parts.retired:
                    raise ContractError('retired recording parts changed during recovery')
                self.frozen = self.parts.retired
            if view.source_bytes < max(self.offset, self.source_bytes, replay_boundary or 0):
                raise ContractError('recording parts shrank')
            available = view.source_bytes - self.offset
            budget = min(available, MAX_REFRESH_BYTES)
            if replay_boundary is not None:
                budget = min(budget, replay_boundary-self.offset)
            digest = self.digest.copy()
            sink = _AppendSink(consumer, digest)
            with self.parts.open_view(view) as stream:
                stream.seek(self.offset)
                size, packets, _ = _copy_packets(stream, sink, budget)
                if self.packets + packets > self.parts.packet_limit:
                    raise ContractError('segmented recording exceeds its packet-count limit')
                sink.finish()
            self.offset += size
            self.packets += packets
            self.source_bytes = view.source_bytes
            self.digest = digest
            return {'snapshot_bytes': self.offset, 'source_bytes': view.source_bytes,
                    'source_sha256': digest.hexdigest(), 'packets': self.packets,
                    'new_bytes': size, 'pending_source_bytes': view.source_bytes-self.offset,
                    'catching_up': available > budget,
                    'incomplete_tail_bytes': view.source_bytes-self.offset if budget == available else None,
                    'parts': len(view.rows)}
        except OSError:
            self.close()
            raise ContractError('recording parts are no longer readable') from None
        except (ContractError, DecoderInterrupted):
            self.close()
            raise
        except BaseException:
            self.close()
            raise

    def close(self):
        self.closed = True


@contextmanager
def snapshot_parts(parts, *, settled=False):
    try:
        view = parts.observe(settled=settled)
        folder = TemporaryDirectory(prefix='browser-core-parts-snapshot-')
        root = Path(folder.name)
        authority = None
        try:
            ancestry = directory_ancestry_binding(root, label='recording parts snapshot directory')
            authority = (root, ancestry[-1], ancestry)
            require_temporary_cleanup_authority(
                folder, authority, label='recording parts snapshot directory',
            )
            path = root / 'prefix.pftrace'
            with parts.open_view(view) as stream, path.open('xb') as destination:
                size, packets, digest = _copy_packets(stream, destination, view.source_bytes,
                                                      packet_limit=parts.packet_limit)
            yield LiveTraceSnapshot(path, size, packets, view.source_bytes, view.source_bytes-size, digest)
            if directory_ancestry_binding(
                parts.source.parent, label='recording parts source parent'
            ) != view.parent_ancestry:
                raise ContractError('recording parts source parent changed during query')
        finally:
            require_temporary_cleanup_authority(
                folder, authority, label='recording parts snapshot directory',
            )
            folder.cleanup()
    except OSError:
        raise ContractError('recording parts snapshot could not be read or written') from None
