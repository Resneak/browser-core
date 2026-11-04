"""Append-only native readout, ordered by Perfetto's actual producer flushes."""
from __future__ import annotations

from copy import deepcopy
import hashlib
import os
from pathlib import Path
import secrets
import time

from .contracts import ContractError
from .inspection import _require_latest_order, _require_latest_population, decode_rows, inspection_result, inspection_sql
from .inspection_health import HEALTH_SQL, MAX_HEALTH_COUNTERS, decode_health, retain_health
from .inspection_history import (decode_cursor, decode_highwater, encode_cursor, history_filters,
                                 history_sql, query_digest)
from .live_trace import (MAX_LIVE_PACKETS, MAX_LIVE_SNAPSHOT_BYTES, _copy_packets,
                         _identity, _open_shared_source, _require_regular)
from .recording_source import RecordingSource
from .inspection_contract import supported_capture
from .inspection_freshness import InspectionFreshness
from .trace_rpc import DecoderInterrupted, MAX_APPEND_BYTES, TraceProcessorPipe

MAX_REFRESH_BYTES = 64 * 1024 * 1024


class InspectionRebuilding(ContractError):
    """A bounded replay is pending; keep displayed evidence until it verifies."""


class _AppendSink:
    def __init__(self, consumer, digest):
        self.consumer = consumer
        self.digest = digest
        self.pending = bytearray()

    def write(self, body):
        self.digest.update(body)
        self.pending.extend(body)
        while len(self.pending) >= MAX_APPEND_BYTES:
            self.consumer(bytes(self.pending[:MAX_APPEND_BYTES]))
            del self.pending[:MAX_APPEND_BYTES]
        return len(body)

    def finish(self):
        if self.pending:
            self.consumer(bytes(self.pending))
            self.pending.clear()


class LivePacketCursor:
    """Retain one shared file handle and feed each committed byte only once.

    The native writer is append-only. This does not detect a hostile writer
    changing old bytes in place while retaining file identity and growing size.
    A failed consume is terminal: its decoder may have accepted a partial batch.
    """
    def __init__(self, source: Path, *, maximum_bytes=None, packet_limit=None):
        if not isinstance(source, Path) or not source.is_absolute():
            raise ContractError('incremental source requires an absolute path')
        maximum_bytes=MAX_LIVE_SNAPSHOT_BYTES if maximum_bytes is None else maximum_bytes
        packet_limit=MAX_LIVE_PACKETS if packet_limit is None else packet_limit
        if (type(maximum_bytes) is not int or not 1<=maximum_bytes<=4*1024**3
                or type(packet_limit) is not int or not 1<=packet_limit<=40000000):
            raise ContractError('invalid incremental source limits')
        self.maximum_bytes,self.packet_limit=maximum_bytes,packet_limit
        self.source = source
        self.handle = None
        self.closed = False
        self.frozen = None
        self.offset = self.packets = self.source_bytes = 0
        self.digest = hashlib.sha256()
        try:
            named = os.lstat(source)
            _require_regular(named)
            self.handle = _open_shared_source(source)
            current = os.fstat(self.handle.fileno())
            _require_regular(current)
            self.identity = _identity(current)
            if self.identity != _identity(named):
                raise ContractError('incremental recording changed before opening')
        except (OSError, ContractError):
            self.close()
            raise ContractError('incremental recording could not be opened') from None

    def relocate(self, source: Path):
        """Follow only a verified rename of the already-open file object."""
        named=os.lstat(source);_require_regular(named)
        if _identity(named)!=self.identity:
            raise ContractError('final recording is a different file')
        self.source=source

    def consume(self, consumer, *, relocate=None, stable=None, replay_boundary=None) -> dict:
        if self.closed:
            raise ContractError('incremental recording is closed')
        try:
            try:
                named = os.lstat(self.source)
            except FileNotFoundError:
                if relocate is None:raise
                self.relocate(relocate())
                named = os.lstat(self.source)
            before = os.fstat(self.handle.fileno())
            _require_regular(named)
            _require_regular(before)
            if _identity(named) != self.identity or _identity(before) != self.identity:
                raise ContractError('incremental recording was replaced')
            if stable is not None and stable():
                metadata=(before.st_size,before.st_mtime_ns)
                if self.frozen is None:self.frozen=metadata
                if metadata!=self.frozen:
                    raise ContractError('retired recording changed')
            if before.st_size < self.source_bytes or before.st_size < self.offset:
                raise ContractError('incremental recording shrank')
            if replay_boundary is not None and before.st_size < replay_boundary:
                raise ContractError('recording shrank below its verified replay boundary')
            if before.st_size > self.maximum_bytes:
                raise ContractError('incremental recording exceeds its byte limit')
            available = before.st_size-self.offset
            budget = min(available, MAX_REFRESH_BYTES)
            if replay_boundary is not None:
                budget = min(budget, replay_boundary-self.offset)
            self.handle.seek(self.offset)
            digest = self.digest.copy()
            sink = _AppendSink(consumer, digest)
            size, packets, _ = _copy_packets(self.handle, sink, budget,packet_limit=self.packet_limit)
            if self.packets+packets > self.packet_limit:
                raise ContractError('incremental packet count exceeds its limit')
            sink.finish()
            after = os.fstat(self.handle.fileno())
            _require_regular(after)
            if _identity(after) != self.identity or after.st_size < before.st_size:
                raise ContractError('incremental recording changed during read')
            if self.frozen is not None and (after.st_size,after.st_mtime_ns)!=self.frozen:
                raise ContractError('retired recording changed during read')
            self.offset += size
            self.packets += packets
            self.source_bytes = before.st_size
            self.digest = digest
            remaining = before.st_size-self.offset
            return {'snapshot_bytes': self.offset, 'source_bytes': before.st_size,
                    'source_sha256': digest.hexdigest(), 'packets': self.packets,
                    'new_bytes': size, 'pending_source_bytes': remaining,
                    'catching_up': available > budget,
                    'incomplete_tail_bytes': remaining if budget == available else None}
        except DecoderInterrupted:
            self.close()
            raise
        except (OSError, ContractError):
            self.close()
            raise ContractError('incremental recording is no longer readable') from None
        except BaseException:
            self.close()
            raise

    def close(self):
        self.closed = True
        if self.handle is not None:
            self.handle.close()
            self.handle = None


class IncrementalInspection:
    """A panel-owned decoder. Final export remains an independent full-file read."""
    def __init__(self, session_path: Path, repository_root: Path, source=None):
        self.session_path = session_path
        self.repository_root = repository_root
        self.cursor = self.decoder = None
        self.run_id = None
        self.health = None
        self.source = source or RecordingSource(session_path,repository_root)
        self.finalized = False
        self.history_key = secrets.token_bytes(32)
        self.closed = False
        self.decoder_restarts = 0
        self.replay_guard = None
        self.replay_frozen = None
        self.freshness = InspectionFreshness()

    def _recover_decoder(self):
        """One retry per inspector; never resume a partially accepted append.

        The original source verifier and observed health survive. Old search
        cursors expire because a new decoder may assign different native IDs.
        No replayed rows are published before the known byte prefix matches.
        """
        if self.decoder_restarts or self.cursor is None or self.decoder is None:
            self.close()
            raise ContractError('local decoder recovery is unavailable')
        self.replay_guard = (self.cursor.offset, self.cursor.digest.hexdigest())
        self.replay_frozen = self.cursor.frozen
        self.close()
        self.cursor = self.decoder = None
        self.finalized = False
        self.closed = False
        self.decoder_restarts += 1
        self.history_key = secrets.token_bytes(32)
        raise InspectionRebuilding('Rebuilding the inspector from the original recording')

    def read(self, *, limit: int = 1000) -> dict:
        sql = inspection_sql(limit, incremental=True)
        if self.closed:
            raise ContractError('incremental inspector is closed')
        try:
            location = self.source.resolve()
            session, executable, source = location.session, location.executable, location.path
            if not supported_capture(session.get('value_capture')):
                raise ContractError('session has no native value capture')
            if self.cursor is None:
                self.run_id = session['run_id']
                if getattr(self.source,'parts',None) is not None:
                    from .recording_parts import PartsCursor
                    self.cursor = PartsCursor(self.source.parts)
                else:
                    self.cursor = LivePacketCursor(source,**getattr(self.source,'cursor_limits',{}))
                self.cursor.frozen = self.replay_frozen
                self.decoder = TraceProcessorPipe(executable.with_name('trace_processor_shell.exe'))
            if self.run_id != session['run_id']:
                raise ContractError('incremental inspector session changed')
            if self.cursor.source != source:
                self.cursor.relocate(source)
            deadline = time.monotonic()+30
            def require_time():
                remaining = deadline-time.monotonic()
                if remaining <= 0:
                    raise ContractError('incremental refresh exceeded its deadline')
                self.decoder.timeout = remaining
            def append(body):
                require_time()
                self.decoder.append(body)
            def relocated_source():
                nonlocal location
                location=self.source.resolve()
                return location.path
            receipt = self.cursor.consume(append, relocate=relocated_source,
                                          stable=lambda:location.phase!='live-prefix',
                                          replay_boundary=self.replay_guard[0] if self.replay_guard else None)
            if self.replay_guard is not None:
                size, digest = self.replay_guard
                if self.cursor.offset < size:
                    raise InspectionRebuilding('Rebuilding the previously verified recording prefix')
                if self.cursor.offset != size or self.cursor.digest.hexdigest() != digest:
                    raise ContractError('recording prefix changed during decoder recovery')
                self.replay_guard = None
            settled=location.phase!='live-prefix' and not receipt['catching_up']
            if settled and not self.finalized:
                if location.phase=='finalized-recording' and receipt['incomplete_tail_bytes']:
                    raise ContractError('finalized recording has an incomplete packet')
                require_time()
                self.decoder.finalize()
                self.finalized=True
            require_time()
            events, total = decode_rows(self.decoder.query(sql, max_rows=limit), limit=limit,capture=session['value_capture'])
            _require_latest_order(events)
            _require_latest_population(events, total, limit)
            require_time()
            health = decode_health(self.decoder.query(HEALTH_SQL, max_rows=MAX_HEALTH_COUNTERS+3))
            self.health = retain_health(self.health, health)
            if self.health['sorter_dropped_events']:
                raise ContractError('incremental decoder discarded late events')
            # The source must remain bound through packet ingestion and both
            # decoder queries, even when the capture is still live.
            after=self.source.resolve()
            if (after.session['run_id'] != self.run_id
                    or after.phase != location.phase or after.path != location.path):
                raise ContractError('recording source changed during inspection')
            location=after
            result = inspection_result(events, total, limit)
            result['freshness'] = self.freshness.observe(
                events, total, finalized=self.finalized,
                generation=self.decoder_restarts)
            result.update(receipt, run_id=self.run_id,
                          complete=self.finalized and location.phase=='finalized-recording',
                          source_phase=location.phase, recording_settled=self.finalized,
                          recovery_incomplete=location.phase in ('recovered-prefix','interrupted-recording'),
                          read_mode='incremental', ordering='end-of-file' if self.finalized else 'native-flush-boundaries',
                          decoder_pending_possible=not self.finalized, sorter_dropped_events=0,
                          recording_health=deepcopy(self.health),
                          decoder_restarts=self.decoder_restarts,
                          browser_running=location.browser_running)
            if getattr(location,'reader_runtime',None) is not None:
                result['reader_runtime']=location.reader_runtime
            if getattr(location,'recording_limit',None) is not None:
                result['recording_limit']=location.recording_limit
            if 'byte_limit' in session.get('live_trace',{}):
                max_parts=(session['live_trace'].get('parts') or {}).get('max_parts',1)
                result['recording_budget']={'byte_limit':session['live_trace']['byte_limit']*max_parts,
                                            'used_bytes':receipt['source_bytes']}
                if max_parts>1:
                    result['recording_parts']={'part_byte_limit':session['live_trace']['byte_limit'],
                                               'max_parts':max_parts,'observed_parts':receipt['parts']}
            return result
        except InspectionRebuilding:
            raise
        except DecoderInterrupted:
            self._recover_decoder()
        except BaseException:
            self.close()
            raise

    def close(self):
        self.closed = True
        try:
            if self.cursor is not None:
                self.cursor.close()
        finally:
            if self.decoder is not None:
                self.decoder.close()

    def history(self, *, search='', script='', context='', scope=None, start_ns='', end_ns='',
                cursor=None, limit=1000):
        """Search all ingested observations, paging through a fixed insertion bound.

        New parser rows have larger slice IDs. A cursor pins the high-water ID
        and orders by exact native timestamp then ID; timestamps never pass
        through JavaScript numbers. Search changes require a new snapshot.
        """
        filters = history_filters(search, script, context, scope=scope, start_ns=start_ns, end_ns=end_ns)
        query = query_digest(filters, limit)
        boundary = decode_cursor(self.history_key, query, cursor) if cursor is not None else None
        # Validate requests before touching the decoder. An invalid filter or
        # foreign cursor must not close a healthy live inspector.
        result = self.read(limit=1)
        try:
            # read() may leave the decoder with only a fraction of its refresh
            # deadline. Give the independent history query its own budget.
            self.decoder.timeout=30
            if boundary is None:
                # Track/slice IDs include many kinds of events; the most recent
                # selected value ID alone is not necessarily the greatest ID.
                highwater=decode_highwater(self.decoder.query(
                    'SELECT COALESCE(MAX(id), 0) AS highwater FROM __intrinsic_slice', max_rows=1))
                before=None
            else:
                highwater, timestamp, event_id=boundary
                before=(timestamp, event_id) if timestamp is not None else None
            self.decoder.timeout=30
            events, total=decode_rows(self.decoder.query(
                history_sql(filters, highwater, before=before, limit=limit), max_rows=limit+1), limit=limit+1,
                capture={'schema':result['schema'],'allowlist':result['allowlist']})
            if any((earlier['ts'],earlier['id']) <= (later['ts'],later['id'])
                   for earlier,later in zip(events,events[1:])):
                raise ContractError('history rows are out of order')
            if any(event['id'] > highwater or
                   (before is not None and (event['ts'],event['id']) >= before)
                   for event in events):
                raise ContractError('history rows exceed their page boundary')
            if before is None and len(events) <= limit and total != len(events):
                raise ContractError('history count disagrees with its short first page')
            if before is not None and total <= max(limit, len(events)):
                raise ContractError('history count disagrees with its page cursor')
            has_more=len(events)>limit
            events=events[:limit]
            next_cursor=(encode_cursor(self.history_key, query, highwater, events[-1]['ts'], events[-1]['id'])
                         if has_more else None)
            result.update(inspection_result(events, total, limit,capture={'schema':result['schema'],'allowlist':result['allowlist']}), read_mode='history',
                          filters=filters, snapshot_max_id=str(highwater), next_cursor=next_cursor,
                          page_cursor=cursor or encode_cursor(self.history_key, query, highwater),
                          snapshot_scope='ingested-at-search-start')
            if result.get('source_phase') is not None:
                # read() verified the source before the search. Keep that
                # binding through the later decoder queries, including for
                # a live source that can be replaced during this page.
                after=self.source.resolve()
                if (after.session['run_id'] != result['run_id']
                        or after.phase != result['source_phase']
                        or after.path != self.cursor.source):
                    raise ContractError('recording source changed during history search')
            return result
        except DecoderInterrupted:
            self._recover_decoder()
        except BaseException:
            self.close()
            raise

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
