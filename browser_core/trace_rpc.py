"""Bounded, owned stdio client for the pinned Perfetto API 14.

Only append, query, status and one final EOF are exposed. No network listener,
page transport, metrics execution, arbitrary module registration or reconnect.
Wire fields follow protos/perfetto/trace_processor/trace_processor.proto.
"""
from __future__ import annotations

import csv
import io
import math
from pathlib import Path
import queue
import struct
import subprocess
from threading import Event, Lock, Thread

from .contracts import ContractError

MAX_REPLY_BYTES = 16 * 1024 * 1024
MAX_APPEND_BYTES = 4 * 1024 * 1024
# One look-ahead row decides whether a 1,000-row history page has a successor.
# The panel still returns at most 1,000 observations and the byte cap is intact.
MAX_QUERY_ROWS = 1001


class DecoderInterrupted(ContractError):
    """The owned helper stopped responding; replay in a new helper is possible."""


class _PipeEnded(ValueError):
    pass


def _varint(value: int) -> bytes:
    result = bytearray()
    while value > 127:
        result.append((value & 127) | 128)
        value >>= 7
    result.append(value)
    return bytes(result)


def _field(number: int, value: bytes | int) -> bytes:
    if isinstance(value, int):
        return _varint(number << 3) + _varint(value)
    return _varint((number << 3) | 2) + _varint(len(value)) + value


def _exact(stream, size: int) -> bytes:
    result = bytearray()
    while len(result) < size:
        data = stream.read(size-len(result))
        if not data:
            raise _PipeEnded('truncated stream')
        result.extend(data)
    return bytes(result)


def _read_varint(stream) -> int:
    result = 0
    for index in range(10):
        value = _exact(stream, 1)[0]
        if index == 9 and value > 1:
            raise ValueError('integer overflow')
        result |= (value & 127) << (7*index)
        if value < 128:
            return result
    raise ValueError('integer overflow')


def _fields(body: bytes) -> dict:
    stream = io.BytesIO(body)
    output = {}
    count = 0
    while stream.tell() < len(body):
        key = _read_varint(stream)
        number, wire = key >> 3, key & 7
        if not 1 <= number < 2**29 or wire not in (0, 1, 2, 5):
            raise ValueError('invalid field')
        if wire == 0:
            value = _read_varint(stream)
        else:
            size = _read_varint(stream) if wire == 2 else 8 if wire == 1 else 4
            if size > len(body)-stream.tell():
                raise ValueError('invalid field length')
            value = _exact(stream, size)
        output.setdefault(number, []).append((wire, value))
        count += 1
        if count > 100_000:
            raise ValueError('too many fields')
    return output


def _one(fields: dict, number: int, wire: int, default=None):
    values = fields.get(number)
    if values is None:
        return default
    if len(values) != 1 or values[0][0] != wire:
        raise ValueError('ambiguous field')
    return values[0][1]


def _repeated(fields: dict, number: int, wire: int) -> list:
    values = fields.get(number, [])
    if any(kind != wire for kind, value in values):
        raise ValueError('invalid repeated field')
    return [value for kind, value in values]


def _packed(fields: dict, number: int) -> list[int]:
    values = []
    for body in _repeated(fields, number, 2):
        stream = io.BytesIO(body)
        while stream.tell() < len(body):
            values.append(_read_varint(stream))
            if len(values) > 128_000:
                raise ValueError('too many cells')
    return values


def query_csv(replies: list[dict], *, max_rows: int) -> bytes:
    """Decode typed streamed cells, including rows split across batches."""
    columns = []
    cells = []
    ended = False
    for reply in replies:
        result = _fields(_one(reply, 203, 2, b''))
        if _one(result, 2, 2, b''):
            raise ValueError('query error')
        names = [name.decode('utf-8') for name in _repeated(result, 1, 2)]
        if names:
            if columns or len(names) > 128 or len(set(names)) != len(names):
                raise ValueError('ambiguous columns')
            columns = names
        for body in _repeated(result, 3, 2):
            if ended or not columns:
                raise ValueError('invalid batch order')
            batch = _fields(body)
            types = _packed(batch, 1)
            integers = iter(_packed(batch, 2))
            floats = b''.join(_repeated(batch, 3, 2))
            if len(floats) % 8:
                raise ValueError('invalid doubles')
            doubles = iter(struct.unpack('<'+'d'*(len(floats)//8), floats))
            strings = _one(batch, 5, 2, b'')
            if strings and strings[-1:] != b'\0':
                raise ValueError('unterminated strings')
            texts = iter(strings[:-1].decode('utf-8').split('\0') if strings else [])
            blobs = iter(_repeated(batch, 4, 2))
            for kind in types:
                if kind == 1:
                    value = None
                elif kind == 2:
                    value = next(integers)
                    if value >= 2**63:
                        value -= 2**64
                elif kind == 3:
                    value = next(doubles)
                    if not math.isfinite(value):
                        raise ValueError('non-finite result')
                elif kind == 4:
                    value = next(texts)
                elif kind == 5:
                    # Callers use SQL hex transport for private JSON; no raw
                    # blobs or accidental Python repr are admitted to CSV.
                    raise ValueError('unexpected result blob')
                else:
                    raise ValueError('unknown cell type')
                cells.append(value)
                if len(cells) > max_rows*len(columns):
                    raise ValueError('too many result rows')
            sentinel = object()
            if any(next(values, sentinel) is not sentinel for values in (integers, doubles, texts, blobs)):
                raise ValueError('unconsumed cells')
            last = _one(batch, 6, 0, 0)
            if last not in (0, 1):
                raise ValueError('invalid last batch')
            ended = bool(last)
    if not ended or not columns or len(cells) % len(columns):
        raise ValueError('incomplete query')
    output = io.StringIO(newline='')
    writer = csv.writer(output, lineterminator='\n')
    writer.writerow(columns)
    for index in range(0, len(cells), len(columns)):
        writer.writerow(cells[index:index+len(columns)])
    body = output.getvalue().encode('utf-8')
    if len(body) > MAX_REPLY_BYTES:
        raise ValueError('oversized CSV result')
    return body


class TraceProcessorPipe:
    """One owned decoder; a deadline or protocol failure closes it permanently."""

    def __init__(self, executable: Path, *, timeout_seconds: float = 30):
        if (isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, (int, float))
                or not math.isfinite(timeout_seconds) or not 0 < timeout_seconds <= 120):
            raise ContractError('decoder deadline must be in (0, 120]')
        self.timeout = timeout_seconds
        self._closed = Event()
        self._lock = Lock()
        self._final_lock = Lock()
        self._close_lock = Lock()
        self._cleanup_complete = False
        self._requests = queue.Queue(maxsize=1)
        self._results = queue.Queue(maxsize=1)
        self._tx = self._rx = 0
        self._final = False
        try:
            self._thread = Thread(target=self._worker, name='core-trace-decoder', daemon=True)
        except (OSError, RuntimeError):
            raise ContractError('local decoder worker could not start') from None
        try:
            self.process = subprocess.Popen([str(executable), 'server', 'stdio'],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
        except (OSError, ValueError, TypeError, OverflowError):
            raise ContractError('local decoder could not start') from None
        try:
            self._thread.start()
        except (OSError, RuntimeError):
            self.close()
            raise ContractError('local decoder worker could not start') from None
        try:
            reply = self._call(10)[0]
            if _one(_fields(_one(reply, 210, 2, b'')), 3, 0) != 14:
                raise ValueError('wrong protocol version')
        except (KeyboardInterrupt, SystemExit):
            self.close()
            raise
        except BaseException:
            self.close()
            raise ContractError('local decoder protocol is unavailable') from None

    def _exchange(self, request: bytes, method: int) -> list[dict]:
        envelope = _field(1, request)
        if self.process.stdin.write(envelope) != len(envelope):
            raise ValueError('local decoder request write was incomplete')
        self.process.stdin.flush()
        replies = []
        size = 0
        while True:
            if _exact(self.process.stdout, 1) != b'\x0a':
                raise ValueError('invalid RPC envelope')
            length = _read_varint(self.process.stdout)
            size += length
            if size > MAX_REPLY_BYTES or len(replies) >= 1024:
                raise ValueError('oversized RPC response')
            reply = _fields(_exact(self.process.stdout, length))
            if (_one(reply, 1, 0) != self._rx or _one(reply, 3, 0) != method
                    or 4 in reply or _one(reply, 5, 2, b'')):
                raise ValueError('invalid RPC response')
            self._rx += 1
            replies.append(reply)
            if method != 3:
                return replies
            result = _fields(_one(reply, 203, 2, b''))
            if _one(result, 2, 2, b''):
                raise ValueError('query failed')
            if any(_one(_fields(body), 6, 0, 0) for body in _repeated(result, 3, 2)):
                return replies

    def _worker(self):
        while not self._closed.is_set():
            item = self._requests.get()
            if item is None or self._closed.is_set():
                return
            try:
                result = self._exchange(*item)
            except (_PipeEnded, BrokenPipeError, ConnectionResetError):
                result = DecoderInterrupted('local decoder transport ended')
            except OSError:
                result = (DecoderInterrupted('local decoder process exited')
                          if self.process.poll() is not None else
                          ContractError('local decoder transport failed'))
            except Exception:
                result = ContractError('local decoder request failed')
            if not self._closed.is_set():
                try:
                    self._results.put_nowait(result)
                except queue.Full:
                    # close() can publish its interruption between the event
                    # check and this write. Retain that cancellation result.
                    if not self._closed.is_set():
                        raise

    def _call(self, method: int, argument: bytes = b'') -> list[dict]:
        with self._lock:
            if self._closed.is_set():
                raise ContractError('local decoder is closed')
            request = _field(1, self._tx) + _field(2, method) + argument
            self._tx += 1
            try:
                self._requests.put_nowait((request, method))
            except queue.Full:
                # A simultaneous close may already have queued the wakeup.
                if self._closed.is_set():
                    raise ContractError('local decoder is closed') from None
                raise ContractError('local decoder request is already queued') from None
            try:
                result = self._results.get(timeout=self.timeout)
                if self._closed.is_set():
                    raise DecoderInterrupted('local decoder is closed')
                if isinstance(result, Exception):
                    raise result
                return result
            except (queue.Empty, DecoderInterrupted):
                self.close()
                raise DecoderInterrupted('local decoder stopped or exceeded its deadline') from None
            except ContractError:
                self.close()
                raise ContractError('local decoder failed or exceeded its deadline') from None

    def append(self, body: bytes):
        with self._final_lock:
            if not isinstance(body, bytes) or not 1 <= len(body) <= MAX_APPEND_BYTES or self._final:
                raise ContractError('decoder append is invalid or the trace is finalized')
            try:
                reply = self._call(1, _field(101, body))[0]
                rejected = _one(_fields(_one(reply, 201, 2)), 2, 2, b'')
            except ContractError:
                raise
            except (ValueError, TypeError):
                rejected = True
            if rejected:
                self.close()
                raise ContractError('local decoder rejected trace data')

    def finalize(self):
        with self._final_lock:
            if self._final:
                raise ContractError('decoder trace was already finalized')
            try:
                reply = self._call(2)[0]
                rejected = _one(_fields(_one(reply, 212, 2)), 1, 2, b'')
            except ContractError:
                raise
            except (ValueError, TypeError):
                rejected = True
            if rejected:
                self.close()
                raise ContractError('local decoder could not finalize trace data')
            self._final = True

    def query(self, sql: str, *, max_rows: int = 1000) -> bytes:
        if not isinstance(sql, str):
            raise ContractError('local decoder query exceeds its limits')
        try:
            sql_body = sql.encode('utf-8')
        except UnicodeEncodeError:
            raise ContractError('local decoder query exceeds its limits') from None
        if (not 1 <= len(sql_body) <= 65536 or isinstance(max_rows, bool)
                or not isinstance(max_rows, int) or not 1 <= max_rows <= MAX_QUERY_ROWS):
            raise ContractError('local decoder query exceeds its limits')
        try:
            replies = self._call(3, _field(103, _field(1, sql_body)))
            return query_csv(replies, max_rows=max_rows)
        except ContractError:
            raise
        except (ValueError, StopIteration, UnicodeError):
            self.close()
            raise ContractError('local decoder returned an invalid bounded result') from None

    def close(self):
        # Closed to new requests is distinct from successfully cleaned up.
        # Concurrent callers wait for cleanup; a failed attempt remains retryable.
        with self._close_lock:
            if self._cleanup_complete:
                return
            self._closed.set()
            try:
                self._requests.put_nowait(None)
            except queue.Full:
                pass  # A queued request also wakes the worker, which sees closed.
            try:
                self._results.put_nowait(DecoderInterrupted('local decoder is closed'))
            except queue.Full:
                pass  # The waiting caller checks closed before accepting a reply.
            try:
                if self.process.poll() is None:
                    try:
                        self.process.kill()
                    except ProcessLookupError:
                        # The decoder may exit after poll() and before kill().
                        pass
                self.process.wait(timeout=5)
            except (OSError, subprocess.TimeoutExpired):
                # The process may still be live. Keep cleanup retryable and do
                # not expose the executable path from an OS diagnostic.
                raise ContractError('local decoder cleanup did not finish') from None
            if self._thread.is_alive():
                self._thread.join(timeout=5)
            if self._thread.is_alive():
                raise ContractError('local decoder cleanup did not finish')
            for stream in (self.process.stdin, self.process.stdout):
                try:
                    stream.close()
                except OSError:
                    # Closing buffered stdin can flush into an already-dead pipe
                    # on Windows. The owned process and worker are already stopped.
                    pass
            self._cleanup_complete = True

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
