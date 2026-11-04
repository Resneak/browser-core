"""Bounded, private protocol collection. This module performs no process control.

The caller drains both pipes in chunks, marks EOF/read failure, and supplies the
exit code from its directly created process object. Locators and child-reported
shutdown receipts never grant this collector authority to close a session.
"""
from __future__ import annotations

import copy
import hashlib
from pathlib import Path
from threading import Lock

from .agent_research import EVENT_SCHEMA, MAX_EVENT_BYTES, MAX_LOCATION_BYTES
from .contracts import RUN_ID_RE
from .control_files import decode_strict_json_bytes
from .errors import ContractError
from .lifecycle import validate_stopped_session_receipt
from .profiles import validate_profile_id

MAX_CHUNK_BYTES = 4096
MAX_STDOUT_BYTES = 3 * MAX_EVENT_BYTES
MAX_STDERR_BYTES = 16384
_CODES = ('input-closed','stopped','cancelled-before-start','invalid-options',
          'input-unavailable','command-too-large','invalid-command',
          'output-unavailable','invalid-session-handoff','interrupted',
          'launch-failed','internal-error')
_SUCCESS_CODES = ('input-closed','stopped','cancelled-before-start')


def _invalid():
    raise ContractError('agent event is invalid')


def _validate_event(value, workspace, profile_id):
    if type(value) is not dict or value.get('schema') != EVENT_SCHEMA:
        _invalid()
    event = value.get('event')
    base = {'schema','event'}
    if event == 'awaiting-start':
        if set(value) != base:
            _invalid()
    elif event == 'ready':
        if set(value) != base | {'run_id','session_file','profile_id',
                                'created_profile','profile_retained_on_exit'}:
            _invalid()
        run_id, location = value['run_id'], value['session_file']
        if (not isinstance(run_id,str) or RUN_ID_RE.fullmatch(run_id) is None
                or not isinstance(location,str) or not location
                or len(location.encode('utf-8',errors='strict')) > MAX_LOCATION_BYTES
                or any(ord(character) < 32 for character in location)
                or value['profile_id'] != profile_id
                or type(value['created_profile']) is not bool
                or value['profile_retained_on_exit'] is not True):
            _invalid()
        # Lexical equality to the expected creator workspace: do not open or
        # resolve a child-supplied file, and never use it as a cleanup target.
        if location != str(workspace / 'sessions' / (run_id + '.json')):
            _invalid()
    elif event == 'closed':
        if set(value) != base | {'status','code','launch_attempted','session_received',
                                'cleanup_verified','cleanup_error','shutdown'}:
            _invalid()
        if (value['code'] not in _CODES
                or type(value['launch_attempted']) is not bool
                or type(value['session_received']) is not bool):
            _invalid()
        received, attempted = value['session_received'], value['launch_attempted']
        cleanup, error, shutdown = value['cleanup_verified'], value['cleanup_error'], value['shutdown']
        if received:
            if not attempted or type(cleanup) is not bool:
                _invalid()
            if cleanup:
                if error is not None or type(shutdown) is not dict:
                    _invalid()
                validated = validate_stopped_session_receipt(shutdown,
                    expected_run_id=shutdown.get('run_id'))
                if validated != shutdown or validated['identity_protected'] is not True:
                    _invalid()
            elif shutdown is not None or error not in ('cleanup-failed','cleanup-interrupted'):
                _invalid()
        elif cleanup is not None or error is not None or shutdown is not None:
            _invalid()
        if value['code'] in ('cancelled-before-start','invalid-options') and attempted:
            _invalid()
        if value['code'] == 'stopped' and not received:
            _invalid()
        if value['code'] == 'input-closed' and attempted and not received:
            _invalid()
        if value['code'] == 'invalid-session-handoff' and not received:
            _invalid()
        if value['code'] == 'launch-failed' and (not attempted or received):
            _invalid()
        expected_status = ('interrupted' if error == 'cleanup-interrupted' else
            'error' if error == 'cleanup-failed' else
            'interrupted' if value['code'] == 'interrupted' else
            'ok' if value['code'] in _SUCCESS_CODES else 'error')
        if value['status'] != expected_status:
            _invalid()
    else:
        _invalid()
    return copy.deepcopy(value)


class _Stream:
    def __init__(self, maximum):
        self.maximum = maximum
        self.observed = 0
        self.retained = 0
        self.digest = hashlib.sha256()
        self.eof = False
        self.read_error = False

    def feed(self, chunk):
        self.observed += len(chunk)
        prefix = chunk[:max(0, self.maximum-self.retained)]
        self.digest.update(prefix)
        self.retained += len(prefix)

    def receipt(self):
        return {'observed_bytes':self.observed,'prefix_bytes':self.retained,
                'prefix_sha256':self.digest.hexdigest(),
                'overflow':self.observed > self.maximum,'eof':self.eof,
                'read_error':self.read_error,
                'prefix_is_complete_stream':self.eof and not self.read_error
                    and self.observed == self.retained}


class AgentChannelCollector:
    """Drain bounded chunks without exposing unvalidated output or stderr bodies.

    Thread-safe for one reader per stream. No threads, reads, waits, launches,
    signals or timers are created here. A transport still needs bounded waits
    and cooperative cancellation; memory bounds do not impose a time limit.
    """
    def __init__(self, *, workspace, profile_id):
        try:
            validate_profile_id(profile_id)
            if not isinstance(workspace,Path) or not workspace.is_absolute():
                raise ValueError()
            self.__workspace = workspace.resolve()
        except Exception:
            raise ContractError('agent collector options are invalid') from None
        self.__profile_id = profile_id
        self.__streams = {'stdout':_Stream(MAX_STDOUT_BYTES),'stderr':_Stream(MAX_STDERR_BYTES)}
        self.__pending = bytearray()
        self.__events = []
        self.__error = None
        self.__lock = Lock()

    def __stream(self, name):
        if name not in ('stdout','stderr'):
            raise ContractError('agent output stream is invalid')
        return self.__streams[name]

    def feed(self, stream, chunk):
        with self.__lock:
            state = self.__stream(stream)
            if type(chunk) is not bytes or not 1 <= len(chunk) <= MAX_CHUNK_BYTES or state.eof or state.read_error:
                state.read_error = True
                raise ContractError('agent output chunk is invalid')
            state.feed(chunk)
            if stream != 'stdout' or self.__error is not None:
                return
            if state.observed > state.maximum:
                self.__error = 'stdout-overflow'
                self.__pending.clear()
                return
            # Only LF delimits events, including when CR/LF is split across
            # reads. Pending bytes never exceed one event plus one input chunk.
            self.__pending.extend(chunk)
            while b'\n' in self.__pending and self.__error is None:
                boundary = self.__pending.index(b'\n') + 1
                body = bytes(self.__pending[:boundary])
                del self.__pending[:boundary]
                self.__accept(body)
            if self.__error is not None:
                self.__pending.clear()
            elif len(self.__pending) >= MAX_EVENT_BYTES:
                self.__error = 'event-too-large'
                self.__pending.clear()

    def __accept(self, body):
        if len(body) > MAX_EVENT_BYTES:
            self.__error = 'event-too-large'
            return
        if len(self.__events) >= 3:
            self.__error = 'too-many-events'
            return
        try:
            event = _validate_event(decode_strict_json_bytes(body,label='agent event'),
                                    self.__workspace,self.__profile_id)
            names = [entry['event'] for entry in self.__events]
            name = event['event']
            if (names and names[-1] == 'closed'
                    or name == 'awaiting-start' and names
                    or name == 'ready' and names != ['awaiting-start']
                    or name == 'closed' and names not in ([],['awaiting-start'],['awaiting-start','ready'])):
                raise ValueError()
            if name == 'closed':
                ready = next((entry for entry in self.__events if entry['event']=='ready'),None)
                if ready is not None:
                    if not event['session_received']:
                        raise ValueError()
                    if event['shutdown'] is not None and event['shutdown']['run_id'] != ready['run_id']:
                        raise ValueError()
                elif event['code'] in ('stopped','input-closed') and event['session_received']:
                    raise ValueError()
                if not names and event['launch_attempted']:
                    raise ValueError()
            self.__events.append(event)
        except Exception:
            self.__error = 'invalid-event'

    def finish_stream(self, stream):
        with self.__lock:
            state = self.__stream(stream)
            state.eof = True
            if stream == 'stdout' and self.__pending and self.__error is None:
                self.__error = 'partial-event'
                self.__pending.clear()

    def fail_stream(self, stream):
        with self.__lock:
            self.__stream(stream).read_error = True

    def receipt(self, *, exit_code=None):
        if exit_code is not None and (type(exit_code) is not int or not -(2**31) <= exit_code <= 2**32-1):
            raise ContractError('agent process exit code is invalid')
        with self.__lock:
            stdout, stderr = (self.__streams[name].receipt() for name in ('stdout','stderr'))
            ready = next((item for item in self.__events if item['event']=='ready'),None)
            closed = next((item for item in self.__events if item['event']=='closed'),None)
            error = self.__error
            if closed is not None and exit_code is not None:
                expected = {'ok':0,'error':2,'interrupted':130}[closed['status']]
                if exit_code != expected:
                    error = error or 'exit-status-mismatch'
            complete = (exit_code is not None and closed is not None and error is None
                and all(item['eof'] and not item['read_error'] and not item['overflow'] for item in (stdout,stderr)))
            succeeded = complete and exit_code == 0 and stderr['observed_bytes'] == 0
            return copy.deepcopy({'schema':'browser-core.agent-channel-receipt/1',
                'stdout':stdout,'stderr':stderr,'events_seen':len(self.__events),
                'ready':ready,'closed':closed,'protocol_error':error,'exit_code':exit_code,
                'completion_verified':bool(complete),'succeeded':bool(succeeded)})
