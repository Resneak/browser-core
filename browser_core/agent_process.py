"""Asynchronous control of one directly created Windows agent-protocol process.

No API accepts a PID, observed process, session target or foreign process object
as control authority. The command itself is trusted caller configuration. This
is a cooperating-process interface, not a sandbox against hostile Python code.
"""
from __future__ import annotations

import asyncio
import json
import math
import ntpath
import os
from pathlib import Path
import subprocess

from .agent_channel import AgentChannelCollector, MAX_CHUNK_BYTES
from .agent_research import COMMAND_SCHEMA
from .errors import ContractError

_START = (json.dumps({'schema':COMMAND_SCHEMA,'action':'start'},separators=(',',':'))+'\n').encode('ascii')
_STOP = (json.dumps({'schema':COMMAND_SCHEMA,'action':'stop'},separators=(',',':'))+'\n').encode('ascii')


def _timeout(value):
    if type(value) not in (int,float) or not 0 < value <= 60 or not math.isfinite(value):
        raise ContractError('agent process timeout must be finite and in (0, 60]')
    return float(value)


def _command(value, cwd):
    if os.name != 'nt':
        raise ContractError('agent process transport requires Windows')
    if (not isinstance(value,(list,tuple)) or not 1 <= len(value) <= 256
            or any(not isinstance(arg,str) or not arg or '\0' in arg
                   or len(arg) > 32768 for arg in value)
            or sum(map(len,value)) > 32766):
        raise ContractError('agent process command is invalid')
    # CreateProcessW counts the complete quoted UTF-16 command line, including
    # its terminating NUL; raw Python string lengths can undercount both quotes
    # and non-BMP characters.
    try:
        command_units = len(subprocess.list2cmdline(value).encode('utf-16-le')) // 2
    except UnicodeEncodeError as exc:
        raise ContractError('agent process command is invalid') from exc
    if command_units > 32766:
        raise ContractError('agent process command is invalid')
    drive, tail = ntpath.splitdrive(value[0])
    if (not drive or not tail.startswith(('\\','/'))
            or ntpath.splitext(value[0])[1].lower() != '.exe'):
        raise ContractError('agent process requires a direct absolute Windows EXE')
    if not isinstance(cwd,Path) or not cwd.is_absolute() or not cwd.is_dir():
        raise ContractError('agent process working directory is invalid')
    return tuple(value)


class _Protocol(asyncio.SubprocessProtocol):
    def __init__(self, owner): self.owner = owner
    def connection_made(self, transport): self.owner._connected(transport)
    def pipe_data_received(self, fd, data): self.owner._data(fd,data)
    def pipe_connection_lost(self, fd, exc): self.owner._pipe_lost(fd,exc)
    def process_exited(self): self.owner._changed()
    def connection_lost(self, exc): self.owner._disconnected(exc)


class AgentProcess:
    """Construct first, then await open/start/close on one running event loop.

    open never sends start. Timeouts request cooperative EOF without dropping
    the creator reference or cancelling its creation task. Keep the event loop
    alive and inspect/retry close until creation and connection are terminal.
    force_stop_creator is explicit and cannot establish browser cleanup.
    """
    def __init__(self, command: list[str] | tuple[str, ...], *, cwd: Path,
                 workspace: Path, profile_id: str) -> None:
        """Require pathlib.Path for cwd/workspace; command arguments are strings.

        cwd must be an existing absolute directory; workspace must be absolute.
        Construction validates configuration only and never starts a process.
        """
        if not isinstance(cwd, Path) or not isinstance(workspace, Path):
            raise ContractError('agent process cwd and workspace must be pathlib.Path objects')
        self.__command = _command(command,cwd)
        self.__cwd = cwd
        self.__collector = AgentChannelCollector(workspace=workspace,profile_id=profile_id)
        self.__loop = None
        self.__event = None
        self.__creation = None
        self.__transport = None
        self.__setup = False
        self.__connection_closed = False
        self.__start_attempted = False
        self.__stop_requested = False
        self.__stop_eof_only = False
        self.__stdin_close_requested = False
        self.__force_requested = False
        self.__force_attempted = False
        self.__output_released = False
        self.__error = None
        self.__timeout_stage = None

    def __check_loop(self):
        loop = asyncio.get_running_loop()
        if self.__loop is not None and loop is not self.__loop:
            raise ContractError('agent process must stay on its creating event loop')
        return loop

    def _changed(self):
        if self.__event is not None:
            self.__event.set()

    def __problem(self, code):
        self.__error = self.__error or code
        self.request_stop(eof_only=True)
        self._changed()

    def _connected(self, transport):
        if self.__transport is not None:
            if transport is not self.__transport:
                # No adoption of a second transport and no control of it.
                self.__problem('unexpected-transport')
            return
        self.__transport = transport
        if self.__stop_requested:
            self.__send_stop()
        if self.__force_requested:
            self.__kill_creator()
        self._changed()

    def _data(self, fd, data):
        stream_fd = type(fd) is int and fd in (1,2)
        try:
            valid_data = isinstance(data,(bytes,bytearray,memoryview)) and (
                not isinstance(data,memoryview) or data.ndim == 1 and data.itemsize == 1)
        except (TypeError,ValueError):
            # A released memoryview raises while reading its shape.
            valid_data = False
        if not stream_fd or not valid_data:
            if stream_fd:
                self.__collector.fail_stream('stdout' if fd == 1 else 'stderr')
            self.__problem('invalid-pipe-data')
            return
        name = 'stdout' if fd == 1 else 'stderr'
        try:
            for offset in range(0,len(data),MAX_CHUNK_BYTES):
                self.__collector.feed(name,bytes(data[offset:offset+MAX_CHUNK_BYTES]))
            channel = self.__collector.receipt()
            if channel['protocol_error'] is not None:
                self.__problem('invalid-output')
            elif any(channel[key]['overflow'] for key in ('stdout','stderr')):
                self.__problem('output-overflow')
            elif channel['stderr']['observed_bytes']:
                self.__problem('stderr-output')
            elif not self.__start_attempted and (channel['ready'] is not None
                    or channel['closed'] is not None and channel['closed']['launch_attempted']):
                self.__problem('unsolicited-start')
        except Exception:
            self.__collector.fail_stream(name)
            self.__problem('pipe-read-failed')
        self._changed()

    def _pipe_lost(self, fd, exc):
        if fd in (1,2):
            name = 'stdout' if fd == 1 else 'stderr'
            if exc is not None:
                self.__collector.fail_stream(name)
                self.__problem('pipe-read-failed')
            self.__collector.finish_stream(name)
            if fd == 1:
                channel = self.__collector.receipt()
                if channel['protocol_error'] is not None or channel['closed'] is None:
                    self.__problem('incomplete-output')
        elif fd == 0:
            if exc is not None:
                self.__problem('pipe-write-failed')
            elif not self.__stop_requested and self.__collector.receipt()['closed'] is None:
                self.__problem('stdin-closed')
        self._changed()

    def _disconnected(self, exc):
        self.__connection_closed = True
        if exc is not None:
            self.__problem('connection-failed')
        self._changed()

    async def __create(self):
        try:
            transport, protocol = await self.__loop.subprocess_exec(
                lambda:_Protocol(self),*self.__command,cwd=self.__cwd,
                stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                shell=False,close_fds=True,creationflags=subprocess.CREATE_NO_WINDOW)
            self._connected(transport)
            if not isinstance(protocol,_Protocol) or protocol.owner is not self:
                self.__problem('invalid-protocol-setup')
                return
            if any(transport.get_pipe_transport(fd) is None for fd in (0,1,2)):
                self.__problem('incomplete-pipe-setup')
                return
            self.__setup = True
            if self.__stop_requested:
                self.__send_stop()
        except asyncio.CancelledError:
            # Only external loop shutdown should cancel this retained task.
            self.__problem('creation-cancelled')
        except Exception:
            self.__problem('creation-failed')
        finally:
            self._changed()

    def __ready_for_start(self):
        channel = self.__collector.receipt()
        return (self.__setup and not self.__stop_requested and not self.__start_attempted
            and self.__error is None and self.__transport.get_returncode() is None
            and channel['events_seen'] == 1 and channel['ready'] is None
            and channel['closed'] is None and channel['protocol_error'] is None
            and not channel['stdout']['eof']
            and not self.__transport.get_pipe_transport(0).is_closing())

    def __settled(self):
        return self.__creation is not None and self.__creation.done() and (
            self.__transport is None or self.__connection_closed)

    async def __wait(self, predicate, seconds, stage):
        deadline = self.__loop.time()+seconds
        try:
            while not predicate():
                remaining = deadline-self.__loop.time()
                if remaining <= 0:
                    self.__timeout_stage = self.__timeout_stage or stage
                    self.request_stop(eof_only=True)
                    break
                self.__event.clear()
                try:
                    await asyncio.wait_for(self.__event.wait(),remaining)
                except asyncio.TimeoutError:
                    self.__timeout_stage = self.__timeout_stage or stage
                    self.request_stop(eof_only=True)
                    break
        except asyncio.CancelledError:
            self.__problem('caller-cancelled')
            raise
        return self.snapshot()

    async def open(self, *, timeout_seconds=10):
        seconds = _timeout(timeout_seconds)
        loop = self.__check_loop()
        if self.__creation is not None or self.__stop_requested:
            raise ContractError('agent process can only be opened once')
        self.__loop, self.__event = loop, asyncio.Event()
        self.__creation = loop.create_task(self.__create())
        return await self.__wait(lambda:self.__ready_for_start() or self.__settled()
            or self.__error is not None,seconds,'open')

    async def start(self, *, timeout_seconds=30):
        seconds = _timeout(timeout_seconds)
        self.__check_loop()
        if not self.__ready_for_start():
            raise ContractError('agent process is not ready for its single start')
        # A failed write can still have transmitted bytes: record the attempt
        # before calling the nonblocking writer, never infer no launch on error.
        self.__start_attempted = True
        try:
            self.__transport.get_pipe_transport(0).write(_START)
        except Exception:
            self.__problem('pipe-write-failed')
        return await self.__wait(lambda:self.__collector.receipt()['ready'] is not None
            or self.__collector.receipt()['closed'] is not None or self.__settled()
            or self.__error is not None,seconds,'start')

    def request_stop(self, *, eof_only=False):
        self.__check_loop()
        if type(eof_only) is not bool:
            raise ContractError('agent stop mode must be boolean')
        if not self.__stop_requested:
            self.__stop_requested, self.__stop_eof_only = True,eof_only
            self.__send_stop()
        self._changed()

    def __send_stop(self):
        if self.__transport is None or self.__stdin_close_requested:
            return
        pipe = self.__transport.get_pipe_transport(0)
        if pipe is None:
            return
        self.__stdin_close_requested = True
        try:
            if not self.__stop_eof_only and not pipe.is_closing():
                pipe.write(_STOP)
            pipe.close()
        except Exception:
            self.__error = self.__error or 'pipe-write-failed'
            try:
                pipe.abort()
            except Exception:
                self.__error = self.__error or 'pipe-close-failed'

    async def close(self, *, timeout_seconds=45):
        seconds = _timeout(timeout_seconds)
        self.__check_loop()
        self.request_stop()
        if self.__creation is None:
            return self.snapshot()
        return await self.__wait(self.__settled,seconds,'close')

    def __kill_creator(self):
        if (self.__transport is None or self.__transport.get_returncode() is not None):
            return
        self.__force_attempted = True
        try:
            self.__transport.kill()
        except ProcessLookupError:
            pass
        except Exception:
            self.__error = self.__error or 'creator-kill-failed'

    async def force_stop_creator(self, *, timeout_seconds=5):
        """Explicit last resort for this direct creator, never its descendants."""
        seconds = _timeout(timeout_seconds)
        self.__check_loop()
        self.request_stop(eof_only=True)
        self.__force_requested = True
        self.__kill_creator()
        if self.__creation is None:
            return self.snapshot()
        return await self.__wait(self.__settled,seconds,'force-stop')

    def release_output(self):
        """After observed creator exit, abandon local pipes with incomplete data.

        Another process may hold an inherited writer. Closing our own read ends
        does not authorize or perform any control of that other process.
        """
        self.__check_loop()
        if self.__transport is None or self.__transport.get_returncode() is None:
            raise ContractError('output release requires observed creator exit')
        self.__output_released = True
        for fd,name in ((1,'stdout'),(2,'stderr')):
            if not self.__collector.receipt()[name]['eof']:
                self.__collector.fail_stream(name)
                pipe = self.__transport.get_pipe_transport(fd)
                if pipe is not None:
                    pipe.close()
        self._changed()

    def snapshot(self):
        self.__check_loop()
        code = self.__transport.get_returncode() if self.__transport is not None else None
        channel = self.__collector.receipt(exit_code=code)
        return {'schema':'browser-core.agent-process/1',
            'creation_requested':self.__creation is not None,
            'creation_pending':self.__creation is not None and not self.__creation.done(),
            'transport_created':self.__transport is not None,
            'ready_for_start':bool(self.__ready_for_start()),
            'start_attempted':self.__start_attempted,'stop_requested':self.__stop_requested,
            'stdin_close_requested':self.__stdin_close_requested,
            'force_stop_requested':self.__force_requested,'force_stop_attempted':self.__force_attempted,
            'creator_exit_observed':code is not None,'connection_closed':self.__connection_closed,
            'output_released':self.__output_released,'transport_error':self.__error,
            'timeout_stage':self.__timeout_stage,'channel':channel,
            'succeeded':bool(channel['succeeded'] and self.__settled() and self.__connection_closed
                and self.__error is None and self.__timeout_stage is None
                and not self.__force_requested and not self.__output_released)}
