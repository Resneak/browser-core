"""Fake event-loop transports only. No OS process is created by these tests."""
import asyncio
import copy
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from browser_core import agent_process as process
from browser_core.agent_research import EVENT_SCHEMA
from browser_core.errors import ContractError

PRIVATE = 'fixture-private-process-output'


class Pipe:
    def __init__(self, transport, fd):
        self.transport,self.fd,self.closing = transport,fd,False
        self.writes = []
        self.write_error = None
    def is_closing(self): return self.closing
    def write(self, data):
        self.writes.append(data)
        if self.write_error: raise self.write_error
        if self.fd != 0: raise AssertionError('only stdin may be written')
        action = json.loads(data)['action']
        if action == 'start':
            self.transport.started = True
            if not self.transport.stall_start:
                self.transport.emit('ready',run_id='fixture-owned',
                    session_file=str(self.transport.workspace/'sessions/fixture-owned.json'),
                    profile_id='fixture-profile',created_profile=True,profile_retained_on_exit=True)
        else:
            self.transport.stopped = True
    def close(self):
        if self.closing: return
        self.closing = True
        if self.fd == 0:
            if not self.transport.stall_stop: self.transport.finish()
        else:
            self.transport.protocol.pipe_connection_lost(self.fd,None)
            self.transport.maybe_disconnect()
    def abort(self): self.close()


class Transport:
    def __init__(self, protocol, workspace):
        self.protocol,self.workspace = protocol,workspace
        self.pipes = {fd:Pipe(self,fd) for fd in (0,1,2)}
        self.started = self.stopped = self.stall_start = self.stall_stop = False
        self.hold_output = False
        self.code = None
        self.kill_calls = 0
        self.kill_error = None
        self.disconnected = False
    def get_pipe_transport(self, fd): return self.pipes.get(fd)
    def get_returncode(self): return self.code
    def get_pid(self): raise AssertionError('PID must not be read as authority')
    def emit(self, event, **fields):
        self.protocol.pipe_data_received(1,(json.dumps({'schema':EVENT_SCHEMA,'event':event,**fields})+'\n').encode())
    def finish(self):
        if self.code is not None: return
        self.emit('closed',status='ok',code=('stopped' if self.started else 'cancelled-before-start')
            if self.stopped else 'input-closed',launch_attempted=self.started,session_received=self.started,
            cleanup_verified=True if self.started else None,cleanup_error=None,
            shutdown={'run_id':'fixture-owned','state':'stopped','running':False,'identity_protected':True}
            if self.started else None)
        self.exit(0)
    def exit(self, code):
        self.code = code
        self.protocol.process_exited()
        if not self.hold_output:
            for fd in (1,2): self.pipes[fd].close()
        self.maybe_disconnect()
    def maybe_disconnect(self):
        if self.code is not None and all(self.pipes[fd].closing for fd in (1,2)) and not self.disconnected:
            self.disconnected = True
            self.protocol.connection_lost(None)
    def kill(self):
        self.kill_calls += 1
        if self.kill_error: raise self.kill_error
        self.exit(1)


@pytest.fixture
def env(tmp_path,monkeypatch):
    workspace = tmp_path/'workspace'
    monkeypatch.setattr(process,'os',SimpleNamespace(name='nt'))
    return SimpleNamespace(workspace=workspace,cwd=tmp_path,monkeypatch=monkeypatch,transports=[],
        calls=[],delay=None,after_connect=None,creation_error=None,configure=lambda transport:None,early_connect=False)


def install(env):
    loop = asyncio.get_running_loop()
    async def create(factory,*command,**kwargs):
        env.calls.append((command,kwargs))
        if env.delay is not None: await env.delay.wait()
        if env.creation_error: raise env.creation_error
        protocol = factory()
        transport = Transport(protocol,env.workspace)
        env.transports.append(transport)
        env.configure(transport)
        if env.early_connect:
            saved = transport.pipes
            transport.pipes = {}
            protocol.connection_made(transport)
            transport.pipes = saved
        else: protocol.connection_made(transport)
        transport.emit('awaiting-start')
        if env.after_connect is not None: await env.after_connect.wait()
        return transport,protocol
    env.monkeypatch.setattr(loop,'subprocess_exec',create)
    return process.AgentProcess(['C:/fixture/python.exe','-m','fixture'],cwd=env.cwd,
        workspace=env.workspace,profile_id='fixture-profile')


def check_private(result):
    assert PRIVATE not in json.dumps(result)


def test_complete_protocol_uses_direct_transport_and_hidden_shell_free_launch(env):
    async def run():
        owner = install(env)
        opened = await owner.open(timeout_seconds=1)
        assert opened['ready_for_start'] and not opened['start_attempted']
        assert not env.transports[0].pipes[0].writes
        ready = await owner.start(timeout_seconds=1)
        assert ready['channel']['ready']['run_id'] == 'fixture-owned'
        closed = await owner.close(timeout_seconds=1)
        assert closed['succeeded'] and closed['creator_exit_observed'] and closed['connection_closed']
        assert env.transports[0].kill_calls == 0
        args = env.calls[0][1]
        assert args['shell'] is False and args['close_fds'] is True
        assert args['creationflags'] == process.subprocess.CREATE_NO_WINDOW
        assert all(args[name] == process.subprocess.PIPE for name in ('stdin','stdout','stderr'))
        assert [json.loads(value)['action'] for value in env.transports[0].pipes[0].writes] == ['start','stop']
        check_private(closed)
    asyncio.run(run())


@pytest.mark.parametrize('eof_only',[False,True])
@pytest.mark.parametrize('started',[False,True])
def test_stop_and_eof_before_and_after_start_are_distinct(env,eof_only,started):
    async def run():
        owner = install(env)
        await owner.open(timeout_seconds=1)
        if started: await owner.start(timeout_seconds=1)
        owner.request_stop(eof_only=eof_only)
        result = await owner.close(timeout_seconds=1)
        assert result['succeeded'] and result['start_attempted'] is started
        assert result['channel']['closed']['launch_attempted'] is started
        assert result['channel']['closed']['code'] == ('input-closed' if eof_only else
            'stopped' if started else 'cancelled-before-start')
    asyncio.run(run())


def test_creation_timeout_retains_task_and_late_creator_receives_only_eof(env):
    async def run():
        env.delay = asyncio.Event()
        env.early_connect = True
        owner = install(env)
        result = await owner.open(timeout_seconds=.01)
        assert result['creation_pending'] and result['timeout_stage']=='open'
        assert not result['transport_created'] and not env.transports
        env.delay.set()
        result = await owner.close(timeout_seconds=1)
        assert result['connection_closed'] and not result['creation_pending']
        assert not env.transports[0].started and not env.transports[0].pipes[0].writes
        assert not result['succeeded'] and result['channel']['succeeded']
    asyncio.run(run())


def test_cancelling_open_does_not_cancel_or_lose_pending_creation(env):
    async def run():
        env.delay = asyncio.Event()
        owner = install(env)
        opening = asyncio.create_task(owner.open(timeout_seconds=1))
        await asyncio.sleep(0)
        opening.cancel()
        with pytest.raises(asyncio.CancelledError): await opening
        assert owner.snapshot()['creation_pending']
        env.delay.set()
        result = await owner.close(timeout_seconds=1)
        assert result['connection_closed'] and result['transport_error']=='caller-cancelled'
        assert not env.transports[0].started and env.transports[0].kill_calls == 0
    asyncio.run(run())


def test_creation_failure_returns_fixed_error_without_a_control_target(env):
    async def run():
        env.creation_error = OSError(PRIVATE)
        owner = install(env)
        await owner.open(timeout_seconds=1)
        result = await owner.close(timeout_seconds=1)
        assert result['transport_error']=='creation-failed' and not result['transport_created']
        assert not result['creator_exit_observed'] and not result['creation_pending']
        check_private(result)
    asyncio.run(run())


def test_start_timeout_requests_eof_and_preserves_unknown_cleanup(env):
    async def run():
        env.configure = lambda t: (setattr(t,'stall_start',True),setattr(t,'stall_stop',True))
        owner = install(env)
        await owner.open(timeout_seconds=1)
        result = await owner.start(timeout_seconds=.01)
        assert result['timeout_stage']=='start' and result['start_attempted']
        assert result['stop_requested'] and not result['creator_exit_observed']
        assert result['channel']['closed'] is None and not result['succeeded']
        result = await owner.force_stop_creator(timeout_seconds=1)
        assert result['creator_exit_observed'] and not result['channel']['completion_verified']
        assert env.transports[0].kill_calls == 1
    asyncio.run(run())


def test_cancelled_start_requests_cooperative_cleanup(env):
    async def run():
        env.configure = lambda t:setattr(t,'stall_start',True)
        owner = install(env)
        await owner.open(timeout_seconds=1)
        waiting = asyncio.create_task(owner.start(timeout_seconds=1))
        await asyncio.sleep(0)
        waiting.cancel()
        with pytest.raises(asyncio.CancelledError): await waiting
        result = await owner.close(timeout_seconds=1)
        assert result['creator_exit_observed'] and result['transport_error']=='caller-cancelled'
        assert env.transports[0].kill_calls == 0
    asyncio.run(run())


@pytest.mark.parametrize('mode',['invalid','stderr','overflow','unsolicited'])
def test_output_failure_automatically_requests_stop_and_stays_private(env,mode):
    async def run():
        owner = install(env)
        await owner.open(timeout_seconds=1)
        t = env.transports[0]
        if mode=='invalid': t.protocol.pipe_data_received(1,PRIVATE.encode()+b'\n')
        elif mode=='stderr': t.protocol.pipe_data_received(2,PRIVATE.encode())
        elif mode=='overflow': t.protocol.pipe_data_received(2,b'x'*20000)
        else:
            t.emit('ready',run_id='fixture-owned',session_file=str(env.workspace/'sessions/fixture-owned.json'),
                profile_id='fixture-profile',created_profile=True,profile_retained_on_exit=True)
        result = await owner.close(timeout_seconds=1)
        assert result['stop_requested'] and result['transport_error'] is not None
        assert not result['succeeded'] and t.kill_calls==0
        check_private(result)
    asyncio.run(run())


def test_write_failure_after_start_attempt_does_not_claim_no_launch(env):
    async def run():
        owner = install(env)
        await owner.open(timeout_seconds=1)
        env.transports[0].pipes[0].write_error = BrokenPipeError(PRIVATE)
        result = await owner.start(timeout_seconds=1)
        assert result['start_attempted'] and result['transport_error']=='pipe-write-failed'
        result = await owner.close(timeout_seconds=1)
        assert not result['succeeded']
        check_private(result)
    asyncio.run(run())


def test_cooperative_timeout_never_kills_and_force_only_uses_exact_creator(env):
    async def run():
        env.configure = lambda t:setattr(t,'stall_stop',True)
        owner = install(env)
        await owner.open(timeout_seconds=1)
        await owner.start(timeout_seconds=1)
        creator = env.transports[0]
        foreign = Transport(creator.protocol,env.workspace)
        result = await owner.close(timeout_seconds=.01)
        assert not result['creator_exit_observed'] and creator.kill_calls==foreign.kill_calls==0
        result = await owner.force_stop_creator(timeout_seconds=1)
        assert creator.kill_calls==1 and foreign.kill_calls==0 and foreign.code is None
        assert result['force_stop_attempted'] and not result['succeeded']
    asyncio.run(run())


def test_failed_force_can_retry_same_creator_without_widening_scope(env):
    async def run():
        env.configure = lambda t:setattr(t,'stall_stop',True)
        owner = install(env)
        await owner.open(timeout_seconds=1)
        t = env.transports[0]
        t.kill_error = OSError(PRIVATE)
        result = await owner.force_stop_creator(timeout_seconds=.01)
        assert not result['creator_exit_observed'] and t.kill_calls==1
        t.kill_error = None
        result = await owner.force_stop_creator(timeout_seconds=1)
        assert result['creator_exit_observed'] and t.kill_calls==2
        check_private(result)
    asyncio.run(run())


def test_creator_exit_does_not_replace_output_eof_and_release_invalidates_completion(env):
    async def run():
        env.configure = lambda t:setattr(t,'hold_output',True)
        owner = install(env)
        await owner.open(timeout_seconds=1)
        await owner.start(timeout_seconds=1)
        result = await owner.close(timeout_seconds=.01)
        assert result['creator_exit_observed'] and not result['connection_closed']
        assert not result['channel']['completion_verified']
        owner.release_output()
        result = await owner.close(timeout_seconds=1)
        assert result['connection_closed'] and not result['succeeded']
        assert result['channel']['stdout']['read_error']
        assert env.transports[0].kill_calls==0
    asyncio.run(run())


def test_repeated_stop_and_close_are_idempotent_but_start_and_open_are_single_use(env):
    async def run():
        owner = install(env)
        await owner.open(timeout_seconds=1)
        with pytest.raises(ContractError): await owner.open(timeout_seconds=1)
        await owner.start(timeout_seconds=1)
        with pytest.raises(ContractError): await owner.start(timeout_seconds=1)
        owner.request_stop()
        owner.request_stop()
        for _ in range(3): assert (await owner.close(timeout_seconds=1))['succeeded']
        assert len(env.transports[0].pipes[0].writes)==2
    asyncio.run(run())


def test_release_is_rejected_while_creator_is_running(env):
    async def run():
        owner = install(env)
        await owner.open(timeout_seconds=1)
        with pytest.raises(ContractError): owner.release_output()
        await owner.close(timeout_seconds=1)
    asyncio.run(run())


@pytest.mark.parametrize('value',[None,False,0,-1,float('nan'),float('inf'),61,10**1000,'1'])
def test_invalid_timeout_is_rejected_before_creation(env,value):
    async def run():
        owner = install(env)
        with pytest.raises(ContractError): await owner.open(timeout_seconds=value)
        assert not env.calls
    asyncio.run(run())


@pytest.mark.parametrize('command',[123,object(),[],['relative.exe'],['C:/fixture/child.cmd'],
    ['C:/fixture/child.bat'],['C:/fixture/child.exe','\0'],['C:/fixture/child.exe',123]])
def test_metadata_and_shell_launchers_cannot_be_control_authority(env,command):
    with pytest.raises(ContractError):
        process.AgentProcess(command,cwd=env.cwd,workspace=env.workspace,profile_id='fixture-profile')


@pytest.mark.parametrize('argument', [
    pytest.param('"'*16380,id='quoted-expansion'),
    pytest.param('\U0001f600'*16380,id='utf16-expansion'),
    pytest.param('\ud800',id='unpaired-surrogate'),
])
def test_windows_command_line_limit_and_unicode_are_checked_before_creation(env,argument):
    with pytest.raises(ContractError,match='agent process command is invalid'):
        process.AgentProcess(['C:/fixture/child.exe',argument],cwd=env.cwd,
            workspace=env.workspace,profile_id='fixture-profile')


def test_unicode_command_within_windows_limit_remains_valid(env):
    process.AgentProcess(['C:/fixture/child.exe','\U0001f600'*100],cwd=env.cwd,
        workspace=env.workspace,profile_id='fixture-profile')


def test_wrong_event_loop_cannot_operate_a_creator(env):
    async def setup():
        owner = install(env)
        await owner.open(timeout_seconds=1)
        await owner.close(timeout_seconds=1)
        return owner
    owner = asyncio.run(setup())
    async def different():
        with pytest.raises(ContractError): await owner.force_stop_creator(timeout_seconds=1)
    asyncio.run(different())


@pytest.mark.parametrize('fd,partial',[(0,False),(1,False),(1,True)])
def test_early_closed_input_or_incomplete_output_requests_stop(env,fd,partial):
    async def run():
        owner = install(env)
        await owner.open(timeout_seconds=1)
        transport = env.transports[0]
        if partial: transport.protocol.pipe_data_received(1,b'{')
        transport.protocol.pipe_connection_lost(fd,None)
        result = await owner.close(timeout_seconds=1)
        assert result['stop_requested'] and not result['succeeded']
        assert result['transport_error'] in ('stdin-closed','incomplete-output','pipe-read-failed')
        assert transport.kill_calls==0
    asyncio.run(run())


def test_already_closed_empty_stderr_does_not_block_a_valid_start(env):
    async def run():
        owner = install(env)
        await owner.open(timeout_seconds=1)
        env.transports[0].protocol.pipe_connection_lost(2,None)
        assert owner.snapshot()['ready_for_start']
        await owner.start(timeout_seconds=1)
        assert (await owner.close(timeout_seconds=1))['succeeded']
    asyncio.run(run())


def test_cancellation_during_close_retains_owner_for_retry(env):
    async def run():
        env.configure = lambda t:setattr(t,'stall_stop',True)
        owner = install(env)
        await owner.open(timeout_seconds=1)
        await owner.start(timeout_seconds=1)
        closing = asyncio.create_task(owner.close(timeout_seconds=1))
        await asyncio.sleep(0)
        closing.cancel()
        with pytest.raises(asyncio.CancelledError): await closing
        assert not owner.snapshot()['creator_exit_observed']
        env.transports[0].finish()
        result = await owner.close(timeout_seconds=1)
        assert result['connection_closed'] and result['channel']['completion_verified']
        assert result['transport_error']=='caller-cancelled' and not result['succeeded']
    asyncio.run(run())


@pytest.mark.parametrize('buffer_type',[bytearray,memoryview])
def test_proactor_bytes_like_buffers_are_copied_in_bounded_chunks(env,buffer_type):
    async def run():
        owner = install(env)
        await owner.open(timeout_seconds=1)
        t = env.transports[0]
        original = t.protocol.pipe_data_received
        t.protocol.pipe_data_received = lambda fd,data:original(fd,buffer_type(data))
        await owner.start(timeout_seconds=1)
        result = await owner.close(timeout_seconds=1)
        assert result['succeeded'] and result['channel']['stdout']['observed_bytes']>0
    asyncio.run(run())


def test_unknown_backend_buffer_cannot_claim_an_empty_complete_stream(env):
    async def run():
        owner = install(env)
        await owner.open(timeout_seconds=1)
        env.transports[0].protocol.pipe_data_received(1,object())
        result = await owner.close(timeout_seconds=1)
        assert not result['channel']['stdout']['prefix_is_complete_stream']
        assert result['transport_error']=='invalid-pipe-data' and not result['succeeded']
    asyncio.run(run())


def test_released_backend_buffer_requests_stop_without_callback_crash(env):
    async def run():
        owner = install(env)
        await owner.open(timeout_seconds=1)
        transport = env.transports[0]
        released = memoryview(PRIVATE.encode())
        released.release()

        transport.protocol.pipe_data_received(1, released)
        result = await owner.close(timeout_seconds=1)
        assert result['transport_error'] == 'invalid-pipe-data'
        assert result['channel']['stdout']['read_error']
        assert result['stop_requested'] and not result['succeeded']
        assert transport.kill_calls == 0
        check_private(result)

    asyncio.run(run())


def test_closed_channel_during_pending_setup_is_not_transport_success(env):
    async def run():
        env.after_connect = asyncio.Event()
        owner = install(env)
        opening = asyncio.create_task(owner.open(timeout_seconds=1))
        while not env.transports: await asyncio.sleep(0)
        env.transports[0].finish()
        result = owner.snapshot()
        assert result['creation_pending'] and result['channel']['succeeded']
        assert not result['succeeded']
        env.after_connect.set()
        await opening
        await owner.close(timeout_seconds=1)
    asyncio.run(run())


def test_transport_schema_matches_live_states_and_rejects_overclaims(env):
    import jsonschema
    schema = json.loads((Path(__file__).resolve().parents[1]/'schemas/agent-process-v1.schema.json').read_text())
    jsonschema.Draft202012Validator.check_schema(schema)
    validator = jsonschema.Draft202012Validator(schema)
    async def run():
        owner = install(env)
        validator.validate(owner.snapshot())
        validator.validate(await owner.open(timeout_seconds=1))
        validator.validate(await owner.start(timeout_seconds=1))
        result = await owner.close(timeout_seconds=1)
        validator.validate(result)
        for change in ({'force_stop_requested':True},{'creation_pending':True},
                       {'connection_closed':False},{'creator_exit_observed':False},
                       {'inspector_url':PRIVATE}):
            with pytest.raises(jsonschema.ValidationError): validator.validate({**result,**change})
    asyncio.run(run())
