"""Protocol failure tests use fake creator objects; no browser is launched."""
import io
import json
from functools import lru_cache
from pathlib import Path
from types import SimpleNamespace

import pytest

from browser_core import agent_research as agent

PRIVATE = 'fixture-private-value-never-published'


@lru_cache
def event_validator():
    import jsonschema
    schema = json.loads((Path(__file__).resolve().parents[1]/'schemas/agent-research-v1.schema.json').read_text())
    jsonschema.Draft202012Validator.check_schema(schema)
    return jsonschema.Draft202012Validator(schema)


def command(action):
    return (json.dumps({'schema':agent.COMMAND_SCHEMA, 'action':action}) + '\n').encode()


class Run:
    def __init__(self, workspace):
        self.session = {'run_id':'fixture-owned-run'}
        self.session_path = workspace / 'sessions' / 'fixture-owned-run.json'
        self.created_profile = True
        self.stop_receipt = {'run_id':'fixture-owned-run', 'state':'stopped',
                             'running':False, 'identity_protected':True,
                             'shutdown_mode':'graceful'}
        self.close_count = 0
        self.close_error = None

    @property
    def url(self):
        raise AssertionError('private inspector URL must not be read')

    def close(self):
        self.close_count += 1
        if self.close_error is not None:
            raise self.close_error


@pytest.fixture
def env(tmp_path, monkeypatch):
    workspace = tmp_path / 'work'
    run = Run(workspace)
    launches = []
    def start(*args, **kwargs):
        launches.append((args, kwargs))
        return run
    monkeypatch.setattr(agent, 'start_research', start)
    return SimpleNamespace(workspace=workspace, run=run, launches=launches,
                           executable=tmp_path/'browser.exe', root=tmp_path/'package')


def invoke(env, body=b'', output=None, input_stream=None, **overrides):
    output = io.StringIO() if output is None else output
    arguments = dict(workspace=env.workspace, repository_root=env.root,
        profile_id='fixture-profile', executable=env.executable,
        input_stream=io.BytesIO(body) if input_stream is None else input_stream,
        output_stream=output)
    arguments.update(overrides)
    code = agent.run_agent_research(**arguments)
    text = output.getvalue()
    assert PRIVATE not in text
    events = [json.loads(line) for line in text.splitlines()]
    assert all(event['schema'] == agent.EVENT_SCHEMA for event in events)
    for event in events:
        event_validator().validate(event)
    assert len(events) <= 3
    assert all(len(line.encode()) + 1 <= agent.MAX_EVENT_BYTES for line in text.splitlines())
    return code, events


def test_start_stop_uses_exact_creator_and_existing_verified_launcher(env):
    result, events = invoke(env, command('start')+command('stop'), headless=True,
        persona_id='fixture-persona', recording_limit_mib=64, recording_parts=3,
        inspect_hash_inputs=True)
    assert result == 0
    assert [item['event'] for item in events] == ['awaiting-start','ready','closed']
    assert events[1] == {'schema':agent.EVENT_SCHEMA, 'event':'ready',
        'run_id':'fixture-owned-run', 'session_file':str(env.run.session_path),
        'profile_id':'fixture-profile','created_profile':True,'profile_retained_on_exit':True}
    assert events[2]['cleanup_verified'] is True
    assert events[2]['shutdown'] == env.run.stop_receipt
    assert events[2]['code'] == 'stopped'
    assert env.run.close_count == 1
    assert env.launches == [((env.workspace,env.root,'fixture-profile'), {
        'persona_id':'fixture-persona','headless':True,'executable':env.executable,
        'recording_limit_mib':64,'recording_parts':3,'inspect_hash_inputs':True})]


def test_agent_refuses_noncanonical_session_path_spelling(env):
    env.run.session_path = (
        Path(str(env.run.session_path.parent).upper()) / env.run.session_path.name
    )
    result, events = invoke(env, command('start') + command('stop'))
    assert result == 2
    assert [event['event'] for event in events] == ['awaiting-start', 'closed']
    assert events[-1]['code'] == 'invalid-session-handoff'
    assert env.run.close_count == 1


def test_metadata_only_agent_keeps_ready_closed_and_extra_argument_ownership(env):
    result,events=invoke(env,command('start')+command('stop'),metadata_only=True,
                         extra_args=('--headless',))
    assert result==0 and events[1]['run_id']==events[2]['shutdown']['run_id']
    assert events[2]['cleanup_verified'] and env.run.close_count==1
    assert env.launches[0][1]['metadata_only'] is True
    assert env.launches[0][1]['extra_args']==('--headless',)


def test_metadata_only_and_private_inputs_reject_before_start(env):
    result,events=invoke(env,command('start'),metadata_only=True,inspect_hash_inputs=True)
    assert result==2 and not env.launches
    assert events[-1]['code']=='invalid-options'


@pytest.mark.parametrize('body,code', [(b'','input-closed'),(command('stop'),'cancelled-before-start')])
def test_no_browser_before_start(env, body, code):
    result, events = invoke(env, body)
    assert result == 0 and events[-1]['code'] == code
    assert events[-1]['launch_attempted'] is False
    assert events[-1]['session_received'] is False
    assert events[-1]['cleanup_verified'] is None
    assert not env.launches and env.run.close_count == 0


def test_awaiting_start_is_flushed_before_read_or_launch(env):
    class Pipe(io.StringIO):
        flushed = False
        def flush(self): self.flushed = True
    output = Pipe()
    class Input(io.BytesIO):
        def readline(self, maximum):
            assert output.flushed and not env.launches
            assert maximum == agent.MAX_COMMAND_BYTES+1
            return b''
    invoke(env, output=output, input_stream=Input())


def test_eof_after_start_closes_exact_creator(env):
    result, events = invoke(env, command('start'))
    assert result == 0 and events[-1]['code'] == 'input-closed'
    assert events[-1]['cleanup_verified'] is True and env.run.close_count == 1


INVALID = [b'\n',b'{}\n',b'[]\n',b'null\n',b'\xff\n',b'{',command('start')[:-1],
    command('start').replace(b'agent-command/1',b'agent-command/2'),
    command('start').replace(b'"start"',b'"'+PRIVATE.encode()+b'"'),
    b'{"schema":"browser-core.agent-command/1","action":"start","action":"stop"}\n',
    b'{"schema":"browser-core.agent-command/1","action":NaN}\n',
    b'{"schema":"browser-core.agent-command/1","action":[]}\n',
    b'{"schema":"browser-core.agent-command/1","action":"stop","pid":777}\n',
    b'{"schema":"browser-core.agent-command/1","action":"stop","session_file":"'+PRIVATE.encode()+b'"}\n']


@pytest.mark.parametrize('body', INVALID)
@pytest.mark.parametrize('started', [False,True])
def test_invalid_command_cannot_choose_a_cleanup_target(env, body, started, capsys):
    result, events = invoke(env, (command('start') if started else b'')+body)
    assert result == 2 and events[-1]['code'] == 'invalid-command'
    assert env.run.close_count == int(started)
    assert events[-1]['cleanup_verified'] is (True if started else None)
    assert capsys.readouterr().err == ''


@pytest.mark.parametrize('started', [False,True])
def test_oversized_command_is_rejected_at_read_boundary(env, started):
    result, events = invoke(env, (command('start') if started else b'')+b'x'*4097+b'\n')
    assert result == 2 and events[-1]['code'] == 'command-too-large'
    assert env.run.close_count == int(started)


def test_duplicate_start_rejected_without_second_launch(env):
    result, events = invoke(env, command('start')+command('start'))
    assert result == 2 and events[-1]['code'] == 'invalid-command'
    assert len(env.launches) == 1 and env.run.close_count == 1


@pytest.mark.parametrize('overrides', [
    {'profile_id':None},{'profile_id':'../foreign'},{'workspace':None},
    {'workspace':Path('relative')},{'executable':None},
    {'executable':Path('relative.exe')},{'exit_with_browser':True}])
def test_explicit_options_are_required_before_protocol_or_launch(env, overrides):
    result, events = invoke(env, command('start'), **overrides)
    assert result == 2 and len(events) == 1 and events[0]['code'] == 'invalid-options'
    assert not env.launches


@pytest.mark.parametrize('error', [RuntimeError(PRIVATE),KeyboardInterrupt()])
def test_launch_without_returned_owner_never_claims_cleanup(env, monkeypatch, error):
    def fail(*args, **kwargs): raise error
    monkeypatch.setattr(agent, 'start_research', fail)
    result, events = invoke(env, command('start'))
    assert result == (130 if isinstance(error,KeyboardInterrupt) else 2)
    assert events[-1]['launch_attempted'] is True
    assert events[-1]['session_received'] is False
    assert events[-1]['cleanup_verified'] is None
    assert env.run.close_count == 0


def test_unexpected_empty_factory_return_is_an_unverified_internal_error(env,monkeypatch):
    monkeypatch.setattr(agent,'start_research',lambda *args,**kwargs:None)
    result, events = invoke(env,command('start'))
    assert result == 2 and events[-1]['code'] == 'internal-error'
    assert events[-1]['launch_attempted'] is True
    assert events[-1]['session_received'] is False
    assert events[-1]['cleanup_verified'] is None


@pytest.mark.parametrize('mutate', [
    lambda run: setattr(run,'session',{'run_id':'../foreign'}),
    lambda run: setattr(run,'session_path',run.session_path.parent.parent/'foreign.json'),
    lambda run: setattr(run,'session_path',Path('fixture-owned-run.json')),
    lambda run: setattr(run,'created_profile',1),
    lambda run: setattr(run,'session_path',run.session_path.parent/('x'*4097+'.json'))])
def test_invalid_returned_handoff_still_closes_creator_but_cannot_verify_receipt(env, mutate):
    mutate(env.run)
    result, events = invoke(env, command('start'))
    assert result == 2 and events[-1]['code'] == 'invalid-session-handoff'
    assert env.run.close_count == 1
    assert events[-1]['cleanup_verified'] is False
    assert events[-1]['cleanup_error'] == 'cleanup-failed'


@pytest.mark.parametrize('change', [
    {'run_id':'foreign-run'},{'running':True},{'running':0},{'state':'unknown'},
    {'identity_protected':False},{'identity_protected':1},
    {'shutdown_mode':'unknown'},{'private':PRIVATE}])
def test_cleanup_needs_exact_identity_protected_stopped_receipt(env, change):
    env.run.stop_receipt.update(change)
    result, events = invoke(env, command('start')+command('stop'))
    assert result == 2 and events[-1]['cleanup_verified'] is False
    assert events[-1]['shutdown'] is None and env.run.close_count == 1


@pytest.mark.parametrize('error,code', [(RuntimeError(PRIVATE),2),(KeyboardInterrupt(),130)])
def test_cleanup_failure_is_independent_from_requested_stop(env, error, code):
    env.run.close_error = error
    result, events = invoke(env, command('start')+command('stop'))
    assert result == code and events[-1]['code'] == 'stopped'
    assert events[-1]['status'] != 'ok' and events[-1]['cleanup_verified'] is False
    assert events[-1]['shutdown'] is None


@pytest.mark.parametrize('error', [OSError(PRIVATE),KeyboardInterrupt()])
def test_input_failure_after_ready_attempts_cleanup(env, error):
    class Input:
        calls = 0
        def readline(self, maximum):
            self.calls += 1
            if self.calls == 1: return command('start')
            raise error
    result, events = invoke(env, input_stream=Input())
    assert result == (130 if isinstance(error,KeyboardInterrupt) else 2)
    assert events[-1]['cleanup_verified'] is True and env.run.close_count == 1


@pytest.mark.parametrize('mode', ['write','short','flush'])
@pytest.mark.parametrize('failure_event', ['awaiting-start','ready','closed'])
def test_output_failure_cleans_up_without_printing_exception(env, mode, failure_event):
    class Output(io.StringIO):
        failing = False
        def write(self, value):
            self.failing = json.loads(value)['event'] == failure_event
            if self.failing and mode == 'write': raise OSError(PRIVATE)
            if self.failing and mode == 'short': return 0
            return super().write(value)
        def flush(self):
            if self.failing and mode == 'flush': raise OSError(PRIVATE)
    result, events = invoke(env, command('start')+command('stop'), output=Output())
    assert result == 2
    assert env.run.close_count == (0 if failure_event=='awaiting-start' else 1)


def test_cli_selects_agent_channel_without_picker_or_inspector_open(env, monkeypatch):
    from browser_core import cli
    import webbrowser
    monkeypatch.setattr(cli.sys,'stdin',SimpleNamespace(buffer=io.BytesIO(command('start')+command('stop'))))
    output = io.StringIO()
    monkeypatch.setattr(cli.sys,'stdout',output)
    def forbidden(*args, **kwargs): raise AssertionError('must not open a UI')
    monkeypatch.setattr(webbrowser,'open',forbidden)
    args = cli.build_parser().parse_args(['research','fixture-profile','--agent-control',
        '--workspace',str(env.workspace),'--executable',str(env.executable),'--headless'])
    assert args.func(args) == 0
    events = [json.loads(line) for line in output.getvalue().splitlines()]
    assert events[-1]['cleanup_verified'] is True
    assert env.run.close_count == 1 and len(env.launches) == 1
