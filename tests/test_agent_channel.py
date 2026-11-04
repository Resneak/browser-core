"""Private output stays bounded and incomplete transcripts cannot claim success."""
from concurrent.futures import ThreadPoolExecutor
import copy
import hashlib
import io
import json
from functools import lru_cache
from pathlib import Path
from types import SimpleNamespace

import pytest

from browser_core import agent_channel as channel
from browser_core import agent_research as producer
from browser_core.errors import ContractError

PRIVATE = b'fixture-private-stderr-and-invalid-output'


@lru_cache
def receipt_validator():
    import jsonschema
    contract = json.loads((Path(__file__).resolve().parents[1]/'schemas/agent-channel-receipt-v1.schema.json').read_text())
    jsonschema.Draft202012Validator.check_schema(contract)
    return jsonschema.Draft202012Validator(contract)


def wire(events):
    return b''.join((json.dumps(event)+'\n').encode() for event in events)


@pytest.fixture
def env(tmp_path):
    workspace = tmp_path/'workspace'
    schema = producer.EVENT_SCHEMA
    ready = {'schema':schema,'event':'ready','run_id':'fixture-owned',
        'session_file':str(workspace/'sessions/fixture-owned.json'),
        'profile_id':'fixture-profile','created_profile':True,'profile_retained_on_exit':True}
    closed = {'schema':schema,'event':'closed','status':'ok','code':'stopped',
        'launch_attempted':True,'session_received':True,'cleanup_verified':True,
        'cleanup_error':None,'shutdown':{'run_id':'fixture-owned','state':'stopped',
            'running':False,'identity_protected':True,'shutdown_mode':'graceful'}}
    events = [{'schema':schema,'event':'awaiting-start'},ready,closed]
    return SimpleNamespace(workspace=workspace, events=events,
        create=lambda:channel.AgentChannelCollector(workspace=workspace,profile_id='fixture-profile'))


def feed(collector, body, stream='stdout', size=4096):
    for offset in range(0,len(body),size):
        collector.feed(stream,body[offset:offset+size])


def complete(collector, exit_code=0):
    collector.finish_stream('stdout')
    collector.finish_stream('stderr')
    receipt = collector.receipt(exit_code=exit_code)
    receipt_validator().validate(receipt)
    return receipt


def test_every_split_of_valid_transcript_preserves_result(env):
    body = wire(env.events)
    expected = None
    for position in range(len(body)+1):
        collector = env.create()
        feed(collector,body[:position])
        feed(collector,body[position:])
        result = complete(collector)
        assert result['succeeded'] and result['completion_verified']
        assert result['stdout']['prefix_sha256'] == hashlib.sha256(body).hexdigest()
        assert result['stdout']['prefix_is_complete_stream']
        if expected is None: expected = result
        assert result == expected


@pytest.mark.parametrize('size', [1,2,3,17,4096])
def test_split_crlf_lines_are_supported(env,size):
    collector = env.create()
    feed(collector,wire(env.events).replace(b'\n',b'\r\n'),size=size)
    assert complete(collector)['succeeded']


def test_zero_exit_and_shutdown_receipt_do_not_replace_eof(env):
    collector = env.create()
    feed(collector,wire(env.events))
    assert collector.receipt(exit_code=0)['closed']['cleanup_verified'] is True
    assert not collector.receipt(exit_code=0)['completion_verified']
    collector.finish_stream('stdout')
    assert not collector.receipt(exit_code=0)['completion_verified']
    collector.finish_stream('stderr')
    assert not collector.receipt()['completion_verified']
    assert collector.receipt(exit_code=0)['completion_verified']


def test_ready_snapshot_is_copied_and_never_a_cleanup_capability(env):
    collector = env.create()
    feed(collector,wire(env.events[:2]))
    receipt = collector.receipt()
    assert receipt['ready']['run_id'] == 'fixture-owned'
    receipt['ready']['run_id'] = 'foreign'
    assert collector.receipt()['ready']['run_id'] == 'fixture-owned'
    assert not hasattr(collector,'stop') and not hasattr(collector,'kill')


def test_ready_locator_requires_the_canonical_owned_spelling(env):
    env.events[1]['session_file'] = env.events[1]['session_file'].upper()
    collector = env.create()
    feed(collector, wire(env.events))
    receipt = complete(collector)
    assert receipt['protocol_error'] == 'invalid-event'
    assert receipt['ready'] is None


@pytest.mark.parametrize('mutation', [
    lambda events: events[1].update(session_file='C:/foreign/fixture-owned.json'),
    lambda events: events[1].update(profile_id='foreign'),
    lambda events: events[1].update(run_id='../foreign'),
    lambda events: events[1].update(created_profile=1),
    lambda events: events[1].update(profile_retained_on_exit=False),
    lambda events: events[1].update(inspector_url=PRIVATE.decode()),
    lambda events: events[2]['shutdown'].update(run_id='foreign'),
    lambda events: events[2]['shutdown'].update(identity_protected=False),
    lambda events: events[2]['shutdown'].update(running=0),
    lambda events: events[2]['shutdown'].update(private=PRIVATE.decode()),
    lambda events: events[2].update(session_received=False),
    lambda events: events[2].update(launch_attempted=False),
    lambda events: events[2].update(cleanup_verified=1),
    lambda events: events[2].update(cleanup_error='cleanup-failed'),
    lambda events: events[2].update(status='error'),
    lambda events: events[2].update(code=PRIVATE.decode())])
def test_invalid_or_foreign_events_are_not_returned(env,mutation):
    mutation(env.events)
    collector = env.create()
    feed(collector,wire(env.events))
    result = complete(collector)
    assert not result['succeeded'] and result['protocol_error'] == 'invalid-event'
    assert PRIVATE.decode() not in json.dumps(result)


@pytest.mark.parametrize('selection', [(1,2),(0,0,1,2),(0,2,1),(0,1,1,2),(0,1,2,2),(0,2),(2,)])
def test_missing_repeated_and_out_of_order_events_fail(env,selection):
    collector = env.create()
    feed(collector,wire([env.events[index] for index in selection]))
    assert not complete(collector)['completion_verified']


@pytest.mark.parametrize('body', [b'\xff\n',b'{}\n',b'[]\n',b'null\n',b'\n',PRIVATE+b'\n',
    b'{"schema":"browser-core.agent-research/1","event":"awaiting-start","event":"closed"}\n',
    b'{"schema":"browser-core.agent-research/1","event":NaN}\n'])
def test_malformed_output_is_private(env,body):
    collector = env.create()
    feed(collector,body)
    result = complete(collector)
    assert not result['completion_verified'] and result['protocol_error'] == 'invalid-event'
    assert PRIVATE.decode() not in json.dumps(result)


def test_partial_final_line_never_counts_as_a_terminal_event(env):
    collector = env.create()
    feed(collector,wire(env.events)[:-1])
    result = complete(collector)
    assert result['protocol_error'] == 'partial-event' and result['closed'] is None


@pytest.mark.parametrize('stream,maximum', [('stdout',channel.MAX_STDOUT_BYTES),('stderr',channel.MAX_STDERR_BYTES)])
def test_excess_output_drains_without_retaining_bodies_or_claiming_full_digest(env,stream,maximum):
    collector = env.create()
    body = (PRIVATE*30000)[:maximum*4+7]
    feed(collector,body,stream)
    result = complete(collector)
    observed = result[stream]
    assert observed['observed_bytes'] == len(body) and observed['prefix_bytes'] == maximum
    assert observed['prefix_sha256'] == hashlib.sha256(body[:maximum]).hexdigest()
    assert observed['overflow'] and not observed['prefix_is_complete_stream']
    assert not result['completion_verified'] and PRIVATE.decode() not in json.dumps(result)


def test_large_single_event_is_rejected_even_below_aggregate_budget(env):
    collector = env.create()
    feed(collector,b' '*producer.MAX_EVENT_BYTES)
    assert complete(collector)['protocol_error'] == 'event-too-large'


def test_stderr_is_counted_and_digested_but_never_printed_or_silently_ignored(env):
    collector = env.create()
    feed(collector,wire(env.events))
    feed(collector,PRIVATE,'stderr')
    result = complete(collector)
    assert result['completion_verified'] and not result['succeeded']
    assert result['stderr']['observed_bytes'] == len(PRIVATE)
    assert PRIVATE.decode() not in json.dumps(result)


@pytest.mark.parametrize('stream', ['stdout','stderr'])
def test_read_error_invalidates_complete_success(env,stream):
    collector = env.create()
    feed(collector,wire(env.events))
    collector.fail_stream(stream)
    result = complete(collector)
    assert not result['completion_verified']
    assert not result[stream]['prefix_is_complete_stream']


@pytest.mark.parametrize('chunk', [b'',b'x'*4097,'text',None,bytearray(b'x')])
def test_transport_must_feed_bounded_bytes(env,chunk):
    collector = env.create()
    with pytest.raises(ContractError,match='chunk is invalid'):
        collector.feed('stdout',chunk)
    assert collector.receipt()['stdout']['read_error']


def test_data_after_eof_invalidates_previous_success(env):
    collector = env.create()
    feed(collector,wire(env.events))
    assert complete(collector)['succeeded']
    with pytest.raises(ContractError): collector.feed('stdout',b'x')
    assert not collector.receipt(exit_code=0)['succeeded']


@pytest.mark.parametrize('exit_code', [2,130,1,-1,4294967295])
def test_exit_code_must_match_reported_status(env,exit_code):
    collector = env.create()
    feed(collector,wire(env.events))
    result = complete(collector,exit_code)
    assert not result['completion_verified'] and result['protocol_error']=='exit-status-mismatch'


@pytest.mark.parametrize('exit_code', [True,'0',2**32,-2**31-1])
def test_invalid_exit_values_rejected(env,exit_code):
    with pytest.raises(ContractError): env.create().receipt(exit_code=exit_code)


def test_concurrent_streams_keep_independent_digests_and_complete_snapshot(env):
    collector = env.create()
    body = wire(env.events)
    stderr = PRIVATE*200
    def drain(name,data):
        feed(collector,data,name,size=7)
        collector.finish_stream(name)
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(drain,'stdout',body),pool.submit(drain,'stderr',stderr)]
        for future in futures: future.result(timeout=5)
    result = collector.receipt(exit_code=0)
    assert result['completion_verified'] and not result['succeeded']
    assert result['stdout']['prefix_sha256']==hashlib.sha256(body).hexdigest()
    assert result['stderr']['prefix_sha256']==hashlib.sha256(stderr).hexdigest()


@pytest.mark.parametrize('action,error,exit_code', [
    ('stop',None,0),('start',None,0),('start',RuntimeError('private'),2),
    ('start',KeyboardInterrupt(),130),('malformed',None,2)])
def test_real_producer_and_collector_agree_with_only_fake_browser_owner(env,monkeypatch,action,error,exit_code):
    shutdown = copy.deepcopy(env.events[2]['shutdown'])
    class Run:
        session = {'run_id':'fixture-owned'}
        session_path = env.workspace/'sessions/fixture-owned.json'
        created_profile = True
        stop_receipt = shutdown
        def close(self):
            if error: raise error
    monkeypatch.setattr(producer,'start_research',lambda *args,**kwargs:Run())
    command = (json.dumps({'schema':producer.COMMAND_SCHEMA,'action':action})+'\n').encode()
    output = io.StringIO()
    code = producer.run_agent_research(env.workspace,env.workspace/'package','fixture-profile',
        executable=env.workspace/'browser.exe',input_stream=io.BytesIO(command),output_stream=output)
    assert code == exit_code
    collector = env.create()
    feed(collector,output.getvalue().encode(),size=1)
    result = complete(collector,code)
    assert result['completion_verified'] and result['succeeded'] is (code==0)


def test_command_schema_accepts_only_start_stop_without_a_target():
    import jsonschema
    schema = json.loads((Path(__file__).resolve().parents[1]/'schemas/agent-command-v1.schema.json').read_text())
    jsonschema.Draft202012Validator.check_schema(schema)
    validator = jsonschema.Draft202012Validator(schema)
    for action in ('start','stop'):
        value = {'schema':producer.COMMAND_SCHEMA,'action':action}
        validator.validate(value)
        value['pid'] = 777
        with pytest.raises(jsonschema.ValidationError): validator.validate(value)


def test_schema_rejects_false_cleanup_and_private_event_fields(env):
    import jsonschema
    schema = json.loads((Path(__file__).resolve().parents[1]/'schemas/agent-research-v1.schema.json').read_text())
    validator = jsonschema.Draft202012Validator(schema)
    for event in env.events: validator.validate(event)
    for change in ({'cleanup_verified':1},{'cleanup_error':'cleanup-failed'},
                   {'shutdown':None},{'session_received':False},{'status':'error'}):
        document = {**env.events[-1],**change}
        with pytest.raises(jsonschema.ValidationError): validator.validate(document)
    with pytest.raises(jsonschema.ValidationError):
        validator.validate({**env.events[1],'inspector_url':PRIVATE.decode()})
