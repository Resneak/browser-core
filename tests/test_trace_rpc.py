import csv
import io
from pathlib import Path
import queue
import sys
import threading
import time

import pytest

from browser_core.contracts import ContractError
import browser_core.trace_rpc as rpc


def batch(kinds, integers=(), strings=b'', last=True):
    return (rpc._field(1,b''.join(rpc._varint(x) for x in kinds))
            +rpc._field(2,b''.join(rpc._varint(x) for x in integers))
            +rpc._field(5,strings)+rpc._field(6,int(last)))


def result(columns, batches):
    return rpc._fields(rpc._field(203,b''.join(rpc._field(1,c.encode()) for c in columns)
                                         +b''.join(rpc._field(3,b) for b in batches)))


def test_cells_split_across_batches_preserve_signed_ids_and_quoted_strings():
    replies=[result(['id','value'],[batch([2],[2**64-1],last=False)]),
             result([],[batch([4],strings=b'quotes, "x"\r\n\x1a\0')])]
    body=rpc.query_csv(replies,max_rows=1)
    assert list(csv.DictReader(io.StringIO(body.decode())))==[{'id':'-1','value':'quotes, "x"\r\n\x1a'}]


def test_empty_result_retains_columns_and_is_not_a_missing_reply():
    body=rpc.query_csv([result(['id','value'],[batch([])])],max_rows=1)
    assert body==b'id,value\n'


def test_history_lookahead_admits_exactly_one_extra_row():
    client=object.__new__(rpc.TraceProcessorPipe)
    replies=[result(['id'],[batch([2]*1001,range(1001))])]
    client._call=lambda *args:replies
    body=client.query('SELECT id',max_rows=1001)
    assert len(list(csv.DictReader(io.StringIO(body.decode()))))==1001
    with pytest.raises(ContractError,match='limits'):
        client.query('SELECT id',max_rows=1002)


def test_query_rejects_invalid_unicode_before_decoder_request():
    client = object.__new__(rpc.TraceProcessorPipe)
    client._call = lambda *_args: pytest.fail('invalid query reached decoder')
    with pytest.raises(ContractError, match='limits'):
        client.query('SELECT \ud800')


def test_decoder_rejects_short_request_write_before_read():
    class ShortStdin:
        def write(self, body):
            return len(body) - 1

        def flush(self):
            pytest.fail('short request was flushed')

    client = object.__new__(rpc.TraceProcessorPipe)
    client.process = type('Process', (), {'stdin': ShortStdin()})()
    with pytest.raises(ValueError, match='request write'):
        client._exchange(b'payload', 1)


@pytest.mark.parametrize('replies',[
    [result(['id','id'],[batch([])])],
    [result(['id'],[batch([2],[])])],
    [result(['id'],[batch([], [42])])],
    [result(['value'],[batch([4],strings=b'unterminated')])],
    [result(['id'],[batch([2],[42],last=False)])],
    [result(['id'],[batch([2],[42]),batch([2],[43])])],
    [result(['id'],[batch([2,2],[42,43])])],
    [result(['id','value'],[batch([2],[42])])],
])
def test_malformed_or_excess_results_do_not_become_partial_success(replies):
    with pytest.raises((ValueError,StopIteration)):
        rpc.query_csv(replies,max_rows=1)


@pytest.mark.parametrize('body',[b'\x00',b'\x0a\x05a',b'\x08'+b'\xff'*10,b'\x0b'])
def test_malformed_protobuf_is_bounded(body):
    with pytest.raises(ValueError):rpc._fields(body)


def fake_process(monkeypatch,tmp_path,mode):
    status=rpc._field(1,rpc._field(1,0)+rpc._field(3,10)+rpc._field(210,rpc._field(3,14)))
    script=tmp_path/'fake_decoder.py'
    body="import os,sys,time\n"
    oversized=(bytes([10])+rpc._varint(rpc.MAX_REPLY_BYTES+1)).hex()
    if mode=='oversize':body+=f"os.write(1,bytes.fromhex('{oversized}'))\ntime.sleep(5)\n"
    elif mode=='truncated':body+="os.write(1,b'\\x0a\\x05x')\n"
    else:body+=f"os.write(1,bytes.fromhex('{status.hex()}'))\ntime.sleep(5)\n"
    script.write_text(body,encoding='utf-8')
    original=rpc.subprocess.Popen;processes=[]
    def start(command,**kwargs):
        assert command[1:]==['server','stdio']
        process=original([sys.executable,'-u',str(script)],**kwargs)
        processes.append(process);return process
    monkeypatch.setattr(rpc.subprocess,'Popen',start)
    return processes


@pytest.mark.parametrize('mode',['oversize','truncated','silent'])
def test_failed_or_timed_out_decoder_is_reaped(monkeypatch,tmp_path,mode):
    processes=fake_process(monkeypatch,tmp_path,mode)
    started=time.monotonic()
    if mode=='silent':
        # The short deadline exercises a stalled request, after the child
        # interpreter has actually started and completed its handshake.
        client=rpc.TraceProcessorPipe(Path('owned-decoder'),timeout_seconds=5)
        client.timeout=.2
        started=time.monotonic()
        with pytest.raises(ContractError,match='deadline'):
            client.query('SELECT 1')
        assert not client._thread.is_alive()
        with pytest.raises(ContractError,match='closed'):client.query('SELECT 1')
    else:
        with pytest.raises(ContractError,match='unavailable'):
            rpc.TraceProcessorPipe(Path('owned-decoder'),timeout_seconds=.2)
    assert time.monotonic()-started<3
    assert len(processes)==1 and processes[0].poll() is not None


def test_worker_start_failure_reaps_decoder_process(monkeypatch, tmp_path):
    processes = fake_process(monkeypatch, tmp_path, 'silent')

    class RefusingThread:
        def __init__(self, **_kwargs):
            pass

        def start(self):
            raise RuntimeError('synthetic worker start failure')

        def is_alive(self):
            return False

        def join(self, **_kwargs):
            pytest.fail('unstarted worker was joined')

    monkeypatch.setattr(rpc, 'Thread', RefusingThread)
    with pytest.raises(ContractError, match='worker could not start'):
        rpc.TraceProcessorPipe(Path('owned-decoder'), timeout_seconds=.2)
    assert len(processes) == 1 and processes[0].poll() is not None


def test_worker_construction_failure_does_not_start_decoder(monkeypatch, tmp_path):
    processes = fake_process(monkeypatch, tmp_path, 'silent')

    def refusing_thread(**_kwargs):
        raise RuntimeError('synthetic worker construction failure')

    monkeypatch.setattr(rpc, 'Thread', refusing_thread)
    with pytest.raises(ContractError, match='worker could not start'):
        rpc.TraceProcessorPipe(Path('owned-decoder'), timeout_seconds=.2)
    assert processes == []


def test_malformed_decoder_executable_error_is_redacted(monkeypatch):
    def malformed_path(*_args, **_kwargs):
        raise ValueError('private decoder executable path')

    monkeypatch.setattr(rpc.subprocess, 'Popen', malformed_path)
    with pytest.raises(ContractError, match='local decoder could not start') as raised:
        rpc.TraceProcessorPipe(Path('owned-decoder'))
    assert 'private decoder executable path' not in str(raised.value)


def test_append_waits_for_concurrent_finalization_decision():
    client = object.__new__(rpc.TraceProcessorPipe)
    client._final = False
    client._final_lock = threading.Lock()
    final_entered = threading.Event()
    release_final = threading.Event()
    append_started = threading.Event()
    append_done = threading.Event()
    outcomes = {}

    def call(method, _argument=b''):
        if method == 2:
            final_entered.set()
            assert release_final.wait(2)
            return [{212: [(2, b'')]}]
        if method == 1:
            return [{201: [(2, b'')]}]
        raise AssertionError('unexpected decoder method')

    client._call = call

    def finalize():
        try:
            client.finalize()
            outcomes['finalize'] = 'ok'
        except Exception as error:
            outcomes['finalize'] = error

    def append():
        append_started.set()
        try:
            client.append(b'x')
            outcomes['append'] = 'ok'
        except Exception as error:
            outcomes['append'] = error
        finally:
            append_done.set()

    final_thread = threading.Thread(target=finalize, daemon=True)
    append_thread = threading.Thread(target=append, daemon=True)
    final_thread.start()
    assert final_entered.wait(2)
    append_thread.start()
    assert append_started.wait(2)
    try:
        assert not append_done.wait(0.1)
    finally:
        release_final.set()
        final_thread.join(timeout=2)
        append_thread.join(timeout=2)
    assert not final_thread.is_alive() and not append_thread.is_alive()
    assert outcomes['finalize'] == 'ok'
    assert isinstance(outcomes['append'], ContractError)
    assert 'finalized' in str(outcomes['append'])


def test_close_reaps_process_that_exits_between_poll_and_kill():
    class ExitingProcess:
        def __init__(self):
            self.stdin = io.BytesIO()
            self.stdout = io.BytesIO()
            self.waited = False

        def poll(self):
            return None

        def kill(self):
            raise ProcessLookupError('already exited')

        def wait(self, *, timeout):
            assert timeout == 5
            self.waited = True
            return 0

    client = object.__new__(rpc.TraceProcessorPipe)
    client.process = ExitingProcess()
    client._closed = threading.Event()
    client._close_lock = threading.Lock()
    client._cleanup_complete = False
    client._requests = queue.Queue(maxsize=1)
    client._results = queue.Queue(maxsize=1)
    client._thread = threading.Thread()

    client.close()
    assert client.process.waited
    assert client._cleanup_complete
    assert client.process.stdin.closed and client.process.stdout.closed


def test_close_retries_a_failed_kill_without_exposing_process_error():
    class Process:
        def __init__(self):
            self.stdin = io.BytesIO()
            self.stdout = io.BytesIO()
            self.kills = 0
            self.waited = False

        def poll(self):
            return None

        def kill(self):
            self.kills += 1
            if self.kills == 1:
                raise OSError("private decoder executable path")

        def wait(self, *, timeout):
            assert timeout == 5
            self.waited = True
            return 0

    client = object.__new__(rpc.TraceProcessorPipe)
    client.process = Process()
    client._closed = threading.Event()
    client._close_lock = threading.Lock()
    client._cleanup_complete = False
    client._requests = queue.Queue(maxsize=1)
    client._results = queue.Queue(maxsize=1)
    client._thread = threading.Thread()

    with pytest.raises(ContractError, match="cleanup did not finish") as failure:
        client.close()
    assert "private" not in str(failure.value)
    assert client._closed.is_set()
    assert client._cleanup_complete is False

    client.close()
    assert client.process.kills == 2
    assert client.process.waited is True
    assert client._cleanup_complete is True


def test_owned_process_exit_and_timeout_have_a_recoverable_type(monkeypatch,tmp_path):
    fake_process(monkeypatch,tmp_path,'silent')
    client=rpc.TraceProcessorPipe(Path('owned-decoder'),timeout_seconds=5)
    client.timeout=.2
    client.process.kill();client.process.wait(timeout=3)
    with pytest.raises(rpc.DecoderInterrupted):client.query('SELECT 1')
    assert not client._thread.is_alive()
    client=rpc.TraceProcessorPipe(Path('owned-decoder'),timeout_seconds=5)
    client.timeout=.2
    with pytest.raises(rpc.DecoderInterrupted):client.query('SELECT 1')
    assert client.process.poll() is not None
