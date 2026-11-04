"""Owned lifecycle cancellation, completion and retry boundaries."""
from pathlib import Path
from queue import Full
from threading import Event, Thread
from types import SimpleNamespace
import subprocess
import sys

import pytest

from browser_core.contracts import ContractError
import browser_core.research as research
import browser_core.research_picker as picker_module
import browser_core.trace_rpc as rpc

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def decoder(tmp_path, monkeypatch):
    status = rpc._field(1, rpc._field(1, 0) + rpc._field(3, 10) + rpc._field(210, rpc._field(3, 14)))
    script = tmp_path / 'owned_decoder.py'
    script.write_text("import os,time\nos.write(1,bytes.fromhex(" + repr(status.hex()) + "))\ntime.sleep(15)\n", encoding='utf-8')
    original = subprocess.Popen
    monkeypatch.setattr(rpc.subprocess, 'Popen', lambda command, **kwargs: original([sys.executable, '-B', str(script)], **kwargs))
    client = rpc.TraceProcessorPipe(Path('owned-test-decoder'), timeout_seconds=5)
    yield client
    # The fixture owns only this child, even when the tested close fails.
    if client.process.poll() is None:
        client.process.kill()
    client.process.wait(timeout=5)
    try:
        client._requests.put_nowait(None)
    except Full:
        pass
    try:
        client._results.put_nowait(ContractError('test cleanup'))
    except Full:
        pass
    client._thread.join(5)
    for stream in (client.process.stdin, client.process.stdout):
        if not stream.closed:
            stream.close()


def test_close_releases_a_caller_waiting_on_decoder_output(decoder, monkeypatch):
    exchanging, done = Event(), Event()
    original = decoder._exchange
    errors = []

    def exchange(*args):
        exchanging.set()
        return original(*args)

    monkeypatch.setattr(decoder, '_exchange', exchange)

    def query():
        try:
            decoder.query('SELECT 1')
        except ContractError as error:
            errors.append(error)
        finally:
            done.set()

    worker = Thread(target=query, daemon=True)
    worker.start()
    try:
        assert exchanging.wait(3)
        decoder.close()
        assert done.wait(1), 'a closed decoder left its caller waiting for the query deadline'
        assert len(errors) == 1 and not decoder._thread.is_alive()
    finally:
        try:
            decoder._results.put_nowait(ContractError('test cleanup'))
        except Full:
            pass
        worker.join(5)


def test_failed_decoder_cleanup_can_be_retried(decoder, monkeypatch):
    original = decoder.process.wait
    calls = []

    def wait(*args, **kwargs):
        calls.append(True)
        if len(calls) == 1:
            raise subprocess.TimeoutExpired('owned decoder', 5)
        return original(*args, **kwargs)

    monkeypatch.setattr(decoder.process, 'wait', wait)
    with pytest.raises(ContractError, match='local decoder cleanup did not finish') as failure:
        decoder.close()
    assert 'owned decoder' not in str(failure.value)
    assert failure.value.__cause__ is None
    decoder.close()
    assert len(calls) == 2
    assert decoder.process.poll() is not None and not decoder._thread.is_alive()
    assert decoder.process.stdin.closed and decoder.process.stdout.closed


def test_simultaneous_decoder_close_waits_for_actual_cleanup(decoder, monkeypatch):
    entered, release, second_started, second_done = Event(), Event(), Event(), Event()
    original = decoder.process.wait
    errors = []

    def wait(*args, **kwargs):
        entered.set()
        assert release.wait(5)
        return original(*args, **kwargs)

    monkeypatch.setattr(decoder.process, 'wait', wait)

    def close(second=False):
        if second:
            second_started.set()
        try:
            decoder.close()
        except BaseException as error:
            errors.append(error)
        finally:
            if second:
                second_done.set()

    first = Thread(target=close, daemon=True)
    second = Thread(target=close, args=(True,), daemon=True)
    first.start()
    try:
        assert entered.wait(3)
        second.start()
        assert second_started.wait(3)
        assert not second_done.wait(.1), 'close returned while owned cleanup was still blocked'
    finally:
        release.set()
        first.join(5)
        if second.ident is not None:
            second.join(5)
    assert not errors and not first.is_alive() and not second.is_alive()


def test_picker_stop_wakes_its_worker_without_waiting_for_a_status_poll(tmp_path, monkeypatch):
    waiting, finished = Event(), Event()

    class ObservedEvent(Event):
        def wait(self, timeout=None):
            waiting.set()
            # A status poll is deliberately slow. A Stop notification must wake
            # the wait itself; this does not benchmark scheduler performance.
            return super().wait(5)

    run = SimpleNamespace(session_path=tmp_path/'owned.json', url='http://127.0.0.1:1/',
                          thread=SimpleNamespace(is_alive=lambda: True))
    run.finish_browser = finished.set
    run.close = finished.set
    monkeypatch.setattr(picker_module, 'start_research', lambda *args, **kwargs: run)
    monkeypatch.setattr(picker_module, 'session_status', lambda path: {'running': True})
    picker = picker_module.ResearchPicker(tmp_path/'workspace', ROOT)
    picker.closing, picker.stop_requested = ObservedEvent(), ObservedEvent()
    try:
        picker.start({'profile_id': 'owned', 'action': 'create'})
        assert waiting.wait(3)
        picker.stop()
        assert finished.wait(1), 'Stop did not wake the pending worker wait'
    finally:
        picker.closing.set()
        picker.stop_requested.set()
        picker.close()
    assert not picker.worker.is_alive()


def test_concurrent_research_finish_and_close_stop_browser_once(monkeypatch, tmp_path):
    entered, release, server_stopped, duplicated = Event(), Event(), Event(), Event()
    calls, errors = [], []

    class Server:
        def serve_forever(self, **kwargs):
            server_stopped.wait(5)
        def shutdown(self):
            server_stopped.set()
        def server_close(self):
            pass

    def stop(*args, **kwargs):
        calls.append(True)
        if len(calls) > 1:
            duplicated.set()
        entered.set()
        assert release.wait(5)
        return {'state': 'stopped', 'running': False}

    monkeypatch.setattr(research, 'stop_session', stop)
    run = research.ResearchRun(tmp_path/'owned.json', {'run_id': 'owned-run'}, Server(), 'http://127.0.0.1:1/', False)

    def action(method):
        try:
            method()
        except BaseException as error:
            errors.append(error)

    first = Thread(target=action, args=(run.finish_browser,), daemon=True)
    second = Thread(target=action, args=(run.close,), daemon=True)
    first.start()
    try:
        assert entered.wait(3)
        second.start()
        assert server_stopped.wait(3)
        assert not duplicated.wait(.1), 'two callers concurrently stopped the same owned browser'
    finally:
        release.set()
        first.join(5)
        second.join(5)
        run.close()
    assert len(calls) == 1 and not errors
    assert run.inspector_closed and not run.thread.is_alive()
