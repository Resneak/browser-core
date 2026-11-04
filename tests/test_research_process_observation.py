"""A transient Windows teardown observation is not a completed-status failure."""
import ctypes
import os
from types import SimpleNamespace
from pathlib import Path

import pytest

import browser_core.process as processes
import browser_core.research as research
from browser_core.contracts import ContractError

pytestmark = pytest.mark.skipif(os.name != 'nt', reason='Windows process query errors')

def path_query_denial():
    def deny(*args):
        ctypes.set_last_error(5)
        return False
    with pytest.raises(ContractError) as caught:
        processes._windows_process_identity_from_handle(
            SimpleNamespace(QueryFullProcessImageNameW=deny), 123, 42)
    return caught.value


def test_wait_retries_actual_windows_access_denial_then_observes_stop(monkeypatch):
    outcomes = iter((path_query_denial(), {'run_id': 'owned-run', 'running': False}))
    reads = []
    sleeps = []
    def status(path):
        reads.append(path)
        value = next(outcomes)
        if isinstance(value, BaseException): raise value
        return value
    run = research.ResearchRun.__new__(research.ResearchRun)
    run.session_path = Path('owned-fixture')
    run.run_id = 'owned-run'
    run.thread = SimpleNamespace(is_alive=lambda: True)
    monkeypatch.setattr(research, 'session_status', status)
    monkeypatch.setattr(research.time, 'sleep', sleeps.append)
    run.wait()
    assert reads == [Path('owned-fixture'), Path('owned-fixture')]
    assert sleeps == [.05]


def test_persistent_denial_fails_at_bounded_deadline_and_never_reports_exit(monkeypatch):
    clock = [0.0]
    error = path_query_denial()
    run = research.ResearchRun.__new__(research.ResearchRun)
    run.session_path = Path('owned-fixture')
    run.run_id = 'owned-run'
    run.thread = SimpleNamespace(is_alive=lambda: True)
    def status(path): raise error
    def sleep(seconds): clock[0] += seconds
    monkeypatch.setattr(research, 'session_status', status)
    monkeypatch.setattr(research.time, 'monotonic', lambda: clock[0])
    monkeypatch.setattr(research.time, 'sleep', sleep)
    with pytest.raises(processes.ProcessQueryUnavailable): run.wait()
    assert clock[0] == pytest.approx(2.0)


@pytest.mark.parametrize('error', [ContractError('invalid session'),
                                  ContractError('cannot inspect browser executable path (Windows error 5)'),
                                  KeyboardInterrupt()])
def test_other_errors_and_cancellation_are_not_retried(monkeypatch, error):
    run = research.ResearchRun.__new__(research.ResearchRun)
    run.session_path = Path('owned-fixture')
    run.run_id = 'owned-run'
    run.thread = SimpleNamespace(is_alive=lambda: True)
    def status(path): raise error
    monkeypatch.setattr(research, 'session_status', status)
    monkeypatch.setattr(research.time, 'sleep', lambda seconds: pytest.fail('unexpected retry'))
    with pytest.raises(type(error)): run.wait()


def test_good_read_resets_only_the_contiguous_denial_budget(monkeypatch):
    clock = [0.0]
    reads = [0]
    error = path_query_denial()
    run = research.ResearchRun.__new__(research.ResearchRun)
    run.session_path = Path('owned-fixture')
    run.run_id = 'owned-run'
    run.thread = SimpleNamespace(is_alive=lambda: True)
    def status(path):
        reads[0] += 1
        if reads[0] in (3, 6): return {'run_id': 'owned-run', 'running': reads[0] == 3}
        raise error
    def sleep(seconds): clock[0] += 1.0
    monkeypatch.setattr(research, 'session_status', status)
    monkeypatch.setattr(research.time, 'monotonic', lambda: clock[0])
    monkeypatch.setattr(research.time, 'sleep', sleep)
    run.wait()
    assert reads[0] == 6 and clock[0] > 2


def test_query_denial_does_not_hide_an_exited_inspector(monkeypatch):
    run = research.ResearchRun.__new__(research.ResearchRun)
    run.session_path = Path('owned-fixture')
    run.run_id = 'owned-run'
    run.thread = SimpleNamespace(is_alive=lambda: False)
    def status(path): raise path_query_denial()
    monkeypatch.setattr(research, 'session_status', status)
    with pytest.raises(ContractError, match='inspector stopped'): run.wait()


@pytest.mark.parametrize('stage', ['open', 'path', 'times'])
@pytest.mark.parametrize('code', [5, 87, 123])
def test_failed_windows_handle_queries_never_prove_exit(stage, code, monkeypatch):
    closed = []
    def fail():
        ctypes.set_last_error(code)
        return 0
    def open_process(*args): return fail() if stage == 'open' else 123
    def path_query(handle, flags, buffer, size):
        if stage == 'path': return fail()
        buffer.value = 'C:/owned/chrome.exe'
        return 1
    def times(*args): return fail()
    def active(_handle, output):
        code_ptr = ctypes.cast(output, ctypes.POINTER(processes.wintypes.DWORD))
        code_ptr.contents.value = 259
        return 1
    def wait(_handle, _milliseconds):
        return 258
    def close(handle):
        closed.append(handle)
        return 1
    kernel = SimpleNamespace(OpenProcess=open_process, QueryFullProcessImageNameW=path_query,
                             GetProcessTimes=times, GetExitCodeProcess=active,
                             WaitForSingleObject=wait, CloseHandle=close)
    monkeypatch.setattr(processes.ctypes, 'WinDLL', lambda *a, **k: kernel)
    expected = ({5: processes.ProcessQueryUnavailable, 87: ProcessLookupError,
                 123: ContractError}[code] if stage == 'open' else processes.ProcessQueryUnavailable)
    with pytest.raises(expected) as caught: processes._windows_process_identity(42)
    assert type(caught.value) is expected
    assert closed == ([] if stage == 'open' else [123])
