"""Coordination bounds, cancellation and native handle ownership."""
from contextlib import contextmanager
import ctypes
import os
from pathlib import Path

import pytest

import browser_core.session_stop_guard as guard
from browser_core.contracts import ContractError

pytestmark = pytest.mark.skipif(os.name != 'nt', reason='Windows stop mutex')


class Kernel:
    def __init__(self, clock):
        self.clock = clock
        self.states = [0]
        self.owned = False
        self.closed = self.releases = self.creates = 0
        self.waits = []
        self.release_failure = self.close_failure = self.create_failure = False
        self.interrupt_after_acquiring = self.acquire_after_deadline = False
    def CreateMutexW(self, security, owner, name):
        assert security is None and owner is False and name.startswith('Local\\BrowserCore.SessionStop.v1.')
        self.creates += 1
        return None if self.create_failure else 123
    def WaitForSingleObject(self, handle, milliseconds):
        assert handle == 123 and 1 <= milliseconds <= 50
        self.waits.append(milliseconds)
        state = self.states.pop(0)
        if state == 0x102: self.clock[0] += milliseconds/1000
        if state in (0, 0x80): self.owned = True
        if self.acquire_after_deadline: self.clock[0] += 100
        if self.interrupt_after_acquiring: raise KeyboardInterrupt()
        return state
    def ReleaseMutex(self, handle):
        assert handle == 123
        self.releases += 1
        if self.release_failure:
            ctypes.set_last_error(5)
            return False
        if not self.owned:
            ctypes.set_last_error(288)  # ERROR_NOT_OWNER from the Windows API
            return False
        self.owned = False
        return True
    def CloseHandle(self, handle):
        assert handle == 123
        self.closed += 1
        return not self.close_failure


@pytest.fixture
def kernel(monkeypatch):
    clock = [10.0]
    fake = Kernel(clock)
    monkeypatch.setattr(guard, '_kernel', lambda: fake)
    monkeypatch.setattr(guard.time, 'monotonic', lambda: clock[0])
    return fake


@pytest.mark.parametrize('state', [0, 0x80])
def test_normal_or_abandoned_mutex_enters_with_owned_handle_and_releases(kernel, tmp_path, state):
    kernel.states = [state]
    with guard.session_stop_guard(tmp_path/'session.json', 11):
        assert kernel.owned and kernel.closed == 0
    assert not kernel.owned and kernel.closed == kernel.releases == 1
    assert not list(tmp_path.iterdir())


@pytest.mark.parametrize('error', [ContractError('body failed'), KeyboardInterrupt()])
def test_body_exception_keeps_its_type_and_closes_handle(kernel, tmp_path, error):
    with pytest.raises(type(error)):
        with guard.session_stop_guard(tmp_path/'session.json', 11): raise error
    assert kernel.closed == kernel.releases == 1 and not kernel.owned


def test_interrupt_immediately_after_native_acquisition_still_releases(kernel, tmp_path):
    kernel.interrupt_after_acquiring = True
    with pytest.raises(KeyboardInterrupt):
        with guard.session_stop_guard(tmp_path/'session.json', 11): pytest.fail('unexpected body')
    assert kernel.closed == kernel.releases == 1 and not kernel.owned


def test_timeout_consumes_original_budget_and_does_not_enter_body(kernel, tmp_path):
    kernel.states = [0x102]
    with pytest.raises(ContractError, match='deadline exhausted'):
        with guard.session_stop_guard(tmp_path/'session.json', 10.05): pytest.fail('unexpected body')
    assert kernel.waits == [50] and kernel.clock[0] == 10.05
    assert kernel.closed == 1 and not kernel.owned


def test_acquisition_after_deadline_cannot_start_cleanup(kernel, tmp_path):
    kernel.acquire_after_deadline = True
    with pytest.raises(ContractError, match='deadline exhausted'):
        with guard.session_stop_guard(tmp_path/'session.json', 11): pytest.fail('unexpected body')
    assert kernel.closed == 1 and not kernel.owned


def test_unknown_wait_failure_is_not_treated_as_acquired(kernel, tmp_path):
    kernel.states = [0xFFFFFFFF]
    with pytest.raises(ContractError, match='wait failed'):
        with guard.session_stop_guard(tmp_path/'session.json', 11): pytest.fail('unexpected body')
    assert kernel.closed == 1 and not kernel.owned


def test_failed_creation_has_no_handle_to_close(kernel, tmp_path):
    kernel.create_failure = True
    with pytest.raises(ContractError, match='unavailable'):
        with guard.session_stop_guard(tmp_path/'session.json', 11): pytest.fail('unexpected body')
    assert kernel.closed == kernel.releases == 0


@pytest.mark.parametrize('failure', ['release_failure', 'close_failure'])
def test_cleanup_failure_remains_explicit_and_close_is_attempted(kernel, tmp_path, failure):
    setattr(kernel, failure, True)
    with pytest.raises(ContractError, match='could not be'):
        with guard.session_stop_guard(tmp_path/'session.json', 11): pass
    assert kernel.closed == kernel.releases == 1


def test_reentry_cannot_release_an_outer_acquisition(kernel, tmp_path):
    path = tmp_path/'session.json'
    with guard.session_stop_guard(path, 11):
        with pytest.raises(ContractError, match='recursive'):
            with guard.session_stop_guard(path, 11): pytest.fail('unexpected body')
        assert kernel.owned and kernel.releases == 0
    assert kernel.closed == kernel.releases == kernel.creates == 1


def test_coordination_key_normalizes_spelling_but_is_not_an_authorization(tmp_path):
    path = tmp_path/'session.json'
    assert guard._name(path) == guard._name(tmp_path/'other'/'..'/'SESSION.JSON')
    assert guard._name(path) != guard._name(tmp_path/'different.json')


def test_waiting_does_not_reset_stop_deadline(tmp_path, monkeypatch):
    import browser_core.lifecycle as lifecycle
    clock = [5.0]
    monkeypatch.setattr(lifecycle.time, 'monotonic', lambda: clock[0])
    @contextmanager
    def waiting(path, deadline):
        assert deadline == 15
        clock[0] += 2
        yield
    seen = []
    monkeypatch.setattr(lifecycle, 'session_stop_guard', waiting)
    monkeypatch.setattr(lifecycle, '_stop_session_serialized', lambda path, **kwargs: seen.append(kwargs) or {})
    lifecycle.stop_session(tmp_path/'session.json', timeout_seconds=10)
    assert seen[0]['started'] == 5 and seen[0]['deadline'] == 15
