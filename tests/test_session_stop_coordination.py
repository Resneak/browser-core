"""Concurrent cancellation must not race publication of the same session."""
import os
import threading
from pathlib import Path
from types import SimpleNamespace

import pytest

import browser_core.lifecycle as lifecycle
import browser_core.control_files as control_files
import browser_core.research as research
from browser_core.contracts import ContractError
from browser_core.profiles import create_profile, acquire_profile_lock
from test_lifecycle import _session


@pytest.mark.skipif(os.name != 'nt', reason='Windows session-stop coordination')
def test_second_stop_reads_only_after_first_completion(tmp_path, monkeypatch):
    create_profile(tmp_path, 'persistent')
    lock = acquire_profile_lock(tmp_path, 'persistent', 'fixture-run')
    path, _ = _session(tmp_path, lock)
    first_read = threading.Event()
    second_started = threading.Event()
    second_read = threading.Event()
    release_first = threading.Event()
    original = lifecycle.load_session_snapshot
    reads = []
    results = []
    errors = []
    def load(path):
        value = original(path)
        reads.append(value.document['state'])
        if len(reads) == 1:
            first_read.set()
            assert release_first.wait(3)
        else:
            second_read.set()
        return value
    def absent(pid): raise ProcessLookupError(pid)
    monkeypatch.setattr(lifecycle, 'load_session_snapshot', load)
    monkeypatch.setattr(lifecycle, 'request_browser_close', lambda *a, **k: None)
    monkeypatch.setattr(lifecycle, 'wait_for_verified_exit', lambda *a, **k: True)
    monkeypatch.setattr(lifecycle, 'observe_process', absent)
    def stop(second=False):
        if second: second_started.set()
        try: results.append(lifecycle.stop_session(path, timeout_seconds=3))
        except BaseException as error: errors.append(error)
    first = threading.Thread(target=stop)
    second = threading.Thread(target=stop, args=(True,))
    first.start()
    try:
        assert first_read.wait(1)
        second.start()
        assert second_started.wait(1)
        assert not second_read.wait(.15), 'second caller read mutable session before first finished'
    finally:
        release_first.set()
        first.join(3)
        if second.ident is not None: second.join(3)
    assert not first.is_alive() and not second.is_alive()
    assert not errors
    assert reads == ['active', 'stopped']
    assert len(results) == 2 and all(value['state'] == 'stopped' for value in results)


@pytest.mark.skipif(os.name != 'nt', reason='Windows session-stop coordination')
@pytest.mark.parametrize('phase', ['missing', 'linked'])
def test_research_monitor_waits_for_session_publication(tmp_path, monkeypatch, phase):
    create_profile(tmp_path, 'persistent')
    lock = acquire_profile_lock(tmp_path, 'persistent', 'fixture-run')
    path, _ = _session(tmp_path, lock)
    publishing = threading.Event()
    release_writer = threading.Event()
    monitor_started = threading.Event()
    monitor_done = threading.Event()
    errors = []
    original_publish = control_files.publish_bytes_exclusive_result
    original_link = os.link

    def pause():
        publishing.set()
        assert release_writer.wait(3)

    def publish(target, *args, **kwargs):
        if target == path and phase == 'missing':
            assert not path.exists()
            pause()
        return original_publish(target, *args, **kwargs)

    def link(source, target, *args, **kwargs):
        result = original_link(source, target, *args, **kwargs)
        if Path(target) == path and phase == 'linked':
            assert path.stat().st_nlink == 2
            pause()
        return result

    def absent(pid): raise ProcessLookupError(pid)
    monkeypatch.setattr(control_files, 'publish_bytes_exclusive_result', publish)
    monkeypatch.setattr(os, 'link', link)
    monkeypatch.setattr(lifecycle, 'observe_process', absent)
    monkeypatch.setattr(lifecycle, 'request_browser_close', lambda *a, **k: None)
    monkeypatch.setattr(lifecycle, 'wait_for_verified_exit', lambda *a, **k: True)

    def stop():
        try: lifecycle.stop_session(path, timeout_seconds=3)
        except BaseException as error: errors.append(error)

    def monitor():
        run = research.ResearchRun.__new__(research.ResearchRun)
        run.session_path = path
        run.run_id = 'fixture-run'
        run.thread = SimpleNamespace(is_alive=lambda: True)
        monitor_started.set()
        try: run.wait()
        except BaseException as error: errors.append(error)
        finally: monitor_done.set()

    writer = threading.Thread(target=stop)
    reader = threading.Thread(target=monitor)
    writer.start()
    try:
        assert publishing.wait(1)
        reader.start()
        assert monitor_started.wait(1)
        assert not monitor_done.wait(.15), [str(error) for error in errors]
    finally:
        release_writer.set()
        writer.join(3)
        if reader.ident is not None: reader.join(3)
    assert not writer.is_alive() and not reader.is_alive()
    assert not errors and monitor_done.is_set()
    assert lifecycle.session_status(path)['state'] == 'stopped'
    assert path.stat().st_nlink == 1


@pytest.mark.skipif(os.name != 'nt', reason='Windows session-stop coordination')
def test_research_monitor_still_rejects_uncoordinated_hard_link(tmp_path):
    create_profile(tmp_path, 'persistent')
    lock = acquire_profile_lock(tmp_path, 'persistent', 'fixture-run')
    path, _ = _session(tmp_path, lock)
    alias = tmp_path / 'linked-session.json'
    os.link(path, alias)
    run = research.ResearchRun.__new__(research.ResearchRun)
    run.session_path = path
    run.run_id = 'fixture-run'
    run.thread = SimpleNamespace(is_alive=lambda: True)
    with pytest.raises(ContractError, match='additional hard links'):
        run.wait()
    assert path.stat().st_nlink == 2
