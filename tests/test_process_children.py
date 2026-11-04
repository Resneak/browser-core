from types import SimpleNamespace
import ctypes
import json

import pytest
from browser_core import process_children as children
from browser_core.errors import ContractError
from browser_core.control_files import canonical_json_bytes


def identity(pid, started=100, executable='C:/owned/chrome.exe'):
    return {'pid': pid, 'executable': executable, 'start_marker': f'windows-filetime:{started}'}


def test_snapshot_keeps_exact_same_executable_descendants_and_excludes_old_or_foreign(monkeypatch):
    expected = identity(42)
    rows = {42: 1, 43: 42, 44: 43, 45: 42, 46: 42, 99: 1}
    values = {42: expected, 43: identity(43, 101), 44: identity(44, 102),
              45: identity(45, 80), 46: identity(46, 103, 'C:/other/helper.exe')}
    monkeypatch.setattr(children, '_windows_parent_rows', lambda: rows)
    monkeypatch.setattr(children, 'observe_process', lambda pid: values[pid])
    snapshot = children.observe_browser_children(expected)
    assert snapshot.parent_running and [x['pid'] for x in snapshot.identities] == [43, 44]


@pytest.mark.parametrize('state', ['gone', 'replaced'])
def test_absent_or_replaced_parent_prevents_snapshot_and_control_admission(monkeypatch, state):
    def observe(pid):
        if state == 'gone':
            raise ProcessLookupError(pid)
        return identity(pid, 999)
    monkeypatch.setattr(children, 'observe_process', observe)
    monkeypatch.setattr(children, '_windows_parent_rows', lambda: pytest.fail('wrong parent was scanned'))
    assert children.observe_browser_children(identity(42)) == children.ChildSnapshot(False, ())


def test_child_query_denial_is_not_an_empty_successful_snapshot(monkeypatch):
    monkeypatch.setattr(children, '_windows_parent_rows', lambda: {43: 42})
    def observe(pid):
        if pid == 43:
            raise ContractError('query unavailable')
        return identity(pid)
    monkeypatch.setattr(children, 'observe_process', observe)
    with pytest.raises(ContractError, match='query unavailable'):
        children.observe_browser_children(identity(42))


def test_children_created_after_parent_are_retained_when_parent_exits_during_snapshot(monkeypatch):
    observations = iter([identity(42), identity(43, 101), ProcessLookupError(42)])
    def observe(pid):
        value = next(observations)
        if isinstance(value, BaseException):
            raise value
        return value
    monkeypatch.setattr(children, 'observe_process', observe)
    monkeypatch.setattr(children, '_windows_parent_rows', lambda: {43: 42})
    snapshot = children.observe_browser_children(identity(42))
    assert not snapshot.parent_running and snapshot.identities[0]['pid'] == 43


def test_snapshot_rejects_parent_cycles(monkeypatch):
    monkeypatch.setattr(children, 'observe_process', lambda pid: identity(pid))
    monkeypatch.setattr(children, '_windows_parent_rows', lambda: {42: 43, 43: 42})
    with pytest.raises(ContractError, match='cycle'):
        children.observe_browser_children(identity(42))


def test_snapshot_stops_observing_when_child_receipt_bound_is_exceeded(monkeypatch):
    monkeypatch.setattr(children, 'MAX_RETAINED_CHILDREN', 2)
    monkeypatch.setattr(children, '_windows_parent_rows',
        lambda: {pid: 42 for pid in range(43, 143)})
    observed = []

    def observe(pid):
        observed.append(pid)
        return identity(pid, 100 if pid == 42 else 100 + pid)

    monkeypatch.setattr(children, 'observe_process', observe)
    with pytest.raises(ContractError, match='child bound'):
        children.observe_browser_children(identity(42))
    assert observed == [42, 43, 44, 45]


class Function:
    def __init__(self, action):
        self.action = action
    def __call__(self, *args):
        return self.action(*args)


@pytest.mark.parametrize('mode', ['create-failed', 'enumeration-failed', 'close-failed', 'empty'])
def test_windows_snapshot_handle_cleanup_and_errors(monkeypatch, mode):
    closed = []
    kernel = SimpleNamespace(
        CreateToolhelp32Snapshot=Function(lambda *a: ctypes.c_void_p(-1).value if mode == 'create-failed' else 12),
        Process32FirstW=Function(lambda *a: False),
        Process32NextW=Function(lambda *a: pytest.fail('empty snapshot advanced')),
        CloseHandle=Function(lambda handle: closed.append(handle) or mode != 'close-failed'))
    monkeypatch.setattr(ctypes, 'WinDLL', lambda *a, **kw: kernel, raising=False)
    monkeypatch.setattr(ctypes, 'get_last_error', lambda: 5 if mode == 'enumeration-failed' else 18, raising=False)
    if mode == 'empty':
        assert children._windows_parent_rows() == {}
    else:
        with pytest.raises(ContractError):
            children._windows_parent_rows()
    assert closed == ([] if mode == 'create-failed' else [12])


def test_retained_children_survive_retry_without_trusting_old_parent_state(tmp_path):
    session = {'run_id': 'owned-run', 'process_identity': identity(42)}
    path = tmp_path / 'owned-run.json'
    body = json.dumps(session).encode()
    initial = children.retain_child_snapshot(path, session, body,
        children.ChildSnapshot(True, (identity(43, 101),)))
    receipt = path.with_name('.owned-run.child-exit')
    original = receipt.read_bytes()
    retry = children.retain_child_snapshot(path, session, body, children.ChildSnapshot(False, ()))
    assert not retry.parent_running and retry.identities == initial.identities
    assert receipt.read_bytes() == original


def test_child_receipt_rejects_a_different_session_without_rewriting(tmp_path):
    session = {'run_id': 'owned-run', 'process_identity': identity(42)}
    path = tmp_path / 'owned-run.json'
    children.retain_child_snapshot(path, session, b'original', children.ChildSnapshot(True, ()))
    receipt = path.with_name('.owned-run.child-exit')
    original = receipt.read_bytes()
    with pytest.raises(ContractError, match='does not match'):
        children.retain_child_snapshot(path, session, b'changed', children.ChildSnapshot(True, ()))
    assert receipt.read_bytes() == original


def test_retry_merges_new_children_with_retained_identities(tmp_path):
    session = {'run_id': 'owned-run', 'process_identity': identity(42)}
    path = tmp_path / 'owned-run.json'
    children.retain_child_snapshot(path, session, b'active', children.ChildSnapshot(True, (identity(43, 101),)))
    result = children.retain_child_snapshot(path, session, b'active', children.ChildSnapshot(True, (identity(44, 102),)))
    assert [x['pid'] for x in result.identities] == [43, 44]
    document = json.loads(path.with_name('.owned-run.child-exit').read_text())
    assert len(document['children']) == 2


def test_child_receipt_rejects_foreign_identity_and_preserves_the_file(tmp_path):
    session = {'run_id': 'owned-run', 'process_identity': identity(42)}
    path = tmp_path / 'owned-run.json'
    children.retain_child_snapshot(path, session, b'active', children.ChildSnapshot(True, ()))
    receipt = path.with_name('.owned-run.child-exit')
    document = json.loads(receipt.read_text())
    document['children'] = [identity(43, 101, 'C:/unrelated/tool.exe')]
    receipt.write_bytes(canonical_json_bytes(document))
    original = receipt.read_bytes()
    with pytest.raises(ContractError, match='unrelated identity'):
        children.retain_child_snapshot(path, session, b'active', children.ChildSnapshot(False, ()))
    assert receipt.read_bytes() == original
