from contextlib import contextmanager
from http.client import HTTPConnection
import json
from pathlib import Path
from threading import Event, Thread
import time
from types import SimpleNamespace
from urllib.parse import urlsplit

import pytest

from browser_core.contracts import ContractError
from browser_core.process import ProcessQueryUnavailable
from browser_core.profiles import create_profile
import browser_core.research_picker as picker_module

ROOT = Path(__file__).resolve().parents[1]


def test_input_picker_rejects_old_build_before_creating_a_server_or_profile(tmp_path):
    with pytest.raises(ContractError, match='hashing-input patch'):
        picker_module.create_research_picker(tmp_path/'workspace', ROOT, inspect_hash_inputs=True)
    assert not (tmp_path/'workspace').exists()


def test_picker_url_emission_failure_closes_server(tmp_path, monkeypatch):
    closed=[]
    server=SimpleNamespace(
        serve_forever=lambda **_kwargs:pytest.fail('server started after URL emission failed'),
        server_close=lambda:closed.append(True))
    monkeypatch.setattr(picker_module,'create_research_picker',
                        lambda *args,**kwargs:(server,'http://127.0.0.1:1234/secret/'))

    def failed_print(*_args,**_kwargs):
        raise BrokenPipeError('closed stdout')

    monkeypatch.setattr(picker_module,'print',failed_print,raising=False)
    with pytest.raises(BrokenPipeError,match='closed stdout'):
        picker_module.serve_research_picker(tmp_path/'workspace',ROOT,open_browser=False)
    assert closed==[True]


def test_input_picker_preserves_explicit_choice_for_every_launch(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(picker_module, 'require_inspection_support', lambda root, mode: calls.append((root, mode)))
    picker = picker_module.ResearchPicker(tmp_path/'workspace', ROOT, inspect_hash_inputs=True)
    try:
        assert calls == [(ROOT, 'research-v3')]
        assert picker.options['inspect_hash_inputs'] is True
    finally:
        picker.close()


def test_picker_worker_start_failure_restores_ready_state(tmp_path, monkeypatch):
    picker = picker_module.ResearchPicker(tmp_path / 'workspace', ROOT)

    class UnavailableThread:
        def __init__(self, *args, **kwargs):
            pass

        def start(self):
            raise RuntimeError('cannot start new thread')

    monkeypatch.setattr(picker_module, 'Thread', UnavailableThread)
    with pytest.raises(ContractError, match='worker could not start'):
        picker.start({'profile_id': 'saved', 'action': 'open'})
    assert picker.snapshot() == {
        'state': 'ready', 'profile_id': None, 'error': None, 'revision': 0,
        'recording_limit_mib': picker.limit_mib, 'recording_parts': picker.part_count,
        'inspector_url': None, 'recent': [],
    }
    assert picker.worker is None


def test_picker_retains_worker_if_start_raises_after_thread_begins(tmp_path, monkeypatch):
    picker = picker_module.ResearchPicker(tmp_path / 'workspace', ROOT)
    entered = Event()
    release = Event()

    class StartedThenRaisedThread(Thread):
        def start(self):
            super().start()
            assert entered.wait(5)
            raise RuntimeError('thread started but caller saw an error')

    def launch(*_args, **_kwargs):
        entered.set()
        assert release.wait(5)
        raise ContractError('unavailable fixture browser')

    monkeypatch.setattr(picker_module, 'Thread', StartedThenRaisedThread)
    monkeypatch.setattr(picker_module, 'start_research', launch)
    try:
        with pytest.raises(ContractError, match='worker could not start'):
            picker.start({'profile_id': 'saved', 'action': 'open'})
        assert picker.worker is not None and picker.worker.is_alive()
        assert picker.closing.is_set() and picker.stop_requested.is_set()
        with pytest.raises(ContractError, match='already opening or running'):
            picker.start({'profile_id': 'saved', 'action': 'open'})
    finally:
        release.set()
        picker.close()
    assert picker.snapshot()['state'] == 'closed'


def test_picker_close_waits_for_worker_start_to_finish(tmp_path, monkeypatch):
    picker = picker_module.ResearchPicker(tmp_path / 'workspace', ROOT)
    entering_start = Event()
    release_start = Event()
    errors = []

    class SlowThread(Thread):
        def start(self):
            entering_start.set()
            assert release_start.wait(5)
            super().start()

    def fail_launch(*_args, **_kwargs):
        raise ContractError('unavailable fixture browser')

    monkeypatch.setattr(picker_module, 'Thread', SlowThread)
    monkeypatch.setattr(picker_module, 'start_research', fail_launch)

    def start():
        try:
            picker.start({'profile_id': 'saved', 'action': 'open'})
        except Exception as error:
            errors.append(error)

    def close():
        try:
            picker.close()
        except Exception as error:
            errors.append(error)

    starter = Thread(target=start)
    closer = Thread(target=close)
    starter.start()
    assert entering_start.wait(5)
    closer.start()
    assert picker.closing.wait(5)
    release_start.set()
    starter.join(5)
    closer.join(5)
    assert not starter.is_alive() and not closer.is_alive()
    assert errors == []
    assert picker.snapshot()['state'] == 'closed'


def test_picker_close_reports_stalled_worker_and_allows_retry(tmp_path, monkeypatch):
    picker = picker_module.ResearchPicker(tmp_path / 'workspace', ROOT)
    release = Event()
    worker = Thread(target=lambda: release.wait(5), daemon=True)
    worker.start()
    picker.worker = worker
    monkeypatch.setattr(picker_module, 'PICKER_WORKER_CLOSE_TIMEOUT_SECONDS', .01)

    try:
        with pytest.raises(ContractError, match='worker cleanup did not finish'):
            picker.close()
        assert picker.closing.is_set()
        assert picker.snapshot()['state'] == 'cleanup-error'
    finally:
        release.set()
        worker.join(5)
        picker.close()
    assert picker.snapshot()['state'] == 'closed'


def eventually(condition):
    deadline = time.monotonic() + 5
    while not condition():
        assert time.monotonic() < deadline
        time.sleep(.01)


@pytest.fixture
def environment(tmp_path, monkeypatch):
    launches = []
    runs = []
    gate = Event()
    gate.set()

    def launch(workspace, root, profile_id, **options):
        launches.append((profile_id, options))
        assert gate.wait(5)
        run = SimpleNamespace(session_path=tmp_path / f'{len(runs)}.json',
                              run_id=f'owned-run-{len(runs)}',
                              url=f'http://127.0.0.1:1234/{len(runs)}/',
                              thread=SimpleNamespace(is_alive=lambda: True),
                              running=True, finished=False, closed=False)
        def finish():
            run.running = False
            run.finished = True
        def close():
            finish()
            run.closed = True
        run.finish_browser = finish
        run.close = close
        runs.append(run)
        return run

    monkeypatch.setattr(picker_module, 'start_research', launch)
    monkeypatch.setattr(picker_module, 'session_status',
                        lambda path: {'running': next(r for r in runs if r.session_path == path).running,
                                      'run_id': next(r for r in runs if r.session_path == path).run_id})
    yield tmp_path / 'workspace', launches, runs, gate
    gate.set()


def test_picker_rejects_status_from_a_replaced_run(tmp_path, monkeypatch):
    picker = picker_module.ResearchPicker(tmp_path / 'workspace', ROOT)
    actions = []
    run = SimpleNamespace(
        run_id='owned-run', session_path=tmp_path / 'owned.json',
        url='http://127.0.0.1:1234/owned/',
        thread=SimpleNamespace(is_alive=lambda: True),
        finish_browser=lambda: actions.append('finish'),
        close=lambda: actions.append('close'),
    )
    monkeypatch.setattr(picker_module, 'start_research', lambda *_a, **_k: run)
    monkeypatch.setattr(picker_module, 'session_status',
                        lambda _p: {'run_id': 'replacement-run', 'running': False})
    picker.stop_requested = SimpleNamespace(wait=lambda _timeout: False)
    picker._run({'profile_id': 'saved', 'action': 'open'})
    assert picker.state == 'error'
    assert actions == ['close']


def test_picker_reads_status_inside_the_session_stop_guard(tmp_path, monkeypatch):
    picker = picker_module.ResearchPicker(tmp_path / 'workspace', ROOT)
    path = tmp_path / 'owned.json'
    actions = []
    run = SimpleNamespace(
        run_id='owned-run', session_path=path, url='http://127.0.0.1:1234/owned/',
        thread=SimpleNamespace(is_alive=lambda: True),
        finish_browser=lambda: actions.append('finish'),
        close=lambda: actions.append('close'),
    )
    inside_guard = []

    @contextmanager
    def guard(observed_path, _deadline):
        assert observed_path == path
        inside_guard.append(True)
        try:
            yield
        finally:
            inside_guard.pop()

    def status(_path):
        assert inside_guard, 'picker read mutable session without stop coordination'
        return {'run_id': 'owned-run', 'running': False}

    monkeypatch.setattr(picker_module, 'start_research', lambda *_a, **_k: run)
    monkeypatch.setattr(picker_module, 'session_stop_guard', guard, raising=False)
    monkeypatch.setattr(picker_module, 'session_status', status)
    picker.stop_requested = SimpleNamespace(wait=lambda _timeout: False)
    picker._run({'profile_id': 'saved', 'action': 'open'})
    assert picker.state == 'ready'
    assert actions == ['finish']


def test_picker_retries_a_transient_process_query_denial(tmp_path, monkeypatch):
    picker = picker_module.ResearchPicker(tmp_path / 'workspace', ROOT)
    actions = []
    run = SimpleNamespace(
        run_id='owned-run', session_path=tmp_path / 'owned.json',
        url='http://127.0.0.1:1234/owned/',
        thread=SimpleNamespace(is_alive=lambda: True),
        finish_browser=lambda: actions.append('finish'),
        close=lambda: actions.append('close'),
    )
    calls = []

    def status(_path):
        calls.append(True)
        if len(calls) == 1:
            raise ProcessQueryUnavailable('query not ready')
        return {'run_id': 'owned-run', 'running': False}

    monkeypatch.setattr(picker_module, 'start_research', lambda *_a, **_k: run)
    monkeypatch.setattr(picker_module, 'session_status', status)
    picker.stop_requested = SimpleNamespace(wait=lambda _timeout: False)
    picker._run({'profile_id': 'saved', 'action': 'open'})
    assert picker.state == 'ready'
    assert len(calls) == 2
    assert actions == ['finish']


@contextmanager
def panel(environment):
    work, calls, runs, gate = environment
    server, address = picker_module.create_research_picker(work, ROOT)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.picker, urlsplit(address), calls, runs, gate
    finally:
        gate.set()
        server.shutdown()
        server.server_close()
        thread.join(5)
        assert not thread.is_alive()


def request(url, route='', *, data=None, headers=None, method=None):
    connection = HTTPConnection(url.hostname, url.port, timeout=5)
    method = method or ('GET' if data is None else 'POST')
    defaults = {}
    if method == 'POST':
        defaults = {'Origin': f'http://{url.netloc}', 'Content-Type': 'application/json',
                    'X-Research-Action': url.path.strip('/')}
    defaults.update(headers or {})
    defaults = {key: value for key, value in defaults.items() if value is not None}
    try:
        connection.request(method, url.path + route, body=data, headers=defaults)
        response = connection.getresponse()
        return response.status, dict(response.getheaders()), response.read()
    finally:
        connection.close()


def test_picker_lists_only_safe_summary_and_requires_exact_capability(environment):
    work, _, _, _ = environment
    create_profile(work, 'saved', 'Research <script> text')
    with panel(environment) as (manager, url, calls, runs, gate):
        status, headers, page = request(url)
        assert status == 200 and headers['Cache-Control'] == 'no-store'
        assert "frame-ancestors 'none'" in headers['Content-Security-Policy']
        assert b'__NONCE__' not in page and b'__ACTION_TOKEN__' not in page
        assert b'.innerHTML' not in page and b'.textContent=' in page
        status, _, body = request(url, 'profiles')
        assert status == 200
        assert json.loads(body) == {'profiles': [{'id': 'saved', 'name': 'Research <script> text',
                                               'identity': 'This computer', 'route': 'Default network'}]}
        assert request(url, '../status')[0] == 404
        assert request(url, 'start', method='GET')[0] == 404
        assert not calls


def test_create_stop_review_reopen_and_shutdown_are_owned_and_serial(environment):
    with panel(environment) as (manager, url, calls, runs, gate):
        gate.clear()
        body = b'{"profile_id":"saved","action":"create"}'
        assert request(url, 'start', data=body)[0] == 202
        assert request(url, 'start', data=body)[0] == 409
        assert manager.snapshot()['state'] == 'opening'
        gate.set()
        eventually(lambda: manager.snapshot()['state'] == 'running')
        assert len(calls) == 1 and calls[0][1]['profile_action'] == 'create'
        assert request(url, 'stop', data=b'{}')[0] == 202
        eventually(lambda: manager.snapshot()['state'] == 'ready' and not manager.worker.is_alive())
        assert runs[0].finished and not runs[0].closed
        assert manager.snapshot()['recent'][0]['inspector_url'] == runs[0].url
        assert request(url, 'start', data=b'{"profile_id":"saved","action":"open"}')[0] == 202
        eventually(lambda: len(runs) == 2)
        assert calls[1][1]['profile_action'] == 'open'
    assert all(run.closed for run in runs)


@pytest.mark.parametrize('headers', [
    {'Host': 'evil.example'}, {'Origin': 'https://evil.example'}, {'Origin': None},
    {'X-Research-Action': None}, {'X-Research-Action': 'wrong'},
    {'Sec-Fetch-Site': 'cross-site'}, {'Sec-Fetch-Site': 'same-site'},
])
def test_no_cross_origin_or_uncredentialed_mutations(environment, headers):
    with panel(environment) as (manager, url, calls, runs, gate):
        for endpoint, body in [('start', b'{"profile_id":"saved","action":"create"}'), ('stop', b'{}')]:
            assert request(url, endpoint, data=body, headers=headers)[0] == 403
        assert not calls and manager.snapshot()['state'] == 'ready'


@pytest.mark.parametrize('body', [b'[]', b'{}', b'{"profile_id":"a","action":"delete"}',
    b'{"profile_id":"../x","action":"create"}', b'{"profile_id":"a","action":"open","executable":"x"}',
    b'{"profile_id":"a","profile_id":"b","action":"open"}', b'x' * 1025, b'{',
    b'{"profile_id":"a","action":null}', b'{"profile_id":false,"action":"open"}'])
def test_invalid_actions_do_not_reach_launcher(environment, body):
    with panel(environment) as (manager, url, calls, runs, gate):
        assert request(url, 'start', data=body)[0] == 409
        assert not calls


@pytest.mark.parametrize('headers', [
    {'Content-Type': 'text/plain'}, {'Content-Length': '-1'},
    {'Content-Length': '10000'}, {'Transfer-Encoding': 'chunked'},
])
def test_ambiguous_or_unbounded_request_is_rejected(environment, headers):
    with panel(environment) as (_, url, calls, _, _):
        assert request(url, 'start', data=b'{}', headers=headers)[0] == 409
        assert not calls


def test_picker_post_rejects_body_completed_after_total_read_deadline(
    environment, monkeypatch
):
    work, _, _, _ = environment
    server, address = picker_module.create_research_picker(work, ROOT)
    handler_type = server.RequestHandlerClass
    clock = [0.0]
    statuses = []
    stopped = []
    monkeypatch.setattr(
        picker_module, 'time', SimpleNamespace(monotonic=lambda: clock[0])
    )
    monkeypatch.setattr(handler_type, 'allowed', lambda _self, **_kwargs: True)
    monkeypatch.setattr(
        handler_type, 'send',
        lambda _self, status, _body, _kind='application/json': statuses.append(status)
    )
    monkeypatch.setattr(server.picker, 'stop', lambda: stopped.append(True))

    class Headers:
        def get_all(self, name):
            return {
                'Content-Type': ['application/json'],
                'Content-Length': ['2'],
            }.get(name)

    class Connection:
        def settimeout(self, _timeout):
            return None

    class Body:
        def read(self, _count):
            clock[0] = 6.0
            return b'{}'

        def read1(self, _count):
            clock[0] = 6.0
            return b'{}'

    handler = handler_type.__new__(handler_type)
    handler.path = urlsplit(address).path + 'stop'
    handler.server = server
    handler.headers = Headers()
    handler.connection = Connection()
    handler.rfile = Body()
    try:
        handler.do_POST()
        assert statuses == [409]
        assert stopped == []
    finally:
        server.server_close()


def test_picker_rejection_drain_has_one_total_deadline(environment, monkeypatch):
    work, _, _, _ = environment
    server, _ = picker_module.create_research_picker(work, ROOT)
    handler_type = server.RequestHandlerClass
    clock = [0.0]
    sent = []
    monkeypatch.setattr(
        picker_module, 'time', SimpleNamespace(monotonic=lambda: clock[0])
    )
    monkeypatch.setattr(handler_type, 'send_response',
                        lambda _self, status: sent.append(status))
    monkeypatch.setattr(handler_type, 'send_header', lambda *_args: None)
    monkeypatch.setattr(handler_type, 'end_headers', lambda _self: None)

    class Connection:
        def __init__(self):
            self.reads = 0

        def shutdown(self, _how):
            return None

        def settimeout(self, _timeout):
            return None

        def recv(self, _maximum):
            self.reads += 1
            clock[0] += .049
            return b'x' if self.reads <= 12 else b''

    handler = handler_type.__new__(handler_type)
    handler.command = 'POST'
    handler.connection = Connection()
    handler.wfile = SimpleNamespace(write=lambda _body: None, flush=lambda: None)
    try:
        handler.send(409, b'{}')
        assert sent == [409]
        assert handler.connection.reads <= 6
    finally:
        server.server_close()


def test_corrupt_profile_registry_is_not_reported_as_empty(environment):
    work, _, _, _ = environment
    target = work / 'profiles/registry/broken.json'
    target.parent.mkdir(parents=True)
    target.write_bytes(b'broken')
    with panel(environment) as (_, url, calls, _, _):
        status, _, body = request(url, 'profiles')
        assert status == 409 and b'error' in body and b'profiles' not in body
        assert target.read_bytes() == b'broken' and not calls


def test_profile_response_header_failure_does_not_append_a_second_response(
    environment, monkeypatch
):
    work, _, _, _ = environment
    server, address = picker_module.create_research_picker(work, ROOT)
    handler_type = server.RequestHandlerClass
    sent = []

    def fail_headers(_handler, status):
        sent.append(status)
        raise OSError('response header failed')

    monkeypatch.setattr(handler_type, 'allowed', lambda _self: True)
    monkeypatch.setattr(handler_type, 'send_response', fail_headers)
    monkeypatch.setattr(server.picker, 'profiles', lambda: [])
    handler = handler_type.__new__(handler_type)
    handler.path = urlsplit(address).path + 'profiles'
    handler.server = server
    handler.close_connection = False
    try:
        handler.do_GET()
        assert sent == [200]
        assert handler.close_connection is True
    finally:
        server.server_close()


def test_failed_launch_is_redacted_and_can_be_retried(environment, monkeypatch):
    work, _, _, _ = environment
    manager = picker_module.ResearchPicker(work, ROOT)
    original = picker_module.start_research
    def fail(*args, **kwargs):
        raise ContractError('secret detail must stay off the page')
    monkeypatch.setattr(picker_module, 'start_research', fail)
    try:
        manager.start({'profile_id': 'saved', 'action': 'open'})
        manager.worker.join(5)
        assert manager.snapshot()['state'] == 'error'
        assert 'secret' not in json.dumps(manager.snapshot())
        monkeypatch.setattr(picker_module, 'start_research', original)
        manager.start({'profile_id': 'saved', 'action': 'open'})
        eventually(lambda: manager.snapshot()['state'] == 'running')
    finally:
        manager.close()


def test_closing_during_startup_waits_and_reaps_only_its_new_run(environment):
    work, calls, runs, gate = environment
    manager = picker_module.ResearchPicker(work, ROOT)
    gate.clear()
    manager.start({'profile_id': 'saved', 'action': 'create'})
    closer = Thread(target=manager.close)
    closer.start()
    eventually(manager.closing.is_set)
    with pytest.raises(ContractError):
        manager.start({'profile_id': 'other', 'action': 'create'})
    gate.set()
    closer.join(5)
    assert not closer.is_alive() and not manager.worker.is_alive()
    assert len(calls) == 1 and runs[0].closed and manager.snapshot()['state'] == 'closed'


def test_retained_viewers_are_bounded_without_deleting_recordings(environment, monkeypatch):
    work, calls, runs, _ = environment
    monkeypatch.setattr(picker_module, 'MAX_REVIEWERS', 2)
    manager = picker_module.ResearchPicker(work, ROOT)
    try:
        for i in range(3):
            manager.start({'profile_id': f'saved-{i}', 'action': 'open'})
            eventually(lambda: manager.snapshot()['state'] == 'running')
            runs[i].running = False  # User closes the native browser window.
            manager.worker.join(5)
        assert len(manager.snapshot()['recent']) == 2
        assert runs[0].closed and not runs[1].closed and not runs[2].closed
    finally:
        manager.close()
    assert all(run.closed for run in runs)


def test_cli_without_profile_opens_picker_and_preserves_options(environment, monkeypatch):
    from browser_core.cli import build_parser
    work, _, _, _ = environment
    calls = []
    monkeypatch.setattr(picker_module, 'serve_research_picker', lambda *a, **k: calls.append((a, k)))
    args = build_parser().parse_args(['research', '--workspace', str(work), '--no-open', '--headless', '--recording-limit-mib', '16'])
    assert args.func(args) == 0
    assert calls[0][0] == (work, ROOT)
    assert calls[0][1] == dict(headless=True, executable=None, recording_limit_mib=16, open_browser=False)


def test_picker_and_its_cli_forward_segmented_recording_policy(environment,monkeypatch):
    from browser_core.cli import build_parser
    work,calls,_,_=environment
    manager=picker_module.ResearchPicker(work,ROOT,recording_limit_mib=128,recording_parts=12)
    try:
        manager.start({'profile_id':'segmented','action':'create'})
        eventually(lambda:manager.snapshot()['state']=='running')
        assert calls[0][1]['recording_parts']==12
        assert calls[0][1]['recording_limit_mib']==128
    finally:manager.close()
    served=[]
    monkeypatch.setattr(picker_module,'serve_research_picker',lambda *a,**k:served.append(k))
    args=build_parser().parse_args(['research','--workspace',str(work),'--no-open',
        '--recording-limit-mib','128','--recording-parts','12'])
    assert args.func(args)==0
    assert served[0]['recording_parts']==12 and served[0]['recording_limit_mib']==128


def test_failed_old_viewer_cleanup_blocks_more_launches_until_cleanup(environment, monkeypatch):
    work, calls, runs, _ = environment
    monkeypatch.setattr(picker_module, 'MAX_REVIEWERS', 1)
    manager = picker_module.ResearchPicker(work, ROOT)
    original_close = None
    try:
        manager.start({'profile_id': 'first', 'action': 'open'})
        eventually(lambda: manager.snapshot()['state'] == 'running')
        manager.stop()
        manager.worker.join(5)
        original_close = runs[0].close
        def fail():
            raise ContractError('viewer close failed')
        runs[0].close = fail
        manager.start({'profile_id': 'second', 'action': 'open'})
        eventually(lambda: manager.snapshot()['state'] == 'running')
        manager.stop()
        manager.worker.join(5)
        assert manager.snapshot()['state'] == 'cleanup-error'
        with pytest.raises(ContractError):
            manager.start({'profile_id': 'third', 'action': 'open'})
        assert len(calls) == 2
    finally:
        if original_close:
            runs[0].close = original_close
        manager.close()
    assert all(run.closed for run in runs)


@pytest.mark.parametrize('extra', [['--persona-id', 'example'], ['--exit-with-browser']])
def test_picker_refuses_single_profile_only_flags(environment, extra):
    from browser_core.cli import build_parser
    work, _, _, _ = environment
    args = build_parser().parse_args(['research', '--workspace', str(work), *extra])
    with pytest.raises(ContractError, match='require a profile name'):
        args.func(args)
