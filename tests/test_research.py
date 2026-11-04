from pathlib import Path
from threading import Event, Thread

import pytest

import browser_core.research as research
from browser_core.contracts import ContractError
from browser_core.profiles import create_profile, load_profile

ROOT=Path(__file__).resolve().parents[1]


class FakeServer:
    def __init__(self):
        self.done=Event();self.closed=False
    def serve_forever(self, poll_interval=.5):self.done.wait(10)
    def shutdown(self):self.done.set()
    def server_close(self):self.closed=True


@pytest.fixture
def environment(tmp_path,monkeypatch):
    work=tmp_path/'work';launches=[];stops=[];servers=[]
    monkeypatch.setattr(research,'executable_evidence',lambda *args,**kwargs:{'provenance':'attested-browser-core'})
    def launch(config,root):
        launches.append(config)
        return work/'session.json',{'run_id':'owned-run'}
    def inspector(*args,**kwargs):
        assert kwargs == {'allow_context_identification': True}
        server=FakeServer();servers.append(server)
        return server,'http://127.0.0.1:12345/capability/'
    monkeypatch.setattr(research,'launch_evaluation',launch)
    monkeypatch.setattr(research,'create_inspector',inspector)
    monkeypatch.setattr(research,'stop_session',lambda path,**kwargs:stops.append(path) or {'state':'stopped'})
    monkeypatch.setattr(research,'session_status',lambda path:{'run_id':'owned-run','running':False})
    return work,launches,stops,servers


def test_one_entry_point_creates_then_reuses_profile_and_closes_only_owned_session(environment):
    work,launches,stops,servers=environment
    with research.start_research(work,ROOT,'research-main') as run:
        assert run.created_profile
        assert launches[-1].live_trace and launches[-1].inspect_values
        assert not launches[-1].allow_unverified_executable
        assert launches[-1].profile_id=='research-main'
        assert str(launches[-1].executable).endswith('BrowserCore/chrome.exe') or str(launches[-1].executable).endswith('BrowserCore\\chrome.exe') or launches[-1].executable.name=='chrome'
        original=load_profile(work,'research-main')
        run.wait()
    run.close()
    assert len(stops)==1 and servers[0].closed and not run.thread.is_alive()
    with research.start_research(work,ROOT,'research-main') as repeated:
        assert not repeated.created_profile
        assert load_profile(work,'research-main')==original
    assert len(stops)==2 and all(server.closed for server in servers)


def test_research_wait_rejects_status_from_a_different_run(
    tmp_path, monkeypatch
):
    run = research.ResearchRun.__new__(research.ResearchRun)
    run.session_path = tmp_path / 'owned.json'
    run.session = {'run_id': 'owned-run'}
    run.run_id = 'owned-run'
    run.thread = type('ThreadState', (), {'is_alive': lambda self: True})()
    monkeypatch.setattr(research, 'session_status',
                        lambda _path: {'run_id': 'replacement-run', 'running': False})
    with pytest.raises(ContractError, match='run ID'):
        run.wait()


def test_metadata_only_research_waits_without_an_inspector_thread(tmp_path, monkeypatch):
    path = tmp_path / 'metadata.json'
    run = research.ResearchRun(path, {'run_id': 'owned-run'}, None, None, False)
    states = iter(({'run_id': 'owned-run', 'running': True},
                   {'run_id': 'owned-run', 'running': False}))
    monkeypatch.setattr(research, 'session_status', lambda _path: next(states))
    monkeypatch.setattr(research.time, 'sleep', lambda _seconds: None)
    run.wait()


def test_metadata_only_research_cannot_wait_for_missing_review(tmp_path):
    run = research.ResearchRun(
        tmp_path / 'metadata.json', {'run_id': 'owned-run'}, None, None, False
    )
    with pytest.raises(ContractError, match='inspector'):
        run.wait_for_review()


def test_research_finish_passes_the_owned_run_id_to_stop(tmp_path, monkeypatch):
    captured = []
    monkeypatch.setattr(research, 'stop_session',
                        lambda path, **options: captured.append((path, options)) or
                        {'run_id': 'owned-run', 'state': 'stopped', 'running': False})
    path = tmp_path / 'owned.json'
    run = research.ResearchRun(path, {'run_id': 'owned-run'}, None, None, False)
    run.finish_browser()
    assert captured == [(path, {'timeout_seconds': 40, 'expected_run_id': 'owned-run'})]


def test_bad_runtime_is_rejected_before_profile_creation(environment,monkeypatch):
    work,launches,_,_=environment
    def fail(*args,**kwargs):raise ContractError('runtime mismatch')
    monkeypatch.setattr(research,'executable_evidence',fail)
    with pytest.raises(ContractError,match='runtime mismatch'):
        research.start_research(work,ROOT,'research-main')
    assert not (work/'profiles').exists() and not launches


def test_metadata_agent_keeps_exact_owner_without_private_inspector(environment):
    work,launches,stops,servers=environment
    with research.start_research(work,ROOT,'metadata',metadata_only=True,
                                 extra_args=('--headless',)) as run:
        assert not launches[-1].inspect_values and launches[-1].trace_scope=='broad'
        assert launches[-1].extra_args==('--headless',)
        assert run.server is None and run.thread is None and run.url is None
    run.close()
    assert len(stops)==1 and not servers


def test_metadata_owner_construction_failure_stops_owned_browser(environment, monkeypatch):
    work, launches, stops, servers = environment

    def fail_owner(*_args, **_kwargs):
        raise RuntimeError('owner construction failed')

    monkeypatch.setattr(research, 'ResearchRun', fail_owner)
    with pytest.raises(RuntimeError, match='owner construction failed'):
        research.start_research(work, ROOT, 'metadata', metadata_only=True)
    assert len(launches) == len(stops) == 1
    assert not servers


def test_metadata_agent_rejects_private_inputs_before_profile(environment):
    work,launches,stops,servers=environment
    with pytest.raises(ContractError,match='private hash'):
        research.start_research(work,ROOT,'metadata',metadata_only=True,inspect_hash_inputs=True)
    assert not launches and not (work/'profiles').exists()


def test_hash_input_request_rejects_old_root_before_runtime_or_profile(environment,monkeypatch):
    work, launches, _, _ = environment
    def must_not_read(*args, **kwargs):raise AssertionError('old capability should fail first')
    monkeypatch.setattr(research, 'executable_evidence', must_not_read)
    with pytest.raises(ContractError, match='hashing-input patch'):
        research.start_research(work, ROOT, 'new-input-profile', inspect_hash_inputs=True)
    assert not launches and not (work/'profiles').exists()


def test_research_passes_explicit_hash_input_choice_to_attested_launcher(environment,monkeypatch):
    work, launches, _, _ = environment
    calls = []
    monkeypatch.setattr(research, 'require_inspection_support', lambda root, allowlist: calls.append((root, allowlist)))
    with research.start_research(work, ROOT, 'new-input-profile', inspect_hash_inputs=True):
        assert calls == [(ROOT, 'research-v3')]
        assert launches[-1].inspection_allowlist == 'research-v3'
        assert launches[-1].inspect_values and not launches[-1].allow_unverified_executable


@pytest.mark.parametrize('invalid', [1, None, 'yes'])
def test_research_input_choice_requires_explicit_boolean(environment, invalid):
    work, launches, _, _ = environment
    with pytest.raises(ContractError, match='boolean'):
        research.start_research(work, ROOT, 'new-input-profile', inspect_hash_inputs=invalid)
    assert not launches and not (work/'profiles').exists()


def test_corrupt_existing_profile_is_not_recreated_or_launched(environment):
    work,launches,_,_=environment
    path=work/'profiles/registry/research-main.json';path.parent.mkdir(parents=True)
    path.write_bytes(b'broken')
    with pytest.raises(ContractError):research.start_research(work,ROOT,'research-main')
    assert path.read_bytes()==b'broken' and not launches


def test_existing_profile_identity_cannot_be_changed_implicitly(environment,monkeypatch):
    work,launches,_,_=environment
    original=create_profile(work,'research-main')
    monkeypatch.setattr(research,'load_persona',lambda *args:{'identity_contract':{'expected':{'window.hardwareConcurrency':8}}})
    monkeypatch.setattr(research,'persona_compatible',lambda *args,**kwargs:True)
    with pytest.raises(ContractError,match='different identity'):
        research.start_research(work,ROOT,'research-main',persona_id='another-persona')
    assert not launches and load_profile(work,'research-main')==original


def test_unsupported_persona_fails_before_any_profile_or_browser_is_created(environment,monkeypatch):
    work,launches,_,_=environment
    monkeypatch.setattr(research,'load_persona',lambda *args:{})
    monkeypatch.setattr(research,'persona_compatible',lambda *args,**kwargs:False)
    with pytest.raises(ContractError,match='active desktop persona'):
        research.start_research(work,ROOT,'research-main',persona_id='wrong-engine')
    assert not launches and not (work/'profiles').exists()


def test_inspector_setup_failure_stops_the_new_browser(environment,monkeypatch):
    work,launches,stops,_=environment
    def fail(*args,**kwargs):raise ContractError('inspector unavailable')
    monkeypatch.setattr(research,'create_inspector',fail)
    with pytest.raises(ContractError,match='inspector unavailable'):
        research.start_research(work,ROOT,'research-main')
    assert len(launches)==len(stops)==1
    assert load_profile(work,'research-main')['id']=='research-main'


def test_inspector_setup_failure_stops_only_the_launched_run(environment, monkeypatch):
    work, _, _, _ = environment
    stopped = []

    def fail(*_args, **_kwargs):
        raise ContractError('inspector unavailable')

    monkeypatch.setattr(research, 'create_inspector', fail)
    monkeypatch.setattr(research, 'stop_session',
                        lambda path, **options: stopped.append((path, options)))
    with pytest.raises(ContractError, match='inspector unavailable'):
        research.start_research(work, ROOT, 'research-main')
    assert stopped == [(work / 'session.json', {
        'timeout_seconds': 40, 'expected_run_id': 'owned-run',
    })]


def test_inspector_worker_started_then_reported_failure_is_joined(environment, monkeypatch):
    work, _, stops, servers = environment
    started = []

    class StartedThenRaisedThread(Thread):
        def start(self):
            super().start()
            started.append(self)
            raise RuntimeError('thread started but caller saw an error')

    monkeypatch.setattr(research, 'Thread', StartedThenRaisedThread)
    try:
        with pytest.raises(RuntimeError, match='thread started'):
            research.start_research(work, ROOT, 'research-main')
        assert len(stops) == 1
        assert len(started) == 1
        assert not started[0].is_alive()
        assert servers[0].closed
    finally:
        for server in servers:
            server.done.set()
        for thread in started:
            thread.join(5)


def test_inspector_that_exits_during_startup_does_not_publish_run(
    environment, monkeypatch
):
    work, launches, stops, servers = environment

    class ExitedServer(FakeServer):
        def serve_forever(self, poll_interval=.5):
            return

    class CompletedThread(Thread):
        def start(self):
            super().start()
            self.join(1)

    server = ExitedServer()
    servers.append(server)
    monkeypatch.setattr(
        research,
        'create_inspector',
        lambda *_args, **_kwargs: (server, 'http://127.0.0.1:12345/'),
    )
    monkeypatch.setattr(research, 'Thread', CompletedThread)

    with pytest.raises(ContractError, match='inspector stopped during startup'):
        research.start_research(work, ROOT, 'research-main')

    assert len(launches) == len(stops) == 1
    assert server.closed


def test_research_close_releases_panel_after_shutdown_error(tmp_path, monkeypatch):
    class FaultyServer(FakeServer):
        def shutdown(self):
            self.done.set()
            raise RuntimeError('panel shutdown reported an error')

    server = FaultyServer()
    stopped = []
    monkeypatch.setattr(research, 'stop_session',
                        lambda path, **kwargs: stopped.append((path, kwargs)) or {'state': 'stopped'})
    run = research.ResearchRun(tmp_path / 'session.json', {'run_id': 'owned-run'},
                               server, 'http://127.0.0.1:12345/', False)
    try:
        with pytest.raises(RuntimeError, match='panel shutdown'):
            run.close()
        assert server.closed
        assert not run.thread.is_alive()
        assert run.inspector_closed
        assert len(stopped) == 1
    finally:
        server.done.set()
        run.thread.join(5)


def test_failed_inspector_cleanup_still_stops_owned_browser(environment, monkeypatch):
    work, _, stops, servers = environment
    class FaultyServer(FakeServer):
        def server_close(self):
            super().server_close()
            raise RuntimeError('panel close reported an error')

    server = FaultyServer()
    monkeypatch.setattr(research, 'create_inspector',
                        lambda *_args, **_kwargs: (server, 'http://127.0.0.1:12345/'))
    monkeypatch.setattr(research, 'ResearchRun',
                        lambda *_args, **_kwargs: (_ for _ in ()).throw(ContractError('construction failed')))
    with pytest.raises(RuntimeError, match='panel close'):
        research.start_research(work, ROOT, 'research-main')
    assert server.closed
    assert len(stops) == 1


def test_failed_launch_retains_the_new_named_profile_for_retry(environment,monkeypatch):
    work,_,stops,_=environment
    def fail(*args):raise ContractError('launcher failure')
    monkeypatch.setattr(research,'launch_evaluation',fail)
    with pytest.raises(ContractError,match='launcher failure'):
        research.start_research(work,ROOT,'research-main')
    assert load_profile(work,'research-main')['id']=='research-main'
    assert not stops  # Launcher owns cleanup before it returns a session.


def test_cli_research_uses_one_profile_and_prints_its_inspector(environment,capsys):
    from browser_core.cli import build_parser
    work,launches,stops,_=environment
    args=build_parser().parse_args(['research','research-main','--workspace',str(work),'--headless','--no-open','--exit-with-browser'])
    assert args.func(args)==0
    assert launches[0].headless and len(stops)==1
    assert 'inspector_url' in capsys.readouterr().out


def test_cli_segmented_research_preserves_explicit_recording_policy(environment,capsys):
    from browser_core.cli import build_parser
    work,launches,stops,_=environment
    args=build_parser().parse_args(['research','research-main','--workspace',str(work),
        '--headless','--no-open','--exit-with-browser','--recording-limit-mib','128',
        '--recording-parts','12'])
    assert args.func(args)==0
    assert launches[0].recording_limit_mib==128 and launches[0].recording_parts==12
    assert len(stops)==1


def test_default_research_keeps_viewer_available_after_browser_exit(environment,monkeypatch,capsys):
    from browser_core.cli import build_parser
    work,launches,stops,servers=environment
    def review(run):
        assert len(stops)==1 and run.thread.is_alive() and not servers[0].closed
        raise KeyboardInterrupt()
    monkeypatch.setattr(research.ResearchRun,'wait_for_review',review)
    args=build_parser().parse_args(['research','research-main','--workspace',str(work),'--headless','--no-open'])
    assert args.func(args)==0
    assert len(stops)==1 and servers[0].closed
    assert 'recording_review_available' in capsys.readouterr().out


def test_explicit_open_never_recreates_a_missing_saved_profile(environment):
    work, launches, _, _ = environment
    with pytest.raises(ContractError):
        research.start_research(work, ROOT, 'missing', profile_action='open')
    assert not launches and not (work/'profiles').exists()


def test_explicit_create_never_opens_an_existing_profile(environment):
    work, launches, _, _ = environment
    saved = create_profile(work, 'existing')
    with pytest.raises(ContractError, match='already exists'):
        research.start_research(work, ROOT, 'existing', profile_action='create')
    assert not launches and load_profile(work, 'existing') == saved
