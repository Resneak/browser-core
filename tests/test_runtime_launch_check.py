"""The optional setup probe must prove startup and cleanup separately from hashes."""
import json
import os
import subprocess
from pathlib import Path

import pytest

import browser_core.runtime_check as checker
from browser_core.contracts import ContractError, SESSION_SCHEMA
from browser_core.control_files import BoundedControlSnapshot

ROOT=Path(__file__).resolve().parents[1]


@pytest.fixture
def probe(tmp_path,monkeypatch):
    events=[]
    state={'renderer':True,'stop_mode':'graceful','leave_profile':False}
    out=tmp_path/'fresh-check'
    exe=tmp_path/'chrome.exe'
    def files(*args):
        events.append('files')
        return {'runtime_verified':True,'status':'verified','code':'verified'}
    def launch(config,root):
        events.append('launch')
        assert root==ROOT and config.workspace==out
        assert config.profile_id is None and config.persona_id is None and config.network_route_id is None
        assert not config.allow_unverified_executable and config.extra_args==()
        assert config.trace_mode=='off'
        state['config']=config
        if state.get('launch_error'):raise state['launch_error']
        profile=out/'profiles/ephemeral/owned-check';profile.mkdir(parents=True)
        path=out/'sessions/owned-check.json';path.parent.mkdir()
        document={'schema':SESSION_SCHEMA,'run_id':'owned-check',
                  'chromium_revision':'a'*40,'pid':1234,
                  'profile':{'id':None,'path':str(profile),'persistence':'ephemeral','lock_path':None},
                  'automation':{'transport':'cdp','cdp_endpoint':'http://127.0.0.1:12345',
                                'managed_target_url':'about:blank#owned'}}
        path.write_text(json.dumps(document),encoding='utf-8')
        state.update(path=path,profile=profile)
        return path,document
    def renderer(endpoint,expression,**kwargs):
        events.append('renderer')
        assert endpoint=='http://127.0.0.1:12345' and kwargs['target_url']=='about:blank#owned'
        if isinstance(state['renderer'],BaseException):raise state['renderer']
        return state['renderer']
    def stop(path,**kwargs):
        events.append('stop')
        assert path==state['path'] and kwargs['timeout_seconds']==40
        if state.get('stop_errors'):
            error=state['stop_errors'].pop(0)
            if error:raise error
        if not state['leave_profile']:state['profile'].rmdir()
        stopped_document=json.loads(path.read_text(encoding='utf-8'))
        stopped_document['state']='stopped'
        stopped_document['stopped_at']='2026-10-27T00:00:00Z'
        path.write_text(json.dumps(stopped_document),encoding='utf-8')
        return {'run_id':'owned-check','state':'stopped','running':False,
                'identity_protected':True,'shutdown_mode':state['stop_mode']}
    def status(path):
        events.append('status')
        return {'run_id':'owned-check','state':'stopped','running':False,'identity_protected':True}
    for name,value in [('check_runtime',files),('launch_evaluation',launch),
                       ('evaluate_page_expression',renderer),('stop_session',stop),('session_status',status)]:
        monkeypatch.setattr(checker,name,value,raising=False)
    return out,exe,state,events


def run(probe,**kwargs):
    out,exe,_,_=probe
    return checker.check_runtime_launch(ROOT,exe,out,**kwargs)


def test_explicit_launch_check_requires_renderer_and_verified_cleanup(probe):
    out,_,state,events=probe
    result=run(probe)
    assert result['status']=='passed' and result['launch_verified']
    assert result['browser_started'] is True and result['renderer_verified'] is True
    assert result['cleanup_verified'] is True and result['shutdown_mode']=='graceful'
    assert events==['files','launch','renderer','stop','status']
    assert state['config'].headless is False
    assert not state['profile'].exists()
    saved=json.loads((out/'runtime-launch-check.json').read_text(encoding='utf-8'))
    assert saved==result and result['receipt_written'] is True
    assert '12345' not in json.dumps(result) and 'about:blank#owned' not in json.dumps(result)


def test_probe_rejects_bad_files_before_creating_output_or_browser(probe,monkeypatch):
    out,_,_,events=probe
    monkeypatch.setattr(checker,'check_runtime',lambda *a:{'runtime_verified':False,'code':'artifact-mismatch'})
    result=run(probe)
    assert result['code']=='file-verification-failed' and not result['launch_verified']
    assert result['file_check']['code']=='artifact-mismatch'
    assert result['browser_started'] is False and not out.exists() and not events


def test_probe_never_reuses_or_modifies_an_existing_output(probe):
    out,_,_,events=probe
    out.mkdir();sentinel=out/'keep.txt';sentinel.write_text('keep')
    result=run(probe)
    assert result['code']=='invalid-output' and not result['launch_verified']
    assert sentinel.read_text()=='keep' and list(out.iterdir())==[sentinel] and not events


def test_new_output_without_custody_reports_residue_before_launch(probe, monkeypatch):
    out, _, _, events = probe
    original = checker.directory_identity

    def unavailable(path, *, label):
        if path == out:
            return None
        return original(path, label=label)

    monkeypatch.setattr(checker, 'directory_identity', unavailable)
    result = run(probe)
    assert result['code'] == 'output-custody-unavailable'
    assert out.is_dir() and result['receipt_written'] is False
    assert result['launch_attempted'] is False and result['cleanup_verified'] is None
    assert events == ['files']
    validator = pytest.importorskip('jsonschema')
    schema = json.loads((ROOT / 'schemas/runtime-launch-check-v1.schema.json').read_text(encoding='utf-8'))
    validator.Draft202012Validator(schema).validate(result)


@pytest.mark.parametrize('value',[False,1,ContractError('private renderer marker'),KeyboardInterrupt()])
def test_renderer_failure_or_interruption_still_closes_owned_browser(probe,value):
    out,_,state,events=probe;state['renderer']=value
    result=run(probe)
    assert not result['launch_verified'] and result['cleanup_verified'] is True
    assert result['code']==('interrupted' if isinstance(value,KeyboardInterrupt) else 'renderer-unavailable')
    assert events[-2:]==['stop','status'] and not state['profile'].exists()
    assert 'private renderer marker' not in json.dumps(result)
    assert (out/'runtime-launch-check.json').is_file()


@pytest.mark.parametrize('error',[
    ContractError('private launch marker'),
    RuntimeError('private launch marker'),
])
def test_failed_launch_does_not_invent_a_successful_rollback(probe,error):
    _,_,state,events=probe;state['launch_error']=error
    result=run(probe)
    assert result['code']=='launch-failed' and result['launch_attempted']
    assert result['browser_started'] is None and result['cleanup_verified'] is None
    assert events==['files','launch'] and 'private launch marker' not in json.dumps(result)


@pytest.mark.parametrize('message', [
    'Windows native path alias is unavailable; choose a shorter workspace',
    'Windows native path is too deep; choose a shorter workspace',
])
def test_known_path_failures_have_an_actionable_code_without_claiming_cleanup(probe, message):
    probe[2]['launch_error'] = ContractError(message)
    result = run(probe)
    assert result['code'] == 'workspace-path-unavailable'
    assert result['browser_started'] is None and result['cleanup_verified'] is None


@pytest.mark.parametrize('mode',['forced','exited-before-force'])
def test_forced_or_unexpected_exit_is_not_a_startup_quality_pass(probe,mode):
    _,_,state,_=probe;state['stop_mode']=mode
    result=run(probe)
    assert result['code']=='non-graceful-stop' and not result['launch_verified']
    assert result['cleanup_verified'] is True


def test_retained_ephemeral_profile_fails_cleanup_gate(probe):
    _,_,state,_=probe;state['leave_profile']=True
    result=run(probe)
    assert result['code']=='cleanup-failed' and result['cleanup_verified'] is False
    assert not result['launch_verified']


def test_profile_entry_that_exists_without_a_target_fails_cleanup_gate(probe, monkeypatch):
    _, _, state, _ = probe
    state['leave_profile'] = True
    original_exists = Path.exists

    def broken_link_exists(path):
        # Path.exists() follows a link, so a dangling profile link looks absent.
        if path == state.get('profile'):
            return False
        return original_exists(path)

    monkeypatch.setattr(Path, 'exists', broken_link_exists)
    result = run(probe)
    assert result['code'] == 'cleanup-failed'
    assert result['cleanup_verified'] is False
    assert not result['launch_verified']


@pytest.mark.skipif(os.name != 'nt', reason='Windows junction behavior')
def test_dangling_profile_junction_fails_cleanup_gate(probe, monkeypatch):
    _, _, state, _ = probe
    original_stop = checker.stop_session

    def stop_then_replace_profile_with_junction(path, **kwargs):
        receipt = original_stop(path, **kwargs)
        profile = state['profile']
        target = profile.with_name('removed-target')
        target.mkdir()
        try:
            subprocess.run(
                ['cmd', '/c', 'mklink', '/J', str(profile), str(target)],
                check=True,
                capture_output=True,
                text=True,
            )
        finally:
            target.rmdir()
        assert os.path.lexists(profile) and not profile.exists()
        return receipt

    monkeypatch.setattr(checker, 'stop_session', stop_then_replace_profile_with_junction)
    try:
        result = run(probe)
        assert result['code'] == 'cleanup-failed'
        assert result['cleanup_verified'] is False
    finally:
        if os.path.lexists(state.get('profile', '')):
            state['profile'].rmdir()


def test_cleanup_failure_retains_actionable_session_receipt_without_exception_text(probe):
    out,_,state,_=probe;state['stop_errors']=[ContractError('private stop marker')]
    result=run(probe)
    assert result['code']=='cleanup-failed' and result['cleanup_verified'] is False
    assert result['session_file']=='sessions/owned-check.json'
    assert (out/result['session_file']).exists() and 'private stop marker' not in json.dumps(result)


def test_interrupt_during_cleanup_retries_only_the_same_owned_session(probe):
    _,_,state,events=probe;state['stop_errors']=[KeyboardInterrupt(),None]
    result=run(probe)
    assert result['code']=='interrupted' and result['cleanup_verified'] is True
    assert events.count('launch')==1 and events.count('stop')==2


def test_headless_mode_is_an_explicit_request(probe):
    result=run(probe,headless=True)
    assert result['launch_verified'] and result['headless_requested'] is True
    assert probe[2]['config'].headless is True


def test_fresh_status_disagreement_prevents_cleanup_pass(probe, monkeypatch):
    monkeypatch.setattr(checker, 'session_status', lambda path: {
        'state': 'running', 'running': True, 'identity_protected': True})
    result = run(probe)
    assert result['code'] == 'cleanup-failed'
    assert result['cleanup_verified'] is False and not result['launch_verified']


@pytest.mark.parametrize('source',['stop_session','session_status'])
def test_cleanup_receipts_must_belong_to_launched_run(probe,monkeypatch,source):
    original=getattr(checker,source)
    monkeypatch.setattr(checker,source,lambda *args,**kwargs:{**original(*args,**kwargs),
        'run_id':'other-run'})
    result=run(probe)
    assert result['code']=='cleanup-failed'
    assert result['cleanup_verified'] is False and not result['launch_verified']


def test_unavailable_session_receipt_preserves_observed_cleanup(probe, monkeypatch):
    _, _, state, _ = probe
    original_read = checker.read_bounded_control_snapshot_result

    def unavailable(path, **kwargs):
        if path == state['path']:
            return BoundedControlSnapshot('missing')
        return original_read(path, **kwargs)

    monkeypatch.setattr(checker, 'read_bounded_control_snapshot_result', unavailable)
    result = run(probe)
    assert result['code'] == 'session-receipt-unavailable'
    assert result['cleanup_verified'] is True and result['session_sha256'] is None
    assert result['receipt_written'] is True and not result['launch_verified']


@pytest.mark.parametrize('changed_field', [
    'run-id', 'profile-path', 'state', 'automation', 'stopped-at',
    'missing-stopped-at',
])
def test_changed_session_receipt_cannot_support_a_launch_pass(probe, monkeypatch, changed_field):
    out, _, state, _ = probe
    original_status = checker.session_status

    def status_then_replace_run(path):
        observed = original_status(path)
        document = json.loads(path.read_text(encoding='utf-8'))
        if changed_field == 'run-id':
            document['run_id'] = 'other-check'
        elif changed_field == 'profile-path':
            document['profile']['path'] = str(out / 'profiles/ephemeral/other-check')
        elif changed_field == 'state':
            document['state'] = 'active'
        elif changed_field == 'stopped-at':
            document['stopped_at'] = 'not-a-timestamp'
        elif changed_field == 'missing-stopped-at':
            del document['stopped_at']
        else:
            document['automation']['cdp_endpoint'] = 'http://127.0.0.1:54321'
        path.write_text(json.dumps(document), encoding='utf-8')
        return observed

    monkeypatch.setattr(checker, 'session_status', status_then_replace_run)
    result = run(probe)
    assert state['path'] == out / 'sessions/owned-check.json'
    assert result['cleanup_verified'] is True
    assert result['code'] == 'session-receipt-unavailable'
    assert result['launch_verified'] is False


def test_hardlinked_session_receipt_cannot_support_a_launch_pass(probe, tmp_path, monkeypatch):
    _, _, state, _ = probe
    original_status = checker.session_status

    def status_then_link(path):
        observed = original_status(path)
        os.link(path, tmp_path / 'outside-session.json')
        return observed

    monkeypatch.setattr(checker, 'session_status', status_then_link)
    result = run(probe)
    assert state['path'].is_file()
    assert result['cleanup_verified'] is True
    assert result['code'] == 'session-receipt-unavailable'
    assert result['launch_verified'] is False


def test_report_publication_failure_preserves_cleanup_and_has_no_raw_exception(probe, monkeypatch):
    def unavailable(*args, **kwargs):
        raise PermissionError('private output marker')
    monkeypatch.setattr(checker, 'publish_json_exclusive_result', unavailable)
    result = run(probe)
    assert result['code'] == 'receipt-unavailable' and not result['receipt_written']
    assert result['cleanup_verified'] is True and not result['launch_verified']
    assert 'private output marker' not in json.dumps(result)


@pytest.mark.parametrize('change', ['content', 'replacement'])
def test_report_changed_after_publication_cannot_support_a_launch_pass(probe, monkeypatch, change):
    out, _, _, _ = probe

    def wrap_publisher(original):
        def publish_then_change(path, document, **kwargs):
            published = original(path, document, **kwargs)
            if change == 'content':
                path.write_bytes(b'{}')
            else:
                replacement = path.with_suffix('.replacement')
                replacement.write_bytes(path.read_bytes())
                replacement.replace(path)
            return published
        return publish_then_change

    monkeypatch.setattr(
        checker,
        'publish_json_exclusive_result',
        wrap_publisher(checker.publish_json_exclusive_result),
    )
    result = run(probe)
    assert out.is_dir()
    assert result['cleanup_verified'] is True
    assert result['code'] == 'receipt-unavailable'
    assert result['receipt_written'] is False
    assert result['launch_verified'] is False


def test_probe_rejects_relocated_output_ancestor_before_receipt(
    probe, tmp_path, monkeypatch
):
    out, _, state, _ = probe
    original_read = checker.read_bounded_control_snapshot_result
    retained = tmp_path.with_name(tmp_path.name + '-retained')

    def relocate_after_session_read(path, **kwargs):
        body = original_read(path, **kwargs)
        if path == state['path']:
            tmp_path.rename(retained)
            tmp_path.mkdir()
            (retained / out.name).rename(out)
        return body

    monkeypatch.setattr(checker, 'read_bounded_control_snapshot_result', relocate_after_session_read)
    result = run(probe)

    assert result['code'] == 'receipt-unavailable'
    assert result['receipt_written'] is False
    assert not (out / 'runtime-launch-check.json').exists()


def test_probe_does_not_launch_after_output_ancestor_moves(
    probe, tmp_path, monkeypatch
):
    out, _, _, events = probe
    original_binding = checker.directory_ancestry_binding
    retained = tmp_path.with_name(tmp_path.name + '-prelaunch')
    relocated = False

    def relocate_after_output_binding(path, *, label):
        nonlocal relocated
        binding = original_binding(path, label=label)
        if path == out and not relocated:
            relocated = True
            tmp_path.rename(retained)
            tmp_path.mkdir()
            (retained / out.name).rename(out)
        return binding

    monkeypatch.setattr(checker, 'directory_ancestry_binding', relocate_after_output_binding)
    result = run(probe)

    assert relocated
    assert events == ['files']
    assert result['launch_attempted'] is False
    assert result['receipt_written'] is False


def test_existing_report_is_never_overwritten(probe, monkeypatch):
    out, _, _, _ = probe
    old_status = checker.session_status
    def status(path):
        (out / 'runtime-launch-check.json').write_text('preserve', encoding='utf-8')
        return old_status(path)
    monkeypatch.setattr(checker, 'session_status', status)
    result = run(probe)
    assert result['code'] == 'receipt-unavailable' and result['cleanup_verified'] is True
    assert (out / 'runtime-launch-check.json').read_text(encoding='utf-8') == 'preserve'


@pytest.mark.parametrize('output', ['relative-check', 'package', 'missing-parent'])
def test_invalid_output_rejected_before_file_or_process_work(probe, output):
    out, exe, _, events = probe
    path = {'relative-check': Path('relative-check'), 'package': ROOT / 'probe',
            'missing-parent': out / 'absent-parent' / 'probe'}[output]
    result = checker.check_runtime_launch(ROOT, exe, path)
    assert result['code'] == 'invalid-output' and not events
    assert result['launch_attempted'] is False and result['cleanup_verified'] is None


def test_cli_distinguishes_launch_check_from_the_file_only_doctor(probe,monkeypatch,capsys):
    import browser_core.cli as cli
    out,exe,_,_=probe
    assert cli.main(['doctor','--executable',str(exe),'--launch-check',str(out),'--headless'])==0
    result=json.loads(capsys.readouterr().out)
    assert result['launch_verified'] and result['schema']=='browser-core.runtime-launch-check/1'


def test_cli_interruption_returns_130_after_cleanup(probe, capsys):
    import browser_core.cli as cli
    out, exe, state, _ = probe
    state['renderer'] = KeyboardInterrupt()
    assert cli.main(['doctor', '--executable', str(exe), '--launch-check', str(out)]) == 130
    result = json.loads(capsys.readouterr().out)
    assert result['code'] == 'interrupted' and result['cleanup_verified'] is True


@pytest.mark.parametrize('case', ['passed', 'renderer-failed', 'launch-failed', 'forced'])
def test_published_schema_accepts_real_results_and_rejects_false_success(probe, case):
    validator = pytest.importorskip('jsonschema')
    state = probe[2]
    if case == 'renderer-failed':
        state['renderer'] = False
    elif case == 'launch-failed':
        state['launch_error'] = ContractError('launch did not complete')
    elif case == 'forced':
        state['stop_mode'] = 'forced'
    schema = json.loads((ROOT / 'schemas/runtime-launch-check-v1.schema.json').read_text(encoding='utf-8'))
    result = run(probe)
    validator.Draft202012Validator(schema).validate(result)
    if result['launch_verified']:
        result['cleanup_verified'] = False
    else:
        result['launch_verified'] = True
    with pytest.raises(validator.ValidationError):
        validator.Draft202012Validator(schema).validate(result)


@pytest.mark.parametrize('args',[
    ['doctor','--launch-check','C:/fresh-check'],
    ['doctor','--executable','C:/chrome.exe','--headless'],
])
def test_cli_refuses_incomplete_or_misleading_launch_options(args,capsys):
    import browser_core.cli as cli
    assert cli.main(args)==2
    assert 'browser-core:' in capsys.readouterr().err
