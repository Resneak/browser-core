from pathlib import Path
import json
import os
import subprocess

import pytest

import browser_core.cli as cli
from browser_core.contracts import ContractError, validate_session
from browser_core.launcher import EvaluationLaunch, evaluation_command, validate_evaluation_launch


def _session():
    return {'schema': 'browser-core.session/1', 'run_id': 'live-test',
            'chromium_revision': 'a'*40, 'pid': 123,
            'trace_mode': 'on', 'trace_path': '/owned/trace.perfetto-trace',
            'live_trace': {'schema': 'browser-core.live-trace/1',
                           'path': '/owned/trace.perfetto-trace.live'},
            'automation': {'transport': 'cdp', 'cdp_endpoint': 'http://127.0.0.1:9222'}}


def test_live_session_retains_existing_control_boundary():
    document = _session()
    assert validate_session(document)['live_trace'] == document['live_trace']
    del document['live_trace']
    assert validate_session(document) == document


@pytest.mark.parametrize('change', ['path', 'schema', 'off', 'extra', 'null'])
def test_live_contract_rejects_wrong_artifact_or_mode(change):
    document = _session()
    if change == 'path':
        document['live_trace']['path'] = '/another/capture.live'
    elif change == 'schema':
        document['live_trace']['schema'] = 'unknown'
    elif change == 'off':
        document['trace_mode'] = 'off'
        document['trace_path'] = None
    elif change == 'extra':
        document['live_trace']['unexpected'] = True
    else:
        document['live_trace'] = None
    with pytest.raises(ContractError):
        validate_session(document)


@pytest.mark.parametrize('headless', [True, False])
def test_live_recording_is_explicit_in_both_launch_modes(tmp_path, headless):
    args = (tmp_path/'chrome.exe', tmp_path/'profile', tmp_path/'trace', 'live-test')
    normal = evaluation_command(*args, headless=headless, extra_args=())
    live = evaluation_command(*args, headless=headless, extra_args=(), live_trace=True)
    assert '--browser-core-live-trace' not in normal
    additions={'--browser-core-live-trace','--browser-core-recording-limit-mib=1024'}
    assert additions.issubset(live)
    assert [arg for arg in live if arg not in additions] == normal


@pytest.mark.parametrize('changes', [dict(live_trace=1), dict(live_trace=True, trace_mode='off'),
                                    dict(live_trace=True, allow_unverified_executable=True),
                                    dict(extra_args=('--browser-core-live-trace',))])
def test_invalid_live_setup_fails_before_launch(tmp_path, changes):
    config = EvaluationLaunch(tmp_path/'chrome.exe', tmp_path, **changes)
    with pytest.raises(ContractError):
        validate_evaluation_launch(config)


def test_cli_passes_managed_live_option_into_launch(tmp_path, monkeypatch, capsys):
    observed = {}
    def launch(config, root):
        observed['config'] = config
        return tmp_path/'session.json', _session()
    monkeypatch.setattr(cli, 'launch_evaluation', launch)
    args = cli.build_parser().parse_args(['launch-eval', '--executable', str(tmp_path/'chrome.exe'),
                                          '--workspace', str(tmp_path), '--live-trace'])
    assert args.func(args) == 0
    assert observed['config'].live_trace is True
    assert observed['config'].extra_args == ()


def test_cli_live_summary_is_read_only_and_bounded_by_default():
    args = cli.build_parser().parse_args(['trace', 'live-summary', '--session', '/owned/session.json'])
    assert args.session == Path('/owned/session.json')
    assert args.limit == 100


@pytest.mark.parametrize('original_running, matching_build', [(True, True), (False, True), (True, False)])
def test_live_preview_requires_original_process_and_attested_build(tmp_path, monkeypatch,
                                                                  original_running, matching_build):
    import browser_core.build as build
    import browser_core.lifecycle as lifecycle
    from browser_core.live_trace import live_trace_summary
    document = _session()
    document['executable'] = str(tmp_path/'chrome.exe')
    document['trace_path'] = str(tmp_path/'trace.perfetto-trace')
    document['live_trace']['path'] = document['trace_path'] + '.live'
    document['build'] = {'provenance': 'attested-browser-core', 'executable_sha256_16': 'a'*16}
    Path(document['live_trace']['path']).touch()
    session_file = tmp_path/'session.json'
    session_file.write_text(json.dumps(document), encoding='utf-8')
    monkeypatch.setattr(lifecycle, 'session_status', lambda path:
                        {'run_id': document['run_id'], 'running': original_running})
    def evidence(root, executable, *, allow_unverified):
        assert allow_unverified is False
        return document['build'] if matching_build else {
            'provenance': 'attested-browser-core', 'executable_sha256_16': 'b'*16}
    monkeypatch.setattr(build, 'executable_evidence', evidence)
    if original_running and matching_build:
        result = live_trace_summary(session_file, tmp_path)
        assert result['complete'] is False
        assert result['browser_running'] is True
        assert result['groups'] == []
        assert result['total_events'] == 0
        assert result['limits']['absence_proves_nonexecution'] is False
        assert result['limits']['names_omitted_below_display_limit'] is False
    else:
        with pytest.raises(ContractError):
            live_trace_summary(session_file, tmp_path)


@pytest.mark.skipif(os.name != 'nt', reason='Windows junction ancestry')
@pytest.mark.parametrize('read_kind', ['verified-source', 'snapshot', 'summary'])
def test_legacy_live_reader_rejects_relocated_source_parent(
    tmp_path, monkeypatch, read_kind,
):
    import browser_core.build as build
    import browser_core.lifecycle as lifecycle
    from browser_core.live_trace import (
        live_trace_summary, snapshot_live_trace, verified_live_source,
    )

    original_parent = tmp_path / 'recording'
    original_parent.mkdir()
    source = original_parent / 'trace.live'
    source.write_bytes(b'')
    session = _session()
    session['executable'] = str(tmp_path / 'chrome.exe')
    session['trace_path'] = str(original_parent / 'trace')
    session['live_trace']['path'] = str(source)
    session['build'] = {
        'provenance': 'attested-browser-core', 'executable_sha256_16': 'a' * 16,
    }
    session_file = tmp_path / 'session.json'
    session_file.write_text(json.dumps(session), encoding='utf-8')
    monkeypatch.setattr(build, 'executable_evidence', lambda *_args, **_kwargs: session['build'])

    moved_parent = tmp_path / 'moved-recording'
    linked = False

    def relocate() -> None:
        nonlocal linked
        original_parent.rename(moved_parent)
        result = subprocess.run(
            ['cmd', '/c', 'mklink', '/J', str(original_parent), str(moved_parent)],
            capture_output=True, text=True, check=False,
        )
        if result.returncode != 0:
            pytest.skip('host could not create an unprivileged directory junction')
        linked = True

    monkeypatch.setattr(
        lifecycle, 'session_status',
        lambda _path: {'run_id': session['run_id'], 'running': True},
    )
    relocate()
    try:
        with pytest.raises(ContractError, match='live trace source parent'):
            if read_kind == 'verified-source':
                verified_live_source(session_file, tmp_path)
            elif read_kind == 'snapshot':
                with snapshot_live_trace(source):
                    pytest.fail('linked recording source was opened')
            else:
                live_trace_summary(session_file, tmp_path)
    finally:
        if linked:
            original_parent.rmdir()
