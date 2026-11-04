from pathlib import Path
import os

import pytest

import browser_core.live_trace as live_trace_module
from browser_core.contracts import ContractError,validate_session
from browser_core.launcher import EvaluationLaunch,evaluation_command,validate_evaluation_launch
from browser_core.recording_limits import MIB,recording_limit_bytes,limit_marker_path,observe_recording_limit
from browser_core.recording_source import RecordingSource
from browser_core.incremental_inspection import IncrementalInspection
from test_recording_recovery import source,FakeDecoder


@pytest.fixture
def limited(source):
    source.session['live_trace']['byte_limit']=8*MIB;source.save()
    source.marker=limit_marker_path(source.final);source.marker.write_bytes(b'')
    return source


@pytest.mark.parametrize('value',[0,3,1025,True,8.0,'8',-1])
def test_invalid_budgets_fail_before_launch(tmp_path,value):
    config=EvaluationLaunch(tmp_path/'chrome.exe',tmp_path,live_trace=True,recording_limit_mib=value)
    with pytest.raises(ContractError,match='recording limit'):validate_evaluation_launch(config)


@pytest.mark.parametrize('value',[4,8,1024,None])
def test_managed_budget_is_the_only_native_switch_and_preserves_default(tmp_path,value):
    command=evaluation_command(tmp_path/'chrome.exe',tmp_path/'profile',tmp_path/'trace','owned-run',
        headless=True,extra_args=(),live_trace=True,recording_limit_mib=value)
    assert f'--browser-core-recording-limit-mib={value or 1024}' in command
    assert recording_limit_bytes(value,live=True)==(value or 1024)*MIB


def test_budget_requires_live_recording_and_cannot_be_injected_as_extra_argument(tmp_path):
    with pytest.raises(ContractError,match='requires live recording'):
        validate_evaluation_launch(EvaluationLaunch(tmp_path/'chrome.exe',tmp_path,recording_limit_mib=8))
    with pytest.raises(ContractError,match='managed recording-limit'):
        validate_evaluation_launch(EvaluationLaunch(tmp_path/'chrome.exe',tmp_path,
            extra_args=('--browser-core-recording-limit-mib=8',)))


@pytest.mark.parametrize('value',[True,0,3*MIB,8*MIB+1,1025*MIB,'8388608',None])
def test_session_budget_is_a_closed_bounded_integer(source,value):
    source.session['live_trace']['byte_limit']=value
    with pytest.raises(ContractError,match='byte limit'):validate_session(source.session)


def test_bound_marker_retires_capture_while_browser_is_still_running(limited):
    location=limited.reader.resolve()
    assert location.phase=='limited-recording' and location.browser_running
    assert location.recording_limit=={'reason':'byte-limit','byte_limit':8*MIB,'written_bytes':5}
    assert limited.reader.retired
    limited.status.update(state='stopped',running=False)
    reopened=RecordingSource(limited.document,limited.document.parent).resolve()
    assert reopened.phase=='limited-recording' and not reopened.browser_running
    assert limited.path.read_bytes()==b'\x0a\x03abc' and not limited.final.exists()


def test_without_marker_recording_remains_live_and_legacy_sessions_are_unchanged(source):
    assert source.reader.resolve().phase=='live-prefix'
    source.session['live_trace']['byte_limit']=8*MIB;source.save()
    assert RecordingSource(source.document,source.document.parent).resolve().phase=='live-prefix'


@pytest.mark.parametrize('marker_present', [False, True])
@pytest.mark.parametrize('extra_byte', [False, True])
def test_recording_budget_applies_before_and_after_limit_marker(source, marker_present, extra_byte):  # noqa: F811
    source.session['live_trace']['byte_limit'] = 4 * MIB
    source.save()
    with source.path.open('r+b') as stream:
        stream.truncate(4 * MIB + int(extra_byte))
    if marker_present:
        limit_marker_path(source.final).write_bytes(b'')

    if extra_byte:
        with pytest.raises(ContractError, match='budget|byte limit'):
            observe_recording_limit(source.session, source.path)
        with pytest.raises(ContractError, match='budget|byte limit'):
            source.reader.resolve()
    else:
        observed, _ = observe_recording_limit(source.session, source.path)
        location = source.reader.resolve()
        assert location.phase == ('limited-recording' if marker_present else 'live-prefix')
        assert (observed is not None) is marker_present
        if marker_present:
            assert observed['written_bytes'] == 4 * MIB


@pytest.mark.parametrize('kind',['content','directory','hardlink','oversize','finalized'])
def test_invalid_limit_publication_is_rejected(limited,kind):
    if kind=='content':limited.marker.write_bytes(b'not empty')
    elif kind=='directory':limited.marker.unlink();limited.marker.mkdir()
    elif kind=='hardlink':os.link(limited.marker,limited.marker.with_name('other-marker'))
    elif kind=='oversize':
        with limited.path.open('r+b') as stream:stream.truncate(8*MIB+1)
    else:limited.path.rename(limited.final)
    with pytest.raises(ContractError):limited.reader.resolve()


@pytest.mark.parametrize('replace',[True,False])
def test_limit_marker_cannot_disappear_or_be_replaced_after_open(limited,replace):
    limited.reader.resolve()
    limited.marker.rename(limited.marker.with_name('kept-original-marker'))
    if replace:limited.marker.write_bytes(b'')
    with pytest.raises(ContractError,match='marker changed'):limited.reader.resolve()


def test_limit_marker_replacement_during_first_observation_is_rejected(
    limited, monkeypatch: pytest.MonkeyPatch
) -> None:
    original = live_trace_module._require_regular
    held = limited.marker.with_name("held-limit-marker")
    checks = 0

    def replace_after_source_check(metadata: os.stat_result) -> None:
        nonlocal checks
        original(metadata)
        checks += 1
        if checks == 3:
            limited.marker.rename(held)
            limited.marker.write_bytes(b"")

    monkeypatch.setattr(live_trace_module, "_require_regular", replace_after_source_check)
    with pytest.raises(ContractError):
        observe_recording_limit(limited.session, limited.path)
    assert checks >= 3
    assert held.is_file() and limited.marker.is_file()


def test_marker_does_not_make_an_unbound_stopped_source_trusted(limited):
    del limited.session['live_trace']['file_binding'];limited.save()
    with pytest.raises(ContractError,match='no persisted recording binding'):limited.reader.resolve()


def test_limited_reader_finalizes_only_available_bytes_without_claiming_complete(limited,monkeypatch):
    monkeypatch.setattr('browser_core.incremental_inspection.TraceProcessorPipe',FakeDecoder)
    with IncrementalInspection(limited.document,limited.document.parent) as reader:
        data=reader.read()
        assert data['recording_settled'] and not data['complete'] and data['browser_running']
        assert data['source_phase']=='limited-recording'
        assert data['recording_limit']['written_bytes']==5
        assert data['recording_budget']=={'byte_limit':8*MIB,'used_bytes':5}
        limited.path.write_bytes(b'\x0a\x03abc\x0a\x00')
        with pytest.raises(ContractError):reader.read()
        assert reader.closed


def test_existing_marker_blocks_new_launch_before_browser_creation(tmp_path):
    from browser_core.live_trace import require_new_live_artifacts
    final=tmp_path/'trace';marker=limit_marker_path(final);marker.write_bytes(b'')
    with pytest.raises(ContractError,match='already exists'):require_new_live_artifacts(final)
    assert marker.read_bytes()==b''


@pytest.mark.parametrize('command',['research','launch-eval'])
def test_cli_accepts_operator_recording_limit_and_passes_it_to_launch(command,tmp_path,monkeypatch):
    from browser_core.cli import build_parser
    parser=build_parser()
    argv=['research','owned','--workspace',str(tmp_path),'--recording-limit-mib','8'] if command=='research' else [
        'launch-eval','--executable',str(tmp_path/'chrome.exe'),'--workspace',str(tmp_path),
        '--live-trace','--recording-limit-mib','8']
    args=parser.parse_args(argv)
    assert args.recording_limit_mib==8
    calls=[]
    class Captured(Exception):pass
    def capture_config(config,*_args):
        calls.append(config.recording_limit_mib);raise Captured()
    def capture_research(*_args,**kwargs):
        calls.append(kwargs['recording_limit_mib']);raise Captured()
    monkeypatch.setattr('browser_core.cli.launch_evaluation',capture_config)
    monkeypatch.setattr('browser_core.research.start_research',capture_research)
    with pytest.raises(Captured):args.func(args)
    assert calls==[8]
