from pathlib import Path

import pytest

from browser_core.contracts import ContractError
from browser_core.recording_source import RecordingSource
from browser_core.incremental_inspection import IncrementalInspection
from test_recording_recovery import source,FakeDecoder


@pytest.fixture
def upgraded(source,monkeypatch):
    source.session['build'].update(runtime_bundle_sha256_16='b'*16,
        attestation_created_at='2026-09-09T00:00:00Z')
    source.save();source.status.update(running=False,state='stopped')
    current=dict(source.session['build'],runtime_bundle_sha256_16='c'*16,
                 attestation_created_at='2026-09-10T00:00:00Z')
    calls=[]
    def evidence(root,exe,*,allow_unverified):
        assert allow_unverified is False
        calls.append(exe)
        return dict(current)
    monkeypatch.setattr('browser_core.build.executable_evidence',evidence)
    source.current=current;source.evidence_calls=calls
    return source


@pytest.mark.parametrize('final',[True,False])
def test_stopped_bound_recording_retains_original_producer_and_verified_new_reader(upgraded,final):
    if final:upgraded.path.rename(upgraded.final)
    before=upgraded.document.read_bytes()
    location=upgraded.reader.resolve()
    assert location.reader_runtime=={'mode':'compatible-reader',
        'producer_build':upgraded.session['build'],'reader_build':upgraded.current}
    assert location.phase==('finalized-recording' if final else 'recovered-prefix')
    assert location.browser_running is False
    assert upgraded.document.read_bytes()==before


@pytest.mark.parametrize('state',['active','inconsistent'])
def test_changed_reader_cannot_attach_to_a_running_original_producer(upgraded,state):
    upgraded.status.update(state=state,running=True)
    with pytest.raises(ContractError,match='owner state|live recording executable'):
        upgraded.reader.resolve()


@pytest.mark.parametrize('missing',['file_binding','runtime_bundle_sha256_16','attestation_created_at'])
def test_legacy_upgrade_cannot_guess_missing_source_or_producer_binding(upgraded,missing):
    if missing=='file_binding':del upgraded.session['live_trace'][missing]
    else:del upgraded.session['build'][missing]
    upgraded.save()
    with pytest.raises(ContractError,match='upgrade reopening requires'):
        upgraded.reader.resolve()


def test_bound_metadata_only_upgrade_preserves_producer_without_guessing_private_contract(upgraded):
    del upgraded.session['value_capture']
    upgraded.save()
    location=upgraded.reader.resolve()
    assert 'value_capture' not in location.session
    assert location.reader_runtime['mode']=='compatible-reader'
    inspector=IncrementalInspection(upgraded.document,upgraded.reader.repository_root,upgraded.reader)
    try:
        with pytest.raises(ContractError,match='no native value capture'):
            inspector.read(limit=1)
    finally:inspector.close()


def test_unknown_capture_version_is_never_reinterpreted(upgraded):
    upgraded.session['value_capture']={'schema':'browser-core.inspection/99','allowlist':'fingerprint-v99'}
    upgraded.save()
    with pytest.raises(ContractError):upgraded.reader.resolve()


def test_compatible_reader_never_admits_a_replaced_recording(upgraded):
    original=upgraded.path.read_bytes();upgraded.path.rename(upgraded.final)
    upgraded.path.write_bytes(original);upgraded.final.unlink()
    with pytest.raises(ContractError,match='original file binding'):
        upgraded.reader.resolve()


def test_compatible_reader_never_admits_modified_startup_bytes(upgraded):
    upgraded.path.write_bytes(b'\x0a\x03xyz')
    with pytest.raises(ContractError,match='original file binding'):
        upgraded.reader.resolve()


def test_open_inspector_cannot_switch_reader_build_between_refreshes(upgraded):
    upgraded.reader.resolve()
    upgraded.current['runtime_bundle_sha256_16']='d'*16
    with pytest.raises(ContractError,match='reader changed'):
        upgraded.reader.resolve()


def test_stopped_recording_can_choose_relocated_verified_reader(upgraded):
    executable=upgraded.document.parent/'current'/'chrome.exe'
    reader=RecordingSource(upgraded.document,upgraded.document.parent,executable)
    assert reader.resolve().executable==executable
    assert upgraded.evidence_calls[-1]==executable
    assert not Path(upgraded.session['executable']).exists()


def test_relocated_reader_does_not_override_live_producer_identity(source):
    executable=source.document.parent/'other'/'chrome.exe'
    with pytest.raises(ContractError,match='live recording executable'):
        RecordingSource(source.document,source.document.parent,executable).resolve()


@pytest.mark.parametrize('value',['relative/chrome.exe',Path('relative/chrome.exe'),42])
def test_reader_selection_requires_absolute_typed_path(source,value):
    with pytest.raises(ContractError,match='absolute Path'):
        RecordingSource(source.document,source.document.parent,value)


def test_unverified_current_reader_still_fails_closed(upgraded,monkeypatch):
    def fail(*args,**kwargs):raise ContractError('reader has invalid attestation')
    monkeypatch.setattr('browser_core.build.executable_evidence',fail)
    with pytest.raises(ContractError,match='invalid attestation'):
        upgraded.reader.resolve()


def test_real_current_build_artifact_checks_apply_to_relocated_reader(upgraded,monkeypatch):
    from test_build import _write_fixture_attestation,ROOT
    import browser_core.build as build
    folder=upgraded.document.parent/'new-runtime';folder.mkdir()
    executable,_,_= _write_fixture_attestation(folder)
    monkeypatch.undo()
    monkeypatch.setattr('browser_core.lifecycle.session_status',lambda path:dict(upgraded.status))
    reader=RecordingSource(upgraded.document,ROOT,executable)
    assert reader.resolve().reader_runtime['mode']=='compatible-reader'
    executable.with_name('trace_processor_shell.exe').write_bytes(b'changed decoder')
    with pytest.raises(ContractError,match='verified Browser Core build'):
        reader.resolve()


def test_reopened_data_and_history_carry_both_builds_without_claiming_complete(upgraded,monkeypatch):
    monkeypatch.setattr('browser_core.incremental_inspection.TraceProcessorPipe',FakeDecoder)
    reader=IncrementalInspection(upgraded.document,upgraded.document.parent)
    try:
        result=reader.read()
        assert result['reader_runtime']['producer_build']==upgraded.session['build']
        assert result['reader_runtime']['reader_build']==upgraded.current
        assert result['complete'] is False and result['recovery_incomplete'] is True
        assert result['recording_settled'] is True
    finally:reader.close()


@pytest.mark.parametrize('explicit',[True,False])
def test_inspector_cli_preserves_default_and_forwards_explicit_reader(tmp_path,monkeypatch,explicit):
    from browser_core.cli import build_parser
    calls=[]
    monkeypatch.setattr('browser_core.inspection_ui.serve_inspector',lambda *args,**kwargs:calls.append((args,kwargs)))
    argv=['trace','inspect','--session',str(tmp_path/'session.json'),'--open']
    if explicit:argv.extend(['--reader-executable',str(tmp_path/'current'/'chrome.exe')])
    args=build_parser().parse_args(argv)
    assert args.func(args)==0
    assert calls[0][0][0]==tmp_path/'session.json'
    assert calls[0][1]=={'open_browser':True,'reader_executable':(tmp_path/'current'/'chrome.exe').resolve() if explicit else None}
