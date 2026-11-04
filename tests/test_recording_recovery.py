import json
import os
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

import browser_core.recording_source as source_module
import browser_core.incremental_inspection as inspection
from browser_core.contracts import ContractError,validate_session
from browser_core.recording_source import RecordingSource,bind_recording_file


@pytest.fixture
def source(tmp_path,monkeypatch):
    path=tmp_path/'trace.live';path.write_bytes(b'\x0a\x03abc')
    final=tmp_path/'trace';executable=tmp_path/'chrome.exe'
    session={'schema':'browser-core.session/1','run_id':'owned-run','chromium_revision':'a'*40,
             'pid':42,'state':'active','executable':str(executable),
             'build':{'provenance':'attested-browser-core','executable_sha256_16':'a'*16},
             'process_identity':{'pid':42,'executable':str(executable),'start_marker':'fixture:1'},
             'trace_mode':'on','trace_path':str(final),
             'live_trace':{'schema':'browser-core.live-trace/1','path':str(path),'file_binding':bind_recording_file(path)},
             'value_capture':{'schema':'browser-core.inspection/1','allowlist':'fingerprint-v1'},
             'automation':{'transport':'cdp','cdp_endpoint':'http://127.0.0.1:9222'}}
    document=tmp_path/'session.json'
    def save():document.write_text(json.dumps(session),encoding='utf-8')
    save()
    status={'run_id':'owned-run','state':'active','running':True,'identity_protected':True}
    monkeypatch.setattr('browser_core.lifecycle.session_status',lambda path:dict(status))
    monkeypatch.setattr('browser_core.build.executable_evidence',lambda *args,**kwargs:session['build'])
    return SimpleNamespace(path=path,final=final,session=session,document=document,status=status,save=save,
                           reader=RecordingSource(document,tmp_path))


def test_new_binding_contract_is_optional_for_old_sessions_and_strict_when_present(source):
    assert validate_session(source.session)['live_trace']['file_binding']==bind_recording_file(source.path)
    del source.session['live_trace']['file_binding']
    assert validate_session(source.session)


@pytest.mark.parametrize('change',[
    {'device':1},{'inode':'-1'},{'inode':'01'},{'inode':'1'*41},
    {'prefix_bytes':0},{'prefix_bytes':65537},{'prefix_bytes':True},
    {'prefix_sha256':'A'*64},{'prefix_sha256':'f'*63},{'extra':1},
])
def test_binding_rejects_malformed_or_unbounded_values(source,change):
    binding=source.session['live_trace']['file_binding'];binding.update(change)
    with pytest.raises(ContractError):validate_session(source.session)


def test_binding_survives_append_and_native_rename_but_rejects_another_file(source):
    binding=bind_recording_file(source.path)
    with source.path.open('ab') as file:file.write(b'\x0a\x00')
    assert bind_recording_file(source.path,binding)==binding
    source.path.rename(source.final)
    assert bind_recording_file(source.final,binding)==binding
    copied=source.final.with_name('copied');copied.write_bytes(source.final.read_bytes())
    with pytest.raises(ContractError):bind_recording_file(copied,binding)


def test_prefix_edit_same_inode_is_rejected(source):
    binding=bind_recording_file(source.path)
    source.path.write_bytes(b'\x0a\x03xyz')
    with pytest.raises(ContractError):bind_recording_file(source.path,binding)


def test_binding_rejects_name_replaced_after_source_open(source,monkeypatch):
    replacement=source.path.with_name('other.live')
    replacement.write_bytes(source.path.read_bytes())
    original_lstat=os.lstat
    named_reads=0

    def replacing_lstat(path):
        nonlocal named_reads
        if Path(path)==source.path:
            named_reads+=1
            if named_reads>=2:
                return original_lstat(replacement)
        return original_lstat(path)

    monkeypatch.setattr(source_module.os,'lstat',replacing_lstat)
    with pytest.raises(ContractError,match='recording changed'):
        bind_recording_file(source.path)


@pytest.mark.skipif(os.name != 'nt', reason='Windows junction ancestry')
@pytest.mark.parametrize('read_kind', ['direct-binding', 'reopened-reader'])
def test_recording_binding_rejects_relocated_parent_junction(source, tmp_path, read_kind):
    original_parent = tmp_path / 'recording'
    original_parent.mkdir()
    original_path = original_parent / 'trace.live'
    source.path.replace(original_path)
    source.path = original_path
    source.final = original_parent / 'trace'
    source.session['live_trace']['path'] = str(source.path)
    source.session['live_trace']['file_binding'] = bind_recording_file(source.path)
    source.session['trace_path'] = str(source.final)
    source.save()
    source.reader = RecordingSource(source.document, tmp_path)
    if read_kind == 'reopened-reader':
        assert source.reader.resolve().phase == 'live-prefix'

    moved_parent = tmp_path / 'moved-recording'
    original_parent.rename(moved_parent)
    linked = subprocess.run(
        ['cmd', '/c', 'mklink', '/J', str(original_parent), str(moved_parent)],
        capture_output=True, text=True, check=False,
    )
    if linked.returncode != 0:
        pytest.skip('host could not create an unprivileged directory junction')
    try:
        with pytest.raises(ContractError, match='recording.*(parent|ancestor|source)'):
            if read_kind == 'direct-binding':
                bind_recording_file(source.path, source.session['live_trace']['file_binding'])
            else:
                source.reader.resolve()
    finally:
        original_parent.rmdir()


@pytest.mark.skipif(os.name != 'nt', reason='Windows junction ancestry')
def test_recording_resolve_rejects_parent_swap_after_final_marker_check(
    source, tmp_path, monkeypatch,
):
    import browser_core.recording_limits as limits

    selected = tmp_path / 'recording'
    selected.mkdir()
    source.path.replace(selected / 'trace.live')
    source.path = selected / 'trace.live'
    source.final = selected / 'trace'
    source.session['live_trace']['path'] = str(source.path)
    source.session['trace_path'] = str(source.final)
    source.save()
    source.reader = RecordingSource(source.document, tmp_path)
    assert source.reader.resolve().phase == 'live-prefix'

    retained = tmp_path / 'retained-recording'
    original_observe = limits.observe_recording_limit
    observations = 0
    swapped = False

    def relocate_after_marker_check(*args):
        nonlocal observations, swapped
        result = original_observe(*args)
        observations += 1
        if observations == 2:
            selected.rename(retained)
            linked = subprocess.run(
                ['cmd', '/c', 'mklink', '/J', str(selected), str(retained)],
                capture_output=True, text=True, check=False,
            )
            if linked.returncode:
                retained.rename(selected)
                pytest.skip('host could not create an unprivileged directory junction')
            swapped = True
        return result

    monkeypatch.setattr(limits, 'observe_recording_limit', relocate_after_marker_check)
    try:
        with pytest.raises(ContractError, match='recording.*parent'):
            source.reader.resolve()
        assert source.path.is_file()
        assert observations == 2
    finally:
        if swapped:
            selected.rmdir()
            retained.rename(selected)


def test_one_shot_live_reader_also_checks_new_persisted_binding(source):
    from browser_core.live_trace import verified_live_source
    assert verified_live_source(source.document,source.document.parent)[2]==source.path
    source.path.rename(source.final);source.path.write_bytes(source.final.read_bytes())
    with pytest.raises(ContractError,match='original file binding'):
        verified_live_source(source.document,source.document.parent)


def test_one_shot_live_reader_rechecks_owner_after_runtime_verification(source, monkeypatch):
    from browser_core.live_trace import verified_live_source

    assert verified_live_source(source.document, source.document.parent)[2] == source.path

    def stop_during_runtime_check(*args, **kwargs):
        source.status.update(state='stale', running=False)
        return source.session['build']

    monkeypatch.setattr('browser_core.build.executable_evidence', stop_during_runtime_check)
    with pytest.raises(ContractError, match='original running browser'):
        verified_live_source(source.document, source.document.parent)


def test_live_summary_rejects_session_source_reselected_during_runtime_verification(
    source, monkeypatch, tmp_path,
):
    from browser_core.live_trace import live_trace_summary

    source.path.write_bytes(b'')
    source.session['live_trace'].pop('file_binding')
    source.save()
    assert live_trace_summary(source.document, tmp_path)['bytes'] == 0

    alternate_final = tmp_path / 'alternate-trace'
    alternate_live = Path(str(alternate_final) + '.live')
    alternate_live.touch()

    def reselect_session_source(*args, **kwargs):
        source.session['trace_path'] = str(alternate_final)
        source.session['live_trace']['path'] = str(alternate_live)
        source.save()
        return source.session['build']

    monkeypatch.setattr('browser_core.build.executable_evidence', reselect_session_source)
    with pytest.raises(ContractError, match='session binding changed'):
        live_trace_summary(source.document, tmp_path)


@pytest.mark.parametrize('route', ['summary', 'inspection'])
def test_one_shot_query_rechecks_session_source_after_decoder(
    source, monkeypatch, tmp_path, route,
):
    from browser_core.live_trace import live_trace_summary
    from browser_core.inspection import live_inspection

    alternate_final = tmp_path / 'alternate-trace'
    alternate_live = Path(str(alternate_final) + '.live')
    alternate_live.write_bytes(source.path.read_bytes())

    def reselect_session_source():
        source.session['trace_path'] = str(alternate_final)
        source.session['live_trace']['path'] = str(alternate_live)
        source.session['live_trace']['file_binding'] = bind_recording_file(alternate_live)
        source.save()

    if route == 'summary':
        def query_then_reselect(*args, **kwargs):
            reselect_session_source()
            return SimpleNamespace(
                returncode=0,
                stdout=b'name,category,events,total_groups,total_events\n',
            )

        monkeypatch.setattr(
            'browser_core.bounded_process.run_with_bounded_stdout', query_then_reselect,
        )
        query = live_trace_summary
    else:
        def inspect_then_reselect(*args, **kwargs):
            reselect_session_source()
            return {'events': []}

        monkeypatch.setattr('browser_core.inspection.read_inspection', inspect_then_reselect)
        query = live_inspection

    with pytest.raises(ContractError, match='session binding changed'):
        query(source.document, tmp_path)
    assert source.path.is_file() and alternate_live.is_file()


@pytest.mark.parametrize('mode',['final','crash','pid-reused'])
def test_reopening_is_bound_to_retired_original_owner_and_original_file(source,mode):
    source.status.update(running=False,state='identity-mismatch' if mode=='pid-reused' else 'stale')
    if mode=='final':source.path.rename(source.final)
    location=source.reader.resolve()
    assert location.phase==('finalized-recording' if mode=='final' else 'recovered-prefix')
    assert not location.browser_running
    assert location.path==(source.final if mode=='final' else source.path)


def test_final_native_rename_can_be_observed_while_original_process_is_exiting(source):
    source.reader.resolve();source.path.rename(source.final)
    location=source.reader.resolve()
    assert location.phase=='finalized-recording' and location.browser_running


def test_finalized_source_cannot_return_to_incomplete_name(source):
    source.status.update(running=False,state='stale')
    source.path.rename(source.final)
    assert source.reader.resolve().phase=='finalized-recording'
    source.final.rename(source.path)
    with pytest.raises(ContractError, match='finalized recording'):
        source.reader.resolve()


def test_legacy_open_viewer_can_follow_its_observed_file_but_fresh_reopen_cannot_guess(source):
    del source.session['live_trace']['file_binding'];source.save()
    source.reader.resolve();source.path.rename(source.final)
    source.status.update(running=False,state='stale')
    assert source.reader.resolve().phase=='finalized-recording'
    with pytest.raises(ContractError,match='no persisted recording binding'):
        RecordingSource(source.document,source.document.parent).resolve()


@pytest.mark.parametrize('state',[
    {'running':None},{'identity_protected':False},{'state':'inconsistent'}, {'run_id':'other'},
])
def test_unverified_owner_state_is_not_treated_as_a_recoverable_crash(source,state):
    source.status.update(state)
    with pytest.raises(ContractError):source.reader.resolve()


def test_session_replacement_cannot_redirect_an_existing_inspector(source):
    source.reader.resolve()
    source.session['automation']['cdp_endpoint']='http://127.0.0.1:9333';source.save()
    with pytest.raises(ContractError,match='binding changed'):source.reader.resolve()


@pytest.mark.parametrize('segmented', [False, True])
def test_returned_location_cannot_mutate_retained_session_binding(source, segmented):
    if segmented:
        source.session['live_trace'].update(
            byte_limit=4 * 1024 * 1024,
            parts={'schema': 'browser-core.recording-parts/1', 'max_parts': 2},
        )
        source.save()
    location = source.reader.resolve()
    if segmented:
        location.session['live_trace']['file_binding']['prefix_sha256'] = '0' * 64
    else:
        location.session['automation']['cdp_endpoint'] = 'http://127.0.0.1:9333'

    reopened = source.reader.resolve()
    assert reopened.phase == 'live-prefix'
    assert reopened.session == source.session


@pytest.mark.parametrize('segmented', [False, True])
def test_first_resolution_rechecks_session_after_source_binding(source, monkeypatch, segmented):
    if segmented:
        source.session['live_trace'].update(
            byte_limit=4 * 1024 * 1024,
            parts={'schema': 'browser-core.recording-parts/1', 'max_parts': 2},
        )
        source.save()
    original_bind = source_module.bind_recording_file

    def replace_session_during_binding(*args, **kwargs):
        result = original_bind(*args, **kwargs)
        source.session['automation']['cdp_endpoint'] = 'http://127.0.0.1:9333'
        source.save()
        return result

    monkeypatch.setattr(source_module, 'bind_recording_file', replace_session_during_binding)
    with pytest.raises(ContractError, match='session binding changed'):
        source.reader.resolve()


@pytest.mark.parametrize('segmented', [False, True])
def test_first_resolution_rechecks_owner_status_after_source_binding(source, monkeypatch, segmented):
    if segmented:
        source.session['live_trace'].update(
            byte_limit=4 * 1024 * 1024,
            parts={'schema': 'browser-core.recording-parts/1', 'max_parts': 2},
        )
        source.save()
    original_bind = source_module.bind_recording_file

    def stop_owner_during_binding(*args, **kwargs):
        result = original_bind(*args, **kwargs)
        source.status.update(state='stale', running=False)
        return result

    monkeypatch.setattr(source_module, 'bind_recording_file', stop_owner_during_binding)
    with pytest.raises(ContractError, match='owner state changed'):
        source.reader.resolve()
    assert source.reader.session_binding is None


def test_only_lifecycle_fields_can_change_in_an_existing_viewer(source):
    source.reader.resolve();source.session.update(state='stopped',stopped_at='2026-09-10T07:00:00Z');source.save()
    source.status.update(state='stopped',running=False)
    assert source.reader.resolve().phase=='recovered-prefix'


def test_ambiguous_or_missing_recording_names_are_not_guessed(source):
    source.final.write_bytes(source.path.read_bytes())
    with pytest.raises(ContractError,match='both'):source.reader.resolve()
    source.final.unlink();source.path.unlink()
    with pytest.raises(ContractError,match='missing'):source.reader.resolve()


def test_additional_hardlink_is_rejected(source):
    os.link(source.path,source.final)
    with pytest.raises(ContractError):bind_recording_file(source.path)


def test_cursor_follows_only_same_file_and_freezes_retired_metadata(source):
    cursor=inspection.LivePacketCursor(source.path);chunks=[]
    try:
        cursor.consume(chunks.append)
        source.path.rename(source.final)
        receipt=cursor.consume(chunks.append,relocate=lambda:source.final,stable=lambda:True)
        assert receipt['new_bytes']==0 and cursor.source==source.final
        with source.final.open('ab') as file:file.write(b'\x0a\x00')
        with pytest.raises(ContractError):cursor.consume(chunks.append,stable=lambda:True)
    finally:cursor.close()


def test_relocation_does_not_admit_a_copied_file(source):
    cursor=inspection.LivePacketCursor(source.path)
    try:
        source.final.write_bytes(source.path.read_bytes());source.path.unlink()
        with pytest.raises(ContractError):cursor.consume(lambda body:None,relocate=lambda:source.final)
    finally:cursor.close()


class FakeDecoder:
    def __init__(self,*args):self.finalizations=0;self.chunks=[];self.closed=False
    def append(self,body):assert not self.finalizations;self.chunks.append(body)
    def finalize(self):self.finalizations+=1
    def query(self,sql,**kwargs):
        if 'FROM stats' in sql:
            return b'name,severity,value\n__capture_stats_present,meta,1\n__sorter_dropped,meta,0\n'
        return b'id,ts,pid,tid,schema,api,allowlist,context_id,context_kind,realm_id,script_id,completion,parameters_json,result_json,total_events\n'
    def close(self):self.closed=True


@pytest.mark.parametrize('final,tail',[(True,b''),(False,b''),(False,b'\x0a\x03x')])
def test_only_retired_prefixes_receive_eof_and_recovery_never_claims_complete(source,monkeypatch,final,tail):
    monkeypatch.setattr(inspection,'TraceProcessorPipe',FakeDecoder)
    reader=inspection.IncrementalInspection(source.document,source.document.parent)
    first=reader.read();assert not first['recording_settled'] and reader.decoder.finalizations==0
    if tail:
        with source.path.open('ab') as file:file.write(tail)
    source.status.update(running=False,state='stale')
    if final:source.path.rename(source.final)
    result=reader.read()
    assert result['complete']==final and result['recovery_incomplete']==(not final)
    assert result['recording_settled'] and not result['decoder_pending_possible']
    assert result['incomplete_tail_bytes']==len(tail)
    assert reader.decoder.finalizations==1
    reader.read();assert reader.decoder.finalizations==1
    reader.close()


def test_finalized_file_with_partial_packet_is_not_reported_complete(source,monkeypatch):
    monkeypatch.setattr(inspection,'TraceProcessorPipe',FakeDecoder)
    reader=inspection.IncrementalInspection(source.document,source.document.parent)
    reader.read()
    with source.path.open('ab') as file:file.write(b'\x0a\x03x')
    source.path.rename(source.final);source.status.update(running=False,state='stale')
    with pytest.raises(ContractError,match='incomplete packet'):reader.read()
    assert reader.closed and reader.decoder.finalizations==0


def test_static_backlog_is_not_finalized_until_all_complete_packets_arrive(source,monkeypatch):
    monkeypatch.setattr(inspection,'MAX_REFRESH_BYTES',5)
    monkeypatch.setattr(inspection,'TraceProcessorPipe',FakeDecoder)
    with source.path.open('ab') as file:file.write(b'\x0a\x03def'*2)
    source.path.rename(source.final);source.status.update(running=False,state='stale')
    reader=inspection.IncrementalInspection(source.document,source.document.parent)
    assert reader.read()['catching_up'] and not reader.finalized
    assert reader.read()['catching_up'] and not reader.finalized
    assert reader.read()['complete'] and reader.finalized
    assert b''.join(reader.decoder.chunks)==source.final.read_bytes()
    reader.close()


def interrupt_decoder(reader):
    def failed(*args,**kwargs):raise inspection.DecoderInterrupted('fixture interruption')
    reader.decoder.query=failed
    old=reader.decoder
    with pytest.raises(inspection.InspectionRebuilding):reader.read()
    assert old.closed and not reader.closed and reader.decoder_restarts==1


def test_decoder_replay_is_bounded_verifies_old_bytes_and_retains_warnings(source,monkeypatch):
    monkeypatch.setattr(inspection,'TraceProcessorPipe',FakeDecoder)
    with source.path.open('ab') as f:f.write(b'\x0a\x03def'*5)
    reader=inspection.IncrementalInspection(source.document,source.document.parent)
    reader.read();old_key=reader.history_key
    reader.health['status']='issues-reported'
    reader.health['counters']=[{'name':'fixture_loss','severity':'data_loss','kind':'loss','value':3}]
    interrupt_decoder(reader)
    assert reader.history_key!=old_key
    monkeypatch.setattr(inspection,'MAX_REFRESH_BYTES',10)
    with source.path.open('ab') as f:f.write(b'\x0a\x03ghi')
    for offset in (10,20):
        with pytest.raises(inspection.InspectionRebuilding):reader.read()
        assert reader.cursor.offset==offset and not reader.closed
    restored=reader.read()
    assert restored['snapshot_bytes']==30 and restored['catching_up']
    assert restored['recording_health']['status']=='issues-reported'
    assert restored['recording_health']['counters'][0]['name']=='fixture_loss'
    assert restored['decoder_restarts']==1 and reader.replay_guard is None
    assert reader.read()['snapshot_bytes']==35
    reader.close()


@pytest.mark.parametrize('change',['same-size-edit','shrink','replace'])
def test_restart_cannot_silently_read_changed_previously_observed_bytes(source,monkeypatch,change):
    monkeypatch.setattr(inspection,'TraceProcessorPipe',FakeDecoder)
    reader=inspection.IncrementalInspection(source.document,source.document.parent)
    # These later bytes lie outside the persisted startup prefix.
    with source.path.open('ab') as f:f.write(b'\x0a\x03def'*3)
    reader.read();interrupt_decoder(reader)
    if change=='same-size-edit':
        with source.path.open('r+b') as f:f.seek(17);f.write(b'xyz')
    elif change=='shrink':
        with source.path.open('r+b') as f:f.truncate(5)
    else:
        body=source.path.read_bytes();source.path.rename(source.final);source.final.unlink();source.path.write_bytes(body)
    with pytest.raises(ContractError):reader.read()
    assert reader.closed


@pytest.mark.parametrize('error',[inspection.DecoderInterrupted('stopped'),ContractError('bad protocol')])
def test_repeated_or_nonrecoverable_failure_does_not_loop(source,monkeypatch,error):
    monkeypatch.setattr(inspection,'TraceProcessorPipe',FakeDecoder)
    reader=inspection.IncrementalInspection(source.document,source.document.parent)
    reader.read();interrupt_decoder(reader);reader.read()
    def failed(*args,**kwargs):raise error
    reader.decoder.query=failed
    with pytest.raises(ContractError) as caught:reader.read()
    assert not isinstance(caught.value,inspection.InspectionRebuilding)
    assert reader.closed and reader.decoder_restarts==1


def test_partial_append_failure_replays_in_a_new_decoder_only(source,monkeypatch):
    monkeypatch.setattr(inspection,'TraceProcessorPipe',FakeDecoder)
    reader=inspection.IncrementalInspection(source.document,source.document.parent)
    reader.read();old=reader.decoder
    with source.path.open('ab') as f:f.write(b'\x0a\x03def')
    def failed(body):
        old.chunks.append(body[:2])
        raise inspection.DecoderInterrupted('after partial append')
    old.append=failed
    with pytest.raises(inspection.InspectionRebuilding):reader.read()
    assert old.closed and reader.replay_guard[0]==5
    reader.read();reader.read()
    assert reader.decoder is not old
    assert b''.join(reader.decoder.chunks)==source.path.read_bytes()
    reader.close()


def test_restart_after_finalization_replays_eof_once_and_rejects_old_cursors(source,monkeypatch):
    from browser_core.inspection_history import encode_cursor,query_digest,history_filters
    monkeypatch.setattr(inspection,'TraceProcessorPipe',FakeDecoder)
    reader=inspection.IncrementalInspection(source.document,source.document.parent)
    source.path.rename(source.final);source.status.update(running=False,state='stale')
    reader.read()
    token=encode_cursor(reader.history_key,query_digest(history_filters('','',''),1000),0)
    interrupt_decoder(reader)
    with pytest.raises(ContractError):reader.history(cursor=token)
    assert not reader.closed
    result=reader.read()
    assert result['complete'] and reader.decoder.finalizations==1
    reader.read();assert reader.decoder.finalizations==1
    reader.close()
