import csv
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
from types import SimpleNamespace

import pytest

from browser_core.contracts import ContractError
from browser_core.incremental_inspection import IncrementalInspection, InspectionRebuilding
from browser_core.inspection_history import encode_cursor, history_filters, query_digest
from browser_core.inspection_contract import CAPTURE_V1
from browser_core.prepared_download import ExportCleanupPending
import browser_core.inspection_comparison as comparison
from browser_core.trace_rpc import DecoderInterrupted
from test_inspection_history import Decoder


@pytest.fixture
def reader():
    item=IncrementalInspection(Path('/session'),Path('/repo'))
    item.decoder=Decoder()
    location=SimpleNamespace(path=Path('/owned-recording'),phase='live-prefix',
                             session={'run_id':'owned-fixture'})
    item.source=SimpleNamespace(resolve=lambda:location)
    item.cursor=SimpleNamespace(source=location.path,close=lambda:None)
    item.read=lambda **kwargs:{**CAPTURE_V1,'run_id':'owned-fixture','events':[],
        'source_sha256':'a'*64,'snapshot_bytes':1234,'source_bytes':1239,
        'pending_source_bytes':5,'source_phase':'live-prefix','recording_settled':False,
        'decoder_pending_possible':True,'catching_up':True,
        'recording_health':{'status':'issues-reported','counters':[]}}
    yield item
    if not item.closed:item.close()


def frozen(reader, highwater, **filters):
    filters=history_filters(**filters)
    return {'filters':filters,'cursor':encode_cursor(reader.history_key,query_digest(filters,1000),highwater)}


def attribution(probes=(),limited=False):
    return SimpleNamespace(probe_events=set(probes),match_limit_reached=limited,reconcile=lambda reader:None)


def test_failed_comparison_preserves_replacement_of_staged_directory(
        reader, tmp_path, monkeypatch):
    reader.decoder.add(1, 1)
    request = {key: frozen(reader, 1) for key in ('a', 'b')}
    folder = comparison.TemporaryDirectory(dir=tmp_path)
    original_name = Path(folder.name)
    retained = tmp_path / 'retained-comparison'
    sentinel = original_name / 'unrelated.txt'
    cleanup = folder.cleanup
    calls = []
    monkeypatch.setattr(folder, 'cleanup', lambda: calls.append('cleanup'))
    monkeypatch.setattr(comparison, 'TemporaryDirectory', lambda **kwargs: folder)

    def replace_then_fail(*args, **kwargs):
        assert original_name.resolve().parent == tmp_path.resolve()
        original_name.rename(retained)
        original_name.mkdir()
        sentinel.write_text('preserve', encoding='utf-8')
        raise comparison.ComparisonLimit('forced scan failure')

    monkeypatch.setattr(comparison, 'membership_window', replace_then_fail)
    export = comparison.ComparisonExport()
    try:
        with pytest.raises(comparison.ComparisonLimit, match='forced scan failure'):
            export.prepare(reader, attribution(), request)
        assert calls == []
        assert sentinel.read_text(encoding='utf-8') == 'preserve'
        assert export._retired is folder
    finally:
        monkeypatch.setattr(folder, 'cleanup', cleanup)
        sentinel.unlink(missing_ok=True)
        if original_name.exists():
            original_name.rmdir()
        retained.rename(original_name)
        if export._retired is not None:
            export._ensure_cleanup()
        cleanup()


def test_comparison_rejects_changed_copy_ancestor_during_scan(
        reader, tmp_path, monkeypatch):
    reader.decoder.add(1, 1)
    request = {key: frozen(reader, 1) for key in ('a', 'b')}
    private_parent = tmp_path / 'private-parent'
    private_parent.mkdir()
    retained_parent = tmp_path / 'retained-parent'
    folder = comparison.TemporaryDirectory(dir=private_parent)
    name = Path(folder.name).name
    current_folder = private_parent / name
    retained_folder = retained_parent / name
    sentinel = current_folder / 'unrelated.txt'
    monkeypatch.setattr(comparison, 'TemporaryDirectory', lambda **kwargs: folder)
    original_window = comparison.membership_window
    swapped = False

    def window_then_move_ancestor(*args, **kwargs):
        nonlocal swapped
        window = original_window(*args, **kwargs)
        if not swapped:
            private_parent.rename(retained_parent)
            private_parent.mkdir()
            retained_folder.rename(current_folder)
            swapped = True
            sentinel.write_text('preserve', encoding='utf-8')
        return window

    monkeypatch.setattr(comparison, 'membership_window', window_then_move_ancestor)
    export = comparison.ComparisonExport()
    try:
        with pytest.raises(ContractError, match='comparison export directory|prepared download'):
            export.prepare(reader, attribution(), request)
        assert swapped
        assert sentinel.read_text(encoding='utf-8') == 'preserve'
    finally:
        sentinel.unlink(missing_ok=True)
        if swapped:
            if current_folder.exists():
                current_folder.rename(retained_folder)
            private_parent.rmdir()
            retained_parent.rename(private_parent)
        if export.folder is None:
            export.close()
        else:
            folder.cleanup()
        private_parent.rmdir()


def test_comparison_restores_shared_decoder_timeout_after_scan(reader,monkeypatch):
    reader.decoder.add(1,1)
    request={key:frozen(reader,1) for key in ('a','b')}
    reader.decoder.timeout=7
    export=comparison.ComparisonExport()
    try:
        export.prepare(reader,attribution(),request)
        assert reader.decoder.timeout==7

        def fail_window(*args,**kwargs):
            raise comparison.ComparisonLimit('scan stopped')
        monkeypatch.setattr(comparison,'membership_window',fail_window)
        with pytest.raises(comparison.ComparisonLimit,match='scan stopped'):
            export.prepare(reader,attribution(),request)
        assert reader.decoder.timeout==7
    finally:
        export.close()


def test_comparison_rechecks_recording_after_prepared_file_binding(reader,monkeypatch):
    import browser_core.perfetto as perfetto
    reader.decoder.add(1,1)
    request={key:frozen(reader,1) for key in ('a','b')}
    location=reader.source.resolve()
    changed=SimpleNamespace(**{**vars(location),
        'session':{**location.session,'run_id':'different-run'}})
    current=[location]
    reader.source.resolve=lambda:current[0]
    original_binding=perfetto._stable_file_binding
    def bind_then_change(*args,**kwargs):
        binding=original_binding(*args,**kwargs)
        current[0]=changed
        return binding
    monkeypatch.setattr(perfetto,'_stable_file_binding',bind_then_change)
    export=comparison.ComparisonExport()
    try:
        with pytest.raises(ContractError,match='prepared download changed before publication'):
            export.prepare(reader,attribution(),request)
        assert export.path is None and export.receipt is None
    finally:export.close()


@pytest.mark.skipif(os.name != 'nt', reason='Windows directory junction boundary')
def test_comparison_does_not_write_into_junction_replacing_private_directory(
        reader,tmp_path,monkeypatch):
    reader.decoder.add(1,1)
    selected={key:frozen(reader,1) for key in ('a','b')}
    target=tmp_path/'unrelated'
    target.mkdir()
    junction=tmp_path/'private-comparison'
    created=subprocess.run(['cmd','/c','mklink','/J',str(junction),str(target)],
                           capture_output=True,check=False)
    if created.returncode:
        pytest.skip('host could not create an unprivileged directory junction')

    class SwappedFolder:
        name=str(junction)
        def cleanup(self):
            if junction.exists():junction.rmdir()

    monkeypatch.setattr(comparison,'TemporaryDirectory',lambda **kwargs:SwappedFolder())
    export=comparison.ComparisonExport()
    try:
        with pytest.raises(ContractError,match='comparison export directory|reparse|junction'):
            export.prepare(reader,attribution(),selected)
        assert list(target.iterdir())==[]
    finally:
        with pytest.raises(ExportCleanupPending):
            export.close()
        if junction.exists():junction.rmdir()


def test_comparison_does_not_append_into_replaced_group_hardlink(
        reader,tmp_path,monkeypatch):
    reader.decoder.add(1,1)
    reader.decoder.add(2,2)
    request={key:frozen(reader,2) for key in ('a','b')}
    monkeypatch.setattr(comparison,'BATCH_EVENTS',1)
    target=tmp_path/'unrelated'
    sentinel=b'unrelated file must remain unchanged'
    target.write_bytes(sentinel)
    original_open=Path.open
    group_opens=[]
    def replace_before_second_group_open(path,mode='r',*args,**kwargs):
        if path.name=='group-0.jsonpart' and mode in ('xb','r+b'):
            group_opens.append(mode)
            if len(group_opens)==2:
                path.unlink()
                os.link(target,path)
        return original_open(path,mode,*args,**kwargs)
    monkeypatch.setattr(Path,'open',replace_before_second_group_open)
    export=comparison.ComparisonExport()
    try:
        with pytest.raises(ContractError,match='comparison membership group'):
            export.prepare(reader,attribution(),request)
        assert len(group_opens)==2
        assert target.read_bytes()==sentinel
        assert export.path is None
    finally:
        export.close()


@pytest.mark.skipif(os.name!='nt',reason='Windows junction boundary')
def test_comparison_reopen_does_not_create_group_through_swapped_junction(
        reader,tmp_path,monkeypatch):
    reader.decoder.add(1,1)
    reader.decoder.add(2,2)
    request={key:frozen(reader,2) for key in ('a','b')}
    monkeypatch.setattr(comparison,'BATCH_EVENTS',1)
    root=tmp_path/'private-comparison'
    root.mkdir()
    held=tmp_path/'held-comparison'
    outside=tmp_path/'unrelated'
    outside.mkdir()

    class Folder:
        name=str(root)
        def cleanup(self):pass

    monkeypatch.setattr(comparison,'TemporaryDirectory',lambda **kwargs:Folder())
    original_open=Path.open
    group_opens=[]

    def swap_before_second_group_open(path,mode='r',*args,**kwargs):
        if path.name=='group-0.jsonpart' and mode in ('xb','ab','r+b'):
            group_opens.append(mode)
            if len(group_opens)==2:
                root.rename(held)
                created=subprocess.run(['cmd','/c','mklink','/J',str(root),str(outside)],
                                       capture_output=True,check=False)
                assert created.returncode==0
        return original_open(path,mode,*args,**kwargs)

    monkeypatch.setattr(Path,'open',swap_before_second_group_open)
    export=comparison.ComparisonExport()
    try:
        with pytest.raises(ContractError,match='comparison export directory|membership group'):
            export.prepare(reader,attribution(),request)
        assert len(group_opens)==2
        assert list(outside.iterdir())==[]
        assert export.path is None
    finally:
        with pytest.raises(ExportCleanupPending):
            export.close()
        if root.exists():root.rmdir()
        held.rename(root)
        export.close()


def manifest(export):
    raw=export.path.read_bytes()
    assert hashlib.sha256(raw).hexdigest()==export.receipt['sha256']
    assert len(raw)==export.receipt['bytes']
    body=json.loads(raw)
    assert {k:v for k,v in body.items() if k!='membership_groups'}==export.receipt['summary']
    return body


def members(report,selection,probe=False):
    groups=[g for g in report['membership_groups'] if g['selection'] in (selection,'both')
            and (g['role']=='confirmed-identification-probe')==probe]
    values=[]
    for group in groups:
        assert group['count']==len(group['event_ids'])
        assert all(isinstance(i,str) for i in group['event_ids'])
        assert list(map(int,group['event_ids']))==sorted(map(int,group['event_ids']))
        values.extend(map(int,group['event_ids']))
    assert len(values)==len(set(values))
    return set(values)


def test_fixed_searches_preserve_exact_membership_counts_overlap_and_probes(reader):
    base=2**53+17
    for i in range(1,13):reader.decoder.add(base+i,base+i,script=42 if i!=8 else 43)
    a=frozen(reader,base+10,script='42',end_ns=str(base+9))
    b=frozen(reader,base+12,start_ns=str(base+5))
    # Newly ingested rows, including earlier timestamps, never enter either saved search.
    reader.decoder.add(base+13,base+6)
    export=comparison.ComparisonExport()
    try:
        export.prepare(reader,attribution([base+6]),{'a':a,'b':b})
        report=manifest(export)
        expected_a={base+i for i in (1,2,3,4,5,7,9)}
        expected_b={base+i for i in (5,7,8,9,10,11,12)}
        assert members(report,'a')==expected_a and members(report,'b')==expected_b
        assert members(report,'a',True)==members(report,'b',True)=={base+6}
        assert report['totals']['a']=={'matched':8,'included':7,'excluded_probes':1,'exceptions':0}
        assert report['totals']['b']==report['totals']['a']
        assert report['overlap']=={'included':3,'excluded_probes':1}
        assert report['membership_events']==12
        assert report['api_counts']==[{'api':'Navigator.userAgent.get','a':7,'b':7,
                                      'a_exceptions':0,'b_exceptions':0,'change_b_minus_a':0}]
        assert report['recording']['source_sha256']=='a'*64
        assert report['recording']['source_phase']=='live-prefix'
        assert report['recording']['recording_health']['status']=='issues-reported'
        assert not report['proves_capture_complete'] and not report['validates_all_captured_values']
        assert a['cursor'] not in export.path.read_text()
    finally:export.close()


def test_comparison_cannot_publish_finalized_phase_lost_during_scan(reader):
    reader.decoder.add(1,1)
    location=SimpleNamespace(path=Path('/owned-recording'),phase='finalized-recording',
                             session={'run_id':'owned-fixture'})
    reader.source=SimpleNamespace(resolve=lambda:location)
    reader.cursor=SimpleNamespace(source=location.path,close=lambda:None)
    reader.read=lambda **kwargs:{**CAPTURE_V1,'run_id':'owned-fixture','events':[],
        'source_sha256':'a'*64,'snapshot_bytes':1234,'source_bytes':1234,
        'pending_source_bytes':0,'source_phase':'finalized-recording',
        'recording_settled':True,'decoder_pending_possible':False,'catching_up':False}
    original=reader.decoder.query
    def query_then_change(sql,**kwargs):
        if 'WITH raw_ids' in sql:
            location.phase='recovered-prefix'
        return original(sql,**kwargs)
    reader.decoder.query=query_then_change
    selected={key:frozen(reader,1) for key in ('a','b')}
    export=comparison.ComparisonExport()
    try:
        with pytest.raises(ContractError,match='source changed'):
            export.prepare(reader,attribution(),selected)
        assert export.path is None
    finally:export.close()


def test_comparison_cannot_publish_live_session_replaced_during_scan(reader):
    reader.decoder.add(1,1)
    location=SimpleNamespace(path=Path('/owned-recording'),phase='live-prefix',
                             session={'run_id':'owned-fixture'})
    reader.source=SimpleNamespace(resolve=lambda:location)
    reader.cursor=SimpleNamespace(source=location.path,close=lambda:None)
    original=reader.decoder.query
    def query_then_replace(sql,**kwargs):
        if 'WITH raw_ids' in sql:
            location.session={'run_id':'replacement-run'}
        return original(sql,**kwargs)
    reader.decoder.query=query_then_replace
    selected={key:frozen(reader,1) for key in ('a','b')}
    export=comparison.ComparisonExport()
    try:
        with pytest.raises(ContractError,match='source changed'):
            export.prepare(reader,attribution(),selected)
        assert export.path is None
    finally:export.close()


def test_comparison_cannot_publish_changed_imported_evidence(reader):
    reader.decoder.add(1,1)
    location=SimpleNamespace(path=Path('/private-evidence-copy'),phase='finalized-recording',
                             session={'run_id':'owned-fixture'})
    reader.source=SimpleNamespace(resolve=lambda:location)
    reader.cursor=SimpleNamespace(source=location.path,close=lambda:None)
    reader.read=lambda **kwargs:{**CAPTURE_V1,'run_id':'owned-fixture','events':[],
        'source_sha256':'a'*64,'snapshot_bytes':1234,'source_bytes':1234,
        'pending_source_bytes':0,'source_phase':'finalized-recording',
        'recording_settled':True,'decoder_pending_possible':False,'catching_up':False}
    original=reader.decoder.query
    def query_then_replace(sql,**kwargs):
        if 'WITH raw_ids' in sql:
            location.session={'run_id':'replacement-run'}
        return original(sql,**kwargs)
    reader.decoder.query=query_then_replace
    selected={key:frozen(reader,1) for key in ('a','b')}
    export=comparison.ComparisonExport()
    try:
        with pytest.raises(ContractError,match='source changed'):
            export.prepare(reader,attribution(),selected,
                           bundle={'source_phase':'recovered-prefix','sha256':'b'*64})
        assert export.path is None
    finally:export.close()


def test_bulk_batches_have_complete_ids_and_separate_exception_counts(reader):
    total=comparison.BATCH_EVENTS+7
    for i in range(1,total+1):reader.decoder.add(i,i)
    reader.decoder.args[1001]['debug.completion']='exception'
    request={'a':frozen(reader,total),'b':frozen(reader,total,start_ns='2')}
    export=comparison.ComparisonExport()
    try:
        export.prepare(reader,attribution(),request)
        report=manifest(export)
        assert members(report,'a')==set(range(1,total+1))
        assert members(report,'b')==set(range(2,total+1))
        assert report['api_counts'][0]['a_exceptions']==1
        assert report['api_counts'][0]['b_exceptions']==0
        assert report['api_counts'][0]['change_b_minus_a']==-1
    finally:export.close()


def test_sparse_id_groups_fall_back_without_skipping_or_duplicating_members(reader):
    ids=[i*4096 for i in range(1,1102)]
    for i in ids:reader.decoder.add(i,i)
    request={key:frozen(reader,ids[-1]) for key in ('a','b')}
    export=comparison.ComparisonExport()
    try:
        export.prepare(reader,attribution(),request)
        report=manifest(export)
        assert members(report,'a')==members(report,'b')==set(ids)
    finally:export.close()


def test_context_filters_and_empty_selections_do_not_fall_back(reader):
    reader.decoder.add(1,1)
    reader.decoder.add(2,2,pid=22)
    scope={'pid':'22','context_id':'AB'*16,'realm_id':'0'}
    request={'a':frozen(reader,2,scope=scope),'b':frozen(reader,2,scope={**scope,'pid':'23'})}
    export=comparison.ComparisonExport()
    try:
        export.prepare(reader,attribution(),request)
        report=manifest(export)
        assert members(report,'a')=={2} and not members(report,'b')
        assert report['totals']['b']['matched']==0
    finally:export.close()


def test_selective_search_finds_late_matches_after_empty_native_ranges(reader,monkeypatch):
    monkeypatch.setattr(comparison,'BATCH_EVENTS',3)
    for event_id in range(1,10):
        reader.decoder.add(event_id,event_id,value='needle' if event_id in (7,8) else 'other',
                           pid=22 if event_id==8 else 21)
    request={'a':frozen(reader,9,search='needle'),
             'b':frozen(reader,9,scope={'pid':'22','context_id':'AB'*16,'realm_id':'0'})}
    # Later decoding must not extend either saved search, even with an earlier timestamp.
    reader.decoder.add(10,1,value='needle',pid=22)
    calls=[];native_query=reader.decoder.query
    def measured(*args,**kwargs):
        calls.append(True)
        return native_query(*args,**kwargs)
    monkeypatch.setattr(reader.decoder,'query',measured)
    export=comparison.ComparisonExport()
    try:
        export.prepare(reader,attribution(),request)
        report=manifest(export)
        assert members(report,'a')=={7,8} and members(report,'b')=={8}
        assert report['membership_events']==2 and report['overlap']['included']==1
        # A small selection should not require a separate query for every
        # unrelated range before it. One initial window plus a search suffices.
        assert len(calls)<=3
        assert not reader.closed
    finally:export.close()


def test_raw_ranges_with_only_orphaned_tracks_do_not_hide_later_exact_large_ids(reader,monkeypatch):
    monkeypatch.setattr(comparison,'BATCH_EVENTS',3)
    base=2**53+17;ids=[base+i*10**10 for i in range(6)]
    for index,event_id in enumerate(ids):
        reader.decoder.add(event_id,index,pid=99 if index<3 else 21)
    orphan=reader.decoder.tracks[99]
    reader.decoder.db.execute('DELETE FROM __intrinsic_process WHERE id=?',(orphan,))
    request={key:frozen(reader,ids[-1]) for key in ('a','b')}
    export=comparison.ComparisonExport()
    try:
        export.prepare(reader,attribution(),request)
        report=manifest(export)
        assert members(report,'a')==members(report,'b')==set(ids[3:])
        assert report['membership_events']==3 and report['totals']['a']['matched']==3
        assert not reader.closed
    finally:export.close()


@pytest.mark.parametrize('body',[
    b'first_id,last_id,scanned\n',
    b'first_id,last_id,scanned\n11,11,1\n12,12,1\n',
    b'first_id,last_id,first_id\n11,11,1\n',
    b'first_id,last_id,scanned,extra\n11,11,1,x\n',
    b'first_id,last_id,scanned\n11,11,1,x\n',
    b'first_id,last_id,scanned\n11,11\n',
    b'first_id,last_id,scanned\n11,11,0\n',
    b'first_id,last_id,scanned\n-1,-1,1\n',
    b'first_id,last_id,scanned\n10,11,2\n',
    b'first_id,last_id,scanned\n11,30001,2\n',
    b'first_id,last_id,scanned\n11,30000,20001\n',
    b'first_id,last_id,scanned\n11,11,2\n',
    b'first_id,last_id,scanned\n11,12,1\n',
    b'first_id,last_id,scanned\n011,11,1\n',
    b'first_id,last_id,scanned\n11,11, 1\n',
    b'first_id,last_id,scanned\n11,11,1.0\n',
    b'first_id,last_id,scanned\n11,11,-1\n',
    b'first_id,last_id,scanned\n11,11,\xff\n',
])
def test_native_window_rejects_ambiguous_out_of_bounds_or_noncanonical_summaries(body):
    with pytest.raises(ContractError,match='native window'):
        comparison.membership_window(body,10,30000)


def test_native_window_preserves_exact_large_ids_and_unambiguous_empty_population():
    first,last=2**53+17,2**63-1
    body=f'first_id,last_id,scanned\n{first},{last},2\n'.encode()
    assert comparison.membership_window(body,first-1,last)==(first,last,2)
    assert comparison.membership_window(b'first_id,last_id,scanned\n-1,-1,0\n',-1,0) is None


def test_native_window_rejects_oversized_csv_even_when_extra_lines_are_blank():
    body=b'first_id,last_id,scanned\n11,11,1\n'+b'\n'*200
    with pytest.raises(ContractError,match='native window'):
        comparison.membership_window(body,10,30000)


def test_native_window_rejects_unterminated_quoted_count():
    with pytest.raises(ContractError,match='native window'):
        comparison.membership_window(b'first_id,last_id,scanned\n11,11,"1',10,30000)


def test_failed_native_window_closes_reader_and_retains_previous_report(reader,monkeypatch):
    reader.decoder.add(1,1)
    request={key:frozen(reader,1) for key in ('a','b')}
    export=comparison.ComparisonExport()
    try:
        prior=export.prepare(reader,attribution(),request);path=export.path
        original=reader.decoder.query
        def broken(sql,**kwargs):
            if sql.startswith('WITH raw_ids AS'):
                return b'first_id,last_id,scanned\n1,1,0\n'
            return original(sql,**kwargs)
        monkeypatch.setattr(reader.decoder,'query',broken)
        with pytest.raises(ContractError,match='native window'):export.prepare(reader,attribution(),request)
        assert reader.closed and export.path==path and export.receipt==prior
        manifest(export)
    finally:export.close()


def test_bundle_phase_probe_uncertainty_and_other_analyst_activity_are_retained(reader):
    reader.decoder.add(1,1,script=77)
    reader.decoder.add(2,2,script=77)  # Not confirmed as a probe simply because its script matches.
    request={key:frozen(reader,2) for key in ('a','b')}
    export=comparison.ComparisonExport()
    try:
        export.prepare(reader,attribution([1],limited=True),request,
                       bundle={'source_phase':'interrupted-recording','sha256':'b'*64})
        report=manifest(export)
        assert members(report,'a')=={2} and members(report,'a',True)=={1}
        assert report['probe_policy']['match_limit_reached']
        assert report['probe_policy']['other_analyst_activity_is_not_automatically_identified']
        assert report['recording']['source_phase']=='interrupted-recording'
    finally:export.close()


@pytest.mark.parametrize('mutation',[
    lambda q:q.update(c={'filters':{}}),lambda q:q['a'].update(extra='x'),
    lambda q:q['a']['filters'].update(sql='SELECT 1'),lambda q:q['a'].update(cursor='bad'),
    lambda q:q['a']['filters'].update(start_ns='1'),lambda q:q['a']['filters'].update(scope={}),
])
def test_invalid_or_changed_selections_do_not_read_or_close_inspector(reader,mutation):
    request={key:frozen(reader,1) for key in ('a','b')}
    mutation(request)
    reader.read=lambda **kwargs:pytest.fail('invalid selection touched the decoder')
    export=comparison.ComparisonExport()
    with pytest.raises(ContractError):export.prepare(reader,attribution(),request)
    assert not reader.closed and export.path is None


def test_decoder_generation_expires_saved_searches_before_replay(reader):
    request={key:frozen(reader,1) for key in ('a','b')}
    reader.history_key=b'changed'*5
    reader.read=lambda **kwargs:pytest.fail('expired selection read')
    with pytest.raises(ContractError):comparison.ComparisonExport().prepare(reader,attribution(),request)
    assert not reader.closed


def test_failed_limits_preserve_prepared_download_and_healthy_inspector(reader,monkeypatch):
    reader.decoder.add(1,1)
    request={key:frozen(reader,1) for key in ('a','b')}
    export=comparison.ComparisonExport()
    try:
        first=export.prepare(reader,attribution(),request)
        path=export.path
        monkeypatch.setattr(comparison,'MAX_ARTIFACT_BYTES',10)
        with pytest.raises(comparison.ComparisonLimit):export.prepare(reader,attribution(),request)
        assert not reader.closed and path==export.path and first==export.receipt
        manifest(export)
        monkeypatch.setattr(comparison,'MAX_ARTIFACT_BYTES',512*1024*1024)
        monkeypatch.setattr(comparison,'MAX_SCAN_SECONDS',-1)
        with pytest.raises(comparison.ComparisonLimit):export.prepare(reader,attribution(),request)
        assert not reader.closed and first==export.receipt
    finally:export.close()


def test_membership_budget_counts_writes_across_batches(reader,monkeypatch):
    for event_id in range(1,4):reader.decoder.add(event_id,event_id)
    request={key:frozen(reader,3) for key in ('a','b')}
    monkeypatch.setattr(comparison,'BATCH_EVENTS',1)
    monkeypatch.setattr(comparison,'MAX_ARTIFACT_BYTES',9)
    export=comparison.ComparisonExport()
    try:
        with pytest.raises(comparison.ComparisonLimit,match='membership exceeds its byte budget'):
            export.prepare(reader,attribution(),request)
        assert export.path is None and not reader.closed
    finally:export.close()


def test_short_comparison_write_preserves_prior_download(reader,monkeypatch):
    reader.decoder.add(1,1)
    request={key:frozen(reader,1) for key in ('a','b')}
    export=comparison.ComparisonExport()
    try:
        first=export.prepare(reader,attribution(),request)
        prior_path=export.path
        original_open=Path.open

        class ShortWriter:
            def __init__(self,stream):
                self.stream=stream
                self.injected=False

            def __enter__(self):
                self.stream.__enter__()
                return self

            def __exit__(self,*args):
                return self.stream.__exit__(*args)

            def __getattr__(self,name):
                return getattr(self.stream,name)

            def write(self,body):
                if not self.injected:
                    self.injected=True
                    self.stream.write(body[:-1])
                    return len(body)-1
                return self.stream.write(body)

        def short_open(path,mode='r',*args,**kwargs):
            stream=original_open(path,mode,*args,**kwargs)
            return ShortWriter(stream) if path.name=='comparison.json' and mode=='xb' else stream

        monkeypatch.setattr(Path,'open',short_open)
        with pytest.raises(ContractError,match='comparison export wrote incomplete bytes'):
            export.prepare(reader,attribution(),request)
        assert export.path==prior_path and export.receipt==first and not reader.closed
        manifest(export)
    finally:export.close()


def test_short_membership_group_write_cannot_publish_false_count(reader,monkeypatch):
    reader.decoder.add(1,1)
    request={key:frozen(reader,1) for key in ('a','b')}
    export=comparison.ComparisonExport()
    try:
        first=export.prepare(reader,attribution(),request)
        prior_path=export.path
        original_open=Path.open

        class EmptyWrite:
            def __init__(self,stream):
                self.stream=stream

            def __enter__(self):
                self.stream.__enter__()
                return self

            def __exit__(self,*args):
                return self.stream.__exit__(*args)

            def write(self,body):
                return 0

            def fileno(self):
                return self.stream.fileno()

        def short_open(path,mode='r',*args,**kwargs):
            stream=original_open(path,mode,*args,**kwargs)
            return EmptyWrite(stream) if path.name.startswith('group-') and mode in ('xb','r+b') else stream

        monkeypatch.setattr(Path,'open',short_open)
        with pytest.raises(ContractError,match='comparison membership wrote incomplete bytes'):
            export.prepare(reader,attribution(),request)
        assert export.path==prior_path and export.receipt==first and not reader.closed
        manifest(export)
    finally:export.close()


@pytest.mark.parametrize('mutation',['truncate','replace'])
def test_changed_membership_group_cannot_publish_false_exact_membership(reader,monkeypatch,mutation):
    reader.decoder.add(1,1)
    reader.decoder.add(2,2)
    request={key:frozen(reader,2) for key in ('a','b')}
    export=comparison.ComparisonExport()
    try:
        first=export.prepare(reader,attribution(),request)
        prior_path=export.path
        original_open=Path.open

        def changed_open(path,mode='r',*args,**kwargs):
            if path.name.startswith('group-') and mode=='rb':
                with original_open(path,'r+b') as stream:
                    body=stream.read()
                    if mutation=='truncate':
                        stream.truncate(body.index(b','))
                    else:
                        stream.seek(0)
                        stream.write(body.replace(b'"2"',b'"3"'))
            return original_open(path,mode,*args,**kwargs)

        monkeypatch.setattr(Path,'open',changed_open)
        with pytest.raises(ContractError,match='comparison membership group changed'):
            export.prepare(reader,attribution(),request)
        assert export.path==prior_path and export.receipt==first and not reader.closed
        manifest(export)
    finally:export.close()


def test_progress_counts_unique_members_and_never_exposes_filters(reader,monkeypatch):
    for i in range(1,8):reader.decoder.add(i,i)
    request={key:frozen(reader,7,search='fixture') for key in ('a','b')}
    export=comparison.ComparisonExport();states=[]
    assert export.progress()=={'preparing':False} and not export.cancel()
    original=export._progress
    def observe(phase,checked=None):
        original(phase,checked);states.append(export.progress())
    monkeypatch.setattr(export,'_progress',observe)
    try:
        export.prepare(reader,attribution(),request)
        assert [s['observations_checked'] for s in states if s['phase']=='scanning']==['0','7']
        assert states[-1]['phase']=='saving' and states[-1]['observations_checked']=='7'
        assert all(set(s)=={'preparing','phase','observations_checked','seconds_elapsed','cancel_requested'} for s in states)
        assert all(s['seconds_elapsed']>=0 and s['preparing'] for s in states)
        assert export.receipt['summary']['membership_events']==7  # Overlap is not counted twice.
        assert export.progress()=={'preparing':False} and not export.cancel()
    finally:export.close()


@pytest.mark.parametrize('phase',['reading','scanning','saving'])
def test_cancellation_preserves_old_report_and_decoder_at_each_stage(reader,monkeypatch,phase):
    reader.decoder.add(1,1)
    request={key:frozen(reader,1) for key in ('a','b')}
    export=comparison.ComparisonExport()
    try:
        first=export.prepare(reader,attribution(),request);prior_path=export.path
        if phase=='reading':
            original=reader.read
            def interrupted_read(**kwargs):
                assert export.progress()['phase']=='reading'
                assert export.cancel()
                return original(**kwargs)
            monkeypatch.setattr(reader,'read',interrupted_read)
        else:
            original=export._progress
            def interrupted_progress(current,checked=None):
                original(current,checked)
                if current==phase:
                    assert export.cancel() and export.progress()['cancel_requested']
            monkeypatch.setattr(export,'_progress',interrupted_progress)
        with pytest.raises(comparison.ComparisonCancelled):export.prepare(reader,attribution(),request)
        assert not reader.closed and export.path==prior_path and export.receipt==first
        assert export.progress()=={'preparing':False} and not export.cancel()
        manifest(export)
        monkeypatch.undo()
        assert export.prepare(reader,attribution(),request)['summary']['membership_events']==1
    finally:export.close()


def test_cancellation_during_native_query_is_observed_without_closing_decoder(reader,monkeypatch):
    reader.decoder.add(1,1)
    request={key:frozen(reader,1) for key in ('a','b')}
    export=comparison.ComparisonExport();query=reader.decoder.query
    def interrupted(*args,**kwargs):
        assert export.cancel()
        return query(*args,**kwargs)
    monkeypatch.setattr(reader.decoder,'query',interrupted)
    try:
        with pytest.raises(comparison.ComparisonCancelled):export.prepare(reader,attribution(),request)
        assert not reader.closed and export.path is None and export.progress()=={'preparing':False}
    finally:export.close()


def test_cancel_after_publication_commits_does_not_promise_withdrawal(reader,monkeypatch):
    reader.decoder.add(1,1)
    request={key:frozen(reader,1) for key in ('a','b')}
    export=comparison.ComparisonExport();publish=export._publish;states=[]
    def publishing(*args,**kwargs):
        states.append(export.progress())
        assert not export.cancel()
        return publish(*args,**kwargs)
    monkeypatch.setattr(export,'_publish',publishing)
    try:
        export.prepare(reader,attribution(),request)
        assert states[0]['phase']=='publishing' and states[0]['preparing']
        assert export.receipt is not None and not reader.closed
    finally:export.close()


def test_native_header_failure_closes_reader_and_never_publishes_partial_report(reader):
    reader.decoder.add(1,1)
    reader.decoder.args[1001]['debug.api']='Unrecognized.private'
    request={key:frozen(reader,1) for key in ('a','b')}
    export=comparison.ComparisonExport()
    with pytest.raises(ContractError):export.prepare(reader,attribution(),request)
    assert reader.closed and export.path is None


@pytest.mark.parametrize('label', ['a','b'])
def test_membership_cannot_assign_event_beyond_its_saved_selection_highwater(reader,monkeypatch,label):
    for event_id in (1,2,3):
        reader.decoder.add(event_id,event_id)
    request={key:frozen(reader,2 if key==label else 3) for key in ('a','b')}
    original=reader.decoder.query

    def forged(sql,**kwargs):
        if sql.startswith('WITH batch AS'):
            output=io.StringIO()
            writer=csv.writer(output)
            writer.writerow(['schema','allowlist','api','completion','in_a','in_b','event_ids'])
            writer.writerow([CAPTURE_V1['schema'],CAPTURE_V1['allowlist'],
                             'Navigator.userAgent.get','returned',
                             '1' if label=='a' else '0','1' if label=='b' else '0','3'])
            return output.getvalue().encode()
        return original(sql,**kwargs)

    monkeypatch.setattr(reader.decoder,'query',forged)
    export=comparison.ComparisonExport()
    with pytest.raises(ContractError,match='selection snapshot'):
        export.prepare(reader,attribution(),request)
    assert reader.closed and export.path is None


def test_native_exit_uses_existing_recovery_and_never_publishes_partial_report(reader):
    request={key:frozen(reader,1) for key in ('a','b')}
    def failed(*args,**kwargs):raise DecoderInterrupted('owned process exited')
    def recover():raise InspectionRebuilding('replaying')
    reader.decoder.query=failed;reader._recover_decoder=recover
    export=comparison.ComparisonExport()
    with pytest.raises(InspectionRebuilding):export.prepare(reader,attribution(),request)
    assert export.path is None


def test_successful_decoder_recovery_cannot_publish_partial_comparison(
    reader, monkeypatch
):
    monkeypatch.setattr(comparison, 'BATCH_EVENTS', 1)
    reader.decoder.add(1, 1)
    reader.decoder.add(2, 2)
    request={key:frozen(reader,2) for key in ('a','b')}
    original=reader.decoder.query
    windows=0
    recovered=[]
    def interrupt_second_window(sql, **kwargs):
        nonlocal windows
        if 'WITH raw_ids' in sql:
            windows+=1
            if windows==2:raise DecoderInterrupted('owned process exited')
        return original(sql, **kwargs)
    reader.decoder.query=interrupt_second_window
    reader._recover_decoder=lambda:recovered.append(True)
    export=comparison.ComparisonExport()
    try:
        with pytest.raises(comparison.ComparisonLimit,match='interrupted'):
            export.prepare(reader,attribution(),request)
        assert recovered==[True]
        assert export.path is None
        assert not reader.closed
    finally:export.close()


@pytest.mark.parametrize('ids',['1,1','01','0','-1',str(2**63),'1,4096','', '1,2,1'])
def test_membership_transport_rejects_duplicate_noncanonical_and_wrong_block_ids(ids):
    output=io.StringIO();writer=csv.writer(output)
    writer.writerow(['event_ids','schema','allowlist','api','completion','in_a','in_b'])
    writer.writerow([ids,CAPTURE_V1['schema'],CAPTURE_V1['allowlist'],'Navigator.userAgent.get','returned','1','0'])
    with pytest.raises(ContractError):comparison.membership_rows(output.getvalue().encode(),0,2**63-1,CAPTURE_V1)


def test_membership_transport_rejects_missing_event_ids_as_contract_error():
    output=io.StringIO();writer=csv.writer(output)
    writer.writerow(['schema','allowlist','api','completion','in_a','in_b','event_ids'])
    writer.writerow([CAPTURE_V1['schema'],CAPTURE_V1['allowlist'],
                     'Navigator.userAgent.get','returned','1','0'])
    with pytest.raises(ContractError,match='bounded contract'):
        comparison.membership_rows(output.getvalue().encode(),0,2**63-1,CAPTURE_V1)


def test_membership_transport_rejects_oversized_csv_before_parsing_blank_padding():
    output=io.StringIO();writer=csv.writer(output)
    writer.writerow(['event_ids','schema','allowlist','api','completion','in_a','in_b'])
    writer.writerow(['1',CAPTURE_V1['schema'],CAPTURE_V1['allowlist'],
                     'Navigator.userAgent.get','returned','1','0'])
    body=output.getvalue().encode()+b'\n'*(2*1024*1024)
    with pytest.raises(ContractError,match='bounded contract'):
        comparison.membership_rows(body,0,1,CAPTURE_V1)


def test_membership_transport_stops_parsing_after_row_limit(monkeypatch):
    body=(b'event_ids,schema,allowlist,api,completion,in_a,in_b\n'
          +b'x,,,,,,\n'*100_000)
    original_reader=comparison.csv.DictReader
    consumed=[]

    class CountedReader:
        def __init__(self,*args,**kwargs):
            self.reader=original_reader(*args,**kwargs)
            self.fieldnames=self.reader.fieldnames

        def __iter__(self):return self

        def __next__(self):
            consumed.append(True)
            if len(consumed)>comparison.PAGE_ROWS+2:
                pytest.fail('comparison parsed beyond its row limit')
            return next(self.reader)

    monkeypatch.setattr(comparison.csv,'DictReader',CountedReader)
    with pytest.raises(ContractError,match='bounded contract'):
        comparison.membership_rows(body,0,2**63-1,CAPTURE_V1)
    assert len(consumed)<=comparison.PAGE_ROWS+2


def test_membership_transport_rejects_unterminated_quoted_selection():
    output=io.StringIO();writer=csv.writer(output)
    writer.writerow(['event_ids','schema','allowlist','api','completion','in_a','in_b'])
    writer.writerow(['1',CAPTURE_V1['schema'],CAPTURE_V1['allowlist'],
                     'Navigator.userAgent.get','returned','1','0'])
    body=output.getvalue().rstrip('\r\n').rsplit(',',1)[0]+',"0'
    with pytest.raises(ContractError,match='bounded contract'):
        comparison.membership_rows(body.encode(),0,1,CAPTURE_V1)
