from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace
import hashlib
import json
import os
import struct
import subprocess
import pytest

import browser_core.evidence_bundle as evidence
from browser_core.evidence_contract import validate_metadata,MAX_METADATA_BYTES
from browser_core.inspection_attribution import ContextAttribution,source_label
from browser_core.inspection_contract import CAPTURE_V2
from browser_core.inspection_health import decode_health
from browser_core.contracts import ContractError
from browser_core.prepared_download import ExportCleanupPending

BUILD={'provenance':'attested-browser-core','executable_sha256_16':'1'*16,
       'runtime_bundle_sha256_16':'2'*16,'attestation_created_at':'2026-09-13T01:00:00Z'}
BODY=b'\x0a\x01x'


def metadata(body=BODY):
    return {'schema':evidence.SCHEMA,'exported_at':'2026-09-13T02:00:00Z','capture':CAPTURE_V2,
        'producer_build':dict(BUILD),'export_reader_build':dict(BUILD),
        'recording':{'bytes':len(body),'sha256':hashlib.sha256(body).hexdigest(),'packets':1,
            'source_bytes':len(body),'excluded_tail_bytes':0,'source_phase':'live-prefix','run_id':'owned-run'},
        'contexts':{'attempts':0,'last_attempt':None,'probes':[],'conflicts':[],'match_limit_reached':False},'health':None}


def pack(path,m=None,body=BODY):
    header=json.dumps(m or metadata(body)).encode()
    data=evidence.MAGIC+struct.pack('<Q',len(header))+header+body
    path.write_bytes(data);return hashlib.sha256(data).hexdigest()


@pytest.mark.parametrize('slow_operation',['read','write'])
def test_export_copy_rejects_final_io_after_deadline(monkeypatch,slow_operation):
    clock=[0.0]
    monkeypatch.setattr(evidence,'time',SimpleNamespace(monotonic=lambda:clock[0]))

    class Source:
        def read(self,_count):
            if slow_operation=='read':clock[0]=2.0
            return b'x'

    class Destination:
        def write(self,body):
            if slow_operation=='write':clock[0]=2.0
            return len(body)

    with pytest.raises(ContractError,match='time budget'):
        evidence._copy(Source(),Destination(),1,deadline=1.0)


@pytest.mark.parametrize('slow_operation',['read','write','packet_validation'])
def test_import_packet_copy_rejects_final_io_after_deadline(monkeypatch,slow_operation):
    clock=[0.0]
    monkeypatch.setattr(evidence,'time',SimpleNamespace(monotonic=lambda:clock[0]))

    class Source:
        def read(self,_count):
            if slow_operation=='read':clock[0]=2.0
            return b'x'

    class Destination:
        def write(self,body):
            if slow_operation=='write':clock[0]=2.0
            return len(body)

    def packet_copy(source,destination,size,*,packet_limit):
        body=source.read(size)
        destination.write(body)
        if slow_operation=='packet_validation':clock[0]=2.0
        return len(body),1,hashlib.sha256(body).hexdigest()

    monkeypatch.setattr(evidence,'_copy_packets',packet_copy)
    with pytest.raises(ContractError,match='time budget'):
        evidence._copy_verified_packets(Source(),Destination(),1,
                                        whole_digest=hashlib.sha256(),deadline=1.0)


@pytest.fixture
def runtime(monkeypatch,tmp_path):
    calls=[]
    monkeypatch.setattr(evidence,'executable_evidence',lambda root,reader,**kw:calls.append(reader) or dict(BUILD))
    return tmp_path/'chrome.exe',calls


def test_bundle_reopens_from_its_verified_copy_after_original_is_removed(tmp_path,runtime):
    reader,calls=runtime;path=tmp_path/'recording.bcevidence';digest=pack(path)
    bundle=evidence.OpenEvidence(path,tmp_path,reader,expected_sha256=digest)
    try:
        path.unlink()
        assert bundle.path.read_bytes()==BODY and bundle.summary['expected_digest_matched']
        location=bundle.source.resolve()
        assert not location.browser_running and location.executable==reader
        assert 'automation' not in location.session
        assert bundle.summary['source_phase']=='live-prefix'
        assert bundle.summary['proves_capture_complete'] is False
        assert bundle.summary['authenticity']=='unsigned-exporter-metadata'
        assert all(p==reader for p in calls)
    finally:bundle.close()
    assert not bundle.path.exists()


def test_open_evidence_preserves_replaced_private_directory_on_close(
        tmp_path, runtime, monkeypatch):
    reader, _ = runtime
    source = tmp_path / 'bundle'
    pack(source)
    original_temporary = evidence.TemporaryDirectory
    monkeypatch.setattr(
        evidence, 'TemporaryDirectory',
        lambda **kwargs: original_temporary(dir=tmp_path, **kwargs),
    )
    bundle = evidence.OpenEvidence(source, tmp_path, reader)
    original_name = Path(bundle.folder.name)
    retained = tmp_path / 'retained-copy'
    assert original_name.resolve().parent == tmp_path.resolve()
    original_name.rename(retained)
    original_name.mkdir()
    sentinel = original_name / 'unrelated.txt'
    sentinel.write_text('preserve', encoding='utf-8')
    cleanup = bundle.folder.cleanup
    calls = []
    monkeypatch.setattr(bundle.folder, 'cleanup', lambda: calls.append('cleanup'))
    try:
        with pytest.raises(ContractError, match='copy directory.*cleanup'):
            bundle.close()
        assert calls == []
        assert sentinel.read_text(encoding='utf-8') == 'preserve'
    finally:
        monkeypatch.setattr(bundle.folder, 'cleanup', cleanup)
        sentinel.unlink(missing_ok=True)
        original_name.rmdir()
        retained.rename(original_name)
        bundle.close()
        cleanup()


def test_open_evidence_rejects_changed_copy_ancestor_during_import(
        tmp_path, runtime, monkeypatch):
    import browser_core.perfetto as perfetto

    reader, _ = runtime
    source = tmp_path / 'bundle'
    pack(source)
    private_parent = tmp_path / 'private-parent'
    private_parent.mkdir()
    retained_parent = tmp_path / 'retained-parent'
    original_temporary = evidence.TemporaryDirectory
    original_stable = perfetto._stable_file_binding
    holder = {}

    def temporary(**kwargs):
        folder = original_temporary(dir=private_parent, **kwargs)
        holder['folder'] = folder
        return folder

    def bind_and_move_parent(*args, **kwargs):
        result = original_stable(*args, **kwargs)
        name = Path(holder['folder'].name).name
        private_parent.rename(retained_parent)
        private_parent.mkdir()
        (retained_parent / name).rename(private_parent / name)
        return result

    monkeypatch.setattr(evidence, 'TemporaryDirectory', temporary)
    monkeypatch.setattr(perfetto, '_stable_file_binding', bind_and_move_parent)
    opened = None
    try:
        with pytest.raises(ContractError, match='copy directory'):
            opened = evidence.OpenEvidence(source, tmp_path, reader)
    finally:
        if opened is not None:
            opened.close()
        folder = holder.get('folder')
        if folder is not None:
            folder.cleanup()
        if retained_parent.exists():
            retained_parent.rmdir()
        private_parent.rmdir()


def test_open_evidence_preserves_copy_after_ancestor_changes_before_close(
        tmp_path, runtime, monkeypatch):
    reader, _ = runtime
    source = tmp_path / 'bundle'
    pack(source)
    private_parent = tmp_path / 'private-parent'
    private_parent.mkdir()
    retained_parent = tmp_path / 'retained-parent'
    original_temporary = evidence.TemporaryDirectory
    monkeypatch.setattr(
        evidence, 'TemporaryDirectory',
        lambda **kwargs: original_temporary(dir=private_parent, **kwargs),
    )
    bundle = evidence.OpenEvidence(source, tmp_path, reader)
    name = Path(bundle.folder.name).name
    current_folder = private_parent / name
    retained_folder = retained_parent / name
    private_parent.rename(retained_parent)
    private_parent.mkdir()
    retained_folder.rename(current_folder)
    sentinel = current_folder / 'unrelated.txt'
    sentinel.write_text('preserve', encoding='utf-8')
    try:
        with pytest.raises(ContractError, match='copy directory.*cleanup'):
            bundle.close()
        assert sentinel.read_text(encoding='utf-8') == 'preserve'
    finally:
        sentinel.unlink(missing_ok=True)
        if current_folder.exists():
            current_folder.rename(retained_folder)
        private_parent.rmdir()
        retained_parent.rename(private_parent)
        if not bundle._closed:
            bundle.close()


@pytest.mark.skipif(os.name != 'nt', reason='Windows directory junction boundary')
def test_open_evidence_does_not_copy_into_junction_replacing_private_directory(
        tmp_path,runtime,monkeypatch):
    reader,_=runtime
    source=tmp_path/'bundle'
    pack(source)
    target=tmp_path/'unrelated'
    target.mkdir()
    junction=tmp_path/'private-copy'
    created=subprocess.run(['cmd','/c','mklink','/J',str(junction),str(target)],
                           capture_output=True,check=False)
    if created.returncode:
        pytest.skip('host could not create an unprivileged directory junction')

    class SwappedFolder:
        name=str(junction)
        def cleanup(self):
            if junction.exists():junction.rmdir()

    monkeypatch.setattr(evidence,'TemporaryDirectory',lambda **kwargs:SwappedFolder())
    opened=None
    try:
        with pytest.raises(ContractError,match='copy directory|reparse|junction'):
            opened=evidence.OpenEvidence(source,tmp_path,reader)
        assert list(target.iterdir())==[]
    finally:
        if opened is not None:opened.close()
        if junction.exists():junction.rmdir()


def test_resolved_evidence_view_cannot_mutate_retained_bundle_claims(tmp_path,runtime):
    reader,_=runtime;path=tmp_path/'bundle';pack(path)
    bundle=evidence.OpenEvidence(path,tmp_path,reader)
    try:
        original_build=deepcopy(bundle.metadata['producer_build'])
        original_capture=deepcopy(bundle.metadata['capture'])
        location=bundle.source.resolve()
        location.session['build']['executable_sha256_16']='9'*16
        location.session['value_capture']['allowlist']='changed'
        location.reader_runtime['producer_build']['runtime_bundle_sha256_16']='8'*16
        location.reader_runtime['reader_build']['runtime_bundle_sha256_16']='7'*16
        assert bundle.metadata['producer_build']==original_build
        assert bundle.metadata['capture']==original_capture
        assert bundle.source.resolve().reader_runtime['reader_build']==BUILD
    finally:bundle.close()


def test_opened_bundle_metadata_alias_cannot_change_verified_source_claims(tmp_path,runtime):
    reader,_=runtime;path=tmp_path/'bundle';pack(path)
    bundle=evidence.OpenEvidence(path,tmp_path,reader)
    try:
        bundle.metadata['recording']['run_id']='forged-run'
        bundle.metadata['producer_build']['executable_sha256_16']='9'*16
        location=bundle.source.resolve()
        assert location.session['run_id']=='owned-run'
        assert location.session['build']==BUILD
    finally:bundle.close()


def test_open_rejects_a_copy_changed_before_its_source_binding(tmp_path,runtime,monkeypatch):
    reader,_=runtime
    path=tmp_path/'bundle'
    pack(path)
    original=evidence.EvidenceSource

    def changed_copy(copy_path,metadata,selected_reader,root):
        copy_path.write_bytes(b'\x0a\x01y')
        return original(copy_path,metadata,selected_reader,root)

    monkeypatch.setattr(evidence,'EvidenceSource',changed_copy)
    opened=None
    try:
        with pytest.raises(ContractError,match='evidence recording copy changed'):
            opened=evidence.OpenEvidence(path,tmp_path,reader)
    finally:
        if opened is not None:opened.close()


@pytest.mark.parametrize('change', ['append', 'replace'])
def test_reopened_evidence_reader_rejects_changed_verified_copy(tmp_path,runtime,change):
    reader,_=runtime
    path=tmp_path/'bundle'
    pack(path)
    bundle=evidence.OpenEvidence(path,tmp_path,reader)
    try:
        if change=='append':
            with bundle.path.open('ab') as stream:
                stream.write(BODY)
        else:
            bundle.path.rename(bundle.path.with_name('retired.pftrace'))
            bundle.path.write_bytes(BODY)
        with pytest.raises(ContractError,match='copy changed'):
            bundle.source.resolve()
    finally:
        bundle.close()


def test_reopened_evidence_reader_rejects_same_size_copy_change_with_restored_mtime(tmp_path,runtime):
    reader,_=runtime
    path=tmp_path/'bundle'
    pack(path)
    bundle=evidence.OpenEvidence(path,tmp_path,reader)
    try:
        before=bundle.path.stat()
        bundle.path.write_bytes(b'\x0a\x01y')
        os.utime(bundle.path,ns=(before.st_atime_ns,before.st_mtime_ns))
        assert bundle.path.stat().st_size==before.st_size
        assert bundle.path.stat().st_mtime_ns==before.st_mtime_ns
        with pytest.raises(ContractError,match='copy changed'):
            bundle.source.resolve()
    finally:
        bundle.close()


@pytest.mark.skipif(os.name != 'nt', reason='Windows change-time fallback')
def test_reopened_evidence_reader_checks_bytes_when_change_time_is_unchanged(
        tmp_path, runtime, monkeypatch):
    reader, _ = runtime
    path = tmp_path/'bundle'
    pack(path)
    bundle = evidence.OpenEvidence(path, tmp_path, reader)
    try:
        before = bundle.path.stat()
        bound_change_time = bundle.source.copy_binding[-1]
        monkeypatch.setattr(evidence, '_windows_change_time',
                            lambda _handle: bound_change_time)
        bundle.path.write_bytes(b'\x0a\x01y')
        os.utime(bundle.path, ns=(before.st_atime_ns, before.st_mtime_ns))
        assert bundle.source._copy_binding() == bundle.source.copy_binding
        with pytest.raises(ContractError, match='copy changed'):
            bundle.source.resolve()
    finally:
        bundle.close()


@pytest.mark.parametrize('change',[
    lambda m:m.update(executable='C:/unexpected.exe'),
    lambda m:m['producer_build'].update(executable='C:/unexpected.exe'),
    lambda m:m['recording'].update(source_phase='complete-and-trusted'),
    lambda m:m['recording'].update(bytes=True),
    lambda m:m['recording'].update(source_bytes=999),
    lambda m:m['recording'].update(run_id='http://private/endpoint'),
    lambda m:m['contexts'].update(attempts=5),
    lambda m:m['contexts'].update(probes=[{}]),
    lambda m:m.update(health={'proves_complete':True}),
    lambda m:m.update(capture={'schema':'unknown','allowlist':'unknown'}),
    lambda m:m['recording'].update(source_phase=[]),
])
def test_manifest_refuses_unbounded_or_executable_metadata(tmp_path,runtime,change):
    reader,calls=runtime;m=metadata();change(m);path=tmp_path/'bad.bcevidence';pack(path,m)
    with pytest.raises(ContractError):evidence.OpenEvidence(path,tmp_path,reader)
    assert not calls


@pytest.mark.parametrize('kind',['recording-bit','truncation','suffix','header-limit','duplicate-key','expected-digest'])
def test_tampering_is_rejected_before_any_reader_runs(tmp_path,runtime,kind):
    reader,calls=runtime;path=tmp_path/'bad.bcevidence';pack(path);body=path.read_bytes()
    if kind=='recording-bit':body=body[:-1]+b'y'
    elif kind=='truncation':body=body[:-1]
    elif kind=='suffix':body+=b'x'
    elif kind=='header-limit':body=evidence.MAGIC+struct.pack('<Q',MAX_METADATA_BYTES+1)
    elif kind=='duplicate-key':
        header=b'{"schema":"one","schema":"two"}'
        body=evidence.MAGIC+struct.pack('<Q',len(header))+header
    path.write_bytes(body)
    with pytest.raises(ContractError):evidence.OpenEvidence(path,tmp_path,reader,expected_sha256='f'*64 if kind=='expected-digest' else None)
    assert not calls


def test_coherent_metadata_rewrite_requires_trusted_external_digest_to_detect(tmp_path,runtime):
    reader,_=runtime;path=tmp_path/'bundle';digest=pack(path)
    m=metadata();m['producer_build']['executable_sha256_16']='3'*16;pack(path,m)
    with pytest.raises(ContractError,match='expected SHA'):evidence.OpenEvidence(path,tmp_path,reader,expected_sha256=digest)
    bundle=evidence.OpenEvidence(path,tmp_path,reader)
    try:assert bundle.summary['expected_digest_matched'] is False
    finally:bundle.close()


@pytest.mark.parametrize('body,packets', [
    (BODY, 2), (b'not-a-packet', 1), (BODY+b'\x0a\x05x', 2),
])
def test_bundle_rejects_false_packet_population_before_reader_runs(tmp_path,runtime,body,packets):
    reader,calls=runtime
    m=metadata(body)
    m['recording']['packets']=packets
    path=tmp_path/'bad-packets.bcevidence'
    pack(path,m,body)
    with pytest.raises(ContractError,match='packet'):
        evidence.OpenEvidence(path,tmp_path,reader)
    assert not calls


def test_bundle_accepts_valid_multiple_packets_with_exact_count(tmp_path,runtime):
    reader,_=runtime
    body=BODY+BODY
    m=metadata(body)
    m['recording']['packets']=2
    path=tmp_path/'two-packets.bcevidence'
    pack(path,m,body)
    opened=evidence.OpenEvidence(path,tmp_path,reader)
    try:
        assert opened.path.read_bytes()==body
        assert opened.metadata['recording']['packets']==2
    finally:
        opened.close()


def test_context_probes_warnings_and_conflicts_round_trip(tmp_path,runtime):
    reader,_=runtime;m=metadata();c=m['contexts'];c['attempts']=1
    c['last_attempt']={'probes_requested':1,'probe_callers_verified':1,
                       'unavailable_contexts_or_commands':0,'truncated':False}
    c['probes']=[{'marker':[123456789,987654321],'probe_script_id':7,'sources':{'4':source_label('https://fixture.invalid/app.js?secret=value')},
        'metadata':{'kind':'worker','target_type':'worker','document':source_label('https://fixture.invalid/worker.js'),
            'isolated_probe':False,'target_id':'t','cdp_context_unique_id':'u','identified_at_utc':'2026-09-13T01:00:00Z'}}]
    c['conflicts']=[[10,'aa']];c['match_limit_reached']=True
    m['health']=decode_health(b'name,severity,value\n__capture_stats_present,meta,1\n__sorter_dropped,meta,0\ntraced_buf_chunks_discarded,info,2\n')
    path=tmp_path/'bundle';pack(path,m)
    bundle=evidence.OpenEvidence(path,tmp_path,reader)
    try:
        assert bundle.attribution.probes==c['probes']
        assert bundle.attribution.retained_conflicts=={(10,'aa')}
        assert bundle.attribution.retained_match_limit
        assert bundle.metadata['health']['status']=='issues-reported'
        assert 'secret' not in str(bundle.metadata)
        original_display=bundle.metadata['contexts']['probes'][0]['sources']['4']['display']
        bundle.attribution.probes[0]['sources']['4']['display']='changed after import'
        bundle.attribution.last_attempt['probes_requested']=0
        assert bundle.metadata['contexts']['probes'][0]['sources']['4']['display']==original_display
        assert bundle.metadata['contexts']['last_attempt']['probes_requested']==1
    finally:bundle.close()


def test_imported_debugger_source_display_obeys_producer_byte_cap():
    m=metadata();m['contexts'].update(attempts=1,last_attempt={
        'probes_requested':1,'probe_callers_verified':1,
        'unavailable_contexts_or_commands':0,'truncated':False})
    label=source_label('https://fixture.invalid/app.js')
    m['contexts']['probes']=[{'marker':[123456789,987654321],
        'probe_script_id':7,'sources':{'4':label},
        'metadata':{'kind':'worker','target_type':'worker','document':label,
            'isolated_probe':False,'target_id':'t','cdp_context_unique_id':'u',
            'identified_at_utc':'2026-09-13T01:00:00Z'}}]
    assert validate_metadata(m)==m
    label['display']='é'*512
    with pytest.raises(ContractError):validate_metadata(m)


@pytest.mark.parametrize('display', [
    'https://fixture.invalid/a\x7fb',
    'https://fixture.invalid/app.js?token=secret',
    'https://fixture.invalid/app.js#private',
    'https://user:password@fixture.invalid/app.js',
    'https://fixture.invalid\\private/app.js',
    'https://fixture.invalid:bad/app.js',
])
def test_imported_debugger_source_display_rejects_unmasked_or_ambiguous_urls(display):
    m=metadata();m['contexts'].update(attempts=1,last_attempt={
        'probes_requested':1,'probe_callers_verified':1,
        'unavailable_contexts_or_commands':0,'truncated':False})
    label=source_label('https://fixture.invalid/app.js')
    m['contexts']['probes']=[{'marker':[123456789,987654321],
        'probe_script_id':7,'sources':{'4':label},
        'metadata':{'kind':'worker','target_type':'worker','document':label,
            'isolated_probe':False,'target_id':'t','cdp_context_unique_id':'u',
            'identified_at_utc':'2026-09-13T01:00:00Z'}}]
    label['display']=display
    with pytest.raises(ContractError):validate_metadata(m)


@pytest.mark.parametrize('attempts,last_attempt',[
    (0,{'status':'unavailable'}), (1,None),
])
def test_imported_context_attempts_require_matching_last_attempt(attempts,last_attempt):
    m=metadata();m['contexts'].update(attempts=attempts,last_attempt=last_attempt)
    with pytest.raises(ContractError):validate_metadata(m)


@pytest.mark.parametrize('last_attempt',[
    {'probes_requested':1,'probe_callers_verified':0,
     'unavailable_contexts_or_commands':0,'truncated':False},
    {'status':'unavailable'},
])
def test_first_context_attempt_probe_count_matches_saved_inventory(last_attempt):
    m=metadata();m['contexts'].update(attempts=1,last_attempt=last_attempt)
    if last_attempt.get('status')=='unavailable':
        m['contexts']['probes']=[{'marker':[123456789,987654321],
            'probe_script_id':None,'sources':{},
            'metadata':{'kind':'worker','target_type':'worker','document':source_label(''),
                'isolated_probe':False,'target_id':'t','cdp_context_unique_id':'u',
                'identified_at_utc':'2026-09-13T01:00:00Z'}}]
    with pytest.raises(ContractError):validate_metadata(m)


def test_first_context_attempt_verified_count_matches_saved_probe_ids():
    m=metadata();m['contexts'].update(attempts=1,last_attempt={
        'probes_requested':1,'probe_callers_verified':1,
        'unavailable_contexts_or_commands':0,'truncated':False})
    m['contexts']['probes']=[{'marker':[123456789,987654321],
        'probe_script_id':None,'sources':{},
        'metadata':{'kind':'worker','target_type':'worker','document':source_label(''),
            'isolated_probe':False,'target_id':'t','cdp_context_unique_id':'u',
            'identified_at_utc':'2026-09-13T01:00:00Z'}}]
    with pytest.raises(ContractError):validate_metadata(m)


def test_context_export_stops_at_metadata_limit_before_building_large_json(monkeypatch):
    index=ContextAttribution();index.attempts=1
    index.probes=[{'marker':[123456789,987654321],'probe_script_id':7,
        'sources':{str(i):source_label('https://fixture.invalid/'+'x'*400+str(i))
                   for i in range(8)},
        'metadata':{'kind':'worker','target_type':'worker',
            'document':source_label('https://fixture.invalid/worker.js'),
            'isolated_probe':False,'target_id':'t','cdp_context_unique_id':'u',
            'identified_at_utc':'2026-09-13T01:00:00Z'}}]
    monkeypatch.setattr(evidence,'MAX_METADATA_BYTES',1024)
    with pytest.raises(ContractError,match='context export exceeds its metadata byte limit'):
        evidence.context_state(index)


def test_export_is_a_packet_boundary_snapshot_and_failure_retains_previous_download(tmp_path):
    source_path=tmp_path/'recording';source_path.write_bytes(BODY+b'\x0a\x05x')
    location=SimpleNamespace(path=source_path,phase='live-prefix',session={'run_id':'owned-run','build':BUILD,'value_capture':CAPTURE_V2},
                             reader_runtime={'reader_build':BUILD})
    source=SimpleNamespace(resolve=lambda:location)
    export=evidence.EvidenceExport()
    try:
        receipt=export.prepare(source,ContextAttribution(),None)
        original=export.path;body=original.read_bytes()
        assert receipt['sha256']==hashlib.sha256(body).hexdigest()
        offset=len(evidence.MAGIC)+8;size=struct.unpack('<Q',body[offset-8:offset])[0]
        m=json.loads(body[offset:offset+size])
        assert body[offset+size:]==BODY and m['recording']['excluded_tail_bytes']==3
        assert 'automation' not in m and 'executable' not in m
        location.phase='finalized-recording'
        with pytest.raises(ContractError):export.prepare(source,ContextAttribution(),None)
        assert export.path==original and original.read_bytes()==body
        assert source_path.read_bytes()==BODY+b'\x0a\x05x'
    finally:export.close()
    assert not original.exists()


def test_failed_evidence_export_preserves_replaced_staged_directory(
        tmp_path, monkeypatch):
    source_path = tmp_path / 'recording'
    source_path.write_bytes(BODY)
    location = SimpleNamespace(
        path=source_path, phase='live-prefix',
        session={'run_id': 'owned-run', 'build': BUILD, 'value_capture': CAPTURE_V2},
        reader_runtime={'reader_build': BUILD},
    )
    temporary = evidence.TemporaryDirectory(dir=tmp_path)
    original_name = Path(temporary.name)
    retained = tmp_path / 'retained-export'
    sentinel = original_name / 'unrelated.txt'
    cleanup = temporary.cleanup
    calls = []
    monkeypatch.setattr(temporary, 'cleanup', lambda: calls.append('cleanup'))
    monkeypatch.setattr(evidence, 'TemporaryDirectory', lambda **kwargs: temporary)
    resolves = 0

    def resolve():
        nonlocal resolves
        resolves += 1
        if resolves == 3:
            assert original_name.resolve().parent == tmp_path.resolve()
            original_name.rename(retained)
            original_name.mkdir()
            sentinel.write_text('preserve', encoding='utf-8')
            raise ContractError('source changed after export copy')
        return location

    export = evidence.EvidenceExport()
    try:
        with pytest.raises(ContractError, match='source changed after export copy'):
            export.prepare(SimpleNamespace(resolve=resolve), ContextAttribution(), None)
        assert resolves == 3
        assert calls == []
        assert sentinel.read_text(encoding='utf-8') == 'preserve'
        assert export._retired is temporary
    finally:
        monkeypatch.setattr(temporary, 'cleanup', cleanup)
        sentinel.unlink(missing_ok=True)
        if original_name.exists():
            original_name.rmdir()
        retained.rename(original_name)
        if export._retired is not None:
            export._ensure_cleanup()
        cleanup()


def test_export_rejects_changed_copy_ancestor_before_prepared_binding(
        tmp_path, monkeypatch):
    source_path = tmp_path / 'recording'
    source_path.write_bytes(BODY)
    location = SimpleNamespace(
        path=source_path, phase='live-prefix',
        session={'run_id': 'owned-run', 'build': BUILD, 'value_capture': CAPTURE_V2},
        reader_runtime={'reader_build': BUILD},
    )
    private_parent = tmp_path / 'private-parent'
    private_parent.mkdir()
    retained_parent = tmp_path / 'retained-parent'
    original_temporary = evidence.TemporaryDirectory
    holder = {}
    resolves = 0
    swapped = False

    def temporary(**kwargs):
        folder = original_temporary(dir=private_parent, **kwargs)
        holder['folder'] = folder
        return folder

    def resolve():
        nonlocal resolves, swapped
        resolves += 1
        if resolves == 3:
            folder = holder['folder']
            name = Path(folder.name).name
            private_parent.rename(retained_parent)
            private_parent.mkdir()
            (retained_parent / name).rename(private_parent / name)
            swapped = True
            (private_parent / name / 'unrelated.txt').write_text(
                'preserve', encoding='utf-8'
            )
        return location

    monkeypatch.setattr(evidence, 'TemporaryDirectory', temporary)
    export = evidence.EvidenceExport()
    try:
        with pytest.raises(ContractError, match='evidence export directory|prepared download'):
            export.prepare(SimpleNamespace(resolve=resolve), ContextAttribution(), None)
        assert swapped
        folder = holder['folder']
        assert (Path(folder.name) / 'unrelated.txt').read_text(encoding='utf-8') == 'preserve'
    finally:
        folder = holder.get('folder')
        if swapped and folder is not None:
            name = Path(folder.name).name
            (private_parent / name).rename(retained_parent / name)
            private_parent.rmdir()
            retained_parent.rename(private_parent)
        if export.folder is None:
            export.close()
        elif folder is not None:
            folder.cleanup()
        private_parent.rmdir()


def test_export_rejects_changed_copy_ancestor_before_publication(
        tmp_path, monkeypatch):
    import browser_core.perfetto as perfetto

    source_path = tmp_path / 'recording'
    source_path.write_bytes(BODY)
    location = SimpleNamespace(
        path=source_path, phase='live-prefix',
        session={'run_id': 'owned-run', 'build': BUILD, 'value_capture': CAPTURE_V2},
        reader_runtime={'reader_build': BUILD},
    )
    private_parent = tmp_path / 'private-parent'
    private_parent.mkdir()
    retained_parent = tmp_path / 'retained-parent'
    original_temporary = evidence.TemporaryDirectory
    original_stable = perfetto._stable_file_binding
    holder = {}
    swapped = False

    def temporary(**kwargs):
        folder = original_temporary(dir=private_parent, **kwargs)
        holder['folder'] = folder
        return folder

    def bind_and_move_parent(path, *args, **kwargs):
        nonlocal swapped
        result = original_stable(path, *args, **kwargs)
        if Path(path).name == 'evidence.bcevidence' and not swapped:
            swapped = True
            name = Path(holder['folder'].name).name
            private_parent.rename(retained_parent)
            private_parent.mkdir()
            (retained_parent / name).rename(private_parent / name)
        return result

    monkeypatch.setattr(evidence, 'TemporaryDirectory', temporary)
    monkeypatch.setattr(perfetto, '_stable_file_binding', bind_and_move_parent)
    export = evidence.EvidenceExport()
    try:
        with pytest.raises(ContractError, match='prepared download'):
            export.prepare(
                SimpleNamespace(resolve=lambda: location), ContextAttribution(), None
            )
        assert swapped
    finally:
        folder = holder.get('folder')
        if swapped and folder is not None:
            name = Path(folder.name).name
            current_folder = private_parent / name
            retained_folder = retained_parent / name
            if current_folder.exists():
                current_folder.rename(retained_folder)
            private_parent.rmdir()
            retained_parent.rename(private_parent)
        export.close()
        if folder is not None:
            folder.cleanup()
        private_parent.rmdir()


def test_export_rejects_ancestor_change_at_prepared_handoff(tmp_path, monkeypatch):
    source_path = tmp_path / 'recording'
    source_path.write_bytes(BODY)
    location = SimpleNamespace(
        path=source_path, phase='live-prefix',
        session={'run_id': 'owned-run', 'build': BUILD, 'value_capture': CAPTURE_V2},
        reader_runtime={'reader_build': BUILD},
    )
    private_parent = tmp_path / 'private-parent'
    private_parent.mkdir()
    retained_parent = tmp_path / 'retained-parent'
    original_temporary = evidence.TemporaryDirectory
    holder = {}

    def temporary(**kwargs):
        folder = original_temporary(dir=private_parent, **kwargs)
        holder['folder'] = folder
        return folder

    monkeypatch.setattr(evidence, 'TemporaryDirectory', temporary)
    export = evidence.EvidenceExport()
    publish = export._publish
    swapped = False

    def move_before_publish(folder, path, receipt, **kwargs):
        nonlocal swapped
        name = Path(folder.name).name
        private_parent.rename(retained_parent)
        private_parent.mkdir()
        (retained_parent / name).rename(private_parent / name)
        swapped = True
        (private_parent / name / 'unrelated.txt').write_text('preserve', encoding='utf-8')
        return publish(folder, path, receipt, **kwargs)

    monkeypatch.setattr(export, '_publish', move_before_publish)
    try:
        with pytest.raises(ContractError, match='prepared download changed'):
            export.prepare(
                SimpleNamespace(resolve=lambda: location), ContextAttribution(), None
            )
        assert swapped
        folder = holder['folder']
        assert (Path(folder.name) / 'unrelated.txt').read_text(encoding='utf-8') == 'preserve'
    finally:
        folder = holder.get('folder')
        if swapped and folder is not None:
            name = Path(folder.name).name
            (private_parent / name).rename(retained_parent / name)
            private_parent.rmdir()
            retained_parent.rename(private_parent)
        export.close()
        private_parent.rmdir()


@pytest.mark.skipif(os.name != 'nt', reason='Windows directory junction boundary')
def test_evidence_export_does_not_write_into_junction_replacing_private_directory(
        tmp_path,monkeypatch):
    source_path=tmp_path/'recording'
    source_path.write_bytes(BODY)
    location=SimpleNamespace(path=source_path,phase='live-prefix',
        session={'run_id':'owned-run','build':BUILD,'value_capture':CAPTURE_V2},
        reader_runtime={'reader_build':BUILD})
    source=SimpleNamespace(resolve=lambda:location)
    target=tmp_path/'unrelated'
    target.mkdir()
    junction=tmp_path/'private-export'
    created=subprocess.run(['cmd','/c','mklink','/J',str(junction),str(target)],
                           capture_output=True,check=False)
    if created.returncode:
        pytest.skip('host could not create an unprivileged directory junction')

    class SwappedFolder:
        name=str(junction)
        def cleanup(self):
            if junction.exists():junction.rmdir()

    monkeypatch.setattr(evidence,'TemporaryDirectory',lambda **kwargs:SwappedFolder())
    export=evidence.EvidenceExport()
    try:
        with pytest.raises(ContractError,match='export directory|reparse|junction'):
            export.prepare(source,ContextAttribution(),None)
        assert list(target.iterdir())==[]
    finally:
        with pytest.raises(ExportCleanupPending):
            export.close()
        if junction.exists():junction.rmdir()


def test_evidence_export_rejects_source_phase_change_during_snapshot(tmp_path):
    source_path=tmp_path/'recording';source_path.write_bytes(BODY)
    session={'run_id':'owned-run','build':BUILD,'value_capture':CAPTURE_V2}
    locations=[SimpleNamespace(path=source_path,phase=phase,session=session,
        reader_runtime={'reader_build':BUILD})
        for phase in ('live-prefix','interrupted-recording')]
    source=SimpleNamespace(resolve=lambda:locations.pop(0))
    export=evidence.EvidenceExport()
    try:
        with pytest.raises(ContractError,match='changed during export'):
            export.prepare(source,ContextAttribution(),None)
        assert export.path is None and export.receipt is None
    finally:export.close()


def test_evidence_export_rejects_same_phase_source_path_change(tmp_path):
    first=tmp_path/'first.pftrace';first.write_bytes(BODY)
    second=tmp_path/'second.pftrace';second.write_bytes(b'\x0a\x01y')
    session={'run_id':'owned-run','build':BUILD,'value_capture':CAPTURE_V2}
    locations=[SimpleNamespace(path=path,phase='finalized-recording',session=session,
        reader_runtime={'reader_build':BUILD}) for path in (first,second)]
    calls=[]
    def resolve():
        calls.append(None)
        return locations[0] if len(calls)<3 else locations[1]
    export=evidence.EvidenceExport()
    try:
        with pytest.raises(ContractError,match='changed during export'):
            export.prepare(SimpleNamespace(resolve=resolve),ContextAttribution(),None)
        assert len(calls)>=3
        assert export.path is None and export.receipt is None
    finally:export.close()


def test_evidence_export_rejects_completion_lost_during_bundle_copy(tmp_path,monkeypatch):
    source_path=tmp_path/'recording';source_path.write_bytes(BODY)
    marker=tmp_path/'done';marker.write_bytes(b'')
    location=SimpleNamespace(path=source_path,phase='finalized-recording',
        session={'run_id':'owned-run','build':BUILD,'value_capture':CAPTURE_V2},
        reader_runtime={'reader_build':BUILD})
    def resolve():
        if not marker.exists():
            raise ContractError('recording parts marker changed')
        return location
    original_copy=evidence._copy
    def copy_then_remove_marker(*args,**kwargs):
        result=original_copy(*args,**kwargs)
        marker.unlink()
        return result
    monkeypatch.setattr(evidence,'_copy',copy_then_remove_marker)
    export=evidence.EvidenceExport()
    try:
        with pytest.raises(ContractError,match='marker changed'):
            export.prepare(SimpleNamespace(resolve=resolve),ContextAttribution(),None)
        assert export.path is None and export.receipt is None
    finally:export.close()


@pytest.mark.parametrize('target', ['recording.pftrace', 'evidence.bcevidence'])
def test_evidence_copy_rejects_short_destination_write(tmp_path, runtime, monkeypatch, target):
    real_open = Path.open

    class ShortWriter:
        def __init__(self, output):
            self.output = output
            self.writes = 0

        def __enter__(self):
            self.output.__enter__()
            return self

        def __exit__(self, *args):
            return self.output.__exit__(*args)

        def __getattr__(self, name):
            return getattr(self.output, name)

        def write(self, body):
            self.writes += 1
            if self.writes == 1:
                return self.output.write(body[:-1])
            return self.output.write(body)

    def short_open(path, mode='r', *args, **kwargs):
        opened = real_open(path, mode, *args, **kwargs)
        return ShortWriter(opened) if path.name == target and mode == 'xb' else opened

    monkeypatch.setattr(Path, 'open', short_open)
    if target == 'recording.pftrace':
        reader, calls = runtime
        path = tmp_path / 'bundle.bcevidence'
        pack(path)
        with pytest.raises(ContractError, match='evidence copy wrote incomplete bytes'):
            bundle = evidence.OpenEvidence(path, tmp_path, reader)
            bundle.close()
        assert calls == []
    else:
        source_path = tmp_path / 'recording'
        source_path.write_bytes(BODY)
        location = SimpleNamespace(path=source_path, phase='finalized-recording',
            session={'run_id':'owned-run','build':BUILD,'value_capture':CAPTURE_V2},
            reader_runtime={'reader_build':BUILD})
        export = evidence.EvidenceExport()
        try:
            with pytest.raises(ContractError, match='evidence copy wrote incomplete bytes'):
                export.prepare(SimpleNamespace(resolve=lambda: location), ContextAttribution(), None)
            assert export.path is None and export.receipt is None
        finally:
            export.close()


def test_changed_reader_is_rejected_and_file_links_are_not_admitted(tmp_path,runtime,monkeypatch):
    reader,_=runtime;path=tmp_path/'bundle';pack(path)
    bundle=evidence.OpenEvidence(path,tmp_path,reader)
    monkeypatch.setattr(evidence,'executable_evidence',lambda *a,**k:{**BUILD,'executable_sha256_16':'9'*16})
    try:
        with pytest.raises(ContractError,match='reader changed'):bundle.source.resolve()
    finally:bundle.close()
    alias=tmp_path/'alias';os.link(path,alias)
    with pytest.raises(ContractError):evidence.OpenEvidence(alias,tmp_path,reader)


def test_resolve_rechecks_private_copy_after_reader_validation(tmp_path,runtime,monkeypatch):
    reader,_=runtime;path=tmp_path/'bundle';pack(path)
    bundle=evidence.OpenEvidence(path,tmp_path,reader)
    try:
        def change_copy_during_reader_check(*args,**kwargs):
            bundle.path.write_bytes(b'\x0a\x01y')
            return dict(BUILD)
        monkeypatch.setattr(evidence,'executable_evidence',change_copy_during_reader_check)
        with pytest.raises(ContractError,match='verified evidence recording copy changed'):
            bundle.source.resolve()
    finally:bundle.close()


def test_export_rechecks_source_after_prepared_file_binding(tmp_path,monkeypatch):
    import browser_core.perfetto as perfetto
    recording=tmp_path/'recording';recording.write_bytes(BODY)
    location=SimpleNamespace(path=recording,phase='finalized-recording',
        session={'run_id':'owned-run','build':BUILD,'value_capture':CAPTURE_V2},
        reader_runtime={'reader_build':BUILD})
    changed=SimpleNamespace(**{**vars(location),'phase':'recovered-prefix'})
    current=[location]
    original_binding=perfetto._stable_file_binding
    def bind_then_change(*args,**kwargs):
        binding=original_binding(*args,**kwargs)
        current[0]=changed
        return binding
    monkeypatch.setattr(perfetto,'_stable_file_binding',bind_then_change)
    export=evidence.EvidenceExport()
    try:
        with pytest.raises(ContractError,match='prepared download changed before publication'):
            export.prepare(SimpleNamespace(resolve=lambda:current[0]),ContextAttribution(),None)
        assert export.path is None and export.receipt is None
    finally:export.close()


def test_cli_reader_is_explicit_and_bundle_does_not_select_it(monkeypatch,tmp_path):
    from browser_core.cli import build_parser
    import browser_core.inspection_ui as ui
    calls=[];monkeypatch.setattr(ui,'serve_evidence',lambda *a,**k:calls.append((a,k)))
    args=build_parser().parse_args(['trace','evidence','--bundle',str(tmp_path/'bundle'),
        '--reader-executable',str(tmp_path/'chrome.exe'),'--expected-sha256','a'*64])
    assert args.func(args)==0 and calls[0][0][2]==tmp_path/'chrome.exe'
    assert calls[0][1]['expected_sha256']=='a'*64


@pytest.mark.skipif(os.name != 'nt', reason='Windows directory junction boundary')
def test_cli_evidence_reader_preserves_selected_runtime_junction(monkeypatch, tmp_path):
    from browser_core.cli import build_parser
    import browser_core.inspection_ui as ui

    physical = tmp_path / 'physical-runtime'
    physical.mkdir()
    (physical / 'chrome.exe').write_bytes(b'fixture')
    selected = tmp_path / 'selected-runtime'
    linked = subprocess.run(
        ['cmd', '/c', 'mklink', '/J', str(selected), str(physical)],
        capture_output=True,
    )
    if linked.returncode:
        pytest.skip('host could not create an unprivileged directory junction')
    calls = []
    monkeypatch.setattr(ui, 'serve_evidence', lambda *args, **kwargs: calls.append(args))
    try:
        args = build_parser().parse_args([
            'trace', 'evidence', '--bundle', str(tmp_path / 'bundle'),
            '--reader-executable', str(selected / 'chrome.exe'),
            '--expected-sha256', 'a' * 64,
        ])
        assert args.func(args) == 0
        assert calls[0][2] == selected / 'chrome.exe'
    finally:
        selected.rmdir()
