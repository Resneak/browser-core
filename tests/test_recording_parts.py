from pathlib import Path
import hashlib
import io
import os
import subprocess
import tempfile

import pytest

from browser_core.contracts import ContractError, validate_session
from browser_core.recording_source import bind_recording_file, RecordingSource
from browser_core.recording_parts import (PartsSource, PartsCursor, part_path,
    done_marker_path, recording_parts, snapshot_parts)
from browser_core.recording_limits import MIB, limit_marker_path
from browser_core.launcher import EvaluationLaunch, evaluation_command, validate_evaluation_launch
from browser_core.incremental_inspection import IncrementalInspection
from browser_core.live_trace import snapshot_live_trace
import browser_core.recording_parts as parts_module
from test_recording_recovery import source, FakeDecoder

SIZE = 4*MIB


def test_joined_reader_seeks_only_when_position_changes_and_keeps_exact_bytes():
    from browser_core.recording_parts import _JoinedReader
    class CountingStream(io.BytesIO):
        def __init__(self,body):super().__init__(body);self.seeks=0
        def seek(self,*args):self.seeks+=1;return super().seek(*args)
    streams=[CountingStream(b'abcd'),CountingStream(b'efgh'),CountingStream(b'ij')]
    reader=_JoinedReader(streams,[4,4,2],4)
    assert b''.join(reader.read(1) for _ in range(10))==b'abcdefghij'
    assert sum(s.seeks for s in streams)==0
    reader.seek(2);assert reader.read(7)==b'cdefghi'
    assert sum(s.seeks for s in streams)==3
    reader.seek(10);assert reader.read(1)==b''
    reader.seek(0);assert reader.read(10)==b'abcdefghij'


def packet(body):
    size=len(body);header=bytearray(b'\x0a')
    while size>=128:
        header.append((size&127)|128);size>>=7
    header.append(size)
    return bytes(header)+body


def split_fixture(tmp_path, body=None, count=3):
    # The second packet's tag is in part1; its length and body are in part2.
    body=body if body is not None else packet(b'a'*(SIZE-6))+packet(b'b'*901)
    original=tmp_path/'trace.live';final=tmp_path/'trace'
    for index,start in enumerate(range(0,len(body),SIZE),1):
        part_path(original,index).write_bytes(body[start:start+SIZE])
    session={'trace_path':str(final),'live_trace':{'path':str(original),
        'byte_limit':SIZE,'parts':{'schema':'browser-core.recording-parts/1','max_parts':count},
        'file_binding':bind_recording_file(original)}}
    return PartsSource(session),body,session


def test_packet_header_and_body_cross_parts_without_reset_or_loss(tmp_path):
    parts,body,_=split_fixture(tmp_path)
    cursor=PartsCursor(parts);chunks=[]
    result=cursor.consume(chunks.append)
    assert b''.join(chunks)==body and result['packets']==2 and result['parts']==2
    assert result['source_sha256']==hashlib.sha256(body).hexdigest()
    assert result['snapshot_bytes']==len(body) and result['incomplete_tail_bytes']==0
    again=[];assert cursor.consume(again.append)['new_bytes']==0 and not again
    with snapshot_parts(parts) as snapshot:
        assert snapshot.path.read_bytes()==body and snapshot.sha256==result['source_sha256']


def test_parts_snapshot_preserves_replaced_private_directory_on_exit(tmp_path, monkeypatch):
    parts, body, _ = split_fixture(tmp_path, packet(b'fixture'))
    folder = tempfile.TemporaryDirectory(dir=tmp_path)
    original_name = Path(folder.name)
    retained = tmp_path / 'retained-parts-snapshot'
    sentinel = original_name / 'unrelated.txt'
    cleanup = folder.cleanup
    calls = []
    monkeypatch.setattr(folder, 'cleanup', lambda: calls.append('cleanup'))
    monkeypatch.setattr(parts_module, 'TemporaryDirectory', lambda **kwargs: folder)
    try:
        with pytest.raises(ContractError, match='snapshot directory.*cleanup'):
            with snapshot_parts(parts) as snapshot:
                assert snapshot.path.read_bytes() == body
                original_name.rename(retained)
                original_name.mkdir()
                sentinel.write_text('preserve', encoding='utf-8')
        assert calls == []
        assert sentinel.read_text(encoding='utf-8') == 'preserve'
    finally:
        monkeypatch.setattr(folder, 'cleanup', cleanup)
        sentinel.unlink(missing_ok=True)
        if original_name.exists():
            original_name.rmdir()
        retained.rename(original_name)
        cleanup()


def test_parts_snapshot_preserves_copy_after_ancestor_changes(tmp_path, monkeypatch):
    parts, body, _ = split_fixture(tmp_path, packet(b'fixture'))
    private_parent = tmp_path / 'private-parent'
    private_parent.mkdir()
    retained_parent = tmp_path / 'retained-parent'
    folder = tempfile.TemporaryDirectory(dir=private_parent)
    name = Path(folder.name).name
    current_folder = private_parent / name
    retained_folder = retained_parent / name
    sentinel = current_folder / 'unrelated.txt'
    monkeypatch.setattr(parts_module, 'TemporaryDirectory', lambda **kwargs: folder)
    swapped = False
    try:
        with pytest.raises(ContractError, match='snapshot directory.*cleanup'):
            with snapshot_parts(parts) as snapshot:
                assert snapshot.path.read_bytes() == body
                private_parent.rename(retained_parent)
                private_parent.mkdir()
                retained_folder.rename(current_folder)
                swapped = True
                sentinel.write_text('preserve', encoding='utf-8')
        assert sentinel.read_text(encoding='utf-8') == 'preserve'
    finally:
        sentinel.unlink(missing_ok=True)
        if swapped:
            if current_folder.exists():
                current_folder.rename(retained_folder)
            private_parent.rmdir()
            retained_parent.rename(private_parent)
        folder.cleanup()


@pytest.mark.skipif(os.name != 'nt', reason='Windows junction ancestry')
def test_segmented_snapshot_rejects_source_parent_swap_after_yield(tmp_path):
    selected = tmp_path / 'selected'
    selected.mkdir()
    body = packet(b'fixture')
    parts, _, _ = split_fixture(selected, body)
    retained = tmp_path / 'retained'
    swapped = False
    try:
        with pytest.raises(ContractError, match='source parent'):
            with snapshot_live_trace(parts.source, parts=parts) as snapshot:
                assert snapshot.path.read_bytes() == body
                selected.rename(retained)
                result = subprocess.run(
                    ['cmd', '/c', 'mklink', '/J', str(selected), str(retained)],
                    capture_output=True, text=True, check=False,
                )
                if result.returncode:
                    retained.rename(selected)
                    pytest.skip('host could not create an unprivileged directory junction')
                swapped = True
        assert (retained / 'trace.live').is_file()
    finally:
        if swapped:
            selected.rmdir()
            retained.rename(selected)


def test_completed_parts_reject_immediate_part_beyond_maximum(tmp_path):
    parts, _body, _ = split_fixture(tmp_path, packet(b'fixture'), count=16)
    done_marker_path(parts.final).write_bytes(b'')
    Path(str(parts.source) + '.part17').write_bytes(packet(b'unlisted'))
    with pytest.raises(ContractError, match='outside their policy'):
        parts.describe(running=False)


def test_parts_description_rejects_final_name_created_during_observation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    parts, _body, _session = split_fixture(tmp_path, packet(b"fixture"))
    original = parts.observe

    def observe_then_finalize(*, settled: bool = False):
        view = original(settled=settled)
        parts.final.write_bytes(b"competing-final-trace")
        return view

    monkeypatch.setattr(parts, "observe", observe_then_finalize)
    with pytest.raises(ContractError, match="single finalized trace"):
        parts.describe(running=True)
    assert parts.final.is_file()


def test_parts_description_rejects_done_marker_created_during_observation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    parts, _body, _session = split_fixture(tmp_path, packet(b"fixture"))
    done = done_marker_path(parts.final)
    original = parts.observe

    def observe_then_finish(*, settled: bool = False):
        view = original(settled=settled)
        done.write_bytes(b"")
        return view

    monkeypatch.setattr(parts, "observe", observe_then_finish)
    with pytest.raises(ContractError, match="marker changed"):
        parts.describe(running=True)
    assert done.is_file()


@pytest.mark.skipif(os.name != 'nt', reason='Windows junction ancestry')
def test_parts_description_rejects_parent_swap_after_observation(tmp_path, monkeypatch):
    selected = tmp_path / 'selected'
    selected.mkdir()
    parts, _, _ = split_fixture(selected, packet(b'fixture'))
    assert parts.describe(running=True)[0] == 'live-prefix'
    retained = tmp_path / 'retained'
    original_observe = parts.observe
    swapped = False

    def observe_then_relocate(**options):
        nonlocal swapped
        view = original_observe(**options)
        selected.rename(retained)
        result = subprocess.run(
            ['cmd', '/c', 'mklink', '/J', str(selected), str(retained)],
            capture_output=True, text=True, check=False,
        )
        if result.returncode:
            retained.rename(selected)
            pytest.skip('host could not create an unprivileged directory junction')
        swapped = True
        return view

    monkeypatch.setattr(parts, 'observe', observe_then_relocate)
    try:
        with pytest.raises(ContractError, match='parent'):
            parts.describe(running=True)
        assert part_path(retained / 'trace.live', 1).is_file()
    finally:
        if swapped:
            selected.rmdir()
            retained.rename(selected)


@pytest.mark.parametrize('mib,count,expected',[(4,2,10_000_000),(128,12,20_000_000),
                                             (1024,3,30_000_000),(1024,4,40_000_000)])
def test_packet_allowance_scales_with_the_bounded_total(tmp_path,mib,count,expected):
    _,_,session=split_fixture(tmp_path)
    session['live_trace']['byte_limit']=mib*MIB
    session['live_trace']['parts']['max_parts']=count
    assert PartsSource(session).packet_limit==expected


def test_aggregate_packet_exhaustion_is_terminal_across_refreshes(tmp_path,monkeypatch):
    parts,_,_=split_fixture(tmp_path,packet(b'a')+packet(b'b')+packet(b'c'))
    parts.packet_limit=2
    monkeypatch.setattr('browser_core.incremental_inspection.MAX_REFRESH_BYTES',3)
    cursor=PartsCursor(parts);chunks=[]
    cursor.consume(chunks.append);cursor.consume(chunks.append)
    with pytest.raises(ContractError,match='packet-count'):
        cursor.consume(chunks.append)
    assert cursor.closed and cursor.packets==2


def test_joined_snapshot_obeys_the_same_aggregate_packet_limit(tmp_path):
    parts,_,_=split_fixture(tmp_path,packet(b'a')*3)
    parts.packet_limit=2
    with pytest.raises(ContractError,match='packet count'):
        with snapshot_parts(parts):pytest.fail('packet limit ignored')


def test_partial_packet_resumes_across_new_part_with_original_ids_and_bytes(tmp_path):
    whole=packet(b'a'*(SIZE-6))+packet(b'b'*901)
    parts,_,_=split_fixture(tmp_path,whole[:SIZE])
    cursor=PartsCursor(parts);chunks=[]
    first=cursor.consume(chunks.append)
    assert first['packets']==1 and first['incomplete_tail_bytes']==1
    original_digest=hashlib.sha256(b''.join(chunks)).hexdigest()
    part_path(parts.source,2).write_bytes(whole[SIZE:])
    second=cursor.consume(chunks.append)
    assert second['packets']==2 and second['parts']==2
    assert b''.join(chunks)==whole and cursor.digest.hexdigest()==hashlib.sha256(whole).hexdigest()
    assert original_digest==hashlib.sha256(whole[:SIZE-1]).hexdigest()


@pytest.mark.parametrize('kind',['missing','hole','short-previous','oversize','extra','replace','hardlink','directory','sealed-edit'])
def test_ambiguous_changed_or_out_of_policy_parts_are_rejected(tmp_path,kind):
    parts,_,_=split_fixture(tmp_path,count=2)
    cursor=PartsCursor(parts);cursor.consume(lambda body:None)
    second=part_path(parts.source,2)
    if kind=='missing':second.unlink()
    elif kind=='hole':second.rename(part_path(parts.source,3))
    elif kind=='short-previous':
        with parts.source.open('r+b') as stream:stream.truncate(SIZE-1)
    elif kind=='oversize':
        with second.open('r+b') as stream:stream.truncate(SIZE+1)
    elif kind=='extra':part_path(parts.source,3).write_bytes(b'\x0a\x00')
    elif kind=='replace':second.rename(tmp_path/'old-second');second.write_bytes(b'\x0a\x00')
    elif kind=='hardlink':os.link(second,tmp_path/'alias')
    elif kind=='directory':second.unlink();second.mkdir()
    else:
        with parts.source.open('r+b') as stream:stream.seek(SIZE-50);stream.write(b'z')
        stat=parts.source.stat();os.utime(parts.source,ns=(stat.st_atime_ns,stat.st_mtime_ns+1_000_000_000))
    with pytest.raises(ContractError):cursor.consume(lambda body:None)
    assert cursor.closed


def test_first_observation_rejects_first_part_replaced_after_binding(tmp_path,monkeypatch):
    import browser_core.recording_source as recording_source

    parts,_,_=split_fixture(tmp_path)
    original=recording_source.bind_recording_file

    def replace_after_binding(path,expected):
        bound=original(path,expected)
        path.rename(tmp_path/'old-first')
        path.write_bytes(b'x'*SIZE)
        return bound

    monkeypatch.setattr(recording_source,'bind_recording_file',replace_after_binding)
    with pytest.raises(ContractError,match='first part changed'):
        parts.observe()


@pytest.mark.skipif(os.name != 'nt', reason='Windows junction ancestry')
def test_parts_observation_rejects_parent_junction_after_first_binding(tmp_path, monkeypatch):
    import browser_core.recording_source as recording_source

    selected = tmp_path / 'selected'
    selected.mkdir()
    parts, _, _ = split_fixture(selected, packet(b'fixture'))
    retained = tmp_path / 'retained'
    original_bind = recording_source.bind_recording_file
    swapped = False

    def bind_then_relocate(path, expected):
        nonlocal swapped
        bound = original_bind(path, expected)
        selected.rename(retained)
        result = subprocess.run(
            ['cmd', '/c', 'mklink', '/J', str(selected), str(retained)],
            capture_output=True, text=True, check=False,
        )
        if result.returncode:
            retained.rename(selected)
            pytest.skip('host could not create an unprivileged directory junction')
        swapped = True
        return bound

    monkeypatch.setattr(recording_source, 'bind_recording_file', bind_then_relocate)
    try:
        with pytest.raises(ContractError, match='parent'):
            parts.observe()
        assert part_path(retained / 'trace.live', 1).is_file()
    finally:
        if swapped:
            selected.rmdir()
            retained.rename(selected)


@pytest.mark.skipif(os.name != 'nt', reason='Windows junction ancestry')
def test_parts_open_view_rejects_parent_junction_after_observation(tmp_path):
    selected = tmp_path / 'selected'
    selected.mkdir()
    parts, body, _ = split_fixture(selected, packet(b'fixture'))
    view = parts.observe()
    retained = tmp_path / 'retained'
    selected.rename(retained)
    result = subprocess.run(
        ['cmd', '/c', 'mklink', '/J', str(selected), str(retained)],
        capture_output=True, text=True, check=False,
    )
    if result.returncode:
        retained.rename(selected)
        pytest.skip('host could not create an unprivileged directory junction')
    try:
        with pytest.raises(ContractError, match='parent'):
            with parts.open_view(view) as stream:
                assert stream.read(len(body)) == body
        assert part_path(retained / 'trace.live', 1).is_file()
    finally:
        selected.rmdir()
        retained.rename(selected)


def test_segmented_source_maps_part_loss_between_descriptions(source, monkeypatch):  # noqa: F811
    import browser_core.recording_source as recording_source

    source.session['live_trace'].update(
        byte_limit=SIZE,
        parts={'schema': 'browser-core.recording-parts/1', 'max_parts': 3},
        file_binding=bind_recording_file(source.path),
    )
    source.save()
    original = recording_source.bind_recording_file
    binds = 0

    def disappear_on_second_bind(path, expected=None):
        nonlocal binds
        binds += 1
        if binds == 2:
            source.path.unlink()
            raise FileNotFoundError('recording part disappeared')
        return original(path, expected)

    monkeypatch.setattr(recording_source, 'bind_recording_file', disappear_on_second_bind)
    with pytest.raises(ContractError, match='recording parts are no longer readable'):
        source.reader.resolve()
    assert binds == 2


@pytest.mark.parametrize('marker',['done','limit'])
def test_completion_markers_are_bound_and_do_not_restart_recording(tmp_path,marker):
    body=packet(b'a'*(SIZE-5))*2 if marker=='limit' else None
    parts,body,_=split_fixture(tmp_path,body,count=2)
    target=done_marker_path(parts.final) if marker=='done' else limit_marker_path(parts.final)
    target.write_bytes(b'')
    phase,limit,view=parts.describe(running=True)
    assert phase==('finalized-recording' if marker=='done' else 'limited-recording')
    assert (limit is not None)==(marker=='limit') and view.source_bytes==len(body)
    target.rename(tmp_path/'old-marker');target.write_bytes(b'')
    with pytest.raises(ContractError,match='marker changed'):parts.describe(running=False)


def test_completion_marker_removed_during_part_observation_cannot_finalize(tmp_path,monkeypatch):
    parts,_,_=split_fixture(tmp_path)
    marker=done_marker_path(parts.final)
    marker.write_bytes(b'')
    original=parts.observe

    def observe_then_remove(**options):
        view=original(**options)
        marker.unlink()
        return view

    monkeypatch.setattr(parts,'observe',observe_then_remove)
    with pytest.raises(ContractError,match='marker changed'):
        parts.describe(running=False)


@pytest.mark.parametrize('kind',['nonempty','both','single-final','early-limit','remove-done'])
def test_bad_or_conflicting_finalization_is_rejected(tmp_path,kind):
    parts,_,_=split_fixture(tmp_path)
    done=done_marker_path(parts.final);limit=limit_marker_path(parts.final)
    if kind=='nonempty':done.write_bytes(b'x')
    elif kind=='both':done.write_bytes(b'');limit.write_bytes(b'')
    elif kind=='single-final':parts.final.write_bytes(b'\x0a\x00')
    elif kind=='early-limit':limit.write_bytes(b'')
    else:done.write_bytes(b'');parts.describe(running=False);done.unlink()
    with pytest.raises(ContractError):parts.describe(running=False)


def test_stopped_parts_stay_frozen_and_limit_tail_is_explicit(tmp_path):
    parts,body,_=split_fixture(tmp_path)
    parts.describe(running=False)
    cursor=PartsCursor(parts);cursor.consume(lambda body:None,stable=lambda:True)
    with part_path(parts.source,2).open('ab') as stream:stream.write(b'\x0a\x00')
    with pytest.raises(ContractError):cursor.consume(lambda body:None,stable=lambda:True)


@pytest.mark.parametrize('value',[0,17,True,2.0,'2',-1])
def test_part_policy_rejects_invalid_values_before_launch(tmp_path,value):
    with pytest.raises(ContractError,match='parts'):
        validate_evaluation_launch(EvaluationLaunch(tmp_path/'chrome.exe',tmp_path,
            live_trace=True,recording_limit_mib=4,recording_parts=value))


def test_total_budget_and_live_only_policy_are_enforced(tmp_path):
    assert recording_parts(4,1024*MIB,live=True)==4
    with pytest.raises(ContractError,match='4096'):recording_parts(5,1024*MIB,live=True)
    with pytest.raises(ContractError,match='require live'):recording_parts(2,None,live=False)
    with pytest.raises(ContractError,match='managed recording-parts'):
        validate_evaluation_launch(EvaluationLaunch(tmp_path/'chrome.exe',tmp_path,
            extra_args=('--browser-core-recording-parts=2',)))
    command=evaluation_command(tmp_path/'chrome.exe',tmp_path/'profile',tmp_path/'trace','owned-run',
        headless=True,extra_args=(),live_trace=True,recording_limit_mib=4,recording_parts=3)
    assert '--browser-core-recording-parts=3' in command and '--browser-core-recording-limit-mib=4' in command


@pytest.mark.parametrize('reader',['incremental','snapshot'])
def test_part_open_failure_is_path_free_and_terminal(tmp_path,monkeypatch,reader):
    parts,_,_=split_fixture(tmp_path)
    def fail(*args):raise PermissionError('private capture path')
    monkeypatch.setattr('browser_core.recording_parts._open_shared_source',fail)
    cursor=PartsCursor(parts)
    with pytest.raises(ContractError) as failure:
        if reader=='incremental':cursor.consume(lambda body:None)
        else:
            with snapshot_parts(parts):pass
    assert 'private' not in str(failure.value)
    if reader=='incremental':assert cursor.closed


def test_session_requires_parts_policy_budget_and_persisted_original_binding(source):
    live=source.session['live_trace'];live['byte_limit']=SIZE
    live['parts']={'schema':'browser-core.recording-parts/1','max_parts':3}
    validate_session(source.session)
    del live['file_binding']
    with pytest.raises(ContractError,match='persisted source'):validate_session(source.session)


def test_direct_parts_source_rejects_unrelated_final_marker(tmp_path):
    parts, _, session = split_fixture(tmp_path, packet(b'fixture'))
    unrelated = tmp_path / 'unrelated-trace'
    done_marker_path(unrelated).write_bytes(b'')
    session['trace_path'] = str(unrelated)

    assert parts.describe(running=False)[0] == 'recovered-prefix'
    with pytest.raises(ContractError, match='original live source'):
        PartsSource(session).describe(running=False)


@pytest.mark.parametrize('running', ['false', None, 1])
def test_direct_parts_description_requires_boolean_running_state(tmp_path, running):
    parts, _, _ = split_fixture(tmp_path, packet(b'fixture'))
    with pytest.raises(ContractError, match='running state'):
        parts.describe(running=running)
    assert parts.minimum_count == 0
    assert parts.retired is None
    assert parts.describe(running=True)[0] == 'live-prefix'
    done_marker_path(parts.final).write_bytes(b'')
    assert parts.describe(running=False)[0] == 'finalized-recording'


def test_incremental_reader_uses_whole_parts_and_finalizes_without_losing_prefix(source,monkeypatch):
    body=packet(b'a'*(SIZE-6))+packet(b'b'*901)
    source.path.write_bytes(body[:SIZE]);part_path(source.path,2).write_bytes(body[SIZE:])
    source.session['live_trace'].update(byte_limit=SIZE,
        parts={'schema':'browser-core.recording-parts/1','max_parts':3},
        file_binding=bind_recording_file(source.path))
    source.save();monkeypatch.setattr('browser_core.incremental_inspection.TraceProcessorPipe',FakeDecoder)
    with IncrementalInspection(source.document,source.document.parent) as reader:
        initial=reader.read()
        assert initial['snapshot_bytes']==len(body) and initial['source_phase']=='live-prefix'
        assert initial['recording_budget']['byte_limit']==3*SIZE
        assert initial['recording_parts']['observed_parts']==2
        done_marker_path(source.final).write_bytes(b'');source.status.update(state='stopped',running=False)
        final=reader.read()
        assert final['complete'] and final['recording_settled'] and final['source_sha256']==hashlib.sha256(body).hexdigest()
    reopened=RecordingSource(source.document,source.document.parent).resolve()
    assert reopened.phase=='finalized-recording' and not reopened.browser_running


def test_incremental_reader_cannot_claim_complete_after_marker_lost_during_consume(source,monkeypatch):
    body=packet(b'a'*(SIZE-6))+packet(b'b'*901)
    source.path.write_bytes(body[:SIZE]);part_path(source.path,2).write_bytes(body[SIZE:])
    source.session['live_trace'].update(byte_limit=SIZE,
        parts={'schema':'browser-core.recording-parts/1','max_parts':3},
        file_binding=bind_recording_file(source.path))
    source.save()
    monkeypatch.setattr('browser_core.incremental_inspection.TraceProcessorPipe',FakeDecoder)
    with IncrementalInspection(source.document,source.document.parent) as reader:
        reader.read()
        marker=done_marker_path(source.final)
        marker.write_bytes(b'')
        source.status.update(state='stopped',running=False)
        original=PartsCursor.consume
        def consume_then_remove(self,*args,**kwargs):
            result=original(self,*args,**kwargs)
            marker.unlink()
            return result
        monkeypatch.setattr(PartsCursor,'consume',consume_then_remove)
        with pytest.raises(ContractError,match='marker changed'):
            reader.read()


@pytest.mark.parametrize('name',['done','part2','part16','part17'])
def test_preexisting_parts_never_get_overwritten(tmp_path,name):
    from browser_core.live_trace import require_new_live_artifacts
    final=tmp_path/'trace'
    target=(done_marker_path(final) if name=='done' else
            Path(str(final)+'.live.part17') if name=='part17' else
            part_path(Path(str(final)+'.live'),int(name[4:])))
    target.write_bytes(b'old')
    with pytest.raises(ContractError,match='already exists'):require_new_live_artifacts(final,recording_parts=2)
    assert target.read_bytes()==b'old'
