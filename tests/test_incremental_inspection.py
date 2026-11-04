import hashlib
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from browser_core.contracts import ContractError
from browser_core.inspection_contract import CAPTURE_V1
import browser_core.incremental_inspection as live
from test_inspection import _body, _row
from test_recording_recovery import source, FakeDecoder


def test_inspector_close_attempts_decoder_after_cursor_close_failure():
    closed=[]
    def close_cursor():
        closed.append('cursor')
        raise OSError('cursor close failed')
    reader=live.IncrementalInspection(Path('/session'),Path('/repo'))
    reader.cursor=SimpleNamespace(close=close_cursor)
    reader.decoder=SimpleNamespace(close=lambda:closed.append('decoder'))
    with pytest.raises(OSError,match='cursor close failed'):
        reader.close()
    assert reader.closed and closed==['cursor','decoder']


@pytest.mark.parametrize('malformed',['order','short-page'])
def test_incremental_latest_inspection_rejects_inconsistent_native_page(malformed):
    older=dict(_row(),id='1',ts='10',total_events='2')
    newer=dict(_row(),id='2',ts='20',total_events='2')
    rows=[older,newer] if malformed=='order' else [dict(_row(),total_events='3')]
    path=Path('/owned-recording')
    location=SimpleNamespace(path=path,executable=Path('/reader.exe'),phase='live-prefix',
        browser_running=True,session={'run_id':'owned','value_capture':CAPTURE_V1})
    class Cursor:
        source=path
        closed=False
        def consume(self,*args,**kwargs):return {'catching_up':False}
        def close(self):self.closed=True
    class Decoder:
        closed=False
        def query(self,sql,**kwargs):
            if 'FROM stats' in sql:
                return b'name,severity,value\n__capture_stats_present,meta,1\n__sorter_dropped,meta,0\n'
            return _body(rows)
        def close(self):self.closed=True
    reader=live.IncrementalInspection(Path('/session'),Path('/repo'),
        source=SimpleNamespace(resolve=lambda:location))
    reader.cursor=Cursor();reader.decoder=Decoder();reader.run_id='owned'
    try:
        with pytest.raises(ContractError,match='out of order' if malformed=='order' else 'count disagrees'):
            reader.read(limit=2)
        assert reader.closed and reader.cursor.closed and reader.decoder.closed
    finally:reader.close()


def test_mutating_returned_health_cannot_erase_retained_recording_loss():
    path=Path('/owned-recording')
    location=SimpleNamespace(path=path,executable=Path('/reader.exe'),phase='live-prefix',
        browser_running=True,session={'run_id':'owned','value_capture':CAPTURE_V1})
    class Cursor:
        source=path
        def consume(self,*args,**kwargs):
            return {'catching_up':False,'source_bytes':3,'snapshot_bytes':3,
                    'source_sha256':'a'*64,'packets':1,'new_bytes':0,
                    'pending_source_bytes':0,'incomplete_tail_bytes':0}
        def close(self):pass
    class Decoder:
        timeout=30
        reads=0
        def query(self,sql,**kwargs):
            if 'FROM stats' not in sql:return _body([_row()])
            self.reads+=1
            warning=b'traced_buf_chunks_discarded,info,2\n' if self.reads==1 else b''
            return (b'name,severity,value\n__capture_stats_present,meta,1\n'
                    b'__sorter_dropped,meta,0\n'+warning)
        def close(self):pass
    reader=live.IncrementalInspection(Path('/session'),Path('/repo'),
        source=SimpleNamespace(resolve=lambda:location))
    reader.cursor=Cursor();reader.decoder=Decoder();reader.run_id='owned'
    try:
        first=reader.read(limit=2)
        first['recording_health']['counters'].clear()
        second=reader.read(limit=2)
        assert second['recording_health']['status']=='issues-reported'
        assert second['recording_health']['counters'][0]['name']=='traced_buf_chunks_discarded'
    finally:reader.close()


def test_live_refresh_cannot_return_observations_after_session_replacement():
    path=Path('/owned-recording')
    location=SimpleNamespace(path=path,executable=Path('/reader.exe'),phase='live-prefix',
        browser_running=True,session={'run_id':'owned','value_capture':CAPTURE_V1})
    class Cursor:
        source=path
        closed=False
        def consume(self,*args,**kwargs):
            return {'catching_up':False,'source_bytes':3,'snapshot_bytes':3,
                    'source_sha256':'a'*64,'packets':1,'new_bytes':0,
                    'pending_source_bytes':0,'incomplete_tail_bytes':0}
        def close(self):self.closed=True
    class Decoder:
        closed=False
        def query(self,sql,**kwargs):
            if 'FROM stats' in sql:
                location.session={'run_id':'replacement','value_capture':CAPTURE_V1}
                return b'name,severity,value\n__capture_stats_present,meta,1\n__sorter_dropped,meta,0\n'
            return _body([_row()])
        def close(self):self.closed=True
    reader=live.IncrementalInspection(Path('/session'),Path('/repo'),
        source=SimpleNamespace(resolve=lambda:location))
    reader.cursor=Cursor();reader.decoder=Decoder();reader.run_id='owned'
    try:
        with pytest.raises(ContractError,match='source changed'):
            reader.read(limit=2)
        assert reader.closed and reader.cursor.closed and reader.decoder.closed
    finally:reader.close()


def test_history_cannot_claim_complete_after_final_source_reverts_during_search(source,monkeypatch):
    monkeypatch.setattr(live,'TraceProcessorPipe',FakeDecoder)
    source.status.update(running=False,state='stale')
    source.path.rename(source.final)
    reader=live.IncrementalInspection(source.document,source.document.parent)
    try:
        assert reader.read()['complete']
        original=reader.decoder.query
        def query_then_revert(sql,**kwargs):
            if 'MAX(id)' in sql:
                source.final.rename(source.path)
                return b'highwater\n0\n'
            return original(sql,**kwargs)
        reader.decoder.query=query_then_revert
        with pytest.raises(ContractError,match='finalized recording'):
            reader.history()
    finally:reader.close()


def test_cursor_feeds_only_new_whole_packets_including_partial_tail(tmp_path):
    path=tmp_path/'trace.live';first=b'\x0a\x03abc';second=b'\x0a\x05defgh'
    path.write_bytes(first+second[:3]);chunks=[];cursor=live.LivePacketCursor(path)
    try:
        receipt=cursor.consume(chunks.append)
        assert b''.join(chunks)==first and receipt['incomplete_tail_bytes']==3
        assert cursor.consume(chunks.append)['new_bytes']==0
        with path.open('ab') as source:source.write(second[3:])
        receipt=cursor.consume(chunks.append)
        assert b''.join(chunks)==first+second
        assert receipt['source_sha256']==hashlib.sha256(first+second).hexdigest()
        assert receipt['packets']==2 and receipt['incomplete_tail_bytes']==0
        final=tmp_path/'trace';path.rename(final)
        assert final.read_bytes()==first+second
    finally:cursor.close()


def test_refresh_cap_is_backlog_and_resumes_at_packet_boundary(tmp_path,monkeypatch):
    monkeypatch.setattr(live,'MAX_REFRESH_BYTES',8)
    path=tmp_path/'trace';path.write_bytes(b'\x0a\x03abc'*3)
    cursor=live.LivePacketCursor(path);chunks=[]
    try:
        first=cursor.consume(chunks.append)
        assert first['catching_up'] and first['incomplete_tail_bytes'] is None
        assert first['snapshot_bytes']==5 and first['pending_source_bytes']==10
        cursor.consume(chunks.append);last=cursor.consume(chunks.append)
        assert not last['catching_up'] and last['pending_source_bytes']==0
        assert b''.join(chunks)==path.read_bytes()
    finally:cursor.close()


@pytest.mark.parametrize('failure',['replace','truncate','link'])
def test_file_identity_or_shape_change_closes_cursor(tmp_path,failure):
    path=tmp_path/'trace';path.write_bytes(b'\x0a\x03abc')
    cursor=live.LivePacketCursor(path)
    cursor.consume(lambda body:None)
    if failure=='replace':
        path.rename(tmp_path/'original');path.write_bytes(b'\x0a\x03def')
    elif failure=='truncate':path.write_bytes(b'\x0a\x00')
    else:os.link(path,tmp_path/'alias')
    with pytest.raises(ContractError,match='no longer readable'):
        cursor.consume(lambda body:None)
    assert cursor.closed and cursor.handle is None


def test_decoder_failure_does_not_retry_a_partially_accepted_batch(tmp_path):
    path=tmp_path/'trace';path.write_bytes(b'\x0a\x03abc')
    cursor=live.LivePacketCursor(path)
    def failed(body):raise ContractError('transport failed after write')
    with pytest.raises(ContractError):cursor.consume(failed)
    with pytest.raises(ContractError,match='closed'):cursor.consume(lambda body:None)


def test_bundle_limits_are_explicit_and_do_not_relax_ordinary_live_cursor(tmp_path,monkeypatch):
    path=tmp_path/'trace';body=b'\x0a\x03abc'*3;path.write_bytes(body)
    monkeypatch.setattr(live,'MAX_LIVE_SNAPSHOT_BYTES',10)
    with pytest.raises(ContractError):
        cursor=live.LivePacketCursor(path)
        try:cursor.consume(lambda b:None)
        finally:cursor.close()
    cursor=live.LivePacketCursor(path,maximum_bytes=15,packet_limit=3)
    try:assert cursor.consume(lambda b:None)['snapshot_bytes']==15
    finally:cursor.close()
    for kwargs in ({'maximum_bytes':True},{'maximum_bytes':4*1024**3+1},{'packet_limit':40000001}):
        with pytest.raises(ContractError):live.LivePacketCursor(path,**kwargs)
