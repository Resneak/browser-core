import csv
import io
import json
import sqlite3
from pathlib import Path
from types import SimpleNamespace

import pytest

from browser_core.contracts import ContractError
from browser_core.incremental_inspection import IncrementalInspection
from browser_core.inspection_history import history_filters, history_sql, encode_cursor, decode_cursor, query_digest


class Decoder:
    """Execute the actual generated query against rows with native column types."""
    def __init__(self):
        self.db=sqlite3.connect(':memory:')
        self.args={1:{'utid':1}}
        self.db.create_function('EXTRACT_ARG',2,lambda arg,key:self.args[arg].get(key))
        self.db.executescript('''
        CREATE TABLE __intrinsic_slice(id INTEGER, ts INTEGER, track_id INTEGER, arg_set_id INTEGER, name TEXT, category TEXT, parent_id INTEGER, dur INTEGER DEFAULT 0);
        CREATE TABLE __intrinsic_track(id INTEGER, dimension_arg_set_id INTEGER);
        CREATE TABLE __intrinsic_thread(id INTEGER, upid INTEGER, tid INTEGER);
        CREATE TABLE __intrinsic_process(id INTEGER, pid INTEGER);
        INSERT INTO __intrinsic_track VALUES(1,1);
        INSERT INTO __intrinsic_thread VALUES(1,1,22);
        INSERT INTO __intrinsic_process VALUES(1,21);
        ''')
        self.closed=False
        self.tracks={21:1}

    def add(self, event_id, timestamp, *, value='fixture', script=42, context='window',
            pid=21, context_id='AB'*16, realm=0):
        if pid not in self.tracks:
            track=len(self.tracks)+1
            self.tracks[pid]=track
            self.args[100+track]={'utid':track}
            self.db.execute('INSERT INTO __intrinsic_track VALUES(?,?)',(track,100+track))
            self.db.execute('INSERT INTO __intrinsic_thread VALUES(?,?,?)',(track,track,pid+1))
            self.db.execute('INSERT INTO __intrinsic_process VALUES(?,?)',(track,pid))
        self.args[event_id+1000]={f'debug.{key}':value for key,value in {
            'schema':'browser-core.inspection/1','allowlist':'fingerprint-v1',
            'api':'Navigator.userAgent.get','context_id':context_id,'context_kind':context,
            'realm_id':realm,'script_id':script,'completion':'returned',
            'parameters_json':json.dumps({'count':0,'observed':[]}),
            'result_json':json.dumps({'type':'string','length':len(value),'value':value}),
        }.items()}
        self.db.execute('INSERT INTO __intrinsic_slice(id,ts,track_id,arg_set_id,name,category) VALUES(?,?,?,?,?,?)',
                        (event_id,timestamp,self.tracks[pid],event_id+1000,'BrowserCoreInspection.BindingValue','browser_core.debug'))

    def query(self, sql, *, max_rows):
        result=self.db.execute(sql);rows=result.fetchall();assert len(rows)<=max_rows
        output=io.StringIO();writer=csv.writer(output)
        writer.writerow([d[0] for d in result.description]);writer.writerows(rows)
        return output.getvalue().encode()

    def close(self):
        self.closed=True;self.db.close()


@pytest.fixture
def reader():
    reader=IncrementalInspection(Path('/session'),Path('/repo'))
    reader.decoder=Decoder()
    reader.read=lambda **kwargs:{'browser_running':True,'schema':'browser-core.inspection/1','allowlist':'fingerprint-v1'}
    yield reader
    if not reader.closed:reader.close()


def test_pages_exhaust_the_snapshot_without_gaps_duplicates_or_timestamp_rounding(reader):
    base=2**53+17
    for i in range(1,13):reader.decoder.add(i,base+i//3)
    first=reader.history(limit=4)
    assert first['total_events']==12 and [e['id'] for e in first['events']]==[12,11,10,9]
    # A newly parsed event can have an older timestamp. Insertion high-water
    # filtering must still exclude it from every page of the original search.
    reader.decoder.add(13,base+1)
    reader.decoder.add(14,base+20)
    second=reader.history(limit=4,cursor=first['next_cursor'])
    third=reader.history(limit=4,cursor=second['next_cursor'])
    assert [e['id'] for e in first['events']+second['events']+third['events']]==list(range(12,0,-1))
    assert second['total_events']==third['total_events']==12 and third['next_cursor'] is None
    again=reader.history(limit=4,cursor=first['page_cursor'])
    assert again['events']==first['events'] and again['snapshot_max_id']==first['snapshot_max_id']
    fresh=reader.history(limit=4)
    assert fresh['total_events']==14 and fresh['events'][0]['id']==14


def test_live_history_cannot_issue_cursor_after_session_replacement(reader):
    reader.decoder.add(1,1)
    location=SimpleNamespace(path=Path('/owned-recording'),phase='live-prefix',
                             session={'run_id':'owned'})
    reader.source=SimpleNamespace(resolve=lambda:location)
    reader.cursor=SimpleNamespace(source=location.path,close=lambda:None)
    reader.read=lambda **kwargs:{'browser_running':True,
        'schema':'browser-core.inspection/1','allowlist':'fingerprint-v1',
        'run_id':'owned','source_phase':'live-prefix'}
    original=reader.decoder.query
    def query_then_replace(sql,**kwargs):
        if 'MAX(id)' in sql:
            location.session={'run_id':'replacement'}
        return original(sql,**kwargs)
    reader.decoder.query=query_then_replace
    with pytest.raises(ContractError,match='source changed'):
        reader.history(limit=1)
    assert reader.closed


def test_search_finds_early_value_after_more_than_1000_later_events(reader):
    reader.decoder.add(1,1,value='early needle',script=7,context='worker')
    for i in range(2,1012):reader.decoder.add(i,i)
    live_order=reader.history()
    assert len(live_order['events'])==1000 and all(e['id']!=1 for e in live_order['events'])
    found=reader.history(search='NEEDLE',script='7',context='worker')
    assert found['total_events']==1 and [e['id'] for e in found['events']]==[1]
    assert reader.history(search='needle',context='window')['events']==[]


@pytest.mark.parametrize('literal',["' OR 1=1 --",'100%_literal',r'a\b', '漢字', '<img src=x>'])
def test_search_text_is_literal_data_and_never_sql(literal,reader):
    reader.decoder.add(1,1,value=literal)
    reader.decoder.add(2,2,value='unrelated')
    # Search is recorded JSON text: escaped characters use their JSON spelling.
    search=json.dumps(literal)[1:-1]
    found=reader.history(search=search)
    assert [e['id'] for e in found['events']]==[1]


@pytest.mark.parametrize('filters',[
    {'search':'x'*257},{'search':'\ud800'},{'search':None},
    {'script':'1 OR 1=1'},{'script':'01'},{'script':'-2'},
    {'script':str(2**31)},{'script':str(2**63)},{'script':42},{'context':'workers'},
])
def test_invalid_filters_do_not_destroy_live_reader(filters,reader):
    with pytest.raises(ContractError):reader.history(**filters)
    assert not reader.closed


def test_foreign_modified_or_different_search_cursors_do_not_close_reader(reader):
    for i in range(1,4):reader.decoder.add(i,i)
    first=reader.history(limit=1);cursor=first['next_cursor']
    for bad in [cursor[:-6]+'AAAAAA', 'x'*513, 'not base64', 42]:
        with pytest.raises(ContractError):reader.history(cursor=bad,limit=1)
        assert not reader.closed
    with pytest.raises(ContractError):reader.history(cursor=cursor,search='different',limit=1)
    with pytest.raises(ContractError):reader.history(cursor=cursor,limit=2)
    other=IncrementalInspection(Path('/session'),Path('/repo'))
    with pytest.raises(ContractError):other.history(cursor=cursor,limit=1)
    assert not other.closed


def test_empty_history_has_no_cursor_and_consistent_population(reader):
    result=reader.history()
    assert result['events']==[] and result['total_events']==0 and result['next_cursor'] is None
    assert reader.history(cursor=result['page_cursor'])['events']==[]


def test_history_resets_refresh_deadline_before_highwater_query(reader):
    original_read=reader.read
    original_query=reader.decoder.query
    observed=[]

    def nearly_expired_read(**kwargs):
        reader.decoder.timeout=0.001
        return original_read(**kwargs)

    def query(sql,**kwargs):
        if 'MAX(id)' in sql:
            observed.append(reader.decoder.timeout)
        return original_query(sql,**kwargs)

    reader.read=nearly_expired_read
    reader.decoder.query=query
    reader.history()
    assert observed==[30]


def test_decoder_query_failure_remains_terminal(reader):
    def failed(*args,**kwargs):raise ContractError('transport failed')
    reader.decoder.query=failed
    with pytest.raises(ContractError):reader.history()
    assert reader.closed and reader.decoder.closed


@pytest.mark.parametrize('body', [
    b'highwater\n',
    b'highwater\n0\n1\n',
    b'other\n1\n',
    b'highwater\n01\n',
])
def test_malformed_highwater_response_cannot_start_incomplete_search(reader,body):
    reader.decoder.add(1,1)
    original=reader.decoder.query

    def malformed(sql,**kwargs):
        if 'SELECT COALESCE(MAX(id), 0) AS highwater' in sql:
            return body
        return original(sql,**kwargs)

    reader.decoder.query=malformed
    with pytest.raises(ContractError,match='history boundary violates its native contract'):
        reader.history()
    assert reader.closed


def test_reordered_native_history_rows_cannot_issue_skipping_page_cursor(reader):
    for event_id in range(1,4):reader.decoder.add(event_id,event_id)
    original=reader.decoder.query

    def reordered(sql,**kwargs):
        body=original(sql,**kwargs)
        if 'FROM selected s ORDER BY s.ts DESC,s.id DESC' not in sql:
            return body
        rows=list(csv.reader(io.StringIO(body.decode())))
        output=io.StringIO();writer=csv.writer(output)
        writer.writerow(rows[0]);writer.writerows(reversed(rows[1:]))
        return output.getvalue().encode()

    reader.decoder.query=reordered
    with pytest.raises(ContractError,match='history rows are out of order'):
        reader.history(limit=2)
    assert reader.closed


def test_history_page_rejects_rows_outside_its_authenticated_boundary(reader):
    for event_id in range(1,4):reader.decoder.add(event_id,event_id)
    first=reader.history(limit=1)
    original=reader.decoder.query
    replay=original(history_sql(history_filters(),3,limit=1),max_rows=2)

    def repeated(sql,**kwargs):
        if sql.startswith('WITH matches AS MATERIALIZED'):
            return replay
        return original(sql,**kwargs)

    reader.decoder.query=repeated
    with pytest.raises(ContractError,match='history rows exceed their page boundary'):
        reader.history(limit=1,cursor=first['next_cursor'])
    assert reader.closed


def test_short_first_history_page_cannot_claim_unreachable_matches(reader):
    reader.decoder.add(1,1)
    original=reader.decoder.query

    def false_count(sql,**kwargs):
        body=original(sql,**kwargs)
        if 'FROM selected s ORDER BY s.ts DESC,s.id DESC' not in sql:
            return body
        rows=list(csv.reader(io.StringIO(body.decode())))
        count=rows[0].index('total_events')
        for row in rows[1:]:
            row[count]='2'
        output=io.StringIO();writer=csv.writer(output)
        writer.writerows(rows)
        return output.getvalue().encode()

    reader.decoder.query=false_count
    with pytest.raises(ContractError,match='history count disagrees'):
        reader.history(limit=2)
    assert reader.closed


def test_later_history_page_cannot_shrink_below_next_cursor_population(reader):
    reader.decoder.add(1,1);reader.decoder.add(2,2)
    first=reader.history(limit=1)
    original=reader.decoder.query

    def false_count(sql,**kwargs):
        body=original(sql,**kwargs)
        if not sql.startswith('WITH matches AS MATERIALIZED'):
            return body
        rows=list(csv.reader(io.StringIO(body.decode())))
        count=rows[0].index('total_events')
        for row in rows[1:]:row[count]='1'
        output=io.StringIO();writer=csv.writer(output)
        writer.writerows(rows)
        return output.getvalue().encode()

    reader.decoder.query=false_count
    with pytest.raises(ContractError,match='history count disagrees'):
        reader.history(limit=1,cursor=first['next_cursor'])
    assert reader.closed


def test_later_history_page_count_includes_the_preceding_page(reader):
    for event_id in range(1,6):
        reader.decoder.add(event_id,event_id)
    first=reader.history(limit=2)
    original=reader.decoder.query

    def false_count(sql,**kwargs):
        body=original(sql,**kwargs)
        if not sql.startswith('WITH matches AS MATERIALIZED'):
            return body
        rows=list(csv.reader(io.StringIO(body.decode())))
        count=rows[0].index('total_events')
        for row in rows[1:]:row[count]='3'
        output=io.StringIO();writer=csv.writer(output)
        writer.writerows(rows)
        return output.getvalue().encode()

    reader.decoder.query=false_count
    with pytest.raises(ContractError,match='history count disagrees'):
        reader.history(limit=2,cursor=first['next_cursor'])
    assert reader.closed


def test_cursor_rejects_a_signed_incoherent_boundary():
    key=b'k'*32;query=query_digest(history_filters(),1)
    cursor=encode_cursor(key,query,5,10,6)
    with pytest.raises(ContractError):decode_cursor(key,query,cursor)


SCOPE={'pid':'21','context_id':'AB'*16,'realm_id':'0'}


def test_exact_context_scope_separates_processes_contexts_and_worlds(reader):
    reader.decoder.add(1,1)
    reader.decoder.add(2,2,script=43)  # Another script in the same native context.
    reader.decoder.add(3,3,pid=22)
    reader.decoder.add(4,4,context_id='CD'*16)
    reader.decoder.add(5,5,realm=7)
    found=reader.history(scope=SCOPE,limit=1)
    assert found['total_events']==2 and [event['id'] for event in found['events']]==[2]
    reader.decoder.add(6,1)  # Late ingestion remains outside the fixed search.
    older=reader.history(scope=SCOPE,cursor=found['next_cursor'],limit=1)
    assert older['total_events']==2 and [event['id'] for event in older['events']]==[1]
    assert older['next_cursor'] is None
    assert reader.history(scope=SCOPE)['total_events']==3
    assert reader.history(scope={**SCOPE,'realm_id':'7'})['events'][0]['id']==5


def test_context_scope_reaches_beyond_the_latest_window(reader):
    reader.decoder.add(1,1)
    for i in range(2,1020):
        reader.decoder.add(i,i,context_id='CD'*16)
    found=reader.history(scope=SCOPE)
    assert found['total_events']==1 and [event['id'] for event in found['events']]==[1]


def test_time_bounds_are_exact_inclusive_and_combined_with_context(reader):
    base=2**53+17
    for i in range(1,7):
        reader.decoder.add(i,base+i//2)
    reader.decoder.add(7,base+1,pid=22)
    found=reader.history(scope=SCOPE,start_ns=str(base+1),end_ns=str(base+2),limit=2)
    assert found['total_events']==4 and [e['id'] for e in found['events']]==[5,4]
    older=reader.history(scope=SCOPE,start_ns=str(base+1),end_ns=str(base+2),
                         cursor=found['next_cursor'],limit=2)
    assert older['total_events']==4 and [e['id'] for e in older['events']]==[3,2]
    ties=reader.history(scope=SCOPE,start_ns=str(base+1),end_ns=str(base+1))
    assert ties['total_events']==2 and {e['ts'] for e in ties['events']}=={base+1}


@pytest.mark.parametrize('filters',[
    {'scope':{}},{'scope':[]},{'scope':{**SCOPE,'extra':'value'}},
    {'scope':{**SCOPE,'pid':21}},{'scope':{**SCOPE,'pid':'021'}},
    {'scope':{**SCOPE,'context_id':"' OR 1=1 --"}},
    {'scope':{**SCOPE,'context_id':'AB'}},
    {'scope':{**SCOPE,'context_id':'0'*32}},
    {'scope':{**SCOPE,'context_id':'A'*65}},{'scope':{**SCOPE,'realm_id':'-1'}},
    {'scope':{**SCOPE,'realm_id':str(2**31)}},
    {'scope':{**SCOPE,'realm_id':str(2**63)}},
    {'start_ns':None},{'start_ns':1},{'end_ns':True},{'start_ns':'01'},
    {'start_ns':'1e3'},{'end_ns':str(2**63)},{'start_ns':'2','end_ns':'1'},
])
def test_invalid_scope_and_time_bounds_preserve_reader(filters,reader):
    with pytest.raises(ContractError):reader.history(**filters)
    assert not reader.closed


def test_scope_and_time_filters_are_bound_to_page_cursors(reader):
    for i in range(1,4):reader.decoder.add(i,i)
    first=reader.history(scope={**SCOPE,'context_id':SCOPE['context_id'].lower()},start_ns='0',limit=1)
    assert first['filters']['scope']==SCOPE
    assert reader.history(scope=SCOPE,start_ns='0',cursor=first['next_cursor'],limit=1)['total_events']==3
    for filters in ({'scope':SCOPE}, {'scope':{**SCOPE,'pid':'22'},'start_ns':'0'},
                    {'scope':SCOPE,'start_ns':'0','end_ns':'3'}):
        with pytest.raises(ContractError):reader.history(**filters,cursor=first['next_cursor'],limit=1)
        assert not reader.closed
