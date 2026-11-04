"""Exact latest-row queries over native-like integer ownership tables."""
import pytest

from browser_core.inspection import decode_rows, inspection_sql
from test_inspection_history import Decoder


@pytest.fixture
def decoder():
    value=Decoder()
    value.db.executescript('''
    CREATE VIEW slice AS SELECT * FROM __intrinsic_slice;
    CREATE VIEW thread_track AS SELECT id,EXTRACT_ARG(dimension_arg_set_id,'utid') AS utid FROM __intrinsic_track;
    CREATE VIEW thread AS SELECT id AS utid,upid,tid FROM __intrinsic_thread;
    CREATE VIEW process AS SELECT id AS upid,pid FROM __intrinsic_process;
    ''')
    yield value
    value.close()


@pytest.mark.parametrize('incremental',[False,True])
@pytest.mark.parametrize('limit',[1,17,1000])
def test_latest_rows_preserve_exact_order_and_joined_population(decoder,incremental,limit):
    base=2**53+31
    expected=[]
    for index in range(1,1041):
        event_id=base+index*7
        timestamp=base+(index*29)%113
        decoder.add(event_id,timestamp,value=f'fixture-{index}',pid=21+index%3)
        expected.append((timestamp,event_id))
    # More recent private slices can lack usable thread/process ownership.
    # Neither those nor unrelated event categories belong in the count or page.
    for index in range(1041,1045):
        decoder.add(base+index*7,base+999)
    decoder.db.execute('UPDATE __intrinsic_slice SET track_id=999 WHERE id=?',(base+1041*7,))
    decoder.db.execute("UPDATE __intrinsic_slice SET name='unrelated' WHERE id=?",(base+1042*7,))
    decoder.db.execute("UPDATE __intrinsic_slice SET category='unrelated' WHERE id=?",(base+1043*7,))
    decoder.args[999]={'utid':999}
    decoder.db.execute('INSERT INTO __intrinsic_track VALUES(999,999)')
    decoder.db.execute('INSERT INTO __intrinsic_thread VALUES(999,999,999)')
    decoder.db.execute('UPDATE __intrinsic_slice SET track_id=999 WHERE id=?',(base+1044*7,))
    rows,total=decode_rows(decoder.query(inspection_sql(limit,incremental=incremental),max_rows=limit),limit=limit)
    assert total==1040
    assert [(row['ts'],row['id']) for row in rows]==sorted(expected,reverse=True)[:limit]
    assert all(row['pid'] in (21,22,23) for row in rows)


@pytest.mark.parametrize('incremental',[False,True])
def test_empty_then_late_ownership_and_values_are_read_fresh(decoder,incremental):
    sql=inspection_sql(1,incremental=incremental)
    assert decode_rows(decoder.query(sql,max_rows=1),limit=1)==([],0)
    decoder.add(1,30,value='first')
    decoder.add(2,20,value='second',pid=22)
    decoder.db.execute('DELETE FROM __intrinsic_process WHERE pid=22')
    assert decode_rows(decoder.query(sql,max_rows=1),limit=1)[1]==1
    decoder.db.execute('INSERT INTO __intrinsic_process VALUES(2,22)')
    rows,total=decode_rows(decoder.query(sql,max_rows=1),limit=1)
    assert total==2 and rows[0]['id']==1
    # A later insertion may carry an older timestamp. New reads still count it.
    decoder.add(2**53+99,10,value='late')
    rows,total=decode_rows(decoder.query(sql,max_rows=1),limit=1)
    assert total==3 and rows[0]['id']==1


@pytest.mark.parametrize('incremental',[False,True])
def test_latest_page_extracts_observation_fields_only_for_displayed_rows(decoder,incremental):
    for index in range(1,65):decoder.add(index,index)
    observations=[]
    def extract(arg,key):
        if key.startswith('debug.'):observations.append((arg,key))
        return decoder.args[arg].get(key)
    decoder.db.create_function('EXTRACT_ARG',2,extract)
    rows,total=decode_rows(decoder.query(inspection_sql(2,incremental=incremental),max_rows=2),limit=2)
    assert total==64 and [row['id'] for row in rows]==[64,63]
    assert {arg for arg,key in observations}=={1063,1064}
    assert len(observations)==22


def add_stack_parent(decoder, *, name='Navigator.userAgent.get', category='blink.bindings',
                     track=1, timestamp=90, duration=20, status='observed'):
    decoder.add(1,100)
    decoder.db.execute('UPDATE __intrinsic_slice SET parent_id=2 WHERE id=1')
    decoder.args[2000]={'debug.stack_context_schema':'browser-core.js-stack/1',
        'debug.stack_context_status':status,'debug.stack_v8_context_id':'C'*32,
        'debug.stack_realm_id':0,'debug.stack_root_script_id':7}
    decoder.db.execute('INSERT INTO __intrinsic_slice VALUES(?,?,?,?,?,?,?,?)',
        (2,timestamp,track,2000,name,category,None,duration))


@pytest.mark.parametrize('incremental',[False,True])
def test_value_query_keeps_direct_stack_context_separate_from_binding_owner(decoder,incremental):
    add_stack_parent(decoder)
    rows,total=decode_rows(decoder.query(inspection_sql(1,incremental=incremental),max_rows=1),limit=1)
    assert total==1
    assert rows[0]['context_id']=='AB'*16 and rows[0]['script_id']==42
    assert rows[0]['js_stack']=={'schema':'browser-core.js-stack/1','status':'observed',
        'v8_context_id':'C'*32,'realm_id':0,'root_script_number':7}


@pytest.mark.parametrize('change',[
    {'name':'Navigator.language.get'},{'category':'unrelated'},
    {'track':9},{'timestamp':101},{'duration':9},
])
def test_value_query_cannot_borrow_stack_context_from_an_unrelated_parent(decoder,change):
    add_stack_parent(decoder,**change)
    rows,total=decode_rows(decoder.query(inspection_sql(1,incremental=True),max_rows=1),limit=1)
    assert total==1 and 'js_stack' not in rows[0]


def test_value_query_rejects_malformed_native_stack_annotation(decoder):
    from browser_core.contracts import ContractError
    add_stack_parent(decoder,status='guessed')
    with pytest.raises(ContractError):
        decode_rows(decoder.query(inspection_sql(1,incremental=True),max_rows=1),limit=1)
