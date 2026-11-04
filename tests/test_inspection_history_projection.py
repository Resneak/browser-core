"""History pages must not project every matching observation's display fields."""
import pytest

from browser_core.inspection import decode_rows
from browser_core.inspection_history import history_filters,history_sql
from test_inspection_history import Decoder


@pytest.mark.parametrize('case',['full','script','search','worker','scope','range','short_range','absent'])
@pytest.mark.parametrize('later_page',[False,True])
def test_history_projects_only_page_rows_while_counting_all_matches(case,later_page):
    decoder=Decoder()
    expected=[];filters={}
    if case=='script':filters={'script':'2'}
    elif case=='search':filters={'search':'group 1'}
    elif case=='worker':filters={'context':'worker'}
    elif case=='scope':filters={'scope':{'pid':'21','context_id':'AB'*16,'realm_id':'0'}}
    elif case=='range':filters={'start_ns':str(2**53+20),'end_ns':str(2**53+30)}
    elif case=='short_range':filters={'start_ns':str(2**53+40),'end_ns':str(2**53+40)}
    elif case=='absent':filters={'search':'absent marker'}
    try:
        for index in range(1,121):
            timestamp=2**53+index//3
            decoder.add(index,timestamp,value=f'group {index%3}',script=index%5,
                        pid=21+index%2,context='worker' if index%2 else 'window')
            matches=(case=='full' or case=='script' and index%5==2 or
                     case=='search' and index%3==1 or case=='worker' and index%2==1 or
                     case=='scope' and index%2==0 or case=='range' and 20<=index//3<=30 or
                     case=='short_range' and index//3==40)
            if matches:expected.append((timestamp,index))
        before=(2**53+28,84) if later_page else None
        ordered=sorted(expected,reverse=True)
        page=[item for item in ordered if before is None or item<before][:6]
        projected=[]
        def extract(arg,key):
            if key=='debug.schema':projected.append(arg)
            return decoder.args[arg].get(key)
        decoder.db.create_function('EXTRACT_ARG',2,extract)
        body=decoder.query(history_sql(history_filters(**filters),120,before=before,limit=5),max_rows=6)
        rows,total=decode_rows(body,limit=6)
        assert [(row['ts'],row['id']) for row in rows]==page
        assert total==(len(expected) if page else 0)
        assert sorted(projected)==sorted(event_id+1000 for timestamp,event_id in page)
    finally:decoder.close()
