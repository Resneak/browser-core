"""Disposed-script contexts retain verified identity without invented document ownership."""
import copy
import pytest

from browser_core.contracts import ContractError
from browser_core.inspection import decode_rows
from browser_core.inspection_attribution import ContextAttribution
from browser_core.inspection_context import decode_context
from test_inspection import _row
from test_inspection_context import encoded,native,with_context


def limited(kind='window'):
    return {'schema':'browser-core.inspection-context/2','context_id':'AB'*16,
            'v8_context_id':'BC'*16,'realm_id':0,'context_kind':kind,
            'unavailable':'invalid-script-context'}


def decode(value,kind='window'):
    return decode_context(encoded(value),context_id='AB'*16,realm_id=0,context_kind=kind)


@pytest.mark.parametrize('kind',['window','worker','other'])
def test_limited_native_identity_accepts_only_actual_envelope_identity(kind):
    value=limited(kind)
    assert decode(value,kind)==value


@pytest.mark.parametrize('change',[
    {'frame_id':'DE'*16},{'document_id':'CD'*16},{'document_url':{'display':'unverified'}},
    {'parent_frame_id':None},{'kind':'frame'},{'context_id':'FF'*16},
    {'v8_context_id':'0'*32},{'v8_context_id':True},{'realm_id':True},{'realm_id':1},
    {'context_kind':'worker'},{'context_kind':[]},{'unavailable':'unknown'},
    {'unavailable':None},{'schema':'browser-core.inspection-context/3'},
    {'schema':'browser-core.inspection-context/1'},
])
def test_limited_metadata_rejects_added_ownership_and_incoherent_identity(change):
    value=limited();value.update(change)
    with pytest.raises(ContractError):decode(value)


@pytest.mark.parametrize('missing',list(limited()))
def test_limited_metadata_never_defaults_a_missing_identity_field(missing):
    value=limited();value.pop(missing)
    with pytest.raises(ContractError):decode(value)


def test_limited_native_metadata_overrides_a_stale_frame_probe_without_claiming_ownership():
    row=_row();row['context_metadata_json']=encoded(limited())
    events,total=decode_rows(with_context([row]),limit=1)
    state=ContextAttribution()
    state.matches[(123,'AB'*16)]={'metadata':{'kind':'frame'},
        'sources':{'42':{'display':'stale frame source'}}}
    result={'events':events};state.enrich(result)
    attribution=events[0]['attribution']
    assert total==1 and attribution['status']=='native-limited'
    assert attribution['reason']=='invalid-script-context'
    assert attribution['kind']=='window' and attribution['v8_context_id']=='BC'*16
    assert all(attribution[k] is None for k in ('document_id','frame_id','parent_frame_id','worker_id','parent_context_id'))
    assert attribution['document']=={'status':'unavailable','reason':'invalid-script-context'}
    assert attribution['source']=={'status':'unresolved','reason':'script-source-not-recorded'}
    assert result['native_attribution']['attributed_observations_in_view']==0
    assert result['native_attribution']['limited_observations_in_view']==1
    assert result['native_attribution']['documents_in_view']==0


def test_limited_and_full_records_keep_their_distinct_provenance_in_a_mixed_view():
    first=_row();first.update(total_events='2',context_metadata_json=encoded(native()))
    second=copy.deepcopy(first);second.update(id='2',context_metadata_json=encoded(limited()))
    events,total=decode_rows(with_context([first,second]),limit=2)
    result={'events':events};ContextAttribution().enrich(result)
    assert total==2
    assert [e['attribution']['status'] for e in events]==['native-observed','native-limited']
    assert result['native_attribution']['attributed_observations_in_view']==1
    assert result['native_attribution']['limited_observations_in_view']==1
    assert result['native_attribution']['documents_in_view']==1


def test_another_realm_with_the_same_context_and_script_is_not_mislabeled_as_a_probe():
    row=_row();row['context_metadata_json']=encoded(limited())
    events,_=decode_rows(with_context([row]),limit=1)
    state=ContextAttribution();state.probes=[{'probe_script_id':42}]
    state.probe_identities[0].add((123,'AB'*16))
    state.probe_realms[0].add((123,'AA'*16,42))
    state.enrich({'events':events})
    assert 'observation_role' not in events[0]
