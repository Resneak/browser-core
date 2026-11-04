"""Pinned closed v1 compatibility, explicit v2 inventory, and hostile ledgers."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import jsonschema
import pytest

from browser_core import cli, evidence_query, metadata_query as query, session_query
from browser_core.contracts import ContractError
from browser_core.control_files import canonical_json_bytes
from browser_core.effort import summarize_effort
from browser_core.inspection_contract import CAPTURE_OFF, CAPTURE_V1
from browser_core.inspection_history import history_filters
from test_metadata_workflow import source, events, invalid_population

ROOT=Path(__file__).resolve().parents[1]
V1_SHA256='de9fc78788d6bded4fae5e6e6543231b56af31cd2b2c1295e94f4243a6365f63'

def validator(version):
    body=(ROOT/f'schemas/metadata-query-v{version}.schema.json').read_bytes()
    if version==1:
        # Frozen 0.5.26 consumer schema: changing it cannot make this test pass.
        assert hashlib.sha256(body).hexdigest()==V1_SHA256
    schema=json.loads(body)
    jsonschema.Draft202012Validator.check_schema(schema)
    return jsonschema.Draft202012Validator(schema)


def test_default_and_explicit_v1_preserve_closed_contract_and_cursor(source,events):
    options=dict(filters=history_filters(),limit=2,bundle_sha256='a'*64)
    default=query.metadata_query(source,**options)
    explicit=query.metadata_query(source,metadata_version=1,**options)
    assert default==explicit and 'inventory' not in default
    validator(1).validate(default)
    digest=hashlib.sha256(canonical_json_bytes(dict(schema='browser-core.metadata-query/1',
        filters=options['filters'],limit=2,ordering='timestamp-descending-then-sequence-descending'))).hexdigest()
    assert default['query']['query_sha256']==digest
    next_page=query.metadata_query(source,metadata_version=1,cursor=default['query']['next_cursor'],**options)
    assert [e['seq'] for e in next_page['events']]==[4,3]


@pytest.mark.parametrize('version',[1,2])
def test_versions_are_distinct_closed_shapes(source,events,version):
    result=query.metadata_query(source,filters=history_filters(),limit=1,metadata_version=version)
    validator(version).validate(result)
    assert result['schema']==f'browser-core.metadata-query/{version}'
    with pytest.raises(jsonschema.ValidationError):validator(3-version).validate(result)
    altered=deepcopy(result);altered['unexpected']=True
    with pytest.raises(jsonschema.ValidationError):validator(version).validate(altered)
    if version==2:
        assert result['inventory']['matching_events']=='7'
        del altered['unexpected'];del altered['inventory']
        with pytest.raises(jsonschema.ValidationError):validator(2).validate(altered)
    else:
        altered=deepcopy(result);altered['inventory']={}
        with pytest.raises(jsonschema.ValidationError):validator(1).validate(altered)


@pytest.mark.parametrize('version',[1,2])
def test_cross_version_cursor_rejected(source,events,version):
    options=dict(filters=history_filters(),limit=1,bundle_sha256='a'*64)
    page=query.metadata_query(source,metadata_version=version,**options)
    with pytest.raises(ContractError,match='cursor is invalid'):
        query.metadata_query(source,metadata_version=3-version,cursor=page['query']['next_cursor'],**options)


@pytest.mark.parametrize('version',[None,False,True,1.0,'2',[],{},0,3])
@pytest.mark.parametrize('entry',['metadata','evidence','session'])
def test_bad_version_is_inert_and_bounded(version,entry):
    with pytest.raises(ContractError,match='metadata version must be 1 or 2'):
        if entry=='metadata':query.metadata_query(None,filters={},limit=1,metadata_version=version)
        elif entry=='evidence':evidence_query.evidence_query(None,None,None,metadata_version=version)
        else:session_query.session_query(None,None,expected_run_id=None,metadata_version=version)


@pytest.mark.parametrize('entry',['metadata','evidence','session'])
def test_v1_does_not_silently_discard_activity(entry):
    with pytest.raises(ContractError,match='require metadata version 2'):
        if entry=='metadata':query.metadata_query(None,filters={},limit=1,analyst_activity=['browser-control'])
        elif entry=='evidence':evidence_query.evidence_query(None,None,None,analyst_activity=['browser-control'])
        else:session_query.session_query(None,None,expected_run_id=None,analyst_activity=['browser-control'])


@pytest.mark.parametrize('version',[1,2])
@pytest.mark.parametrize('route',['session-query','evidence-query'])
def test_cli_routes_version_to_actual_metadata_result(source,events,monkeypatch,tmp_path,capsys,route,version):
    options=['--metadata-version',str(version)]
    closed=[]
    if route=='session-query':
        monkeypatch.setattr(session_query,'RecordingSource',lambda *a,**kw:source)
        args=['--session',str(tmp_path/'owned-run.json'),'--expected-run-id','owned-run']
    else:
        bundle=SimpleNamespace(metadata={'capture':CAPTURE_OFF},source=source,sha256='a'*64,close=lambda:closed.append(True))
        monkeypatch.setattr(evidence_query,'OpenEvidence',lambda *a,**kw:bundle)
        args=['--bundle',str(tmp_path/'bundle'),'--reader-executable',str(tmp_path/'reader.exe')]
    if version==2:options+=['--analyst-activity','browser-control']
    assert cli.main(['trace',route,*args,*options])==0
    result=json.loads(capsys.readouterr().out);validator(version).validate(result)
    assert ('inventory' in result)==(version==2)
    if route=='evidence-query':assert closed==[True]


@pytest.mark.parametrize('route',['session-query','evidence-query'])
def test_private_routes_reject_v2_without_opening_inspector(source,monkeypatch,tmp_path,route):
    source.resolve().session['value_capture']=CAPTURE_V1
    if route=='session-query':
        monkeypatch.setattr(session_query,'RecordingSource',lambda *a,**kw:source)
        with pytest.raises(ContractError,match='requires metadata-only'):
            session_query.session_query(tmp_path/'owned-run.json',ROOT,expected_run_id='owned-run',metadata_version=2)
    else:
        closed=[]
        bundle=SimpleNamespace(metadata={'capture':CAPTURE_V1},close=lambda:closed.append(True))
        monkeypatch.setattr(evidence_query,'OpenEvidence',lambda *a,**kw:bundle)
        with pytest.raises(ContractError,match='requires metadata-only'):
            evidence_query.evidence_query(tmp_path/'bundle',ROOT,tmp_path/'reader.exe',metadata_version=2)
        assert closed==[True]


@pytest.mark.parametrize('version',[1,2])
@pytest.mark.parametrize('parent',['callback','promise'])
def test_versions_validate_hidden_population_before_inventory(source,invalid_population,parent,version):
    invalid_population(parent)
    with pytest.raises(ContractError,match='parent scope is inconsistent'):
        query.metadata_query(source,filters=history_filters(apis=['Unknown.event']),limit=1,metadata_version=version)


@pytest.mark.parametrize('version',[1,2])
def test_versions_keep_whole_response_bound(source,events,monkeypatch,version):
    monkeypatch.setattr(query,'MAX_OUTPUT_BYTES',1)
    with pytest.raises(ContractError,match='output limit'):
        query.metadata_query(source,filters=history_filters(),limit=1,metadata_version=version)


@pytest.mark.parametrize('field',['kind','stage','parent_id'])
@pytest.mark.parametrize('bad',[[],['untrusted-ledger-value'],{}, {'untrusted-ledger-value':1}, 0, True, 1.5, 'untrusted-ledger-value'])
def test_malformed_effort_fields_are_closed_in_reader_and_cli(tmp_path,capsys,field,bad):
    row=dict(schema='browser-core.effort/1',event='start',id='a'*32,parent_id=None,kind='outer-tool',stage='setup')
    row[field]=bad
    path=tmp_path/'untrusted-ledger-value.jsonl';path.write_text(json.dumps(row)+'\n')
    with pytest.raises(ContractError,match='duplicate or invalid effort start'):summarize_effort(path)
    assert cli.main(['agent','effort-summary','--ledger',str(path)])==2
    result=capsys.readouterr()
    assert result.out=='' and result.err=='browser-core: duplicate or invalid effort start\n'


@pytest.mark.parametrize('field',['kind','stage'])
def test_missing_or_null_effort_enum_is_closed(tmp_path,field):
    row=dict(schema='browser-core.effort/1',event='start',id='a'*32,parent_id=None,kind='outer-tool',stage='setup')
    for missing in (False,True):
        row[field]=None
        if missing:del row[field]
        path=tmp_path/'ledger';path.write_text(json.dumps(row)+'\n')
        with pytest.raises(ContractError):summarize_effort(path)
