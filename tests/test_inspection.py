import csv
import io
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from browser_core.contracts import ContractError, validate_session
from browser_core.inspection import decode_rows
import browser_core.inspection as inspection
from browser_core.launcher import EvaluationLaunch, evaluation_command, validate_evaluation_launch


def _row():
    return dict(id='7', ts='1000', pid='123', tid='124', schema='browser-core.inspection/1',
        api='Navigator.userAgent.get', allowlist='fingerprint-v1', context_id='AB'*16,
        context_kind='window', realm_id='0', script_id='42', completion='returned',
        parameters_json=json.dumps({'count':0,'observed':[]}).encode().hex(),
        result_json=json.dumps({'type':'string','length':8,'value':'a,"b\nc<>'.ljust(8)}).encode().hex(),
        total_events='1')


def _body(rows):
    stream=io.StringIO();writer=csv.DictWriter(stream,fieldnames=list(_row()))
    writer.writeheader();writer.writerows(rows)
    return stream.getvalue().encode()


def test_lossless_value_readout_with_quotes_commas_newline_and_markup():
    values,total=decode_rows(_body([_row()]),limit=100)
    assert total==1 and values[0]['result']['value']=='a,"b\nc<>'
    assert values[0]['script_id']==42 and values[0]['context_id']=='AB'*16


def test_native_value_rows_reject_unterminated_quoted_population():
    body=_body([_row()]).rstrip(b'\r\n').rsplit(b',',1)[0]+b',"1'
    with pytest.raises(ContractError,match='bounded local contract'):
        decode_rows(body,limit=1)


def test_native_value_rows_reject_nonbyte_result():
    with pytest.raises(ContractError,match='bounded local contract'):
        decode_rows(_body([_row()]).decode(),limit=1)


def test_native_value_rows_stop_parsing_at_first_row_over_limit(monkeypatch):
    original_reader=csv.DictReader

    class CountedReader:
        def __init__(self,*args,**kwargs):
            self.reader=original_reader(*args,**kwargs)
            self.reads=0

        @property
        def fieldnames(self):
            return self.reader.fieldnames

        def __iter__(self):
            return self

        def __next__(self):
            self.reads+=1
            if self.reads>2:
                raise AssertionError('parsed beyond the first excess row')
            return next(self.reader)

    monkeypatch.setattr(inspection.csv,'DictReader',CountedReader)
    with pytest.raises(ContractError,match='bounded local contract'):
        decode_rows(_body([_row(),_row(),_row()]),limit=1)


def test_latest_inspection_rejects_reordered_native_rows(monkeypatch):
    older=dict(_row(),id='1',ts='10',total_events='2')
    newer=dict(_row(),id='2',ts='20',total_events='2')
    monkeypatch.setattr(inspection,'run_with_bounded_stdout',lambda *args,**kwargs:
                        SimpleNamespace(returncode=0,stdout=_body([older,newer])))
    with pytest.raises(ContractError,match='out of order'):
        inspection.read_inspection(Path('/processor'),Path('/recording'),limit=2)


def test_short_latest_inspection_page_cannot_claim_unreachable_matches(monkeypatch):
    row=dict(_row(),total_events='3')
    monkeypatch.setattr(inspection,'run_with_bounded_stdout',lambda *args,**kwargs:
                        SimpleNamespace(returncode=0,stdout=_body([row])))
    with pytest.raises(ContractError,match='count disagrees'):
        inspection.read_inspection(Path('/processor'),Path('/recording'),limit=2)


def test_live_inspection_does_not_borrow_a_replacement_runs_running_state(tmp_path,monkeypatch):
    source=tmp_path/'trace.live'
    source.write_bytes(b'\x0a\x01x')
    session={'run_id':'selected-run','trace_path':str(tmp_path/'trace'),
             'live_trace':{},'value_capture':inspection.CAPTURE_V1}
    monkeypatch.setattr(inspection,'verified_live_source',
                        lambda *args:(session,tmp_path/'chrome.exe',source))
    monkeypatch.setattr(inspection,'require_live_session_binding',lambda *args:None)
    monkeypatch.setattr('browser_core.recording_limits.observe_recording_limit',
                        lambda *args:(None,None))
    monkeypatch.setattr('browser_core.recording_interruption.observe_interruption',
                        lambda *args:None)
    monkeypatch.setattr(inspection,'read_inspection',lambda *args,**kwargs:{'events':[]})
    monkeypatch.setattr('browser_core.lifecycle.session_status',
                        lambda *args:{'run_id':'replacement-run','running':True})
    result=inspection.live_inspection(tmp_path/'session.json',tmp_path)
    assert result['run_id']=='selected-run'
    assert result['browser_running'] is False


@pytest.mark.parametrize('transition, expected_phase', [
    ('none', 'live-prefix'),
    ('limit', 'limited-recording'),
    ('final', 'finalized-recording'),
])
def test_live_inspection_reconciles_completion_during_query(tmp_path, monkeypatch, transition, expected_phase):
    from browser_core.recording_limits import MIB, limit_marker_path
    from browser_core.recording_source import bind_recording_file

    source = tmp_path/'trace.live'
    source.write_bytes(b'\x0a\x01x')
    final = tmp_path/'trace'
    session = {'run_id': 'owned-run', 'trace_path': str(final),
               'live_trace': {'path': str(source), 'byte_limit': 4*MIB,
                              'file_binding': bind_recording_file(source)},
               'value_capture': inspection.CAPTURE_V1}
    monkeypatch.setattr(inspection, 'verified_live_source',
                        lambda *args: (session, tmp_path/'chrome.exe', source))
    monkeypatch.setattr(inspection,'require_live_session_binding',lambda *args:None)
    monkeypatch.setattr('browser_core.lifecycle.session_status',
                        lambda *args: {'run_id': 'owned-run', 'running': True})

    def finish_during_query(*args, **kwargs):
        if transition == 'limit':
            limit_marker_path(final).write_bytes(b'')
        elif transition == 'final':
            source.rename(final)
        return {'events': [], 'total_events': 0}

    monkeypatch.setattr(inspection, 'read_inspection', finish_during_query)
    result = inspection.live_inspection(tmp_path/'session.json', tmp_path)
    assert result['source_phase'] == expected_phase
    assert result['complete'] is False
    assert result['snapshot_bytes'] == 3 and result['browser_running'] is True
    assert ('recording_limit' in result) is (transition == 'limit')


def test_live_inspection_rejects_replaced_live_file_after_query(tmp_path, monkeypatch):
    from browser_core.recording_limits import MIB
    from browser_core.recording_source import bind_recording_file

    source = tmp_path / 'trace.live'
    source.write_bytes(b'\x0a\x01x')
    session = {'run_id': 'owned-run', 'trace_path': str(tmp_path / 'trace'),
               'live_trace': {'path': str(source), 'byte_limit': 4*MIB,
                              'file_binding': bind_recording_file(source)},
               'value_capture': inspection.CAPTURE_V1}
    monkeypatch.setattr(inspection, 'verified_live_source',
                        lambda *args: (session, tmp_path / 'chrome.exe', source))
    monkeypatch.setattr('browser_core.lifecycle.session_status',
                        lambda *args: {'run_id': 'owned-run', 'running': True})

    def replace_live_file(*args, **kwargs):
        source.rename(tmp_path / 'retired-live')
        source.write_bytes(b'\x0a\x01x')
        return {'events': [], 'total_events': 0}

    monkeypatch.setattr(inspection, 'read_inspection', replace_live_file)
    with pytest.raises(ContractError, match='original file binding'):
        inspection.live_inspection(tmp_path / 'session.json', tmp_path)


def test_copied_string_length_matches_native_utf16_units():
    row=_row()
    row['result_json']=json.dumps({'type':'string','length':8,'value':'x'}).encode().hex()
    with pytest.raises(ContractError):decode_rows(_body([row]),limit=1)
    row['result_json']=json.dumps({'type':'string','length':2,'value':'\U0001f600'}).encode().hex()
    result,_=decode_rows(_body([row]),limit=1)
    assert result[0]['result']['value']=='\U0001f600'


def test_short_native_result_string_cannot_claim_length_omission():
    row=_row()
    row['result_json']=json.dumps({'type':'string','length':1024,
                                   'omitted':'length-limit'}).encode().hex()
    with pytest.raises(ContractError):decode_rows(_body([row]),limit=1)
    row['result_json']=json.dumps({'type':'string','length':1025,
                                   'omitted':'length-limit'}).encode().hex()
    assert decode_rows(_body([row]),limit=1)[0][0]['result']['omitted']=='length-limit'


@pytest.mark.parametrize('change',[
    {'schema':'browser-core.native/1'}, {'api':'Document.cookie.get'},
    {'allowlist':'everything'}, {'context_id':'arbitrary-url'}, {'completion':'success'},
    {'result_json':'not hex'}, {'result_json':'00'}, {'script_id':'-2'},
    {'total_events':'0'}, {'parameters_json':json.dumps({'count':1,'observed':[{'type':'string','length':6,'value':'secret'}]}).encode().hex()},
    {'result_json':json.dumps({'type':'object','value':{'secret':'x'}}).encode().hex()},
    {'result_json':json.dumps({'type':'number','value':float('nan')}).encode().hex()},
    {'completion':'exception'}, {'realm_id':'-1'},
])
def test_readout_rejects_unknown_or_incoherent_native_shapes(change):
    row=_row();row.update(change)
    with pytest.raises(ContractError):decode_rows(_body([row]),limit=100)


def test_readout_rejects_duplicate_or_excess_rows():
    row=_row();row['total_events']='2'
    with pytest.raises(ContractError):decode_rows(_body([row,row]),limit=100)
    with pytest.raises(ContractError):decode_rows(_body([row]),limit=0)


@pytest.mark.parametrize('field,wire',[
    ('id','07'),('ts','+1000'),('script_id',' 42'),('total_events','01'),
])
def test_native_integer_cells_must_be_canonical_decimal_text(field,wire):
    row=_row();row[field]=wire
    with pytest.raises(ContractError,match='bounded local contract'):
        decode_rows(_body([row]),limit=1)


@pytest.mark.parametrize('field',['realm_id','script_id'])
def test_native_int32_realm_and_script_ids_reject_larger_trace_cells(field):
    row=_row();row[field]=str(2**31)
    with pytest.raises(ContractError):decode_rows(_body([row]),limit=1)


@pytest.mark.parametrize('context_id',['AB','0'*32])
def test_native_context_id_is_the_full_execution_context_token(context_id):
    row=_row();row['context_id']=context_id
    with pytest.raises(ContractError):decode_rows(_body([row]),limit=1)


@pytest.mark.parametrize('field',['parameters_json','result_json'])
def test_native_hex_cells_must_be_contiguous(field):
    row=_row();row[field]=' '+row[field]
    with pytest.raises(ContractError,match='bounded local contract'):
        decode_rows(_body([row]),limit=1)


@pytest.mark.parametrize(('field', 'encoded'), [
    ('parameters_json', '{"count":9,"count":0,"observed":[]}'),
    ('parameters_json', '{"count":0,"observed":[1],"observed":[]}'),
    ('result_json', '{"type":"object","type":"number","value":7}'),
    ('result_json', '{"type":"number","value":1,"value":2}'),
    ('result_json', '{"type":"Int32Array","length":1,"values":[{"type":"number","value":1,"value":2}]}'),
])
def test_private_value_json_rejects_ambiguous_duplicate_keys(field, encoded):
    row = _row()
    row[field] = encoded.encode().hex()
    with pytest.raises(ContractError):
        decode_rows(_body([row]), limit=1)


@pytest.mark.parametrize('field', ['parameters_json', 'result_json'])
def test_deep_private_value_json_is_a_bounded_contract_failure(field):
    row = _row()
    row[field] = ('[' * 1200 + '0' + ']' * 1200).encode().hex()
    with pytest.raises(ContractError):
        decode_rows(_body([row]), limit=1)


def test_empty_population_requires_the_actual_query_header():
    assert decode_rows(_body([]),limit=100)==([],0)
    with pytest.raises(ContractError):decode_rows(b'',limit=100)
    with pytest.raises(ContractError):decode_rows(b'"id","id"\n',limit=100)


def test_vectors_and_exceptions_preserve_typed_results():
    row=_row();row.update(api='WebGL2RenderingContext.getParameter',
        parameters_json=json.dumps({'count':1,'observed':[{'type':'number','value':3386}]}).encode().hex(),
        result_json=json.dumps({'type':'Int32Array','length':2.0,'values':[{'type':'number','value':16384},{'type':'number','value':16384}]}).encode().hex())
    result,total=decode_rows(_body([row]),limit=1)
    assert result[0]['result']['values'][1]['value']==16384
    row.update(completion='exception',result_json=json.dumps({'type':'unavailable','omitted':'exception'}).encode().hex())
    assert decode_rows(_body([row]),limit=1)[0][0]['completion']=='exception'


@pytest.mark.parametrize('number',[-0.0,2**53+1])
def test_plain_number_cannot_claim_a_value_native_double_cannot_emit(number):
    row=_row()
    row['result_json']=json.dumps({'type':'number','value':number}).encode().hex()
    with pytest.raises(ContractError,match='bounded local contract'):
        decode_rows(_body([row]),limit=1)


@pytest.mark.parametrize('case',['boolean-result-without-value',
                                 'result-with-input-omission','input-with-result-omission'])
def test_native_value_roles_cannot_swap_result_and_input_forms(case):
    row=_row()
    if case=='boolean-result-without-value':
        row['api']='Navigator.cookieEnabled.get'
        row['result_json']=json.dumps({'type':'boolean'}).encode().hex()
    elif case=='result-with-input-omission':
        row['result_json']=json.dumps({'type':'string','length':2000,
                                       'omitted':'input-not-numeric'}).encode().hex()
    else:
        row['api']='WebGL2RenderingContext.getParameter'
        row['parameters_json']=json.dumps({'count':1,'observed':[
            {'type':'string','length':1,'omitted':'length-limit'}]}).encode().hex()
    with pytest.raises(ContractError,match='bounded local contract'):
        decode_rows(_body([row]),limit=1)


@pytest.mark.parametrize('invalid',[-2**31-1,2**31,1.5])
def test_copied_int32_vector_rejects_impossible_elements(invalid):
    row=_row();row.update(api='WebGL2RenderingContext.getParameter',
        parameters_json=json.dumps({'count':1,'observed':[{'type':'number','value':3386}]}).encode().hex(),
        result_json=json.dumps({'type':'Int32Array','length':1,
            'values':[{'type':'number','value':invalid}]}).encode().hex())
    with pytest.raises(ContractError):decode_rows(_body([row]),limit=1)


@pytest.mark.parametrize('changes',[{'inspect_values':1},{'inspect_values':True,'trace_mode':'off'},
    {'inspect_values':True,'allow_unverified_executable':True},
    {'extra_args':('--browser-core-inspect-values=fingerprint-v1',)},
    {'extra_args':('--browser-core-inspect-values=arbitrary',)}])
def test_value_capture_is_an_explicit_managed_option(tmp_path,changes):
    with pytest.raises(ContractError):validate_evaluation_launch(EvaluationLaunch(tmp_path/'chrome.exe',tmp_path,**changes))


def test_default_launch_retains_no_value_option(tmp_path):
    args=(tmp_path/'chrome.exe',tmp_path/'profile',tmp_path/'trace','example')
    off=evaluation_command(*args,headless=True,extra_args=())
    on=evaluation_command(*args,headless=True,extra_args=(),inspect_values=True)
    assert [arg for arg in on if arg!='--browser-core-inspect-values=fingerprint-v2']==off


def test_session_and_cli_preserve_the_declared_local_allowlist(tmp_path,monkeypatch,capsys):
    import browser_core.cli as cli
    document={'schema':'browser-core.session/1','run_id':'value-test','chromium_revision':'a'*40,
        'pid':123,'trace_mode':'on','trace_path':'/owned/trace',
        'automation':{'transport':'cdp','cdp_endpoint':'http://127.0.0.1:9222'},
        'value_capture':{'schema':'browser-core.inspection/1','allowlist':'fingerprint-v1'}}
    assert validate_session(document)==document
    observed=[]
    def launch(config,root):observed.append(config);return tmp_path/'session.json',document
    monkeypatch.setattr(cli,'launch_evaluation',launch)
    args=cli.build_parser().parse_args(['launch-eval','--executable',str(tmp_path/'chrome.exe'),'--workspace',str(tmp_path),'--live-trace','--inspect-values'])
    args.func(args)
    assert observed[0].inspect_values and observed[0].live_trace
    args=cli.build_parser().parse_args(['trace','live-values','--session',str(tmp_path/'session.json')])
    assert args.limit==100
    document['trace_mode']='off';document['trace_path']=None
    with pytest.raises(ContractError):validate_session(document)


def test_private_values_have_a_separate_native_schema_and_are_excluded_from_both_export_queries():
    from browser_core.perfetto import EXPORT_SQL, EXPORT_COUNT_SQL
    for query in (EXPORT_SQL,EXPORT_COUNT_SQL):
        assert "s.name='BrowserCoreInspection.BindingValue'" in query
    assert 'EXTRACT_ARG' not in EXPORT_COUNT_SQL
    root=Path(__file__).resolve().parents[1]
    patch=(root/'patches/0018-browser-core-native-binding-values.patch').read_text()
    assert 'info_.GetReturnValue().Get()' in patch
    assert 'isolate->HasPendingException()' in patch
    assert 'parameters.Append(Observe(isolate, info[0], false))' in patch
    assert 'GetExecutionContextToken' in patch and 'CurrentScriptId' in patch
