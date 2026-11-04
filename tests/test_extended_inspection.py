import hashlib,json,struct
import pytest
from browser_core.contracts import ContractError,validate_session
from browser_core.inspection import decode_rows,inspection_result
from browser_core.inspection_contract import CAPTURE_V1,CAPTURE_V2,APIS_V1,APIS_V2
from test_inspection import _row,_body

def extended_row(api='AudioBuffer.getChannelData',value=None):
    row=_row();row.update(CAPTURE_V2,api=api)
    row['parameters_json']=json.dumps({'count':1,'observed':[{'type':'number','value':0}]} if api=='AudioBuffer.getChannelData' else {'count':0,'observed':[]}).encode().hex()
    row['result_json']=json.dumps(value or {'type':'Float32Array','length':128.0,'byte_length':512,'sha256':'a'*64,'prefix_values':[{'type':'number','value':0}]*64}).encode().hex()
    return row

def test_extended_digest_and_prefix_keep_the_recording_version():
    rows,total=decode_rows(_body([extended_row()]),limit=1)
    assert rows[0]['result']['length']==128 and len(rows[0]['result']['prefix_values'])==64
    assert inspection_result(rows,total,1)['schema']==CAPTURE_V2['schema']
    assert inspection_result(rows,total,1)['allowlist']==CAPTURE_V2['allowlist']

def test_empty_session_result_uses_the_explicit_capture_version():
    rows,total=decode_rows(_body([]),limit=1,capture=CAPTURE_V2)
    assert inspection_result(rows,total,1)['schema']==CAPTURE_V2['schema']

@pytest.mark.parametrize('change',[
    {'schema':CAPTURE_V1['schema']},{'allowlist':CAPTURE_V1['allowlist']},
    CAPTURE_V1,{'api':'Navigator.credentials.get'},{'schema':'browser-core.inspection/3'},
])
def test_new_fields_cannot_be_smuggled_into_an_old_or_unknown_capture(change):
    row=extended_row();row.update(change)
    with pytest.raises(ContractError):decode_rows(_body([row]),limit=1)

def test_mixed_versions_and_disagreement_with_session_are_rejected():
    old=_row();new=extended_row();new['id']='2'
    for r in (old,new):r['total_events']='2'
    with pytest.raises(ContractError):decode_rows(_body([old,new]),limit=2)
    with pytest.raises(ContractError):decode_rows(_body([old]),limit=1,capture=CAPTURE_V2)

@pytest.mark.parametrize('change',[
    {'sha256':'A'*64},{'sha256':'a'*63},{'sha256':None},
    {'length':True},{'length':128.5},{'length':64},{'byte_length':513},
    {'prefix_values':[]},{'prefix_values':[{'type':'number','value':0}]*65},
    {'prefix_values':[{'type':'string','length':1,'value':'x'}]*64},
    {'length':300000,'byte_length':1200000}, {'extra':1},
])
def test_vector_digests_are_bounded_and_structurally_exact(change):
    row=extended_row();value=json.loads(bytes.fromhex(row['result_json']));value.update(change)
    row['result_json']=json.dumps(value).encode().hex()
    with pytest.raises(ContractError):decode_rows(_body([row]),limit=1)


@pytest.mark.parametrize('kind,api,invalid,size',[
    ('Uint8ClampedArray','ImageData.data.get',256,1),
    ('Int32Array','WebGL2RenderingContext.getParameter',2**31,4),
])
def test_digested_integer_vector_prefix_rejects_impossible_elements(kind,api,invalid,size):
    value={'type':kind,'length':128,'byte_length':128*size,'sha256':'a'*64,
           'prefix_values':[{'type':'number','value':0}]*64}
    row=extended_row(api,value)
    if api=='WebGL2RenderingContext.getParameter':
        row['parameters_json']=json.dumps({'count':1,'observed':[
            {'type':'number','value':123}]}).encode().hex()
    assert decode_rows(_body([row]),limit=1)[0][0]['result']==value
    value['prefix_values'][-1]={'type':'number','value':invalid}
    row['result_json']=json.dumps(value).encode().hex()
    with pytest.raises(ContractError):decode_rows(_body([row]),limit=1)


@pytest.mark.parametrize('digested',[False,True])
def test_float32_vector_elements_must_be_exact_copied_float32_values(digested):
    field='prefix_values' if digested else 'values'
    value={'type':'Float32Array','length':128 if digested else 1,
           field:[{'type':'number','value':0.1}]* (64 if digested else 1)}
    if digested:value.update(byte_length=512,sha256='a'*64)
    row=extended_row('AudioBuffer.getChannelData',value)
    with pytest.raises(ContractError):decode_rows(_body([row]),limit=1)
    rounded=struct.unpack('<f',struct.pack('<f',0.1))[0]
    value[field]=[{'type':'number','value':rounded}]*len(value[field])
    row['result_json']=json.dumps(value).encode().hex()
    assert decode_rows(_body([row]),limit=1)[0][0]['result']==value


def test_float64_vector_keeps_non_float32_double_values():
    value={'type':'Float64Array','length':1,
           'values':[{'type':'number','value':0.1}]}
    row=extended_row('WebGL2RenderingContext.getParameter',value)
    row['parameters_json']=json.dumps({'count':1,'observed':[
        {'type':'number','value':123}]}).encode().hex()
    assert decode_rows(_body([row]),limit=1)[0][0]['result']==value

@pytest.mark.parametrize('kind',['Uint8ClampedArray','Uint8Array','Float64Array'])
def test_new_small_native_vectors_are_supported_only_in_v2(kind):
    value={'type':kind,'length':2.0,'values':[{'type':'number','value':1},{'type':'number','value':2}]}
    row=extended_row('ImageData.data.get',value)
    assert decode_rows(_body([row]),limit=1)[0][0]['result']==value
    row.update(CAPTURE_V1,api='Navigator.userAgent.get')
    with pytest.raises(ContractError):decode_rows(_body([row]),limit=1)


@pytest.mark.parametrize('invalid',[-1,256,1.5])
def test_copied_byte_vector_rejects_impossible_elements(invalid):
    value={'type':'Uint8ClampedArray','length':1,
           'values':[{'type':'number','value':invalid}]}
    with pytest.raises(ContractError):
        decode_rows(_body([extended_row('ImageData.data.get',value)]),limit=1)

def test_own_string_sequence_has_exact_content_and_bounded_total():
    value={'type':'string-array','length':2.0,'values':[{'type':'string','length':5,'value':'en-US'},{'type':'string','length':2,'value':'en'}]}
    row=extended_row('Navigator.languages.get',value)
    assert decode_rows(_body([row]),limit=1)[0][0]['result']==value
    value['length']=64;value['values']=[{'type':'string','length':128,'value':'x'*128}]*64
    row['result_json']=json.dumps(value).encode().hex()
    with pytest.raises(ContractError):decode_rows(_body([row]),limit=1)


def test_copied_string_sequence_only_appears_on_native_sequence_apis():
    value={'type':'string-array','length':1,
           'values':[{'type':'string','length':2,'value':'en'}]}
    row=extended_row('HTMLCanvasElement.toDataURL',value)
    with pytest.raises(ContractError):decode_rows(_body([row]),limit=1)
    for api in ('Navigator.languages.get','WorkerNavigator.languages.get',
                'WebGLRenderingContext.getSupportedExtensions',
                'WebGL2RenderingContext.getSupportedExtensions'):
        assert decode_rows(_body([extended_row(api,value)]),limit=1)[0][0]['result']==value

@pytest.mark.parametrize('value',[
    {'type':'string-array','length':65,'values':[]},
    {'type':'string-array','length':1,'values':[{'type':'object','omitted':'no-object-inspection'}]},
    {'type':'string-array','length':1,'values':[{'type':'string','length':129,'value':'x'*129}]},
    {'type':'string-array','length':1,'omitted':'arbitrary'},
])
def test_string_sequence_never_admits_general_object_traversal(value):
    with pytest.raises(ContractError):decode_rows(_body([extended_row('Navigator.languages.get',value)]),limit=1)


@pytest.mark.parametrize('length,reason',[
    (65,'not-own-string-data'), (0,'not-own-string-data'), (0,'length-limit'),
])
def test_string_sequence_omission_matches_native_decision_order(length,reason):
    value={'type':'string-array','length':length,'omitted':reason}
    with pytest.raises(ContractError):
        decode_rows(_body([extended_row('Navigator.languages.get',value)]),limit=1)
    if length==65:
        value['omitted']='length-limit'
        assert decode_rows(_body([extended_row('Navigator.languages.get',value)]),limit=1)[0][0]['result']==value

def test_long_string_is_a_digest_and_preview_not_a_claim_of_full_text():
    text='x'*2048
    value={'type':'string','length':len(text),'byte_length':len(text),'sha256':hashlib.sha256(text.encode()).hexdigest(),'prefix':text[:256]}
    row=extended_row('HTMLCanvasElement.toDataURL',value)
    assert decode_rows(_body([row]),limit=1)[0][0]['result']==value
    value['prefix']='x'*257;row['result_json']=json.dumps(value).encode().hex()
    with pytest.raises(ContractError):decode_rows(_body([row]),limit=1)


def test_long_string_prefix_is_bounded_by_native_utf8_bytes():
    value={'type':'string','length':2048,'byte_length':2048,
           'sha256':'a'*64,'prefix':'é'*200}
    with pytest.raises(ContractError):
        decode_rows(_body([extended_row('HTMLCanvasElement.toDataURL',value)]),limit=1)


def test_long_string_digest_keeps_the_full_native_prefix_window():
    value={'type':'string','length':2048,'byte_length':2048,
           'sha256':'a'*64,'prefix':'x'*252}
    with pytest.raises(ContractError):
        decode_rows(_body([extended_row('HTMLCanvasElement.toDataURL',value)]),limit=1)
    value['prefix']='x'*256
    assert decode_rows(_body([extended_row('HTMLCanvasElement.toDataURL',value)]),limit=1)[0][0]['result']==value


def test_long_string_digest_byte_count_respects_utf16_to_utf8_maximum():
    value={'type':'string','length':2048,'byte_length':6145,
           'sha256':'a'*64,'prefix':'€'*85}
    with pytest.raises(ContractError):
        decode_rows(_body([extended_row('HTMLCanvasElement.toDataURL',value)]),limit=1)
    value['byte_length']=6144
    assert decode_rows(_body([extended_row('HTMLCanvasElement.toDataURL',value)]),limit=1)[0][0]['result']==value

def test_new_calls_observe_only_their_bounded_parameters():
    row=extended_row('CanvasRenderingContext2D.getImageData',{'type':'object','omitted':'no-object-inspection'})
    parameters={'count':8,'observed':[{'type':'number','value':n} for n in range(4)]}
    row['parameters_json']=json.dumps(parameters).encode().hex()
    assert len(decode_rows(_body([row]),limit=1)[0][0]['parameters']['observed'])==4
    parameters['observed'].append({'type':'number','value':5});row['parameters_json']=json.dumps(parameters).encode().hex()
    with pytest.raises(ContractError):decode_rows(_body([row]),limit=1)

def test_legacy_schema_remains_closed_and_session_versions_are_paired():
    assert APIS_V1<APIS_V2
    document={'schema':'browser-core.session/1','run_id':'coverage-test','chromium_revision':'a'*40,'pid':123,'trace_mode':'on','trace_path':'/owned/trace','automation':{'transport':'cdp','cdp_endpoint':'http://127.0.0.1:9222'},'value_capture':CAPTURE_V2}
    assert validate_session(document)['value_capture']==CAPTURE_V2
    document['value_capture']={**CAPTURE_V2,'schema':CAPTURE_V1['schema']}
    with pytest.raises(ContractError):validate_session(document)


def test_legacy_native_mode_remains_explicitly_selectable(tmp_path):
    from browser_core.launcher import evaluation_command,EvaluationLaunch,validate_evaluation_launch
    args=(tmp_path/'chrome.exe',tmp_path/'profile',tmp_path/'trace','version-test')
    command=evaluation_command(*args,headless=True,extra_args=(),inspect_values=True,inspection_allowlist='fingerprint-v1')
    assert '--browser-core-inspect-values=fingerprint-v1' in command
    with pytest.raises(ContractError):
        validate_evaluation_launch(EvaluationLaunch(tmp_path/'chrome.exe',tmp_path,inspection_allowlist='arbitrary'))


def image_row():
    return extended_row('CanvasRenderingContext2D.getImageData',{'type':'ImageData','width':2,'height':2,
        'data':{'type':'Uint8ClampedArray','length':16,'values':[{'type':'number','value':255}]*16}})


def test_native_image_result_keeps_bounded_pixels_with_dimensions():
    result=decode_rows(_body([image_row()]),limit=1)[0][0]['result']
    assert result['width']==2 and result['height']==2 and len(result['data']['values'])==16


@pytest.mark.parametrize('fault',['width','height','nested','extra','unrelated_api','old_version','wrong_length'])
def test_image_result_rejects_inconsistent_or_unrelated_content(fault):
    row=image_row();value=json.loads(bytes.fromhex(row['result_json']))
    if fault in ('width','height'):value[fault]=0
    elif fault=='nested':value['data']=dict(value)
    elif fault=='extra':value['extra']='unrelated'
    elif fault=='unrelated_api':row['api']='Navigator.hardwareConcurrency.get'
    elif fault=='old_version':row.update(CAPTURE_V1)
    elif fault=='wrong_length':value['width']=3
    row['result_json']=json.dumps(value).encode().hex()
    with pytest.raises(ContractError):decode_rows(_body([row]),limit=1)
