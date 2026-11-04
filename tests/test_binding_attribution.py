"""The same compiled script in different realms must not alias call identity."""
import csv
import io
import json

import pytest

from browser_core.contracts import ContractError
from browser_core.perfetto import EXPORT_COLUMNS, NULL_VALUE, parse_export_csv
from browser_core.inspection_context import LIMITED_CONTEXT_SCHEMA


def normalize(rows):
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=EXPORT_COLUMNS)
    writer.writeheader()
    for index, row in enumerate(rows):
        writer.writerow({**dict.fromkeys(EXPORT_COLUMNS, NULL_VALUE),
                         'ts_monotonic_ns': str(100 + index), 'pid': '42',
                         'tid': '43', 'process_name': 'Renderer',
                         'thread_name': 'CrRendererMain', **row})
    return parse_export_csv(output.getvalue(), 'owned-test', 'a' * 40)


def anchor(context):
    return {'trace_category': 'browser_core.debug', 'native_schema': 'browser-core.native/1',
            'native_name': 'BrowserCore.ScriptRun', 'event_category': 'execution',
            'event_name': 'script.run', 'component': 'blink.v8', 'context_id': context,
            'context_kind': 'frame', 'script_id': '4', 'native_id': f'script:{context}:4'}


def binding(**values):
    return {'trace_category': 'blink.bindings', 'native_name': 'Navigator.language.get',
            'duration_ns': '92000', 'script_id': '4', **values}


def test_reused_script_without_call_context_stays_unresolved():
    events = normalize([anchor('top'), anchor('frame'), binding()])
    assert events[-1]['execution']['context_id'] == 'bindings:42:43'
    assert events[-1]['detail']['context_attribution'] == 'unresolved'


@pytest.mark.parametrize(('kind', 'key'), [('window', 'frame_id'), ('worker', 'worker_id'), ('other', None)])
def test_direct_value_owner_wins_without_inventing_caller_identity(kind, key):
    event = normalize([anchor('top'), anchor('frame'), binding(
        binding_value_count='1', binding_value_slice_id='6413',
        binding_value_context_id='top', binding_value_context_kind=kind)])[-1]
    assert event['execution']['context_id'] == 'top'
    assert 'script_id' not in event['execution']
    assert event['detail']['script_number'] == 4
    assert event['detail']['binding_value_slice_id'] == 6413
    assert event['detail']['context_attribution'] == 'native-binding-owner'
    if key:
        assert event['execution'][key] == 'top'


def test_multiple_direct_values_are_explicitly_ambiguous():
    event = normalize([binding(binding_value_count='2', binding_value_slice_id='1',
                               binding_value_context_id='top', binding_value_context_kind='window')])[0]
    assert event['execution']['context_id'] == 'bindings:42:43'
    assert event['detail']['context_attribution'] == 'ambiguous-native-binding-owner'
    assert event['detail']['binding_value_count'] == 2


def test_limited_native_context_cannot_be_promoted_to_complete_owner_metadata():
    context = 'A' * 32
    metadata = {'schema':LIMITED_CONTEXT_SCHEMA, 'context_id':context, 'v8_context_id':'B'*32,
                'context_kind':'window', 'realm_id':0, 'unavailable':'invalid-script-context'}
    event = normalize([binding(binding_value_count='1', binding_value_slice_id='12',
        binding_value_context_id=context, binding_value_context_kind='window',
        binding_value_realm_id='0', binding_value_context_metadata=json.dumps(metadata).encode().hex())])[0]
    assert event['detail']['context_attribution'] == 'native-binding-owner-limited'
    assert event['detail']['context_unavailable'] == 'invalid-script-context'
    assert event['execution'] == {'context_id':context}


@pytest.mark.parametrize('overrides', [
    {'binding_value_context_id': NULL_VALUE}, {'binding_value_context_kind': 'invalid'},
    {'binding_value_slice_id': '-1'}, {'binding_value_count': '0'},
])
def test_malformed_direct_owner_metadata_is_rejected(overrides):
    fields = dict(binding_value_count='1', binding_value_slice_id='1',
                  binding_value_context_id='top', binding_value_context_kind='window')
    fields.update(overrides)
    with pytest.raises(ContractError):
        normalize([binding(**fields)])


def test_explicit_causal_parent_survives_a_later_run_of_same_script_in_other_realm():
    fetch = {'trace_category': 'browser_core.debug', 'native_schema': 'browser-core.native/1',
             'native_name': 'BrowserCore.FetchCall', 'event_category': 'api', 'event_name': 'fetch',
             'component': 'blink.fetch', 'context_id': 'top', 'context_kind': 'frame',
             'script_id': '4', 'native_id': 'fetch-api:top:1', 'native_parent_id': 'script:top:4'}
    event = normalize([anchor('top'), anchor('frame'), fetch])[-1]
    assert event['causal_parent_seq'] == 0
    assert event['execution']['context_id'] == 'top'


def stack_columns(**overrides):
    return {'stack_context_schema':'browser-core.js-stack/1', 'stack_context_status':'observed',
            'stack_v8_context_id':'B'*32, 'stack_realm_id':'0',
            'stack_root_script_id':'3', **overrides}


def test_direct_js_frame_remains_separate_from_borrowed_api_owner_and_eval_script():
    event = normalize([anchor('top'), anchor('other'), binding(
        binding_value_count='1', binding_value_slice_id='14',
        binding_value_context_id='owner', binding_value_context_kind='window',
        **stack_columns())])[-1]
    assert event['execution'] == {'context_id':'owner', 'frame_id':'owner'}
    assert event['detail']['script_number'] == 4
    assert event['detail']['js_stack'] == {
        'schema':'browser-core.js-stack/1', 'status':'observed', 'v8_context_id':'B'*32,
        'realm_id':0, 'root_script_number':3}
    assert 'causal_parent_seq' not in event


def test_direct_js_frame_is_retained_without_a_selected_binding_value():
    events = normalize([binding(**stack_columns()), binding(**stack_columns(stack_v8_context_id='C'*32))])
    assert all(e['detail']['context_attribution'] == 'unresolved' for e in events)
    assert [e['detail']['js_stack']['v8_context_id'] for e in events] == ['B'*32, 'C'*32]
    assert all('causal_parent_seq' not in e for e in events)


def test_disposed_stack_context_keeps_its_explicit_limit():
    event = normalize([binding(**stack_columns(stack_context_status='limited-context'))])[0]
    assert event['detail']['js_stack']['status'] == 'limited-context'
    assert event['detail']['context_attribution'] == 'unresolved'


@pytest.mark.parametrize('status', ['no-isolate','no-visible-js-frame','non-blink-context'])
def test_unavailable_stack_has_no_invented_identity(status):
    event = normalize([binding(stack_context_schema='browser-core.js-stack/1', stack_context_status=status)])[0]
    assert event['detail']['js_stack'] == {'schema':'browser-core.js-stack/1','status':status}


@pytest.mark.parametrize('change', [
    {'stack_context_schema':'unknown'}, {'stack_context_schema':NULL_VALUE},
    {'stack_context_status':'guessed'}, {'stack_context_status':'no-visible-js-frame'},
    {'stack_v8_context_id':'0'*32}, {'stack_v8_context_id':'b'*32},
    {'stack_v8_context_id':NULL_VALUE}, {'stack_realm_id':'-1'},
    {'stack_realm_id':'01'}, {'stack_root_script_id':'0'},
    {'stack_root_script_id':'2147483648'}, {'stack_root_script_id':NULL_VALUE},
])
def test_malformed_native_js_frame_cannot_turn_into_attribution(change):
    with pytest.raises(ContractError, match='JavaScript stack'):
        normalize([binding(**stack_columns(**change))])


def test_generated_stack_metadata_cannot_be_attached_to_script_run():
    with pytest.raises(ContractError, match='unrelated native event'):
        normalize([{**anchor('top'), **stack_columns()}])
