import copy
import csv
import io
import json

import pytest

from browser_core.contracts import ContractError
from browser_core.inspection import decode_rows, inspection_select
from browser_core.inspection_attribution import ContextAttribution
from browser_core.inspection_context import CONTEXT_SCHEMA, decode_context, view_summary
from test_inspection import _row, _body


def native(kind='page'):
    value = {'schema': CONTEXT_SCHEMA, 'context_id': 'AB'*16,
             'v8_context_id': 'BC'*16, 'realm_id': 0, 'kind': kind,
             'document_id': 'CD'*16, 'frame_id': 'DE'*16,
             'parent_frame_id': None, 'worker_id': None, 'parent_context_id': None,
             'document_url': {'status': 'native-context-url',
                              'display': 'https://example.test/exercise',
                              'url_sha256': 'a'*64, 'not_fetch_provenance': True}}
    if kind == 'frame':
        value['parent_frame_id'] = 'EF'*16
    elif kind == 'detached-window':
        value['frame_id'] = None
    elif kind.endswith('worker'):
        value.update(document_id=None, frame_id=None, worker_id=value['context_id'])
        if kind == 'dedicated-worker':
            value['parent_context_id'] = 'EF'*16
    elif kind == 'other':
        value.update(document_id=None, frame_id=None)
    return value


def encoded(value):
    return json.dumps(value).encode().hex()


def decode(value):
    kind = value.get('kind')
    context_kind = 'worker' if isinstance(kind, str) and kind.endswith('worker') else 'other' if kind == 'other' else 'window'
    return decode_context(encoded(value), context_id='AB'*16, realm_id=0, context_kind=context_kind)


def with_context(rows):
    stream = io.StringIO()
    writer = csv.DictWriter(stream, fieldnames=[*list(_row()), 'context_metadata_json'])
    writer.writeheader()
    writer.writerows(rows)
    return stream.getvalue().encode()


@pytest.mark.parametrize('kind', ['page', 'frame', 'detached-window', 'dedicated-worker',
                                   'shared-worker', 'service-worker', 'worker', 'other'])
def test_native_context_kinds_have_separate_frame_document_and_realm_identities(kind):
    value = native(kind)
    assert decode(value) == value


def test_legacy_rows_remain_readable_without_invented_ownership():
    row = _row()
    assert 'native_context' not in decode_rows(_body([row]), limit=1)[0][0]
    row['context_metadata_json'] = ''
    assert 'native_context' not in decode_rows(with_context([row]), limit=1)[0][0]
    assert 'context_metadata_json' in inspection_select()
    assert 'context_metadata_json' in inspection_select(incremental=True)


@pytest.mark.parametrize('change', [
    {'schema': 'browser-core.inspection-context/2'}, {'context_id': 'FF'*16},
    {'v8_context_id': '0'*32}, {'v8_context_id': '1'}, {'realm_id': True},
    {'realm_id': 1}, {'frame_id': None}, {'kind': 'frame'},
    {'parent_context_id': 'EF'*16}, {'worker_id': 'AB'*16},
    {'cookie': 'not allowed'}, {'document_id': []}, {'schema': []},
])
def test_native_identity_metadata_rejects_unknown_or_incoherent_claims(change):
    value = native()
    value.update(change)
    with pytest.raises(ContractError):
        decode(value)


@pytest.mark.parametrize('display', [
    'https://name:credential@example.test/path', 'https://example.test/?private=value',
    'https://example.test/#private', 'data:text/plain,private', 'file:///private/path',
    'javascript:alert(1)', 'https://example.test/\nignored', 'https://example.test:99999/',
    'x'*513, '<img src=x onerror=alert(1)>',
])
def test_native_url_labels_cannot_carry_credentials_query_fragment_or_opaque_source(display):
    value = native()
    value['document_url']['display'] = display
    with pytest.raises(ContractError):
        decode(value)


@pytest.mark.parametrize('url', [
    {'status': 'unavailable', 'reason': 'length-limit', 'not_fetch_provenance': True},
    {'status': 'native-context-url', 'display': '[non-HTTP URL omitted]',
     'url_sha256': 'a'*64, 'not_fetch_provenance': True},
    {'status': 'native-context-url', 'display': 'about:srcdoc',
     'url_sha256': 'a'*64, 'not_fetch_provenance': True},
])
def test_native_url_omissions_stay_explicit(url):
    value = native()
    value['document_url'] = url
    assert decode(value)['document_url'] == url


@pytest.mark.parametrize('wire', ['00', '7b', '6e756c6c', ' ' * 10, 'aa' * 8193,
                                  b'00', encoded({'schema': CONTEXT_SCHEMA})])
def test_native_context_transport_is_bounded_and_strict(wire):
    with pytest.raises(ContractError):
        decode_context(wire, context_id='AB'*16, realm_id=0, context_kind='window')


def test_duplicate_metadata_keys_are_not_accepted():
    text = json.dumps(native()).replace('{', '{"realm_id": 0,', 1)
    with pytest.raises(ContractError):
        decode_context(text.encode().hex(), context_id='AB'*16, realm_id=0, context_kind='window')


def test_passive_metadata_survives_value_decode_and_overrides_stale_probe_mapping():
    row = _row()
    row['context_metadata_json'] = encoded(native())
    events, total = decode_rows(with_context([row]), limit=1)
    state = ContextAttribution()
    state.matches[(123, 'AB'*16)] = {'metadata': {'kind': 'frame'},
                                    'sources': {'42': {'display': 'stale source'}}}
    state.conflicts.add((123, 'AB'*16))
    result = {'events': events}
    state.enrich(result)
    assert total == 1
    assert result['events'][0]['attribution']['status'] == 'native-observed'
    assert result['events'][0]['attribution']['kind'] == 'page'
    assert result['events'][0]['attribution']['source']['status'] == 'unresolved'
    assert result['native_attribution']['binding_realms_in_view'] == 1
    assert result['native_attribution']['passive'] is True
    assert state.attempts == 0


def test_navigation_and_isolated_worlds_never_share_document_or_realm_labels():
    events = []
    for index, (realm, document, world) in enumerate([
        ('BC'*16, 'CD'*16, 0), ('CC'*16, 'CD'*16, 1), ('DC'*16, 'DD'*16, 0),
    ]):
        context = native()
        context.update(v8_context_id=realm, document_id=document, realm_id=world)
        row = _row()
        row.update(id=str(index), realm_id=str(world), total_events='3',
                   context_metadata_json=encoded(context))
        events.append(row)
    events, _ = decode_rows(with_context(events), limit=3)
    result = {'events': events}
    ContextAttribution().enrich(result)
    assert result['native_attribution']['binding_realms_in_view'] == 3
    assert result['native_attribution']['documents_in_view'] == 2
    assert len({e['attribution']['v8_context_id'] for e in events}) == 3
    assert len({e['attribution']['frame_id'] for e in events}) == 1


def test_document_count_keeps_separate_process_namespaces():
    context = native()
    summary = view_summary([
        {'pid': 123, 'native_context': context},
        {'pid': 456, 'native_context': copy.deepcopy(context)},
    ])
    assert summary['binding_realms_in_view'] == 2
    assert summary['documents_in_view'] == 2


def test_new_document_with_reused_script_number_is_not_an_old_analyst_probe():
    state = ContextAttribution()
    state.probes = [{'probe_script_id': 42}]
    state.probe_identities[0].add((123, 'AB'*16))
    state.probe_realms[0].add((123, 'AA'*16, 42))
    row = _row()
    row['context_metadata_json'] = encoded(native())
    events, _ = decode_rows(with_context([row]), limit=1)
    result = {'events': events}
    state.enrich(result)
    assert 'observation_role' not in events[0]
    state.probe_realms[0].add((123, 'BC'*16, 42))
    state.enrich(result)
    assert events[0]['observation_role'] == 'context-identification-probe'
