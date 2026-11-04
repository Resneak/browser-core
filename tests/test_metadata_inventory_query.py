"""Inventory-only discovery, bounded failures, and pinned legacy wire bytes."""
from copy import deepcopy
import hashlib
import io
import json
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace

import jsonschema
import pytest

from browser_core import cli, metadata_inventory as inventory_model
from browser_core import metadata_inventory_query as inventory, metadata_query as query
from browser_core.contracts import ContractError
from browser_core.control_files import canonical_json_bytes
from browser_core.evidence_bundle import EvidenceExport
from browser_core.inspection_attribution import ContextAttribution
from browser_core.inspection_contract import CAPTURE_OFF, CAPTURE_V1, CAPTURE_V2, CAPTURE_V3
from browser_core.inspection_history import history_filters
from test_metadata_workflow import source, events, invalid_population

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = json.loads((ROOT / 'schemas/metadata-inventory-query-v1.schema.json').read_text())
jsonschema.Draft202012Validator.check_schema(SCHEMA)
VALIDATOR = jsonschema.Draft202012Validator(SCHEMA)


def rendered(result):
    return json.dumps(result, sort_keys=True, indent=2, ensure_ascii=True, allow_nan=False).encode('ascii')


def test_inventory_retains_exact_population_identity_and_no_rows(source, events):
    result = inventory.metadata_inventory_query(source, analyst_activity=['browser-control'])
    VALIDATOR.validate(result)
    assert 'events' not in result
    assert result['query']['matching_events'] == '7'
    assert result['query']['returned_events'] == 0
    assert 'requested_limit' not in result['query'] and 'next_cursor' not in result['query']
    assert result['inventory']['contexts']['groups'][0]['events'] == '7'
    assert result['inventory']['analyst_instrumentation']['event_ownership'] == 'unresolved'
    assert result['reader_runtime'] == source.resolve().reader_runtime
    assert result['producer_chromium_revision'] == source.resolve().session['chromium_revision']
    assert result['run_id'] == 'owned-run'
    assert result['snapshot']['sha256'] == hashlib.sha256(source.resolve().path.read_bytes()).hexdigest()
    assert result['snapshot']['source_phase'] == 'finalized-recording'
    assert result['recording_health']['proves_complete'] is False
    assert result['semantics']['full_snapshot_decode'] is True
    assert result['semantics']['population_validated_before_filtering'] is True
    assert result['semantics']['query_launched_browser'] is False
    assert result['output']['rendered_json_bytes'] == len(rendered(result)) <= 16384
    assert result['output']['transport_delivery_verified'] is False
    assert result['output']['transport_truncated'] is None
    altered = deepcopy(result)
    altered['events'] = []
    with pytest.raises(jsonschema.ValidationError): VALIDATOR.validate(altered)
    for version in (1, 2):
        legacy = json.loads((ROOT / f'schemas/metadata-query-v{version}.schema.json').read_text())
        with pytest.raises(jsonschema.ValidationError): jsonschema.validate(result, legacy)


def test_inventory_filters_enable_exact_subsequent_event_query(source, events):
    result = inventory.metadata_inventory_query(source)
    context = result['inventory']['contexts']['groups'][0]
    api = context['apis']['groups'][0]['api']
    selector = {key: context[key] for key in ('pid', 'context_id')}
    selected = inventory.metadata_inventory_query(source, portable_context=selector,
        apis=[api], script_id='7', context_kind='window', start_ns='102', end_ns='104')
    page = query.metadata_query(source, filters=history_filters(apis=[api], script='7',
        context='window', start_ns='102', end_ns='104'), portable_context=selector, limit=25)
    assert selected['query']['matching_events'] == page['query']['matching_events'] == '3'
    assert [event['seq'] for event in page['events']] == [4, 3, 2]
    assert selected['query']['query_sha256'] != result['query']['query_sha256']
    assert selected['query']['query_sha256'] != page['query']['query_sha256']
    empty = inventory.metadata_inventory_query(source, apis=['Unknown.event'])
    assert empty['query']['matching_events'] == '0'
    assert empty['inventory']['contexts']['groups'] == []
    assert empty['output']['summaries_truncated'] is False


def test_real_bundle_opening_retains_digest_and_leaves_original_unchanged(source, events):
    export = EvidenceExport()
    try:
        prepared = export.prepare(source, ContextAttribution(), None)
        before = export.path.read_bytes()
        result = inventory.evidence_inventory(export.path, ROOT, source.resolve().executable,
            expected_sha256=prepared['sha256'])
        VALIDATOR.validate(result)
        assert result['bundle']['sha256'] == prepared['sha256']
        assert result['bundle']['expected_digest_matched'] is True
        assert result['query']['matching_events'] == '7'
        assert result['source_recording']['run_id'] == result['run_id']
        assert result['source_recording']['sha256'] == result['snapshot']['sha256']
        assert export.path.read_bytes() == before
        with pytest.raises(ContractError):
            inventory.evidence_inventory(export.path, ROOT, source.resolve().executable,
                expected_sha256='f'*64)
        assert export.path.read_bytes() == before
    finally:
        export.close()


def test_evidence_inventory_rechecks_copy_after_origin_output_binding(source,events,monkeypatch):
    export=EvidenceExport()
    try:
        prepared=export.prepare(source,ContextAttribution(),None)
        original_open=inventory.OpenEvidence
        opened=[]
        def open_bundle(*args,**kwargs):
            bundle=original_open(*args,**kwargs)
            opened.append(bundle)
            return bundle
        original_bound=inventory._bound_inventory_output
        def bind_then_change(result):
            bounded=original_bound(result)
            if 'source_recording' in result:
                opened[0].path.write_bytes(b'\x0a\x01y')
            return bounded
        monkeypatch.setattr(inventory,'OpenEvidence',open_bundle)
        monkeypatch.setattr(inventory,'_bound_inventory_output',bind_then_change)
        with pytest.raises(ContractError,match='verified evidence recording copy changed'):
            inventory.evidence_inventory(export.path,ROOT,source.resolve().executable,
                expected_sha256=prepared['sha256'])
    finally:
        export.close()


@pytest.mark.parametrize('phase', ['live-prefix','recovered-prefix','interrupted-recording','limited-recording'])
def test_original_bundle_recording_and_reopened_copy_are_separately_retained(source, events, phase):
    location = source.resolve()
    location.phase = phase
    location.path.write_bytes(location.path.read_bytes() + b'\x0a\x05abc')
    original_bytes = location.path.read_bytes()
    export = EvidenceExport()
    try:
        prepared = export.prepare(source, ContextAttribution(), None)
        bundle_bytes = export.path.read_bytes()
        result = inventory.evidence_inventory(export.path, ROOT, location.executable,
            expected_sha256=prepared['sha256'])
        VALIDATOR.validate(result)
        origin = result['source_recording']
        assert origin == {'run_id':'owned-run','sha256':prepared['recording_sha256'],
            'bytes':'3','packets':'1','source_bytes':'8','excluded_tail_bytes':'5','source_phase':phase}
        assert result['snapshot'] == {'sha256':origin['sha256'],'bytes':'3','packets':'1',
            'source_bytes':'3','excluded_tail_bytes':'0','source_phase':'finalized-recording'}
        assert result['bundle']['sha256'] == prepared['sha256']
        assert result['output']['rendered_json_bytes'] == len(rendered(result)) <= 16384
        assert location.path.read_bytes() == original_bytes and export.path.read_bytes() == bundle_bytes
        altered = deepcopy(result)
        altered['source_recording']['extra_private_value'] = 'sentinel'
        with pytest.raises(jsonschema.ValidationError): VALIDATOR.validate(altered)
        altered = deepcopy(result)
        del altered['bundle']
        with pytest.raises(jsonschema.ValidationError): VALIDATOR.validate(altered)
    finally:
        export.close()


@pytest.mark.parametrize('key,bad', [('run_id','other-run'), ('sha256','f'*64),
    ('bytes',4), ('packets',2), ('source_bytes',4), ('excluded_tail_bytes',1),
    ('source_phase',None), ('source_phase',[]), ('source_phase','unknown'),
    ('bytes',True), ('packets','1'), ('source_bytes',-1), ('excluded_tail_bytes',2**63)])
def test_bundle_origin_mismatch_fails_closed_and_closes_copy(source, events, monkeypatch, tmp_path, key, bad):
    recording = {'run_id':'owned-run','sha256':hashlib.sha256(source.resolve().path.read_bytes()).hexdigest(),
        'bytes':3,'packets':1,'source_bytes':3,'excluded_tail_bytes':0,'source_phase':'finalized-recording'}
    recording[key] = bad
    closed = []
    monkeypatch.setattr(inventory, 'OpenEvidence', lambda *a, **kw:SimpleNamespace(
        metadata={'capture':CAPTURE_OFF,'recording':recording}, source=source,
        sha256='a'*64, close=lambda:closed.append(True)))
    with pytest.raises(ContractError, match='source recording binding is invalid'):
        inventory.evidence_inventory(tmp_path/'bundle', ROOT, tmp_path/'chrome.exe')
    assert closed == [True]


def test_origin_is_counted_before_final_byte_pruning(source, events, monkeypatch):
    source.resolve().phase = 'live-prefix'
    source.resolve().path.write_bytes(source.resolve().path.read_bytes() + b'\x0a\x05abc')
    export = EvidenceExport()
    try:
        prepared = export.prepare(source, ContextAttribution(), None)
        full = inventory.evidence_inventory(export.path, ROOT, source.resolve().executable)
        assert not full['output']['byte_limit_applied']
        # Initial source-only result fits, but adding origin now requires pruning.
        monkeypatch.setattr(inventory, 'MAX_INVENTORY_OUTPUT_BYTES', len(rendered(full))-16)
        bounded = inventory.evidence_inventory(export.path, ROOT, source.resolve().executable)
        assert bounded['source_recording'] == full['source_recording']
        assert bounded['bundle']['sha256'] == prepared['sha256']
        assert bounded['output']['byte_limit_applied'] and bounded['output']['summaries_truncated']
        assert bounded['output']['rendered_json_bytes'] == len(rendered(bounded)) <= inventory.MAX_INVENTORY_OUTPUT_BYTES
        assert bounded['query']['matching_events'] == '7'
    finally:
        export.close()


@pytest.mark.parametrize('parent', ['callback', 'promise'])
def test_inventory_rejects_invalid_unselected_population(source, invalid_population, parent):
    invalid_population(parent)
    with pytest.raises(ContractError, match='parent scope is inconsistent'):
        inventory.metadata_inventory_query(source, apis=['Unknown.event'],
            portable_context={'pid':'999', 'context_id':'absent'})


@pytest.mark.parametrize('apis', [(), ('Unknown.event',)])
def test_inventory_rejects_malformed_context_identity_before_filtering(source, events, apis):
    events[0]['execution'] = {'context_id': []}
    with pytest.raises(ContractError, match='identity is invalid'):
        inventory.metadata_inventory_query(source, apis=apis)


def test_inventory_accepts_nullable_optional_execution_ids(source, events):
    events[0]['execution']['worker_id'] = None
    events[0]['execution']['script_id'] = None

    result = inventory.metadata_inventory_query(source)
    VALIDATOR.validate(result)
    assert result['query']['matching_events'] == '7'
    assert result['inventory']['contexts']['groups'][0]['worker_id'] == ''
    assert inventory.metadata_inventory_query(source, script_id='7')['query']['matching_events'] == '6'


@pytest.mark.parametrize('capture', [CAPTURE_V1, CAPTURE_V2, CAPTURE_V3])
@pytest.mark.parametrize('route', ['metadata', 'session', 'evidence'])
def test_private_capture_is_rejected_before_any_decoder(source, monkeypatch, tmp_path, capture, route):
    source.resolve().session['value_capture'] = capture
    def forbidden(*args, **kwargs): pytest.fail('private recording reached the decoder')
    monkeypatch.setattr(query, '_query', forbidden)
    monkeypatch.setattr(query, 'export_perfetto', forbidden)
    closed = []
    monkeypatch.setattr(inventory, 'RecordingSource', lambda *a, **kw:source)
    monkeypatch.setattr(inventory, 'OpenEvidence', lambda *a, **kw:SimpleNamespace(
        metadata={'capture':capture}, source=source, close=lambda:closed.append(True)))
    with pytest.raises(ContractError, match='value-free capture'):
        if route == 'metadata': inventory.metadata_inventory_query(source)
        elif route == 'session': inventory.session_inventory(tmp_path/'owned-run.json', ROOT, expected_run_id='owned-run')
        else: inventory.evidence_inventory(tmp_path/'bundle', ROOT, tmp_path/'chrome.exe')
    assert closed == ([True] if route == 'evidence' else [])


def test_private_records_in_off_capture_fail_before_export(source, monkeypatch):
    monkeypatch.setattr(query, '_query', lambda *a, **kw:b'private_records\n1\n')
    monkeypatch.setattr(query, 'export_perfetto', lambda *a, **kw:pytest.fail('exported private capture'))
    with pytest.raises(query.MetadataQueryError, match='metadata-recording-contains-values'):
        inventory.metadata_inventory_query(source)


@pytest.mark.parametrize('body', [b'', b'private_records\nunknown-secret\n', b'private_records\n0\n1\n'])
def test_inventory_never_converts_missing_private_count_to_zero(source, monkeypatch, body):
    monkeypatch.setattr(query, '_query', lambda *a, **kw:body)
    with pytest.raises(ContractError, match='value-count unavailable'):
        inventory.metadata_inventory_query(source)


BAD_OPTIONS = [
    *({'inventory_version':v} for v in (None, True, False, 1.0, '1', 0, 2, [], {})),
    *({'portable_context':v} for v in ({}, [], True, {'pid':'10'}, {'pid':10,'context_id':'A'},
        {'pid':'01','context_id':'A'}, {'pid':'9223372036854775808','context_id':'A'},
        {'pid':'10','context_id':'A\nsecret'}, {'pid':'10','context_id':'\ud800'},
        {'pid':'10','context_id':'é'*129}, {'pid':'10','context_id':'A','extra':'secret'})),
    *({'analyst_activity':v} for v in (None, True, {}, ['secret'], ['browser-control']*2)),
    *({'apis':v} for v in (None, True, {}, ['secret space'], ['A']*2, ['A']*33)),
    {'script_id':True}, {'script_id':'1 OR secret'}, {'context_kind':[]}, {'context_kind':'secret'},
    {'start_ns':True}, {'start_ns':'01'}, {'start_ns':{}}, {'end_ns':-1},
    {'start_ns':'2', 'end_ns':'1'},
]


@pytest.mark.parametrize('options', BAD_OPTIONS)
@pytest.mark.parametrize('route', ['metadata', 'session', 'evidence'])
def test_malformed_arguments_reject_before_source_access(monkeypatch, tmp_path, options, route):
    def forbidden(*args, **kwargs): pytest.fail('invalid options accessed a source')
    monkeypatch.setattr(inventory, 'RecordingSource', forbidden)
    monkeypatch.setattr(inventory, 'OpenEvidence', forbidden)
    with pytest.raises(ContractError):
        if route == 'metadata': inventory.metadata_inventory_query(SimpleNamespace(resolve=forbidden), **options)
        elif route == 'session': inventory.session_inventory(tmp_path/'owned-run.json', ROOT, expected_run_id='owned-run', **options)
        else: inventory.evidence_inventory(tmp_path/'bundle', ROOT, tmp_path/'chrome.exe', **options)


@pytest.mark.parametrize('options', [dict(limit=0), dict(limit=1), dict(cursor='secret'),
    dict(include_values=True), dict(scope={}), dict(metadata_version=2), dict(filters={})])
@pytest.mark.parametrize('route', ['metadata', 'session', 'evidence'])
def test_new_inventory_contract_does_not_silently_accept_query_options(options, route):
    with pytest.raises(TypeError):
        if route == 'metadata': inventory.metadata_inventory_query(None, **options)
        elif route == 'session': inventory.session_inventory(None, None, expected_run_id=None, **options)
        else: inventory.evidence_inventory(None, None, None, **options)


def test_binding_arguments_reject_without_io(monkeypatch, tmp_path):
    def forbidden(*args, **kwargs): pytest.fail('invalid binding accessed a source')
    source = SimpleNamespace(resolve=forbidden)
    monkeypatch.setattr(inventory, 'RecordingSource', forbidden)
    monkeypatch.setattr(inventory, 'OpenEvidence', forbidden)
    for bad in ([], {}, True, '', 'secret/path'):
        with pytest.raises(ContractError): inventory.metadata_inventory_query(source, expected_run_id=bad)
        with pytest.raises(ContractError): inventory.metadata_inventory_query(source, bundle_sha256=bad)
        with pytest.raises(ContractError): inventory.evidence_inventory(tmp_path/'bundle', ROOT, tmp_path/'chrome.exe', expected_sha256=bad)
    for bad in (True, 1, 'secret', None):
        with pytest.raises(ContractError): inventory.metadata_inventory_query(source, expected_digest_matched=bad)
    for bad in (None, 'secret', Path('relative')):
        with pytest.raises(ContractError): inventory.session_inventory(bad, ROOT, expected_run_id='owned-run')
        with pytest.raises(ContractError): inventory.evidence_inventory(tmp_path/'bundle', ROOT, bad)
    with pytest.raises(ContractError): inventory.session_inventory(tmp_path/'other.json', ROOT, expected_run_id='owned-run')
    for bad in (None, {}, [], True):
        with pytest.raises(ContractError): inventory.metadata_inventory_query(bad)


def test_group_counts_and_byte_cap_are_exact_without_slicing_identifiers(source, events, monkeypatch):
    template = deepcopy(events[0])
    events.clear()
    for i in range(21):
        for j in range(12):
            event = deepcopy(template)
            event['seq'] = len(events)
            event['ts_monotonic_ns'] = 100 + len(events)
            context = f'{i:02d}' + 'é'*100
            event['execution'] = {'context_id':context, 'frame_id':context}
            event['event']['name'] = f'API{j:02d}.' + 'x'*200
            events.append(event)
    result = inventory.metadata_inventory_query(source)
    VALIDATOR.validate(result)
    assert result['query']['matching_events'] == '252'
    assert result['inventory']['context_kind_counts'] == {'window':'252','worker':'0','other':'0'}
    assert result['inventory']['contexts']['total_groups'] == 21
    assert result['inventory']['apis']['total_groups'] == 12
    assert result['output']['byte_limit_applied'] is True
    assert result['output']['summaries_truncated'] is True
    assert result['output']['rendered_json_bytes'] == len(rendered(result)) <= 16384
    for group in (result['inventory']['contexts'], result['inventory']['apis']):
        assert group['reported_groups'] == len(group['groups'])
        assert group['truncated'] == (len(group['groups']) < group['total_groups'])
    for row in result['inventory']['contexts']['groups']:
        assert len(row['context_id']) == 102 and row['events'] == '12'
        assert row['apis']['total_groups'] == 12
        assert row['apis']['reported_groups'] == len(row['apis']['groups']) <= 8
        assert row['apis']['truncated']
    monkeypatch.setattr(inventory, 'MAX_INVENTORY_OUTPUT_BYTES', 1)
    with pytest.raises(ContractError, match='output limit'): inventory.metadata_inventory_query(source)


def test_group_cap_truncation_is_distinct_from_byte_limit(source, events):
    template = deepcopy(events[0])
    events.clear()
    for i in range(20):
        event = deepcopy(template)
        event['seq'] = i
        event['ts_monotonic_ns'] = 100 + i
        event['event']['name'] = f'API{i:02d}.get'
        events.append(event)
    result = inventory.metadata_inventory_query(source)
    assert result['inventory']['apis']['total_groups'] == 20
    assert result['inventory']['apis']['reported_groups'] == 16
    assert result['inventory']['contexts']['groups'][0]['apis']['reported_groups'] == 8
    assert result['output']['summaries_truncated'] is True
    assert result['output']['byte_limit_applied'] is False
    assert result['query']['matching_events'] == '20'


@pytest.mark.parametrize('dimension,groups', [
    ('contexts', [('A', 'API0'), ('B', 'API0'), ('C', 'API0')]),
    ('apis', [('A', 'API0'), ('A', 'API1'), ('A', 'API2')]),
    ('context_apis', [('A', 'API0'), ('A', 'API1'), ('B', 'API0')]),
])
def test_inventory_rejects_unbounded_distinct_groups(source, events, monkeypatch, dimension, groups):
    maximum = {'contexts': 'MAX_INVENTORY_CONTEXT_GROUPS',
               'apis': 'MAX_INVENTORY_API_GROUPS',
               'context_apis': 'MAX_INVENTORY_CONTEXT_API_GROUPS'}[dimension]
    monkeypatch.setattr(inventory_model, maximum, 2, raising=False)
    template = deepcopy(events[0])
    events.clear()
    for index, (context, api) in enumerate(groups):
        event = deepcopy(template)
        event['seq'] = index
        event['ts_monotonic_ns'] = 100 + index
        event['execution']['context_id'] = context
        event['execution']['frame_id'] = context
        event['event']['name'] = api
        events.append(event)
    with pytest.raises(ContractError, match=f'inventory {dimension} limit'):
        inventory.metadata_inventory_query(source)


@pytest.mark.parametrize('field', ['context_id', 'api'])
@pytest.mark.parametrize('label', ['A' * 1025, 'é' * 513])
def test_inventory_rejects_oversized_retained_group_label(source, events, field, label):
    if field == 'api':
        events[0]['event']['name'] = label
    else:
        events[0]['execution'][field] = label
    with pytest.raises(ContractError, match='inventory .* byte limit'):
        inventory.metadata_inventory_query(source)


def test_inventory_ceiling_allows_repeated_existing_groups(source, events, monkeypatch):
    monkeypatch.setattr(inventory_model, 'MAX_INVENTORY_CONTEXT_GROUPS', 2)
    monkeypatch.setattr(inventory_model, 'MAX_INVENTORY_API_GROUPS', 2)
    monkeypatch.setattr(inventory_model, 'MAX_INVENTORY_CONTEXT_API_GROUPS', 2)
    template = deepcopy(events[0])
    events.clear()
    for index, (context, api) in enumerate([('A', 'API0'), ('B', 'API1'), ('A', 'API0')]):
        event = deepcopy(template)
        event['seq'] = index
        event['ts_monotonic_ns'] = 100 + index
        event['execution']['context_id'] = context
        event['execution']['frame_id'] = context
        event['event']['name'] = api
        events.append(event)
    result = inventory.metadata_inventory_query(source)
    VALIDATOR.validate(result)
    assert result['query']['matching_events'] == '3'
    assert result['inventory']['contexts']['total_groups'] == 2
    assert result['inventory']['apis']['total_groups'] == 2
    assert sorted(row['events'] for row in result['inventory']['contexts']['groups']) == ['1', '2']


def test_health_cannot_be_silently_discarded_to_meet_byte_cap(source, events, monkeypatch):
    original = query._query
    def health(executable, path, sql, **kwargs):
        if 'private_records' in sql: return original(executable, path, sql, **kwargs)
        return (b'name,severity,value\n__capture_stats_present,meta,1\n__sorter_dropped,meta,0\n'
            + b''.join((f'counter_{i:03d}' + 'x'*110 + ',error,1\n').encode() for i in range(128)))
    monkeypatch.setattr(query, '_query', health)
    with pytest.raises(ContractError, match='output limit'): inventory.metadata_inventory_query(source)


@pytest.mark.parametrize('phase', ['live-prefix','finalized-recording','recovered-prefix','interrupted-recording','limited-recording'])
def test_inventory_preserves_phase_without_completeness_claim(source, events, phase):
    source.resolve().phase = phase
    result = inventory.metadata_inventory_query(source)
    assert result['snapshot']['source_phase'] == phase
    assert not result['semantics']['proves_capture_complete']


def test_incomplete_snapshot_tail_remains_explicit(source, events):
    source.resolve().path.write_bytes(source.resolve().path.read_bytes() + b'\x0a\x05abc')
    source.resolve().phase = 'live-prefix'
    result = inventory.metadata_inventory_query(source)
    assert result['snapshot']['bytes'] == '3'
    assert result['snapshot']['source_bytes'] == '8'
    assert result['snapshot']['excluded_tail_bytes'] == '5'
    assert result['snapshot']['source_phase'] == 'live-prefix'
    assert not result['semantics']['proves_capture_complete']


@pytest.mark.parametrize('route', ['events', 'inventory'])
def test_finalized_snapshot_rejects_incomplete_packet(source, events, route):
    location = source.resolve()
    location.path.write_bytes(location.path.read_bytes() + b'\x0a\x05abc')
    with pytest.raises(ContractError, match='finalized recording has an incomplete packet'):
        if route == 'events':
            query.metadata_query(source, filters=history_filters(), limit=25)
        else:
            inventory.metadata_inventory_query(source)


def test_source_and_snapshot_binding_changes_are_rejected(source, events, monkeypatch):
    with pytest.raises(ContractError, match='run binding'):
        inventory.metadata_inventory_query(source, expected_run_id='other-run')
    original = query.export_perfetto
    def changed_digest(*args, **kwargs):
        result = original(*args, **kwargs)
        result['report']['source_trace']['sha256'] = '0'*64
        return result
    monkeypatch.setattr(query, 'export_perfetto', changed_digest)
    with pytest.raises(ContractError, match='digest changed'): inventory.metadata_inventory_query(source)
    monkeypatch.setattr(query, 'export_perfetto', original)
    location = source.resolve()
    altered = deepcopy(location)
    altered.session['chromium_revision'] = '2'*40
    resolutions = iter((location, altered))
    source.resolve = lambda:next(resolutions)
    with pytest.raises(ContractError, match='identity changed'): inventory.metadata_inventory_query(source)


def test_no_event_payloads_or_source_target_side_effects(source, events, tmp_path, monkeypatch):
    # All valid extra event detail/provenance stays internal to validated export.
    events[0]['detail']['fixture_note'] = 'PRIVATE_SENTINEL_EVENT_DETAIL'
    before = source.resolve().path.read_bytes()
    before_session = deepcopy(source.resolve().session)
    paths = set(tmp_path.rglob('*'))
    exports = []
    original_export = query.export_perfetto
    def export(processor, snapshot, output, run, revision):
        assert snapshot != source.resolve().path
        exports.append((snapshot, output))
        return original_export(processor, snapshot, output, run, revision)
    monkeypatch.setattr(query, 'export_perfetto', export)
    import browser_core.incremental_inspection as private
    monkeypatch.setattr(private, 'IncrementalInspection', lambda *a, **kw:pytest.fail('opened private reader'))
    result = inventory.metadata_inventory_query(source)
    assert b'PRIVATE_SENTINEL' not in rendered(result)
    assert source.resolve().path.read_bytes() == before
    assert source.resolve().session == before_session
    assert set(tmp_path.rglob('*')) == paths
    assert len(exports) == 1 and all(not p.exists() for p in exports[0])


@pytest.mark.parametrize('route', ['session-inventory','evidence-inventory'])
def test_cli_routes_to_full_inventory_and_reports_exact_rendered_bytes(source, events, monkeypatch, tmp_path, capsys, route):
    closed = []
    if route == 'session-inventory':
        monkeypatch.setattr(inventory, 'RecordingSource', lambda *a, **kw:source)
        args = ['--session', str(tmp_path/'owned-run.json'), '--expected-run-id','owned-run']
    else:
        monkeypatch.setattr(inventory, 'OpenEvidence', lambda *a, **kw:SimpleNamespace(
            metadata={'capture':CAPTURE_OFF,'recording':{
                'run_id':'owned-run','sha256':hashlib.sha256(source.resolve().path.read_bytes()).hexdigest(),
                'bytes':3,'packets':1,'source_bytes':3,'excluded_tail_bytes':0,'source_phase':'finalized-recording'}},
            source=source, sha256='a'*64, close=lambda:closed.append(True)))
        args = ['--bundle', str(tmp_path/'bundle'), '--reader-executable', str(tmp_path/'chrome.exe'), '--expected-sha256','a'*64]
    assert cli.main(['trace',route,*args,'--analyst-activity','source-acquisition']) == 0
    captured = capsys.readouterr()
    result = json.loads(captured.out)
    VALIDATOR.validate(result)
    assert len(captured.out.encode('ascii')) == result['output']['rendered_json_bytes'] <= 16384
    assert captured.out.endswith('}') and '\r' not in captured.out
    assert captured.err == '' and 'events' not in result
    if route == 'evidence-inventory':
        assert closed == [True]
        assert result['bundle'] == {'sha256':'a'*64,'expected_digest_matched':True,'authenticity':'unsigned-exporter-metadata'}


@pytest.mark.parametrize('route', ['session-inventory','evidence-inventory'])
@pytest.mark.parametrize('extra', [['--limit','0'], ['--limit','25'], ['--include-values'],
    ['--cursor','secret'], ['--metadata-version','2'], ['--inventory-version','2'], ['--realm-id','0']])
def test_cli_rejects_unsupported_query_options_before_io(tmp_path, route, extra):
    args = (['--session',str(tmp_path/'owned-run.json'),'--expected-run-id','owned-run']
            if route == 'session-inventory' else ['--bundle',str(tmp_path/'bundle'),'--reader-executable',str(tmp_path/'chrome.exe')])
    with pytest.raises(SystemExit) as caught: cli.build_parser().parse_args(['trace',route,*args,*extra])
    assert caught.value.code == 2


@pytest.mark.parametrize('failure', [ContractError('PRIVATE_SENTINEL'), OSError('PRIVATE_SENTINEL'),
    query.MetadataQueryError('metadata-recording-contains-values'), KeyboardInterrupt()])
def test_cli_failures_are_bounded_closed_and_redacted(source, monkeypatch, tmp_path, capsys, failure):
    def fail(*a, **kw): raise failure
    monkeypatch.setattr(inventory, 'RecordingSource', fail)
    status = cli.main(['trace','session-inventory','--session',str(tmp_path/'owned-run.json'),'--expected-run-id','owned-run'])
    captured = capsys.readouterr()
    result = json.loads(captured.out)
    VALIDATOR.validate(result)
    assert status == (130 if isinstance(failure, KeyboardInterrupt) else 2)
    assert 'PRIVATE_SENTINEL' not in captured.out and captured.err == ''
    assert len(captured.out) < 256


@pytest.mark.parametrize('route', ['session-inventory','evidence-inventory'])
@pytest.mark.parametrize('case', ['help','missing-source','incomplete-selector','bad-filter'])
def test_actual_source_cli_process_is_discoverable_and_fails_closed(tmp_path, route, case):
    args = (['--session',str(tmp_path/'owned-run.json'),'--expected-run-id','owned-run']
            if route == 'session-inventory' else ['--bundle',str(tmp_path/'bundle'),'--reader-executable',str(tmp_path/'chrome.exe')])
    if case == 'help': args = ['--help']
    elif case == 'incomplete-selector': args += ['--portable-pid','10']
    elif case == 'bad-filter': args += ['--api','PRIVATE_SENTINEL invalid filter']
    result = subprocess.run([sys.executable, '-m', 'browser_core', 'trace', route, *args],
        cwd=ROOT, capture_output=True, timeout=30, check=False)
    assert result.stderr == b''
    if case == 'help':
        assert result.returncode == 0 and b'--inventory-version {1}' in result.stdout
        assert b'--include-values' not in result.stdout and b'--limit ' not in result.stdout
    else:
        assert result.returncode == 2
        body = json.loads(result.stdout)
        VALIDATOR.validate(body)
        assert body['status'] == 'error' and body['code'] == 'query-unavailable'
        assert len(result.stdout) < 256 and b'PRIVATE_SENTINEL' not in result.stdout
        assert str(tmp_path).encode() not in result.stdout


@pytest.mark.parametrize('route', ['session-inventory','evidence-inventory'])
def test_actual_cli_success_emits_exact_lf_bytes_below_cap(source, events, route):
    # Independent F2 repro: 16 contexts, 8 APIs and 26-character labels.
    template = deepcopy(events[0])
    events.clear()
    for context in range(16):
        for api in range(8):
            event = deepcopy(template)
            event['seq'] = len(events)
            event['ts_monotonic_ns'] = 100 + len(events)
            label = f'{context:02d}' + 'x'*24
            event['execution'] = {'context_id':label, 'frame_id':label}
            event['event']['name'] = f'API{api:02d}.read'
            events.append(event)
    result = inventory.metadata_inventory_query(source)
    body = rendered(result)
    assert result['query']['matching_events'] == '128'
    assert len(body.replace(b'\n', b'\r\n')) > 16384  # prior Windows regression
    process = subprocess.run([sys.executable, '-B', *(['-O'] if sys.flags.optimize else []), '-c',
        'import json,sys; from browser_core import cli,metadata_inventory_query as inventory; '
        'result=json.loads(sys.stdin.buffer.read()); '
        'inventory.evidence_inventory=lambda *a,**k:result; '
        'inventory.session_inventory=lambda *a,**k:result; '
        'raise SystemExit(cli.main(sys.argv[1:]))', 'trace', route,
        *(['--session','C:/owned-run.json','--expected-run-id','owned-run'] if route=='session-inventory'
          else ['--bundle','C:/fixture.bcevidence','--reader-executable','C:/fixture-chrome.exe'])],
        input=body, cwd=ROOT, capture_output=True, timeout=30, check=False)
    assert process.returncode == 0 and process.stderr == b''
    assert process.stdout == body
    assert len(process.stdout) == result['output']['rendered_json_bytes'] <= 16384
    assert process.stdout.count(b'\r') == 0 and process.stdout.endswith(b'}')
    assert result['output']['transport_delivery_verified'] is False


def test_inventory_emitter_bypasses_crlf_translation_and_keeps_legacy_emitter(source, events, monkeypatch):
    result = inventory.metadata_inventory_query(source)
    raw = io.BytesIO()
    translated = io.TextIOWrapper(raw, encoding='ascii', newline='\r\n')
    monkeypatch.setattr(sys, 'stdout', translated)
    inventory._emit_inventory_json(result)
    assert raw.getvalue() == rendered(result)
    raw.seek(0); raw.truncate()
    cli._json(result)
    translated.flush()
    assert raw.getvalue() == rendered(result).replace(b'\n', b'\r\n') + b'\r\n'


@pytest.mark.parametrize('case', ['wrong-count','too-large','text-only'])
def test_inventory_emitter_rejects_before_writing(source, events, monkeypatch, case):
    result = inventory.metadata_inventory_query(source)
    raw = io.BytesIO()
    target = io.StringIO() if case == 'text-only' else SimpleNamespace(buffer=raw)
    monkeypatch.setattr(sys, 'stdout', target)
    if case == 'wrong-count': result['output']['rendered_json_bytes'] += 1
    elif case == 'too-large': result['oversized'] = 'x'*16384
    with pytest.raises(ContractError): inventory._emit_inventory_json(result)
    assert raw.getvalue() == b''
    if case == 'text-only': assert target.getvalue() == ''


def test_inventory_emitter_does_not_claim_success_on_short_binary_write(source, events, monkeypatch):
    sink = SimpleNamespace(write=lambda body:len(body)-1,
        flush=lambda:pytest.fail('short write was treated as success'))
    monkeypatch.setattr(sys, 'stdout', SimpleNamespace(buffer=sink))
    with pytest.raises(ContractError, match='write was incomplete'):
        inventory._emit_inventory_json(inventory.metadata_inventory_query(source))


@pytest.mark.parametrize('stage', ['write', 'flush'])
def test_inventory_emitter_closes_binary_transport_errors(source, events, monkeypatch, stage):
    calls = []

    def write(body):
        calls.append('write')
        if stage == 'write':
            raise OSError('PRIVATE_SENTINEL transport')
        return len(body)

    def flush():
        calls.append('flush')
        raise OSError('PRIVATE_SENTINEL transport')

    monkeypatch.setattr(sys, 'stdout', SimpleNamespace(buffer=SimpleNamespace(
        write=write, flush=flush)))
    with pytest.raises(ContractError, match='transport failed') as caught:
        inventory._emit_inventory_json(inventory.metadata_inventory_query(source))
    assert calls == (['write'] if stage == 'write' else ['write', 'flush'])
    assert 'PRIVATE_SENTINEL' not in str(caught.value)


@pytest.mark.parametrize('route', ['session-inventory', 'evidence-inventory'])
@pytest.mark.parametrize('option', ['--unknown=PRIVATE_SENTINEL',
    '--inventory-version=PRIVATE_SENTINEL', '--api'])
def test_actual_inventory_cli_parse_failures_are_closed(route, option):
    process = subprocess.run([sys.executable, '-m', 'browser_core', 'trace', route, option],
        cwd=ROOT, capture_output=True, timeout=30, check=False)
    assert process.returncode == 2 and process.stderr == b''
    result = json.loads(process.stdout)
    assert result == {'schema': inventory.SCHEMA, 'status': 'error', 'code': 'query-unavailable'}
    assert b'PRIVATE_SENTINEL' not in process.stdout and len(process.stdout) <= 16384


# Measured before implementation, against the deterministic shared fixture.
# Hashes cover every field and opaque cursor, not just selected assertions.
LEGACY = {
    (1,1): ('c7d92b3c629fd93ae60df201d36cddf5dba99ba4ed1494a380766cee5ddb75d4','399df4d2a21d539294515ca4564055e4706851ce7644f8086d231d6f55e3c276'),
    (1,2): ('8aaaac57c939775823acb91cc9d87764fe00d7333fe5fb4ad5353f98abadcaf1','340afb7f7fc9f843163a1bc894957ec2decb838169a82e3df770f96eaa4095e5'),
    (1,25): ('3eae1c37b4a132a4ce03c0c9849966fd0acfb38af23e7c66c7b0b88e201bdc0d',),
    (1,100): ('d9ebdb28139ae1e7ce188a6adfc1908d7ea820c74cb21d527e2944848f1f0b17',),
    (2,1): ('95c21b70a73bed1c64b8ed185b6d2c5dab5c72adc4c2259eb87bd588ba1b1ff3','77d495b7966bec85f74db16aa943b7e0809942ab866841d28810864b56a87761'),
    (2,2): ('aca4d12328f369c8302479bf045640840b7a781a0a3795147622abcef4e036ae','8a05c6f9512c2c12c48e8ed31f62b27c17771b6234c1e1526ac4ec137b427237'),
    (2,25): ('22ee5a32caa55aba7895ebfc8faf86002608ce9894e0255def6bc0c7ea906f2e',),
    (2,100): ('60e71e8d38fe87004299c2affee12985294ba09ff8ba7bec22e7b6274629ce81',),
}


@pytest.mark.parametrize('version,limit', LEGACY)
def test_legacy_response_and_cursor_bytes_preserved(source, events, version, limit):
    options = dict(filters=history_filters(), limit=limit, metadata_version=version, bundle_sha256='a'*64)
    cursor = None
    for digest in LEGACY[version,limit]:
        result = query.metadata_query(source, cursor=cursor, **options)
        assert hashlib.sha256(canonical_json_bytes(result)).hexdigest() == digest
        cursor = result['query']['next_cursor']


@pytest.mark.parametrize('version', [1,2])
@pytest.mark.parametrize('limit', [0, -1, 101, True, False, 1.0, '1', None, [], {}])
def test_legacy_limit_rejects_are_unchanged(version, limit):
    with pytest.raises(ContractError, match='metadata query limit must be from 1 to 100'):
        query.metadata_query(None, filters={}, limit=limit, metadata_version=version)
