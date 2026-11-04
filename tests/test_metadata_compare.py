"""Window comparison over one validated metadata snapshot: windows, rows, limits and bytes."""
from contextlib import closing
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace

import jsonschema
import pytest

from browser_core import cli, metadata_compare as compare, metadata_query as query
from browser_core.contracts import ContractError, EXACT_NATIVE_EVENT_COMPONENTS
from browser_core.evidence_bundle import EvidenceExport
from browser_core.inspection_attribution import ContextAttribution
from browser_core.inspection_contract import CAPTURE_OFF
from browser_core.trace import validate_trace_event
from test_evidence_bundle import BODY
from test_metadata_workflow import source, invalid_population, REVISION

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = json.loads((ROOT / 'schemas/metadata-compare-v1.schema.json').read_text())
jsonschema.Draft202012Validator.check_schema(SCHEMA)
VALIDATOR = jsonschema.Draft202012Validator(SCHEMA)
COLLECT = 'http:same-origin:/api/collect'
ARM = 'http:same-origin:/api/arm'


def _event(seq, ts, name, category='api', *, kind='window', native=None, validate=True, **extra):
    context = {'window': 'ABCD', 'worker': 'W1', 'other': None}[kind]
    execution = None if context is None else {'context_id': context, 'script_id': f'v8:10:{context}:7',
        **({'frame_id': context} if kind == 'window' else {'worker_id': context})}
    event = {'schema': 'browser-core.trace-event/1', 'run_id': 'owned-run', 'seq': seq, 'ts_monotonic_ns': ts,
             'process': {'pid': 10, 'type': 'renderer'}, 'event': {'category': category, 'name': name},
             'provenance': {'source': 'fixture', 'component': 'blink', 'chromium_revision': REVISION},
             'detail': {}}
    if execution is not None:
        event['execution'] = execution
    if native is not None:
        event['provenance'].update(source='native', component=EXACT_NATIVE_EVENT_COMPONENTS[native])
        event['detail'] = {'native_name': native, 'thread_id': 5}
    event.update(extra)
    return validate_trace_event(event) if validate else event


def _request(seq, ts, method, url_class, body):
    return _event(seq, ts, 'fetch.request.start', 'network', native='BrowserCore.FetchRequestStart',
                  causal_parent_seq=seq - 1, request={'id': f'fetch-request:ABCD:{seq}', 'method': method,
                  'url_class': url_class, 'target_scope': 'loopback', 'body_bytes': body})


def _eval(seq, ts, length):
    event = _event(seq, ts, 'dynamic.code.materialized', 'execution', kind='other',
                   native='BrowserCore.DynamicCodeMaterialized', validate=False)
    event['detail'].update(dynamic_kind='eval', cache_status='compiled', generated_script_id=9,
        caller_script_id=7, caller_status='observed', caller_parent_status='script_parent_not_in_trace',
        source_length=length, source_length_unit='utf16-code-units')
    return validate_trace_event(event)


def trials():
    """Three trials: arm request, a trial-specific read in generated code, then collect."""
    rows, seq = [], 0
    def add(maker, *args, **kwargs):
        nonlocal seq
        seq += 1
        rows.append(maker(seq, *args, **kwargs))
    add(_event, 1_000, 'Navigator.userAgent.get')          # before every window
    for trial, (read, kind, body) in enumerate([('Screen.width.get', 'window', 120),
                                                ('Navigator.language.get', 'window', 130),
                                                ('WorkerNavigator.language.get', 'worker', 125)]):
        base = 10_000_000 * (trial + 1)
        add(_request, base, 'POST', ARM, 0)
        add(_eval, base + 1_000, 900 + trial)
        add(_event, base + 2_000, 'Document.referrer.get', dynamic_code_parent_seq=seq)
        add(_event, base + 3_000, read, kind=kind, dynamic_code_parent_seq=seq - 1)
        add(_event, base + 4_000, 'Window.fetch')
        add(_request, base + 5_000, 'POST', COLLECT, body)
        add(_event, base + 9_000_000, 'TreeWalker.nextNode')  # analyst-like noise between trials
    return rows


@pytest.fixture
def recorded(source, monkeypatch):
    rows = trials()
    def export(processor, trace, path, run, revision):
        path.write_text('\n'.join(json.dumps(event) for event in rows), encoding='utf-8')
        return {'report': {'source_trace': {'sha256': hashlib.sha256(BODY).hexdigest()}}}
    monkeypatch.setattr(query, 'export_perfetto', export)
    # Fixture rows pass per-event validation; whole-population rules (fetch API
    # parents, dynamic-code joins) are covered by the dedicated test below.
    def per_event_scan(path, consume, *, hash_update):
        with closing(query.iter_trace(path, hash_update=hash_update)) as trace_events:
            for event in trace_events:
                consume(event)
        return {}
    monkeypatch.setattr(query, 'scan_validated_trace', per_event_scan)
    return rows


def rows_by_api(result):
    return {(row[0], row[1]): row for row in result['differences']['rows']}


@pytest.mark.parametrize('axis', ['api', 'context'])
def test_comparison_bounds_distinct_groups_before_report_sorting(monkeypatch, axis):
    rows = []
    for index in range(3):
        name = f'Fixture.read{index}' if axis == 'api' else 'Fixture.read'
        event = _event(index + 1, index + 1, name, validate=False)
        if axis == 'context':
            context = f'frame-{index}'
            event['execution'] = {
                'context_id': context, 'frame_id': context,
                'script_id': f'v8:10:{context}:7',
            }
        rows.append(validate_trace_event(event))
    spec = compare.comparison_spec(windows=['0:10', '11:20'])
    collector = compare.WindowComparison(spec, compare.history_filters(), [])
    collector.prepare(lambda: (row for row in rows))
    monkeypatch.setattr(compare, 'MAX_COMPARISON_GROUPS_PER_WINDOW', 2, raising=False)
    with pytest.raises(compare.ComparePopulationError, match='comparison distinct group limit') as caught:
        for row in rows:
            collector.add(row)
    VALIDATOR.validate({'schema': compare.SCHEMA, 'status': 'error',
                        'code': caught.value.code, 'hint': caught.value.hint})


@pytest.mark.parametrize('pass_name',['anchor','neighbor'])
def test_comparison_prepasses_close_retained_trace_iterator_after_projection_error(pass_name):
    spec={'mode':'anchor','anchor':{'api':'fixture','max_windows':2,
        'direction':'before','url_class':None,'method':None}}
    collector=compare.WindowComparison(spec,{},[])
    retained=[]
    closed=[]

    def events():
        def rows():
            try:
                yield {'event':{'name':'fixture'},'ts_monotonic_ns':1}
            finally:
                closed.append(True)
        generator=rows()
        retained.append(generator)
        return generator

    with pytest.raises(KeyError,match='seq'):
        if pass_name=='anchor':
            collector.prepare(events)
        else:
            collector._same_api_neighbors(events,[(2,2)])
    assert len(retained)==1
    assert closed==[True]


def test_anchor_windows_isolate_each_trial_between_requests(source, recorded):
    result = compare.compare_windows(source, anchor_url_class=COLLECT, anchor_method='post')
    VALIDATOR.validate(result)
    windows = result['windows']['rows']
    assert [row[4] for row in windows] == ['previous-same-api'] * 3
    # Each window runs from just after that trial's arm request to its collect request.
    assert [(int(row[1]), int(row[2])) for row in windows] == [
        (10_000_001, 10_005_000), (20_000_001, 20_005_000), (30_000_001, 30_005_000)]
    assert result['query']['anchor']['method'] == 'POST'
    assert result['query']['anchor']['anchors_matched'] == 3
    assert [row[7] for row in result['anchors']['rows']] == [120, 130, 125]
    differing = rows_by_api(result)
    assert differing[('Screen.width.get', 'window')][2:5] == ['some-windows', [1, 0, 0], [1, 0, 0]]
    assert differing[('WorkerNavigator.language.get', 'worker')][3] == [0, 0, 1]
    assert differing[('Screen.width.get', 'window')][5] == [-2, None, None]
    constant = {(row[0], row[1]): row for row in result['constant']['rows']}
    assert constant[('Document.referrer.get', 'window')][2:] == [1, 3]
    assert ('TreeWalker.nextNode', 'window') not in constant and ('TreeWalker.nextNode', 'window') not in differing
    assert [row[5] for row in result['generated_code']['rows']] == [900, 901, 902]
    assert result['generated_code']['rows'][0][3] == 'eval'
    assert result['limits']['absence_proves_nonexecution'] is False
    assert result['limits']['window_membership_proves_causality'] is False
    assert result['limits']['source_url_to_script_mapping_established'] is False
    assert result['limits']['response_to_generated_code_mapping_established'] is False
    assert result['semantics']['event_rows_included'] is False and 'events' not in result
    assert result['output']['rendered_json_bytes'] == len(compare.rendered_bytes(result)) <= 16384


def test_anchor_boundary_and_span_edges(source, recorded):
    wide = compare.compare_windows(source, anchor_url_class=COLLECT, boundary='anchor')
    assert [row[4] for row in wide['windows']['rows']] == ['recording-start', 'previous-anchor', 'previous-anchor']
    noise = {(row[0], row[1]): row for row in wide['differences']['rows'] + wide['constant']['rows']}
    assert noise[('TreeWalker.nextNode', 'window')][2:4] == ['some-windows', [0, 1, 1]]
    narrow = compare.compare_windows(source, anchor_url_class=COLLECT, span_ns='2500')
    assert [row[4] for row in narrow['windows']['rows']] == ['span'] * 3
    assert int(narrow['windows']['rows'][0][1]) == 10_002_500
    assert ('Document.referrer.get', 'window') not in rows_by_api(narrow)
    VALIDATOR.validate(wide); VALIDATOR.validate(narrow)


@pytest.mark.parametrize('boundary', ['same-api', 'anchor'])
def test_same_timestamp_selected_anchors_are_rejected(source, recorded, boundary):
    timestamp = recorded[-1]['ts_monotonic_ns'] + 1
    sequence = recorded[-1]['seq']
    recorded.extend([
        _event(sequence + 1, timestamp, 'Navigator.userAgent.get'),
        _event(sequence + 2, timestamp, 'Navigator.userAgent.get'),
    ])
    with pytest.raises(compare.CompareOptionError) as caught:
        compare.compare_windows(source, anchor_api='Navigator.userAgent.get',
                                max_windows=2, boundary=boundary)
    assert caught.value.code == 'compare-anchors-ambiguous-timestamp'
    assert 'nanosecond-only windows cannot separate them' in caught.value.hint
    VALIDATOR.validate({'schema': compare.SCHEMA, 'status': 'error',
                        'code': caught.value.code, 'hint': caught.value.hint})


def test_after_anchor_boundary_rejects_unselected_anchor_at_same_timestamp(source, recorded):
    timestamp = recorded[-1]['ts_monotonic_ns'] + 1
    sequence = recorded[-1]['seq']
    recorded.extend([
        _event(sequence + 1, timestamp, 'Navigator.userAgent.get'),
        _event(sequence + 2, timestamp, 'Navigator.userAgent.get'),
        _event(sequence + 3, timestamp + 1, 'Navigator.userAgent.get'),
    ])
    with pytest.raises(compare.CompareOptionError) as caught:
        compare.compare_windows(source, anchor_api='Navigator.userAgent.get',
                                max_windows=2, direction='after', boundary='anchor')
    assert caught.value.code == 'compare-anchors-ambiguous-timestamp'


def test_same_timestamp_nonmatching_request_boundary_is_rejected(source, recorded):
    timestamp = recorded[-1]['ts_monotonic_ns'] + 1
    sequence = recorded[-1]['seq']
    recorded.extend([
        _request(sequence + 1, timestamp, 'POST', COLLECT, 140),
        _request(sequence + 2, timestamp, 'POST', ARM, 0),
    ])
    with pytest.raises(compare.CompareOptionError) as caught:
        compare.compare_windows(source, anchor_url_class=COLLECT, direction='after',
                                max_windows=2, boundary='same-api')
    assert caught.value.code == 'compare-anchors-ambiguous-timestamp'


def test_before_window_rejects_later_request_at_anchor_timestamp(source, recorded):
    timestamp = recorded[-1]['ts_monotonic_ns'] + 1
    sequence = recorded[-1]['seq']
    recorded.extend([
        _request(sequence + 1, timestamp, 'POST', COLLECT, 140),
        _request(sequence + 2, timestamp, 'POST', ARM, 0),
    ])
    with pytest.raises(compare.CompareOptionError) as caught:
        compare.compare_windows(source, anchor_url_class=COLLECT, direction='before',
                                max_windows=2, boundary='same-api')
    assert caught.value.code == 'compare-anchors-ambiguous-timestamp'


def test_after_direction_stops_at_next_request_and_flags_the_snapshot_end(source, recorded):
    result = compare.compare_windows(source, anchor_url_class=ARM, direction='after')
    VALIDATOR.validate(result)
    rows = result['windows']['rows']
    assert [row[4] for row in rows] == ['next-same-api', 'next-same-api', 'next-same-api']
    assert int(rows[0][2]) == 10_004_999 and rows[-1][-1] is False
    last = compare.compare_windows(source, anchor_url_class=COLLECT, direction='after')
    assert last['windows']['rows'][-1][4] == 'snapshot-end' and last['windows']['rows'][-1][-1] is True


@pytest.mark.parametrize('phase,live,hint', [
    ('live-prefix', True, 'live snapshot'),
    ('recovered-prefix', False, 'stopped incomplete recording prefix'),
    ('limited-recording', False, 'stopped incomplete recording prefix'),
    ('interrupted-recording', False, 'stopped incomplete recording prefix'),
    ('finalized-recording', False, 'last recorded event'),
])
def test_window_past_snapshot_distinguishes_live_and_stopped_sources(source, recorded, phase, live, hint):
    source.resolve().phase = phase
    result = compare.compare_windows(source, anchor_url_class=COLLECT, direction='after')
    VALIDATOR.validate(result)
    assert result['snapshot']['source_phase'] == phase
    assert result['limits']['snapshot_is_live_prefix'] is live
    assert result['windows']['rows'][-1][-1] is True
    assert any(hint in text for text in result['hints'])
    if not live:
        assert all('repeat after the trial finishes' not in text for text in result['hints'])


def test_path_only_url_class_matches_the_path_part(source, recorded):
    by_path = compare.compare_windows(source, anchor_url_class='/api/collect')
    exact = compare.compare_windows(source, anchor_url_class=COLLECT)
    assert by_path['windows'] == exact['windows'] and by_path['anchors'] == exact['anchors']
    with pytest.raises(compare.CompareOptionError):
        compare.compare_windows(source, anchor_url_class='api/collect')


def test_path_only_url_class_keeps_colons_in_the_path():
    assert compare._url_class_matches('same-origin:/api:item', '/api:item')
    assert compare._url_class_matches('http:same-origin:/api:item', '/api:item')
    assert not compare._url_class_matches('same-origin:/other:/api:item', '/api:item')


def test_latest_anchors_are_used_and_truncation_is_explicit(source, recorded):
    result = compare.compare_windows(source, anchor_api='fetch.request.start', max_windows=2)
    anchor = result['query']['anchor']
    assert (anchor['anchors_matched'], anchor['anchors_used'], anchor['truncated']) == (6, 2, True)
    assert [row[5] for row in result['anchors']['rows']] == [ARM, COLLECT]
    assert any('More anchors matched' in hint for hint in result['hints'])
    VALIDATOR.validate(result)


def test_fifty_nearby_differences_fit_without_premature_row_truncation(source, recorded, monkeypatch):
    rows = trials()
    names = [f'Metric{index:02}.get' for index in range(50)]
    rows.extend(_event(1000 + index, 10_003_100 + index, name)
                for index, name in enumerate(names))
    rows.sort(key=lambda event: (event['ts_monotonic_ns'], event['seq']))

    def export(processor, trace, path, run, revision):
        path.write_text('\n'.join(json.dumps(event) for event in rows), encoding='utf-8')
        return {'report': {'source_trace': {'sha256': hashlib.sha256(BODY).hexdigest()}}}

    monkeypatch.setattr(query, 'export_perfetto', export)
    result = compare.compare_windows(source, anchor_url_class=COLLECT)
    VALIDATOR.validate(result)
    shown = {row[0] for row in result['differences']['rows']}
    assert set(names) <= shown
    assert result['differences']['reported'] == result['differences']['total']
    assert result['output']['byte_limit_applied'] is False
    assert result['output']['rendered_json_bytes'] <= compare.MAX_OUTPUT_BYTES


def test_landmarks_nearest_anchor_survive_more_than_the_memory_cap(source, recorded, monkeypatch):
    rows = trials()
    base = 10_000_000
    for index in range(compare.MAX_RETAINED_LANDMARKS + 44):
        seq = 1000 + 2 * index
        rows.append(_request(seq, base + 1100 + 2 * index, 'POST', ARM, index))
        rows.append(_eval(seq + 1, base + 1101 + 2 * index, 10_000 + index))
    rows.sort(key=lambda event: (event['ts_monotonic_ns'], event['seq']))

    def export(processor, trace, path, run, revision):
        path.write_text('\n'.join(json.dumps(event) for event in rows), encoding='utf-8')
        return {'report': {'source_trace': {'sha256': hashlib.sha256(BODY).hexdigest()}}}

    monkeypatch.setattr(query, 'export_perfetto', export)
    result = compare.compare_windows(source, anchor_api='Document.referrer.get')
    VALIDATOR.validate(result)
    requests = [row for row in result['requests']['rows'] if row[0] == 1]
    code = [row for row in result['generated_code']['rows'] if row[0] == 1]
    assert result['requests']['total'] > compare.MAX_RETAINED_LANDMARKS
    assert result['generated_code']['total'] > compare.MAX_RETAINED_LANDMARKS
    last = compare.MAX_RETAINED_LANDMARKS + 43
    assert [row[-1] for row in requests] == list(range(last - 7, last + 1))
    assert [row[-1] for row in code] == list(range(10_000 + last - 5, 10_000 + last + 1))


def test_explicit_windows_and_overlap(source, recorded):
    result = compare.compare_windows(source, windows=['10000000:10005000', '20000000:20005000', '20004000:39000000'])
    VALIDATOR.validate(result)
    assert result['query']['mode'] == 'explicit' and 'anchors' not in result
    assert [row[4] for row in result['windows']['rows']] == ['explicit'] * 3
    assert result['limits']['windows_overlap'] is True
    assert result['windows']['rows'][2][-1] is False
    beyond = compare.compare_windows(source, windows=['1:2', '50000000:60000000'])
    assert beyond['windows']['rows'][1][-1] is True
    assert any('No matching event' in hint for hint in beyond['hints'])


def test_api_filter_narrows_rows_but_keeps_landmarks(source, recorded):
    result = compare.compare_windows(source, anchor_url_class=COLLECT, apis=['Screen.width.get'])
    assert [row[0] for row in result['differences']['rows']] == ['Screen.width.get']
    assert result['constant']['rows'] == []
    assert result['requests']['total'] == 3 and result['generated_code']['total'] == 3
    worker = compare.compare_windows(source, anchor_url_class=COLLECT, context_kind='worker')
    assert worker['requests']['total'] == 0 and worker['generated_code']['total'] == 0
    assert [row[0] for row in worker['differences']['rows']] == ['WorkerNavigator.language.get']


@pytest.mark.parametrize('options', [
    {}, {'windows': ['1:2', '3:4'], 'anchor_api': 'fetch.request.start'}, {'windows': ['1:2']},
    {'windows': [f'{i}:{i}' for i in range(9)]}, {'windows': ['5:3', '1:2']}, {'windows': ['1-2', '3:4']},
    {'windows': ['01:2', '3:4']}, {'windows': ['1:2', '3:4'], 'direction': 'after'},
    {'windows': ['1:2', '3:4'], 'span_ns': '5'},
    {'windows': ['1:2', '3:4'], 'max_windows': 2},
    {'anchor_api': 'fetch.request.start', 'span_ns': '0'},
    {'anchor_api': 'fetch.request.start', 'span_ns': 10**4300},
    {'anchor_api': 'bad name'}, {'anchor_method': 'PO ST'}, {'anchor_url_class': 'x\ny'},
    {'anchor_api': 'Screen.width.get', 'anchor_method': 'POST'},
    {'anchor_url_class': '/api/\ud800'}, {'anchor_url_class': 'api/collect'},
    {'anchor_url_class': 'http:same-origin:/api/collect?token=private'},
    {'anchor_api': 'x', 'direction': 'sideways'}, {'anchor_api': 'x', 'max_windows': 9},
    {'anchor_api': 'x', 'max_windows': True}, {'anchor_api': 'x', 'boundary': 'none'}])
def test_invalid_options_fail_before_the_source_is_opened(options):
    opened = []
    source = SimpleNamespace(resolve=lambda: opened.append(True))
    with pytest.raises(compare.CompareOptionError) as caught:
        compare.compare_windows(source, **options)
    assert caught.value.code == 'compare-options-invalid' and opened == []


@pytest.mark.parametrize('binding', [
    {'bundle_sha256': 'not-a-digest'},
    {'expected_digest_matched': True},
    {'bundle_sha256': 'a' * 64, 'expected_digest_matched': 'yes'},
])
def test_invalid_programmatic_bundle_claim_fails_before_source_access(binding):
    opened = []
    source = SimpleNamespace(resolve=lambda: opened.append(True))
    with pytest.raises(ContractError, match='digest binding'):
        compare.compare_windows(source, anchor_api='fetch.request.start', **binding)
    assert opened == []


def test_too_few_anchors_reports_the_matched_count(source, recorded):
    with pytest.raises(compare.CompareOptionError) as caught:
        compare.compare_windows(source, anchor_url_class='http:same-origin:/api/none')
    assert caught.value.code == 'compare-anchors-insufficient'
    assert caught.value.fields == {'anchors_matched': 0}


def test_byte_cap_prunes_least_useful_rows_and_keeps_totals(source, recorded, monkeypatch):
    full = compare.compare_windows(source, anchor_url_class=COLLECT)
    monkeypatch.setattr(compare, 'MAX_OUTPUT_BYTES', full['output']['rendered_json_bytes'] - 200)
    pruned = compare.compare_windows(source, anchor_url_class=COLLECT)
    assert pruned['output']['byte_limit_applied'] is True
    assert pruned['constant']['truncated'] is True
    assert pruned['constant']['total'] == full['constant']['total']
    assert pruned['differences'] == full['differences'] and pruned['windows'] == full['windows']
    assert len(compare.rendered_bytes(pruned)) == pruned['output']['rendered_json_bytes'] <= compare.MAX_OUTPUT_BYTES


def test_byte_cap_warns_when_it_prunes_differences(source, recorded, monkeypatch):
    full = compare.compare_windows(source, anchor_url_class=COLLECT)
    assert full['differences']['rows'] and not full['differences']['truncated']
    assert compare.DIFFERENCE_TRUNCATED_HINT not in full['hints']
    pruned = None
    for cap in range(full['output']['rendered_json_bytes'] - 200, 2000, -200):
        monkeypatch.setattr(compare, 'MAX_OUTPUT_BYTES', cap)
        try:
            candidate = compare.bound_output(deepcopy(full))
        except ContractError:
            break
        if candidate['differences']['truncated']:
            pruned = candidate
            break
    assert pruned is not None
    assert pruned['differences']['reported'] < pruned['differences']['total']
    assert pruned['hints'].count(compare.DIFFERENCE_TRUNCATED_HINT) == 1
    assert pruned['output']['byte_limit_applied'] is True
    assert len(compare.rendered_bytes(pruned)) == pruned['output']['rendered_json_bytes'] <= cap
    VALIDATOR.validate(pruned)
    assert compare.bound_output(pruned)['hints'].count(compare.DIFFERENCE_TRUNCATED_HINT) == 1


@pytest.mark.parametrize('exact_filter', [False, True])
def test_long_anchor_request_classes_do_not_make_comparison_unavailable(
        source, recorded, monkeypatch, exact_filter):
    rows = trials()
    # The second class fits the 1024-byte exact selector but expands in ASCII JSON.
    long_class = 'http:same-origin:/' + ('é' * 500 if exact_filter else 'x' * 4000)
    for index in range(8):
        rows.append(_request(1000 + index, 40_000_000 + index * 1000,
                             'POST', long_class, index))
        rows.append(_event(2000 + index, 40_000_100 + index * 1000,
                           f'Metric{index}.get'))
    rows.sort(key=lambda event: (event['ts_monotonic_ns'], event['seq']))

    def export(processor, trace, path, run, revision):
        path.write_text('\n'.join(json.dumps(event) for event in rows), encoding='utf-8')
        return {'report': {'source_trace': {'sha256': hashlib.sha256(BODY).hexdigest()}}}

    monkeypatch.setattr(query, 'export_perfetto', export)
    options = ({'anchor_url_class': long_class} if exact_filter
               else {'anchor_api': 'fetch.request.start'})
    result = compare.compare_windows(source, **options)
    VALIDATOR.validate(result)
    assert len(result['anchors']['rows']) == 8
    if exact_filter:
        assert result['query']['anchor']['url_class'] == long_class
    assert result['anchors']['url_classes_omitted_windows']
    assert all(result['anchors']['rows'][window - 1][5] is None
               for window in result['anchors']['url_classes_omitted_windows'])
    assert result['output']['byte_limit_applied'] is True
    assert result['output']['rendered_json_bytes'] == len(compare.rendered_bytes(result)) <= 16384
    assert {'Metric0.get', 'Metric1.get', 'Metric2.get', 'Metric3.get',
            'Metric4.get', 'Metric5.get', 'Metric6.get'} <= {
        row[0] for row in result['differences']['rows']}
    assert any('anchor url_class' in hint for hint in result['hints'])


def test_oversized_anchor_omission_preserves_detail_rows_and_window_bindings(
        source, recorded, monkeypatch):
    rows = trials()
    long_class = 'http:same-origin:/' + 'x' * 1000
    for index in range(2):
        rows.append(_request(1000 + index, 40_000_000 + index * 1000,
                             'POST', long_class, index))
        rows.append(_event(2000 + index, 40_000_100 + index * 1000,
                           f'Metric{index}.get'))
    rows.sort(key=lambda event: (event['ts_monotonic_ns'], event['seq']))

    def export(processor, trace, path, run, revision):
        path.write_text('\n'.join(json.dumps(event) for event in rows), encoding='utf-8')
        return {'report': {'source_trace': {'sha256': hashlib.sha256(BODY).hexdigest()}}}

    monkeypatch.setattr(query, 'export_perfetto', export)
    full = compare.compare_windows(source, anchor_api='fetch.request.start', max_windows=2)
    assert full['differences']['rows'] and full['requests']['rows']
    monkeypatch.setattr(compare, 'MAX_OUTPUT_BYTES', full['output']['rendered_json_bytes'] - 300)
    bounded = compare.bound_output(deepcopy(full))
    VALIDATOR.validate(bounded)
    assert bounded['anchors']['url_classes_omitted_windows'] == [1]
    assert bounded['windows'] == full['windows']
    assert [(row[0], row[1], row[2]) for row in bounded['anchors']['rows']] == [
        (row[0], row[1], row[2]) for row in full['anchors']['rows']]
    for table in ('differences', 'constant', 'contexts', 'requests', 'generated_code'):
        assert bounded[table] == full[table]
    assert bounded['output']['rendered_json_bytes'] == len(compare.rendered_bytes(bounded))
    assert bounded['output']['rendered_json_bytes'] <= compare.MAX_OUTPUT_BYTES
    assert compare.bound_output(deepcopy(bounded)) == bounded


def test_private_value_recordings_are_refused(source, recorded, monkeypatch):
    monkeypatch.setattr(query, '_query', lambda *a, **kw: b'private_records\n1\n')
    with pytest.raises(query.MetadataQueryError, match='contains-values'):
        compare.compare_windows(source, anchor_url_class=COLLECT)


@pytest.mark.parametrize('parent', ['callback', 'promise'])
def test_whole_population_is_validated_before_any_window_is_counted(source, invalid_population, parent):
    invalid_population(parent)
    with pytest.raises(ContractError, match='parent scope is inconsistent'):
        compare.compare_windows(source, windows=['1:2', '3:4'], apis=['Unknown.event'])


def test_query_digest_binds_the_window_specification(source, recorded):
    first = compare.compare_windows(source, anchor_url_class=COLLECT)
    second = compare.compare_windows(source, anchor_url_class=COLLECT, span_ns='2500')
    again = compare.compare_windows(source, anchor_url_class=COLLECT)
    assert first['query']['query_sha256'] == again['query']['query_sha256'] != second['query']['query_sha256']


def test_saved_bundle_binds_its_source_recording(source, recorded):
    export = EvidenceExport()
    try:
        prepared = export.prepare(source, ContextAttribution(), None)
        result = compare.evidence_compare(export.path, ROOT, source.resolve().executable,
            expected_sha256=prepared['sha256'], anchor_url_class=COLLECT)
        VALIDATOR.validate(result)
        assert result['bundle']['sha256'] == prepared['sha256']
        assert result['bundle']['expected_digest_matched'] is True
        assert result['source_recording']['sha256'] == result['snapshot']['sha256']
    finally:
        export.close()


def test_saved_comparison_rechecks_copy_after_origin_output_binding(source,recorded,monkeypatch):
    export=EvidenceExport()
    try:
        prepared=export.prepare(source,ContextAttribution(),None)
        original_open=compare.OpenEvidence
        opened=[]
        def open_bundle(*args,**kwargs):
            bundle=original_open(*args,**kwargs)
            opened.append(bundle)
            return bundle
        original_bound=compare.bound_output
        def bind_then_change(result):
            bounded=original_bound(result)
            if 'source_recording' in result:
                opened[0].path.write_bytes(b'\x0a\x01y')
            return bounded
        monkeypatch.setattr(compare,'OpenEvidence',open_bundle)
        monkeypatch.setattr(compare,'bound_output',bind_then_change)
        with pytest.raises(ContractError,match='verified evidence recording copy changed'):
            compare.evidence_compare(export.path,ROOT,source.resolve().executable,
                expected_sha256=prepared['sha256'],anchor_url_class=COLLECT)
    finally:
        export.close()


def test_cli_success_emits_counted_ascii_bytes(source, recorded, monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(compare, 'RecordingSource', lambda *a, **kw: source)
    status = cli.main(['trace', 'session-compare', '--session', str(tmp_path / 'owned-run.json'),
                       '--expected-run-id', 'owned-run', '--anchor-url-class', COLLECT])
    captured = capsys.readouterr()
    result = json.loads(captured.out)
    VALIDATOR.validate(result)
    assert status == 0 and captured.err == ''
    assert len(captured.out.encode('ascii')) == result['output']['rendered_json_bytes']
    assert '\r' not in captured.out and captured.out.endswith('}\n')


def test_cli_reports_bounded_comparison_population(monkeypatch, tmp_path, capsys):
    def over_limit(*args, **kwargs):
        raise compare.ComparePopulationError()

    monkeypatch.setattr(compare, 'session_compare', over_limit)
    status = cli.main(['trace', 'session-compare', '--session', str(tmp_path / 'owned-run.json'),
                       '--expected-run-id', 'owned-run', '--window', '0:10', '--window', '11:20'])
    captured = capsys.readouterr()
    result = json.loads(captured.out)
    VALIDATOR.validate(result)
    assert status == 2 and captured.err == ''
    assert result == {'schema': compare.SCHEMA, 'status': 'error',
                      'code': 'compare-population-over-limit', 'hint': compare.POPULATION_HINT}


def test_cli_rejects_short_binary_stdout_write(monkeypatch):
    class ShortOutput:
        def write(self, body):return len(body)-1
        def flush(self):pass

    monkeypatch.setattr(compare.sys, 'stdout', SimpleNamespace(buffer=ShortOutput()))
    with pytest.raises(ContractError, match='incomplete'):
        compare._emit({'schema':compare.SCHEMA,'status':'error','code':'query-unavailable'})


def test_cli_closes_broken_binary_stdout_without_retrying(monkeypatch):
    writes = []

    def broken(body):
        writes.append(body)
        raise OSError('PRIVATE_SENTINEL broken transport')

    monkeypatch.setattr(compare.sys, 'stdout', SimpleNamespace(buffer=SimpleNamespace(
        write=broken, flush=lambda: pytest.fail('broken write flushed'))))
    with pytest.raises(ContractError, match='transport failed') as caught:
        compare._emit({'schema': compare.SCHEMA, 'status': 'error', 'code': 'query-unavailable'})
    assert len(writes) == 1 and 'PRIVATE_SENTINEL' not in str(caught.value)


@pytest.mark.parametrize('route', ['session-compare', 'evidence-compare'])
@pytest.mark.parametrize('option', ['--unknown=PRIVATE_SENTINEL',
    '--max-windows=PRIVATE_SENTINEL', '--anchor-api'])
def test_actual_cli_parse_failures_are_closed(route, option):
    process = subprocess.run([sys.executable, '-m', 'browser_core', 'trace', route, option],
        cwd=ROOT, capture_output=True, timeout=30, check=False)
    assert process.returncode == 2 and process.stderr == b''
    result = json.loads(process.stdout)
    assert result == {'schema': compare.SCHEMA, 'status': 'error',
                      'code': 'compare-options-invalid', 'hint': compare.OPTION_HINT}
    assert b'PRIVATE_SENTINEL' not in process.stdout and len(process.stdout) <= compare.MAX_OUTPUT_BYTES


@pytest.mark.parametrize('args,code', [
    (['--window', '5:3', '--window', '1:2'], 'compare-options-invalid'),
    (['--window', '1:2', '--window', '3:4', '--anchor-api', 'fetch.request.start'], 'compare-options-invalid'),
    ([], 'compare-options-invalid')])
def test_cli_option_errors_are_fixed_and_carry_a_hint(tmp_path, capsys, args, code):
    status = cli.main(['trace', 'session-compare', '--session', str(tmp_path / 'owned-run.json'),
                       '--expected-run-id', 'owned-run', *args])
    captured = capsys.readouterr()
    result = json.loads(captured.out)
    VALIDATOR.validate(result)
    assert status == 2 and result['code'] == code and '--window START_NS:END_NS' in result['hint']
    assert '5:3' not in captured.out


@pytest.mark.parametrize('failure', [ContractError('PRIVATE_SENTINEL'), OSError('PRIVATE_SENTINEL'),
    query.MetadataQueryError('metadata-recording-contains-values'), KeyboardInterrupt()])
def test_cli_failures_are_closed_and_redacted(monkeypatch, tmp_path, capsys, failure):
    def fail(*a, **kw): raise failure
    monkeypatch.setattr(compare, 'RecordingSource', fail)
    status = cli.main(['trace', 'session-compare', '--session', str(tmp_path / 'owned-run.json'),
                       '--expected-run-id', 'owned-run', '--anchor-api', 'fetch.request.start'])
    captured = capsys.readouterr()
    result = json.loads(captured.out)
    VALIDATOR.validate(result)
    assert status == (130 if isinstance(failure, KeyboardInterrupt) else 2)
    assert 'PRIVATE_SENTINEL' not in captured.out and captured.err == ''


def test_evidence_cli_is_registered_with_its_own_binding_options():
    parser = cli.build_parser()
    args = parser.parse_args(['trace', 'evidence-compare', '--bundle', 'b', '--reader-executable', 'r',
                              '--anchor-api', 'fetch.request.start'])
    assert args.compare_source == 'evidence' and args.expected_sha256 is None
    with pytest.raises(SystemExit):
        parser.parse_args(['trace', 'session-compare', '--session', 's', '--expected-run-id', 'r', '--limit', '5'])


def test_null_execution_context_is_not_rendered_as_a_literal_context_id(source, recorded):
    recorded.append(_event(len(recorded)+1,40_000_000,'TreeWalker.nextNode',kind='other',
                           execution={'context_id':None}))
    result=compare.compare_windows(source,windows=['40000000:41000000','41000001:42000000'])
    VALIDATOR.validate(result)
    assert result['contexts']['rows']==[[1,'10','','other',1]]
