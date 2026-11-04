"""Scope containment cannot resolve a dynamic caller's reused ScriptId."""
import hashlib
import json

import pytest

from browser_core.contracts import ContractError
from browser_core.inspection_history import history_filters
from browser_core import metadata_query, perfetto
from browser_core.trace import validate_trace
from test_evidence_bundle import BODY
from test_metadata_workflow import source
from test_perfetto import (REVISION, csv_rows_fixture, dynamic_code_row,
                          host_callback_row, promise_microtask_row, script_run_row)


def rows():
    return [script_run_row(),
            script_run_row(ts_monotonic_ns='110', context_id='reload', native_id='script:reload:7'),
            host_callback_row(context_id='reload', native_parent_id='script:reload:7'),
            promise_microtask_row(ts_monotonic_ns='210', duration_ns='30', context_id='reload'),
            dynamic_code_row(ts_monotonic_ns='220')]


def assert_unresolved(events):
    """An ambiguous caller keeps its event but selects no context or parent."""
    dynamic = [event for event in events
               if event['event'] == {'category': 'execution', 'name': 'dynamic.code.materialized'}
               or event['detail'].get('native_name') == 'BrowserCore.DynamicCodeMaterialized']
    assert dynamic, 'dynamic code event must be retained'
    event = dynamic[-1]
    assert event['detail']['caller_parent_status'] == 'caller_context_ambiguous'
    assert 'execution' not in event and 'causal_parent_seq' not in event
    return event


def decode(population):
    return perfetto.parse_export_csv(csv_rows_fixture(population), 'fixture-run', REVISION)


def validate(events, tmp_path):
    path = tmp_path/'events.jsonl'
    path.write_text('\n'.join(json.dumps(event) for event in events), encoding='utf-8')
    return validate_trace(path)


def claimed_scope_resolution(population=None, selected=1):
    """Construct the old claimed result without depending on ambiguous export."""
    population = rows() if population is None else population
    events = decode(population[:-1])
    dynamic = decode([population[selected], population[-1]])[-1]
    dynamic.update(seq=len(events), causal_parent_seq=selected,
                   callback_parent_seq=next(event['seq'] for event in reversed(events)
                                            if event['event']['name'] == 'host.callback.execution'),
                   promise_parent_seq=next(event['seq'] for event in reversed(events)
                                           if event['event']['name'] == 'promise.microtask.execution'))
    events.append(dynamic)
    return events


@pytest.mark.parametrize('selected_context,selected', [('reload', 1), ('frame-token', 0)])
def test_agreeing_complete_scopes_cannot_select_either_reused_context(selected_context, selected, tmp_path):
    population = rows()
    population[2].update(context_id=selected_context, native_parent_id=f'script:{selected_context}:7')
    population[3]['context_id'] = selected_context
    assert_unresolved(decode(population))
    events = claimed_scope_resolution(population, selected)
    assert events[-1]['callback_parent_seq'] == 2
    assert events[-1]['promise_parent_seq'] == 3
    assert events[-1]['execution'] == events[selected]['execution']
    with pytest.raises(ContractError, match='not its matching script run'):
        validate(events, tmp_path)


def test_unique_caller_keeps_complete_callback_and_promise_edges(tmp_path):
    events = decode(rows()[1:])
    assert events[-1]['causal_parent_seq'] == 0
    assert events[-1]['callback_parent_seq'] == 1
    assert events[-1]['promise_parent_seq'] == 2
    assert events[-1]['execution'] == events[0]['execution']
    validate(events, tmp_path)


@pytest.mark.parametrize('dynamic_kind', ['eval', 'function-constructor'])
def test_new_scopes_do_not_distinguish_old_retained_function_with_same_script_id(dynamic_kind, tmp_path):
    # Both New-local and New -> retained Old calls can produce these same rows.
    # The callback is New's function, not the dynamic caller frame; neither scope
    # records the synchronous cross-realm call or that frame's context.
    population = [
        script_run_row(context_id='Old', native_id='script:Old:7'),
        script_run_row(ts_monotonic_ns='110', context_id='New', native_id='script:New:7'),
        promise_microtask_row(context_id='New'),
        host_callback_row(context_id='New', native_parent_id='script:New:7'),
        dynamic_code_row(ts_monotonic_ns='220', dynamic_kind=dynamic_kind),
    ]
    assert_unresolved(decode(population))
    events = claimed_scope_resolution(population)
    assert events[3]['execution'] == events[1]['execution']
    assert events[3]['causal_parent_seq'] == 1
    assert events[3]['promise_parent_seq'] == 2
    assert events[2]['execution']['context_id'] == 'New'
    assert events[-1]['callback_parent_seq'] == 3
    assert events[-1]['promise_parent_seq'] == 2
    with pytest.raises(ContractError, match='not its matching script run'):
        validate(events, tmp_path)


@pytest.mark.parametrize('omitted', [(2,), (3,), (2, 3)])
def test_missing_scope_kinds_do_not_resolve_reused_caller(omitted):
    assert_unresolved(decode([row for index, row in enumerate(rows()) if index not in omitted]))


@pytest.mark.parametrize('index', [2, 3])
@pytest.mark.parametrize('change', [
    {'duration_ns': '-1'}, {'duration_ns': '0'}, {'duration_ns': '1'},
    {'track_id': '10'}, {'tid': '44'}, {'pid': '44'},
])
def test_partial_expired_or_other_execution_scope_never_disambiguates(index, change):
    population = rows()
    population[index].update(change)
    assert_unresolved(decode(population))


@pytest.mark.parametrize('timestamp', ['240', '250', '300'])
def test_ended_scopes_do_not_resolve_reused_caller(timestamp):
    population = rows()
    population[-1]['ts_monotonic_ns'] = timestamp
    assert_unresolved(decode(population))


@pytest.mark.parametrize('index', [2, 3])
def test_conflicting_scope_contexts_refuse(index):
    population = rows()
    population[index]['context_id'] = 'frame-token'
    if index == 2:
        population[index]['native_parent_id'] = 'script:frame-token:7'
    assert_unresolved(decode(population))


def test_other_track_candidate_stays_ambiguous():
    population = rows()
    population[1]['track_id'] = '10'
    assert_unresolved(decode(population))


def test_mismatched_callback_script_stays_ambiguous():
    population = rows()
    population[2].update(script_id='8', native_parent_id='script:reload:8')
    assert_unresolved(decode(population))


@pytest.mark.parametrize('kind', ['callback', 'promise'])
@pytest.mark.parametrize('context,complete', [('frame-token', True), ('reload', False), ('reload', True)])
def test_nested_scopes_cannot_resolve_reused_caller(kind, context, complete):
    population = rows()
    factory = host_callback_row if kind == 'callback' else promise_microtask_row
    outer = factory(ts_monotonic_ns='180', duration_ns='100' if complete else '-1', context_id=context)
    if kind == 'callback':
        outer['native_parent_id'] = f'script:{context}:7'
    population.insert(2, outer)
    assert_unresolved(decode(population))


@pytest.mark.parametrize('version', [1, 2])
@pytest.mark.parametrize('hidden', [False, True])
def test_resolved_export_still_validates_entire_population(source, monkeypatch, version, hidden):
    population = rows()[1:]
    population.append(script_run_row(ts_monotonic_ns='230', context_id='unrelated',
                                    script_id='9', native_id='script:unrelated:9'))
    def export(processor, trace, path, run_id, revision):
        events = perfetto.parse_export_csv(csv_rows_fixture(population), run_id, revision)
        path.write_text('\n'.join(json.dumps(event) for event in events), encoding='utf-8')
        return {'report': {'source_trace': {'sha256': hashlib.sha256(BODY).hexdigest()}}}
    monkeypatch.setattr(metadata_query, 'export_perfetto', export)
    with pytest.raises(ContractError, match='parent scope is inconsistent'):
        metadata_query.metadata_query(source, filters=history_filters(apis=['Unknown.event'] if hidden else []),
                                      limit=1, metadata_version=version)


@pytest.mark.parametrize('version', [1, 2])
@pytest.mark.parametrize('hidden', [False, True])
@pytest.mark.parametrize('portable', [False, True])
def test_ambiguous_scopes_keep_query_available(source, monkeypatch, version, hidden, portable):
    def export(processor, trace, path, run_id, revision):
        events = (claimed_scope_resolution() if portable else
                  perfetto.parse_export_csv(csv_rows_fixture(rows()), run_id, revision))
        for event in events:
            event['run_id'] = run_id
        path.write_text('\n'.join(json.dumps(event) for event in events), encoding='utf-8')
        return {'report': {'source_trace': {'sha256': hashlib.sha256(BODY).hexdigest()}}}
    monkeypatch.setattr(metadata_query, 'export_perfetto', export)
    options = dict(filters=history_filters(apis=['Unknown.event'] if hidden else []),
                   limit=1, metadata_version=version)
    if portable:
        # A forged resolution of the ambiguous caller is still rejected.
        with pytest.raises(ContractError, match='not its matching script run'):
            metadata_query.metadata_query(source, **options)
        return
    result = metadata_query.metadata_query(source, **options)
    assert result['status'] == 'ok'
    assert result['query']['matching_events'] == ('0' if hidden else '5')


@pytest.mark.parametrize('with_scopes', [False, True])
def test_unresolved_caller_is_retained_with_exact_status(with_scopes, tmp_path):
    events = decode(rows() if with_scopes else [rows()[0], rows()[1], rows()[-1]])
    event = assert_unresolved(events)
    assert event['seq'] == (4 if with_scopes else 2)
    assert event['detail']['caller_script_id'] == 7
    assert event['detail']['caller_status'] == 'observed'
    # The retained population is still a valid trace, and neither candidate
    # context was assigned to the dynamic code event.
    validate(events, tmp_path)  # raises on any invalid edge


@pytest.mark.parametrize('mutation', [
    'no-callback-edge', 'no-promise-edge', 'open-callback', 'open-promise',
    'wrong-script-parent', 'wrong-callback-parent', 'callback-other-script',
    'callback-ended', 'promise-ended', 'dynamic-other-thread', 'dynamic-other-pid',
    'promise-other-context',
])
def test_portable_validator_independently_rejects_forged_resolution(mutation, tmp_path):
    events = claimed_scope_resolution()
    callback, promise, dynamic = events[2:]
    if mutation == 'no-callback-edge':
        del dynamic['callback_parent_seq']
    elif mutation == 'no-promise-edge':
        del dynamic['promise_parent_seq']
    elif mutation.startswith('open-'):
        scope = callback if mutation == 'open-callback' else promise
        scope['detail']['completion'] = 'open'
        del scope['detail']['duration_ns']
    elif mutation == 'wrong-script-parent':
        dynamic['causal_parent_seq'] = 0
    elif mutation == 'wrong-callback-parent':
        callback['causal_parent_seq'] = 0
    elif mutation == 'callback-other-script':
        callback['execution']['script_id'] = 'v8:42:reload:8'
        del callback['causal_parent_seq']
        callback['detail']['causal_parent_status'] = 'script_parent_not_in_trace'
    elif mutation == 'callback-ended':
        callback['detail']['duration_ns'] = 20
    elif mutation == 'promise-ended':
        promise['detail']['duration_ns'] = 10
    elif mutation == 'dynamic-other-thread':
        dynamic['detail']['thread_id'] = 44
    elif mutation == 'dynamic-other-pid':
        dynamic['process']['pid'] = 44
    elif mutation == 'promise-other-context':
        promise['execution'] = {'context_id': 'frame-token', 'frame_id': 'frame-token'}
    with pytest.raises(ContractError):
        validate(events, tmp_path)


@pytest.mark.parametrize('kind', ['callback', 'promise'])
@pytest.mark.parametrize('condition', ['conflicting', 'open', 'stale-link'])
def test_portable_reused_caller_rejects_with_unlinked_active_scope_population(
    kind, condition, tmp_path
):
    population = rows()
    factory = host_callback_row if kind == 'callback' else promise_microtask_row
    context = 'frame-token' if condition == 'conflicting' else 'reload'
    extra = factory(ts_monotonic_ns='215',
                    duration_ns='-1' if condition == 'open' else '100',
                    context_id=context)
    if kind == 'callback':
        extra['native_parent_id'] = f'script:{context}:7'
    independent_scope = decode([population[0], population[1], extra])[-1]
    events = claimed_scope_resolution(population)
    independent_scope['seq'] = 4
    independent_scope.pop('callback_parent_seq', None)
    independent_scope.pop('promise_parent_seq', None)
    events[-1]['seq'] = 5
    events.insert(-1, independent_scope)
    with pytest.raises(ContractError, match='not its matching script run'):
        validate(events, tmp_path)
