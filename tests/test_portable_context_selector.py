"""Synthetic portable-context selection; no browser or private reader involved."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from browser_core import cli, evidence_query, metadata_query as query, session_query
from browser_core.contracts import ContractError
from browser_core.control_files import canonical_json_bytes
from browser_core.inspection_contract import CAPTURE_OFF, CAPTURE_V1
from browser_core.inspection_history import history_filters
from test_metadata_workflow import events, invalid_population, source
from test_metadata_versions import validator

ROOT = Path(__file__).resolve().parents[1]
SELECTOR = {'pid': '10', 'context_id': 'ABCD'}


@pytest.fixture
def population(events):
    for event, (pid, context) in zip(events, [
            (10, 'ABCD'), (10, 'ABCD'), (20, 'ABCD'), (20, 'ABCD'),
            (10, 'abcd'), (10, 'worker-label'), (10, None)]):
        event['process']['pid'] = pid
        event['execution'] = None if context is None else {
            'context_id': context, 'script_id': f'v8:{pid}:{context}:7',
            'worker_id' if context == 'worker-label' else 'frame_id': context}
    return events


@pytest.mark.parametrize('version', [1, 2])
@pytest.mark.parametrize('selector,expected', [
    (SELECTOR, [1, 0]), ({'pid': '20', 'context_id': 'ABCD'}, [3, 2]),
    ({'pid': '10', 'context_id': 'abcd'}, [4]),
    ({'pid': '10', 'context_id': 'worker-label'}, [5]),
    ({'pid': '30', 'context_id': 'ABCD'}, []),
    ({'pid': '10', 'context_id': 'absent'}, []),
])
def test_exact_pair_separates_reused_context_labels_and_script_numbers(
        source, population, version, selector, expected):
    filters = history_filters(script='7')
    original = deepcopy(filters)
    result = query.metadata_query(source, filters=filters, portable_context=selector,
                                  limit=10, metadata_version=version)
    validator(version).validate(result)
    assert [event['seq'] for event in result['events']] == expected
    assert result['query']['matching_events'] == str(len(expected))
    assert result['query']['filters']['portable_context'] == selector
    assert filters == original
    assert result['semantics']['proves_capture_complete'] is False
    assert result['semantics']['server_side_architecture_observed'] is False
    if version == 2:
        inventory = result['inventory']
        assert inventory['matching_events'] == str(len(expected))
        assert inventory['analyst_instrumentation']['event_ownership'] == 'unresolved'
        assert inventory['source_url_to_script_mapping_established'] is False
        assert inventory['context_identity_proves_process_isolation'] is False
        assert all((group['pid'], group['context_id']) ==
                   (selector['pid'], selector['context_id'])
                   for group in inventory['contexts']['groups'])


def test_selector_intersects_existing_filters_and_excludes_missing_context(source, population):
    result = query.metadata_query(source, portable_context=SELECTOR,
        filters=history_filters(script='7', context='window',
                                apis=['Navigator.language.get'], start_ns='101', end_ns='104'),
        limit=1)
    assert [event['seq'] for event in result['events']] == [1]
    result = query.metadata_query(source, portable_context=SELECTOR,
                                  filters=history_filters(context='worker'), limit=1)
    assert result['events'] == []
    result = query.metadata_query(source, portable_context={'pid': '10', 'context_id': 'None'},
                                  filters=history_filters(), limit=1)
    assert result['events'] == []


@pytest.mark.parametrize('version', [1, 2])
def test_selector_is_bound_into_digest_and_all_cursor_pages(source, population, version):
    options = dict(filters=history_filters(), limit=1, bundle_sha256='a' * 64,
                   metadata_version=version, portable_context=SELECTOR)
    first = query.metadata_query(source, **options)
    second = query.metadata_query(source, cursor=first['query']['next_cursor'], **options)
    assert [event['seq'] for page in (first, second) for event in page['events']] == [1, 0]
    assert second['query']['next_cursor'] is None
    assert first['query']['snapshot_max_seq'] == '6'
    assert first['query']['matching_events'] == second['query']['matching_events'] == '2'
    digest = hashlib.sha256(canonical_json_bytes({
        'schema': first['schema'], 'filters': {**history_filters(), 'portable_context': SELECTOR},
        'limit': 1, 'ordering': 'timestamp-descending-then-sequence-descending'})).hexdigest()
    assert first['query']['query_sha256'] == digest
    for changed in (None, {'pid': '20', 'context_id': 'ABCD'},
                    {'pid': '10', 'context_id': 'abcd'}):
        with pytest.raises(ContractError, match='cursor is invalid'):
            query.metadata_query(source, cursor=first['query']['next_cursor'],
                                 **{**options, 'portable_context': changed})
    unfiltered = query.metadata_query(source, **{**options, 'portable_context': None})
    with pytest.raises(ContractError, match='cursor is invalid'):
        query.metadata_query(source, cursor=unfiltered['query']['next_cursor'], **options)


@pytest.mark.parametrize('version,expected', [
    (1, '8aaaac57c939775823acb91cc9d87764fe00d7333fe5fb4ad5353f98abadcaf1'),
    (2, 'aca4d12328f369c8302479bf045640840b7a781a0a3795147622abcef4e036ae'),
])
def test_unselected_responses_preserve_pre_candidate_bytes(source, events, version, expected):
    # Hashes recorded from the unmodified source before adding this selector,
    # including the saved-query cursor, response semantics and v2 inventory.
    options = dict(filters=history_filters(), limit=2, bundle_sha256='a' * 64,
                   metadata_version=version)
    for result in (query.metadata_query(source, **options),
                   query.metadata_query(source, portable_context=None, **options)):
        assert hashlib.sha256(canonical_json_bytes(result)).hexdigest() == expected


class DictSubclass(dict):
    pass


class StringSubclass(str):
    pass


BAD_SELECTORS = [
    {}, [], (), '', 'ABCD', True, 10, DictSubclass(SELECTOR),
    {'pid': '10'}, {'context_id': 'ABCD'}, {**SELECTOR, 'realm_id': '0'},
    *[{'pid': pid, 'context_id': 'ABCD'} for pid in
      (None, True, 10, 1.0, [], {}, '', '0', '-1', '+10', '010', '10.0',
       '1e1', ' 10', '10\n', '\u0661', '9' * 20, str(2**63), StringSubclass('10'))],
    *[{'pid': '10', 'context_id': context} for context in
      (None, True, 10, [], {}, '', 'a' * 257, '\u00e9' * 129, 'a\n', 'a\0',
       'a\x7f', '\ud800', StringSubclass('ABCD'))],
]


@pytest.mark.parametrize('selector', BAD_SELECTORS)
@pytest.mark.parametrize('entry', ['metadata', 'session', 'evidence'])
def test_bad_selector_rejected_before_source_access(selector, entry):
    with pytest.raises(ContractError, match='portable context selector'):
        if entry == 'metadata':
            query.metadata_query(None, filters=history_filters(), limit=1,
                                 portable_context=selector)
        elif entry == 'session':
            session_query.session_query(None, None, expected_run_id=None,
                                        portable_context=selector)
        else:
            evidence_query.evidence_query(None, None, None, portable_context=selector)


@pytest.mark.parametrize('selector', [None, *BAD_SELECTORS])
def test_filter_dictionary_cannot_bypass_selector_validation(selector):
    with pytest.raises(ContractError, match='portable context selector'):
        query.metadata_query(None, filters={**history_filters(), 'portable_context': selector}, limit=1)


def test_filter_dictionary_can_replay_and_never_mutates_selector(source, population):
    selector = dict(SELECTOR)
    filters = history_filters()
    result = query.metadata_query(source, filters=filters, portable_context=selector, limit=1)
    selector['pid'] = '20'
    assert result['query']['filters']['portable_context'] == SELECTOR
    replay = query.metadata_query(source, filters=result['query']['filters'], limit=1)
    assert replay == result
    with pytest.raises(ContractError, match='duplicated'):
        query.metadata_query(None, filters=result['query']['filters'],
                             portable_context=SELECTOR, limit=1)


@pytest.mark.parametrize('context', ['bindings:10:20', '\u00e9' * 128, 'a' * 256])
def test_bounded_portable_labels_are_exact(context):
    selector = {'pid': str(2**63 - 1), 'context_id': context}
    assert query.portable_context_selector(selector) == selector


@pytest.mark.parametrize('version', [1, 2])
@pytest.mark.parametrize('parent', ['callback', 'promise'])
@pytest.mark.parametrize('phase', ['live-prefix', 'finalized-recording', 'recovered-prefix'])
def test_invalid_population_outside_selected_context_still_fails(
        source, invalid_population, version, parent, phase):
    invalid_population(parent)
    source.resolve().phase = phase
    with pytest.raises(ContractError, match='parent scope is inconsistent'):
        query.metadata_query(source, filters=history_filters(), limit=1, metadata_version=version,
            portable_context={'pid': '999', 'context_id': 'unmatched-context'})


@pytest.fixture
def route_setup(source, monkeypatch, tmp_path):
    closed = []
    def setup(route):
        if route == 'session-query':
            monkeypatch.setattr(session_query, 'RecordingSource', lambda *a, **kw: source)
            args = ['--session', str(tmp_path / 'owned-run.json'), '--expected-run-id', 'owned-run']
        else:
            bundle = SimpleNamespace(metadata={'capture': CAPTURE_OFF}, source=source,
                                     sha256='a' * 64, close=lambda: closed.append(True))
            monkeypatch.setattr(evidence_query, 'OpenEvidence', lambda *a, **kw: bundle)
            args = ['--bundle', str(tmp_path / 'bundle'),
                    '--reader-executable', str(tmp_path / 'reader.exe')]
        return args, closed
    return setup


@pytest.mark.parametrize('route', ['session-query', 'evidence-query'])
@pytest.mark.parametrize('version', [1, 2])
def test_cli_routes_to_selected_validated_metadata(route_setup, population, capsys, route, version):
    args, closed = route_setup(route)
    assert cli.main(['trace', route, *args, '--metadata-version', str(version),
                     '--portable-pid', '20', '--portable-context-id', 'ABCD', '--limit', '1']) == 0
    result = json.loads(capsys.readouterr().out)
    validator(version).validate(result)
    assert [event['seq'] for event in result['events']] == [3]
    assert result['query']['matching_events'] == '2'
    assert result['query']['filters']['portable_context'] == {'pid': '20', 'context_id': 'ABCD'}
    if route == 'session-query':
        assert result['query']['next_cursor'] is None
    else:
        assert result['query']['next_cursor'] is not None
        assert closed == [True]


@pytest.mark.parametrize('route', ['session-query', 'evidence-query'])
@pytest.mark.parametrize('options', [
    ['--portable-pid', '10'], ['--portable-context-id', 'private-sentinel'],
    ['--portable-pid', '010', '--portable-context-id', 'private-sentinel'],
    ['--portable-pid', '10', '--portable-context-id', 'private-sentinel\n'],
])
def test_cli_bad_selector_is_bounded_and_inert(monkeypatch, tmp_path, capsys, route, options):
    def forbidden(*a, **kw):
        raise AssertionError('invalid selector must fail before recording access')
    monkeypatch.setattr(session_query, 'RecordingSource', forbidden)
    monkeypatch.setattr(evidence_query, 'OpenEvidence', forbidden)
    args = (['--session', str(tmp_path / 'owned-run.json'), '--expected-run-id', 'owned-run']
            if route == 'session-query' else
            ['--bundle', str(tmp_path / 'bundle'), '--reader-executable', str(tmp_path / 'reader.exe')])
    assert cli.main(['trace', route, *args, *options]) == 2
    output = capsys.readouterr()
    assert output.err == ''
    assert json.loads(output.out) == {'schema': 'browser-core.evidence-query/1',
                                      'status': 'error', 'code': 'query-unavailable'}


@pytest.mark.parametrize('route', ['session-query', 'evidence-query'])
def test_legacy_private_realm_selector_stays_unavailable(route_setup, population, capsys, route):
    args, _ = route_setup(route)
    assert cli.main(['trace', route, *args, '--pid', '10', '--context-id', 'AB'*16,
                     '--realm-id', '0', '--portable-pid', '10', '--portable-context-id', 'ABCD']) == 2
    assert json.loads(capsys.readouterr().out)['code'] == 'metadata-realm-filter-unavailable'


@pytest.mark.parametrize('route', ['session', 'evidence'])
def test_private_recording_rejects_selector_before_inspector(source, monkeypatch, tmp_path, route):
    def forbidden(*a, **kw):
        raise AssertionError('portable selection must not open a private reader')
    monkeypatch.setattr(session_query, 'IncrementalInspection', forbidden)
    monkeypatch.setattr(evidence_query, 'IncrementalInspection', forbidden)
    source.resolve().session['value_capture'] = CAPTURE_V1
    with pytest.raises(ContractError, match='portable context selector requires metadata-only'):
        if route == 'session':
            monkeypatch.setattr(session_query, 'RecordingSource', lambda *a, **kw: source)
            session_query.session_query(tmp_path / 'owned-run.json', ROOT,
                                        expected_run_id='owned-run', portable_context=SELECTOR)
        else:
            closed = []
            bundle = SimpleNamespace(metadata={'capture': CAPTURE_V1}, close=lambda: closed.append(True))
            monkeypatch.setattr(evidence_query, 'OpenEvidence', lambda *a, **kw: bundle)
            try:
                evidence_query.evidence_query(tmp_path / 'bundle', ROOT, tmp_path / 'reader.exe',
                                              portable_context=SELECTOR)
            finally:
                assert closed == [True]
