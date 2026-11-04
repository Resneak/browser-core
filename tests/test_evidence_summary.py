"""Counts and omissions on native-shaped data, without payload extraction."""
import csv
import io
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

import browser_core.evidence_summary as summary
from browser_core.contracts import ContractError
from browser_core.inspection_contract import CAPTURE_V1, CAPTURE_V2, CAPTURE_V3, capture_apis
from test_inspection_history import Decoder


@pytest.fixture
def decoder():
    value = Decoder()
    yield value
    value.close()


def inventory(decoder, capture=CAPTURE_V1):
    return summary.decode_summary(decoder.query(summary.summary_sql(capture), max_rows=200), capture)


@pytest.mark.parametrize('capture', [CAPTURE_V1, CAPTURE_V2, CAPTURE_V3])
def test_empty_recording_does_not_turn_known_contract_into_observed_support(decoder, capture):
    data = inventory(decoder, capture)
    assert all(value == 0 for value in data['counts'].values())
    assert {row['api'] for row in data['apis']} == capture_apis(capture)
    assert all(row['records'] == 0 and row['first_ns'] is None for row in data['apis'])
    assert data['timestamps']['first_ns'] is data['timestamps']['last_ns'] is None


def test_missing_ownership_and_bad_envelopes_remain_counted(decoder):
    base = 2**53 + 31
    for i in range(1, 9):
        decoder.add(i, base+i, value='DO_NOT_EXPOSE_PRIVATE_VALUE')
    decoder.db.execute('UPDATE __intrinsic_slice SET track_id=999 WHERE id=2')
    decoder.args[1003]['debug.schema'] = 'unexpected-schema'
    decoder.args[1004]['debug.api'] = 'DO_NOT_EXPOSE_PRIVATE_API_NAME'
    decoder.args[1005]['debug.completion'] = 'unexpected-completion'
    del decoder.args[1006]['debug.allowlist']
    del decoder.args[1007]['debug.api']
    del decoder.args[1008]['debug.completion']
    # Neither unrelated rows nor omitted-observation diagnostics are value rows.
    decoder.add(9, base+100)
    decoder.db.execute("UPDATE __intrinsic_slice SET name='BrowserCoreInspection.OmittedBinding' WHERE id=9")
    data = inventory(decoder)
    assert data['counts'] == dict(zip(summary.METRICS, (8, 7, 1, 6, 2, 4, 2, 2, 2, 1)))
    observed = [row for row in data['apis'] if row['records']]
    assert observed == [{'api': 'Navigator.userAgent.get', 'records': 2,
                         'first_ns': str(base+1), 'last_ns': str(base+2)}]
    assert data['timestamps']['last_ns'] == str(base+8)
    assert 'DO_NOT_EXPOSE' not in json.dumps(data)


def test_record_counts_include_duplicate_representations_and_tied_timestamps(decoder):
    for i in range(1, 4):
        decoder.add(i, 99)
    data = inventory(decoder)
    assert data['counts']['binding_value_records'] == 3
    assert data['counts']['completion_compatible_records'] == 3
    assert data['counts']['queryable_records'] == 3
    assert data['timestamps']['first_ns'] == data['timestamps']['last_ns'] == '99'


def test_query_never_extracts_parameters_results_contexts_or_script_labels(decoder):
    decoder.add(1, 1)
    keys = []
    def extract(arg, key):
        keys.append(key)
        if key not in ('utid', 'debug.schema', 'debug.allowlist', 'debug.api', 'debug.completion'):
            raise AssertionError('private field extraction')
        return decoder.args[arg].get(key)
    decoder.db.create_function('EXTRACT_ARG', 2, extract)
    assert inventory(decoder)['counts']['binding_value_records'] == 1
    assert set(keys) == {'utid', 'debug.schema', 'debug.allowlist', 'debug.api', 'debug.completion'}


@pytest.mark.parametrize('capture,completion,expected', [
    (CAPTURE_V2, 'input-copied', 0), (CAPTURE_V3, 'returned', 0),
    (CAPTURE_V3, 'input-copied', 1),
])
def test_version_and_completion_rules_are_not_promoted_across_contracts(decoder, capture, completion, expected):
    decoder.add(1, 1)
    decoder.args[1001].update({'debug.schema': capture['schema'], 'debug.allowlist': capture['allowlist'],
                             'debug.api': summary.CRYPTO_INPUT_API, 'debug.completion': completion})
    assert inventory(decoder, capture)['counts']['completion_compatible_records'] == expected


@pytest.mark.parametrize('change', ['missing', 'duplicate', 'unknown', 'extra', 'negative',
                                    'rounded', 'backward-time', 'inconsistent', 'oversized'])
def test_decoder_output_rejects_invalid_or_inconsistent_counts_without_echo(decoder, change):
    decoder.add(1, 10)
    body = decoder.query(summary.summary_sql(CAPTURE_V1), max_rows=200)
    rows = list(csv.reader(io.StringIO(body.decode())))
    if change == 'missing': rows.pop()
    elif change == 'duplicate': rows.append(rows[-1])
    elif change == 'unknown': rows[1][1] = 'private-do-not-echo'
    elif change == 'extra': rows[1].append('private-do-not-echo')
    elif change == 'negative': rows[1][2] = '-1'
    elif change == 'rounded': rows[1][2] = str(2**53)
    elif change == 'backward-time': rows[1][3:5] = ['11', '10']
    elif change == 'inconsistent': rows[1][2] = '2'
    stream = io.StringIO(); csv.writer(stream).writerows(rows)
    body = stream.getvalue().encode()
    if change == 'oversized': body = b'x' * (summary.MAX_SUMMARY_BYTES+1)
    with pytest.raises(ContractError) as exc:
        summary.decode_summary(body, CAPTURE_V1)
    assert 'private-do-not-echo' not in str(exc.value)


def test_decoder_output_rejects_unterminated_quoted_empty_field(decoder):
    body = decoder.query(summary.summary_sql(CAPTURE_V1), max_rows=200).rstrip(b'\r\n') + b'"'
    with pytest.raises(ContractError, match='bounded contract'):
        summary.decode_summary(body, CAPTURE_V1)


def test_decoder_output_rejects_nonbyte_native_result(decoder):
    body = decoder.query(summary.summary_sql(CAPTURE_V1), max_rows=200).decode()
    with pytest.raises(ContractError, match='bounded contract'):
        summary.decode_summary(body, CAPTURE_V1)


def test_queryable_count_cannot_be_below_forced_overlap_of_linked_and_compatible(decoder):
    decoder.add(1,10)
    rows=list(csv.reader(io.StringIO(decoder.query(
        summary.summary_sql(CAPTURE_V1),max_rows=200).decode())))
    for row in rows[1:]:
        if row[:2]==['metric','queryable_records']:
            row[2:]=['0','','']
            break
    stream=io.StringIO();csv.writer(stream).writerows(rows)
    with pytest.raises(ContractError,match='bounded contract'):
        summary.decode_summary(stream.getvalue().encode(),CAPTURE_V1)


def test_single_record_summary_cannot_span_two_native_timestamps(decoder):
    decoder.add(1,10)
    rows=list(csv.reader(io.StringIO(decoder.query(
        summary.summary_sql(CAPTURE_V1),max_rows=200).decode())))
    for row in rows[1:]:
        if row[:2]==['metric','binding_value_records']:
            row[4]='11'
            break
    stream=io.StringIO();csv.writer(stream).writerows(rows)
    with pytest.raises(ContractError,match='bounded contract'):
        summary.decode_summary(stream.getvalue().encode(),CAPTURE_V1)


def test_compatible_time_range_must_contain_compatible_api_time_range(decoder):
    decoder.add(1,10)
    decoder.add(2,20)
    decoder.args[1002]['debug.api']='unrecognized.private'
    rows=list(csv.reader(io.StringIO(decoder.query(
        summary.summary_sql(CAPTURE_V1),max_rows=200).decode())))
    for row in rows[1:]:
        if row[:2]==['metric','completion_compatible_records']:
            row[3:5]=['20','20']
            break
    stream=io.StringIO();csv.writer(stream).writerows(rows)
    with pytest.raises(ContractError,match='bounded contract'):
        summary.decode_summary(stream.getvalue().encode(),CAPTURE_V1)


@pytest.mark.parametrize('changed_range',['total','api-partition'])
def test_partition_timestamp_extrema_must_match_their_children(decoder,changed_range):
    decoder.add(1,10)
    decoder.add(2,20)
    rows=list(csv.reader(io.StringIO(decoder.query(
        summary.summary_sql(CAPTURE_V1),max_rows=200).decode())))
    for row in rows[1:]:
        if (row[0]=='metric' and row[2]=='2' and
                (changed_range=='api-partition' or row[1]=='binding_value_records')):
            row[4]='30'
    stream=io.StringIO();csv.writer(stream).writerows(rows)
    with pytest.raises(ContractError,match='bounded contract'):
        summary.decode_summary(stream.getvalue().encode(),CAPTURE_V1)


@pytest.fixture
def opened(monkeypatch, tmp_path, decoder):
    decoder.add(1, 100)
    state = SimpleNamespace(closed=0, resolved=0, calls=[])
    health_body = (b'name,severity,value\n__capture_stats_present,meta,0\n__sorter_dropped,meta,0\n'
                   b'private_diagnostic_name,error,1\n')
    build = {'provenance': 'attested-browser-core', 'executable_sha256_16': 'c'*16,
             'runtime_bundle_sha256_16': 'd'*16, 'attestation_created_at': '2026-09-14T00:00:00Z'}
    location = SimpleNamespace(executable=tmp_path/'chrome.exe', reader_runtime={
        'mode': 'compatible-reader', 'producer_build': build, 'reader_build': build})
    def resolve():
        state.resolved += 1
        return location
    def close(): state.closed += 1
    bundle = SimpleNamespace(
        path=tmp_path/'copy.pftrace', sha256='a'*64, close=close, source=SimpleNamespace(resolve=resolve),
        metadata={'capture': CAPTURE_V1, 'health': None,
                  'recording': {'sha256': 'b'*64, 'bytes': 123, 'packets': 3, 'source_bytes': 126,
                                'excluded_tail_bytes': 3, 'source_phase': 'live-prefix'}})
    def query(command, **kwargs):
        state.calls.append((command, kwargs))
        return SimpleNamespace(returncode=0, stdout=health_body if command[-1] == summary.HEALTH_SQL else
                               decoder.query(command[-1], max_rows=200))
    monkeypatch.setattr(summary, 'OpenEvidence', lambda *a, **k: bundle)
    monkeypatch.setattr(summary, 'run_with_bounded_stdout', query)
    return state, bundle


def test_saved_prefix_stays_prefix_after_decoder_eof_and_health_is_explicit(opened):
    state, bundle = opened
    data = summary.evidence_summary(Path('bundle'), Path('root'), Path('reader'))
    assert state.closed == 1 and state.resolved == 2
    assert len(state.calls) == 2
    assert 'queryable_records' not in data['counts']
    assert all(call[1]['timeout_seconds'] == 30 and call[1]['maximum_stdout'] == 131072 for call in state.calls)
    assert data['recording']['source_phase'] == 'live-prefix'
    assert data['recording']['excluded_tail_bytes'] == '3'
    assert data['semantics']['proves_capture_complete'] is False
    assert data['semantics']['private_payloads_validated'] is False
    assert data['recording_health']['status'] == 'issues-reported'
    assert data['exporter_reported_health'] is None
    assert not data['bundle']['expected_digest_matched']
    assert 'private_diagnostic_name' not in json.dumps(data)
    assert 'name_sha256' in data['recording_health']['counters'][0]


def test_summary_rechecks_copy_after_health_rendering(opened,monkeypatch):
    state,bundle=opened
    changed=[False]
    original_resolve=bundle.source.resolve
    original_summary=summary._health_summary
    def resolve():
        if changed[0]:raise ContractError('verified evidence recording copy changed')
        return original_resolve()
    def render_health(health):
        result=original_summary(health)
        if health is not None:changed[0]=True
        return result
    bundle.source.resolve=resolve
    monkeypatch.setattr(summary,'_health_summary',render_health)
    with pytest.raises(ContractError,match='verified evidence recording copy changed'):
        summary.evidence_summary(Path('bundle'),Path('root'),Path('reader'))
    assert state.closed==1


def test_stop_timeout_health_names_remain_explicit_for_agents():
    names = (
        'traced_data_source_stop_timeouts',
        'traced_data_source_stop_timeout_pending_instances',
        'traced_data_source_stop_timeout_pending_producers',
        'traced_data_source_stop_timeout_details_truncated',
    )
    health = {
        'status': 'issues-reported',
        'capture_stats_seen': True,
        'counters_truncated': False,
        'sorter_dropped_events': 0,
        'proves_complete': False,
        'counters': [
            {'name': name, 'kind': 'error', 'severity': 'error', 'value': index + 1}
            for index, name in enumerate(names)
        ],
    }
    public = summary._health_summary(health)
    assert [row['name'] for row in public['counters']] == list(names)
    assert all('name_sha256' not in row for row in public['counters'])


def test_planner_only_queryability_count_does_not_change_public_v1(opened):
    data = summary.evidence_summary(
        Path('bundle'), Path('root'), Path('reader'), include_queryability=True
    )
    assert data['counts']['queryable_records'] == 1


def test_queryability_mode_rejects_non_boolean_before_open(monkeypatch):
    monkeypatch.setattr(
        summary,
        'OpenEvidence',
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError('opened')),
    )
    with pytest.raises(ContractError, match='queryability mode'):
        summary.evidence_summary(
            Path('bundle'), Path('root'), Path('reader'), include_queryability=1
        )


@pytest.mark.parametrize('failure', ['decoder', 'metadata', 'interrupt', 'reader-change'])
def test_failure_always_closes_owned_copy_and_never_returns_partial_success(opened, monkeypatch, failure):
    state, bundle = opened
    if failure == 'reader-change':
        original = bundle.source.resolve
        def resolve():
            if state.resolved: raise ContractError('reader changed')
            return original()
        bundle.source.resolve = resolve
    else:
        def query(*a, **k):
            if failure == 'interrupt': raise KeyboardInterrupt()
            return SimpleNamespace(returncode=1 if failure == 'decoder' else 0, stdout=b'bad')
        monkeypatch.setattr(summary, 'run_with_bounded_stdout', query)
    with pytest.raises(KeyboardInterrupt if failure == 'interrupt' else ContractError):
        summary.evidence_summary(Path('bundle'), Path('root'), Path('reader'))
    assert state.closed == 1


@pytest.mark.parametrize('failure,code,status', [(ContractError('private-exception'), 'summary-unavailable', 2),
                                               (OSError('private-path'), 'summary-unavailable', 2),
                                               (KeyboardInterrupt(), 'interrupted', 130)])
def test_cli_errors_are_json_and_do_not_echo_private_details(monkeypatch, capsys, failure, code, status):
    from browser_core.cli import main
    def fail(*a, **k): raise failure
    monkeypatch.setattr(summary, 'evidence_summary', fail)
    assert main(['trace', 'evidence-summary', '--bundle', 'file', '--reader-executable', 'reader']) == status
    output = capsys.readouterr()
    assert json.loads(output.out) == {'schema': summary.SCHEMA, 'status': 'error', 'code': code}
    assert output.err == ''


def test_cli_threads_expected_digest_and_requires_explicit_reader(monkeypatch, capsys):
    from browser_core.cli import main
    seen = []
    def read(*a, **k):
        seen.append((a, k))
        return {'schema': summary.SCHEMA, 'status': 'ok'}
    monkeypatch.setattr(summary, 'evidence_summary', read)
    assert main(['trace', 'evidence-summary', '--bundle', 'file', '--reader-executable', 'reader',
                 '--expected-sha256', 'a'*64]) == 0
    assert seen[0][1]['expected_sha256'] == 'a'*64 and seen[0][0][2].is_absolute()
    with pytest.raises(SystemExit): main(['trace', 'evidence-summary', '--bundle', 'file'])


def test_schema_accepts_success_and_errors_but_rejects_unstated_claims(opened):
    import jsonschema
    contract = json.loads((Path(__file__).resolve().parents[1]/'schemas/evidence-summary-v1.schema.json').read_text())
    jsonschema.Draft202012Validator.check_schema(contract)
    validator = jsonschema.Draft202012Validator(contract)
    data = summary.evidence_summary(Path('bundle'), Path('root'), Path('reader'))
    validator.validate(data)
    validator.validate({'schema': summary.SCHEMA, 'status': 'error', 'code': 'summary-unavailable'})
    validator.validate({'schema': summary.SCHEMA, 'status': 'error', 'code': 'interrupted'})
    data['semantics']['proves_capture_complete'] = True
    with pytest.raises(jsonschema.ValidationError): validator.validate(data)
    data['semantics']['proves_capture_complete'] = False
    data['private_value'] = 'unexpected'
    with pytest.raises(jsonschema.ValidationError): validator.validate(data)
