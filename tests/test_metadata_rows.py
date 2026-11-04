"""Focused rows: exact wire budget, frozen legacy boundaries and hostile inputs."""
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

from browser_core import cli, metadata_rows as rows, metadata_query as query
from browser_core.contracts import ContractError
from browser_core.evidence_bundle import EvidenceExport
from browser_core.inspection_attribution import ContextAttribution
from browser_core.inspection_contract import CAPTURE_OFF, CAPTURE_V1, CAPTURE_V2, CAPTURE_V3
from browser_core.inspection_history import history_filters
from browser_core.perfetto import parse_export_csv
from test_metadata_workflow import source, events, invalid_population, REVISION
from test_metadata_inventory_query import BAD_OPTIONS as INVENTORY_BAD_OPTIONS
from test_perfetto import csv_rows_fixture, script_run_row

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = json.loads((ROOT/'schemas/metadata-rows-v1.schema.json').read_text())
jsonschema.Draft202012Validator.check_schema(SCHEMA)
VALIDATOR = jsonschema.Draft202012Validator(SCHEMA)


def rendered(result):
    return json.dumps(result, indent=2, sort_keys=True, ensure_ascii=True, allow_nan=False).encode('ascii')


def population(events, count, *, wide=False, ties=False):
    template = deepcopy(events[0])
    events.clear()
    for i in range(count):
        event = deepcopy(template)
        event['seq'] = i
        event['ts_monotonic_ns'] = 100 if ties else 100+i
        if wide:
            event['execution'] = {'context_id':'é'*120, 'worker_id':'é'*120,
                                  'script_id':'v8:10:'+'é'*120+':7'}
            event['event']['name'] = 'A.'+'x'*250
        events.append(event)


def test_fixed_projection_keeps_identity_counts_and_complete_25_rows(source, events):
    population(events, 25)
    result = rows.metadata_rows(source)
    VALIDATOR.validate(result)
    assert len(result['rows']) == result['query']['returned_events'] == 25
    assert result['query']['matching_events'] == '25'
    assert result['query']['more_available'] is False
    assert result['query']['output_limited'] is False
    assert result['query']['next_cursor'] is None
    assert [r['seq'] for r in result['rows']] == [str(i) for i in reversed(range(25))]
    assert result['reader_runtime'] == source.resolve().reader_runtime
    assert result['producer_chromium_revision'] == REVISION
    assert result['run_id'] == 'owned-run'
    assert result['recording_health']['proves_complete'] is False
    assert result['output']['rendered_json_bytes'] == len(rendered(result)) <= 16384
    assert result['output']['transport_truncated'] is None
    assert result['semantics']['population_validated_before_filtering']
    assert not result['semantics']['continuation_supported']
    assert result['semantics']['continuation'] == 'collect-immutable-bundle-for-continuation'
    assert 'events' not in result and 'inventory' not in result
    assert set(result['rows'][0]) == {'seq','timestamp_ns','pid','api','category','context','script_id','parents','request'}


def test_request_metadata_is_same_event_only_and_requires_exact_request_name(source, events):
    common = {'context_id':'frame-token', 'context_kind':'frame', 'script_id':'7', 'component':'blink.fetch'}
    events[:] = parse_export_csv(csv_rows_fixture([
        script_run_row(),
        {**common, 'ts_monotonic_ns':'101','native_name':'BrowserCore.FetchCall',
         'event_category':'api','event_name':'fetch','native_id':'fetch-api:frame-token:1',
         'native_parent_id':'script:frame-token:7'},
        {**common, 'ts_monotonic_ns':'102','native_name':'BrowserCore.FetchRequestStart',
         'event_category':'network','event_name':'fetch.request.start','native_id':'fetch-request:frame-token:1',
         'native_parent_id':'fetch-api:frame-token:1','request_id':'fetch-request:frame-token:1',
         'method':'POST','url_class':'https:same-origin:/probe','target_scope':'loopback','body_bytes':'4'}
    ]), 'owned-run', REVISION)
    api_only = rows.metadata_rows(source, apis=['fetch'])
    assert api_only['query']['matching_events'] == '1' and api_only['rows'][0]['request'] is None
    both = rows.metadata_rows(source, apis=['fetch', 'fetch.request.start'])
    VALIDATOR.validate(both)
    assert both['query']['matching_events'] == '2'
    assert both['rows'][0]['request'] == {'id':'fetch-request:frame-token:1', 'method':'POST',
        'url_class':'https:same-origin:<redacted>', 'body_bytes':'4', 'target_scope':'loopback'}
    assert both['rows'][0]['parents']['causal_parent_seq'] == both['rows'][1]['seq']
    assert both['rows'][1]['request'] is None
    assert both['semantics']['request_metadata'] == 'same-event-only-no-inferred-join'


@pytest.mark.parametrize('limit', [1, 25, 100])
@pytest.mark.parametrize('wide,ties', [(False,False),(True,False),(True,True)])
def test_immutable_pagination_is_complete_without_duplicate_or_cut_rows(source, events, limit, wide, ties):
    population(events, 75, wide=wide, ties=ties)
    options = dict(limit=limit, bundle_sha256='a'*64)
    seen, cursor = [], None
    for _ in range(76):
        page = rows.metadata_rows(source, cursor=cursor, **options)
        VALIDATOR.validate(page)
        assert page['query']['matching_events'] == '75'
        assert page['query']['returned_events'] == len(page['rows']) > 0
        assert page['output']['rendered_json_bytes'] == len(rendered(page)) <= 16384
        assert page['output']['byte_limit_applied'] == page['query']['output_limited']
        seen.extend(int(row['seq']) for row in page['rows'])
        cursor = page['query']['next_cursor']
        assert bool(cursor) == page['query']['more_available']
        if cursor is None:
            break
    else:
        pytest.fail('pagination did not terminate')
    assert seen == list(reversed(range(75)))


@pytest.mark.parametrize('change', ['bundle','limit','api','time','context','legacy'])
def test_cursor_is_bound_to_bundle_exact_query_and_distinct_schema(source, events, change):
    options = dict(bundle_sha256='a'*64, limit=1)
    page = rows.metadata_rows(source, **options)
    cursor = page['query']['next_cursor']
    if change == 'bundle': options['bundle_sha256'] = 'b'*64
    elif change == 'limit': options['limit'] = 2
    elif change == 'api': options['apis'] = ['Navigator.language.get']
    elif change == 'time': options['start_ns'] = '102'
    elif change == 'context': options['portable_context'] = {'pid':'10','context_id':'ABCD'}
    with pytest.raises(ContractError, match='cursor is invalid'):
        if change == 'legacy': query.metadata_query(source, filters=history_filters(), cursor=cursor, **options)
        else: rows.metadata_rows(source, cursor=cursor, **options)
    legacy = query.metadata_query(source, filters=history_filters(), limit=1, bundle_sha256='a'*64)
    with pytest.raises(ContractError, match='cursor is invalid'):
        rows.metadata_rows(source, cursor=legacy['query']['next_cursor'], limit=1, bundle_sha256='a'*64)


def test_cursor_snapshot_highwater_change_rejects_and_empty_match_is_honest(source, events):
    page = rows.metadata_rows(source, limit=1, bundle_sha256='a'*64)
    events.pop()
    with pytest.raises(ContractError, match='snapshot changed'):
        rows.metadata_rows(source, limit=1, bundle_sha256='a'*64, cursor=page['query']['next_cursor'])
    empty = rows.metadata_rows(source, apis=['Unknown.event'])
    VALIDATOR.validate(empty)
    assert empty['rows'] == [] and empty['query']['matching_events'] == '0'
    assert not empty['query']['more_available'] and not empty['query']['output_limited']


BAD_OPTIONS = [
    *(opt for opt in INVENTORY_BAD_OPTIONS if not ({'inventory_version','analyst_activity'} & opt.keys())),
    *({'rows_version':v} for v in (None, True, 1.0, '1', 0, 2, [], {})),
    *({'limit':v} for v in (None, True, False, 1.0, '25', 0, 101, [], {})),
    *({'cursor':v} for v in (True, 0, [], {}, '', 'x'*1025, 'bad/secret', 'é', '\ud800')),
]


@pytest.mark.parametrize('options', BAD_OPTIONS)
@pytest.mark.parametrize('route', ['metadata','session','evidence'])
def test_bad_filters_and_options_reject_before_io(monkeypatch, tmp_path, options, route):
    def forbidden(*a, **k): pytest.fail('malformed option accessed a source')
    monkeypatch.setattr(rows, 'RecordingSource', forbidden)
    monkeypatch.setattr(rows, 'OpenEvidence', forbidden)
    with pytest.raises(ContractError):
        if route == 'metadata': rows.metadata_rows(SimpleNamespace(resolve=forbidden), **options)
        elif route == 'session': rows.session_rows(tmp_path/'owned-run.json', ROOT, expected_run_id='owned-run', **options)
        else: rows.evidence_rows(tmp_path/'bundle', ROOT, tmp_path/'chrome.exe', **options)


@pytest.mark.parametrize('options', [{'include_values':True},{'fields':['value']},{'scope':{}},
    {'filters':{}},{'metadata_version':2},{'analyst_activity':['browser-control']},{'search':'secret'}])
@pytest.mark.parametrize('route', ['metadata','session','evidence'])
def test_unknown_fields_and_private_options_are_not_silently_accepted(route, options):
    with pytest.raises(TypeError):
        if route == 'metadata': rows.metadata_rows(None, **options)
        elif route == 'session': rows.session_rows(None, None, expected_run_id=None, **options)
        else: rows.evidence_rows(None, None, None, **options)


@pytest.mark.parametrize('parent', ['callback','promise'])
@pytest.mark.parametrize('filter_options', [{'apis':['Unknown.event']},{'start_ns':'999999'},
    {'end_ns':'1'}, {'portable_context':{'pid':'999','context_id':'absent'}}, {'limit':1}])
def test_invalid_population_cannot_hide_outside_window_filter_or_page(source, invalid_population, parent, filter_options):
    invalid_population(parent)
    with pytest.raises(ContractError, match='parent scope is inconsistent'):
        rows.metadata_rows(source, **filter_options)


def test_malformed_projected_identity_outside_filter_rejected(source, events):
    events[0]['execution']['context_id'] = ['PRIVATE_SENTINEL']
    with pytest.raises(ContractError, match='trace execution identity is invalid'):
        rows.metadata_rows(source, start_ns='999999')


@pytest.mark.parametrize('capture', [CAPTURE_V1,CAPTURE_V2,CAPTURE_V3])
@pytest.mark.parametrize('route', ['metadata','session','evidence'])
def test_private_capture_never_reaches_decoder(source, monkeypatch, tmp_path, capture, route):
    source.resolve().session['value_capture'] = capture
    def forbidden(*a, **k): pytest.fail('private source reached decoder')
    monkeypatch.setattr(query, '_query', forbidden)
    monkeypatch.setattr(query, 'export_perfetto', forbidden)
    monkeypatch.setattr(rows, 'RecordingSource', lambda *a, **k:source)
    closed = []
    monkeypatch.setattr(rows, 'OpenEvidence', lambda *a, **k:SimpleNamespace(
        metadata={'capture':capture}, close=lambda:closed.append(True)))
    with pytest.raises(ContractError, match='value-free capture'):
        if route == 'metadata': rows.metadata_rows(source)
        elif route == 'session': rows.session_rows(tmp_path/'owned-run.json', ROOT, expected_run_id='owned-run')
        else: rows.evidence_rows(tmp_path/'bundle', ROOT, tmp_path/'chrome.exe')
    assert closed == ([True] if route == 'evidence' else [])


@pytest.mark.parametrize('body', [b'private_records\n1\n',b'private_records\nunknown-secret\n',b''])
def test_false_off_capture_fails_before_export(source, monkeypatch, body):
    monkeypatch.setattr(query, '_query', lambda *a, **k:body)
    monkeypatch.setattr(query, 'export_perfetto', lambda *a, **k:pytest.fail('private export opened'))
    with pytest.raises(ContractError): rows.metadata_rows(source)


def test_unprojected_detail_value_and_extra_fields_cannot_escape(source, events, monkeypatch):
    events[0]['detail']['fixture_note'] = 'PRIVATE_SENTINEL_DETAIL'
    events[0]['provenance']['fixture_note'] = 'PRIVATE_SENTINEL_PROVENANCE'
    events[0]['process']['fixture_note'] = 'PRIVATE_SENTINEL_PROCESS'
    events[0]['execution']['fixture_note'] = 'PRIVATE_SENTINEL_EXECUTION'
    events[0]['value'] = {'redaction':'metadata','fixture_note':'PRIVATE_SENTINEL_VALUE'}
    import browser_core.incremental_inspection as private
    monkeypatch.setattr(private, 'IncrementalInspection', lambda *a, **k:pytest.fail('private reader opened'))
    before = source.resolve().path.read_bytes()
    result = rows.metadata_rows(source)
    assert b'PRIVATE_SENTINEL' not in rendered(result)
    assert source.resolve().path.read_bytes() == before
    assert result['semantics']['private_values_included'] is False
    assert result['semantics']['private_value_records'] == 0


@pytest.mark.parametrize('phase', ['live-prefix','recovered-prefix','interrupted-recording','limited-recording'])
def test_real_bundle_preserves_origin_identity_and_incomplete_tail(source, events, phase):
    source.resolve().phase = phase
    source.resolve().path.write_bytes(source.resolve().path.read_bytes()+b'\x0a\x05abc')
    export = EvidenceExport()
    try:
        prepared = export.prepare(source, ContextAttribution(), None)
        original = export.path.read_bytes()
        result = rows.evidence_rows(export.path, ROOT, source.resolve().executable,
            expected_sha256=prepared['sha256'], limit=1)
        VALIDATOR.validate(result)
        assert result['source_recording']['source_phase'] == phase
        assert result['source_recording']['source_bytes'] == '8'
        assert result['source_recording']['excluded_tail_bytes'] == '5'
        assert result['snapshot']['source_phase'] == 'finalized-recording'
        assert result['snapshot']['source_bytes'] == '3'
        assert result['bundle']['sha256'] == prepared['sha256']
        assert result['output']['rendered_json_bytes'] == len(rendered(result))
        assert export.path.read_bytes() == original
        with pytest.raises(ContractError):
            rows.evidence_rows(export.path, ROOT, source.resolve().executable, expected_sha256='f'*64)
    finally:
        export.close()


def test_identity_change_and_unbounded_health_never_get_silently_trimmed(source, events, monkeypatch):
    original = query._query
    monkeypatch.setattr(query, '_query', lambda e,p,sql,**k: original(e,p,sql,**k) if 'private_records' in sql else
        b'name,severity,value\n__capture_stats_present,meta,1\n__sorter_dropped,meta,0\n' +
        b''.join((f'counter_{i:03d}'+'x'*110+',error,1\n').encode() for i in range(128)))
    with pytest.raises(ContractError, match='output limit'): rows.metadata_rows(source)
    monkeypatch.setattr(query, '_query', original)
    location = source.resolve()
    other = deepcopy(location)
    other.reader_runtime['reader_build']['artifact_set_sha256'] = 'f'*64
    resolutions = iter((location, other))
    source.resolve = lambda:next(resolutions)
    with pytest.raises(ContractError, match='identity changed'): rows.metadata_rows(source)


def test_one_over_cap_row_fails_closed_at_actual_cli_boundary(source, events, monkeypatch, tmp_path, capsys):
    # Mandatory health fits alone, but one complete wide row cannot fit with it.
    # It must not be cut, omitted with a success claim, or given a stuck cursor.
    event = deepcopy(events[0])
    event['event'] = {'category':'network','name':'request.start'}
    event['execution'] = {'context_id':'é'*120, 'worker_id':'é'*120, 'script_id':'v8:10:'+'é'*200+':7'}
    event['request'] = {'id':'é'*256,'method':'GET','url_class':'https:same-origin:/probe','body_bytes':0}
    events[:] = [event]
    original = query._query
    monkeypatch.setattr(query, '_query', lambda e,p,sql,**k: original(e,p,sql,**k) if 'private_records' in sql else
        b'name,severity,value\n__capture_stats_present,meta,1\n__sorter_dropped,meta,0\n' +
        b''.join((f'counter_{i:03d}'+'x'*110+',error,1\n').encode() for i in range(42)))
    empty = rows.metadata_rows(source, apis=['Unknown.event'])
    assert empty['output']['rendered_json_bytes'] <= 16384 and empty['rows'] == []
    monkeypatch.setattr(rows, 'RecordingSource', lambda *a, **k:source)
    assert cli.main(['trace','session-rows','--session',str(tmp_path/'owned-run.json'),
                     '--expected-run-id','owned-run']) == 2
    captured = capsys.readouterr()
    result = json.loads(captured.out)
    VALIDATOR.validate(result)
    assert result == {'schema':rows.SCHEMA,'status':'error','code':'query-unavailable'}
    assert len(captured.out.encode('ascii')) < 256 and captured.err == ''
    assert 'é' not in captured.out and 'request:1' not in captured.out


@pytest.mark.parametrize('classification', ['https:same-origin','http:cross-origin','same-origin','cross-origin'])
def test_path_bearer_tokens_are_redacted_without_changing_legacy_portable_event(source, events, classification):
    events[0]['event'] = {'category':'network','name':'request.start'}
    original = classification+':/PRIVATE_SENTINEL/bearer:secret@host'
    events[0]['request'] = {'id':'request:1','method':'GET','url_class':original,'body_bytes':0}
    result = rows.metadata_rows(source, apis=['request.start'])
    VALIDATOR.validate(result)
    assert result['rows'][0]['request']['url_class'] == classification+':<redacted>'
    assert b'PRIVATE_SENTINEL' not in rendered(result) and b'bearer:secret' not in rendered(result)
    assert result['semantics']['request_url_path'] == 'always-redacted'
    legacy = query.metadata_query(source, filters=history_filters(apis=['request.start']), limit=25)
    assert legacy['events'][0]['request']['url_class'] == original


@pytest.mark.parametrize('change', [
    {'url_class':'https://user:password@host.invalid/private?token=PRIVATE_SENTINEL'},
    {'url_class':'https:same-origin:/probe?token=PRIVATE_SENTINEL'},
    {'url_class':'https:same-origin:/probe#PRIVATE_SENTINEL'},
    {'url_class':'https:same-origin://user:PRIVATE_SENTINEL@host.invalid'},
    {'headers':{'Authorization':'PRIVATE_SENTINEL'}},
    {'body':'PRIVATE_SENTINEL'}, {'cookies':'PRIVATE_SENTINEL'},
])
def test_unapproved_request_values_fail_even_outside_window(source, events, change):
    events[0]['event'] = {'category':'network','name':'request.start'}
    events[0]['request'] = {'id':'request:1','method':'GET','url_class':'https:same-origin:/probe',
                            'body_bytes':0, **change}
    with pytest.raises(ContractError): rows.metadata_rows(source, start_ns='99999')


def test_request_body_digest_is_not_part_of_focused_projection(source, events):
    events[0]['event'] = {'category':'network','name':'request.start'}
    events[0]['request'] = {'id':'request:1','method':'GET','url_class':'https:same-origin:/probe',
        'body_bytes':0, 'body_sha256_16':'f'*16}
    result = rows.metadata_rows(source, apis=['request.start'])
    VALIDATOR.validate(result)
    assert 'body_sha256_16' not in result['rows'][0]['request']
    assert b'ffffffffffffffff' not in rendered(result)


def test_run_and_snapshot_digest_changes_fail_closed(source, events, monkeypatch):
    with pytest.raises(ContractError, match='run binding'):
        rows.metadata_rows(source, expected_run_id='different-run')
    original = query.export_perfetto
    def changed_digest(*a, **k):
        result = original(*a, **k)
        result['report']['source_trace']['sha256'] = 'f'*64
        return result
    monkeypatch.setattr(query, 'export_perfetto', changed_digest)
    with pytest.raises(ContractError, match='digest changed'): rows.metadata_rows(source)


@pytest.mark.parametrize('key,bad', [('run_id','other-run'),('sha256','f'*64),('bytes',4),
    ('packets',2),('source_bytes',4),('excluded_tail_bytes',1),('source_phase','unknown')])
def test_mismatched_bundle_origin_rejected_and_closed(source, events, monkeypatch, tmp_path, key, bad):
    origin = {'run_id':'owned-run','sha256':hashlib.sha256(source.resolve().path.read_bytes()).hexdigest(),
        'bytes':3,'packets':1,'source_bytes':3,'excluded_tail_bytes':0,'source_phase':'finalized-recording'}
    origin[key] = bad
    closed = []
    monkeypatch.setattr(rows, 'OpenEvidence', lambda *a, **k:SimpleNamespace(
        metadata={'capture':CAPTURE_OFF,'recording':origin},source=source,sha256='a'*64,
        close=lambda:closed.append(True)))
    with pytest.raises(ContractError, match='source recording binding is invalid'):
        rows.evidence_rows(tmp_path/'bundle', ROOT, tmp_path/'chrome.exe')
    assert closed == [True]


@pytest.mark.parametrize('route', ['session-rows','evidence-rows'])
def test_actual_cli_process_emits_exact_lf_bytes_below_windows_cap(source, events, route):
    population(events, 100)
    result = rows.metadata_rows(source, limit=100, bundle_sha256='a'*64)
    body = rendered(result)
    assert result['query']['output_limited']
    assert len(body.replace(b'\n', b'\r\n')) > 16384
    process = subprocess.run([sys.executable, '-B', *(['-O'] if sys.flags.optimize else []), '-c',
        'import json,sys; from browser_core import cli,metadata_rows as rows; '
        'result=json.loads(sys.stdin.buffer.read()); '
        'rows.evidence_rows=lambda *a,**k:result; rows.session_rows=lambda *a,**k:result; '
        'raise SystemExit(cli.main(sys.argv[1:]))', 'trace', route,
        *(['--session','C:/owned-run.json','--expected-run-id','owned-run'] if route=='session-rows'
          else ['--bundle','C:/fixture.bcevidence','--reader-executable','C:/fixture-chrome.exe'])],
        input=body, cwd=ROOT, capture_output=True, timeout=30, check=False)
    assert process.returncode == 0 and process.stderr == b''
    assert process.stdout == body and b'\r' not in process.stdout
    assert len(process.stdout) == result['output']['rendered_json_bytes'] <= 16384
    assert result['output']['transport_delivery_verified'] is False


def test_binary_emitter_bypasses_crlf_and_does_not_change_legacy_emitter(source, events, monkeypatch):
    result = rows.metadata_rows(source)
    raw = io.BytesIO()
    translated = io.TextIOWrapper(raw, encoding='ascii', newline='\r\n')
    monkeypatch.setattr(sys, 'stdout', translated)
    rows._emit_rows_json(result)
    assert raw.getvalue() == rendered(result)
    raw.seek(0); raw.truncate()
    cli._json(result)
    translated.flush()
    assert raw.getvalue() == rendered(result).replace(b'\n',b'\r\n')+b'\r\n'


@pytest.mark.parametrize('case', ['wrong-count','too-large','text-only','short-write'])
def test_emitter_rejects_false_counts_unsupported_streams_and_short_writes(source, events, monkeypatch, case):
    result = rows.metadata_rows(source)
    raw = io.BytesIO()
    if case == 'wrong-count': result['output']['rendered_json_bytes'] += 1
    if case == 'too-large': result['extra'] = 'x'*16384
    target = io.StringIO() if case == 'text-only' else SimpleNamespace(buffer=raw)
    if case == 'short-write':
        target = SimpleNamespace(buffer=SimpleNamespace(write=lambda body:len(body)-1,
            flush=lambda:pytest.fail('short write flushed as complete')))
    monkeypatch.setattr(sys, 'stdout', target)
    with pytest.raises(ContractError): rows._emit_rows_json(result)
    assert raw.getvalue() == b''


@pytest.mark.parametrize('stage', ['write', 'flush'])
def test_emitter_closes_binary_transport_errors(source, events, monkeypatch, stage):
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
        rows._emit_rows_json(rows.metadata_rows(source))
    assert calls == (['write'] if stage == 'write' else ['write', 'flush'])
    assert 'PRIVATE_SENTINEL' not in str(caught.value)


def test_parse_error_with_broken_output_returns_closed_status(monkeypatch):
    def fail(body):raise OSError('PRIVATE_SENTINEL transport')
    monkeypatch.setattr(sys,'stdout',SimpleNamespace(buffer=SimpleNamespace(
        write=fail,flush=lambda:pytest.fail('failed write was flushed'))))
    assert cli.main(['trace','session-rows','--unknown=PRIVATE_SENTINEL'])==2


@pytest.mark.parametrize('route', ['session-rows','evidence-rows'])
@pytest.mark.parametrize('case', ['help','missing-source','bad-filter','incomplete-selector'])
def test_real_cli_discovery_and_redacted_failures(tmp_path, route, case):
    args = (['--session',str(tmp_path/'owned-run.json'),'--expected-run-id','owned-run']
        if route=='session-rows' else ['--bundle',str(tmp_path/'bundle'),'--reader-executable',str(tmp_path/'chrome.exe')])
    if case == 'help': args = ['--help']
    elif case == 'bad-filter': args += ['--api','PRIVATE_SENTINEL invalid filter']
    elif case == 'incomplete-selector': args += ['--portable-pid','10']
    result = subprocess.run([sys.executable, '-m','browser_core','trace',route,*args],
        cwd=ROOT, capture_output=True, timeout=30, check=False)
    assert result.stderr == b''
    if case == 'help':
        assert result.returncode == 0
        assert b'fetch.request.start' in result.stdout and b'--rows-version {1}' in result.stdout
        assert b'--include-values' not in result.stdout
    else:
        assert result.returncode == 2
        body = json.loads(result.stdout)
        VALIDATOR.validate(body)
        assert body['code'] == 'query-unavailable'
        assert len(result.stdout) < 256 and b'PRIVATE_SENTINEL' not in result.stdout
        assert str(tmp_path).encode() not in result.stdout
