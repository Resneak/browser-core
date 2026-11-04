"""Regressions for metadata-only launch-eval omission and agent discovery."""
from contextlib import closing
from copy import deepcopy
import hashlib
import io
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace

import pytest

from browser_core.contracts import ContractError
from browser_core.evidence_bundle import EvidenceExport, OpenEvidence
from browser_core.inspection_attribution import ContextAttribution
from browser_core.inspection_contract import CAPTURE_OFF, recording_capture, supported_capture
from browser_core.inspection_history import history_filters
from browser_core import metadata_query as module
from browser_core import workspace_check
from browser_core.effort import EffortRecorder, summarize_effort
from test_evidence_bundle import BUILD, BODY

ROOT=Path(__file__).resolve().parents[1]
REVISION='1'*40


@pytest.fixture
def source(tmp_path,monkeypatch):
    path=tmp_path/'trace';path.write_bytes(BODY)
    session={'run_id':'owned-run','chromium_revision':REVISION,'build':dict(BUILD)}
    location=SimpleNamespace(session=session,executable=tmp_path/'chrome.exe',path=path,
        phase='finalized-recording',reader_runtime={'producer_build':BUILD,'reader_build':BUILD})
    source=SimpleNamespace(resolve=lambda:location)
    monkeypatch.setattr(module,'_query',lambda executable,path,sql,**kw:
        b'private_records\n0\n' if 'private_records' in sql else b'name,severity,value\n__capture_stats_present,meta,1\n__sorter_dropped,meta,0\n')
    monkeypatch.setattr('browser_core.evidence_bundle.executable_evidence',lambda *a,**kw:dict(BUILD))
    return source


def test_exact_missing_optional_capture_collect_preparation_roundtrips(source,tmp_path):
    export=EvidenceExport()
    try:
        result=export.prepare(source,ContextAttribution(),None)
        assert result['private_values'] is False
        bundle=OpenEvidence(export.path,tmp_path,source.resolve().executable,
                            expected_sha256=result['sha256'])
        try:
            assert bundle.metadata['capture']==CAPTURE_OFF
            assert bundle.source.resolve().session['chromium_revision']==REVISION
            assert bundle.path.read_bytes()==BODY
        finally:bundle.close()
    finally:export.close()


def test_metadata_export_rejects_chromium_revision_change_before_publication(source):
    first=source.resolve()
    changed=SimpleNamespace(**{**vars(first),
        'session':{**first.session,'chromium_revision':'2'*40}})
    calls=[]
    def resolve():
        calls.append(None)
        return first if len(calls)<3 else changed
    export=EvidenceExport()
    try:
        with pytest.raises(ContractError,match='recording source changed during export'):
            export.prepare(SimpleNamespace(resolve=resolve),ContextAttribution(),None)
        assert len(calls)>=3
        assert export.path is None
    finally:export.close()


@pytest.mark.parametrize('version', [1, 2])
def test_metadata_evidence_query_preserves_incomplete_origin_phase(source, events, version):
    from browser_core.evidence_query import evidence_query
    import jsonschema

    source.resolve().phase = 'recovered-prefix'
    source.resolve().path.write_bytes(BODY + b'\x0a\x05abc')
    export = EvidenceExport()
    try:
        prepared = export.prepare(source, ContextAttribution(), None)
        result = evidence_query(export.path, ROOT, source.resolve().executable,
                                expected_sha256=prepared['sha256'], metadata_version=version)
        schema = json.loads((ROOT / f'schemas/metadata-query-v{version}.schema.json').read_text())
        jsonschema.Draft202012Validator(schema).validate(result)
        assert result['snapshot']['source_phase'] == 'finalized-recording'
        if version == 2:
            assert result['source_recording']['source_phase'] == 'recovered-prefix'
            assert result['source_recording']['source_bytes'] == str(len(BODY) + 5)
            assert result['source_recording']['excluded_tail_bytes'] == '5'
            assert result['source_recording']['sha256'] == result['snapshot']['sha256']
        else:
            assert 'source_recording' not in result
    finally:
        export.close()


def test_private_bundle_keeps_its_previous_metadata_shape(source,tmp_path):
    from browser_core.inspection_contract import CAPTURE_V2
    source.resolve().session['value_capture']=dict(CAPTURE_V2)
    export=EvidenceExport()
    try:
        result=export.prepare(source,ContextAttribution(),None)
        assert result['private_values'] is True
        bundle=OpenEvidence(export.path,tmp_path,source.resolve().executable)
        try:assert 'producer_chromium_revision' not in bundle.metadata
        finally:bundle.close()
    finally:export.close()


@pytest.mark.parametrize('value',[None,{},False,{'schema':'unknown','allowlist':'none'}])
def test_unknown_or_null_capture_is_not_silently_disabled(value):
    with pytest.raises(ContractError):recording_capture({'value_capture':value})
    assert not supported_capture(CAPTURE_OFF)


def test_false_metadata_declaration_never_publishes_raw_values(source,monkeypatch):
    monkeypatch.setattr(module,'_query',lambda *a,**kw:b'private_records\n1\n')
    export=EvidenceExport()
    try:
        with pytest.raises(module.MetadataQueryError,match='contains-values'):
            export.prepare(source,ContextAttribution(),None)
        assert export.path is None
    finally:export.close()


@pytest.fixture
def events(source,monkeypatch):
    events=[{'schema':'browser-core.trace-event/1','run_id':'owned-run','seq':i,
        'ts_monotonic_ns':100+i,'process':{'pid':10,'type':'renderer'},
        'execution':{'context_id':'ABCD','frame_id':'ABCD','script_id':'v8:10:ABCD:7'},
        'event':{'category':'api','name':'Navigator.language.get'},
        'provenance':{'source':'fixture','component':'blink','chromium_revision':REVISION},
        'detail':{}} for i in range(7)]
    def export(processor,trace,path,run,revision):
        path.write_text('\n'.join(json.dumps(event) for event in events),encoding='utf-8')
        return {'report':{'source_trace':{'sha256':hashlib.sha256(BODY).hexdigest()}}}
    monkeypatch.setattr(module,'export_perfetto',export)
    return events


def test_metadata_known_absent_queries_and_immutable_pagination(source,events):
    options={'filters':history_filters(apis=['Navigator.language.get']),'limit':3,'bundle_sha256':'a'*64}
    first=module.metadata_query(source,**options)
    import jsonschema
    schema=json.loads((ROOT/'schemas/metadata-query-v1.schema.json').read_text())
    jsonschema.Draft202012Validator(schema).validate(first)
    second=module.metadata_query(source,cursor=first['query']['next_cursor'],**options)
    third=module.metadata_query(source,cursor=second['query']['next_cursor'],**options)
    assert [e['seq'] for page in (first,second,third) for e in page['events']]==list(reversed(range(7)))
    assert third['query']['next_cursor'] is None
    assert first['semantics']['private_value_records']==0
    assert first['reader_runtime']==source.resolve().reader_runtime
    assert first['query']['matching_events']=='7'
    assert module.metadata_query(source,filters=history_filters(apis=['Unknown.event']),limit=25)['events']==[]
    with pytest.raises(ContractError,match='different evidence'):
        module.metadata_query(source,cursor=first['query']['next_cursor'],**{**options,'bundle_sha256':'b'*64})


def test_metadata_query_preserves_replaced_private_directory_on_exit(
        source, events, tmp_path, monkeypatch):
    folder = tempfile.TemporaryDirectory(dir=tmp_path)
    original_name = Path(folder.name)
    retained = tmp_path / 'retained-metadata'
    sentinel = original_name / 'unrelated.txt'
    cleanup = folder.cleanup
    calls = []
    monkeypatch.setattr(folder, 'cleanup', lambda: calls.append('cleanup'))
    monkeypatch.setattr(module, 'TemporaryDirectory', lambda **kwargs: folder)
    original_bind = module.bind_perfetto_source_trace
    binds = 0

    def replace_after_final_bind(path):
        nonlocal binds
        binding = original_bind(path)
        binds += 1
        if binds == 2:
            assert original_name.resolve().parent == tmp_path.resolve()
            original_name.rename(retained)
            original_name.mkdir()
            sentinel.write_text('preserve', encoding='utf-8')
        return binding

    monkeypatch.setattr(module, 'bind_perfetto_source_trace', replace_after_final_bind)
    try:
        with pytest.raises(ContractError, match='metadata query directory.*cleanup'):
            module.metadata_query(source, filters=history_filters(), limit=2)
        assert binds == 2
        assert calls == []
        assert sentinel.read_text(encoding='utf-8') == 'preserve'
    finally:
        monkeypatch.setattr(folder, 'cleanup', cleanup)
        sentinel.unlink(missing_ok=True)
        if original_name.exists():
            original_name.rmdir()
        retained.rename(original_name)
        cleanup()


def test_metadata_filters_and_mutable_snapshot_limits(source,events):
    result=module.metadata_query(source,filters=history_filters(script='7',context='window',start_ns='103'),limit=2)
    assert result['query']['matching_events']=='4'
    assert result['query']['more_available'] and result['query']['next_cursor'] is None
    assert not result['semantics']['continuation_supported']
    with pytest.raises(module.MetadataQueryError,match='realm-filter-unavailable'):
        module.metadata_query(source,filters=history_filters(scope={'pid':'10','context_id':'AB'*16,'realm_id':'0'}),limit=25)
    with pytest.raises(module.MetadataQueryError,match='private-values-disabled'):
        module.metadata_query(source,filters=history_filters(),limit=25,include_values=True)
    with pytest.raises(ContractError,match='run binding'):
        module.metadata_query(source,filters=history_filters(),limit=25,expected_run_id='other-run')


@pytest.mark.parametrize('filters', [
    history_filters(search='unimplemented-search'),
    {**history_filters(), 'ignored_selector': 'Navigator.language.get'},
    {**history_filters(), 'apis': ['Z.event', 'A.event']},
    None,
])
def test_metadata_query_rejects_ignored_or_noncanonical_filters_before_source(filters):
    with pytest.raises(ContractError):
        module.metadata_query(None, filters=filters, limit=1)


@pytest.mark.parametrize('include_values', [None, 0, 1, '', [], {}])
def test_metadata_query_requires_a_boolean_value_selector_before_source(include_values):
    with pytest.raises(ContractError, match='value selection'):
        module.metadata_query(None, filters=history_filters(), limit=1,
                              include_values=include_values)


def test_metadata_query_detaches_validated_filters_before_export(source, events, monkeypatch):
    filters = history_filters(apis=['Navigator.language.get'])
    original_export = module.export_perfetto

    def mutate_caller_filters(*args, **kwargs):
        filters['apis'].clear()
        filters['script'] = '-1'
        return original_export(*args, **kwargs)

    monkeypatch.setattr(module, 'export_perfetto', mutate_caller_filters)
    result = module.metadata_query(source, filters=filters, limit=25)
    assert result['query']['filters'] == history_filters(apis=['Navigator.language.get'])
    assert result['query']['matching_events'] == '7'


def test_metadata_output_bound_does_not_claim_no_events(source,events,monkeypatch):
    monkeypatch.setattr(module,'MAX_OUTPUT_BYTES',1)
    with pytest.raises(ContractError,match='output limit'):
        module.metadata_query(source,filters=history_filters(),limit=25)


@pytest.mark.parametrize('bundle_sha256,expected_digest_matched',[
    ('invalid', False), ('a'*64, []), (None, True)])
def test_metadata_query_rejects_invalid_bundle_declaration(
        source, events, bundle_sha256, expected_digest_matched):
    with pytest.raises(ContractError, match='digest'):
        module.metadata_query(source, filters=history_filters(), limit=25,
            bundle_sha256=bundle_sha256,
            expected_digest_matched=expected_digest_matched)


def test_metadata_output_cap_includes_pretty_printed_windows_cli_bytes(source,events,monkeypatch):
    full=module.metadata_query(source,filters=history_filters(),limit=7)
    plain=len(json.dumps(full,indent=2,sort_keys=True,ensure_ascii=True,
                         allow_nan=False).encode('ascii'))
    monkeypatch.setattr(module,'MAX_OUTPUT_BYTES',plain)
    limited=module.metadata_query(source,filters=history_filters(),limit=7)
    rendered=json.dumps(limited,indent=2,sort_keys=True,ensure_ascii=True,
                        allow_nan=False).encode('ascii')
    assert len(rendered)+rendered.count(b'\n')+2<=module.MAX_OUTPUT_BYTES
    assert limited['query']['returned_events']<7


def test_metadata_query_rejects_changed_normalized_trace_between_passes(source,events,monkeypatch):
    original=module.iter_trace
    changed=[]
    def replace_after_validation(path, **kwargs):
        if not changed:
            changed.append(True)
            lines=path.read_text(encoding='utf-8').splitlines()
            final=json.loads(lines[-1]);final['ts_monotonic_ns']=107
            lines[-1]=json.dumps(final)
            path.write_text('\n'.join(lines),encoding='utf-8')
        return original(path, **kwargs)
    monkeypatch.setattr(module,'iter_trace',replace_after_validation)
    with pytest.raises(ContractError,match='normalized trace changed'):
        module.metadata_query(source,filters=history_filters(),limit=25)
    assert changed


def test_metadata_query_binds_bytes_seen_by_population_validation(
    source, events, monkeypatch, tmp_path,
):
    import browser_core.trace as trace_module

    valid = tmp_path / 'valid.jsonl'
    valid.write_text('\n'.join(json.dumps(event) for event in events), encoding='utf-8')
    valid_body = valid.read_bytes()
    events[-1]['seq'] = events[-2]['seq']  # Individually valid, invalid population.
    real_validate = trace_module.validate_trace
    real_scan = trace_module.scan_validated_trace

    def swapped(call, path, *args, **kwargs):
        original_body = path.read_bytes()
        path.write_bytes(valid_body)
        try:
            return call(path, *args, **kwargs)
        finally:
            path.write_bytes(original_body)

    monkeypatch.setattr(module, 'validate_trace',
                        lambda path: swapped(real_validate, path), raising=False)
    monkeypatch.setattr(module, 'scan_validated_trace',
                        lambda path, consume, **kwargs:
                        swapped(real_scan, path, consume, **kwargs), raising=False)
    with pytest.raises(ContractError, match='normalized trace changed during validation'):
        module.metadata_query(source, filters=history_filters(), limit=25)


@pytest.mark.parametrize('boundary', ['compare', 'selection'])
def test_metadata_query_binds_bytes_seen_by_comparison_and_selection(
    source, events, monkeypatch, tmp_path, boundary,
):
    original_iter = module.iter_trace
    alternate = tmp_path / 'alternate.jsonl'
    alternate_events = deepcopy(events)
    alternate_events[0]['event']['name'] = 'Navigator.other.get'
    alternate.write_text('\n'.join(json.dumps(event) for event in alternate_events),
                         encoding='utf-8')
    alternate_body = alternate.read_bytes()
    swapped = []

    def swapped_iter(path, **kwargs):
        if swapped:
            return original_iter(path, **kwargs)
        swapped.append(True)
        original_body = path.read_bytes()
        path.write_bytes(alternate_body)

        def rows():
            try:
                yield from original_iter(path, **kwargs)
            finally:
                path.write_bytes(original_body)

        return rows()

    monkeypatch.setattr(module, 'iter_trace', swapped_iter)
    if boundary == 'compare':
        class Comparison:
            schema = 'browser-core.metadata-compare/1'
            contract = {'fixture': True}

            def prepare(self, events_factory):
                with closing(events_factory()) as rows:
                    self.seen = [event['event']['name'] for event in rows]

            def add(self, _event):
                pass

            def result(self, _base, *, producer_revision):
                return {'observed': self.seen[0], 'revision': producer_revision}

        with pytest.raises(ContractError, match='normalized trace changed during scan'):
            module._metadata_query(source, filters=history_filters(), limit=25,
                                   _compare=Comparison())
    else:
        with pytest.raises(ContractError, match='normalized trace changed during scan'):
            module.metadata_query(source, filters=history_filters(apis=['Navigator.other.get']),
                                  limit=25)
    assert swapped


def test_metadata_query_closes_trace_iterator_after_row_rejection(source,events,monkeypatch):
    retained=[]
    closed=[]

    def tracked_iter_trace(_path, **_kwargs):
        def rows():
            try:
                yield {**events[0],'run_id':'foreign-run'}
            finally:
                closed.append(True)
        generator=rows()
        retained.append(generator)
        return generator

    monkeypatch.setattr(module,'iter_trace',tracked_iter_trace)
    with pytest.raises(ContractError,match='event run binding changed'):
        module.metadata_query(source,filters=history_filters(),limit=25)
    assert len(retained)==1
    assert closed==[True]


def test_metadata_query_rejects_finalized_source_rollback_during_export(source,events,monkeypatch):
    initial=source.resolve()
    rolled_back=SimpleNamespace(**{**vars(initial),'phase':'recovered-prefix'})
    current=[initial]
    source.resolve=lambda:current[0]
    original_export=module.export_perfetto

    def export_then_rollback(*args,**kwargs):
        report=original_export(*args,**kwargs)
        current[0]=rolled_back
        return report

    monkeypatch.setattr(module,'export_perfetto',export_then_rollback)
    with pytest.raises(ContractError,match='source phase or path changed'):
        module.metadata_query(source,filters=history_filters(),limit=25)


def test_metadata_query_rechecks_source_after_page_rendering(source,events,monkeypatch):
    initial=source.resolve()
    changed=SimpleNamespace(**{**vars(initial),
        'session':{**initial.session,'chromium_revision':'2'*40}})
    current=[initial]
    source.resolve=lambda:current[0]
    original_size=module._cli_rendered_size
    def render_then_change(result):
        size=original_size(result)
        current[0]=changed
        return size
    monkeypatch.setattr(module,'_cli_rendered_size',render_then_change)
    with pytest.raises(ContractError,match='source identity changed'):
        module.metadata_query(source,filters=history_filters(),limit=25)


def test_existing_ambiguous_caller_rejection_has_stable_metadata_code(source,monkeypatch):
    def ambiguous(*a,**kw):
        raise ContractError('native dynamic code caller script is ambiguous')
    monkeypatch.setattr(module,'export_perfetto',ambiguous)
    with pytest.raises(module.MetadataQueryError,match='metadata-attribution-ambiguous'):
        module.metadata_query(source,filters=history_filters(),limit=25)


@pytest.mark.parametrize('body',[b'',b'private_records\nnot-a-count\n',
    b'private_records\n0\n1\n',b'private_records\n"0'])
def test_unavailable_private_count_is_not_declared_value_free(source,monkeypatch,body):
    monkeypatch.setattr(module,'_query',lambda *a,**kw:body)
    with pytest.raises(ContractError,match='value-count unavailable'):
        module.require_value_free_recording(source.resolve().executable,source.resolve().path)


def test_workspace_exact_profile_and_recording_admission_precedes_browser(tmp_path,monkeypatch):
    calls=[]
    monkeypatch.setattr(workspace_check,'native_browser_path',lambda path,**kw:calls.append((path,kw)) or path)
    work=tmp_path/'short'
    result=workspace_check.check_workspace(work,ROOT,'analysis')
    assert result['workspace_ready'] and result['cleanup_verified']
    assert not result['browser_launched'] and not work.exists()
    assert calls[0][0]==work/'profiles/data/analysis'
    assert calls[1][0].name.endswith('.perfetto-trace')


def test_workspace_native_alias_failure_is_structured_and_clean(tmp_path,monkeypatch):
    def unavailable(*a,**kw):
        raise ContractError('Windows native path alias is unavailable; choose a shorter workspace')
    monkeypatch.setattr(workspace_check,'native_browser_path',unavailable)
    work=tmp_path/'long'
    result=workspace_check.check_workspace(work,ROOT,'analysis')
    assert result['code']=='native-path-unavailable' and not work.exists()


def test_workspace_permission_failure_has_no_launch_or_profile(tmp_path,monkeypatch):
    def denied(*a,**kw):raise PermissionError('private OS diagnostic')
    monkeypatch.setattr(workspace_check.tempfile,'mkstemp',denied)
    work=tmp_path/'denied'
    result=workspace_check.check_workspace(work,ROOT,'analysis')
    assert result['code']=='workspace-permission-denied' and result['cleanup_verified']
    assert not work.exists() and 'private OS diagnostic' not in json.dumps(result)


def test_workspace_admission_rejects_relocated_ancestor_before_ready(tmp_path,monkeypatch):
    work=tmp_path/'workspace'
    for directory in (work/'profiles/data/analysis',work/'profiles/registry',work/'sessions',work/'traces'):
        directory.mkdir(parents=True,exist_ok=True)
    retained=tmp_path/'retained-workspace'
    relocated=False

    def relocate_on_native_path(path,**_kwargs):
        nonlocal relocated
        if not relocated:
            work.rename(retained)
            work.mkdir()
            for name in ('profiles','sessions','traces'):
                (retained/name).rename(work/name)
            relocated=True
        return path

    monkeypatch.setattr(workspace_check,'native_browser_path',relocate_on_native_path)
    result=workspace_check.check_workspace(work,ROOT,'analysis')
    assert relocated
    assert result['code']=='workspace-cleanup-incomplete'
    assert not result['workspace_ready'] and not result['cleanup_verified']
    assert (work/'profiles/data/analysis').is_dir()


@pytest.mark.parametrize('ancestor',['workspace','profiles'])
def test_workspace_probe_cleanup_refuses_relocated_ancestor(tmp_path,monkeypatch,ancestor):
    work=tmp_path/'workspace'
    for directory in (work/'profiles/data/analysis',work/'profiles/registry',work/'sessions',work/'traces'):
        directory.mkdir(parents=True,exist_ok=True)
    retained=tmp_path/'retained-ancestor'
    original=workspace_check.directory_identity
    relocated=False

    def relocate_after_probe(path,*,label):
        nonlocal relocated
        identity=original(path,label=label)
        if (not relocated and path==work/'profiles/data/analysis'
                and label=='workspace admission directory'
                and list(path.glob('.browser-core-admission-*'))):
            if ancestor=='workspace':
                work.rename(retained)
                work.mkdir()
                for name in ('profiles','sessions','traces'):
                    (retained/name).rename(work/name)
            else:
                (work/'profiles').rename(retained)
                (work/'profiles').mkdir()
                for name in ('data','registry'):
                    (retained/name).rename(work/'profiles'/name)
            relocated=True
        return identity

    monkeypatch.setattr(workspace_check,'directory_identity',relocate_after_probe)
    monkeypatch.setattr(workspace_check,'native_browser_path',lambda path,**_kwargs:path)
    result=workspace_check.check_workspace(work,ROOT,'analysis')
    assert relocated
    assert result['code']=='workspace-cleanup-incomplete'
    assert not result['workspace_ready'] and not result['cleanup_verified']
    assert list((work/'profiles/data/analysis').glob('.browser-core-admission-*'))


def test_effort_counts_failed_retry_nested_and_packaging_once(tmp_path):
    path=tmp_path/'effort.jsonl';recorder=EffortRecorder(path)
    outer=recorder.start('outer-tool','setup')
    failed=recorder.start('nested-cli','setup',parent_id=outer)
    recorder.finish(failed,returncode=1,stdout=b'',stderr=b'failed',visible_output=b'')
    retry=recorder.start('nested-cli','setup',parent_id=outer)
    recorder.finish(retry,returncode=0,stdout=b'ok',stderr=b'',visible_output=b'')
    recorder.finish(outer,returncode=0,visible_output=b'failed\nok')
    package=recorder.start('packaging','packaging')
    recorder.finish(package,returncode=0,visible_output=b'done')
    recorder.close()
    result=summarize_effort(path,operation_limit=3,visible_byte_limit=12)
    assert result['inclusive_recorded_operations']==4 and result['failed_operations']==1
    assert result['visible_output_bytes']==13
    assert result['operation_limit_exceeded'] and result['visible_byte_limit_exceeded']
    assert result['by_kind']['nested-cli']==2


def test_effort_missing_completion_is_counted_and_unknown_bytes_stay_unknown(tmp_path):
    path=tmp_path/'effort.jsonl';recorder=EffortRecorder(path)
    recorder.start('outer-tool','analysis');recorder.close()
    result=summarize_effort(path,operation_limit=0,visible_byte_limit=100)
    assert result['incomplete_operations']==1 and result['operation_limit_exceeded']
    assert result['visible_output_bytes'] is None and result['visible_byte_limit_exceeded'] is None
    with pytest.raises(FileExistsError):EffortRecorder(path)


def test_known_byte_overrun_is_not_hidden_by_other_unknown_bytes(tmp_path):
    path=tmp_path/'effort.jsonl';recorder=EffortRecorder(path)
    done=recorder.start('outer-tool','analysis')
    recorder.finish(done,returncode=0,visible_output=b'over-limit')
    recorder.start('outer-tool','packaging');recorder.close()
    result=summarize_effort(path,visible_byte_limit=1)
    assert result['visible_output_bytes'] is None
    assert result['visible_byte_limit_exceeded'] is True


def test_agent_metadata_options_are_discoverable():
    from browser_core.cli import build_parser
    args=build_parser().parse_args(['research','owned','--agent-control','--metadata-only','--extra-arg=--headless'])
    assert args.metadata_only and args.extra_arg==['--headless']


@pytest.fixture
def invalid_population(source, monkeypatch):
    from browser_core import perfetto
    from test_perfetto import csv_rows_fixture, host_callback_row, promise_microtask_row, script_run_row
    source.resolve().executable.with_name('trace_processor_shell.exe').write_bytes(b'fixture')
    def arrange(parent):
        scope = host_callback_row() if parent == 'callback' else promise_microtask_row()
        rows = [script_run_row(), scope,
                script_run_row(ts_monotonic_ns='210', track_id='9', context_id='other-frame',
                               script_id='8', native_id='script:other-frame:8')]
        class Process:
            def __init__(self):
                self.stdout = io.StringIO(csv_rows_fixture(rows))
                self.returncode = None
            def poll(self): return self.returncode
            def wait(self, timeout=None): self.returncode=0; return 0
            def kill(self): self.returncode=-9
        monkeypatch.setattr(perfetto.subprocess, 'Popen', lambda *a,**kw:Process())
    return arrange


@pytest.mark.parametrize('parent', ['callback', 'promise'])
@pytest.mark.parametrize('phase', ['live-prefix','finalized-recording','recovered-prefix'])
@pytest.mark.parametrize('hidden', [False, True])
def test_full_population_rejected_even_when_filter_or_page_hides_bad_edge(source, invalid_population, parent, phase, hidden):
    invalid_population(parent)
    source.resolve().phase = phase
    filters = history_filters(apis=['Unknown.event'] if hidden else [])
    with pytest.raises(ContractError, match='parent scope is inconsistent'):
        module.metadata_query(source, filters=filters, limit=1,
                              bundle_sha256='a'*64 if phase=='finalized-recording' else None)


def test_population_failure_closes_the_trace_handle_before_temporary_cleanup(source, invalid_population, tmp_path):
    from browser_core.trace import validate_trace
    invalid_population('callback')
    path = tmp_path/'invalid-population.jsonl'
    location = source.resolve()
    module.export_metadata(location.executable.with_name('trace_processor_shell.exe'),
                           location.path, path, location.session['run_id'], REVISION)
    with pytest.raises(ContractError, match='parent scope is inconsistent') as caught:
        validate_trace(path)
    # Retain the traceback during unlink; Windows rejects an open read handle.
    assert caught.value.__traceback__ is not None
    path.unlink()
    assert not path.exists()


def test_population_limits_are_not_relaxed_by_small_query_limit(source, events, monkeypatch):
    from browser_core import trace
    monkeypatch.setattr(trace, 'MAX_TRACE_EVENTS', 2)
    with pytest.raises(ContractError, match='population exceeds limit'):
        module.metadata_query(source, filters=history_filters(apis=['Unknown.event']), limit=1)


@pytest.mark.parametrize('body', [b'foreign-file-must-survive', b'browser-core-workspace-check\n', None])
def test_workspace_cleanup_does_not_adopt_a_replaced_or_missing_probe(tmp_path, monkeypatch, body):
    work = tmp_path/'workspace'
    for directory in (work/'profiles/data/analysis',work/'profiles/registry',work/'sessions',work/'traces'):
        directory.mkdir(parents=True, exist_ok=True)
    original = workspace_check.directory_identity
    retained = tmp_path/'retained-original-probe'
    replaced = []
    def swap(directory, *, label):
        identity = original(directory, label=label)
        matches = list(directory.glob('.browser-core-admission-*'))
        if not replaced and matches:
            probe = matches[0]
            probe.rename(retained)
            if body is not None:
                probe.write_bytes(body)
            replaced.append(probe)
        return identity
    monkeypatch.setattr(workspace_check, 'directory_identity', swap)
    def no_native(*a, **kw): raise AssertionError('must fail before native admission')
    monkeypatch.setattr(workspace_check, 'native_browser_path', no_native)
    result = workspace_check.check_workspace(work,ROOT,'analysis')
    assert result['code']=='workspace-cleanup-incomplete'
    assert not result['workspace_ready'] and not result['cleanup_verified']
    assert retained.read_bytes()==b'browser-core-workspace-check\n'
    if body is not None:
        assert replaced[0].read_bytes()==body
    else:
        assert not replaced[0].exists()


def test_failed_probe_write_never_claims_cleanup_without_custody(tmp_path,monkeypatch):
    def failed(*a,**kw): raise OSError('private-error-text')
    monkeypatch.setattr(workspace_check.os, 'fsync', failed)
    result = workspace_check.check_workspace(tmp_path/'workspace',ROOT,'analysis')
    assert result['code']=='workspace-cleanup-incomplete'
    assert not result['workspace_ready'] and not result['cleanup_verified']
    assert 'private-error-text' not in json.dumps(result)


def test_new_directory_without_custody_does_not_claim_complete_cleanup(tmp_path,monkeypatch):
    work = tmp_path/'workspace'
    (work/'profiles/data').mkdir(parents=True)
    original = workspace_check.directory_identity

    def unavailable(path, *, label):
        if path == work/'profiles/data/analysis' and path.exists():
            raise ContractError('new directory custody unavailable')
        return original(path,label=label)

    monkeypatch.setattr(workspace_check,'directory_identity',unavailable)
    result = workspace_check.check_workspace(work,ROOT,'analysis')
    assert (work/'profiles/data/analysis').exists()
    assert result['code']=='workspace-cleanup-incomplete'
    assert not result['cleanup_verified'] and not result['workspace_ready']


@pytest.mark.parametrize('capture', [None,False,[],{},dict(CAPTURE_OFF),
    {'schema':'unknown','allowlist':'unknown'},
    {'schema':'browser-core.values/2','allowlist':'fingerprint-v2','extra':'private-sentinel'}])
def test_real_session_query_cli_closes_malformed_capture_diagnostic(tmp_path,capsys,capture):
    from browser_core import cli
    from test_contracts import session
    payload=session();payload['value_capture']=capture
    path=tmp_path/(payload['run_id']+'.json')
    path.write_text(json.dumps(payload),encoding='utf-8')
    assert cli.main(['trace','session-query','--session',str(path),
                     '--expected-run-id',payload['run_id']])==2
    output=capsys.readouterr()
    assert json.loads(output.out)['code']=='capture-contract-unsupported'
    assert 'private-sentinel' not in output.out+output.err


def test_graph_failure_is_redacted_by_actual_session_query_cli(source,invalid_population,monkeypatch,tmp_path,capsys):
    from browser_core import cli,session_query
    invalid_population('promise')
    monkeypatch.setattr(session_query,'RecordingSource',lambda *a,**kw:source)
    assert cli.main(['trace','session-query','--session',str(tmp_path/'owned-run.json'),
                     '--expected-run-id','owned-run'])==2
    output=capsys.readouterr()
    assert json.loads(output.out)['code']=='query-unavailable'
    assert 'other-frame' not in output.out+output.err
    assert 'events' not in json.loads(output.out)
