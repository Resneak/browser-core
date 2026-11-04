"""Generic interface/adversarial regressions; no application-specific oracle."""
import asyncio
import inspect
import json
from pathlib import Path

import pytest

from browser_core.agent_process import AgentProcess
from browser_core.contracts import ContractError
from browser_core.effort import EffortRecorder, effort_contract, summarize_effort
from browser_core.metadata_inventory import MetadataInventory, analyst_activity
from browser_core.perfetto import DynamicCallerAmbiguity, parse_export_csv
from test_perfetto import csv_rows_fixture, dynamic_code_row, script_run_row, REVISION
from test_agent_process import env, install
from test_metadata_workflow import source, events


def test_path_signature_discoverable_and_documented_shape_reaches_awaiting_start(env):
    signature=inspect.signature(AgentProcess)
    assert signature.parameters['cwd'].annotation == 'Path'
    assert signature.parameters['workspace'].annotation == 'Path'
    async def run():
        owner=install(env)
        assert env.calls == []
        await owner.open()
        assert owner.snapshot()['ready_for_start']
        await owner.close()
        assert owner.snapshot()['creator_exit_observed']
    asyncio.run(run())


@pytest.mark.parametrize('which',['cwd','workspace'])
def test_string_paths_fail_before_creation_with_actionable_message(tmp_path,which):
    kwargs={'cwd':tmp_path,'workspace':tmp_path,'profile_id':'analysis'}
    kwargs[which]=str(tmp_path)
    with pytest.raises(ContractError,match='pathlib.Path'):
        AgentProcess(['C:/inert/python.exe'],**kwargs)


def test_effort_contract_cli_and_first_input_wrapper(tmp_path,capsys):
    from browser_core.cli import main
    assert main(['agent','effort-contract']) == 0
    assert json.loads(capsys.readouterr().out) == effort_contract()
    path=tmp_path/'ledger'
    with EffortRecorder(path,operation_limit=5,cleanup_reserve=1) as recorder:
        with recorder.operation('outer-tool','setup',question='Read the supplied input') as outer:
            with recorder.operation('nested-cli','setup',parent_id=outer,question='Check the contract') as inner:
                recorder.finish(inner,returncode=0,stdout=b'raw',visible_output=b'')
            recorder.finish(outer,returncode=0,visible_output='résumé'.encode('utf-8'))
        with pytest.raises(ValueError):
            with recorder.operation('browser-action','analysis',question='Check one change'):
                raise ValueError('private exception text')
        with recorder.operation('packaging','packaging') as package:
            recorder.finish(package,returncode=0,visible_output=b'')
        with pytest.raises(ContractError,match='reserved for cleanup'):
            recorder.start('outer-tool','analysis')
        for _ in range(2):
            with recorder.operation('outer-tool','cleanup') as cleanup:
                recorder.finish(cleanup,returncode=0,visible_output=b'')
    summary=summarize_effort(path,operation_limit=5)
    assert summary['inclusive_recorded_operations']==6 and summary['operation_limit_exceeded']
    assert summary['failed_operations']==1 and summary['operations_with_question']==3
    assert summary['visible_output_bytes'] is None
    assert summary['known_visible_output_bytes']==len('résumé'.encode('utf-8'))
    assert not summary['complete_external_census']
    assert 'private exception text' not in path.read_text()


@pytest.mark.parametrize('options',[
    {'operation_limit':True}, {'operation_limit':-1}, {'cleanup_reserve':1},
    {'operation_limit':1,'cleanup_reserve':2}, {'cleanup_reserve':True}])
def test_invalid_budget_does_not_create_ledger(tmp_path,options):
    path=tmp_path/'ledger'
    with pytest.raises(ContractError):EffortRecorder(path,**options)
    assert not path.exists()


@pytest.mark.parametrize('question',['', '\nsecret', 'a'*513, 4, '   ', 'a\x7fb', 'a\ud800b'])
def test_question_contract_rejects_invalid_without_start(tmp_path,question):
    path=tmp_path/'ledger'
    with EffortRecorder(path) as recorder:
        with pytest.raises(ContractError):recorder.start('outer-tool','setup',question=question)
    assert summarize_effort(path)['inclusive_recorded_operations']==0


def test_unicode_question_remains_within_reader_row_limit(tmp_path):
    path=tmp_path/'ledger'
    with EffortRecorder(path) as recorder:
        with recorder.operation('outer-tool','setup',question='\U0001f310'*256):pass
    assert summarize_effort(path)['operations_with_question']==1


@pytest.mark.parametrize('kind,stage,parent', [([], 'setup', None), ('outer-tool', {}, None),
    ('outer-tool','setup',[])])
def test_non_string_effort_enums_and_parent_fail_closed(tmp_path,kind,stage,parent):
    with EffortRecorder(tmp_path/'ledger') as recorder:
        with pytest.raises(ContractError):recorder.start(kind,stage,parent_id=parent)


def _event(number,*,kind='window',pid=10,api='Document.querySelector'):
    execution={'context_id':str(number)}
    if kind=='window':execution['frame_id']=str(number)
    if kind=='worker':execution['worker_id']=str(number)
    return {'process':{'pid':pid},'execution':execution,'event':{'name':api}}


def test_inventory_discovers_minor_context_without_assigning_analyst_ownership():
    inventory=MetadataInventory()
    for index in range(20):
        for _ in range(10):inventory.add(_event(index))
    inventory.add(_event(99,kind='worker',api='Worker.postMessage'))
    result=inventory.result(analyst_activity(['browser-control']))
    assert result['matching_events']=='201'
    assert result['context_kind_counts']['worker']=='1'
    assert result['contexts']['total_groups']==21 and result['contexts']['truncated']
    assert len(result['contexts']['groups'])==16
    assert result['analyst_instrumentation']['event_ownership']=='unresolved'
    assert not result['analyst_instrumentation']['declaration_assigns_events']
    assert inventory.result([])['analyst_instrumentation']['activity_presence']=='unknown'


def test_inventory_does_not_merge_contexts_across_renderer_processes():
    inventory=MetadataInventory()
    inventory.add(_event(1,pid=1));inventory.add(_event(1,pid=2))
    assert inventory.result([])['contexts']['total_groups']==2


@pytest.mark.parametrize('value',['browser-control', ['unknown'], ['browser-control']*2, [None]])
def test_activity_declarations_fail_closed(value):
    with pytest.raises(ContractError):analyst_activity(value)


def test_inventory_exact_filtered_population_and_declaration_cursor_binding(source,events):
    from browser_core.metadata_query import metadata_query
    from browser_core.inspection_history import history_filters
    options={'filters':history_filters(start_ns='103'),'limit':1,'bundle_sha256':'a'*64,
             'analyst_activity':['page-evaluation'], 'metadata_version':2}
    result=metadata_query(source,**options)
    assert len(result['events'])==1 and result['inventory']['matching_events']=='4'
    assert result['inventory']['contexts']['groups'][0]['events']=='4'
    assert result['inventory']['apis']['groups'][0]['events']=='4'
    import jsonschema
    schema=json.loads((Path(__file__).resolve().parents[1]/'schemas/metadata-query-v2.schema.json').read_text())
    jsonschema.Draft202012Validator(schema).validate(result)
    with pytest.raises(ContractError,match='cursor is invalid'):
        metadata_query(source,**{**options,'analyst_activity':[]},cursor=result['query']['next_cursor'])


def test_terminal_ambiguity_receipt_binds_frozen_source_and_no_raw_details(tmp_path):
    from browser_core.collect_evidence import _terminal_failure
    from browser_core.metadata_query import MetadataQueryError
    import time
    diagnostic=DynamicCallerAmbiguity(pid=1,thread_id=2,caller_script_id=3,seq=5,timestamp=6,
                                     matches={1:{'seq':1},2:{'seq':2}}).diagnostic
    state={'stage':'export','completion_published':False,
           'source':{'run_id':'fixture-run','recording_sha256':'a'*64,'bundle_sha256':'b'*64}}
    with pytest.raises(MetadataQueryError):
        with _terminal_failure(tmp_path,lambda:None,state,time.monotonic()):
            raise MetadataQueryError('metadata-attribution-ambiguous',diagnostic=diagnostic)
    receipt=json.loads((tmp_path/'collection.failure.json').read_text())
    assert receipt['source']==state['source'] and receipt['diagnostic']==diagnostic
    assert len(json.dumps(receipt).encode())<16*1024
    assert not (tmp_path/'collection.json').exists()


def test_changed_output_identity_does_not_publish_failure(tmp_path):
    from browser_core.collect_evidence import _terminal_failure
    import time
    def changed():raise ContractError('identity changed')
    with pytest.raises(ContractError,match='original') as caught:
        with _terminal_failure(tmp_path,changed,{'stage':'export','completion_published':False},time.monotonic()):
            raise ContractError('original')
    assert not caught.value.collection_failure_receipt['failure_receipt_published']
    assert not (tmp_path/'collection.failure.json').exists()


def test_ambiguity_is_retained_unresolved_without_context_leak():
    rows=[script_run_row(ts_monotonic_ns=str(100+index),context_id=f'context-{index}',
                        native_id=f'script:context-{index}:7') for index in range(12)]
    rows.append(dynamic_code_row(ts_monotonic_ns='150'))
    events=parse_export_csv(csv_rows_fixture(rows),'fixture-run',REVISION)
    dynamic=events[-1]
    assert dynamic['seq']==12
    assert dynamic['detail']['caller_parent_status']=='caller_context_ambiguous'
    assert 'execution' not in dynamic and 'causal_parent_seq' not in dynamic
    assert 'context-' not in json.dumps(dynamic)


def test_collection_failure_is_terminal_redacted_and_exclusive(tmp_path,monkeypatch):
    from types import SimpleNamespace
    from browser_core import collect_evidence as module
    class Source:
        def __init__(self,*args):pass
        def resolve(self):return SimpleNamespace()
    class Export:
        def prepare(self,*args):raise ContractError('sensitive operating system detail')
        def close(self):pass
    monkeypatch.setattr(module,'RecordingSource',Source)
    monkeypatch.setattr(module,'EvidenceExport',Export)
    output=tmp_path/'collection'
    with pytest.raises(ContractError) as caught:
        module.collect_evidence(tmp_path/'session',tmp_path,output)
    receipt=json.loads((output/'collection.failure.json').read_text())
    assert receipt==caught.value.collection_failure_receipt
    assert receipt['terminal'] and receipt['failure_receipt_published']
    assert not receipt['completion_published'] and not receipt['wait_for_completion_manifest']
    assert receipt['stage']=='prepare' and 'sensitive' not in json.dumps(receipt)
    assert not (output/'collection.json').exists()
    with pytest.raises(ContractError,match='new directory'):
        module.collect_evidence(tmp_path/'session',tmp_path,output)


def test_collection_receipt_publication_failure_preserves_original_failure(tmp_path,monkeypatch):
    from browser_core.collect_evidence import _terminal_failure
    import browser_core.collect_evidence as module
    import time
    monkeypatch.setattr(module,'publish_json_exclusive',lambda *a,**kw:(_ for _ in ()).throw(PermissionError()))
    with pytest.raises(ContractError,match='original') as caught:
        with _terminal_failure(tmp_path,lambda:None,{'stage':'export','completion_published':False},time.monotonic()):
            raise ContractError('original')
    assert caught.value.collection_failure_receipt['terminal']
    assert not caught.value.collection_failure_receipt['failure_receipt_published']


def test_cli_pre_admission_failure_is_terminal(tmp_path,capsys):
    from browser_core.cli import main
    assert main(['trace','collect','--session',str(tmp_path/'absent'), '--out',str(tmp_path/'out')])==2
    result=json.loads(capsys.readouterr().out)
    assert result['terminal'] and not result['failure_receipt_published']
    assert result['failure_receipt_file'] is None and not result['wait_for_completion_manifest']
