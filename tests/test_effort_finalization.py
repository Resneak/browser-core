"""Opt-in reserves preserve actual accounting; no browser or real clock waits."""
import json
from types import SimpleNamespace

import pytest

from browser_core import effort
from browser_core.contracts import ContractError
from browser_core.effort import EffortRecorder, FinalizationRequired, summarize_effort


@pytest.fixture
def clock(monkeypatch):
    class FakeClock:
        now=100.0

        def __call__(self):
            if isinstance(self.now,BaseException):
                raise self.now
            return self.now

    clock=FakeClock()
    monkeypatch.setattr(effort,'time',SimpleNamespace(monotonic=clock))
    return clock


def complete(recorder,stage,*,kind='outer-tool',parent_id=None):
    operation=recorder.start(kind,stage,parent_id=parent_id)
    recorder.finish(operation,returncode=0,visible_output=b'')
    return operation


def refused(recorder,path,stage,reason,**options):
    before=path.read_bytes()
    starts=recorder.started
    active=dict(recorder.active)
    with pytest.raises(FinalizationRequired) as caught:
        recorder.start('outer-tool',stage,**options)
    assert isinstance(caught.value,ContractError)
    assert caught.value.reason==reason
    assert str(caught.value)=='effort finalization reserve reached; stop analysis, package current evidence, then clean up'
    assert len(str(caught.value).encode('ascii'))<128
    assert path.read_bytes()==before and recorder.started==starts and recorder.active==active


@pytest.mark.parametrize('stage',['setup','analysis'])
def test_operation_reserve_keeps_packaging_and_cleanup_countable(tmp_path,clock,stage):
    path=tmp_path/'ledger'
    with EffortRecorder(path,operation_limit=5,cleanup_reserve=1,packaging_reserve=2) as recorder:
        complete(recorder,'setup')
        complete(recorder,'analysis')
        refused(recorder,path,stage,'operation-reserve')
        for _ in range(4):
            complete(recorder,'packaging',kind='packaging')
        complete(recorder,'cleanup')
        refused(recorder,path,stage,'operation-reserve')
    summary=summarize_effort(path,operation_limit=5)
    assert summary['inclusive_recorded_operations']==7
    assert summary['operation_limit_exceeded'] is True
    assert summary['by_stage']=={'setup':1,'analysis':1,'packaging':4,'cleanup':1}
    assert summary['visible_output_bytes']==0 and summary['complete_external_census'] is False
    assert {row['event'] for row in map(json.loads,path.read_bytes().splitlines())}=={'start','finish'}


def test_nested_actions_share_reserve_and_existing_parent_can_finish(tmp_path,clock):
    path=tmp_path/'ledger'
    with EffortRecorder(path,operation_limit=4,cleanup_reserve=1,packaging_reserve=1) as recorder:
        outer=recorder.start('outer-tool','analysis')
        complete(recorder,'analysis',kind='nested-cli',parent_id=outer)
        refused(recorder,path,'analysis','operation-reserve',parent_id=outer)
        complete(recorder,'packaging',kind='packaging',parent_id=outer)
        recorder.finish(outer,returncode=0,visible_output=b'')
    assert summarize_effort(path)['inclusive_recorded_operations']==3


def test_nested_refusal_finishes_outer_wrapper_as_failed(tmp_path,clock):
    path=tmp_path/'ledger'
    with EffortRecorder(path,operation_limit=3,cleanup_reserve=1,packaging_reserve=1) as recorder:
        with pytest.raises(FinalizationRequired,match='stop analysis'):
            with recorder.operation('outer-tool','analysis') as outer:
                with recorder.operation('nested-cli','analysis',parent_id=outer):
                    pytest.fail('refused nested work must never execute')
        assert recorder.started==1 and recorder.active=={}
        complete(recorder,'packaging')
        complete(recorder,'cleanup')
    summary=summarize_effort(path)
    assert summary['inclusive_recorded_operations']==3 and summary['failed_operations']==1
    assert summary['incomplete_operations']==0 and summary['visible_output_bytes'] is None


@pytest.mark.parametrize('bad_clock',[None,float('nan'),OSError('PRIVATE_CLOCK_FAILURE')])
def test_persistent_bad_clock_preserves_nested_primary_and_incomplete_outer(tmp_path,clock,bad_clock):
    path=tmp_path/'ledger'
    original=[]
    with EffortRecorder(path) as recorder:
        recorder.set_analysis_deadline(200.0)
        with pytest.raises(FinalizationRequired) as caught:
            with recorder.operation('outer-tool','analysis') as outer:
                clock.now=bad_clock
                try:
                    with recorder.operation('nested-cli','analysis',parent_id=outer):
                        pytest.fail('refused child must never run')
                except FinalizationRequired as primary:
                    original.append(primary)
                    raise
        assert caught.value is original[0]
        assert caught.value.reason=='clock-unavailable'
        assert caught.value.automatic_finish_failed is True
        assert caught.value.__context__ is None and 'PRIVATE' not in str(caught.value)
        assert recorder.started==1 and set(recorder.active)=={outer}
        rows=list(map(json.loads,path.read_bytes().splitlines()))
        assert len(rows)==1 and rows[0]['event']=='start' and rows[0]['id']==outer
        interim=summarize_effort(path)
        assert interim['incomplete_operations']==1 and interim['completed_operations']==0
        assert interim['visible_output_bytes'] is None
        clock.now=220.0
        complete(recorder,'packaging')
        complete(recorder,'cleanup')
    summary=summarize_effort(path)
    assert summary['inclusive_recorded_operations']==3 and summary['incomplete_operations']==1
    assert summary['completed_operations']==2 and summary['failed_operations']==0
    assert summary['visible_output_bytes'] is None


@pytest.mark.parametrize('bad_clock,expected',[
    (None,TypeError),(float('nan'),ValueError),(OSError('PRIVATE_CLOCK_FAILURE'),OSError),
])
def test_direct_finish_error_behavior_is_unchanged(tmp_path,clock,bad_clock,expected):
    path=tmp_path/'ledger'
    with EffortRecorder(path) as recorder:
        operation=recorder.start('outer-tool','analysis')
        before=path.read_bytes()
        clock.now=bad_clock
        with pytest.raises(expected):
            recorder.finish(operation,returncode=1)
        assert path.read_bytes()==before and set(recorder.active)=={operation}
    summary=summarize_effort(path)
    assert summary['inclusive_recorded_operations']==1 and summary['incomplete_operations']==1


@pytest.mark.parametrize('partial_write',[False,True])
def test_finalization_primary_survives_completion_write_failure_without_integrity_claim(tmp_path,clock,monkeypatch,partial_write):
    path=tmp_path/'ledger'
    with EffortRecorder(path,operation_limit=2,packaging_reserve=1) as recorder:
        original_write=recorder._write
        def fail_finish(row):
            if row['event']=='finish':
                if partial_write:
                    recorder.stream.write(b'{')
                    recorder.stream.flush()
                raise OSError('PRIVATE_WRITE_FAILURE')
            original_write(row)
        monkeypatch.setattr(recorder,'_write',fail_finish)
        with pytest.raises(FinalizationRequired) as caught:
            with recorder.operation('outer-tool','analysis') as outer:
                before=path.read_bytes()
                with recorder.operation('nested-cli','analysis',parent_id=outer):
                    pytest.fail('refused child must never run')
        assert caught.value.reason=='operation-reserve'
        assert caught.value.automatic_finish_failed is True
        assert caught.value.__context__ is None and 'PRIVATE' not in str(caught.value)
        assert path.read_bytes()==before+(b'{' if partial_write else b'')
        assert recorder.started==1 and set(recorder.active)=={outer}
    if partial_write:
        with pytest.raises(ContractError):
            summarize_effort(path)
    else:
        summary=summarize_effort(path)
        assert summary['incomplete_operations']==1 and summary['completed_operations']==0
        assert summary['visible_output_bytes'] is None


def test_ordinary_exception_completion_failure_keeps_legacy_precedence(tmp_path,clock,monkeypatch):
    path=tmp_path/'ledger'
    secondary=OSError('SECONDARY_WRITE_FAILURE')
    with EffortRecorder(path) as recorder:
        original_write=recorder._write
        def fail_finish(row):
            if row['event']=='finish':
                raise secondary
            original_write(row)
        monkeypatch.setattr(recorder,'_write',fail_finish)
        with pytest.raises(OSError) as caught:
            with recorder.operation('outer-tool','analysis'):
                raise ValueError('ORIGINAL_BODY_FAILURE')
        assert caught.value is secondary and recorder.started==1 and len(recorder.active)==1


def test_finalization_completion_does_not_swallow_baseexception_interrupt(tmp_path,clock,monkeypatch):
    path=tmp_path/'ledger'
    interrupt=KeyboardInterrupt()
    with EffortRecorder(path,operation_limit=2,packaging_reserve=1) as recorder:
        original_write=recorder._write
        def interrupt_finish(row):
            if row['event']=='finish':
                raise interrupt
            original_write(row)
        monkeypatch.setattr(recorder,'_write',interrupt_finish)
        with pytest.raises(KeyboardInterrupt) as caught:
            with recorder.operation('outer-tool','analysis') as outer:
                recorder.start('nested-cli','analysis',parent_id=outer)
        assert caught.value is interrupt and set(recorder.active)=={outer}


def test_all_operations_can_be_reserved_before_setup(tmp_path,clock):
    path=tmp_path/'ledger'
    with EffortRecorder(path,operation_limit=3,cleanup_reserve=1,packaging_reserve=2) as recorder:
        refused(recorder,path,'setup','operation-reserve')
        complete(recorder,'packaging')
        complete(recorder,'cleanup')


@pytest.mark.parametrize('packaging_reserve',[False,True,-1,1.0,float('nan'),float('inf'),None,'2',[],{}])
def test_invalid_operation_reserve_creates_no_file(tmp_path,packaging_reserve):
    path=tmp_path/'ledger'
    with pytest.raises(ContractError,match='^invalid effort packaging reserve$'):
        EffortRecorder(path,operation_limit=5,packaging_reserve=packaging_reserve)
    assert not path.exists()


@pytest.mark.parametrize('options',[
    {'packaging_reserve':1},
    {'operation_limit':3,'cleanup_reserve':2,'packaging_reserve':2},
    {'operation_limit':0,'packaging_reserve':1},
    {'operation_limit':10**1000,'cleanup_reserve':10**1000,'packaging_reserve':1},
    {'operation_limit':5,'packaging_reserve':10**1000},
])
def test_unfunded_operation_reserve_creates_no_file(tmp_path,options):
    path=tmp_path/'ledger'
    with pytest.raises(ContractError,match='^invalid effort packaging reserve$'):
        EffortRecorder(path,**options)
    assert not path.exists()


@pytest.mark.parametrize('stage',['setup','analysis'])
def test_explicit_time_reserve_boundary_and_late_completion(tmp_path,clock,stage):
    path=tmp_path/'ledger'
    with EffortRecorder(path) as recorder:
        complete(recorder,'setup')
        recorder.set_analysis_deadline(200.0,packaging_reserve_seconds=20.0)
        clock.now=179.99
        active=recorder.start('outer-tool',stage)
        clock.now=180.0
        refused(recorder,path,stage,'time-reserve')
        clock.now=220.0
        recorder.finish(active,returncode=0,visible_output=b'')
        complete(recorder,'packaging')
        complete(recorder,'cleanup')
        # Once observed, exhaustion cannot be undone by a subsequent clock value.
        clock.now=150.0
        refused(recorder,path,'analysis','time-reserve')
    summary=summarize_effort(path)
    assert summary['inclusive_recorded_operations']==4 and summary['completed_operations']==4
    assert summary['complete_external_census'] is False


@pytest.mark.parametrize('invalid',[float('nan'),float('inf'),float('-inf'),True,None,'PRIVATE'])
def test_unavailable_clock_refuses_new_work_and_does_not_echo_values(tmp_path,clock,invalid):
    path=tmp_path/'ledger'
    with EffortRecorder(path) as recorder:
        recorder.set_analysis_deadline(200.0)
        clock.now=invalid
        refused(recorder,path,'analysis','clock-unavailable')
        clock.now=100.0
        refused(recorder,path,'setup','clock-unavailable')
        complete(recorder,'packaging')
        complete(recorder,'cleanup')


@pytest.mark.parametrize('exception',[OSError('PRIVATE clock error'),RuntimeError('PRIVATE clock error')])
def test_failed_clock_read_refuses_before_dispatch(tmp_path,clock,monkeypatch,exception):
    path=tmp_path/'ledger'
    with EffortRecorder(path) as recorder:
        recorder.set_analysis_deadline(200.0)
        def fail_clock():
            raise exception
        monkeypatch.setattr(effort.time,'monotonic',fail_clock)
        refused(recorder,path,'analysis','clock-unavailable')
        monkeypatch.setattr(effort.time,'monotonic',clock)
        complete(recorder,'packaging')


@pytest.mark.parametrize('deadline,reserve',[(99.0,0.0),(100.0,0.0),(110.0,20.0)])
def test_already_reached_cutoff_is_valid_but_refuses_new_work(tmp_path,clock,deadline,reserve):
    path=tmp_path/'ledger'
    with EffortRecorder(path) as recorder:
        recorder.set_analysis_deadline(deadline,packaging_reserve_seconds=reserve)
        refused(recorder,path,'setup','time-reserve')
        complete(recorder,'packaging')


@pytest.mark.parametrize('field',['deadline_monotonic','packaging_reserve_seconds'])
@pytest.mark.parametrize('value',[None,False,True,float('nan'),float('inf'),float('-inf'),10**1000,'PRIVATE',[],{}])
def test_invalid_time_policy_leaves_deadline_unset_and_ledger_unchanged(tmp_path,clock,field,value):
    path=tmp_path/'ledger'
    with EffortRecorder(path) as recorder:
        options={'deadline_monotonic':200.0,'packaging_reserve_seconds':20.0,field:value}
        before=path.read_bytes()
        with pytest.raises(ContractError,match='^invalid effort deadline or packaging time reserve$'):
            recorder.set_analysis_deadline(**options)
        assert path.read_bytes()==before and recorder._analysis_deadline is None
        recorder.set_analysis_deadline(200.0,packaging_reserve_seconds=20.0)
        complete(recorder,'analysis')


@pytest.mark.parametrize('deadline,reserve',[(200.0,-1.0),(-1e308,1e308)])
def test_negative_time_reserve_and_cutoff_overflow_fail_closed(tmp_path,clock,deadline,reserve):
    path=tmp_path/'ledger'
    with EffortRecorder(path) as recorder:
        with pytest.raises(ContractError,match='^invalid effort deadline or packaging time reserve$'):
            recorder.set_analysis_deadline(deadline,packaging_reserve_seconds=reserve)
        assert recorder._analysis_deadline is None and path.read_bytes()==b''


def test_deadline_cannot_be_extended_or_installed_after_analysis(tmp_path,clock):
    with EffortRecorder(tmp_path/'once') as recorder:
        recorder.set_analysis_deadline(200.0,packaging_reserve_seconds=20.0)
        with pytest.raises(ContractError,match='^effort deadline must be set once before analysis starts$'):
            recorder.set_analysis_deadline(300.0)
        assert recorder._analysis_deadline==200.0 and recorder._analysis_cutoff==180.0
    with EffortRecorder(tmp_path/'late') as recorder:
        complete(recorder,'analysis')
        with pytest.raises(ContractError,match='^effort deadline must be set once before analysis starts$'):
            recorder.set_analysis_deadline(300.0)
    with pytest.raises(ContractError,match='^effort deadline must be set once before analysis starts$'):
        recorder.set_analysis_deadline(300.0)


@pytest.mark.parametrize('operation_limit,deadline,expected',[(2,200.0,'operation-reserve'),(10,100.0,'time-reserve')])
def test_first_reached_reserve_gates_analysis(tmp_path,clock,operation_limit,deadline,expected):
    path=tmp_path/'ledger'
    with EffortRecorder(path,operation_limit=operation_limit,cleanup_reserve=1,packaging_reserve=1) as recorder:
        recorder.set_analysis_deadline(deadline)
        refused(recorder,path,'analysis',expected)
        complete(recorder,'packaging')
        complete(recorder,'cleanup')


def test_time_only_opt_in_preserves_exhausted_count_and_unfinished_packaging(tmp_path,clock):
    path=tmp_path/'ledger'
    with EffortRecorder(path,operation_limit=1) as recorder:
        recorder.set_analysis_deadline(200.0)
        complete(recorder,'setup')
        refused(recorder,path,'analysis','operation-reserve')
        recorder.start('packaging','packaging')
        with pytest.raises(ValueError):
            with recorder.operation('outer-tool','cleanup'):
                raise ValueError('PRIVATE exception')
    summary=summarize_effort(path,operation_limit=1)
    assert summary['inclusive_recorded_operations']==3 and summary['operation_limit_exceeded'] is True
    assert summary['incomplete_operations']==1 and summary['failed_operations']==1
    assert summary['visible_output_bytes'] is None and b'PRIVATE' not in path.read_bytes()


@pytest.mark.parametrize('options',[{}, {'packaging_reserve':0}])
def test_no_opt_in_preserves_old_gate_and_message(tmp_path,clock,options):
    path=tmp_path/'ledger'
    with EffortRecorder(path,operation_limit=2,cleanup_reserve=1,**options) as recorder:
        complete(recorder,'analysis')
        clock.now=1e9
        for stage in ('setup','analysis','packaging'):
            with pytest.raises(ContractError) as caught:
                recorder.start('outer-tool',stage)
            assert not isinstance(caught.value,FinalizationRequired)
            assert str(caught.value)=='effort operation budget reserved for cleanup; new work was not started'
        complete(recorder,'cleanup')
        complete(recorder,'cleanup')
    assert summarize_effort(path,operation_limit=2)['operation_limit_exceeded'] is True


def test_opt_in_does_not_change_legacy_summary_or_contract_during_use(tmp_path,clock):
    contract=effort.effort_contract()
    summaries=[]
    for name,options in [('legacy',{}),('reserve',{'packaging_reserve':2})]:
        path=tmp_path/name
        with EffortRecorder(path,operation_limit=10,cleanup_reserve=1,**options) as recorder:
            for stage in ('setup','analysis','packaging','cleanup'):
                complete(recorder,stage)
        summaries.append(summarize_effort(path,operation_limit=10))
    assert summaries[0]==summaries[1]
    assert effort.effort_contract()==contract
    assert contract['budget_gate']=='optional-start-limit-with-cleanup-reserve'
    assert contract['complete_external_census'] is False


def test_discovery_preserves_legacy_fields_and_bounds_additive_policy(capsys):
    from browser_core.cli import main
    contract=effort.effort_contract()
    finalization=contract.pop('finalization_reserve')
    assert contract=={
        'schema':'browser-core.effort-contract/1',
        'kinds':['browser-action','nested-cli','observed-request','outer-tool','packaging'],
        'stages':['analysis','cleanup','packaging','setup'],
        'question_max_characters':256,'begin_before_first_input_read':True,
        'records_output_content':False,'visible_bytes_measured_by':'caller-at-the-exposure-boundary',
        'unobserved_bytes':None,'complete_external_census':False,
        'budget_gate':'optional-start-limit-with-cleanup-reserve',
        'cleanup_may_exceed_limit':True,'instrumentation_is_caller_declared':True}
    assert finalization=={
        'opt_in':True,'operation_parameter':'packaging_reserve',
        'deadline_method':'set_analysis_deadline','time_reserve_parameter':'packaging_reserve_seconds',
        'clock':'same-process-monotonic','deadline_set_once_before_analysis':True,
        'refused_stages':['setup','analysis'],'finalization_stages':['packaging','cleanup'],
        'finalization_may_exceed_limits':True,'interrupts_running_operations':False,
        'external_freeze_verified':False}
    assert main(['agent','effort-contract'])==0
    captured=capsys.readouterr()
    assert captured.err=='' and json.loads(captured.out)==effort.effort_contract()
    assert len(captured.out.replace('\n','\r\n').encode('utf-8'))<=4096
