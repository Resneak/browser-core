"""Caller-side operation ledger. Never executes commands or stores their output.

Record wrappers and nested actions separately using IDs and parent IDs. Summary
counts each started ID once, including failed/incomplete attempts. Observed
requests are their own kind; they are not inferred to be agent-issued actions.
"""
from __future__ import annotations

from collections import Counter
from contextlib import contextmanager
from datetime import datetime, timezone
from io import BytesIO
import json
import math
from pathlib import Path
import time
import uuid

from .contracts import ContractError
from .control_files import decode_strict_json_bytes, read_bounded_control_snapshot_result

SCHEMA='browser-core.effort/1'
KINDS={'outer-tool','nested-cli','browser-action','observed-request','packaging'}
STAGES={'setup','analysis','cleanup','packaging'}
MAX_EFFORT_LEDGER_BYTES=16*1024*1024


class FinalizationRequired(ContractError):
    """A caller-side reserve refuses new work, not packaging or cleanup."""
    def __init__(self, reason: str):
        super().__init__('effort finalization reserve reached; stop analysis, package current evidence, then clean up')
        self.reason=reason
        self.automatic_finish_failed=False


def _finite_number(value):
    if type(value) not in (int,float):
        return False
    try:
        return math.isfinite(value)
    except OverflowError:
        return False


def _valid_question(question):
    return (isinstance(question, str) and bool(question.strip())
            and len(question) <= 256 and question.isprintable())


def effort_contract():
    """Discover enums and accounting limits without opening a ledger."""
    return {'schema':'browser-core.effort-contract/1', 'kinds':sorted(KINDS),
        'stages':sorted(STAGES), 'question_max_characters':256,
        'begin_before_first_input_read':True, 'records_output_content':False,
        'visible_bytes_measured_by':'caller-at-the-exposure-boundary',
        'unobserved_bytes':None, 'complete_external_census':False,
        'budget_gate':'optional-start-limit-with-cleanup-reserve',
        'cleanup_may_exceed_limit':True,
        'instrumentation_is_caller_declared':True,
        'finalization_reserve':{
            'opt_in':True,
            'operation_parameter':'packaging_reserve',
            'deadline_method':'set_analysis_deadline',
            'time_reserve_parameter':'packaging_reserve_seconds',
            'clock':'same-process-monotonic',
            'deadline_set_once_before_analysis':True,
            'refused_stages':['setup','analysis'],
            'finalization_stages':['packaging','cleanup'],
            'finalization_may_exceed_limits':True,
            'interrupts_running_operations':False,
            'external_freeze_verified':False}}


class EffortRecorder:
    """Construct before the first input read; retain the output file on failure."""
    def __init__(self,path: Path, *, operation_limit: int | None = None,
                 cleanup_reserve: int = 0, packaging_reserve: int = 0):
        if (operation_limit is not None and (type(operation_limit) is not int or operation_limit < 0)
                or type(cleanup_reserve) is not int or cleanup_reserve < 0
                or operation_limit is None and cleanup_reserve
                or operation_limit is not None and cleanup_reserve > operation_limit):
            raise ContractError('invalid effort operation limit or cleanup reserve')
        if (type(packaging_reserve) is not int or packaging_reserve < 0
                or operation_limit is None and packaging_reserve
                or operation_limit is not None
                and packaging_reserve + cleanup_reserve > operation_limit):
            raise ContractError('invalid effort packaging reserve')
        self.stream=path.open('xb')
        self.active={}
        self.started=0
        self.operation_limit=operation_limit
        self.cleanup_reserve=cleanup_reserve
        self.packaging_reserve=packaging_reserve
        self._analysis_started=False
        self._analysis_deadline=None
        self._analysis_cutoff=None
        self._finalization_reason=None

    def set_analysis_deadline(self, deadline_monotonic: float, *, packaging_reserve_seconds: float = 0.0):
        """Set once, before analysis, using this process's monotonic clock.

        The deadline includes packaging. Refuse new setup/analysis starts at
        deadline minus reserve; running operations and finalization are not
        cancelled. A past deadline is valid and causes immediate refusal.
        This in-memory policy is not evidence of an externally timely freeze.
        """
        if self._analysis_started or self._analysis_deadline is not None or self.stream.closed:
            raise ContractError('effort deadline must be set once before analysis starts')
        if (not _finite_number(deadline_monotonic)
                or not _finite_number(packaging_reserve_seconds)
                or packaging_reserve_seconds < 0):
            raise ContractError('invalid effort deadline or packaging time reserve')
        cutoff=deadline_monotonic-packaging_reserve_seconds
        if not _finite_number(cutoff):
            raise ContractError('invalid effort deadline or packaging time reserve')
        self._analysis_deadline=deadline_monotonic
        self._analysis_cutoff=cutoff

    def _check_finalization_reserve(self, stage):
        if stage in ('packaging','cleanup'):
            return
        if self._finalization_reason is None:
            if (self.operation_limit is not None
                    and self.started >= self.operation_limit-self.cleanup_reserve-self.packaging_reserve):
                self._finalization_reason='operation-reserve'
            elif self._analysis_cutoff is not None:
                try:
                    now=time.monotonic()
                except Exception:
                    now=None
                if not _finite_number(now):
                    self._finalization_reason='clock-unavailable'
                elif now >= self._analysis_cutoff:
                    self._finalization_reason='time-reserve'
        if self._finalization_reason is not None:
            raise FinalizationRequired(self._finalization_reason)

    def _write(self,row):
        body = (json.dumps({'schema':SCHEMA,**row},separators=(',',':'),
                           ensure_ascii=True,allow_nan=False)+'\n').encode('ascii')
        if self.stream.write(body) != len(body):
            raise ContractError('effort ledger write was incomplete')
        self.stream.flush()

    def start(self,kind: str,stage: str,*,parent_id=None,question: str | None = None):
        if (not isinstance(kind,str) or kind not in KINDS
                or not isinstance(stage,str) or stage not in STAGES
                or parent_id is not None and (not isinstance(parent_id,str) or parent_id not in self.active)):
            raise ContractError('invalid effort kind, stage or active parent; use effort_contract() or agent effort-contract')
        if question is not None and not _valid_question(question):
            raise ContractError('effort question must be 1..256 printable characters')
        if self.packaging_reserve or self._analysis_deadline is not None:
            self._check_finalization_reserve(stage)
        elif (stage!='cleanup' and self.operation_limit is not None
                and self.started>=self.operation_limit-self.cleanup_reserve):
            raise ContractError('effort operation budget reserved for cleanup; new work was not started')
        operation_id=uuid.uuid4().hex
        self._write({'event':'start','id':operation_id,'parent_id':parent_id,'kind':kind,'stage':stage,
                     'at':datetime.now(timezone.utc).isoformat(), 'question':question})
        self.active[operation_id]=time.monotonic()
        self.started+=1
        if stage=='analysis':
            self._analysis_started=True
        return operation_id

    @contextmanager
    def operation(self, kind: str, stage: str, *, parent_id=None, question=None):
        """Count before entry; finish with unknown bytes unless explicitly finished.

        Yield the operation ID. Call finish(id, ...) at the layer exposing bytes.
        Exceptions are re-raised; only their failed outcome is recorded.
        """
        operation_id=self.start(kind,stage,parent_id=parent_id,question=question)
        try:
            yield operation_id
        except FinalizationRequired as primary:
            if operation_id in self.active:
                try:
                    self.finish(operation_id,returncode=1)
                except Exception:
                    # Preserve the bounded gate result; no replacement finish
                    # or elapsed time is fabricated after a completion error.
                    primary.automatic_finish_failed=True
            raise
        except BaseException:
            if operation_id in self.active:
                self.finish(operation_id,returncode=1)
            raise
        else:
            if operation_id in self.active:
                self.finish(operation_id,returncode=0)

    def finish(self,operation_id,*,returncode,stdout=None,stderr=None,visible_output=None):
        if (not isinstance(operation_id,str) or operation_id not in self.active
                or returncode is not None and type(returncode) is not int):
            raise ContractError('invalid effort completion')
        if any(value is not None and type(value) is not bytes for value in (stdout,stderr,visible_output)):
            raise ContractError('effort output must be exact bytes or unknown')
        self._write({'event':'finish','id':operation_id,'at':datetime.now(timezone.utc).isoformat(),
            'elapsed_seconds':time.monotonic()-self.active[operation_id], 'returncode':returncode,
            'stdout_bytes':None if stdout is None else len(stdout),
            'stderr_bytes':None if stderr is None else len(stderr),
            'visible_output_bytes':None if visible_output is None else len(visible_output)})
        del self.active[operation_id]

    def close(self):
        self.stream.close()  # Unfinished starts remain countable and explicit.

    def __enter__(self):
        return self

    def __exit__(self,*exc):
        self.close()


def summarize_effort(path: Path,*,operation_limit=None,visible_byte_limit=None):
    for value in (operation_limit,visible_byte_limit):
        if value is not None and (type(value) is not int or value<0):
            raise ContractError('effort limits must be nonnegative integers')
    starts={}
    finishes={}
    snapshot=read_bounded_control_snapshot_result(
        path, maximum=MAX_EFFORT_LEDGER_BYTES, label='effort ledger'
    )
    if snapshot.state!='complete' or snapshot.body is None:
        raise ContractError(f'effort ledger is {snapshot.state}')
    with BytesIO(snapshot.body) as stream:
        for raw in stream:
            if len(raw)>4096 or len(starts)>100000:
                raise ContractError('effort ledger exceeds row limit')
            row=decode_strict_json_bytes(raw,label='effort row')
            if not isinstance(row,dict) or row.get('schema')!=SCHEMA:
                raise ContractError('invalid effort schema')
            operation_id=row.get('id')
            if not isinstance(operation_id,str) or len(operation_id)!=32:
                raise ContractError('invalid effort operation ID')
            if row.get('event')=='start':
                kind, stage, parent_id = row.get('kind'), row.get('stage'), row.get('parent_id')
                if (operation_id in starts or not isinstance(kind,str) or kind not in KINDS
                        or not isinstance(stage,str) or stage not in STAGES
                        or parent_id is not None and (not isinstance(parent_id,str)
                            or parent_id not in starts or parent_id in finishes)):
                    raise ContractError('duplicate or invalid effort start')
                question=row.get('question')
                if question is not None and not _valid_question(question):
                    raise ContractError('invalid effort question')
                starts[operation_id]=row
            elif row.get('event')=='finish':
                if operation_id not in starts or operation_id in finishes:
                    raise ContractError('unbound or duplicate effort finish')
                for key in ('stdout_bytes','stderr_bytes','visible_output_bytes'):
                    if key not in row or (row[key] is not None and (type(row[key]) is not int or row[key]<0)):
                        raise ContractError('invalid effort byte count')
                # Missing is malformed; explicit null is the legacy unknown result.
                if 'returncode' not in row or (row['returncode'] is not None and type(row['returncode']) is not int):
                    raise ContractError('invalid effort result code')
                finishes[operation_id]=row
            else:
                raise ContractError('invalid effort event')
    known=sum(row['visible_output_bytes'] or 0 for row in finishes.values())
    unknown=sum(row['visible_output_bytes'] is None for row in finishes.values())+len(starts)-len(finishes)
    return {'schema':'browser-core.effort-summary/1','inclusive_recorded_operations':len(starts),
        'by_kind':dict(Counter(row['kind'] for row in starts.values())),
        'by_stage':dict(Counter(row['stage'] for row in starts.values())),
        'completed_operations':len(finishes),'incomplete_operations':len(starts)-len(finishes),
        'failed_operations':sum(row['returncode'] not in (0,None) for row in finishes.values()),
        'operations_with_question':sum(bool(row.get('question')) for row in starts.values()),
        'visible_output_bytes':None if unknown else known,'known_visible_output_bytes':known,
        'operations_with_unknown_visible_bytes':unknown,
        'operation_limit':operation_limit,
        'operation_limit_exceeded':None if operation_limit is None else len(starts)>operation_limit,
        'visible_byte_limit':visible_byte_limit,
        'visible_byte_limit_exceeded':(None if visible_byte_limit is None else
            True if known>visible_byte_limit else None if unknown else False),
        'counting':'unique-start-ids-including-wrappers-nested-actions-failures-and-observations',
        'observed_requests_are_agent_actions':False,'complete_external_census':False}
