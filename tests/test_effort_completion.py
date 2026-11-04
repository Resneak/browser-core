"""Finish-row boundaries and legacy accounting, without application fixtures."""
from copy import deepcopy
import itertools
import json
from pathlib import Path

import pytest

from browser_core.cli import main
from browser_core.contracts import ContractError
from browser_core.effort import EffortRecorder, SCHEMA, summarize_effort
import browser_core.effort as effort_module

ID = 'a'*32
BAD = [None, False, True, 0, 1, -1, 0.0, 1.5, '', 'private-marker', [], {}, [0], {'x':0}]
REQUIRED = ['schema','event','id','returncode','stdout_bytes','stderr_bytes','visible_output_bytes']
COUNTS = ['stdout_bytes','stderr_bytes','visible_output_bytes']

def rows():
    return [dict(schema=SCHEMA,event='start',id=ID,kind='outer-tool',stage='analysis'),
            dict(schema=SCHEMA,event='finish',id=ID,returncode=0,
                 stdout_bytes=0,stderr_bytes=0,visible_output_bytes=0)]

def ledger(tmp_path, values):
    path=tmp_path/'ledger.jsonl'
    path.write_text(''.join(json.dumps(r,separators=(',',':'))+'\n' for r in values),encoding='utf-8')
    return path


def test_recorder_rejects_short_ledger_write() -> None:
    class ShortStream:
        flushed = False

        def write(self, body):
            return len(body) - 1

        def flush(self):
            self.flushed = True

    recorder = EffortRecorder.__new__(EffortRecorder)
    recorder.stream = ShortStream()
    with pytest.raises(ContractError, match="effort ledger write"):
        recorder._write({"event": "start"})
    assert recorder.stream.flushed is False


def test_effort_summary_rechecks_file_size_after_open(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = ledger(tmp_path, rows()[:1])
    replacement = tmp_path / "replacement.jsonl"
    replacement.write_text(
        json.dumps({
            "schema": SCHEMA,
            "event": "start",
            "id": ID,
            "kind": "outer-tool",
            "stage": "analysis",
            "question": "x" * 256,
        }) + "\n",
        encoding="utf-8",
    )
    limit = target.stat().st_size + 1
    assert replacement.stat().st_size > limit
    monkeypatch.setattr(effort_module, "MAX_EFFORT_LEDGER_BYTES", limit, raising=False)
    original_open = Path.open

    def swapped_open(path, *args, **kwargs):
        if path == target:
            replacement.replace(target)
        return original_open(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", swapped_open)
    with pytest.raises(ContractError, match="effort ledger.*bytes"):
        summarize_effort(target)


@pytest.mark.parametrize('question', ['a\x7fb', 'a\u200bb'])
def test_effort_summary_rejects_nonprintable_question(tmp_path, question):
    values = rows()
    values[0]['question'] = question
    with pytest.raises(ContractError, match='^invalid effort question$'):
        summarize_effort(ledger(tmp_path, values))

def reject(path,capsys,message=None):
    with pytest.raises(ContractError) as caught:summarize_effort(path)
    diagnostic=str(caught.value)
    if message:assert diagnostic==message
    assert len(diagnostic.encode())<128 and 'private-marker' not in diagnostic
    assert main(['agent','effort-summary','--ledger',str(path)])==2
    captured=capsys.readouterr()
    assert captured.out=='' and captured.err=='browser-core: '+diagnostic+'\n'
    assert 'Traceback' not in captured.err

@pytest.mark.parametrize('key',REQUIRED)
def test_finish_required_field_omission_fails_closed(tmp_path,capsys,key):
    values=rows();del values[-1][key]
    reject(ledger(tmp_path,values),capsys,'invalid effort result code' if key=='returncode' else None)

@pytest.mark.parametrize('key',['schema','event','id','returncode',*COUNTS])
@pytest.mark.parametrize('value',BAD)
def test_finish_hostile_accounting_fields(tmp_path,capsys,key,value):
    if key=='returncode' and (value is None or type(value) is int):return
    if key in COUNTS and (value is None or type(value) is int and value>=0):return
    values=rows();values[-1][key]=value
    reject(ledger(tmp_path,values),capsys)

@pytest.mark.parametrize('value',BAD)
def test_finish_row_nonobject_shape(tmp_path,capsys,value):
    reject(ledger(tmp_path,[rows()[0],value]),capsys)

@pytest.mark.parametrize('sequence',['unbound','duplicate','before-start','changed-id','after-valid'])
def test_finish_binding_failure_never_returns_partial_summary(tmp_path,capsys,sequence):
    values=rows()
    if sequence=='unbound':values=values[1:]
    elif sequence=='duplicate':values.append(deepcopy(values[-1]))
    elif sequence=='before-start':values.reverse()
    elif sequence=='changed-id':values[-1]['id']='b'*32
    else:
        values.extend([{**values[0],'id':'b'*32},{**values[1],'id':'b'*32}])
        del values[-1]['returncode']
    reject(ledger(tmp_path,values),capsys)

@pytest.mark.parametrize('body',[
    b'{',b'\xff',b'{"schema":NaN}',b'{"schema":Infinity}',
    b'{"schema":1,"schema":2}',b'['*130+b'0'+b']'*130,
    b'{"x":'+b'1'*1025+b'}',b'{"x":"'+b'z'*4096+b'"}',
    b'{"x":"\\ud800"}',b'{"x":1e999}',
])
def test_finish_strict_json_and_size_bounds(tmp_path,capsys,body):
    path=ledger(tmp_path,rows()[:1])
    with path.open('ab') as stream:stream.write(body+b'\n')
    reject(path,capsys)

@pytest.mark.parametrize('returncode',[None,0,1,-1,255,10**100])
@pytest.mark.parametrize('counts',list(itertools.product([None,0,17],repeat=3)))
def test_legacy_valid_finish_fields_and_accounting(tmp_path,returncode,counts):
    values=rows();values[-1].update(returncode=returncode,**dict(zip(COUNTS,counts)))
    summary=summarize_effort(ledger(tmp_path,values),operation_limit=0,visible_byte_limit=16)
    assert summary['inclusive_recorded_operations']==summary['completed_operations']==1
    assert summary['failed_operations']==int(returncode not in (0,None))
    assert summary['known_visible_output_bytes']==(counts[-1] or 0)
    assert summary['visible_output_bytes']==counts[-1]
    assert summary['operations_with_unknown_visible_bytes']==int(counts[-1] is None)
    assert summary['visible_byte_limit_exceeded']==(None if counts[-1] is None else counts[-1]>16)
    assert summary['operation_limit_exceeded'] is True
    assert summary['operations_with_question']==0

@pytest.mark.parametrize('key',['at','elapsed_seconds','extension'])
@pytest.mark.parametrize('value',BAD)
def test_legacy_optional_metadata_does_not_affect_accounting(tmp_path,key,value):
    values=rows();path=ledger(tmp_path,values);expected=summarize_effort(path)
    values[-1][key]=value
    assert summarize_effort(ledger(tmp_path,values))==expected

@pytest.mark.parametrize('operation_id',BAD)
def test_recorder_finish_invalid_identity_fails_before_write(tmp_path,operation_id):
    path=tmp_path/'ledger'
    with EffortRecorder(path) as recorder:
        active=recorder.start('outer-tool','analysis')
        before=path.read_bytes()
        with pytest.raises(ContractError,match='^invalid effort completion$'):
            recorder.finish(operation_id,returncode=0)
        assert path.read_bytes()==before and active in recorder.active
        recorder.finish(active,returncode=0)
    assert summarize_effort(path)['completed_operations']==1

@pytest.mark.parametrize('field',['returncode','stdout','stderr','visible_output'])
@pytest.mark.parametrize('value',[False,True,0.0,'private-marker',[],{},bytearray(b'x')])
def test_recorder_finish_invalid_values_preserve_active_operation(tmp_path,field,value):
    path=tmp_path/'ledger'
    with EffortRecorder(path) as recorder:
        active=recorder.start('outer-tool','analysis');before=path.read_bytes()
        options={'returncode':0,field:value}
        with pytest.raises(ContractError):recorder.finish(active,**options)
        assert path.read_bytes()==before and active in recorder.active
        recorder.finish(active,returncode=None,visible_output=b'')
    result=summarize_effort(path)
    assert result['completed_operations']==1 and result['visible_output_bytes']==0
