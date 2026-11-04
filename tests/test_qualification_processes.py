"""Offline ownership regressions. Every process API is replaced by a fake."""
from dataclasses import FrozenInstanceError, replace
from pathlib import Path
from types import SimpleNamespace
import itertools
import subprocess

import pytest
from browser_core.errors import ContractError
from scripts import qualification_processes as q

IMAGE = 'C:/fixture/python.exe'
CHROME = 'C:/fixture/chrome.exe'


def row(pid, parent=1, created=100, image=IMAGE):
    return q.ObservedProcess(pid, parent, created, image)


def observe(rows, later=None, root=None, images=(IMAGE, CHROME)):
    root = rows[0] if root is None else root
    return q.observe_descendant_frames(root, q.snapshot(rows),
        q.snapshot(rows if later is None else later), allowed_images=images)


class FakeProcess:
    def __init__(self, pid):
        self.pid = pid
        self.returncode = None
        self.killed = 0
        self.waits = []
        self.kill_error = self.wait_error = None
    def poll(self): return self.returncode
    def kill(self):
        self.killed += 1
        if self.kill_error is not None: raise self.kill_error
        self.returncode = -1
    def wait(self, timeout):
        self.waits.append(timeout)
        if self.wait_error is not None: raise self.wait_error
        return self.returncode


@pytest.fixture(autouse=True)
def fake_process_api(monkeypatch):
    launches = []
    def create(command, **kwargs):
        process = FakeProcess(700 + len(launches))
        launches.append((process, command, kwargs))
        return process
    monkeypatch.setattr(q, 'os', SimpleNamespace(name='nt'))
    monkeypatch.setattr(q, 'subprocess', SimpleNamespace(
        Popen=create, DEVNULL=subprocess.DEVNULL, CREATE_NO_WINDOW=0x08000000))
    return launches


def test_valid_tree_and_unrelated_process_are_separate():
    report = observe([row(10), row(12,10,102,CHROME), row(11,10,101),
                      row(13,11,103,CHROME), row(90,1,105,CHROME)])
    assert report.root_state == 'stable'
    assert [item.pid for item in report.processes] == [11,12,13]
    assert not report.excluded_counts


def test_incident_shape_rejects_old_process_even_if_image_is_allowed():
    report = observe([row(10), row(11,10,90)])
    assert not report.processes
    assert report.excluded_counts == {'created-before-parent': 1}


def test_creation_order_is_checked_against_each_parent_not_just_root():
    report = observe([row(10), row(11,10,200), row(12,11,150,CHROME), row(13,12,300)])
    assert [item.pid for item in report.processes] == [11]
    assert report.excluded_counts == {'created-before-parent': 1}


def test_old_or_unrelated_bridge_cannot_admit_a_younger_allowed_process():
    for bridge in (row(11,10,90), row(11,10,101,'C:/unrelated/service.exe')):
        report = observe([row(10),bridge,row(12,11,102,CHROME)])
        assert not report.processes
        assert sum(report.excluded_counts.values()) == 1


@pytest.mark.parametrize('change,reason', [
    ({'created':999},'changed-instance'), ({'executable':CHROME},'changed-instance'),
    ({'parent_pid':99},'changed-parent')])
def test_reused_pid_or_changed_edge_is_not_admitted(change, reason):
    rows=[row(10),row(11,10,101),row(12,11,102)]
    report=observe(rows,[rows[0],replace(rows[1],**change),rows[2]])
    assert not report.processes and report.excluded_counts=={reason:1}


@pytest.mark.parametrize('mode', ['missing-before','missing-after','root-reused','root-image-changed'])
def test_root_must_be_same_instance_in_both_frames(mode):
    root=row(10)
    before=[root,row(11,10,101)]
    after=list(before)
    if mode=='missing-before':before=before[1:]
    elif mode=='missing-after':after=after[1:]
    elif mode=='root-reused':after[0]=replace(root,created=999)
    else:after[0]=replace(root,executable=CHROME)
    report=observe(before,after,root=root)
    assert report.root_state==('unavailable' if mode.startswith('missing') else 'changed')
    assert not report.processes


def test_missing_child_is_explicit_and_new_late_child_not_silently_added():
    before=[row(10),row(11,10,101)]
    after=[before[0],row(12,10,102)]
    report=observe(before,after)
    assert not report.processes and report.excluded_counts=={'unavailable':1}


def test_rooted_cycle_is_rejected():
    root=row(10,11,100)
    with pytest.raises(ContractError,match='cycle'):
        observe([root,row(11,10,100)])


def test_order_does_not_change_results():
    root=row(10)
    rows=[root,row(11,10,101),row(12,11,102)]
    expected=observe(rows)
    for before in itertools.permutations(rows):
        for after in itertools.permutations(rows):
            assert observe(list(before),list(after),root=root)==expected


def test_deep_chain_is_iterative_and_bounded():
    root=row(10)
    rows=[root]+[row(i,i-1,100+i) for i in range(11,1011)]
    assert len(observe(rows).processes)==1000


def test_snapshot_and_result_are_not_mutable_aliases():
    root=row(10)
    source=[root,row(11,10,101)]
    frame=q.snapshot(source)
    source.clear()
    assert len(frame)==2
    with pytest.raises(TypeError):frame[99]=root
    with pytest.raises(FrozenInstanceError):root.created=999
    result=q.observe_descendant_frames(root,frame,frame,allowed_images=[IMAGE])
    with pytest.raises(TypeError):result.excluded_counts['changed-instance']=1


@pytest.mark.parametrize('rows', [[row(10),row(10)], [None], (x for x in []), None])
def test_invalid_or_duplicate_snapshot_rows_are_rejected(rows):
    with pytest.raises(ContractError):q.snapshot(rows)


def test_snapshot_limits(monkeypatch):
    monkeypatch.setattr(q,'MAX_ROWS',1)
    with pytest.raises(ContractError):q.snapshot([row(10),row(11)])
    monkeypatch.setattr(q,'MAX_SNAPSHOT_CHARS',1)
    with pytest.raises(ContractError):q.snapshot([row(10)])


@pytest.mark.parametrize('values', [
    {'pid':True}, {'pid':0}, {'parent_pid':-1}, {'created':0}, {'created':2**64},
    {'executable':'relative.exe'}, {'executable':'C:relative.exe'},
    {'executable':'C:/bad\0image.exe'}, {'executable':None},
    {'executable':'C:/bad\ud800image.exe'}])
def test_malformed_identity_is_rejected(values):
    fields=dict(pid=10,parent_pid=1,created=100,executable=IMAGE)
    fields.update(values)
    with pytest.raises(ContractError):q.ObservedProcess(**fields)


@pytest.mark.parametrize('frame', [{True:row(1)}, {11:row(10)}, {'10':row(10)}, {10:None}, []])
def test_malformed_frame_does_not_become_a_successful_empty_observation(frame):
    root=row(10)
    with pytest.raises(ContractError):
        q.observe_descendant_frames(root,frame,{10:root},allowed_images=[IMAGE])


@pytest.mark.parametrize('images',[[],IMAGE,['relative.exe'],[None],['C:/unrelated/tool.exe']])
def test_invalid_image_policy_is_explicit(images):
    root=row(10);frame=q.snapshot([root])
    with pytest.raises(ContractError):
        q.observe_descendant_frames(root,frame,frame,allowed_images=images)


def test_canonical_image_aliases_compare_without_opening_files():
    root=row(10,image='C:/FIXTURE/./PYTHON.EXE')
    child=row(11,10,101,'c:\\fixture\\python.exe')
    assert observe([root,child],images=[IMAGE]).processes==(child,)


@pytest.mark.parametrize('owner', [700, {'pid':700}, row(700), q.snapshot([row(700)]),
    q.DescendantObservations('stable',(row(700),),{}), FakeProcess(700)])
def test_observed_pid_or_external_process_object_cannot_authorize_cleanup(owner,fake_process_api):
    with pytest.raises(ContractError,match='directly created'):
        q.stop_created_process(owner)
    assert not fake_process_api
    if isinstance(owner,FakeProcess):assert owner.killed==0


def test_stop_targets_only_the_retained_launch_object(tmp_path,fake_process_api):
    owner=q.CreatedProcess([IMAGE,'-B'],cwd=tmp_path)
    first=fake_process_api[0][0]
    unrelated=FakeProcess(owner.diagnostic_pid)
    assert q.stop_created_process(owner,timeout_seconds=2)==-1
    assert first.killed==1 and first.waits==[2.0] and unrelated.killed==0
    kwargs=fake_process_api[0][2]
    assert kwargs['shell'] is False and kwargs['creationflags']==0x08000000
    assert kwargs['stdout']==kwargs['stderr']==subprocess.DEVNULL


def test_already_exited_owner_is_reaped_without_kill(tmp_path,fake_process_api):
    owner=q.CreatedProcess([IMAGE],cwd=tmp_path)
    child=fake_process_api[0][0];child.returncode=0
    assert q.stop_created_process(owner)==0 and child.killed==0
    assert q.stop_created_process(owner)==0 and child.killed==0


@pytest.mark.parametrize('error', [PermissionError(),RuntimeError(),KeyboardInterrupt()])
def test_cleanup_error_does_not_fall_back_to_pid_or_other_owner(tmp_path,fake_process_api,error):
    first=q.CreatedProcess([IMAGE],cwd=tmp_path)
    second=q.CreatedProcess([IMAGE],cwd=tmp_path)
    fake_process_api[0][0].kill_error=error
    with pytest.raises(type(error)):q.stop_created_process(first)
    assert fake_process_api[1][0].killed==0 and second.poll() is None


def test_disappearance_at_kill_still_uses_the_original_wait_object(tmp_path,fake_process_api):
    owner=q.CreatedProcess([IMAGE],cwd=tmp_path)
    child=fake_process_api[0][0];child.kill_error=ProcessLookupError()
    q.stop_created_process(owner)
    assert child.killed==1 and child.waits==[5.0]


def test_bounded_wait_failure_has_no_descendant_cleanup(tmp_path,fake_process_api):
    owner=q.CreatedProcess([IMAGE],cwd=tmp_path)
    child=fake_process_api[0][0]
    child.wait_error=subprocess.TimeoutExpired('fixture',.1)
    with pytest.raises(subprocess.TimeoutExpired):q.stop_created_process(owner,timeout_seconds=.1)
    assert child.killed==1 and child.waits==[.1] and len(fake_process_api)==1


@pytest.mark.parametrize('timeout', [0,-1,True,None,float('nan'),float('inf'),61,10**1000],
                         ids=['zero','negative','boolean','none','nan','infinity','too-long','huge-integer'])
def test_invalid_timeout_fails_before_any_process_action(tmp_path,fake_process_api,timeout):
    owner=q.CreatedProcess([IMAGE],cwd=tmp_path)
    with pytest.raises(ContractError):q.stop_created_process(owner,timeout_seconds=timeout)
    assert fake_process_api[0][0].killed==0 and not fake_process_api[0][0].waits


@pytest.mark.parametrize('command', [700,{'pid':700},[],['relative.exe'],[IMAGE,None],[IMAGE,'bad\0arg'],
                                    ['C:/fixture/launch.cmd'],['C:/fixture/launch.bat']])
def test_pid_and_invalid_command_cannot_construct_an_owner(tmp_path,fake_process_api,command):
    with pytest.raises(ContractError):q.CreatedProcess(command,cwd=tmp_path)
    assert not fake_process_api


def test_creation_error_does_not_produce_an_owner_or_cleanup_other_processes(tmp_path,monkeypatch):
    def fail(*args,**kwargs):raise OSError('fixture creation failure')
    monkeypatch.setattr(q.subprocess,'Popen',fail)
    with pytest.raises(OSError):q.CreatedProcess([IMAGE],cwd=tmp_path)
