"""Final-boundary custody for strict control-file removal and workspace probes."""
from contextlib import contextmanager
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from browser_core import control_files, windows_file_delete, workspace_check
from browser_core.contracts import ContractError

ROOT=Path(__file__).resolve().parents[1]
WINDOWS=pytest.mark.skipif(os.name!='nt', reason='real Windows exclusive-handle deletion')
BODY=b'browser-core-workspace-check\n'


def options(path):
    return dict(expected_body=path.read_bytes(),
                expected_identity=control_files._identity(path.stat()),
                maximum=4096,label='owned test control',require_handle_delete=True)


def remove(path, bound):
    control_files.remove_control_conditionally(path,**bound)


def quarantines(path):
    return list(path.parent.glob('.'+path.name+'.removed-*'))


@WINDOWS
@pytest.mark.parametrize('filename',['state.bin','tool.exe','tool.cmd','unicode-\u00e9.txt'])
def test_strict_delete_holds_byte_read_and_delete_authority_together(tmp_path,monkeypatch,filename):
    path=tmp_path/filename;path.write_bytes(BODY);bound=options(path)
    original=windows_file_delete.mark_for_delete
    calls=[]
    def protected(descriptor):
        current=quarantines(path)[0]
        os.lseek(descriptor,0,os.SEEK_SET)
        assert os.read(descriptor,4096)==BODY
        with pytest.raises(OSError):current.rename(tmp_path/'stolen')
        with pytest.raises(OSError):current.write_bytes(b'foreign')
        with pytest.raises(OSError):current.unlink()
        calls.append(True)
        original(descriptor)
    monkeypatch.setattr(windows_file_delete,'mark_for_delete',protected)
    remove(path,bound)
    assert calls==[True] and not path.exists() and not quarantines(path)


@WINDOWS
@pytest.mark.parametrize('replacement',[b'foreign-late-replacement',BODY])
def test_exact_late_quarantine_replacement_survives_preflight(tmp_path,monkeypatch,replacement):
    work=tmp_path/'workspace'
    for part in ('profiles/data/analysis','profiles/registry','sessions','traces'):
        (work/part).mkdir(parents=True,exist_ok=True)
    original=control_files.directory_identity;seen=0;replaced=[]
    retained=tmp_path/'retained-original-quarantine'
    def swap(path,*,label):
        nonlocal seen
        identity=original(path,label=label)
        found=list(path.glob('.*.removed-*'))
        if label=='control removal parent' and found and not replaced:
            seen+=1
            if seen==2:
                current=found[0];current.rename(retained)
                current.write_bytes(replacement);replaced.append(current)
        return identity
    monkeypatch.setattr(control_files,'directory_identity',swap)
    def forbidden(*a,**kw):raise AssertionError('cleanup failed before native admission')
    monkeypatch.setattr(workspace_check,'native_browser_path',forbidden)
    result=workspace_check.check_workspace(work,ROOT,'analysis')
    assert replaced and replaced[0].read_bytes()==replacement
    assert retained.read_bytes()==BODY
    assert result['code']=='workspace-cleanup-incomplete'
    assert not result['workspace_ready'] and not result['cleanup_verified']


@WINDOWS
def test_replacement_on_final_handle_open_is_not_adopted(tmp_path,monkeypatch):
    path=tmp_path/'probe';path.write_bytes(BODY);bound=options(path)
    retained=tmp_path/'retained-original';replaced=[]
    original=windows_file_delete.exclusive_file
    @contextmanager
    def replace(current,**kwargs):
        current.rename(retained);current.write_bytes(BODY);replaced.append(current)
        with original(current,**kwargs) as descriptor:yield descriptor
    monkeypatch.setattr(windows_file_delete,'exclusive_file',replace)
    with pytest.raises(ContractError,match='changed before handle removal'):remove(path,bound)
    assert retained.read_bytes()==BODY and replaced[0].read_bytes()==BODY


@WINDOWS
def test_same_inode_rewritten_bytes_are_rechecked_under_final_handle(tmp_path,monkeypatch):
    path=tmp_path/'probe';path.write_bytes(BODY);bound=options(path)
    original=windows_file_delete.exclusive_file;changed=[]
    @contextmanager
    def rewrite(current,**kwargs):
        before=current.stat();current.write_bytes(b'x'*len(BODY))
        os.utime(current,ns=(before.st_atime_ns,before.st_mtime_ns))
        changed.append(current)
        with original(current,**kwargs) as descriptor:yield descriptor
    monkeypatch.setattr(windows_file_delete,'exclusive_file',rewrite)
    with pytest.raises(ContractError,match='changed before handle removal'):remove(path,bound)
    assert changed[0].read_bytes()==b'x'*len(BODY)


@WINDOWS
def test_conflicting_reader_never_enables_a_pathname_fallback(tmp_path,monkeypatch):
    path=tmp_path/'probe';path.write_bytes(BODY);bound=options(path)
    original=windows_file_delete.exclusive_file
    @contextmanager
    def blocked(current,**kwargs):
        with current.open('rb'):
            with original(current,**kwargs) as descriptor:yield descriptor
    monkeypatch.setattr(windows_file_delete,'exclusive_file',blocked)
    def no_unlink(*a,**kw):raise AssertionError('strict removal must not unlink by pathname')
    monkeypatch.setattr(control_files.os,'unlink',no_unlink)
    with pytest.raises(ContractError,match='handle-bound removal failed'):remove(path,bound)
    assert quarantines(path)[0].read_bytes()==BODY


@WINDOWS
@pytest.mark.parametrize('error',[PermissionError('private-message'),OSError('private-message'),KeyboardInterrupt()])
def test_final_mark_failure_closes_handle_preserves_residue_and_redacts(tmp_path,monkeypatch,error):
    path=tmp_path/'probe';path.write_bytes(BODY);bound=options(path)
    def failed(descriptor):raise error
    monkeypatch.setattr(windows_file_delete,'mark_for_delete',failed)
    with pytest.raises(KeyboardInterrupt if isinstance(error,KeyboardInterrupt) else ContractError) as caught:
        remove(path,bound)
    assert 'private-message' not in str(caught.value)
    residue=quarantines(path)[0]
    assert residue.read_bytes()==BODY
    residue.rename(tmp_path/'unlocked-residue')


@WINDOWS
def test_non_deleting_api_result_is_not_reported_as_cleanup_success(tmp_path,monkeypatch):
    path=tmp_path/'probe';path.write_bytes(BODY);bound=options(path)
    monkeypatch.setattr(windows_file_delete,'mark_for_delete',lambda descriptor:None)
    with pytest.raises(ContractError,match='not confirmed'):remove(path,bound)
    assert quarantines(path)[0].read_bytes()==BODY


@WINDOWS
def test_recreated_quarantine_after_handle_close_is_preserved(tmp_path,monkeypatch):
    path=tmp_path/'probe';path.write_bytes(BODY);bound=options(path)
    original=windows_file_delete.exclusive_file;recreated=[]
    @contextmanager
    def after_close(current,**kwargs):
        with original(current,**kwargs) as descriptor:yield descriptor
        assert not current.exists()
        current.write_bytes(b'foreign-after-close');recreated.append(current)
    monkeypatch.setattr(windows_file_delete,'exclusive_file',after_close)
    with pytest.raises(ContractError,match='not confirmed'):remove(path,bound)
    assert recreated[0].read_bytes()==b'foreign-after-close'


@WINDOWS
def test_parent_replacement_cannot_redirect_handle_deletion(tmp_path,monkeypatch):
    parent=tmp_path/'owned';parent.mkdir()
    path=parent/'probe';path.write_bytes(BODY);bound=options(path)
    retained=tmp_path/'retained-parent';original=windows_file_delete.mark_for_delete
    replacement=[]
    def swap(descriptor):
        current=quarantines(path)[0]
        try:parent.rename(retained)
        except OSError:replacement.append(False)
        else:
            parent.mkdir();current.write_bytes(b'foreign-parent');replacement.append(current)
        original(descriptor)
    monkeypatch.setattr(windows_file_delete,'mark_for_delete',swap)
    try:remove(path,bound)
    except ContractError:
        assert replacement and replacement[0] is not False
        assert replacement[0].read_bytes()==b'foreign-parent'
    else:assert replacement==[False]


@WINDOWS
def test_strict_delete_rejects_shared_file_custody(tmp_path):
    path=tmp_path/'probe';path.write_bytes(BODY)
    outside=tmp_path/'outside';os.link(path,outside);bound=options(path)
    with pytest.raises(ContractError):remove(path,bound)
    assert outside.read_bytes()==BODY and quarantines(path)[0].read_bytes()==BODY


def test_unsupported_platform_preserves_public_probe_without_quarantine(tmp_path,monkeypatch):
    path=tmp_path/'probe';path.write_bytes(BODY);bound=options(path)
    parent=control_files.directory_identity(path.parent,label='fixture')
    monkeypatch.setattr(control_files,'os',SimpleNamespace(name='unsupported'))
    with pytest.raises(ContractError,match='unavailable'):
        control_files._remove_control_strict(path,expected_body=BODY,
            expected_identity=bound['expected_identity'],expected_parent_identity=parent,
            maximum=4096,label='owned test control')
    assert path.read_bytes()==BODY and not quarantines(path)


@pytest.mark.parametrize('flag',[None,0,1,'yes'])
def test_strict_removal_option_requires_a_boolean_before_file_access(tmp_path,flag):
    path=tmp_path/'probe';path.write_bytes(BODY);bound=options(path)
    bound['require_handle_delete']=flag
    with pytest.raises(ContractError,match='handle policy'):remove(path,bound)
    assert path.read_bytes()==BODY and not quarantines(path)


def test_strict_removal_cannot_claim_a_missing_probe_was_cleaned(tmp_path):
    path=tmp_path/'probe';path.write_bytes(BODY);bound=options(path)
    bound['missing_ok']=True
    with pytest.raises(ContractError,match='existing source'):remove(path,bound)
    assert path.read_bytes()==BODY and not quarantines(path)
