from contextlib import contextmanager
import gc
import hashlib
import os
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import weakref

import pytest

from browser_core.contracts import ContractError
from browser_core.evidence_bundle import EvidenceExport
from browser_core.inspection_attribution import ContextAttribution
from browser_core.inspection_comparison import ComparisonExport
from browser_core.inspection_contract import CAPTURE_V1, CAPTURE_V2
from browser_core.incremental_inspection import IncrementalInspection
from browser_core.owned_paths import directory_ancestry_binding
from browser_core.prepared_download import (
    ExportCleanupPending,
    PreparedDownload,
    guarded_temporary_directory_with_check,
)
from test_evidence_bundle import BUILD, BODY
from test_inspection_comparison import frozen, attribution
from test_inspection_history import Decoder


@pytest.fixture(params=['comparison','evidence'])
def prepared(request,tmp_path):
    calls=[]
    if request.param=='comparison':
        reader=IncrementalInspection(Path('/session'),tmp_path)
        reader.decoder=Decoder();reader.decoder.add(1,1)
        location=SimpleNamespace(path=tmp_path/'recording',phase='finalized-recording',
                                 session={'run_id':'owned-fixture'})
        reader.source=SimpleNamespace(resolve=lambda:location)
        reader.cursor=SimpleNamespace(source=location.path,close=lambda:None)
        def read(**kwargs):
            calls.append(True)
            return {**CAPTURE_V1,'run_id':'owned-fixture','events':[],
                    'source_sha256':'a'*64,'snapshot_bytes':3,'source_phase':'finalized-recording'}
        reader.read=read
        selection={k:frozen(reader,1) for k in ('a','b')}
        export=ComparisonExport()
        prepare=lambda:export.prepare(reader,attribution(),selection)
    else:
        path=tmp_path/'recording';path.write_bytes(BODY)
        location=SimpleNamespace(path=path,phase='finalized-recording',
            session={'run_id':'owned-run','build':BUILD,'value_capture':CAPTURE_V2},
            reader_runtime={'reader_build':BUILD})
        def resolve():calls.append(True);return location
        export=EvidenceExport()
        prepare=lambda:export.prepare(SimpleNamespace(resolve=resolve),ContextAttribution(),None)
        reader=None
    try:yield export,prepare,calls
    finally:
        export.close()
        if reader is not None:reader.close()


def verified(export):
    body=export.path.read_bytes()
    assert len(body)==export.receipt['bytes']
    assert hashlib.sha256(body).hexdigest()==export.receipt['sha256']
    return body


def test_published_receipt_does_not_retain_caller_alias(tmp_path: Path):
    export = PreparedDownload()
    folder = tempfile.TemporaryDirectory(dir=tmp_path)
    path = Path(folder.name) / 'export.json'
    path.write_bytes(b'published')
    receipt = {'bytes': 9, 'sha256': hashlib.sha256(b'published').hexdigest(),
               'summary': {'membership_events': 1}}
    try:
        returned = export._publish(folder, path, receipt)
        receipt['summary']['membership_events'] = 2
        returned['summary']['membership_events'] = 3
        assert export.receipt['summary']['membership_events'] == 1
        assert verified(export) == b'published'
    finally:
        export.close()


def test_replaced_published_directory_is_preserved_on_close(tmp_path, monkeypatch):
    export = PreparedDownload()
    folder = tempfile.TemporaryDirectory(dir=tmp_path)
    original_name = Path(folder.name)
    path = original_name / 'export.json'
    body = b'published'
    path.write_bytes(body)
    receipt = {'bytes': len(body), 'sha256': hashlib.sha256(body).hexdigest()}
    export._publish(folder, path, receipt)
    retained = tmp_path / 'retained-original'
    assert original_name.resolve().parent == tmp_path.resolve()
    original_name.rename(retained)
    original_name.mkdir()
    sentinel = original_name / 'unrelated.txt'
    sentinel.write_text('preserve', encoding='utf-8')
    cleanup = folder.cleanup
    calls = []
    monkeypatch.setattr(folder, 'cleanup', lambda: calls.append('cleanup'))
    try:
        with pytest.raises(ExportCleanupPending):
            export.close()
        assert calls == []
        assert sentinel.read_text(encoding='utf-8') == 'preserve'
        assert export.folder is folder
    finally:
        monkeypatch.setattr(folder, 'cleanup', cleanup)
        sentinel.unlink(missing_ok=True)
        original_name.rmdir()
        retained.rename(original_name)
        export.close()
        cleanup()


def test_published_download_preserves_copy_after_ancestor_changes(tmp_path):
    private_parent = tmp_path / 'private-parent'
    private_parent.mkdir()
    retained_parent = tmp_path / 'retained-parent'
    export = PreparedDownload()
    folder = tempfile.TemporaryDirectory(dir=private_parent)
    name = Path(folder.name).name
    current_folder = private_parent / name
    retained_folder = retained_parent / name
    path = current_folder / 'export.json'
    body = b'published'
    path.write_bytes(body)
    export._publish(folder, path, {
        'bytes': len(body), 'sha256': hashlib.sha256(body).hexdigest(),
    })
    private_parent.rename(retained_parent)
    private_parent.mkdir()
    retained_folder.rename(current_folder)
    sentinel = current_folder / 'unrelated.txt'
    sentinel.write_text('preserve', encoding='utf-8')
    try:
        with pytest.raises(ExportCleanupPending):
            export.close()
        assert sentinel.read_text(encoding='utf-8') == 'preserve'
    finally:
        sentinel.unlink(missing_ok=True)
        if current_folder.exists():
            current_folder.rename(retained_folder)
        private_parent.rmdir()
        retained_parent.rename(private_parent)
        if export.folder is not None:
            export.close()


def test_abandoned_replaced_download_cannot_finalize_replacement(tmp_path):
    original_name = None

    def abandon():
        nonlocal original_name
        export = PreparedDownload()
        folder = tempfile.TemporaryDirectory(dir=tmp_path)
        original_name = Path(folder.name)
        path = original_name / 'export.json'
        body = b'published'
        path.write_bytes(body)
        export._publish(folder, path, {
            'bytes': len(body), 'sha256': hashlib.sha256(body).hexdigest(),
        })
        assert original_name.resolve().parent == tmp_path.resolve()
        original_name.rename(tmp_path / 'retained-original')
        original_name.mkdir()
        (original_name / 'unrelated.txt').write_text('preserve', encoding='utf-8')
        with pytest.raises(ExportCleanupPending):
            export.close()
        return weakref.ref(folder)

    abandoned = abandon()
    gc.collect()
    assert abandoned() is None
    assert (original_name / 'unrelated.txt').read_text(encoding='utf-8') == 'preserve'


def test_replaced_retired_directory_is_preserved_on_retry(tmp_path, monkeypatch):
    export = PreparedDownload()
    old = tempfile.TemporaryDirectory(dir=tmp_path)
    old_name = Path(old.name)
    old_body = b'first'
    old_path = old_name / 'export.json'
    old_path.write_bytes(old_body)
    export._publish(old, old_path, {
        'bytes': len(old_body), 'sha256': hashlib.sha256(old_body).hexdigest(),
    })
    old_cleanup = old.cleanup
    monkeypatch.setattr(
        old, 'cleanup',
        lambda: (_ for _ in ()).throw(PermissionError('held old directory')),
    )
    new = tempfile.TemporaryDirectory(dir=tmp_path)
    new_body = b'second'
    new_path = Path(new.name) / 'export.json'
    new_path.write_bytes(new_body)
    export._publish(new, new_path, {
        'bytes': len(new_body), 'sha256': hashlib.sha256(new_body).hexdigest(),
    })
    assert export._retired is old
    retained = tmp_path / 'retained-old'
    assert old_name.resolve().parent == tmp_path.resolve()
    old_name.rename(retained)
    old_name.mkdir()
    sentinel = old_name / 'unrelated.txt'
    sentinel.write_text('preserve', encoding='utf-8')
    calls = []
    monkeypatch.setattr(old, 'cleanup', lambda: calls.append('cleanup'))
    try:
        with pytest.raises(ExportCleanupPending):
            export._ensure_cleanup()
        assert calls == []
        assert sentinel.read_text(encoding='utf-8') == 'preserve'
        assert export._retired is old
    finally:
        monkeypatch.setattr(old, 'cleanup', old_cleanup)
        sentinel.unlink(missing_ok=True)
        old_name.rmdir()
        retained.rename(old_name)
        export._ensure_cleanup()
        export.close()
        old_cleanup()


def test_replaced_staged_directory_is_preserved_after_source_rejection(
        tmp_path, monkeypatch):
    export = PreparedDownload()
    folder = tempfile.TemporaryDirectory(dir=tmp_path)
    original_name = Path(folder.name)
    path = original_name / 'export.json'
    body = b'staged'
    path.write_bytes(body)
    receipt = {'bytes': len(body), 'sha256': hashlib.sha256(body).hexdigest()}
    retained = tmp_path / 'retained-staged'
    sentinel = original_name / 'unrelated.txt'
    cleanup = folder.cleanup
    calls = []
    monkeypatch.setattr(folder, 'cleanup', lambda: calls.append('cleanup'))

    def replace_before_publication():
        assert original_name.resolve().parent == tmp_path.resolve()
        original_name.rename(retained)
        original_name.mkdir()
        sentinel.write_text('preserve', encoding='utf-8')
        raise ContractError('source changed')

    try:
        with pytest.raises(ContractError, match='prepared download changed'):
            export._publish(
                folder, path, receipt, validate_source=replace_before_publication,
            )
        assert calls == []
        assert sentinel.read_text(encoding='utf-8') == 'preserve'
        assert export._retired is folder
    finally:
        monkeypatch.setattr(folder, 'cleanup', cleanup)
        sentinel.unlink(missing_ok=True)
        original_name.rmdir()
        retained.rename(original_name)
        export._ensure_cleanup()
        cleanup()


def test_staged_download_preserves_copy_after_ancestor_changes(tmp_path):
    private_parent = tmp_path / 'private-parent'
    private_parent.mkdir()
    retained_parent = tmp_path / 'retained-parent'
    export = PreparedDownload()
    folder = tempfile.TemporaryDirectory(dir=private_parent)
    name = Path(folder.name).name
    current_folder = private_parent / name
    retained_folder = retained_parent / name
    path = current_folder / 'export.json'
    body = b'staged'
    path.write_bytes(body)
    receipt = {'bytes': len(body), 'sha256': hashlib.sha256(body).hexdigest()}
    sentinel = current_folder / 'unrelated.txt'

    def replace_before_publication():
        private_parent.rename(retained_parent)
        private_parent.mkdir()
        retained_folder.rename(current_folder)
        sentinel.write_text('preserve', encoding='utf-8')
        raise ContractError('source changed')

    try:
        with pytest.raises(ContractError, match='prepared download changed'):
            export._publish(
                folder, path, receipt, validate_source=replace_before_publication,
            )
        assert sentinel.read_text(encoding='utf-8') == 'preserve'
        assert export._retired is folder
    finally:
        sentinel.unlink(missing_ok=True)
        if current_folder.exists():
            current_folder.rename(retained_folder)
        private_parent.rmdir()
        retained_parent.rename(private_parent)
        export._ensure_cleanup()
        folder.cleanup()


def test_guarded_temporary_directory_detects_changed_ancestor(tmp_path):
    private_parent = tmp_path / 'private-parent'
    private_parent.mkdir()
    retained_parent = tmp_path / 'retained-parent'
    folder = tempfile.TemporaryDirectory(dir=private_parent)
    name = Path(folder.name).name
    current_folder = private_parent / name
    retained_folder = retained_parent / name
    try:
        with guarded_temporary_directory_with_check(
            folder, label='test temporary directory'
        ) as (_root, check):
            private_parent.rename(retained_parent)
            private_parent.mkdir()
            retained_folder.rename(current_folder)
            try:
                with pytest.raises(ContractError, match='changed before cleanup'):
                    check()
            finally:
                current_folder.rename(retained_folder)
                private_parent.rmdir()
                retained_parent.rename(private_parent)
    finally:
        folder.cleanup()


def test_interrupted_final_source_validation_discards_staged_artifact(tmp_path):
    export=PreparedDownload()
    folder=tempfile.TemporaryDirectory(dir=tmp_path)
    path=Path(folder.name)/'export.json'
    body=b'staged'
    path.write_bytes(body)
    receipt={'bytes':len(body),'sha256':hashlib.sha256(body).hexdigest()}
    def interrupt():raise KeyboardInterrupt()
    try:
        with pytest.raises(KeyboardInterrupt):
            export._publish(folder,path,receipt,validate_source=interrupt)
        assert not Path(folder.name).exists()
        assert export.path is None and export.receipt is None
    finally:
        export.close()
        folder.cleanup()


def test_source_validation_cannot_publish_changed_download(tmp_path):
    export = PreparedDownload()
    folder = tempfile.TemporaryDirectory(dir=tmp_path)
    path = Path(folder.name) / 'export.json'
    body = b'published'
    path.write_bytes(body)
    receipt = {'bytes': len(body), 'sha256': hashlib.sha256(body).hexdigest()}

    def change_staged_download():
        path.write_bytes(b'corrupted')

    try:
        with pytest.raises(ContractError, match='prepared download changed before publication'):
            export._publish(folder, path, receipt, validate_source=change_staged_download)
        assert not Path(folder.name).exists()
        assert export.path is None and export.receipt is None
    finally:
        export.close()
        folder.cleanup()


def test_source_validation_cannot_change_retained_receipt(tmp_path):
    export = PreparedDownload()
    folder = tempfile.TemporaryDirectory(dir=tmp_path)
    path = Path(folder.name) / 'export.json'
    body = b'published'
    path.write_bytes(body)
    expected_digest = hashlib.sha256(body).hexdigest()
    receipt = {'bytes': len(body), 'sha256': expected_digest,
               'summary': {'membership_events': 1}}

    def change_caller_receipt():
        receipt['sha256'] = '0' * 64
        receipt['summary']['membership_events'] = 2

    try:
        returned = export._publish(folder, path, receipt,
                                   validate_source=change_caller_receipt)
        assert returned['sha256'] == expected_digest
        assert returned['summary']['membership_events'] == 1
        assert export.receipt == returned
        assert verified(export) == body
    finally:
        export.close()


@pytest.mark.skipif(os.name != 'nt', reason='Windows directory junction boundary')
def test_publication_rejects_export_path_through_junction_directory(tmp_path):
    target=tmp_path/'unrelated'
    target.mkdir()
    body=b'outside private export directory'
    (target/'export.json').write_bytes(body)
    junction=tmp_path/'private-export'
    created=subprocess.run(['cmd','/c','mklink','/J',str(junction),str(target)],
                           capture_output=True,check=False)
    if created.returncode:
        pytest.skip('host could not create an unprivileged directory junction')

    class SwappedFolder:
        name=str(junction)
        def cleanup(self):
            if junction.exists():junction.rmdir()

    export=PreparedDownload()
    path=junction/'export.json'
    receipt={'bytes':len(body),'sha256':hashlib.sha256(body).hexdigest()}
    try:
        with pytest.raises(ContractError,match='prepared download changed'):
            export._publish(SwappedFolder(),path,receipt)
        assert export.path is None
        assert (target/'export.json').read_bytes()==body
    finally:
        with pytest.raises(ExportCleanupPending):
            export.close()
        if junction.exists():junction.rmdir()


@pytest.mark.parametrize('prepared',['comparison'],indirect=True)
def test_comparison_returned_receipt_cannot_mutate_retained_report(prepared):
    export,prepare,_=prepared
    returned=prepare()
    saved=verified(export)
    original=export.receipt['summary']['membership_events']
    returned['summary']['membership_events']=original+1
    assert export.receipt['summary']['membership_events']==original
    assert verified(export)==saved


def test_changed_staged_bytes_cannot_publish_or_retire_previous_download(prepared,monkeypatch):
    export,prepare,_=prepared
    prepare()
    previous_path=export.path
    previous_body=verified(export)
    publish=export._publish
    staged=[]

    def change_before_publication(folder,path,receipt,**kwargs):
        body=path.read_bytes()
        path.write_bytes(bytes([body[0] ^ 1])+body[1:])
        staged.append(path)
        return publish(folder,path,receipt,**kwargs)

    monkeypatch.setattr(export,'_publish',change_before_publication)
    with pytest.raises(ContractError,match='prepared download changed'):
        prepare()
    assert export.path==previous_path
    assert verified(export)==previous_body
    assert staged and not staged[0].exists()


@pytest.mark.parametrize('failure',[PermissionError,RecursionError])
def test_partial_old_cleanup_never_invalidates_published_download_and_retry_is_bounded(prepared,monkeypatch,failure):
    export,prepare,calls=prepared
    prepare();old=export.folder;old_path=export.path;cleanup=old.cleanup
    def held():
        old_path.unlink(missing_ok=True)
        raise failure('owned test lock')
    monkeypatch.setattr(old,'cleanup',held)
    try:
        second=prepare();body=verified(export)
        assert export.folder is not old and not old_path.exists()
        assert export._retired is old
        attempts=len(calls);active=export.folder
        for _ in range(3):
            with pytest.raises(ExportCleanupPending):prepare()
            assert len(calls)==attempts and export.folder is active and export._retired is old
            assert export.receipt==second and verified(export)==body
        monkeypatch.setattr(old,'cleanup',cleanup)
        prepare();verified(export)
        assert export._retired is None and not Path(old.name).exists()
    finally:monkeypatch.setattr(old,'cleanup',cleanup)


def test_failed_preparation_cleanup_keeps_current_download_and_original_error(prepared,monkeypatch):
    export,prepare,_=prepared
    prepare();body=verified(export);path=export.path
    folder=tempfile.TemporaryDirectory(prefix='browser-core-aborted-test-')
    partial=Path(folder.name)/'partial';partial.write_bytes(b'owned incomplete output')
    ancestry=directory_ancestry_binding(Path(folder.name),label='aborted test directory')
    authority=(Path(folder.name),ancestry[-1],ancestry)
    cleanup=folder.cleanup
    def held():raise PermissionError('owned test lock')
    monkeypatch.setattr(folder,'cleanup',held)
    try:
        with pytest.raises(ContractError,match='original preparation error'):
            try:raise ContractError('original preparation error')
            except BaseException:export._discard(folder,authority=authority);raise
        assert export.path==path and verified(export)==body and export._retired is folder
        with pytest.raises(ExportCleanupPending):prepare()
        assert partial.exists()
    finally:
        monkeypatch.setattr(folder,'cleanup',cleanup)
        export._ensure_cleanup()


def test_unbound_retired_directory_is_preserved_after_ancestor_change(tmp_path):
    private_parent = tmp_path / 'private-parent'
    private_parent.mkdir()
    retained_parent = tmp_path / 'retained-parent'
    folder = tempfile.TemporaryDirectory(dir=private_parent)
    name = Path(folder.name).name
    current_folder = private_parent / name
    retained_folder = retained_parent / name
    sentinel = current_folder / 'unrelated.txt'
    export = PreparedDownload()
    private_parent.rename(retained_parent)
    private_parent.mkdir()
    retained_folder.rename(current_folder)
    sentinel.write_text('preserve', encoding='utf-8')
    try:
        export._discard(folder)
        assert sentinel.read_text(encoding='utf-8') == 'preserve'
        assert export._retired is folder
        with pytest.raises(ExportCleanupPending):
            export.close()
    finally:
        sentinel.unlink(missing_ok=True)
        if current_folder.exists():
            current_folder.rename(retained_folder)
        private_parent.rmdir()
        retained_parent.rename(private_parent)
        folder.cleanup()


def test_close_attempts_active_and_retired_cleanup_even_when_one_fails(prepared,monkeypatch):
    export,prepare,_=prepared
    prepare();old=export.folder;old_cleanup=old.cleanup
    monkeypatch.setattr(old,'cleanup',lambda:(_ for _ in ()).throw(PermissionError('held old')))
    prepare();active=export.folder;active_cleanup=active.cleanup
    monkeypatch.setattr(active,'cleanup',lambda:(_ for _ in ()).throw(PermissionError('held active')))
    monkeypatch.setattr(old,'cleanup',old_cleanup)
    try:
        with pytest.raises(ExportCleanupPending):export.close()
        assert export._retired is None and not Path(old.name).exists()
        assert export.folder is active
    finally:
        monkeypatch.setattr(active,'cleanup',active_cleanup)
        export.close()
    assert export.path is None and not Path(active.name).exists()


@contextmanager
def held_windows_directory(path):
    import ctypes
    from ctypes import wintypes
    kernel=ctypes.WinDLL('kernel32',use_last_error=True)
    kernel.CreateFileW.argtypes=[wintypes.LPCWSTR,wintypes.DWORD,wintypes.DWORD,ctypes.c_void_p,
                                wintypes.DWORD,wintypes.DWORD,wintypes.HANDLE]
    kernel.CreateFileW.restype=wintypes.HANDLE
    kernel.CloseHandle.argtypes=[wintypes.HANDLE]
    kernel.CloseHandle.restype=wintypes.BOOL
    handle=kernel.CreateFileW(str(path),1,3,None,3,0x02000000,None)
    if handle==wintypes.HANDLE(-1).value:raise ctypes.WinError(ctypes.get_last_error())
    try:yield
    finally:kernel.CloseHandle(handle)


@pytest.mark.skipif(os.name!='nt',reason='Windows directory sharing semantics')
def test_actual_windows_directory_lock_preserves_replacement_and_recovers(prepared):
    export,prepare,calls=prepared
    prepare();old_path=export.path
    with held_windows_directory(old_path.parent):
        prepare();body=verified(export)
        assert not old_path.exists() and export._retired is not None
        attempts=len(calls)
        with pytest.raises(ExportCleanupPending):prepare()
        assert len(calls)==attempts and verified(export)==body
    prepare();verified(export)
    assert export._retired is None and not old_path.parent.exists()
