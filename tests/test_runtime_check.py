import json
import os
import subprocess
from pathlib import Path

import pytest

import browser_core.runtime_check as runtime_check
from browser_core.contracts import ContractError
from test_build import _write_fixture_attestation

ROOT=Path(__file__).resolve().parents[1]


def test_runtime_check_uses_full_attestation_without_starting_browser(tmp_path):
    executable,_,document=_write_fixture_attestation(tmp_path)
    before={p.name:p.read_bytes() for p in tmp_path.iterdir()}
    result=runtime_check.check_runtime(ROOT,executable)
    assert result['status']=='verified' and result['runtime_verified']
    assert result['runtime']['runtime_bundle_sha256']==document['runtime_bundle_sha256']
    assert result['runtime']['artifacts']==3
    assert result['browser_started'] is False and result['workspace_checked'] is False
    assert {p.name:p.read_bytes() for p in tmp_path.iterdir()}==before


@pytest.mark.skipif(os.name != 'nt', reason='Windows directory junction boundary')
def test_runtime_check_rejects_selected_runtime_junction(tmp_path: Path) -> None:
    physical_runtime = tmp_path / 'physical-runtime'
    physical_runtime.mkdir()
    executable, receipt, _document = _write_fixture_attestation(physical_runtime)
    original_receipt = receipt.read_bytes()
    selected_runtime = tmp_path / 'selected-runtime'
    linked = subprocess.run(
        ['cmd', '/c', 'mklink', '/J', str(selected_runtime), str(physical_runtime)],
        capture_output=True,
    )
    if linked.returncode:
        pytest.skip('host could not create an unprivileged directory junction')
    try:
        result = runtime_check.check_runtime(ROOT, selected_runtime / executable.name)
        assert result['code'] == 'unverified'
        assert result['runtime_verified'] is False
        assert receipt.read_bytes() == original_receipt
    finally:
        selected_runtime.rmdir()


@pytest.mark.parametrize('relocation_stage', ['patch-series', 'attestation'])
def test_runtime_check_rejects_relocated_package_ancestor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    relocation_stage: str,
) -> None:
    package_outer = tmp_path / 'package-outer'
    package = package_outer / 'package'
    package.mkdir(parents=True)
    (package / 'upstream.json').write_bytes((ROOT / 'upstream.json').read_bytes())
    runtime = tmp_path / 'runtime'
    runtime.mkdir()
    executable, _path, document = _write_fixture_attestation(runtime)
    manifest = json.loads((ROOT / 'upstream.json').read_text(encoding='utf-8'))
    relocated = False

    def relocate_package() -> None:
        nonlocal relocated
        if relocated:
            return
        retained = tmp_path / 'retained-package-outer'
        package_outer.rename(retained)
        package_outer.mkdir()
        (retained / 'package').rename(package)
        relocated = True

    def patches_then_maybe_relocate(_root: Path) -> dict:
        if relocation_stage == 'patch-series':
            relocate_package()
        return {'patches': [], 'patch_series_sha256': document['patch_series_sha256']}

    def attestation_then_maybe_relocate(_root: Path, _executable: Path) -> dict:
        if relocation_stage == 'attestation':
            relocate_package()
        return document

    monkeypatch.setattr(runtime_check, 'verify_upstream', lambda _root: manifest)
    monkeypatch.setattr(runtime_check, 'verify_patch_series', patches_then_maybe_relocate)
    monkeypatch.setattr(runtime_check, 'load_build_attestation', attestation_then_maybe_relocate)
    result = runtime_check.check_runtime(package, executable)
    assert result['code'] == 'resources-unavailable'
    assert result['runtime_verified'] is False
    assert relocated


@pytest.mark.parametrize('rewrite_stage', ['patch-series', 'attestation'])
@pytest.mark.parametrize('same_meaning', [False, True])
def test_runtime_check_rejects_manifest_rewrite_during_verification(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    rewrite_stage: str,
    same_meaning: bool,
) -> None:
    package = tmp_path / 'package'
    package.mkdir()
    manifest_path = package / 'upstream.json'
    original = (ROOT / 'upstream.json').read_bytes()
    manifest_path.write_bytes(original)
    if same_meaning:
        changed = original.replace(b'"captured_at": ', b'"captured_at" :', 1)
    else:
        changed = original.replace(b'"captured_at": "2026-08-02"', b'"captured_at": "2026-08-03"', 1)
    assert changed != original and len(changed) == len(original)
    assert (json.loads(changed) == json.loads(original)) is same_meaning
    runtime = tmp_path / 'runtime'
    runtime.mkdir()
    executable, _path, document = _write_fixture_attestation(runtime)

    def rewrite_manifest() -> None:
        before = manifest_path.stat()
        manifest_path.write_bytes(changed)
        os.utime(manifest_path, ns=(before.st_atime_ns, before.st_mtime_ns))

    def patches(_root: Path) -> dict:
        if rewrite_stage == 'patch-series':
            rewrite_manifest()
        return {'patches': [], 'patch_series_sha256': document['patch_series_sha256']}

    def attestation(_root: Path, _executable: Path) -> dict:
        if rewrite_stage == 'attestation':
            rewrite_manifest()
        return document

    monkeypatch.setattr(runtime_check, 'verify_patch_series', patches)
    monkeypatch.setattr(runtime_check, 'load_build_attestation', attestation)
    result = runtime_check.check_runtime(package, executable)
    assert result['code'] == 'resources-unavailable'
    assert result['package'] is None and result['runtime'] is None
    assert result['runtime_verified'] is False


def test_runtime_check_rejects_patch_series_change_during_attestation_load(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    executable, _path, document = _write_fixture_attestation(tmp_path)
    original_verify = runtime_check.verify_patch_series
    initial_patches = original_verify(ROOT)
    changed = False

    def verify_patches(_root: Path) -> dict:
        if changed:
            return {**initial_patches, 'patch_series_sha256': 'f' * 64}
        return initial_patches

    def load_then_change(_root: Path, _executable: Path) -> dict:
        nonlocal changed
        changed = True
        return document

    monkeypatch.setattr(runtime_check, 'verify_patch_series', verify_patches)
    monkeypatch.setattr(runtime_check, 'load_build_attestation', load_then_change)
    result = runtime_check.check_runtime(ROOT, executable)
    assert changed
    assert result['code'] == 'resources-unavailable'
    assert result['runtime_verified'] is False
    assert result['package'] is None and result['runtime'] is None


def test_changed_file_is_rechecked_after_a_successful_setup_check(tmp_path):
    executable,_,_=_write_fixture_attestation(tmp_path)
    assert runtime_check.check_runtime(ROOT,executable)['runtime_verified']
    (tmp_path/'chrome.dll').write_bytes(b'changed local fixture')
    result=runtime_check.check_runtime(ROOT,executable)
    assert result['code']=='artifact-mismatch' and not result['runtime_verified']
    assert result['runtime'] is None
    assert '--allow-unverified' not in result['message']


def test_mismatched_package_is_distinguished_from_missing_browser(tmp_path):
    executable,attestation,document=_write_fixture_attestation(tmp_path)
    document['patch_series_sha256']='0'*64
    attestation.write_text(json.dumps(document),encoding='utf-8')
    mismatch=runtime_check.check_runtime(ROOT,executable)
    assert mismatch['code']=='package-mismatch' and not mismatch['runtime_verified']
    attestation.unlink()
    assert runtime_check.check_runtime(ROOT,executable)['code']=='missing-file'


def test_missing_runtime_component_is_not_reported_as_verified(tmp_path):
    executable,_,_=_write_fixture_attestation(tmp_path)
    (tmp_path/'trace_processor_shell.exe').unlink()
    result=runtime_check.check_runtime(ROOT,executable)
    assert result['code']=='missing-file' and not result['runtime_verified']


@pytest.mark.parametrize('selection',[Path('chrome.exe'),Path('other.exe'),None,'chrome.exe'])
def test_invalid_selection_does_not_read_runtime_or_resources(monkeypatch,selection):
    def forbidden(*args):raise AssertionError('invalid input reached verifier')
    monkeypatch.setattr(runtime_check,'verify_upstream',forbidden)
    assert runtime_check.check_runtime(ROOT,selection)['code']=='invalid-selection'


@pytest.mark.parametrize('invalid_part', ['package', 'executable'])
def test_embedded_nul_path_is_an_invalid_selection(invalid_part):
    package = ROOT if invalid_part == 'executable' else ROOT / ('bad' + chr(0))
    executable = (
        ROOT / 'chrome.exe' if invalid_part == 'package'
        else ROOT / ('bad' + chr(0)) / 'chrome.exe'
    )
    result = runtime_check.check_runtime(package, executable)
    assert result['code'] == 'invalid-selection'
    assert result['runtime_verified'] is False


def test_unreadable_resources_get_actionable_error_without_exception_text(tmp_path,monkeypatch):
    def fail(*args):raise PermissionError('private location marker')
    monkeypatch.setattr(runtime_check,'verify_upstream',fail)
    result=runtime_check.check_runtime(ROOT,tmp_path/'chrome.exe')
    assert result['code']=='resources-unavailable'
    assert 'private location marker' not in json.dumps(result)


@pytest.mark.parametrize('error,code',[
    (PermissionError('private location marker'),'access-unavailable'),
    (ContractError('build attestation is locked'),'access-unavailable'),
    (ContractError('runtime artifact chrome.dll read failed'),'access-unavailable'),
    (ContractError('runtime artifact chrome.dll read failed (os_error=32)'),'access-unavailable'),
    (ContractError('upstream manifest changed during verification'),'resources-unavailable'),
    (ContractError('unknown private location marker'),'unverified'),
    (RuntimeError('private symlink resolution marker'),'unverified'),
])
def test_runtime_errors_stay_bounded_and_do_not_disclose_paths(tmp_path,monkeypatch,error,code):
    def fail(*args):raise error
    monkeypatch.setattr(runtime_check,'load_build_attestation',fail)
    result=runtime_check.check_runtime(ROOT,tmp_path/'chrome.exe')
    assert result['code']==code and not result['runtime_verified']
    assert 'private location marker' not in json.dumps(result)


@pytest.mark.skipif(os.name!='nt',reason='Windows file-sharing behaviour')
@pytest.mark.parametrize('name',['browser-core-build.json','chrome.dll'])
def test_real_windows_read_lock_is_reported_and_recovers_when_released(tmp_path,name):
    import ctypes
    from ctypes import wintypes
    executable,_,_=_write_fixture_attestation(tmp_path)
    kernel=ctypes.WinDLL('kernel32',use_last_error=True)
    kernel.CreateFileW.argtypes=[wintypes.LPCWSTR,wintypes.DWORD,wintypes.DWORD,
        wintypes.LPVOID,wintypes.DWORD,wintypes.DWORD,wintypes.HANDLE]
    kernel.CreateFileW.restype=wintypes.HANDLE
    kernel.CloseHandle.argtypes=[wintypes.HANDLE]
    kernel.CloseHandle.restype=wintypes.BOOL
    handle=kernel.CreateFileW(str(tmp_path/name),0x80000000,0,None,3,0,None)
    assert handle!=wintypes.HANDLE(-1).value
    try:
        result=runtime_check.check_runtime(ROOT,executable)
        assert result['code']=='access-unavailable' and not result['runtime_verified']
    finally:
        assert kernel.CloseHandle(handle)
    assert runtime_check.check_runtime(ROOT,executable)['runtime_verified']


def test_runtime_doctor_does_not_require_checkout_workspace_or_build_tools(tmp_path,monkeypatch,capsys):
    import browser_core.cli as cli
    executable,_,_=_write_fixture_attestation(tmp_path)
    def forbidden(*args):raise AssertionError('prebuilt runtime mode reached build setup')
    monkeypatch.setattr(cli,'_workspace',forbidden)
    monkeypatch.setattr(cli,'_doctor_command',forbidden)
    assert cli.main(['doctor','--executable',str(executable)])==0
    report=json.loads(capsys.readouterr().out)
    assert report['runtime_verified'] and report['browser_started'] is False
    assert cli.main(['doctor','--executable',str(tmp_path/'missing/chrome.exe')])==2
    assert json.loads(capsys.readouterr().out)['code']=='missing-file'
