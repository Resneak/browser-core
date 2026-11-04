from __future__ import annotations
import difflib
import hashlib
import os
import subprocess
from types import SimpleNamespace

import pytest

from browser_core.contracts import ContractError
from browser_core.dependency_patches import apply_dependency_series, dependency_scopes
import browser_core.upstream as up


def git(root, *args):
    result = subprocess.run(['git', '-c', 'user.name=Browser Core test', '-c',
        'user.email=browser-core@example.invalid', '-C', str(root), *args],
        check=True, capture_output=True)
    return result.stdout.decode('utf-8').strip()


@pytest.fixture
def population(tmp_path, monkeypatch):
    checkout=tmp_path/'checkout'; checkout.mkdir()
    dependency=checkout/'deps'/'decoder'; dependency.mkdir(parents=True)
    for folder,name in ((checkout,'a.txt'),(dependency,'b.txt')):
        git(folder,'init','-q')
        git(folder,'config','core.autocrlf','false')
        (folder/name).write_bytes(b'before\n')
        git(folder,'add',name);git(folder,'commit','-qm','fixture')
    revision=git(dependency,'rev-parse','HEAD')
    git(checkout,'update-index','--add','--cacheinfo',f'160000,{revision},deps/decoder')
    git(checkout,'commit','-qm','pin dependency')
    manifest={'chromium_revision':git(checkout,'rev-parse','HEAD'),
        'dependencies':[{'path':'deps/decoder','revision':revision}],
        'patches':[{'file':'root.patch'},{'file':'dep.patch','checkout':'deps/decoder'}],
        'postimages':[]}
    bodies=[]
    for name,scope,file in [('root.patch','', 'a.txt'),('dep.patch','deps/decoder','b.txt')]:
        body=f'diff --git a/{file} b/{file}\n'+''.join(difflib.unified_diff(
            ['before\n'],['after\n'],fromfile='a/'+file,tofile='b/'+file))
        bodies.append((name,body.encode()))
        manifest['postimages'].append({'path':scope+'/'+file if scope else file,
            'sha256':hashlib.sha256(b'after\n').hexdigest()})
    bundle=SimpleNamespace(series=manifest,patch_bodies=bodies,report={'patches':2})
    monkeypatch.setattr(up,'_verified_patch_bundle',lambda root:bundle)
    return checkout,dependency,bundle


def test_applies_pinned_root_and_dependency_then_verifies_exact_population(population):
    checkout,dep,bundle=population
    assert up.apply_patch_series(checkout,checkout,True)=={'applied':0,'already_applied':0,'checked':2}
    assert (checkout/'a.txt').read_text()=='before\n'
    assert up.apply_patch_series(checkout,checkout,False)['applied']==2
    assert up.apply_patch_series(checkout,checkout,False)=={'applied':0,'already_applied':2,'checked':2}
    result=up.verify_patched_checkout(checkout,checkout)
    assert result['patches']==2 and len(result['patched_sources_sha256'])==64


@pytest.mark.skipif(os.name != 'nt', reason='Windows directory junction boundary')
def test_dependency_patch_preflight_rejects_nested_junction_before_any_write(
    population, tmp_path,
):
    checkout, dep, bundle = population
    foreign = tmp_path / 'foreign'
    foreign.mkdir()
    target = foreign / 'target.txt'
    target.write_bytes(b'before\n')
    linked_parent = dep / 'nested'
    linked = subprocess.run(
        ['cmd', '/c', 'mklink', '/J', str(linked_parent), str(foreign)],
        capture_output=True,
    )
    if linked.returncode:
        pytest.skip('host could not create an unprivileged directory junction')
    bundle.patch_bodies[1] = ('dep.patch', (
        b'diff --git a/nested/target.txt b/nested/target.txt\n'
        b'--- a/nested/target.txt\n'
        b'+++ b/nested/target.txt\n'
        b'@@ -1 +1 @@\n'
        b'-before\n'
        b'+after\n'
    ))
    bundle.series['postimages'][1]['path'] = 'deps/decoder/nested/target.txt'
    try:
        with pytest.raises(ContractError, match='patch target'):
            up.apply_patch_series(checkout, checkout, False)
        assert (checkout / 'a.txt').read_bytes() == b'before\n'
        assert target.read_bytes() == b'before\n'
    finally:
        linked_parent.rmdir()


def test_dependency_preflight_failure_does_not_change_root(population):
    checkout,dep,bundle=population
    (dep/'b.txt').write_text('unrelated\n',encoding='utf-8')
    with pytest.raises(ContractError,match='apply cleanly'):
        apply_dependency_series(checkout,bundle,check_only=False)
    assert (checkout/'a.txt').read_text()=='before\n'


@pytest.mark.parametrize('check_only', [False, True])
def test_dependency_preflight_rejects_relocation_during_pin_check(population, monkeypatch, check_only):
    checkout, dep, bundle = population
    original = up._run_git_capture
    relocated = False

    def git_then_relocate(target, arguments, *, maximum):
        nonlocal relocated
        result = original(target, arguments, maximum=maximum)
        if target == dep and arguments == ['rev-parse', 'HEAD'] and not relocated:
            parent = checkout / 'deps'
            retained = checkout / 'retained-deps'
            parent.rename(retained)
            parent.mkdir()
            (retained / 'decoder').rename(dep)
            relocated = True
        return result

    monkeypatch.setattr(up, '_run_git_capture', git_then_relocate)
    with pytest.raises(ContractError, match='patch dependency checkout authority changed'):
        apply_dependency_series(checkout, bundle, check_only=check_only)
    assert relocated
    assert (checkout / 'a.txt').read_bytes() == b'before\n'
    assert (dep / 'b.txt').read_bytes() == b'before\n'


def test_exact_verification_rejects_relocated_dependency_ancestor(population, monkeypatch):
    checkout, dep, _bundle = population
    up.apply_patch_series(checkout, checkout, False)
    original = up._stable_file_sha256
    relocated = False

    def hash_then_relocate(*args, **kwargs):
        nonlocal relocated
        digest = original(*args, **kwargs)
        if not relocated:
            parent = checkout / 'deps'
            retained = checkout / 'retained-deps'
            parent.rename(retained)
            parent.mkdir()
            (retained / 'decoder').rename(dep)
            relocated = True
        return digest

    monkeypatch.setattr(up, '_stable_file_sha256', hash_then_relocate)
    with pytest.raises(ContractError, match='patched checkout authority changed'):
        up.verify_patched_checkout(checkout, checkout)
    assert relocated
    assert (checkout / 'a.txt').read_bytes() == b'after\n'
    assert (dep / 'b.txt').read_bytes() == b'after\n'


@pytest.mark.parametrize('check_only',[False,True])
@pytest.mark.parametrize('relocation_step',['root','dependency'])
def test_dependency_preflight_rejects_relocated_scope_before_any_patch(population,monkeypatch,check_only,relocation_step):
    checkout,dep,bundle=population
    original=up._classify_patch_population
    moved=False

    def classify_then_relocate(target,bodies):
        nonlocal moved
        result=original(target,bodies)
        selected=checkout if relocation_step=='root' else dep
        if target==selected and not moved:
            parent=checkout/'deps'
            retained=checkout/'retained-deps'
            parent.rename(retained)
            parent.mkdir()
            (retained/'decoder').rename(parent/'decoder')
            moved=True
        return result

    monkeypatch.setattr(up,'_classify_patch_population',classify_then_relocate)
    with pytest.raises(ContractError,match='dependency checkout authority changed'):
        apply_dependency_series(checkout,bundle,check_only=check_only)
    assert moved
    assert (checkout/'a.txt').read_bytes()==b'before\n'
    assert (dep/'b.txt').read_bytes()==b'before\n'


@pytest.mark.parametrize('scope',['root','dependency'])
def test_exact_verification_rejects_extra_tracked_source_changes(population,scope):
    checkout,dep,bundle=population
    up.apply_patch_series(checkout,checkout,False)
    folder=dep if scope=='dependency' else checkout
    (folder/'extra.txt').write_text('unexpected\n',encoding='utf-8')
    git(folder,'add','-N','extra.txt')
    with pytest.raises(ContractError,match='delta'):
        up.verify_patched_checkout(checkout,checkout)


def test_dependency_wrong_head_is_rejected_even_when_postimage_matches(population):
    checkout,dep,bundle=population
    up.apply_patch_series(checkout,checkout,False)
    git(dep,'add','b.txt');git(dep,'commit','-qm','unexpected revision')
    with pytest.raises(ContractError,match='differs from its pin'):
        up.verify_patched_checkout(checkout,checkout)


def test_manifest_cannot_repin_dependency_independently_of_chromium(population):
    checkout,dep,bundle=population
    bundle.series['dependencies'][0]['revision']='a'*40
    with pytest.raises(ContractError,match='Chromium Git pin'):
        apply_dependency_series(checkout,bundle,check_only=True)


def test_git_ignore_submodules_config_does_not_hide_declared_dependency(population):
    checkout,dep,bundle=population
    git(checkout,'config','diff.ignoreSubmodules','all')
    up.apply_patch_series(checkout,checkout,False)
    assert up.verify_patched_checkout(checkout,checkout)['patches']==2
    (dep/'unexpected.txt').write_bytes(b'unknown\n')
    git(dep,'add','-N','unexpected.txt')
    with pytest.raises(ContractError,match='delta'):
        up.verify_patched_checkout(checkout,checkout)


def test_dependency_verification_does_not_run_repository_clean_filter(population, tmp_path):
    checkout, dep, _bundle = population
    up.apply_patch_series(checkout, checkout, False)
    (dep / '.git' / 'info' / 'attributes').write_text('b.txt filter=observed\n', encoding='ascii')
    marker = tmp_path / 'dependency-filter-called.txt'
    git(dep, 'config', 'filter.observed.clean',
        f"sh -c 'echo invoked >> \"{marker.as_posix()}\"; cat'")

    assert up.verify_patched_checkout(checkout, checkout)['patches'] == 2
    assert not marker.exists()


def test_dependency_git_newline_conversion_preserves_exact_declared_source(population):
    checkout,dep,bundle=population
    git(dep,'config','core.autocrlf','true')
    up.apply_patch_series(checkout,checkout,False)
    assert (dep/'b.txt').read_bytes()==b'after\n'
    assert up.verify_patched_checkout(checkout,checkout)['patches']==2


def test_dependency_rejects_relinked_postimage_before_normalization(population, tmp_path, monkeypatch):
    checkout, dep, bundle = population
    foreign = tmp_path / 'foreign.txt'
    foreign.write_bytes(b'foreign payload\n')
    original_apply = up._apply_pending_population

    def apply_with_crlf(target, bodies):
        original_apply(target, bodies)
        if target == dep:
            (dep / 'b.txt').write_bytes(b'after\r\n')

    monkeypatch.setattr(up, '_apply_pending_population', apply_with_crlf)
    original_hash = up._stable_file_sha256
    relinked = False

    def hash_then_relink(target, *, label, maximum):
        nonlocal relinked
        digest = original_hash(target, label=label, maximum=maximum)
        if target == dep / 'b.txt' and label == 'dependency postimage' and not relinked:
            assert target.read_bytes() == b'after\r\n'
            target.unlink()
            os.link(foreign, target)
            relinked = True
        return digest

    monkeypatch.setattr(up, '_stable_file_sha256', hash_then_relink)
    with pytest.raises(ContractError, match='patch target is not an ordinary file'):
        apply_dependency_series(checkout, bundle, check_only=False)
    assert relinked
    assert foreign.read_bytes() == b'foreign payload\n'


def test_dependency_postimage_mismatch_is_rejected(population):
    checkout,dep,bundle=population
    up.apply_patch_series(checkout,checkout,False)
    bundle.series['postimages'][1]['sha256']='f'*64
    with pytest.raises(ContractError,match='postimage hash'):
        up.verify_patched_checkout(checkout,checkout)


@pytest.mark.parametrize('mutation',[
    lambda s:s['patches'][1].update(checkout=[]),
    lambda s:s['patches'][1].update(checkout='elsewhere/decoder'),
    lambda s:s['dependencies'][0].update(path='../decoder'),
    lambda s:s['dependencies'][0].update(path='deps/.git'),
    lambda s:s['dependencies'][0].update(revision='a'*39),
    lambda s:s.update(dependencies=[]),
    lambda s:s['dependencies'].append({'path':'DEPS/DECODER','revision':'a'*40}),
    lambda s:s['dependencies'].append({'path':'deps/decoder/nested','revision':'a'*40}),
])
def test_manifest_rejects_unbound_or_overlapping_patch_scopes(population,mutation):
    _,_,bundle=population;mutation(bundle.series)
    with pytest.raises(ContractError):dependency_scopes(bundle.series)


def test_manifest_accepts_pinned_top_level_dependency_scope() -> None:
    series = {
        "dependencies": [{"path": "v8", "revision": "a" * 40}],
        "patches": [{"file": "v8.patch", "checkout": "v8"}],
        "postimages": [{"path": "v8/src/compiler.cc", "sha256": "b" * 64}],
    }

    assert dependency_scopes(series) == {"v8": "a" * 40}
