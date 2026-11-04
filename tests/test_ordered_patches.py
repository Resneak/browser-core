from __future__ import annotations

import difflib
import hashlib
import os
import tempfile
from pathlib import Path
from types import SimpleNamespace

import pytest

import browser_core.upstream as up
from browser_core import ordered_patches as ordered
from browser_core.contracts import ContractError
from test_dependency_patches import git


@pytest.mark.skipif(os.name != 'nt', reason='Windows filename executable bits')
def test_ordered_patch_snapshot_accepts_stable_batch_postimage(tmp_path: Path) -> None:
    checkout = tmp_path / 'checkout'
    checkout.mkdir()
    (checkout / 'tool.bat').write_bytes(b'@echo off\r\n')
    _directories, files, _ancestry = ordered._snapshot(checkout, ['tool.bat'])
    assert files['tool.bat'].state == 'complete'
    assert files['tool.bat'].body == b'@echo off\r\n'


def patch(name, before, after):
    header = f'diff --git a/{name} b/{name}\n'
    if before is None:
        header += 'new file mode 100644\n'
    return (header + ''.join(difflib.unified_diff(
        (before or '').splitlines(keepends=True), after.splitlines(keepends=True),
        fromfile='/dev/null' if before is None else 'a/'+name, tofile='b/'+name))).encode()


@pytest.fixture
def chain(tmp_path, monkeypatch):
    checkout = tmp_path/'checkout'
    checkout.mkdir()
    git(checkout, 'init', '-q')
    git(checkout, 'config', 'core.autocrlf', 'false')
    (checkout/'a.txt').write_bytes(b'before\n')
    git(checkout, 'add', 'a.txt')
    git(checkout, 'commit', '-qm', 'baseline')
    bodies = [patch('a.txt', 'before\n', 'middle\n') + patch('added.txt', None, 'one\n'),
              patch('a.txt', 'middle\n', 'after\n') + patch('added.txt', 'one\n', 'two\n')]
    series = {'chromium_revision': git(checkout, 'rev-parse', 'HEAD'),
              'patches': [{'file': 'first.patch'}, {'file': 'second.patch'}],
              'postimages': [{'path': name, 'sha256': hashlib.sha256(body).hexdigest()}
                             for name, body in [('a.txt', b'after\n'), ('added.txt', b'two\n')]]}
    bundle = SimpleNamespace(series=series, report={'patches': 2},
        patch_bodies=list(zip(['first.patch', 'second.patch'], bodies)))
    monkeypatch.setattr(up, '_verified_patch_bundle', lambda root: bundle)
    return checkout, bodies, bundle


@pytest.mark.parametrize('installed', [0, 1, 2])
def test_overlapping_chain_preflight_apply_idempotence_and_exact_verification(chain, installed):
    checkout, bodies, _bundle = chain
    for body in bodies[:installed]:
        assert up._run_apply(checkout, [], [body]).returncode == 0
    before = {p.name: (p.read_bytes(), p.stat().st_mtime_ns)
              for p in checkout.glob('*.txt')}
    assert up.apply_patch_series(checkout, checkout, True) == {
        'applied': 0, 'already_applied': installed, 'checked': 2}
    assert before == {p.name: (p.read_bytes(), p.stat().st_mtime_ns)
                      for p in checkout.glob('*.txt')}
    assert up.apply_patch_series(checkout, checkout, False) == {
        'applied': 2-installed, 'already_applied': installed, 'checked': 2}
    assert (checkout/'a.txt').read_bytes() == b'after\n'
    assert (checkout/'added.txt').read_bytes() == b'two\n'
    assert up.apply_patch_series(checkout, checkout, False) == {
        'applied': 0, 'already_applied': 2, 'checked': 2}
    git(checkout, 'add', '-N', 'added.txt')
    before = [(p.read_bytes(), p.stat().st_mtime_ns) for p in checkout.glob('*.txt')]
    assert up.verify_patched_checkout(checkout, checkout)['patches'] == 2
    assert before == [(p.read_bytes(), p.stat().st_mtime_ns) for p in checkout.glob('*.txt')]
    (checkout/'added.txt').write_bytes(b'unrelated\n')
    with pytest.raises(ContractError, match='not fully applied|postimage'):
        up.verify_patched_checkout(checkout, checkout)


def test_publication_uses_one_real_worktree_mutation(chain, monkeypatch):
    checkout, bodies, _ = chain
    real = up._run_apply
    mutations = []
    def spy(root, arguments, patches):
        if root == checkout and '--check' not in arguments:
            mutations.append((arguments, patches))
        return real(root, arguments, patches)
    monkeypatch.setattr(up, '_run_apply', spy)
    up.apply_patch_series(checkout, checkout, False)
    assert len(mutations) == 1
    assert mutations[0][1] == bodies


@pytest.mark.parametrize('check_only', [False, True])
def test_patch_preflight_rejects_relocation_during_bundle_verification(chain, tmp_path, monkeypatch, check_only):
    checkout, _bodies, _bundle = chain
    outer = tmp_path / 'outer'
    outer.mkdir()
    checkout.rename(outer / 'checkout')
    checkout = outer / 'checkout'
    original = up._verified_patch_bundle
    relocated = False

    def bundle_then_relocate(root):
        nonlocal relocated
        bundle = original(root)
        if not relocated:
            retained = tmp_path / 'retained-outer'
            outer.rename(retained)
            outer.mkdir()
            (retained / 'checkout').rename(checkout)
            relocated = True
        return bundle

    monkeypatch.setattr(up, '_verified_patch_bundle', bundle_then_relocate)
    with pytest.raises(ContractError, match='patch checkout authority changed'):
        up.apply_patch_series(tmp_path, checkout, check_only)
    assert relocated
    assert (checkout / 'a.txt').read_bytes() == b'before\n'
    assert not (checkout / 'added.txt').exists()


def test_exact_verification_rejects_relocation_during_bundle_verification(chain, tmp_path, monkeypatch):
    checkout, _bodies, _bundle = chain
    up.apply_patch_series(checkout, checkout, False)
    git(checkout, 'add', '-N', 'added.txt')
    outer = tmp_path / 'outer'
    outer.mkdir()
    checkout.rename(outer / 'checkout')
    checkout = outer / 'checkout'
    original = up._verified_patch_bundle
    relocated = False

    def bundle_then_relocate(root):
        nonlocal relocated
        bundle = original(root)
        if not relocated:
            retained = tmp_path / 'retained-outer'
            outer.rename(retained)
            outer.mkdir()
            (retained / 'checkout').rename(checkout)
            relocated = True
        return bundle

    monkeypatch.setattr(up, '_verified_patch_bundle', bundle_then_relocate)
    with pytest.raises(ContractError, match='patched checkout authority changed'):
        up.verify_patched_checkout(tmp_path, checkout)
    assert relocated
    assert (checkout / 'a.txt').read_bytes() == b'after\n'


def test_exact_verification_rejects_relocated_checkout_ancestor(chain, tmp_path, monkeypatch):
    checkout, _bodies, _bundle = chain
    up.apply_patch_series(checkout, checkout, False)
    git(checkout, 'add', '-N', 'added.txt')
    outer = tmp_path / 'outer'
    outer.mkdir()
    checkout.rename(outer / 'checkout')
    checkout = outer / 'checkout'
    original = up._stable_file_sha256
    relocated = False

    def hash_then_relocate(*args, **kwargs):
        nonlocal relocated
        digest = original(*args, **kwargs)
        if not relocated:
            retained = tmp_path / 'retained-outer'
            outer.rename(retained)
            outer.mkdir()
            (retained / 'checkout').rename(checkout)
            relocated = True
        return digest

    monkeypatch.setattr(up, '_stable_file_sha256', hash_then_relocate)
    with pytest.raises(ContractError, match='patched checkout authority changed'):
        up.verify_patched_checkout(checkout, checkout)
    assert relocated
    assert (checkout / 'a.txt').read_bytes() == b'after\n'
    assert (checkout / 'added.txt').read_bytes() == b'two\n'


@pytest.mark.parametrize('fault', ['wrong_order', 'divergent', 'late_preflight_change'])
def test_failed_chain_preflight_does_not_publish(chain, monkeypatch, fault):
    checkout, bodies, bundle = chain
    if fault == 'wrong_order':
        bundle.patch_bodies.reverse()
        bundle.series['patches'].reverse()
    elif fault == 'divergent':
        (checkout/'a.txt').write_bytes(b'foreign\n')
    else:
        real = up._run_apply
        def mutate(root, arguments, patches):
            result = real(root, arguments, patches)
            if root != checkout:
                (checkout/'a.txt').write_bytes(b'foreign\n')
            return result
        monkeypatch.setattr(up, '_run_apply', mutate)
    with pytest.raises(ContractError, match='apply cleanly|changed during preflight'):
        if fault == 'late_preflight_change':
            ordered.classify(checkout, bodies)
        else:
            up.apply_patch_series(checkout, checkout, False)
    assert (checkout/'a.txt').read_bytes() in (b'before\n', b'foreign\n')
    assert not (checkout/'added.txt').exists()


def test_ordered_preflight_rejects_relocated_checkout_ancestor(chain, tmp_path):
    checkout, bodies, _bundle = chain
    outer = tmp_path / 'outer'
    outer.mkdir()
    checkout.rename(outer / 'checkout')
    checkout = outer / 'checkout'
    retained = tmp_path / 'retained-outer'

    with pytest.raises(ContractError, match='sources changed during preflight'):
        with ordered._copy(checkout, bodies[:1]):
            outer.rename(retained)
            outer.mkdir()
            (retained / 'checkout').rename(checkout)

    assert (checkout / 'a.txt').read_bytes() == b'before\n'


@pytest.mark.parametrize('check_only',[False,True])
def test_patch_publication_rejects_relocated_checkout_after_preflight(chain, tmp_path, monkeypatch, check_only):
    checkout, _bodies, _bundle = chain
    outer = tmp_path / 'outer'
    outer.mkdir()
    checkout.rename(outer / 'checkout')
    checkout = outer / 'checkout'
    retained = tmp_path / 'retained-outer'
    original_classify = up._classify_patch_population

    def classify_then_relocate(path, patches):
        pending = original_classify(path, patches)
        outer.rename(retained)
        outer.mkdir()
        (retained / 'checkout').rename(checkout)
        return pending

    monkeypatch.setattr(up, '_classify_patch_population', classify_then_relocate)
    with pytest.raises(ContractError, match='checkout authority changed'):
        up.apply_patch_series(checkout, checkout, check_only)
    assert (checkout / 'a.txt').read_bytes() == b'before\n'
    assert not (checkout / 'added.txt').exists()


def test_ordered_copy_rejects_hardlinks_and_bounds_total_source(chain, monkeypatch):
    checkout, bodies, _ = chain
    os.link(checkout/'a.txt', checkout/'alias.txt')
    with pytest.raises(ContractError, match='hard links'):
        ordered.classify(checkout, bodies)
    (checkout/'alias.txt').unlink()
    monkeypatch.setattr(ordered, 'MAX_COPY_BYTES', 4)
    with pytest.raises(ContractError, match='bound'):
        ordered.classify(checkout, bodies)


@pytest.mark.parametrize('name', ['../outside', 'a/../../outside', '.git/config',
                                  'a/.GiT/config', 'a./escape', 'a:stream', '/absolute'])
def test_scratch_paths_cannot_escape_or_target_git_metadata(name):
    with pytest.raises(ContractError, match='target'):
        ordered._paths([patch(name, 'before\n', 'after\n')])


def test_changed_file_headers_cannot_redirect_scratch_write():
    body = patch('a.txt', 'before\n', 'after\n').replace(b'+++ b/a.txt', b'+++ b/elsewhere')
    with pytest.raises(ContractError, match='header'):
        ordered._paths([body])


def test_overlapping_dependency_chain_uses_same_ordered_checks(tmp_path, monkeypatch):
    # Build the real pinned dependency fixture, then extend its existing delta.
    from test_dependency_patches import population
    checkout, dependency, bundle = population.__wrapped__(tmp_path, monkeypatch)
    next_body = patch('b.txt', 'after\n', 'final\n')
    bundle.patch_bodies.append(('dep-next.patch', next_body))
    bundle.series['patches'].append({'file': 'dep-next.patch', 'checkout': 'deps/decoder'})
    bundle.series['postimages'][1]['sha256'] = hashlib.sha256(b'final\n').hexdigest()
    assert up.apply_patch_series(checkout, checkout, True)['already_applied'] == 0
    assert up.apply_patch_series(checkout, checkout, False)['applied'] == 3
    assert up.apply_patch_series(checkout, checkout, False)['already_applied'] == 3
    assert up.verify_patched_checkout(checkout, checkout)['patched_sources_sha256']
    assert (dependency/'b.txt').read_bytes() == b'final\n'


def test_replaced_patch_scratch_directory_is_preserved(chain, monkeypatch, tmp_path):
    checkout, bodies, _ = chain
    folder = tempfile.TemporaryDirectory(dir=tmp_path)
    root = Path(folder.name)
    parked = tmp_path / 'original-patch-scratch'
    sentinel = root / 'replacement.txt'
    monkeypatch.setattr(ordered.tempfile, 'TemporaryDirectory', lambda **_kwargs: folder)
    try:
        with pytest.raises(ContractError, match='ordered patch scratch directory changed before cleanup'):
            with ordered._copy(checkout, bodies) as (scratch, _names, _before, _check):
                assert scratch == root
                root.rename(parked)
                root.mkdir()
                sentinel.write_text('replacement', encoding='utf-8')
        assert sentinel.read_text(encoding='utf-8') == 'replacement'
    finally:
        if sentinel.exists():
            sentinel.unlink()
            root.rmdir()
        if parked.exists():
            parked.rename(root)
        folder.cleanup()


def test_replaced_patch_scratch_is_not_written_after_step(chain, monkeypatch, tmp_path):
    checkout, bodies, _ = chain
    folder = tempfile.TemporaryDirectory(dir=tmp_path)
    root = Path(folder.name)
    parked = tmp_path / 'original-patch-scratch'
    sentinel = root / 'a.txt'
    monkeypatch.setattr(ordered.tempfile, 'TemporaryDirectory', lambda **_kwargs: folder)
    calls = 0

    def swap_after_step(_scratch, _patch, _check, **_kwargs):
        nonlocal calls
        calls += 1
        if calls == 1:
            root.rename(parked)
            root.mkdir()
            sentinel.write_text('replacement', encoding='utf-8')
        return False

    monkeypatch.setattr(ordered, '_step', swap_after_step)
    try:
        with pytest.raises(ContractError, match='ordered patch scratch directory changed before cleanup'):
            ordered.classify(checkout, bodies[:1])
        assert sentinel.read_text(encoding='utf-8') == 'replacement'
    finally:
        if sentinel.exists():
            sentinel.unlink()
            root.rmdir()
        if parked.exists():
            parked.rename(root)
        folder.cleanup()
