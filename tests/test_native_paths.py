from pathlib import Path
from types import SimpleNamespace

import pytest

from browser_core.errors import ContractError
import browser_core.native_paths as paths


def test_short_path_and_non_windows_paths_need_no_alias(monkeypatch):
    monkeypatch.setattr(paths, '_short_directory', lambda _: pytest.fail('unexpected alias lookup'))
    assert paths.native_browser_path(Path('short'), profile=True) == Path('short')
    monkeypatch.setattr(paths, 'os', SimpleNamespace(name='posix'))
    path = Path('x' * 250)
    assert paths.native_browser_path(path, profile=True) == path


@pytest.mark.parametrize('profile', [True, False])
def test_alias_preserves_directory_identity_and_file_leaf(monkeypatch, tmp_path, profile):
    monkeypatch.setattr(paths, 'os', SimpleNamespace(name='nt'))
    original = tmp_path / ('long' * 65)
    alias = tmp_path / 's'
    monkeypatch.setattr(paths, '_short_directory', lambda directory: alias)
    monkeypatch.setattr(paths, 'directory_identity', lambda *args, **kwargs: (1, 2, 3, 4))
    # Keep this test independent of pytest's own temporary path depth.
    monkeypatch.setattr(paths, '_windows_units', lambda p: 300 if 'long' in str(p) else 80)
    target = original if profile else original / 'recording.perfetto-trace'
    actual = paths.native_browser_path(target, profile=profile)
    assert actual == (alias if profile else alias / target.name)


@pytest.mark.parametrize('identities', [[None], [(1, 2, 3, 4), (1, 9, 3, 4)], [(1, 2, 3, 4), (1, 2, 3, 4), (1, 9, 3, 4)]])
def test_alias_refuses_missing_mismatched_or_replaced_directory(monkeypatch, tmp_path, identities):
    monkeypatch.setattr(paths, 'os', SimpleNamespace(name='nt'))
    monkeypatch.setattr(paths, '_windows_units', lambda p: 300)
    monkeypatch.setattr(paths, '_short_directory', lambda p: tmp_path / 's')
    observed = iter(identities)
    monkeypatch.setattr(paths, 'directory_identity', lambda *args, **kwargs: next(observed))
    with pytest.raises(ContractError, match='missing|changed'):
        paths.native_browser_path(tmp_path / 'long', profile=True)


def test_unchanged_or_still_deep_alias_fails_before_browser_launch(monkeypatch, tmp_path):
    monkeypatch.setattr(paths, 'os', SimpleNamespace(name='nt'))
    monkeypatch.setattr(paths, '_windows_units', lambda p: 300)
    monkeypatch.setattr(paths, '_short_directory', lambda p: p)
    monkeypatch.setattr(paths, 'directory_identity', lambda *args, **kwargs: (1, 2, 3, 4))
    with pytest.raises(ContractError, match='choose a shorter workspace'):
        paths.native_browser_path(tmp_path / 'long', profile=True)


def test_windows_budget_counts_utf16_units():
    assert paths._windows_units(Path('a\U0001f600')) == 3
