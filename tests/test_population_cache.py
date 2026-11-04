"""A cache hit must return exactly what a fresh decode returns, or nothing."""
import json

import pytest

from browser_core import metadata_query as module, population_cache
from browser_core.contracts import ContractError
from browser_core.inspection_history import history_filters
from test_metadata_workflow import source, events  # noqa: F401  (fixtures)


@pytest.fixture
def cache(tmp_path, monkeypatch):
    root = tmp_path / 'cache'
    monkeypatch.setenv('BROWSER_CORE_METADATA_CACHE', str(root))
    return root


@pytest.fixture
def counted_export(events, monkeypatch):
    calls = []
    original = module.export_perfetto

    def export(*args, **kwargs):
        calls.append(1)
        return original(*args, **kwargs)

    monkeypatch.setattr(module, 'export_perfetto', export)
    return calls


QUERIES = [
    dict(filters=history_filters(), limit=3),
    dict(filters=history_filters(apis=['Navigator.language.get']), limit=2),
    dict(filters=history_filters(apis=['Unknown.event']), limit=5),
    dict(filters=history_filters(script='7'), limit=4),
    dict(filters=history_filters(script='8'), limit=4),
    dict(filters=history_filters(start_ns='102', end_ns='104'), limit=10),
    dict(filters=history_filters(), limit=2, metadata_version=2),
    dict(filters=history_filters(), limit=2, portable_context={'pid': '10', 'context_id': 'ABCD'}),
    dict(filters=history_filters(), limit=2, portable_context={'pid': '11', 'context_id': 'ABCD'}),
]


@pytest.mark.parametrize('options', QUERIES)
def test_hit_is_identical_to_fresh_decode(source, cache, counted_export, options):
    fresh = module.metadata_query(source, **options)
    assert len(counted_export) == 1 and any(cache.iterdir())
    hit = module.metadata_query(source, **options)
    assert len(counted_export) == 1, 'second query must not re-export'
    assert hit == fresh


def test_cursor_pages_match_across_hit_and_miss(source, cache, counted_export, monkeypatch):
    options = dict(filters=history_filters(), limit=3, bundle_sha256='a' * 64)
    first = module.metadata_query(source, **options)
    second = module.metadata_query(source, cursor=first['query']['next_cursor'], **options)
    monkeypatch.setenv('BROWSER_CORE_METADATA_CACHE', 'off')
    fresh_second = module.metadata_query(source, cursor=first['query']['next_cursor'], **options)
    assert second == fresh_second and len(counted_export) == 2


def test_corrupted_entry_is_discarded_and_rebuilt(source, cache, counted_export):
    options = dict(filters=history_filters(), limit=3)
    fresh = module.metadata_query(source, **options)
    (entry,) = [path for path in cache.iterdir() if not path.name.startswith('.')]
    events_file = entry / 'events.jsonl'
    events_file.write_bytes(events_file.read_bytes().replace(b'Navigator', b'Navigatox'))
    again = module.metadata_query(source, **options)
    assert again == fresh and len(counted_export) == 2


def test_live_prefix_is_never_cached(source, cache, counted_export):
    source.resolve().phase = 'live-prefix'
    module.metadata_query(source, filters=history_filters(), limit=1)
    module.metadata_query(source, filters=history_filters(), limit=1)
    assert len(counted_export) == 2
    assert not cache.exists() or not any(cache.iterdir())


def test_disabled_cache_writes_nothing(source, counted_export, tmp_path, monkeypatch):
    monkeypatch.setenv('BROWSER_CORE_METADATA_CACHE', 'off')
    module.metadata_query(source, filters=history_filters(), limit=1)
    module.metadata_query(source, filters=history_filters(), limit=1)
    assert len(counted_export) == 2


def test_key_binds_reader_runtime_and_version():
    base = dict(phase='finalized-recording', snapshot_sha256='a' * 64, run_id='r',
                revision='b' * 40, reader_runtime={'x': 1}, package_version='1')
    key = population_cache.cache_key(**base)
    assert key != population_cache.cache_key(**{**base, 'reader_runtime': {'x': 2}})
    assert key != population_cache.cache_key(**{**base, 'package_version': '2'})
    assert key != population_cache.cache_key(**{**base, 'snapshot_sha256': 'c' * 64})
    assert population_cache.cache_key(**{**base, 'phase': 'live-prefix'}) is None


def test_population_that_fails_row_validation_is_not_cached(source, cache, events, monkeypatch):
    events[3]['execution']['context_id'] = 'x' * 300  # rows projection rejects >256
    module.metadata_query(source, filters=history_filters(), limit=1)
    assert not any(path for path in cache.iterdir() if not path.name.startswith('.'))
    from browser_core import metadata_rows
    with pytest.raises(ContractError):
        metadata_rows.project_row(events[3])
