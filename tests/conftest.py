import pytest


@pytest.fixture(autouse=True)
def _isolate_population_cache(monkeypatch):
    # Tests reuse identical snapshot bytes with different fake exporters, so a
    # shared content-addressed cache would leak populations between tests.
    # Cache tests opt back in with their own temporary directory.
    monkeypatch.setenv('BROWSER_CORE_METADATA_CACHE', 'off')
