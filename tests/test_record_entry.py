from pathlib import Path
import pytest

from browser_core.contracts import ContractError
from browser_core.record import CallSummary, validate_url, write_summary


@pytest.mark.parametrize('url', ['file:///secret', 'https://user:pass@example.org/', 'https://example.org/\n', '--no-sandbox', 'https://example.org:bad/'])
def test_rejects_non_page_arguments_and_credentials(url):
    with pytest.raises(ContractError):
        validate_url(url)


def test_keeps_process_scopes_and_does_not_claim_fetch_sent():
    summary = CallSummary()
    for pid in (1, 2):
        summary.consume({'event': {'category': 'api', 'name': 'WorkerGlobalScope.fetch'},
                         'process': {'pid': pid}, 'execution': {'context_id': 'same', 'script_id': 'script'}})
    text = summary.markdown()
    assert len(summary.calls) == 2
    assert 'does not establish a network request' in text
    assert 'unresolved' in text


def test_does_not_publish_index_from_invalid_trace(tmp_path):
    events = tmp_path / 'events.jsonl'
    events.write_text('{"invalid": true}\n', encoding='utf-8')
    destination = tmp_path / 'calls.md'
    with pytest.raises(ContractError):
        write_summary(events, destination)
    assert not destination.exists()
