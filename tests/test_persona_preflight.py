"""A ready selected profile must reflect the browser, including legacy graphics."""
from contextlib import contextmanager, nullcontext
from pathlib import Path
from tempfile import TemporaryDirectory

import pytest

import browser_core.cdp as cdp
import browser_core.persona_preflight as preflight
from browser_core.contracts import ContractError
from browser_core.personas import persona_digest
from browser_core.persona_projection import native_persona_arguments
from test_personas import fixture_persona


def measured():
    return {key: None for key in preflight.SUPPORTED_CLAIMS} | {
        'userAgentData.mobile': False, 'window.platform': 'Win32',
    }


def test_claims_are_checked_with_typed_values_and_ordered_lists():
    persona = fixture_persona()
    expected = persona['identity_contract']['expected']
    expected.update({'window.hardwareConcurrency': 10, 'window.languages': ['en-US', 'en']})
    observed = measured() | expected
    preflight.require_native_claims(persona, observed)
    preflight.require_native_claims(persona, observed | {'window.hardwareConcurrency': 10.0})
    with pytest.raises(ContractError, match='window.languages'):
        preflight.require_native_claims(persona, observed | {'window.languages': ['en', 'en-US']})
    with pytest.raises(ContractError, match='userAgentData.mobile'):
        preflight.require_native_claims(persona, observed | {'userAgentData.mobile': 0})


@pytest.mark.parametrize('key', sorted(preflight.SUPPORTED_CLAIMS))
def test_every_supported_claim_can_block_a_mismatched_profile(key):
    persona = fixture_persona()
    persona['identity_contract']['expected'] = {key: 'expected-private-value'}
    with pytest.raises(ContractError, match=key) as error:
        preflight.require_native_claims(persona, measured() | {key: 'actual-private-value'})
    assert 'private-value' not in str(error.value)


def test_unknown_claims_are_not_silently_skipped_before_launch():
    persona = fixture_persona()
    persona['identity_contract']['expected']['worker.extraProbe'] = 10
    persona['integrity_sha256'] = persona_digest(persona)
    with pytest.raises(ContractError, match='cannot verify'):
        native_persona_arguments(persona, ())


@pytest.mark.parametrize('observed', [None, {}, [], {'unexpected': True}])
def test_partial_or_invalid_observation_is_not_success(observed):
    with pytest.raises(ContractError, match='incomplete'):
        preflight.require_native_claims(fixture_persona(), observed)


@pytest.mark.parametrize('value', [True, float('inf'), float('nan'), '1', 10 ** 1000])
def test_number_comparison_does_not_coerce_or_accept_nonfinite_values(value):
    persona = fixture_persona()
    persona['identity_contract']['expected']['window.hardwareConcurrency'] = 1
    with pytest.raises(ContractError, match='window.hardwareConcurrency'):
        preflight.require_native_claims(persona, measured() | {'window.hardwareConcurrency': value})


def wire_fixture(monkeypatch, *, create=None, close=None):
    calls = []
    monkeypatch.setattr(cdp, '_browser_websocket_url', lambda *_a: 'ws://127.0.0.1:9222/devtools/browser/owned')

    def command(websocket, payload, timeout):
        assert websocket.endswith('/owned') and timeout > 0
        calls.append(payload)
        if payload['method'] == 'Target.createTarget':
            return create if create is not None else {'result': {'targetId': 'created-target'}}
        assert payload['method'] == 'Target.closeTarget'
        assert payload['params'] == {'targetId': 'created-target'}
        return close if close is not None else {'result': {'success': True}}

    monkeypatch.setattr(cdp, '_websocket_json_command', command)
    return calls


FIXTURE = Path.cwd() / ('browser-core-startup-' + 'a' * 32) / 'profile.html'


@pytest.mark.parametrize('failure', [False, True])
def test_temporary_page_closes_only_its_created_target_even_on_check_failure(monkeypatch, failure):
    calls = wire_fixture(monkeypatch)
    with pytest.raises(RuntimeError) if failure else nullcontext():
        with cdp.temporary_startup_page('http://127.0.0.1:9222', FIXTURE) as url:
            assert url == FIXTURE.as_uri()
            if failure:
                raise RuntimeError('fixture check failed')
    assert len(calls) == 2
    assert calls[0]['params'] == {'url': FIXTURE.as_uri(), 'background': True}


@pytest.mark.parametrize('fixture', [
    'https://example.com/', 'http://user:password@127.0.0.1:8765/',
    FIXTURE.as_uri(), Path('relative/profile.html'), FIXTURE.with_name('unowned.html'),
    Path.cwd() / 'unowned/profile.html', FIXTURE.parent / '../profile.html',
])
def test_temporary_page_rejects_nonfixture_paths_before_discovery(monkeypatch, fixture):
    monkeypatch.setattr(cdp, '_browser_websocket_url', lambda *_a: pytest.fail('unexpected discovery'))
    with pytest.raises(ContractError):
        with cdp.temporary_startup_page('http://127.0.0.1:9222', fixture):
            pytest.fail('unexpected page')


@pytest.mark.parametrize('response', [
    {}, {'error': {'message': 'private text'}}, {'result': {'targetId': '../../unowned'}},
    {'result': {'targetId': True}}, {'result': {'targetId': 'x' * 257}},
])
def test_bad_creation_never_closes_a_guessed_target(monkeypatch, response):
    calls = wire_fixture(monkeypatch, create=response)
    with pytest.raises(ContractError, match='could not be created'):
        with cdp.temporary_startup_page('http://127.0.0.1:9222', FIXTURE):
            pytest.fail('unexpected page')
    assert len(calls) == 1


@pytest.mark.parametrize('response', [{}, {'result': {'success': False}}, {'result': {'success': 1}}, {'error': {}}])
def test_cleanup_failure_is_not_silently_successful(monkeypatch, response):
    wire_fixture(monkeypatch, close=response)
    with pytest.raises(ContractError, match='cleanup failed'):
        with cdp.temporary_startup_page('http://127.0.0.1:9222', FIXTURE):
            pass


@pytest.mark.parametrize('failure', ['none', 'claims', 'insecure', 'different-url', 'evaluate'])
def test_secure_owned_check_always_releases_page_and_local_document(monkeypatch, failure, tmp_path):
    phases = []

    class Directory:
        def __init__(self, *, prefix):
            assert prefix == 'browser-core-startup-'
            self.name = str(tmp_path / (prefix + 'owned'))
            Path(self.name).mkdir()
            phases.append('directory-open')

        def cleanup(self):
            folder = Path(self.name)
            (folder / 'profile.html').unlink()
            folder.rmdir()
            phases.append('directory-close')

    @contextmanager
    def page(endpoint, fixture, **kwargs):
        assert endpoint == 'http://127.0.0.1:9222'
        assert kwargs['timeout_seconds'] <= 3
        assert b'Content-Security-Policy' in fixture.read_bytes()
        phases.append('page-open')
        try:
            yield fixture.as_uri()
        finally:
            phases.append('page-close')

    def read(endpoint, expression, *, target_url, timeout_seconds, command_id):
        assert expression == preflight._READ_NATIVE_SETTINGS and timeout_seconds <= 3
        phases.append('read')
        if failure == 'evaluate':
            raise ContractError('evaluation failed')
        result = {'url': target_url, 'secure': True, 'claims': measured()}
        if failure == 'claims':
            result['claims']['window.platform'] = 'Linux'
        if failure == 'insecure':
            result['secure'] = False
        if failure == 'different-url':
            result['url'] = 'https://example.com/'
        return result

    monkeypatch.setattr(preflight, 'TemporaryDirectory', Directory)
    monkeypatch.setattr(preflight, 'temporary_startup_page', page)
    monkeypatch.setattr(preflight, 'evaluate_page_expression', read)
    with pytest.raises(ContractError) if failure != 'none' else nullcontext():
        preflight.verify_native_persona(fixture_persona(), 'http://127.0.0.1:9222', timeout_seconds=3)
    assert phases == ['directory-open', 'page-open', 'read', 'page-close', 'directory-close']
    assert list(tmp_path.iterdir()) == []


def test_replaced_startup_fixture_directory_is_preserved(monkeypatch, tmp_path):
    folder = TemporaryDirectory(dir=tmp_path)
    root = Path(folder.name)
    parked = tmp_path / 'original-startup-fixture'
    sentinel = root / 'replacement.txt'
    monkeypatch.setattr(preflight, 'TemporaryDirectory', lambda **_kwargs: folder)

    @contextmanager
    def page(_endpoint, fixture, **_kwargs):
        yield fixture.as_uri()

    def read(_endpoint, _expression, *, target_url, **_kwargs):
        root.rename(parked)
        root.mkdir()
        sentinel.write_text('replacement', encoding='utf-8')
        return {'url': target_url, 'secure': True, 'claims': measured()}

    monkeypatch.setattr(preflight, 'temporary_startup_page', page)
    monkeypatch.setattr(preflight, 'evaluate_page_expression', read)
    try:
        with pytest.raises(ContractError, match='native startup fixture directory changed before cleanup'):
            preflight.verify_native_persona(
                fixture_persona(), 'http://127.0.0.1:9222', timeout_seconds=3,
            )
        assert sentinel.read_text(encoding='utf-8') == 'replacement'
    finally:
        if sentinel.exists():
            sentinel.unlink()
            root.rmdir()
        if parked.exists():
            parked.rename(root)
        folder.cleanup()
