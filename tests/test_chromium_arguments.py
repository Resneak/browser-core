"""Pinned Chromium argv rules at the managed launch boundary; no browser runs."""
from pathlib import Path

import pytest

from browser_core import chromium_arguments as arguments
from browser_core.contracts import ContractError
from browser_core.launcher import (EvaluationLaunch, evaluation_command,
    managed_startup_target, validate_evaluation_extra_args, validate_evaluation_launch)
from browser_core.persona_projection import native_persona_arguments
from test_personas import fixture_persona


MANAGED = (
    'user-data-dir', 'profile-directory', 'remote-debugging-port', 'remote-debugging-pipe',
    'remote-debugging-io-pipes', 'remote-debugging-address', 'remote-debugging-socket-name',
    'remote-debugging-targets', 'remote-allow-origins', 'proxy-server', 'proxy-auto-detect',
    'proxy-bypass-list', 'proxy-pac-url', 'no-proxy-server', 'force-webrtc-ip-handling-policy',
    'webrtc-ip-handling-policy', 'trace-startup', 'trace-startup-duration', 'trace-startup-file',
    'trace-startup-format', 'trace-startup-record-mode', 'trace-startup-owner',
    'trace-config-file', 'trace-perfetto-config-file', 'trace-config-handle', 'enable-tracing',
    'enable-tracing-output', 'enable-tracing-format', 'browser-core-live-trace',
    'browser-core-recording-limit-mib', 'browser-core-recording-parts',
    'browser-core-inspect-values', 'browser-core-evaluation', 'single-argument', 'type',
)


@pytest.fixture
def windows_parser(monkeypatch):
    # Select the target parser without changing os.name or filesystem semantics.
    monkeypatch.setattr(arguments, '_WINDOWS', True)


@pytest.mark.parametrize('name', MANAGED)
@pytest.mark.parametrize('prefix,upper,padding', [('--', False, ''), ('-', False, ''),
    ('/', False, ''), ('--', True, ''), ('/', True, ' '), ('-', True, '\u3000')])
@pytest.mark.parametrize('suffix', ['', '=', '=arbitrary=opaque value'])
def test_all_native_managed_spellings_fail_before_launch(windows_parser, name, prefix, upper, padding, suffix):
    argument = padding+prefix+(name.upper() if upper else name)+suffix+padding
    with pytest.raises(ContractError):
        validate_evaluation_extra_args((argument,))


@pytest.mark.parametrize('name', MANAGED)
@pytest.mark.parametrize('reverse', [False, True])
def test_no_duplicate_order_can_cancel_an_override(windows_parser, name, reverse):
    items = ('/'+name.upper()+'=first', '-'+name+'=last')
    with pytest.raises(ContractError):
        validate_evaluation_extra_args(tuple(reversed(items)) if reverse else items)


@pytest.mark.parametrize('padding', list(arguments._WINDOWS_WHITESPACE))
def test_every_pinned_windows_trim_character_is_guarded(windows_parser, padding):
    with pytest.raises(ContractError):
        validate_evaluation_extra_args((padding+'/BROWSER-CORE-INSPECT-VALUES=fingerprint-v2'+padding,))


@pytest.mark.parametrize('prefix', ['--', '-', '/'])
@pytest.mark.parametrize('name', ['enable-quic','disable-quic','host-resolver-rules','host-rules',
                                'origin-to-force-quic-on','quic-version'])
def test_containment_uses_the_same_classifier_in_preflight(windows_parser, tmp_path, prefix, name):
    with pytest.raises(ContractError, match='containment'):
        validate_evaluation_launch(EvaluationLaunch(tmp_path/'chrome.exe', tmp_path/'workspace',
            extra_args=(' '+prefix+name.upper()+'=opaque ',),
            local_containment_proxy=('127.0.0.1', 1234, 5678)))


@pytest.mark.parametrize('argument', [
    '--headless=new', '-headless=new', '/HEADLESS=new', '--no-sandbox',
    '--disable-background-networking', '--custom=--user-data-dir=opaque',
    '--custom=/BROWSER-CORE-INSPECT-VALUES=fingerprint-v2',
    '--custom=first=second', '--custom=with spaces and "quotes"',
    '--user-data-directory=opaque', '--trace-startup-not-a-native-switch=x',
    '--remote-debugging-portability=x', '--proxy-serverish=x',
    '--browser-core-inspect-values-extra=x', '--browser-core-inspect-values =x',
    '---user-data-dir=opaque', '//user-data-dir=opaque',
    '\u200b--user-data-dir=opaque', '\ufeff--user-data-dir=opaque',
    'https://example.invalid/?flag=--user-data-dir=opaque',
    'data:text/plain,--browser-core-inspect-values=fingerprint-v2',
])
def test_legitimate_arguments_and_opaque_values_are_not_rewritten_or_overblocked(windows_parser, tmp_path, argument):
    validate_evaluation_extra_args((argument,))
    result = evaluation_command(tmp_path/'chrome.exe', tmp_path/'profile', None,
        'owned-run', headless=False, extra_args=(argument,), trace_mode='off')
    assert argument in result


def test_first_terminator_ends_parsing_but_positionals_do_not(windows_parser):
    with pytest.raises(ContractError):
        validate_evaluation_extra_args(('https://example.invalid/', '/USER-DATA-DIR=x'))
    parsed = arguments.classify_arguments((' /HEADLESS=new ', ' -- ', '/USER-DATA-DIR=x', '--'))
    assert parsed.switches == ('headless',)
    assert parsed.positional == ('/USER-DATA-DIR=x', '--')
    validate_evaluation_extra_args((' -- ', '/USER-DATA-DIR=x'))


def test_platform_rules_are_not_python_strip_or_unicode_casefold():
    items = ('\u00a0/User-Data-Dir=x\u00a0', '-USER-DATA-DIR=x', ' -- ', '--x=y')
    windows = arguments.classify_arguments(items, windows=True)
    posix = arguments.classify_arguments(items, windows=False)
    assert windows.switches == ('user-data-dir', 'user-data-dir')
    assert windows.positional == ('--x=y',)
    assert posix.switches == ('USER-DATA-DIR',)
    assert posix.positional == ('\u00a0/User-Data-Dir=x\u00a0', '--x=y')
    assert arguments.classify_arguments(('--\u0130=Value',), windows=True).switches == ('\u0130',)


def test_classifier_retains_duplicates_not_values():
    parsed = arguments.classify_arguments(('--custom=FIRST', '/CUSTOM=last'), windows=True)
    assert parsed.switches == ('custom', 'custom')
    assert parsed.positional == ()


@pytest.mark.parametrize('items', [('/HEADLESS=new',), (' -- ',), ('-headless=new', ' -- ')])
def test_inert_target_is_still_added_for_native_switches_and_terminator(windows_parser, items):
    actual, target = managed_startup_target(items, 'owned-run')
    assert actual == (*items, target)
    assert target.startswith('data:text/html,')
    assert arguments.classify_arguments(actual).positional == (target,)


def test_explicit_target_uses_chromium_trimming_without_rewriting_argv(windows_parser):
    items = ('/HEADLESS=new', ' \u3000https://example.invalid/\u3000 ')
    actual, target = managed_startup_target(items, 'owned-run')
    assert actual == items
    assert target == 'https://example.invalid/'


@pytest.mark.parametrize('name', ['screen-info','window-size','lang','accept-lang',
    'browser-core-screen-size','browser-core-screen-work-area','browser-core-timezone',
    'browser-core-locale','force-device-scale-factor'])
def test_selected_profile_claims_reject_alternate_native_override_names(windows_parser, name):
    with pytest.raises(ContractError, match='override'):
        native_persona_arguments(fixture_persona(), (' /'+name.upper()+'=opaque ',))
