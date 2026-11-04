"""Native resizing must use measured content geometry and fail before publication."""
import pytest
import browser_core.cdp as cdp
from browser_core.contracts import ContractError
from browser_core.launcher import evaluation_command


@pytest.mark.parametrize('headless', [False, True])
def test_explicit_research_launch_keeps_occluded_windows_active(headless, tmp_path):
    command = evaluation_command(
        tmp_path/'chrome.exe', tmp_path/'profile', None, 'owned-run',
        headless=headless, trace_mode='off', extra_args=(),
    )
    assert '--browser-core-evaluation' in command
    assert '--disable-backgrounding-occluded-windows' in command


def fixture(monkeypatch, observations, *, window=None, resize_error=False):
    calls = []
    pending = iter(observations)
    current = observations[-1]
    now = [100.0]
    monkeypatch.setattr(cdp.time, 'monotonic', lambda: now[0])
    monkeypatch.setattr(cdp.time, 'sleep', lambda delay: now.__setitem__(0, now[0] + delay))

    def target(endpoint, url, timeout):
        assert endpoint == 'http://127.0.0.1:9222' and url == 'about:blank#owned'
        return 'ws://127.0.0.1:9222/devtools/page/owned'

    def command(url, payload, timeout):
        nonlocal current
        assert url == 'ws://127.0.0.1:9222/devtools/page/owned'
        assert 0 < timeout <= 1
        calls.append(payload)
        method = payload['method']
        if method == 'Page.bringToFront':
            return {'result': {}}
        if method == 'Runtime.evaluate':
            current = next(pending, current)
            value = {'outerWidth': 1296, 'outerHeight': 815, **current} if isinstance(current, dict) else current
            return {'result': {'result': {'type': 'object', 'value': value}}}
        if method == 'Browser.getWindowForTarget':
            return {'result': window if window is not None else {'windowId': 7, 'bounds': {'windowState': 'normal', 'width': 1296, 'height': 815}}}
        assert method == 'Browser.setContentsSize'
        assert payload['params'] == {'windowId': 7, 'width': 1280, 'height': 720}
        return {'error': {'message': 'private browser text'}} if resize_error else {'result': {}}

    monkeypatch.setattr(cdp, '_page_websocket_url', target)
    monkeypatch.setattr(cdp, '_websocket_json_command', command)
    return calls


def run():
    return cdp.realize_native_viewport('http://127.0.0.1:9222', 'about:blank#owned', 1280, 720, timeout_seconds=1)


def test_zero_startup_frame_waits_and_real_native_resize_is_verified(monkeypatch):
    calls = fixture(monkeypatch, [{'width': 0, 'height': 0}, {'width': 1264, 'height': 625}, {'width': 1280, 'height': 720}])
    assert run() == {'width': 1280, 'height': 720}
    assert [p['method'] for p in calls[:6]] == ['Page.bringToFront', 'Runtime.evaluate', 'Runtime.evaluate', 'Browser.getWindowForTarget', 'Browser.setContentsSize', 'Runtime.evaluate']
    assert all(p['method'] == 'Runtime.evaluate' for p in calls[6:])


def test_correct_size_requires_no_window_mutation(monkeypatch):
    calls = fixture(monkeypatch, [{'width': 1280, 'height': 720}])
    assert run() == {'width': 1280, 'height': 720}
    assert len(calls) > 2 and all(p['method'] == 'Runtime.evaluate' for p in calls[1:])


def test_matching_viewport_observed_after_deadline_is_not_ready(monkeypatch):
    clock = [0.0]
    monkeypatch.setattr(cdp.time, 'monotonic', lambda: clock[0])
    monkeypatch.setattr(cdp.time, 'sleep', lambda delay: clock.__setitem__(0, clock[0] + delay))
    monkeypatch.setattr(
        cdp, '_page_websocket_url',
        lambda *_args: 'ws://127.0.0.1:9222/devtools/page/owned',
    )

    def command(_url, payload, _timeout):
        if payload['method'] == 'Page.bringToFront':
            return {'result': {}}
        assert payload['method'] == 'Runtime.evaluate'
        if clock[0] >= .5:
            clock[0] = 1.1
        return {
            'result': {
                'result': {
                    'type': 'object',
                    'value': {
                        'width': 1280,
                        'height': 720,
                        'outerWidth': 1296,
                        'outerHeight': 815,
                    },
                },
            },
        }

    monkeypatch.setattr(cdp, '_websocket_json_command', command)
    with pytest.raises(ContractError, match='deadline expired'):
        run()


def test_transient_match_during_toolbar_animation_is_not_readiness(monkeypatch):
    calls = fixture(monkeypatch, [{'width': 1280, 'height': 720}, {'width': 1280, 'height': 754}, {'width': 1280, 'height': 720}])
    assert run() == {'width': 1280, 'height': 720}
    assert sum(p['method'] == 'Browser.setContentsSize' for p in calls) == 1


def test_resize_acknowledgment_without_matching_geometry_is_not_success(monkeypatch):
    calls = fixture(monkeypatch, [{'width': 1264, 'height': 625}])
    with pytest.raises(ContractError):
        run()
    assert sum(p['method'] == 'Browser.setContentsSize' for p in calls) == 3


def test_permanently_unready_frame_is_bounded_without_resize(monkeypatch):
    calls = fixture(monkeypatch, [{'width': 0, 'height': 0}])
    with pytest.raises(ContractError):
        run()
    assert all(p['method'] == 'Runtime.evaluate' for p in calls[1:])


def test_matching_inner_size_with_unready_native_window_is_not_success(monkeypatch):
    calls = fixture(monkeypatch, [{'width': 1280, 'height': 720, 'outerWidth': 0, 'outerHeight': 0}])
    with pytest.raises(ContractError):
        run()
    assert sum(p['method'] == 'Browser.setContentsSize' for p in calls) == 3


def test_real_native_bounds_break_permanently_zero_renderer_outer_dimensions(monkeypatch):
    calls = fixture(monkeypatch, [
        {'width': 1264, 'height': 625, 'outerWidth': 0, 'outerHeight': 0},
        {'width': 1280, 'height': 720},
    ])
    assert run() == {'width': 1280, 'height': 720}
    assert [p['method'] for p in calls[:4]] == ['Page.bringToFront', 'Runtime.evaluate', 'Browser.getWindowForTarget', 'Browser.setContentsSize']


def test_zero_page_outer_dimensions_without_positive_native_bounds_do_not_resize(monkeypatch):
    calls = fixture(monkeypatch, [{'width': 1264, 'height': 625, 'outerWidth': 0, 'outerHeight': 0}],
                    window={'windowId': 7, 'bounds': {'windowState': 'normal', 'width': 0, 'height': 0}})
    with pytest.raises(ContractError):
        run()
    assert not any(p['method'] == 'Browser.setContentsSize' for p in calls)


@pytest.mark.parametrize('observed', [None, {}, {'width': True, 'height': 720}, {'width': -1, 'height': 720}, {'width': '1280', 'height': 720}, {'width': 100001, 'height': 720}])
def test_invalid_geometry_is_not_used_for_window_arithmetic(monkeypatch, observed):
    calls = fixture(monkeypatch, [observed])
    with pytest.raises(ContractError, match='observation is invalid'):
        run()
    assert len(calls) == 2


@pytest.mark.parametrize('window', [{}, {'windowId': True, 'bounds': {'windowState': 'normal'}}, {'windowId': 7, 'bounds': {'windowState': 'minimized'}}, {'windowId': 7, 'bounds': None}])
def test_missing_or_wrong_window_state_cannot_be_resized(monkeypatch, window):
    calls = fixture(monkeypatch, [{'width': 1264, 'height': 625}], window=window)
    with pytest.raises(ContractError, match='window is unavailable'):
        run()
    assert not any(p['method'] == 'Browser.setContentsSize' for p in calls)


def test_protocol_error_does_not_echo_browser_text(monkeypatch):
    fixture(monkeypatch, [{'width': 1264, 'height': 625}], resize_error=True)
    with pytest.raises(ContractError, match='native viewport command failed') as error:
        run()
    assert 'private' not in str(error.value)


@pytest.mark.parametrize('width,height', [(True, 720), (199, 720), (10001, 720), (1280, 0)])
def test_bad_requested_geometry_does_not_reach_the_browser(monkeypatch, width, height):
    monkeypatch.setattr(cdp, '_page_websocket_url', lambda *a: pytest.fail('no discovery allowed'))
    with pytest.raises(ContractError, match='dimensions are invalid'):
        cdp.realize_native_viewport('http://127.0.0.1:9222', 'about:blank#owned', width, height)
