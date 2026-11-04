from __future__ import annotations

import json

import pytest

from browser_core import cdp
from browser_core.contracts import ContractError


class Response:
    def __init__(self, document: object) -> None:
        self.payload = json.dumps(document).encode("utf-8")
        self.offset = 0
        self.closed = False

    def __enter__(self) -> "Response":
        return self

    def __exit__(self, *_: object) -> None:
        return None

    def close(self) -> None:
        self.closed = True

    def getcode(self) -> int:
        return 200

    def read(self, maximum: int) -> bytes:
        block = self.payload[self.offset : self.offset + maximum]
        self.offset += len(block)
        return block


def test_wait_for_page_target_matches_exact_fixture(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = {
        "id": "fixture",
        "type": "page",
        "url": "file:///fixture.html",
        "title": "browser-core-native-canvas-ok",
    }
    monkeypatch.setattr(cdp, "urlopen", lambda *_args, **_kwargs: Response([target]))
    assert (
        cdp.wait_for_page_target(
            "http://127.0.0.1:9222",
            target["url"],
            target["title"],
            timeout_seconds=0.1,
        )
        == target
    )


def test_wait_for_page_target_rejects_non_loopback_endpoint() -> None:
    with pytest.raises(ContractError, match="loopback"):
        cdp.wait_for_page_target(
            "http://example.com:9222",
            "file:///fixture.html",
            "fixture",
        )


def test_wait_for_page_target_rejects_duplicate_exact_targets(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    owned_url = "about:blank#browser-core-fixture-run-1"
    targets = [
        {
            "id": "expected",
            "type": "page",
            "url": owned_url,
            "title": "browser-core-native-canvas-ok",
        },
        {
            "id": "competitor",
            "type": "page",
            "url": owned_url,
            "title": "competitor-title",
        },
    ]
    response = Response(targets)
    monkeypatch.setattr(cdp, "urlopen", lambda *_args, **_kwargs: response)

    with pytest.raises(ContractError) as raised:
        cdp.wait_for_page_target(
            "http://127.0.0.1:9222",
            owned_url,
            "browser-core-native-canvas-ok",
            timeout_seconds=0.1,
        )
    assert str(raised.value) == (
        "multiple page targets matched the exact managed target URL"
    )
    assert response.closed is True
    assert "competitor" not in str(raised.value)


def test_page_websocket_url_selects_only_exact_owned_target(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    owned_url = "about:blank#browser-core-identity-run-1"
    targets = [
        {
            "id": "unrelated",
            "type": "page",
            "url": "about:blank",
            "webSocketDebuggerUrl": "ws://127.0.0.1:9222/devtools/page/unrelated",
        },
        {
            "id": "owned",
            "type": "page",
            "url": owned_url,
            "webSocketDebuggerUrl": "ws://127.0.0.1:9222/devtools/page/owned",
        },
        {
            "id": "restored",
            "type": "page",
            "url": "https://example.test/restored",
            "webSocketDebuggerUrl": "ws://127.0.0.1:9222/devtools/page/restored",
        },
    ]
    monkeypatch.setattr(cdp, "urlopen", lambda *_args, **_kwargs: Response(targets))

    assert cdp._page_websocket_url("http://127.0.0.1:9222", owned_url, 0.1) == (
        "ws://127.0.0.1:9222/devtools/page/owned"
    )


@pytest.mark.parametrize(
    ("target_id", "websocket_url"),
    [
        ("owned", "ws://127.0.0.1:9222/devtools/page/other"),
        ("owned", "ws://127.0.0.1:9222/devtools/browser/owned"),
        (None, "ws://127.0.0.1:9222/devtools/page/owned"),
    ],
)
def test_page_websocket_url_binds_page_id_to_socket_target(
    monkeypatch: pytest.MonkeyPatch, target_id: object, websocket_url: str
) -> None:
    owned_url = "about:blank#browser-core-identity-run-1"
    target = {
        "id": target_id,
        "type": "page",
        "url": owned_url,
        "webSocketDebuggerUrl": websocket_url,
    }
    monkeypatch.setattr(cdp, "urlopen", lambda *_args, **_kwargs: Response([target]))
    with pytest.raises(ContractError, match="page target"):
        cdp._page_websocket_url("http://127.0.0.1:9222", owned_url, 0.1)


def test_page_websocket_url_rejects_duplicate_exact_targets(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    owned_url = "about:blank#browser-core-identity-run-1"
    targets = [
        {
            "type": "page",
            "url": owned_url,
            "webSocketDebuggerUrl": f"ws://127.0.0.1:9222/devtools/page/{index}",
        }
        for index in range(2)
    ]
    monkeypatch.setattr(cdp, "urlopen", lambda *_args, **_kwargs: Response(targets))

    with pytest.raises(ContractError, match="multiple page targets"):
        cdp._page_websocket_url("http://127.0.0.1:9222", owned_url, 0.1)
