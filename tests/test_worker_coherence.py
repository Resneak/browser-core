"""Worker-realm identity coherence — the cross-check the collector performs on us.

`akamai-web/knowledge/144` §4.1: the Akamai BM web collector builds a worker from a
Blob URL, re-reads nine `WorkerNavigator` identity fields inside it, and posts them
back for comparison. These tests pin that we measure the same thing honestly: a real
disagreement fails, a field the worker realm simply does not expose does not.
"""

from __future__ import annotations

import json
import http.server
import os
import socket
import shutil
import subprocess
import sys
import threading
import urllib.request
from pathlib import Path

import pytest

import browser_core.worker_coherence as worker_module
from browser_core.contracts import ContractError
from browser_core.local_http import MAX_HTTP_HEADER_BYTES
from browser_core.worker_coherence import (
    IDENTITY_FIELDS,
    WORKER_COHERENCE_SCHEMA,
    check_worker_realm_coherence,
    compare_realms,
)


def _identity(**overrides) -> dict:
    base = {
        "userAgent": "Mozilla/5.0 Chrome/153.0.0.0",
        "platform": "Win32",
        "language": "en-US",
        "languages": "en-US,en",
        "appVersion": "5.0 (Windows)",
        "hardwareConcurrency": 32,
        "deviceMemory": 8,
        "connection.effectiveType": "4g",
        "connection.rtt": 50,
        "userAgentData.platform": "Windows",
        "userAgentData.mobile": False,
    }
    base.update(overrides)
    return base


# ------------------------------------------------------------------ comparison


def test_identical_realms_are_coherent() -> None:
    result = compare_realms(_identity(), _identity())
    assert result["coherent"] is True
    assert result["mismatched_fields"] == []
    assert result["agreed"] == len(IDENTITY_FIELDS)


def test_main_thread_only_spoof_is_caught() -> None:
    """The exact failure the collector is looking for."""
    main = _identity(hardwareConcurrency=4, platform="Linux x86_64")
    worker = _identity()  # untouched worker realm still reports the host values
    result = compare_realms(main, worker)
    assert result["coherent"] is False
    assert sorted(result["mismatched_fields"]) == ["hardwareConcurrency", "platform"]
    assert result["fields"]["platform"]["status"] == "mismatch"
    assert result["fields"]["platform"]["main"] == "Linux x86_64"
    assert result["fields"]["platform"]["worker"] == "Win32"


def test_user_agent_mismatch_is_caught() -> None:
    result = compare_realms(_identity(userAgent="spoofed"), _identity())
    assert result["coherent"] is False
    assert result["mismatched_fields"] == ["userAgent"]


def test_field_absent_from_the_worker_realm_is_not_a_mismatch() -> None:
    """WorkerNavigator legitimately lacks some surfaces; that is not a lie."""
    worker = _identity()
    del worker["userAgentData.platform"]
    result = compare_realms(_identity(), worker)
    assert result["coherent"] is True
    assert "userAgentData.platform" in result["worker_absent_fields"]
    assert result["fields"]["userAgentData.platform"]["status"] == "worker_absent"
    assert result["compared"] == len(IDENTITY_FIELDS) - 1


def test_null_on_the_worker_side_only_is_treated_as_absent() -> None:
    result = compare_realms(_identity(), _identity(deviceMemory=None))
    assert result["coherent"] is True
    assert "deviceMemory" in result["worker_absent_fields"]


def test_both_null_agrees() -> None:
    result = compare_realms(_identity(deviceMemory=None), _identity(deviceMemory=None))
    assert result["fields"]["deviceMemory"]["status"] == "agree"
    assert result["coherent"] is True


def test_compare_rejects_non_objects() -> None:
    with pytest.raises(ContractError, match="must be an object"):
        compare_realms(_identity(), "nope")


def test_compare_rejects_unknown_or_unbounded_identity_fields() -> None:
    with pytest.raises(ContractError, match="fields are invalid"):
        compare_realms(_identity(extra="substituted"), _identity())
    with pytest.raises(ContractError, match="bounded safe text"):
        compare_realms(_identity(userAgent="x" * 4097), _identity())


@pytest.mark.parametrize("field", ["deviceMemory", "connection.rtt"])
def test_compare_rejects_huge_numeric_identity_fields(field: str) -> None:
    with pytest.raises(ContractError, match=field.replace(".", "\\.")):
        compare_realms(_identity(**{field: 10**400}), _identity())


def test_compare_bounds_identity_text_by_utf8_bytes() -> None:
    with pytest.raises(ContractError, match="bounded safe text"):
        compare_realms(_identity(userAgent="\U0001f642" * 2000), _identity())


def test_all_nine_observed_fields_are_covered() -> None:
    """The checklist must match what §4.1 actually recorded."""
    for name in (
        "userAgent",
        "platform",
        "language",
        "languages",
        "appVersion",
        "hardwareConcurrency",
        "deviceMemory",
    ):
        assert name in IDENTITY_FIELDS
    assert any(f.startswith("connection.") for f in IDENTITY_FIELDS)
    assert any(f.startswith("userAgentData.") for f in IDENTITY_FIELDS)


def test_repeated_worker_installation_remeasures_current_identity() -> None:
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node.js is unavailable")
    harness = """
const vm = require('node:vm');
const source = process.argv[1];
const window = {};
const navigator = {userAgent: 'first'};
let closed = 0;
let revoked = 0;
class SharedWorker {
  constructor() {
    const userAgent = navigator.userAgent;
    this.port = {
      start() { this.onmessage({data: {ok: true, id: {userAgent}}}); },
      close() { closed++; },
    };
  }
}
const context = {
  window, navigator, SharedWorker,
  Blob: class Blob {},
  URL: {createObjectURL: () => 'blob:worker', revokeObjectURL: () => {revoked++;}},
};
vm.runInNewContext(source, context);
const first = window.__bcMainIdentity.userAgent;
navigator.userAgent = 'second';
vm.runInNewContext(source, context);
const released = vm.runInNewContext(process.argv[2], context);
process.stdout.write(JSON.stringify({
  first,
  second: window.__bcMainIdentity.userAgent,
  worker: window.__bcWorkerCoherence.id.userAgent,
  released,
  cleanupGone: window.__bcWorkerCoherenceCleanup === null,
  closed,
  revoked,
}));
"""
    result = subprocess.run(
        [node, "-e", harness, worker_module._INSTALL_JS, worker_module._RELEASE_JS],
        capture_output=True,
        check=True,
        text=True,
        timeout=10,
    )
    observation = json.loads(result.stdout)
    assert observation == {
        "first": "first",
        "second": "second",
        "worker": "second",
        "released": True,
        "cleanupGone": True,
        "closed": 2,
        "revoked": 2,
    }


def test_worker_installation_releases_blob_url_when_both_constructors_fail() -> None:
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node.js is unavailable")
    harness = """
const vm = require('node:vm');
const window = {};
let revoked = 0;
class UnavailableWorker { constructor() { throw Error('unavailable'); } }
const context = {
  window,
  navigator: {userAgent: 'test'},
  SharedWorker: UnavailableWorker,
  Worker: UnavailableWorker,
  Blob: class Blob {},
  URL: {createObjectURL: () => 'blob:worker', revokeObjectURL: () => {revoked++;}},
};
vm.runInNewContext(process.argv[1], context);
process.stdout.write(JSON.stringify({
  kind: window.__bcWorkerKind,
  hasError: Boolean(window.__bcWorkerCoherenceError),
  revoked,
}));
"""
    result = subprocess.run(
        [node, "-e", harness, worker_module._INSTALL_JS],
        capture_output=True,
        check=True,
        text=True,
        timeout=10,
    )

    assert json.loads(result.stdout) == {"kind": None, "hasError": True, "revoked": 1}


# ------------------------------------------------------------------ session flow


def _session(tmp_path: Path, state: str = "active") -> Path:
    document = {
        "schema": "browser-core.session/1",
        "run_id": "core-20260805T070000Z-aaaaaaaa",
        "chromium_revision": "b" * 40,
        "pid": 42,
        "state": state,
        "created_at": "2026-08-05T07:00:00Z",
        "build": {
            "provenance": "attested-browser-core",
            "executable_sha256_16": "a" * 16,
        },
        "automation": {
            "transport": "cdp",
            "cdp_endpoint": "http://127.0.0.1:9333",
            "managed_target_url": "http://127.0.0.1:9333/inert",
        },
        "trace_mode": "off",
        "trace_categories": [],
        "trace_category_contract": "browser-core.trace-categories/2",
    }
    path = tmp_path / f"session-{state}.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


def _evaluator(worker_payload, *, kind="shared", error=None, main=None, delay=0):
    """Fake CDP evaluator: first call installs, later calls collect."""
    state = {"calls": 0}

    def evaluate(expression: str):
        state["calls"] += 1
        if "__bcWorkerCoherence !== undefined" in expression:
            return True
        ready = state["calls"] > delay + 1
        return json.dumps(
            {
                "main": main if main is not None else _identity(),
                "worker": worker_payload if ready else None,
                "kind": kind,
                "error": error,
            }
        )

    return evaluate


def test_coherent_session_reports_ok(tmp_path: Path) -> None:
    result = check_worker_realm_coherence(
        _session(tmp_path),
        evaluate=_evaluator({"ok": True, "id": _identity()}),
        sleep=lambda _s: None,
    )
    assert result["schema"] == WORKER_COHERENCE_SCHEMA
    assert result["status"] == "ok"
    assert result["coherent"] is True
    assert result["worker_coherence_claim_ready"] is False
    assert result["method"] == {
        "secure_loopback_origin": False,
        "shared_worker": True,
        "collector_equivalent": False,
    }
    assert result["worker_kind"] == "shared"
    assert result["session_run_id"] == "core-20260805T070000Z-aaaaaaaa"


@pytest.mark.parametrize("mutation", ["stopped", "replaced"])
def test_worker_coherence_rejects_session_change_during_collection(
    tmp_path: Path, mutation: str
) -> None:
    path = _session(tmp_path)
    original = path.read_bytes()
    retained = tmp_path / "retained-session.json"
    calls = 0

    def evaluate(_expression: str):
        nonlocal calls
        calls += 1
        if calls == 1:
            return True
        if mutation == "stopped":
            document = json.loads(path.read_text(encoding="utf-8"))
            document["state"] = "stopped"
            path.write_text(json.dumps(document), encoding="utf-8")
        else:
            path.rename(retained)
            path.write_bytes(original)
        return json.dumps(
            {
                "main": _identity(),
                "worker": {"ok": True, "id": _identity()},
                "kind": "shared",
                "error": None,
            }
        )

    with pytest.raises(ContractError, match="worker-realm coherence session changed"):
        check_worker_realm_coherence(path, evaluate=evaluate, sleep=lambda _s: None)

    assert calls == 2
    if mutation == "replaced":
        assert retained.read_bytes() == original
        assert path.read_bytes() == original
    else:
        assert json.loads(path.read_text(encoding="utf-8"))["state"] == "stopped"


@pytest.mark.skipif(os.name != "nt", reason="Windows directory junction boundary")
def test_worker_coherence_rejects_session_parent_junction_swap(
    tmp_path: Path
) -> None:
    probe_target = tmp_path / "probe-target"
    probe_target.mkdir()
    probe = tmp_path / "probe-junction"
    created = subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(probe), str(probe_target)],
        capture_output=True,
        check=False,
    )
    if created.returncode:
        pytest.skip("host could not create an unprivileged directory junction")
    probe.rmdir()

    sessions = tmp_path / "sessions"
    sessions.mkdir()
    path = _session(sessions)
    original = path.read_bytes()
    retained = tmp_path / "retained-sessions"
    calls = 0

    def evaluate(_expression: str):
        nonlocal calls
        calls += 1
        if calls == 1:
            return True
        sessions.rename(retained)
        linked = subprocess.run(
            ["cmd", "/c", "mklink", "/J", str(sessions), str(retained)],
            capture_output=True,
            check=False,
        )
        assert linked.returncode == 0
        return json.dumps(
            {
                "main": _identity(),
                "worker": {"ok": True, "id": _identity()},
                "kind": "shared",
                "error": None,
            }
        )

    try:
        with pytest.raises(ContractError, match="worker-realm coherence session changed"):
            check_worker_realm_coherence(path, evaluate=evaluate, sleep=lambda _s: None)
    finally:
        if sessions.exists():
            sessions.rmdir()

    assert calls == 2
    assert (retained / path.name).read_bytes() == original


@pytest.mark.parametrize(("kind", "claim_ready"), [("shared", True), ("dedicated", False)])
def test_live_loopback_claim_requires_the_shared_worker_path(
    monkeypatch, tmp_path: Path, kind: str, claim_ready: bool
) -> None:
    from browser_core import cdp

    loopback_url = "http://127.0.0.1:8123/"
    server_handle = (object(), object())
    monkeypatch.setattr(
        worker_module,
        "_serve_loopback_page",
        lambda: (server_handle, loopback_url),
    )

    def evaluate(_endpoint, expression, *, target_url, timeout_seconds):  # noqa: ANN001
        if expression == worker_module._COLLECT_JS:
            return json.dumps(
                {
                    "main": _identity(),
                    "worker": {"ok": True, "id": _identity()},
                    "kind": kind,
                    "error": None,
                }
            )
        return True

    monkeypatch.setattr(cdp, "evaluate_page_expression", evaluate)
    monkeypatch.setattr(cdp, "navigate_managed_page", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(cdp, "wait_for_page_target", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(worker_module, "_stop_loopback_page", lambda _handle: [])

    result = check_worker_realm_coherence(_session(tmp_path))

    assert result["coherent"] is True
    assert result["origin_kind"] == "loopback-secure-origin"
    assert result["worker_kind"] == kind
    assert result["method"]["collector_equivalent"] is claim_ready
    assert result["worker_coherence_claim_ready"] is claim_ready


def test_incoherent_session_reports_the_fields(tmp_path: Path) -> None:
    result = check_worker_realm_coherence(
        _session(tmp_path),
        evaluate=_evaluator(
            {"ok": True, "id": _identity()}, main=_identity(hardwareConcurrency=2)
        ),
        sleep=lambda _s: None,
    )
    assert result["coherent"] is False
    assert result["mismatched_fields"] == ["hardwareConcurrency"]


def test_worker_result_arriving_late_is_still_collected(tmp_path: Path) -> None:
    result = check_worker_realm_coherence(
        _session(tmp_path),
        evaluate=_evaluator({"ok": True, "id": _identity()}, delay=3),
        sleep=lambda _s: None,
    )
    assert result["status"] == "ok"
    assert result["poll_attempts"] > 1


def test_worker_that_never_reports_is_unavailable_not_coherent(tmp_path: Path) -> None:
    """Never claim coherence we did not observe."""
    result = check_worker_realm_coherence(
        _session(tmp_path),
        evaluate=_evaluator(None),
        attempts=3,
        sleep=lambda _s: None,
    )
    assert result["status"] == "unavailable"
    assert result["coherent"] is None
    assert result["worker_coherence_claim_ready"] is False


def test_worker_construction_error_is_surfaced(tmp_path: Path) -> None:
    private = "SecurityError: private-worker-value"
    result = check_worker_realm_coherence(
        _session(tmp_path),
        evaluate=_evaluator(None, kind=None, error=private),
        attempts=3,
        sleep=lambda _s: None,
    )
    assert result["status"] == "unavailable"
    assert result["coherent"] is None
    assert result["error"] == "worker-construction-failed"
    assert private not in json.dumps(result)
    assert result["error_digest"].startswith("sha256:")


def test_worker_internal_failure_is_unavailable(tmp_path: Path) -> None:
    private = "TypeError in private worker"
    result = check_worker_realm_coherence(
        _session(tmp_path),
        evaluate=_evaluator({"ok": False, "error": private}),
        sleep=lambda _s: None,
    )
    assert result["status"] == "unavailable"
    assert result["error"] == "worker-observation-failed"
    assert private not in json.dumps(result)


def test_worker_failure_requires_a_nonempty_error(tmp_path: Path) -> None:
    with pytest.raises(ContractError, match="failure is invalid"):
        check_worker_realm_coherence(
            _session(tmp_path),
            evaluate=_evaluator({"ok": False, "error": ""}),
            sleep=lambda _s: None,
        )


def test_worker_error_receipt_rejects_surrogate_text(tmp_path: Path) -> None:
    with pytest.raises(ContractError, match="worker observation"):
        check_worker_realm_coherence(
            _session(tmp_path),
            evaluate=_evaluator(None, kind=None, error="\ud800"),
            sleep=lambda _s: None,
        )


@pytest.mark.parametrize(
    ("kind", "worker", "error"),
    [
        ([], {"ok": True, "id": _identity()}, None),
        (None, {"ok": True, "id": _identity()}, None),
        ("shared", {"ok": True, "id": _identity()}, "construction failed"),
    ],
)
def test_worker_observation_rejects_incoherent_status(
    tmp_path: Path, kind, worker, error
) -> None:
    with pytest.raises(ContractError, match="worker observation"):
        check_worker_realm_coherence(
            _session(tmp_path),
            evaluate=_evaluator(worker, kind=kind, error=error),
            sleep=lambda _seconds: None,
        )


def test_worker_observation_refuses_duplicate_or_unknown_fields(tmp_path: Path) -> None:
    replies = iter(
        [
            True,
            '{"main":null,"worker":null,"kind":"shared","kind":"dedicated","error":null}',
        ]
    )
    with pytest.raises(ContractError, match="duplicate key"):
        check_worker_realm_coherence(
            _session(tmp_path),
            evaluate=lambda _expression: next(replies),
            sleep=lambda _s: None,
        )

    malformed = _evaluator({"ok": True, "id": _identity(extra="substituted")})
    with pytest.raises(ContractError, match="fields are invalid"):
        check_worker_realm_coherence(
            _session(tmp_path), evaluate=malformed, sleep=lambda _s: None
        )


@pytest.mark.parametrize(
    ("keyword", "value", "message"),
    [
        ("session_path", "session.json", "must be a Path"),
        ("timeout_seconds", float("inf"), "timeout is invalid"),
        ("timeout_seconds", 10**400, "timeout is invalid"),
        ("attempts", True, "attempts are invalid"),
        ("interval_seconds", -1, "interval is invalid"),
        ("interval_seconds", 10**400, "interval is invalid"),
        ("use_loopback_page", 1, "must be boolean"),
    ],
)
def test_worker_check_rejects_invalid_public_arguments(
    tmp_path: Path, keyword: str, value, message: str
) -> None:
    arguments = {
        "session_path": _session(tmp_path),
        "evaluate": _evaluator(None),
        "sleep": lambda _s: None,
    }
    arguments[keyword] = value
    with pytest.raises(ContractError, match=message):
        check_worker_realm_coherence(**arguments)


@pytest.mark.parametrize(
    ("keyword", "value", "message"),
    [
        ("evaluate", [], "evaluator must be callable"),
        ("sleep", {}, "sleeper must be callable"),
    ],
)
def test_worker_callbacks_reject_before_session_load(
    monkeypatch,
    keyword,
    value,
    message,
) -> None:
    contacted = False

    def forbidden_load(_path):
        nonlocal contacted
        contacted = True
        raise AssertionError("session load")

    monkeypatch.setattr(worker_module, "load_session_snapshot", forbidden_load)
    arguments = {"session_path": Path("session.json"), keyword: value}
    with pytest.raises(ContractError, match=message):
        check_worker_realm_coherence(**arguments)
    assert contacted is False


def test_worker_polling_spends_one_shared_deadline(monkeypatch, tmp_path: Path) -> None:
    clock = [10.0]
    calls = []
    sleeps = []
    monkeypatch.setattr(worker_module.time, "monotonic", lambda: clock[0])

    def evaluate(expression):  # noqa: ANN001
        calls.append(expression)
        clock[0] += 0.2
        if "__bcWorkerCoherence !== undefined" in expression:
            return True
        return json.dumps(
            {"main": _identity(), "worker": None, "kind": "shared", "error": None}
        )

    def sleep(delay):  # noqa: ANN001
        sleeps.append(delay)
        clock[0] += delay

    with pytest.raises(ContractError, match="timed out"):
        check_worker_realm_coherence(
            _session(tmp_path),
            timeout_seconds=0.5,
            attempts=1000,
            interval_seconds=10,
            evaluate=evaluate,
            sleep=sleep,
        )
    assert len(calls) == 2
    assert sleeps == pytest.approx([0.1])


def test_worker_installation_requires_literal_acknowledgement(tmp_path: Path) -> None:
    with pytest.raises(ContractError, match="installation was not acknowledged"):
        check_worker_realm_coherence(
            _session(tmp_path),
            evaluate=lambda _expression: 1,
            sleep=lambda _seconds: None,
        )


def test_partial_loopback_navigation_is_restored_and_server_stopped(
    monkeypatch,
    tmp_path: Path,
) -> None:
    from browser_core import cdp

    managed_url = "http://127.0.0.1:9333/inert"
    loopback_url = "http://127.0.0.1:8123/"
    events = []
    server_handle = (object(), object())
    monkeypatch.setattr(
        worker_module,
        "_serve_loopback_page",
        lambda: (server_handle, loopback_url),
    )

    def evaluate(_endpoint, expression, *, target_url, timeout_seconds):  # noqa: ANN001
        events.append(("evaluate", target_url, expression, timeout_seconds))
        if expression == worker_module._COLLECT_JS:
            return json.dumps(
                {
                    "main": _identity(),
                    "worker": {"ok": True, "id": _identity()},
                    "kind": "shared",
                    "error": None,
                }
            )
        return True

    monkeypatch.setattr(cdp, "evaluate_page_expression", evaluate)
    def navigate(_endpoint, destination, *, current_target_url, timeout_seconds):  # noqa: ANN001
        events.append(("navigate", current_target_url, destination, timeout_seconds))
        return True

    monkeypatch.setattr(cdp, "navigate_managed_page", navigate)
    monkeypatch.setattr(
        cdp,
        "wait_for_page_target",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(ContractError("not ready")),
    )

    def stop(handle):  # noqa: ANN001
        events.append(("stop", handle))
        return []

    monkeypatch.setattr(worker_module, "_stop_loopback_page", stop)
    result = check_worker_realm_coherence(_session(tmp_path))
    assert result["status"] == "ok"
    assert result["coherent"] is True
    assert result["origin_kind"] == "managed-data-url"
    assert result["method"]["collector_equivalent"] is False
    assert result["worker_coherence_claim_ready"] is False
    restore = [event for event in events if event[0] == "navigate" and event[2] == managed_url]
    assert restore[-1][1] == loopback_url
    assert events[-1] == ("stop", server_handle)


@pytest.mark.parametrize("release_acknowledged", [True, False])
def test_worker_check_releases_installed_worker_on_managed_page(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, release_acknowledged: bool
) -> None:
    from browser_core import cdp

    expressions: list[str] = []

    def evaluate(_endpoint, expression, *, target_url, timeout_seconds):  # noqa: ANN001
        expressions.append(expression)
        assert target_url.endswith("/inert")
        assert timeout_seconds > 0
        if expression == worker_module._COLLECT_JS:
            return json.dumps(
                {
                    "main": _identity(),
                    "worker": {"ok": True, "id": _identity()},
                    "kind": "shared",
                    "error": None,
                }
            )
        if "__bcWorkerCoherenceCleanup" in expression and expression != worker_module._INSTALL_JS:
            assert timeout_seconds <= worker_module.WORKER_CLEANUP_TIMEOUT_SECONDS
            return release_acknowledged
        return True

    monkeypatch.setattr(cdp, "evaluate_page_expression", evaluate)
    if release_acknowledged:
        result = check_worker_realm_coherence(
            _session(tmp_path), use_loopback_page=False
        )
        assert result["status"] == "ok"
    else:
        with pytest.raises(ContractError, match=r"cleanup failed \(worker-release\)"):
            check_worker_realm_coherence(_session(tmp_path), use_loopback_page=False)
    assert any("__bcWorkerCoherenceCleanup" in expression for expression in expressions[2:])


def test_worker_check_releases_worker_after_poll_failure(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from browser_core import cdp

    expressions: list[str] = []

    def evaluate(_endpoint, expression, *, target_url, timeout_seconds):  # noqa: ANN001
        expressions.append(expression)
        if expression == worker_module._COLLECT_JS:
            raise ContractError("synthetic poll failure")
        return True

    monkeypatch.setattr(cdp, "evaluate_page_expression", evaluate)
    with pytest.raises(ContractError, match="synthetic poll failure"):
        check_worker_realm_coherence(_session(tmp_path), use_loopback_page=False)
    assert expressions[-1] == worker_module._RELEASE_JS


def test_worker_cleanup_failure_blocks_success_after_all_phases(
    monkeypatch,
    tmp_path: Path,
) -> None:
    from browser_core import cdp

    loopback_url = "http://127.0.0.1:8123/"
    server_handle = (object(), object())
    stopped = False
    measurement_finished = False
    monkeypatch.setattr(
        worker_module,
        "_serve_loopback_page",
        lambda: (server_handle, loopback_url),
    )

    def evaluate(_endpoint, expression, *, target_url, timeout_seconds):  # noqa: ANN001
        nonlocal measurement_finished
        if expression == worker_module._COLLECT_JS:
            measurement_finished = True
            return json.dumps(
                {
                    "main": _identity(),
                    "worker": {"ok": True, "id": _identity()},
                    "kind": "shared",
                    "error": None,
                }
            )
        if measurement_finished:
            raise ContractError("private-restore")
        if expression == worker_module._INSTALL_JS or target_url.endswith("/inert"):
            return True
        return True

    monkeypatch.setattr(cdp, "evaluate_page_expression", evaluate)
    navigate_calls = 0

    def navigate(*_args, **_kwargs):
        nonlocal navigate_calls
        navigate_calls += 1
        if navigate_calls > 1:
            raise ContractError("private-restore")
        return True

    monkeypatch.setattr(cdp, "navigate_managed_page", navigate)
    monkeypatch.setattr(cdp, "wait_for_page_target", lambda *_args, **_kwargs: None)

    def stop(_handle):
        nonlocal stopped
        stopped = True
        return ["server-close"]

    monkeypatch.setattr(worker_module, "_stop_loopback_page", stop)
    with pytest.raises(
        ContractError,
        match=r"cleanup failed \(worker-release,page-restore,server-close\)",
    ) as failure:
        check_worker_realm_coherence(_session(tmp_path))
    assert "private-restore" not in str(failure.value)
    assert stopped is True


def test_worker_server_shutdown_closes_accepted_keepalive_client() -> None:
    handle, _url = worker_module._serve_loopback_page()
    server, _thread = handle
    stopped = False
    try:
        with socket.create_connection(server.server_address, timeout=2) as client:
            client.settimeout(2)
            client.sendall(b'GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n')
            response = b''
            body = worker_module._LOOPBACK_HTML.encode('utf-8')
            while body not in response:
                part = client.recv(4096)
                assert part
                response += part
            assert b'HTTP/1.1 200 OK' in response
            assert worker_module._stop_loopback_page(handle) == []
            stopped = True
            client.settimeout(0.2)
            assert client.recv(1) == b''
    finally:
        if not stopped:
            worker_module._stop_loopback_page(handle)


def test_worker_server_rejects_aggregate_oversized_request_headers() -> None:
    handle, _url = worker_module._serve_loopback_page()
    server, _thread = handle
    request = (
        b'GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n'
        + b''.join(
            f'X-Pad-{index:03d}: '.encode() + b'a' * 900 + b'\r\n'
            for index in range(80)
        )
        + b'\r\n'
    )
    assert len(request) > MAX_HTTP_HEADER_BYTES
    try:
        with socket.create_connection(server.server_address, timeout=2) as client:
            client.settimeout(2)
            try:
                client.sendall(request)
            except (BrokenPipeError, ConnectionResetError):
                pass
            response = bytearray()
            while b'HTTP/1.1 200 OK' not in response:
                try:
                    chunk = client.recv(4096)
                except ConnectionResetError:
                    break
                if not chunk:
                    break
                response.extend(chunk)
            assert b'HTTP/1.1 200 OK' not in response
    finally:
        worker_module._stop_loopback_page(handle)


def test_worker_server_suppresses_expected_peer_disconnect_errors(monkeypatch) -> None:
    seen = []
    monkeypatch.setattr(
        http.server.ThreadingHTTPServer, 'handle_error',
        lambda self, request, address: seen.append(type(sys.exc_info()[1])),
    )
    handle, _url = worker_module._serve_loopback_page()
    server, _thread = handle
    try:
        for error in (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
            try:
                raise error('peer disconnected')
            except error:
                server.handle_error(None, ('127.0.0.1', 1))
        assert seen == []
        try:
            raise ValueError('unexpected server error')
        except ValueError:
            server.handle_error(None, ('127.0.0.1', 1))
        assert seen == [ValueError]
    finally:
        worker_module._stop_loopback_page(handle)


def test_worker_server_stop_continues_after_shutdown_failure() -> None:
    events = []

    class Server:
        def shutdown(self):
            events.append("shutdown")
            raise OSError("private-shutdown")

        def server_close(self):
            events.append("close")

    class ServerThread:
        def join(self, *, timeout):
            events.append(("join", timeout))

        def is_alive(self):
            return False

    failures = worker_module._stop_loopback_page((Server(), ServerThread()))
    assert failures == ["server-shutdown"]
    assert events == [
        "shutdown",
        "close",
        ("join", worker_module.WORKER_CLEANUP_TIMEOUT_SECONDS),
    ]


def test_worker_server_reclaims_shutdown_thread_after_late_start_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    release = threading.Event()
    threads: list[object] = []
    real_thread = threading.Thread

    class Server:
        closed = False

        def shutdown(self) -> None:
            release.wait(1)

        def server_close(self) -> None:
            self.closed = True
            release.set()

    class ShutdownThread:
        joined = False

        def __init__(self, *, target, name, daemon):  # noqa: ANN001
            self.worker = real_thread(target=target, name=name, daemon=daemon)
            threads.append(self)

        def start(self) -> None:
            self.worker.start()
            raise RuntimeError("late start error")

        def is_alive(self) -> bool:
            return self.worker.is_alive()

        def join(self, *, timeout: float) -> None:
            self.joined = True
            self.worker.join(timeout=timeout)

    class Worker:
        joined = False

        def join(self, *, timeout: float) -> None:
            self.joined = True

        def is_alive(self) -> bool:
            return not self.joined

    monkeypatch.setattr(threading, "Thread", ShutdownThread)
    monkeypatch.setattr(worker_module, "WORKER_CLEANUP_TIMEOUT_SECONDS", 0.1)
    server = Server()
    worker = Worker()
    failures = worker_module._stop_loopback_page((server, worker))

    assert failures == ["server-shutdown"]
    assert server.closed is True
    assert worker.joined is True
    assert threads[0].joined is True
    assert threads[0].is_alive() is False


def test_worker_loopback_start_error_reclaims_live_server_thread(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    started = threading.Event()
    released = threading.Event()
    events: list[str] = []
    workers: list[object] = []
    real_thread = threading.Thread

    class Server:
        server_port = 8123

        def __init__(self, _address, _handler):  # noqa: ANN001
            pass

        def serve_forever(self) -> None:
            started.set()
            released.wait(2)

        def shutdown(self) -> None:
            events.append("shutdown")
            released.set()

        def server_close(self) -> None:
            events.append("close")

    class LateStartThread:
        def __init__(self, *, target, name, daemon):  # noqa: ANN001
            self.worker = real_thread(target=target, name=name, daemon=daemon)
            workers.append(self)

        def start(self) -> None:
            self.worker.start()
            assert started.wait(1)
            raise RuntimeError("start raised after launching the thread")

        def is_alive(self) -> bool:
            return self.worker.is_alive()

        def join(self, *, timeout: float) -> None:
            events.append("join")
            self.worker.join(timeout=timeout)

    def make_thread(*, target, name, daemon):  # noqa: ANN001
        if name == "browser-core-worker-coherence":
            return LateStartThread(target=target, name=name, daemon=daemon)
        return real_thread(target=target, name=name, daemon=daemon)

    with monkeypatch.context() as patched:
        patched.setattr(http.server, "ThreadingHTTPServer", Server)
        patched.setattr(threading, "Thread", make_thread)
        try:
            with pytest.raises(ContractError, match="worker loopback server could not start"):
                worker_module._serve_loopback_page()
            alive_on_return = workers[0].is_alive()
        finally:
            released.set()
            if workers:
                workers[0].worker.join(timeout=1)

    assert events == ["shutdown", "close", "join"]
    assert alive_on_return is False


def test_worker_loopback_server_real_lifecycle() -> None:
    server_handle, url = worker_module._serve_loopback_page()
    try:
        with urllib.request.urlopen(url, timeout=2) as response:
            body = response.read(4096)
        assert response.status == 200
        assert worker_module.LOOPBACK_PAGE_TITLE.encode("ascii") in body
    finally:
        failures = worker_module._stop_loopback_page(server_handle)
    assert failures == []
    assert server_handle[1].is_alive() is False


def test_stopped_session_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(ContractError, match="requires an active session"):
        check_worker_realm_coherence(_session(tmp_path, state="stopped"))
