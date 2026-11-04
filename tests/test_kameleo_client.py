from __future__ import annotations

import io
import json
import os
import threading
import urllib.error
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace

import pytest

import scripts.run_alternating_kameleo as kameleo
from browser_core.contracts import ContractError
from browser_eval.redact import redact_obj


class _Parser:
    def __init__(self, args: SimpleNamespace) -> None:
        self.args = args

    def parse_args(self) -> SimpleNamespace:
        return self.args


class _Response:
    def __init__(self, body: bytes, *, status: int = 200) -> None:
        self.body = body
        self.status = status
        self.requested: int | None = None
        self.closed = False

    def __enter__(self):
        return self

    def __exit__(self, *args: object) -> None:
        return None

    def close(self) -> None:
        self.closed = True

    def getcode(self) -> int:
        return self.status

    def read(self, maximum: int) -> bytes:
        self.requested = maximum
        return self.body[:maximum]


def _controlled_summary() -> dict[str, object]:
    return {
        "evaluators": [
            {
                "id": "controlled_coherence",
                "status": "ok",
                "verdict": "pass",
                "signals": {
                    "collector_checkset_sha256_16": "a" * 16,
                    "passed_checks": 60,
                    "failed_checks": 0,
                    "unavailable_checks": 2,
                    "render_fingerprint": "b" * 16,
                    "surface_fingerprint": "c" * 16,
                    "automation_fingerprint": "d" * 16,
                    "private": "must not enter the cohort report",
                },
            }
        ]
    }


def _stopped_receipt(run_id: str = "owned-core-run") -> dict[str, object]:
    return {
        "run_id": run_id,
        "state": "stopped",
        "running": False,
        "identity_protected": True,
    }


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("status", "error"),
        ("failed_checks", 1),
        ("passed_checks", 0),
        ("identity_failed_claims", 1),
    ],
)
def test_kameleo_result_vector_rejects_a_pass_without_complete_signals(
    field: str, value: object
) -> None:
    summary = _controlled_summary()
    row = summary["evaluators"][0]
    if field == "identity_failed_claims":
        row["signals"].update(
            identity_contract_sha256_16="e" * 16,
            identity_passed_claims=1,
            identity_failed_claims=0,
            identity_unavailable_claims=0,
        )
    if field == "status":
        row[field] = value
    else:
        row["signals"][field] = value
    with pytest.raises(ContractError, match="controlled evaluator"):
        kameleo.result_vector(summary)


def test_kameleo_client_closes_http_error_response(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    response = io.BytesIO(b"rejected")
    error = urllib.error.HTTPError(
        "http://127.0.0.1:5050/profiles",
        503,
        "unavailable",
        {},
        response,
    )

    def reject(*_args: object, **_kwargs: object) -> None:
        raise error

    monkeypatch.setattr(kameleo, "_open_kameleo_request", reject)
    with pytest.raises(RuntimeError, match=r"Kameleo GET /profiles returned HTTP 503"):
        kameleo.KameleoLocal("http://127.0.0.1:5050").request("GET", "/profiles")
    assert response.closed


def test_kameleo_local_api_request_does_not_follow_redirect_to_another_listener() -> None:
    target_hits: list[str] = []

    class Target(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            target_hits.append(self.path)
            self.send_response(200)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"{}")

        def log_message(self, *_args: object) -> None:
            pass

    target = ThreadingHTTPServer(("127.0.0.1", 0), Target)

    class Redirect(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            self.send_response(302)
            self.send_header(
                "Location", f"http://127.0.0.1:{target.server_port}/profiles"
            )
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, *_args: object) -> None:
            pass

    source = ThreadingHTTPServer(("127.0.0.1", 0), Redirect)
    source_thread = threading.Thread(target=source.serve_forever, daemon=True)
    target_thread = threading.Thread(target=target.serve_forever, daemon=True)
    source_thread.start()
    target_thread.start()
    try:
        with pytest.raises(RuntimeError, match="HTTP 302"):
            kameleo.KameleoLocal(f"http://127.0.0.1:{source.server_port}").request(
                "GET", "/profiles"
            )
        assert target_hits == []
    finally:
        source.shutdown()
        target.shutdown()
        source.server_close()
        target.server_close()
        source_thread.join(timeout=2)
        target_thread.join(timeout=2)


def test_kameleo_client_owns_response_without_entering_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class EnterRejectingResponse(_Response):
        def __enter__(self):
            raise AssertionError("implicit response context must not be entered")

    response = EnterRejectingResponse(b"{}")
    monkeypatch.setattr(
        kameleo,
        "_open_kameleo_request",
        lambda *_args, **_kwargs: response,
    )
    assert (
        kameleo.KameleoLocal("http://127.0.0.1:5050").request("GET", "/profiles") == {}
    )
    assert response.closed is True


def test_kameleo_client_close_failure_blocks_valid_response(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class CloseFailingResponse(_Response):
        def close(self) -> None:
            raise OSError("private Kameleo close diagnostic")

    monkeypatch.setattr(
        kameleo,
        "_open_kameleo_request",
        lambda *_args, **_kwargs: CloseFailingResponse(b"{}"),
    )
    with pytest.raises(ContractError) as raised:
        kameleo.KameleoLocal("http://127.0.0.1:5050").request("GET", "/profiles")
    assert str(raised.value) == "Kameleo response cleanup failed (response-close)"
    assert raised.value.__cause__ is None
    assert "private" not in str(raised.value)


def test_kameleo_client_cleanup_failure_retains_only_safe_read_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class ReadCloseFailingResponse(_Response):
        def read(self, _maximum: int) -> bytes:
            raise OSError("private Kameleo read diagnostic")

        def close(self) -> None:
            raise RuntimeError("private Kameleo close diagnostic")

    monkeypatch.setattr(
        kameleo,
        "_open_kameleo_request",
        lambda *_args, **_kwargs: ReadCloseFailingResponse(b""),
    )
    with pytest.raises(ContractError) as raised:
        kameleo.KameleoLocal("http://127.0.0.1:5050").request("GET", "/profiles")
    assert str(raised.value) == "Kameleo response cleanup failed (response-close)"
    assert isinstance(raised.value.__cause__, RuntimeError)
    assert str(raised.value.__cause__) == "Kameleo GET request failed (OSError)"
    assert "private" not in str(raised.value)


def test_kameleo_client_http_error_close_failure_is_fixed_shape(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class CloseFailingHTTPError(urllib.error.HTTPError):
        def close(self) -> None:
            raise ValueError("private rejected response close diagnostic")

    error = CloseFailingHTTPError(
        "http://127.0.0.1:5050/profiles",
        503,
        "private unavailable",
        {},
        io.BytesIO(b"private rejected body"),
    )

    def reject(*_args: object, **_kwargs: object) -> None:
        raise error

    monkeypatch.setattr(kameleo, "_open_kameleo_request", reject)
    with pytest.raises(ContractError) as raised:
        kameleo.KameleoLocal("http://127.0.0.1:5050").request("GET", "/profiles")
    assert str(raised.value) == "Kameleo response cleanup failed (response-close)"
    assert isinstance(raised.value.__cause__, RuntimeError)
    assert str(raised.value.__cause__) == "Kameleo GET /profiles returned HTTP 503"
    assert "private" not in str(raised.value)


@pytest.mark.parametrize(
    "url",
    [
        "https://127.0.0.1:5050",
        "http://example.com:5050",
        "http://user@127.0.0.1:5050",
        "http://@127.0.0.1:5050",
        "http://127.0.0.1:5050/api",
        "http://127.0.0.1:5050?query=yes",
        "http://127.0.0.1",
        "http://[::1]:0",
    ],
)
def test_kameleo_client_requires_exact_loopback_origin(url: str) -> None:
    with pytest.raises(ContractError, match="loopback"):
        kameleo.KameleoLocal(url)


def test_kameleo_client_normalizes_localhost_before_transport() -> None:
    assert kameleo.KameleoLocal("http://localhost:5050").base_url == (
        "http://127.0.0.1:5050"
    )
    assert kameleo.parser().get_default("kameleo_api") == "http://127.0.0.1:5050"


@pytest.mark.parametrize("host", ["localhost", "example.com"])
def test_kameleo_transport_refuses_plain_http_hostname_before_contact(
    monkeypatch: pytest.MonkeyPatch, host: str
) -> None:
    monkeypatch.setattr(
        kameleo.urllib.request,
        "build_opener",
        lambda *_args: pytest.fail("hostname reached transport construction"),
    )
    request = kameleo.urllib.request.Request(f"http://{host}:5050/profiles")
    with pytest.raises(ContractError, match="literal loopback"):
        kameleo._open_kameleo_request(request, timeout=1.0)


@pytest.mark.parametrize(
    ("method", "path", "payload", "timeout"),
    [
        ("PATCH", "/profiles", None, 1),
        ("GET", "//example.com/profiles", None, 1),
        ("GET", "/profiles#fragment", None, 1),
        ("GET", "/profiles", {"body": True}, 1),
        ("POST", "/profiles", {"value": float("nan")}, 1),
        ("GET", "/profiles", None, True),
        ("GET", "/profiles", None, 61),
        pytest.param("GET", "/profiles", None, 10**10_000, id="huge-timeout"),
    ],
)
def test_kameleo_request_rejects_invalid_controls_before_contact(
    method: str,
    path: str,
    payload: object,
    timeout: object,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        kameleo,
        "_open_kameleo_request",
        lambda *_args, **_kwargs: pytest.fail("invalid request reached API contact"),
    )
    with pytest.raises(ContractError):
        kameleo.KameleoLocal("http://127.0.0.1:5050").request(
            method,
            path,
            payload,
            timeout_seconds=timeout,  # type: ignore[arg-type]
        )


def test_kameleo_request_rejects_extreme_payload_nesting_before_contact(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        kameleo,
        "_open_kameleo_request",
        lambda *_args, **_kwargs: pytest.fail("invalid request reached API contact"),
    )
    deeply_nested: object = 0
    for _ in range(2_000):
        deeply_nested = [deeply_nested]

    with pytest.raises(ContractError, match="strict JSON"):
        kameleo.KameleoLocal("http://127.0.0.1:5050").request(
            "POST",
            "/profiles",
            {"value": deeply_nested},
        )


@pytest.mark.parametrize(
    ("body", "status", "match"),
    [
        (b'{"id":"one","id":"two"}', 200, "strict JSON"),
        (b'{"value":NaN}', 200, "strict JSON"),
        (b'{"value":1e400}', 200, "strict JSON"),
        (b"{}", 300, "unexpected status"),
    ],
)
def test_kameleo_request_rejects_ambiguous_responses(
    body: bytes,
    status: int,
    match: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    response = _Response(body, status=status)
    monkeypatch.setattr(
        kameleo, "_open_kameleo_request", lambda *_args, **_kwargs: response
    )
    with pytest.raises((ContractError, RuntimeError), match=match):
        kameleo.KameleoLocal("http://127.0.0.1:5050").request("GET", "/profiles")


def test_kameleo_request_reads_one_byte_past_response_limit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    response = _Response(b"x" * (kameleo.MAX_KAMELEO_RESPONSE_BYTES + 1))
    monkeypatch.setattr(
        kameleo, "_open_kameleo_request", lambda *_args, **_kwargs: response
    )
    with pytest.raises(ContractError, match="too large"):
        kameleo.KameleoLocal("http://127.0.0.1:5050").request("GET", "/profiles")
    assert response.requested == kameleo.MAX_KAMELEO_RESPONSE_BYTES + 1


def test_kameleo_response_read_uses_one_deadline_across_short_chunks(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    elapsed = [10.0]

    class SlowResponse(_Response):
        def __init__(self) -> None:
            super().__init__(b"[]")
            self.offset = 0

        def read(self, _maximum: int) -> bytes:
            pytest.fail("blocking response read was used")

        def read1(self, maximum: int) -> bytes:
            elapsed[0] += 0.06
            block = self.body[self.offset : self.offset + min(maximum, 1)]
            self.offset += len(block)
            return block

    response = SlowResponse()
    monkeypatch.setattr(kameleo.time, "monotonic", lambda: elapsed[0])
    monkeypatch.setattr(
        kameleo, "_open_kameleo_request", lambda *_args, **_kwargs: response
    )
    with pytest.raises(ContractError, match="response deadline"):
        kameleo.KameleoLocal("http://127.0.0.1:5050").request(
            "GET", "/profiles", timeout_seconds=0.1
        )
    assert response.closed


def test_kameleo_fingerprint_and_profile_ids_are_path_safe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = kameleo.KameleoLocal("http://127.0.0.1:5050")
    monkeypatch.setattr(
        client, "request", lambda *_args, **_kwargs: [{"id": "../escape"}]
    )
    with pytest.raises(ContractError, match="fingerprint ID"):
        client.fresh_fingerprint("151")
    with pytest.raises(ContractError, match="profile ID"):
        client.playwright_endpoint("profile/escape")


def test_kameleo_profile_creation_binds_the_returned_name(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = kameleo.KameleoLocal("http://127.0.0.1:5050")
    monkeypatch.setattr(
        client,
        "request",
        lambda *_args, **_kwargs: {"id": "profile-1", "name": "someone else's profile"},
    )
    with pytest.raises(RuntimeError, match="invalid profile"):
        client.create_disposable(
            "fingerprint-1", f"{kameleo.KAMELEO_NAME_PREFIX} owned"
        )


def test_kameleo_fingerprint_vector_is_a_closed_typed_projection() -> None:
    vector = kameleo._fingerprint_vector(
        {
            "id": "fingerprint-1",
            "browser": {
                "major": 151,
                "product": "chrome",
                "version": "151.0.7922.72",
                "private": "not retained",
            },
            "os": {
                "family": "windows",
                "platform": "Win32",
                "version": "11.0",
                "private": "not retained",
            },
        },
        expected_major="151",
    )
    assert vector == {
        "browser": {"major": 151, "product": "chrome", "version": "151.0.7922.72"},
        "os": {"family": "windows", "platform": "Win32", "version": "11.0"},
    }


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("major", True),
        ("major", 150),
        ("product", "firefox"),
        ("version", "151-current"),
    ],
)
def test_kameleo_fingerprint_vector_rejects_mismatched_browser(
    field: str,
    value: object,
) -> None:
    fingerprint = {
        "browser": {"major": 151, "product": "chrome", "version": "151.0.7922.72"},
        "os": {"family": "windows", "platform": "Win32", "version": "11.0"},
    }
    fingerprint["browser"][field] = value
    with pytest.raises(ContractError, match="fingerprint evidence"):
        kameleo._fingerprint_vector(fingerprint, expected_major="151")


def _client(
    monkeypatch: pytest.MonkeyPatch, cleanup: list[tuple[str, str]]
) -> kameleo.KameleoLocal:
    client = kameleo.KameleoLocal("http://127.0.0.1:5050")
    monkeypatch.setattr(
        client,
        "fresh_fingerprint",
        lambda _version: {
            "id": "fingerprint-1",
            "browser": {"major": 151, "product": "chrome", "version": "151.0.7922.72"},
            "os": {"family": "windows", "platform": "Win32", "version": "11.0"},
        },
    )
    monkeypatch.setattr(
        client,
        "create_disposable",
        lambda fingerprint_id, name: {"id": "profile-1", "name": name},
    )
    monkeypatch.setattr(
        client,
        "cleanup_disposable",
        lambda profile_id, expected_name: cleanup.append((profile_id, expected_name)),
    )
    return client


def test_kameleo_trial_cleans_profile_when_recovery_publication_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cleanup: list[tuple[str, str]] = []
    client = _client(monkeypatch, cleanup)
    output = tmp_path / "runs" / "trial"
    recovery = output.parent / "disposables" / "profile-1.json"
    recovery.parent.mkdir(parents=True)
    recovery.write_bytes(b"foreign recovery record")
    with pytest.raises(ContractError):
        kameleo.run_kameleo_trial(
            client,
            "151",
            "cohort-1",
            1,
            output,
            "controlled_coherence",
        )
    assert cleanup and cleanup[0][0] == "profile-1"
    assert recovery.read_bytes() == b"foreign recovery record"


def test_kameleo_trial_cleans_profile_when_endpoint_construction_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cleanup: list[tuple[str, str]] = []
    client = _client(monkeypatch, cleanup)
    monkeypatch.setattr(
        client,
        "playwright_endpoint",
        lambda _profile_id: (_ for _ in ()).throw(
            ContractError("owned endpoint failure")
        ),
    )
    monkeypatch.setenv("BROWSER_CORE_SESSION_FILE", "prior-session")
    with pytest.raises(ContractError, match="owned endpoint failure"):
        kameleo.run_kameleo_trial(
            client,
            "151",
            "cohort-1",
            1,
            tmp_path / "runs" / "trial",
            "controlled_coherence",
        )
    assert cleanup and os.environ["BROWSER_CORE_SESSION_FILE"] == "prior-session"


def test_kameleo_trial_marks_recovery_clean_after_evaluator_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cleanup: list[tuple[str, str]] = []
    client = _client(monkeypatch, cleanup)
    monkeypatch.setattr(
        kameleo,
        "evaluator_run",
        lambda *_args: (_ for _ in ()).throw(RuntimeError("owned eval failure")),
    )
    output = tmp_path / "runs" / "trial"
    with pytest.raises(RuntimeError, match="owned eval failure"):
        kameleo.run_kameleo_trial(
            client,
            "151",
            "cohort-1",
            1,
            output,
            "controlled_coherence",
        )
    recovery = output.parent / "disposables" / "profile-1.json"
    assert json.loads(recovery.read_text(encoding="utf-8"))["cleaned"] is True


def test_kameleo_trial_reports_only_closed_fingerprint_and_result_vectors(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cleanup: list[tuple[str, str]] = []
    client = _client(monkeypatch, cleanup)

    def evaluator(output: Path, _selection: str):
        run_dir = output / "owned-run"
        run_dir.mkdir(parents=True)
        (run_dir / "summary.json").write_text(
            json.dumps(redact_obj(_controlled_summary())),
            encoding="utf-8",
        )
        return run_dir, _controlled_summary()

    monkeypatch.setattr(kameleo, "evaluator_run", evaluator)
    result = kameleo.run_kameleo_trial(
        client,
        "151",
        "cohort-1",
        1,
        tmp_path / "runs" / "trial",
        "controlled_coherence",
    )
    assert set(result) == {"arm", "run_dir", "profile_id", "fingerprint", "vector"}
    assert result["fingerprint"]["browser"]["major"] == 151
    assert "private" not in result["vector"]
    assert cleanup == [("profile-1", f"{kameleo.KAMELEO_NAME_PREFIX} cohort-1 01")]


def test_kameleo_trial_rejects_a_saved_summary_changed_after_evaluation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cleanup: list[tuple[str, str]] = []
    client = _client(monkeypatch, cleanup)

    def evaluator(output: Path, _selection: str):
        run_dir = output / "owned-run"
        run_dir.mkdir(parents=True)
        changed = _controlled_summary()
        changed["evaluators"][0]["verdict"] = "fail"
        (run_dir / "summary.json").write_text(json.dumps(changed), encoding="utf-8")
        return run_dir, _controlled_summary()

    monkeypatch.setattr(kameleo, "evaluator_run", evaluator)
    with pytest.raises(ContractError, match="summary changed"):
        kameleo.run_kameleo_trial(
            client,
            "151",
            "cohort-1",
            1,
            tmp_path / "runs" / "trial",
            "controlled_coherence",
        )
    assert cleanup and cleanup[0][0] == "profile-1"


def test_kameleo_core_trial_stops_and_restores_environment_on_eval_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session_path = tmp_path / "session.json"
    stopped: list[Path] = []
    monkeypatch.setattr(
        kameleo,
        "launch_evaluation",
        lambda *_args, **_kwargs: (
            session_path,
            {
                "run_id": "owned-core-run",
                "trace_path": None,
                "build": {"revision": "1" * 40},
            },
        ),
    )
    monkeypatch.setattr(
        kameleo,
        "evaluator_run",
        lambda *_args: (_ for _ in ()).throw(RuntimeError("owned core eval failure")),
    )
    monkeypatch.setattr(
        kameleo,
        "stop_session",
        lambda path, timeout_seconds: stopped.append(path) or _stopped_receipt(),
    )
    monkeypatch.setenv("BROWSER_CORE_SESSION_FILE", "prior-session")
    monkeypatch.setenv("BROWSER_EVAL_CDP_ENDPOINT", "prior-endpoint")
    with pytest.raises(RuntimeError, match="owned core eval failure"):
        kameleo.run_core_trial(
            tmp_path / "browser.exe",
            tmp_path / "workspace",
            "owned-profile",
            tmp_path / "out",
            "controlled_coherence",
        )
    assert stopped == [session_path]
    assert os.environ["BROWSER_CORE_SESSION_FILE"] == "prior-session"
    assert os.environ["BROWSER_EVAL_CDP_ENDPOINT"] == "prior-endpoint"


def test_kameleo_core_trial_rejects_a_saved_summary_changed_after_evaluation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session_path = tmp_path / "session.json"
    monkeypatch.setattr(
        kameleo,
        "launch_evaluation",
        lambda *_args, **_kwargs: (
            session_path,
            {
                "run_id": "owned-core-run",
                "trace_path": None,
                "build": {"revision": "1" * 40},
            },
        ),
    )
    stopped: list[Path] = []
    monkeypatch.setattr(
        kameleo,
        "stop_session",
        lambda path, timeout_seconds: stopped.append(path) or _stopped_receipt(),
    )

    def evaluator(output: Path, _selection: str):
        run_dir = output / "owned-run"
        run_dir.mkdir(parents=True)
        changed = _controlled_summary()
        changed["evaluators"][0]["verdict"] = "fail"
        (run_dir / "summary.json").write_text(json.dumps(changed), encoding="utf-8")
        return run_dir, _controlled_summary()

    monkeypatch.setattr(kameleo, "evaluator_run", evaluator)
    with pytest.raises(ContractError, match="summary changed"):
        kameleo.run_core_trial(
            tmp_path / "browser.exe",
            tmp_path / "workspace",
            "owned-profile",
            tmp_path / "out",
            "controlled_coherence",
        )
    assert stopped == [session_path]


def test_kameleo_core_trial_rejects_active_stop_before_returning_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session_path = tmp_path / "session.json"
    monkeypatch.setattr(
        kameleo,
        "launch_evaluation",
        lambda *_args, **_kwargs: (
            session_path,
            {
                "run_id": "owned-core-run",
                "trace_path": None,
                "build": {"revision": "1" * 40},
            },
        ),
    )

    def evaluator(output: Path, _selection: str):
        run_dir = output / "owned-run"
        run_dir.mkdir(parents=True)
        (run_dir / "summary.json").write_text(
            json.dumps(_controlled_summary()),
            encoding="utf-8",
        )
        return run_dir, {}

    monkeypatch.setattr(kameleo, "evaluator_run", evaluator)
    monkeypatch.setattr(
        kameleo,
        "stop_session",
        lambda *_args, **_kwargs: {
            **_stopped_receipt(),
            "state": "active",
            "running": True,
        },
    )
    with pytest.raises(ContractError, match="stop was not verified"):
        kameleo.run_core_trial(
            tmp_path / "browser.exe",
            tmp_path / "workspace",
            "owned-profile",
            tmp_path / "out",
            "controlled_coherence",
        )


def test_kameleo_trial_rejects_escaped_evaluator_run_and_cleans_profile(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cleanup: list[tuple[str, str]] = []
    client = _client(monkeypatch, cleanup)
    monkeypatch.setattr(
        kameleo,
        "evaluator_run",
        lambda *_args: (tmp_path / "escaped", {}),
    )
    with pytest.raises(ContractError, match="escaped"):
        kameleo.run_kameleo_trial(
            client,
            "151",
            "cohort-1",
            1,
            tmp_path / "runs" / "trial",
            "controlled_coherence",
        )
    assert cleanup and cleanup[0][0] == "profile-1"


def test_kameleo_main_invalid_counts_fail_before_build_or_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    args = SimpleNamespace(
        executable=tmp_path / "browser.exe",
        workspace=tmp_path / "workspace",
        profile_id="owned-profile",
        out=tmp_path / "cohort",
        core_trials=True,
        kameleo_trials=1,
        kameleo_browser_version="151",
        kameleo_api="http://127.0.0.1:5050",
        evaluators="controlled_coherence",
    )
    monkeypatch.setattr(kameleo, "parser", lambda: _Parser(args))
    monkeypatch.setattr(
        kameleo,
        "executable_evidence",
        lambda *_args, **_kwargs: pytest.fail(
            "invalid counts reached build inspection"
        ),
    )
    with pytest.raises(ContractError, match="trial counts"):
        kameleo.main()
    assert not args.out.exists()


def test_kameleo_progress_cursor_preserves_competing_replacement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    args = SimpleNamespace(
        executable=tmp_path / "browser.exe",
        workspace=tmp_path / "workspace",
        profile_id="owned-profile",
        out=tmp_path / "cohort",
        core_trials=1,
        kameleo_trials=1,
        kameleo_browser_version="151",
        kameleo_api="http://127.0.0.1:5050",
        evaluators="controlled_coherence",
    )
    monkeypatch.setattr(kameleo, "parser", lambda: _Parser(args))
    monkeypatch.setattr(kameleo, "executable_evidence", lambda *_args, **_kwargs: {})
    monkeypatch.setattr(kameleo, "load_profile", lambda *_args: {})
    foreign = b"foreign cohort progress"
    monkeypatch.setattr(
        kameleo, "run_kameleo_trial", lambda *_args, **_kwargs: {"arm": "kameleo"}
    )

    def core_trial(*_args, **_kwargs):
        (args.out / "cohort.json").write_bytes(foreign)
        return {"arm": "core"}

    monkeypatch.setattr(kameleo, "run_core_trial", core_trial)
    with pytest.raises(ContractError, match="changed"):
        kameleo.main()
    assert (args.out / "cohort.json").read_bytes() == foreign
