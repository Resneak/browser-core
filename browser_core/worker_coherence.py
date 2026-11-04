"""Does this browser tell the same identity story on a worker thread?

Residual-driven. The offline rehost of the current Akamai BM web pin showed the
collector building a SharedWorker from a Blob URL and **re-reading nine
`WorkerNavigator` identity fields inside it**, then posting them back to the frame for
comparison (`akamai-web/knowledge/144` §4.1). The same worker program appears in the
SBSD family. Patching `window.navigator` does not patch `WorkerNavigator` on another
thread, so a main-thread-only identity is detectable by construction.

This module measures the same thing about *our* browser, from the outside: read the
nine fields on the main thread, read them again inside a real worker realm, and report
any field that disagrees.

It is a coherence measurement, not a spoofing tool. It changes nothing, and a pass is
not an acceptance, undetectability, or bot-score claim -- it only says the two realms
agreed on the day it ran.
"""

from __future__ import annotations

import hashlib
import socket
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock
from typing import Any

from .contracts import ContractError, load_session_snapshot
from .control_files import decode_strict_json_bytes
from .local_http import _LocalPanelHeaderDeadline
from .numeric import is_finite_number
from .owned_paths import directory_ancestry_binding

WORKER_COHERENCE_SCHEMA = "browser-core.worker-realm-coherence/1"

# The exact fields the observed collector re-reads inside its worker, in its order.
IDENTITY_FIELDS = (
    "userAgent",
    "platform",
    "language",
    "languages",
    "appVersion",
    "hardwareConcurrency",
    "deviceMemory",
    "connection.effectiveType",
    "connection.rtt",
    "userAgentData.platform",
    "userAgentData.mobile",
)

# Read the fields the same way in both realms so a difference is a real difference and
# not an artifact of asking differently.
_READ_IDENTITY_JS = """(nav) => {
  const conn = nav.connection || {};
  const uad = nav.userAgentData || null;
  return {
    'userAgent': String(nav.userAgent || ''),
    'platform': String(nav.platform || ''),
    'language': String(nav.language || ''),
    'languages': Array.from(nav.languages || []).join(','),
    'appVersion': String(nav.appVersion || ''),
    'hardwareConcurrency': nav.hardwareConcurrency ?? null,
    'deviceMemory': nav.deviceMemory ?? null,
    'connection.effectiveType': conn.effectiveType ?? null,
    'connection.rtt': conn.rtt ?? null,
    'userAgentData.platform': uad ? String(uad.platform || '') : null,
    'userAgentData.mobile': uad ? uad.mobile === true : null,
  };
}"""

_INSTALL_JS = """(() => {
  if (window.__bcWorkerCoherence !== undefined &&
      typeof window.__bcWorkerCoherenceCleanup === 'function') {
    window.__bcWorkerCoherenceCleanup();
  }
  window.__bcWorkerCoherence = null;
  window.__bcWorkerCoherenceError = null;
  window.__bcWorkerKind = null;
  const readFn = %READ%;
  window.__bcMainIdentity = readFn(navigator);
  const body =
    'const read = ' + readFn.toString() + ';' +
    'const payload = () => { try { return {ok:true, id: read(navigator)}; }' +
    ' catch (e) { return {ok:false, error: String(e)}; } };' +
    'if (typeof onconnect !== "undefined" || typeof SharedWorkerGlobalScope !== "undefined") {' +
    '  self.onconnect = (e) => { e.ports[0].postMessage(payload()); };' +
    '} else { self.postMessage(payload()); }';
  const url = URL.createObjectURL(new Blob([body], {type: 'text/javascript'}));
  let active = true;
  let worker = null;
  window.__bcWorkerCoherenceCleanup = () => {
    active = false;
    try {
      if (worker && worker.port) worker.port.close();
      else if (worker) worker.terminate();
    } catch (_) {}
    try { URL.revokeObjectURL(url); } catch (_) {}
    window.__bcWorkerCoherenceCleanup = null;
  };
  try {
    const sw = new SharedWorker(url);
    worker = sw;
    window.__bcWorkerKind = 'shared';
    sw.port.onmessage = (e) => { if (active) window.__bcWorkerCoherence = e.data; };
    sw.port.start();
  } catch (sharedError) {
    if (worker && worker.port) {
      try { worker.port.close(); } catch (_) {}
    }
    worker = null;
    window.__bcWorkerKind = null;
    try {
      const w = new Worker(url);
      worker = w;
      window.__bcWorkerKind = 'dedicated';
      w.onmessage = (e) => { if (active) window.__bcWorkerCoherence = e.data; };
    } catch (workerError) {
      window.__bcWorkerCoherenceError =
        'shared: ' + String(sharedError) + ' | dedicated: ' + String(workerError);
      window.__bcWorkerCoherenceCleanup();
    }
  }
  return true;
})()""".replace("%READ%", _READ_IDENTITY_JS)

_COLLECT_JS = """(() => JSON.stringify({
  main: window.__bcMainIdentity || null,
  worker: window.__bcWorkerCoherence || null,
  kind: window.__bcWorkerKind || null,
  error: window.__bcWorkerCoherenceError || null,
}))()"""

_RELEASE_JS = """(() => {
  const release = window.__bcWorkerCoherenceCleanup;
  if (typeof release === 'function') {
    release();
  } else if (release !== null) {
    return false;
  }
  return window.__bcWorkerCoherenceCleanup === null;
})()"""

WORKER_POLL_ATTEMPTS = 20
WORKER_POLL_INTERVAL_SECONDS = 0.25
MAX_WORKER_OBSERVATION_BYTES = 128 * 1024
MAX_IDENTITY_TEXT_BYTES = 4096
WORKER_CLEANUP_TIMEOUT_SECONDS = 5.0
_LOOPBACK_CLIENTS_LOCK = Lock()
_OBSERVATION_FIELDS = frozenset({"main", "worker", "kind", "error"})
_WORKER_OK_FIELDS = frozenset({"ok", "id"})
_WORKER_ERROR_FIELDS = frozenset({"ok", "error"})

# The launcher's managed identity page is a `data:` URL, which is an opaque,
# non-secure origin: `SharedWorker` is disallowed there and `navigator.userAgentData`
# is null. Measuring on it would silently downgrade the check -- the SharedWorker path
# the collector actually uses would never run, and two fields would agree trivially
# because both realms report null. So by default the check serves its own loopback
# page, which is a real secure origin, and restores the managed page afterwards.
LOOPBACK_PAGE_TITLE = "browser-core-worker-coherence"
_LOOPBACK_HTML = (
    '<!doctype html><html lang="en"><head><meta charset="utf-8">'
    f'<title>{LOOPBACK_PAGE_TITLE}</title></head><body><div id="root">ok</div>'
    "</body></html>"
)


def _track_loopback_client(server: Any, connection: socket.socket) -> None:
    with _LOOPBACK_CLIENTS_LOCK:
        clients = getattr(server, '_loopback_clients', None)
        if clients is None:
            clients = set()
            server._loopback_clients = clients
        clients.add(connection)


def _release_loopback_client(server: Any, connection: socket.socket) -> None:
    with _LOOPBACK_CLIENTS_LOCK:
        clients = getattr(server, '_loopback_clients', None)
        if clients is not None:
            clients.discard(connection)


def _track_loopback_requests(server: Any) -> None:
    original = getattr(server, 'process_request', None)
    original_shutdown = getattr(server, 'shutdown_request', None)
    if not callable(original) or not callable(original_shutdown):
        return

    def process_request(request, address):
        _track_loopback_client(server, request)
        try:
            return original(request, address)
        except BaseException:
            _release_loopback_client(server, request)
            raise

    def shutdown_request(request):
        try:
            return original_shutdown(request)
        finally:
            _release_loopback_client(server, request)

    server.process_request = process_request
    server.shutdown_request = shutdown_request


def _serve_loopback_page() -> tuple[Any, str]:
    """Start a bounded loopback server hosting one inert page. Caller shuts it down."""
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    from threading import Thread

    payload = _LOOPBACK_HTML.encode("utf-8")

    class Handler(_LocalPanelHeaderDeadline, BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def setup(self) -> None:
            super().setup()
            _track_loopback_client(self.server, self.connection)

        def finish(self) -> None:
            try:
                super().finish()
            finally:
                _release_loopback_client(self.server, self.connection)

        def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
            if self.path != "/":
                self.send_response(404)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, fmt: str, *args: object) -> None:
            return

    class LoopbackServer(ThreadingHTTPServer):
        def handle_error(self, request, client_address) -> None:
            if isinstance(
                sys.exc_info()[1],
                (BrokenPipeError, ConnectionResetError, ConnectionAbortedError),
            ):
                return
            super().handle_error(request, client_address)

    try:
        server = LoopbackServer(("127.0.0.1", 0), Handler)
    except (OSError, ValueError):
        raise ContractError("worker loopback server could not start") from None
    server.daemon_threads = True
    thread: Any | None = None
    try:
        _track_loopback_requests(server)
        thread = Thread(
            target=server.serve_forever,
            name="browser-core-worker-coherence",
            daemon=True,
        )
        thread.start()
    except (OSError, RuntimeError, ValueError):
        if thread is not None:
            try:
                thread_running = thread.is_alive()
            except (OSError, RuntimeError):
                thread_running = True
            if thread_running:
                if _stop_loopback_page((server, thread)):
                    raise ContractError(
                        "worker loopback server start cleanup failed"
                    ) from None
                raise ContractError("worker loopback server could not start") from None
        cleanup_failed = False
        try:
            server.server_close()
        except OSError:
            cleanup_failed = True
        if cleanup_failed:
            raise ContractError("worker loopback server start cleanup failed") from None
        raise ContractError("worker loopback server could not start") from None
    return (server, thread), f"http://127.0.0.1:{server.server_port}/"


def _remaining_time(deadline: float, *, maximum: float = 120.0) -> float:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise ContractError("worker-realm coherence timed out")
    return min(remaining, maximum)


def _stop_loopback_page(server_handle: tuple[Any, Any]) -> list[str]:
    from threading import Thread

    server, thread = server_handle
    failures: list[str] = []
    shutdown_failed: list[bool] = []
    shutdown_thread: Any | None = None
    shutdown_deadline = time.monotonic() + WORKER_CLEANUP_TIMEOUT_SECONDS

    def shutdown() -> None:
        try:
            server.shutdown()
        except Exception:
            shutdown_failed.append(True)

    try:
        shutdown_thread = Thread(
            target=shutdown,
            name="browser-core-worker-coherence-shutdown",
            daemon=True,
        )
        shutdown_thread.start()
        shutdown_thread.join(timeout=max(0.0, shutdown_deadline - time.monotonic()))
        if shutdown_thread.is_alive() or shutdown_failed:
            failures.append("server-shutdown")
    except (OSError, RuntimeError):
        failures.append("server-shutdown")
    try:
        server.server_close()
    except Exception:
        failures.append("server-close")
    if shutdown_thread is not None:
        try:
            shutdown_thread.join(
                timeout=max(0.0, shutdown_deadline - time.monotonic())
            )
            if shutdown_thread.is_alive() and "server-shutdown" not in failures:
                failures.append("server-shutdown")
        except (OSError, RuntimeError):
            if "server-shutdown" not in failures:
                failures.append("server-shutdown")
    try:
        thread.join(timeout=WORKER_CLEANUP_TIMEOUT_SECONDS)
        if thread.is_alive():
            failures.append("server-thread")
    except (OSError, RuntimeError):
        failures.append("server-thread")
    with _LOOPBACK_CLIENTS_LOCK:
        clients = tuple(getattr(server, '_loopback_clients', ()))
    for client in clients:
        try:
            client.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            client.close()
        except OSError:
            if 'server-client-close' not in failures:
                failures.append('server-client-close')
    return failures


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _safe_text(value: object, *, label: str, nullable: bool = False) -> str | None:
    if nullable and value is None:
        return None
    if not isinstance(value, str):
        raise ContractError(f"{label} must be bounded safe text")
    try:
        encoded = value.encode("utf-8", errors="strict")
    except UnicodeEncodeError:
        raise ContractError(f"{label} must be bounded safe text") from None
    if len(encoded) > MAX_IDENTITY_TEXT_BYTES or any(
        ord(character) < 0x20 and character not in "\t" or ord(character) == 0x7F
        for character in value
    ):
        raise ContractError(f"{label} must be bounded safe text")
    return value


def _identity_reading(
    value: object, *, label: str, require_all: bool
) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ContractError(f"{label} must be an object")
    actual = set(value)
    expected = set(IDENTITY_FIELDS)
    if not actual <= expected or require_all and actual != expected:
        raise ContractError(f"{label} fields are invalid")
    result = dict(value)
    for name in ("userAgent", "platform", "language", "languages", "appVersion"):
        if name in result:
            result[name] = _safe_text(result[name], label=f"{label}.{name}")
    for name in ("connection.effectiveType", "userAgentData.platform"):
        if name in result:
            result[name] = _safe_text(
                result[name], label=f"{label}.{name}", nullable=True
            )
    if "hardwareConcurrency" in result:
        hardware = result["hardwareConcurrency"]
        if hardware is not None and (
            isinstance(hardware, bool)
            or not isinstance(hardware, int)
            or not 1 <= hardware <= 4096
        ):
            raise ContractError(f"{label}.hardwareConcurrency is invalid")
    for name in ("deviceMemory", "connection.rtt"):
        if name not in result or result[name] is None:
            continue
        number = result[name]
        if not is_finite_number(number) or not 0 <= number <= 1_000_000:
            raise ContractError(f"{label}.{name} is invalid")
    if "userAgentData.mobile" in result:
        mobile = result["userAgentData.mobile"]
        if mobile is not None and type(mobile) is not bool:
            raise ContractError(f"{label}.userAgentData.mobile is invalid")
    return result


def _parse_worker_observation(raw: object) -> dict[str, Any]:
    if not isinstance(raw, str):
        raise ContractError("worker observation must be a JSON string")
    try:
        body = raw.encode("utf-8", errors="strict")
    except UnicodeEncodeError:
        raise ContractError("worker observation must be valid UTF-8 text") from None
    if len(body) > MAX_WORKER_OBSERVATION_BYTES:
        raise ContractError("worker observation exceeds the byte limit")
    document = decode_strict_json_bytes(body, label="worker observation")
    if not isinstance(document, dict) or set(document) != _OBSERVATION_FIELDS:
        raise ContractError("worker observation fields are invalid")
    kind = document["kind"]
    if kind is not None and (not isinstance(kind, str) or kind not in {"shared", "dedicated"}):
        raise ContractError("worker observation kind is invalid")
    if document["error"] is not None and (
        not isinstance(document["error"], str) or not document["error"]
    ):
        raise ContractError("worker observation error is invalid")
    if document["main"] is not None:
        document["main"] = _identity_reading(
            document["main"], label="main identity", require_all=True
        )
    worker = document["worker"]
    if worker is None:
        return document
    if kind is None or document["error"] is not None:
        raise ContractError("worker observation status is inconsistent")
    if not isinstance(worker, dict):
        raise ContractError("worker observation payload must be an object or null")
    if set(worker) == _WORKER_OK_FIELDS and worker["ok"] is True:
        worker["id"] = _identity_reading(
            worker["id"], label="worker identity", require_all=True
        )
    elif set(worker) == _WORKER_ERROR_FIELDS and worker["ok"] is False:
        if not isinstance(worker["error"], str) or not worker["error"]:
            raise ContractError("worker observation failure is invalid")
    else:
        raise ContractError("worker observation payload fields are invalid")
    return document


def _error_receipt(value: str, *, category: str) -> tuple[str, str]:
    if not isinstance(value, str) or not value:
        raise ContractError("worker error receipt is invalid")
    try:
        body = value.encode("utf-8", errors="strict")
    except UnicodeEncodeError:
        raise ContractError("worker error receipt is invalid") from None
    if len(body) > MAX_WORKER_OBSERVATION_BYTES:
        raise ContractError("worker error receipt is invalid")
    digest = hashlib.sha256(body).hexdigest()
    return category, f"sha256:{digest}"


def compare_realms(main: dict[str, Any], worker: dict[str, Any]) -> dict[str, Any]:
    """Field-by-field comparison of two identity readings.

    A field the worker realm does not expose at all is reported as ``worker_absent``
    rather than as a mismatch: WorkerNavigator legitimately lacks some surfaces, and
    calling that an incoherence would be wrong.
    """
    main = _identity_reading(main, label="main identity", require_all=True)
    worker = _identity_reading(worker, label="worker identity", require_all=False)
    fields: dict[str, Any] = {}
    mismatched: list[str] = []
    absent: list[str] = []
    for name in IDENTITY_FIELDS:
        main_value = main.get(name)
        worker_value = worker.get(name)
        if name not in worker or worker_value is None and main_value is not None:
            # Absent on the worker side only; not evidence of a lie.
            fields[name] = {
                "main": main_value,
                "worker": worker_value,
                "status": "worker_absent",
            }
            absent.append(name)
            continue
        agree = main_value == worker_value
        fields[name] = {
            "main": main_value,
            "worker": worker_value,
            "status": "agree" if agree else "mismatch",
        }
        if not agree:
            mismatched.append(name)
    return {
        "fields": fields,
        "compared": len(IDENTITY_FIELDS) - len(absent),
        "agreed": len(IDENTITY_FIELDS) - len(absent) - len(mismatched),
        "mismatched_fields": mismatched,
        "worker_absent_fields": absent,
        "coherent": not mismatched,
    }


def check_worker_realm_coherence(
    session_path: Path,
    *,
    timeout_seconds: float = 15.0,
    attempts: int = WORKER_POLL_ATTEMPTS,
    interval_seconds: float = WORKER_POLL_INTERVAL_SECONDS,
    use_loopback_page: bool = True,
    evaluate: Any = None,
    sleep: Any = None,
) -> dict[str, Any]:
    """Read identity on the main thread and inside a real worker realm, then diff."""
    from .cdp import (
        evaluate_page_expression,
        navigate_managed_page,
        wait_for_page_target,
    )

    if not isinstance(session_path, Path):
        raise ContractError("worker-realm coherence session path must be a Path")
    if not is_finite_number(timeout_seconds) or not 0 < timeout_seconds <= 120:
        raise ContractError("worker-realm coherence timeout is invalid")
    if (
        isinstance(attempts, bool)
        or not isinstance(attempts, int)
        or not 1 <= attempts <= 1000
    ):
        raise ContractError("worker-realm coherence attempts are invalid")
    if not is_finite_number(interval_seconds) or not 0 <= interval_seconds <= 10:
        raise ContractError("worker-realm coherence interval is invalid")
    if type(use_loopback_page) is not bool:
        raise ContractError("worker-realm coherence loopback choice must be boolean")
    if evaluate is not None and not callable(evaluate):
        raise ContractError("worker-realm coherence evaluator must be callable")
    if sleep is not None and not callable(sleep):
        raise ContractError("worker-realm coherence sleeper must be callable")

    session_parent = session_path.absolute().parent
    session_parent_binding = directory_ancestry_binding(
        session_parent, label="worker-realm coherence session parent"
    )

    def require_session_parent_unchanged() -> None:
        try:
            current = directory_ancestry_binding(
                session_parent, label="worker-realm coherence session parent"
            )
        except ContractError:
            raise ContractError("worker-realm coherence session changed") from None
        if current != session_parent_binding:
            raise ContractError("worker-realm coherence session changed")

    session_snapshot = load_session_snapshot(session_path)
    require_session_parent_unchanged()
    session = session_snapshot.document
    if session.get("state", "active") != "active":
        raise ContractError("worker-realm coherence requires an active session")

    def require_session_unchanged() -> None:
        require_session_parent_unchanged()
        try:
            current = load_session_snapshot(session_path)
        except ContractError:
            raise ContractError("worker-realm coherence session changed") from None
        require_session_parent_unchanged()
        if (
            current.body != session_snapshot.body
            or current.identity != session_snapshot.identity
        ):
            raise ContractError("worker-realm coherence session changed")

    automation = session.get("automation")
    if not isinstance(automation, dict):
        raise ContractError("session is missing automation hand-off")
    endpoint = automation.get("cdp_endpoint")
    managed_url = automation.get("managed_target_url")
    if not isinstance(endpoint, str) or not endpoint:
        raise ContractError("session is missing automation.cdp_endpoint")
    if not isinstance(managed_url, str) or not managed_url:
        raise ContractError("session is missing automation.managed_target_url")

    deadline = time.monotonic() + float(timeout_seconds)
    sleeper = time.sleep if sleep is None else sleep
    page_url = managed_url
    server_handle = None
    loopback_url: str | None = None
    navigation_attempted = False
    navigation_acknowledged = False
    origin_kind = "injected-evaluator" if evaluate is not None else "managed-data-url"

    observed: dict[str, Any] = {}
    used = 0
    worker_installed = False
    try:
        if evaluate is None and use_loopback_page:
            server_handle, loopback_url = _serve_loopback_page()
            navigation_attempted = True
            try:
                navigation_receipt = navigate_managed_page(
                    endpoint,
                    loopback_url,
                    current_target_url=managed_url,
                    timeout_seconds=_remaining_time(deadline),
                )
                if navigation_receipt is not True:
                    raise ContractError(
                        "worker loopback navigation was not acknowledged"
                    )
                navigation_acknowledged = True
                wait_for_page_target(
                    endpoint,
                    loopback_url,
                    LOOPBACK_PAGE_TITLE,
                    timeout_seconds=_remaining_time(deadline),
                )
                page_url = loopback_url
                origin_kind = "loopback-secure-origin"
            except (ContractError, OSError, ValueError):
                page_url = managed_url
                origin_kind = "managed-data-url"

        def evaluator(expression: str) -> Any:
            _remaining_time(deadline)
            if evaluate is not None:
                value = evaluate(expression)
                _remaining_time(deadline)
                return value
            return evaluate_page_expression(
                endpoint,
                expression,
                target_url=page_url,
                timeout_seconds=_remaining_time(deadline),
            )

        if evaluator(_INSTALL_JS) is not True:
            raise ContractError("worker installation was not acknowledged")
        worker_installed = True
        for index in range(attempts):
            used = index + 1
            raw = evaluator(_COLLECT_JS)
            observed = _parse_worker_observation(raw)
            if observed.get("worker") is not None or observed.get("error"):
                break
            if index + 1 < attempts:
                delay = min(float(interval_seconds), _remaining_time(deadline))
                sleeper(delay)
                _remaining_time(deadline)
    finally:
        cleanup_failures: list[str] = []
        cleanup_deadline = time.monotonic() + WORKER_CLEANUP_TIMEOUT_SECONDS
        if worker_installed and evaluate is None:
            try:
                released = evaluate_page_expression(
                    endpoint,
                    _RELEASE_JS,
                    target_url=page_url,
                    timeout_seconds=min(1.5, _remaining_time(cleanup_deadline)),
                )
                if released is not True:
                    cleanup_failures.append("worker-release")
            except Exception:  # noqa: BLE001 - bounded cleanup continues below
                cleanup_failures.append("worker-release")
        if server_handle is not None:
            if navigation_attempted and loopback_url is not None:
                candidates = (
                    (loopback_url, managed_url)
                    if navigation_acknowledged
                    else (managed_url, loopback_url)
                )
                restored = False
                for candidate in candidates:
                    try:
                        if candidate == managed_url:
                            confirmation = evaluate_page_expression(
                                endpoint,
                                "true",
                                target_url=managed_url,
                                timeout_seconds=min(
                                    1.5,
                                    _remaining_time(cleanup_deadline),
                                ),
                            )
                            if confirmation is True:
                                restored = True
                                break
                        restore_receipt = navigate_managed_page(
                            endpoint,
                            managed_url,
                            current_target_url=candidate,
                            timeout_seconds=min(
                                1.5,
                                _remaining_time(cleanup_deadline),
                            ),
                        )
                        if restore_receipt is not True:
                            continue
                        confirmation = evaluate_page_expression(
                            endpoint,
                            "true",
                            target_url=managed_url,
                            timeout_seconds=_remaining_time(cleanup_deadline),
                        )
                        if confirmation is True:
                            restored = True
                            break
                    except Exception:  # noqa: BLE001 - continue bounded recovery
                        continue
                if not restored:
                    cleanup_failures.append("page-restore")
            cleanup_failures.extend(_stop_loopback_page(server_handle))
        if cleanup_failures:
            phases = ",".join(cleanup_failures)
            cleanup_error = ContractError(
                f"worker-realm coherence cleanup failed ({phases})"
            )
            active_error = sys.exc_info()[1]
            if active_error is not None:
                raise cleanup_error from active_error
            raise cleanup_error from None

    build = session.get("build") if isinstance(session.get("build"), dict) else {}
    result: dict[str, Any] = {
        "schema": WORKER_COHERENCE_SCHEMA,
        "generated_at": _utc_now(),
        "session_run_id": session.get("run_id"),
        "chromium_revision": session.get("chromium_revision"),
        "build_provenance": build.get("provenance"),
        "origin_kind": origin_kind,
        "worker_kind": observed.get("kind"),
        "method": {
            "secure_loopback_origin": origin_kind == "loopback-secure-origin",
            "shared_worker": observed.get("kind") == "shared",
            "collector_equivalent": bool(
                origin_kind == "loopback-secure-origin"
                and observed.get("kind") == "shared"
            ),
        },
        "poll_attempts": used,
        "error": None,
        "non_claims": [
            "a coherent result is not an acceptance, undetectability, or bot-score claim",
            "this measures our own browser; it changes nothing and spoofs nothing",
        ],
    }

    worker_payload = observed.get("worker")
    main_identity = observed.get("main")
    outer_error = observed.get("error")
    if isinstance(outer_error, str):
        result["error"], result["error_digest"] = _error_receipt(
            outer_error, category="worker-construction-failed"
        )
    if not isinstance(worker_payload, dict) or not worker_payload.get("ok"):
        result["status"] = "unavailable"
        result["coherent"] = None
        result["worker_coherence_claim_ready"] = False
        if isinstance(worker_payload, dict) and worker_payload.get("error"):
            category, digest = _error_receipt(
                worker_payload["error"], category="worker-observation-failed"
            )
            if result["error"] is None:
                result["error"] = category
                result["error_digest"] = digest
        require_session_unchanged()
        return result
    if not isinstance(main_identity, dict):
        result["status"] = "unavailable"
        result["coherent"] = None
        result["worker_coherence_claim_ready"] = False
        require_session_unchanged()
        return result

    comparison = compare_realms(main_identity, worker_payload["id"])
    result["status"] = "ok"
    result.update(comparison)
    result["worker_coherence_claim_ready"] = bool(
        comparison["coherent"] is True
        and result["method"]["collector_equivalent"] is True
    )
    require_session_unchanged()
    return result
