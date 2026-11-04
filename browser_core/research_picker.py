"""Local saved-profile picker; all launches use the ordinary attested workflow."""
from __future__ import annotations

from http.server import BaseHTTPRequestHandler
from .local_http import LocalPanelServer
from datetime import datetime, timezone
import json
from pathlib import Path
import secrets
import socket
from threading import Event, Lock, Thread
import time

from .contracts import ContractError
from .control_files import decode_strict_json_bytes
from .launcher import validate_workspace
from .inspection_contract import require_inspection_support
from .lifecycle import session_status
from .profiles import list_profiles, validate_profile_id
from .process import ProcessQueryUnavailable
from .recording_limits import MIB, recording_limit_bytes
from .research import start_research
from .session_stop_guard import session_stop_guard

MAX_REVIEWERS = 8
PICKER_WORKER_CLOSE_TIMEOUT_SECONDS = 120.0


class ResearchPicker:
    """One owned browser at a time, with a bounded set of retained viewers."""

    def __init__(self, workspace, repository_root, *, headless=False,
                 executable=None, recording_limit_mib=None, recording_parts=None,
                 inspect_hash_inputs=False):
        self.workspace = validate_workspace(workspace, repository_root)
        self.repository_root = repository_root
        self.options = dict(headless=headless, executable=executable,
                            recording_limit_mib=recording_limit_mib)
        if not isinstance(inspect_hash_inputs, bool):
            raise ContractError('hash input inspection must be boolean')
        if inspect_hash_inputs:
            require_inspection_support(repository_root, 'research-v3')
            self.options['inspect_hash_inputs'] = True
        self.limit_mib = recording_limit_bytes(recording_limit_mib, live=True) // MIB
        from .recording_parts import recording_parts as validate_recording_parts
        self.part_count = validate_recording_parts(recording_parts,self.limit_mib*MIB,live=True)
        if recording_parts is not None:
            self.options['recording_parts'] = recording_parts
        self.limit_mib *= self.part_count
        self.lock = Lock()
        self.closing = Event()
        self.stop_requested = Event()
        self.worker = None
        self.active = None
        self.reviews = []
        self.state = 'ready'
        self.profile_id = None
        self.error = None
        self.revision = 0

    def profiles(self):
        # Full, verified registry inventory. Neither identity documents nor
        # route configuration/credentials are sent to the page.
        return [{'id': p['id'], 'name': p['name'],
                 'identity': (p.get('persona') or {}).get('id') or
                             ('Saved custom identity' if p.get('identity_contract') else 'This computer'),
                 'route': 'Saved network route' if p.get('network_route') else 'Default network'}
                for p in sorted(list_profiles(self.workspace), key=lambda p: (p['name'].casefold(), p['id']))]

    def snapshot(self):
        with self.lock:
            return {'state': self.state, 'profile_id': self.profile_id,
                    'error': self.error, 'revision': self.revision,
                    'recording_limit_mib': self.limit_mib,
                    'recording_parts': self.part_count,
                    'inspector_url': self.active.url if self.active else None,
                    'recent': [{'profile_id': profile_id, 'inspector_url': run.url,
                                'opened_at': run.picker_opened_at}
                               for profile_id, run in reversed(self.reviews)]}

    def start(self, data):
        if (type(data) is not dict or set(data) != {'profile_id', 'action'} or
                data['action'] not in ('open', 'create')):
            raise ContractError('invalid profile selection')
        validate_profile_id(data['profile_id'])
        with self.lock:
            if (self.closing.is_set() or self.active or self.state == 'cleanup-error' or
                    (self.worker and self.worker.is_alive())):
                raise ContractError('a research browser is already opening or running')
            previous = (self.state, self.profile_id, self.error)
            self.state = 'opening'
            self.profile_id = data['profile_id']
            self.error = None
            self.stop_requested.clear()
            worker = None
            try:
                worker = Thread(target=self._run, args=(dict(data),), daemon=True)
                self.worker = worker
                worker.start()
            except (RuntimeError, OSError) as error:
                if worker is not None and getattr(worker, 'ident', None) is not None:
                    # start() may raise after starting. Keep ownership until close()
                    # joins the worker; another browser must not launch meanwhile.
                    self.closing.set()
                    self.stop_requested.set()
                    self.state = 'cleanup-error'
                    self.error = 'The research worker started but its launch result was uncertain. Finish this command before retrying.'
                    self.revision += 1
                else:
                    self.state, self.profile_id, self.error = previous
                    self.worker = None
                raise ContractError('research browser worker could not start') from error
            self.revision += 1

    def stop(self):
        with self.lock:
            if self.state != 'running' or not self.active or self.closing.is_set():
                raise ContractError('no owned research browser is running')
            self.stop_requested.set()
            self.state = 'finishing'
            self.revision += 1

    def _run(self, data):
        run = None
        retired = None
        try:
            run = start_research(self.workspace, self.repository_root, data['profile_id'],
                                 profile_action=data['action'], **self.options)
            run.picker_opened_at = datetime.now(timezone.utc).isoformat(timespec='seconds')
            with self.lock:
                if self.closing.is_set():
                    return
                self.active = run
                self.state = 'running'
                self.revision += 1
            unavailable_since = None
            while not self.closing.is_set():
                if self.stop_requested.wait(.5):
                    break
                if not run.thread.is_alive():
                    raise ContractError('research inspector stopped unexpectedly')
                try:
                    with session_stop_guard(run.session_path, time.monotonic() + 40):
                        status = session_status(run.session_path)
                except ProcessQueryUnavailable:
                    now = time.monotonic()
                    if unavailable_since is None:
                        unavailable_since = now
                    elif now - unavailable_since >= 2.0:
                        raise
                    continue
                unavailable_since = None
                if status.get('run_id') != run.run_id:
                    raise ContractError('research session run ID changed while picking')
                if not status['running']:
                    break
            if self.closing.is_set():
                return
            with self.lock:
                self.state = 'finishing'
                self.revision += 1
            run.finish_browser()
            with self.lock:
                self.reviews.append((data['profile_id'], run))
                self.active = None
                run = None  # Ownership moves to retained viewers.
                if len(self.reviews) > MAX_REVIEWERS:
                    _, retired = self.reviews[0]
            if retired:
                retired.close()  # Its original recording remains on disk.
                with self.lock:
                    self.reviews.pop(0)
            with self.lock:
                self.state = 'ready'
                self.revision += 1
        except Exception:
            with self.lock:
                self.state = 'cleanup-error' if retired else 'error'
                self.error = ('An earlier inspector could not be closed. Finish this command before opening another browser.'
                              if retired else 'Could not open or finish this research session. Check the saved profile, '
                              'its identity and whether it is already open. The browser build must be verified.')
                self.revision += 1
        finally:
            if run:
                try:
                    run.close()
                except Exception:
                    with self.lock:
                        self.state = 'cleanup-error'
                        self.error = 'The owned session needs cleanup. Keep this command open and check its session before retrying.'
                else:
                    with self.lock:
                        self.active = None

    def close(self):
        self.closing.set()
        self.stop_requested.set()
        with self.lock:
            worker = self.worker
        if worker:
            worker.join(timeout=PICKER_WORKER_CLOSE_TIMEOUT_SECONDS)
            if worker.is_alive():
                with self.lock:
                    self.state = 'cleanup-error'
                    self.error = 'Research browser worker cleanup is still in progress. Retry closing after it finishes.'
                    self.revision += 1
                raise ContractError('research browser worker cleanup did not finish')
        with self.lock:
            runs = [run for _, run in self.reviews]
            if self.active:
                runs.append(self.active)
        failures = []
        for run in runs:
            try:
                run.close()
            except Exception as error:
                failures.append(error)
        if failures:
            raise ContractError('an owned research session could not be cleaned up') from None
        with self.lock:
            self.active = None
            self.reviews = []
            self.state = 'closed'
            self.error = None
            self.revision += 1


def create_research_picker(workspace: Path, repository_root: Path, **options):
    picker = ResearchPicker(workspace, repository_root, **options)
    token = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(24)
    page = Path(__file__).with_name('research_picker.html').read_text(encoding='utf-8')
    page = page.replace('__NONCE__', nonce).replace('__ACTION_TOKEN__', token).encode('utf-8')
    inventory_lock = Lock()

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def send(self, status, body, kind='application/json'):
            self._response_started = True
            self.send_response(status)
            self.send_header('Content-Type', kind)
            self.send_header('Content-Length', str(len(body)))
            self.send_header('Cache-Control', 'no-store')
            self.send_header('X-Content-Type-Options', 'nosniff')
            self.send_header('Referrer-Policy', 'no-referrer')
            self.send_header('Content-Security-Policy', f"default-src 'none'; script-src 'nonce-{nonce}'; style-src 'nonce-{nonce}'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
            self.end_headers()
            try:
                self.wfile.write(body)
                if self.command == 'POST' and status >= 400:
                    self.wfile.flush()
                    self.connection.shutdown(socket.SHUT_WR)
                    drain_deadline = time.monotonic() + .05
                    remaining = 8192
                    while remaining:
                        timeout = drain_deadline - time.monotonic()
                        if timeout <= 0:
                            break
                        self.connection.settimeout(timeout)
                        chunk = self.connection.recv(min(remaining, 4096))
                        if not chunk or time.monotonic() >= drain_deadline:
                            break
                        remaining -= len(chunk)
            except OSError:
                pass

        def allowed(self, *, mutation=False):
            expected = f'127.0.0.1:{self.server.server_port}'
            if (self.headers.get_all('Host') != [expected] or
                    self.headers.get('Sec-Fetch-Site') not in (None, 'none', 'same-origin')):
                return False
            origins = self.headers.get_all('Origin')
            if origins is not None and origins != ['http://' + expected]:
                return False
            if mutation and (origins != ['http://' + expected] or
                             self.headers.get_all('X-Research-Action') != [token]):
                return False
            return True

        def do_GET(self):
            self._response_started = False
            if not self.allowed():
                return self.send(403, b'{"error":"Forbidden"}')
            if self.path == f'/{token}/':
                return self.send(200, page, 'text/html; charset=utf-8')
            if self.path == f'/{token}/status':
                return self.send(200, json.dumps(picker.snapshot()).encode())
            if self.path != f'/{token}/profiles':
                return self.send(404, b'{"error":"Not found"}')
            if not inventory_lock.acquire(blocking=False):
                return self.send(503, b'{"error":"Profile list is already loading. Try again."}')
            try:
                self.send(200, json.dumps({'profiles': picker.profiles()}, ensure_ascii=True).encode())
            except (ContractError, OSError):
                if self._response_started:
                    self.close_connection = True
                    return
                self.send(409, b'{"error":"The saved profile list could not be verified. Check the registry and try again."}')
            finally:
                inventory_lock.release()

        def do_POST(self):
            self.close_connection = True
            if not self.allowed(mutation=True):
                return self.send(403, b'{"error":"Forbidden"}')
            if self.path not in (f'/{token}/start', f'/{token}/stop'):
                return self.send(404, b'{"error":"Not found"}')
            try:
                lengths = self.headers.get_all('Content-Length')
                if (self.headers.get_all('Content-Type') != ['application/json'] or
                        self.headers.get_all('Transfer-Encoding') is not None or
                        lengths is None or len(lengths) != 1 or not lengths[0].isascii() or
                        not lengths[0].isdigit() or len(lengths[0]) > 4 or not 1 <= int(lengths[0]) <= 1024):
                    raise ContractError('invalid request framing')
                length = int(lengths[0])
                deadline = time.monotonic() + 5.0
                body = bytearray()
                reader = getattr(self.rfile, 'read1', None)
                if not callable(reader):
                    reader = self.rfile.read
                while len(body) < length:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise ContractError('request body read deadline exceeded')
                    self.connection.settimeout(remaining)
                    chunk = reader(length - len(body))
                    if time.monotonic() >= deadline:
                        raise ContractError('request body read deadline exceeded')
                    if type(chunk) is not bytes or len(chunk) > length - len(body):
                        raise ContractError('invalid request body')
                    if not chunk:
                        break
                    body.extend(chunk)
                if len(body) != length:
                    raise ContractError('incomplete request')
                data = decode_strict_json_bytes(bytes(body), label='profile selection')
                if self.path == f'/{token}/stop':
                    if data != {}:
                        raise ContractError('invalid stop request')
                    picker.stop()
                else:
                    picker.start(data)
            except (OSError, ContractError):
                return self.send(409, b'{"error":"Cannot start this selection. Check its name and close the current research browser before opening another."}')
            self.send(202, b'{"accepted":true}')

    class PickerServer(LocalPanelServer):
        daemon_threads = True

        def server_close(self):
            try:
                super().server_close()
            finally:
                picker.close()

    server = PickerServer(('127.0.0.1', 0), Handler)
    server.picker = picker
    return server, f'http://127.0.0.1:{server.server_port}/{token}/'


def serve_research_picker(workspace, repository_root, *, open_browser=True, **options):
    server, url = create_research_picker(workspace, repository_root, **options)
    try:
        print(json.dumps({'profile_picker_url': url,
                          'stop': 'Keep this command running. Press Ctrl+C when finished.'}), flush=True)
        if open_browser:
            import webbrowser
            webbrowser.open(url)
        server.serve_forever(poll_interval=.25)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
