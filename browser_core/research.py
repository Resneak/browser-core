"""One owned research browser, persistent profile and live inspector."""
from __future__ import annotations

import os
from pathlib import Path
from threading import Lock, Thread
import time

from .build import executable_evidence
from .contracts import ContractError, RUN_ID_RE
from .inspection_ui import create_inspector
from .inspection_contract import require_inspection_support
from .launcher import (EvaluationLaunch, launch_evaluation,
                       validate_evaluation_launch, validate_workspace)
from .lifecycle import session_status, stop_session
from .persona_preflight import require_supported_native_claims
from .personas import load_persona, persona_compatible
from .process import ProcessQueryUnavailable
from .session_stop_guard import session_stop_guard
from .profiles import (attach_persona, create_profile, load_profile,
                       validate_profile_id)
from .upstream import verify_upstream


class ResearchRun:
    """Own only the newly launched session; keep the named profile on exit."""
    def __init__(self, session_path, session, server, url, created_profile):
        run_id = session.get('run_id') if isinstance(session, dict) else None
        if not isinstance(run_id, str) or RUN_ID_RE.fullmatch(run_id) is None:
            raise ContractError('research session run ID is invalid')
        self.session_path = session_path
        self.session = session
        self.run_id = run_id
        self.server = server
        self.url = url
        self.created_profile = created_profile
        self._close_lock = Lock()
        self._browser_stop_lock = Lock()
        # The owned panel wakes directly on shutdown without an idle timer.
        self.thread = Thread(target=server.serve_forever, daemon=True) if server else None
        if self.thread is not None:
            try:
                self.thread.start()
                if not self.thread.is_alive():
                    raise ContractError('research inspector stopped during startup')
            except BaseException:
                # Thread.start() can report an error after the panel loop has
                # begun. The caller cannot own a ResearchRun that failed to
                # construct, so retire and join that loop before propagating.
                if getattr(self.thread, 'ident', None) is not None:
                    try:
                        server.shutdown()
                    finally:
                        self.thread.join(5)
                    if self.thread.is_alive():
                        raise ContractError('research inspector cleanup did not finish') from None
                raise
        self.inspector_closed = server is None
        self.stop_receipt = None

    def wait(self):
        unavailable_since = None
        while True:
            try:
                # Cooperating stop callers temporarily retire and republish the
                # contract. Read only after their guarded transition completes;
                # keep the strict missing/link/identity checks on the fresh read.
                # Use the same finite budget as this owner's normal cleanup.
                with session_stop_guard(self.session_path, time.monotonic() + 40):
                    state = session_status(self.session_path)
            except ProcessQueryUnavailable:
                # Windows may briefly deny queries while another caller closes
                # the owned process. Unknown is not exit: retry only this typed
                # OS condition, for at most two seconds without a good read.
                now = time.monotonic()
                if unavailable_since is None:
                    unavailable_since = now
                remaining = 2.0 - (now - unavailable_since)
                if remaining <= 0:
                    raise
                if self.thread is not None and not self.thread.is_alive():
                    raise ContractError('research inspector stopped unexpectedly') from None
                time.sleep(min(.05, remaining))
                continue
            unavailable_since = None
            if state.get('run_id') != self.run_id:
                raise ContractError('research session run ID changed while waiting')
            if not state['running']:
                return
            if self.thread is not None and not self.thread.is_alive():
                raise ContractError('research inspector stopped unexpectedly')
            time.sleep(.5)

    def finish_browser(self):
        """Clean up the retired owned browser while keeping its viewer alive."""
        with self._browser_stop_lock:
            if self.stop_receipt is None:
                self.stop_receipt = stop_session(
                    self.session_path, timeout_seconds=40,
                    expected_run_id=self.run_id)

    def wait_for_review(self):
        if self.thread is None:
            raise ContractError('research inspector is unavailable for review')
        while self.thread.is_alive():
            self.thread.join(.5)
        raise ContractError('research inspector stopped unexpectedly')

    def close(self):
        with self._close_lock:
            try:
                if not self.inspector_closed:
                    panel_error = None
                    server_closed = False
                    try:
                        self.server.shutdown()
                    except BaseException as exc:
                        panel_error = exc
                    try:
                        self.server.server_close()
                        server_closed = True
                    except BaseException as exc:
                        if panel_error is None:
                            panel_error = exc
                    self.thread.join(5)
                    if self.thread.is_alive():
                        raise ContractError('research inspector cleanup did not finish')
                    self.inspector_closed = server_closed
                    if panel_error is not None:
                        raise panel_error
            finally:
                self.finish_browser()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


def start_research(workspace: Path, repository_root: Path, profile_id: str, *,
                   persona_id: str | None = None, headless: bool = False,
                   executable: Path | None = None, recording_limit_mib: int | None = None,
                   profile_action: str = 'open-or-create', recording_parts: int | None = None,
                   inspect_hash_inputs: bool = False, metadata_only: bool = False,
                   extra_args: tuple[str, ...] = ()) -> ResearchRun:
    """Create/reuse a named profile and start an attested recorded session.

    Existing profile identity is never rebound by this convenience command.
    A new profile remains available after a launch failure, allowing a retry.
    The ordinary launcher still performs its runtime and identity checks.
    """
    workspace = validate_workspace(workspace, repository_root)
    validate_profile_id(profile_id)
    if profile_action not in ('open-or-create', 'open', 'create'):
        raise ContractError('invalid research profile action')
    if not isinstance(inspect_hash_inputs, bool):
        raise ContractError('hash input inspection must be boolean')
    if type(metadata_only) is not bool or (metadata_only and inspect_hash_inputs):
        raise ContractError('metadata-only research cannot request private hash inputs')
    allowlist = 'research-v3' if inspect_hash_inputs else 'fingerprint-v2'
    require_inspection_support(repository_root, allowlist)
    upstream = verify_upstream(repository_root)
    if executable is None:
        executable = (workspace/'chromium/src'/upstream['build']['output_directory']/
                      ('chrome.exe' if os.name == 'nt' else 'chrome'))
    config = validate_evaluation_launch(EvaluationLaunch(
        executable, workspace, profile_id=profile_id, headless=headless,
        live_trace=True, inspect_values=not metadata_only, extra_args=extra_args,
        trace_scope='broad', recording_limit_mib=recording_limit_mib,
        recording_parts=recording_parts, inspection_allowlist=allowlist))
    # Resolve the executable before creating a persistent profile. The launch
    # checks it again after profile setup; this is not a cached attestation.
    executable_evidence(repository_root, executable, allow_unverified=False)
    if persona_id is not None:
        validate_profile_id(persona_id)
        persona = load_persona(workspace, persona_id)
        major = int(upstream['chromium']['version'].split('.')[0])
        if not persona_compatible(persona, engine='chromium', product='browser-core',
                                  major=major, device_class='desktop'):
            raise ContractError('research requires an active desktop persona for this Browser Core version')
        require_supported_native_claims(persona)
    registry = workspace/'profiles/registry'/f'{profile_id}.json'
    created = not os.path.lexists(registry)
    if profile_action == 'open':
        load_profile(workspace, profile_id)
        created = False
    elif profile_action == 'create' and not created:
        raise ContractError('profile already exists; open its saved profile or choose another name')
    if created:
        create_profile(workspace, profile_id)
        if persona_id is not None:
            attach_persona(workspace, profile_id, persona_id)
    else:
        profile = load_profile(workspace, profile_id)
        if persona_id is not None and (profile.get('persona') or {}).get('id') != persona_id:
            raise ContractError('existing profile has a different identity; use its saved identity or a new profile name')
    session_path, session = launch_evaluation(config, repository_root)
    run_id = session.get('run_id') if isinstance(session, dict) else None
    if not isinstance(run_id, str) or RUN_ID_RE.fullmatch(run_id) is None:
        raise ContractError('research session run ID is invalid')
    server = None
    try:
        if metadata_only:
            return ResearchRun(session_path, session, None, None, created)
        server, url = create_inspector(session_path, repository_root, allow_context_identification=True)
        return ResearchRun(session_path, session, server, url, created)
    except BaseException:
        try:
            if server is not None:
                server.server_close()
        finally:
            stop_session(session_path, timeout_seconds=40,
                         expected_run_id=run_id)
        raise
