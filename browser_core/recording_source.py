"""Bind live, finalized and recovered reads to the original recording object."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re

from .contracts import ContractError, load_session
from .live_trace import _identity, _open_shared_source, _require_regular
from .owned_paths import directory_ancestry_binding

PREFIX_LIMIT = 64 * 1024


def validate_recording_binding(value):
    if not isinstance(value, dict) or set(value) != {
        "device",
        "inode",
        "prefix_bytes",
        "prefix_sha256",
    }:
        raise ContractError("recording file binding has invalid fields")
    for key in ("device", "inode"):
        if not isinstance(value[key], str) or not re.fullmatch(
            r"0|[1-9][0-9]{0,39}", value[key]
        ):
            raise ContractError("recording file identity is invalid")
    if (
        type(value["prefix_bytes"]) is not int
        or not 1 <= value["prefix_bytes"] <= PREFIX_LIMIT
    ):
        raise ContractError("recording binding prefix size is invalid")
    if not isinstance(value["prefix_sha256"], str) or not re.fullmatch(
        r"[0-9a-f]{64}", value["prefix_sha256"]
    ):
        raise ContractError("recording binding prefix digest is invalid")
    return dict(value)


def bind_recording_file(path: Path, expected=None):
    """Observe file identity plus a bounded immutable startup prefix.

    This is a local source binding, not an authenticity signature over future
    recording bytes. Native append-only writing remains a producer assumption.
    """
    if not isinstance(path, Path) or not path.is_absolute():
        raise ContractError("recording source must be absolute")
    expected = validate_recording_binding(expected) if expected is not None else None
    parent_ancestry = directory_ancestry_binding(
        path.parent, label="recording source parent"
    )
    named = os.lstat(path)
    _require_regular(named)
    with _open_shared_source(path) as source:
        before = os.fstat(source.fileno())
        _require_regular(before)
        if _identity(named) != _identity(before):
            raise ContractError("recording changed before opening")
        size = (
            expected["prefix_bytes"] if expected else min(before.st_size, PREFIX_LIMIT)
        )
        if not size or before.st_size < size:
            raise ContractError("recording has no bound startup prefix")
        body = source.read(size)
        after = os.fstat(source.fileno())
        _require_regular(after)
        if (
            len(body) != size
            or _identity(after) != _identity(before)
            or after.st_size < before.st_size
        ):
            raise ContractError("recording changed during prefix verification")
        named_after = os.lstat(path)
        _require_regular(named_after)
        if _identity(named_after) != _identity(before):
            raise ContractError("recording changed during prefix verification")
        if directory_ancestry_binding(
            path.parent, label="recording source parent"
        ) != parent_ancestry:
            raise ContractError("recording source parent changed during binding")
        actual = {
            "device": str(before.st_dev),
            "inode": str(before.st_ino),
            "prefix_bytes": size,
            "prefix_sha256": hashlib.sha256(body).hexdigest(),
        }
        if expected is not None and actual != expected:
            raise ContractError("recording no longer matches its original file binding")
        return actual


@dataclass(frozen=True)
class RecordingLocation:
    session: dict
    executable: Path
    path: Path
    phase: str
    browser_running: bool
    reader_runtime: dict | None = None
    recording_limit: dict | None = None


class RecordingSource:
    def __init__(
        self,
        session_path: Path,
        repository_root: Path,
        reader_executable: Path | None = None,
    ):
        if reader_executable is not None and (
            not isinstance(reader_executable, Path)
            or not reader_executable.is_absolute()
        ):
            raise ContractError("recording reader executable must be an absolute Path")
        self.session_path = session_path
        self.repository_root = repository_root
        self.reader_executable = reader_executable
        self.reader_binding = None
        self.binding = None
        self.session_binding = None
        self.retired = False
        self.finalized = False
        self.limit_binding = None
        self.interruption_binding = None
        self.parts = None

    def resolve(self):
        from .build import executable_evidence
        from .lifecycle import session_status

        session = load_session(self.session_path)
        live = session.get("live_trace")
        if live is None:
            raise ContractError("session has no live recording")
        # Only lifecycle state/time may change after publication. A replaced
        # session document cannot redirect an already-open viewer to a new run.
        binding = deepcopy(
            {k: v for k, v in session.items() if k not in ("state", "stopped_at")}
        )
        if self.session_binding is not None and self.session_binding != binding:
            raise ContractError("inspector session binding changed")

        def recheck_session_binding():
            current = load_session(self.session_path)
            current_binding = {
                k: v for k, v in current.items() if k not in ("state", "stopped_at")
            }
            if current_binding != binding:
                raise ContractError("inspector session binding changed during source resolution")

        state = session_status(self.session_path)
        if (
            state["run_id"] != session["run_id"]
            or state.get("identity_protected") is not True
            or type(state.get("running")) is not bool
            or state["state"] == "inconsistent"
        ):
            raise ContractError("recording owner state could not be verified")
        running = state["running"]

        def recheck_owner_status():
            if session_status(self.session_path) != state:
                raise ContractError("recording owner state changed during source resolution")

        build = session.get("build")
        if (
            not isinstance(session.get("executable"), str)
            or not isinstance(build, dict)
            or build.get("provenance") != "attested-browser-core"
        ):
            raise ContractError("recording requires an attested executable binding")
        producer_executable = Path(session["executable"])
        executable = self.reader_executable or producer_executable
        actual_build = executable_evidence(
            self.repository_root, executable, allow_unverified=False
        )
        same_build = actual_build == build
        if running and (
            not same_build or executable.resolve() != producer_executable.resolve()
        ):
            raise ContractError(
                "live recording executable no longer matches its session"
            )
        if not same_build:
            from .inspection_contract import recording_capture

            # A stopped recording is data, not a request to run its old browser.
            # Keep the recorded producer claim and verify the current reader
            # separately. Never guess a source for an old unbound session.
            recording_capture(session)
            if (
                set(build)
                != {
                    "provenance",
                    "executable_sha256_16",
                    "runtime_bundle_sha256_16",
                    "attestation_created_at",
                }
                or live.get("file_binding") is None
            ):
                raise ContractError(
                    "upgrade reopening requires a supported capture and persisted source/producer binding"
                )
        reader_binding = (
            str(executable.resolve()),
            json.dumps(actual_build, sort_keys=True, separators=(",", ":")),
        )
        if self.reader_binding is not None and self.reader_binding != reader_binding:
            raise ContractError(
                "recording reader changed; reopen the inspector with the verified new runtime"
            )
        reader_runtime = {
            "mode": "producer-build" if same_build else "compatible-reader",
            "producer_build": dict(build),
            "reader_build": dict(actual_build),
        }
        original = Path(live["path"])
        final = Path(session["trace_path"])
        if not original.is_absolute() or not final.is_absolute():
            raise ContractError("recording paths must be absolute")
        source_parent_ancestry = directory_ancestry_binding(
            original.parent, label="recording source parent"
        )

        def recheck_source_parent():
            if directory_ancestry_binding(
                original.parent, label="recording source parent"
            ) != source_parent_ancestry:
                raise ContractError("recording source parent changed during resolution")

        if "parts" in live:
            from .recording_parts import PartsSource

            if self.parts is None:
                self.parts = PartsSource(session)
            phase, recording_limit, _ = self.parts.describe(running=running)
            if self.retired and phase == "live-prefix":
                raise ContractError("a retired recording became live again")
            if self.finalized and phase != "finalized-recording":
                raise ContractError("finalized recording phase changed")
            try:
                actual = bind_recording_file(
                    original, self.binding or live.get("file_binding")
                )
            except OSError:
                raise ContractError("recording parts are no longer readable") from None
            current_phase, current_limit, _ = self.parts.describe(running=running)
            if current_phase != phase or current_limit != recording_limit:
                raise ContractError("recording parts marker changed during source binding")
            recheck_session_binding()
            recheck_owner_status()
            recheck_source_parent()
            self.binding = actual
            self.session_binding = binding
            self.reader_binding = reader_binding
            if phase != "live-prefix":
                self.retired = True
            if phase == "finalized-recording":
                self.finalized = True
            return RecordingLocation(
                session,
                executable,
                original,
                phase,
                running,
                reader_runtime,
                recording_limit,
            )
        for attempt in range(3):
            try:
                live_exists = os.path.lexists(original)
                final_exists = os.path.lexists(final)
                if live_exists and final_exists:
                    raise ContractError("both live and finalized recording names exist")
                if not live_exists and not final_exists:
                    raise FileNotFoundError()
                source = final if final_exists else original
                from .recording_limits import observe_recording_limit

                recording_limit, limit_binding = observe_recording_limit(
                    session, source
                )
                if (
                    self.limit_binding is not None
                    and self.limit_binding != limit_binding
                ):
                    raise ContractError("recording limit marker changed")
                from .recording_interruption import observe_interruption

                interrupted = observe_interruption(final)
                if (
                    self.interruption_binding is not None
                    and self.interruption_binding != interrupted
                ):
                    raise ContractError("recording interruption marker changed")
                if interrupted is not None and (
                    final_exists or recording_limit is not None
                ):
                    raise ContractError("recording has conflicting completion markers")
                phase = (
                    "finalized-recording"
                    if final_exists
                    else ("live-prefix" if running else "recovered-prefix")
                )
                if recording_limit is not None:
                    phase = "limited-recording"
                if interrupted is not None:
                    phase = "interrupted-recording"
                if self.retired and phase == "live-prefix":
                    raise ContractError("a retired recording became live again")
                if self.finalized and phase != "finalized-recording":
                    raise ContractError("finalized recording phase changed")
                expected = self.binding or live.get("file_binding")
                if expected is None and phase != "live-prefix":
                    raise ContractError(
                        "old session has no persisted recording binding; keep its live viewer open before shutdown"
                    )
                actual = bind_recording_file(source, expected)
                if (
                    os.path.lexists(original) != live_exists
                    or os.path.lexists(final) != final_exists
                ):
                    raise FileNotFoundError()
                if observe_recording_limit(session, source) != (
                    recording_limit,
                    limit_binding,
                ):
                    raise ContractError(
                        "recording limit marker changed during source binding"
                    )
                if observe_interruption(final) != interrupted:
                    raise ContractError(
                        "recording interruption marker changed during source binding"
                    )
                recheck_session_binding()
                recheck_owner_status()
                recheck_source_parent()
                self.binding = actual
                self.session_binding = binding
                self.reader_binding = reader_binding
                self.limit_binding = limit_binding
                self.interruption_binding = interrupted
                if phase != "live-prefix":
                    self.retired = True
                if phase == "finalized-recording":
                    self.finalized = True
                return RecordingLocation(
                    session,
                    executable,
                    source,
                    phase,
                    running,
                    reader_runtime,
                    recording_limit,
                )
            except FileNotFoundError:
                # The native final rename can happen between the two lookups
                # or between lstat/open. Re-resolve only this same bound pair.
                if attempt == 2:
                    raise ContractError("the original recording is missing") from None
            except OSError:
                raise ContractError("the original recording is not readable") from None
        raise ContractError("recording location could not be resolved")
