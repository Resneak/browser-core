"""Bound native recording size and recognize its create-only stop marker.

The marker is a local producer signal, like the finalized filename, not an
authenticity signature. It is published only after the bound writer closes.
"""

from __future__ import annotations

import os
from pathlib import Path

from .contracts import ContractError

MIB = 1024 * 1024
DEFAULT_LIMIT_MIB = 1024
MIN_LIMIT_MIB = 4


def recording_limit_bytes(limit_mib: int | None, *, live: bool) -> int | None:
    if limit_mib is not None and (
        type(limit_mib) is not int
        or not MIN_LIMIT_MIB <= limit_mib <= DEFAULT_LIMIT_MIB
    ):
        raise ContractError("recording limit must be an integer from 4 to 1024 MiB")
    if not live:
        if limit_mib is not None:
            raise ContractError("recording limit requires live recording")
        return None
    return (DEFAULT_LIMIT_MIB if limit_mib is None else limit_mib) * MIB


def validate_byte_limit(value):
    if (
        type(value) is not int
        or not MIN_LIMIT_MIB * MIB <= value <= DEFAULT_LIMIT_MIB * MIB
        or value % MIB
    ):
        raise ContractError("session recording byte limit is invalid")
    return value


def limit_marker_path(final_path: Path) -> Path:
    return Path(str(final_path) + ".limit")


def observe_recording_limit(session: dict, source: Path):
    """Return a checked local marker and its immutable identity, or absence."""
    from .live_trace import _identity, _open_shared_source, _require_regular

    live = session.get("live_trace") or {}
    if "parts" in live:
        from .recording_parts import PartsSource

        parts = PartsSource(session)
        _, limit, _ = parts.describe(running=True)
        return limit, parts.markers.get("limit")
    if "byte_limit" not in live:
        return None, None
    limit = validate_byte_limit(live["byte_limit"])
    marker = limit_marker_path(Path(session["trace_path"]))
    try:
        named = os.lstat(marker)
    except FileNotFoundError:
        try:
            recorded = os.lstat(source)
        except OSError:
            raise ContractError("recording source could not be inspected") from None
        _require_regular(recorded)
        if recorded.st_size > limit:
            raise ContractError("recording exceeds its byte limit")
        return None, None
    except OSError:
        raise ContractError("recording limit marker could not be inspected") from None
    try:
        _require_regular(named)
        with _open_shared_source(marker) as stream:
            actual = os.fstat(stream.fileno())
            _require_regular(actual)
            if _identity(actual) != _identity(named) or actual.st_size != 0:
                raise ContractError("recording limit marker is invalid")
        if source != Path(live["path"]):
            raise ContractError("limited recording cannot also be finalized")
        recorded = os.lstat(source)
        _require_regular(recorded)
        if not 0 < recorded.st_size <= limit:
            raise ContractError("limited recording size disagrees with its budget")
        recorded_after = os.lstat(source)
        _require_regular(recorded_after)
        if (
            _identity(recorded_after) != _identity(recorded)
            or recorded_after.st_size != recorded.st_size
        ):
            raise ContractError("limited recording changed during observation")
        marker_after = os.lstat(marker)
        _require_regular(marker_after)
        if (
            _identity(marker_after) != _identity(actual)
            or marker_after.st_size != 0
            or marker_after.st_mtime_ns != actual.st_mtime_ns
        ):
            raise ContractError("recording limit marker changed during observation")
        identity = (*_identity(actual), actual.st_mtime_ns)
        return {
            "reason": "byte-limit",
            "byte_limit": limit,
            "written_bytes": recorded.st_size,
        }, identity
    except OSError:
        raise ContractError("recording limit marker is no longer readable") from None
