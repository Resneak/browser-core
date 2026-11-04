"""Keep urllib body reads inside an operation's remaining time budget."""

from __future__ import annotations

import socket
from typing import Any


def clamp_urllib_response_read_timeout(
    response: Any, remaining_seconds: float
) -> bool:
    """Cap the live socket's next read; return false once the deadline expires.

    urllib's open timeout is applied to each blocking socket operation. A body
    assembled from several reads can therefore outlive the caller's deadline.
    HTTPError adds an extra ``fp`` wrapper around the same HTTPResponse socket.
    Unknown response adapters retain their own timeout and are checked after
    each read by their caller.
    """
    if remaining_seconds <= 0:
        return False
    source = response
    for _ in range(4):
        raw = getattr(source, "raw", None)
        connection = getattr(raw, "_sock", None)
        if isinstance(connection, socket.socket):
            connection.settimeout(remaining_seconds)
            break
        source = getattr(source, "fp", None)
        if source is None:
            break
    return True


def urllib_response_has_unread_declared_bytes(response: Any) -> bool:
    """Detect EOF before an HTTPResponse's declared Content-Length is consumed.

    ``HTTPResponse.read1`` returns an empty block on premature EOF without
    raising ``IncompleteRead`` and leaves its ``length`` count positive.
    Call this only after a bounded body read has reached EOF.
    """
    remaining = getattr(response, "length", None)
    return type(remaining) is int and remaining > 0
