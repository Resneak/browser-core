"""Recognize an interrupted native writer after it closes its retained prefix.

This local marker has the same producer trust boundary as a completed filename.
It contains no error text or captured values and never certifies completeness.
"""
from pathlib import Path
import os

from .contracts import ContractError
from .live_trace import _identity, _open_shared_source, _require_regular


def interruption_marker_path(final: Path) -> Path:
    return Path(str(final) + '.interrupted')


def observe_interruption(final: Path):
    path = interruption_marker_path(final)
    try:
        named = os.lstat(path)
    except FileNotFoundError:
        return None
    except OSError:
        raise ContractError('recording interruption marker is not readable') from None
    try:
        _require_regular(named)
        with _open_shared_source(path) as stream:
            actual = os.fstat(stream.fileno())
            _require_regular(actual)
            binding = (*_identity(actual), actual.st_size, actual.st_mtime_ns)
            if binding != (*_identity(named), named.st_size, named.st_mtime_ns) or actual.st_size:
                raise ContractError('recording interruption marker is invalid')
        named_after = os.lstat(path)
        _require_regular(named_after)
        if binding != (*_identity(named_after), named_after.st_size, named_after.st_mtime_ns):
            raise ContractError('recording interruption marker changed during observation')
        return binding
    except OSError:
        raise ContractError('recording interruption marker is not readable') from None
