from __future__ import annotations

import hashlib
from collections.abc import Callable, Collection
from functools import wraps
from typing import Any, ParamSpec, TypeVar


class ContractError(ValueError):
    """A stable, user-facing Browser Core contract violation."""


class PersonaRealizationError(ContractError):
    """Measured native identity claims differ from the selected persona."""


class ProfileCreationRollbackError(ContractError):
    """Creation failed and cleanup of its owned data could not be confirmed."""


_P = ParamSpec("_P")
_R = TypeVar("_R")


def require_renderer_document(
    document: object,
    *,
    schema: str,
    required: Collection[str],
    label: str,
) -> dict[str, Any]:
    """Require the stable outer shape shared by portable text renderers.

    Producer output is already typed, but rendered artifacts are commonly copied
    between machines or edited before inspection.  A schema-shaped sparse object
    must not turn into plausible prose, and a foreign schema value must never be
    echoed back as part of a public failure.
    """
    if not isinstance(document, dict):
        raise ContractError(f"rendered {label} input must be an object")
    if document.get("schema") != schema:
        raise ContractError(f"rendered {label} schema is invalid")
    if not set(required) <= set(document):
        raise ContractError(f"rendered {label} structure is invalid")
    return document


def normalize_renderer_failures(
    label: str,
) -> Callable[[Callable[_P, _R]], Callable[_P, _R]]:
    """Normalize malformed portable renderer inputs to a value-free error.

    Memory, process, and interpreter-shutdown failures intentionally remain
    outside this guard.  The caught classes are ordinary data-shape failures
    that would otherwise expose implementation details such as a missing key.
    """

    def decorate(function: Callable[_P, _R]) -> Callable[_P, _R]:
        @wraps(function)
        def wrapped(*args: _P.args, **kwargs: _P.kwargs) -> _R:
            try:
                return function(*args, **kwargs)
            except ContractError:
                raise
            except (
                LookupError,
                AttributeError,
                TypeError,
                ValueError,
                OverflowError,
                UnicodeError,
                RecursionError,
            ):
                raise ContractError(f"rendered {label} structure is invalid") from None

        return wrapped

    return decorate


def safe_failure_receipt(exc: BaseException) -> str:
    """Return a deterministic failure category without echoing exception text."""
    if not isinstance(exc, BaseException):
        raise TypeError("failure receipt requires an exception")
    category = "contract-failure" if isinstance(exc, ContractError) else "execution-failure"
    try:
        message = str(exc)
    except Exception:
        message = "<unrenderable>"
    digest = hashlib.sha256(
        f"{type(exc).__name__}\0{message}".encode("utf-8", errors="replace")
    ).hexdigest()[:16]
    return f"{category}; diagnostic_sha256_16={digest}"
