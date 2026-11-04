from __future__ import annotations

import re

import pytest

from browser_core.errors import ContractError, safe_failure_receipt


@pytest.mark.parametrize(
    ("exc", "category"),
    [
        (ContractError(r"private C:\\customer\\capture.json"), "contract-failure"),
        (RuntimeError("private bearer token abc123"), "execution-failure"),
    ],
)
def test_safe_failure_receipt_is_deterministic_and_value_free(
    exc: BaseException,
    category: str,
) -> None:
    first = safe_failure_receipt(exc)
    assert first == safe_failure_receipt(exc)
    assert re.fullmatch(rf"{category}; diagnostic_sha256_16=[0-9a-f]{{16}}", first)
    assert "private" not in first
    assert "customer" not in first
    assert "token" not in first


def test_safe_failure_receipt_requires_an_exception() -> None:
    with pytest.raises(TypeError, match="requires an exception"):
        safe_failure_receipt("not an exception")  # type: ignore[arg-type]


def test_safe_failure_receipt_survives_broken_exception_formatter() -> None:
    class BrokenMessageError(RuntimeError):
        def __str__(self) -> str:
            raise ValueError("private formatter detail")

    exc = BrokenMessageError("private capture path")
    first = safe_failure_receipt(exc)
    assert first == safe_failure_receipt(exc)
    assert re.fullmatch(r"execution-failure; diagnostic_sha256_16=[0-9a-f]{16}", first)
    assert "private" not in first
