from __future__ import annotations

from browser_core.numeric import (
    is_ascii_decimal,
    is_finite_binary64_number,
    is_finite_number,
)


class IntSubclass(int):
    pass


class StrSubclass(str):
    pass


def test_ascii_decimal_accepts_only_exact_ascii_digit_text() -> None:
    assert is_ascii_decimal("0") is True
    assert is_ascii_decimal("153") is True
    for value in ("", "١٥٣", "１２", "+1", " 1", 1, StrSubclass("1")):
        assert is_ascii_decimal(value) is False


def test_finite_number_accepts_exact_json_numbers_without_float_conversion() -> None:
    assert is_finite_number(0) is True
    assert is_finite_number(-1) is True
    assert is_finite_number(1.5) is True
    assert is_finite_number(10**10_000) is True


def test_finite_number_rejects_nonfinite_boolean_and_numeric_subclass_values() -> None:
    for value in (
        True,
        False,
        float("nan"),
        float("inf"),
        float("-inf"),
        IntSubclass(1),
        "1",
        None,
    ):
        assert is_finite_number(value) is False


def test_binary64_number_requires_finite_representable_range() -> None:
    assert is_finite_binary64_number(10**308) is True
    assert is_finite_binary64_number(float.fromhex("0x1.fffffffffffffp+1023")) is True
    assert is_finite_binary64_number(10**400) is False
    assert is_finite_binary64_number(-(10**400)) is False
    assert is_finite_binary64_number(float("inf")) is False
    assert is_finite_binary64_number(True) is False
