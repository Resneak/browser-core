from __future__ import annotations

import math


def is_ascii_decimal(value: object) -> bool:
    """Return whether *value* is non-empty ASCII decimal text."""

    return type(value) is str and value.isascii() and value.isdecimal()


def is_finite_number(value: object) -> bool:
    """Return whether *value* is an exact finite JSON numeric primitive.

    Arbitrary-size Python integers are mathematically finite and must not be
    converted to binary float merely to answer this question. Callers apply their
    own range before converting an accepted small value. Exact types deliberately
    exclude booleans and numeric subclasses with overloaded comparison methods.
    """

    return type(value) is int or (type(value) is float and math.isfinite(value))


def is_finite_binary64_number(value: object) -> bool:
    """Return whether an exact JSON number converts to a finite binary64 value."""

    maximum = float.fromhex("0x1.fffffffffffffp+1023")
    return is_finite_number(value) and -maximum <= value <= maximum
