"""Strict readers for the values that go into a signature.

* Whole numbers: an int (not a bool), a string of ASCII digits 0-9, or a Decimal with a whole value. A float is refused
  (it may already have lost digits), and so is a fractional value. Python also reads the digits of other scripts
  (Arabic-Indic, full-width, ...) as numbers; those are refused, so what is signed is what an ASCII reader sees.
* Addresses: 40 hex characters, with or without 0x. All lower-case or all upper-case hex is taken as written; mixed case
  is an EIP-55 checksum and must be the right one, so a single changed letter is refused instead of signed.
"""
from __future__ import annotations

import re
from decimal import Decimal
from typing import Any

from eth_utils import to_checksum_address

_DIGITS = re.compile(r"[0-9]+", re.ASCII)
_HEX40 = re.compile(r"(?:0[xX])?[0-9a-fA-F]{40}", re.ASCII)


def is_ascii_digits(v: Any) -> bool:
    """True for a non-empty string of ASCII digits 0-9 only."""
    return isinstance(v, str) and bool(_DIGITS.fullmatch(v))


def whole(v: Any, what: str = "a value") -> int:
    """``v`` as an int: an int (not a bool) or a string of ASCII digits; ValueError otherwise."""
    if isinstance(v, bool):
        raise ValueError(f"{what} is not a whole number")
    if isinstance(v, int):
        return v
    if isinstance(v, Decimal):
        if v.is_finite() and v == v.to_integral_value():
            return int(v)
        raise ValueError(f"{what} is not a whole number")
    if isinstance(v, str) and is_ascii_digits(v.strip()):
        return int(v.strip())
    raise ValueError(f"{what} is not a whole number written with the digits 0-9")


def address(v: Any, what: str = "an address") -> str:
    """The checksummed form of ``v``; ValueError for anything that is not 0x + 40 hex, or a mixed-case address whose
    EIP-55 checksum is wrong."""
    if not isinstance(v, str) or not _HEX40.fullmatch(v):
        raise ValueError(f"{what} must be 40 hex characters (with or without 0x)")
    body = v[2:] if v[:2] in ("0x", "0X") else v
    out = to_checksum_address("0x" + body.lower())
    if body != body.lower() and body != body.upper() and out[2:] != body:
        raise ValueError(f"{what} has a wrong checksum (a letter's case does not match the address); check it")
    return out
