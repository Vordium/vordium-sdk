"""Agent names (from the activation height). Clients normalise, consensus judges.

This checks the part of the chain's rule that needs no chain state, exactly as written, so the SDK never refuses a
name the chain would accept for its FORM, nor signs one the chain refuses for its form:

* normalise before signing: NFKC, every run of ASCII whitespace becomes one space, no space at either end;
* then the chain's rule, checked in the chain's own step order, so that when a name breaks several rules the reason
  given is the one the chain would give: 1 NonAscii, 2 ControlChar, 3 BadChar (only ``A-Z a-z 0-9 space - _ .``),
  4 TooShort / TooLong (3-32 bytes), 5 NotCanonical (no leading, trailing or double space), 6 NoAlphanumeric,
  7 Reserved (the skeleton -- lower-case, with ``space - _ .`` removed -- contains a reserved word).
  ``refusal_step()`` names the step.

NOT checked here, because they depend on chain state the SDK cannot read exactly: uniqueness among the owner's live
agents, the rename cooldown (chain time) and the live-agent limit -- the chain judges those (the network spec publishes
the cooldown and the limit under ``agents.nameRule``). The default reserved-word list is used; pass ``reserved=`` to
check against another list.

The Vordex web app applies the same rule; a cross-check holds the two to identical answers.
"""

from __future__ import annotations

import re
import unicodedata
from typing import Optional, Sequence, Tuple

NAME_MIN_BYTES = 3
NAME_MAX_BYTES = 32
RESERVED_WORDS_DEFAULT: Tuple[str, ...] = (
    "admin", "helpdesk", "moderator", "official", "support", "validator", "vordex", "vordium", "vordscan",
)

_WS = re.compile(r"[ \t\n\r\f\v]+")
# fullmatch, never `$`: in Python `$` also matches before a trailing newline, in JavaScript it does not
_CHARS = re.compile(r"[A-Za-z0-9 \-_.]+")
_ALNUM = re.compile(r"[A-Za-z0-9]")
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")


class InvalidAgentName(ValueError):
    """A name the chain's rule refuses (``str(e)`` is the plain-words reason)."""


def _strip_one(s: str) -> str:
    if s.startswith(" "):
        s = s[1:]
    if s.endswith(" "):
        s = s[:-1]
    return s


def normalize_name(raw: str) -> str:
    """What is signed: NFKC, every run of ASCII whitespace becomes one space, no space at either end."""
    return _strip_one(_WS.sub(" ", unicodedata.normalize("NFKC", raw)))


#: short alias
normalize = normalize_name


def name_skeleton(name: str) -> str:
    """Lower-case, with ``space - _ .`` removed: what reserved words are matched in."""
    return re.sub(r"[ \-_.]", "", name.lower())


def _judge(name: str, reserved: Sequence[str]) -> Optional[Tuple[str, str]]:
    """``None`` when the rule accepts ``name``, else ``(step, reason)`` for the first failing step, in the chain's order."""
    if not name:
        return "TooShort", "Enter a name."
    if any(ord(c) > 0x7F for c in name):
        return "NonAscii", "Use plain letters and digits: no accents, emoji or other symbols."
    if _CONTROL.search(name):
        return "ControlChar", "No tabs, line breaks or other control characters."
    if not _CHARS.fullmatch(name):
        return "BadChar", "Use only letters, digits, spaces, hyphens (-), underscores (_) and dots (.)."
    if len(name) < NAME_MIN_BYTES:
        return "TooShort", f"Use at least {NAME_MIN_BYTES} characters."
    if len(name) > NAME_MAX_BYTES:
        return "TooLong", f"Use at most {NAME_MAX_BYTES} characters."
    if name.startswith(" ") or name.endswith(" ") or "  " in name:
        return "NotCanonical", "No space at the start or end, and no double spaces."
    if not _ALNUM.search(name):
        return "NoAlphanumeric", "Include at least one letter or digit."
    sk = name_skeleton(name)
    for w in reserved:
        if w in sk:
            return "Reserved", f'A name can\'t contain the reserved word "{w}".'
    return None


def check_name(name: str, reserved: Sequence[str] = RESERVED_WORDS_DEFAULT) -> Tuple[bool, str]:
    """Check an ALREADY-normalised name. Returns ``(True, name)`` or ``(False, reason)``."""
    j = _judge(name, reserved)
    return (True, name) if j is None else (False, j[1])


def refusal_step(name: str, reserved: Sequence[str] = RESERVED_WORDS_DEFAULT) -> Optional[str]:
    """The chain's step that refuses an ALREADY-normalised name (``"NonAscii"``, ``"ControlChar"``, ``"BadChar"``,
    ``"TooShort"``, ``"TooLong"``, ``"NotCanonical"``, ``"NoAlphanumeric"`` or ``"Reserved"``), or ``None`` when the
    rule accepts it. An empty name is ``"TooShort"``."""
    j = _judge(name, reserved)
    return None if j is None else j[0]


def prepare_name(raw: str, reserved: Sequence[str] = RESERVED_WORDS_DEFAULT) -> Tuple[bool, str]:
    """Normalise then check -- ``(True, normalised_name)`` or ``(False, reason)``."""
    return check_name(normalize(raw), reserved)


def require_name(raw: str, reserved: Sequence[str] = RESERVED_WORDS_DEFAULT) -> str:
    """The normalised name, or raise :class:`InvalidAgentName` with the reason."""
    ok, out = prepare_name(raw, reserved)
    if not ok:
        raise InvalidAgentName(out)
    return out


def short_address(addr: str) -> str:
    """``0xAbCd…1234`` from an address, exactly as given (pass it checksummed)."""
    return f"{addr[:6]}…{addr[-4:]}" if len(addr) > 10 else addr


def agent_display_name(name: Optional[str], addr: str) -> str:
    """Display form: ``<name> · 0xAbCd…1234``, else ``Unnamed agent · 0xAbCd…1234``."""
    n = name.strip() if isinstance(name, str) else ""
    return f"{n or 'Unnamed agent'} · {short_address(addr)}"
