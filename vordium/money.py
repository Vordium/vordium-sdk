"""The five money operations of the pool and staking, signed by the OWNER with ``personal_sign`` (EIP-191).

Exactly as the chain published them (with the node's own vectors in ``tests/vectors/``)::

    Vordium Admin
    Chain: <id>
    Genesis: <sha256>        <- from the activation height H only (the window before H signs nothing)
    Action: <op>
    ...the op's lines...
    Nonce: <u64>

A session key is refused on four of them (at intake, and at apply from H). ``ClaimStakingRewards`` is the
one exception: the owner OR one of its live session keys may sign it, and it pays only the owner. Addresses are written
lower-case in the message and the body, as the vectors are. The web app builds the same bytes;
a cross-check holds the two to identical output.

Pass the phase from :func:`vordium.rollb.read_signing_phase`, read just before signing.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Tuple

from eth_account import Account
from eth_account.messages import encode_defunct

from .rollb import SigningPhase, with_genesis_line

MONEY_OPS = ("VlpDeposit", "VlpWithdraw", "Stake", "Unstake", "ClaimStakingRewards")
MONEY_ROUTES = {"VlpDeposit": "/vlp/deposit", "VlpWithdraw": "/vlp/withdraw", "Stake": "/staking/stake",
                "Unstake": "/staking/unstake", "ClaimStakingRewards": "/staking/claim"}
#: "owner" = the owner's key only; "owner-or-session" = the owner or one of its live session keys.
MONEY_SIGNER = {"VlpDeposit": "owner", "VlpWithdraw": "owner", "Stake": "owner", "Unstake": "owner",
                "ClaimStakingRewards": "owner-or-session"}

_ADDRESS = re.compile(r"^0x[0-9a-fA-F]{40}$")
_SIGNATURE = re.compile(r"^0x[0-9a-f]{130}$")
_U64_MAX = 2**64 - 1
_U128_MAX = 2**128 - 1
_MAX_SAFE = 2**53 - 1


class MoneyOpError(ValueError):
    """A money operation that cannot be built as given."""


def _addr(v: Any, what: str) -> str:
    if not isinstance(v, str) or not _ADDRESS.match(v):
        raise MoneyOpError(f"{what} is not an address")
    return v.lower()


def _uint(v: Any, mx: int, what: str) -> int:
    if isinstance(v, bool) or not isinstance(v, int) or v < 0 or v > mx:
        raise MoneyOpError(f"{what} is not a whole number in range")
    return v


def _json_u64(v: int, what: str) -> int:
    """A u64 written as a JSON NUMBER in the body must stay exact there."""
    if v > _MAX_SAFE:
        raise MoneyOpError(f"{what} is past the exact-integer range")
    return v


def _layout(op: str, a: Dict[str, Any]) -> Tuple[str, List[str], Dict[str, Any]]:
    """The action name, the lines after ``Action:`` and the body fields, in the vectors' order."""
    if op == "VlpDeposit":
        user, amt, n = _addr(a.get("user"), "user"), _uint(a.get("amount_6dec"), _U64_MAX, "amount"), _uint(a.get("nonce"), _U64_MAX, "nonce")
        return "Vlp Deposit", [f"User: {user}", f"Amount 6dec: {amt}", f"Nonce: {n}"], \
            {"user": user, "amount_6dec": _json_u64(amt, "amount_6dec"), "nonce": _json_u64(n, "nonce")}
    if op == "VlpWithdraw":
        user, sh, n = _addr(a.get("user"), "user"), _uint(a.get("shares"), _U128_MAX, "shares"), _uint(a.get("nonce"), _U64_MAX, "nonce")
        return "Vlp Withdraw", [f"User: {user}", f"Shares: {sh}", f"Nonce: {n}"], \
            {"user": user, "shares": str(sh), "nonce": _json_u64(n, "nonce")}
    if op == "Stake":
        owner, amt = _addr(a.get("owner"), "owner"), _uint(a.get("amount"), _U128_MAX, "amount")
        lock, n = _uint(a.get("lock_ms"), _U64_MAX, "lock"), _uint(a.get("nonce"), _U64_MAX, "nonce")
        return "Stake", [f"Owner: {owner}", f"Amount: {amt}", f"Lock Ms: {lock}", f"Nonce: {n}"], \
            {"owner": owner, "amount": str(amt), "lock_ms": _json_u64(lock, "lock_ms"), "nonce": _json_u64(n, "nonce")}
    if op == "Unstake":
        owner, n = _addr(a.get("owner"), "owner"), _uint(a.get("nonce"), _U64_MAX, "nonce")
        return "Unstake", [f"Owner: {owner}", f"Nonce: {n}"], {"owner": owner, "nonce": _json_u64(n, "nonce")}
    if op == "ClaimStakingRewards":
        owner, n = _addr(a.get("owner"), "owner"), _uint(a.get("nonce"), _U64_MAX, "nonce")
        return "Claim Staking Rewards", [f"Owner: {owner}", f"Nonce: {n}"], {"owner": owner, "nonce": _json_u64(n, "nonce")}
    raise MoneyOpError(f"{op} is not a money operation ({', '.join(MONEY_OPS)})")


def money_message(op: str, args: Dict[str, Any], chain_id: int, phase: SigningPhase) -> str:
    """The exact text to sign, for the phase a signature made now lands in. Raises
    :class:`vordium.rollb.SigningPaused` in the window before H or when the format cannot be confirmed.

    ``args``: VlpDeposit ``user, amount_6dec, nonce`` · VlpWithdraw ``user, shares, nonce`` · Stake ``owner, amount
    (18-dec), lock_ms, nonce`` · Unstake / ClaimStakingRewards ``owner, nonce``."""
    if isinstance(chain_id, bool) or not isinstance(chain_id, int) or chain_id <= 0:
        raise MoneyOpError("the chain id is not known")
    action, lines, _ = _layout(op, args)
    return "\n".join(with_genesis_line(["Vordium Admin", f"Chain: {chain_id}", f"Action: {action}", *lines], phase))


def money_body(op: str, args: Dict[str, Any], signature: str) -> Dict[str, Any]:
    """The exact POST body for ``MONEY_ROUTES[op]``, carrying the signature over :func:`money_message`."""
    s = signature.lower() if isinstance(signature, str) else ""
    if not _SIGNATURE.match(s):
        raise MoneyOpError("the signature is not 65 bytes of hex")
    return {**_layout(op, args)[2], "signature": s}


def sign_money_op(private_key: str, op: str, args: Dict[str, Any], chain_id: int, phase: SigningPhase,
                  by: str = "owner") -> Dict[str, Any]:
    """Sign one money op (65-byte ``r||s||v`` over the EIP-191 message) and return the POST body.

    ``by`` says whose key ``private_key`` is: ``"owner"``, or ``"session"`` -- allowed only for
    ``ClaimStakingRewards``; the chain refuses a session key on the other four. The SDK checks only the rule, not that
    the key really is the owner's: the chain recovers the signer and refuses a stranger."""
    if by not in ("owner", "session"):
        raise MoneyOpError('by is "owner" or "session"')
    if by == "session" and MONEY_SIGNER.get(op) != "owner-or-session":
        raise MoneyOpError("this operation must be signed with the owner's key; a session key may not move funds")
    msg = money_message(op, args, chain_id, phase)
    sig = Account.sign_message(encode_defunct(text=msg), private_key=private_key).signature.hex()
    return money_body(op, args, "0x" + sig.removeprefix("0x"))


def to_units(text: str, decimals: int) -> "int | None":
    """An amount written as text ("25", "25.5") as exact integer units of ``decimals`` places; None when it is not a
    plain non-negative decimal or has more places than the unit holds (never rounded)."""
    m = re.match(r"^(\d+)(?:\.(\d*))?$", str(text).strip(), flags=re.ASCII)
    if not m:
        return None
    frac = m.group(2) or ""
    if len(frac) > decimals:
        return None
    return int(m.group(1)) * 10**decimals + int((frac + "0" * decimals)[:decimals] or "0")


def shares_for(amount_6dec: int, held_shares: int, held_value_6dec: int) -> "int | None":
    """Shares to burn for a USDC amount, proportional to what the chain says the holding is worth, never above it."""
    if held_shares <= 0 or held_value_6dec <= 0 or amount_6dec <= 0:
        return None
    s = (held_shares * amount_6dec) // held_value_6dec
    return min(s, held_shares)
