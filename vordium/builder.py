"""Builder codes: a fee an app or bot (the *builder*) adds to the orders it sends, up to what the trader approved.

Three signed operations, each an EIP-712 struct in the ``VordCore`` domain (the same domain as orders), signed as 65
bytes ``r||s||v``:

    ApproveBuilderFee   POST /builder/approve   the trader's own key: let ``builder`` charge up to ``maxFeeCbps``
    PlaceOrderV3        POST /order/place       an order that names a builder and its fee (``builderFeeCbps``)
    ClaimBuilderFees    POST /builder/claim     the builder's own key: move its accrued fees to its balance

A revoke is an ``ApproveBuilderFee`` with ``maxFeeCbps`` 0.

UNITS -- fees are in ``cbps``, hundredths of a basis point: 1,000 cbps = 0.1 %, 500 cbps = 5 bps = 0.05 %. A builder
fee is charged on the order's filled value, on top of the trading fee. The network publishes its limits in its reads:
the cap per market kind (``caps_cbps`` {perps, spot} of the stats read), the most builders an account may approve
(``max`` of the approvals read), and the account value a builder needs for orders that name it to be accepted
(``min_account_value_6dec``, with ``account_value_ok``). The SDK checks against these reads, never against fixed
figures; a read without them is refused before signing.

READS -- ``GET /builder/approvals/<address>`` (the builders an account approved, the count, the most it may approve,
its approval nonce) and ``GET /builder/stats/<address>`` (a builder's volume, fees, unclaimed and claimed amounts, the
caps, whether its account value is enough, its claim nonce). Both carry ``active``: whether builder fees are switched
on at the network's next block. Nothing here is signed while ``active`` is not true.

Every check here runs before anything is signed; a refusal raises :class:`BuilderError` with the network's own code
and a plain sentence. The pure half (type strings, digests, bodies) sends nothing; :class:`BuilderOps` sends and then
reads the chain back.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, Dict, List, Mapping, Optional, Tuple

from eth_utils import keccak, to_checksum_address

from .account_ops import AccountOps, Result

# -- the type strings (byte for byte as the network signs them) --------------------------------------------------------
APPROVE_BUILDER_FEE = "ApproveBuilderFee(address user,address builder,uint32 maxFeeCbps,uint64 nonce,uint64 validUntil)"
CLAIM_BUILDER_FEES = "ClaimBuilderFees(address builder,uint64 nonce,uint64 validUntil)"
PLACE_ORDER_V3 = ("PlaceOrderV3(address owner,uint32 pairId,uint8 side,uint128 size,uint64 price,uint32 leverageBps,"
                  "uint8 orderType,bool reduceOnly,bool postOnly,uint64 triggerPrice8dec,uint8 triggerDir,"
                  "uint8 timeInForce,uint64 expiresAt,uint64 clientNonce,uint64 validUntil,uint64 worstPrice8dec,"
                  "string source,address builder,uint32 builderFeeCbps)")

TYPES: Dict[str, str] = {"ApproveBuilderFee": APPROVE_BUILDER_FEE, "ClaimBuilderFees": CLAIM_BUILDER_FEES,
                         "PlaceOrderV3": PLACE_ORDER_V3}
#: keccak256 of each type string, as published with the network's vectors (checked against the strings in the tests).
TYPEHASHES: Dict[str, str] = {
    "ApproveBuilderFee": "0xe63fa83d341ba3dfe6b57bc221d00f03edce9f043613f5243078e294ff0c849a",
    "ClaimBuilderFees": "0xd5774785d91fe35740b030286fca8338c06609f3ba19595ee63a21d6e020500f",
    "PlaceOrderV3": "0xe328eb68341f2a35a289620b7147dc72672f356f6dff3b10098ae02f19a6c5d5",
}

ROUTES = {"ApproveBuilderFee": "/builder/approve", "ClaimBuilderFees": "/builder/claim", "PlaceOrderV3": "/order/place"}

#: The market kinds a builder fee cap is published for (``caps_cbps`` of the stats read).
MARKET_KINDS = ("perps", "spot")
#: The approval deadline: at most this many seconds ahead of the network's block time.
MAX_AHEAD_S = 300
#: The deadline used when the caller gives none.
DEFAULT_AHEAD_S = 120
#: The ``source`` an order placed through this SDK signs.
SOURCE = "sdk"

class BuilderError(ValueError):
    """A builder operation the network would refuse, caught before anything was signed. ``code`` is the network's code
    for the same refusal; the message says what to do."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


class BuilderNotActive(BuilderError):
    """Builder fees are not active on this network (the reads' ``active`` is not true). Nothing was signed."""

    def __init__(self, message: str = "Builder fees are not active on this network, so nothing was signed."):
        super().__init__("builder_not_active", message)


# -- pure checks ---------------------------------------------------------------------------------------------------------
def _addr(value: Any, what: str) -> str:
    try:
        return to_checksum_address(str(value))
    except Exception:
        raise BuilderError("invalid_body", f"{what} must be an address (0x and 40 hex characters).") from None


def _uint(value: Any, bits: int, what: str) -> int:
    v = int(value) if isinstance(value, str) and value.strip().isdigit() else value
    if isinstance(v, bool) or not isinstance(v, int) or v < 0 or v >= 1 << bits:
        raise BuilderError("invalid_body", f"{what} must be a whole number from 0 to {(1 << bits) - 1}.")
    return v


def require_active(read: Any) -> None:
    """Raise :class:`BuilderNotActive` unless a builder read (approvals or stats) says ``active: true``."""
    if not (isinstance(read, Mapping) and read.get("active") is True):
        raise BuilderNotActive()


def caps_from(read: Any) -> Dict[str, int]:
    """The caps in cbps from a stats read (``caps_cbps`` {perps, spot}). A read without both is refused
    (:class:`BuilderError` ``unreadable``): the fee cannot be checked, so nothing is signed."""
    got = read.get("caps_cbps") if isinstance(read, Mapping) else None
    caps: Dict[str, int] = {}
    for k in MARKET_KINDS:
        v = got.get(k) if isinstance(got, Mapping) else None
        if isinstance(v, bool) or not isinstance(v, int) or v < 0:
            raise BuilderError("unreadable", "The network's builder read gives no fee caps (caps_cbps), so the fee "
                               "cannot be checked and nothing was signed.")
        caps[k] = v
    return caps


def check_fee(fee_cbps: Any, kind: str, caps: Mapping[str, int]) -> int:
    """A builder fee on an order, in cbps: above zero and at most the cap of ``kind`` (``perps`` or ``spot``) in
    ``caps`` (:func:`caps_from`). Raises :class:`BuilderError` (``builder_fee_zero`` / ``builder_fee_above_cap``)."""
    if kind not in MARKET_KINDS or not isinstance(caps, Mapping) or kind not in caps:
        raise BuilderError("invalid_body", "kind is perps or spot.")
    fee = _uint(fee_cbps, 32, "The builder fee")
    if fee == 0:
        raise BuilderError("builder_fee_zero", "A builder was named with a fee of 0: name no builder, or a fee above 0.")
    if fee > caps[kind]:
        raise BuilderError("builder_fee_above_cap", f"A builder fee of {fee} cbps is above the {kind} cap of "
                           f"{caps[kind]} cbps ({describe_cbps(caps[kind])}). Use a fee at or below the cap.")
    return fee


def check_max_fee(max_fee_cbps: Any, caps: Mapping[str, int]) -> int:
    """The most a builder may charge under an approval, in cbps: above zero and at most the highest cap (an approval
    covers every market; each order is still held to its own market's cap). 0 is a revoke: use
    :meth:`BuilderOps.revoke_builder_fee`."""
    fee = _uint(max_fee_cbps, 32, "The approved fee")
    if fee == 0:
        raise BuilderError("builder_fee_zero", "An approval of 0 is a revoke: use revoke_builder_fee.")
    top = max(caps[k] for k in MARKET_KINDS)
    if fee > top:
        raise BuilderError("builder_fee_above_cap", f"An approved fee of {fee} cbps is above the highest cap of {top} "
                           f"cbps ({describe_cbps(top)}). Approve a fee at or below it.")
    return fee


def describe_cbps(cbps: int) -> str:
    """A fee in plain words: 500 -> ``"5 bps (0.05%)"``."""
    bps = cbps / 100
    pct = cbps / 10_000
    b = f"{bps:g}"
    p = f"{pct:.4f}".rstrip("0").rstrip(".")
    return f"{b} bps ({p}%)"


def deadline(valid_until: Optional[int] = None, now_s: Optional[int] = None, ahead_s: int = DEFAULT_AHEAD_S) -> int:
    """The ``validUntil`` to sign (unix seconds): ``valid_until`` when given, else ``now + ahead_s``. Refused before
    signing when it is more than 300 s ahead (``approval_too_far``) or not after now (``approval_expired``)."""
    now = int(time.time()) if now_s is None else int(now_s)
    vu = now + int(ahead_s) if valid_until is None else valid_until
    if isinstance(vu, bool) or not isinstance(vu, int):
        raise BuilderError("invalid_body", "validUntil must be whole unix seconds.")
    if vu - now > MAX_AHEAD_S:
        raise BuilderError("approval_too_far", f"Not signed: the deadline is {vu - now} s ahead; the network takes at "
                           f"most {MAX_AHEAD_S} s.")
    if vu <= now:
        raise BuilderError("approval_expired", "Not signed: the deadline has already passed.")
    return vu


def approval_of(read: Any, builder: str) -> Optional[int]:
    """The fee (cbps) an approvals read shows for ``builder``, or None when it is not approved."""
    rows = read.get("approvals") if isinstance(read, Mapping) else None
    b = str(builder).lower()
    for row in rows if isinstance(rows, list) else []:
        if isinstance(row, Mapping) and str(row.get("builder", "")).lower() == b:
            v = row.get("max_fee_cbps")
            return int(v) if isinstance(v, int) and not isinstance(v, bool) else None
    return None


def check_order_builder(owner: str, builder: str, fee_cbps: int, approvals: Any, stats: Any) -> None:
    """What the network checks for an order that names a builder, from the two reads: rule active, not the account
    itself, approved at or above the fee, builder account value enough. Raises :class:`BuilderError` otherwise."""
    require_active(approvals)
    require_active(stats)
    if str(owner).lower() == str(builder).lower():
        raise BuilderError("builder_self", "An account cannot be its own builder: name another builder.")
    approved = approval_of(approvals, builder)
    if approved is None or approved == 0:
        raise BuilderError("builder_not_approved", f"The account has not approved builder {builder}: approve it first "
                           "(approve_builder_fee).")
    if fee_cbps > approved:
        raise BuilderError("builder_fee_above_approved", f"A builder fee of {fee_cbps} cbps is above the {approved} cbps "
                           "the account approved: use a lower fee, or approve a higher one.")
    if isinstance(stats, Mapping) and stats.get("account_value_ok") is False:
        need = stats.get("min_account_value_6dec")
        floor = (f"the {_usdc(int(need))} USDC minimum" if isinstance(need, str) and need.isdigit()
                 else "the network's minimum account value")
        raise BuilderError("builder_too_small", f"The builder's account value is below {floor}, so the network "
                           "refuses orders that name it. The builder must fund its account first.")


def _usdc(amount_6dec: int) -> str:
    """6-decimal USDC as a plain decimal: 100000000 -> "100", 1500000 -> "1.5"."""
    whole, frac = divmod(int(amount_6dec), 1_000_000)
    return f"{whole:,}" + (f".{frac:06d}".rstrip("0") if frac else "")


def parse_builder(builder: Any) -> Tuple[str, int]:
    """``{"address": ..., "fee_cbps": ...}`` (or ``"fee"``) as (checksummed address, fee in cbps)."""
    if not isinstance(builder, Mapping):
        raise BuilderError("invalid_body", 'builder is {"address": "0x…", "fee_cbps": 500}.')
    addr = _addr(builder.get("address"), "The builder")
    fee = builder.get("fee_cbps", builder.get("fee"))
    if fee is None:
        raise BuilderError("invalid_body", "The builder fee is missing (fee_cbps).")
    return addr, _uint(fee, 32, "The builder fee")


# -- hashing ------------------------------------------------------------------------------------------------------------
def _fields(type_string: str) -> List[Tuple[str, str]]:
    inner = type_string[type_string.index("(") + 1:-1]
    return [tuple(f.split(" ")) for f in inner.split(",")]  # type: ignore[misc]


FIELDS: Dict[str, List[Tuple[str, str]]] = {k: _fields(v) for k, v in TYPES.items()}


def _word(kind: str, value: Any) -> bytes:
    if kind == "address":
        return bytes(12) + bytes.fromhex(_addr(value, "address")[2:])
    if kind == "bool":
        return (1 if value is True else 0).to_bytes(32, "big")
    if kind == "string":
        return keccak(str(value).encode())
    return int(value).to_bytes(32, "big")


def struct_hash(primary_type: str, message: Mapping[str, Any]) -> bytes:
    """hashStruct: keccak256(typeHash || each field as one 32-byte word; a string as its keccak)."""
    enc = keccak(TYPES[primary_type].encode())
    for kind, name in FIELDS[primary_type]:
        if name not in message:
            raise BuilderError("invalid_body", f"{name} is missing from {primary_type}.")
        enc += _word(kind, message[name])
    return keccak(enc)


def digest(primary_type: str, message: Mapping[str, Any], domain_separator: bytes) -> bytes:
    """keccak256(0x1901 || domainSeparator || structHash)."""
    return keccak(b"\x19\x01" + domain_separator + struct_hash(primary_type, message))


def sign(private_key: str, d: bytes) -> str:
    """65 bytes ``r||s||v`` as 0x-hex (v = 27/28)."""
    from .account_ops import sign_digest
    return sign_digest(private_key, d)


@dataclass(frozen=True)
class Signed:
    """One signed builder operation: what was signed and the exact request body. Nothing is sent."""
    primary_type: str
    message: Dict[str, Any]
    digest: bytes
    signature: str
    route: str
    body: Dict[str, Any]


def approve_builder_fee(private_key: str, user: str, builder: str, max_fee_cbps: int, nonce: int, valid_until: int,
                        domain_separator: bytes) -> Signed:
    """ApproveBuilderFee, signed by ``user``'s own key (``builder_approval_owner_only`` otherwise). ``max_fee_cbps`` 0
    revokes. ``nonce`` is the approvals read's ``nonce`` + 1."""
    from eth_account import Account
    user = _addr(user, "The account")
    builder = _addr(builder, "The builder")
    if Account.from_key(private_key).address.lower() != user.lower():
        raise BuilderError("builder_approval_owner_only", "A builder approval is signed by the account's own key, and "
                           "this key is not the account's.")
    if user.lower() == builder.lower():
        raise BuilderError("builder_self", "An account cannot be its own builder: name another builder.")
    msg = {"user": user, "builder": builder, "maxFeeCbps": _uint(max_fee_cbps, 32, "The approved fee"),
           "nonce": _uint(nonce, 64, "nonce"), "validUntil": _uint(valid_until, 64, "validUntil")}
    d = digest("ApproveBuilderFee", msg, domain_separator)
    sig = sign(private_key, d)
    body = {"user": user, "builder": builder, "maxFeeCbps": msg["maxFeeCbps"], "nonce": msg["nonce"],
            "validUntil": msg["validUntil"], "signature": sig}
    return Signed("ApproveBuilderFee", msg, d, sig, ROUTES["ApproveBuilderFee"], body)


def claim_builder_fees(private_key: str, builder: str, nonce: int, valid_until: int, domain_separator: bytes) -> Signed:
    """ClaimBuilderFees, signed by the builder's own key. ``nonce`` is the stats read's ``claim_nonce`` + 1."""
    from eth_account import Account
    builder = _addr(builder, "The builder")
    if Account.from_key(private_key).address.lower() != builder.lower():
        raise BuilderError("bad_signature", "Builder fees are claimed with the builder's own key, and this key is not "
                           "the builder's.")
    msg = {"builder": builder, "nonce": _uint(nonce, 64, "nonce"), "validUntil": _uint(valid_until, 64, "validUntil")}
    d = digest("ClaimBuilderFees", msg, domain_separator)
    sig = sign(private_key, d)
    body = {"builder": builder, "nonce": msg["nonce"], "validUntil": msg["validUntil"], "signature": sig}
    return Signed("ClaimBuilderFees", msg, d, sig, ROUTES["ClaimBuilderFees"], body)


_SIDE_NAMES = {0: "buy", 1: "sell"}
_ORDER_TYPE_NAMES = {0: "Market", 1: "Limit"}


def place_order_v3(private_key: str, owner: str, pair_id: int, side: int, size_18dec: int, price_8dec: int,
                   leverage_bps: int, order_type: int, client_nonce: int, valid_until: int, builder: str,
                   builder_fee_cbps: int, domain_separator: bytes, *, reduce_only: bool = False,
                   post_only: bool = False, source: str = SOURCE, worst_price_8dec: int = 0) -> Signed:
    """PlaceOrderV3: a Market (0) or Limit (1) perps order that names ``builder`` and its fee. Signed by the owner, its
    session key or one of its agents; the body carries no session field (the network recovers the signer).

    A market order carries a worst price, or none: ``worst_price_8dec`` (on the market's price step) is signed as both
    ``price`` (the slippage cap: the network refuses ``slippage`` when the market is already past it) and
    ``worstPrice8dec`` (refused ``worst_price``; a fill beyond it is not made). With none, both are 0 and the order
    has no price limit. A market order's ``price_8dec`` is 0 or equal to the worst price. A limit order signs its
    price and a worst price of 0. Stop orders cannot carry a builder fee (``builder_on_stop``)."""
    if isinstance(order_type, bool) or order_type not in _ORDER_TYPE_NAMES:
        raise BuilderError("builder_on_stop", "Only market and limit orders can carry a builder fee: place a stop "
                           "without a builder.")
    if side not in _SIDE_NAMES:
        raise BuilderError("invalid_body", "side is 0 (buy) or 1 (sell).")
    if order_type == 1 and int(price_8dec) <= 0:
        raise BuilderError("invalid_body", "A limit order needs a price.")
    worst = _uint(worst_price_8dec, 64, "The worst price")
    if order_type == 0:
        if int(price_8dec) not in (0, worst):
            raise BuilderError("invalid_body", "A market order's price is its worst price: give it as worst_price_8dec.")
        price_8dec = worst
    elif worst:
        raise BuilderError("invalid_body", "A worst price applies to a market order; a limit order's price is its limit.")
    if post_only and order_type != 1:
        raise BuilderError("invalid_body", "Post-only applies to a limit order.")
    owner = _addr(owner, "The account")
    builder = _addr(builder, "The builder")
    msg = {"owner": owner, "pairId": _uint(pair_id, 32, "pairId"), "side": side,
           "size": _uint(size_18dec, 128, "size"), "price": _uint(price_8dec, 64, "price"),
           "leverageBps": _uint(leverage_bps, 32, "leverageBps"), "orderType": order_type,
           "reduceOnly": bool(reduce_only), "postOnly": bool(post_only), "triggerPrice8dec": 0, "triggerDir": 0,
           "timeInForce": 0, "expiresAt": 0, "clientNonce": _uint(client_nonce, 64, "clientNonce"),
           "validUntil": _uint(valid_until, 64, "validUntil"), "worstPrice8dec": worst, "source": str(source),
           "builder": builder, "builderFeeCbps": _uint(builder_fee_cbps, 32, "builderFeeCbps")}
    if msg["size"] == 0:
        raise BuilderError("invalid_body", "The size is zero.")
    d = digest("PlaceOrderV3", msg, domain_separator)
    sig = sign(private_key, d)
    body: Dict[str, Any] = {"owner": owner, "pairId": msg["pairId"], "side": _SIDE_NAMES[side],
                            "size_18dec": str(msg["size"]), "orderType": _ORDER_TYPE_NAMES[order_type],
                            "leverageBps": msg["leverageBps"], "clientNonce": str(msg["clientNonce"]),
                            "validUntil": str(msg["validUntil"]), "worstPrice8dec": str(worst), "source": msg["source"],
                            "builder": builder, "builderFeeCbps": msg["builderFeeCbps"], "signature": sig}
    if msg["price"]:
        body["price_8dec"] = str(msg["price"])
    if reduce_only:
        body["reduceOnly"] = True
    if post_only:
        body["postOnly"] = True
    return Signed("PlaceOrderV3", msg, d, sig, ROUTES["PlaceOrderV3"], body)


# -- referral levels ----------------------------------------------------------------------------------------------------
#: The level fields ``GET /referral/stats/<address>`` carries while referral levels are in force.
LEVEL_FIELDS = ("level", "share_bps", "discount_bps", "l2_progress", "next_check_ms", "own_volume_6dec",
                "min_own_volume_6dec", "meets_min", "limits", "referee_volume_6dec")


@dataclass(frozen=True)
class ReferralLevel:
    """An account's referral level as the network reads it. ``level`` is ``"L1"``, ``"L2"`` or ``"PARTNER"``;
    ``share_bps`` is its share of the fee its referees actually pay, ``discount_bps`` its referees' discount;
    ``l2_progress`` is the current 30-day period (referred volume and active referees against the L2 targets);
    ``meets_min`` whether its own volume reaches the minimum a referrer needs. Amounts are 6-decimal USDC strings."""
    level: str
    share_bps: Optional[int]
    discount_bps: Optional[int]
    l2_progress: Dict[str, Any]
    next_check_ms: Optional[int]
    own_volume_6dec: Optional[str]
    min_own_volume_6dec: Optional[str]
    meets_min: Optional[bool]
    limits: Dict[str, Any]
    referee_volume_6dec: Optional[str]


def referral_level(read: Any) -> Optional[ReferralLevel]:
    """The level fields of a ``/referral/stats`` read, or None when the read carries no ``level`` (levels not in force)."""
    if not isinstance(read, Mapping) or not isinstance(read.get("level"), str):
        return None
    i = lambda k: read.get(k) if isinstance(read.get(k), int) and not isinstance(read.get(k), bool) else None
    s = lambda k: read.get(k) if isinstance(read.get(k), str) else None
    return ReferralLevel(level=read["level"], share_bps=i("share_bps"), discount_bps=i("discount_bps"),
                         l2_progress=dict(read.get("l2_progress") or {}), next_check_ms=i("next_check_ms"),
                         own_volume_6dec=s("own_volume_6dec"), min_own_volume_6dec=s("min_own_volume_6dec"),
                         meets_min=read.get("meets_min") if isinstance(read.get("meets_min"), bool) else None,
                         limits=dict(read.get("limits") or {}), referee_volume_6dec=s("referee_volume_6dec"))


# -- the client ---------------------------------------------------------------------------------------------------------
class BuilderOps(AccountOps):
    """Builder approvals, claims and reads for one account, signed with that account's own key.

    As a trader: :meth:`approve_builder_fee`, :meth:`revoke_builder_fee`, :meth:`approvals`. As a builder:
    :meth:`claim_builder_fees`, :meth:`stats`. Orders that name a builder go through
    :meth:`vordium.dex.Vordex.place_order` (``builder=``). Every write returns a :class:`~vordium.account_ops.Result`
    whose ``applied`` is True only once the chain's own read shows the change."""

    def _now_s(self) -> Optional[int]:
        try:
            ms = self._chain() if getattr(self, "_chain", None) is not None else None
        except Exception:
            ms = None
        return ms // 1000 if isinstance(ms, int) and ms > 0 else None

    # reads
    def approvals(self, user: Optional[str] = None) -> Dict[str, Any]:
        """``GET /builder/approvals/<user>`` (default: this account): ``approvals`` [{builder, max_fee_cbps}], ``count``,
        ``max``, ``nonce``, ``active``."""
        j = self._get(f"/builder/approvals/{_addr(user or self.owner, 'The account')}")
        if not isinstance(j, dict):
            raise BuilderError("unreadable", "The network did not answer the builder approvals read.")
        return j

    def stats(self, builder: Optional[str] = None) -> Dict[str, Any]:
        """``GET /builder/stats/<builder>`` (default: this account): ``volume_6dec``, ``fees_6dec``, ``unclaimed_6dec``,
        ``claimed_6dec``, ``users_30d``, ``account_value_ok``, ``claim_nonce``, ``caps_cbps``, ``active``. The fees always
        equal unclaimed plus claimed."""
        j = self._get(f"/builder/stats/{_addr(builder or self.owner, 'The builder')}")
        if not isinstance(j, dict):
            raise BuilderError("unreadable", "The network did not answer the builder stats read.")
        return j

    def referral_stats(self, address: Optional[str] = None) -> Dict[str, Any]:
        """``GET /referral/stats/<address>`` as the network answers it."""
        j = self._get(f"/referral/stats/{_addr(address or self.owner, 'The account')}")
        return j if isinstance(j, dict) else {}

    def referral_level(self, address: Optional[str] = None) -> Optional[ReferralLevel]:
        """The account's referral level (:class:`ReferralLevel`), or None when the network does not show levels."""
        return referral_level(self.referral_stats(address))

    def referral_tiers(self) -> Dict[str, Any]:
        """``GET /referral/tiers``: the ``levels`` table, the L2 rule, the partner bounds and the referee caps."""
        j = self._get("/referral/tiers")
        return j if isinstance(j, dict) else {}

    # writes
    def approve_builder_fee(self, builder: str, max_fee_cbps: int, wait_s: float = 30.0) -> Result:
        """Let ``builder`` charge this account up to ``max_fee_cbps`` per order (500 cbps = 5 bps = 0.05 %). Approving
        a builder again replaces its fee. Refused before signing when builder fees are not active, the fee is 0 or
        above the highest cap (``caps_cbps``), the builder is this account, or the account already approved the most
        builders it may (``max``)."""
        builder = _addr(builder, "The builder")
        read = self.approvals()
        require_active(read)
        caps = caps_from(self.stats(builder))
        fee = check_max_fee(max_fee_cbps, caps)
        if builder.lower() == self.owner.lower():
            raise BuilderError("builder_self", "An account cannot be its own builder: name another builder.")
        count, most = read.get("count"), read.get("max")
        if any(isinstance(x, bool) or not isinstance(x, int) for x in (count, most)):
            raise BuilderError("unreadable", "The network's approvals read gives no count or maximum, so nothing was "
                               "signed.")
        if approval_of(read, builder) is None and count >= most:
            raise BuilderError("builder_approvals_full", f"The account has approved the most builders it may "
                               f"({most}): revoke one first.")
        return self._approve(builder, fee, read, wait_s, lambda r: approval_of(r, builder) == fee,
                             "the chain does not show the approval")

    def revoke_builder_fee(self, builder: str, wait_s: float = 30.0) -> Result:
        """Withdraw the approval of ``builder`` (an approval of 0). Orders that name it are refused from then on."""
        builder = _addr(builder, "The builder")
        read = self.approvals()
        require_active(read)
        if approval_of(read, builder) is None:
            return Result(True, 0, None, "no approval to revoke")
        return self._approve(builder, 0, read, wait_s, lambda r: approval_of(r, builder) is None,
                             "the chain still shows the approval")

    def _approve(self, builder: str, fee: int, read: Mapping[str, Any], wait_s: float, shows, not_shown: str) -> Result:
        import json
        nonce = int(read.get("nonce") or 0) + 1
        s = approve_builder_fee(self.key, self.owner, builder, fee, nonce, deadline(None, self._now_s()),
                                self.separator("VordCore"))
        code, ans = self._post(s.route, json.dumps(s.body, separators=(",", ":")))

        def applied() -> bool:
            # the account's approval nonce has reached ours AND the approval reads as asked
            r = self.approvals()
            return int(r.get("nonce") or 0) >= nonce and shows(r)
        return self._outcome(code, ans, applied, wait_s, not_shown)

    def claim_builder_fees(self, wait_s: float = 30.0) -> Result:
        """Move this builder's unclaimed fees to its balance. Refused before signing when builder fees are not active
        or there is nothing to claim. Applied once the stats read shows the claim (its ``claim_nonce`` moves on)."""
        import json
        st = self.stats()
        require_active(st)
        unclaimed = st.get("unclaimed_6dec")
        if not (isinstance(unclaimed, str) and unclaimed.isdigit() and int(unclaimed) > 0):
            raise BuilderError("builder_nothing_to_claim", "There are no builder fees to claim; nothing was signed.")
        before = int(st.get("claim_nonce") or 0)
        s = claim_builder_fees(self.key, self.owner, before + 1, deadline(None, self._now_s()),
                               self.separator("VordCore"))
        code, ans = self._post(s.route, json.dumps(s.body, separators=(",", ":")))
        return self._outcome(code, ans, lambda: int(self.stats().get("claim_nonce") or 0) > before, wait_s,
                             "the chain does not show the claim")
