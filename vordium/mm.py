"""Market-maker API: signed batches, cancel-all, modify, Market Maker Protection, and the account reads.

Every write is EIP-712 signed in the VordCore domain (the same domain as PlaceOrder) by the account owner or a live
session key of it, and answered:

    202  {"status": "submitted", "intaken": true, "actions": [...]}   accepted for the next block, NOT yet applied
    400  {"code": "invalid_body" | "batch_size", "error": ...}   a malformed batch only: nothing is submitted
    403  {"code": "bad_signature"}
    409  {"code": "not_active"}       the release is not active on this network yet
    429  {"code": "mempool_full"}     retry after ``Retry-After`` seconds

A batch lists, per action, what committed state says at submission: ``{"index": i, "status": "accepted"}`` or
``{"index": i, "status": "refused" | "will_be_refused", "code": ..., "error": ...}`` -- ``unknown_order`` and
``insufficient_balance`` arrive here, per action. Valid actions apply; a refused one never takes the rest of the batch
with it. The chain decides again when it applies, so read the result from committed state (orders, fills, feeds) -- a
202 is a submission.

Units: prices are 8-decimal integers (``price_8dec``), sizes 18-decimal integers (``size_18dec``), USDC 6-decimal.
Nonces are UNIX milliseconds within 2 days before / 1 day after block time, each used once per account (the MMP nonce
is its own rising counter). The chain admits a batch's nonce, every client nonce and the dead-man switch's nonce through
the SAME per-account window, so a client takes all of them from one clock: :func:`nonce_clock` returns the one
:class:`NonceClock` of an account in this process, and :class:`MarketMaker` and
:class:`vordium.schedule_cancel.KeepAlive` use it by default.

The signing domain is the node's own (:mod:`vordium.node_domain`): read from the ``/status`` of the node the client posts
to, and checked against the network the caller configured, if any. A mismatch refuses before anything is signed.

Nothing here caches a chain value: limits, ticks and lots come from :meth:`MarketMaker.specs` when they are needed.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from eth_utils import keccak

from . import caps
from .node_domain import NodeDomain, NodeIdentity, read_identity

_U32 = (1 << 32) - 1
_U64 = (1 << 64) - 1
_U128 = (1 << 128) - 1

#: Action kinds as signed.
PLACE, CANCEL, CANCEL_BY_CLIENT_NONCE = 0, 1, 2
#: Order types as signed in a batch (and the names the body may carry).
ORDER_TYPES = {"market": 0, "limit": 1, "ioc": 4, "fok": 5}
#: ``side`` as signed.
SIDES = {"buy": 0, "sell": 1}

_ACTION_TYPE = ("BatchAction(uint8 kind,uint32 pairId,uint8 side,uint128 size,uint64 price,uint32 leverageBps,"
                "uint8 orderType,bool reduceOnly,bool postOnly,uint64 clientNonce,uint64 orderId)")
_BATCH_TYPE = "BatchOrders(address owner,uint64 nonce,BatchAction[] actions)" + _ACTION_TYPE
_CANCEL_ALL_TYPE = "CancelAllOrders(address owner,uint32 pairId,uint64 nonce)"
_MODIFY_V2_TYPE = "ModifyOrderV2(address owner,uint64 orderId,uint64 newPrice,uint128 newSize,uint64 clientNonce)"
_SET_MMP_TYPE = ("SetMmp(address owner,uint64 windowMs,uint32 maxFills,uint128 maxFilledNotional6dec,"
                 "uint128 maxNetSize18dec,uint64 freezeMs,uint64 nonce)")

ACTION_TYPEHASH = keccak(_ACTION_TYPE.encode())
BATCH_TYPEHASH = keccak(_BATCH_TYPE.encode())
CANCEL_ALL_TYPEHASH = keccak(_CANCEL_ALL_TYPE.encode())
MODIFY_V2_TYPEHASH = keccak(_MODIFY_V2_TYPE.encode())
SET_MMP_TYPEHASH = keccak(_SET_MMP_TYPE.encode())

#: The largest batch the chain takes (also published as ``specs.batch_max_actions``; the read wins when given).
BATCH_MAX = 50
#: ``windowMs`` and ``freezeMs`` of Market Maker Protection are at most this.
MMP_MAX_MS = 3_600_000


class MMError(ValueError):
    """An argument the chain would refuse, caught before anything is signed or sent."""


# --- refusals, in plain words ------------------------------------------------------------------------------------
#: One plain sentence per code the chain names. A caller shows ``Refusal.message``; ``code`` stays machine-readable.
MESSAGES = {
    "invalid_body": "The request was refused before any signature check; a field is missing or malformed.",
    "batch_size": "A batch holds between 1 and the published maximum of actions.",
    "unknown_order": "That order is not open on this account.",
    "insufficient_balance": "The account's free balance is too small for this.",
    "bad_signature": "The signature does not belong to the account or to a live session key of it.",
    "not_active": "The market-maker release is not active on this network yet.",
    "mempool_full": "The network is busy; try again in a moment.",
    "rate_limited": "Order rate limit reached; this order was not placed. Cancels are never limited.",
    "rate_burst": "Too many orders in one block; spread them over the next blocks.",
    "min_notional": "The order is below the smallest order size.",
    "too_many_open_orders": "The account has reached its open-order limit.",
    "price_band": "The price is too far from the mark price.",
    "price": "The price is not accepted (it may be too far from the mark price or off the tick size).",
}


def _price_band(code: Optional[str], text: str) -> bool:
    return (code or "") == "price_band" or "too far from mark" in text.lower() or "too far from the mark" in text.lower()


@dataclass(frozen=True)
class Refusal:
    """A refused request or action, named. ``retry_after`` is set when the chain says when to retry."""
    code: str
    message: str
    detail: str = ""
    retry_after: Optional[float] = None


def refusal(code: Optional[str], error: Any = "", retry_after: Optional[float] = None) -> Refusal:
    """Name a refusal. The price-band refusal is recognised by its code or its text ("price too far from mark")."""
    text = "" if error is None else str(error)
    if _price_band(code, text):
        return Refusal("price_band", MESSAGES["price_band"], text, retry_after)
    c = code or ("http_error" if not text else "refused")
    return Refusal(c, MESSAGES.get(c, text or "The request was refused."), text, retry_after)


# --- encoding ------------------------------------------------------------------------------------------------------
def _uint(v: Any, bits_max: int, name: str) -> int:
    if isinstance(v, bool):
        raise MMError(f"{name} is not a number")
    if isinstance(v, str) and v.isdigit():
        v = int(v)
    if not isinstance(v, int) or v < 0 or v > bits_max:
        raise MMError(f"{name} is out of range")
    return v


def _b(v: Any, name: str) -> bool:
    if not isinstance(v, bool):
        raise MMError(f"{name} is not true or false")
    return v


@dataclass(frozen=True)
class Action:
    """One batch action, in its signed form. Build with :func:`place`, :func:`cancel` or :func:`cancel_by_client_nonce`."""
    kind: int
    pair_id: int = 0
    side: int = 0
    size_18dec: int = 0
    price_8dec: int = 0
    leverage_bps: int = 0
    order_type: int = 0
    reduce_only: bool = False
    post_only: bool = False
    client_nonce: int = 0
    order_id: int = 0

    def struct_hash(self) -> bytes:
        return keccak(ACTION_TYPEHASH + caps._u256(self.kind) + caps._u256(self.pair_id) + caps._u256(self.side)
                      + caps._u256(self.size_18dec) + caps._u256(self.price_8dec) + caps._u256(self.leverage_bps)
                      + caps._u256(self.order_type) + caps._u256(int(self.reduce_only)) + caps._u256(int(self.post_only))
                      + caps._u256(self.client_nonce) + caps._u256(self.order_id))

    def body(self) -> Dict[str, Any]:
        """The action as the request body carries it (names for side and order type; sizes as decimal strings)."""
        if self.kind == CANCEL:
            return {"kind": "cancel", "orderId": self.order_id}
        if self.kind == CANCEL_BY_CLIENT_NONCE:
            return {"kind": "cancelByClientNonce", "clientNonce": self.client_nonce}
        otype = {v: k for k, v in ORDER_TYPES.items()}[self.order_type]
        return {"kind": "place", "pairId": self.pair_id, "side": "buy" if self.side == 0 else "sell",
                "size_18dec": str(self.size_18dec), "price_8dec": self.price_8dec, "leverageBps": self.leverage_bps,
                "orderType": otype, "postOnly": self.post_only, "reduceOnly": self.reduce_only,
                "clientNonce": self.client_nonce}


def place(pair_id: int, side: str, size_18dec: int, price_8dec: int, client_nonce: int, order_type: str = "limit",
          post_only: bool = False, reduce_only: bool = False, leverage_bps: int = 10_000) -> Action:
    """A place action. ``order_type`` is limit, ioc, fok or market; a market order carries price 0.

    Refused here (nothing signed): an unknown side/type, a post-only order that is not a resting limit, a priced market
    order, a zero size, and numbers out of their signed range."""
    if side not in SIDES:
        raise MMError(f"side is buy or sell, not {side!r}")
    if order_type not in ORDER_TYPES:
        raise MMError(f"order type is one of {sorted(ORDER_TYPES)}, not {order_type!r}")
    _b(post_only, "post_only"); _b(reduce_only, "reduce_only")
    if post_only and order_type != "limit":
        raise MMError("post-only applies to a resting limit order only")
    size = _uint(size_18dec, _U128, "size_18dec")
    if size == 0:
        raise MMError("size_18dec is zero")
    price = _uint(price_8dec, _U64, "price_8dec")
    if order_type == "market" and price != 0:
        raise MMError("a market order carries no price (price_8dec 0)")
    if order_type != "market" and price == 0:
        raise MMError(f"a {order_type} order needs a price")
    return Action(PLACE, _uint(pair_id, _U32, "pair_id"), SIDES[side], size, price,
                  _uint(leverage_bps, _U32, "leverage_bps"), ORDER_TYPES[order_type], reduce_only, post_only,
                  _uint(client_nonce, _U64, "client_nonce"), 0)


def cancel(order_id: int) -> Action:
    return Action(CANCEL, order_id=_uint(order_id, _U64, "order_id"))


def cancel_by_client_nonce(client_nonce: int) -> Action:
    return Action(CANCEL_BY_CLIENT_NONCE, client_nonce=_uint(client_nonce, _U64, "client_nonce"))


def batch_struct_hash(owner: str, nonce: int, actions: Sequence[Action]) -> bytes:
    """hashStruct(BatchOrders): ``actions`` hashed the EIP-712 way for an array of structs."""
    arr = keccak(b"".join(a.struct_hash() for a in actions))
    return keccak(BATCH_TYPEHASH + caps._addr32(owner) + caps._u256(_uint(nonce, _U64, "nonce")) + arr)


def cancel_all_struct_hash(owner: str, pair_id: int, nonce: int) -> bytes:
    return keccak(CANCEL_ALL_TYPEHASH + caps._addr32(owner) + caps._u256(_uint(pair_id, _U32, "pair_id"))
                  + caps._u256(_uint(nonce, _U64, "nonce")))


def modify_v2_struct_hash(owner: str, order_id: int, new_price_8dec: int, new_size_18dec: int, client_nonce: int) -> bytes:
    return keccak(MODIFY_V2_TYPEHASH + caps._addr32(owner) + caps._u256(_uint(order_id, _U64, "order_id"))
                  + caps._u256(_uint(new_price_8dec, _U64, "new_price_8dec"))
                  + caps._u256(_uint(new_size_18dec, _U128, "new_size_18dec"))
                  + caps._u256(_uint(client_nonce, _U64, "client_nonce")))


@dataclass(frozen=True)
class Mmp:
    """Market Maker Protection. 0 switches a limit off; all zero switches MMP off."""
    window_ms: int = 0
    max_fills: int = 0
    max_filled_notional_6dec: int = 0
    max_net_size_18dec: int = 0
    freeze_ms: int = 0

    def checked(self) -> "Mmp":
        for v, n in ((self.window_ms, "window_ms"), (self.freeze_ms, "freeze_ms")):
            if _uint(v, _U64, n) > MMP_MAX_MS:
                raise MMError(f"{n} is at most {MMP_MAX_MS} ms")
        _uint(self.max_fills, _U32, "max_fills")
        _uint(self.max_filled_notional_6dec, _U128, "max_filled_notional_6dec")
        _uint(self.max_net_size_18dec, _U128, "max_net_size_18dec")
        if (self.max_fills or self.max_filled_notional_6dec or self.max_net_size_18dec) and not self.window_ms:
            raise MMError("a limit needs a window (window_ms)")
        return self


def set_mmp_struct_hash(owner: str, mmp: Mmp, nonce: int) -> bytes:
    m = mmp.checked()
    return keccak(SET_MMP_TYPEHASH + caps._addr32(owner) + caps._u256(m.window_ms) + caps._u256(m.max_fills)
                  + caps._u256(m.max_filled_notional_6dec) + caps._u256(m.max_net_size_18dec)
                  + caps._u256(m.freeze_ms) + caps._u256(_uint(nonce, _U64, "nonce")))


def digest(struct_hash: bytes, domain_separator: Optional[bytes] = None) -> bytes:
    """keccak256(0x1901 || domainSeparator || structHash). The separator defaults to the network's VordCore domain."""
    sep = domain_separator if domain_separator is not None else caps.domain_separator()
    return keccak(b"\x19\x01" + sep + struct_hash)


def sign(private_key: str, d: bytes) -> str:
    """Sign a 32-byte digest: 65 bytes ``r||s||v`` as 0x-hex (v = 27/28)."""
    from eth_account import Account

    s = Account._sign_hash(d, private_key) if hasattr(Account, "_sign_hash") else Account.unsafe_sign_hash(d, private_key)
    h = s.signature.hex()
    return "0x" + (h[2:] if h.startswith("0x") else h)


# --- bodies --------------------------------------------------------------------------------------------------------
def batch_body(owner: str, nonce: int, actions: Sequence[Action], signature: str) -> Dict[str, Any]:
    return {"owner": owner, "nonce": int(nonce), "signature": signature, "actions": [a.body() for a in actions]}


def cancel_all_body(owner: str, pair_id: int, nonce: int, signature: str) -> Dict[str, Any]:
    return {"owner": owner, "pairId": int(pair_id), "nonce": int(nonce), "signature": signature}


def modify_body(owner: str, order_id: int, new_price_8dec: int, new_size_18dec: int, client_nonce: int,
                signature: str) -> Dict[str, Any]:
    return {"owner": owner, "orderId": int(order_id), "newPrice8dec": int(new_price_8dec),
            "newSize18dec": str(int(new_size_18dec)), "clientNonce": int(client_nonce), "signature": signature}


def mmp_body(owner: str, mmp: Mmp, nonce: int, signature: str) -> Dict[str, Any]:
    return {"owner": owner, "windowMs": mmp.window_ms, "maxFills": mmp.max_fills,
            "maxFilledNotional6dec": str(mmp.max_filled_notional_6dec), "maxNetSize18dec": str(mmp.max_net_size_18dec),
            "freezeMs": mmp.freeze_ms, "nonce": int(nonce), "signature": signature}


# --- results -------------------------------------------------------------------------------------------------------
@dataclass(frozen=True)
class ActionStatus:
    index: int
    accepted: bool
    refusal: Optional[Refusal] = None


@dataclass(frozen=True)
class Submitted:
    """The answer to one write. ``ok`` means submitted (202) -- not applied; read committed state for that."""
    ok: bool
    status_code: Optional[int]
    refusal: Optional[Refusal] = None
    actions: Tuple[ActionStatus, ...] = ()
    nonce: Optional[int] = None


def read_answer(status_code: Optional[int], j: Any, retry_after: Optional[str] = None) -> Submitted:
    """Parse a write's answer by its published shape. Anything else is a refusal, never a success."""
    j = j if isinstance(j, dict) else {}
    ra = None
    try:
        ra = float(retry_after) if retry_after is not None else None
    except ValueError:
        ra = None
    if status_code == 202 and j.get("status") == "submitted":
        acts = []
        for a in j.get("actions") or []:
            if not isinstance(a, dict) or not isinstance(a.get("index"), int):
                continue
            if a.get("status") == "accepted":
                acts.append(ActionStatus(a["index"], True))
            else:
                acts.append(ActionStatus(a["index"], False, refusal(a.get("code"), a.get("error"))))
        return Submitted(True, status_code, None, tuple(acts))
    code = j.get("code")
    if status_code == 429 and not code:
        code = "mempool_full"
    return Submitted(False, status_code, refusal(code, j.get("error") or j.get("reason") or (f"HTTP {status_code}" if status_code else ""), ra))


class NonceClock:
    """Rising millisecond nonces: never the same twice in one process, never below the clock."""

    def __init__(self, clock: Callable[[], float] = time.time):
        self._clock, self._last, self._lock = clock, 0, threading.Lock()

    def __call__(self) -> int:
        return self.next_at_least(0)

    def next_at_least(self, floor: int) -> int:
        """The next nonce, and at least ``floor`` (e.g. above a nonce the chain already holds)."""
        with self._lock:
            self._last = max(int(self._clock() * 1000), self._last + 1, int(floor))
            return self._last

    def seen(self, nonce: int) -> None:
        """Note a nonce the chain already holds for the account, so the next one is above it."""
        with self._lock:
            self._last = max(self._last, int(nonce))


_CLOCKS: Dict[str, NonceClock] = {}
_CLOCKS_LOCK = threading.Lock()


def nonce_clock(owner: str) -> NonceClock:
    """The one nonce clock of ``owner`` in this process, shared by batches, cancels, modifies, the dead-man switch and
    single orders: the chain admits them all through one per-account window, so they must never collide."""
    k = str(owner).lower()
    with _CLOCKS_LOCK:
        if k not in _CLOCKS:
            _CLOCKS[k] = NonceClock()
        return _CLOCKS[k]


# --- the client ----------------------------------------------------------------------------------------------------
class MarketMaker:
    """Signs and submits market-maker writes for ``owner`` with ``signer_key`` (the owner key or a live session key).

    The signing domain is the node's: its chain id and genesis are read from ``rpc_url``'s ``/status`` and checked against
    ``network`` (or the network set with :func:`vordium.network.set_network`, or the environment pins) when one is
    configured; a mismatch raises :class:`vordium.network.NetworkMismatch` before anything is signed. A
    ``domain_separator`` given here must equal the node's (it pins, never overrides). Nonces come from the account's one
    clock (:func:`nonce_clock`) unless ``nonce`` is given. ``post``/``get``/``identity`` are injectable for tests."""

    def __init__(self, rpc_url: str, signer_key: str, owner: str, domain_separator: Optional[bytes] = None,
                 timeout: float = 10.0, nonce: Optional[NonceClock] = None, post=None, get=None,
                 network=None, identity: Optional[Callable[[], NodeIdentity]] = None):
        self.rpc_url = rpc_url.rstrip("/")
        self.owner = owner
        self._key = signer_key
        self.timeout = timeout
        self.nonce = nonce or nonce_clock(owner)
        self._post = post or self._http_post
        self._get = get or self._http_get
        self.domain = NodeDomain(self.rpc_url, network, domain_separator,
                                 identity or (lambda: read_identity(self._get("/status"))))

    # transport
    def _http_post(self, path: str, body: Dict[str, Any]):
        import requests

        r = requests.post(self.rpc_url + path, json=body, timeout=self.timeout)
        try:
            j = r.json()
        except ValueError:
            j = {}
        return r.status_code, j, r.headers.get("Retry-After")

    def _http_get(self, path: str):
        import requests

        r = requests.get(self.rpc_url + path, timeout=self.timeout)
        r.raise_for_status()
        return r.json()

    def _sig(self, struct_hash: bytes) -> str:
        return sign(self._key, digest(struct_hash, self.domain.separator()))

    def _send(self, path: str, body: Dict[str, Any], nonce: Optional[int] = None) -> Submitted:
        code, j, ra = self._post(path, body)
        s = read_answer(code, j, ra)
        return Submitted(s.ok, s.status_code, s.refusal, s.actions, nonce)

    # writes
    def batch(self, actions: Sequence[Action], nonce: Optional[int] = None, max_actions: int = BATCH_MAX) -> Submitted:
        """Sign and submit 1..``max_actions`` actions in one batch. Cancels apply first, then each place on its own."""
        if not 1 <= len(actions) <= max_actions:
            raise MMError(f"a batch holds 1 to {max_actions} actions, not {len(actions)}")
        n = nonce if nonce is not None else self.nonce()
        sig = self._sig(batch_struct_hash(self.owner, n, actions))
        return self._send("/order/batch-signed", batch_body(self.owner, n, actions, sig), n)

    def cancel_all(self, pair_id: int = 0, nonce: Optional[int] = None) -> Submitted:
        """Cancel every open order on ``pair_id`` (0 = every pair)."""
        n = nonce if nonce is not None else self.nonce()
        sig = self._sig(cancel_all_struct_hash(self.owner, pair_id, n))
        return self._send("/order/cancel-all", cancel_all_body(self.owner, pair_id, n, sig), n)

    def modify(self, order_id: int, new_price_8dec: int, new_size_18dec: int, client_nonce: Optional[int] = None) -> Submitted:
        """Cancel-and-replace: the order leaves the book and a NEW order (new id, this ``client_nonce``, no time
        priority) rests at the new price and size. If the new order would not rest, nothing changes."""
        if _uint(new_size_18dec, _U128, "new_size_18dec") == 0 or _uint(new_price_8dec, _U64, "new_price_8dec") == 0:
            raise MMError("a modified order needs a price and a size")
        n = client_nonce if client_nonce is not None else self.nonce()
        sig = self._sig(modify_v2_struct_hash(self.owner, order_id, new_price_8dec, new_size_18dec, n))
        return self._send("/order/modify", modify_body(self.owner, order_id, new_price_8dec, new_size_18dec, n, sig), n)

    def set_mmp(self, mmp: Mmp, nonce: int) -> Submitted:
        """Set Market Maker Protection. ``nonce`` must be above the account's last MMP nonce (read it with
        :meth:`account`)."""
        sig = self._sig(set_mmp_struct_hash(self.owner, mmp, nonce))
        return self._send("/account/mmp", mmp_body(self.owner, mmp.checked(), nonce, sig), nonce)

    # reads
    def specs(self) -> Dict[str, Any]:
        """``GET /markets/specs``: limits, per-pair tick/lot, margins and fees, from committed state."""
        return self._get("/markets/specs")

    def account(self, address: Optional[str] = None) -> Dict[str, Any]:
        """``GET /markets/account/{address}``: open orders and cap, request allowance and use, tier, MMP."""
        return self._get(f"/markets/account/{address or self.owner}")

    def activity(self, address: Optional[str] = None) -> Dict[str, Any]:
        """``GET /events/activity/{address}``: the last hour and day of orders, fills and cancels."""
        return self._get(f"/events/activity/{address or self.owner}")

    def open_orders(self, address: Optional[str] = None) -> List["OpenOrder"]:
        """``GET /orders/{address}``: the account's resting orders, from committed state."""
        return read_open_orders(self._get(f"/orders/{address or self.owner}"))

    def positions(self, address: Optional[str] = None) -> List["Position"]:
        """``GET /positions/{address}``: the account's open positions, from committed state (sizes exact at any size)."""
        return read_positions(self._get(f"/positions/{address or self.owner}"))


@dataclass(frozen=True)
class PairSpec:
    pair_id: int
    symbol: str
    tick_8dec: int            # 0 = not enforced
    lot_18dec: int            # 0 = not enforced
    liquidation_fee_bps: Optional[int]
    maintenance_margin_bps: Optional[int]


def pair_specs(specs_read: Dict[str, Any]) -> Dict[int, PairSpec]:
    """Each pair's tick, lot, liquidation fee and maintenance margin from a ``/markets/specs`` read."""
    out: Dict[int, PairSpec] = {}
    s = (specs_read or {}).get("specs") or {}
    for p in s.get("pairs") or []:
        pr = p.get("pair") or {}
        pid = pr.get("pair_id")
        if not isinstance(pid, int):
            continue
        out[pid] = PairSpec(pid, str(pr.get("symbol") or pr.get("name") or pid), int(p.get("tick_8dec") or 0),
                            int(p.get("lot_18dec") or 0),
                            p.get("liquidation_fee_bps") if isinstance(p.get("liquidation_fee_bps"), int) else None,
                            p.get("maintenance_margin_bps") if isinstance(p.get("maintenance_margin_bps"), int) else None)
    return out


def round_price(price_8dec: int, spec: PairSpec, side: str) -> int:
    """``price_8dec`` onto the pair's tick: a bid (``buy``) rounds down and an ask (``sell``) up, so rounding never makes
    an order more aggressive. Where the chain sets no tick (0) the price is returned unchanged; a bid below one tick
    rounds to 0."""
    if side not in SIDES:
        raise MMError(f"side is buy or sell, not {side!r}")
    p = _uint(price_8dec, _U64, "price_8dec")
    t = spec.tick_8dec
    if t <= 0 or p == 0:
        return p
    r = p % t
    if r == 0:
        return p
    out = p - r if side == "buy" else p - r + t
    if out > _U64:
        raise MMError("the price rounds outside its range")
    return out                     # a bid below one tick rounds to 0: an order at that price cannot be placed


def round_size(size_18dec: int, spec: PairSpec) -> int:
    """``size_18dec`` down onto the pair's lot (never more than asked). Where the chain sets no lot (0) the size is
    returned unchanged. A size below one lot rounds to 0 -- an order of that size cannot be placed."""
    s = _uint(size_18dec, _U128, "size_18dec")
    lot = spec.lot_18dec
    return s if lot <= 0 else s - (s % lot)


def on_tick(price_8dec: int, spec: PairSpec) -> bool:
    return spec.tick_8dec == 0 or price_8dec % spec.tick_8dec == 0


def on_lot(size_18dec: int, spec: PairSpec) -> bool:
    return spec.lot_18dec == 0 or size_18dec % spec.lot_18dec == 0


def next_mmp_nonce(account_read: Dict[str, Any]) -> int:
    """The nonce the next :meth:`MarketMaker.set_mmp` must carry, from a ``/markets/account`` read: the read's
    ``mmp.next_nonce``, or 1 when the account has never set Market Maker Protection (``mmp`` is null)."""
    m = (account_read or {}).get("mmp")
    if m is None:
        return 1
    n = m.get("next_nonce") if isinstance(m, dict) else None
    if not isinstance(n, int) or isinstance(n, bool) or n < 1:
        raise MMError("the account read carries no usable mmp.next_nonce")
    return n


# --- account reads ----------------------------------------------------------------------------------------------
@dataclass(frozen=True)
class OpenOrder:
    order_id: int
    client_nonce: Optional[int]
    pair_id: int
    side: str                 # "buy" | "sell"
    size_18dec: int
    price_8dec: int           # 0 for an order without a price
    status: Optional[str]
    signer: Optional[str]     # the key that signed it (the owner or a session/agent key), as the node names it
    timestamp_ms: Optional[int]


@dataclass(frozen=True)
class Position:
    position_id: int
    pair_id: int
    is_long: bool
    size_18dec: int           # exact at any size
    entry_price: int          # as the node gives it (6-decimal integer)
    leverage: int
    margin_6dec: int
    unrealized_pnl_6dec: int
    liquidation_price: int


def _int_field(v: Any, name: str, allow_none: bool = False) -> Optional[int]:
    if v is None and allow_none:
        return None
    if isinstance(v, bool):
        raise MMError(f"{name} is not a number")
    if isinstance(v, str) and v.lstrip("-").isdigit():
        return int(v)
    if isinstance(v, int):
        return v
    raise MMError(f"{name} is not a whole number")


def read_open_orders(j: Any) -> List[OpenOrder]:
    """Parse ``GET /orders/{address}``. Anything without the published shape raises, never a guess."""
    if not isinstance(j, list):
        raise MMError("the open-orders read is not a list")
    out = []
    for o in j:
        if not isinstance(o, dict):
            raise MMError("an open order is not an object")
        side = str(o.get("side") or "").lower()
        if side not in SIDES:
            raise MMError(f"an open order has no side ({o.get('side')!r})")
        out.append(OpenOrder(_int_field(o.get("id"), "id"), _int_field(o.get("client_nonce"), "client_nonce", True),
                             _int_field(o.get("pair_id"), "pair_id"), side, _int_field(o.get("size"), "size"),
                             _int_field(o.get("price_8dec") or 0, "price_8dec"),
                             str(o["status"]).lower() if isinstance(o.get("status"), str) else None,
                             o.get("agent") if isinstance(o.get("agent"), str) else None,
                             _int_field(o.get("timestamp_ms"), "timestamp_ms", True)))
    return out


def read_positions(j: Any) -> List[Position]:
    """Parse ``GET /positions/{address}``. Sizes are decimal strings of 18-decimal base units and exact at any size."""
    if not isinstance(j, list):
        raise MMError("the positions read is not a list")
    out = []
    for p in j:
        if not isinstance(p, dict) or not isinstance(p.get("is_long"), bool):
            raise MMError("a position does not have the published shape")
        out.append(Position(_int_field(p.get("id"), "id"), _int_field(p.get("pair_id"), "pair_id"), p["is_long"],
                            _int_field(p.get("size"), "size"), _int_field(p.get("entry_price"), "entry_price"),
                            _int_field(p.get("leverage"), "leverage"), _int_field(p.get("margin"), "margin"),
                            _int_field(p.get("unrealized_pnl"), "unrealized_pnl"),
                            _int_field(p.get("liquidation_price"), "liquidation_price")))
    return out
