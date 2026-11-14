"""Vordex client -- a CENTRAL LIMIT ORDER BOOK for perpetual futures.

Vordex is not an AMM. There is no router, no constant-product pair and no
``swapExactTokensForTokens``: orders rest on a book, match against it, and
settle as perp positions with leverage and funding.

Releases up to 0.2.0 shipped a Uniswap-style router/pair client against
addresses that do not exist on this chain. That model is gone; this module
speaks the live engine instead.

READ paths are plain REST. WRITE paths (place/cancel) are EIP-712 signed with a
session key and posted to the engine. Signing is delegated to
:mod:`vordium.caps` -- the same primitives :class:`vordium.operator.SessionSigner`
uses -- so there is exactly ONE signer in this package. Its digests are gated
against the chain's pinned vectors by ``tests/test_eip712_vectors.py``.

UNITS -- there are TWO different scales, do not mix them:
    SIGNED order fields (EIP-712 / POST body)
        price : uint64, 8 decimals    ($2441.54 -> 244154000000)
        size  : uint128, 18 decimals  (1.5 units -> 1500000000000000000)
        leverage : basis points       (10x -> 100000)
    READ endpoints
        /oracle/{id} returns prices at 1e6  (2441541428 -> $2441.54)
        /oracle/prices returns them already divided, as floats

    Use :func:`to_price_8dec` for anything you sign, and :meth:`Vordex.mark_price`
    to read a human price -- never feed a raw /oracle value into an order.

TICK AND LOT -- each market has a price step (tick) and a size step (lot), read
from ``GET /markets/specs``. An order off them is not applied, so every order
is put on them before it is signed (:mod:`vordium.units`): a bid price rounds
down and an ask price up (never a worse price than asked), a size rounds down
(never more than asked). Numbers are read exactly from their decimal form; a
float is never multiplied.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

import requests
from . import _http

from .network import api_base, get_network
from eth_utils import keccak

from .caps import place_order_digest, cancel_order_digest, place_order_struct_hash, cancel_order_struct_hash
from .node_domain import NodeDomain
from . import units
from .units import OrderValueError, SpecsUnavailable

#: ``orderType`` values as SIGNED (the uint8 in the PlaceOrder digest). The signed format keeps four values; the chain
#: accepts Market and Limit. Stop orders (2, 3) are not available: every write path refuses them before signing.
MARKET, LIMIT, STOP_MARKET, STOP_LIMIT = 0, 1, 2, 3
#: Order types the chain does not accept.
NOT_AVAILABLE = (STOP_MARKET, STOP_LIMIT)
#: ``side`` values as SIGNED (the uint8 in the PlaceOrder digest).
BUY, SELL = 0, 1

#: How the order intake names them in the request body. The signed digest keeps the numbers above; the body carries
#: these names (the order type is case-sensitive), and the chain maps them back to the signed numbers.
SIDE_NAMES = {BUY: "buy", SELL: "sell"}
ORDER_TYPE_NAMES = {MARKET: "Market", LIMIT: "Limit", STOP_MARKET: "StopMarket", STOP_LIMIT: "StopLimit"}
#: Order types that carry a limit price (sent as ``price``); the others carry none and are signed with price 0.
PRICED = (LIMIT, STOP_LIMIT)
#: The intake reads a price as a decimal number and keeps 6 decimals of it, so a signed 8-decimal price must be a
#: multiple of 100 — otherwise the chain rebuilds a different digest and the order is dropped.
PRICE_STEP_8DEC = 100

#: Decimals for the signed uint64 price field.
PRICE_DECIMALS = 8
#: Decimals for the signed uint128 size field.
SIZE_DECIMALS = 18
#: Decimals used by the /oracle/{id} read endpoint (NOT the signed price scale).
ORACLE_DECIMALS = 6


def _nearest(num: int, den: int) -> int:
    q, r = divmod(num, den)
    return q + (1 if 2 * r > den or (2 * r == den and q % 2) else 0)        # half to even, like round()


def to_price_8dec(price: Any) -> int:
    """Convert a human price to the engine's uint64 8-dec integer: exact from its decimal form, to the nearest unit.
    It does not apply a market's tick; orders use :func:`vordium.units.price_8dec`."""
    return _nearest(*units.scaled(price, PRICE_DECIMALS, "a price"))


def limit_price_8dec(price: Any) -> int:
    """A limit price at the 6 decimals the chain keeps, as the signed 8-decimal integer (exact, to the nearest unit).
    It does not apply a market's tick; :meth:`Vordex.place_order` uses :func:`vordium.units.price_8dec`."""
    try:
        positive = units.decimal_of(price, "a limit price") > 0
    except OrderValueError:
        positive = False
    if not positive:
        raise ValueError(f"a limit price must be a positive number; got {price!r}")
    return _nearest(*units.scaled(price, 6, "a limit price")) * PRICE_STEP_8DEC


def _decimal(v8: int) -> float:
    """The JSON number the intake reads for a signed 8-decimal value (exactly v8 / 1e8 at 6 decimals)."""
    if v8 % PRICE_STEP_8DEC:
        raise ValueError(f"{v8} has more than 6 decimals: the chain would keep a different price")
    from decimal import Decimal
    return float(Decimal(v8) / Decimal(10 ** 8))


def to_size_18dec(size: Any) -> int:
    """Convert a human size to the engine's uint128 18-dec integer: exact from its decimal form, to the nearest unit.
    It does not apply a market's lot; orders use :func:`vordium.units.size_18dec` (down onto the lot)."""
    return _nearest(*units.scaled(size, SIZE_DECIMALS, "a size"))


def _sign_digest(private_key: str, digest: bytes) -> str:
    """Sign a 32-byte EIP-712 digest, returning 64-byte ``r||s`` hex.

    The chain brute-forces the recovery id, so the trailing ``v`` is stripped.
    """
    from eth_account import Account

    signed = Account._sign_hash(digest, private_key) if hasattr(Account, "_sign_hash") \
        else Account.unsafe_sign_hash(digest, private_key)
    return "0x" + signed.signature.hex().removeprefix("0x")[:128]


class OrderNotAvailable(ValueError):
    """An order the chain does not accept (a stop order, or trigger fields on a plain order). Raised before anything is
    signed or sent."""


STOP_REFUSAL = ("Stop orders are not available: set a take-profit or stop-loss on the position instead "
                "(Operator.set_tpsl).")


def refuse_unavailable(order_type: Any, trigger_price_8dec: Any = 0, trigger_dir: Any = 0) -> None:
    """Raise :class:`OrderNotAvailable` for a stop order type or any non-zero trigger field."""
    if order_type in NOT_AVAILABLE:
        raise OrderNotAvailable(STOP_REFUSAL)
    if trigger_price_8dec or trigger_dir:
        raise OrderNotAvailable("Trigger price and direction belong to stop orders, which are not available; send 0 "
                                "for both.")


def _wire(table: Dict[int, str], value: Any, what: str) -> str:
    if isinstance(value, bool) or not isinstance(value, int) or value not in table:
        raise ValueError(f"{what} must be one of {sorted(table)}; got {value!r}")
    return table[value]


def place_order_body(owner: str, session_address: str, pair_id: int, side: int, size18: int, price8: int,
                     leverage_bps: int, order_type: int, reduce_only: bool, post_only: bool, trigger8: int,
                     trigger_dir: int, client_nonce: int, signature: str) -> Dict[str, Any]:
    """The ``/order/place`` request body for a signed PlaceOrder.

    ``side`` and ``orderType`` go by name ("buy"/"sell"; "Limit", "Market", …). A limit price goes in ``price`` as a
    decimal number (the signed ``price8`` / 1e8, at most 6 decimals); a market order carries no price and is signed with
    price 0. ``size_18dec`` is the signed 18-decimal integer as a string. Stop orders and trigger fields are refused
    (:class:`OrderNotAvailable`), as is anything else the chain would not take.
    """
    otype = _wire(ORDER_TYPE_NAMES, order_type, "order_type")
    refuse_unavailable(order_type, trigger8, trigger_dir)
    body: Dict[str, Any] = {
        "owner": owner,
        "pairId": int(pair_id),
        "side": _wire(SIDE_NAMES, side, "side"),
        "size_18dec": str(int(size18)),
        "orderType": otype,
        "reduceOnly": bool(reduce_only),
        "leverageBps": int(leverage_bps),
        "clientNonce": int(client_nonce),
        "sessionKey": session_address,
        "post_only": bool(post_only),
        "trigger_price_8dec": int(trigger8),
        "trigger_dir": int(trigger_dir),
        "signature": signature,
    }
    if order_type in PRICED:
        if int(price8) <= 0:
            raise ValueError("a limit order needs a price")
        body["price"] = _decimal(int(price8))
    elif int(price8) != 0:
        raise ValueError("a market order carries no price (it is signed with price 0)")
    return body


def cancel_order_body(owner: str, session_address: str, order_id: int, signature: str) -> Dict[str, Any]:
    """The ``/order/cancel`` request body for a signed CancelOrder."""
    return {"order_id": int(order_id), "owner": owner, "session_key": session_address, "signature": signature}


def set_tpsl_body(owner: str, session_address: str, pair_id: int, position_id: int, take_profit_8dec: int,
                  stop_loss_8dec: int, signature: str) -> Dict[str, Any]:
    """The ``/tpsl/set`` request body for a signed SetTpSl (prices are 8-decimal integers; 0 leaves a leg unset)."""
    return {"action": "perp_tpsl", "owner": owner, "pair_id": int(pair_id), "position_id": int(position_id),
            "take_profit_8dec": int(take_profit_8dec), "stop_loss_8dec": int(stop_loss_8dec),
            "session_key": session_address, "signature": signature}


def cancel_outcome(records: Any, order_id: int) -> Optional[str]:
    """How an order that no longer rests was closed, from the account's records: ``"cancelled"``, ``"filled"``, or
    None when no record says."""
    mine = [e for e in (records or []) if isinstance(e, dict)
            and str(e.get("order_id", e.get("orderId", e.get("id")))) == str(order_id)]
    kinds = [(str(e.get("kind") or "").lower(), str(e.get("status") or "").lower()) for e in mine]
    if any(k == "order_cancelled" or (k == "order_closed" and st == "cancelled") for k, st in kinds):
        return "cancelled"
    if any(k in ("fill", "order_filled") or (k == "order_closed" and st == "filled") for k, st in kinds):
        return "filled"
    return None


def cancel_read_back(read_orders: Any, order_id: int, answer: Any = None, attempts: int = 0,
                     read_records: Any = None) -> Dict[str, Any]:
    """After a cancel whose earlier copy may have arrived (its answer was lost, then a refusal or a 5xx): the account's
    resting orders and records decide. Gone with a cancel record: ``status "done"`` (``already_received``). Gone with a
    fill record: ``status "filled"`` (the order filled before the cancel). Gone with no record, still resting, or
    unreadable: ``status "unknown"``. Never a plain refusal."""
    rows = None
    try:
        rows = read_orders()
    except Exception:
        rows = None
    base = {"status_code": None, "attempts": attempts, "chain_answer": answer, "order_id": int(order_id)}
    if isinstance(rows, list) and not any(isinstance(o, dict) and str(o.get("id", o.get("order_id"))) == str(order_id)
                                          for o in rows):
        try:
            j = read_records() if read_records is not None else None
        except Exception:
            j = None
        how = cancel_outcome(j.get("events") if isinstance(j, dict) else j, order_id)
        if how == "cancelled":
            return {**base, "status": "done", "already_received": True, "order_gone": True,
                    "detail": "The order was cancelled."}
        if how == "filled":
            return {**base, "status": "filled", "already_received": False, "order_gone": True,
                    "detail": "The order filled before the cancel: check your position."}
        return {**base, "status": "unknown", "delivery_unknown": True, "already_received": False, "order_gone": True,
                "detail": "The order no longer rests: it closed (filled or cancelled). Check the fills and the position."}
    return {**base, "status": "unknown", "delivery_unknown": True, "already_received": False,
            "detail": ("The order is still resting" if isinstance(rows, list) else "The orders could not be read")
                      + " after an earlier copy of the cancel may have arrived; read the account's orders, then "
                      "cancel again if it is still resting."}


def _num(v: Any) -> Optional[int]:
    if isinstance(v, bool) or v is None:
        return None
    if isinstance(v, int):
        return v
    if isinstance(v, str) and v.strip().lstrip("-").isdigit():
        return int(v.strip())
    return None


def matches_signed(rec: Dict[str, Any], signed: Optional[Dict[str, Any]]) -> bool:
    """Whether an order record carries what was signed: its market and side, and its size or limit price. The size is
    the record's ``original_size_18dec`` when it shows one, else its ``size_18dec`` / ``size`` (which a partly filled
    order shows as what is left: then it does not match, and the write reads as unknown, never as received). A field
    the record does not show is not counted; a field it shows with another value is a mismatch; a record that shows
    neither size nor price is not enough."""
    if not signed:
        return True
    pair = _num(rec.get("pair_id", rec.get("pairId")))
    if pair is None or pair != int(signed["pair_id"]):
        return False
    side = rec.get("side")
    s = str(side).strip().lower() if side is not None else ""
    side_n = 0 if s in ("0", "buy", "b", "long") else 1 if s in ("1", "sell", "s", "short") else None
    if side_n is None or side_n != int(signed["side"]):
        return False
    shown = 0
    for k in ("original_size_18dec", "size_18dec", "size"):
        v = _num(rec.get(k))
        if v is not None:
            if v != int(signed["size_18dec"]):
                return False
            shown += 1
            break
    if signed.get("price_8dec") is not None:
        v = _num(rec.get("price_8dec"))
        if v is not None:
            if v != int(signed["price_8dec"]):
                return False
            shown += 1
    return shown > 0


class Vordex:
    """Client for the Vordex perpetual CLOB."""

    def __init__(self, rpc_url: str = None, timeout: int = 15, network=None, identity=None, specs: Any = None,
                 chain_clock: Any = "auto"):
        # rpc_url resolves at client init from the live network's REST base (never a baked default); pass one
        # explicitly to point at a custom node.
        self.rpc_url = (rpc_url or api_base(get_network())).rstrip("/")
        self.timeout = timeout
        # the market rules (tick, lot, minimums): read from this node for each order unless a read is given here
        self.specs = specs
        # writes are signed under the domain of THIS node (its /status), checked against the configured network
        self.domain = NodeDomain(self.rpc_url, network, None, identity)
        # the network's block time for the client-nonce window check (None: this computer's clock)
        from . import nonces
        self._chain = nonces.chain_clock_for(self.rpc_url, network) if chain_clock == "auto" else chain_clock

    def _digest(self, struct_hash: bytes) -> bytes:
        return keccak(b"\x19\x01" + self.domain.separator() + struct_hash)

    # -- read ---------------------------------------------------------------

    def _get(self, path: str) -> Any:
        r = _http.get(f"{self.rpc_url}{path}", timeout=self.timeout)
        r.raise_for_status()
        return r.json()

    def markets(self) -> List[Dict[str, Any]]:
        """Every live perp market with its oracle and mark price."""
        return self._get("/oracle/prices").get("prices", [])

    def orderbook(self, pair_id: int) -> Dict[str, List[Any]]:
        """Resting bids and asks for ``pair_id``."""
        return self._get(f"/orderbook/{pair_id}")

    def oracle(self, pair_id: int) -> Dict[str, Any]:
        """Oracle/mark/index price and funding detail for ``pair_id``.

        Prices in this payload are 1e6 integers (``oracle_price`` 2441541428
        means $2441.54) -- a DIFFERENT scale from the 8-dec price you sign.
        Prefer :meth:`mark_price` unless you need the raw fields.
        """
        return self._get(f"/oracle/{pair_id}")

    def mark_price(self, pair_id: int) -> float:
        """Human mark price for ``pair_id`` (handles the 1e6 read scaling)."""
        return self.oracle(pair_id)["mark_price"] / 10 ** ORACLE_DECIMALS

    def pair_spec(self, pair_id: int):
        """The market's tick, lot and minimums (:class:`vordium.mm.PairSpec`), read now unless ``specs`` was given."""
        return units.resolve(getattr(self, "specs", None), self.rpc_url, pair_id, self.timeout)

    def slippage_cap_8dec(self, pair_id: int, side: int, slippage_bps: int = 50) -> int:
        """Slippage CAP for a MARKET order, as the 8-dec integer (exact: the 6-decimal mark × the bps factor, rounded
        away from the mark).

        BUY caps above the mark, SELL caps below it.
        """
        mark8 = units.whole(self.oracle(pair_id)["mark_price"], "mark_price") * 10 ** (PRICE_DECIMALS - ORACLE_DECIMALS)
        bps = int(slippage_bps)
        if side == BUY:
            return -(-mark8 * (10_000 + bps) // 10_000)
        return mark8 * (10_000 - bps) // 10_000

    def funding(self, pair_id: int) -> Dict[str, Any]:
        """Current funding rate and open interest for ``pair_id``."""
        return self._get(f"/funding/{pair_id}")

    def fills(self, pair_id: int) -> List[Dict[str, Any]]:
        """Recent trades for ``pair_id``."""
        return self._get(f"/fills/{pair_id}")

    def positions(self, address: str) -> List[Dict[str, Any]]:
        """Open perp positions for ``address``."""
        return self._get(f"/positions/{address}")

    def balance(self, address: str) -> Dict[str, Any]:
        """USDC collateral for ``address`` (6-decimal integers). ``free_balance`` is what a new order can use as margin:
        the chain accepts an order only when it covers the order's margin. Margin is isolated per position, and
        unrealized profit or loss is not part of it."""
        return self._get(f"/balance/{address}")

    # -- write --------------------------------------------------------------

    def place_order(
        self,
        session_key: str,
        owner: str,
        pair_id: int,
        side: int,
        size: Any,
        price: Any,
        leverage: Any = 1.0,
        order_type: int = LIMIT,
        reduce_only: bool = False,
        post_only: bool = False,
        trigger_price: float = 0.0,
        trigger_dir: int = 0,
        client_nonce: Optional[int] = None,
        retries: int = 3,
        builder: Optional[Dict[str, Any]] = None,
        worst_price: Any = None,
    ) -> Dict[str, Any]:
        """Sign and submit an order.

        ``session_key`` is the session private key (the chain recovers ``owner``
        from it). ``size``, ``price`` and ``leverage`` may be int, str, Decimal
        or float, and are read exactly from their decimal form. The order is put
        on the market's tick and lot first (read from ``GET /markets/specs``
        unless the client holds ``specs``): a buy's limit price rounds down and a
        sell's up, at most 6 decimals; the size rounds down onto the lot. A size
        that rounds to 0, below the market's smallest size, or a limit order
        below the network's smallest order value raises :class:`OrderValueError`
        before anything is signed. A MARKET order carries no price and ``price``
        is ignored.

        The client nonce comes from the account's one clock (:func:`vordium.mm.nonce_clock`) unless ``client_nonce`` is
        given: strictly rising across threads, processes and restarts, and checked against the network's window first
        (:class:`vordium.nonces.ClockOutOfWindow` when this computer's clock is too far off; nothing is signed).

        The order is signed ONCE. A timeout, a lost connection or a busy gateway sends the same signed body again, up
        to ``retries`` copies in all; it never signs a new nonce. When a resent copy is answered with the nonce code, the
        order is read back: if the network lists an order with this client nonce AND the signed market, side and size
        or price, the answer is ``{"status": "received", "already_received": True, "found": ...}``; otherwise it is
        ``{"status": "unknown", "delivery_unknown": True}`` (read the account's orders before sending a new one). Neither
        carries an HTTP status (``status_code`` is None). When no copy is answered,
        :class:`vordium.nonces.DeliveryUnknown` is raised unless the read-back finds the order. Every answer carries
        ``clientNonce`` and ``attempts``.

        ``order_type`` is MARKET or LIMIT; stop orders are
        not available, and ``trigger_price`` / ``trigger_dir`` must stay 0
        (:class:`OrderNotAvailable` otherwise, before anything is signed).

        ``builder`` (``{"address": "0x…", "fee_cbps": 500}``) adds a builder fee to the order: it is then signed as
        PlaceOrderV3 with a 65-byte signature and an approval deadline 120 s ahead. Fees are in cbps (1,000 cbps = 0.1 %).
        Before anything is signed the network's builder reads are checked: builder fees active, the fee above 0 and at
        most the perps cap (``caps_cbps``), the builder approved by ``owner`` at or above the fee, the builder's account value enough,
        and the builder not ``owner`` itself (:class:`vordium.builder.BuilderError` with the network's code otherwise).
        Without ``builder`` the order is signed exactly as before.

        ``worst_price`` (a MARKET order with ``builder`` only) is the worst price the order may fill at: put on the
        market's price step so it is never worse than given (a buy's rounds down, a sell's up), then signed as both the
        slippage cap (``price``) and ``worstPrice8dec``. The network refuses the order (``slippage`` /
        ``worst_price``) when the market is already past it. Without it a builder market order has no price limit.
        """
        from .mm import nonce_clock
        from . import nonces

        _wire(SIDE_NAMES, side, "side")
        _wire(ORDER_TYPE_NAMES, order_type, "order_type")
        refuse_unavailable(order_type, trigger_price, trigger_dir)
        spec = self.pair_spec(pair_id)
        size18 = units.size_18dec(size, spec)
        price8 = units.price_8dec(price, spec, side) if order_type in PRICED else 0
        units.check_notional(size18, price8, spec)
        trigger8 = 0                                    # stop orders are refused above: no trigger is ever signed
        leverage_bps = units.leverage_bps(leverage)

        if worst_price is not None and (builder is None or order_type != MARKET):
            raise ValueError("worst_price applies to a market order that names a builder")
        checked = self._builder_checked(owner, builder) if builder is not None else None
        worst8 = units.price_8dec(worst_price, spec, side) if worst_price is not None else 0

        # The signed value and the POST body MUST carry identical values -- the engine rebuilds the digest from the body.
        nonce = int(client_nonce) if client_nonce is not None else nonces.fresh(nonce_clock(owner), 0, getattr(self, "_chain", None))
        if checked is not None:
            from . import builder as _b
            s = _b.place_order_v3(session_key, owner, pair_id, side, size18, price8, leverage_bps, order_type, nonce,
                                  _b.deadline(None, self._now_s()), checked[0], checked[1], self.domain.separator(),
                                  reduce_only=reduce_only, post_only=post_only, worst_price_8dec=worst8)
            body = s.body
        else:
            digest = self._digest(place_order_struct_hash(
                owner, pair_id, side, size18, price8, leverage_bps,
                order_type, reduce_only, nonce, post_only, trigger8, trigger_dir,
            ))
            signature = _sign_digest(session_key, digest)
            from eth_account import Account

            body = place_order_body(
                owner, Account.from_key(session_key).address, pair_id, side, size18, price8, leverage_bps,
                order_type, reduce_only, post_only, trigger8, trigger_dir, nonce, signature,
            )
        signed = {"pair_id": int(pair_id), "side": int(side), "size_18dec": int(size18),
                  "price_8dec": int(price8) if order_type in PRICED else None}
        rewound = getattr(nonce_clock(owner), "rewound_before", lambda n: None)(nonce)

        def ours(found):
            """A read-back counts only when it matches what was signed AND, when this nonce may have been handed out
            before the mark was set back, it is newer than that."""
            if found is None or rewound is None:
                return found
            ts = next((found.get(k) for k in ("timestamp_ms", "ts_ms", "time_ms") if isinstance(found.get(k), int)), None)
            return found if ts is not None and ts > rewound else None
        base = {"clientNonce": nonce}
        try:
            sent = nonces.send_same(lambda: self._post_once("/order/place", body), attempts=retries, nonce=nonce)
        except nonces.DeliveryUnknown as e:
            found = ours(self.order_by_client_nonce(owner, nonce, signed))
            if found is None:
                raise
            return {**base, "status": "received", "already_received": True, "found": found, "attempts": e.attempts,
                    "status_code": None}
        if sent.needs_read_back:
            # an earlier copy may have arrived and the last answer is not a 2xx (the nonce code - which also means
            # "outside the window" or "used by another signer" -, a refusal of a later copy, a 5xx): the order is ours
            # only when the network lists it with what was signed
            found = ours(self.order_by_client_nonce(owner, nonce, signed))
            if found is not None:
                return {**base, "status": "received", "already_received": True, "found": found,
                        "attempts": sent.attempts, "status_code": None, "chain_answer": sent.answer}
            return {**base, "status": "unknown", "already_received": False, "delivery_unknown": True, "found": None,
                    "attempts": sent.attempts, "status_code": None, "chain_answer": sent.answer,
                    "detail": "An earlier copy may have arrived (its answer was lost), the network answered "
                              f"{sent.status_code}, and it does not list this order (yet). It may have arrived: read "
                              "the account's orders before sending a new one."}
        out: Dict[str, Any] = dict(sent.answer) if isinstance(sent.answer, dict) else {"answer": sent.answer}
        out.setdefault("status_code", sent.status_code)
        out["clientNonce"], out["attempts"] = nonce, sent.attempts
        if checked is not None:
            out["builder"] = {"address": checked[0], "fee_cbps": checked[1]}
        return out

    def _now_s(self) -> Optional[int]:
        """The network's block time in unix seconds (None: this computer's clock is used)."""
        try:
            ms = self._chain() if getattr(self, "_chain", None) is not None else None
        except Exception:
            ms = None
        return ms // 1000 if isinstance(ms, int) and ms > 0 else None

    def _builder_checked(self, owner: str, builder: Any):
        """(address, fee cbps) of an order's builder after the network's builder reads allow it; raises
        :class:`vordium.builder.BuilderError` before anything is signed otherwise."""
        from . import builder as _b
        addr, fee = _b.parse_builder(builder)
        try:
            approvals = self._get(f"/builder/approvals/{owner}")
            stats = self._get(f"/builder/stats/{addr}")
        except Exception:
            raise _b.BuilderNotActive("The network did not answer its builder reads, so the builder fee cannot be "
                                      "checked and nothing was signed. Try again, or send the order without a "
                                      "builder.") from None
        _b.require_active(approvals)
        _b.require_active(stats)
        _b.check_fee(fee, "perps", _b.caps_from(stats))
        _b.check_order_builder(owner, addr, fee, approvals, stats)
        return addr, fee

    def builder_approvals(self, user: str) -> Dict[str, Any]:
        """``GET /builder/approvals/<user>``: the builders ``user`` approved (``approvals`` [{builder, max_fee_cbps}]),
        ``count``, ``max``, ``nonce`` and ``active`` (builder fees active)."""
        return self._get(f"/builder/approvals/{user}")

    def builder_stats(self, builder: str) -> Dict[str, Any]:
        """``GET /builder/stats/<builder>``: volume, fees (= unclaimed + claimed), users in 30 days, whether its account
        value is enough, the caps in cbps, its claim nonce and ``active``."""
        return self._get(f"/builder/stats/{builder}")

    def referral_stats(self, address: str) -> Dict[str, Any]:
        """``GET /referral/stats/<address>``; with referral levels in force it carries ``level``, ``share_bps``,
        ``discount_bps``, ``l2_progress``, ``next_check_ms``, ``own_volume_6dec``, ``meets_min``, ``limits`` and more
        (:func:`vordium.builder.referral_level` reads them)."""
        return self._get(f"/referral/stats/{address}")

    def referral_tiers(self) -> Dict[str, Any]:
        """``GET /referral/tiers``: the referral levels table and its rules."""
        return self._get("/referral/tiers")

    def _post_once(self, path: str, body: Dict[str, Any]):
        """One attempt: (status, answer, Retry-After)."""
        r = _http.post(f"{self.rpc_url}{path}", json=body, timeout=self.timeout)
        try:
            j = r.json() if r.content else {}
        except ValueError:
            j = {"error": (getattr(r, "text", "") or "")[:300]}
        headers = getattr(r, "headers", None) or {}
        return r.status_code, j, headers.get("Retry-After")

    def order_by_client_nonce(self, owner: str, client_nonce: int,
                              signed: Optional[Dict[str, Any]] = None) -> Optional[Dict[str, Any]]:
        """The account's order with ``client_nonce`` as the network lists it: the resting order (``GET /orders``), else
        its record (``GET /events/account``), else None. With ``signed`` (pair_id, side, size_18dec, price_8dec), only a
        record that carries those values counts: another signer of the account may use the same millisecond nonce. A
        failed read is None."""
        want = str(int(client_nonce))
        try:
            rows = self._get(f"/orders/{owner}")
            for o in rows if isinstance(rows, list) else []:
                if isinstance(o, dict) and str(o.get("client_nonce")) == want and matches_signed(o, signed):
                    return {"source": "orders", **o}
        except Exception:
            pass
        try:
            j = self._get(f"/events/account/{str(owner).lower()}?limit=50")
            for e in (j.get("events") if isinstance(j, dict) else None) or []:
                if isinstance(e, dict) and str(e.get("client_nonce")) == want and matches_signed(e, signed):
                    return {"source": "events", **e}
        except Exception:
            pass
        return None

    def cancel_order(self, session_key: str, owner: str, order_id: int) -> Dict[str, Any]:
        """Sign and submit a cancel for ``order_id``."""
        from eth_account import Account

        from . import nonces

        signature = _sign_digest(session_key, self._digest(cancel_order_struct_hash(owner, order_id)))
        body = cancel_order_body(owner, Account.from_key(session_key).address, order_id, signature)
        # a cancel carries no nonce; cancelling an order twice cancels it once, so a timeout sends the same body again.
        # When an earlier copy may have arrived, the answer to a later one ("not found", a 5xx) is about that later
        # copy: the account's resting orders decide.
        read = lambda: self._get(f"/orders/{owner}")
        records = lambda: self._get(f"/events/account/{str(owner).lower()}?limit=50")
        try:
            sent = nonces.send_same(lambda: self._post_once("/order/cancel", body))
        except nonces.DeliveryUnknown as e:
            if e.never_sent:
                return {"status": "not_sent", "status_code": None, "attempts": e.attempts, "detail": str(e)}
            return cancel_read_back(read, order_id, None, e.attempts, records)
        if sent.needs_read_back:
            return cancel_read_back(read, order_id, sent.answer, sent.attempts, records)
        out = dict(sent.answer) if isinstance(sent.answer, dict) else {"answer": sent.answer}
        out.setdefault("status_code", sent.status_code)
        return out
