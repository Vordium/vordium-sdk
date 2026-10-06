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
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

import requests

from .network import get_network
from eth_utils import keccak

from .caps import place_order_digest, cancel_order_digest, place_order_struct_hash, cancel_order_struct_hash
from .node_domain import NodeDomain

#: ``orderType`` values as SIGNED (the uint8 in the PlaceOrder digest).
MARKET, LIMIT, STOP_MARKET, STOP_LIMIT = 0, 1, 2, 3
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


def to_price_8dec(price: float) -> int:
    """Convert a human price to the engine's uint64 8-dec integer."""
    return int(round(price * 10 ** PRICE_DECIMALS))


def limit_price_8dec(price: float) -> int:
    """A limit price as the chain keeps it: rounded to 6 decimals, as the signed 8-decimal integer."""
    if not isinstance(price, (int, float)) or isinstance(price, bool) or not price > 0:
        raise ValueError(f"a limit price must be a positive number; got {price!r}")
    return int(round(price * 10 ** 6)) * PRICE_STEP_8DEC


def _decimal(v8: int) -> float:
    """The JSON number the intake reads for a signed 8-decimal value (exactly v8 / 1e8 at 6 decimals)."""
    if v8 % PRICE_STEP_8DEC:
        raise ValueError(f"{v8} has more than 6 decimals: the chain would keep a different price")
    from decimal import Decimal
    return float(Decimal(v8) / Decimal(10 ** 8))


def to_size_18dec(size: float) -> int:
    """Convert a human size to the engine's uint128 18-dec integer."""
    return int(round(size * 10 ** SIZE_DECIMALS))


def _sign_digest(private_key: str, digest: bytes) -> str:
    """Sign a 32-byte EIP-712 digest, returning 64-byte ``r||s`` hex.

    The chain brute-forces the recovery id, so the trailing ``v`` is stripped.
    """
    from eth_account import Account

    signed = Account._sign_hash(digest, private_key) if hasattr(Account, "_sign_hash") \
        else Account.unsafe_sign_hash(digest, private_key)
    return "0x" + signed.signature.hex().removeprefix("0x")[:128]


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
    price 0. ``size_18dec`` is the signed 18-decimal integer as a string. Anything else is refused before it is sent.
    """
    otype = _wire(ORDER_TYPE_NAMES, order_type, "order_type")
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


class Vordex:
    """Client for the Vordex perpetual CLOB."""

    def __init__(self, rpc_url: str = None, timeout: int = 15, network=None, identity=None):
        # rpc_url resolves at client init from the live network (never a baked
        # default); pass one explicitly to point at a custom node.
        self.rpc_url = (rpc_url or get_network().rpc_url).rstrip("/")
        self.timeout = timeout
        # writes are signed under the domain of THIS node (its /status), checked against the configured network
        self.domain = NodeDomain(self.rpc_url, network, None, identity)

    def _digest(self, struct_hash: bytes) -> bytes:
        return keccak(b"\x19\x01" + self.domain.separator() + struct_hash)

    # -- read ---------------------------------------------------------------

    def _get(self, path: str) -> Any:
        r = requests.get(f"{self.rpc_url}{path}", timeout=self.timeout)
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

    def slippage_cap_8dec(self, pair_id: int, side: int, slippage_bps: int = 50) -> int:
        """Slippage CAP for a MARKET order, as the signed 8-dec integer.

        A market order signs a price bound, not a limit: BUY caps above the
        mark, SELL caps below it.
        """
        mark = self.mark_price(pair_id)
        factor = 1 + slippage_bps / 10_000 if side == BUY else 1 - slippage_bps / 10_000
        return to_price_8dec(mark * factor)

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
        """USDC collateral for ``address`` (total/free/locked/in-positions)."""
        return self._get(f"/balance/{address}")

    # -- write --------------------------------------------------------------

    def place_order(
        self,
        session_key: str,
        owner: str,
        pair_id: int,
        side: int,
        size: float,
        price: float,
        leverage: float = 1.0,
        order_type: int = LIMIT,
        reduce_only: bool = False,
        post_only: bool = False,
        trigger_price: float = 0.0,
        trigger_dir: int = 0,
        client_nonce: Optional[int] = None,
        retries: int = 3,
    ) -> Dict[str, Any]:
        """Sign and submit an order.

        ``session_key`` is the session private key (the chain recovers ``owner``
        from it). A LIMIT price is rounded to 6 decimals (the precision the chain
        keeps); a MARKET order carries no price and ``price`` is ignored.

        A duplicate ``client_nonce`` is retried with a fresh one, matching the
        web app's behaviour.
        """
        from .mm import nonce_clock

        _wire(SIDE_NAMES, side, "side")
        _wire(ORDER_TYPE_NAMES, order_type, "order_type")
        size18 = to_size_18dec(size)
        price8 = limit_price_8dec(price) if order_type in PRICED else 0
        trigger8 = to_price_8dec(trigger_price) if trigger_price else 0
        leverage_bps = int(round(leverage * 10_000))

        last: Dict[str, Any] = {}
        for _ in range(max(1, retries)):
            nonce = client_nonce if client_nonce is not None else nonce_clock(owner)()   # the account's one clock
            # The signed value and the POST body MUST carry identical values --
            # the engine rebuilds the digest from the body.
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
            r = requests.post(
                f"{self.rpc_url}/order/place", json=body, timeout=self.timeout
            )
            last = r.json() if r.content else {}
            duplicate = r.status_code == 409 or "duplicate" in str(
                last.get("error", "")
            ).lower()
            if duplicate and client_nonce is None:
                continue
            last.setdefault("status_code", r.status_code)
            return last
        return last

    def cancel_order(self, session_key: str, owner: str, order_id: int) -> Dict[str, Any]:
        """Sign and submit a cancel for ``order_id``."""
        from eth_account import Account

        signature = _sign_digest(session_key, self._digest(cancel_order_struct_hash(owner, order_id)))
        body = cancel_order_body(owner, Account.from_key(session_key).address, order_id, signature)
        r = requests.post(
            f"{self.rpc_url}/order/cancel", json=body, timeout=self.timeout
        )
        out = r.json() if r.content else {}
        out.setdefault("status_code", r.status_code)
        return out
