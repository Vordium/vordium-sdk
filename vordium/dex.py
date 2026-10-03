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
from .caps import place_order_digest, cancel_order_digest

#: ``orderType`` values accepted by the engine.
MARKET, LIMIT, STOP_MARKET, STOP_LIMIT = 0, 1, 2, 3
#: ``side`` values accepted by the engine.
BUY, SELL = 0, 1

#: Decimals for the signed uint64 price field.
PRICE_DECIMALS = 8
#: Decimals for the signed uint128 size field.
SIZE_DECIMALS = 18
#: Decimals used by the /oracle/{id} read endpoint (NOT the signed price scale).
ORACLE_DECIMALS = 6


def to_price_8dec(price: float) -> int:
    """Convert a human price to the engine's uint64 8-dec integer."""
    return int(round(price * 10 ** PRICE_DECIMALS))


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


class Vordex:
    """Client for the Vordex perpetual CLOB."""

    def __init__(self, rpc_url: str = None, timeout: int = 15):
        # rpc_url resolves at client init from the live network (never a baked
        # default); pass one explicitly to point at a custom node.
        self.rpc_url = (rpc_url or get_network().rpc_url).rstrip("/")
        self.timeout = timeout

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
        from it). For a MARKET order, ``price`` is the slippage CAP, not a limit.

        A duplicate ``client_nonce`` is retried with a fresh one, matching the
        web app's behaviour.
        """
        import time

        size18 = to_size_18dec(size)
        price8 = to_price_8dec(price)
        trigger8 = to_price_8dec(trigger_price) if trigger_price else 0
        leverage_bps = int(round(leverage * 10_000))

        last: Dict[str, Any] = {}
        for _ in range(max(1, retries)):
            nonce = client_nonce if client_nonce is not None else int(time.time() * 1000)
            # The signed value and the POST body MUST carry identical values --
            # the engine rebuilds the digest from the body.
            digest = place_order_digest(
                owner, pair_id, side, size18, price8, leverage_bps,
                order_type, reduce_only, nonce, post_only, trigger8, trigger_dir,
            )
            signature = _sign_digest(session_key, digest)
            from eth_account import Account

            body = {
                "owner": owner,
                "pairId": pair_id,
                "side": side,
                "size_18dec": str(size18),
                "price_8dec": price8,
                "orderType": order_type,
                "reduceOnly": reduce_only,
                "leverageBps": leverage_bps,
                "clientNonce": nonce,
                "sessionKey": Account.from_key(session_key).address,
                "post_only": post_only,
                "trigger_price_8dec": trigger8,
                "trigger_dir": trigger_dir,
                "signature": signature,
            }
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

        signature = _sign_digest(session_key, cancel_order_digest(owner, order_id))
        body = {
            "owner": owner,
            "orderId": order_id,
            "sessionKey": Account.from_key(session_key).address,
            "signature": signature,
        }
        r = requests.post(
            f"{self.rpc_url}/order/cancel", json=body, timeout=self.timeout
        )
        out = r.json() if r.content else {}
        out.setdefault("status_code", r.status_code)
        return out
