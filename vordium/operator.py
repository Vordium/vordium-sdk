"""
Agent Operator -- session-key signing, graceful reads, and order submit.

SAFETY MODEL (bounded by construction):
  * The operator drives an agent's TRADING account (``owner``) using a SESSION
    KEY. The session key SIGNS order digests; the ``owner`` field in every
    payload stays the trading account. The chain accepts a signature that
    recovers to the owner OR to an active session key of that owner.
  * A session key can ONLY place / cancel / modify orders within the on-chain
    agent caps. It can NEVER withdraw funds and NEVER change caps --
    those need the account's own key. So an operator (an AI or a script holding a session
    key) is bounded no matter what it does.
  * This SDK adds a LOCAL cap pre-check (see ``caps.agent_cap_check``) purely to
    fail fast. The chain re-checks everything authoritatively.

The session key is loaded from an env var or a keystore file. It is NEVER
hardcoded and NEVER transmitted -- only 64-byte r||s signatures leave the box.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Optional

import requests

from .node_domain import NodeDomain
from eth_account import Account

from . import caps as capsmod
from .caps import (
    AgentCaps,
    CandidateOrder,
    Side,
    OrderType,
    PlaceOrderType,
    agent_cap_check,
    cancel_order_digest,
    modify_order_digest,
    place_order_digest,
    set_tpsl_digest,
    AGENT_CAPS_PRECOMPILE_ADDR,
    AGENT_REGISTRY_ADDR,
    VORDEX_VAULT_THIN_ADDR,
)
from .network import api_base, get_network
from .dex import place_order_body, cancel_order_body, set_tpsl_body, _wire, SIDE_NAMES, ORDER_TYPE_NAMES, PRICED, OrderNotAvailable, STOP_REFUSAL, refuse_unavailable


# ---------------------------------------------------------------------------
# Session-key signer
# ---------------------------------------------------------------------------
class SessionSigner:
    """
    Signs Agent Operator order digests with a session key.

    The key is loaded from (in order): an explicit ``private_key`` arg, the
    ``VORDIUM_SESSION_KEY`` env var, or a keystore JSON file path. It is never
    written back out and never sent over the wire -- only signatures are.
    """

    def __init__(self, private_key: Optional[str] = None):
        key = private_key or os.getenv("VORDIUM_SESSION_KEY")
        if not key:
            raise ValueError(
                "no session key: pass private_key, set VORDIUM_SESSION_KEY, "
                "or use SessionSigner.from_keystore(path)"
            )
        if not key.startswith("0x"):
            key = "0x" + key
        self._acct = Account.from_key(key)

    @classmethod
    def from_env(cls, var: str = "VORDIUM_SESSION_KEY") -> "SessionSigner":
        key = os.getenv(var)
        if not key:
            raise ValueError(f"env var {var} not set")
        return cls(private_key=key)

    @classmethod
    def from_keystore(cls, path: str, password: Optional[str] = None) -> "SessionSigner":
        """
        Load a session key from a JSON file. Supports both a plain
        ``{"private_key": "0x.."}`` file (like Wallet.save) and a standard
        eth keystore (needs ``password``).
        """
        with open(path) as f:
            data = json.load(f)
        if "private_key" in data:
            return cls(private_key=data["private_key"])
        if password is None:
            raise ValueError("keystore is encrypted -- password required")
        key = Account.decrypt(data, password)
        return cls(private_key="0x" + key.hex())

    @property
    def address(self) -> str:
        return self._acct.address

    def sign_digest(self, digest: bytes) -> str:
        """
        Sign a 32-byte EIP-712 digest and return 64-byte r||s hex (v dropped).

        ``digest`` is the fully-formed EIP-712 signing hash
        (``keccak256(0x1901 || domainSeparator || hashStruct(op))``) produced by
        the ``caps`` module. Uses ``unsafe_sign_hash`` (eth_account >= 0.13) or
        the older ``_sign_hash`` -- both sign the raw 32-byte hash with NO extra
        EIP-191 prefixing, so the chain recovers the signer over the exact same
        EIP-712 digest.
        """
        if len(digest) != 32:
            raise ValueError("digest must be 32 bytes")
        signer = getattr(Account, "unsafe_sign_hash", None) or getattr(
            Account, "_sign_hash"
        )
        signed = signer(digest, self._acct.key)
        return signed.signature[:64].hex()

    # -- convenience: build+sign each order digest in one call --------------
    def sign_place(
        self,
        owner,
        pair_id,
        side,
        size,
        price,
        leverage_bps,
        client_nonce,
        order_type: int = PlaceOrderType.LIMIT,
        reduce_only: bool = False,
        post_only: bool = False,
        trigger_price_8dec: int = 0,
        trigger_dir: int = 0,
    ) -> str:
        return self.sign_digest(
            place_order_digest(
                owner,
                pair_id,
                side,
                size,
                price,
                leverage_bps,
                order_type,
                reduce_only,
                client_nonce,
                post_only,
                trigger_price_8dec,
                trigger_dir,
            )
        )

    def sign_cancel(self, owner, order_id) -> str:
        return self.sign_digest(cancel_order_digest(owner, order_id))

    def sign_modify(self, owner, order_id, new_price, new_size) -> str:
        return self.sign_digest(
            modify_order_digest(owner, order_id, new_price, new_size)
        )

    def sign_set_tpsl(
        self, owner, pair_id, position_id, take_profit_8dec, stop_loss_8dec
    ) -> str:
        return self.sign_digest(
            set_tpsl_digest(
                owner, pair_id, position_id, take_profit_8dec, stop_loss_8dec
            )
        )


# ---------------------------------------------------------------------------
# AgentBox -- graceful reads (caps / balance / positions / orders / fills)
# ---------------------------------------------------------------------------
_NOT_LIVE = "agent predeploys not live yet -- deferred to deploy"


@dataclass
class ReadResult:
    """Wraps a read so callers can distinguish 'null because not-live' cleanly."""
    value: object
    live: bool
    note: str = ""


class AgentBox:
    """
    Read-only view of an agent's on-chain caps / balance and REST market data.

    GRACEFUL BY DESIGN: the agent-system predeploys (0x1005 / 0x1002 / 0x080B)
    are NOT deployed yet. eth_call returns ``0x`` against them, so every read
    returns ``None`` and reports a clean "not live yet -- deferred to deploy"
    note instead of throwing. This mirrors the UI/explorer pattern.
    """

    def __init__(self, rpc_url: str = None, rest_url: Optional[str] = None,
                 timeout: float = 10.0):
        net = None if rpc_url else get_network()
        self.rpc_url = rpc_url or net.rpc_url
        # REST market data lives on the node: an address you pass is used for both; else the network's REST base.
        self.rest_url = (rest_url or rpc_url or api_base(net)).rstrip("/")
        self.timeout = timeout

    # -- low-level eth_call, returns hex string or None on any failure ------
    def _eth_call(self, to: str, data_hex: str) -> Optional[str]:
        try:
            resp = requests.post(
                self.rpc_url,
                json={
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "eth_call",
                    "params": [{"to": to, "data": data_hex}, "latest"],
                },
                timeout=self.timeout,
            )
            out = resp.json()
            if "result" not in out:
                return None
            return out["result"]
        except Exception:
            return None

    @staticmethod
    def _abi_addr_arg(addr: str) -> str:
        """Left-pad a 20-byte address into a 32-byte ABI word (no selector)."""
        h = addr[2:] if addr.startswith("0x") else addr
        return "0x" + h.rjust(64, "0")

    @staticmethod
    def _is_empty(hexstr: Optional[str]) -> bool:
        return hexstr is None or hexstr in ("0x", "0X", "")

    @staticmethod
    def _words(hexstr: str) -> list[int]:
        raw = bytes.fromhex(hexstr[2:] if hexstr.startswith("0x") else hexstr)
        return [
            int.from_bytes(raw[i:i + 32], "big") for i in range(0, len(raw), 32)
        ]

    def read_caps(self, agent: str) -> Optional[AgentCaps]:
        """
        Read the 6-word cap struct from the 0x080B precompile.

        Returns ``None`` (not live) when the predeploy isn't deployed yet.
        Falls back to the AgentRegistry (0x1005) if the precompile is empty but
        the registry answers -- both are stubs today, so both return None.
        """
        result = self._eth_call(
            AGENT_CAPS_PRECOMPILE_ADDR, self._abi_addr_arg(agent)
        )
        if self._is_empty(result):
            # fallback: AgentRegistry.getCaps(address) -> selector 0x... + arg.
            # The registry is also a stub today; kept for when it goes live.
            result = self._eth_call(
                AGENT_REGISTRY_ADDR,
                _REGISTRY_GETCAPS_SELECTOR + self._abi_addr_arg(agent)[2:],
            )
        if self._is_empty(result):
            return None
        words = self._words(result)
        if len(words) < 6:
            return None
        return AgentCaps.from_words(words)

    def read_caps_verbose(self, agent: str) -> ReadResult:
        caps = self.read_caps(agent)
        if caps is None:
            return ReadResult(None, live=False, note=_NOT_LIVE)
        return ReadResult(caps, live=True)

    def read_balance(self, agent: str) -> Optional[int]:
        """
        Read VordexVaultThin.balances(address) -> USDC (6-dec) as an int.

        Returns ``None`` (not live) when the vault predeploy isn't deployed.
        """
        result = self._eth_call(
            VORDEX_VAULT_THIN_ADDR,
            _VAULT_BALANCES_SELECTOR + self._abi_addr_arg(agent)[2:],
        )
        if self._is_empty(result):
            return None
        words = self._words(result)
        return words[0] if words else None

    def read_balance_verbose(self, agent: str) -> ReadResult:
        bal = self.read_balance(agent)
        if bal is None:
            return ReadResult(None, live=False, note=_NOT_LIVE)
        return ReadResult(bal, live=True)

    # -- REST reads (positions / orders / fills), all graceful --------------
    def _rest_get(self, path: str) -> Optional[object]:
        try:
            r = requests.get(self.rest_url + path, timeout=self.timeout)
            if r.status_code != 200:
                return None
            return r.json()
        except Exception:
            return None

    def positions(self, address: str) -> Optional[object]:
        """GET /positions/{address} -- None if not live / unreachable."""
        return self._rest_get(f"/positions/{address}")

    def orders(self, address: str) -> Optional[object]:
        """GET /orders/{address} -- None if not live / unreachable."""
        return self._rest_get(f"/orders/{address}")

    def fills(self, pair_id: int) -> Optional[object]:
        """GET /fills/{pair_id} -- None if not live / unreachable."""
        return self._rest_get(f"/fills/{pair_id}")


# Selectors kept next to the reads that use them. These are the standard
# keccak-4 selectors; they only matter once the registry/vault go live.
#   balances(address)  -> 0x27e235e3
#   getCaps(address)   -> 0x6dde7209  (illustrative; registry is a stub today)
_VAULT_BALANCES_SELECTOR = "27e235e3"
_REGISTRY_GETCAPS_SELECTOR = "6dde7209"


# ---------------------------------------------------------------------------
# Operator -- build + session-sign + submit, with a local cap pre-check
# ---------------------------------------------------------------------------
class Operator:
    """
    Drives an agent's trading account with a session key.

    Flow for every order:
      1. build the tagged digest (owner = trading account),
      2. run the LOCAL cap pre-check (fail fast; chain re-checks),
      3. session-sign the digest -> 64-byte r||s hex,
      4. POST the JSON body (incl owner, session_key, fields, signature).

    The chain is the authority; this is convenience + a pre-flight guard.
    """

    def __init__(
        self,
        owner: str,
        signer: SessionSigner,
        box: Optional[AgentBox] = None,
        submit_url: Optional[str] = None,
    ):
        self.owner = owner
        self.signer = signer
        self.box = box or AgentBox()
        # order intake HTTP base; defaults to the node RPC host.
        self.submit_url = (submit_url or self.box.rest_url).rstrip("/")
        # The signer signs under the process network's domain; before it signs, the node this client posts to must
        # serve that same network (its /status), or nothing is signed.
        self._node = NodeDomain(self.submit_url, get_network())

    def _checked_signer(self) -> SessionSigner:
        self._node.identity()          # raises NetworkMismatch when the node serves another network
        return self.signer

    # -- HTTP submit --------------------------------------------------------
    def _post(self, path: str, body: dict) -> dict:
        r = requests.post(
            self.submit_url + path, json=body, timeout=self.box.timeout
        )
        try:
            return r.json()
        except Exception:
            return {"status_code": r.status_code, "text": r.text}

    # -- place --------------------------------------------------------------
    def place_order(
        self,
        pair_id: int,
        side: int,
        size: int,
        price: int,
        leverage_bps: int,
        client_nonce: int,
        order_type: int = PlaceOrderType.LIMIT,
        reduce_only: bool = False,
        post_only: bool = False,
        trigger_price_8dec: int = 0,
        trigger_dir: int = 0,
        caps: Optional[AgentCaps] = None,
        current_net_position: int = 0,
        precheck: bool = True,
    ) -> dict:
        """
        Build, cap-check, session-sign and submit a PlaceOrder.

        Units: ``size`` is canonical u128 18-dec, ``price`` is canonical u64
        8-dec, ``leverage_bps`` is bps (10000 == 1x). For a LIMIT order ``price``
        is the limit price, signed AS-IS, and must be a multiple of 100 (the
        chain keeps 6 decimals of a price). A MARKET order carries no price: it
        is signed with price 0, and ``price`` is used only by the local cap
        check (as the price the order is expected to fill near).

        ``order_type`` is the wire uint8: 0=Market or 1=Limit. Stop orders
        (2, 3) are not available and are refused before signing, as is any
        non-zero ``trigger_price_8dec`` / ``trigger_dir`` (raises
        ``OrderNotAvailable``). ``reduce_only`` and ``post_only`` are the wire
        bools. All fields are bound into the EIP-712 digest. The SDK owns
        ``client_nonce``; the chain does not assign nonces.

        If ``precheck`` and ``caps`` are provided, the local
        ``agent_cap_check`` runs first and raises ``CapError`` on violation.
        """
        _wire(SIDE_NAMES, side, "side")
        _wire(ORDER_TYPE_NAMES, order_type, "order_type")
        refuse_unavailable(order_type, trigger_price_8dec, trigger_dir)
        if precheck and caps is not None:
            agent_cap_check(
                caps,
                CandidateOrder(
                    pair_id=pair_id,
                    side=side,
                    size=size,
                    price=price,
                    leverage_bps=leverage_bps,
                    order_type=order_type,
                ),
                current_net_position=current_net_position,
            )
        wire_price = price if order_type in PRICED else 0
        sig = self._checked_signer().sign_place(
            self.owner,
            pair_id,
            side,
            size,
            wire_price,
            leverage_bps,
            client_nonce,
            order_type,
            reduce_only,
            post_only,
            trigger_price_8dec,
            trigger_dir,
        )
        body = place_order_body(
            self.owner, self.signer.address, pair_id, side, size, wire_price, leverage_bps, order_type, reduce_only,
            post_only, trigger_price_8dec, trigger_dir, client_nonce, sig,
        )
        return self._post("/order/place", body)

    # -- market convenience -------------------------------------------------
    def place_market_order(
        self,
        pair_id: int,
        side: int,
        size: int,
        cap_price: int,
        leverage_bps: int,
        client_nonce: int,
        reduce_only: bool = False,
        caps: Optional[AgentCaps] = None,
        current_net_position: int = 0,
        precheck: bool = True,
    ) -> dict:
        """
        Submit a MARKET order (``order_type=0``).

        The order carries no price and is signed with price 0. ``cap_price``
        (canonical u64 8-dec) is used only by the local cap check.
        """
        return self.place_order(
            pair_id=pair_id,
            side=side,
            size=size,
            price=cap_price,
            leverage_bps=leverage_bps,
            client_nonce=client_nonce,
            order_type=PlaceOrderType.MARKET,
            reduce_only=reduce_only,
            caps=caps,
            current_net_position=current_net_position,
            precheck=precheck,
        )

    # -- cancel -------------------------------------------------------------
    def cancel_order(self, order_id: int) -> dict:
        sig = self._checked_signer().sign_cancel(self.owner, order_id)
        return self._post("/order/cancel", cancel_order_body(self.owner, self.signer.address, order_id, sig))

    # -- modify -------------------------------------------------------------
    def modify_order(self, order_id: int, new_price: int, new_size: int) -> dict:
        """Not available here. Use :meth:`vordium.mm.MarketMaker.modify` (a signed cancel-and-replace, on a network that
        publishes the market-maker release in ``GET /markets/specs``), or cancel the order and place a new one.

        Raises before anything is signed or sent.
        """
        raise NotImplementedError("Operator does not modify orders: use MarketMaker.modify, or cancel the order and place a new one")

    # -- set take-profit / stop-loss on an open position --------------------
    def set_tpsl(
        self,
        pair_id: int,
        position_id: int,
        take_profit_8dec: int = 0,
        stop_loss_8dec: int = 0,
    ) -> dict:
        """
        Attach a take-profit / stop-loss to an open position.

        ``take_profit_8dec`` and ``stop_loss_8dec`` are canonical u64 8-dec
        prices; ``0`` leaves that leg unset. Session-key signed -- the ``owner``
        field stays the trading account and the session key signs the SetTpSl
        EIP-712 digest.
        """
        sig = self._checked_signer().sign_set_tpsl(
            self.owner, pair_id, position_id, take_profit_8dec, stop_loss_8dec
        )
        body = set_tpsl_body(self.owner, self.signer.address, pair_id, position_id, take_profit_8dec,
                             stop_loss_8dec, sig)
        return self._post("/tpsl/set", body)

    # -- stop orders ---------------------------------------------------------
    def place_stop_order(
        self,
        pair_id: int,
        side: int,
        size: int,
        price: int,
        leverage_bps: int,
        client_nonce: int,
        trigger_price_8dec: int,
        trigger_dir: int,
        order_type: int = PlaceOrderType.STOP_MARKET,
        reduce_only: bool = False,
        post_only: bool = False,
        caps: Optional[AgentCaps] = None,
        current_net_position: int = 0,
        precheck: bool = True,
    ) -> dict:
        """
        Stop orders are not available on the chain: this raises
        ``OrderNotAvailable`` and signs nothing. Set a take-profit or
        stop-loss on the position with :meth:`set_tpsl`.
        """
        raise OrderNotAvailable(STOP_REFUSAL)

    # -- build-only helpers (sign without submitting) -----------------------
    def build_place_body(
        self, pair_id, side, size, price, leverage_bps, client_nonce,
        order_type: int = PlaceOrderType.LIMIT, reduce_only: bool = False,
        post_only: bool = False, trigger_price_8dec: int = 0, trigger_dir: int = 0,
    ) -> dict:
        """Build the signed PlaceOrder body without submitting (for tests/dry-run)."""
        refuse_unavailable(order_type, trigger_price_8dec, trigger_dir)
        price = price if order_type in PRICED else 0
        sig = self._checked_signer().sign_place(
            self.owner, pair_id, side, size, price, leverage_bps, client_nonce,
            order_type, reduce_only, post_only, trigger_price_8dec, trigger_dir,
        )
        return place_order_body(
            self.owner, self.signer.address, pair_id, side, size, price, leverage_bps, order_type, reduce_only,
            post_only, trigger_price_8dec, trigger_dir, client_nonce, sig,
        )

    def build_set_tpsl_body(
        self, pair_id, position_id, take_profit_8dec=0, stop_loss_8dec=0,
    ) -> dict:
        """Build the signed SetTpSl body without submitting (for tests/dry-run)."""
        sig = self._checked_signer().sign_set_tpsl(
            self.owner, pair_id, position_id, take_profit_8dec, stop_loss_8dec
        )
        return set_tpsl_body(self.owner, self.signer.address, pair_id, position_id, take_profit_8dec,
                             stop_loss_8dec, sig)
