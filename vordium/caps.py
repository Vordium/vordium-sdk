"""
Agent Operator caps + order-signing primitives.

This module is the LOCAL, deterministic half of the "Agent Operator" extension.
It is a CONVENIENCE + PRE-CHECK layer only. The CHAIN is always the authority:

  * A session key can only ever do what the native ``agent_order_gate``
    allows. It can NEVER withdraw funds and NEVER change caps -- those need
    the account's own key and are enforced on-chain.
  * ``agent_cap_check`` below is a faithful integer port of the native check so
    an operator can fail fast BEFORE spending a round-trip, but the chain
    re-runs the exact same check authoritatively on apply. If this local port
    and the chain ever disagree, the CHAIN wins.

Nothing in this file signs anything or touches a private key -- see
``operator.SessionSigner`` for that. Everything here is pure and unit-testable
without a node.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum

from eth_utils import keccak

# --- Genesis predeploy addresses (agent system) -----------------------------
# Not deployed yet on the live chain -- reads against these return 0x until the
# agent-system predeploys go live (see operator.AgentBox for graceful handling).
AGENT_REGISTRY_ADDR = "0x0000000000000000000000000000000000001005"
VORDEX_VAULT_THIN_ADDR = "0x0000000000000000000000000000000000001002"
AGENT_CAPS_PRECOMPILE_ADDR = "0x000000000000000000000000000000000000080B"

# --- EIP-712 typed-data signing (chain verification) ------------------------
# The chain verifies agent ops via EIP-712 typed data. Every op is signed over
#     digest = keccak256(0x1901 || domainSeparator || hashStruct(op))
# with the SAME domain for every op. The session key signs that 32-byte digest
# directly (v dropped -> 64-byte r||s). These constants MUST match the chain
# byte-for-byte.
# chainId + verifyingContract are RESOLVED AT RUNTIME (vordium.network). There is
# deliberately NO chainId constant in this module: a copied chainId can go
# stale, and a stale one makes every signed op fail. Name/version are protocol
# constants shared from the network module.
from .network import (
    EIP712_DOMAIN_NAME,
    NetworkResolutionError,
    EIP712_DOMAIN_VERSION,
    get_network,
)

_EIP712_DOMAIN_TYPEHASH = keccak(
    b"EIP712Domain(string name,string version,uint256 chainId,"
    b"address verifyingContract,bytes32 salt)"  # 5-field, genesis-bound salt
)

# Class tag for the VordCore signing domain; the salt is keccak(tag || genesis_sha256_bytes).
# This REPRODUCES the node-authoritative domain (verified against the chain's published separator); it is
# NOT a self-composed domain — a saltless/4-field domain is REJECTED by the chain.
_VORDCORE_SALT_TAG = b"VORDIUM_VORDCORE\x01"

_PLACE_ORDER_TYPEHASH = keccak(
    b"PlaceOrder(address owner,uint32 pairId,uint8 side,uint128 size,"
    b"uint64 price,uint32 leverageBps,uint8 orderType,bool reduceOnly,"
    b"bool postOnly,uint64 triggerPrice8dec,uint8 triggerDir,"
    b"uint64 clientNonce)"
)
_CANCEL_ORDER_TYPEHASH = keccak(b"CancelOrder(address owner,uint64 orderId)")
_SCHEDULE_CANCEL_TYPEHASH = keccak(b"ScheduleCancel(address owner,uint64 cancelAtMs,uint64 nonce)")
_MODIFY_ORDER_TYPEHASH = keccak(
    b"ModifyOrder(address owner,uint64 orderId,uint64 newPrice,uint128 newSize)"
)
_SET_AGENT_CAPS_TYPEHASH = keccak(
    b"SetAgentCaps(address owner,uint64 maxLeverage,uint32 allowedOrderTypes,"
    b"uint128 maxInputPerTrade,uint128 maxTotalPosition)"
)
_SET_AGENT_MODE_TYPEHASH = keccak(b"SetAgentMode(address owner,uint8 mode)")
_SET_TPSL_TYPEHASH = keccak(
    b"SetTpSl(address owner,uint32 pairId,uint64 positionId,"
    b"uint64 takeProfit8dec,uint64 stopLoss8dec)"
)

# --- Unit scales (documented, used by the cap math) -------------------------
SIZE_DECIMALS = 18       # order size is a u128 with 18 decimals
PRICE_DECIMALS = 8       # order price is a u64 with 8 decimals
USDC_DECIMALS = 6        # margin / input caps are 6-decimal USDC
LEVERAGE_ONE_X_BPS = 10000  # 10000 bps == 1x


class AgentMode(IntEnum):
    """On-chain agent mode enum."""
    OFF = 0
    REDUCE_ONLY = 1
    ACTIVE = 2


class OrderType(IntEnum):
    """
    Order-type bit indices for the ``allowed_order_types`` bitmask.

    The chain checks ``allowed_order_types & (1 << (order_type & 31))``. These
    indices are the SDK's convenience names; the only load-bearing thing is the
    integer used as the bit index. NOTE: these are the CAP-BITMASK
    indices, which are a SEPARATE numbering from the wire ``orderType``
    field signed into the PlaceOrder digest -- see ``PlaceOrderType``.
    """
    LIMIT = 0
    MARKET = 1
    POST_ONLY = 2
    IOC = 3
    REDUCE_ONLY = 4


class PlaceOrderType(IntEnum):
    """
    Wire ``orderType`` values, signed into the PlaceOrder EIP-712 digest.

    This is the on-the-wire uint8 the chain reads from the PlaceOrder struct.
    It is DISTINCT from ``OrderType`` above (which is a cap-bitmask bit index).
    The chain accepts MARKET and LIMIT; STOP_MARKET and STOP_LIMIT are kept
    because the signed format names them, and every order path refuses them.
    """
    MARKET = 0
    LIMIT = 1
    STOP_MARKET = 2
    STOP_LIMIT = 3


class Side(IntEnum):
    """Order side. Buy increases net position, sell decreases it."""
    BUY = 0
    SELL = 1


@dataclass(frozen=True)
class AgentCaps:
    """
    The 6-word cap struct returned by the agentCaps read precompile (0x080B).

    Fields mirror the on-chain layout exactly:
        mode                 u8   (see AgentMode)
        caps_set             u8   (0/1 -- caps must be explicitly set)
        max_leverage         u64  (bps, e.g. 200000 == 20x)
        allowed_order_types  u32  (bitmask over OrderType bit indices)
        max_input_per_trade  u128 (6-decimal USDC margin cap per trade)
        max_total_position   u128 (18-decimal absolute net position cap)
    """
    mode: int
    caps_set: int
    max_leverage: int
    allowed_order_types: int
    max_input_per_trade: int
    max_total_position: int

    @classmethod
    def from_words(cls, words: list[int]) -> "AgentCaps":
        """Build from 6 decoded 32-byte words (as ints)."""
        if len(words) < 6:
            raise ValueError(f"expected 6 cap words, got {len(words)}")
        return cls(
            mode=words[0] & 0xFF,
            caps_set=words[1] & 0xFF,
            max_leverage=words[2],
            allowed_order_types=words[3] & 0xFFFFFFFF,
            max_input_per_trade=words[4],
            max_total_position=words[5],
        )


@dataclass(frozen=True)
class CandidateOrder:
    """A candidate order the operator wants to place, for the local pre-check."""
    pair_id: int
    side: int          # Side
    size: int          # u128, 18-dec
    price: int         # u64, 8-dec
    leverage_bps: int  # u32
    order_type: int = OrderType.LIMIT


# --- EIP-712 encoding helpers -----------------------------------------------
#
# Every op is signed over an EIP-712 digest, NOT a tagged-keccak preimage. Each
# field is ABI-encoded into a 32-byte word (uints big-endian, address right-
# aligned), the struct hash is keccak256(typeHash || words...), and the signed
# digest is keccak256(0x1901 || domainSeparator || structHash). These MUST match
# the chain byte-for-byte.


def _addr_bytes(addr: str) -> bytes:
    """Normalize a 0x-hex address to its raw 20 bytes."""
    h = addr[2:] if addr.startswith(("0x", "0X")) else addr
    b = bytes.fromhex(h)
    if len(b) != 20:
        raise ValueError(f"owner must be a 20-byte address, got {len(b)} bytes")
    return b


def _u256(value: int) -> bytes:
    """ABI-encode an unsigned integer as a 32-byte big-endian word."""
    v = int(value)
    if v < 0:
        raise ValueError("EIP-712 uint field cannot be negative")
    return v.to_bytes(32, "big")


def _addr32(addr: str) -> bytes:
    """ABI-encode a 20-byte address as a right-aligned 32-byte word."""
    return bytes(12) + _addr_bytes(addr)


def _vordcore_salt(genesis_sha256: str) -> bytes:
    """Genesis-bound salt = keccak(VORDIUM_VORDCORE\x01 || genesis_sha256_bytes)."""
    g = genesis_sha256[2:] if genesis_sha256.startswith("0x") else genesis_sha256
    return keccak(_VORDCORE_SALT_TAG + bytes.fromhex(g))


def vordcore_domain_separator(chain_id: int, verifying_contract: str, genesis_sha256: str) -> bytes:
    """Pure (no network) 5-field genesis-bound VordCore domainSeparator. Testable in isolation.

    On the mainnet genesis (2c1c0679…) this equals the chain's published value
    ``0x68b86feeb9a9d9d471c3355da4719f2ce6a2330fbde6dad54d815783dacab34b``.
    """
    return keccak(
        _EIP712_DOMAIN_TYPEHASH
        + keccak(EIP712_DOMAIN_NAME.encode())
        + keccak(EIP712_DOMAIN_VERSION.encode())
        + _u256(chain_id)
        + _addr32(verifying_contract)
        + _vordcore_salt(genesis_sha256)
    )


def domain_separator() -> bytes:
    """EIP-712 domainSeparator for the VordCore domain (genesis-bound salt).

    chainId + verifyingContract + genesis_sha256 are RUNTIME-resolved from :mod:`vordium.network`
    (the node's /status), so it tracks the chain the node serves with no code change — one source of truth. If the
    genesis is unknown the SDK REFUSES to sign rather than emit a domain the chain would reject."""
    net = get_network()
    if not getattr(net, "genesis_sha256", None):
        raise NetworkResolutionError(
            "genesis_sha256 unavailable from the node's /status — cannot build the genesis-bound "
            "VordCore EIP-712 domain. The chain rejects a saltless/4-field domain, so the SDK "
            "refuses to sign rather than produce a rejected signature. Point at a node whose /status "
            "exposes genesis_sha256."
        )
    return vordcore_domain_separator(net.chain_id, net.verifying_contract, net.genesis_sha256)


def _eip712_digest(struct_hash: bytes) -> bytes:
    """The 32 bytes actually signed: keccak256(0x1901 || domainSep || structHash)."""
    return keccak(b"\x19\x01" + domain_separator() + struct_hash)


def __getattr__(name: str):
    # ``DOMAIN_SEPARATOR`` is a runtime value, resolved lazily on attribute access
    # (never at import), so ``import vordium`` triggers no network call.
    if name == "DOMAIN_SEPARATOR":
        return domain_separator()
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


# --- Struct hashes + signing digests (EIP-712) ------------------------------


def place_order_struct_hash(
    owner: str,
    pair_id: int,
    side: int,
    size: int,
    price: int,
    leverage_bps: int,
    order_type: int,
    reduce_only: bool,
    client_nonce: int,
    post_only: bool = False,
    trigger_price_8dec: int = 0,
    trigger_dir: int = 0,
) -> bytes:
    """hashStruct(PlaceOrder) -- keccak256(typeHash || encoded fields).

    Shape: ``orderType`` (uint8) and ``reduceOnly`` (bool) are encoded
    between ``leverageBps`` and ``clientNonce``. The chain accepts orderType
    0 (Market) and 1 (Limit); the order paths refuse 2 and 3 (stop orders are
    not available).

    ``postOnly`` (bool), ``triggerPrice8dec`` (uint64) and ``triggerDir``
    (uint8) are encoded between ``reduceOnly`` and ``clientNonce``. The
    trigger fields belong to stop orders and are signed as 0.
    Bools are encoded as 32-byte 0/1 words. ``size`` is canonical u128 18-dec,
    ``price`` is canonical u64 8-dec -- signed as-is, no server derivation.
    """
    return keccak(
        _PLACE_ORDER_TYPEHASH
        + _addr32(owner)
        + _u256(pair_id)
        + _u256(side)
        + _u256(size)
        + _u256(price)
        + _u256(leverage_bps)
        + _u256(order_type)
        + _u256(1 if reduce_only else 0)
        + _u256(1 if post_only else 0)
        + _u256(trigger_price_8dec)
        + _u256(trigger_dir)
        + _u256(client_nonce)
    )


def place_order_digest(
    owner: str,
    pair_id: int,
    side: int,
    size: int,
    price: int,
    leverage_bps: int,
    order_type: int,
    reduce_only: bool,
    client_nonce: int,
    post_only: bool = False,
    trigger_price_8dec: int = 0,
    trigger_dir: int = 0,
) -> bytes:
    """EIP-712 digest for PlaceOrder -- the 32 bytes the session key signs."""
    return _eip712_digest(
        place_order_struct_hash(
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


def cancel_order_struct_hash(owner: str, order_id: int) -> bytes:
    """hashStruct(CancelOrder)."""
    return keccak(_CANCEL_ORDER_TYPEHASH + _addr32(owner) + _u256(order_id))


def cancel_order_digest(owner: str, order_id: int) -> bytes:
    """EIP-712 digest for CancelOrder."""
    return _eip712_digest(cancel_order_struct_hash(owner, order_id))


_U64_MAX = (1 << 64) - 1


def _u64(name: str, value: int) -> int:
    v = int(value)
    if v < 0 or v > _U64_MAX:
        raise ValueError(f"{name} must fit an unsigned 64-bit integer")
    return v


def schedule_cancel_struct_hash(owner: str, cancel_at_ms: int, nonce: int) -> bytes:
    """hashStruct(ScheduleCancel). ``cancel_at_ms`` 0 clears the switch."""
    return keccak(_SCHEDULE_CANCEL_TYPEHASH + _addr32(owner) + _u256(_u64("cancel_at_ms", cancel_at_ms))
                  + _u256(_u64("nonce", nonce)))


def schedule_cancel_digest(owner: str, cancel_at_ms: int, nonce: int) -> bytes:
    """EIP-712 digest for ScheduleCancel (the VordCore domain, as PlaceOrder)."""
    return _eip712_digest(schedule_cancel_struct_hash(owner, cancel_at_ms, nonce))


def modify_order_struct_hash(
    owner: str, order_id: int, new_price: int, new_size: int
) -> bytes:
    """hashStruct(ModifyOrder)."""
    return keccak(
        _MODIFY_ORDER_TYPEHASH
        + _addr32(owner)
        + _u256(order_id)
        + _u256(new_price)
        + _u256(new_size)
    )


def modify_order_digest(
    owner: str, order_id: int, new_price: int, new_size: int
) -> bytes:
    """EIP-712 digest for ModifyOrder."""
    return _eip712_digest(
        modify_order_struct_hash(owner, order_id, new_price, new_size)
    )


def set_tpsl_struct_hash(
    owner: str,
    pair_id: int,
    position_id: int,
    take_profit_8dec: int,
    stop_loss_8dec: int,
) -> bytes:
    """hashStruct(SetTpSl) -- keccak256(typeHash || encoded fields).

    Attaches a take-profit / stop-loss to an open position. Prices are
    canonical u64 8-dec; ``0`` means that leg is unset. This is a SESSION-KEY
    op -- the session key signs the digest; ``owner`` stays the trading account.
    """
    return keccak(
        _SET_TPSL_TYPEHASH
        + _addr32(owner)
        + _u256(pair_id)
        + _u256(position_id)
        + _u256(take_profit_8dec)
        + _u256(stop_loss_8dec)
    )


def set_tpsl_digest(
    owner: str,
    pair_id: int,
    position_id: int,
    take_profit_8dec: int,
    stop_loss_8dec: int,
) -> bytes:
    """EIP-712 digest for SetTpSl -- the 32 bytes the session key signs."""
    return _eip712_digest(
        set_tpsl_struct_hash(
            owner, pair_id, position_id, take_profit_8dec, stop_loss_8dec
        )
    )


# The two owner-only ops below are NOT session-key operations -- an operator can
# never change caps or mode. They are provided so the OWNER flow (browser / SDK)
# can produce chain-accepted EIP-712 signatures over the same domain.


def set_agent_caps_struct_hash(
    owner: str,
    max_leverage: int,
    allowed_order_types: int,
    max_input_per_trade: int,
    max_total_position: int,
) -> bytes:
    """hashStruct(SetAgentCaps)."""
    return keccak(
        _SET_AGENT_CAPS_TYPEHASH
        + _addr32(owner)
        + _u256(max_leverage)
        + _u256(allowed_order_types)
        + _u256(max_input_per_trade)
        + _u256(max_total_position)
    )


def set_agent_caps_digest(
    owner: str,
    max_leverage: int,
    allowed_order_types: int,
    max_input_per_trade: int,
    max_total_position: int,
) -> bytes:
    """EIP-712 digest for SetAgentCaps (OWNER-signed, not a session-key op)."""
    return _eip712_digest(
        set_agent_caps_struct_hash(
            owner,
            max_leverage,
            allowed_order_types,
            max_input_per_trade,
            max_total_position,
        )
    )


def set_agent_mode_struct_hash(owner: str, mode: int) -> bytes:
    """hashStruct(SetAgentMode)."""
    return keccak(_SET_AGENT_MODE_TYPEHASH + _addr32(owner) + _u256(mode))


def set_agent_mode_digest(owner: str, mode: int) -> bytes:
    """EIP-712 digest for SetAgentMode (OWNER-signed, not a session-key op)."""
    return _eip712_digest(set_agent_mode_struct_hash(owner, mode))


# --- Local cap pre-check (port of native agent_cap_check) -------------------


class CapError(ValueError):
    """Raised by ``agent_cap_check`` when a candidate order violates caps."""


def notional_6dec(price: int, size: int) -> int:
    """
    notional in 6-decimal USDC = price(8-dec) * size(18-dec) // 10**20.
    Integer arithmetic, matching the chain.
    """
    return (int(price) * int(size)) // (10 ** 20)


def margin_6dec(price: int, size: int, leverage_bps: int) -> int:
    """margin (6-dec USDC) = notional_6dec * 10000 // leverage_bps."""
    return (notional_6dec(price, size) * LEVERAGE_ONE_X_BPS) // int(leverage_bps)


def agent_cap_check(
    caps: AgentCaps,
    order: CandidateOrder,
    current_net_position: int = 0,
) -> None:
    """
    Reject a candidate order BEFORE sending if it violates the on-chain caps.

    This is a LOCAL fast-fail only -- a faithful integer port of the native
    ``agent_cap_check``. The chain re-checks authoritatively on apply,
    so passing here is necessary but NOT sufficient; the chain has the final say.

    Raises ``CapError`` with a clear message on the first violation.
    ``current_net_position`` is the agent's signed net position on this pair,
    18-dec (positive = long, negative = short).
    """
    mode = caps.mode

    if mode == AgentMode.OFF:
        raise CapError("agent mode OFF")

    if not caps.caps_set:
        raise CapError("agent caps unset")

    # order-type allowed?
    if (caps.allowed_order_types & (1 << (int(order.order_type) & 31))) == 0:
        raise CapError("order type not allowed")

    # leverage within [1, max]
    if order.leverage_bps < 1 or order.leverage_bps > caps.max_leverage:
        raise CapError("leverage over cap")

    # input (margin) cap
    m6 = margin_6dec(order.price, order.size, order.leverage_bps)
    if m6 > caps.max_input_per_trade:
        raise CapError("input over cap")

    # resulting net position (signed) after this order
    signed_size = int(order.size) if order.side == Side.BUY else -int(order.size)
    new_net = int(current_net_position) + signed_size
    new_pos_abs = abs(new_net)

    # REDUCE_ONLY must strictly reduce the absolute net position
    if mode == AgentMode.REDUCE_ONLY:
        if new_pos_abs >= abs(int(current_net_position)):
            raise CapError("reduce-only: order does not reduce position")

    # total position cap
    if new_pos_abs > caps.max_total_position:
        raise CapError("position over cap")
