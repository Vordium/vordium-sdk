"""
Unit tests for the Agent Operator extension.

No live node required. Covers:
  * digest byte-match against a pinned test vector (shared with the JS SDK),
  * 64-byte r||s signing that recovers to the session key,
  * the local cap pre-check: every boundary + every mode,
  * graceful reads (predeploys not live -> None),
  * a deferred-to-deploy live end-to-end placeholder (xfail).
"""

import pytest
from eth_account import Account

from vordium.caps import (
    AgentCaps,
    AgentMode,
    CandidateOrder,
    CapError,
    OrderType,
    Side,
    agent_cap_check,
    margin_6dec,
    notional_6dec,
    domain_separator,
    place_order_digest,
    cancel_order_digest,
    modify_order_digest,
    set_agent_caps_digest,
    set_agent_mode_digest,
    set_tpsl_digest,
)
from vordium.operator import AgentBox, Operator, SessionSigner


# ---------------------------------------------------------------------------
# Inputs used by the signing / structure tests below (arbitrary but valid).
# ---------------------------------------------------------------------------
VEC_OWNER = "0x1111111111111111111111111111111111111111"
VEC_PAIR = 1
VEC_SIDE = 0          # BUY
VEC_SIZE = 10 ** 18   # 1.0 (18-dec)
VEC_PRICE = 250000000000  # 2500.00000000 (8-dec)
VEC_LEV = 20000       # 2x
VEC_ORDER_TYPE = 1    # Limit (wire value)
VEC_REDUCE_ONLY = False
VEC_NONCE = 42


# ---------------------------------------------------------------------------
# MANDATORY EIP-712 byte-match gate.
# The SDK's EIP-712 digest MUST equal each pinned vector byte-for-byte, and the
# domainSeparator MUST match the authoritative constant. Inputs are the pinned
# vectors from the migration spec; these are also asserted by the JS SDK.
# ---------------------------------------------------------------------------
E712_OWNER = "0x1111111111111111111111111111111111111111"
E712_TO = "0x2222222222222222222222222222222222222222"

# Chain-authoritative VordCore domain separator on live 101101 (node-pinned,
# the published EIP-712 source-of-truth). Under the offline
# network pin in conftest.py (chainId 101101), the SDK must reproduce it.
CHAIN_DOMAIN_SEPARATOR = (
    "0x68b86feeb9a9d9d471c3355da4719f2ce6a2330fbde6dad54d815783dacab34b"
)


def _hx(b: bytes) -> str:
    return "0x" + b.hex()


def test_domain_separator_equals_chain_value():
    # Resolved from chainId 101101, must equal the chain's own domainSeparator —
    # this is what makes SDK signatures verify on-chain. Per-op digest
    # byte-agreement across both signers is asserted in test_eip712_vectors.py.
    assert _hx(domain_separator()) == CHAIN_DOMAIN_SEPARATOR


# ---------------------------------------------------------------------------
# Signing: 64-byte r||s that recovers to the session key
# ---------------------------------------------------------------------------
def test_sign_produces_64_byte_rs_recovering_to_session_key():
    acct = Account.create()
    signer = SessionSigner(private_key=acct.key.hex())
    assert signer.address == acct.address

    digest = place_order_digest(
        VEC_OWNER, VEC_PAIR, VEC_SIDE, VEC_SIZE, VEC_PRICE, VEC_LEV,
        VEC_ORDER_TYPE, VEC_REDUCE_ONLY, VEC_NONCE
    )
    rs_hex = signer.sign_digest(digest)
    rs = bytes.fromhex(rs_hex)
    assert len(rs) == 64  # r||s, v dropped

    # recover: try both v candidates (27/28) since v was dropped
    recovered = None
    for v in (27, 28):
        try:
            cand = Account._recover_hash(digest, signature=rs + bytes([v]))
        except Exception:
            continue
        if cand == acct.address:
            recovered = cand
            break
    assert recovered == acct.address


def test_owner_stays_trading_account_session_key_signs():
    """owner in the payload is the trading account; the session key signs."""
    owner = VEC_OWNER
    session = Account.create()
    signer = SessionSigner(private_key=session.key.hex())
    op = Operator(owner=owner, signer=signer, box=AgentBox())
    body = op.build_place_body(
        VEC_PAIR, VEC_SIDE, VEC_SIZE, VEC_PRICE, VEC_LEV, VEC_NONCE
    )
    assert body["owner"] == owner
    assert body["session_key"] == session.address
    assert len(bytes.fromhex(body["signature"])) == 64


def test_build_set_tpsl_body_session_signs():
    """SetTpSl body: owner is the trading account; session key signs."""
    owner = VEC_OWNER
    session = Account.create()
    signer = SessionSigner(private_key=session.key.hex())
    op = Operator(owner=owner, signer=signer, box=AgentBox())
    body = op.build_set_tpsl_body(1, 42, 3500000000, 2500000000)
    assert body["owner"] == owner
    assert body["session_key"] == session.address
    assert body["pair_id"] == 1
    assert body["position_id"] == 42
    assert body["take_profit_8dec"] == "3500000000"
    assert body["stop_loss_8dec"] == "2500000000"
    assert len(bytes.fromhex(body["signature"])) == 64

    # signature recovers to the session key over the SetTpSl digest
    digest = set_tpsl_digest(owner, 1, 42, 3500000000, 2500000000)
    rs = bytes.fromhex(body["signature"])
    recovered = None
    for v in (27, 28):
        try:
            cand = Account._recover_hash(digest, signature=rs + bytes([v]))
        except Exception:
            continue
        if cand == session.address:
            recovered = cand
            break
    assert recovered == session.address


# ---------------------------------------------------------------------------
# Cap pre-check -- helpers
# ---------------------------------------------------------------------------
def make_caps(
    mode=AgentMode.ACTIVE,
    caps_set=1,
    max_leverage=200000,          # 20x
    allowed_order_types=0xFFFFFFFF,
    max_input_per_trade=10 ** 12,  # huge (1,000,000 USDC 6-dec)
    max_total_position=10 ** 30,   # huge
):
    return AgentCaps(
        mode=int(mode),
        caps_set=caps_set,
        max_leverage=max_leverage,
        allowed_order_types=allowed_order_types,
        max_input_per_trade=max_input_per_trade,
        max_total_position=max_total_position,
    )


def make_order(
    side=Side.BUY,
    size=10 ** 18,
    price=250000000000,
    leverage_bps=20000,
    order_type=OrderType.LIMIT,
    pair_id=1,
):
    return CandidateOrder(
        pair_id=pair_id, side=int(side), size=size, price=price,
        leverage_bps=leverage_bps, order_type=int(order_type),
    )


# ---------------------------------------------------------------------------
# Cap math sanity
# ---------------------------------------------------------------------------
def test_notional_and_margin_math():
    # price 2500 (8-dec) * size 1.0 (18-dec) = 2500 USDC notional (6-dec)
    assert notional_6dec(250000000000, 10 ** 18) == 2500 * 10 ** 6
    # at 2x leverage, margin is half the notional
    assert margin_6dec(250000000000, 10 ** 18, 20000) == 1250 * 10 ** 6


# ---------------------------------------------------------------------------
# Cap pre-check -- modes
# ---------------------------------------------------------------------------
def test_mode_off_rejects_all():
    caps = make_caps(mode=AgentMode.OFF)
    with pytest.raises(CapError, match="agent mode OFF"):
        agent_cap_check(caps, make_order())


def test_mode_active_within_cap_passes():
    caps = make_caps(mode=AgentMode.ACTIVE)
    agent_cap_check(caps, make_order())  # must not raise


def test_reduce_only_rejects_increasing():
    caps = make_caps(mode=AgentMode.REDUCE_ONLY)
    # currently flat -> a BUY increases |net| -> reject
    with pytest.raises(CapError, match="reduce-only"):
        agent_cap_check(caps, make_order(side=Side.BUY), current_net_position=0)


def test_reduce_only_allows_reducing():
    caps = make_caps(mode=AgentMode.REDUCE_ONLY)
    # long 2.0, SELL 1.0 -> net drops to 1.0 (strictly reduces) -> allowed
    agent_cap_check(
        caps,
        make_order(side=Side.SELL, size=10 ** 18),
        current_net_position=2 * 10 ** 18,
    )


# ---------------------------------------------------------------------------
# Cap pre-check -- boundaries
# ---------------------------------------------------------------------------
def test_caps_unset_rejects():
    caps = make_caps(caps_set=0)
    with pytest.raises(CapError, match="caps unset"):
        agent_cap_check(caps, make_order())


def test_order_type_not_allowed():
    # only LIMIT (bit 0) allowed; submit a MARKET (bit 1)
    caps = make_caps(allowed_order_types=1 << OrderType.LIMIT)
    with pytest.raises(CapError, match="order type not allowed"):
        agent_cap_check(caps, make_order(order_type=OrderType.MARKET))


def test_leverage_over_cap():
    caps = make_caps(max_leverage=20000)  # 2x cap
    with pytest.raises(CapError, match="leverage over cap"):
        agent_cap_check(caps, make_order(leverage_bps=30000))  # 3x


def test_leverage_zero_rejected():
    caps = make_caps()
    with pytest.raises(CapError, match="leverage over cap"):
        agent_cap_check(caps, make_order(leverage_bps=0))


def test_input_over_cap():
    # margin for 1.0 @ 2500 @ 2x = 1250 USDC (6-dec). Cap it below that.
    caps = make_caps(max_input_per_trade=1000 * 10 ** 6)
    with pytest.raises(CapError, match="input over cap"):
        agent_cap_check(caps, make_order())


def test_input_at_cap_passes():
    caps = make_caps(max_input_per_trade=1250 * 10 ** 6)
    agent_cap_check(caps, make_order())  # exactly at cap -> ok


def test_position_over_cap():
    # buying 1.0 with a 0.5 total-position cap -> reject
    caps = make_caps(max_total_position=5 * 10 ** 17)
    with pytest.raises(CapError, match="position over cap"):
        agent_cap_check(caps, make_order(size=10 ** 18), current_net_position=0)


# ---------------------------------------------------------------------------
# Graceful reads -- predeploys not live -> None (mock eth_call/REST)
# ---------------------------------------------------------------------------
def test_read_caps_graceful_not_live():
    box = AgentBox(rpc_url="http://rpc.invalid:1")  # a name that never resolves (.invalid is reserved)

    # simulate an empty eth_call result deterministically
    box._eth_call = lambda to, data: "0x"  # type: ignore
    assert box.read_caps(VEC_OWNER) is None
    vr = box.read_caps_verbose(VEC_OWNER)
    assert vr.live is False
    assert "not live" in vr.note


def test_read_balance_graceful_not_live():
    box = AgentBox()
    box._eth_call = lambda to, data: "0x"  # type: ignore
    assert box.read_balance(VEC_OWNER) is None
    assert box.read_balance_verbose(VEC_OWNER).live is False


def test_read_caps_decodes_when_live():
    box = AgentBox()
    # 6 words: mode=2, caps_set=1, max_leverage=200000, order_types=0xff,
    #          max_input=1e12, max_total=1e30
    words = [2, 1, 200000, 0xFF, 10 ** 12, 10 ** 30]
    payload = "0x" + "".join(w.to_bytes(32, "big").hex() for w in words)
    box._eth_call = lambda to, data: payload  # type: ignore
    caps = box.read_caps(VEC_OWNER)
    assert caps is not None
    assert caps.mode == 2 and caps.caps_set == 1
    assert caps.max_leverage == 200000
    assert caps.max_total_position == 10 ** 30


def test_rest_reads_graceful():
    box = AgentBox()
    box._rest_get = lambda path: None  # type: ignore
    assert box.positions(VEC_OWNER) is None
    assert box.orders(VEC_OWNER) is None
    assert box.fills(1) is None


# ---------------------------------------------------------------------------
# Live end-to-end -- DEFERRED TO DEPLOY (predeploys + intake not live yet)
# ---------------------------------------------------------------------------
@pytest.mark.xfail(
    reason="live submit against a running node -- deferred to deploy "
           "(agent predeploys + order intake not live yet)",
    run=False,
)
def test_live_submit_end_to_end():
    # When the agent predeploys and /order/place intake are live:
    #   1. box.read_caps(owner) returns real caps
    #   2. op.place_order(...) returns an accepted order id
    #   3. box.orders(owner) reflects the new order
    raise AssertionError("intentionally deferred to deploy")
