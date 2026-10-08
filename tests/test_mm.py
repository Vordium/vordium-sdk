"""Market-maker signing, bodies and answers.

Every digest is checked against eth_account's own EIP-712 encoder over the same domain, so the hand-built struct hashes
cannot drift from the standard. No network call: the domain separator is built from a fixed chain id and genesis."""
import random

import pytest
from eth_account import Account
from eth_account.messages import encode_typed_data
from eth_utils import keccak

from vordium.node_domain import NodeIdentity
from vordium import caps, mm
from vordium import network as net

GENESIS = "3263e89e7cd024467a58c352a4d4446f30020093ed979d6e318196c7007d2482"
CHAIN_ID = 101102
VC = "0x0000000000000000000000000000000000001002"
SEP = caps.vordcore_domain_separator(CHAIN_ID, VC, GENESIS)
_IDENT = lambda: NodeIdentity(CHAIN_ID, GENESIS)
_NET = net.Network(chain_id=CHAIN_ID, chain_id_hex=hex(CHAIN_ID), chain_name="Vordium Testnet", rpc_url="offline", ws_url=None,
                   explorer_url=None, bridge_address=None, bridge_chain=None, bridge_chain_id=None, native_symbol="VORD",
                   native_decimals=18, verifying_contract=VC, source="test", genesis_sha256=GENESIS)
KEY = "0x" + keccak(b"vordium-sdk-test-mm").hex()
OWNER = Account.from_key(KEY).address

DOMAIN = {"name": "VordCore", "version": "1", "chainId": CHAIN_ID, "verifyingContract": VC,
          "salt": "0x" + keccak(b"VORDIUM_VORDCORE\x01" + bytes.fromhex(GENESIS)).hex()}
DOMAIN_TYPE = [{"name": "name", "type": "string"}, {"name": "version", "type": "string"},
               {"name": "chainId", "type": "uint256"}, {"name": "verifyingContract", "type": "address"},
               {"name": "salt", "type": "bytes32"}]
ACTION_FIELDS = [("kind", "uint8"), ("pairId", "uint32"), ("side", "uint8"), ("size", "uint128"), ("price", "uint64"),
                 ("leverageBps", "uint32"), ("orderType", "uint8"), ("reduceOnly", "bool"), ("postOnly", "bool"),
                 ("clientNonce", "uint64"), ("orderId", "uint64")]


def _t(fields):
    return [{"name": n, "type": ty} for n, ty in fields]


def _ref(primary, types, message):
    t = {"EIP712Domain": DOMAIN_TYPE, **types}
    e = encode_typed_data(full_message={"types": t, "primaryType": primary, "domain": DOMAIN, "message": message})
    return keccak(b"\x19\x01" + e.header + e.body)


def _action_msg(a):
    return {"kind": a.kind, "pairId": a.pair_id, "side": a.side, "size": a.size_18dec, "price": a.price_8dec,
            "leverageBps": a.leverage_bps, "orderType": a.order_type, "reduceOnly": a.reduce_only,
            "postOnly": a.post_only, "clientNonce": a.client_nonce, "orderId": a.order_id}


def test_domain_separator_is_the_published_one():
    assert "0x" + SEP.hex() == "0x3cdf5b80374a5d66614de56de656e69799c3075bb8b49d5212f4656bbe8ddbdc"


def test_type_hashes_name_the_signed_types():
    assert mm.BATCH_TYPEHASH == keccak((
        "BatchOrders(address owner,uint64 nonce,BatchAction[] actions)BatchAction(uint8 kind,uint32 pairId,uint8 side,"
        "uint128 size,uint64 price,uint32 leverageBps,uint8 orderType,bool reduceOnly,bool postOnly,uint64 clientNonce,"
        "uint64 orderId)").encode())
    assert mm.CANCEL_ALL_TYPEHASH == keccak(b"CancelAllOrders(address owner,uint32 pairId,uint64 nonce)")
    assert mm.MODIFY_V2_TYPEHASH == keccak(
        b"ModifyOrderV2(address owner,uint64 orderId,uint64 newPrice,uint128 newSize,uint64 clientNonce)")
    assert mm.SET_MMP_TYPEHASH == keccak(
        b"SetMmp(address owner,uint64 windowMs,uint32 maxFills,uint128 maxFilledNotional6dec,uint128 maxNetSize18dec,"
        b"uint64 freezeMs,uint64 nonce)")


def _random_actions(rng, n):
    out = []
    for _ in range(n):
        k = rng.choice(["place", "cancel", "nonce"])
        if k == "place":
            ot = rng.choice(["limit", "ioc", "fok", "market"])
            out.append(mm.place(rng.randint(1, 20), rng.choice(["buy", "sell"]), rng.randint(1, 2**100),
                                0 if ot == "market" else rng.randint(1, 2**60), rng.randint(1, 2**63),
                                order_type=ot, post_only=(ot == "limit" and rng.random() < .5),
                                reduce_only=rng.random() < .3, leverage_bps=rng.randint(10_000, 500_000)))
        elif k == "cancel":
            out.append(mm.cancel(rng.randint(1, 2**60)))
        else:
            out.append(mm.cancel_by_client_nonce(rng.randint(1, 2**63)))
    return out


def test_batch_digest_matches_eth_account():
    rng = random.Random(7)
    types = {"BatchOrders": _t([("owner", "address"), ("nonce", "uint64"), ("actions", "BatchAction[]")]),
             "BatchAction": _t(ACTION_FIELDS)}
    for _ in range(40):
        acts = _random_actions(rng, rng.randint(1, 50))
        nonce = rng.randint(1, 2**63)
        want = _ref("BatchOrders", types, {"owner": OWNER, "nonce": nonce, "actions": [_action_msg(a) for a in acts]})
        assert mm.digest(mm.batch_struct_hash(OWNER, nonce, acts), SEP) == want


def test_cancel_all_modify_and_mmp_digests_match_eth_account():
    rng = random.Random(11)
    for _ in range(25):
        pair, nonce = rng.randint(0, 2**32 - 1), rng.randint(1, 2**63)
        assert mm.digest(mm.cancel_all_struct_hash(OWNER, pair, nonce), SEP) == _ref(
            "CancelAllOrders", {"CancelAllOrders": _t([("owner", "address"), ("pairId", "uint32"), ("nonce", "uint64")])},
            {"owner": OWNER, "pairId": pair, "nonce": nonce})
        oid, p, s, cn = rng.randint(1, 2**63), rng.randint(1, 2**63), rng.randint(1, 2**127), rng.randint(1, 2**63)
        assert mm.digest(mm.modify_v2_struct_hash(OWNER, oid, p, s, cn), SEP) == _ref(
            "ModifyOrderV2", {"ModifyOrderV2": _t([("owner", "address"), ("orderId", "uint64"), ("newPrice", "uint64"),
                                                   ("newSize", "uint128"), ("clientNonce", "uint64")])},
            {"owner": OWNER, "orderId": oid, "newPrice": p, "newSize": s, "clientNonce": cn})
        m = mm.Mmp(rng.randint(1, mm.MMP_MAX_MS), rng.randint(0, 2**32 - 1), rng.randint(0, 2**127),
                   rng.randint(0, 2**127), rng.randint(0, mm.MMP_MAX_MS))
        assert mm.digest(mm.set_mmp_struct_hash(OWNER, m, nonce), SEP) == _ref(
            "SetMmp", {"SetMmp": _t([("owner", "address"), ("windowMs", "uint64"), ("maxFills", "uint32"),
                                     ("maxFilledNotional6dec", "uint128"), ("maxNetSize18dec", "uint128"),
                                     ("freezeMs", "uint64"), ("nonce", "uint64")])},
            {"owner": OWNER, "windowMs": m.window_ms, "maxFills": m.max_fills,
             "maxFilledNotional6dec": m.max_filled_notional_6dec, "maxNetSize18dec": m.max_net_size_18dec,
             "freezeMs": m.freeze_ms, "nonce": nonce})


def test_every_kind_signs_zero_in_the_fields_it_does_not_use():
    c = mm.cancel(1447)
    assert (c.kind, c.pair_id, c.side, c.size_18dec, c.price_8dec, c.leverage_bps, c.order_type,
            c.reduce_only, c.post_only, c.client_nonce, c.order_id) == (1, 0, 0, 0, 0, 0, 0, False, False, 0, 1447)
    n = mm.cancel_by_client_nonce(99)
    assert (n.kind, n.client_nonce, n.order_id, n.pair_id) == (2, 99, 0, 0)
    p = mm.place(1, "sell", 5, 7, 3, order_type="ioc")
    assert (p.kind, p.side, p.order_type, p.order_id) == (0, 1, 4, 0)
    assert mm.place(1, "buy", 5, 7, 3, order_type="fok").order_type == 5
    assert mm.place(1, "buy", 5, 0, 3, order_type="market").order_type == 0


def test_bodies_have_the_published_shape():
    acts = [mm.place(1, "buy", 3900000000000000, 271000000000, 1791203264249, post_only=True, leverage_bps=30000),
            mm.cancel(1447), mm.cancel_by_client_nonce(1791203264100)]
    b = mm.batch_body(OWNER, 5, acts, "0xsig")
    assert b == {"owner": OWNER, "nonce": 5, "signature": "0xsig", "actions": [
        {"kind": "place", "pairId": 1, "side": "buy", "size_18dec": "3900000000000000", "price_8dec": 271000000000,
         "leverageBps": 30000, "orderType": "limit", "postOnly": True, "reduceOnly": False, "clientNonce": 1791203264249},
        {"kind": "cancel", "orderId": 1447}, {"kind": "cancelByClientNonce", "clientNonce": 1791203264100}]}
    assert mm.cancel_all_body(OWNER, 0, 9, "0xs") == {"owner": OWNER, "pairId": 0, "nonce": 9, "signature": "0xs"}
    assert mm.modify_body(OWNER, 1447, 270900000000, 3900000000000000, 11, "0xs") == {
        "owner": OWNER, "orderId": 1447, "newPrice8dec": 270900000000, "newSize18dec": "3900000000000000",
        "clientNonce": 11, "signature": "0xs"}
    assert mm.mmp_body(OWNER, mm.Mmp(60000, 20, 0, 0, 15000), 7, "0xs") == {
        "owner": OWNER, "windowMs": 60000, "maxFills": 20, "maxFilledNotional6dec": "0", "maxNetSize18dec": "0",
        "freezeMs": 15000, "nonce": 7, "signature": "0xs"}


@pytest.mark.parametrize("call", [
    lambda: mm.place(1, "long", 1, 1, 1),
    lambda: mm.place(1, "buy", 1, 1, 1, order_type="stop"),
    lambda: mm.place(1, "buy", 1, 1, 1, order_type="ioc", post_only=True),
    lambda: mm.place(1, "buy", 0, 1, 1),
    lambda: mm.place(1, "buy", 1, 5, 1, order_type="market"),
    lambda: mm.place(1, "buy", 1, 0, 1, order_type="limit"),
    lambda: mm.place(1, "buy", 2**128, 1, 1),
    lambda: mm.place(1, "buy", 1, 2**64, 1),
    lambda: mm.place(2**32, "buy", 1, 1, 1),
    lambda: mm.place(1, "buy", 1, 1, 1, post_only=1),
    lambda: mm.cancel(-1),
    lambda: mm.Mmp(window_ms=mm.MMP_MAX_MS + 1).checked(),
    lambda: mm.Mmp(freeze_ms=mm.MMP_MAX_MS + 1).checked(),
    lambda: mm.Mmp(max_fills=3).checked(),
])
def test_refused_before_signing(call):
    with pytest.raises(mm.MMError):
        call()


def test_mmp_all_zero_switches_it_off():
    assert mm.Mmp().checked() == mm.Mmp(0, 0, 0, 0, 0)


def test_answers_are_read_by_their_published_shape():
    ok = mm.read_answer(202, {"status": "submitted", "intaken": True, "actions": [
        {"index": 0, "status": "accepted"},
        {"index": 1, "status": "will_be_refused", "code": "rate_limited", "error": "allowance used"},
        {"index": 2, "status": "will_be_refused", "code": "min_notional", "error": "below the 10 USDC minimum"}]})
    assert ok.ok and [a.accepted for a in ok.actions] == [True, False, False]
    assert ok.actions[1].refusal.code == "rate_limited" and "rate limit" in ok.actions[1].refusal.message
    assert ok.actions[2].refusal.code == "min_notional"
    r429 = mm.read_answer(429, {"error": "busy"}, "1")
    assert not r429.ok and r429.refusal.code == "mempool_full" and r429.refusal.retry_after == 1.0
    assert mm.read_answer(403, {"code": "bad_signature", "error": "x"}).refusal.code == "bad_signature"
    assert mm.read_answer(409, {"code": "not_active"}).refusal.code == "not_active"
    assert mm.read_answer(400, {"code": "batch_size"}).refusal.code == "batch_size"
    # anything that is not the published success is never a success
    for code, body in ((200, {"status": "submitted"}), (202, {}), (202, {"status": "applied"}), (500, None), (None, None)):
        assert not mm.read_answer(code, body).ok


@pytest.mark.parametrize("code,error", [
    ("price_band", "x"),
    ("price", "price too far from mark (band 5%)"),
    (None, "Price too far from mark"),
    ("invalid_body", "the price is too far from the mark price"),
])
def test_price_band_refusal_is_named_plainly(code, error):
    r = mm.refusal(code, error)
    assert r.code == "price_band" and r.message == "The price is too far from the mark price."


def test_price_band_on_a_batch_action_and_on_the_whole_request():
    a = mm.read_answer(202, {"status": "submitted", "actions": [
        {"index": 0, "status": "will_be_refused", "code": "price", "error": "price too far from mark"}]})
    assert a.actions[0].refusal.code == "price_band"
    w = mm.read_answer(400, {"code": "invalid_body", "error": "price too far from mark"})
    assert w.refusal.code == "price_band"


def test_other_price_refusal_is_not_called_a_band():
    assert mm.refusal("price", "not on the tick size").code == "price"


def test_nonce_clock_rises_even_when_the_clock_stands_still():
    clk = mm.NonceClock(lambda: 1_791_000_000.0)
    a, b, c = clk(), clk(), clk()
    assert a == 1_791_000_000_000 and b == a + 1 and c == a + 2


class _Recorder:
    def __init__(self, answer=(202, {"status": "submitted", "intaken": True, "actions": []}, None)):
        self.sent, self.answer = [], answer

    def __call__(self, path, body):
        self.sent.append((path, body))
        return self.answer


def _recover(struct_hash, sig):
    return Account._recover_hash(mm.digest(struct_hash, SEP), signature=bytes.fromhex(sig[2:]))


def test_client_signs_what_it_sends_and_signatures_are_65_bytes():
    rec = _Recorder()
    c = mm.MarketMaker("https://example.invalid/chain", KEY, OWNER, domain_separator=SEP, identity=_IDENT, network=_NET, post=rec,
                       nonce=mm.NonceClock(lambda: 1_791_000_000.0))
    acts = [mm.place(1, "buy", 10**16, 10**11, 5, post_only=True), mm.cancel(3)]
    r = c.batch(acts)
    path, body = rec.sent[-1]
    assert path == "/order/batch-signed" and r.ok and r.nonce == body["nonce"]
    assert len(bytes.fromhex(body["signature"][2:])) == 65
    assert _recover(mm.batch_struct_hash(OWNER, body["nonce"], acts), body["signature"]) == OWNER
    c.cancel_all(4)
    path, body = rec.sent[-1]
    assert path == "/order/cancel-all" and _recover(mm.cancel_all_struct_hash(OWNER, 4, body["nonce"]),
                                                     body["signature"]) == OWNER
    c.modify(9, 10**11, 10**16)
    path, body = rec.sent[-1]
    assert path == "/order/modify" and _recover(
        mm.modify_v2_struct_hash(OWNER, 9, 10**11, 10**16, body["clientNonce"]), body["signature"]) == OWNER
    c.set_mmp(mm.Mmp(60000, 20, 0, 0, 15000), 7)
    path, body = rec.sent[-1]
    assert path == "/account/mmp" and _recover(mm.set_mmp_struct_hash(OWNER, mm.Mmp(60000, 20, 0, 0, 15000), 7),
                                               body["signature"]) == OWNER


def test_client_refuses_an_empty_or_oversized_batch_without_sending():
    rec = _Recorder()
    c = mm.MarketMaker("https://example.invalid", KEY, OWNER, domain_separator=SEP, identity=_IDENT, network=_NET, post=rec)
    with pytest.raises(mm.MMError):
        c.batch([])
    with pytest.raises(mm.MMError):
        c.batch([mm.cancel(i + 1) for i in range(51)])
    with pytest.raises(mm.MMError):
        c.batch([mm.cancel(i + 1) for i in range(11)], max_actions=10)
    with pytest.raises(mm.MMError):
        c.modify(1, 0, 5)
    assert rec.sent == []


def test_client_reports_a_refusal_with_its_retry_time():
    c = mm.MarketMaker("https://example.invalid", KEY, OWNER, domain_separator=SEP, identity=_IDENT, network=_NET,
                       post=_Recorder((429, {"code": "mempool_full", "error": "full"}, "1")))
    r = c.cancel_all()
    assert not r.ok and r.refusal.code == "mempool_full" and r.refusal.retry_after == 1.0


def test_next_mmp_nonce():
    assert mm.next_mmp_nonce({"mmp": None}) == 1
    assert mm.next_mmp_nonce({"mmp": {"next_nonce": 3}}) == 3
    with pytest.raises(mm.MMError):
        mm.next_mmp_nonce({"mmp": {"window_ms": 1}})


def test_pair_specs_tick_and_lot():
    read = {"specs": {"pairs": [
        {"pair": {"pair_id": 1, "symbol": "ETHUSDT"}, "tick_8dec": "0", "lot_18dec": "0", "liquidation_fee_bps": 40,
         "maintenance_margin_bps": 200},
        {"pair": {"pair_id": 2, "symbol": "BTCUSDT"}, "tick_8dec": "100000", "lot_18dec": "1000000000000000"}]}}
    s = mm.pair_specs(read)
    assert s[1].liquidation_fee_bps == 40 and s[1].maintenance_margin_bps == 200 and s[2].liquidation_fee_bps is None
    assert mm.on_tick(123, s[1]) and mm.on_lot(7, s[1])
    assert mm.on_tick(200000, s[2]) and not mm.on_tick(150000, s[2])
    assert mm.on_lot(2 * 10**15, s[2]) and not mm.on_lot(10**15 + 1, s[2])
