"""Builder codes: type strings, typehashes and digests against the network's published vectors; local refusals before
signing; request bodies; the client's reads and writes against a stub network; referral level fields."""

import json
import pathlib

import pytest
from eth_account import Account
from eth_utils import keccak

from vordium import builder as b
from vordium import caps
from vordium.account_ops import Result

CAPS = {"perps": 1000, "spot": 5000}          # the caps the vectors' stats read carries
VEC = json.loads((pathlib.Path(__file__).parent / "vectors" / "builder-fees.json").read_text())
EV = VEC["eip712_vectors"]
SEP = bytes.fromhex(EV["domain_separator"][2:])
GENESIS_MAINNET = "2c1c0679fa6ab8358f1d3e8d294a8d1c73ac2e2caf9079f1216abedc3d9fdf4f"
GENESIS_TESTNET = "8b5d414c5cd5d18bc468b64f87ac8e2c2b5ff494c769d5e09dcf50ce75a59792"
KEY = "0x" + "01" * 32                      # throwaway test key, never funded
ADDR = Account.from_key(KEY).address
BUILDER = "0x2222222222222222222222222222222222222222"
PLACE_ORDER_V2 = ("PlaceOrderV2(address owner,uint32 pairId,uint8 side,uint128 size,uint64 price,uint32 leverageBps,"
                  "uint8 orderType,bool reduceOnly,bool postOnly,uint64 triggerPrice8dec,uint8 triggerDir,"
                  "uint8 timeInForce,uint64 expiresAt,uint64 clientNonce,uint64 validUntil,uint64 worstPrice8dec,"
                  "string source)")


# -- type strings and typehashes ----------------------------------------------------------------------------------------
def test_type_strings_equal_the_published_ones():
    assert b.APPROVE_BUILDER_FEE == EV["approve_builder_fee"]["type"]
    assert b.CLAIM_BUILDER_FEES == EV["claim_builder_fees"]["type"]


def test_place_order_v3_is_the_17_v2_fields_then_builder_and_fee():
    pub = EV["place_order_v3"]["type"]
    assert pub.startswith("PlaceOrderV3(") and pub.endswith(",address builder,uint32 builderFeeCbps)")
    v2 = PLACE_ORDER_V2[len("PlaceOrderV2("):-1]
    assert len(v2.split(",")) == 17
    assert b.PLACE_ORDER_V3 == "PlaceOrderV3(" + v2 + ",address builder,uint32 builderFeeCbps)"


@pytest.mark.parametrize("name", ["ApproveBuilderFee", "ClaimBuilderFees", "PlaceOrderV3"])
def test_typehash_pins(name):
    assert "0x" + keccak(b.TYPES[name].encode()).hex() == b.TYPEHASHES[name]


def test_vector_domain_is_the_mainnet_vordcore_domain():
    assert caps.vordcore_domain_separator(101101, "0x0000000000000000000000000000000000001002", GENESIS_MAINNET) == SEP


# -- digests against the published vectors ------------------------------------------------------------------------------
def test_approve_digest_equals_the_published_vector():
    a = EV["approve_builder_fee"]["args"]
    d = b.digest("ApproveBuilderFee", a, SEP)
    assert "0x" + d.hex() == EV["approve_builder_fee"]["digest"]


def test_claim_digest_equals_the_published_vector():
    a = EV["claim_builder_fees"]["args"]
    d = b.digest("ClaimBuilderFees", a, SEP)
    assert "0x" + d.hex() == EV["claim_builder_fees"]["digest"]


def test_digest_matches_eth_account_typed_data():
    """The hand-built digest equals the general EIP-712 encoder's for the same domain and message."""
    from eth_account.messages import encode_typed_data
    dom = {"name": "VordCore", "version": "1", "chainId": 101101,
           "verifyingContract": "0x0000000000000000000000000000000000001002",
           "salt": caps._vordcore_salt(GENESIS_MAINNET)}
    msg = {"owner": ADDR, "pairId": 1, "side": 0, "size": 10 ** 16, "price": 170000000000, "leverageBps": 10000,
           "orderType": 1, "reduceOnly": False, "postOnly": False, "triggerPrice8dec": 0, "triggerDir": 0,
           "timeInForce": 0, "expiresAt": 0, "clientNonce": 1794362062000, "validUntil": 1794362362,
           "worstPrice8dec": 0, "source": "sdk", "builder": BUILDER, "builderFeeCbps": 500}
    types = {"PlaceOrderV3": [{"name": n, "type": t} for t, n in b.FIELDS["PlaceOrderV3"]]}
    sm = encode_typed_data(domain_data=dom, message_types=types, message_data=msg)
    full = keccak(b"\x19\x01" + sm.header + sm.body)
    assert full == b.digest("PlaceOrderV3", msg, SEP)
    assert sm.header == SEP


def test_testnet_domain_differs_from_the_vector_domain():
    t = caps.vordcore_domain_separator(101102, "0x0000000000000000000000000000000000001002", GENESIS_TESTNET)
    assert t != SEP
    a = EV["approve_builder_fee"]["args"]
    assert b.digest("ApproveBuilderFee", a, t).hex() != EV["approve_builder_fee"]["digest"][2:]


# -- signing and bodies -------------------------------------------------------------------------------------------------
def _recover(d: bytes, sig: str) -> str:
    from eth_keys import keys
    raw = bytes.fromhex(sig[2:])
    assert len(raw) == 65 and raw[64] in (27, 28)
    return keys.Signature(raw[:64] + bytes([raw[64] - 27])).recover_public_key_from_msg_hash(d).to_checksum_address()


def test_approve_signs_65_bytes_and_builds_the_body():
    s = b.approve_builder_fee(KEY, ADDR, BUILDER, 500, 1, 1794362362, SEP)
    assert _recover(s.digest, s.signature) == ADDR
    assert s.route == "/builder/approve"
    assert s.body == {"user": ADDR, "builder": BUILDER, "maxFeeCbps": 500, "nonce": 1, "validUntil": 1794362362,
                      "signature": s.signature}
    # deterministic (RFC 6979): the same inputs give the same bytes
    assert b.approve_builder_fee(KEY, ADDR, BUILDER, 500, 1, 1794362362, SEP).signature == s.signature


def test_revoke_is_an_approval_of_zero():
    s = b.approve_builder_fee(KEY, ADDR, BUILDER, 0, 2, 1794362362, SEP)
    assert s.message["maxFeeCbps"] == 0 and s.body["maxFeeCbps"] == 0


def test_approve_refuses_another_key_and_self():
    with pytest.raises(b.BuilderError) as e:
        b.approve_builder_fee("0x" + "02" * 32, ADDR, BUILDER, 500, 1, 1794362362, SEP)
    assert e.value.code == "builder_approval_owner_only"
    with pytest.raises(b.BuilderError) as e:
        b.approve_builder_fee(KEY, ADDR, ADDR, 500, 1, 1794362362, SEP)
    assert e.value.code == "builder_self"


def test_claim_signs_with_the_builder_key_only():
    s = b.claim_builder_fees(KEY, ADDR, 3, 1794362362, SEP)
    assert _recover(s.digest, s.signature) == ADDR
    assert s.body == {"builder": ADDR, "nonce": 3, "validUntil": 1794362362, "signature": s.signature}
    with pytest.raises(b.BuilderError):
        b.claim_builder_fees("0x" + "02" * 32, ADDR, 3, 1794362362, SEP)


def test_place_order_v3_body_limit():
    s = b.place_order_v3(KEY, ADDR, 1, 0, 10 ** 16, 170000000000, 10000, 1, 1794362062000, 1794362362, BUILDER, 500,
                         SEP)
    assert _recover(s.digest, s.signature) == ADDR
    assert s.route == "/order/place"
    assert s.body == {"owner": ADDR, "pairId": 1, "side": "buy", "size_18dec": "10000000000000000",
                      "orderType": "Limit", "leverageBps": 10000, "clientNonce": "1794362062000",
                      "validUntil": "1794362362", "worstPrice8dec": "0", "source": "sdk", "builder": BUILDER,
                      "builderFeeCbps": 500, "price_8dec": "170000000000", "signature": s.signature}


def test_place_order_v3_market_carries_no_price():
    s = b.place_order_v3(KEY, ADDR, 1, 1, 10 ** 16, 0, 10000, 0, 1794362062000, 1794362362, BUILDER, 500, SEP,
                         reduce_only=True)
    assert "price_8dec" not in s.body and s.body["orderType"] == "Market" and s.body["reduceOnly"] is True
    with pytest.raises(b.BuilderError):
        b.place_order_v3(KEY, ADDR, 1, 1, 10 ** 16, 100, 10000, 0, 1, 1794362362, BUILDER, 500, SEP)


def test_place_order_v3_market_with_a_worst_price_signs_it_as_price_and_worst():
    s = b.place_order_v3(KEY, ADDR, 1, 0, 10 ** 16, 0, 10000, 0, 1794362062000, 1794362362, BUILDER, 500, SEP,
                         worst_price_8dec=193130000000)
    assert s.message["price"] == s.message["worstPrice8dec"] == 193130000000
    assert s.body["price_8dec"] == s.body["worstPrice8dec"] == "193130000000"
    # a price equal to the worst price is the same order; any other price is refused
    same = b.place_order_v3(KEY, ADDR, 1, 0, 10 ** 16, 193130000000, 10000, 0, 1794362062000, 1794362362, BUILDER,
                            500, SEP, worst_price_8dec=193130000000)
    assert same.signature == s.signature
    with pytest.raises(b.BuilderError):
        b.place_order_v3(KEY, ADDR, 1, 0, 10 ** 16, 193120000000, 10000, 0, 1, 1794362362, BUILDER, 500, SEP,
                         worst_price_8dec=193130000000)
    with pytest.raises(b.BuilderError):
        b.place_order_v3(KEY, ADDR, 1, 0, 10 ** 16, 170000000000, 10000, 1, 1, 1794362362, BUILDER, 500, SEP,
                         worst_price_8dec=193130000000)


def test_place_order_v3_refuses_stops():
    with pytest.raises(b.BuilderError) as e:
        b.place_order_v3(KEY, ADDR, 1, 0, 10 ** 16, 100, 10000, 2, 1, 1794362362, BUILDER, 500, SEP)
    assert e.value.code == "builder_on_stop"


# -- local checks -------------------------------------------------------------------------------------------------------
def test_fee_caps():
    assert b.check_fee(1000, "perps", CAPS) == 1000
    assert b.check_fee(5000, "spot", CAPS) == 5000
    with pytest.raises(b.BuilderError) as e:
        b.check_fee(1001, "perps", CAPS)
    assert e.value.code == "builder_fee_above_cap" and "1000 cbps" in str(e.value)
    with pytest.raises(b.BuilderError) as e:
        b.check_fee(0, "perps", CAPS)
    assert e.value.code == "builder_fee_zero"
    with pytest.raises(b.BuilderError):
        b.check_fee(-1, "perps", CAPS)
    with pytest.raises(b.BuilderError):
        b.check_fee(True, "perps", CAPS)
    assert b.check_fee(800, "perps", {"perps": 800, "spot": 5000}) == 800
    with pytest.raises(b.BuilderError):
        b.check_fee(801, "perps", {"perps": 800, "spot": 5000})


def test_max_fee_is_held_to_the_highest_cap():
    assert b.check_max_fee(5000, CAPS) == 5000
    with pytest.raises(b.BuilderError):
        b.check_max_fee(5001, CAPS)
    with pytest.raises(b.BuilderError) as e:
        b.check_max_fee(0, CAPS)
    assert e.value.code == "builder_fee_zero"


def test_caps_from_a_read():
    assert b.caps_from(VEC["builder_stats"]) == CAPS
    assert b.caps_from({"caps_cbps": {"perps": 700, "spot": 900}}) == {"perps": 700, "spot": 900}
    # a read without both caps cannot be checked against: refused, never a typed-in figure
    for bad in (None, {}, {"caps_cbps": {"perps": 700}}, {"caps_cbps": {"perps": "700", "spot": 1}},
                {"caps_cbps": {"perps": True, "spot": 1}}):
        with pytest.raises(b.BuilderError) as e:
            b.caps_from(bad)
        assert e.value.code == "unreadable"


def test_fee_kind_must_be_perps_or_spot():
    for kind in ("toString", "__class__", "keys", ""):
        with pytest.raises(b.BuilderError) as e:
            b.check_fee(1, kind, CAPS)
        assert e.value.code == "invalid_body"


def test_no_fixed_chain_figures_in_the_module():
    """Caps, the approval maximum and the builder minimum are reads; the module keeps no copy of them."""
    for name in ("DEFAULT_CAPS_CBPS", "MAX_APPROVALS", "MIN_BUILDER_ACCOUNT_VALUE_6DEC", "CODES"):
        assert not hasattr(b, name), name
    src = pathlib.Path(b.__file__).read_text()
    for text in ("100 USDC", "today", "switched on", "yet,"):
        assert text not in src, text


def test_describe_and_fee_math():
    assert b.describe_cbps(1000) == "10 bps (0.1%)"
    assert b.describe_cbps(500) == "5 bps (0.05%)"
    # the fee charged is the network's: read it from the fill's builder key, never computed here
    assert not hasattr(b, "fee_6dec")


def test_deadline_bounds():
    assert b.deadline(None, 1000) == 1120
    assert b.deadline(1300, 1000) == 1300
    with pytest.raises(b.BuilderError) as e:
        b.deadline(1301, 1000)
    assert e.value.code == "approval_too_far"
    with pytest.raises(b.BuilderError) as e:
        b.deadline(1000, 1000)
    assert e.value.code == "approval_expired"


def test_require_active():
    b.require_active({"active": True})
    for r in ({"active": False}, {}, None, {"active": "true"}):
        with pytest.raises(b.BuilderNotActive) as e:
            b.require_active(r)
        assert e.value.code == "builder_not_active" and "nothing was signed" in str(e.value)


def _approvals(rows, active=True, count=None):
    return {"user": ADDR.lower(), "approvals": rows, "count": len(rows) if count is None else count, "max": 10,
            "nonce": 4, "active": active, "source": "committed_state", "head_height": 1}


def test_order_checks():
    st = dict(VEC["builder_stats"])
    ok = _approvals([{"builder": BUILDER.lower(), "max_fee_cbps": 500}])
    b.check_order_builder(ADDR, BUILDER, 500, ok, st)
    cases = [
        (ADDR, ADDR, 500, ok, st, "builder_self"),
        (ADDR, BUILDER, 500, _approvals([]), st, "builder_not_approved"),
        (ADDR, BUILDER, 501, ok, st, "builder_fee_above_approved"),
        (ADDR, BUILDER, 500, ok, {**st, "account_value_ok": False}, "builder_too_small"),
        (ADDR, BUILDER, 500, ok, {**{k: v for k, v in st.items() if k != "min_account_value_6dec"},
                                  "account_value_ok": False}, "builder_too_small"),
        (ADDR, BUILDER, 500, _approvals([], active=False), st, "builder_not_active"),
        (ADDR, BUILDER, 500, ok, {**st, "active": False}, "builder_not_active"),
    ]
    for owner, bd, fee, ap, s, code in cases:
        with pytest.raises(b.BuilderError) as e:
            b.check_order_builder(owner, bd, fee, ap, s)
        assert e.value.code == code


def test_builder_too_small_names_the_read_minimum_or_none():
    ok = _approvals([{"builder": BUILDER.lower(), "max_fee_cbps": 500}])
    st = {**VEC["builder_stats"], "account_value_ok": False}
    with pytest.raises(b.BuilderError) as e:
        b.check_order_builder(ADDR, BUILDER, 500, ok, st)
    assert "the 100 USDC minimum" in str(e.value)                       # the read's min_account_value_6dec
    with pytest.raises(b.BuilderError) as e:
        b.check_order_builder(ADDR, BUILDER, 500, ok, {**st, "min_account_value_6dec": "1500000"})
    assert "the 1.5 USDC minimum" in str(e.value)
    no_min = {k: v for k, v in st.items() if k != "min_account_value_6dec"}
    with pytest.raises(b.BuilderError) as e:
        b.check_order_builder(ADDR, BUILDER, 500, ok, no_min)
    assert "below the network's minimum account value" in str(e.value)
    assert not any(ch.isdigit() for ch in str(e.value))


def test_not_active_message():
    assert str(b.BuilderNotActive()) == "Builder fees are not active on this network, so nothing was signed."


def test_parse_builder():
    assert b.parse_builder({"address": BUILDER.lower(), "fee_cbps": 500}) == (BUILDER, 500)
    assert b.parse_builder({"address": BUILDER, "fee": "250"}) == (BUILDER, 250)
    for bad in (None, {"address": "0x12"}, {"address": BUILDER}, "x"):
        with pytest.raises(b.BuilderError):
            b.parse_builder(bad)


def test_approval_of():
    assert b.approval_of(VEC["builder_approvals"], BUILDER) == 500
    assert b.approval_of(VEC["builder_approvals"], ADDR) is None
    assert b.approval_of(None, BUILDER) is None


def test_fixture_identity_fees_equal_unclaimed_plus_claimed():
    s = VEC["builder_stats"]
    assert int(s["fees_6dec"]) == int(s["unclaimed_6dec"]) + int(s["claimed_6dec"])


# -- referral levels ----------------------------------------------------------------------------------------------------
def test_referral_level_reads_the_added_fields():
    lv = b.referral_level({"address": ADDR, "tier": "NONE", **VEC["referral_stats_added_fields"]})
    assert lv.level == "L1" and lv.share_bps == 1000 and lv.discount_bps == 400
    assert lv.l2_progress["target_volume_6dec"] == "5000000000000" and lv.l2_progress["target_active"] == 10
    assert lv.meets_min is True and lv.next_check_ms == 1795737600000
    assert lv.limits["referee_cut_cap_6dec"] == "1000000000000000"
    assert set(b.LEVEL_FIELDS) <= set(VEC["referral_stats_added_fields"])


def test_referral_level_absent_below_the_rule():
    assert b.referral_level({"address": ADDR, "tier": "SIGNAL"}) is None
    assert b.referral_level(None) is None


# -- the client against a stub network ----------------------------------------------------------------------------------
class Stub(b.BuilderOps):
    """BuilderOps with the network replaced: reads come from ``state``, posts are recorded and change ``state``."""

    def __init__(self, key, state, answer=(202, {"status": "submitted"})):
        self.key = key
        self.owner = Account.from_key(key).address
        self.state = state
        self.answer = answer
        self.posts = []
        self._chain = None

    def separator(self, domain_class):
        assert domain_class == "VordCore"
        return SEP

    def _get(self, path):
        if path.startswith("/builder/approvals/"):
            return self.state["approvals"]
        if path.startswith("/builder/stats/"):
            return self.state["stats"]
        if path.startswith("/referral/stats/"):
            return self.state.get("referral")
        if path == "/referral/tiers":
            return self.state.get("tiers")
        raise AssertionError(path)

    def _post(self, path, body, dedup=True):
        body = json.loads(body)
        self.posts.append((path, body))
        code, ans = self.answer
        if 200 <= code < 300 and path == "/builder/approve":
            ap = self.state["approvals"]
            rows = [r for r in ap["approvals"] if r["builder"] != body["builder"].lower()]
            if body["maxFeeCbps"]:
                rows.append({"builder": body["builder"].lower(), "max_fee_cbps": body["maxFeeCbps"]})
            self.state["approvals"] = {**ap, "approvals": rows, "count": len(rows), "nonce": body["nonce"]}
        if 200 <= code < 300 and path == "/builder/claim":
            st = self.state["stats"]
            self.state["stats"] = {**st, "claim_nonce": body["nonce"], "claimed_6dec": st["unclaimed_6dec"],
                                   "unclaimed_6dec": "0"}
        return code, ans

    @staticmethod
    def _wait(fn, secs, step=1.0):
        return fn()


def _state(active=True):
    return {"approvals": _approvals([], active=active), "stats": {**VEC["builder_stats"], "active": active}}


def test_client_approve_then_revoke():
    s = Stub(KEY, _state())
    r = s.approve_builder_fee(BUILDER, 500)
    assert isinstance(r, Result) and r.applied is True
    path, body = s.posts[-1]
    assert path == "/builder/approve" and body["nonce"] == 5 and body["maxFeeCbps"] == 500
    assert b.approval_of(s.approvals(), BUILDER) == 500
    r = s.revoke_builder_fee(BUILDER)
    assert r.applied is True and s.posts[-1][1]["maxFeeCbps"] == 0 and s.posts[-1][1]["nonce"] == 6
    assert s.approvals()["count"] == 0
    r = s.revoke_builder_fee(BUILDER)          # nothing left to revoke: nothing is signed
    assert r.applied is True and len(s.posts) == 2


def test_client_refuses_before_signing():
    s = Stub(KEY, _state(active=False))
    with pytest.raises(b.BuilderNotActive):
        s.approve_builder_fee(BUILDER, 500)
    s = Stub(KEY, _state())
    with pytest.raises(b.BuilderError) as e:
        s.approve_builder_fee(BUILDER, 5001)
    assert e.value.code == "builder_fee_above_cap"
    with pytest.raises(b.BuilderError) as e:
        s.approve_builder_fee(ADDR, 500)
    assert e.value.code == "builder_self"
    full = _state()
    full["approvals"] = _approvals([{"builder": "0x%040x" % i, "max_fee_cbps": 10} for i in range(1, 11)])
    s = Stub(KEY, full)
    with pytest.raises(b.BuilderError) as e:
        s.approve_builder_fee(BUILDER, 500)
    assert e.value.code == "builder_approvals_full"
    for missing in ("max", "count"):
        st = _state()
        st["approvals"] = {k: v for k, v in st["approvals"].items() if k != missing}
        s2 = Stub(KEY, st)
        with pytest.raises(b.BuilderError) as e:
            s2.approve_builder_fee(BUILDER, 500)
        assert e.value.code == "unreadable" and s2.posts == []
    st = _state()
    st["stats"] = {k: v for k, v in st["stats"].items() if k != "caps_cbps"}
    s3 = Stub(KEY, st)
    with pytest.raises(b.BuilderError) as e:
        s3.approve_builder_fee(BUILDER, 500)
    assert e.value.code == "unreadable" and s3.posts == []
    assert s.posts == []


def test_client_refused_answer_is_not_applied():
    s = Stub(KEY, _state(), answer=(400, {"code": "builder_fee_above_cap", "meaning": "the builder fee is above the "
                                                                                      "market's cap"}))
    r = s.approve_builder_fee(BUILDER, 500)
    assert r.applied is False and r.answer["code"] == "builder_fee_above_cap"


def test_client_claim():
    st = _state()
    st["stats"] = {**st["stats"], "unclaimed_6dec": "50000000", "claim_nonce": 2}
    s = Stub(KEY, st)
    r = s.claim_builder_fees()
    assert r.applied is True
    path, body = s.posts[-1]
    assert path == "/builder/claim" and body["nonce"] == 3 and body["builder"] == ADDR
    with pytest.raises(b.BuilderError) as e:
        s.claim_builder_fees()                 # nothing left
    assert e.value.code == "builder_nothing_to_claim"


def test_client_referral_reads():
    st = _state()
    st["referral"] = {"address": ADDR, **VEC["referral_stats_added_fields"]}
    st["tiers"] = VEC["referral_tiers"]
    s = Stub(KEY, st)
    assert s.referral_level().level == "L1"
    assert [x["level"] for x in s.referral_tiers()["levels"]] == ["L1", "L2", "PARTNER"]


# -- orders that name a builder (Vordex.place_order) --------------------------------------------------------------------
class _Resp:
    def __init__(self, code, body):
        self.status_code, self._b, self.content, self.headers = code, body, b"x", {}

    def json(self):
        return self._b


def _vordex(monkeypatch, approvals, stats, post_answer=(202, {"status": "submitted"})):
    from vordium import dex, mm, units
    from vordium.node_domain import NodeDomain

    v = dex.Vordex.__new__(dex.Vordex)
    v.rpc_url, v.timeout, v._chain = "https://node.test", 5, None
    spec = mm.PairSpec(pair_id=1, symbol="ETHUSDT", tick_8dec=10_000_000, lot_18dec=10 ** 14, liquidation_fee_bps=0,
                       maintenance_margin_bps=250, min_size_18dec=0, min_notional_6dec=10_000_000)
    v.specs = None
    monkeypatch.setattr(dex.Vordex, "pair_spec", lambda self, pid: spec)

    class Dom:
        def separator(self):
            return SEP
    v.domain = Dom()
    posted = []

    def get(path):
        if path.startswith("/builder/approvals/"):
            return approvals
        if path.startswith("/builder/stats/"):
            return stats
        return []
    monkeypatch.setattr(v, "_get", get)
    monkeypatch.setattr(v, "_post_once", lambda path, body: (posted.append((path, body)) or (post_answer[0], post_answer[1], None)))
    return v, posted


def test_place_order_with_builder_signs_v3(monkeypatch, tmp_path):
    monkeypatch.setenv("VORDIUM_STATE_DIR", str(tmp_path))
    ap = _approvals([{"builder": BUILDER.lower(), "max_fee_cbps": 500}])
    v, posted = _vordex(monkeypatch, ap, dict(VEC["builder_stats"]))
    out = v.place_order(KEY, ADDR, 1, 0, "0.01", "1700", order_type=1, builder={"address": BUILDER, "fee_cbps": 500})
    path, body = posted[-1]
    assert path == "/order/place"
    assert body["builder"] == BUILDER and body["builderFeeCbps"] == 500 and body["source"] == "sdk"
    assert body["price_8dec"] == "170000000000" and body["size_18dec"] == "10000000000000000"
    assert len(body["signature"]) == 132 and "sessionKey" not in body
    assert out["builder"] == {"address": BUILDER, "fee_cbps": 500}
    msg = {"owner": ADDR, "pairId": 1, "side": 0, "size": 10 ** 16, "price": 170000000000, "leverageBps": 10000,
           "orderType": 1, "reduceOnly": False, "postOnly": False, "triggerPrice8dec": 0, "triggerDir": 0,
           "timeInForce": 0, "expiresAt": 0, "clientNonce": int(body["clientNonce"]),
           "validUntil": int(body["validUntil"]), "worstPrice8dec": 0, "source": "sdk", "builder": BUILDER,
           "builderFeeCbps": 500}
    assert _recover(b.digest("PlaceOrderV3", msg, SEP), body["signature"]) == ADDR


@pytest.mark.parametrize("fee,approvals,stats,code", [
    (1001, [{"builder": BUILDER.lower(), "max_fee_cbps": 5000}], {}, "builder_fee_above_cap"),
    (600, [{"builder": BUILDER.lower(), "max_fee_cbps": 500}], {}, "builder_fee_above_approved"),
    (500, [], {}, "builder_not_approved"),
    (500, [{"builder": BUILDER.lower(), "max_fee_cbps": 500}], {"account_value_ok": False}, "builder_too_small"),
    (500, [{"builder": BUILDER.lower(), "max_fee_cbps": 500}], {"active": False}, "builder_not_active"),
    (500, [{"builder": BUILDER.lower(), "max_fee_cbps": 500}], {"caps_cbps": None}, "unreadable"),
    (0, [{"builder": BUILDER.lower(), "max_fee_cbps": 500}], {}, "builder_fee_zero"),
])
def test_place_order_with_builder_refused_before_signing(monkeypatch, tmp_path, fee, approvals, stats, code):
    monkeypatch.setenv("VORDIUM_STATE_DIR", str(tmp_path))
    v, posted = _vordex(monkeypatch, _approvals(approvals), {**VEC["builder_stats"], **stats})
    with pytest.raises(b.BuilderError) as e:
        v.place_order(KEY, ADDR, 1, 0, "0.01", "1700", order_type=1, builder={"address": BUILDER, "fee_cbps": fee})
    assert e.value.code == code
    assert posted == []


@pytest.mark.parametrize("side,given,signed", [
    (0, "1931.27", 193120000000),     # a buy's cap rounds DOWN onto the 0.1 tick: never pays more than given
    (1, "1872.71", 187280000000),     # a sell's floor rounds UP: never sells for less than given
    (0, "1931.2", 193120000000),
])
def test_builder_market_order_worst_price_on_the_tick(monkeypatch, tmp_path, side, given, signed):
    monkeypatch.setenv("VORDIUM_STATE_DIR", str(tmp_path))
    ap = _approvals([{"builder": BUILDER.lower(), "max_fee_cbps": 500}])
    v, posted = _vordex(monkeypatch, ap, dict(VEC["builder_stats"]))
    v.place_order(KEY, ADDR, 1, side, "0.01", None, order_type=0, builder={"address": BUILDER, "fee_cbps": 500},
                  worst_price=given)
    body = posted[-1][1]
    assert body["orderType"] == "Market"
    assert body["price_8dec"] == body["worstPrice8dec"] == str(signed)
    msg = {"owner": ADDR, "pairId": 1, "side": side, "size": 10 ** 16, "price": signed, "leverageBps": 10000,
           "orderType": 0, "reduceOnly": False, "postOnly": False, "triggerPrice8dec": 0, "triggerDir": 0,
           "timeInForce": 0, "expiresAt": 0, "clientNonce": int(body["clientNonce"]),
           "validUntil": int(body["validUntil"]), "worstPrice8dec": signed, "source": "sdk", "builder": BUILDER,
           "builderFeeCbps": 500}
    assert _recover(b.digest("PlaceOrderV3", msg, SEP), body["signature"]) == ADDR


def test_builder_market_order_without_worst_price_has_none(monkeypatch, tmp_path):
    monkeypatch.setenv("VORDIUM_STATE_DIR", str(tmp_path))
    ap = _approvals([{"builder": BUILDER.lower(), "max_fee_cbps": 500}])
    v, posted = _vordex(monkeypatch, ap, dict(VEC["builder_stats"]))
    v.place_order(KEY, ADDR, 1, 0, "0.01", None, order_type=0, builder={"address": BUILDER, "fee_cbps": 500})
    body = posted[-1][1]
    assert "price_8dec" not in body and body["worstPrice8dec"] == "0"


def test_worst_price_only_with_a_builder_market_order(monkeypatch, tmp_path):
    monkeypatch.setenv("VORDIUM_STATE_DIR", str(tmp_path))
    ap = _approvals([{"builder": BUILDER.lower(), "max_fee_cbps": 500}])
    v, posted = _vordex(monkeypatch, ap, dict(VEC["builder_stats"]))
    with pytest.raises(ValueError):
        v.place_order(KEY, ADDR, 1, 0, "0.01", None, order_type=0, worst_price="1900")
    with pytest.raises(ValueError):
        v.place_order(KEY, ADDR, 1, 0, "0.01", "1700", order_type=1, builder={"address": BUILDER, "fee_cbps": 500},
                      worst_price="1900")
    assert posted == []


def test_place_order_without_builder_is_unchanged(monkeypatch, tmp_path):
    monkeypatch.setenv("VORDIUM_STATE_DIR", str(tmp_path))
    v, posted = _vordex(monkeypatch, None, None)
    v.place_order(KEY, ADDR, 1, 0, "0.01", "1700", order_type=1)
    body = posted[-1][1]
    assert "builder" not in body and body["sessionKey"] == ADDR and len(body["signature"]) == 130


# -- the shared signatures (the TypeScript SDK checks the same file) -----------------------------------------------------
def test_shared_signatures_reproduce():
    x = json.loads((pathlib.Path(__file__).parent / "vectors" / "builder-cross.json").read_text())
    sep = bytes.fromhex(x["domain_separator"][2:])
    assert Account.from_key(x["key"]).address == x["address"]
    for c in x["cases"]:
        m = c["message"]
        key = c.get("signer_key", x["key"])
        if c.get("signer") == "session":
            assert Account.from_key(key).address == c["signer_address"] and "sessionKey" not in c["body"]
        if c["primaryType"] == "ApproveBuilderFee":
            s = b.approve_builder_fee(x["key"], m["user"], m["builder"], m["maxFeeCbps"], m["nonce"], m["validUntil"], sep)
        elif c["primaryType"] == "ClaimBuilderFees":
            s = b.claim_builder_fees(x["key"], m["builder"], m["nonce"], m["validUntil"], sep)
        else:
            s = b.place_order_v3(key, m["owner"], m["pairId"], m["side"], int(m["size"]), m["price"],
                                 m["leverageBps"], m["orderType"], m["clientNonce"], m["validUntil"], m["builder"],
                                 m["builderFeeCbps"], sep, reduce_only=m["reduceOnly"], post_only=m["postOnly"],
                                 worst_price_8dec=int(m["worstPrice8dec"]) if m["orderType"] == 0 else 0)
        assert "0x" + s.digest.hex() == c["digest"]
        assert s.signature == c["signature"]
        assert s.body == c["body"]
    shapes = [c["body"] for c in x["cases"] if c["primaryType"] == "PlaceOrderV3"]
    both = [bd for bd in shapes if bd.get("reduceOnly") and bd.get("postOnly")]
    assert both and all(k not in bd for bd in shapes for k in ("reduce_only", "post_only", "sessionKey"))
