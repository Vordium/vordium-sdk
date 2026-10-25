"""Session, TWAP and margin-mode helpers: the published PlaceTwap vector byte for byte, the published SetMarginMode type
hash, the exact request bodies, the TWAP plan and spec reading, and "applied" only when the chain's read shows it."""
import json

import pytest

from vordium import account_ops as A
from vordium import domains

# the node's published PlaceTwap vector (public test key: 32 bytes of 0x21, never funded)
VEC_GENESIS = "2c1c0679fa6ab8358f1d3e8d294a8d1c73ac2e2caf9079f1216abedc3d9fdf4f"
VEC_KEY = "0x" + "21" * 32
VEC_VALUE = {"owner": "0x2BD0C9FE079c8FcA0E3352eb3D02839c371E5c41", "pairId": 1, "side": 0, "totalSize18dec": 20 * 10**18,
             "numSlices": 10, "durationMs": 300000, "leverageBps": 30000, "slippageBps": 300, "randomize": False,
             "triggerPrice8dec": 0, "triggerDir": 0, "minPrice8dec": 0, "maxPrice8dec": 0, "clientNonce": 1790400000000}
VEC_SEP = "0x68b86feeb9a9d9d471c3355da4719f2ce6a2330fbde6dad54d815783dacab34b"
VEC_DIGEST = "0xe232a8d77cd5c55c7f0b3b573faeae8f65019d2fed007e2c20106e98fad66499"
VEC_SIG = ("0xed3245c52b7fa5e1a4bc69ab63e72c994c1e928a75c4278989a3e211bc3b9c5c2fa975ee3df922033b1c88e0772a5f159d39fabff5fca"
           "2732bfe3688aa9582181c")


def test_place_twap_vector():
    sep = domains.separator("VordCore", 101101, VEC_GENESIS)
    assert "0x" + sep.hex() == VEC_SEP
    d = A.digest(sep, "PlaceTwap", A.PLACE_TWAP, VEC_VALUE)
    assert "0x" + d.hex() == VEC_DIGEST
    assert A.sign_digest(VEC_KEY, d) == VEC_SIG


def test_type_strings():
    assert A.type_string("PlaceTwap", A.PLACE_TWAP) == (
        "PlaceTwap(address owner,uint32 pairId,uint8 side,uint128 totalSize18dec,uint32 numSlices,uint64 durationMs,"
        "uint32 leverageBps,uint32 slippageBps,bool randomize,uint64 triggerPrice8dec,uint8 triggerDir,"
        "uint64 minPrice8dec,uint64 maxPrice8dec,uint64 clientNonce)")
    from eth_utils import keccak
    assert "0x" + keccak(text=A.type_string("SetMarginMode", A.SET_MARGIN_MODE)).hex() == A.SET_MARGIN_MODE_TYPEHASH
    assert A.type_string("SessionCreate", A.SESSION_CREATE) == "SessionCreate(address sessionKey,uint256 expiresAt,uint256 nonce)"
    assert A.type_string("SessionRevoke", A.SESSION_REVOKE) == "SessionRevoke(address owner,uint256 nonce)"
    assert A.type_string("CancelTwap", A.CANCEL_TWAP) == "CancelTwap(address owner,uint64 twapId,uint64 clientNonce)"


def test_signature_recovers_to_the_signer():
    from eth_account import Account
    sep = domains.separator("VordexSession", 101102, VEC_GENESIS)
    d = A.digest(sep, "SessionCreate", A.SESSION_CREATE, {"sessionKey": "0x" + "11" * 20, "expiresAt": 1, "nonce": 2})
    sig = A.sign_digest(VEC_KEY, d)
    assert len(bytes.fromhex(sig[2:])) == 65 and sig[-2:] in ("1b", "1c")
    assert Account._recover_hash(d, signature=bytes.fromhex(sig[2:])) == Account.from_key(VEC_KEY).address


def test_bodies_are_exact():
    b = A.twap_body(VEC_VALUE, "0xab")
    assert b.startswith('{"owner":"0x2BD0C9FE079c8FcA0E3352eb3D02839c371E5c41","pair_id":1,"side":0,"total_size_18dec":20000000000000000000,')
    assert '"randomize":false' in b and b.endswith('"client_nonce":1790400000000,"signature":"0xab"}')
    assert list(json.loads(b).keys()) == ["owner", "pair_id", "side", "total_size_18dec", "num_slices", "duration_ms",
                                          "leverage_bps", "slippage_bps", "randomize", "trigger_price_8dec", "trigger_dir",
                                          "min_price_8dec", "max_price_8dec", "client_nonce", "signature"]
    assert A.cancel_twap_body("0xAb", 7, 9, "0xcd") == '{"owner":"0xAb","twap_id":7,"client_nonce":9,"signature":"0xcd"}'
    assert A.margin_mode_body("0xAB", 3, 1, 5, "0xcd") == '{"owner":"0xab","pair_id":3,"mode":1,"nonce":5,"signature":"0xcd"}'
    assert json.loads(A.session_create_body("0xA", "0xB", 10, 11, "0xs")) == {"owner": "0xA", "session_key": "0xB", "expires_at": 10, "nonce": 11, "signature": "0xs"}
    assert json.loads(A.session_revoke_body("0xA", "0xB", 12, "0xs")) == {"owner": "0xA", "session_key": "0xB", "nonce": 12, "signature": "0xs"}


def test_nonce_and_end():
    assert A.next_nonce(0, 1000) == 1000 and A.next_nonce(5000, 1000) == 5001
    assert A.session_end(10**15, 0) == A.SESSION_MAX_SECONDS
    assert A.session_end(7_000, 0) == 7


SPEC = {"twap": {"liveToday": True,
                 "place": {"method": "POST", "path": "/twap/place", "typeString": {"value": A.type_string("PlaceTwap", A.PLACE_TWAP)},
                           "body": [{"name": f} for f in A.TWAP_BODY]},
                 "cancel": {"path": "/twap/cancel", "typeString": A.type_string("CancelTwap", A.CANCEL_TWAP)},
                 "durationMs": {"min": 300000, "max": 604800000},
                 "subOrders": {"minIntervalMs": 30000, "maxNumSlices": 100, "maxSlippageBpsPerSubOrder": 500,
                               "minSubOrderNotional6dec": "10000000", "minTotalNotional6dec": "10000000"}}}


def test_twap_rules_from_a_recorded_spec():
    """The spec the app was proven on (recorded): both readers must agree on its limits."""
    import pathlib
    p = pathlib.Path(__file__).parent / "vectors" / "twap-spec-v6.json"
    r = A.read_twap_rules(json.loads(p.read_text()))
    assert r.path == "/twap/place" and r.cancel_path == "/twap/cancel" and r.max_slices > 0 and r.min_interval_ms > 0


def test_twap_rules_and_plan():
    r = A.read_twap_rules(SPEC)
    assert (r.path, r.max_slices, r.min_interval_ms, r.max_slippage_bps) == ("/twap/place", 100, 30000, 500)
    assert A.plan_twap(300000, r) == (10, 30000)
    assert A.plan_twap(3_600_000, r, total_notional_6dec=50_000_000) == (5, 720000)
    with pytest.raises(ValueError):
        A.plan_twap(1000, r)
    with pytest.raises(ValueError):
        A.plan_twap(300000, r, total_notional_6dec=1)


def test_twap_spec_in_another_format_is_refused():
    bad = json.loads(json.dumps(SPEC))
    bad["twap"]["place"]["typeString"] = "PlaceTwap(address owner)"
    with pytest.raises(ValueError):
        A.read_twap_rules(bad)
    with pytest.raises(ValueError):
        A.read_twap_rules({})
    other = json.loads(json.dumps(SPEC)); other["twap"]["place"]["body"] = [{"name": "owner"}]
    with pytest.raises(ValueError, match="body"):
        A.read_twap_rules(other)
    with pytest.raises(ValueError, match="not derived yet"):
        A.read_twap_rules({"twap": {"available": False, "reason": "not derived yet"}})


class _Ident:
    chain_id = 101102
    genesis_sha256 = VEC_GENESIS


class _Stub(A.AccountOps):
    """A client whose node is a script: posts are recorded and answered; reads come from a list."""
    def __init__(self, post_answer, reads):
        self.rest, self.key, self.timeout, self.ident = "http://node.invalid", VEC_KEY, 1.0, _Ident()
        from eth_account import Account
        self.owner = Account.from_key(VEC_KEY).address
        self.posts, self.post_answer, self.reads = [], post_answer, list(reads)

    def _post(self, path, body):
        self.posts.append((path, body))
        return self.post_answer

    def _get(self, path):
        return self.reads.pop(0) if len(self.reads) > 1 else self.reads[0]

    @staticmethod
    def _wait(fn, secs, step=0.0):
        for _ in range(5):
            if fn():
                return True
        return False


def test_margin_mode_applied_only_when_read():
    shown = {"modes": [{"pair_id": 4, "mode": "cross"}], "default_mode": "isolated"}
    c = _Stub((202, {"status": "submitted"}), [shown])
    r = c.set_margin_mode(4, "cross")
    assert r.applied and c.posts[0][0] == "/margin/mode" and '"mode":1' in c.posts[0][1]
    c = _Stub((202, {"status": "submitted"}), [{"modes": [], "default_mode": "isolated"}])
    assert not c.set_margin_mode(4, "cross").applied
    c = _Stub((409, {"error": "pending"}), [shown])
    assert not c.set_margin_mode(4, "cross").applied
    with pytest.raises(ValueError):
        c.set_margin_mode(4, "portfolio")


def test_session_create_revokes_another_key_first():
    other = {"session_key": "0x" + "22" * 20, "confirmed": True}
    mine = {"session_key": "0x" + "33" * 20, "confirmed": True}
    c = _Stub((200, {"success": True}), [other, other, {"error": "no active session"}, mine])
    r = c.create_session("0x" + "33" * 20, 10**15)
    assert [p for p, _ in c.posts] == ["/session/revoke", "/session/create"]
    assert r.applied
    a, b = json.loads(c.posts[0][1])["nonce"], json.loads(c.posts[1][1])["nonce"]
    assert b > a


def test_session_not_confirmed_is_not_applied():
    c = _Stub((200, {"success": True}), [None, {"session_key": "0x" + "33" * 20, "confirmed": False}])
    assert not c.create_session("0x" + "33" * 20, 10**15).applied


def test_twap_placed_only_when_listed():
    r = A.read_twap_rules(SPEC)
    c = _Stub((202, {"status": "submitted"}), [{"twaps": []}])
    assert not c.place_twap(r, 1, 0, 10**18, 300000).applied
    body = json.loads(c.posts[0][1])
    assert body["num_slices"] == 10 and body["owner"] == c.owner
    with pytest.raises(ValueError):
        c.place_twap(r, 1, 0, 10**18, 300000, slippage_bps=900)
