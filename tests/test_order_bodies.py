"""Order intake bodies: what each write sends, where it sends it, and that every body value is the value that was signed.

The order intake names ``side`` and ``orderType`` ("buy"/"sell", "Limit"/"Market"/"StopMarket"/"StopLimit" — the type is
case-sensitive); the signed PlaceOrder digest keeps them as the uint8 values 0/1 and 0..3. A limit price goes in ``price`` as
a decimal number (the signed 8-decimal price / 1e8, at most 6 decimals); a market order carries no price and signs 0.
"""
import pytest
from eth_account import Account

from vordium import dex
from vordium import operator as opm
from vordium.caps import place_order_digest, cancel_order_digest, set_tpsl_digest

OWNER = "0x" + "11" * 20


class _Resp:
    status_code = 202
    content = b"{}"

    def json(self):
        return {"success": True}


def _capture(monkeypatch):
    """Every POST the SDK would send, captured instead of sent."""
    calls = []

    def fake_post(url, json=None, timeout=None):
        calls.append((url, json))
        return _Resp()

    monkeypatch.setattr(dex.requests, "post", fake_post)
    monkeypatch.setattr(opm.requests, "post", fake_post)
    return calls


def _recovers(digest: bytes, signature: str, address: str) -> bool:
    rs = bytes.fromhex(signature.removeprefix("0x"))[:64]
    for v in (27, 28):
        try:
            if Account._recover_hash(digest, signature=rs + bytes([v])) == address:
                return True
        except Exception:
            pass
    return False


@pytest.mark.parametrize("side,name", [(dex.BUY, "buy"), (dex.SELL, "sell")])
@pytest.mark.parametrize("otype,oname", [(dex.MARKET, "Market"), (dex.LIMIT, "Limit"),
                                         (dex.STOP_MARKET, "StopMarket"), (dex.STOP_LIMIT, "StopLimit")])
def test_place_body_names_side_and_type_and_carries_the_signed_values(monkeypatch, side, name, otype, oname):
    sent = _capture(monkeypatch)
    session = Account.create()
    trig = 2_500.5 if otype in (dex.STOP_MARKET, dex.STOP_LIMIT) else 0.0
    tdir = 2 if trig else 0
    dex.Vordex(rpc_url="http://rpc.invalid").place_order(
        session.key.hex(), OWNER, 3, side, 0.25, 2_400.12, leverage=2.0, order_type=otype, post_only=otype == dex.LIMIT,
        trigger_price=trig, trigger_dir=tdir, client_nonce=1_700_000_000_123)
    (url, body), = sent
    assert url == "http://rpc.invalid/order/place"
    assert body["side"] == name and body["orderType"] == oname
    assert "price_8dec" not in body and "limitPrice" not in body
    priced = otype in (dex.LIMIT, dex.STOP_LIMIT)
    if priced:
        assert type(body["price"]) is float and body["price"] == 2_400.12
    else:
        assert "price" not in body                       # a market order carries no price
    signed_price = 240_012_000_000 if priced else 0
    assert body["size_18dec"] == str(250_000_000_000_000_000)
    assert body["pairId"] == 3 and body["leverageBps"] == 20_000 and body["clientNonce"] == 1_700_000_000_123
    assert body["sessionKey"] == session.address and body["owner"] == OWNER
    assert body["trigger_price_8dec"] == (250_050_000_000 if trig else 0) and body["trigger_dir"] == tdir
    # the body's values, mapped back to the signed numbers, are exactly what the session key signed
    back_side = {v: k for k, v in dex.SIDE_NAMES.items()}[body["side"]]
    back_type = {v: k for k, v in dex.ORDER_TYPE_NAMES.items()}[body["orderType"]]
    back_price = round(body["price"] * 10**6) * 100 if priced else 0
    assert back_price == signed_price
    d = place_order_digest(OWNER, body["pairId"], back_side, int(body["size_18dec"]), back_price,
                           body["leverageBps"], back_type, body["reduceOnly"], body["clientNonce"], body["post_only"],
                           body["trigger_price_8dec"], body["trigger_dir"])
    assert _recovers(d, body["signature"], session.address)


@pytest.mark.parametrize("given,kept", [(1343.87, 134_387_000_000), (1343.8712346, 134_387_123_500),
                                        (0.1234567, 12_345_700), (2_400.12, 240_012_000_000)])
def test_a_limit_price_is_signed_at_the_six_decimals_the_chain_keeps(monkeypatch, given, kept):
    sent = _capture(monkeypatch)
    session = Account.create()
    dex.Vordex(rpc_url="http://rpc.invalid").place_order(session.key.hex(), OWNER, 1, dex.BUY, 1, given, client_nonce=9)
    body = sent[0][1]
    assert round(body["price"] * 10**6) * 100 == kept and kept % 100 == 0
    d = place_order_digest(OWNER, 1, dex.BUY, 10**18, kept, 10_000, dex.LIMIT, False, 9, False, 0, 0)
    assert _recovers(d, body["signature"], session.address)


def test_a_body_refuses_a_price_with_more_than_six_decimals_or_a_priced_market():
    with pytest.raises(ValueError):
        dex.place_order_body(OWNER, OWNER, 1, dex.BUY, 1, 134_387_123_45, 10_000, dex.LIMIT, False, False, 0, 0, 1, "0x")
    with pytest.raises(ValueError):
        dex.place_order_body(OWNER, OWNER, 1, dex.BUY, 1, 134_387_000_000, 10_000, dex.MARKET, False, False, 0, 0, 1, "0x")
    with pytest.raises(ValueError):
        dex.place_order_body(OWNER, OWNER, 1, dex.BUY, 1, 0, 10_000, dex.LIMIT, False, False, 0, 0, 1, "0x")


def test_no_number_is_ever_sent_for_side_or_type(monkeypatch):
    sent = _capture(monkeypatch)
    session = Account.create()
    dex.Vordex(rpc_url="http://rpc.invalid").place_order(session.key.hex(), OWNER, 1, dex.SELL, 1, 100, client_nonce=5)
    body = sent[0][1]
    assert type(body["side"]) is str and type(body["orderType"]) is str


@pytest.mark.parametrize("bad", [2, -1, True, "buy", 0.0, None])
def test_an_unknown_side_is_refused_before_anything_is_signed_or_sent(monkeypatch, bad):
    sent = _capture(monkeypatch)
    with pytest.raises(ValueError):
        dex.Vordex(rpc_url="http://rpc.invalid").place_order(Account.create().key.hex(), OWNER, 1, bad, 1, 100)
    assert sent == []


@pytest.mark.parametrize("bad", [4, -1, False, "limit", "Limit"])
def test_an_unknown_order_type_is_refused_before_anything_is_sent(monkeypatch, bad):
    sent = _capture(monkeypatch)
    with pytest.raises(ValueError):
        dex.Vordex(rpc_url="http://rpc.invalid").place_order(Account.create().key.hex(), OWNER, 1, dex.BUY, 1, 100,
                                                              order_type=bad)
    assert sent == []


def test_cancel_body_names_the_order_as_order_id(monkeypatch):
    sent = _capture(monkeypatch)
    session = Account.create()
    dex.Vordex(rpc_url="http://rpc.invalid").cancel_order(session.key.hex(), OWNER, 42)
    (url, body), = sent
    assert url == "http://rpc.invalid/order/cancel"
    assert set(body) == {"order_id", "owner", "session_key", "signature"} and body["order_id"] == 42
    assert body["session_key"] == session.address
    assert _recovers(cancel_order_digest(OWNER, 42), body["signature"], session.address)


def _operator():
    session = Account.create()
    return opm.Operator(owner=OWNER, signer=opm.SessionSigner(private_key=session.key.hex()),
                        box=opm.AgentBox(rpc_url="http://rpc.invalid", rest_url="http://rpc.invalid"),
                        submit_url="http://rpc.invalid"), session


def test_operator_place_sends_the_same_body_shape(monkeypatch):
    sent = _capture(monkeypatch)
    op, session = _operator()
    op.place_order(pair_id=2, side=dex.SELL, size=10**18, price=123_400_000_000, leverage_bps=10_000,
                   client_nonce=77, post_only=True, precheck=False)
    (url, body), = sent
    assert url == "http://rpc.invalid/order/place"
    ref = dex.place_order_body(OWNER, session.address, 2, dex.SELL, 10**18, 123_400_000_000, 10_000, dex.LIMIT,
                               False, True, 0, 0, 77, body["signature"])
    assert body == ref and body["side"] == "sell" and body["price"] == 1234.0


def test_operator_market_signs_price_zero_and_sends_no_price(monkeypatch):
    sent = _capture(monkeypatch)
    op, session = _operator()
    op.place_market_order(pair_id=2, side=dex.BUY, size=10**18, cap_price=123_400_000_000, leverage_bps=10_000,
                          client_nonce=78, precheck=False)
    body = sent[0][1]
    assert body["orderType"] == "Market" and "price" not in body and "price_8dec" not in body
    d = place_order_digest(OWNER, 2, dex.BUY, 10**18, 0, 10_000, dex.MARKET, False, 78, False, 0, 0)
    assert _recovers(d, body["signature"], session.address)


def test_operator_cancel_and_tpsl_use_the_routes_the_intake_has(monkeypatch):
    sent = _capture(monkeypatch)
    op, session = _operator()
    op.cancel_order(9)
    op.set_tpsl(pair_id=1, position_id=4, take_profit_8dec=3_500_000_000, stop_loss_8dec=0)
    (u1, b1), (u2, b2) = sent
    assert u1.endswith("/order/cancel") and b1["order_id"] == 9
    assert u2.endswith("/tpsl/set") and b2["action"] == "perp_tpsl"
    assert b2["take_profit_8dec"] == 3_500_000_000 and b2["stop_loss_8dec"] == 0
    assert _recovers(set_tpsl_digest(OWNER, 1, 4, 3_500_000_000, 0), b2["signature"], session.address)


def test_operator_modify_is_refused_without_sending(monkeypatch):
    sent = _capture(monkeypatch)
    op, _ = _operator()
    with pytest.raises(NotImplementedError):
        op.modify_order(1, 100, 100)
    assert sent == []
