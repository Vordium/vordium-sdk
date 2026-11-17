"""What is signed is what an ASCII reader sees, and a mistyped checksummed address is refused, on every signing path."""
import pytest
from eth_account import Account

from vordium import _strict, account_ops as ao, builder, caps, domains, eip712, mm, money, schedule_cancel as sc

GOOD = "0x52908400098527886E0F7030069857D2E4169EE7"          # EIP-55 test vector (mixed case, right checksum)
BAD = "0x52908400098527886E0F7030069857D2E4169Ee7"           # one letter's case changed
OWNER = Account.create()
NON_ASCII = ["٣", "1٠5", "1５", "١٢"]


def test_strict_whole_and_address():
    assert _strict.whole("12") == 12 and _strict.whole(12) == 12
    for x in NON_ASCII + [True, "1.5", "", "-1x", 1.0]:
        with pytest.raises(ValueError):
            _strict.whole(x)
    assert _strict.address(GOOD) == GOOD
    assert _strict.address(GOOD.lower()) == GOOD
    assert _strict.address("0x" + GOOD[2:].upper()) == GOOD
    with pytest.raises(ValueError):
        _strict.address(BAD)


@pytest.mark.parametrize("x", NON_ASCII)
def test_non_ascii_whole_numbers_are_refused_on_signing_paths(x):
    with pytest.raises(ValueError):
        caps.place_order_struct_hash(OWNER.address, x, 0, 10 ** 18, 10 ** 8, 10_000, 1, False, 1, False, 0, 0)
    with pytest.raises(ValueError):
        caps.place_order_struct_hash(OWNER.address, 1, 0, 10 ** 18, 10 ** 8, 10_000, 1, False, x, False, 0, 0)
    with pytest.raises(ValueError):
        caps.cancel_order_struct_hash(OWNER.address, x)
    with pytest.raises(ValueError):
        caps.schedule_cancel_struct_hash(OWNER.address, x, 1)
    with pytest.raises(ValueError):
        ao.struct_hash("SessionCreate", ao.SESSION_CREATE, {"sessionKey": GOOD, "expiresAt": 1, "nonce": x})
    with pytest.raises(builder.BuilderError):
        builder.parse_builder({"address": GOOD, "fee_cbps": x})
    with pytest.raises(ValueError):
        builder.struct_hash("ClaimBuilderFees", {"builder": GOOD, "nonce": x, "validUntil": 1})
    with pytest.raises(mm.MMError):
        mm.cancel_all_struct_hash(OWNER.address, x, 1)
    with pytest.raises(ValueError):
        eip712.digest("RevokeAgent", {"owner": OWNER.address, "agent": GOOD, "nonce": x})


def test_wrong_checksum_is_refused_on_signing_paths():
    with pytest.raises(ValueError):
        caps.place_order_struct_hash(BAD, 1, 0, 10 ** 18, 10 ** 8, 10_000, 1, False, 1, False, 0, 0)
    with pytest.raises(ValueError):
        ao.struct_hash("SessionCreate", ao.SESSION_CREATE, {"sessionKey": BAD, "expiresAt": 1, "nonce": 1})
    with pytest.raises(builder.BuilderError):
        builder.parse_builder({"address": BAD, "fee_cbps": 10})
    with pytest.raises(ValueError):
        eip712.digest("RevokeAgent", {"owner": OWNER.address, "agent": BAD, "nonce": 1})
    with pytest.raises(money.MoneyOpError):
        money._addr(BAD, "the account")
    # the right checksum and plain lower case still sign
    assert caps.place_order_struct_hash(GOOD, 1, 0, 10 ** 18, 10 ** 8, 10_000, 1, False, 1, False, 0, 0)
    assert caps.place_order_struct_hash(GOOD.lower(), 1, 0, 10 ** 18, 10 ** 8, 10_000, 1, False, 1, False, 0, 0)
    assert builder.parse_builder({"address": GOOD.lower(), "fee_cbps": 10})[0] == GOOD


@pytest.mark.parametrize("field,args", [
    ("pair_id", dict(pair_id=2 ** 32)), ("leverage", dict(leverage_bps=2 ** 32)), ("nonce", dict(client_nonce=2 ** 64)),
    ("size", dict(size=2 ** 128)), ("price", dict(price=2 ** 64)),
])
def test_out_of_range_order_fields_are_refused_never_wrapped(field, args):
    base = dict(owner=OWNER.address, pair_id=1, side=0, size=10 ** 18, price=10 ** 8, leverage_bps=10_000, order_type=1,
                reduce_only=False, client_nonce=1, post_only=False, trigger_price_8dec=0, trigger_dir=0)
    base.update(args)
    with pytest.raises(ValueError):
        caps.place_order_struct_hash(**base)


def test_out_of_range_ids_are_refused():
    with pytest.raises(ValueError):
        caps.cancel_order_struct_hash(OWNER.address, 2 ** 64)
    with pytest.raises(ValueError):
        caps.set_tpsl_struct_hash(OWNER.address, 2 ** 32, 1, 1, 1)
    with pytest.raises(ValueError):
        ao.struct_hash("SetMarginMode", ao.SET_MARGIN_MODE, {"owner": OWNER.address, "pairId": 2 ** 32, "mode": 1, "nonce": 1})


def test_whole_decimal_and_unprefixed_address_sign_as_before():
    """A whole-number Decimal and an address without 0x are normalised: the digest is the one an int and 0x give."""
    from decimal import Decimal
    a = caps.place_order_struct_hash(GOOD, 1, 0, 10 ** 18, 10 ** 8, 10_000, 1, False, 7, False, 0, 0)
    b = caps.place_order_struct_hash(GOOD[2:].lower(), Decimal(1), 0, Decimal(10 ** 18), Decimal("100000000"), 10_000, 1,
                                     False, Decimal(7), False, 0, 0)
    assert a == b
    assert ao.struct_hash("SessionCreate", ao.SESSION_CREATE, {"sessionKey": GOOD[2:], "expiresAt": Decimal(5), "nonce": 1}) == \
        ao.struct_hash("SessionCreate", ao.SESSION_CREATE, {"sessionKey": GOOD, "expiresAt": 5, "nonce": 1})


@pytest.mark.parametrize("x", [1.0, 1e10, "1.5"])
def test_floats_and_fractions_are_refused_in_whole_number_fields(x):
    from decimal import Decimal
    with pytest.raises(ValueError):
        caps.cancel_order_struct_hash(OWNER.address, x)
    with pytest.raises(ValueError):
        caps.cancel_order_struct_hash(OWNER.address, Decimal("1.5"))


def test_set_agent_caps_and_mode_fields_must_fit():
    with pytest.raises(ValueError):
        caps.set_agent_caps_struct_hash(OWNER.address, 2 ** 64, 1, 1, 1)
    with pytest.raises(ValueError):
        caps.set_agent_caps_struct_hash(OWNER.address, 1, 2 ** 32, 1, 1)
    with pytest.raises(ValueError):
        caps.set_agent_mode_struct_hash(OWNER.address, 256)
    assert caps.set_agent_mode_struct_hash(OWNER.address, 2)


def test_web3_calls_refuse_a_redirect_with_a_plain_sentence():
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    from web3 import Web3
    from vordium import _http
    hits = []

    class Other(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_POST(self):
            hits.append(self.path)
            self.send_response(200); self.end_headers(); self.wfile.write(b'{"jsonrpc":"2.0","id":1,"result":"0x1"}')

    other = ThreadingHTTPServer(("127.0.0.1", 0), Other)
    threading.Thread(target=other.serve_forever, daemon=True).start()

    class Node(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_POST(self):
            self.send_response(307); self.send_header("Location", f"http://127.0.0.1:{other.server_address[1]}/")
            self.send_header("Content-Length", "0"); self.end_headers()

    node = ThreadingHTTPServer(("127.0.0.1", 0), Node)
    threading.Thread(target=node.serve_forever, daemon=True).start()
    try:
        w3 = Web3(_http.web3_provider(f"http://127.0.0.1:{node.server_address[1]}/"))
        with pytest.raises(Exception) as e:
            w3.eth.block_number
        assert _http.REDIRECT_WORDS in str(e.value) and hits == []
    finally:
        node.shutdown(); other.shutdown()
