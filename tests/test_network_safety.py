"""Network safety, one nonce clock per account, tick/lot rounding and the market maker's account reads."""

import pytest
from eth_account import Account
from eth_utils import keccak

from vordium import caps, mm, node_domain
from vordium import network as net
from vordium import schedule_cancel as sc
from vordium import dex
from vordium import operator as opm
from vordium.network import NetworkMismatch, NetworkResolutionError
from vordium.node_domain import NodeIdentity

VC = net.VERIFYING_CONTRACT
LIVE = NodeIdentity(101101, "2c1c0679fa6ab8358f1d3e8d294a8d1c73ac2e2caf9079f1216abedc3d9fdf4f")
TEST = NodeIdentity(101102, "3263e89e7cd024467a58c352a4d4446f30020093ed979d6e318196c7007d2482")
KEY = "0x" + keccak(b"vordium-sdk-test-network-safety").hex()
OWNER = Account.from_key(KEY).address


def _net(ident):
    return net.Network(chain_id=ident.chain_id, chain_id_hex=hex(ident.chain_id), chain_name="x", rpc_url="offline",
                       ws_url=None, explorer_url=None, bridge_address=None, bridge_chain=None, bridge_chain_id=None,
                       native_symbol="VORD", native_decimals=18, verifying_contract=VC, source="test",
                       genesis_sha256=ident.genesis_sha256)


def _sep(ident):
    return caps.vordcore_domain_separator(ident.chain_id, VC, ident.genesis_sha256)


class _Rec:
    def __init__(self):
        self.sent = []

    def __call__(self, path, body):
        self.sent.append((path, body))
        return 202, {"status": "submitted", "intaken": True, "actions": []}, None


def _client(node, network=None, sep=None, rec=None, unconfigured=False):
    if unconfigured:
        net.reset_network()
    return mm.MarketMaker("https://node.invalid", KEY, OWNER, domain_separator=sep, post=rec or _Rec(),
                          identity=lambda: node, network=network)


# --- the domain is the node's; a configured network that disagrees refuses ------------------------------------
def test_a_test_node_never_signs_for_the_live_network():
    rec = _Rec()
    c = _client(TEST, rec=rec)                       # conftest configures the live network
    with pytest.raises(NetworkMismatch):
        c.cancel_all()
    assert rec.sent == []


def test_a_live_node_never_signs_for_the_test_network():
    rec = _Rec()
    c = _client(LIVE, network=_net(TEST), rec=rec)
    with pytest.raises(NetworkMismatch):
        c.batch([mm.cancel(1)])
    assert rec.sent == []


def test_unconfigured_the_client_signs_for_the_node_it_posts_to(monkeypatch):
    monkeypatch.delenv("VORDIUM_CHAIN_ID", raising=False)
    monkeypatch.delenv("VORDIUM_GENESIS_SHA256", raising=False)
    rec = _Rec()
    c = _client(TEST, rec=rec, unconfigured=True)
    c.cancel_all(3)
    _, body = rec.sent[-1]
    d = keccak(b"\x19\x01" + _sep(TEST) + mm.cancel_all_struct_hash(OWNER, 3, body["nonce"]))
    assert Account._recover_hash(d, signature=bytes.fromhex(body["signature"][2:])) == OWNER


def test_environment_pins_are_the_configured_network(monkeypatch):
    net.reset_network()
    monkeypatch.setenv("VORDIUM_CHAIN_ID", "101101")
    with pytest.raises(NetworkMismatch):
        _client(TEST).cancel_all()
    monkeypatch.setenv("VORDIUM_CHAIN_ID", "101102")
    monkeypatch.setenv("VORDIUM_GENESIS_SHA256", "0x" + LIVE.genesis_sha256)
    with pytest.raises(NetworkMismatch):
        _client(TEST).cancel_all()


def test_a_given_separator_pins_and_never_overrides():
    with pytest.raises(NetworkMismatch):
        _client(TEST, network=_net(TEST), sep=_sep(LIVE)).cancel_all()
    assert _client(TEST, network=_net(TEST), sep=_sep(TEST)).cancel_all().ok


def test_a_node_that_changes_chain_is_refused_not_followed():
    t = {"now": 0.0}
    seen = [TEST]
    d = node_domain.NodeDomain("https://node.invalid", _net(TEST), None, lambda: seen[0], ttl_s=60, clock=lambda: t["now"])
    assert d.separator() == _sep(TEST)
    seen[0] = NodeIdentity(TEST.chain_id, "e" * 64)        # same id, a relaunched genesis
    t["now"] = 30.0
    assert d.separator() == _sep(TEST)                     # inside the window: the bound identity
    t["now"] = 61.0
    with pytest.raises(NetworkMismatch):
        d.separator()


def test_a_status_without_chain_id_or_genesis_is_refused():
    for bad in ({}, {"chain_id": 101102}, {"genesis_sha256": TEST.genesis_sha256}, {"chain_id": True, "genesis_sha256": "x"},
                [], {"chain_id": 101102, "genesis_sha256": "12"}):
        with pytest.raises(NetworkResolutionError):
            node_domain.read_identity(bad)
    assert node_domain.read_identity({"chain_id": "101102", "genesis_sha256": "0x" + TEST.genesis_sha256.upper()}) == TEST


def test_node_identity_reads_the_paths_own_status_then_the_root():
    assert node_domain.status_urls("https://host.invalid/chain/") == ["https://host.invalid/chain/status", "https://host.invalid/status"]
    assert node_domain.status_urls("https://host.invalid") == ["https://host.invalid/status"]


# --- the dead-man switch: same rules -----------------------------------------------------------------------------
def test_schedule_cancel_signs_under_the_nodes_domain_and_refuses_another():
    sent = []

    def post(rpc_url, body, timeout):
        sent.append(body)
        return 202, {"status": "submitted"}
    r = sc.submit("https://node.invalid", KEY, OWNER, 1_900_000_000_000, 5, post=post, network=_net(TEST), identity=lambda: TEST)
    assert r.ok
    d = sc.schedule_cancel_digest(OWNER, 1_900_000_000_000, 5, _sep(TEST))
    assert Account._recover_hash(d, signature=bytes.fromhex(sent[-1]["signature"][2:])) == OWNER
    with pytest.raises(NetworkMismatch):
        sc.submit("https://node.invalid", KEY, OWNER, 1_900_000_000_000, 6, post=post, identity=lambda: TEST)
    assert len(sent) == 1


def test_keepalive_on_another_network_raises_and_is_not_alive():
    st = sc.read_state({"account": OWNER, "cancel_at_ms": None, "set_at_ms": None, "nonce": None, "fired": False,
                        "orders_refused": False, "active": True,
                        "limits": {"min_lead_ms": 5000, "max_horizon_ms": 600000, "min_refresh_ms": 1000}}, OWNER)
    ka = sc.KeepAlive("https://node.invalid", KEY, OWNER, lead_ms=30_000, post=lambda *a: (202, {"status": "submitted"}),
                      read=lambda: st, identity=lambda: TEST)
    with pytest.raises(NetworkMismatch):
        ka.refresh()
    assert ka.alive is False


# --- one nonce clock per account -------------------------------------------------------------------------------
def test_one_clock_per_account_shared_by_batches_and_the_dead_man_switch():
    assert mm.nonce_clock(OWNER) is mm.nonce_clock(OWNER.lower()) is mm.nonce_clock(OWNER.upper().replace("0X", "0x"))
    assert mm.nonce_clock(OWNER) is not mm.nonce_clock("0x" + "1" * 40)
    rec = _Rec()
    c = mm.MarketMaker("https://node.invalid", KEY, OWNER, post=rec, identity=lambda: LIVE)
    st = sc.read_state({"account": OWNER, "cancel_at_ms": None, "set_at_ms": None, "nonce": None, "fired": False,
                        "orders_refused": False, "active": True,
                        "limits": {"min_lead_ms": 5000, "max_horizon_ms": 600000, "min_refresh_ms": 0}}, OWNER)
    ka_sent = []
    ka = sc.KeepAlive("https://node.invalid", KEY, OWNER, lead_ms=30_000, sleep=lambda s: None,
                      post=lambda u, b, t: (ka_sent.append(b), (202, {"status": "submitted"}))[1], read=lambda: st,
                      identity=lambda: LIVE)
    assert c.nonce is ka.nonce
    seen = []
    for _ in range(25):
        c.cancel_all(); seen.append(rec.sent[-1][1]["nonce"])
        ka.refresh(); seen.append(ka_sent[-1]["nonce"])
    assert seen == sorted(seen) and len(set(seen)) == len(seen)       # strictly rising, never shared


def test_a_nonce_the_chain_holds_moves_the_clock_above_it():
    k = mm.NonceClock(lambda: 1.0)
    k.seen(5_000_000)
    assert k() == 5_000_001 and k.next_at_least(9) == 5_000_002 and k.next_at_least(7_000_000) == 7_000_000


def test_single_orders_take_the_same_clock(monkeypatch):
    sent = []

    class R:
        status_code, content = 202, b"{}"

        def json(self):
            return {}
    monkeypatch.setattr(dex.requests, "post", lambda url, json=None, timeout=None: (sent.append(json), R())[1])
    session = Account.create()
    mm.nonce_clock(OWNER).seen(9_999_999_999_000)
    dex.Vordex(rpc_url="http://rpc.invalid").place_order(session.key.hex(), OWNER, 1, dex.BUY, 1, 100)
    assert sent[-1]["clientNonce"] == 9_999_999_999_001


def test_single_orders_and_the_operator_refuse_another_network(monkeypatch):
    sent = []
    monkeypatch.setattr(dex.requests, "post", lambda *a, **k: sent.append(1))
    monkeypatch.setattr(opm.requests, "post", lambda *a, **k: sent.append(1))
    session = Account.create()
    with pytest.raises(NetworkMismatch):
        dex.Vordex(rpc_url="http://rpc.invalid", identity=lambda: TEST).place_order(session.key.hex(), OWNER, 1, dex.BUY, 1, 100)
    with pytest.raises(NetworkMismatch):
        dex.Vordex(rpc_url="http://rpc.invalid", identity=lambda: TEST).cancel_order(session.key.hex(), OWNER, 4)
    monkeypatch.setattr(node_domain, "node_identity", lambda rpc_url, timeout=6.0, get_json=None: TEST)
    op = opm.Operator(owner=OWNER, signer=opm.SessionSigner(private_key=session.key.hex()), submit_url="http://rpc.invalid")
    with pytest.raises(NetworkMismatch):
        op.cancel_order(4)
    assert sent == []


# --- tick and lot ----------------------------------------------------------------------------------------------
SPEC = mm.PairSpec(1, "BTC", 100_000_000, 10**15, None, None)      # tick 1.00, lot 0.001
FREE = mm.PairSpec(2, "ETH", 0, 0, None, None)


@pytest.mark.parametrize("price,side,want", [(8_593_012_345_678, "buy", 8_593_000_000_000), (8_593_012_345_678, "sell", 8_593_100_000_000),
                                             (8_593_000_000_000, "buy", 8_593_000_000_000), (8_593_000_000_000, "sell", 8_593_000_000_000)])
def test_round_price_bids_down_asks_up(price, side, want):
    assert mm.round_price(price, SPEC, side) == want
    assert mm.on_tick(mm.round_price(price, SPEC, side), SPEC)


def test_round_without_a_tick_or_lot_returns_the_value():
    assert mm.round_price(123_456_789, FREE, "sell") == 123_456_789 and mm.round_size(987_654_321, FREE) == 987_654_321


def test_round_size_down_onto_the_lot():
    assert mm.round_size(2_345_678_000_000_000_000, SPEC) == 2_345_000_000_000_000_000
    assert mm.round_size(999_999_999_999_999, SPEC) == 0
    assert mm.on_lot(mm.round_size(7 * 10**18 + 1, SPEC), SPEC)
    with pytest.raises(mm.MMError):
        mm.round_price(10, SPEC, "hold")


# --- account reads -------------------------------------------------------------------------------------------
def test_open_orders_and_positions_reads_parse_the_published_shapes():
    def get(path):
        if path.startswith("/orders/"):
            return [{"id": 77, "client_nonce": 1791000000001, "pair_id": 2, "side": "Buy", "size": "38800000000000000",
                     "price_8dec": 8593000000000, "status": "Open", "agent": OWNER, "timestamp_ms": 1791000000002}]
        if path.startswith("/positions/"):
            return [{"id": 28, "pair_id": 11, "is_long": True, "size": "342200000000000000000", "entry_price": 94683,
                     "leverage": 3, "margin": 11119749, "unrealized_pnl": -187094, "liquidation_price": 1893}]
        raise AssertionError(path)
    c = mm.MarketMaker("https://node.invalid", KEY, OWNER, get=get, identity=lambda: LIVE)
    o = c.open_orders()[0]
    assert (o.order_id, o.side, o.size_18dec, o.price_8dec, o.status, o.client_nonce) == (77, "buy", 38_800_000_000_000_000,
                                                                                         8_593_000_000_000, "open", 1791000000001)
    p = c.positions()[0]
    assert p.size_18dec == 342_200_000_000_000_000_000 and p.is_long and p.unrealized_pnl_6dec == -187094   # exact above 2^64
    for bad in ({}, [{"id": 1}], [{"id": 1, "pair_id": 1, "side": "hold", "size": "1"}]):
        with pytest.raises(mm.MMError):
            mm.read_open_orders(bad)
    with pytest.raises(mm.MMError):
        mm.read_positions([{"id": 1, "is_long": "yes"}])
