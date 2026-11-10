"""Each named network is pinned to its chain id and genesis; a network that reports anything else is never signed for.

Every read resolve_network makes comes from a fake network (spec, eth_chainId, /status). The last test reads the
public endpoints and runs only with LIVE_TESTS=1.
"""

import dataclasses
import os
import warnings

import pytest
from eth_account import Account
from eth_utils import keccak

from vordium import caps, eip712, mm, money, referral, rollb
from vordium import network as net
from vordium.node_domain import NodeIdentity
from vordium.pins import PINS, Pin

MAIN, TEST = PINS["mainnet"], PINS["testnet"]
OTHER_GENESIS = "e" * 64
KEY = "0x" + keccak(b"vordium-sdk-test-pins").hex()
OWNER = Account.from_key(KEY).address
ENV = ("VORDIUM_CHAIN_ID", "VORDIUM_RPC_URL", "VORDIUM_SPEC_URL", "VORDIUM_WS_URL", "VORDIUM_EXPLORER_URL",
       "VORDIUM_NETWORK", "VORDIUM_GENESIS_SHA256")


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    for k in ENV:
        monkeypatch.delenv(k, raising=False)
    net.reset_network()
    yield
    net.reset_network()


class FakeNetwork:
    """What the network reports: the spec, eth_chainId and the node's /status genesis. Records every read."""

    def __init__(self, monkeypatch, spec_chain_id, eth_chain_id, status_genesis, spec_genesis=None, testnet=False):
        spec = {"chainId": spec_chain_id, "rpc": "https://rpc-testnet.vordium.com" if testnet else "https://rpc.vordium.com",
                "genesisSha256": spec_genesis if spec_genesis is not None else status_genesis}
        if testnet:
            spec["testnet"] = True
        self.reads = []
        monkeypatch.setattr(net, "_fetch_spec", lambda u, t: (self.reads.append(("spec", u)), spec)[1])
        monkeypatch.setattr(net, "_eth_chain_id", lambda r, t: (self.reads.append(("eth_chainId", r)), eth_chain_id)[1])
        monkeypatch.setattr(net, "_status_genesis_sha256",
                            lambda r, t: (self.reads.append(("status", r)), status_genesis)[1])


def _resolve(**kw):
    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")
        n = net.resolve_network(**kw)
    return n, [x for x in w if issubclass(x.category, net.PinWarning)]


def _sign_cancel():
    return eip712.sign_op(KEY, "CancelOrder", {"owner": OWNER, "orderId": 7})


# --- the pins ------------------------------------------------------------------------------------------------------
def test_the_named_networks_carry_their_pins():
    assert (MAIN.chain_id, MAIN.name) == (101101, "mainnet") and (TEST.chain_id, TEST.name) == (101102, "testnet")
    assert MAIN.genesis_sha256 == "2c1c0679fa6ab8358f1d3e8d294a8d1c73ac2e2caf9079f1216abedc3d9fdf4f"
    assert TEST.genesis_sha256 == "8b5d414c5cd5d18bc468b64f87ac8e2c2b5ff494c769d5e09dcf50ce75a59792"
    assert set(PINS) == set(net.NETWORKS)                  # every named network has a pin
    # the published VordCore separator of the main network follows from its pin
    assert caps.vordcore_domain_separator(MAIN.chain_id, net.VERIFYING_CONTRACT, MAIN.genesis_sha256).hex() == \
        "68b86feeb9a9d9d471c3355da4719f2ce6a2330fbde6dad54d815783dacab34b"


def test_a_pin_refuses_malformed_values():
    for cid, g in ((0, MAIN.genesis_sha256), (True, MAIN.genesis_sha256), (101101, "12"), (101101, None)):
        with pytest.raises(ValueError):
            Pin(cid, g)
    assert Pin(5, "0X" + "AB" * 32).genesis_sha256 == "ab" * 32


# --- match: signs ----------------------------------------------------------------------------------------------------
@pytest.mark.parametrize("name,pin", [("mainnet", MAIN), ("testnet", TEST)])
def test_a_network_that_matches_its_pin_signs(monkeypatch, name, pin):
    FakeNetwork(monkeypatch, pin.chain_id, pin.chain_id, pin.genesis_sha256, testnet=name == "testnet")
    n, w = _resolve(network=name)
    assert w == [] and n.pin == pin and n.pin_problem is None
    net.set_network(n)
    assert net.signing_pin() == pin
    d = eip712.domain()
    assert d["chainId"] == pin.chain_id and d["salt"] == caps._vordcore_salt(pin.genesis_sha256)
    assert len(bytes.fromhex(_sign_cancel()[2:])) == 64


def test_the_domain_is_built_from_the_pin_not_the_read(monkeypatch):
    FakeNetwork(monkeypatch, MAIN.chain_id, MAIN.chain_id, MAIN.genesis_sha256)
    net.set_network(_resolve()[0])
    other = Pin(4242, OTHER_GENESIS)
    for mod in (eip712, caps):
        monkeypatch.setattr(mod, "signing_pin", lambda n=None: other)
    assert eip712.domain()["chainId"] == 4242 and eip712.domain()["salt"] == caps._vordcore_salt(OTHER_GENESIS)
    assert caps.domain_separator() == caps.vordcore_domain_separator(4242, net.VERIFYING_CONTRACT, OTHER_GENESIS)


# --- wrong chain id / wrong genesis / spec and node disagree: refuses -------------------------------------------------
def test_wrong_chain_id_reads_with_a_warning_and_refuses_to_sign(monkeypatch):
    FakeNetwork(monkeypatch, TEST.chain_id, TEST.chain_id, MAIN.genesis_sha256)      # "mainnet" answers chain 101102
    n, w = _resolve(network="mainnet")
    assert n.chain_id == 101102 and len(w) == 1                                     # the read works, with a warning
    net.set_network(n)
    with pytest.raises(net.PinMismatch) as e:
        _sign_cancel()
    msg = str(e.value)
    assert "mainnet" in msg and "101102" in msg and "expected 101101" in msg and "Nothing was signed" in msg
    with pytest.raises(net.PinMismatch):
        caps.domain_separator()


def test_wrong_genesis_refuses_to_sign(monkeypatch):
    FakeNetwork(monkeypatch, MAIN.chain_id, MAIN.chain_id, OTHER_GENESIS)
    n, w = _resolve()
    assert n.genesis_sha256 == OTHER_GENESIS and len(w) == 1
    net.set_network(n)
    with pytest.raises(net.PinMismatch) as e:
        _sign_cancel()
    assert OTHER_GENESIS in str(e.value) and MAIN.genesis_sha256 in str(e.value)


def test_spec_and_node_disagree_about_the_genesis_refuses(monkeypatch):
    FakeNetwork(monkeypatch, MAIN.chain_id, MAIN.chain_id, OTHER_GENESIS, spec_genesis=MAIN.genesis_sha256)
    net.set_network(_resolve()[0])
    with pytest.raises(net.PinMismatch, match="the node's /status reports genesis"):
        _sign_cancel()
    FakeNetwork(monkeypatch, MAIN.chain_id, MAIN.chain_id, MAIN.genesis_sha256, spec_genesis=OTHER_GENESIS)
    net.set_network(_resolve()[0])
    with pytest.raises(net.PinMismatch, match="the network spec reports genesis"):
        _sign_cancel()


def test_spec_and_node_disagree_about_the_chain_id_refuses(monkeypatch):
    FakeNetwork(monkeypatch, TEST.chain_id, MAIN.chain_id, MAIN.genesis_sha256)
    with pytest.raises(net.ChainIdDisagreement):
        net.resolve_network()


def test_a_node_without_a_genesis_is_not_signed_for(monkeypatch):
    FakeNetwork(monkeypatch, MAIN.chain_id, MAIN.chain_id, None, spec_genesis=MAIN.genesis_sha256)
    net.set_network(_resolve()[0])
    with pytest.raises(net.PinMismatch, match="reports no genesis"):
        _sign_cancel()


def test_an_environment_value_must_equal_the_named_pin(monkeypatch):
    FakeNetwork(monkeypatch, MAIN.chain_id, MAIN.chain_id, MAIN.genesis_sha256)
    monkeypatch.setenv("VORDIUM_GENESIS_SHA256", TEST.genesis_sha256)
    net.set_network(_resolve(network="mainnet")[0])
    with pytest.raises(net.PinMismatch, match="VORDIUM_GENESIS_SHA256"):
        _sign_cancel()


# --- an endpoint of your own -----------------------------------------------------------------------------------------
def test_a_custom_endpoint_without_a_pin_reads_but_never_signs(monkeypatch):
    f = FakeNetwork(monkeypatch, MAIN.chain_id, MAIN.chain_id, MAIN.genesis_sha256)
    n, w = _resolve(rpc_url="https://node.example")
    assert n.chain_id == 101101 and n.name is None and n.pin is None and len(w) == 1   # reads work
    assert ("spec", net.DEFAULT_SPEC_URL) not in f.reads                              # its values, not the spec's
    net.set_network(n)
    with pytest.raises(net.UnpinnedNetwork) as e:
        _sign_cancel()
    assert "https://node.example" in str(e.value) and "Nothing was signed" in str(e.value)


def test_a_custom_endpoint_that_names_its_network_signs_under_that_pin(monkeypatch):
    FakeNetwork(monkeypatch, TEST.chain_id, TEST.chain_id, TEST.genesis_sha256, testnet=True)
    n, w = _resolve(rpc_url="https://node.example/chain", network="testnet")
    assert w == [] and n.pin == TEST
    net.set_network(n)
    assert eip712.domain()["chainId"] == 101102
    # the same endpoint named as the main network: refused
    n, w = _resolve(rpc_url="https://node.example/chain", network="mainnet")
    assert len(w) == 1
    net.set_network(n)
    with pytest.raises(net.PinMismatch):
        _sign_cancel()


def test_a_custom_endpoint_with_an_explicit_pin(monkeypatch):
    own = Pin(777001, OTHER_GENESIS)
    FakeNetwork(monkeypatch, None, 777001, OTHER_GENESIS)
    n, w = _resolve(rpc_url="https://devnet.example", pin=own)
    assert w == [] and n.pin == own
    net.set_network(n)
    assert eip712.domain()["salt"] == caps._vordcore_salt(OTHER_GENESIS)
    FakeNetwork(monkeypatch, None, 777002, OTHER_GENESIS)
    net.set_network(_resolve(rpc_url="https://devnet.example", pin=own)[0])
    with pytest.raises(net.PinMismatch, match="777002"):
        _sign_cancel()
    with pytest.raises(net.NetworkResolutionError, match="not mainnet's pin"):
        net.resolve_network(rpc_url="https://devnet.example", network="mainnet", pin=own)


def test_environment_pin_both_values(monkeypatch):
    FakeNetwork(monkeypatch, None, 777001, OTHER_GENESIS)
    monkeypatch.setenv("VORDIUM_RPC_URL", "https://devnet.example")
    monkeypatch.setenv("VORDIUM_CHAIN_ID", "777001")
    net.set_network(_resolve()[0])
    with pytest.raises(net.UnpinnedNetwork):              # a chain id alone is not a pin
        _sign_cancel()
    monkeypatch.setenv("VORDIUM_GENESIS_SHA256", OTHER_GENESIS)
    net.set_network(_resolve()[0])
    assert net.signing_pin() == Pin(777001, OTHER_GENESIS)


# --- clients posting to a node: the node's /status is held to the pin -------------------------------------------------
class _Rec:
    def __init__(self):
        self.sent = []

    def __call__(self, path, body):
        self.sent.append((path, body))
        return 202, {"status": "submitted", "intaken": True, "actions": []}, None


def _mm(url, ident, network=None):
    rec = _Rec()
    return mm.MarketMaker(url, KEY, OWNER, post=rec, identity=lambda: ident, network=network), rec


def test_client_at_a_named_address_signs_under_that_networks_pin():
    c, rec = _mm("https://testnet.vordex.xyz/chain", NodeIdentity(TEST.chain_id, TEST.genesis_sha256))
    c.cancel_all(1)
    assert len(rec.sent) == 1
    c, rec = _mm("https://rpc.vordium.com", NodeIdentity(TEST.chain_id, TEST.genesis_sha256))
    with pytest.raises(net.PinMismatch) as e:
        c.cancel_all(1)
    assert "mainnet" in str(e.value) and rec.sent == []


def test_client_at_an_address_of_your_own_refuses_unless_named():
    ident = NodeIdentity(TEST.chain_id, TEST.genesis_sha256)
    c, rec = _mm("https://node.example", ident)
    with pytest.raises(net.UnpinnedNetwork):
        c.cancel_all(1)
    assert rec.sent == []
    c, rec = _mm("https://node.example", ident, network="testnet")
    c.cancel_all(1)
    assert len(rec.sent) == 1
    c, rec = _mm("https://node.example", ident, network=Pin(TEST.chain_id, OTHER_GENESIS))
    with pytest.raises(net.PinMismatch):
        c.cancel_all(1)
    assert rec.sent == []


def test_client_refuses_a_node_whose_genesis_differs_from_the_pin():
    c, rec = _mm("https://node.example", NodeIdentity(MAIN.chain_id, OTHER_GENESIS), network="mainnet")
    with pytest.raises(net.PinMismatch, match=OTHER_GENESIS):
        c.cancel_all(1)
    assert rec.sent == []


# --- EIP-191 messages (money, referral) -------------------------------------------------------------------------------
def _phase(genesis):
    return rollb.SigningPhase("genesis-bound", H=1, head=2, genesis=genesis)


def _use(monkeypatch, pin):
    FakeNetwork(monkeypatch, pin.chain_id, pin.chain_id, pin.genesis_sha256, testnet=pin is TEST)
    net.set_network(_resolve(network=pin.name)[0])


def test_money_message_must_carry_the_pinned_chain_and_genesis(monkeypatch):
    _use(monkeypatch, MAIN)
    args = {"owner": OWNER, "nonce": 1}
    body = money.sign_money_op(KEY, "Unstake", args, MAIN.chain_id, _phase(MAIN.genesis_sha256))
    assert body["signature"].startswith("0x")
    with pytest.raises(net.PinMismatch, match="chain 101102"):
        money.sign_money_op(KEY, "Unstake", args, TEST.chain_id, _phase(MAIN.genesis_sha256))
    with pytest.raises(net.PinMismatch, match="genesis"):
        money.sign_money_op(KEY, "Unstake", args, MAIN.chain_id, _phase(OTHER_GENESIS))
    moved = dataclasses.replace(net.get_network(), chain_id=TEST.chain_id)        # held to mainnet, reports 101102
    with pytest.raises(net.PinMismatch):
        money.sign_money_op(KEY, "Unstake", args, MAIN.chain_id, _phase(MAIN.genesis_sha256), network=moved)


def test_referral_message_must_carry_the_pinned_chain_and_genesis(monkeypatch):
    _use(monkeypatch, TEST)
    ok = referral.claim_earnings_message(TEST.chain_id, OWNER, 1, _phase(TEST.genesis_sha256))
    assert len(referral.sign_referral_message(KEY, ok)) == 130
    for bad in (referral.claim_earnings_message(MAIN.chain_id, OWNER, 1, _phase(TEST.genesis_sha256)),
                referral.claim_earnings_message(TEST.chain_id, OWNER, 1, _phase(MAIN.genesis_sha256))):
        with pytest.raises(net.PinMismatch):
            referral.sign_referral_message(KEY, bad)


# --- raw transfer -----------------------------------------------------------------------------------------------------
def test_raw_transfer_refuses_a_node_on_another_chain(monkeypatch):
    from vordium.agent import Agent
    _use(monkeypatch, MAIN)
    a = Agent(KEY)
    sent = []

    class Eth:
        chain_id, gas_price = TEST.chain_id, 1

        def send_raw_transaction(self, raw):
            sent.append(raw)
            return bytes(32)

    class W3:
        eth = Eth()

    a._w3 = W3()
    with pytest.raises(net.PinMismatch, match="eth_chainId"):
        a.send("0x" + "22" * 20, 0.5)
    assert sent == []


# --- the pins equal the live networks (reads the public endpoints) -----------------------------------------------------
LIVE = {"mainnet": ("https://rpc.vordium.com", "https://rpc.vordium.com/status", "https://rpc.vordium.com/network-spec.json"),
        "testnet": ("https://rpc-testnet.vordium.com", "https://testnet.vordex.xyz/chain/status",
                    "https://testnet.vordex.xyz/network-spec.json")}


@pytest.mark.skipif(os.getenv("LIVE_TESTS") != "1", reason="set LIVE_TESTS=1 to read the public networks")
@pytest.mark.parametrize("name", sorted(LIVE))
def test_the_pins_equal_the_live_networks(name):
    from vordium import _http
    rpc, status, spec = LIVE[name]
    eth = int(_http.post(rpc, json={"jsonrpc": "2.0", "id": 1, "method": "eth_chainId", "params": []},
                         timeout=15).json()["result"], 16)
    st = _http.get(status, timeout=15).json()
    sp = _http.get(spec, timeout=15).json()
    pin = PINS[name]
    assert eth == st["chain_id"] == sp["chainId"] == pin.chain_id
    assert st["genesis_sha256"].lower() == sp["genesisSha256"].lower() == pin.genesis_sha256


def test_a_named_networks_own_address_names_it(monkeypatch):
    FakeNetwork(monkeypatch, MAIN.chain_id, MAIN.chain_id, MAIN.genesis_sha256)
    n, w = _resolve(rpc_url="https://rpc.vordium.com/")
    assert w == [] and n.pin == MAIN


def test_the_operator_refuses_when_the_configured_network_changed(monkeypatch):
    from vordium import node_domain
    from vordium import operator as opm
    _use(monkeypatch, MAIN)
    monkeypatch.setattr(node_domain, "node_identity",
                        lambda rpc_url, timeout=6.0, get_json=None: NodeIdentity(MAIN.chain_id, MAIN.genesis_sha256))
    session = Account.create()
    op = opm.Operator(owner=OWNER, signer=opm.SessionSigner(private_key=session.key.hex()), submit_url="https://rpc.vordium.com")
    op._checked_signer()
    _use(monkeypatch, TEST)
    with pytest.raises(net.PinMismatch, match="changed"):
        op._checked_signer()
