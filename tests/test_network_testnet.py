"""Named networks: the test network's addresses, the main network unchanged, an address you pass still wins.

The test network serves JSON-RPC on its own host and its REST routes (/status, orders, reads) under its API base; the
main network serves both on one host. No network call is made: every read is replaced and recorded.
"""

import pytest

from vordium import network as net
from vordium import rollb

TESTNET_RPC = "https://rpc-testnet.vordium.com"
TESTNET_API = "https://testnet.vordex.xyz/chain"
TESTNET_SPEC = "https://testnet.vordex.xyz/network-spec.json"
GENESIS = "3263e89e7cd024467a58c352a4d4446f30020093ed979d6e318196c7007d2482"
OTHER = "2c1c0679fa6ab8358f1d3e8d294a8d1c73ac2e2caf9079f1216abedc3d9fdf4f"


@pytest.fixture(autouse=True)
def _reset(monkeypatch):
    for k in ("VORDIUM_CHAIN_ID", "VORDIUM_RPC_URL", "VORDIUM_SPEC_URL", "VORDIUM_WS_URL", "VORDIUM_EXPLORER_URL",
              "VORDIUM_NETWORK", "VORDIUM_GENESIS_SHA256"):
        monkeypatch.delenv(k, raising=False)
    net.reset_network()
    yield
    net.reset_network()


def _testnet_spec(**over):
    s = {"testnet": True, "chainId": 101102, "rpc": TESTNET_RPC, "evmRpc": TESTNET_RPC + "/evmrpc",
         "genesisSha256": GENESIS, "bridge": {"address": "0x" + "ab" * 20, "chain": "Arbitrum Sepolia", "chainId": 421614}}
    s.update(over)
    return s


def _mainnet_spec():
    return {"chainId": 101101, "rpc": "https://rpc.vordium.com", "ws": "wss://rpc.vordium.com/ws",
            "bridge": {"address": "0x04d6f8b77a340b33d4bf04be20dc96ec14d4a299", "chain": "Arbitrum One", "chainId": 42161}}


class Reads:
    """Replaces the three reads resolve_network makes and records where each went."""

    def __init__(self, monkeypatch, spec, chain_id, genesis=GENESIS):
        self.spec_urls, self.rpc_urls, self.status_urls = [], [], []
        monkeypatch.setattr(net, "_fetch_spec", lambda u, t: (self.spec_urls.append(u), spec)[1])
        monkeypatch.setattr(net, "_eth_chain_id", lambda r, t: (self.rpc_urls.append(r), chain_id)[1])
        monkeypatch.setattr(net, "_status_genesis_sha256", lambda r, t: (self.status_urls.append(r), genesis)[1])


# --- the test network's defaults --------------------------------------------------------------------------------
def test_testnet_default_rpc_is_rpc_testnet(monkeypatch):
    r = Reads(monkeypatch, _testnet_spec(), 101102)
    n = net.resolve_network(network="testnet")
    assert n.rpc_url == TESTNET_RPC and n.chain_id == 101102 and n.name == "testnet"
    assert r.rpc_urls == [TESTNET_RPC]                     # eth_chainId asked of rpc-testnet.vordium.com
    assert r.spec_urls == [TESTNET_SPEC]                   # the test network's own spec
    assert r.status_urls == [TESTNET_API]                  # genesis from the REST base, not the JSON-RPC host
    assert net.api_base(n) == TESTNET_API
    assert n.genesis_sha256 == GENESIS
    assert n.chain_id_sources == {"eth_chainId": 101102, "spec": 101102}


def test_testnet_rpc_default_when_the_spec_names_none(monkeypatch):
    Reads(monkeypatch, _testnet_spec(rpc=None), 101102)
    assert net.resolve_network(network="testnet").rpc_url == TESTNET_RPC


def test_testnet_rpc_default_when_the_spec_is_unreachable(monkeypatch):
    r = Reads(monkeypatch, None, 101102)
    n = net.resolve_network(network="testnet")
    assert n.rpc_url == TESTNET_RPC and r.rpc_urls == [TESTNET_RPC] and n.source == "spec-unreachable"
    assert n.chain_name == "Vordium Testnet"


def test_testnet_selected_by_the_environment(monkeypatch):
    Reads(monkeypatch, _testnet_spec(), 101102)
    monkeypatch.setenv("VORDIUM_NETWORK", "testnet")
    n = net.get_network()
    assert n.rpc_url == TESTNET_RPC and n.name == "testnet"


def test_testnet_preset_names_rpc_testnet():
    assert net.NETWORKS["testnet"]["rpc"] == TESTNET_RPC
    assert net.NETWORKS["testnet"]["api"] == TESTNET_API
    assert net.NETWORKS["mainnet"]["rpc"] == "https://rpc.vordium.com"


# --- refusals ----------------------------------------------------------------------------------------------------
def test_testnet_refuses_a_spec_that_is_not_a_test_network(monkeypatch):
    Reads(monkeypatch, _mainnet_spec(), 101101)
    with pytest.raises(net.NetworkResolutionError, match="does not describe a test network"):
        net.resolve_network(network="testnet")


def test_testnet_refuses_when_spec_and_node_name_different_genesis(monkeypatch):
    Reads(monkeypatch, _testnet_spec(), 101102, genesis=OTHER)
    with pytest.raises(net.NetworkResolutionError, match="genesis"):
        net.resolve_network(network="testnet")


def test_testnet_chain_id_still_by_agreement(monkeypatch):
    Reads(monkeypatch, _testnet_spec(), 101101)            # the JSON-RPC host answers another chain
    with pytest.raises(net.ChainIdDisagreement):
        net.resolve_network(network="testnet")


def test_unknown_network_name_refused(monkeypatch):
    Reads(monkeypatch, _testnet_spec(), 101102)
    with pytest.raises(net.NetworkResolutionError, match="unknown network"):
        net.resolve_network(network="devnet")


def test_a_pin_with_a_named_network_must_agree(monkeypatch):
    Reads(monkeypatch, _testnet_spec(), 101102)
    monkeypatch.setenv("VORDIUM_CHAIN_ID", "101102")
    assert net.resolve_network(network="testnet").chain_id_sources["pinned(VORDIUM_CHAIN_ID)"] == 101102
    monkeypatch.setenv("VORDIUM_CHAIN_ID", "101101")
    with pytest.raises(net.ChainIdDisagreement):
        net.resolve_network(network="testnet")


# --- the main network is unchanged --------------------------------------------------------------------------------
def test_mainnet_default_unchanged(monkeypatch):
    r = Reads(monkeypatch, _mainnet_spec(), 101101, genesis=OTHER)
    n = net.resolve_network()
    assert n.rpc_url == "https://rpc.vordium.com" and n.name == "mainnet" and n.api_url is None
    assert net.api_base(n) == "https://rpc.vordium.com"
    assert r.spec_urls == [net.DEFAULT_SPEC_URL] and r.rpc_urls == ["https://rpc.vordium.com"]
    assert r.status_urls == ["https://rpc.vordium.com"]
    assert net.releases_url(n) == "https://rpc.vordium.com/releases.json"


def test_mainnet_by_name_equals_the_default(monkeypatch):
    Reads(monkeypatch, _mainnet_spec(), 101101, genesis=OTHER)
    a, b = net.resolve_network(), net.resolve_network(network="mainnet")
    assert a == b


# --- an address you pass still wins --------------------------------------------------------------------------------
def test_explicit_rpc_url_wins_over_the_testnet_default(monkeypatch):
    r = Reads(monkeypatch, _testnet_spec(), 101102)
    n = net.resolve_network(rpc_url="https://node.example/chain", network="testnet")
    assert n.rpc_url == "https://node.example/chain" and n.api_url is None
    assert net.api_base(n) == "https://node.example/chain"   # used for REST too, as before
    assert r.rpc_urls == ["https://node.example/chain"] and r.status_urls == ["https://node.example/chain"]
    assert r.spec_urls == []                                 # transport from your settings, not a spec


def test_environment_rpc_url_wins_over_the_testnet_default(monkeypatch):
    Reads(monkeypatch, _testnet_spec(), 101102)
    monkeypatch.setenv("VORDIUM_NETWORK", "testnet")
    monkeypatch.setenv("VORDIUM_RPC_URL", "https://node.example/chain")
    assert net.resolve_network().rpc_url == "https://node.example/chain"


def test_use_network_with_an_explicit_address(monkeypatch):
    Reads(monkeypatch, _testnet_spec(), 101102)
    n = net.use_network("testnet", rpc_url="https://node.example/chain")
    assert net.explicit_network() is n and n.rpc_url == "https://node.example/chain"


# --- clients follow the configured network --------------------------------------------------------------------------
def test_clients_use_the_testnet_rest_base(monkeypatch):
    Reads(monkeypatch, _testnet_spec(), 101102)
    n = net.use_network("testnet")
    from vordium.dex import Vordex
    from vordium.operator import AgentBox
    assert Vordex().rpc_url == TESTNET_API                   # REST routes on the API base
    box = AgentBox()
    assert box.rpc_url == TESTNET_RPC and box.rest_url == TESTNET_API
    assert Vordex(rpc_url="https://node.example").rpc_url == "https://node.example"
    assert net.default_spec_url() == TESTNET_SPEC
    assert net.releases_url(n) == "https://testnet.vordex.xyz/releases.json"
    assert net.releases_url(n, "https://node.example/") == "https://node.example/releases.json"


def test_signing_phase_reads_the_testnet_release_list(monkeypatch):
    Reads(monkeypatch, _testnet_spec(), 101102)
    net.use_network("testnet")
    asked = []
    monkeypatch.setattr(rollb, "_get_json", lambda u, t: (asked.append(u), None)[1])
    rollb.read_signing_phase()
    assert asked == ["https://testnet.vordex.xyz/releases.json", TESTNET_SPEC, TESTNET_API + "/status"]


def test_bridge_reads_the_configured_networks_spec(monkeypatch):
    Reads(monkeypatch, _testnet_spec(), 101102)
    net.use_network("testnet")
    seen = []
    monkeypatch.setattr(net, "_fetch_spec", lambda u, t: (seen.append(u), _testnet_spec())[1])
    assert net.current_bridge() == "0x" + "ab" * 20 and seen == [TESTNET_SPEC]
