"""Offline network pin for deterministic unit tests.

Unit tests must not depend on a reachable spec/RPC. This autouse fixture injects
a fully-resolved Network for the LIVE chain (101101, VordCore verifyingContract
0x..1002) via ``set_network`` so every digest computes against the real live
domain WITHOUT a network call. Live round-trip checks live outside this
fixture."""

import pytest

from vordium import bridge_v4, mm, node_domain
from vordium import network as net


LIVE_CHAIN_ID = 101101
VERIFYING_CONTRACT = "0x0000000000000000000000000000000000001002"


def make_live_network():
    return net.Network(
        chain_id=LIVE_CHAIN_ID,
        chain_id_hex="0x18aed",
        chain_name="Vordium Chain",
        rpc_url="https://rpc.vordium.com",
        ws_url="wss://wss.vordium.com",
        explorer_url="https://vordscan.io",
        bridge_address="0x04d6f8b77a340b33d4bf04be20dc96ec14d4a299",
        bridge_chain="Arbitrum One",
        bridge_chain_id=42161,
        native_symbol="VORD",
        native_decimals=18,
        verifying_contract=VERIFYING_CONTRACT,
        source="test-pin",
        genesis_sha256="2c1c0679fa6ab8358f1d3e8d294a8d1c73ac2e2caf9079f1216abedc3d9fdf4f",
    )


@pytest.fixture(autouse=True)
def _module_state_restored():
    """Every test leaves the module switches as it found them, so no test depends on the order the suite runs in."""
    before = (bridge_v4.ENABLED, dict(bridge_v4.V34))
    yield
    after = (bridge_v4.ENABLED, dict(bridge_v4.V34))
    if after != before:
        bridge_v4.ENABLED = before[0]
        bridge_v4.V34.clear()
        bridge_v4.V34.update(before[1])
        raise AssertionError(f"the test left bridge_v4 switches changed: {before} -> {after}")


@pytest.fixture(autouse=True)
def _pin_network():
    net.set_network(make_live_network())
    yield
    net.reset_network()


@pytest.fixture(autouse=True)
def _offline_node(monkeypatch):
    """Unit tests read no node: a client's node identity is the pinned live network's (a test that needs another
    node passes ``identity=``), and every test starts with fresh per-account nonce clocks."""
    net_ = make_live_network()
    monkeypatch.setattr(node_domain, "node_identity",
                        lambda rpc_url, timeout=6.0, get_json=None: node_domain.NodeIdentity(net_.chain_id, net_.genesis_sha256))
    mm._CLOCKS.clear()
    yield
    mm._CLOCKS.clear()
