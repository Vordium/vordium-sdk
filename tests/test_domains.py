"""The genesis-bound EIP-712 domains, pinned to the node-authoritative separators at the
mainnet genesis (2c1c0679), plus a best-effort LIVE byte-check against a reachable node."""
import os
import pytest
from vordium import domains

GENESIS = "2c1c0679fa6ab8358f1d3e8d294a8d1c73ac2e2caf9079f1216abedc3d9fdf4f"
CHAIN_ID = 101101
NODE_AUTHORITATIVE = {  # the chain's own values at this genesis
    "VordCore":      "0x68b86feeb9a9d9d471c3355da4719f2ce6a2330fbde6dad54d815783dacab34b",
    "VordexSession": "0x519818aadee0cf7503a73f7087eef99d936b37b242e79ee9a825942596d3ad6e",
}


def test_every_separator_matches_the_node_at_the_mainnet_genesis():
    assert domains.separators(CHAIN_ID, GENESIS) == NODE_AUTHORITATIVE


def test_domains_are_genesis_bound_not_chain_id_bound():
    other = domains.separators(CHAIN_ID, "00" * 32)
    assert all(other[k] != NODE_AUTHORITATIVE[k] for k in NODE_AUTHORITATIVE), "same chainId, other genesis ⇒ every domain moves"


def test_domain_dict_shapes():
    assert "verifyingContract" in domains.domain("VordCore", CHAIN_ID, GENESIS)
    assert "verifyingContract" in domains.domain("VordexSession", CHAIN_ID, GENESIS)
    assert domains.domain("VordCore", CHAIN_ID, GENESIS)["salt"] == domains.salt("VordCore", GENESIS)


def test_live_node_derivation_matches():
    """Best-effort LIVE check: derive the separators from a reachable node's chainId + genesis."""
    rpc = os.getenv("VORDIUM_LIVE_RPC_URL")
    if not rpc:
        pytest.skip("set VORDIUM_LIVE_RPC_URL to run the live derivation check")
    from vordium import network as net
    net.reset_network()  # drop the offline pin: resolve for real
    got = domains.verify_against_node(rpc_url=rpc)
    assert got == NODE_AUTHORITATIVE, got
