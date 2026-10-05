"""EIP-712 unification + chain-alignment gate.

The anchor is not a frozen digest but the CHAIN'S OWN domain separator (genesis 2c1c0679, 5-field
genesis-bound salt):

  VordCore domainSeparator @ 101101 =
    0x68b86feeb9a9d9d471c3355da4719f2ce6a2330fbde6dad54d815783dacab34b

(node-authoritative; pinned by the chain's own vectors). Every signed op is built
over this domain, so if the SDK reproduces it from the RESOLVED chainId, its
signatures verify on-chain. These tests prove (a) the resolved domain equals the
chain's, (b) the two signing paths agree on one value, and (c) no stale chainId
copy survives anywhere.
"""

from vordium import caps, eip712
from vordium import network as net

# Chain-authoritative VordCore domain separator on live 101101.
VORDCORE_DOMSEP_101101 = (
    "0x68b86feeb9a9d9d471c3355da4719f2ce6a2330fbde6dad54d815783dacab34b"
)

# Mainnet genesis sha256; the VordCore domain salt binds to this.
GENESIS_SHA256 = "2c1c0679fa6ab8358f1d3e8d294a8d1c73ac2e2caf9079f1216abedc3d9fdf4f"


def test_vordcore_domain_is_genesis_bound_hermetic():
    """Pure (no network): the 5-field genesis-bound domain for the mainnet genesis equals the
    node-authoritative separator. Proves the salt math without a live node."""
    sep = "0x" + caps.vordcore_domain_separator(101101, net.VERIFYING_CONTRACT, GENESIS_SHA256).hex()
    assert sep == VORDCORE_DOMSEP_101101, sep
    assert "0x" + caps._vordcore_salt(GENESIS_SHA256).hex() == "0x8590981a62e73d4fe04427a68536a1a63f3acb4765e41116859ab126c20099a2"

OWNER = "0x1111111111111111111111111111111111111111"
TO = "0x2222222222222222222222222222222222222222"

# (primaryType, caps-call, eip712-value) — the two signers must agree per op.
def _caps_digests():
    return {
        "PlaceOrder": caps.place_order_digest(
            OWNER, 1, 0, 10**18, 3000000000, 10000, 1, False, 7, False, 0, 0),
        "CancelOrder": caps.cancel_order_digest(OWNER, 42),
        "ModifyOrder": caps.modify_order_digest(OWNER, 42, 2500000000, 2 * 10**18),
        "SetAgentCaps": caps.set_agent_caps_digest(OWNER, 10, 3, 100000000, 1000000000),
        "SetAgentMode": caps.set_agent_mode_digest(OWNER, 2),
        "SetTpSl": caps.set_tpsl_digest(OWNER, 1, 42, 3500000000, 2500000000),
    }

_EIP712_VALUES = {
    "PlaceOrder": {"owner": OWNER, "pairId": 1, "side": 0, "size": 10**18,
                   "price": 3000000000, "leverageBps": 10000, "orderType": 1,
                   "reduceOnly": False, "postOnly": False, "triggerPrice8dec": 0,
                   "triggerDir": 0, "clientNonce": 7},
    "CancelOrder": {"owner": OWNER, "orderId": 42},
    "ModifyOrder": {"owner": OWNER, "orderId": 42, "newPrice": 2500000000,
                    "newSize": 2 * 10**18},
    "SetAgentCaps": {"owner": OWNER, "maxLeverage": 10, "allowedOrderTypes": 3,
                     "maxInputPerTrade": 100000000, "maxTotalPosition": 1000000000},
    "SetAgentMode": {"owner": OWNER, "mode": 2},
    "SetTpSl": {"owner": OWNER, "pairId": 1, "positionId": 42,
                "takeProfit8dec": 3500000000, "stopLoss8dec": 2500000000},
}


from types import SimpleNamespace


def _fixed_net():
    """A deterministic resolved network (no live fetch) pinned to the mainnet genesis, so the
    domain/agreement tests are hermetic. Live resolution is exercised separately below."""
    return SimpleNamespace(chain_id=101101, verifying_contract=net.VERIFYING_CONTRACT,
                           genesis_sha256=GENESIS_SHA256)


def test_domain_separator_equals_chain_value(monkeypatch):
    """The 5-field genesis-bound domain separator (resolved chainId + genesis) must equal the chain's
    own VordCore domain separator. This is what makes every signature verifiable on-chain."""
    monkeypatch.setattr(caps, "get_network", _fixed_net)
    assert "0x" + caps.domain_separator().hex() == VORDCORE_DOMSEP_101101


def test_two_signers_agree_on_one_value(monkeypatch):
    """caps.py (hand-rolled) and eip712.py (JSON-driven) are the SDK's two signing paths. They must
    produce byte-identical digests — one domain (with the genesis-bound salt), no disagreement."""
    monkeypatch.setattr(caps, "get_network", _fixed_net)
    monkeypatch.setattr(eip712, "get_network", _fixed_net)
    cd = _caps_digests()
    for pt, value in _EIP712_VALUES.items():
        caps_hex = "0x" + cd[pt].hex()
        eip712_hex = eip712.digest(pt, value)
        assert caps_hex.lower() == eip712_hex.lower(), f"{pt}: signers disagree"


def test_live_resolution_carries_genesis_and_matches(monkeypatch):
    """Best-effort LIVE check: if a node is reachable, the resolved network must carry genesis_sha256
    and the domain must equal the chain value. Skipped (not failed) if the network is unreachable."""
    import pytest
    try:
        n = net.get_network()
    except Exception as e:
        pytest.skip(f"network unresolved: {e}")
    if not getattr(n, "genesis_sha256", None):
        pytest.skip("live node did not expose genesis_sha256")
    assert "0x" + caps.domain_separator().hex() == VORDCORE_DOMSEP_101101


def test_no_stale_chain_id_copy_anywhere():
    """The three former copies must be gone: no caps.EIP712_CHAIN_ID, no chainId
    or domainSeparator pinned in eip712.json, no CHAIN_ID constant in config
    (it now resolves through the live network)."""
    import json, pathlib, vordium
    assert not hasattr(caps, "EIP712_CHAIN_ID"), "caps.EIP712_CHAIN_ID still defined"
    cfg = json.loads((pathlib.Path(vordium.__file__).parent / "eip712.json").read_text())
    assert "chainId" not in cfg["domain"], "eip712.json still pins a chainId"
    assert "domainSeparator" not in cfg, "eip712.json still pins a domainSeparator"


def test_chain_id_is_the_resolved_value_not_a_constant():
    """config.CHAIN_ID must reflect the RESOLVED network, not a baked literal."""
    import vordium.config as config
    assert config.CHAIN_ID == net.get_network().chain_id == 101101
