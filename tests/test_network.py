"""Resolution + the signing-chainId AGREEMENT check.

Transport comes from the spec (a bad value fails harmlessly). The signing
chainId is resolved by AGREEMENT across every available source; any
disagreement is a hard failure — never pick one, never prefer the spec, never
fall back to a constant.
"""

import pytest

from vordium import network as net


@pytest.fixture(autouse=True)
def _reset(monkeypatch):
    # Neutralise any ambient env so tests are deterministic.
    for k in ("VORDIUM_CHAIN_ID", "VORDIUM_RPC_URL", "VORDIUM_SPEC_URL",
              "VORDIUM_WS_URL", "VORDIUM_EXPLORER_URL", "VORDIUM_NETWORK"):
        monkeypatch.delenv(k, raising=False)
    net.reset_network()
    yield
    net.reset_network()


def _spec(chain_id=101101):
    return {
        "chainId": chain_id, "rpc": "https://rpc.vordium.com",
        "ws": "wss://wss.vordium.com", "explorer": "https://vordscan.io",
        "bridge": {"address": "0x04d6f8b77a340b33d4bf04be20dc96ec14d4a299",
                   "chain": "Arbitrum One", "chainId": 42161},
        "nativeCurrency": {"symbol": "VORD", "decimals": 18},
    }


# --- agreement (the happy path is agreement, not a single trusted source) ---
def test_spec_and_ethchainid_agree(monkeypatch):
    monkeypatch.setattr(net, "_fetch_spec", lambda u, t: _spec(101101))
    monkeypatch.setattr(net, "_eth_chain_id", lambda r, t: 101101)
    n = net.resolve_network()
    assert n.chain_id == 101101
    assert n.chain_id_sources == {"eth_chainId": 101101, "spec": 101101}
    # transport still from the spec
    assert n.bridge_address == "0x04d6f8b77a340b33d4bf04be20dc96ec14d4a299"


def test_spec_lies_but_ethchainid_disagrees_HARD_FAIL(monkeypatch):
    """A malicious/stale spec says 999; the RPC we actually send to says 101101.
    This MUST refuse to sign, not silently prefer either."""
    monkeypatch.setattr(net, "_fetch_spec", lambda u, t: _spec(999))
    monkeypatch.setattr(net, "_eth_chain_id", lambda r, t: 101101)
    with pytest.raises(net.ChainIdDisagreement) as ei:
        net.resolve_network()
    msg = str(ei.value)
    assert "spec=999" in msg and "eth_chainId=101101" in msg


def test_pin_disagrees_HARD_FAIL(monkeypatch):
    """A user pin that disagrees with the live sources is a hard failure — the
    pin is a source that must AGREE, not an override that skips the check."""
    monkeypatch.setattr(net, "_fetch_spec", lambda u, t: _spec(101101))
    monkeypatch.setattr(net, "_eth_chain_id", lambda r, t: 101101)
    monkeypatch.setenv("VORDIUM_CHAIN_ID", "777")
    monkeypatch.setenv("VORDIUM_RPC_URL", "https://rpc.vordium.com")
    with pytest.raises(net.ChainIdDisagreement) as ei:
        net.resolve_network()
    assert "pinned(VORDIUM_CHAIN_ID)=777" in str(ei.value)


def test_pin_agrees_is_honoured_as_a_source(monkeypatch):
    monkeypatch.setattr(net, "_eth_chain_id", lambda r, t: 101101)
    monkeypatch.setenv("VORDIUM_CHAIN_ID", "101101")
    monkeypatch.setenv("VORDIUM_RPC_URL", "https://rpc.vordium.com")
    n = net.resolve_network()
    assert n.chain_id == 101101
    assert n.chain_id_sources["pinned(VORDIUM_CHAIN_ID)"] == 101101
    assert n.chain_id_sources["eth_chainId"] == 101101


def test_spec_down_falls_back_to_ethchainid(monkeypatch):
    monkeypatch.setattr(net, "_fetch_spec", lambda u, t: None)
    monkeypatch.setattr(net, "_eth_chain_id", lambda r, t: 101101)
    n = net.resolve_network()
    assert n.chain_id == 101101
    assert n.source == "spec-unreachable"
    assert set(n.chain_id_sources) == {"eth_chainId"}


def test_nothing_available_RAISES_not_a_constant(monkeypatch):
    monkeypatch.setattr(net, "_fetch_spec", lambda u, t: None)
    monkeypatch.setattr(net, "_eth_chain_id", lambda r, t: None)
    with pytest.raises(net.NetworkResolutionError):
        net.resolve_network()


def test_chain_id_env_without_rpc_is_incoherent(monkeypatch):
    monkeypatch.setenv("VORDIUM_CHAIN_ID", "424242")
    with pytest.raises(net.NetworkResolutionError, match="whole network identity"):
        net.resolve_network()


def test_env_override_still_cross_checks_ethchainid(monkeypatch):
    """A coherent env override (pin + rpc) is not a bypass — eth_chainId of the
    pinned RPC must still agree with the pin."""
    monkeypatch.setenv("VORDIUM_CHAIN_ID", "424242")
    monkeypatch.setenv("VORDIUM_RPC_URL", "https://custom.example/rpc")
    monkeypatch.setattr(net, "_eth_chain_id", lambda r, t: 999999)  # node disagrees
    with pytest.raises(net.ChainIdDisagreement):
        net.resolve_network()
