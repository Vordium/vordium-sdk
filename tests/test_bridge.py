"""The deposit bridge is an allow-list of one: the address the live network spec names at the moment of the call.

Anything else is refused, and so is every address when the spec cannot be read. A caller that reads
config.ARBITRUM_BRIDGE, or checks an address with require_current_bridge(), is about to send funds to it.
"""
import pytest

from vordium import config
from vordium import network as net

CURRENT = "0x04d6f8b77a340b33d4bf04be20dc96ec14d4a299"


def _spec(bridge):
    return {"chainId": 101101, "rpc": "https://rpc.vordium.com", "bridge": {"address": bridge, "chain": "Arbitrum One", "chainId": 42161}}


def _others():
    """Addresses that are not CURRENT: arbitrary ones and near-misses of it (one nibble, one byte)."""
    near = [CURRENT[:-1] + ("0" if CURRENT[-1] != "0" else "1"), "0x" + CURRENT[4:] + CURRENT[2:4],
            CURRENT[:10] + ("f" if CURRENT[10] != "f" else "e") + CURRENT[11:]]
    return ["0x" + "11" * 20, "0x" + "00" * 20, "0x" + "ab" * 20] + near


@pytest.fixture(autouse=True)
def _offline(monkeypatch):
    for k in ("VORDIUM_CHAIN_ID", "VORDIUM_RPC_URL", "VORDIUM_SPEC_URL", "VORDIUM_BRIDGE_ADDRESS"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setattr(net, "_eth_chain_id", lambda r, t: 101101)
    monkeypatch.setattr(net, "_status_genesis_sha256", lambda r, t: None)
    net.reset_network()
    yield
    net.reset_network()


def test_current_bridge_is_accepted(monkeypatch):
    monkeypatch.setattr(net, "_fetch_spec", lambda u, t: _spec(CURRENT))
    assert config.ARBITRUM_BRIDGE == CURRENT
    assert net.current_bridge() == CURRENT
    # the same address in any letter case is the same address
    assert config.require_current_bridge(CURRENT.upper().replace("0X", "0x")) == CURRENT


def test_any_other_address_is_refused(monkeypatch):
    monkeypatch.setattr(net, "_fetch_spec", lambda u, t: _spec(CURRENT))
    for other in _others():
        assert other.lower() != CURRENT
        with pytest.raises(net.BridgeRefused):
            config.require_current_bridge(other)


def test_not_an_address_is_refused(monkeypatch):
    monkeypatch.setattr(net, "_fetch_spec", lambda u, t: _spec(CURRENT))
    for bad in ("", "0x", CURRENT[:-2], CURRENT + "00", CURRENT[2:], "0x" + "zz" * 20, None):
        with pytest.raises(net.BridgeRefused):
            config.require_current_bridge(bad)


def test_spec_unreachable_refuses_everything(monkeypatch):
    monkeypatch.setattr(net, "_fetch_spec", lambda u, t: None)
    with pytest.raises(net.BridgeRefused):
        config.ARBITRUM_BRIDGE
    with pytest.raises(net.BridgeRefused):
        net.current_bridge()
    for addr in [CURRENT] + _others():   # the current address too: it cannot be confirmed
        with pytest.raises(net.BridgeRefused):
            config.require_current_bridge(addr)


def test_spec_without_a_valid_bridge_refuses(monkeypatch):
    for published in (None, "", "0x1234", "not-an-address", 42):
        monkeypatch.setattr(net, "_fetch_spec", lambda u, t, p=published: _spec(p))
        with pytest.raises(net.BridgeRefused):
            config.ARBITRUM_BRIDGE
        with pytest.raises(net.BridgeRefused):
            config.require_current_bridge(CURRENT)


def test_read_live_on_every_call_never_cached(monkeypatch):
    """A cached answer could outlive a change of bridge; each call reads the spec again."""
    reads = []
    monkeypatch.setattr(net, "_fetch_spec", lambda u, t: reads.append(u) or _spec(CURRENT))
    config.ARBITRUM_BRIDGE
    config.require_current_bridge(CURRENT)
    assert len(reads) == 2
    moved = "0x" + "cd" * 20
    monkeypatch.setattr(net, "_fetch_spec", lambda u, t: _spec(moved))
    assert config.ARBITRUM_BRIDGE == moved
    with pytest.raises(net.BridgeRefused):
        config.require_current_bridge(CURRENT)


def test_environment_cannot_supply_a_bridge(monkeypatch):
    monkeypatch.setenv("VORDIUM_RPC_URL", "https://rpc.vordium.com")
    monkeypatch.setenv("VORDIUM_BRIDGE_ADDRESS", "0x" + "11" * 20)
    n = net.resolve_network()
    assert n.bridge_address is None
    monkeypatch.setattr(net, "_fetch_spec", lambda u, t: None)
    with pytest.raises(net.BridgeRefused):
        config.require_current_bridge("0x" + "11" * 20)


def test_no_address_list_ships():
    """The one address the spec names is the whole rule: no module holds a collection of addresses to compare with."""
    import importlib
    import pkgutil
    import vordium
    for info in pkgutil.iter_modules(vordium.__path__):
        mod = importlib.import_module(f"vordium.{info.name}")
        for name, value in vars(mod).items():
            if isinstance(value, (set, frozenset, list, tuple)):
                assert not any(net._address(v) for v in value if isinstance(v, str)), (mod.__name__, name)
