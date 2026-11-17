"""A spec named only by VORDIUM_SPEC_URL never names the deposit bridge on its own."""
import pytest

from vordium import bridge_v4 as b
from vordium import network as N

ATTACKER = "0x" + "ab" * 20
HANDLER = b.create_address(ATTACKER, 1)
SPEC = {"chainId": 101101, "bridge": {"chain": "Arbitrum One", "chainId": 42161, "address": ATTACKER, "handler": HANDLER}}


@pytest.fixture
def env_spec(monkeypatch):
    monkeypatch.setenv("VORDIUM_SPEC_URL", "https://spec.example.invalid/network-spec.json")
    monkeypatch.setattr(N, "_fetch_spec", lambda url, timeout: SPEC)


def test_env_spec_does_not_name_the_bridge(env_spec):
    with pytest.raises(N.BridgeRefused):
        N.current_bridge()
    with pytest.raises(N.BridgeRefused):
        b.fetch_deployments()


def test_env_spec_with_the_expected_bridge_must_match(env_spec):
    assert N.current_bridge(expected_bridge=ATTACKER) == ATTACKER
    assert b.fetch_deployments(expected_bridge=ATTACKER)
    other = "0x" + "cd" * 20
    with pytest.raises(N.BridgeRefused):
        N.current_bridge(expected_bridge=other)
    with pytest.raises(N.BridgeRefused):
        b.fetch_deployments(expected_bridge=other)


def test_an_explicit_spec_url_is_the_callers_choice(monkeypatch):
    monkeypatch.delenv("VORDIUM_SPEC_URL", raising=False)
    monkeypatch.setattr(N, "_fetch_spec", lambda url, timeout: SPEC)
    assert N.current_bridge(spec_url="https://spec.example.invalid/x.json") == ATTACKER


def test_prepare_arc_deposit_refuses_under_an_env_spec(env_spec):
    out = b.prepare_arc_deposit("0x" + "11" * 20, 5_000_000, arc_rpc_url="http://127.0.0.1:9")
    assert out["ok"] is False and "VORDIUM_SPEC_URL" in out["text"]


def test_the_expected_bridge_must_carry_its_checksum(env_spec):
    good = "0x52908400098527886E0F7030069857D2E4169EE7"
    bad = "0x52908400098527886E0F7030069857D2E4169Ee7"
    with pytest.raises(N.BridgeRefused):
        N.current_bridge(expected_bridge=bad)
    with pytest.raises(N.BridgeRefused):                   # the right checksum, but not the address the spec names
        N.current_bridge(expected_bridge=good)
