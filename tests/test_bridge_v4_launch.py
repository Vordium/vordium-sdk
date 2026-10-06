"""Bridge v4 at launch: the deployed contracts come from the network spec, and deposits are open only when the vaults read
is fresh, the deployed vault is listed and ``depositsOpen`` for the source chain is exactly true."""
import json
from dataclasses import replace
from pathlib import Path

import pytest

import vordium.bridge_v4 as b

HERE = Path(__file__).resolve().parent
F = json.loads((HERE / "vectors" / "bridge-v4-v35.json").read_text(encoding="utf-8"))
SPEC = {"bridge": {"chain": "Arbitrum One", "chainId": 42161, "address": "0x04D6f8b77A340b33d4bf04bE20dC96ec14d4A299",
                   "handler": "0x0ae6d8d70cC4B31B6D4A97e9058040f4F7E74F19", "depositsOpen": False}}
DEP = b.deployments_from_spec(SPEC)
D = DEP["42161"]
NOW = 1_000.0


@pytest.fixture(autouse=True)
def _enabled():
    was = b.ENABLED
    b.ENABLED = True
    yield
    b.ENABLED = was


def vaults(address=D["vault"], handler=D["handler"], open_=False, active=True, read_at=NOW, opens=None):
    v = b.read_vaults({
        "active": active,
        "vaults": [{"id": 1, "chain_id": 42161, "address": address, "handler": handler, "cctp_domain": 3,
                    "deposits": {"direct": {"chain_id": 42161, "minimum_6dec": "5000000"},
                                 "cctp": {"from_chain_ids": [5042], "minimum_6dec": "10000000"}},
                    "withdrawals": {"routes": [{"route_kind": 0, "name": "local", "open": True}], "fee_6dec": "1000000",
                                    "maximum_6dec": "250000000000"},
                    "runtime_sha256": {"vault": F["pins"]["vault"]["runtime"], "handler": F["pins"]["handler"]["runtime"]},
                    "binding": {"handler_vault": address, "local_domain": 3, "usdc": "0xaf88d065e77c8cC2239327C5EDb3A432268e5831",
                                "confirmed": True}}],
        "depositsOpen": opens if opens is not None else {"42161": open_, "5042": open_},
        "minimumDeposit6dec": {"42161": "5000000", "5042": "10000000"},
        "withdrawalFee6dec": "1000000", "feeQuote": None, "as_of": {"height": 7},
    })
    return replace(v, read_at=read_at) if v.ok else v


def unlisted(open_=True, read_at=NOW):
    v = b.read_vaults({"active": True, "vaults": [], "depositsOpen": {"42161": open_}, "minimumDeposit6dec": {},
                       "withdrawalFee6dec": "1000000", "feeQuote": None, "as_of": {"height": 7}})
    return replace(v, read_at=read_at)


def test_the_deployment_is_read_from_the_spec():
    assert D["vault"] == SPEC["bridge"]["address"] and D["handler"] == SPEC["bridge"]["handler"]
    assert b.create_address(D["vault"], 1) == D["handler"].lower() and D["setRules"] == b.create_address(D["vault"], 2)
    assert not hasattr(b, "DEPLOYMENTS")
    for bad in (None, {}, {"bridge": None}, {"bridge": {**SPEC["bridge"], "chainId": "42161"}},
                {"bridge": {**SPEC["bridge"], "chainId": True}}, {"bridge": {**SPEC["bridge"], "address": "0x12"}},
                {"bridge": {**SPEC["bridge"], "handler": None}},
                {"bridge": {**SPEC["bridge"], "handler": "0x" + "34" * 20}}):   # a handler the vault did not create
        assert b.deployments_from_spec(bad) is None, bad


def test_deposits_open_only_on_the_rule():
    g = lambda v, now=NOW + 10, src=42161: b.deposit_gate(v, src, DEP, now)  # noqa: E731
    assert g(vaults(open_=True)).state == "open"
    # listed + depositsOpen missing / false / true-but-stale
    assert g(vaults(opens={"5042": True})).state == "unknown"
    c = g(vaults(open_=False))
    assert c.state == "closed" and c.text == b.LINE_BRIDGE_CLOSED == "Deposits are closed for now. They will open soon."
    assert g(vaults(open_=True), now=NOW + b.BRIDGE_READ_FRESH_S + 0.5).state == "unknown"
    assert g(vaults(open_=True, read_at=None)).state == "unknown"          # not read from the network
    assert g(vaults(open_=True), now=NOW - 6).state == "unknown"           # a read from the future
    assert g(vaults(open_=True), now=NOW + b.BRIDGE_READ_FRESH_S).state == "open"
    # not listed, inactive, unreadable, no deployment read, another vault
    assert g(unlisted()).state == "closed"
    assert g(vaults(open_=True, active=False)).state == "closed"
    assert g(None).state == "unknown" and g(b.VaultsRead(ok=False, error="x")).state == "unknown"
    assert b.deposit_gate(vaults(open_=True), 42161, None, NOW).state == "unknown"
    other = "0x" + "12" * 20
    assert g(vaults(open_=True, address=other, handler=b.create_address(other, 1))).state == "closed"
    # per source chain
    assert g(vaults(opens={"42161": True, "5042": False}), src=5042).state == "closed"
    assert g(vaults(opens={"42161": False, "5042": True}), src=5042).state == "open"
    assert g(vaults(opens={"42161": True, "5042": "true"}), src=5042).state == "unknown"


def test_deposit_check_needs_depositsOpen_true():
    ok = b.deposit_check(vaults(open_=True), 42161, 5_000_000)
    assert ok.ok and ok.kind == "direct" and ok.vault == D["vault"]
    assert b.deposit_check(vaults(), 42161, 5_000_000).reason == "closed"
    assert b.deposit_check(vaults(opens={"5042": True}), 42161, 5_000_000).reason == "unknown"
    assert not b.deposit_check(vaults(open_=True), 42161, 4_999_999).ok


def test_bool_words():
    T, Z = "0x" + "0" * 63 + "1", "0x" + "0" * 64
    assert b.read_bool_word(T) is True and b.read_bool_word(Z) is False
    assert b.read_bool_word("0x01") is None and b.read_bool_word("0x" + "0" * 62 + "02") is None and b.read_bool_word(None) is None


def test_deployment_check():
    assert b.deployment_check(vaults(), DEP).ok
    other = "0x" + "12" * 20
    assert not b.deployment_check(vaults(address=other, handler=b.create_address(other, 1)), DEP).ok
    assert not b.deployment_check(vaults(handler="0x" + "34" * 20), DEP).ok
    assert not b.deployment_check(vaults(address=other), DEP).ok          # another vault naming the deployed handler
    assert not b.deployment_check(vaults(), None).ok                     # the spec could not be read
    assert b.deployment_check(vaults(), DEP).read_at == NOW


def test_the_release_ships_the_bridge_on():
    src = Path(b.__file__).read_text(encoding="utf-8")
    assert "\nENABLED = True\n" in src and "\nENABLED = False\n" not in src
    import vordium
    assert vordium.bridge_v4 is b and "bridge_v4" in vordium.__all__
