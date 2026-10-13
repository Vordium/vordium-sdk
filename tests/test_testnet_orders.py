"""A real signed limit order on a TEST chain: it must rest on the book at the signed price as a limit order, and its cancel
must take it off.

Runs only when a test chain is named (it never runs against the live network):
  VORDIUM_TESTNET_RPC            the test chain's read service (base URL)
  VORDIUM_TESTNET_SPEC           its network-spec.json URL
  VORDIUM_TESTNET_OWNER_KEY      file holding the funded test account's 0x key (0600)
  VORDIUM_TESTNET_SESSION_KEY    file holding a session key registered for that account (0600)
The chain id comes from the test spec and must equal the node's eth_chainId; the genesis comes from the node's /status and
must equal the spec's. The live chain's id is refused.
"""
import os
import stat
import time

import pytest
import requests
from eth_account import Account

from vordium import dex
from vordium import network as net

LIVE_CHAIN_ID = 101101
ENV = ("VORDIUM_TESTNET_RPC", "VORDIUM_TESTNET_SPEC", "VORDIUM_TESTNET_OWNER_KEY", "VORDIUM_TESTNET_SESSION_KEY")


def _key(path):
    if stat.S_IMODE(os.stat(path).st_mode) & 0o077:
        raise AssertionError(f"{path} must be 0600")
    k = open(path).read().strip()
    assert k.startswith("0x") and len(k) == 66
    return k


def _pin():
    rpc = os.environ["VORDIUM_TESTNET_RPC"].rstrip("/")
    spec = requests.get(os.environ["VORDIUM_TESTNET_SPEC"], timeout=10).json()
    cid = spec.get("chainId")
    assert isinstance(cid, int) and cid > 0 and cid != LIVE_CHAIN_ID, f"not a test chain: {cid!r}"
    rpc_cid = int(requests.post(f"{rpc}/rpc", json={"jsonrpc": "2.0", "id": 1, "method": "eth_chainId", "params": []},
                                timeout=10).json()["result"], 16)
    assert rpc_cid == cid, f"spec chain {cid} != node chain {rpc_cid}"
    genesis = requests.get(f"{rpc}/status", timeout=10).json().get("genesis_sha256")
    assert genesis and spec.get("genesisSha256") in (None, genesis), "spec and node name different genesis files"
    net.set_network(net.Network(chain_id=cid, chain_id_hex=hex(cid), chain_name="test", rpc_url=rpc, ws_url=None,
                                explorer_url=None, bridge_address=None, bridge_chain=None, bridge_chain_id=None,
                                native_symbol="VORD", native_decimals=18, verifying_contract=net.VERIFYING_CONTRACT,
                                source="test chain", genesis_sha256=genesis))
    return rpc


def _mine(orders, nonce):
    return [o for o in (orders if isinstance(orders, list) else []) if int(o.get("client_nonce", -1)) == nonce]


def test_a_signed_limit_bid_rests_on_the_book_and_cancels():
    if not all(os.environ.get(k) for k in ENV):
        pytest.skip("no test chain named")
    rpc = _pin()
    owner = Account.from_key(_key(os.environ["VORDIUM_TESTNET_OWNER_KEY"])).address
    skey = _key(os.environ["VORDIUM_TESTNET_SESSION_KEY"])
    valid = requests.get(f"{rpc}/session/valid", params={"owner": owner, "session_key": Account.from_key(skey).address},
                         timeout=10).json()
    assert valid.get("valid") and valid.get("confirmed", True), "register the session key first"
    pairs = requests.get(f"{rpc}/api/pairs/perps", timeout=10).json()["pairs"]
    pair = next(p for p in pairs if p.get("active") and not p.get("paused"))
    pid = int(pair["pair_id"])
    mark = float(requests.get(f"{rpc}/oracle/{pid}", timeout=10).json()["mark_price"]) / 10 ** dex.ORACLE_DECIMALS
    price = round(mark * 0.8, 6)                       # far below the mark: the bid rests, never fills
    size = round(15 / price, 6)
    vx = dex.Vordex(rpc_url=rpc)
    nonce = int(time.time() * 1000)
    ans = vx.place_order(skey, owner, pid, dex.BUY, size, price, order_type=dex.LIMIT, client_nonce=nonce)
    assert ans.get("status_code") in (200, 202) and ans.get("success") is not False, ans
    resting = []
    for _ in range(30):
        resting = _mine(requests.get(f"{rpc}/orders/{owner}", timeout=10).json(), nonce)
        if resting:
            break
        time.sleep(1)
    assert resting, "the order was accepted but never rested"
    assert resting[0].get("order_type") == "Limit", f"rested as {resting[0].get('order_type')!r}, not a limit order"
    assert int(resting[0]["price_8dec"]) == dex.limit_price_8dec(price), "rested at a price other than the signed one"
    # The committed order list is the truth for "rested"; the order book read is a separate view (on the test chain it
    # did not list committed orders — reported), so it is not what this test checks.
    oid = int(resting[0].get("order_id", resting[0].get("id")))
    c = vx.cancel_order(skey, owner, oid)
    assert c.get("status_code") in (200, 202) and c.get("success") is not False, c
    for _ in range(30):
        if not _mine(requests.get(f"{rpc}/orders/{owner}", timeout=10).json(), nonce):
            break
        time.sleep(1)
    else:
        raise AssertionError("the cancel was accepted but the order is still resting")
