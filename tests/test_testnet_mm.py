"""The market-maker API on a TEST chain, end to end: orders placed in one signed batch rest on the book, a modify replaces
one with a new order id, a cancel by client nonce and a cancel-all take them off, Market Maker Protection is set, read back
and switched off, and the order feed shows the change with an unbroken sequence.

Runs only when a test chain is named (never against the live network):
  VORDIUM_TESTNET_RPC        the test chain's read service base URL (its /status names the chain id and genesis)
  VORDIUM_TESTNET_OWNER_KEY  file holding a funded test account's 0x key (0600)
  VORDIUM_TESTNET_FEEDS      (optional) the feeds URL, e.g. wss://…/feeds
"""
import os
import stat
import threading
import time

import pytest
import requests
from eth_account import Account

from vordium import caps, feeds, mm

LIVE_CHAIN_ID = 101101
HEADERS = {"User-Agent": "vordium-sdk-tests"}
NEEDED = ("VORDIUM_TESTNET_RPC", "VORDIUM_TESTNET_OWNER_KEY")


def _key(path):
    if stat.S_IMODE(os.stat(path).st_mode) & 0o077:
        raise AssertionError(f"{path} must be 0600")
    return open(path).read().strip()


def _client():
    rpc = os.environ["VORDIUM_TESTNET_RPC"].rstrip("/")
    st = requests.get(f"{rpc}/status", headers=HEADERS, timeout=10).json()
    cid = int(st["chain_id"])
    assert cid != LIVE_CHAIN_ID, "the live chain is never a test chain"
    sep = caps.vordcore_domain_separator(cid, "0x0000000000000000000000000000000000001002", st["genesis_sha256"])
    key = _key(os.environ["VORDIUM_TESTNET_OWNER_KEY"])
    owner = Account.from_key(key).address

    def post(path, body):
        r = requests.post(rpc + path, json=body, headers=HEADERS, timeout=15)
        try:
            j = r.json()
        except ValueError:
            j = {}
        return r.status_code, j, r.headers.get("Retry-After")

    def get(path):
        r = requests.get(rpc + path, headers=HEADERS, timeout=15)
        r.raise_for_status()
        return r.json()

    return mm.MarketMaker(rpc, key, owner, domain_separator=sep, post=post, get=get), get, owner


def _wait(fn, pred, n=30):
    for _ in range(n):
        v = fn()
        if pred(v):
            return v
        time.sleep(1.5)
    return fn()


def test_batch_modify_cancels_and_mmp_on_a_test_chain():
    if any(not os.getenv(k) for k in NEEDED):
        pytest.skip("no test chain named")
    c, get, owner = _client()
    specs = get("/markets/specs")["specs"]
    assert specs["mm_release_active"] is True
    pair = next(p for p in specs["pairs"] if p["pair"]["active"] and not p["pair"]["paused"])["pair"]["pair_id"]
    mark = next(x for x in get("/oracle/prices")["prices"] if x["pair_id"] == pair)["mark_price"]
    min_usdc = int(specs["min_order_notional_6dec"]) / 1e6
    px = int(round(mark * 0.9, 2) * 1e6) * 100
    size = int(((min_usdc * 1.1) / (px / 1e8)) * 1e18) // 10**12 * 10**12
    orders = lambda: get(f"/orders/{owner}")
    c.cancel_all(0)
    _wait(orders, lambda o: not o)

    fd = None
    seen = []
    if os.getenv("VORDIUM_TESTNET_FEEDS"):
        fd = feeds.Feeds(os.environ["VORDIUM_TESTNET_FEEDS"], timeout=10, reconnect=False)
        fd.subscribe("orders", account=owner)
        threading.Thread(target=lambda: [seen.append(k) for k, _ in fd.events()], daemon=True).start()
        time.sleep(2)

    n1, n2 = c.nonce(), c.nonce()
    r = c.batch([mm.place(pair, "buy", size, px, n1, post_only=True),
                 mm.place(pair, "buy", size, px - 10**8, n2, post_only=True)])
    assert r.ok and all(a.accepted for a in r.actions), r
    o = _wait(orders, lambda o: {n1, n2} <= {x["client_nonce"] for x in o})
    assert {n1, n2} <= {x["client_nonce"] for x in o}
    second = next(x for x in o if x["client_nonce"] == n2)

    nm = c.nonce()
    assert c.modify(second["id"], second["price_8dec"] - 10**8, int(second["size"]), nm).ok
    o = _wait(orders, lambda o: any(x["client_nonce"] == nm for x in o))
    moved = next(x for x in o if x["client_nonce"] == nm)
    assert moved["id"] != second["id"] and moved["price_8dec"] == second["price_8dec"] - 10**8

    assert c.batch([mm.cancel_by_client_nonce(n1)]).ok
    o = _wait(orders, lambda o: not any(x["client_nonce"] == n1 for x in o))
    assert not any(x["client_nonce"] == n1 for x in o)

    tiny = c.batch([mm.place(pair, "buy", 10**12, px, c.nonce(), post_only=True)])
    assert tiny.actions and not tiny.actions[0].accepted and tiny.actions[0].refusal.code == "min_notional"

    assert c.cancel_all(pair).ok
    assert _wait(orders, lambda o: not o) == []

    nn = mm.next_mmp_nonce(get(f"/markets/account/{owner}"))
    assert c.set_mmp(mm.Mmp(60000, 20, 0, 0, 15000), nn).ok
    acct = _wait(lambda: get(f"/markets/account/{owner}"), lambda a: (a.get("mmp") or {}).get("max_fills") == 20)
    assert acct["mmp"]["window_ms"] == 60000 and acct["mmp"]["freeze_ms"] == 15000
    assert c.set_mmp(mm.Mmp(), mm.next_mmp_nonce(acct)).ok
    acct = _wait(lambda: get(f"/markets/account/{owner}"), lambda a: (a.get("mmp") or {}).get("window_ms") == 0)
    assert acct["mmp"]["window_ms"] == 0 and acct["mmp"]["max_fills"] == 0

    if fd is not None:
        fd.close()
        assert seen[0] == "snapshot" and seen.count("update") >= 4 and "resubscribed" not in seen
