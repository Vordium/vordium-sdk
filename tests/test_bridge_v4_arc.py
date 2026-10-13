"""Bridge v4 -- Arc as a deposit source and a payout destination (the one vault on Arbitrum): an Arc deposit is
Circle-forwarded (forwarding header + beneficiary hook, zero destination caller, standard finality, Circle's protocol and
forwarding fee as the maximum); Arc's blocklist; the payout route to Arc is the vault's forwarded one, only when open; a
route-3 intent to Arc equals the published vector; a withdrawal row names its destination; an Arc deposit's stages come
from the deposit read alone; and the two helpers -- prepare_arc_deposit and prepare_withdraw_to_arc -- run every check
before anything is built (the network answered here by stubs)."""

import json
import time
from dataclasses import replace
from pathlib import Path

import pytest

from vordium import bridge_v4 as b

HERE = Path(__file__).parent / "vectors"
F = json.loads((HERE / "bridge-v4-v35.json").read_text())
V34 = json.loads((HERE / "bridge-v4-v34.json").read_text())
INTENTS = json.loads((HERE / "bridge-v4-intents.json").read_text())
VAULT, HANDLER = F["vault"], F["handler"]
BY = "0x8FeD45485e06C1496E0DF1b2e11a87c53e292e39"
OTHER = "0x3219364FdFAeC2A60D14CDDA6E58Ec65eD33c009"
ACCEPTED = {"ok": True, "outcome": "accepted"}
ROUTES = [("local", 0), ("standard", 1), ("fast", 2), ("standard-forwarded", 3), ("fast-forwarded", 4)]


def vaults_json(open_routes=(0, 1, 3), domain=3, fee_quote=True, deposits_open=True, maximum="250000000000"):
    return {"active": True, "vaults": [{
        "id": 1, "chain_id": 42161, "address": VAULT, "handler": HANDLER, "cctp_domain": domain,
        "deposits": {"direct": {"chain_id": 42161, "minimum_6dec": "5000000"}, "cctp": {"from_chain_ids": [5042], "minimum_6dec": "10000000"}},
        "withdrawals": {"routes": [{"route_kind": k, "name": n, "open": k in open_routes} for n, k in ROUTES], "fee_6dec": "1000000",
                        "maximum_6dec": maximum},
        "runtime_sha256": {"vault": F["pins"]["vault"]["runtime"], "handler": F["pins"]["handler"]["runtime"]},
        "binding": {"handler_vault": VAULT, "local_domain": domain, "usdc": "0xaf88d065e77c8cC2239327C5EDb3A432268e5831", "confirmed": True}}],
        "depositsOpen": {"42161": deposits_open, "5042": deposits_open}, "minimumDeposit6dec": {"42161": "5000000", "5042": "10000000"},
        "withdrawalFee6dec": "1000000", "feeQuote": json.loads(json.dumps(V34["feeQuote"])) if fee_quote else None, "as_of": {"height": 7}}


VR = b.read_vaults(vaults_json())


def word(a):
    return "0x" + "0" * 24 + a[2:].lower()


def quote(rows):
    return [{"finalityThreshold": f, "minimumFee": m, "forwardFee": {"low": 1, "med": 2, "high": h}} for f, m, h in rows]


def burn_fields(data):
    w = [data[10:][i:i + 64] for i in range(0, len(data) - 10, 64)]
    n = int(w[8], 16)
    return {"amount": int(w[0], 16), "domain": int(w[1], 16), "mint": "0x" + w[2], "token": "0x" + w[3], "caller": "0x" + w[4],
            "max_fee": int(w[5], 16), "finality": int(w[6], 16), "hook": "0x" + "".join(w[9:])[:n * 2]}


@pytest.fixture(autouse=True)
def _open():
    was = b.ENABLED
    b.ENABLED = True
    yield
    b.ENABLED = was


def test_an_arc_deposit_is_circle_forwarded():
    assert b.ARC_DEPOSIT_FORWARDED is True and b.ARC_DEPOSIT_QUOTE_ROUTE == 3 and b.ARC_DOMAIN == 26 and b.ARC_CHAIN_ID == 5042
    chk = b.deposit_check(VR, 5042, 20_000_000, 199_000, b.sender_check({"ok": True, "kind": "wallet"}, None))
    assert chk.ok and chk.kind == "cctp"
    fwd = b.arc_deposit_txs(chk, VR, 5042, b.ARC_USDC, b.CCTP_TOKEN_MESSENGER_V2, OTHER, 20_000_000, 199_000, ACCEPTED, False, forwarded=True)
    plain = b.arc_deposit_txs(chk, VR, 5042, b.ARC_USDC, b.CCTP_TOKEN_MESSENGER_V2, OTHER, 20_000_000, 199_000, ACCEPTED, False)
    f, p = burn_fields(fwd[1]["data"]), burn_fields(plain[1]["data"])
    assert fwd[0]["data"].startswith(b.APPROVE_SELECTOR) and fwd[1]["data"].startswith(b.DEPOSIT_FOR_BURN_WITH_HOOK_SELECTOR)
    assert f["hook"] == (b.FORWARD_HEADER_V0 + word(OTHER)[2:]).lower() == b.hook_data(OTHER, True).lower()
    assert f["caller"] == "0x" + "0" * 64
    assert f["mint"] == word(HANDLER) and f["domain"] == 3 and f["finality"] == 2000 and f["max_fee"] == 199_000 and f["amount"] == 20_000_000
    assert f["token"] == word(b.ARC_USDC)
    assert p["caller"] == word(HANDLER) and p["hook"] == word(OTHER)        # the plain shape is unchanged
    with pytest.raises(ValueError, match="own contract"):
        b.arc_deposit_txs(chk, VR, 5042, b.ARC_USDC, b.CCTP_TOKEN_MESSENGER_V2, VAULT, 20_000_000, 199_000, ACCEPTED, False, forwarded=True)


def test_circles_fee_for_an_arc_deposit():
    assert b.arc_deposit_fee(quote([(1000, 9, 9), (2000, 1.3, 200000)]), 100_000_000) == 267_000
    assert b.arc_deposit_fee(quote([(2000, 0, 159140)]), 100_000_000) == 199_000
    assert b.arc_deposit_fee(quote([(1000, 0, 159140)]), 100_000_000) is None
    assert b.arc_deposit_fee([{"finalityThreshold": 2000, "minimumFee": 0}], 100_000_000) is None
    assert b.arc_deposit_fee(None, 1) is None and b.arc_deposit_fee(quote([(2000, 0, 1)]), 0) is None


def test_arcs_blocklist():
    assert b.blocklist_call_data(BY) == "0xfe575a87" + word(BY)[2:]
    with pytest.raises(ValueError):
        b.blocklist_call_data("0x12")
    assert b.arc_blocklist_check(False, "from") == {"ok": True}
    assert b.arc_blocklist_check(True, "from") == {"ok": False, "text": b.LINE_ARC_BLOCKED_FROM}
    assert b.arc_blocklist_check(True, "to") == {"ok": False, "text": b.LINE_ARC_BLOCKED_TO}
    assert b.arc_blocklist_check(None, "to") == {"ok": False, "text": b.LINE_ARC_BLOCK_UNREAD}


def test_the_payout_route_to_arc():
    assert b.arc_payout_route(VR.vaults[0]) == 3
    assert b.arc_payout_route(b.read_vaults(vaults_json(open_routes=(0, 4))).vaults[0]) == 4
    assert b.arc_payout_route(b.read_vaults(vaults_json(open_routes=(0, 3, 4))).vaults[0]) == 3     # standard (the lower fee) first
    # a base where the two readings differ after rounding: 2 USDC - the 1 USDC withdrawal fee = 1 USDC leaves the vault
    assert b.arc_payout_fee(VR, quote([(2000, 1000, 0)]), 3, 2_000_000) == 125_000
    assert b.arc_payout_route(b.read_vaults(vaults_json(open_routes=(0, 1, 2))).vaults[0]) is None
    dv = b.read_vaults(vaults_json(domain=26))
    assert b.arc_payout_route(dv.vaults[0] if dv.ok else None) is None and b.arc_payout_route(None) is None
    q = quote([(1000, 1.3, 18807), (2000, 0, 18807)])
    assert b.arc_payout_fee(VR, q, 3, 101_000_000) == 24_000
    assert b.arc_payout_fee(VR, q, 4, 101_000_000) == 40_000
    assert b.arc_payout_fee(VR, q, 0, 101_000_000) is None and b.arc_payout_fee(VR, q, 3, 1_000_000) is None and b.arc_payout_fee(VR, None, 3, 101_000_000) is None
    s = b.withdraw_arc_screen(VR, 101_000_000, 24_000)
    assert s["rows"] == [{"label": "Withdrawal fee", "value": "1 USDC"}, {"label": "Circle's fee (at most)", "value": "0.024 USDC"},
                         {"label": "You receive (at least)", "value": "99.976 USDC on Arc"}] and s["refusal"] is None and s["gas"] == b.LINE_NO_ETH
    assert b.withdraw_arc_screen(VR, 1_024_000, 24_000) is None and b.withdraw_arc_screen(VR, 101_000_000, None) is None
    big = b.withdraw_arc_screen(b.read_vaults(vaults_json(maximum="60000000")), 101_000_000, 24_000)
    assert big["refusal"] == b.line_above_max(60_000_000)


def test_a_withdrawal_to_arc_is_the_published_vector():
    vec = next(x for x in INTENTS["vectors"] if x["id"] == "WithdrawIntentV4-v3-3")
    m = vec["message"]
    p = b.WithdrawIntent(account=m["account"], vault_id=m["vaultId"], recipient=m["recipient"], amount=int(m["amount"]), nonce=int(m["nonce"]),
                         route_kind=m["routeKind"], destination_domain=m["destinationDomain"], max_fee=int(m["maxFee"]), deadline=m["deadline"])
    intent, err = b.build_withdraw_intent(VR, p, 1, m["deadline"] - 600)
    assert intent is not None, err
    body = b.submit_body(intent, "0x" + "11" * 65)
    assert body["route_kind"] == 3 and body["destination_domain"] == 26 and body["max_fee_6dec"] == "1300000"
    bad = b.WithdrawIntent(**{**p.__dict__, "recipient": "0x" + "ff" * 12 + m["recipient"][26:]})
    assert b.build_withdraw_intent(VR, bad, 1, m["deadline"] - 600)[0] is None
    assert b.build_withdraw_intent(b.read_vaults(vaults_json(open_routes=(0, 1))), p, 1, m["deadline"] - 600)[0] is None
    assert b.build_withdraw_intent(b.read_vaults(vaults_json(fee_quote=False)), p, 1, m["deadline"] - 600)[0] is None


def test_rows_and_stages():
    r = {"account": BY, "nonce": 4, "vault_id": 1, "status": "paid", "amount_6dec": "101000000", "payout_6dec": "100000000", "fee_6dec": "1000000",
         "route": "standard-forwarded", "destination_domain": 26, "recipient": word(BY), "paid_tx": "0x" + "aa" * 32, "refunded_6dec": None}
    assert b.read_withdrawal_row(r, BY)["destination_domain"] == 26
    assert b.read_withdrawal_row({**r, "destination_domain": None}, BY)["destination_domain"] is None

    def dep(**o):
        return {"status": "found", "row": {"kind": "cctp", "status": "pending", "nonce": None, "source_domain": 26, **o}}
    assert b.arc_deposit_stage(None) == "sent" and b.arc_deposit_stage({"status": "unknown"}) == "sent"
    assert b.arc_deposit_stage(dep()) == "sent" and b.arc_deposit_stage(dep(nonce="0x" + "ab" * 32)) == "confirmed"
    assert b.arc_deposit_stage(dep(status="credited", nonce="0x01")) == "credited"
    assert all(b.arc_deposit_stage(dep(status=s, nonce="0x01")) is None for s in ("waiting", "stranded", "not accepted"))
    assert [l for _, l in b.ARC_DEPOSIT_STEPS] == ["Sent on Arc", "Confirmed by Circle", "Credited on Vordium"]


# ---- the two helpers, with the network answered by stubs ----------------------------------------------------------------

class Net:
    def __init__(self, monkeypatch, *, vaults=None, fee=quote([(2000, 0, 159140)]), arc_code="wallet", allowed="accepted", blocked=False,
                 next_nonce=7, chain_time=1_900_000_000, age_s=0.0, deployments=True):
        self.calls = []
        v = b.read_vaults(vaults or vaults_json())
        monkeypatch.setattr(b, "fetch_vaults", lambda: replace(v, read_at=time.monotonic() - age_s))
        monkeypatch.setattr(b, "fetch_deployments", lambda: {"42161": {"vault": VAULT, "handler": HANDLER,
                                                                       "setRules": b.create_address(VAULT, 2)}} if deployments else None)
        monkeypatch.setattr(b, "fetch_fee_quote", lambda s, d, fwd: (self.calls.append(("quote", s, d, fwd)), fee)[1])
        monkeypatch.setattr(b, "fetch_account_code", lambda c, a: {"ok": True, "kind": arc_code} if arc_code else {"ok": False})
        monkeypatch.setattr(b, "fetch_deposit_allowed", lambda c, s, a: (self.calls.append(("allowed", c, a)), {"ok": True, "outcome": allowed})[1])
        monkeypatch.setattr(b, "read_arc_blocked", lambda url, a: (self.calls.append(("blocked", a)), blocked)[1])
        monkeypatch.setattr(b, "fetch_next_nonce", lambda a: (next_nonce, ""))
        monkeypatch.setattr(b, "_chain_time_s", lambda: chain_time)


def test_prepare_arc_deposit_runs_every_check(monkeypatch):
    n = Net(monkeypatch)
    out = b.prepare_arc_deposit(BY, 20_000_000, arc_rpc_url="https://arc.example")
    # Circle's forwarding fee is flat: 0.15914 x 1.25 -> 0.199 USDC at most, whatever the amount
    assert out["ok"] and out["max_fee"] == 199_000 and out["credited_at_least"] == 19_801_000
    assert ("quote", 26, 3, True) in n.calls and ("allowed", 42161, 19_801_000) in n.calls and ("blocked", BY) in n.calls
    f = burn_fields(out["txs"][1]["data"])
    assert f["caller"] == "0x" + "0" * 64 and f["hook"].startswith(b.FORWARD_HEADER_V0.lower()) and f["max_fee"] == 199_000


@pytest.mark.parametrize("kw,text", [
    ({"blocked": True}, b.LINE_ARC_BLOCKED_FROM), ({"blocked": None}, b.LINE_ARC_BLOCK_UNREAD),
    ({"fee": None}, "Circle's fee could not be read"), ({"arc_code": "contract"}, "smart-contract wallet"),
    ({"allowed": "waits"}, "Press Deposit again"), ({"vaults": vaults_json(deposits_open=False)}, b.LINE_BRIDGE_CLOSED),
    ({"age_s": b.BRIDGE_READ_FRESH_S + 5}, b.LINE_BRIDGE_STALE), ({"deployments": False}, "could not be read"),
])
def test_prepare_arc_deposit_refuses(monkeypatch, kw, text):
    Net(monkeypatch, **kw)
    out = b.prepare_arc_deposit(BY, 20_000_000, arc_rpc_url="https://arc.example")
    assert not out["ok"] and text in out["text"], out


def test_nothing_is_built_while_deposits_are_closed(monkeypatch):
    n = Net(monkeypatch, vaults=vaults_json(deposits_open=False))
    out = b.prepare_arc_deposit(BY, 20_000_000, arc_rpc_url="https://arc.example")
    assert not out["ok"] and out["text"] == b.LINE_BRIDGE_CLOSED and "txs" not in out and n.calls == []


def test_prepare_withdraw_to_arc(monkeypatch):
    n = Net(monkeypatch, fee=quote([(1000, 1.3, 18807), (2000, 0, 18807)]))
    out = b.prepare_withdraw_to_arc(BY, 101_000_000, arc_rpc_url="https://arc.example")
    assert out["ok"], out
    i = out["intent"]
    assert (i.route_kind, i.destination_domain, i.max_fee, i.nonce, i.recipient) == (3, 26, 24_000, 7, word(BY))
    assert i.deadline == 1_900_000_000 + b.INTENT_DEFAULT_TTL_S and out["receive_at_least"] == 99_976_000
    assert ("quote", 3, 26, True) in n.calls and ("blocked", BY) in n.calls
    Net(monkeypatch, blocked=True)
    assert b.prepare_withdraw_to_arc(BY, 101_000_000, arc_rpc_url="https://arc.example")["text"] == b.LINE_ARC_BLOCKED_TO
    Net(monkeypatch, vaults=vaults_json(open_routes=(0, 1)))
    assert b.prepare_withdraw_to_arc(BY, 101_000_000, arc_rpc_url="https://arc.example")["text"] == "Withdrawals to Arc are not open."
    Net(monkeypatch, chain_time=None)
    assert "chain's time" in b.prepare_withdraw_to_arc(BY, 101_000_000, arc_rpc_url="https://arc.example")["text"]


def test_withdraw_to_arc_signs_and_submits(monkeypatch):
    Net(monkeypatch, fee=quote([(2000, 0, 18807)]))
    sent = {}
    monkeypatch.setattr(b, "submit_withdrawal", lambda i, sig: (sent.update(i=i, sig=sig), ("submitted", None, b.MESSAGE_SUBMITTED))[1])
    key = "0x" + "4" * 64
    from eth_account import Account
    out = b.withdraw_to_arc(key, 101_000_000, arc_rpc_url="https://arc.example")
    assert out == ("submitted", None, b.MESSAGE_SUBMITTED)
    assert sent["i"].account == Account.from_key(key).address and sent["i"].route_kind == 3 and len(sent["sig"]) == 132
