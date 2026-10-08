"""Bridge v4 client rules: the withdrawal intent and a payout's ready call reproduce the published vectors byte for
byte; the deadline, the minimum, the nonce read, the submit body, the refusal codes, depositsOpen, the fee rule and the
fee quote object, the sender of a deposit from Arc, the key-held account, the deposit transactions, the refund claim,
sending the ready call yourself, the reads a client shows, the pins and the public words follow the published rules;
every chain fact a rule needs comes from a public bridge read that two sources confirmed; everything that signs or sends
refuses while the module is off."""

import hashlib
import json
import re
from dataclasses import replace
from pathlib import Path

import pytest
from eth_abi import encode
from eth_account import Account
from eth_utils import keccak

from vordium import bridge_v4 as b

V = json.loads((Path(__file__).parent / "vectors" / "bridge-v4-intents.json").read_text())
V32 = json.loads((Path(__file__).parent / "vectors" / "bridge-v4-v34.json").read_text())     # interface v3.4 test data
VAULT = "0xeBbaa620Ee72874237172A5DF16723f81Bd47642"
HANDLER = V32["testHandler"]                     # v3.4: the handler the vault created, CREATE(vault, nonce 1)
LINE = "Not accepted: below the minimum deposit (5 USDC from Arbitrum, 10 USDC from Arc)."
BY = "0x8FeD45485e06C1496E0DF1b2e11a87c53e292e39"
USDC_ARB = "0xaf88d065e77c8cC2239327C5EDb3A432268e5831"
WALLET, DELEGATED, CONTRACT, UNREAD = {"ok": True, "kind": "wallet"}, {"ok": True, "kind": "delegated-wallet"}, {"ok": True, "kind": "contract"}, {"ok": False}


def vaults_json(direct_open=False, cctp_open=False, active=True, direct_min="5000000", cctp_min="10000000",
                fee="1000000", standard_open=False, fee_quote=None):
    return {
        "active": active,
        "vaults": [{
            "id": 1, "chain": "arbitrum", "chain_id": 42161, "address": VAULT, "handler": HANDLER, "cctp_domain": 3,
            "deposits": {"direct": {"chain_id": 42161, "minimum_6dec": direct_min, "open": direct_open},
                         "cctp": {"from_chain_ids": [5042], "minimum_6dec": cctp_min, "open": cctp_open}},
            "withdrawals": {"routes": [{"route_kind": 0, "name": "local", "open": True},
                                       {"route_kind": 1, "name": "standard", "open": standard_open},
                                       {"route_kind": 2, "name": "fast", "open": False},
                                       {"route_kind": 3, "name": "standard-forwarded", "open": False},
                                       {"route_kind": 4, "name": "fast-forwarded", "open": False}],
                            "fee_6dec": fee, "maximum_6dec": "250000000000"},
            "runtime_sha256": {"vault": b.PINS["vault"]["runtime"], "handler": b.PINS["handler"]["runtime"]},
            "binding": {"handler_vault": VAULT, "local_domain": 3, "usdc": USDC_ARB, "confirmed": True},
        }],
        "depositsOpen": {"42161": direct_open, "5042": cctp_open},
        "minimumDeposit6dec": {"42161": direct_min, "5042": cctp_min},
        "withdrawalFee6dec": fee,
        "feeQuote": json.loads(json.dumps(V32["feeQuote"] if fee_quote is None else fee_quote)),
        "as_of": {"height": 7},
    }


@pytest.fixture(autouse=True)
def _enabled():
    was = b.ENABLED
    b.ENABLED = True
    yield
    b.ENABLED = was


def intent_of(x):
    m = x["message"]
    return b.WithdrawIntent(m["account"], int(m["vaultId"]), m["recipient"], int(m["amount"]), int(m["nonce"]),
                            int(m["routeKind"]), int(m["destinationDomain"]), int(m["maxFee"]), int(m["deadline"]))


PAYOUT = V32["payout"]
WC = V32["withdrawCall"]
PM = PAYOUT["message"]


def expected(**change):
    w = b.ExpectedPayout(PAYOUT["vault"], PAYOUT["chainId"], PM["account"], int(PM["nonce"]), PM["recipient"],
                         int(PM["amount"]), int(PM["routeKind"]), int(PM["destinationDomain"]), int(PM["maxFee"]))
    return replace(w, **change)


NOW = int(PM["deadline"]) - 60


def deposit_row(**o):
    """One deposit row with its 17 names (interface v3.4.1 section 23.2): a not-accepted CCTP deposit by default."""
    base = {"status": "not accepted", "reason": "below_minimum", "text": "any text", "kind": "cctp", "account": BY,
            "amount_6dec": "9000000", "vault_id": 1, "chain_id": 42161, "deposit_id": None, "source_domain": 26,
            "nonce": "0x" + "ab" * 32, "source_chain_id": None, "source_tx": None, "vault_tx": "0x" + "cd" * 32,
            "claim": {"chain_id": 42161, "handler": HANDLER, "by": BY, "amount_6dec": "9000000", "refundable_6dec": "9000000", "read": "ok"},
            "credited_height": None, "as_of": {"height": 12}}
    base.update(o)
    return base


def credited_row(**o):
    return deposit_row(**{"status": "credited", "reason": None, "text": None, "kind": "direct", "deposit_id": 7, "source_domain": None,
                          "nonce": None, "source_chain_id": 42161, "source_tx": "0x" + "ef" * 32, "claim": None, "credited_height": 99, **o})


def test_intent_type_string_and_hash():
    for x in V["vectors"]:
        assert b.WITHDRAW_INTENT_TYPE == x["typeString"]
        assert "0x" + keccak(text=b.WITHDRAW_INTENT_TYPE).hex().removeprefix("0x") == x["typehash"]


def test_intent_digests_and_signatures_match_the_vectors():
    for x in V["vectors"]:
        s = b.withdraw_intent_signable(intent_of(x))
        assert "0x" + s.header.hex() == V["domain"]["vordcore101101"]
        assert "0x" + keccak(b"\x19\x01" + s.header + s.body).hex() == x["digest"]
        key = keccak(text="vordium-v4-test-account-1") if x["message"]["account"].lower() == Account.from_key(
            keccak(text="vordium-v4-test-account-1")).address.lower() else keccak(text="vordium-v4-test-account-2")
        assert b.sign_withdraw_intent(key, intent_of(x)) == x["signatures"][0]["signature"].lower()


def test_the_deadline_is_signed():
    one, four = (next(x for x in V["vectors"] if x["id"] == i) for i in ("WithdrawIntentV4-v3-1", "WithdrawIntentV4-v3-4"))
    assert int(four["message"]["deadline"]) == int(one["message"]["deadline"]) + 1
    assert four["digest"] != one["digest"]


def test_submit_body_is_the_worked_example_key_for_key():
    x = next(x for x in V["vectors"] if x["id"] == V["submitExample"]["vector"])
    body = b.submit_body(intent_of(x), x["signatures"][0]["signature"])
    assert body == V["submitExample"]["body"]
    assert list(body) == list(V["submitExample"]["body"])


def test_deadline_rules():
    now = 1_900_000_000
    assert b.intent_deadline(now) == now + 600
    assert b.deadline_problem(now + 600, now) is None
    assert b.deadline_problem(now + 86_400, now) is None
    assert "more than 24 hours" in b.deadline_problem(now + 86_401, now)
    assert "has passed" in b.deadline_problem(now, now)
    assert "has passed" in b.deadline_problem(now - 1, now)


def test_next_nonce_read():
    a = "0x3219364FdFAeC2A60D14CDDA6E58Ec65eD33c009"
    assert b.read_next_nonce({"account": a.lower(), "last_nonce": 2, "next_nonce": 3, "as_of": {"height": 1}}, a) == (3, "")
    assert b.read_next_nonce({"account": a, "last_nonce": None, "next_nonce": "1"}, a) == (1, "")
    assert b.read_next_nonce({"account": HANDLER, "next_nonce": 3}, a)[0] is None
    assert b.read_next_nonce({"account": a, "last_nonce": 3, "next_nonce": 3}, a)[0] is None


def test_build_intent_route_zero_and_refusals():
    v = b.read_vaults(vaults_json())
    x = next(x for x in V["vectors"] if x["id"] == "WithdrawIntentV4-v3-1")
    i = intent_of(x)
    now = i.deadline - 600
    assert b.build_withdraw_intent(v, i, 1, now)[0] is not None
    assert "below the next nonce" in b.build_withdraw_intent(v, i, 2, now)[1]
    assert "more than 24 hours" in b.build_withdraw_intent(v, i, 1, i.deadline - 86_401)[1]
    assert "has passed" in b.build_withdraw_intent(v, i, 1, i.deadline)[1]
    assert "no CCTP fee" in b.build_withdraw_intent(v, replace(i, max_fee=1), 1, now)[1]
    assert "own chain" in b.build_withdraw_intent(v, replace(i, destination_domain=26), 1, now)[1]
    assert b.build_withdraw_intent(v, replace(i, recipient="0x" + "0" * 24 + VAULT[2:]), 1, now)[1] == b.LINE_OWN_ADDRESS
    assert "cover the withdrawal fee" in b.build_withdraw_intent(v, replace(i, amount=1_000_000), 1, now)[1]
    assert "not open" in b.build_withdraw_intent(v, replace(i, route_kind=1, destination_domain=26), 1, now)[1]


def test_a_cctp_route_needs_a_confirmed_fee_quote():
    x = next(x for x in V["vectors"] if x["id"] == "WithdrawIntentV4-v3-1")
    i = replace(intent_of(x), route_kind=1, destination_domain=26, max_fee=40_000)
    now = i.deadline - 600
    assert b.build_withdraw_intent(b.read_vaults(vaults_json(standard_open=True)), i, 1, now)[0] is not None
    bad = dict(V32["feeQuote"], marginBps=1)
    r = b.build_withdraw_intent(b.read_vaults(vaults_json(standard_open=True, fee_quote=bad)), i, 1, now)
    assert r[0] is None and "fee quote cannot be confirmed" in r[1]


def test_submit_responses_are_read_by_their_code():
    codes = V32["intakeCodes"]
    assert len(codes) == 12 and {c["code"] for c in codes} == set(b.INTAKE_CODES) and codes[-1]["code"] == "over_maximum"
    assert all(b.INTAKE_CODES[c["code"]][0] == c["http"] for c in codes)
    assert b.read_submit_response(202, {"status": "submitted"}) == ("submitted", None, "Withdrawal submitted.")
    assert b.read_submit_response(400, {"error": "the intent has expired", "code": "expired"}) == (
        "resign", "expired", "This withdrawal request expired. Please try again.")
    assert b.read_submit_response(400, {"error": "the intent has expired"})[0] == "unknown"      # the code decides
    assert b.read_submit_response(403, {"error": "x", "code": "expired"})[0] == "unknown"        # wrong status
    assert b.read_submit_response(409, {"error": "not accepted (already pending)"}) == (
        "duplicate", None, "This withdrawal is already being processed.")
    assert b.read_submit_response(409, {"error": "x", "code": "nonce_used"})[0] == "duplicate"
    assert b.read_submit_response(400, {"error": "x", "code": "no_such_code"})[0] == "unknown"
    assert b.read_submit_response(500, None)[0] == "unknown"
    shown = [b.read_submit_response(c["http"], {"error": "CHAIN TEXT", "code": c["code"]})[2] for c in codes]
    assert all(s and "CHAIN TEXT" not in s for s in shown) and len(set(shown)) == len(shown)


def test_below_minimum_line_is_built_from_the_read():
    v = b.read_vaults(vaults_json())
    assert b.below_minimum_line(v) == LINE
    v2 = b.read_vaults(vaults_json(direct_min="7500000", cctp_min="12250000"))
    assert b.below_minimum_line(v2) == "Not accepted: below the minimum deposit (7.5 USDC from Arbitrum, 12.25 USDC from Arc)."


def test_deposits_open_is_one_value_and_only_true_builds():
    closed = b.read_vaults(vaults_json(direct_open=False))
    assert b.deposit_check(closed, 42161, 50_000_000).reason == "closed"
    j = vaults_json(direct_open=True)
    j["depositsOpen"]["42161"] = None
    assert b.deposit_check(b.read_vaults(j), 42161, 50_000_000).reason == "unknown"
    j["depositsOpen"].pop("42161")
    assert b.deposit_check(b.read_vaults(j), 42161, 50_000_000).reason == "unknown"
    j["depositsOpen"]["42161"] = "true"
    assert b.deposit_check(b.read_vaults(j), 42161, 50_000_000).reason == "unknown"
    ok = b.deposit_check(b.read_vaults(vaults_json(direct_open=True)), 42161, 5_000_000)
    assert ok.ok and ok.kind == "direct" and ok.vault == VAULT
    assert b.deposit_check(b.read_vaults(vaults_json(direct_open=True, active=False)), 42161, 50_000_000).reason == "closed"


def test_below_the_minimum_is_refused_before_signing():
    v = b.read_vaults(vaults_json(direct_open=True, cctp_open=True))
    w = b.sender_check(WALLET, None)
    r = b.deposit_check(v, 42161, 4_999_999)
    assert not r.ok and r.reason == "below-minimum" and r.text == LINE
    assert b.deposit_check(v, 5042, 10_000_000, max_fee=1, sender=w).reason == "below-minimum"   # the vault must RECEIVE it
    assert b.deposit_check(v, 5042, 10_001_000, max_fee=1_000, sender=w).ok
    assert b.deposit_check(v, 1, 50_000_000).reason in ("unknown", "no-vault")


def test_the_sender_of_a_deposit_from_arc_must_be_able_to_claim_on_arbitrum():
    v = b.read_vaults(vaults_json(direct_open=True, cctp_open=True))
    assert b.sender_check(WALLET, WALLET).kind == "wallet"
    assert b.sender_check(DELEGATED, None).kind == "delegated-wallet"
    assert b.sender_check(CONTRACT, CONTRACT).kind == "contract-on-arbitrum"
    no = b.sender_check(CONTRACT, WALLET)
    assert not no.ok and no.reason == "contract-not-on-arbitrum" and "does not exist on Arbitrum" in no.text
    assert b.sender_check(CONTRACT, DELEGATED).reason == "contract-not-on-arbitrum"
    for arc in (UNREAD, None):
        assert b.sender_check(arc, WALLET).reason == "unreadable"
    assert b.sender_check(CONTRACT, None).reason == "unreadable" and b.sender_check(CONTRACT, UNREAD).reason == "unreadable"
    assert b.deposit_check(v, 5042, 20_000_000, max_fee=1_000).reason == "sender"
    assert b.deposit_check(v, 5042, 20_000_000, max_fee=1_000, sender=no).text == no.text
    assert b.deposit_check(v, 42161, 20_000_000).ok                                # a direct deposit needs no sender check


def test_the_account_code_read():
    a = "0x3219364FdFAeC2A60D14CDDA6E58Ec65eD33c009"

    def body(**o):
        x = {"address": a.lower(), "has_code": False, "delegation": None, "as_of": {"chain_id": 5042, "block": 88}, "read": "ok"}
        x.update(o)
        return x
    rc = b.read_account_code
    assert rc(200, body(), 5042, a) == WALLET
    assert rc(200, body(has_code=True, delegation="0x" + "11" * 20), 5042, a) == DELEGATED
    assert rc(200, body(has_code=True), 5042, a) == CONTRACT
    for what, s, bo in (("unavailable", 200, body(read="unavailable", has_code=None)), ("no read field", 200, {k: v for k, v in body().items() if k != "read"}),
                        ("another address", 200, body(address=HANDLER)), ("another chain", 200, body(as_of={"chain_id": 42161, "block": 88})),
                        ("block 0", 200, body(as_of={"chain_id": 5042, "block": 0})), ("block null", 200, body(as_of={"chain_id": 5042, "block": None})),
                        ("committed height, not a live read", 200, body(as_of={"height": 5})), ("delegation without code", 200, body(delegation="0x" + "11" * 20)),
                        ("has_code not a bool", 200, body(has_code="false")), ("delegation missing", 200, {k: v for k, v in body().items() if k != "delegation"}),
                        ("HTTP 404", 404, {"error": "not found", "code": "not_found"}), ("HTTP 502", 502, {"code": "upstream_unavailable"})):
        assert rc(s, bo, 5042, a) == UNREAD, what
    assert b.key_held_check(WALLET)["ok"] and b.key_held_check(DELEGATED)["ok"]
    assert not b.key_held_check(CONTRACT)["ok"] and "key-held wallet" in b.key_held_check(CONTRACT)["text"]
    assert not b.key_held_check(UNREAD)["ok"] and not b.key_held_check(None)["ok"]


def test_the_read_is_refused_whole_when_it_disagrees_with_itself():
    j = vaults_json()
    j["minimumDeposit6dec"]["42161"] = "4000000"
    assert not b.read_vaults(j).ok
    j = vaults_json()
    j["vaults"][0]["withdrawals"]["routes"][1]["name"] = "slow"
    assert not b.read_vaults(j).ok
    j = vaults_json()
    j["vaults"][0]["withdrawals"]["fee_6dec"] = "2000000"
    assert not b.read_vaults(j).ok


def test_fee_rule():
    assert b.max_fee_from_quote(250_000_000, "1", 200_000) == 282_000            # (25,000 + 200,000) × 1.25 → 281,250 → 282,000
    assert b.max_fee_from_quote(250_000_000, "0", 0) == 0
    assert b.max_fee_from_quote(1_000_000, "1.3", 0) == 1_000                     # 130 × 1.25 = 162.5 → 163 → 1,000
    assert b.max_fee_from_quote(100_000_000, "1", 0) == 13_000                    # 10,000 × 1.25 = 12,500 → 13,000
    assert b.max_fee_from_quote(80_000_000, "1", 0) == 10_000                     # 8,000 × 1.25 = 10,000 exactly
    assert b.max_fee_from_quote(8_005_000, "1", 0) == 2_000                       # 800.5 exact × 1.25 → 1,001 → 2,000 (floored first: 1,000)
    for e in V32["feeQuote"]["examples"]:
        assert b.max_fee_from_quote(int(e["amount_6dec"]), e["minimumFee"], int(e["forwardFeeHigh_6dec"])) == int(e["maxFee_6dec"])
    quote = [{"finalityThreshold": 1000, "minimumFee": 1, "forwardFee": {"low": 1, "med": 2, "high": 200000}},
             {"finalityThreshold": 2000, "minimumFee": 0, "forwardFee": {"low": 1, "med": 2, "high": 150000}}]
    assert b.quote_for(quote, 2) == ("1", 0) and b.quote_for(quote, 4) == ("1", 200000)
    assert b.quote_for(quote, 1) == ("0", 0) and b.quote_for(quote, 3) == ("0", 150000)
    assert b.quote_for(quote, 0) is None


def test_the_fee_quote_object():
    q = b.read_fee_quote(V32["feeQuote"])
    assert q.ok and q.examples == 2 and q.quote_url == "https://iris-api.circle.com/v2/burn/USDC/fees/{sourceDomain}/{destDomain}"
    assert q.forward_param == "forward=true"

    def err(**change):
        o = json.loads(json.dumps(V32["feeQuote"]))
        o.update(change)
        return b.read_fee_quote(o).error
    assert "margin" in err(marginBps=2000)
    assert "round up to 1000" in err(roundUp6dec="100")
    assert "its URL is quoteUrl" in err(host="iris-api.circle.com") and "its URL is quoteUrl" in err(path="/v2/burn/USDC/fees/{sourceDomain}/{destDomain}")
    assert "quote URL" in err(quoteUrl="https://fees.example.com/v2/burn/USDC/fees/{sourceDomain}/{destDomain}") and "quote URL" in err(forwardParam="forward=1")
    ex = json.loads(json.dumps(V32["feeQuote"]["examples"]))
    ex[0]["maxFee_6dec"] = "4000"
    assert "gives 4000; the published rule gives 3000" in err(examples=ex)
    ex = json.loads(json.dumps(V32["feeQuote"]["examples"]))
    ex[0]["forwardFeeHigh_6dec"] = "5"
    assert "not forwarded" in err(examples=ex)
    assert "other routes" in err(appliesTo=["local", "fast"]) and "no worked example" in err(examples=[])
    assert "five items" in err(showBeforeSigning=["a"])
    assert b.fee_quote_url(26, 3, False) == "https://iris-api.circle.com/v2/burn/USDC/fees/26/3"
    assert b.fee_quote_url(3, 26, True) == "https://iris-api.circle.com/v2/burn/USDC/fees/3/26?forward=true"
    assert b.fee_quote_url(3, 26, True) == "https://iris-api.circle.com/v2/burn/USDC/fees/3/26?forward=true"


def test_pre_sign_summary_and_the_withdrawal_screen():
    x = next(x for x in V["vectors"] if x["id"] == "WithdrawIntentV4-v3-1")
    s = b.pre_sign_summary(intent_of(x), 1_000_000)
    assert s["leaving"] == 250_000_000 and s["withdrawalFee"] == 1_000_000 and s["maxFee"] is None
    assert s["minimumReceived"] == 249_000_000 and s["exact"] and s["route"] == "local"
    assert s["destination"]["chain"] == "Arbitrum"
    sc = b.withdraw_screen(b.read_vaults(vaults_json()), 250_000_000)
    assert sc == {"refusal": None, "rows": [{"label": "Withdrawal fee", "value": "1 USDC"},
                           {"label": "You receive", "value": "249 USDC on Arbitrum"}], "gas": "No ETH needed"}
    assert b.withdraw_screen(b.read_vaults(vaults_json(fee="2500000")), 250_000_000)["rows"][0]["value"] == "2.5 USDC"
    assert b.withdraw_screen(b.read_vaults(vaults_json()), 1_000_000) is None


def test_public_words():
    for w in ("pending", "paid", "refunded"):
        assert b.withdrawal_status(w) == w
    # the read carries the three words only: any other word -- a vault state, another spelling -- shows nothing
    for w in ("queued", "held", "parked", "unpaid", "signing", "signed", "cancelled", "expired", "expired_refunded", "Paid", "unknown", "", None, 3):
        assert b.withdrawal_status(w) is None
    for w in ("pending", "credited", "waiting", "stranded", "not accepted"):
        assert b.deposit_status(w) == w
    for w in ("held", "unknown", "refused", "not_accepted", "paused", "Pending", "under review", "Waiting"):
        assert b.deposit_status(w) is None
    assert b.DEPOSIT_STATUSES == ("pending", "credited", "waiting", "stranded", "not accepted") and "held" not in b.STATUS_WORD


def test_reason_lines():
    v = b.read_vaults(vaults_json())
    assert b.reason_line("below_minimum", v, "42161") == LINE
    assert b.reason_line("above_per_deposit_limit", v, "42161") == b.LINE_OVER_CAP
    assert b.reason_line("stranded", v, "42161") == b.LINE_STRANDED and b.reason_line("rescued", v, "42161") == b.LINE_RESCUED
    assert b.reason_line("waiting", v, "42161") == b.LINE_WAITING
    assert b.reason_line("not_completed", v, "42161") == b.LINE_NOT_COMPLETED
    assert b.reason_line("other", v, "42161") == b.LINE_NOT_ACCEPTED
    assert b.reason_line("not_completed", v, "5042") == b.LINE_NOT_COMPLETED.replace(" on Arbitrum ", " on Arc ")
    assert b.reason_line("below_minimum", b.read_vaults({"x": 1}), "42161") == "Not accepted."


def test_the_not_accepted_row_and_the_claim():
    v = b.read_vaults(vaults_json())
    vault = v.vaults[0]
    r = b.read_deposit_row(deposit_row(), v)
    assert r["status"] == "not accepted" and r["reason"] == "below_minimum" and r["line"] == LINE
    assert r["claim"]["chain"] == "Arbitrum" and r["claim"]["amount"] == 9_000_000 and r["claim"]["refundable"] == 9_000_000 and r["claim"]["checked"]
    assert b.read_deposit_row(deposit_row(text="Not accepted: ask support."), v)["line"] == LINE      # the key decides, never the text
    assert b.read_deposit_row(deposit_row(reason="not_completed", text=LINE), v)["line"] == b.LINE_NOT_COMPLETED
    assert not b.read_deposit_row(deposit_row(claim=dict(deposit_row()["claim"], handler=VAULT)), v)["claim"]["checked"]
    ok = b.refund_claim(r, BY, vault)
    assert ok == {"ok": True, "tx": {"chainId": 42161, "to": HANDLER, "data": "0xb5545a3c", "value": 0}, "amount": 9_000_000, "to": BY}

    def why(row=r, who=BY, vt=vault, to=None):
        x = b.refund_claim(row, who, vt, to)
        return "ok" if x["ok"] else x["reason"]

    def with_claim(**c):
        return b.read_deposit_row(deposit_row(claim=dict(deposit_row()["claim"], **c)), v)
    assert why(who=VAULT) == "not-owed" and why(row=with_claim(refundable_6dec="0")) == "nothing"
    assert why(row=with_claim(refundable_6dec=None, read="unavailable")) == "unread"
    nr = dict(deposit_row()["claim"])
    del nr["refundable_6dec"], nr["read"]
    assert why(row=b.read_deposit_row(deposit_row(claim=nr), v)) == "unread"           # the node row alone: not confirmed
    assert why(vt=replace(vault, runtime_sha_handler=b.PINS["vault"]["runtime"])) == "pin" and why(vt=replace(vault, runtime_sha_handler=None)) == "pin"
    assert why(row=None) == "unreadable" and why(vt=None) == "handler"
    assert why(row=b.read_deposit_row(deposit_row(claim=dict(deposit_row()["claim"], handler=VAULT)), v)) == "handler"
    assert why(to=b.refund_recipient(VAULT, BY, b.own_addresses(vault))) == "recipient"
    with pytest.raises(ValueError):
        b.claim_refund_tx(HANDLER, b.own_addresses(vault), VAULT, BY)


def _payout_fields():
    return b.PayoutFields(PM["account"], PM["recipient"], int(PM["amount"]), int(PM["nonce"]), int(PM["routeKind"]),
                          int(PM["destinationDomain"]), int(PM["maxFee"]), int(PM["epoch"]), int(PM["deadline"]))


def _ready(**over):
    return {"status": "ready", "vault_id": 1, "digest": WC["digest"], "quorum_reached": True, "vault_settled": False, "chain_time": NOW,
            "read": "ok", "chain_id": WC["chain_id"], "to": WC["to"], "data": WC["data"], "value": WC["value"], "as_of": {"height": 9}, **over}


def _payout_vault(**change):
    """The vault the payout vectors are signed for, as the vaults read carries it (id 1, its live code = the pin)."""
    v = b.read_vaults(vaults_json()).vaults[0]
    return replace(v, **{"address": PAYOUT["vault"], **change})


def _flip(data, index, value):
    raw = bytearray(bytes.fromhex(data[2:]))
    raw[index] = value
    return "0x" + raw.hex()


def test_the_ready_call_is_reproduced_byte_for_byte():
    enc = b.encode_withdraw_call(_payout_fields(), PAYOUT["signatures"])
    assert enc == WC["data"].lower()
    assert (len(enc) - 2) // 2 == WC["dataBytes"] and hashlib.sha256(bytes.fromhex(enc[2:])).hexdigest() == WC["dataSha256"]
    tup = (PM["account"], bytes.fromhex(PM["recipient"][2:]), int(PM["amount"]), int(PM["nonce"]), int(PM["routeKind"]),
           int(PM["destinationDomain"]), int(PM["maxFee"]), int(PM["epoch"]), int(PM["deadline"]))
    ref = "0xe8c13bb8" + encode(["(address,bytes32,uint256,uint256,uint8,uint32,uint256,uint64,uint64)", "bytes[]"],
                                [tup, [bytes.fromhex(s[2:]) for s in PAYOUT["signatures"]]]).hex()
    assert ref == enc                                                     # eth_abi agrees
    d = b.decode_withdraw_call(WC["data"])
    assert d["ok"] and d["fields"] == replace(_payout_fields(), account=PM["account"].lower(), recipient=PM["recipient"].lower())
    assert d["signatures"] == [s.lower() for s in PAYOUT["signatures"]]
    assert "0x" + keccak(text="withdraw((address,bytes32,uint256,uint256,uint8,uint32,uint256,uint64,uint64),bytes[])")[:4].hex() == b.WITHDRAW_SELECTOR


def test_every_tampering_of_the_call_is_refused_by_name():
    W = WC["data"]

    def dec(x):
        r = b.decode_withdraw_call(x)
        return "ok" if r["ok"] else r["field"]
    assert dec(W[:-2]) == "length" and dec(W + "00") == "length" and dec(W + "00" * 32) == "encoding"
    assert dec(_flip(W, 0, 0)) == "selector"
    assert dec(_flip(W, 4 + 11, 1)) == "account"
    assert dec(_flip(W, 4 + 4 * 32 + 30, 1)) == "routeKind"
    assert dec(_flip(W, 4 + 5 * 32 + 27, 1)) == "destinationDomain"
    assert dec(_flip(W, 4 + 7 * 32 + 23, 1)) == "epoch" and dec(_flip(W, 4 + 8 * 32 + 23, 1)) == "deadline"
    assert dec(_flip(W, 4 + 9 * 32 + 31, 0x60)) == "encoding"
    assert b.decode_withdraw_call(_flip(W, 4 + 9 * 32 + 31, 0x60))["text"] == "The signatures are not where the one encoding puts them."
    assert dec(_flip(W, 4 + 10 * 32 + 31, 0)) == "signatures"
    assert dec(_flip(W, 4 + 11 * 32 + 5 * 32 + 31, 64)) == "signature 1"
    assert dec(_flip(W, 4 + 11 * 32 + 31, 0xC0)) == "encoding"
    assert dec(_flip(W, 4 + 11 * 32 + 5 * 32 + 32 + 96 - 1, 1)) == "encoding"
    assert dec(_flip(W, 4 + 2 * 32 + 31, 0x41)) == "ok" and dec("0xzz") == "data" and dec(None) == "data"


def test_the_call_read():
    r = b.read_withdrawal_call
    ok = r(200, _ready())
    assert ok.status == "ready" and ok.chain_id == 42161 and ok.to == WC["to"] and ok.data == WC["data"] and ok.value == 0
    assert ok.vault_id == 1 and ok.digest == WC["digest"] and ok.quorum_reached is True and ok.vault_settled is False and ok.chain_time == NOW
    nr = r(200, _ready(status="not ready"))
    assert nr.status == "not ready" and nr.to is None and nr.quorum_reached is True
    assert all(r(200, {"status": s, "vault_id": 1, "as_of": {"height": 3}}).status == s for s in ("paid", "refunded"))
    assert r(200, {"status": "paid"}).status == "unreadable"                           # every answer names its vault (v3.4.1)
    assert r(404, {"status": "unknown"}).status == "unknown"
    # "unavailable": the two sources did not agree, so the live fields are not used
    un = r(200, _ready(read="unavailable"))
    assert un.status == "ready" and un.vault_settled is None and un.chain_time is None and un.quorum_reached is True
    for bad in (_ready(status="queued"), _ready(to="nope"), _ready(value="0x0"), _ready(read="maybe"), _ready(digest="0x12"),
                _ready(quorum_reached="yes"), _ready(vault_settled=1), _ready(chain_time=0), _ready(chain_time=-5),
                {k: v for k, v in _ready().items() if k != "chain_time"}, {k: v for k, v in _ready().items() if k != "digest"},
                {k: v for k, v in _ready().items() if k != "read"}, {k: v for k, v in _ready().items() if k != "vault_settled"}):
        assert r(200, bad).status == "unreadable", bad
    assert r(500, None).status == "unreadable" and r(404, {"error": "not found", "code": "not_found"}).status == "unreadable"


def test_sending_the_ready_call_yourself():
    call = b.read_withdrawal_call(200, _ready())
    got = b.self_send_from_call(call, expected(), _payout_vault())
    assert got["ok"] and got["tx"] == {"chainId": 42161, "to": WC["to"], "data": WC["data"], "value": 0}
    assert got["lines"][0] == b.LINE_SELF_SEND_GAS and "pays its network fee (gas)" in b.LINE_SELF_SEND_GAS
    assert got["lines"][1] == "The vault pays exactly 49 USDC to the address in your withdrawal."

    def why(c=call, want=None, vault=None, **body):
        c = b.read_withdrawal_call(200, _ready(**body)) if body else c
        x = b.self_send_from_call(c, want or expected(), vault if vault is not None else _payout_vault())
        return "ok" if x["ok"] else f'{x["reason"]}:{x["text"]}'
    for k, v in (("account", HANDLER), ("nonce", int(PM["nonce"]) + 1), ("recipient", "0x" + "22" * 32),
                 ("amount", int(PM["amount"]) + 1), ("route_kind", 1), ("destination_domain", 26), ("max_fee", 1)):
        field = {"route_kind": "routeKind", "destination_domain": "destinationDomain", "max_fee": "maxFee"}.get(k, k)
        assert why(want=expected(**{k: v})) == f"mismatch:The payout does not match your withdrawal ({field}), so nothing was sent."
    assert why(data=_flip(WC["data"], 4 + 2 * 32 + 31, 0x41)).startswith("mismatch:") and why(data=_flip(WC["data"], 4 + 32 + 31, 1)).startswith("mismatch:")
    assert why(data=_flip(WC["data"], 0, 0)).startswith("encoding:") and "withdraw function" in why(data=_flip(WC["data"], 0, 0))
    assert why(chain_id=1).startswith("chain:") and why(to=HANDLER).startswith("vault:") and why(value=1).startswith("value:")
    assert why(vault_id=2).startswith("vault:") and why(vault=_payout_vault(address=HANDLER)).startswith("vault:")
    assert why(vault=_payout_vault(chain_id="5042")).startswith("chain:")
    assert why(c=b.WithdrawalCall("not ready")).startswith("not-ready:") and why(c=b.WithdrawalCall("paid", vault_id=1)).startswith("not-ready:")
    assert why(vault=_payout_vault(runtime_sha_vault=b.PINS["handler"]["runtime"])).startswith("pin:")
    assert why(vault=_payout_vault(runtime_sha_vault=None)).startswith("pin:")
    assert why(chain_time=int(PM["deadline"])).startswith("expired:") and why(chain_time=None).startswith("unread:")
    assert why(read="unavailable").startswith("unread:")                           # the two sources did not agree: nothing is sent
    assert why(vault_settled=None).startswith("unread:") and why(vault_settled=True) == "state:This payout was already settled."
    assert why(quorum_reached=False).startswith("quorum:") and why(quorum_reached=None).startswith("quorum:")
    T = 1_000_000
    off = b.self_send_offered
    assert off("pending", "ready", T, T + b.SELF_SEND_AFTER_MS) and not off("pending", "ready", T, T + b.SELF_SEND_AFTER_MS - 1)
    assert not off("pending", "ready", None, T) and not off("paid", "ready", T, T + 10 * b.SELF_SEND_AFTER_MS)
    assert not off("pending", "not ready", T, T + 10 * b.SELF_SEND_AFTER_MS) and not off(None, "ready", T, T + 10 * b.SELF_SEND_AFTER_MS)
    assert not off("pending", "ready", T, T + 179_999) and off("pending", "ready", T, T + 180_000)   # the relay is slow after 3 minutes


def test_the_public_reads_a_client_shows():
    acct = "0x3219364FdFAeC2A60D14CDDA6E58Ec65eD33c009"

    def row(**o):
        base = {"account": acct, "nonce": 3, "vault_id": 1, "status": "pending", "amount_6dec": "11000000", "payout_6dec": "10000000",
                "fee_6dec": "1000000", "route": "local", "destination_domain": 3, "recipient": "0x" + "0" * 24 + acct[2:],
                "paid_tx": None, "refunded_6dec": None, "settled_height": None}
        base.update(o)
        return base
    r = b.read_withdrawal_row(row(), acct)
    assert r["status"] == "pending" and r["amount"] == 11_000_000 and r["payout"] == 10_000_000 and r["fee"] == 1_000_000 and r["route"] == "local"
    for other in ("queued", "held", "cancelled", "Held", "signing"):
        assert b.read_withdrawal_row(row(status=other), acct) is None
    assert b.read_withdrawal_row(row(), HANDLER) is None
    paid = b.read_withdrawal_row(row(status="paid", paid_tx="0x" + "ab" * 32, release_after=99, epoch=4), acct)
    assert paid["paid_tx"] == "0x" + "ab" * 32 and "epoch" not in paid and "release_after" not in paid
    rows, err = b.read_withdrawals({"account": acct, "withdrawals": [row(nonce=4, status="paid"), row(), row(status="bogus")]}, acct)
    assert not err and len(rows) == 2 and rows[0]["nonce"] == 4
    v = b.read_vaults(vaults_json())
    d = lambda s, body, h=None: b.read_deposit(s, body, v, h)  # noqa: E731
    c = d(200, credited_row())
    assert c["status"] == "found" and c["row"]["status"] == "credited" and c["row"]["depositId"] == 7 and b.deposit_word(c) == "credited"
    assert b.deposit_line(c) is None
    assert d(404, {"status": "unknown"})["status"] == "unknown" and d(404, {"status": "unknown", "as_of": {"height": 3}})["status"] == "unknown"
    assert d(404, {"error": "not found", "code": "not_found"})["status"] == "unreadable"        # the route is not live / a bad path
    assert d(404, {"status": "unknown", "hint": 1})["status"] == "unreadable"
    un = d(200, {"status": None, "read": "unavailable"})
    assert un == {"status": "unavailable"} and b.deposit_word(un) is None and b.deposit_line(un) == b.LINE_UNAVAILABLE
    assert d(200, {"status": "pending", "read": "unavailable"})["status"] == "unreadable"
    assert d(200, credited_row(status="waiting"))["status"] == "unreadable"                    # a waiting row needs its reason
    na = d(200, deposit_row(status="stranded", reason="stranded", account=None, claim=None))
    assert na["row"]["line"] == b.LINE_STRANDED and b.deposit_word(na) == "stranded" and na["row"]["claim"] is None
    assert b.deposit_word(d(404, {"status": "unknown"})) == "pending" and b.deposit_word(d(200, {"status": "refused"})) is None
    # by transaction: the row must be that transaction's
    assert d(200, credited_row(), "0x" + "ef" * 32)["status"] == "found" and d(200, credited_row(), "0x" + "CD" * 32)["status"] == "found"
    assert d(200, credited_row(), "0x" + "12" * 32)["status"] == "unreadable" and d(200, credited_row(), "0x12")["status"] == "unreadable"
    res = b.read_reserves({"total": {"usdc_6dec": "10", "credited_6dec": "8", "paid_6dec": "1", "pending_withdrawals_6dec": "1",
                                     "liabilities_6dec": "9", "solvent": True, "refunded_6dec": "2", "handler_refunds_owed_6dec": "0"},
                           "read": [{"chain_id": 42161, "block": 5}], "as_of": {"height": 3}, "vaults": [{"id": 1}]})
    assert res["ok"] and res["usdc"] == 10 and res["liabilities"] == 9 and res["refunded"] == 2 and res["solvent"] is True and "vaults" not in res
    t5 = {"usdc_6dec": "10", "credited_6dec": "8", "paid_6dec": "1", "pending_withdrawals_6dec": "1", "liabilities_6dec": "9", "solvent": False}
    assert b.read_reserves({"total": t5, "read": [{"block": None}]})["ok"] and b.read_reserves({"total": t5})["refunded"] is None
    assert not b.read_reserves({"total": t5, "read": [{"block": 0}]})["ok"] and not b.read_reserves({"total": dict(t5, refunded_6dec="x")})["ok"]
    assert not b.read_reserves({"vaults": []})["ok"] and not b.read_reserves({"total": {"usdc_6dec": "x"}})["ok"]
    assert not b.read_reserves({"total": dict(t5, solvent="true")})["ok"] and not b.read_reserves({"total": dict(t5, solvent=1)})["ok"]
    assert not b.read_reserves({"total": {k: v for k, v in t5.items() if k != "solvent"}})["ok"]


def test_building_a_deposit():
    acct = "0x3219364FdFAeC2A60D14CDDA6E58Ec65eD33c009"
    usdc_arc, tm = "0x3600000000000000000000000000000000000000", "0x28b5a0e9C621a5BadaA536219b3a228C8168cf5d"
    sel = lambda s: "0x" + keccak(text=s)[:4].hex()  # noqa: E731
    v = b.read_vaults(vaults_json(direct_open=True, cctp_open=True))
    dc = b.deposit_check(v, 42161, 5_000_000)
    yes, waits, above, unread = {"ok": True, "outcome": "accepted"}, {"ok": True, "outcome": "waits"}, {"ok": True, "outcome": "above_per_deposit_limit"}, {"ok": False}
    txs = b.direct_deposit_txs(dc, v, 42161, USDC_ARB, 5_000_000, yes)
    assert txs[0]["to"] == USDC_ARB and txs[0]["data"] == sel("approve(address,uint256)") + encode(["address", "uint256"], [VAULT, 5_000_000]).hex()
    assert txs[1]["to"] == VAULT and txs[1]["data"] == sel("deposit(uint256)") + encode(["uint256"], [5_000_000]).hex()
    for no, text in ((unread, "cannot be confirmed"), (None, "cannot be confirmed"), (waits, "paused or at a limit"), (above, "above the per-deposit limit")):
        with pytest.raises(ValueError, match=text):
            b.direct_deposit_txs(dc, v, 42161, USDC_ARB, 5_000_000, no)
    for sha in (b.PINS["handler"]["runtime"], None):
        j = vaults_json(direct_open=True, cctp_open=True)
        j["vaults"][0]["runtime_sha256"]["vault"] = sha
        with pytest.raises(ValueError, match="does not match the published code"):
            b.direct_deposit_txs(dc, b.read_vaults(j), 42161, USDC_ARB, 5_000_000, yes)
    cc = b.deposit_check(v, 5042, 10_001_000, 1_000, b.sender_check(WALLET, None))
    arc = b.arc_deposit_txs(cc, v, 5042, usdc_arc, tm, acct, 10_001_000, 1_000, yes, False)
    hook = bytes.fromhex(b.hook_data(acct, False)[2:])
    want = sel("depositForBurnWithHook(uint256,uint32,bytes32,address,bytes32,uint256,uint32,bytes)") + encode(
        ["uint256", "uint32", "bytes32", "address", "bytes32", "uint256", "uint32", "bytes"],
        [10_001_000, 3, bytes.fromhex("0" * 24 + HANDLER[2:]), usdc_arc, bytes.fromhex("0" * 24 + HANDLER[2:]), 1_000, 2000, hook]).hex()
    assert arc[0]["chainId"] == 5042 and arc[0]["data"] == sel("approve(address,uint256)") + encode(["address", "uint256"], [tm, 10_001_000]).hex()
    assert arc[1]["to"] == tm and arc[1]["data"] == want
    # a deposit that would wait is built only once the user has seen the Waiting line and confirmed
    with pytest.raises(ValueError, match="Press Deposit again"):
        b.arc_deposit_txs(cc, v, 5042, usdc_arc, tm, acct, 10_001_000, 1_000, waits, False)
    assert b.arc_deposit_txs(cc, v, 5042, usdc_arc, tm, acct, 10_001_000, 1_000, waits, True) == arc
    for no in (above, unread, None):
        with pytest.raises(ValueError, match="above the per-deposit limit|cannot be confirmed"):
            b.arc_deposit_txs(cc, v, 5042, usdc_arc, tm, acct, 10_001_000, 1_000, no, True)
    with pytest.raises(ValueError):
        b.arc_deposit_txs(cc, v, 42161, usdc_arc, tm, acct, 10_001_000, 1_000, yes, False)
    assert b.DEPOSIT_FOR_BURN_WITH_HOOK_SELECTOR == sel("depositForBurnWithHook(uint256,uint32,bytes32,address,bytes32,uint256,uint32,bytes)")
    assert b.CCTP_DEPOSIT_FINALITY == 2000
    # the handler is proven to be the vault's own before any burn (section 5.1): from the vaults read, confirmed by two sources
    vault = v.vaults[0]
    assert b.binding_check(vault)["ok"]
    bad = {"the read did not confirm the binding": {"binding_confirmed": None}, "the binding was refused": {"binding_confirmed": False},
           "the handler names another vault": {"binding_handler_vault": HANDLER}, "the handler names no vault": {"binding_handler_vault": None},
           "another CCTP domain": {"binding_local_domain": 26}, "no USDC read": {"binding_usdc": None},
           "the handler code is not the pin": {"runtime_sha_handler": b.PINS["vault"]["runtime"]}, "the handler code was not read": {"runtime_sha_handler": None},
           "the vault code is not the pin": {"runtime_sha_vault": b.PINS["handler"]["runtime"]}, "the vault code was not read": {"runtime_sha_vault": None},
           "the handler is not CREATE(vault, 1)": {"handler": "0x" + "77" * 20}, "no handler": {"handler": None}}
    for what, change in bad.items():
        wrong = replace(vault, **change)
        assert not b.binding_check(wrong)["ok"], what
        rv = replace(v, vaults=(wrong,))
        with pytest.raises(ValueError, match="could not be confirmed|not a checked"):
            b.arc_deposit_txs(b.deposit_check(rv, 5042, 10_001_000, 1_000, b.sender_check(WALLET, None)), rv, 5042, usdc_arc, tm, acct, 10_001_000, 1_000, yes, False)
    assert b.binding_check(replace(vault, runtime_sha_vault=b.TESTNET_VAULT_PIN["runtime"])) == {"ok": False, "text": "This is a test-network vault, so nothing was built."}
    assert not b.binding_check(None)["ok"]


def test_sending_the_ready_call_from_your_own_key_signs_only_that_call(monkeypatch):
    """With the JSON-RPC answered in the test (no chain, no server): the helper signs the checked call, and nothing else,
    with the given key, and refuses a call that was not checked or is for another chain."""
    import requests
    key = "0x" + keccak(text="vordium-v4-test-account-1").hex()          # a published TEST key; holds nothing
    seen = []

    class Answer:
        def __init__(self, body):
            self.body = body

        def json(self):
            return self.body

    def post(url, json=None, timeout=None):
        assert url == "https://rpc.invalid"
        seen.append(json)
        res = {"eth_chainId": hex(42161), "eth_getTransactionCount": "0x7", "eth_estimateGas": hex(210_000),
               "eth_getBlockByNumber": {"baseFeePerGas": hex(10_000_000)}, "eth_maxPriorityFeePerGas": hex(1_000),
               "eth_sendRawTransaction": "0x" + "ab" * 32}[json["method"]]
        return Answer({"jsonrpc": "2.0", "id": json["id"], "result": res})
    monkeypatch.setattr(requests, "post", post)
    checked = b.self_send_from_call(b.read_withdrawal_call(200, _ready()), expected(), _payout_vault())
    h = b.send_self_send(key, checked, "https://rpc.invalid")
    assert h == "0x" + "ab" * 32
    raw = next(r for r in seen if r["method"] == "eth_sendRawTransaction")["params"][0]
    tx = Account.recover_transaction(raw)
    assert tx == Account.from_key(key).address
    from eth_account.typed_transactions import TypedTransaction
    from hexbytes import HexBytes
    t = TypedTransaction.from_bytes(HexBytes(raw)).as_dict()
    to = t["to"] if isinstance(t["to"], str) else "0x" + bytes(t["to"]).hex()
    assert t["chainId"] == 42161 and to.lower() == WC["to"].lower() and t["value"] == 0
    assert "0x" + bytes(t["data"]).hex() == WC["data"].lower() and t["nonce"] == 7
    n = len(seen)
    with pytest.raises(ValueError):
        b.send_self_send(key, {"ok": False, "text": "no"}, "https://rpc.invalid")
    assert len(seen) == n                                   # an unchecked call reaches no RPC at all
    wrong = dict(checked, tx=dict(checked["tx"], chainId=5042))
    with pytest.raises(ValueError):
        b.send_self_send(key, wrong, "https://rpc.invalid")
    assert not any(r["method"] == "eth_sendRawTransaction" for r in seen[n:])


def test_hook_data_and_pins():
    a = "0x3219364FdFAeC2A60D14CDDA6E58Ec65eD33c009"
    assert b.hook_data(a, False) == "0x" + "0" * 24 + a[2:].lower()
    assert b.hook_data(a, True) == b.FORWARD_HEADER_V0 + "0" * 24 + a[2:].lower()
    P = V32["pins"]                                     # the v3.4 pins: none of them matches the v3.5 pins (test_bridge_v4_v35)
    assert b.PINS["interface"] == "v3.5"
    for name in ("VordiumVaultV4TestnetOnly", "VordiumVaultV4", "VordiumCctpHandlerV4"):
        assert b.vault_build(P[name]["runtimeSha256"]) == "unknown"
        assert b.runtime_pin("vault", P[name]["runtimeSha256"]) == "mismatch" and b.runtime_pin("handler", P[name]["runtimeSha256"]) == "mismatch"
    assert b.vault_build(b.TESTNET_VAULT_PIN["runtime"]) == "testnet-only" and b.vault_build(b.PINS["vault"]["runtime"]) == "vault"
    assert b.runtime_pin("vault", "0x" + b.PINS["vault"]["runtime"]) == "match"
    assert b.runtime_pin("vault", "bf39eb94b8760289659ce9fff9c88c92ad6c35854bf7a18d8e518f8b358a4578") == "mismatch"
    assert b.creation_pin(b.PINS["vault"]["creation"].upper()) == "match"
    assert b.creation_pin(b.PINS["vault"]["runtime"]) == "mismatch"


def test_everything_that_signs_or_sends_refuses_while_off():
    b.ENABLED = False
    v = b.read_vaults(vaults_json(direct_open=True))
    i = intent_of(V["vectors"][0])
    row = b.read_deposit_row(deposit_row(), v)
    for call in (lambda: b.deposit_check(v, 42161, 50_000_000), lambda: b.build_withdraw_intent(v, i, 1, 0),
                 lambda: b.withdraw_intent_signable(i), lambda: b.sign_withdraw_intent("0x" + "11" * 32, i),
                 lambda: b.submit_body(i, "0x" + "00" * 65), lambda: b.claim_refund_tx(HANDLER, VAULT, HANDLER, HANDLER),
                 lambda: b.refund_claim(row, BY, v.vaults[0]),
                 lambda: b.self_send_from_call(b.WithdrawalCall("ready", vault_id=1, chain_id=42161, to=VAULT, data="0x", value=0), expected(), v.vaults[0]),
                 lambda: b.direct_deposit_txs(b.DepositCheck(ok=True, kind="direct", vault_id=1, vault=VAULT), v, 42161, VAULT, 1, {"ok": True, "outcome": "accepted"}),
                 lambda: b.arc_deposit_txs(b.DepositCheck(ok=True, kind="cctp", vault_id=1, vault=VAULT, handler=HANDLER), v, 5042, VAULT, VAULT, VAULT, 1, 0, None, False),
                 lambda: b.send_self_send("0x" + "11" * 32, {"ok": True, "tx": {}}, "https://rpc.invalid"),
                 lambda: b.fetch_withdrawal_call(VAULT, 1), lambda: b.fetch_account_code(42161, VAULT),
                 lambda: b.fetch_deposit_allowed(42161, VAULT, 1), lambda: b.fetch_deposit_by_tx("0x" + "ab" * 32, v),
                 lambda: b.fetch_deposits(VAULT, v),
                 lambda: b.fetch_vaults(), lambda: b.fetch_next_nonce(HANDLER), lambda: b.submit_withdrawal(i, "0x" + "00" * 65)):
        with pytest.raises(b.BridgeV4Off):
            call()
    assert b.read_vaults(vaults_json()).ok and b.read_fee_quote(V32["feeQuote"]).ok     # the pure readers still work
    assert b.read_deposit_row(deposit_row(), v) is not None and b.read_deposit_allowed(200, {"allowed": True, "code": 0, "read": "ok",
                                                                                            "as_of": {"chain_id": 42161, "block": 1}}, 42161)["ok"]


# Names the package must never carry, held as sha-256 of each identifier so this public test does not spell them.
_ABSENT = {
    "02d3807bc4ff792c614aba645e813a545b5ed7ae98b2fa20bd2653e99142488f",
    "26cfe06efa252f1ad8dfdd41fb9c128a44ee3a1550c39e0cd7976521a3cb0eeb",
    "3abb708319c6026109923cdc60a24e9111bec25b9170fbcbcef7effb33c4ea65",
    "4ea408c9b0f098ccd2c2b8444ae72a7ddf1377ecebef795bf4a18fd755fd0441",
    "75cb79d84c199769cbd8d085a0592040c826f06ada92adf2027b2e57adb7b619",
    "8e61d74d1499bb55ef683af6d24e286d915a33eb8f541595d754cfe07017cfbb",
    "a111671e2e91cc1ea1e88f6ad8c78f4eec6bc303deeabe07364b0e2de2a8088a",
    "b09e358bf75626eaff4207731ca45db344d57452b3d28b11aeb311f696b3b5a6",
    "b72ca9a773de4b94a51d5e5974607fc26d5b71aaccb92d4ac06d0a80f2793e3c",
    "bcc1d2060caad4490b356a83d8569a307ee5f551a3ecf0a49e2a9db68469254e",
    "c39961f8f50ab4b96d330849d391ff85619be7b66808e3aefa8c30dc07002ef2",
    "e5fbeaa096d1b726c904d7a12d3fb8dbfbaa89ff4d5c892cb90a4e74adef3571",
    "eef1f68e022e3100372ad0b0e15eee8d6c03c134645970e588d585cd6c93d9f1",
}


def _runs(t):
    """Every run of whole name parts inside one identifier (camelCase and snake_case), so a name inside a longer one
    (a builder called build_X or buildX) is still seen."""
    cut = {0, len(t)} | {i for i in range(1, len(t)) if t[i] == "_" or t[i - 1] == "_" or (t[i].isupper() and not t[i - 1].isupper())
                                  or (t[i].isupper() and t[i - 1].isupper() and i + 1 < len(t) and t[i + 1].islower())}
    cut = sorted(cut)
    return {t[x:y] for k, x in enumerate(cut) for y in cut[k + 1:]}


def test_no_vault_change_builders_or_owner_envelopes_in_the_package():
    pkg = Path(b.__file__).parent
    text = "\n".join(p.read_text() for p in pkg.rglob("*") if p.suffix in (".py", ".json"))
    tokens = set(re.findall(r"[A-Za-z0-9_]+", text))
    found = sorted({part for t in tokens for part in _runs(t) if hashlib.sha256(part.encode()).hexdigest() in _ABSENT})
    assert not found, found
    assert len(_ABSENT) == 13 and len(tokens) > 500      # the scan read the package
    import vordium
    assert "from . import bridge_v4" in Path(vordium.__file__).read_text()      # the release exports the bridge
