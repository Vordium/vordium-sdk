"""Bridge v4 interface v3.4.1 -- against the published v3.4.1 test data (tests/vectors/bridge-v4-v341.json): the public
lines for codes 2, 5 and 7 and the Waiting line; a not-accepted deposit is read by its stable reason key, never its text;
one deposit row is read whole (its 17 names) or not at all, and no read says "waiting"; deposit-allowed is read for its
coarse outcome only (accepted / waits / above the per-deposit limit) and the code behind it is never returned; a live
read that two sources could not confirm is unavailable, never a guess; an account's deposits are read with their totals."""

import json
from pathlib import Path

import pytest

from vordium import bridge_v4 as b

V = json.loads((Path(__file__).parent / "vectors" / "bridge-v4-v341.json").read_text())
VAULT = "0xeBbaa620Ee72874237172A5DF16723f81Bd47642"
HANDLER = json.loads((Path(__file__).parent / "vectors" / "bridge-v4-v34.json").read_text())["testHandler"]
BY = "0x8FeD45485e06C1496E0DF1b2e11a87c53e292e39"
OTHER = "0x3219364FdFAeC2A60D14CDDA6E58Ec65eD33c009"
LINE = "Not accepted: below the minimum deposit (5 USDC from Arbitrum, 10 USDC from Arc)."


def vaults_json():
    return {"active": True, "vaults": [{
        "id": 1, "chain_id": 42161, "address": VAULT, "handler": HANDLER, "cctp_domain": 3,
        "deposits": {"direct": {"chain_id": 42161, "minimum_6dec": "5000000"}, "cctp": {"from_chain_ids": [5042], "minimum_6dec": "10000000"}},
        "withdrawals": {"routes": [{"route_kind": 0, "name": "local", "open": True}], "fee_6dec": "1000000"},
        "runtime_sha256": {"vault": b.PINS["vault"]["runtime"], "handler": b.PINS["handler"]["runtime"]},
        "binding": {"handler_vault": VAULT, "local_domain": 3, "usdc": "0xaf88d065e77c8cC2239327C5EDb3A432268e5831", "confirmed": True}}],
        "depositsOpen": {"42161": True, "5042": True}, "minimumDeposit6dec": {"42161": "5000000", "5042": "10000000"},
        "withdrawalFee6dec": "1000000", "as_of": {"height": 7}}


VR = b.read_vaults(vaults_json())


def na_row(**o):
    x = {"status": "not accepted", "reason": "not_completed", "text": "node text", "kind": "cctp", "account": BY, "amount_6dec": "9000000",
         "vault_id": 1, "chain_id": 42161, "deposit_id": None, "source_domain": 26, "nonce": "0x" + "ab" * 32, "source_chain_id": None,
         "source_tx": None, "vault_tx": "0x" + "cd" * 32, "credited_height": None, "as_of": {"height": 4},
         "claim": {"chain_id": 42161, "handler": HANDLER, "by": BY, "amount_6dec": "9000000", "refundable_6dec": "9000000", "read": "ok"}}
    x.update(o)
    return x


def credited(**o):
    return na_row(**{"status": "credited", "reason": None, "text": None, "claim": None, "credited_height": 55, **o})


def allowed(**o):
    x = {"allowed": True, "code": 0, "as_of": {"chain_id": 42161, "block": 123}, "read": "ok"}
    x.update(o)
    return x


@pytest.fixture(autouse=True)
def _enabled():
    was = b.ENABLED
    b.ENABLED = True
    yield
    b.ENABLED = was


def test_the_public_lines_are_the_published_ones():
    L = V["publicLines"]
    assert b.LINE_OVER_CAP == L["2"] and b.LINE_NOT_COMPLETED == L["7"] and b.LINE_WAITING == L["waiting"]
    assert b.LINE_WILL_WAIT.startswith(L["waiting"] + " ")            # the Waiting line, shown before the burn
    # v3.5 retires the code-5 "claimed back by the sender" line, the code-9 "returned" line and "under review"
    assert not any(hasattr(b, n) for n in ("LINE_ACCOUNT_UNREADABLE", "LINE_RETURNED", "LINE_UNDER_REVIEW", "DEPOSIT_STATUSES_PROPOSED"))
    by_key = {"above_per_deposit_limit": L["2"], "not_completed": L["7"], "below_minimum": LINE, "waiting": L["waiting"],
              "stranded": b.LINE_STRANDED, "rescued": b.LINE_RESCUED, "other": "Not accepted."}
    assert all(b.reason_line(k, VR, "42161") == want for k, want in by_key.items())


def test_the_row_names_statuses_and_reason_keys_are_the_published_ones():
    assert list(b.DEPOSIT_ROW_FIELDS) == V["depositRow"]["fields"] and len(b.DEPOSIT_ROW_FIELDS) == 17
    assert b.DEPOSIT_STATUSES == ("pending", "credited", "waiting", "stranded", "not accepted")               # v3.5
    assert b.DEPOSIT_REASONS == ("waiting", "stranded", "rescued", "above_per_deposit_limit", "not_completed", "below_minimum", "other")
    assert list(b.DEPOSIT_OUTCOMES) == list(V["depositAllowed"]["outcomes"])
    assert b.HANDLER_REASONS == {"waits": [1, 3, 4], "refundsToBeneficiary": [2, 7, 8], "stranded": [5], "rescued": 9}


def test_a_row_is_read_whole_or_not_at_all():
    r = b.read_deposit_row(na_row(), VR)
    assert r["status"] == "not accepted" and r["reason"] == "not_completed" and r["line"] == V["publicLines"]["7"]
    assert r["claim"] == {"chainId": "42161", "chain": "Arbitrum", "handler": HANDLER, "by": BY, "amount": 9_000_000, "refundable": 9_000_000, "checked": True}
    assert b.read_deposit_row(na_row(text="Claim it from support."), VR)["line"] == V["publicLines"]["7"]   # the key decides, never the text
    for f in V["depositRow"]["fields"]:
        assert b.read_deposit_row({k: v for k, v in na_row().items() if k != f}, VR) is None, f"a row without {f} was read"
        assert b.read_deposit_row({k: v for k, v in credited().items() if k != f}, VR) is None, f"a credited row without {f} was read"
    c = b.read_deposit_row(credited(), VR)
    assert c["status"] == "credited" and c["reason"] is None and c["line"] is None and c["creditedHeight"] == 55
    bad = {
        "a waiting status": na_row(status="waiting"), "a status in capitals": credited(status="Credited"),
        "an unknown reason key": na_row(reason="paused"), "a not-accepted row with no reason": na_row(reason=None),
        "a reason on a credited row": credited(reason="other"), "a credited row with no height": credited(credited_height=None),
        "a pending row with a height": credited(status="pending"), "a height of 0": credited(credited_height=0),
        "no account outside a stranded row": na_row(account=None), "a waiting row with a claim": na_row(status="waiting", reason="waiting"),
        "a stranded row with a claim": na_row(status="stranded", reason="stranded"),
        "a waiting status with the stranded reason": na_row(status="waiting", reason="stranded", claim=None),
        "a not-accepted row with the waiting reason": na_row(reason="waiting"), "a rescued row with no claim": na_row(reason="rescued", claim=None), "a not-accepted direct deposit": na_row(kind="direct", source_domain=None, nonce=None),
        "a deposit id on a refused message": na_row(deposit_id=3), "a CCTP row with no source domain": na_row(source_domain=None),
        "a direct row with a nonce": credited(kind="direct", source_domain=None), "a source tx without its chain": credited(source_tx="0x" + "ee" * 32),
        "a direct row whose source chain is not the vault's": credited(kind="direct", source_domain=None, nonce=None, source_chain_id=5042, source_tx="0x" + "ee" * 32),
        "a live block of 0": credited(as_of={"chain_id": 42161, "block": 0}), "no as_of": credited(as_of={}),
        "a claim on a credited row": credited(claim=na_row()["claim"]), "a not-accepted row with no claim": na_row(claim=None),
        "a claim owed to someone other than the deposit's account": na_row(claim=dict(na_row()["claim"], by=OTHER)),
        "an unavailable claim that still carries an amount": na_row(claim=dict(na_row()["claim"], read="unavailable")),
        "a claim with an unknown read state": na_row(claim=dict(na_row()["claim"], read="maybe")),
        "an ok claim without an amount": na_row(claim=dict(na_row()["claim"], refundable_6dec=None)),
        "an amount that is not base units": na_row(amount_6dec="9.5"), "a text that is not text": na_row(text=7),
    }
    for what, row in bad.items():
        assert b.read_deposit_row(row, VR) is None, what
    # v3.5: the account could not be read (code 5) -> stranded, owed to nobody until a recovery: no claim
    un = b.read_deposit_row(na_row(status="stranded", reason="stranded", account=None, claim=None), VR)
    assert un["line"] == b.LINE_STRANDED and un["claim"] is None and un["account"] is None
    r9 = b.read_deposit_row(na_row(reason="rescued", claim=dict(na_row()["claim"], by=OTHER)), VR)
    assert r9["line"] == b.LINE_RESCUED and r9["claim"]["by"] == OTHER                       # a recovery names its own address
    assert b.read_deposit_row(na_row(reason="below_minimum", claim=None), VR)["claim"] is None   # code 6: nothing owed
    two = b.read_deposit_row(na_row(reason="above_per_deposit_limit"), VR)
    assert two["line"] == V["publicLines"]["2"]
    unconfirmed = b.read_deposit_row(na_row(claim=dict(na_row()["claim"], refundable_6dec=None, read="unavailable")), VR)
    assert unconfirmed["claim"]["refundable"] is None


def test_lookups_unknown_unavailable_and_not_found():
    R = V["reads"]
    d = b.read_deposit
    assert d(404, R["unknown404"], VR) == {"status": "unknown"} and b.deposit_word(d(404, R["unknown404"], VR)) == "pending"
    assert d(404, R["notFound404"], VR)["status"] == "unreadable"
    un = d(200, {"status": None, "read": R["unavailable"]}, VR)
    assert un == {"status": "unavailable"} and b.deposit_word(un) is None and b.deposit_line(un) == b.LINE_UNAVAILABLE
    ok = d(200, dict(credited(), read=R["ok"]), VR)
    assert ok["status"] == "found" and b.deposit_word(ok) == "credited"
    assert d(200, dict(credited(), read="partial"), VR)["status"] == "unreadable"
    # by transaction: the hash must be the row's vault-chain transaction or the transaction the user sent
    arc = credited(source_chain_id=5042, source_tx="0x" + "12" * 32)
    assert d(200, arc, VR, "0x" + "12" * 32)["status"] == "found" and d(200, arc, VR, "0x" + "cd" * 32)["status"] == "found"
    assert d(200, arc, VR, "0x" + "34" * 32)["status"] == "unreadable"
    pend = credited(status="pending", credited_height=None, nonce=None, vault_tx=None, source_chain_id=5042, source_tx="0x" + "12" * 32)
    p = d(200, pend, VR, "0x" + "12" * 32)
    assert p["status"] == "found" and b.deposit_word(p) == "pending" and b.deposit_line(p) is None   # pending, never waiting


def test_deposit_allowed_is_read_for_its_coarse_outcome_only():
    O = V["depositAllowed"]["outcomes"]
    for code in range(0, 12):
        want = next((k for k, codes in O.items() if code in codes and k != "accepted"), None)
        got = b.read_deposit_allowed(200, allowed(allowed=False, code=code), 42161)
        assert got == ({"ok": True, "outcome": want} if want else {"ok": False}), code
        assert "code" not in got and str(code) not in json.dumps(got).replace("42161", "")   # the code is never returned
    assert b.read_deposit_allowed(200, allowed(), 42161) == {"ok": True, "outcome": "accepted"}
    assert b.read_deposit_allowed(200, allowed(code=1), 42161) == {"ok": False}                 # allowed with a code: unreadable
    for o in O:
        assert b.read_deposit_allowed(200, {"outcome": o, "as_of": {"chain_id": 42161, "block": 9}, "read": "ok"}, 42161) == {"ok": True, "outcome": o}
    assert b.read_deposit_allowed(200, {"outcome": "waits", "allowed": True, "as_of": {"chain_id": 42161, "block": 9}, "read": "ok"}, 42161) == {"ok": False}
    assert b.read_deposit_allowed(200, {"outcome": "paused", "as_of": {"chain_id": 42161, "block": 9}, "read": "ok"}, 42161) == {"ok": False}
    for what, s, body in (("unavailable", 200, allowed(read="unavailable", allowed=None)), ("no read", 200, {k: v for k, v in allowed().items() if k != "read"}),
                          ("another chain", 200, allowed(as_of={"chain_id": 5042, "block": 1})), ("block null", 200, allowed(as_of={"chain_id": 42161, "block": None})),
                          ("block 0", 200, allowed(as_of={"chain_id": 42161, "block": 0})), ("committed height", 200, allowed(as_of={"height": 3})),
                          ("allowed not a bool", 200, allowed(allowed="true")), ("code not a number", 200, allowed(allowed=False, code="3")),
                          ("HTTP 404", 404, V["reads"]["notFound404"]), ("HTTP 429", 429, {"code": "rate_limited"})):
        assert b.read_deposit_allowed(s, body, 42161) == {"ok": False}, what
    # the Waiting line is shown BEFORE the burn, and only a CCTP deposit may be sent anyway
    waits = {"ok": True, "outcome": "waits"}
    assert b.pre_burn(waits, "cctp", False) == {"ok": False, "ask": True, "line": b.LINE_WILL_WAIT}
    assert b.pre_burn(waits, "cctp", True) == {"ok": True} and not b.pre_burn(waits, "direct", True)["ok"]
    assert b.pre_burn({"ok": True, "outcome": "accepted"}, "direct", False) == {"ok": True}
    assert "above the per-deposit limit" in b.pre_burn({"ok": True, "outcome": "above_per_deposit_limit"}, "cctp", True)["text"]
    assert "cannot be confirmed" in b.pre_burn({"ok": False}, "cctp", True)["text"] and "cannot be confirmed" in b.pre_burn(None, "cctp", True)["text"]


def test_an_accounts_deposits():
    def body(rows, **o):
        x = {"account": BY.lower(), "deposits": rows, "totals": {"pending_6dec": "1", "credited_6dec": "55", "not_accepted_6dec": "9000000"},
             "count": len(rows or []), "limit": 500, "as_of": {"height": 9}}
        x.update(o)
        return x
    owed_to_me = na_row(reason="rescued", account=OTHER, claim=dict(na_row()["claim"], by=BY))   # a recovery owed to this account
    r = b.read_deposits(body([credited(), na_row(), owed_to_me, {"status": "waiting"}, credited(account=OTHER)]), BY, VR)
    assert r["ok"] and len(r["rows"]) == 3 and r["unreadable"] == 2 and r["totals"] == {"pending": 1, "credited": 55, "notAccepted": 9_000_000}
    assert r["count"] == 5 and r["more"] is False
    assert b.read_deposits(body([credited()], count=800), BY, VR)["more"] is True
    for what, j in (("another account", body([], account=OTHER)), ("more rows than the count", body([credited()], count=0)),
                    ("more rows than the limit", body([credited()], limit=0)), ("a total that is not base units", body([], totals={"pending_6dec": "x", "credited_6dec": "0", "not_accepted_6dec": "0"})),
                    ("no totals", body([], totals=None)), ("no as_of", body([], as_of=None)), ("not a list", body(None)), ("nothing", None)):
        assert not b.read_deposits(j, BY, VR)["ok"], what


def test_the_vaults_read_carries_live_code_hashes_and_the_binding():
    ok = b.read_vaults(vaults_json())
    v = ok.vaults[0]
    assert ok.ok and v.runtime_sha_vault == b.PINS["vault"]["runtime"] and v.binding_confirmed is True and v.binding_local_domain == 3

    def edit(f):
        j = vaults_json()
        f(j["vaults"][0])
        return b.read_vaults(j)
    bad = {"a code hash that is not a sha256": lambda x: x["runtime_sha256"].update(vault="zz"),
           "runtime_sha256 not an object": lambda x: x.update(runtime_sha256="x"),
           "a binding vault that is not an address": lambda x: x["binding"].update(handler_vault="0x12"),
           "a binding USDC that is not an address": lambda x: x["binding"].update(usdc=7),
           "a binding domain that is not a number": lambda x: x["binding"].update(local_domain="three"),
           "confirmed that is not a boolean": lambda x: x["binding"].update(confirmed="true"),
           "binding not an object": lambda x: x.update(binding=[])}
    for what, f in bad.items():
        assert not edit(f).ok, what
    un = edit(lambda x: x.update(runtime_sha256={"vault": None, "handler": None}, binding={"handler_vault": None, "local_domain": None, "usdc": None, "confirmed": None}))
    assert un.ok and un.vaults[0].runtime_sha_vault is None and un.vaults[0].binding_confirmed is None
    upper = edit(lambda x: x["runtime_sha256"].update(handler="0x" + b.PINS["handler"]["runtime"].upper()))
    assert upper.vaults[0].runtime_sha_handler == b.PINS["handler"]["runtime"]


def test_the_claim_goes_only_through_the_vault_reads_own_handler():
    from dataclasses import replace
    vault = VR.vaults[0]
    row = b.read_deposit_row(na_row(), VR)
    assert b.refund_claim(row, BY, vault)["ok"]

    def why(vt):
        x = b.refund_claim(row, BY, vt)
        return "ok" if x["ok"] else x["reason"]
    assert why(replace(vault, handler=OTHER)) == "handler" and why(replace(vault, chain_id="5042")) == "handler"
    assert why(replace(vault, handler=None)) == "handler" and why(None) == "handler"
    node_only = {k: v for k, v in na_row()["claim"].items() if k not in ("read",)}
    assert b.read_deposit_row(na_row(claim=node_only), VR)["claim"]["refundable"] is None   # an amount without the read's confirmation is not used


def test_v35_retires_under_review_and_the_returned_line():
    """v3.5: code 9 is ``rescued`` (its own line); "under review" is not a status -- a deposit no one can be owed is stranded."""
    assert b.LINE_RESCUED == "Owed to you on Arbitrum by a recovery: claim it there."
    assert b.LINE_STRANDED == "Waiting for a recovery: the deposit's account could not be read. Nothing is lost."
    assert all(b.reason_line(k, VR, "42161") == "Not accepted." for k in ("something_new", "", "Other", "other"))
    assert b.deposit_status("under review") is None and b.deposit_status("waiting") == "waiting"
    assert all(b.deposit_status(w) is None for w in ("Under review", "under_review", "Waiting", "held", "Stranded"))

