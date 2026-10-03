"""Bridge v4, contracts v3.4 -- against the published v3.4 test data (tests/vectors/bridge-v4-v34.json): claimRefundTo
and the CCTP deposit into the handler reproduce the published calldata byte for byte; the handler's reason keys are the
published ones; the per-withdrawal maximum is read under its published name; the fee quote has one name; the handler is
the one the vault created (CREATE(vault, nonce 1)); a validator signature has v 27 or 28 and a low s; the refund goes to
the owed address or to another address typed with its checksum, never the handler or the vault. (The v3.4.1 lines and
reads: test_bridge_v4_v341.py.)"""

import json
from pathlib import Path

import pytest
from eth_abi import encode
from eth_utils import keccak, to_checksum_address

from vordium import bridge_v4 as b

V = json.loads((Path(__file__).parent / "vectors" / "bridge-v4-v34.json").read_text())
VAULT = V["testVault"]
HANDLER = V["testHandler"]
#: v3.5: the system's own addresses -- the vault, its handler (CREATE nonce 1) and its set rules (CREATE nonce 2)
OWN = [VAULT.lower(), b.create_address(VAULT, 1), b.create_address(VAULT, 2)]
LINE = "Not accepted: below the minimum deposit (5 USDC from Arbitrum, 10 USDC from Arc)."
BY = "0x8FeD45485e06C1496E0DF1b2e11a87c53e292e39"
OTHER = "0x3219364FdFAeC2A60D14CDDA6E58Ec65eD33c009"
USDC_ARB = "0xaf88d065e77c8cC2239327C5EDb3A432268e5831"
USDC_ARC = "0x3600000000000000000000000000000000000000"
TM = "0x28b5a0e9C621a5BadaA536219b3a228C8168cf5d"


def sig_of(entry):
    return entry["name"] + "(" + ",".join(i["type"] if i["type"] != "tuple" else "(" + ",".join(c["type"] for c in i["components"]) + ")"
                                         for i in entry["inputs"]) + ")"


def sel(s):
    return "0x" + keccak(text=s)[:4].hex()


ABI = {w: {e["name"]: e for e in V["abi"][w]} for w in ("vault", "handler")}


def vaults_json(direct_open=True, cctp_open=True, maximum=None):
    w = {"routes": [{"route_kind": 0, "name": "local", "open": True},
                    {"route_kind": 1, "name": "standard", "open": False},
                    {"route_kind": 2, "name": "fast", "open": False},
                    {"route_kind": 3, "name": "standard-forwarded", "open": False},
                    {"route_kind": 4, "name": "fast-forwarded", "open": False}],
         "fee_6dec": "1000000"}
    if maximum is not None:
        w["maximum_6dec"] = maximum
    return {
        "active": True,
        "vaults": [{
            "id": 1, "chain": "arbitrum", "chain_id": 42161, "address": VAULT, "handler": HANDLER, "cctp_domain": 3,
            "deposits": {"direct": {"chain_id": 42161, "minimum_6dec": "5000000", "open": direct_open},
                         "cctp": {"from_chain_ids": [5042], "minimum_6dec": "10000000", "open": cctp_open}},
            "withdrawals": w,
            "runtime_sha256": {"vault": b.PINS["vault"]["runtime"], "handler": b.PINS["handler"]["runtime"]},
            "binding": {"handler_vault": VAULT, "local_domain": 3, "usdc": USDC_ARB, "confirmed": True},
        }],
        "depositsOpen": {"42161": direct_open, "5042": cctp_open},
        "minimumDeposit6dec": {"42161": "5000000", "5042": "10000000"},
        "withdrawalFee6dec": "1000000",
        "feeQuote": json.loads(json.dumps(V["feeQuote"])),
        "as_of": {"height": 7},
    }


def row(reason="not_completed", handler=HANDLER):
    """A not-accepted deposit row (interface v3.4.1 section 23.2), confirmed as still claimable."""
    return {"status": "not accepted", "reason": reason, "text": "node text", "kind": "cctp", "account": BY, "amount_6dec": "9000000",
            "vault_id": 1, "chain_id": 42161, "deposit_id": None, "source_domain": 26, "nonce": "0x" + "ab" * 32, "source_chain_id": None,
            "source_tx": None, "vault_tx": "0x" + "cd" * 32, "credited_height": None, "as_of": {"height": 4},
            "claim": {"chain_id": 42161, "handler": handler, "by": BY, "amount_6dec": "9000000", "refundable_6dec": "9000000", "read": "ok"}}


def w32(a):
    return "0x" + "0" * 24 + a[2:].lower()


ACCEPTED = {"ok": True, "outcome": "accepted"}


@pytest.fixture(autouse=True)
def _enabled():
    was = b.ENABLED
    b.ENABLED = True
    saved = dict(b.V34)
    yield
    b.ENABLED = was
    b.V34.clear()
    b.V34.update(saved)


def test_the_switches():
    assert b.V34["encoders"] is True and b.V34["max_per_withdrawal_field"] == "maximum_6dec"
    assert "withdrawals.maximum_6dec" in V["perWithdrawalMaximum"]["read"]
    b.ENABLED = False
    with pytest.raises(b.BridgeV4Off):
        b.claim_refund_tx(HANDLER, OWN, BY, BY, OTHER)


def test_claim_refund_to_reproduces_the_published_calldata():
    E = V["claimRefundTo"]
    assert b.CLAIM_REFUND_TO_SELECTOR == E["selector"] == sel(sig_of(ABI["handler"]["claimRefundTo"]))
    tx = b.claim_refund_tx(HANDLER, OWN, BY, BY, E["example"]["to"])
    assert tx == {"to": HANDLER, "data": E["example"]["calldata"], "value": 0}
    assert tx["data"] == E["selector"] + encode(["address"], [E["example"]["to"]]).hex()
    assert b.claim_refund_tx(HANDLER, OWN, BY, BY, BY)["data"] == b.CLAIM_REFUND_SELECTOR == sel(sig_of(ABI["handler"]["claimRefund"]))
    with pytest.raises(ValueError, match="Only the address that is owed"):
        b.claim_refund_tx(HANDLER, OWN, OTHER, BY, OTHER)
    for to in ("0x" + "0" * 40, HANDLER, VAULT, VAULT.lower(), b.create_address(VAULT, 2)):   # v3.5: never the vault, its handler or its set rules
        with pytest.raises(ValueError, match="cannot be sent to that address"):
            b.claim_refund_tx(HANDLER, OWN, BY, BY, to)
    b.V34["encoders"] = False
    with pytest.raises(ValueError, match="isn't available yet"):
        b.claim_refund_tx(HANDLER, OWN, BY, BY, OTHER)


def test_the_claim_to_another_address():
    v = b.read_vaults(vaults_json())
    vault = v.vaults[0]
    na = b.read_deposit_row(row(), v)
    r = b.refund_claim(na, BY, vault, b.refund_recipient(OTHER, BY, OWN))
    assert r["ok"] and r["to"] == OTHER and r["amount"] == 9_000_000
    assert r["tx"]["data"] == b.CLAIM_REFUND_TO_SELECTOR + "0" * 24 + OTHER[2:].lower()
    own = b.refund_claim(na, BY, vault, b.refund_recipient("", BY, OWN))
    assert own["ok"] and own["tx"]["data"] == b.CLAIM_REFUND_SELECTOR and own["to"] == BY
    flag = b.refund_claim(na, BY, vault, b.refund_recipient("", OTHER, OWN))
    assert flag["ok"] and flag["to"] == OTHER and flag["tx"]["data"] == b.CLAIM_REFUND_TO_SELECTOR + "0" * 24 + OTHER[2:].lower()
    to_h = b.refund_claim(na, BY, vault, b.refund_recipient(HANDLER, BY, [OTHER.lower()]))
    assert not to_h["ok"] and to_h["reason"] == "recipient"
    to_v = b.refund_claim(na, BY, vault, {"ok": True, "to": VAULT, "own": False})   # even a recipient checked elsewhere
    assert not to_v["ok"] and to_v["reason"] == "recipient"
    b.V34["encoders"] = False
    ny = b.refund_claim(na, BY, vault, b.refund_recipient(OTHER, BY, OWN))
    assert not ny["ok"] and ny["reason"] == "not-yet"
    assert b.refund_claim(na, BY, vault, b.refund_recipient("", BY, OWN))["ok"]
    b.V34["encoders"] = True


def test_the_cctp_deposit_into_the_handler_reproduces_the_published_calldata():
    E = V["cctpDepositIntoTheHandler"]
    v = b.read_vaults(vaults_json())
    amount, ben = int(E["example"]["amount"]), to_checksum_address(E["example"]["beneficiary"])
    cc = b.deposit_check(v, 5042, amount, 0, b.sender_check({"ok": True, "kind": "wallet"}, None))
    txs = b.arc_deposit_txs(cc, v, 5042, USDC_ARC, TM, ben, amount, 0, ACCEPTED, False)
    assert txs[1]["data"] == E["example"]["calldata"]
    assert b.destination_caller_word(HANDLER, False) == w32(HANDLER)[2:] and b.destination_caller_word(HANDLER, True) == "0" * 64
    b.V34["encoders"] = False
    assert b.destination_caller_word(HANDLER, False) == "0" * 64


def test_the_reason_keys_are_the_published_ones():
    assert b.HANDLER_REASONS == {"waits": [1, 3, 4], "refundsToBeneficiary": [2, 7, 8], "stranded": [5], "rescued": 9}   # v3.5: 5 stranded
    want = {1: "waits", 3: "waits", 4: "waits", 2: "refundsToBeneficiary", 7: "refundsToBeneficiary", 8: "refundsToBeneficiary",
            5: "stranded", 9: "rescued", 6: "nothing"}
    assert all(b.handler_reason(c) == k for c, k in want.items()) and b.handler_reason(10) is None and b.handler_reason(True) is None


def test_the_public_words():
    assert b.DEPOSIT_STATUSES == ("pending", "credited", "waiting", "stranded", "not accepted") and b.WITHDRAWAL_STATUSES == ("pending", "paid", "refunded")
    assert all(b.withdrawal_status(w) is None for w in ("queued", "held", "signing", "parked", "cancelled", "expired"))


def test_the_per_withdrawal_maximum():
    v = b.read_vaults(vaults_json(maximum="100000000"))
    assert v.ok and v.vaults[0].max_per_withdrawal == 100_000_000

    def line(x):
        return V["perWithdrawalMaximum"]["line"].replace("{X}", x)
    assert b.line_above_max(100_000_000) == line("100") and b.line_above_max(2_500_000) == line("2.5")
    i = b.WithdrawIntent(OTHER, 1, w32(OTHER), 100_000_001, 0, 0, 3, 0, 1_000_600)
    assert b.build_withdraw_intent(v, i, 0, 1_000_000) == (None, line("100"))
    from dataclasses import replace
    assert b.build_withdraw_intent(v, replace(i, amount=100_000_000), 0, 1_000_000)[0] is not None
    assert b.withdraw_screen(b.read_vaults(vaults_json()), 5_000_000)["refusal"] == "The per-withdrawal maximum can't be read right now, so nothing was signed."
    assert all(not b.read_vaults(vaults_json(maximum=bad)).ok for bad in ("0", "-1", "1.5", "x"))
    assert b.read_submit_response(400, {"error": "CHAIN TEXT", "code": "over_maximum"}, 100_000_000) == ("refused", "over_maximum", line("100"))
    assert b.read_submit_response(400, {"code": "over_maximum"})[2] == "Above the per-withdrawal maximum. Please withdraw in smaller parts."
    assert V["perWithdrawalMaximum"]["intake"]["status"] == 400 and b.read_submit_response(403, {"code": "over_maximum"})[0] == "unknown"


def test_the_fee_quote_has_one_name():
    q = b.read_fee_quote(V["feeQuote"])
    assert q.ok and q.quote_url == V["feeQuote"]["quoteUrl"] and q.forward_param == V["feeQuote"]["forwardParam"]
    assert "host" not in V["feeQuote"] and not b.read_fee_quote(dict(V["feeQuote"], host="iris-api.circle.com")).ok
    assert b.fee_quote_url(26, 3, False) == V["feeQuote"]["quoteUrl"].replace("{sourceDomain}", "26").replace("{destDomain}", "3")
    with pytest.raises(ValueError):
        b.fee_quote_url(-1, 3, False)


def test_the_handler_the_vault_created():
    assert b.create_address(VAULT, 1).lower() == HANDLER.lower() and "CREATE(vault, nonce 1)" in V["handlerRule"]
    import rlp
    for n in (0, 1, 2, 127, 128, 255, 256, 65535, 70000, 2 ** 24):
        want = "0x" + keccak(rlp.encode([bytes.fromhex(VAULT[2:]), n]))[12:].hex()
        assert b.create_address(VAULT, n) == want, n
    from dataclasses import replace
    vault = b.read_vaults(vaults_json()).vaults[0]
    assert b.binding_check(vault)["ok"]
    fake = "0x" + "77" * 20
    assert not b.binding_check(replace(vault, handler=fake))["ok"]                   # not CREATE(vault, 1)
    assert not b.binding_check(replace(vault, binding_handler_vault=fake))["ok"]
    t = b.binding_check(replace(vault, runtime_sha_vault=b.TESTNET_VAULT_PIN["runtime"]))
    assert t == {"ok": False, "text": "This is a test-network vault, so nothing was built."}


def test_signatures_are_v27_or_v28_with_a_low_s():
    R = V["signatureRule"]
    assert b.signature_rule_problem(R["accepted"]["signature"]) is None
    assert all(b.signature_rule_problem(x["signature"]) is not None for x in R["refused"])
    s0 = R["accepted"]["signature"]
    n = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141
    high = s0[:66] + f"{n - int(s0[66:130], 16):064x}" + ("1c" if s0[130:] == "1b" else "1b")
    assert all(b.signature_rule_problem(x) is not None for x in (s0[:-2] + "01", s0[:-2] + "1d", high, s0[:-2]))
    call = V["withdrawCall"]["data"]
    d = b.decode_withdraw_call(call)
    assert d["ok"]
    first = d["signatures"][0]
    at = call.index(first[2:]) + 128
    bad = call[:at] + f"{int(first[130:], 16) - 27:02x}" + call[at + 2:]
    r = b.decode_withdraw_call(bad)
    assert not r["ok"] and r["field"] == "signature 1" and "v = " in r["text"]


def test_the_refund_recipient():
    def rr(x, owed, h, vault):                         # v3.5: the own addresses are the vault's three
        return b.refund_recipient(x, owed, [vault.lower(), h.lower(), b.create_address(vault, 2)])
    assert rr("", BY, HANDLER, VAULT) == {"ok": True, "to": BY, "own": True}
    assert rr(OTHER, BY, HANDLER, VAULT) == {"ok": True, "to": OTHER, "own": False}
    assert not rr(OTHER.lower(), BY, HANDLER, VAULT)["ok"] and not rr(HANDLER, BY, HANDLER, VAULT)["ok"]
    assert not rr("0x" + "0" * 40, BY, HANDLER, VAULT)["ok"]
    stuck = "That is the bridge's own contract: the USDC would be stuck there."
    assert rr(to_checksum_address(VAULT), BY, HANDLER, VAULT)["text"] == stuck and rr(to_checksum_address(HANDLER), BY, HANDLER, VAULT)["text"] == stuck
    for k in range(50):
        a = "0x" + keccak(text=f"checksum-{k}")[:20].hex()
        assert b.to_checksum(a) == to_checksum_address(a)
    caps = "Enter the address with its capital letters, as your wallet shows it, so a typo can't slip through."
    assert rr(OTHER.lower(), BY, HANDLER, VAULT)["text"] == caps and rr("0x" + OTHER[2:].upper(), BY, HANDLER, VAULT)["text"] == caps
    k = next(i for i, c in enumerate(OTHER) if i > 1 and c.lower() in "abcdef")
    typo = OTHER[:k] + OTHER[k].swapcase() + OTHER[k + 1:]
    assert rr(typo, BY, HANDLER, VAULT)["text"] == "That address has a typo: its capital letters don't match."
    v = b.read_vaults(vaults_json())
    na = b.read_deposit_row(row(), v)
    assert b.refund_claim(na, VAULT, v.vaults[0])["text"] == "Only the address that is owed can claim it. Connect that wallet."
