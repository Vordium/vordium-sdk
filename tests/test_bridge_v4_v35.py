"""Bridge v4 contracts v3.5 -- against the v3.5 client test data (tests/vectors/bridge-v4-v35.json): the runtime pins of
the vault, its handler and its set rules (and the test-network vault, never accepted); the system's own addresses -- the
vault, the handler it created (CREATE nonce 1) and its set rules (CREATE nonce 2) -- are never a payout recipient (on every
route), a refund's destination or a CCTP beneficiary; an EVM destination takes a 20-byte address; deposits read pending /
credited / waiting / stranded / not accepted, with the published lines; a stranded deposit is owed to nobody; a payout reads
pending / paid / refunded only."""

import hashlib
import json
import re
from dataclasses import replace
from pathlib import Path

import pytest

from vordium import bridge_v4 as b

F = json.loads((Path(__file__).parent / "vectors" / "bridge-v4-v35.json").read_text())
VAULT, HANDLER, SET_RULES = F["vault"], F["handler"], F["setRules"]
BY = "0x8FeD45485e06C1496E0DF1b2e11a87c53e292e39"
OTHER = "0x3219364FdFAeC2A60D14CDDA6E58Ec65eD33c009"
USDC_ARC = "0x3600000000000000000000000000000000000000"
TM = "0x28b5a0e9C621a5BadaA536219b3a228C8168cf5d"
ACCEPTED = {"ok": True, "outcome": "accepted"}


def vaults_json(handler=HANDLER, vault_sha=None):
    return {"active": True, "vaults": [{
        "id": 1, "chain_id": 42161, "address": VAULT, "handler": handler, "cctp_domain": 3,
        "deposits": {"direct": {"chain_id": 42161, "minimum_6dec": "5000000"}, "cctp": {"from_chain_ids": [5042], "minimum_6dec": "10000000"}},
        "withdrawals": {"routes": [{"route_kind": 0, "name": "local", "open": True}], "fee_6dec": "1000000", "maximum_6dec": "250000000000"},
        "runtime_sha256": {"vault": vault_sha or F["pins"]["vault"]["runtime"], "handler": F["pins"]["handler"]["runtime"]},
        "binding": {"handler_vault": VAULT, "local_domain": 3, "usdc": "0xaf88d065e77c8cC2239327C5EDb3A432268e5831", "confirmed": True}}],
        "depositsOpen": {"42161": True, "5042": True}, "minimumDeposit6dec": {"42161": "5000000", "5042": "10000000"},
        "withdrawalFee6dec": "1000000", "as_of": {"height": 7}}


VR = b.read_vaults(vaults_json())


def word(a):
    return "0x" + "0" * 24 + a[2:].lower()


def row(**o):
    x = {"status": "not accepted", "reason": "not_completed", "text": "node text", "kind": "cctp", "account": BY, "amount_6dec": "9000000",
         "vault_id": 1, "chain_id": 42161, "deposit_id": None, "source_domain": 26, "nonce": "0x" + "ab" * 32, "source_chain_id": None,
         "source_tx": None, "vault_tx": None, "credited_height": None, "as_of": {"height": 4},
         "claim": {"chain_id": 42161, "handler": HANDLER, "by": BY, "amount_6dec": "9000000", "refundable_6dec": "9000000", "read": "ok"}}
    x.update(o)
    return x


@pytest.fixture(autouse=True)
def _open():
    was = b.ENABLED
    b.ENABLED = True
    yield
    b.ENABLED = was


def test_the_pins_are_the_v35_ones():
    assert b.PINS["interface"] == "v3.5" and VR.ok
    for k in ("vault", "handler", "setRules"):
        assert b.PINS[k]["runtime"] == F["pins"][k]["runtime"] and b.PINS[k]["runtimeBytes"] == F["pins"][k]["runtimeBytes"], k
    assert b.TESTNET_VAULT_PIN == F["pins"]["testnetVault"]
    assert b.PINS["vault"]["creation"] == F["pins"]["vault"]["creation"] and b.PINS["vault"]["creationBytes"] == F["pins"]["vault"]["creationBytes"]
    assert b.runtime_pin("setRules", F["pins"]["setRules"]["runtime"]) == "match" and b.runtime_pin("setRules", F["pins"]["handler"]["runtime"]) == "mismatch"
    assert b.creation_pin(F["pins"]["vault"]["creation"].upper()) == "match" and b.creation_pin(F["pins"]["vault"]["runtime"]) == "mismatch"
    assert b.vault_build(F["pins"]["testnetVault"]["runtime"]) == "testnet-only" and b.vault_build(F["pins"]["setRules"]["runtime"]) == "unknown"
    tn = b.read_vaults(vaults_json(vault_sha=F["pins"]["testnetVault"]["runtime"]))
    assert b.binding_check(tn.vaults[0]) == {"ok": False, "text": "This is a test-network vault, so nothing was built."}
    assert b.binding_check(VR.vaults[0])["ok"]


def test_the_system_s_own_addresses():
    assert b.create_address(VAULT, 1) == HANDLER and b.create_address(VAULT, 2) == SET_RULES
    t = F["testNetwork"]
    assert b.create_address(t["vault"], 1) == t["handler"].lower() and b.create_address(t["vault"], 2) == t["setRules"].lower()
    own = b.own_addresses(VR.vaults[0])
    assert own == [VAULT.lower(), HANDLER, SET_RULES]
    assert b.own_addresses(replace(VR.vaults[0], handler=OTHER)) is None and b.own_addresses(None) is None
    assert all(b.is_own_address(a, own) for a in (VAULT, HANDLER, SET_RULES, word(SET_RULES), "0x" + "ff" * 12 + SET_RULES[2:]))
    assert not any(b.is_own_address(a, own) for a in (BY, OTHER, word(BY), "0x", ""))


def test_withdrawal_recipients():
    now = 1_900_000_000
    i = b.WithdrawIntent(BY, 1, word(BY), 50_000_000, 1, 0, 3, 0, now + 600)
    assert b.build_withdraw_intent(VR, i, 1, now)[0] is not None
    for a in (VAULT, HANDLER, SET_RULES):
        assert b.build_withdraw_intent(VR, replace(i, recipient=word(a)), 1, now)[1] == b.LINE_OWN_ADDRESS, a
    assert b.build_withdraw_intent(VR, replace(i, recipient="0x" + "ab" * 12 + BY[2:].lower()), 1, now)[1] == "The destination address is not valid."
    assert b.EVM_DOMAINS == (0, 3, 26)
    bad = b.read_vaults(vaults_json(handler=OTHER))
    assert b.build_withdraw_intent(bad, i, 1, now)[1] == "The bridge contracts could not be confirmed, so nothing was built."


def test_refunds_never_go_to_the_system_s_own_contracts():
    own = b.own_addresses(VR.vaults[0])
    for a in (VAULT, HANDLER, SET_RULES):
        cs = b.to_checksum(a)
        assert b.refund_recipient(cs, BY, own)["text"] == b.LINE_OWN_ADDRESS, a
        with pytest.raises(ValueError, match="cannot be sent to that address"):
            b.claim_refund_tx(HANDLER, own, BY, BY, cs)
    assert b.refund_recipient(OTHER, BY, own)["ok"] and b.refund_recipient("", BY, own)["own"]
    assert b.refund_recipient(OTHER, BY, None)["text"] == "The bridge contracts could not be confirmed, so nothing was built."
    with pytest.raises(ValueError, match="bridge's own contract"):
        b.claim_refund_tx(OTHER, own, BY, BY)
    r = b.read_deposit_row(row(), VR)
    to_sr = b.refund_claim(r, BY, VR.vaults[0], {"ok": True, "to": SET_RULES, "own": False})
    assert not to_sr["ok"] and to_sr["reason"] == "recipient"
    ok = b.refund_claim(r, BY, VR.vaults[0], b.refund_recipient(OTHER, BY, own))
    assert ok["ok"] and ok["tx"]["to"] == HANDLER and ok["tx"]["data"] == b.CLAIM_REFUND_TO_SELECTOR + "0" * 24 + OTHER[2:].lower()


def test_a_cctp_beneficiary_is_never_one_of_them():
    cc = b.deposit_check(VR, 5042, 20_000_000, 1_000, b.sender_check({"ok": True, "kind": "wallet"}, {"ok": True, "kind": "wallet"}))
    assert len(b.arc_deposit_txs(cc, VR, 5042, USDC_ARC, TM, BY, 20_000_000, 1_000, ACCEPTED, False)) == 2
    for a in (VAULT, HANDLER, SET_RULES):
        with pytest.raises(ValueError, match="own contract"):
            b.arc_deposit_txs(cc, VR, 5042, USDC_ARC, TM, b.to_checksum(a), 20_000_000, 1_000, ACCEPTED, False)


def test_deposit_statuses_and_lines():
    assert list(b.DEPOSIT_STATUSES) == F["depositStatuses"] and sorted(b.DEPOSIT_REASONS) == sorted(F["reasonKeys"])
    L = F["publicLines"]
    assert b.LINE_WAITING == L["waiting"] and b.LINE_STRANDED == L["stranded"] and b.LINE_RESCUED == L["rescued"]
    hr = F["handlerReasons"]
    assert b.HANDLER_REASONS == {"waits": hr["waitsAsRecord"], "refundsToBeneficiary": hr["owedToBeneficiary"], "stranded": hr["stranded"],
                                 "rescued": hr["rescued"]}
    w = b.read_deposit_row(row(status="waiting", reason="waiting", claim=None), VR)
    assert w["line"] == L["waiting"] and w["claim"] is None and b.STATUS_WORD["waiting"] == "Waiting"
    s = b.read_deposit_row(row(status="stranded", reason="stranded", account=None, claim=None), VR)
    assert s["line"] == L["stranded"] and s["claim"] is None and s["account"] is None
    assert b.read_deposit_row(row(status="stranded", reason="stranded"), VR) is None          # a stranded deposit offers no claim
    r9 = b.read_deposit_row(row(reason="rescued", claim=dict(row()["claim"], by=OTHER)), VR)
    assert r9["line"] == L["rescued"] and r9["claim"]["by"] == OTHER
    r9n = b.read_deposit_row(row(reason="rescued", account=None, claim=dict(row()["claim"], by=OTHER)), VR)
    assert r9n is not None and r9n["account"] is None and r9n["claim"]["by"] == OTHER   # a recovered stranded deposit keeps no account
    assert b.read_deposit_row(row(reason="not_completed", account=None), VR) is None
    assert b.read_deposit_row(row(reason="below_minimum", claim=None), VR) is not None
    for k in ("not_completed", "above_per_deposit_limit", "rescued"):
        assert b.read_deposit_row(row(reason=k, claim=None), VR) is None, k
    for what, j in (("waiting with a claim", row(status="waiting", reason="waiting")),
                    ("waiting with the stranded key", row(status="waiting", reason="stranded", claim=None)),
                    ("stranded with the waiting key", row(status="stranded", reason="waiting", claim=None)),
                    ("not accepted with an unknown key", row(reason="paused")),
                    ("not accepted with the waiting key", row(reason="waiting")),
                    ("waiting with no account", row(status="waiting", reason="waiting", claim=None, account=None)),
                    ("the proposed under review", row(status="under review", reason=None, claim=None))):
        assert b.read_deposit_row(j, VR) is None, what


def test_payouts_never_read_held():
    assert list(b.WITHDRAWAL_STATUSES) == F["withdrawalStatuses"]
    assert all(b.withdrawal_status(w) is None for w in ("held", "failed", "lost", "queued", "cancelled"))
    shown = [v for v in vars(b).values() if isinstance(v, str)] + list(b.STATUS_WORD.values())
    assert not any(re.search(r"\b(held|lost|queued|queue)\b", x.replace("key-held", "").replace("Nothing is lost.", ""), re.I) for x in shown)


def test_no_operator_message_in_the_public_module():
    """The module builds only what a user signs or sends; the operators' messages, their calls and their selectors stay out
    (compared by hash, so this file does not spell them)."""
    src = (Path(b.__file__)).read_text(encoding="utf-8")
    names = set(re.findall(r"[A-Za-z_][A-Za-z0-9_]*", src))
    sha = {hashlib.sha256(n.encode()).hexdigest()[:16] for n in names} | {hashlib.sha256(n.lower().encode()).hexdigest()[:16] for n in names}
    refused = {"1303c68dc01887f6", "216a272add501376", "344af7fd753b6627", "35c9e4bf3ab6a80a", "42eddaad2fea6572", "5ca15245edc255d9", "72d70e49aee45402", "827616033146995f", "8e61d74d1499bb55", "a2f217e1e0ed6d84", "c04632c1acc8d1bc", "c39961f8f50ab4b9", "e972076c9c547152", "eef1f68e022e3100", "fc778038352feb61", "ff00517a5ed8d72d"}
    assert len(refused) == 16
    assert not (sha & refused)
    for sel in ("0767435c", "4e276639", "6e3d099a", "f78e55e1", "e0060400"):
        assert sel not in src


def test_aa2070_canonical_read_rescued_row_published_fields_and_handler_pin():
    n = "0x" + "ab" * 32
    assert b.deposit_message_path(26, n) == f"/bridge/v4/deposit/cctp/26/{n}"
    assert b.deposit_message_path(-1, n) is None and b.deposit_message_path(26, "0x12") is None and b.deposit_message_path(True, n) is None
    by_msg = lambda **o: b.read_deposit(200, row(status="waiting", reason="waiting", claim=None, **o), VR, None, (26, n))  # noqa: E731
    assert by_msg()["status"] == "found" and by_msg(nonce="0x" + "cd" * 32)["status"] == "unreadable" and by_msg(source_domain=0)["status"] == "unreadable"
    assert "/deposits/cctp/" not in Path(b.__file__).read_text(encoding="utf-8").replace("/bridge/v4/deposit/cctp/", "")
    ex = F["rescuedRowExample"]
    exv = b.read_vaults(vaults_json(handler=b.to_checksum(ex["claim"]["handler"])))
    rr = b.read_deposit_row(ex, exv)
    assert rr["status"] == "not accepted" and rr["reason"] == "rescued" and rr["account"] is None and rr["claim"]["by"].lower() == ex["claim"]["by"]
    assert rr["claim"]["checked"] and rr["claim"]["refundable"] is None
    assert rr["line"] == F["publicLines"]["rescued"] == "Owed to you on Arbitrum by a recovery: claim it there."
    assert b.reason_line("rescued", VR, "5042") == "Owed to you on Arc by a recovery: claim it there."
    P = F["vaultsReadFieldsExample"]

    def with_pub(**pub):
        j = vaults_json()
        j["vaults"][0].update(pub)
        return b.read_vaults(j)
    pv = with_pub(own_addresses=P["own_addresses"], set_rules=P["set_rules"], vordium_contracts=P["vordium_contracts"], evm_domains=P["evm_domains"])
    assert pv.ok and pv.vaults[0].pub_evm_domains == tuple(P["evm_domains"]) and pv.vaults[0].pub_set_rules == P["set_rules"]
    own = b.own_addresses(pv.vaults[0])
    seven = "0x7777777777777777777777777777777777777777"
    assert own is not None and seven in own and len(own) == 4
    now = 1_900_000_000
    i = b.WithdrawIntent(BY, 1, word(BY), 50_000_000, 1, 0, 3, 0, now + 600)
    assert b.build_withdraw_intent(pv, replace(i, recipient=word(seven)), 1, now)[1] == b.LINE_OWN_ADDRESS
    assert b.build_withdraw_intent(VR, replace(i, recipient=word(seven)), 1, now)[0] is not None
    assert b.is_listed_contract_word("0x" + "ab" * 32, pv.vaults[0]) and not b.is_listed_contract_word("0x" + "ab" * 32, VR.vaults[0])
    assert b.is_evm_domain(pv.vaults[0], 0) and b.is_evm_domain(pv.vaults[0], 26) and not b.is_evm_domain(pv.vaults[0], 5)
    # a listed non-EVM word is refused as a recipient word before any route rule (the EVM rule would name it otherwise)
    assert b.build_withdraw_intent(pv, replace(i, recipient="0x" + "ab" * 32), 1, now)[1] == b.LINE_OWN_ADDRESS
    # each published field adds what only it carries: an own address not listed, a listed word not in the own list,
    # an EVM domain outside the known chains (the node's example is redundant on all three)
    eight, nine = "0x8888888888888888888888888888888888888888", "0x9999999999999999999999999999999999999999"
    px = with_pub(own_addresses=P["own_addresses"] + [eight], set_rules=P["set_rules"],
                  vordium_contracts=P["vordium_contracts"] + [word(nine)], evm_domains=P["evm_domains"] + [7])
    ownx = b.own_addresses(px.vaults[0])
    assert px.ok and ownx is not None and eight in ownx and nine in ownx and len(ownx) == 6
    assert b.build_withdraw_intent(px, replace(i, recipient=word(eight)), 1, now)[1] == b.LINE_OWN_ADDRESS
    assert b.build_withdraw_intent(px, replace(i, recipient=word(nine)), 1, now)[1] == b.LINE_OWN_ADDRESS
    assert b.is_evm_domain(px.vaults[0], 7) and not b.is_evm_domain(pv.vaults[0], 7) and not b.is_evm_domain(VR.vaults[0], 7)
    assert b.own_addresses(with_pub(set_rules=OTHER).vaults[0]) is None
    assert b.own_addresses(with_pub(own_addresses=[VAULT.lower(), HANDLER]).vaults[0]) is None
    for bad in (dict(own_addresses="x"), dict(own_addresses=[1]), dict(evm_domains=["x"]), dict(evm_domains=26), dict(vordium_contracts=["0x12"]), dict(set_rules="0x12")):
        assert not with_pub(**bad).ok, bad
    assert b.own_addresses(VR.vaults[0]) == [VAULT.lower(), HANDLER, SET_RULES]       # without the fields: as before
    assert b.PINS["handler"]["creation"] == F["pins"]["handler"]["creation"] and b.PINS["handler"]["creationBytes"] == F["pins"]["handler"]["creationBytes"]
    assert b.creation_pin(F["pins"]["handler"]["creation"], "handler") == "match" and b.creation_pin(F["pins"]["handler"]["creation"]) == "mismatch"
