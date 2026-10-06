"""The signing-format switch at the activation height: agent names, the referral messages and the two new agent ops.

Offline: the phase is computed from fixtures (a release list in the shape of the chain's releases.json that names no
activation height, plus copies naming one). The web app carries the same rules; a byte-for-byte cross-check holds the two to
identical bytes.
"""

import copy
import json
from pathlib import Path

import pytest
from eth_account import Account
from eth_account.messages import encode_defunct, encode_typed_data
from eth_utils import keccak

from vordium import agent_ops, eip712, names, referral, rollb

CHAIN = 101101
G = "2c1c0679fa6ab8358f1d3e8d294a8d1c73ac2e2caf9079f1216abedc3d9fdf4f"
SPEC = {"genesisSha256": G}
TODAY = json.loads((Path(__file__).parent / "vectors" / "releases-sample.json").read_text())   # names other activations only
H = 6_000_000


def with_h(h, form="list"):
    r = copy.deepcopy(TODAY)
    e = ({"sha16": "rollb", "activations": [{"key": "feature_b_activation_height", "height": 845000},
                                             {"key": rollb.ROLLB_KEY, "height": h}]}
         if form == "list" else {"sha16": "rollb", "activation_key": rollb.ROLLB_KEY, "activation_height": h})
    r["releases"].insert(0, e)
    return r


def phase(releases=TODAY, head=5_000_000, spec=SPEC, status_genesis=G):
    return rollb.signing_phase(releases, CHAIN, head, spec, status_genesis)


# ── the phase ──────────────────────────────────────────────────────────────────────────────────────────────────────

def test_today_is_legacy():
    p = phase()
    assert p.kind == "legacy" and p.H is None
    assert phase(head=None).kind == "legacy"


def test_window_edges():
    assert rollb.ROLLB_KEY == "aa2007_activation_height" and rollb.ROLLB_WINDOW == 3000
    assert phase(with_h(H), H - 3001).kind == "legacy"
    p = phase(with_h(H), H - 3000)
    assert p.kind == "window" and p.heights_to_go == 3000
    assert phase(with_h(H), H - 1).kind == "window"
    p = phase(with_h(H), H)
    assert p.kind == "genesis-bound" and p.genesis == G and p.H == H
    assert phase(with_h(H, "single"), H).kind == "genesis-bound"


def test_unknown_cases():
    r = with_h(H)
    r["releases"].insert(0, {"activation_key": rollb.ROLLB_KEY, "activation_height": H + 1})
    assert phase(r, H).kind == "unknown"
    for bad in (0, -5, 1.5, "6000000", None, True):
        r = copy.deepcopy(TODAY)
        r["releases"].append({"activations": [{"key": rollb.ROLLB_KEY, "height": bad}]})
        assert phase(r).kind == "unknown", bad
    assert phase(None).kind == "unknown"
    assert phase(dict(TODAY, chain_id=1)).kind == "unknown"
    assert phase(with_h(H), None).kind == "unknown"
    assert phase(with_h(H), H, spec={}).kind == "unknown"
    assert phase(with_h(H), H, status_genesis="ab" * 32).kind == "unknown"
    p = phase(with_h(H), H, spec={"genesisSha256": "0x" + G.upper()}, status_genesis=None)
    assert p.kind == "genesis-bound" and p.genesis == G


def test_refusals():
    with pytest.raises(rollb.SigningPaused, match="3,000 heights from now"):
        rollb.require_signable(phase(with_h(H), H - 3000))
    with pytest.raises(rollb.SigningPaused, match="can't be confirmed"):
        rollb.require_signable(phase(None))
    assert rollb.refusal_text(phase()) is None


# ── EIP-191 ─────────────────────────────────────────────────────────────────────────────────────────────────────────

def test_genesis_line_example():
    lines = ["Vordium Admin", "Chain: 101101", "Action: …", "…", "Nonce: n"]
    assert "\n".join(rollb.with_genesis_line(lines, phase(with_h(H), H))) == \
        f"Vordium Admin\nChain: 101101\nGenesis: {G}\nAction: …\n…\nNonce: n"
    assert rollb.with_genesis_line(lines, phase()) == lines


def test_referral_messages():
    ref, code, nonce = "0xAbCdEF0123456789abcdef0123456789ABCDEF01", "VORD-76A8FBC", 1790000000123
    old = f"Vordex Referral\nChain: {CHAIN}\nAction: Register Trader\nReferrer: {ref.lower()}\nCode: {code}\nNonce: {nonce}"
    assert referral.register_trader_message(CHAIN, ref, code, nonce, phase()) == old
    assert referral.register_trader_message(CHAIN, ref, code, nonce, phase(with_h(H), H)) == \
        old.replace(f"Chain: {CHAIN}\n", f"Chain: {CHAIN}\nGenesis: {G}\n")
    claim = referral.claim_earnings_message(CHAIN, ref, nonce, phase(with_h(H), H + 5))
    assert claim.split("\n")[2] == f"Genesis: {G}" and claim.endswith(f"Nonce: {nonce}")
    with pytest.raises(rollb.SigningPaused):
        referral.claim_earnings_message(CHAIN, ref, nonce, phase(with_h(H), H - 1))


def test_referral_signature_is_64_bytes_and_recovers():
    acct = Account.from_key("0x" + "42" * 32)
    msg = referral.register_trader_message(CHAIN, acct.address, "VORD-76A8FBC", 1, phase())
    sig = referral.sign_referral_message(acct.key.hex() if hasattr(acct.key, "hex") else acct.key, msg)
    assert len(sig) == 2 + 128
    full = Account.sign_message(encode_defunct(text=msg), private_key=acct.key).signature
    assert sig[2:] == bytes(full).hex()[:128]


# ── names ───────────────────────────────────────────────────────────────────────────────────────────────────────────

ACCEPT = ["ETH scalper", "Bot", "a" * 32, "a.b", "Grid_v2-beta", "adm1n"]
REFUSE = [("ab", "at least 3"), ("a" * 33, "at most 32"), ("Bot!", "Use only letters"), ("Café bot", "plain letters"),
          ("bot \U0001F916", "plain letters"), ("---", "at least one letter"), ("Admin bot", '"admin"'),
          ("a.d-m_i n", '"admin"'), ("Vord ex", '"vordex"'), ("MyValidator", '"validator"'), ("support42", '"support"'),
          ("bot  one", "double spaces"), (" bot", "start or end"), ("", "Enter a name"), ("abc\n", "control characters")]


def test_names_accept_and_refuse():
    for n in ACCEPT:
        assert names.check_name(n) == (True, n), n
    for n, why in REFUSE:
        ok, reason = names.check_name(n)
        assert not ok and why in reason, (n, reason)


# when a name breaks several rules, the reason is the chain's first failing step, in the chain's order
ORDER = [("a!", "BadChar"), ("a\x01", "ControlChar"), ("é!", "NonAscii"), ("a\x01!", "ControlChar"), ("\x7f", "ControlChar"),
         ("!" * 33, "BadChar"), ("a" * 40 + "/", "BadChar"), (" ab", "NotCanonical"), ("a" * 33 + " ", "TooLong"),
         ("-", "TooShort"), ("- " * 20, "TooLong"), ("---", "NoAlphanumeric"), ("", "TooShort"), ("Admin", "Reserved")]


def test_names_refuse_in_the_chains_step_order():
    for n, step in ORDER:
        assert names.refusal_step(n) == step, (n, names.refusal_step(n))
        assert not names.check_name(n)[0], n
    assert names.refusal_step("Alpha Bot") is None


def test_normalisation():
    assert names.normalize_name("  ETH   scalper  ") == "ETH scalper"
    assert names.normalize_name("ＥＴＨ ｂｏｔ") == "ETH bot"
    assert names.normalize_name("bot\t\tone\n") == "bot one"
    assert names.normalize_name("grid bot") == "grid bot"
    assert not names.prepare_name("Café")[0]
    assert names.name_skeleton("A.d-M_i N") == "admin"
    assert names.agent_display_name("ETH scalper", "0xAbCd00000000000000000000000000000000Ef12") == "ETH scalper · 0xAbCd…Ef12"
    assert names.agent_display_name(None, "0xAbCd00000000000000000000000000000000Ef12") == "Unnamed agent · 0xAbCd…Ef12"
    with pytest.raises(names.InvalidAgentName):
        names.require_name("x")


# ── the agent ops from H ────────────────────────────────────────────────────────────────────────────────────────────

def _type_hash(primary):
    fields = eip712.TYPES[primary]
    return keccak(f"{primary}({','.join(f['type'] + ' ' + f['name'] for f in fields)})".encode()).hex()


def test_type_hashes_match_the_published_types():
    th2, thn = _type_hash("RegisterAgentV2"), _type_hash("SetAgentName")
    assert th2.startswith("b5b48938") and th2.endswith("df06"), th2
    assert thn.startswith("9c25acb2") and thn.endswith("48da"), thn
    # the vector file carries every op's type string; test_rollb_vectors.py reproduces every vector
    rb = json.loads((Path(__file__).parent / "vectors" / "rollb-client-vectors-2c1c0679.json").read_text())["ops"]
    for o in rb:
        assert "0x" + _type_hash(o["typeString"].split("(")[0]) == o["typeHash"], o["op"]
    v1 = json.loads((Path(__file__).parent / "vectors" / "agent-ops-vectors-2c1c0679.json").read_text())["types"]
    for t, d in v1.items():
        assert "0x" + _type_hash(t) == d["typeHash"], t


def test_registration_by_phase():
    o, a = "0x" + "11" * 20, "0x" + "22" * 20
    assert agent_ops.registration(o, a, "mm", 1, 7, phase()) == \
        ("RegisterAgent", {"owner": o, "agent": a, "mandate": "mm", "expiresMs": 1, "nonce": 7})
    assert agent_ops.registration(o, a, "mm", 1, 7, phase(with_h(H), H), name="  mm   bot ") == \
        ("RegisterAgentV2", {"owner": o, "agent": a, "name": "mm bot", "mandate": "mm", "expiresMs": 1, "nonce": 7})
    with pytest.raises(ValueError, match="requires a name"):
        agent_ops.registration(o, a, "mm", 1, 7, phase(with_h(H), H))
    with pytest.raises(names.InvalidAgentName):
        agent_ops.registration(o, a, "mm", 1, 7, phase(with_h(H), H), name="official bot")
    with pytest.raises(rollb.SigningPaused):
        agent_ops.registration(o, a, "mm", 1, 7, phase(with_h(H), H - 2), name="mm bot")
    with pytest.raises(ValueError, match="only from the activation height"):
        agent_ops.rename(o, a, "mm bot", 8, phase())
    assert agent_ops.rename(o, a, "mm bot", 8, phase(with_h(H), H)) == \
        ("SetAgentName", {"owner": o, "agent": a, "name": "mm bot", "nonce": 8})


def test_signed_bodies():
    owner = Account.from_key("0x0ba9e90da38e10d38b665eab483937922935bf861abf17a28e6e1b83af21c1f1")  # public test key
    agent = "0x705b803E72B85900854704C9917bA11FFD24d3c6"
    op, value = agent_ops.registration(owner.address, agent, "mm", 1, 7, phase(with_h(H), H), name="mm bot")
    body = agent_ops.sign_owner_op(owner.key, op, value)
    assert list(body) == ["op", "owner", "agent", "name", "mandate", "expires_ms", "nonce", "signature"]
    assert body["op"] == "RegisterAgentV2" and body["name"] == "mm bot" and body["expires_ms"] == 1
    assert len(body["signature"]) == 132
    signable = encode_typed_data(domain_data=eip712.domain(), message_types={op: eip712.TYPES[op]}, message_data=value)
    assert Account.recover_message(signable, signature=body["signature"]).lower() == owner.address.lower()
    op, value = agent_ops.rename(owner.address, agent, "grid two", 9, phase(with_h(H), H))
    b2 = agent_ops.sign_owner_op(owner.key, op, value)
    assert list(b2) == ["op", "owner", "agent", "name", "nonce", "signature"] and b2["nonce"] == 9
    with pytest.raises(ValueError, match="name is missing"):
        agent_ops.submit_body("RegisterAgentV2", {"owner": owner.address, "agent": agent, "mandate": "mm",
                                                  "expiresMs": 1, "nonce": 7}, "0x" + "ab" * 65)
