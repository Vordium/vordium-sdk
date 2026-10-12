"""The signing-format switch, against the NODE's own client vectors: ops 129-133, the five money ops, the referral messages.

Reference: tests/vectors/rollb-client-vectors-2c1c0679.json — the chain's client vectors for genesis 2c1c0679, kept to
the fields these tests read. The file is refused unless its sha256 is the pin below. Nothing from it is retyped: every expected value
is READ from the file, and every actual value is COMPUTED by the SDK's own builders and signers (agent_ops, policy, money,
referral).

The keys are the two PUBLIC TEST KEYS of agent-ops-vectors-2c1c0679.json (also vendored); never fund them.

Runs under pytest, or standalone: python tests/test_rollb_vectors.py
"""
import hashlib
import json
from pathlib import Path

import pytest
from eth_account.messages import encode_defunct
from eth_utils import keccak

from vordium import agent_ops, eip712, money, names, policy, referral, rollb
from vordium import network as net

HERE = Path(__file__).parent / "vectors"
VECTORS = HERE / "rollb-client-vectors-2c1c0679.json"
#: The sha256 of the vector file. A cross-check pin, not a value.
PINNED_SHA256 = "45441e2dcb238b44e28bf0d3e9ad7b3c7b893defd6350f82d3c34dd6ecbfa057"


def _load():
    raw = VECTORS.read_bytes()
    sha = hashlib.sha256(raw).hexdigest()
    assert sha == PINNED_SHA256, f"vector file sha256 {sha} is not the pinned {PINNED_SHA256}; refusing to compare"
    return json.loads(raw)


V = _load()
KEYS = json.loads((HERE / "agent-ops-vectors-2c1c0679.json").read_text())["test_keys"]
OWNER_KEY, AGENT_KEY = KEYS["owner"]["private_key"], KEYS["agent"]["private_key"]
CHAIN = V["network"]["chainId"]
G = V["network"]["genesis_sha256"]
H = V["activation"]["sample_H"]
LEGACY = rollb.SigningPhase(kind="legacy", H=None, head=H - 5000)
BOUND = rollb.SigningPhase(kind="genesis-bound", H=H, head=H, genesis=G)
WINDOW = rollb.SigningPhase(kind="window", H=H, head=H - 1)
UNKNOWN = rollb.SigningPhase(kind="unknown", reason="the chain's release list could not be read")
OPS = {o["typeString"].split("(")[0]: o for o in V["ops"]}


def canon(o):
    """Byte-for-byte on the canonical serialisation: same keys, same values, same JSON types (1 is not true)."""
    return json.dumps(o, sort_keys=True, separators=(",", ":"))


@pytest.fixture(autouse=True)
def _pin_vector_network():
    net.set_network(net.Network(
        chain_id=CHAIN, chain_id_hex=hex(CHAIN), chain_name="Vordium Chain", rpc_url="offline", ws_url=None,
        explorer_url=None, bridge_address=None, bridge_chain=None, bridge_chain_id=None, native_symbol="VORD",
        native_decimals=18, verifying_contract=V["domain"]["verifyingContract"], source="vectors", genesis_sha256=G))
    yield


def _policy_from_fields(f):
    return policy.PolicyV1(
        caps_bitmask=f["capsBitmask"], side_mode=f["sideMode"], max_total_exposure_6dec=int(f["maxTotalExposure6dec"]),
        max_leverage_bps=f["maxLeverageBps"], daily_loss_limit_6dec=int(f["dailyLossLimit6dec"]),
        daily_fee_cap_6dec=int(f["dailyFeeCap6dec"]), ops_per_window=f["opsPerWindow"], ops_window_ms=f["opsWindowMs"],
        active_from_ms_of_day=f["activeFromMsOfDay"], active_to_ms_of_day=f["activeToMsOfDay"],
        oracle_band_bps=f["oracleBandBps"], lock_auto_clear=f["lockAutoClear"], expires_ms=f["expiresMs"],
        enabled=f["enabled"])


NOW = V["ops"][2]["fields"]["expiresMs"] - 10**9   # a moment before the vector policy expires


def _build(op):
    """(op, value) through the SDK's own builder for that op, from the vector's fields."""
    f = OPS[op]["fields"]
    if op == "RegisterAgentV2":
        return agent_ops.registration(f["owner"], f["agent"], f["mandate"], f["expiresMs"], f["nonce"], BOUND, name=f["name"])
    if op == "SetAgentName":
        return agent_ops.rename(f["owner"], f["agent"], f["name"], f["nonce"], BOUND)
    if op == "SetAgentPolicyV1":
        return agent_ops.set_policy(f["owner"], f["agent"], _policy_from_fields(f), f["nonce"], BOUND, NOW)
    if op == "ClearAgentLock":
        return agent_ops.clear_lock(f["owner"], f["agent"], f["lockSinceMs"], f["nonce"], BOUND)
    raise AssertionError(op)


# ── the domain and the four ops ───────────────────────────────────────────────────────────────────────────────────

def test_the_domain_is_the_nodes():
    assert eip712.DOMAIN_SEPARATOR == V["domain"]["domainSeparator"]


@pytest.mark.parametrize("op", sorted(OPS))
def test_type_string_and_type_hash(op):
    s = op + "(" + ",".join(f"{x['type']} {x['name']}" for x in eip712.TYPES[op]) + ")"
    assert s == OPS[op]["typeString"]
    assert "0x" + keccak(text=s).hex() == OPS[op]["typeHash"]


@pytest.mark.parametrize("op", sorted(OPS))
def test_digest_signature_and_submit_body(op):
    o = OPS[op]
    name, value = _build(op)
    assert name == op
    assert eip712.digest(op, value) == o["digest"]
    body = agent_ops.sign_owner_op(OWNER_KEY, op, value)
    assert body["signature"] == o["signed"]["signature"]
    assert len(bytes.fromhex(body["signature"][2:])) == 65
    assert canon(body) == canon(o["submit"]["body"])


@pytest.mark.parametrize("op", sorted(OPS))
def test_a_checksummed_owner_and_agent_give_the_vector_body(op):
    """A wallet hands over the checksummed form; these bodies are written lower-case, as the node's vectors are."""
    from eth_utils import to_checksum_address
    o = OPS[op]
    value = {**_build(op)[1], "owner": to_checksum_address(o["fields"]["owner"]), "agent": to_checksum_address(o["fields"]["agent"])}
    assert canon(agent_ops.submit_body(op, value, o["submit"]["body"]["signature"])) == canon(o["submit"]["body"])


def test_v1_bodies_keep_the_address_as_given():
    from eth_utils import to_checksum_address
    a = to_checksum_address(OPS["SetAgentName"]["fields"]["owner"])
    body = agent_ops.submit_body("RevokeAgent", {"owner": a, "agent": a, "nonce": 1}, "0x" + "ab" * 65)
    assert body["owner"] == a


def test_op_132_signed_by_the_agent_for_a_tightening():
    f = OPS["SetAgentPolicyV1"]["fields"]
    p = _policy_from_fields(f)
    _, value = agent_ops.set_policy(f["owner"], f["agent"], p, f["nonce"], BOUND, NOW, stored=p, signer="agent")
    body = agent_ops.sign_agent_policy(AGENT_KEY, value)
    want = OPS["SetAgentPolicyV1"]
    assert body["signature"] == want["signed_by_agent_key"]["signature"]
    assert canon(body) == canon(want["submit_signed_by_agent"]["body"])


def test_the_agent_may_not_loosen_or_set_the_first_policy():
    f = OPS["SetAgentPolicyV1"]["fields"]
    p = _policy_from_fields(f)
    tighter = policy.PolicyV1(**{**p.__dict__, "max_total_exposure_6dec": p.max_total_exposure_6dec - 1})
    with pytest.raises(ValueError, match="raises the total exposure"):
        agent_ops.set_policy(f["owner"], f["agent"], p, f["nonce"], BOUND, NOW, stored=tighter, signer="agent")
    with pytest.raises(ValueError, match="no stored policy"):
        agent_ops.set_policy(f["owner"], f["agent"], p, f["nonce"], BOUND, NOW, signer="agent")
    # the owner may loosen
    agent_ops.set_policy(f["owner"], f["agent"], p, f["nonce"], BOUND, NOW, stored=tighter, signer="owner")


def test_a_policy_the_chain_would_refuse_is_never_built():
    f = OPS["SetAgentPolicyV1"]["fields"]
    bad = policy.PolicyV1(**{**_policy_from_fields(f).__dict__, "oracle_band_bps": 0})
    with pytest.raises(ValueError, match="oracle band"):
        agent_ops.set_policy(f["owner"], f["agent"], bad, f["nonce"], BOUND, NOW)


@pytest.mark.parametrize("op", sorted(OPS))
@pytest.mark.parametrize("ph", [LEGACY, WINDOW, UNKNOWN], ids=["below-H", "window", "unknown"])
def test_nothing_is_built_before_h(op, ph):
    """Intake accepts these below H but apply ignores them: a client never signs them before H."""
    f = OPS[op]["fields"]
    with pytest.raises((ValueError, rollb.SigningPaused)):
        if op == "RegisterAgentV2":
            # below H this becomes the legacy RegisterAgent — never the V2 op
            n, _ = agent_ops.registration(f["owner"], f["agent"], f["mandate"], f["expiresMs"], f["nonce"], ph, name=f["name"])
            if n != "RegisterAgentV2":
                raise ValueError("legacy op below H")
        elif op == "SetAgentName":
            agent_ops.rename(f["owner"], f["agent"], f["name"], f["nonce"], ph)
        elif op == "SetAgentPolicyV1":
            agent_ops.set_policy(f["owner"], f["agent"], _policy_from_fields(f), f["nonce"], ph, NOW)
        else:
            agent_ops.clear_lock(f["owner"], f["agent"], f["lockSinceMs"], f["nonce"], ph)


def test_only_op_132_can_be_agent_signed():
    for op in ("RegisterAgentV2", "SetAgentName", "ClearAgentLock"):
        assert "REFUSED" in OPS[op]["signed_by_agent_key"]["rule"]
    f = OPS["ClearAgentLock"]["fields"]
    _, value = agent_ops.clear_lock(f["owner"], f["agent"], f["lockSinceMs"], f["nonce"], BOUND)
    with pytest.raises(Exception):
        agent_ops.sign_agent_policy(AGENT_KEY, value)   # the agent path signs SetAgentPolicyV1 and nothing else


# ── the money ops (EIP-191, owner-signed) ─────────────────────────────────────────────────────────────────────────

MONEY = {m["op"]: m for m in V["owner_signed_money_ops"]}
_ARG_FROM_BODY = {"VlpDeposit": ("user", "amount_6dec", "nonce"), "VlpWithdraw": ("user", "shares", "nonce"),
                  "Stake": ("owner", "amount", "lock_ms", "nonce"), "Unstake": ("owner", "nonce"),
                  "ClaimStakingRewards": ("owner", "nonce")}


def _money_args(op):
    body = MONEY[op]["legacy_below_H"]["owner_signed_post_body"]
    return {k: (body[k] if k in ("user", "owner") else int(body[k])) for k in _ARG_FROM_BODY[op]}


def _eip191(msg):
    m = encode_defunct(text=msg)
    return "0x" + keccak(b"\x19" + m.version + m.header + m.body).hex()


def test_all_five_money_ops_are_covered():
    assert sorted(MONEY) == sorted(money.MONEY_OPS)
    for op, m in MONEY.items():
        assert m["route"] == "POST " + money.MONEY_ROUTES[op]


@pytest.mark.parametrize("op", sorted(money.MONEY_OPS))
@pytest.mark.parametrize("fmt", ["legacy_below_H", "genesis_bound_from_H"])
def test_money_message_digest_signature_body(op, fmt):
    m, ph = MONEY[op], (LEGACY if fmt == "legacy_below_H" else BOUND)
    args = _money_args(op)
    msg = money.money_message(op, args, CHAIN, ph)
    assert msg == m["messages"][fmt]["message"]
    assert _eip191(msg) == m["messages"][fmt]["digest"]
    body = money.sign_money_op(OWNER_KEY, op, args, CHAIN, ph)
    assert body["signature"] == m[fmt]["owner_signature"]
    assert canon(body) == canon(m[fmt]["owner_signed_post_body"])


def test_a_checksummed_address_gives_the_vector_bytes():
    """A wallet hands over the EIP-55 checksummed form; the message and body are written lower-case."""
    from eth_utils import to_checksum_address
    m = MONEY["VlpDeposit"]
    args = {**_money_args("VlpDeposit"), "user": to_checksum_address(_money_args("VlpDeposit")["user"])}
    assert args["user"] != _money_args("VlpDeposit")["user"]
    assert money.money_message("VlpDeposit", args, CHAIN, LEGACY) == m["messages"]["legacy_below_H"]["message"]
    assert canon(money.sign_money_op(OWNER_KEY, "VlpDeposit", args, CHAIN, LEGACY)) == canon(m["legacy_below_H"]["owner_signed_post_body"])


@pytest.mark.parametrize("op", sorted(money.MONEY_OPS))
def test_money_nothing_in_the_window_or_unknown(op):
    for ph in (WINDOW, UNKNOWN):
        with pytest.raises(rollb.SigningPaused):
            money.money_message(op, _money_args(op), CHAIN, ph)


def test_money_signer_rule():
    for op in money.MONEY_OPS:
        if money.MONEY_SIGNER[op] == "owner":
            with pytest.raises(money.MoneyOpError, match="owner's key"):
                money.sign_money_op(OWNER_KEY, op, _money_args(op), CHAIN, BOUND, by="session")
        else:
            assert op == "ClaimStakingRewards"
            money.sign_money_op(AGENT_KEY, op, _money_args(op), CHAIN, BOUND, by="session")
    assert [op for op in money.MONEY_OPS if money.MONEY_SIGNER[op] != "owner"] == ["ClaimStakingRewards"]


def test_amounts_are_exact():
    assert money.to_units("25", 6) == 25_000_000 and money.to_units("25.5", 6) == 25_500_000
    assert money.to_units("0.0000001", 6) is None and money.to_units("-1", 6) is None and money.to_units("1e3", 6) is None
    assert money.to_units("1.000000000000000001", 18) == 10**18 + 1
    assert money.shares_for(5, 10, 100) == 0 and money.shares_for(1000, 10, 100) == 10 and money.shares_for(50, 10, 100) == 5
    assert money.shares_for(0, 10, 100) is None and money.shares_for(1, 0, 100) is None


# ── the referral messages (EIP-191) ───────────────────────────────────────────────────────────────────────────────

def _lines(msg):
    return dict(l.split(": ", 1) for l in msg.split("\n")[1:] if ": " in l)


@pytest.mark.parametrize("label", sorted(V["referral_messages"]))
@pytest.mark.parametrize("fmt", ["legacy_below_H", "genesis_bound_from_H"])
def test_referral_messages(label, fmt):
    want = V["referral_messages"][label][fmt]
    f = _lines(V["referral_messages"][label]["legacy_below_H"]["message"])
    ph = LEGACY if fmt == "legacy_below_H" else BOUND
    act = f["Action"]
    if act == "Claim Earnings":
        got = referral.claim_earnings_message(CHAIN, f["Referrer"], int(f["Nonce"]), ph)
    elif act == "Register Code":
        got = referral.register_code_message(CHAIN, f["Referrer"], f["Code"], int(f["Nonce"]), ph)
    elif act == "Register Trader":
        got = referral.register_trader_message(CHAIN, f["Referrer"], f["Code"], int(f["Nonce"]), ph)
    else:
        raise AssertionError(act)
    assert got == want["message"]
    assert _eip191(got) == want["digest"]


# ── the name rule ─────────────────────────────────────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("row", V["name_rule"]["table"], ids=lambda r: r["name_hex"])
def test_name_rule_table(row):
    ok, reason = names.check_name(row["name"], V["name_rule"]["default_reserved_words"])
    assert ok == (row["result"] == "accepted")
    step = names.refusal_step(row["name"], V["name_rule"]["default_reserved_words"])
    want = None if row["result"] == "accepted" else row["result"].split("(")[0]
    assert step == want, (row["name"], step, row["result"])
    if want == "Reserved":
        assert row["result"].split("(")[1].strip('")') in reason
    if ok:
        assert names.name_skeleton(row["name"]) == row["skeleton"]


# ── the policy rules ──────────────────────────────────────────────────────────────────────────────────────────────

def test_vector_policy_passes_and_each_refusal_is_named():
    p = _policy_from_fields(OPS["SetAgentPolicyV1"]["fields"])
    assert policy.policy_problems(p, NOW) == []
    d = p.__dict__
    cases = [
        ({"max_total_exposure_6dec": 0}, "total exposure"), ({"daily_loss_limit_6dec": 0}, "daily loss"),
        ({"oracle_band_bps": 0}, "oracle band"), ({"oracle_band_bps": 1001}, "oracle band"),
        ({"expires_ms": NOW}, "expiry"), ({"caps_bitmask": 64}, "capabilities"), ({"side_mode": 2}, "open positions"),
        ({"ops_per_window": 1, "ops_window_ms": 0}, "operations"), ({"ops_window_ms": policy.DAY_MS + 1}, "operations"),
        ({"active_from_ms_of_day": 5, "active_to_ms_of_day": 5}, "active hours"),
        ({"active_to_ms_of_day": policy.DAY_MS}, "active hours"), ({"max_leverage_bps": 500_001}, "Leverage"),
    ]
    for change, word in cases:
        probs = policy.policy_problems(policy.PolicyV1(**{**d, **change}), NOW)
        assert len(probs) == 1 and word in probs[0], (change, probs)
    assert policy.policy_problems(policy.PolicyV1(**{**d, "ops_per_window": 0, "ops_window_ms": 0,
                                                     "active_from_ms_of_day": 0, "active_to_ms_of_day": 0}), NOW) == []


def test_loosen_table():
    p = _policy_from_fields(OPS["SetAgentPolicyV1"]["fields"])
    d = p.__dict__
    L = lambda **c: policy.loosens(p, policy.PolicyV1(**{**d, **c}))   # noqa: E731
    assert policy.loosens(None, p) == [] and policy.loosens(p, p) == []
    assert L(caps_bitmask=p.caps_bitmask | 32) == ["adds a capability"]
    assert L(caps_bitmask=p.caps_bitmask & ~1) == []
    assert L(side_mode=1) == [] and policy.loosens(policy.PolicyV1(**{**d, "side_mode": 1}), p) == ["lets the agent open positions"]
    assert L(max_leverage_bps=0) == ["raises the leverage"] and L(max_leverage_bps=p.max_leverage_bps - 1) == []
    assert L(daily_fee_cap_6dec=0) == ["raises the daily fee cap"]
    assert L(expires_ms=p.expires_ms + 1) == ["extends the expiry"] and L(oracle_band_bps=p.oracle_band_bps + 1) == ["widens the oracle band"]
    assert L(ops_per_window=p.ops_per_window - 1) == ["changes the operations limit"]
    assert L(active_to_ms_of_day=p.active_to_ms_of_day - 1) == ["changes the active hours"]
    off = policy.PolicyV1(**{**d, "enabled": False, "lock_auto_clear": False})
    assert policy.loosens(off, p) == ["turns on automatic lock clearing", "turns the policy on"]


def test_reads():
    f = OPS["SetAgentPolicyV1"]["fields"]
    p = _policy_from_fields(f)
    camel = {k: v for k, v in f.items() if k not in ("owner", "agent", "nonce")}
    assert policy.policy_from_read(camel) == p
    wire = {w: f[s] for s, w, _ in agent_ops.SUBMIT_FIELDS["SetAgentPolicyV1"] if s not in ("owner", "agent", "nonce")}
    assert policy.policy_from_read(wire) == p
    assert policy.policy_from_read({**wire, "enabled": None}) is None
    assert policy.policy_from_read({**camel, "capsBitmask": True}) is None      # a true/false is not a number
    assert policy.policy_from_read({**camel, "enabled": 1}) is None             # nor a number a true/false
    assert policy.lock_since_from_read({"lock_since_ms": 5}) == 5 and policy.lock_since_from_read({"lockSinceMs": 0}) is None


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
