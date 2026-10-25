"""Agent refusals: the network's published meanings, the event records and the intake answer."""
from vordium import agent_ops, mm

SPEC = {"agents": {"refusalCodes": {"reasons": [
    {"key": "registration_not_live", "meaning": "The agent's registration is revoked or expired."},
    {"key": "price_outside_band", "meaning": "The price is outside the policy's band around the oracle price."},
    {"key": "broken"}]}}}


def test_meanings_from_the_spec():
    m = agent_ops.refusal_meanings(SPEC)
    assert m == {"registration_not_live": "The agent's registration is revoked or expired.",
                 "price_outside_band": "The price is outside the policy's band around the oracle price."}
    assert agent_ops.refusal_meanings({}) == {} and agent_ops.refusal_meanings(None) == {}


def test_records_carry_reason_and_meaning():
    j = {"events": [{"kind": "order_placed"},
                    {"kind": "agent_refused", "reason": "registration_not_live", "client_nonce": 7, "op_kind": "PlaceOrder",
                     "height": 9, "at_ms": 11},
                    {"kind": "agent_refused", "reason": "a_new_reason"}]}
    r = agent_ops.read_agent_refusals(j, agent_ops.refusal_meanings(SPEC))
    assert [x.reason for x in r] == ["registration_not_live", "a_new_reason"]
    assert r[0].meaning == "The agent's registration is revoked or expired." and r[0].client_nonce == 7 and r[0].at_ms == 11
    assert r[1].meaning is None
    assert agent_ops.read_agent_refusals({"events": None}) == []


def test_an_intake_refusal_is_read_with_its_reason():
    s = mm.read_answer(403, {"code": "agent_refused", "reason": "registration_not_live",
                             "meaning": "The agent's registration is revoked or expired."})
    assert not s.ok and s.refusal.code == "agent_refused" and s.refusal.detail == "registration_not_live"
    assert s.refusal.message == "The agent's registration is revoked or expired."
    s2 = mm.read_answer(403, {"code": "agent_refused", "reason": "zzz"})
    assert not s2.ok and "zzz" in s2.refusal.message
