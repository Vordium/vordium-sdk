"""Agent account operations across the signing-format switch (ops 129 and 130).

Below the activation height ``H`` an agent is registered with ``RegisterAgent`` (no name on chain). From ``H`` the
chain ignores ``RegisterAgent`` and requires ``RegisterAgentV2``, which REQUIRES a name, and ``SetAgentName`` renames
an agent. In the window before ``H`` nothing is signed. The EIP-712 domain does not change (it is genesis-bound);
only the operation does.

The two type strings are confirmed against the typeHashes the chain publishes (both ends of each):

    RegisterAgentV2(address owner,address agent,string name,string mandate,uint64 expiresMs,uint64 nonce)  0xb5b48938…df06
    SetAgentName(address owner,address agent,string name,uint64 nonce)                                    0x9c25acb2…48da

From ``H`` the policy engine adds two more (confirmed against the node's own vectors the same way):

    SetAgentPolicyV1(...17 fields...)                                                                     0x3292e41e…aea9
    ClearAgentLock(address owner,address agent,uint64 lockSinceMs,uint64 nonce)                            0x9bda2658…b8d5

``SetAgentPolicyV1`` may be signed by the owner, or by the agent itself only to TIGHTEN the stored policy (with the
agent's own nonce); ``ClearAgentLock`` by the owner only. :mod:`vordium.policy` holds the stateless rules.

:func:`submit_body` builds the ``POST /submit`` body (wire names; u128 as decimal strings, u64 as numbers).
"""

from __future__ import annotations

from typing import Any, Dict, Optional, Tuple

from .eip712 import sign_agent_op
from .names import require_name
from .policy import PolicyV1, clear_lock_value, loosens, policy_problems, policy_value
from .rollb import SigningPhase, require_signable

#: wire layouts, in wire order: (struct field, wire field, kind)
SUBMIT_FIELDS: Dict[str, Tuple[Tuple[str, str, str], ...]] = {
    "RegisterAgent": (("owner", "owner", "address"), ("agent", "agent", "address"), ("mandate", "mandate", "string"),
                      ("expiresMs", "expires_ms", "u64"), ("nonce", "nonce", "u64")),
    "RevokeAgent": (("owner", "owner", "address"), ("agent", "agent", "address"), ("nonce", "nonce", "u64")),
    "SetAgentPolicy": (("owner", "owner", "address"), ("agent", "agent", "address"),
                       ("capsBitmask", "caps_bitmask", "u32"), ("sideMode", "side_mode", "u8"),
                       ("maxTotalNotional6dec", "max_total_notional_6dec", "u128"),
                       ("maxLeverageOverallBps", "max_leverage_overall_bps", "u32"),
                       ("dailyLossLimit6dec", "daily_loss_limit_6dec", "u128"), ("drawdownBps", "drawdown_bps", "u32"),
                       ("feeCapWindow6dec", "fee_cap_window_6dec", "u128"), ("opsPerWindow", "ops_per_window", "u64"),
                       ("windowLenMs", "window_len_ms", "u64"), ("activeFromMsOfDay", "active_from_ms_of_day", "u32"),
                       ("activeToMsOfDay", "active_to_ms_of_day", "u32"), ("expiresMs", "expires_ms", "u64"),
                       ("enabled", "enabled", "bool"), ("nonce", "nonce", "u64")),
    "SetAgentMarketLimit": (("owner", "owner", "address"), ("agent", "agent", "address"), ("pair", "pair", "u32"),
                            ("allowed", "allowed", "bool"), ("maxOrder18dec", "max_order_18dec", "u128"),
                            ("maxPosition18dec", "max_position_18dec", "u128"),
                            ("maxLeverageBps", "max_leverage_bps", "u32"), ("nonce", "nonce", "u64")),
    # From H. Same wire rule as the four above; no worked example has been published for these two yet.
    "RegisterAgentV2": (("owner", "owner", "address"), ("agent", "agent", "address"), ("name", "name", "string"),
                        ("mandate", "mandate", "string"), ("expiresMs", "expires_ms", "u64"), ("nonce", "nonce", "u64")),
    "SetAgentName": (("owner", "owner", "address"), ("agent", "agent", "address"), ("name", "name", "string"),
                     ("nonce", "nonce", "u64")),
    # Ops 132 / 133 (worked /submit examples published in the node's vector file)
    "SetAgentPolicyV1": (("owner", "owner", "address"), ("agent", "agent", "address"),
                         ("capsBitmask", "caps_bitmask", "u32"), ("sideMode", "side_mode", "u8"),
                         ("maxTotalExposure6dec", "max_total_exposure_6dec", "u128"),
                         ("maxLeverageBps", "max_leverage_bps", "u32"),
                         ("dailyLossLimit6dec", "daily_loss_limit_6dec", "u128"),
                         ("dailyFeeCap6dec", "daily_fee_cap_6dec", "u128"), ("opsPerWindow", "ops_per_window", "u32"),
                         ("opsWindowMs", "ops_window_ms", "u32"), ("activeFromMsOfDay", "active_from_ms_of_day", "u32"),
                         ("activeToMsOfDay", "active_to_ms_of_day", "u32"), ("oracleBandBps", "oracle_band_bps", "u32"),
                         ("lockAutoClear", "lock_auto_clear", "bool"), ("expiresMs", "expires_ms", "u64"),
                         ("enabled", "enabled", "bool"), ("nonce", "nonce", "u64")),
    "ClearAgentLock": (("owner", "owner", "address"), ("agent", "agent", "address"),
                       ("lockSinceMs", "lock_since_ms", "u64"), ("nonce", "nonce", "u64")),
}


def registration(owner: str, agent: str, mandate: str, expires_ms: int, nonce: int,
                 phase: SigningPhase, name: Optional[str] = None) -> Tuple[str, Dict[str, Any]]:
    """``(primary_type, value)`` for registering ``agent`` at ``phase``: ``RegisterAgent`` below H (a name, if
    given, stays yours -- the chain has nowhere to keep it), ``RegisterAgentV2`` from H (``name`` required and
    normalised). Raises :class:`vordium.rollb.SigningPaused` in the window or when the format is unknown."""
    require_signable(phase)
    if phase.kind == "genesis-bound":
        if name is None:
            raise ValueError("from the activation height the chain requires a name for every agent (RegisterAgentV2)")
        return "RegisterAgentV2", {"owner": owner, "agent": agent, "name": require_name(name), "mandate": mandate,
                                   "expiresMs": int(expires_ms), "nonce": int(nonce)}
    return "RegisterAgent", {"owner": owner, "agent": agent, "mandate": mandate,
                             "expiresMs": int(expires_ms), "nonce": int(nonce)}


def rename(owner: str, agent: str, name: str, nonce: int, phase: SigningPhase) -> Tuple[str, Dict[str, Any]]:
    """``("SetAgentName", value)``; only from H (the operation does not exist before it)."""
    require_signable(phase)
    if phase.kind != "genesis-bound":
        raise ValueError("SetAgentName exists only from the activation height")
    return "SetAgentName", {"owner": owner, "agent": agent, "name": require_name(name), "nonce": int(nonce)}


def _from_h(phase: SigningPhase, op: str) -> None:
    require_signable(phase)
    if phase.kind != "genesis-bound":
        raise ValueError(f"{op} exists only from the activation height")


def set_policy(owner: str, agent: str, policy: PolicyV1, nonce: int, phase: SigningPhase, now_ms: int,
               stored: Optional[PolicyV1] = None, signer: str = "owner") -> Tuple[str, Dict[str, Any]]:
    """``("SetAgentPolicyV1", value)``; only from H. Refused before signing when the chain would refuse it at apply
    (:func:`vordium.policy.policy_problems`, raised as ``ValueError`` naming every reason).

    ``signer="agent"``: the agent signs for itself with ITS OWN nonce, and only a tightening of ``stored`` (the policy
    the chain holds now) -- with nothing stored, or with any loosening, it is refused here, because the chain accepts
    it at intake and then ignores it. The owner may loosen (at most once per cooldown; the chain judges that)."""
    _from_h(phase, "SetAgentPolicyV1")
    if signer not in ("owner", "agent"):
        raise ValueError('signer is "owner" or "agent"')
    problems = policy_problems(policy, now_ms)
    if problems:
        raise ValueError("the chain would refuse this policy: " + " ".join(problems))
    if signer == "agent":
        if stored is None:
            raise ValueError("an agent may only tighten a policy its owner has set; there is no stored policy to tighten")
        wider = loosens(stored, policy)
        if wider:
            raise ValueError("an agent may only tighten its own policy; this " + ", ".join(wider)
                             + " -- only the owner may sign that")
    return "SetAgentPolicyV1", policy_value(owner, agent, policy, nonce)


def clear_lock(owner: str, agent: str, lock_since_ms: int, nonce: int, phase: SigningPhase) -> Tuple[str, Dict[str, Any]]:
    """``("ClearAgentLock", value)``; only from H, owner only. ``lock_since_ms`` is the start of the lock being cleared
    (from the agent read), so a clear signed in advance can never clear a later lock."""
    _from_h(phase, "ClearAgentLock")
    if isinstance(lock_since_ms, bool) or not isinstance(lock_since_ms, int) or lock_since_ms <= 0:
        raise ValueError("lock_since_ms is the start of the active lock (from the agent read)")
    return "ClearAgentLock", clear_lock_value(owner, agent, lock_since_ms, nonce)


#: these ops' bodies write addresses lower-case, exactly as the node's own vectors do; the v1 ops keep the
#: caller's form. The value signed is the same 20 bytes either way.
LOWERCASE_ADDRESS_OPS = frozenset({"RegisterAgentV2", "SetAgentName", "SetAgentPolicyV1", "ClearAgentLock"})


def _encode(kind: str, wire: str, v: Any, op: str = "") -> Any:
    if kind == "address":
        if not (isinstance(v, str) and len(v) == 42 and v.startswith("0x")):
            raise ValueError(f"{wire} is not an address")
        int(v[2:], 16)
        return v.lower() if op in LOWERCASE_ADDRESS_OPS else v
    if kind == "string":
        if not isinstance(v, str):
            raise ValueError(f"{wire} is not text")
        return v
    if kind == "bool":
        if not isinstance(v, bool):
            raise ValueError(f"{wire} is not true or false")
        return v
    if isinstance(v, bool) or not isinstance(v, int) or v < 0:
        raise ValueError(f"{wire} is not a whole number")
    if kind == "u128":
        return str(v)
    if v > 2**53 - 1:
        raise ValueError(f"{wire} is past the exact-integer range")
    return v


def submit_body(op: str, value: Dict[str, Any], signature: str) -> Dict[str, Any]:
    """The exact ``POST /submit`` body for one signed owner op (every field present, in wire order)."""
    fields = SUBMIT_FIELDS.get(op)
    if fields is None:
        raise ValueError(f"{op} is not an agent owner op")
    s = signature.lower()
    if not (s.startswith("0x") and len(s) == 132 and all(c in "0123456789abcdef" for c in s[2:])):
        raise ValueError("signature is not a 65-byte lowercase 0x-hex string")
    body: Dict[str, Any] = {"op": op}
    for struct, wire, kind in fields:
        if struct not in value:
            raise ValueError(f"{struct} is missing from the signed operation")
        body[wire] = _encode(kind, wire, value[struct], op)
    body["signature"] = s
    return body


def sign_owner_op(owner_private_key: str, op: str, value: Dict[str, Any]) -> Dict[str, Any]:
    """Sign ``(op, value)`` with the OWNER key (65-byte ``r||s||v``) and return the ``/submit`` body."""
    return submit_body(op, value, sign_agent_op(owner_private_key, op, value))


def sign_agent_policy(agent_private_key: str, value: Dict[str, Any]) -> Dict[str, Any]:
    """Sign a ``SetAgentPolicyV1`` value built by :func:`set_policy` with ``signer="agent"`` using the AGENT's key, and
    return the ``/submit`` body. Only this op may be agent-signed; the chain refuses the agent's key on every other."""
    return submit_body("SetAgentPolicyV1", value, sign_agent_op(agent_private_key, "SetAgentPolicyV1", value))
