"""An agent's policy under the chain's policy engine: op 132 ``SetAgentPolicyV1`` and op 133 ``ClearAgentLock``.

Exactly as the chain published them (with the node's own vectors in ``tests/vectors/``).
Pure: no I/O. The web app carries the same rules; a cross-check holds the two to identical
answers.

WHY A CLIENT CHECKS: the chain refuses a bad policy SILENTLY at apply (no state change, no nonce consumed), so a policy it
will refuse reads as "submitted" and then never appears. :func:`policy_problems` says why before anything is signed. Only
the rules that need no chain state are here; whether the registration is live, and the nonce, are the chain's to judge.

WHO MAY SIGN: the owner always; the agent itself only to TIGHTEN (:func:`loosens` lists what would loosen). A loosening
signed by the agent is accepted at intake and ignored at apply, so it is refused here before signing. The owner may loosen
at most once per cooldown (the first policy has none); the chain judges that one.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Mapping, Optional

#: Capability bits: bits outside 0b111111 are refused.
CAPABILITY_BITS = ((0, "place"), (1, "cancel"), (2, "modify"), (3, "tpsl"), (4, "close"), (5, "vault"))
CAPS_ALL = 0b111111
#: sideMode: 0 open and reduce, 1 reduce only; > 1 is refused. A LOWER sideMode loosens.
SIDE_MODES = ((0, "Open and reduce"), (1, "Reduce only"))
ORACLE_BAND_MIN_BPS = 1
ORACLE_BAND_MAX_BPS = 1000
MAX_LEVERAGE_BPS = 500_000
DAY_MS = 86_400_000
_MAX_SAFE = 2**53 - 1


@dataclass(frozen=True)
class PolicyV1:
    caps_bitmask: int
    side_mode: int
    max_total_exposure_6dec: int
    max_leverage_bps: int        # 0 = unlimited
    daily_loss_limit_6dec: int
    daily_fee_cap_6dec: int      # 0 = unlimited
    ops_per_window: int          # both 0 = unlimited
    ops_window_ms: int
    active_from_ms_of_day: int   # both 0 = always
    active_to_ms_of_day: int
    oracle_band_bps: int
    lock_auto_clear: bool
    expires_ms: int
    enabled: bool


def _is_u(v: Any) -> bool:
    return isinstance(v, int) and not isinstance(v, bool) and 0 <= v <= _MAX_SAFE


def _is_big(v: Any) -> bool:
    return isinstance(v, int) and not isinstance(v, bool)


def _fmt(n: float) -> str:
    """A number as the app's template literal prints it (50 not 50.0; 0.01 as is)."""
    return str(int(n)) if float(n).is_integer() else repr(n)


def policy_problems(p: PolicyV1, now_ms: int) -> List[str]:
    """Why the chain would refuse this policy at apply, in plain words; [] = none of the stateless reasons."""
    out: List[str] = []
    if not _is_u(p.caps_bitmask) or (p.caps_bitmask & ~CAPS_ALL) != 0:
        out.append("Choose capabilities from the list only.")
    if p.side_mode not in (0, 1) or isinstance(p.side_mode, bool):
        out.append("Choose whether the agent may open positions or only reduce them.")
    if not _is_big(p.max_total_exposure_6dec) or p.max_total_exposure_6dec <= 0:
        out.append("Set a total exposure above zero.")
    if not _is_big(p.daily_loss_limit_6dec) or p.daily_loss_limit_6dec <= 0:
        out.append("Set a daily loss limit above zero.")
    if not _is_big(p.daily_fee_cap_6dec) or p.daily_fee_cap_6dec < 0:
        out.append("The daily fee cap cannot be negative.")
    if not _is_u(p.max_leverage_bps) or p.max_leverage_bps > MAX_LEVERAGE_BPS:
        out.append(f"Leverage can be at most {_fmt(MAX_LEVERAGE_BPS / 10000)}x (or 0 for no limit).")
    if not _is_u(p.oracle_band_bps) or p.oracle_band_bps < ORACLE_BAND_MIN_BPS or p.oracle_band_bps > ORACLE_BAND_MAX_BPS:
        out.append(f"The oracle band must be between {_fmt(ORACLE_BAND_MIN_BPS / 100)}% and {_fmt(ORACLE_BAND_MAX_BPS / 100)}%.")
    both_zero = p.ops_per_window == 0 and p.ops_window_ms == 0
    if not _is_u(p.ops_per_window) or not _is_u(p.ops_window_ms) or not (
            both_zero or (p.ops_per_window > 0 and 0 < p.ops_window_ms <= DAY_MS)):
        out.append("Set both the operations per window and a window of at most a day, or leave both at zero for no limit.")
    if (not _is_u(p.active_from_ms_of_day) or not _is_u(p.active_to_ms_of_day)
            or p.active_from_ms_of_day >= DAY_MS or p.active_to_ms_of_day >= DAY_MS
            or (p.active_from_ms_of_day == p.active_to_ms_of_day and p.active_from_ms_of_day != 0)):
        out.append("Set active hours that start and end at different times within the day, or leave both at midnight for always.")
    if not _is_u(p.expires_ms) or p.expires_ms <= now_ms:
        out.append("Set an expiry in the future.")
    return out


def loosens(prev: Optional[PolicyV1], nxt: PolicyV1) -> List[str]:
    """What in ``nxt`` would LOOSEN ``prev``; [] = a tightening or no change. No stored policy: [] (the first
    policy is the owner's to set). Only the owner may sign a loosening."""
    if prev is None:
        return []
    out: List[str] = []

    def higher_or_unlimited(a: int, b: int) -> bool:   # 0 = unlimited
        return a != 0 if b == 0 else (a != 0 and b > a)

    if (nxt.caps_bitmask & ~prev.caps_bitmask) != 0:
        out.append("adds a capability")
    if nxt.side_mode < prev.side_mode:
        out.append("lets the agent open positions")
    if nxt.max_total_exposure_6dec > prev.max_total_exposure_6dec:
        out.append("raises the total exposure")
    if higher_or_unlimited(prev.max_leverage_bps, nxt.max_leverage_bps):
        out.append("raises the leverage")
    if nxt.daily_loss_limit_6dec > prev.daily_loss_limit_6dec:
        out.append("raises the daily loss limit")
    if higher_or_unlimited(prev.daily_fee_cap_6dec, nxt.daily_fee_cap_6dec):
        out.append("raises the daily fee cap")
    if nxt.expires_ms > prev.expires_ms:
        out.append("extends the expiry")
    if nxt.oracle_band_bps > prev.oracle_band_bps:
        out.append("widens the oracle band")
    if nxt.lock_auto_clear and not prev.lock_auto_clear:
        out.append("turns on automatic lock clearing")
    if nxt.enabled and not prev.enabled:
        out.append("turns the policy on")
    if nxt.ops_per_window != prev.ops_per_window or nxt.ops_window_ms != prev.ops_window_ms:
        out.append("changes the operations limit")
    if nxt.active_from_ms_of_day != prev.active_from_ms_of_day or nxt.active_to_ms_of_day != prev.active_to_ms_of_day:
        out.append("changes the active hours")
    return out


def policy_value(owner: str, agent: str, p: PolicyV1, nonce: int) -> Dict[str, Any]:
    """The signed ``SetAgentPolicyV1`` struct (field names = the node's type string)."""
    return {
        "owner": owner, "agent": agent, "capsBitmask": p.caps_bitmask, "sideMode": p.side_mode,
        "maxTotalExposure6dec": p.max_total_exposure_6dec, "maxLeverageBps": p.max_leverage_bps,
        "dailyLossLimit6dec": p.daily_loss_limit_6dec, "dailyFeeCap6dec": p.daily_fee_cap_6dec,
        "opsPerWindow": p.ops_per_window, "opsWindowMs": p.ops_window_ms,
        "activeFromMsOfDay": p.active_from_ms_of_day, "activeToMsOfDay": p.active_to_ms_of_day,
        "oracleBandBps": p.oracle_band_bps, "lockAutoClear": p.lock_auto_clear, "expiresMs": p.expires_ms,
        "enabled": p.enabled, "nonce": int(nonce),
    }


def clear_lock_value(owner: str, agent: str, lock_since_ms: int, nonce: int) -> Dict[str, Any]:
    """The signed ``ClearAgentLock`` struct. It clears only the lock that began at ``lock_since_ms``, so a clear signed
    in advance can never clear a later lock."""
    return {"owner": owner, "agent": agent, "lockSinceMs": int(lock_since_ms), "nonce": int(nonce)}


def _pick(o: Mapping[str, Any], camel: str, snake: str) -> Any:
    return o[camel] if camel in o else o.get(snake)


def _to_int(v: Any, exact: bool) -> Optional[int]:
    if isinstance(v, bool):
        return None
    if isinstance(v, int) and 0 <= v <= _MAX_SAFE:
        return v
    if isinstance(v, str) and v.isascii() and v.isdigit():
        n = int(v)
        return n if (not exact or n <= _MAX_SAFE) else None
    return None


def policy_from_read(x: Any) -> Optional[PolicyV1]:
    """The stored policy from ``GET /agents/<owner>/<agent>`` (``policy_v1``). The read's field names are not
    published, so the node's struct names and their wire forms are both accepted; anything missing or malformed = no
    policy read (None)."""
    if not isinstance(x, Mapping):
        return None
    n = lambda c, s: _to_int(_pick(x, c, s), True)    # noqa: E731
    b = lambda c, s: _to_int(_pick(x, c, s), False)   # noqa: E731

    def t(c: str, s: str) -> Optional[bool]:
        v = _pick(x, c, s)
        return v if isinstance(v, bool) else None

    vals = dict(
        caps_bitmask=n("capsBitmask", "caps_bitmask"), side_mode=n("sideMode", "side_mode"),
        max_total_exposure_6dec=b("maxTotalExposure6dec", "max_total_exposure_6dec"),
        max_leverage_bps=n("maxLeverageBps", "max_leverage_bps"),
        daily_loss_limit_6dec=b("dailyLossLimit6dec", "daily_loss_limit_6dec"),
        daily_fee_cap_6dec=b("dailyFeeCap6dec", "daily_fee_cap_6dec"),
        ops_per_window=n("opsPerWindow", "ops_per_window"), ops_window_ms=n("opsWindowMs", "ops_window_ms"),
        active_from_ms_of_day=n("activeFromMsOfDay", "active_from_ms_of_day"),
        active_to_ms_of_day=n("activeToMsOfDay", "active_to_ms_of_day"),
        oracle_band_bps=n("oracleBandBps", "oracle_band_bps"), lock_auto_clear=t("lockAutoClear", "lock_auto_clear"),
        expires_ms=n("expiresMs", "expires_ms"), enabled=t("enabled", "enabled"),
    )
    return None if any(v is None for v in vals.values()) else PolicyV1(**vals)


def lock_since_from_read(x: Any) -> Optional[int]:
    """The active lock's start from the read (``risk_v1``), or None when none is recorded."""
    if not isinstance(x, Mapping):
        return None
    v = _to_int(_pick(x, "lockSinceMs", "lock_since_ms"), True)
    return v if v is not None and v > 0 else None
