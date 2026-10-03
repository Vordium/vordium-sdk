"""The dead-man switch (ScheduleCancel).

An account -- or a live session key of it -- sets a time T. At the first block whose time is at or past T the chain
cancels ALL of the account's open orders (perpetual and spot) and its TWAPs, and from T on it refuses the account's new
orders until a new ScheduleCancel arms a later T, or one with T = 0 clears the switch. Cancels always pass; TP/SL
brackets are kept. A client keeps pushing T forward; if it stops (a crash, a lost connection, a frozen process), its
orders go.

    set      sign + POST /schedule-cancel with T = cancel_at_ms
    refresh  the same with a later T (:class:`KeepAlive` does it on every call)
    clear    T = 0
    read     GET /schedule-cancel/{address} -- the committed state, with the chain's own limits

The signed op uses the VordCore domain (the same as PlaceOrder):
    ScheduleCancel(address owner,uint64 cancelAtMs,uint64 nonce)
``nonce`` must be strictly above the account's last accepted ScheduleCancel nonce; a millisecond clock works.
A 202 ``submitted`` is a submission, not an application: the read says what the chain holds.
The switch may not be active on a network yet: the read then says ``active: false`` and a POST answers 409
``not_active``. :class:`KeepAlive` reports that as a failed refresh -- nothing protects the orders then.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, Callable, Dict, Optional

from . import caps

_U64_MAX = (1 << 64) - 1


class ScheduleCancelError(ValueError):
    """A read of the switch that does not have the published shape, or an argument the chain would refuse."""


@dataclass(frozen=True)
class Limits:
    min_lead_ms: int
    max_horizon_ms: int
    min_refresh_ms: int


@dataclass(frozen=True)
class State:
    account: str
    cancel_at_ms: Optional[int]      # None when no deadline is set or it was cleared
    set_at_ms: Optional[int]
    nonce: Optional[int]
    fired: bool                      # the deadline passed and the chain cancelled the orders
    orders_refused: bool             # new orders are refused until a later deadline is armed or the switch is cleared
    limits: Limits
    active: bool                     # the switch is live on this network
    height: Optional[int]


@dataclass(frozen=True)
class Result:
    ok: bool                         # submitted (202) -- the read says when it is applied
    cancel_at_ms: int
    nonce: int
    status_code: Optional[int]
    reason: str


def _int(v, name: str, allow_none: bool = False) -> Optional[int]:
    if v is None and allow_none:
        return None
    if isinstance(v, bool):
        raise ScheduleCancelError(f"{name} is not a number")
    if isinstance(v, str) and v.isdigit():
        v = int(v)
    if not isinstance(v, int) or v < 0 or v > _U64_MAX:
        raise ScheduleCancelError(f"{name} is not an unsigned 64-bit number")
    return v


def read_state(j: Any, address: str) -> State:
    """Parse ``GET /schedule-cancel/{address}``. Anything without the published shape raises -- never a guess."""
    if not isinstance(j, dict):
        raise ScheduleCancelError("the read is not an object")
    acct = j.get("account")
    if not isinstance(acct, str) or acct.lower() != address.lower():
        raise ScheduleCancelError("the read is for another account")
    lim = j.get("limits")
    if not isinstance(lim, dict):
        raise ScheduleCancelError("the read carries no limits")
    limits = Limits(_int(lim.get("min_lead_ms"), "limits.min_lead_ms"), _int(lim.get("max_horizon_ms"), "limits.max_horizon_ms"),
                    _int(lim.get("min_refresh_ms"), "limits.min_refresh_ms"))
    for k in ("fired", "orders_refused", "active"):
        if not isinstance(j.get(k), bool):
            raise ScheduleCancelError(f"{k} is not true or false")
    cat = _int(j.get("cancel_at_ms"), "cancel_at_ms", allow_none=True)
    as_of = j.get("as_of") if isinstance(j.get("as_of"), dict) else {}
    return State(account=acct, cancel_at_ms=cat or None, set_at_ms=_int(j.get("set_at_ms"), "set_at_ms", allow_none=True),
                 nonce=_int(j.get("nonce"), "nonce", allow_none=True), fired=j["fired"], orders_refused=j["orders_refused"],
                 limits=limits, active=j["active"], height=_int(as_of.get("height"), "as_of.height", allow_none=True))


def sign_schedule_cancel(private_key: str, owner: str, cancel_at_ms: int, nonce: int,
                         digest: Callable[[str, int, int], bytes] = caps.schedule_cancel_digest) -> str:
    """Sign ScheduleCancel with the owner key or a live session key: 65-byte ``r||s||v`` 0x-hex (v = 27/28)."""
    from eth_account import Account

    d = digest(owner, cancel_at_ms, nonce)
    signed = Account._sign_hash(d, private_key) if hasattr(Account, "_sign_hash") else Account.unsafe_sign_hash(d, private_key)
    sig = signed.signature.hex()
    return "0x" + (sig[2:] if sig.startswith("0x") else sig)


def schedule_cancel_body(owner: str, cancel_at_ms: int, nonce: int, signature: str) -> Dict[str, Any]:
    """The POST body, exactly the published fields (numbers as JSON integers; the chain also takes decimal strings)."""
    _int(cancel_at_ms, "cancel_at_ms"); _int(nonce, "nonce")
    return {"owner": owner, "cancel_at_ms": int(cancel_at_ms), "nonce": int(nonce), "signature": signature}


def deadline(now_ms: int, lead_ms: int, limits: Limits) -> int:
    """T = now + lead, refused unless the lead sits inside the chain's window with a margin for clock and block time."""
    if lead_ms < limits.min_lead_ms * 2:
        raise ScheduleCancelError(f"a lead of {lead_ms} ms is too close to the chain's minimum of {limits.min_lead_ms} ms")
    if lead_ms > limits.max_horizon_ms:
        raise ScheduleCancelError(f"a lead of {lead_ms} ms is beyond the chain's maximum of {limits.max_horizon_ms} ms")
    return int(now_ms) + int(lead_ms)


def _post(rpc_url: str, body: Dict[str, Any], timeout: float):
    import requests

    r = requests.post(f"{rpc_url.rstrip('/')}/schedule-cancel", json=body, timeout=timeout)
    try:
        j = r.json()
    except ValueError:
        j = {}
    return r.status_code, j if isinstance(j, dict) else {}


def get_state(rpc_url: str, address: str, timeout: float = 5.0) -> State:
    """Read the committed state of ``address``'s switch."""
    import requests

    r = requests.get(f"{rpc_url.rstrip('/')}/schedule-cancel/{address}", timeout=timeout)
    r.raise_for_status()
    return read_state(r.json(), address)


def submit(rpc_url: str, signer_key: str, owner: str, cancel_at_ms: int, nonce: int, timeout: float = 5.0,
           post=_post) -> Result:
    """Sign and POST one ScheduleCancel (``cancel_at_ms`` 0 clears). ``ok`` only on 202 ``submitted``."""
    sig = sign_schedule_cancel(signer_key, owner, cancel_at_ms, nonce)
    code, j = post(rpc_url, schedule_cancel_body(owner, cancel_at_ms, nonce, sig), timeout)
    ok = code == 202 and j.get("status") == "submitted"
    reason = "submitted" if ok else " ".join(str(x) for x in (j.get("error"), j.get("reason")) if x) or f"HTTP {code}"
    return Result(ok=ok, cancel_at_ms=int(cancel_at_ms), nonce=int(nonce), status_code=code, reason=reason)


def clear(rpc_url: str, signer_key: str, owner: str, nonce: int, **kw) -> Result:
    """Disarm the switch (T = 0). New orders are accepted again."""
    return submit(rpc_url, signer_key, owner, 0, nonce, **kw)


class KeepAlive:
    """Keeps the deadline ahead of the clock. Call :meth:`refresh` on every loop of the client.

    Each refresh arms T = now + ``lead_ms`` with a nonce strictly above the last one; when the previous refresh was
    answered less than the chain's minimum interval (plus a margin) ago it waits out the remainder first: the interval is
    counted from when the previous answer CAME BACK, because the chain accepts a submission only after receiving it, so it
    never sends one the chain would refuse as too soon. :attr:`alive` is True only while the latest refresh was submitted -- a client that sees it
    False should stop quoting: if nothing refreshes, the chain cancels the orders at the last T.
    The limits come from the chain's own read (:meth:`start`); nothing about them is assumed.
    """

    def __init__(self, rpc_url: str, signer_key: str, owner: str, lead_ms: int = 90_000,
                 clock: Callable[[], float] = time.time, sleep: Callable[[float], None] = time.sleep,
                 post=_post, read: Optional[Callable[[], State]] = None):
        self.rpc_url, self.owner, self.lead_ms = rpc_url, owner, int(lead_ms)
        self._key = signer_key
        self.clock, self.sleep, self.post = clock, sleep, post
        self.read = read or (lambda: get_state(rpc_url, owner))
        self.limits: Optional[Limits] = None
        self.last_nonce = 0
        self.last_sent_ms: Optional[int] = None
        self.alive = False
        self.last: Optional[Result] = None

    def start(self) -> State:
        """Read the switch: its limits, and whether it is active on this network."""
        st = self.read()
        self.limits = st.limits
        if st.nonce is not None:
            self.last_nonce = max(self.last_nonce, st.nonce)
        deadline(0, self.lead_ms, st.limits)        # refuses a lead outside the chain's window, before anything is sent
        return st

    def _nonce(self, now_ms: int) -> int:
        self.last_nonce = max(now_ms, self.last_nonce + 1)
        return self.last_nonce

    def refresh(self) -> Result:
        if self.limits is None:
            self.start()
        now_ms = int(self.clock() * 1000)
        gap = self.limits.min_refresh_ms + max(250, self.limits.min_refresh_ms // 4)   # the chain's minimum + a margin
        if self.last_sent_ms is not None and now_ms - self.last_sent_ms < gap:
            self.sleep((gap - (now_ms - self.last_sent_ms)) / 1000)
            now_ms = int(self.clock() * 1000)
        t = deadline(now_ms, self.lead_ms, self.limits)
        try:
            res = submit(self.rpc_url, self._key, self.owner, t, self._nonce(now_ms), post=self.post)
        except Exception as e:  # a lost connection is a failed refresh, never an exception the loop must catch
            res = Result(ok=False, cancel_at_ms=t, nonce=self.last_nonce, status_code=None, reason=f"{e.__class__.__name__}: {e}"[:200])
        self.last_sent_ms = int(self.clock() * 1000)     # when the answer came back: the chain had it by then
        self.alive = res.ok
        self.last = res
        return res

    def clear(self) -> Result:
        now_ms = int(self.clock() * 1000)
        res = clear(self.rpc_url, self._key, self.owner, self._nonce(now_ms), post=self.post)
        self.alive = False
        self.last = res
        return res
