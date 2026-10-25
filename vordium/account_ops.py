"""Session keys, TWAP orders and margin mode — signed by the account's own key.

Each operation has a pure half (the typed value, its EIP-712 digest under the node's own domain, and the exact request
body the node reads) and a client half (:class:`AccountOps`) that sends it and then reads the chain back. A 202 answer
means the node accepted the request for a coming block, not that it applied: every call here returns ``applied=True``
only once the chain's own read shows the change, and ``applied=False`` with the chain's answer otherwise.

* **Session key** — ``SessionCreate`` / ``SessionRevoke`` in the ``VordexSession`` domain. The chain keeps one session
  per account, so a session it holds for another key is revoked first. Each nonce is larger than the last
  (milliseconds, or the previous nonce + 1). A session lasts at most 90 days less an hour (the app's rule).
* **TWAP** — ``PlaceTwap`` / ``CancelTwap`` in the ``VordCore`` domain, signed by the account's own key: a session key
  is refused for these. The route and the limits come from the network spec's ``twap`` section; a spec whose signed
  type differs from this SDK's is refused before anything is signed.
* **Margin mode** — ``SetMarginMode`` (operation 150) in the ``VordCore`` domain: cross or isolated, per market, only
  while the market has no open position and no resting order of the account.

Every domain is bound to the node's genesis (``vordium.domains``); a node that serves another chain than the configured
network is refused (``vordium.node_domain``). Signatures are 65 bytes (``r‖s‖v``), as a wallet signs.
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from eth_abi import encode
from eth_utils import keccak, to_checksum_address

from . import domains as _domains

# ── typed structs (the chain's layouts) ─────────────────────────────────────────────────────────────────────────────
SESSION_CREATE: List[Tuple[str, str]] = [("sessionKey", "address"), ("expiresAt", "uint256"), ("nonce", "uint256")]
SESSION_REVOKE: List[Tuple[str, str]] = [("owner", "address"), ("nonce", "uint256")]
PLACE_TWAP: List[Tuple[str, str]] = [
    ("owner", "address"), ("pairId", "uint32"), ("side", "uint8"), ("totalSize18dec", "uint128"), ("numSlices", "uint32"),
    ("durationMs", "uint64"), ("leverageBps", "uint32"), ("slippageBps", "uint32"), ("randomize", "bool"),
    ("triggerPrice8dec", "uint64"), ("triggerDir", "uint8"), ("minPrice8dec", "uint64"), ("maxPrice8dec", "uint64"),
    ("clientNonce", "uint64"),
]
CANCEL_TWAP: List[Tuple[str, str]] = [("owner", "address"), ("twapId", "uint64"), ("clientNonce", "uint64")]
SET_MARGIN_MODE: List[Tuple[str, str]] = [("owner", "address"), ("pairId", "uint32"), ("mode", "uint8"), ("nonce", "uint64")]

SET_MARGIN_MODE_TYPEHASH = "0xe21cb7097749ae53e743c95bbe6143cd2dc1917e7504598a32a6f5062f7ebc3d"   # published (op 150)
MODE_CODE = {"cross": 1, "isolated": 2}
SESSION_MAX_SECONDS = 90 * 86400 - 3600


def type_string(name: str, fields: Sequence[Tuple[str, str]]) -> str:
    return f"{name}(" + ",".join(f"{t} {n}" for n, t in fields) + ")"


def struct_hash(name: str, fields: Sequence[Tuple[str, str]], value: Dict[str, Any]) -> bytes:
    """keccak(typeHash ‖ each field abi-encoded); the structs here hold only atomic types."""
    types, vals = ["bytes32"], [keccak(text=type_string(name, fields))]
    for n, t in fields:
        if n not in value:
            raise ValueError(f"{name}: {n} is missing")
        v = value[n]
        types.append(t)
        vals.append(to_checksum_address(v) if t == "address" else bool(v) if t == "bool" else int(v))
    return keccak(encode(types, vals))


def digest(domain_separator: bytes, name: str, fields: Sequence[Tuple[str, str]], value: Dict[str, Any]) -> bytes:
    return keccak(b"\x19\x01" + domain_separator + struct_hash(name, fields, value))


def sign_digest(private_key: str, d: bytes) -> str:
    """65-byte r‖s‖v hex, as a wallet's eth_signTypedData_v4 returns it."""
    from eth_account import Account
    sign = getattr(Account, "unsafe_sign_hash", None) or getattr(Account, "_sign_hash")
    s = sign(d, private_key)
    return "0x" + s.r.to_bytes(32, "big").hex() + s.s.to_bytes(32, "big").hex() + bytes([s.v]).hex()


def next_nonce(after: int = 0, now_ms: Optional[int] = None) -> int:
    """Larger than the last nonce: the time in ms, or the previous nonce + 1."""
    return max(int(time.time() * 1000) if now_ms is None else now_ms, after + 1)


def session_end(end_ms: int, now_ms: Optional[int] = None) -> int:
    """The session's end in seconds: the asked end, at most 90 days less an hour from now."""
    now = int(time.time() * 1000) if now_ms is None else now_ms
    return min(end_ms // 1000, now // 1000 + SESSION_MAX_SECONDS)


# ── request bodies, exactly as the node reads them ──────────────────────────────────────────────────────────────────
def session_create_body(owner: str, session_key: str, expires_at: int, nonce: int, signature: str) -> str:
    return json.dumps({"owner": owner, "session_key": session_key, "expires_at": int(expires_at), "nonce": int(nonce),
                       "signature": signature}, separators=(",", ":"))


def session_revoke_body(owner: str, session_key: str, nonce: int, signature: str) -> str:
    return json.dumps({"owner": owner, "session_key": session_key, "nonce": int(nonce), "signature": signature},
                      separators=(",", ":"))


def twap_body(v: Dict[str, Any], signature: str) -> str:
    """snake_case, the chain's field order, every integer as its exact digits."""
    parts = [("owner", json.dumps(str(v["owner"]))), ("pair_id", str(int(v["pairId"]))), ("side", str(int(v["side"]))),
             ("total_size_18dec", str(int(v["totalSize18dec"]))), ("num_slices", str(int(v["numSlices"]))),
             ("duration_ms", str(int(v["durationMs"]))), ("leverage_bps", str(int(v["leverageBps"]))),
             ("slippage_bps", str(int(v["slippageBps"]))), ("randomize", "true" if v["randomize"] is True else "false"),
             ("trigger_price_8dec", str(int(v["triggerPrice8dec"]))), ("trigger_dir", str(int(v["triggerDir"]))),
             ("min_price_8dec", str(int(v["minPrice8dec"]))), ("max_price_8dec", str(int(v["maxPrice8dec"]))),
             ("client_nonce", str(int(v["clientNonce"]))), ("signature", json.dumps(signature))]
    return "{" + ",".join(f"{json.dumps(k)}:{x}" for k, x in parts) + "}"


def cancel_twap_body(owner: str, twap_id: int, client_nonce: int, signature: str) -> str:
    return f'{{"owner":{json.dumps(owner)},"twap_id":{int(twap_id)},"client_nonce":{int(client_nonce)},"signature":{json.dumps(signature)}}}'


def margin_mode_body(owner: str, pair_id: int, mode: int, nonce: int, signature: str) -> str:
    return f'{{"owner":"{owner.lower()}","pair_id":{int(pair_id)},"mode":{int(mode)},"nonce":{int(nonce)},"signature":"{signature}"}}'


# ── what the spec says about TWAP ───────────────────────────────────────────────────────────────────────────────────
@dataclass(frozen=True)
class TwapRules:
    path: str
    cancel_path: str
    min_duration_ms: int
    max_duration_ms: int
    min_interval_ms: int
    max_slices: int
    max_slippage_bps: int
    min_slice_notional_6dec: int
    min_total_notional_6dec: int


def _val(x: Any) -> Any:
    return x.get("value") if isinstance(x, dict) and "value" in x else x


TWAP_BODY = ["owner", "pair_id", "side", "total_size_18dec", "num_slices", "duration_ms", "leverage_bps", "slippage_bps",
             "randomize", "trigger_price_8dec", "trigger_dir", "min_price_8dec", "max_price_8dec", "client_nonce", "signature"]


def read_twap_rules(spec: Any) -> TwapRules:
    """The spec's ``twap`` section. Raises ValueError (nothing is signed) when it is not published, names another route,
    signs another type or sends another body than this SDK, or does not publish its limits. Two published layouts are
    read: ``place.limits`` (one object), or ``durationMs`` {min, max} + ``subOrders`` {…} beside ``place``."""
    t = spec.get("twap") if isinstance(spec, dict) else None
    if not isinstance(t, dict) or t.get("liveToday") is False or t.get("available") is False:
        why = t.get("reason") if isinstance(t, dict) and isinstance(t.get("reason"), str) else ""
        raise ValueError("the network does not publish TWAP placement" + (f" ({why})" if why else ""))
    place, cancel = t.get("place"), t.get("cancel") if isinstance(t.get("cancel"), dict) else {}
    if not isinstance(place, dict):
        raise ValueError("the network's TWAP section names no placement route")
    path = place.get("path")
    if place.get("method") != "POST" or not (isinstance(path, str) and path.startswith("/")):
        raise ValueError("the network publishes a TWAP route this SDK cannot use")
    if _val(place.get("typeString")) != type_string("PlaceTwap", PLACE_TWAP):
        raise ValueError("the network signs PlaceTwap in another format than this SDK; nothing is signed")
    body = [b.get("name") if isinstance(b, dict) else b for b in place.get("body") or []]
    if [b for b in body if b != "reduce_only"] != TWAP_BODY:
        raise ValueError("the network publishes a TWAP body this SDK does not send; nothing is signed")
    if _val(cancel.get("typeString")) not in (None, type_string("CancelTwap", CANCEL_TWAP)):
        raise ValueError("the network signs CancelTwap in another format than this SDK; nothing is signed")
    def n(src: Any, k: str) -> Optional[int]:
        v = _val(src.get(k)) if isinstance(src, dict) else None
        return int(v) if isinstance(v, int) and not isinstance(v, bool) or (isinstance(v, str) and v.isdigit()) else None
    lim = place.get("limits") or t.get("limits")
    d, so = t.get("durationMs"), t.get("subOrders")
    if isinstance(lim, dict):
        vals = (n(lim, "minDurationMs"), n(lim, "maxDurationMs"), n(lim, "minIntervalMs"), n(lim, "maxNumSlices"),
                n(lim, "maxSlippageBps"), n(lim, "minSubOrderNotional6dec") or 0, n(lim, "minTotalNotional6dec"))
    elif isinstance(d, dict) and isinstance(so, dict):
        vals = (n(d, "min"), n(d, "max"), n(so, "minIntervalMs"), n(so, "maxNumSlices"), n(so, "maxSlippageBpsPerSubOrder"),
                n(so, "minSubOrderNotional6dec") or 0, n(so, "minTotalNotional6dec"))
    else:
        vals = (None,)
    if any(v is None for v in vals) or vals[0] > vals[1]:
        raise ValueError("the network does not publish its TWAP limits, so an order cannot be checked before signing")
    return TwapRules(path=path, cancel_path=str(cancel.get("path") or "/twap/cancel"), min_duration_ms=vals[0],
                     max_duration_ms=vals[1], min_interval_ms=vals[2], max_slices=vals[3], max_slippage_bps=vals[4],
                     min_slice_notional_6dec=vals[5], min_total_notional_6dec=vals[6])


def plan_twap(duration_ms: int, r: TwapRules, total_notional_6dec: Optional[int] = None) -> Tuple[int, int]:
    """(slices, interval ms): as many slices as the limits allow — the most slices, the shortest interval and the smallest
    slice notional — the interval being the duration shared out. Raises ValueError when no plan fits."""
    if not r.min_duration_ms <= duration_ms <= r.max_duration_ms:
        raise ValueError("the running time is outside the network's TWAP range")
    n = min(r.max_slices, duration_ms // max(1, r.min_interval_ms))
    if total_notional_6dec is not None:
        if total_notional_6dec < r.min_total_notional_6dec:
            raise ValueError("the order is smaller than the network's smallest TWAP")
        n = min(n, total_notional_6dec // max(1, r.min_slice_notional_6dec))
    if n < 1:
        raise ValueError("no plan fits the network's TWAP limits")
    return n, duration_ms // n


# ── the client ──────────────────────────────────────────────────────────────────────────────────────────────────────
@dataclass
class Result:
    applied: bool
    status_code: int
    answer: Any
    detail: str = ""


class AccountOps:
    """Session, TWAP and margin-mode operations of one account, signed with the account's own key.

    ``rest`` is the network's REST base (``vordium.network.api_base``), ``spec`` the network spec (for TWAP). A TWAP's
    size and price bounds go onto the market's lot and tick, read from ``GET /markets/specs`` unless ``specs`` is given."""

    def __init__(self, owner_key: str, network=None, rest: Optional[str] = None, timeout: float = 15.0,
                 identity: Optional[Callable[[], Any]] = None, specs: Any = None):
        self.specs = specs
        from eth_account import Account
        from .network import api_base, get_network
        from .node_domain import node_identity, check
        self.net = network or get_network()
        self.rest = (rest or api_base(self.net)).rstrip("/")
        self.key = owner_key
        self.owner = Account.from_key(owner_key).address
        self.timeout = timeout
        ident = (identity or (lambda: node_identity(self.rest)))()
        self.ident = check(ident, self.net)

    # domains (bound to the node's genesis, checked against the configured network)
    def separator(self, domain_class: str) -> bytes:
        return _domains.separator(domain_class, self.ident.chain_id, self.ident.genesis_sha256)

    def _post(self, path: str, body: str) -> Tuple[int, Any]:
        from ._http import session                   # one attempt, never retried; the body is sent byte for byte
        r = session().post(f"{self.rest}{path}", data=body.encode(), headers={"Content-Type": "application/json"}, timeout=self.timeout)
        try:
            return r.status_code, r.json()
        except ValueError:
            return r.status_code, r.text[:300]

    def _get(self, path: str) -> Any:
        from . import _http
        r = _http.get(f"{self.rest}{path}", timeout=self.timeout)
        return r.json() if r.status_code == 200 else None

    @staticmethod
    def _wait(fn: Callable[[], bool], secs: float, step: float = 1.0) -> bool:
        end = time.monotonic() + secs
        while True:
            try:
                if fn():
                    return True
            except Exception:
                pass
            if time.monotonic() >= end:
                return False
            time.sleep(step)

    # session key
    def session(self) -> Optional[Dict[str, Any]]:
        """The session the chain holds for this account: {session_key, expires_at, confirmed}, or None."""
        j = self._get(f"/session/get?owner={self.owner}")
        return j if isinstance(j, dict) and isinstance(j.get("session_key"), str) else None

    def revoke_session(self, wait_s: float = 30.0) -> Result:
        held = self.session()
        if held is None:
            return Result(True, 0, None, "no session to revoke")
        n = next_nonce()
        sig = sign_digest(self.key, digest(self.separator("VordexSession"), "SessionRevoke", SESSION_REVOKE, {"owner": self.owner, "nonce": n}))
        code, ans = self._post("/session/revoke", session_revoke_body(self.owner, held["session_key"], n, sig))
        ok = 200 <= code < 300 and self._wait(lambda: self.session() is None, wait_s)
        return Result(ok, code, ans, "" if ok else "the chain still holds the session")

    def create_session(self, session_key_address: str, end_ms: int, wait_s: float = 60.0) -> Result:
        """Give ``session_key_address`` (a session key, or a registered agent's key) this account's session until
        ``end_ms``. A session the chain holds for another key is revoked first (one more signature)."""
        held = self.session()
        after = 0
        if held and held["session_key"].lower() != session_key_address.lower():
            r = self.revoke_session()
            if not r.applied:
                return Result(False, r.status_code, r.answer, "the account's other session could not be ended")
            after = next_nonce()
        n, exp = next_nonce(after), session_end(end_ms)
        sig = sign_digest(self.key, digest(self.separator("VordexSession"), "SessionCreate", SESSION_CREATE,
                                           {"sessionKey": session_key_address, "expiresAt": exp, "nonce": n}))
        code, ans = self._post("/session/create", session_create_body(self.owner, session_key_address, exp, n, sig))
        mine = lambda: (lambda s: bool(s) and s["session_key"].lower() == session_key_address.lower() and s.get("confirmed") is True)(self.session())
        ok = 200 <= code < 300 and self._wait(mine, wait_s)
        return Result(ok, code, ans, "" if ok else "the chain does not show the session as confirmed")

    # TWAP
    def twaps(self) -> List[Dict[str, Any]]:
        j = self._get(f"/twaps/{self.owner.lower()}")
        rows = j.get("twaps") if isinstance(j, dict) else j
        return rows if isinstance(rows, list) else []

    def place_twap(self, rules: TwapRules, pair_id: int, side: int, total_size_18dec: int, duration_ms: int,
                   leverage_bps: int = 10_000, slippage_bps: int = 100, randomize: bool = False,
                   num_slices: Optional[int] = None, min_price_8dec: int = 0, max_price_8dec: int = 0,
                   wait_s: float = 30.0) -> Result:
        if not 0 <= slippage_bps <= rules.max_slippage_bps:
            raise ValueError("the slippage is above the network's TWAP limit")
        n = num_slices if num_slices is not None else plan_twap(duration_ms, rules)[0]
        total_size_18dec, min_price_8dec, max_price_8dec = self.twap_on_steps(pair_id, total_size_18dec, n,
                                                                              min_price_8dec, max_price_8dec)
        cn = next_nonce()
        v = {"owner": self.owner, "pairId": pair_id, "side": side, "totalSize18dec": total_size_18dec, "numSlices": n,
             "durationMs": duration_ms, "leverageBps": leverage_bps, "slippageBps": slippage_bps, "randomize": randomize,
             "triggerPrice8dec": 0, "triggerDir": 0, "minPrice8dec": min_price_8dec, "maxPrice8dec": max_price_8dec,
             "clientNonce": cn}
        sig = sign_digest(self.key, digest(self.separator("VordCore"), "PlaceTwap", PLACE_TWAP, v))
        code, ans = self._post(rules.path, twap_body(v, sig))
        held = lambda: any(str(t.get("client_nonce")) == str(cn) for t in self.twaps())
        ok = 200 <= code < 300 and self._wait(held, wait_s)
        return Result(ok, code, ans, "" if ok else "the chain does not list the TWAP")

    def twap_on_steps(self, pair_id: int, total_size_18dec: Any, num_slices: int, min_price_8dec: Any = 0,
                      max_price_8dec: Any = 0) -> Tuple[int, int, int]:
        """A TWAP's signed size and price bounds on the market's lot and tick: the total DOWN to a whole number of lots
        per slice (every slice on the lot, never more than asked), the lowest price UP and the highest DOWN (the band
        never widens). Refuses, before signing, a total below one lot per slice or a band the tick empties."""
        from . import units

        spec = units.resolve(getattr(self, "specs", None), self.rest, pair_id, self.timeout)
        n = int(num_slices)
        if n < 1:
            raise units.OrderValueError("a TWAP has at least one slice")
        total = units.whole(total_size_18dec, "total_size_18dec")
        step = units.size_step(spec) * n
        total = units.check_size(total - total % step, spec, total_size_18dec)
        lo = units.whole(min_price_8dec, "min_price_8dec")
        hi = units.whole(max_price_8dec, "max_price_8dec")
        lo = units.snap_price_8dec(lo, spec, "sell") if lo else 0          # up
        hi = units.snap_price_8dec(hi, spec, "buy") if hi else 0           # down
        if lo and hi and hi < lo:
            raise units.OrderValueError("the TWAP's price band holds no tick of this market")
        return total, lo, hi

    def cancel_twap(self, rules: TwapRules, twap_id: int, wait_s: float = 30.0) -> Result:
        cn = next_nonce()
        sig = sign_digest(self.key, digest(self.separator("VordCore"), "CancelTwap", CANCEL_TWAP,
                                           {"owner": self.owner, "twapId": twap_id, "clientNonce": cn}))
        code, ans = self._post(rules.cancel_path, cancel_twap_body(self.owner, twap_id, cn, sig))
        gone = lambda: all(str(t.get("twap_id", t.get("id"))) != str(twap_id) for t in self.twaps())
        ok = 200 <= code < 300 and self._wait(gone, wait_s)
        return Result(ok, code, ans, "" if ok else "the chain still lists the TWAP")

    # margin mode
    def margin_modes(self) -> Optional[Dict[str, Any]]:
        """The chain's cross margin read for this account (GET /account/cross/{address}), or None."""
        j = self._get(f"/account/cross/{self.owner}")
        return j if isinstance(j, dict) else None

    def mode_of(self, pair_id: int) -> Optional[str]:
        j = self.margin_modes()
        if not j:
            return None
        if not isinstance(j.get("modes"), list):
            return None
        m = next((x.get("mode") for x in j["modes"] if isinstance(x, dict) and str(x.get("pair_id")) == str(pair_id)), j.get("default_mode"))
        return {1: "cross", 2: "isolated", "1": "cross", "2": "isolated", "cross": "cross", "isolated": "isolated"}.get(m)

    def set_margin_mode(self, pair_id: int, mode: str, wait_s: float = 30.0) -> Result:
        if mode not in MODE_CODE:
            raise ValueError("mode is cross or isolated")
        n = next_nonce()
        sig = sign_digest(self.key, digest(self.separator("VordCore"), "SetMarginMode", SET_MARGIN_MODE,
                                           {"owner": self.owner, "pairId": pair_id, "mode": MODE_CODE[mode], "nonce": n}))
        code, ans = self._post("/margin/mode", margin_mode_body(self.owner, pair_id, MODE_CODE[mode], n, sig))
        ok = code == 202 and self._wait(lambda: self.mode_of(pair_id) == mode, wait_s)
        return Result(ok, code, ans, "" if ok else "the chain does not show the new mode")
