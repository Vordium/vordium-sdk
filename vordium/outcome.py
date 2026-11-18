"""What a write whose answer was lost turned into, read from the node only.

A write the network takes is answered "submitted": it carries no receipt, so when that answer is lost (a timeout, a
dropped connection, a gateway error, a resent copy answered with the nonce code) the only way to know what happened is
to read the state the write changes. This module does that, the same way for every action:

    sending ──answer──▶ (the answer decides)
       └─lost──▶ pending_checking ──the read shows it────────────▶ applied / applied_other
                         │        ──a refusal record names it────▶ refused
                         │        ──its signed deadline passed───▶ not_applied   (only a write with a deadline)
                         └──the limit passed, nothing proven─────▶ still_unknown (a later check can still end it)

* Reads go to the node the write was sent to, never to an explorer: committed state first (``/orders``,
  ``/positions``, ``/agents``, ``/session/get``, ``/signers``), then the node's own records (``/events/account``) for a
  refusal and for filled versus cancelled. A missing record never means "not applied".
* Every read has its own time limit (``READ_TIMEOUT_S``); a failed read is "not shown yet", never a final.
* Reads come every second for the first 10 s, every 2 s to 30 s, then every 5 s, up to ``LIMIT_S`` (120 s) after the
  send. A call waits ``SETTLE_S`` (30 s) by default and then returns ``pending_checking`` with a :class:`PendingWrite`
  whose :meth:`PendingWrite.check` and :meth:`PendingWrite.wait` go on reading.
* Only the same signed bytes are ever sent again, and only for a write the network applies once (a cancel, an agent
  revoke, the stop). Nothing here signs anything.

Every :class:`Outcome` carries one plain sentence (``text``) and the next action (``next``), from the shared word file
(``outcome_words.json``), and the read that decided it (``read``: route, height, time).

A write sent through this SDK is noted in a journal next to the nonce marks (``outcome-pending.json``, file mode 0600)
before it is sent, and taken off once its outcome is known: :func:`pending` lists what is still open after a restart,
and checks it with ``check=True``.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import threading
import time
import warnings
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Tuple

#: The shared words (package data, a byte-equal copy of the one source).
WORDS: Dict[str, Any] = json.loads(Path(__file__).with_name("outcome_words.json").read_text(encoding="utf-8"))
#: How long after the send an outcome is checked before it is called ``still_unknown`` (seconds).
LIMIT_S: float = float(WORDS["limit_s"])
#: How long a call waits for the outcome before it returns ``pending_checking`` (seconds; 0 returns at once).
SETTLE_S: float = 30.0
#: The time limit of each read while checking (seconds).
READ_TIMEOUT_S: float = 6.0
#: How many of the account's latest records are read (the records have no filter by client nonce).
RECORDS_LIMIT = 200
#: A deadline counts as passed only this long after it, on the network's clock (seconds).
DEADLINE_GRACE_S = 10
#: How long a journal entry is kept (seconds).
JOURNAL_MAX_AGE_S = 86_400

PENDING, STILL_UNKNOWN = "pending_checking", "still_unknown"
APPLIED, APPLIED_OTHER, REFUSED, NOT_APPLIED = "applied", "applied_other", "refused", "not_applied"
STATES = (PENDING, APPLIED, APPLIED_OTHER, REFUSED, NOT_APPLIED, STILL_UNKNOWN)
FINAL = frozenset({APPLIED, APPLIED_OTHER, REFUSED, NOT_APPLIED})
ACTIONS = tuple(WORDS["actions"])
#: Writes the network applies at most once, so the same signed bytes may go again while the outcome is checked.
SAME_BYTES_SAFE = frozenset(a for a, label in WORDS["resend_while_pending"].items() if label)


def interval(elapsed_s: float) -> float:
    """Seconds to the next read: 1 s for the first 10 s, 2 s to 30 s, then 5 s."""
    return 1.0 if elapsed_s < 10 else 2.0 if elapsed_s < 30 else 5.0


_PLACE = re.compile(r"\{([a-z_]+)\}")


def _fill(s: str, fill: Dict[str, Any]) -> str:
    return _PLACE.sub(lambda m: str(fill[m.group(1)]) if fill.get(m.group(1)) is not None else "?", s)


def say(action: str, state: str, /, **fill: Any) -> Tuple[str, str]:
    """(text, next) of ``action`` in ``state``, the placeholders filled."""
    w = WORDS["actions"][action][state]
    return _fill(w["text"], fill), _fill(w["next"], fill)


def clause(meaning: Any) -> str:
    """A chain meaning as the end of a sentence ("Not placed: {meaning}."): no closing stop, a lower-case first word."""
    s = str(meaning or "").strip().rstrip(".").strip()
    if len(s) > 1 and s[0].isupper() and (s[1].islower() or s[1] in " '’"):
        s = s[0].lower() + s[1:]
    return s or "the network refused it"


def body_digest(data: bytes) -> str:
    """sha256 of the exact bytes sent: the same on every copy of one signed write."""
    return hashlib.sha256(data).hexdigest()


def json_bytes(body: Any) -> bytes:
    """The bytes ``requests`` sends for ``json=body``."""
    return json.dumps(body, allow_nan=False).encode("utf-8")


# ── the result ──────────────────────────────────────────────────────────────────────────────────────────────────────
@dataclass
class Outcome:
    """Where one write stands. ``state`` is one of :data:`STATES`; ``applied`` is True for applied / applied_other,
    False for refused / not_applied and None while it is not known. ``read`` is the read that decided (source "node",
    route, height, at_ms); ``resend`` says whether the same signed bytes may go again (``allowed``, ``same_bytes``,
    ``label``, ``why``); ``attempts`` counts the copies of those bytes sent."""
    action: str
    state: str
    text: str
    next: str
    applied: Optional[bool]
    refusal: Optional[Dict[str, Any]] = None
    read: Optional[Dict[str, Any]] = None
    resend: Dict[str, Any] = field(default_factory=dict)
    nonce: Optional[int] = None
    order_id: Optional[int] = None
    agent: Optional[str] = None
    digest: Optional[str] = None
    attempts: int = 0
    counts: Dict[str, Any] = field(default_factory=dict)

    @property
    def final(self) -> bool:
        return self.state in FINAL

    def as_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["final"] = self.final
        return d


def resend_rule(action: str, state: str) -> Dict[str, Any]:
    if state in FINAL:
        return {"allowed": False, "same_bytes": False, "label": None, "why": "final"}
    if action in SAME_BYTES_SAFE:
        return {"allowed": True, "same_bytes": True, "label": WORDS["resend_while_pending"][action],
                "why": "applies_once"}
    if action == "order":
        return {"allowed": False, "same_bytes": False, "label": None, "why": "a_new_signature_is_a_new_order"}
    return {"allowed": False, "same_bytes": False, "label": None, "why": "not_known_to_apply_once"}


@dataclass
class View:
    """One check's finding: ``state`` a final state or None (not shown yet); ``fill`` the words' placeholders;
    ``still`` the placeholders of ``still_unknown``; ``found`` the row or record that showed it."""
    state: Optional[str] = None
    fill: Dict[str, Any] = field(default_factory=dict)
    read: Optional[Dict[str, Any]] = None
    refusal: Optional[Dict[str, Any]] = None
    still: Dict[str, Any] = field(default_factory=dict)
    found: Optional[Dict[str, Any]] = None
    #: the word-file key used instead of ``still_unknown`` once the limit passed (``still_unknown_gone``: the order left
    #: the book with no record yet; ``still_unknown_unread``: the read that decides did not answer)
    still_key: Optional[str] = None


# ── reads (node only) ───────────────────────────────────────────────────────────────────────────────────────────────
class NodeReads:
    """GET reads of one node's REST base, each with its own time limit and no retry. ``get(path)`` may be given (a
    test, or a client's own transport); it returns (status, json) and may raise. Every route read is kept in
    ``routes``."""

    def __init__(self, rest: str, timeout: float = READ_TIMEOUT_S,
                 get: Optional[Callable[[str], Tuple[Optional[int], Any]]] = None):
        self.rest = rest.rstrip("/")
        self.timeout = timeout
        self._get = get
        self._codes: Optional[Dict[str, Any]] = None
        self.routes: List[str] = []

    def get(self, path: str) -> Tuple[Optional[int], Any]:
        self.routes.append(path)
        try:
            if self._get is not None:
                return self._get(path)
            from . import _http
            r = _http.get(f"{self.rest}{path}", timeout=self.timeout, retries=0)
            try:
                j = r.json()
            except ValueError:
                j = None
            return r.status_code, j
        except Exception:
            return None, None

    def ok(self, path: str) -> Any:
        """The answer of a 200, else None."""
        st, j = self.get(path)
        return j if st == 200 else None

    def records(self, owner: str) -> Tuple[Optional[List[Dict[str, Any]]], Dict[str, Any]]:
        j = self.ok(f"/events/account/{str(owner).lower()}?limit={RECORDS_LIMIT}")
        if not isinstance(j, dict) or not isinstance(j.get("events"), list):
            return None, {}
        cov = j.get("coverage") if isinstance(j.get("coverage"), dict) else {}
        return [e for e in j["events"] if isinstance(e, dict)], cov

    def head(self) -> Optional[int]:
        j = self.ok("/status")
        h = j.get("chain_head") if isinstance(j, dict) else None
        return h if isinstance(h, int) and not isinstance(h, bool) else None

    def codes(self) -> Dict[str, Any]:
        """The network's refusal words (``GET /orders/codes``), read once."""
        if self._codes is None:
            j = self.ok("/orders/codes")
            self._codes = j if isinstance(j, dict) else {}
        return self._codes

    def meaning(self, code: str, agent: bool = False) -> Tuple[Optional[str], Optional[str]]:
        rows = self.codes().get("agent_refusal_keys" if agent else "order_refusal_codes") or []
        key = "key" if agent else "code"
        for r in rows if isinstance(rows, list) else []:
            if isinstance(r, dict) and r.get(key) == code:
                return r.get("meaning"), r.get("action")
        return None, None


def _now_ms() -> int:
    return int(time.time() * 1000)


def _read(route: str, height: Optional[int]) -> Dict[str, Any]:
    return {"source": "node", "route": route, "height": height, "at_ms": _now_ms()}


def _int(v: Any) -> Optional[int]:
    if isinstance(v, bool) or v is None:
        return None
    if isinstance(v, int):
        return v
    if isinstance(v, str) and v.strip().isdigit():
        return int(v.strip())
    return None


def _scan_anchor(recs: List[Dict[str, Any]], cov: Dict[str, Any], since_ms: int) -> Optional[int]:
    """The height of the newest record older than ``since_ms`` when the read of the latest records covers every record
    since then: it holds such a record (so it reached back before the send), and no gap (a snapshot restore) or pruning
    lies above it. None when that is not shown."""
    def at(e: Dict[str, Any]) -> Optional[int]:
        v = _int(e.get("at_ms"))
        return v if v is not None and v >= 10 ** 12 else None          # milliseconds only (a seconds value is not one)
    before = [h for h in (_int(e.get("height")) for e in recs if (at(e) or since_ms) < since_ms) if h is not None]
    if not before:
        return None
    anchor = max(before)
    for g in cov.get("gaps") or []:
        resumed = _int(g.get("resumed_at")) if isinstance(g, dict) else None
        after = _int(g.get("after_height")) if isinstance(g, dict) else None
        if resumed is None or after is None or resumed > anchor or after >= anchor:
            return None                                               # a gap above the anchor, or one not understood
    pruned = _int(cov.get("pruned_below"))
    return anchor if pruned is None or pruned <= anchor else None


def _deadline_passed(valid_until_s: Optional[int], chain_ms: Optional[Callable[[], Optional[int]]]) -> bool:
    if valid_until_s is None or chain_ms is None:
        return False
    try:
        now = chain_ms()
    except Exception:
        return False
    return isinstance(now, int) and now > (int(valid_until_s) + DEADLINE_GRACE_S) * 1000


# ── judges: one check of what a write did ──────────────────────────────────────────────────────────────────────────
def _closed_words(rec: Dict[str, Any]) -> str:
    st = str(rec.get("status") or "").lower()
    if st == "filled":
        return "Filled"
    if (_int(rec.get("filled_total_18dec")) or _int(rec.get("filled_18dec")) or 0) > 0 or rec.get("partially_filled") is True:
        return "Partly filled"
    return "Placed"


#: Refusal codes that name the nonce: a later copy of OUR write (or another signer's) meets them while an earlier copy
#: applied, so they never prove that our write did not apply.
NONCE_CODES = frozenset({"nonce", "nonce_used", "nonce_window", "nonce_jam", "duplicate", "duplicate_nonce"})


def _signer_matches(rec: Dict[str, Any], agent: Optional[str]) -> bool:
    """Whether a row or record was signed by our signer: the network keeps one nonce window per signer, so an agent and
    the account's own or session key may use the same client nonce. ``agent`` is our signer when it is an agent of the
    account (None: the account's own key or its session key). A record that does not say which agent signed it is
    counted only for a signer that is not an agent."""
    got = rec.get("agent")
    got = got.lower() if isinstance(got, str) and got else None
    return got == (agent.lower() if agent else None)


class SignerOf:
    """Whether the signer of a write is an agent of the account, read once from the node (``/agents/{owner}/{signer}``)
    and kept only once the read answered: (known, agent address or None)."""

    def __init__(self, r: "NodeReads", owner: str, signer: Optional[str], journal_id: Optional[str] = None):
        self.r, self.owner, self.signer, self.journal_id = r, str(owner), signer, journal_id
        self.known: Optional[Tuple[bool, Optional[str]]] = None
        if not signer or signer.lower() == self.owner.lower():
            self.known = (True, None)

    def __call__(self) -> Tuple[bool, Optional[str]]:
        if self.known is None:
            st, a = self.r.get(f"/agents/{self.owner}/{str(self.signer).lower()}")
            if st == 200 and isinstance(a, dict):
                self.known = (True, self.signer if a.get("found") is not False and a.get("agent") else None)
            else:
                return False, None                           # not answered: asked again at the next check
            journal_set(self.journal_id, agent=self.known[1])
        return self.known


def _records_current(head: Optional[int], cov: Dict[str, Any]) -> bool:
    """The node's records are being written and have reached ``head`` (read just before them)."""
    if head is None or cov.get("recording") is False:
        return False
    last = _int(cov.get("last_height"))
    return last is not None and last >= head


def judge_order(r: NodeReads, owner: str, client_nonce: int, signed: Optional[Dict[str, Any]] = None,
                rewound: Optional[int] = None, valid_until_s: Optional[int] = None, sent_at_ms: Optional[int] = None,
                chain_ms: Optional[Callable[[], Optional[int]]] = None, agent: Optional[str] = None) -> View:
    """An order by its client nonce, signed by our signer (``agent`` when an agent of the account signed it): listed
    with what was signed (applied), its closing or placing record (applied: Filled / Partly filled / Placed), a refusal
    record with its nonce, our signer and our market that does not name the nonce (refused), or, for an order with a
    signed deadline once that deadline passed on the network's clock and a full, current read of the records shows
    nothing, not_applied."""
    from .dex import matches_signed
    if not signed:
        return View()                       # without what was signed nothing can be told apart from another write
    want = str(int(client_nonce))

    def newer(rec: Dict[str, Any]) -> bool:
        if rewound is None:
            return True
        ts = next((_int(rec.get(k)) for k in ("timestamp_ms", "ts_ms", "time_ms", "at_ms") if _int(rec.get(k))), None)
        return ts is not None and ts > rewound

    route_o = f"/orders/{owner}"
    rows = r.ok(route_o)
    resting = None
    if isinstance(rows, list):
        resting = next((o for o in rows if isinstance(o, dict) and str(o.get("client_nonce")) == want
                        and matches_signed(o, signed) and _signer_matches(o, agent) and newer(o)), None)
    head = r.head() if valid_until_s is not None else None
    recs, cov = r.records(owner)
    route_r = f"/events/account/{str(owner).lower()}"
    mine = [e for e in recs or [] if str(e.get("client_nonce")) == want and newer(e) and _signer_matches(e, agent)]
    placed = next((e for e in mine if e.get("kind") == "order_placed" and matches_signed(e, signed)), None)
    closed = next((e for e in mine if e.get("kind") == "order_closed" and matches_signed(e, signed)), None)
    if resting is not None:
        h = _int((placed or {}).get("height")) or r.head()
        return View(APPLIED, {"order_words": "Placed", "height": h}, _read(route_o, h), found={"source": "orders", **resting})
    if closed is not None or placed is not None:
        rec = closed or placed
        h = _int(rec.get("height"))
        return View(APPLIED, {"order_words": _closed_words(closed) if closed else "Placed", "height": h},
                    _read(route_r, h), found={"source": "events", **rec})
    pair = int(signed["pair_id"])
    for kind, by_agent in (("agent_refused", True), ("order_refused", False)):
        e = next((x for x in mine if x.get("kind") == kind and _int(x.get("pair_id")) == pair
                  and str((x.get("reason") if by_agent else x.get("code")) or "").lower() not in NONCE_CODES), None)
        if e is not None:
            code = str((e.get("reason") if by_agent else e.get("code")) or "")
            meaning, action = r.meaning(code, by_agent)
            meaning = meaning or e.get("meaning") or code
            h = _int(e.get("height"))
            return View(REFUSED, {"meaning": clause(meaning), "action": action or ""}, _read(route_r, h),
                        refusal={"code": code, "meaning": meaning, "action": action}, found={"source": "events", **e})
    if (_deadline_passed(valid_until_s, chain_ms) and isinstance(rows, list) and recs is not None
            and sent_at_ms is not None and _scan_anchor(recs, cov, sent_at_ms - 60_000) is not None
            and _records_current(head, cov)):
        return View(NOT_APPLIED, {}, _read(route_r, None))
    return View()


def judge_cancel(r: NodeReads, owner: str, order_id: int) -> View:
    """A cancel: the order no longer listed AND its record says cancelled (applied) or filled (applied_other)."""
    from .dex import cancel_outcome
    route_o = f"/orders/{owner}"
    rows = r.ok(route_o)
    if not isinstance(rows, list):
        return View(still_key="still_unknown_unread")
    if any(isinstance(o, dict) and str(o.get("id", o.get("order_id"))) == str(order_id) for o in rows):
        return View()
    recs, _ = r.records(owner)
    how = cancel_outcome(recs, order_id)
    rec = next((e for e in recs or [] if str(e.get("order_id", e.get("id"))) == str(order_id)
                and e.get("kind") in ("order_closed", "order_cancelled")), None)
    h = _int((rec or {}).get("height"))
    route_r = f"/events/account/{str(owner).lower()}"
    if how == "cancelled":
        return View(APPLIED, {"height": h}, _read(route_r, h), found=rec)
    if how == "filled":
        return View(APPLIED_OTHER, {"height": h}, _read(route_r, h), found=rec)
    # gone from the book with no record yet: it closed, but whether by this cancel or a fill is not known
    return View(still={"order_gone": True}, still_key="still_unknown_gone")


def _order_ids(rows: Any, pair_id: int = 0) -> Optional[List[int]]:
    if not isinstance(rows, list):
        return None
    out = []
    for o in rows:
        if not isinstance(o, dict):
            continue
        if o.get("liquidation") is True or o.get("is_liquidation") is True:
            continue                                           # the network's liquidation order is not the account's
        if pair_id and _int(o.get("pair_id")) != int(pair_id):
            continue
        i = _int(o.get("id", o.get("order_id")))
        if i is not None:
            out.append(i)
    return out


def judge_cancel_all(r: NodeReads, owner: str, before: Optional[Sequence[int]], pair_id: int = 0) -> View:
    """A cancel-all: none of the orders listed before the send is still listed, every one of them has its closing
    record, and at least one closed as cancelled (applied; applied_other when some filled first). With nothing listed
    before, or no cancel among the records, nothing shows that the cancel-all applied: it stays not known."""
    from .dex import cancel_outcome
    route_o = f"/orders/{owner}"
    ids = _order_ids(r.ok(route_o), pair_id)
    if ids is None:
        return View(still_key="still_unknown_unread")
    if before is None:
        return View(still={"n": len(ids)})
    left = [i for i in before if i in set(ids)]
    if left or not before:
        return View(still={"n": len(left)})
    recs, _ = r.records(owner)
    how = [cancel_outcome(recs, i) for i in before]
    if any(h is None for h in how) or "cancelled" not in how:
        return View(still={"n": 0})
    m, k = len(before), how.count("filled")
    h = r.head()
    if k:
        return View(APPLIED_OTHER, {"n": m - k, "m": m, "k": k}, _read(route_o, h))
    return View(APPLIED, {"n": m}, _read(route_o, h))


def judge_batch(r: NodeReads, owner: str, places: Sequence[Tuple[int, Dict[str, Any]]], cancels: Sequence[int],
                rewound: Optional[int] = None, cancel_nonces: Sequence[int] = (), agent: Optional[str] = None) -> View:
    """A batch: every place shown (or refused) by its client nonce, and every cancelled order (by id, or by client
    nonce) no longer listed and closed in the records. Applied only when every action is decided."""
    from .dex import cancel_outcome
    route_o = f"/orders/{owner}"
    if not places and not cancels and not cancel_nonces:
        return View()
    if cancels or cancel_nonces:
        rows = r.ok(route_o)
        if not isinstance(rows, list):
            return View(still_key="still_unknown_unread")
        ids = set(_order_ids(rows) or [])
        cns = {str(o.get("client_nonce")) for o in rows if isinstance(o, dict)}
        if any(i in ids for i in cancels) or any(str(n) in cns for n in cancel_nonces):
            return View(still={"n": len(cancels) + len(cancel_nonces)})
        recs, _ = r.records(owner)
        if any(cancel_outcome(recs, i) is None for i in cancels):
            return View(still={"n": 0})
        closed = {str(e.get("client_nonce")) for e in recs or [] if e.get("kind") == "order_closed"}
        if any(str(n) not in closed for n in cancel_nonces):
            return View(still={"n": 0})
    results = [judge_order(r, owner, n, s, rewound, agent=agent) for n, s in places]
    if any(v.state is None for v in results):
        return View()
    if results and not cancels and not cancel_nonces and all(v.state == REFUSED for v in results):
        return results[0]
    if not results:
        return View(APPLIED, {"n": len(cancels) + len(cancel_nonces)}, _read(route_o, r.head()))
    h = max([_int(v.fill.get("height")) or 0 for v in results] + [0]) or r.head()
    refused = sum(1 for v in results if v.state == REFUSED)
    return View(APPLIED, {"order_words": "Placed", "height": h, "placed": len(results) - refused, "refused": refused,
                          "cancelled": len(cancels) + len(cancel_nonces)}, _read(route_o, h))


def judge_revoke(r: NodeReads, owner: str, agent: str) -> View:
    """An agent revoke: the agent's committed record reads ``revoked``."""
    route = f"/agents/{owner}/{agent}"
    a = r.ok(route)
    if not isinstance(a, dict):
        return View(still_key="still_unknown_unread")
    if str(a.get("status") or "").lower() != "revoked":
        return View()
    h = _int(a.get("revoked_height"))
    return View(APPLIED, {"height": h, "m": _int(a.get("revoke_orders_cancelled")) or 0},
                _read(route, h or _int(a.get("head_height"))), found=a)


def _plural(n: int, one: str, many: str) -> str:
    return one if n == 1 else many


def _stored_session_nonce(*reads: Any) -> Optional[int]:
    out = None
    for j in reads:
        if isinstance(j, dict):
            for k in ("nonce", "last_nonce", "session_nonce"):
                v = _int(j.get(k))
                if v is not None:
                    out = v if out is None else max(out, v)
    return out


def judge_stop(r: NodeReads, owner: str, valid_until_s: Optional[int] = None,
               chain_ms: Optional[Callable[[], Optional[int]]] = None, nonce: Optional[int] = None) -> View:
    """The stop (StopAllSigners): no trading key (the session read answers "no active session") and no live agent
    (``/signers`` names ``app_session`` as null and ``live_agents`` 0); then the open orders decide applied (none) or
    applied_other (orders the wallet placed itself stay). Past its signed deadline with a key or an agent still live,
    and the stored session nonce still below the stop's ``nonce``: not_applied."""
    st, s = r.get(f"/session/get?owner={owner}")
    no_session = st == 404 and isinstance(s, dict) and "no active session" in str(s.get("error") or "").lower()
    session = ("none" if no_session else "live" if st == 200 and isinstance(s, dict)
               and isinstance(s.get("session_key"), str) else None)
    sg = r.ok(f"/signers/{owner}")
    live = _int(sg.get("live_agents")) if isinstance(sg, dict) else None
    app = sg.get("app_session", "unread") if isinstance(sg, dict) else "unread"
    rows = r.ok(f"/orders/{owner}")
    orders = len(rows) if isinstance(rows, list) else None
    h = _int(sg.get("head_height")) if isinstance(sg, dict) else None
    if session == "none" and live == 0 and app is None:
        if orders == 0:
            return View(APPLIED, {}, _read(f"/signers/{owner}", h))
        if orders is not None:
            return View(APPLIED_OTHER, {"n": orders}, _read(f"/signers/{owner}", h))
    elif session == "live" or (live or 0) > 0 or (app not in (None, "unread")):
        stored = _stored_session_nonce(s, sg)
        if (_deadline_passed(valid_until_s, chain_ms) and nonce is not None and stored is not None
                and stored < int(nonce)):
            return View(NOT_APPLIED, {}, _read(f"/signers/{owner}", h))
    parts = []
    if session == "live" or (app not in (None, "unread")):
        parts.append("your trading key is still on")
    elif session is None:
        parts.append("your trading key could not be read")
    if live is None:
        parts.append("your agents could not be read")
    elif live > 0:
        parts.append(f"{live} {_plural(live, 'agent is', 'agents are')} still live")
    if orders is None:
        parts.append("your open orders could not be read")
    what = "; ".join(parts) or "the network has not shown the stop"
    return View(still={"what_is_live": what[0].upper() + what[1:]})


# ── a write being checked ───────────────────────────────────────────────────────────────────────────────────────────
class PendingWrite:
    """A sent write whose outcome is being read. :meth:`check` reads once; :meth:`wait` reads until a final or a time
    limit; :meth:`resend_same` sends the same signed bytes again (only where the network applies the write once)."""

    def __init__(self, action: str, judge: Callable[[], View], *, started: Optional[float] = None,
                 meta: Optional[Dict[str, Any]] = None, resend: Optional[Callable[[], Any]] = None,
                 journal_id: Optional[str] = None, clock: Optional[Callable[[], float]] = None,
                 sleep: Optional[Callable[[float], None]] = None, limit_s: float = LIMIT_S):
        if action not in WORDS["actions"]:
            raise ValueError(f"no words for the action {action!r}")
        self.action, self._judge, self.meta = action, judge, dict(meta or {})
        self._clock = clock or _clock
        self._sleep = sleep or _sleep
        self.started = self._clock() if started is None else started
        self.limit_s = limit_s
        self._resend = resend
        self.journal_id = journal_id
        self.attempts = int(self.meta.pop("attempts", 1) or 1)
        self.last: Outcome = self._outcome(PENDING, View())
        self._lock = threading.Lock()

    def _outcome(self, state: str, v: View) -> Outcome:
        fill = v.fill if state in FINAL else v.still
        key = v.still_key if state == STILL_UNKNOWN and v.still_key in WORDS["actions"][self.action] else state
        text, nxt = say(self.action, key, **fill)
        rule = resend_rule(self.action, state)
        if rule["allowed"] and self._resend is None:
            rule = {"allowed": False, "same_bytes": False, "label": None, "why": "bytes_not_kept"}
        return Outcome(self.action, state, text, nxt, True if state in (APPLIED, APPLIED_OTHER)
                       else False if state in (REFUSED, NOT_APPLIED) else None, v.refusal, v.read,
                       rule, self.meta.get("nonce"), self.meta.get("order_id"),
                       self.meta.get("agent"), self.meta.get("digest"), self.attempts,
                       {k: x for k, x in (v.fill if state in FINAL else v.still).items() if isinstance(x, (int, bool))})

    @property
    def elapsed(self) -> float:
        return self._clock() - self.started

    def _judged(self) -> View:
        try:
            v = self._judge()
            return v if isinstance(v, View) else View()
        except Exception:
            return View()                                          # a failed read is "not shown yet"

    def check(self) -> Outcome:
        """Read once. A final ends it (and takes it off the journal); otherwise ``pending_checking`` within the limit,
        ``still_unknown`` after it."""
        with self._lock:
            v = self._judged()
            self.found = v.found
            if v.state in FINAL:
                self.last = self._outcome(v.state, v)
                journal_done(self.journal_id)
            else:
                self.last = self._outcome(STILL_UNKNOWN if self.elapsed >= self.limit_s else PENDING, v)
            return self.last

    def wait(self, limit_s: Optional[float] = None) -> Outcome:
        """Read until a final, or ``limit_s`` seconds from now (default: to the end of the limit after the send; at
        least one read). Never sends anything."""
        end = self._clock() + (max(0.0, self.limit_s - self.elapsed) if limit_s is None else max(0.0, limit_s))
        while True:
            o = self.check()
            now = self._clock()
            if o.final or now >= end:
                return o
            self._sleep(max(0.0, min(interval(now - self.started), end - now)))

    def resend_same(self) -> Outcome:
        """Send the same signed bytes once more (a cancel, a revoke, the stop: the network applies them once), then
        read once. Refused (ValueError) for any other write or once the outcome is final."""
        rule = resend_rule(self.action, self.last.state)
        if not rule["allowed"] or self._resend is None:
            raise ValueError("this write is not sent again: " + rule["why"])
        try:
            self._resend()
        except Exception:
            pass                                   # its answer decides nothing: the read does
        finally:
            self.attempts += 1
        return self.check()

    def __repr__(self) -> str:
        return f"PendingWrite({self.action!r}, state={self.last.state!r}, attempts={self.attempts})"


_clock: Callable[[], float] = time.monotonic
_sleep: Callable[[float], None] = time.sleep


def settle(pw: PendingWrite, settle_s: float) -> Outcome:
    """Wait inside the call: up to ``settle_s`` seconds (0 = no read: ``pending_checking`` at once)."""
    if settle_s is None or settle_s <= 0:
        return pw.last
    return pw.wait(min(float(settle_s), max(0.0, pw.limit_s - pw.elapsed)) or 0.0)


# ── the journal ─────────────────────────────────────────────────────────────────────────────────────────────────────
JOURNAL_NAME = "outcome-pending.json"
_JLOCK = threading.Lock()


def _journal_path() -> Path:
    from . import nonces
    return nonces.state_dir() / JOURNAL_NAME


def _journal_update(fn: Callable[[Dict[str, Any]], None]) -> None:
    from . import nonces
    p = _journal_path()
    try:
        p.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        with _JLOCK, nonces._file_lock(p.with_name(p.name + ".lock")):
            try:
                data = json.loads(p.read_text(encoding="utf-8"))
                data = data if isinstance(data, dict) else {}
            except (FileNotFoundError, ValueError):
                data = {}
            fn(data)
            cut = time.time() * 1000 - JOURNAL_MAX_AGE_S * 1000
            data = {k: e for k, e in data.items() if isinstance(e, dict) and (_int(e.get("sent_at_ms")) or 0) >= cut}
            tmp = p.with_name(f"{p.name}.{os.getpid()}.{threading.get_ident()}.tmp")
            fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            try:
                os.write(fd, json.dumps(data, sort_keys=True).encode("utf-8"))
            finally:
                os.close(fd)
            os.replace(tmp, p)
    except OSError as e:
        warnings.warn(f"the pending-write journal could not be written ({e.__class__.__name__}); the outcome is still "
                      "checked in this process", nonces.NonceStateWarning, stacklevel=3)


def journal_add(entry: Dict[str, Any]) -> str:
    """Note a write BEFORE it is sent; returns its id (the digest of its bytes)."""
    jid = str(entry["digest"])
    e = {**entry, "state": "sending"}

    def put(d: Dict[str, Any]) -> None:
        d[jid] = e
    _journal_update(put)
    return jid


def journal_set(jid: Optional[str], **fields: Any) -> None:
    if not jid:
        return

    def put(d: Dict[str, Any]) -> None:
        if jid in d:
            d[jid].update(fields)
    _journal_update(put)


def journal_done(jid: Optional[str]) -> None:
    if not jid:
        return

    def drop(d: Dict[str, Any]) -> None:
        d.pop(jid, None)
    _journal_update(drop)


def _judge_for(entry: Dict[str, Any], reads: NodeReads, chain_ms=None) -> Callable[[], View]:
    a, owner = entry.get("action"), entry.get("owner")
    who = SignerOf(reads, owner, entry.get("signer"), entry.get("digest"))
    if "agent" in entry:
        who.known = (True, entry.get("agent"))
    if a == "order":
        signed = entry.get("signed")

        def judge_one() -> View:
            known, agent = who()
            if not known:
                return View()
            return judge_order(reads, owner, int(entry["nonce"]), signed, entry.get("rewound"),
                               entry.get("valid_until"), entry.get("sent_at_ms"), chain_ms, agent)
        return judge_one
    if a == "cancel":
        return lambda: judge_cancel(reads, owner, int(entry["order_id"]))
    if a == "cancel_all":
        return lambda: judge_cancel_all(reads, owner, entry.get("before"), int(entry.get("pair_id") or 0))
    if a == "revoke":
        return lambda: judge_revoke(reads, owner, entry["agent"])
    if a == "stop":
        return lambda: judge_stop(reads, owner, entry.get("valid_until"), chain_ms, entry.get("nonce"))
    if a == "batch":
        def judge_b() -> View:
            known, agent = who() if entry.get("places") else (True, None)
            if not known:
                return View()
            return judge_batch(reads, owner, [(int(n), s) for n, s in entry.get("places") or []],
                               [int(i) for i in entry.get("cancels") or []], entry.get("rewound"),
                               [int(n) for n in entry.get("cancel_nonces") or []], agent)
        return judge_b
    raise ValueError(f"unknown action {a!r}")


def pending(check: bool = False, max_age_s: float = JOURNAL_MAX_AGE_S) -> List[Any]:
    """The writes noted in this computer's journal whose outcome is not known yet (younger than ``max_age_s``), as
    dicts: action, owner, node (``rest``), nonce / order id / agent, digest, sent_at_ms, state. With ``check=True``
    each is read once at the node it was sent to and an :class:`Outcome` is returned for it instead; a final one is
    taken off the journal."""
    try:
        data = json.loads(_journal_path().read_text(encoding="utf-8"))
    except (FileNotFoundError, ValueError, OSError):
        return []
    cut = time.time() * 1000 - max_age_s * 1000
    rows = [e for e in data.values() if isinstance(e, dict) and (_int(e.get("sent_at_ms")) or 0) >= cut]
    rows.sort(key=lambda e: _int(e.get("sent_at_ms")) or 0)
    if not check:
        return rows
    out = []
    for e in rows:
        reads = NodeReads(str(e.get("rest") or ""))
        action = e.get("action")
        if action == "batch":
            action = "order" if e.get("places") else "cancel_all"
        pw = PendingWrite(action, _judge_for(e, reads), started=_clock() - max(
            0.0, (time.time() * 1000 - (_int(e.get("sent_at_ms")) or 0)) / 1000), meta={
            "nonce": e.get("nonce"), "order_id": e.get("order_id"), "agent": e.get("agent"),
            "digest": e.get("digest"), "attempts": e.get("attempts") or 1}, journal_id=e.get("digest"))
        out.append(pw.check())
    return out
