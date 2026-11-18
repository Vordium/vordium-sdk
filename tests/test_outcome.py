"""A write whose answer was lost: the outcome is read from the node only (never an explorer), the same signed bytes are
the only thing ever sent again, and the state goes pending_checking -> a final (or still_unknown) with the shared words.
Fake node, no network."""
import json
import os
import stat
from pathlib import Path

import pytest
import requests
from eth_account import Account

from vordium import _http, account_ops as A, dex, mm, nonces, outcome as oc
from vordium.eip712 import sign_agent_op

NODE = "http://node.invalid"
OWNER_KEY = "0x" + "21" * 32
OWNER = Account.from_key(OWNER_KEY).address
SESSION_KEY = "0x" + "31" * 32
AGENT = "0x" + "4e" * 20


class Resp:
    def __init__(self, code, j):
        self.status_code, self._j, self.headers = code, j, {}
        self.content = b"" if j is None else json.dumps(j).encode()
        self.text = self.content.decode()

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.HTTPError(str(self.status_code))

    def json(self):
        if self._j is None:
            raise ValueError("no json")
        return self._j


class Node:
    """A node the client talks to: every request is logged; GETs read ``state``; POSTs go to ``script(path, data, i)``."""

    def __init__(self, monkeypatch, script=None):
        self.urls, self.posts = [], []
        self.state = {"orders": [], "events": [], "coverage": {}, "agents": {}, "session": None, "signers": None,
                      "codes": {"order_refusal_codes": [{"code": "insufficient_margin", "meaning": "The account's free "
                                "margin does not cover the order.", "action": "Add USDC or make the order smaller."}],
                                "agent_refusal_keys": [{"key": "policy_expired", "meaning": "The agent's policy has expired.",
                                                        "action": "The owner sets a new policy."}]},
                      "head": 1000}
        self.script = script or (lambda path, data, i: (202, {"status": "submitted", "intaken": True}))
        node = self

        def get(url, timeout=None, retries=None, headers=None):
            node.urls.append(("GET", url))
            return node.get(url)

        def post(url, json=None, timeout=None, headers=None):
            data = _jbytes(json)
            node.urls.append(("POST", url))
            node.posts.append((url, data))
            return Resp(*node.script(url[len(NODE):], data, len(node.posts)))

        class S:
            def post(self, url, data=None, headers=None, timeout=None):
                node.urls.append(("POST", url))
                node.posts.append((url, data))
                return Resp(*node.script(url[len(NODE):], data, len(node.posts)))
        monkeypatch.setattr(_http, "get", get)
        monkeypatch.setattr(_http, "post", post)
        monkeypatch.setattr(_http, "session", lambda: S())

    def get(self, url):
        s, p = self.state, url[len(NODE):]
        if p.startswith("/orders/codes"):
            return Resp(200, s["codes"])
        if p.startswith("/orders/"):
            return Resp(200, s["orders"])
        if p.startswith("/events/account/"):
            return Resp(200, {"events": s["events"], "coverage": s["coverage"]})
        if p.startswith("/status"):
            return Resp(200, {"chain_head": s["head"]})
        if p.startswith("/agents/"):
            a = s["agents"].get(p.rsplit("/", 1)[1].lower())
            return Resp(200, a) if a else Resp(200, {"found": False})      # as the node answers an unknown agent
        if p.startswith("/session/get"):
            return Resp(200, s["session"]) if s["session"] else Resp(404, {"error": "no active session", "session_nonce": 5})
        if p.startswith("/signers/"):
            return Resp(200, s["signers"] or {"live_agents": 0, "app_session": None, "head_height": s["head"], "agents": []})
        return Resp(404, {"error": "not found"})


def _jbytes(body):
    return json.dumps(body, allow_nan=False).encode()


def lost_then(apply, then=(400, {"code": "nonce_used", "error": "already used"})):
    """The first copy reaches the node (``apply`` runs) and its answer is lost; later copies get ``then``."""
    def script(path, data, i):
        if i == 1:
            apply(json.loads(data))
            raise requests.ReadTimeout("read timed out")
        return then
    return script


def _vx():
    return dex.Vordex(rpc_url=NODE, chain_clock=None)


def _no_explorer(node):
    for _, u in node.urls:
        assert u.startswith(NODE + "/"), u
        assert "vordscan" not in u and "/fills/" not in u and "/orders/history" not in u, u


def _list_order(node, body, oid=7):
    node.state["orders"].append({"id": oid, "client_nonce": int(body["clientNonce"]), "pair_id": body["pairId"],
                                 "side": body["side"], "size": body["size_18dec"],
                                 "price_8dec": int(round(body["price"] * 1e8)) if "price" in body else 0})


# ── the words and the schedule ─────────────────────────────────────────────────────────────────────────────────────
def test_the_words_are_the_shared_file_and_every_action_has_its_states():
    shipped = Path(oc.__file__).with_name("outcome_words.json")
    assert json.loads(shipped.read_bytes()) == oc.WORDS and oc.LIMIT_S == 120
    for a, states in oc.WORDS["actions"].items():
        assert {"pending_checking", "applied", "refused", "still_unknown"} <= set(states), a
    assert oc.say("order", "pending_checking")[0].startswith("Pending — checking.")
    assert oc.say("revoke", "applied", height=9, m=2) == ("Agent revoked at block 9. 2 orders cancelled.", "")
    assert oc.clause("The agent's policy has expired.") == "the agent's policy has expired"


def test_the_read_schedule_is_1s_then_2s_then_5s():
    assert [oc.interval(t) for t in (0, 9.9, 10, 29, 30, 119)] == [1, 1, 2, 2, 5, 5]


# ── orders ──────────────────────────────────────────────────────────────────────────────────────────────────────────
def test_a_lost_answer_resends_the_same_bytes_and_ends_applied_from_the_orders_read(monkeypatch):
    node = Node(monkeypatch)
    node.script = lost_then(lambda b: _list_order(node, b))
    out = _vx().place_order(SESSION_KEY, OWNER, 1, dex.BUY, 1, 100)
    bodies = [d for _, d in node.posts]
    assert len(bodies) == 2 and bodies[0] == bodies[1]                      # one signature, identical bytes
    o = out["outcome"]
    assert out["status"] == "received" and o.state == "applied" and o.applied is True and o.final
    assert o.text == "Placed. Found on the network at block 1000." and o.next == ""
    assert o.read["source"] == "node" and o.read["route"].startswith("/orders/") and o.digest == oc.body_digest(bodies[0])
    assert out["pending"] is None and oc.pending() == []                     # the journal entry is gone
    _no_explorer(node)


def test_records_lag_does_not_stop_the_committed_read_and_never_reads_not_applied(monkeypatch):
    node = Node(monkeypatch)
    node.state["events"] = []                                                 # the records have not caught up
    node.script = lost_then(lambda b: _list_order(node, b))
    assert _vx().place_order(SESSION_KEY, OWNER, 1, dex.BUY, 1, 100)["outcome"].state == "applied"


def test_a_502_after_the_order_applied_is_read_back_not_refused(monkeypatch):
    node = Node(monkeypatch)
    monkeypatch.setattr(_http, "retry_wait", lambda attempt, ra=None, rand=None: 0.0)

    def script(path, data, i):
        if i == 1:
            _list_order(node, json.loads(data))
            return 502, {}
        return 400, {"code": "nonce_used"}
    node.script = script
    out = _vx().place_order(SESSION_KEY, OWNER, 1, dex.BUY, 1, 100)
    assert out["outcome"].state == "applied" and len({d for _, d in node.posts}) == 1


def test_never_sent_raises_and_leaves_no_journal_entry(monkeypatch):
    node = Node(monkeypatch, lambda path, data, i: (_ for _ in ()).throw(requests.ConnectTimeout("connect timed out")))
    monkeypatch.setattr(_http, "retry_wait", lambda attempt, ra=None, rand=None: 0.0)
    with pytest.raises(nonces.DeliveryUnknown) as e:
        _vx().place_order(SESSION_KEY, OWNER, 1, dex.BUY, 1, 100)
    assert e.value.never_sent and oc.pending() == []


def test_a_refusal_record_with_our_nonce_ends_refused_in_the_chains_words(monkeypatch):
    node = Node(monkeypatch)
    node.script = lost_then(lambda b: node.state["events"].append(
        {"kind": "order_refused", "client_nonce": int(b["clientNonce"]), "pair_id": 1, "code": "insufficient_margin",
         "height": 77, "at_ms": 1}), then=(400, {"code": "nonce_used"}))
    out = _vx().place_order(SESSION_KEY, OWNER, 1, dex.BUY, 1, 100)
    o = out["outcome"]
    assert out["status"] == "refused" and o.state == "refused" and o.applied is False
    assert o.text == "Not placed: the account's free margin does not cover the order." and o.next == "Add USDC or make the order smaller."
    assert o.refusal["code"] == "insufficient_margin"


def test_an_agent_refusal_record_names_the_agent_reason(monkeypatch):
    node = Node(monkeypatch)
    node.script = lost_then(lambda b: node.state["events"].extend([
        {"kind": "agent_refused", "client_nonce": int(b["clientNonce"]), "pair_id": 1, "reason": "policy_expired"},
        {"kind": "order_refused", "client_nonce": int(b["clientNonce"]), "pair_id": 1, "code": "agent_refused"}]))
    o = _vx().place_order(SESSION_KEY, OWNER, 1, dex.BUY, 1, 100)["outcome"]
    assert o.text == "Not placed: the agent's policy has expired." and o.refusal["code"] == "policy_expired"


def test_a_refusal_of_another_market_on_the_same_nonce_is_not_ours(monkeypatch):
    node = Node(monkeypatch)
    node.script = lost_then(lambda b: node.state["events"].append(
        {"kind": "order_refused", "client_nonce": int(b["clientNonce"]), "pair_id": 2, "code": "insufficient_margin"}))
    assert _vx().place_order(SESSION_KEY, OWNER, 1, dex.BUY, 1, 100)["outcome"].state == "pending_checking"


def test_nothing_shown_is_pending_after_the_settle_and_still_unknown_after_the_limit(monkeypatch, _outcome_clock):
    node = Node(monkeypatch)
    node.script = lost_then(lambda b: None)
    out = _vx().place_order(SESSION_KEY, OWNER, 1, dex.BUY, 1, 100)
    o, pw = out["outcome"], out["pending"]
    assert o.state == "pending_checking" and o.applied is None and out["delivery_unknown"] is True
    assert o.text == oc.WORDS["actions"]["order"]["pending_checking"]["text"] and o.next.startswith("Do not place it again")
    assert o.resend["allowed"] is False and o.resend["why"] == "a_new_signature_is_a_new_order"
    assert 28 <= pw.elapsed <= 31                                             # waited the 30 s settle inside the call
    assert [e["state"] for e in oc.pending()] == ["pending_checking"]
    o2 = pw.wait()
    assert o2.state == "still_unknown" and o2.text.startswith("Still not known after 2 minutes")
    assert pw.elapsed >= 120 and len(node.posts) == 2                         # never sent again while checking
    with pytest.raises(ValueError):
        pw.resend_same()                                                      # an order is never sent again
    # a later read that shows it moves it to a final
    _list_order(node, json.loads(node.posts[0][1]))
    assert pw.check().state == "applied" and oc.pending() == []


def test_settle_zero_returns_at_once_without_a_read(monkeypatch):
    node = Node(monkeypatch)
    node.script = lost_then(lambda b: _list_order(node, b))
    out = _vx().place_order(SESSION_KEY, OWNER, 1, dex.BUY, 1, 100, settle_s=0)
    assert out["outcome"].state == "pending_checking" and not [u for m, u in node.urls if m == "GET"]
    assert out["pending"].check().state == "applied"


def _v3(monkeypatch, node, chain_ms):
    from vordium import builder as _b
    vx = dex.Vordex(rpc_url=NODE, chain_clock=lambda: chain_ms[0])
    monkeypatch.setattr(vx, "_builder_checked", lambda owner, b: ("0x" + "77" * 20, 500))
    return vx


def test_a_v3_order_past_its_deadline_with_a_full_records_read_is_not_applied(monkeypatch, _outcome_clock):
    import time as _t
    node = Node(monkeypatch)
    node.script = lost_then(lambda b: None)
    chain = [int(_t.time() * 1000)]
    vx = _v3(monkeypatch, node, chain)
    out = vx.place_order(SESSION_KEY, OWNER, 1, dex.BUY, 1, 100, order_type=dex.LIMIT, builder={"address": "0x" + "77" * 20, "fee_cbps": 500})
    assert out["outcome"].state == "pending_checking"
    vu = int(json.loads(node.posts[0][1])["validUntil"])
    chain[0] = (vu + 11) * 1000
    # a snapshot gap inside the records read: absence is not proven
    node.state["events"] = [{"kind": "funding_payment", "height": 50, "at_ms": 1_700_000_000_000}]
    node.state["coverage"] = {"gaps": [{"after_height": 60, "resumed_at": 70}]}
    assert out["pending"].check().state == "pending_checking"
    node.state["coverage"] = {"recording": True, "last_height": 999}       # the records lag behind the head
    assert out["pending"].check().state == "pending_checking"
    node.state["coverage"] = {"recording": False, "last_height": 2000}     # the records are not being written
    assert out["pending"].check().state == "pending_checking"
    node.state["coverage"] = {"recording": True, "last_height": 1000}
    o = out["pending"].check()
    assert o.state == "not_applied" and o.applied is False and o.next == "You can place it again."


def test_a_v1_order_is_never_not_applied(monkeypatch, _outcome_clock):
    node = Node(monkeypatch)
    node.script = lost_then(lambda b: None)
    import time as _t
    chain = [int(_t.time() * 1000)]
    vx = dex.Vordex(rpc_url=NODE, chain_clock=lambda: chain[0])
    out = vx.place_order(SESSION_KEY, OWNER, 1, dex.BUY, 1, 100)
    chain[0] += 10 * 86_400_000                                              # far past any deadline
    assert out["pending"].wait().state == "still_unknown"


def test_the_trades_list_and_explorers_are_never_read(monkeypatch, _outcome_clock):
    node = Node(monkeypatch)
    node.script = lost_then(lambda b: None)
    out = _vx().place_order(SESSION_KEY, OWNER, 1, dex.BUY, 1, 100)
    out["pending"].wait()
    assert len(node.urls) > 20
    _no_explorer(node)


def test_an_explorer_read_fails_the_guard():
    class N:
        urls = [("GET", "https://testnet.vordscan.io/api/tx/1")]
    with pytest.raises(AssertionError):
        _no_explorer(N)


# ── cancel ──────────────────────────────────────────────────────────────────────────────────────────────────────────
def test_a_lost_cancel_sends_the_same_cancel_again_on_demand_and_ends_cancelled(monkeypatch, _outcome_clock):
    node = Node(monkeypatch)
    node.state["orders"] = [{"id": 9, "client_nonce": 1, "pair_id": 1, "side": "buy", "size": "1"}]
    node.script = lambda path, data, i: (_ for _ in ()).throw(requests.ReadTimeout("lost"))
    monkeypatch.setattr(_http, "retry_wait", lambda attempt, ra=None, rand=None: 0.0)
    out = _vx().cancel_order(SESSION_KEY, OWNER, 9)
    pw = out["pending"]
    assert out["outcome"].state == "pending_checking" and out["outcome"].resend["label"] == "Send the same cancel again"
    n = len(node.posts)

    def applies(path, data, i):
        node.state["orders"] = []
        node.state["events"] = [{"kind": "order_closed", "order_id": 9, "status": "cancelled", "height": 31}]
        return 202, {"status": "submitted"}
    node.script = applies
    o = pw.resend_same()
    assert len(node.posts) == n + 1 and len({d for _, d in node.posts}) == 1  # the same bytes, never a new signature
    assert o.state == "applied" and o.text == "Cancelled. The order is off the book." and o.attempts == n + 1


# ── cancel all and batch: never resent ─────────────────────────────────────────────────────────────────────────────
def _mm(node):
    from vordium.node_domain import NodeIdentity
    return mm.MarketMaker(NODE, SESSION_KEY, OWNER, specs=__import__("vordium").units.NO_RULES,
                          identity=lambda: NodeIdentity(101101, GEN))


def test_a_lost_cancel_all_is_not_resent_and_ends_on_the_before_set(monkeypatch, _outcome_clock):
    node = Node(monkeypatch)
    node.state["orders"] = [{"id": 1, "client_nonce": 1, "pair_id": 1, "side": "buy", "size": "1"},
                            {"id": 2, "client_nonce": 2, "pair_id": 1, "side": "buy", "size": "1"}]

    def script(path, data, i):
        node.state["orders"] = []
        node.state["events"] = [{"kind": "order_closed", "order_id": 2, "status": "filled"},
                                {"kind": "order_closed", "order_id": 1, "status": "cancelled"}]
        raise requests.ReadTimeout("lost")
    node.script = script
    s = _mm(node).cancel_all()
    assert len(node.posts) == 1 and s.ok is True and s.refusal is None and s.already_received   # applied, read back
    o = s.outcome
    assert o.state == "applied_other" and o.text == "1 of 2 cancelled; 1 filled first." and s.pending is None
    assert o.resend["allowed"] is False


def test_a_lost_cancel_all_with_orders_still_listed_says_how_many(monkeypatch, _outcome_clock):
    node = Node(monkeypatch)
    node.state["orders"] = [{"id": 1, "client_nonce": 1, "pair_id": 1, "side": "buy", "size": "1"}]
    node.script = lambda path, data, i: (502, {})
    s = _mm(node).cancel_all()
    assert len(node.posts) == 1 and s.outcome.state == "pending_checking"
    o = s.pending.wait()
    assert o.state == "still_unknown" and o.text == "Still not known after 2 minutes. 1 orders are still open."
    with pytest.raises(ValueError):
        s.pending.resend_same()
    assert len(node.posts) == 1


def test_a_lost_batch_is_not_resent_and_reads_each_place(monkeypatch, _outcome_clock):
    node = Node(monkeypatch)
    m = _mm(node)
    a = mm.place(1, "buy", 10 ** 18, 10 ** 10, 1_794_000_000_123)

    def script(path, data, i):
        node.state["orders"] = [{"id": 5, "client_nonce": 1_794_000_000_123, "pair_id": 1, "side": "buy",
                                 "size": str(10 ** 18), "price_8dec": 10 ** 10}]
        raise requests.ReadTimeout("lost")
    node.script = script
    s = m.batch([a])
    assert len(node.posts) == 1 and s.outcome.state == "applied" and s.already_received


# ── revoke and stop (owner key) ────────────────────────────────────────────────────────────────────────────────────
GEN = "2c1c0679fa6ab8358f1d3e8d294a8d1c73ac2e2caf9079f1216abedc3d9fdf4f"


def _ops():
    from vordium.node_domain import NodeIdentity
    from conftest import make_live_network
    return A.AccountOps(OWNER_KEY, network=make_live_network(), rest=NODE, identity=lambda: NodeIdentity(101101, GEN),
                        chain_clock=None)


def test_the_revoke_signature_is_the_published_agent_op_signature():
    ops = _ops()
    v = {"owner": OWNER, "agent": Account.from_key("0x" + "41" * 32).address, "nonce": 1_794_000_000_000}
    mine = A.sign_digest(OWNER_KEY, A.digest(ops.separator("VordCore"), "RevokeAgent", A.REVOKE_AGENT, v))
    assert mine == sign_agent_op(OWNER_KEY, "RevokeAgent", v)


def test_revoke_is_pending_after_a_202_until_the_agent_reads_revoked(monkeypatch, _outcome_clock):
    node = Node(monkeypatch)
    node.state["agents"][AGENT] = {"status": "active", "head_height": 5}
    import time as _t
    mark = int(_t.time() * 1000) + 5_000
    node.state["signers"] = {"live_agents": 1, "app_session": None, "agents": [{"key": AGENT, "last_nonce": mark}]}
    r = _ops().revoke_agent(AGENT, settle_s=0)
    assert r.applied is None and r.outcome.state == "pending_checking" and r.outcome.text.startswith("Pending — checking.")
    body = json.loads(node.posts[-1][1])
    assert body["op"] == "RevokeAgent" and body["nonce"] > mark and len(body["signature"]) == 132
    node.state["agents"][AGENT] = {"status": "revoked", "revoked_height": 44, "revoke_orders_cancelled": 3}
    o = r.pending.check()
    assert o.state == "applied" and o.text == "Agent revoked at block 44. 3 orders cancelled."


def test_a_lost_revoke_resends_the_same_bytes(monkeypatch, _outcome_clock):
    node = Node(monkeypatch)
    node.state["agents"][AGENT] = {"status": "active"}
    monkeypatch.setattr(_http, "retry_wait", lambda attempt, ra=None, rand=None: 0.0)

    def script(path, data, i):
        if path == "/submit" and sum(1 for u, _ in node.posts if u.endswith("/submit")) == 1:
            node.state["agents"][AGENT] = {"status": "revoked", "revoked_height": 8, "revoke_orders_cancelled": 0}
            raise requests.ReadTimeout("lost")
        return 400, {"code": "nonce", "error": "nonce not above"}
    node.script = script
    r = _ops().revoke_agent(AGENT)
    subs = [d for u, d in node.posts if u.endswith("/submit")]
    assert len(subs) >= 2 and len(set(subs)) == 1 and r.applied is True and r.outcome.state == "applied"


def test_a_refused_revoke_is_refused_with_the_networks_words(monkeypatch):
    node = Node(monkeypatch)
    node.state["agents"][AGENT] = {"status": "active"}
    node.script = lambda path, data, i: (403, {"code": "bad_signature", "meaning": "The signature does not match the owner."})
    r = _ops().revoke_agent(AGENT)
    assert r.applied is False and r.outcome.text == "Not revoked: the signature does not match the owner."


def test_an_already_revoked_agent_is_not_signed_for(monkeypatch):
    node = Node(monkeypatch)
    node.state["agents"][AGENT] = {"status": "revoked", "revoked_height": 3, "revoke_orders_cancelled": 0}
    r = _ops().revoke_agent(AGENT)
    assert r.applied is True and node.posts == []


def _stop_script(node, applies=True, lose=True):
    def script(path, data, i):
        if data == b"{}":
            return 400, {"code": "invalid_body", "error": "missing owner"}
        if applies:
            node.state["session"] = None
            node.state["signers"] = {"live_agents": 0, "app_session": None, "head_height": 900}
        if lose and sum(1 for u, d in node.posts if d != b"{}") == 1:
            raise requests.ReadTimeout("lost")
        return 202, {"status": "submitted"}
    return script


def test_stop_all_signs_once_and_ends_applied_from_the_reads(monkeypatch, _outcome_clock):
    node = Node(monkeypatch)
    node.state["session"] = {"session_key": "0x" + "55" * 20, "nonce": 1_794_000_000_000}
    node.state["signers"] = {"live_agents": 2, "app_session": {"key": "x"}, "head_height": 800}
    monkeypatch.setattr(_http, "retry_wait", lambda attempt, ra=None, rand=None: 0.0)
    node.script = _stop_script(node)
    r = _ops().stop_all()
    sends = [d for _, d in node.posts if d != b"{}"]
    assert len(sends) == 2 and len(set(sends)) == 1
    b = json.loads(sends[0])
    assert set(b) == {"owner", "nonce", "validUntil", "signature"} and b["nonce"] > 1_794_000_000_000
    assert r.applied is True and r.outcome.state == "applied"
    assert r.outcome.text == "Stopped on the network: no trading key, no live agent, no open order."
    node.state["orders"] = [{"id": 1}]
    assert r.outcome.final and _ops().stop_all().outcome.state == "applied_other"


def test_stop_all_past_its_deadline_with_a_live_key_is_not_applied(monkeypatch, _outcome_clock):
    node = Node(monkeypatch)
    node.state["session"] = {"session_key": "0x" + "55" * 20, "session_nonce": 7}
    node.state["signers"] = {"live_agents": 1, "app_session": None}
    node.script = _stop_script(node, applies=False, lose=False)
    ops = _ops()
    r = ops.stop_all(settle_s=0)
    assert r.outcome.state == "pending_checking" and r.outcome.resend["label"] == "Send the same stop again"
    ops._chain = lambda: (json.loads([d for _, d in node.posts if d != b"{}"][0])["validUntil"] + 11) * 1000
    # the judge holds the client's clock at send time: a new pending reads the deadline through the journal path
    sent = json.loads([d for _, d in node.posts if d != b"{}"][0])
    judge = lambda n: oc.PendingWrite("stop", lambda: oc.judge_stop(oc.NodeReads(NODE), OWNER, sent["validUntil"],
                                                                     ops._chain, n)).check()
    o = judge(sent["nonce"])
    assert o.state == "not_applied" and o.next == "Press Stop everything now again."
    node.state["session"]["session_nonce"] = sent["nonce"]              # a later key: the stop may have applied first
    assert judge(sent["nonce"]).state == "pending_checking"
    node.state["session"]["session_nonce"] = 7
    r2 = r.pending.wait()
    assert r2.state == "still_unknown" and "Your trading key is still on; 1 agent is still live" in r2.text


def test_stop_all_is_not_signed_where_the_network_does_not_take_it(monkeypatch):
    node = Node(monkeypatch, lambda path, data, i: (404, {"error": "not found"}))
    r = _ops().stop_all()
    assert r.applied is False and r.outcome is None and len(node.posts) == 1


# ── the journal ─────────────────────────────────────────────────────────────────────────────────────────────────────
def test_the_journal_is_0600_next_to_the_nonce_marks_and_survives_a_restart(monkeypatch, _outcome_clock):
    node = Node(monkeypatch)
    node.script = lost_then(lambda b: None)
    _vx().place_order(SESSION_KEY, OWNER, 1, dex.BUY, 1, 100, settle_s=0)
    p = nonces.state_dir() / oc.JOURNAL_NAME
    assert p.exists() and stat.S_IMODE(os.stat(p).st_mode) == 0o600
    rows = oc.pending()
    assert len(rows) == 1 and rows[0]["action"] == "order" and rows[0]["rest"] == NODE
    _list_order(node, json.loads(node.posts[0][1]))
    out = oc.pending(check=True)                                                # a restarted process checks it
    assert [o.state for o in out] == ["applied"] and oc.pending() == []


# ── review cases ────────────────────────────────────────────────────────────────────────────────────────────────────
def test_a_nonce_refusal_of_a_later_copy_is_never_read_as_refused(monkeypatch):
    node = Node(monkeypatch)
    node.script = lost_then(lambda b: node.state["events"].append(
        {"kind": "order_refused", "client_nonce": int(b["clientNonce"]), "pair_id": 1, "code": "nonce_used"}))
    assert _vx().place_order(SESSION_KEY, OWNER, 1, dex.BUY, 1, 100)["outcome"].state == "pending_checking"


def test_another_signers_refusal_on_the_same_nonce_is_not_ours(monkeypatch):
    node = Node(monkeypatch)
    node.script = lost_then(lambda b: node.state["events"].append(
        {"kind": "agent_refused", "client_nonce": int(b["clientNonce"]), "pair_id": 1, "reason": "policy_expired",
         "agent": "0x" + "99" * 20}))
    assert _vx().place_order(SESSION_KEY, OWNER, 1, dex.BUY, 1, 100)["outcome"].state == "pending_checking"


def test_a_refusal_with_no_market_is_not_ours(monkeypatch):
    node = Node(monkeypatch)
    node.script = lost_then(lambda b: node.state["events"].append(
        {"kind": "order_refused", "client_nonce": int(b["clientNonce"]), "code": "insufficient_margin"}))
    assert _vx().place_order(SESSION_KEY, OWNER, 1, dex.BUY, 1, 100)["outcome"].state == "pending_checking"


def test_a_cancel_all_with_nothing_listed_before_is_never_called_applied(monkeypatch, _outcome_clock):
    node = Node(monkeypatch, lambda path, data, i: (_ for _ in ()).throw(requests.ReadTimeout("lost")))
    s = _mm(node).cancel_all()
    assert s.outcome.state == "pending_checking" and s.pending.wait().state == "still_unknown"


def test_a_cancel_all_whose_orders_left_with_no_record_is_not_applied_yet(monkeypatch, _outcome_clock):
    node = Node(monkeypatch)
    node.state["orders"] = [{"id": 1, "client_nonce": 1, "pair_id": 1, "side": "buy", "size": "1"}]

    def script(path, data, i):
        node.state["orders"] = []
        raise requests.ReadTimeout("lost")
    node.script = script
    s = _mm(node).cancel_all()
    assert s.outcome.state == "pending_checking"
    node.state["events"] = [{"kind": "order_closed", "order_id": 1, "status": "cancelled"}]
    o = s.pending.check()
    assert o.state == "applied" and o.text == "All 1 orders cancelled."


def test_a_batch_cancel_by_client_nonce_is_judged(monkeypatch, _outcome_clock):
    node = Node(monkeypatch)
    node.state["orders"] = [{"id": 3, "client_nonce": 555, "pair_id": 1, "side": "buy", "size": "1"}]
    node.script = lambda path, data, i: (_ for _ in ()).throw(requests.ReadTimeout("lost"))
    s = _mm(node).batch([mm.cancel_by_client_nonce(555)])
    assert len(node.posts) == 1 and s.outcome.state == "pending_checking"
    assert s.refusal.message == s.outcome.text
    node.state["orders"] = []
    assert s.pending.check().state == "pending_checking"              # gone, no closing record yet
    node.state["events"] = [{"kind": "order_closed", "client_nonce": 555, "order_id": 3, "status": "cancelled"}]
    assert s.pending.check().state == "applied"


def test_stop_all_is_still_sent_when_the_route_probe_gets_no_answer(monkeypatch, _outcome_clock):
    node = Node(monkeypatch)

    def script(path, data, i):
        if data == b"{}":
            raise requests.ConnectionError("blip")
        return 202, {"status": "submitted"}
    node.script = script
    r = _ops().stop_all(settle_s=0)
    assert r.outcome is not None and len([d for _, d in node.posts if d != b"{}"]) == 1


def test_after_a_restart_the_same_bytes_are_not_offered(monkeypatch, _outcome_clock):
    node = Node(monkeypatch)
    node.state["orders"] = [{"id": 9, "client_nonce": 1, "pair_id": 1, "side": "buy", "size": "1"}]
    node.script = lambda path, data, i: (_ for _ in ()).throw(requests.ReadTimeout("lost"))
    out = _vx().cancel_order(SESSION_KEY, OWNER, 9, settle_s=0)
    assert out["outcome"].resend["allowed"] is True
    [o] = oc.pending(check=True)
    assert o.state == "pending_checking" and o.resend == {"allowed": False, "same_bytes": False, "label": None,
                                                          "why": "bytes_not_kept"}


def test_a_send_that_raises_leaves_no_journal_entry(monkeypatch):
    Node(monkeypatch, lambda path, data, i: (_ for _ in ()).throw(RuntimeError("boom")))
    with pytest.raises(RuntimeError):
        _vx().place_order(SESSION_KEY, OWNER, 1, dex.BUY, 1, 100)
    assert oc.pending() == []


def test_a_snapshot_gap_after_the_send_keeps_a_deadline_order_unknown(monkeypatch, _outcome_clock):
    import time as _t
    node = Node(monkeypatch)
    node.script = lost_then(lambda b: None)
    chain = [int(_t.time() * 1000)]
    out = _v3(monkeypatch, node, chain).place_order(SESSION_KEY, OWNER, 1, dex.BUY, 1, 100, order_type=dex.LIMIT,
                                                    builder={"address": "0x" + "77" * 20, "fee_cbps": 500})
    chain[0] = (int(json.loads(node.posts[0][1])["validUntil"]) + 11) * 1000
    now = int(_t.time() * 1000)
    # a restore after the send lost the order's records: what is left starts above the gap
    node.state["events"] = [{"kind": "funding_payment", "height": 50, "at_ms": 1_700_000_000_000},
                            {"kind": "funding_payment", "height": 900, "at_ms": now}]
    node.state["coverage"] = {"recording": True, "last_height": 1000, "gaps": [{"after_height": 60, "resumed_at": 800}]}
    assert out["pending"].check().state == "pending_checking"
    node.state["events"] = [{"kind": "funding_payment", "height": 900, "at_ms": now}]   # nothing older than the send
    node.state["coverage"] = {"recording": True, "last_height": 1000}
    assert out["pending"].check().state == "pending_checking"


def test_an_unanswered_signer_read_is_asked_again(monkeypatch, _outcome_clock):
    node = Node(monkeypatch)
    agent_key = "0x" + "41" * 32
    agent = Account.from_key(agent_key).address
    node.script = lost_then(lambda b: _list_order(node, b))
    node.state["orders"] = []
    real_get = node.get
    calls = {"n": 0}

    def get(url):
        if "/agents/" in url:
            calls["n"] += 1
            if calls["n"] == 1:
                return Resp(503, None)
            return Resp(200, {"found": True, "agent": agent.lower()})
        return real_get(url)
    node.get = get
    out = _vx().place_order(agent_key, OWNER, 1, dex.BUY, 1, 100, settle_s=0)
    o = out["pending"].check()
    assert o.state == "pending_checking" and calls["n"] == 1             # not known yet: nothing judged
    node.state["orders"][0]["agent"] = agent.lower()
    assert out["pending"].check().state == "applied" and calls["n"] == 2


def test_a_404_signer_read_is_not_an_answer_and_an_odd_gap_blocks():
    calls = []
    r = oc.NodeReads(NODE, get=lambda p: (calls.append(p), (404, {"error": "not found"}))[1])
    who = oc.SignerOf(r, OWNER, "0x" + "41" * 20)
    assert who() == (False, None) and who() == (False, None) and len(calls) == 2
    recs = [{"height": 50, "at_ms": 1_700_000_000_000}]
    assert oc._scan_anchor(recs, {}, 1_800_000_000_000) == 50
    assert oc._scan_anchor(recs, {"gaps": [{"reason": "restore"}]}, 1_800_000_000_000) is None
    assert oc._scan_anchor([{"height": 50, "at_ms": 1_700_000_000}], {}, 1_800_000_000_000) is None   # seconds
