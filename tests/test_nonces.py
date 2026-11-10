"""The nonce allocator and the same-body resend: duplicate submit, clock drift, delayed delivery, concurrency and
persistence, against fake transports (no network)."""
import multiprocessing as mp
import os
import stat
import threading
import time

import pytest
import requests
from eth_account import Account

from vordium import dex, mm, nonces
from vordium import _http as _http_mod
from vordium import schedule_cancel as sc
from vordium.nonces import ClockOutOfWindow, DAY_MS, NonceAllocator

OWNER = "0x" + "ab" * 20
T0 = 1_794_000_000.0                       # a fixed "now" (seconds) for the injected clocks


class FakeChain:
    """Like the network: an order (owner, clientNonce) applies once and a second copy is answered with the nonce code;
    a cancel-all is NOT deduplicated (the same signed body applies every time it arrives)."""

    def __init__(self):
        self.effects, self.bodies, self.lock = [], [], threading.Lock()

    def deliver(self, body, dedup=True):
        with self.lock:
            self.bodies.append(dict(body))
            key = (body["owner"].lower(), body.get("clientNonce", body.get("nonce")))
            if dedup and key in {(e["owner"].lower(), e.get("clientNonce", e.get("nonce"))) for e in self.effects}:
                return 400, {"code": "nonce", "status": "refused",
                             "error": "The client nonce is outside the window (a millisecond time within 2 days before "
                                      "and 1 day after now) or already used."}
            self.effects.append(dict(body))
            return 202, {"status": "submitted", "intaken": True}

    def listed(self, owner, n):
        """GET /orders as the network shows it: the applied orders of ``owner`` with their signed fields."""
        return [{"id": i, "client_nonce": e["clientNonce"], "pair_id": e["pairId"],
                 "side": "buy" if e["side"] == "buy" else "sell", "size": e["size_18dec"]}
                for i, e in enumerate(self.effects) if "clientNonce" in e and e["owner"].lower() == owner.lower()]


class Resp:
    def __init__(self, code, j):
        self.status_code, self._j, self.content, self.headers = code, j, b"{}", {}

    def json(self):
        return self._j


def _patch_post(monkeypatch, script):
    """``script(body, attempt)`` -> (status, json) or raises; every POST body is recorded."""
    calls = []

    def post(url, json=None, timeout=None, **k):
        calls.append(json)
        out = script(json, len(calls))
        return Resp(*out)
    monkeypatch.setattr(_http_mod, "post", post)
    return calls


def _vx(monkeypatch, chain=None, **kw):
    vx = dex.Vordex(rpc_url="http://rpc.invalid", **kw)
    if chain is not None:
        monkeypatch.setattr(vx, "_get", lambda path: chain.listed(OWNER, 0) if path.startswith("/orders/") else {"events": []})
    return vx


def _place(**kw):
    session = kw.pop("session", None) or Account.create()
    return dex.Vordex(rpc_url="http://rpc.invalid", **{k: kw.pop(k) for k in list(kw) if k in ("chain_clock",)}).place_order(
        session.key.hex(), OWNER, 1, dex.BUY, 1, 100, **kw)


# ── duplicate submit ────────────────────────────────────────────────────────────────────────────────────────────────
def test_duplicate_submit_of_the_same_signed_body_is_one_effect(monkeypatch):
    chain = FakeChain()
    calls = _patch_post(monkeypatch, lambda body, i: chain.deliver(body))
    vx = _vx(monkeypatch, chain)
    first = vx.place_order(Account.create().key.hex(), OWNER, 1, dex.BUY, 1, 100)
    again = nonces.send_same(lambda: vx._post_once("/order/place", calls[0]))      # the caller sends it again
    assert first["status"] == "submitted" and first["attempts"] == 1 and "already_received" not in first
    assert len(chain.effects) == 1 and len(chain.bodies) == 2 and chain.bodies[0] == chain.bodies[1]
    # a copy sent by an EARLIER call is not this call's: the answer is the chain's refusal, never "received"
    assert again.needs_read_back is False and again.status_code == 400


def test_a_used_nonce_on_a_first_copy_is_a_refusal_not_a_success(monkeypatch):
    _patch_post(monkeypatch, lambda body, i: (400, {"code": "nonce", "error": "... or already used."}))
    out = _place(client_nonce=int(time.time() * 1000))
    assert out["status_code"] == 400 and out["code"] == "nonce" and "already_received" not in out and out["attempts"] == 1


def test_a_timed_out_order_is_resent_and_counts_as_received_only_after_a_matching_read_back(monkeypatch):
    chain = FakeChain()

    def script(body, i):
        code, j = chain.deliver(body)              # every copy reaches the chain ...
        if i == 1:
            raise requests.Timeout("read timed out")   # ... but the first answer is lost
        return code, j
    calls = _patch_post(monkeypatch, script)
    out = _vx(monkeypatch, chain).place_order(Account.create().key.hex(), OWNER, 1, dex.BUY, 1, 100)
    assert len(calls) == 2 and calls[0] is calls[1] and len(chain.effects) == 1
    assert out["status"] == "received" and out["already_received"] is True and out["status_code"] is None
    assert out["attempts"] == 2 and out["found"]["client_nonce"] == out["clientNonce"]


# reviewer probe 1: the read-back lags (the order is not listed yet) -> never a refusal body, never a 4xx at the top
def test_a_resend_answered_nonce_with_no_read_back_is_unknown_never_refused(monkeypatch):
    chain = FakeChain()

    def script(body, i):
        code, j = chain.deliver(body)
        if i == 1:
            raise requests.Timeout("lost")
        return code, j
    _patch_post(monkeypatch, script)
    vx = dex.Vordex(rpc_url="http://rpc.invalid", chain_clock=None)
    monkeypatch.setattr(vx, "order_by_client_nonce", lambda o, c, signed=None: None)
    out = vx.place_order(Account.create().key.hex(), OWNER, 1, dex.BUY, 1, 100)
    assert out["status"] == "unknown" and out["delivery_unknown"] is True and out["already_received"] is False
    assert out["status_code"] is None and out.get("code") is None and out["status"] != "refused"


def test_another_writers_order_on_the_same_nonce_is_not_ours(monkeypatch):
    """The nonce code after a resend, and the account lists an order with that client nonce but another size: unknown."""
    chain = FakeChain()

    def script(body, i):
        if i == 1:
            raise requests.Timeout("lost")         # never arrived
        chain.effects.append({**body, "size_18dec": str(int(body["size_18dec"]) * 7)})   # another signer, same ms
        return chain.deliver(body)
    _patch_post(monkeypatch, script)
    out = _vx(monkeypatch, chain).place_order(Account.create().key.hex(), OWNER, 1, dex.BUY, 1, 100)
    assert out["status"] == "unknown" and out["already_received"] is False


def test_signed_fields_are_compared_on_read_back():
    signed = {"pair_id": 1, "side": 0, "size_18dec": 10 ** 18, "price_8dec": 100 * 10 ** 8}
    assert dex.matches_signed({"pair_id": 1, "side": "Buy", "size": str(10 ** 18), "price_8dec": 100 * 10 ** 8}, signed)
    assert not dex.matches_signed({"pair_id": 1, "side": "Sell", "size": str(10 ** 18)}, signed)
    assert not dex.matches_signed({"pair_id": 2, "side": "buy", "size": str(10 ** 18)}, signed)
    assert not dex.matches_signed({"pair_id": 1, "side": "buy", "price_8dec": 99 * 10 ** 8}, signed)
    assert not dex.matches_signed({"pair_id": 1, "side": "buy"}, signed)          # neither size nor price shown


# ── delayed delivery ────────────────────────────────────────────────────────────────────────────────────────────────
def test_delayed_first_copy_arriving_after_the_retry_is_still_one_effect(monkeypatch):
    chain, late = FakeChain(), []

    def script(body, i):
        if i == 1:
            late.append(dict(body))                # held in the network, past the client's time limit
            raise requests.Timeout("read timed out")
        return chain.deliver(body)                 # the retry arrives first
    calls = _patch_post(monkeypatch, script)
    out = _place()
    late_answer = chain.deliver(late[0])           # then the delayed copy arrives
    assert out["status"] == "submitted" and out["attempts"] == 2 and "already_received" not in out
    assert late[0] == calls[1] and late_answer[0] == 400
    assert len(chain.effects) == 1


def test_no_answer_at_all_raises_delivery_unknown_unless_the_order_is_listed(monkeypatch):
    def script(body, i):
        raise requests.ConnectionError("Connection aborted.")
    calls = _patch_post(monkeypatch, script)
    vx = dex.Vordex(rpc_url="http://rpc.invalid")
    monkeypatch.setattr(vx, "order_by_client_nonce", lambda owner, n, signed=None: None)
    with pytest.raises(nonces.DeliveryUnknown) as e:
        vx.place_order(Account.create().key.hex(), OWNER, 1, dex.BUY, 1, 100, retries=3)
    assert len(calls) == 3 and all(c is calls[0] for c in calls) and e.value.nonce == calls[0]["clientNonce"]
    monkeypatch.setattr(vx, "order_by_client_nonce", lambda owner, n, signed=None: {"client_nonce": n, "source": "events"})
    out = vx.place_order(Account.create().key.hex(), OWNER, 1, dex.BUY, 1, 100)
    assert out["already_received"] is True and out["status"] == "received" and out["found"]["source"] == "events"


def test_a_busy_gateway_is_waited_out_with_the_same_body(monkeypatch):
    chain = FakeChain()
    calls = _patch_post(monkeypatch, lambda body, i: (503, {}) if i < 3 else chain.deliver(body))
    monkeypatch.setattr(_http_mod, "retry_wait", lambda attempt, ra=None, rand=None: 0.0)
    out = _place()
    assert out["status"] == "submitted" and out["attempts"] == 3 and len({id(c) for c in calls}) == 1


# ── writes the network does not deduplicate ─────────────────────────────────────────────────────────────────────────
def _mm(post):
    return mm.MarketMaker("https://node.invalid", Account.create().key.hex(), OWNER, post=post,
                          identity=lambda: _live_identity())


def test_a_cancel_all_whose_answer_is_lost_is_not_sent_again_and_reads_as_unknown():
    chain, sent = FakeChain(), []

    def post(path, body):
        sent.append(body)
        code, j = chain.deliver(body, dedup=False)          # the network applies every copy of a cancel-all
        if len(sent) == 1:
            raise requests.Timeout("lost")
        return code, j, None
    r = _mm(post).cancel_all(pair_id=0)
    assert r.ok is False and r.unknown is True and r.refusal.code == "delivery_unknown"
    assert len(sent) == 1 and len(chain.effects) == 1        # sent once: a second copy would apply twice


def test_a_gateway_error_on_a_cancel_all_is_unknown_and_not_resent():
    sent = []
    r = _mm(lambda path, body: (sent.append(body), (502, {}, None))[1]).cancel_all(pair_id=0)
    assert r.unknown is True and r.ok is False and len(sent) == 1


def test_a_copy_that_never_left_this_machine_is_sent_again(monkeypatch):
    monkeypatch.setattr(_http_mod, "retry_wait", lambda attempt, ra=None, rand=None: 0.0)
    chain, sent = FakeChain(), []

    def post(path, body):
        sent.append(body)
        if len(sent) == 1:
            raise requests.ConnectionError("Failed to establish a new connection: [Errno 111] Connection refused")
        return (*chain.deliver(body, dedup=False), None)
    r = _mm(post).cancel_all(pair_id=0)
    assert r.ok and r.attempts == 2 and len(chain.effects) == 1 and sent[0] is sent[1]


# reviewer probe 2: a window refusal whose first answer was lost is never "ok"
def test_market_maker_never_reads_a_nonce_answer_as_success():
    n = [0]

    def post(path, body):
        n[0] += 1
        if n[0] == 1:
            raise requests.Timeout("read timed out")
        return 400, {"code": "nonce", "status": "refused", "error": "... outside the window ... or already used."}, None
    r = _mm(post).cancel_all(pair_id=0)
    assert r.ok is False and r.already_received is False and n[0] == 1 and r.unknown is True


def test_operator_take_profit_is_not_resent_after_a_lost_answer(monkeypatch):
    from vordium import operator as opm
    calls = _patch_post(monkeypatch, lambda body, i: (_ for _ in ()).throw(requests.Timeout("lost")))
    s = Account.create()
    op = opm.Operator(owner=OWNER, signer=opm.SessionSigner(private_key=s.key.hex()), submit_url="http://rpc.invalid")
    out = op.set_tpsl(1, 5, 200 * 10 ** 8, 0)
    assert out["status"] == "unknown" and out["delivery_unknown"] is True and len(calls) == 1


def _live_identity():
    from tests.conftest import make_live_network
    from vordium.node_domain import NodeIdentity
    n = make_live_network()
    return NodeIdentity(n.chain_id, n.genesis_sha256)


def test_the_networks_nonce_answers_are_recognised():
    # as answered on the test network: an order client nonce, an agent op, the dead-man switch
    assert nonces.nonce_used_answer(400, {"code": "nonce", "error": "... or already used."})
    assert nonces.nonce_used_answer(403, {"code": "nonce_used", "message": "the nonce must be greater than 1"})
    assert nonces.nonce_used_answer(400, {"code": "refused", "error": "nonce not above the account's last ScheduleCancel nonce"})
    assert nonces.nonce_used_answer(409, {})
    assert not nonces.nonce_used_answer(400, {"code": "insufficient_margin", "error": "The account's free USDC ..."})
    assert not nonces.nonce_used_answer(202, {"status": "submitted"})


# ── clock drift ─────────────────────────────────────────────────────────────────────────────────────────────────────
def test_the_allocator_keeps_rising_when_the_clock_goes_back_an_hour_or_forward_five_minutes(tmp_path):
    clock = {"t": T0}
    a = NonceAllocator(OWNER, state=tmp_path, clock=lambda: clock["t"])
    got = [a() for _ in range(5)]
    clock["t"] = T0 - 3600                         # set back one hour
    got += [a() for _ in range(5)]
    clock["t"] = T0 + 300                          # five minutes ahead
    got += [a() for _ in range(5)]
    clock["t"] = T0                                # set right again
    got += [a() for _ in range(5)]
    assert got == sorted(got) and len(set(got)) == len(got)
    assert got[5] == got[4] + 1 and got[10] == int((T0 + 300) * 1000) and got[15] == got[14] + 1


def test_a_nonce_outside_the_window_is_refused_before_anything_is_handed_out(tmp_path):
    now = int(T0 * 1000)
    a = NonceAllocator(OWNER, state=tmp_path, clock=lambda: T0)
    assert a.next_at_least(0, chain_ms=now + 3_600_000) == now          # clock an hour behind the chain: fine
    with pytest.raises(ClockOutOfWindow) as e:
        a.next_at_least(0, chain_ms=now - 2 * DAY_MS)                   # clock 2 days ahead of the chain
    assert "ahead of the network's block time" in str(e.value) and "Nothing was signed" in str(e.value)
    with pytest.raises(ClockOutOfWindow) as e:
        a.next_at_least(0, chain_ms=now + 3 * DAY_MS)                   # clock 3 days behind the chain
    assert "behind the network's block time" in str(e.value)
    assert a.last() == now                                              # a refused nonce never moved the mark


def test_a_mark_left_far_ahead_does_not_lock_the_order_space_out(tmp_path):
    a = NonceAllocator(OWNER, state=tmp_path, clock=lambda: T0)
    a.seen(int(T0 * 1000) + 2 * DAY_MS)
    with pytest.warns(nonces.NonceStateWarning):
        n = a()
    assert n == int(T0 * 1000) and a() == n + 1 and a.last() == n + 1        # rises again from the clock


def test_a_mark_left_far_ahead_in_the_account_space_names_its_file(tmp_path):
    a = NonceAllocator(OWNER, "account", state=tmp_path, clock=lambda: T0)
    a.seen(int(T0 * 1000) + 2 * DAY_MS)
    with pytest.raises(ClockOutOfWindow) as e:
        a()
    assert str(tmp_path / f"{OWNER}.account") in str(e.value) and "delete the file" in str(e.value)


def test_the_chain_clock_reads_outside_its_lock_and_serves_the_last_reading_meanwhile():
    gate, started = threading.Event(), threading.Event()
    calls = []

    def slow_block():
        calls.append(1)
        started.set()
        gate.wait(5)
        return {"number": hex(100), "timestamp": hex(int(T0) - 2)}
    c = nonces.ChainClock("x", None, rpc=slow_block, clock=lambda: T0)
    t = threading.Thread(target=c)
    t.start()
    assert started.wait(5)
    t0 = time.monotonic()
    assert c() is None and time.monotonic() - t0 < 0.5          # served at once (no reading yet), not blocked
    gate.set()
    t.join(5)
    assert len(calls) == 1 and c() == int(T0 * 1000) - 2000 + 500


def test_an_order_is_not_signed_when_the_clock_is_too_far_from_block_time(monkeypatch):
    calls = _patch_post(monkeypatch, lambda body, i: (202, {"status": "submitted"}))
    real = int(time.time() * 1000)
    with pytest.raises(ClockOutOfWindow):
        _place(chain_clock=lambda: real - 3 * DAY_MS)       # this computer 3 days ahead of the chain
    with pytest.raises(ClockOutOfWindow):
        _place(chain_clock=lambda: real + 3 * DAY_MS)       # 3 days behind
    assert calls == []
    out = _place(chain_clock=lambda: real - 3_600_000)      # an hour ahead: inside the window
    assert out["status"] == "submitted"


def test_the_chain_clock_refuses_a_jsonrpc_that_serves_another_head():
    block = {"number": hex(6495), "timestamp": hex(1_794_255_333)}
    stale = nonces.ChainClock("x", "y", rpc=lambda: block, status=lambda: {"chain_head": 201_783_495}, clock=lambda: T0)
    assert stale() is None
    good = nonces.ChainClock("x", "y", rpc=lambda: {"number": hex(406_207_591), "timestamp": hex(int(T0) - 2)},
                             status=lambda: {"chain_head": 406_207_600}, clock=lambda: T0)
    assert good() == int(T0 * 1000) - 2000 + 500


# ── concurrency ─────────────────────────────────────────────────────────────────────────────────────────────────────
def test_threads_allocate_unique_strictly_rising_nonces(tmp_path):
    a = NonceAllocator(OWNER, state=tmp_path, clock=lambda: T0)     # a clock that stands still
    out = {}

    def work(i):
        out[i] = [a() for _ in range(200)]
    ts = [threading.Thread(target=work, args=(i,)) for i in range(8)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    every = [n for v in out.values() for n in v]
    assert len(set(every)) == 1600 and all(v == sorted(v) for v in out.values())
    assert a.last() == max(every) == int(T0 * 1000) + 1599


def _child(state, q):
    a = NonceAllocator(OWNER, state=state)
    q.put([a() for _ in range(150)])


def test_processes_allocate_unique_strictly_rising_nonces(tmp_path):
    ctx = mp.get_context("spawn")
    q = ctx.Queue()
    ps = [ctx.Process(target=_child, args=(str(tmp_path), q)) for _ in range(4)]
    [p.start() for p in ps]
    got = [q.get(timeout=60) for _ in ps]
    [p.join(timeout=60) for p in ps]
    every = [n for v in got for n in v]
    assert len(every) == 600 and len(set(every)) == 600 and all(v == sorted(v) for v in got)
    assert NonceAllocator(OWNER, state=tmp_path).last() == max(every)


# ── persistence ─────────────────────────────────────────────────────────────────────────────────────────────────────
def test_the_mark_survives_a_restart_even_with_the_clock_set_back(tmp_path):
    a = NonceAllocator(OWNER, state=tmp_path, clock=lambda: T0)
    last = [a() for _ in range(10)][-1]
    b = NonceAllocator(OWNER, state=tmp_path, clock=lambda: T0 - 3600)     # a new process, clock an hour back
    assert b() == last + 1
    f = tmp_path / f"{OWNER}.orders"
    assert stat.S_IMODE(os.stat(f).st_mode) == 0o600 and stat.S_IMODE(os.stat(tmp_path).st_mode) == 0o700
    assert f.read_text().strip() == str(last + 1)


def test_spaces_and_accounts_keep_their_own_marks(tmp_path):
    o = NonceAllocator(OWNER, "orders", state=tmp_path, clock=lambda: T0)
    s = NonceAllocator(OWNER, "account", state=tmp_path, clock=lambda: T0)
    other = NonceAllocator("0x" + "cd" * 20, "orders", state=tmp_path, clock=lambda: T0)
    assert o() == s() == other() == int(T0 * 1000)
    with pytest.raises(ValueError):
        NonceAllocator("not-an-address", state=tmp_path)


def test_the_shared_clock_is_the_persisted_allocator_and_the_dead_man_switch_uses_it(monkeypatch, tmp_path):
    c = mm.nonce_clock(OWNER)
    assert isinstance(c, NonceAllocator) and c.persistent and c is mm.nonce_clock(OWNER.upper().replace("0X", "0x"))
    held = int(time.time() * 1000) + 60_000
    c.seen(held)
    st = sc.read_state({"account": OWNER, "cancel_at_ms": None, "set_at_ms": None, "nonce": None, "fired": False,
                        "orders_refused": False, "active": True,
                        "limits": {"min_lead_ms": 5000, "max_horizon_ms": 600000, "min_refresh_ms": 0}}, OWNER)
    sent = []
    ka = sc.KeepAlive("offline", Account.create().key.hex(), OWNER, lead_ms=30_000, sleep=lambda s: None,
                      post=lambda u, b, t: (sent.append(b), (202, {"status": "submitted"}))[1], read=lambda: st,
                      identity=_live_identity)
    assert ka.refresh().ok and sent[-1]["nonce"] == held + 1


def test_an_unwritable_state_directory_still_rises_in_process(tmp_path):
    blocker = tmp_path / "file"
    blocker.write_text("x")
    with pytest.warns(nonces.NonceStateWarning):
        a = NonceAllocator(OWNER, state=blocker / "sub", clock=lambda: T0)
    assert not a.persistent and a() < a() < a()


# ── one optional live check (testnet, throwaway key, nothing to clean up) ───────────────────────────────────────────
@pytest.mark.skipif(os.environ.get("VORDIUM_LIVE_TESTNET") != "1", reason="set VORDIUM_LIVE_TESTNET=1 for the live check")
def test_live_testnet_same_body_twice_applies_once(monkeypatch):
    """A throwaway, unfunded key clears its own dead-man switch twice with ONE signed body: the network applies it
    once and answers the second copy with its nonce refusal."""
    from vordium import network
    from vordium.node_domain import NodeDomain
    import json as _json
    net = network.resolve_network(network="testnet")
    rest = network.api_base(net)
    k = Account.create()
    from vordium.mm import read_identity
    dom = NodeDomain(rest, net, None, lambda: read_identity(requests.get(rest + "/status", timeout=15).json()))
    n = mm.nonce_clock(k.address)()
    body = sc.schedule_cancel_body(k.address, 0, n, sc.sign_schedule_cancel(k.key.hex(), k.address, 0, n,
                                                                            domain_separator=dom.separator()))

    def once():
        r = requests.post(rest + "/schedule-cancel", data=_json.dumps(body), headers={"content-type": "application/json"},
                          timeout=15)
        return r.status_code, r.json(), r.headers.get("Retry-After")
    first = nonces.send_same(once)
    second = nonces.send_same(once)                  # the same signed body, sent again by a new call
    assert first.status_code == 202 and not first.needs_read_back
    assert nonces.nonce_used_answer(second.status_code, second.answer) and second.needs_read_back is False
    assert sc.get_state(rest, k.address).nonce == n  # applied once: the committed state holds this nonce


# ── round 3: an answer after a copy that may have arrived is never a plain refusal ──────────────────────────────────
def _seq(*steps):
    steps = list(steps)

    def send():
        x = steps.pop(0)
        if isinstance(x, BaseException):
            raise x
        return x
    return send


def test_a_final_gateway_error_after_a_lost_answer_needs_a_read_back():          # reviewer probe 1
    s = nonces.send_same(_seq(requests.ReadTimeout("read timed out"), (504, {"error": "gateway"}, None),
                              (504, {"error": "gateway"}, None)), attempts=3, sleep=lambda t: None)
    assert s.needs_read_back is True and s.attempts == 3


def test_a_refusal_after_a_lost_answer_needs_a_read_back():                       # reviewer probe 4
    s = nonces.send_same(_seq(requests.ReadTimeout("read timed out"),
                              (400, {"code": "insufficient_margin", "error": "insufficient margin"}, None)),
                         attempts=3, sleep=lambda t: None)
    assert s.needs_read_back is True and s.status_code == 400


def test_a_gateway_error_on_a_write_without_dedup_is_always_unknown():           # reviewer probe 2
    with pytest.raises(nonces.DeliveryUnknown):
        nonces.send_same(_seq((502, {"error": "bad gw"}, None)), attempts=1, dedup=False, sleep=lambda t: None)
    with pytest.raises(nonces.DeliveryUnknown):
        nonces.send_same(_seq((429, {}, None), (429, {}, None), (502, {"error": "bad gw"}, None)), attempts=3,
                         dedup=False, sleep=lambda t: None)
    r = _mm(lambda path, body: (502, {"error": "bad gateway"}, None))
    r.attempts = 1
    out = r.cancel_all(pair_id=0)
    assert out.unknown is True and out.ok is False and out.refusal.code == "delivery_unknown"


def test_what_counts_as_never_sent():
    import urllib3
    assert not nonces.never_sent(requests.ConnectionError(urllib3.exceptions.ProtocolError(
        "Connection aborted.", ConnectionResetError(104, "Connection reset by peer"))))
    assert not nonces.never_sent(requests.ReadTimeout("Read timed out. (read timeout=5)"))
    assert not nonces.never_sent(TimeoutError("timed out"))
    try:
        try:
            raise ConnectionRefusedError(111, "Connection refused")
        except Exception:
            raise requests.ReadTimeout("read timed out")      # raised while handling a refused connect: still a read
    except Exception as e:
        assert not nonces.never_sent(e)
    assert nonces.never_sent(requests.ConnectionError("Failed to establish a new connection: [Errno 111] Connection refused"))
    assert nonces.never_sent(requests.ConnectTimeout("connect timed out"))


def test_an_order_refused_after_a_lost_answer_is_unknown_unless_it_reads_back(monkeypatch):
    chain = FakeChain()

    seen = set()

    def script(body, i):
        if body["clientNonce"] not in seen:         # each order's first copy applies, and its answer is lost
            seen.add(body["clientNonce"])
            chain.deliver(body)
            raise requests.ReadTimeout("lost")
        return 400, {"code": "insufficient_margin", "error": "The account's free USDC does not cover the order."}
    _patch_post(monkeypatch, script)
    vx = dex.Vordex(rpc_url="http://rpc.invalid", chain_clock=None)
    monkeypatch.setattr(vx, "order_by_client_nonce", lambda o, n, signed=None: None)
    out = vx.place_order(Account.create().key.hex(), OWNER, 1, dex.BUY, 1, 100)
    assert out["status"] == "unknown" and out["status_code"] is None and out.get("code") is None
    out = _vx(monkeypatch, chain).place_order(Account.create().key.hex(), OWNER, 1, dex.BUY, 1, 100)
    assert out["status"] == "received" and len(chain.effects) == 2      # (each call is its own order)


def test_operator_order_refused_after_a_lost_answer_is_unknown(monkeypatch):
    from vordium import operator as opm
    _patch_post(monkeypatch, lambda body, i: (_ for _ in ()).throw(requests.ReadTimeout("lost")) if i == 1
                else (400, {"code": "insufficient_margin"}))
    s = Account.create()
    op = opm.Operator(owner=OWNER, signer=opm.SessionSigner(private_key=s.key.hex()), submit_url="http://rpc.invalid")
    out = op.place_order(1, dex.BUY, 10 ** 18, 100 * 10 ** 8, 10_000)
    assert out["status"] == "unknown" and out["status_code"] is None


def test_account_ops_refused_after_a_lost_answer_goes_to_the_read_back(monkeypatch):
    from vordium import account_ops as A
    ops = A.AccountOps.__new__(A.AccountOps)
    ops.rest, ops.timeout, ops.attempts = "http://rpc.invalid", 1, 3
    seq = [requests.ReadTimeout("lost"), Resp(400, {"code": "refused", "error": "x"})]

    class S:
        def post(self, *a, **k):
            x = seq.pop(0)
            if isinstance(x, BaseException):
                raise x
            x.text = ""
            return x
    monkeypatch.setattr(_http_mod, "session", lambda: S())
    code, ans = ops._post("/margin/mode", "{}", dedup=True)
    assert code == 0 and ans["status"] == "unknown" and ops._took(code, ans)


def test_signed_size_reads_the_original_size_first():
    sig = {"pair_id": 1, "side": 0, "size_18dec": 10 ** 18, "price_8dec": None}
    assert dex.matches_signed({"pair_id": 1, "side": "buy", "size_18dec": 5 * 10 ** 17, "original_size_18dec": 10 ** 18}, sig)
    assert not dex.matches_signed({"pair_id": 1, "side": "buy", "size_18dec": 5 * 10 ** 17}, sig)   # left over: unknown
    assert not dex.matches_signed({"pair_id": 1, "side": "buy", "price_8dec": 123}, sig)            # market: price is no proof
    from vordium.account_ops import twap_matches
    assert not twap_matches({"client_nonce": 5, "side": "long"}, {"clientNonce": 5, "pairId": 1, "side": 1, "totalSize18dec": 1})
    assert twap_matches({"client_nonce": 5, "side": "short"}, {"clientNonce": 5, "pairId": 1, "side": 1, "totalSize18dec": 1})


def test_after_a_rewind_an_older_order_on_a_reused_nonce_is_not_ours(monkeypatch, tmp_path):
    a = NonceAllocator(OWNER, state=tmp_path, clock=lambda: T0)
    a.seen(int(T0 * 1000) + 2 * DAY_MS)
    with pytest.warns(nonces.NonceStateWarning):
        n = a()
    assert a.rewound_before(n) == int(T0 * 1000) and a.rewound_before(int(T0 * 1000) + 3 * DAY_MS) is None
    b = NonceAllocator(OWNER, state=tmp_path, clock=lambda: T0)           # another process sees it too
    assert b.rewound_before(n) == int(T0 * 1000)
    # in the client: a matching order OLDER than the set-back is another write's
    now = int(time.time() * 1000)
    c = mm.nonce_clock(OWNER)
    c.seen(now + 2 * DAY_MS)

    seen = set()

    def script(body, i):
        if body["clientNonce"] not in seen:
            seen.add(body["clientNonce"])
            raise requests.ReadTimeout("lost")
        return 400, {"code": "nonce", "error": "... or already used."}
    _patch_post(monkeypatch, script)
    vx = dex.Vordex(rpc_url="http://rpc.invalid", chain_clock=None)
    rec = lambda ts: (lambda o, n, signed=None: {"client_nonce": n, **signed, "side": "buy", "timestamp_ms": ts})
    monkeypatch.setattr(vx, "order_by_client_nonce", rec(now - 60_000))
    with pytest.warns(nonces.NonceStateWarning):
        out = vx.place_order(Account.create().key.hex(), OWNER, 1, dex.BUY, 1, 100)
    assert out["status"] == "unknown"
    monkeypatch.setattr(vx, "order_by_client_nonce", rec(now + 60_000))
    out = vx.place_order(Account.create().key.hex(), OWNER, 1, dex.BUY, 1, 100)
    assert out["status"] == "received"


def test_the_answer_parser_never_calls_a_gateway_error_a_refusal():
    for code, body in ((502, {"error": "bad gateway"}), (504, "<html>504</html>"), (503, {})):
        r = mm.read_answer(code, body)
        assert r.ok is False and r.unknown is True and r.refusal.code == "delivery_unknown"


# ── round 4 ─────────────────────────────────────────────────────────────────────────────────────────────────────────
def test_a_cancel_whose_first_copy_landed_is_done_not_refused(monkeypatch):           # reviewer probe-cancel
    _patch_post(monkeypatch, lambda body, i: (_ for _ in ()).throw(requests.ReadTimeout("lost")) if i % 2 == 1
                else (400, {"code": "order_not_found", "error": "order not open"}))
    vx = dex.Vordex(rpc_url="http://rpc.invalid", chain_clock=None)
    records = {"events": [{"kind": "order_closed", "order_id": 77, "status": "cancelled"}]}
    monkeypatch.setattr(vx, "_get", lambda path: records if path.startswith("/events/") else [])   # no longer resting
    out = vx.cancel_order(Account.create().key.hex(), OWNER, 77)
    assert out["status"] == "done" and out["order_gone"] is True and out["status_code"] is None
    records = {"events": [{"kind": "order_closed", "order_id": 77, "status": "filled"}]}           # it filled first
    out = vx.cancel_order(Account.create().key.hex(), OWNER, 77)
    assert out["status"] == "filled" and out["already_received"] is False and "check your position" in out["detail"]
    records = {"events": []}                                                                      # gone, no record yet
    out = vx.cancel_order(Account.create().key.hex(), OWNER, 77)
    assert out["status"] == "unknown" and "filled or cancelled" in out["detail"]
    monkeypatch.setattr(vx, "_get", lambda path: [{"id": 77, "client_nonce": 1}])      # still resting
    out = vx.cancel_order(Account.create().key.hex(), OWNER, 77)
    assert out["status"] == "unknown" and out["delivery_unknown"] is True


def test_a_cancel_answered_5xx_with_a_code_after_a_lost_answer_is_unknown(monkeypatch):
    monkeypatch.setattr(_http_mod, "retry_wait", lambda attempt, ra=None, rand=None: 0.0)
    _patch_post(monkeypatch, lambda body, i: (_ for _ in ()).throw(requests.ReadTimeout("lost")) if i == 1
                else (500, {"code": "internal", "error": "x"}))
    vx = dex.Vordex(rpc_url="http://rpc.invalid", chain_clock=None)
    monkeypatch.setattr(vx, "_get", lambda path: (_ for _ in ()).throw(requests.ConnectionError("down")))
    out = vx.cancel_order(Account.create().key.hex(), OWNER, 77)
    assert out["status"] == "unknown" and out.get("code") is None


def test_operator_cancel_reads_the_orders_back(monkeypatch):
    from vordium import operator as opm
    _patch_post(monkeypatch, lambda body, i: (_ for _ in ()).throw(requests.ReadTimeout("lost")) if i == 1
                else (400, {"code": "order_not_found"}))
    monkeypatch.setattr(_http_mod, "get", lambda url, timeout=None, **k: Resp(200, {"events": [
        {"kind": "order_cancelled", "order_id": 77}]} if "/events/" in url else []))
    s = Account.create()
    op = opm.Operator(owner=OWNER, signer=opm.SessionSigner(private_key=s.key.hex()), submit_url="http://rpc.invalid")
    out = op.cancel_order(77)
    assert out["status"] == "done" and out["order_gone"] is True


def test_account_ops_say_unknown_when_a_write_may_have_landed_and_is_not_seen():
    from test_account_ops import _Stub, SPEC
    from vordium import account_ops as A
    r = A.read_twap_rules(SPEC)
    c = _Stub((0, {"status": "unknown"}), [{"twaps": []}])
    assert c.place_twap(r, 1, 0, 10 ** 18, 300000).applied is None
    c = _Stub((202, {"status": "submitted"}), [{"twaps": []}])
    assert c.place_twap(r, 1, 0, 10 ** 18, 300000).applied is None                  # received, not shown yet
    c = _Stub((400, {"code": "twap_params"}), [{"twaps": []}])
    assert c.place_twap(r, 1, 0, 10 ** 18, 300000).applied is False                 # refused: certainly not applied
    c = _Stub((0, {"status": "unknown"}), [{"modes": [], "default_mode": "isolated"}])
    assert c.set_margin_mode(4, "cross").applied is None


def test_an_ended_twap_counts_as_placed():
    from test_account_ops import _Stub, SPEC
    from vordium import account_ops as A
    r = A.read_twap_rules(SPEC)
    c = _Stub((0, {"status": "unknown"}), [{"twaps": []}])
    real_get = c._get

    def get(path):
        if path.startswith("/events/account/"):
            body = __import__("json").loads(c.posts[-1][1])
            return {"events": [{"kind": "twap_ended", "client_nonce": body["client_nonce"], "pair_id": 1, "side": 0}]}
        return real_get(path)
    c._get = get
    assert c.place_twap(r, 1, 0, 10 ** 18, 300000).applied is True


def test_a_refusal_during_the_connect_step_only_is_never_sent():
    import urllib3
    assert not nonces.never_sent(ConnectionRefusedError(111, "Connection refused"))           # not tied to the connect
    assert not nonces.never_sent(requests.ConnectionError("[Errno 113] No route to host"))
    assert nonces.never_sent(requests.ConnectionError(urllib3.exceptions.NewConnectionError(
        None, "Failed to establish a new connection: [Errno 111] Connection refused")))
    assert nonces.never_sent(requests.ConnectTimeout("connect timed out"))


def test_the_rewind_time_is_the_networks_when_known(tmp_path):
    a = NonceAllocator(OWNER, state=tmp_path, clock=lambda: T0)
    a.seen(int(T0 * 1000) + 2 * DAY_MS)
    chain = int(T0 * 1000) + 3_600_000                                                   # the chain is an hour ahead
    with pytest.warns(nonces.NonceStateWarning):
        n = a.next_at_least(0, chain_ms=chain)
    assert a.rewound_before(n) == chain



# ── round 5 ─────────────────────────────────────────────────────────────────────────────────────────────────────────
def _refused_connect():
    import urllib3
    return requests.ConnectionError(urllib3.exceptions.NewConnectionError(
        None, "Failed to establish a new connection: [Errno 111] Connection refused"))


def test_a_connect_that_failed_on_every_try_is_not_sent(monkeypatch):
    monkeypatch.setattr(_http_mod, "retry_wait", lambda attempt, ra=None, rand=None: 0.0)
    with pytest.raises(nonces.DeliveryUnknown) as e:
        nonces.send_same(lambda: (_ for _ in ()).throw(_refused_connect()), sleep=lambda t: None)
    assert e.value.never_sent is True and "nothing was sent" in str(e.value)
    out = _mm(lambda path, body: (_ for _ in ()).throw(_refused_connect())).cancel_all(pair_id=0)
    assert out.ok is False and out.unknown is False and out.refusal.code == "not_sent"
    from vordium import account_ops as A
    ops = A.AccountOps.__new__(A.AccountOps)
    ops.rest, ops.timeout, ops.attempts = "http://rpc.invalid", 1, 2

    class S:
        def post(self, *a, **k):
            raise _refused_connect()
    monkeypatch.setattr(_http_mod, "session", lambda: S())
    code, ans = ops._post("/margin/mode", "{}", dedup=False)
    r = ops._outcome(code, ans, lambda: True, 0.0, "x")
    assert r.applied is False and "nothing was sent" in r.detail
