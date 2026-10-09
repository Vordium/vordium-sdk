"""The dead-man switch (ScheduleCancel) against the chain's PUBLISHED vectors, and the client rules around it.

Reference: tests/vectors/schedule-cancel-vectors.json -- produced by the node and checked there by a second, independent
encoder. Its sha256 is pinned below; a file that does not match is refused rather than compared against. Every expected
value is READ from it; every actual value is COMPUTED by the SDK (caps.schedule_cancel_*), and the digests are also
recomputed with eth_account's own EIP-712 encoder -- two encoders in this file, the node's third.

Runs under pytest, or standalone: python tests/test_schedule_cancel.py
"""
import hashlib
import json
from pathlib import Path

from eth_account import Account
from eth_account.messages import encode_typed_data
from eth_utils import keccak

from vordium.node_domain import NodeIdentity
from vordium import caps
from vordium import network as net
from vordium import schedule_cancel as sc

VECTORS = Path(__file__).parent / "vectors" / "schedule-cancel-vectors.json"
PINNED_SHA256 = "0efa2de525b6fca6f72c76d346c8d348271cf399e2478e2a2d0a60032cbbc7e6"
TYPE = "ScheduleCancel(address owner,uint64 cancelAtMs,uint64 nonce)"
#: a public test key: keccak of a label, never funded
TEST_KEY = "0x" + keccak(b"vordium-test-schedule-cancel").hex().removeprefix("0x")


def _load():
    raw = VECTORS.read_bytes()
    sha = hashlib.sha256(raw).hexdigest()
    assert sha == PINNED_SHA256, f"vectors file sha256 {sha} is not the pinned {PINNED_SHA256}; refusing to compare"
    return json.loads(raw)


V = _load()


_IDENT = lambda: NodeIdentity(V["chain_id"], V["genesis_sha256"])


def _pin_network():
    net.set_network(net.Network(
        chain_id=V["chain_id"], chain_id_hex=hex(V["chain_id"]), chain_name="Vordium Chain", rpc_url="offline", ws_url=None,
        explorer_url=None, bridge_address=None, bridge_chain=None, bridge_chain_id=None, native_symbol="VORD",
        native_decimals=18, verifying_contract=net.VERIFYING_CONTRACT, source="vectors", genesis_sha256=V["genesis_sha256"],
    ))


def _hex(b):
    return "0x" + bytes(b).hex()


def test_type_hash_matches_published():
    assert _hex(keccak(TYPE.encode())) == V["type_hash"]
    assert _hex(caps._SCHEDULE_CANCEL_TYPEHASH) == V["type_hash"]


def test_domain_separator_matches_published():
    sep = caps.vordcore_domain_separator(V["chain_id"], net.VERIFYING_CONTRACT, V["genesis_sha256"])
    assert _hex(sep) == V["domain_separator"]
    _pin_network()
    assert _hex(caps.domain_separator()) == V["domain_separator"]


def test_struct_hashes_and_digests_match_published():
    _pin_network()
    assert len(V["cases"]) >= 3
    for c in V["cases"]:
        assert _hex(caps.schedule_cancel_struct_hash(c["owner"], c["cancel_at_ms"], c["nonce"])) == c["struct_hash"], c
        assert _hex(caps.schedule_cancel_digest(c["owner"], c["cancel_at_ms"], c["nonce"])) == c["digest"], c


def test_a_second_encoder_agrees():
    """eth_account's EIP-712 encoder, given the domain fields and the type, lands on the same digests."""
    salt = keccak(b"VORDIUM_VORDCORE\x01" + bytes.fromhex(V["genesis_sha256"]))
    domain = {"name": "VordCore", "version": "1", "chainId": V["chain_id"], "verifyingContract": net.VERIFYING_CONTRACT, "salt": salt}
    types = {"ScheduleCancel": [{"name": "owner", "type": "address"}, {"name": "cancelAtMs", "type": "uint64"},
                                {"name": "nonce", "type": "uint64"}]}
    for c in V["cases"]:
        m = encode_typed_data(domain_data=domain, message_types=types,
                              message_data={"owner": c["owner"], "cancelAtMs": c["cancel_at_ms"], "nonce": c["nonce"]})
        assert _hex(m.header) == V["domain_separator"]
        assert _hex(m.body) == c["struct_hash"], c
        assert _hex(keccak(b"\x19\x01" + m.header + m.body)) == c["digest"], c


def test_signature_is_65_bytes_and_recovers_the_signer():
    _pin_network()
    owner = Account.from_key(TEST_KEY).address
    for c in V["cases"]:
        sig = sc.sign_schedule_cancel(TEST_KEY, owner, c["cancel_at_ms"], c["nonce"])
        raw = bytes.fromhex(sig[2:])
        assert len(raw) == 65 and raw[64] in (27, 28), sig
        d = caps.schedule_cancel_digest(owner, c["cancel_at_ms"], c["nonce"])
        assert Account._recover_hash(d, signature=raw) == owner


def test_values_outside_u64_are_refused():
    for bad in (-1, 1 << 64):
        for args in (("0x" + "11" * 20, bad, 1), ("0x" + "11" * 20, 1, bad)):
            try:
                caps.schedule_cancel_struct_hash(*args)
            except ValueError:
                continue
            raise AssertionError(f"accepted {args}")


def test_body_carries_exactly_the_published_fields():
    b = sc.schedule_cancel_body("0x" + "ab" * 20, (1 << 64) - 1, 7, "0x" + "00" * 65)
    assert list(b) == ["owner", "cancel_at_ms", "nonce", "signature"]
    assert b["cancel_at_ms"] == (1 << 64) - 1 and b["nonce"] == 7


def _read(**over):
    j = {"account": "0x" + "ab" * 20, "cancel_at_ms": 1_800_000_060_000, "set_at_ms": 1_800_000_000_000, "nonce": "12",
         "fired": False, "orders_refused": False, "limits": {"min_lead_ms": 5000, "max_horizon_ms": 86_400_000, "min_refresh_ms": 1000},
         "active": True, "as_of": {"height": 42}}
    j.update(over)
    return j


def test_read_is_parsed_strictly():
    s = sc.read_state(_read(), "0x" + "AB" * 20)
    assert s.cancel_at_ms == 1_800_000_060_000 and s.nonce == 12 and s.active and s.limits.min_refresh_ms == 1000 and s.height == 42
    assert sc.read_state(_read(cancel_at_ms=None), "0x" + "ab" * 20).cancel_at_ms is None
    for bad in ({"account": "0x" + "cd" * 20}, {"limits": None}, {"active": "yes"}, {"fired": None}, {"cancel_at_ms": -5},
                {"limits": {"min_lead_ms": 5000, "max_horizon_ms": 1}}):
        try:
            sc.read_state(_read(**bad), "0x" + "ab" * 20)
        except sc.ScheduleCancelError:
            continue
        raise AssertionError(f"accepted {bad}")


def test_deadline_stays_inside_the_chains_window():
    lim = sc.Limits(5000, 86_400_000, 1000)
    assert sc.deadline(1_000_000, 90_000, lim) == 1_090_000
    for lead in (9_999, 86_400_001):
        try:
            sc.deadline(1_000_000, lead, lim)
        except sc.ScheduleCancelError:
            continue
        raise AssertionError(f"accepted a lead of {lead}")


class _Chain:
    """A fake transport: answers as the chain's route does, records what was sent."""

    def __init__(self, answers):
        self.answers, self.sent = list(answers), []

    def __call__(self, rpc_url, body, timeout):
        self.sent.append(body)
        a = self.answers.pop(0) if self.answers else (202, {"status": "submitted"})
        if isinstance(a, Exception):
            raise a
        return a


def _keepalive(answers, t0=1_800_000_000.0):
    clock = {"t": t0}
    slept = []
    chain = _Chain(answers)
    st = sc.read_state(_read(nonce=None, cancel_at_ms=None), "0x" + "ab" * 20)
    ka = sc.KeepAlive("offline", TEST_KEY, Account.from_key(TEST_KEY).address, lead_ms=30_000,
                      clock=lambda: clock["t"], sleep=lambda s: (slept.append(s), clock.__setitem__("t", clock["t"] + s)),
                      post=chain, read=lambda: st, identity=_IDENT)
    return ka, chain, clock, slept


def test_keepalive_arms_now_plus_lead_with_rising_nonces():
    _pin_network()
    ka, chain, clock, slept = _keepalive([])
    r1 = ka.refresh(); clock["t"] += 2.0
    r2 = ka.refresh()
    assert r1.ok and r2.ok and ka.alive
    assert chain.sent[0]["cancel_at_ms"] == 1_800_000_000_000 + 30_000
    assert chain.sent[1]["nonce"] > chain.sent[0]["nonce"] and chain.sent[1]["cancel_at_ms"] > chain.sent[0]["cancel_at_ms"]
    assert not slept


def test_keepalive_never_sends_inside_the_minimum_interval():
    """the interval runs from when the previous ANSWER came back (the chain had it by then), plus a margin"""
    _pin_network()
    ka, chain, clock, slept = _keepalive([])
    ka.refresh(); clock["t"] += 0.3
    ka.refresh()
    assert slept and abs(slept[0] - 0.95) < 0.01, slept          # 1000 ms minimum + 250 ms margin − 300 ms elapsed
    assert chain.sent[1]["nonce"] - chain.sent[0]["nonce"] >= 1250


def test_keepalive_counts_the_interval_from_the_answer_not_the_send():
    """a slow answer: the next refresh waits a full interval from when it came back, not from when it was sent"""
    _pin_network()
    clock, slept = {"t": 1_800_000_000.0}, []

    def slow_post(rpc_url, body, timeout):
        clock["t"] += 0.8                     # the answer takes 800 ms
        return 202, {"status": "submitted"}
    st = sc.read_state(_read(nonce=None, cancel_at_ms=None), "0x" + "ab" * 20)
    ka = sc.KeepAlive("offline", TEST_KEY, Account.from_key(TEST_KEY).address, lead_ms=30_000, clock=lambda: clock["t"],
                      sleep=lambda s: (slept.append(s), clock.__setitem__("t", clock["t"] + s)), post=slow_post, read=lambda: st, identity=_IDENT)
    ka.refresh()
    answered = clock["t"]
    clock["t"] += 0.5
    ka.refresh()
    assert slept and clock["t"] - 0.8 - answered >= 1.25 - 1e-6, (slept, clock["t"] - answered)


def test_keepalive_reports_every_failure_as_not_alive():
    _pin_network()
    for answer, word in (((409, {"error": "not_active"}), "not_active"), ((400, {"error": "refused", "reason": "nonce not above"}), "refused"),
                         ((403, {"error": "bad_signature"}), "bad_signature"), (ConnectionError("down"), "ConnectionError"),
                         ((202, {"status": "pending"}), "HTTP 202"), ((200, {}), "HTTP 200")):
        ka, chain, clock, _ = _keepalive([answer])
        r = ka.refresh()
        assert not r.ok and not ka.alive and word in r.reason, (answer, r)
        clock["t"] += 2.0
        assert ka.refresh().ok and ka.alive


def test_keepalive_goes_not_alive_after_a_success_when_a_refresh_fails():
    _pin_network()
    ka, chain, clock, _ = _keepalive([(202, {"status": "submitted"}), (409, {"error": "not_active"})])
    assert ka.refresh().ok and ka.alive
    clock["t"] += 2.0
    r = ka.refresh()
    assert not r.ok and not ka.alive, r


def test_nonce_rises_above_the_chains_last_and_when_the_clock_steps_back():
    _pin_network()
    clock, chain = {"t": 1_800_000_000.0}, _Chain([])
    ahead = 1_800_000_000_000 + 5_000_000          # the chain already holds a nonce ahead of this clock
    st = sc.read_state(_read(nonce=ahead), "0x" + "ab" * 20)
    ka = sc.KeepAlive("offline", TEST_KEY, Account.from_key(TEST_KEY).address, lead_ms=30_000,
                      clock=lambda: clock["t"], sleep=lambda s: clock.__setitem__("t", clock["t"] + s), post=chain, read=lambda: st, identity=_IDENT)
    ka.refresh()
    assert chain.sent[0]["nonce"] > ahead, chain.sent[0]
    clock["t"] -= 30.0                              # the host clock steps back
    ka.refresh()
    assert chain.sent[1]["nonce"] > chain.sent[0]["nonce"], chain.sent


def test_keepalive_refuses_a_lead_outside_the_window_before_sending():
    ka, chain, _, _ = _keepalive([])
    ka.lead_ms = 4_000
    try:
        ka.start()
    except sc.ScheduleCancelError:
        assert chain.sent == []
        return
    raise AssertionError("a 4 s lead was accepted")


def test_clear_sends_zero():
    _pin_network()
    ka, chain, clock, _ = _keepalive([])
    ka.refresh(); clock["t"] += 2
    r = ka.clear()
    assert r.ok and chain.sent[-1]["cancel_at_ms"] == 0 and not ka.alive


if __name__ == "__main__":
    import sys
    fails = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn(); print(f"PASS  {name}")
            except Exception as e:
                fails += 1; print(f"FAIL  {name}: {e!r}")
    sys.exit(1 if fails else 0)
