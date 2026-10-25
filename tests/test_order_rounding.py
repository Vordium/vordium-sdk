"""Every order value on its market's tick and lot, exactly, for every market of both networks.

The chain keeps a price step (``tick_8dec``) and a size step (``lot_18dec``) per market and answers an order off them with
``202``, then does not apply it. The two files in ``tests/vectors/`` are the networks' own ``GET /markets/specs`` answers,
pinned by sha256. For every market in them, many prices and sizes — floats, strings, Decimals and ints, on the step and
off it — go through every order path, and each signed value must be:

    a multiple of the step, exactly;
    a limit price: a buy's at or below the price asked and less than one step below it, a sell's at or above it;
    a trigger price: the nearest step;
    a size: at or below the size asked and less than one lot below it;
    equal to an independent reference computed with fractions from the number's decimal form.

A float multiplication (``int(round(x * 10**18))``) is the counter-example that shows the test bites: it lands sizes and
prices that were asked ON the step off it.
"""
import hashlib
import json
import os
import random
from decimal import Decimal
from fractions import Fraction

import pytest
from eth_account import Account

from vordium import account_ops, dex, mm, node_domain, units
from vordium import operator as opm
from vordium import _http

HERE = os.path.dirname(__file__)
#: sha256 of each recorded answer. A cross-check pin, not a value.
PINNED = {
    "markets-specs-testnet.json": "d09e90044000c07abc56c81e1f002c81150697578dbaaacbac2cf6a5209f24ea",
    "markets-specs-mainnet.json": "4c6de2f227e6ab9e52578737688dec31c8c3114bbaed770d215b220fc6fa2f39",
}
OWNER = "0x" + "11" * 20
IDENT = lambda: node_domain.NodeIdentity(101101, "2c1c0679fa6ab8358f1d3e8d294a8d1c73ac2e2caf9079f1216abedc3d9fdf4f")
KEY = "0x" + "42" * 32
R = random.Random(14_008)
REAL_FETCH = units.fetch_specs          # the unit tests' fixture replaces it with "no rules"; these tests read the real one


def _load(name):
    raw = open(os.path.join(HERE, "vectors", name), "rb").read()
    sha = hashlib.sha256(raw).hexdigest()
    assert sha == PINNED[name], f"{name} sha256 {sha} is not the pinned {PINNED[name]}; refusing to compare"
    return json.loads(raw)


READS = {n.split("-")[-1][:-5]: _load(n) for n in PINNED}
SPECS = {net: mm.pair_specs(r) for net, r in READS.items()}
MARKETS = [(net, pid) for net, by in SPECS.items() for pid in sorted(by)]


def test_the_recordings_hold_every_market_with_its_rules():
    assert len(SPECS["testnet"]) == 16 and len(SPECS["mainnet"]) == 16
    eth = SPECS["testnet"][1]
    assert (eth.tick_8dec, eth.lot_18dec) == (10**7, 10**14)                  # ETH: tick 0.1, lot 0.0001
    assert sum(1 for s in SPECS["testnet"].values() if s.tick_8dec and s.lot_18dec) == 15
    assert all(s.tick_8dec == 0 and s.lot_18dec == 0 for s in SPECS["mainnet"].values())
    assert all(s.min_notional_6dec == 10_000_000 for by in SPECS.values() for s in by.values())


# --- an independent reference ---------------------------------------------------------------------------------

def frac(x):
    if isinstance(x, float):
        return Fraction(repr(x))
    return Fraction(str(x)) if not isinstance(x, int) else Fraction(x)


def lcm(a, b):
    from math import gcd
    return a * b // gcd(a, b)


def ref_price(x, spec, side, place=True):
    step = (lcm(spec.tick_8dec, 100) if spec.tick_8dec else 100) if place else (spec.tick_8dec or 1)
    v = frac(x) * 10**8 / step
    q = v.numerator // v.denominator
    if v.denominator != 1 and side == "sell":
        q += 1
    return q * step, step


def ref_size(x, spec):
    lot = spec.lot_18dec or 1
    v = frac(x) * 10**18 / lot
    return (v.numerator // v.denominator) * lot, lot


def ref_trigger(p8, spec):
    t = spec.tick_8dec or 1
    q, r = divmod(p8, t)
    return (q + 1) * t if 2 * r >= t else q * t


def number(x_frac, kind):
    """The same value in one of the forms a caller passes."""
    s = format(Decimal(x_frac.numerator) / Decimal(x_frac.denominator), "f") if x_frac.denominator != 1 else str(x_frac)
    if kind == "float":
        return float(s)
    if kind == "str":
        return s
    if kind == "exp":
        d = Decimal(s)
        return f"{d:e}"
    if kind == "decimal":
        return Decimal(s)
    return s


def prices(spec):
    """Prices around the market: on the tick, off it, with many decimals, and tiny."""
    tick = spec.tick_8dec or 100
    out = []
    for _ in range(120):
        k = R.choice([R.randrange(1, 100), R.randrange(100, 10**6), R.randrange(10**6, 10**9)])
        on = Fraction(k * tick, 10**8)
        off = on + Fraction(R.randrange(1, 10**12), 10**R.randrange(9, 20))
        for v in (on, off):
            out.append(number(v, R.choice(["float", "float", "str", "exp", "decimal"])))
    out += [0.1, 0.3, 1.005, 2420.5, 1343.8712346, "0.00000123456789", Decimal("97000.123456789")]
    return out


def sizes(spec):
    lot = spec.lot_18dec or 10**12
    out = []
    for _ in range(120):
        k = R.choice([R.randrange(1, 50), R.randrange(50, 10**5), R.randrange(10**5, 10**8)])
        on = Fraction(k * lot, 10**18)
        off = on + Fraction(R.randrange(1, 10**9), 10**R.randrange(10, 25))
        for v in (on, off):
            out.append(number(v, R.choice(["float", "float", "str", "exp", "decimal"])))
    out += [0.29, 0.0062, 1.1, 15 / 2420.5, "0.000000000000000001", Decimal("3.000000000000000000999")]
    return out


# --- every market, every number ----------------------------------------------------------------------------------

@pytest.mark.parametrize("net,pid", MARKETS)
def test_every_price_and_size_lands_exactly_on_the_step(net, pid):
    spec = SPECS[net][pid]
    checked = 0
    for x in prices(spec):
        for side in ("buy", "sell"):
            for place in (True, False):
                want, step = ref_price(x, spec, side, place)
                if want == 0:
                    with pytest.raises(units.OrderValueError):
                        units.price_8dec(x, spec, side, place)
                    continue
                got = units.price_8dec(x, spec, side, place)
                asked = frac(x) * 10**8
                assert got == want and got % step == 0, (net, pid, x, side, got, want)
                assert (got <= asked < got + step) if side == "buy" else (got - step < asked <= got)
                if spec.tick_8dec:
                    assert got % spec.tick_8dec == 0
                checked += 1
    for x in sizes(spec):
        want, lot = ref_size(x, spec)
        if want == 0:
            with pytest.raises(units.OrderValueError):
                units.size_18dec(x, spec)
            continue
        got = units.size_18dec(x, spec)
        asked = frac(x) * 10**18
        assert got == want and got % lot == 0 and got <= asked < got + lot, (net, pid, x, got, want)
        checked += 1
    for p8 in (R.randrange(1, 10**16) for _ in range(200)):
        assert units.snap_trigger_8dec(p8, spec) == ref_trigger(p8, spec)
        s18 = R.randrange(1, 10**24)
        want = s18 - s18 % (spec.lot_18dec or 1)
        if want:
            assert units.snap_size_18dec(s18, spec) == want
        for side in ("buy", "sell"):
            want = ref_price(Fraction(p8, 10**8), spec, side, False)[0]
            if want == 0:
                with pytest.raises(units.OrderValueError):
                    units.snap_price_8dec(p8, spec, side)
            else:
                assert units.snap_price_8dec(p8, spec, side) == want
    assert checked > 900


# --- a float multiplication fails values asked ON the step ------------------------------------------------------

def float_size(x):
    return int(round(x * 10**18))


def float_price(x):
    return int(round(x * 10**6)) * 100


def test_a_float_multiplication_lands_values_asked_on_the_step_off_it_and_the_exact_one_never():
    float_bad = exact_bad = n = float_sizes = float_prices = 0
    rng = random.Random(7)
    for net, pid in MARKETS:
        spec = SPECS[net][pid]
        if not spec.lot_18dec:
            continue
        for _ in range(400):
            k = rng.choice([rng.randrange(1, 1000), rng.randrange(1000, 10**6)])
            s = float(format(Decimal(k * spec.lot_18dec) / Decimal(10**18), "f"))
            t = float(format(Decimal(k * spec.tick_8dec) / Decimal(10**8), "f"))
            n += 1
            size_off, price_off = float_size(s) % spec.lot_18dec != 0, float_price(t) % spec.tick_8dec != 0
            float_sizes += size_off
            float_prices += price_off
            if size_off or price_off:
                float_bad += 1
            if units.size_18dec(s, spec) % spec.lot_18dec or units.price_8dec(t, spec, "buy") % spec.tick_8dec:
                exact_bad += 1
    rate = float_bad / n
    print(f"float multiplication: {float_bad} of {n} on-step orders off the step ({rate:.1%}: sizes {float_sizes / n:.1%}, "
          f"prices {float_prices / n:.1%}); exact path: {exact_bad}")
    assert float_bad > n // 50, "a float multiplication is expected to fail some on-step values"
    assert exact_bad == 0


def test_numbers_typed_at_six_decimals_are_off_the_step_unless_snapped():
    """Sizes and prices as a caller computes them (``round(15 / price, 6)``, ``round(mark * 0.8, 6)``): without the
    step they are signed off it; with it, never."""
    rng = random.Random(8)
    n = off = 0
    for pid, spec in SPECS["testnet"].items():
        if not spec.lot_18dec:
            continue
        for _ in range(400):
            mark = rng.uniform(0.05, 120_000)
            price = round(mark * rng.uniform(0.8, 1.2), 6)
            size = round(rng.uniform(15, 5_000) / price, 6)
            n += 1
            off += bool(float_size(size) % spec.lot_18dec or float_price(price) % spec.tick_8dec)
            side = rng.choice(["buy", "sell"])
            if ref_size(size, spec)[0] == 0:
                with pytest.raises(units.OrderValueError):
                    units.size_18dec(size, spec)
            else:
                assert units.size_18dec(size, spec) % spec.lot_18dec == 0
            assert units.price_8dec(price, spec, side) % spec.tick_8dec == 0
    print(f"typed at 6 decimals, no step: {off} of {n} off the step ({off / n:.1%})")
    assert off > n // 2


# --- every order path signs values on the step -------------------------------------------------------------------

class _Resp:
    status_code = 202
    content = b"{}"
    headers = {}

    def json(self):
        return {"status": "submitted"}


def _capture(monkeypatch):
    sent = []
    monkeypatch.setattr(_http, "post", lambda url, json=None, timeout=None, **k: (sent.append((url, json)), _Resp())[1])
    return sent


def _cases(spec, n):
    out = []
    for _ in range(n):
        p = number(Fraction(R.randrange(1, 10**6) * (spec.tick_8dec or 100) + R.randrange(0, 10**8), 10**8 * R.choice([1, 1, 7])),
                   R.choice(["float", "str", "decimal"]))
        off_lot = R.randrange(0, 10**12) if R.random() < 0.5 else 0          # half of the sizes asked exactly on the lot
        s = number(Fraction(R.randrange(1, 10**6) * (spec.lot_18dec or 10**12) + off_lot, 10**18),
                   R.choice(["float", "float", "str", "decimal"]))
        out.append((p, s, R.choice(["buy", "sell"])))
    return out


@pytest.mark.parametrize("net,pid", MARKETS)
def test_vordex_place_order_signs_on_the_step(monkeypatch, net, pid):
    spec = SPECS[net][pid]
    sent = _capture(monkeypatch)
    vx = dex.Vordex(rpc_url="http://rpc.invalid", specs=READS[net])
    for p, s, side in _cases(spec, 25):
        before = len(sent)
        want_p, _ = ref_price(p, spec, side)
        want_s, _ = ref_size(s, spec)
        sd = dex.BUY if side == "buy" else dex.SELL
        if want_s == 0 or want_p == 0 or units.notional_6dec(want_s, want_p) < spec.min_notional_6dec:
            with pytest.raises(units.OrderValueError):
                vx.place_order(KEY, OWNER, pid, sd, s, p, client_nonce=9)
            assert len(sent) == before                                   # refused before anything was sent
            continue
        vx.place_order(KEY, OWNER, pid, sd, s, p, client_nonce=9)
        body = sent[-1][1]
        assert int(body["size_18dec"]) == want_s
        assert (Decimal(repr(body["price"])) * 10**8) == want_p
        if spec.lot_18dec:
            assert want_s % spec.lot_18dec == 0 and want_p % spec.tick_8dec == 0


@pytest.mark.parametrize("net,pid", MARKETS)
def test_operator_and_market_maker_sign_on_the_step(monkeypatch, net, pid):
    spec = SPECS[net][pid]
    sent = _capture(monkeypatch)
    op = opm.Operator(owner=OWNER, signer=opm.SessionSigner(private_key=KEY),
                      box=opm.AgentBox(rpc_url="http://rpc.invalid", rest_url="http://rpc.invalid"),
                      submit_url="http://rpc.invalid", specs=READS[net])
    rec = []
    c = mm.MarketMaker("https://example.invalid", KEY, OWNER, post=lambda path, body: (rec.append((path, body)), (202, {}, None))[1],
                       specs=READS[net], identity=IDENT)
    for p, s, side in _cases(spec, 10):
        p8 = int(frac(p) * 10**8)
        s18 = int(frac(s) * 10**18)
        sd = dex.BUY if side == "buy" else dex.SELL
        wp, _ = ref_price(Fraction(p8, 10**8), spec, side)
        ws, _ = ref_size(Fraction(s18, 10**18), spec)
        ok = ws and wp and units.notional_6dec(ws, wp) >= spec.min_notional_6dec
        if not ok:
            with pytest.raises(units.OrderValueError):
                op.build_place_body(pid, sd, s18, p8, 10_000, 5)
        else:
            b = op.build_place_body(pid, sd, s18, p8, 10_000, 5)
            assert int(b["size_18dec"]) == ws and Decimal(repr(b["price"])) * 10**8 == wp
            op.place_order(pair_id=pid, side=sd, size=s18, price=p8, leverage_bps=10_000, client_nonce=6, precheck=False)
            assert int(sent[-1][1]["size_18dec"]) == ws
        # a batch and a modify: the batch body carries the 8-decimal price itself (only the tick applies)
        bp, _ = ref_price(Fraction(p8, 10**8), spec, side, place=False)
        if ws and bp and units.notional_6dec(ws, bp) >= spec.min_notional_6dec:
            c.batch([mm.place(pid, side, s18, p8, 5)])
            act = rec[-1][1]["actions"][0]
            assert int(act["size_18dec"]) == ws and act["price_8dec"] == bp
            c.modify(77, p8, s18, pair_id=pid, side=side)
            assert rec[-1][1]["newPrice8dec"] == bp and int(rec[-1][1]["newSize18dec"]) == ws
        # take-profit / stop-loss to the nearest tick
        tp = R.randrange(1, 10**14)
        if ref_trigger(tp, spec) == 0:
            with pytest.raises(units.OrderValueError):
                op.build_set_tpsl_body(pid, 3, tp, 0)
        else:
            b = op.build_set_tpsl_body(pid, 3, tp, 0)
            assert b["take_profit_8dec"] == ref_trigger(tp, spec) and b["stop_loss_8dec"] == 0


@pytest.mark.parametrize("net,pid", MARKETS)
def test_twap_size_and_band_on_the_step(net, pid):
    spec = SPECS[net][pid]
    ops = account_ops.AccountOps.__new__(account_ops.AccountOps)
    ops.rest, ops.timeout, ops.specs = "http://node.invalid", 1.0, READS[net]
    lot = spec.lot_18dec or 1
    for _ in range(40):
        n = R.randrange(1, 30)
        total = R.randrange(1, 10**22)
        lo, hi = R.randrange(1, 10**12), R.randrange(10**12, 10**14)
        if total - total % (lot * n) == 0:
            with pytest.raises(units.OrderValueError):
                ops.twap_on_steps(pid, total, n, lo, hi)
            continue
        t, a, b = ops.twap_on_steps(pid, total, n, lo, hi)
        assert t % (lot * n) == 0 and total - lot * n < t <= total
        assert a >= lo and b <= hi and (not spec.tick_8dec or (a % spec.tick_8dec == 0 and b % spec.tick_8dec == 0))


# --- refusals before signing -------------------------------------------------------------------------------------

@pytest.mark.parametrize("bad", [True, float("nan"), float("inf"), -1, "-1", "1_000", " 1", "1,5", "0x10", "", None, [1],
                                 Decimal("-0.5"), -0.25])
def test_a_number_that_is_not_a_plain_positive_decimal_is_refused(bad):
    with pytest.raises(units.OrderValueError):
        units.size_18dec(bad, units.select(units.NO_RULES, 1))
    with pytest.raises(units.OrderValueError):
        units.decimal_of(bad)
    with pytest.raises(units.OrderValueError):
        units.leverage_bps(bad)


def test_a_size_below_one_lot_or_the_market_minimum_is_refused():
    eth = SPECS["testnet"][1]
    with pytest.raises(units.OrderValueError, match="rounds to 0"):
        units.size_18dec("0.00009", eth)                               # lot 0.0001
    assert units.size_18dec("0.00019", eth) == 10**14
    big = mm.PairSpec(1, "X", 0, 10**14, None, None, min_size_18dec=10**16)
    with pytest.raises(units.OrderValueError, match="smallest order"):
        units.size_18dec("0.005", big)
    with pytest.raises(units.OrderValueError, match="smallest order the network takes"):
        units.check_notional(10**15, 10**11, eth)                     # 0.001 × 1000 = 1 USDC < 10


def test_nothing_is_signed_or_sent_when_the_rules_cannot_be_read(monkeypatch):
    sent = _capture(monkeypatch)

    def down(base_url, timeout=10.0, get=None):
        raise units.SpecsUnavailable("the market rules could not be read")
    monkeypatch.setattr(units, "fetch_specs", down)
    with pytest.raises(units.SpecsUnavailable):
        dex.Vordex(rpc_url="http://rpc.invalid").place_order(KEY, OWNER, 1, dex.BUY, 1, 100, client_nonce=1)
    with pytest.raises(units.SpecsUnavailable):
        mm.MarketMaker("https://example.invalid", KEY, OWNER, post=lambda p, b: sent.append(b), identity=IDENT).batch([mm.place(1, "buy", 10**18, 10**10, 1)])
    assert sent == []


def test_a_market_the_network_does_not_list_is_refused(monkeypatch):
    sent = _capture(monkeypatch)
    with pytest.raises(units.OrderValueError, match="lists no market 999"):
        dex.Vordex(rpc_url="http://rpc.invalid", specs=READS["testnet"]).place_order(KEY, OWNER, 999, dex.BUY, 1, 100, client_nonce=1)
    assert sent == []


def test_the_specs_read_is_parsed_exactly_and_a_bad_rule_is_refused():
    assert REAL_FETCH("http://x", get=lambda p: READS["testnet"]) is READS["testnet"]
    with pytest.raises(units.SpecsUnavailable):
        REAL_FETCH("http://x", get=lambda p: {"error": "not found"})
    with pytest.raises(units.SpecsUnavailable):
        REAL_FETCH("http://x", get=lambda p: (_ for _ in ()).throw(OSError("down")))
    with pytest.raises(mm.MMError):
        mm.pair_specs({"specs": {"pairs": [{"pair": {"pair_id": 1}, "tick_8dec": "0.1", "lot_18dec": "1"}]}})


def test_floats_are_read_from_their_shortest_decimal_form():
    assert units.size_18dec(0.57, units.select(units.NO_RULES, 1)) == 570_000_000_000_000_000
    assert float_size(0.57) == 569_999_999_999_999_936                  # the float product is not 0.57
    assert float_size(1.1) == 1_100_000_000_000_000_128 and units.size_18dec(1.1, units.select(units.NO_RULES, 1)) == 11 * 10**17
    assert dex.to_size_18dec(0.57) == 570_000_000_000_000_000
    assert dex.to_price_8dec(0.1) == 10_000_000 and dex.limit_price_8dec("0.1234565") == 12_345_600
    assert units.leverage_bps(2.3) == 23_000 and units.leverage_bps("10") == 100_000


def test_halves_trigger_up_and_leverage_to_even():
    eth = SPECS["testnet"][1]                                         # tick 0.1
    assert units.snap_trigger_8dec(15_000_000, eth) == 20_000_000     # 0.15: a half tick rounds up
    assert units.snap_trigger_8dec(14_999_999, eth) == 10_000_000
    assert units.trigger_8dec("0.25", eth) == 30_000_000 and units.trigger_8dec(0.2499, eth) == 20_000_000
    assert units.leverage_bps("2.00005") == 20_000 and units.leverage_bps("2.00015") == 20_002
