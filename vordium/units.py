"""Exact order units: a price or size as the signed integer, on the market's tick and lot.

The chain keeps a tick (``tick_8dec``, the price step) and a lot (``lot_18dec``, the size step) per market, published in
``GET /markets/specs``. An order off its tick or lot is answered ``202`` and is NOT applied. Every order path of this SDK
therefore turns a number into the signed integer exactly and puts it on the market's step before anything is signed.

How a number is read
    An ``int`` as it is; a ``str`` or :class:`~decimal.Decimal` exactly; a ``float`` from its shortest decimal form
    (``0.1`` is 0.1, never 0.1000000000000000055…). Nothing is ever multiplied as a float. A string is a plain decimal
    (``"2420.5"``, ``".5"``, ``"1e-4"``); a sign, spaces, underscores, ``inf`` and ``nan`` are refused.

How it is put on the step (the rule every order path uses)
    * A limit price rounds TOWARD THE PASSIVE SIDE: a bid (buy) down, an ask (sell) up, onto the tick. A rounded order
      is never more aggressive than the one asked for: a buy never pays more, a sell never takes less. On ``/order/place``
      the price is also kept at the 6 decimals the intake reads (the step is the tick and a multiple of 100).
    * A take-profit / stop-loss trigger rounds to the NEAREST tick (a half tick rounds up).
    * A size rounds DOWN onto the lot: never more than asked.
    * A tick or lot of 0 means the network sets none: then only the signed unit applies (8 or 18 decimals; a limit
      price on ``/order/place`` still at 6 decimals).

Refused before anything is signed (:class:`OrderValueError`)
    a size that rounds to 0 or below the market's ``min_size_18dec``; a limit price that rounds to 0; a priced order
    whose notional is below ``min_order_notional_6dec``; a market the network does not list; a specs read that fails
    (:class:`SpecsUnavailable`).
"""

from __future__ import annotations

import re
from decimal import Decimal, InvalidOperation
from typing import Any, Callable, Dict, Optional, Tuple

PRICE_DECIMALS = 8
SIZE_DECIMALS = 18
USDC_DECIMALS = 6
#: The intake keeps 6 decimals of a ``/order/place`` price: a signed 8-decimal price there is a multiple of 100.
PLACE_PRICE_STEP_8DEC = 100

_U64 = (1 << 64) - 1
_U128 = (1 << 128) - 1
_PLAIN = re.compile(r"^(?:\d+\.?\d*|\.\d+)(?:[eE][+-]?\d+)?$")


class OrderValueError(ValueError):
    """A price or size the chain would not apply. Raised before anything is signed or sent."""


class SpecsUnavailable(OrderValueError):
    """The market rules (``GET /markets/specs``) could not be read, so no order value can be put on its step."""


# --- reading a number ------------------------------------------------------------------------------------------

def decimal_of(x: Any, what: str = "a value") -> Decimal:
    """``x`` as an exact :class:`~decimal.Decimal`: an int, a plain decimal string, a Decimal, or a float read from its
    shortest decimal form. Refuses booleans, negatives, non-finite values and anything else."""
    if isinstance(x, bool):
        raise OrderValueError(f"{what} is not a number ({x!r})")
    if isinstance(x, int):
        d = Decimal(x)
    elif isinstance(x, float):
        if x != x or x in (float("inf"), float("-inf")):
            raise OrderValueError(f"{what} is not a finite number ({x!r})")
        d = Decimal(repr(x))
    elif isinstance(x, Decimal):
        d = x
    elif isinstance(x, str):
        if not _PLAIN.match(x):
            raise OrderValueError(f"{what} is not a plain decimal number ({x!r})")
        try:
            d = Decimal(x)
        except InvalidOperation:
            raise OrderValueError(f"{what} is not a plain decimal number ({x!r})") from None
    else:
        raise OrderValueError(f"{what} is not a number ({x!r})")
    if not d.is_finite():
        raise OrderValueError(f"{what} is not a finite number ({x!r})")
    if d < 0:
        raise OrderValueError(f"{what} cannot be negative ({x!r})")
    return d


def scaled(x: Any, decimals: int, what: str = "a value") -> Tuple[int, int]:
    """``x`` × 10^``decimals`` as an exact fraction ``(numerator, denominator)``, denominator > 0."""
    n, d = decimal_of(x, what).as_integer_ratio()
    return n * 10 ** decimals, d


def whole(x: Any, what: str = "a value") -> int:
    """A count of base units (an 8- or 18-decimal integer): an int, a digit string, or an integral Decimal/float."""
    n, d = scaled(x, 0, what)
    if n % d:
        raise OrderValueError(f"{what} is a count of base units and must be a whole number ({x!r})")
    return n // d


def _lcm(a: int, b: int) -> int:
    from math import gcd

    return a * b // gcd(a, b)


def on_step(num: int, den: int, step: int, mode: str) -> int:
    """The fraction ``num/den`` onto a multiple of ``step``: ``down``, ``up`` or ``nearest`` (a half step rounds up)."""
    if step <= 0:
        raise ValueError("a step is at least 1")
    q, r = divmod(num, den * step)          # num/den = (q + r/(den·step)) · step, 0 ≤ r < den·step
    if r == 0 or mode == "down":
        return q * step
    if mode == "up":
        return (q + 1) * step
    if mode == "nearest":
        return (q + 1) * step if 2 * r >= den * step else q * step
    raise ValueError(f"mode is down, up or nearest, not {mode!r}")


def _side(side: Any) -> str:
    if side in ("buy", 0):
        return "buy"
    if side in ("sell", 1):
        return "sell"
    raise OrderValueError(f"side is buy or sell, not {side!r}")


def price_step(spec: Any, place_route: bool = True) -> int:
    """The step a signed 8-decimal limit price must be a multiple of: the market's tick, and on ``/order/place`` also a
    multiple of 100 (the intake keeps 6 decimals)."""
    tick = int(getattr(spec, "tick_8dec", 0) or 0) if spec is not None else 0
    base = PLACE_PRICE_STEP_8DEC if place_route else 1
    return _lcm(tick, base) if tick > 0 else base


def size_step(spec: Any) -> int:
    lot = int(getattr(spec, "lot_18dec", 0) or 0) if spec is not None else 0
    return lot if lot > 0 else 1


# --- order values ----------------------------------------------------------------------------------------------

def price_8dec(price: Any, spec: Any, side: Any, place_route: bool = True) -> int:
    """A limit price (a number in quote currency) as the signed 8-decimal integer on the market's tick: a bid rounds
    down, an ask up. Refuses a price that rounds to 0."""
    n, d = scaled(price, PRICE_DECIMALS, "a limit price")
    out = on_step(n, d, price_step(spec, place_route), "down" if _side(side) == "buy" else "up")
    if out <= 0:
        raise OrderValueError(f"the limit price {price!r} rounds to 0 on this market's tick")
    if out > _U64:
        raise OrderValueError("the limit price is out of range")
    return out


def size_18dec(size: Any, spec: Any) -> int:
    """A size (a number of base units of the market) as the signed 18-decimal integer, down onto the lot."""
    n, d = scaled(size, SIZE_DECIMALS, "a size")
    return check_size(on_step(n, d, size_step(spec), "down"), spec, size)


def trigger_8dec(price: Any, spec: Any) -> int:
    """A take-profit / stop-loss trigger price as the 8-decimal integer, to the nearest tick (0 = no trigger)."""
    n, d = scaled(price, PRICE_DECIMALS, "a trigger price")
    if n == 0:
        return 0
    out = on_step(n, d, price_step(spec, False), "nearest")
    if out <= 0:
        raise OrderValueError(f"the trigger price {price!r} rounds to 0 on this market's tick")
    if out > _U64:
        raise OrderValueError("the trigger price is out of range")
    return out


def snap_price_8dec(price8: Any, spec: Any, side: Any, place_route: bool = False) -> int:
    """A signed 8-decimal price already in base units, onto the tick by the passive rule (0 stays 0: no price)."""
    p = whole(price8, "price_8dec")
    if p == 0:
        return 0
    out = on_step(p, 1, price_step(spec, place_route), "down" if _side(side) == "buy" else "up")
    if out <= 0:
        raise OrderValueError(f"the price {p} rounds to 0 on this market's tick")
    if out > _U64:
        raise OrderValueError("the price is out of range")
    return out


def snap_size_18dec(size18: Any, spec: Any) -> int:
    """A signed 18-decimal size already in base units, down onto the lot."""
    s = whole(size18, "size_18dec")
    return check_size(s - s % size_step(spec), spec, size18)


def snap_trigger_8dec(price8: Any, spec: Any) -> int:
    p = whole(price8, "trigger price")
    if p == 0:
        return 0
    out = on_step(p, 1, price_step(spec, False), "nearest")
    if out <= 0:
        raise OrderValueError(f"the trigger price {p} rounds to 0 on this market's tick")
    if out > _U64:
        raise OrderValueError("the trigger price is out of range")
    return out


def check_size(size18: int, spec: Any, asked: Any = None) -> int:
    if size18 <= 0:
        lot = size_step(spec)
        raise OrderValueError(f"the size {asked!r} rounds to 0 on this market's lot ({lot} base units)"
                              if lot > 1 else f"the size {asked!r} is below one base unit")
    if size18 > _U128:
        raise OrderValueError("the size is out of range")
    minimum = int(getattr(spec, "min_size_18dec", 0) or 0) if spec is not None else 0
    if minimum and size18 < minimum:
        raise OrderValueError(f"the size is below this market's smallest order ({minimum} base units)")
    return size18


def notional_6dec(size18: int, price8: int) -> int:
    """size × price in USDC base units (6 decimals), rounded down."""
    return size18 * price8 // 10 ** (SIZE_DECIMALS + PRICE_DECIMALS - USDC_DECIMALS)


def check_notional(size18: int, price8: int, spec: Any) -> None:
    """Refuse a priced order whose value is below the network's smallest order value."""
    minimum = int(getattr(spec, "min_notional_6dec", 0) or 0) if spec is not None else 0
    if minimum and price8 and notional_6dec(size18, price8) < minimum:
        raise OrderValueError(f"the order's value is below the smallest order the network takes "
                              f"({minimum / 10 ** USDC_DECIMALS:g} USDC)")


def leverage_bps(leverage: Any) -> int:
    """Leverage (``2`` or ``"2.5"``) as basis points, exactly (10x = 100000)."""
    n, d = scaled(leverage, 4, "leverage")
    q, r = divmod(n, d)
    return q + (1 if 2 * r > d or (2 * r == d and q % 2) else 0)      # half to even, like round()


# --- the market rules ------------------------------------------------------------------------------------------

class _NoRules:
    """Every market without a tick, lot or minimum: for dry runs and offline tests. Never what a network publishes."""

    def __repr__(self) -> str:
        return "NO_RULES"


#: Market rules that put no step on anything (only the signed units apply). Pass as ``specs=`` for a dry run.
NO_RULES = _NoRules()


def specs_by_pair(specs: Any) -> Dict[int, Any]:
    """A ``/markets/specs`` read (or an already parsed ``{pair_id: PairSpec}``) as ``{pair_id: PairSpec}``."""
    from .mm import PairSpec, pair_specs

    if isinstance(specs, dict) and specs and all(isinstance(v, PairSpec) for v in specs.values()):
        return specs
    if isinstance(specs, dict) and "specs" in specs:
        return pair_specs(specs)
    raise SpecsUnavailable("the market rules are not a /markets/specs read")


def select(specs: Any, pair_id: int) -> Any:
    """One market's rules from a specs read; a market the read does not list is refused."""
    if isinstance(specs, _NoRules):
        from .mm import PairSpec

        return PairSpec(int(pair_id), str(pair_id), 0, 0, None, None)
    by = specs_by_pair(specs)
    if int(pair_id) not in by:
        raise OrderValueError(f"the network lists no market {pair_id} (GET /markets/specs)")
    return by[int(pair_id)]


def fetch_specs(base_url: str, timeout: float = 10.0, get: Optional[Callable[[str], Any]] = None) -> Dict[str, Any]:
    """``GET {base_url}/markets/specs`` (or ``get("/markets/specs")``)."""
    try:
        if get is not None:
            j = get("/markets/specs")
        else:
            from . import _http

            r = _http.get(f"{base_url.rstrip('/')}/markets/specs", timeout=timeout)
            r.raise_for_status()
            j = r.json()
    except Exception as e:  # noqa: BLE001
        raise SpecsUnavailable(f"the market rules could not be read ({type(e).__name__}); nothing was signed") from None
    if not isinstance(j, dict) or not isinstance(j.get("specs"), dict):
        raise SpecsUnavailable("the market rules read has no specs; nothing was signed")
    return j


def pair_spec_for(base_url: str, pair_id: int, timeout: float = 10.0, get: Optional[Callable[[str], Any]] = None) -> Any:
    """The market's rules, read from the node now (never cached)."""
    return select(fetch_specs(base_url, timeout, get), pair_id)


def resolve(specs: Any, base_url: str, pair_id: int, timeout: float = 10.0,
            get: Optional[Callable[[str], Any]] = None) -> Any:
    """The rules a client uses: from the ``specs`` it was given, else read from its node."""
    if specs is not None:
        return select(specs, pair_id)
    return pair_spec_for(base_url, pair_id, timeout, get)
