"""Read-only: list live perp markets, an order book, and a mark price.

No key required — every call here is a public read against rpc.vordium.com.
    python examples/read_markets.py
"""
from vordium import Vordex

dex = Vordex()
markets = dex.markets()
for m in markets:
    print(f"pair {m['pair_id']:>2}  {m['symbol']:<6}  mark={m['mark_price']}")

first = markets[0]
book = dex.orderbook(first["pair_id"])
print(f"\n{first['symbol']} top of book:")
print("  bids:", book["bids"][:3])
print("  asks:", book["asks"][:3])

print(f"\n{first['symbol']} mark price:", dex.mark_price(first["pair_id"]))
