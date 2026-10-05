# Changelog

## 1.4.0
- `vordium.mm`, for market makers: `MarketMaker.batch()` signs up to 50 actions in one request (place, cancel by order
  id, cancel by client nonce; cancels apply first) and reports each action as accepted or, with the chain's reason, not
  accepted; `cancel_all(pair_id)` (0 = every pair); `modify()` replaces an order with a new one at the new price and size
  (a new order id carrying the client nonce you give; nothing changes if the new order would not rest); `set_mmp()` sets
  Market Maker Protection (0 switches a limit off, all zero switches it off; `next_mmp_nonce()` reads the nonce to use);
  `specs()`, `account()` and `activity()` read the market specs, the account's order limits and request allowance, and
  its recent activity. Order types: limit (good till cancelled), post-only, IOC, FOK and market. Every refusal has a
  plain message: `rate_limited`, `rate_burst`, `min_notional`, `too_many_open_orders`, `unknown_order`,
  `insufficient_balance`, `bad_signature`, `not_active`, `mempool_full` (with the time to retry) and `price_band` (the
  price is too far from the mark price). `NonceClock` gives rising millisecond nonces. `pair_specs()`, `on_tick()` and
  `on_lot()` check a price and size against a pair's tick and lot size.
- `vordium.feeds`: the book, trades, orders and fills feeds over one WebSocket. Each subscription starts with a snapshot;
  `SeqTracker` checks every update's `prev_seq` and a missed message makes `Feeds` subscribe again; `Book` keeps a pair's
  levels (a size of 0 removes one). Reconnects with back-off and resubscribes everything; a quiet feed is pinged, not
  dropped. Standard library only.
- The node's genesis is read from `/status` under the RPC URL's own path first, so a node served below a path works.
- `Operator.modify_order` calls `MarketMaker.modify`.
