# Changelog

## 1.4.1
- Every signed write is bound to the node it is sent to: `MarketMaker`, `schedule_cancel.submit`, `KeepAlive` and
  `Vordex` read the chain id and genesis from that node's `/status` and sign under its domain. When a network is
  configured (a `network` given to the client, `set_network()`, or the `VORDIUM_CHAIN_ID` / `VORDIUM_GENESIS_SHA256`
  settings) and the node serves another, nothing is signed and `NetworkMismatch` is raised. A `domain_separator` given
  to a client must equal the node's own. A node that starts serving another chain is refused, not followed.
  `Operator` checks that the node it posts to serves the network it signs for before it signs.
- One nonce clock per account: `nonce_clock(owner)` is shared by batches, cancels, modifies, single orders and the
  dead-man switch (`KeepAlive` takes the same clock and starts above the nonce the chain holds).
- `round_price(price_8dec, spec, side)` (bids down, asks up) and `round_size(size_18dec, spec)` (down) put a price and
  size on a pair's tick and lot; a pair without a tick or lot leaves the value unchanged.
- `MarketMaker.open_orders()` and `MarketMaker.positions()` read the account's resting orders and open positions
  (`OpenOrder`, `Position`; sizes as exact integers at any size).
