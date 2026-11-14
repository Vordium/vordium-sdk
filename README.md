# Vordium Python SDK

The AI Layer for crypto. `vordium` is the Python SDK for building AI agents that
read and trade on **Vordium Chain** — a Layer 1 whose perp DEX (Vordex) is a
central limit order book settled in consensus, chainId **101101**.

```bash
pip install vordium
```

## Why this SDK is safe to point at a live chain

- **Each named network is pinned.** The SDK carries the chain id and genesis sha256 of `mainnet` and `testnet`
  (`vordium.PINS`) and builds every signing domain from that pin. Before anything is signed, `eth_chainId`, the network
  spec and the node's `/status` must all report the pinned values; when one differs, reads still work (with a
  `PinWarning`) but nothing is signed (`PinMismatch`, naming the network, the expected and the reported values). A new
  genesis for a named network needs a new SDK release.
- **Transport is discovered.** RPC, explorer and the Arbitrum bridge are resolved at runtime from the network spec.
- **The deposit bridge is an allow-list of one.** The SDK accepts only the bridge address the live network spec
  names at the moment you ask, and refuses every other address — and every address when the spec cannot be read.
- **EIP-712 domains are genesis-bound.** The VordCore domain salt is derived from
  the live `genesis_sha256`; if the node can't tell the SDK its genesis, the SDK
  refuses to sign rather than emit a digest the chain will reject.

## Quick start (read-only)

```python
from vordium import Vordex

dex = Vordex()
for m in dex.markets():                 # live perp markets (ETH, BTC, …)
    print(m["symbol"], m["mark_price"])

book = dex.orderbook(1)                  # resting bids/asks for pair 1
print(dex.mark_price(1))                 # human mark price
```

## The test network

```python
from vordium import Vordex, use_network

use_network("testnet")                   # JSON-RPC https://rpc-testnet.vordium.com; reads and orders on the
dex = Vordex()                           # testnet's API base https://testnet.vordex.xyz/chain
```

`use_network("testnet")` (or `VORDIUM_NETWORK=testnet`) reads the test network's own spec, asks its JSON-RPC
endpoint for the chain id and its node for the genesis, and signs only when they equal the test network's pin. The main
network stays the default (https://rpc.vordium.com).

An address you pass yourself -- `rpc_url=` or `VORDIUM_RPC_URL` -- is used for transport, and must say which network it
serves:

```python
from vordium import Pin, resolve_network, set_network

set_network(resolve_network(rpc_url="https://node.example", network="mainnet"))   # held to the mainnet pin
set_network(resolve_network(rpc_url="https://node.example",                     # a network of your own
                            pin=Pin(chain_id=777001, genesis_sha256="<64 hex>")))
```

`VORDIUM_NETWORK`, or both `VORDIUM_CHAIN_ID` and `VORDIUM_GENESIS_SHA256`, do the same from the environment. An address
with no pin can be read, but nothing is signed for it (`UnpinnedNetwork`).

## Agents

An agent on Vordium is an account operated through a **session key** bounded
by opt-in, on-chain caps that the account sets. A session key can only ever do what the
native agent gate allows; it can never withdraw funds or change its own caps.

```python
import os
from vordium import Agent, Vordex

agent = Agent(os.environ["VORDIUM_PRIVATE_KEY"])   # never hardcode a key
print(agent.address, agent.balance)                # native VORD (authoritative /vord route)

dex = Vordex()
print(dex.balance(agent.address))                  # USDC collateral
print(dex.positions(agent.address))                # open perp positions
```

Order placement is EIP-712 signed with the session key. Agent write ops take effect
once agent trading is enabled for the account on-chain — reads work regardless, and
calls that aren't live yet return an "unavailable" result rather than inventing data.

## Deposit bridge

Deposits are made on Arbitrum, to the bridge the network spec names. Read it at the moment you use it, and check any
address you were given against it:

```python
from vordium import current_bridge, require_current_bridge, BridgeRefused

bridge = current_bridge()              # read from the live network spec now; raises BridgeRefused if it cannot be read
require_current_bridge(address)        # returns the address only if it is that bridge; raises BridgeRefused otherwise
```

`vordium.bridge_v4` builds deposits into the vault (from Arbitrum, or from Arc through Circle's CCTP) and withdrawals
to Arbitrum or Arc. Everything it needs is read from the chain's public bridge routes at the moment of use, and it refuses
before anything is signed when a read cannot be confirmed:

```python
from vordium import bridge_v4 as bridge

deployments = bridge.fetch_deployments()                   # the vault and its handler, as the network spec names them
v = bridge.deployment_check(bridge.fetch_vaults(), deployments)
gate = bridge.deposit_gate(v, 42161, deployments)           # deposits from Arbitrum: open right now?
check = bridge.deposit_check(v, 42161, 25_000_000)          # 25 USDC from Arbitrum: may it be built?
print(gate.state, check.ok, check.text)

nonce, why = bridge.fetch_next_nonce(account)               # withdrawals are signed by the account's own key
```

Deposits are open only when the read is recent, the vault the network spec names is listed and `depositsOpen` for the
source chain is `true`; otherwise `deposit_gate` says they are closed and nothing is built. Amounts are USDC base units
(6 decimals).

From Arc, the network fee is paid in USDC and Circle delivers the deposit to the vault, so nothing is needed on Arbitrum.
Arc refuses USDC transfers from or to an address on its blocklist; both helpers check that first:

```python
prepared = bridge.prepare_arc_deposit(address, 25_000_000, arc_rpc_url=ARC_RPC)
if prepared["ok"]:
    tx = bridge.send_arc_deposit(private_key, prepared, ARC_RPC)   # then follow it: bridge.arc_deposit_stage(...)
else:
    print(prepared["text"])

outcome, code, message = bridge.withdraw_to_arc(private_key, 10_000_000, arc_rpc_url=ARC_RPC)
```

## Signing formats and agent names

Every signature names this chain's genesis. The SDK reads the chain's release list, its genesis and the current height
live before it signs, and refuses to sign when it cannot confirm the format the chain accepts:

```python
from vordium import read_signing_phase, registration, rename, sign_owner_op

phase = read_signing_phase()          # read it right before signing
op, value = registration(owner, agent, "strategy: Grid", expires_ms, nonce, phase, name="Grid bot")
body = sign_owner_op(owner_key, op, value)   # RegisterAgentV2: the on-chain name is required
```

Agent names follow the chain's rule: 3–32 ASCII characters (`A-Z a-z 0-9 space - _ .`), no reserved words such as
"vordium" or "admin"; `prepare_name()` normalises and checks one (the reason given is the chain's first failing step,
and `refusal_step()` names it), and `agent_display_name()` renders `<name> · 0xAbCd…1234`.

### Agent policies

An account sets what its agent may do with `SetAgentPolicyV1`, and clears a risk lock with `ClearAgentLock`. The chain
drops a policy it refuses without saying so, so the SDK checks the stateless rules first:

```python
from vordium import PolicyV1, set_policy, clear_lock, sign_owner_op, policy_problems

op, value = set_policy(owner, agent, policy, nonce, phase, now_ms)     # raises, naming every reason, if the chain would drop it
body = sign_owner_op(owner_key, op, value)
op, value = clear_lock(owner, agent, lock_since_ms, nonce, phase)     # clears only the lock that began at lock_since_ms
```

An agent may tighten its own policy (never loosen it) with `set_policy(..., stored=current, signer="agent")` and
`sign_agent_policy(agent_key, value)`.

### Pool and staking

Deposits, withdrawals, staking, unstaking and claims are messages the account key signs; a session key is refused on
all of them except a claim:

```python
from vordium import sign_money_op
from vordium.money import to_units

body = sign_money_op(owner_key, "VlpDeposit", {"user": owner, "amount_6dec": to_units("25", 6), "nonce": nonce},
                     chain_id, phase)     # POST it to /vlp/deposit
```

## Market makers

```python
from vordium import MarketMaker, Feeds, Mmp, next_mmp_nonce
from vordium import mm

maker = MarketMaker("https://rpc.example", private_key, owner_address)   # owner key or a live session key
spec = mm.pair_specs(maker.specs())[1]                                  # tick, lot, margins, liquidation fee

bid, ask = maker.nonce(), maker.nonce()                        # the account's one nonce clock (also used by KeepAlive)
r = maker.batch([
    mm.place(1, "buy",  mm.round_size(size_18dec, spec), mm.round_price(bid_price_8dec, spec, "buy"), bid, post_only=True),
    mm.place(1, "sell", mm.round_size(size_18dec, spec), mm.round_price(ask_price_8dec, spec, "sell"), ask, post_only=True),
])
for a in r.actions:
    print(a.index, "accepted" if a.accepted else a.refusal.message)

maker.batch([mm.cancel_by_client_nonce(bid)])                  # or mm.cancel(order_id)
maker.cancel_all(1)                                            # 0 = every pair
orders, positions = maker.open_orders(), maker.positions()
maker.set_mmp(Mmp(window_ms=60_000, max_fills=20, freeze_ms=15_000),
              next_mmp_nonce(maker.account()))

feed = Feeds("wss://rpc.example/feeds")
feed.subscribe("book", pair=1)
feed.subscribe("orders", account=owner_address)
for kind, msg in feed.events():         # snapshot, update, resubscribed (after a missed message), reconnected
    ...
```

Every write is signed under a pin, and the node it is sent to must report that pin's chain id and genesis (its
`/status`). The pin is the one of `network=` on the client (a resolved network, `"mainnet"`, `"testnet"` or a `Pin`),
else of `set_network()`, else of `VORDIUM_NETWORK` or `VORDIUM_CHAIN_ID` + `VORDIUM_GENESIS_SHA256`, else of the named
network whose address the client posts to. When the node serves another network, nothing is signed and `PinMismatch`
(a `NetworkMismatch`) is raised; a node at another address with no pin raises `UnpinnedNetwork`.

A 202 answer means the request was accepted for the next block; read the result from your orders, fills or the feeds.
Prices are 8-decimal integers, sizes 18-decimal integers and USDC amounts 6-decimal integers.

## Builder codes

An app or bot that sends orders for traders (a *builder*) can add its own fee to those orders, up to what each trader
approved. Fees are in cbps, hundredths of a basis point: 1,000 cbps = 0.1 %, 500 cbps = 5 bps = 0.05 %. The network
publishes its limits in its reads: the fee cap per market kind (`caps_cbps` in `stats()`), the most builders an account
may approve (`max` in `approvals()`), and the account value a builder needs for orders that name it to be accepted
(`min_account_value_6dec`, with `account_value_ok`).

```python
from vordium import BuilderOps, Vordex

trader = BuilderOps(trader_key)                     # signed with the account's own key
trader.approve_builder_fee(builder_address, 500)    # let the builder charge up to 5 bps
trader.approvals()                                  # {"approvals": [{"builder", "max_fee_cbps"}], "count", "max", "active", ...}

dex = Vordex()
dex.place_order(key, trader.owner, 1, 0, "0.01", "1700", order_type=1,
                builder={"address": builder_address, "fee_cbps": 500})
dex.place_order(key, trader.owner, 1, 0, "0.01", None, order_type=0,      # a market order with a worst price
                builder={"address": builder_address, "fee_cbps": 500}, worst_price="1950")

trader.revoke_builder_fee(builder_address)          # an approval of 0

me = BuilderOps(builder_key)                        # as the builder
me.stats()                                          # volume, fees = unclaimed + claimed, users in 30 days, caps
me.claim_builder_fees()                             # move unclaimed fees to the builder's balance
```

Before anything is signed the SDK reads the network: builder fees must be active (`active` in the builder reads),
the fee above 0 and within the cap (`caps_cbps`), the builder approved at or above the fee, its account value enough, and the builder
not the trader. Otherwise `BuilderError` is raised with the network's code (for example `builder_fee_above_cap`,
`builder_not_approved`, `builder_too_small`) and a sentence saying what to do; `BuilderNotActive` when builder fees are
not active. An order without `builder` is signed exactly as before. An order with one is signed as `PlaceOrderV3`
(65-byte signature, a deadline 120 seconds ahead). A market order with a builder takes `worst_price`: it is put on
the market's price step so it is never worse than given (a buy's rounds down, a sell's up) and signed as both the
slippage cap and the worst price; the network refuses the order (`slippage`, `worst_price`) when the market is already
past it. Without `worst_price` a builder market order has no price limit. Writes return a `Result` whose `applied` is true only once the
chain's own read shows the change.

The fee a fill charged is in that fill's record, under its `builder` key (`taker_builder`, `taker_fee_6dec`,
`maker_builder`, `maker_fee_6dec`; the key is absent when no builder fee was charged), and the builder's totals in its
stats read.

`trader.referral_level()` reads the account's referral level (`L1`, `L2` or `PARTNER`), its fee share and its
referees' discount, its progress in the current 30-day period toward L2, and whether its own volume meets the referrer
minimum; `trader.referral_tiers()` reads the table and its rules.

## CLI

```bash
vordium init                          # new key in ~/.vordium/<address>.key (mode 0600)
vordium init --out ./agent.key        # or a path you choose; an existing file is never overwritten
vordium balance 0x…                   # read the native VORD balance of an address
vordium send 0x… 1.5 --key-file ./agent.key
```

The SDK and the CLI never print a private key. `vordium init` prints only the new address and the key file's path.
A key file is written once with mode 0600; a key file that other users can read is refused when it is loaded.
In Python, `Agent(key_file=...)` or `Wallet.load(path)` read one, and `agent.save(path)` writes one. `Agent()` with no
key makes a new key held only in memory; save it before you fund its address.

## Units (do not mix)

| context            | price          | size           |
|--------------------|----------------|----------------|
| signed order (EIP-712 / POST) | uint64, 8 decimals | uint128, 18 decimals |
| read endpoints (`/oracle/*`)  | 1e6 integers / floats | — |

Each market has a price step (tick) and a size step (lot), published in `GET /markets/specs`; the chain does not apply
an order that is off them. Every order the SDK signs is put on them first (`vordium.units`): numbers are read exactly
from their decimal form (a float is never multiplied), a buy's limit price rounds down and a sell's up (never a worse
price than asked), a take-profit or stop-loss trigger goes to the nearest tick, and a size rounds down onto the lot
(never more than asked). A size that rounds to 0, a size below the market's smallest size, or a limit order below the
network's smallest order value raises `OrderValueError` before anything is signed.

```python
from vordium import Vordex, units

vx = Vordex()                                     # reads the market rules from the node for each order
vx.place_order(session_key, owner, 1, 0, "0.01234", "2420.57")    # signed as 0.0123 at 2420.5 on a 0.1 tick, 0.0001 lot
spec = vx.pair_spec(1)
units.price_8dec("2420.57", spec, "buy"), units.size_18dec(0.01234, spec)
```

## Links

- RPC: https://rpc.vordium.com
- Testnet RPC: https://rpc-testnet.vordium.com (test tokens have no value)
- Docs: https://docs.vordium.com
- Explorer: https://vordscan.io
- Source: https://github.com/Vordium/vordium-sdk

## License

MIT

## Genesis-bound EIP-712 domains (mainnet genesis `2c1c0679…`)
Every Vordium signing domain binds its `salt` to the chain's genesis sha256, so a signature made for
one genesis never verifies on another chain with the same chainId. The SDK builds the domains from the network's pin
(`vordium.PINS`) once the node's `/status.genesis_sha256` equals it; at the mainnet genesis the two used for trading are
VordCore `0x68b86fee…` and VordexSession `0x519818aa…` (`vordium.domains.verify_against_node()` derives them from a live
node to compare).
