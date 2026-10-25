# Changelog

## 1.4.9
- No private key is ever printed. `Agent()` with no key makes a new key held only in memory and exposes its address
  (save it with `agent.save(path)`); `vordium init` writes the new key to a key file (`--out PATH`, default
  `~/.vordium/<address>.key`) and prints only the address and the path; `vordium balance` needs an address and never
  makes a key; `vordium send` and the interactive terminal take `--key-file PATH` or `VORDIUM_PRIVATE_KEY` and never
  make a key.
- Key files are written with mode 0600 in one step and never overwritten (`Wallet.save`, `Agent.save`); a folder the
  SDK creates for them is 0700. `Wallet.load`, `Agent(key_file=...)` and `SessionSigner.from_keystore` refuse a plain
  key file that other users can read. `Wallet.save` returns the path and prints nothing.
- New `KeyFileError`.

## 1.4.8
- Every order is put on its market's tick and lot before it is signed: `Vordex.place_order`, `Operator.place_order` and
  `build_place_body`, `MarketMaker.batch` and `modify`, take-profit / stop-loss (`set_tpsl`) and TWAP orders
  (`AccountOps.place_twap`). The rules come from the node's `GET /markets/specs` (or a read passed as `specs=`).
- Prices and sizes are converted exactly: a number is read from its decimal form (int, str, Decimal, or a float's
  shortest decimal form) and never multiplied as a float.
- A buy's limit price rounds down and a sell's up onto the tick (never a worse price than asked); a trigger price goes
  to the nearest tick; a size rounds down onto the lot (never more than asked); a TWAP's total size rounds down to a whole
  number of lots per slice and its price band never widens.
- Refused before signing (`OrderValueError`): a size that rounds to 0 or is below the market's smallest size, a limit
  order below the network's smallest order value, a market the network does not list, and an order whose market rules
  cannot be read (`SpecsUnavailable`).
- New `vordium.units` (the conversion and rounding rules) and `mm.PairSpec.min_size_18dec` / `min_notional_6dec`.
  `MarketMaker.modify` takes the order's `pair_id` and `side`, or reads them from the account's open orders.

## 1.4.7
- New `vordium.account_ops`: an account's session key (`create_session`, `revoke_session`), TWAP orders (`place_twap`,
  `cancel_twap`, with the route and limits read from the network spec) and margin mode (`set_margin_mode`, cross or
  isolated per market). Each is signed with the account's own key under the node's genesis-bound domain, and returns
  `applied=True` only once the chain's own read shows the change.
- Agent refusals in plain words: `agent_ops.agent_refusals(agent)` lists what the chain refused for an agent (its
  `agent_refused` records), each with the reason key and the meaning the network publishes for it
  (`agents.refusalCodes` in the network spec; `refusal_meanings(spec)` reads them). A node that checks agent orders when
  it receives them answers `403` with code `agent_refused`: `mm.read_answer` reports that refusal with its reason and
  meaning.

## 1.4.6
- The README and docstrings describe the agent operations the chain applies: `RegisterAgentV2`, `SetAgentName`,
  `SetAgentPolicyV1`, `SetAgentMarketLimit`, `ClearAgentLock` and `RevokeAgent`. The `SetAgentCaps` / `SetAgentMode`
  digests and the `RegisterAgent` / `SetAgentPolicy` types stay only for the published vectors; the chain does not apply
  them. No behaviour changes.

## 1.4.5
- Connections are reused: every call goes through one pooled HTTP session per thread instead of opening a new
  connection each time.
- Reads (GET) are retried up to twice on a dropped connection, a timeout, or HTTP 429/502/503/504, after a random wait
  that grows with each try and is never shorter than the server's `Retry-After`. Writes (POST: orders, cancels,
  transfers) are sent once and never retried by the SDK — a timed-out write may still have landed.
- `feeds.Feeds`: the reconnect wait resets only after a connection has delivered a message (a server that drops every
  connection at once is retried less and less often); each wait is randomised between half and all of the backoff; a
  frame or message over 16 MiB is refused; a message split across a read timeout is kept; a malformed message is skipped
  instead of ending the stream; unsubscribing a book drops its state.

## 1.4.4
- Stop orders are not available on the chain, and the SDK refuses them: `Vordex.place_order`,
  `Operator.place_order`, `Operator.build_place_body` and `dex.place_order_body` raise `dex.OrderNotAvailable` (a
  `ValueError`) for a stop order type or a non-zero trigger price or direction, before anything is signed or sent.
  `Operator.place_stop_order` raises the same error; set a take-profit or stop-loss on the position with
  `Operator.set_tpsl`.
- `Vordex.balance` documents `free_balance`: what a new order can use as margin. Margin is isolated per position, and
  unrealized profit or loss is not part of it.

## 1.4.3
- The test network is a named setting: `use_network("testnet")`, `resolve_network(network="testnet")` or
  `VORDIUM_NETWORK=testnet`. Its JSON-RPC endpoint is https://rpc-testnet.vordium.com; its reads, orders and
  `/status` use the testnet's API base https://testnet.vordex.xyz/chain; its spec and release list are its own.
  The test network's spec must say it is a test network and name the genesis its node serves.
- The main network is unchanged (https://rpc.vordium.com). An address you pass (`rpc_url=`, `VORDIUM_RPC_URL`) still
  wins over either network's defaults.
- New: `api_base()`, `NETWORKS`, and `config.API_URL` (the base of the node's REST routes).

## 1.4.2
- Signing works on a chain that started with the current signing rules already in force: an activation listed at
  height 0 is accepted.
- `vordium.mm`: the module notes now match the API — a 400 is only a malformed batch (`invalid_body`, `batch_size`);
  `unknown_order` and `insufficient_balance` arrive per action inside the 202, and a refused action never takes the
  rest of the batch with it. No code change: `batch()` already read them per action.

