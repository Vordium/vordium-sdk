# Changelog

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

