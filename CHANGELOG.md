# Changelog

## 1.3.0
- `vordium.bridge_v4`: deposits into the bridge vault on Arbitrum — from Arbitrum, or from Arc through Circle's CCTP — and
  withdrawals to Arbitrum or Arc. The vault, its handler, the minimums and what is open are read from the chain's public bridge
  routes; a deposit or withdrawal is refused before anything is signed when a read cannot be confirmed.
- Deposits are offered only when the vaults read is recent, the deployed vault is listed and `depositsOpen` for the
  source chain is `true` (`deposit_gate`). The vault and its handler are read from the network spec
  (`fetch_deployments`); a vaults read naming any other is not used.
- Withdrawals: an intent signed by the account's own key with a deadline, the next nonce read from the chain, the
  outcome read back afterwards; a ready payout can be sent by the user (`self_send_from_call`).
- A deposit that is not accepted is claimed back on Arbitrum by the address it is owed to (`refund_claim`).
- Every message, encoding and wording is checked against the bridge's test vectors.
- `vordium.schedule_cancel`, the dead-man switch: the chain cancels all of an account's open orders and TWAPs at a time
  T it set, and refuses its new orders from T, unless the client keeps moving T forward. `submit` (set or refresh),
  `clear` (T = 0), `get_state` (the committed state, with the chain's own limits and whether the switch is active on
  the network), and `KeepAlive`, which arms T = now + lead on every `refresh()` with a rising nonce and never inside the
  chain's minimum interval; `alive` turns false on any refresh that is not accepted for submission. Signatures are 65
  bytes (`r||s||v`). The digests match the chain's published vectors.
- `vordium.bridge_v4`: Arc as a deposit source and a payout destination. `prepare_arc_deposit` runs every check and builds
  a Circle-forwarded deposit (approve, then the burn with the forwarding header and your address as the beneficiary;
  Circle's protocol and forwarding fee inside the maximum fee), refusing an address Arc's USDC blocklists;
  `send_arc_deposit` sends it from your key through your Arc RPC (the network fee is paid in USDC on Arc) and
  `arc_deposit_stage` follows it: sent on Arc, confirmed by Circle, credited on Vordium. `prepare_withdraw_to_arc` /
  `withdraw_to_arc` withdraw to the same address on Arc through the vault's forwarded route, with Circle's fee from its
  quote. Withdrawal rows carry their `destination_domain`.

## 1.2.0
- The deposit bridge is an allow-list of one: `current_bridge()` reads the address the live network spec names at the
  moment of the call, and `require_current_bridge(address)` returns an address only when it is that one. Any other
  address raises `BridgeRefused`, and so does every address when the spec cannot be read. `config.ARBITRUM_BRIDGE`
  reads the spec on every access. The bridge is never taken from the environment.
- `vordium.names` checks a name in the chain's own step order (NonAscii, ControlChar, BadChar, TooShort / TooLong,
  NotCanonical, NoAlphanumeric, Reserved), so when a name breaks several rules the reason given is the chain's;
  `refusal_step()` names the step.
- `vordium.rollb` reads the activation height `H` from `releases.json`, the genesis from the network spec (refused if it
  disagrees with the node's `/status`) and the current height, and signs only in the format the chain expects.
- `vordium.agent_ops`: `registration()` / `rename()` / `set_policy()` / `clear_lock()` build the agent ops;
  `submit_body()` / `sign_owner_op()` produce the `POST /submit` body; an agent may sign only a tightening of its
  stored policy (`set_policy(..., signer="agent")`, `sign_agent_policy()`).
- `vordium.policy`, `vordium.money`, `vordium.referral`: the stateless policy rules, the pool and staking messages
  (account key; a session key only for a claim), and the referral messages.
- Every digest, 65-byte signature, `/submit` body and POST body is checked against the chain's test vectors.
