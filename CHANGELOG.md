# Changelog

## 1.7.0
- When the answer to a write is lost (a timeout, a dropped connection, a gateway error, or a resent copy answered with
  the nonce code), its outcome is read from the node the write was sent to, never from an explorer: committed state
  first (the account's orders, an agent's record, the session and signers reads), then the node's own records for a
  refusal and for filled versus cancelled. Reads come every second for 10 s, every 2 s to 30 s, then every 5 s, each
  with a 6 s limit; a failed read counts as "not shown yet". Two minutes after the send an outcome nobody has shown is
  `still_unknown`, never refused.
- New `vordium.outcome`: `Outcome` (`action`, `state` = `pending_checking` / `applied` / `applied_other` / `refused` /
  `not_applied` / `still_unknown`, one plain sentence in `text`, the next action in `next`, `applied` True / False /
  None, `refusal`, the deciding `read` with route, height and time, `resend`, `attempts`, `digest`) and `PendingWrite`
  (`check()`, `wait()`, `resend_same()`). The words come from one shared word file shipped as `vordium/outcome_words.json`.
- Behaviour change: `Vordex.place_order` and `Vordex.cancel_order` wait up to `settle_s` seconds (default 30; 0 returns
  at once) for that outcome inside the call, and their answers carry `outcome` and, while it is not final, `pending`. A
  lost order answers `status` "unknown" (`delivery_unknown`), "received",
  "refused" or "not_applied". `DeliveryUnknown` is raised only when no copy left this computer (`never_sent`).
- `not_applied` is said only with proof: a write with a signed deadline (an order with a builder fee, the stop) whose
  deadline passed on the network's clock while a full read of the account's records, with no snapshot gap inside it,
  shows nothing. An order without a deadline is never called not applied.
- `MarketMaker.cancel_all` reads the open orders first; it and `MarketMaker.batch` are still never sent again after a
  lost answer, and now read the outcome for up to `settle_s` seconds: a cancel-all is applied only when none of the
  orders listed before is still listed, each has its closing record and at least one closed as cancelled; a batch when
  each placed order shows by its client nonce and each cancelled one (by id or by client nonce) is gone with its
  closing record. `Submitted` gains `outcome` and `pending`.
- A refusal is read only from a record of the same signer and market that does not name the nonce: an answer or record
  naming the nonce may be about a later copy while an earlier one applied. `not_applied` also needs the node's records
  to be written up to the head read just before them.
- New owner writes: `AccountOps.revoke_agent(agent)` (RevokeAgent, its nonce above the chain's mark for that agent; an
  agent already revoked is not signed for) and `AccountOps.stop_all()` (StopAllSigners, one signature that stops the
  account's trading key and every agent, with a deadline 120 s after block time, or after this computer's clock when block time cannot
  be read; nothing is signed where the network says it does not take it). Both send the same bytes again on a lost answer and are applied only when the node's reads show
  the effect. `Result` gains `outcome` and `pending`.
- A write sent through the SDK is noted, before it is sent, in a journal next to the nonce marks
  (`outcome-pending.json`, file mode 0600) and taken off once its outcome is known. `vordium.pending()` lists what is
  still open (for a day), and `vordium.pending(check=True)` reads each once at the node it was sent to.

- The signed release record: each SDK release ships, per chain id, the lowest record sequence it accepts
  (`vordium.release_record.MIN_SEQUENCE`, set when the release is made; 0 = none). An older record is refused also on a
  computer that has read none, and a floor above 0 counts as a record already seen.
- The highest record sequence seen is shared with the JavaScript SDK in the same state folder: each reads both marks and
  is held to the higher, and writes its own.
- A record that cannot be used raises `RecordUnavailable` (a `PinMismatch`) with `record_code` (`expired`, `rollback`,
  `not_served`, `unsigned`, `bad_signature`, `not_listed`, …); a network named only by its chain id raises
  `UnpinnedNetwork` with `record_code`. Each refusal says "Nothing was signed" once; an expired record adds "Try again
  later; if this persists, check this computer's clock." When no record could be read and the node's genesis differs
  from the SDK's own pin, the refusal says that the signed record could not be read.

## 1.6.2
- A network's identity comes from the signed release record. `releases.json` (at
  `https://binaries.vordium.com/<network>/releases.json`, and for the main network also `https://rpc.vordium.com/releases.json`)
  names, for each network, its chain id, genesis sha256 and deposit bridge (vault, handler, USDC and their chain), with the
  record's sequence, issue time and expiry, and the geneses it lists in `retired_genesis`. It is used only when its detached OpenPGP signature
  (`releases.json.asc`, over the exact bytes served) verifies under the release key shipped in the SDK, fingerprint
  `C5EB4728F660369CE519D834B48FB4B71EFD48AE`. The SDK verifies the signature itself: ASCII armour and its CRC-24, the
  version 4 signature packet, its hashed subpackets and issuer fingerprint, and Ed25519 (RFC 8032), with no new
  dependency and no other program (`vordium.release_record`).
- The release key is pinned by its fingerprint. Its expiry is read from its own self-signature (the shipped key expires
  2028-09-11). From 30 days before that expiry, the key is read again from where it is served (`KEY_URLS`: the
  `release-key.asc` of github.com/Vordium/security and the `pub_key.asc` of github.com/Vordium/node), on every record read and at most every six hours (every 30 seconds while the key it has is
  expired); a read that fails never takes back a later expiry. A
  served copy is used only when it is the same key (same fingerprint and point) with a newer self-signature that verifies
  under it, and only for its expiry; a revocation that verifies under the key refuses every record. A copy that cannot be read,
  is another key or is older is skipped. A record is refused once the key has expired and no served copy gives a later
  expiry, and so is a key with no self-signature that verifies. The record, its signature and the key are read no further
  than their size limits.
- A record is refused, with a plain sentence, when it is unsigned, its signature does not verify, it is signed by another
  key, it has expired, its sequence is lower than the highest one seen on this computer for that network (kept next to
  the nonce marks, file mode 0600), or it does not list the network. A node whose genesis the record lists in
  `retired_genesis`, or does not name for the network, is never signed for. Values are read only from the verified bytes.
- When the record is served, its genesis is the network's pin, so a new genesis listed in it needs no new SDK release.
  While no record is served, the pins in `vordium.PINS` apply as before. Once a record for a network has been read on a
  computer, signing for that network waits until a record is served again.
- Signing and the deposit bridge use the record as it is at that moment: it is read again after five minutes
  (`RECORD_TTL_S`), at once when it has expired, and a refused record is read again after 30 seconds (`RECORD_RETRY_S`).
- With a record, the deposit bridge comes from it alone: `current_bridge()`, `require_current_bridge()`,
  `bridge_v4.fetch_deployments()` and the deposit builders do not read the bridge from a network spec, and the vaults read
  must name the record's USDC.
- `resolve_network(network=<chain id>, rpc_url=...)` names a network that only the signed record lists. Clients given a
  network name (`"mainnet"`, `VORDIUM_NETWORK`, or a named network's address) also take the record's genesis.

## 1.6.1
- Redirects are never followed. A 3xx answer to a read, a signed write or the signing-phase read raises
  `RedirectRefused`, is not read as data and is not sent again. Web3 calls (balances, transfers) do not follow
  redirects either and raise the same `RedirectRefused`.
- Sizes, prices and leverage take an int, a str, a Decimal or a float (a float is read from its shortest decimal
  form). Whole-number fields that are signed as they are (ids, nonces, times, and the raw 18- and 8-decimal integers
  the digest helpers take) take an int, a string of digits or a Decimal with a whole value; a float or a fractional
  value is refused (`ValueError`). Numbers are read with the digits 0-9 only; digits of other scripts are refused
  (`OrderValueError` / `ValueError`).
- Every signed whole number must fit its field (for example a pair id in 32 bits, a client nonce or an order id in 64
  bits); a value past it is refused before signing.
- An address is 40 hex characters, with or without 0x. Written in mixed case it must carry its EIP-55 checksum; an
  all-lower-case or all-upper-case address is taken as written. This applies to owners, session keys, agents, builders, money operations and withdrawal destinations.
- Market rules that list markets but do not name the smallest order value (`min_order_notional_6dec`) are refused
  (`SpecsUnavailable`).
- A network spec named only by `VORDIUM_SPEC_URL` does not name the deposit bridge on its own: `current_bridge()`,
  `fetch_deployments()`, `prepare_arc_deposit()`, `prepare_withdraw_to_arc()` and `withdraw_to_arc()` refuse it
  (`BridgeRefused`, or `{"ok": False}`) unless the caller passes `expected_bridge=` with the address it has checked,
  which the spec must then name.

## 1.6.0
- Builder codes. `BuilderOps` (signed with the account's own key): `approve_builder_fee(builder, max_fee_cbps)`,
  `revoke_builder_fee(builder)` (an approval of 0), `claim_builder_fees()` for a builder, and the reads `approvals()`,
  `stats()`, `referral_stats()`, `referral_level()` and `referral_tiers()`. `Vordex` gains `builder_approvals()`,
  `builder_stats()`, `referral_stats()` and `referral_tiers()`.
- `Vordex.place_order(..., builder={"address": ..., "fee_cbps": ...})` signs the order as `PlaceOrderV3` with the
  builder and its fee. A market order with a builder takes `worst_price` (on the price step, never worse than given),
  signed as both the slippage cap and the worst price. Without `builder` an order is signed exactly as before.
- Fees are in cbps (1,000 cbps = 0.1 %). Before signing, the SDK checks the network's builder reads: the rule is active
  (`active`), the fee is above 0 and within the market's cap (`caps_cbps`), the builder is approved at or above the
  fee, its account value is enough (`account_value_ok`, `min_account_value_6dec`), and it is not the trader. A
  refusal raises `BuilderError` with the network's code and what to do; `BuilderNotActive` when builder fees are not
  active. Nothing is signed then.
- `vordium.builder` holds the type strings, typehashes, digests and request bodies (`ApproveBuilderFee`,
  `ClaimBuilderFees`, `PlaceOrderV3`), checked against the network's published vectors in the tests.
- `referral_level()` returns the level fields (`level`, `share_bps`, `discount_bps`, `l2_progress`, `next_check_ms`,
  `own_volume_6dec`, `min_own_volume_6dec`, `meets_min`, `limits`, `referee_volume_6dec`), or None where the network
  does not show levels.

## 1.4.10
- Each named network carries its pin in the SDK: `mainnet` chain 101101, genesis
  `2c1c0679fa6ab8358f1d3e8d294a8d1c73ac2e2caf9079f1216abedc3d9fdf4f`; `testnet` chain 101102, genesis
  `8b5d414c5cd5d18bc468b64f87ac8e2c2b5ff494c769d5e09dcf50ce75a59792` (`vordium.PINS`, `vordium.Pin`).
- Every signature (orders, cancels, sessions, agent operations, TWAP, margin mode, the dead-man switch, withdrawals,
  money and referral messages, VORD transfers) is made under the pin. Before signing, the SDK compares the pin with
  `eth_chainId`, the network spec and the node's `/status`; when any differs it raises `PinMismatch` with the network,
  the expected and the reported values, and nothing is signed. Reads still work and issue a `PinWarning`.
- The EIP-712 salt is derived from the pinned genesis.
- An address of your own (`rpc_url=`, `VORDIUM_RPC_URL`) must name its network (`network="mainnet"` or `"testnet"`) or
  carry an explicit pin (`pin=Pin(chain_id, genesis_sha256)`, or both `VORDIUM_CHAIN_ID` and `VORDIUM_GENESIS_SHA256`).
  Without one it can be read, but nothing is signed for it (`UnpinnedNetwork`). Clients posting to a node accept
  `network="mainnet"`, `"testnet"` or a `Pin`. A named network's own address counts as naming it. `VORDIUM_CHAIN_ID`
  alone is not a pin: with an address of your own, set `VORDIUM_GENESIS_SHA256` too, or nothing is signed.
- A new genesis for a named network takes a new SDK release with the new pin.
- New `signing_pin()`, `PinMismatch`, `UnpinnedNetwork`, `PinWarning`.
- One nonce allocator per account and nonce space (`vordium.nonces.NonceAllocator`; `nonce_clock(owner)` returns the
  account's one in the `orders` space). Nonces are `max(last + 1, now in ms)`: strictly rising across threads and
  processes on one machine (a file lock around a mark kept in `VORDIUM_STATE_DIR`, else `~/.vordium/nonces`; folder
  0700, files 0600), never back when the clock goes back, and never reused after a restart. Orders, batches,
  cancel-all, modify, the dead-man switch and TWAP orders share the `orders` space; session keys and margin mode use
  the `account` space.
- Before a nonce is used it is checked against the window the network accepts (a client nonce within 2 days before
  and 1 day after block time; other nonces at most 1 day ahead): against the network's block time when the client can
  read it (`ChainClock`: one short read at most every 5 minutes, never holding up other writes), else against this
  computer's clock (no network set, `chain_clock=None`, or a network whose block time cannot be read). Outside it,
  `ClockOutOfWindow` says how far the clock is off and nothing is signed.
- A stored mark left far ahead of the clock (outside the window) does not stop orders: client nonces continue from
  the clock, with a `NonceStateWarning` (the network refuses a nonce it already holds). For session, agent and margin
  nonces, which must rise, the error names the mark's file and when it is safe to delete it.
- A write is signed once and never signed again with a new nonce. For a write the network applies once per nonce (an
  order, a TWAP order, a session key, a cancel), a timeout, a lost connection or HTTP 429/502/503/504 sends the same
  signed body again (up to 3 copies). A write it does not deduplicate (cancel-all, a batch, a modify, a take-profit /
  stop-loss, margin mode) is sent again only when the first copy never left this machine; otherwise the answer says it
  is unknown whether it arrived (`MarketMaker`: `Submitted(ok=False, unknown=True)`; `Operator`: `status: "unknown"`)
  and nothing is sent twice.
- When a copy may have reached the network (its answer was lost, or a gateway answered 502/503/504) and the final
  answer is not a 2xx (a refusal such as insufficient margin, the nonce code, a 5xx), that answer is never reported as
  a refusal: the write is read back, else it is unknown. A 5xx on a write the network does not deduplicate is always
  unknown, and `MarketMaker` reads any 5xx without a code as `delivery_unknown`, never as refused.
- After a stored mark is set back to the clock, a client nonce may repeat one handed out before; an order found with
  it then counts as this write's only when the network's record is newer than the set-back (the set-back's time is the
  network's block time when it is known, else this computer's clock).
- A cancel whose earlier copy may have arrived is read back from the account's resting orders and records: gone with
  a cancel record answers `status: "done"`; gone with a fill record answers `status: "filled"` (the order filled
  before the cancel: check the position); gone with no record, still resting, or unreadable answers `status:
  "unknown"`. Never a plain refusal (`Vordex.cancel_order`, `Operator.cancel_order`).
- A write that could not reach the network on any try (the connection could not be made) is reported as not sent:
  `DeliveryUnknown.never_sent`, `AccountOps` `applied=False` ("nothing was sent"), `MarketMaker` refusal `not_sent`,
  `status: "not_sent"` for cancels and `Operator`.
- `AccountOps` results say `applied=None` when the write may have been received (submitted, or its answer was lost) and
  the chain's read has not shown it within the wait; `applied=False` only when the network refused it. A TWAP also
  counts as placed when the account's TWAP records show it ended.
- A refused or unreachable connection counts as "never sent" only when it happened while the connection was being
  made (urllib3's NewConnectionError, a name lookup failure, a connect timeout); otherwise the copy may have arrived.
- The network answers a used nonce, a nonce outside the window and a nonce used by another signer with one code, so
  that answer alone never counts as success. After a resent copy is answered with it, `Vordex.place_order` reads the
  order back by its client nonce and compares the signed market, side and size (its original size when the
  record shows one) or limit price: a match answers
  `status: "received"`, `already_received: True` with `found`; anything else answers `status: "unknown"`,
  `delivery_unknown: True` (read the account's orders before sending a new one). Neither carries an HTTP status. When
  no copy is answered, `DeliveryUnknown` is raised unless the read-back finds the order. A nonce answer to the first
  copy is a refusal.
- `Vordex.place_order` answers carry `clientNonce` and `attempts`; `Vordex.order_by_client_nonce(owner, n, signed)`
  reads an order back by its client nonce and, with `signed`, only an order that carries those values. A TWAP counts
  as placed only when the chain lists its client nonce with the signed market, side and size. `Operator.place_order`
  takes its client nonce from the account's allocator when none is given.
- New `vordium.nonces` (`NonceAllocator`, `ChainClock`, `ClockOutOfWindow`, `DeliveryUnknown`, `send_same`), and
  `vordium.dex.matches_signed`.

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

