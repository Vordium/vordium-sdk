# Changelog

## 1.4.2
- Signing works on a chain that started with the current signing rules already in force: an activation listed at
  height 0 is accepted.
- `vordium.mm`: the module notes now match the API — a 400 is only a malformed batch (`invalid_body`, `batch_size`);
  `unknown_order` and `insufficient_balance` arrive per action inside the 202, and a refused action never takes the
  rest of the batch with it. No code change: `batch()` already read them per action.

