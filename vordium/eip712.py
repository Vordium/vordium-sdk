"""EIP-712 signing for VordCore user ops (orders, cancels, agent caps, TP/SL).

The chain verifies every
browser/agent-signable op over an EIP-712 digest under one shared app domain.
This module is a faithful Python port of the app-side signer.

The domain and typed structs are NOT declared here — they are loaded verbatim
from ``eip712.json``, which carries the same domain and typed structs as the web
app's copy and is pinned by the chain's own test vectors. Never hand-edit the
field set: reordering or renaming a field silently changes the digest and the
chain will reject the signature.

CANONICAL UNITS -- ``value`` must carry ON-CHAIN INTEGER fields, not human
decimals:
  * price / triggerPrice8dec : uint64, 8-dec   ($30      -> 3_000_000_000)
  * size                     : uint128, 18-dec (1 unit   -> 10**18)
  * leverageBps              : uint32          (1x       -> 10_000)

For order and session ops the chain consumes a 64-byte ``r||s`` signature (the
recovery id ``v`` is brute-forced chain-side), so the trailing ``v`` byte is
stripped here. The four agent owner ops (``AGENT_OPS``) are signed in their
published 65-byte ``r||s||v`` format instead — see ``sign_agent_op``.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict

from eth_account import Account
from eth_account.messages import encode_typed_data
from eth_utils import keccak

from .network import get_network, NetworkResolutionError
from .caps import _vordcore_salt

_CFG = json.loads((Path(__file__).parent / "eip712.json").read_text())

# Only the TYPE STRUCTS (field order/names/solidity types) come from the JSON —
# they are protocol-structural and checked against the chain's test vectors. The
# domain's chainId and salt are RESOLVED AT RUNTIME (vordium.network); the JSON
# carries no chainId or separator, so the signing domain always follows the live chain.
_DOMAIN_STATIC: Dict[str, Any] = _CFG["domain"]  # used only for name + version
TYPES: Dict[str, Any] = _CFG["types"]


def domain() -> Dict[str, Any]:
    """The EIP-712 domain, with chainId + verifyingContract from the resolved
    live network (name/version are protocol constants)."""
    net = get_network()
    if not getattr(net, "genesis_sha256", None):
        raise NetworkResolutionError(
            "genesis_sha256 unavailable from the node's /status — cannot build the genesis-bound "
            "VordCore EIP-712 domain. The SDK refuses to sign rather than emit a rejected domain."
        )
    return {
        "name": _DOMAIN_STATIC["name"],
        "version": _DOMAIN_STATIC["version"],
        "chainId": net.chain_id,
        "verifyingContract": net.verifying_contract,
        # The canonical 5th field; keccak(VORDIUM_VORDCORE\x01 || genesis_sha256).
        # eth_account.encode_typed_data adds `bytes32 salt` to EIP712Domain automatically when present.
        "salt": _vordcore_salt(net.genesis_sha256),
    }


def _signable(primary_type: str, value: Dict[str, Any]):
    if primary_type not in TYPES:
        raise KeyError(
            f"unknown op {primary_type!r}; pinned ops are {sorted(TYPES)}"
        )
    return encode_typed_data(
        domain_data=domain(),
        message_types={primary_type: TYPES[primary_type]},
        message_data=value,
    )


def __getattr__(name: str):
    # ``DOMAIN`` / ``DOMAIN_SEPARATOR`` are runtime values, resolved on attribute access.
    if name == "DOMAIN":
        return domain()
    if name == "DOMAIN_SEPARATOR":
        m = _signable("CancelOrder", {"owner": "0x" + "00" * 20, "orderId": 0})
        return "0x" + m.header.hex()
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def digest(primary_type: str, value: Dict[str, Any]) -> str:
    """Return the EIP-712 digest for ``primary_type`` as a 0x-hex string.

    digest = keccak(0x19 0x01 || domainSeparator || hashStruct(message))
    """
    m = _signable(primary_type, value)
    return "0x" + keccak(b"\x19\x01" + m.header + m.body).hex()


#: The four agent-management owner operations. Their published signature format
#: (vectors/agent-ops-vectors-2c1c0679.json in Vordium/node) is 65 bytes
#: ``r||s||v`` with v = 27/28, over the raw EIP-712 digest.
AGENT_OPS = ("RegisterAgent", "RevokeAgent", "SetAgentPolicy", "SetAgentMarketLimit")
#: The agent operations from the activation height (ops 129, 130, 132, 133): same 65-byte
#: format, valid only from the activation height (see vordium.agent_ops / vordium.rollb).
ROLLB_AGENT_OPS = ("RegisterAgentV2", "SetAgentName", "SetAgentPolicyV1", "ClearAgentLock")


def sign_agent_op(private_key: str, primary_type: str, value: Dict[str, Any]) -> str:
    """Sign an agent owner op (AGENT_OPS or ROLLB_AGENT_OPS), returning the published 65-byte
    ``r||s||v`` 0x-hex signature (v = 27/28). ``private_key`` is the OWNER key."""
    if primary_type not in AGENT_OPS + ROLLB_AGENT_OPS:
        raise ValueError(
            f"{primary_type!r} is not an agent owner op ({', '.join(AGENT_OPS + ROLLB_AGENT_OPS)}); use sign_op"
        )
    signed = Account.sign_message(
        _signable(primary_type, value), private_key=private_key
    )
    return "0x" + signed.signature.hex().removeprefix("0x")


def sign_op(private_key: str, primary_type: str, value: Dict[str, Any]) -> str:
    """Sign a pinned VordCore op and return its 0x-hex signature.

    Order, cancel, TWAP, transfer, TP/SL and agent-cap/mode ops: 64-byte
    ``r||s`` (the chain brute-forces the recovery id). The four agent owner ops
    in ``AGENT_OPS``: the published 65-byte ``r||s||v`` (see ``sign_agent_op``).

    ``private_key`` is the SESSION key for order/cancel paths (the chain
    recovers the owner from an active session key), or the owner key for
    owner-authorised ops such as ``SetAgentCaps`` and the agent owner ops.
    """
    if primary_type in AGENT_OPS + ROLLB_AGENT_OPS:
        return sign_agent_op(private_key, primary_type, value)
    signed = Account.sign_message(
        _signable(primary_type, value), private_key=private_key
    )
    # Chain expects 64-byte r||s (v stripped; recovery id is brute-forced chain-side).
    return "0x" + signed.signature.hex().removeprefix("0x")[:128]