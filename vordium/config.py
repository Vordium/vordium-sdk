"""Protocol constants + runtime-resolved network accessors for Vordium.

The per-deployment network identity — chainId, rpc/ws/explorer, the Arbitrum
bridge — is not hardcoded here. It is discovered at runtime by
:mod:`vordium.network` (canonical spec -> eth_chainId -> raise).

``config.CHAIN_ID`` / ``CHAIN_ID_HEX`` / ``CHAIN_NAME`` / ``RPC_URL`` / ``WS_URL``
/ ``EXPLORER_URL`` resolve LAZILY through the live network on attribute access
(never at import). ``ARBITRUM_BRIDGE`` is read from the live network spec on every
access, and ``require_current_bridge(addr)`` accepts only that address. Override a deployment coherently via env (VORDIUM_CHAIN_ID +
VORDIUM_RPC_URL), not by editing a constant here.
"""

import os

from .network import BridgeRefused, current_bridge, get_network, require_current_bridge  # noqa: F401

NATIVE_TOKEN = "VORD"
NATIVE_DECIMALS = 18

# ---------------------------------------------------------------------------
# Genesis predeploys (native ops, not EVM bytecode).
#
# These are native VordCore addresses. ``eth_getCode`` on them returns "0x" --
# that is expected and is NOT evidence they are missing. They are reached
# through the REST engine and through EIP-712 signed ops, not through Solidity
# ABI calls.
# ---------------------------------------------------------------------------
PERP_ENGINE = "0x0000000000000000000000000000000000001000"
ASSISTANCE_FUND = "0x0000000000000000000000000000000000001001"
VAULT = "0x0000000000000000000000000000000000001002"
FEE_CONFIG = "0x0000000000000000000000000000000000001003"
BUYBACK_ENGINE = "0x0000000000000000000000000000000000001004"
BRIDGE = "0x0000000000000000000000000000000000001007"
USDC_ADDRESS = "0x000000000000000000000000000000000000100a"
INSURANCE_FUND = "0x000000000000000000000000000000000000100b"
REFERRAL_REGISTRY = "0x000000000000000000000000000000000000100e"

#: EIP-712 ``verifyingContract`` for signed user ops (see ``vordium.eip712``).
VERIFYING_CONTRACT = VAULT

# ---------------------------------------------------------------------------
# Agents are NOT a registry contract.
#
# An agent on Vordium is not a deployed contract and not a registered record --
# it is an account operated through a session key with opt-in caps that the
# account sets. Agent authority is granted by signing ``SetAgentCaps`` /
# ``SetAgentMode`` (see ``vordium.eip712``), not by calling a registry.
# ---------------------------------------------------------------------------
AGENT_MODEL = "native-session-keys"

# ---------------------------------------------------------------------------
# Arbitrum bridge (deposits are made on Arbitrum, not on Vordium).
# ARBITRUM_BRIDGE is NOT hardcoded — it is read from the live network spec on
# every access (vordium.network.current_bridge). The SDK accepts that one address
# and nothing else: require_current_bridge(addr) raises BridgeRefused for any
# other address, and for every address when the spec cannot be read.
# ---------------------------------------------------------------------------
ARBITRUM_CHAIN_ID = 42161  # Arbitrum One's own chainId (external, constant)
ARBITRUM_USDC = "0xaf88d065e77c8cC2239327C5EDb3A432268e5831"  # native USDC on Arbitrum


# --- Lazy accessors — resolve through the live network --------------------------
# (Never at import: these fire only when the attribute is actually read.)
_NETWORK_ATTRS = {
    "CHAIN_ID": lambda n: n.chain_id,
    "CHAIN_ID_HEX": lambda n: n.chain_id_hex,
    "CHAIN_NAME": lambda n: n.chain_name,
    "RPC_URL": lambda n: n.rpc_url,
    "API_URL": lambda n: (n.api_url or n.rpc_url).rstrip("/"),
    "WS_URL": lambda n: n.ws_url,
    "EXPLORER_URL": lambda n: n.explorer_url,
}


def __getattr__(name: str):
    if name in _NETWORK_ATTRS:
        return _NETWORK_ATTRS[name](get_network())
    if name == "ARBITRUM_BRIDGE":
        return current_bridge()  # read live on every access; raises BridgeRefused when it cannot be confirmed
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def native_balance(address: str) -> float:
    """Authoritative native VORD balance of ``address``, in whole VORD.

    Native VORD lives in VordCore state, not the EVM account trie. The chain
    serves the authoritative figure at ``GET {rpc}/vord/balance/{addr}`` ->
    ``{"data": {"balance": "<wei>"}}``. (``eth_getBalance`` mirrors it today,
    but the REST route is the source of truth and never depends on the mirror.)
    """
    import requests
    from .network import get_network
    net = get_network()
    addr = address if address.startswith("0x") else "0x" + address
    r = requests.get(f"{(net.api_url or net.rpc_url).rstrip('/')}/vord/balance/{addr.lower()}", timeout=15)
    r.raise_for_status()
    return int(r.json()["data"]["balance"]) / 10 ** NATIVE_DECIMALS
