"""Runtime network resolution — the SINGLE source of the network identity.

The SDK does NOT carry a copy of the chain parameters: a copied value can go
stale, a resolved one cannot.

Two DIFFERENT trust rules, because the two kinds of value fail differently:

  TRANSPORT — rpc, ws, explorer, bridge address, native currency.
      Derived from the canonical spec (``VORDIUM_SPEC_URL`` or
      https://rpc.vordium.com/network-spec.json). A bad transport value
      fails LOUDLY and HARMLESSLY: a bad RPC just won't connect.

  SIGNING DOMAIN — the EIP-712 ``chainId``.
      A mismatched signing chainId is dangerous: it yields a VALID signature on
      ANOTHER chain (an attacker who controls the spec/RPC could harvest
      signatures valid elsewhere). So the chainId is NOT taken from any single
      source. It is resolved by AGREEMENT: every available source —
        * ``eth_chainId`` from the RPC you are actually sending to,
        * the spec's ``chainId``,
        * a user-pinned ``VORDIUM_CHAIN_ID`` (if set),
      must be present-and-equal. ANY disagreement is a HARD FAILURE: the SDK
      refuses to sign and reports each source's value. A pin is honoured as one
      of the sources that must agree, never as an override that skips the check.
      If NO source is available, it raises — never a baked constant.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Dict, Optional

import requests

# The endpoints we ASK — never an assumed chainId (chainId is always agreed).
DEFAULT_SPEC_URL = "https://rpc.vordium.com/network-spec.json"
DEFAULT_RPC_URL = "https://rpc.vordium.com"

# The named networks: where the SDK ASKS on each. ``rpc`` is the JSON-RPC endpoint (eth_* calls); ``api`` the base of
# the node's REST routes (/status, orders, sessions, reads; None = the same host as ``rpc``); ``releases`` the chain's
# release list (None = ``{api}/releases.json``). Select one with ``network=`` on resolve_network() / use_network(), or
# with VORDIUM_NETWORK. An address the caller passes (``rpc_url=``, VORDIUM_RPC_URL) always wins over these.
NETWORKS: Dict[str, Dict[str, Optional[str]]] = {
    "mainnet": {"spec": DEFAULT_SPEC_URL, "rpc": DEFAULT_RPC_URL, "api": None, "releases": None},
    "testnet": {"spec": "https://testnet.vordex.xyz/network-spec.json",
                "rpc": "https://rpc-testnet.vordium.com",
                "api": "https://testnet.vordex.xyz/chain",
                "releases": "https://testnet.vordex.xyz/releases.json"},
}

# Protocol constants (the same on every deployment): the native predeploy
# layout + the VordCore EIP-712 domain name/version are part of the protocol,
# not the per-deployment identity. verifyingContract is the VAULT predeploy.
VERIFYING_CONTRACT = "0x0000000000000000000000000000000000001002"
EIP712_DOMAIN_NAME = "VordCore"
EIP712_DOMAIN_VERSION = "1"
NATIVE_SYMBOL = "VORD"
NATIVE_DECIMALS = 18

class NetworkResolutionError(RuntimeError):
    """The network identity could not be discovered. Deliberately fatal — the
    SDK refuses to sign against an assumed chain."""


class ChainIdDisagreement(NetworkResolutionError):
    """Two or more chainId sources disagreed. Refusing to sign, because a
    mismatched signing domain produces a valid signature on another chain."""


class NetworkMismatch(NetworkResolutionError):
    """The node a client posts to serves another network than the one configured (or than it signed for before).
    Nothing is signed."""


class BridgeRefused(NetworkResolutionError):
    """The deposit bridge could not be confirmed: the address is not the one the live network spec publishes, or
    the spec could not be read. Nothing should be sent."""


@dataclass(frozen=True)
class Network:
    """A fully-resolved network identity. Every signing/endpoint value the SDK
    uses comes from ONE of these — there is no other definition anywhere.
    ``chain_id`` is the AGREED signing chainId; ``chain_id_sources`` records
    which sources were consulted and what each returned."""
    chain_id: int
    chain_id_hex: str
    chain_name: str
    rpc_url: str
    ws_url: Optional[str]
    explorer_url: Optional[str]
    bridge_address: Optional[str]
    bridge_chain: Optional[str]
    bridge_chain_id: Optional[int]
    native_symbol: str
    native_decimals: int
    verifying_contract: str
    source: str  # how transport was obtained: "spec" | "env" | "spec-unreachable"
    chain_id_sources: Dict[str, int] = field(default_factory=dict)
    # The live genesis sha256 (from the node's /status). The VordCore/VordexSession EIP-712
    # domains bind their salt to THIS. None ⇒ the salted domain cannot be built ⇒ sign refused.
    genesis_sha256: Optional[str] = None
    # Which named network this is ("mainnet", "testnet"; None for a network built by hand).
    name: Optional[str] = None
    # The base of the node's REST routes when it is not the JSON-RPC host (None ⇒ ``rpc_url``). See api_base().
    api_url: Optional[str] = None
    # Where this network's spec and release list are read (None ⇒ the defaults: the main network's spec,
    # ``{api}/releases.json``).
    spec_url: Optional[str] = None
    releases_url: Optional[str] = None


def api_base(net: "Network") -> str:
    """The base URL of the node's REST routes for ``net`` (no trailing slash): ``api_url`` when the network names
    one, else the JSON-RPC host."""
    return (net.api_url or net.rpc_url).rstrip("/")


def _preset(name: str) -> Dict[str, Optional[str]]:
    p = NETWORKS.get(str(name).strip().lower())
    if p is None:
        raise NetworkResolutionError(f"unknown network {name!r}; known: {', '.join(sorted(NETWORKS))}")
    return p


def _http_json(url: str, timeout: float):
    # Use requests (an SDK dependency) — matches the rest of the SDK's HTTP
    # stack and its User-Agent, which CDNs in front of the endpoints accept.
    r = requests.get(url, headers={"accept": "application/json"}, timeout=timeout)
    r.raise_for_status()
    return r.json()


def _rpc(rpc_url: str, method: str, params, timeout: float):
    r = requests.post(rpc_url, json={"jsonrpc": "2.0", "id": 1, "method": method,
                                     "params": params or []}, timeout=timeout)
    r.raise_for_status()
    return r.json().get("result")


def _status_genesis_sha256(rpc_url: str, timeout: float) -> Optional[str]:
    """Resolve the live genesis sha256 from the node's /status: first under the RPC URL's own path (a node
    served below a path, e.g. ``https://host/chain``), then at the host root. ONE source of truth for the
    genesis-bound EIP-712 salt: it tracks the chain the node serves with no code change. Returns a 64-hex
    string or None (None ⇒ the SDK refuses to sign, never guesses)."""
    from urllib.parse import urlsplit, urlunsplit
    pr = urlsplit(rpc_url)
    candidates = [urlunsplit((pr.scheme or 'http', pr.netloc, pr.path.rstrip('/') + '/status', '', ''))]
    root = urlunsplit((pr.scheme or 'http', pr.netloc, '/status', '', ''))
    if root not in candidates:
        candidates.append(root)
    for status in candidates:
        try:
            j = _http_json(status, timeout)
            g = j.get('genesis_sha256') if isinstance(j, dict) else None
            if isinstance(g, str):
                g = g[2:] if g.startswith('0x') else g
                if len(g) == 64 and all(c in '0123456789abcdefABCDEF' for c in g):
                    return g.lower()
        except Exception:
            continue
    return None


def _hexid(chain_id: int) -> str:
    return "0x" + format(int(chain_id), "x")


def _fetch_spec(spec_url: str, timeout: float) -> Optional[dict]:
    try:
        return _http_json(spec_url, timeout)
    except Exception:
        return None


def _eth_chain_id(rpc_url: str, timeout: float) -> Optional[int]:
    try:
        res = _rpc(rpc_url, "eth_chainId", [], timeout)
        return int(res, 16) if res else None
    except Exception:
        return None


def _agree_chain_id(candidates: Dict[str, int]) -> int:
    """Return the single agreed chainId, or raise. ``candidates`` is
    {source_name: chain_id} for every AVAILABLE source."""
    present = {k: v for k, v in candidates.items() if v is not None}
    if not present:
        raise NetworkResolutionError(
            "could not determine chainId from any source (eth_chainId of the "
            "RPC, the spec, or a pinned VORDIUM_CHAIN_ID) — refusing to sign."
        )
    distinct = set(present.values())
    if len(distinct) > 1:
        detail = ", ".join(f"{k}={v}" for k, v in present.items())
        raise ChainIdDisagreement(
            f"chainId sources DISAGREE ({detail}). Refusing to sign — a "
            f"mismatched signing domain yields a valid signature on another "
            f"chain. Reconcile the sources (a stale spec, a repointed RPC, or a "
            f"mismatched VORDIUM_CHAIN_ID pin) before signing."
        )
    return present.popitem()[1]


def resolve_network(rpc_url: Optional[str] = None,
                    spec_url: Optional[str] = None,
                    timeout: float = 6.0,
                    network: Optional[str] = None) -> Network:
    """Discover transport from the spec; resolve the signing chainId by
    AGREEMENT across every available source. Never a baked constant, never a
    single trusted source for the signing domain.

    ``network`` names the network ("mainnet" — the default — or "testnet"; else VORDIUM_NETWORK). It chooses where
    the SDK asks (see NETWORKS); it never supplies a chain id. An explicit ``rpc_url`` (or VORDIUM_RPC_URL) still
    wins: that node is used for JSON-RPC and REST alike, as before."""
    env_chain = os.getenv("VORDIUM_CHAIN_ID")
    env_rpc = os.getenv("VORDIUM_RPC_URL")
    custom_rpc = rpc_url or env_rpc
    pin = int(env_chain, 0) if env_chain else None
    named = network or os.getenv("VORDIUM_NETWORK") or None
    name = str(named).strip().lower() if named else "mainnet"
    preset = _preset(name)

    if env_chain and not custom_rpc and not named:
        raise NetworkResolutionError(
            "VORDIUM_CHAIN_ID is set but VORDIUM_RPC_URL is not — an override "
            "must supply the whole network identity coherently. Set both, or "
            "unset VORDIUM_CHAIN_ID to discover from the spec."
        )

    spec_url = spec_url or os.getenv("VORDIUM_SPEC_URL") or preset["spec"]
    api_url: Optional[str] = None
    releases_url: Optional[str] = None
    spec_genesis: Optional[str] = None

    # --- transport ---------------------------------------------------------
    spec_chain_id: Optional[int] = None
    if custom_rpc:
        # A custom node: transport comes from env only — the canonical spec at
        # rpc.vordium.com does not describe someone else's node, so we do not
        # borrow its values. chainId is still cross-checked below (eth_chainId
        # of this node + any pin).
        rpc = custom_rpc
        ws = os.getenv("VORDIUM_WS_URL")
        explorer = os.getenv("VORDIUM_EXPLORER_URL")
        # The deposit bridge is never taken from the environment: only the live network spec names it
        # (see current_bridge()).
        bridge_addr = bridge_chain = bridge_cid = None
        native_sym = os.getenv("VORDIUM_NATIVE_SYMBOL", NATIVE_SYMBOL)
        native_dec = int(os.getenv("VORDIUM_NATIVE_DECIMALS", NATIVE_DECIMALS))
        chain_name = os.getenv("VORDIUM_CHAIN_NAME", "Vordium Chain")
        transport_source = "env"
    else:
        spec = _fetch_spec(spec_url, timeout)
        api_url, releases_url = preset["api"], preset["releases"]
        if spec and name == "testnet" and spec.get("testnet") is not True:
            raise NetworkResolutionError(
                f"the spec at {spec_url} does not describe a test network (its \"testnet\" is not true); "
                "refusing to resolve the test network from it."
            )
        if spec:
            if name == "testnet":
                g = spec.get("genesisSha256")
                spec_genesis = (g[2:] if g[:2] in ("0x", "0X") else g).lower() if isinstance(g, str) else None
            rpc = spec.get("rpc") or preset["rpc"]
            ws = spec.get("ws")
            explorer = spec.get("explorer")
            b = spec.get("bridge") or {}
            bridge_addr = _address(b.get("address"))
            bridge_chain = b.get("chain")
            bridge_cid = b.get("chainId")
            nc = spec.get("nativeCurrency") or {}
            native_sym = nc.get("symbol", NATIVE_SYMBOL)
            native_dec = int(nc.get("decimals", NATIVE_DECIMALS))
            chain_name = spec.get("chainName", "Vordium Testnet" if name == "testnet" else "Vordium Chain")
            spec_chain_id = int(spec["chainId"]) if spec.get("chainId") is not None else None
            transport_source = "spec"
        else:
            # spec unreachable → minimal transport; the RPC is still asked for
            # eth_chainId below so signing can proceed if the node answers.
            rpc = preset["rpc"]
            ws = explorer = bridge_addr = bridge_chain = bridge_cid = None
            native_sym, native_dec = NATIVE_SYMBOL, NATIVE_DECIMALS
            chain_name = "Vordium Testnet" if name == "testnet" else "Vordium Chain"
            transport_source = "spec-unreachable"

    # --- signing chainId: AGREEMENT across all available sources -----------
    onchain_cid = _eth_chain_id(rpc, timeout)  # the RPC we will actually send to
    candidates: Dict[str, int] = {}
    if onchain_cid is not None:
        candidates["eth_chainId"] = onchain_cid
    if spec_chain_id is not None:
        candidates["spec"] = spec_chain_id
    if pin is not None:
        candidates["pinned(VORDIUM_CHAIN_ID)"] = pin

    chain_id = _agree_chain_id(candidates)  # raises on disagreement / none

    genesis_sha256 = _status_genesis_sha256(api_url or rpc, timeout)
    if spec_genesis and genesis_sha256 and spec_genesis != genesis_sha256:
        raise NetworkResolutionError(
            f"the spec names genesis {spec_genesis[:8]}… but the node serves genesis {genesis_sha256[:8]}…; "
            "refusing to sign for either."
        )
    return Network(
        chain_id=chain_id,
        genesis_sha256=genesis_sha256,
        chain_id_hex=_hexid(chain_id),
        chain_name=chain_name,
        rpc_url=rpc,
        ws_url=ws,
        explorer_url=explorer,
        bridge_address=bridge_addr,
        bridge_chain=bridge_chain,
        bridge_chain_id=bridge_cid,
        native_symbol=native_sym,
        native_decimals=native_dec,
        verifying_contract=VERIFYING_CONTRACT,
        source=transport_source,
        chain_id_sources=dict(candidates),
        name=name,
        api_url=api_url,
        spec_url=spec_url,
        releases_url=releases_url,
    )


# --- the deposit bridge: an allow-list of one, read live ---------------------
def _address(v) -> Optional[str]:
    """``v`` as a lower-case 0x-prefixed 20-byte address, or None when it is not one."""
    if not isinstance(v, str):
        return None
    h = v[2:] if v[:2] in ("0x", "0X") else None
    if h is None or len(h) != 40 or any(c not in "0123456789abcdefABCDEF" for c in h):
        return None
    return "0x" + h.lower()


def current_bridge(spec_url: Optional[str] = None, timeout: float = 6.0) -> str:
    """The deposit bridge address, read from the live network spec at the moment of the call (never cached,
    never from the environment). Raises :class:`BridgeRefused` when the spec cannot be read or names no valid
    address."""
    url = spec_url or default_spec_url()
    spec = _fetch_spec(url, timeout)
    if not isinstance(spec, dict):
        raise BridgeRefused(f"the network spec could not be read ({url}); the deposit bridge cannot be confirmed, "
                            "so no address is returned.")
    addr = _address((spec.get("bridge") or {}).get("address"))
    if not addr:
        raise BridgeRefused("the network spec names no valid deposit bridge address; no address is returned.")
    return addr


def require_current_bridge(address: str, spec_url: Optional[str] = None, timeout: float = 6.0) -> str:
    """Return ``address`` (lower-case) only when it is the deposit bridge the live network spec names right now.
    Any other address — and any address at all when the spec cannot be read — raises :class:`BridgeRefused`."""
    given = _address(address)
    if not given:
        raise BridgeRefused(f"{address!r} is not an address; nothing should be sent to it.")
    current = current_bridge(spec_url, timeout)
    if given != current:
        raise BridgeRefused(f"{given} is not the deposit bridge the network spec names ({current}); "
                            "nothing should be sent to it.")
    return given


# --- process-wide resolved singleton ---------------------------------------
_current: Optional[Network] = None


def get_network() -> Network:
    """Return the resolved network, resolving once and caching. Every digest and
    endpoint reads through here, so there is exactly one live value in-process."""
    global _current
    if _current is None:
        _current = resolve_network()
    return _current


_explicit = False


def set_network(net: Network) -> None:
    """Inject a resolved network (explicit init / offline tests / air-gapped). A network set here is the CONFIGURED
    network: clients refuse to sign for a node that serves another one."""
    global _current, _explicit
    _current, _explicit = net, True


def explicit_network() -> Optional[Network]:
    """The network set with :func:`set_network`, or None when the caller has set none."""
    return _current if _explicit else None


def use_network(name: str, rpc_url: Optional[str] = None, timeout: float = 6.0) -> Network:
    """Resolve the named network ("mainnet" or "testnet") and set it as the configured network (see set_network).
    ``rpc_url`` — an address of your own — still wins. Returns the resolved network."""
    n = resolve_network(rpc_url=rpc_url, timeout=timeout, network=name)
    set_network(n)
    return n


def default_spec_url() -> str:
    """Where the network spec is read when no URL is given: VORDIUM_SPEC_URL, else the configured (or already
    resolved) network's own spec, else the spec of the network VORDIUM_NETWORK names, else the main network's."""
    env = os.getenv("VORDIUM_SPEC_URL")
    if env:
        return env
    if _current is not None and _current.spec_url:
        return _current.spec_url
    named = os.getenv("VORDIUM_NETWORK")
    if named:
        return _preset(named)["spec"]
    return DEFAULT_SPEC_URL


def releases_url(net: Network, rpc_url: Optional[str] = None) -> str:
    """The chain's release list for ``net``: ``{rpc_url}/releases.json`` when the caller names a node, else the
    network's own list, else ``{api}/releases.json``."""
    if rpc_url:
        return rpc_url.rstrip("/") + "/releases.json"
    return net.releases_url or (api_base(net) + "/releases.json")


def reset_network() -> None:
    """Drop the cached resolution (next access re-resolves)."""
    global _current, _explicit
    _current, _explicit = None, False
