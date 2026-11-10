"""Runtime network resolution — the SINGLE source of the network identity.

The SDK does NOT carry a copy of the chain parameters: a copied value can go
stale, a resolved one cannot.

Two DIFFERENT trust rules, because the two kinds of value fail differently:

  TRANSPORT — rpc, ws, explorer, bridge address, native currency.
      Derived from the canonical spec (``VORDIUM_SPEC_URL`` or
      https://rpc.vordium.com/network-spec.json). A bad transport value
      fails LOUDLY and HARMLESSLY: a bad RPC just won't connect.

  SIGNING DOMAIN — the EIP-712 ``chainId`` and the genesis-bound ``salt``.
      A mismatched signing domain is dangerous: it yields a VALID signature on
      ANOTHER chain (an attacker who controls the spec/RPC could harvest
      signatures valid elsewhere). So every named network carries a PIN in the
      SDK (:mod:`vordium.pins`: its chain id and genesis sha256), and the domain
      is built from the pin. Every available source —
        * ``eth_chainId`` from the RPC you are actually sending to,
        * the spec's ``chainId`` and ``genesisSha256``,
        * the node's ``/status`` ``genesis_sha256``,
        * ``VORDIUM_CHAIN_ID`` / ``VORDIUM_GENESIS_SHA256`` (if set),
      must equal the pin. The chain id sources must also agree with each other
      (a disagreement is a HARD FAILURE, as before). When a read value differs
      from the pin, reads still work (with a :class:`PinWarning`) but nothing is
      signed (:class:`PinMismatch`). An endpoint of your own must say which
      network it serves (``network=``) or carry an explicit pin (``pin=``, or
      both environment values); without one it can be read, but nothing is
      signed for it (:class:`UnpinnedNetwork`).
"""

from __future__ import annotations

import os
import warnings
from dataclasses import dataclass, field
from typing import Dict, Optional, Union

import requests
from . import _http
from .pins import PINS, Pin, differences, normalize_genesis, refusal

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


class PinMismatch(NetworkMismatch):
    """The network reports a chain id or genesis other than the one it is pinned to. Nothing is signed."""


class UnpinnedNetwork(NetworkMismatch):
    """The endpoint is not a named network and carries no explicit pin. It can be read; nothing is signed for it."""


class PinWarning(UserWarning):
    """A read value differs from the network's pin. Reads continue; signing is refused."""


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
    # The pin this network is held to (vordium.pins). None for a network built by hand: then a named network's pin
    # applies, else the network's own chain_id + genesis_sha256 (the caller wrote them). See signing_pin().
    pin: Optional[Pin] = None
    # Why nothing may be signed for this network (a read value differs from the pin, or the endpoint has no pin).
    pin_problem: Optional[str] = None


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
    r = _http.get(url, headers={"accept": "application/json"}, timeout=timeout)
    r.raise_for_status()
    return r.json()


def _rpc(rpc_url: str, method: str, params, timeout: float):
    r = _http.post(rpc_url, json={"jsonrpc": "2.0", "id": 1, "method": method,
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


def _env_pin() -> "tuple[Optional[int], Optional[str]]":
    """``(VORDIUM_CHAIN_ID, VORDIUM_GENESIS_SHA256)`` as read from the environment (each None when unset)."""
    c = os.getenv("VORDIUM_CHAIN_ID")
    g = os.getenv("VORDIUM_GENESIS_SHA256")
    cid = int(c, 0) if c else None
    gen = None
    if g:
        gen = normalize_genesis(g)
        if gen is None:
            raise NetworkResolutionError("VORDIUM_GENESIS_SHA256 is not 64 hex characters")
    return cid, gen


def resolve_network(rpc_url: Optional[str] = None,
                    spec_url: Optional[str] = None,
                    timeout: float = 6.0,
                    network: Optional[str] = None,
                    pin: Optional[Union[Pin, str]] = None) -> Network:
    """Discover transport from the spec, resolve the chain id by AGREEMENT across every available source, and hold
    what the network reports to its pin.

    ``network`` names the network ("mainnet" — the default — or "testnet"; else VORDIUM_NETWORK). It chooses where
    the SDK asks (see NETWORKS) and the pin it is held to (:data:`vordium.pins.PINS`). An explicit ``rpc_url`` (or
    VORDIUM_RPC_URL) still wins for transport: that node is used for JSON-RPC and REST alike. Such an endpoint is
    held to the pin of the network you name, or to ``pin`` (a :class:`~vordium.pins.Pin`, or a network name), or to
    ``VORDIUM_CHAIN_ID`` + ``VORDIUM_GENESIS_SHA256``; with none of them it is read but never signed for.

    A read value that differs from the pin does not stop reads (a :class:`PinWarning` is issued); it stops signing
    (:func:`signing_pin` raises :class:`PinMismatch`)."""
    env_chain = os.getenv("VORDIUM_CHAIN_ID")
    env_rpc = os.getenv("VORDIUM_RPC_URL")
    custom_rpc = rpc_url or env_rpc
    env_cid, env_gen = _env_pin()
    if isinstance(pin, str):
        if network and str(network).strip().lower() != pin.strip().lower():
            raise NetworkResolutionError(f"network {network!r} and pin {pin!r} name different networks")
        network, pin = pin, None
    named = network or os.getenv("VORDIUM_NETWORK") or None
    if not named and custom_rpc and pin is None:
        # an address that IS a named network's own JSON-RPC or REST base names that network
        for key, pre in NETWORKS.items():
            if custom_rpc.rstrip("/") in {(pre.get(k) or "").rstrip("/") for k in ("rpc", "api") if pre.get(k)}:
                named = key
    name = str(named).strip().lower() if named else ("mainnet" if not custom_rpc or pin is not None else None)
    preset = _preset(name or "mainnet")
    # The pin this network is held to: the one passed, else the named network's, else both environment values.
    held: Optional[Pin] = None
    pin_problem: Optional[str] = None
    if pin is not None:
        if not isinstance(pin, Pin):
            raise NetworkResolutionError("pin must be a vordium.pins.Pin or a network name")
        held = pin
        if named and PINS.get(name) is not None and PINS[name] != Pin(pin.chain_id, pin.genesis_sha256, name):
            raise NetworkResolutionError(f"the pin given is not {name}'s pin (chain {PINS[name].chain_id}, genesis "
                                         f"{PINS[name].genesis_sha256}); pass one or the other")
        if not named:
            name = None
    elif name is not None:
        held = PINS.get(name)
    elif env_cid is not None and env_gen is not None:
        held = Pin(env_cid, env_gen)
    else:
        pin_problem = (f"Refusing to sign: the endpoint {custom_rpc} is not a named network and has no pin. Say which "
                       "network it serves (network=\"mainnet\" or \"testnet\"), or pass pin=Pin(chain_id, "
                       "genesis_sha256), or set both VORDIUM_CHAIN_ID and VORDIUM_GENESIS_SHA256. Nothing was signed.")

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
            g = spec.get("genesisSha256")
            spec_genesis = normalize_genesis(g) if isinstance(g, str) else None
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
    if env_cid is not None:
        candidates["pinned(VORDIUM_CHAIN_ID)"] = env_cid

    chain_id = _agree_chain_id(candidates)  # raises on disagreement / none

    genesis_sha256 = _status_genesis_sha256(api_url or rpc, timeout)
    if name == "testnet" and spec_genesis and genesis_sha256 and spec_genesis != genesis_sha256:
        raise NetworkResolutionError(
            f"the spec names genesis {spec_genesis[:8]}… but the node serves genesis {genesis_sha256[:8]}…; "
            "refusing to sign for either."
        )
    if held is not None:
        problems = differences(
            held,
            {"eth_chainId": onchain_cid, "the network spec": spec_chain_id, "VORDIUM_CHAIN_ID": env_cid},
            {"the node's /status": genesis_sha256, "the network spec": spec_genesis, "VORDIUM_GENESIS_SHA256": env_gen})
        if onchain_cid is None:
            problems.append(f"eth_chainId of {rpc} did not answer, expected {held.chain_id}")
        if genesis_sha256 is None:
            problems.append(f"the node's /status reports no genesis, expected {held.genesis_sha256}")
        if problems:
            pin_problem = refusal(held, problems)
    if pin_problem:
        warnings.warn(pin_problem, PinWarning, stacklevel=2)
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
        pin=held,
        pin_problem=pin_problem,
    )


def signing_pin(net: Optional[Network] = None) -> Pin:
    """The pin to sign under for ``net`` (default: the configured network), after every check. Raises
    :class:`UnpinnedNetwork` when the network has no pin and :class:`PinMismatch` when what it reports differs from
    the pin; in both cases nothing may be signed. Every signing path in the SDK calls this first and builds its
    EIP-712 domain from the returned pin."""
    net = net if net is not None else get_network()
    problem, pin, name = (getattr(net, "pin_problem", None), getattr(net, "pin", None), getattr(net, "name", None))
    if problem:
        raise (UnpinnedNetwork if pin is None else PinMismatch)(problem)
    if pin is None and name is not None and name in PINS:
        pin = PINS[name]
    if pin is None:
        g = normalize_genesis(getattr(net, "genesis_sha256", None))
        if g is None:
            raise UnpinnedNetwork("Refusing to sign: the network names no genesis, so no signing domain can be "
                                  "built. Nothing was signed.")
        pin = Pin(int(net.chain_id), g)
    reported_genesis = getattr(net, "genesis_sha256", None) or None
    problems = differences(pin, {"the network": net.chain_id}, {"the network": reported_genesis})
    if reported_genesis is None:
        problems.append(f"the network reports no genesis, expected {pin.genesis_sha256}")
    if problems:
        raise PinMismatch(refusal(pin, problems))
    return pin


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
    ``rpc_url`` — an address of your own — still wins for transport and is held to that network's pin. Returns the
    resolved network."""
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


def require_message_pin(message: str, net: Optional[Network] = None) -> Pin:
    """Check an EIP-191 message's ``Chain: <id>`` (line 2) and, when present, ``Genesis: <sha256>`` (line 3) against
    the pin of ``net`` (default: the configured network). Raises :class:`PinMismatch` / :class:`UnpinnedNetwork`
    before anything is signed; returns the pin."""
    pin = signing_pin(net)
    lines = str(message).split("\n")
    if len(lines) < 2 or not lines[1].startswith("Chain: "):
        raise ValueError('an EIP-191 message must carry "Chain: <id>" as line 2')
    problems = []
    c = lines[1][len("Chain: "):].strip()
    if not c.isdigit() or int(c) != pin.chain_id:
        problems.append(f"the message names chain {c}, expected {pin.chain_id}")
    if len(lines) > 2 and lines[2].startswith("Genesis: "):
        g = lines[2][len("Genesis: "):].strip()
        if normalize_genesis(g) != pin.genesis_sha256:
            problems.append(f"the message names genesis {g}, expected {pin.genesis_sha256}")
    if problems:
        raise PinMismatch(refusal(pin, problems))
    return pin


def reset_network() -> None:
    """Drop the cached resolution (next access re-resolves)."""
    global _current, _explicit
    _current, _explicit = None, False
