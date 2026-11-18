"""Runtime network resolution — the SINGLE source of the network identity.

The SDK does NOT carry a copy of the chain parameters: a copied value can go
stale, a resolved one cannot.

Two DIFFERENT trust rules, because the two kinds of value fail differently:

  TRANSPORT — rpc, ws, explorer, native currency (and the bridge address
      when no signed release record is served; with one, the bridge comes
      from the record only).
      Derived from the canonical spec (``VORDIUM_SPEC_URL`` or
      https://rpc.vordium.com/network-spec.json). A bad transport value
      fails LOUDLY and HARMLESSLY: a bad RPC just won't connect.

  SIGNING DOMAIN — the EIP-712 ``chainId`` and the genesis-bound ``salt``.
      A mismatched signing domain is dangerous: it yields a VALID signature on
      ANOTHER chain (an attacker who controls the spec/RPC could harvest
      signatures valid elsewhere). So every named network is held to a PIN: its
      chain id and genesis sha256 from the signed release record when one is
      served (:mod:`vordium.release_record`), else the SDK's own
      (:mod:`vordium.pins`), and the domain is built from the pin. Every
      available source —
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
import re
import time as _time
import warnings
from dataclasses import dataclass, field
from typing import Dict, Optional, Sequence, Union

import requests
from . import _http
from .pins import PINS, Pin, differences, normalize_genesis, refusal
from . import release_record as _rr

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

    #: When the reason is the signed release record (a network named only by its chain id): its code, else None.
    record_code: Optional[str] = None


class RecordUnavailable(PinMismatch):
    """The signed release record of the network cannot be used now, so nothing is signed. ``record_code`` names why:
    ``expired``, ``rollback`` (an older sequence), ``not_served``, ``unsigned``, ``bad_signature``, ``not_listed``,
    ``key_expired``, … (:class:`vordium.release_record.RecordRefused` codes). Retrying later can help for ``expired``
    and ``not_served``; it is still a :class:`PinMismatch`."""

    def __init__(self, message: str, record_code: Optional[str] = None):
        super().__init__(message)
        self.record_code = record_code


class _RecordProblem(str):
    """The text of a record problem, with its code (a str, so it is kept wherever the text is)."""
    code: Optional[str] = None


def _record_problem(text: str, code: Optional[str]) -> "_RecordProblem":
    p = _RecordProblem(text if re.search(r"nothing (is|was) signed", text, re.I) else f"{text} Nothing was signed.")
    p.code = code
    return p


def _refuse(problem: str, unpinned: bool = False) -> Exception:
    """The error to raise for ``problem``: a record problem carries its code."""
    code = getattr(problem, "code", None)
    if unpinned:
        e = UnpinnedNetwork(problem)
        e.record_code = code
        return e
    return RecordUnavailable(problem, code) if code is not None else PinMismatch(problem)


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
    # The signed release record this network was checked against (vordium.release_record), when one is served. Its
    # genesis is the pin, and the deposit bridge comes from it. None when no record is served (the SDK's pin applies).
    record: Optional["_rr.Verified"] = None
    # Why the served release record cannot be used (unsigned, bad signature, another key, expired, older than one seen
    # before, not listing this network). Nothing is signed, and the deposit bridge is not named, while it is set.
    record_problem: Optional[str] = None
    # Where the record is read again ((chain id, addresses, keys, timeout, named by chain id)), and the record as last
    # read ([record, problem, monotonic time]): signing and the deposit bridge use the record as it is now (read again
    # after RECORD_TTL_S, at once when it has expired, and a refused one after RECORD_RETRY_S).
    record_source: Optional[tuple] = field(default=None, compare=False, repr=False)
    record_live: Optional[list] = field(default=None, compare=False, repr=False)
    # What every source reported at resolution ((chain ids, geneses, rpc)): a record that verifies later is held to
    # all of them, as at resolution.
    record_reports: Optional[tuple] = field(default=None, compare=False, repr=False)


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


def _read_record(chain_id: int, urls, keys, timeout: float) -> "Optional[_rr.Verified]":
    """The signed release record for ``chain_id`` (see :func:`vordium.release_record.read_record`). One function, so a
    test can stand in for the network."""
    return _rr.read_record(chain_id, urls, keys, timeout)


def _record_chain_id(network) -> Optional[int]:
    """A network named by its chain id (an int, or a string of digits), else None."""
    if isinstance(network, bool):
        return None
    if isinstance(network, int):
        return network if network > 0 else None
    if isinstance(network, str) and re.fullmatch(r"[0-9]+", network.strip()):
        n = int(network.strip())
        return n if n > 0 else None
    return None


def resolve_network(rpc_url: Optional[str] = None,
                    spec_url: Optional[str] = None,
                    timeout: float = 6.0,
                    network: Optional[Union[str, int]] = None,
                    pin: Optional[Union[Pin, str]] = None,
                    release_keys: Optional[Sequence[str]] = None,
                    release_record_url: Optional[str] = None) -> Network:
    """Discover transport from the spec, resolve the chain id by AGREEMENT across every available source, and hold
    what the network reports to its identity.

    ``network`` names the network ("mainnet" — the default — or "testnet"; else VORDIUM_NETWORK). It chooses where
    the SDK asks (see NETWORKS) and the identity it is held to. That identity comes from the signed release record
    (:mod:`vordium.release_record`): when the record is served and verifies under the release key, its genesis for the
    network's chain id is the pin, and its deposit bridge is the bridge. When no record is served, the SDK's own pin
    applies (:data:`vordium.pins.PINS`). ``network`` may also be a chain id (with ``rpc_url``): a network that only the
    signed record names; nothing is signed for it without a record that lists it.

    An explicit ``rpc_url`` (or VORDIUM_RPC_URL) still wins for transport: that node is used for JSON-RPC and REST
    alike. Such an endpoint is held to the network you name, or to ``pin`` (a :class:`~vordium.pins.Pin`, or a network
    name), or to ``VORDIUM_CHAIN_ID`` + ``VORDIUM_GENESIS_SHA256``; with none of them it is read but never signed for.

    ``release_keys`` (armoured OpenPGP public keys) and ``release_record_url`` are for tests only: they replace the
    shipped release key and the record's address.

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
    by_chain = _record_chain_id(network)
    if by_chain is not None:
        named_by_id = next((k for k, p in PINS.items() if p.chain_id == by_chain), None)
        if named_by_id is not None:
            network, by_chain = named_by_id, None
        elif not custom_rpc:
            raise NetworkResolutionError(f"network {by_chain} is named by its chain id; give its rpc_url too")
        elif pin is not None:
            raise NetworkResolutionError("a network named by its chain id takes its identity from the signed release "
                                         "record; do not pass pin= as well")
    named = (None if by_chain is not None else network) or (os.getenv("VORDIUM_NETWORK") if by_chain is None else None) or None
    if not named and by_chain is None and custom_rpc and pin is None:
        # an address that IS a named network's own JSON-RPC or REST base names that network
        for key, pre in NETWORKS.items():
            if custom_rpc.rstrip("/") in {(pre.get(k) or "").rstrip("/") for k in ("rpc", "api") if pre.get(k)}:
                named = key
    if by_chain is not None:
        name = None
    else:
        name = str(named).strip().lower() if named else ("mainnet" if not custom_rpc or pin is not None else None)
    preset = _preset(name or "mainnet")
    # The pin this network is held to: the one passed, else the named network's (from the signed record when one is
    # served, else the SDK's own), else both environment values.
    held: Optional[Pin] = None
    pin_problem: Optional[str] = None
    record: Optional[_rr.Verified] = None
    record_problem: Optional[str] = None
    record_cid: Optional[int] = None
    if pin is not None:
        if not isinstance(pin, Pin):
            raise NetworkResolutionError("pin must be a vordium.pins.Pin or a network name")
        held = pin
        if named and PINS.get(name) is not None and PINS[name] != Pin(pin.chain_id, pin.genesis_sha256, name):
            raise NetworkResolutionError(f"the pin given is not {name}'s pin (chain {PINS[name].chain_id}, genesis "
                                         f"{PINS[name].genesis_sha256}); pass one or the other")
        if not named:
            name = None
    elif by_chain is not None:
        record_cid = by_chain
    elif name is not None:
        held = PINS.get(name)
        record_cid = held.chain_id if held is not None else None
    elif env_cid is not None and env_gen is not None:
        held = Pin(env_cid, env_gen)
    else:
        pin_problem = (f"Refusing to sign: the endpoint {custom_rpc} is not a named network and has no pin. Say which "
                       "network it serves (network=\"mainnet\" or \"testnet\"), or pass pin=Pin(chain_id, "
                       "genesis_sha256), or set both VORDIUM_CHAIN_ID and VORDIUM_GENESIS_SHA256. Nothing was signed.")
    record_source: Optional[tuple] = None
    if record_cid is not None:
        if release_record_url:
            urls: tuple = (release_record_url,)
        elif by_chain is not None:                         # a chain only the record names: every record address
            urls = tuple(u for v in _rr.RECORD_URLS.values() for u in v)
        else:
            urls = _rr.RECORD_URLS.get(name or "", ())
        try:
            keys = _rr.pinned_keys(release_keys)
            record_source = (record_cid, urls, keys, timeout, by_chain is not None)
            record = _read_record(record_cid, urls, keys, timeout)
        except _rr.RecordRefused as e:
            record_problem = _record_problem(str(e), e.code)
        if record is not None:
            held = Pin(record_cid, record.entry.genesis_sha256, name)
        elif by_chain is not None and record_problem is None:
            record_problem = _record_problem(f"Refusing to sign: no signed release record lists chain {by_chain}, and a "
                                             "network named only by its chain id needs one. Nothing was signed.",
                                             "not_listed")
        if record_problem is not None:
            pin_problem = record_problem

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
        if record is not None:
            if genesis_sha256 is not None and genesis_sha256 in record.entry.retired_genesis:
                problems.insert(0, f"the node serves genesis {genesis_sha256}, which the signed release record lists "
                                   f"in retired_genesis for chain {record.entry.chain_id}")
        if problems and record_problem is None:
            pin_problem = refusal(held, problems)
            if record is None and record_cid is not None and any(" reports genesis " in x for x in problems):
                pin_problem += (" The signed release record could not be read, so the SDK's own pin was used: if this "
                                "network has moved to a new genesis, try again once the record can be read.")
    if record is not None:
        # The deposit bridge comes from the signed record only; the spec's value is not used.
        b = record.entry.bridge
        if bridge_cid != b.chain_id:
            bridge_chain = None
        bridge_addr, bridge_cid = b.vault, b.chain_id
    elif record_problem is not None:
        bridge_addr = bridge_chain = bridge_cid = None
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
        record=record,
        record_problem=record_problem,
        record_source=record_source,
        record_reports=({"eth_chainId": onchain_cid, "the network spec": spec_chain_id, "VORDIUM_CHAIN_ID": env_cid},
                        {"the node's /status": genesis_sha256, "the network spec": spec_genesis,
                         "VORDIUM_GENESIS_SHA256": env_gen}, rpc) if record_source is not None else None,
        record_live=[record, record_problem, _time.monotonic()] if record_source is not None else None,
    )


#: How long a named network's record is reused by :func:`named_pin` before it is read again (seconds).
NAMED_RECORD_TTL_S = 300.0
_NAMED: Dict[str, tuple] = {}


def named_pin(name: str, timeout: float = 6.0) -> Pin:
    """The pin of a named network ("mainnet", "testnet") for a client that is given only the name: the genesis of the
    signed release record when one is served (read again after NAMED_RECORD_TTL_S, and at once when it has expired),
    else the SDK's own pin. Raises :class:`PinMismatch` while the served record cannot be used, and
    :class:`NetworkResolutionError` for an unknown name."""
    import time as _time
    key = str(name).strip().lower()
    hard = PINS.get(key)
    if hard is None:
        raise NetworkResolutionError(f"unknown network {name!r}; known: {', '.join(sorted(PINS))}")
    hit = _NAMED.get(key)
    mono = _time.monotonic()
    if hit is not None and mono - hit[2] < NAMED_RECORD_TTL_S and (hit[3] is None or _rr._now() <= hit[3]):
        pin, problem = hit[0], hit[1]
    else:
        pin, problem, until = hard, None, None
        try:
            rec = _read_record(hard.chain_id, _rr.RECORD_URLS.get(key, ()), _rr.pinned_keys(), timeout)
            if rec is not None:
                pin, until = Pin(hard.chain_id, rec.entry.genesis_sha256, key), rec.record.valid_until
        except _rr.RecordRefused as e:
            problem = _record_problem(str(e), e.code)
        _NAMED[key] = (pin, problem, mono, until)
    if problem:
        raise _refuse(problem)
    return pin


#: How long a network's release record is used before it is read again (seconds), and how soon a refused one is retried.
RECORD_TTL_S = 300.0
RECORD_RETRY_S = 30.0


def record_now(net: Network) -> "tuple":
    """``(record, problem)`` of ``net``'s release record as it is now: read again when it has expired, when it is older
    than RECORD_TTL_S, or when it was refused more than RECORD_RETRY_S ago."""
    live, src = net.record_live, net.record_source
    rec, prob, at = live
    age = _time.monotonic() - at
    if ((rec is not None and (_rr._now() > rec.record.valid_until or age >= RECORD_TTL_S))
            or (prob is not None and age >= RECORD_RETRY_S)):
        chain, urls, keys, timeout, by_chain = src
        try:
            rec, prob = _read_record(chain, urls, keys, timeout), None
        except _rr.RecordRefused as e:
            rec, prob = None, _record_problem(str(e), e.code)
        if rec is None and prob is None and by_chain:
            prob = _record_problem(f"Refusing to sign: no signed release record lists chain {chain}, and a network "
                                   "named only by its chain id needs one. Nothing was signed.", "not_listed")
        live[:] = [rec, prob, _time.monotonic()]
    if rec is None and prob is None and net.record is not None:
        prob = _record_problem("Refusing to sign: the signed release record this network was checked against is not "
                               "served now. Nothing was signed.", "not_served")
    return rec, prob


def _record_signing_pin(net: Network) -> Optional[Pin]:
    """The pin from ``net``'s release record as it is now (raises when it cannot be used), or None when no record is
    served and none was used for ``net`` (then the SDK's own pin applies, as checked by the caller)."""
    rec, prob = record_now(net)
    if prob:
        raise _refuse(prob, unpinned=bool(net.record_source[4]))
    if rec is None:
        if net.record_problem is None:
            return None                                    # no record, as at resolution: the caller's checks apply
        if net.name not in PINS:
            raise _refuse(net.record_problem, unpinned=True)
        pin = PINS[net.name]
    else:
        pin = Pin(rec.entry.chain_id, rec.entry.genesis_sha256, net.name)
    g = normalize_genesis(getattr(net, "genesis_sha256", None))
    same = net.record is not None and rec is not None and rec.entry.genesis_sha256 == net.record.entry.genesis_sha256
    if same and net.pin_problem:                          # the record held; what the network reported did not
        raise PinMismatch(net.pin_problem)
    problems = differences(pin, {"the network": net.chain_id}, {"the network": g})
    if g is None:
        problems.append(f"the network reports no genesis, expected {pin.genesis_sha256}")
    if not same and net.record_reports is not None:   # a record read after resolution: every source, as at resolution
        cids, gens, rpc = net.record_reports
        problems += [x for x in differences(pin, cids, gens) if x not in problems]
        if cids.get("eth_chainId") is None:
            problems.append(f"eth_chainId of {rpc} did not answer, expected {pin.chain_id}")
    if rec is not None and g in rec.entry.retired_genesis:
        problems.insert(0, f"the node serves genesis {g}, which the signed release record lists in retired_genesis "
                           f"for chain {rec.entry.chain_id}")
    if problems:
        raise PinMismatch(refusal(pin, problems))
    return pin


def signing_pin(net: Optional[Network] = None) -> Pin:
    """The pin to sign under for ``net`` (default: the configured network), after every check. Raises
    :class:`UnpinnedNetwork` when the network has no pin and :class:`PinMismatch` when what it reports differs from
    the pin; in both cases nothing may be signed. Every signing path in the SDK calls this first and builds its
    EIP-712 domain from the returned pin."""
    net = net if net is not None else get_network()
    if getattr(net, "record_live", None) is not None:
        live = _record_signing_pin(net)
        if live is not None:
            return live
    problem, pin, name = (getattr(net, "pin_problem", None), getattr(net, "pin", None), getattr(net, "name", None))
    if problem:
        raise _refuse(problem, unpinned=pin is None)
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


def deposit_spec_url(spec_url: Optional[str] = None, expected_bridge: Optional[str] = None) -> str:
    """Where the spec is read for anything that names the deposit bridge or builds a deposit. A spec named only by the
    environment (VORDIUM_SPEC_URL) is refused for this unless the caller also gives the bridge address it expects
    (``expected_bridge``), which the spec must then name. Raises :class:`BridgeRefused`."""
    if spec_url:
        return spec_url
    if os.getenv("VORDIUM_SPEC_URL") and not _address(expected_bridge):
        raise BridgeRefused("VORDIUM_SPEC_URL is set, and a spec named by the environment does not name the deposit "
                            "bridge on its own. Pass expected_bridge= with the bridge address you have checked, or "
                            "unset VORDIUM_SPEC_URL. Nothing was built.")
    return default_spec_url()


def record_bridge() -> "Optional[_rr.Bridge]":
    """The deposit bridge the signed release record names for the configured network, or None when no record is
    served for it (then the live network spec names the bridge). Raises :class:`BridgeRefused` while the served record
    cannot be used, or when the network cannot be resolved."""
    try:
        net = get_network()
    except NetworkResolutionError as e:
        raise BridgeRefused(f"the network could not be resolved, so the deposit bridge cannot be confirmed ({e}).") from None
    if getattr(net, "record_live", None) is None:
        if getattr(net, "record_problem", None):
            raise BridgeRefused(f"{net.record_problem} The deposit bridge is not named while the release record "
                                "cannot be used.")
        rec = getattr(net, "record", None)
        return rec.entry.bridge if rec is not None else None
    rec, prob = record_now(net)
    if prob or (rec is None and net.record_problem):
        raise BridgeRefused(f"{prob or net.record_problem} The deposit bridge is not named while the release record "
                            "cannot be used.")
    return rec.entry.bridge if rec is not None else None


def _expected(expected_bridge: Optional[str]) -> Optional[str]:
    if expected_bridge is None:
        return None
    from ._strict import address as _checked
    try:
        return _checked(expected_bridge, "the expected bridge").lower()
    except ValueError as e:
        raise BridgeRefused(f"{e}; nothing should be sent to it.") from None


def current_bridge(spec_url: Optional[str] = None, timeout: float = 6.0, expected_bridge: Optional[str] = None) -> str:
    """The deposit bridge address. When the signed release record is served for the configured network, it is the
    record's vault (the spec is not read). Else it is read from the live network spec at the moment of the call (never
    cached); a spec named only by VORDIUM_SPEC_URL is used only with ``expected_bridge`` (see
    :func:`deposit_spec_url`). With ``expected_bridge`` the bridge must be exactly that address. Raises
    :class:`BridgeRefused` when the record cannot be used, the spec cannot be read, names no valid address, or names
    another address than the one expected."""
    rb = record_bridge()
    if rb is not None:
        want = _expected(expected_bridge)
        if want is not None and want != rb.vault:
            raise BridgeRefused(f"the signed release record names {rb.vault} as the deposit bridge, not the expected "
                                f"{want}; nothing should be sent to it.")
        return rb.vault
    url = deposit_spec_url(spec_url, expected_bridge)
    spec = _fetch_spec(url, timeout)
    if not isinstance(spec, dict):
        raise BridgeRefused(f"the network spec could not be read ({url}); the deposit bridge cannot be confirmed, "
                            "so no address is returned.")
    addr = _address((spec.get("bridge") or {}).get("address"))
    if not addr:
        raise BridgeRefused("the network spec names no valid deposit bridge address; no address is returned.")
    want = _expected(expected_bridge)
    if expected_bridge is not None and addr != want:
        raise BridgeRefused(f"the network spec names {addr} as the deposit bridge, not the expected {want or expected_bridge!r}; "
                            "nothing should be sent to it.")
    return addr


def require_current_bridge(address: str, spec_url: Optional[str] = None, timeout: float = 6.0) -> str:
    """Return ``address`` (lower-case) only when it is the deposit bridge right now: the one the signed release record
    names, else (no record served) the one the live network spec names. Any other address, and any address at all
    when neither can be read, raises :class:`BridgeRefused`."""
    given = _address(address)
    if not given:
        raise BridgeRefused(f"{address!r} is not an address; nothing should be sent to it.")
    current = current_bridge(spec_url, timeout, expected_bridge=given)
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
    if not (c.isascii() and c.isdigit()) or int(c) != pin.chain_id:
        problems.append(f"the message names chain {c}, expected {pin.chain_id}")
    if len(lines) > 2 and lines[2].startswith("Genesis: "):
        g = lines[2][len("Genesis: "):].strip()
        if normalize_genesis(g) != pin.genesis_sha256:
            problems.append(f"the message names genesis {g}, expected {pin.genesis_sha256}")
    if problems:
        raise PinMismatch(refusal(pin, problems))
    return pin


def reset_network() -> None:
    """Drop the cached resolution (next access re-resolves), and the named networks' records."""
    global _current, _explicit
    _current, _explicit = None, False
    _NAMED.clear()
