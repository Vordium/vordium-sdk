"""The signing domain of the node a client posts to.

Every signed write is bound to one network by its EIP-712 domain: the chain id and the genesis-bound salt. A client
that builds the domain from one network and posts to a node of another gets every write refused -- or, worse, holds a
signature that is valid elsewhere. So the clients here build the domain from the node they post to:

* :func:`node_identity` reads the node's ``/status`` (its ``chain_id`` and ``genesis_sha256``; under the URL's own path
  first, then at the host root). A read without both is refused -- nothing is signed on a guess.
* the identity is checked against the PIN of the network the client signs for (:mod:`vordium.pins`): the pin of a
  ``network`` given to the client, else of a network set with :func:`vordium.network.set_network`, else of the
  network ``VORDIUM_NETWORK`` names, else both ``VORDIUM_CHAIN_ID`` and ``VORDIUM_GENESIS_SHA256``, else the pin of
  the named network whose address the client posts to. A node at any other address, with none of these, is never
  signed for (:class:`~vordium.network.UnpinnedNetwork`). Any disagreement raises
  :class:`~vordium.network.PinMismatch` before anything is signed. A pointer to a test node never signs for the live
  network, and the reverse.
* the domain is built from the pin (equal to the node's identity once checked), never from the read alone.
* :class:`NodeDomain` keeps the identity for a short while and reads it again; if the node now serves another chain it
  refuses rather than follow it silently.
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass
from typing import Any, Callable, Optional

from . import network as _net
from .network import NetworkMismatch, NetworkResolutionError, PinMismatch, UnpinnedNetwork
from .pins import PINS, Pin, differences, refusal


@dataclass(frozen=True)
class NodeIdentity:
    chain_id: int
    genesis_sha256: str      # 64 lower-case hex, no 0x


def read_identity(status: Any) -> NodeIdentity:
    """A node identity from a ``/status`` answer. Raises :class:`NetworkResolutionError` unless it names both."""
    if not isinstance(status, dict):
        raise NetworkResolutionError("the node's /status is not an object; refusing to sign")
    cid = status.get("chain_id")
    g = status.get("genesis_sha256")
    if isinstance(cid, str) and cid.strip().isdigit():
        cid = int(cid)
    if isinstance(cid, bool) or not isinstance(cid, int) or cid <= 0:
        raise NetworkResolutionError("the node's /status names no chain id; refusing to sign")
    if isinstance(g, str) and g[:2] in ("0x", "0X"):
        g = g[2:]
    if not (isinstance(g, str) and len(g) == 64 and all(c in "0123456789abcdefABCDEF" for c in g)):
        raise NetworkResolutionError("the node's /status names no genesis; refusing to sign")
    return NodeIdentity(cid, g.lower())


def status_urls(rpc_url: str) -> list:
    """Where a node's ``/status`` is read: under the URL's own path first, then at the host root."""
    from urllib.parse import urlsplit, urlunsplit

    pr = urlsplit(rpc_url)
    own = urlunsplit((pr.scheme or "https", pr.netloc, pr.path.rstrip("/") + "/status", "", ""))
    root = urlunsplit((pr.scheme or "https", pr.netloc, "/status", "", ""))
    return [own] if own == root else [own, root]


def node_identity(rpc_url: str, timeout: float = 6.0, get_json: Optional[Callable[[str], Any]] = None) -> NodeIdentity:
    """Read the identity of the node at ``rpc_url`` (its ``/status``: the URL's own path first, then the host root)."""
    get = get_json or (lambda u: _net._http_json(u, timeout))
    last: Optional[Exception] = None
    for u in status_urls(rpc_url):
        try:
            return read_identity(get(u))
        except Exception as e:  # try the next form; report the last failure
            last = e
    raise NetworkResolutionError(f"the node at {rpc_url} did not give its chain id and genesis ({last}); refusing to sign")


def _known_endpoint(rpc_url: str) -> Optional[Pin]:
    """The pin of the named network whose address ``rpc_url`` is (its JSON-RPC host or its REST base), or None."""
    u = (rpc_url or "").rstrip("/")
    for name, preset in _net.NETWORKS.items():
        for key in ("rpc", "api"):
            v = preset.get(key)
            if v and v.rstrip("/") == u:
                return PINS[name]
    return None


def configured_pin(network: Optional["_net.Network"] = None, rpc_url: Optional[str] = None) -> tuple:
    """``(pin, where)``: the pin a client posting to ``rpc_url`` signs under. Raises
    :class:`~vordium.network.UnpinnedNetwork` / :class:`~vordium.network.PinMismatch` when there is none or the
    configured network does not match its own pin."""
    if isinstance(network, Pin):
        return network, "the pin given to the client"
    if isinstance(network, str):
        p = PINS.get(network.strip().lower())
        if p is None:
            raise NetworkResolutionError(f"unknown network {network!r}; known: {', '.join(sorted(PINS))}")
        return p, f"the network named {p.name}"
    if network is not None:
        return _net.signing_pin(network), "the network given to the client"
    n = _net.explicit_network()
    if n is not None:
        return _net.signing_pin(n), "the network set with set_network()"
    cid, gen = _net._env_pin()
    named = os.getenv("VORDIUM_NETWORK")
    if named:
        p = PINS.get(named.strip().lower())
        if p is None:
            raise NetworkResolutionError(f"unknown network {named!r}; known: {', '.join(sorted(PINS))}")
        problems = differences(p, {"VORDIUM_CHAIN_ID": cid}, {"VORDIUM_GENESIS_SHA256": gen})
        if problems:
            raise PinMismatch(refusal(p, problems))
        return p, "the network VORDIUM_NETWORK names"
    if cid is not None and gen is not None:
        return Pin(cid, gen), "the VORDIUM_CHAIN_ID / VORDIUM_GENESIS_SHA256 pins"
    if cid is not None or gen is not None:
        raise UnpinnedNetwork("Refusing to sign: only one of VORDIUM_CHAIN_ID and VORDIUM_GENESIS_SHA256 is set. "
                              "Set both, or name the network with VORDIUM_NETWORK. Nothing was signed.")
    p = _known_endpoint(rpc_url or "")
    if p is not None:
        return p, f"the address of {p.name}"
    raise UnpinnedNetwork(f"Refusing to sign: the node at {rpc_url} is not a named network's address and no pin is "
                          "configured. Say which network it serves (network=\"mainnet\" or \"testnet\"), or pass "
                          "network=Pin(chain_id, genesis_sha256), or set both VORDIUM_CHAIN_ID and "
                          "VORDIUM_GENESIS_SHA256. Nothing was signed.")


def check(ident: NodeIdentity, network: Optional["_net.Network"] = None, rpc_url: Optional[str] = None) -> NodeIdentity:
    """Raise :class:`~vordium.network.PinMismatch` when the node's identity is not the pin the client signs under
    (see :func:`configured_pin`); :class:`~vordium.network.UnpinnedNetwork` when there is no pin."""
    pin_ident(ident, network, rpc_url)
    return ident


def pin_ident(ident: NodeIdentity, network: Optional["_net.Network"] = None, rpc_url: Optional[str] = None) -> Pin:
    """Check the node's identity against the pin in force and return the pin."""
    pin, where = configured_pin(network, rpc_url)
    problems = differences(pin, {"the node's /status": ident.chain_id}, {"the node's /status": ident.genesis_sha256})
    if problems:
        raise PinMismatch(refusal(pin, problems) + f" (pin from {where})")
    return pin


class NodeDomain:
    """The VordCore signing domain of the node at ``rpc_url``, checked against the pin the client signs under.

    ``domain_separator``, when given, must equal the node's own (it pins, it does not override). The identity is read
    again after ``ttl_s`` seconds; a node that now serves another chain is refused, never followed."""

    def __init__(self, rpc_url: str, network: Optional["_net.Network"] = None, domain_separator: Optional[bytes] = None,
                 identity: Optional[Callable[[], NodeIdentity]] = None, ttl_s: float = 60.0,
                 clock: Callable[[], float] = time.monotonic):
        self.rpc_url = rpc_url
        self.network = network
        self.pinned = domain_separator
        self._identity = identity or (lambda: node_identity(rpc_url))
        self.ttl_s, self.clock = ttl_s, clock
        self.bound: Optional[NodeIdentity] = None
        self._read_at: Optional[float] = None
        self._sep: Optional[bytes] = None
        self._pin: Optional[Pin] = None

    def identity(self) -> NodeIdentity:
        now = self.clock()
        if self.bound is not None and self._read_at is not None and now - self._read_at < self.ttl_s:
            # the bound identity, still held to the pin in force now (no read: the pin check is local)
            p = pin_ident(self.bound, self.network, self.rpc_url)
            if self._pin is None or (p.chain_id, p.genesis_sha256) != (self._pin.chain_id, self._pin.genesis_sha256):
                raise PinMismatch(f"the pin for the node at {self.rpc_url} changed since this client signed; "
                                  "refusing to sign. Make a new client for the other network.")
            return self.bound
        ident = self._identity()
        pin = pin_ident(ident, self.network, self.rpc_url)
        if self.bound is not None and ident != self.bound:
            raise NetworkMismatch(f"the node at {self.rpc_url} now serves chain {ident.chain_id} genesis "
                                  f"{ident.genesis_sha256[:8]}…, not the chain {self.bound.chain_id} genesis "
                                  f"{self.bound.genesis_sha256[:8]}… this client signed for; refusing to sign")
        if self.bound is None:
            from .caps import vordcore_domain_separator

            # built from the pin; the node's identity equals it (checked above)
            sep = vordcore_domain_separator(pin.chain_id, _net.VERIFYING_CONTRACT, pin.genesis_sha256)
            if self.pinned is not None and self.pinned != sep:
                raise NetworkMismatch("the domain separator given to the client is not the node's own "
                                      f"(chain {ident.chain_id}, genesis {ident.genesis_sha256[:8]}…); refusing to sign")
            self._sep, self._pin = sep, pin
        self.bound, self._read_at = ident, now
        return ident

    def separator(self) -> bytes:
        """The domain separator to sign with -- the node's, after every check."""
        self.identity()
        assert self._sep is not None
        return self._sep
