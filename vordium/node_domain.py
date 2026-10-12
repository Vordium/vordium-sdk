"""The signing domain of the node a client posts to.

Every signed write is bound to one network by its EIP-712 domain: the chain id and the genesis-bound salt. A client
that builds the domain from one network and posts to a node of another gets every write refused -- or, worse, holds a
signature that is valid elsewhere. So the clients here build the domain from the node they post to:

* :func:`node_identity` reads the node's ``/status`` (its ``chain_id`` and ``genesis_sha256``; under the URL's own path
  first, then at the host root). A read without both is refused -- nothing is signed on a guess.
* the identity is checked against the network the caller configured, when one is configured: a ``network`` given to
  the client, a network set with :func:`vordium.network.set_network`, or the ``VORDIUM_CHAIN_ID`` /
  ``VORDIUM_GENESIS_SHA256`` environment pins. Any disagreement raises :class:`~vordium.network.NetworkMismatch`
  before anything is signed. A pointer to a test node never signs for the live network, and the reverse.
* :class:`NodeDomain` keeps the identity for a short while and reads it again; if the node now serves another chain it
  refuses rather than follow it silently.
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass
from typing import Any, Callable, Optional

from . import network as _net
from .network import NetworkMismatch, NetworkResolutionError


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


def configured(network: Optional["_net.Network"] = None) -> tuple:
    """``(chain_id, genesis_sha256, where)`` the caller configured, each None when not configured: an explicit
    ``network``, else a network set with :func:`vordium.network.set_network`, else the environment pins."""
    if network is not None:
        return network.chain_id, (network.genesis_sha256 or None), "the network given to the client"
    n = _net.explicit_network()
    if n is not None:
        return n.chain_id, (n.genesis_sha256 or None), "the network set with set_network()"
    cid = os.getenv("VORDIUM_CHAIN_ID")
    g = os.getenv("VORDIUM_GENESIS_SHA256")
    g = (g[2:] if g and g[:2] in ("0x", "0X") else g) or None
    return (int(cid, 0) if cid else None), (g.lower() if g else None), "the VORDIUM_CHAIN_ID / VORDIUM_GENESIS_SHA256 pins"


def check(ident: NodeIdentity, network: Optional["_net.Network"] = None) -> NodeIdentity:
    """Raise :class:`NetworkMismatch` when the configured network (if any) is not the node's."""
    cid, gen, where = configured(network)
    if cid is not None and cid != ident.chain_id:
        raise NetworkMismatch(f"{where} is chain {cid}, but the node serves chain {ident.chain_id}; refusing to sign")
    if gen is not None and gen != ident.genesis_sha256:
        raise NetworkMismatch(f"{where} has genesis {gen[:8]}…, but the node serves genesis {ident.genesis_sha256[:8]}…; "
                              "refusing to sign")
    return ident


class NodeDomain:
    """The VordCore signing domain of the node at ``rpc_url``, checked against the configured network.

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

    def identity(self) -> NodeIdentity:
        now = self.clock()
        if self.bound is not None and self._read_at is not None and now - self._read_at < self.ttl_s:
            return self.bound
        ident = check(self._identity(), self.network)
        if self.bound is not None and ident != self.bound:
            raise NetworkMismatch(f"the node at {self.rpc_url} now serves chain {ident.chain_id} genesis "
                                  f"{ident.genesis_sha256[:8]}…, not the chain {self.bound.chain_id} genesis "
                                  f"{self.bound.genesis_sha256[:8]}… this client signed for; refusing to sign")
        if self.bound is None:
            from .caps import vordcore_domain_separator

            sep = vordcore_domain_separator(ident.chain_id, _net.VERIFYING_CONTRACT, ident.genesis_sha256)
            if self.pinned is not None and self.pinned != sep:
                raise NetworkMismatch("the domain separator given to the client is not the node's own "
                                      f"(chain {ident.chain_id}, genesis {ident.genesis_sha256[:8]}…); refusing to sign")
            self._sep = sep
        self.bound, self._read_at = ident, now
        return ident

    def separator(self) -> bytes:
        """The domain separator to sign with -- the node's, after every check."""
        self.identity()
        assert self._sep is not None
        return self._sep
