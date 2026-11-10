"""The identity each named network is pinned to: its chain id and its genesis sha256.

These values are part of the SDK. Before anything is signed, the SDK compares the pin with what the network reports
(``eth_chainId``, the node's ``/status`` and the network spec). When any of them differs, nothing is signed: a
signature made under the wrong chain id or genesis would be valid on another chain.

The EIP-712 domains are built from the pin, never from a value read off the network. A new genesis for a named
network (a relaunch) therefore needs a new SDK release that carries the new pin.

A network that is not named here can still be used: pass an explicit :class:`Pin` with its chain id and genesis
(``resolve_network(rpc_url=..., pin=Pin(...))``), or set both ``VORDIUM_CHAIN_ID`` and ``VORDIUM_GENESIS_SHA256``.
Without a pin such an endpoint can be read, but nothing is signed for it.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional

_HEX = "0123456789abcdef"


def normalize_genesis(value: object) -> Optional[str]:
    """``value`` as 64 lower-case hex characters without ``0x``, or None when it is not a 32-byte hex string."""
    if not isinstance(value, str):
        return None
    g = value[2:] if value[:2] in ("0x", "0X") else value
    g = g.lower()
    if len(g) != 64 or any(c not in _HEX for c in g):
        return None
    return g


@dataclass(frozen=True)
class Pin:
    """The chain id and genesis a network is pinned to. ``name`` is the named network ("mainnet", "testnet"), or
    None for a pin the caller gives."""
    chain_id: int
    genesis_sha256: str
    name: Optional[str] = None

    def __post_init__(self):
        if isinstance(self.chain_id, bool) or not isinstance(self.chain_id, int) or self.chain_id <= 0:
            raise ValueError("a pin needs a positive integer chain id")
        g = normalize_genesis(self.genesis_sha256)
        if g is None:
            raise ValueError("a pin needs the genesis sha256 as 64 hex characters")
        object.__setattr__(self, "genesis_sha256", g)

    @property
    def label(self) -> str:
        return self.name or f"the pinned network (chain {self.chain_id})"


#: The named networks' pins. Keep in step with the network spec of each network.
PINS: Dict[str, Pin] = {
    "mainnet": Pin(101101, "2c1c0679fa6ab8358f1d3e8d294a8d1c73ac2e2caf9079f1216abedc3d9fdf4f", "mainnet"),
    "testnet": Pin(101102, "8b5d414c5cd5d18bc468b64f87ac8e2c2b5ff494c769d5e09dcf50ce75a59792", "testnet"),
}


def pin_for(name: str) -> Pin:
    """The pin of a named network. Raises KeyError for a name that has none."""
    return PINS[str(name).strip().lower()]


def differences(pin: Pin, chain_ids: Dict[str, Optional[int]], geneses: Dict[str, Optional[str]]) -> List[str]:
    """One plain line per reported value that differs from ``pin``. ``chain_ids`` / ``geneses`` map a source name
    ("eth_chainId", "the network spec", "the node's /status") to what it reported; a None value was not reported and
    is skipped here (the caller decides whether a missing value is acceptable)."""
    out: List[str] = []
    for src, cid in chain_ids.items():
        if cid is not None and cid != pin.chain_id:
            out.append(f"{src} reports chain id {cid}, expected {pin.chain_id}")
    for src, g in geneses.items():
        if g is None:
            continue
        n = normalize_genesis(g)
        if n != pin.genesis_sha256:
            out.append(f"{src} reports genesis {n or g}, expected {pin.genesis_sha256}")
    return out


def refusal(pin: Pin, problems: List[str]) -> str:
    """The refusal text for a pin that the network does not match."""
    return (f"Refusing to sign for {pin.label}: " + "; ".join(problems)
            + ". Nothing was signed. Check that the endpoint serves this network.")
