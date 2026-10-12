"""The genesis-bound EIP-712 domains of a Vordium chain, derived, never pinned.

Every signing domain on Vordium binds its ``salt`` to the chain's genesis:
``salt = keccak256(class_tag || genesis_sha256_bytes)``, so a signature made for one genesis of
chainId 101101 can never verify on another. The SDK therefore DERIVES each domain from the live
node's ``/status.genesis_sha256`` (``vordium.network``) and refuses to sign when the genesis is
unknown. These helpers are pure (no network) so they can be byte-checked against the node's own
published separators; :func:`verify_against_node` does that at runtime.

Layouts (node-authoritative):
  * ``VordCore``      — name ``VordCore``,     version ``1``, chainId, verifyingContract 0x…1002, salt(``VORDIUM_VORDCORE\\x01``)
  * ``VordexSession`` — name ``VordexSession``, version ``1``, chainId, verifyingContract 0x…1002, salt(``VORDIUM_VORDEXSESSION\\x01``)
"""
from typing import Dict, Optional

from eth_abi import encode
from eth_utils import keccak

VERIFYING_CONTRACT = "0x0000000000000000000000000000000000001002"

_DOMAINS = {
    # class: (name, version, salt_tag); both carry verifyingContract
    "VordCore": ("VordCore", "1", b"VORDIUM_VORDCORE\x01"),
    "VordexSession": ("VordexSession", "1", b"VORDIUM_VORDEXSESSION\x01"),
}
_TYPEHASH = keccak(b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract,bytes32 salt)")


def _genesis_bytes(genesis_sha256: str) -> bytes:
    g = genesis_sha256[2:] if genesis_sha256.startswith("0x") else genesis_sha256
    if len(g) != 64:
        raise ValueError("genesis_sha256 must be 32 bytes of hex")
    return bytes.fromhex(g)


def salt(domain_class: str, genesis_sha256: str) -> bytes:
    """keccak256(class_tag || genesis_sha256) — the canonical 5th EIP712Domain field."""
    return keccak(_DOMAINS[domain_class][2] + _genesis_bytes(genesis_sha256))


def domain(domain_class: str, chain_id: int, genesis_sha256: str) -> Dict[str, object]:
    """The EIP712Domain dict a signer passes to ``encode_typed_data`` (salt as bytes)."""
    name, version, _ = _DOMAINS[domain_class]
    return {"name": name, "version": version, "chainId": int(chain_id), "verifyingContract": VERIFYING_CONTRACT,
            "salt": salt(domain_class, genesis_sha256)}


def separator(domain_class: str, chain_id: int, genesis_sha256: str) -> bytes:
    """The EIP-712 domainSeparator = keccak(abi.encode(typeHash, keccak(name), keccak(version), chainId, vc, salt))."""
    name, version, _ = _DOMAINS[domain_class]
    return keccak(encode(["bytes32", "bytes32", "bytes32", "uint256", "address", "bytes32"],
                         [_TYPEHASH, keccak(name.encode()), keccak(version.encode()), int(chain_id), VERIFYING_CONTRACT,
                          salt(domain_class, genesis_sha256)]))


def separators(chain_id: int, genesis_sha256: str) -> Dict[str, str]:
    """Every separator as 0x-hex, keyed by class."""
    return {c: "0x" + separator(c, chain_id, genesis_sha256).hex() for c in _DOMAINS}


def verify_against_node(rpc_url: Optional[str] = None, timeout: float = 8.0) -> Dict[str, str]:
    """Resolve chainId + genesis_sha256 from a LIVE node (``vordium.network``) and return the
    separators derived from them. Raises if the node does not expose its genesis — a domain that
    cannot be bound to a genesis must not be signed under."""
    from .network import resolve_network
    net = resolve_network(rpc_url=rpc_url, timeout=timeout) if rpc_url else resolve_network(timeout=timeout)
    if not getattr(net, "genesis_sha256", None):
        raise RuntimeError("live node exposes no genesis_sha256; refusing to derive a signing domain")
    return separators(net.chain_id, net.genesis_sha256)
