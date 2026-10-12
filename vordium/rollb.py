"""Which signing format applies right now: the chain's signing-format switch.

From activation height ``H`` the chain accepts ONLY the genesis-bound formats, and
below ``H`` ONLY the legacy ones -- there is no dual window. So a signature is built in the format of the height it
will land at, and near the switch this SDK refuses to sign at all:

    head <  H - 3000        legacy          today's bytes, unchanged
    H - 3000 <= head < H    window          refused: a signature made now could land on either side of H
    head >= H               genesis-bound   EIP-191 messages carry ``Genesis: <sha256>`` as line 3; RegisterAgentV2

``H`` is read live from the chain's release list (``releases.json``: any release's ``activations`` or
``activation_key``/``activation_height``), never typed. No release naming the key means the switch is not scheduled:
legacy. The genesis comes from the network spec (``genesisSha256``) and must agree with the node's ``/status``.
Anything unreadable, ambiguous or contradictory is ``unknown`` and nothing is signed.

The pure functions take what was read; :func:`read_signing_phase` reads it. The web app carries the same rule;
a cross-check holds the two to identical answers.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from typing import Any, List, Optional, Union
from urllib.request import Request, urlopen

ROLLB_KEY = "aa2007_activation_height"
#: Heights below H in which nothing is signed.
ROLLB_WINDOW = 3000

_HEX64 = re.compile(r"^[0-9a-f]{64}$")


class SigningPaused(RuntimeError):
    """Raised in the window before H, or when the signing format cannot be confirmed."""


@dataclass(frozen=True)
class SigningPhase:
    #: "legacy" | "window" | "genesis-bound" | "unknown"
    kind: str
    H: Optional[int] = None
    head: Optional[int] = None
    genesis: Optional[str] = None
    reason: Optional[str] = None

    @property
    def heights_to_go(self) -> Optional[int]:
        return (self.H - self.head) if self.kind == "window" and self.H is not None and self.head is not None else None


def _is_height(v: Any) -> bool:
    return isinstance(v, int) and not isinstance(v, bool) and 0 < v <= 2**53 - 1


def _is_activation(v: Any) -> bool:
    """An activation height may be 0: a chain started with the rule already in force (a relaunched test network)."""
    return isinstance(v, int) and not isinstance(v, bool) and 0 <= v <= 2**53 - 1


def activation_height(releases: Any, chain_id: int) -> Union[int, None, str]:
    """H from releases.json: an int, None when no release names the key, or an error string."""
    if not isinstance(releases, dict) or not isinstance(releases.get("releases"), list):
        return "the chain's release list could not be read"
    if releases.get("chain_id") != chain_id:
        return f"the release list is for chain {releases.get('chain_id')}, not {chain_id}"
    found = set()
    for rel in releases["releases"]:
        if not isinstance(rel, dict):
            continue
        if rel.get("activation_key") == ROLLB_KEY:
            if not _is_activation(rel.get("activation_height")):
                return f"a release names {ROLLB_KEY} without a valid height"
            found.add(rel["activation_height"])
        acts = rel.get("activations")
        if isinstance(acts, list):
            for a in acts:
                if isinstance(a, dict) and a.get("key") == ROLLB_KEY:
                    if not _is_activation(a.get("height")):
                        return f"a release names {ROLLB_KEY} without a valid height"
                    found.add(a["height"])
    if len(found) > 1:
        return f"the release list names {ROLLB_KEY} at {len(found)} different heights"
    return next(iter(found)) if found else None


def genesis_from(spec: Any, status_genesis: Any = None) -> Union[str, "tuple[str]"]:
    """The genesis to sign with (spec ``genesisSha256``, lower-case, no 0x), or ``(error,)``."""
    g = spec.get("genesisSha256") if isinstance(spec, dict) else None
    if not isinstance(g, str):
        return ("the network spec does not publish the genesis",)
    s = g.lower()
    s = s[2:] if s.startswith("0x") else s
    if not _HEX64.match(s):
        return ("the network spec publishes a malformed genesis",)
    if isinstance(status_genesis, str):
        n = status_genesis.lower()
        n = n[2:] if n.startswith("0x") else n
        if n != s:
            return ("the network spec and the node disagree about the genesis",)
    return s


def signing_phase(releases: Any, chain_id: int, head: Optional[int], spec: Any, status_genesis: Any = None) -> SigningPhase:
    """The phase for a signature made now. ``head`` is the chain's current height (None = unreadable)."""
    H = activation_height(releases, chain_id)
    if isinstance(H, str):
        return SigningPhase("unknown", reason=H)
    if H is None:
        return SigningPhase("legacy", H=None, head=head)
    if not _is_height(head):
        return SigningPhase("unknown", reason="the chain's current height could not be read")
    if head < H - ROLLB_WINDOW:
        return SigningPhase("legacy", H=H, head=head)
    if head < H:
        return SigningPhase("window", H=H, head=head)
    g = genesis_from(spec, status_genesis)
    if isinstance(g, tuple):
        return SigningPhase("unknown", reason=g[0])
    return SigningPhase("genesis-bound", H=H, head=head, genesis=g)


def refusal_text(phase: SigningPhase) -> Optional[str]:
    """Plain words for a phase in which nothing may be signed; None when signing is allowed."""
    if phase.kind == "window":
        return (f"The chain switches its signing format at height {phase.H:,}, {phase.heights_to_go:,} heights from now. "
                "Signing is paused until it passes, so nothing you sign lands in the wrong format. Try again in a few minutes.")
    if phase.kind == "unknown":
        return (f"The signing format the chain expects right now can't be confirmed ({phase.reason}). "
                "Nothing was signed. Try again in a moment.")
    return None


def require_signable(phase: SigningPhase) -> SigningPhase:
    """Raise :class:`SigningPaused` in the window or when unknown; otherwise return the phase."""
    t = refusal_text(phase)
    if t:
        raise SigningPaused(t)
    return phase


def with_genesis_line(lines: List[str], phase: SigningPhase) -> List[str]:
    """EIP-191 messages from H: insert ``Genesis: <sha256>`` as line 3, directly after ``Chain: <id>``."""
    if phase.kind == "legacy":
        return list(lines)
    require_signable(phase)
    if len(lines) < 2 or not lines[1].startswith("Chain: "):
        raise ValueError('an EIP-191 message must carry "Chain: <id>" as line 2')
    return [lines[0], lines[1], f"Genesis: {phase.genesis}", *lines[2:]]


def _get_json(url: str, timeout: float) -> Any:
    req = Request(url, headers={"User-Agent": "vordium-sdk", "Cache-Control": "no-store"})
    with urlopen(req, timeout=timeout) as r:  # noqa: S310 - https URLs from the resolved network
        return json.loads(r.read().decode("utf-8"))


def read_signing_phase(rpc_url: Optional[str] = None, spec_url: Optional[str] = None,
                       chain_id: Optional[int] = None, timeout: float = 8.0) -> SigningPhase:
    """Read releases.json, the network spec and the node's /status NOW, and return the phase. Never cached: the
    answer changes at one height."""
    from .network import api_base, default_spec_url, get_network, releases_url

    net = get_network()
    base = (rpc_url or api_base(net)).rstrip("/")
    spec_url = spec_url or default_spec_url()
    cid = chain_id if chain_id is not None else net.chain_id

    def attempt(url):
        try:
            return _get_json(url, timeout)
        except Exception:  # unreadable is an answer: it makes the phase unknown (or legacy if nothing is scheduled)
            return None

    releases = attempt(releases_url(net, rpc_url))
    spec = attempt(spec_url)
    status = attempt(f"{base}/status")
    head = status.get("chain_head") if isinstance(status, dict) else None
    sg = status.get("genesis_sha256") if isinstance(status, dict) else None
    return signing_phase(releases, cid, head if _is_height(head) else None, spec, sg)
