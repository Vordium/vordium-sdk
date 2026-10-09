"""Bridge v4: the client rules for deposits into the v4 vault and withdrawals out of it.

``ENABLED`` is True. Set it False and every function that produces something to sign or to send refuses
(``BridgeV4Off``); the read parsers and the wording helpers stay usable.

Rules:
  * a deposit is built only while the chain says deposits from that chain are open (``depositsOpen`` is ``true``),
    and only at or above that chain's minimum -- refused BEFORE anything is signed;
  * a deposit from Arc is built only when the sending address can also act on Arbitrum (a refused deposit is claimed
    back there, by that address);
  * the minimums come from the vault read, per source chain -- never typed here;
  * a withdrawal intent signs a deadline: suggested now + 10 minutes, never past, never more than 24 h ahead;
  * the next nonce comes from the chain's read; the submit body is exactly the published shape; a refusal is read by
    its stable code, never by its text;
  * the maximum CCTP fee is the quote plus a 25 % margin: the protocol fee exact, one ceiling, then up to 0.001 USDC;
  * users see only pending / paid / refunded (withdrawals) and pending / credited / not accepted (deposits).

Contracts (see ``V34``):
  * above the per-deposit limit (2), and code 7, the USDC is claimed back on Arbitrum by the deposit's account; the owed
    address claims to its own wallet (claimRefund) or to another address typed in full with its checksum (claimRefundTo),
    never the handler and never the vault;
  * a withdrawal above the vault's per-withdrawal maximum (``withdrawals.maximum_6dec``) is refused before anything is
    signed;
  * a CCTP deposit this SDK creates names the handler as its destination caller; a Circle-forwarded one names none;
  * the handler is the one the vault created (CREATE(vault, nonce 1)), and the vault read confirms it is bound to that
    vault;
  * the fee quote has one name: ``quoteUrl`` (a URL template) + ``forwardParam``;
  * a validator signature is 65 bytes with v 27 or 28 and a low s -- the vault refuses any other form;
  * the account credited on Vordium is a key-held address (no contract code, or an EIP-7702 delegation);
  * "send it yourself" sends the payout's public ready call unchanged, after checking every field against the
    user's own withdrawal, the pinned vault, the deadline and the chain's answers about that payout.

Reads: the chain facts a rule needs come from the public bridge routes -- the vaults (live
code hashes and the handler's binding), deposit-allowed, account code, a deposit by transaction, an account's deposits,
the payout's call. A live read is made from two sources that agree, or it says ``"read": "unavailable"``: then the value
is unavailable here too and nothing is built on it -- never a guess, never a fallback. A not-accepted deposit is read by
its stable ``reason`` key, never by its text. No read says "waiting": whether a deposit would wait is known only BEFORE
the burn, from deposit-allowed's coarse outcome (accepted / waits / above the per-deposit limit); after it arrives a
deposit reads "pending" until it is credited. The finer codes behind that outcome are neither returned nor kept.

Amounts are ints in USDC base units (6 decimals).
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, replace
from typing import Any, Dict, List, Optional, Sequence, Tuple

ENABLED = True


class BridgeV4Off(RuntimeError):
    """Bridge v4 is not open in this SDK yet."""

    def __init__(self) -> None:
        super().__init__("Bridge v4 is not open in this SDK yet.")


def _require_open() -> None:
    if not ENABLED:
        raise BridgeV4Off()


ROUTES: Tuple[Tuple[int, str], ...] = (
    (0, "local"), (1, "standard"), (2, "fast"), (3, "standard-forwarded"), (4, "fast-forwarded"),
)
_ROUTE_NAME = dict(ROUTES)
_FINALITY = {1: 2000, 2: 1000, 3: 2000, 4: 1000}
_FORWARDED = {3, 4}

#: ``encoders`` turns on the encoders whose bytes depend on the deployed contracts -- the handler as a CCTP
#: deposit's destination caller, and a refund claimed to another address (claimRefundTo) -- built from the published client
#: ABI and checked against its vectors. ``max_per_withdrawal_field`` is the vault read's name for the per-withdrawal maximum
#: (``vaults[].withdrawals.maximum_6dec``); with ``encoders`` on, a maximum that cannot be read refuses the withdrawal. This
#: switch is not the bridge's own: ``ENABLED`` above still decides whether anything is built at all.
V34: Dict[str, Any] = {"encoders": True, "max_per_withdrawal_field": "maximum_6dec"}

INTENT_MAX_TTL_S = 86_400
INTENT_DEFAULT_TTL_S = 600

#: sha256 of the three contracts' runtime code. The vault creates its handler (CREATE nonce 1) and its
#: set rules (CREATE nonce 2), so the vault's creation code (without constructor arguments) carries both; the handler's
#: creation code is the slice the vault deploys at nonce 1. The deployed addresses come from the network spec.
PINS = {
    "interface": "v3.5",
    "vault": {"runtime": "b9b4ef3e5c9f242bda6708acc5c224689b05d26b918c003a1330d504a5fcb84e", "runtimeBytes": 23_781,
              "creation": "a468c04cf424248d6b1a4007de9040294471932340ecc5ab92a0b8f178394708", "creationBytes": 42_681},
    "handler": {"runtime": "22ce002c903bc47181375a8bc5658111b9327a5ca6e6569122785f4abd8a32c4", "runtimeBytes": 11_242,
                "creation": "03880ed503169f0e4ef908dd70bb6d110eace8620fb50c3939d6f8ef51685d26", "creationBytes": 11_774},
    "setRules": {"runtime": "0240b522204b01e84b837954214462fae35fb5e28e9f5952145b434fbb510040", "runtimeBytes": 2_662},
}
#: The test-network-only vault build (refused on every main network): recognised so it is named, never accepted.
#: Where the pinned code is deployed is read from the live network spec (``bridge``: chainId, address, handler) at the
#: moment of use, never typed here: see deployments_from_spec. The handler must be CREATE(vault, 1); the set rules are
#: CREATE(vault, 2). A vaults read naming another vault or handler on that chain is not used (deployment_check).
TESTNET_VAULT_PIN = {"runtime": "fc23e84c2f73809bc8896032d45399babf28dacf259221c23d1cf4ee8840d86e", "runtimeBytes": 22_471}
#: The CREATE nonces of the contracts the vault deploys itself.
VAULT_CREATES = {"handler": 1, "setRules": 2}
#: The CCTP domains whose addresses are 20 bytes (EVM chains): a recipient word for one of them must carry zeros in its
#: upper 12 bytes. Ethereum, Arbitrum and Arc -- every domain a payout is offered to.
EVM_DOMAINS: Tuple[int, ...] = (0, 3, 26)
LINE_OWN_ADDRESS = "That is the bridge's own contract: the USDC would be stuck there."

WITHDRAW_INTENT_FIELDS: Tuple[Tuple[str, str], ...] = (
    ("account", "address"), ("vaultId", "uint32"), ("recipient", "bytes32"), ("amount", "uint256"),
    ("nonce", "uint256"), ("routeKind", "uint8"), ("destinationDomain", "uint32"), ("maxFee", "uint256"),
    ("deadline", "uint64"),
)
WITHDRAW_INTENT_TYPE = "WithdrawIntentV4(" + ",".join(f"{t} {n}" for n, t in WITHDRAW_INTENT_FIELDS) + ")"

#: The vault's payout message, as the validators sign it (field order = the ABI tuple).
WITHDRAW_V2_FIELDS: Tuple[Tuple[str, str], ...] = (
    ("account", "address"), ("recipient", "bytes32"), ("amount", "uint256"), ("nonce", "uint256"),
    ("routeKind", "uint8"), ("destinationDomain", "uint32"), ("maxFee", "uint256"), ("epoch", "uint64"),
    ("deadline", "uint64"),
)

#: claimRefund() / claimRefundTo(address) on the handler -- sent by the address that is owed, and only by it.
CLAIM_REFUND_SELECTOR = "0xb5545a3c"
CLAIM_REFUND_TO_SELECTOR = "0x38f83332"
#: The handler's reason codes: 1, 3, 4 wait (a waiting record, finished later); 2, 7, 8 are owed to the
#: deposit's beneficiary; 5 is stranded -- owed to nobody until a recovery; 9 is owed by a recovery to a named address; 6
#: owes nothing. Clients read only deposit-allowed's coarse meaning of them and the deposit reads' reason keys.
HANDLER_REASONS: Dict[str, Any] = {"waits": [1, 3, 4], "refundsToBeneficiary": [2, 7, 8], "stranded": [5], "rescued": 9}


def handler_reason(code: Any) -> Optional[str]:
    """The published reason key of a handler code (``nothing`` for 6), or None."""
    if isinstance(code, bool) or not isinstance(code, int):
        return None
    if code in HANDLER_REASONS["waits"]:
        return "waits"
    if code in HANDLER_REASONS["refundsToBeneficiary"]:
        return "refundsToBeneficiary"
    if code in HANDLER_REASONS["stranded"]:
        return "stranded"
    if code == HANDLER_REASONS["rescued"]:
        return "rescued"
    return "nothing" if code == 6 else None
#: withdraw(WithdrawV2, bytes[]) on the vault -- anyone may send a validator-signed payout.
WITHDRAW_SELECTOR = "0xe8c13bb8"
# Deposits: USDC approve, the vault's deposit(uint256); CCTP V2 depositForBurnWithHook.
APPROVE_SELECTOR = "0x095ea7b3"
DEPOSIT_SELECTOR = "0xb6b55f25"
DEPOSIT_FOR_BURN_WITH_HOOK_SELECTOR = "0x779b432d"
# A deposit from Arc asks for standard finality (Arc's finality is deterministic).
CCTP_DEPOSIT_FINALITY = 2000

CHAIN_NAMES = {"42161": "Arbitrum", "5042": "Arc"}
DOMAIN_NAMES = {0: "Ethereum", 3: "Arbitrum", 26: "Arc"}

#: The words a user sees. Nothing else from a payout's or a deposit's life is shown. A payout that could not be paid yet
#: is still ``pending`` (it stays queued and is retried) -- never "held" or "lost"; it reads ``refunded`` only once cancelled.
WITHDRAWAL_STATUSES = ("pending", "paid", "refunded")
DEPOSIT_STATUSES = ("pending", "credited", "waiting", "stranded", "not accepted")
#: A deposit's stable reason key: ``waiting`` (codes 1, 3, 4) and ``stranded`` (5) go with the statuses
#: of the same name; the rest with ``not accepted``. Match the key, never the read's text.
DEPOSIT_REASONS = ("waiting", "stranded", "rescued", "above_per_deposit_limit", "not_completed", "below_minimum", "other")
#: The reason keys a not-accepted deposit carries, and those whose row must carry a claim (owed to someone).
NOT_ACCEPTED_REASONS = ("rescued", "above_per_deposit_limit", "not_completed", "below_minimum", "other")
OWED_REASONS = ("rescued", "above_per_deposit_limit", "not_completed")
#: deposit-allowed's coarse outcome -- all a client may use of it.
DEPOSIT_OUTCOMES = ("accepted", "waits", "above_per_deposit_limit")

#: Said before the burn when deposit-allowed answers that a deposit would wait: it is kept and credited when they reopen.
LINE_WAITING = "Waiting: deposits are paused or at a limit. It will be credited when they reopen."
LINE_OVER_CAP = ("Not accepted: above the per-deposit limit. The USDC can be claimed back on Arbitrum by the deposit's "
                 "account.")
LINE_NOT_COMPLETED = ("Not accepted: the deposit could not be completed. The USDC can be claimed back on Arbitrum by "
                      "the deposit's account.")
#: Code 5: stranded -- nobody is owed it until a recovery; nothing to claim.
LINE_STRANDED = "Waiting for a recovery: the deposit's account could not be read. Nothing is lost."
#: Code 9: owed by a recovery to a named address, claimed on the vault's chain.
LINE_RESCUED = "Owed to you on Arbitrum by a recovery: claim it there."
#: A payout not paid yet, and one that was cancelled.
LINE_PAYOUT_PENDING = "The payout is sent as soon as it can be. Nothing to do."
LINE_PAYOUT_REFUNDED = "The payout was cancelled and the amount returned to your account on Vordium."
LINE_NOT_ACCEPTED = "Not accepted."
#: The Waiting line before the burn, and what pressing Deposit again does.
LINE_WILL_WAIT = LINE_WAITING + " Press Deposit again to send it anyway."
#: The word shown for each public status.
STATUS_WORD = {"pending": "Pending", "credited": "Credited", "waiting": "Waiting", "stranded": "Waiting for a recovery",
               "not accepted": "Not accepted", "paid": "Paid", "refunded": "Refunded"}
#: What a client says for a read that answered "unavailable" (two sources did not agree, or one could not be read).
LINE_UNAVAILABLE = "Unavailable right now."

#: POST /bridge/v4/withdraw refusals: each stable code -> (HTTP status, the one message a user sees, outcome).
INTAKE_CODES: Dict[str, Tuple[int, str, str]] = {
    "inactive": (403, "Withdrawals are not open yet.", "refused"),
    "malformed": (400, "The withdrawal request could not be read. Please try again.", "refused"),
    "bad_recipient": (400, "The destination address is not valid.", "refused"),
    "bad_signature_encoding": (400, "The signature could not be read. Please sign again.", "refused"),
    "bad_signature": (403, "The signature does not match this account. Please sign again from the same wallet.", "refused"),
    "expired": (400, "This withdrawal request expired. Please try again.", "resign"),
    "deadline_too_far": (400, "This withdrawal request's time limit is too far ahead. Please try again.", "resign"),
    "unknown_vault": (404, "This withdrawal destination is not available.", "refused"),
    "below_fee": (400, "The amount does not cover the withdrawal fee.", "refused"),
    "route_refused": (400, "This withdrawal route is not available right now.", "refused"),
    "nonce_used": (409, "This withdrawal was already submitted.", "duplicate"),
    "over_maximum": (400, "Above the per-withdrawal maximum. Please withdraw in smaller parts.", "refused"),
}
MESSAGE_ALREADY_PENDING = "This withdrawal is already being processed."
MESSAGE_SUBMITTED = "Withdrawal submitted."
MESSAGE_UNKNOWN = "The withdrawal was not accepted. Please try again later."

#: The withdrawal screen's gas line: the payout is sent for the user, so the user needs no ETH on Arbitrum.
LINE_NO_ETH = "No ETH needed"
LINE_SELF_SEND_GAS = "Whoever sends this payout pays its network fee (gas) in ETH on Arbitrum. If you send it yourself, that is you."
# How long a payout's call must have read ready before a client offers to send it by hand.
SELF_SEND_AFTER_MS = 180_000
#: Circle's fee quote: one name everywhere -- the URL template ``quoteUrl`` and ``forwardParam`` -- and the frozen margin rule.
FEE_QUOTE_RULE = {
    "source": "circle", "quoteUrl": "https://iris-api.circle.com/v2/burn/USDC/fees/{sourceDomain}/{destDomain}",
    "forwardParam": "forward=true", "appliesTo": ("standard", "fast", "standard-forwarded", "fast-forwarded"),
    "marginBps": 2500, "roundUp6dec": 1000,
}

FORWARD_HEADER_V0 = "0x636374702d666f72776172640000000000000000000000000000000000000000"

_ADDR = re.compile(r"^0x[0-9a-fA-F]{40}$")
_B32 = re.compile(r"^0x[0-9a-fA-F]{64}$")
_DEC = re.compile(r"[0-9]+(\.[0-9]+)?")


def units(x: Any) -> Optional[int]:
    """A decimal amount in base units, as a string or a safe integer; anything else is unreadable."""
    if isinstance(x, bool):
        return None
    if isinstance(x, str) and re.fullmatch(r"[0-9]+", x):
        return int(x)
    if isinstance(x, int) and 0 <= x <= 2 ** 53 - 1:
        return x
    return None


def _small(x: Any) -> Optional[int]:
    u = units(x)
    return u if u is not None and u <= 0xFFFFFFFF else None


def _strip0x(h: str) -> str:
    return h[2:] if h.startswith("0x") else h


def _is_addr(x: Any) -> bool:
    return isinstance(x, str) and bool(_ADDR.fullmatch(x))


def _is_b32(x: Any) -> bool:
    return isinstance(x, str) and bool(_B32.fullmatch(x))


def _is_hex64(x: Any) -> bool:
    return isinstance(x, str) and bool(re.fullmatch(r"(0x)?[0-9a-fA-F]{64}", x))


def _pos_int(x: Any) -> Optional[int]:
    return x if isinstance(x, int) and not isinstance(x, bool) and 0 < x <= 2 ** 53 - 1 else None


def read_as_of(x: Any) -> Optional[Dict[str, Any]]:
    """``as_of``: ``{"height"}`` for committed state, ``{"chain_id", "block"}`` for a live
    chain read -- a block is a positive number or None, never 0. None when it is neither."""
    if not isinstance(x, dict):
        return None
    if "height" in x and "chain_id" not in x:
        h = _pos_int(x["height"])
        return None if h is None else {"height": h}
    if "chain_id" in x and "block" in x and "height" not in x:
        c = _pos_int(x["chain_id"])
        if c is None:
            return None
        if x["block"] is None:
            return {"chainId": c, "block": None}
        b = _pos_int(x["block"])
        return None if b is None else {"chainId": c, "block": b}
    return None


def usdc(v: int) -> str:
    """5000000 -> "5", 5250000 -> "5.25"."""
    whole, frac = divmod(v, 1_000_000)
    f = f"{frac:06d}".rstrip("0")
    return f"{whole}.{f}" if f else f"{whole}"


def _chain_name(cid: str) -> str:
    return CHAIN_NAMES.get(cid, f"chain {cid}")


# ---- fees --------------------------------------------------------------------------------------------------------------


def max_fee_from_quote(amount: int, minimum_fee_bps: str, forward_fee: int) -> int:
    """maxFee = roundUp(1000, ceil((protocolFee + forwardFee) * 125 / 100)), protocolFee = amount * minimumFee / 10000.
    ``minimum_fee_bps`` is the quote's decimal as written ("1", "1.3"): protocolFee stays exact, one ceiling is taken
    after the margin, then the result goes up to a multiple of 1,000 base units."""
    m = re.fullmatch(r"([0-9]+)(?:\.([0-9]+))?", minimum_fee_bps or "")
    if not m or amount < 0 or forward_fee < 0:
        raise ValueError("unreadable fee quote")
    frac = m.group(2) or ""
    num, den = int(m.group(1) + frac), 10 ** len(frac)
    margin, step = 10_000 + FEE_QUOTE_RULE["marginBps"], FEE_QUOTE_RULE["roundUp6dec"]
    top, bottom = (amount * num + forward_fee * 10_000 * den) * margin, 10_000 * den * 10_000
    with_margin = -(-top // bottom)
    return -(-with_margin // step) * step


def quote_for(quote: Any, route_kind: int) -> Optional[Tuple[str, int]]:
    """The quote row for a route -> (minimumFee as written, forwardFee.high for a forwarded route else 0)."""
    fin = _FINALITY.get(route_kind)
    if not fin or not isinstance(quote, list):
        return None
    row = next((r for r in quote if isinstance(r, dict) and r.get("finalityThreshold") == fin), None)
    if row is None:
        return None
    mf = row.get("minimumFee")
    if isinstance(mf, bool):
        return None
    if isinstance(mf, int) and mf >= 0:
        mfs = str(mf)
    elif isinstance(mf, float) and mf >= 0 and mf == mf and mf != float("inf"):
        mfs = repr(mf)
        if mfs.endswith(".0"):
            mfs = mfs[:-2]
        if "e" in mfs.lower():
            return None
    elif isinstance(mf, str) and _DEC.fullmatch(mf):
        mfs = mf
    else:
        return None
    if route_kind not in _FORWARDED:
        return mfs, 0
    fw = row.get("forwardFee")
    hi = units(fw.get("high")) if isinstance(fw, dict) else None
    return None if hi is None else (mfs, hi)


@dataclass(frozen=True)
class FeeQuote:
    ok: bool
    error: str = ""
    quote_url: str = ""
    forward_param: str = ""
    applies_to: Tuple[str, ...] = ()
    show_before_signing: Tuple[str, ...] = ()
    examples: int = 0


def read_fee_quote(fq: Any) -> FeeQuote:
    """The ``feeQuote`` object of /bridge/v4/vaults. Accepted only when it names the pinned ``quoteUrl`` and
    ``forwardParam`` (and no ``host`` / ``path`` keys), the frozen margin (2500 bps) and step (1,000),
    and when THIS module's rule reproduces every worked example it carries."""
    R = FEE_QUOTE_RULE

    def no(e: str) -> FeeQuote:
        return FeeQuote(ok=False, error=e)
    if not isinstance(fq, dict):
        return no("the fee quote is missing")
    if "host" in fq or "path" in fq:
        return no("the fee quote carries host / path keys: its URL is quoteUrl")
    if fq.get("source") != R["source"] or fq.get("quoteUrl") != R["quoteUrl"] or fq.get("forwardParam") != R["forwardParam"]:
        return no("the fee quote names another source, quote URL or forward parameter")
    at = fq.get("appliesTo")
    if not isinstance(at, list) or "|".join(str(x) for x in at) != "|".join(R["appliesTo"]):
        return no("the fee quote applies to other routes")
    mb = fq.get("marginBps")
    if isinstance(mb, bool) or mb != R["marginBps"]:
        return no(f"the fee quote's margin is not {R['marginBps']} bps")
    if units(fq.get("roundUp6dec")) != R["roundUp6dec"]:
        return no(f"the fee quote does not round up to {R['roundUp6dec']}")
    sb = fq.get("showBeforeSigning")
    if not isinstance(sb, list) or len(sb) != 5 or not all(isinstance(s, str) for s in sb):
        return no("the fee quote does not list the five items shown before signing")
    ex = fq.get("examples")
    if not isinstance(ex, list) or not ex:
        return no("the fee quote carries no worked example")
    for e in ex:
        if not isinstance(e, dict) or not isinstance(e.get("route"), str) or e["route"] not in R["appliesTo"]:
            return no("a fee example names no CCTP route")
        amount, fwd, want = units(e.get("amount_6dec")), units(e.get("forwardFeeHigh_6dec")), units(e.get("maxFee_6dec"))
        mf = e.get("minimumFee")
        if amount is None or fwd is None or want is None or not isinstance(mf, str) or not _DEC.fullmatch(mf):
            return no(f"the fee example for {e['route']} is malformed")
        if not e["route"].endswith("forwarded") and fwd != 0:
            return no(f"the fee example for {e['route']} has a forwarding fee on a route that is not forwarded")
        got = max_fee_from_quote(amount, mf, fwd)
        if got != want:
            return no(f"the fee example for {e['route']} gives {want}; the published rule gives {got}")
    return FeeQuote(ok=True, quote_url=fq["quoteUrl"], forward_param=fq["forwardParam"],
                    applies_to=tuple(R["appliesTo"]), show_before_signing=tuple(sb), examples=len(ex))


def fee_quote_url(source_domain: int, dest_domain: int, forwarded: bool) -> str:
    """The quote URL for a route -- always the pinned template; the read only decides the domains."""
    R = FEE_QUOTE_RULE
    if isinstance(source_domain, bool) or isinstance(dest_domain, bool) or not isinstance(source_domain, int) \
            or not isinstance(dest_domain, int) or source_domain < 0 or dest_domain < 0:
        raise ValueError("not a CCTP domain")
    url = R["quoteUrl"].replace("{sourceDomain}", str(source_domain)).replace("{destDomain}", str(dest_domain))
    return url + (f"?{R['forwardParam']}" if forwarded else "")


# ---- GET /bridge/v4/vaults -------------------------------------------------------------------------------------------


@dataclass(frozen=True)
class Vault:
    id: int
    chain_id: str
    address: str
    handler: Optional[str]
    cctp_domain: int
    direct: Optional[Tuple[str, int]]            # (chain id, minimum)
    cctp: Optional[Tuple[Tuple[str, ...], int]]  # (from chain ids, minimum)
    routes: Tuple[Tuple[int, str, bool], ...]
    fee: int
    #: The per-withdrawal maximum (the vault's hour limit), once the read publishes it (V34["max_per_withdrawal_field"]).
    max_per_withdrawal: Optional[int] = None
    #: sha256 of the vault's and the handler's live runtime code, read from two sources (
    #: B5); None when the read did not carry it or could not confirm it. The client compares them with the pins itself.
    runtime_sha_vault: Optional[str] = None
    runtime_sha_handler: Optional[str] = None
    #: The handler's binding: the vault it names, its CCTP domain, its USDC, and whether the read confirmed all three.
    binding_handler_vault: Optional[str] = None
    binding_local_domain: Optional[int] = None
    binding_usdc: Optional[str] = None
    binding_confirmed: Optional[bool] = None
    #: What the vaults read publishes of the vault's own contracts, when it does (a node release adds them; None = not
    #: published, and everything still works from the vault's address alone): its set rules, every own address (vault,
    #: handler, set rules, each listed Vordium contract that is a 20-byte address), every listed contract word, its EVM domains.
    pub_set_rules: Optional[str] = None
    pub_own_addresses: Optional[Tuple[str, ...]] = None
    pub_vordium_contracts: Optional[Tuple[str, ...]] = None
    pub_evm_domains: Optional[Tuple[int, ...]] = None


@dataclass(frozen=True)
class VaultsRead:
    ok: bool
    error: str = ""
    active: bool = False
    vaults: Tuple[Vault, ...] = ()
    deposits_open: Tuple[Tuple[str, Optional[bool]], ...] = ()
    minimums: Tuple[Tuple[str, int], ...] = ()
    withdrawal_fee: int = 0
    height: Optional[int] = None
    fee_quote: FeeQuote = FeeQuote(ok=False, error="not read")
    read_at: Optional[float] = None   # time.monotonic() when the read arrived; None = not read from the network

    def open_for(self, cid: str) -> Optional[bool]:
        return dict(self.deposits_open).get(cid)

    def minimum_for(self, cid: str) -> Optional[int]:
        return dict(self.minimums).get(cid)


def read_vaults(j: Any) -> VaultsRead:
    """Reads the public vault list; anything not in the published shape is refused whole."""
    def no(e: str) -> VaultsRead:
        return VaultsRead(ok=False, error=e)
    if not isinstance(j, dict) or not isinstance(j.get("active"), bool) or not isinstance(j.get("vaults"), list):
        return no("the vault list is not in the published shape")
    fee = units(j.get("withdrawalFee6dec"))
    if fee is None:
        return no("withdrawalFee6dec is not a base-unit amount")
    opens, mins = j.get("depositsOpen"), j.get("minimumDeposit6dec")
    if not isinstance(opens, dict) or not isinstance(mins, dict):
        return no("depositsOpen / minimumDeposit6dec missing")
    order: List[str] = []
    minimums: Dict[str, int] = {}

    def seen(cid: str, m: int) -> Optional[str]:
        served = units(mins.get(cid))
        if served is None:
            return f"minimumDeposit6dec has no amount for chain {cid}"
        if served != m:
            return f"the minimum for chain {cid} disagrees between the vault and minimumDeposit6dec"
        if cid not in order:
            order.append(cid)
            minimums[cid] = m
        return None

    vaults: List[Vault] = []
    for v in j["vaults"]:
        if not isinstance(v, dict):
            return no("a vault entry is not an object")
        vid, cid, dom = _small(v.get("id")), _small(v.get("chain_id")), _small(v.get("cctp_domain"))
        if vid is None or cid is None or dom is None or not _is_addr(v.get("address")):
            return no("a vault entry lacks id / chain_id / address / cctp_domain")
        handler = v.get("handler")
        if handler is not None and not _is_addr(handler):
            return no(f"vault {vid}: handler is not an address")
        dep = v.get("deposits") if isinstance(v.get("deposits"), dict) else {}
        direct = cctp = None
        if isinstance(dep.get("direct"), dict):
            c, m = _small(dep["direct"].get("chain_id")), units(dep["direct"].get("minimum_6dec"))
            if c is None or m is None:
                return no(f"vault {vid}: direct deposits lack chain_id / minimum_6dec")
            direct = (str(c), m)
            e = seen(str(c), m)
            if e:
                return no(e)
        if isinstance(dep.get("cctp"), dict):
            m = units(dep["cctp"].get("minimum_6dec"))
            fr = dep["cctp"].get("from_chain_ids")
            ids = [_small(x) for x in fr] if isinstance(fr, list) else None
            if m is None or ids is None or any(x is None for x in ids):
                return no(f"vault {vid}: CCTP deposits lack from_chain_ids / minimum_6dec")
            cctp = (tuple(str(x) for x in ids), m)
            for c in cctp[0]:
                e = seen(c, m)
                if e:
                    return no(e)
        w = v.get("withdrawals")
        if not isinstance(w, dict) or not isinstance(w.get("routes"), list):
            return no(f"vault {vid}: no withdrawal routes")
        routes = []
        for r in w["routes"]:
            kind = _small(r.get("route_kind")) if isinstance(r, dict) else None
            if kind is None or not isinstance(r.get("open"), bool):
                return no(f"vault {vid}: a route entry is malformed")
            if _ROUTE_NAME.get(kind) != r.get("name"):
                return no(f'vault {vid}: route {kind} is named "{r.get("name")}", not one of the route names')
            routes.append((kind, r["name"], r["open"]))
        vfee = units(w.get("fee_6dec"))
        if vfee is None or vfee != fee:
            return no(f"vault {vid}: its withdrawal fee disagrees with withdrawalFee6dec")
        maxw = None
        field = V34["max_per_withdrawal_field"]
        if field is not None and field in w:
            maxw = units(w.get(field))
            if maxw is None or maxw <= 0:
                return no(f"vault {vid}: its per-withdrawal maximum is not a positive amount")
        rs = v.get("runtime_sha256")
        if rs is not None and not isinstance(rs, dict):
            return no(f"vault {vid}: runtime_sha256 is not an object")
        rs = rs or {}

        def sha(x: Any) -> Tuple[bool, Optional[str]]:
            if x is None:
                return True, None
            return (True, _strip0x(x.lower())) if _is_hex64(x) else (False, None)
        okv, rv = sha(rs.get("vault"))
        okh, rh = sha(rs.get("handler"))
        if not okv or not okh:
            return no(f"vault {vid}: a runtime_sha256 is not a sha256")
        bd = v.get("binding")
        if bd is not None and not isinstance(bd, dict):
            return no(f"vault {vid}: binding is not an object")
        bd = bd or {}
        bv, bu, bdom, bc = bd.get("handler_vault"), bd.get("usdc"), bd.get("local_domain"), bd.get("confirmed")
        if (bv is not None and not _is_addr(bv)) or (bu is not None and not _is_addr(bu)) \
                or (bdom is not None and _small(bdom) is None) or (bc is not None and not isinstance(bc, bool)):
            return no(f"vault {vid}: its binding is malformed")
        # published with a node release: optional, but when present each must be exactly its shape, or the read is refused
        ps, po, pw, pe = v.get("set_rules"), v.get("own_addresses"), v.get("vordium_contracts"), v.get("evm_domains")
        if ps is not None and not _is_addr(ps):
            return no(f"vault {vid}: set_rules is not an address")
        if po is not None and (not isinstance(po, list) or not all(_is_addr(a) for a in po)):
            return no(f"vault {vid}: own_addresses is not a list of addresses")
        if pw is not None and (not isinstance(pw, list) or not all(_is_b32(x) for x in pw)):
            return no(f"vault {vid}: vordium_contracts is not a list of 32-byte words")
        if pe is not None and (not isinstance(pe, list) or not all(_small(d) is not None for d in pe)):
            return no(f"vault {vid}: evm_domains is not a list of domains")
        vaults.append(Vault(vid, str(cid), v["address"], handler, dom, direct, cctp, tuple(routes), vfee, maxw,
                            rv, rh, bv, None if bdom is None else _small(bdom), bu, bc,
                            None if ps is None else ps.lower(), None if po is None else tuple(a.lower() for a in po),
                            None if pw is None else tuple(x.lower() for x in pw), None if pe is None else tuple(_small(d) for d in pe)))
    dopen = []
    for cid in order:
        o = opens.get(cid)
        dopen.append((cid, True if o is True else False if o is False else None))
    as_of = j.get("as_of")
    h = _small(as_of.get("height")) if isinstance(as_of, dict) else None
    return VaultsRead(ok=True, active=j["active"], vaults=tuple(vaults), deposits_open=tuple(dopen),
                      minimums=tuple((c, minimums[c]) for c in order), withdrawal_fee=fee, height=h,
                      fee_quote=read_fee_quote(j.get("feeQuote")))


def below_minimum_line(v: VaultsRead) -> Optional[str]:
    """ "Not accepted: below the minimum deposit (5 USDC from Arbitrum, 10 USDC from Arc)." -- figures from the read."""
    if not v.ok or not v.minimums:
        return None
    parts = [f"{usdc(m)} USDC from {_chain_name(c)}" for c, m in v.minimums]
    return f"Not accepted: below the minimum deposit ({', '.join(parts)})."


# ---- deposits ----------------------------------------------------------------------------------------------------------


def read_account_code(http_status: int, body: Any, chain_id: Any, address: str) -> Dict[str, Any]:
    """GET /bridge/v4/account-code/{chainId}/{address}: whether an address holds contract
    code on a chain, read from two sources -> {"ok": True, "kind": wallet | delegated-wallet | contract} or {"ok": False}
    for anything else ("read": "unavailable", another address or chain, a block that is not positive, a delegation
    without code)."""
    no: Dict[str, Any] = {"ok": False}
    if http_status != 200 or not isinstance(body, dict) or body.get("read") != "ok" or not _is_addr(address) \
            or not _is_addr(body.get("address")) or body["address"].lower() != address.lower():
        return no
    at = read_as_of(body.get("as_of"))
    if not at or "chainId" not in at or str(at["chainId"]) != str(chain_id) or at["block"] is None:
        return no
    if not isinstance(body.get("has_code"), bool):
        return no
    if "delegation" not in body or (body["delegation"] is not None and not _is_addr(body["delegation"])):
        return no
    if not body["has_code"]:
        return {"ok": True, "kind": "wallet"} if body["delegation"] is None else no
    return {"ok": True, "kind": "contract" if body["delegation"] is None else "delegated-wallet"}


@dataclass(frozen=True)
class SenderCheck:
    ok: bool
    kind: str = ""            # wallet | delegated-wallet | contract-on-arbitrum
    reason: str = ""          # unreadable | contract-not-on-arbitrum
    text: str = ""


_SENDER_UNREADABLE = "Your wallet's type cannot be confirmed right now, so nothing was built."


def sender_check(arc: Optional[Dict[str, Any]], arbitrum: Optional[Dict[str, Any]]) -> SenderCheck:
    """Can the address that sends a deposit from Arc act at the same address on Arbitrum? A refused deposit is owed
    there, to that address. A plain wallet always can, and so can a key-held wallet with an EIP-7702 delegation; a
    contract wallet can only if it exists on Arbitrum too. ``arc`` / ``arbitrum`` are read_account_code answers for the
    sending address (None = not read)."""
    if not arc or not arc.get("ok"):
        return SenderCheck(False, reason="unreadable", text=_SENDER_UNREADABLE)
    if arc["kind"] != "contract":
        return SenderCheck(True, kind=arc["kind"])
    if not arbitrum or not arbitrum.get("ok"):
        return SenderCheck(False, reason="unreadable", text=_SENDER_UNREADABLE)
    if arbitrum["kind"] != "contract":
        return SenderCheck(False, reason="contract-not-on-arbitrum",
                           text="This is a smart-contract wallet that does not exist on Arbitrum. A deposit that is not "
                                "accepted can only be claimed back on Arbitrum by the same address, so nothing was built. "
                                "Deposit from a wallet that also exists on Arbitrum.")
    return SenderCheck(True, kind="contract-on-arbitrum")


def key_held_check(code: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """The account credited on Vordium must be an ordinary key-held address (a wallet with no code, or one with an
    EIP-7702 delegation): a contract address cannot sign on Vordium. ``code`` is the read_account_code answer."""
    if not code or not code.get("ok"):
        return {"ok": False, "text": "Your wallet's type cannot be confirmed right now, so nothing was built."}
    if code["kind"] != "contract":
        return {"ok": True}
    return {"ok": False, "text": "Deposits are credited to the depositing address on Vordium, and that must be a wallet with its own key, not a smart-contract wallet. Deposit from a key-held wallet."}


def read_deposit_allowed(http_status: int, body: Any, vault_chain_id: Any) -> Dict[str, Any]:
    """GET /bridge/v4/deposit-allowed/{chainId}/{sender}/{amount} -> its coarse outcome
    only: {"ok": True, "outcome": accepted | waits | above_per_deposit_limit} or {"ok": False}. Read from ``outcome`` when
    the answer carries one, else from ``allowed`` + ``code`` (1, 3, 4 wait; 2 is above the per-deposit limit; nothing
    finer). The code is neither returned nor kept."""
    no: Dict[str, Any] = {"ok": False}
    if http_status != 200 or not isinstance(body, dict) or body.get("read") != "ok":
        return no
    at = read_as_of(body.get("as_of"))
    if not at or "chainId" not in at or str(at["chainId"]) != str(vault_chain_id) or at["block"] is None:
        return no
    if "allowed" in body and not isinstance(body["allowed"], bool):
        return no
    if "outcome" in body:
        o = body["outcome"]
        if not isinstance(o, str) or o not in DEPOSIT_OUTCOMES:
            return no
        if "allowed" in body and body["allowed"] != (o == "accepted"):
            return no
        return {"ok": True, "outcome": o}
    code = body.get("code")
    if not isinstance(body.get("allowed"), bool) or isinstance(code, bool) or not isinstance(code, int):
        return no
    if body["allowed"]:
        return {"ok": True, "outcome": "accepted"} if code == 0 else no
    if handler_reason(code) == "waits":
        return {"ok": True, "outcome": "waits"}
    if code == 2:
        return {"ok": True, "outcome": "above_per_deposit_limit"}
    return no


def pre_burn(read: Optional[Dict[str, Any]], kind: str, wait_confirmed: bool) -> Dict[str, Any]:
    """Before anything is signed: may this deposit be built, given deposit-allowed's outcome? A CCTP deposit that would
    wait is built only after the Waiting line was shown and the user confirmed (``wait_confirmed``); a deposit straight
    into the vault cannot wait, so it is not built then. Above the per-deposit limit, or not confirmable -> nothing.
    -> {"ok": True} | {"ok": False, "ask": True, "line"} | {"ok": False, "ask": False, "text"}."""
    if not read or not read.get("ok"):
        return {"ok": False, "ask": False, "text": "Whether the vault takes this deposit cannot be confirmed right now, so nothing was built."}
    if read["outcome"] == "accepted":
        return {"ok": True}
    if read["outcome"] == "above_per_deposit_limit":
        return {"ok": False, "ask": False, "text": "This deposit is above the per-deposit limit, so nothing was built."}
    if kind == "direct":
        return {"ok": False, "ask": False, "text": "Deposits are paused or at a limit right now, so nothing was built."}
    return {"ok": True} if wait_confirmed else {"ok": False, "ask": True, "line": LINE_WILL_WAIT}


@dataclass(frozen=True)
class DepositGate:
    state: str               # open | closed | unknown
    text: str = ""


#: How old a vaults read may be and still say deposits are open: 90 s, measured on a monotonic clock.
BRIDGE_READ_FRESH_S = 90.0
LINE_BRIDGE_CLOSED = "Deposits are closed for now. They will open soon."
LINE_BRIDGE_UNREAD = "The bridge could not be read right now."
LINE_BRIDGE_STALE = "The bridge read is not recent enough, so nothing is built. Read it again."
LINE_DEPLOYMENT_UNREAD = "The bridge contracts could not be read from the network spec, so nothing is built."


def read_bool_word(x: Any) -> Optional[bool]:
    """A boolean return word: exactly 32 bytes, 0 or 1 — anything else is not read."""
    if not isinstance(x, str) or not re.fullmatch(r"0x[0-9a-fA-F]{64}", x):
        return None
    if re.fullmatch(r"0x0{64}", x):
        return False
    if re.fullmatch(r"0x0{63}1", x):
        return True
    return None


def deployments_from_spec(spec: Any) -> Optional[Dict[str, Dict[str, str]]]:
    """The deployed bridge contracts as the network spec names them: ``{chain id: {vault, handler, setRules}}``. The
    handler must be the contract the vault created (CREATE(vault, 1)); the set rules are CREATE(vault, 2). None when the
    spec names no complete, consistent deployment."""
    br = spec.get("bridge") if isinstance(spec, dict) else None
    if not isinstance(br, dict):
        return None
    cid, vault, handler = br.get("chainId"), br.get("address"), br.get("handler")
    if isinstance(cid, bool) or not isinstance(cid, int) or cid <= 0 or not _is_addr(vault) or not _is_addr(handler):
        return None
    if create_address(vault, VAULT_CREATES["handler"]) != handler.lower():
        return None
    return {str(cid): {"vault": vault, "handler": handler, "setRules": create_address(vault, VAULT_CREATES["setRules"])}}


def fetch_deployments(spec_url: Optional[str] = None, timeout: float = 6.0) -> Optional[Dict[str, Dict[str, str]]]:
    """``deployments_from_spec`` of the live network spec, read at the moment of the call (never cached)."""
    from .network import default_spec_url, _fetch_spec
    url = spec_url or default_spec_url()
    return deployments_from_spec(_fetch_spec(url, timeout))


def deposit_gate(v: Optional[VaultsRead], source_chain_id: Any, deployments: Optional[Dict[str, Dict[str, str]]],
                 now: Optional[float] = None) -> DepositGate:
    """Whether deposits from ``source_chain_id`` are open. Open ONLY when the vaults read is ok, active and fresh (at most
    BRIDGE_READ_FRESH_S old on the monotonic clock), a deployed vault (``deployments``, from the network spec) is listed,
    and ``depositsOpen`` for that chain is exactly ``true``. Anything else is closed or unknown, and nothing is built."""
    if v is None or not v.ok:
        return DepositGate("unknown", LINE_BRIDGE_UNREAD)
    if not deployments:
        return DepositGate("unknown", LINE_DEPLOYMENT_UNREAD)
    if not v.active:
        return DepositGate("closed", LINE_BRIDGE_CLOSED)
    t = time.monotonic() if now is None else now
    if v.read_at is None or t - v.read_at > BRIDGE_READ_FRESH_S or t < v.read_at - 5:
        return DepositGate("unknown", LINE_BRIDGE_STALE)
    if not any((deployments.get(x.chain_id) or {}).get("vault", "").lower() == x.address.lower() for x in v.vaults):
        return DepositGate("closed", LINE_BRIDGE_CLOSED)
    op = v.open_for(str(source_chain_id))
    if op is True:
        return DepositGate("open")
    if op is False:
        return DepositGate("closed", LINE_BRIDGE_CLOSED)
    return DepositGate("unknown", "Whether deposits are open cannot be confirmed right now.")


def deployment_check(v: VaultsRead, deployments: Optional[Dict[str, Dict[str, str]]]) -> VaultsRead:
    """The vaults read names the deployed contracts: on a chain the network spec names (``deployments``) every vault must
    be that vault and its handler that handler, or the read is not used. No deployments read = the read is not used."""
    if not v.ok:
        return v
    if not deployments:
        return VaultsRead(ok=False, error="the deployed contracts could not be read from the network spec")
    for x in v.vaults:
        d = deployments.get(x.chain_id)
        if not d:
            continue
        if x.address.lower() != d["vault"].lower():
            return VaultsRead(ok=False, error=f"the vault on chain {x.chain_id} is not the deployed one")
        if not x.handler or x.handler.lower() != d["handler"].lower():
            return VaultsRead(ok=False, error=f"the handler on chain {x.chain_id} is not the deployed one")
    return v


@dataclass(frozen=True)
class DepositCheck:
    ok: bool
    reason: str = ""          # unreadable | closed | unknown | below-minimum | no-vault | sender
    text: str = ""
    kind: str = ""            # direct | cctp
    vault_id: int = 0
    vault: str = ""
    handler: Optional[str] = None
    net: int = 0


def deposit_check(v: VaultsRead, source_chain_id: Any, amount: int, max_fee: int = 0,
                  sender: Optional[SenderCheck] = None) -> DepositCheck:
    """Decides, BEFORE anything is signed, whether a deposit of ``amount`` from ``source_chain_id`` may be built. For a
    CCTP deposit ``sender`` (sender_check of the depositing address) must say that address can claim a refund on the
    vault's chain."""
    _require_open()
    if not v.ok:
        return DepositCheck(False, "unreadable", "The bridge could not be read, so nothing was built.")
    if not v.active:
        return DepositCheck(False, "closed", "Deposits are not open.")
    cid = str(source_chain_id)
    op = v.open_for(cid)
    if op is False:
        return DepositCheck(False, "closed", "Deposits are not open.")
    if op is not True:
        return DepositCheck(False, "unknown", "Whether deposits are open cannot be confirmed right now, so nothing was built.")
    direct = next((x for x in v.vaults if x.direct and x.direct[0] == cid), None)
    cctp = None if direct else next((x for x in v.vaults if x.cctp and cid in x.cctp[0]), None)
    vault = direct or cctp
    mn = v.minimum_for(cid)
    if vault is None or mn is None:
        return DepositCheck(False, "no-vault", "No vault takes deposits from this chain.")
    if amount <= 0 or max_fee < 0 or max_fee >= amount:
        return DepositCheck(False, "below-minimum", below_minimum_line(v) or "")
    net = amount if direct else amount - max_fee
    if net < mn:
        return DepositCheck(False, "below-minimum", below_minimum_line(v) or "")
    if not direct:
        if sender is None:
            return DepositCheck(False, "sender", _SENDER_UNREADABLE)
        if not sender.ok:
            return DepositCheck(False, "sender", sender.text)
    return DepositCheck(True, kind="direct" if direct else "cctp", vault_id=vault.id, vault=vault.address,
                        handler=vault.handler, net=net)


def hook_data(beneficiary: str, forwarded: bool) -> str:
    """Hook data for a CCTP deposit into the handler: the beneficiary word, or the version-0 header + that word."""
    if not _is_addr(beneficiary) or int(beneficiary, 16) == 0:
        raise ValueError("the beneficiary must be a non-zero address")
    w = "0x" + "0" * 24 + beneficiary[2:].lower()
    return FORWARD_HEADER_V0 + w[2:] if forwarded else w


# ---- withdrawals -------------------------------------------------------------------------------------------------------


def read_next_nonce(j: Any, account: str) -> Tuple[Optional[int], str]:
    """GET /bridge/v4/withdraw-nonce/{account} -> (next nonce, "") or (None, why)."""
    if not isinstance(j, dict) or not isinstance(j.get("account"), str) or j["account"].lower() != account.lower():
        return None, "the nonce read is for another account"
    nxt = units(j.get("next_nonce"))
    last = None if j.get("last_nonce") is None else units(j.get("last_nonce"))
    if nxt is None or nxt == 0:
        return None, "next_nonce is not a positive amount"
    if last is not None and nxt <= last:
        return None, "next_nonce is not above last_nonce"
    return nxt, ""


def intent_deadline(chain_now_s: float, ttl_s: int = INTENT_DEFAULT_TTL_S) -> int:
    """The deadline to sign: the CHAIN's time now + 10 minutes (never the local clock)."""
    return int(chain_now_s // 1) + ttl_s


def deadline_problem(deadline: int, chain_now_s: float) -> Optional[str]:
    now = int(chain_now_s // 1)
    if deadline <= now:
        return "The withdrawal deadline has passed. Sign again."
    if deadline - now > INTENT_MAX_TTL_S:
        return "The withdrawal deadline is more than 24 hours ahead."
    return None


@dataclass(frozen=True)
class WithdrawIntent:
    account: str
    vault_id: int
    recipient: str
    amount: int
    nonce: int
    route_kind: int
    destination_domain: int
    max_fee: int
    deadline: int


def build_withdraw_intent(v: VaultsRead, p: WithdrawIntent, next_nonce: int, chain_now_s: float) -> Tuple[Optional[WithdrawIntent], str]:
    """Checks an intent against the vault read and the route rules; returns (intent, "") or (None, why)."""
    _require_open()
    if not v.ok:
        return None, "The bridge could not be read."
    if not v.active:
        return None, "Withdrawals through this bridge are not open."
    vault = next((x for x in v.vaults if x.id == p.vault_id), None)
    if vault is None:
        return None, "Unknown vault."
    route = next((r for r in vault.routes if r[0] == p.route_kind), None)
    if route is None or not route[2]:
        return None, f"The {_ROUTE_NAME.get(p.route_kind, 'requested')} route is not open."
    if not _is_addr(p.account):
        return None, "The account is not an address."
    if not _is_b32(p.recipient) or int(p.recipient, 16) == 0:
        return None, "The recipient is not a 32-byte address word."
    # an EVM destination takes a 20-byte address; no route pays the system's own contracts
    if is_listed_contract_word(p.recipient, vault):
        return None, LINE_OWN_ADDRESS
    if is_evm_domain(vault, p.destination_domain) and not re.fullmatch(r"0x0{24}[0-9a-fA-F]{40}", p.recipient):
        return None, "The destination address is not valid."
    own = own_addresses(vault)
    if own is None:
        return None, "The bridge contracts could not be confirmed, so nothing was built."
    if is_own_address(p.recipient, own):
        return None, LINE_OWN_ADDRESS
    if p.nonce < next_nonce:
        return None, "The nonce is below the next nonce the chain expects."
    if p.amount <= v.withdrawal_fee:
        return None, "The amount does not cover the withdrawal fee."
    over = withdraw_max_problem(vault, p.amount)
    if over:
        return None, over
    if p.route_kind == 0:
        if p.destination_domain != vault.cctp_domain:
            return None, "A local payout stays on the vault's own chain."
        if p.max_fee != 0:
            return None, "A local payout has no CCTP fee."
    else:
        if not v.fee_quote.ok:
            return None, "The CCTP fee quote cannot be confirmed, so nothing was built."
        if p.destination_domain == vault.cctp_domain:
            return None, "A CCTP payout goes to another chain."
        if p.max_fee >= p.amount - v.withdrawal_fee:
            return None, "The CCTP fee would take the whole payout."
    dl = deadline_problem(p.deadline, chain_now_s)
    if dl:
        return None, dl
    return replace(p, recipient=p.recipient.lower()), ""


def withdraw_intent_message(i: WithdrawIntent) -> Dict[str, Any]:
    """The EIP-712 message (field names as the type string)."""
    return {"account": i.account, "vaultId": i.vault_id, "recipient": i.recipient, "amount": i.amount,
            "nonce": i.nonce, "routeKind": i.route_kind, "destinationDomain": i.destination_domain,
            "maxFee": i.max_fee, "deadline": i.deadline}


def withdraw_intent_signable(i: WithdrawIntent):
    """The signable EIP-712 message under the SDK's genesis-bound VordCore domain."""
    _require_open()
    from eth_account.messages import encode_typed_data
    from .eip712 import domain
    msg = withdraw_intent_message(i)
    msg["recipient"] = bytes.fromhex(i.recipient[2:])
    return encode_typed_data(domain_data=domain(),
                             message_types={"WithdrawIntentV4": [{"name": n, "type": t} for n, t in WITHDRAW_INTENT_FIELDS]},
                             message_data=msg)


def sign_withdraw_intent(private_key: str, i: WithdrawIntent) -> str:
    """Signs the intent with the ACCOUNT's owner key (a session key cannot withdraw): 65-byte r||s||v, v = 27/28."""
    _require_open()
    from eth_account import Account
    signed = Account.sign_message(withdraw_intent_signable(i), private_key=private_key)
    return "0x" + _strip0x(signed.signature.hex())


def submit_body(i: WithdrawIntent, signature: str) -> Dict[str, Any]:
    """POST /bridge/v4/withdraw -- the published body, key for key."""
    _require_open()
    if not isinstance(signature, str) or not re.fullmatch(r"0x[0-9a-fA-F]{130}", signature):
        raise ValueError("the signature is not 65 bytes")
    return {"account": i.account, "vault_id": i.vault_id, "recipient": i.recipient.lower(),
            "amount_6dec": str(i.amount), "nonce": str(i.nonce), "route_kind": i.route_kind,
            "destination_domain": i.destination_domain, "max_fee_6dec": str(i.max_fee),
            "deadline": str(i.deadline), "signature": signature.lower()}


def read_submit_response(status: int, body: Any, max_per_withdrawal: Optional[int] = None) -> Tuple[str, Optional[str], str]:
    """The answer to POST /bridge/v4/withdraw -> (outcome, code, message), read by its stable ``code`` (never its text):
    submitted | resign | refused | duplicate | unknown. A known code whose HTTP status is not the published one is not
    trusted. The chain's own error text is never shown; ``over_maximum`` carries the vault's figure when it is given."""
    if status == 202 and isinstance(body, dict) and body.get("status") == "submitted":
        return "submitted", None, MESSAGE_SUBMITTED
    code = body.get("code") if isinstance(body, dict) and isinstance(body.get("code"), str) else None
    if code is not None and code in INTAKE_CODES:
        http, message, outcome = INTAKE_CODES[code]
        if http == status and code == "over_maximum" and max_per_withdrawal is not None:
            return outcome, code, line_above_max(max_per_withdrawal)
        return (outcome, code, message) if http == status else ("unknown", code, MESSAGE_UNKNOWN)
    if status == 409 and code is None:
        return "duplicate", None, MESSAGE_ALREADY_PENDING
    return "unknown", code, MESSAGE_UNKNOWN


def pre_sign_summary(i: WithdrawIntent, fee: int) -> Dict[str, Any]:
    """What the user sees before signing: the five items. Route 0 receives exactly amount - fee."""
    mx = None if i.route_kind == 0 else i.max_fee
    return {"leaving": i.amount, "withdrawalFee": fee, "maxFee": mx,
            "minimumReceived": i.amount - fee - (mx or 0), "exact": i.route_kind == 0,
            "route": _ROUTE_NAME.get(i.route_kind),
            "destination": {"chain": DOMAIN_NAMES.get(i.destination_domain, f"CCTP domain {i.destination_domain}"),
                            "recipient": i.recipient.lower()}}


def line_above_max(maximum: int) -> str:
    """ "Above the per-withdrawal maximum of X USDC. Please withdraw in smaller parts." -- X is the vault read's."""
    return f"Above the per-withdrawal maximum of {usdc(maximum)} USDC. Please withdraw in smaller parts."


def withdraw_max_problem(vault: Vault, amount: int) -> Optional[str]:
    """The per-withdrawal maximum, checked on the amount leaving the Vordium balance BEFORE anything is signed. With
    ``V34["encoders"]`` on, a maximum that cannot be read refuses the withdrawal."""
    if vault.max_per_withdrawal is not None:
        return line_above_max(vault.max_per_withdrawal) if amount > vault.max_per_withdrawal else None
    return "The per-withdrawal maximum can't be read right now, so nothing was signed." if V34["encoders"] else None


def withdraw_screen(v: VaultsRead, amount: int) -> Optional[Dict[str, Any]]:
    """The withdrawal screen for a payout to Arbitrum (route 0): the fee as the chain reads it, what arrives, and that no
    ETH is needed -- the payout is sent for the user. None when the read is unusable or the amount does not cover it."""
    if not v.ok or amount <= v.withdrawal_fee:
        return None
    vault = next((x for x in v.vaults if any(r[0] == 0 and r[2] for r in x.routes)), None)
    over = withdraw_max_problem(vault, amount) if vault else None
    return {"refusal": over,
            "rows": [{"label": "Withdrawal fee", "value": f"{usdc(v.withdrawal_fee)} USDC"},
                     {"label": "You receive", "value": f"{usdc(amount - v.withdrawal_fee)} USDC on Arbitrum"}],
            "gas": LINE_NO_ETH}


# ---- sending a payout's ready call by hand (the relay is slow or down) -------------------------------------------------

_U_MAX = {"uint8": 0xFF, "uint32": 0xFFFF_FFFF, "uint64": 0xFFFF_FFFF_FFFF_FFFF, "uint256": (1 << 256) - 1}


def _w32(n: int) -> str:
    return f"{n:064x}"


@dataclass(frozen=True)
class ExpectedPayout:
    vault: str
    chain_id: int
    account: str
    nonce: int
    recipient: str
    amount: int
    route_kind: int
    destination_domain: int
    max_fee: int


@dataclass(frozen=True)
class PayoutFields:
    account: str
    recipient: str
    amount: int
    nonce: int
    route_kind: int
    destination_domain: int
    max_fee: int
    epoch: int
    deadline: int


_FIELD_ATTR = {"account": "account", "recipient": "recipient", "amount": "amount", "nonce": "nonce",
               "routeKind": "route_kind", "destinationDomain": "destination_domain", "maxFee": "max_fee",
               "epoch": "epoch", "deadline": "deadline"}


def encode_withdraw_call(f: PayoutFields, signatures: Sequence[str]) -> str:
    """withdraw(WithdrawV2, bytes[]) calldata: the static 9-word tuple, then the signatures in the order given."""
    if not _is_addr(f.account) or not _is_b32(f.recipient):
        raise ValueError("account / recipient malformed")
    sigs = list(signatures)
    if not sigs or not all(isinstance(s, str) and re.fullmatch(r"0x[0-9a-fA-F]{130}", s) for s in sigs):
        raise ValueError("each signature must be 65 bytes")
    parts = []
    for name, ty in WITHDRAW_V2_FIELDS:
        x = getattr(f, _FIELD_ATTR[name])
        if ty == "address":
            parts.append("0" * 24 + x[2:].lower())
        elif ty == "bytes32":
            parts.append(x[2:].lower())
        else:
            if not isinstance(x, int) or isinstance(x, bool) or x < 0 or x > _U_MAX[ty]:
                raise ValueError(f"{name} is out of range")
            parts.append(_w32(x))
    n = len(sigs)
    heads = "".join(_w32(n * 32 + i * 128) for i in range(n))
    bodies = "".join(_w32(65) + s[2:].lower() + "0" * 62 for s in sigs)
    return WITHDRAW_SELECTOR + "".join(parts) + _w32(len(WITHDRAW_V2_FIELDS) * 32 + 32) + _w32(n) + heads + bodies


#: secp256k1's group order n; the vault takes a signature only with s <= n / 2.
_SECP256K1_N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141


def signature_rule_problem(sig: Any) -> Optional[str]:
    """A validator signature the vault accepts: exactly 65 bytes r || s || v with v 27 or 28 and s at most n / 2
    (the v = 0 / 1 form of a valid signature is refused). None when it passes, else why not."""
    if not isinstance(sig, str) or not re.fullmatch(r"0x[0-9a-fA-F]{130}", sig):
        return "is not 65 bytes"
    h = sig[2:]
    r, sv, v = int(h[0:64], 16), int(h[64:128], 16), int(h[128:130], 16)
    if v not in (27, 28):
        return f"has v = {v} (only 27 or 28)"
    if r == 0 or sv == 0 or sv > _SECP256K1_N // 2:
        return "has an s the vault refuses"
    return None


def decode_withdraw_call(data: Any) -> Dict[str, Any]:
    """Reads a withdraw(WithdrawV2, bytes[]) call and accepts it only in its one canonical encoding: the published
    selector, every value inside its type, each signature 65 bytes, no byte more or less -- re-encoding what was read
    must give the same bytes. -> {"ok": True, "fields", "signatures"} or {"ok": False, "field", "text"}."""
    def no(field: str, text: str) -> Dict[str, Any]:
        return {"ok": False, "field": field, "text": text}
    if not isinstance(data, str) or not re.fullmatch(r"0x(?:[0-9a-fA-F]{2})*", data):
        return no("data", "The payout call is not hex.")
    h = data[2:].lower()
    if not h.startswith(WITHDRAW_SELECTOR[2:]):
        return no("selector", "The call is not the vault's withdraw function.")
    words = h[8:]
    if len(words) % 64:
        return no("length", "The payout call has a partial word.")
    count = len(words) // 64

    def w(i: int) -> str:
        return words[i * 64:i * 64 + 64]
    if count < 13:
        return no("length", "The payout call is too short.")
    vals: Dict[str, Any] = {}
    for i, (name, ty) in enumerate(WITHDRAW_V2_FIELDS):
        word = w(i)
        if ty == "address":
            if not word.startswith("0" * 24):
                return no(name, f"The payout's {name} is not an address.")
            vals[name] = "0x" + word[24:]
        elif ty == "bytes32":
            vals[name] = "0x" + word
        else:
            v = int(word, 16)
            if v > _U_MAX[ty]:
                return no(name, f"The payout's {name} is out of range.")
            vals[name] = v
    if int(w(9), 16) != 320:
        return no("encoding", "The signatures are not where the one encoding puts them.")
    n = int(w(10), 16)
    if n < 1 or n > 64:
        return no("signatures", "The payout call carries no readable signature list.")
    sigs: List[str] = []
    for i in range(n):
        at = 11 + n + i * 4
        if at + 3 >= count:
            return no("length", "The payout call is too short for its signatures.")
        if int(w(at), 16) != 65:
            return no(f"signature {i + 1}", f"Signature {i + 1} is not 65 bytes.")
        sig = "0x" + w(at + 1) + w(at + 2) + w(at + 3)[:2]
        bad = signature_rule_problem(sig)
        if bad:
            return no(f"signature {i + 1}", f"Signature {i + 1} {bad}: the vault would refuse it.")
        sigs.append(sig)
    fields = PayoutFields(account=vals["account"], recipient=vals["recipient"], amount=vals["amount"], nonce=vals["nonce"],
                          route_kind=vals["routeKind"], destination_domain=vals["destinationDomain"], max_fee=vals["maxFee"],
                          epoch=vals["epoch"], deadline=vals["deadline"])
    try:
        again = encode_withdraw_call(fields, sigs)
    except ValueError:
        return no("encoding", "The payout call does not re-encode.")
    if again != "0x" + h:
        return no("encoding", "The payout call is not in its one canonical encoding.")
    return {"ok": True, "fields": fields, "signatures": sigs}


@dataclass(frozen=True)
class WithdrawalCall:
    status: str                      # ready | not ready | paid | refunded | unknown | unreadable
    vault_id: Optional[int] = None
    digest: Optional[str] = None
    quorum_reached: Optional[bool] = None
    vault_settled: Optional[bool] = None
    chain_time: Optional[int] = None
    read: Optional[str] = None       # ok | unavailable (pending answers)
    chain_id: Optional[int] = None
    to: Optional[str] = None
    data: Optional[str] = None
    value: Optional[int] = None
    error: str = ""


def read_withdrawal_call(http_status: int, body: Any) -> WithdrawalCall:
    """GET /bridge/v4/withdrawal/{account}/{nonce}/call -- the payout's own vault
    call, ready for anyone to send. While pending it carries the vault the payout is for, the digest the validators sign
    and whether their signatures reach quorum (the node's answers), whether the vault has settled it and the vault chain's
    time (read from two sources, ``read``); ``ready`` adds the call itself. Settled: paid or refunded. None of these is
    shown to a user; they are read only to check a payout before it is sent by hand."""
    if http_status == 404:
        return WithdrawalCall("unknown") if isinstance(body, dict) and body.get("status") == "unknown" \
            else WithdrawalCall("unreadable", error="unexpected 404")
    if http_status != 200 or not isinstance(body, dict):
        return WithdrawalCall("unreadable", error=f"HTTP {http_status}")
    st, vault_id = body.get("status"), _small(body.get("vault_id"))
    if st not in ("ready", "not ready", "paid", "refunded"):
        return WithdrawalCall("unreadable", error="an unknown status")
    if vault_id is None:
        return WithdrawalCall("unreadable", error="the call names no vault")
    if st in ("paid", "refunded"):
        return WithdrawalCall(st, vault_id=vault_id)
    if body.get("read") not in ("ok", "unavailable"):
        return WithdrawalCall("unreadable", error="the call does not say whether its live read agreed")
    if "digest" not in body or (body["digest"] is not None and not _is_b32(body["digest"])):
        return WithdrawalCall("unreadable", error="the digest is not 32 bytes")
    qr, vs = body.get("quorum_reached"), body.get("vault_settled")
    if (qr is not None and not isinstance(qr, bool)) or (vs is not None and not isinstance(vs, bool)) \
            or "quorum_reached" not in body or "vault_settled" not in body:
        return WithdrawalCall("unreadable", error="quorum_reached / vault_settled is not true, false or null")
    ct_raw = body.get("chain_time")
    ct = None if ct_raw is None else _pos_int(ct_raw)
    if ct_raw is not None and ct is None or "chain_time" not in body:
        return WithdrawalCall("unreadable", error="chain_time is not a positive time")
    live = body["read"] == "ok"     # "unavailable": the two sources did not agree, so neither live field is used
    common = dict(vault_id=vault_id, digest=body.get("digest"), quorum_reached=qr, vault_settled=vs if live else None,
                  chain_time=ct if live else None, read=body["read"])
    if st == "not ready":
        return WithdrawalCall("not ready", **common)
    chain_id, value = _small(body.get("chain_id")), units(body.get("value"))
    if chain_id is None or not _is_addr(body.get("to")) or not isinstance(body.get("data"), str) or value is None:
        return WithdrawalCall("unreadable", error="the ready call lacks chain_id / to / data / value")
    return WithdrawalCall("ready", chain_id=chain_id, to=body["to"], data=body["data"], value=value, **common)


def self_send_from_call(call: WithdrawalCall, want: ExpectedPayout, vault: Optional[Vault]) -> Dict[str, Any]:
    """"Send it yourself": the ready call from GET .../withdrawal/{account}/{nonce}/call, checked before the user's own key
    sends it. Every field of the payout inside the call must equal THIS user's withdrawal; the call goes to the vault the
    call names -- this withdrawal's vault -- on its chain with value 0; that vault's live code must match the pin (the
    vaults read); the deadline must still be ahead by the vault chain's time; the vault must not have settled the payout;
    and the signatures must reach quorum. The bytes sent are the read's own bytes, unchanged.
    -> {"ok": True, "tx", "payout", "signatures", "lines"} or {"ok": False, "reason", "text"}."""
    _require_open()

    def no(reason: str, text: str) -> Dict[str, Any]:
        return {"ok": False, "reason": reason, "text": text}
    if call.status != "ready" or call.to is None:
        return no("not-ready", "This payout is not ready to be sent by hand.")
    if not _is_addr(want.vault) or vault is None or vault.address.lower() != want.vault.lower():
        return no("vault", "The payout call is not addressed to the bridge vault, so nothing was sent.")
    if call.vault_id != vault.id:
        return no("vault", "The payout call is for another vault, so nothing was sent.")
    if call.chain_id != want.chain_id or str(call.chain_id) != vault.chain_id:
        return no("chain", "The payout call is for another chain, so nothing was sent.")
    if not isinstance(call.to, str) or call.to.lower() != want.vault.lower():
        return no("vault", "The payout call is not addressed to the bridge vault, so nothing was sent.")
    if call.value != 0:
        return no("value", "The payout call carries a value, so nothing was sent.")
    d = decode_withdraw_call(call.data)
    if not d["ok"]:
        return no("encoding", f"{d['text']} Nothing was sent.")
    f: PayoutFields = d["fields"]
    expect = (("account", f.account, want.account.lower()), ("nonce", f.nonce, want.nonce),
              ("recipient", f.recipient, want.recipient.lower()), ("amount", f.amount, want.amount),
              ("routeKind", f.route_kind, want.route_kind), ("destinationDomain", f.destination_domain, want.destination_domain),
              ("maxFee", f.max_fee, want.max_fee))
    for k, got, w in expect:
        if got != w:
            return no("mismatch", f"The payout does not match your withdrawal ({k}), so nothing was sent.")
    if runtime_pin("vault", vault.runtime_sha_vault or "") != "match":
        return no("pin", "The vault contract does not match the published code, so nothing was sent.")
    if call.read != "ok" or call.chain_time is None:
        return no("unread", "The vault chain's time cannot be confirmed right now, so nothing was sent.")
    if f.deadline <= call.chain_time:
        return no("expired", "This payout's deadline has passed, so it cannot be sent. It will be returned to your Vordium balance.")
    if call.vault_settled is None:
        return no("unread", "Whether this payout was already sent cannot be confirmed right now, so nothing was sent.")
    if call.vault_settled:
        return no("state", "This payout was already settled.")
    if call.quorum_reached is not True:
        return no("quorum", "The vault could not confirm the payout's signatures, so nothing was sent.")
    return {"ok": True, "tx": {"chainId": call.chain_id, "to": call.to, "data": call.data, "value": 0},
            "payout": f, "signatures": d["signatures"],
            "lines": [LINE_SELF_SEND_GAS, f"The vault pays exactly {usdc(f.amount)} USDC to the address in your withdrawal."]}


def self_send_offered(withdrawal: Optional[str], call_status: str, ready_since_ms: Optional[int], now_ms: int) -> bool:
    """"Send it yourself" is offered only for a pending withdrawal whose call has read ready for a while."""
    return withdrawal == "pending" and call_status == "ready" and ready_since_ms is not None \
        and now_ms - ready_since_ms >= SELF_SEND_AFTER_MS


# ---- what users see ----------------------------------------------------------------------------------------------------


def withdrawal_status(raw: Any) -> Optional[str]:
    """Only the three public words, exactly as the read writes them; anything else shows nothing."""
    return raw if isinstance(raw, str) and raw in WITHDRAWAL_STATUSES else None


def deposit_status(raw: Any) -> Optional[str]:
    return raw if isinstance(raw, str) and raw in DEPOSIT_STATUSES else None


def reason_line(reason: str, v: VaultsRead, claim_chain_id: Optional[str]) -> str:
    """The public line for a deposit with a reason key (never the read's text). The chain named is the one the claim is
    on -- the vault's chain. A key with no decided line reads "Not accepted."."""
    def on(line: str) -> str:
        return line.replace(" on Arbitrum ", f" on {_chain_name(claim_chain_id)} ") if claim_chain_id and claim_chain_id != "42161" else line
    if reason == "waiting":
        return LINE_WAITING
    if reason == "stranded":
        return LINE_STRANDED
    if reason == "rescued":
        return on(LINE_RESCUED)
    if reason == "above_per_deposit_limit":
        return on(LINE_OVER_CAP)
    if reason == "not_completed":
        return on(LINE_NOT_COMPLETED)
    if reason == "below_minimum":
        return below_minimum_line(v) or LINE_NOT_ACCEPTED
    return LINE_NOT_ACCEPTED


#: The 17 names of one deposit row; a row lacking any of them is not read.
DEPOSIT_ROW_FIELDS = ("status", "reason", "text", "kind", "account", "amount_6dec", "vault_id", "chain_id", "deposit_id",
                      "source_domain", "nonce", "source_chain_id", "source_tx", "vault_tx", "claim", "credited_height", "as_of")


def read_deposit_row(j: Any, v: VaultsRead) -> Optional[Dict[str, Any]]:
    """One deposit row, whole or not at all. ``waiting`` and ``stranded`` rows carry the reason key of the
    same name; a ``not accepted`` row one of NOT_ACCEPTED_REASONS. All three are CCTP messages with no deposit id. Only an
    owed row carries a claim: always for OWED_REASONS, maybe for below_minimum (nothing is owed when Circle's fee took it
    all) and ``other``; never for a waiting or stranded deposit. An owed-to-beneficiary claim is the deposit's account's; a
    recovery names its own address. Only a stranded deposit -- or one a recovery later made owed (rescued) -- may have no
    readable account. ``text`` is never shown -- the line comes from the key. -> a dict with the row's fields or None."""
    if not isinstance(j, dict) or not all(k in j for k in DEPOSIT_ROW_FIELDS):
        return None
    status, amount, vault_id, chain_id = deposit_status(j["status"]), units(j["amount_6dec"]), _small(j["vault_id"]), _small(j["chain_id"])
    if status is None or amount is None or vault_id is None or chain_id is None or j["kind"] not in ("direct", "cctp"):
        return None
    if j["account"] is not None and not _is_addr(j["account"]):
        return None
    if j["text"] is not None and not isinstance(j["text"], str):
        return None
    if read_as_of(j["as_of"]) is None:
        return None
    na = status == "not accepted"
    keyed = na or status in ("waiting", "stranded")
    reason = (j["reason"] if isinstance(j["reason"], str) else None) if keyed else None    # checked against its status's keys below
    if (reason is None) if keyed else (j["reason"] is not None):
        return None
    if status == "waiting" and reason != "waiting":
        return None
    if status == "stranded" and reason != "stranded":
        return None
    if na and reason not in NOT_ACCEPTED_REASONS:
        return None
    if j["account"] is None and status != "stranded" and reason != "rescued":   # a recovered stranded deposit keeps no account
        return None
    dep_id = None if j["deposit_id"] is None else units(j["deposit_id"])
    if j["deposit_id"] is not None and dep_id is None:
        return None
    if keyed and (j["kind"] != "cctp" or dep_id is not None):
        return None
    source_domain = nonce = None
    if j["kind"] == "cctp":
        source_domain = _small(j["source_domain"])
        if source_domain is None or (j["nonce"] is not None and not _is_b32(j["nonce"])):
            return None
        nonce = None if j["nonce"] is None else j["nonce"].lower()
    elif j["source_domain"] is not None or j["nonce"] is not None:
        return None
    sc = None if j["source_chain_id"] is None else _small(j["source_chain_id"])
    if (j["source_chain_id"] is not None and sc is None) or (j["source_tx"] is not None and not _is_b32(j["source_tx"])):
        return None
    if (sc is None) != (j["source_tx"] is None):
        return None
    if j["kind"] == "direct" and sc is not None and sc != chain_id:
        return None
    if j["vault_tx"] is not None and not _is_b32(j["vault_tx"]):
        return None
    ch = None if j["credited_height"] is None else _pos_int(j["credited_height"])
    if (status == "credited") != (ch is not None):
        return None
    claim = None
    owed = na and reason in OWED_REASONS
    if owed and j["claim"] is None:
        return None
    if na and j["claim"] is not None:
        c = j["claim"]
        if not isinstance(c, dict):
            return None
        cc, ca = _small(c.get("chain_id")), units(c.get("amount_6dec"))
        if cc is None or ca is None or not _is_addr(c.get("handler")) or not _is_addr(c.get("by")):
            return None
        if reason not in ("rescued", "other") and c["by"].lower() != j["account"].lower():
            return None
        refundable = None
        if "read" in c:
            if c["read"] == "ok":
                refundable = units(c.get("refundable_6dec"))
                if refundable is None:
                    return None
            elif c["read"] != "unavailable" or c.get("refundable_6dec") is not None:
                return None
        vault = next((x for x in v.vaults if x.chain_id == str(cc) and x.handler), None) if v.ok else None
        claim = {"chainId": str(cc), "chain": _chain_name(str(cc)), "handler": c["handler"], "by": c["by"], "amount": ca,
                 "refundable": refundable, "checked": vault is not None and vault.handler.lower() == c["handler"].lower()}
    elif j["claim"] is not None:
        return None
    return {"status": status, "reason": reason,
            "line": reason_line(reason, v, claim["chainId"] if claim else None) if reason else None,
            "kind": j["kind"], "account": j["account"], "amount": amount, "vaultId": vault_id, "chainId": str(chain_id),
            "depositId": dep_id, "sourceDomain": source_domain, "nonce": nonce, "sourceChainId": None if sc is None else str(sc),
            "sourceTx": None if j["source_tx"] is None else j["source_tx"].lower(),
            "vaultTx": None if j["vault_tx"] is None else j["vault_tx"].lower(), "claim": claim, "creditedHeight": ch}


def _keccak_utf8(s: str) -> str:
    from eth_utils import keccak
    return keccak(text=s).hex()


def to_checksum(addr: str) -> str:
    """EIP-55: the checksummed form of a 20-byte address."""
    if not _is_addr(addr):
        raise ValueError("not an address")
    lower = addr[2:].lower()
    h = _keccak_utf8(lower)
    h = h[2:] if h.startswith("0x") else h
    return "0x" + "".join(c.upper() if int(h[i], 16) >= 8 else c for i, c in enumerate(lower))


def refund_recipient(entered: Optional[str], owed: str, own: Optional[List[str]]) -> Dict[str, Any]:
    """Where a refund goes: the owed address's own wallet (an empty field), or another address typed in full WITH its
    checksum (all-lowercase or all-uppercase is refused: a typo in it could not be caught). Never the zero address or one
    of the system's own addresses (own_addresses: the vault, its handler, its set rules): USDC sent there would be stuck."""
    s = (entered or "").strip()
    if not s:
        return {"ok": True, "to": owed, "own": True}
    if not _is_addr(s):
        return {"ok": False, "text": "That is not an address."}
    body = s[2:]
    if int(body, 16) == 0:
        return {"ok": False, "text": "That is not an address."}
    if re.search(r"[a-fA-F]", body) and (body == body.lower() or body == body.upper()):
        return {"ok": False, "text": "Enter the address with its capital letters, as your wallet shows it, so a typo can't slip through."}
    if to_checksum(s) != s:
        return {"ok": False, "text": "That address has a typo: its capital letters don't match."}
    if own is None:
        return {"ok": False, "text": "The bridge contracts could not be confirmed, so nothing was built."}
    if is_own_address(s, own):
        return {"ok": False, "text": LINE_OWN_ADDRESS}
    return {"ok": True, "to": s, "own": s.lower() == owed.lower()}


def claim_refund_tx(handler: str, own: List[str], sender: str, owed: str, to: Optional[str] = None) -> Dict[str, Any]:
    """The refund claim, sent only from the address that is owed: claimRefund() to its own wallet, or claimRefundTo(to)
    -- the whole owed amount, once -- to another non-zero address that is none of the system's own addresses (``own``:
    the vault, its handler, its set rules; claimRefundTo only while V34["encoders"] is on)."""
    _require_open()
    to = owed if to is None else to
    if not (_is_addr(handler) and _is_addr(sender) and _is_addr(owed) and _is_addr(to)):
        raise ValueError("not an address")
    if not any(a.lower() == handler.lower() for a in own):
        raise ValueError("The claim does not point at the bridge's own contract.")
    if sender.lower() != owed.lower():
        raise ValueError("Only the address that is owed can claim it.")
    if to.lower() == owed.lower():
        return {"to": handler, "data": CLAIM_REFUND_SELECTOR, "value": 0}
    if not V34["encoders"]:
        raise ValueError("Claiming to another address isn't available yet.")
    if int(to[2:], 16) == 0 or is_own_address(to, own):
        raise ValueError("The USDC cannot be sent to that address.")
    return {"to": handler, "data": CLAIM_REFUND_TO_SELECTOR + "0" * 24 + to[2:].lower(), "value": 0}


def refund_claim(row: Optional[Dict[str, Any]], connected: str, vault: Optional[Vault],
                 to: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """The refund claim for a not-accepted deposit: on the claim's chain, to the vault's own handler (the claim is
    checked against the vault read, and the handler's live code against the pin), sent only by the address owed, and
    only while the read says something is left to claim (the claim's ``refundable``, confirmed by two sources)."""
    _require_open()
    c = row.get("claim") if row else None
    if not row or not c:
        return {"ok": False, "reason": "unreadable", "text": "This deposit could not be read, so nothing was built."}
    if not c["checked"] or vault is None or vault.chain_id != c["chainId"] or not vault.handler \
            or vault.handler.lower() != c["handler"].lower():
        return {"ok": False, "reason": "handler", "text": "The claim does not point at the bridge's own contract, so nothing was built."}
    if runtime_pin("handler", vault.runtime_sha_handler or "") != "match":
        return {"ok": False, "reason": "pin", "text": "The contract does not match the published code, so nothing was built."}
    if not _is_addr(connected) or connected.lower() != c["by"].lower():
        return {"ok": False, "reason": "not-owed", "text": "Only the address that is owed can claim it. Connect that wallet."}
    if to is not None and not to.get("ok"):
        return {"ok": False, "reason": "recipient", "text": to.get("text") or "That is not an address."}
    dest = to["to"] if to is not None and to.get("ok") else c["by"]      # "own" is decided against the claim's owed address
    if dest.lower() != c["by"].lower() and not V34["encoders"]:
        return {"ok": False, "reason": "not-yet", "text": "Claiming to another address isn't available yet."}
    own = own_addresses(vault)
    if own is None:
        return {"ok": False, "reason": "handler", "text": "The claim does not point at the bridge's own contract, so nothing was built."}
    if int(dest[2:], 16) == 0 or is_own_address(dest, own):
        return {"ok": False, "reason": "recipient", "text": LINE_OWN_ADDRESS}
    if c["refundable"] is None:
        return {"ok": False, "reason": "unread", "text": "What is left to claim cannot be confirmed right now, so nothing was built."}
    if c["refundable"] <= 0:
        return {"ok": False, "reason": "nothing", "text": "There is nothing left to claim for this address."}
    tx = claim_refund_tx(c["handler"], own, connected, c["by"], dest)
    return {"ok": True, "tx": {"chainId": int(c["chainId"]), **tx}, "amount": c["refundable"], "to": dest}


# ---- public reads a client shows ---------------------------------------------------------------------------------------


def read_withdrawal_row(j: Any, account: str) -> Optional[Dict[str, Any]]:
    """One row of GET /bridge/v4/withdrawal(s): only the three public words and the amounts; nothing else is read."""
    if not isinstance(j, dict) or not isinstance(j.get("account"), str) or j["account"].lower() != account.lower():
        return None
    status, nonce, vault_id, amount = withdrawal_status(j.get("status")), units(j.get("nonce")), _small(j.get("vault_id")), units(j.get("amount_6dec"))
    if status is None or nonce is None or vault_id is None or amount is None:
        return None

    def opt(x: Any) -> Optional[int]:
        return None if x is None else units(x)
    route = j.get("route")
    return {"nonce": nonce, "vault_id": vault_id, "status": status, "amount": amount, "payout": opt(j.get("payout_6dec")),
            "fee": opt(j.get("fee_6dec")),
            "route": route if isinstance(route, str) and any(r[1] == route for r in ROUTES) else None,
            "recipient": j["recipient"].lower() if _is_b32(j.get("recipient")) else None,
            "paid_tx": j["paid_tx"] if status == "paid" and _is_b32(j.get("paid_tx")) else None,
            "refunded": opt(j.get("refunded_6dec")) if status == "refunded" else None,
            # the payout's CCTP domain (the vault's own for a local payout); None when the row does not carry one
            "destination_domain": None if j.get("destination_domain") is None else _small(j.get("destination_domain"))}


def read_withdrawals(j: Any, account: str) -> Tuple[Optional[List[Dict[str, Any]]], str]:
    """GET /bridge/v4/withdrawals/{account} -> the rows, newest first; a row that does not read is left out."""
    if not isinstance(j, dict) or not isinstance(j.get("account"), str) or j["account"].lower() != account.lower() \
            or not isinstance(j.get("withdrawals"), list):
        return None, "the withdrawals read is not in the published shape"
    rows = [read_withdrawal_row({"account": j["account"], **(r if isinstance(r, dict) else {})}, account) for r in j["withdrawals"]]
    return [r for r in rows if r], ""


def deposit_message_path(source_domain: int, nonce: str) -> Optional[str]:
    """The canonical read of one CCTP deposit by its message: GET /bridge/v4/deposit/cctp/{sourceDomain}/{nonce}."""
    if isinstance(source_domain, bool) or not isinstance(source_domain, int) or source_domain < 0 or not _is_b32(nonce):
        return None
    return f"/bridge/v4/deposit/cctp/{source_domain}/{nonce.lower()}"


def read_deposit(http_status: int, body: Any, v: VaultsRead, tx_hash: Optional[str] = None,
                 message: Optional[Tuple[int, str]] = None) -> Dict[str, Any]:
    """A lookup of one deposit -- by its transaction (GET /bridge/v4/deposit/tx/{hash}) or, canonically, by its CCTP
    message (GET /bridge/v4/deposit/cctp/{sourceDomain}/{nonce}; the row must be that message's). 404 {"status":"unknown"} = the chain holds no record of it (yet); a
    200 with "read": "unavailable" = the two sources did not agree; a row = the row. By transaction, the row must be that
    transaction's: the hash is its vault-chain transaction or the transaction the user sent.
    -> {"status": found, "row"} | {"status": unknown} | {"status": unavailable} | {"status": unreadable, "error"}."""
    if http_status == 404:
        if isinstance(body, dict) and body.get("status") == "unknown" and all(k in ("status", "as_of") for k in body):
            return {"status": "unknown"}
        return {"status": "unreadable", "error": "not found"}
    if http_status != 200 or not isinstance(body, dict):
        return {"status": "unreadable", "error": f"HTTP {http_status}"}
    if body.get("read") == "unavailable":
        return {"status": "unavailable"} if "status" in body and body["status"] is None \
            else {"status": "unreadable", "error": "an unavailable read carries a status"}
    if "read" in body and body["read"] != "ok":
        return {"status": "unreadable", "error": "an unknown read state"}
    row = read_deposit_row(body, v)
    if row is None:
        return {"status": "unreadable", "error": "the deposit row is not in the published shape"}
    if tx_hash is not None:
        h = tx_hash.lower() if _is_b32(tx_hash) else None
        if h is None or (row["vaultTx"] != h and row["sourceTx"] != h):
            return {"status": "unreadable", "error": "the row is not that transaction's"}
    if message is not None and (row["kind"] != "cctp" or row["sourceDomain"] != message[0] or row["nonce"] != str(message[1]).lower()):
        return {"status": "unreadable", "error": "the row is not that message's"}
    return {"status": "found", "row": row}


def deposit_word(d: Dict[str, Any]) -> Optional[str]:
    """The word a user sees for a deposit: one the chain holds no record of yet reads "pending"; an unconfirmed read
    shows no word."""
    st = d.get("status")
    return d["row"]["status"] if st == "found" else "pending" if st == "unknown" else None


def deposit_line(d: Dict[str, Any]) -> Optional[str]:
    """The one line under a deposit's word: why it was not accepted, or that the read is unavailable; nothing otherwise."""
    st = d.get("status")
    if st == "found":
        return d["row"]["line"]
    return LINE_UNAVAILABLE if st == "unavailable" else None


def read_deposits(j: Any, account: str, v: VaultsRead) -> Dict[str, Any]:
    """GET /bridge/v4/deposits/{account} -> the account's deposit rows (newest first, at most ``limit``), with totals over
    every row. A row belongs to the account when it names it, or -- its account unreadable -- when the account can claim
    it. A row that does not read is counted, never guessed.
    -> {"ok": True, "rows", "unreadable", "totals": {pending, credited, notAccepted}, "count", "more"} or {"ok": False, "error"}."""
    def no(e: str) -> Dict[str, Any]:
        return {"ok": False, "error": e}
    if not isinstance(j, dict) or not _is_addr(account) or not _is_addr(j.get("account")) or j["account"].lower() != account.lower() \
            or not isinstance(j.get("deposits"), list):
        return no("the deposits read is not in the published shape")
    count = j.get("count")
    count = count if isinstance(count, int) and not isinstance(count, bool) and 0 <= count <= 2 ** 53 - 1 else None
    limit = _pos_int(j.get("limit"))
    if count is None or limit is None or len(j["deposits"]) > limit or len(j["deposits"]) > count:
        return no("count / limit do not fit the list")
    tot = j.get("totals")
    if not isinstance(tot, dict):
        return no("the deposits read has no totals")
    tp, tc, tn = units(tot.get("pending_6dec")), units(tot.get("credited_6dec")), units(tot.get("not_accepted_6dec"))
    if tp is None or tc is None or tn is None:
        return no("a total is not a base-unit amount")
    if read_as_of(j.get("as_of")) is None:
        return no("the deposits read has no as_of")
    rows: List[Dict[str, Any]] = []
    unreadable = 0
    for r in j["deposits"]:
        row = read_deposit_row(r, v)
        mine = row is not None and ((row["account"] is not None and row["account"].lower() == account.lower())
                                    or (bool(row["claim"]) and row["claim"]["by"].lower() == account.lower()))
        if row is not None and mine:
            rows.append(row)
        else:
            unreadable += 1
    return {"ok": True, "rows": rows, "unreadable": unreadable, "totals": {"pending": tp, "credited": tc, "notAccepted": tn},
            "count": count, "more": count > len(j["deposits"])}


def read_reserves(j: Any) -> Dict[str, Any]:
    """GET /reserves -- the total only (per-vault figures are not public and are never read here). A read block is never 0."""
    if not isinstance(j, dict) or not isinstance(j.get("total"), dict):
        return {"ok": False, "error": "the reserves read has no total"}
    t = j["total"]
    keys = ("usdc_6dec", "credited_6dec", "paid_6dec", "pending_withdrawals_6dec", "liabilities_6dec")
    if any(t.get(k) is not None and units(t.get(k)) is None for k in keys) or any(k not in t for k in keys):
        return {"ok": False, "error": "a total is not a base-unit amount"}
    if t.get("refunded_6dec") is not None and units(t.get("refunded_6dec")) is None:
        return {"ok": False, "error": "refunded_6dec is not a base-unit amount"}
    if "solvent" not in t or (t["solvent"] is not None and not isinstance(t["solvent"], bool)):
        return {"ok": False, "error": "solvent is not true, false or null"}
    if "read" in j:
        rd = j["read"]
        if not isinstance(rd, list) or any(not isinstance(r, dict) or (r.get("block") is not None and _pos_int(r.get("block")) is None)
                                           or "block" not in r for r in rd):
            return {"ok": False, "error": "a read block is not a positive number or null"}

    def n(x: Any) -> Optional[int]:
        return None if x is None else units(x)
    as_of = j.get("as_of")
    return {"ok": True, "usdc": n(t["usdc_6dec"]), "credited": n(t["credited_6dec"]), "paid": n(t["paid_6dec"]),
            "pending_withdrawals": n(t["pending_withdrawals_6dec"]), "liabilities": n(t["liabilities_6dec"]),
            "refunded": n(t.get("refunded_6dec")), "solvent": t.get("solvent"),
            "height": _small(as_of.get("height")) if isinstance(as_of, dict) else None}


# ---- building a deposit -------------------------------------------------------------------------------------------------


def _approve_data(spender: str, amount: int) -> str:
    return APPROVE_SELECTOR + "0" * 24 + spender[2:].lower() + _w32(amount)


_BINDING_TEXT = "The bridge contracts could not be confirmed, so nothing was built."


def create_address(deployer: str, nonce: int) -> str:
    """The address a contract at ``deployer`` creates with its ``nonce``-th CREATE: keccak256(rlp([deployer, nonce]))[12:]."""
    from eth_utils import keccak
    if not _is_addr(deployer) or isinstance(nonce, bool) or not isinstance(nonce, int) or nonce < 0:
        raise ValueError("not a deployer / nonce")
    if nonce == 0:
        n = b"\x80"
    elif nonce < 0x80:
        n = bytes([nonce])
    else:
        b = nonce.to_bytes((nonce.bit_length() + 7) // 8, "big")
        n = bytes([0x80 + len(b)]) + b
    body = b"\x94" + bytes.fromhex(deployer[2:]) + n
    return "0x" + keccak(bytes([0xc0 + len(body)]) + body)[12:].hex()


def vault_build(sha256_hex: str) -> str:
    """Which build a vault's runtime is: the published vault, the test-network-only build (never accepted), or neither."""
    h = _strip0x(sha256_hex.lower()) if isinstance(sha256_hex, str) else ""
    return "vault" if h == PINS["vault"]["runtime"] else "testnet-only" if h == TESTNET_VAULT_PIN["runtime"] else "unknown"


def binding_check(vault: Optional[Vault]) -> Dict[str, Any]:
    """Proves handler -> vault before a burn (from the vaults read): the
    handler is the one the vault created -- CREATE(vault, nonce 1) -- and the read confirmed its binding (it names this
    vault, both use the same USDC, both local domains are the vault's registered CCTP domain); both contracts' live runtime
    sha256 are the pins (a test-network-only vault is refused by name). Anything the read could not confirm refuses."""
    no = {"ok": False, "text": _BINDING_TEXT}
    if vault is None or not _is_addr(vault.address) or not vault.handler or not _is_addr(vault.handler):
        return no
    if vault_build(vault.runtime_sha_vault or "") == "testnet-only":
        return {"ok": False, "text": "This is a test-network vault, so nothing was built."}
    if vault.binding_confirmed is not True or not vault.binding_handler_vault \
            or vault.binding_handler_vault.lower() != vault.address.lower() or vault.binding_local_domain != vault.cctp_domain \
            or not vault.binding_usdc:
        return no
    try:
        created = create_address(vault.address, 1)
    except ValueError:
        return no
    if created.lower() != vault.handler.lower():
        return no
    if runtime_pin("handler", vault.runtime_sha_handler or "") != "match" or runtime_pin("vault", vault.runtime_sha_vault or "") != "match":
        return no
    return {"ok": True}


def direct_deposit_txs(check: DepositCheck, v: VaultsRead, chain_id: int, usdc_token: str, amount: int,
                       allowed: Optional[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """A deposit from the vault's own chain: approve the vault, then deposit(amount) -- credited to the sending address.
    Built only for the pinned vault code (its live runtime sha256 from the vaults read) and while deposit-allowed says the
    vault takes it now."""
    _require_open()
    if not check.ok or check.kind != "direct":
        raise ValueError("not a checked direct deposit")
    if not _is_addr(usdc_token):
        raise ValueError("USDC is not an address")
    vault = next((x for x in v.vaults if x.id == check.vault_id), None) if v.ok else None
    if vault is None or runtime_pin("vault", vault.runtime_sha_vault or "") != "match":
        raise ValueError("The vault contract does not match the published code, so nothing was built.")
    pre = pre_burn(allowed, "direct", False)
    if not pre["ok"]:
        raise ValueError(pre["line"] if pre["ask"] else pre["text"])
    return [{"chainId": chain_id, "to": usdc_token, "data": _approve_data(check.vault, amount), "value": 0, "label": "Approve USDC"},
            {"chainId": chain_id, "to": check.vault, "data": DEPOSIT_SELECTOR + _w32(amount), "value": 0, "label": "Deposit"}]


def destination_caller_word(handler: str, forwarded: bool) -> str:
    """The destination caller a CCTP deposit names (a 32-byte word, hex without 0x). A deposit
    this SDK creates names the handler (only the handler's process() can receive it); a Circle-forwarded deposit names
    none (Circle's Forwarding Service does not support one). With ``V34["encoders"]`` off, none."""
    if not _is_addr(handler):
        raise ValueError("not an address")
    return "0" * 24 + handler[2:].lower() if V34["encoders"] and not forwarded else "0" * 64


def arc_deposit_txs(check: DepositCheck, v: VaultsRead, source_chain_id: int, arc_usdc: str, token_messenger: str,
                    sender: str, amount: int, max_fee: int, allowed: Optional[Dict[str, Any]], wait_confirmed: bool,
                    forwarded: bool = False) -> List[Dict[str, Any]]:
    """A deposit from Arc through CCTP into the vault's handler: approve TokenMessengerV2, then
    depositForBurnWithHook(amount, the vault's domain, the handler as mint recipient, Arc's USDC, the destination caller
    (destination_caller_word), maxFee, finality 2000, the beneficiary word). The beneficiary is the sending address itself.
    Built only after the handler is proven to be the vault's own (binding_check) and deposit-allowed's outcome allows it
    (a deposit that would wait only once the user has seen the Waiting line and confirmed: ``wait_confirmed``).
    ``forwarded`` (interface section 2.1 / 5.4): the hook carries the forwarding header before the beneficiary word and the
    destination caller is zero, so Circle's forwarding service completes the mint on the vault's chain (its fee is inside
    ``max_fee``: arc_deposit_fee); otherwise the handler is the destination caller and the keeper completes it."""
    _require_open()
    if not check.ok or check.kind != "cctp" or not check.handler:
        raise ValueError("not a checked CCTP deposit")
    if not v.ok:
        raise ValueError("the vault read is unusable")
    vault = next((x for x in v.vaults if x.id == check.vault_id), None)
    if vault is None:
        raise ValueError("unknown vault")
    if not (_is_addr(arc_usdc) and _is_addr(token_messenger) and _is_addr(sender)):
        raise ValueError("not an address")
    if vault.cctp is None or str(source_chain_id) not in vault.cctp[0]:
        raise ValueError("this vault takes no CCTP deposit from that chain")
    if not vault.handler or vault.handler.lower() != check.handler.lower():
        raise ValueError(_BINDING_TEXT)
    bound = binding_check(vault)
    if not bound["ok"]:
        raise ValueError(bound["text"])
    own = own_addresses(vault)                    # a beneficiary that is one of these strands the deposit (code 5)
    if own is None or is_own_address(sender, own):
        raise ValueError(LINE_OWN_ADDRESS)
    pre = pre_burn(allowed, "cctp", wait_confirmed)
    if not pre["ok"]:
        raise ValueError(pre["line"] if pre["ask"] else pre["text"])
    hook = hook_data(sender, forwarded)[2:]
    burn = (DEPOSIT_FOR_BURN_WITH_HOOK_SELECTOR + _w32(amount) + _w32(vault.cctp_domain) + "0" * 24 + check.handler[2:].lower()
            + "0" * 24 + arc_usdc[2:].lower() + destination_caller_word(check.handler, forwarded) + _w32(max_fee) + _w32(CCTP_DEPOSIT_FINALITY) + _w32(256)
            + _w32(len(hook) // 2) + hook)
    return [{"chainId": source_chain_id, "to": arc_usdc, "data": _approve_data(token_messenger, amount), "value": 0, "label": "Approve USDC"},
            {"chainId": source_chain_id, "to": token_messenger, "data": burn, "value": 0, "label": "Deposit"}]


# ---- contract pins -----------------------------------------------------------------------------------------------------


def runtime_pin(which: str, sha256_hex: str) -> str:
    """'match' or 'mismatch' of a contract's runtime sha256 (vault, handler or setRules) against its pin."""
    ok = isinstance(sha256_hex, str) and _strip0x(sha256_hex.lower()) == PINS[which]["runtime"]
    return "match" if ok else "mismatch"


def creation_pin(sha256_hex: str, which: str = "vault") -> str:
    """'match' or 'mismatch' of a creation code sha256 (the vault's: before the constructor arguments; or the handler's)."""
    ok = isinstance(sha256_hex, str) and _strip0x(sha256_hex.lower()) == PINS[which]["creation"]
    return "match" if ok else "mismatch"


def own_addresses(vault: Optional[Vault]) -> Optional[List[str]]:
    """The addresses a payout recipient's low 20 bytes, a CCTP beneficiary and a refund's destination may never be: the
    vault, the handler it created (CREATE nonce 1) and its set rules (CREATE nonce 2). The read's handler must be the
    created one. None when the vault's address cannot be read."""
    if vault is None or not _is_addr(vault.address):
        return None
    try:
        handler = create_address(vault.address, VAULT_CREATES["handler"])
        set_rules = create_address(vault.address, VAULT_CREATES["setRules"])
    except ValueError:
        return None
    if vault.handler and vault.handler.lower() != handler:
        return None
    own = [vault.address.lower(), handler, set_rules]
    pub_sr, pub_own = getattr(vault, "pub_set_rules", None), getattr(vault, "pub_own_addresses", None)
    if pub_sr and pub_sr.lower() != set_rules:                  # a published set rules must be CREATE(vault, 2)
        return None
    if pub_own is not None:                                     # and a published list must hold the three
        if not all(any(a == b.lower() for b in pub_own) for a in own):
            return None
        own += [a.lower() for a in pub_own if a.lower() not in own]
    for w in getattr(vault, "pub_vordium_contracts", None) or ():  # a listed contract that is a 20-byte address
        if re.fullmatch(r"0x0{24}[0-9a-f]{40}", w) and "0x" + w[26:] not in own:
            own.append("0x" + w[26:])
    return own


def is_listed_contract_word(word: str, vault: Optional[Vault]) -> bool:
    """A recipient word that is a listed Vordium contract word exactly (a non-EVM contract is a full 32-byte word)."""
    words = getattr(vault, "pub_vordium_contracts", None) if vault is not None else None
    return isinstance(word, str) and bool(words) and word.lower() in words


def is_evm_domain(vault: Vault, domain: int) -> bool:
    """Whether a CCTP domain takes 20-byte addresses for this vault: its own domain, the published list, or a known EVM chain."""
    return domain == vault.cctp_domain or domain in EVM_DOMAINS or domain in (getattr(vault, "pub_evm_domains", None) or ())


def is_own_address(addr_or_word: str, own: List[str]) -> bool:
    """True when a 20-byte address (or the low 20 bytes of a 32-byte word) is one of the system's own addresses."""
    low = addr_or_word.lower()[2:][-40:] if isinstance(addr_or_word, str) and addr_or_word.startswith("0x") else ""
    return len(low) == 40 and any(_strip0x(a.lower()) == low for a in own)


# ---- the public reads (network) ----------------------------------------------------------------------------------------


def _get(path: str) -> Tuple[int, Any]:
    import requests
    from .network import api_base, get_network
    r = requests.get(api_base(get_network()) + path, timeout=15)
    try:
        return r.status_code, r.json()
    except ValueError:
        return r.status_code, None


def fetch_vaults() -> VaultsRead:
    _require_open()
    status, body = _get("/bridge/v4/vaults")
    if status != 200:
        return VaultsRead(ok=False, error=f"HTTP {status}")
    v = read_vaults(body)
    return replace(v, read_at=time.monotonic()) if v.ok else v


def fetch_next_nonce(account: str) -> Tuple[Optional[int], str]:
    _require_open()
    status, body = _get(f"/bridge/v4/withdraw-nonce/{account}")
    return read_next_nonce(body, account) if status == 200 else (None, f"HTTP {status}")


def submit_withdrawal(i: WithdrawIntent, signature: str) -> Tuple[str, Optional[str], str]:
    """POST the signed intent; the outcome is READ BACK afterwards with /bridge/v4/withdrawal/{account}/{nonce}."""
    _require_open()
    import requests
    from .network import api_base, get_network
    r = requests.post(api_base(get_network()) + "/bridge/v4/withdraw", json=submit_body(i, signature), timeout=15)
    try:
        body = r.json()
    except ValueError:
        body = None
    return read_submit_response(r.status_code, body)


def fetch_withdrawal_call(account: str, nonce: int) -> WithdrawalCall:
    """GET /bridge/v4/withdrawal/{account}/{nonce}/call -- the ready call anyone may send (the relay, or you)."""
    _require_open()
    status, body = _get(f"/bridge/v4/withdrawal/{account}/{nonce}/call")
    return read_withdrawal_call(status, body)


withdrawal_call = fetch_withdrawal_call


def fetch_account_code(chain_id: int, address: str) -> Dict[str, Any]:
    """GET /bridge/v4/account-code/{chainId}/{address} -> read_account_code."""
    _require_open()
    status, body = _get(f"/bridge/v4/account-code/{int(chain_id)}/{address}")
    return read_account_code(status, body, chain_id, address)


def fetch_deposit_allowed(vault_chain_id: int, sender: str, amount: int) -> Dict[str, Any]:
    """GET /bridge/v4/deposit-allowed/{chainId}/{sender}/{amount} -> its coarse outcome only (read_deposit_allowed)."""
    _require_open()
    status, body = _get(f"/bridge/v4/deposit-allowed/{int(vault_chain_id)}/{sender}/{int(amount)}")
    return read_deposit_allowed(status, body, vault_chain_id)


def fetch_deposit_by_tx(tx_hash: str, v: VaultsRead, chain_id: Optional[int] = None) -> Dict[str, Any]:
    """GET /bridge/v4/deposit/tx/{hash}[?chain_id=] -- a deposit by the transaction the user sent (on the vault's chain,
    or a burn on Arc) -> read_deposit."""
    _require_open()
    q = f"?chain_id={int(chain_id)}" if chain_id is not None else ""
    status, body = _get(f"/bridge/v4/deposit/tx/{tx_hash}{q}")
    return read_deposit(status, body, v, tx_hash)


def fetch_deposits(account: str, v: VaultsRead) -> Dict[str, Any]:
    """GET /bridge/v4/deposits/{account} -> read_deposits (the account's rows and totals)."""
    _require_open()
    status, body = _get(f"/bridge/v4/deposits/{account}")
    return read_deposits(body, account, v) if status == 200 else {"ok": False, "error": f"HTTP {status}"}


def send_self_send(private_key: str, checked: Dict[str, Any], rpc_url: str) -> str:
    """Signs a call that ``self_send_from_call`` accepted with YOUR OWN key and sends it to the vault's chain through
    ``rpc_url``; you pay its gas. Returns the transaction hash. Nothing else is signed or sent."""
    _require_open()
    if not isinstance(checked, dict) or checked.get("ok") is not True:
        raise ValueError((checked or {}).get("text") or "the call was not checked")
    import requests
    from eth_account import Account
    from eth_utils import to_checksum_address
    tx = checked["tx"]

    def rpc(method: str, params: list) -> Any:
        r = requests.post(rpc_url, json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params}, timeout=15)
        d = r.json()
        if not isinstance(d, dict) or "error" in d or "result" not in d:
            raise RuntimeError(f"{method}: the chain did not answer")
        return d["result"]
    acct = Account.from_key(private_key)
    if int(rpc("eth_chainId", []), 16) != tx["chainId"]:
        raise ValueError("The RPC is for another chain, so nothing was sent.")
    nonce = int(rpc("eth_getTransactionCount", [acct.address, "pending"]), 16)
    gas = int(rpc("eth_estimateGas", [{"from": acct.address, "to": tx["to"], "data": tx["data"], "value": "0x0"}]), 16)
    base = int(rpc("eth_getBlockByNumber", ["latest", False])["baseFeePerGas"], 16)
    tip = int(rpc("eth_maxPriorityFeePerGas", []), 16)
    signed = acct.sign_transaction({"type": 2, "chainId": tx["chainId"], "nonce": nonce, "to": to_checksum_address(tx["to"]),
                                    "data": tx["data"], "value": 0, "gas": gas, "maxFeePerGas": 2 * base + tip,
                                    "maxPriorityFeePerGas": tip})
    raw = getattr(signed, "raw_transaction", None) or getattr(signed, "rawTransaction")
    raw_hex = raw.hex() if hasattr(raw, "hex") else str(raw)
    return rpc("eth_sendRawTransaction", [raw_hex if raw_hex.startswith("0x") else "0x" + raw_hex])


# ---- Arc: a source of deposits and a destination of payouts (the one vault on Arbitrum; interface 2.1, 5) ----------

#: Arc (chain 5042, CCTP domain 26). USDC is Arc's gas; deposits use its 6-decimal ERC-20 interface at 0x3600...0000.
ARC_CHAIN_ID = 5042
ARC_DOMAIN = 26
ARC_USDC = "0x3600000000000000000000000000000000000000"
#: Circle's CCTP V2 TokenMessenger (Circle publishes the same address on every EVM chain it lists).
CCTP_TOKEN_MESSENGER_V2 = "0x28b5a0e9C621a5BadaA536219b3a228C8168cf5d"
#: Arc deposits are Circle-forwarded: Circle's forwarding service completes the mint on the vault's chain.
ARC_DEPOSIT_FORWARDED = True
#: The fee-quote row for an Arc deposit: standard finality (Arc offers no other) with the forwarding fee.
ARC_DEPOSIT_QUOTE_ROUTE = 3


def arc_deposit_fee(quote: Any, amount: int) -> Optional[int]:
    """The most Circle may take from an Arc deposit of ``amount`` -- its protocol fee plus its forwarding fee, from the
    fee quote (Arc -> the vault's domain, forwarded), by the published rule. None when the quote does not read."""
    row = quote_for(quote, ARC_DEPOSIT_QUOTE_ROUTE)
    if row is None or not isinstance(amount, int) or amount <= 0:
        return None
    try:
        return max_fee_from_quote(amount, row[0], row[1])
    except ValueError:
        return None


#: Arc's USDC refuses transfers to and from blocklisted addresses: ``isBlacklisted(address)`` on its 6-decimal interface.
BLOCKLIST_SELECTOR = "0xfe575a87"
LINE_ARC_BLOCKED_FROM = "Arc does not allow USDC transfers from this address, so nothing was sent."
LINE_ARC_BLOCKED_TO = "Arc does not allow USDC transfers to this address, so nothing was signed."
LINE_ARC_BLOCK_UNREAD = "Whether Arc accepts USDC for this address cannot be confirmed right now, so nothing was built."


def blocklist_call_data(account: str) -> str:
    """The eth_call data of ``isBlacklisted(account)`` on Arc's USDC."""
    if not _is_addr(account):
        raise ValueError("not an address")
    return BLOCKLIST_SELECTOR + "0" * 24 + account[2:].lower()


def arc_blocklist_check(blocked: Optional[bool], direction: str) -> Dict[str, Any]:
    """The blocklist answer for an address (None = not read): a transfer is built only on a definite "not blocked"."""
    if blocked is False:
        return {"ok": True}
    if blocked is True:
        return {"ok": False, "text": LINE_ARC_BLOCKED_FROM if direction == "from" else LINE_ARC_BLOCKED_TO}
    return {"ok": False, "text": LINE_ARC_BLOCK_UNREAD}


def arc_payout_route(vault: Optional[Vault]) -> Optional[int]:
    """The payout route to Arc the vault offers: Circle-forwarded so nothing is needed on Arc -- standard (3) if the vault
    read has it open, else fast (4). None when neither is open, Arc is the vault's own domain, or Arc is not a 20-byte-
    address domain for it."""
    if vault is None or vault.cctp_domain == ARC_DOMAIN or not is_evm_domain(vault, ARC_DOMAIN):
        return None
    def is_open(k: int) -> bool:
        return any(r[0] == k and r[2] for r in vault.routes)
    return 3 if is_open(3) else 4 if is_open(4) else None


def arc_payout_fee(v: VaultsRead, quote: Any, route_kind: int, amount: int) -> Optional[int]:
    """The most Circle may take from a payout to Arc on ``route_kind``: the payout leaving the vault is ``amount`` - the
    withdrawal fee; the quote is the vault's domain -> Arc, forwarded. None when the quote does not read."""
    if not v.ok or route_kind not in (3, 4) or amount <= v.withdrawal_fee:
        return None
    row = quote_for(quote, route_kind)
    if row is None:
        return None
    try:
        return max_fee_from_quote(amount - v.withdrawal_fee, row[0], row[1])
    except ValueError:
        return None


def withdraw_arc_screen(v: VaultsRead, amount: int, max_fee: Optional[int]) -> Optional[Dict[str, Any]]:
    """The withdrawal screen for a payout to Arc: the withdrawal fee, Circle's fee (at most) and what arrives on Arc (at
    least). None when the read is unusable, the fee is not known, or the amount does not cover both fees."""
    if not v.ok or max_fee is None or amount <= v.withdrawal_fee + max_fee:
        return None
    vault = next((x for x in v.vaults if arc_payout_route(x) is not None), None)
    over = withdraw_max_problem(vault, amount) if vault else None
    return {"refusal": over,
            "rows": [{"label": "Withdrawal fee", "value": f"{usdc(v.withdrawal_fee)} USDC"},
                     {"label": "Circle's fee (at most)", "value": f"{usdc(max_fee)} USDC"},
                     {"label": "You receive (at least)", "value": f"{usdc(amount - v.withdrawal_fee - max_fee)} USDC on Arc"}],
            "gas": LINE_NO_ETH}


LINE_ARC_DELIVERY = "Circle delivers it to your address on Arc."
LINE_ARC_NO_ETH = "No ETH needed: on Arc the network fee is paid in USDC, and Circle delivers the deposit to Arbitrum."
#: Where an Arc deposit stands, from our deposit read alone (no Circle read).
ARC_DEPOSIT_STEPS = (("sent", "Sent on Arc"), ("confirmed", "Confirmed by Circle"), ("credited", "Credited on Vordium"))


def arc_deposit_stage(read: Optional[Dict[str, Any]]) -> Optional[str]:
    """sent (no message yet) -> confirmed (Circle's message named: the nonce) -> credited. None for a deposit that has its
    own line (waiting, stranded, not accepted) or is not a CCTP deposit."""
    if not read or read.get("status") != "found":
        return "sent"
    r = read["row"]
    if r.get("kind") != "cctp":
        return None
    if r.get("status") == "credited":
        return "credited"
    if r.get("status") == "pending":
        return "confirmed" if r.get("nonce") else "sent"
    return None


# ---- Arc deposit and withdraw helpers (network) ------------------------------------------------------------------------


def _rpc(url: str, method: str, params: list) -> Any:
    import requests
    r = requests.post(url, json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params}, timeout=15)
    d = r.json()
    if not isinstance(d, dict) or "error" in d or "result" not in d:
        raise RuntimeError(f"{method}: the chain did not answer")
    return d["result"]


def fetch_fee_quote(source_domain: int, dest_domain: int, forwarded: bool) -> Any:
    """Circle's fee quote (the pinned quote URL); None when it does not answer."""
    import requests
    try:
        r = requests.get(fee_quote_url(source_domain, dest_domain, forwarded), timeout=15)
        return r.json() if r.status_code == 200 else None
    except Exception:  # noqa: BLE001 -- no quote is "nothing is built", never a guess
        return None


def read_arc_blocked(arc_rpc_url: str, account: str) -> Optional[bool]:
    """isBlacklisted(account) on Arc, through YOUR Arc RPC (checked to be chain 5042). None when it does not read."""
    try:
        if int(_rpc(arc_rpc_url, "eth_chainId", []), 16) != ARC_CHAIN_ID:
            return None
        return read_bool_word(_rpc(arc_rpc_url, "eth_call", [{"to": ARC_USDC, "data": blocklist_call_data(account)}, "latest"]))
    except Exception:  # noqa: BLE001
        return None


def prepare_arc_deposit(sender: str, amount: int, *, arc_rpc_url: str, wait_confirmed: bool = False) -> Dict[str, Any]:
    """Every check of an Arc deposit, then its two calls (approve + the Circle-forwarded burn) -- or why nothing was built.

    Reads: the deployed contracts (network spec), the vaults (deposits must be open: a fresh read, the deployed vault
    listed, ``depositsOpen`` true for Arc), Circle's forwarded fee quote, the sender's account code on Arc and on the vault's
    chain, deposit-allowed, and Arc's blocklist (``arc_rpc_url``). A deposit that would wait is built only with
    ``wait_confirmed`` (you have seen the Waiting line). Returns ``{"ok": True, "txs", "max_fee", "credited_at_least"}``
    or ``{"ok": False, "text"}`` (or ``"ask": True`` with the Waiting line)."""
    _require_open()
    if not _is_addr(sender) or not isinstance(amount, int) or amount <= 0:
        return {"ok": False, "text": "Enter a USDC amount and an address."}
    deployments = fetch_deployments()
    v = deployment_check(fetch_vaults(), deployments)
    if not v.ok:
        return {"ok": False, "text": "The bridge could not be read, so nothing was built."}
    gate = deposit_gate(v, ARC_CHAIN_ID, deployments)
    if gate.state != "open":
        return {"ok": False, "text": gate.text}
    vault = next((x for x in v.vaults if x.cctp is not None and str(ARC_CHAIN_ID) in x.cctp[0]), None)
    if vault is None or not vault.handler:
        return {"ok": False, "text": "No vault takes deposits from Arc."}
    max_fee = arc_deposit_fee(fetch_fee_quote(ARC_DOMAIN, vault.cctp_domain, ARC_DEPOSIT_FORWARDED), amount)
    if max_fee is None:
        return {"ok": False, "text": "Circle's fee could not be read right now, so nothing was built."}
    arc_code, vault_code = fetch_account_code(ARC_CHAIN_ID, sender), fetch_account_code(int(vault.chain_id), sender)
    sender_ok = sender_check(arc_code, vault_code)
    if not sender_ok.ok:
        return {"ok": False, "text": sender_ok.text}
    held = key_held_check(arc_code)
    if not held["ok"]:
        return {"ok": False, "text": held["text"]}
    chk = deposit_check(v, ARC_CHAIN_ID, amount, max_fee, sender_ok)
    if not chk.ok:
        return {"ok": False, "text": chk.text}
    bound = binding_check(vault)
    if not bound["ok"]:
        return {"ok": False, "text": bound["text"]}
    allowed = fetch_deposit_allowed(int(vault.chain_id), sender, amount - max_fee)
    pre = pre_burn(allowed, "cctp", wait_confirmed)
    if not pre["ok"]:
        return {"ok": False, "ask": True, "text": pre["line"]} if pre.get("ask") else {"ok": False, "text": pre["text"]}
    bl = arc_blocklist_check(read_arc_blocked(arc_rpc_url, sender), "from")
    if not bl["ok"]:
        return {"ok": False, "text": bl["text"]}
    txs = arc_deposit_txs(chk, v, ARC_CHAIN_ID, ARC_USDC, CCTP_TOKEN_MESSENGER_V2, sender, amount, max_fee, allowed, wait_confirmed,
                          forwarded=ARC_DEPOSIT_FORWARDED)
    return {"ok": True, "txs": txs, "max_fee": max_fee, "credited_at_least": amount - max_fee}


def _send(rpc_url: str, private_key: str, tx: Dict[str, Any]) -> str:
    from eth_account import Account
    from eth_utils import to_checksum_address
    acct = Account.from_key(private_key)
    if int(_rpc(rpc_url, "eth_chainId", []), 16) != tx["chainId"]:
        raise ValueError("The RPC is for another chain, so nothing was sent.")
    nonce = int(_rpc(rpc_url, "eth_getTransactionCount", [acct.address, "pending"]), 16)
    gas = int(_rpc(rpc_url, "eth_estimateGas", [{"from": acct.address, "to": tx["to"], "data": tx["data"], "value": "0x0"}]), 16)
    base = int(_rpc(rpc_url, "eth_getBlockByNumber", ["latest", False])["baseFeePerGas"], 16)
    tip = int(_rpc(rpc_url, "eth_maxPriorityFeePerGas", []), 16)
    signed = acct.sign_transaction({"type": 2, "chainId": tx["chainId"], "nonce": nonce, "to": to_checksum_address(tx["to"]),
                                    "data": tx["data"], "value": 0, "gas": gas, "maxFeePerGas": 2 * base + tip, "maxPriorityFeePerGas": tip})
    raw = getattr(signed, "raw_transaction", None) or getattr(signed, "rawTransaction")
    raw_hex = raw.hex() if hasattr(raw, "hex") else str(raw)
    return _rpc(rpc_url, "eth_sendRawTransaction", [raw_hex if raw_hex.startswith("0x") else "0x" + raw_hex])


def _receipt(rpc_url: str, tx_hash: str, timeout_s: float = 240.0) -> Optional[Dict[str, Any]]:
    import time
    end = time.time() + timeout_s
    while time.time() < end:
        try:
            r = _rpc(rpc_url, "eth_getTransactionReceipt", [tx_hash])
            if isinstance(r, dict) and isinstance(r.get("status"), str):
                return r
        except RuntimeError:
            pass
        time.sleep(2)
    return None


def send_arc_deposit(private_key: str, prepared: Dict[str, Any], arc_rpc_url: str) -> str:
    """Signs and sends a ``prepare_arc_deposit`` result from YOUR key through YOUR Arc RPC (the fee is paid in USDC on
    Arc; nothing is needed on Arbitrum): the approval, then the burn, each confirmed. Returns the burn's transaction hash;
    follow it with ``fetch_deposit_by_tx(hash, v)`` and ``arc_deposit_stage``."""
    _require_open()
    if not isinstance(prepared, dict) or prepared.get("ok") is not True:
        raise ValueError((prepared or {}).get("text") or "the deposit was not prepared")
    last = ""
    for tx in prepared["txs"]:
        last = _send(arc_rpc_url, private_key, tx)
        rc = _receipt(arc_rpc_url, last)
        if rc is None:
            raise RuntimeError("The transaction has not confirmed yet. Check it before sending again.")
        if rc["status"] != "0x1":
            raise RuntimeError("The transaction failed on chain. Nothing was deposited.")
    return last


def _chain_time_s() -> Optional[int]:
    """The Vordium chain's own time (its latest block), never the computer's clock."""
    from .network import get_network
    try:
        ts = _rpc(get_network().rpc_url, "eth_getBlockByNumber", ["latest", False])["timestamp"]
        return int(ts, 16) if isinstance(ts, str) else int(ts)
    except Exception:  # noqa: BLE001
        return None


def prepare_withdraw_to_arc(account: str, amount: int, *, arc_rpc_url: str) -> Dict[str, Any]:
    """A withdrawal from Vordium to the same address on Arc, checked and ready to sign -- or why nothing was built.

    The vault's Circle-forwarded route (standard if open, else fast), Circle's fee from the forwarded quote on what leaves
    the vault, Arc's blocklist for the address (``arc_rpc_url``), the chain's next nonce and time. Returns
    ``{"ok": True, "intent", "max_fee", "receive_at_least"}``; sign with ``sign_withdraw_intent`` and post with
    ``submit_withdrawal`` (or use ``withdraw_to_arc``)."""
    _require_open()
    if not _is_addr(account) or not isinstance(amount, int) or amount <= 0:
        return {"ok": False, "text": "Enter a USDC amount and an address."}
    v = deployment_check(fetch_vaults(), fetch_deployments())
    if not v.ok:
        return {"ok": False, "text": "The bridge could not be read, so nothing was built."}
    vault = next((x for x in v.vaults if arc_payout_route(x) is not None), None)
    route = arc_payout_route(vault)
    if vault is None or route is None:
        return {"ok": False, "text": "Withdrawals to Arc are not open."}
    max_fee = arc_payout_fee(v, fetch_fee_quote(vault.cctp_domain, ARC_DOMAIN, True), route, amount)
    screen = withdraw_arc_screen(v, amount, max_fee)
    if max_fee is None or screen is None:
        return {"ok": False, "text": "Circle's fee could not be read right now, or the amount does not cover the fees, so nothing was built."}
    if screen["refusal"]:
        return {"ok": False, "text": screen["refusal"]}
    bl = arc_blocklist_check(read_arc_blocked(arc_rpc_url, account), "to")
    if not bl["ok"]:
        return {"ok": False, "text": bl["text"]}
    nxt, why = fetch_next_nonce(account)
    if nxt is None:
        return {"ok": False, "text": "The withdrawal could not be prepared right now. Try again in a moment."}
    now = _chain_time_s()
    if now is None:
        return {"ok": False, "text": "The chain's time could not be read, so nothing was signed."}
    intent, err = build_withdraw_intent(v, WithdrawIntent(account=account, vault_id=vault.id, recipient="0x" + "0" * 24 + account[2:].lower(),
                                                          amount=amount, nonce=nxt, route_kind=route, destination_domain=ARC_DOMAIN,
                                                          max_fee=max_fee, deadline=intent_deadline(now)), nxt, now)
    if intent is None:
        return {"ok": False, "text": err}
    return {"ok": True, "intent": intent, "max_fee": max_fee, "receive_at_least": amount - v.withdrawal_fee - max_fee}


def withdraw_to_arc(private_key: str, amount: int, *, arc_rpc_url: str) -> Tuple[str, Optional[str], str]:
    """Prepare, sign with YOUR account key, and submit a withdrawal to your own address on Arc. Returns
    ``read_submit_response``'s (outcome, code, message); read the outcome back with /bridge/v4/withdrawal/{account}/{nonce}."""
    _require_open()
    from eth_account import Account
    account = Account.from_key(private_key).address
    prepared = prepare_withdraw_to_arc(account, amount, arc_rpc_url=arc_rpc_url)
    if not prepared.get("ok"):
        return "refused", None, prepared.get("text", "")
    return submit_withdrawal(prepared["intent"], sign_withdraw_intent(private_key, prepared["intent"]))
