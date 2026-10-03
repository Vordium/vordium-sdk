"""The referral messages a trader signs with ``personal_sign`` (EIP-191).

Below the activation height ``H`` these are byte-for-byte the messages the web app builds. From ``H`` they
carry ``Genesis: <sha256>`` as line 3. In the window before ``H``, or when the format cannot be
confirmed, nothing is built: :class:`vordium.rollb.SigningPaused` is raised with the reason. Pass the phase from
:func:`vordium.rollb.read_signing_phase` (read it just before signing).
"""

from __future__ import annotations

from eth_account import Account
from eth_account.messages import encode_defunct

from .rollb import SigningPhase, with_genesis_line


def register_trader_message(chain_id: int, referrer: str, code: str, nonce: int, phase: SigningPhase) -> str:
    return "\n".join(with_genesis_line([
        "Vordex Referral",
        f"Chain: {chain_id}",
        "Action: Register Trader",
        f"Referrer: {referrer.lower()}",
        f"Code: {code}",
        f"Nonce: {nonce}",
    ], phase))


def register_code_message(chain_id: int, referrer: str, code: str, nonce: int, phase: SigningPhase) -> str:
    """Registering a referral code, signed by the referrer."""
    return "\n".join(with_genesis_line([
        "Vordex Referral",
        f"Chain: {chain_id}",
        "Action: Register Code",
        f"Referrer: {referrer.lower()}",
        f"Code: {code}",
        f"Nonce: {nonce}",
    ], phase))


def claim_earnings_message(chain_id: int, referrer: str, nonce: int, phase: SigningPhase) -> str:
    return "\n".join(with_genesis_line([
        "Vordex Referral",
        f"Chain: {chain_id}",
        "Action: Claim Earnings",
        f"Referrer: {referrer.lower()}",
        f"Nonce: {nonce}",
    ], phase))


def sign_referral_message(private_key: str, message: str) -> str:
    """``personal_sign`` the message and return the 64-byte ``r||s`` 0x-hex the referral routes take."""
    sig = Account.sign_message(encode_defunct(text=message), private_key=private_key).signature.hex()
    sig = sig[2:] if sig.startswith("0x") else sig
    return "0x" + sig[:128]
