"""The signed release record: the genesis, chain id and deposit bridge of each network, signed by the release key.

A network's identity is taken from ``releases.json``, and only after its detached OpenPGP signature
(``releases.json.asc``) verifies under the release key that ships in this package (:data:`RELEASE_KEY`, fingerprint
:data:`RELEASE_KEY_FINGERPRINT`). The signature covers the exact bytes as served; the record is read from those same
bytes only after the signature holds.

The record names, for each network (keyed by its chain id): ``chain_id``, ``genesis_sha256``, the deposit ``bridge``
(``chain_id``, ``vault``, ``handler``, ``usdc``) and ``retired_genesis``; and for the whole record: ``sequence``,
``issued_at`` and ``valid_until``. A record is refused when it is unsigned, its signature does not verify, it is signed
by another key, its sequence is lower than the highest one this computer has seen for that network, or it has expired.

The key is pinned by its fingerprint. Its expiry is read from its newest self-signature. When that expiry is near
(:data:`KEY_REFRESH_BEFORE_S`) or past, the key is read again from where it is served (:data:`KEY_URLS`). A served copy is
used only when it is the same key (same fingerprint and point) and its self-signature verifies under that key: its newest
self-signature then gives the expiry. A revocation that verifies under the key refuses every record. Nothing else is
taken from a served copy, and when none can be read the shipped key is used as it is.

Everything else is checked here, with no other program: the ASCII armour (and its
CRC-24), the version 4 signature packet (EdDSA over Ed25519, SHA-256 or SHA-512), its hashed subpackets, the issuer
fingerprint, the signature hash over the data and the hashed trailer, and the Ed25519 signature itself (RFC 8032).
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import re
import threading
import time
import warnings
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Dict, List, Optional, Sequence, Tuple

#: The release key: every network record must be signed by it.
RELEASE_KEY_FINGERPRINT = "C5EB4728F660369CE519D834B48FB4B71EFD48AE"
RELEASE_KEY = """-----BEGIN PGP PUBLIC KEY BLOCK-----

mDMEaqXHBhYJKwYBBAHaRw8BAQdA8NRFgXw3NaEYFesojdDl1TlSlk9O5bXhsM4i
o7k3e+q0J1ZvcmRpdW0gUmVsZWFzZXMgPHJlbGVhc2VzQHZvcmRpdW0uY29tPoi1
BBMWCgBdFiEExetHKPZgNpzlGdg0tI+0tx79SK4FAmqlxwYbFIAAAAAABAAObWFu
dTIsMi41KzEuMTIsMCwzAhsDBQkDwmcABQsJCAcCAiICBhUKCQgLAgQWAgMBAh4H
AheAAAoJELSPtLce/UiuMUgA/2VojVnml+DJHQ6xbxhnbrNeD5p8H4lXsVASdpvs
RsCIAQCkMr8M76++QNGj08s+apf7CDgEVwbBFo4shxsYAU+gDw==
=20lT
-----END PGP PUBLIC KEY BLOCK-----
"""

#: Where each named network's record is read, in order. The signature is read at the same address + ".asc".
RECORD_URLS: Dict[str, Tuple[str, ...]] = {
    "mainnet": ("https://binaries.vordium.com/mainnet/releases.json", "https://rpc.vordium.com/releases.json"),
    "testnet": ("https://binaries.vordium.com/testnet/releases.json",),
}

#: The lowest record sequence this SDK release accepts for each chain id, also on a computer that has read no record yet
#: (an empty state folder): the release process sets it to the sequence of the record served when the release is made.
#: 0 = no floor. A floor above 0 also counts as a record already seen: while none is served, nothing is signed.
MIN_SEQUENCE: Dict[int, int] = {101101: 0, 101102: 0}

#: The record format this SDK reads.
RECORD_SCHEMA = "vordium.release-record/3"

#: Where the release key is served. Read only when the key's expiry is near or past (see :func:`refresh_key`).
KEY_URLS: Tuple[str, ...] = ("https://raw.githubusercontent.com/Vordium/security/main/release-key.asc",
                             "https://raw.githubusercontent.com/Vordium/node/main/pub_key.asc")
#: The key is read again from :data:`KEY_URLS` from this long before its expiry.
KEY_REFRESH_BEFORE_S = 30 * 86400
#: A key read from :data:`KEY_URLS` is used for this long before it is read again.
KEY_REFRESH_TTL_S = 6 * 3600
#: A read that left an expired key as it was is tried again after this long.
KEY_RETRY_S = 30
MAX_KEY_BYTES = 64 * 1024

MAX_RECORD_BYTES = 4 * 1024 * 1024
MAX_SIGNATURE_BYTES = 64 * 1024


class RecordRefused(Exception):
    """The release record cannot be used. ``code`` names the reason; the message is a plain sentence."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def _now() -> float:
    """This computer's clock (seconds). Tests replace it."""
    return time.time()


# ── Ed25519 verification (RFC 8032, section 6 reference) ────────────────────────────────────────────────────────────
_P = 2 ** 255 - 19
_L = 2 ** 252 + 27742317777372353535851937790883648493
_D = -121665 * pow(121666, _P - 2, _P) % _P
_SQRT_M1 = pow(2, (_P - 1) // 4, _P)


def _padd(a, b):
    x1, y1, z1, t1 = a
    x2, y2, z2, t2 = b
    a_ = (y1 - x1) * (y2 - x2) % _P
    b_ = (y1 + x1) * (y2 + x2) % _P
    c = 2 * t1 * t2 * _D % _P
    d = 2 * z1 * z2 % _P
    e, f, g, h = b_ - a_, d - c, d + c, b_ + a_
    return e * f % _P, g * h % _P, f * g % _P, e * h % _P


def _pmul(s: int, pt):
    q = (0, 1, 1, 0)
    while s > 0:
        if s & 1:
            q = _padd(q, pt)
        pt = _padd(pt, pt)
        s >>= 1
    return q


def _pequal(a, b) -> bool:
    x1, y1, z1, _ = a
    x2, y2, z2, _ = b
    return (x1 * z2 - x2 * z1) % _P == 0 and (y1 * z2 - y2 * z1) % _P == 0


def _recover_x(y: int, sign: int) -> Optional[int]:
    if y >= _P:
        return None
    x2 = (y * y - 1) * pow(_D * y * y + 1, _P - 2, _P)
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P != 0:
        x = x * _SQRT_M1 % _P
    if (x * x - x2) % _P != 0:
        return None
    if (x & 1) != sign:
        x = _P - x
    return x


_GY = 4 * pow(5, _P - 2, _P) % _P
_GX = _recover_x(_GY, 0)
_G = (_GX, _GY, 1, _GX * _GY % _P)


def _decompress(s: bytes):
    if len(s) != 32:
        return None
    y = int.from_bytes(s, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    x = _recover_x(y, sign)
    if x is None:
        return None
    return x, y, 1, x * y % _P


def ed25519_verify(public: bytes, msg: bytes, signature: bytes) -> bool:
    """RFC 8032 Ed25519 verification: True only for a valid signature of ``msg`` by ``public``."""
    if len(public) != 32 or len(signature) != 64:
        return False
    a = _decompress(public)
    if a is None:
        return False
    r = _decompress(signature[:32])
    if r is None:
        return False
    s = int.from_bytes(signature[32:], "little")
    if s >= _L:
        return False
    h = int.from_bytes(hashlib.sha512(signature[:32] + public + msg).digest(), "little") % _L
    return _pequal(_pmul(s, _G), _padd(r, _pmul(h, a)))


# ── ASCII armour and packets ────────────────────────────────────────────────────────────────────────────────────────
def _crc24(data: bytes) -> int:
    crc = 0xB704CE
    for byte in data:
        crc ^= byte << 16
        for _ in range(8):
            crc <<= 1
            if crc & 0x1000000:
                crc ^= 0x1864CFB
    return crc & 0xFFFFFF


def dearmor(text, kind: str) -> bytes:
    """The bytes inside one ASCII-armoured block of ``kind`` ("PGP SIGNATURE", "PGP PUBLIC KEY BLOCK"). The CRC-24
    line, when present, must match. Raises :class:`RecordRefused`."""
    if isinstance(text, (bytes, bytearray)):
        try:
            text = bytes(text).decode("ascii")
        except UnicodeDecodeError:
            raise RecordRefused("bad_armour", "The signature file is not ASCII armour.") from None
    lines = [(ln[:-1] if ln.endswith("\r") else ln).rstrip(" \t") for ln in str(text).split("\n")]
    while lines and not lines[0]:
        lines.pop(0)
    while lines and not lines[-1]:
        lines.pop()
    begin, end = f"-----BEGIN {kind}-----", f"-----END {kind}-----"
    if len(lines) < 3 or lines[0] != begin or lines[-1] != end:
        raise RecordRefused("bad_armour", f"The file is not one ASCII-armoured {kind.lower()}.")
    body = lines[1:-1]
    i = 0
    while i < len(body) and body[i]:                      # armour headers ("Key: value") up to the blank line
        if ": " not in body[i]:
            raise RecordRefused("bad_armour", f"The armour of the {kind.lower()} has a header line that is not one.")
        i += 1
    if i >= len(body):
        raise RecordRefused("bad_armour", f"The armour of the {kind.lower()} has no blank line before its data.")
    data_lines = body[i + 1:]
    crc_line = None
    if data_lines and data_lines[-1].startswith("="):
        crc_line = data_lines.pop()
    b64 = "".join(data_lines)
    if not b64 or any(ln.startswith("-----") for ln in data_lines):
        raise RecordRefused("bad_armour", f"The armour of the {kind.lower()} holds no data, or more than one block.")
    try:
        raw = base64.b64decode(b64, validate=True)
    except (binascii.Error, ValueError):
        raise RecordRefused("bad_armour", f"The armour of the {kind.lower()} is not valid base64.") from None
    if crc_line is not None:
        try:
            crc = base64.b64decode(crc_line[1:], validate=True)
        except (binascii.Error, ValueError):
            crc = b""
        if len(crc) != 3 or int.from_bytes(crc, "big") != _crc24(raw):
            raise RecordRefused("bad_armour", f"The armour checksum (CRC-24) of the {kind.lower()} does not match "
                                              "its data: the file was damaged or changed.")
    return raw


def _packets(raw: bytes) -> List[Tuple[int, bytes]]:
    """``[(tag, body)]`` of an OpenPGP packet sequence (old and new headers; partial lengths refused)."""
    out: List[Tuple[int, bytes]] = []
    i = 0
    bad = RecordRefused("bad_packet", "The OpenPGP data is not well formed.")
    while i < len(raw):
        ctb = raw[i]
        i += 1
        if not ctb & 0x80:
            raise bad
        if ctb & 0x40:                                     # new format
            tag = ctb & 0x3F
            if i >= len(raw):
                raise bad
            o = raw[i]
            if o < 192:
                n, i = o, i + 1
            elif o < 224:
                if i + 1 >= len(raw):
                    raise bad
                n, i = ((o - 192) << 8) + raw[i + 1] + 192, i + 2
            elif o == 255:
                if i + 4 >= len(raw):
                    raise bad
                n, i = int.from_bytes(raw[i + 1:i + 5], "big"), i + 5
            else:
                raise RecordRefused("bad_packet", "The OpenPGP data uses partial lengths, which are not read here.")
        else:                                              # old format
            tag, lt = (ctb >> 2) & 0x0F, ctb & 0x03
            if lt == 3:
                raise RecordRefused("bad_packet", "The OpenPGP data uses an indeterminate length, which is not read here.")
            w = (1, 2, 4)[lt]
            if i + w > len(raw):
                raise bad
            n, i = int.from_bytes(raw[i:i + w], "big"), i + w
        if i + n > len(raw):
            raise bad
        out.append((tag, raw[i:i + n]))
        i += n
    return out


def _mpi(b: bytes, i: int) -> Tuple[bytes, int]:
    if i + 2 > len(b):
        raise RecordRefused("bad_packet", "The OpenPGP data is not well formed.")
    bits = int.from_bytes(b[i:i + 2], "big")
    n = (bits + 7) // 8
    if i + 2 + n > len(b):
        raise RecordRefused("bad_packet", "The OpenPGP data is not well formed.")
    return b[i + 2:i + 2 + n], i + 2 + n


_ED25519_OID = bytes.fromhex("2b06010401da470f01")
_EDDSA_LEGACY = 22
_HASHES = {8: "sha256", 10: "sha512"}


@dataclass(frozen=True)
class PublicKey:
    """An Ed25519 OpenPGP public key: its v4 fingerprint (40 upper-case hex), its 32-byte point, and when it expires
    (seconds; None = never), read from its newest self-signature that verifies."""
    fingerprint: str
    point: bytes
    expires: Optional[int] = None
    signed_at: int = 0                     # the time of the self-signature the expiry was read from
    revoked: bool = False                  # a key revocation signature by this key verifies


def _key_body_point(body: bytes) -> bytes:
    if len(body) < 6 or body[0] != 4:
        raise RecordRefused("bad_key", "The release key is not a version 4 OpenPGP key.")
    if body[5] != _EDDSA_LEGACY:
        raise RecordRefused("bad_key", "The release key is not an Ed25519 key.")
    i = 6
    if i >= len(body):
        raise RecordRefused("bad_key", "The release key is not well formed.")
    oid_len = body[i]
    if body[i + 1:i + 1 + oid_len] != _ED25519_OID:
        raise RecordRefused("bad_key", "The release key is not an Ed25519 key.")
    point, end = _mpi(body, i + 1 + oid_len)
    if end != len(body) or len(point) != 33 or point[0] != 0x40:
        raise RecordRefused("bad_key", "The release key is not well formed.")
    return point[1:]


def parse_public_key(armoured) -> PublicKey:
    """The primary key of an armoured public key block. The fingerprint is computed from the key packet (SHA-1 over
    0x99 || length || packet). Only a version 4 EdDSA key on Ed25519 is accepted, with at least one user ID whose
    self-signature verifies; the newest such self-signature gives the key's expiry (``expires``, None = never)."""
    pk = _packets(dearmor(armoured, "PGP PUBLIC KEY BLOCK"))
    if not pk or pk[0][0] != 6:
        raise RecordRefused("bad_key", "The release key is not an OpenPGP public key.")
    body = pk[0][1]
    point = _key_body_point(body)
    key_prefix = b"\x99" + len(body).to_bytes(2, "big") + body
    fp = hashlib.sha1(key_prefix).hexdigest().upper()
    created_key = int.from_bytes(body[1:5], "big")
    best: Optional[Tuple[int, Optional[int]]] = None          # (self-signature time, key expiry seconds)
    uid: Optional[bytes] = None
    in_subkey = revoked = False
    for tag, pbody in pk[1:]:
        if tag == 14:                                          # a subkey: its signatures are not about the primary key
            uid, in_subkey = None, True
            continue
        if tag == 13:
            uid, in_subkey = pbody, False
            continue
        if tag == 2 and uid is None and not in_subkey:         # a signature on the key itself: only revocation is read
            try:
                rev = _parse_sig(pbody, (0x20,))
            except RecordRefused:
                continue
            if rev.issuer == fp and _sig_ok(rev, key_prefix, point):
                revoked = True
            continue
        if tag != 2 or uid is None:
            continue
        try:
            sig = _parse_sig(pbody, (0x10, 0x11, 0x12, 0x13))
        except RecordRefused:
            continue
        if sig.issuer != fp:
            continue
        prefix = key_prefix + b"\xb4" + len(uid).to_bytes(4, "big") + uid
        if not _sig_ok(sig, prefix, point):
            continue
        if best is None or sig.created >= best[0]:
            best = (sig.created, sig.key_expires)
    if best is None:
        raise RecordRefused("bad_key", "The release key carries no self-signature that verifies.")
    expires = created_key + best[1] if best[1] else None
    return PublicKey(fp, point, expires, best[0], revoked)


@dataclass(frozen=True)
class Signature:
    """A checked detached signature: who made it (issuer fingerprint) and when (seconds)."""
    fingerprint: str
    created: int


def _subpackets(area: bytes) -> List[Tuple[int, bool, bytes]]:
    out = []
    i = 0
    while i < len(area):
        o = area[i]
        if o < 192:
            n, i = o, i + 1
        elif o < 255:
            if i + 1 >= len(area):
                raise RecordRefused("bad_packet", "The signature's subpackets are not well formed.")
            n, i = ((o - 192) << 8) + area[i + 1] + 192, i + 2
        else:
            if i + 4 >= len(area):
                raise RecordRefused("bad_packet", "The signature's subpackets are not well formed.")
            n, i = int.from_bytes(area[i + 1:i + 5], "big"), i + 5
        if n < 1 or i + n > len(area):
            raise RecordRefused("bad_packet", "The signature's subpackets are not well formed.")
        t = area[i]
        out.append((t & 0x7F, bool(t & 0x80), area[i + 1:i + n]))
        i += n
    return out


class _Sig:
    """A parsed version 4 signature packet (EdDSA over Ed25519)."""

    def __init__(self, **kw):
        self.__dict__.update(kw)


def _parse_sig(b: bytes, types: Tuple[int, ...]) -> "_Sig":
    """A version 4 EdDSA signature packet of one of ``types``, with its hashed subpackets read. Raises
    :class:`RecordRefused` for anything else."""
    if not b:
        raise RecordRefused("bad_packet", "The OpenPGP signature is empty.")
    if b[0] != 4:
        raise RecordRefused("unsupported", f"The signature is a version {b[0]} OpenPGP signature; only version 4 "
                                           "signatures are accepted.")
    if len(b) < 6:
        raise RecordRefused("bad_packet", "The OpenPGP signature is not well formed.")
    sig_type, pk_algo, hash_algo = b[1], b[2], b[3]
    if sig_type not in types:
        raise RecordRefused("unsupported", "The signature is not a binary-document signature over the exact bytes.")
    if pk_algo != _EDDSA_LEGACY:
        raise RecordRefused("unsupported", f"The signature uses public-key algorithm {pk_algo}; only Ed25519 (EdDSA) "
                                           "signatures are accepted.")
    if hash_algo not in _HASHES:
        raise RecordRefused("unsupported", f"The signature uses hash algorithm {hash_algo}; only SHA-256 and SHA-512 "
                                           "are accepted.")
    hashed_end = 6 + int.from_bytes(b[4:6], "big")
    if hashed_end + 2 > len(b):
        raise RecordRefused("bad_packet", "The OpenPGP signature is not well formed.")
    hashed = b[6:hashed_end]
    i = hashed_end + 2 + int.from_bytes(b[hashed_end:hashed_end + 2], "big")
    if i + 2 > len(b):
        raise RecordRefused("bad_packet", "The OpenPGP signature is not well formed.")
    left16 = b[i:i + 2]
    r, i = _mpi(b, i + 2)
    s, i = _mpi(b, i)
    if i != len(b) or len(r) > 32 or len(s) > 32:
        raise RecordRefused("bad_packet", "The OpenPGP signature is not well formed.")
    created = expires = issuer = key_expires = None
    for t, critical, val in _subpackets(hashed):
        if t == 2:
            if created is not None or len(val) != 4:
                raise RecordRefused("bad_packet", "The signature's creation time is not well formed.")
            created = int.from_bytes(val, "big")
        elif t == 3:
            if expires is not None or len(val) != 4:
                raise RecordRefused("bad_packet", "The signature's expiry is not well formed.")
            expires = int.from_bytes(val, "big")
        elif t == 9:
            if key_expires is not None or len(val) != 4:
                raise RecordRefused("bad_packet", "The key's expiry is not well formed.")
            key_expires = int.from_bytes(val, "big")
        elif t == 33:
            if issuer is not None or len(val) != 21 or val[0] != 4:
                raise RecordRefused("bad_packet", "The signature's issuer fingerprint is not a version 4 fingerprint.")
            issuer = val[1:].hex().upper()
        elif critical:
            raise RecordRefused("unsupported", f"The signature carries a critical subpacket ({t}) that is not read here.")
    if created is None:
        raise RecordRefused("bad_packet", "The signature names no creation time.")
    return _Sig(head=b[:hashed_end], hash_algo=hash_algo, left16=left16, r=r, s=s, created=created, expires=expires,
                key_expires=key_expires, issuer=issuer)


def _sig_ok(sig: "_Sig", data: bytes, point: bytes) -> bool:
    """Whether ``sig`` is a valid signature by ``point`` over ``data`` (the v4 hash: data, the hashed part, the trailer)."""
    digest = hashlib.new(_HASHES[sig.hash_algo],
                         bytes(data) + sig.head + b"\x04\xff" + len(sig.head).to_bytes(4, "big")).digest()
    return digest[:2] == sig.left16 and ed25519_verify(point, digest, sig.r.rjust(32, b"\x00") + sig.s.rjust(32, b"\x00"))


def verify_detached(data: bytes, armoured_sig, keys: Sequence[PublicKey], now: Optional[float] = None) -> Signature:
    """Verify an armoured detached signature over the exact bytes ``data`` under one of ``keys`` (the pinned keys).
    Returns the signature's issuer and time; raises :class:`RecordRefused` with a plain sentence otherwise."""
    if not keys:
        raise RecordRefused("no_key", "No release key is pinned, so no record can be trusted.")
    pk = _packets(dearmor(armoured_sig, "PGP SIGNATURE"))
    if len(pk) != 1 or pk[0][0] != 2:
        raise RecordRefused("bad_packet", "The signature file must hold exactly one OpenPGP signature.")
    sig = _parse_sig(pk[0][1], (0x00,))
    issuer = sig.issuer
    if issuer is None:
        raise RecordRefused("wrong_key", "The signature does not name the fingerprint of the key that made it, so it "
                                         "cannot be matched to the release key.")
    key = next((k for k in keys if k.fingerprint == issuer), None)
    if key is None:
        raise RecordRefused("wrong_key", f"The record is signed by key {issuer}, not by the release key "
                                         f"{keys[0].fingerprint}. It is not used.")
    if not _sig_ok(sig, data, key.point):
        raise RecordRefused("bad_signature", "The record's signature does not verify under the release key: the record "
                                             "was changed after it was signed, or the signature is damaged. It is not used.")
    if key.revoked:
        raise RecordRefused("key_revoked", f"The release key {key.fingerprint} has been revoked by its owner. The record "
                                           "is not used.")
    t_now = _now() if now is None else now
    if sig.expires and sig.created + sig.expires < t_now:
        raise RecordRefused("signature_expired", "The record's signature has expired. It is not used.")
    if key.expires is not None and t_now > key.expires:
        raise RecordRefused("key_expired", f"The release key {key.fingerprint} expired at "
                                           f"{datetime.fromtimestamp(key.expires, timezone.utc):%Y-%m-%d %H:%M} UTC, "
                                           "and no served copy of it gives a later expiry. The record is not used.")
    return Signature(issuer, sig.created)


# ── the record ─────────────────────────────────────────────────────────────────────────────────────────────────────
_HEX64 = re.compile(r"[0-9a-f]{64}")
_ADDR = re.compile(r"0x[0-9a-fA-F]{40}")
_TIME = re.compile(r"([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})Z")


@dataclass(frozen=True)
class Bridge:
    """The deposit bridge as the signed record names it."""
    chain_id: int
    vault: str          # lower-case 0x address
    handler: str
    usdc: str


@dataclass(frozen=True)
class NetworkEntry:
    """One network of a signed record."""
    chain_id: int
    genesis_sha256: str
    bridge: Bridge
    retired_genesis: Tuple[str, ...]
    name: Optional[str] = None


@dataclass(frozen=True)
class Record:
    """A signed record, read from the verified bytes."""
    sequence: int
    issued_at: int
    valid_until: int
    networks: Dict[int, NetworkEntry]
    signed_by: str = ""


def _malformed(what: str) -> RecordRefused:
    return RecordRefused("malformed", f"The signed release record is not well formed: {what}. It is not used.")


def _pairs(pairs):
    d = {}
    for k, v in pairs:
        if k in d:
            raise _malformed(f"the key {k!r} appears twice")
        d[k] = v
    return d


def _time(v, what: str) -> int:
    m = _TIME.fullmatch(v) if isinstance(v, str) else None
    if not m:
        raise _malformed(f"{what} is not a time like 2026-01-01T00:00:00Z")
    try:
        return int(datetime(*map(int, m.groups()), tzinfo=timezone.utc).timestamp())
    except ValueError:
        raise _malformed(f"{what} is not a real date") from None


def _int(v, what: str) -> int:
    if isinstance(v, bool) or not isinstance(v, int) or v < 0 or v > 2 ** 53 - 1:
        raise _malformed(f"{what} is not a whole number")
    return v


def _addr(v, what: str) -> str:
    if not isinstance(v, str) or not _ADDR.fullmatch(v):
        raise _malformed(f"{what} is not an address")
    return v.lower()


def _genesis(v, what: str) -> str:
    if not isinstance(v, str) or not _HEX64.fullmatch(v):
        raise _malformed(f"{what} is not 64 lower-case hex characters")
    return v


def is_network_record(data: bytes) -> bool:
    """Whether bytes that could not be verified claim to be a network record (a JSON object with ``networks``). Used
    only to tell an unsigned record (refused) from another file (ignored); no value of it is ever used."""
    try:
        j = json.loads(bytes(data).decode("utf-8"))
    except (ValueError, UnicodeDecodeError, RecursionError):
        return False
    return isinstance(j, dict) and "networks" in j


def parse_record(data: bytes) -> Optional[Record]:
    """The record in the VERIFIED bytes ``data``. None when the file is not a network record (it has no ``networks``:
    the release list of an earlier format). Raises :class:`RecordRefused` for a record that is not well formed."""
    try:
        j = json.loads(bytes(data).decode("utf-8"), object_pairs_hook=_pairs)
    except RecordRefused:
        raise
    except (ValueError, UnicodeDecodeError, RecursionError):
        raise _malformed("it is not JSON") from None
    if not isinstance(j, dict) or "networks" not in j:
        return None
    if j.get("schema") != RECORD_SCHEMA:
        raise RecordRefused("schema", f"The signed release record has schema {j.get('schema')!r}; this SDK reads "
                                      f"{RECORD_SCHEMA!r}. Update the SDK. It is not used.")
    seq = _int(j.get("sequence"), "sequence")
    issued = _time(j.get("issued_at"), "issued_at")
    until = _time(j.get("valid_until"), "valid_until")
    if until < issued:
        raise _malformed("valid_until is before issued_at")
    nets = j.get("networks")
    if not isinstance(nets, dict) or not nets:
        raise _malformed("networks lists no network")
    out: Dict[int, NetworkEntry] = {}
    for key, e in nets.items():
        if not isinstance(e, dict):
            raise _malformed(f"network {key} is not an object")
        cid = _int(e.get("chain_id"), f"network {key} chain_id")
        if cid <= 0 or key != str(cid):
            raise _malformed(f"network {key} is listed under another chain id than its own ({cid})")
        g = _genesis(e.get("genesis_sha256"), f"network {key} genesis_sha256")
        b = e.get("bridge")
        if not isinstance(b, dict):
            raise _malformed(f"network {key} names no bridge")
        bcid = _int(b.get("chain_id"), f"network {key} bridge chain_id")
        if bcid <= 0:
            raise _malformed(f"network {key} bridge chain_id is not a chain id")
        bridge = Bridge(bcid, _addr(b.get("vault"), f"network {key} bridge vault"),
                        _addr(b.get("handler"), f"network {key} bridge handler"),
                        _addr(b.get("usdc"), f"network {key} bridge usdc"))
        rg = e.get("retired_genesis", [])
        if not isinstance(rg, list):
            raise _malformed(f"network {key} retired_genesis is not a list")
        past = tuple(_genesis(x, f"network {key} retired_genesis") for x in rg)
        if g in past:
            raise _malformed(f"network {key} lists its own genesis in retired_genesis")
        name = e.get("name")
        out[cid] = NetworkEntry(cid, g, bridge, past, name if isinstance(name, str) else None)
    return Record(seq, issued, until, out)


# ── the highest sequence seen, per network (next to the nonce marks, 0600) ──────────────────────────────────────────
_MEMORY: Dict[str, int] = {}
_MEMORY_LOCK = threading.Lock()


class RecordStateWarning(UserWarning):
    """The record's sequence is kept in this process only (the state directory cannot be used)."""


def _state_path(fingerprint: str, chain_id: int) -> Optional[Path]:
    from .nonces import state_dir
    d = state_dir()
    try:
        d.mkdir(mode=0o700, parents=True, exist_ok=True)
        try:
            os.chmod(d, 0o700)
        except OSError:
            pass
    except OSError as e:
        warnings.warn(f"the release record's sequence is kept in this process only: the state directory {d} cannot "
                      f"be used ({e.__class__.__name__}).", RecordStateWarning, stacklevel=4)
        return None
    return d / f"release-record.{fingerprint[:16].lower()}.{int(chain_id)}"


def _state_warning(path: Path, e: OSError) -> None:
    warnings.warn(f"the release record's sequence is kept in this process only: {path.parent} cannot be used "
                  f"({e.__class__.__name__}).", RecordStateWarning, stacklevel=4)


def _write_seq(path: Path, sequence: int) -> None:
    """Write ``sequence`` as the stored mark (0600, by rename); a temporary file left by a failed write is removed."""
    tmp = path.with_name(f"{path.name}.{os.getpid()}.{threading.get_ident()}.tmp")
    try:
        fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.write(fd, f"{sequence}\n".encode())
        finally:
            os.close(fd)
        os.replace(tmp, path)
    except OSError:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _read_seq(path: Path) -> Optional[int]:
    try:
        txt = path.read_text().strip()
    except FileNotFoundError:
        return None
    except (OSError, UnicodeDecodeError) as e:             # it is there but cannot be read: refuse, never "none seen"
        raise RecordRefused("state", f"The stored sequence of the release record ({path}) cannot be read "
                                     f"({e.__class__.__name__}); nothing was signed. Check the file, or remove it to "
                                     "accept the next record.") from None
    if not re.fullmatch(r"[0-9]+", txt):
        raise RecordRefused("state", f"The stored sequence of the release record ({path}) cannot be read; nothing was "
                                     "signed. Check the file, or remove it to accept the next record.")
    return int(txt)


def _floor(chain_id: int) -> Optional[int]:
    v = MIN_SEQUENCE.get(int(chain_id), 0)
    return int(v) if isinstance(v, int) and not isinstance(v, bool) and v > 0 else None


def _other_sdk_seq(path: Path) -> Optional[int]:
    """The sequence the JavaScript SDK keeps in the same state folder (its file holds the sequence + 1; 0 = none). A
    file that cannot be read is not counted here (that SDK refuses on it itself)."""
    other = path.with_name(path.name.replace("release-record.", "release-record-mark.", 1))
    try:
        txt = other.read_text().strip()
    except (OSError, UnicodeDecodeError):
        return None
    return int(txt) - 1 if re.fullmatch(r"[0-9]+", txt) and int(txt) > 0 else None


def seen_sequence(fingerprint: str, chain_id: int, with_floor: bool = True) -> Optional[int]:
    """The highest sequence of a verified record seen for ``chain_id`` on this computer, by this SDK or the JavaScript
    SDK in the same state folder, and (``with_floor``) at least this release's :data:`MIN_SEQUENCE` (None when none)."""
    floor = _floor(chain_id) if with_floor else None
    key = f"{fingerprint}:{chain_id}"
    path = _state_path(fingerprint, chain_id)
    with _MEMORY_LOCK:
        mem = _MEMORY.get(key)
    if path is None:
        vals = [v for v in (mem, floor) if v is not None]
        return max(vals) if vals else None
    from .nonces import _file_lock
    try:
        with _file_lock(path.with_name(path.name + ".lock")):
            disk = _read_seq(path)
    except OSError as e:                                   # no lock (a folder that cannot be written): read it as is
        _state_warning(path, e)
        disk = _read_seq(path)
    vals = [v for v in (mem, disk, _other_sdk_seq(path), floor) if v is not None]
    return max(vals) if vals else None


def accept_sequence(fingerprint: str, chain_id: int, sequence: int) -> None:
    """Refuse ``sequence`` when it is lower than the highest one seen for ``chain_id``; else keep the highest."""
    key = f"{fingerprint}:{chain_id}"
    path = _state_path(fingerprint, chain_id)

    floor = _floor(chain_id)
    if floor is not None and sequence < floor:
        raise RecordRefused("rollback", f"The signed release record for chain {chain_id} has sequence {sequence}, "
                                        f"lower than sequence {floor}, the lowest this SDK release accepts: an older "
                                        "record is being served. It is not used.")

    def check(last: Optional[int]) -> None:
        if path is not None:
            o = _other_sdk_seq(path)
            last = o if last is None else (last if o is None else max(last, o))
        if last is not None and sequence < last:
            raise RecordRefused("rollback", f"The signed release record for chain {chain_id} has sequence {sequence}, "
                                            f"lower than sequence {last} already seen on this computer: an older record "
                                            "is being served. It is not used.")

    with _MEMORY_LOCK:
        check(_MEMORY.get(key))
        if path is None:
            _MEMORY[key] = max(sequence, _MEMORY.get(key, sequence))
            return
        from .nonces import _file_lock
        try:
            with _file_lock(path.with_name(path.name + ".lock")):
                last = _read_seq(path)
                check(last)
                if last is None or sequence > last:
                    _write_seq(path, sequence)
        except OSError as e:                               # no lock or no write: kept in this process only, and still
            _state_warning(path, e)                        # held to the stored sequence, read without the lock
            check(_read_seq(path))
        _MEMORY[key] = max(sequence, _MEMORY.get(key, sequence))


# ── reading ────────────────────────────────────────────────────────────────────────────────────────────────────────
def fetch(url: str, timeout: float, limit: int) -> Optional[bytes]:
    """The exact bytes served at ``url``, or None when nothing is served there (no answer, not 200, a redirect)."""
    from . import _http
    try:
        r = _http.get(url, timeout=timeout, stream=True)
    except Exception:
        return None
    try:
        if r.status_code != 200:
            return None
        body = bytearray()
        try:
            for chunk in r.iter_content(65536):             # read no further than the limit
                body += chunk
                if len(body) > limit:
                    raise RecordRefused("too_large", f"The file at {url} is larger than a release record can be. It "
                                                     "is not used.")
        except RecordRefused:
            raise
        except Exception:
            return None
        return bytes(body)
    finally:
        r.close()


@dataclass(frozen=True)
class Verified:
    """A verified record and the entry of the network it was read for."""
    record: Record
    entry: NetworkEntry
    url: str


def refresh_key(key: PublicKey, urls: Sequence[str] = KEY_URLS, timeout: float = 6.0,
                get: Optional[Callable[[str, float, int], Optional[bytes]]] = None) -> PublicKey:
    """``key`` as its newest served copy states it. A copy at ``urls`` is used only when it parses as the same key (same
    fingerprint and point, a self-signature that verifies under that key) and its newest self-signature is newer than
    the one ``key`` was read from; a copy carrying a revocation that verifies under the key gives the key as revoked.
    A copy that cannot be read, is another key or is older is skipped; with none usable, ``key`` is returned as it is."""
    get = get or fetch
    best = key
    for url in urls:
        try:
            data = get(url, timeout, MAX_KEY_BYTES)
            if data is None:
                continue
            k = parse_public_key(data.decode("ascii"))
        except (RecordRefused, UnicodeDecodeError, ValueError):
            continue
        if k.fingerprint != key.fingerprint or k.point != key.point:
            continue
        if k.revoked:
            return k
        if k.signed_at > best.signed_at:
            best = k
    return best


_refreshed: Dict[str, Tuple[float, PublicKey]] = {}          # fingerprint -> (read again after, key)
_refresh_lock = threading.Lock()
_shipped_point: Optional[bytes] = None


def key_now(key: PublicKey, timeout: float = 6.0,
            get: Optional[Callable[[str, float, int], Optional[bytes]]] = None) -> PublicKey:
    """``key`` with its expiry refreshed (:func:`refresh_key`) when it is the shipped release key and its expiry is near
    or past; any other key as given. A refresh starts from the newest copy read before, so a read that fails never
    takes back a later expiry; it is done again after :data:`KEY_REFRESH_TTL_S`, or after :data:`KEY_RETRY_S` while the
    key it gives has expired. The key is read outside any lock, within ``timeout`` per read."""
    global _shipped_point
    if _shipped_point is None:
        _shipped_point = parse_public_key(RELEASE_KEY).point
    if key.fingerprint != RELEASE_KEY_FINGERPRINT or key.point != _shipped_point:
        return key
    if key.expires is None or _now() < key.expires - KEY_REFRESH_BEFORE_S:
        return key
    with _refresh_lock:
        hit = _refreshed.get(key.fingerprint)
        seed = hit[1] if hit is not None and hit[1].signed_at >= key.signed_at else key
        if hit is not None and seed is hit[1] and _now() < hit[0]:
            return seed
    r = refresh_key(seed, timeout=timeout, get=get)                 # read outside the lock
    with _refresh_lock:
        hit = _refreshed.get(key.fingerprint)
        if hit is not None and (hit[1].revoked or (hit[1].signed_at > r.signed_at and not r.revoked)):
            r = hit[1]                                              # a revocation, or a newer copy read meanwhile, stays
        expired = r.expires is not None and _now() > r.expires and not r.revoked
        _refreshed[key.fingerprint] = (_now() + (KEY_RETRY_S if expired else KEY_REFRESH_TTL_S), r)
    return r


def pinned_keys(release_keys: Optional[Sequence] = None) -> List[PublicKey]:
    """The keys a record must be signed by: the shipped release key, or (tests only) the armoured keys given. The shipped
    key's expiry is refreshed by :func:`read_record` from its served copy when near or past (see :func:`key_now`)."""
    if release_keys is None:
        k = parse_public_key(RELEASE_KEY)
        if k.fingerprint != RELEASE_KEY_FINGERPRINT:                      # the shipped key is the one named
            raise RecordRefused("bad_key", "The shipped release key does not have the shipped fingerprint.")
        return [k]
    keys = [x if isinstance(x, PublicKey) else parse_public_key(x) for x in release_keys]
    if not keys:
        raise RecordRefused("no_key", "No release key was given, so no record can be trusted.")
    return keys


def read_record(chain_id: int, urls: Sequence[str], keys: Sequence[PublicKey], timeout: float = 6.0,
                get: Optional[Callable[[str, float, int], Optional[bytes]]] = None) -> Optional[Verified]:
    """Read the signed record for ``chain_id`` from the first of ``urls`` that serves one.

    Returns None when no address serves a network record (nothing, or a signed release list of an earlier format) and
    no record for this network was seen on this computer before. Raises :class:`RecordRefused` (with a plain sentence)
    for an unsigned record, a bad signature, another key, a record of an unknown format, an expired record, a sequence
    lower than one seen before, a record that does not list ``chain_id``, or, when a record for this network was seen
    before, for no record served now."""
    get = get or fetch
    problem: Optional[RecordRefused] = None
    for url in urls:
        try:
            data = get(url, timeout, MAX_RECORD_BYTES)
            if data is None:
                continue
            sig = get(url + ".asc", timeout, MAX_SIGNATURE_BYTES)
            if sig is None or b"-----BEGIN PGP SIGNATURE-----" not in sig:
                if is_network_record(data):
                    raise RecordRefused("unsigned", f"The release record at {url} is not signed (no {url}.asc). It "
                                                    "is not used.")
                continue
            signed = verify_detached(data, sig, [key_now(k, timeout, get) for k in keys])
            rec = parse_record(data)                       # the verified bytes, never a second read
            if rec is None:
                continue
            rec = Record(rec.sequence, rec.issued_at, rec.valid_until, rec.networks, signed.fingerprint)
            if _now() > rec.valid_until:
                raise RecordRefused("expired", f"The signed release record expired at "
                                               f"{datetime.fromtimestamp(rec.valid_until, timezone.utc):%Y-%m-%d %H:%M} "
                                               "UTC. It is not used. Try again later; if this persists, check this "
                                               "computer's clock.")
            entry = rec.networks.get(int(chain_id))
            if entry is None:
                raise RecordRefused("not_listed", f"The signed release record does not list chain {chain_id}. Nothing "
                                                  "is signed for it.")
            accept_sequence(signed.fingerprint, chain_id, rec.sequence)
            return Verified(rec, entry, url)
        except RecordRefused as e:
            if problem is None:
                problem = e
    if problem is not None:
        raise problem
    for k in keys:
        last = seen_sequence(k.fingerprint, chain_id)
        if last is not None and seen_sequence(k.fingerprint, chain_id, with_floor=False) is None:
            raise RecordRefused("not_served", f"No signed release record for chain {chain_id} is served now, and this "
                                              f"SDK release needs one with sequence {last} or later. Nothing is signed "
                                              "until it is served.")
        if last is not None:
            raise RecordRefused("not_served", f"No signed release record for chain {chain_id} is served now, though "
                                              f"one (sequence {last}) was read on this computer before. Nothing is "
                                              "signed until it is served again.")
    return None
