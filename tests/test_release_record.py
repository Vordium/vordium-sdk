"""The signed release record: a network's genesis, chain id and deposit bridge are taken only from ``releases.json``
whose detached OpenPGP signature verifies under the pinned release key.

Vectors (tests/vectors/release-record): ``releases.json`` + ``.asc`` signed by a TEST key (``test-pub_key.asc``; its
private half was destroyed), ``negative/tampered-*`` (one byte changed after signing) and ``negative/wrong-key-*`` (a
valid signature by another key). The shipped code pins only the release key; the test key reaches the SDK through the
test-only ``release_keys=`` argument.

Records with other contents are signed here by a throwaway key made in the test (RFC 8032 signing below).
"""

import base64
import dataclasses
import hashlib
import json
import pathlib
import warnings

import pytest

from vordium import bridge_v4, eip712, domains, release_record as rr
from vordium import network as net

V = pathlib.Path(__file__).parent / "vectors" / "release-record"
TEST_FP = "9BDD04101034D5C48AAA0B75ECF4078B2EE64A49"
FIX_CHAIN = 101199
FIX_GENESIS = "3bab98d17e374eed971918a5bb83a5dc07c9665e1f43753443bc85369e58dcdf"
FIX_RETIRED = "2c1c0679fa6ab8358f1d3e8d294a8d1c73ac2e2caf9079f1216abedc3d9fdf4f"
IN_FORCE = 1795000000          # 2026-11-18, inside the fixture's issued_at .. valid_until
URL = "https://records.invalid/releases.json"
_REAL_READ = net._read_record


def vec(name: str) -> bytes:
    return (V / name).read_bytes()


TEST_KEY = vec("test-pub_key.asc").decode()


# ── a throwaway signer (test only) ─────────────────────────────────────────────────────────────────────────────────
def _encode(pt) -> bytes:
    x, y, z, _ = pt
    zi = pow(z, rr._P - 2, rr._P)
    x, y = x * zi % rr._P, y * zi % rr._P
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


class Signer:
    """An Ed25519 OpenPGP key made from a seed, able to sign detached v4 signatures."""

    def __init__(self, seed: bytes, created: int = 1794900000):
        h = hashlib.sha512(seed).digest()
        a = int.from_bytes(h[:32], "little")
        a &= (1 << 254) - 8
        a |= 1 << 254
        self.a, self.prefix = a, h[32:]
        self.point = _encode(rr._pmul(a, rr._G))
        body = bytes([4]) + created.to_bytes(4, "big") + bytes([22]) + bytes([9]) + rr._ED25519_OID + \
            (263).to_bytes(2, "big") + b"\x40" + self.point
        self.key_body = body
        self.fingerprint = hashlib.sha1(b"\x99" + len(body).to_bytes(2, "big") + body).hexdigest().upper()

    def raw_sign(self, msg: bytes) -> bytes:
        r = int.from_bytes(hashlib.sha512(self.prefix + msg).digest(), "little") % rr._L
        rb = _encode(rr._pmul(r, rr._G))
        k = int.from_bytes(hashlib.sha512(rb + self.point + msg).digest(), "little") % rr._L
        return rb + ((r + k * self.a) % rr._L).to_bytes(32, "little")

    def public_armour(self) -> str:
        return key_block(self)

    def sign(self, data: bytes, *, version=4, sig_type=0, algo=22, hash_algo=10, created=1794950000,
             extra_hashed=b"", issuer=True) -> str:
        sub = b""
        if issuer:
            sub += bytes([22, 33, 4]) + bytes.fromhex(self.fingerprint)
        sub += bytes([5, 2]) + created.to_bytes(4, "big") + extra_hashed
        head = bytes([version, sig_type, algo, hash_algo]) + len(sub).to_bytes(2, "big") + sub
        name = {8: "sha256", 10: "sha512"}.get(hash_algo, "sha512")
        digest = hashlib.new(name, data + head + b"\x04\xff" + len(head).to_bytes(4, "big")).digest()
        sig = self.raw_sign(digest)
        unhashed = bytes([9, 16]) + bytes.fromhex(self.fingerprint)[-8:]
        body = head + len(unhashed).to_bytes(2, "big") + unhashed + digest[:2] + mpi(sig[:32]) + mpi(sig[32:])
        return armour(packet(2, body), "PGP SIGNATURE")


def mpi(b: bytes) -> bytes:
    b = b.lstrip(b"\x00")
    return (len(b) * 8 - (8 - b[0].bit_length()) if b else 0).to_bytes(2, "big") + b


def packet(tag: int, body: bytes) -> bytes:
    assert len(body) < 192
    return bytes([0xC0 | tag, len(body)]) + body


def armour(raw: bytes, kind: str, crc: bool = True) -> str:
    b64 = base64.b64encode(raw).decode()
    lines = [f"-----BEGIN {kind}-----", ""] + [b64[i:i + 64] for i in range(0, len(b64), 64)]
    if crc:
        lines.append("=" + base64.b64encode(rr._crc24(raw).to_bytes(3, "big")).decode())
    return "\n".join(lines + [f"-----END {kind}-----", ""])


SIGNER = Signer(b"release-record test signer")
OTHER = Signer(b"another signer")
NEW_GENESIS = hashlib.sha256(b"a new genesis").hexdigest()
VAULT = "0x" + "11" * 20
HANDLER = bridge_v4.create_address(VAULT, 1)
USDC = "0x" + "af" * 20


def record(seq=1, chain=101101, genesis=NEW_GENESIS, past=(FIX_RETIRED,), until="2026-12-17T00:00:00Z",
           schema=rr.RECORD_SCHEMA, vault=VAULT, handler=HANDLER, usdc=USDC) -> bytes:
    j = {"schema": schema, "sequence": seq, "issued_at": "2026-11-17T00:00:00Z", "valid_until": until,
         "networks": {str(chain): {"chain_id": chain, "genesis_sha256": genesis,
                                   "bridge": {"chain_id": 42161, "vault": vault, "handler": handler, "usdc": usdc},
                                   "retired_genesis": list(past)}}}
    return json.dumps(j, indent=1).encode()


class Served:
    """What the record addresses serve: url -> bytes. Counts reads."""

    def __init__(self, files=None):
        self.files = dict(files or {})
        self.reads = []

    def __call__(self, url, timeout, limit):
        self.reads.append(url)
        return self.files.get(url)


@pytest.fixture(autouse=True)
def _clock(monkeypatch):
    monkeypatch.setattr(rr, "_now", lambda: IN_FORCE)
    rr._MEMORY.clear()
    yield
    rr._MEMORY.clear()


def read(served, chain=FIX_CHAIN, keys=None, urls=(URL,)):
    return rr.read_record(chain, urls, rr.pinned_keys(keys if keys is not None else [TEST_KEY]), get=served)


def refused(code, served, **kw):
    with pytest.raises(rr.RecordRefused) as e:
        read(served, **kw)
    assert e.value.code == code, (e.value.code, str(e.value))
    msg = str(e.value)
    assert msg[0].isupper() and msg.endswith("."), msg          # a plain sentence
    return msg


# ── the fixture ───────────────────────────────────────────────────────────────────────────────────────────────────
def test_vectors_are_the_published_fixture():
    for line in vec("SHA256SUMS").decode().splitlines():
        digest, name = line.split()
        assert hashlib.sha256(vec(name)).hexdigest() == digest, name


def test_fixture_verifies_under_the_test_key():
    v = read(Served({URL: vec("releases.json"), URL + ".asc": vec("releases.json.asc")}))
    assert v.record.signed_by == TEST_FP and v.record.sequence == 1
    assert v.entry.chain_id == FIX_CHAIN and v.entry.genesis_sha256 == FIX_GENESIS
    assert v.entry.retired_genesis == (FIX_RETIRED,)
    assert v.entry.bridge.chain_id == 42161


def test_test_key_fingerprint_is_recomputed_from_the_key_packet():
    assert rr.parse_public_key(TEST_KEY).fingerprint == TEST_FP


def test_tampered_record_is_refused_as_a_bad_signature():
    msg = refused("bad_signature", Served({URL: vec("negative/tampered-releases.json"),
                                           URL + ".asc": vec("negative/tampered-releases.json.asc")}))
    assert "does not verify" in msg


def test_signature_by_another_key_is_refused():
    msg = refused("wrong_key", Served({URL: vec("negative/wrong-key-releases.json"),
                                       URL + ".asc": vec("negative/wrong-key-releases.json.asc")}))
    assert "not by the release key" in msg and TEST_FP in msg


def test_the_shipped_key_does_not_accept_the_test_fixture():
    with pytest.raises(rr.RecordRefused) as e:
        rr.read_record(FIX_CHAIN, (URL,), rr.pinned_keys(), get=Served(FIXTURE))
    assert e.value.code == "wrong_key"


def test_shipped_key_is_the_release_key_and_the_test_key_is_never_pinned():
    k = rr.pinned_keys()
    assert [x.fingerprint for x in k] == ["C5EB4728F660369CE519D834B48FB4B71EFD48AE"] == [rr.RELEASE_KEY_FINGERPRINT]
    src = pathlib.Path(rr.__file__).parent
    for f in src.rglob("*.py"):
        t = f.read_text()
        assert TEST_FP not in t and TEST_FP[-16:] not in t, f


# ── the record's rules ────────────────────────────────────────────────────────────────────────────────────────────
def signed(data: bytes, signer=SIGNER, **kw):
    return Served({URL: data, URL + ".asc": signer.sign(data, **kw).encode()})


def test_a_record_signed_by_a_pinned_key_is_read():
    v = read(signed(record()), chain=101101, keys=[SIGNER.public_armour()])
    assert v.entry.genesis_sha256 == NEW_GENESIS and v.entry.bridge.vault == VAULT and v.entry.bridge.usdc == USDC


def test_sha256_signatures_are_accepted_too():
    assert read(signed(record(), hash_algo=8), chain=101101, keys=[SIGNER.public_armour()])


def test_sequence_lower_than_one_seen_is_refused():
    keys = [SIGNER.public_armour()]
    read(signed(record(seq=5)), chain=101101, keys=keys)
    read(signed(record(seq=5)), chain=101101, keys=keys)                 # the same record again is fine
    msg = refused("rollback", signed(record(seq=4)), chain=101101, keys=keys)
    assert "sequence 4" in msg and "sequence 5" in msg
    read(signed(record(seq=6)), chain=101101, keys=keys)
    refused("rollback", signed(record(seq=5)), chain=101101, keys=keys)


def test_highest_sequence_is_kept_on_disk_0600_next_to_the_nonce_marks(tmp_path, monkeypatch):
    from vordium import nonces
    keys = [SIGNER.public_armour()]
    read(signed(record(seq=9)), chain=101101, keys=keys)
    files = list(nonces.state_dir().glob("release-record.*"))
    stored = [f for f in files if not f.name.endswith(".lock")]
    assert len(stored) == 1 and stored[0].read_text().strip() == "9"
    assert stored[0].stat().st_mode & 0o777 == 0o600
    rr._MEMORY.clear()                                                    # a new process: only the file remembers
    refused("rollback", signed(record(seq=8)), chain=101101, keys=keys)


def test_expired_record_is_refused(monkeypatch):
    monkeypatch.setattr(rr, "_now", lambda: 1797465601)                   # one second after valid_until
    msg = refused("expired", Served({URL: vec("releases.json"), URL + ".asc": vec("releases.json.asc")}))
    assert "expired" in msg


def test_record_that_does_not_list_the_network_is_refused():
    msg = refused("not_listed", Served({URL: vec("releases.json"), URL + ".asc": vec("releases.json.asc")}),
                  chain=101101)
    assert "does not list chain 101101" in msg


def test_unsigned_record_is_refused():
    msg = refused("unsigned", Served({URL: record()}), chain=101101, keys=[SIGNER.public_armour()])
    assert "not signed" in msg
    # an address that answers the signature with a web page is no signature either
    refused("unsigned", Served({URL: record(), URL + ".asc": b"<!doctype html><html></html>"}), chain=101101,
            keys=[SIGNER.public_armour()])


def test_json_value_changed_after_signing_is_refused():
    data = record()
    sig = SIGNER.sign(data).encode()
    changed = data.replace(NEW_GENESIS.encode(), FIX_GENESIS.encode())
    refused("bad_signature", Served({URL: changed, URL + ".asc": sig}), chain=101101, keys=[SIGNER.public_armour()])


def test_values_come_from_the_verified_bytes_read_once():
    s = signed(record())
    v = read(s, chain=101101, keys=[SIGNER.public_armour()])
    assert s.reads == [URL, URL + ".asc"] and v.entry.genesis_sha256 == NEW_GENESIS


def test_duplicate_keys_unknown_schema_and_malformed_values_are_refused():
    keys = [SIGNER.public_armour()]
    dup = record().replace(b'"sequence": 1,', b'"sequence": 1,\n "sequence": 7,')
    assert dup != record()
    refused("malformed", signed(dup), chain=101101, keys=keys)
    refused("schema", signed(record(schema="vordium.release-record/4")), chain=101101, keys=keys)
    refused("malformed", signed(record(until="tomorrow")), chain=101101, keys=keys)
    refused("malformed", signed(record(genesis="AB" * 32)), chain=101101, keys=keys)
    refused("malformed", signed(record(vault="0x1234")), chain=101101, keys=keys)
    refused("malformed", signed(record(past=(NEW_GENESIS,))), chain=101101, keys=keys)


def test_corrupted_armour_crc_is_refused():
    sig = vec("releases.json.asc").decode()
    crc_line = next(x for x in sig.splitlines() if x.startswith("="))
    bad = sig.replace(crc_line, "=" + base64.b64encode(b"\x00\x00\x00").decode())
    msg = refused("bad_armour", Served({URL: vec("releases.json"), URL + ".asc": bad.encode()}))
    assert "CRC-24" in msg


def _resign_packet(edit):
    """The fixture's signature packet with ``edit`` applied to its body, armoured again with a correct CRC."""
    raw = rr.dearmor(vec("releases.json.asc"), "PGP SIGNATURE")
    (tag, body), = rr._packets(raw)
    return armour(packet(tag, edit(bytearray(body))), "PGP SIGNATURE").encode()


def test_version_3_signature_is_refused():
    def v3(b):
        b[0] = 3
        return bytes(b)
    msg = refused("unsupported", Served({URL: vec("releases.json"), URL + ".asc": _resign_packet(v3)}))
    assert "version 3" in msg


def test_non_ed25519_algorithm_is_refused():
    def rsa(b):
        b[2] = 1
        return bytes(b)
    msg = refused("unsupported", Served({URL: vec("releases.json"), URL + ".asc": _resign_packet(rsa)}))
    assert "Ed25519" in msg

    def sha1(b):
        b[3] = 2
        return bytes(b)
    refused("unsupported", Served({URL: vec("releases.json"), URL + ".asc": _resign_packet(sha1)}))


def test_text_mode_and_unknown_critical_subpackets_are_refused():
    keys = [SIGNER.public_armour()]
    refused("unsupported", signed(record(), sig_type=1), chain=101101, keys=keys)
    refused("unsupported", signed(record(), extra_hashed=bytes([2, 0x80 | 99, 0])), chain=101101, keys=keys)
    # a non-critical subpacket that is not read is skipped
    assert read(signed(record(), extra_hashed=bytes([2, 99, 0])), chain=101101, keys=keys)


def test_signature_without_issuer_fingerprint_is_refused():
    refused("wrong_key", signed(record(), issuer=False), chain=101101, keys=[SIGNER.public_armour()])


def test_correct_quick_check_but_wrong_signature_is_refused():
    def flip(b):
        b[-1] ^= 0x01                                                     # the last byte of S
        return bytes(b)
    refused("bad_signature", Served({URL: vec("releases.json"), URL + ".asc": _resign_packet(flip)}))


def test_signature_by_another_key_claiming_the_pinned_fingerprint_is_refused():
    data = record()
    forged = OTHER.sign(data)
    raw = rr.dearmor(forged, "PGP SIGNATURE")
    (tag, body), = rr._packets(raw)
    body = body.replace(bytes.fromhex(OTHER.fingerprint), bytes.fromhex(SIGNER.fingerprint))
    refused("bad_signature", Served({URL: data, URL + ".asc": armour(packet(tag, body), "PGP SIGNATURE").encode()}),
            chain=101101, keys=[SIGNER.public_armour()])


def test_two_signature_packets_or_armour_garbage_are_refused():
    keys = [SIGNER.public_armour()]
    data = record()
    one = rr.dearmor(SIGNER.sign(data), "PGP SIGNATURE")
    refused("bad_packet", Served({URL: data, URL + ".asc": armour(one + one, "PGP SIGNATURE").encode()}),
            chain=101101, keys=keys)
    good = SIGNER.sign(data)
    refused("bad_armour", Served({URL: data, URL + ".asc": (good + good).encode()}), chain=101101, keys=keys)
    refused("bad_armour", Served({URL: data, URL + ".asc": good.replace("\n\n", "\n!!!!\n", 1).encode()}),
            chain=101101, keys=keys)


def test_armour_without_crc_line_is_read():
    data = record()
    raw = rr.dearmor(SIGNER.sign(data), "PGP SIGNATURE")
    assert read(Served({URL: data, URL + ".asc": armour(raw, "PGP SIGNATURE", crc=False).encode()}), chain=101101,
                keys=[SIGNER.public_armour()])


# ── no record served ──────────────────────────────────────────────────────────────────────────────────────────────
def test_nothing_served_means_no_record():
    assert read(Served({})) is None


def test_a_signed_release_list_of_the_earlier_format_is_no_record():
    old = json.dumps({"schema": 1, "chain_id": 101101, "releases": []}).encode()
    assert read(signed(old), chain=101101, keys=[SIGNER.public_armour()]) is None
    assert read(Served({URL: old}), chain=101101, keys=[SIGNER.public_armour()]) is None


def test_no_record_after_one_was_seen_is_refused():
    keys = [SIGNER.public_armour()]
    read(signed(record(seq=3)), chain=101101, keys=keys)
    msg = refused("not_served", Served({}), chain=101101, keys=keys)
    assert "sequence 3" in msg


def test_a_bad_first_address_does_not_hide_a_good_second_one():
    second = "https://mirror.invalid/releases.json"
    data = record()
    s = Served({URL: data, URL + ".asc": OTHER.sign(data).encode(), second: data, second + ".asc": SIGNER.sign(data).encode()})
    assert read(s, chain=101101, keys=[SIGNER.public_armour()], urls=(URL, second)).url == second
    s = Served({URL: data, URL + ".asc": OTHER.sign(data).encode()})
    refused("wrong_key", s, chain=101101, keys=[SIGNER.public_armour()], urls=(URL, second))


# ── Ed25519 (RFC 8032, section 7.1) ───────────────────────────────────────────────────────────────────────────────
RFC8032 = [
    ("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", "",
     "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"),
    ("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c", "72",
     "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"),
    ("fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025", "af82",
     "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"),
]


@pytest.mark.parametrize("pub,msg,sig", RFC8032)
def test_rfc8032_vectors(pub, msg, sig):
    p, m, s = bytes.fromhex(pub), bytes.fromhex(msg), bytes.fromhex(sig)
    assert rr.ed25519_verify(p, m, s)
    assert not rr.ed25519_verify(p, m + b"x", s)
    assert not rr.ed25519_verify(p, m, s[:63] + bytes([s[63] ^ 1]))
    bad_s = s[:32] + (int.from_bytes(s[32:], "little") + rr._L).to_bytes(32, "little")
    assert not rr.ed25519_verify(p, m, bad_s)                             # S must be below the group order


# ── wired into the network identity ───────────────────────────────────────────────────────────────────────────────
class FakeNode:
    def __init__(self, monkeypatch, chain, genesis, served):
        monkeypatch.setattr(net, "_read_record", _REAL_READ)
        monkeypatch.setattr(rr, "fetch", served)
        monkeypatch.setattr(net, "_fetch_spec", lambda u, t: {"chainId": chain, "genesisSha256": genesis})
        monkeypatch.setattr(net, "_eth_chain_id", lambda r, t: chain)
        monkeypatch.setattr(net, "_status_genesis_sha256", lambda r, t: genesis)
        for k in ("VORDIUM_CHAIN_ID", "VORDIUM_RPC_URL", "VORDIUM_SPEC_URL", "VORDIUM_NETWORK", "VORDIUM_GENESIS_SHA256"):
            monkeypatch.delenv(k, raising=False)
        net.reset_network()


def resolve(**kw):
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", net.PinWarning)
        return net.resolve_network(**kw)


def sign_for(n):
    net.set_network(n)
    try:
        return eip712.domain()
    finally:
        net.reset_network()


FIXTURE = {URL: vec("releases.json"), URL + ".asc": vec("releases.json.asc")}


def test_fixture_network_named_by_chain_id_signs_under_the_listed_genesis(monkeypatch):
    FakeNode(monkeypatch, FIX_CHAIN, FIX_GENESIS, Served(FIXTURE))
    n = resolve(rpc_url="https://node.invalid", network=FIX_CHAIN, release_keys=[TEST_KEY], release_record_url=URL)
    assert n.pin_problem is None and n.record is not None
    assert net.signing_pin(n).genesis_sha256 == FIX_GENESIS
    assert sign_for(n)["salt"] == domains.salt("VordCore", FIX_GENESIS)
    assert n.bridge_address == "0x" + "00" * 20 and n.bridge_chain_id == 42161


@pytest.mark.parametrize("files,code_words", [
    ({URL: vec("negative/tampered-releases.json"), URL + ".asc": vec("negative/tampered-releases.json.asc")},
     "does not verify"),
    ({URL: vec("negative/wrong-key-releases.json"), URL + ".asc": vec("negative/wrong-key-releases.json.asc")},
     "not by the release key"),
    ({URL: vec("releases.json")}, "not signed"),
    ({}, "no signed release record lists chain 101199"),
])
def test_fixture_network_is_not_signed_for_without_a_good_record(monkeypatch, files, code_words):
    FakeNode(monkeypatch, FIX_CHAIN, FIX_GENESIS, Served(files))
    n = resolve(rpc_url="https://node.invalid", network=FIX_CHAIN, release_keys=[TEST_KEY], release_record_url=URL)
    assert n.pin_problem and code_words in n.pin_problem
    with pytest.raises(net.NetworkMismatch):
        net.signing_pin(n)
    with pytest.raises(net.BridgeRefused):
        net.set_network(n)
        try:
            net.current_bridge()
        finally:
            net.reset_network()


def test_retired_genesis_is_refused(monkeypatch):
    FakeNode(monkeypatch, FIX_CHAIN, FIX_RETIRED, Served(FIXTURE))
    n = resolve(rpc_url="https://node.invalid", network=FIX_CHAIN, release_keys=[TEST_KEY], release_record_url=URL)
    assert "in retired_genesis" in n.pin_problem
    with pytest.raises(net.PinMismatch):
        net.signing_pin(n)


def test_genesis_not_listed_is_refused(monkeypatch):
    other = hashlib.sha256(b"not listed").hexdigest()
    FakeNode(monkeypatch, FIX_CHAIN, other, Served(FIXTURE))
    n = resolve(rpc_url="https://node.invalid", network=FIX_CHAIN, release_keys=[TEST_KEY], release_record_url=URL)
    assert n.pin_problem and FIX_GENESIS in n.pin_problem
    with pytest.raises(net.PinMismatch):
        net.signing_pin(n)


def test_new_main_network_genesis_works_from_a_signed_record(monkeypatch):
    FakeNode(monkeypatch, 101101, NEW_GENESIS, signed(record()))
    n = resolve(network="mainnet", release_keys=[SIGNER.public_armour()], release_record_url=URL)
    assert n.pin_problem is None and net.signing_pin(n).genesis_sha256 == NEW_GENESIS
    assert sign_for(n)["salt"] == domains.salt("VordCore", NEW_GENESIS)


def test_without_a_record_the_shipped_pin_still_applies(monkeypatch):
    FakeNode(monkeypatch, 101101, NEW_GENESIS, Served({}))
    n = resolve(network="mainnet", release_keys=[SIGNER.public_armour()], release_record_url=URL)
    with pytest.raises(net.PinMismatch):
        net.signing_pin(n)
    FakeNode(monkeypatch, 101101, FIX_RETIRED, Served({}))                 # today's main-network genesis
    n = resolve(network="mainnet", release_keys=[SIGNER.public_armour()], release_record_url=URL)
    assert net.signing_pin(n).genesis_sha256 == FIX_RETIRED


def test_a_record_overrides_the_shipped_pin_and_can_retire_it(monkeypatch):
    FakeNode(monkeypatch, 101101, FIX_RETIRED, signed(record()))
    n = resolve(network="mainnet", release_keys=[SIGNER.public_armour()], release_record_url=URL)
    assert "in retired_genesis" in n.pin_problem


def test_unnamed_endpoint_is_still_not_signed_for(monkeypatch):
    FakeNode(monkeypatch, 101101, NEW_GENESIS, signed(record()))
    n = resolve(rpc_url="https://node.invalid", release_keys=[SIGNER.public_armour()], release_record_url=URL)
    with pytest.raises(net.UnpinnedNetwork):
        net.signing_pin(n)


def test_record_names_the_bridge_and_the_spec_does_not(monkeypatch):
    FakeNode(monkeypatch, 101101, NEW_GENESIS, signed(record()))
    monkeypatch.setattr(net, "_fetch_spec", lambda u, t: {"chainId": 101101, "genesisSha256": NEW_GENESIS,
                                                         "bridge": {"address": "0x" + "66" * 20, "chainId": 42161,
                                                                    "handler": "0x" + "77" * 20}})
    n = resolve(network="mainnet", release_keys=[SIGNER.public_armour()], release_record_url=URL)
    assert n.bridge_address == VAULT
    net.set_network(n)
    try:
        assert net.current_bridge() == VAULT
        assert net.current_bridge(spec_url="https://hostile.invalid/spec.json") == VAULT
        assert net.require_current_bridge(VAULT) == VAULT
        with pytest.raises(net.BridgeRefused):
            net.require_current_bridge("0x" + "66" * 20)
        d = bridge_v4.fetch_deployments(spec_url="https://hostile.invalid/spec.json")
        assert d == {"42161": {"vault": VAULT, "handler": HANDLER, "usdc": USDC,
                               "setRules": bridge_v4.create_address(VAULT, 2)}}
        with pytest.raises(net.BridgeRefused):
            bridge_v4.fetch_deployments(expected_bridge="0x" + "66" * 20)
    finally:
        net.reset_network()


def test_record_bridge_with_a_handler_the_vault_did_not_create_is_not_used():
    assert bridge_v4.deployments_from_record(rr.Bridge(42161, VAULT, "0x" + "77" * 20, USDC)) is None


def test_deployment_check_holds_the_vaults_usdc_to_the_record():
    v = bridge_v4.VaultsRead(ok=True, vaults=(bridge_v4.Vault(1, "42161", VAULT, HANDLER, 3, None, None, (), 0,
                                                              binding_usdc="0x" + "99" * 20),))
    d = bridge_v4.deployments_from_record(rr.Bridge(42161, VAULT, HANDLER, USDC))
    assert not bridge_v4.deployment_check(v, d).ok
    v_ok = dataclasses.replace(v, vaults=(dataclasses.replace(v.vaults[0], binding_usdc=USDC),))
    assert bridge_v4.deployment_check(v_ok, d).ok


def test_named_clients_take_the_record_genesis(monkeypatch):
    from vordium import node_domain
    monkeypatch.setattr(net, "_read_record", lambda cid, urls, keys, t: rr.read_record(
        cid, (URL,), rr.pinned_keys([SIGNER.public_armour()]), t, get=signed(record())))
    net._NAMED.clear()
    pin, _ = node_domain.configured_pin("mainnet")
    assert pin.genesis_sha256 == NEW_GENESIS
    monkeypatch.setattr(net, "_read_record", lambda cid, urls, keys, t: (_ for _ in ()).throw(
        rr.RecordRefused("bad_signature", "The record's signature does not verify.")))
    net._NAMED.clear()
    with pytest.raises(net.PinMismatch):
        node_domain.configured_pin("mainnet")


# ── the record as it is at the moment of use ──────────────────────────────────────────────────────────────────────
def test_an_expired_record_stops_signing_and_the_bridge_at_use(monkeypatch):
    s = signed(record())
    FakeNode(monkeypatch, 101101, NEW_GENESIS, s)
    n = resolve(network="mainnet", release_keys=[SIGNER.public_armour()], release_record_url=URL)
    assert net.signing_pin(n).genesis_sha256 == NEW_GENESIS
    monkeypatch.setattr(rr, "_now", lambda: 1797465601)                   # past valid_until
    with pytest.raises(net.PinMismatch) as e:
        net.signing_pin(n)
    assert "expired" in str(e.value)
    net.set_network(n)
    try:
        with pytest.raises(net.BridgeRefused):
            net.current_bridge()
    finally:
        net.reset_network()


def test_a_newer_record_is_read_again_after_its_time(monkeypatch):
    s = signed(record(seq=1))
    FakeNode(monkeypatch, 101101, NEW_GENESIS, s)
    n = resolve(network="mainnet", release_keys=[SIGNER.public_armour()], release_record_url=URL)
    assert net.signing_pin(n).genesis_sha256 == NEW_GENESIS
    newer = record(seq=2, genesis=FIX_GENESIS, past=(NEW_GENESIS,))       # lists the node's genesis in retired_genesis
    s.files.update({URL: newer, URL + ".asc": SIGNER.sign(newer).encode()})
    assert net.signing_pin(n).genesis_sha256 == NEW_GENESIS               # within RECORD_TTL_S: as read
    monkeypatch.setattr(net, "RECORD_TTL_S", 0.0)
    with pytest.raises(net.PinMismatch) as e:
        net.signing_pin(n)
    assert "retired_genesis" in str(e.value)


def test_a_refused_record_is_read_again_and_signing_resumes(monkeypatch):
    s = Served({URL: record()})                                           # unsigned at first
    FakeNode(monkeypatch, 101101, NEW_GENESIS, s)
    n = resolve(network="mainnet", release_keys=[SIGNER.public_armour()], release_record_url=URL)
    with pytest.raises(net.PinMismatch):
        net.signing_pin(n)
    s.files[URL + ".asc"] = SIGNER.sign(record()).encode()
    with pytest.raises(net.PinMismatch):                                  # not before RECORD_RETRY_S
        net.signing_pin(n)
    monkeypatch.setattr(net, "RECORD_RETRY_S", 0.0)
    assert net.signing_pin(n).genesis_sha256 == NEW_GENESIS


def test_a_network_named_by_chain_id_reads_every_record_address(monkeypatch):
    seen = []
    monkeypatch.setattr(net, "_read_record", lambda cid, urls, keys, t: seen.append((cid, urls)))
    monkeypatch.setattr(net, "_fetch_spec", lambda u, t: {"chainId": 424242})
    monkeypatch.setattr(net, "_eth_chain_id", lambda r, t: 424242)
    monkeypatch.setattr(net, "_status_genesis_sha256", lambda r, t: NEW_GENESIS)
    resolve(rpc_url="https://node.invalid", network=424242)
    assert seen == [(424242, tuple(u for v in rr.RECORD_URLS.values() for u in v))]


# ── hostile input is refused, never a crash ───────────────────────────────────────────────────────────────────────
def test_deeply_nested_unsigned_bytes_are_not_a_crash():
    deep = b"[" * 200000
    assert rr.is_network_record(deep) is False
    assert read(Served({URL: deep})) is None
    with pytest.raises(rr.RecordRefused):
        rr.parse_record(deep)


def test_strict_text_profile():
    keys = [SIGNER.public_armour()]
    data = record()
    sig = SIGNER.sign(data)
    refused("bad_armour", Served({URL: data, URL + ".asc": sig.replace("\n", "\r\r\n").encode()}), chain=101101, keys=keys)
    assert read(Served({URL: data, URL + ".asc": sig.replace("\n", "\r\n").encode()}), chain=101101, keys=keys)
    refused("malformed", signed(record(until="2026-12-1٢7T00:00:00Z")), chain=101101, keys=keys)
    refused("malformed", signed(record(seq=2 ** 53)), chain=101101, keys=keys)
    refused("malformed", signed(record().replace(b'"sequence": 1,', b'"sequence": 1.0,')), chain=101101, keys=keys)
    refused("malformed", signed(b"\xef\xbb\xbf" + record()), chain=101101, keys=keys)


def test_a_record_read_after_resolution_is_held_to_every_source(monkeypatch):
    s = Served({URL: record()})                                           # unsigned at resolution
    FakeNode(monkeypatch, 101101, NEW_GENESIS, s)
    monkeypatch.setenv("VORDIUM_GENESIS_SHA256", FIX_GENESIS)             # disagrees with the record named later
    n = resolve(network="mainnet", release_keys=[SIGNER.public_armour()], release_record_url=URL)
    s.files[URL + ".asc"] = SIGNER.sign(record()).encode()
    monkeypatch.setattr(net, "RECORD_RETRY_S", 0.0)
    with pytest.raises(net.PinMismatch) as e:
        net.signing_pin(n)
    assert "VORDIUM_GENESIS_SHA256" in str(e.value)


# ── downloads stop at the limit; the release key's own expiry ─────────────────────────────────────────────────────
class _Endless:
    """A 200 answer whose body never ends; counts the chunks read."""
    status_code = 200
    chunks = 0
    closed = False

    def iter_content(self, n):
        while True:
            _Endless.chunks += 1
            yield b"x" * n

    def close(self):
        _Endless.closed = True


def test_a_download_stops_at_the_limit(monkeypatch):
    from vordium import _http
    seen = {}
    monkeypatch.setattr(_http, "get", lambda url, timeout, stream=False: (seen.update(stream=stream), _Endless())[1])
    with pytest.raises(rr.RecordRefused) as e:
        rr.fetch(URL, 1.0, 200_000)
    assert e.value.code == "too_large" and seen["stream"] is True
    assert _Endless.chunks <= 200_000 // 65536 + 2 and _Endless.closed


def key_block(signer: "Signer", key_expires=None, sig_created=1794900000) -> str:
    """``signer``'s key with a user ID and a self-signature (positive certification) naming ``key_expires`` seconds."""
    uid = b"test <test@invalid>"
    sub = bytes([22, 33, 4]) + bytes.fromhex(signer.fingerprint) + bytes([5, 2]) + sig_created.to_bytes(4, "big")
    if key_expires is not None:
        sub += bytes([5, 9]) + key_expires.to_bytes(4, "big")
    head = bytes([4, 0x13, 22, 10]) + len(sub).to_bytes(2, "big") + sub
    prefix = b"\x99" + len(signer.key_body).to_bytes(2, "big") + signer.key_body + b"\xb4" + len(uid).to_bytes(4, "big") + uid
    digest = hashlib.sha512(prefix + head + b"\x04\xff" + len(head).to_bytes(4, "big")).digest()
    sig = signer.raw_sign(digest)
    body = head + b"\x00\x00" + digest[:2] + mpi(sig[:32]) + mpi(sig[32:])
    return armour(packet(6, signer.key_body) + packet(13, uid) + packet(2, body), "PGP PUBLIC KEY BLOCK")


def test_the_release_keys_own_expiry_is_read_from_its_self_signature():
    assert rr.pinned_keys()[0].expires == 1852321286                      # 2028-09-11, from the shipped key
    assert rr.parse_public_key(TEST_KEY).expires == 1794956454 + 2592000
    assert rr.parse_public_key(key_block(SIGNER)).expires is None


def test_a_record_signed_by_an_expired_key_is_refused():
    expired = key_block(SIGNER, key_expires=3600)                         # one hour after the key was made, long past
    msg = refused("key_expired", signed(record()), chain=101101, keys=[expired])
    assert "expired" in msg
    assert read(signed(record()), chain=101101, keys=[key_block(SIGNER, key_expires=10 ** 8)])


def test_a_key_without_a_valid_self_signature_is_refused():
    with pytest.raises(rr.RecordRefused) as e:
        rr.parse_public_key(armour(packet(6, SIGNER.key_body), "PGP PUBLIC KEY BLOCK"))   # no self-signature
    assert e.value.code == "bad_key"
    raw = rr.dearmor(key_block(SIGNER, key_expires=10 ** 8), "PGP PUBLIC KEY BLOCK")
    tampered = armour(raw[:-1] + bytes([raw[-1] ^ 1]), "PGP PUBLIC KEY BLOCK")
    with pytest.raises(rr.RecordRefused):
        rr.parse_public_key(tampered)


def test_a_state_folder_that_cannot_be_written_keeps_the_sequence_in_this_process(monkeypatch):
    from vordium import nonces

    def no_lock(path):
        raise PermissionError(13, "Permission denied", str(path))
    monkeypatch.setattr(nonces, "_file_lock", no_lock)
    keys = [SIGNER.public_armour()]
    with pytest.warns(rr.RecordStateWarning):
        assert read(signed(record(seq=3)), chain=101101, keys=keys)
    refused("rollback", signed(record(seq=2)), chain=101101, keys=keys)       # held in this process
    with pytest.warns(rr.RecordStateWarning):
        assert read(Served({}), chain=101101, keys=[TEST_KEY]) is None


def test_a_stored_sequence_that_cannot_be_read_refuses():
    from vordium import nonces
    keys = [SIGNER.public_armour()]
    read(signed(record(seq=4)), chain=101101, keys=keys)
    mark = next(f for f in nonces.state_dir().glob("release-record.*") if not f.name.endswith(".lock"))
    mark.unlink()
    mark.mkdir()                                                          # there, but not a readable file
    rr._MEMORY.clear()
    refused("state", signed(record(seq=1)), chain=101101, keys=keys)
    mark.rmdir()
    mark.write_bytes(b"\xff\xfe")
    refused("state", signed(record(seq=1)), chain=101101, keys=keys)


def _stored_then_no_lock(monkeypatch, seq):
    """A sequence ``seq`` stored on disk, a new process (memory cleared), and a lock that cannot be taken."""
    from vordium import nonces
    read(signed(record(seq=seq)), chain=101101, keys=[SIGNER.public_armour()])
    rr._MEMORY.clear()

    def no_lock(path):
        raise PermissionError(13, "Permission denied", str(path))
    monkeypatch.setattr(nonces, "_file_lock", no_lock)


def test_without_the_lock_a_lower_sequence_than_the_stored_one_is_refused(monkeypatch):
    _stored_then_no_lock(monkeypatch, 5)
    with pytest.warns(rr.RecordStateWarning):
        refused("rollback", signed(record(seq=2)), chain=101101, keys=[SIGNER.public_armour()])


def test_without_the_lock_a_stored_sequence_still_means_seen(monkeypatch):
    _stored_then_no_lock(monkeypatch, 5)
    with pytest.warns(rr.RecordStateWarning):
        assert "sequence 5" in refused("not_served", Served({}), chain=101101, keys=[SIGNER.public_armour()])


def test_a_failed_write_leaves_no_temporary_file(monkeypatch, tmp_path):
    path = tmp_path / "release-record.x.1"

    def broken(*a):
        raise OSError(28, "No space left on device")
    monkeypatch.setattr(rr.os, "replace", broken)
    with pytest.raises(OSError):
        rr._write_seq(path, 7)
    assert list(tmp_path.iterdir()) == []


# ── the release key's expiry, refreshed from where the key is served ─────────────────────────────────────────────────
def _key_sig(signer: "Signer", sig_type: int, prefix: bytes, created: int, key_expires=None) -> bytes:
    sub = bytes([22, 33, 4]) + bytes.fromhex(signer.fingerprint) + bytes([5, 2]) + created.to_bytes(4, "big")
    if key_expires is not None:
        sub += bytes([5, 9]) + key_expires.to_bytes(4, "big")
    head = bytes([4, sig_type, 22, 10]) + len(sub).to_bytes(2, "big") + sub
    digest = hashlib.sha512(prefix + head + b"\x04\xff" + len(head).to_bytes(4, "big")).digest()
    sig = signer.raw_sign(digest)
    return packet(2, head + b"\x00\x00" + digest[:2] + mpi(sig[:32]) + mpi(sig[32:]))


def served_key(signer: "Signer", key_expires=None, sig_created=1794900000, revoke=False, by=None) -> str:
    """``signer``'s key with one self-signature made at ``sig_created``; ``revoke`` adds a key revocation made by ``by``."""
    uid = b"test <test@invalid>"
    kp = b"\x99" + len(signer.key_body).to_bytes(2, "big") + signer.key_body
    raw = packet(6, signer.key_body)
    if revoke:
        raw += _key_sig(by or signer, 0x20, kp, sig_created)
    raw += packet(13, uid) + _key_sig(signer, 0x13, kp + b"\xb4" + len(uid).to_bytes(4, "big") + uid, sig_created,
                                      key_expires)
    return armour(raw, "PGP PUBLIC KEY BLOCK")


def _pk(armoured: str):
    return rr.parse_public_key(armoured)


def test_a_newer_served_copy_of_the_same_key_gives_its_later_expiry():
    old = _pk(served_key(SIGNER, key_expires=10 ** 6, sig_created=1794900000))
    newer = served_key(SIGNER, key_expires=10 ** 8, sig_created=1794990000)
    got = rr.refresh_key(old, urls=(URL,), get=Served({URL: newer.encode()}))
    assert got.expires == old.expires - 10 ** 6 + 10 ** 8 and got.signed_at == 1794990000


def test_an_older_or_equal_served_copy_never_replaces_the_key():
    cur = _pk(served_key(SIGNER, key_expires=10 ** 8, sig_created=1794990000))
    older = served_key(SIGNER, key_expires=10 ** 9, sig_created=1794900000)
    assert rr.refresh_key(cur, urls=(URL,), get=Served({URL: older.encode()})) == cur
    same_time = served_key(SIGNER, key_expires=10 ** 9, sig_created=1794990000)
    assert rr.refresh_key(cur, urls=(URL,), get=Served({URL: same_time.encode()})) == cur


def test_a_served_copy_of_another_key_is_never_used():
    cur = _pk(served_key(SIGNER, key_expires=10 ** 6))
    other = served_key(OTHER, key_expires=10 ** 9, sig_created=1794999999)
    assert rr.refresh_key(cur, urls=(URL,), get=Served({URL: other.encode()})) == cur


def test_a_served_copy_whose_self_signature_does_not_verify_is_skipped():
    cur = _pk(served_key(SIGNER, key_expires=10 ** 6))
    raw = rr.dearmor(served_key(SIGNER, key_expires=10 ** 9, sig_created=1794999999), "PGP PUBLIC KEY BLOCK")
    tampered = armour(raw[:-1] + bytes([raw[-1] ^ 1]), "PGP PUBLIC KEY BLOCK")
    for bad in (tampered.encode(), b"not a key", b"\xff\xfe", None):
        assert rr.refresh_key(cur, urls=(URL,), get=Served({URL: bad} if bad is not None else {})) == cur


def test_the_first_usable_newest_copy_wins_across_addresses():
    cur = _pk(served_key(SIGNER, key_expires=10 ** 6))
    a, b = URL + ".a", URL + ".b"
    files = {a: served_key(SIGNER, key_expires=10 ** 7, sig_created=1794950000).encode(),
             b: served_key(SIGNER, key_expires=10 ** 8, sig_created=1794990000).encode()}
    assert rr.refresh_key(cur, urls=(a, b), get=Served(files)).signed_at == 1794990000


def test_a_revocation_by_the_key_refuses_every_record():
    cur = _pk(served_key(SIGNER, key_expires=10 ** 8))
    revoked = rr.refresh_key(cur, urls=(URL,), get=Served({URL: served_key(SIGNER, 10 ** 8, revoke=True).encode()}))
    assert revoked.revoked
    msg = refused("key_revoked", signed(record()), chain=101101, keys=[revoked])
    assert "revoked" in msg


def test_a_revocation_made_by_another_key_is_ignored():
    cur = _pk(served_key(SIGNER, key_expires=10 ** 8))
    fake = served_key(SIGNER, 10 ** 8, revoke=True, by=OTHER)
    assert not _pk(fake).revoked
    assert not rr.refresh_key(cur, urls=(URL,), get=Served({URL: fake.encode()})).revoked


def _shipped_read(monkeypatch, at, served_keys):
    """read_record with the shipped key at time ``at``, the key URLs serving ``served_keys`` (url -> bytes or None)."""
    calls = []

    def fetch(url, timeout, limit):
        calls.append(url)
        return served_keys.get(url)
    monkeypatch.setattr(rr, "fetch", lambda *a: (_ for _ in ()).throw(AssertionError("the caller's reader is used")))
    monkeypatch.setattr(rr, "_now", lambda: at[0])
    rec = signed(record())                                                 # signed by the test key, not the release key

    def get(url, timeout, limit):
        return fetch(url, timeout, limit) if url in rr.KEY_URLS else rec(url, timeout, limit)
    try:
        rr.read_record(101101, (URL,), rr.pinned_keys(), get=get)
    except rr.RecordRefused as e:
        return calls, e.code
    return calls, None


def test_the_shipped_key_is_read_again_only_near_its_expiry_on_every_record_read(monkeypatch):
    shipped = rr.parse_public_key(rr.RELEASE_KEY)
    monkeypatch.setattr(rr, "_refreshed", {})
    keys = {u: rr.RELEASE_KEY.encode() for u in rr.KEY_URLS}
    at = [shipped.expires - rr.KEY_REFRESH_BEFORE_S - 1]
    calls, _ = _shipped_read(monkeypatch, at, keys)
    assert calls == []
    at[0] = shipped.expires - 60                                           # a long-lived process crosses into the window
    calls, code = _shipped_read(monkeypatch, at, keys)
    assert calls == list(rr.KEY_URLS) and code == "wrong_key"
    at[0] += 10
    assert _shipped_read(monkeypatch, at, keys)[0] == []                   # within the refresh time: no second read
    at[0] = shipped.expires - 60 + rr.KEY_REFRESH_TTL_S
    assert _shipped_read(monkeypatch, at, keys)[0] == list(rr.KEY_URLS)


def test_a_failed_read_never_takes_back_a_good_one_and_retries_soon_while_expired(monkeypatch):
    shipped = rr.parse_public_key(rr.RELEASE_KEY)
    later = rr.PublicKey(shipped.fingerprint, shipped.point, shipped.expires + 10 ** 8, shipped.signed_at + 1)
    monkeypatch.setattr(rr, "refresh_key", lambda key, **kw: later if key.signed_at <= shipped.signed_at else key)
    monkeypatch.setattr(rr, "_refreshed", {})
    t = [shipped.expires + 100]
    monkeypatch.setattr(rr, "_now", lambda: t[0])
    assert rr.key_now(shipped) == later
    monkeypatch.setattr(rr, "refresh_key", lambda key, **kw: key)          # every read fails from here
    t[0] += rr.KEY_REFRESH_TTL_S + 1
    assert rr.key_now(shipped) == later                                   # the later expiry is kept
    monkeypatch.setattr(rr, "_refreshed", {})
    calls = []
    monkeypatch.setattr(rr, "refresh_key", lambda key, **kw: (calls.append(1), key)[1])
    assert rr.key_now(shipped) == shipped and len(calls) == 1             # expired, nothing served
    t[0] += rr.KEY_RETRY_S - 1
    rr.key_now(shipped)
    assert len(calls) == 1
    t[0] += 2
    rr.key_now(shipped)
    assert len(calls) == 2                                                 # tried again after KEY_RETRY_S, not 6 h


def test_another_key_is_never_read_again(monkeypatch):
    monkeypatch.setattr(rr, "refresh_key", lambda *a, **k: (_ for _ in ()).throw(AssertionError("read")))
    monkeypatch.setattr(rr, "_now", lambda: 10 ** 10)
    k = _pk(served_key(SIGNER, key_expires=10))
    assert rr.key_now(k) is k


def test_an_expired_key_with_nothing_served_refuses_with_a_plain_sentence():
    msg = refused("key_expired", signed(record()), chain=101101, keys=[key_block(SIGNER, key_expires=3600)])
    assert "no served copy of it gives a later expiry" in msg


def test_a_cached_revocation_is_never_overwritten_by_a_failed_read(monkeypatch):
    shipped = rr.parse_public_key(rr.RELEASE_KEY)
    revoked = rr.PublicKey(shipped.fingerprint, shipped.point, shipped.expires, shipped.signed_at, True)
    monkeypatch.setattr(rr, "_now", lambda: shipped.expires - 60)
    monkeypatch.setattr(rr, "_refreshed", {})

    def racing(key, **kw):                     # another thread caches the revocation while this read fails
        rr._refreshed[key.fingerprint] = (shipped.expires + 10 ** 6, revoked)
        return key
    monkeypatch.setattr(rr, "refresh_key", racing)
    assert rr.key_now(shipped).revoked
    assert rr._refreshed[shipped.fingerprint][1].revoked


# ── the shipped floor, the other SDK's mark, the refusal code ───────────────────────────────────────────────────────
def test_a_floor_shipped_with_the_release_refuses_an_older_record_on_a_fresh_install(monkeypatch):
    keys = [SIGNER.public_armour()]
    assert rr.MIN_SEQUENCE.get(101101) == 0 and rr.MIN_SEQUENCE.get(101102) == 0      # set by the release process
    monkeypatch.setitem(rr.MIN_SEQUENCE, 101101, 10)
    msg = refused("rollback", signed(record(seq=9)), chain=101101, keys=keys)          # an empty state folder
    assert "sequence 9" in msg and "sequence 10" in msg and "lowest this SDK release accepts" in msg
    # a floor above 0 counts as a record seen: while none is served, nothing is signed
    msg = refused("not_served", Served({}), chain=101101, keys=keys)
    assert "needs one with sequence 10 or later" in msg and "read on this computer" not in msg
    assert read(signed(record(seq=10)), chain=101101, keys=keys)
    rr._MEMORY.clear()
    assert "read on this computer" in refused("not_served", Served({}), chain=101101, keys=keys)


def test_the_javascript_sdks_mark_in_the_same_folder_is_held_to(monkeypatch):
    from vordium import nonces
    keys = [SIGNER.public_armour()]
    d = nonces.state_dir()
    d.mkdir(parents=True, exist_ok=True)
    fp = rr.pinned_keys(keys)[0].fingerprint[:16].lower()
    (d / f"release-record-mark.{fp}.101101").write_text("11\n")                     # it read sequence 10
    msg = refused("rollback", signed(record(seq=9)), chain=101101, keys=keys)
    assert "sequence 10" in msg
    assert rr.seen_sequence(rr.pinned_keys(keys)[0].fingerprint, 101101) == 10
    read(signed(record(seq=12)), chain=101101, keys=keys)
    assert (d / f"release-record.{fp}.101101").read_text().strip() == "12"          # each writes its own
    assert (d / f"release-record-mark.{fp}.101101").read_text().strip() == "11"


def test_an_expired_record_says_what_to_do():
    import pytest as _p
    rr._now  # noqa: B018
    with _p.MonkeyPatch.context() as m:
        m.setattr(rr, "_now", lambda: 1797465601)
        msg = refused("expired", Served({URL: vec("releases.json"), URL + ".asc": vec("releases.json.asc")}))
    assert msg.endswith("Try again later; if this persists, check this computer's clock.")


def test_a_record_refusal_carries_its_code_and_is_still_a_pin_mismatch(monkeypatch):
    def fail(chain_id, urls, keys, timeout):
        raise rr.RecordRefused("not_served", "No signed release record for chain 101102 is served now, though one "
                                             "(sequence 3) was read on this computer before. Nothing is signed until "
                                             "it is served again.")
    monkeypatch.setattr(net, "_read_record", fail)
    net._NAMED.clear()
    with pytest.raises(net.PinMismatch) as e:
        net.named_pin("testnet")
    assert isinstance(e.value, net.RecordUnavailable) and e.value.record_code == "not_served"
    assert str(e.value).count("Nothing") == 1                                          # said once
    net._NAMED.clear()


def test_a_genesis_refusal_with_no_record_read_says_the_record_could_not_be_read(monkeypatch):
    from vordium.pins import PINS
    FakeNode(monkeypatch, PINS["testnet"].chain_id, NEW_GENESIS, Served({}))           # a moved node, no record served
    n = resolve(rpc_url="https://node.invalid", network="testnet", release_keys=[SIGNER.public_armour()],
                release_record_url=URL)
    assert n.record is None and "The signed release record could not be read" in n.pin_problem
    with pytest.raises(net.PinMismatch) as e:
        net.signing_pin(n)
    assert "could not be read" in str(e.value) and not isinstance(e.value, net.RecordUnavailable)


def test_a_record_refused_at_resolution_names_its_code(monkeypatch):
    from vordium.pins import PINS
    FakeNode(monkeypatch, PINS["testnet"].chain_id, PINS["testnet"].genesis_sha256,
             Served({URL: record(seq=1, chain=PINS["testnet"].chain_id)}))             # unsigned
    n = resolve(rpc_url="https://node.invalid", network="testnet", release_keys=[SIGNER.public_armour()],
                release_record_url=URL)
    with pytest.raises(net.RecordUnavailable) as e:
        net.signing_pin(n)
    assert e.value.record_code == "unsigned" and str(e.value).count("Nothing") == 1


def test_no_genesis_answer_adds_no_record_note(monkeypatch):
    from vordium.pins import PINS
    FakeNode(monkeypatch, PINS["testnet"].chain_id, None, Served({}))
    monkeypatch.setattr(net, "_fetch_spec", lambda u, t: {"chainId": PINS["testnet"].chain_id})
    n = resolve(rpc_url="https://node.invalid", network="testnet", release_keys=[SIGNER.public_armour()],
                release_record_url=URL)
    assert n.pin_problem and "could not be read" not in n.pin_problem


def test_record_refusals_say_nothing_was_signed_once_also_for_state_files():
    from vordium import network as N
    assert str(N._record_problem("The stored sequence cannot be read; nothing was signed. Check the file.", "state")).lower().count("nothing") == 1
