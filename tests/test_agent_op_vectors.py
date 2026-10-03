"""The SDK's agent owner ops against the chain's PUBLISHED vectors.

Reference: tests/vectors/agent-ops-vectors-2c1c0679.json — the chain's agent-op test vectors for genesis 2c1c0679,
kept to the fields these tests read. The pin below is that file's sha256; a file that does not match it is refused
rather than compared against.

Nothing from the file is retyped here: every expected value is READ from it at run time, and every
actual value is COMPUTED by the SDK's own signing code (eip712.domain / digest / sign_op / sign_agent_op).
The private keys in the file are its PUBLIC TEST KEYS; never fund them.

Runs under pytest, or standalone: python tests/test_agent_op_vectors.py
"""
import hashlib
import json
from pathlib import Path

from eth_account import Account
from eth_account.messages import encode_typed_data

from vordium import eip712
from vordium import network as net

VECTORS = Path(__file__).parent / "vectors" / "agent-ops-vectors-2c1c0679.json"
#: The sha256 of the vector file. A cross-check pin, not a value.
PINNED_SHA256 = "cd7da267707e1910823e909772204690d8938e0db9a365a301ad81dfb315c0cd"


def _load():
    raw = VECTORS.read_bytes()
    sha = hashlib.sha256(raw).hexdigest()
    assert sha == PINNED_SHA256, f"vectors file sha256 {sha} is not the pinned {PINNED_SHA256}; refusing to compare"
    return json.loads(raw)


V = _load()


def _pin_network():
    """The network the vectors were generated for, fed to the SDK's own resolved-network object."""
    n = V["network"]
    net.set_network(net.Network(
        chain_id=n["chainId"], chain_id_hex=hex(n["chainId"]), chain_name="Vordium Chain",
        rpc_url="offline", ws_url=None, explorer_url=None, bridge_address=None, bridge_chain=None,
        bridge_chain_id=None, native_symbol="VORD", native_decimals=18,
        verifying_contract=net.VERIFYING_CONTRACT, source="vectors", genesis_sha256=n["genesis_sha256"],
    ))


def _eq(a, b):
    return str(a).lower() == str(b).lower()


def test_domain_matches_published():
    _pin_network()
    d = eip712.domain()
    for k in ("name", "version", "chainId", "verifyingContract"):
        assert _eq(d[k], V["domain"][k]), f"domain.{k}: sdk {d[k]} file {V['domain'][k]}"
    assert _eq("0x" + d["salt"].hex(), V["domain"]["salt"]), "domain.salt"
    m = encode_typed_data(domain_data=d, message_types={"RevokeAgent": eip712.TYPES["RevokeAgent"]},
                          message_data=V["canonical_vectors"]["vectors"][1]["message"])
    assert _eq("0x" + m.header.hex(), V["domain"]["domainSeparator"]), "domainSeparator"


def test_the_sdk_declares_exactly_the_published_agent_ops():
    ops = sorted(v["op"] for v in V["canonical_vectors"]["vectors"])
    assert sorted(eip712.AGENT_OPS) == ops, f"sdk {sorted(eip712.AGENT_OPS)} file {ops}"


def test_types_struct_hashes_and_digests_match_published():
    _pin_network()
    for vec in V["canonical_vectors"]["vectors"]:
        op = vec["op"]
        sdk_fields = [(f["name"], f["type"]) for f in eip712.TYPES[op]]
        pub_fields = [(f["name"], f["type"]) for f in V["types"][op]["fields"]]
        assert sdk_fields == pub_fields, f"{op}: field names/types/order"
        m = encode_typed_data(domain_data=eip712.domain(), message_types={op: eip712.TYPES[op]},
                              message_data=vec["message"])
        assert _eq("0x" + m.body.hex(), vec["structHash"]), f"{op}: structHash"
        assert _eq(eip712.digest(op, vec["message"]), vec["digest"]), f"{op}: digest"


def test_signatures_are_the_published_65_bytes():
    _pin_network()
    keys = {"owner": V["test_keys"]["owner"]["private_key"], "agent": V["test_keys"]["agent"]["private_key"]}
    for vec in V["signed_vectors"]["vectors"]:
        op = vec["op"]
        for case in vec["cases"]:
            key = keys["agent" if "agent key" in case["signedBy"] else "owner"]
            for signer in (eip712.sign_agent_op, eip712.sign_op):
                sig = signer(key, op, vec["message"])
                assert (len(sig) - 2) // 2 == 65, f"{op} [{case['signedBy']}] via {signer.__name__}: {(len(sig) - 2) // 2} bytes"
                assert _eq(sig, case["signature"]), f"{op} [{case['signedBy']}] via {signer.__name__}: signature bytes"
                assert int(sig[-2:], 16) in (27, 28), f"{op}: v must be 27/28"
            rec = Account._recover_hash(bytes.fromhex(vec["digest"][2:]), signature=bytes.fromhex(case["signature"][2:]))
            assert _eq(rec, case["recovers"]), f"{op} [{case['signedBy']}]: recovers {rec}"
            # the chain's verdict follows from recovery: accepted iff the signer is the owner (a replay is the
            # same bytes; its rejection is the stored nonce — chain state, not checkable offline)
            if "replay" not in case["signedBy"].lower():
                assert _eq(rec, vec["message"]["owner"]) == case["expected"].startswith("ACCEPTED"), f"{op} [{case['signedBy']}]: verdict"


def test_sign_agent_op_refuses_order_ops():
    _pin_network()
    key = V["test_keys"]["owner"]["private_key"]
    try:
        eip712.sign_agent_op(key, "CancelOrder", {"owner": "0x" + "11" * 20, "orderId": 1})
    except ValueError:
        return
    raise AssertionError("sign_agent_op signed an order op")


def test_order_ops_keep_their_64_byte_form():
    _pin_network()
    key = V["test_keys"]["owner"]["private_key"]
    sig = eip712.sign_op(key, "CancelOrder", {"owner": "0x" + "11" * 20, "orderId": 1})
    assert (len(sig) - 2) // 2 == 64


if __name__ == "__main__":
    import sys
    fails = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print(f"  PASS  {name}")
            except Exception as e:  # noqa: BLE001 — report every failure, then exit non-zero
                fails += 1
                print(f"  FAIL  {name}: {e}")
    net.reset_network()
    print(f"\n{'FAIL' if fails else 'PASS'}  agent-op vectors ({fails} failing)")
    sys.exit(1 if fails else 0)
