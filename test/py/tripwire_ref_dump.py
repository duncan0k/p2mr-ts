"""
The S3 output of a key pair, with its two leaves of version 0xe0, computed without this library.

Reads one JSON object from stdin:

    {"seed": <32-byte ML-DSA-44 seed>, "xonly": <32-byte x-only key>, "hash_types": [n, ...],
     "annex_cases": [{"path": "schnorr" or "mldsa44", "hash_type": n, "annex": <annex>}, ...]}

(hex) and prints, as JSON:

- the ML-DSA-44 public key of the seed, from ML-DSA.KeyGen_internal of `core_m1/fips204.py`;
- the two leaf scripts, `20 <xonly> ac` and S1 (the key in pushes of 520, 520 and 272 bytes,
  then 0xf0), put together here from the published encoding;
- the TapLeaf hashes of both at leaf versions 0xe0 and 0xc0, the merkle root of the two 0xe0
  leaves, the control block of each and the addresses for the hrps tb and bcrt, from the BIP-360
  reference implementation `reference/python/p2mr.py`;
- for each hash type, the BIP-342 signature hash (key_version 0) of the Schnorr leaf at versions
  0xe0 and 0xc0, on the transaction pair Core's script tests build for an output of 1 satoshi,
  from `TaprootSignatureMsg` of the Bitcoin Core v29.0 test framework;
- for each annex case, the signature hash of the given leaf at version 0xe0 with that annex, from
  the same function: key_version 0 for the Schnorr leaf, and for the ML-DSA-44 leaf the same
  message with the key_version byte set to 1, as the rule of OP_CHECKMLDSA44 defines its message.

None of these shares code with this library.

Usage: echo '{"seed": "...", "xonly": "...", "hash_types": [0]}' | python test/py/tripwire_ref_dump.py
"""

import importlib.util
import json
import os
import platform
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, os.path.join(HERE, "core_m1"))
sys.path.insert(0, os.path.join(HERE, "core_v29"))

from fips204 import ML_DSA  # noqa: E402
from test_framework.key import TaggedHash  # noqa: E402
from test_framework.messages import COutPoint, CTransaction, CTxIn, CTxOut  # noqa: E402
from test_framework.script import TaprootSignatureMsg  # noqa: E402

TRIPWIRED = 0xE0
TAPSCRIPT = 0xC0
KEY_VERSIONS = {"schnorr": 0, "mldsa44": 1}


def load_reference():
    path = os.path.join(REPO_ROOT, "reference", "python", "p2mr.py")
    spec = importlib.util.spec_from_file_location("bip360_ref_p2mr", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load %s" % path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def s1_leaf(pk):
    return (
        bytes.fromhex("4d0802") + pk[:520]
        + bytes.fromhex("4d0802") + pk[520:1040]
        + bytes.fromhex("4d1001") + pk[1040:]
        + bytes([0xF0])
    )


def spending_tx(spk):
    """BuildCreditingTransaction and BuildSpendingTransaction of Core's script tests, for 1 satoshi."""
    credit = CTransaction()
    credit.version = 1
    credit.vin = [CTxIn(COutPoint(0, 0xFFFFFFFF), bytes.fromhex("0000"), 0xFFFFFFFF)]
    credit.vout = [CTxOut(1, spk)]
    credit.rehash()
    spend = CTransaction()
    spend.version = 1
    spend.vin = [CTxIn(COutPoint(credit.sha256, 0), b"", 0xFFFFFFFF)]
    spend.vout = [CTxOut(1, b"")]
    return spend


def main():
    request = json.load(sys.stdin)
    ref = load_reference()
    pk, _ = ML_DSA("ML-DSA-44").keygen_internal(bytes.fromhex(request["seed"]))
    pk = bytes(pk)
    leaves = {
        "schnorr": bytes([0x20]) + bytes.fromhex(request["xonly"]) + bytes([0xAC]),
        "mldsa44": s1_leaf(pk),
    }
    tree = [
        {"script": leaves["schnorr"].hex(), "leafVersion": TRIPWIRED},
        {"script": leaves["mldsa44"].hex(), "leafVersion": TRIPWIRED},
    ]
    root = ref.compute_merkle_root(tree)
    spk = bytes.fromhex("5220") + root
    tx = spending_tx(spk)

    sighashes = []
    for hash_type in request["hash_types"]:
        entry = {"hash_type": hash_type}
        for name, version in (("e0", TRIPWIRED), ("c0", TAPSCRIPT)):
            msg = TaprootSignatureMsg(
                tx,
                [CTxOut(1, spk)],
                hash_type,
                0,
                scriptpath=True,
                leaf_script=leaves["schnorr"],
                leaf_ver=version,
            )
            entry[name] = TaggedHash("TapSighash", msg).hex()
        sighashes.append(entry)

    annex_sighashes = []
    for case in request.get("annex_cases", []):
        msg = bytearray(TaprootSignatureMsg(
            tx,
            [CTxOut(1, spk)],
            case["hash_type"],
            0,
            scriptpath=True,
            leaf_script=leaves[case["path"]],
            annex=bytes.fromhex(case["annex"]),
            leaf_ver=TRIPWIRED,
        ))
        # ext = TapLeaf hash || key_version || codesep_pos
        assert msg[-5] == 0
        msg[-5] = KEY_VERSIONS[case["path"]]
        annex_sighashes.append(dict(case, e0=TaggedHash("TapSighash", bytes(msg)).hex()))

    json.dump(
        {
            "python": platform.python_version(),
            "public_key": pk.hex(),
            "leaf_scripts": {name: script.hex() for name, script in leaves.items()},
            "leaf_hashes": {
                name: {
                    "e0": ref.tapleaf_hash(script, TRIPWIRED).hex(),
                    "c0": ref.tapleaf_hash(script, TAPSCRIPT).hex(),
                }
                for name, script in leaves.items()
            },
            "merkle_root": root.hex(),
            "control_blocks": [cb.hex() for cb in ref.collect_control_blocks(tree)],
            "addresses": {
                hrp: ref.encode(hrp=hrp, witver=2, witprog=ref.s2w(root.hex()))
                for hrp in ("tb", "bcrt")
            },
            "sighashes": sighashes,
            "annex_sighashes": annex_sighashes,
        },
        sys.stdout,
    )


if __name__ == "__main__":
    main()
