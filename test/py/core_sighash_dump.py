"""
Recompute every case in vectors/self_generated_p2mr_sighash.json with Bitcoin Core's
Python test framework (tag v29.0, vendored unmodified under test/py/core_v29/) and
dump the results as JSON on stdout.

Core's TaprootSignatureMsg knows nothing about P2MR. It serialises whatever spent
scriptPubKeys it is given and, with scriptpath=True, appends the BIP-342 ext
(TapLeaf hash || key_version || codesep_pos). That is exactly the part of the P2MR
digest that has no upstream vector, so this is an implementation-independent oracle
for it. Nothing here re-implements any hashing: every value comes from the vendored
framework.

Usage: python test/py/core_sighash_dump.py
"""

import json
import os
import sys
from io import BytesIO

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, os.path.join(HERE, "core_v29"))

from test_framework.key import TaggedHash  # noqa: E402
from test_framework.messages import CTransaction, CTxOut, ser_string  # noqa: E402
from test_framework.script import TaprootSignatureMsg  # noqa: E402

NO_CODESEPARATOR = 0xFFFFFFFF


def load_vectors(name):
    with open(os.path.join(REPO_ROOT, "vectors", name), "r", encoding="utf-8") as f:
        return json.load(f)


def main():
    given = load_vectors("bip341_wallet_test_vectors.json")["keyPathSpending"][0]["given"]
    cases = load_vectors("self_generated_p2mr_sighash.json")["cases"]

    tx = CTransaction()
    tx.deserialize(BytesIO(bytes.fromhex(given["rawUnsignedTx"])))
    spent = [
        CTxOut(u["amountSats"], bytes.fromhex(u["scriptPubKey"])) for u in given["utxosSpent"]
    ]

    # Replace the P2MR inputs exactly as the generator did. Every case for the same
    # input must carry the same scriptPubKey, otherwise the fixture is inconsistent.
    replaced = {}
    for c in cases:
        spk = bytes.fromhex(c["scriptPubKey"])
        if replaced.setdefault(c["inputIndex"], spk) != spk:
            raise SystemExit("inconsistent scriptPubKey for input %d" % c["inputIndex"])
    for idx, spk in replaced.items():
        spent[idx] = CTxOut(spent[idx].nValue, spk)

    results = []
    for c in cases:
        leaf_script = bytes.fromhex(c["leafScript"])
        annex = None if c["annex"] is None else bytes.fromhex(c["annex"])
        # Core encodes "no OP_CODESEPARATOR executed" as -1 (serialised signed -> ffffffff)
        codesep = -1 if c["codesepPos"] == NO_CODESEPARATOR else c["codesepPos"]
        msg = TaprootSignatureMsg(
            tx,
            spent,
            c["hashType"],
            c["inputIndex"],
            scriptpath=True,
            leaf_script=leaf_script,
            codeseparator_pos=codesep,
            annex=annex,
            leaf_ver=c["leafVersion"],
        )
        results.append(
            {
                "leafHash": TaggedHash(
                    "TapLeaf", bytes([c["leafVersion"]]) + ser_string(leaf_script)
                ).hex(),
                "sigMsg": msg.hex(),
                "sigHash": TaggedHash("TapSighash", msg).hex(),
            }
        )

    json.dump(
        {
            "framework": "bitcoin/bitcoin v29.0 test/functional/test_framework",
            "python": sys.version.split()[0],
            "replacedInputs": sorted(replaced),
            "results": results,
        },
        sys.stdout,
    )


if __name__ == "__main__":
    main()
