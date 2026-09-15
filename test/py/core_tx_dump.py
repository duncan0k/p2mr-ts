"""
Re-serialise transactions with Bitcoin Core's Python test framework (tag v29.0,
vendored unmodified under test/py/core_v29/) and dump the results as JSON on stdout.

Core's CTransaction is an independent implementation of the BIP-144 wire format and
of txid/wtxid (double-SHA256 over the witness-less / witness-bearing serialisation).
It knows nothing about P2MR — it just round-trips whatever bytes it is handed — which
is exactly what makes it a usable oracle for encodeTransaction/computeTxid/computeWtxid.
Nothing here re-implements any serialisation or hashing.

Input : JSON array of raw transaction hex strings on stdin.
Output: JSON on stdout; txid/wtxid are in display (reversed) byte order.

Usage: echo '["0200..."]' | python test/py/core_tx_dump.py
"""

import json
import os
import sys
from io import BytesIO

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "core_v29"))

from test_framework.messages import CTransaction  # noqa: E402


def main():
    raws = json.load(sys.stdin)
    results = []
    for raw in raws:
        tx = CTransaction()
        tx.deserialize(BytesIO(bytes.fromhex(raw)))
        tx.rehash()
        results.append(
            {
                "withWitness": tx.serialize_with_witness().hex(),
                "withoutWitness": tx.serialize_without_witness().hex(),
                "txid": tx.hash,
                "wtxid": tx.getwtxid(),
                "weight": tx.get_weight(),
                "vsize": tx.get_vsize(),
            }
        )

    json.dump(
        {
            "framework": "bitcoin/bitcoin v29.0 test/functional/test_framework",
            "python": sys.version.split()[0],
            "results": results,
        },
        sys.stdout,
    )


if __name__ == "__main__":
    main()
