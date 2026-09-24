"""ML-DSA-44 results of the Python implementation in Bitcoin Core's functional test framework.

Reads one JSON object from stdin:

    {"keygen": [seed, ...],
     "sign":   [{"seed": ..., "message": ..., "context": ...}, ...],
     "verify": [{"public_key": ..., "message": ..., "signature": ..., "context": ...}, ...]}

(all hex) and prints, as JSON, the key pairs from ML-DSA.KeyGen_internal, the signatures of the
deterministic variant (rnd = 32 zero bytes) and the results of ML-DSA.Verify, all pure ML-DSA-44
with the given context string.

The implementation is `core_m1/fips204.py`, vendored byte for byte from the M1 patch series of
Bitcoin Core (see vectors/SOURCE.md). It shares no code with @noble/post-quantum.
"""

import json
import os
import platform
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "core_m1"))

from fips204 import ML_DSA  # noqa: E402

MLDSA44 = ML_DSA("ML-DSA-44")


def main():
    request = json.load(sys.stdin)
    keygen = []
    for seed in request.get("keygen", []):
        pk, sk = MLDSA44.keygen_internal(bytes.fromhex(seed))
        keygen.append({"public_key": bytes(pk).hex(), "secret_key": bytes(sk).hex()})
    signatures = []
    for case in request.get("sign", []):
        _, sk = MLDSA44.keygen_internal(bytes.fromhex(case["seed"]))
        sig = MLDSA44.sign(bytes(sk), bytes.fromhex(case["message"]), bytes.fromhex(case["context"]))
        signatures.append(bytes(sig).hex())
    verified = []
    for case in request.get("verify", []):
        verified.append(bool(MLDSA44.verify(
            bytes.fromhex(case["public_key"]),
            bytes.fromhex(case["message"]),
            bytes.fromhex(case["signature"]),
            bytes.fromhex(case["context"]),
        )))
    json.dump({
        "python": platform.python_version(),
        "keygen": keygen,
        "sign": signatures,
        "verify": verified,
    }, sys.stdout)


if __name__ == "__main__":
    main()
