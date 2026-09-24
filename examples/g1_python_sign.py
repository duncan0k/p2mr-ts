"""The Bitcoin Core test framework's side of the OP_CHECKMLDSA44 regtest run (examples/g1-regtest.ts).

Reads one JSON request from stdin and answers on stdout, using the functional test framework of a
Bitcoin Core tree with the M1 patch series (its directory in G1_CORE_FUNCTIONAL):

    {"mode": "sign", "tx": ..., "spent": [{"amount": ..., "script_pubkey": ...}], "index": ...,
     "leaf": ..., "seed": ..., "hash_type": ...}
      -> {"message": ..., "signature": ..., "public_key": ...}
    {"mode": "verify", "tx": ..., "spent": [...], "index": ..., "leaf": ..., "public_key": ...,
     "signature": ...}
      -> {"message": ..., "valid": ...}

All byte strings are hex. The message is computed by the framework from the transaction, not taken
from the caller, and signing is the deterministic variant of FIPS 204.
"""

import json
import os
import sys

sys.path.insert(0, os.environ["G1_CORE_FUNCTIONAL"])

from test_framework.messages import CTxOut, tx_from_hex  # noqa: E402
from test_framework.p2mr_mldsa44 import (  # noqa: E402
    MLDSA44_SIGNATURE_SIZE,
    mldsa44_keygen,
    mldsa44_sighash,
    mldsa44_sign_input,
    mldsa44_verify,
)
from test_framework.script import CScript  # noqa: E402


def main():
    req = json.load(sys.stdin)
    tx = tx_from_hex(req["tx"])
    spent = [CTxOut(o["amount"], bytes.fromhex(o["script_pubkey"])) for o in req["spent"]]
    leaf = CScript(bytes.fromhex(req["leaf"]))
    if req["mode"] == "sign":
        pubkey, seckey = mldsa44_keygen(bytes.fromhex(req["seed"]))
        hash_type = req["hash_type"]
        msg = mldsa44_sighash(tx, spent, req["index"], leaf, hash_type=hash_type)
        sig = mldsa44_sign_input(seckey, tx, spent, req["index"], leaf, hash_type=hash_type)
        out = {"message": msg.hex(), "signature": sig.hex(), "public_key": pubkey.hex()}
    elif req["mode"] == "verify":
        sig = bytes.fromhex(req["signature"])
        hash_type = sig[MLDSA44_SIGNATURE_SIZE] if len(sig) == MLDSA44_SIGNATURE_SIZE + 1 else 0
        msg = mldsa44_sighash(tx, spent, req["index"], leaf, hash_type=hash_type)
        valid = mldsa44_verify(bytes.fromhex(req["public_key"]), msg, sig[:MLDSA44_SIGNATURE_SIZE])
        out = {"message": msg.hex(), "valid": bool(valid)}
    else:
        raise ValueError(f"unknown mode {req['mode']}")
    json.dump(out, sys.stdout)


if __name__ == "__main__":
    main()
