"""
Judge the tripwired leaf rows of vectors/tripwire_crossimpl_rows.json without this library, and
print the verdicts as JSON on stdout.

Each row is judged by the rules of the M3 design: a leaf of version 0xe0 runs as a leaf of version
0xc0 under P2MR_TRIPWIRE, and under P2MR_EC_DISABLED a signature check on a 32-byte key with a
non-empty signature fails in it. The parts come from code that shares nothing with this library:

- the control block must commit to the output: `tapleaf_hash` and `tapbranch_hash` of the BIP-360
  reference implementation `reference/python/p2mr.py`;
- the transaction pair is the one Core's script tests build, from `CTransaction` of the Bitcoin
  Core v29.0 test framework, and the signature messages come from its `TaprootSignatureMsg`, with
  the key_version byte set to 1 for OP_CHECKMLDSA44, as its rule defines the message;
- BIP-340 signatures are verified by `verify_schnorr` of that framework, ML-DSA-44 signatures by
  `core_m1/fips204.py` with the context string "P2MR/MLDSA44/EXP0".

Usage: python test/py/tripwire_rows_judge.py
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
from test_framework.key import TaggedHash, verify_schnorr  # noqa: E402
from test_framework.messages import COutPoint, CTransaction, CTxIn, CTxOut  # noqa: E402
from test_framework.script import TaprootSignatureMsg  # noqa: E402

MLDSA44 = ML_DSA("ML-DSA-44")
CONTEXT = b"P2MR/MLDSA44/EXP0"
S1_SIZE = 3 + 520 + 3 + 520 + 3 + 272 + 1


def load_reference():
    path = os.path.join(REPO_ROOT, "reference", "python", "p2mr.py")
    spec = importlib.util.spec_from_file_location("bip360_ref_p2mr", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load %s" % path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def spending_tx(spk, amount):
    """BuildCreditingTransaction and BuildSpendingTransaction of Core's script tests."""
    credit = CTransaction()
    credit.version = 1
    credit.vin = [CTxIn(COutPoint(0, 0xFFFFFFFF), bytes.fromhex("0000"), 0xFFFFFFFF)]
    credit.vout = [CTxOut(amount, spk)]
    credit.rehash()
    spend = CTransaction()
    spend.version = 1
    spend.vin = [CTxIn(COutPoint(credit.sha256, 0), b"", 0xFFFFFFFF)]
    spend.vout = [CTxOut(amount, b"")]
    return spend


def parse_mldsa44_leaf(leaf):
    """(public key, x-only key or None) of S1 or S2, or None for any other script."""
    if len(leaf) not in (S1_SIZE, S1_SIZE + 35):
        return None
    if (
        leaf[0:3] != bytes.fromhex("4d0802")
        or leaf[523:526] != bytes.fromhex("4d0802")
        or leaf[1046:1049] != bytes.fromhex("4d1001")
        or leaf[S1_SIZE - 1] != 0xF0
    ):
        return None
    pk = leaf[3:523] + leaf[526:1046] + leaf[1049:S1_SIZE - 1]
    if len(leaf) == S1_SIZE:
        return pk, None
    if leaf[S1_SIZE] != 0x69 or leaf[S1_SIZE + 1] != 0x20 or leaf[-1] != 0xAC:
        return None
    return pk, leaf[S1_SIZE + 2:S1_SIZE + 34]


def judge(ref, row):
    witness = [bytes.fromhex(item) for item in row[0][:-1]]
    amount = round(row[0][-1] * 100_000_000)
    asm = row[2].split(" ")
    if asm[:2] != ["0x52", "0x20"]:
        return "NOT_P2MR"
    spk = bytes.fromhex("5220" + asm[2][2:])
    flags = set(row[3].split(","))
    control_block, leaf, stack = witness[-1], witness[-2], witness[:-2]
    version = control_block[0] & 0xFE
    acc = ref.tapleaf_hash(leaf, version)
    for i in range(1, len(control_block), 32):
        acc = ref.tapbranch_hash(acc, control_block[i:i + 32])
    if acc != spk[2:]:
        return "NOT_COMMITTED"
    m = (len(control_block) - 1) // 32
    if "P2MR" not in flags or m == 0 or not (version == 0xC0 or (version == 0xE0 and "P2MR_TRIPWIRE" in flags)):
        return "NOT_EXECUTED"
    ec_off = version == 0xE0 and "P2MR_EC_DISABLED" in flags
    tx = spending_tx(spk, amount)

    def message(hash_type, key_version):
        msg = bytearray(TaprootSignatureMsg(
            tx, [CTxOut(amount, spk)], hash_type, 0, scriptpath=True, leaf_script=leaf, leaf_ver=version,
        ))
        # ext = TapLeaf hash || key_version || codesep_pos
        msg[-5] = key_version
        return TaggedHash("TapSighash", bytes(msg))

    def checksig(sig, key):
        if ec_off:
            return "EC_DISABLED"
        hash_type = sig[64] if len(sig) == 65 else 0
        return None if verify_schnorr(key, sig[:64], message(hash_type, 0)) else "SCHNORR_INVALID"

    if len(leaf) == 34 and leaf[0] == 0x20 and leaf[33] == 0xAC:
        return checksig(stack[0], leaf[1:33]) or "VALID"
    parsed = parse_mldsa44_leaf(leaf)
    if parsed is None:
        return "OTHER_LEAF"
    pk, xonly = parsed
    sig = b"".join(stack[-5:])
    hash_type = sig[2420] if len(sig) == 2421 else 0
    if not MLDSA44.verify(pk, message(hash_type, 1), sig[:2420], CONTEXT):
        return "MLDSA44_INVALID"
    if xonly is not None:
        return checksig(stack[0], xonly) or "VALID"
    return "VALID"


def main():
    ref = load_reference()
    with open(os.path.join(REPO_ROOT, "vectors", "tripwire_crossimpl_rows.json"), "r", encoding="utf-8") as f:
        rows = [row for row in json.load(f) if len(row) == 6]
    json.dump(
        {
            "python": platform.python_version(),
            "verdicts": [judge(ref, row) for row in rows],
        },
        sys.stdout,
    )


if __name__ == "__main__":
    main()
