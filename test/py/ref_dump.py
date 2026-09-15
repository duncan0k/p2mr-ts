"""
Run the vendored BIP-360 Python reference implementation over both vector files
and dump what it computes as JSON on stdout.

The TypeScript differential test compares its own results against this dump.
Nothing here re-implements anything: every value comes from
reference/python/p2mr.py, which is a byte-for-byte copy of
bitcoin/bips@620871a7a442e276a058b487cd8743775fb499a4.

Usage: python test/py/ref_dump.py
"""

import importlib.util
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
REF_PATH = os.path.join(REPO_ROOT, "reference", "python", "p2mr.py")


def load_reference():
    spec = importlib.util.spec_from_file_location("bip360_ref_p2mr", REF_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load %s" % REF_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def script_tree(given):
    if "scriptTree" in given:
        return given["scriptTree"]
    return given.get("script_tree")


def dump_file(ref, filename):
    with open(os.path.join(REPO_ROOT, "vectors", filename), "r", encoding="utf-8") as f:
        vectors = json.load(f)["test_vectors"]

    results = []
    for v in vectors:
        given = v.get("given", {})
        tree = script_tree(given)
        entry = {
            "id": v["id"],
            "hasInternalPubkey": "internalPubkey" in given,
            "treeMissing": tree is None or tree == "",
        }
        if not entry["treeMissing"]:
            merkle_root = ref.compute_merkle_root(tree)
            entry["leafHashes"] = [h.hex() for h in ref.collect_leaf_hashes(tree)]
            entry["merkleRoot"] = merkle_root.hex()
            entry["scriptPubKey"] = "5220" + merkle_root.hex()
            entry["bip350Address"] = ref.encode(
                hrp="bc", witver=2, witprog=ref.s2w(merkle_root.hex())
            )
            entry["controlBlocks"] = [cb.hex() for cb in ref.collect_control_blocks(tree)]
            entry["leafPaths"] = ref.walk_script_tree_paths(tree)
        results.append(entry)
    return results


def main():
    ref = load_reference()
    payload = {
        "referenceFile": os.path.relpath(REF_PATH, REPO_ROOT).replace(os.sep, "/"),
        "python": sys.version.split()[0],
        "files": {
            name: dump_file(ref, name)
            for name in ("p2mr_construction.json", "p2mr_pqc_construction.json")
        },
    }
    json.dump(payload, sys.stdout)


if __name__ == "__main__":
    main()
