# Sources of the vectors and the reference implementation

Every file here is taken from a **pinned commit** of the `bitcoin/bips` repository:

```
620871a7a442e276a058b487cd8743775fb499a4
```

That commit corresponds to BIP-360 v0.12.1 (2026-07-24: adds the Python reference
implementation, drops the Rust/JS bindings, corrects the vectors). BIP-360 is still a Draft
and upstream may change at any time; this repository does not follow the tip, it aligns with
this one commit. Upgrading the vectors requires updating the sha256 values in this file and
the commit in the README at the same time.

How they were fetched (`curl` straight from the raw files, with no further processing):

```
https://raw.githubusercontent.com/bitcoin/bips/620871a7a442e276a058b487cd8743775fb499a4/<path>
```

## Checksums

| sha256 | Path in this repo | Upstream path |
| --- | --- | --- |
| `cd02da0b3c5bcbea98ed4d3141ebaf71344ee5acc8eb543841b7d2ed853251c7` | `vectors/p2mr_construction.json` | `bip-0360/ref-impl/common/tests/data/p2mr_construction.json` |
| `3bd10ece56cb52c2616d5d7ff341afb5b039bc75a8b55caf680e74805a3cf454` | `vectors/p2mr_pqc_construction.json` | `bip-0360/ref-impl/common/tests/data/p2mr_pqc_construction.json` |
| `403e19fb81dd1f31e745699216308f61fb403774b2aafa87b631b8f7c042d37f` | `vectors/bip341_wallet_test_vectors.json` | `bip-0341/wallet-test-vectors.json` |
| `988957d7373b3779c05877aaf7aa671ce74f0db66d014c98d69132d12f3b6770` | `reference/bip-0360.mediawiki` | `bip-0360.mediawiki` |
| `ade7e6099eb722cc2f45fb366b7e89b766da46a0424e2ce3732f9419fc1146e5` | `reference/python/p2mr.py` | `bip-0360/ref-impl/python/p2mr.py` |
| `79b6f8054f8ef5e9e78c18174bf57caf29b11410166b9268d6923e87520eb88f` | `reference/python/python.gitignore` | `bip-0360/ref-impl/python/.gitignore` |
| `977c0cc832014c559c3228a20857486264a0e9a45f267af204379793bf12fc85` | `reference/python/ref-impl.gitignore` | `bip-0360/ref-impl/.gitignore` |

The two `.gitignore` files are kept byte-for-byte and only renamed to `*.gitignore`, so that
they do not actually take effect inside this repository.

The full contents of `bip-0360/ref-impl/` were enumerated and checked against the GitHub tree
API: that directory holds exactly the 5 files in the table above (two vector JSONs, two
`.gitignore` files, one `p2mr.py`), nothing was missed.

## Fact-check of the upstream files

- `p2mr_construction.json`: `version: 1` is the **vector format version**, not the BIP version.
  9 cases in total = 7 construction positive cases (16 control blocks between them) + 2
  construction API error cases.
- Both `scriptTree` and `script_tree` appear as key names inside `given`; a parser has to
  accept either.
- The `expected` of the misuse vector `p2mr_misuse_v2_witness_version_with_pubkey_error`
  contains **both an `error` and a `scriptPubKey`**. That `scriptPubKey` is a leftover
  BIP-341 tweaked pubkey (`5220<tweakedPubkey>`), not a valid P2MR output.
  Code written as "skip anything that has an `error`" walks straight past this trap.
- `internalPubkey` / `tweak` / `tweakedPubkey` are all leftover BIP-341 fields; P2MR has no
  key path.
- `p2mr_pqc_construction.json`: 7 cases (1 error case + 6 positive cases). The leaf scripts
  have the shape `20<32 bytes>7f`, where the trailing `0x7f` is `OP_SUCCESS127` standing in
  for "PQ signature verification". It carries **no consensus meaning** and is only good for
  exercising construction. The objective of its `p2mr_different_version_leaves` still carries
  an upstream to-do ("currently ignores given leaf version and over-rides").
- The Python reference implementation (`reference/python/p2mr.py`, 427 lines) **covers
  construction only**: `tapleaf_hash` / `tapbranch_hash` / `compute_merkle_root` /
  `compute_control_block` / bech32 encoding and decoding / a test driver. It has **no sighash
  or spend-related function whatsoever**, and neither of the two official vector files
  contains any spend vector.

## Non-upstream file

`vectors/self_generated_p2mr_sighash.json` is **not** an upstream file. It is a regression
vector produced by this repository via `scripts/generate-sighash-vectors.ts`, and it carries
a `SELF-GENERATED` warning inside the file itself. It works as a regression anchor only; it
does not constitute cross-implementation verification.

## Licensing

The MIT license of this repository does not apply to the upstream files. The BIP-360 text
declares `License: BSD-3-Clause` in its header (v0.12.1, `reference/bip-0360.mediawiki:11`),
and `reference/python/p2mr.py` sits in the same BIP directory and inherits it;
`vectors/bip341_wallet_test_vectors.json` follows the license declared by BIP-341 itself.
Handle each of these files under its own license when forwarding or redistributing them.

## Bitcoin Core v29.0 test framework (independent cross-check for the digest layer)

The files under `test/py/core_v29/test_framework/` are taken from
`test/functional/test_framework/` of `bitcoin/bitcoin` at tag `v29.0`
(commit `f490f5562d4b20857ef8d042c050763795fd43da`), byte-for-byte unmodified, MIT licensed
(each file carries its own copyright header). Only `TaprootSignatureMsg` /
`TaprootSignatureHash` / `TaggedHash` and the transaction serialization are used, as an
independent recomputer for P2MR script-path digests (`test/py/core_sighash_dump.py`, driven
by `test/differential-core-sighash.test.ts`).

How they were fetched: `https://raw.githubusercontent.com/bitcoin/bitcoin/v29.0/test/functional/test_framework/<path>`.

| sha256 | Path in this repo | Upstream path (under `test/functional/test_framework/`) |
| --- | --- | --- |
| `ae8d3e2770933f35c755c00651ca6cc0b4d57a1ca95c687941637ffcdf1dc772` | `test/py/core_v29/test_framework/script.py` | `script.py` |
| `37cdc47790abb64ad909beae0a12ffba99e5123b429a2879ce448414d8139c00` | `test/py/core_v29/test_framework/messages.py` | `messages.py` |
| `c820332654015a3f3f3d16d61e50beca1aafb9723e52aae84c20431f8e243217` | `test/py/core_v29/test_framework/key.py` | `key.py` |
| `9ebc188ce51969a9757305939f295bbb2ba9a2f79dec19176eb79990b3df34a2` | `test/py/core_v29/test_framework/crypto/siphash.py` | `crypto/siphash.py` |
| `99da6dafa9804d3ca5490a736354027b10ec3d517206caad6ea28c0e097f6b9a` | `test/py/core_v29/test_framework/crypto/ripemd160.py` | `crypto/ripemd160.py` |
| `1b2d1c40fcc7360218833ef37d4337f8617833bc71dfd7238aa4e838809841eb` | `test/py/core_v29/test_framework/crypto/secp256k1.py` | `crypto/secp256k1.py` |
| `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` | `test/py/core_v29/test_framework/__init__.py` | `__init__.py` (empty file) |

Upstream has no `__init__.py` in its `crypto/` directory (a Python 3 namespace package); this
repository copies that as-is and does not add one.

`test/py/core_v29/test_framework/util.py` is **not** a Core file: Core's `util.py` drags in
RPC-related modules such as `authproxy` and `coverage`, so it is replaced here by a stub that
provides only `assert_equal` and `random_bitflip` (the only two names `messages.py` and
`key.py` actually use).

Why use it: Core's `TaprootSignatureMsg` shares no code with this library and knows nothing
about P2MR -- it simply serializes the `OP_2 <root>` scriptPubKey it is handed, and with
`scriptpath=True` appends `TapLeaf(leaf_ver || script) || key_version || codesep_pos`. That is
exactly the part for which BIP-360 upstream publishes no vectors. What it establishes is
that this library and the Core test framework compute the same values; it does not establish
that any node would accept these spends.
