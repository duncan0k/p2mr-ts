# p2mr

An **offline construction library** for BIP-360 Pay-to-Merkle-Root (P2MR). TypeScript, ESM,
Node >= 20, with `@noble/hashes` and `bech32` as the only runtime dependencies.

It is aligned with a pinned commit of the `bitcoin/bips` repository:

```
620871a7a442e276a058b487cd8743775fb499a4
```

That commit corresponds to BIP-360 v0.12.1. The vectors, the BIP text and the Python
reference implementation are all vendored in this repository at that commit, with a per-file
sha256 recorded in [`vectors/SOURCE.md`](vectors/SOURCE.md).

## What it does

- **Tree hashing**: `TapLeaf` / `TapBranch` tagged hashes, with branches ordered
  lexicographically. Identical to BIP-341, only with the key path and the tweak removed.
- **Control blocks**: `1 + 32*m` bytes, `c[0] = (leafVersion & 0xfe) | 1`, `m <= 128`.
  Duplicate leaves get one control block each **by position in the tree**; they are not
  deduplicated by hash.
- **scriptPubKey and addresses**: `OP_2 OP_PUSHBYTES_32 <root>`; bech32m witness v2, the three
  hrps `bc` / `tb` / `bcrt`, both encoding and decoding.
- **Witness stacks**: assembly for script-path spends
  (`[stack elements..., leaf script, control block, (annex)]`) plus shape validation.
- **Transaction serialization**: BIP-144 in both directions (`encodeTransaction` and
  `decodeTransaction` are mutually inverse, with witness stacks preserved on
  `TxInput.witness`), plus `computeTxid` / `computeWtxid`. The txid and `TxInput.txid` are
  both in **internal byte order**; display order is up to the caller, via `reverseBytes`.
- **Signature hashes**: the BIP-341/342
  `TaggedHash("TapSighash", 0x00 ‖ SigMsg(hash_type, ext_flag=1) ‖ ext)`, with
  `ext = tapleaf_hash(32) ‖ key_version(0x00) ‖ codesep_pos(4, LE)` and
  `spend_type = 2*ext_flag + annex_present`. All seven sighash types are supported. The digest
  commits to the **actual** `OP_2 <root>` scriptPubKey of each spent output.

## What it does not do

- **No network validation of any kind.** It only constructs and computes digests. There is no
  node, no mempool, no consensus execution. "The vectors pass" says only that the construction agrees;
  it says nothing about whether these outputs can be spent on any network.
- **No signing.** It holds no private key, performs no BIP-340 signing, and contains no
  post-quantum signature algorithm.
- **Not a consensus implementation.** The library's "reject internal pubkeys", "reject single
  leaves" and "reject non-`0xC0` leaves" are **construction-interface constraints** and must
  not be carried into consensus tests as they are -- a node only ever sees a 32-byte witness
  program.
- **BIP-360 is still a Draft.** It changed four times during 2026. Once upstream changes, the
  commit this library is aligned with may be out of date. This library does not follow the
  tip; upgrading is an explicit action.

## What is rejected by default, and why

| Input | Default | Opt-out | Rationale |
| --- | --- | --- | --- |
| `internalPubkey` / `tweak` / `tweakedPubkey` | rejected | none | P2MR has no key path. The witness program is the merkle root itself, so there is no internal pubkey and no taproot tweak. These fields are BIP-341 leftovers in the official vectors. |
| single-leaf tree (m=0) | rejected | `allowUnsafeSingleLeaf` | Under BIP-360 v0.12.0, a control block with `m=0` succeeds the moment the root matches, **whether or not the script itself executes**. A depth-0 tree is anyone-can-spend. Low-level tooling has to be able to build such a test case; a wallet interface has to refuse it. |
| leaf version other than 0xC0 | rejected | `allowUnsafeLeafVersion` | The spec text: execution of a future leaf version (anything but `0xC0`) **must succeed**. In other words a non-`0xC0` leaf does not execute the script and succeeds unconditionally, which is again anyone-can-spend. A consensus implementation needs that success case; a wallet must not generate one. |
| annex | rejected | `allowAnnex` | Consensus permits an annex, but the taproot **policy** in Bitcoin Core v29.0 rejects transactions carrying one -- consensus-valid is not the same as mempool-accepted. The wallet layer produces no annex by default; the signature-hash interface still supports an annex for when the flag is set explicitly. |
| leaf script containing `OP_SUCCESSx` | rejected | `allowOpSuccess` | Under tapscript, hitting an `OP_SUCCESSx` succeeds unconditionally. The scanner decodes by opcode and skips push data -- a raw byte scan would mistake a `0xfe` or `0xbb` inside push data for an OP_SUCCESS. |

The opt-outs are all explicit. The two with `unsafe` in the name in particular have no place
in a wallet code path, and `allowAnnex` belongs only in test tooling.

## Usage

```ts
import { createP2mrOutput, bytesToHex } from 'p2mr';

const out = createP2mrOutput({
  scriptTree: [
    { script: '2072ea…69ac', leafVersion: 0xc0 },
    [
      { script: '2023…a8ac', leafVersion: 0xc0 },
      { script: '2073…6aac', leafVersion: 0xc0 },
    ],
  ],
  network: 'mainnet',
});

out.merkleRoot;   // Uint8Array(32)
out.scriptPubKey; // OP_2 OP_PUSHBYTES_32 <root>
out.address;      // bech32m witness v2
out.leaves;       // per leaf position: leafHash / merklePath / controlBlock
```

Witness and digest for a script-path spend:

```ts
import { assembleScriptPathWitness, p2mrScriptPathSighash } from 'p2mr';

const sighash = p2mrScriptPathSighash({
  tx,                       // { version, locktime, inputs, outputs }
  inputIndex: 0,
  spentOutputs,             // in one-to-one correspondence with inputs
  leafHash: out.leaves[1].leafHash,
  // hashType defaults to SIGHASH_DEFAULT(0x00); codesep defaults to 0xffffffff
});

const witness = assembleScriptPathWitness({
  stack: [signature],       // this library does not sign; the caller supplies the signature
  leafScript: out.leaves[1].script,
  controlBlock: out.leaves[1].controlBlock,
});
```

Both key names `scriptTree` and `script_tree` are accepted -- the official vectors use both.

## Tests

```bash
npm install
npm run typecheck
npm test
```

Seven layers of coverage:

1. **All 9 cases of `p2mr_construction.json`** (at the pinned commit). The 7 positive cases
   are compared case by case on leaf hashes, merkle root, scriptPubKey, `bip350Address` and
   **all 16** control blocks; the 2 construction API error cases assert that a throw happens.
   The `expected` of the misuse vector contains **both an `error` and a `scriptPubKey`**, the
   latter being a leftover BIP-341 tweaked pubkey -- code written as "skip anything that has
   an `error`" walks straight past this trap, and there is a dedicated assertion for it.
2. **All 7 cases of `p2mr_pqc_construction.json`**. The leaf scripts in these vectors are
   `20<32 bytes>7f`, where the trailing `0x7f` is `OP_SUCCESS127` standing in for "PQ
   signature verification". It carries **no consensus meaning** and is only good for
   exercising construction, so `allowOpSuccess` has to be turned on explicitly.
3. **A negative matrix**: control block length that is not `1+32m`; low bit of `c[0]` equal to
   0; `m > 128`; a single leaf; a non-`0xC0` leaf; an internal pubkey; a witness stack with
   fewer than 2 elements; exactly 2 elements where the last one starts with `0x50`; witness v2
   with a bech32 (rather than bech32m) checksum; a mismatched hrp; a witness version other
   than 2; a program length other than 32; `OP_1 <root>` posing as P2MR; a tree deeper than
   128.
4. **Differential against the vendored Python reference implementation**: where Python 3 is
   available, `reference/python/p2mr.py` (the original file from the bips repo, unmodified) is
   run directly and every entry of both vector files is compared field by field. This is the sole
   **independent** cross-check at the construction layer.
5. **Differential against the Bitcoin Core v29.0 test framework (digest layer)**: where
   Python 3 is available, the vendored `test_framework/script.py` recomputes 28 P2MR
   script-path digests and they are compared byte for byte (see the next section).
6. **Full OP_SUCCESSx table**: all 87 opcodes are verified one by one, along with the fact
   that the same byte values inside push data are not misread.
7. **Transaction serialization**: the BIP-341 unsigned transaction and two self-built
   transactions with witnesses go through a byte-for-byte decode-to-encode round-trip, and all
   three are handed to `CTransaction` from the Core v29.0 test framework to compare the
   serialization and the txid/wtxid. Byte order needs an external cross-check -- a
   self-consistent test cannot catch a txid that is reversed as a whole.

### How the signature-hash layer is cross-checked (important)

The BIP-360 Python reference implementation **covers construction only**: `tapleaf_hash`,
`tapbranch_hash`, `compute_merkle_root`, `compute_control_block`, bech32 encoding and
decoding, and **no sighash function at all**; neither official vector file **contains any
spend or digest vector**. So there is no BIP-360 cross-check available for the digest layer.

This library uses a two-part approach instead:

- **The part with an upstream cross-check**: the 7 key-path digest vectors from the official
  BIP-341 `wallet-test-vectors.json` (at the same pinned commit) validate the generic
  `SigMsg` implementation. The BIP-342 signature-hash extension shares that same `SigMsg`, so
  the prevouts / amounts / scriptPubKeys / sequences / outputs hashes, the `spend_type`, and
  the SIGHASH_SINGLE and ANYONECANPAY branches all have an external cross-check.
- **The self-generated part**: the two inputs of that fixture are replaced with
  `OP_2 <root>` (root taken from published positive cases in `p2mr_construction.json`), and 28
  digests are generated with `ext_flag=1` / `key_version=0` / `codesep_pos=0xffffffff`. They
  live in `vectors/self_generated_p2mr_sighash.json`, which carries a `SELF-GENERATED` warning
  inside the file itself. **These expected values are produced by this library, so the file is
  a regression anchor and nothing more.** Regenerate with `npm run gen:sighash-vectors`.
- **The independently recomputed part**: `test/differential-core-sighash.test.ts` hands the
  same fixture to `TaprootSignatureHash` from the Bitcoin Core v29.0 Python test framework
  (`test/py/core_v29/`, vendored, unmodified, checksums in `vectors/SOURCE.md`) and recomputes
  the TapLeaf hash, the SigMsg and the digest of all 28 cases byte for byte with
  `scriptpath=True`. Core's function knows nothing about P2MR; it simply serializes the
  `OP_2 <root>` scriptPubKey it is handed together with the `ext_flag=1` tail -- which is
  exactly the part that needs an independent cross-check. **What it establishes is that this
  library and the Core test framework compute the same values; it does not establish that any
  node would accept these spends.**

## Ark-0 experimental signet interoperability

[`examples/ark0-spend.ts`](examples/ark0-spend.ts) performs one P2MR script-path spend on an
experimental signet with a custom challenge: the address, merkle root, control block, BIP-342
signature hash, witness stack and transaction serialization are all produced by this library,
the Schnorr signature is produced separately by `@noble/curves`, and the transaction is handed
to a Bitcoin Core node running a BIP-360 patch, which validates it and confirms it in a block.
The same script then sends a second transaction that differs only in the flipped last byte of
the signature, and the mempool rejects it with
`mempool-script-verify-flag-failed (Invalid Schnorr signature)`.

This is an interoperability check between this library and one consensus implementation, and
it is **not part of `npm test`**: it needs a running experimental chain. The node address, the
data directories and the wallet name are all read from environment variables, so no host
information is left in the repository; the demo private key travels only through an
environment variable or process memory, and is never written to a file or printed.

```bash
ARK0_SSH=user@host npx tsx examples/ark0-spend.ts run
```

What it shows is that the address, the BIP-342 digest and the witness stack computed by this
library are accepted by that patched node under its consensus rules. It does **not** show that
anything works on mainnet, and it does not show any post-quantum property -- the signature is
Schnorr over secp256k1 from beginning to end. That chain activates P2MR from height 1, whereas
the default signet and mainnet do not activate it at all, and this section has no bearing on
the official status of BIP-360.

## Wording for public claims (red lines)

The following claims **must not be used**:

- "the real bc1z"
- "the first / the only / nothing else implements it"
- anything implying "verified on a network" or "verified on chain"

Wording that is fine:

> A P2MR construction library for BIP-360 v0.12.1 (commit `620871a7`), passing all 9 cases of
> `p2mr_construction.json`; **construction and digests only, with no network validation of any
> kind**. The construction layer agrees with the Python reference implementation in the bips
> repository under differential testing; the 28 script-path digests agree byte for byte with
> the Bitcoin Core v29.0 test framework (which likewise does not amount to network validation).

## Layout

```
src/          library code
test/         tests (test/py/ref_dump.py runs the vendored Python reference implementation;
              test/py/core_v29/ is the vendored Core v29.0 test framework)
scripts/      generator for the self-generated digest vectors
vectors/      vectors (3 upstream + 1 self-generated) plus SOURCE.md checksums
reference/    the BIP-360 text and the Python reference implementation (vendored, unmodified)
```
