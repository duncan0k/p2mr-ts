# p2mr

An **offline construction library** for BIP-360 Pay-to-Merkle-Root (P2MR). TypeScript, ESM,
Node >= 20, with `@noble/hashes` and `bech32` as runtime dependencies, and `@noble/post-quantum`
for the experimental OP_CHECKMLDSA44 leaves (see below).

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
- **No BIP-340 signing, and no key storage.** It keeps no private key. The one signing
  function is for the experimental OP_CHECKMLDSA44 leaves below: it takes an ML-DSA-44
  secret key from the caller and signs with `@noble/post-quantum`.
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
| annex | rejected | `allowAnnex` | Consensus permits an annex, but the taproot **policy** in Bitcoin Core v29.0 rejects transactions carrying one -- consensus-valid is not the same as mempool-accepted. The wallet layer produces no annex by default; both witness assembly and the signature hash require the flag to be set explicitly. |
| leaf script containing `OP_SUCCESSx` | rejected | `allowOpSuccess` | Under tapscript, hitting an `OP_SUCCESSx` succeeds unconditionally. The scanner decodes by opcode and skips push data -- a raw byte scan would mistake a `0xfe` or `0xbb` inside push data for an OP_SUCCESS. |
| truncated leaf script (a push runs past the end) | rejected | `allowTruncatedScript` | The script fails to decode, so the leaf can **never** be spent. |
| leaf script with a push of more than 520 bytes | rejected | `allowOversizedPush` | BIP-342 keeps the 520-byte element limit, and Bitcoin Core checks the push size before it checks whether the branch is executed, so the leaf can **never** be spent, even with the push in an unexecuted `OP_IF` branch. |
| push-only leaf script (every opcode in `0x00`-`0x60`) | rejected | `allowPushOnlyScript` | The leaf checks no signature: it is **anyone-can-spend** if it leaves a true value (e.g. `07546170726f6f74` in the official vectors), unspendable otherwise. |

The last three checks apply to leaf version `0xC0` only: BIP-360 does not execute leaves of any
other version, which are already gated behind `allowUnsafeLeafVersion`.

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
  network: 'regtest',        // required; there is no default
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
  leafScript: out.leaves[1].script, // optional: checks leafHash and codeseparatorPosition
  // hashType defaults to SIGHASH_DEFAULT(0x00); codeseparatorPosition defaults to 0xffffffff
});

const witness = assembleScriptPathWitness({
  stack: [signature],       // this library does not sign; the caller supplies the signature
  leafScript: out.leaves[1].script,
  controlBlock: out.leaves[1].controlBlock,
  merkleRoot: out.merkleRoot, // optional: check that leaf + control block commit to this output
});
```

Notes on the signature hash:

- **Hash type and signature length** (BIP-341/342): with `SIGHASH_DEFAULT` (`0x00`) the BIP-340
  signature is 64 bytes. With any other hash type the hash type byte must be appended to the
  signature, giving **65 bytes**; a 64-byte signature always means `SIGHASH_DEFAULT`, and a
  65-byte signature ending in `0x00` is invalid. The library does not sign, so appending the byte
  is up to the caller.
- **`codeseparatorPosition`** is BIP-342's `codesep_pos`: the opcode position (not the byte
  offset) of the last `OP_CODESEPARATOR` executed before the signature opcode, or `0xffffffff`
  when none was executed. It defaults to `0xffffffff`, which is wrong for a signature checked
  after an `OP_CODESEPARATOR`. Pass `leafScript` to have it checked: the position is then
  required when the leaf contains `OP_CODESEPARATOR`, and must be `0xffffffff` or the position
  of one of them (`codeSeparatorPositions` lists them).
- **Annex**: like `assembleScriptPathWitness`, the signature hash rejects an `annex` unless
  `allowAnnex: true` is passed.

`assembleScriptPathWitness` always enforces the BIP-342 limits on the initial stack (at most
1000 elements, each at most 520 bytes); with `merkleRoot` it also checks that the leaf script and
control block recompute the output's merkle root.

`network` is required and has no default. BIP-360 is not active on mainnet or testnet: there a
witness v2 output is an unknown witness version, which BIP-141 leaves **spendable by anyone**.
Use `regtest` or a signet that activates BIP-360; `'mainnet'` and `'testnet'` remain available
only as explicit values (for example to reproduce the `bc1z` addresses of the official vectors).

Both key names `scriptTree` and `script_tree` are accepted -- the official vectors use both.

## Tests

```bash
npm install
npm run typecheck
npm test
```

Nine layers of coverage:

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
8. **OP_CHECKMLDSA44 (experimental)**: the unit tests of `src/mldsa44.ts`, and the
   cross-implementation checks against the M1 patch series of Bitcoin Core described in
   the section on OP_CHECKMLDSA44 below.
9. **Tripwired leaves (experimental)**: the unit tests of `src/tripwire.ts`, and the
   cross-checks described in the section on tripwired leaves below.

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

## Experimental: OP_CHECKMLDSA44 leaves

`OP_CHECKMLDSA44` is an experiment of the Ark-0 test signet. It is **not part of BIP-360**,
which defines no post-quantum signature check. A Bitcoin Core node with the M1 patch series
executes byte `0xf0` in a P2MR leaf as an ML-DSA-44 (FIPS 204) signature check, from an
activation height `H` fixed in its build. Everywhere else the byte keeps its meaning: it is
`OP_SUCCESS240` in tapscript. The series is `patches-m1/` in
[bitcoin-p2mr-patches](https://github.com/duncan0k/bitcoin-p2mr-patches); on the Ark-0 signet
`H` is 8600. `src/mldsa44.ts` is the wallet side:

- **Leaves**: `buildMldsa44LeafScript` makes S1
  (`<pk[0]:520> <pk[1]:520> <pk[2]:272> OP_CHECKMLDSA44`) or S2 (S1
  `OP_VERIFY <x-only key> OP_CHECKSIG`, which needs a BIP-340 signature as well), and
  `parseMldsa44LeafScript` recognizes them byte for byte, as node policy does.
- **Outputs**: `createMldsa44Output` builds for `signet` or `regtest` only (the network is
  required: on mainnet or testnet a witness v2 output is spendable by anyone) and puts the
  template leaf next to an `OP_RETURN` leaf, both
  at depth one with leaf version `0xC0`. A single leaf would be spent without executing it,
  and a second leaf of another version, or any other OP_SUCCESSx in the leaf, would let the
  output be spent without a signature. `createP2mrOutput` still refuses `0xf0` like any
  OP_SUCCESSx; only `createMldsa44Output` lifts that, for the one leaf it builds from a key.
- **Activation**: `createMldsa44Output` refuses unless the tip the wallet observed is at least
  `H + 6` (`mldsa44AddressesAllowed`). `H` is read from the node's `getdeploymentinfo`
  (`mldsa44ActivationHeight`): the later of the `p2mr` and `p2mr_mldsa44` heights, since the
  node checks the opcode only where both are active; unknown state is a refusal. Before `H`
  the leaf is an OP_SUCCESSx that anyone can spend.
- **Received outputs**: `mldsa44ProtectionStatus` counts an output as protected only when it
  commits to exactly the template tree of the wallet's keys and confirmed at or above `H`.
  Unconfirmed is pending; everything else is unprotected, at any height. Compute it again
  after a reorganization.
- **Funding**: `withMldsa44FundingLockTime` sets `nLockTime` to `H` on a funding transaction
  the wallet builds (one input must have an `nSequence` below `0xffffffff`), so that the
  transaction never confirms at or below `H`, even after a reorganization.
- **Signing**: `mldsa44Sighash` is the BIP-341 tapscript signature message with `key_version`
  1. `signMldsa44Input` signs it with pure ML-DSA-44 and the context string
  `P2MR/MLDSA44/EXP0`, hedged by default and deterministic with `extraEntropy: false`.
  `assembleMldsa44Witness` lays the signature out in five witness elements of 520, 520, 520,
  520 and 340 bytes (341 with an explicit hash type). For S2 the caller supplies the BIP-340
  signature over the same message with `key_version` 0 (`p2mrScriptPathSighash`).

`@noble/post-quantum` states that it has not been independently audited.

What is cross-checked (`test/mldsa44-crossimpl.test.ts`; the files and their checksums are in
`vectors/SOURCE.md`):

- the signature messages, byte for byte against vectors computed by the Core test framework;
- the 39 OP_CHECKMLDSA44 rows of Core's `script_tests.json`, whose ML-DSA-44 signatures were
  made by the Core test framework: on the 23 rows that execute a template leaf under the
  active rules, this library reaches the verdict of Core's interpreter (valid, invalid
  signature, wrong chunk size, wrong hash type, missing elements); the other 16 rows are
  leaves that are not templates, leaves that are not executed and scripts that are not P2MR,
  which this library refuses to treat as template spends;
- the ACVP and Wycheproof ML-DSA-44 verification vectors that Core's verifier (mldsa-native)
  passes: `@noble/post-quantum` gives the expected result on all 195;
- key generation and deterministic signatures, byte for byte against `fips204.py` of the Core
  test framework, and each side verifying the other's signatures.

This is agreement between implementations on these inputs. A template leaf protects the
spending path of its own output and nothing else: the signet's blocks are still authorized by
a classical signature, and none of this is a claim about Bitcoin.

## Experimental: tripwired leaves (version 0xe0) and the S3 template

Leaf version `0xe0`, the *tripwired leaf*, is an experiment of the Ark-0 test signet. It is
**not part of BIP-360**, nor of any other BIP. From an activation height `H3` fixed in its
build, a Bitcoin Core node with the M3 patch series runs a P2MR leaf of version `0xe0` by the
rules of a `0xC0` leaf, `OP_CHECKMLDSA44` included, except for one thing: once either of two
designated *tripwire outputs* has been spent, from the next block on, `OP_CHECKSIG`,
`OP_CHECKSIGVERIFY` and `OP_CHECKSIGADD` in these leaves fail the script whenever they meet a
32-byte key and a non-empty signature. One tripwire output is locked to the BIP-341 NUMS point
and is never meant to be spent; the other belongs to the signet's operator, who spends it in an
announced drill. Leaves of version `0xC0` are not affected at any height, and before `H3` a leaf
of version `0xe0` is not run at all: anyone can spend it.

It is an experimental implementation that follows the tripwire idea (P2XX-T) of Pieter
Wuille's mail
[Giving teeth to expected EC disabling: P2XX(-T)(-ML)](https://groups.google.com/g/bitcoindev/c/aWYtPLVPZ3U)
of 2026-06-25, with two changes: what is constrained is one experimental leaf version, and the
tripwires are two designated outputs, where the mail's trigger is any input that successfully
executes `<NUMS> OP_CHECKSIG`. Earlier work includes Anthony Towns's aRsm proof in the same
thread and Sjors Provoost's demo, [Sjors/bitcoin#121](https://github.com/Sjors/bitcoin/pull/121).
A drill on this signet does not mean that any elliptic curve key has been broken.
`src/tripwire.ts` is the wallet side:

- **Leaves**: the TapLeaf hash commits to the leaf version, so a script in a `0xe0` leaf hashes
  differently from the same script in a `0xC0` leaf, and its control block starts with `0xe1`.
  Signature messages are those of `0xC0` leaves with that TapLeaf hash: a signature made for one
  version does not verify in the other.
- **S3**: `createTripwiredOutput` builds the one template, a tree of exactly two `0xe0` leaves at
  depth one, `<x-only key> OP_CHECKSIG` and S1. Either leaf spends the output: the Schnorr leaf,
  the cheaper one, while the checks are on, and the ML-DSA-44 leaf before and after. Like
  `createMldsa44Output` it builds for `signet` or `regtest` only, and only once the tip is at
  least `H3 + 6` (`tripwiredAddressesAllowed`). `H3` is read from the node's
  `getdeploymentinfo` (`tripwireActivationHeight`: the latest of the `p2mr`, `p2mr_mldsa44` and
  `p2mr_tripwire` heights); unknown state is a refusal. No template puts both checks in one leaf,
  since once the checks are off such a leaf cannot be spent at all, and no tree has a single
  leaf, which would be spent without running it. `createP2mrOutput` still refuses leaf version
  `0xe0`, like any version other than `0xC0`.
- **Received outputs**: `tripwiredOutputMatches` holds only when an output commits to exactly
  the S3 tree of the wallet's keys. `tripwiredOutputStatus` counts such an output as constrained
  once it confirmed at or above `H3` and as pending while it is unconfirmed; everything else is
  unprotected, at any height. Compute it again after a reorganization.
- **Funding**: a funding transaction the wallet builds itself takes its lock time from
  `withMldsa44FundingLockTime(tx, H3)`.
- **Spending**: `tripwiredSighash` gives the message of either leaf (`key_version` 0 for the
  Schnorr leaf, 1 for the ML-DSA-44 leaf). The caller makes the BIP-340 signature;
  `signMldsa44Input` makes the ML-DSA-44 one when given `leafVersion: TRIPWIRED_LEAF_VERSION`.
  `assembleTripwiredWitness` builds the witness of either leaf from the two keys.

What is cross-checked (`test/tripwire.test.ts` and `test/tripwire-crossimpl.test.ts`):

- the TapLeaf hashes, merkle root, control blocks and addresses of a fixed S3 output, and the
  messages of its Schnorr leaf at both leaf versions, against the BIP-360 reference
  implementation and the Bitcoin Core v29.0 test framework;
- 14 rows in the format of Core's `script_tests.json`, signed by this library for the M3 patch
  series (`vectors/tripwire_crossimpl_rows.json`, written by
  `scripts/generate-tripwire-crossimpl.ts`): spends of S3 through either leaf with the checks on
  and off, signatures made for the other leaf version, a `0xC0` leaf with the checks off, and S2
  in a `0xe0` leaf. On every row this library reaches the expected verdict, and so does a judge
  built from the BIP-360 reference implementation, the Core v29.0 test framework and
  `fips204.py`.

This is agreement between implementations on these inputs. The drill shows how a rule that turns
the elliptic curve checks off in one kind of leaf behaves on a test network; it is not a claim
about Bitcoin.

## Wording for public claims (red lines)

The following claims **must not be used**:

- "the real bc1z"
- "the first / the only / nothing else implements it"
- anything implying "verified on a network" or "verified on chain"
- for OP_CHECKMLDSA44: "part of BIP-360", "quantum-safe Bitcoin", or a network described as
  resistant to quantum attacks
- for the tripwired leaves: "part of BIP-360" or of BIP-361, a "quantum attack drill", a
  tripwire that warns of or predicts a quantum computer, the elliptic curve paths of P2MR as a
  whole being disabled, or any elliptic curve key being broken

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
              test/py/core_v29/ is the vendored Core v29.0 test framework;
              test/py/core_m1/ holds fips204.py from the M1 patch series)
scripts/      generator for the self-generated digest vectors
vectors/      vectors (3 upstream + 1 self-generated; core_m1/ from the M1 patch series)
              plus SOURCE.md checksums
reference/    the BIP-360 text and the Python reference implementation (vendored, unmodified)
```
