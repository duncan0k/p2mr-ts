/**
 * Generate this repository's **own** regression vectors for P2MR script-path signature hashes.
 *
 * Why they have to be self-generated: the BIP-360 reference implementation
 * (bips repo, bip-0360/ref-impl/python/p2mr.py) covers construction only -- tapleaf/tapbranch
 * hashes, merkle root, control block, bech32 encoding -- and ships no sighash function at all;
 * neither official vector file contains a spend or digest vector either.
 *
 * Method: take the transaction and spent outputs from the official BIP-341 wallet vectors as a
 * fixture, replace the scriptPubKey of two of its inputs with `OP_2 <root>` (root taken from a
 * published positive case in p2mr_construction.json), then compute the digests with
 * ext_flag=1 / key_version=0 / codesep=0xffffffff.
 *
 * Net effect: the transaction and the shared part of SigMsg have an external cross-check from
 * the upstream vectors (see test/sighash.test.ts); the ext tail is recomputed independently by
 * test/differential-core-sighash.test.ts using TaprootSignatureHash from the Bitcoin Core v29.0
 * test_framework. The expected values are still produced by this library, so this file is a
 * regression anchor and nothing more; cross-implementation agreement is what that differential
 * test establishes.
 *
 * Usage: npm run gen:sighash-vectors
 */
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  bytesToHex,
  buildP2mrScriptPubKey,
  createP2mrOutput,
  decodeTransaction,
  hexToBytes,
  taprootSighash,
  taprootSigMsg,
} from '../src/index.js';
import type { CreateP2mrOutputOptions, SpentOutput } from '../src/index.js';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');

export const HASH_TYPES = [0x00, 0x01, 0x02, 0x03, 0x81, 0x82, 0x83] as const;
export const ANNEX_HEX = '50deadbeef';

/** Which fixture input indices are turned into P2MR, and the published construction vector each borrows. */
export const P2MR_INPUTS = [
  { inputIndex: 0, vectorId: 'p2mr_two_leaf_same_version', leafIndex: 0 },
  { inputIndex: 1, vectorId: 'p2mr_three_leaf_complex', leafIndex: 2 },
] as const;

export interface P2mrFixture {
  tx: ReturnType<typeof decodeTransaction>;
  spentOutputs: SpentOutput[];
  leafHashes: Map<number, Uint8Array>;
  leafScripts: Map<number, Uint8Array>;
  leafVersions: Map<number, number>;
  merkleRoots: Map<number, Uint8Array>;
}

/**
 * A mixed-input transaction derived from the official BIP-341 fixture: some inputs P2MR, the rest
 * left as they were.
 */
export function buildFixture(): P2mrFixture {
  const bip341 = JSON.parse(
    readFileSync(resolve(ROOT, 'vectors/bip341_wallet_test_vectors.json'), 'utf8'),
  ) as {
    keyPathSpending: Array<{
      given: {
        rawUnsignedTx: string;
        utxosSpent: Array<{ scriptPubKey: string; amountSats: number }>;
      };
    }>;
  };
  const construction = JSON.parse(
    readFileSync(resolve(ROOT, 'vectors/p2mr_construction.json'), 'utf8'),
  ) as { test_vectors: Array<{ id: string; given: Record<string, unknown> }> };

  const given = bip341.keyPathSpending[0]!.given;
  const tx = decodeTransaction(hexToBytes(given.rawUnsignedTx));
  const spentOutputs: SpentOutput[] = given.utxosSpent.map((u) => ({
    amount: BigInt(u.amountSats),
    scriptPubKey: hexToBytes(u.scriptPubKey),
  }));

  const leafHashes = new Map<number, Uint8Array>();
  const leafScripts = new Map<number, Uint8Array>();
  const merkleRoots = new Map<number, Uint8Array>();
  const leafVersions = new Map<number, number>();

  for (const spec of P2MR_INPUTS) {
    const v = construction.test_vectors.find((t) => t.id === spec.vectorId);
    if (!v) throw new Error(`missing construction vector ${spec.vectorId}`);
    const out = createP2mrOutput({ ...v.given } as CreateP2mrOutputOptions);
    const leaf = out.leaves[spec.leafIndex];
    if (!leaf) throw new Error(`${spec.vectorId} has no leaf at index ${spec.leafIndex}`);
    spentOutputs[spec.inputIndex] = {
      amount: spentOutputs[spec.inputIndex]!.amount,
      scriptPubKey: buildP2mrScriptPubKey(out.merkleRoot),
    };
    leafHashes.set(spec.inputIndex, leaf.leafHash);
    leafScripts.set(spec.inputIndex, leaf.script);
    leafVersions.set(spec.inputIndex, leaf.leafVersion);
    merkleRoots.set(spec.inputIndex, out.merkleRoot);
  }

  return { tx, spentOutputs, leafHashes, leafScripts, leafVersions, merkleRoots };
}

interface GeneratedCase {
  inputIndex: number;
  sourceConstructionVector: string;
  leafIndex: number;
  merkleRoot: string;
  scriptPubKey: string;
  leafHash: string;
  leafScript: string;
  leafVersion: number;
  hashType: number;
  annex: string | null;
  extFlag: 1;
  keyVersion: 0;
  codesepPos: number;
  spendType: number;
  sigMsg: string;
  sigHash: string;
}

export function generateCases(): GeneratedCase[] {
  const fx = buildFixture();
  const cases: GeneratedCase[] = [];

  for (const spec of P2MR_INPUTS) {
    const leafHash = fx.leafHashes.get(spec.inputIndex)!;
    for (const hashType of HASH_TYPES) {
      for (const annexHex of [null, ANNEX_HEX]) {
        const params = {
          tx: fx.tx,
          inputIndex: spec.inputIndex,
          spentOutputs: fx.spentOutputs,
          hashType,
          extFlag: 1 as const,
          leafHash,
          ...(annexHex === null ? {} : { annex: hexToBytes(annexHex) }),
        };
        const sigMsg = taprootSigMsg(params);
        cases.push({
          inputIndex: spec.inputIndex,
          sourceConstructionVector: spec.vectorId,
          leafIndex: spec.leafIndex,
          merkleRoot: bytesToHex(fx.merkleRoots.get(spec.inputIndex)!),
          scriptPubKey: bytesToHex(fx.spentOutputs[spec.inputIndex]!.scriptPubKey),
          leafHash: bytesToHex(leafHash),
          leafScript: bytesToHex(fx.leafScripts.get(spec.inputIndex)!),
          leafVersion: fx.leafVersions.get(spec.inputIndex)!,
          hashType,
          annex: annexHex,
          extFlag: 1,
          keyVersion: 0,
          codesepPos: 0xffffffff,
          spendType: annexHex === null ? 0x02 : 0x03,
          sigMsg: bytesToHex(sigMsg),
          sigHash: bytesToHex(taprootSighash(params)),
        });
      }
    }
  }
  return cases;
}

function main(): void {
  const cases = generateCases();
  const payload = {
    _warning:
      'SELF-GENERATED — NOT AN UPSTREAM TEST VECTOR. ' +
      'The BIP-360 reference implementation ships no sighash function, and neither official vector file contains a spend vector. ' +
      'The expected values are computed by this library and recomputed independently by test/differential-core-sighash.test.ts ' +
      'using TaprootSignatureHash from the Bitcoin Core v29.0 test_framework. That shows this library and the Core test framework ' +
      'agree on the same fixture; it does not show that any network would accept these spends.',
    _fixture:
      'Transaction and spent outputs are taken from bip-0341/wallet-test-vectors.json in the bips repo (commit 620871a7). ' +
      `The scriptPubKeys of inputs ${P2MR_INPUTS.map((s) => s.inputIndex).join(' and ')} are replaced with OP_2 <root>, ` +
      'where root comes from a published positive case in p2mr_construction.json; the remaining inputs are left untouched (mixed-input scenario).',
    _params: 'ext_flag=1, key_version=0x00, codesep_pos=0xffffffff, spend_type=2*ext_flag+annex',
    generator: 'scripts/generate-sighash-vectors.ts',
    cases,
  };
  const dest = resolve(ROOT, 'vectors/self_generated_p2mr_sighash.json');
  writeFileSync(dest, `${JSON.stringify(payload, null, 2)}\n`, 'utf8');
  console.log(`wrote ${cases.length} cases -> ${dest}`);
}

if (process.argv[1] && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url))) {
  main();
}
