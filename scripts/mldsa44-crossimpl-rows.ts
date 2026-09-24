/**
 * OP_CHECKMLDSA44 script test rows signed by this library (gate G1 of the M1 design).
 *
 * Each row has the shape of a row of Bitcoin Core's `src/test/data/script_tests.json`:
 * `[[witness..., amount], scriptSig, scriptPubKey, flags, expected error, comment]`. The
 * transactions are the pair `script_json_test` builds for a row, so the same rows run through
 * Core's interpreter there and through this library's checks here. Every ML-DSA-44 signature is
 * made by @noble/post-quantum, every BIP-340 signature by @noble/curves, and every message by
 * this library; nothing is copied from Core.
 *
 * All signatures are reproducible: the deterministic variant of FIPS 204, or the hedged one with
 * fixed randomness, and BIP-340 with zero auxiliary randomness.
 */
import { schnorr } from '@noble/curves/secp256k1.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { ml_dsa44 } from '@noble/post-quantum/ml-dsa.js';
import {
  bytesToHex,
  computeTxid,
  concatBytes,
  hexToBytes,
  MLDSA44_CONTEXT,
  mldsa44Keygen,
  mldsa44MerkleRoot,
  mldsa44Sighash,
  mldsa44Sign,
  p2mrScriptPathSighash,
  SEQUENCE_FINAL,
  buildMldsa44LeafScript,
  encodeControlBlock,
  tapLeafHash,
  MLDSA44_FAIL_LEAF_SCRIPT,
} from '../src/index.js';
import type { SpentOutput, Transaction } from '../src/index.js';

export const BLOCK_HEADER = 'P2MR OP_CHECKMLDSA44 rows signed by p2mr-ts (@noble/post-quantum), cross-implementation gate G1';
export const FLAGS = 'P2SH,WITNESS,TAPROOT,P2MR,P2MR_MLDSA44';
/** The rows spend 1 satoshi, as the other P2MR rows of script_tests.json do. */
export const AMOUNT_BTC = 0.00000001;
const AMOUNT_SAT = 1n;

export type CrossImplRow = [unknown[], string, string, string, string, string];

const KEY = mldsa44Keygen(sha256(new TextEncoder().encode('p2mr-ts G1 key')));
const OTHER_KEY = mldsa44Keygen(sha256(new TextEncoder().encode('p2mr-ts G1 other key')));
const SCHNORR_SECRET = sha256(new TextEncoder().encode('p2mr-ts G1 schnorr key'));
const XONLY = schnorr.getPublicKey(SCHNORR_SECRET);
const ZERO_AUX = new Uint8Array(32);
const FIXED_RND = sha256(new TextEncoder().encode('p2mr-ts G1 hedged randomness'));

/** The scriptPubKey of the template output, written as the rows write it. */
function spkAsm(scriptPubKey: Uint8Array): string {
  return `0x52 0x20 0x${bytesToHex(scriptPubKey.subarray(2))}`;
}

/** The transaction pair `script_json_test` builds (BuildCreditingTransaction, BuildSpendingTransaction). */
export function spendingTx(scriptPubKey: Uint8Array): { tx: Transaction; spentOutputs: SpentOutput[] } {
  const credit: Transaction = {
    version: 1,
    locktime: 0,
    inputs: [{ txid: new Uint8Array(32), vout: 0xffffffff, sequence: SEQUENCE_FINAL, scriptSig: hexToBytes('0000') }],
    outputs: [{ amount: AMOUNT_SAT, scriptPubKey }],
  };
  const tx: Transaction = {
    version: 1,
    locktime: 0,
    inputs: [{ txid: computeTxid(credit), vout: 0, sequence: SEQUENCE_FINAL }],
    outputs: [{ amount: AMOUNT_SAT, scriptPubKey: new Uint8Array(0) }],
  };
  return { tx, spentOutputs: [{ amount: AMOUNT_SAT, scriptPubKey }] };
}

interface Template {
  readonly leaf: Uint8Array;
  readonly controlBlock: Uint8Array;
  readonly scriptPubKey: Uint8Array;
}

/**
 * The template output of a key, built from its parts rather than through `createMldsa44Output`,
 * whose activation gate needs a chain state these rows do not have.
 */
function template(publicKey: Uint8Array, xonly?: Uint8Array): Template {
  const leaf = buildMldsa44LeafScript(publicKey, xonly);
  const sibling = tapLeafHash(MLDSA44_FAIL_LEAF_SCRIPT, 0xc0);
  const root = mldsa44MerkleRoot(publicKey, xonly);
  return {
    leaf,
    controlBlock: encodeControlBlock(0xc0, [sibling]),
    scriptPubKey: concatBytes(Uint8Array.of(0x52, 0x20), root),
  };
}

function chunks(signature: Uint8Array): Uint8Array[] {
  const out: Uint8Array[] = [];
  for (let i = 0; i < 4; i++) out.push(signature.subarray(520 * i, 520 * (i + 1)));
  out.push(signature.subarray(2080));
  return out;
}

function row(witness: Uint8Array[], t: Template, error: string, comment: string): CrossImplRow {
  return [
    [...witness.map(bytesToHex), AMOUNT_BTC],
    '',
    spkAsm(t.scriptPubKey),
    FLAGS,
    error,
    `P2MR_MLDSA44 G1 (p2mr-ts): ${comment}`,
  ];
}

/** Append the hash type byte unless it is SIGHASH_DEFAULT. */
function withType(sig: Uint8Array, hashType: number): Uint8Array {
  return hashType === 0x00 ? sig : concatBytes(sig, Uint8Array.of(hashType));
}

export function buildRows(): CrossImplRow[] {
  const rows: CrossImplRow[] = [];
  const s1 = template(KEY.publicKey);
  const s2 = template(KEY.publicKey, XONLY);
  const s1Spend = spendingTx(s1.scriptPubKey);
  const s2Spend = spendingTx(s2.scriptPubKey);
  const m1 = (t: Template, spend: typeof s1Spend, hashType: number) =>
    mldsa44Sighash({ ...spend, inputIndex: 0, leafScript: t.leaf, hashType });
  const m0 = (t: Template, spend: typeof s1Spend, hashType: number) =>
    p2mrScriptPathSighash({ ...spend, inputIndex: 0, leafHash: tapLeafHash(t.leaf, 0xc0), hashType });
  const det = { extraEntropy: false as const };

  // Valid spends
  for (const [hashType, name] of [
    [0x00, 'SIGHASH_DEFAULT'],
    [0x02, 'explicit SIGHASH_NONE'],
    [0x03, 'explicit SIGHASH_SINGLE'],
    [0x81, 'explicit SIGHASH_ALL|SIGHASH_ANYONECANPAY'],
  ] as const) {
    const sig = withType(mldsa44Sign(KEY.secretKey, m1(s1, s1Spend, hashType), det), hashType);
    rows.push(row([...chunks(sig), s1.leaf, s1.controlBlock], s1, 'OK', `template S1, ${name}, deterministic`));
  }
  {
    const sig = mldsa44Sign(KEY.secretKey, m1(s1, s1Spend, 0x00), { extraEntropy: FIXED_RND });
    rows.push(row([...chunks(sig), s1.leaf, s1.controlBlock], s1, 'OK', 'template S1, hedged signature with fixed randomness'));
  }
  {
    const pq = mldsa44Sign(KEY.secretKey, m1(s2, s2Spend, 0x00), det);
    const bip340 = schnorr.sign(m0(s2, s2Spend, 0x00), SCHNORR_SECRET, ZERO_AUX);
    rows.push(row([bip340, ...chunks(pq), s2.leaf, s2.controlBlock], s2, 'OK', 'template S2, SIGHASH_DEFAULT for both signatures'));
  }
  {
    const pq = withType(mldsa44Sign(KEY.secretKey, m1(s2, s2Spend, 0x83), det), 0x83);
    const bip340 = withType(schnorr.sign(m0(s2, s2Spend, 0x01), SCHNORR_SECRET, ZERO_AUX), 0x01);
    rows.push(row([bip340, ...chunks(pq), s2.leaf, s2.controlBlock], s2, 'OK', 'template S2, 0x83 for ML-DSA-44 and 0x01 for BIP-340'));
  }

  // Signatures over something else than the message and context of this opcode
  const bad = (sig: Uint8Array, comment: string) =>
    rows.push(row([...chunks(sig), s1.leaf, s1.controlBlock], s1, 'MLDSA44_SIG', comment));
  bad(mldsa44Sign(KEY.secretKey, m0(s1, s1Spend, 0x00), det), 'signed over the key_version 0 message');
  bad(
    ml_dsa44.sign(m1(s1, s1Spend, 0x00), KEY.secretKey, { context: new TextEncoder().encode('P2MR/MLDSA44/EXP1'), extraEntropy: false }),
    'signed with the context string P2MR/MLDSA44/EXP1',
  );
  bad(ml_dsa44.sign(m1(s1, s1Spend, 0x00), KEY.secretKey, { extraEntropy: false }), 'signed with an empty context string');
  bad(
    ml_dsa44.prehash(sha256).sign(m1(s1, s1Spend, 0x00), KEY.secretKey, { context: MLDSA44_CONTEXT, extraEntropy: false }),
    'a HashML-DSA (SHA-256 pre-hash) signature',
  );
  bad(mldsa44Sign(OTHER_KEY.secretKey, m1(s1, s1Spend, 0x00), det), 'signed by another key');
  {
    const sig = mldsa44Sign(KEY.secretKey, m1(s1, s1Spend, 0x00), det).slice();
    sig[2419] = (sig[2419] as number) ^ 0x80;
    bad(sig, 'the last byte, in the hint encoding, altered');
  }
  {
    // the hash type byte is part of the message: signed for SIGHASH_ALL, labelled SIGHASH_NONE
    const sig = withType(mldsa44Sign(KEY.secretKey, m1(s1, s1Spend, 0x01), det), 0x02);
    bad(sig, 'signed for SIGHASH_ALL, carrying SIGHASH_NONE');
  }
  {
    const pq = mldsa44Sign(KEY.secretKey, m1(s2, s2Spend, 0x00), det);
    const bip340 = schnorr.sign(m1(s2, s2Spend, 0x00), SCHNORR_SECRET, ZERO_AUX);
    rows.push(
      row([bip340, ...chunks(pq), s2.leaf, s2.controlBlock], s2, 'SCHNORR_SIG', 'template S2, the BIP-340 signature over the key_version 1 message'),
    );
  }
  {
    const pq = mldsa44Sign(KEY.secretKey, m0(s2, s2Spend, 0x00), det);
    const bip340 = schnorr.sign(m0(s2, s2Spend, 0x00), SCHNORR_SECRET, ZERO_AUX);
    rows.push(
      row([bip340, ...chunks(pq), s2.leaf, s2.controlBlock], s2, 'MLDSA44_SIG', 'template S2, the ML-DSA-44 signature over the key_version 0 message'),
    );
  }
  return rows;
}

/** Render rows in the multi-line style of the P2MR blocks of script_tests.json. */
export function formatRows(rows: readonly CrossImplRow[]): string {
  const out = [`[${JSON.stringify(BLOCK_HEADER)}],`];
  for (const [witness, scriptSig, spk, flags, error, comment] of rows) {
    out.push('[');
    out.push('    [');
    for (const element of witness.slice(0, -1)) out.push(`        ${JSON.stringify(element)},`);
    out.push(`        ${AMOUNT_BTC.toFixed(8)}`);
    out.push('    ],');
    out.push(`    ${JSON.stringify(scriptSig)},`);
    out.push(`    ${JSON.stringify(spk)},`);
    out.push(`    ${JSON.stringify(flags)},`);
    out.push(`    ${JSON.stringify(error)},`);
    out.push(`    ${JSON.stringify(comment)}`);
    out.push('],');
  }
  return out.join('\n');
}
