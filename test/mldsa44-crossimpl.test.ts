import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { schnorr } from '@noble/curves/secp256k1.js';
import { ml_dsa44 } from '@noble/post-quantum/ml-dsa.js';
import { describe, expect, it } from 'vitest';
import {
  bytesToHex,
  computeTxid,
  concatBytes,
  decodeTransaction,
  hexToBytes,
  MLDSA44_CONTEXT,
  mldsa44Keygen,
  mldsa44Sighash,
  mldsa44Sign,
  mldsa44Verify,
  P2mrError,
  parseControlBlock,
  parseMldsa44LeafScript,
  SEQUENCE_FINAL,
  tapLeafHash,
  taprootSighash,
} from '../src/index.js';
import type { SpentOutput, Transaction } from '../src/index.js';
import { BLOCK_HEADER, buildRows } from '../scripts/mldsa44-crossimpl-rows.js';
import { findPython, runPythonJson } from './python.js';
import { REPO_ROOT } from './vectors.js';

/**
 * Cross-implementation checks for OP_CHECKMLDSA44 (gate G1 of the M1 design), against the M1
 * patch series of Bitcoin Core:
 *
 * - signature messages: the vectors the Core test framework computed, byte for byte;
 * - the script test rows of Core, whose ML-DSA-44 signatures were made by the Core test
 *   framework's `fips204.py`: on the rows that execute a template leaf under the active rules,
 *   this library, checking with @noble/post-quantum, must reach the verdict Core's interpreter
 *   reaches; on the others it must refuse to treat the row as a template spend;
 * - the ACVP and Wycheproof verification vectors Core's verifier (mldsa-native) passes;
 * - key generation and deterministic signing, byte for byte against `fips204.py`, and each
 *   side verifying the other's signatures.
 *
 * What this establishes is agreement between implementations on these inputs. It does not
 * establish that a network enforces the rules; that takes a node (the M1 regtest run).
 */

const VENDORED: ReadonlyArray<readonly [string, string]> = [
  ['vectors/core_m1/p2mr_mldsa44_sighash.json', '8db61a06ab132f08d0f51d4681cc0f8828add178fa9ec132db13d4768747d3ca'],
  ['vectors/core_m1/mldsa44_acvp_sigver.json', 'f80a0322269a14e9031adcfaee9fcfa25588f86bdefe4243955c286f03c8e04e'],
  ['vectors/core_m1/mldsa44_wycheproof_verify.json', '664410b591441e417a32a3ec74455b59ef7725b5ebbb5e06cf821bfbb81c35ec'],
  ['vectors/core_m1/script_tests_mldsa44.json', '8631bf49eb2c85950dd8b77624108a28d8a626f28876b9bd6aa08bb3b51c62b7'],
  ['test/py/core_m1/fips204.py', '85b1a86a801179b32f527c25bae33be8f041f101bdac1e33bcaff723269175b5'],
];

function readJson<T>(path: string): T {
  return JSON.parse(readFileSync(resolve(REPO_ROOT, path), 'utf8')) as T;
}

/** A hex field that must decode; malformed hex must fail the test, not turn into a short input. */
function hex(field: string): Uint8Array {
  expect(field.length % 2, `odd-length hex ${field.slice(0, 20)}`).toBe(0);
  expect(/^[0-9a-f]*$/i.test(field), `not hex: ${field.slice(0, 20)}`).toBe(true);
  return hexToBytes(field);
}

describe('vendored M1 files', () => {
  const source = readFileSync(resolve(REPO_ROOT, 'vectors/SOURCE.md'), 'utf8');
  it.each(VENDORED)('%s matches its recorded sha256', (path, sha) => {
    const actual = createHash('sha256').update(readFileSync(resolve(REPO_ROOT, path))).digest('hex');
    expect(actual).toBe(sha);
    expect(source).toContain(sha);
  });
});

interface SighashFile {
  tx: string;
  spent_outputs: Array<{ amount: number; script_pubkey: string }>;
  cases: Array<{
    input_index: number;
    leaf_script: string;
    hash_type: number;
    annex: string | null;
    codeseparator_pos: number;
    msg_key_version_1: string | null;
    msg_key_version_0: string | null;
  }>;
}

describe('signature messages against the Core test framework', () => {
  const [, file] = readJson<[string, SighashFile]>('vectors/core_m1/p2mr_mldsa44_sighash.json');

  it('agree for every case, with key_version 1 and 0', () => {
    const tx = decodeTransaction(hex(file.tx));
    const spentOutputs: SpentOutput[] = file.spent_outputs.map((o) => ({
      amount: BigInt(o.amount),
      scriptPubKey: hex(o.script_pubkey),
    }));
    let compared = 0;
    for (const c of file.cases) {
      const leafScript = hex(c.leaf_script);
      const base = {
        tx,
        inputIndex: c.input_index,
        spentOutputs,
        hashType: c.hash_type,
        codeseparatorPosition: c.codeseparator_pos,
        ...(c.annex === null ? {} : { annex: hex(c.annex) }),
      };
      const common = { ...base, extFlag: 1 as const, leafHash: tapLeafHash(leafScript, 0xc0) };
      if (c.msg_key_version_1 === null) {
        // Core has no message for these: SIGHASH_SINGLE without an output of the same index
        expect(c.msg_key_version_0).toBeNull();
        expect(() => taprootSighash({ ...common, keyVersion: 1 })).toThrow(P2mrError);
        continue;
      }
      expect(bytesToHex(taprootSighash({ ...common, keyVersion: 1 }))).toBe(c.msg_key_version_1);
      expect(bytesToHex(taprootSighash({ ...common, keyVersion: 0 }))).toBe(c.msg_key_version_0);
      expect(bytesToHex(mldsa44Sighash({ ...base, leafScript }))).toBe(c.msg_key_version_1);
      compared += 1;
    }
    expect(compared).toBe(8);
  });
});

type ScriptRow = [unknown[], string, string, string, string, string];

/** A scriptPubKey written the way these rows write P2MR outputs: `0x52 0x20 0x<32 bytes>`. */
function p2mrScriptPubKey(asm: string): Uint8Array | null {
  const parts = asm.split(' ');
  if (parts.length !== 3 || parts[0] !== '0x52' || parts[1] !== '0x20') return null;
  const program = hex((parts[2] as string).replace(/^0x/, ''));
  return program.length === 32 ? concatBytes(Uint8Array.of(0x52, 0x20), program) : null;
}

/** The transaction pair script_json_test builds for a row (BuildCreditingTransaction and BuildSpendingTransaction). */
function spendingTx(scriptPubKey: Uint8Array, amount: bigint): { tx: Transaction; spentOutputs: SpentOutput[] } {
  const credit: Transaction = {
    version: 1,
    locktime: 0,
    inputs: [{ txid: new Uint8Array(32), vout: 0xffffffff, sequence: SEQUENCE_FINAL, scriptSig: hexToBytes('0000') }],
    outputs: [{ amount, scriptPubKey }],
  };
  const tx: Transaction = {
    version: 1,
    locktime: 0,
    inputs: [{ txid: computeTxid(credit), vout: 0, sequence: SEQUENCE_FINAL }],
    outputs: [{ amount, scriptPubKey: new Uint8Array(0) }],
  };
  return { tx, spentOutputs: [{ amount, scriptPubKey }] };
}

type Verdict =
  | 'VALID'
  | 'INVALID'
  | 'SIZE'
  | 'HASHTYPE'
  | 'STACK'
  | 'SCHNORR_INVALID'
  | 'NOT_TEMPLATE'
  | 'NOT_EXECUTED';

const EXPLICIT = new Set([0x01, 0x02, 0x03, 0x81, 0x82, 0x83]);

/**
 * What this library makes of one row, as a wallet checking a template spend would: is the leaf S1
 * or S2, are the signature chunks the fixed sizes, is the hash type valid, does the ML-DSA-44
 * signature (and for S2 the BIP-340 one) verify over the message this library computes.
 */
function judge(row: ScriptRow): Verdict {
  const [witnessWithAmount, , spkAsm, flags] = row;
  const scriptPubKey = p2mrScriptPubKey(spkAsm);
  if (scriptPubKey === null || !flags.split(',').includes('P2MR_MLDSA44')) return 'NOT_EXECUTED';
  const amountBtc = witnessWithAmount[witnessWithAmount.length - 1] as number;
  const amount = BigInt(Math.round(amountBtc * 1e8));
  let items = (witnessWithAmount.slice(0, -1) as string[]).map(hex);
  let annex: Uint8Array | undefined;
  const last = items[items.length - 1];
  if (items.length >= 2 && last !== undefined && last.length > 0 && last[0] === 0x50) {
    annex = last;
    items = items.slice(0, -1);
  }
  const controlBlock = items[items.length - 1] as Uint8Array;
  const leaf = items[items.length - 2] as Uint8Array;
  const stack = items.slice(0, -2);
  const cb = parseControlBlock(controlBlock);
  if (cb.m === 0 || cb.leafVersion !== 0xc0) return 'NOT_EXECUTED';

  // An OP_CODESEPARATOR in front of the template: the signature commits to its position, 0
  const codesep = leaf[0] === 0xab ? 0 : 0xffffffff;
  const parsed = parseMldsa44LeafScript(codesep === 0 ? leaf.subarray(1) : leaf);
  if (parsed === null) return 'NOT_TEMPLATE';
  const needed = parsed.template === 'S2' ? 6 : 5;
  if (stack.length < needed) return 'STACK';
  const chunks = stack.slice(-5);
  const sizes = chunks.map((c) => c.length);
  if (!sizes.slice(0, 4).every((s) => s === 520) || (sizes[4] !== 340 && sizes[4] !== 341)) return 'SIZE';
  const sig = concatBytes(...chunks);
  const hashType = sig.length === 2421 ? (sig[2420] as number) : 0x00;
  if (sig.length === 2421 && !EXPLICIT.has(hashType)) return 'HASHTYPE';

  const { tx, spentOutputs } = spendingTx(scriptPubKey, amount);
  const params = {
    tx,
    inputIndex: 0,
    spentOutputs,
    hashType,
    codeseparatorPosition: codesep,
    ...(annex === undefined ? {} : { annex }),
  };
  const message = mldsa44Sighash({ ...params, leafScript: leaf });
  if (!mldsa44Verify(parsed.publicKey, message, sig.subarray(0, 2420))) return 'INVALID';
  if (parsed.template === 'S2') {
    const bip340 = stack[stack.length - 6] as Uint8Array;
    const schnorrHashType = bip340.length === 65 ? (bip340[64] as number) : 0x00;
    const m0 = taprootSighash({
      ...params,
      hashType: schnorrHashType,
      extFlag: 1,
      leafHash: tapLeafHash(leaf, 0xc0),
      keyVersion: 0,
    });
    const ok = schnorr.verify(bip340.subarray(0, 64), m0, parsed.xonlyPubkey as Uint8Array);
    if (!ok) return 'SCHNORR_INVALID';
  }
  return 'VALID';
}

/** The verdicts that agree with each error Core's interpreter reports for a row. */
const AGREEING: Readonly<Record<string, readonly Verdict[]>> = {
  OK: ['VALID', 'NOT_TEMPLATE', 'NOT_EXECUTED'],
  MLDSA44_SIG: ['INVALID'],
  MLDSA44_SIG_SIZE: ['SIZE'],
  PUSH_SIZE: ['SIZE'],
  MLDSA44_SIG_HASHTYPE: ['HASHTYPE'],
  INVALID_STACK_OPERATION: ['STACK'],
  SCHNORR_SIG: ['SCHNORR_INVALID'],
  MLDSA44_PUBKEY_SIZE: ['NOT_TEMPLATE'],
  TAPSCRIPT_VALIDATION_WEIGHT: ['NOT_TEMPLATE'],
  DISCOURAGE_OP_SUCCESS: ['NOT_EXECUTED'],
  BAD_OPCODE: ['NOT_EXECUTED'],
};

describe('Core script test rows signed by the Python test framework', () => {
  const rows = readJson<ScriptRow[]>('vectors/core_m1/script_tests_mldsa44.json').filter((r) => r.length === 6);

  it('holds the 39 rows of the block', () => {
    expect(rows).toHaveLength(39);
  });

  it.each(rows.map((r) => [r[5], r] as const))('%s', (_comment, row) => {
    const verdict = judge(row);
    const agreeing = AGREEING[row[4]];
    expect(agreeing, `no verdict mapping for Core error ${row[4]}`).toBeDefined();
    expect(agreeing).toContain(verdict);
  });

  it('checks a real verdict on every template spend', () => {
    const counts: Record<string, number> = {};
    for (const row of rows) {
      const v = judge(row);
      counts[v] = (counts[v] ?? 0) + 1;
    }
    // Rows Core accepts with a non-template leaf, or without executing the opcode, are the
    // bypasses the templates exist to rule out; a wallet built on this library never makes them.
    expect(counts).toEqual({
      VALID: 6,
      INVALID: 7,
      SIZE: 5,
      HASHTYPE: 3,
      STACK: 1,
      SCHNORR_INVALID: 1,
      NOT_TEMPLATE: 8,
      NOT_EXECUTED: 8,
    });
  });
});

describe('rows signed by this library for Core (vectors/mldsa44_crossimpl_rows.json)', () => {
  const file = readJson<unknown[][]>('vectors/mldsa44_crossimpl_rows.json');
  const rows = file.slice(1) as ScriptRow[];

  it('are exactly what the generator produces', () => {
    expect(file[0]).toEqual([BLOCK_HEADER]);
    expect(rows).toEqual(JSON.parse(JSON.stringify(buildRows())));
  });

  it.each(rows.map((r) => [r[5], r] as const))('%s', (_comment, row) => {
    const agreeing = AGREEING[row[4]];
    expect(agreeing, `no verdict mapping for Core error ${row[4]}`).toBeDefined();
    expect(agreeing).toContain(judge(row));
  });

  it('are all template spends with a real verdict', () => {
    const counts: Record<string, number> = {};
    for (const row of rows) {
      const v = judge(row);
      counts[v] = (counts[v] ?? 0) + 1;
    }
    expect(counts).toEqual({ VALID: 7, INVALID: 8, SCHNORR_INVALID: 1 });
  });
});

interface AcvpRow extends Array<unknown> {
  0: string;
  1: string;
  2: string;
  3: string;
  4: boolean;
  5: string;
}

/**
 * The verification rule of Core's vector tests: a key or signature of another length is rejected
 * before verification; a context string over 255 bytes is invalid rather than an error.
 */
function nobleVerify(pk: Uint8Array, msg: Uint8Array, ctx: Uint8Array, sig: Uint8Array): boolean {
  if (pk.length !== 1312 || sig.length !== 2420) return false;
  try {
    return ml_dsa44.verify(sig, msg, pk, { context: ctx });
  } catch {
    return false;
  }
}

describe('@noble/post-quantum against the verification vectors Core passes', () => {
  it('agrees with every ACVP sigVer vector (external interface, pure ML-DSA-44)', () => {
    const rows = readJson<unknown[][]>('vectors/core_m1/mldsa44_acvp_sigver.json').filter((r) => r.length === 6) as AcvpRow[];
    expect(rows).toHaveLength(15);
    for (const r of rows) {
      expect(nobleVerify(hex(r[0]), hex(r[1]), hex(r[2]), hex(r[3])), r[5]).toBe(r[4]);
    }
  });

  it('agrees with every Wycheproof ML-DSA-44 verification test', () => {
    const groups = readJson<unknown[][]>('vectors/core_m1/mldsa44_wycheproof_verify.json').filter((g) => g.length === 2);
    let total = 0;
    let valid = 0;
    for (const [pkHex, tests] of groups as Array<[string, Array<[string, string, string, string, string]>]>) {
      const pk = hex(pkHex);
      for (const [msg, ctx, sig, result, note] of tests) {
        expect(['valid', 'invalid'], note).toContain(result);
        expect(nobleVerify(pk, hex(msg), hex(ctx), hex(sig)), note).toBe(result === 'valid');
        total += 1;
        valid += result === 'valid' ? 1 : 0;
      }
    }
    expect(total).toBe(180);
    expect(valid).toBe(77);
  });
});

const python = findPython();

interface PythonResult {
  python: string;
  keygen: Array<{ public_key: string; secret_key: string }>;
  sign: string[];
  verify: boolean[];
}

describe.skipIf(python === null)('byte for byte against fips204.py of the Core test framework', () => {
  const seeds = ['00'.repeat(32), '11'.repeat(32), 'c0ffee'.padEnd(64, '5a')];
  const messages = ['00'.repeat(32), 'e041299c889ca99b700b5a80b8f6fb0a4c4f4f1c7c1c4b1b3f2e8e6e5d3b2a19'];
  const ctx = bytesToHex(MLDSA44_CONTEXT);

  it('derives the same keys and the same deterministic signatures, and each side verifies the other', () => {
    const keys = seeds.map((s) => mldsa44Keygen(hexToBytes(s)));
    const signCases = seeds.flatMap((seed) => messages.map((message) => ({ seed, message, context: ctx })));
    const hedged = keys.map((k, i) => mldsa44Sign(k.secretKey, hexToBytes(messages[i % 2] as string)));
    const flipped = hedged.map((s) => {
      const t = s.slice();
      t[2419] = (t[2419] as number) ^ 0x01;
      return t;
    });
    const otherContext = keys.map((k, i) =>
      ml_dsa44.sign(hexToBytes(messages[i % 2] as string), k.secretKey, {
        context: new TextEncoder().encode('P2MR/MLDSA44/EXP1'),
      }),
    );
    const verifyCases = [
      ...hedged.map((sig, i) => ({ i, sig, expected: true })),
      ...flipped.map((sig, i) => ({ i, sig, expected: false })),
      ...otherContext.map((sig, i) => ({ i, sig, expected: false })),
    ];

    const result = runPythonJson<PythonResult>(
      python as string,
      'test/py/mldsa44_dump.py',
      JSON.stringify({
        keygen: seeds,
        sign: signCases,
        verify: verifyCases.map(({ i, sig }) => ({
          public_key: bytesToHex((keys[i] as { publicKey: Uint8Array }).publicKey),
          message: messages[i % 2],
          signature: bytesToHex(sig),
          context: ctx,
        })),
      }),
    );

    keys.forEach((k, i) => {
      expect(result.keygen[i]?.public_key).toBe(bytesToHex(k.publicKey));
      expect(result.keygen[i]?.secret_key).toBe(bytesToHex(k.secretKey));
    });
    signCases.forEach((c, i) => {
      const key = mldsa44Keygen(hexToBytes(c.seed));
      const mine = mldsa44Sign(key.secretKey, hexToBytes(c.message), { extraEntropy: false });
      expect(result.sign[i]).toBe(bytesToHex(mine));
      expect(mldsa44Verify(key.publicKey, hexToBytes(c.message), hexToBytes(result.sign[i] as string))).toBe(true);
    });
    expect(result.verify).toEqual(verifyCases.map((c) => c.expected));
  });
});
