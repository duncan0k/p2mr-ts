import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { schnorr } from '@noble/curves/secp256k1.js';
import { describe, expect, it } from 'vitest';
import {
  concatBytes,
  hexToBytes,
  mldsa44Sighash,
  mldsa44Verify,
  p2mrScriptPathSighash,
  parseControlBlock,
  parseMldsa44LeafScript,
  tapLeafHash,
  TRIPWIRED_LEAF_VERSION,
  tripwiredOutputMatches,
  verifyControlBlock,
} from '../src/index.js';
import { AMOUNT_BTC, spendingTx } from '../scripts/mldsa44-crossimpl-rows.js';
import { BLOCK_HEADER, buildRows, DISABLED, ENABLED, KEYS } from '../scripts/tripwire-crossimpl-rows.js';
import { findPython, runPythonJson } from './python.js';
import { REPO_ROOT } from './vectors.js';

/**
 * The tripwired leaf rows this library signs for the M3 patch series of Bitcoin Core
 * (vectors/tripwire_crossimpl_rows.json, made by scripts/generate-tripwire-crossimpl.ts). Core's
 * interpreter runs them as script tests; here every row must get the verdict of its expected error
 * from this library's own parts, with the rules of the M3 design: a leaf of version 0xe0 runs as a
 * leaf of version 0xC0 under P2MR_TRIPWIRE, and under P2MR_EC_DISABLED a signature check on a
 * 32-byte key with a non-empty signature fails in it, whatever the signature.
 */

type ScriptRow = [unknown[], string, string, string, string, string];

type Verdict = 'VALID' | 'SCHNORR_INVALID' | 'MLDSA44_INVALID' | 'EC_DISABLED' | 'NOT_EXECUTED' | 'NOT_COMMITTED' | 'OTHER_LEAF';

/** A hex field that must decode; malformed hex must fail the test, not turn into a short input. */
function hex(field: string): Uint8Array {
  expect(field.length % 2, `odd-length hex ${field.slice(0, 20)}`).toBe(0);
  expect(/^[0-9a-f]*$/i.test(field), `not hex: ${field.slice(0, 20)}`).toBe(true);
  return hexToBytes(field);
}

function scriptPubKeyOf(asm: string): Uint8Array {
  const parts = asm.split(' ');
  expect(parts.slice(0, 2)).toEqual(['0x52', '0x20']);
  const program = hex((parts[2] as string).replace(/^0x/, ''));
  expect(program.length).toBe(32);
  return concatBytes(Uint8Array.of(0x52, 0x20), program);
}

function isSchnorrLeaf(leaf: Uint8Array): boolean {
  return leaf.length === 34 && leaf[0] === 0x20 && leaf[33] === 0xac;
}

function judge(row: ScriptRow): Verdict {
  const [witnessWithAmount, scriptSig, spkAsm, flagNames] = row;
  expect(scriptSig).toBe('');
  expect(witnessWithAmount[witnessWithAmount.length - 1]).toBe(AMOUNT_BTC);
  const flags = new Set(flagNames.split(','));
  const scriptPubKey = scriptPubKeyOf(spkAsm);
  const items = (witnessWithAmount.slice(0, -1) as string[]).map(hex);
  const controlBlock = items[items.length - 1] as Uint8Array;
  const leaf = items[items.length - 2] as Uint8Array;
  const stack = items.slice(0, -2);

  if (!flags.has('P2MR')) return 'NOT_EXECUTED';
  if (!verifyControlBlock({ leafScript: leaf, controlBlock, merkleRoot: scriptPubKey.subarray(2) })) return 'NOT_COMMITTED';
  const cb = parseControlBlock(controlBlock);
  const executed =
    cb.m > 0 && (cb.leafVersion === 0xc0 || (cb.leafVersion === TRIPWIRED_LEAF_VERSION && flags.has('P2MR_TRIPWIRE')));
  if (!executed) return 'NOT_EXECUTED';
  const ecOff = cb.leafVersion === TRIPWIRED_LEAF_VERSION && flags.has('P2MR_EC_DISABLED');
  const base = { ...spendingTx(scriptPubKey), inputIndex: 0 };

  /** OP_CHECKSIG on a 32-byte key with this signature: null when it passes. */
  const checksig = (sig: Uint8Array, xonly: Uint8Array): Verdict | null => {
    expect(sig.length === 64 || sig.length === 65).toBe(true);
    if (ecOff) return 'EC_DISABLED';
    const message = p2mrScriptPathSighash({
      ...base,
      hashType: sig.length === 65 ? (sig[64] as number) : 0x00,
      leafHash: tapLeafHash(leaf, cb.leafVersion),
    });
    return schnorr.verify(sig.subarray(0, 64), message, xonly) ? null : 'SCHNORR_INVALID';
  };

  if (isSchnorrLeaf(leaf)) {
    expect(stack).toHaveLength(1);
    return checksig(stack[0] as Uint8Array, leaf.subarray(1, 33)) ?? 'VALID';
  }
  const parsed = parseMldsa44LeafScript(leaf);
  if (parsed === null) return 'OTHER_LEAF';
  expect(flags.has('P2MR_MLDSA44')).toBe(true);
  expect(stack).toHaveLength(parsed.template === 'S2' ? 6 : 5);
  const sig = concatBytes(...stack.slice(-5));
  const message = mldsa44Sighash({
    ...base,
    hashType: sig.length === 2421 ? (sig[2420] as number) : 0x00,
    leafScript: leaf,
    leafVersion: cb.leafVersion,
  });
  if (!mldsa44Verify(parsed.publicKey, message, sig.subarray(0, 2420))) return 'MLDSA44_INVALID';
  if (parsed.template === 'S2') return checksig(stack[0] as Uint8Array, parsed.xonlyPubkey as Uint8Array) ?? 'VALID';
  return 'VALID';
}

/** The verdict that agrees with each error Core's interpreter is expected to report. */
const AGREEING: Readonly<Record<string, Verdict>> = {
  OK: 'VALID',
  P2MR_EC_DISABLED: 'EC_DISABLED',
  SCHNORR_SIG: 'SCHNORR_INVALID',
  MLDSA44_SIG: 'MLDSA44_INVALID',
};

describe('tripwired leaf rows signed by this library for Core (vectors/tripwire_crossimpl_rows.json)', () => {
  const file = JSON.parse(readFileSync(resolve(REPO_ROOT, 'vectors/tripwire_crossimpl_rows.json'), 'utf8')) as unknown[][];
  const rows = file.slice(1) as ScriptRow[];

  it('are exactly what the generator produces', () => {
    expect(file[0]).toEqual([BLOCK_HEADER]);
    expect(rows).toEqual(JSON.parse(JSON.stringify(buildRows())));
  });

  it.each(rows.map((r) => [r[5], r] as const))('%s', (_comment, row) => {
    expect([ENABLED, DISABLED]).toContain(row[3]);
    const agreeing = AGREEING[row[4]];
    expect(agreeing, `no verdict for the error ${row[4]}`).toBeDefined();
    expect(judge(row)).toBe(agreeing);
  });

  it('get a real verdict on every row', () => {
    const counts: Record<string, number> = {};
    for (const row of rows) {
      const v = judge(row);
      counts[v] = (counts[v] ?? 0) + 1;
    }
    expect(counts).toEqual({ VALID: 7, EC_DISABLED: 3, SCHNORR_INVALID: 2, MLDSA44_INVALID: 2 });
  });

  it('spend the S3 output of their keys exactly where they say so', () => {
    for (const row of rows) {
      const isS3 = row[5].includes(': template S3,');
      expect(tripwiredOutputMatches({ ...KEYS, scriptPubKey: scriptPubKeyOf(row[2]) }), row[5]).toBe(isS3);
    }
    expect(rows.filter((r) => r[5].includes(': template S3,'))).toHaveLength(9);
  });

  const python = findPython();

  it.skipIf(python === null)('get the same verdicts from the BIP-360 reference implementation, the Core test framework and fips204.py', () => {
    const result = runPythonJson<{ python: string; verdicts: string[] }>(python as string, 'test/py/tripwire_rows_judge.py');
    expect(result.python.startsWith('3.')).toBe(true);
    expect(result.verdicts).toEqual(rows.map((row) => AGREEING[row[4]]));
  });
});
