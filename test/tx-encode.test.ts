import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import {
  assembleScriptPathWitness,
  bytesToHex,
  computeTxid,
  computeWtxid,
  createP2mrOutput,
  decodeTransaction,
  encodeTransaction,
  hexToBytes,
  P2mrError,
  reverseBytes,
} from '../src/index.js';
import type { CreateP2mrOutputOptions, Transaction } from '../src/index.js';
import { findPython, runPythonJson } from './python.js';
import { loadVectorFile, REPO_ROOT } from './vectors.js';

/** The unsigned transaction from the official BIP-341 wallet vectors: 9 inputs, 2 outputs, no witness. */
const RAW_UNSIGNED: string = (
  JSON.parse(
    readFileSync(resolve(REPO_ROOT, 'vectors/bip341_wallet_test_vectors.json'), 'utf8'),
  ) as { keyPathSpending: Array<{ given: { rawUnsignedTx: string } }> }
).keyPathSpending[0]!.given.rawUnsignedTx;

const vector = loadVectorFile('p2mr_construction.json').test_vectors.find(
  (v) => v.id === 'p2mr_three_leaf_complex',
)!;
const out = createP2mrOutput({ ...vector.given } as CreateP2mrOutputOptions);
const leaf = out.leaves[1]!;

/** A placeholder signature; this library does not sign, only the serialization matters here. */
const FAKE_SIG = hexToBytes('ab'.repeat(64));
const P2MR_WITNESS = assembleScriptPathWitness({
  stack: [FAKE_SIG],
  leafScript: leaf.script,
  controlBlock: leaf.controlBlock,
});

const PREVOUT = hexToBytes('7d'.repeat(32));
const PAY_TO = hexToBytes(`5120${'3c'.repeat(32)}`);

/** A single-input P2MR script-path spend. */
const witnessTx: Transaction = {
  version: 2,
  locktime: 0,
  inputs: [{ txid: PREVOUT, vout: 1, sequence: 0xffffffff, witness: P2MR_WITNESS }],
  outputs: [{ amount: 49_990_000n, scriptPubKey: PAY_TO }],
};

/**
 * Two inputs, where the second input has an empty witness stack -- BIP-144 still requires a 0x00
 * record for it.
 */
const mixedTx: Transaction = {
  version: 2,
  locktime: 800_000,
  inputs: [
    { txid: PREVOUT, vout: 0, sequence: 0xfffffffd, witness: P2MR_WITNESS },
    {
      txid: hexToBytes('5e'.repeat(32)),
      vout: 7,
      sequence: 0xfffffffd,
      scriptSig: hexToBytes('76a914'),
      witness: [],
    },
  ],
  outputs: [{ amount: 1n, scriptPubKey: hexToBytes('6a0470326d72') }],
};

describe('transaction serialization: encodeTransaction and decodeTransaction are mutually inverse', () => {
  it('BIP-341 rawUnsignedTx: decode -> encode round-trips byte-for-byte', () => {
    const tx = decodeTransaction(hexToBytes(RAW_UNSIGNED));
    expect(tx.inputs).toHaveLength(9);
    expect(tx.outputs).toHaveLength(2);
    for (const input of tx.inputs) expect(input.witness).toBeUndefined();
    expect(bytesToHex(encodeTransaction(tx))).toBe(RAW_UNSIGNED);
    expect(bytesToHex(encodeTransaction(tx, { witness: false }))).toBe(RAW_UNSIGNED);
  });

  it('the wtxid of a witness-less transaction equals its txid (BIP-141)', () => {
    const tx = decodeTransaction(hexToBytes(RAW_UNSIGNED));
    expect(bytesToHex(computeWtxid(tx))).toBe(bytesToHex(computeTxid(tx)));
  });

  it('witness: true is rejected when there is no non-empty witness, rather than emitting bytes Core cannot parse', () => {
    const tx = decodeTransaction(hexToBytes(RAW_UNSIGNED));
    let thrown: unknown;
    try {
      encodeTransaction(tx, { witness: true });
    } catch (err) {
      thrown = err;
    }
    expect(thrown).toBeInstanceOf(P2mrError);
    expect((thrown as P2mrError).code).toBe('INVALID_TRANSACTION');
  });

  it('a transaction with a witness: encode -> decode -> encode round-trips, with the witness stack equal element by element', () => {
    const raw = encodeTransaction(witnessTx, { witness: true });
    const back = decodeTransaction(raw);

    expect(back.version).toBe(witnessTx.version);
    expect(back.locktime).toBe(witnessTx.locktime);
    expect(back.inputs).toHaveLength(1);
    expect(back.inputs[0]!.vout).toBe(1);
    expect(bytesToHex(back.inputs[0]!.txid)).toBe(bytesToHex(PREVOUT));
    expect(back.outputs[0]!.amount).toBe(49_990_000n);

    const witness = back.inputs[0]!.witness!;
    expect(witness).toHaveLength(3);
    expect(witness.map((w) => bytesToHex(w))).toEqual(P2MR_WITNESS.map((w) => bytesToHex(w)));

    expect(bytesToHex(encodeTransaction(back))).toBe(bytesToHex(raw));
  });

  it('the txid preimage carries no witness, so txid and wtxid differ', () => {
    const noWitness = bytesToHex(encodeTransaction(witnessTx, { witness: false }));
    expect(noWitness).not.toContain(bytesToHex(leaf.controlBlock));
    expect(noWitness.slice(8, 12)).not.toBe('0001');
    expect(bytesToHex(computeTxid(witnessTx))).not.toBe(bytesToHex(computeWtxid(witnessTx)));
  });

  it('an input with an empty witness serializes to a single 0x00 record and is still an empty array after the round-trip', () => {
    const raw = encodeTransaction(mixedTx, { witness: true });
    const back = decodeTransaction(raw);
    expect(back.inputs[0]!.witness).toHaveLength(3);
    expect(back.inputs[1]!.witness).toHaveLength(0);
    expect(bytesToHex(back.inputs[1]!.scriptSig!)).toBe('76a914');
    expect(bytesToHex(encodeTransaction(back))).toBe(bytesToHex(raw));
  });

  it('a transaction carrying the segwit marker but not a single witness record is rejected (Core: Superfluous witness record)', () => {
    const raw =
      '02000000' +
      '0001' +
      '01' +
      '11'.repeat(32) +
      '00000000' +
      '00' +
      'ffffffff' +
      '01' +
      'e803000000000000' +
      '16' +
      `0014${'22'.repeat(20)}` +
      '00' +
      '00000000';
    let thrown: unknown;
    try {
      decodeTransaction(hexToBytes(raw));
    } catch (err) {
      thrown = err;
    }
    expect(thrown).toBeInstanceOf(P2mrError);
    expect((thrown as P2mrError).code).toBe('INVALID_TRANSACTION');
  });
});

/**
 * Independent cross-check for serialization and txid/wtxid.
 *
 * The `CTransaction` of the Core v29.0 test framework shares no code with this library; all it does
 * is de/serialize faithfully per BIP-144 and apply double-SHA256. Byte order in particular needs an
 * external cross-check: a self-consistent test cannot catch a txid that has been reversed wholesale.
 */
interface CoreTxDump {
  framework: string;
  python: string;
  results: Array<{
    withWitness: string;
    withoutWitness: string;
    txid: string;
    wtxid: string;
    weight: number;
    vsize: number;
  }>;
}

const python = findPython();

describe('differential against the Bitcoin Core v29.0 test framework (serialization and txid/wtxid)', () => {
  it('a Python 3 interpreter is available on this machine', () => {
    if (python === null) {
      console.warn('[differential-core-tx] No Python 3 found; skipping the serialization differential comparison');
    }
    expect(python === null || typeof python === 'string').toBe(true);
  });

  describe.skipIf(python === null)('byte-for-byte comparison of three transactions', () => {
    const cases: Array<{ label: string; tx: Transaction }> = [
      { label: 'BIP-341 unsigned transaction (9 inputs, no witness)', tx: decodeTransaction(hexToBytes(RAW_UNSIGNED)) },
      { label: 'P2MR script-path spend (1 input, 3-element witness)', tx: witnessTx },
      { label: 'two inputs, one of them with an empty witness stack', tx: mixedTx },
    ];
    const dump = runPythonJson<CoreTxDump>(
      python as string,
      'test/py/core_tx_dump.py',
      JSON.stringify(cases.map((c) => bytesToHex(encodeTransaction(c.tx)))),
    );

    it('the cross-check comes from the vendored Core v29.0 test framework', () => {
      expect(dump.framework).toContain('v29.0');
      expect(dump.python.startsWith('3.')).toBe(true);
      expect(dump.results).toHaveLength(cases.length);
    });

    for (const [i, c] of cases.entries()) {
      it(`${c.label}: serialization and txid/wtxid all agree with Core`, () => {
        const ref = dump.results[i]!;
        expect(bytesToHex(encodeTransaction(c.tx))).toBe(ref.withWitness);
        expect(bytesToHex(encodeTransaction(c.tx, { witness: false }))).toBe(ref.withoutWitness);
        // Core reports hex in display order (reversed)
        expect(bytesToHex(reverseBytes(computeTxid(c.tx)))).toBe(ref.txid);
        expect(bytesToHex(reverseBytes(computeWtxid(c.tx)))).toBe(ref.wtxid);
      });
    }
  });
});
