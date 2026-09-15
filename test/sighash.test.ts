import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import {
  buildP2mrScriptPubKey,
  bytesToHex,
  decodeTransaction,
  hexToBytes,
  NO_CODESEPARATOR,
  P2mrError,
  p2mrScriptPathSighash,
  SIGHASH_SINGLE,
  taprootSighash,
  taprootSigMsg,
} from '../src/index.js';
import type { P2mrErrorCode, SpentOutput } from '../src/index.js';
import { buildFixture } from '../scripts/generate-sighash-vectors.js';
import { REPO_ROOT } from './vectors.js';

function expectCode(fn: () => unknown, code: P2mrErrorCode): void {
  let thrown: unknown;
  try {
    fn();
  } catch (err) {
    thrown = err;
  }
  expect(thrown, `expected to throw ${code}`).toBeInstanceOf(P2mrError);
  expect((thrown as P2mrError).code).toBe(code);
}

interface Bip341Vectors {
  keyPathSpending: Array<{
    given: {
      rawUnsignedTx: string;
      utxosSpent: Array<{ scriptPubKey: string; amountSats: number }>;
    };
    inputSpending: Array<{
      given: { txinIndex: number; hashType: number };
      intermediary: { sigMsg: string; sigHash: string };
    }>;
  }>;
}

const bip341 = JSON.parse(
  readFileSync(resolve(REPO_ROOT, 'vectors/bip341_wallet_test_vectors.json'), 'utf8'),
) as Bip341Vectors;

/**
 * Layer one: validate the generic SigMsg implementation against the official BIP-341 wallet vectors.
 *
 * These are **upstream-published** vectors with ext_flag=0 (key path). The BIP-342 signature-hash
 * extension shares the same SigMsg, so once this layer passes, the prevouts/amounts/scriptPubKeys/
 * sequences/outputs hashes, spend_type, and the SIGHASH_SINGLE and ANYONECANPAY branches all have
 * an external cross-check. What is left specific to P2MR is the trailing ext.
 */
describe('official BIP-341 wallet vectors (upstream-published, ext_flag=0)', () => {
  const group = bip341.keyPathSpending[0]!;
  const tx = decodeTransaction(hexToBytes(group.given.rawUnsignedTx));
  const spentOutputs: SpentOutput[] = group.given.utxosSpent.map((u) => ({
    amount: BigInt(u.amountSats),
    scriptPubKey: hexToBytes(u.scriptPubKey),
  }));

  it('the transaction parses correctly: 9 inputs, 2 outputs', () => {
    expect(tx.inputs).toHaveLength(9);
    expect(tx.outputs).toHaveLength(2);
    expect(spentOutputs).toHaveLength(9);
  });

  for (const s of group.inputSpending) {
    const { txinIndex, hashType } = s.given;
    it(`input ${txinIndex} / hash_type 0x${hashType.toString(16).padStart(2, '0')}: SigMsg and sigHash both agree`, () => {
      const params = { tx, inputIndex: txinIndex, spentOutputs, hashType, extFlag: 0 as const };
      expect(bytesToHex(taprootSigMsg(params))).toBe(s.intermediary.sigMsg);
      expect(bytesToHex(taprootSighash(params))).toBe(s.intermediary.sigHash);
    });
  }

  it('the sigMsg field of the official vectors already includes the leading 0x00 epoch byte', () => {
    const first = group.inputSpending[0]!;
    expect(first.intermediary.sigMsg.slice(0, 2)).toBe('00');
    // The second byte is the hash_type itself
    expect(parseInt(first.intermediary.sigMsg.slice(2, 4), 16)).toBe(first.given.hashType);
  });

  it('spend_type is 0 for a key path (ext_flag=0 and no annex)', () => {
    const msg = taprootSigMsg({
      tx,
      inputIndex: 0,
      spentOutputs,
      hashType: 0x01,
      extFlag: 0,
    });
    // 0x00 epoch | hash_type | version(4) | locktime(4) | 4*32 hashes | outputs(32) | spend_type
    expect(msg[1 + 1 + 4 + 4 + 32 * 4 + 32]).toBe(0x00);
  });
});

/**
 * Layer two: P2MR script-path digests (ext_flag=1).
 *
 * ⚠️ The expected values are **self-generated**. The BIP-360 Python reference implementation covers
 * construction only and has no sighash function at all; neither of the two official vector files
 * contains spend vectors. This layer is therefore a regression anchor and does not amount to
 * cross-implementation verification -- a genuine cross-implementation comparison has to wait for a
 * patched node or a second independent implementation.
 */
describe('P2MR script-path signature hash (ext_flag=1, self-generated vectors)', () => {
  const selfGenerated = JSON.parse(
    readFileSync(resolve(REPO_ROOT, 'vectors/self_generated_p2mr_sighash.json'), 'utf8'),
  ) as {
    _warning: string;
    cases: Array<{
      inputIndex: number;
      leafHash: string;
      scriptPubKey: string;
      hashType: number;
      annex: string | null;
      spendType: number;
      sigMsg: string;
      sigHash: string;
    }>;
  };
  const fx = buildFixture();

  it('the vector file carries its own "self-generated, not upstream" warning', () => {
    expect(selfGenerated._warning).toContain('SELF-GENERATED');
    expect(selfGenerated.cases).toHaveLength(28);
  });

  for (const c of selfGenerated.cases) {
    const label = `input ${c.inputIndex} / hash_type 0x${c.hashType.toString(16).padStart(2, '0')} / ${c.annex === null ? 'no annex' : 'with annex'}`;
    it(`${label}: the digest is stable`, () => {
      const params = {
        tx: fx.tx,
        inputIndex: c.inputIndex,
        spentOutputs: fx.spentOutputs,
        hashType: c.hashType,
        leafHash: hexToBytes(c.leafHash),
        ...(c.annex === null ? {} : { annex: hexToBytes(c.annex) }),
      };
      expect(bytesToHex(p2mrScriptPathSighash(params))).toBe(c.sigHash);
      expect(bytesToHex(taprootSigMsg({ ...params, extFlag: 1 }))).toBe(c.sigMsg);
    });
  }

  it('spend_type: 0x02 without an annex, 0x03 with one', () => {
    for (const c of selfGenerated.cases) {
      expect(c.spendType).toBe(c.annex === null ? 0x02 : 0x03);
    }
  });

  it('ext structure: the tail is exactly tapleaf_hash(32) || key_version(0x00) || codesep_pos(4, LE)', () => {
    const inputIndex = 0;
    const leafHash = fx.leafHashes.get(inputIndex)!;
    const msg = taprootSigMsg({
      tx: fx.tx,
      inputIndex,
      spentOutputs: fx.spentOutputs,
      hashType: 0x00,
      extFlag: 1,
      leafHash,
    });
    const ext = msg.slice(msg.length - 37);
    expect(bytesToHex(ext.slice(0, 32))).toBe(bytesToHex(leafHash));
    expect(ext[32]).toBe(0x00); // key_version, which is neither the witness version nor the leaf version
    expect(bytesToHex(ext.slice(33))).toBe('ffffffff'); // no OP_CODESEPARATOR executed
  });

  it('codesep_pos feeds the digest: a different position gives a different digest', () => {
    const base = {
      tx: fx.tx,
      inputIndex: 0,
      spentOutputs: fx.spentOutputs,
      leafHash: fx.leafHashes.get(0)!,
    };
    const a = p2mrScriptPathSighash(base);
    const b = p2mrScriptPathSighash({ ...base, codeseparatorPosition: 3 });
    expect(bytesToHex(a)).not.toBe(bytesToHex(b));
    expect(NO_CODESEPARATOR).toBe(0xffffffff);
  });

  it('the leaf hash feeds the digest: a different leaf in the same transaction gives a different digest', () => {
    const base = {
      tx: fx.tx,
      inputIndex: 0,
      spentOutputs: fx.spentOutputs,
      leafHash: fx.leafHashes.get(0)!,
    };
    const other = fx.leafHashes.get(1)!;
    expect(bytesToHex(p2mrScriptPathSighash(base))).not.toBe(
      bytesToHex(p2mrScriptPathSighash({ ...base, leafHash: other })),
    );
  });

  it('ext_flag feeds the digest: script path and key path differ under identical parameters', () => {
    const common = { tx: fx.tx, inputIndex: 0, spentOutputs: fx.spentOutputs, hashType: 0x00 };
    const keyPath = taprootSighash({ ...common, extFlag: 0 });
    const scriptPath = taprootSighash({
      ...common,
      extFlag: 1,
      leafHash: fx.leafHashes.get(0)!,
    });
    expect(bytesToHex(keyPath)).not.toBe(bytesToHex(scriptPath));
  });

  it('the digest commits to the actual OP_2 <root>: swap in OP_1 <root> and it changes immediately', () => {
    const inputIndex = 0;
    const root = fx.merkleRoots.get(inputIndex)!;
    expect(bytesToHex(fx.spentOutputs[inputIndex]!.scriptPubKey)).toBe(
      bytesToHex(buildP2mrScriptPubKey(root)),
    );

    const swapped = fx.spentOutputs.map((o, i) =>
      i === inputIndex ? { amount: o.amount, scriptPubKey: Uint8Array.from([0x51, 0x20, ...root]) } : o,
    );
    const real = taprootSighash({
      tx: fx.tx,
      inputIndex,
      spentOutputs: fx.spentOutputs,
      extFlag: 1,
      leafHash: fx.leafHashes.get(inputIndex)!,
    });
    const fake = taprootSighash({
      tx: fx.tx,
      inputIndex,
      spentOutputs: swapped,
      extFlag: 1,
      leafHash: fx.leafHashes.get(inputIndex)!,
    });
    expect(bytesToHex(real)).not.toBe(bytesToHex(fake));
  });

  it('without ANYONECANPAY the digest covers the scriptPubKey of every spent output, not just this input', () => {
    const inputIndex = 0;
    const tampered = fx.spentOutputs.map((o, i) =>
      i === 5 ? { amount: o.amount, scriptPubKey: Uint8Array.from([0x6a]) } : o,
    );
    const base = {
      tx: fx.tx,
      inputIndex,
      spentOutputs: fx.spentOutputs,
      leafHash: fx.leafHashes.get(inputIndex)!,
    };
    expect(bytesToHex(p2mrScriptPathSighash(base))).not.toBe(
      bytesToHex(p2mrScriptPathSighash({ ...base, spentOutputs: tampered })),
    );
    // ANYONECANPAY commits to this input alone, so changing another input has no effect
    const acp = { ...base, hashType: 0x81 };
    expect(bytesToHex(p2mrScriptPathSighash(acp))).toBe(
      bytesToHex(p2mrScriptPathSighash({ ...acp, spentOutputs: tampered })),
    );
  });

  it('the 7 hash_type values are pairwise distinct', () => {
    const base = {
      tx: fx.tx,
      inputIndex: 0,
      spentOutputs: fx.spentOutputs,
      leafHash: fx.leafHashes.get(0)!,
    };
    const hashes = [0x00, 0x01, 0x02, 0x03, 0x81, 0x82, 0x83].map((hashType) =>
      bytesToHex(p2mrScriptPathSighash({ ...base, hashType })),
    );
    expect(new Set(hashes).size).toBe(7);
  });

  it('SIGHASH_DEFAULT and SIGHASH_ALL give different digests (the hash_type byte of DEFAULT is 0x00)', () => {
    const base = {
      tx: fx.tx,
      inputIndex: 0,
      spentOutputs: fx.spentOutputs,
      leafHash: fx.leafHashes.get(0)!,
    };
    expect(bytesToHex(p2mrScriptPathSighash({ ...base, hashType: 0x00 }))).not.toBe(
      bytesToHex(p2mrScriptPathSighash({ ...base, hashType: 0x01 })),
    );
  });
});

describe('parameter validation for the signature hash', () => {
  const fx = buildFixture();
  const base = {
    tx: fx.tx,
    inputIndex: 0,
    spentOutputs: fx.spentOutputs,
    leafHash: fx.leafHashes.get(0)!,
  };

  it('rejects an invalid hash_type (including a bare 0x80)', () => {
    for (const hashType of [0x04, 0x80, 0x84, 0xff]) {
      expectCode(() => p2mrScriptPathSighash({ ...base, hashType }), 'INVALID_HASH_TYPE');
    }
  });

  it('the number of spentOutputs must match the number of inputs', () => {
    expectCode(
      () => p2mrScriptPathSighash({ ...base, spentOutputs: fx.spentOutputs.slice(0, 3) }),
      'SPENT_OUTPUTS_MISMATCH',
    );
  });

  it('the input index must be in range', () => {
    expectCode(() => p2mrScriptPathSighash({ ...base, inputIndex: 99 }), 'INVALID_INPUT_INDEX');
    expectCode(() => p2mrScriptPathSighash({ ...base, inputIndex: -1 }), 'INVALID_INPUT_INDEX');
  });

  it('SIGHASH_SINGLE requires an output at the same index', () => {
    // The fixture has only 2 outputs, so input index 4 has no matching output
    expectCode(
      () =>
        taprootSighash({
          ...base,
          inputIndex: 4,
          hashType: SIGHASH_SINGLE,
          extFlag: 0,
        }),
      'SIGHASH_SINGLE_WITHOUT_OUTPUT',
    );
  });

  it('extFlag=1 requires a 32-byte leafHash', () => {
    const { leafHash: _drop, ...noLeaf } = base;
    expectCode(() => taprootSighash({ ...noLeaf, extFlag: 1 }), 'MISSING_LEAF_HASH');
    expectCode(
      () => taprootSighash({ ...base, extFlag: 1, leafHash: new Uint8Array(31) }),
      'INVALID_LEAF_HASH',
    );
  });

  it('extFlag may only be 0 or 1: caught at runtime as well (JavaScript callers get no type protection)', () => {
    for (const bad of [2, 255, -1, 'x']) {
      expectCode(
        () => taprootSighash({ ...base, extFlag: bad as unknown as 0 | 1 }),
        'INVALID_EXT_FLAG',
      );
    }
  });

  it('the annex must start with 0x50', () => {
    expectCode(
      () => p2mrScriptPathSighash({ ...base, annex: Uint8Array.of(0x51, 0x01) }),
      'INVALID_ANNEX',
    );
    expectCode(() => p2mrScriptPathSighash({ ...base, annex: new Uint8Array(0) }), 'INVALID_ANNEX');
  });

  it('out-of-range key_version and codesep_pos are rejected', () => {
    expectCode(() => p2mrScriptPathSighash({ ...base, keyVersion: 256 }), 'INVALID_KEY_VERSION');
    expectCode(
      () => p2mrScriptPathSighash({ ...base, codeseparatorPosition: 0x1_0000_0000 }),
      'INVALID_CODESEPARATOR_POSITION',
    );
  });

  it('p2mrScriptPathSighash rejects a spent output that is not P2MR', () => {
    // Input 4 is still the original P2TR output in the fixture
    expectCode(
      () => p2mrScriptPathSighash({ ...base, inputIndex: 4 }),
      'NOT_A_P2MR_OUTPUT',
    );
    // The generic interface does not run this check and still computes a digest
    expect(
      taprootSighash({ ...base, inputIndex: 4, extFlag: 1 }),
    ).toHaveLength(32);
  });
});
