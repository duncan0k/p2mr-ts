import { bech32, bech32m } from 'bech32';
import { describe, expect, it } from 'vitest';
import {
  createP2mrOutput,
  decodeP2mrAddress,
  encodeControlBlock,
  encodeP2mrAddress,
  hexToBytes,
  MAX_MERKLE_PATH_LENGTH,
  P2mrError,
  parseControlBlock,
  parseP2mrScriptPubKey,
  validateWitnessShape,
} from '../src/index.js';
import type { CreateP2mrOutputOptions, P2mrErrorCode, ScriptTreeInput } from '../src/index.js';

const LEAF_A = { script: `20${'11'.repeat(32)}ac`, leafVersion: 192 };
const LEAF_B = { script: `20${'22'.repeat(32)}ac`, leafVersion: 192 };
const TWO_LEAF: ScriptTreeInput = [LEAF_A, LEAF_B];
const ROOT = createP2mrOutput({ scriptTree: TWO_LEAF }).merkleRoot;

/** Assert that the thrown value is a P2mrError carrying the given code. */
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

describe('negative-case matrix: construction-interface constraints', () => {
  it('rejects an internal pubkey -- P2MR has no key path', () => {
    expectCode(
      () =>
        createP2mrOutput({
          scriptTree: TWO_LEAF,
          internalPubkey: 'd6889cb081036e0faefa3a35157ad71086b123b2b144b649798b494c300a961d',
        }),
      'INTERNAL_PUBKEY_NOT_SUPPORTED',
    );
  });

  it('rejects leftover BIP-341 tweak / tweakedPubkey fields', () => {
    expectCode(
      () => createP2mrOutput({ scriptTree: TWO_LEAF, tweak: '00'.repeat(32) }),
      'INTERNAL_PUBKEY_NOT_SUPPORTED',
    );
    expectCode(
      () => createP2mrOutput({ scriptTree: TWO_LEAF, tweakedPubkey: '00'.repeat(32) }),
      'INTERNAL_PUBKEY_NOT_SUPPORTED',
    );
  });

  it('the internal-pubkey check runs before the script-tree check (same shape as the official misuse vector: both problems present at once)', () => {
    expectCode(
      () => createP2mrOutput({ internalPubkey: '00'.repeat(32), scriptTree: null }),
      'INTERNAL_PUBKEY_NOT_SUPPORTED',
    );
  });

  it('rejects an empty / null / missing script tree', () => {
    expectCode(() => createP2mrOutput({ scriptTree: null }), 'SCRIPT_TREE_REQUIRED');
    expectCode(() => createP2mrOutput({ scriptTree: '' }), 'SCRIPT_TREE_REQUIRED');
    expectCode(() => createP2mrOutput({} as CreateP2mrOutputOptions), 'SCRIPT_TREE_REQUIRED');
  });

  it('rejects a single-leaf tree by default (m=0 means anyone-can-spend), allowed once the flag is set explicitly', () => {
    expectCode(() => createP2mrOutput({ scriptTree: LEAF_A }), 'SINGLE_LEAF_NOT_ALLOWED');
    const out = createP2mrOutput({ scriptTree: LEAF_A, allowUnsafeSingleLeaf: true });
    expect(out.leaves).toHaveLength(1);
    expect(out.leaves[0]!.merklePath).toHaveLength(0);
    expect(out.leaves[0]!.controlBlock).toHaveLength(1);
    expect(parseControlBlock(out.leaves[0]!.controlBlock).m).toBe(0);
  });

  it('rejects non-0xC0 leaf versions by default, allowed once the flag is set explicitly', () => {
    const tree: ScriptTreeInput = [LEAF_A, { script: '06424950333431', leafVersion: 250 }];
    expectCode(() => createP2mrOutput({ scriptTree: tree }), 'LEAF_VERSION_NOT_ALLOWED');
    const out = createP2mrOutput({ scriptTree: tree, allowUnsafeLeafVersion: true });
    expect(out.leaves[1]!.leafVersion).toBe(250);
  });

  it('rejects leaf scripts containing OP_SUCCESSx by default, allowed once the flag is set explicitly', () => {
    const tree: ScriptTreeInput = [LEAF_A, { script: `20${'33'.repeat(32)}7f`, leafVersion: 192 }];
    expectCode(() => createP2mrOutput({ scriptTree: tree }), 'OP_SUCCESS_NOT_ALLOWED');
    expect(createP2mrOutput({ scriptTree: tree, allowOpSuccess: true }).leaves).toHaveLength(2);
  });

  it('rejects invalid leaf versions: odd, 0x50, out of range', () => {
    expectCode(
      () => createP2mrOutput({ scriptTree: [LEAF_A, { script: '51', leafVersion: 0xc1 }] }),
      'INVALID_LEAF_VERSION',
    );
    expectCode(
      () => createP2mrOutput({ scriptTree: [LEAF_A, { script: '51', leafVersion: 0x50 }] }),
      'INVALID_LEAF_VERSION',
    );
    expectCode(
      () => createP2mrOutput({ scriptTree: [LEAF_A, { script: '51', leafVersion: 256 }] }),
      'INVALID_LEAF_VERSION',
    );
  });

  it('rejects empty leaf scripts and non-binary branches', () => {
    expectCode(
      () => createP2mrOutput({ scriptTree: [LEAF_A, { script: '', leafVersion: 192 }] }),
      'INVALID_LEAF_SCRIPT',
    );
    expectCode(
      () => createP2mrOutput({ scriptTree: [LEAF_A] as unknown as ScriptTreeInput }),
      'INVALID_BRANCH_ARITY',
    );
    expectCode(
      () => createP2mrOutput({ scriptTree: [LEAF_A, LEAF_B, LEAF_A] as unknown as ScriptTreeInput }),
      'INVALID_BRANCH_ARITY',
    );
  });

  it(`rejects a tree deeper than ${MAX_MERKLE_PATH_LENGTH}`, () => {
    let deep: ScriptTreeInput = LEAF_A;
    for (let i = 0; i <= MAX_MERKLE_PATH_LENGTH; i++) {
      deep = [{ script: `20${i.toString(16).padStart(2, '0').repeat(32)}ac` }, deep];
    }
    expectCode(() => createP2mrOutput({ scriptTree: deep }), 'TREE_TOO_DEEP');
  });
});

describe('negative-case matrix: control block', () => {
  it('the length must be 1 + 32m', () => {
    expectCode(() => parseControlBlock(new Uint8Array(0)), 'INVALID_CONTROL_BLOCK_LENGTH');
    expectCode(() => parseControlBlock(new Uint8Array(2)), 'INVALID_CONTROL_BLOCK_LENGTH');
    expectCode(() => parseControlBlock(new Uint8Array(34)), 'INVALID_CONTROL_BLOCK_LENGTH');
    // 33 = the P2TR base length; under P2MR that length is a wrong value outside 1 + 32*1
    expectCode(() => parseControlBlock(new Uint8Array(66)), 'INVALID_CONTROL_BLOCK_LENGTH');
  });

  it('33 bytes is a valid P2MR shape (m = 1); a P2TR-style 33 + 32m length is not', () => {
    // 33 bytes = 1 + 32*1, valid as a shape, but the low bit of the first byte still has to be 1
    const cb = new Uint8Array(33);
    cb[0] = 0xc1;
    expect(parseControlBlock(cb).m).toBe(1);
    // Whereas P2TR's 33 + 32m lands on an invalid length under P2MR
    expectCode(() => parseControlBlock(new Uint8Array(33 + 32 + 1)), 'INVALID_CONTROL_BLOCK_LENGTH');
  });

  it('a first byte whose low bit is 0 must be rejected', () => {
    const cb = new Uint8Array(33);
    cb[0] = 0xc0; // low bit 0
    expectCode(() => parseControlBlock(cb), 'INVALID_CONTROL_BLOCK_PARITY');
  });

  it(`m must not exceed ${MAX_MERKLE_PATH_LENGTH}`, () => {
    const ok = new Uint8Array(1 + 32 * MAX_MERKLE_PATH_LENGTH);
    ok[0] = 0xc1;
    expect(parseControlBlock(ok).m).toBe(MAX_MERKLE_PATH_LENGTH);
    expect(ok).toHaveLength(4097);

    const tooLong = new Uint8Array(1 + 32 * (MAX_MERKLE_PATH_LENGTH + 1));
    tooLong[0] = 0xc1;
    expectCode(() => parseControlBlock(tooLong), 'INVALID_CONTROL_BLOCK_LENGTH');

    expectCode(
      () =>
        encodeControlBlock(
          0xc0,
          Array.from({ length: MAX_MERKLE_PATH_LENGTH + 1 }, () => new Uint8Array(32)),
        ),
      'CONTROL_BLOCK_PATH_TOO_LONG',
    );
  });

  it('encoding forces the low bit of the first byte to 1; the leaf version is read back from c[0] & 0xfe', () => {
    expect(encodeControlBlock(0xc0, [])[0]).toBe(0xc1);
    expect(encodeControlBlock(0xfa, [])[0]).toBe(0xfb);
    expect(parseControlBlock(encodeControlBlock(0xfa, [])).leafVersion).toBe(0xfa);
  });
});

describe('negative-case matrix: witness stack shape', () => {
  const leafScript = hexToBytes(LEAF_A.script);
  const controlBlock = encodeControlBlock(0xc0, [new Uint8Array(32)]);
  const annex = Uint8Array.of(0x50, 0x01, 0x02);

  it('fewer than 2 elements fails', () => {
    expect(validateWitnessShape([]).valid).toBe(false);
    const r = validateWitnessShape([controlBlock]);
    expect(r.valid).toBe(false);
    expect(r.valid === false && r.code).toBe('WITNESS_TOO_FEW_ELEMENTS');
  });

  it('exactly 2 elements with the last one starting with 0x50 -> fails (P2MR has no key path)', () => {
    const r = validateWitnessShape([leafScript, annex]);
    expect(r.valid).toBe(false);
    expect(r.valid === false && r.code).toBe('WITNESS_ANNEX_WITHOUT_SCRIPT_PATH');
    expect(r.hasAnnex).toBe(true);
  });

  it('>=3 elements with the last one starting with 0x50 -> recognized as an annex', () => {
    const r = validateWitnessShape([leafScript, controlBlock, annex]);
    expect(r.valid).toBe(true);
    expect(r.hasAnnex).toBe(true);
    expect(r.valid === true && r.annex).toEqual(annex);
    expect(r.valid === true && r.parsedControlBlock.m).toBe(1);
  });

  it('an invalid control block shape -> the witness shape check fails', () => {
    const bad = new Uint8Array(34);
    bad[0] = 0xc1;
    const r = validateWitnessShape([leafScript, bad]);
    expect(r.valid).toBe(false);
    expect(r.valid === false && r.code).toBe('WITNESS_CONTROL_BLOCK_INVALID');
  });

  it('a normal 2-element witness (leaf script + control block) passes', () => {
    const r = validateWitnessShape([leafScript, controlBlock]);
    expect(r.valid).toBe(true);
    expect(r.hasAnnex).toBe(false);
    expect(r.valid === true && r.stack).toHaveLength(0);
  });
});

describe('negative-case matrix: address', () => {
  it('witness v2 with a bech32 (rather than bech32m) checksum must be rejected, with a distinguishable error', () => {
    const wrong = bech32.encode('bc', [2, ...bech32.toWords(ROOT)], 90);
    expect(wrong.startsWith('bc1z')).toBe(true);
    expectCode(() => decodeP2mrAddress(wrong), 'ADDRESS_WRONG_CHECKSUM_VARIANT');
  });

  it('a mismatched hrp is rejected', () => {
    const tb = encodeP2mrAddress(ROOT, 'testnet');
    expect(tb.startsWith('tb1z')).toBe(true);
    expectCode(() => decodeP2mrAddress(tb, { network: 'mainnet' }), 'ADDRESS_WRONG_HRP');
    const unknownHrp = bech32m.encode('xx', [2, ...bech32m.toWords(ROOT)], 90);
    expectCode(() => decodeP2mrAddress(unknownHrp), 'ADDRESS_WRONG_HRP');
  });

  it('a witness version other than 2 is rejected', () => {
    const v1 = bech32m.encode('bc', [1, ...bech32m.toWords(ROOT)], 90);
    expectCode(() => decodeP2mrAddress(v1), 'ADDRESS_WRONG_WITNESS_VERSION');
  });

  it('a witness program that is not 32 bytes is rejected', () => {
    const short = bech32m.encode('bc', [2, ...bech32m.toWords(new Uint8Array(20))], 90);
    expectCode(() => decodeP2mrAddress(short), 'ADDRESS_WRONG_PROGRAM_LENGTH');
  });

  it('a garbled address is rejected', () => {
    expectCode(() => decodeP2mrAddress('not-an-address'), 'INVALID_ADDRESS');
  });

  it('per-network prefixes: bc1z / tb1z / bcrt1z', () => {
    expect(encodeP2mrAddress(ROOT, 'mainnet').startsWith('bc1z')).toBe(true);
    expect(encodeP2mrAddress(ROOT, 'testnet').startsWith('tb1z')).toBe(true);
    expect(encodeP2mrAddress(ROOT, 'signet').startsWith('tb1z')).toBe(true);
    expect(encodeP2mrAddress(ROOT, 'regtest').startsWith('bcrt1z')).toBe(true);
    // tb covers both testnet and signet, so the address itself cannot tell them apart
    expect(decodeP2mrAddress(encodeP2mrAddress(ROOT, 'signet')).networks).toEqual([
      'testnet',
      'signet',
    ]);
  });
});

describe('negative-case matrix: scriptPubKey', () => {
  it('accepts only the 34-byte OP_2 OP_PUSHBYTES_32 shape', () => {
    expectCode(() => parseP2mrScriptPubKey(new Uint8Array(34)), 'INVALID_SCRIPT_PUBKEY');
    // The P2TR shape (OP_1) must be rejected
    const p2tr = Uint8Array.from([0x51, 0x20, ...ROOT]);
    expectCode(() => parseP2mrScriptPubKey(p2tr), 'INVALID_SCRIPT_PUBKEY');
    const ok = Uint8Array.from([0x52, 0x20, ...ROOT]);
    expect(parseP2mrScriptPubKey(ok)).toEqual(ROOT);
  });
});

describe('negative-case matrix: input format', () => {
  it('an invalid hex leaf script is rejected', () => {
    expectCode(
      () => createP2mrOutput({ scriptTree: [LEAF_A, { script: 'zz', leafVersion: 192 }] }),
      'INVALID_HEX',
    );
    expectCode(
      () => createP2mrOutput({ scriptTree: [LEAF_A, { script: 'abc', leafVersion: 192 }] }),
      'INVALID_HEX',
    );
  });

  it('a tree node that is neither a leaf nor a branch is rejected', () => {
    expectCode(
      () => createP2mrOutput({ scriptTree: [LEAF_A, { foo: 1 }] as unknown as ScriptTreeInput }),
      'INVALID_TREE_NODE',
    );
    expectCode(
      () => createP2mrOutput({ scriptTree: [LEAF_A, 42] as unknown as ScriptTreeInput }),
      'INVALID_TREE_NODE',
    );
  });
});
