import { describe, expect, it } from 'vitest';
import {
  assembleScriptPathWitness,
  bytesToHex,
  createP2mrOutput,
  hexToBytes,
  P2mrError,
  parseControlBlock,
  validateWitnessShape,
  verifyControlBlock,
} from '../src/index.js';
import type { CreateP2mrOutputOptions } from '../src/index.js';
import { loadVectorFile } from './vectors.js';

const vector = loadVectorFile('p2mr_construction.json').test_vectors.find(
  (v) => v.id === 'p2mr_three_leaf_complex',
);
const out = createP2mrOutput({ ...vector!.given } as CreateP2mrOutputOptions);

/** A placeholder signature; this library does not sign, it only assembles. */
const FAKE_SIG = hexToBytes(`${'ab'.repeat(64)}`);

describe('script-path witness stack assembly', () => {
  it('the order is [stack elements..., leaf script, control block]', () => {
    const leaf = out.leaves[1]!;
    const witness = assembleScriptPathWitness({
      stack: [FAKE_SIG],
      leafScript: leaf.script,
      controlBlock: leaf.controlBlock,
    });
    expect(witness).toHaveLength(3);
    expect(bytesToHex(witness[0]!)).toBe(bytesToHex(FAKE_SIG));
    expect(bytesToHex(witness[1]!)).toBe(bytesToHex(leaf.script));
    expect(bytesToHex(witness[2]!)).toBe(bytesToHex(leaf.controlBlock));
  });

  it('an annex is rejected by default (Core policy does not accept transactions carrying an annex); allowAnnex must be explicit', () => {
    const leaf = out.leaves[0]!;
    let thrown: unknown;
    try {
      assembleScriptPathWitness({
        leafScript: leaf.script,
        controlBlock: leaf.controlBlock,
        annex: hexToBytes('50c0ffee'),
      });
    } catch (err) {
      thrown = err;
    }
    expect(thrown).toBeInstanceOf(P2mrError);
    expect((thrown as P2mrError).code).toBe('ANNEX_NOT_ALLOWED');
  });

  it('with allowAnnex set explicitly the annex is appended as the last element, and its first byte must be 0x50', () => {
    const leaf = out.leaves[0]!;
    const annex = hexToBytes('50c0ffee');
    const witness = assembleScriptPathWitness({
      stack: [FAKE_SIG],
      leafScript: leaf.script,
      controlBlock: leaf.controlBlock,
      annex,
      allowAnnex: true,
    });
    expect(witness).toHaveLength(4);
    expect(bytesToHex(witness[3]!)).toBe('50c0ffee');

    expect(() =>
      assembleScriptPathWitness({
        leafScript: leaf.script,
        controlBlock: leaf.controlBlock,
        annex: hexToBytes('51c0ffee'),
        allowAnnex: true,
      }),
    ).toThrowError(P2mrError);
  });

  it('a malformed control block is blocked at assembly time', () => {
    expect(() =>
      assembleScriptPathWitness({
        leafScript: out.leaves[0]!.script,
        controlBlock: new Uint8Array(34),
      }),
    ).toThrowError(P2mrError);
  });

  it('an assembled witness stack is taken apart by validateWitnessShape into the same pieces', () => {
    for (const leaf of out.leaves) {
      const witness = assembleScriptPathWitness({
        stack: [FAKE_SIG],
        leafScript: leaf.script,
        controlBlock: leaf.controlBlock,
      });
      const shape = validateWitnessShape(witness);
      expect(shape.valid).toBe(true);
      if (!shape.valid) return;

      expect(bytesToHex(shape.leafScript)).toBe(bytesToHex(leaf.script));
      expect(bytesToHex(shape.controlBlock)).toBe(bytesToHex(leaf.controlBlock));
      expect(shape.stack).toHaveLength(1);
      expect(shape.hasAnnex).toBe(false);
      expect(shape.parsedControlBlock.m).toBe(leaf.merklePath.length);
      expect(shape.parsedControlBlock.leafVersion).toBe(leaf.leafVersion);
      expect(shape.parsedControlBlock.parityBit).toBe(1);

      // The witness stack alone is enough to recompute the root in the scriptPubKey
      expect(
        verifyControlBlock({
          leafScript: shape.leafScript,
          controlBlock: shape.controlBlock,
          merkleRoot: out.merkleRoot,
        }),
      ).toBe(true);
    }
  });

  it('witness stack with an annex: with >=3 elements the annex is stripped correctly', () => {
    const leaf = out.leaves[2]!;
    const witness = assembleScriptPathWitness({
      stack: [FAKE_SIG],
      leafScript: leaf.script,
      controlBlock: leaf.controlBlock,
      annex: hexToBytes('5001020304'),
      allowAnnex: true,
    });
    const shape = validateWitnessShape(witness);
    expect(shape.valid).toBe(true);
    if (!shape.valid) return;
    expect(shape.hasAnnex).toBe(true);
    expect(bytesToHex(shape.annex!)).toBe('5001020304');
    expect(bytesToHex(shape.controlBlock)).toBe(bytesToHex(leaf.controlBlock));
  });

  it('m=0 (single leaf) witness stack: the control block is a single byte', () => {
    const single = createP2mrOutput({
      scriptTree: { script: `20${'11'.repeat(32)}ac`, leafVersion: 192 },
      allowUnsafeSingleLeaf: true,
    });
    const leaf = single.leaves[0]!;
    const witness = assembleScriptPathWitness({
      leafScript: leaf.script,
      controlBlock: leaf.controlBlock,
    });
    expect(witness).toHaveLength(2);
    expect(witness[1]).toHaveLength(1);
    expect(parseControlBlock(witness[1]!).m).toBe(0);

    const shape = validateWitnessShape(witness);
    expect(shape.valid).toBe(true);
    // With m=0 the root is the leaf hash: BIP-360 says the spend succeeds as soon as the root
    // matches, regardless of whether the script itself runs
    expect(bytesToHex(single.merkleRoot)).toBe(bytesToHex(leaf.leafHash));
  });
});
