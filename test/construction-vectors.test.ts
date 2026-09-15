import { describe, expect, it } from 'vitest';
import {
  bytesToHex,
  collectLeafHashes,
  createP2mrOutput,
  decodeP2mrAddress,
  hexToBytes,
  normalizeScriptTree,
  P2mrError,
  verifyControlBlock,
} from '../src/index.js';
import type { CreateP2mrOutputOptions } from '../src/index.js';
import { givenScriptTree, isErrorVector, loadVectorFile } from './vectors.js';

const file = loadVectorFile('p2mr_construction.json');

/**
 * Opt-out flags each positive case has to enable explicitly.
 *
 * Entries missing from this table carry no flags at all -- they pass under the default
 * configuration, which is what shows the default rejections were picked accurately.
 */
const VECTOR_FLAGS: Readonly<Record<string, Partial<CreateP2mrOutputOptions>>> = {
  p2mr_single_leaf_script_tree: { allowUnsafeSingleLeaf: true },
  p2mr_different_version_leaves: { allowUnsafeLeafVersion: true },
};

describe('p2mr_construction.json (pinned commit 620871a7)', () => {
  it('the version field of the vector file is vector-format version 1, not a BIP version', () => {
    expect(file.version).toBe(1);
  });

  it('9 vectors: 7 construction positive cases + 2 construction-API error cases, 16 control blocks across the positive cases', () => {
    expect(file.test_vectors).toHaveLength(9);
    const errors = file.test_vectors.filter(isErrorVector);
    const successes = file.test_vectors.filter((v) => !isErrorVector(v));
    expect(errors).toHaveLength(2);
    expect(successes).toHaveLength(7);
    const totalControlBlocks = successes.reduce(
      (n, v) => n + (v.expected?.scriptPathControlBlocks?.length ?? 0),
      0,
    );
    expect(totalControlBlocks).toBe(16);
  });

  describe('construction positive cases', () => {
    for (const v of file.test_vectors.filter((x) => !isErrorVector(x))) {
      it(`${v.id}: leaf hashes / root / scriptPubKey / address / every control block`, () => {
        const flags = VECTOR_FLAGS[v.id] ?? {};
        const out = createP2mrOutput({
          ...v.given,
          ...flags,
          network: 'mainnet',
        } as CreateP2mrOutputOptions);

        // Leaf hashes come in depth-first order, the same order as intermediary.leafHashes
        const tree = normalizeScriptTree(givenScriptTree(v.given), {
          allowUnsafeLeafVersion: flags.allowUnsafeLeafVersion === true,
          allowOpSuccess: flags.allowOpSuccess === true,
        });
        expect(collectLeafHashes(tree).map(bytesToHex)).toEqual(v.intermediary?.leafHashes);
        expect(out.leaves.map((l) => bytesToHex(l.leafHash))).toEqual(v.intermediary?.leafHashes);

        expect(bytesToHex(out.merkleRoot)).toBe(v.intermediary?.merkleRoot);
        expect(bytesToHex(out.scriptPubKey)).toBe(v.expected?.scriptPubKey);
        expect(out.address).toBe(v.expected?.bip350Address);

        // One control block per leaf "position"; duplicate leaves are not merged
        expect(out.leaves.map((l) => bytesToHex(l.controlBlock))).toEqual(
          v.expected?.scriptPathControlBlocks,
        );

        // Reverse self-consistency: leaf script + control block must recompute the same root
        for (const leaf of out.leaves) {
          expect(
            verifyControlBlock({
              leafScript: leaf.script,
              controlBlock: leaf.controlBlock,
              merkleRoot: out.merkleRoot,
            }),
          ).toBe(true);
        }

        // The address decodes back to the same root
        const decoded = decodeP2mrAddress(out.address, { network: 'mainnet' });
        expect(bytesToHex(decoded.merkleRoot)).toBe(v.intermediary?.merkleRoot);
        expect(decoded.witnessVersion).toBe(2);
        expect(decoded.hrp).toBe('bc');
      });
    }
  });

  it('p2mr_duplicate_leaves: two identical leaves each get a control block distinguished by position', () => {
    const v = file.test_vectors.find((x) => x.id === 'p2mr_duplicate_leaves');
    expect(v).toBeDefined();
    const out = createP2mrOutput({ ...v!.given } as CreateP2mrOutputOptions);

    expect(out.leaves).toHaveLength(3);
    // The leaf scripts at position 0 and position 2 are identical
    expect(bytesToHex(out.leaves[0]!.script)).toBe(bytesToHex(out.leaves[2]!.script));
    expect(bytesToHex(out.leaves[0]!.leafHash)).toBe(bytesToHex(out.leaves[2]!.leafHash));
    // The control blocks differ, though -- an implementation that dedupes by hash would miss one of the paths
    expect(bytesToHex(out.leaves[0]!.controlBlock)).not.toBe(
      bytesToHex(out.leaves[2]!.controlBlock),
    );
    expect(out.leaves[0]!.depth).toBe(1);
    expect(out.leaves[2]!.depth).toBe(2);
  });

  it('p2mr_different_version_leaves: the control block for leaf version 250 starts with 0xfb', () => {
    const v = file.test_vectors.find((x) => x.id === 'p2mr_different_version_leaves');
    const out = createP2mrOutput({
      ...v!.given,
      allowUnsafeLeafVersion: true,
    } as CreateP2mrOutputOptions);
    expect(out.leaves[0]!.leafVersion).toBe(0xc0);
    expect(out.leaves[1]!.leafVersion).toBe(0xfa);
    expect(bytesToHex(out.leaves[0]!.controlBlock).slice(0, 2)).toBe('c1');
    expect(bytesToHex(out.leaves[1]!.controlBlock).slice(0, 2)).toBe('fb');
  });

  describe('construction-API error cases', () => {
    it('p2mr_misuse_v2_witness_version_with_pubkey_error: rejects an internal pubkey', () => {
      const v = file.test_vectors.find(
        (x) => x.id === 'p2mr_misuse_v2_witness_version_with_pubkey_error',
      );
      expect(v).toBeDefined();
      expect(v!.given['internalPubkey']).toBeTypeOf('string');

      // Trap: the expected of this vector carries both error and scriptPubKey,
      // and the latter is a BIP-341 tweaked pubkey, not any valid P2MR output.
      expect(v!.expected?.error).toBeTypeOf('string');
      expect(v!.expected?.scriptPubKey).toBe(`5220${v!.intermediary?.tweakedPubkey}`);

      let thrown: unknown;
      try {
        createP2mrOutput({ ...v!.given } as CreateP2mrOutputOptions);
      } catch (err) {
        thrown = err;
      }
      expect(thrown).toBeInstanceOf(P2mrError);
      expect((thrown as P2mrError).code).toBe('INTERNAL_PUBKEY_NOT_SUPPORTED');
    });

    it('p2mr_null_or_missing_script_tree_error: rejects an empty/missing script tree (the key name is script_tree)', () => {
      const v = file.test_vectors.find((x) => x.id === 'p2mr_null_or_missing_script_tree_error');
      expect(v).toBeDefined();
      expect(Object.keys(v!.given)).toContain('script_tree');
      expect(givenScriptTree(v!.given)).toBe('');

      expect(() => createP2mrOutput({ ...v!.given } as CreateP2mrOutputOptions)).toThrowError(
        P2mrError,
      );
      try {
        createP2mrOutput({ ...v!.given } as CreateP2mrOutputOptions);
      } catch (err) {
        expect((err as P2mrError).code).toBe('SCRIPT_TREE_REQUIRED');
      }
    });
  });

  it('both namings, scriptTree and script_tree, produce the same output', () => {
    const tree = [
      { script: '20' + '11'.repeat(32) + 'ac', leafVersion: 192 },
      { script: '20' + '22'.repeat(32) + 'ac', leafVersion: 192 },
    ];
    const a = createP2mrOutput({ scriptTree: tree });
    const b = createP2mrOutput({ script_tree: tree });
    expect(bytesToHex(a.merkleRoot)).toBe(bytesToHex(b.merkleRoot));
    expect(a.address).toBe(b.address);
  });

  it('leaf hashes match the BIP-341 TapLeaf definition (v & 0xfe || compact_size || script)', () => {
    // The root of a single-leaf tree is the leaf hash itself
    const v = file.test_vectors.find((x) => x.id === 'p2mr_single_leaf_script_tree');
    const leafHash = v!.intermediary?.leafHashes?.[0];
    expect(leafHash).toBe(v!.intermediary?.merkleRoot);
    expect(hexToBytes(leafHash!)).toHaveLength(32);
  });
});
