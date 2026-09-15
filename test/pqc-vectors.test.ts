import { describe, expect, it } from 'vitest';
import {
  bytesToHex,
  createP2mrOutput,
  decodeP2mrAddress,
  hexToBytes,
  isOpSuccess,
  P2mrError,
  scanLeafScript,
  verifyControlBlock,
} from '../src/index.js';
import type { CreateP2mrOutputOptions } from '../src/index.js';
import { givenScriptTree, isErrorVector, loadVectorFile } from './vectors.js';

const file = loadVectorFile('p2mr_pqc_construction.json');

/**
 * The leaf scripts in the PQC vectors are `20<32 bytes>7f`, where the trailing 0x7f is
 * OP_SUCCESS127 standing in as a placeholder for "PQ signature verification". Scripts like this
 * succeed unconditionally under tapscript, carry **no consensus meaning**, and serve only to test
 * construction. Every positive case therefore has to enable allowOpSuccess explicitly.
 */
const BASE_FLAGS: Partial<CreateP2mrOutputOptions> = { allowOpSuccess: true };

const VECTOR_FLAGS: Readonly<Record<string, Partial<CreateP2mrOutputOptions>>> = {
  p2mr_single_leaf_script_tree: { ...BASE_FLAGS, allowUnsafeSingleLeaf: true },
  p2mr_different_version_leaves: { ...BASE_FLAGS, allowUnsafeLeafVersion: true },
};

describe('p2mr_pqc_construction.json (pinned commit 620871a7, construction only, no consensus meaning)', () => {
  it('7 vectors: 6 positive cases + 1 error case', () => {
    expect(file.test_vectors).toHaveLength(7);
    expect(file.test_vectors.filter(isErrorVector)).toHaveLength(1);
    expect(file.test_vectors.filter((v) => !isErrorVector(v))).toHaveLength(6);
  });

  for (const v of file.test_vectors.filter((x) => !isErrorVector(x))) {
    it(`${v.id}: root / scriptPubKey / address / control blocks`, () => {
      const flags = VECTOR_FLAGS[v.id] ?? BASE_FLAGS;
      const out = createP2mrOutput({
        ...v.given,
        ...flags,
        network: 'mainnet',
      } as CreateP2mrOutputOptions);

      expect(out.leaves.map((l) => bytesToHex(l.leafHash))).toEqual(v.intermediary?.leafHashes);
      expect(bytesToHex(out.merkleRoot)).toBe(v.intermediary?.merkleRoot);
      expect(bytesToHex(out.scriptPubKey)).toBe(v.expected?.scriptPubKey);
      expect(out.address).toBe(v.expected?.bip350Address);
      expect(out.leaves.map((l) => bytesToHex(l.controlBlock))).toEqual(
        v.expected?.scriptPathControlBlocks,
      );

      for (const leaf of out.leaves) {
        expect(
          verifyControlBlock({
            leafScript: leaf.script,
            controlBlock: leaf.controlBlock,
            merkleRoot: out.merkleRoot,
          }),
        ).toBe(true);
      }
      expect(bytesToHex(decodeP2mrAddress(out.address).merkleRoot)).toBe(
        v.intermediary?.merkleRoot,
      );
    });
  }

  it('every positive case has a leaf script containing OP_SUCCESS127; all are rejected without allowOpSuccess', () => {
    for (const v of file.test_vectors.filter((x) => !isErrorVector(x))) {
      const flags = VECTOR_FLAGS[v.id] ?? BASE_FLAGS;
      let thrown: unknown;
      try {
        createP2mrOutput({
          ...v.given,
          ...flags,
          allowOpSuccess: false,
        } as CreateP2mrOutputOptions);
      } catch (err) {
        thrown = err;
      }
      expect(thrown, v.id).toBeInstanceOf(P2mrError);
      expect((thrown as P2mrError).code, v.id).toBe('OP_SUCCESS_NOT_ALLOWED');
    }
  });

  it('the scanner decodes by opcode: bytes inside pushdata that land in the OP_SUCCESS range are not misread', () => {
    // This is a leaf script from the regular construction vectors; its 32-byte push data contains
    // bytes such as 0xfe/0xfb/0xbb that land in the OP_SUCCESS range (0xbb-0xfe), which a raw
    // byte scan would misreport
    const script = '20387671353e273264c495656e27e39ba899ea8fee3bb69fb2a680e22093447d48ac';
    const bytes = hexToBytes(script);
    const pushData = bytes.slice(1, 33);
    const decoys = [...pushData].filter(isOpSuccess);
    expect(decoys.length).toBeGreaterThan(0);
    expect(scanLeafScript(bytes).opSuccess).toBeNull();

    // Whereas the leaf script from the PQC vectors really does end with OP_SUCCESS127
    const pqc = '201f4b1febdc7dfa77c1efacc875b43317b46155e5a564decf475fc369124c5f247f';
    const hit = scanLeafScript(hexToBytes(pqc)).opSuccess;
    expect(hit?.opcode).toBe(127);
    expect(hit?.offset).toBe(33);
  });

  it('p2mr_missing_leaf_script_tree_error: rejects an empty script tree', () => {
    const v = file.test_vectors.find((x) => x.id === 'p2mr_missing_leaf_script_tree_error');
    expect(givenScriptTree(v!.given)).toBe('');
    try {
      createP2mrOutput({ ...v!.given, ...BASE_FLAGS } as CreateP2mrOutputOptions);
      expect.unreachable('should have thrown');
    } catch (err) {
      expect(err).toBeInstanceOf(P2mrError);
      expect((err as P2mrError).code).toBe('SCRIPT_TREE_REQUIRED');
    }
  });
});
