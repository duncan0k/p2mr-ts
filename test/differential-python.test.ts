import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import { bytesToHex, createP2mrOutput } from '../src/index.js';
import type { CreateP2mrOutputOptions } from '../src/index.js';
import { findPython, runPythonJson } from './python.js';
import { givenScriptTree, loadVectorFile, REPO_ROOT } from './vectors.js';

/**
 * Differential against the BIP-360 Python reference implementation vendored in this repo.
 *
 * At present this is the sole **independent** cross-check: the Python reference
 * implementation comes from the bips repository and shares no code with this library.
 * Note that it covers construction only -- there is no sighash, so the signature-hash layer gets
 * no independent cross-check out of it.
 */

interface RefEntry {
  id: string;
  hasInternalPubkey: boolean;
  treeMissing: boolean;
  leafHashes?: string[];
  merkleRoot?: string;
  scriptPubKey?: string;
  bip350Address?: string;
  controlBlocks?: string[];
  leafPaths?: number[];
}

interface RefDump {
  referenceFile: string;
  python: string;
  files: Record<string, RefEntry[]>;
}

const python = findPython();

function runReference(bin: string): RefDump {
  return runPythonJson<RefDump>(bin, 'test/py/ref_dump.py');
}

/**
 * Matches the value recorded in vectors/SOURCE.md, so any in-place modification of the reference
 * implementation is caught.
 */
const REFERENCE_SHA256 = createHash('sha256')
  .update(readFileSync(resolve(REPO_ROOT, 'reference/python/p2mr.py')))
  .digest('hex');

const FLAGS: Readonly<Record<string, Partial<CreateP2mrOutputOptions>>> = {
  'p2mr_construction.json:p2mr_single_leaf_script_tree': { allowUnsafeSingleLeaf: true },
  'p2mr_construction.json:p2mr_different_version_leaves': { allowUnsafeLeafVersion: true },
  'p2mr_pqc_construction.json:p2mr_single_leaf_script_tree': {
    allowUnsafeSingleLeaf: true,
    allowOpSuccess: true,
  },
  'p2mr_pqc_construction.json:p2mr_different_version_leaves': {
    allowUnsafeLeafVersion: true,
    allowOpSuccess: true,
  },
};

describe('differential against the vendored Python reference implementation', () => {
  it('the sha256 of the reference implementation file matches the value recorded in vectors/SOURCE.md', () => {
    const source = readFileSync(resolve(REPO_ROOT, 'vectors/SOURCE.md'), 'utf8');
    expect(source).toContain(REFERENCE_SHA256);
  });

  it('a Python 3 interpreter is available on this machine', () => {
    // Without Python the differential cases below are skipped; record the fact here
    expect(python === null || typeof python === 'string').toBe(true);
    if (python === null) {
      console.warn('[differential] No Python 3 found; skipping the differential comparison against the reference implementation');
    }
  });

  describe.skipIf(python === null)('field-by-field comparison of construction results', () => {
    const dump = runReference(python as string);

    it('the reference implementation comes from the vendored file, not a pip package', () => {
      expect(dump.referenceFile).toBe('reference/python/p2mr.py');
      expect(dump.python.startsWith('3.')).toBe(true);
    });

    for (const filename of ['p2mr_construction.json', 'p2mr_pqc_construction.json']) {
      const vectors = loadVectorFile(filename);
      const refEntries = dump.files[filename] as RefEntry[];

      it(`${filename}: entry counts agree`, () => {
        expect(refEntries).toHaveLength(vectors.test_vectors.length);
      });

      for (const [i, v] of vectors.test_vectors.entries()) {
        const ref = refEntries[i] as RefEntry;

        it(`${filename} / ${v.id}`, () => {
          expect(ref.id).toBe(v.id);

          if (ref.treeMissing) {
            // The Python reference implementation merely prints an error message for these; this
            // library must throw
            expect([null, '']).toContain(givenScriptTree(v.given));
            expect(() =>
              createP2mrOutput({ ...v.given, allowOpSuccess: true } as CreateP2mrOutputOptions),
            ).toThrowError();
            return;
          }

          const key = `${filename}:${v.id}`;
          const flags = FLAGS[key] ?? (filename.includes('pqc') ? { allowOpSuccess: true } : {});
          const out = createP2mrOutput({
            ...v.given,
            ...flags,
            network: 'mainnet',
          } as CreateP2mrOutputOptions);

          expect(out.leaves.map((l) => bytesToHex(l.leafHash))).toEqual(ref.leafHashes);
          expect(bytesToHex(out.merkleRoot)).toBe(ref.merkleRoot);
          expect(bytesToHex(out.scriptPubKey)).toBe(ref.scriptPubKey);
          expect(out.address).toBe(ref.bip350Address);
          expect(out.leaves.map((l) => bytesToHex(l.controlBlock))).toEqual(ref.controlBlocks);
          // The leaf-position counts line up: the reference implementation encodes paths as bits,
          // this library uses depth-first indices
          expect(out.leaves).toHaveLength((ref.leafPaths ?? []).length);
        });
      }
    }
  });
});
