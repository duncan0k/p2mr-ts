import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import { findPython, runPythonJson } from './python.js';
import { REPO_ROOT } from './vectors.js';

/**
 * Independent cross-check at the digest layer: recompute the 28 P2MR script-path
 * digests with the Bitcoin Core v29.0 Python test framework.
 *
 * The BIP-360 reference implementation has no sighash and the official vectors carry no
 * spend vectors, so the expected values in `vectors/self_generated_p2mr_sighash.json` can
 * only be produced by this library. Core's `TaprootSignatureMsg` shares no code with this
 * library and knows nothing about P2MR; it merely serializes the given `OP_2 <root>`
 * scriptPubKey faithfully and appends the BIP-342 ext when scriptpath=True -- precisely the
 * part that has no upstream vector.
 *
 * What it establishes is "this library and the Core test framework agree on the same fixture";
 * it does not establish that any network would accept these spends.
 */

interface CoreDump {
  framework: string;
  python: string;
  replacedInputs: number[];
  results: Array<{ leafHash: string; sigMsg: string; sigHash: string }>;
}

interface SelfGenerated {
  _warning: string;
  cases: Array<{
    inputIndex: number;
    hashType: number;
    annex: string | null;
    leafHash: string;
    leafScript: string;
    leafVersion: number;
    sigMsg: string;
    sigHash: string;
  }>;
}

/**
 * The vendored Core files must match the checksums recorded in vectors/SOURCE.md, so any in-place
 * modification is caught.
 */
const VENDORED_CORE_FILES = [
  'test/py/core_v29/test_framework/script.py',
  'test/py/core_v29/test_framework/messages.py',
  'test/py/core_v29/test_framework/key.py',
  'test/py/core_v29/test_framework/crypto/siphash.py',
  'test/py/core_v29/test_framework/crypto/ripemd160.py',
  'test/py/core_v29/test_framework/crypto/secp256k1.py',
];

const python = findPython();

describe('differential against the Bitcoin Core v29.0 test framework (P2MR script-path digests)', () => {
  const source = readFileSync(resolve(REPO_ROOT, 'vectors/SOURCE.md'), 'utf8');
  const vectors = JSON.parse(
    readFileSync(resolve(REPO_ROOT, 'vectors/self_generated_p2mr_sighash.json'), 'utf8'),
  ) as SelfGenerated;

  for (const rel of VENDORED_CORE_FILES) {
    it(`the sha256 of ${rel} matches the value recorded in vectors/SOURCE.md`, () => {
      const digest = createHash('sha256').update(readFileSync(resolve(REPO_ROOT, rel))).digest('hex');
      expect(source).toContain(digest);
    });
  }

  it('a Python 3 interpreter is available on this machine', () => {
    if (python === null) {
      console.warn('[differential-core] No Python 3 found; skipping the differential comparison against the Core test framework');
    }
    expect(python === null || typeof python === 'string').toBe(true);
  });

  describe.skipIf(python === null)('byte-for-byte comparison of 28 digests', () => {
    const dump = runPythonJson<CoreDump>(python as string, 'test/py/core_sighash_dump.py');

    it('the cross-check comes from the vendored Core v29.0 test framework', () => {
      expect(dump.framework).toContain('v29.0');
      expect(dump.python.startsWith('3.')).toBe(true);
      expect(dump.replacedInputs).toEqual([0, 1]);
      expect(dump.results).toHaveLength(vectors.cases.length);
      expect(vectors.cases).toHaveLength(28);
    });

    for (const [i, c] of vectors.cases.entries()) {
      const label = `input ${c.inputIndex} / hash_type 0x${c.hashType.toString(16).padStart(2, '0')} / ${c.annex === null ? 'no annex' : 'with annex'}`;
      it(`${label}: TapLeaf hash, SigMsg and digest all agree with Core`, () => {
        const ref = dump.results[i]!;
        expect(ref.leafHash).toBe(c.leafHash);
        expect(ref.sigMsg).toBe(c.sigMsg);
        expect(ref.sigHash).toBe(c.sigHash);
      });
    }
  });
});
