import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

export const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');

/** Vectors are pinned to this commit; README and vectors/SOURCE.md record the same value. */
export const BIPS_COMMIT = '620871a7a442e276a058b487cd8743775fb499a4';

export interface VectorIntermediary {
  readonly leafHashes?: readonly string[];
  readonly merkleRoot?: string | null;
  readonly tweak?: string;
  readonly tweakedPubkey?: string;
}

export interface VectorExpected {
  readonly scriptPubKey?: string;
  readonly bip350Address?: string;
  readonly scriptPathControlBlocks?: readonly string[];
  readonly error?: string;
}

export interface ConstructionVector {
  readonly id: string;
  readonly objective: string;
  readonly given: Record<string, unknown>;
  readonly intermediary?: VectorIntermediary;
  readonly expected?: VectorExpected;
}

export interface VectorFile {
  readonly version: number;
  readonly test_vectors: readonly ConstructionVector[];
}

export function loadVectorFile(filename: string): VectorFile {
  return JSON.parse(readFileSync(resolve(REPO_ROOT, 'vectors', filename), 'utf8')) as VectorFile;
}

/**
 * Pull out the script tree.
 *
 * The official vectors use both the `scriptTree` and `script_tree` namings, so accept either.
 */
export function givenScriptTree(given: Record<string, unknown>): unknown {
  return 'scriptTree' in given ? given['scriptTree'] : given['script_tree'];
}

/**
 * Decide whether a vector is an error case.
 *
 * Only `expected.error` may be consulted. Note that the `expected` of
 * `p2mr_misuse_v2_witness_version_with_pubkey_error` carries both `error` and `scriptPubKey` -- that
 * scriptPubKey is a leftover BIP-341 tweaked pubkey and must never be taken for a correct output.
 */
export function isErrorVector(v: ConstructionVector): boolean {
  return typeof v.expected?.error === 'string' && v.expected.error.length > 0;
}
