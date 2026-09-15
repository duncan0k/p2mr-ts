import { sha256 } from '@noble/hashes/sha2.js';
import { utf8ToBytes } from '@noble/hashes/utils.js';
import { compareBytes, concatBytes, serializeVarBytes } from './bytes.js';
import { assert } from './errors.js';

/** Cache of BIP-340 tagged hash tag prefixes: sha256(tag) || sha256(tag). */
const tagPrefixCache = new Map<string, Uint8Array>();

function tagPrefix(tag: string): Uint8Array {
  let prefix = tagPrefixCache.get(tag);
  if (!prefix) {
    const h = sha256(utf8ToBytes(tag));
    prefix = concatBytes(h, h);
    tagPrefixCache.set(tag, prefix);
  }
  return prefix;
}

/** BIP-340 tagged hash: sha256(sha256(tag) || sha256(tag) || data). */
export function taggedHash(tag: string, ...data: Uint8Array[]): Uint8Array {
  return sha256(concatBytes(tagPrefix(tag), ...data));
}

/**
 * Shape check for a leaf version: an even integer in 0..255.
 *
 * The low-level API rejects odd values outright instead of silently normalizing via `& 0xfe` --
 * otherwise 0xc1 would pass as 0xc0 and yield a "correct" hash, leaving the misuse undetectable.
 * Both 0x50 (ambiguous with the annex prefix) and "only 0xC0 allowed" are construction-interface
 * policy handled by the normalization in tree.ts; the low-level API follows consensus and accepts
 * any even version.
 */
export function assertLeafVersionShape(leafVersion: number): void {
  assert(
    Number.isInteger(leafVersion) && leafVersion >= 0 && leafVersion <= 0xff,
    'INVALID_LEAF_VERSION',
    `leaf version must be an integer in 0..255, got ${String(leafVersion)}`,
  );
  assert(
    (leafVersion & 1) === 0,
    'INVALID_LEAF_VERSION',
    `leaf version must be even (the low bit is reserved for the control block parity bit), got 0x${leafVersion.toString(16)}`,
  );
}

/**
 * Leaf hash: TapLeaf(leafVersion || compact_size(len(script)) || script).
 *
 * Identical to BIP-341; P2MR only drops the key path and the tweak, and tree hashing is unchanged.
 * leafVersion must already be even (see assertLeafVersionShape); no `& 0xfe` is applied here.
 */
export function tapLeafHash(script: Uint8Array, leafVersion: number): Uint8Array {
  assertLeafVersionShape(leafVersion);
  return taggedHash('TapLeaf', Uint8Array.of(leafVersion), serializeVarBytes(script));
}

/** Branch hash: TapBranch(the two child hashes in lexicographic order). */
export function tapBranchHash(a: Uint8Array, b: Uint8Array): Uint8Array {
  return compareBytes(a, b) <= 0
    ? taggedHash('TapBranch', a, b)
    : taggedHash('TapBranch', b, a);
}

/** Signature hash tag: TapSighash. */
export function tapSighash(data: Uint8Array): Uint8Array {
  return taggedHash('TapSighash', data);
}
