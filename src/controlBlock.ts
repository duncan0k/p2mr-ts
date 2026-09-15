import { bytesEqual, concatBytes } from './bytes.js';
import { assert } from './errors.js';
import { assertLeafVersionShape, tapBranchHash, tapLeafHash } from './tagged.js';
import { MAX_MERKLE_PATH_LENGTH } from './tree.js';

/** Control block base size: P2MR drops the 32-byte x-only internal pubkey of P2TR, 33 -> 1. */
export const CONTROL_BLOCK_BASE_SIZE = 1;

/** Maximum control block size: 1 + 32 * 128 = 4097 bytes. */
export const MAX_CONTROL_BLOCK_SIZE =
  CONTROL_BLOCK_BASE_SIZE + 32 * MAX_MERKLE_PATH_LENGTH;

/**
 * Assemble a control block: c[0] = leafVersion | 1, followed by m 32-byte sibling hashes.
 *
 * leafVersion must be even (odd values are rejected outright, not silently normalized), and the
 * low bit of c[0] is forced to 1. The BIP footnote gives the reason: an implementation that reads
 * the leaf version straight out of c[0] instead of c[0] & 0xfe fails immediately, rather than
 * silently producing a wrong leaf version.
 */
export function encodeControlBlock(
  leafVersion: number,
  merklePath: readonly Uint8Array[],
): Uint8Array {
  assertLeafVersionShape(leafVersion);
  assert(
    merklePath.length <= MAX_MERKLE_PATH_LENGTH,
    'CONTROL_BLOCK_PATH_TOO_LONG',
    `merkle path length ${merklePath.length} exceeds the maximum ${MAX_MERKLE_PATH_LENGTH}`,
  );
  for (const node of merklePath) {
    assert(
      node.length === 32,
      'INVALID_CONTROL_BLOCK_LENGTH',
      `merkle path element must be 32 bytes, got ${node.length}`,
    );
  }
  return concatBytes(Uint8Array.of(leafVersion | 1), ...merklePath);
}

export interface ParsedControlBlock {
  /** c[0] & 0xfe. */
  readonly leafVersion: number;
  /** c[0] & 1; must be 1 in P2MR (not the y-parity bit of the output pubkey, as in P2TR). */
  readonly parityBit: number;
  /** Number of sibling hashes, m. */
  readonly m: number;
  readonly merklePath: readonly Uint8Array[];
}

/**
 * Parse and validate a control block.
 *
 * The length check cannot be reused from P2TR: P2TR is 33 + 32m, P2MR is 1 + 32m.
 */
export function parseControlBlock(controlBlock: Uint8Array): ParsedControlBlock {
  assert(
    controlBlock.length >= CONTROL_BLOCK_BASE_SIZE &&
      (controlBlock.length - CONTROL_BLOCK_BASE_SIZE) % 32 === 0,
    'INVALID_CONTROL_BLOCK_LENGTH',
    `control block length must be 1 + 32m, got ${controlBlock.length}`,
  );
  const m = (controlBlock.length - CONTROL_BLOCK_BASE_SIZE) / 32;
  assert(
    m <= MAX_MERKLE_PATH_LENGTH,
    'INVALID_CONTROL_BLOCK_LENGTH',
    `control block m=${m} exceeds the maximum ${MAX_MERKLE_PATH_LENGTH} (at most ${MAX_CONTROL_BLOCK_SIZE} bytes)`,
  );

  const head = controlBlock[0] as number;
  assert(
    (head & 1) === 1,
    'INVALID_CONTROL_BLOCK_PARITY',
    `the low bit of the control block first byte must be 1, got 0x${head.toString(16).padStart(2, '0')}`,
  );

  const merklePath: Uint8Array[] = [];
  for (let i = 0; i < m; i++) {
    const start = CONTROL_BLOCK_BASE_SIZE + i * 32;
    merklePath.push(controlBlock.slice(start, start + 32));
  }

  return { leafVersion: head & 0xfe, parityBit: head & 1, m, merklePath };
}

/**
 * Recompute the merkle root from a leaf script plus its control block.
 *
 * With m=0 the result is the leaf hash itself -- which is exactly why BIP-360 treats a depth-0
 * tree as anyone-can-spend: once the root matches, the spend succeeds, whether or not the script
 * itself executes successfully.
 */
export function computeMerkleRootFromControlBlock(
  leafScript: Uint8Array,
  controlBlock: Uint8Array,
): Uint8Array {
  const { leafVersion, merklePath } = parseControlBlock(controlBlock);
  let acc = tapLeafHash(leafScript, leafVersion);
  for (const sibling of merklePath) acc = tapBranchHash(acc, sibling);
  return acc;
}

/** Check whether a leaf script plus control block really commits to the given merkle root. */
export function verifyControlBlock(params: {
  leafScript: Uint8Array;
  controlBlock: Uint8Array;
  merkleRoot: Uint8Array;
}): boolean {
  return bytesEqual(
    computeMerkleRootFromControlBlock(params.leafScript, params.controlBlock),
    params.merkleRoot,
  );
}
