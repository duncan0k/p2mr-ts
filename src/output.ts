import type { Network } from './address.js';
import { decodeP2mrAddress, encodeP2mrAddress } from './address.js';
import { bytesEqual, concatBytes } from './bytes.js';
import { encodeControlBlock } from './controlBlock.js';
import { assert, P2mrError } from './errors.js';
import type { NormalizeTreeOptions, ScriptTreeInput, ScriptTreeNode } from './tree.js';
import { analyzeScriptTree, normalizeScriptTree } from './tree.js';

/** scriptPubKey prefix: OP_2 OP_PUSHBYTES_32. */
const SCRIPT_PUBKEY_PREFIX = Uint8Array.of(0x52, 0x20);

/** scriptPubKey = OP_2 OP_PUSHBYTES_32 <merkle root>, 34 bytes in total. */
export function buildP2mrScriptPubKey(merkleRoot: Uint8Array): Uint8Array {
  assert(
    merkleRoot.length === 32,
    'INVALID_MERKLE_ROOT',
    `merkle root must be 32 bytes, got ${merkleRoot.length}`,
  );
  return concatBytes(SCRIPT_PUBKEY_PREFIX, merkleRoot);
}

export function isP2mrScriptPubKey(scriptPubKey: Uint8Array): boolean {
  return (
    scriptPubKey.length === 34 &&
    scriptPubKey[0] === 0x52 &&
    scriptPubKey[1] === 0x20
  );
}

/** Recover the merkle root from a scriptPubKey; throws if the shape does not match. */
export function parseP2mrScriptPubKey(scriptPubKey: Uint8Array): Uint8Array {
  assert(
    isP2mrScriptPubKey(scriptPubKey),
    'INVALID_SCRIPT_PUBKEY',
    'scriptPubKey is not in P2MR form (expected 34 bytes of OP_2 OP_PUSHBYTES_32 <32 bytes>)',
  );
  return scriptPubKey.slice(2);
}

export interface CreateP2mrOutputOptions extends NormalizeTreeOptions {
  /** The script tree. Both namings occur in the vectors, so both are accepted here. */
  readonly scriptTree?: ScriptTreeInput | null | '' | undefined;
  /** snake_case alias for `scriptTree`. */
  readonly script_tree?: ScriptTreeInput | null | '' | undefined;
  /** Defaults to mainnet. */
  readonly network?: Network;
  /**
   * Allow constructing a single-leaf (m=0) output. Defaults to false.
   *
   * Per BIP-360 v0.12.0: with m=0 in the control block the spend succeeds as soon as the root
   * matches, no matter whether the script itself succeeds -- a depth-0 tree is anyone-can-spend.
   * Low-level tooling may build such test cases; a wallet interface must reject them.
   */
  readonly allowUnsafeSingleLeaf?: boolean;
  /** Leftover BIP-341 fields. P2MR has no key path, so their presence is an error. */
  readonly internalPubkey?: unknown;
  readonly tweak?: unknown;
  readonly tweakedPubkey?: unknown;
}

export interface P2mrLeafOutput {
  /**
   * Depth-first index, i.e. the position of the leaf in the tree. Duplicate leaves get one control
   * block per position.
   */
  readonly index: number;
  readonly depth: number;
  readonly script: Uint8Array;
  readonly leafVersion: number;
  readonly leafHash: Uint8Array;
  readonly merklePath: readonly Uint8Array[];
  readonly controlBlock: Uint8Array;
}

export interface P2mrOutput {
  readonly network: Network;
  readonly merkleRoot: Uint8Array;
  readonly scriptPubKey: Uint8Array;
  readonly address: string;
  readonly tree: ScriptTreeNode;
  readonly leaves: readonly P2mrLeafOutput[];
}

const KEY_PATH_FIELDS = ['internalPubkey', 'tweak', 'tweakedPubkey'] as const;

/**
 * Build a P2MR output: merkle root, scriptPubKey, bech32m address, and a control block per leaf position.
 *
 * Three classes of input that construct fine but offer no protection at all when spent are rejected by
 * default -- internal pubkey, single-leaf tree, leaf version other than 0xC0 -- plus leaf scripts
 * containing OP_SUCCESSx. These are construction-interface constraints, not consensus rules: a node
 * only looks at the 32-byte witness program, so do not carry these rejections into consensus tests.
 */
export function createP2mrOutput(options: CreateP2mrOutputOptions): P2mrOutput {
  const bag = options as Record<string, unknown>;
  for (const field of KEY_PATH_FIELDS) {
    if (bag[field] !== undefined) {
      throw new P2mrError(
        'INTERNAL_PUBKEY_NOT_SUPPORTED',
        `P2MR has no key path, so \`${field}\` is not accepted. The witness program is the merkle root itself; ` +
          'there is no internal pubkey and no taproot tweak',
      );
    }
  }

  const rawTree = options.scriptTree !== undefined ? options.scriptTree : options.script_tree;
  const normalizeOptions: NormalizeTreeOptions = {
    allowUnsafeLeafVersion: options.allowUnsafeLeafVersion === true,
    allowOpSuccess: options.allowOpSuccess === true,
  };
  const tree = normalizeScriptTree(rawTree, normalizeOptions);

  assert(
    tree.type !== 'leaf' || options.allowUnsafeSingleLeaf === true,
    'SINGLE_LEAF_NOT_ALLOWED',
    'a single-leaf tree gives m=0 in the control block; per BIP-360 a matching root succeeds immediately without executing the script, which is anyone-can-spend. ' +
      'Pass allowUnsafeSingleLeaf: true explicitly if you really need to construct one',
  );

  const network: Network = options.network ?? 'mainnet';
  const { merkleRoot, leaves } = analyzeScriptTree(tree);

  return {
    network,
    merkleRoot,
    scriptPubKey: buildP2mrScriptPubKey(merkleRoot),
    address: encodeP2mrAddress(merkleRoot, network),
    tree,
    leaves: leaves.map((entry) => ({
      index: entry.index,
      depth: entry.depth,
      script: entry.leaf.script,
      leafVersion: entry.leaf.leafVersion,
      leafHash: entry.leafHash,
      merklePath: entry.merklePath,
      controlBlock: encodeControlBlock(entry.leaf.leafVersion, entry.merklePath),
    })),
  };
}

/** Check whether an address commits to exactly the given merkle root. */
export function addressMatchesMerkleRoot(
  address: string,
  merkleRoot: Uint8Array,
  network?: Network,
): boolean {
  const decoded = decodeP2mrAddress(
    address,
    network === undefined ? {} : { network },
  );
  return bytesEqual(decoded.merkleRoot, merkleRoot);
}
