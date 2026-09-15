import { toBytes } from './bytes.js';
import { assert, P2mrError } from './errors.js';
import { scanLeafScript } from './script.js';
import { assertLeafVersionShape, tapBranchHash, tapLeafHash } from './tagged.js';

/** The tapscript leaf version; by default the P2MR wallet interface accepts only this one. */
export const DEFAULT_LEAF_VERSION = 0xc0;

/** A control block carries at most 128 sibling hashes of 32 bytes each, so leaf depth is capped at 128. */
export const MAX_MERKLE_PATH_LENGTH = 128;

/** Leaf node in input form; extra fields from the vectors such as id/asm/description are allowed. */
export interface ScriptLeafInput {
  readonly script: Uint8Array | string;
  readonly leafVersion?: number;
  readonly [key: string]: unknown;
}

/** Script tree in input form: a leaf object, or an array of exactly two children (a branch). */
export type ScriptTreeInput = ScriptLeafInput | readonly ScriptTreeInput[];

/** A normalized leaf. */
export interface ScriptLeaf {
  readonly script: Uint8Array;
  readonly leafVersion: number;
}

/** A normalized tree node. */
export type ScriptTreeNode =
  | { readonly type: 'leaf'; readonly leaf: ScriptLeaf }
  | {
      readonly type: 'branch';
      readonly left: ScriptTreeNode;
      readonly right: ScriptTreeNode;
    };

export interface NormalizeTreeOptions {
  /** Allow leaf versions other than 0xC0. Defaults to false. */
  readonly allowUnsafeLeafVersion?: boolean;
  /** Allow leaf scripts containing OP_SUCCESSx. Defaults to false. */
  readonly allowOpSuccess?: boolean;
}

function normalizeLeaf(node: ScriptLeafInput, opts: NormalizeTreeOptions): ScriptLeaf {
  const script = toBytes(node.script, 'leaf script');
  assert(script.length > 0, 'INVALID_LEAF_SCRIPT', 'leaf script must not be empty');

  const leafVersion =
    node.leafVersion === undefined ? DEFAULT_LEAF_VERSION : node.leafVersion;
  assertLeafVersionShape(leafVersion);
  assert(
    leafVersion !== 0x50,
    'INVALID_LEAF_VERSION',
    'leaf version 0x50 is reserved by the BIP-341 leaf version namespace convention (under P2TR c[0] may be 0x50, which is ambiguous with the annex prefix). ' +
      'In P2MR c[0] is always odd, so no such ambiguity exists -- this is a conservative construction-interface policy, and the low-level API still accepts 0x50',
  );
  assert(
    opts.allowUnsafeLeafVersion === true || leafVersion === DEFAULT_LEAF_VERSION,
    'LEAF_VERSION_NOT_ALLOWED',
    `leaf version 0x${leafVersion.toString(16)} is rejected by default: per BIP-360 a non-0xC0 leaf succeeds unconditionally when spent (the script is not executed), ` +
      'which is anyone-can-spend. Pass allowUnsafeLeafVersion: true explicitly if you really need it',
  );

  if (opts.allowOpSuccess !== true) {
    const { opSuccess } = scanLeafScript(script);
    if (opSuccess !== null) {
      throw new P2mrError(
        'OP_SUCCESS_NOT_ALLOWED',
        `leaf script contains OP_SUCCESS${opSuccess.opcode} (0x${opSuccess.opcode.toString(16)}) at offset ${opSuccess.offset}, ` +
          'and under tapscript that script succeeds unconditionally, which is anyone-can-spend. Pass allowOpSuccess: true explicitly if you really need it',
      );
    }
  }

  return { script, leafVersion };
}

function isLeafInput(node: unknown): node is ScriptLeafInput {
  return (
    typeof node === 'object' &&
    node !== null &&
    !Array.isArray(node) &&
    'script' in (node as Record<string, unknown>)
  );
}

/** Normalize a script tree from input form, completing all leaf-level validation at this stage. */
export function normalizeScriptTree(
  input: unknown,
  opts: NormalizeTreeOptions = {},
): ScriptTreeNode {
  if (input === undefined || input === null || input === '') {
    throw new P2mrError('SCRIPT_TREE_REQUIRED', 'P2MR requires a script tree with at least one leaf');
  }
  if (Array.isArray(input)) {
    assert(
      input.length === 2,
      'INVALID_BRANCH_ARITY',
      `the script tree is a strict binary tree, a branch must have exactly 2 children, got ${input.length}`,
    );
    return {
      type: 'branch',
      left: normalizeScriptTree(input[0], opts),
      right: normalizeScriptTree(input[1], opts),
    };
  }
  if (isLeafInput(input)) {
    return { type: 'leaf', leaf: normalizeLeaf(input, opts) };
  }
  throw new P2mrError(
    'INVALID_TREE_NODE',
    'tree node is neither a leaf (an object with a script field) nor a branch (an array of length 2)',
  );
}

/** Full positional information for one leaf of the tree. */
export interface LeafEntry {
  /** Depth-first traversal index, i.e. the "position in the tree". Duplicate leaves take one slot each. */
  readonly index: number;
  /** Number of steps from the root to this leaf, equal to the merklePath length. */
  readonly depth: number;
  readonly leaf: ScriptLeaf;
  readonly leafHash: Uint8Array;
  /** Sibling hashes ordered from the deepest level towards the root (the control block order). */
  readonly merklePath: readonly Uint8Array[];
}

interface BuiltLeaf {
  leaf: ScriptLeaf;
  leafHash: Uint8Array;
  depth: number;
  path: Uint8Array[];
}

interface BuildResult {
  root: Uint8Array;
  leaves: BuiltLeaf[];
}

function build(node: ScriptTreeNode, depth: number): BuildResult {
  if (node.type === 'leaf') {
    const leafHash = tapLeafHash(node.leaf.script, node.leaf.leafVersion);
    return { root: leafHash, leaves: [{ leaf: node.leaf, leafHash, depth, path: [] }] };
  }
  const left = build(node.left, depth + 1);
  const right = build(node.right, depth + 1);
  // Siblings are pushed bottom-up, so the resulting path order is exactly the control block order
  for (const e of left.leaves) e.path.push(right.root);
  for (const e of right.leaves) e.path.push(left.root);
  return {
    root: tapBranchHash(left.root, right.root),
    leaves: [...left.leaves, ...right.leaves],
  };
}

/** A single traversal yielding both the merkle root and the sibling path of every leaf position. */
export function analyzeScriptTree(node: ScriptTreeNode): {
  merkleRoot: Uint8Array;
  leaves: LeafEntry[];
} {
  const { root, leaves } = build(node, 0);
  const entries: LeafEntry[] = leaves.map((e, index) => {
    assert(
      e.path.length <= MAX_MERKLE_PATH_LENGTH,
      'TREE_TOO_DEEP',
      `leaf depth ${e.path.length} exceeds the maximum ${MAX_MERKLE_PATH_LENGTH} (a control block is at most 1 + 32*128 bytes)`,
    );
    return {
      index,
      depth: e.depth,
      leaf: e.leaf,
      leafHash: e.leafHash,
      merklePath: e.path,
    };
  });
  return { merkleRoot: root, leaves: entries };
}

/** Just the merkle root. */
export function computeMerkleRoot(node: ScriptTreeNode): Uint8Array {
  return build(node, 0).root;
}

/** Collect all leaf hashes in depth-first order (same order as intermediary.leafHashes in the vectors). */
export function collectLeafHashes(node: ScriptTreeNode): Uint8Array[] {
  return build(node, 0).leaves.map((e) => e.leafHash);
}

/** Total number of leaf positions in the tree (duplicate leaves counted once per position). */
export function countLeafPositions(node: ScriptTreeNode): number {
  return node.type === 'leaf'
    ? 1
    : countLeafPositions(node.left) + countLeafPositions(node.right);
}
