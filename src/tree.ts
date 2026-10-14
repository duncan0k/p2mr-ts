import { toBytes } from './bytes.js';
import { assert, P2mrError } from './errors.js';
import { analyzeLeafScript, MAX_SCRIPT_ELEMENT_SIZE } from './script.js';
import { assertLeafVersionShape, tapBranchHash, tapLeafHash } from './tagged.js';

/** The tapscript leaf version; by default the P2MR wallet interface accepts only this one. */
export const DEFAULT_LEAF_VERSION = 0xc0;

/**
 * Leaf version 0xe0, the tripwired leaf of the Ark-0 test signet (experimental, not part of
 * BIP-360; see tripwire.ts). Like every version other than 0xC0 it is refused by default.
 */
export const TRIPWIRED_LEAF_VERSION = 0xe0;

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
  /**
   * Allow leaf scripts containing OP_SUCCESSx. Defaults to false. Such a leaf is anyone-can-spend
   * (BIP-342: OP_SUCCESSx makes the script succeed unconditionally).
   */
  readonly allowOpSuccess?: boolean;
  /**
   * Allow leaf scripts whose push decoding runs past the end of the script. Defaults to false.
   * Such a leaf fails to decode, so it can never be spent.
   */
  readonly allowTruncatedScript?: boolean;
  /**
   * Allow leaf scripts with a single push of more than 520 bytes. Defaults to false. The push-size
   * check comes before the fExec check in Bitcoin Core, so the leaf fails even when the push sits
   * in an unexecuted branch: it can never be spent.
   */
  readonly allowOversizedPush?: boolean;
  /**
   * Allow leaf scripts made only of push opcodes (0x00-0x60). Defaults to false. Such a leaf
   * needs no signature: it is anyone-can-spend if its final stack is true, unspendable otherwise.
   */
  readonly allowPushOnlyScript?: boolean;
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

  const scan = analyzeLeafScript(script);
  if (scan.opSuccess !== null) {
    const { opSuccess } = scan;
    if (opts.allowOpSuccess !== true) {
      throw new P2mrError(
        'OP_SUCCESS_NOT_ALLOWED',
        `leaf script contains OP_SUCCESS${opSuccess.opcode} (0x${opSuccess.opcode.toString(16)}) at offset ${opSuccess.offset}, ` +
          'and under tapscript that script succeeds unconditionally, which is anyone-can-spend. Pass allowOpSuccess: true explicitly if you really need it',
      );
    }
    // An allowed OP_SUCCESSx decides the outcome before anything else is executed (BIP-342), so the
    // remaining checks do not apply to this leaf
    return { script, leafVersion };
  }
  // The checks below are about BIP-342 execution, which only leaf version 0xC0 gets: BIP-360 says
  // that for future (non-0xC0) leaf versions "the execution must succeed" without running the
  // script, and such leaves are already gated behind allowUnsafeLeafVersion
  if (leafVersion !== DEFAULT_LEAF_VERSION) return { script, leafVersion };
  assert(
    !scan.truncated || opts.allowTruncatedScript === true,
    'LEAF_SCRIPT_TRUNCATED',
    'leaf script is truncated: a push runs past the end of the script, so the script fails to decode and the leaf can never be spent. ' +
      'Pass allowTruncatedScript: true explicitly if you really need it',
  );
  if (scan.oversizedPush !== null && opts.allowOversizedPush !== true) {
    throw new P2mrError(
      'LEAF_SCRIPT_PUSH_TOO_LARGE',
      `leaf script pushes ${scan.oversizedPush.size} bytes at offset ${scan.oversizedPush.offset}, more than the ${MAX_SCRIPT_ELEMENT_SIZE}-byte element limit kept by BIP-342. ` +
        'Bitcoin Core checks the push size before fExec, so the script fails even in an unexecuted branch and the leaf can never be spent. ' +
        'Pass allowOversizedPush: true explicitly if you really need it',
    );
  }
  assert(
    !scan.pushOnly || opts.allowPushOnlyScript === true,
    'LEAF_SCRIPT_PUSH_ONLY',
    'leaf script consists only of push opcodes (0x00-0x60), so it checks no signature: it is anyone-can-spend if it leaves a true value, unspendable otherwise. ' +
      'Pass allowPushOnlyScript: true explicitly if you really need it',
  );

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

/**
 * Throw TREE_TOO_DEEP when a node sits deeper than any leaf may. BIP-360: the control block holds m
 * sibling hashes with "m an integer between 0 and 128, inclusive", so a leaf is at depth <= 128 and
 * any node at depth 129 is already too deep. Checked on the way down, so recursion stays bounded.
 */
function assertDepth(depth: number): void {
  assert(
    depth <= MAX_MERKLE_PATH_LENGTH,
    'TREE_TOO_DEEP',
    `leaf depth ${depth} exceeds the maximum ${MAX_MERKLE_PATH_LENGTH} (a control block is at most 1 + 32*128 bytes)`,
  );
}

function normalizeNode(input: unknown, opts: NormalizeTreeOptions, depth: number): ScriptTreeNode {
  if (input === undefined || input === null || input === '') {
    throw new P2mrError('SCRIPT_TREE_REQUIRED', 'P2MR requires a script tree with at least one leaf');
  }
  assertDepth(depth);
  if (Array.isArray(input)) {
    assert(
      input.length === 2,
      'INVALID_BRANCH_ARITY',
      `the script tree is a strict binary tree, a branch must have exactly 2 children, got ${input.length}`,
    );
    return {
      type: 'branch',
      left: normalizeNode(input[0], opts, depth + 1),
      right: normalizeNode(input[1], opts, depth + 1),
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

/** Normalize a script tree from input form, completing all leaf-level validation at this stage. */
export function normalizeScriptTree(
  input: unknown,
  opts: NormalizeTreeOptions = {},
): ScriptTreeNode {
  return normalizeNode(input, opts, 0);
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
  assertDepth(depth);
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
  // build() has already enforced the depth limit
  const entries: LeafEntry[] = leaves.map((e, index) => ({
    index,
    depth: e.depth,
    leaf: e.leaf,
    leafHash: e.leafHash,
    merklePath: e.path,
  }));
  return { merkleRoot: root, leaves: entries };
}

/** Just the merkle root. Throws TREE_TOO_DEEP for a leaf deeper than 128. */
export function computeMerkleRoot(node: ScriptTreeNode): Uint8Array {
  return build(node, 0).root;
}

/**
 * Collect all leaf hashes in depth-first order (same order as intermediary.leafHashes in the
 * vectors). Throws TREE_TOO_DEEP for a leaf deeper than 128.
 */
export function collectLeafHashes(node: ScriptTreeNode): Uint8Array[] {
  return build(node, 0).leaves.map((e) => e.leafHash);
}

function countFrom(node: ScriptTreeNode, depth: number): number {
  assertDepth(depth);
  return node.type === 'leaf'
    ? 1
    : countFrom(node.left, depth + 1) + countFrom(node.right, depth + 1);
}

/**
 * Total number of leaf positions in the tree (duplicate leaves counted once per position). Throws
 * TREE_TOO_DEEP for a leaf deeper than 128.
 */
export function countLeafPositions(node: ScriptTreeNode): number {
  return countFrom(node, 0);
}
