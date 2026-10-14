/**
 * Regression tests for the findings of the independent review of commit c2501dff.
 *
 * The fixture values (roots, addresses, leaf hashes) were computed independently by the review and
 * are re-checked here against this library.
 */
import { describe, expect, it } from 'vitest';
import {
  analyzeLeafScript,
  assembleScriptPathWitness,
  bytesToHex,
  codeSeparatorPositions,
  collectLeafHashes,
  computeMerkleRoot,
  countLeafPositions,
  createP2mrOutput,
  decodeTransaction,
  encodeTransaction,
  hexToBytes,
  MAX_CONTROL_BLOCK_SIZE,
  normalizeScriptTree,
  p2mrScriptPathSighash,
  serializeOutPoint,
  serializeTxOutput,
  tapLeafHash,
  MAX_INITIAL_STACK_ELEMENTS,
  P2mrError,
  scanLeafScript,
} from '../src/index.js';
import type {
  CreateP2mrOutputOptions,
  P2mrErrorCode,
  ScriptTreeInput,
  ScriptTreeNode,
  SpentOutput,
  Transaction,
} from '../src/index.js';

const LEAF_A = { script: `20${'11'.repeat(32)}ac`, leafVersion: 0xc0 };
const LEAF_B = { script: `20${'22'.repeat(32)}ac`, leafVersion: 0xc0 };
const TWO_LEAF: ScriptTreeInput = [LEAF_A, LEAF_B];

function expectCode(fn: () => unknown, code: P2mrErrorCode): void {
  let thrown: unknown;
  try {
    fn();
  } catch (err) {
    thrown = err;
  }
  expect(thrown, `expected to throw ${code}`).toBeInstanceOf(P2mrError);
  expect((thrown as P2mrError).code).toBe(code);
}

describe('P1-1: createP2mrOutput requires an explicit network', () => {
  it('omitting network is a compile-time error', () => {
    // The directive itself is the assertion: `npm run typecheck` fails if this line compiles
    // @ts-expect-error -- `network` is a required property of CreateP2mrOutputOptions
    const options: CreateP2mrOutputOptions = { scriptTree: TWO_LEAF };
    expect(options.scriptTree).toBe(TWO_LEAF);
  });

  it('omitting network is a runtime error for JavaScript callers', () => {
    const untyped = createP2mrOutput as (options: unknown) => unknown;
    expectCode(() => untyped({ scriptTree: TWO_LEAF }), 'NETWORK_REQUIRED');
    expectCode(() => untyped({ scriptTree: TWO_LEAF, network: undefined }), 'NETWORK_REQUIRED');
  });

  it('an unknown network string is rejected', () => {
    const untyped = createP2mrOutput as (options: unknown) => unknown;
    expectCode(() => untyped({ scriptTree: TWO_LEAF, network: 'bitcoin' }), 'UNKNOWN_NETWORK');
    expectCode(() => untyped({ scriptTree: TWO_LEAF, network: 'toString' }), 'UNKNOWN_NETWORK');
  });

  it('every network, mainnet and testnet included, is still available as an explicit value', () => {
    const prefixes = { mainnet: 'bc1z', testnet: 'tb1z', signet: 'tb1z', regtest: 'bcrt1z' } as const;
    for (const [network, prefix] of Object.entries(prefixes)) {
      const out = createP2mrOutput({ scriptTree: TWO_LEAF, network: network as keyof typeof prefixes });
      expect(out.network).toBe(network);
      expect(out.address.startsWith(prefix)).toBe(true);
    }
  });
});

describe('P2-1 / V8: leaves that are anyone-can-spend or never spendable are rejected by default', () => {
  const companion = { script: `20${'aa'.repeat(32)}ac`, leafVersion: 0xc0 };
  const cases = [
    {
      name: 'pure 32-byte push (20 + 31 bytes + ac): anyone can spend',
      script: `20${'bb'.repeat(31)}ac`,
      code: 'PUSH_ONLY_SCRIPT_NOT_ALLOWED',
      flag: 'allowPushOnlyScript',
    },
    {
      name: 'truncated push (20 + 30 bytes + ac): never spendable',
      script: `20${'bb'.repeat(30)}ac`,
      code: 'TRUNCATED_SCRIPT_NOT_ALLOWED',
      flag: 'allowTruncatedScript',
    },
    {
      name: '521-byte push (4d0902 + 521 bytes + 7551): never spendable, even unexecuted',
      script: `4d0902${'bb'.repeat(521)}7551`,
      code: 'OVERSIZED_PUSH_NOT_ALLOWED',
      flag: 'allowOversizedPush',
    },
  ] as const;
  const flags = cases.map((c) => c.flag);

  for (const c of cases) {
    it(`${c.name} -> ${c.code}, accepted only with ${c.flag}`, () => {
      const scriptTree: ScriptTreeInput = [companion, { script: c.script, leafVersion: 0xc0 }];
      expectCode(() => createP2mrOutput({ scriptTree, network: 'regtest' }), c.code);
      // The other two opt-outs do not help
      const others = Object.fromEntries(flags.filter((f) => f !== c.flag).map((f) => [f, true]));
      expectCode(() => createP2mrOutput({ scriptTree, network: 'regtest', ...others }), c.code);
      const out = createP2mrOutput({ scriptTree, network: 'regtest', [c.flag]: true });
      expect(out.leaves).toHaveLength(2);
    });
  }

  it('a 520-byte push is at the limit and allowed', () => {
    const scriptTree: ScriptTreeInput = [companion, { script: `4d0802${'bb'.repeat(520)}7551`, leafVersion: 0xc0 }];
    expect(createP2mrOutput({ scriptTree, network: 'regtest' }).leaves).toHaveLength(2);
  });

  it('OP_1 / OP_16 / OP_0 alone are push-only; a script with any non-push opcode is not', () => {
    for (const script of ['51', '60', '00', '4f', '0101']) {
      expect(analyzeLeafScript(hexToBytes(script)).pushOnly, script).toBe(true);
    }
    for (const script of ['61', '5175', `20${'11'.repeat(32)}ac`]) {
      expect(analyzeLeafScript(hexToBytes(script)).pushOnly, script).toBe(false);
    }
  });

  it('an OP_SUCCESSx before an oversized push decides the outcome; one after it does not hide it', () => {
    const successFirst = hexToBytes(`7f4d0902${'bb'.repeat(521)}`);
    expect(analyzeLeafScript(successFirst)).toMatchObject({ opSuccess: { opcode: 0x7f, offset: 0 }, oversizedPush: null });
    const pushFirst = hexToBytes(`4d0902${'bb'.repeat(521)}7f`);
    expect(analyzeLeafScript(pushFirst)).toMatchObject({
      opSuccess: { opcode: 0x7f },
      oversizedPush: { offset: 0, size: 521 },
    });
    // With allowOpSuccess the leaf is anyone-can-spend regardless, so no further check applies
    const scriptTree: ScriptTreeInput = [companion, { script: pushFirst, leafVersion: 0xc0 }];
    expect(createP2mrOutput({ scriptTree, network: 'regtest', allowOpSuccess: true }).leaves).toHaveLength(2);
  });

  it('scanLeafScript keeps its original result shape', () => {
    expect(scanLeafScript(hexToBytes(`20${'bb'.repeat(30)}ac`))).toEqual({ opSuccess: null, truncated: true });
  });

  it('non-0xC0 leaves are not executed (BIP-360), so the script checks do not apply to them', () => {
    const scriptTree: ScriptTreeInput = [companion, { script: `20${'bb'.repeat(31)}ac`, leafVersion: 0xc2 }];
    expectCode(() => createP2mrOutput({ scriptTree, network: 'regtest' }), 'LEAF_VERSION_NOT_ALLOWED');
    expect(createP2mrOutput({ scriptTree, network: 'regtest', allowUnsafeLeafVersion: true }).leaves).toHaveLength(2);
  });
});

describe('P2-2: assembleScriptPathWitness binds to the merkle root and enforces BIP-342 stack limits', () => {
  const out = createP2mrOutput({ scriptTree: TWO_LEAF, network: 'regtest' });
  const other = createP2mrOutput({
    scriptTree: [LEAF_A, { script: `20${'33'.repeat(32)}ac`, leafVersion: 0xc0 }],
    network: 'regtest',
  });
  const leaf = out.leaves[0]!;
  const sig = new Uint8Array(64).fill(7);

  it('accepts a leaf and control block that commit to the given merkle root', () => {
    const witness = assembleScriptPathWitness({
      stack: [sig],
      leafScript: leaf.script,
      controlBlock: leaf.controlBlock,
      merkleRoot: out.merkleRoot,
    });
    expect(witness).toEqual([sig, leaf.script, leaf.controlBlock]);
  });

  it('rejects a control block of another output (CONTROL_BLOCK_ROOT_MISMATCH)', () => {
    expectCode(
      () =>
        assembleScriptPathWitness({
          stack: [sig],
          leafScript: leaf.script,
          controlBlock: leaf.controlBlock,
          merkleRoot: other.merkleRoot,
        }),
      'CONTROL_BLOCK_ROOT_MISMATCH',
    );
    // The leaf of position 1 with the control block of position 0
    expectCode(
      () =>
        assembleScriptPathWitness({
          leafScript: out.leaves[1]!.script,
          controlBlock: leaf.controlBlock,
          merkleRoot: out.merkleRoot,
        }),
      'CONTROL_BLOCK_ROOT_MISMATCH',
    );
  });

  it('rejects a merkle root that is not 32 bytes', () => {
    expectCode(
      () =>
        assembleScriptPathWitness({
          leafScript: leaf.script,
          controlBlock: leaf.controlBlock,
          merkleRoot: out.merkleRoot.subarray(0, 31),
        }),
      'INVALID_MERKLE_ROOT',
    );
  });

  it('without merkleRoot the binding is not checked (backward compatible)', () => {
    expect(
      assembleScriptPathWitness({ leafScript: out.leaves[1]!.script, controlBlock: leaf.controlBlock }),
    ).toHaveLength(2);
  });

  it('stack elements: 520 bytes is allowed, 521 bytes is rejected', () => {
    const base = { leafScript: leaf.script, controlBlock: leaf.controlBlock };
    expect(assembleScriptPathWitness({ ...base, stack: [new Uint8Array(520)] })).toHaveLength(3);
    expectCode(
      () => assembleScriptPathWitness({ ...base, stack: [sig, new Uint8Array(521)] }),
      'WITNESS_STACK_ELEMENT_TOO_LARGE',
    );
  });

  it('stack element count: 1000 is allowed, 1001 is rejected', () => {
    const base = { leafScript: leaf.script, controlBlock: leaf.controlBlock };
    expect(MAX_INITIAL_STACK_ELEMENTS).toBe(1000);
    const full = Array.from({ length: 1000 }, () => new Uint8Array(1));
    expect(assembleScriptPathWitness({ ...base, stack: full })).toHaveLength(1002);
    expectCode(
      () => assembleScriptPathWitness({ ...base, stack: [...full, new Uint8Array(1)] }),
      'WITNESS_STACK_TOO_MANY_ELEMENTS',
    );
  });

  it('the leaf script, control block and annex do not count towards the initial stack limits', () => {
    // A 4097-byte control block and a long leaf script are not stack elements
    const longLeaf = hexToBytes(`4d0802${'bb'.repeat(520)}75${'20'}${'11'.repeat(32)}ac`);
    expect(
      assembleScriptPathWitness({
        leafScript: longLeaf,
        controlBlock: leaf.controlBlock,
        annex: new Uint8Array(600).fill(0x50),
        allowAnnex: true,
      }),
    ).toHaveLength(3);
  });
});

describe('P3-1 / V1: the depth limit of 128 is enforced by every exported tree function', () => {
  const chainLeaf = (i: number) => ({
    script: `20${i.toString(16).padStart(2, '0').repeat(32)}ac`,
    leafVersion: 0xc0,
  });
  /** t = L0; for i = 1..depth: t = [L_i, t]. L0 ends up at the given depth. */
  const chain = (depth: number): ScriptTreeInput => {
    let t: ScriptTreeInput = chainLeaf(0);
    for (let i = 1; i <= depth; i++) t = [chainLeaf(i), t];
    return t;
  };

  it('a depth-128 chain matches the independently computed root, address and control block size', () => {
    const out = createP2mrOutput({ scriptTree: chain(128), network: 'regtest' });
    expect(bytesToHex(out.merkleRoot)).toBe('a85635c68d8424882a41abe7960515dc4f5d7ea97063cfd74d643211bf673b1c');
    expect(out.address).toBe('bcrt1z4ptrt35dssjgs2jp40nevpg4m3846l4fwp3ul46dvsepr0m88vwqxt0dqy');
    const l0 = out.leaves.find((l) => bytesToHex(l.script) === chainLeaf(0).script)!;
    expect(l0.depth).toBe(128);
    expect(l0.controlBlock).toHaveLength(4097);
    expect(MAX_CONTROL_BLOCK_SIZE).toBe(4097);
    expect(bytesToHex(computeMerkleRoot(out.tree))).toBe(bytesToHex(out.merkleRoot));
  });

  it('wrapping once more (depth 129) throws TREE_TOO_DEEP from createP2mrOutput and computeMerkleRoot', () => {
    expectCode(() => createP2mrOutput({ scriptTree: chain(129), network: 'regtest' }), 'TREE_TOO_DEEP');
    expectCode(() => normalizeScriptTree(chain(129)), 'TREE_TOO_DEEP');
    // A ScriptTreeNode built by hand bypasses normalizeScriptTree
    const tree128 = normalizeScriptTree(chain(128));
    const leaf129 = normalizeScriptTree(chainLeaf(129));
    const tree129: ScriptTreeNode = { type: 'branch', left: leaf129, right: tree128 };
    expectCode(() => computeMerkleRoot(tree129), 'TREE_TOO_DEEP');
    expectCode(() => collectLeafHashes(tree129), 'TREE_TOO_DEEP');
    expectCode(() => countLeafPositions(tree129), 'TREE_TOO_DEEP');
    expect(countLeafPositions(tree128)).toBe(129);
  });

  it('a very deep tree throws TREE_TOO_DEEP rather than a RangeError (stack overflow)', () => {
    const depth = 200_000;
    let node: ScriptTreeNode = normalizeScriptTree(chainLeaf(0));
    const sibling = node;
    for (let i = 0; i < depth; i++) node = { type: 'branch', left: sibling, right: node };
    expectCode(() => computeMerkleRoot(node), 'TREE_TOO_DEEP');
    expectCode(() => collectLeafHashes(node), 'TREE_TOO_DEEP');

    let input: ScriptTreeInput = chainLeaf(0);
    for (let i = 0; i < depth; i++) input = [chainLeaf(1), input];
    expectCode(() => createP2mrOutput({ scriptTree: input, network: 'regtest' }), 'TREE_TOO_DEEP');
  });
});

describe('V2: a 253-byte leaf (CompactSize length prefix fd fd00) hashes as computed independently', () => {
  it('leaf hashes and root', () => {
    const s = `4cd8${'aa'.repeat(216)}75${'20'}${'11'.repeat(32)}ac`;
    expect(hexToBytes(s)).toHaveLength(253);
    const out = createP2mrOutput({
      scriptTree: [{ script: s }, { script: `20${'22'.repeat(32)}ac` }],
      network: 'regtest',
    });
    expect(out.leaves.map((l) => bytesToHex(l.leafHash))).toEqual([
      'ec236ffcb0312fb6f56ce9c24d67bd8137e6e2ac60b0df52f393c924b544e274',
      '29cfff6f39dce5e4426403ec1dc93f59e3c538141a3612e819d896d17bae94f2',
    ]);
    expect(bytesToHex(out.merkleRoot)).toBe('3274d5cab99bcdf48c7c66729de782e22b70ef1abd6f633cc023c2cadec40e2a');
  });
});

describe('P3-2 / V7: decodeTransaction rejects non-canonical CompactSize encodings', () => {
  const tail = `${'11'.repeat(32)}0000000000ffffffff01e8030000000000000151` + '00000000';

  it('the canonical form decodes and re-encodes byte for byte', () => {
    const raw = hexToBytes(`0200000001${tail}`);
    expect(bytesToHex(encodeTransaction(decodeTransaction(raw)))).toBe(bytesToHex(raw));
  });

  it('V7: fd0100 for an input count of 1 throws INVALID_TRANSACTION', () => {
    expectCode(() => decodeTransaction(hexToBytes(`02000000fd0100${tail}`)), 'INVALID_TRANSACTION');
  });

  it('every non-minimal width is rejected; the smallest value of each width is accepted', () => {
    expectCode(() => decodeTransaction(hexToBytes(`02000000fe01000000${tail}`)), 'INVALID_TRANSACTION');
    expectCode(() => decodeTransaction(hexToBytes(`02000000ff0100000000000000${tail}`)), 'INVALID_TRANSACTION');
    expectCode(() => decodeTransaction(hexToBytes(`02000000fdfc00${tail}`)), 'INVALID_TRANSACTION');
    // fdfd00 is canonical (253); it fails later only because the data runs out
    let thrown: unknown;
    try {
      decodeTransaction(hexToBytes(`02000000fdfd00${tail}`));
    } catch (err) {
      thrown = err;
    }
    expect((thrown as P2mrError).message).toContain('ran out');
  });

  it('a non-canonical script length is rejected too', () => {
    const raw = `0200000001${'11'.repeat(32)}00000000fd0000ffffffff01e8030000000000000151` + '00000000';
    expectCode(() => decodeTransaction(hexToBytes(raw)), 'INVALID_TRANSACTION');
  });
});

describe('P3-3: numeric fields are range-checked instead of reduced modulo 2^32 / 2^64', () => {
  const p2mr = createP2mrOutput({ scriptTree: TWO_LEAF, network: 'regtest' });
  const tx: Transaction = {
    version: 2,
    locktime: 0,
    inputs: [{ txid: new Uint8Array(32).fill(0x11), vout: 0, sequence: 0xffffffff }],
    outputs: [{ amount: 1000n, scriptPubKey: Uint8Array.of(0x51) }],
  };
  const spentOutputs: SpentOutput[] = [{ amount: 2000n, scriptPubKey: p2mr.scriptPubKey }];
  const sighash = (t: Transaction, spent: readonly SpentOutput[] = spentOutputs) =>
    p2mrScriptPathSighash({ tx: t, inputIndex: 0, spentOutputs: spent, leafHash: p2mr.leaves[0]!.leafHash });
  const withInput = (patch: object): Transaction => ({ ...tx, inputs: [{ ...tx.inputs[0]!, ...patch }] });
  const withOutput = (amount: bigint): Transaction => ({ ...tx, outputs: [{ ...tx.outputs[0]!, amount }] });

  const bad: Array<[string, Transaction]> = [
    ['vout 2**32', withInput({ vout: 2 ** 32 })],
    ['vout -1', withInput({ vout: -1 })],
    ['vout 1.5', withInput({ vout: 1.5 })],
    ['sequence -1', withInput({ sequence: -1 })],
    ['sequence 2**32', withInput({ sequence: 2 ** 32 })],
    ['locktime -1', { ...tx, locktime: -1 }],
    ['version 2**32', { ...tx, version: 2 ** 32 }],
    ['version -1', { ...tx, version: -1 }],
    ['output amount -1n', withOutput(-1n)],
    ['output amount 2n**64n', withOutput(2n ** 64n)],
  ];

  for (const [name, t] of bad) {
    it(`${name}: rejected by encodeTransaction and by the signature hash`, () => {
      expectCode(() => encodeTransaction(t), 'INVALID_TRANSACTION');
      expectCode(() => sighash(t), 'INVALID_TRANSACTION');
    });
  }

  it('spent output amounts out of range are rejected by the signature hash', () => {
    expectCode(() => sighash(tx, [{ ...spentOutputs[0]!, amount: -1n }]), 'INVALID_TRANSACTION');
    expectCode(() => sighash(tx, [{ ...spentOutputs[0]!, amount: 2n ** 64n }]), 'INVALID_TRANSACTION');
  });

  it('serializeOutPoint and serializeTxOutput check their fields too', () => {
    expectCode(() => serializeOutPoint({ ...tx.inputs[0]!, vout: 2 ** 32 }), 'INVALID_TRANSACTION');
    expectCode(() => serializeTxOutput({ amount: -1n, scriptPubKey: Uint8Array.of(0x51) }), 'INVALID_TRANSACTION');
  });

  it('boundary values are accepted', () => {
    const edge: Transaction = {
      version: 0xffffffff,
      locktime: 0xffffffff,
      inputs: [{ txid: new Uint8Array(32), vout: 0xffffffff, sequence: 0xffffffff }],
      outputs: [{ amount: 2n ** 64n - 1n, scriptPubKey: Uint8Array.of(0x51) }],
    };
    const raw = encodeTransaction(edge);
    expect(decodeTransaction(raw)).toMatchObject({ version: 0xffffffff, locktime: 0xffffffff });
    expect(sighash(edge, [{ amount: 2n ** 64n - 1n, scriptPubKey: p2mr.scriptPubKey }])).toHaveLength(32);
  });
});

describe('P3-4: signature hash annex handling and codesep_pos', () => {
  const p2mr = createP2mrOutput({ scriptTree: TWO_LEAF, network: 'regtest' });
  const tx: Transaction = {
    version: 2,
    locktime: 0,
    inputs: [{ txid: new Uint8Array(32).fill(0x11), vout: 0, sequence: 0xffffffff }],
    outputs: [{ amount: 1000n, scriptPubKey: Uint8Array.of(0x51) }],
  };
  const base = {
    tx,
    inputIndex: 0,
    spentOutputs: [{ amount: 2000n, scriptPubKey: p2mr.scriptPubKey }],
    leafHash: p2mr.leaves[0]!.leafHash,
  };
  const annex = Uint8Array.of(0x50, 0x01);

  it('an annex is rejected without allowAnnex, as in assembleScriptPathWitness', () => {
    expectCode(() => p2mrScriptPathSighash({ ...base, annex }), 'ANNEX_NOT_ALLOWED');
    expectCode(
      () => assembleScriptPathWitness({ leafScript: p2mr.leaves[0]!.script, controlBlock: p2mr.leaves[0]!.controlBlock, annex }),
      'ANNEX_NOT_ALLOWED',
    );
    const withAnnex = p2mrScriptPathSighash({ ...base, annex, allowAnnex: true });
    expect(bytesToHex(withAnnex)).not.toBe(bytesToHex(p2mrScriptPathSighash(base)));
  });

  // <pk> OP_CODESEPARATOR OP_CHECKSIGVERIFY OP_CODESEPARATOR <pk> OP_CHECKSIG: positions 1 and 3
  const pk = '22'.repeat(32);
  const codesepLeaf = hexToBytes(`20${pk}abadab20${pk}ac`);
  const codesepLeafHash = tapLeafHash(codesepLeaf, 0xc0);
  const codesepBase = { ...base, leafHash: codesepLeafHash, leafScript: codesepLeaf };

  it('codeSeparatorPositions counts opcodes, not bytes (BIP-342), and skips push data', () => {
    expect(codeSeparatorPositions(codesepLeaf)).toEqual([1, 3]);
    expect(codeSeparatorPositions(hexToBytes(`01ab`))).toEqual([]);
    expect(codeSeparatorPositions(hexToBytes(`ab4c01abab`))).toEqual([0, 2]);
  });

  it('with leafScript containing OP_CODESEPARATOR, codeseparatorPosition is required', () => {
    expectCode(() => p2mrScriptPathSighash(codesepBase), 'CODESEPARATOR_POSITION_REQUIRED');
    expect(p2mrScriptPathSighash({ ...codesepBase, codeseparatorPosition: 1 })).toHaveLength(32);
    expect(p2mrScriptPathSighash({ ...codesepBase, codeseparatorPosition: 3 })).toHaveLength(32);
    // Explicit 0xffffffff: a signature checked before any OP_CODESEPARATOR executed
    expect(p2mrScriptPathSighash({ ...codesepBase, codeseparatorPosition: 0xffffffff })).toHaveLength(32);
    // The digest with leafScript is the same as without it
    expect(bytesToHex(p2mrScriptPathSighash({ ...codesepBase, codeseparatorPosition: 3 }))).toBe(
      bytesToHex(p2mrScriptPathSighash({ ...base, leafHash: codesepLeafHash, codeseparatorPosition: 3 })),
    );
  });

  it('a position that is not an OP_CODESEPARATOR of the leaf is rejected', () => {
    expectCode(() => p2mrScriptPathSighash({ ...codesepBase, codeseparatorPosition: 2 }), 'INVALID_CODESEPARATOR_POSITION');
    // 33 is the byte offset of the first OP_CODESEPARATOR, not its opcode position
    expectCode(() => p2mrScriptPathSighash({ ...codesepBase, codeseparatorPosition: 33 }), 'INVALID_CODESEPARATOR_POSITION');
    const plain = { ...base, leafScript: p2mr.leaves[0]!.script };
    expect(p2mrScriptPathSighash(plain)).toHaveLength(32);
    expectCode(() => p2mrScriptPathSighash({ ...plain, codeseparatorPosition: 0 }), 'INVALID_CODESEPARATOR_POSITION');
  });

  it('leafScript must hash to leafHash', () => {
    expectCode(() => p2mrScriptPathSighash({ ...base, leafScript: codesepLeaf }), 'INVALID_LEAF_HASH');
    expectCode(
      () => p2mrScriptPathSighash({ ...codesepBase, codeseparatorPosition: 1, leafVersion: 0xc2 }),
      'INVALID_LEAF_HASH',
    );
  });
});

describe('P3-5: scriptTree and script_tree together are rejected', () => {
  it('both present -> CONFLICTING_SCRIPT_TREE, even when they are equal', () => {
    const other: ScriptTreeInput = [LEAF_B, LEAF_A];
    expectCode(
      () => createP2mrOutput({ scriptTree: TWO_LEAF, script_tree: other, network: 'regtest' }),
      'CONFLICTING_SCRIPT_TREE',
    );
    expectCode(
      () => createP2mrOutput({ scriptTree: TWO_LEAF, script_tree: TWO_LEAF, network: 'regtest' }),
      'CONFLICTING_SCRIPT_TREE',
    );
    // null / '' still count as present
    expectCode(
      () => createP2mrOutput({ scriptTree: TWO_LEAF, script_tree: null, network: 'regtest' }),
      'CONFLICTING_SCRIPT_TREE',
    );
  });

  it('either one alone still works', () => {
    const a = createP2mrOutput({ scriptTree: TWO_LEAF, network: 'regtest' });
    const b = createP2mrOutput({ script_tree: TWO_LEAF, network: 'regtest' });
    expect(bytesToHex(a.merkleRoot)).toBe(bytesToHex(b.merkleRoot));
  });
});
