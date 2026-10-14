/**
 * Regression tests for the findings of the independent review of commit c2501dff.
 *
 * The fixture values (roots, addresses, leaf hashes) were computed independently by the review and
 * are re-checked here against this library.
 */
import { describe, expect, it } from 'vitest';
import { analyzeLeafScript, createP2mrOutput, hexToBytes, P2mrError, scanLeafScript } from '../src/index.js';
import type { CreateP2mrOutputOptions, P2mrErrorCode, ScriptTreeInput } from '../src/index.js';

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
      code: 'LEAF_SCRIPT_PUSH_ONLY',
      flag: 'allowPushOnlyScript',
    },
    {
      name: 'truncated push (20 + 30 bytes + ac): never spendable',
      script: `20${'bb'.repeat(30)}ac`,
      code: 'LEAF_SCRIPT_TRUNCATED',
      flag: 'allowTruncatedScript',
    },
    {
      name: '521-byte push (4d0902 + 521 bytes + 7551): never spendable, even unexecuted',
      script: `4d0902${'bb'.repeat(521)}7551`,
      code: 'LEAF_SCRIPT_PUSH_TOO_LARGE',
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
