/**
 * Regression tests for the findings of the independent review of commit c2501dff.
 *
 * The fixture values (roots, addresses, leaf hashes) were computed independently by the review and
 * are re-checked here against this library.
 */
import { describe, expect, it } from 'vitest';
import { createP2mrOutput, P2mrError } from '../src/index.js';
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
