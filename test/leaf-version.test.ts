import { describe, expect, it } from 'vitest';
import {
  bytesToHex,
  computeMerkleRootFromControlBlock,
  encodeControlBlock,
  P2mrError,
  parseControlBlock,
  tapLeafHash,
} from '../src/index.js';
import type { P2mrErrorCode } from '../src/index.js';

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

const SCRIPT = Uint8Array.of(0x51);

/**
 * Leaf-version shape required by the low-level tooling (tapLeafHash / encodeControlBlock):
 * an even number in 0..255. Odd values are rejected outright instead of being silently normalized
 * by & 0xfe -- otherwise 0xc1 would produce the same "correct" hash as 0xc0.
 */
describe('leaf-version shape in the low-level tooling', () => {
  it('tapLeafHash rejects odd, out-of-range and non-integer versions', () => {
    for (const bad of [0xc1, 1, 0xff, 256, -2, 1.5, Number.NaN]) {
      expectCode(() => tapLeafHash(SCRIPT, bad), 'INVALID_LEAF_VERSION');
    }
  });

  it('encodeControlBlock rejects odd versions and sets the low bit on even ones', () => {
    expectCode(() => encodeControlBlock(0xc1, []), 'INVALID_LEAF_VERSION');
    expectCode(() => encodeControlBlock(0xfb, []), 'INVALID_LEAF_VERSION');
    expect(encodeControlBlock(0xc0, [])[0]).toBe(0xc1);
    expect(encodeControlBlock(0xfa, [])[0]).toBe(0xfb);
  });

  it('all 128 even versions yield a leaf hash, and they are pairwise distinct', () => {
    const hashes = new Set<string>();
    for (let v = 0; v <= 0xfe; v += 2) {
      hashes.add(bytesToHex(tapLeafHash(SCRIPT, v)));
    }
    expect(hashes.size).toBe(128);
  });

  it('0x50 is rejected by the construction interface alone; the low-level tooling follows consensus and parses and computes as usual', () => {
    // A parsed leaf version of 0x50 (c[0]=0x51) is not rejected at the consensus layer, so the
    // low-level tooling adds no policy of its own
    const cb = Uint8Array.of(0x51);
    expect(parseControlBlock(cb).leafVersion).toBe(0x50);
    expect(bytesToHex(computeMerkleRootFromControlBlock(SCRIPT, cb))).toBe(
      bytesToHex(tapLeafHash(SCRIPT, 0x50)),
    );
  });
});
