import { schnorr } from '@noble/curves/secp256k1.js';
import { describe, expect, it } from 'vitest';
import {
  assembleMldsa44Witness,
  assembleTripwiredWitness,
  assertTripwiredAddressesAllowed,
  buildMldsa44LeafScript,
  bytesToHex,
  computeMerkleRootFromControlBlock,
  concatBytes,
  createMldsa44Output,
  createP2mrOutput,
  createTripwiredOutput,
  encodeControlBlock,
  hexToBytes,
  MLDSA44_FAIL_LEAF_SCRIPT,
  mldsa44Keygen,
  mldsa44Sighash,
  mldsa44Verify,
  P2mrError,
  p2mrScriptPathSighash,
  parseControlBlock,
  parseMldsa44LeafScript,
  parseP2mrScriptPubKey,
  signMldsa44Input,
  tapLeafHash,
  taprootSighash,
  TRIPWIRED_LEAF_VERSION,
  tripwireActivationHeight,
  tripwiredAddressesAllowed,
  tripwiredMerkleRoot,
  tripwiredOutputMatches,
  tripwiredOutputStatus,
  tripwiredSighash,
  validateWitnessShape,
  verifyControlBlock,
} from '../src/index.js';
import type {
  P2mrErrorCode,
  P2mrLeafOutput,
  ScriptTreeInput,
  SpentOutput,
  Transaction,
  TripwireChainState,
  TripwiredPath,
} from '../src/index.js';
import { spendingTx } from '../scripts/mldsa44-crossimpl-rows.js';
import { findPython, runPythonJson } from './python.js';

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

const E0 = TRIPWIRED_LEAF_VERSION;
const SEED = new Uint8Array(32).fill(0x11);
const KEY = mldsa44Keygen(SEED);
const OTHER_KEY = mldsa44Keygen(new Uint8Array(32).fill(0x22));
/** The secret key 1: its x-only key is the x coordinate of G. */
const SCHNORR_SECRET = hexToBytes('00'.repeat(31) + '01');
const XONLY = hexToBytes('79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798');
const OTHER_XONLY = hexToBytes('c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5');
const KEYS = { xonlyPubkey: XONLY, publicKey: KEY.publicKey };
const ZERO_AUX = new Uint8Array(32);

const H3 = 300;
const ACTIVE: TripwireChainState = { tripwireHeight: H3, tipHeight: H3 + 6 };

const SCHNORR_LEAF = concatBytes(Uint8Array.of(0x20), XONLY, Uint8Array.of(0xac));
const S1 = buildMldsa44LeafScript(KEY.publicKey);
const S2 = buildMldsa44LeafScript(KEY.publicKey, XONLY);

/**
 * The S3 output of KEYS, as test/py/tripwire_ref_dump.py computes it from the BIP-360 reference
 * implementation and the Core v29.0 test framework, sharing no code with this library. The
 * signature hashes are those of the Schnorr leaf on `spendingTx` of its scriptPubKey.
 */
const VECTORS = {
  leafHashes: {
    schnorr: {
      e0: 'd1e14a231a1777ee4dd6eff90c98cb31f7015b03611c24fb83a1d2f981fa48c9',
      c0: '763e9da064b9dc0471fb0f3c8fa2c84b4b84d2ca992497c12d2274386795aa8e',
    },
    mldsa44: {
      e0: 'e9a5ed74532802fe51a9871186186422ad89a0e3d370ceb8f79c9efcbeb44c4c',
      c0: 'af53e8b3b6382b23a146b3930c16f4f9d98d8ea58ba12724a7a77ee15a38df89',
    },
  },
  merkleRoot: '26c2f880794474aa0ca9f1a5232464e58d1db29605dd7723c8432d0b9201e855',
  controlBlocks: [
    'e1e9a5ed74532802fe51a9871186186422ad89a0e3d370ceb8f79c9efcbeb44c4c',
    'e1d1e14a231a1777ee4dd6eff90c98cb31f7015b03611c24fb83a1d2f981fa48c9',
  ],
  addresses: {
    tb: 'tb1zymp03qreg3625r9f7xjjxfryukx3mv5kqhwhwg7ggvkshyspap2smr2xaq',
    bcrt: 'bcrt1zymp03qreg3625r9f7xjjxfryukx3mv5kqhwhwg7ggvkshyspap2sk6qqg6',
  },
  sighashes: [
    {
      hash_type: 0x00,
      e0: 'bfa9109bd2b72f2209017b84b3d34f1a210f893d35e8aac440cbad19c87161ef',
      c0: 'da3b7c859813f05cd3b3a613467b53140d56d4bcc938d0217c027a65ffbb979d',
    },
    {
      hash_type: 0x83,
      e0: 'c19f8686798424765009c17dae1ddecce7054639be4b5685f7fa64cf79f47996',
      c0: 'cbf65e53f0f10037e9fcbb16e28aa94d0e39a8e110c169ec1da9cc2e0a35722c',
    },
  ],
};

/** A one-input, one-output spend of `spk`, the shape a wallet signs. */
function spendOf(spk: Uint8Array, amount = 50_000n): { tx: Transaction; spentOutputs: SpentOutput[] } {
  const tx: Transaction = {
    version: 2,
    locktime: 0,
    inputs: [{ txid: new Uint8Array(32).fill(0xaa), vout: 1, sequence: 0xfffffffd }],
    outputs: [{ amount: amount - 1000n, scriptPubKey: hexToBytes('0014' + '11'.repeat(20)) }],
  };
  return { tx, spentOutputs: [{ amount, scriptPubKey: spk }] };
}

/** Any tree, with every construction check of the generic builder lifted. */
function anyTree(scriptTree: ScriptTreeInput): Uint8Array {
  return createP2mrOutput({
    scriptTree,
    allowUnsafeLeafVersion: true,
    allowUnsafeSingleLeaf: true,
    allowOpSuccess: true,
  }).scriptPubKey;
}

function flipBit(script: Uint8Array, offset: number): Uint8Array {
  const copy = script.slice();
  copy[offset] = (copy[offset] as number) ^ 0x01;
  return copy;
}

type Verdict = 'valid' | 'invalid signature' | 'not committed' | 'not executed' | 'other leaf';

/**
 * What a node with the tripwire rules active, the checks still on, makes of the spend of input
 * `inputIndex` through a `<key> OP_CHECKSIG` or an S1 leaf, from this library's parts and a BIP-340
 * verifier: the leaf and control block must commit to the spent output, the leaf must be executed,
 * and the signature must verify over the message of the leaf at its own version.
 */
function verdict(witness: Uint8Array[], tx: Transaction, spentOutputs: SpentOutput[], inputIndex = 0): Verdict {
  const shape = validateWitnessShape(witness);
  expect(shape.valid).toBe(true);
  if (!shape.valid) throw new Error('unreachable');
  const { leafScript, controlBlock, parsedControlBlock: cb, stack } = shape;
  const merkleRoot = parseP2mrScriptPubKey((spentOutputs[inputIndex] as SpentOutput).scriptPubKey);
  if (!verifyControlBlock({ leafScript, controlBlock, merkleRoot })) return 'not committed';
  if (cb.m === 0 || (cb.leafVersion !== 0xc0 && cb.leafVersion !== E0)) return 'not executed';
  const base = { tx, inputIndex, spentOutputs };
  if (leafScript.length === 34 && leafScript[0] === 0x20 && leafScript[33] === 0xac) {
    const sig = stack[0] as Uint8Array;
    const message = p2mrScriptPathSighash({
      ...base,
      hashType: sig.length === 65 ? (sig[64] as number) : 0x00,
      leafHash: tapLeafHash(leafScript, cb.leafVersion),
    });
    return schnorr.verify(sig.subarray(0, 64), message, leafScript.subarray(1, 33)) ? 'valid' : 'invalid signature';
  }
  const parsed = parseMldsa44LeafScript(leafScript);
  if (parsed === null || parsed.template !== 'S1') return 'other leaf';
  const sig = concatBytes(...stack);
  const message = mldsa44Sighash({
    ...base,
    hashType: sig.length === 2421 ? (sig[2420] as number) : 0x00,
    leafScript,
    leafVersion: cb.leafVersion,
  });
  return mldsa44Verify(parsed.publicKey, message, sig.subarray(0, 2420)) ? 'valid' : 'invalid signature';
}

describe('leaf version 0xe0', () => {
  it('fixtures: the secret key 1 has the x-only key of the vectors', () => {
    expect(schnorr.getPublicKey(SCHNORR_SECRET)).toEqual(XONLY);
  });

  it('is in the TapLeaf hash, so a leaf of version 0xe0 and the same script at 0xc0 differ', () => {
    expect(bytesToHex(tapLeafHash(SCHNORR_LEAF, E0))).toBe(VECTORS.leafHashes.schnorr.e0);
    expect(bytesToHex(tapLeafHash(SCHNORR_LEAF, 0xc0))).toBe(VECTORS.leafHashes.schnorr.c0);
    expect(bytesToHex(tapLeafHash(S1, E0))).toBe(VECTORS.leafHashes.mldsa44.e0);
    expect(bytesToHex(tapLeafHash(S1, 0xc0))).toBe(VECTORS.leafHashes.mldsa44.c0);
  });

  it('starts its control block with 0xe1; 0xe0 as the first byte is refused', () => {
    const sibling = hexToBytes(VECTORS.leafHashes.mldsa44.e0);
    const cb = encodeControlBlock(E0, [sibling]);
    expect(bytesToHex(cb)).toBe(VECTORS.controlBlocks[0]);
    expect(parseControlBlock(cb)).toEqual({ leafVersion: E0, parityBit: 1, m: 1, merklePath: [sibling] });
    expectCode(() => parseControlBlock(concatBytes(Uint8Array.of(0xe0), sibling)), 'INVALID_CONTROL_BLOCK_PARITY');
    expectCode(() => encodeControlBlock(0xe1, [sibling]), 'INVALID_LEAF_VERSION');
  });

  it('is still refused by the generic builder unless explicitly allowed', () => {
    const scriptTree = [
      { script: SCHNORR_LEAF, leafVersion: E0 },
      { script: MLDSA44_FAIL_LEAF_SCRIPT, leafVersion: E0 },
    ];
    expectCode(() => createP2mrOutput({ scriptTree }), 'LEAF_VERSION_NOT_ALLOWED');
    expect(createP2mrOutput({ scriptTree, allowUnsafeLeafVersion: true }).leaves[0]?.controlBlock[0]).toBe(0xe1);
  });
});

describe('S3 outputs', () => {
  it('have two leaves of version 0xe0 at depth one, against fixed vectors', () => {
    const out = createTripwiredOutput({ ...KEYS, network: 'signet', chain: ACTIVE });
    expect(bytesToHex(out.merkleRoot)).toBe(VECTORS.merkleRoot);
    expect(bytesToHex(tripwiredMerkleRoot(KEYS))).toBe(VECTORS.merkleRoot);
    expect(bytesToHex(out.scriptPubKey)).toBe(`5220${VECTORS.merkleRoot}`);
    expect(out.address).toBe(VECTORS.addresses.tb);
    expect(out.leaves).toEqual([out.schnorrLeaf, out.mldsa44Leaf]);
    expect(out.schnorrLeaf.script).toEqual(SCHNORR_LEAF);
    expect(out.mldsa44Leaf.script).toEqual(S1);
    expect(out.leaves.map((leaf) => bytesToHex(leaf.controlBlock))).toEqual(VECTORS.controlBlocks);
    for (const leaf of out.leaves) {
      expect(leaf.depth).toBe(1);
      expect(leaf.leafVersion).toBe(E0);
      expect(computeMerkleRootFromControlBlock(leaf.script, leaf.controlBlock)).toEqual(out.merkleRoot);
    }
    const regtest = createTripwiredOutput({ ...KEYS, network: 'regtest', chain: ACTIVE });
    expect(regtest.address).toBe(VECTORS.addresses.bcrt);
  });

  it('are built for signet and regtest only', () => {
    for (const network of ['mainnet', 'testnet', undefined]) {
      expectCode(
        () => createTripwiredOutput({ ...KEYS, network: network as unknown as 'signet', chain: ACTIVE }),
        'TRIPWIRED_NETWORK_NOT_ALLOWED',
      );
    }
  });

  it('are refused until the tip is six blocks past H3', () => {
    const build = (chain: TripwireChainState) => () => createTripwiredOutput({ ...KEYS, network: 'signet', chain });
    expectCode(build({ tripwireHeight: H3, tipHeight: H3 + 5 }), 'TRIPWIRED_NOT_ACTIVE');
    expectCode(build({ tripwireHeight: null, tipHeight: 10_000 }), 'TRIPWIRED_ACTIVATION_UNKNOWN');
    expectCode(build({ tripwireHeight: H3, tipHeight: null }), 'TRIPWIRED_ACTIVATION_UNKNOWN');
    // a chain state made for the template outputs carries H, not H3, and is not taken for one
    const m1Shaped = { activationHeight: 1, tipHeight: H3 + 6 } as unknown as TripwireChainState;
    expectCode(build(m1Shaped), 'TRIPWIRED_ACTIVATION_UNKNOWN');
    expect(build({ tripwireHeight: H3, tipHeight: H3 + 6 })().address).toBe(VECTORS.addresses.tb);
  });

  it('refuse keys of the wrong size', () => {
    const build = (xonlyPubkey: Uint8Array, publicKey: Uint8Array) => () =>
      createTripwiredOutput({ xonlyPubkey, publicKey, network: 'signet', chain: ACTIVE });
    expectCode(build(XONLY.subarray(1), KEY.publicKey), 'INVALID_XONLY_PUBKEY');
    expectCode(build(concatBytes(Uint8Array.of(0x02), XONLY), KEY.publicKey), 'INVALID_XONLY_PUBKEY');
    expectCode(build(XONLY, KEY.publicKey.subarray(1)), 'MLDSA44_INVALID_PUBLIC_KEY');
    expectCode(() => tripwiredMerkleRoot({ xonlyPubkey: XONLY, publicKey: XONLY }), 'MLDSA44_INVALID_PUBLIC_KEY');
  });
});

describe('the S3 check', () => {
  const { scriptPubKey } = createTripwiredOutput({ ...KEYS, network: 'signet', chain: ACTIVE });

  it('holds for the S3 output of the keys, in either leaf order', () => {
    expect(tripwiredOutputMatches({ ...KEYS, scriptPubKey })).toBe(true);
    const swapped = anyTree([
      { script: S1, leafVersion: E0 },
      { script: SCHNORR_LEAF, leafVersion: E0 },
    ]);
    expect(tripwiredOutputMatches({ ...KEYS, scriptPubKey: swapped })).toBe(true);
  });

  it('fails for other keys', () => {
    expect(tripwiredOutputMatches({ xonlyPubkey: OTHER_XONLY, publicKey: KEY.publicKey, scriptPubKey })).toBe(false);
    expect(tripwiredOutputMatches({ xonlyPubkey: XONLY, publicKey: OTHER_KEY.publicKey, scriptPubKey })).toBe(false);
  });

  it('fails for every tree that is not exactly S3', () => {
    const a = { script: SCHNORR_LEAF, leafVersion: E0 };
    const b = { script: S1, leafVersion: E0 };
    const fail = { script: MLDSA44_FAIL_LEAF_SCRIPT, leafVersion: E0 };
    const lookalikes: Array<[string, Uint8Array]> = [
      ['a third leaf next to the two', anyTree([[a, b], fail])],
      ['the ML-DSA-44 leaf one level deeper', anyTree([a, [b, fail]])],
      ['the Schnorr leaf twice', anyTree([a, a])],
      ['the Schnorr leaf at version 0xc0', anyTree([{ ...a, leafVersion: 0xc0 }, b])],
      ['the ML-DSA-44 leaf at version 0xc0', anyTree([a, { ...b, leafVersion: 0xc0 }])],
      ['both leaves at version 0xc0', anyTree([{ ...a, leafVersion: 0xc0 }, { ...b, leafVersion: 0xc0 }])],
      ['both leaves at version 0xe2', anyTree([{ ...a, leafVersion: 0xe2 }, { ...b, leafVersion: 0xe2 }])],
      ['OP_CHECKSIGVERIFY in place of OP_CHECKSIG', anyTree([{ ...a, script: concatBytes(SCHNORR_LEAF.subarray(0, 33), Uint8Array.of(0xad)) }, b])],
      ['one bit of the x-only key flipped', anyTree([{ ...a, script: flipBit(SCHNORR_LEAF, 1) }, b])],
      ['one bit of the ML-DSA-44 key flipped', anyTree([a, { ...b, script: flipBit(S1, 1000) }])],
      ['OP_CODESEPARATOR in front of S1', anyTree([a, { ...b, script: concatBytes(Uint8Array.of(0xab), S1) }])],
      ['both checks in one leaf (S2), next to OP_RETURN', anyTree([{ ...b, script: S2 }, fail])],
      ['both checks in one leaf (S2), next to the Schnorr leaf', anyTree([a, { ...b, script: S2 }])],
      ['the Schnorr leaf alone (m = 0)', anyTree(a)],
      ['the ML-DSA-44 leaf alone (m = 0)', anyTree(b)],
      ['the S1 template output of OP_CHECKMLDSA44', createMldsa44Output({ publicKey: KEY.publicKey, network: 'signet', chain: { activationHeight: 1, tipHeight: 7 } }).scriptPubKey],
      ['the same root under witness version 1', concatBytes(Uint8Array.of(0x51, 0x20), scriptPubKey.subarray(2))],
    ];
    for (const [name, spk] of lookalikes) {
      expect(tripwiredOutputMatches({ ...KEYS, scriptPubKey: spk }), name).toBe(false);
    }
  });
});

describe('activation', () => {
  const buried = (height: unknown) => ({ type: 'buried', active: false, height });
  const info = (p2mr: unknown, mldsa44: unknown, tripwire: unknown) => ({
    deployments: { p2mr, p2mr_mldsa44: mldsa44, p2mr_tripwire: tripwire },
  });

  it('is the highest of the p2mr, p2mr_mldsa44 and p2mr_tripwire heights', () => {
    expect(tripwireActivationHeight(info(buried(1), buried(200), buried(H3)))).toBe(H3);
    expect(tripwireActivationHeight(info(buried(1), buried(400), buried(H3)))).toBe(400);
    expect(tripwireActivationHeight(info(buried(500), buried(200), buried(H3)))).toBe(500);
    expect(tripwireActivationHeight(info(buried(0), buried(0), buried(0)))).toBe(0);
  });

  it('is unknown without any one of them, or with a height that is not one', () => {
    expect(tripwireActivationHeight(info(buried(1), buried(200), undefined))).toBeNull();
    expect(tripwireActivationHeight(info(buried(1), undefined, buried(H3)))).toBeNull();
    expect(tripwireActivationHeight(info(undefined, buried(200), buried(H3)))).toBeNull();
    expect(tripwireActivationHeight(info(buried(1), buried(200), { type: 'bip9', height: H3 }))).toBeNull();
    for (const height of [-1, 1.5, '300', null]) {
      expect(tripwireActivationHeight(info(buried(1), buried(200), buried(height)))).toBeNull();
    }
    expect(tripwireActivationHeight({ deployments: {} })).toBeNull();
    expect(tripwireActivationHeight(null)).toBeNull();
    expect(tripwireActivationHeight('{"deployments":{}}')).toBeNull();
  });

  it('allows addresses from H3 + 6 on and stops again when a reorganization goes below', () => {
    const at = (tipHeight: number | null) => tripwiredAddressesAllowed({ tripwireHeight: H3, tipHeight });
    expect(at(H3 - 1)).toBe(false);
    expect(at(H3)).toBe(false);
    expect(at(H3 + 5)).toBe(false);
    expect(at(H3 + 6)).toBe(true);
    expect(at(H3 + 100)).toBe(true);
    expect(at(H3 + 5)).toBe(false);
    expect(at(null)).toBe(false);
    expect(tripwiredAddressesAllowed({ tripwireHeight: null, tipHeight: H3 + 6 })).toBe(false);
    expect(tripwiredAddressesAllowed({ tripwireHeight: Number.NaN, tipHeight: H3 + 6 })).toBe(false);
    expect(() => assertTripwiredAddressesAllowed(ACTIVE)).not.toThrow();
  });
});

describe('status of received outputs', () => {
  const { scriptPubKey } = createTripwiredOutput({ ...KEYS, network: 'signet', chain: ACTIVE });
  const status = (confirmationHeight: number | null, tripwireHeight: number | null = H3, spk = scriptPubKey) =>
    tripwiredOutputStatus({ ...KEYS, scriptPubKey: spk, confirmationHeight, tripwireHeight });

  it('follows the confirmation height through a reorganization', () => {
    expect(status(null)).toBe('pending');
    expect(status(H3 - 1)).toBe('unprotected');
    expect(status(null)).toBe('pending');
    expect(status(H3)).toBe('constrained');
    expect(status(H3 + 1)).toBe('constrained');
  });

  it('is unprotected for any other tree, and when H3 is unknown', () => {
    const c0 = anyTree([{ script: SCHNORR_LEAF }, { script: S1 }]);
    expect(status(H3 + 10, H3, c0)).toBe('unprotected');
    expect(status(null, H3, c0)).toBe('unprotected');
    expect(status(H3 + 10, null)).toBe('unprotected');
    expect(status(-1)).toBe('unprotected');
  });
});

describe('signature messages', () => {
  const { scriptPubKey } = createTripwiredOutput({ ...KEYS, network: 'signet', chain: ACTIVE });
  const fixture = { ...spendingTx(scriptPubKey), inputIndex: 0 };

  it('of the Schnorr leaf are the BIP-342 message over the TapLeaf hash at 0xe0', () => {
    for (const { hash_type: hashType, e0, c0 } of VECTORS.sighashes) {
      expect(bytesToHex(tripwiredSighash({ ...KEYS, ...fixture, hashType, path: 'schnorr' }))).toBe(e0);
      const atC0 = p2mrScriptPathSighash({ ...fixture, hashType, leafHash: tapLeafHash(SCHNORR_LEAF, 0xc0) });
      expect(bytesToHex(atC0)).toBe(c0);
    }
  });

  it('of the ML-DSA-44 leaf are the key_version 1 message over the TapLeaf hash at 0xe0', () => {
    for (const hashType of [0x00, 0x01, 0x83]) {
      const m = tripwiredSighash({ ...KEYS, ...fixture, hashType, path: 'mldsa44' });
      expect(m).toEqual(mldsa44Sighash({ ...fixture, hashType, leafScript: S1, leafVersion: E0 }));
      expect(m).toEqual(taprootSighash({ ...fixture, hashType, extFlag: 1, leafHash: tapLeafHash(S1, E0), keyVersion: 1 }));
      expect(m).not.toEqual(mldsa44Sighash({ ...fixture, hashType, leafScript: S1 }));
    }
  });

  it('keep their key_version whatever else an untyped caller passes', () => {
    const extra = { keyVersion: 1, leafHash: new Uint8Array(32), leafVersion: 0xc0 } as object;
    for (const path of ['schnorr', 'mldsa44'] as const) {
      expect(tripwiredSighash({ ...KEYS, ...fixture, ...extra, path })).toEqual(tripwiredSighash({ ...KEYS, ...fixture, path }));
    }
  });

  it('refuse a path that is neither leaf', () => {
    expectCode(
      () => tripwiredSighash({ ...KEYS, ...fixture, path: 'both' as unknown as TripwiredPath }),
      'TRIPWIRED_INVALID_PATH',
    );
  });
});

describe('spends of an S3 output', () => {
  const out = createTripwiredOutput({ ...KEYS, network: 'signet', chain: ACTIVE });
  const { tx, spentOutputs } = spendOf(out.scriptPubKey);
  const base = { ...KEYS, tx, inputIndex: 0, spentOutputs };

  it('through the Schnorr leaf: a BIP-340 signature over tripwiredSighash', () => {
    for (const hashType of [0x00, 0x01, 0x83]) {
      const message = tripwiredSighash({ ...base, hashType, path: 'schnorr' });
      const sig = schnorr.sign(message, SCHNORR_SECRET, ZERO_AUX);
      const signature = hashType === 0x00 ? sig : concatBytes(sig, Uint8Array.of(hashType));
      const witness = assembleTripwiredWitness({ ...KEYS, path: 'schnorr', signature });
      expect(witness).toEqual([signature, out.schnorrLeaf.script, out.schnorrLeaf.controlBlock]);
      expect(verdict(witness, tx, spentOutputs)).toBe('valid');
    }
  });

  it('through the ML-DSA-44 leaf: signMldsa44Input with leaf version 0xe0', () => {
    for (const hashType of [0x00, 0x83]) {
      const signature = signMldsa44Input({
        ...base,
        hashType,
        leafScript: out.mldsa44Leaf.script,
        leafVersion: out.mldsa44Leaf.leafVersion,
        secretKey: KEY.secretKey,
      });
      const message = tripwiredSighash({ ...base, hashType, path: 'mldsa44' });
      expect(mldsa44Verify(KEY.publicKey, message, signature.subarray(0, 2420))).toBe(true);
      const witness = assembleTripwiredWitness({ ...KEYS, path: 'mldsa44', signature });
      expect(witness.slice(5)).toEqual([out.mldsa44Leaf.script, out.mldsa44Leaf.controlBlock]);
      expect(concatBytes(...witness.slice(0, 5))).toEqual(signature);
      expect(verdict(witness, tx, spentOutputs)).toBe('valid');
    }
  });

  it('do not take a signature made for the same leaf at version 0xc0', () => {
    const schnorrAtC0 = p2mrScriptPathSighash({ tx, inputIndex: 0, spentOutputs, leafHash: tapLeafHash(SCHNORR_LEAF, 0xc0) });
    const schnorrWitness = assembleTripwiredWitness({
      ...KEYS,
      path: 'schnorr',
      signature: schnorr.sign(schnorrAtC0, SCHNORR_SECRET, ZERO_AUX),
    });
    expect(verdict(schnorrWitness, tx, spentOutputs)).toBe('invalid signature');

    const mldsa44AtC0 = signMldsa44Input({ tx, inputIndex: 0, spentOutputs, leafScript: S1, secretKey: KEY.secretKey });
    const mldsa44Witness = assembleTripwiredWitness({ ...KEYS, path: 'mldsa44', signature: mldsa44AtC0 });
    expect(verdict(mldsa44Witness, tx, spentOutputs)).toBe('invalid signature');
  });

  it('give signatures that a leaf of version 0xc0 does not take either', () => {
    // the Schnorr address of a wallet: <key> OP_CHECKSIG next to OP_RETURN, both 0xc0
    const c0 = createP2mrOutput({ scriptTree: [{ script: SCHNORR_LEAF }, { script: MLDSA44_FAIL_LEAF_SCRIPT }] });
    const spend = spendOf(c0.scriptPubKey);
    const witnessFor = (message: Uint8Array) => [
      schnorr.sign(message, SCHNORR_SECRET, ZERO_AUX),
      SCHNORR_LEAF,
      (c0.leaves[0] as P2mrLeafOutput).controlBlock,
    ];
    const atE0 = tripwiredSighash({ ...KEYS, ...spend, inputIndex: 0, path: 'schnorr' });
    const atC0 = p2mrScriptPathSighash({ ...spend, inputIndex: 0, leafHash: tapLeafHash(SCHNORR_LEAF, 0xc0) });
    expect(verdict(witnessFor(atE0), spend.tx, spend.spentOutputs)).toBe('invalid signature');
    expect(verdict(witnessFor(atC0), spend.tx, spend.spentOutputs)).toBe('valid');

    // the S1 template output of OP_CHECKMLDSA44, version 0xc0
    const m1 = createMldsa44Output({ publicKey: KEY.publicKey, network: 'signet', chain: { activationHeight: 1, tipHeight: 7 } });
    const m1Spend = { ...spendOf(m1.scriptPubKey), inputIndex: 0, leafScript: S1, secretKey: KEY.secretKey };
    const m1Witness = (signature: Uint8Array) =>
      assembleMldsa44Witness({ signature, leafScript: S1, controlBlock: m1.templateLeaf.controlBlock });
    const signedAtE0 = signMldsa44Input({ ...m1Spend, leafVersion: E0 });
    const signedAtC0 = signMldsa44Input(m1Spend);
    expect(verdict(m1Witness(signedAtE0), m1Spend.tx, m1Spend.spentOutputs)).toBe('invalid signature');
    expect(verdict(m1Witness(signedAtC0), m1Spend.tx, m1Spend.spentOutputs)).toBe('valid');
  });
});

describe('witnesses of an S3 spend', () => {
  const mldsa44Signature = new Uint8Array(2420).fill(7);
  const schnorrSignature = new Uint8Array(64).fill(9);
  const assemble = (path: TripwiredPath, signature: Uint8Array) => () =>
    assembleTripwiredWitness({ ...KEYS, path, signature });

  it('carry the ML-DSA-44 signature in five chunks, next to the Schnorr leaf', () => {
    const witness = assemble('mldsa44', mldsa44Signature)();
    expect(witness.map((w) => w.length)).toEqual([520, 520, 520, 520, 340, 1322, 33]);
    expect(bytesToHex(witness[6] as Uint8Array)).toBe(VECTORS.controlBlocks[1]);
    expect(assemble('mldsa44', concatBytes(mldsa44Signature, Uint8Array.of(0x81)))()[4]?.length).toBe(341);
    expectCode(assemble('mldsa44', mldsa44Signature.subarray(1)), 'MLDSA44_INVALID_SIGNATURE_SIZE');
    expectCode(assemble('mldsa44', concatBytes(mldsa44Signature, Uint8Array.of(0x00))), 'INVALID_HASH_TYPE');
  });

  it('carry the BIP-340 signature next to the ML-DSA-44 leaf', () => {
    const witness = assemble('schnorr', schnorrSignature)();
    expect(witness.map((w) => w.length)).toEqual([64, 34, 33]);
    expect(bytesToHex(witness[2] as Uint8Array)).toBe(VECTORS.controlBlocks[0]);
    for (const hashType of [0x01, 0x02, 0x03, 0x81, 0x82, 0x83]) {
      expect(assemble('schnorr', concatBytes(schnorrSignature, Uint8Array.of(hashType)))()[0]?.length).toBe(65);
    }
    for (const hashType of [0x00, 0x04, 0x80, 0x84]) {
      expectCode(assemble('schnorr', concatBytes(schnorrSignature, Uint8Array.of(hashType))), 'INVALID_HASH_TYPE');
    }
    for (const size of [0, 63, 66, 2420]) {
      expectCode(assemble('schnorr', new Uint8Array(size)), 'TRIPWIRED_INVALID_SIGNATURE_SIZE');
    }
  });

  it('refuse a path that is neither leaf, and keys of the wrong size', () => {
    expectCode(assemble('S3' as unknown as TripwiredPath, schnorrSignature), 'TRIPWIRED_INVALID_PATH');
    expectCode(
      () => assembleTripwiredWitness({ xonlyPubkey: XONLY.subarray(1), publicKey: KEY.publicKey, path: 'schnorr', signature: schnorrSignature }),
      'INVALID_XONLY_PUBKEY',
    );
    expectCode(
      () => assembleTripwiredWitness({ xonlyPubkey: XONLY, publicKey: KEY.publicKey.subarray(1), path: 'schnorr', signature: schnorrSignature }),
      'MLDSA44_INVALID_PUBLIC_KEY',
    );
  });
});

const python = findPython();

interface RefDump {
  python: string;
  public_key: string;
  leaf_scripts: { schnorr: string; mldsa44: string };
  leaf_hashes: typeof VECTORS.leafHashes;
  merkle_root: string;
  control_blocks: string[];
  addresses: typeof VECTORS.addresses;
  sighashes: typeof VECTORS.sighashes;
}

describe.skipIf(python === null)('fixed vectors against the BIP-360 reference implementation and the Core test framework', () => {
  it('are what they compute, without this library', () => {
    const dump = runPythonJson<RefDump>(
      python as string,
      'test/py/tripwire_ref_dump.py',
      JSON.stringify({
        seed: bytesToHex(SEED),
        xonly: bytesToHex(XONLY),
        hash_types: VECTORS.sighashes.map((s) => s.hash_type),
      }),
    );
    expect(dump.python.startsWith('3.')).toBe(true);
    expect(dump.public_key).toBe(bytesToHex(KEY.publicKey));
    expect(dump.leaf_scripts).toEqual({ schnorr: bytesToHex(SCHNORR_LEAF), mldsa44: bytesToHex(S1) });
    expect(dump.leaf_hashes).toEqual(VECTORS.leafHashes);
    expect(dump.merkle_root).toBe(VECTORS.merkleRoot);
    expect(dump.control_blocks).toEqual(VECTORS.controlBlocks);
    expect(dump.addresses).toEqual(VECTORS.addresses);
    expect(dump.sighashes).toEqual(VECTORS.sighashes);
  });
});
