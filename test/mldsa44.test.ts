import { ml_dsa44 } from '@noble/post-quantum/ml-dsa.js';
import { describe, expect, it } from 'vitest';
import {
  assembleMldsa44Witness,
  assertMldsa44AddressesAllowed,
  buildMldsa44LeafScript,
  bytesToHex,
  concatBytes,
  createMldsa44Output,
  createP2mrOutput,
  hexToBytes,
  isFinalAtHeight,
  MLDSA44_CONTEXT,
  MLDSA44_FAIL_LEAF_SCRIPT,
  mldsa44ActivationHeight,
  mldsa44AddressesAllowed,
  mldsa44Keygen,
  mldsa44MerkleRoot,
  mldsa44OutputMatches,
  mldsa44ProtectionStatus,
  mldsa44Sighash,
  mldsa44Sign,
  mldsa44Verify,
  OP_CHECKMLDSA44,
  P2mrError,
  p2mrScriptPathSighash,
  parseControlBlock,
  parseMldsa44LeafScript,
  SEQUENCE_FINAL,
  SIGHASH_ALL,
  SIGHASH_DEFAULT,
  SIGHASH_SINGLE,
  signMldsa44Input,
  splitMldsa44Signature,
  tapLeafHash,
  TRIPWIRED_LEAF_VERSION,
  withMldsa44FundingLockTime,
} from '../src/index.js';
import type { P2mrErrorCode, SpentOutput, Transaction } from '../src/index.js';

function expectCode(fn: () => unknown, code: P2mrErrorCode): void {
  let thrown: unknown;
  try {
    fn();
  } catch (err) {
    thrown = err;
  }
  expect(thrown).toBeInstanceOf(P2mrError);
  expect((thrown as P2mrError).code).toBe(code);
}

const KEY_A = mldsa44Keygen(new Uint8Array(32).fill(0x11));
const KEY_B = mldsa44Keygen(new Uint8Array(32).fill(0x22));
const XONLY = hexToBytes('79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798');
const H = 200;
const ACTIVE = { activationHeight: H, tipHeight: H + 6 };

const S1 = buildMldsa44LeafScript(KEY_A.publicKey);
const S2 = buildMldsa44LeafScript(KEY_A.publicKey, XONLY);

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

describe('OP_CHECKMLDSA44 leaf templates', () => {
  it('S1 is the three key chunks and the opcode, byte for byte', () => {
    const pk = KEY_A.publicKey;
    expect(S1.length).toBe(1322);
    expect(bytesToHex(S1.subarray(0, 3))).toBe('4d0802');
    expect(S1.subarray(3, 523)).toEqual(pk.subarray(0, 520));
    expect(bytesToHex(S1.subarray(523, 526))).toBe('4d0802');
    expect(S1.subarray(526, 1046)).toEqual(pk.subarray(520, 1040));
    expect(bytesToHex(S1.subarray(1046, 1049))).toBe('4d1001');
    expect(S1.subarray(1049, 1321)).toEqual(pk.subarray(1040));
    expect(S1[1321]).toBe(OP_CHECKMLDSA44);
  });

  it('S2 is S1, OP_VERIFY and a BIP-340 check', () => {
    expect(S2.length).toBe(1357);
    expect(S2.subarray(0, 1322)).toEqual(S1);
    expect(bytesToHex(S2.subarray(1322))).toBe('6920' + bytesToHex(XONLY) + 'ac');
  });

  it('parses both templates back', () => {
    expect(parseMldsa44LeafScript(S1)).toEqual({
      template: 'S1',
      publicKey: KEY_A.publicKey,
      xonlyPubkey: null,
    });
    expect(parseMldsa44LeafScript(S2)).toEqual({
      template: 'S2',
      publicKey: KEY_A.publicKey,
      xonlyPubkey: XONLY,
    });
  });

  it('rejects keys of the wrong size', () => {
    expectCode(() => buildMldsa44LeafScript(KEY_A.publicKey.subarray(1)), 'MLDSA44_INVALID_PUBLIC_KEY');
    expectCode(
      () => buildMldsa44LeafScript(concatBytes(KEY_A.publicKey, Uint8Array.of(0))),
      'MLDSA44_INVALID_PUBLIC_KEY',
    );
    expectCode(() => buildMldsa44LeafScript(KEY_A.publicKey, XONLY.subarray(1)), 'INVALID_XONLY_PUBKEY');
  });

  it('recognizes nothing but the exact templates', () => {
    const variants: Array<[string, Uint8Array]> = [
      ['empty', new Uint8Array(0)],
      ['S1 without the opcode', S1.subarray(0, 1321)],
      ['S1 with OP_CHECKSIG instead of the opcode', concatBytes(S1.subarray(0, 1321), Uint8Array.of(0xac))],
      ['OP_CODESEPARATOR before S1', concatBytes(Uint8Array.of(0xab), S1)],
      ['S1 followed by OP_NOT', concatBytes(S1, Uint8Array.of(0x91))],
      ['S1 with the first chunk pushed by OP_PUSHDATA4', concatBytes(Uint8Array.of(0x4e, 0x08, 0x02, 0, 0), S1.subarray(3))],
      ['S2 with OP_CHECKSIGVERIFY', concatBytes(S2.subarray(0, 1356), Uint8Array.of(0xad))],
      ['S2 with OP_EQUALVERIFY instead of OP_VERIFY', concatBytes(S1, Uint8Array.of(0x88), S2.subarray(1323))],
      ['S2 followed by OP_1', concatBytes(S2, Uint8Array.of(0x51))],
      ['all zero bytes of S1 length', new Uint8Array(1322)],
    ];
    for (const [, script] of variants) expect(parseMldsa44LeafScript(script)).toBeNull();
  });

  it('a generic tree with the opcode is still refused', () => {
    // 0xf0 is OP_SUCCESS240 to a generic construction; only the template builder lifts that
    expectCode(
      () => createP2mrOutput({ network: 'regtest', scriptTree: [{ script: S1 }, { script: MLDSA44_FAIL_LEAF_SCRIPT }] }),
      'OP_SUCCESS_NOT_ALLOWED',
    );
  });
});

describe('template outputs', () => {
  it('put the template leaf and the fail leaf at depth one', () => {
    for (const xonlyPubkey of [undefined, XONLY]) {
      const out = createMldsa44Output({
        publicKey: KEY_A.publicKey,
        ...(xonlyPubkey === undefined ? {} : { xonlyPubkey }),
        network: 'signet',
        chain: ACTIVE,
      });
      expect(out.template).toBe(xonlyPubkey === undefined ? 'S1' : 'S2');
      expect(out.leaves).toHaveLength(2);
      for (const leaf of out.leaves) {
        expect(leaf.depth).toBe(1);
        expect(leaf.leafVersion).toBe(0xc0);
        expect(leaf.controlBlock.length).toBe(33);
        expect(leaf.controlBlock[0]).toBe(0xc1);
      }
      expect(out.templateLeaf.script).toEqual(xonlyPubkey === undefined ? S1 : S2);
      expect(bytesToHex(out.failLeaf.script)).toBe('6a');
      expect(out.merkleRoot).toEqual(mldsa44MerkleRoot(KEY_A.publicKey, xonlyPubkey));
      expect(out.address.startsWith('tb1z')).toBe(true);
    }
  });

  it('commit to the same root in either leaf order', () => {
    const swapped = createP2mrOutput({
      network: 'regtest',
      scriptTree: [{ script: MLDSA44_FAIL_LEAF_SCRIPT }, { script: S1 }],
      allowOpSuccess: true,
    });
    expect(swapped.merkleRoot).toEqual(mldsa44MerkleRoot(KEY_A.publicKey));
  });

  it('are built for signet and regtest only', () => {
    for (const network of ['mainnet', 'testnet', undefined]) {
      expectCode(
        () =>
          createMldsa44Output({
            publicKey: KEY_A.publicKey,
            network: network as unknown as 'signet',
            chain: ACTIVE,
          }),
        'MLDSA44_NETWORK_NOT_ALLOWED',
      );
    }
    const regtest = createMldsa44Output({ publicKey: KEY_A.publicKey, network: 'regtest', chain: ACTIVE });
    expect(regtest.address.startsWith('bcrt1z')).toBe(true);
  });

  it('are refused until the tip is six blocks past activation', () => {
    const build = (chain: { activationHeight: number | null; tipHeight: number | null }) => () =>
      createMldsa44Output({ publicKey: KEY_A.publicKey, network: 'signet', chain });
    expectCode(build({ activationHeight: H, tipHeight: H + 5 }), 'MLDSA44_NOT_ACTIVE');
    expectCode(build({ activationHeight: null, tipHeight: 10_000 }), 'MLDSA44_ACTIVATION_UNKNOWN');
    expectCode(build({ activationHeight: H, tipHeight: null }), 'MLDSA44_ACTIVATION_UNKNOWN');
    expect(build({ activationHeight: H, tipHeight: H + 6 })().template).toBe('S1');
  });

  it('match only the exact template tree of the given keys', () => {
    const { scriptPubKey } = createMldsa44Output({ publicKey: KEY_A.publicKey, network: 'signet', chain: ACTIVE });
    expect(mldsa44OutputMatches({ scriptPubKey, publicKey: KEY_A.publicKey })).toBe(true);
    expect(mldsa44OutputMatches({ scriptPubKey, publicKey: KEY_B.publicKey })).toBe(false);
    expect(mldsa44OutputMatches({ scriptPubKey, publicKey: KEY_A.publicKey, xonlyPubkey: XONLY })).toBe(false);

    const other = (scriptTree: Parameters<typeof createP2mrOutput>[0]['scriptTree'], unsafe = false) =>
      createP2mrOutput({
        network: 'regtest',
        scriptTree,
        allowOpSuccess: true,
        ...(unsafe ? { allowUnsafeSingleLeaf: true, allowUnsafeLeafVersion: true } : {}),
      }).scriptPubKey;
    const classicalLeaf = concatBytes(Uint8Array.of(0x20), XONLY, Uint8Array.of(0xac));
    const lookalikes = [
      other([{ script: S1 }, { script: hexToBytes('6a6a') }]),
      other([{ script: S1 }, { script: classicalLeaf }]),
      other([{ script: S1 }, { script: MLDSA44_FAIL_LEAF_SCRIPT, leafVersion: 0xc2 }], true),
      other({ script: S1 }, true),
      other([[{ script: S1 }, { script: MLDSA44_FAIL_LEAF_SCRIPT }], { script: MLDSA44_FAIL_LEAF_SCRIPT }]),
    ];
    for (const spk of lookalikes) {
      expect(mldsa44OutputMatches({ scriptPubKey: spk, publicKey: KEY_A.publicKey })).toBe(false);
    }
    // the same root under witness version 1 is a P2TR output, not this one
    const p2tr = concatBytes(Uint8Array.of(0x51, 0x20), scriptPubKey.subarray(2));
    expect(mldsa44OutputMatches({ scriptPubKey: p2tr, publicKey: KEY_A.publicKey })).toBe(false);
  });
});

describe('activation', () => {
  it('reads the height of the buried deployment and nothing else', () => {
    const info = (entry: unknown, p2mr: unknown = { type: 'buried', active: true, height: 1 }) => ({ hash: '00', height: 5, deployments: { p2mr, p2mr_mldsa44: entry } });
    expect(mldsa44ActivationHeight(info({ type: 'buried', active: false, height: H }))).toBe(H);
    expect(mldsa44ActivationHeight(info({ type: 'buried', active: true, height: 0 }))).toBe(1);
    expect(mldsa44ActivationHeight(info({ type: 'buried', active: true, height: 0 }, { type: 'buried', active: true, height: 0 }))).toBe(0);
    expect(mldsa44ActivationHeight({ deployments: {} })).toBeNull();
    expect(mldsa44ActivationHeight(info({ type: 'bip9', height: H }))).toBeNull();
    expect(mldsa44ActivationHeight(info({ type: 'buried', height: -1 }))).toBeNull();
    expect(mldsa44ActivationHeight(info({ type: 'buried', height: 1.5 }))).toBeNull();
    expect(mldsa44ActivationHeight(info({ type: 'buried', height: '200' }))).toBeNull();
    expect(mldsa44ActivationHeight(null)).toBeNull();
    expect(mldsa44ActivationHeight('{"deployments":{}}')).toBeNull();
  });

  it('is the later of the two deployments, and unknown without either', () => {
    const both = (p2mr: unknown, mldsa44: unknown) => ({ deployments: { p2mr, p2mr_mldsa44: mldsa44 } });
    const buried = (height: number) => ({ type: 'buried', active: false, height });
    // P2MR itself activating later holds the rules back until then
    expect(mldsa44ActivationHeight(both(buried(300), buried(H)))).toBe(300);
    expect(mldsa44ActivationHeight(both(buried(1), buried(H)))).toBe(H);
    expect(mldsa44ActivationHeight(both(undefined, buried(H)))).toBeNull();
    expect(mldsa44ActivationHeight(both(buried(1), undefined))).toBeNull();
  });

  it('allows addresses from H + 6 on and stops again when a reorganization goes below', () => {
    const at = (tipHeight: number | null) => mldsa44AddressesAllowed({ activationHeight: H, tipHeight });
    expect(at(H - 1)).toBe(false);
    expect(at(H)).toBe(false);
    expect(at(H + 5)).toBe(false);
    expect(at(H + 6)).toBe(true);
    expect(at(H + 100)).toBe(true);
    // a reorganization back to H + 5: the same question, the new tip
    expect(at(H + 5)).toBe(false);
    expect(at(null)).toBe(false);
    expect(mldsa44AddressesAllowed({ activationHeight: null, tipHeight: H + 6 })).toBe(false);
    expect(mldsa44AddressesAllowed({ activationHeight: Number.NaN, tipHeight: H + 6 })).toBe(false);
    expect(() => assertMldsa44AddressesAllowed(ACTIVE)).not.toThrow();
  });
});

describe('protection status of received outputs', () => {
  const { scriptPubKey } = createMldsa44Output({ publicKey: KEY_A.publicKey, network: 'signet', chain: ACTIVE });
  const status = (confirmationHeight: number | null, activationHeight: number | null = H, spk = scriptPubKey) =>
    mldsa44ProtectionStatus({ scriptPubKey: spk, publicKey: KEY_A.publicKey, confirmationHeight, activationHeight });

  it('follows the confirmation height through a reorganization', () => {
    // an address handed out earlier receives a payment while the tip is back below H
    expect(status(null)).toBe('pending');
    expect(status(H - 1)).toBe('unprotected');
    // the reorganization unwinds and the payment confirms again above H
    expect(status(null)).toBe('pending');
    expect(status(H + 1)).toBe('protected');
    expect(status(H)).toBe('protected');
  });

  it('never protects an output whose tree is not the template tree', () => {
    const classicalOrPq = createP2mrOutput({
      network: 'regtest',
      scriptTree: [{ script: S1 }, { script: concatBytes(Uint8Array.of(0x20), XONLY, Uint8Array.of(0xac)) }],
      allowOpSuccess: true,
    }).scriptPubKey;
    expect(status(H + 10, H, classicalOrPq)).toBe('unprotected');
    expect(status(null, H, classicalOrPq)).toBe('unprotected');
  });

  it('protects nothing when H is unknown', () => {
    expect(status(H + 10, null)).toBe('unprotected');
    expect(status(-1)).toBe('unprotected');
  });
});

describe('funding transactions', () => {
  const base: Transaction = {
    version: 2,
    locktime: 0,
    inputs: [
      { txid: new Uint8Array(32).fill(1), vout: 0, sequence: SEQUENCE_FINAL },
      { txid: new Uint8Array(32).fill(2), vout: 0, sequence: 0xfffffffd },
    ],
    outputs: [{ amount: 1000n, scriptPubKey: createMldsa44Output({ publicKey: KEY_A.publicKey, network: 'signet', chain: ACTIVE }).scriptPubKey }],
  };

  it('lock the transaction out of every block up to H', () => {
    const tx = withMldsa44FundingLockTime(base, H);
    expect(tx.locktime).toBe(H);
    expect(isFinalAtHeight(tx, H - 1)).toBe(false);
    expect(isFinalAtHeight(tx, H)).toBe(false);
    expect(isFinalAtHeight(tx, H + 1)).toBe(true);
  });

  it('need an input that is not final, or the lock time would not apply', () => {
    const allFinal: Transaction = {
      ...base,
      inputs: base.inputs.map((input) => ({ ...input, sequence: SEQUENCE_FINAL })),
    };
    expectCode(() => withMldsa44FundingLockTime(allFinal, H), 'MLDSA44_FUNDING_SEQUENCE_FINAL');
    expect(isFinalAtHeight({ ...allFinal, locktime: H }, H)).toBe(true);
  });

  it('refuse lock fields that do not serialize as themselves', () => {
    const minusOne: Transaction = {
      ...base,
      inputs: base.inputs.map((input) => ({ ...input, sequence: -1 })),
    };
    // -1 would be written as 0xffffffff, which turns the lock time off
    expectCode(() => withMldsa44FundingLockTime(minusOne, H), 'INVALID_TRANSACTION');
    expectCode(() => isFinalAtHeight({ ...minusOne, locktime: H }, H), 'INVALID_TRANSACTION');
    expectCode(() => isFinalAtHeight({ ...base, locktime: -5 }, H), 'INVALID_TRANSACTION');
    expectCode(
      () => withMldsa44FundingLockTime({ ...base, inputs: [{ ...base.inputs[1]!, sequence: 1.5 }] }, H),
      'INVALID_TRANSACTION',
    );
  });

  it('take a block height, not a timestamp', () => {
    expectCode(() => withMldsa44FundingLockTime(base, 500_000_000), 'INVALID_LOCKTIME');
    expectCode(() => withMldsa44FundingLockTime(base, -1), 'INVALID_LOCKTIME');
    expectCode(() => isFinalAtHeight({ ...base, locktime: 500_000_000 }, H), 'INVALID_LOCKTIME');
    expect(isFinalAtHeight(base, 0)).toBe(true);
  });
});

describe('signatures', () => {
  const message = new Uint8Array(32).fill(0x5a);

  it('derive keys from a seed', () => {
    expect(KEY_A.publicKey.length).toBe(1312);
    expect(KEY_A.secretKey.length).toBe(2560);
    expect(mldsa44Keygen(new Uint8Array(32).fill(0x11))).toEqual(KEY_A);
    expect(mldsa44Keygen().publicKey).not.toEqual(KEY_A.publicKey);
    expectCode(() => mldsa44Keygen(new Uint8Array(31)), 'MLDSA44_INVALID_SEED');
  });

  it('sign deterministically on request and hedged by default', () => {
    const d1 = mldsa44Sign(KEY_A.secretKey, message, { extraEntropy: false });
    const d2 = mldsa44Sign(KEY_A.secretKey, message, { extraEntropy: false });
    expect(d1).toEqual(d2);
    const h1 = mldsa44Sign(KEY_A.secretKey, message);
    const h2 = mldsa44Sign(KEY_A.secretKey, message);
    expect(h1).not.toEqual(h2);
    for (const sig of [d1, h1, h2]) {
      expect(sig.length).toBe(2420);
      expect(mldsa44Verify(KEY_A.publicKey, message, sig)).toBe(true);
    }
  });

  it('verify false for anything else, without throwing', () => {
    const sig = mldsa44Sign(KEY_A.secretKey, message, { extraEntropy: false });
    const flipped = sig.slice();
    flipped[100] = (flipped[100] as number) ^ 1;
    const otherMessage = message.slice();
    otherMessage[0] = 0;
    expect(mldsa44Verify(KEY_A.publicKey, message, flipped)).toBe(false);
    expect(mldsa44Verify(KEY_B.publicKey, message, sig)).toBe(false);
    expect(mldsa44Verify(KEY_A.publicKey, otherMessage, sig)).toBe(false);
    expect(mldsa44Verify(KEY_A.publicKey, message, sig.subarray(1))).toBe(false);
    expect(mldsa44Verify(KEY_A.publicKey, message, concatBytes(sig, Uint8Array.of(1)))).toBe(false);
    expect(mldsa44Verify(KEY_A.publicKey.subarray(1), message, sig)).toBe(false);
    expect(mldsa44Verify(KEY_A.publicKey, message.subarray(1), sig)).toBe(false);
    // the same key and message under another context string, or none
    const otherContext = ml_dsa44.sign(message, KEY_A.secretKey, {
      context: new TextEncoder().encode('P2MR/MLDSA44/EXP1'),
      extraEntropy: false,
    });
    const noContext = ml_dsa44.sign(message, KEY_A.secretKey, { extraEntropy: false });
    expect(mldsa44Verify(KEY_A.publicKey, message, otherContext)).toBe(false);
    expect(mldsa44Verify(KEY_A.publicKey, message, noContext)).toBe(false);
    expect(MLDSA44_CONTEXT.length).toBe(17);
  });

  it('refuse messages and secret keys of the wrong size', () => {
    expectCode(() => mldsa44Sign(KEY_A.secretKey, message.subarray(1)), 'MLDSA44_INVALID_MESSAGE');
    expectCode(() => mldsa44Sign(KEY_A.secretKey.subarray(1), message), 'MLDSA44_INVALID_SECRET_KEY');
  });
});

describe('signing an input', () => {
  const out = createMldsa44Output({ publicKey: KEY_A.publicKey, network: 'signet', chain: ACTIVE });
  const { tx, spentOutputs } = spendOf(out.scriptPubKey);
  const leafScript = out.templateLeaf.script;

  it('signs the key_version 1 message', () => {
    const m1 = mldsa44Sighash({ tx, inputIndex: 0, spentOutputs, leafScript });
    const viaGeneric = p2mrScriptPathSighash({
      tx,
      inputIndex: 0,
      spentOutputs,
      leafHash: out.templateLeaf.leafHash,
      keyVersion: 1,
    });
    const m0 = p2mrScriptPathSighash({ tx, inputIndex: 0, spentOutputs, leafHash: out.templateLeaf.leafHash });
    expect(m1).toEqual(viaGeneric);
    expect(m1).not.toEqual(m0);

    const sig = signMldsa44Input({ secretKey: KEY_A.secretKey, tx, inputIndex: 0, spentOutputs, leafScript });
    expect(sig.length).toBe(2420);
    expect(mldsa44Verify(KEY_A.publicKey, m1, sig)).toBe(true);
    expect(mldsa44Verify(KEY_A.publicKey, m0, sig)).toBe(false);
  });

  it('signs the message of the leaf at version 0xe0 when asked, and of no other version', () => {
    const atC0 = mldsa44Sighash({ tx, inputIndex: 0, spentOutputs, leafScript });
    expect(mldsa44Sighash({ tx, inputIndex: 0, spentOutputs, leafScript, leafVersion: 0xc0 })).toEqual(atC0);
    const atE0 = mldsa44Sighash({ tx, inputIndex: 0, spentOutputs, leafScript, leafVersion: TRIPWIRED_LEAF_VERSION });
    expect(atE0).toEqual(
      p2mrScriptPathSighash({ tx, inputIndex: 0, spentOutputs, leafHash: tapLeafHash(leafScript, 0xe0), keyVersion: 1 }),
    );
    expect(atE0).not.toEqual(atC0);

    const sig = signMldsa44Input({
      secretKey: KEY_A.secretKey,
      tx,
      inputIndex: 0,
      spentOutputs,
      leafScript,
      leafVersion: TRIPWIRED_LEAF_VERSION,
    });
    expect(mldsa44Verify(KEY_A.publicKey, atE0, sig)).toBe(true);
    expect(mldsa44Verify(KEY_A.publicKey, atC0, sig)).toBe(false);

    for (const leafVersion of [0xc2, 0xe2, 0x50, 0xc1, 0xe1, 0x00]) {
      expectCode(
        () => mldsa44Sighash({ tx, inputIndex: 0, spentOutputs, leafScript, leafVersion }),
        'LEAF_VERSION_NOT_ALLOWED',
      );
    }
  });

  it('appends an explicit hash type, never SIGHASH_DEFAULT', () => {
    const sig = signMldsa44Input({
      secretKey: KEY_A.secretKey,
      tx,
      inputIndex: 0,
      spentOutputs,
      leafScript,
      hashType: SIGHASH_ALL,
    });
    expect(sig.length).toBe(2421);
    expect(sig[2420]).toBe(SIGHASH_ALL);
    const m = mldsa44Sighash({ tx, inputIndex: 0, spentOutputs, leafScript, hashType: SIGHASH_ALL });
    expect(mldsa44Verify(KEY_A.publicKey, m, sig.subarray(0, 2420))).toBe(true);
    const plain = signMldsa44Input({
      secretKey: KEY_A.secretKey,
      tx,
      inputIndex: 0,
      spentOutputs,
      leafScript,
      hashType: SIGHASH_DEFAULT,
    });
    expect(plain.length).toBe(2420);
  });

  it('refuses what the signature message refuses', () => {
    const noOutput: Transaction = { ...tx, outputs: [] };
    expectCode(
      () =>
        signMldsa44Input({
          secretKey: KEY_A.secretKey,
          tx: noOutput,
          inputIndex: 0,
          spentOutputs,
          leafScript,
          hashType: SIGHASH_SINGLE,
        }),
      'SIGHASH_SINGLE_WITHOUT_OUTPUT',
    );
    const p2tr = [{ amount: 50_000n, scriptPubKey: concatBytes(Uint8Array.of(0x51, 0x20), out.merkleRoot) }];
    expectCode(
      () => signMldsa44Input({ secretKey: KEY_A.secretKey, tx, inputIndex: 0, spentOutputs: p2tr, leafScript }),
      'NOT_A_P2MR_OUTPUT',
    );
  });
});

describe('witnesses', () => {
  const s1 = createMldsa44Output({ publicKey: KEY_A.publicKey, network: 'signet', chain: ACTIVE });
  const s2 = createMldsa44Output({ publicKey: KEY_A.publicKey, xonlyPubkey: XONLY, network: 'signet', chain: ACTIVE });
  const signature = new Uint8Array(2420).fill(7);
  const schnorr = new Uint8Array(64).fill(9);

  it('carry an S1 signature in five chunks', () => {
    const witness = assembleMldsa44Witness({
      signature,
      leafScript: s1.templateLeaf.script,
      controlBlock: s1.templateLeaf.controlBlock,
    });
    expect(witness.map((w) => w.length)).toEqual([520, 520, 520, 520, 340, 1322, 33]);
    expect(concatBytes(...witness.slice(0, 5))).toEqual(signature);
    const withHashType = assembleMldsa44Witness({
      signature: concatBytes(signature, Uint8Array.of(0x83)),
      leafScript: s1.templateLeaf.script,
      controlBlock: s1.templateLeaf.controlBlock,
    });
    expect(withHashType[4]?.length).toBe(341);
  });

  it('put the BIP-340 signature of S2 below the chunks', () => {
    const witness = assembleMldsa44Witness({
      signature,
      schnorrSignature: schnorr,
      leafScript: s2.templateLeaf.script,
      controlBlock: s2.templateLeaf.controlBlock,
    });
    expect(witness.map((w) => w.length)).toEqual([64, 520, 520, 520, 520, 340, 1357, 33]);
    expect(witness[0]).toEqual(schnorr);
    expectCode(
      () =>
        assembleMldsa44Witness({
          signature,
          leafScript: s2.templateLeaf.script,
          controlBlock: s2.templateLeaf.controlBlock,
        }),
      'MLDSA44_INVALID_WITNESS',
    );
    expectCode(
      () =>
        assembleMldsa44Witness({
          signature,
          schnorrSignature: schnorr,
          leafScript: s1.templateLeaf.script,
          controlBlock: s1.templateLeaf.controlBlock,
        }),
      'MLDSA44_INVALID_WITNESS',
    );
  });

  it('refuse other leaves and control blocks of other depths', () => {
    expectCode(
      () =>
        assembleMldsa44Witness({
          signature,
          leafScript: concatBytes(s1.templateLeaf.script, Uint8Array.of(0x91)),
          controlBlock: s1.templateLeaf.controlBlock,
        }),
      'MLDSA44_NOT_A_TEMPLATE',
    );
    for (const controlBlock of [
      Uint8Array.of(0xc1),
      concatBytes(s1.templateLeaf.controlBlock, new Uint8Array(32)),
      concatBytes(Uint8Array.of(0xc3), s1.templateLeaf.controlBlock.subarray(1)),
      // depth one, but next to a leaf that is not the fail leaf
      concatBytes(Uint8Array.of(0xc1), tapLeafHash(concatBytes(Uint8Array.of(0x20), XONLY, Uint8Array.of(0xac)), 0xc0)),
    ]) {
      expectCode(
        () => assembleMldsa44Witness({ signature, leafScript: s1.templateLeaf.script, controlBlock }),
        'MLDSA44_INVALID_CONTROL_BLOCK',
      );
    }
    expect(parseControlBlock(s1.templateLeaf.controlBlock).m).toBe(1);
  });

  it('check the hash type of a 65-byte BIP-340 signature', () => {
    const assemble = (schnorrSignature: Uint8Array) => () =>
      assembleMldsa44Witness({
        signature,
        schnorrSignature,
        leafScript: s2.templateLeaf.script,
        controlBlock: s2.templateLeaf.controlBlock,
      });
    for (const hashType of [0x00, 0x04, 0x80]) {
      expectCode(assemble(concatBytes(schnorr, Uint8Array.of(hashType))), 'INVALID_HASH_TYPE');
    }
    expect(assemble(concatBytes(schnorr, Uint8Array.of(0x01)))()[0]?.length).toBe(65);
    expectCode(assemble(new Uint8Array(63)), 'MLDSA44_INVALID_WITNESS');
  });

  it('take only signatures of the fixed sizes and valid hash types', () => {
    expectCode(() => splitMldsa44Signature(signature.subarray(1)), 'MLDSA44_INVALID_SIGNATURE_SIZE');
    expectCode(() => splitMldsa44Signature(new Uint8Array(0)), 'MLDSA44_INVALID_SIGNATURE_SIZE');
    for (const hashType of [0x00, 0x04, 0x80, 0x84]) {
      expectCode(
        () => splitMldsa44Signature(concatBytes(signature, Uint8Array.of(hashType))),
        'INVALID_HASH_TYPE',
      );
    }
    for (const hashType of [0x01, 0x02, 0x03, 0x81, 0x82, 0x83]) {
      expect(splitMldsa44Signature(concatBytes(signature, Uint8Array.of(hashType)))).toHaveLength(5);
    }
  });
});
