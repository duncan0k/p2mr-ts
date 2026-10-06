/**
 * Script test rows for the tripwired leaves (leaf version 0xe0, the M3 rules of the Ark-0 signet)
 * signed by this library.
 *
 * Each row has the shape of a row of Bitcoin Core's `src/test/data/script_tests.json`:
 * `[[witness..., amount], scriptSig, scriptPubKey, flags, expected error, comment]`. The
 * transactions are the pair `script_json_test` builds for a row, so the same rows run through
 * Core's interpreter there and through this library's checks here. Every output, witness and
 * signature message is made by this library, every ML-DSA-44 signature by @noble/post-quantum and
 * every BIP-340 signature by @noble/curves; nothing is copied from Core.
 *
 * The rows run with the tripwire rules active, the elliptic curve checks on (ENABLED) or off
 * (DISABLED). All signatures are reproducible: the deterministic variant of FIPS 204, or the hedged
 * one with fixed randomness, and BIP-340 with zero auxiliary randomness.
 */
import { schnorr } from '@noble/curves/secp256k1.js';
import { sha256 } from '@noble/hashes/sha2.js';
import {
  assembleMldsa44Witness,
  assembleTripwiredWitness,
  buildMldsa44LeafScript,
  bytesToHex,
  concatBytes,
  encodeControlBlock,
  MLDSA44_FAIL_LEAF_SCRIPT,
  mldsa44Keygen,
  mldsa44MerkleRoot,
  mldsa44Sighash,
  mldsa44Sign,
  p2mrScriptPathSighash,
  signMldsa44Input,
  splitMldsa44Signature,
  tapBranchHash,
  tapLeafHash,
  TRIPWIRED_LEAF_VERSION,
  tripwiredMerkleRoot,
  tripwiredSighash,
} from '../src/index.js';
import type { TripwiredKeys } from '../src/index.js';
import { AMOUNT_BTC, spendingTx } from './mldsa44-crossimpl-rows.js';
import type { CrossImplRow } from './mldsa44-crossimpl-rows.js';

export const BLOCK_HEADER = 'P2MR tripwired leaf (version 0xe0) rows signed by p2mr-ts';
/** The tripwire rules active, with OP_CHECKMLDSA44, and the elliptic curve checks on. */
export const ENABLED = 'P2SH,WITNESS,TAPROOT,P2MR,P2MR_MLDSA44,P2MR_TRIPWIRE';
/** The same, with the elliptic curve checks in leaves of version 0xe0 off. */
export const DISABLED = `${ENABLED},P2MR_EC_DISABLED`;

const label = (text: string) => sha256(new TextEncoder().encode(text));
const KEY = mldsa44Keygen(label('p2mr-ts M3 key'));
const SCHNORR_SECRET = label('p2mr-ts M3 schnorr key');
const ZERO_AUX = new Uint8Array(32);
const FIXED_RND = label('p2mr-ts M3 hedged randomness');
const E0 = TRIPWIRED_LEAF_VERSION;

/** The keys of the S3 output the rows spend. */
export const KEYS: TripwiredKeys = { xonlyPubkey: schnorr.getPublicKey(SCHNORR_SECRET), publicKey: KEY.publicKey };

const SCHNORR_LEAF = concatBytes(Uint8Array.of(0x20), KEYS.xonlyPubkey, Uint8Array.of(0xac));
const S1 = buildMldsa44LeafScript(KEY.publicKey);
const S2 = buildMldsa44LeafScript(KEY.publicKey, KEYS.xonlyPubkey);

function p2mr(root: Uint8Array): Uint8Array {
  return concatBytes(Uint8Array.of(0x52, 0x20), root);
}

function row(witness: Uint8Array[], scriptPubKey: Uint8Array, flags: string, error: string, comment: string): CrossImplRow {
  return [
    [...witness.map(bytesToHex), AMOUNT_BTC],
    '',
    `0x52 0x20 0x${bytesToHex(scriptPubKey.subarray(2))}`,
    flags,
    error,
    `P2MR_TRIPWIRE (p2mr-ts): ${comment}`,
  ];
}

function bip340(message: Uint8Array, hashType = 0x00): Uint8Array {
  const sig = schnorr.sign(message, SCHNORR_SECRET, ZERO_AUX);
  return hashType === 0x00 ? sig : concatBytes(sig, Uint8Array.of(hashType));
}

export function buildRows(): CrossImplRow[] {
  const rows: CrossImplRow[] = [];
  const s3 = p2mr(tripwiredMerkleRoot(KEYS));
  const s3Spend = { ...spendingTx(s3), inputIndex: 0 };

  // S3, the Schnorr leaf: valid with the checks on; with them off it fails whatever the signature
  for (const [hashType, name] of [
    [0x00, 'SIGHASH_DEFAULT'],
    [0x83, 'explicit SIGHASH_SINGLE|SIGHASH_ANYONECANPAY'],
  ] as const) {
    const message = tripwiredSighash({ ...KEYS, ...s3Spend, hashType, path: 'schnorr' });
    const witness = assembleTripwiredWitness({ ...KEYS, path: 'schnorr', signature: bip340(message, hashType) });
    rows.push(row(witness, s3, ENABLED, 'OK', `template S3, Schnorr leaf, ${name}`));
    rows.push(row(witness, s3, DISABLED, 'P2MR_EC_DISABLED', `template S3, Schnorr leaf, ${name}, EC checks off`));
  }

  // S3, the ML-DSA-44 leaf: valid either way
  const mldsa44Witness = (hashType: number, extraEntropy: Uint8Array | false) =>
    assembleTripwiredWitness({
      ...KEYS,
      path: 'mldsa44',
      signature: signMldsa44Input({ ...s3Spend, hashType, leafScript: S1, leafVersion: E0, secretKey: KEY.secretKey, extraEntropy }),
    });
  {
    const witness = mldsa44Witness(0x00, false);
    rows.push(row(witness, s3, ENABLED, 'OK', 'template S3, ML-DSA-44 leaf, SIGHASH_DEFAULT, deterministic'));
    rows.push(row(witness, s3, DISABLED, 'OK', 'template S3, ML-DSA-44 leaf, SIGHASH_DEFAULT, deterministic, EC checks off'));
  }
  rows.push(
    row(
      mldsa44Witness(0x81, FIXED_RND),
      s3,
      DISABLED,
      'OK',
      'template S3, ML-DSA-44 leaf, explicit SIGHASH_ALL|SIGHASH_ANYONECANPAY, hedged with fixed randomness, EC checks off',
    ),
  );

  // S3, signatures over the message of the same leaf at version 0xc0
  {
    const message = p2mrScriptPathSighash({ ...s3Spend, leafHash: tapLeafHash(SCHNORR_LEAF, 0xc0) });
    const witness = assembleTripwiredWitness({ ...KEYS, path: 'schnorr', signature: bip340(message) });
    rows.push(row(witness, s3, ENABLED, 'SCHNORR_SIG', 'template S3, Schnorr leaf, signed over the message of the leaf at version 0xc0'));
  }
  {
    const signature = mldsa44Sign(KEY.secretKey, mldsa44Sighash({ ...s3Spend, leafScript: S1 }), { extraEntropy: false });
    const witness = assembleTripwiredWitness({ ...KEYS, path: 'mldsa44', signature });
    rows.push(row(witness, s3, ENABLED, 'MLDSA44_SIG', 'template S3, ML-DSA-44 leaf, signed over the message of the leaf at version 0xc0'));
  }

  // Leaves of version 0xc0: a signature over the message at version 0xe0 fails; the EC checks being
  // off does not touch them
  {
    const sibling = tapLeafHash(MLDSA44_FAIL_LEAF_SCRIPT, 0xc0);
    const c0 = p2mr(tapBranchHash(tapLeafHash(SCHNORR_LEAF, 0xc0), sibling));
    const c0Spend = { ...spendingTx(c0), inputIndex: 0 };
    const controlBlock = encodeControlBlock(0xc0, [sibling]);
    const atE0 = tripwiredSighash({ ...KEYS, ...c0Spend, path: 'schnorr' });
    const atC0 = p2mrScriptPathSighash({ ...c0Spend, leafHash: tapLeafHash(SCHNORR_LEAF, 0xc0) });
    rows.push(
      row([bip340(atE0), SCHNORR_LEAF, controlBlock], c0, ENABLED, 'SCHNORR_SIG', '<key> OP_CHECKSIG at version 0xc0, signed over the message of the leaf at version 0xe0'),
    );
    rows.push(row([bip340(atC0), SCHNORR_LEAF, controlBlock], c0, DISABLED, 'OK', '<key> OP_CHECKSIG at version 0xc0, EC checks off'));
  }
  {
    const m1 = p2mr(mldsa44MerkleRoot(KEY.publicKey));
    const m1Spend = { ...spendingTx(m1), inputIndex: 0 };
    const signature = signMldsa44Input({ ...m1Spend, leafScript: S1, leafVersion: E0, secretKey: KEY.secretKey, extraEntropy: false });
    const controlBlock = encodeControlBlock(0xc0, [tapLeafHash(MLDSA44_FAIL_LEAF_SCRIPT, 0xc0)]);
    const witness = assembleMldsa44Witness({ signature, leafScript: S1, controlBlock });
    rows.push(row(witness, m1, ENABLED, 'MLDSA44_SIG', 'template S1 at version 0xc0, signed over the message of the leaf at version 0xe0'));
  }

  // Both checks in one leaf of version 0xe0 (S2 next to OP_RETURN): no wallet builds it, and once the
  // EC checks are off it cannot be spent
  {
    const sibling = tapLeafHash(MLDSA44_FAIL_LEAF_SCRIPT, E0);
    const s2 = p2mr(tapBranchHash(tapLeafHash(S2, E0), sibling));
    const s2Spend = { ...spendingTx(s2), inputIndex: 0 };
    const pq = signMldsa44Input({ ...s2Spend, leafScript: S2, leafVersion: E0, secretKey: KEY.secretKey, extraEntropy: false });
    const classical = bip340(p2mrScriptPathSighash({ ...s2Spend, leafHash: tapLeafHash(S2, E0) }));
    const witness = [classical, ...splitMldsa44Signature(pq), S2, encodeControlBlock(E0, [sibling])];
    rows.push(row(witness, s2, ENABLED, 'OK', 'S2 in a leaf of version 0xe0, which no template builds'));
    rows.push(row(witness, s2, DISABLED, 'P2MR_EC_DISABLED', 'S2 in a leaf of version 0xe0, which no template builds, EC checks off'));
  }
  return rows;
}
